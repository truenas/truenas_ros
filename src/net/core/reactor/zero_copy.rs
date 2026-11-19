//! Zero-copy sends (`ServerConfig::send_zero_copy`) on the reactor: admission, the two completions of a send, the held
//! `CLOSE`, and the stop drain.

use super::{Reactor, SendStep};
use crate::errno;
use crate::net::core::conn::{Op, ZcLedger, pack, unpack};
use crate::net::core::handles::stat;
use crate::net::core::probe::fill_setsockopt_cmd;
use crate::net::core::protocol::ClientAddr;
use crate::uring::sys::*;
use std::time::Instant;

/// Whether only notifications are left of the ops in flight: every one is an owed send. `<=`, so that a count gone
/// wrong still ends in the reset instead of a wait with no deadline.
pub(super) fn only_notifications_left(inflight: u64, owed: u64) -> bool {
    inflight <= owed
}

/// A `CONNECT` to `AF_UNSPEC` disconnects the socket, and TCP then resets the peer and drops its send queues
/// (`tcp_disconnect`, `net/ipv4/tcp.c`). The kernel copies the address at prep.
static UNSPEC: libc::sockaddr = libc::sockaddr {
    sa_family: libc::AF_UNSPEC as libc::sa_family_t,
    sa_data: [0; 14],
};

impl<U> Reactor<U> {
    /// The sequence of a zero-copy send for the gather just armed on `slot`, or `None` to copy. Called only when the
    /// gather reaches the threshold. Nothing is counted until the ring takes the SQE
    /// ([`commit_zero_copy`](Self::commit_zero_copy)), since staging can fail with `EBUSY`.
    #[cold]
    pub(crate) fn admit_zero_copy(&mut self, slot: u32, armed: usize) -> Option<u32> {
        if self.zc_pinned.saturating_add(armed) > self.cfg.zc_max_pinned {
            return None;
        }
        let linger_ms = u32::try_from(self.cfg.zc_linger.as_millis()).unwrap_or(u32::MAX);
        let conn = self.table.conn_mut(slot);
        // A ULP such as kTLS clears `SOCK_SUPPORT_ZC` (`__tcp_set_ulp`, `net/ipv4/tcp_ulp.c`), a BPF sockmap does too
        // (`sock_replace_proto`), and AF_UNIX never has it. A socket this misses takes the `EOPNOTSUPP` fallback.
        if !matches!(conn.peer, ClientAddr::Inet(_)) || conn.is_ktls() || conn.file_body_in_flight() {
            return None;
        }
        conn.zc
            .get_or_insert_with(|| Box::new(ZcLedger::new(linger_ms)))
            .admit()
    }

    /// Counts zero-copy send `seq`, which the ring took for `slot`. Its armed bytes count against `max_pinned` from now
    /// on, so every later admission in this loop sees them.
    pub(crate) fn commit_zero_copy(&mut self, slot: u32, seq: u32, armed: usize) {
        let zc = self
            .table
            .conn_mut(slot)
            .zc
            .as_deref_mut()
            .expect("admission made the ledger");
        zc.staged(seq, armed);
        self.zc_owed += 1;
        self.zc_pinned += armed;
    }

    /// The result of zero-copy send `seq`. Its bytes stay pinned until the notification, if `IORING_CQE_F_MORE` says
    /// one follows. A send the kernel refused goes again with a copy, and the connection copies from then on.
    pub(crate) fn on_send_zc_complete(&mut self, slot: u32, seq: u32, res: i32, flags: u32) -> errno::Result<SendStep> {
        let more = flags & IORING_CQE_F_MORE != 0;
        let Some(zc) = self.table.get_conn_mut(slot).and_then(|c| c.zc.as_deref_mut()) else {
            debug_assert!(false, "a zero-copy result names slot {slot}, which has no ledger");
            return Ok(SendStep::Done);
        };
        let (was_owed, staged, moved) = zc.result(seq, res, more);
        if was_owed && !more {
            self.zc_owed -= 1;
        }
        self.zc_pinned = self.zc_pinned - staged + moved;
        if moved > 0 {
            stat!(self, zero_copy_sends);
            stat!(self, zero_copy_bytes, moved as u64);
        }
        let generation = self.table.generation_low(slot);
        if matches!(-res, libc::EOPNOTSUPP | libc::ENOMEM | libc::EINVAL) {
            // Nothing went out. The socket cannot send zero-copy (`io_send_zc`), the pinned pages would pass
            // `RLIMIT_MEMLOCK` (`io_notif_account_mem`), or the kernel refused the flags.
            stat!(self, zero_copy_fallbacks);
            let conn = self.table.conn_mut(slot);
            conn.sending = false;
            if let Some(zc) = conn.zc.as_deref_mut() {
                zc.off = true;
            }
            if !self.op_done(slot)? {
                return Ok(SendStep::Done);
            }
            self.submit_send(slot, generation)?;
            return Ok(SendStep::Done);
        }
        self.finish_send(slot, generation, res, Some(seq))
    }

    /// The notification of zero-copy send `seq`. The kernel no longer reads its pages, so what no other send carries
    /// goes back, and a held `CLOSE` may go out.
    pub(crate) fn on_send_zc_notif(&mut self, slot: u32, seq: u32, res: i32) -> errno::Result<()> {
        let copied = res as u32 & IORING_NOTIF_USAGE_ZC_COPIED != 0;
        let Some(zc) = self.table.get_conn_mut(slot).and_then(|c| c.zc.as_deref_mut()) else {
            debug_assert!(false, "a zero-copy notification names slot {slot}, which has no ledger");
            return Ok(());
        };
        let (was_owed, moved, turned_off) = zc.notified(seq, copied);
        let close = zc.close_held && !zc.owes() && !zc.linger_inflight;
        if close {
            zc.close_held = false;
        }
        if was_owed {
            self.zc_owed -= 1;
        }
        self.zc_pinned -= moved;
        if turned_off {
            stat!(self, zero_copy_copied);
        }
        if close {
            let generation = self.table.generation_low(slot);
            self.submit_close(slot, generation)?;
        }
        Ok(())
    }

    /// The `TCP_USER_TIMEOUT` setsockopt completed. Its result does not matter, since the `CLOSE` still waits for the
    /// notifications. A completion of a past incarnation must not touch the slot: it would release the new
    /// connection's `CLOSE` while the kernel may still read that connection's `optval`.
    pub(crate) fn on_zc_linger(&mut self, slot: u32, generation: u32) -> errno::Result<()> {
        if !self.table.slot_matches_cqe(slot, generation) {
            return Ok(());
        }
        let Some(zc) = self.table.get_conn_mut(slot).and_then(|c| c.zc.as_deref_mut()) else {
            return Ok(());
        };
        zc.linger_inflight = false;
        let close = zc.close_held && !zc.owes();
        if close {
            zc.close_held = false;
            let generation = self.table.generation_low(slot);
            self.submit_close(slot, generation)?;
        }
        Ok(())
    }

    /// Whether the `CLOSE` of `slot` must wait for zero-copy notifications. Until they come, the kernel may read the
    /// pages, and the slot and its fd index must stay taken, since an accept takes any free index. The first hold sets
    /// `TCP_USER_TIMEOUT`, so the kernel resets a peer that never acknowledges. TCP checks the timeout only when a
    /// retransmit or zero-window probe timer fires (`tcp_write_timeout`, `tcp_probe_timer`, `net/ipv4/tcp_timer.c`),
    /// so the reset can come a timer interval after the linger.
    pub(super) fn hold_close(&mut self, slot: u32, generation: u32) -> errno::Result<bool> {
        let Some(zc) = self.table.get_conn_mut(slot).and_then(|c| c.zc.as_deref_mut()) else {
            return Ok(false);
        };
        if !zc.owes() && !zc.linger_inflight {
            return Ok(false);
        }
        zc.close_held = true;
        if zc.linger_set || !zc.owes() {
            return Ok(true);
        }
        let optval = std::ptr::addr_of!(zc.linger_ms) as u64;
        self.stage(pack(Op::ZcLinger, slot, generation), move |sqe| {
            let optlen = size_of::<u32>() as u32;
            fill_setsockopt_cmd(sqe, libc::IPPROTO_TCP, libc::TCP_USER_TIMEOUT, optval, optlen);
            sqe.fd = slot as i32;
            sqe.flags = IOSQE_FIXED_FILE;
        })?;
        let zc = self
            .table
            .conn_mut(slot)
            .zc
            .as_deref_mut()
            .expect("the ledger checked above");
        zc.linger_set = true;
        zc.linger_inflight = true;
        Ok(true)
    }

    /// [`cancel_and_reap_all`](Self::cancel_and_reap_all) for a ring with zero-copy sends. A notification cannot be
    /// cancelled, and the sockets close only with the ring, after the drain, so a peer that never acknowledges would
    /// hold the drain for ever. So once only notifications are left, this waits up to the linger, then resets the
    /// sockets that still owe.
    pub(super) fn settle_zero_copy(&mut self, other: &mut dyn FnMut(&IoUringCqe)) -> errno::Result<()> {
        if self.engine.inflight > 0 {
            self.stage(pack(Op::Cancel, 0, 0), |sqe| {
                sqe.opcode = IORING_OP_ASYNC_CANCEL;
                sqe.fd = -1;
                sqe.op_flags = IORING_ASYNC_CANCEL_ANY;
            })?;
        }
        let deadline = Instant::now() + self.cfg.zc_linger;
        let mut reset = false;
        while self.engine.inflight > 0 {
            let mut wait = None;
            if !reset && only_notifications_left(self.engine.inflight, self.zc_owed) {
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    self.reset_owing()?;
                    reset = true;
                } else {
                    wait = Some(left);
                }
            }
            self.engine.ring.submit_and_wait_for(1, wait)?;
            while let Some(cqe) = self.engine.ring.reap() {
                self.engine.retire(&cqe);
                self.settle_cqe(&cqe, other);
            }
        }
        self.engine.ring.submit()
    }

    /// Keeps the ledgers and counts right during the drain. Other completions get the plain drain's sweep.
    fn settle_cqe(&mut self, cqe: &IoUringCqe, other: &mut dyn FnMut(&IoUringCqe)) {
        let (op, slot, seq) = unpack(cqe.user_data);
        match op {
            Some(Op::SendZc) => {
                let Some(zc) = self.table.get_conn_mut(slot).and_then(|c| c.zc.as_deref_mut()) else {
                    return;
                };
                if cqe.flags & IORING_CQE_F_NOTIF != 0 {
                    let (was_owed, moved, _) = zc.notified(seq, false);
                    if was_owed {
                        self.zc_owed -= 1;
                    }
                    self.zc_pinned -= moved;
                } else {
                    let more = cqe.flags & IORING_CQE_F_MORE != 0;
                    let (was_owed, staged, moved) = zc.result(seq, cqe.res, more);
                    if was_owed && !more {
                        self.zc_owed -= 1;
                    }
                    self.zc_pinned = self.zc_pinned - staged + moved;
                }
            }
            Some(Op::ZcLinger) => {
                if let Some(zc) = self.table.get_conn_mut(slot).and_then(|c| c.zc.as_deref_mut()) {
                    zc.linger_inflight = false;
                }
            }
            Some(Op::ZcReset) => {}
            _ => Self::on_drained(cqe, other),
        }
    }

    /// Resets every socket that still owes notifications, which frees its pages at once.
    pub(super) fn reset_owing(&mut self) -> errno::Result<()> {
        for slot in 0..self.table.len() as u32 {
            let owes = self
                .table
                .get_conn(slot)
                .and_then(|c| c.zc.as_deref())
                .is_some_and(ZcLedger::owes);
            if !owes {
                continue;
            }
            let generation = self.table.generation_low(slot);
            self.stage(pack(Op::ZcReset, slot, generation), |sqe| {
                sqe.opcode = IORING_OP_CONNECT;
                sqe.fd = slot as i32;
                sqe.flags = IOSQE_FIXED_FILE;
                sqe.addr = std::ptr::addr_of!(UNSPEC) as u64;
                sqe.off_addr2 = size_of::<libc::sockaddr>() as u64;
            })?;
            // Counted after the stage, which can fail, so the count reports only resets that went out.
            stat!(self, zero_copy_resets);
        }
        Ok(())
    }
}
