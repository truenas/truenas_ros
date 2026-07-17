//! Connection teardown: close reasons, the SHUTDOWN-then-CLOSE FIN forcing,
//! op-count draining so the kernel never touches freed buffers, and slot
//! release. Beyond the close hook (a boxed dyn on the reactor), no user code
//! runs here — so it is fully core.

use super::Reactor;
use crate::errno::{self, Errno};
use crate::net::core::conn::{pack, Op};
use crate::net::core::protocol::CloseReason;
use crate::net::core::sys::*;

impl<U> Reactor<U> {
    /// Begin (idempotently) tearing a connection down: report it to the close
    /// hook, mark it closing, and submit the `CLOSE`. Any recv/send still in
    /// flight completes afterwards; the slot is freed only once all of its ops
    /// (this close included) have reaped, so the kernel never touches freed
    /// buffers.
    pub(crate) fn close_conn(
        &mut self,
        slot: u32,
        generation: u32,
        reason: CloseReason,
    ) -> errno::Result<()> {
        if let Some(conn) = self.table.get_conn_mut(slot) {
            if conn.closing {
                return Ok(());
            }
            conn.closing = true;
            // Stash the reason for the client's `Event::Closed` (emitted when
            // the slot is reclaimed). Client-only — the server reports closes
            // through its hook below and never reads this back.
            #[cfg(feature = "net-client")]
            {
                conn.close_reason = Some(reason);
            }
            // Disjoint-field borrow: `self.on_close` vs `self.table`; within
            // the connection, addr (immutable) vs userdata (mutable).
            if let Some(hook) = self.on_close.as_mut() {
                let (addr, state) = conn.close_parts();
                hook(addr, reason, state);
            }
        }
        // Retire the kTLS-splice inactivity watchdog if one is armed: it is not
        // an `ops`-counted op, so nothing else reaps it — an uncancelled timer
        // would keep `inflight` up (delaying an idle `serve_forever`'s exit)
        // until it expired. A no-op when none is armed.
        self.cancel_splice_deadline(slot, generation)?;
        // The peer already sent its FIN (clean EOF) or is gone (reset/error),
        // so no SHUTDOWN is owed; every other reason is a server-initiated
        // close of a maybe-still-connected peer and must force the FIN.
        let shutdown_first = !matches!(
            reason,
            CloseReason::PeerClosed
                | CloseReason::RecvError(_)
                | CloseReason::SendError(_)
        );
        // SECURITY: the index-freeing CLOSE must be the connection's LAST ring
        // op. A recv or send still in flight (pipelined read-ahead, or a push
        // send racing the idle recv) pins the fixed descriptor's kernel rsrc
        // node. CLOSE frees the table slot and bitmap bit at issue and biases
        // the allocator to hand that index to the next accept, yet the pinned
        // node keeps the old socket — and its recv buffer — alive under the
        // surviving op. That accept can then reuse the index while our slot is
        // still `Serving` (freed only at `ops == 0`), and `accept_connection`
        // would overwrite the live connection: a use-after-free of the recv
        // buffer, plus cross-connection reply misrouting (the generation never
        // bumps on reuse-without-free). So when anything is in flight, cancel
        // it and defer the teardown until it reaps; the CLOSE then runs alone
        // and the slot frees cleanly before any reuse-accept can land.
        let (recving, sending, splicing, splice_polling) = self
            .table
            .get_conn_mut(slot)
            .map(|c| (c.recving, c.sending, c.splicing, c.splice_polling))
            .unwrap_or((false, false, false, false));
        if recving || sending || splicing || splice_polling {
            let conn = self.table.conn_mut(slot);
            conn.teardown_deferred = true;
            conn.teardown_shutdown_first = shutdown_first;
            // One fd-keyed cancel catches an in-flight recv, send, and/or splice
            // readiness poll — all ride the socket slot. The SPLICE itself does
            // NOT: its SQE `fd` is the consumer pipe, so it is unreachable by the
            // fd cancel and must be cancelled by its own `user_data`. Whichever
            // ops were live each drive `op_done`, which submits the deferred
            // teardown once the last drains — keeping CLOSE the last op.
            if recving || sending || splice_polling {
                self.submit_cancel(slot, generation)?;
            }
            if splicing {
                self.submit_cancel_splice(slot, generation)?;
            }
            Ok(())
        } else {
            self.submit_teardown(slot, generation, shutdown_first)
        }
    }

    /// Cancel every op in flight on a connection's fixed descriptor (its recv
    /// and/or send) so a deferred teardown can run once they reap. One
    /// `ASYNC_CANCEL` keyed on the fixed fd catches both regardless of opcode;
    /// a linked idle/request timeout is cancelled along with its recv. The
    /// cancel is a control op — it is not counted in `conn.ops`, and its own
    /// completion is ignored; the cancelled recv/send drive `op_done`, which
    /// submits the teardown once the last of them drains.
    fn submit_cancel(
        &mut self,
        slot: u32,
        generation: u32,
    ) -> errno::Result<()> {
        self.stage(pack(Op::Cancel, slot, generation), move |sqe| {
            sqe.opcode = IORING_OP_ASYNC_CANCEL;
            sqe.fd = slot as i32;
            sqe.op_flags = IORING_ASYNC_CANCEL_ALL
                | IORING_ASYNC_CANCEL_FD
                | IORING_ASYNC_CANCEL_FD_FIXED;
        })
    }

    /// Cancel an in-flight body splice by its `user_data`. Unlike a recv/send —
    /// both keyed on the socket slot, so `submit_cancel`'s fd cancel reaps them
    /// — a splice's SQE `fd` is the consumer pipe, so only a `user_data` match
    /// reaches it: cancel-by-user_data (no `CANCEL_FD` flag) with `sqe.addr`
    /// set to the splice's token. Like `submit_cancel` it is an uncounted
    /// control op; the splice's own `-ECANCELED` completion drives `op_done`,
    /// which submits the deferred teardown once every cancelled op has drained.
    pub(crate) fn submit_cancel_splice(
        &mut self,
        slot: u32,
        generation: u32,
    ) -> errno::Result<()> {
        let target = pack(Op::SpliceRecv, slot, generation);
        self.stage(pack(Op::Cancel, slot, generation), move |sqe| {
            sqe.opcode = IORING_OP_ASYNC_CANCEL;
            sqe.fd = -1;
            sqe.addr = target;
        })
    }

    /// Submit the teardown a `close_conn` deferred, now that the recv/send it
    /// cancelled have drained (called from `op_done`). The CLOSE runs with
    /// nothing else in flight on the descriptor.
    pub(crate) fn submit_deferred_teardown(
        &mut self,
        slot: u32,
    ) -> errno::Result<()> {
        let generation = self.table.generation_low(slot);
        let shutdown_first = {
            let conn = self.table.conn_mut(slot);
            conn.teardown_deferred = false;
            conn.teardown_shutdown_first
        };
        self.submit_teardown(slot, generation, shutdown_first)
    }

    /// Map a failed recv completion to its close reason. `was_idle` is the
    /// armed op's `recv_idle` (parked between requests vs mid-message).
    pub(crate) fn recv_close_reason(
        &self,
        res: i32,
        was_idle: bool,
    ) -> CloseReason {
        if res == 0 {
            return if was_idle {
                CloseReason::PeerClosed // clean keep-alive end
            } else {
                CloseReason::TruncatedMessage
            };
        }
        if res > 0 {
            return CloseReason::TruncatedMessage; // short exact read: EOF mid-frame
        }
        let e = Errno::from_raw(-res);
        if e == Errno::ECANCELED {
            if self.draining || self.stopping() {
                return CloseReason::ShuttingDown;
            }
            if was_idle && self.cfg.idle_timeout.is_some() {
                return CloseReason::IdleTimeout;
            }
            // SECURITY: a non-idle exact read (body / `Need` remainder) is the
            // only recv that carries the request clock, so an ECANCELED there
            // is it firing — the slow-loris reclaim (see `request_timeout`).
            if !was_idle && self.cfg.request_timeout.is_some() {
                return CloseReason::RequestTimeout;
            }
        }
        CloseReason::RecvError(e)
    }

    /// Map a failed send completion to its close reason.
    pub(crate) fn send_close_reason(&self, res: i32) -> CloseReason {
        if res < 0 {
            let e = Errno::from_raw(-res);
            if e == Errno::ECANCELED {
                if self.draining || self.stopping() {
                    return CloseReason::ShuttingDown;
                }
                if self.cfg.send_timeout.is_some() {
                    return CloseReason::SendTimeout;
                }
            }
            return CloseReason::SendError(e);
        }
        // A zero-byte send completion is not an expected success shape.
        CloseReason::SendError(Errno::EIO)
    }

    /// Tear a connection's socket down and free its slot.
    ///
    /// `shutdown_first` inserts a `SHUTDOWN` before the `CLOSE`. A bare CLOSE
    /// of a direct (pool) descriptor only drops the ring's file-table
    /// reference; the socket's final `fput` — which sends the peer's FIN — can
    /// be deferred while another connection's in-flight op pins the ring's
    /// resource node, so a server-initiated close of a *still-connected* peer
    /// (reject, idle/send timeout, eviction, handler close) could leave it
    /// hanging fully connected until unrelated traffic drains the node. An
    /// explicit SHUTDOWN forces the FIN out at once. It is `IORING_OP_SHUTDOWN`,
    /// which the kernel runs async (io-wq), so it is skipped when the peer has
    /// already closed or reset (`PeerClosed`/`RecvError`/`SendError`): there
    /// the plain CLOSE both suffices and reclaims the slot with no added
    /// latency (the hot path for slot reuse).
    pub(crate) fn submit_teardown(
        &mut self,
        slot: u32,
        generation: u32,
        shutdown_first: bool,
    ) -> errno::Result<()> {
        // Count the teardown as one op on the connection (if it has one), so
        // the slot is freed only after it — and any recv/send still in flight
        // — have reaped. When it is SHUTDOWN then CLOSE, one count still covers
        // both: `on_shutdown` submits the CLOSE without re-counting, and
        // `on_closed` does the single decrement.
        if let Some(conn) = self.table.get_conn_mut(slot) {
            conn.ops += 1;
        }
        if shutdown_first {
            self.stage(pack(Op::Shutdown, slot, generation), move |sqe| {
                sqe.opcode = IORING_OP_SHUTDOWN;
                sqe.fd = slot as i32;
                sqe.flags = IOSQE_FIXED_FILE;
                sqe.len = libc::SHUT_RDWR as u32;
            })
        } else {
            self.submit_close(slot, generation)
        }
    }

    /// Stage the `CLOSE` that reclaims a direct descriptor (and, once it
    /// reaps, the slot). Does not touch `ops` — the teardown is counted in
    /// `submit_teardown`.
    fn submit_close(
        &mut self,
        slot: u32,
        generation: u32,
    ) -> errno::Result<()> {
        self.stage(pack(Op::Close, slot, generation), move |sqe| {
            sqe.opcode = IORING_OP_CLOSE;
            sqe.fd = 0;
            sqe.file_index = slot + 1;
        })
    }

    /// A pre-close `SHUTDOWN` completed. Its result is irrelevant — a peer
    /// that vanished mid-flight yields `-ENOTCONN`, which is fine; any owed FIN
    /// is out. Submit the CLOSE. The slot cannot recycle between the two ops
    /// (release happens only in `on_closed`), so no generation recheck.
    pub(crate) fn on_shutdown(
        &mut self,
        slot: u32,
        generation: u32,
    ) -> errno::Result<()> {
        self.submit_close(slot, generation)
    }

    /// The `CLOSE` that reclaims a direct descriptor completed: account it and,
    /// once the connection's last op has reaped, free the slot.
    pub(crate) fn on_closed(&mut self, slot: u32) -> errno::Result<()> {
        let free = match self.table.get_conn_mut(slot) {
            Some(conn) => {
                conn.ops -= 1;
                conn.ops == 0
            }
            None => true, // reject / out-of-range close: nothing to track
        };
        if free {
            self.reclaim_slot(slot)?;
        }
        Ok(())
    }

    /// Account one completed recv/send op. Returns `true` if the connection is
    /// still active (keep processing), `false` if it is being torn down — in
    /// which case, if this was its last op, the slot is freed here.
    pub(crate) fn op_done(&mut self, slot: u32) -> errno::Result<bool> {
        let (closing, teardown_ready, empty) = {
            let conn = self.table.conn_mut(slot);
            conn.ops -= 1;
            (
                conn.closing,
                // The last recv/send/splice/readiness-poll cancelled by a
                // deferred close just reaped (the splice is cancelled by
                // user_data, the rest by the fd — see `close_conn`).
                conn.teardown_deferred
                    && !conn.recving
                    && !conn.sending
                    && !conn.splicing
                    && !conn.splice_polling,
                conn.ops == 0,
            )
        };
        if !closing {
            return Ok(true);
        }
        // A close that found recv/send still in flight cancelled them and
        // deferred its teardown; submit it now that they have drained, so the
        // index-freeing CLOSE is the connection's last op (see `close_conn`).
        // Check this before `empty`: the drained sibling leaves `ops == 0`, but
        // the slot must not be reclaimed — the teardown re-counts it.
        if teardown_ready {
            self.submit_deferred_teardown(slot)?;
            return Ok(false);
        }
        if empty {
            self.reclaim_slot(slot)?;
        }
        Ok(false)
    }

    /// Free a fully-reaped slot, run the drain-quiescence check, and flag the
    /// role loop to re-arm any listener parked on a full pool (the pool now has
    /// a free slot). The re-arm itself is a role concern (it touches the
    /// listeners) — the loop drains `pool_freed` after dispatch and never while
    /// tearing down, so the flag being set during `cancel_and_reap_all` is inert.
    fn reclaim_slot(&mut self, slot: u32) -> errno::Result<()> {
        self.free_slot(slot);
        self.maybe_finish_drain();
        self.pool_freed = true;
        Ok(())
    }
}
