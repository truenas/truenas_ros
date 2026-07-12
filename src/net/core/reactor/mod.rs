//! The role-generic reactor core: [`Reactor`], the io_uring engine both the
//! server and client roles embed. Holds the ring, the connection table, the
//! projected [`CoreConfig`], the shared cross-thread flags/stats, and the
//! kernel-touched landing pads; the role wrappers (`net::server` and
//! `net::client`) own admission/listen/connect/protocol on top of it.
//!
//! The engine is split by lifecycle stage across the submodules — `io` (the
//! request data plane's submission/completion helpers), `close` (teardown),
//! `wake` (the wake arm and drain quiescence check) — plus this file's SQE
//! staging and slot bookkeeping every stage shares.

mod close;
mod io;
mod wake;

pub(crate) use io::{Enacted, Gate, RecvStep, SendStep, SpliceStep};

/// The pure framing decision, re-exported only under the `__fuzz` feature for
/// the fuzz harness (`fuzz/fuzz_targets/framing_arithmetic.rs`). Not part of
/// the stable API.
#[cfg(feature = "__fuzz")]
pub use io::{frame_step, FrameStep};

use crate::errno;
use crate::net::core::config::CoreConfig;
use crate::net::core::conn::{pack, unpack, Op};
use crate::net::core::handles::{stat, CloseHook, LoopShared, StatsInner};
use crate::net::core::ring::Ring;
use crate::net::core::sys::*;
use crate::net::core::table::ConnTable;
use std::sync::atomic::Ordering;
use std::sync::Arc;

/// Every engine-level buffer the kernel reads or writes asynchronously
/// (per-connection buffers live in `Connection`), in one boxed block so the
/// addresses stay stable for in-flight ops no matter where the owning reactor
/// moves. The timespecs for optional features exist unconditionally; arming
/// them stays gated by `cfg`.
pub(crate) struct KernelPads {
    /// Landing pad for the wake eventfd `READ` (the kernel drains the
    /// counter into it on completion).
    pub(crate) wake_buf: u64,
    /// Grace-period deadline (written by `begin_drain` before arming).
    pub(crate) deadline: KernelTimespec,
    /// Fixed accept-retry backoff (`ACCEPT_RETRY_MS`).
    pub(crate) accept_retry: KernelTimespec,
    /// Relative idle timeout — meaningful iff `cfg.idle_timeout` is set.
    pub(crate) idle_timeout: KernelTimespec,
    /// Relative send timeout — meaningful iff `cfg.send_timeout` is set.
    pub(crate) send_timeout: KernelTimespec,
    /// Relative request-receive timeout — meaningful iff `cfg.request_timeout`
    /// is set.
    pub(crate) request_timeout: KernelTimespec,
    /// Relative kTLS handshake timeout — meaningful iff
    /// `cfg.tls_handshake_timeout` is set (bounds the parked-handshake slot).
    pub(crate) tls_handshake: KernelTimespec,
}

/// The role-agnostic io_uring engine: one ring, one connection table, and the
/// state every stage shares. A role (`Server` or `Client`) embeds one as
/// `core` and drives it with its own admission/connect/protocol code.
///
/// Field order is load-bearing: `table` is declared before `ring` so the
/// connection buffers drop first — freed before the ring is unmapped and its
/// pool descriptors close (the kernel must never touch a freed buffer).
pub(crate) struct Reactor<U> {
    /// The connection table: one typed state machine per pool slot, with the
    /// generation that makes recycled-slot tokens stale. Declared first so it
    /// drops before `ring`.
    pub(crate) table: ConnTable<U>,
    /// The engine-read tuning knobs a role config projects in.
    pub(crate) cfg: CoreConfig,
    /// Loop-side counters, shared with stats handles.
    pub(crate) stats: Arc<StatsInner>,
    /// Stop/graceful flags + the wake eventfd, shared with every cross-thread
    /// handle.
    pub(crate) shared: Arc<LoopShared>,
    /// Kernel-touched landing pads (stable boxed addresses).
    pub(crate) pads: Box<KernelPads>,
    /// Optional close hook, invoked once per connection as it begins closing.
    /// Lives here (not on the role's handlers) so the whole teardown path is
    /// core.
    pub(crate) on_close: Option<CloseHook<U>>,
    /// Operations currently in flight on the ring.
    pub(crate) inflight: u64,
    /// The loop-local state a graceful request transitions into: stop
    /// accepting, stop starting requests, finish in-flight work under a
    /// Deadline timer that escalates to a hard stop.
    pub(crate) draining: bool,
    /// Whether the kernel supports `IORING_OP_FIXED_FD_INSTALL` (Linux ≥ 6.8;
    /// probed at construction) — required by kTLS and by `Response::Detach`.
    pub(crate) fixed_fd_install: bool,
    /// Set by `reclaim_slot` whenever a pool slot is freed, drained by the
    /// role loop (`take_pool_freed`) to re-arm any listener parked on a full
    /// pool. A flag rather than a role-side call keeps slot reclamation core.
    pub(crate) pool_freed: bool,
    /// Declared last so it drops after `table`: connection buffers are freed
    /// before the ring is unmapped and the ring fd (which owns the pool
    /// descriptors) closes.
    pub(crate) ring: Ring,
}

impl<U> Reactor<U> {
    /// Stage one SQE (setting its `user_data`) and count it as in-flight.
    pub(crate) fn stage<Fill: FnOnce(&mut IoUringSqe)>(
        &mut self,
        user_data: u64,
        fill: Fill,
    ) -> errno::Result<()> {
        self.ring.push_sqe(move |sqe| {
            fill(sqe);
            sqe.user_data = user_data;
        })?;
        self.inflight += 1;
        Ok(())
    }

    /// Stage an `IO_LINK` head plus its trailing `LINK_TIMEOUT` as one
    /// contiguous pair (the kernel accepts the timeout only in the same
    /// submission as its head), counting both as in-flight. Each yields its own
    /// terminal completion.
    pub(crate) fn stage_linked<H, T>(
        &mut self,
        head_ud: u64,
        head: H,
        tail_ud: u64,
        tail: T,
    ) -> errno::Result<()>
    where
        H: FnOnce(&mut IoUringSqe),
        T: FnOnce(&mut IoUringSqe),
    {
        self.ring.push_sqe_linked(
            move |sqe| {
                head(sqe);
                sqe.user_data = head_ud;
            },
            move |sqe| {
                tail(sqe);
                sqe.user_data = tail_ud;
            },
        )?;
        self.inflight += 2;
        Ok(())
    }

    /// Cancel every outstanding op, then reap until nothing is in flight.
    pub(crate) fn cancel_and_reap_all(&mut self) -> errno::Result<()> {
        if self.inflight > 0 {
            self.stage(pack(Op::Cancel, 0, 0), |sqe| {
                sqe.opcode = IORING_OP_ASYNC_CANCEL;
                sqe.fd = -1;
                sqe.op_flags = IORING_ASYNC_CANCEL_ANY;
            })?;
        }
        while self.inflight > 0 {
            self.ring.submit_and_wait(1)?;
            while let Some(cqe) = self.ring.reap() {
                if cqe.flags & IORING_CQE_F_MORE == 0 {
                    self.inflight = self.inflight.saturating_sub(1);
                }
                // A `FIXED_FD_INSTALL` (kTLS handshake or detach) that completed
                // during this non-dispatching drain never reaches
                // `on_fd_install`/`on_detach_install`, which own the furnished
                // fd's close — so close it here, or a teardown racing an install
                // leaks a real process fd (it survives the ring's own close;
                // matters when the process outlives the owner).
                let (op, _, _) = unpack(cqe.user_data);
                if matches!(op, Some(Op::FdInstall | Op::DetachInstall))
                    && cqe.res >= 0
                {
                    // SAFETY: `res` is a freshly installed owned process fd that
                    // no handler will take ownership of on this teardown path.
                    unsafe { libc::close(cqe.res) };
                }
            }
        }
        self.ring.submit()
    }

    /// Empty a fully-reaped slot (bumping its generation) and account a
    /// closed connection if one was serving there.
    pub(crate) fn free_slot(&mut self, slot: u32) {
        if self.table.free(slot) {
            stat!(self, closed);
            self.stats
                .active
                .store(u64::from(self.table.active()), Ordering::Relaxed);
        }
    }

    pub(crate) fn stopping(&self) -> bool {
        self.shared.stop.load(Ordering::Acquire)
    }

    /// Take and clear the `pool_freed` flag: `true` if `reclaim_slot` freed a
    /// slot since the last check, so the role loop can re-arm any listener
    /// parked on a full pool.
    pub(crate) fn take_pool_freed(&mut self) -> bool {
        std::mem::take(&mut self.pool_freed)
    }
}
