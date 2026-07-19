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
use crate::net::core::handles::{stat, CloseHook, StatsInner};
use crate::net::core::table::ConnTable;
use crate::uring::engine::Engine;
use crate::uring::sys::*;
use std::sync::atomic::Ordering;
use std::sync::Arc;

/// Every stream-level timeout pad the kernel reads asynchronously
/// (per-connection buffers live in `Connection`; the wake eventfd's landing
/// pad lives in the [`Engine`]), in one boxed block so the addresses stay
/// stable for in-flight ops no matter where the owning reactor moves. The
/// timespecs for optional features exist unconditionally; arming them stays
/// gated by `cfg`.
pub(crate) struct KernelPads {
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

/// The stream reactor: the shared [`Engine`] plus the connection table and
/// the state every stream stage shares. A role (`Server` or `Client`) embeds
/// one as `core` and drives it with its own admission/connect/protocol code.
///
/// Field order is load-bearing: `table` is declared before `engine` so the
/// connection buffers drop first — freed before the engine's ring is unmapped
/// and its pool descriptors close (the kernel must never touch a freed
/// buffer).
pub(crate) struct Reactor<U> {
    /// The connection table: one typed state machine per pool slot, with the
    /// generation that makes recycled-slot tokens stale. Declared first so it
    /// drops before `engine` (whose last field is the ring).
    pub(crate) table: ConnTable<U>,
    /// The engine-read tuning knobs a role config projects in.
    pub(crate) cfg: CoreConfig,
    /// Loop-side counters, shared with stats handles.
    pub(crate) stats: Arc<StatsInner>,
    /// Kernel-touched stream timeout pads (stable boxed addresses).
    pub(crate) pads: Box<KernelPads>,
    /// Optional close hook, invoked once per connection as it begins closing.
    /// Lives here (not on the role's handlers) so the whole teardown path is
    /// core.
    pub(crate) on_close: Option<CloseHook<U>>,
    /// The loop-local state a graceful request transitions into: stop
    /// accepting, stop starting requests, finish in-flight work under a
    /// Deadline timer that escalates to a hard stop.
    pub(crate) draining: bool,
    /// Set by `reclaim_slot` whenever a pool slot is freed, drained by the
    /// role loop (`take_pool_freed`) to re-arm any listener parked on a full
    /// pool. A flag rather than a role-side call keeps slot reclamation core.
    pub(crate) pool_freed: bool,
    /// The shared io_uring engine (ring, in-flight accounting, wake, stop
    /// flags). Declared last so the ring drops after `table`'s buffers.
    pub(crate) engine: Engine,
}

impl<U> Reactor<U> {
    /// Assemble a reactor around an already-built engine. The stream tag
    /// vocabulary ([`Op`]) and the teardown fd sweep are supplied by the thin
    /// wrappers below; everything mechanical lives in the engine.
    pub(crate) fn from_parts(
        engine: Engine,
        pool_size: u32,
        cfg: CoreConfig,
        pads: Box<KernelPads>,
    ) -> Reactor<U> {
        Reactor {
            table: ConnTable::new(pool_size),
            cfg,
            stats: Arc::new(StatsInner::default()),
            pads,
            on_close: None,
            draining: false,
            pool_freed: false,
            engine,
        }
    }

    /// Stage one SQE (setting its `user_data`) and count it as in-flight.
    pub(crate) fn stage<Fill: FnOnce(&mut IoUringSqe)>(
        &mut self,
        user_data: u64,
        fill: Fill,
    ) -> errno::Result<()> {
        self.engine.stage(user_data, fill)
    }

    /// Stage an `IO_LINK` head plus its trailing `LINK_TIMEOUT` as one
    /// contiguous pair; see [`Engine::stage_linked`].
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
        self.engine.stage_linked(head_ud, head, tail_ud, tail)
    }

    /// Cancel every outstanding op, then reap until nothing is in flight —
    /// [`Engine::cancel_and_reap_all`] under the stream tag vocabulary, with
    /// the stream-specific sweep: a `FIXED_FD_INSTALL` (kTLS handshake or
    /// detach) that completed during this non-dispatching drain never reaches
    /// `on_fd_install`/`on_detach_install`, which own the furnished fd's
    /// close — so close it here, or a teardown racing an install leaks a real
    /// process fd (it survives the ring's own close; matters when the process
    /// outlives the owner).
    pub(crate) fn cancel_and_reap_all(&mut self) -> errno::Result<()> {
        self.engine
            .cancel_and_reap_all(pack(Op::Cancel, 0, 0), |cqe| {
                let (op, _, _) = unpack(cqe.user_data);
                if matches!(op, Some(Op::FdInstall | Op::DetachInstall))
                    && cqe.res >= 0
                {
                    // SAFETY: `res` is a freshly installed owned process fd
                    // that no handler will take ownership of on this teardown
                    // path.
                    unsafe { libc::close(cqe.res) };
                }
            })
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
        self.engine.stopping()
    }

    /// Teardown drain for a role's `Drop`: cancel and reap every in-flight op
    /// so the kernel holds no reference to a connection buffer before the
    /// buffers are freed. If the drain itself fails — a hard `io_uring_enter`
    /// error (not `EBUSY`/`EAGAIN`, which are retried) that returns with ops
    /// still in flight — leak the kernel-visible buffers instead of freeing
    /// them: the ring fd still closes as the engine drops (cancelling the ops),
    /// but now against permanently-valid memory. Mirrors the `mem::forget` the
    /// peercred probe uses when `io_uring_enter` fails under it.
    pub(crate) fn drain_or_leak(&mut self) {
        if self.cancel_and_reap_all().is_err() {
            self.table.leak();
            self.engine.leak_wake_buf();
        }
    }

    /// Take and clear the `pool_freed` flag: `true` if `reclaim_slot` freed a
    /// slot since the last check, so the role loop can re-arm any listener
    /// parked on a full pool.
    pub(crate) fn take_pool_freed(&mut self) -> bool {
        std::mem::take(&mut self.pool_freed)
    }
}
