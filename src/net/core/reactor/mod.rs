//! The role-generic reactor core: [`Reactor`], the io_uring engine both the
//! server and client roles embed. Holds the ring, the connection table, the
//! projected [`CoreConfig`], the shared cross-thread flags/stats, and the
//! kernel-touched landing pads; the role wrappers (`net::server` and
//! `net::client`) own admission/listen/connect/protocol on top of it.
//!
//! The engine is split by lifecycle stage across the submodules - `io` (the
//! request data plane's submission/completion helpers), `close` (teardown),
//! `wake` (the wake arm and drain quiescence check) - plus this file's SQE
//! staging and slot bookkeeping every stage shares.

mod close;
mod io;
mod wake;

// The role layers are the only consumers, so a core-alone build has
// none: gate the re-export or it is an unused import there.
#[cfg(any(feature = "net-server", feature = "net-client"))]
pub(crate) use io::{Enacted, Gate, RecvStep, SendStep, SpliceStep};
#[cfg(feature = "net-server")]
pub(crate) use io::{RECV_LEASE_DEPTH, recv_pool_buf_len};

/// The pure framing decision, re-exported only under the `__fuzz` feature for
/// the fuzz harness (`fuzz/fuzz_targets/framing_arithmetic.rs`). Not part of
/// the stable API.
#[cfg(feature = "__fuzz")]
pub use io::{FrameStep, frame_step};

use crate::errno;
use crate::net::core::config::CoreConfig;
use crate::net::core::conn::{Op, pack, unpack};
use crate::net::core::handles::{CloseHook, StatsInner, stat};
use crate::net::core::table::ConnTable;
use crate::sync::Arc;
#[cfg(feature = "net-server")]
use crate::uring::bufring::BufPool;
use crate::uring::engine::Engine;
use crate::uring::sys::*;
use std::sync::atomic::Ordering;

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
    /// Relative idle timeout - meaningful iff `cfg.idle_timeout` is set.
    pub(crate) idle_timeout: KernelTimespec,
    /// Relative send timeout - meaningful iff `cfg.send_timeout` is set.
    pub(crate) send_timeout: KernelTimespec,
    /// Relative request-receive timeout - meaningful iff `cfg.request_timeout`
    /// is set.
    pub(crate) request_timeout: KernelTimespec,
    /// Relative kTLS handshake timeout - meaningful iff
    /// `cfg.tls_handshake_timeout` is set (bounds the parked-handshake slot).
    pub(crate) tls_handshake: KernelTimespec,
    /// Backoff before retrying a recv parked on an exhausted buffer pool --
    /// meaningful iff `cfg.recv_shortage_retry` is set.
    pub(crate) recv_retry: KernelTimespec,
}

/// The stream reactor: the shared [`Engine`] plus the connection table and
/// the state every stream stage shares. A role (`Server` or `Client`) embeds
/// one as `core` and drives it with its own admission/connect/protocol code.
///
/// Field order is load-bearing: `table` is declared before `engine` so the
/// connection buffers drop first - freed before the engine's ring is unmapped
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
    /// Connections `(slot, generation)` that began closing this dispatch and
    /// carry an embedded fs pool: the server drains this after the reap loop to
    /// sweep any fs files they left open (`FsCore::close_owned_by`). Recorded
    /// in `close_conn` (once per connection); a server-only concern, so it is
    /// gated on the combined feature.
    #[cfg(all(feature = "net-server", feature = "uring-fs"))]
    pub(crate) fs_closed: Vec<(u32, u64)>,
    /// Whether this reactor actually has an fs pool to sweep. Only a server
    /// built with `fs_ops > 0` sets it; a client (which drains nothing) and a
    /// pool-less server leave it false, so `close_conn` never records into
    /// `fs_closed` for them - otherwise a client would grow that Vec unbounded.
    #[cfg(all(feature = "net-server", feature = "uring-fs"))]
    pub(crate) has_fs_pool: bool,
    /// Recv buffers drawn from a registered ring rather than owned per
    /// connection.
    ///
    /// A connection takes one when data actually arrives and gives it back
    /// once its message is consumed, so a keep-alive connection parked on an
    /// idle recv holds nothing - `IOSQE_BUFFER_SELECT` has the kernel pick a
    /// buffer at *completion* rather than at submit, which is the whole
    /// reason this is a provided-buffer ring and not a free list.
    ///
    /// Declared after `table` so connections drop first: a claim points into
    /// this pool's storage.
    #[cfg(feature = "net-server")]
    pub(crate) recv_bufs: Option<BufPool>,
    /// Buffers a file-sourced response body is read into, on their own
    /// group. Ring-global: every connection on this reactor draws from it,
    /// so the memory tracks bodies in flight rather than the connection
    /// table. Declared beside `recv_bufs` and after `table` for the same
    /// reason - a queued send segment points into it.
    #[cfg(all(feature = "net-server", feature = "uring-fs"))]
    pub(crate) body_bufs: Option<BufPool>,
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
            #[cfg(all(feature = "net-server", feature = "uring-fs"))]
            fs_closed: Vec::new(),
            #[cfg(all(feature = "net-server", feature = "uring-fs"))]
            has_fs_pool: false,
            #[cfg(feature = "net-server")]
            recv_bufs: None,
            #[cfg(all(feature = "net-server", feature = "uring-fs"))]
            body_bufs: None,
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

    /// Cancel every outstanding op, then reap until nothing is in flight --
    /// [`Engine::cancel_and_reap_all`] under the stream tag vocabulary, with
    /// the stream-specific sweep: a `FIXED_FD_INSTALL` (kTLS handshake or
    /// detach) that completed during this non-dispatching drain never reaches
    /// `on_fd_install`/`on_detach_install`, which own the furnished fd's
    /// close - so close it here, or a teardown racing an install leaks a real
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
        // Before the connection goes away, so its buffer can be reissued
        // and its group can eventually be retired.
        #[cfg(feature = "net-server")]
        if let Some(claim) = self.table.forfeit_recv_claim(slot)
            && let Some(pool) = self.recv_bufs.as_mut()
        {
            pool.release(claim.bid);
            self.sync_recv_buf_stats();
        }
        // Segments still queued name ring buffers; the connection is about
        // to go away and they are owed back.
        #[cfg(all(feature = "net-server", feature = "uring-fs"))]
        {
            let bids = self.table.drain_pooled_send_bids(slot);
            if !bids.is_empty() {
                if let Some(pool) = self.body_bufs.as_mut() {
                    for bid in bids {
                        pool.release(bid);
                    }
                }
                self.sync_recv_buf_stats();
            }
        }
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
    /// buffers are freed. If the drain itself fails - a hard `io_uring_enter`
    /// error (not `EBUSY`/`EAGAIN`, which are retried) that returns with ops
    /// still in flight - leak the kernel-visible buffers instead of freeing
    /// them: the ring fd still closes as the engine drops (cancelling the ops),
    /// but now against permanently-valid memory. Mirrors the `mem::forget` the
    /// peercred probe uses when `io_uring_enter` fails under it.
    /// Returns `true` if the drain failed and the buffers were leaked - an
    /// embedding host with its own kernel-visible buffers on this ring (the
    /// server's fs op table) must then leak those too.
    pub(crate) fn drain_or_leak(&mut self) -> bool {
        if self.cancel_and_reap_all().is_err() {
            self.table.leak();
            // Registered recv buffers are kernel-visible on this same ring:
            // an op still in flight names one by index, so unmapping the
            // group would hand the kernel freed pages to write into.
            #[cfg(feature = "net-server")]
            if let Some(pool) = self.recv_bufs.take() {
                std::mem::forget(pool);
            }
            #[cfg(all(feature = "net-server", feature = "uring-fs"))]
            if let Some(pool) = self.body_bufs.take() {
                std::mem::forget(pool);
            }
            self.engine.leak_wake_buf();
            true
        } else {
            false
        }
    }

    /// Take and clear the `pool_freed` flag: `true` if `reclaim_slot` freed a
    /// slot since the last check, so the role loop can re-arm any listener
    /// parked on a full pool.
    pub(crate) fn take_pool_freed(&mut self) -> bool {
        std::mem::take(&mut self.pool_freed)
    }
}
