//! The engine: one ring plus the state every domain shares — SQE staging with
//! in-flight accounting, the wake eventfd, and the cancel-everything
//! teardown. Tag vocabularies stay with the domains: every method that names
//! an op takes its `user_data` as a parameter, so the engine never interprets
//! a completion.

use crate::errno;
use crate::uring::probe::probe_op_supported;
use crate::uring::ring::Ring;
use crate::uring::sys::*;
use crate::uring::wake::{create_eventfd, LoopShared, WakeHandle};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

/// The role-agnostic io_uring engine a domain stack embeds. Field order is
/// load-bearing: the embedding struct declares its buffer-owning tables
/// before the engine, and `ring` is this struct's last field — so every
/// kernel-visible buffer drops before the ring is unmapped and its pool
/// descriptors close (the kernel must never touch a freed buffer).
pub(crate) struct Engine {
    /// Stop/graceful flags + the wake eventfd, shared with every cross-thread
    /// handle.
    pub(crate) shared: Arc<LoopShared>,
    /// Landing pad for the wake eventfd `READ` (the kernel drains the counter
    /// into it on completion). Boxed so the address stays stable for the
    /// in-flight op no matter where the owning engine moves.
    pub(crate) wake_buf: Box<u64>,
    /// Operations currently in flight on the ring.
    pub(crate) inflight: u64,
    /// Whether the kernel supports `IORING_OP_FIXED_FD_INSTALL` (Linux ≥ 6.8;
    /// probed at construction) — required to furnish real fds (kTLS
    /// handshakes, connection detach).
    pub(crate) fixed_fd_install: bool,
    /// Declared last so it drops after everything above; see the struct doc.
    pub(crate) ring: Ring,
}

impl Engine {
    /// Build the ring, register a sparse fixed-file pool of `pool_slots`,
    /// run the universal capability probe, and wire the wake eventfd. Domain
    /// probes (socket commands, TLS ULP) run afterwards against
    /// [`Engine::ring`].
    pub(crate) fn new(entries: u32, pool_slots: u32) -> crate::Result<Engine> {
        Self::assemble(Ring::new(entries)?, |ring| {
            ring.register_pool(pool_slots)
        })
    }

    /// Like [`Engine::new`], but registers one shared table of
    /// `pool_slots + fs_slots` with the auto-allocation range confined to the
    /// connection pool `[0, pool_slots)` — the embedded fs reactor owns the
    /// upper range at explicit indices ([`Ring::register_pool_with_fs`]).
    #[cfg(all(feature = "net-server", feature = "async-fs"))]
    pub(crate) fn new_with_fs(
        entries: u32,
        pool_slots: u32,
        fs_slots: u32,
    ) -> crate::Result<Engine> {
        Self::assemble(Ring::new(entries)?, |ring| {
            ring.register_pool_with_fs(pool_slots, fs_slots)
        })
    }

    fn assemble(
        ring: Ring,
        register: impl FnOnce(&Ring) -> errno::Result<()>,
    ) -> crate::Result<Engine> {
        register(&ring)?;
        let fixed_fd_install =
            probe_op_supported(&ring, IORING_OP_FIXED_FD_INSTALL);
        let shared = Arc::new(LoopShared {
            stop: AtomicBool::new(false),
            graceful: AtomicBool::new(false),
            grace_ms: AtomicU64::new(0),
            wake: WakeHandle {
                fd: create_eventfd()?,
            },
        });
        Ok(Engine {
            shared,
            wake_buf: Box::new(0),
            inflight: 0,
            fixed_fd_install,
            ring,
        })
    }

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
    /// submission as its head), counting both as in-flight. Each yields its
    /// own terminal completion.
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

    /// Arm the wake-eventfd `READ` under the domain's wake tag. Reading the
    /// 8-byte counter directly (rather than polling the fd) auto-arms
    /// io_uring's internal fast-poll and completes only once the fd is
    /// readable, draining the counter to 0 in the same op — no separate poll
    /// SQE, no follow-up `read()` syscall.
    pub(crate) fn arm_wake(&mut self, user_data: u64) -> errno::Result<()> {
        let fd = self.shared.wake.as_raw_fd();
        let buf = std::ptr::addr_of_mut!(*self.wake_buf) as u64;
        self.stage(user_data, move |sqe| {
            sqe.opcode = IORING_OP_READ;
            sqe.fd = fd;
            sqe.addr = buf;
            sqe.len = 8;
        })
    }

    /// Cancel every outstanding op, then reap until nothing is in flight.
    /// `cancel_user_data` tags the `CANCEL_ANY` op; every reaped CQE is
    /// handed to `on_reaped` so the domain can release resources a
    /// non-dispatching drain would otherwise leak (the stream stack closes
    /// fds a completed `FIXED_FD_INSTALL` furnished, for example).
    pub(crate) fn cancel_and_reap_all(
        &mut self,
        cancel_user_data: u64,
        mut on_reaped: impl FnMut(&IoUringCqe),
    ) -> errno::Result<()> {
        if self.inflight > 0 {
            self.stage(cancel_user_data, |sqe| {
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
                on_reaped(&cqe);
            }
        }
        self.ring.submit()
    }

    pub(crate) fn stopping(&self) -> bool {
        self.shared.stop.load(Ordering::Acquire)
    }

    /// Leak the wake landing pad without freeing it. On a failed teardown drain
    /// the armed wake `READ` may still be in flight, and completing it writes 8
    /// bytes into [`Engine::wake_buf`]; leaking keeps that address permanently
    /// valid rather than freeing heap the kernel is about to write. Pairs with
    /// the connection-buffer leak on the same teardown path.
    pub(crate) fn leak_wake_buf(&mut self) {
        std::mem::forget(std::mem::replace(&mut self.wake_buf, Box::new(0)));
    }
}
