//! The engine: one ring plus the state every domain shares — SQE staging with
//! in-flight accounting, the wake eventfd, and the cancel-everything
//! teardown. Tag vocabularies stay with the domains: every method that names
//! an op takes its `user_data` as a parameter, so the engine never interprets
//! a completion.

use crate::errno;
use crate::uring::probe::probe_op_supported;
use crate::uring::ring::Ring;
use crate::uring::sys::*;
use crate::uring::wake::{LoopShared, WakeHandle};
// `LoopShared` is loom-modelled (see `src/uring/wake.rs`), so the engine
// builds it from `crate::sync` — std's outside `--cfg loom`.
use crate::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use crate::sync::Arc;

/// Longest chain [`Engine::stage_chain`] will stage. A cap rather than an
/// open-ended count because every link is one more SQE that must be staged
/// contiguously, and a chain that cannot fit the SQ is an `EBUSY` the caller
/// has to unwind.
///
/// Four covers the deepest shape built only from opcodes that actually
/// fail-fast — `openat2 → writev → writev → close`. It is deliberately *not*
/// sized for a durable publish tail (`write → fsync → link → rename`): three
/// of those four links cannot break a chain, so that sequence must be driven
/// from completions instead. See [`Engine::stage_chain`].
#[cfg(feature = "uring-fs")]
pub(crate) const MAX_CHAIN_LINKS: usize = 4;

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
            wake: WakeHandle::new()?,
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

    /// Stage `n` SQEs as one `IOSQE_IO_LINK` chain under a **single**
    /// `user_data`, counting all `n` as in-flight.
    ///
    /// One token for the whole chain is what makes the rest tractable: links
    /// execute in order and post their CQEs in order, so the domain tracks a
    /// `links_remaining` countdown against one op-table slot instead of `n`
    /// entries; and one `ASYNC_CANCEL` keyed on that token with
    /// `IORING_ASYNC_CANCEL_ALL` reaches every link. A failed link breaks the
    /// chain, but each successor still completes `-ECANCELED`, so the countdown
    /// reaches zero deterministically and in-flight accounting stays exact.
    ///
    /// `IOSQE_CQE_SKIP_SUCCESS` is deliberately not used: the accounting above
    /// assumes one CQE per SQE.
    ///
    /// # Fail-fast applies to some opcodes and not others
    ///
    /// "A failed link cancels the rest" is **not** universal. The kernel
    /// breaks a chain only when the failing op calls `req_set_fail()`:
    ///
    /// | family | breaks the chain? |
    /// |---|---|
    /// | `rw.c`, `splice.c`, `openclose.c`, `nop.c` | yes |
    /// | `fs.c` — linkat/renameat/unlinkat/mkdirat/symlinkat | **no** |
    /// | `sync.c` — fsync/fallocate/sync_file_range | **no** |
    /// | `statx.c`, `xattr.c` — statx, f/getxattr, f/setxattr | **no** |
    /// | any op failing at submission (bad fd, bad prep) | yes |
    ///
    /// An fs op that fails sets its result and stops; its successors run
    /// regardless. Chaining `linkat` to `renameat` and expecting the rename to
    /// be skipped is therefore wrong, and dangerously so — see
    /// `linked_fs_ops_do_not_break_the_chain`, which pins the behaviour.
    /// Sequence fs ops from completions instead.
    #[cfg(feature = "uring-fs")]
    pub(crate) fn stage_chain(
        &mut self,
        user_data: u64,
        n: usize,
        mut fill: impl FnMut(usize, &mut IoUringSqe),
    ) -> errno::Result<()> {
        if n == 0 || n > MAX_CHAIN_LINKS {
            return Err(errno::Errno::EINVAL);
        }
        self.ring.push_sqe_chain(n, |i, sqe| {
            fill(i, sqe);
            sqe.user_data = user_data;
        })?;
        self.inflight += n as u64;
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

    /// Rewind SQE staging and the in-flight count, so a staging-only test can
    /// reuse one engine across iterations. See [`Ring::reset_staging`] for the
    /// conditions that make the rewind sound.
    #[cfg(all(test, not(loom), feature = "uring-fs"))]
    pub(crate) fn reset_staging(&mut self) {
        self.ring.reset_staging();
        self.inflight = 0;
    }

    /// Read back a staged (not yet submitted) SQE. See [`Ring::staged_sqe`].
    #[cfg(all(test, not(loom), feature = "uring-fs"))]
    pub(crate) fn staged_sqe(&self, i: u32) -> IoUringSqe {
        self.ring.staged_sqe(i)
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

#[cfg(all(test, not(loom), feature = "uring-fs"))]
mod tests {
    use super::*;

    const RING_ENTRIES: u32 = 32;
    const POOL: u32 = 8;

    /// Skip where io_uring is unavailable (sandbox/old kernel), like the fs
    /// suites. Nothing here submits, so no other failure mode is tolerated.
    fn engine_or_skip() -> Option<Engine> {
        match Engine::new(RING_ENTRIES, POOL) {
            Ok(e) => Some(e),
            Err(crate::Error::Errno(
                errno::Errno::EPERM
                | errno::Errno::ENOSYS
                | errno::Errno::EACCES,
            )) => None,
            Err(e) => panic!("Engine::new: {e}"),
        }
    }

    /// The load-bearing property: `IOSQE_IO_LINK` on every link but the last,
    /// one shared `user_data`, and per-op flags preserved through the OR.
    #[test]
    fn chain_links_all_but_the_last() {
        let Some(mut eng) = engine_or_skip() else {
            return;
        };
        eng.stage_chain(0xABCD, 4, |i, sqe| {
            sqe.opcode = IORING_OP_READ;
            sqe.fd = i as i32;
            // A caller-set flag must survive the link OR.
            sqe.flags = IOSQE_FIXED_FILE;
        })
        .expect("stage a 4-link chain");

        assert_eq!(eng.inflight, 4, "every link counts as in-flight");
        for i in 0..4u32 {
            let sqe = eng.staged_sqe(i);
            assert_eq!(
                sqe.user_data, 0xABCD,
                "link {i} shares the chain token"
            );
            assert_eq!(sqe.fd, i as i32, "link {i} kept its own fill");
            assert_ne!(
                sqe.flags & IOSQE_FIXED_FILE,
                0,
                "link {i} kept the caller's flags"
            );
            let linked = sqe.flags & IOSQE_IO_LINK != 0;
            assert_eq!(
                linked,
                i < 3,
                "link {i}: IO_LINK set iff another link follows"
            );
        }
    }

    /// A one-link chain is legal and carries no link flag — it is just an op,
    /// which keeps callers from special-casing degenerate chains.
    #[test]
    fn single_link_chain_is_unlinked() {
        let Some(mut eng) = engine_or_skip() else {
            return;
        };
        eng.stage_chain(1, 1, |_, sqe| sqe.opcode = IORING_OP_READ)
            .expect("stage a 1-link chain");
        assert_eq!(eng.inflight, 1);
        assert_eq!(eng.staged_sqe(0).flags & IOSQE_IO_LINK, 0);
    }

    /// Link-breaking works when the failure happens at **submission**: a bad
    /// fd fails `io_init_req`, which marks the request and cancels the rest of
    /// the chain. Contrast `linked_fs_ops_do_not_break_the_chain`.
    #[test]
    fn chain_breaks_on_a_submission_time_failure() {
        let Some(mut eng) = engine_or_skip() else {
            return;
        };
        // SAFETY: /dev/null always opens; the fd is ours to close.
        let good = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDWR) };
        assert!(good >= 0);
        eng.stage_chain(0x1234, 2, |i, sqe| {
            sqe.opcode = IORING_OP_FSYNC;
            sqe.fd = if i == 0 { -1 } else { good };
        })
        .expect("stage");
        eng.ring.submit_and_wait(2).expect("submit");
        let mut got = Vec::new();
        while let Some(c) = eng.ring.reap() {
            got.push(c.res);
        }
        assert_eq!(
            got,
            vec![-libc::EBADF, -libc::ECANCELED],
            "a submission-time failure must cancel the rest of the chain"
        );
        eng.inflight = 0;
        // SAFETY: our fd.
        unsafe { libc::close(good) };
    }

    /// **A failing filesystem op does NOT break its chain**, and this test
    /// exists to keep that surprise documented rather than rediscovered.
    ///
    /// `IOSQE_IO_LINK` cancels successors only when the failing op calls the
    /// kernel's `req_set_fail()`. `io_uring/rw.c`, `splice.c`, `openclose.c`
    /// and `nop.c` do; **`fs.c` (linkat/renameat/unlinkat/mkdirat/symlinkat)
    /// and `sync.c` (fsync/fallocate) do not** — they set the result and stop.
    /// So a link that fails `EEXIST` is followed by a rename that runs anyway.
    ///
    /// The consequence is why the durable-create commit is *not* built as a
    /// chain: link-then-rename would, with a stale staging entry, rename an
    /// unrelated file onto a live object. If this test ever starts failing,
    /// the kernel gained fail-fast for fs ops and that decision can be
    /// revisited.
    #[test]
    fn linked_fs_ops_do_not_break_the_chain() {
        let Some(mut eng) = engine_or_skip() else {
            return;
        };
        let d = crate::tempdir().expect("tempdir");
        let p = d.path();
        std::fs::create_dir(p.join("s")).unwrap();
        std::fs::create_dir(p.join("o")).unwrap();
        std::fs::write(p.join("s/taken"), b"unrelated").unwrap();
        std::fs::write(p.join("o/key"), b"live object").unwrap();
        let cs = std::ffi::CString::new(p.join("s").to_str().unwrap()).unwrap();
        let co = std::ffi::CString::new(p.join("o").to_str().unwrap()).unwrap();
        // SAFETY: valid NUL-terminated paths; the fds are ours to close.
        let (sfd, ofd, tmp) = unsafe {
            (
                libc::open(cs.as_ptr(), libc::O_PATH | libc::O_DIRECTORY),
                libc::open(co.as_ptr(), libc::O_PATH | libc::O_DIRECTORY),
                libc::open(cs.as_ptr(), libc::O_TMPFILE | libc::O_RDWR, 0o644),
            )
        };
        assert!(sfd >= 0 && ofd >= 0 && tmp >= 0);
        let (empty, taken, key) = (c"", c"taken", c"key");

        // Link the unnamed file onto an occupied name (fails EEXIST), with a
        // rename of that same name linked behind it.
        eng.stage_chain(0x5678, 2, |i, sqe| match i {
            0 => {
                sqe.opcode = IORING_OP_LINKAT;
                sqe.fd = tmp;
                sqe.addr = empty.as_ptr() as u64;
                sqe.off_addr2 = taken.as_ptr() as u64;
                sqe.len = sfd as u32;
                sqe.op_flags = libc::AT_EMPTY_PATH as u32;
            }
            _ => {
                sqe.opcode = IORING_OP_RENAMEAT;
                sqe.fd = sfd;
                sqe.addr = taken.as_ptr() as u64;
                sqe.off_addr2 = key.as_ptr() as u64;
                sqe.len = ofd as u32;
            }
        })
        .expect("stage");
        eng.ring.submit_and_wait(2).expect("submit");
        let mut got = Vec::new();
        while let Some(c) = eng.ring.reap() {
            got.push(c.res);
        }
        assert_eq!(
            got,
            vec![-libc::EEXIST, 0],
            "fs ops do not set REQ_F_FAIL, so the rename runs despite the \
             link failing (see the doc comment)"
        );
        assert_eq!(
            std::fs::read(p.join("o/key")).unwrap(),
            b"unrelated",
            "and it clobbered the target with an unrelated file — exactly the \
             corruption that rules chains out for the commit path"
        );
        eng.inflight = 0;
        // SAFETY: our fds.
        unsafe {
            libc::close(sfd);
            libc::close(ofd);
            libc::close(tmp);
        }
    }

    /// Out-of-range lengths are rejected *before* anything is staged, so a
    /// rejected chain cannot leave a partial chain in the SQ.
    #[test]
    fn chain_bounds_are_rejected_without_staging() {
        let Some(mut eng) = engine_or_skip() else {
            return;
        };
        for n in [0, MAX_CHAIN_LINKS + 1] {
            assert_eq!(
                eng.stage_chain(1, n, |_, _| unreachable!("must not fill")),
                Err(errno::Errno::EINVAL),
                "n = {n}"
            );
            assert_eq!(eng.inflight, 0, "n = {n}: nothing was staged");
        }
    }
}
