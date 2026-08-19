//! The standalone host: [`UringFs`] owns the engine and the fs core, runs
//! the completion loop on its thread, and mints the cross-thread handles.
//! (The core is host-agnostic - a `net` server is the other host, driving the
//! same [`FsCore`] on its own ring.)

use super::core::{
    deliver_embedded, deliver_pool_completions, FsCore, FsWaiter, TAG_CANCEL,
    TAG_WAKE,
};
use super::{
    FsHandle, FsInject, FsOutcome, OffloadBounds, Personality, PrivilegedXattrs,
};
use crate::errno::{self, Errno};
use crate::sync::{mpsc, Arc};
use crate::uring::engine::Engine;
use crate::uring::probe::probe_op_supported;
use crate::uring::sys::{
    register_personality, IoUringCqe, IORING_CQE_F_MORE, IORING_OP_OPENAT2,
};
use crate::uring::user_data::{pack_raw, unpack_raw, SLOT_MASK, TAG_FS_DOMAIN};
use crate::uring::wake::LoopShared;
use std::fmt;
use std::sync::atomic::Ordering;

/// Sizing for an [`UringFs`], defaulted for a **server**: a request handler
/// fans out many independent operations and collects their completions. Both
/// fields are public; a consumer with a different shape sets its own.
///
/// There is deliberately no open-file count here. Files are plain
/// reference-counted descriptors (`Arc<OwnedFd>`) and no fs operation sets
/// `IOSQE_FIXED_FILE`, so the reactor registers no fixed-file pool and has no
/// ceiling of its own to configure - the limit on concurrently open files is
/// the process's `RLIMIT_NOFILE`.
///
/// # `entries` and `ops` bound different things
///
/// `entries` is the submission queue, and `io_uring_enter` **consumes** SQEs
/// into kernel-side requests, freeing the slots. Staging past a full queue
/// therefore flushes and continues rather than failing, so `entries` sets how
/// much work rides on one `io_uring_enter` - a batching knob, not a ceiling.
///
/// `ops` is the table an in-flight operation holds a slot in until its
/// completion reaps, so **`ops` is the real concurrency ceiling**, and
/// exhausting it is what fails a fan-out with `EBUSY`. It should exceed
/// `entries`, not match it.
///
/// # Only `entries` costs locked memory
///
/// A ring's queues are charged against `RLIMIT_MEMLOCK` - `__io_account_mem`
/// (`io_uring/rsrc.c:39-47`) tests `rlimit(RLIMIT_MEMLOCK)` with **no
/// capability bypass, so running as root does not exempt it**. The cost is
/// about `entries x 96` bytes (a 64-byte SQE array plus a double-sized
/// completion queue), so the default is roughly 400 KiB per reactor against a
/// common 8 MiB limit; measured, the 22nd concurrent default-sized ring fails
/// `ENOMEM`.
///
/// `ops` is ordinary heap - about 180 bytes per slot, so the default costs
/// ~5.8 MiB of RSS, allocated once at construction - and is not accounted
/// against any limit. That asymmetry is why the two defaults differ by 8x:
/// raising concurrency is cheap, raising the batch size is not.
///
/// One reactor sits well inside 8 MiB. Several (a `reuse_port` reactor per
/// core), or a consumer that also registers buffers, must raise the limit
/// (`LimitMEMLOCK=` in the unit, or `setrlimit` before the first
/// [`UringFs::new`]) - the symptom otherwise is a bare `ENOMEM` from ring
/// creation with nothing pointing at the cause.
#[derive(Clone, Copy, Debug)]
pub struct FsConfig {
    /// Submission-queue depth (rounded up to a power of two by the kernel) --
    /// how much work rides on one `io_uring_enter`. The field that costs
    /// `RLIMIT_MEMLOCK`; see the type docs.
    pub entries: u32,
    /// Op-table slots - the maximum number of concurrently in-flight
    /// operations, and the ceiling a fan-out actually hits: submitting past
    /// it fails `EBUSY` however deep the ring is. Plain heap at ~180 bytes a
    /// slot, so this is the cheap axis to raise.
    pub ops: u32,
    /// Sizing for the blocking-offload pool that backs `FsConn::offload` and
    /// the hybrid lister. Per ring; see [`OffloadBounds`].
    pub offload: OffloadBounds,
}

impl Default for FsConfig {
    fn default() -> FsConfig {
        FsConfig {
            entries: 4096,
            ops: 32768,
            offload: OffloadBounds::default(),
        }
    }
}

/// Stops a running [`UringFs::run`] loop from any thread.
#[derive(Clone, Debug)]
pub struct ShutdownHandle {
    shared: Arc<LoopShared>,
}

impl ShutdownHandle {
    /// Stop the loop: in-flight operations are cancelled (parked callers
    /// observe `ECANCELED`/`ECONNABORTED`) and [`UringFs::run`] returns.
    /// Safe to call from any thread and more than once. Infallible: a flag
    /// store plus an eventfd poke.
    pub fn shutdown(&self) {
        self.shared.stop.store(true, Ordering::Release);
        self.shared.wake.poke();
    }
}

/// The standalone fs reactor: one ring, one loop thread, open files as plain
/// reference-counted fds (`Arc<OwnedFd>`, closed by last reference), every
/// operation stamped with a [`Personality`].
///
/// Like the `net` roles it is deliberately `!Send` (the ring is
/// single-thread-owned): build it, mint [`FsHandle`]s/[`ShutdownHandle`]s
/// for other threads, then park the owning thread in [`UringFs::run`].
pub struct UringFs {
    // Field order is load-bearing (as in the net roles): `fs` owns every
    // kernel-visible buffer and is declared before `eng`, so those buffers
    // drop before the engine unmaps the ring - the kernel must never touch a
    // freed buffer.
    fs: FsCore,
    inject_tx: mpsc::Sender<FsInject>,
    inject_rx: mpsc::Receiver<FsInject>,
    eng: Engine,
}

impl fmt::Debug for UringFs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UringFs").finish_non_exhaustive()
    }
}

impl Drop for UringFs {
    fn drop(&mut self) {
        // On the normal path `run` already drained, so this is a cheap no-op
        // (nothing in flight -> `cancel_and_reap_all` returns at once). On an
        // early drop, or a panic unwinding out of `run`, drain here - and if
        // that drain fails, leak the op buffers rather than free them under a
        // still-live kernel op (mirrors the net `Server::drop`).
        let _ = self.drain_or_leak();
    }
}

impl UringFs {
    /// Build the ring and probe the kernel (`OPENAT2` as the canary for the
    /// op set). Fails with `Validation` on an unsupported kernel and with the
    /// underlying errno where io_uring itself is unavailable.
    ///
    /// No fixed-file pool is registered: fs ops name files by raw descriptor.
    pub fn new(cfg: FsConfig) -> crate::Result<UringFs> {
        if cfg.ops < 2 || u64::from(cfg.ops) > SLOT_MASK {
            return Err(crate::Error::Validation(
                "FsConfig::ops must be in 2..=SLOT_MASK".into(),
            ));
        }
        if cfg.entries < 4 {
            return Err(crate::Error::Validation(
                "FsConfig::entries must be at least 4".into(),
            ));
        }
        let eng = Engine::without_pool(cfg.entries)?;
        if !probe_op_supported(&eng.ring, IORING_OP_OPENAT2) {
            return Err(crate::Error::Validation(
                "uring_fs requires io_uring OPENAT2 (Linux >= 5.6); this \
                 kernel's io_uring does not support it"
                    .into(),
            ));
        }
        let (inject_tx, inject_rx) = mpsc::channel();
        Ok(UringFs {
            fs: FsCore::new(cfg.ops, cfg.offload),
            inject_tx,
            inject_rx,
            eng,
        })
    }

    /// This reactor's ring descriptor - handed to the credential broker so
    /// it can register personalities on this ring (and to nothing else: a
    /// ring fd plus its personality table is a credential capability).
    pub(crate) fn ring_fd(&self) -> std::os::fd::RawFd {
        self.eng.ring.raw_fd()
    }

    /// Register the calling process's **current** credentials as a
    /// [`Personality`] - the identity every subsequent operation must name.
    ///
    /// Unprivileged: registering your own credentials needs no capability.
    /// The snapshot is frozen at this call (a later `setgroups`/capability
    /// drop does not update it - register again for a fresh one). Ids are
    /// kernel-allocated from 1 upward, cyclically, without immediate reuse.
    pub fn register_self(&self) -> crate::Result<Personality> {
        let id = register_personality(self.eng.ring.raw_fd())?;
        Ok(Personality(id))
    }

    /// Declare which extended attributes are written under this reactor's
    /// ambient credentials rather than the requesting [`Personality`] - see
    /// [`PrivilegedXattrs`] for the rules and the reasoning.
    ///
    /// Setup-time only, and enforced as such: [`UringFs::run`] borrows `&mut
    /// self` for the lifetime of the loop, so this cannot be called while
    /// operations are in flight. Replaces any previous policy; the default
    /// permits nothing.
    pub fn set_privileged_xattrs(&mut self, policy: PrivilegedXattrs) {
        self.fs.set_privileged_xattrs(policy);
    }

    /// A `Send + Sync` handle for submitting operations from other threads.
    pub fn handle(&self) -> FsHandle {
        FsHandle {
            tx: self.inject_tx.clone(),
            shared: self.eng.shared.clone(),
            pool: self.fs.pool_handle(),
        }
    }

    /// A handle that stops [`UringFs::run`] from any thread.
    pub fn shutdown_handle(&self) -> ShutdownHandle {
        ShutdownHandle {
            shared: self.eng.shared.clone(),
        }
    }

    /// Run the completion loop until a [`ShutdownHandle`] stops it or a
    /// fatal ring error occurs. In-flight operations are cancelled and
    /// drained before returning; parked handle callers are unblocked with
    /// errors. Terminal: build a fresh `UringFs` rather than re-running.
    pub fn run(&mut self) -> crate::Result<()> {
        self.eng.arm_wake(pack_raw(TAG_WAKE, 0, 0))?;
        let run = self.run_loop();
        let drained = self.drain_teardown();
        run?;
        drained?;
        Ok(())
    }

    fn run_loop(&mut self) -> errno::Result<()> {
        while !self.eng.stopping() {
            if self.eng.inflight == 0 {
                break; // nothing outstanding; avoid blocking forever
            }
            self.eng.ring.submit_and_wait(1)?;
            while let Some(cqe) = self.eng.ring.reap() {
                self.dispatch(cqe)?;
            }
        }
        Ok(())
    }

    fn dispatch(&mut self, cqe: IoUringCqe) -> errno::Result<()> {
        // Count the reaped CQE off `inflight` before its handler runs, so an
        // error return can't leave the count permanently high (which would
        // hang the teardown drain).
        if cqe.flags & IORING_CQE_F_MORE == 0 {
            self.eng.inflight = self.eng.inflight.saturating_sub(1);
        }
        let (tag, slot, gen32) = unpack_raw(cqe.user_data);
        if tag & TAG_FS_DOMAIN == 0 {
            return Ok(()); // not ours (nothing stages such tags today)
        }
        match tag {
            TAG_WAKE => {
                if !self.eng.stopping() {
                    self.eng.arm_wake(pack_raw(TAG_WAKE, 0, 0))?;
                }
                self.drain_injects();
                // Fire on-loop deliveries from finished off-loop pool jobs
                // (`FsConn::offload` and the hybrid lister). Additive: the
                // `FsHandle` path never touches the pool.
                deliver_pool_completions(&mut self.fs, &mut self.eng, true);
            }
            TAG_CANCEL => {}
            // Deliver a completion. An `FsHandle` op parks a channel waiter
            // (routed inside `on_cqe`, returns `None`); an embedded on-loop op
            // (`FsConn`) hands its callback back to fire here with a fresh
            // owner-scoped `FsConn`.
            _ => {
                let reaped =
                    self.fs.on_cqe(&mut self.eng, tag, slot, gen32, cqe.res);
                deliver_embedded(&mut self.fs, &mut self.eng, reaped, true);
            }
        }
        Ok(())
    }

    fn drain_injects(&mut self) {
        while let Ok(msg) = self.inject_rx.try_recv() {
            match msg {
                FsInject::Open {
                    pers,
                    anchor,
                    path,
                    how,
                    reply,
                } => self.fs.submit_open(
                    &mut self.eng,
                    pers,
                    anchor,
                    path,
                    how,
                    FsWaiter::Channel(reply),
                ),
                FsInject::Rw {
                    tag,
                    pers,
                    file,
                    bufs,
                    off,
                    rw_flags,
                    reply,
                } => self.fs.submit_rw(
                    &mut self.eng,
                    tag,
                    pers,
                    file,
                    bufs,
                    off,
                    rw_flags,
                    FsWaiter::Channel(reply),
                ),
                FsInject::Fsync {
                    pers,
                    file,
                    datasync,
                    offset,
                    length,
                    reply,
                } => self.fs.submit_fsync(
                    &mut self.eng,
                    pers,
                    file,
                    datasync,
                    offset,
                    length,
                    FsWaiter::Channel(reply),
                ),
                FsInject::FdMeta {
                    tag,
                    pers,
                    file,
                    name,
                    value,
                    off,
                    len64,
                    aux32,
                    reply,
                } => self.fs.submit_fd_meta(
                    &mut self.eng,
                    tag,
                    pers,
                    file,
                    name,
                    value,
                    off,
                    len64,
                    aux32,
                    FsWaiter::Channel(reply),
                ),
                FsInject::FdMetaAsRoot {
                    file,
                    name,
                    value,
                    reply,
                } => self.fs.submit_fgetxattr_as_root(
                    &mut self.eng,
                    file,
                    name,
                    value,
                    FsWaiter::Channel(reply),
                ),
                FsInject::FRemoveXattr { file, name, reply } => {
                    self.fs.remove_priv_xattr(file, name, reply)
                }
                FsInject::PathOp {
                    tag,
                    pers,
                    a1,
                    n1,
                    a2,
                    n2,
                    flags,
                    len_arg,
                    reply,
                } => self.fs.submit_path_op(
                    &mut self.eng,
                    tag,
                    pers,
                    a1,
                    n1,
                    a2,
                    n2,
                    flags,
                    len_arg,
                    FsWaiter::Channel(reply),
                ),
                FsInject::LinkatFile {
                    pers,
                    file,
                    a2,
                    n2,
                    reply,
                } => self.fs.submit_linkat_file(
                    &mut self.eng,
                    pers,
                    file,
                    a2,
                    n2,
                    FsWaiter::Channel(reply),
                ),
            }
        }
    }

    /// Teardown: cancel everything, reap to zero (routing each fs completion
    /// so waiters unblock and buffers free), then flush the inject queue and
    /// any parked close waiters with `ECONNABORTED`.
    /// Cancel and reap everything; if that drain FAILS (a hard ring error
    /// with ops possibly still in flight), leak the op buffers and the wake
    /// pad rather than free memory the kernel may still be writing into. The
    /// net stack does the same on its teardown-drain failure.
    fn drain_or_leak(&mut self) -> errno::Result<()> {
        let fs = &mut self.fs;
        let drained = self
            .eng
            .cancel_and_reap_all(pack_raw(TAG_CANCEL, 0, 0), |cqe| {
                fs.on_drain_cqe(cqe)
            });
        if drained.is_err() {
            self.fs.leak();
            self.eng.leak_wake_buf();
        }
        drained
    }

    fn drain_teardown(&mut self) -> crate::Result<()> {
        let drained = self.drain_or_leak();
        while let Ok(msg) = self.inject_rx.try_recv() {
            let (reply, bufs) = match msg {
                FsInject::Open { reply, .. } => (Some(reply), Vec::new()),
                FsInject::Rw { reply, bufs, .. } => (Some(reply), bufs),
                // The pooled lease rides inside `reply` and round-trips (or
                // returns to the pool) via `ReplyTo::send`.
                // A late cancel request for an op that is being torn down
                // anyway: nothing to reply to, nothing to reclaim.
                FsInject::Fsync { reply, .. } => (Some(reply), Vec::new()),
                FsInject::FdMeta { reply, value, .. } => {
                    (Some(reply), vec![value])
                }
                FsInject::FdMetaAsRoot { reply, value, .. } => {
                    (Some(reply), vec![value])
                }
                FsInject::FRemoveXattr { reply, .. } => {
                    (Some(reply), Vec::new())
                }
                FsInject::PathOp { reply, .. } => (Some(reply), Vec::new()),
                FsInject::LinkatFile { reply, .. } => (Some(reply), Vec::new()),
            };
            if let Some(reply) = reply {
                let _ = reply.send(FsOutcome::new(
                    Err(Errno::ECONNABORTED),
                    bufs,
                    None,
                    None,
                ));
            }
        }
        drained?;
        Ok(())
    }
}

/// Kernel-convention pins that need crate internals (raw rings, forged
/// tokens): the ALLOC1 personality-id contract, the `SINGLE_ISSUER`
/// registration gate, the explicit-index install `res` convention, and
/// stale-token/stale-personality inertness. Environmental skips follow the
/// integration suites' discipline (`TRUENAS_ROS_REQUIRE_IO_URING`).
#[cfg(all(test, not(loom)))]
mod tests {
    use super::*;
    use crate::sync_fs::openat2::RawOpenHow;
    use crate::sync_fs::{OFlag, OpenHow};
    use crate::uring::ring::Ring;
    use crate::uring::sys::{
        io_uring_setup, unregister_personality, IoUringParams,
        IORING_OP_FGETXATTR, IORING_OP_FSETXATTR, IORING_SETUP_SINGLE_ISSUER,
    };
    use crate::uring_fs::{Anchor, FsConfig, Personality, RwFlags};
    use std::ffi::CString;
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;

    fn skip_unavailable(e: Errno) -> bool {
        let unavailable =
            matches!(e, Errno::EPERM | Errno::ENOSYS | Errno::EACCES);
        if unavailable {
            assert!(
                std::env::var_os("TRUENAS_ROS_REQUIRE_IO_URING").is_none(),
                "TRUENAS_ROS_REQUIRE_IO_URING set but io_uring unavailable: \
                 {e}"
            );
        }
        unavailable
    }

    fn ring_or_skip(entries: u32) -> Option<Ring> {
        match Ring::new(entries) {
            Ok(r) => Some(r),
            Err(e) if skip_unavailable(e) => None,
            Err(e) => panic!("Ring::new: {e}"),
        }
    }

    /// The ALLOC1 contract this design leans on: ids start at 1 (0 stays the
    /// "ambient creds" SQE sentinel), allocate cyclically, and an
    /// unregistered id is not immediately reused.
    #[test]
    fn personality_ids_start_at_one_and_do_not_reuse() {
        let Some(ring) = ring_or_skip(4) else { return };
        let fd = ring.raw_fd();
        assert_eq!(register_personality(fd), Ok(1));
        assert_eq!(register_personality(fd), Ok(2));
        assert_eq!(register_personality(fd), Ok(3));
        unregister_personality(fd, 1).expect("unregister");
        assert_eq!(register_personality(fd), Ok(4), "cyclic, no reuse");
    }

    /// sec. 6.3 of the fs-reactor design: a `SINGLE_ISSUER` ring refuses
    /// registration from any task but its creator with `-EEXIST` - the flag
    /// our rings must never set (the credential broker registers from
    /// outside). Pin both directions.
    #[test]
    fn single_issuer_gates_cross_thread_registration() {
        let mut p = IoUringParams {
            flags: IORING_SETUP_SINGLE_ISSUER,
            ..Default::default()
        };
        let fd = match io_uring_setup(4, &mut p) {
            Ok(fd) => fd,
            // EINVAL: kernel predates the flag (< 6.0) - nothing to pin.
            Err(Errno::EINVAL) => return,
            Err(e) if skip_unavailable(e) => return,
            Err(e) => panic!("io_uring_setup: {e}"),
        };
        let raw = fd.as_raw_fd();
        std::thread::scope(|s| {
            s.spawn(move || {
                assert_eq!(
                    register_personality(raw),
                    Err(Errno::EEXIST),
                    "cross-task register must hit the SINGLE_ISSUER gate"
                );
            });
        });
        // The creating task itself may register.
        assert!(register_personality(raw).is_ok());
    }

    /// The explicit-index install convention: `OPENAT2` with
    /// `file_index = slot + 1` completes with `res == 0` (not an fd number).
    /// Raw-ring test on purpose - it pins the kernel, not our plumbing.
    #[test]
    fn explicit_index_install_res_is_zero() {
        let Some(mut ring) = ring_or_skip(8) else {
            return;
        };
        ring.register_pool(4).expect("register pool");
        let dir = crate::tempdir().unwrap();
        let path =
            CString::new(dir.path().join("f").as_os_str().as_bytes()).unwrap();
        let how = RawOpenHow {
            flags: (libc::O_CREAT | libc::O_WRONLY) as u64,
            mode: 0o600,
            resolve: 0,
        };
        ring.push_sqe(|sqe| {
            sqe.opcode = IORING_OP_OPENAT2;
            sqe.fd = libc::AT_FDCWD;
            sqe.addr = path.as_ptr() as u64;
            sqe.off_addr2 = &how as *const RawOpenHow as u64;
            sqe.len = std::mem::size_of::<RawOpenHow>() as u32;
            sqe.file_index = 1; // slot 0
            sqe.user_data = 7;
        })
        .expect("stage");
        ring.submit_and_wait(1).expect("submit");
        let cqe = ring.reap().expect("cqe");
        assert_eq!(cqe.user_data, 7);
        assert_eq!(
            cqe.res, 0,
            "explicit-index install must complete with res == 0"
        );
    }

    /// Pin the xattr SQE field packing - `addr` = name, `addr2` = value,
    /// `len` = size, `xattr_flags` = flags - independently of the
    /// fd-based xattr ops, which need no capability gate at this crate's 6.18
    /// kernel floor.
    ///
    /// Deliberately submitted against a **real** fd: the encoding is what
    /// this test is for, and a real fd works on every kernel since 5.19, so
    /// the packing stays covered on hosts older than 6.13 (where the
    /// integration tests' fixed-file form skips).
    #[test]
    fn xattr_sqe_packing_round_trips() {
        let Some(mut ring) = ring_or_skip(8) else {
            return;
        };
        let dir = crate::tempdir().unwrap();
        let path = dir.path().join("x");
        std::fs::write(&path, b"body").unwrap();
        let file = std::fs::File::open(&path).unwrap();
        let fd = file.as_raw_fd();
        let name = c"user.packing";
        let value = b"VALUE".to_vec();

        ring.push_sqe(|sqe| {
            sqe.opcode = IORING_OP_FSETXATTR;
            sqe.fd = fd;
            sqe.addr = name.as_ptr() as u64;
            sqe.off_addr2 = value.as_ptr() as u64;
            sqe.len = value.len() as u32;
            sqe.user_data = 1;
        })
        .unwrap();
        ring.submit_and_wait(1).unwrap();
        let res = ring.reap().expect("set cqe").res;
        if res == -libc::EOPNOTSUPP || res == -libc::ENOTSUP {
            return; // filesystem without user xattrs (unusual /tmp)
        }
        assert_eq!(res, 0, "fsetxattr with our packing");

        let mut out = vec![0u8; 32];
        ring.push_sqe(|sqe| {
            sqe.opcode = IORING_OP_FGETXATTR;
            sqe.fd = fd;
            sqe.addr = name.as_ptr() as u64;
            sqe.off_addr2 = out.as_mut_ptr() as u64;
            sqe.len = out.len() as u32;
            sqe.user_data = 2;
        })
        .unwrap();
        ring.submit_and_wait(1).unwrap();
        let got = ring.reap().expect("get cqe").res;
        assert_eq!(got, value.len() as i32, "res is the attribute size");
        assert_eq!(&out[..got as usize], &value[..], "value round-trips");
    }

    /// A forged/stale token (recycled generation) is inert: the op fails
    /// `EBADF` without touching the slot's current occupant. And a
    /// personality id nothing registered fails `EINVAL` at submission --
    /// the kernel refusing the stamp, surfaced as the op's error.
    #[test]
    fn stale_token_and_stale_personality_are_inert() {
        let dir = crate::tempdir().unwrap();
        std::fs::write(dir.path().join("f"), b"data").unwrap();
        // Not `FsConfig::default()`: that is server-sized and costs ~400 KiB
        // of RLIMIT_MEMLOCK per ring, and `cargo test` runs this alongside
        // every other test in one process.
        let cfg = FsConfig {
            entries: 128,
            ops: 128,
            ..FsConfig::default()
        };
        let mut afs = match UringFs::new(cfg) {
            Ok(a) => a,
            Err(crate::Error::Errno(e)) if skip_unavailable(e) => return,
            Err(e) => panic!("UringFs::new: {e}"),
        };
        let me = afs.register_self().unwrap();
        let h = afs.handle();
        let stop = afs.shutdown_handle();
        let dir_path = dir.path().to_path_buf();
        std::thread::scope(|s| {
            let stop_c = stop.clone();
            s.spawn(move || {
                let anchor = Anchor::open(dir_path.as_path()).unwrap();
                let how = OpenHow::new().flags(OFlag::O_RDONLY);
                let f = h.open(me, &anchor, "f", how).unwrap();

                // A plain read works (files are real fds now - there is no
                // stale `{slot, generation}` token left to forge).
                let (res, bufs) =
                    h.preadv2(me, &f, vec![vec![0u8; 4]], 0, RwFlags::empty());
                assert_eq!(res.unwrap(), 4);
                assert_eq!(&bufs[0], b"data");

                // A personality nothing registered: the kernel refuses the
                // SQE at init; the caller sees EINVAL.
                let bogus = Personality(4242);
                let (res, _b) = h.preadv2(
                    bogus,
                    &f,
                    vec![vec![0u8; 4]],
                    0,
                    RwFlags::empty(),
                );
                assert!(matches!(res, Err(crate::Error::Errno(Errno::EINVAL))));

                h.close(f).unwrap();
                stop_c.shutdown();
            });
            afs.run().unwrap();
        });
    }
}
