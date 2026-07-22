//! The standalone host: [`AsyncFs`] owns the engine and the fs core, runs
//! the completion loop on its thread, and mints the cross-thread handles.
//! (The core is host-agnostic — a `net` server is the other host, driving the
//! same [`FsCore`] on its own ring.)

use super::core::{FsCore, FsWaiter, TAG_CANCEL, TAG_WAKE};
use super::{FsHandle, FsInject, FsOutcome, Personality};
use crate::errno::{self, Errno};
use crate::uring::engine::Engine;
use crate::uring::probe::probe_op_supported;
use crate::uring::ring::Ring;
use crate::uring::sys::{
    register_personality, IoUringCqe, IORING_CQE_F_MORE, IORING_OP_FGETXATTR,
    IORING_OP_FTRUNCATE, IORING_OP_OPENAT2, IOSQE_FIXED_FILE,
};
use crate::uring::user_data::{pack_raw, unpack_raw, SLOT_MASK, TAG_FS_DOMAIN};
use crate::uring::wake::LoopShared;
use std::fmt;
use std::os::fd::AsRawFd;
use std::sync::atomic::Ordering;
use std::sync::{mpsc, Arc};

/// Does this kernel accept a **registered-table file** for the fd-based
/// xattr ops?
///
/// This cannot be answered by [`probe_op_supported`]: `FGETXATTR` is
/// "supported" on every kernel since 5.19 — it just rejected
/// `IOSQE_FIXED_FILE` with `-EBADF` until Linux 6.13, because the check
/// belonged to the *path* variants but sat in a helper both shared
/// (kernel commit `dc7e76ba7a60`, "IORING_OP_F[GS]ETXATTR is fine with
/// REQ_F_FIXED_FILE"). Only attempting the real combination distinguishes
/// them, so this builds a throwaway ring over an anonymous `memfd` — no
/// filesystem is touched and the reactor's own table is untouched — and
/// asks for an attribute that does not exist. Anything other than `EBADF`
/// (`ENODATA`, `EOPNOTSUPP`, success) means the fixed-file path works.
pub(crate) fn probe_fixed_file_xattr() -> bool {
    let Ok(mut ring) = Ring::new(4) else {
        return false;
    };
    if ring.register_pool(1).is_err() {
        return false;
    }
    // SAFETY: a valid NUL-terminated name; memfd_create returns a fresh fd
    // or -1.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_memfd_create,
            c"truenas_ros-xattr-probe".as_ptr(),
            libc::MFD_CLOEXEC,
        )
    };
    let Ok(fd) = Errno::result(fd) else {
        return false;
    };
    // SAFETY: a fresh owned fd from memfd_create.
    let memfd = unsafe { crate::fd::owned_from_raw(fd as std::os::fd::RawFd) };
    if ring.install_file(0, memfd.as_raw_fd()).is_err() {
        return false;
    }
    let name = c"user.truenas_ros_probe";
    if ring
        .push_sqe(|sqe| {
            sqe.opcode = IORING_OP_FGETXATTR;
            sqe.flags = IOSQE_FIXED_FILE;
            sqe.fd = 0;
            sqe.addr = name.as_ptr() as u64;
            sqe.off_addr2 = 0; // size query: no value buffer
            sqe.len = 0;
            sqe.user_data = 1;
        })
        .is_err()
    {
        return false;
    }
    if ring.submit_and_wait(1).is_err() {
        return false;
    }
    match ring.reap() {
        Some(cqe) => cqe.res != -libc::EBADF,
        None => false,
    }
}

/// Sizing for an [`AsyncFs`].
#[derive(Clone, Copy, Debug)]
pub struct FsConfig {
    /// Submission-queue depth (rounded up to a power of two by the kernel).
    pub entries: u32,
    /// Fixed-file pool slots — the maximum number of concurrently open
    /// files. Opening with the pool exhausted fails `ENFILE`.
    pub files: u32,
    /// Op-table slots — the maximum number of concurrently in-flight
    /// operations. Submitting past it fails `EBUSY`.
    pub ops: u32,
}

impl Default for FsConfig {
    fn default() -> FsConfig {
        FsConfig {
            entries: 128,
            files: 64,
            ops: 128,
        }
    }
}

/// Stops a running [`AsyncFs::run`] loop from any thread.
#[derive(Clone, Debug)]
pub struct ShutdownHandle {
    shared: Arc<LoopShared>,
}

impl ShutdownHandle {
    /// Stop the loop: in-flight operations are cancelled (parked callers
    /// observe `ECANCELED`/`ECONNABORTED`) and [`AsyncFs::run`] returns.
    /// Safe to call from any thread and more than once. Infallible: a flag
    /// store plus an eventfd poke.
    pub fn shutdown(&self) {
        self.shared.stop.store(true, Ordering::Release);
        self.shared.wake.poke();
    }
}

/// The standalone fs reactor: one ring, one loop thread, files in a
/// fixed-descriptor pool, every operation stamped with a [`Personality`].
///
/// Like the `net` roles it is deliberately `!Send` (the ring is
/// single-thread-owned): build it, mint [`FsHandle`]s/[`ShutdownHandle`]s
/// for other threads, then park the owning thread in [`AsyncFs::run`].
pub struct AsyncFs {
    // Field order is load-bearing (as in the net roles): `fs` owns every
    // kernel-visible buffer and is declared before `eng`, so those buffers
    // drop before the engine unmaps the ring — the kernel must never touch a
    // freed buffer.
    fs: FsCore,
    inject_tx: mpsc::Sender<FsInject>,
    inject_rx: mpsc::Receiver<FsInject>,
    /// `IORING_OP_FTRUNCATE` (Linux ≥ 6.9) — above this crate's other
    /// io_uring floors, so its absence disables just that call rather than
    /// failing construction.
    ftruncate_ok: bool,
    /// Fixed-file `FGETXATTR`/`FSETXATTR` (Linux ≥ 6.13); see
    /// [`probe_fixed_file_xattr`].
    fd_xattr_ok: bool,
    eng: Engine,
}

impl fmt::Debug for AsyncFs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AsyncFs").finish_non_exhaustive()
    }
}

impl Drop for AsyncFs {
    fn drop(&mut self) {
        // On the normal path `run` already drained, so this is a cheap no-op
        // (nothing in flight → `cancel_and_reap_all` returns at once). On an
        // early drop, or a panic unwinding out of `run`, drain here — and if
        // that drain fails, leak the op buffers rather than free them under a
        // still-live kernel op (mirrors the net `Server::drop`).
        let _ = self.drain_or_leak();
    }
}

impl AsyncFs {
    /// Build the ring, register the sparse fixed-file pool, and probe the
    /// kernel (`OPENAT2` as the canary for the op set). Fails with
    /// `Validation` on an unsupported kernel and with the underlying errno
    /// where io_uring itself is unavailable.
    pub fn new(cfg: FsConfig) -> crate::Result<AsyncFs> {
        if cfg.files == 0 {
            return Err(crate::Error::Validation(
                "FsConfig::files must be at least 1".into(),
            ));
        }
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
        let eng = Engine::new(cfg.entries, cfg.files)?;
        if !probe_op_supported(&eng.ring, IORING_OP_OPENAT2) {
            return Err(crate::Error::Validation(
                "async_fs requires io_uring OPENAT2 (Linux >= 5.6); this \
                 kernel's io_uring does not support it"
                    .into(),
            ));
        }
        let ftruncate_ok = probe_op_supported(&eng.ring, IORING_OP_FTRUNCATE);
        let fd_xattr_ok = probe_fixed_file_xattr();
        let (inject_tx, inject_rx) = mpsc::channel();
        Ok(AsyncFs {
            fs: FsCore::new(cfg.ops, 0, cfg.files),
            inject_tx,
            inject_rx,
            ftruncate_ok,
            fd_xattr_ok,
            eng,
        })
    }

    /// Whether this kernel supports [`FsHandle::ftruncate`] (Linux ≥ 6.9).
    pub fn supports_ftruncate(&self) -> bool {
        self.ftruncate_ok
    }

    /// This reactor's ring descriptor — handed to the credential broker so
    /// it can register personalities on this ring (and to nothing else: a
    /// ring fd plus its personality table is a credential capability).
    pub(crate) fn ring_fd(&self) -> std::os::fd::RawFd {
        self.eng.ring.raw_fd()
    }

    /// Whether this kernel supports [`FsHandle::fgetxattr`] /
    /// [`FsHandle::fsetxattr`] on an open [`FixedFile`](super::FixedFile)
    /// (Linux ≥ 6.13 — before that, io_uring rejected a registered-table
    /// file for these ops). Where it is false those two calls return
    /// `EOPNOTSUPP`; everything else in the API works normally.
    pub fn supports_fd_xattr(&self) -> bool {
        self.fd_xattr_ok
    }

    /// Register the calling process's **current** credentials as a
    /// [`Personality`] — the identity every subsequent operation must name.
    ///
    /// Unprivileged: registering your own credentials needs no capability.
    /// The snapshot is frozen at this call (a later `setgroups`/capability
    /// drop does not update it — register again for a fresh one). Ids are
    /// kernel-allocated from 1 upward, cyclically, without immediate reuse.
    pub fn register_self(&self) -> crate::Result<Personality> {
        let id = register_personality(self.eng.ring.raw_fd())?;
        Ok(Personality(id))
    }

    /// A `Send + Sync` handle for submitting operations from other threads.
    pub fn handle(&self) -> FsHandle {
        FsHandle {
            tx: self.inject_tx.clone(),
            shared: self.eng.shared.clone(),
            ftruncate_ok: self.ftruncate_ok,
            fd_xattr_ok: self.fd_xattr_ok,
        }
    }

    /// A handle that stops [`AsyncFs::run`] from any thread.
    pub fn shutdown_handle(&self) -> ShutdownHandle {
        ShutdownHandle {
            shared: self.eng.shared.clone(),
        }
    }

    /// Run the completion loop until a [`ShutdownHandle`] stops it or a
    /// fatal ring error occurs. In-flight operations are cancelled and
    /// drained before returning; parked handle callers are unblocked with
    /// errors. Terminal: build a fresh `AsyncFs` rather than re-running.
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
            }
            TAG_CANCEL => {}
            // The standalone host only ever parks channel waiters, so
            // `on_cqe` never returns an embedded callback here; drop the
            // (always-`None`) result.
            _ => {
                let _ =
                    self.fs.on_cqe(&mut self.eng, tag, slot, gen32, cqe.res);
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
                    slot,
                    gen,
                    bufs,
                    off,
                    reply,
                } => self.fs.submit_rw(
                    &mut self.eng,
                    tag,
                    pers,
                    slot,
                    gen,
                    bufs,
                    off,
                    FsWaiter::Channel(reply),
                ),
                FsInject::Fsync {
                    pers,
                    slot,
                    gen,
                    datasync,
                    reply,
                } => self.fs.submit_fsync(
                    &mut self.eng,
                    pers,
                    slot,
                    gen,
                    datasync,
                    FsWaiter::Channel(reply),
                ),
                FsInject::Close { slot, gen, reply } => {
                    self.fs.submit_close(&mut self.eng, slot, gen, reply)
                }
                FsInject::FdMeta {
                    tag,
                    pers,
                    slot,
                    gen,
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
                    slot,
                    gen,
                    name,
                    value,
                    off,
                    len64,
                    aux32,
                    FsWaiter::Channel(reply),
                ),
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
        self.fs.fail_parked();
        while let Ok(msg) = self.inject_rx.try_recv() {
            let (reply, bufs) = match msg {
                FsInject::Open { reply, .. } => (Some(reply), Vec::new()),
                FsInject::Rw { reply, bufs, .. } => (Some(reply), bufs),
                FsInject::Fsync { reply, .. } => (Some(reply), Vec::new()),
                FsInject::Close { reply, .. } => (reply, Vec::new()),
                FsInject::FdMeta { reply, value, .. } => {
                    (Some(reply), vec![value])
                }
                FsInject::PathOp { reply, .. } => (Some(reply), Vec::new()),
            };
            if let Some(reply) = reply {
                let _ = reply.send(FsOutcome {
                    res: Err(Errno::ECONNABORTED),
                    bufs,
                    file: None,
                    stat: None,
                });
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
#[cfg(test)]
mod tests {
    use super::*;
    use crate::async_fs::{Anchor, FixedFile, FsConfig, Personality};
    use crate::sync_fs::openat2::RawOpenHow;
    use crate::sync_fs::{OFlag, OpenHow};
    use crate::uring::ring::Ring;
    use crate::uring::sys::{
        io_uring_setup, unregister_personality, IoUringParams,
        IORING_OP_FSETXATTR, IORING_SETUP_SINGLE_ISSUER,
    };
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

    /// §6.3 of the fs-reactor design: a `SINGLE_ISSUER` ring refuses
    /// registration from any task but its creator with `-EEXIST` — the flag
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
            // EINVAL: kernel predates the flag (< 6.0) — nothing to pin.
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
    /// Raw-ring test on purpose — it pins the kernel, not our plumbing.
    #[test]
    fn explicit_index_install_res_is_zero() {
        let Some(mut ring) = ring_or_skip(8) else {
            return;
        };
        ring.register_pool(4).expect("register pool");
        let dir = tempfile::tempdir().unwrap();
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

    /// Pin the xattr SQE field packing — `addr` = name, `addr2` = value,
    /// `len` = size, `xattr_flags` = flags — independently of the
    /// fixed-file gate that [`probe_fixed_file_xattr`] handles.
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
        let dir = tempfile::tempdir().unwrap();
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
    /// personality id nothing registered fails `EINVAL` at submission —
    /// the kernel refusing the stamp, surfaced as the op's error.
    #[test]
    fn stale_token_and_stale_personality_are_inert() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("f"), b"data").unwrap();
        let mut afs = match AsyncFs::new(FsConfig::default()) {
            Ok(a) => a,
            Err(crate::Error::Errno(e)) if skip_unavailable(e) => return,
            Err(e) => panic!("AsyncFs::new: {e}"),
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

                // Forge a token with a wrong generation: EBADF, and the real
                // token still works afterwards.
                let forged = FixedFile {
                    slot: f.slot,
                    gen: f.gen.wrapping_add(7),
                    tx: h.tx.clone(),
                    shared: h.shared.clone(),
                    defused: true,
                };
                let (res, _b) = h.pread(me, &forged, vec![0u8; 4], 0);
                assert!(matches!(res, Err(crate::Error::Errno(Errno::EBADF))));
                drop(forged);
                let (res, buf) = h.pread(me, &f, vec![0u8; 4], 0);
                assert_eq!(res.unwrap(), 4);
                assert_eq!(&buf, b"data");

                // A personality nothing registered: the kernel refuses the
                // SQE at init; the caller sees EINVAL.
                let bogus = Personality(4242);
                let (res, _b) = h.pread(bogus, &f, vec![0u8; 4], 0);
                assert!(matches!(res, Err(crate::Error::Errno(Errno::EINVAL))));

                h.close(f).unwrap();
                stop_c.shutdown();
            });
            afs.run().unwrap();
        });
    }
}
