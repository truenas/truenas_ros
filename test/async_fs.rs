//! Integration tests for the `async_fs` io_uring reactor — live data and
//! metadata ops against a tempdir, every one stamped with a self personality
//! and resolved against an [`Anchor`] (there is no unstamped or
//! absolute-path variant to test).
//!
//! Like `test/net_server.rs`, these **skip** (return early) when io_uring is
//! unavailable — a bare sandbox blocks the syscalls (ENOSYS/EPERM/EACCES) —
//! and `TRUENAS_ROS_REQUIRE_IO_URING=1` turns that skip into a hard failure.
//!
//! `AsyncFs` is `!Send` (single-thread ring), so the harness runs the loop on
//! the test thread and drives the client from a scoped thread; a panic-safe
//! guard stops the loop however the client exits.
#![cfg(all(target_os = "linux", feature = "async-fs"))]

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};
use truenas_ros::async_fs::{
    Anchor, AsUser, AsyncFs, CredBroker, CredHandle, FsConfig, FsHandle,
    IdentityCache, Leaf, Personality, ShutdownHandle,
};
use truenas_ros::sync_fs::{
    AtFlags, Mode, OFlag, OpenHow, RenameFlags, ResolveFlag, StatxMask,
};
use truenas_ros::{Errno, Error};

/// A validated single component, for the many call sites that pass one.
fn leaf(name: &str) -> Leaf<'_> {
    Leaf::new(name).expect("valid leaf")
}

fn xattr_name(name: &str) -> CString {
    CString::new(name).unwrap()
}

/// Errors that mean "io_uring is unavailable here" — an environmental skip.
/// Deliberately excludes `EINVAL` (a rejected setup argument is a real bug).
fn should_skip(e: &Error) -> bool {
    let unavailable = matches!(
        e,
        Error::Errno(Errno::EPERM | Errno::ENOSYS | Errno::EACCES)
    );
    if unavailable {
        assert!(
            std::env::var_os("TRUENAS_ROS_REQUIRE_IO_URING").is_none(),
            "TRUENAS_ROS_REQUIRE_IO_URING set but io_uring unavailable: {e}"
        );
    }
    unavailable
}

/// Stops the loop when dropped, so a panicking client can't hang the test.
struct StopGuard(ShutdownHandle);
impl Drop for StopGuard {
    fn drop(&mut self) {
        self.0.shutdown();
    }
}

/// What the running kernel supports, for tests that must gate on it.
#[derive(Clone, Copy)]
struct Caps {
    fd_xattr: bool,
    ftruncate: bool,
}

/// `fd_xattr` needs Linux >= 6.13 (kernel commit dc7e76ba7a60). Skip where
/// absent, unless the environment demands full coverage.
fn require_fd_xattr(caps: Caps) -> bool {
    if !caps.fd_xattr {
        assert!(
            std::env::var_os("TRUENAS_ROS_REQUIRE_FD_XATTR").is_none(),
            "TRUENAS_ROS_REQUIRE_FD_XATTR set but this kernel rejects \
             fixed-file xattr ops (needs Linux >= 6.13)"
        );
        return false;
    }
    true
}

/// Pin a known umask for the whole binary. Several tests assert on the mode
/// of something they create — `mkdirat`'s mode argument, or a setup file an
/// impersonated user has to be able to read — and the kernel masks every one
/// of those with the umask the suite happens to inherit. Left alone, a
/// developer or CI runner at 0077 fails those tests for a reason that has
/// nothing to do with the code under test.
fn pin_umask() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        // SAFETY: umask cannot fail; it returns the previous mask.
        unsafe { libc::umask(0o022) };
    });
}

/// Build an `AsyncFs` over a fresh tempdir, register a self personality, run
/// the loop on this thread, and drive `client` from a scoped thread.
fn with_fs<F>(cfg: FsConfig, client: F)
where
    F: FnOnce(FsHandle, Personality, PathBuf, ShutdownHandle) + Send,
{
    with_fs_caps(cfg, |h, me, dir, stop, _caps| client(h, me, dir, stop))
}

/// [`with_fs`] plus the probed kernel capabilities.
fn with_fs_caps<F>(cfg: FsConfig, client: F)
where
    F: FnOnce(FsHandle, Personality, PathBuf, ShutdownHandle, Caps) + Send,
{
    pin_umask();
    let dir = tempfile::tempdir().expect("tempdir");
    let mut afs = match AsyncFs::new(cfg) {
        Ok(a) => a,
        Err(e) => {
            if should_skip(&e) {
                return;
            }
            panic!("AsyncFs::new: {e}");
        }
    };
    let me = afs.register_self().expect("register_self");
    let caps = Caps {
        fd_xattr: afs.supports_fd_xattr(),
        ftruncate: afs.supports_ftruncate(),
    };
    let handle = afs.handle();
    let stop = afs.shutdown_handle();
    let dir_path = dir.path().to_path_buf();
    thread::scope(|s| {
        let stop_for_client = stop.clone();
        s.spawn(move || {
            let _guard = StopGuard(stop);
            client(handle, me, dir_path, stop_for_client, caps);
        });
        afs.run().expect("run");
    });
}

/// Retry `f` while it fails with `retry_on` (an orphan close is
/// asynchronous; the slot frees when its CQE lands), bounded at 2s.
fn eventually<T>(
    retry_on: Errno,
    mut f: impl FnMut() -> truenas_ros::Result<T>,
) -> T {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match f() {
            Ok(v) => return v,
            Err(Error::Errno(e)) if e == retry_on => {
                assert!(
                    Instant::now() < deadline,
                    "still failing {retry_on} after 2s"
                );
                thread::sleep(Duration::from_millis(5));
            }
            Err(e) => panic!("unexpected error: {e}"),
        }
    }
}

fn rdonly() -> OpenHow {
    OpenHow::new().flags(OFlag::O_RDONLY)
}

fn creat_rw() -> OpenHow {
    OpenHow::new()
        .flags(OFlag::O_CREAT | OFlag::O_RDWR)
        .mode(truenas_ros::sync_fs::Mode::from_bits_truncate(0o600))
}

fn mkfifo(dir: &Path, name: &str) -> String {
    let p = dir.join(name);
    let c = CString::new(p.as_os_str().as_bytes()).unwrap();
    // SAFETY: valid NUL-terminated path.
    let rc = unsafe { libc::mkfifo(c.as_ptr(), 0o600) };
    assert_eq!(rc, 0, "mkfifo failed: {}", std::io::Error::last_os_error());
    name.to_string()
}

// ---------------------------------------------------------------------------

#[test]
fn round_trip_write_fsync_read() {
    with_fs(FsConfig::default(), |h, me, dir, _stop| {
        let anchor = Anchor::open(dir.as_path()).expect("anchor");

        // Write a new file through the reactor: two gathered buffers.
        let f = h.open(me, &anchor, "out.bin", creat_rw()).expect("open");
        let (n, bufs) =
            h.pwritev(me, &f, vec![b"hello ".to_vec(), b"world".to_vec()], 0);
        assert_eq!(n.expect("writev"), 11);
        assert_eq!(bufs.len(), 2, "buffers round-trip");
        h.fsync(me, &f).expect("fsync");
        h.fdatasync(me, &f).expect("fdatasync");
        h.close(f).expect("close");

        // Oracle: the bytes are on disk, owned by us (O_CREAT under a self
        // personality creates as the calling identity).
        let disk = std::fs::read(dir.join("out.bin")).expect("std read");
        assert_eq!(disk, b"hello world");
        let meta = std::fs::metadata(dir.join("out.bin")).unwrap();
        // SAFETY: geteuid is always safe.
        assert_eq!(meta.uid(), unsafe { libc::geteuid() });

        // Read it back scattered: 4 + 4 + 8 byte buffers, 11 bytes total.
        let f = h.open(me, &anchor, "out.bin", rdonly()).expect("reopen");
        let (n, bufs) =
            h.preadv(me, &f, vec![vec![0u8; 4], vec![0u8; 4], vec![0u8; 8]], 0);
        assert_eq!(n.expect("readv"), 11, "short only at EOF");
        assert_eq!(&bufs[0], b"hell");
        assert_eq!(&bufs[1], b"o wo");
        assert_eq!(&bufs[2][..3], b"rld");

        // Positional single-buffer read.
        let (n, buf) = h.pread(me, &f, vec![0u8; 5], 6);
        assert_eq!(n.expect("pread"), 5);
        assert_eq!(&buf, b"world");
        h.close(f).expect("close 2");
    });
}

#[test]
fn multi_component_and_beneath() {
    with_fs(FsConfig::default(), |h, me, dir, _stop| {
        std::fs::create_dir(dir.join("sub")).unwrap();
        std::fs::write(dir.join("sub/inner.txt"), b"beneath").unwrap();
        let anchor = Anchor::open(dir.as_path()).unwrap();

        // Multi-component relative paths are the open's job (only op that
        // walks); RESOLVE_BENEATH confines them in-kernel.
        let how = rdonly().resolve(ResolveFlag::RESOLVE_BENEATH);
        let f = h.open(me, &anchor, "sub/inner.txt", how).expect("open");
        let (n, buf) = h.pread(me, &f, vec![0u8; 16], 0);
        assert_eq!(&buf[..n.unwrap()], b"beneath");
        h.close(f).unwrap();

        // Escaping the anchor under RESOLVE_BENEATH is the kernel's EXDEV.
        let how = rdonly().resolve(ResolveFlag::RESOLVE_BENEATH);
        match h.open(me, &anchor, "../escape", how) {
            Err(Error::Errno(Errno::EXDEV)) => {}
            other => panic!("expected EXDEV, got {other:?}"),
        }

        // The DEFAULT (no explicit resolve) now confines too: `open` applies
        // RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS when `how` set no resolve, so a
        // bare `rdonly()` rejects a `..` escape without the caller opting in.
        match h.open(me, &anchor, "../escape", rdonly()) {
            Err(Error::Errno(Errno::EXDEV)) => {}
            other => panic!("default open must confine `..`, got {other:?}"),
        }
        // …and does not follow a symlink (NO_SYMLINKS → ELOOP), so a
        // peer-planted link can't redirect the open out of the share.
        std::os::unix::fs::symlink("/etc/hostname", dir.join("out")).unwrap();
        match h.open(me, &anchor, "out", rdonly()) {
            Err(Error::Errno(Errno::ELOOP)) => {}
            other => {
                panic!("default open must not follow a symlink, {other:?}")
            }
        }
        // A legit in-anchor nested path still opens under the default policy:
        // BENEATH permits descending real subdirs; NO_SYMLINKS blocks only
        // symlink components.
        let f = h
            .open(me, &anchor, "sub/inner.txt", rdonly())
            .expect("nested");
        h.close(f).unwrap();
    });
}

#[test]
fn validation_and_errno_mapping() {
    with_fs(FsConfig::default(), |h, me, dir, _stop| {
        let anchor = Anchor::open(dir.as_path()).unwrap();

        // Library validation: no absolute paths, no empty path, no O_CLOEXEC.
        assert!(matches!(
            h.open(me, &anchor, "/etc/hostname", rdonly()),
            Err(Error::Validation(_))
        ));
        assert!(matches!(
            h.open(me, &anchor, "", rdonly()),
            Err(Error::Validation(_))
        ));
        let cloexec = OpenHow::new().flags(OFlag::O_RDONLY | OFlag::O_CLOEXEC);
        assert!(matches!(
            h.open(me, &anchor, "x", cloexec),
            Err(Error::Validation(_))
        ));

        // Kernel errno round-trips: ENOENT for a missing file, EBADF for a
        // write on a read-only open.
        assert!(matches!(
            h.open(me, &anchor, "missing.txt", rdonly()),
            Err(Error::Errno(Errno::ENOENT))
        ));
        std::fs::write(dir.join("ro.txt"), b"ro").unwrap();
        let f = h.open(me, &anchor, "ro.txt", rdonly()).unwrap();
        let (res, _buf) = h.pwrite(me, &f, b"nope".to_vec(), 0);
        assert!(matches!(res, Err(Error::Errno(Errno::EBADF))));
        h.close(f).unwrap();
    });
}

#[test]
fn stale_personality_from_other_ring_is_einval() {
    // Two reactors: an id registered on ring A names nothing on ring B.
    let dir = tempfile::tempdir().unwrap();
    let afs_a = match AsyncFs::new(FsConfig::default()) {
        Ok(a) => a,
        Err(e) => {
            if should_skip(&e) {
                return;
            }
            panic!("{e}");
        }
    };
    let id_a = afs_a.register_self().unwrap();
    let mut afs_b = AsyncFs::new(FsConfig::default()).unwrap();
    // Deliberately: nothing registered on B.
    let h = afs_b.handle();
    let stop = afs_b.shutdown_handle();
    std::fs::write(dir.path().join("f"), b"x").unwrap();
    let dir_path = dir.path().to_path_buf();
    thread::scope(|s| {
        let stop_c = stop.clone();
        s.spawn(move || {
            let _guard = StopGuard(stop_c);
            let anchor = Anchor::open(dir_path.as_path()).unwrap();
            match h.open(id_a, &anchor, "f", rdonly()) {
                Err(Error::Errno(Errno::EINVAL)) => {}
                other => panic!("expected EINVAL, got {other:?}"),
            }
        });
        afs_b.run().unwrap();
    });
    drop(afs_a); // ring A (and its registration) outlived the use on B
}

#[test]
fn pool_exhaustion_enfile_then_reclaim() {
    let cfg = FsConfig {
        files: 2,
        ..FsConfig::default()
    };
    with_fs(cfg, |h, me, dir, _stop| {
        std::fs::write(dir.join("a"), b"a").unwrap();
        let anchor = Anchor::open(dir.as_path()).unwrap();
        let f1 = h.open(me, &anchor, "a", rdonly()).unwrap();
        let f2 = h.open(me, &anchor, "a", rdonly()).unwrap();
        match h.open(me, &anchor, "a", rdonly()) {
            Err(Error::Errno(Errno::ENFILE)) => {}
            other => panic!("expected ENFILE, got {other:?}"),
        }
        h.close(f1).unwrap();
        let f3 = h.open(me, &anchor, "a", rdonly()).expect("slot reclaimed");
        h.close(f3).unwrap();
        h.close(f2).unwrap();
    });
}

#[test]
fn dropped_file_reclaims_slot() {
    let cfg = FsConfig {
        files: 1,
        ..FsConfig::default()
    };
    with_fs(cfg, |h, me, dir, _stop| {
        std::fs::write(dir.join("a"), b"a").unwrap();
        let anchor = Anchor::open(dir.as_path()).unwrap();
        let f = h.open(me, &anchor, "a", rdonly()).unwrap();
        drop(f); // orphan close: injected by Drop, completes asynchronously
        let f =
            eventually(Errno::ENFILE, || h.open(me, &anchor, "a", rdonly()));
        h.close(f).unwrap();
    });
}

#[test]
fn dropped_file_mid_op_cancels_and_reclaims() {
    let cfg = FsConfig {
        files: 1,
        ..FsConfig::default()
    };
    with_fs(cfg, |h, me, dir, _stop| {
        mkfifo(&dir, "fifo");
        std::fs::write(dir.join("a"), b"a").unwrap();
        let anchor = Anchor::open(dir.as_path()).unwrap();

        // O_RDWR on a FIFO opens immediately and keeps a writer attached, so
        // a read with no data parks forever — an op genuinely in flight.
        let how = OpenHow::new().flags(OFlag::O_RDWR);
        let f = h.open(me, &anchor, "fifo", how).expect("open fifo");
        let pending = h
            .start_preadv(me, &f, vec![vec![0u8; 8]], 0)
            .expect("start readv");
        thread::sleep(Duration::from_millis(50)); // let it park in the kernel

        // Dropping the only token cancels the parked read and closes the
        // file once it drains — the close-last rule, observably: the pool's
        // single slot becomes reusable.
        drop(f);
        let (res, _bufs) = pending.wait();
        let err = res.expect_err("parked read must not complete normally");
        let Error::Errno(_) = err else {
            panic!("expected an errno from the cancelled read, got {err:?}");
        };

        let f =
            eventually(Errno::ENFILE, || h.open(me, &anchor, "a", rdonly()));
        h.close(f).unwrap();
    });
}

#[test]
fn teardown_with_inflight_op() {
    with_fs(FsConfig::default(), |h, me, dir, stop| {
        mkfifo(&dir, "fifo");
        let anchor = Anchor::open(dir.as_path()).unwrap();
        let how = OpenHow::new().flags(OFlag::O_RDWR);
        let f = h.open(me, &anchor, "fifo", how).expect("open fifo");
        let pending = h
            .start_preadv(me, &f, vec![vec![0u8; 8]], 0)
            .expect("start readv");
        thread::sleep(Duration::from_millis(50));

        // Shut down with the read parked: run()'s drain cancels it, the
        // waiter unblocks with an error, and run() returns cleanly (the
        // harness asserts that).
        stop.shutdown();
        let (res, _bufs) = pending.wait();
        assert!(res.is_err(), "parked read must fail at teardown");
        // The token is now pointed at a dead loop; ops fail, drop is inert.
        let (res, _buf) = h.pread(me, &f, vec![0u8; 4], 0);
        assert!(matches!(res, Err(Error::Errno(Errno::ECONNABORTED))));
        drop(f);
    });
}

#[test]
fn concurrent_ops_across_threads() {
    let cfg = FsConfig {
        files: 8,
        ..FsConfig::default()
    };
    with_fs(cfg, |h, me, dir, _stop| {
        let anchor = Anchor::open(dir.as_path()).unwrap();
        thread::scope(|s| {
            for i in 0..4usize {
                let h = h.clone();
                let anchor = anchor.clone();
                s.spawn(move || {
                    let name = format!("t{i}.bin");
                    let name = name.as_str();
                    let payload = vec![i as u8 + 1; 4096 * (i + 1)];
                    let f = h.open(me, &anchor, name, creat_rw()).unwrap();
                    let (n, _bufs) =
                        h.pwritev(me, &f, vec![payload.clone()], 0);
                    assert_eq!(n.unwrap(), payload.len());
                    h.fsync(me, &f).unwrap();
                    h.close(f).unwrap();
                    // Verify through a fresh open + scattered read.
                    let f = h.open(me, &anchor, name, rdonly()).unwrap();
                    let half = payload.len() / 2;
                    let (n, bufs) = h.preadv(
                        me,
                        &f,
                        vec![vec![0u8; half], vec![0u8; payload.len() - half]],
                        0,
                    );
                    assert_eq!(n.unwrap(), payload.len());
                    assert_eq!(&bufs[0], &payload[..half]);
                    assert_eq!(&bufs[1], &payload[half..]);
                    h.close(f).unwrap();
                });
            }
        });
    });
}

#[test]
fn write_pread_offsets() {
    with_fs(FsConfig::default(), |h, me, dir, _stop| {
        let anchor = Anchor::open(dir.as_path()).unwrap();
        let f = h.open(me, &anchor, "sparse", creat_rw()).unwrap();
        let (n, _b) = h.pwrite(me, &f, b"tail".to_vec(), 100);
        assert_eq!(n.unwrap(), 4);
        let (n, buf) = h.pread(me, &f, vec![0u8; 8], 98);
        assert_eq!(n.unwrap(), 6, "2 hole bytes + 4 tail bytes to EOF");
        assert_eq!(&buf[..6], b"\0\0tail");
        h.close(f).unwrap();
        assert_eq!(std::fs::metadata(dir.join("sparse")).unwrap().len(), 104);
    });
}

// --- M2: metadata ----------------------------------------------------------

#[test]
fn open_metadata_close_workflow() {
    // The shape the API is built to encourage: open once, do every metadata
    // op against the resulting fd, close. No path is named after the open.
    with_fs_caps(FsConfig::default(), |h, me, dir, _stop, caps| {
        if !require_fd_xattr(caps) {
            return;
        }
        let anchor = Anchor::open(dir.as_path()).unwrap();
        let f = h.open(me, &anchor, "doc.bin", creat_rw()).unwrap();

        let (n, _b) = h.pwrite(me, &f, vec![b'x'; 4096], 0);
        assert_eq!(n.unwrap(), 4096);

        // Extended attributes, by fd. (This is the DOS-attributes shape the
        // whole reactor exists for.)
        let name = xattr_name("user.dosattrib");
        let (res, _v) = h.fsetxattr(me, &f, &name, b"\x01\x02\x03".to_vec(), 0);
        res.expect("fsetxattr");
        let (n, val) = h.fgetxattr(me, &f, &name, vec![0u8; 64]);
        assert_eq!(n.expect("fgetxattr"), 3);
        assert_eq!(&val[..3], b"\x01\x02\x03");

        // Size query with an empty buffer (the kernel's size-only form).
        let (n, _v) = h.fgetxattr(me, &f, &name, Vec::new());
        assert_eq!(n.expect("size query"), 3);

        // A too-small buffer is ERANGE, not a silent truncation.
        let (res, _v) = h.fgetxattr(me, &f, &name, vec![0u8; 2]);
        assert!(matches!(res, Err(Error::Errno(Errno::ERANGE))));

        // XATTR_CREATE on an existing attribute must fail EEXIST.
        let (res, _v) =
            h.fsetxattr(me, &f, &name, b"zz".to_vec(), libc::XATTR_CREATE);
        assert!(matches!(res, Err(Error::Errno(Errno::EEXIST))));

        // Allocation control, by fd.
        h.fallocate(me, &f, 0, 4096, 4096).expect("fallocate");
        assert_eq!(std::fs::metadata(dir.join("doc.bin")).unwrap().len(), 8192);

        h.fsync(me, &f).unwrap();
        h.close(f).unwrap();

        // Oracle: the xattr is really on disk, seen by a plain syscall.
        let mut out = [0u8; 8];
        let p =
            CString::new(dir.join("doc.bin").as_os_str().as_bytes()).unwrap();
        // SAFETY: valid path/name/buffer.
        let n = unsafe {
            libc::getxattr(
                p.as_ptr(),
                name.as_ptr(),
                out.as_mut_ptr().cast(),
                out.len(),
            )
        };
        assert_eq!(n, 3, "attribute visible to getxattr(2)");
        assert_eq!(&out[..3], b"\x01\x02\x03");
    });
}

#[test]
fn ftruncate_by_fd_or_unsupported() {
    with_fs_caps(FsConfig::default(), |h, me, dir, _stop, caps| {
        let anchor = Anchor::open(dir.as_path()).unwrap();
        let f = h.open(me, &anchor, "t.bin", creat_rw()).unwrap();
        let (n, _b) = h.pwrite(me, &f, vec![b'y'; 100], 0);
        assert_eq!(n.unwrap(), 100);

        let res = h.ftruncate(me, &f, 10);
        if caps.ftruncate {
            res.expect("ftruncate");
            assert_eq!(std::fs::metadata(dir.join("t.bin")).unwrap().len(), 10);
        } else {
            // Below 6.9 the op is disabled, not attempted.
            assert!(matches!(res, Err(Error::Errno(Errno::EOPNOTSUPP))));
        }
        h.close(f).unwrap();
    });
}

#[test]
fn fd_metadata_respects_close_last() {
    // Metadata ops hold a file reference like data ops do: a close with one
    // in flight must still be the file's last op (single-slot pool proves
    // the slot is reclaimed, not leaked).
    let cfg = FsConfig {
        files: 1,
        ..FsConfig::default()
    };
    with_fs_caps(cfg, |h, me, dir, _stop, caps| {
        if !require_fd_xattr(caps) {
            return;
        }
        let anchor = Anchor::open(dir.as_path()).unwrap();
        let f = h.open(me, &anchor, "a.bin", creat_rw()).unwrap();
        let name = xattr_name("user.k");
        let (res, _v) = h.fsetxattr(me, &f, &name, b"v".to_vec(), 0);
        res.unwrap();
        h.close(f).unwrap();
        // Slot reusable immediately: the close waited for the real close.
        let f = h.open(me, &anchor, "a.bin", rdonly()).expect("reopen");
        let (n, v) = h.fgetxattr(me, &f, &name, vec![0u8; 16]);
        assert_eq!(n.unwrap(), 1);
        assert_eq!(&v[..1], b"v");
        h.close(f).unwrap();
    });
}

#[test]
fn statx_by_leaf_and_anchor() {
    with_fs(FsConfig::default(), |h, me, dir, _stop| {
        std::fs::write(dir.join("sized"), vec![0u8; 1234]).unwrap();
        std::fs::create_dir(dir.join("sub")).unwrap();
        let anchor = Anchor::open(dir.as_path()).unwrap();

        let st = h
            .statx(
                me,
                &anchor,
                leaf("sized"),
                AtFlags::empty(),
                StatxMask::BASIC_STATS,
            )
            .expect("statx leaf");
        assert_eq!(st.size(), 1234);
        // SAFETY: geteuid is always safe.
        assert_eq!(st.uid(), unsafe { libc::geteuid() });

        // The anchor itself, via AT_EMPTY_PATH — the closest to fd-based
        // statx this interface can offer.
        let st = h
            .statx_anchor(me, &anchor, AtFlags::empty(), StatxMask::BASIC_STATS)
            .expect("statx anchor");
        assert!(st.is_dir(), "anchor is a directory");

        // A missing entry is a plain ENOENT.
        assert!(matches!(
            h.statx(
                me,
                &anchor,
                leaf("nope"),
                AtFlags::empty(),
                StatxMask::BASIC_STATS
            ),
            Err(Error::Errno(Errno::ENOENT))
        ));

        // The async surface does not follow a terminal symlink BY DEFAULT (a
        // peer-planted symlink can't redirect the stat out of the anchor), but
        // AT_SYMLINK_FOLLOW opts into stat'ing the target; an explicit
        // AT_SYMLINK_NOFOLLOW is the default.
        std::os::unix::fs::symlink("sized", dir.join("ln")).unwrap();
        let by_default = h
            .statx(
                me,
                &anchor,
                leaf("ln"),
                AtFlags::empty(),
                StatxMask::BASIC_STATS,
            )
            .unwrap();
        assert!(by_default.is_symlink(), "does not follow by default");
        let explicit = h
            .statx(
                me,
                &anchor,
                leaf("ln"),
                AtFlags::AT_SYMLINK_NOFOLLOW,
                StatxMask::BASIC_STATS,
            )
            .unwrap();
        assert!(explicit.is_symlink(), "NOFOLLOW stats the link itself");
        let followed = h
            .statx(
                me,
                &anchor,
                leaf("ln"),
                AtFlags::AT_SYMLINK_FOLLOW,
                StatxMask::BASIC_STATS,
            )
            .unwrap();
        assert_eq!(followed.size(), 1234, "AT_SYMLINK_FOLLOW stats the target");
    });
}

#[test]
fn leaf_validation_is_the_confinement() {
    // The *at opcodes honour no RESOLVE_* flags, so the single-component
    // rule is what keeps a directory op inside its anchor. Reject anything
    // that could walk.
    for bad in ["", ".", "..", "a/b", "/abs", "../escape", "sub/"] {
        assert!(
            matches!(Leaf::new(bad), Err(Error::Validation(_))),
            "{bad:?} must be rejected"
        );
    }
    assert!(Leaf::new("file.txt").is_ok());
    assert!(
        Leaf::new("..hidden").is_ok(),
        "only exactly `..` is special"
    );
    assert!(Leaf::new(&b"nul\0byte"[..]).is_err());
}

#[test]
fn directory_entry_ops() {
    with_fs(FsConfig::default(), |h, me, dir, _stop| {
        let anchor = Anchor::open(dir.as_path()).unwrap();

        // mkdir / rmdir
        h.mkdirat(me, &anchor, leaf("d"), Mode::from_bits_truncate(0o750))
            .expect("mkdirat");
        let md = std::fs::metadata(dir.join("d")).unwrap();
        assert!(md.is_dir());
        assert_eq!(md.permissions().mode() & 0o777, 0o750);
        h.rmdirat(me, &anchor, leaf("d")).expect("rmdirat");
        assert!(!dir.join("d").exists());

        // unlink, and the rmdir/unlink distinction the kernel enforces
        std::fs::write(dir.join("f"), b"x").unwrap();
        std::fs::create_dir(dir.join("realdir")).unwrap();
        assert!(matches!(
            h.unlinkat(me, &anchor, leaf("realdir")),
            Err(Error::Errno(Errno::EISDIR))
        ));
        assert!(matches!(
            h.rmdirat(me, &anchor, leaf("f")),
            Err(Error::Errno(Errno::ENOTDIR))
        ));
        h.unlinkat(me, &anchor, leaf("f")).expect("unlinkat");
        assert!(!dir.join("f").exists());

        // symlink: the target is content, never resolved at creation, so a
        // dangling (and multi-component) target is legal.
        h.symlinkat(me, "../elsewhere/target", &anchor, leaf("link"))
            .expect("symlinkat");
        assert_eq!(
            std::fs::read_link(dir.join("link")).unwrap(),
            Path::new("../elsewhere/target")
        );

        // hard link + rename
        std::fs::write(dir.join("orig"), b"data").unwrap();
        h.linkat(
            me,
            &anchor,
            leaf("orig"),
            &anchor,
            leaf("hard"),
            AtFlags::empty(),
        )
        .expect("linkat");
        assert_eq!(std::fs::read(dir.join("hard")).unwrap(), b"data");
        assert_eq!(
            std::fs::metadata(dir.join("orig")).unwrap().nlink(),
            2,
            "same inode"
        );

        h.renameat(
            me,
            &anchor,
            leaf("hard"),
            &anchor,
            leaf("moved"),
            RenameFlags::empty(),
        )
        .expect("renameat");
        assert!(dir.join("moved").exists() && !dir.join("hard").exists());

        // RENAME_NOREPLACE refuses to clobber.
        assert!(matches!(
            h.renameat(
                me,
                &anchor,
                leaf("moved"),
                &anchor,
                leaf("orig"),
                RenameFlags::RENAME_NOREPLACE,
            ),
            Err(Error::Errno(Errno::EEXIST))
        ));

        // RENAME_EXCHANGE swaps two entries atomically.
        std::fs::write(dir.join("A"), b"a").unwrap();
        std::fs::write(dir.join("B"), b"b").unwrap();
        h.renameat(
            me,
            &anchor,
            leaf("A"),
            &anchor,
            leaf("B"),
            RenameFlags::RENAME_EXCHANGE,
        )
        .expect("exchange");
        assert_eq!(std::fs::read(dir.join("A")).unwrap(), b"b");
        assert_eq!(std::fs::read(dir.join("B")).unwrap(), b"a");
    });
}

#[test]
fn rename_across_two_anchors() {
    with_fs(FsConfig::default(), |h, me, dir, _stop| {
        std::fs::create_dir(dir.join("src")).unwrap();
        std::fs::create_dir(dir.join("dst")).unwrap();
        std::fs::write(dir.join("src/f"), b"payload").unwrap();
        let a_src = Anchor::open(dir.join("src").as_path()).unwrap();
        let a_dst = Anchor::open(dir.join("dst").as_path()).unwrap();

        // Two distinct dirfds: the second rides in sqe.len per the kernel's
        // packing, which this proves end-to-end.
        h.renameat(
            me,
            &a_src,
            leaf("f"),
            &a_dst,
            leaf("g"),
            RenameFlags::empty(),
        )
        .expect("cross-anchor rename");
        assert!(!dir.join("src/f").exists());
        assert_eq!(std::fs::read(dir.join("dst/g")).unwrap(), b"payload");
    });
}

#[test]
fn metadata_ops_carry_the_personality() {
    // Every metadata op stamps sqe.personality; an id this ring never
    // registered must fail at submission rather than running as the daemon.
    with_fs_caps(FsConfig::default(), |h, me, dir, _stop, caps| {
        std::fs::write(dir.join("f"), b"x").unwrap();
        let anchor = Anchor::open(dir.as_path()).unwrap();
        let bogus = Personality::from_raw(4242).unwrap();

        assert!(matches!(
            h.statx(
                bogus,
                &anchor,
                leaf("f"),
                AtFlags::empty(),
                StatxMask::BASIC_STATS
            ),
            Err(Error::Errno(Errno::EINVAL))
        ));
        assert!(matches!(
            h.mkdirat(
                bogus,
                &anchor,
                leaf("d"),
                Mode::from_bits_truncate(0o755)
            ),
            Err(Error::Errno(Errno::EINVAL))
        ));
        assert!(matches!(
            h.unlinkat(bogus, &anchor, leaf("f")),
            Err(Error::Errno(Errno::EINVAL))
        ));
        assert!(dir.join("f").exists(), "the refused unlink did nothing");

        let f = h.open(me, &anchor, "f", rdonly()).unwrap();
        if caps.fd_xattr {
            let name = xattr_name("user.k");
            let (res, _v) = h.fgetxattr(bogus, &f, &name, vec![0u8; 8]);
            assert!(matches!(res, Err(Error::Errno(Errno::EINVAL))));
        }
        h.close(f).unwrap();
    });
}

// --- M3: the credential broker ---------------------------------------------

/// The broker forks, so it must be created before the harness starts
/// threads. These tests each build their own reactor rather than using
/// `with_fs`, and run the loop on a scoped thread while the test thread
/// drives registration (the reverse of the other tests, because `AsyncFs`
/// is `!Send` but `CredBroker`/`CredHandle` are `Send`).
fn with_broker<F>(client: F)
where
    F: FnOnce(&FsHandle, &CredHandle, Personality, &Path) + Send,
{
    pin_umask();
    let dir = tempfile::tempdir().expect("tempdir");
    // These tests drive ops as an impersonated user, who must be able to
    // traverse this directory and — for the ones that create as that user —
    // write in it. A fresh tempdir is only owner-writable, so widen it once
    // here rather than in each test.
    std::fs::set_permissions(
        dir.path(),
        std::fs::Permissions::from_mode(0o777),
    )
    .expect("chmod tempdir");
    // The ring must exist before the broker forks: it inherits the fd,
    // because an io_uring descriptor cannot be sent over a unix socket.
    let mut afs = match AsyncFs::new(FsConfig::default()) {
        Ok(a) => a,
        Err(e) => {
            if should_skip(&e) {
                return;
            }
            panic!("AsyncFs::new: {e}");
        }
    };
    let me = afs.register_self().expect("register_self");
    let broker = match CredBroker::spawn(&[&afs]) {
        Ok(b) => b,
        Err(e) => {
            if should_skip(&e) {
                return;
            }
            panic!("CredBroker::spawn: {e}");
        }
    };
    let creds = broker.handle(0).expect("broker handle");
    let handle = afs.handle();
    let stop = afs.shutdown_handle();
    let dir_path = dir.path().to_path_buf();
    thread::scope(|s| {
        s.spawn(move || {
            let _guard = StopGuard(stop);
            client(&handle, &creds, me, &dir_path);
        });
        afs.run().expect("run");
    });
}

/// Skip a root-only test when not running privileged.
fn is_root() -> bool {
    // SAFETY: geteuid cannot fail.
    unsafe { libc::geteuid() == 0 }
}

/// A uid/gid pair that exists nowhere — no files, no group memberships —
/// so a personality for it has exactly the authority "other" grants.
const NOBODY_UID: u32 = 65_534;
const NOBODY_GID: u32 = 65_534;

/// The identity a test can actually register: root impersonates anyone, an
/// unprivileged runner can only ask for what it already holds — *including*
/// its supplementary groups. Naming uid/gid alone would request an empty
/// group list, and dropping a group is itself a privileged change, so the
/// broker's `setgroups` would fail with `EPERM`.
fn registerable_user() -> AsUser {
    if is_root() {
        // Carry two supplementary groups: the callers that exercise set
        // normalization need something to shuffle, and an empty list would
        // leave that check dead whenever the suite runs privileged.
        return AsUser::new(NOBODY_UID, NOBODY_GID)
            .groups(vec![NOBODY_GID, 65_533]);
    }
    // SAFETY: these cannot fail.
    let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
    // SAFETY: a zero count asks for the length instead of writing.
    let n = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    assert!(n >= 0, "getgroups count");
    let mut groups = vec![0 as libc::gid_t; n as usize];
    // SAFETY: the destination holds the `n` entries just counted.
    let n = unsafe { libc::getgroups(n, groups.as_mut_ptr()) };
    assert!(n >= 0, "getgroups");
    groups.truncate(n as usize);
    AsUser::new(uid, gid).groups(groups)
}

#[test]
fn broker_registers_own_identity_unprivileged() {
    // Registering credentials identical to the broker's needs no privilege
    // at all, so this leg runs everywhere and covers the IPC round trip:
    // socketpair framing, the inherited ring fd, and a real op under the
    // resulting id.
    with_broker(|h, creds, _me, dir| {
        if is_root() {
            // Root's own identity is refused by policy; covered below.
            return;
        }
        let who = registerable_user();
        let id = creds.register(&who).expect("brokered self-registration");

        std::fs::write(dir.join("f"), b"brokered").unwrap();
        let anchor = Anchor::open(dir).unwrap();
        let f = h.open(id, &anchor, "f", rdonly()).expect("open as self");
        let (n, buf) = h.pread(id, &f, vec![0u8; 16], 0);
        assert_eq!(&buf[..n.unwrap()], b"brokered");
        h.close(f).unwrap();
        creds.unregister(id).expect("unregister");
    });
}

#[test]
fn broker_refuses_uid_zero() {
    with_broker(|_h, creds, _me, _dir| {
        // A root personality would carry the daemon's capabilities — the
        // exact thing the broker exists to prevent.
        assert!(matches!(
            creds.register(&AsUser::new(0, 0)),
            Err(Error::Validation(_))
        ));
    });
}

#[test]
fn group_list_beyond_the_cap_is_rejected_not_truncated() {
    with_broker(|_h, creds, _me, _dir| {
        // Distinct ids: repeating one gid would collapse under the set
        // normalization and no longer exceed the cap.
        let over: Vec<u32> = (0..=truenas_ros::async_fs::MAX_GROUPS)
            .map(|i| 400_000 + i as u32)
            .collect();
        let who = AsUser::new(NOBODY_UID, NOBODY_GID).groups(over);
        // Truncating would silently change what the identity may do, so an
        // over-long list must fail loudly instead.
        assert!(matches!(creds.register(&who), Err(Error::Validation(_))));
    });
}

#[test]
fn impersonated_open_obeys_dac() {
    if !is_root() {
        return; // cross-uid impersonation needs CAP_SETUID
    }
    with_broker(|h, creds, me, dir| {
        // A root-owned 0600 file, and a world-readable one beside it.
        std::fs::write(dir.join("secret"), b"root only").unwrap();
        std::fs::set_permissions(
            dir.join("secret"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        std::fs::write(dir.join("public"), b"everyone").unwrap();
        std::fs::set_permissions(
            dir.join("public"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        let anchor = Anchor::open(dir).unwrap();

        let user = creds
            .register(&AsUser::new(NOBODY_UID, NOBODY_GID))
            .expect("register nobody");

        // The daemon (root) can read the secret...
        let f = h.open(me, &anchor, "secret", rdonly()).expect("root open");
        h.close(f).unwrap();

        // ...the impersonated user cannot. This is the whole design in one
        // assertion: the kernel refused, under credentials the daemon
        // itself does not have.
        assert!(
            matches!(
                h.open(user, &anchor, "secret", rdonly()),
                Err(Error::Errno(Errno::EACCES))
            ),
            "impersonated open of a 0600 root file must be denied"
        );

        // A world-readable file is fine as that user.
        let f = h.open(user, &anchor, "public", rdonly()).expect("open");
        let (n, buf) = h.pread(user, &f, vec![0u8; 16], 0);
        assert_eq!(&buf[..n.unwrap()], b"everyone");
        h.close(f).unwrap();

        creds.unregister(user).unwrap();
    });
}

#[test]
fn impersonated_personality_holds_no_dac_override() {
    if !is_root() {
        return;
    }
    with_broker(|h, creds, _me, dir| {
        // A directory the user cannot even traverse.
        std::fs::create_dir(dir.join("vault")).unwrap();
        std::fs::write(dir.join("vault/inner"), b"x").unwrap();
        std::fs::set_permissions(
            dir.join("vault"),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        let anchor = Anchor::open(dir).unwrap();
        let user = creds
            .register(&AsUser::new(NOBODY_UID, NOBODY_GID))
            .unwrap();

        // CAP_DAC_OVERRIDE would sail through both of these. The snapshot
        // must not carry it: dropping euid to a non-root uid clears the
        // effective capability set, which is the property being pinned.
        assert!(matches!(
            h.open(user, &anchor, "vault/inner", rdonly()),
            Err(Error::Errno(Errno::EACCES))
        ));
        assert!(matches!(
            h.statx(
                user,
                &anchor,
                leaf("vault"),
                AtFlags::empty(),
                StatxMask::BASIC_STATS
            )
            .map(|st| st.is_dir()),
            Ok(true)
        ));
        let sub = Anchor::open(dir.join("vault").as_path()).unwrap();
        assert!(matches!(
            h.statx(
                user,
                &sub,
                leaf("inner"),
                AtFlags::empty(),
                StatxMask::BASIC_STATS
            ),
            Err(Error::Errno(Errno::EACCES))
        ));
        creds.unregister(user).unwrap();
    });
}

#[test]
fn impersonated_create_is_owned_by_the_user() {
    if !is_root() {
        return;
    }
    with_broker(|h, creds, _me, dir| {
        let anchor = Anchor::open(dir).unwrap();
        let user = creds
            .register(&AsUser::new(NOBODY_UID, NOBODY_GID))
            .unwrap();

        // O_CREAT under the personality: the file belongs to the user, not
        // to the (root) daemon that actually issued the syscall.
        let f = h.open(user, &anchor, "theirs", creat_rw()).expect("create");
        let (n, _b) = h.pwritev(user, &f, vec![b"mine".to_vec()], 0);
        assert_eq!(n.unwrap(), 4);
        h.close(f).unwrap();
        let md = std::fs::metadata(dir.join("theirs")).unwrap();
        assert_eq!(md.uid(), NOBODY_UID, "created as the impersonated user");
        assert_eq!(md.gid(), NOBODY_GID);

        // Directory entries too: mkdir and unlink run as the user.
        h.mkdirat(
            user,
            &anchor,
            leaf("theirdir"),
            Mode::from_bits_truncate(0o755),
        )
        .expect("mkdirat");
        assert_eq!(
            std::fs::metadata(dir.join("theirdir")).unwrap().uid(),
            NOBODY_UID
        );
        h.unlinkat(user, &anchor, leaf("theirs")).expect("unlinkat");
        assert!(!dir.join("theirs").exists());
        creds.unregister(user).unwrap();
    });
}

#[test]
fn impersonated_trusted_xattr_is_denied() {
    if !is_root() {
        return;
    }
    with_broker(|h, creds, me, dir| {
        let anchor = Anchor::open(dir).unwrap();
        let f = h.open(me, &anchor, "attr", creat_rw()).unwrap();
        let user = creds
            .register(&AsUser::new(NOBODY_UID, NOBODY_GID))
            .unwrap();

        let trusted = xattr_name("trusted.probe");
        let (res, _v) = h.fsetxattr(me, &f, &trusted, b"v".to_vec(), 0);
        if matches!(res, Err(Error::Errno(Errno::EOPNOTSUPP))) {
            creds.unregister(user).unwrap();
            h.close(f).unwrap();
            return; // kernel < 6.13 (or no trusted.* support here)
        }
        res.expect("root may write trusted.*");

        // trusted.* needs CAP_SYS_ADMIN, which the personality lacks. Note
        // the kernel's masquerade: an unprivileged *read* reports ENODATA
        // ("no such attribute"), not EPERM — it hides the attribute's
        // existence rather than its contents.
        let (res, _v) = h.fgetxattr(user, &f, &trusted, vec![0u8; 16]);
        assert!(
            matches!(res, Err(Error::Errno(Errno::ENODATA))),
            "unprivileged trusted.* read must report ENODATA, got {res:?}"
        );
        let (res, _v) = h.fsetxattr(user, &f, &trusted, b"z".to_vec(), 0);
        assert!(matches!(res, Err(Error::Errno(Errno::EPERM))));

        // user.* on a file the personality does not own is also refused.
        let user_attr = xattr_name("user.mine");
        let (res, _v) = h.fsetxattr(user, &f, &user_attr, b"z".to_vec(), 0);
        assert!(matches!(res, Err(Error::Errno(Errno::EACCES))));

        creds.unregister(user).unwrap();
        h.close(f).unwrap();
    });
}

#[test]
fn broker_reverts_credentials_between_registrations() {
    if !is_root() {
        return;
    }
    with_broker(|h, creds, _me, dir| {
        let anchor = Anchor::open(dir).unwrap();

        // Register a low-privilege identity, then another with a different
        // uid. If the broker failed to revert, the second snapshot would
        // inherit the first's (unprivileged) credentials and could not
        // impersonate a different user at all.
        let a = creds
            .register(&AsUser::new(NOBODY_UID, NOBODY_GID))
            .unwrap();
        let b = creds
            .register(&AsUser::new(NOBODY_UID - 1, NOBODY_GID - 1))
            .expect("second registration needs privilege back");

        let f = h.open(a, &anchor, "a", creat_rw()).unwrap();
        h.close(f).unwrap();
        let f = h.open(b, &anchor, "b", creat_rw()).unwrap();
        h.close(f).unwrap();
        assert_eq!(std::fs::metadata(dir.join("a")).unwrap().uid(), NOBODY_UID);
        assert_eq!(
            std::fs::metadata(dir.join("b")).unwrap().uid(),
            NOBODY_UID - 1
        );
        creds.unregister(a).unwrap();
        creds.unregister(b).unwrap();
    });
}

#[test]
fn unregistered_personality_stops_working() {
    with_broker(|h, creds, _me, dir| {
        let who = registerable_user();
        std::fs::write(dir.join("f"), b"x").unwrap();
        std::fs::set_permissions(
            dir.join("f"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        let anchor = Anchor::open(dir).unwrap();

        let id = creds.register(&who).expect("register");
        let f = h
            .open(id, &anchor, "f", rdonly())
            .expect("works while live");
        h.close(f).unwrap();

        creds.unregister(id).expect("unregister");
        // The id is gone: the kernel refuses the SQE outright rather than
        // falling back to the submitter's (root) credentials.
        assert!(matches!(
            h.open(id, &anchor, "f", rdonly()),
            Err(Error::Errno(Errno::EINVAL))
        ));
    });
}

// --- M3: the identity cache (register once per *identity*, not per connection)

#[test]
fn identity_cache_registers_once_per_identity() {
    with_broker(|h, creds, _me, dir| {
        let cache = IdentityCache::new(creds.clone());
        let who = registerable_user();

        // Many "connections" for one identity → one registration.
        let leases: Vec<_> = (0..8)
            .map(|_| cache.acquire(&who).expect("acquire"))
            .collect();
        assert_eq!(cache.len(), 1, "one cached identity");
        let id = leases[0].personality();
        assert!(
            leases.iter().all(|l| l.personality() == id),
            "every lease shares the personality"
        );

        // Group order and duplicates are not semantically meaningful, so an
        // equivalent list must hit the same entry rather than mint another.
        if !who.group_list().is_empty() {
            let mut shuffled = who.group_list().to_vec();
            shuffled.reverse();
            shuffled.push(shuffled[0]);
            let same = AsUser::new(who.uid, who.gid).groups(shuffled);
            let l = cache.acquire(&same).expect("acquire equivalent");
            assert_eq!(l.personality(), id, "set-equal identity is the same");
            assert_eq!(cache.len(), 1);
        }

        // The id works while leased.
        let anchor = Anchor::open(dir).unwrap();
        let f = h.open(id, &anchor, "c", creat_rw()).expect("open");
        h.close(f).unwrap();

        // Every lease is gone, but the cache map holds the last reference —
        // so the id survives and the next acquire reuses it rather than
        // paying for a fresh registration.
        drop(leases);
        let held = cache.acquire(&who).expect("re-acquire");
        assert_eq!(held.personality(), id, "still the same registration");
        let f = h.open(id, &anchor, "d", creat_rw()).expect("still live");
        h.close(f).unwrap();

        // The last lease *and* the cache entry must both go before the
        // kernel id is retired.
        cache.invalidate(&who);
        drop(held);
        assert!(matches!(
            h.open(id, &anchor, "e", creat_rw()),
            Err(Error::Errno(Errno::EINVAL))
        ));
    });
}

#[test]
fn identity_cache_invalidation_reregisters_without_disturbing_leases() {
    with_broker(|h, creds, _me, dir| {
        let cache = IdentityCache::new(creds.clone());
        let who = registerable_user();
        let anchor = Anchor::open(dir).unwrap();

        let old = cache.acquire(&who).expect("acquire");
        let old_id = old.personality();

        // A directory-services change: forget the snapshot. Work already
        // under way must not be disturbed — this is the property that lets
        // re-registration happen while requests are in flight.
        cache.invalidate(&who);
        assert_eq!(cache.len(), 0);
        let f = h
            .open(old_id, &anchor, "old", creat_rw())
            .expect("old lives");
        h.close(f).unwrap();

        // The next acquire mints a *fresh* personality.
        let new = cache.acquire(&who).expect("re-acquire");
        assert_ne!(new.personality(), old_id, "re-registered under a new id");
        let f = h
            .open(new.personality(), &anchor, "new", creat_rw())
            .expect("new works");
        h.close(f).unwrap();

        // Retiring the old lease does not disturb the new registration.
        drop(old);
        assert!(matches!(
            h.open(old_id, &anchor, "gone", creat_rw()),
            Err(Error::Errno(Errno::EINVAL))
        ));
        let f = h
            .open(new.personality(), &anchor, "still", creat_rw())
            .expect("new still works");
        h.close(f).unwrap();
    });
}

#[test]
fn identity_cache_is_concurrency_safe() {
    with_broker(|_h, creds, _me, _dir| {
        let cache = IdentityCache::new(creds.clone());
        let who = registerable_user();
        // A connection burst for one identity collapses to one registration
        // rather than stampeding the broker.
        let ids: Vec<Personality> = thread::scope(|s| {
            let handles: Vec<_> = (0..8)
                .map(|_| {
                    let cache = cache.clone();
                    let who = who.clone();
                    s.spawn(move || {
                        let l = cache.acquire(&who).expect("acquire");
                        l.personality()
                    })
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });
        assert!(
            ids.windows(2).all(|w| w[0] == w[1]),
            "all threads saw one personality: {ids:?}"
        );
        assert_eq!(cache.len(), 1);
    });
}

#[test]
fn large_ad_group_list_round_trips() {
    // winbindd imposes no small ceiling (Samba grows its buffer and
    // retries), and an AD Kerberos PAC carries on the order of 1000 group
    // SIDs, so the wire format and the impersonation window must handle a
    // list of that size — not just the handful a POSIX user has.
    if !is_root() {
        return; // setgroups with a foreign list needs CAP_SETGID
    }
    with_broker(|h, creds, _me, dir| {
        for n in [256usize, 1024, truenas_ros::async_fs::MAX_GROUPS] {
            let groups: Vec<u32> = (0..n as u32).map(|i| 200_000 + i).collect();
            // One of them is the group that will own the file, proving the
            // supplementary list actually reached the kernel intact rather
            // than being truncated somewhere in the middle.
            let marker = 200_000 + (n as u32 - 1);
            let who =
                AsUser::new(NOBODY_UID, NOBODY_GID).groups(groups.clone());
            assert_eq!(who.group_list().len(), n, "list preserved");

            let id = creds
                .register(&who)
                .unwrap_or_else(|e| panic!("register with {n} groups: {e}"));

            // A directory only that last group may enter: reaching the file
            // proves the tail of the list survived.
            let dirname = format!("g{n}");
            std::fs::create_dir(dir.join(&dirname)).unwrap();
            std::fs::write(dir.join(&dirname).join("f"), b"deep").unwrap();
            // SAFETY: valid path; chown to root:marker, mode 0710 — only a
            // member of `marker` can traverse it.
            let cpath = CString::new(dir.join(&dirname).as_os_str().as_bytes())
                .unwrap();
            assert_eq!(
                unsafe { libc::chown(cpath.as_ptr(), 0, marker) },
                0,
                "chown"
            );
            std::fs::set_permissions(
                dir.join(&dirname),
                std::fs::Permissions::from_mode(0o710),
            )
            .unwrap();

            let sub = Anchor::open(dir.join(&dirname).as_path()).unwrap();
            let f = h.open(id, &sub, "f", rdonly()).unwrap_or_else(|e| {
                panic!("group {marker} (entry {} of {n}) lost: {e}", n - 1)
            });
            let (got, buf) = h.pread(id, &f, vec![0u8; 8], 0);
            assert_eq!(&buf[..got.unwrap()], b"deep");
            h.close(f).unwrap();
            creds.unregister(id).unwrap();
        }
    });
}

// --- Security regressions -------------------------------------------------

#[test]
fn personality_zero_is_not_constructible() {
    // `sqe.personality == 0` means "no credential override" — an op stamped
    // with it runs as the reactor thread (the root daemon), bypassing the
    // whole per-op identity model. The public constructor must refuse 0 so
    // that path is unreachable, as the module docs claim.
    assert!(Personality::from_raw(0).is_none());
    assert_eq!(Personality::from_raw(1).map(|p| p.id()), Some(1));
    assert_eq!(Personality::from_raw(4242).map(|p| p.id()), Some(4242));
}

#[test]
fn sentinel_uid_gid_are_refused_by_the_api() {
    // `(uid_t)-1`/`(gid_t)-1` are the kernel's "leave unchanged" sentinel for
    // setres*id: a broker that passed them straight through would no-op the
    // privilege drop and snapshot its own root creds. The API must reject
    // them before they reach the impersonation window.
    with_broker(|_h, creds, _me, _dir| {
        assert!(matches!(
            creds.register(&AsUser::new(u32::MAX, 1000)),
            Err(Error::Validation(_))
        ));
        assert!(matches!(
            creds.register(&AsUser::new(1000, u32::MAX)),
            Err(Error::Validation(_))
        ));
    });
}
