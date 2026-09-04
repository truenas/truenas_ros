//! Integration tests for the `uring_fs` io_uring reactor - live data and
//! metadata ops against a tempdir, every one stamped with a self personality
//! and resolved against an [`Anchor`] (there is no unstamped or
//! absolute-path variant to test).
//!
//! Like `test/net_server.rs`, these **skip** (return early) when io_uring is
//! unavailable - a bare sandbox blocks the syscalls (ENOSYS/EPERM/EACCES) --
//! and `TRUENAS_ROS_REQUIRE_IO_URING=1` turns that skip into a hard failure.
//!
//! `UringFs` is `!Send` (single-thread ring), so the harness runs the loop on
//! the test thread and drives the client from a scoped thread; a panic-safe
//! guard stops the loop however the client exits.
#![cfg(all(target_os = "linux", feature = "uring-fs"))]

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;
use truenas_ros::sync_fs::{
    AtFlags, Mode, OFlag, OpenHow, RenameFlags, ResolveFlag, StatxAttr,
    StatxMask, ZfsAttr,
};
use truenas_ros::uring_fs::{
    Advice, Anchor, AsUser, Caps, CredBroker, CredHandle, EnrichSpec, File,
    FsConfig, FsHandle, IdentityCache, Leaf, Order, Personality,
    PrivilegedXattrs, QueryOptions, RwFlags, ShutdownHandle, TreeCursor,
    TreeOptions, UringFs, query_directory, query_tree,
};
use truenas_ros::{Errno, Error};

#[path = "support/privilege.rs"]
mod privilege;
#[path = "support/xattr.rs"]
mod xattr_probe;
#[path = "support/zfs_dir.rs"]
mod zfs_dir;

use privilege::{is_root, root_or_skip};
use zfs_dir::zfs_dir_or_skip;

/// Hold a ring-side `fsetxattr` refusal to the `TRUENAS_ROS_REQUIRE_XATTRS`
/// gate, returning whether the set stuck.
///
/// The probes here set through the fs handle rather than `libc`, so the
/// shared module's path helper cannot serve them - but what a refusal means
/// is identical: every xattr assertion behind it is about to be skipped, and
/// a runner whose scratch filesystem dropped xattr support has to fail where
/// CI arms the gate rather than pass green having tested nothing.
fn fd_xattr_ok<T>(what: &str, res: &Result<T, Error>) -> bool {
    if let Err(e) = res {
        xattr_probe::refusal_is_allowed(what, e);
    }
    res.is_ok()
}

/// Single-buffer read, over the reactor's only read op.
///
/// `uring_fs` exposes just the vectored, flagged forms - one shape to learn
/// and one to audit - so the many tests that read a single buffer wrap it
/// here rather than repeating `vec![..]` and `RwFlags::empty()` and then
/// indexing the result.
fn pread1(
    h: &FsHandle,
    who: Personality,
    f: &File,
    buf: Vec<u8>,
    off: u64,
) -> (Result<usize, Error>, Vec<u8>) {
    let (res, mut bufs) = h.preadv2(who, f, vec![buf], off, RwFlags::empty());
    (res, bufs.pop().unwrap_or_default())
}

/// Single-buffer write; the write-side twin of [`pread1`].
fn pwrite1(
    h: &FsHandle,
    who: Personality,
    f: &File,
    buf: Vec<u8>,
    off: u64,
) -> (Result<usize, Error>, Vec<u8>) {
    let (res, mut bufs) = h.pwritev2(who, f, vec![buf], off, RwFlags::empty());
    (res, bufs.pop().unwrap_or_default())
}

/// A validated single component, for the many call sites that pass one.
fn leaf(name: &str) -> Leaf<'_> {
    Leaf::new(name).expect("valid leaf")
}

fn xattr_name(name: &str) -> CString {
    CString::new(name).unwrap()
}

/// Errors that mean "io_uring is unavailable here" - an environmental skip.
/// Deliberately excludes `EINVAL` (a rejected setup argument is a real bug).
fn should_skip(e: &Error) -> bool {
    let unavailable = matches!(
        e,
        // ENOMEM: rings pin pages against RLIMIT_MEMLOCK, so a loaded
        // box exhausts it and ring creation fails - environmental, and
        // the REQUIRE variable turns the skip red where it must not
        // happen.
        Error::Errno(
            Errno::EPERM | Errno::ENOSYS | Errno::EACCES | Errno::ENOMEM
        )
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

/// Pin a known umask for the whole binary. Several tests assert on the mode
/// of something they create - `mkdirat`'s mode argument, or a setup file an
/// impersonated user has to be able to read - and the kernel masks every one
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

/// Reactor sizing for tests, deliberately **not** [`FsConfig::default`].
///
/// The default is sized for a server daemon, which costs roughly 400 KiB of
/// `RLIMIT_MEMLOCK` per ring (see `FsConfig`'s docs). `cargo test` runs a
/// binary's tests as threads in **one** process, so inheriting that default
/// would have every concurrent test drawing on one locked-memory budget - and
/// the failure lands on whichever test happens to create the ring that
/// crosses the limit, not on the one that caused it.
fn test_cfg() -> FsConfig {
    let mut cfg = FsConfig::default();
    cfg.entries = 128;
    cfg.ops = 128;
    cfg
}

/// Build an `UringFs` over a fresh tempdir, register a self personality, run
/// the loop on this thread, and drive `client` from a scoped thread.
fn with_fs<F>(cfg: FsConfig, client: F)
where
    F: FnOnce(FsHandle, Personality, PathBuf, ShutdownHandle) + Send,
{
    pin_umask();
    let dir = truenas_ros::tempdir().expect("tempdir");
    let mut afs = match UringFs::new(cfg) {
        Ok(a) => a,
        Err(e) => {
            if should_skip(&e) {
                return;
            }
            panic!("UringFs::new: {e}");
        }
    };
    let me = afs.register_self().expect("register_self");
    let handle = afs.handle();
    let stop = afs.shutdown_handle();
    let dir_path = dir.path().to_path_buf();
    thread::scope(|s| {
        let stop_for_client = stop.clone();
        s.spawn(move || {
            let _guard = StopGuard(stop);
            client(handle, me, dir_path, stop_for_client);
        });
        afs.run().expect("run");
    });
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

/// A close-on-exec pipe, returned `(read end, write end)`. Both are plain
/// descriptors the caller closes; `splice_from_pipe` never adopts either.
fn pipe_pair() -> (libc::c_int, libc::c_int) {
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: `pipe2` writes exactly two descriptors into `fds`.
    let rc = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
    assert_eq!(rc, 0, "pipe2: {}", std::io::Error::last_os_error());
    (fds[0], fds[1])
}

/// `splice_from_pipe` moves pipe bytes into a file with no userspace buffer,
/// honouring the destination offset - and reports a short move as a count
/// rather than an error, which is what the resubmit contract rests on.
///
/// Bites three ways: drop the destination offset and the seeded bytes are
/// overwritten at 0; leave `splice_off_in` at 0 instead of -1 and the kernel
/// refuses a pipe source with `ESPIPE`; put the pipe in `sqe.fd` instead of
/// `splice_fd_in` and it moves nothing.
#[test]
fn splice_from_a_pipe_lands_at_the_offset_and_reports_short_moves() {
    with_fs(test_cfg(), |h, me, dir, _stop| {
        let anchor = Anchor::open(dir.as_path()).expect("anchor");
        let f = h
            .open(me, &anchor, "spliced.bin", creat_rw())
            .expect("open");

        // Seed 16 bytes so a splice at offset 4 has to land *inside* existing
        // content: an ignored offset shows up as clobbered leading bytes.
        let (n, _) =
            h.pwritev2(me, &f, vec![vec![b'.'; 16]], 0, RwFlags::empty());
        assert_eq!(n.expect("seed"), 16);

        let (rd, wr) = pipe_pair();
        let body = b"SPLICED";
        // SAFETY: writing our own buffer to our own pipe's write end.
        let w = unsafe { libc::write(wr, body.as_ptr().cast(), body.len()) };
        assert_eq!(w, body.len() as isize, "seed the pipe");
        // Close the write end so the pipe is at EOF once drained, making both
        // the short move and the follow-up zero deterministic.
        // SAFETY: our own descriptor, not used again.
        unsafe { libc::close(wr) };

        // Ask for far more than the pipe holds.
        let moved = h.splice_from_pipe(me, &f, rd, 4, 4096).expect("splice");
        assert_eq!(
            moved,
            body.len() as u64,
            "a pipe delivers what it has; short is progress, not failure"
        );

        // Drained: the next move is a clean zero, not an error.
        let eof = h
            .splice_from_pipe(me, &f, rd, 11, 4096)
            .expect("splice eof");
        assert_eq!(eof, 0, "drained pipe with the write end closed");
        // SAFETY: our own descriptor, not used again.
        unsafe { libc::close(rd) };

        h.fsync(me, &f).expect("fsync");
        h.close(f).expect("close");

        let disk = std::fs::read(dir.join("spliced.bin")).expect("std read");
        assert_eq!(disk.len(), 16, "a splice inside the file cannot extend it");
        assert_eq!(&disk[..4], b"....", "bytes before the offset are intact");
        assert_eq!(&disk[4..11], body, "the body landed at the offset");
        assert_eq!(&disk[11..], b".....", "bytes after are intact");
    });
}

#[test]
fn round_trip_write_fsync_read() {
    with_fs(test_cfg(), |h, me, dir, _stop| {
        let anchor = Anchor::open(dir.as_path()).expect("anchor");

        // Write a new file through the reactor: two gathered buffers.
        let f = h.open(me, &anchor, "out.bin", creat_rw()).expect("open");
        let (n, bufs) = h.pwritev2(
            me,
            &f,
            vec![b"hello ".to_vec(), b"world".to_vec()],
            0,
            RwFlags::empty(),
        );
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
        let (n, bufs) = h.preadv2(
            me,
            &f,
            vec![vec![0u8; 4], vec![0u8; 4], vec![0u8; 8]],
            0,
            RwFlags::empty(),
        );
        assert_eq!(n.expect("readv"), 11, "short only at EOF");
        assert_eq!(&bufs[0], b"hell");
        assert_eq!(&bufs[1], b"o wo");
        assert_eq!(&bufs[2][..3], b"rld");

        // Positional single-buffer read.
        let (n, buf) = pread1(&h, me, &f, vec![0u8; 5], 6);
        assert_eq!(n.expect("pread"), 5);
        assert_eq!(&buf, b"world");
        h.close(f).expect("close 2");
    });
}

/// `fstatfs` answers for the mount, from a file and from an anchor alike, and
/// the two agree because they name the same filesystem. The anchor form is
/// the one that matters: an `Anchor` is `O_PATH`, which `fsync` refuses, so
/// this pins that `fstatfs` accepts it and a caller need not open anything to
/// ask a whole tree's capacity.
#[test]
fn fstatfs_answers_from_a_file_and_from_an_anchor() {
    with_fs(test_cfg(), |h, me, dir, _stop| {
        let anchor = Anchor::open(dir.as_path()).expect("anchor");
        let f = h.open(me, &anchor, "sf.bin", creat_rw()).expect("open");

        let by_anchor = h.fstatfs_anchor(&anchor).expect("statfs by anchor");
        let by_file = h.fstatfs(&f).expect("statfs by file");

        assert!(by_anchor.block_size() > 0, "a unit is always reported");
        assert_eq!(
            by_anchor.block_size(),
            by_file.block_size(),
            "same filesystem, same unit"
        );
        assert_eq!(
            by_anchor.total_blocks(),
            by_file.total_blocks(),
            "same filesystem, same size"
        );
        assert!(by_anchor.total_blocks() > 0);
        assert!(by_anchor.available_blocks() <= by_anchor.free_blocks());
        assert_eq!(
            by_anchor.total_bytes(),
            by_anchor.total_blocks() * by_anchor.block_size()
        );
        h.close(f).expect("close");
    });
}

/// The immutability claim, exercised rather than asserted: set `IMMUTABLE`
/// through the reactor and the file becomes undeletable *and* its xattrs
/// unwritable - enforcement the VFS applies, so no protocol routes around it.
///
/// Needs a real ZFS dataset - a tmpfs tempdir answers the ioctl `ENOTTY` - so
/// it resolves one and skips loudly under `TRUENAS_ROS_REQUIRE_ZFS`, which
/// the QEMU job arms. Unprivileged, the `EPERM` on setting the flag is itself
/// the property under test and is asserted rather than skipped.
#[test]
fn an_immutable_file_cannot_be_unlinked_or_relabelled() {
    let Some(ds) = zfs_dir_or_skip() else {
        return;
    };
    with_fs(test_cfg(), |h, me, _dir, _stop| {
        let anchor = Anchor::open(ds.as_path()).expect("anchor");
        let f = h.open(me, &anchor, "locked.bin", creat_rw()).expect("open");
        let (n, _) = pwrite1(&h, me, &f, b"retained".to_vec(), 0);
        assert_eq!(n.expect("write"), 8);

        let before = h
            .fget_zfs_attrs(&f)
            .expect("a ZFS dataset must answer the attribute ioctl");
        assert_eq!(
            before & ZfsAttr::IMMUTABLE,
            ZfsAttr::empty(),
            "a fresh file is not locked"
        );

        // Metadata has to land before the lock: an immutable inode refuses
        // xattr writes (`may_write_xattr`, fs/xattr.c).
        let name = xattr_name("user.retain-until");
        let (res, _) = h.fsetxattr(me, &f, &name, b"2099-01-01".to_vec(), 0);
        res.expect("xattr before locking");

        match h.fset_zfs_attrs(&f, before | ZfsAttr::IMMUTABLE) {
            Ok(()) => {}
            // CAP_LINUX_IMMUTABLE is required, and its absence is the very
            // property under test - so an unprivileged refusal is a pass for
            // the half this can reach, not a skip of the whole test.
            Err(Error::Errno(Errno::EPERM)) => {
                assert!(!is_root(), "root was refused CAP_LINUX_IMMUTABLE");
                h.close(f).expect("close");
                return;
            }
            Err(e) => panic!("fset_zfs_attrs: {e}"),
        }

        // statx sees it without an ioctl - the free read path.
        let st = h
            .fstatx(me, &f, AtFlags::empty(), StatxMask::BASIC_STATS)
            .expect("fstatx");
        assert!(
            st.attributes().contains(StatxAttr::IMMUTABLE),
            "statx must report the lock"
        );

        // The lock holds against deletion and against relabelling.
        let unlinked = h.unlinkat(me, &anchor, leaf("locked.bin"));
        assert!(
            matches!(unlinked, Err(Error::Errno(Errno::EPERM))),
            "an immutable file must not unlink: {unlinked:?}"
        );
        let (res, _) = h.fsetxattr(me, &f, &name, b"2000-01-01".to_vec(), 0);
        assert!(
            matches!(res, Err(Error::Errno(Errno::EPERM))),
            "an immutable file's xattrs must be sealed: {res:?}"
        );

        // Clear it so the tempdir can be torn down.
        h.fset_zfs_attrs(&f, before).expect("unlock");
        h.unlinkat(me, &anchor, leaf("locked.bin")).expect("unlink");
        h.close(f).expect("close");
    });
}

#[test]
fn ranged_fsync_syncs_a_byte_range_and_whole_file() {
    with_fs(test_cfg(), |h, me, dir, _stop| {
        let anchor = Anchor::open(dir.as_path()).expect("anchor");
        let f = h.open(me, &anchor, "ranged.bin", creat_rw()).expect("open");

        // Write 8 KiB so a sub-range fsync has a range to bound.
        let data = vec![0xABu8; 8192];
        let (n, _) = pwrite1(&h, me, &f, data.clone(), 0);
        assert_eq!(n.expect("pwrite"), 8192);

        // Sync just the first 4 KiB (fsync range form: off=0, len=4096), then a
        // tail range with datasync semantics, then the whole file via 0/0.
        h.fsync_range(me, &f, false, 0, 4096)
            .expect("fsync_range head");
        h.fsync_range(me, &f, true, 4096, 4096)
            .expect("fdatasync_range tail");
        h.fsync_range(me, &f, false, 0, 0)
            .expect("fsync_range whole");
        // The plain wrappers keep their whole-file behavior.
        h.fsync(me, &f).expect("fsync");
        h.fdatasync(me, &f).expect("fdatasync");
        h.close(f).expect("close");

        // The data is intact on disk.
        let disk = std::fs::read(dir.join("ranged.bin")).expect("read");
        assert_eq!(disk, data);
    });
}

#[test]
fn multi_component_and_beneath() {
    with_fs(test_cfg(), |h, me, dir, _stop| {
        std::fs::create_dir(dir.join("sub")).unwrap();
        std::fs::write(dir.join("sub/inner.txt"), b"beneath").unwrap();
        let anchor = Anchor::open(dir.as_path()).unwrap();

        // Multi-component relative paths are the open's job (only op that
        // walks); RESOLVE_BENEATH confines them in-kernel.
        let how = rdonly().resolve(ResolveFlag::RESOLVE_BENEATH);
        let f = h.open(me, &anchor, "sub/inner.txt", how).expect("open");
        let (n, buf) = pread1(&h, me, &f, vec![0u8; 16], 0);
        assert_eq!(&buf[..n.unwrap()], b"beneath");
        h.close(f).unwrap();

        // Escaping the anchor under RESOLVE_BENEATH is the kernel's EXDEV.
        let how = rdonly().resolve(ResolveFlag::RESOLVE_BENEATH);
        match h.open(me, &anchor, "../escape", how) {
            Err(Error::Errno(Errno::EXDEV)) => {}
            other => panic!("expected EXDEV, got {other:?}"),
        }

        // The DEFAULT (no explicit resolve) confines too: `open` applies the
        // whole `CONFINED_RESOLVE` set - BENEATH | NO_SYMLINKS | NO_XDEV --
        // when `how` states no policy, so a bare `rdonly()` rejects a `..`
        // escape without the caller opting in.
        match h.open(me, &anchor, "../escape", rdonly()) {
            Err(Error::Errno(Errno::EXDEV)) => {}
            other => panic!("default open must confine `..`, got {other:?}"),
        }
        // ...and does not follow a symlink (NO_SYMLINKS -> ELOOP), so a
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
fn fstatx_reports_open_file_metadata() {
    with_fs(test_cfg(), |h, me, dir, _stop| {
        std::fs::write(dir.join("m.bin"), vec![0u8; 4096]).unwrap();
        let anchor = Anchor::open(dir.as_path()).unwrap();
        let f = h.open(me, &anchor, "m.bin", rdonly()).expect("open");
        // fstat-by-fd: no path resolved - the metadata is exactly this fd's.
        let st = h
            .fstatx(me, &f, AtFlags::empty(), StatxMask::BASIC_STATS)
            .expect("fstatx");
        assert_eq!(st.size(), 4096);
        h.close(f).unwrap();
    });
}

/// A `resolve` that only *hardens* must not also un-confine. `open` applies
/// the full `CONFINED_RESOLVE` and lets a caller replace it, but only by
/// naming a policy (`RESOLVE_BENEATH`, `RESOLVE_IN_ROOT`); a request for
/// `RESOLVE_NO_MAGICLINKS` asks for *more* restriction and keeps the default
/// underneath it. Keying that union on `resolve == 0` instead turns the
/// hardening request into an escape hatch, which is what this pins.
#[test]
fn a_hardening_flag_does_not_opt_out_of_confinement() {
    with_fs(test_cfg(), |h, me, dir, _stop| {
        std::fs::write(dir.join("abs.txt"), b"abs").unwrap();
        std::os::unix::fs::symlink("abs.txt", dir.join("link")).unwrap();
        let anchor = Anchor::open(dir.as_path()).unwrap();
        let abs = dir.join("abs.txt"); // an absolute path

        let hardened = rdonly().resolve(ResolveFlag::RESOLVE_NO_MAGICLINKS);
        for (what, how) in [("default", rdonly()), ("hardened", hardened)] {
            // An absolute path cannot be resolved from the filesystem root.
            match h.open(me, &anchor, &abs, how) {
                Err(Error::Errno(Errno::EXDEV)) => {}
                other => panic!("{what}: absolute path opened: {other:?}"),
            }
            // Nor is a symlink followed, in-tree or not.
            match h.open(me, &anchor, "link", how) {
                Err(Error::Errno(Errno::ELOOP)) => {}
                other => panic!("{what}: symlink followed: {other:?}"),
            }
        }

        // A *stated* policy still stands alone: `RESOLVE_BENEATH` without
        // `RESOLVE_NO_SYMLINKS` is how a caller asks to follow in-tree
        // symlinks, and it must keep meaning that.
        let stated = rdonly().resolve(ResolveFlag::RESOLVE_BENEATH);
        let f = h
            .open(me, &anchor, "link", stated)
            .expect("in-tree symlink");
        h.close(f).unwrap();
    });
}

#[test]
fn validation_and_errno_mapping() {
    with_fs(test_cfg(), |h, me, dir, _stop| {
        let anchor = Anchor::open(dir.as_path()).unwrap();

        // An empty path is a library-validation error; an absolute path is
        // refused by the *kernel* under the default RESOLVE_BENEATH confinement
        // (it cannot resolve outside the anchor).
        assert!(matches!(
            h.open(me, &anchor, "", rdonly()),
            Err(Error::Validation(_))
        ));
        assert!(matches!(
            h.open(me, &anchor, "/etc/hostname", rdonly()),
            Err(Error::Errno(Errno::EXDEV))
        ));
        // O_CLOEXEC is accepted now (opens return real fds) and reaches the
        // kernel, which opens the file.
        std::fs::write(dir.join("cx"), b"cx").unwrap();
        let cloexec = OpenHow::new().flags(OFlag::O_RDONLY | OFlag::O_CLOEXEC);
        let fc = h.open(me, &anchor, "cx", cloexec).expect("O_CLOEXEC open");
        h.close(fc).unwrap();

        // Kernel errno round-trips: ENOENT for a missing file, EBADF for a
        // write on a read-only open.
        assert!(matches!(
            h.open(me, &anchor, "missing.txt", rdonly()),
            Err(Error::Errno(Errno::ENOENT))
        ));
        std::fs::write(dir.join("ro.txt"), b"ro").unwrap();
        let f = h.open(me, &anchor, "ro.txt", rdonly()).unwrap();
        let (res, _buf) = pwrite1(&h, me, &f, b"nope".to_vec(), 0);
        assert!(matches!(res, Err(Error::Errno(Errno::EBADF))));
        h.close(f).unwrap();
    });
}

#[test]
fn stale_personality_from_other_ring_is_einval() {
    // Two reactors: an id registered on ring A names nothing on ring B.
    let dir = truenas_ros::tempdir().unwrap();
    let afs_a = match UringFs::new(test_cfg()) {
        Ok(a) => a,
        Err(e) => {
            if should_skip(&e) {
                return;
            }
            panic!("{e}");
        }
    };
    let id_a = afs_a.register_self().unwrap();
    let mut afs_b = UringFs::new(test_cfg()).unwrap();
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

// Files are plain reference-counted fds now - there is no per-file pool to
// exhaust (`ENFILE`), and dropping a token does NOT cancel in-flight ops: the
// reactor keeps the fd alive (via the op entry's parked `Arc<OwnedFd>`) until
// the op completes, then the fd closes with the last reference (close-last by
// ownership). This test covers that cancel-safety property: a parked read
// whose only caller token is dropped mid-flight still completes correctly when
// data arrives - no use-after-close.
#[test]
fn dropped_file_mid_op_completes_without_use_after_close() {
    with_fs(test_cfg(), |h, me, dir, _stop| {
        mkfifo(&dir, "fifo");
        let anchor = Anchor::open(dir.as_path()).unwrap();

        // O_RDWR on a FIFO opens immediately and keeps a writer attached, so a
        // read with no data parks - an op genuinely in flight.
        let how = OpenHow::new().flags(OFlag::O_RDWR);
        let f = h.open(me, &anchor, "fifo", how).expect("open fifo");
        let pending = h
            .start_preadv2(me, &f, vec![vec![0u8; 4]], 0, RwFlags::empty())
            .expect("start readv");
        thread::sleep(Duration::from_millis(50)); // let it park in the kernel

        // Drop the caller's only token while the read is parked. The reactor
        // still owns the fd (op-entry `Arc`), so the read stays valid.
        drop(f);

        // Feed the fifo from a fresh writer; the parked read must complete with
        // the real bytes, proving the fd was not closed out from under it.
        let path = dir.join("fifo");
        let writer = thread::spawn(move || {
            use std::io::Write;
            let mut w =
                std::fs::OpenOptions::new().write(true).open(&path).unwrap();
            w.write_all(b"okay").unwrap();
        });

        let (res, bufs) = pending.wait();
        assert_eq!(res.expect("parked read completes after data arrives"), 4);
        assert_eq!(&bufs[0], b"okay");
        writer.join().unwrap();
    });
}

/// A creating open must not block on a name someone else planted.
///
/// `io_openat_force_async` puts every `O_CREAT`/`O_TRUNC` open on an io-wq
/// worker, where the kernel does *not* add the `O_NONBLOCK` its inline path
/// adds, so an `O_CREAT` that lands on a pre-existing FIFO sleeps in
/// `wait_for_partner` until a writer appears. That pins a bounded io-wq
/// worker and the calling thread - `into_outcome` waits with no deadline --
/// so a handful of names in a shared multiprotocol tree stall every blocking
/// fs op on the ring.
///
/// Both flags are driven: `O_CREAT|O_RDONLY` blocks for a writer,
/// `O_TRUNC|O_WRONLY` for a reader. Non-blocking, the first opens and the
/// second answers `ENXIO`; what is asserted is that each *returns*.
#[test]
fn a_creating_open_of_a_planted_fifo_does_not_block() {
    use std::sync::mpsc;
    with_fs(test_cfg(), |h, me, dir, _stop| {
        mkfifo(&dir, "planted");
        let anchor = Anchor::open(dir.as_path()).unwrap();
        for (what, flags) in [
            ("O_CREAT|O_RDONLY", OFlag::O_CREAT | OFlag::O_RDONLY),
            ("O_TRUNC|O_WRONLY", OFlag::O_TRUNC | OFlag::O_WRONLY),
        ] {
            let (tx, rx) = mpsc::channel();
            let h2 = h.clone();
            let a2 = anchor.clone();
            // Off-thread, because the failure mode is an indefinite block: a
            // regression must fail this test rather than hang it.
            thread::spawn(move || {
                let how = OpenHow::new()
                    .flags(flags)
                    .mode(Mode::from_bits_truncate(0o600));
                let _ = tx.send(h2.open(me, &a2, "planted", how).is_ok());
            });
            rx.recv_timeout(Duration::from_secs(3)).unwrap_or_else(|_| {
                panic!(
                    "{what} on a pre-existing FIFO never returned: the open \
                     is blocked in fifo_open on an io-wq worker, and the \
                     calling thread with it"
                )
            });
        }
    });
}

#[test]
fn teardown_with_inflight_op() {
    with_fs(test_cfg(), |h, me, dir, stop| {
        mkfifo(&dir, "fifo");
        let anchor = Anchor::open(dir.as_path()).unwrap();
        let how = OpenHow::new().flags(OFlag::O_RDWR);
        let f = h.open(me, &anchor, "fifo", how).expect("open fifo");
        let pending = h
            .start_preadv2(me, &f, vec![vec![0u8; 8]], 0, RwFlags::empty())
            .expect("start readv");
        thread::sleep(Duration::from_millis(50));

        // Shut down with the read parked: run()'s drain cancels it, the
        // waiter unblocks with an error, and run() returns cleanly (the
        // harness asserts that).
        stop.shutdown();
        let (res, _bufs) = pending.wait();
        assert!(res.is_err(), "parked read must fail at teardown");
        // The token is now pointed at a dead loop; ops fail, drop is inert.
        let (res, _buf) = pread1(&h, me, &f, vec![0u8; 4], 0);
        assert!(matches!(res, Err(Error::Errno(Errno::ECONNABORTED))));
        drop(f);
    });
}

#[test]
fn concurrent_ops_across_threads() {
    with_fs(test_cfg(), |h, me, dir, _stop| {
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
                    let (n, _bufs) = h.pwritev2(
                        me,
                        &f,
                        vec![payload.clone()],
                        0,
                        RwFlags::empty(),
                    );
                    assert_eq!(n.unwrap(), payload.len());
                    h.fsync(me, &f).unwrap();
                    h.close(f).unwrap();
                    // Verify through a fresh open + scattered read.
                    let f = h.open(me, &anchor, name, rdonly()).unwrap();
                    let half = payload.len() / 2;
                    let (n, bufs) = h.preadv2(
                        me,
                        &f,
                        vec![vec![0u8; half], vec![0u8; payload.len() - half]],
                        0,
                        RwFlags::empty(),
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
    with_fs(test_cfg(), |h, me, dir, _stop| {
        let anchor = Anchor::open(dir.as_path()).unwrap();
        let f = h.open(me, &anchor, "sparse", creat_rw()).unwrap();
        let (n, _b) = pwrite1(&h, me, &f, b"tail".to_vec(), 100);
        assert_eq!(n.unwrap(), 4);
        let (n, buf) = pread1(&h, me, &f, vec![0u8; 8], 98);
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
    with_fs(test_cfg(), |h, me, dir, _stop| {
        let anchor = Anchor::open(dir.as_path()).unwrap();
        let f = h.open(me, &anchor, "doc.bin", creat_rw()).unwrap();

        let (n, _b) = pwrite1(&h, me, &f, vec![b'x'; 4096], 0);
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
    with_fs(test_cfg(), |h, me, dir, _stop| {
        let anchor = Anchor::open(dir.as_path()).unwrap();
        let f = h.open(me, &anchor, "t.bin", creat_rw()).unwrap();
        let (n, _b) = pwrite1(&h, me, &f, vec![b'y'; 100], 0);
        assert_eq!(n.unwrap(), 100);

        h.ftruncate(me, &f, 10).expect("ftruncate");
        assert_eq!(std::fs::metadata(dir.join("t.bin")).unwrap().len(), 10);
        h.close(f).unwrap();
    });
}

#[test]
fn fd_metadata_respects_close_last() {
    // Metadata ops hold a file reference like data ops do, so a close racing
    // one in flight must still be the file's last op: the reactor parks an
    // `Arc<OwnedFd>` clone for the duration, and the descriptor closes when
    // that clone drops, not when the caller lets go.
    with_fs(test_cfg(), |h, me, dir, _stop| {
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
    with_fs(test_cfg(), |h, me, dir, _stop| {
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

        // The anchor itself, via AT_EMPTY_PATH - the closest to fd-based
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
    with_fs(test_cfg(), |h, me, dir, _stop| {
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
    with_fs(test_cfg(), |h, me, dir, _stop| {
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

/// An `O_TMPFILE` create is invisible until `linkat` names it, and complete the
/// instant it becomes visible - the durable-publish property an object store
/// needs. Also pins that the file really has no name beforehand: the directory
/// stays empty while the data is being written.
#[test]
fn o_tmpfile_is_invisible_until_linkat_publishes_it() {
    with_fs(test_cfg(), |h, me, dir, _stop| {
        let anchor = Anchor::open(dir.as_path()).expect("anchor");

        // O_TMPFILE names the *directory*; the file it creates has no entry.
        // Deliberately no O_EXCL - that is the "never linkable" opt-out.
        let how = OpenHow::new()
            .flags(OFlag::O_TMPFILE | OFlag::O_RDWR)
            .mode(Mode::from_bits_truncate(0o600));
        let f = h.open(me, &anchor, ".", how).expect("open O_TMPFILE");

        let (n, _) = pwrite1(&h, me, &f, b"published atomically".to_vec(), 0);
        assert_eq!(n.expect("write"), 20);
        h.fdatasync(me, &f).expect("fdatasync");

        // Written, synced, and still nowhere in the namespace.
        assert_eq!(
            std::fs::read_dir(&dir).unwrap().count(),
            0,
            "an unlinked O_TMPFILE must not appear in its directory"
        );

        h.linkat_file(me, &f, &anchor, leaf("object"))
            .expect("linkat AT_EMPTY_PATH");

        // Visible, and already whole: no window where a reader sees a partial
        // file, which is the entire point of publishing this way.
        assert_eq!(
            std::fs::read(dir.join("object")).unwrap(),
            b"published atomically"
        );
    });
}

/// `linkat` cannot replace an existing name, so overwriting is link-to-temp
/// then rename. Pins the `EEXIST` that forces the two-step, and that the
/// rename really does replace the old content atomically.
#[test]
fn linkat_file_cannot_replace_but_rename_can() {
    with_fs(test_cfg(), |h, me, dir, _stop| {
        let anchor = Anchor::open(dir.as_path()).expect("anchor");
        std::fs::write(dir.join("object"), b"old").unwrap();

        let how = OpenHow::new()
            .flags(OFlag::O_TMPFILE | OFlag::O_RDWR)
            .mode(Mode::from_bits_truncate(0o600));
        let f = h.open(me, &anchor, ".", how).expect("open O_TMPFILE");
        let (n, _) = pwrite1(&h, me, &f, b"new".to_vec(), 0);
        assert_eq!(n.expect("write"), 3);

        // Straight at the live name: refused.
        assert!(
            matches!(
                h.linkat_file(me, &f, &anchor, leaf("object")),
                Err(Error::Errno(Errno::EEXIST))
            ),
            "linkat must not clobber an existing entry"
        );
        assert_eq!(std::fs::read(dir.join("object")).unwrap(), b"old");

        // Land on a private name, then rename over the target.
        h.linkat_file(me, &f, &anchor, leaf(".tmp.object"))
            .expect("link to a staging name");
        h.renameat(
            me,
            &anchor,
            leaf(".tmp.object"),
            &anchor,
            leaf("object"),
            RenameFlags::empty(),
        )
        .expect("rename over the target");

        assert_eq!(std::fs::read(dir.join("object")).unwrap(), b"new");
        assert!(!dir.join(".tmp.object").exists(), "staging name consumed");
    });
}

/// `O_EXCL` with `O_TMPFILE` is the "this inode may never be linked" opt-out:
/// the kernel withholds `I_LINKABLE`, and `vfs_link` then refuses an inode
/// whose link count is zero. The failure is `ENOENT`, which says nothing about
/// the real cause - hence the test, and hence the warning in the docs.
#[test]
fn o_tmpfile_with_o_excl_is_unlinkable() {
    with_fs(test_cfg(), |h, me, dir, _stop| {
        let anchor = Anchor::open(dir.as_path()).expect("anchor");
        let how = OpenHow::new()
            .flags(OFlag::O_TMPFILE | OFlag::O_RDWR | OFlag::O_EXCL)
            .mode(Mode::from_bits_truncate(0o600));
        let f = h
            .open(me, &anchor, ".", how)
            .expect("O_TMPFILE|O_EXCL still opens");

        assert!(
            matches!(
                h.linkat_file(me, &f, &anchor, leaf("object")),
                Err(Error::Errno(Errno::ENOENT))
            ),
            "an O_EXCL temp file is permanently anonymous"
        );
        assert!(!dir.join("object").exists());
    });
}

/// Which personality may publish an `O_TMPFILE`?
///
/// `AT_EMPTY_PATH` demands `f_cred == current_cred()` - a **pointer**
/// comparison (`fs/namei.c:2631`). io_uring's `register_personality` stores
/// `get_current_cred()`, so two registrations taken from unchanged credentials
/// reference the same `struct cred`. This pins the consequence: two
/// `register_self` ids are interchangeable for the link, because they *are*
/// the same credentials. The requirement therefore bites across genuinely
/// different identities (the broker's), not across id values.
#[test]
fn linkat_file_accepts_any_id_for_the_same_credentials() {
    pin_umask();
    let dir = truenas_ros::tempdir().expect("tempdir");
    let mut afs = match UringFs::new(test_cfg()) {
        Ok(a) => a,
        Err(e) => {
            if should_skip(&e) {
                return;
            }
            panic!("UringFs::new: {e}");
        }
    };
    let opener = afs.register_self().expect("first register_self");
    let linker = afs.register_self().expect("second register_self");
    assert_ne!(opener.id(), linker.id(), "two distinct personality ids");

    let h = afs.handle();
    let stop = afs.shutdown_handle();
    let dir_path = dir.path().to_path_buf();
    thread::scope(|s| {
        s.spawn(move || {
            let _guard = StopGuard(stop);
            let anchor = Anchor::open(dir_path.as_path()).expect("anchor");
            let how = OpenHow::new()
                .flags(OFlag::O_TMPFILE | OFlag::O_RDWR)
                .mode(Mode::from_bits_truncate(0o600));
            let f = h.open(opener, &anchor, ".", how).expect("open");
            let (n, _) = pwrite1(&h, opener, &f, b"x".to_vec(), 0);
            assert_eq!(n.expect("write"), 1);

            h.linkat_file(linker, &f, &anchor, leaf("object"))
                .expect("a different id over the same creds may link");
            assert_eq!(std::fs::read(dir_path.join("object")).unwrap(), b"x");
        });
        afs.run().expect("run");
    });
}

/// The allowlist's *refusals* are the security property, so they get the test.
/// `security.` would grant file capabilities, `system.` would rewrite ACLs, and
/// `user.` needs no privilege at all - none may be elevated. A bare `trusted.`
/// is refused too: it would cover the entire namespace.
#[test]
fn privileged_xattr_prefixes_refuse_dangerous_namespaces() {
    for bad in [
        c"security.",
        c"security.capability",
        c"system.",
        c"system.posix_acl_access",
        c"user.",
        c"user.anything",
        c"trusted.", // the whole namespace: too broad
        c"",
        c"nonsense",
    ] {
        assert!(
            matches!(
                PrivilegedXattrs::new().allow_prefix(bad),
                Err(Error::Validation(_))
            ),
            "prefix {bad:?} must be refused"
        );
    }
    // Anything naming more than the bare `trusted.` namespace is fine.
    PrivilegedXattrs::new()
        .allow_prefix(c"trusted.myserver_")
        .expect("a scoped trusted. prefix is allowed");
}

/// An allowlisted `trusted.*` write is elevated to the reactor's ambient
/// credentials; an unlisted name in the same namespace, through the same call,
/// is not - and unprivileged callers cannot even see the elevated name.
///
/// Requires privilege to be meaningful (the `trusted.` namespace is
/// `CAP_SYS_ADMIN`-gated), so it skips when not root - and skips on kernels
/// below 6.13, where fd-based xattrs are unavailable.
#[test]
fn privileged_xattr_allowlist_elevates_only_listed_names() {
    if !root_or_skip("privileged_xattr_allowlist_elevates_only_listed_names") {
        return;
    }
    pin_umask();
    let dir = truenas_ros::tempdir().expect("tempdir");
    // `tempdir` creates the directory 0700; the unprivileged identity must
    // traverse it, and reaching the file is not what this test probes.
    std::fs::set_permissions(
        dir.path(),
        std::fs::Permissions::from_mode(0o755),
    )
    .expect("open up the scratch dir");
    let mut afs = match UringFs::new(test_cfg()) {
        Ok(a) => a,
        Err(e) => {
            if should_skip(&e) {
                return;
            }
            panic!("UringFs::new: {e}");
        }
    };
    afs.set_privileged_xattrs(
        PrivilegedXattrs::new()
            .allow_prefix(c"trusted.truenas_test_")
            .expect("valid prefix"),
    );

    // A *brokered*, unprivileged identity: the whole point is that this
    // personality could never write `trusted.*` itself.
    let broker = match CredBroker::spawn(&[&afs]) {
        Ok(b) => b,
        Err(_) => return, // no privilege to impersonate here
    };
    let creds = broker.handle(0).expect("broker handle");
    let nobody = creds
        .register(&AsUser::new(65534, 65534))
        .expect("register an unprivileged identity");

    let h = afs.handle();
    let stop = afs.shutdown_handle();
    let dir_path = dir.path().to_path_buf();
    thread::scope(|s| {
        s.spawn(move || {
            let _guard = StopGuard(stop);
            let anchor = Anchor::open(dir_path.as_path()).expect("anchor");
            std::fs::write(dir_path.join("obj"), b"data").unwrap();
            // World-writable so the identity's failures are about the xattr
            // namespace, not about reaching the file.
            std::fs::set_permissions(
                dir_path.join("obj"),
                std::fs::Permissions::from_mode(0o666),
            )
            .unwrap();
            let f = h
                .open(
                    nobody,
                    &anchor,
                    "obj",
                    OpenHow::new().flags(OFlag::O_RDWR),
                )
                .expect("open as the unprivileged identity");

            // Allowlisted: elevated, so it succeeds despite `nobody` holding
            // no CAP_SYS_ADMIN.
            let (res, _) = h.fsetxattr(
                nobody,
                &f,
                &xattr_name("trusted.truenas_test_meta"),
                b"server-owned".to_vec(),
                0,
            );
            res.expect("an allowlisted name is written with ambient creds");

            // Same namespace, same call, not listed: stays with the request
            // identity and is refused by the kernel.
            let (res, _) = h.fsetxattr(
                nobody,
                &f,
                &xattr_name("trusted.other"),
                b"nope".to_vec(),
                0,
            );
            assert!(
                matches!(res, Err(Error::Errno(Errno::EPERM))),
                "an unlisted trusted.* name must not be elevated, got {res:?}"
            );

            // The stored value is real, and readable only with privilege.
            let (res, buf) = h.fgetxattr_as_root(
                &f,
                &xattr_name("trusted.truenas_test_meta"),
                vec![0u8; 64],
            );
            let n = res.expect("privileged read");
            assert_eq!(&buf[..n], b"server-owned");

            // ...and invisible to the identity that "owns" the file.
            let (res, _) = h.fgetxattr(
                nobody,
                &f,
                &xattr_name("trusted.truenas_test_meta"),
                vec![0u8; 64],
            );
            assert!(
                matches!(res, Err(Error::Errno(Errno::ENODATA))),
                "trusted.* must be invisible unprivileged, got {res:?}"
            );
        });
        afs.run().expect("run");
    });
}

/// `preadv2`/`pwritev2` round-trip with a durability flag, and - the part that
/// matters - an *unsupported* flag fails the operation instead of being
/// silently dropped. A durability flag that no-ops would be the worst possible
/// failure mode, so the degrade path is the assertion.
#[test]
fn preadv2_pwritev2_flags_apply_or_fail_loudly() {
    with_fs(test_cfg(), |h, me, dir, _stop| {
        let anchor = Anchor::open(dir.as_path()).expect("anchor");
        let f = h.open(me, &anchor, "rw2", creat_rw()).expect("open");

        // No flags: identical to the plain forms.
        let (n, _) =
            h.pwritev2(me, &f, vec![b"alpha".to_vec()], 0, RwFlags::empty());
        assert_eq!(n.expect("pwritev2"), 5);

        // RWF_DSYNC: the write is itself durable, standing in for fdatasync.
        let (n, _) =
            h.pwritev2(me, &f, vec![b"-beta".to_vec()], 5, RwFlags::RWF_DSYNC);
        assert_eq!(n.expect("pwritev2 RWF_DSYNC"), 5);

        let (n, bufs) =
            h.preadv2(me, &f, vec![vec![0u8; 10]], 0, RwFlags::empty());
        assert_eq!(n.expect("preadv2"), 10);
        assert_eq!(&bufs[0][..10], b"alpha-beta");
        assert_eq!(std::fs::read(dir.join("rw2")).unwrap(), b"alpha-beta");

        // A flag the filesystem does not implement must be refused outright.
        // `RWF_ATOMIC` needs FMODE_CAN_ATOMIC_WRITE, which neither tmpfs nor
        // ZFS sets; accept EOPNOTSUPP or EINVAL, but never a silent success.
        let (res, _) =
            h.pwritev2(me, &f, vec![b"x".to_vec()], 0, RwFlags::RWF_ATOMIC);
        assert!(
            matches!(res, Err(Error::Errno(Errno::EOPNOTSUPP | Errno::EINVAL))),
            "an unsupported rw flag must fail the op, got {res:?}"
        );
        // ...and must not have written anything.
        assert_eq!(std::fs::read(dir.join("rw2")).unwrap(), b"alpha-beta");

        h.close(f).unwrap();
    });
}

/// `open_confined` cannot be talked out of its confinement. `open` yields to a
/// caller that *states* a policy (documented, and fine for a general opener);
/// the confined form unions the guarantees in, so a `how` that buys in-tree
/// symlinks through `open` buys nothing through `open_confined`.
#[test]
fn open_confined_cannot_be_weakened_by_the_caller() {
    with_fs(test_cfg(), |h, me, dir, _stop| {
        std::fs::create_dir(dir.join("inner")).unwrap();
        std::fs::write(dir.join("outside"), b"secret").unwrap();
        std::fs::write(dir.join("inner/target"), b"in-tree").unwrap();
        let inner = Anchor::open(dir.join("inner").as_path()).unwrap();

        // A stated policy `open` honours: BENEATH without NO_SYMLINKS follows
        // a link that stays inside the anchor.
        let stated = OpenHow::new()
            .flags(OFlag::O_RDONLY)
            .resolve(ResolveFlag::RESOLVE_BENEATH);
        std::os::unix::fs::symlink("target", dir.join("inner/in_tree"))
            .unwrap();
        let f = h
            .open(me, &inner, "in_tree", stated)
            .expect("plain open honours a stated policy");
        h.close(f).unwrap();

        // The same `how`, confined: NO_SYMLINKS is unioned back in.
        let res = h.open_confined(me, &inner, "in_tree", stated);
        assert!(
            matches!(res, Err(Error::Errno(Errno::ELOOP))),
            "confined open must not follow even an in-tree symlink, got {res:?}"
        );

        // Neither form walks out of the anchor.
        let permissive = OpenHow::new()
            .flags(OFlag::O_RDONLY)
            .resolve(ResolveFlag::RESOLVE_NO_MAGICLINKS);
        let res = h.open(me, &inner, "../outside", permissive);
        assert!(
            matches!(res, Err(Error::Errno(Errno::EXDEV))),
            "plain open must refuse a `..` escape, got {res:?}"
        );
        let res = h.open_confined(me, &inner, "../outside", permissive);
        assert!(
            matches!(res, Err(Error::Errno(Errno::EXDEV | Errno::ELOOP))),
            "confined open must refuse a `..` escape, got {res:?}"
        );

        // A symlink pointing out of the tree is refused too, even though the
        // path itself contains no `..`.
        std::os::unix::fs::symlink(dir.join("outside"), dir.join("inner/link"))
            .unwrap();
        let res = h.open_confined(me, &inner, "link", permissive);
        assert!(
            matches!(res, Err(Error::Errno(Errno::ELOOP | Errno::EXDEV))),
            "confined open must not follow a symlink out, got {res:?}"
        );

        // And an absolute path cannot bypass the anchor.
        let res = h.open_confined(me, &inner, "/etc/hostname", permissive);
        assert!(res.is_err(), "confined open must refuse an absolute path");

        // `RESOLVE_IN_ROOT` is the one flag that cannot be unioned in: the
        // kernel refuses `BENEATH|IN_ROOT` outright (`fs/open.c:1264`), so
        // the union answered `EINVAL` for every path shape - a leaf, a
        // nested path, `"."` - while the same call through `open` worked.
        // Refused at the boundary, where the message can name the fix.
        let in_root = OpenHow::new()
            .flags(OFlag::O_RDONLY)
            .resolve(ResolveFlag::RESOLVE_IN_ROOT);
        for path in ["target", "./target", "."] {
            let res = h.open_confined(me, &inner, path, in_root);
            assert!(
                matches!(res, Err(Error::Validation(_))),
                "open_confined({path:?}) with RESOLVE_IN_ROOT must be \
                 refused as a bad argument, not answered EINVAL by the \
                 kernel: got {res:?}"
            );
            // The plain opener still serves it, which is what makes the
            // refusal a routing decision rather than a lost capability.
            let f = h
                .open(me, &inner, path, in_root)
                .unwrap_or_else(|e| panic!("open({path:?}) IN_ROOT: {e}"));
            h.close(f).unwrap();
        }
    });
}

/// `mkdir_path` is `mkdir -p`, confined: it creates what is missing, tolerates
/// what exists, and refuses to build a path that would leave the anchor.
#[test]
fn mkdir_path_creates_confined_and_is_idempotent() {
    with_fs(test_cfg(), |h, me, dir, _stop| {
        let anchor = Anchor::open(dir.as_path()).expect("anchor");
        let mode = Mode::from_bits_truncate(0o755);

        let leaf_anchor = h
            .mkdir_path(me, &anchor, "a/b/c", mode)
            .expect("create a nested tree");
        assert!(dir.join("a/b/c").is_dir());

        // The returned anchor really is the deepest directory: a leaf op
        // through it lands in `a/b/c`.
        h.mkdirat(me, &leaf_anchor, leaf("d"), mode)
            .expect("mkdir through the returned anchor");
        assert!(dir.join("a/b/c/d").is_dir());

        // Idempotent: re-running changes nothing and still succeeds (this is
        // also the lost-race outcome when two callers create the same tree).
        h.mkdir_path(me, &anchor, "a/b/c", mode)
            .expect("existing tree is not an error");
        // Partially-existing trees extend rather than fail.
        h.mkdir_path(me, &anchor, "a/b/other/deep", mode)
            .expect("extend an existing prefix");
        assert!(dir.join("a/b/other/deep").is_dir());

        // Every component must be a plain name. `a/../b` is the one worth
        // stating: `openat2` under CONFINED_RESOLVE resolves it safely, so
        // it is refused for a different reason - a walk creating `b` cannot
        // know what `a/..` will turn out to be, and a path that succeeded
        // where the tree existed and failed where it did not would name two
        // different things. Redundant separators go with them: they name
        // the same directory, which makes them a caller assembling a path
        // wrongly rather than a path meaning something unintended.
        for bad in [
            "../escape",
            "a/../../escape",
            "/abs/path",
            "a/../b",
            ".",
            "..",
            "./a",
            "a/.",
            "a//b",
            "a/b/",
            "",
        ] {
            assert!(
                h.mkdir_path(me, &anchor, bad, mode).is_err(),
                "mkdir_path must refuse {bad:?}"
            );
        }
        assert!(!dir.parent().unwrap().join("escape").exists());
        // Refused on shape, so refused whether or not the tree exists:
        // `a/b/c` is there by now and `a/b/../b/c` still is not accepted.
        assert!(
            h.mkdir_path(me, &anchor, "a/b/../b/c", mode).is_err(),
            "an existing tree does not make `..` acceptable"
        );
    });
}

/// Top-level directories that genuinely sit on another filesystem - the
/// fixture the `RESOLVE_NO_XDEV` tests need.
///
/// `symlink_metadata`, not `metadata`: a followed symlink reports its TARGET's
/// device, so on a usr-merged root `/lib -> usr/lib` qualifies while being an
/// ordinary symlink on the root filesystem. The opens under test resolve with
/// `RESOLVE_NO_SYMLINKS`, so such a candidate dies `ELOOP` before the
/// confinement is ever reached.
///
/// **Real mounts first, and the order is deterministic.** `/proc`, `/sys`,
/// `/dev` and `/run` are top-level mounts on every Linux host, so "is the
/// list empty" is a question that answers itself: an emptiness gate could
/// never fire, and the boundary actually crossed would be whichever entry
/// `read_dir` happened to yield first - in practice procfs, and a different
/// pick from run to run.
///
/// What the QEMU job pays for is a pair of ZFS datasets (`setup-test-zfs.sh`
/// mounts `/POSIXACL` and `/NFSV4ACL`), and those are the boundary worth
/// crossing: a pseudo filesystem shares neither ZFS's mount semantics nor its
/// ACL behaviour, so pinning `RESOLVE_NO_XDEV` against procfs proves nothing
/// about the platform the product ships. So the pseudo mounts sort last, and
/// `TRUENAS_ROS_REQUIRE_MOUNT_BOUNDARY=1` demands a **real** crossing rather
/// than merely any crossing - which is what holds the runner to what the job
/// provisions.
///
/// `symlink_metadata`, not `metadata`: a followed symlink reports its TARGET's
/// device, so on a usr-merged root `/lib -> usr/lib` qualifies while being an
/// ordinary symlink on the root filesystem. The opens under test resolve with
/// `RESOLVE_NO_SYMLINKS`, so such a candidate dies `ELOOP` before the
/// confinement is ever reached.
fn mount_crossings() -> Vec<String> {
    /// Always present, so their presence proves nothing about provisioning.
    const PSEUDO: [&str; 4] = ["proc", "sys", "dev", "run"];

    let root_dev = std::fs::metadata("/").unwrap().dev();
    let mut found: Vec<String> = std::fs::read_dir("/")
        .unwrap()
        .flatten()
        .filter_map(|e| {
            let md = std::fs::symlink_metadata(e.path()).ok()?;
            (md.is_dir() && md.dev() != root_dev)
                .then(|| e.file_name().into_string().ok())?
        })
        .collect();
    // Alphabetical, then a stable partition - so the chosen boundary is the
    // same on every run of the same host.
    found.sort();
    found.sort_by_key(|n| PSEUDO.contains(&n.as_str()));
    let real = found
        .iter()
        .filter(|n| !PSEUDO.contains(&n.as_str()))
        .count();
    assert!(
        real > 0
            || std::env::var_os("TRUENAS_ROS_REQUIRE_MOUNT_BOUNDARY").is_none(),
        "TRUENAS_ROS_REQUIRE_MOUNT_BOUNDARY is set but the only top-level \
         mounts are pseudo filesystems ({found:?}): the datasets \
         setup-test-zfs.sh provisions are missing, and crossing into procfs \
         says nothing about ZFS"
    );
    found
}

/// `RESOLVE_NO_XDEV` is what makes "this tree is one filesystem" a rule the
/// kernel enforces rather than a convention: a walk that would step onto
/// another mount fails instead of quietly serving files from it. Uses a real
/// mount boundary on the running system (on TrueNAS, a child dataset);
/// self-skips where the root filesystem has no child mounts.
#[test]
fn confined_open_refuses_to_cross_a_mount_point() {
    with_fs(test_cfg(), |h, me, _dir, _stop| {
        let root = Anchor::open("/").expect("anchor /");
        let Some(name) = mount_crossings().into_iter().next() else {
            return; // single-filesystem host: nothing to cross
        };

        let how = OpenHow::new().flags(OFlag::O_PATH | OFlag::O_DIRECTORY);

        // The default carries NO_XDEV, so an ordinary open stops too. This is
        // the half a caller gets without asking: a share anchored on a parent
        // dataset does not serve a child dataset's files through an object
        // key that happens to name its mountpoint.
        for (what, res) in [
            ("open", h.open(me, &root, name.as_str(), how)),
            (
                "open_confined",
                h.open_confined(me, &root, name.as_str(), how),
            ),
        ] {
            assert!(
                matches!(res, Err(Error::Errno(Errno::EXDEV))),
                "{what}: crossing into /{name} must fail EXDEV, got {res:?}"
            );
        }

        // Stating a policy replaces the policy, not the hardening that
        // rides with it. `RESOLVE_BENEATH` is how a caller asks to follow
        // in-tree symlinks; it must not also, silently, be how they ask to
        // leave the filesystem - the kernel keeps the two questions apart
        // (`__traverse_mounts` consults only `LOOKUP_NO_XDEV`), and so does
        // this.
        for stated in [
            ResolveFlag::RESOLVE_BENEATH,
            ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS,
            ResolveFlag::RESOLVE_IN_ROOT,
        ] {
            let res = h.open(me, &root, name.as_str(), how.resolve(stated));
            assert!(
                matches!(res, Err(Error::Errno(Errno::EXDEV))),
                "{stated:?} must not buy a mount crossing, got {res:?}"
            );
        }

        // The capability is not lost, only relocated to where a reader can
        // see it: anchor on the nested mount and open relative to that.
        let nested =
            Anchor::open(format!("/{name}").as_str()).expect("anchor nested");
        h.open(me, &nested, ".", how).unwrap_or_else(|e| {
            panic!("open of /{name} as its own anchor: {e}")
        });
    });
}

/// An abandoned upload leaves nothing to clean up - the property that removes
/// the need for a temp-file sweeper. Drop the file instead of committing it
/// and assert the staging directory is still empty.
#[test]
fn abandoned_tmpfile_leaves_nothing_behind() {
    with_fs(test_cfg(), |h, me, dir, _stop| {
        std::fs::create_dir(dir.join("staging")).unwrap();
        let staging = Anchor::open(dir.join("staging").as_path()).unwrap();
        let how = OpenHow::new()
            .flags(OFlag::O_TMPFILE | OFlag::O_RDWR)
            .mode(Mode::from_bits_truncate(0o644));

        for _ in 0..8 {
            let f = h.open(me, &staging, ".", how).expect("open O_TMPFILE");
            let (n, _) = pwrite1(&h, me, &f, vec![b'x'; 4096], 0);
            assert_eq!(n.expect("write"), 4096);
            drop(f); // the upload is abandoned mid-flight
        }
        assert_eq!(
            std::fs::read_dir(dir.join("staging")).unwrap().count(),
            0,
            "abandoned temp files must leave no directory entries"
        );
    });
}

/// The confinement composes with every enrichment, not only the one that
/// takes the by-name `statx` path.
///
/// Asking for xattrs, an ACL or a name list opens a descriptor, and the
/// device then comes from a `statx` of *that* - issued in the read phase,
/// with no by-name answer at the collection phase at all. A confinement
/// that reads "no metadata here" as a failure at the earlier phase would
/// refuse every such listing outright.
#[test]
fn confinement_composes_with_the_descriptor_enrichments() {
    with_fs(test_cfg(), |h, me, dir, _stop| {
        std::fs::write(dir.join("a"), b"x").expect("write");
        std::fs::create_dir(dir.join("d")).expect("mkdir");
        let anchor = Anchor::open(&dir).expect("anchor");
        for spec in [
            EnrichSpec::STATX | EnrichSpec::XATTR,
            EnrichSpec::STATX | EnrichSpec::XATTR_LIST,
            EnrichSpec::STATX,
        ] {
            let opts = QueryOptions {
                spec,
                clump: 64,
                same_device_only: true,
                xattr_names: vec![xattr_name("user.nope")],
                ..Default::default()
            };
            let mut q = query_directory(&h, me, &anchor, opts).expect("list");
            let mut names = Vec::new();
            while let Some(batch) = q.next() {
                for e in batch
                    .unwrap_or_else(|e| panic!("{spec:?} listing refused: {e}"))
                {
                    names.push(e.name.to_string_lossy().into_owned());
                }
            }
            names.sort();
            assert_eq!(names, ["a", "d"], "{spec:?}");
        }
    });
}

/// `readdir` honours no `RESOLVE_*` flags, so the listing side needs its own
/// mount check - otherwise a nested dataset lists as though it were part of
/// the tree. Uses a real mount boundary; self-skips without one.
#[test]
fn listing_can_be_confined_to_one_filesystem() {
    with_fs(test_cfg(), |h, me, _dir, _stop| {
        let root = Anchor::open("/").expect("anchor /");
        let crossings = mount_crossings();
        if crossings.is_empty() {
            return; // single-filesystem host
        }

        let names = |same_device_only: bool| -> Vec<String> {
            let opts = QueryOptions {
                spec: EnrichSpec::STATX,
                clump: 64,
                same_device_only,
                ..Default::default()
            };
            let mut q = query_directory(&h, me, &root, opts).expect("list /");
            let mut out = Vec::new();
            while let Some(batch) = q.next() {
                for e in batch.expect("batch") {
                    out.push(e.name.to_string_lossy().into_owned());
                }
            }
            out
        };

        let all = names(false);
        let confined = names(true);
        for c in &crossings {
            assert!(all.contains(c), "unconfined listing should include /{c}");
            assert!(
                !confined.contains(c),
                "confined listing must drop the mount point /{c}"
            );
        }
        // Only the crossings are dropped; same-filesystem entries survive.
        assert!(
            all.len() > confined.len(),
            "confinement should drop something here"
        );
        for n in &confined {
            assert!(all.contains(n), "confinement must not invent entries");
        }
    });
}

#[test]
fn metadata_ops_carry_the_personality() {
    // Every metadata op stamps sqe.personality; an id this ring never
    // registered must fail at submission rather than running as the daemon.
    with_fs(test_cfg(), |h, me, dir, _stop| {
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
        let name = xattr_name("user.k");
        let (res, _v) = h.fgetxattr(bogus, &f, &name, vec![0u8; 8]);
        assert!(matches!(res, Err(Error::Errno(Errno::EINVAL))));
        h.close(f).unwrap();
    });
}

// --- M3: the credential broker ---------------------------------------------

/// The broker forks, so it must be created before the harness starts
/// threads. These tests each build their own reactor rather than using
/// `with_fs`, and run the loop on a scoped thread while the test thread
/// drives registration (the reverse of the other tests, because `UringFs`
/// is `!Send` but `CredBroker`/`CredHandle` are `Send`).
/// Dropping the broker must leave no zombie behind.
///
/// `clone3_fork(0, 0, ..)` gives the child `exit_signal == 0`, which makes it
/// a "clone child": `eligible_child` (`kernel/exit.c:1163`) tests
/// `(p->exit_signal != SIGCHLD) ^ !!(wo->wo_flags & __WCLONE)`, so a plain
/// `waitpid` answers `-1 ECHILD` at once and the task stays `Z` for the host
/// process's life. Nothing else reaps it either - no `SIGCHLD` is delivered
/// to hang a handler off - so this leaks one task per broker.
#[test]
fn dropping_the_broker_leaves_no_zombie() {
    let afs = match UringFs::new(test_cfg()) {
        Ok(a) => a,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("UringFs::new: {e}"),
    };
    let broker = match CredBroker::spawn(&[&afs]) {
        Ok(b) => b,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("CredBroker::spawn: {e}"),
    };
    let pid = broker.pid();
    assert!(broker.is_alive(), "the broker should be running");
    drop(broker); // SIGKILL via the pidfd, then the reap

    // A successful reap releases the task, so `/proc/<pid>` is gone the
    // moment `Drop` returns. The poll is for the failing shape: a
    // `waitpid` that answered ECHILD returns just as fast, and the child
    // needs a moment to finish dying before it reads `Z`.
    let deadline = std::time::Instant::now() + Duration::from_millis(500);
    // Loops while `/proc/<pid>` still exists; a read error is the reap.
    while let Ok(last) = std::fs::read_to_string(format!("/proc/{pid}/status"))
    {
        assert!(
            std::time::Instant::now() < deadline,
            "broker pid {pid} outlived its drop ({}): the reap needs \
             __WALL, since exit_signal == 0 makes plain waitpid answer \
             ECHILD and nothing else collects the task",
            last.lines()
                .find(|l| l.starts_with("State:"))
                .unwrap_or("no State line")
        );
        thread::sleep(Duration::from_millis(10));
    }
}

fn with_broker<F>(client: F)
where
    F: FnOnce(&FsHandle, &CredHandle, Personality, &Path) + Send,
{
    with_broker_caps(Caps::empty(), client)
}

/// [`with_broker`] with a spawn-time capability ceiling.
fn with_broker_caps<F>(allowed: Caps, client: F)
where
    F: FnOnce(&FsHandle, &CredHandle, Personality, &Path) + Send,
{
    pin_umask();
    let dir = truenas_ros::tempdir().expect("tempdir");
    // These tests drive ops as an impersonated user, who must be able to
    // traverse this directory and - for the ones that create as that user --
    // write in it. A fresh tempdir is only owner-writable, so widen it once
    // here rather than in each test.
    std::fs::set_permissions(
        dir.path(),
        std::fs::Permissions::from_mode(0o777),
    )
    .expect("chmod tempdir");
    // The ring must exist before the broker forks: it inherits the fd,
    // because an io_uring descriptor cannot be sent over a unix socket.
    let mut afs = match UringFs::new(test_cfg()) {
        Ok(a) => a,
        Err(e) => {
            if should_skip(&e) {
                return;
            }
            panic!("UringFs::new: {e}");
        }
    };
    let me = afs.register_self().expect("register_self");
    let broker = match CredBroker::spawn_with_caps(&[&afs], allowed) {
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

// --- query_directory -------------------------------------------------------

/// The special-file guard leaves nothing behind on the descriptor.
///
/// `O_NONBLOCK` stops the *open* parking on a planted FIFO, but on the file
/// it returns it is not inert: `io_file_get_flags` reads it into
/// `REQ_F_SUPPORT_NOWAIT`, so `__io_read` takes the `IOCB_NOWAIT` branch and
/// the transfer runs in the submitting task - the reactor thread - instead of
/// on an io-wq worker. Measured at 22.7 ms inline for a 32 MiB warm ZFS read
/// against a punt. The kernel strips the flag from files it added it to
/// (`io_uring/openclose.c:161-162`); so does this.
#[test]
fn an_open_leaves_no_guard_nonblock_on_the_descriptor() {
    use truenas_ros::sync_fs::{OFlag, OpenHow};
    use truenas_ros::uring_fs::FsOpenHow;

    with_fs(test_cfg(), |h, me, dir, _stop| {
        std::fs::write(dir.join("f"), b"data").unwrap();
        let anchor = Anchor::open(dir.as_path()).unwrap();
        let flags = |f: &truenas_ros::uring_fs::File| {
            // SAFETY: a live descriptor; F_GETFL reads no memory through it.
            unsafe { libc::fcntl(f.as_raw_fd(), libc::F_GETFL) }
        };

        // Guarded (the default): the open cannot block, and the descriptor
        // does not carry the flag that made it so.
        let plain = OpenHow::new().flags(OFlag::O_RDONLY);
        let f = h.open(me, &anchor, "f", plain).unwrap();
        assert_eq!(
            flags(&f) & libc::O_NONBLOCK,
            0,
            "the guard's O_NONBLOCK rode out on the descriptor"
        );

        // A caller asking for it keeps it - the flag is theirs, and the
        // kernel makes the same distinction with `nonblock_set`.
        let mine = OpenHow::new().flags(OFlag::O_RDONLY | OFlag::O_NONBLOCK);
        let f = h.open(me, &anchor, "f", mine).unwrap();
        assert_ne!(
            flags(&f) & libc::O_NONBLOCK,
            0,
            "a caller's own O_NONBLOCK must not be stripped"
        );

        // And opting out leaves the flags exactly as given.
        let allow = FsOpenHow::from(plain)
            .allow_blocking_special_files(std::time::Duration::from_secs(5));
        let f = h.open(me, &anchor, "f", allow).unwrap();
        assert_eq!(
            flags(&f) & libc::O_NONBLOCK,
            0,
            "Allow adds nothing, so there is nothing to strip"
        );
    });
}

/// A creating open does not park on a planted writer-less FIFO.
///
/// `io_openat_force_async` (`io_uring/openclose.c:42-50`) puts every
/// `O_CREAT`/`O_TRUNC`/`O_TMPFILE` open straight onto an io-wq worker, where
/// the `op.open_flag |= O_NONBLOCK` the inline path applies never runs and
/// `fifo_open` sleeps in `wait_for_partner` (`fs/pipe.c`) until a writer
/// appears - forever, for a FIFO nobody will write to. The io-wq pool is
/// `min(sq_entries, 4 * nr_cpus)`, so a handful of planted names pins every
/// blocking fs op on the ring, and `into_outcome` waits with no deadline, so
/// each pins a caller thread too.
///
/// Runs with a deadline on a worker thread: without the guard this does not
/// fail, it hangs, and a hung test is a worse signal than a red one.
#[test]
fn a_creating_open_does_not_park_on_a_planted_fifo() {
    use std::sync::mpsc;
    use std::time::Duration;
    use truenas_ros::sync_fs::{Mode, OFlag, OpenHow};

    with_fs(test_cfg(), |h, me, dir, _stop| {
        let fifo = dir.join("planted");
        let c = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes())
            .unwrap();
        // SAFETY: a NUL-terminated path we own.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o644) }, 0, "mkfifo");

        let anchor = Anchor::open(dir.as_path()).unwrap();
        let (tx, rx) = mpsc::channel();
        std::thread::scope(|s| {
            s.spawn(|| {
                // Exactly what an object create issues.
                let how = OpenHow::new()
                    .flags(OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_TRUNC)
                    .mode(Mode::from_bits_truncate(0o644));
                let _ = tx.send(h.open(me, &anchor, "planted", how));
            });
            if rx.recv_timeout(Duration::from_secs(5)).is_err() {
                panic!(
                    "a creating open parked on a writer-less FIFO: the \
                     special-file guard is not reaching this path"
                );
            }
        });
    });
}

/// An `Allow` open that blocks is bounded by its own deadline, and the
/// worker it parked comes back.
///
/// The shape the mandatory deadline exists for: `O_WRONLY|O_CREAT` on a
/// planted writer-less FIFO is forced onto an io-wq worker
/// (`io_openat_force_async`) where `fifo_open` sleeps in
/// `wait_for_partner` - with `Allow` and no deadline, forever, and the
/// pool is one bounded set shared by every blocking fs op on the ring.
/// The deadline is a guard timer in its own op slot whose expiry
/// stages an `ASYNC_CANCEL` for the open (`core::TAG_OPEN_DEADLINE` -
/// **not** a kernel `LINK_TIMEOUT`, which arms only after the blocking
/// issue returns and so cannot bound this shape); the cancellation
/// reaches the sleep as a signal, so the errno is `ECANCELED` or --
/// where the open was already parked and returns `-ERESTARTSYS`,
/// folded by `map_res` the way the kernel's own rw path folds it --
/// `EINTR`. Either way the worker is freed, which the guarded open
/// afterwards proves: it needs an io-wq worker of its own and
/// completes.
#[test]
fn an_allow_open_is_bounded_by_its_deadline() {
    use std::time::{Duration, Instant};
    use truenas_ros::errno::Errno;
    use truenas_ros::sync_fs::{Mode, OFlag, OpenHow};
    use truenas_ros::uring_fs::FsOpenHow;

    with_fs(test_cfg(), |h, me, dir, _stop| {
        let fifo = dir.join("planted");
        let c = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes())
            .unwrap();
        // SAFETY: a NUL-terminated path we own.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o644) }, 0, "mkfifo");
        let anchor = Anchor::open(dir.as_path()).unwrap();

        let how = OpenHow::new()
            .flags(OFlag::O_WRONLY | OFlag::O_CREAT)
            .mode(Mode::from_bits_truncate(0o644));
        let allow = FsOpenHow::from(how)
            .allow_blocking_special_files(Duration::from_millis(300));
        let began = Instant::now();
        let got = h.open(me, &anchor, "planted", allow);
        let took = began.elapsed();
        let errno = match got {
            Err(truenas_ros::Error::Errno(e)) => e,
            other => panic!("a blocked Allow open must fail: {other:?}"),
        };
        assert!(
            matches!(errno, Errno::ECANCELED | Errno::EINTR),
            "the deadline's cancellation, not some other failure: {errno}"
        );
        assert!(
            took >= Duration::from_millis(250),
            "failed in {took:?}: something other than the deadline ended it"
        );
        assert!(
            took < Duration::from_secs(5),
            "took {took:?}: the deadline did not bound the park"
        );

        // The worker came back: a guarded creating open needs one too.
        let plain = OpenHow::new()
            .flags(OFlag::O_WRONLY | OFlag::O_CREAT)
            .mode(Mode::from_bits_truncate(0o644));
        h.open(me, &anchor, "after", plain)
            .expect("the parked worker was never freed");
    });
}

/// An `Allow` open that completes retracts its guard, giving both
/// slots back long before the hour-long deadline.
///
/// On a two-slot table, so the leak is the difference: an `Allow` open
/// charges its own slot and its guard's, and a guard left armed after
/// the open answered holds one of the two for the deadline's full
/// length - the next `Allow` open, which needs both, then never fits.
/// The retraction's slot returns with its own CQE, so the second open
/// is retried briefly rather than demanded instantly.
#[test]
fn an_allow_open_that_completes_disarms_its_deadline() {
    use std::time::{Duration, Instant};
    use truenas_ros::sync_fs::{Mode, OFlag, OpenHow};
    use truenas_ros::uring_fs::FsOpenHow;

    let mut cfg = test_cfg();
    cfg.ops = 2;
    with_fs(cfg, |h, me, dir, _stop| {
        let anchor = Anchor::open(dir.as_path()).unwrap();
        let how = OpenHow::new()
            .flags(OFlag::O_RDWR | OFlag::O_CREAT)
            .mode(Mode::from_bits_truncate(0o600));
        let allow = FsOpenHow::from(how)
            .allow_blocking_special_files(Duration::from_secs(3600));
        let f = h
            .open(me, &anchor, "quick", allow)
            .expect("a regular file answers long before its deadline");
        drop(f);

        // Both slots come back once the guard's retraction lands.
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match h.open(me, &anchor, "again", allow) {
                Ok(_) => break,
                Err(truenas_ros::Error::Errno(
                    truenas_ros::errno::Errno::EBUSY,
                )) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(e) => panic!(
                    "the guard's slot never came back after the open \
                     answered: {e}"
                ),
            }
        }
    });
}

/// A zero `Allow` deadline is refused at entry: it would cancel the
/// open it exists to guard, so it is a shape defect like any other.
#[test]
fn a_zero_allow_deadline_is_refused() {
    use std::time::Duration;
    use truenas_ros::sync_fs::{OFlag, OpenHow};
    use truenas_ros::uring_fs::FsOpenHow;

    with_fs(test_cfg(), |h, me, dir, _stop| {
        let anchor = Anchor::open(dir.as_path()).unwrap();
        let allow = FsOpenHow::from(OpenHow::new().flags(OFlag::O_RDONLY))
            .allow_blocking_special_files(Duration::ZERO);
        assert!(
            matches!(
                h.open(me, &anchor, "x", allow),
                Err(truenas_ros::Error::Validation(_))
            ),
            "a zero deadline must be refused before anything submits"
        );
    });
}

/// An entry whose descriptor could not be opened still reports metadata.
///
/// `enrich` takes an entry's `statx` from the descriptor it opened, so that
/// the metadata cannot describe a different inode than the content. Where the
/// open fails there is no descriptor to stat - and equally nothing for a
/// by-name answer to be mispaired against - so the by-name lookup is both
/// safe there and the only answer available. A symlink under `O_NOFOLLOW`
/// is the deterministic way to reach that arm as root.
#[test]
fn an_unopenable_entry_still_reports_statx() {
    use std::collections::BTreeMap;
    use std::ffi::CString;
    use truenas_ros::uring_fs::{
        DirEntry, EnrichSpec, QueryOptions, query_directory,
    };

    with_fs(test_cfg(), |h, me, dir, _stop| {
        std::fs::write(dir.join("real"), b"xx").unwrap();
        std::os::unix::fs::symlink("real", dir.join("link")).unwrap();

        let anchor = Anchor::open(dir.as_path()).unwrap();
        let opts = QueryOptions {
            // Both, so a descriptor is opened and the fd-keyed statx is the
            // one that normally answers.
            spec: EnrichSpec::STATX | EnrichSpec::XATTR,
            xattr_names: vec![CString::new("user.etag").unwrap()],
            acl_name: CString::new("system.nfs4_acl_xdr").unwrap(),
            xattr_ns: truenas_ros::uring_fs::XattrNamespaces::empty(),
            clump: 8,
            same_device_only: false,
            ..Default::default()
        };
        let mut q = query_directory(&h, me, &anchor, opts).unwrap();
        let mut all: BTreeMap<String, DirEntry> = BTreeMap::new();
        while let Some(batch) = q.next() {
            for e in batch.unwrap() {
                all.insert(e.name.to_string_lossy().into_owned(), e);
            }
        }

        assert_eq!(all.len(), 2, "the file and the symlink");
        let link = all["link"].statx.as_ref().expect(
            "a symlink cannot be opened O_NOFOLLOW, so its metadata has to \
             come from the by-name fallback",
        );
        assert!(link.is_symlink(), "and it describes the symlink itself");
        let real = all["real"].statx.as_ref().expect("opened, so fd-keyed");
        assert_eq!(real.size(), 2);
    });
}

#[test]
fn query_directory_lists_and_enriches() {
    use std::collections::BTreeMap;
    use std::ffi::CString;
    use truenas_ros::uring_fs::{
        DirEntry, EnrichSpec, QueryOptions, query_directory,
    };

    with_fs(test_cfg(), |h, me, dir, _stop| {
        std::fs::write(dir.join("a.txt"), b"aa").unwrap();
        std::fs::write(dir.join("b.txt"), vec![0u8; 100]).unwrap();
        std::fs::write(dir.join("c.txt"), vec![0u8; 4096]).unwrap();
        std::fs::create_dir(dir.join("sub")).unwrap();

        let anchor = Anchor::open(dir.as_path()).unwrap();
        let etag = CString::new("user.etag").unwrap();
        // Tag a.txt; skip the xattr checks if the fs/kernel refuses user xattrs.
        let xattr_ok = {
            let how = OpenHow::new().flags(OFlag::O_RDWR);
            let f = h.open(me, &anchor, "a.txt", how).unwrap();
            let (res, _) = h.fsetxattr(me, &f, &etag, b"deadbeef".to_vec(), 0);
            h.close(f).unwrap();
            fd_xattr_ok("fsetxattr(user.etag)", &res)
        };

        let opts = QueryOptions {
            spec: EnrichSpec::STATX | EnrichSpec::XATTR,
            xattr_names: vec![etag.clone()],
            acl_name: CString::new("system.nfs4_acl_xdr").unwrap(),
            xattr_ns: truenas_ros::uring_fs::XattrNamespaces::empty(),
            clump: 2, // force more than one batch
            same_device_only: false,
            ..Default::default()
        };
        let mut q = query_directory(&h, me, &anchor, opts).unwrap();
        let mut all: BTreeMap<String, DirEntry> = BTreeMap::new();
        while let Some(batch) = q.next() {
            for e in batch.unwrap() {
                all.insert(e.name.to_string_lossy().into_owned(), e);
            }
        }

        assert_eq!(all.len(), 4, "3 files + 1 subdir");
        assert_eq!(all["a.txt"].statx.as_ref().unwrap().size(), 2);
        assert_eq!(all["b.txt"].statx.as_ref().unwrap().size(), 100);
        assert_eq!(all["c.txt"].statx.as_ref().unwrap().size(), 4096);
        assert!(all["sub"].is_dir);
        assert!(!all["a.txt"].is_dir);
        if xattr_ok {
            assert_eq!(
                all["a.txt"].xattrs[0].1.as_deref(),
                Some(&b"deadbeef"[..]),
                "a.txt carries the etag",
            );
            assert_eq!(all["b.txt"].xattrs[0].1, None, "b.txt has no etag");
        }
    });
}

/// `XATTR_LIST` discovers the attributes present in the requested namespace and
/// returns their values; a namespace the attributes are not in discovers none
/// of them.
#[test]
fn query_directory_discovers_user_xattrs() {
    use std::collections::BTreeMap;
    use truenas_ros::uring_fs::{
        EnrichSpec, QueryOptions, XattrNamespaces, query_directory,
    };

    with_fs(test_cfg(), |h, me, dir, _stop| {
        std::fs::write(dir.join("a.txt"), b"aa").unwrap();
        let anchor = Anchor::open(dir.as_path()).unwrap();

        // Tag a.txt with two user attrs; the first set probes fd-xattr support.
        let set = |name: &str, val: &[u8]| -> bool {
            let how = OpenHow::new().flags(OFlag::O_RDWR);
            let f = h.open(me, &anchor, "a.txt", how).unwrap();
            let (res, _) =
                h.fsetxattr(me, &f, &xattr_name(name), val.to_vec(), 0);
            h.close(f).unwrap();
            fd_xattr_ok(&format!("fsetxattr({name})"), &res)
        };
        if !set("user.alpha", b"one") {
            return; // this kernel/fs refuses fd xattrs; nothing to discover
        }
        assert!(set("user.beta", b"two"));

        let discover = |ns: XattrNamespaces| {
            let opts = QueryOptions {
                spec: EnrichSpec::XATTR_LIST,
                xattr_ns: ns,
                ..Default::default()
            };
            let mut q = query_directory(&h, me, &anchor, opts).unwrap();
            let mut got: BTreeMap<String, Option<Vec<u8>>> = BTreeMap::new();
            while let Some(batch) = q.next() {
                for e in batch.unwrap() {
                    if e.name.as_bytes() == b"a.txt" {
                        for (n, v) in e.xattrs {
                            got.insert(n.to_string_lossy().into_owned(), v);
                        }
                    }
                }
            }
            got
        };

        let user = discover(XattrNamespaces::USER);
        assert_eq!(
            user.get("user.alpha").and_then(|v| v.as_deref()),
            Some(&b"one"[..]),
        );
        assert_eq!(
            user.get("user.beta").and_then(|v| v.as_deref()),
            Some(&b"two"[..]),
        );

        let trusted = discover(XattrNamespaces::TRUSTED);
        assert!(
            !trusted.contains_key("user.alpha"),
            "user.* must not surface under a TRUSTED-only query"
        );
    });
}

/// A discovered attribute whose name is not UTF-8 is enriched under `who`: its
/// bytes reach `fgetxattr` verbatim, so the value comes back rather than the
/// attribute being dropped over a lossy name.
#[test]
fn query_directory_discovers_non_utf8_name() {
    use std::ffi::CString;
    use truenas_ros::uring_fs::{
        EnrichSpec, QueryOptions, XattrNamespaces, query_directory,
    };

    with_fs(test_cfg(), |h, me, dir, _stop| {
        std::fs::write(dir.join("a.txt"), b"aa").unwrap();
        let anchor = Anchor::open(dir.as_path()).unwrap();
        // A `user.` name whose trailing bytes are not valid UTF-8.
        let name = CString::new(&b"user.\xff\xfe"[..]).unwrap();

        let set_ok = {
            let how = OpenHow::new().flags(OFlag::O_RDWR);
            let f = h.open(me, &anchor, "a.txt", how).unwrap();
            let (res, _) = h.fsetxattr(me, &f, &name, b"present".to_vec(), 0);
            h.close(f).unwrap();
            fd_xattr_ok("fsetxattr(user.<non-utf8>)", &res)
        };
        if !set_ok {
            return; // fd xattrs unsupported, or the fs rejects the name
        }

        let opts = QueryOptions {
            spec: EnrichSpec::XATTR_LIST,
            xattr_ns: XattrNamespaces::USER,
            ..Default::default()
        };
        let mut q = query_directory(&h, me, &anchor, opts).unwrap();
        let mut found = None;
        while let Some(batch) = q.next() {
            for e in batch.unwrap() {
                if e.name.as_bytes() == b"a.txt" {
                    for (n, v) in e.xattrs {
                        if n.as_bytes() == b"user.\xff\xfe" {
                            found = v;
                        }
                    }
                }
            }
        }
        assert_eq!(
            found.as_deref(),
            Some(&b"present"[..]),
            "non-UTF-8 name enriched with its value, not dropped"
        );
    });
}

/// A discovered value larger than the initial buffer is refetched at its true
/// size, not silently truncated or dropped.
#[test]
fn query_directory_discovers_large_value() {
    use truenas_ros::uring_fs::{
        EnrichSpec, QueryOptions, XattrNamespaces, query_directory,
    };

    with_fs(test_cfg(), |h, me, dir, _stop| {
        std::fs::write(dir.join("big.bin"), b"x").unwrap();
        let anchor = Anchor::open(dir.as_path()).unwrap();
        let big = vec![0xabu8; 5000]; // larger than the 4096-byte buffer

        let set_ok = {
            let how = OpenHow::new().flags(OFlag::O_RDWR);
            let f = h.open(me, &anchor, "big.bin", how).unwrap();
            let (res, _) =
                h.fsetxattr(me, &f, &xattr_name("user.blob"), big.clone(), 0);
            h.close(f).unwrap();
            fd_xattr_ok("fsetxattr(user.blob)", &res)
        };
        if !set_ok {
            return; // fd xattrs unsupported, or the fs rejects the value size
        }

        let opts = QueryOptions {
            spec: EnrichSpec::XATTR_LIST,
            xattr_ns: XattrNamespaces::USER,
            ..Default::default()
        };
        let mut q = query_directory(&h, me, &anchor, opts).unwrap();
        let mut found = None;
        while let Some(batch) = q.next() {
            for e in batch.unwrap() {
                if e.name.as_bytes() == b"big.bin" {
                    for (n, v) in e.xattrs {
                        if n.to_bytes() == b"user.blob" {
                            found = v;
                        }
                    }
                }
            }
        }
        assert_eq!(
            found.as_deref(),
            Some(big.as_slice()),
            "the whole value is refetched"
        );
    });
}

/// An explicitly requested value larger than the initial buffer is returned at
/// its true size, not reported absent: the ERANGE the fixed buffer yields must
/// not read as "no such attribute".
#[test]
fn query_directory_explicit_large_value() {
    use truenas_ros::uring_fs::{
        EnrichSpec, QueryOptions, XattrNamespaces, query_directory,
    };

    with_fs(test_cfg(), |h, me, dir, _stop| {
        std::fs::write(dir.join("big.bin"), b"x").unwrap();
        let anchor = Anchor::open(dir.as_path()).unwrap();
        let name = xattr_name("user.blob");
        let big = vec![0xcdu8; 8192]; // twice the 4096-byte explicit buffer

        let set_ok = {
            let how = OpenHow::new().flags(OFlag::O_RDWR);
            let f = h.open(me, &anchor, "big.bin", how).unwrap();
            let (res, _) = h.fsetxattr(me, &f, &name, big.clone(), 0);
            h.close(f).unwrap();
            fd_xattr_ok("fsetxattr(user.blob)", &res)
        };
        if !set_ok {
            return; // fd xattrs unsupported, or the fs rejects the value size
        }

        let opts = QueryOptions {
            spec: EnrichSpec::XATTR,
            xattr_names: vec![name.clone()],
            xattr_ns: XattrNamespaces::empty(),
            ..Default::default()
        };
        let mut q = query_directory(&h, me, &anchor, opts).unwrap();
        let mut found = None;
        while let Some(batch) = q.next() {
            for e in batch.unwrap() {
                if e.name.as_bytes() == b"big.bin" {
                    // The explicit name keeps its slot, in request order.
                    assert_eq!(e.xattrs[0].0, name);
                    found = e.xattrs[0].1.clone();
                }
            }
        }
        assert_eq!(
            found.as_deref(),
            Some(big.as_slice()),
            "the whole explicit value is returned, not reported absent"
        );
    });
}

/// Discovery runs each value read under the caller: an unprivileged identity
/// sees the world-readable `user.*` attribute but never the `trusted.*` one,
/// while a privileged identity does. The candidate-listing `flistxattr` runs at
/// the reactor's privilege, so the per-value `who` read is what gates it.
#[test]
fn query_directory_discovery_drops_unreadable_trusted() {
    use std::collections::BTreeMap;
    use truenas_ros::uring_fs::{
        EnrichSpec, QueryOptions, XattrNamespaces, query_directory,
    };

    if !root_or_skip("query_directory_discovery_drops_unreadable_trusted") {
        return; // broker impersonation and trusted.* both need privilege
    }
    const NOBODY_UID: u32 = 65_534;
    const NOBODY_GID: u32 = 65_534;

    with_broker(|h, creds, me, dir| {
        std::fs::write(dir.join("f.txt"), b"hi").unwrap();
        std::fs::set_permissions(
            dir.join("f.txt"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        let anchor = Anchor::open(dir).unwrap();

        let set = |who: Personality, name: &str, val: &[u8]| {
            let how = OpenHow::new().flags(OFlag::O_RDWR);
            let f = h.open(who, &anchor, "f.txt", how).unwrap();
            let (res, _) =
                h.fsetxattr(who, &f, &xattr_name(name), val.to_vec(), 0);
            h.close(f).unwrap();
            res
        };
        if !fd_xattr_ok("fsetxattr(user.pub)", &set(me, "user.pub", b"public"))
        {
            return; // fd xattrs unsupported
        }
        set(me, "trusted.secret", b"classified").unwrap();

        let peer = creds
            .register(&AsUser::new(NOBODY_UID, NOBODY_GID))
            .unwrap();

        let discover = |who: Personality| {
            let opts = QueryOptions {
                spec: EnrichSpec::XATTR_LIST,
                xattr_ns: XattrNamespaces::USER | XattrNamespaces::TRUSTED,
                ..Default::default()
            };
            let mut q = query_directory(h, who, &anchor, opts).unwrap();
            let mut got: BTreeMap<String, Option<Vec<u8>>> = BTreeMap::new();
            while let Some(batch) = q.next() {
                for e in batch.unwrap() {
                    if e.name.as_bytes() == b"f.txt" {
                        for (n, v) in e.xattrs {
                            got.insert(n.to_string_lossy().into_owned(), v);
                        }
                    }
                }
            }
            got
        };

        let peer_view = discover(peer);
        assert!(
            peer_view.contains_key("user.pub"),
            "peer should read the world-readable user attr"
        );
        assert!(
            !peer_view.contains_key("trusted.secret"),
            "trusted.* must not leak to an unprivileged identity"
        );

        let root_view = discover(me);
        assert_eq!(
            root_view.get("trusted.secret").and_then(|v| v.as_deref()),
            Some(&b"classified"[..]),
            "a privileged identity does read trusted.*"
        );
    });
}

/// Discovery works through the pooled lister as well as the direct one.
#[test]
fn query_pool_discovers_xattrs() {
    use truenas_ros::uring_fs::{
        EnrichSpec, QueryOptions, QueryPool, XattrNamespaces,
    };

    with_fs(test_cfg(), |h, me, dir, _stop| {
        std::fs::write(dir.join("p.txt"), b"hi").unwrap();
        let anchor = Anchor::open(dir.as_path()).unwrap();
        let set_ok = {
            let how = OpenHow::new().flags(OFlag::O_RDWR);
            let f = h.open(me, &anchor, "p.txt", how).unwrap();
            let (res, _) =
                h.fsetxattr(me, &f, &xattr_name("user.tag"), b"v".to_vec(), 0);
            h.close(f).unwrap();
            fd_xattr_ok("fsetxattr(user.tag)", &res)
        };
        if !set_ok {
            return;
        }

        let pool = QueryPool::new(h);
        let opts = QueryOptions {
            spec: EnrichSpec::XATTR_LIST,
            xattr_ns: XattrNamespaces::USER,
            ..Default::default()
        };
        let handle = pool.query(me, anchor, opts);
        let mut found = false;
        while let Some(batch) = handle.next() {
            for e in batch.unwrap() {
                if e.name.as_bytes() == b"p.txt" {
                    found = e.xattrs.iter().any(|(n, v)| {
                        n.to_bytes() == b"user.tag"
                            && v.as_deref() == Some(&b"v"[..])
                    });
                }
            }
        }
        assert!(found, "pool discovery surfaces the user attr");
    });
}

/// Enumeration is gated by the caller's list permission: opening the directory
/// readable under `who` is the DAC check, so a non-root peer that cannot list a
/// `0700` directory it does not own gets `EACCES` (never the reactor's root).
#[test]
fn query_directory_enumeration_obeys_dac() {
    use std::ffi::CString;
    use truenas_ros::errno::Errno;
    use truenas_ros::uring_fs::{EnrichSpec, QueryOptions, query_directory};

    if !root_or_skip("query_directory_enumeration_obeys_dac") {
        return; // the broker cannot become another uid without CAP_SETUID
    }
    const NOBODY_UID: u32 = 65_534;
    const NOBODY_GID: u32 = 65_534;

    with_broker(|h, creds, _me, dir| {
        // A root-owned 0700 subdir the peer cannot list.
        let secret = dir.join("secret");
        std::fs::create_dir(&secret).unwrap();
        std::fs::set_permissions(
            &secret,
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        std::fs::write(secret.join("hidden.txt"), b"x").unwrap();

        let peer = creds
            .register(&AsUser::new(NOBODY_UID, NOBODY_GID))
            .unwrap();
        let anchor = Anchor::open(&secret).unwrap();
        let opts = QueryOptions {
            spec: EnrichSpec::STATX,
            xattr_names: vec![],
            acl_name: CString::new("system.nfs4_acl_xdr").unwrap(),
            xattr_ns: truenas_ros::uring_fs::XattrNamespaces::empty(),
            clump: 8,
            same_device_only: false,
            ..Default::default()
        };
        let err = query_directory(h, peer, &anchor, opts).unwrap_err();
        assert!(
            matches!(err, Error::Errno(Errno::EACCES)),
            "peer cannot list a 0700 dir it does not own: {err:?}"
        );
    });
}

/// Dropping a `QueryDir` mid-walk closes its directory fd (RAII), not at some
/// later teardown - verified against `/proc/self/fd`.
#[test]
fn query_directory_drop_closes_dir_fd() {
    use std::ffi::CString;
    use truenas_ros::uring_fs::{EnrichSpec, QueryOptions, query_directory};

    with_fs(test_cfg(), |h, me, dir, _stop| {
        for i in 0..6 {
            std::fs::write(dir.join(format!("f{i}")), b"x").unwrap();
        }
        let anchor = Anchor::open(dir.as_path()).unwrap();
        let opts = QueryOptions {
            spec: EnrichSpec::STATX,
            xattr_names: vec![],
            acl_name: CString::new("system.nfs4_acl_xdr").unwrap(),
            xattr_ns: truenas_ros::uring_fs::XattrNamespaces::empty(),
            clump: 2,
            same_device_only: false,
            ..Default::default()
        };
        let mut q = query_directory(&h, me, &anchor, opts).unwrap();
        let fd = q.dir_fd();
        let link = format!("/proc/self/fd/{fd}");
        // Pull one batch, then drop mid-walk (files remain unread).
        let first = q.next().expect("a batch").unwrap();
        assert!(!first.is_empty());
        let target =
            std::fs::read_link(&link).expect("dir fd open during walk");
        drop(q);
        // `Drop` closes the `DIR*` (and its dup fd) synchronously via `closedir`.
        // The freed fd *number* can be reused by the reactor thread running
        // concurrently, so assert the fd no longer names our directory - closed
        // (`Err`) or reused for something else (a different target) - rather than
        // that the number is merely absent, which fd reuse would race.
        match std::fs::read_link(&link) {
            Err(_) => {}
            Ok(reused) => assert_ne!(
                reused, target,
                "dir fd still open and still the directory after drop \
                 (deferred to teardown?)"
            ),
        }
    });
}

/// The off-loop async-fs API enumerates a file's xattrs directly (no directory
/// walk): `flistxattr` lists names, `query_xattrs` returns namespace-filtered
/// names and values read under `who`.
#[test]
fn fs_handle_query_xattrs_reads_user_namespace() {
    use std::collections::BTreeMap;
    use truenas_ros::uring_fs::XattrNamespaces;

    with_fs(test_cfg(), |h, me, dir, _stop| {
        std::fs::write(dir.join("f.txt"), b"hi").unwrap();
        let anchor = Anchor::open(dir.as_path()).unwrap();
        let how = OpenHow::new().flags(OFlag::O_RDWR);
        let f = h.open(me, &anchor, "f.txt", how).unwrap();

        let set = |name: &str, val: &[u8]| {
            let (res, _) =
                h.fsetxattr(me, &f, &xattr_name(name), val.to_vec(), 0);
            res
        };
        if !fd_xattr_ok("fsetxattr(user.a)", &set("user.a", b"1")) {
            return; // this kernel/fs refuses fd xattrs
        }
        set("user.b", b"22").unwrap();

        let names: Vec<String> = h
            .flistxattr(&f)
            .unwrap()
            .into_iter()
            .map(|c| c.to_string_lossy().into_owned())
            .collect();
        assert!(names.iter().any(|n| n == "user.a"));
        assert!(names.iter().any(|n| n == "user.b"));

        let got: BTreeMap<String, Vec<u8>> = h
            .query_xattrs(me, &f, XattrNamespaces::USER)
            .unwrap()
            .into_iter()
            .map(|(n, v)| (n.to_string_lossy().into_owned(), v))
            .collect();
        assert_eq!(got.get("user.a").map(Vec::as_slice), Some(&b"1"[..]));
        assert_eq!(got.get("user.b").map(Vec::as_slice), Some(&b"22"[..]));

        h.close(f).unwrap();
    });
}

/// Off-loop `query_xattrs` gates each value read under `who`: an unprivileged
/// identity gets the world-readable `user.*` attribute but never the
/// `trusted.*` one, while a privileged identity does.
#[test]
fn fs_handle_query_xattrs_drops_unreadable_trusted() {
    use std::collections::BTreeMap;
    use truenas_ros::uring_fs::XattrNamespaces;

    if !root_or_skip("fs_handle_query_xattrs_drops_unreadable_trusted") {
        return; // broker impersonation and trusted.* both need privilege
    }
    const NOBODY_UID: u32 = 65_534;
    const NOBODY_GID: u32 = 65_534;

    with_broker(|h, creds, me, dir| {
        std::fs::write(dir.join("f.txt"), b"hi").unwrap();
        std::fs::set_permissions(
            dir.join("f.txt"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        let anchor = Anchor::open(dir).unwrap();
        let owner =
            h.open(me, &anchor, "f.txt", OpenHow::new().flags(OFlag::O_RDWR));
        let owner = owner.unwrap();

        let set = |name: &str, val: &[u8]| {
            let (res, _) =
                h.fsetxattr(me, &owner, &xattr_name(name), val.to_vec(), 0);
            res
        };
        if !fd_xattr_ok("fsetxattr(user.pub)", &set("user.pub", b"public")) {
            return; // fd xattrs unsupported
        }
        set("trusted.secret", b"classified").unwrap();
        h.close(owner).unwrap();

        let peer = creds
            .register(&AsUser::new(NOBODY_UID, NOBODY_GID))
            .unwrap();
        let ns = XattrNamespaces::USER | XattrNamespaces::TRUSTED;
        let query = |who| {
            let how = OpenHow::new().flags(OFlag::O_RDONLY);
            let f = h.open(who, &anchor, "f.txt", how).unwrap();
            let got: BTreeMap<String, Vec<u8>> = h
                .query_xattrs(who, &f, ns)
                .unwrap()
                .into_iter()
                .map(|(n, v)| (n.to_string_lossy().into_owned(), v))
                .collect();
            h.close(f).unwrap();
            got
        };

        let peer_view = query(peer);
        assert!(peer_view.contains_key("user.pub"));
        assert!(
            !peer_view.contains_key("trusted.secret"),
            "trusted.* must not leak off-loop"
        );

        let root_view = query(me);
        assert_eq!(
            root_view.get("trusted.secret").map(Vec::as_slice),
            Some(&b"classified"[..]),
        );
    });
}

/// `FsHandle::fgetxattr_as_root` reads under the reactor's ambient (root)
/// credentials, so it returns a `trusted.*` value that the same fd's normal
/// `who`-attributed read (as an unprivileged identity) is denied.
#[test]
fn fs_handle_fgetxattr_as_root_reads_trusted() {
    if !root_or_skip("fs_handle_fgetxattr_as_root_reads_trusted") {
        return; // broker impersonation and trusted.* both need privilege
    }
    const NOBODY_UID: u32 = 65_534;
    const NOBODY_GID: u32 = 65_534;

    with_broker(|h, creds, me, dir| {
        std::fs::write(dir.join("f.txt"), b"hi").unwrap();
        std::fs::set_permissions(
            dir.join("f.txt"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        let anchor = Anchor::open(dir).unwrap();
        let how = OpenHow::new().flags(OFlag::O_RDWR);
        let f = h.open(me, &anchor, "f.txt", how).unwrap();
        let name = xattr_name("trusted.secret");
        let (set, _) = h.fsetxattr(me, &f, &name, b"classified".to_vec(), 0);
        if !fd_xattr_ok("fsetxattr(trusted.secret)", &set) {
            return; // fd xattrs unsupported
        }

        let peer = creds
            .register(&AsUser::new(NOBODY_UID, NOBODY_GID))
            .unwrap();
        // Attributed to the unprivileged peer, the read is denied.
        let (peer_res, _) = h.fgetxattr(peer, &f, &name, vec![0u8; 64]);
        assert!(peer_res.is_err(), "peer cannot read trusted.* as itself");

        // As root, the same fd yields the value regardless of any `who`.
        let (root_res, buf) = h.fgetxattr_as_root(&f, &name, vec![0u8; 64]);
        let n = root_res.expect("as-root read succeeds");
        assert_eq!(&buf[..n], b"classified");

        h.close(f).unwrap();
    });
}

#[test]
fn query_pool_lists_directory() {
    use std::collections::BTreeSet;
    use std::ffi::CString;
    use truenas_ros::uring_fs::{EnrichSpec, QueryOptions, QueryPool};

    with_fs(test_cfg(), |h, me, dir, _stop| {
        for n in ["x.txt", "y.txt", "z.txt"] {
            std::fs::write(dir.join(n), b"hi").unwrap();
        }
        let anchor = Anchor::open(dir.as_path()).unwrap();
        let pool = QueryPool::new(h);
        let opts = QueryOptions {
            spec: EnrichSpec::STATX,
            xattr_names: vec![],
            acl_name: CString::new("system.nfs4_acl_xdr").unwrap(),
            xattr_ns: truenas_ros::uring_fs::XattrNamespaces::empty(),
            clump: 2,
            same_device_only: false,
            ..Default::default()
        };
        // Non-blocking enqueue; pull batches from the handle.
        let handle = pool.query(me, anchor, opts);
        let mut names: BTreeSet<String> = BTreeSet::new();
        while let Some(batch) = handle.next() {
            for e in batch.unwrap() {
                names.insert(e.name.to_string_lossy().into_owned());
            }
        }
        let want: BTreeSet<String> = ["x.txt", "y.txt", "z.txt"]
            .into_iter()
            .map(String::from)
            .collect();
        assert_eq!(names, want);
    });
}

#[test]
fn query_pool_runs_multiple_listings() {
    use std::collections::BTreeSet;
    use std::ffi::CString;
    use truenas_ros::uring_fs::{
        EnrichSpec, QueryHandle, QueryOptions, QueryPool,
    };

    with_fs(test_cfg(), |h, me, dir, _stop| {
        let d1 = dir.join("d1");
        let d2 = dir.join("d2");
        std::fs::create_dir(&d1).unwrap();
        std::fs::create_dir(&d2).unwrap();
        std::fs::write(d1.join("a"), b"1").unwrap();
        std::fs::write(d1.join("b"), b"1").unwrap();
        std::fs::write(d2.join("c"), b"2").unwrap();

        let a1 = Anchor::open(d1.as_path()).unwrap();
        let a2 = Anchor::open(d2.as_path()).unwrap();
        let pool = QueryPool::new(h);
        let mk_opts = || QueryOptions {
            spec: EnrichSpec::STATX,
            xattr_names: vec![],
            acl_name: CString::new("system.nfs4_acl_xdr").unwrap(),
            xattr_ns: truenas_ros::uring_fs::XattrNamespaces::empty(),
            clump: 8,
            same_device_only: false,
            ..Default::default()
        };
        // Submit BOTH from this one thread before collecting either - the pool
        // runs the walks (up to 2 concurrently), decoupled from the caller.
        let h1 = pool.query(me, a1, mk_opts());
        let h2 = pool.query(me, a2, mk_opts());
        let collect = |handle: &QueryHandle| {
            let mut names = BTreeSet::new();
            while let Some(batch) = handle.next() {
                for e in batch.unwrap() {
                    names.insert(e.name.to_string_lossy().into_owned());
                }
            }
            names
        };
        let n1 = collect(&h1);
        let n2 = collect(&h2);
        let want1: BTreeSet<String> =
            ["a", "b"].into_iter().map(String::from).collect();
        let want2: BTreeSet<String> =
            ["c"].into_iter().map(String::from).collect();
        assert_eq!(n1, want1, "d1 listing");
        assert_eq!(n2, want2, "d2 listing");
    });
}

#[test]
fn pool_copy_file_range_whole() {
    use truenas_ros::uring_fs::QueryPool;

    with_fs(test_cfg(), |h, me, dir, _stop| {
        let content: Vec<u8> = (0..5000u32).map(|i| i as u8).collect();
        std::fs::write(dir.join("src"), &content).unwrap();
        std::fs::write(dir.join("dst"), b"").unwrap();
        let anchor = Anchor::open(dir.as_path()).unwrap();
        let src = h
            .open(me, &anchor, "src", OpenHow::new().flags(OFlag::O_RDONLY))
            .unwrap();
        let dst = h
            .open(me, &anchor, "dst", OpenHow::new().flags(OFlag::O_RDWR))
            .unwrap();
        let pool = QueryPool::new(h);
        // Clones inline on a block-cloning fs, else offloads a byte copy --
        // either way the bytes land.
        let n = match pool
            .copy_file_range(&src, &dst, 0, 0, content.len() as u64)
            .wait()
        {
            Ok(n) => n,
            // Not a skip: every filesystem these tests run on serves
            // copy_file_range, so an error here is the copy path broken, and
            // swallowing it is how a green suite covers nothing.
            Err(e) => panic!("copy_file_range: {e}"),
        };
        assert_eq!(n, content.len() as u64);
        assert_eq!(std::fs::read(dir.join("dst")).unwrap(), content);
    });
}

#[test]
fn pool_copy_file_range_ranged_offload() {
    use truenas_ros::uring_fs::QueryPool;

    with_fs(test_cfg(), |h, me, dir, _stop| {
        // src byte i = (i / 100): three 100-byte runs of 0, 1, 2.
        let content: Vec<u8> = (0..300u32).map(|i| (i / 100) as u8).collect();
        std::fs::write(dir.join("src"), &content).unwrap();
        std::fs::write(dir.join("dst"), vec![0xFFu8; 300]).unwrap();
        let anchor = Anchor::open(dir.as_path()).unwrap();
        let src = h
            .open(me, &anchor, "src", OpenHow::new().flags(OFlag::O_RDONLY))
            .unwrap();
        let dst = h
            .open(me, &anchor, "dst", OpenHow::new().flags(OFlag::O_RDWR))
            .unwrap();
        let pool = QueryPool::new(h);
        // A misaligned sub-block range forces the byte-copy offload path even on
        // a block-cloning fs: copy src[100..200] -> dst[50..150].
        let n = match pool.copy_file_range(&src, &dst, 100, 50, 100).wait() {
            Ok(n) => n,
            Err(e) => panic!("copy_file_range: {e}"),
        };
        assert_eq!(n, 100);
        let out = std::fs::read(dir.join("dst")).unwrap();
        assert_eq!(&out[50..150], &content[100..200], "the copied range");
        assert_eq!(out[49], 0xFF, "before the range: untouched");
        assert_eq!(out[150], 0xFF, "after the range: untouched");
    });
}

/// The `EXDEV` byte-copy fallback, entered where it actually runs.
///
/// `copy_file_range(2)` answers `EXDEV` when the endpoints are on different
/// filesystems, and `copy_range_rw` is what carries the bytes then. Every
/// other copy test puts both endpoints in one tempdir, where that answer
/// never comes: with a `panic!` at the top of `copy_range_rw` the whole
/// privileged lane stays green and the probe never fires. Here one endpoint
/// is on the tempdir's filesystem and the other on a ZFS dataset.
#[test]
fn pool_copy_file_range_across_filesystems_takes_the_byte_copy() {
    use truenas_ros::uring_fs::QueryPool;

    let Some(ds) = zfs_dir_or_skip() else {
        return;
    };
    let scratch = ds.join(format!("ros-xdev-{}", std::process::id()));
    std::fs::create_dir_all(&scratch).unwrap();

    let content: Vec<u8> = (0..5000u32).map(|i| i as u8).collect();
    let result = std::panic::catch_unwind({
        let scratch = scratch.clone();
        let content = content.clone();
        move || {
            with_fs(test_cfg(), |h, me, dir, _stop| {
                // src on the tempdir's filesystem, dst on the dataset.
                std::fs::write(dir.join("src"), &content).unwrap();
                std::fs::write(scratch.join("dst"), b"").unwrap();
                let a_src = Anchor::open(dir.as_path()).unwrap();
                let a_dst = Anchor::open(scratch.as_path()).unwrap();
                let src = h
                    .open(
                        me,
                        &a_src,
                        "src",
                        OpenHow::new().flags(OFlag::O_RDONLY),
                    )
                    .unwrap();
                let dst = h
                    .open(
                        me,
                        &a_dst,
                        "dst",
                        OpenHow::new().flags(OFlag::O_RDWR),
                    )
                    .unwrap();
                let pool = QueryPool::new(h);
                let n = pool
                    .copy_file_range(&src, &dst, 0, 0, content.len() as u64)
                    .wait()
                    .expect("the cross-filesystem copy must carry the bytes");
                assert_eq!(n, content.len() as u64);
                assert_eq!(
                    std::fs::read(scratch.join("dst")).unwrap(),
                    content,
                    "the EXDEV fallback copied the wrong bytes"
                );
            });
        }
    });
    let _ = std::fs::remove_dir_all(&scratch);
    if let Err(e) = result {
        std::panic::resume_unwind(e);
    }
}

/// The copy where the commit that added it actually runs: a ZFS dataset.
///
/// `test/support/zfs_dir.rs` states the reason - "`copy_file_range` is the
/// clearest case - tmpfs serves it as a plain copy while ZFS serves it as a
/// block clone (`zfs_clone_range`), which is the code that actually ships".
/// Both tests the commit added run in `crate::tempdir()`, so they exercise
/// the plain copy and assert nothing about the clone.
#[test]
fn pool_copy_file_range_on_a_dataset() {
    use truenas_ros::uring_fs::QueryPool;

    let Some(ds) = zfs_dir_or_skip() else {
        return;
    };
    let scratch = ds.join(format!("ros-clone-{}", std::process::id()));
    std::fs::create_dir_all(&scratch).unwrap();

    // Several blocks, whole-range and block-aligned: the shape that can
    // clone. A range split below MAX_CHUNK forfeits it, which no other test
    // in the tree would notice.
    let content: Vec<u8> = (0..(1024u32 * 1024)).map(|i| i as u8).collect();
    let result = std::panic::catch_unwind({
        let scratch = scratch.clone();
        let content = content.clone();
        move || {
            with_fs(test_cfg(), |h, me, _dir, _stop| {
                std::fs::write(scratch.join("src"), &content).unwrap();
                std::fs::write(scratch.join("dst"), b"").unwrap();
                let anchor = Anchor::open(scratch.as_path()).unwrap();
                let src = h
                    .open(
                        me,
                        &anchor,
                        "src",
                        OpenHow::new().flags(OFlag::O_RDONLY),
                    )
                    .unwrap();
                let dst = h
                    .open(
                        me,
                        &anchor,
                        "dst",
                        OpenHow::new().flags(OFlag::O_RDWR),
                    )
                    .unwrap();
                let pool = QueryPool::new(h);
                let n = pool
                    .copy_file_range(&src, &dst, 0, 0, content.len() as u64)
                    .wait()
                    .expect("the dataset copy must carry the bytes");
                assert_eq!(n, content.len() as u64, "whole range in one call");
                assert_eq!(
                    std::fs::read(scratch.join("dst")).unwrap(),
                    content,
                    "the dataset copy produced the wrong bytes"
                );
            });
        }
    });
    let _ = std::fs::remove_dir_all(&scratch);
    if let Err(e) = result {
        std::panic::resume_unwind(e);
    }
}

/// A uid/gid pair that exists nowhere - no files, no group memberships --
/// so a personality for it has exactly the authority "other" grants.
const NOBODY_UID: u32 = 65_534;
const NOBODY_GID: u32 = 65_534;

/// The identity a test can actually register: root impersonates anyone, an
/// unprivileged runner can only ask for what it already holds - *including*
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
        let (n, buf) = pread1(h, id, &f, vec![0u8; 16], 0);
        assert_eq!(&buf[..n.unwrap()], b"brokered");
        h.close(f).unwrap();
        creds.unregister(id).expect("unregister");
    });
}

#[test]
fn broker_refuses_uid_zero() {
    with_broker(|_h, creds, _me, _dir| {
        // A root personality would carry the daemon's capabilities - the
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
        let over: Vec<u32> = (0..=truenas_ros::uring_fs::MAX_GROUPS)
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
    if !root_or_skip("impersonated_open_obeys_dac") {
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
        let (n, buf) = pread1(h, user, &f, vec![0u8; 16], 0);
        assert_eq!(&buf[..n.unwrap()], b"everyone");
        h.close(f).unwrap();

        creds.unregister(user).unwrap();
    });
}

#[test]
fn impersonated_personality_holds_no_dac_override() {
    if !root_or_skip("impersonated_personality_holds_no_dac_override") {
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
    if !root_or_skip("impersonated_create_is_owned_by_the_user") {
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
        let (n, _b) =
            h.pwritev2(user, &f, vec![b"mine".to_vec()], 0, RwFlags::empty());
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
    if !root_or_skip("impersonated_trusted_xattr_is_denied") {
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
        // ("no such attribute"), not EPERM - it hides the attribute's
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
    if !root_or_skip("broker_reverts_credentials_between_registrations") {
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

        // Many "connections" for one identity -> one registration.
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

        // Every lease is gone, but the cache map holds the last reference --
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
        // under way must not be disturbed - this is the property that lets
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
    // list of that size - not just the handful a POSIX user has.
    if !root_or_skip("large_ad_group_list_round_trips") {
        return; // setgroups with a foreign list needs CAP_SETGID
    }
    with_broker(|h, creds, _me, dir| {
        for n in [256usize, 1024, truenas_ros::uring_fs::MAX_GROUPS] {
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
            // SAFETY: valid path; chown to root:marker, mode 0710 - only a
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
            let (got, buf) = pread1(h, id, &f, vec![0u8; 8], 0);
            assert_eq!(&buf[..got.unwrap()], b"deep");
            h.close(f).unwrap();
            creds.unregister(id).unwrap();
        }
    });
}

// --- Security regressions -------------------------------------------------

#[test]
fn personality_zero_is_not_constructible() {
    // `sqe.personality == 0` means "no credential override" - an op stamped
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

// ---- ordered / filtered / resumable listing --------------------------------

/// Every name a query yields, in the order it yields them.
fn list_names(
    h: &FsHandle,
    me: Personality,
    anchor: &Anchor,
    opts: QueryOptions,
) -> Vec<String> {
    let mut q = query_directory(h, me, anchor, opts).expect("list");
    let mut out = Vec::new();
    while let Some(batch) = q.next() {
        for e in batch.expect("batch") {
            out.push(e.name.to_string_lossy().into_owned());
        }
    }
    out
}

/// A directory sorts where its trailing separator puts it, not where its bare
/// name does. `/` is `0x2F`, above `-` (`0x2D`) and `.` (`0x2E`), so `a`
/// belongs *between* `a.txt` and `aa.txt`. A walk that recursed in bare-name
/// order would emit everything under `a/` before `a-1.txt`, disagreeing with
/// the order the full paths actually compare in.
#[test]
fn path_order_places_a_directory_after_its_dotted_siblings() {
    with_fs(test_cfg(), |h, me, dir, _stop| {
        std::fs::create_dir(dir.join("a")).expect("mkdir a");
        for f in ["a-1.txt", "a.txt", "aa.txt"] {
            std::fs::write(dir.join(f), b"x").expect("write");
        }
        let anchor = Anchor::open(dir.as_path()).expect("anchor");
        // `clump` below the entry count, so the sorted buffer is drained
        // across several batches rather than served in one.
        let opts = |order| QueryOptions {
            clump: 2,
            order,
            ..Default::default()
        };

        assert_eq!(
            list_names(&h, me, &anchor, opts(Order::ByPathBytes)),
            ["a-1.txt", "a.txt", "a", "aa.txt"],
        );
        // The ordering a walk must not use, asserted so the difference stays
        // visible if either mode is ever touched.
        assert_eq!(
            list_names(&h, me, &anchor, opts(Order::ByName)),
            ["a", "a-1.txt", "a.txt", "aa.txt"],
        );
        // Unordered yields the same set, in whatever order the filesystem has.
        let mut raw = list_names(&h, me, &anchor, opts(Order::Readdir));
        raw.sort();
        assert_eq!(raw, ["a", "a-1.txt", "a.txt", "aa.txt"]);
    });
}

/// `name_prefix` drops entries during the `readdir` pass, and a batch is still
/// filled to `clump` *kept* entries - so a short batch keeps meaning
/// end-of-directory rather than "the filter ate this one".
#[test]
fn name_prefix_filters_without_shortening_batches() {
    with_fs(test_cfg(), |h, me, dir, _stop| {
        for i in 0..5 {
            std::fs::write(dir.join(format!("keep-{i}")), b"x").expect("write");
            std::fs::write(dir.join(format!("drop-{i}")), b"x").expect("write");
        }
        let anchor = Anchor::open(dir.as_path()).expect("anchor");
        let opts = QueryOptions {
            clump: 2,
            order: Order::ByName,
            name_prefix: Some(b"keep-".to_vec()),
            ..Default::default()
        };

        let mut q = query_directory(&h, me, &anchor, opts).expect("list");
        let mut sizes = Vec::new();
        let mut names = Vec::new();
        while let Some(batch) = q.next() {
            let batch = batch.expect("batch");
            sizes.push(batch.len());
            names.extend(
                batch.iter().map(|e| e.name.to_string_lossy().into_owned()),
            );
        }

        assert_eq!(
            names,
            ["keep-0", "keep-1", "keep-2", "keep-3", "keep-4"],
            "only the prefixed names, in order"
        );
        // 5 kept entries at clump 2: full, full, remainder. The interleaved
        // `drop-*` names must not have shortened either full batch.
        assert_eq!(sizes, [2, 2, 1], "batches fill to clump on kept entries");
    });
}

/// `start_after` resumes an ordered listing exactly at the cut, with no key
/// repeated and none skipped. The cursor is a **literal key**, so resuming
/// past the directory `a` means passing `a/` - where `a/` sorts - rather than
/// `a`, where a file of that name would sort.
#[test]
fn start_after_resumes_a_path_ordered_listing_without_gaps() {
    with_fs(test_cfg(), |h, me, dir, _stop| {
        std::fs::create_dir(dir.join("a")).expect("mkdir a");
        for f in ["a-1.txt", "a.txt", "aa.txt"] {
            std::fs::write(dir.join(f), b"x").expect("write");
        }
        let anchor = Anchor::open(dir.as_path()).expect("anchor");
        let page = |start_after: Option<Vec<u8>>| {
            list_names(
                &h,
                me,
                &anchor,
                QueryOptions {
                    clump: 64,
                    order: Order::ByPathBytes,
                    start_after,
                    ..Default::default()
                },
            )
        };

        let all = page(None);
        assert_eq!(all, ["a-1.txt", "a.txt", "a", "aa.txt"]);

        // Cutting after each key in turn yields exactly the remainder. The
        // directory's key carries its separator; the files' do not.
        let keys = ["a-1.txt", "a.txt", "a/", "aa.txt"];
        for (i, key) in keys.iter().enumerate() {
            assert_eq!(
                page(Some(key.as_bytes().to_vec())),
                all[i + 1..],
                "resuming after {key:?}"
            );
        }

        // The bare name `a` is *not* the directory's key: it sorts where a
        // file `a` would, before `a-1.txt`, so nothing is consumed.
        assert_eq!(page(Some(b"a".to_vec())), all);
    });
}

/// The change cookie is the exact validator for anything cached per file, so
/// two properties have to hold: it moves when the file is modified, and it
/// does **not** move when the file is merely read. A cookie that advanced on
/// reads would invalidate every cache entry on every access.
///
/// Skips where the kernel does not hand the cookie to userspace, which is a
/// property of the *kernel*, not the filesystem: upstream strips the bit in
/// `cp_statx` and clears it from the request mask ("kernel-only for now",
/// fs/stat.c), while the TrueNAS fork exposes it under `CONFIG_TRUENAS`.
/// Runs on a **ZFS dataset**, not the default `tempdir`. tmpfs carries
/// `i_version` too (`SB_I_VERSION`, mm/shmem.c:5375), so a tempdir fixture
/// would pass - but it would be pinning tmpfs's cookie, and the product only
/// ships on ZFS. What has to hold is that *ZFS* moves the cookie on a write
/// and holds it across a read.
///
/// Two gates, both armed in the QEMU job: `TRUENAS_ROS_REQUIRE_ZFS` for the
/// dataset, and `TRUENAS_ROS_REQUIRE_CHANGE_COOKIE` for the kernel.
#[test]
fn change_cookie_moves_on_writes_and_not_on_reads() {
    let Some(ds) = zfs_dir_or_skip() else {
        return;
    };
    with_fs(test_cfg(), |h, me, _dir, _stop| {
        let anchor = Anchor::open(ds.as_path()).expect("anchor");
        let how = OpenHow::new()
            .flags(OFlag::O_RDWR | OFlag::O_CREAT)
            .mode(Mode::from_bits_truncate(0o600));
        let f = h.open(me, &anchor, "cookie.bin", how).expect("open");
        let mask = StatxMask::BASIC_STATS | StatxMask::CHANGE_COOKIE;
        let cookie = |f: &_| {
            h.fstatx(me, f, AtFlags::empty(), mask)
                .expect("fstatx")
                .change_cookie()
        };

        let Some(first) = cookie(&f) else {
            assert!(
                std::env::var_os("TRUENAS_ROS_REQUIRE_CHANGE_COOKIE").is_none(),
                "TRUENAS_ROS_REQUIRE_CHANGE_COOKIE is set but the dataset \
                 at {} reports none: this kernel is not exposing \
                 STATX_CHANGE_COOKIE",
                ds.display()
            );
            return;
        };

        let (n, _) = pwrite1(&h, me, &f, b"hello".to_vec(), 0);
        assert_eq!(n.expect("write"), 5);
        let after_write = cookie(&f).expect("cookie still reported");
        assert_ne!(after_write, first, "a write must move the change cookie");

        let (n, _) = pread1(&h, me, &f, vec![0u8; 5], 0);
        assert_eq!(n.expect("read"), 5);
        assert_eq!(
            cookie(&f).expect("cookie still reported"),
            after_write,
            "a read must not move the change cookie (note: a `noatime` or \
             `relatime` mount can hide a violation here)"
        );

        h.close(f).expect("close");
    });
}

// ---- capability-carrying personalities -------------------------------------

const CAP_NOBODY_UID: u32 = 65_534;
const CAP_NOBODY_GID: u32 = 65_534;

/// The traversal problem this capability exists for: an object the identity is
/// entitled to, under a directory it cannot search. Without the capability the
/// walk stops at `vault/`; with it the kernel resolves through and the read
/// succeeds.
///
/// The second assertion is the uncomfortable half, and it is here on purpose:
/// `CAP_DAC_READ_SEARCH` is not traverse-only. It reads the file too, and no
/// narrower capability exists (`CAP_DAC_OVERRIDE` and `CAP_DAC_READ_SEARCH`
/// are the only two DAC bypasses Linux defines). Anyone loosening this should
/// have to change a test that says so.
#[test]
fn dac_read_search_traverses_a_directory_the_identity_cannot_search() {
    if !root_or_skip(
        "dac_read_search_traverses_a_directory_the_identity_cannot_search",
    ) {
        return;
    }
    with_broker_caps(Caps::DAC_READ_SEARCH, |h, creds, _me, dir| {
        std::fs::create_dir(dir.join("vault")).unwrap();
        std::fs::write(dir.join("vault/inner"), b"secret").unwrap();
        std::fs::set_permissions(
            dir.join("vault"),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        // Unreadable to the identity in its own right, so the successful read
        // below is the capability's doing and not the mode's.
        std::fs::set_permissions(
            dir.join("vault/inner"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let anchor = Anchor::open(dir).unwrap();
        let plain = AsUser::new(CAP_NOBODY_UID, CAP_NOBODY_GID);
        let privileged = plain.clone().caps(Caps::DAC_READ_SEARCH);

        let bare = creds.register(&plain).unwrap();
        assert!(
            matches!(
                h.open(bare, &anchor, "vault/inner", rdonly()),
                Err(Error::Errno(Errno::EACCES))
            ),
            "without the capability the 0700 directory still blocks the walk"
        );

        let elevated = creds.register(&privileged).unwrap();
        let f = h
            .open(elevated, &anchor, "vault/inner", rdonly())
            .expect("DAC_READ_SEARCH should traverse the 0700 directory");
        let (n, buf) = pread1(h, elevated, &f, vec![0u8; 6], 0);
        assert_eq!(n.expect("read"), 6);
        assert_eq!(&buf[..6], b"secret", "and it reads the file, too");
        h.close(f).unwrap();

        creds.unregister(bare).unwrap();
        creds.unregister(elevated).unwrap();
    });
}

/// `CAP_DAC_READ_SEARCH` grants a *pure* read and nothing wider: `fs/namei.c`
/// tests `mask == MAY_READ` with exact equality, so adding a write bit drops
/// out of the grant entirely. `O_RDONLY` succeeds on a file `O_RDWR` cannot
/// even open - asymmetric enough to be worth pinning.
#[test]
fn dac_read_search_grants_o_rdonly_but_not_o_rdwr() {
    if !root_or_skip("dac_read_search_grants_o_rdonly_but_not_o_rdwr") {
        return;
    }
    with_broker_caps(Caps::DAC_READ_SEARCH, |h, creds, _me, dir| {
        std::fs::write(dir.join("locked"), b"x").unwrap();
        std::fs::set_permissions(
            dir.join("locked"),
            std::fs::Permissions::from_mode(0o000),
        )
        .unwrap();
        let anchor = Anchor::open(dir).unwrap();
        let who = creds
            .register(
                &AsUser::new(CAP_NOBODY_UID, CAP_NOBODY_GID)
                    .caps(Caps::DAC_READ_SEARCH),
            )
            .unwrap();

        let f = h
            .open(who, &anchor, "locked", rdonly())
            .expect("a pure read is granted");
        h.close(f).unwrap();

        assert!(
            matches!(
                h.open(
                    who,
                    &anchor,
                    "locked",
                    OpenHow::new().flags(OFlag::O_RDWR)
                ),
                Err(Error::Errno(Errno::EACCES))
            ),
            "read|write is not `mask == MAY_READ`, so the grant does not apply"
        );

        creds.unregister(who).unwrap();
    });
}

/// The spawn-time mask is a ceiling the broker enforces, not a hint the caller
/// may exceed. This is the property that keeps a compromised main - which can
/// already mint any non-root identity - from minting itself read access to
/// every file on the system.
#[test]
fn spawn_time_mask_is_a_ceiling_on_requested_caps() {
    if !root_or_skip("spawn_time_mask_is_a_ceiling_on_requested_caps") {
        return;
    }
    with_broker(|_h, creds, _me, _dir| {
        // `with_broker` spawns with `Caps::empty()`.
        let err = creds
            .register(
                &AsUser::new(CAP_NOBODY_UID, CAP_NOBODY_GID)
                    .caps(Caps::DAC_READ_SEARCH),
            )
            .expect_err("a capability outside the ceiling must be refused");
        assert!(
            matches!(err, Error::Errno(Errno::EPERM)),
            "expected EPERM, got {err:?}"
        );
        // The same identity without capabilities still registers.
        let ok = creds
            .register(&AsUser::new(CAP_NOBODY_UID, CAP_NOBODY_GID))
            .expect("the plain identity is unaffected");
        creds.unregister(ok).unwrap();
    });
}

/// `caps` participates in `AsUser`'s identity, so the cache mints a separate
/// personality rather than handing back one registered without them. Getting
/// this wrong would silently serve whichever variant was requested first --
/// either leaking a capability or withholding one, depending on the order.
#[test]
fn identity_cache_keys_on_the_capability_set() {
    if !root_or_skip("identity_cache_keys_on_the_capability_set") {
        return;
    }
    with_broker_caps(Caps::DAC_READ_SEARCH, |_h, creds, _me, _dir| {
        let cache = IdentityCache::new(creds.clone());
        let plain = AsUser::new(CAP_NOBODY_UID, CAP_NOBODY_GID);
        let privileged = plain.clone().caps(Caps::DAC_READ_SEARCH);
        assert_ne!(plain, privileged, "the capability set is part of identity");

        let a = cache.acquire(&plain).unwrap();
        let b = cache.acquire(&privileged).unwrap();
        assert_ne!(
            a.personality().id(),
            b.personality().id(),
            "distinct capability sets must not share a personality"
        );
        // And each is stable on re-acquire.
        assert_eq!(
            cache.acquire(&plain).unwrap().personality().id(),
            a.personality().id()
        );
    });
}

// ---- recursive, resumable subtree walk -------------------------------------

/// A tree whose root level exercises the `/`-vs-`.`-vs-`-` ordering trap at
/// more than one depth, so a walk that got the comparator right at one level
/// and wrong at another still fails.
fn make_tree(dir: &Path) {
    std::fs::create_dir(dir.join("a")).unwrap();
    std::fs::create_dir(dir.join("a/c")).unwrap();
    std::fs::create_dir(dir.join("z")).unwrap();
    for f in [
        "a-1.txt",
        "a.txt",
        "aa.txt",
        "a/b.txt",
        "a/c/d.txt",
        "z/y.txt",
    ] {
        std::fs::write(dir.join(f), b"x").unwrap();
    }
}

/// Every key the walk yields, in order, as strings.
fn walk_keys(
    h: &FsHandle,
    me: Personality,
    anchor: &Anchor,
    opts: TreeOptions,
) -> Vec<String> {
    let mut t = query_tree(h, me, anchor, opts).expect("query_tree");
    let mut out = Vec::new();
    while let Some(e) = t.next() {
        let e = e.expect("entry");
        out.push(String::from_utf8(e.key()).unwrap());
    }
    out
}

/// Per-directory sorting composes into global path order. Note where `a/`
/// lands: after `a.txt` because `/` outranks `.`, and its whole subtree
/// follows immediately - `a/c/d.txt` still precedes `aa.txt`, which is the
/// property a naive bare-name sort breaks.
#[test]
fn tree_walk_emits_the_subtree_in_global_path_order() {
    with_fs(test_cfg(), |h, me, dir, _stop| {
        make_tree(&dir);
        let anchor = Anchor::open(dir.as_path()).expect("anchor");
        let keys = walk_keys(
            &h,
            me,
            &anchor,
            TreeOptions {
                entries: QueryOptions {
                    clump: 2,
                    ..Default::default()
                },
                ..Default::default()
            },
        );
        assert_eq!(
            keys,
            [
                "a-1.txt",
                "a.txt",
                "a/",
                "a/b.txt",
                "a/c/",
                "a/c/d.txt",
                "aa.txt",
                "z/",
                "z/y.txt",
            ]
        );

        // The same set, sorted independently as flat byte strings, must agree
        // -- that is what "global path order" means, and it is checked here
        // rather than trusted from the literal above.
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted);
    });
}

/// `max_depth: 1` and `skip_descent` are the two ways to get the
/// non-recursive listing a delimiter asks for, and they must agree.
#[test]
fn depth_one_and_skip_descent_both_stop_at_the_top_level() {
    with_fs(test_cfg(), |h, me, dir, _stop| {
        make_tree(&dir);
        let anchor = Anchor::open(dir.as_path()).expect("anchor");
        let expected = ["a-1.txt", "a.txt", "a/", "aa.txt", "z/"];

        let capped = walk_keys(
            &h,
            me,
            &anchor,
            TreeOptions {
                max_depth: 1,
                ..Default::default()
            },
        );
        assert_eq!(capped, expected, "max_depth 1");

        // Pruning every directory as it is yielded reaches the same place,
        // and is how a caller folds one into a common prefix.
        let mut t = query_tree(&h, me, &anchor, TreeOptions::default())
            .expect("query_tree");
        let mut pruned = Vec::new();
        while let Some(e) = t.next() {
            let e = e.expect("entry");
            let is_dir = e.is_dir();
            pruned.push(String::from_utf8(e.key()).unwrap());
            if is_dir {
                t.skip_descent();
            }
        }
        assert_eq!(pruned, expected, "skip_descent on every directory");
    });
}

/// The pagination property, and the reason the cursor is key-based rather
/// than a directory offset: paging through the tree must reproduce the whole
/// walk **exactly** - no key repeated, none skipped - including when a page
/// boundary falls on a directory, which is the case a position-based cursor
/// gets wrong.
#[test]
fn paging_with_a_cursor_reproduces_the_walk_exactly() {
    with_fs(test_cfg(), |h, me, dir, _stop| {
        make_tree(&dir);
        let anchor = Anchor::open(dir.as_path()).expect("anchor");
        let full = walk_keys(&h, me, &anchor, TreeOptions::default());

        // Every page size from 1 up, so the boundary lands on each entry in
        // turn - files, directories, and the last entry of a level alike.
        for page in 1..=full.len() {
            let mut paged: Vec<String> = Vec::new();
            let mut resume: Option<TreeCursor> = None;
            loop {
                let mut t = query_tree(
                    &h,
                    me,
                    &anchor,
                    TreeOptions {
                        resume: resume.clone(),
                        ..Default::default()
                    },
                )
                .expect("query_tree");
                let mut n = 0;
                while n < page {
                    match t.next() {
                        Some(e) => {
                            let e = e.expect("entry");
                            paged.push(String::from_utf8(e.key()).unwrap());
                            n += 1;
                        }
                        None => break,
                    }
                }
                if n == 0 {
                    break;
                }
                resume = Some(t.cursor());
            }
            assert_eq!(paged, full, "paging {page} at a time");
        }
    });
}

/// Resuming a listing must tolerate a subtree that vanished between pages, the
/// same way the forward walk tolerates one removed mid-walk: the walk emits a
/// directory before its contents, so a page can end on `a/c/` with the resume
/// about to re-open it. If `a/c` is gone by then, the rebuild must skip its
/// subtree and advance to the next sibling, not fail the whole listing.
#[test]
fn a_subtree_removed_between_pages_is_skipped_not_fatal() {
    with_fs(test_cfg(), |h, me, dir, _stop| {
        make_tree(&dir);
        let anchor = Anchor::open(dir.as_path()).expect("anchor");
        let full = walk_keys(&h, me, &anchor, TreeOptions::default());
        // `a/c/` is emitted before its contents, so removing it once yielded
        // drops only `a/c/d.txt`.
        let expected: Vec<String> =
            full.iter().filter(|k| *k != "a/c/d.txt").cloned().collect();

        let mut paged: Vec<String> = Vec::new();
        let mut resume: Option<TreeCursor> = None;
        let mut removed = false;
        loop {
            let mut t = query_tree(
                &h,
                me,
                &anchor,
                TreeOptions {
                    resume: resume.clone(),
                    ..Default::default()
                },
            )
            .expect("query_tree resumes across the removed subtree");
            let Some(e) = t.next() else { break };
            let key = String::from_utf8(e.expect("entry").key()).unwrap();
            if key == "a/c/" && !removed {
                // The next page re-opens `a/c`; remove it first so the rebuild
                // hits ENOENT on that level (the walk has not descended into it
                // yet - a directory is emitted before its contents).
                std::fs::remove_dir_all(dir.join("a/c")).unwrap();
                removed = true;
            }
            paged.push(key);
            resume = Some(t.cursor());
        }
        assert!(removed, "a/c/ was never yielded");
        assert_eq!(paged, expected);
    });
}

/// The other half of the restore guard: a level that fails for a reason
/// that is *not* a subtree skip aborts the resume.
///
/// `a_subtree_removed_between_pages_is_skipped_not_fatal` pins the skip
/// half - EACCES/EPERM/ENOENT are levels the forward walk would have
/// skipped too, so a resume that cannot re-enter them is still at the
/// position it saved. Everything else is not: the cursor names a place the
/// rebuild could not reach, so continuing from a shallower level would hand
/// back a short listing with no error in it - which is data loss for the
/// recursive copy and delete built on this.
///
/// Provoked by replacing the directory with a regular file between pages.
/// The rebuild opens each level `O_DIRECTORY`, so the file answers ENOTDIR,
/// which `is_subtree_skip` deliberately does not cover.
#[test]
fn a_level_that_became_a_file_between_pages_aborts_the_resume() {
    with_fs(test_cfg(), |h, me, dir, _stop| {
        make_tree(&dir);
        let anchor = Anchor::open(dir.as_path()).expect("anchor");

        let mut resume: Option<TreeCursor> = None;
        let mut swapped = false;
        loop {
            let opened = query_tree(
                &h,
                me,
                &anchor,
                TreeOptions {
                    resume: resume.clone(),
                    ..Default::default()
                },
            );
            if swapped {
                // The page after the swap must refuse rather than resume
                // somewhere shallower.
                let err = match opened {
                    Ok(_) => panic!(
                        "a level the rebuild could not re-enter was resumed \
                         past, not reported"
                    ),
                    Err(e) => e,
                };
                let truenas_ros::Error::IteratorRestore { path, .. } = &err
                else {
                    panic!("expected IteratorRestore, got {err:?}");
                };
                assert!(
                    path.ends_with("c"),
                    "the refusal names the level it could not rebuild: \
                     {path:?}"
                );
                return;
            }
            let mut t = opened.expect("query_tree resumes");
            let Some(e) = t.next() else {
                panic!("a/c/ was never yielded");
            };
            let key = String::from_utf8(e.expect("entry").key()).unwrap();
            if key == "a/c/" {
                // The next page re-opens `a/c`. Replace it with a regular
                // file so the rebuild's O_DIRECTORY open answers ENOTDIR.
                std::fs::remove_dir_all(dir.join("a/c")).unwrap();
                std::fs::write(dir.join("a/c"), b"").unwrap();
                swapped = true;
            }
            resume = Some(t.cursor());
        }
    });
}

/// `skip_descent` and `cursor` are both documented delimiter primitives, so
/// the obvious composition of them - fold a directory into a common prefix,
/// then page - has to work. It is the page boundary that makes it hard: the
/// walk emits a directory *before* its contents, so a cursor sitting on a
/// folded directory is positioned at the start of the subtree the caller just
/// said to skip. Resuming there must not re-enter it, and must not re-emit
/// the directory either.
#[test]
fn a_folded_subtree_stays_folded_across_a_page_boundary() {
    with_fs(test_cfg(), |h, me, dir, _stop| {
        make_tree(&dir);
        let anchor = Anchor::open(dir.as_path()).expect("anchor");
        // What one uninterrupted walk yields when every directory is pruned.
        let expected = ["a-1.txt", "a.txt", "a/", "aa.txt", "z/"];

        for page in 1..=expected.len() {
            let mut paged: Vec<String> = Vec::new();
            let mut resume: Option<TreeCursor> = None;
            loop {
                let mut t = query_tree(
                    &h,
                    me,
                    &anchor,
                    TreeOptions {
                        resume: resume.clone(),
                        ..Default::default()
                    },
                )
                .expect("query_tree");
                let mut n = 0;
                while n < page {
                    match t.next() {
                        Some(e) => {
                            let e = e.expect("entry");
                            let is_dir = e.is_dir();
                            paged.push(String::from_utf8(e.key()).unwrap());
                            if is_dir {
                                t.skip_descent();
                            }
                            n += 1;
                        }
                        None => break,
                    }
                }
                if n == 0 {
                    break;
                }
                // Round-trip the token, since a real pager persists it.
                let blob = t.cursor().to_bytes();
                resume = Some(
                    TreeCursor::from_bytes(&blob).expect("cursor decodes"),
                );
            }
            assert_eq!(
                paged, expected,
                "folding every directory, {page} entries at a time"
            );
        }
    });
}

/// A cursor survives serialization, so a listing can be resumed by a later
/// request - or a later process - and not just within one walk.
#[test]
fn a_serialized_cursor_resumes_the_walk() {
    with_fs(test_cfg(), |h, me, dir, _stop| {
        make_tree(&dir);
        let anchor = Anchor::open(dir.as_path()).expect("anchor");
        let full = walk_keys(&h, me, &anchor, TreeOptions::default());

        let mut t = query_tree(&h, me, &anchor, TreeOptions::default())
            .expect("query_tree");
        for _ in 0..4 {
            t.next().expect("entry").expect("ok");
        }
        let blob = t.cursor().to_bytes();
        drop(t);

        let restored = TreeCursor::from_bytes(&blob).expect("cursor decodes");
        let rest = walk_keys(
            &h,
            me,
            &anchor,
            TreeOptions {
                resume: Some(restored),
                ..Default::default()
            },
        );
        assert_eq!(rest, full[4..], "the tail of the walk, exactly once");
    });
}

/// Descent resolves one component against the descriptor the walk already
/// holds, under `CONFINED_RESOLVE` - so a symlink planted in the tree is not
/// a way out of it, whether it points outside or back inside.
#[test]
fn the_walk_does_not_follow_symlinks_out_of_the_tree() {
    with_fs(test_cfg(), |h, me, dir, _stop| {
        std::fs::create_dir(dir.join("real")).unwrap();
        std::fs::write(dir.join("real/inside.txt"), b"x").unwrap();
        std::os::unix::fs::symlink("/etc", dir.join("escape")).unwrap();
        std::os::unix::fs::symlink("real", dir.join("loop")).unwrap();

        let anchor = Anchor::open(dir.as_path()).expect("anchor");
        let keys = walk_keys(&h, me, &anchor, TreeOptions::default());

        // The links are yielded as entries - they exist - but neither is
        // descended into, so nothing from /etc and no second copy of
        // `real/`'s contents appears.
        assert!(keys.contains(&"real/".to_string()));
        assert!(keys.contains(&"real/inside.txt".to_string()));
        assert!(
            !keys.iter().any(|k| k.starts_with("escape/")),
            "symlink to /etc must not be descended: {keys:?}"
        );
        assert!(
            !keys.iter().any(|k| k.starts_with("loop/")),
            "symlink to a sibling must not be descended: {keys:?}"
        );
    });
}

// ---- fadvise / fremovexattr / copy_file_range ------------------------------

/// `fadvise` is advisory, so the assertion is that it is *accepted* and does
/// not disturb the file - both advices ZFS implements natively (`WILLNEED` is
/// a `dmu_prefetch`, `DONTNEED` a `dmu_evict_range`) plus the whole-file `0`
/// length form.
#[test]
fn fadvise_is_accepted_and_leaves_contents_alone() {
    with_fs(test_cfg(), |h, me, dir, _stop| {
        let anchor = Anchor::open(dir.as_path()).expect("anchor");
        let f = h.open(me, &anchor, "adv.bin", creat_rw()).expect("open");
        let (n, _) = pwrite1(&h, me, &f, b"0123456789".to_vec(), 0);
        assert_eq!(n.expect("write"), 10);

        for advice in [
            Advice::Normal,
            Advice::Sequential,
            Advice::Random,
            Advice::WillNeed,
            Advice::NoReuse,
        ] {
            h.fadvise(me, &f, 0, 10, advice)
                .unwrap_or_else(|e| panic!("fadvise {advice:?}: {e}"));
        }
        // Length 0 means "to end of file" - the form used after syncing a
        // whole object, and the one most likely to be mis-encoded since the
        // kernel reads the length from `addr`, not `len`.
        h.fadvise(me, &f, 0, 0, Advice::DontNeed).expect("dontneed");
        h.fadvise(me, &f, 4, 6, Advice::DontNeed).expect("ranged");

        let (n, buf) = pread1(&h, me, &f, vec![0u8; 10], 0);
        assert_eq!(n.expect("read"), 10);
        assert_eq!(&buf[..10], b"0123456789", "advice must not alter data");
        h.close(f).unwrap();
    });
}

/// Drive `client` against a reactor whose [`PrivilegedXattrs`] policy claims
/// `trusted.example_`, the namespace these two tests treat as server-owned.
fn with_priv_xattr_fs<F>(client: F)
where
    F: FnOnce(&FsHandle, Personality, &Path) + Send,
{
    let mut afs = match UringFs::new(test_cfg()) {
        Ok(a) => a,
        Err(e) => {
            if should_skip(&e) {
                return;
            }
            panic!("UringFs::new: {e}");
        }
    };
    afs.set_privileged_xattrs(
        PrivilegedXattrs::new()
            .allow_prefix(c"trusted.example_")
            .expect("allowlist"),
    );
    let me = afs.register_self().expect("register_self");
    let h = afs.handle();
    let stop = afs.shutdown_handle();
    let dir = truenas_ros::tempdir().expect("tempdir");
    let dir_path = dir.path().to_path_buf();
    thread::scope(|s| {
        s.spawn(move || {
            let _guard = StopGuard(stop);
            client(&h, me, &dir_path);
        });
        afs.run().expect("run");
    });
}

/// The allowlist is the whole security contract for `fremovexattr`: it takes
/// no [`Personality`], so an attribute the server does not own must be
/// refused outright rather than removed under the reactor's credentials.
///
/// Deliberately needs no privilege - the refusal is decided from the policy
/// before any syscall, so this runs everywhere and is the half worth having
/// unconditional coverage of.
#[test]
fn fremovexattr_refuses_attributes_outside_the_allowlist() {
    with_priv_xattr_fs(|h, me, dir| {
        let anchor = Anchor::open(dir).expect("anchor");
        let f = h.open(me, &anchor, "obj", creat_rw()).expect("open");
        let user = xattr_name("user.mine");
        h.fsetxattr(me, &f, &user, b"xyz".to_vec(), 0)
            .0
            .expect("an unprivileged user.* set");

        assert!(
            matches!(
                h.fremovexattr(&f, &user),
                Err(Error::Errno(Errno::EPERM))
            ),
            "an attribute the server does not own must not be removable"
        );
        assert!(
            h.flistxattr(&f).unwrap().contains(&user),
            "the refused attribute is still there"
        );
        h.close(f).unwrap();
    });
}

/// The other half: an allowlisted attribute really is removed, and is *gone
/// from the listing* rather than left present with an empty value - which is
/// all a zero-length `FSETXATTR` would have achieved.
///
/// Root-only: writing `trusted.*` needs `CAP_SYS_ADMIN`, and the allowlist
/// promotion runs under the reactor's own credentials, so an unprivileged
/// reactor cannot set the attribute this removes.
#[test]
fn fremovexattr_removes_allowlisted_attributes() {
    if !root_or_skip("fremovexattr_removes_allowlisted_attributes") {
        return;
    }
    with_priv_xattr_fs(|h, me, dir| {
        let anchor = Anchor::open(dir).expect("anchor");
        let f = h.open(me, &anchor, "obj", creat_rw()).expect("open");
        let owned = xattr_name("trusted.example_etag");
        let user = xattr_name("user.mine");
        h.fsetxattr(me, &f, &owned, b"abc".to_vec(), 0)
            .0
            .expect("server-owned set is promoted to the reactor's creds");
        h.fsetxattr(me, &f, &user, b"xyz".to_vec(), 0)
            .0
            .expect("user set");

        h.fremovexattr(&f, &owned).expect("server-owned removal");
        let names = h.flistxattr(&f).unwrap();
        assert!(!names.contains(&owned), "removed, not emptied: {names:?}");
        assert!(names.contains(&user), "the other attribute is untouched");

        // Removing what is not there is an error, not a silent success.
        assert!(h.fremovexattr(&f, &owned).is_err());
        h.close(f).unwrap();
    });
}

/// A subtree that cannot be *opened* for a non-permission reason must surface
/// as an error, not vanish from the walk the way the readdir path already
/// refuses to. A silently dropped subtree is data loss for the recursive
/// delete/copy this walk backs.
///
/// The trigger is a real race: a directory is yielded, and the descent into it
/// is deferred to the next call so `skip_descent` can cancel it - swap the
/// directory for a regular file inside that window and the deferred
/// `O_DIRECTORY` open fails `ENOTDIR`.
///
/// Keep any provocation here *local* to the walk. `cargo test` runs a
/// binary's tests as threads in one process, so anything that exhausts a
/// process-wide resource - the fd table above all - starves whatever else is
/// running rather than only this test, and fails a different innocent test on
/// each run depending on the fd limit.
#[test]
fn descend_open_failure_surfaces_rather_than_dropping_the_subtree() {
    with_fs(test_cfg(), |h, me, dir, _stop| {
        std::fs::create_dir(dir.join("sub")).unwrap();
        std::fs::write(dir.join("sub/f.txt"), b"x").unwrap();
        std::fs::write(dir.join("z.txt"), b"x").unwrap();
        let anchor = Anchor::open(dir.as_path()).expect("anchor");

        let mut t = query_tree(&h, me, &anchor, TreeOptions::default())
            .expect("query_tree");
        // "sub/" sorts before "z.txt"; its descent is deferred to the next call.
        assert_eq!(t.next().expect("some").expect("ok").key(), b"sub/");

        // The window: replace the directory with a regular file of the same
        // name, so the deferred open of "sub" cannot be a directory open.
        std::fs::remove_file(dir.join("sub/f.txt")).unwrap();
        std::fs::remove_dir(dir.join("sub")).unwrap();
        std::fs::write(dir.join("sub"), b"x").unwrap();

        match t.next() {
            // triggers descend("sub")
            Some(Err(Error::Errno(Errno::ENOTDIR))) => {}
            other => panic!(
                "an unopenable subtree must surface an error, got {other:?}"
            ),
        }
        // The error is per-subtree, not fatal: the walk carries on in the
        // parent with the sibling it had already read.
        assert_eq!(
            t.next().expect("some").expect("ok").key(),
            b"z.txt",
            "a surfaced descend failure must not end the walk"
        );
    });
}

/// The other side of that race, and the common one: a directory removed
/// between the parent's `readdir` and the deferred descent leaves no subtree
/// to list, so it drops out quietly rather than failing the walk. Any walk
/// over a tree being written to hits this routinely, and a recursive copy that
/// aborted every time a directory went away underneath it would be unusable.
#[test]
fn a_subtree_removed_under_the_walk_is_skipped_quietly() {
    with_fs(test_cfg(), |h, me, dir, _stop| {
        std::fs::create_dir(dir.join("sub")).unwrap();
        std::fs::write(dir.join("sub/f.txt"), b"x").unwrap();
        std::fs::write(dir.join("z.txt"), b"x").unwrap();
        let anchor = Anchor::open(dir.as_path()).expect("anchor");

        let mut t = query_tree(&h, me, &anchor, TreeOptions::default())
            .expect("query_tree");
        assert_eq!(t.next().expect("some").expect("ok").key(), b"sub/");

        // Same deferred-descent window as the ENOTDIR case, but the entry is
        // gone rather than replaced.
        std::fs::remove_file(dir.join("sub/f.txt")).unwrap();
        std::fs::remove_dir(dir.join("sub")).unwrap();

        assert_eq!(
            t.next().expect("some").expect("ok").key(),
            b"z.txt",
            "a vanished subtree must not fail the walk"
        );
        assert!(t.next().is_none(), "the walk ends after the last sibling");
    });
}
