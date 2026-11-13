//! Integration tests for the `uring_fs` io_uring reactor - live data and metadata ops against a tempdir, every one
//! stamped with a self personality and resolved against an [`Anchor`] (there is no unstamped or absolute-path variant
//! to test).
//!
//! Like `test/net_server.rs`, these **skip** (return early) when io_uring is unavailable - a bare sandbox blocks the
//! syscalls (ENOSYS/EPERM/EACCES) -- and `TRUENAS_ROS_REQUIRE_IO_URING=1` turns that skip into a hard failure.
//!
//! `UringFs` is `!Send` (single-thread ring), so the harness runs the loop on the test thread and drives the client
//! from a scoped thread; a panic-safe guard stops the loop however the client exits.
#![cfg(all(target_os = "linux", feature = "uring-fs"))]

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;
use truenas_ros::sync_fs::{AtFlags, Mode, OFlag, OpenHow, RenameFlags, ResolveFlag, StatxAttr, StatxMask, ZfsAttr};
use truenas_ros::uring_fs::{
    Advice, Anchor, AsUser, Caps, CredBroker, CredHandle, EnrichSpec, File, FsConfig, FsHandle, IdentityCache, Leaf,
    Order, Personality, PrivilegedXattrs, QueryOptions, ReopenAccess, RwFlags, ShutdownHandle, TreeCursor, TreeOptions,
    UringFs, query_directory, query_tree,
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

/// Hold a ring-side `fsetxattr` refusal to the `TRUENAS_ROS_REQUIRE_XATTRS` gate, returning whether the set stuck.
///
/// The probes here set through the fs handle rather than `libc`, so the shared module's path helper cannot serve them,
/// but a refusal means the same thing.
fn fd_xattr_ok<T>(what: &str, res: &Result<T, Error>) -> bool {
    if let Err(e) = res {
        xattr_probe::refusal_is_allowed(what, e);
    }
    res.is_ok()
}

/// Single-buffer read into a buffer the caller filled first, over the vectored, flagged form.
/// A read into the room past a buffer's length is `FsHandle::pread_spare` instead.
fn pread1(h: &FsHandle, who: Personality, f: &File, buf: Vec<u8>, off: u64) -> (Result<usize, Error>, Vec<u8>) {
    let (res, mut bufs) = h.preadv2(who, f, vec![buf], off, RwFlags::empty());
    (res, bufs.pop().unwrap_or_default())
}

/// Single-buffer write; the write-side twin of [`pread1`].
fn pwrite1(h: &FsHandle, who: Personality, f: &File, buf: Vec<u8>, off: u64) -> (Result<usize, Error>, Vec<u8>) {
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

/// Errors that mean "io_uring is unavailable here" - an environmental skip. Deliberately excludes `EINVAL` (a rejected
/// setup argument is a real bug).
fn should_skip(e: &Error) -> bool {
    let unavailable = matches!(
        e,
        // ENOMEM: rings pin pages against RLIMIT_MEMLOCK, so a loaded box exhausts it and ring creation fails -
        // environmental, and the REQUIRE variable turns the skip red where it must not happen.
        Error::Errno(Errno::EPERM | Errno::ENOSYS | Errno::EACCES | Errno::ENOMEM)
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

/// Pin a known umask for the whole binary. Several tests assert on the mode of something they create - `mkdirat`'s mode
/// argument, or a setup file an impersonated user has to be able to read - and the kernel masks every one of those with
/// the umask the suite happens to inherit. Left alone, a developer or CI runner at 0077 fails those tests for a reason
/// that has nothing to do with the code under test.
fn pin_umask() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        // SAFETY: umask cannot fail; it returns the previous mask.
        unsafe { libc::umask(0o022) };
    });
}

/// Reactor sizing for tests, deliberately **not** [`FsConfig::default`].
///
/// The default is sized for a server daemon, which costs roughly 400 KiB of `RLIMIT_MEMLOCK` per ring (see `FsConfig`'s
/// docs). `cargo test` runs a binary's tests as threads in **one** process, so inheriting that default would have every
/// concurrent test drawing on one locked-memory budget - and the failure lands on whichever test happens to create the
/// ring that crosses the limit, not on the one that caused it.
fn test_cfg() -> FsConfig {
    let mut cfg = FsConfig::default();
    cfg.entries = 128;
    cfg.ops = 128;
    cfg
}

/// Build an `UringFs` over a fresh tempdir, register a self personality, run the loop on this thread, and drive
/// `client` from a scoped thread.
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
    with_broker_policy(allowed, None, client)
}

/// The body of [`with_broker_caps`] and [`with_broker_root`].
fn with_broker_policy<F>(allowed: Caps, root: Option<Caps>, client: F)
where
    F: FnOnce(&FsHandle, &CredHandle, Personality, &Path) + Send,
{
    pin_umask();
    let dir = truenas_ros::tempdir().expect("tempdir");
    // These tests drive ops as an impersonated user, who must be able to traverse this directory and - for the ones
    // that create as that user -- write in it. A fresh tempdir is only owner-writable, so widen it once here rather
    // than in each test.
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o777)).expect("chmod tempdir");
    // The ring must exist before the broker forks: it inherits the fd, because an io_uring descriptor cannot be sent
    // over a unix socket.
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
    let spawned = match root {
        None => CredBroker::spawn_with_caps(&[&afs], allowed),
        Some(root) => CredBroker::spawn_with_root(&[&afs], allowed, root),
    };
    let broker = match spawned {
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

/// An NFSv4 ACL as `system.nfs4_acl_xdr` holds it, with no flags of the whole ACL. Each entry is its type, flags,
/// whether its who is special, mask and who, in that order (`acep_to_nfsace4i` in `zpl_xattr.c`).
fn nfs4_xdr(entries: &[[u32; 5]]) -> Vec<u8> {
    let mut xdr = Vec::new();
    xdr.extend(0u32.to_be_bytes());
    xdr.extend((entries.len() as u32).to_be_bytes());
    for word in entries.iter().flatten() {
        xdr.extend(word.to_be_bytes());
    }
    xdr
}

/// A uid/gid pair that exists nowhere - no files, no group memberships -- so a personality for it has exactly the
/// authority "other" grants.
const NOBODY_UID: u32 = 65_534;
const NOBODY_GID: u32 = 65_534;

// --- system.truenas_setattr ------------------------------------------------

/// The setter of the TrueNAS ZFS fork, `system.truenas_setattr`, through the ring. These run as root on ZFS, since they
/// chown and act as other users. `TRUENAS_ROS_REQUIRE_ZFS` fails a runner with no dataset, and
/// `TRUENAS_ROS_REQUIRE_ZFS_SETATTR` one whose ZFS lacks the handler.
#[path = "uring_fs/zfs_setattr.rs"]
mod zfs_setattr;

#[path = "uring_fs/ops.rs"]
mod ops;

#[path = "uring_fs/metadata.rs"]
mod metadata;

#[path = "uring_fs/broker.rs"]
mod broker;

#[path = "uring_fs/query_directory.rs"]
mod query_directory;

#[path = "uring_fs/xattrs.rs"]
mod xattrs;

#[path = "uring_fs/listing.rs"]
mod listing;

#[path = "uring_fs/fd_ops.rs"]
mod fd_ops;
