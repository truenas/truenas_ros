//! Resolve a ZFS dataset directory for tests whose subject is filesystem
//! behaviour rather than generic VFS behaviour.
//!
//! The appliance only runs on ZFS, so a fixture that lands on the default
//! tmpfs pins the wrong filesystem: it will often pass, having exercised a
//! path the product never takes. `copy_file_range` is the clearest case -
//! tmpfs serves it as a plain copy while ZFS serves it as a block clone
//! (`zfs_clone_range`), which is the code that actually ships.
//!
//! `TRUENAS_ROS_REQUIRE_ZFS` turns the skip into a failure, so a runner that
//! stopped provisioning a dataset goes red instead of reporting a green suite
//! that exercised tmpfs.

/// A ZFS dataset directory to work in, or `None` to skip.
///
/// Resolved as the CI provisioning script exports it, then the `/NFSV4ACL` /
/// `/POSIXACL` convention paths. Any dataset serves a caller that does not
/// care about `acltype` - the ACL suites resolve their own, by type.
///
/// Each candidate is checked with `statfs`, not `is_dir`. A directory that
/// exists proves only that: pointed at `/dev/shm`, an `is_dir` gate hands
/// back tmpfs, both ZFS fixtures pass on it, and `TRUENAS_ROS_REQUIRE_ZFS`
/// stays green having tested the filesystem this module exists to avoid.
#[allow(dead_code)] // each including binary uses the half it needs
#[track_caller]
pub fn zfs_dir_or_skip() -> Option<std::path::PathBuf> {
    use std::path::PathBuf;
    let mut wrong_fs = Vec::new();
    let mut pick = |d: PathBuf| match is_zfs(&d) {
        Some(true) => Some(d),
        Some(false) => {
            wrong_fs.push(d);
            None
        }
        None => None, // absent, or unreadable: not a wrong-filesystem report
    };
    for var in ["TRUENAS_ROS_NFS4_DATASET", "TRUENAS_ROS_POSIX_DATASET"] {
        if let Some(d) = std::env::var_os(var).map(PathBuf::from)
            && let Some(d) = pick(d)
        {
            return Some(d);
        }
    }
    for fallback in ["/NFSV4ACL", "/POSIXACL"] {
        if let Some(d) = pick(PathBuf::from(fallback)) {
            return Some(d);
        }
    }
    assert!(
        std::env::var_os("TRUENAS_ROS_REQUIRE_ZFS").is_none(),
        "TRUENAS_ROS_REQUIRE_ZFS is set but no ZFS dataset is present \
         (candidates that exist but are not ZFS: {wrong_fs:?})"
    );
    None
}

/// Whether `path` is on ZFS. `None` when it does not exist or cannot be
/// stat'd, which is the "no fixture" case rather than the "wrong one".
#[allow(dead_code)] // see `zfs_dir_or_skip`
fn is_zfs(path: &std::path::Path) -> Option<bool> {
    use std::os::unix::ffi::OsStrExt;
    // `zfs_super_magic` (`include/os/linux/zfs/sys/zfs_vfsops_os.h`).
    const ZFS_SUPER_MAGIC: i64 = 0x2fc12fc1;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    // SAFETY: `statfs` writes the whole struct; a zeroed one is a valid
    // starting value and the path is NUL-terminated.
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: valid path pointer and a live output struct.
    if unsafe { libc::statfs(c.as_ptr(), &mut st) } != 0 {
        return None;
    }
    Some(st.f_type == ZFS_SUPER_MAGIC)
}

/// The discriminator the gate rests on: a directory that exists is not
/// evidence of a filesystem.
///
/// `/proc` is always present on Linux and is never ZFS - an `is_dir` gate
/// says yes to it, and to `/dev/shm`, which is how two ZFS fixtures came to
/// pass on tmpfs with `TRUENAS_ROS_REQUIRE_ZFS` armed.
#[test]
fn is_zfs_reads_the_filesystem_not_the_directory() {
    let proc = std::path::Path::new("/proc");
    assert!(proc.is_dir(), "/proc must exist to test against");
    assert_eq!(is_zfs(proc), Some(false), "/proc is not ZFS");
    assert_eq!(
        is_zfs(std::path::Path::new("/no/such/fixture")),
        None,
        "an absent path is 'no fixture', not 'the wrong one'"
    );
}
