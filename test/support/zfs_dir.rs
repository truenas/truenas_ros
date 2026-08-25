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
#[allow(dead_code)] // each including binary uses the half it needs
#[track_caller]
pub fn zfs_dir_or_skip() -> Option<std::path::PathBuf> {
    use std::path::PathBuf;
    for var in ["TRUENAS_ROS_NFS4_DATASET", "TRUENAS_ROS_POSIX_DATASET"] {
        if let Some(d) = std::env::var_os(var).map(PathBuf::from)
            && d.is_dir()
        {
            return Some(d);
        }
    }
    for fallback in ["/NFSV4ACL", "/POSIXACL"] {
        let d = PathBuf::from(fallback);
        if d.is_dir() {
            return Some(d);
        }
    }
    assert!(
        std::env::var_os("TRUENAS_ROS_REQUIRE_ZFS").is_none(),
        "TRUENAS_ROS_REQUIRE_ZFS is set but no ZFS dataset is present"
    );
    None
}
