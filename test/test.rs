//! Integration tests for `truenas_ros` (mirrors `src/`, nix convention).
#![cfg(target_os = "linux")]

// The `TRUENAS_ROS_REQUIRE_XATTRS` gate, shared with the live suites.
#[cfg(feature = "xattr")]
#[path = "support/xattr.rs"]
mod xattr_probe;

#[cfg(feature = "sync-fs")]
#[path = "test/fs.rs"]
mod fs;

#[cfg(feature = "xattr")]
#[path = "test/xattr.rs"]
mod xattr;

#[cfg(feature = "mount")]
#[path = "test/mount.rs"]
mod mount;

#[cfg(all(feature = "fanotify", feature = "mount"))]
#[path = "test/fanotify.rs"]
mod fanotify;

#[cfg(feature = "acl")]
#[path = "support/zfs_dir.rs"]
mod zfs_dir;

#[cfg(feature = "acl")]
#[path = "test/acl.rs"]
mod acl;

#[cfg(feature = "fhandle")]
#[path = "test/fhandle.rs"]
mod fhandle;

#[cfg(feature = "fsiter")]
#[path = "test/fsiter.rs"]
mod fsiter;

#[cfg(feature = "idmap")]
#[path = "test/namespace.rs"]
mod namespace;

#[cfg(feature = "sync-fs")]
#[path = "test/io.rs"]
mod io;

#[cfg(feature = "mount")]
#[path = "test/mount_helpers.rs"]
mod mount_helpers;

#[cfg(feature = "shutil")]
#[path = "test/shutil.rs"]
mod shutil;

#[cfg(feature = "configfile")]
#[path = "test/configfile.rs"]
mod configfile;
