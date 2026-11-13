//! Coverage-oriented integration tests (companion to `test.rs`), exercising the error/errno/path plumbing and the many
//! exposed paths the primary suite does not reach across each subsystem.
#![cfg(target_os = "linux")]

// The `TRUENAS_ROS_REQUIRE_XATTRS` gate, shared with the live suites: a filesystem that refuses xattrs must fail this
// suite loudly where CI arms it, not skip the assertions behind the probe.
#[path = "support/xattr.rs"]
mod xattr_probe;
#[cfg(feature = "xattr")]
#[path = "support/zfs_dir.rs"]
mod zfs_dir;

// ------------------------------------------------------------------ errno/error
#[path = "coverage/errno_error.rs"]
mod errno_error;

// ------------------------------------------------------------------------- path
#[path = "coverage/path_tests.rs"]
mod path_tests;

// --------------------------------------------------------------------------- fs
#[cfg(feature = "sync-fs")]
#[path = "coverage/fs.rs"]
mod fs;

// ------------------------------------------------------------------------ xattr
#[cfg(feature = "xattr")]
#[path = "coverage/xattr.rs"]
mod xattr;

// ------------------------------------------------------------------------ mount
#[cfg(feature = "mount")]
#[path = "coverage/mount.rs"]
mod mount;

// -------------------------------------------------------------------------- acl
#[cfg(feature = "acl")]
#[path = "coverage/acl.rs"]
mod acl;

// ---------------------------------------------------------------------- fhandle
#[cfg(feature = "fhandle")]
#[path = "coverage/fhandle.rs"]
mod fhandle;

// ----------------------------------------------------------------------- fsiter
#[cfg(feature = "fsiter")]
#[path = "coverage/fsiter.rs"]
mod fsiter;

// --------------------------------------------------------------------------- io
#[cfg(feature = "sync-fs")]
#[path = "coverage/io.rs"]
mod io;

// ----------------------------------------------------------------------- shutil
#[cfg(feature = "shutil")]
#[path = "coverage/shutil.rs"]
mod shutil;

// ------------------------------------------------------------------- configfile

#[cfg(feature = "configfile")]
#[path = "coverage/configfile.rs"]
mod configfile;
