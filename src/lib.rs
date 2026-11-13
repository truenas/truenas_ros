//! `truenas_ros` - idiomatic Rust bindings for modern Linux filesystem and mount syscalls that glibc does not wrap,
//! plus NFS4/POSIX1E ACLs, a filesystem iterator, idmapped-mount user namespaces, and symlink-safe / atomic file I/O.
//!
//! This is the Rust equivalent of the Python `truenas_pyos` library. It targets Linux kernels 6.18 and newer. The base
//! crate depends only on `libc` and `bitflags`, the `http` and `ws` codecs add `httparse`, and `ws` adds `openssl`.
//!
//! # Error layering
//!
//! Low-level syscall wrappers return [`errno::Result<T>`] (a bare [`Errno`]). Higher-level APIs return [`Result<T>`]
//! (the rich [`Error`]); `Errno` converts into `Error` via `From`, so `?` bridges the two.
//!
//! # Features and layout
//!
//! Functionality is split into per-subsystem Cargo features grouped under umbrella modules: [`sync_fs`] (blocking fs
//! bindings - features `sync-fs`, `xattr`, `acl`, `fhandle`, `fanotify`, `fsiter`, `shutil`), [`mount`] (mount
//! topology and idmapped-mount support - features `mount`, `idmap`), [`configfile`], [`audit`] (kernel audit records
//! over `NETLINK_AUDIT`), [`log`](mod@log) (a daemon's log, sent to the journal without blocking), the io_uring `net`
//! stack (`net-core`/`net-server`/`net-client`) with the [`http`] codec over it (`http`) and the client WebSocket codec
//! [`ws`] (`ws`), the io_uring fs reactor [`uring_fs`] (`uring-fs`), and two pieces for a daemon's `main`, [`secrets`]
//! (`memfd_secret`-backed memory, `secrets`) and [`signal`] (block the signals a daemon acts on and receive them as
//! values, `signal`). `full` enables everything except `uring-fs`, which is opted into on its own.
#![cfg(target_os = "linux")]
#![allow(non_camel_case_types)]
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(unexpected_cfgs)]
#![warn(missing_docs)]
#![warn(missing_debug_implementations)]
#![warn(clippy::cast_ptr_alignment)]

/// Re-export of the `libc` crate so downstream code can reach raw items without a second dependency edge.
pub use libc;

#[macro_use]
mod macros;

pub mod errno;
mod error;
pub mod fd;
pub mod path;
pub mod tempdir;

// std's synchronization primitives, or loom's under `--cfg loom`. Only the subsystems with loom models import from
// here, and the rest use `std::sync` directly.
#[cfg(any(feature = "uring", feature = "uring-fs"))]
pub(crate) mod sync;

#[cfg(any(feature = "idmap", feature = "uring-fs"))]
mod clone3;

#[cfg(any(feature = "configfile", feature = "secrets"))]
mod scrub;

pub use errno::Errno;
pub use error::{Error, Result};
pub use fd::AT_FDCWD;
pub use path::TnPath;
pub use tempdir::{TempDir, tempdir};

#[cfg(any(
    feature = "sync-fs",
    feature = "xattr",
    feature = "acl",
    feature = "fhandle",
    feature = "fanotify",
    feature = "fsiter",
    feature = "shutil"
))]
pub mod sync_fs;

#[cfg(any(feature = "mount", feature = "idmap"))]
pub mod mount;

#[cfg(feature = "configfile")]
pub mod configfile;

#[cfg(feature = "audit")]
pub mod audit;

#[cfg(feature = "log")]
pub mod log;

#[cfg(feature = "secrets")]
pub mod secrets;

#[cfg(feature = "signal")]
pub mod signal;

#[cfg(feature = "uring")]
mod uring;

#[cfg(feature = "uring-fs")]
pub mod uring_fs;

#[cfg(feature = "net-core")]
pub mod net;

#[cfg(feature = "http")]
pub mod http;

#[cfg(feature = "ws")]
pub mod ws;
