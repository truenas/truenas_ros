//! `truenas_ros` — idiomatic Rust bindings for modern Linux filesystem and
//! mount syscalls that glibc does not wrap, plus NFS4/POSIX1E ACLs, a
//! filesystem iterator, idmapped-mount user namespaces, and symlink-safe /
//! atomic file I/O.
//!
//! This is the Rust equivalent of the Python `truenas_pyos` library. It targets
//! Linux kernels 6.18 and newer and depends only on `libc` and `bitflags`.
//!
//! # Error layering
//!
//! Low-level syscall wrappers return [`errno::Result<T>`] (a bare [`Errno`]).
//! Higher-level APIs return [`Result<T>`] (the rich [`Error`]); `Errno`
//! converts into `Error` via `From`, so `?` bridges the two.
//!
//! # Features and layout
//!
//! Functionality is split into per-subsystem Cargo features grouped under
//! umbrella modules: [`sync_fs`] (blocking fs bindings — features `sync-fs`,
//! `xattr`, `acl`, `fhandle`, `fsiter`, `shutil`), [`mount`] (mount topology
//! and idmapped-mount support — features `mount`, `idmap`), [`configfile`],
//! the io_uring `net` stack (`net-core`/`net-server`/`net-client`), and the
//! io_uring fs reactor `async_fs` (`async-fs`); `full` enables all but the
//! still-landing fs reactor.
#![cfg(target_os = "linux")]
#![allow(non_camel_case_types)]
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(unexpected_cfgs)]
#![warn(missing_docs)]
#![warn(missing_debug_implementations)]
#![warn(clippy::cast_ptr_alignment)]

/// Re-export of the `libc` crate so downstream code can reach raw items without
/// a second dependency edge.
pub use libc;

#[macro_use]
mod macros;

pub mod errno;
mod error;
pub mod fd;
pub mod path;

// The shared `clone3` fork helper (pidfd + signal-handler reset), used by the
// credential broker and the idmapped-mount userns builder.
#[cfg(any(feature = "idmap", feature = "async-fs"))]
mod clone3;

pub use errno::Errno;
pub use error::{Error, Result};
pub use fd::AT_FDCWD;
pub use path::TnPath;

#[cfg(any(
    feature = "sync-fs",
    feature = "xattr",
    feature = "acl",
    feature = "fhandle",
    feature = "fsiter",
    feature = "shutil"
))]
pub mod sync_fs;

#[cfg(any(feature = "mount", feature = "idmap"))]
pub mod mount;

#[cfg(feature = "configfile")]
pub mod configfile;

#[cfg(feature = "uring")]
mod uring;

#[cfg(feature = "async-fs")]
pub mod async_fs;

#[cfg(feature = "net-core")]
pub mod net;
