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
//! # Features
//!
//! Functionality is split into per-subsystem Cargo features (`fs`, `xattr`,
//! `mount`, `acl`, `fhandle`, `fsiter`, `namespace`, `shutil`, `configfile`,
//! and the `net` stack: `net-core`/`net-server`/`net-client`); `full` enables
//! them all.
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

pub use errno::Errno;
pub use error::{Error, Result};
pub use fd::AT_FDCWD;
pub use path::TnPath;

#[cfg(feature = "fs")]
pub mod fs;

#[cfg(feature = "xattr")]
pub mod xattr;

#[cfg(feature = "mount")]
pub mod mount;

#[cfg(feature = "acl")]
pub mod acl;

#[cfg(feature = "fhandle")]
pub mod fhandle;

#[cfg(feature = "fsiter")]
pub mod iter;

#[cfg(feature = "namespace")]
pub mod namespace;

#[cfg(feature = "shutil")]
pub mod shutil;

#[cfg(feature = "configfile")]
pub mod configfile;

#[cfg(feature = "net-core")]
pub mod net;
