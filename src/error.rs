//! The rich crate-level [`Error`] type.
//!
//! Low-level syscall wrappers return [`crate::errno::Result`] (a bare
//! [`Errno`]). Higher-level APIs that can also fail validation, parsing, or
//! traversal invariants return [`Result`] (this module's `Error`). `Errno`
//! converts into `Error` via `From`, so `?` bridges the two layers.

use crate::errno::Errno;
use std::fmt;
use std::io;
use std::path::PathBuf;

/// The crate-level result type used by higher-level APIs.
pub type Result<T> = std::result::Result<T, Error>;

/// An error raised by a higher-level `truenas_ros` operation.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// A raw syscall failure.
    Errno(Errno),

    /// A precondition, range, or shape check failed (the analogue of Python's
    /// `ValueError` / `TypeError`).
    Validation(String),

    /// On-disk / wire data could not be parsed (e.g. a malformed ACL xattr).
    Parse(String),

    /// A filesystem iterator could not be resumed from a saved directory
    /// stack: the directory recorded at `depth` no longer exists or changed
    /// inode.
    IteratorRestore {
        /// Directory-stack depth (0-indexed) at which restoration failed.
        depth: usize,
        /// Path of the directory whose expected child was not found.
        path: PathBuf,
    },

    /// A filesystem iterator's root did not belong to the expected mount
    /// source (its `statmount` `sb_source` did not match).
    MountSourceMismatch {
        /// The filesystem source name that was expected.
        expected: String,
        /// The filesystem source name actually reported by the kernel.
        found: String,
        /// The path whose mount was checked.
        path: PathBuf,
    },

    /// A symlink was encountered on a path opened with `RESOLVE_NO_SYMLINKS`
    /// (the underlying `errno` is `ELOOP`).
    SymlinkInPath {
        /// The path that contained a symlink component.
        path: PathBuf,
    },
}

impl From<Errno> for Error {
    fn from(err: Errno) -> Self {
        Error::Errno(err)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Errno(e) => write!(f, "{e}"),
            Error::Validation(msg) => write!(f, "invalid argument: {msg}"),
            Error::Parse(msg) => write!(f, "parse error: {msg}"),
            Error::IteratorRestore { depth, path } => write!(
                f,
                "cannot restore iterator at depth {depth}: {}",
                path.display()
            ),
            Error::MountSourceMismatch {
                expected,
                found,
                path,
            } => write!(
                f,
                "mount source mismatch at {}: expected {expected:?}, \
                 found {found:?}",
                path.display()
            ),
            Error::SymlinkInPath { path } => {
                write!(f, "symlink in path: {}", path.display())
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Errno(e) => Some(e),
            _ => None,
        }
    }
}

impl From<Error> for io::Error {
    fn from(err: Error) -> Self {
        match err {
            Error::Errno(e) => e.into(),
            Error::SymlinkInPath { .. } => {
                io::Error::from_raw_os_error(libc::ELOOP)
            }
            other => io::Error::new(io::ErrorKind::InvalidInput, other),
        }
    }
}
