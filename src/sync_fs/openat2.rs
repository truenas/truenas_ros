//! `openat2(2)` — open with fine-grained path-resolution control.

use super::{Mode, OFlag};
use crate::errno::{self, retry_on_eintr};
use crate::fd::owned_from_raw;
use crate::path::TnPath;
use std::mem::size_of;
use std::os::fd::{AsFd, AsRawFd, OwnedFd, RawFd};

tn_bitflags! {
    /// Path-resolution flags for [`openat2`] (`RESOLVE_*`).
    pub struct ResolveFlag: libc::c_ulonglong {
        /// Fail if resolution would cross a mount point / leave `dirfd`'s
        /// filesystem.
        RESOLVE_NO_XDEV = 0x01;
        /// Disallow magic-link (e.g. `/proc/*/fd/*`) resolution.
        RESOLVE_NO_MAGICLINKS = 0x02;
        /// Disallow all symbolic-link resolution (implies `NO_MAGICLINKS`).
        RESOLVE_NO_SYMLINKS = 0x04;
        /// Reject any path component that escapes the directory `dirfd`.
        RESOLVE_BENEATH = 0x08;
        /// Treat `dirfd` as the root directory during resolution.
        RESOLVE_IN_ROOT = 0x10;
        /// Only succeed if the path can be resolved entirely from cache.
        RESOLVE_CACHED = 0x20;
    }
}

/// Kernel `struct open_how`. Must be zero-initialised; unknown fields are
/// zeroed so future kernels reject unsupported bits. Shared with the io_uring
/// fs reactor, whose `OPENAT2` SQE points at one of these (`sqe.addr2`).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct RawOpenHow {
    pub(crate) flags: u64,
    pub(crate) mode: u64,
    pub(crate) resolve: u64,
}

/// The `open_how` argument to [`openat2`], constructed with builder methods.
#[derive(Clone, Copy, Debug, Default)]
pub struct OpenHow(RawOpenHow);

impl OpenHow {
    /// Create a new, zeroed `open_how`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the open flags, overwriting any previously set.
    pub fn flags(mut self, flags: OFlag) -> Self {
        self.0.flags = flags.bits() as u64;
        self
    }

    /// Set the creation mode (used only when `O_CREAT`/`O_TMPFILE` is set),
    /// overwriting any previously set.
    pub fn mode(mut self, mode: Mode) -> Self {
        self.0.mode = mode.bits() as u64;
        self
    }

    /// Set the resolve flags, overwriting any previously set.
    pub fn resolve(mut self, resolve: ResolveFlag) -> Self {
        self.0.resolve = resolve.bits();
        self
    }

    /// The raw kernel payload (for the io_uring `OPENAT2` SQE).
    #[cfg_attr(not(feature = "async-fs"), allow(dead_code))]
    pub(crate) fn to_raw(self) -> RawOpenHow {
        self.0
    }
}

/// Open or create a file relative to `dirfd`, controlling path resolution via
/// [`OpenHow`].
///
/// See [`openat2(2)`](https://man7.org/linux/man-pages/man2/openat2.2.html).
pub fn openat2<P, Fd>(
    dirfd: Fd,
    path: &P,
    how: OpenHow,
) -> errno::Result<OwnedFd>
where
    P: ?Sized + TnPath,
    Fd: AsFd,
{
    let mut raw = how.0;
    let raw_dirfd = dirfd.as_fd().as_raw_fd();
    let fd = path.with_tn_path(|cstr| {
        retry_on_eintr(|| unsafe {
            libc::syscall(
                libc::SYS_openat2,
                raw_dirfd,
                cstr.as_ptr(),
                &mut raw as *mut RawOpenHow,
                size_of::<RawOpenHow>(),
            )
        })
    })??;
    // SAFETY: on success `openat2` returns a fresh owned file descriptor.
    Ok(unsafe { owned_from_raw(fd as RawFd) })
}
