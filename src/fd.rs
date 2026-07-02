//! File-descriptor helpers shared across the crate.

use std::os::fd::{BorrowedFd, FromRawFd, OwnedFd, RawFd};

/// A [`BorrowedFd`] referring to the current working directory, for use with
/// the `*at` family of syscalls (the `AT_FDCWD` sentinel).
///
/// Passing this through the same `AsFd` bound as a real directory fd keeps the
/// `*at` wrappers uniform instead of special-casing a magic integer.
pub const AT_FDCWD: BorrowedFd<'static> =
    // SAFETY: `AT_FDCWD` is a sentinel the kernel never treats as a real fd; it
    // is never closed, so a `'static` borrow is sound.
    unsafe { BorrowedFd::borrow_raw(libc::AT_FDCWD) };

/// Wraps a raw fd returned by a syscall into an [`OwnedFd`].
///
/// # Safety
///
/// `fd` must be a valid, freshly-created owned file descriptor (i.e. the caller
/// owns it and it is not owned elsewhere).
#[inline]
#[allow(dead_code)] // unused only when no feature module is compiled
pub(crate) unsafe fn owned_from_raw(fd: RawFd) -> OwnedFd {
    // SAFETY: guaranteed by the caller.
    unsafe { OwnedFd::from_raw_fd(fd) }
}
