//! File-descriptor helpers shared across the crate.

use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};

/// A [`BorrowedFd`] referring to the current working directory, for use with
/// the `*at` family of syscalls (the `AT_FDCWD` sentinel).
///
/// Passing this through the same `AsFd` bound as a real directory fd keeps the
/// `*at` wrappers uniform instead of special-casing a magic integer.
pub const AT_FDCWD: BorrowedFd<'static> =
    // SAFETY: `AT_FDCWD` is a sentinel the kernel never treats as a real fd; it
    // is never closed, so a `'static` borrow is sound.
    unsafe { BorrowedFd::borrow_raw(libc::AT_FDCWD) };

/// Duplicate `fd` into an owned, close-on-exec descriptor.
///
/// The dup aliases the same open file description, so socket state read
/// through it (`getsockopt`) is the socket's regardless of what the
/// original number is later reused for - which is why a handle that must
/// outlive a caller-owned fd carries its own dup rather than the number.
///
/// **The errno is the answer, not a bool.** Every failure here is
/// `EMFILE` or `ENFILE` in practice, and a caller that swallows it has to
/// invent one: `net::client::tls` reported `ECONNABORTED` for a process
/// out of descriptors, telling the consumer the peer had gone.
#[allow(dead_code)] // unused only when no feature module is compiled
pub(crate) fn dup_cloexec(fd: BorrowedFd<'_>) -> crate::errno::Result<OwnedFd> {
    // SAFETY: `F_DUPFD_CLOEXEC` allocates a fresh descriptor >= 0; it
    // reads no memory.
    let dup = crate::errno::retry_on_eintr(|| unsafe {
        libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0)
    })?;
    // SAFETY: `dup` is fresh and owned by nobody else.
    Ok(unsafe { owned_from_raw(dup) })
}

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
