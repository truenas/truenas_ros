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

/// Raise this process's soft `RLIMIT_NOFILE` to its hard limit and give back
/// the limit now in force, for a server that keeps many files open.
///
/// A soft limit left low answers `EMFILE` to every open in the process once
/// it is reached (`alloc_fd` in `fs/file.c`), and a service starts with one
/// of 1024 under systemd's default. It stays that low for `select(2)`, whose
/// `fd_set` holds no higher number, so a process that raises it must never
/// hand `select` a descriptor. Soft up to hard needs no privilege
/// (`do_prlimit` in `kernel/sys.c`). A hard limit is the service manager's
/// to set, and this leaves it alone.
pub fn raise_nofile_limit() -> crate::errno::Result<u64> {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `limit` is a valid out-pointer for the call.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 {
        return Err(crate::errno::Errno::last());
    }
    if limit.rlim_cur < limit.rlim_max {
        limit.rlim_cur = limit.rlim_max;
        // SAFETY: a valid rlimit, which the call only reads.
        if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) } != 0 {
            return Err(crate::errno::Errno::last());
        }
    }
    Ok(limit.rlim_cur)
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Run `check` in a forked child, whose limits and descriptors are its
    /// own, since a binary's tests share one process, and pass if it does.
    /// The child makes system calls alone before it exits.
    fn in_a_child(check: fn() -> bool) -> bool {
        // SAFETY: the child runs `check`, which allocates nothing, and leaves
        // through `_exit`.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            let passed = check();
            // SAFETY: async-signal-safe exit with the verdict as the status.
            unsafe { libc::_exit(i32::from(!passed)) };
        }
        let mut status = 0;
        // SAFETY: `status` is a valid out-pointer and `pid` is our child.
        unsafe { libc::waitpid(pid, &mut status, 0) };
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
    }

    /// The limits in force, soft then hard, or zeros should the call fail,
    /// which no check below takes for a limit.
    fn limits() -> (u64, u64) {
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: `limit` is a valid out-pointer for the call.
        unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) };
        (limit.rlim_cur, limit.rlim_max)
    }

    /// Lower the limits to `soft` and `hard`.
    fn set_limits(soft: u64, hard: u64) -> bool {
        let limit = libc::rlimit {
            rlim_cur: soft,
            rlim_max: hard,
        };
        // SAFETY: a valid rlimit, which the call only reads.
        unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) == 0 }
    }

    /// Whether a new descriptor can take the number `at` or above, which
    /// the limit in force decides (`f_dupfd` in `fs/file.c`).
    fn takes_a_number_from(at: i32) -> bool {
        // SAFETY: a valid NUL-ended path.
        let dir = unsafe { libc::open(c".".as_ptr(), libc::O_RDONLY) };
        // SAFETY: `F_DUPFD_CLOEXEC` reads no memory. A failed open above
        // gives `EBADF`, which fails the check.
        unsafe { libc::fcntl(dir, libc::F_DUPFD_CLOEXEC, at) >= at }
    }

    #[test]
    fn the_soft_limit_rises_to_the_hard_limit() {
        assert!(in_a_child(|| {
            let (_, hard) = limits();
            let hard = hard.min(4096);
            set_limits(64, hard)
                && !takes_a_number_from(100)
                && raise_nofile_limit() == Ok(hard)
                && limits() == (hard, hard)
                && takes_a_number_from(100)
        }));
    }

    #[test]
    fn a_soft_limit_at_the_hard_limit_stays_there() {
        assert!(in_a_child(|| {
            set_limits(64, 64)
                && raise_nofile_limit() == Ok(64)
                && limits() == (64, 64)
        }));
    }
}
