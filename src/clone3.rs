//! `clone3(2)` fork helper shared by the credential broker ([`crate::uring_fs`]) and the idmapped-mount user-namespace
//! builder ([`crate::mount`]).
//!
//! Both fork a child without `CLONE_VM`, like `fork`, but need two things `libc::fork` cannot give.
//!
//! - **`CLONE_PIDFD`** - a pidfd for the child, written atomically at creation (no `fork`-then-`pidfd_open` reuse
//!   race), for race-free wait/signal.
//! - **`CLONE_CLEAR_SIGHAND`** - the child's inherited signal handlers reset to `SIG_DFL`. A fork-without-exec child
//!   would otherwise run the parent's handler code, and in the credential broker that could happen inside the
//!   impersonation window, at the impersonated identity.
//!
//! A raw `clone3` bypasses glibc's `atfork` handlers, malloc's arena locks included, so a child that allocates (the
//! broker) relies entirely on the caller being single-threaded at fork. A child that is async-signal-safe only (the
//! userns builder's `pause()` loop) does not.

use crate::errno::{self, Errno};
use std::os::fd::RawFd;

/// `clone3` flag: the child enters a new user namespace (idmap only; the broker forks with no extra flags).
#[cfg_attr(not(feature = "idmap"), allow(dead_code))]
pub(crate) const CLONE_NEWUSER: u64 = 0x1000_0000;
/// `clone3` flag: place a pidfd for the child in `clone_args.pidfd`.
const CLONE_PIDFD: u64 = 0x0000_1000;
/// `clone3` flag: reset the child's signal handlers to `SIG_DFL` (Linux >= 5.5). `libc` does not expose it.
const CLONE_CLEAR_SIGHAND: u64 = 0x1_0000_0000;

/// Kernel `struct clone_args` (VER2, 88 bytes).
#[repr(C)]
#[derive(Default)]
struct CloneArgs {
    flags: u64,
    pidfd: u64,
    child_tid: u64,
    parent_tid: u64,
    exit_signal: u64,
    stack: u64,
    stack_size: u64,
    tls: u64,
    set_tid: u64,
    set_tid_size: u64,
    cgroup: u64,
}
const _: () = assert!(core::mem::size_of::<CloneArgs>() == 88);

/// Fork via `clone3`, always with `CLONE_PIDFD | CLONE_CLEAR_SIGHAND` plus `extra_flags`, using `exit_signal` (0 = send
/// **no** signal to the parent on child exit - the parent learns of death through the pidfd instead).
///
/// Writes the child's pidfd to `*pidfd_out`, and returns `0` in the child / the child pid in the parent (exactly like
/// `fork`).
///
/// # Safety
///
/// The contract is `fork`'s, so the calling process **must be single-threaded**. A raw `clone3` has none of glibc's
/// `atfork` mitigation, so a lock held by another thread at call time deadlocks the child. The child must run only
/// async-signal-safe work unless that precondition holds.
pub(crate) unsafe fn clone3_fork(
    extra_flags: u64,
    exit_signal: u64,
    pidfd_out: &mut RawFd,
) -> errno::Result<libc::pid_t> {
    let mut ca = CloneArgs {
        flags: CLONE_PIDFD | CLONE_CLEAR_SIGHAND | extra_flags,
        pidfd: pidfd_out as *mut RawFd as u64,
        exit_signal,
        ..Default::default()
    };
    // SAFETY: `clone3` reads a valid, correctly-sized `clone_args`; the `CLONE_PIDFD` store targets `pidfd_out`, a
    // valid writable `RawFd`.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_clone3,
            &mut ca as *mut CloneArgs,
            core::mem::size_of::<CloneArgs>(),
        )
    };
    if ret < 0 {
        return Err(Errno::last());
    }
    Ok(ret as libc::pid_t)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errno::retry_on_eintr;

    extern "C" fn dummy_handler(_sig: libc::c_int) {}

    /// `CLONE_CLEAR_SIGHAND` resets the child's inherited signal handlers to `SIG_DFL`, so a parent handler never runs
    /// inside the broker's child. The child exits 0 iff its own `SIGUSR2` disposition is `SIG_DFL`.
    #[test]
    fn clears_inherited_signal_handlers() {
        // Install a real handler in the parent for a normally-unused signal.
        // SAFETY: zeroed sigaction is valid; sa_sigaction set to our handler.
        let mut sa: libc::sigaction = unsafe { std::mem::zeroed() };
        sa.sa_sigaction = dummy_handler as *const () as usize;
        let mut old: libc::sigaction = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::sigaction(libc::SIGUSR2, &sa, &mut old) },
            0,
            "install parent handler"
        );

        let mut pidfd: RawFd = -1;
        // SAFETY: the child does only async-signal-safe work (a sigaction query and `_exit`), so forking from the
        // multi-threaded test harness cannot hit the malloc-arena hazard.
        let pid = unsafe { clone3_fork(0, libc::SIGCHLD as u64, &mut pidfd) }.expect("clone3_fork");
        if pid == 0 {
            let mut cur: libc::sigaction = unsafe { std::mem::zeroed() };
            let q = unsafe { libc::sigaction(libc::SIGUSR2, std::ptr::null(), &mut cur) };
            let cleared = q == 0 && cur.sa_sigaction == libc::SIG_DFL;
            // SAFETY: async-signal-safe process exit in the child.
            unsafe { libc::_exit(if cleared { 0 } else { 1 }) };
        }

        let mut status = 0;
        // SAFETY: waitpid on our own child, writing through a live local.
        let _ = retry_on_eintr(|| unsafe { libc::waitpid(pid, &mut status, 0) });
        // Restore the parent's original disposition and close the pidfd.
        // SAFETY: restoring the saved sigaction; closing our owned pidfd.
        unsafe {
            libc::sigaction(libc::SIGUSR2, &old, std::ptr::null_mut());
            libc::close(pidfd);
        }
        assert!(
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
            "child must see SIG_DFL for SIGUSR2 (handlers cleared), \
             status={status}"
        );
    }
}
