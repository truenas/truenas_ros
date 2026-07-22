//! `clone3(2)` fork helper shared by the credential broker
//! ([`crate::async_fs`]) and the idmapped-mount user-namespace builder
//! ([`crate::mount`]).
//!
//! Both fork a child *without* `CLONE_VM` — a plain copy-on-write
//! address-space copy, like `fork` — but need two things `libc::fork` cannot
//! give:
//!
//! - **`CLONE_PIDFD`** — a pidfd for the child, written atomically at
//!   creation (no `fork`-then-`pidfd_open` reuse race), for race-free
//!   wait/signal.
//! - **`CLONE_CLEAR_SIGHAND`** — the child's inherited signal handlers reset
//!   to `SIG_DFL`. For a **fork-without-exec** child this is load-bearing,
//!   not a nicety: otherwise a signal delivered to the child runs the
//!   *parent's* handler code inside the child. In the credential broker that
//!   handler could fire inside the impersonation window — executing parent
//!   code at the impersonated identity — so clearing handlers is a soundness
//!   requirement.
//!
//! **This does not relax the fork-before-threads rule; it sharpens it.** A
//! raw `clone3` bypasses glibc's `atfork` handlers (including malloc's arena
//! lock/unlock), so the single-threaded-at-fork precondition is strictly
//! load-bearing with no safety net. A caller whose child allocates (the
//! broker) relies on it entirely; a caller whose child is async-signal-safe
//! only (the userns builder's `pause()` loop) does not.

use crate::errno::{self, Errno};
use std::os::fd::RawFd;

/// `clone3` flag: the child enters a new user namespace (idmap only; the
/// broker forks with no extra flags).
#[cfg_attr(not(feature = "idmap"), allow(dead_code))]
pub(crate) const CLONE_NEWUSER: u64 = 0x1000_0000;
/// `clone3` flag: place a pidfd for the child in `clone_args.pidfd`.
const CLONE_PIDFD: u64 = 0x0000_1000;
/// `clone3` flag: reset the child's signal handlers to `SIG_DFL` (Linux
/// ≥ 5.5). `libc` does not expose it.
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

/// Fork via `clone3`, always with `CLONE_PIDFD | CLONE_CLEAR_SIGHAND` plus
/// `extra_flags`, using `exit_signal` (0 = send **no** signal to the parent
/// on child exit — the parent learns of death through the pidfd instead).
///
/// Writes the child's pidfd to `*pidfd_out`, and returns `0` in the child /
/// the child pid in the parent (exactly like `fork`).
///
/// # Safety
///
/// Same contract as `fork`: the calling process **must be single-threaded**.
/// A `clone3` without `CLONE_VM` shares fork's malloc-arena hazard and, being
/// a raw syscall, has none of glibc's `atfork` mitigation, so a lock held by
/// another thread at call time deadlocks the child. The child must run only
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
    // SAFETY: `clone3` reads a valid, correctly-sized `clone_args`; the
    // `CLONE_PIDFD` store targets `pidfd_out`, a valid writable `RawFd`.
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

    extern "C" fn dummy_handler(_sig: libc::c_int) {}

    /// `CLONE_CLEAR_SIGHAND` must reset the child's inherited signal handlers
    /// to `SIG_DFL`. This is the soundness property the credential broker
    /// relies on: a signal must never run the *parent's* handler inside the
    /// forked child, which in the broker would execute at the impersonated
    /// identity. The child queries its own `SIGUSR2` disposition and exits 0
    /// iff it is `SIG_DFL` (i.e. the parent's handler did not survive).
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
        // SAFETY: the child does ONLY async-signal-safe work (a sigaction
        // query + `_exit`), so forking from the multi-threaded test harness
        // cannot hit the malloc-arena hazard (same as the idmap userns tests).
        let pid = unsafe { clone3_fork(0, libc::SIGCHLD as u64, &mut pidfd) }
            .expect("clone3_fork");
        if pid == 0 {
            let mut cur: libc::sigaction = unsafe { std::mem::zeroed() };
            let q = unsafe {
                libc::sigaction(libc::SIGUSR2, std::ptr::null(), &mut cur)
            };
            let cleared = q == 0 && cur.sa_sigaction == libc::SIG_DFL;
            // SAFETY: async-signal-safe process exit in the child.
            unsafe { libc::_exit(if cleared { 0 } else { 1 }) };
        }

        let mut status = 0;
        loop {
            let r = unsafe { libc::waitpid(pid, &mut status, 0) };
            if r >= 0 || Errno::last() != Errno::EINTR {
                break;
            }
        }
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
