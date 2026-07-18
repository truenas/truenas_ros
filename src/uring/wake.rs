//! The wake eventfd and the cross-thread loop flags it serves: the one block
//! of state shared (`Arc`) between a loop thread and every cross-thread
//! handle a domain mints (shutdown handles, deferred replies, pushes, …).

use crate::errno::{self, Errno};
use crate::fd::owned_from_raw;
use std::ffi::c_void;
use std::mem::size_of;
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, AtomicU64};

/// The stop/graceful-drain flags and the wake eventfd cross-thread pokes ride
/// on. Domains wrap it in their own public handles; the engine arms the
/// eventfd `READ` ([`super::engine::Engine::arm_wake`]).
#[derive(Debug)]
pub(crate) struct LoopShared {
    /// Hard-stop flag (`Release` store, `Acquire` load in the loop).
    pub(crate) stop: AtomicBool,
    /// Graceful-drain request flag; `grace_ms` is read when it is seen.
    pub(crate) graceful: AtomicBool,
    pub(crate) grace_ms: AtomicU64,
    pub(crate) wake: WakeHandle,
}

/// The wake eventfd. Poking it adds 1 to the counter, completing the loop's
/// armed `READ` so it drains pending work.
#[derive(Debug)]
pub(crate) struct WakeHandle {
    pub(crate) fd: OwnedFd,
}

impl WakeHandle {
    pub(crate) fn as_raw_fd(&self) -> i32 {
        self.fd.as_raw_fd()
    }

    pub(crate) fn poke(&self) {
        let one: u64 = 1;
        // SAFETY: write 8 bytes from a valid u64 to the eventfd. Errors are
        // ignored: a full counter has already signalled, and a closed fd means
        // the loop is gone (so the wake is moot).
        unsafe {
            libc::write(
                self.fd.as_raw_fd(),
                std::ptr::addr_of!(one).cast::<c_void>(),
                size_of::<u64>(),
            );
        }
    }
}

pub(crate) fn create_eventfd() -> errno::Result<OwnedFd> {
    // SAFETY: eventfd() returns a fresh owned fd or -1.
    let fd = Errno::result(unsafe {
        libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK)
    })?;
    // SAFETY: fresh owned fd from eventfd().
    Ok(unsafe { owned_from_raw(fd) })
}
