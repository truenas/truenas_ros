//! The wake eventfd and the cross-thread loop flags it serves: the one block
//! of state shared (`Arc`) between a loop thread and every cross-thread
//! handle a domain mints (shutdown handles, deferred replies, pushes, ...).

use crate::errno;
#[cfg(not(loom))]
use crate::errno::Errno;
#[cfg(not(loom))]
use crate::fd::owned_from_raw;
// `LoopShared`'s flags are loom-modelled (`loom_graceful_publication`), so the
// atomics come from `crate::sync` - std's outside `--cfg loom`.
use crate::sync::atomic::{AtomicBool, AtomicU64};
#[cfg(not(loom))]
use std::ffi::c_void;
#[cfg(not(loom))]
use std::mem::size_of;
#[cfg(not(loom))]
use std::os::fd::{AsRawFd, OwnedFd};

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
///
/// Under `--cfg loom` the fd is replaced by a counter plus a condvar. A real
/// eventfd cannot be used in a model: `loom::model` re-runs its closure once
/// per interleaving - thousands of times - and each run would open another
/// descriptor. The stand-in reproduces the two properties the no-lost-wakeup
/// argument actually rests on: pokes **accumulate**, and a drain takes the
/// whole count at once. Anything a model proves is therefore conditional on
/// the kernel's eventfd behaving that way, which
/// [`Engine::arm_wake`](super::engine::Engine::arm_wake) documents but nothing
/// here verifies.
#[derive(Debug)]
pub(crate) struct WakeHandle {
    #[cfg(not(loom))]
    pub(crate) fd: OwnedFd,
    #[cfg(loom)]
    count: crate::sync::Mutex<u64>,
    #[cfg(loom)]
    ready: crate::sync::Condvar,
}

impl WakeHandle {
    /// A fresh wake handle (an eventfd, or the model's counter).
    pub(crate) fn new() -> errno::Result<WakeHandle> {
        #[cfg(not(loom))]
        {
            // SAFETY: eventfd() returns a fresh owned fd or -1.
            let fd = Errno::result(unsafe {
                libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK)
            })?;
            // SAFETY: fresh owned fd from eventfd().
            Ok(WakeHandle {
                fd: unsafe { owned_from_raw(fd) },
            })
        }
        #[cfg(loom)]
        {
            Ok(WakeHandle {
                count: crate::sync::Mutex::new(0),
                ready: crate::sync::Condvar::new(),
            })
        }
    }

    #[cfg(not(loom))]
    pub(crate) fn as_raw_fd(&self) -> i32 {
        self.fd.as_raw_fd()
    }

    /// The descriptor the loop arms its `READ` on. Models never reach the
    /// ring, so there is nothing to arm.
    #[cfg(loom)]
    pub(crate) fn as_raw_fd(&self) -> i32 {
        -1
    }

    pub(crate) fn poke(&self) {
        #[cfg(not(loom))]
        {
            let one: u64 = 1;
            // SAFETY: write 8 bytes from a valid u64 to the eventfd. Errors
            // are ignored: a full counter has already signalled, and a closed
            // fd means the loop is gone (so the wake is moot).
            unsafe {
                libc::write(
                    self.fd.as_raw_fd(),
                    std::ptr::addr_of!(one).cast::<c_void>(),
                    size_of::<u64>(),
                );
            }
        }
        #[cfg(loom)]
        {
            let mut n = self.count.lock().unwrap_or_else(|e| e.into_inner());
            *n += 1;
            self.ready.notify_all();
        }
    }

    /// Model-only: what the loop's armed `READ` does when it completes - block
    /// until the counter is non-zero, then drain it to 0 in one go. Returns
    /// the count consumed.
    ///
    /// This is the half of the protocol that makes a poke arriving between a
    /// drain and the next arm safe: it is still counted, so the next read
    /// completes immediately instead of parking.
    #[cfg(loom)]
    pub(crate) fn drain(&self) -> u64 {
        let mut n = self.count.lock().unwrap_or_else(|e| e.into_inner());
        while *n == 0 {
            n = self.ready.wait(n).unwrap_or_else(|e| e.into_inner());
        }
        std::mem::replace(&mut *n, 0)
    }

    /// Model-only: drain without blocking, for a loop checking whether a poke
    /// is already pending rather than parking on one.
    #[cfg(loom)]
    pub(crate) fn try_drain(&self) -> u64 {
        let mut n = self.count.lock().unwrap_or_else(|e| e.into_inner());
        std::mem::replace(&mut *n, 0)
    }
}

// ---------------------------------------------------------------------------
// loom model of the graceful-drain publication
// ---------------------------------------------------------------------------
//
// Run with:  RUSTFLAGS="--cfg loom" cargo test --lib --features uring loom_
//
// `grace_ms` is a **Relaxed** payload published by a **Release** store of
// `graceful`, and read after an **Acquire** load of it:
//
//   writer (net/server/handles.rs:510-518)   loop (net/server/wake.rs:37, :88)
//   grace_ms.store(ms, Relaxed)              if graceful.load(Acquire) {
//   graceful.store(true, Release)                grace_ms.load(Relaxed)
//   wake.poke()                              }
//
// That is message passing: the Release/Acquire pair is the only thing making
// the Relaxed payload visible. Weaken the store to Relaxed and a loop that
// sees `graceful` may still read `grace_ms == 0`, arming a zero-length grace
// period and hard-killing connections it promised to drain.
#[cfg(loom)]
mod loom_tests {
    use super::*;
    use crate::sync::Arc;
    use crate::sync::atomic::Ordering;

    const GRACE_MS: u64 = 30_000;

    fn shared() -> Arc<LoopShared> {
        Arc::new(LoopShared {
            stop: AtomicBool::new(false),
            graceful: AtomicBool::new(false),
            grace_ms: AtomicU64::new(0),
            wake: WakeHandle::new().expect("the model's wake never fails"),
        })
    }

    /// Observing `graceful` must imply observing the grace period it was
    /// published with - including against a racing hard `shutdown()`, which
    /// writes a different flag through the same shared block.
    #[test]
    fn loom_graceful_publication() {
        loom::model(|| {
            let s = shared();

            let w = Arc::clone(&s);
            let drain = loom::thread::spawn(move || {
                w.grace_ms.store(GRACE_MS, Ordering::Relaxed);
                w.graceful.store(true, Ordering::Release);
                w.wake.poke();
            });

            let h = Arc::clone(&s);
            let hard = loom::thread::spawn(move || {
                h.stop.store(true, Ordering::Release);
                h.wake.poke();
            });

            // The loop's half. Reading `graceful` as set is a promise that the
            // period behind it is readable too.
            if s.graceful.load(Ordering::Acquire) {
                assert_eq!(
                    s.grace_ms.load(Ordering::Relaxed),
                    GRACE_MS,
                    "graceful became visible before its grace period"
                );
            }

            drain.join().expect("drain writer");
            hard.join().expect("hard writer");

            // Both requests landed; neither writer lost to the other.
            assert!(s.graceful.load(Ordering::Acquire), "drain request lost");
            assert!(s.stop.load(Ordering::Acquire), "hard stop lost");
            assert_eq!(s.grace_ms.load(Ordering::Relaxed), GRACE_MS);
        });
    }

    /// Pokes accumulate rather than coalescing to a single edge, and a drain
    /// takes the whole count. This is the eventfd property the "no poke is
    /// lost" argument rests on - modelled here, assumed of the kernel.
    #[test]
    fn loom_wake_pokes_accumulate() {
        loom::model(|| {
            let s = shared();
            let a = Arc::clone(&s);
            let poker = loom::thread::spawn(move || a.wake.poke());
            s.wake.poke();
            poker.join().expect("poker");
            assert_eq!(
                s.wake.try_drain(),
                2,
                "a concurrent poke was coalesced away"
            );
            assert_eq!(s.wake.try_drain(), 0, "drain did not clear the count");
        });
    }
}
