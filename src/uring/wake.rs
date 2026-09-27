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
use crate::sync::atomic::{AtomicBool, AtomicU64, Ordering};
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

impl LoopShared {
    /// Request a hard stop.
    ///
    /// A function, and one spelling of the ordering, so a model drives *this*
    /// store rather than its own copy of the pairing - a model with its own
    /// copy checks the memory model rather than the code, and stays green
    /// with the shipping ordering weakened (`bufring::publish_tail` states
    /// the same rule).
    #[inline]
    pub(crate) fn request_stop(&self) {
        self.stop.store(true, Ordering::Release);
    }

    /// Whether a hard stop was requested. Paired with
    /// [`request_stop`](Self::request_stop).
    #[inline]
    pub(crate) fn stop_requested(&self) -> bool {
        self.stop.load(Ordering::Acquire)
    }

    /// Request a graceful drain of `grace_ms`: the period first, then the
    /// flag whose **Release** store is what makes it readable.
    ///
    /// `grace_ms` is a Relaxed payload published by this pair - message
    /// passing, and the Release/Acquire is the only thing making it visible.
    /// Weaken the store and a loop that sees `graceful` may still read
    /// `grace_ms == 0`, arming a zero-length grace period and hard-killing
    /// connections it promised to drain.
    ///
    /// **The loom lane owns this edge** (`loom_graceful_publication`):
    /// this module's concurrency tests compile only under `--cfg loom`,
    /// so Miri interprets nothing that crosses it and every Miri arm
    /// stays green with the store weakened - measured, against loom
    /// going red in seconds. The mirror-image edge is the wake dedup's
    /// (`task::poll_window`), which only Miri catches; retire either
    /// lane and its edge goes unwatched.
    #[inline]
    pub(crate) fn request_graceful(&self, grace_ms: u64) {
        self.grace_ms.store(grace_ms, Ordering::Relaxed);
        self.graceful.store(true, Ordering::Release);
    }

    /// The paired read: the grace period once a drain has been requested.
    #[inline]
    pub(crate) fn graceful_requested(&self) -> Option<u64> {
        self.graceful
            .load(Ordering::Acquire)
            .then(|| self.grace_ms.load(Ordering::Relaxed))
    }
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
    /// Whether the loop is asleep in `io_uring_enter`, as tokio's `Parker`
    /// tracks it.
    ///
    /// A poke writes the eventfd only when the loop is [`PARKED`]. An
    /// [`ACTIVE`] loop drains every wake source before it parks
    /// ([`Self::park`]), so a poke that only sets [`NOTIFIED`] is seen
    /// there, without the syscall and the completion.
    ///
    /// Opt-in per loop: a handle starts [`LEGACY`], where every poke
    /// writes, because a site that blocks without calling [`Self::park`]
    /// (the ring tests, the teardown drain) would sleep through a skipped
    /// write. A loop opts in with [`Self::activate`].
    state: AtomicU64,
}

/// No loop has claimed the protocol: every poke writes.
const LEGACY: u64 = 0;
/// The loop is running, or between two waits, and will drain before
/// it blocks.
const ACTIVE: u64 = 1;
/// The loop is about to block, or is blocked, in `io_uring_enter`.
const PARKED: u64 = 2;
/// A poke landed; the loop must drain before it may block.
const NOTIFIED: u64 = 3;

/// What [`WakeHandle::park`] tells the loop to do.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Park {
    /// Block; the eventfd is armed and a poke will write it.
    Block,
    /// A poke landed since the last drain: drain instead of blocking.
    Drain,
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
                state: AtomicU64::new(LEGACY),
            })
        }
        #[cfg(loom)]
        {
            Ok(WakeHandle {
                count: crate::sync::Mutex::new(0),
                ready: crate::sync::Condvar::new(),
                state: AtomicU64::new(LEGACY),
            })
        }
    }

    /// Opt in: the calling loop blocks on this handle's ring and drains
    /// every wake source before it blocks. Called once, after the wake
    /// `READ` is armed.
    pub(crate) fn activate(&self) {
        // `LEGACY -> ACTIVE` only. A plain store could overwrite
        // `NOTIFIED`, which a poke sets instead of writing the eventfd, and
        // the loop would park with that wake lost.
        let _ = self.state.compare_exchange(
            LEGACY,
            ACTIVE,
            Ordering::Release,
            Ordering::Relaxed,
        );
    }

    /// Called by the loop right before it blocks, after it has drained
    /// every wake source.
    ///
    /// `ACTIVE -> PARKED`: from here a poke writes the eventfd. `NOTIFIED`
    /// means a poke landed since the drain without writing, so the loop
    /// drains again instead of blocking. The check and the transition are
    /// one compare-exchange, so no poke falls between them. A [`LEGACY`]
    /// handle always blocks; every poke to it writes.
    pub(crate) fn park(&self) -> Park {
        match self.state.compare_exchange(
            ACTIVE,
            PARKED,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) | Err(LEGACY) => Park::Block,
            Err(seen) => {
                // `NOTIFIED`: a poke landed while the loop was awake.
                // `PARKED` would be a second park without an `unpark`,
                // which both callers rule out; `Drain` is safe either way.
                debug_assert_ne!(
                    seen, PARKED,
                    "park() re-entered without an unpark"
                );
                self.state.store(ACTIVE, Ordering::Release);
                Park::Drain
            }
        }
    }

    /// The loop is awake again. A poke that arrived while it was parked
    /// wrote the eventfd, and the armed `READ` completes for it.
    pub(crate) fn unpark(&self) {
        if self.state.load(Ordering::Acquire) != LEGACY {
            self.state.store(ACTIVE, Ordering::Release);
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
        // Release: the pusher's item is visible to the loop that reads this
        // state. A `LEGACY` handle is always written.
        let mut cur = self.state.load(Ordering::Acquire);
        loop {
            match cur {
                LEGACY => break,
                NOTIFIED => return,
                _ => {}
            }
            match self.state.compare_exchange_weak(
                cur,
                NOTIFIED,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                // Awake: the loop drains before it blocks, so skip the
                // write.
                Ok(ACTIVE) => return,
                Ok(_) => break,
                Err(seen) => cur = seen,
            }
        }
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
//   writer (`ShutdownHandle::shutdown_graceful`)   loop (`Server::on_wake`)
//   LoopShared::request_graceful(ms)              LoopShared::graceful_requested()
//   wake.poke()
//
// That is message passing: the Release/Acquire pair is the only thing making
// the Relaxed payload visible. Weaken the store to Relaxed and a loop that
// sees `graceful` may still read `grace_ms == 0`, arming a zero-length grace
// period and hard-killing connections it promised to drain.
//
// The model calls those two functions rather than re-spelling their stores,
// which is what makes it a test of the code instead of a test of loom.
#[cfg(all(test, loom))]
mod loom_tests {
    use super::*;
    use crate::sync::Arc;

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
                w.request_graceful(GRACE_MS);
                w.wake.poke();
            });

            let h = Arc::clone(&s);
            let hard = loom::thread::spawn(move || {
                h.request_stop();
                h.wake.poke();
            });

            // The loop's half. Reading `graceful` as set is a promise that the
            // period behind it is readable too.
            if let Some(ms) = s.graceful_requested() {
                assert_eq!(
                    ms, GRACE_MS,
                    "graceful became visible before its grace period"
                );
            }

            drain.join().expect("drain writer");
            hard.join().expect("hard writer");

            // Both requests landed; neither writer lost to the other.
            assert_eq!(
                s.graceful_requested(),
                Some(GRACE_MS),
                "drain request lost"
            );
            assert!(s.stop_requested(), "hard stop lost");
        });
    }

    /// A poke that skips the eventfd write still reaches the loop, by a
    /// `Drain` verdict or an eventfd count, in every interleaving. The loop
    /// never blocks with a poke unseen.
    ///
    /// The item is checked only where `state` carries it (`poke`'s CAS
    /// releases, `park`'s failed CAS acquires). Production wake sources
    /// have their own locks, so this models the verdict, not the payload.
    #[test]
    fn loom_an_activated_poke_is_never_lost() {
        loom::model(|| {
            let s = shared();
            s.wake.activate();
            let item = Arc::new(AtomicBool::new(false));

            let (p, it) = (Arc::clone(&s), Arc::clone(&item));
            let poker = loom::thread::spawn(move || {
                it.store(true, Ordering::Release);
                p.wake.poke();
            });

            // The loop's half: decide whether to block, then wake again.
            let verdict = s.wake.park();
            let armed = s.wake.try_drain() > 0;
            let told_now = matches!(verdict, Park::Drain) || armed;
            let item_then = item.load(Ordering::Acquire);
            s.wake.unpark();

            poker.join().expect("poker");

            if told_now {
                assert!(
                    item_then,
                    "the loop was told of a poke whose item was not yet \
                     visible"
                );
            }
            // The poke has certainly happened now. Either the loop already
            // knew, or the next park must refuse to block.
            let told = told_now
                || s.wake.try_drain() > 0
                || matches!(s.wake.park(), Park::Drain);
            assert!(told, "a poke left no trace for the loop to find");
        });
    }

    /// A poke that finds the loop awake writes nothing, and the next park
    /// refuses to block.
    #[test]
    fn loom_a_poke_taken_while_awake_refuses_the_next_park() {
        loom::model(|| {
            let s = shared();
            s.wake.activate();

            let p = Arc::clone(&s);
            let poker = loom::thread::spawn(move || p.wake.poke());
            poker.join().expect("poker");

            assert_eq!(
                s.wake.try_drain(),
                0,
                "a poke to an awake loop wrote the eventfd after all"
            );
            assert_eq!(
                s.wake.park(),
                Park::Drain,
                "the loop parked with a poke outstanding"
            );
        });
    }

    /// A second `activate` does not overwrite a pending `NOTIFIED`. No
    /// caller activates twice today; this keeps it safe if one does.
    #[test]
    fn loom_activate_does_not_clobber_a_pending_poke() {
        loom::model(|| {
            let s = shared();
            s.wake.activate();

            let p = Arc::clone(&s);
            let poker = loom::thread::spawn(move || p.wake.poke());
            poker.join().expect("poker");

            // The poke wrote nothing, so `state` is its only record.
            assert_eq!(
                s.wake.try_drain(),
                0,
                "a poke to an awake loop wrote the eventfd after all"
            );
            // The activating caller tries again after a failed arming step.
            s.wake.activate();
            assert_eq!(
                s.wake.park(),
                Park::Drain,
                "re-activating lost a poke that had already landed"
            );
        });
    }

    /// Two pokes and one park: the second poke finds `NOTIFIED` and does
    /// nothing, which is safe only while the first poke's trace remains.
    #[test]
    fn loom_two_pokes_racing_one_park_leave_a_trace() {
        loom::model(|| {
            let s = shared();
            s.wake.activate();

            let a = Arc::clone(&s);
            let other = loom::thread::spawn(move || a.wake.poke());
            s.wake.poke();

            let verdict = s.wake.park();
            let armed = s.wake.try_drain() > 0;
            s.wake.unpark();
            other.join().expect("poker");

            let told = matches!(verdict, Park::Drain)
                || armed
                || s.wake.try_drain() > 0
                || matches!(s.wake.park(), Park::Drain);
            assert!(told, "two pokes and the loop could still block");
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
