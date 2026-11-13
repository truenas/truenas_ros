//! Synchronization primitives: `std` in production, `loom`'s under `--cfg loom`.
//!
//! Under `cfg(not(loom))` every item here is a plain re-export, so this module costs nothing outside a model run.
//! Under `--cfg loom` the same names resolve to loom's permutation-checking versions, which lets [`loom::model`]
//! explore every interleaving a protocol admits. `UnsafeCell` is not covered here, and `src/uring/ring.rs` swaps it
//! per field.
//!
//! Three things loom does not provide, and how the crate copes:
//!
//! * **`OnceLock`.** There is no loom equivalent, and no `Mutex<Option<T>>` can hand out the `&T` that
//!   `OnceLock::get` returns. [`OnceCell`] therefore exposes a closure-taking [`with`](OnceCell::with) instead, which
//!   both builds can implement. Production still holds a real `OnceLock` behind it, so the fast path is one acquire
//!   load.
//! * **Timeouts.** `loom::sync::Condvar::wait_timeout` never reports a timeout - it delegates to `wait` and hardcodes
//!   `timed_out() == false`. Any branch predicated on a timeout is unreachable in a model and needs an explicit seam;
//!   the offload pool's idle-retire path has one.
//! * **Clocks.** `Instant` is not modelled. Code that throttles on elapsed time is exercised with the interval set to
//!   zero.
//!
//! Models are also capped at [`loom::MAX_THREADS`] (5, including the main thread), which is why every model in this
//! crate is deliberately tiny.

// `atomic` and `Arc` serve both engines, and the rest mostly the fs reactor's. Gating each name on the exact features
// costs more than it says, so the unused ones are allowed through instead.
#[cfg_attr(not(feature = "uring-fs"), allow(unused_imports))]
#[cfg(loom)]
pub(crate) use loom::{
    sync::{Arc, Condvar, Mutex, atomic, mpsc},
    thread,
};
#[cfg_attr(not(feature = "uring-fs"), allow(unused_imports))]
#[cfg(not(loom))]
pub(crate) use std::{
    sync::{Arc, Condvar, Mutex, atomic, mpsc},
    thread,
};

/// A write-once cell: [`std::sync::OnceLock`] in production, a mutex-backed stand-in under loom.
///
/// [`with`](Self::with) runs a closure against a borrow rather than returning one, because a `Mutex<Option<T>>` cannot
/// produce a `&T` that outlives its guard.
#[cfg_attr(not(feature = "uring-fs"), allow(dead_code))]
#[derive(Debug)]
pub(crate) struct OnceCell<T> {
    #[cfg(not(loom))]
    inner: std::sync::OnceLock<T>,
    #[cfg(loom)]
    inner: Mutex<Option<T>>,
}

#[cfg_attr(not(feature = "uring-fs"), allow(dead_code))]
impl<T> OnceCell<T> {
    /// An empty cell.
    pub(crate) fn new() -> OnceCell<T> {
        OnceCell {
            #[cfg(not(loom))]
            inner: std::sync::OnceLock::new(),
            #[cfg(loom)]
            inner: Mutex::new(None),
        }
    }

    /// Install `value` unless the cell is already full. Returns whether this call was the one that filled it.
    pub(crate) fn set(&self, value: T) -> bool {
        #[cfg(not(loom))]
        {
            self.inner.set(value).is_ok()
        }
        #[cfg(loom)]
        {
            let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            if g.is_some() {
                return false;
            }
            *g = Some(value);
            true
        }
    }

    /// Run `f` against the contents, or return `None` if still empty.
    ///
    /// Under loom the cell's lock is held for the duration of `f`, a coarser interleaving than production. The
    /// lazy-init models explore the race to fill the cell, and concurrency through a filled one is modelled on the
    /// inner type.
    pub(crate) fn with<R>(&self, f: impl FnOnce(&T) -> R) -> Option<R> {
        #[cfg(not(loom))]
        {
            self.inner.get().map(f)
        }
        #[cfg(loom)]
        {
            let g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            g.as_ref().map(f)
        }
    }

    /// True once the cell has been filled.
    pub(crate) fn is_set(&self) -> bool {
        self.with(|_| ()).is_some()
    }
}
