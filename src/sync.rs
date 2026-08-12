//! Synchronization primitives: `std` in production, `loom`'s under
//! `--cfg loom`.
//!
//! Under `cfg(not(loom))` every item here is a plain re-export, so the
//! compiled artifact is byte-for-byte what importing `std::sync` directly
//! would produce — this module costs nothing outside a model run. Under
//! `--cfg loom` the same names resolve to loom's permutation-checking
//! versions, which is what lets [`loom::model`] explore every interleaving a
//! protocol admits. See `src/uring/ring.rs` for the older, per-field form of
//! the same trick (it also swaps `UnsafeCell`, which this module does not
//! cover).
//!
//! Three things loom does not provide, and how the crate copes:
//!
//! * **`OnceLock`.** There is no loom equivalent (only `lazy_static`, which is
//!   for statics), and no `Mutex<Option<T>>` can hand out the `&T` that
//!   `OnceLock::get` returns. [`OnceCell`] therefore exposes a closure-taking
//!   [`with`](OnceCell::with) instead, which both builds can implement;
//!   production still holds a real `OnceLock` behind it, so the fast path is
//!   the same single acquire load it always was. Only the offload pool's lazy
//!   init uses this — the broker's `IdSlot` keeps its plain `OnceLock`,
//!   because minting an identity means IPC to a forked child and so cannot be
//!   modelled anyway.
//! * **Timeouts.** `loom::sync::Condvar::wait_timeout` never reports a
//!   timeout — it delegates to `wait` and hardcodes `timed_out() == false`.
//!   Any branch predicated on a timeout is unreachable in a model and needs an
//!   explicit seam; the offload pool's idle-retire path has one.
//! * **Clocks.** `Instant` is not modelled. Code that throttles on elapsed
//!   time is exercised with the interval set to zero.
//!
//! Models are also capped at [`loom::MAX_THREADS`] (5, including the main
//! thread), which is why every model in this crate is deliberately tiny.

#[cfg(loom)]
pub(crate) use loom::sync::{atomic, mpsc, Arc, Condvar, Mutex};
#[cfg(loom)]
pub(crate) use loom::thread;

#[cfg(not(loom))]
pub(crate) use std::sync::{atomic, mpsc, Arc, Condvar, Mutex};
#[cfg(not(loom))]
pub(crate) use std::thread;

/// A write-once cell: [`std::sync::OnceLock`] in production, a mutex-backed
/// stand-in under loom.
///
/// The API is deliberately narrower than `OnceLock`'s — [`get`](Self::get)
/// clones out rather than borrowing, and [`with`](Self::with) runs a closure
/// against a borrow — because a `Mutex<Option<T>>` cannot produce a `&T` that
/// outlives its guard. Both callers already wanted one of those two shapes.
#[derive(Debug)]
pub(crate) struct OnceCell<T> {
    #[cfg(not(loom))]
    inner: std::sync::OnceLock<T>,
    #[cfg(loom)]
    inner: Mutex<Option<T>>,
}

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

    /// Install `value` unless the cell is already full. Returns whether this
    /// call was the one that filled it.
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
    /// Under loom the cell's lock is held for the duration of `f`. That is a
    /// coarser interleaving than production, where `OnceLock::get` borrows
    /// without locking — deliberately so: what the lazy-init models need to
    /// explore is the race to *fill* the cell, and concurrency *through* an
    /// already-filled one is covered by the models that drive the inner type
    /// directly.
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
