//! The volatile zeroing burn shared by [`secrets`](crate::secrets) (which
//! re-exports it) and `configfile`'s scrub-on-release mode.

use std::sync::atomic::{compiler_fence, Ordering};

/// Overwrite `len` bytes at `p` with zeroes so the optimizer cannot elide it.
///
/// A per-byte `write_volatile` plus a compiler fence — the same primitives
/// `zeroize` uses internally, and what `truenas_pam::Secret` uses. A plain
/// store to soon-dead memory is a dead store the compiler will drop; a
/// volatile one it must keep. Use it on a transient buffer a secret passed
/// through.
///
/// # Safety
///
/// `p` must be valid for writes of `len` bytes.
pub unsafe fn scrub(p: *mut u8, len: usize) {
    for i in 0..len {
        // SAFETY: `i < len`, within the caller's guaranteed range.
        unsafe { p.add(i).write_volatile(0) };
    }
    compiler_fence(Ordering::SeqCst);
}
