//! The volatile zeroing burn shared by [`secrets`](crate::secrets) (which re-exports it) and `configfile`'s
//! scrub-on-release mode.

use std::sync::atomic::{Ordering, compiler_fence};

/// Overwrite `len` bytes at `p` with zeroes so the optimizer cannot elide it.
///
/// Use it on a transient buffer a secret passed through. A plain store to soon-dead memory is a dead store the compiler
/// drops, so keep the volatile writes.
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
