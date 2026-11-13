#![no_main]

//! Fuzz the `statmount(2)` reply decoder, the highest-risk parse in the crate.
//!
//! `parse` casts the reply buffer to a `struct statmount`, then reads every string from a header-declared u32 offset
//! past a fixed base up to a NUL. The bytes it scans are clamped to `min(hdr.size, buffer)`, and the only per-string
//! guard is `start >= bytes.len()`. A reply whose `size`, offsets or `*_num` counts disagree with the buffer must still
//! decode in bounds, `get_str_array` above all, since it advances `pos += end + 1` `count` times and must check the
//! guard on each.
//!
//! Run it under AddressSanitizer, cargo-fuzz's default, so an out-of-bounds read is a crash. The property is memory
//! safety and total accessors. Field values are not asserted, since the kernel is their only authority and the unit
//! tests in `src/mount/statmount.rs` pin the well-formed shape.

use libfuzzer_sys::fuzz_target;
use truenas_ros::mount::{fuzz, is_zfs_snapshot};

/// `size_of::<RawStatmount>()`, the offset the string area starts at.
const STR_BASE: usize = 512;

fuzz_target!(|data: &[u8]| {
    // The syscall wrapper always hands `parse` at least 1 KiB, so a short buffer is not a shape the decoder has to
    // survive — the `__fuzz` seam returns `None` for it. Build a word-aligned buffer from the input, padded to the
    // header size so the interesting cases are reachable.
    let mut words = vec![0u64; STR_BASE / 8];
    for (i, chunk) in data.chunks(8).enumerate() {
        let mut w = [0u8; 8];
        w[..chunk.len()].copy_from_slice(chunk);
        let w = u64::from_ne_bytes(w);
        match words.get_mut(i) {
            Some(slot) => *slot = w,
            None => words.push(w),
        }
    }

    let Some(sm) = fuzz::parse(&words) else {
        unreachable!("a buffer padded to STR_BASE is always long enough");
    };

    // Every accessor must be total on whatever `parse` produced.
    let _ = sm.mount_opts();
    let _ = is_zfs_snapshot(&sm);
    let _ = format!("{sm:?}");

    // Decoding is a pure function of the buffer, so it must be deterministic — a second pass over the same words yields
    // the same answer. This catches a decoder that reads uninitialized padding beyond `hdr.size`.
    let Some(again) = fuzz::parse(&words) else {
        unreachable!("determinism: the second parse must also succeed");
    };
    assert_eq!(sm.mount_opts(), again.mount_opts(), "parse is not deterministic");
    assert_eq!(format!("{sm:?}"), format!("{again:?}"), "parse is not deterministic");
});
