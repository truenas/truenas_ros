#![no_main]

//! Fuzz the filesystem-iterator resume cookie.
//!
//! A cookie is persisted between runs and handed back to resume a walk, so the
//! decoder eats bytes whose provenance is a disk file rather than the process
//! that wrote them. It reads a magic, a version, a level count capped at
//! `MAX_DEPTH`, and then per level an inode plus a **length-prefixed raw path**
//! — an attacker-chosen `u32` driving a copy out of the blob.
//!
//! The format is exact in both directions: `from_bytes` rejects a short read
//! *and* trailing bytes, and `to_bytes` writes precisely what it reads. So
//! unlike the handle codec this is a **strict** round trip — anything accepted
//! must re-encode to the identical bytes. A mismatch means the decoder is
//! ignoring part of the blob, which is how a resume silently restarts somewhere
//! other than where it stopped.

use libfuzzer_sys::fuzz_target;
use truenas_ros::sync_fs::iter::Cookie;

/// `MAX_DEPTH` from `src/sync_fs/iter.rs`.
const MAX_DEPTH: usize = 2048;

fuzz_target!(|data: &[u8]| {
    let Ok(cookie) = Cookie::from_bytes(data) else {
        return;
    };

    assert!(
        cookie.len() <= MAX_DEPTH,
        "accepted a cookie {} levels deep, over the {MAX_DEPTH} cap",
        cookie.len()
    );
    assert_eq!(
        cookie.is_empty(),
        cookie.len() == 0,
        "is_empty disagrees with len"
    );
    assert_eq!(
        cookie.entries().len(),
        cookie.len(),
        "entries disagrees with len"
    );

    let enc = cookie.to_bytes();
    assert_eq!(
        enc, data,
        "the cookie format is exact, so re-encoding must be byte-identical"
    );

    // Truncation is the documented recovery path; it must leave a cookie that
    // still encodes and decodes.
    for depth in [0, cookie.len() / 2, cookie.len()] {
        let mut trimmed = cookie.clone();
        trimmed.truncate(depth);
        assert_eq!(trimmed.len(), depth.min(cookie.len()));
        let tenc = trimmed.to_bytes();
        assert_eq!(
            Cookie::from_bytes(&tenc)
                .expect("a truncated cookie must decode")
                .to_bytes(),
            tenc,
            "a truncated cookie does not round-trip"
        );
    }
});
