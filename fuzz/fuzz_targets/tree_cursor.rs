#![no_main]

//! Fuzz the subtree-walk resume cursor.
//!
//! Same provenance as the iterator cookie — persisted, handed back later — and
//! the same exact framing: magic, version, a `u16` of flags, a `u32` length,
//! then that many raw key bytes, with a length disagreeing with the blob
//! rejected. Exactly one blob encodes a given cursor, so the round trip is
//! strict: anything accepted must re-encode byte-identically, which catches a
//! flag dropped on decode as readily as a mangled key.
//!
//! The key itself is a `/`-separated path that drives the walk's descent, so it
//! is also checked here that a cursor built directly from arbitrary bytes
//! survives a round trip — that is the constructor a caller reaches through
//! `TreeEntry::key`, and its input is a filename an unprivileged user chose.

use libfuzzer_sys::fuzz_target;
use truenas_ros::uring_fs::TreeCursor;

fuzz_target!(|data: &[u8]| {
    // Decode direction: whatever the blob framing accepts must re-encode
    // exactly, since the decoder rejects both truncation and trailing bytes.
    if let Ok(cursor) = TreeCursor::from_bytes(data) {
        assert_eq!(
            cursor.to_bytes(),
            data,
            "the cursor format is exact, so re-encoding must be identical"
        );
        assert_eq!(
            cursor.is_empty(),
            cursor.key().is_empty(),
            "is_empty disagrees with the key"
        );
    }

    // Construct direction: an arbitrary key — a real filename, possibly
    // non-UTF-8, possibly full of separators — must survive serialization.
    let built = TreeCursor::from_key(data.to_vec());
    assert_eq!(built.key(), data, "from_key altered the key");
    let enc = built.to_bytes();
    let back =
        TreeCursor::from_bytes(&enc).expect("an encoded cursor must decode");
    assert_eq!(back, built, "cursor does not round-trip");
    assert_eq!(back.to_bytes(), enc, "encoding is not a fixed point");
});
