#![no_main]

//! Fuzz the `struct file_handle` codec.
//!
//! A serialized handle is persisted and handed back later, across a reboot or by a client, so `from_bytes` copies a
//! length the blob itself declares (`handle_bytes`) into a fixed `MAX_HANDLE_SZ` array. Its guards, a floor of
//! `HEADER_SZ`, a ceiling of `HEADER_SZ + MAX_HANDLE_SZ` and `n <= data.len() - HEADER_SZ`, must keep it from
//! over-reading the input or overflowing the destination.
//!
//! The round trip is one-directional on purpose. `to_bytes` writes only the `handle_bytes` the header declared, so a
//! blob with trailing slack re-encodes shorter, and the encoded form must be a **prefix** of the input. Encoding then
//! decoding must reproduce the handle exactly.

use libfuzzer_sys::fuzz_target;
use truenas_ros::sync_fs::fhandle::FileHandle;

/// `handle_bytes: u32` + `handle_type: i32`.
const HEADER_SZ: usize = 8;
/// `MAX_HANDLE_SZ` from `linux/fcntl.h`.
const MAX_HANDLE_SZ: usize = 128;

fuzz_target!(|input: &[u8]| {
    // The mount id and its uniqueness flag ride beside the blob, so both come from one leading byte and the rest is the
    // `struct file_handle`.
    let Some((&sel, data)) = input.split_first() else {
        return;
    };
    let mount_id = u64::from(sel);
    let unique_mount_id = sel & 1 == 0;

    let Ok(handle) = FileHandle::from_bytes(data, mount_id, unique_mount_id) else {
        return;
    };

    assert!(
        data.len() >= HEADER_SZ && data.len() <= HEADER_SZ + MAX_HANDLE_SZ,
        "accepted a blob outside the declared size bounds: {}",
        data.len()
    );
    assert_eq!(handle.mount_id(), mount_id, "mount id was not carried");
    assert_eq!(
        handle.unique_mount_id(),
        unique_mount_id,
        "mount-id uniqueness was not carried"
    );

    let enc = handle.to_bytes();
    assert!(
        enc.len() >= HEADER_SZ && enc.len() <= data.len(),
        "encoding grew the handle: {} from {}",
        enc.len(),
        data.len()
    );
    assert!(
        data.starts_with(&enc),
        "the re-encoded handle is not a prefix of the blob it came from"
    );

    // Canonical direction: what the encoder writes, the decoder reproduces exactly, and encoding again is a fixed
    // point.
    let again = FileHandle::from_bytes(&enc, mount_id, unique_mount_id).expect("an encoded handle must decode");
    assert_eq!(again.to_bytes(), enc, "encoding is not a fixed point");
});
