#![no_main]

//! Fuzz the `TnPath` byte-to-`CStr` conversion — the crate's one hot unsafe
//! buffer.
//!
//! Every path the library passes to a syscall goes through here. The `[u8]`
//! implementation writes into a `MaybeUninit<[u8; 1024]>` on the stack with
//! `ptr::copy_nonoverlapping` plus a manual NUL, and falls back to a `#[cold]`
//! heap path when the name does not fit. The boundary between those two arms is
//! exactly where an off-by-one writes past the array — 1023, 1024 and 1025
//! bytes are all reachable from a real filename, and `PATH_MAX` is 4096.
//!
//! Under AddressSanitizer a one-byte overrun on either arm is a crash. The
//! functional property is that whichever arm runs, the yielded `CStr` carries
//! exactly the input bytes and is NUL-terminated, and that an interior NUL is
//! refused rather than silently truncating the path — truncation would open a
//! different file than the caller named.

use libfuzzer_sys::fuzz_target;
use truenas_ros::TnPath;

fuzz_target!(|data: &[u8]| {
    let has_interior_nul = data.contains(&0);

    let observed = data.with_tn_path(|c| c.to_bytes().to_vec());

    match observed {
        Ok(bytes) => {
            assert!(
                !has_interior_nul,
                "a name with an interior NUL was silently converted: {data:?}"
            );
            assert_eq!(bytes, data, "the CStr does not carry the input bytes");
        }
        Err(_) => assert!(
            has_interior_nul,
            "conversion refused a NUL-free name: {data:?}"
        ),
    }

    // `len`/`is_empty` describe the same bytes the conversion sees.
    assert_eq!(
        TnPath::len(data),
        data.len(),
        "len disagrees with the input"
    );
    assert_eq!(
        TnPath::is_empty(data),
        data.is_empty(),
        "is_empty disagrees with the input"
    );

    // The `str` implementation shares the byte path; drive it too when the
    // input happens to be UTF-8, so both arms see the same boundary cases.
    if let Ok(s) = std::str::from_utf8(data) {
        let via_str = s.with_tn_path(|c| c.to_bytes().to_vec());
        assert_eq!(
            via_str.is_ok(),
            !has_interior_nul,
            "the str and [u8] impls disagree about interior NUL"
        );
        if let Ok(bytes) = via_str {
            assert_eq!(
                bytes, data,
                "the str impl produced different bytes than [u8]"
            );
        }
    }
});
