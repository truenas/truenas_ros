#![no_main]

//! Fuzz the POSIX.1e ACL codec — the little-endian `system.posix_acl_access`
//! and `system.posix_acl_default` blobs.
//!
//! Same contract as the NFSv4 target: `parse_aces` indexes entries with
//! unchecked `le16`/`le32` behind a version check and a
//! `(len - HDR) % ACE_SZ == 0` check, and anything it accepts must be
//! re-encodable. The interesting asymmetry here is the `e_id` field — the
//! kernel writes `ACL_UNDEFINED_ID` for every non-USER/GROUP tag and ignores
//! the field when reading one back (`fs/posix_acl.c`), so the decoder
//! normalizes a special entry's id to -1 and rejects a named entry carrying the
//! sentinel. Without that, `from_xattr` would accept blobs `access_bytes`
//! either refuses outright or re-emits differently.
//!
//! Asserted as idempotence after one normalization pass, not byte equality: a
//! special tag whose wire id is some stray value normalizes to the sentinel on
//! the way out, which is correct.

use libfuzzer_sys::fuzz_target;
use truenas_ros::sync_fs::acl::PosixAcl;

/// The 4-byte version header.
const HDR_SZ: usize = 4;
/// One entry: tag, perms, id.
const ACE_SZ: usize = 8;

fuzz_target!(|data: &[u8]| {
    // Split one input into the access blob and the optional default blob, so
    // a corpus entry is just the bytes of a real xattr pair. The leading byte
    // chooses whether a default ACL is present at all — `None` and
    // `Some(empty)` are different states, and both must round-trip.
    let Some((&sel, rest)) = data.split_first() else {
        return;
    };
    let (access, default) = if sel & 1 == 0 {
        (rest, None)
    } else {
        let mid = usize::from(sel >> 1).min(rest.len());
        let (a, d) = rest.split_at(mid);
        (a, Some(d))
    };
    let Ok(acl) = PosixAcl::from_xattr(access, default) else {
        return;
    };

    let aenc = acl
        .access_bytes()
        .expect("a decoded access ACL must be re-encodable");
    let denc = acl
        .default_bytes()
        .expect("a decoded default ACL must be re-encodable");

    // An empty input decodes to an empty list and encodes back to a bare
    // header; anything else is header + one record per entry.
    assert_eq!(
        aenc.len(),
        HDR_SZ + ACE_SZ * acl.access.len(),
        "encoded access length disagrees with the entry count"
    );
    if let (Some(d), Some(entries)) = (denc.as_ref(), acl.default.as_ref()) {
        assert_eq!(
            d.len(),
            HDR_SZ + ACE_SZ * entries.len(),
            "encoded default length disagrees with the entry count"
        );
    }
    assert_eq!(
        denc.is_some(),
        acl.default.is_some(),
        "the default ACL appeared or vanished across encoding"
    );

    // Re-decoding the encoder's own output must reproduce the same ACL, and
    // encoding it again must reproduce the same bytes.
    let again = PosixAcl::from_xattr(&aenc, denc.as_deref())
        .expect("re-encoded ACL must re-decode");
    assert_eq!(
        (&again.access, &again.default),
        (&acl.access, &acl.default),
        "decode/encode is not idempotent"
    );
    assert_eq!(
        again.access_bytes().expect("re-decoded ACL must re-encode"),
        aenc,
        "access encoding is not a fixed point"
    );
    assert_eq!(
        again
            .default_bytes()
            .expect("re-decoded ACL must re-encode"),
        denc,
        "default encoding is not a fixed point"
    );

    // Inheritance needs a default ACL to draw from; erroring is a normal
    // answer. What it returns must satisfy the same contract.
    for is_dir in [false, true] {
        let Ok(child) = acl.generate_inherited_acl(is_dir) else {
            continue;
        };
        let cenc = child
            .access_bytes()
            .expect("an inherited ACL must be re-encodable");
        let cdef = child
            .default_bytes()
            .expect("an inherited ACL must be re-encodable");
        let redecoded = PosixAcl::from_xattr(&cenc, cdef.as_deref())
            .expect("inherited ACL must re-decode");
        assert_eq!(
            (&redecoded.access, &redecoded.default),
            (&child.access, &child.default),
            "inherited ACL does not round-trip"
        );
    }
});
