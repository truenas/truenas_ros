#![no_main]

//! Fuzz the credential broker's request decoder, the sharpest privilege boundary in the crate.
//!
//! The broker runs in a forked child holding `CAP_SETUID` and mints io_uring personalities from whatever the decoder
//! accepts, so a malformed datagram that decodes to a `Req` is a personality the caller was never entitled to. An
//! accepted request must satisfy
//! - `ring < nrings`, because the ring index becomes `RING_FD_BASE + ring`, a raw descriptor number in the child,
//! - `ngroups <= MAX_GROUPS`, the bound on the caller-supplied scratch buffer,
//! - a length of exactly `HDR_LEN + 4 * ngroups`, since a lower bound would read a truncated datagram as though its
//!   missing tail were zeroed groups,
//! - `caps ⊆ allowed`, the ceiling fixed at spawn, with an unknown bit refused rather than masked off,
//! - and for a registration of uid 0, `caps ⊆ root` instead, the root limit `spawn_with_root` fixed, with no
//!   registration of uid 0 accepted at all when the broker has none.
//!
//! Rejection must also be honest: the only errnos the loop can reply with are `EINVAL` and `EPERM`.

use libfuzzer_sys::fuzz_target;
use truenas_ros::uring_fs::{
    Caps, MAX_GROUPS, MAX_RINGS,
    fuzz::{decode_groups, decode_request},
};

/// `HDR_LEN` from `src/uring_fs/broker.rs`.
const HDR_LEN: usize = 16;

fuzz_target!(|data: &[u8]| {
    // Model a real ring count and ceiling, each from a byte of its own so neither couples the other. `nrings` takes the
    // whole byte to reach `MAX_RINGS`, from 1 since `spawn_with_caps` refuses no rings. The ceiling is every capability
    // or the byte's bits, since a random one almost always rejects and leaves the accept path untested.
    let Some((&sel, rest)) = data.split_first() else {
        return;
    };
    let Some((&cap_sel, rest)) = rest.split_first() else {
        return;
    };
    // A third byte for the root limit, an axis of its own. It gives none, every capability, or a ceiling drawn from the
    // byte, so a registration of uid 0 is tried against each.
    let Some((&root_sel, req)) = rest.split_first() else {
        return;
    };
    let nrings = 1 + usize::from(sel) % MAX_RINGS;
    let allowed = if cap_sel & 1 == 0 {
        Caps::all()
    } else {
        Caps::from_bits_truncate(u32::from(cap_sel >> 1))
    };
    let root = match root_sel % 3 {
        0 => None,
        1 => Some(Caps::all()),
        _ => Some(Caps::from_bits_truncate(u32::from(root_sel >> 2))),
    };

    let decoded = match decode_request(req, nrings, allowed, root) {
        Ok(r) => r,
        Err(errno) => {
            assert!(
                errno == -(libc::EINVAL as i64) || errno == -(libc::EPERM as i64),
                "rejected with an errno the loop cannot reply with: {errno}"
            );
            return;
        }
    };

    assert!(
        decoded.ring < nrings,
        "accepted ring {} with only {nrings} rings",
        decoded.ring
    );
    assert!(
        decoded.ngroups <= MAX_GROUPS,
        "accepted {} groups, over the {MAX_GROUPS} cap",
        decoded.ngroups
    );
    assert_eq!(
        req.len(),
        HDR_LEN + 4 * decoded.ngroups,
        "accepted a datagram whose length does not match its group count"
    );
    // `OP_REGISTER` is 1. A registration of uid 0 is held to the root limit, and needs one. Anything else is held to
    // `allowed`.
    let ceiling = if decoded.op == 1 && decoded.uid == 0 {
        root.expect("a registration of uid 0 accepted with no root limit")
    } else {
        allowed
    };
    assert!(
        ceiling.contains(decoded.caps),
        "accepted caps {:?} outside the ceiling {ceiling:?}",
        decoded.caps
    );
    // An unknown bit must be refused, not masked off, or a caller gets a weaker personality than it asked for and finds
    // out as an `EACCES` far from here. The `contains` above would hold under `from_bits_truncate` just as well, so
    // re-derive the wire word and require a lossless decode.
    let caps_bits = u32::from_le_bytes([req[12], req[13], req[14], req[15]]);
    assert_eq!(
        Caps::from_bits(caps_bits),
        Some(decoded.caps),
        "accepted a caps word {caps_bits:#x} that is not exactly {:?}",
        decoded.caps
    );

    // Deciding is a pure function of the inputs.
    assert_eq!(
        decode_request(req, nrings, allowed, root).expect("still accepted"),
        decoded,
        "decoding is not deterministic"
    );

    // The group payload is read against the length the header declared, which the exactness check above has already
    // tied to the datagram. Reading it must stay inside the buffer for any accepted request.
    let mut groups = vec![0u32; MAX_GROUPS];
    decode_groups(&req, decoded.ngroups, &mut groups);
    for (i, g) in groups.iter().take(decoded.ngroups).enumerate() {
        let at = HDR_LEN + 4 * i;
        assert_eq!(
            *g,
            u32::from_le_bytes([req[at], req[at + 1], req[at + 2], req[at + 3]]),
            "group {i} was not copied verbatim"
        );
    }
    // A short destination must truncate, never overrun - so the count goes in unclamped. `MAX_GROUPS` is 4096, so an
    // accepted request really can declare more groups than this buffer holds; clamping here would exercise no
    // truncation at all, and an `out[i]` rewrite of `decode_groups` would go unnoticed.
    let mut small = [0u32; 4];
    decode_groups(&req, decoded.ngroups, &mut small);
});
