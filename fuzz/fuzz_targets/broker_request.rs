#![no_main]

//! Fuzz the credential broker's request decoder — the sharpest privilege
//! boundary in the crate.
//!
//! The broker runs in a forked child holding `CAP_SETUID`, reading fixed-layout
//! datagrams off a socket and minting io_uring personalities from whatever the
//! decoder accepts. Everything downstream — `register_as`, the uid/gid it
//! assumes, the capability set it grants — trusts these fields. If a malformed
//! datagram can produce a `Req`, it can produce a personality the caller was
//! never entitled to.
//!
//! The four properties an accepted request must satisfy, each of which gates a
//! separate downstream use:
//! - `ring < nrings`, because the ring index becomes `RING_FD_BASE + ring`, a
//!   raw descriptor number in the child,
//! - `ngroups <= MAX_GROUPS`, the bound on the caller-supplied scratch buffer,
//! - the datagram is **exactly** `HDR_LEN + 4 * ngroups` — a lower bound would
//!   let a receive-buffer truncation be read as though the missing tail were
//!   zeroed groups,
//! - `caps ⊆ allowed`, the ceiling fixed when the broker was spawned; an
//!   unknown bit must be refused rather than masked off, or the caller silently
//!   gets a weaker personality and discovers it as an `EACCES` far away.
//!
//! Rejection must also be honest: the only errnos the loop can reply with are
//! `EINVAL` and `EPERM`.

use libfuzzer_sys::fuzz_target;
use truenas_ros::uring_fs::{
    fuzz::{decode_groups, decode_request},
    Caps, MAX_GROUPS, MAX_RINGS,
};

/// `HDR_LEN` from `src/uring_fs/broker.rs`.
const HDR_LEN: usize = 16;

fuzz_target!(|data: &[u8]| {
    // A broker is spawned with a real ring count and a real ceiling, so model
    // both rather than letting the fuzzer invent impossible ones. The ceiling
    // is drawn from the selector rather than independently: with a random
    // ceiling the `caps ⊆ allowed` check would almost always reject, and the
    // accept path — the one that mints a personality — would go untested.
    let Some((&sel, req)) = data.split_first() else {
        return;
    };
    let nrings = usize::from(sel >> 4) % (MAX_RINGS + 1);
    let allowed = if sel & 1 == 0 {
        Caps::all()
    } else {
        Caps::from_bits_truncate(u32::from(sel >> 1))
    };

    let decoded = match decode_request(req, nrings, allowed) {
        Ok(r) => r,
        Err(errno) => {
            assert!(
                errno == -(libc::EINVAL as i64)
                    || errno == -(libc::EPERM as i64),
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
    assert!(
        allowed.contains(decoded.caps),
        "accepted caps {:?} outside the ceiling {allowed:?}",
        decoded.caps
    );

    // Deciding is a pure function of the inputs.
    assert_eq!(
        decode_request(req, nrings, allowed).expect("still accepted"),
        decoded,
        "decoding is not deterministic"
    );

    // The group payload is read against the length the header declared, which
    // the exactness check above has already tied to the datagram. Reading it
    // must stay inside the buffer for any accepted request.
    let mut groups = vec![0u32; MAX_GROUPS];
    decode_groups(&req, decoded.ngroups, &mut groups);
    for (i, g) in groups.iter().take(decoded.ngroups).enumerate() {
        let at = HDR_LEN + 4 * i;
        assert_eq!(
            *g,
            u32::from_le_bytes([
                req[at],
                req[at + 1],
                req[at + 2],
                req[at + 3]
            ]),
            "group {i} was not copied verbatim"
        );
    }
    // A short destination must truncate, never overrun.
    let mut small = [0u32; 4];
    decode_groups(&req, decoded.ngroups.min(small.len()), &mut small);
});
