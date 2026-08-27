#![no_main]

//! Fuzz the NFSv4 ACL XDR codec — the `system.nfs4_acl_xdr` blob ZFS hands
//! back, decoded straight off the wire.
//!
//! `from_xattr` indexes the blob with an unchecked `be32`, guarded only by the
//! exactness check `header + naces * ACE_SZ == data.len()` and the
//! `checked_mul`/`checked_add` behind it. For any bytes at all it must (a)
//! never panic, and (b) if it accepts, produce an ACL the encoder can write
//! back: **a decode that cannot re-encode is a blob we can read and never
//! store.**
//!
//! The asserted round trip is *idempotence after one normalization pass*, not
//! byte equality. The decoder is deliberately laxer than the encoder in one
//! place — it reads only bit 0 of an ACE's `iflag` word, matching how ZFS
//! decides "special principal", while `to_xattr` writes the whole word as 0 or
//! 1 — so `iflag = 5` decodes fine and re-encodes as 1. Normalizing is correct;
//! normalizing *differently on a second pass* would not be.

use libfuzzer_sys::fuzz_target;
use truenas_ros::sync_fs::acl::{Nfs4Acl, PosixAcl};

/// XDR header: `acl_flags` + `naces`.
const HDR_SZ: usize = 8;
/// One ACE: type, flags, iflag, access mask, who.
const ACE_SZ: usize = 20;

fuzz_target!(|data: &[u8]| {
    let Ok(acl) = Nfs4Acl::from_xattr(data) else {
        return;
    };

    // Every decoded ACL must encode. `to_xattr` can only fail on a `Named` ACE
    // whose `who_id` is not a valid uid/gid, and a decoded one always is (the
    // wire field is a u32 widened to i64), so a failure here is a real
    // read-but-cannot-write asymmetry.
    let enc = acl.to_xattr().expect("a decoded ACL must be re-encodable");
    assert_eq!(
        enc.len(),
        HDR_SZ + ACE_SZ * acl.aces.len(),
        "encoded length disagrees with the ACE count"
    );

    // The encoder's output is exactly what the decoder demands, so it must
    // decode — and to the same ACL.
    let again =
        Nfs4Acl::from_xattr(&enc).expect("re-encoded ACL must re-decode");
    assert_eq!(again, acl, "decode/encode is not idempotent");
    assert_eq!(
        again.to_xattr().expect("re-decoded ACL must re-encode"),
        enc,
        "encoding is not a fixed point"
    );

    // Inheritance derives a child ACL by filtering and rewriting flags; its
    // output must satisfy the same contract. It errors when nothing is
    // inheritable, which is a normal answer, not a failure.
    for is_dir in [false, true] {
        let Ok(child) = acl.generate_inherited_acl(is_dir) else {
            continue;
        };
        assert!(
            !child.aces.is_empty(),
            "an inherited ACL is either an error or non-empty"
        );
        assert!(
            child.aces.len() <= acl.aces.len(),
            "inheritance only filters, never invents ACEs"
        );
        let cenc = child
            .to_xattr()
            .expect("an inherited ACL must be re-encodable");
        assert_eq!(
            Nfs4Acl::from_xattr(&cenc).expect("inherited ACL must re-decode"),
            child,
            "inherited ACL does not round-trip"
        );
    }

    // The lossy POSIX1E translation runs a deny-propagating state machine
    // over the same attacker-controlled ACEs, so it is driven from here too.
    // It errors on an id POSIX cannot hold, which is a normal answer.
    for is_dir in [false, true] {
        let Ok(posix) = acl.to_posix_lossy(is_dir) else {
            continue;
        };
        check_posix(&posix, is_dir);

        // Anything we produced must convert back, and the pair must settle:
        // the first pass can widen the group-class mask, because that mask is
        // derived from the union of the NFS4 allow masks and `w` can be
        // spelled by bits no single entry holds in full. The second pass
        // recomputes it from entries that are already reduced, so from there
        // on the two conversions have to be a fixed point.
        let nfs4 = posix
            .to_nfs4_lossy(is_dir)
            .expect("a POSIX ACL we produced must convert back");
        let again = nfs4
            .to_posix_lossy(is_dir)
            .expect("and that must convert forward again");
        check_posix(&again, is_dir);
        let settled = again
            .to_nfs4_lossy(is_dir)
            .expect("a settled POSIX ACL must convert back")
            .to_posix_lossy(is_dir)
            .expect("and forward again");
        assert_eq!(settled, again, "the conversion pair does not settle");
    }
});

/// A converted POSIX ACL must be one we could write: it is validated on the
/// way out, so a shape the encoder refuses - or a default half on something
/// that cannot carry one - is a read-but-cannot-write asymmetry.
fn check_posix(acl: &PosixAcl, is_dir: bool) {
    acl.access_bytes()
        .expect("a converted POSIX ACL must be encodable");
    let default = acl
        .default_bytes()
        .expect("a converted default ACL must be encodable");
    assert_eq!(
        default.is_some(),
        acl.default.is_some(),
        "the default half disagrees with its encoding"
    );
    assert!(
        is_dir || acl.default.is_none(),
        "only a directory can carry a default ACL"
    );
}
