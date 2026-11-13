use std::os::fd::AsFd;
use truenas_ros::sync_fs::acl::{
    Acl, Nfs4Ace, Nfs4AceType, Nfs4Acl, Nfs4AclFlag, Nfs4Flag, Nfs4Perm, Nfs4Who, PosixAce, PosixAcl, PosixPerm,
    PosixTag, fgetacl, fsetacl,
};
use truenas_ros::sync_fs::xattr::fgetxattr;

/// Skip a live-fixture check. `TRUENAS_ROS_REQUIRE_ZFS` (the same gate `test/zfs.rs` uses) turns the skip into a
/// failure, so a fixture on the wrong dataset type is caught where CI provisions one and ignored where it does not.
#[track_caller]
fn require_zfs(why: &str) {
    assert!(
        std::env::var_os("TRUENAS_ROS_REQUIRE_ZFS").is_none(),
        "TRUENAS_ROS_REQUIRE_ZFS is set but {why}"
    );
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

// Real xattrs captured from /NFSV4ACL/raw_bytes and /POSIXACL/raw_bytes.
const NFS4_GOLD: &str = "0000000000000003000000000000000000000001001f\
        01ff00000001000000000000004000000001001200a900000002000000000000000\
        000000001001200a900000003";
const POSIX_GOLD: &str = "0200000001000700ffffffff02000500e90300000400\
        0500ffffffff10000500ffffffff20000000ffffffff";

#[test]
fn nfs4_decode_and_byte_exact_roundtrip() {
    let data = hex(NFS4_GOLD);
    let acl = Nfs4Acl::from_xattr(&data).unwrap();
    assert_eq!(acl.aces.len(), 3);
    assert!(!acl.trivial());

    // OWNER@, ALLOW, full control.
    assert_eq!(acl.aces[0].who_type, Nfs4Who::Owner);
    assert_eq!(acl.aces[0].who_id, -1);
    assert_eq!(acl.aces[0].ace_type, Nfs4AceType::Allow);
    assert!(
        acl.aces[0]
            .access_mask
            .contains(Nfs4Perm::READ_DATA | Nfs4Perm::WRITE_OWNER)
    );
    // GROUP@ carries IDENTIFIER_GROUP.
    assert_eq!(acl.aces[1].who_type, Nfs4Who::Group);
    assert!(acl.aces[1].ace_flags.contains(Nfs4Flag::IDENTIFIER_GROUP));
    // EVERYONE@.
    assert_eq!(acl.aces[2].who_type, Nfs4Who::Everyone);

    assert_eq!(acl.to_xattr().unwrap(), data);
}

#[test]
fn posix_decode_and_byte_exact_roundtrip() {
    let data = hex(POSIX_GOLD);
    let acl = PosixAcl::from_xattr(&data, None).unwrap();
    assert_eq!(acl.access.len(), 5);
    assert!(!acl.trivial());

    assert_eq!(acl.access[0].tag, PosixTag::UserObj);
    assert_eq!(
        acl.access[0].perms,
        PosixPerm::READ | PosixPerm::WRITE | PosixPerm::EXECUTE
    );
    assert_eq!(acl.access[1].tag, PosixTag::User);
    assert_eq!(acl.access[1].id, 1001);
    assert_eq!(acl.access[4].tag, PosixTag::Other);
    assert_eq!(acl.access[4].perms, PosixPerm::empty());

    assert_eq!(acl.access_bytes().unwrap(), data);
    assert!(acl.default_bytes().unwrap().is_none());
}

#[test]
fn nfs4_from_aces_sorts_into_canonical_buckets() {
    // Supplied out of order: inherited-allow, explicit-deny, explicit-allow.
    let inherited_allow = Nfs4Ace::new(
        Nfs4AceType::Allow,
        Nfs4Flag::INHERITED,
        Nfs4Perm::READ_DATA,
        Nfs4Who::Everyone,
        -1,
    );
    let explicit_deny = Nfs4Ace::new(
        Nfs4AceType::Deny,
        Nfs4Flag::empty(),
        Nfs4Perm::WRITE_DATA,
        Nfs4Who::Named,
        1000,
    );
    let explicit_allow = Nfs4Ace::new(
        Nfs4AceType::Allow,
        Nfs4Flag::empty(),
        Nfs4Perm::READ_DATA,
        Nfs4Who::Owner,
        -1,
    );
    let acl = Nfs4Acl::from_aces([inherited_allow, explicit_deny, explicit_allow], Nfs4AclFlag::empty());
    // Canonical order: explicit-deny, explicit-allow, then inherited-allow.
    assert_eq!(acl.aces[0].ace_type, Nfs4AceType::Deny);
    assert_eq!(acl.aces[1].ace_type, Nfs4AceType::Allow);
    assert!(!acl.aces[1].ace_flags.contains(Nfs4Flag::INHERITED));
    assert!(acl.aces[2].ace_flags.contains(Nfs4Flag::INHERITED));
}

/// A scratch file on `dir`, or `None` when the dataset is not there.
///
/// The fixture is created here rather than expected at the dataset root, and every early exit goes through
/// `require_zfs`, so `TRUENAS_ROS_REQUIRE_ZFS` turns a skip red.
fn live_acl_file(env_var: &str, fallback: &str) -> Option<(std::path::PathBuf, std::fs::File)> {
    // Resolved as every other ZFS fixture is, the provisioning script's env var first and then the convention path, and
    // gated on `statfs` rather than on the directory existing. An `is_dir` gate says yes to a leftover mountpoint and
    // to tmpfs, which serves POSIX ACLs, so the POSIX half would pass having tested the wrong filesystem.
    let dir = std::env::var_os(env_var)
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from(fallback));
    let dir = dir.as_path();
    if super::zfs_dir::is_zfs(dir) != Some(true) {
        require_zfs(&format!("{} is not a ZFS dataset", dir.display()));
        return None;
    }
    let path = dir.join(format!("rostest_acl_{}", std::process::id()));
    let _ = std::fs::remove_file(&path);
    match std::fs::write(&path, b"acl round trip") {
        Ok(()) => {}
        Err(e) => {
            require_zfs(&format!("{} is not writable: {e}", dir.display()));
            return None;
        }
    }
    let f = std::fs::File::open(&path).expect("reopen the scratch file");
    Some((path, f))
}

#[test]
fn fgetacl_live_nfs4_roundtrips() {
    let Some((path, f)) = live_acl_file("TRUENAS_ROS_NFS4_DATASET", "/NFSV4ACL") else {
        return;
    };
    let got = fgetacl(f.as_fd());
    let _ = std::fs::remove_file(&path);
    match got {
        Ok(Acl::Nfs4(acl)) => {
            let raw = fgetxattr(f.as_fd(), "system.nfs4_acl_xdr").unwrap();
            assert_eq!(acl.to_xattr().unwrap(), raw);
        }
        // The path exists but is not on an NFSv4-ACL dataset.
        Ok(Acl::Posix(_)) => require_zfs("/NFSV4ACL is not NFSv4-ACL"),
        // Not an NFS4-ACL filesystem at all. Swallowed only where the fixture is not required; under REQUIRE_ZFS it
        // is a failure like any other, since the dataset was provisioned to serve exactly this.
        Err(e) => require_zfs(&format!("/NFSV4ACL fgetacl failed: {e}")),
    }
}

#[test]
fn fgetacl_live_posix_roundtrips() {
    let Some((path, f)) = live_acl_file("TRUENAS_ROS_POSIX_DATASET", "/POSIXACL") else {
        return;
    };
    let got = fgetacl(f.as_fd());
    let _ = std::fs::remove_file(&path);
    match got {
        Ok(Acl::Posix(acl)) => {
            // A file with only mode bits has no stored `system.posix_acl_access`: the trivial ACL is synthesised,
            // and reading the xattr answers `ENODATA`. Give it a real one - a named user, which also forces the
            // MASK entry - so the round trip compares the codec against bytes the kernel actually stored.
            let mut access = acl.access.clone();
            access.push(PosixAce {
                tag: PosixTag::User,
                perms: PosixPerm::READ | PosixPerm::WRITE,
                id: 4_200,
                default: false,
            });
            // Only when there is not one already. A file inheriting a default ACL from its parent arrives with a MASK,
            // and a second one is not a valid POSIX1E ACL, so `fsetacl` would refuse it.
            if !access.iter().any(|a| a.tag == PosixTag::Mask) {
                access.push(PosixAce {
                    tag: PosixTag::Mask,
                    perms: PosixPerm::READ | PosixPerm::WRITE,
                    id: -1,
                    default: false,
                });
            }
            let want = PosixAcl::from_aces(access);
            fsetacl(f.as_fd(), Some(&Acl::Posix(want))).expect("set a real ACL");

            let Ok(Acl::Posix(stored)) = fgetacl(f.as_fd()) else {
                panic!("the ACL just written did not read back as POSIX")
            };
            let raw = fgetxattr(f.as_fd(), "system.posix_acl_access").unwrap();
            assert_eq!(stored.access_bytes().unwrap(), raw);
        }
        // The path exists but is not on a POSIX-ACL dataset.
        Ok(Acl::Nfs4(_)) => require_zfs("/POSIXACL is not POSIX-ACL"),
        Err(e) => require_zfs(&format!("/POSIXACL fgetacl failed: {e}")),
    }
}
