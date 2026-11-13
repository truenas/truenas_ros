use std::os::fd::AsFd;
use truenas_ros::Error;
use truenas_ros::sync_fs::acl::{
    Acl, AclTarget, Nfs4Ace, Nfs4AceType, Nfs4Acl, Nfs4AclFlag, Nfs4Flag, Nfs4Perm, Nfs4Who, PosixAce, PosixAcl,
    PosixPerm, PosixTag, fgetacl, fsetacl, validate_acl,
};

fn nfs4(aces: Vec<Nfs4Ace>, flags: Nfs4AclFlag) -> Acl {
    Acl::Nfs4(Nfs4Acl { acl_flags: flags, aces })
}
fn n_ace(t: Nfs4AceType, f: Nfs4Flag, who: Nfs4Who, id: i64) -> Nfs4Ace {
    Nfs4Ace::new(t, f, Nfs4Perm::READ_DATA, who, id)
}

#[test]
fn nfs4_named_user_and_flags_roundtrip() {
    let acl = Nfs4Acl {
        acl_flags: Nfs4AclFlag::PROTECTED | Nfs4AclFlag::AUTO_INHERIT,
        aces: vec![n_ace(Nfs4AceType::Allow, Nfs4Flag::empty(), Nfs4Who::Named, 1000)],
    };
    let back = Nfs4Acl::from_xattr(&acl.to_xattr().unwrap()).unwrap();
    assert_eq!(back.aces[0].who_type, Nfs4Who::Named);
    assert_eq!(back.aces[0].who_id, 1000);
    assert_eq!(back.acl_flags, acl.acl_flags);
}

#[test]
fn nfs4_ace_new_forces_special_who_id() {
    assert_eq!(
        n_ace(Nfs4AceType::Allow, Nfs4Flag::empty(), Nfs4Who::Owner, 999).who_id,
        -1
    );
    assert_eq!(
        n_ace(Nfs4AceType::Allow, Nfs4Flag::empty(), Nfs4Who::Named, 42).who_id,
        42
    );
}

#[test]
fn nfs4_from_xattr_rejects_bad_input() {
    // Header claims 2 ACEs but none follow.
    let mut buf = vec![0u8; 8];
    buf[7] = 2;
    assert!(matches!(Nfs4Acl::from_xattr(&buf), Err(Error::Parse(_))));
    // One ACE with an out-of-range type (4).
    let mut buf = vec![0u8; 28];
    buf[7] = 1;
    buf[11] = 4;
    assert!(matches!(Nfs4Acl::from_xattr(&buf), Err(Error::Parse(_))));
}

#[test]
fn nfs4_generate_inherited_for_dir() {
    let acl = nfs4(
        vec![n_ace(
            Nfs4AceType::Allow,
            Nfs4Flag::DIRECTORY_INHERIT | Nfs4Flag::FILE_INHERIT,
            Nfs4Who::Owner,
            -1,
        )],
        Nfs4AclFlag::ACL_IS_DIR,
    );
    let Acl::Nfs4(acl) = acl else { unreachable!() };
    let child = acl.generate_inherited_acl(true).unwrap();
    assert!(child.aces[0].ace_flags.contains(Nfs4Flag::INHERITED));
    assert_eq!(child.acl_flags, Nfs4AclFlag::ACL_IS_DIR);
    // A non-inheritable parent ACE -> error.
    let plain = Nfs4Acl {
        acl_flags: Nfs4AclFlag::empty(),
        aces: vec![n_ace(Nfs4AceType::Allow, Nfs4Flag::empty(), Nfs4Who::Owner, -1)],
    };
    assert!(plain.generate_inherited_acl(true).is_err());
}

#[test]
fn nfs4_validate_directory_rules() {
    // DENY for a special principal -> rejected.
    assert!(
        validate_acl(
            AclTarget::AssumeDir,
            &nfs4(
                vec![n_ace(Nfs4AceType::Deny, Nfs4Flag::empty(), Nfs4Who::Everyone, -1)],
                Nfs4AclFlag::empty()
            )
        )
        .is_err()
    );
    // INHERIT_ONLY without an inheritable bit -> rejected.
    assert!(
        validate_acl(
            AclTarget::AssumeDir,
            &nfs4(
                vec![n_ace(Nfs4AceType::Allow, Nfs4Flag::INHERIT_ONLY, Nfs4Who::Owner, -1)],
                Nfs4AclFlag::empty()
            )
        )
        .is_err()
    );
    // Directory ACL with no inheritable ACE -> rejected.
    assert!(
        validate_acl(
            AclTarget::AssumeDir,
            &nfs4(
                vec![n_ace(Nfs4AceType::Allow, Nfs4Flag::empty(), Nfs4Who::Owner, -1)],
                Nfs4AclFlag::empty()
            )
        )
        .is_err()
    );
    // A valid, inheritable directory ACL -> ok; an empty ACL on a directory -> err (no inheritable ACE, matching
    // the C).
    assert!(
        validate_acl(
            AclTarget::AssumeDir,
            &nfs4(
                vec![n_ace(
                    Nfs4AceType::Allow,
                    Nfs4Flag::FILE_INHERIT | Nfs4Flag::DIRECTORY_INHERIT,
                    Nfs4Who::Owner,
                    -1
                )],
                Nfs4AclFlag::empty()
            )
        )
        .is_ok()
    );
    assert!(validate_acl(AclTarget::AssumeDir, &nfs4(vec![], Nfs4AclFlag::empty())).is_err());
}

#[test]
fn nfs4_validate_file_rejects_inherit_flags() {
    let dir = truenas_ros::tempdir().unwrap();
    let p = dir.path().join("f");
    std::fs::write(&p, b"x").unwrap();
    let f = std::fs::File::open(&p).unwrap();
    let acl = nfs4(
        vec![n_ace(Nfs4AceType::Allow, Nfs4Flag::FILE_INHERIT, Nfs4Who::Owner, -1)],
        Nfs4AclFlag::empty(),
    );
    assert!(validate_acl(AclTarget::Fd(f.as_fd()), &acl).is_err());
    // An empty ACL on a *file*, by contrast, is valid.
    let empty = nfs4(vec![], Nfs4AclFlag::empty());
    assert!(validate_acl(AclTarget::Fd(f.as_fd()), &empty).is_ok());
}

fn posix(aces: Vec<PosixAce>) -> Acl {
    Acl::Posix(PosixAcl::from_aces(aces))
}
fn p_ace(tag: PosixTag, id: i64, default: bool) -> PosixAce {
    PosixAce {
        tag,
        perms: PosixPerm::READ,
        id,
        default,
    }
}
fn valid_access() -> Vec<PosixAce> {
    vec![
        p_ace(PosixTag::UserObj, -1, false),
        p_ace(PosixTag::GroupObj, -1, false),
        p_ace(PosixTag::Other, -1, false),
    ]
}

#[test]
fn posix_validate_structural_rules() {
    assert!(validate_acl(AclTarget::AssumeDir, &posix(valid_access())).is_ok());
    // Missing each required tag -> rejected.
    for skip in [PosixTag::UserObj, PosixTag::GroupObj, PosixTag::Other] {
        let aces: Vec<_> = valid_access().into_iter().filter(|a| a.tag != skip).collect();
        assert!(
            validate_acl(AclTarget::AssumeDir, &posix(aces)).is_err(),
            "missing {skip:?} should be rejected"
        );
    }
    // Named USER without MASK -> rejected; with MASK -> ok.
    let mut aces = valid_access();
    aces.push(p_ace(PosixTag::User, 1000, false));
    assert!(validate_acl(AclTarget::AssumeDir, &posix(aces.clone())).is_err());
    aces.push(p_ace(PosixTag::Mask, -1, false));
    assert!(validate_acl(AclTarget::AssumeDir, &posix(aces)).is_ok());
    // Entries out of canonical tag order -> rejected, as the kernel would.
    let mut unsorted = PosixAcl::from_aces(valid_access());
    unsorted.access.reverse();
    assert!(validate_acl(AclTarget::AssumeDir, &Acl::Posix(unsorted)).is_err());
}

#[test]
fn posix_default_only_valid_on_directory() {
    let dir = truenas_ros::tempdir().unwrap();
    let p = dir.path().join("f");
    std::fs::write(&p, b"x").unwrap();
    let f = std::fs::File::open(&p).unwrap();
    let mut aces = valid_access();
    aces.extend(valid_access().into_iter().map(|mut a| {
        a.default = true;
        a
    }));
    let acl = posix(aces);
    assert!(validate_acl(AclTarget::Fd(f.as_fd()), &acl).is_err());
    assert!(validate_acl(AclTarget::AssumeDir, &acl).is_ok());
}

#[test]
fn posix_codec_default_bytes_and_inherit() {
    let mut aces = valid_access();
    aces.extend(valid_access().into_iter().map(|mut a| {
        a.default = true;
        a
    }));
    let acl = PosixAcl::from_aces(aces);
    assert!(acl.default.is_some());
    assert!(acl.default_bytes().unwrap().is_some());
    assert!(!acl.trivial());
    // Round-trip through the wire codec.
    let round = PosixAcl::from_xattr(&acl.access_bytes().unwrap(), acl.default_bytes().unwrap().as_deref()).unwrap();
    assert_eq!(round.access.len(), 3);
    assert_eq!(round.default.as_ref().unwrap().len(), 3);
    // Inheriting keeps a default for a dir, drops it for a file.
    assert!(acl.generate_inherited_acl(true, 0o755).unwrap().0.default.is_some());
    assert!(acl.generate_inherited_acl(false, 0o755).unwrap().0.default.is_none());
}

#[test]
fn posix_from_xattr_rejects_bad_input() {
    assert!(matches!(PosixAcl::from_xattr(&[0u8], None), Err(Error::Parse(_))));
    // version=2 header + one entry with an unknown tag (0x99).
    let mut buf = vec![2u8, 0, 0, 0];
    buf.extend_from_slice(&[0x99, 0, 0, 0, 0xff, 0xff, 0xff, 0xff]);
    assert!(matches!(PosixAcl::from_xattr(&buf, None), Err(Error::Parse(_))));
}

#[test]
fn fgetacl_on_a_plain_file() {
    let dir = truenas_ros::tempdir().unwrap();
    let p = dir.path().join("f");
    std::fs::write(&p, b"x").unwrap();
    let f = std::fs::File::open(&p).unwrap();
    match fgetacl(f.as_fd()) {
        // POSIX fs with no access xattr -> synthesised from the mode bits.
        Ok(Acl::Posix(a)) => assert!(a.trivial()),
        Ok(Acl::Nfs4(_)) => {}
        Err(_) => {} // ACLs disabled entirely on this filesystem
    }
}

#[test]
fn fsetacl_posix_roundtrip_if_supported() {
    let dir = truenas_ros::tempdir().unwrap();
    let p = dir.path().join("f");
    std::fs::write(&p, b"x").unwrap();
    let f = std::fs::OpenOptions::new().read(true).write(true).open(&p).unwrap();
    let acl = Acl::Posix(PosixAcl::from_aces(vec![
        p_ace(PosixTag::UserObj, -1, false),
        p_ace(PosixTag::GroupObj, -1, false),
        p_ace(PosixTag::Other, -1, false),
    ]));
    // A POSIX ACL is the `system.posix_acl_access` xattr, refused `EOPNOTSUPP` off a dataset whose `acltype` is not
    // `posixacl` (`zpl_xattr_acl_set_access`, module/os/linux/zfs/zpl_xattr.c), so the refusal answers to the gate
    // rather than skipping in silence.
    match fsetacl(f.as_fd(), Some(&acl)) {
        Ok(()) => {
            let _ = fgetacl(f.as_fd()).unwrap(); // read back
            fsetacl(f.as_fd(), None).unwrap(); // remove
        }
        Err(e) => crate::xattr_probe::posix_acl_refusal_is_allowed("fsetacl", e),
    }
}

#[test]
fn low_level_fsetacl_paths() {
    use truenas_ros::errno::Errno;
    use truenas_ros::sync_fs::acl::{fsetacl_nfs4, fsetacl_posix};
    let dir = truenas_ros::tempdir().unwrap();
    let d = std::fs::File::open(dir.path()).unwrap();
    let access = PosixAcl::from_aces(vec![
        p_ace(PosixTag::UserObj, -1, false),
        p_ace(PosixTag::GroupObj, -1, false),
        p_ace(PosixTag::Other, -1, false),
    ])
    .access_bytes()
    .unwrap();
    let default = PosixAcl::from_aces(vec![
        p_ace(PosixTag::UserObj, -1, true),
        p_ace(PosixTag::GroupObj, -1, true),
        p_ace(PosixTag::Other, -1, true),
    ]);
    // POSIX low-level, with a default ACL then without one.
    let _ = fsetacl_posix(d.as_fd(), &access, default.default_bytes().unwrap().as_deref());
    let _ = fsetacl_posix(d.as_fd(), &access, None);
    // NFS4 low-level (empty, trivially valid): fails on a non-NFS4 fs but exercises parse + validate + the
    // fsetxattr call.
    let nfs4 = Nfs4Acl {
        acl_flags: Nfs4AclFlag::empty(),
        aces: vec![],
    }
    .to_xattr()
    .unwrap();
    let _ = fsetacl_nfs4(d.as_fd(), &nfs4);
    assert!(!nfs4.is_empty(), "an empty ACL still serialises to bytes");

    // An *empty* slice is refused, on both raw paths, before it can reach the filesystem. The kernel leaves
    // `kvalue` NULL for a zero-length `setxattr` (`setxattr_copy`, `fs/xattr.c:655-669`) and ZFS reads `(NULL, 0)`
    // as the strip signal, so writing one would silently revert the object to mode-only permissions - the opposite
    // of the "deny everyone" a caller that filtered an ACL down to nothing means by it. Removal is `fsetacl(fd,
    // None)`.
    assert!(matches!(
        fsetacl_nfs4(d.as_fd(), &[]),
        Err(truenas_ros::Error::Errno(Errno::EINVAL))
    ));
    assert!(matches!(
        fsetacl_posix(d.as_fd(), &[], None),
        Err(truenas_ros::Error::Errno(Errno::EINVAL))
    ));
}
