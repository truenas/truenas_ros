//! Coverage-oriented integration tests (companion to `test.rs`), exercising the
//! error/errno/path plumbing and the many exposed-but-previously-untested paths
//! across each subsystem.
#![cfg(target_os = "linux")]

// ------------------------------------------------------------------ errno/error
mod errno_error {
    use std::io;
    use truenas_ros::errno::{Errno, ErrnoSentinel};
    use truenas_ros::Error;

    #[test]
    fn from_raw_known_and_unknown() {
        assert_eq!(Errno::from_raw(libc::EPERM), Errno::EPERM);
        assert_eq!(Errno::from_raw(libc::ENOENT), Errno::ENOENT);
        assert_eq!(Errno::from_raw(libc::EOPNOTSUPP), Errno::EOPNOTSUPP);
        assert_eq!(Errno::from_raw(0), Errno::UnknownErrno);
        assert_eq!(Errno::from_raw(999_999), Errno::UnknownErrno);
    }

    #[test]
    fn aliases() {
        assert_eq!(Errno::EWOULDBLOCK, Errno::EAGAIN);
        assert_eq!(Errno::EDEADLOCK, Errno::EDEADLK);
        assert_eq!(Errno::ENOTSUP, Errno::EOPNOTSUPP);
    }

    #[test]
    fn thread_local_get_set_clear() {
        Errno::EINVAL.set();
        assert_eq!(Errno::last(), Errno::EINVAL);
        assert_eq!(Errno::last_raw(), libc::EINVAL);
        Errno::clear();
        assert_eq!(Errno::last_raw(), 0);
        Errno::set_raw(libc::EIO);
        assert_eq!(Errno::last(), Errno::EIO);
        Errno::clear();
    }

    #[test]
    fn result_and_sentinel() {
        assert_eq!(<isize as ErrnoSentinel>::sentinel(), -1isize);
        Errno::EACCES.set();
        assert_eq!(Errno::result(-1isize), Err(Errno::EACCES));
        assert_eq!(Errno::result(7isize), Ok(7isize));
        Errno::clear();
    }

    #[test]
    fn display_and_io_roundtrip() {
        assert!(format!("{}", Errno::EIO).contains("EIO"));
        let io_err: io::Error = Errno::EIO.into();
        assert_eq!(io_err.raw_os_error(), Some(libc::EIO));
        assert_eq!(
            Errno::try_from(io::Error::from_raw_os_error(libc::EACCES)).ok(),
            Some(Errno::EACCES)
        );
        // An io::Error without an os error cannot convert.
        assert!(Errno::try_from(io::Error::other("x")).is_err());
    }

    #[test]
    fn from_raw_covers_every_known_value() {
        // Drive every arm of the `from_raw` match, plus Display, across the
        // whole Linux errno range.
        for e in 1..=133 {
            let errno = Errno::from_raw(e);
            let _ = format!("{errno}");
            if errno != Errno::UnknownErrno {
                assert_eq!(errno as i32, e);
            }
        }
    }

    #[test]
    fn error_display_all_variants() {
        use std::path::PathBuf;
        assert_eq!(
            format!("{}", Error::Errno(Errno::EIO)),
            format!("{}", Errno::EIO)
        );
        assert!(format!("{}", Error::Validation("bad".into())).contains("bad"));
        assert!(format!("{}", Error::Parse("boom".into())).contains("boom"));
        assert!(format!(
            "{}",
            Error::IteratorRestore {
                depth: 3,
                path: PathBuf::from("/x")
            }
        )
        .contains("depth 3"));
        assert!(format!(
            "{}",
            Error::MountSourceMismatch {
                expected: "a".into(),
                found: "b".into(),
                path: PathBuf::from("/m"),
            }
        )
        .contains("mismatch"));
        assert!(format!(
            "{}",
            Error::SymlinkInPath {
                path: PathBuf::from("/l")
            }
        )
        .contains("symlink"));
    }

    #[test]
    fn error_source_and_into_io() {
        use std::error::Error as _;
        assert!(Error::Errno(Errno::EIO).source().is_some());
        assert!(Error::Validation("x".into()).source().is_none());
        let e: Error = Errno::ENOENT.into();
        assert!(matches!(e, Error::Errno(Errno::ENOENT)));

        let io1: io::Error = Error::Errno(Errno::EACCES).into();
        assert_eq!(io1.raw_os_error(), Some(libc::EACCES));
        let io2: io::Error = Error::SymlinkInPath { path: "/l".into() }.into();
        assert_eq!(io2.raw_os_error(), Some(libc::ELOOP));
        let io3: io::Error = Error::Validation("x".into()).into();
        assert_eq!(io3.kind(), io::ErrorKind::InvalidInput);
    }
}

// ------------------------------------------------------------------------- path
mod path_tests {
    use std::ffi::{CString, OsStr};
    use std::path::{Path, PathBuf};
    use truenas_ros::errno::Errno;
    use truenas_ros::path::TnPath;

    #[test]
    fn len_and_is_empty_across_impls() {
        assert_eq!(TnPath::len("abc"), 3);
        assert_eq!(TnPath::len(OsStr::new("abcd")), 4);
        assert_eq!(TnPath::len(Path::new("abcde")), 5);
        assert_eq!(TnPath::len(&PathBuf::from("ab")), 2);
        assert_eq!(TnPath::len(b"abcdef" as &[u8]), 6);
        let cs = CString::new("xy").unwrap();
        assert_eq!(TnPath::len(cs.as_c_str()), 2);

        assert!(!TnPath::is_empty("x"));
        assert!(TnPath::is_empty(""));
        assert!(TnPath::is_empty(OsStr::new("")));
        assert!(TnPath::is_empty(Path::new("")));
        assert!(TnPath::is_empty(&PathBuf::from("")));
        assert!(TnPath::is_empty(b"" as &[u8]));
        assert!(TnPath::is_empty(CString::new("").unwrap().as_c_str()));
    }

    #[test]
    fn interior_nul_is_einval() {
        assert_eq!("a\0b".with_tn_path(|_| ()).unwrap_err(), Errno::EINVAL);
    }

    #[test]
    fn heap_fallback_for_long_paths() {
        // Longer than the 1024-byte stack buffer → heap CString path.
        let long = "a".repeat(2000);
        let n = long.as_str().with_tn_path(|c| c.to_bytes().len()).unwrap();
        assert_eq!(n, 2000);
    }

    #[test]
    fn every_impl_materialises_a_cstr() {
        let want = b"pth".to_vec();
        let get = |c: &std::ffi::CStr| c.to_bytes().to_vec();
        assert_eq!("pth".with_tn_path(get).unwrap(), want);
        assert_eq!(OsStr::new("pth").with_tn_path(get).unwrap(), want);
        assert_eq!(Path::new("pth").with_tn_path(get).unwrap(), want);
        assert_eq!(PathBuf::from("pth").with_tn_path(get).unwrap(), want);
        assert_eq!((b"pth" as &[u8]).with_tn_path(get).unwrap(), want);
        let cs = CString::new("pth").unwrap();
        assert_eq!(cs.as_c_str().with_tn_path(get).unwrap(), want);
    }
}

// --------------------------------------------------------------------------- fs
#[cfg(feature = "fs")]
mod fs {
    use truenas_ros::errno::Errno;
    use truenas_ros::fs::{
        makedev, openat2, renameat2, statx, AtFlags, Mode, OFlag, OpenHow,
        RenameFlags, ResolveFlag, StatxMask,
    };
    use truenas_ros::AT_FDCWD;

    #[test]
    fn statx_accessors_match_std_metadata() {
        use std::os::unix::fs::MetadataExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f");
        std::fs::write(&path, b"1234567").unwrap();
        let md = std::fs::metadata(&path).unwrap();

        let st = statx(
            AT_FDCWD,
            &path,
            AtFlags::empty(),
            StatxMask::BASIC_STATS | StatxMask::BTIME,
        )
        .unwrap();
        assert!(st.is_regular() && !st.is_dir() && !st.is_symlink());
        assert_eq!(st.size(), 7);
        assert_eq!(st.uid(), md.uid());
        assert_eq!(st.gid(), md.gid());
        assert_eq!(st.ino(), md.ino());
        assert_eq!(u64::from(st.nlink()), md.nlink());
        assert_eq!(u32::from(st.mode()) & 0o777, md.mode() & 0o777);
        assert!(st.blksize() > 0);
        assert_eq!(st.mtime().sec, md.mtime());
        assert_eq!(makedev(st.dev_major(), st.dev_minor()), st.dev());
        // Exercise the remaining accessors / timestamp conversions.
        let _ = (st.blocks(), st.subvol(), st.mask(), st.attributes());
        let _ = (st.attributes_mask(), st.raw(), st.btime());
        let _ = (st.atime().as_secs_f64(), st.ctime().as_nanos());
        assert!(st.mtime().to_system_time().is_some());
    }

    #[test]
    fn statx_symlink_nofollow() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("t"), b"x").unwrap();
        std::os::unix::fs::symlink("t", dir.path().join("l")).unwrap();
        let link = dir.path().join("l");
        assert!(statx(AT_FDCWD, &link, AtFlags::empty(), StatxMask::TYPE)
            .unwrap()
            .is_regular());
        assert!(statx(
            AT_FDCWD,
            &link,
            AtFlags::AT_SYMLINK_NOFOLLOW,
            StatxMask::TYPE
        )
        .unwrap()
        .is_symlink());
    }

    #[test]
    fn statx_device_file_rdev() {
        let st = match statx(
            AT_FDCWD,
            "/dev/null",
            AtFlags::empty(),
            StatxMask::BASIC_STATS,
        ) {
            Ok(s) => s,
            Err(_) => return,
        };
        assert_eq!(u32::from(st.mode()) & libc::S_IFMT, libc::S_IFCHR);
        assert_eq!(st.rdev(), makedev(1, 3));
    }

    #[test]
    fn makedev_encoding() {
        assert_eq!(makedev(0, 0), 0);
        assert_eq!(makedev(1, 3), 0x103);
        let (ma, mi) = (0x1234u64, 0x5678u64);
        assert_eq!(
            makedev(ma as u32, mi as u32),
            ((ma & 0xffff_f000) << 32)
                | ((ma & 0x0000_0fff) << 8)
                | ((mi & 0xffff_ff00) << 12)
                | (mi & 0x0000_00ff)
        );
    }

    #[test]
    fn openat2_creates_with_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("new");
        let how = OpenHow::new()
            .flags(OFlag::O_CREAT | OFlag::O_WRONLY | OFlag::O_EXCL)
            .mode(Mode::S_IRUSR | Mode::S_IWUSR)
            .resolve(ResolveFlag::empty());
        let _fd = openat2(AT_FDCWD, &path, how).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o600, 0o600);
    }

    #[test]
    fn renameat2_plain_and_error_flags() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a");
        let b = dir.path().join("b");
        let c = dir.path().join("c");
        std::fs::write(&a, b"data").unwrap();

        renameat2(AT_FDCWD, &a, AT_FDCWD, &b, RenameFlags::empty()).unwrap();
        assert!(!a.exists());
        assert_eq!(std::fs::read(&b).unwrap(), b"data");

        // EXCHANGE with a missing partner → ENOENT.
        assert_eq!(
            renameat2(AT_FDCWD, &b, AT_FDCWD, &c, RenameFlags::RENAME_EXCHANGE)
                .unwrap_err(),
            Errno::ENOENT
        );
        // NOREPLACE | EXCHANGE is contradictory → EINVAL.
        assert_eq!(
            renameat2(
                AT_FDCWD,
                &b,
                AT_FDCWD,
                &c,
                RenameFlags::RENAME_NOREPLACE | RenameFlags::RENAME_EXCHANGE,
            )
            .unwrap_err(),
            Errno::EINVAL
        );
    }
}

// ------------------------------------------------------------------------ xattr
#[cfg(feature = "xattr")]
mod xattr {
    use std::os::fd::AsFd;
    use truenas_ros::errno::Errno;
    use truenas_ros::xattr::{
        fgetxattr, flistxattr, fremovexattr, fsetxattr, XattrFlags,
        XATTR_SIZE_MAX,
    };

    fn tmp() -> (tempfile::TempDir, std::fs::File) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f");
        std::fs::write(&path, b"d").unwrap();
        let f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        (dir, f)
    }

    fn user_xattrs_supported(f: &std::fs::File) -> bool {
        match fsetxattr(f.as_fd(), "user.probe", b"1", XattrFlags::empty()) {
            Ok(()) => {
                let _ = fremovexattr(f.as_fd(), "user.probe");
                true
            }
            Err(Errno::EOPNOTSUPP) => false,
            Err(e) => panic!("probe: {e}"),
        }
    }

    #[test]
    fn size_max_constant() {
        assert_eq!(XATTR_SIZE_MAX, 2 * 1024 * 1024);
    }

    #[test]
    fn remove_and_create_replace_semantics() {
        let (_d, f) = tmp();
        if !user_xattrs_supported(&f) {
            return;
        }
        let n = "user.tn";
        fsetxattr(f.as_fd(), n, b"v1", XattrFlags::XATTR_CREATE).unwrap();
        // CREATE again → EEXIST, value unchanged.
        assert_eq!(
            fsetxattr(f.as_fd(), n, b"v2", XattrFlags::XATTR_CREATE)
                .unwrap_err(),
            Errno::EEXIST
        );
        assert_eq!(fgetxattr(f.as_fd(), n).unwrap(), b"v1");
        // REPLACE existing → ok; REPLACE missing → ENODATA.
        fsetxattr(f.as_fd(), n, b"v3", XattrFlags::XATTR_REPLACE).unwrap();
        assert_eq!(fgetxattr(f.as_fd(), n).unwrap(), b"v3");
        assert_eq!(
            fsetxattr(
                f.as_fd(),
                "user.absent",
                b"x",
                XattrFlags::XATTR_REPLACE
            )
            .unwrap_err(),
            Errno::ENODATA
        );
        // Remove, then get / re-remove both → ENODATA.
        fremovexattr(f.as_fd(), n).unwrap();
        assert_eq!(fgetxattr(f.as_fd(), n).unwrap_err(), Errno::ENODATA);
        assert_eq!(fremovexattr(f.as_fd(), n).unwrap_err(), Errno::ENODATA);
    }

    #[test]
    fn oversize_short_circuits_to_e2big() {
        let (_d, f) = tmp();
        // Rejected before any syscall, so filesystem support is irrelevant.
        let big = vec![0u8; XATTR_SIZE_MAX + 1];
        assert_eq!(
            fsetxattr(f.as_fd(), "user.big", &big, XattrFlags::empty())
                .unwrap_err(),
            Errno::E2BIG
        );
    }

    #[test]
    fn large_value_exercises_buffer_growth() {
        let (_d, f) = tmp();
        if !user_xattrs_supported(&f) {
            return;
        }
        let val = vec![7u8; 4096];
        match fsetxattr(f.as_fd(), "user.big", &val, XattrFlags::empty()) {
            Ok(()) => {
                assert_eq!(fgetxattr(f.as_fd(), "user.big").unwrap(), val);
                assert!(flistxattr(f.as_fd())
                    .unwrap()
                    .iter()
                    .any(|s| s == "user.big"));
            }
            // Some filesystems impose a smaller per-value limit.
            Err(Errno::E2BIG | Errno::ENOSPC) => {}
            Err(e) => panic!("{e}"),
        }
    }
}

// ------------------------------------------------------------------------ mount
#[cfg(feature = "mount")]
mod mount {
    use std::os::fd::AsFd;
    use std::path::Path;
    use truenas_ros::fs::{statx, AtFlags, OFlag, StatxMask};
    use truenas_ros::mount::{
        fsconfig, is_zfs_snapshot, listmount, mount_setattr, move_mount,
        open_mount_by_id, open_tree, statmount, statmount_path, umount,
        umount2, FsConfig, MntFlags, MntPropagation, MountAttr, MountSetattr,
        MoveMountFlags, OpenTreeFlags, StatmountMask, UmountOptions, LSMT_ROOT,
    };
    use truenas_ros::{Error, AT_FDCWD};

    fn root_id() -> u64 {
        statx(AT_FDCWD, "/", AtFlags::empty(), StatxMask::MNT_ID_UNIQUE)
            .unwrap()
            .mnt_id()
    }

    #[test]
    fn open_mount_by_id_opens_root() {
        let fd =
            open_mount_by_id(root_id(), OFlag::O_DIRECTORY | OFlag::O_RDONLY)
                .unwrap();
        let st = statx(fd.as_fd(), "", AtFlags::AT_EMPTY_PATH, StatxMask::TYPE)
            .unwrap();
        assert!(st.is_dir());
    }

    #[test]
    fn statmount_mask_filtering_and_invalid_id() {
        let sm = statmount(root_id(), StatmountMask::MNT_BASIC).unwrap();
        assert!(sm.mnt_id.is_some());
        assert!(sm.mnt_point.is_none());
        assert!(sm.fs_type.is_none());
        assert!(statmount(u64::MAX - 1, StatmountMask::MNT_BASIC).is_err());
    }

    #[test]
    fn listmount_forward_and_reverse() {
        let fwd = listmount(LSMT_ROOT, false).unwrap();
        let rev = listmount(LSMT_ROOT, true).unwrap();
        assert!(!fwd.is_empty());
        assert_eq!(fwd.len(), rev.len());
    }

    #[test]
    fn is_zfs_snapshot_false_for_root() {
        assert!(!is_zfs_snapshot(&statmount_path(Path::new("/")).unwrap()));
    }

    #[test]
    fn statmount_path_rejects_symlink() {
        let dir = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink("/", dir.path().join("l")).unwrap();
        assert!(matches!(
            statmount_path(&dir.path().join("l")).unwrap_err(),
            Error::SymlinkInPath { .. }
        ));
    }

    #[test]
    fn umount_error_paths() {
        assert!(umount2("/no/such/mount/xyz", MntFlags::empty()).is_err());
        let dir = tempfile::tempdir().unwrap();
        // Recursive umount of a non-mountpoint → validation error.
        assert!(matches!(
            umount(
                dir.path(),
                UmountOptions {
                    recursive: true,
                    ..Default::default()
                }
            )
            .unwrap_err(),
            Error::Validation(_)
        ));
        // Non-recursive umount of a non-mountpoint → syscall error.
        assert!(umount(dir.path(), UmountOptions::default()).is_err());
    }

    #[test]
    fn privileged_wrappers_are_callable() {
        // These need CAP_SYS_ADMIN; unprivileged they return an error. We only
        // drive the wrapper + errno mapping, so the outcome is not asserted.
        let _ = open_tree(AT_FDCWD, "/", OpenTreeFlags::OPEN_TREE_CLONE);
        let _ = move_mount(
            AT_FDCWD,
            "/proc/self/ns/mnt",
            AT_FDCWD,
            "/tmp",
            MoveMountFlags::empty(),
        );
        let anchor = std::fs::File::open("/").unwrap();
        let attr = MountSetattr::new()
            .set(MountAttr::RDONLY)
            .clear(MountAttr::NODEV)
            .propagation(MntPropagation::MS_SLAVE)
            .idmap(anchor.as_fd());
        let _ = mount_setattr(AT_FDCWD, "/", AtFlags::empty(), &attr);
    }

    #[test]
    fn fsconfig_variants_reach_the_syscall() {
        // fsopen needs CAP_SYS_ADMIN; drive fsconfig against a plain fd instead
        // — each command fails at the syscall but every match arm is exercised.
        let f = std::fs::File::open("/").unwrap();
        let fd = f.as_fd();
        let _ = fsconfig(fd, FsConfig::Flag { key: "ro" });
        let _ = fsconfig(
            fd,
            FsConfig::String {
                key: "src",
                value: "x",
            },
        );
        let _ = fsconfig(
            fd,
            FsConfig::Binary {
                key: "k",
                value: b"v",
            },
        );
        let _ = fsconfig(fd, FsConfig::Fd { key: "fd", fd });
        let _ = fsconfig(fd, FsConfig::Create);
        let _ = fsconfig(fd, FsConfig::Reconfigure);
        let _ = fsconfig(fd, FsConfig::CreateExcl);
    }
}

// -------------------------------------------------------------------------- acl
#[cfg(feature = "acl")]
mod acl {
    use std::os::fd::AsFd;
    use truenas_ros::acl::{
        fgetacl, fsetacl, validate_acl, Acl, AclTarget, Nfs4Ace, Nfs4AceType,
        Nfs4Acl, Nfs4AclFlag, Nfs4Flag, Nfs4Perm, Nfs4Who, PosixAce, PosixAcl,
        PosixPerm, PosixTag,
    };
    use truenas_ros::Error;

    fn nfs4(aces: Vec<Nfs4Ace>, flags: Nfs4AclFlag) -> Acl {
        Acl::Nfs4(Nfs4Acl {
            acl_flags: flags,
            aces,
        })
    }
    fn n_ace(t: Nfs4AceType, f: Nfs4Flag, who: Nfs4Who, id: i64) -> Nfs4Ace {
        Nfs4Ace::new(t, f, Nfs4Perm::READ_DATA, who, id)
    }

    #[test]
    fn nfs4_named_user_and_flags_roundtrip() {
        let acl = Nfs4Acl {
            acl_flags: Nfs4AclFlag::PROTECTED | Nfs4AclFlag::AUTO_INHERIT,
            aces: vec![n_ace(
                Nfs4AceType::Allow,
                Nfs4Flag::empty(),
                Nfs4Who::Named,
                1000,
            )],
        };
        let back = Nfs4Acl::from_xattr(&acl.to_xattr()).unwrap();
        assert_eq!(back.aces[0].who_type, Nfs4Who::Named);
        assert_eq!(back.aces[0].who_id, 1000);
        assert_eq!(back.acl_flags, acl.acl_flags);
    }

    #[test]
    fn nfs4_ace_new_forces_special_who_id() {
        assert_eq!(
            n_ace(Nfs4AceType::Allow, Nfs4Flag::empty(), Nfs4Who::Owner, 999)
                .who_id,
            -1
        );
        assert_eq!(
            n_ace(Nfs4AceType::Allow, Nfs4Flag::empty(), Nfs4Who::Named, 42)
                .who_id,
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
        // A non-inheritable parent ACE → error.
        let plain = Nfs4Acl {
            acl_flags: Nfs4AclFlag::empty(),
            aces: vec![n_ace(
                Nfs4AceType::Allow,
                Nfs4Flag::empty(),
                Nfs4Who::Owner,
                -1,
            )],
        };
        assert!(plain.generate_inherited_acl(true).is_err());
    }

    #[test]
    fn nfs4_validate_directory_rules() {
        // DENY for a special principal → rejected.
        assert!(validate_acl(
            AclTarget::AssumeDir,
            &nfs4(
                vec![n_ace(
                    Nfs4AceType::Deny,
                    Nfs4Flag::empty(),
                    Nfs4Who::Everyone,
                    -1
                )],
                Nfs4AclFlag::empty()
            )
        )
        .is_err());
        // INHERIT_ONLY without an inheritable bit → rejected.
        assert!(validate_acl(
            AclTarget::AssumeDir,
            &nfs4(
                vec![n_ace(
                    Nfs4AceType::Allow,
                    Nfs4Flag::INHERIT_ONLY,
                    Nfs4Who::Owner,
                    -1
                )],
                Nfs4AclFlag::empty()
            )
        )
        .is_err());
        // Directory ACL with no inheritable ACE → rejected.
        assert!(validate_acl(
            AclTarget::AssumeDir,
            &nfs4(
                vec![n_ace(
                    Nfs4AceType::Allow,
                    Nfs4Flag::empty(),
                    Nfs4Who::Owner,
                    -1
                )],
                Nfs4AclFlag::empty()
            )
        )
        .is_err());
        // A valid, inheritable directory ACL → ok; an empty ACL on a
        // directory → err (no inheritable ACE, matching the C).
        assert!(validate_acl(
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
        .is_ok());
        assert!(validate_acl(
            AclTarget::AssumeDir,
            &nfs4(vec![], Nfs4AclFlag::empty())
        )
        .is_err());
    }

    #[test]
    fn nfs4_validate_file_rejects_inherit_flags() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("f");
        std::fs::write(&p, b"x").unwrap();
        let f = std::fs::File::open(&p).unwrap();
        let acl = nfs4(
            vec![n_ace(
                Nfs4AceType::Allow,
                Nfs4Flag::FILE_INHERIT,
                Nfs4Who::Owner,
                -1,
            )],
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
        assert!(
            validate_acl(AclTarget::AssumeDir, &posix(valid_access())).is_ok()
        );
        // Missing each required tag → rejected.
        for skip in [PosixTag::UserObj, PosixTag::GroupObj, PosixTag::Other] {
            let aces: Vec<_> = valid_access()
                .into_iter()
                .filter(|a| a.tag != skip)
                .collect();
            assert!(
                validate_acl(AclTarget::AssumeDir, &posix(aces)).is_err(),
                "missing {skip:?} should be rejected"
            );
        }
        // Named USER without MASK → rejected; with MASK → ok.
        let mut aces = valid_access();
        aces.push(p_ace(PosixTag::User, 1000, false));
        assert!(
            validate_acl(AclTarget::AssumeDir, &posix(aces.clone())).is_err()
        );
        aces.push(p_ace(PosixTag::Mask, -1, false));
        assert!(validate_acl(AclTarget::AssumeDir, &posix(aces)).is_ok());
    }

    #[test]
    fn posix_default_only_valid_on_directory() {
        let dir = tempfile::tempdir().unwrap();
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
        assert!(acl.default_bytes().is_some());
        assert!(!acl.trivial());
        // Round-trip through the wire codec.
        let round = PosixAcl::from_xattr(
            &acl.access_bytes(),
            acl.default_bytes().as_deref(),
        )
        .unwrap();
        assert_eq!(round.access.len(), 3);
        assert_eq!(round.default.as_ref().unwrap().len(), 3);
        // Inheriting keeps a default for a dir, drops it for a file.
        assert!(acl.generate_inherited_acl(true).unwrap().default.is_some());
        assert!(acl.generate_inherited_acl(false).unwrap().default.is_none());
    }

    #[test]
    fn posix_from_xattr_rejects_bad_input() {
        assert!(matches!(
            PosixAcl::from_xattr(&[0u8], None),
            Err(Error::Parse(_))
        ));
        // version=2 header + one entry with an unknown tag (0x99).
        let mut buf = vec![2u8, 0, 0, 0];
        buf.extend_from_slice(&[0x99, 0, 0, 0, 0xff, 0xff, 0xff, 0xff]);
        assert!(matches!(
            PosixAcl::from_xattr(&buf, None),
            Err(Error::Parse(_))
        ));
    }

    #[test]
    fn fgetacl_on_a_plain_file() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("f");
        std::fs::write(&p, b"x").unwrap();
        let f = std::fs::File::open(&p).unwrap();
        match fgetacl(f.as_fd()) {
            // POSIX fs with no access xattr → synthesised from the mode bits.
            Ok(Acl::Posix(a)) => assert!(a.trivial()),
            Ok(Acl::Nfs4(_)) => {}
            Err(_) => {} // ACLs disabled entirely on this filesystem
        }
    }

    #[test]
    fn fsetacl_posix_roundtrip_if_supported() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("f");
        std::fs::write(&p, b"x").unwrap();
        let f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&p)
            .unwrap();
        let acl = Acl::Posix(PosixAcl::from_aces(vec![
            p_ace(PosixTag::UserObj, -1, false),
            p_ace(PosixTag::GroupObj, -1, false),
            p_ace(PosixTag::Other, -1, false),
        ]));
        // An Err here just means the filesystem doesn't support POSIX ACL
        // writes; skip in that case.
        if let Ok(()) = fsetacl(f.as_fd(), Some(&acl)) {
            let _ = fgetacl(f.as_fd()).unwrap(); // read back
            fsetacl(f.as_fd(), None).unwrap(); // remove
        }
    }

    #[test]
    fn low_level_fsetacl_paths() {
        use truenas_ros::acl::{fsetacl_nfs4, fsetacl_posix};
        let dir = tempfile::tempdir().unwrap();
        let d = std::fs::File::open(dir.path()).unwrap();
        let access = PosixAcl::from_aces(vec![
            p_ace(PosixTag::UserObj, -1, false),
            p_ace(PosixTag::GroupObj, -1, false),
            p_ace(PosixTag::Other, -1, false),
        ])
        .access_bytes();
        let default = PosixAcl::from_aces(vec![
            p_ace(PosixTag::UserObj, -1, true),
            p_ace(PosixTag::GroupObj, -1, true),
            p_ace(PosixTag::Other, -1, true),
        ]);
        // POSIX low-level, with a default ACL then without one.
        let _ = fsetacl_posix(
            d.as_fd(),
            &access,
            default.default_bytes().as_deref(),
        );
        let _ = fsetacl_posix(d.as_fd(), &access, None);
        // NFS4 low-level (empty, trivially valid): fails on a non-NFS4 fs but
        // exercises parse + validate + the fsetxattr call.
        let nfs4 = Nfs4Acl {
            acl_flags: Nfs4AclFlag::empty(),
            aces: vec![],
        }
        .to_xattr();
        let _ = fsetacl_nfs4(d.as_fd(), &nfs4);
    }
}

// ---------------------------------------------------------------------- fhandle
#[cfg(feature = "fhandle")]
mod fhandle {
    use std::os::fd::AsFd;
    use truenas_ros::errno::Errno;
    use truenas_ros::fhandle::{name_to_handle_at, FhFlags, FileHandle};
    use truenas_ros::fs::OFlag;
    use truenas_ros::{Error, AT_FDCWD};

    #[test]
    fn from_bytes_validates_lengths() {
        assert!(matches!(
            FileHandle::from_bytes(&[0u8; 4], 1, false),
            Err(Error::Validation(_))
        ));
        assert!(matches!(
            FileHandle::from_bytes(&[0u8; 200], 1, false),
            Err(Error::Validation(_))
        ));
        // handle_bytes = 100 but no data follows.
        let mut buf = vec![0u8; 8];
        buf[0] = 100;
        assert!(matches!(
            FileHandle::from_bytes(&buf, 1, false),
            Err(Error::Validation(_))
        ));
    }

    #[test]
    fn accessors_and_bytes_roundtrip() {
        let h = FileHandle::from_bytes(&[0u8; 8], 42, true).unwrap();
        assert_eq!(h.mount_id(), 42);
        assert!(h.unique_mount_id());
        assert_eq!(h.to_bytes(), vec![0u8; 8]);
        assert!(!FileHandle::from_bytes(&[0u8; 8], 42, false)
            .unwrap()
            .unique_mount_id());
    }

    #[test]
    fn open_uninitialised_is_rejected() {
        // u64::MAX is the uninitialised sentinel.
        let h = FileHandle::from_bytes(&[0u8; 8], u64::MAX, true).unwrap();
        let root = std::fs::File::open("/").unwrap();
        assert!(matches!(
            h.open(root.as_fd(), OFlag::O_RDONLY),
            Err(Error::Validation(_))
        ));
    }

    #[test]
    fn open_wrong_mount_id_is_rejected() {
        let h = FileHandle::from_bytes(&[0u8; 8], 1, true).unwrap();
        let root = std::fs::File::open("/").unwrap();
        match h.open(root.as_fd(), OFlag::O_RDONLY) {
            // Mount-id mismatch (expected), or a fluke match then a syscall
            // errno (e.g. seccomp ENOSYS) — never success.
            Err(Error::Validation(_)) | Err(Error::Errno(_)) => {}
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn name_to_handle_nonexistent_path() {
        assert!(matches!(
            name_to_handle_at(
                AT_FDCWD,
                "/no/such/path/xyz",
                FhFlags::AT_HANDLE_MNT_ID_UNIQUE
            )
            .unwrap_err(),
            Error::Errno(Errno::ENOENT)
        ));
    }

    #[test]
    fn different_paths_yield_different_handles() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a");
        let b = dir.path().join("b");
        std::fs::write(&a, b"a").unwrap();
        std::fs::write(&b, b"b").unwrap();
        let ha = match name_to_handle_at(
            AT_FDCWD,
            &a,
            FhFlags::AT_HANDLE_MNT_ID_UNIQUE,
        ) {
            Ok(h) => h,
            Err(Error::Errno(Errno::EOPNOTSUPP)) => return,
            Err(e) => panic!("{e}"),
        };
        let hb =
            name_to_handle_at(AT_FDCWD, &b, FhFlags::AT_HANDLE_MNT_ID_UNIQUE)
                .unwrap();
        assert_ne!(ha.to_bytes(), hb.to_bytes());
        assert_eq!(ha.mount_id(), hb.mount_id());
    }
}

// ----------------------------------------------------------------------- fsiter
#[cfg(feature = "fsiter")]
mod fsiter {
    use truenas_ros::errno::Errno;
    use truenas_ros::fs::{statx, AtFlags, OFlag, StatxMask};
    use truenas_ros::iter::{Cookie, DirStackEntry, EntryType, FsIterBuilder};
    use truenas_ros::{Error, AT_FDCWD};

    /// The mount source of `p`, so the fsiter source-check matches on kernels
    /// that report `sb_source`. Where it is not reported (e.g. the TrueNAS 6.12
    /// kernel) this returns a placeholder and the check is skipped anyway.
    fn fs_source(p: &std::path::Path) -> String {
        truenas_ros::mount::statmount_path(p)
            .ok()
            .and_then(|sm| sm.sb_source)
            .unwrap_or_else(|| "x".to_string())
    }

    #[test]
    fn relative_path_scopes_iteration() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("sub")).unwrap();
        std::fs::write(dir.path().join("sub/inner"), b"x").unwrap();
        std::fs::write(dir.path().join("outside"), b"y").unwrap();
        let it = FsIterBuilder::new(dir.path(), fs_source(dir.path()))
            .relative_path("sub")
            .build()
            .unwrap();
        let names: Vec<_> = it
            .map(|e| e.unwrap().name().to_string_lossy().into_owned())
            .collect();
        assert!(names.contains(&"inner".to_string()));
        assert!(!names.contains(&"outside".to_string()));
    }

    #[test]
    fn build_on_a_file_is_enotdir() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("f");
        std::fs::write(&p, b"x").unwrap();
        assert!(matches!(
            FsIterBuilder::new(&p, "x").build().unwrap_err(),
            Error::Errno(Errno::ENOTDIR)
        ));
    }

    #[test]
    fn file_open_flags_dir_stack_and_entry_helpers() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("d")).unwrap();
        std::fs::write(dir.path().join("d/f"), b"hello").unwrap();
        let mut it = FsIterBuilder::new(dir.path(), fs_source(dir.path()))
            .file_open_flags(OFlag::O_RDONLY | OFlag::O_NOFOLLOW)
            .build()
            .unwrap();
        let mut saw = false;
        let mut max_depth = 0;
        while let Some(res) = it.next() {
            let e = res.unwrap();
            max_depth = max_depth.max(it.dir_stack().len());
            if e.name() == "f" {
                saw = true;
                assert!(e.is_regular());
                assert_eq!(e.file_type(), EntryType::File);
                assert_eq!(e.path(), dir.path().join("d").join("f"));
                assert_eq!(e.parent(), dir.path().join("d"));
                let fd = e.into_fd();
                use std::os::fd::AsFd;
                let st = statx(
                    fd.as_fd(),
                    "",
                    AtFlags::AT_EMPTY_PATH,
                    StatxMask::SIZE,
                )
                .unwrap();
                assert_eq!(st.size(), 5);
            }
        }
        assert!(saw);
        assert!(max_depth >= 1);
    }

    #[test]
    fn btime_cutoff_skips_newer_files() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("f");
        std::fs::write(&p, b"x").unwrap();
        let st =
            statx(AT_FDCWD, &p, AtFlags::empty(), StatxMask::BTIME).unwrap();
        // Skip when the filesystem doesn't record a birth time.
        if !st.mask().contains(StatxMask::BTIME) || st.btime().sec <= 0 {
            return;
        }
        let it = FsIterBuilder::new(dir.path(), fs_source(dir.path()))
            .btime_cutoff(st.btime().sec - 1)
            .build()
            .unwrap();
        let names: Vec<_> = it
            .map(|e| e.unwrap().name().to_string_lossy().into_owned())
            .collect();
        assert!(!names.contains(&"f".to_string()));
    }

    #[test]
    fn empty_directory_yields_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let mut it = FsIterBuilder::new(dir.path(), fs_source(dir.path()))
            .build()
            .unwrap();
        assert!(it.next().is_none());
        assert_eq!(it.stats().count, 0);
    }

    #[test]
    fn deep_nesting_is_fully_walked() {
        let dir = tempfile::tempdir().unwrap();
        let mut p = dir.path().to_path_buf();
        for i in 0..12 {
            p = p.join(format!("d{i}"));
        }
        std::fs::create_dir_all(&p).unwrap();
        std::fs::write(p.join("leaf"), b"z").unwrap();
        let count = FsIterBuilder::new(dir.path(), fs_source(dir.path()))
            .build()
            .unwrap()
            .map(Result::unwrap)
            .count();
        assert_eq!(count, 13); // 12 dirs + 1 leaf
    }

    #[test]
    fn unreadable_regular_file_is_skipped() {
        use std::os::unix::fs::PermissionsExt;
        // Root bypasses mode bits, so this only holds unprivileged.
        if unsafe { libc::getuid() } == 0 {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("ok"), b"x").unwrap();
        let bad = dir.path().join("bad");
        std::fs::write(&bad, b"y").unwrap();
        std::fs::set_permissions(&bad, std::fs::Permissions::from_mode(0o000))
            .unwrap();
        // "bad" hits the EACCES branch (retry O_RDONLY, still denied → skip).
        let names: Vec<_> =
            FsIterBuilder::new(dir.path(), fs_source(dir.path()))
                .build()
                .unwrap()
                .map(|e| e.unwrap().name().to_string_lossy().into_owned())
                .collect();
        assert!(names.contains(&"ok".to_string()));
        assert!(!names.contains(&"bad".to_string()));
    }

    #[test]
    fn cookie_bytes_round_trip_including_non_utf8_path() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        let ck = Cookie::from(vec![
            DirStackEntry {
                path: "/mnt/tank".into(),
                ino: 2,
            },
            DirStackEntry {
                path: std::path::PathBuf::from(OsStr::from_bytes(
                    b"/mnt/tank/we\xffird",
                )),
                ino: 42,
            },
        ]);
        let back = Cookie::from_bytes(&ck.to_bytes()).unwrap();
        assert_eq!(back, ck);
        assert_eq!(back.len(), 2);
        assert_eq!(back.entries()[1].ino, 42);
    }

    #[test]
    fn cookie_from_bytes_rejects_malformed() {
        // Empty / too short for even the header.
        assert!(matches!(Cookie::from_bytes(&[]), Err(Error::Validation(_))));
        // Ten bytes but a bad magic.
        assert!(matches!(
            Cookie::from_bytes(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]),
            Err(Error::Validation(_))
        ));
        let good = Cookie::from(vec![DirStackEntry {
            path: "/a".into(),
            ino: 5,
        }])
        .to_bytes();
        assert!(Cookie::from_bytes(&good).is_ok());
        // A byte lopped off ⇒ truncated; a byte added ⇒ trailing garbage.
        let mut truncated = good.clone();
        truncated.pop();
        assert!(matches!(
            Cookie::from_bytes(&truncated),
            Err(Error::Validation(_))
        ));
        let mut trailing = good.clone();
        trailing.push(0);
        assert!(matches!(
            Cookie::from_bytes(&trailing),
            Err(Error::Validation(_))
        ));
    }

    #[test]
    fn empty_and_single_level_cookies_walk_the_whole_tree() {
        use std::collections::BTreeSet;
        use std::os::unix::fs::MetadataExt;
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("sub")).unwrap();
        std::fs::write(root.join("sub/f"), b"x").unwrap();
        std::fs::write(root.join("g"), b"y").unwrap();
        let walk = |b: FsIterBuilder| -> BTreeSet<String> {
            b.build()
                .unwrap()
                .map(|r| r.unwrap().name().to_string_lossy().into_owned())
                .collect()
        };
        let full = walk(FsIterBuilder::new(root, fs_source(root)));

        // Empty cookie ⇒ no resume ⇒ full walk.
        let empty = walk(
            FsIterBuilder::new(root, fs_source(root))
                .resume_from(Cookie::default()),
        );
        assert_eq!(empty, full);

        // A single-level (root-only) cookie re-reads root from the start ⇒
        // also a full walk (the root inode must match).
        let ck = Cookie::from(vec![DirStackEntry {
            path: root.to_path_buf(),
            ino: std::fs::metadata(root).unwrap().ino(),
        }]);
        let one =
            walk(FsIterBuilder::new(root, fs_source(root)).resume_from(ck));
        assert_eq!(one, full);
    }

    #[test]
    fn resume_from_wrong_root_inode_is_restore_depth_0() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let ck = Cookie::from(vec![DirStackEntry {
            path: root.to_path_buf(),
            ino: u64::MAX, // definitely not the real root inode
        }]);
        let err = FsIterBuilder::new(root, fs_source(root))
            .resume_from(ck)
            .build()
            .unwrap_err();
        assert!(matches!(err, Error::IteratorRestore { depth: 0, .. }));
    }

    #[test]
    fn cookie_deeper_than_max_depth_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        // MAX_DEPTH is 2048; a longer cookie is rejected before any descent.
        let entries: Vec<DirStackEntry> = (0..2049)
            .map(|i| DirStackEntry {
                path: format!("/x/{i}").into(),
                ino: i as u64,
            })
            .collect();
        let err = FsIterBuilder::new(root, fs_source(root))
            .resume_from(Cookie::from(entries))
            .build()
            .unwrap_err();
        assert!(matches!(err, Error::Validation(_)));
    }

    #[test]
    fn seed_stats_continues_running_totals() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(root.join("f"), b"xyz").unwrap();
        let mut it = FsIterBuilder::new(root, fs_source(root))
            .seed_stats(100, 1000)
            .build()
            .unwrap();
        // The seed is in effect before anything is yielded.
        assert_eq!(it.stats().count, 100);
        assert_eq!(it.stats().bytes, 1000);
        for r in it.by_ref() {
            r.unwrap();
        }
        // One 3-byte file added on top of the seed.
        assert_eq!(it.stats().count, 101);
        assert_eq!(it.stats().bytes, 1003);
    }
}

// --------------------------------------------------------------------------- io
#[cfg(feature = "fs")]
mod io {
    use std::io::{Read, Write};
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use truenas_ros::errno::Errno;
    use truenas_ros::fs::{
        atomic_replace, atomic_write, safe_open, AtomicWriteOptions, Mode,
        OFlag,
    };
    use truenas_ros::{Error, AT_FDCWD};

    #[test]
    fn atomic_write_sets_mode_and_preserves_owner() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("cfg");
        let (uid, gid) =
            unsafe { (libc::getuid() as u32, libc::getgid() as u32) };
        let opts = AtomicWriteOptions {
            uid: Some(uid),
            gid: Some(gid),
            mode: 0o600,
            noclobber: false,
        };
        atomic_replace(&target, b"secret", opts).unwrap();
        let md = std::fs::metadata(&target).unwrap();
        assert_eq!(md.permissions().mode() & 0o777, 0o600);
        assert_eq!(md.uid(), uid);
        assert_eq!(md.gid(), gid);
        assert_eq!(std::fs::read(&target).unwrap(), b"secret");
    }

    #[test]
    fn failed_write_leaves_target_and_no_temp() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("cfg");
        atomic_replace(&target, b"original", AtomicWriteOptions::default())
            .unwrap();
        let err = atomic_write(&target, AtomicWriteOptions::default(), |f| {
            f.write_all(b"partial")?;
            Err(std::io::Error::other("boom"))
        })
        .unwrap_err();
        assert!(matches!(err, Error::Errno(_)));
        assert_eq!(std::fs::read(&target).unwrap(), b"original");
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .filter(|n| n != "cfg")
            .collect();
        assert!(leftovers.is_empty(), "temp left: {leftovers:?}");
    }

    #[test]
    fn noclobber_creates_new_but_refuses_existing() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("once");
        let opts = AtomicWriteOptions {
            noclobber: true,
            ..Default::default()
        };
        atomic_replace(&target, b"v1", opts).unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"v1");
        assert!(matches!(
            atomic_replace(&target, b"v2", opts).unwrap_err(),
            Error::Errno(Errno::EEXIST)
        ));
        assert_eq!(std::fs::read(&target).unwrap(), b"v1");
    }

    #[test]
    fn rejects_target_without_file_name() {
        assert!(matches!(
            atomic_replace(
                std::path::Path::new("/"),
                b"x",
                AtomicWriteOptions::default()
            ),
            Err(Error::Validation(_))
        ));
    }

    #[test]
    fn safe_open_returns_usable_file() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("f");
        std::fs::write(&p, b"hello world").unwrap();
        let mut f =
            safe_open(AT_FDCWD, &p, OFlag::O_RDONLY, Mode::empty()).unwrap();
        let mut s = String::new();
        f.read_to_string(&mut s).unwrap();
        assert_eq!(s, "hello world");
    }

    #[test]
    fn safe_open_creates_a_file() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("new");
        let mut f = safe_open(
            AT_FDCWD,
            &p,
            OFlag::O_CREAT | OFlag::O_WRONLY,
            Mode::S_IRUSR | Mode::S_IWUSR,
        )
        .unwrap();
        f.write_all(b"data").unwrap();
        drop(f);
        assert_eq!(std::fs::read(&p).unwrap(), b"data");
    }

    #[test]
    fn safe_open_propagates_other_errors() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nope");
        assert!(
            safe_open(AT_FDCWD, &missing, OFlag::O_RDONLY, Mode::empty())
                .is_err()
        );
    }
}

// ----------------------------------------------------------------------- shutil
#[cfg(feature = "shutil")]
mod shutil {
    use std::os::fd::AsFd;
    use std::os::unix::fs::PermissionsExt;
    use truenas_ros::errno::Errno;
    use truenas_ros::shutil::{
        clonefile, copy_permissions, copy_xattrs, copyfile, copysendfile,
        copytree, copyuserspace, CopyFlags, CopyTreeConfig, CopyTreeOp,
        MAX_RW_SZ,
    };

    fn pair(src: &[u8]) -> (tempfile::TempDir, std::fs::File, std::fs::File) {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("s"), src).unwrap();
        let s = std::fs::File::open(dir.path().join("s")).unwrap();
        let d = std::fs::File::create(dir.path().join("d")).unwrap();
        (dir, s, d)
    }

    #[test]
    fn max_rw_sz_constant() {
        assert_eq!(MAX_RW_SZ, 0x7FFF_FFFF & !0xFFF);
    }

    #[test]
    fn copyuserspace_copies_and_empty_is_zero() {
        let (dir, s, d) = pair(b"hello world");
        assert_eq!(copyuserspace(s.as_fd(), d.as_fd()).unwrap(), 11);
        drop(d);
        assert_eq!(
            std::fs::read(dir.path().join("d")).unwrap(),
            b"hello world"
        );
        let (_d2, s2, d2) = pair(b"");
        assert_eq!(copyuserspace(s2.as_fd(), d2.as_fd()).unwrap(), 0);
    }

    #[test]
    fn copysendfile_copies_and_empty_falls_back() {
        let (dir, s, d) = pair(b"abcdef");
        assert_eq!(copysendfile(s.as_fd(), d.as_fd()).unwrap(), 6);
        drop(d);
        assert_eq!(std::fs::read(dir.path().join("d")).unwrap(), b"abcdef");
        // Empty source: sendfile transfers nothing → userspace fallback → 0.
        let (_d2, s2, d2) = pair(b"");
        assert_eq!(copysendfile(s2.as_fd(), d2.as_fd()).unwrap(), 0);
    }

    #[test]
    fn clonefile_and_copyfile() {
        let (dir, s, d) = pair(b"clone me");
        match clonefile(s.as_fd(), d.as_fd()) {
            Ok(n) => {
                assert_eq!(n, 8);
                drop(d);
                assert_eq!(
                    std::fs::read(dir.path().join("d")).unwrap(),
                    b"clone me"
                );
            }
            // copy_file_range may be unsupported here.
            Err(
                Errno::EXDEV
                | Errno::ENOSYS
                | Errno::EOPNOTSUPP
                | Errno::EINVAL,
            ) => {}
            Err(e) => panic!("clonefile: {e}"),
        }
        // copyfile always lands the content (clone or fallback).
        let (dir2, s2, d2) = pair(b"copy me");
        copyfile(s2.as_fd(), d2.as_fd()).unwrap();
        drop(d2);
        assert_eq!(std::fs::read(dir2.path().join("d")).unwrap(), b"copy me");
    }

    #[test]
    fn copy_permissions_fchmod_path() {
        let (_dir, s, d) = pair(b"x");
        copy_permissions(s.as_fd(), d.as_fd(), &[], 0o640).unwrap();
        assert_eq!(d.metadata().unwrap().permissions().mode() & 0o777, 0o640);
    }

    #[test]
    fn copy_xattrs_skips_acl_and_system() {
        use truenas_ros::xattr::{fgetxattr, fsetxattr, XattrFlags};
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("s"), b"x").unwrap();
        let s = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(dir.path().join("s"))
            .unwrap();
        let d = std::fs::File::create(dir.path().join("d")).unwrap();
        if fsetxattr(s.as_fd(), "user.keep", b"v", XattrFlags::empty()).is_err()
        {
            return; // user xattrs unsupported here
        }
        // A system/ACL name in the list must be skipped without error.
        let names =
            vec!["user.keep".to_string(), "system.posix_acl_access".into()];
        copy_xattrs(s.as_fd(), d.as_fd(), &names).unwrap();
        assert_eq!(fgetxattr(d.as_fd(), "user.keep").unwrap(), b"v");
        assert!(fgetxattr(d.as_fd(), "system.posix_acl_access").is_err());
    }

    #[test]
    fn copytree_op_variants_and_exist_ok() {
        for op in [
            CopyTreeOp::Default,
            CopyTreeOp::Sendfile,
            CopyTreeOp::Userspace,
        ] {
            let tmp = tempfile::tempdir().unwrap();
            let src = tmp.path().join("src");
            let dst = tmp.path().join("dst");
            std::fs::create_dir_all(src.join("sub")).unwrap();
            std::fs::write(src.join("a"), vec![1u8; 100]).unwrap();
            std::fs::write(src.join("sub/b"), b"bb").unwrap();
            let stats = copytree(
                &src,
                &dst,
                &CopyTreeConfig {
                    op,
                    ..Default::default()
                },
            )
            .unwrap();
            assert_eq!(stats.files, 2);
            assert_eq!(std::fs::read(dst.join("a")).unwrap(), vec![1u8; 100]);
            // exist_ok = false on an existing destination → error.
            assert!(copytree(
                &src,
                &dst,
                &CopyTreeConfig {
                    exist_ok: false,
                    ..Default::default()
                }
            )
            .is_err());
        }
    }

    #[test]
    fn copytree_permissions_only_flag() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        let dst = tmp.path().join("dst");
        std::fs::create_dir(&src).unwrap();
        std::fs::write(src.join("f"), b"x").unwrap();
        std::fs::set_permissions(
            src.join("f"),
            std::fs::Permissions::from_mode(0o640),
        )
        .unwrap();
        copytree(
            &src,
            &dst,
            &CopyTreeConfig {
                flags: CopyFlags::PERMISSIONS,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(
            std::fs::metadata(dst.join("f"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o640
        );
    }

    #[test]
    fn copytree_defers_root_metadata_so_children_are_creatable() {
        // Regression: the destination root's permissions must be applied AFTER
        // the walk. A read-only source root would otherwise make the dst root
        // unwritable before its children are created (EACCES unprivileged).
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        let dst = tmp.path().join("dst");
        std::fs::create_dir(&src).unwrap();
        std::fs::write(src.join("child"), b"hi").unwrap();
        std::fs::set_permissions(&src, std::fs::Permissions::from_mode(0o555))
            .unwrap();

        let config = CopyTreeConfig {
            flags: CopyFlags::PERMISSIONS,
            ..Default::default()
        };
        let res = copytree(&src, &dst, &config);

        // Restore write so the tempdir cleanup can remove the tree.
        let _ = std::fs::set_permissions(
            &src,
            std::fs::Permissions::from_mode(0o755),
        );

        let stats = res.expect("read-only-rooted copytree should succeed");
        assert_eq!(stats.files, 1);
        assert_eq!(std::fs::read(dst.join("child")).unwrap(), b"hi");
        // The root's restrictive mode is still applied — just last.
        assert_eq!(
            std::fs::metadata(&dst).unwrap().permissions().mode() & 0o777,
            0o555
        );
        let _ = std::fs::set_permissions(
            &dst,
            std::fs::Permissions::from_mode(0o755),
        );
    }
}

// ------------------------------------------------------------------- configfile

#[cfg(feature = "configfile")]
mod configfile {
    use truenas_ros::configfile::ConfigFile;
    use truenas_ros::Error;

    #[test]
    fn writes_global_section_byte_exact() {
        // The exact bytes the TrueNAS `configfile.py` wrapper emits via
        // `configparser` for its `[GLOBAL]` section: keys lowercased, `" = "`
        // delimiter, `str(bool)` booleans, a trailing blank line.
        let mut cfg = ConfigFile::new();
        cfg.add_section("GLOBAL").unwrap();
        cfg.set_bool("GLOBAL", "Enabled", false).unwrap();
        cfg.set_int("GLOBAL", "MaxConcurrentJobs", 4).unwrap();
        cfg.set_int("GLOBAL", "ReportingStatsWriteInterval", 120)
            .unwrap();
        cfg.set_int("GLOBAL", "RewriteChunkSize", 2048).unwrap();
        cfg.set_int("GLOBAL", "ReportingCallbackInterval", 200)
            .unwrap();
        cfg.set_int("GLOBAL", "MaxUsedPercent", 85).unwrap();
        cfg.set_int("GLOBAL", "StatsFlushInterval", 1).unwrap();
        let expected = "[GLOBAL]\n\
             enabled = False\n\
             maxconcurrentjobs = 4\n\
             reportingstatswriteinterval = 120\n\
             rewritechunksize = 2048\n\
             reportingcallbackinterval = 200\n\
             maxusedpercent = 85\n\
             statsflushinterval = 1\n\n";
        assert_eq!(cfg.write_string(), expected);
    }

    #[test]
    fn serialization_modes_and_multiline() {
        let mut cfg = ConfigFile::raw();
        cfg.read_str("[s]\nk = one\n  two\n").unwrap();
        // A newline in a value is re-indented with a tab.
        assert_eq!(cfg.write_string(), "[s]\nk = one\n\ttwo\n\n");
        // `space_around=false` drops the padding.
        assert_eq!(cfg.to_string_with(false), "[s]\nk=one\n\ttwo\n\n");
    }

    #[test]
    fn default_section_written_first() {
        let mut cfg = ConfigFile::raw();
        cfg.read_str("[s]\nk = v\n[DEFAULT]\nd = 1\n").unwrap();
        assert_eq!(cfg.write_string(), "[DEFAULT]\nd = 1\n\n[s]\nk = v\n\n");
    }

    #[test]
    fn keys_lowercased_sections_case_sensitive() {
        let mut cfg = ConfigFile::new();
        cfg.read_str("[Sec]\nKey = V\n[sec]\nKey = W\n").unwrap();
        assert_eq!(cfg.sections(), vec!["Sec", "sec"]);
        assert_eq!(cfg.get_raw("Sec", "KEY"), Some("V"));
        assert_eq!(cfg.get_raw("sec", "key"), Some("W"));
        assert!(cfg.has_section("Sec") && !cfg.has_section("SEC"));
    }

    #[test]
    fn inline_comment_chars_are_not_comments() {
        let mut cfg = ConfigFile::new();
        cfg.read_str("# top\n[s]\n  ; indented\nk = a ; b\nj = c # d\n")
            .unwrap();
        assert_eq!(cfg.get_raw("s", "k"), Some("a ; b"));
        assert_eq!(cfg.get_raw("s", "j"), Some("c # d"));
    }

    #[test]
    fn multiline_values_join_and_rstrip() {
        let mut cfg = ConfigFile::raw();
        cfg.read_str("[s]\nk = one\n  two\n\n  three\n  \n")
            .unwrap();
        assert_eq!(cfg.get_raw("s", "k"), Some("one\ntwo\n\nthree"));
    }

    #[test]
    fn default_inheritance_and_override() {
        let mut cfg = ConfigFile::new();
        cfg.read_str("[DEFAULT]\nd = base\nk = def\n[s]\nk = over\n")
            .unwrap();
        assert_eq!(cfg.get("s", "d").unwrap().as_deref(), Some("base"));
        assert_eq!(cfg.get("s", "k").unwrap().as_deref(), Some("over"));
        assert!(cfg.has_option("s", "d"));
        let opts = cfg.options("s").unwrap();
        assert!(opts.iter().any(|o| o == "d"));
        assert!(opts.iter().any(|o| o == "k"));
    }

    #[test]
    fn rejects_malformed_documents() {
        for doc in [
            "k = v\n",         // no section header
            "[s]\n[s]\n",      // duplicate section
            "[s]\nk=1\nk=2\n", // duplicate option
            "[s]\n = v\n",     // empty option name
            "[s]\n  orphan\n", // continuation with no prior option
        ] {
            assert!(
                matches!(ConfigFile::new().read_str(doc), Err(Error::Parse(_))),
                "should reject {doc:?}"
            );
        }
    }

    #[test]
    fn typed_getters_and_bad_values() {
        let mut cfg = ConfigFile::new();
        cfg.read_str("[s]\nn = 42\nneg = -7\nf = 3.5\nb = ON\nbad = xx\n")
            .unwrap();
        assert_eq!(cfg.get_int("s", "n").unwrap(), Some(42));
        assert_eq!(cfg.get_int("s", "neg").unwrap(), Some(-7));
        assert_eq!(cfg.get_float("s", "f").unwrap(), Some(3.5));
        assert_eq!(cfg.get_bool("s", "b").unwrap(), Some(true));
        assert!(matches!(cfg.get_int("s", "bad"), Err(Error::Parse(_))));
        assert!(matches!(cfg.get_bool("s", "bad"), Err(Error::Parse(_))));
        assert_eq!(cfg.get_int("s", "absent").unwrap(), None);
    }

    #[test]
    fn boolean_states() {
        let mut cfg = ConfigFile::new();
        cfg.read_str(
            "[s]\na=1\nb=yes\nc=true\nd=on\ne=0\nf=no\ng=false\nh=off\n",
        )
        .unwrap();
        for k in ["a", "b", "c", "d"] {
            assert_eq!(cfg.get_bool("s", k).unwrap(), Some(true));
        }
        for k in ["e", "f", "g", "h"] {
            assert_eq!(cfg.get_bool("s", k).unwrap(), Some(false));
        }
    }

    #[test]
    fn interpolation_basic_and_escapes() {
        let mut cfg = ConfigFile::new();
        cfg.read_str(
            "[DEFAULT]\nbase = /srv\n[s]\np = %(base)s/x\nlit = 100%%\n",
        )
        .unwrap();
        assert_eq!(cfg.get("s", "p").unwrap().as_deref(), Some("/srv/x"));
        assert_eq!(cfg.get("s", "lit").unwrap().as_deref(), Some("100%"));
        // `get_raw` bypasses interpolation.
        assert_eq!(cfg.get_raw("s", "p"), Some("%(base)s/x"));
    }

    #[test]
    fn interpolation_errors_and_depth_limit() {
        let mut cfg = ConfigFile::new();
        cfg.read_str(
            "[s]\nbad = 50%\nmissing = %(nope)s\na = %(b)s\nb = %(a)s\n",
        )
        .unwrap();
        assert!(matches!(cfg.get("s", "bad"), Err(Error::Parse(_))));
        assert!(matches!(cfg.get("s", "missing"), Err(Error::Parse(_))));
        assert!(matches!(cfg.get("s", "a"), Err(Error::Parse(_))));
    }

    #[test]
    fn raw_mode_does_not_interpolate() {
        let mut cfg = ConfigFile::raw();
        cfg.read_str("[s]\np = %(x)s\nlit = 50%\n").unwrap();
        assert_eq!(cfg.get("s", "p").unwrap().as_deref(), Some("%(x)s"));
        assert_eq!(cfg.get("s", "lit").unwrap().as_deref(), Some("50%"));
    }

    #[test]
    fn set_rejects_invalid_interpolation_but_raw_allows() {
        let mut cfg = ConfigFile::new();
        cfg.add_section("s").unwrap();
        assert!(matches!(
            cfg.set("s", "k", Some("50%")),
            Err(Error::Validation(_))
        ));
        cfg.set("s", "k", Some("100%%")).unwrap();
        cfg.set("s", "k", Some("%(other)s")).unwrap();

        let mut raw = ConfigFile::raw();
        raw.add_section("s").unwrap();
        raw.set("s", "k", Some("50%")).unwrap();
    }

    #[test]
    fn mutation_add_set_remove() {
        let mut cfg = ConfigFile::new();
        cfg.add_section("s").unwrap();
        assert!(matches!(cfg.add_section("s"), Err(Error::Validation(_))));
        assert!(matches!(
            cfg.add_section("DEFAULT"),
            Err(Error::Validation(_))
        ));
        assert!(matches!(
            cfg.set("missing", "k", Some("v")),
            Err(Error::Validation(_))
        ));
        cfg.set("s", "k", Some("v")).unwrap();
        assert!(cfg.has_option("s", "k"));
        assert!(cfg.remove_option("s", "k").unwrap());
        assert!(!cfg.remove_option("s", "k").unwrap());
        assert!(cfg.remove_section("s"));
        assert!(!cfg.remove_section("s"));
        assert!(matches!(
            cfg.remove_option("gone", "k"),
            Err(Error::Validation(_))
        ));
    }

    #[test]
    fn allow_no_value_parses_and_writes_bare_keys() {
        let mut cfg = ConfigFile::new().allow_no_value(true);
        cfg.read_str("[s]\nflag\nk = v\n").unwrap();
        assert!(cfg.has_option("s", "flag"));
        assert_eq!(cfg.get_raw("s", "flag"), None);
        assert_eq!(cfg.write_string(), "[s]\nflag\nk = v\n\n");
        // Without the flag, a bare key is a parse error.
        assert!(matches!(
            ConfigFile::new().read_str("[s]\nflag\n"),
            Err(Error::Parse(_))
        ));
    }

    #[test]
    fn multiple_reads_merge_and_override() {
        let mut cfg = ConfigFile::raw();
        cfg.read_str("[s]\na = 1\nb = 2\n").unwrap();
        cfg.read_str("[s]\nb = 20\nc = 3\n").unwrap();
        assert_eq!(cfg.get_raw("s", "a"), Some("1"));
        assert_eq!(cfg.get_raw("s", "b"), Some("20"));
        assert_eq!(cfg.get_raw("s", "c"), Some("3"));
    }
}
