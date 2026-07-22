//! Integration tests for `truenas_ros` (mirrors `src/`, nix convention).
#![cfg(target_os = "linux")]

#[cfg(feature = "sync-fs")]
mod fs {
    use std::os::fd::AsFd;
    use truenas_ros::errno::Errno;
    use truenas_ros::sync_fs::{
        openat2, renameat2, statx, AtFlags, OFlag, OpenHow, RenameFlags,
        ResolveFlag, StatxMask,
    };
    use truenas_ros::AT_FDCWD;

    #[test]
    fn statx_dot_is_a_directory() {
        let st = statx(AT_FDCWD, ".", AtFlags::empty(), StatxMask::BASIC_STATS)
            .expect("statx . failed");
        assert!(st.is_dir());
        assert!(st.mask().contains(StatxMask::MODE));
    }

    #[test]
    fn openat2_then_statx_by_fd() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("file");
        std::fs::write(&path, b"hello").unwrap();

        let how = OpenHow::new()
            .flags(OFlag::O_RDONLY)
            .resolve(ResolveFlag::RESOLVE_NO_SYMLINKS);
        let fd = openat2(AT_FDCWD, &path, how).expect("openat2 failed");

        let st = statx(
            fd.as_fd(),
            "",
            AtFlags::AT_EMPTY_PATH,
            StatxMask::BASIC_STATS,
        )
        .expect("statx by fd failed");
        assert!(st.is_regular());
        assert_eq!(st.size(), 5);
    }

    #[test]
    fn openat2_no_symlinks_rejects_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        std::fs::write(&target, b"x").unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let how = OpenHow::new()
            .flags(OFlag::O_RDONLY)
            .resolve(ResolveFlag::RESOLVE_NO_SYMLINKS);
        let err = openat2(AT_FDCWD, &link, how).unwrap_err();
        assert_eq!(err, Errno::ELOOP);
    }

    #[test]
    fn renameat2_noreplace_and_exchange() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a");
        let b = dir.path().join("b");
        std::fs::write(&a, b"aaa").unwrap();
        std::fs::write(&b, b"bbb").unwrap();

        // NOREPLACE must fail because `b` already exists.
        let err = renameat2(
            AT_FDCWD,
            &a,
            AT_FDCWD,
            &b,
            RenameFlags::RENAME_NOREPLACE,
        )
        .unwrap_err();
        assert_eq!(err, Errno::EEXIST);

        // EXCHANGE swaps the two files atomically.
        renameat2(AT_FDCWD, &a, AT_FDCWD, &b, RenameFlags::RENAME_EXCHANGE)
            .expect("exchange failed");
        assert_eq!(std::fs::read(&a).unwrap(), b"bbb");
        assert_eq!(std::fs::read(&b).unwrap(), b"aaa");
    }
}

#[cfg(feature = "xattr")]
mod xattr {
    use std::os::fd::AsFd;
    use truenas_ros::errno::Errno;
    use truenas_ros::sync_fs::xattr::{
        fgetxattr, flistxattr, fsetxattr, XattrFlags,
    };

    #[test]
    fn set_get_list_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("file");
        std::fs::write(&path, b"data").unwrap();
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let name = "user.truenas_ros_test";

        match fsetxattr(file.as_fd(), name, b"value", XattrFlags::empty()) {
            Ok(()) => {
                let got = fgetxattr(file.as_fd(), name).unwrap();
                assert_eq!(got, b"value");
                let names = flistxattr(file.as_fd()).unwrap();
                assert!(names.iter().any(|n| n == name));
            }
            // Some filesystems (e.g. certain tmpfs configs) reject user
            // xattrs; treat that as "not applicable" rather than a failure.
            Err(Errno::EOPNOTSUPP) => {}
            Err(e) => panic!("fsetxattr failed unexpectedly: {e}"),
        }
    }

    #[test]
    fn missing_xattr_is_enodata() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("file");
        std::fs::write(&path, b"data").unwrap();
        let file = std::fs::File::open(&path).unwrap();
        let err =
            fgetxattr(file.as_fd(), "user.definitely_absent").unwrap_err();
        assert!(matches!(err, Errno::ENODATA | Errno::EOPNOTSUPP));
    }
}

#[cfg(feature = "mount")]
mod mount {
    use std::os::fd::AsFd;
    use truenas_ros::errno::Errno;
    use truenas_ros::mount::{
        fsconfig, fsmount, fsopen, iter_mount, listmount, statmount, FsConfig,
        FsmountFlags, FsopenFlags, MountAttr, StatmountMask, LSMT_ROOT,
    };
    use truenas_ros::sync_fs::{statx, AtFlags, StatxMask};
    use truenas_ros::AT_FDCWD;

    fn root_mnt_id() -> u64 {
        statx(AT_FDCWD, "/", AtFlags::empty(), StatxMask::MNT_ID_UNIQUE)
            .unwrap()
            .mnt_id()
    }

    #[test]
    fn listmount_namespace_is_nonempty() {
        let ids = listmount(LSMT_ROOT, false).unwrap();
        assert!(!ids.is_empty());
    }

    #[test]
    fn statmount_root_reports_mountpoint_and_opts() {
        let id = root_mnt_id();
        let sm = statmount(
            id,
            StatmountMask::MNT_BASIC
                | StatmountMask::SB_BASIC
                | StatmountMask::MNT_POINT
                | StatmountMask::FS_TYPE
                | StatmountMask::MNT_OPTS,
        )
        .unwrap();
        assert_eq!(sm.mnt_id, Some(id));
        assert_eq!(sm.mnt_point.as_deref(), Some("/"));
        assert!(sm.fs_type.is_some());
        // With SB_BASIC co-requested, options carry the synthetic ro/rw prefix.
        let opts = sm.mount_opts().unwrap();
        assert!(
            opts.starts_with("rw") || opts.starts_with("ro"),
            "unexpected mount_opts: {opts:?}"
        );
    }

    #[test]
    fn iter_mount_yields_records() {
        let mounts: Vec<_> =
            iter_mount(LSMT_ROOT, false, StatmountMask::MNT_POINT)
                .unwrap()
                .filter_map(Result::ok)
                .collect();
        assert!(!mounts.is_empty());
        assert!(mounts.iter().any(|sm| sm.mnt_point.is_some()));
    }

    #[test]
    fn fsopen_fsconfig_fsmount_detached_tmpfs() {
        // Build a tmpfs mount object but never `move_mount` it into the tree,
        // so this is safe even in the initial mount namespace: the detached
        // mount is discarded when its fd drops. Skips when unprivileged.
        let fs = match fsopen("tmpfs", FsopenFlags::empty()) {
            Ok(fd) => fd,
            Err(Errno::EPERM | Errno::ENOSYS | Errno::EACCES) => return,
            Err(e) => panic!("fsopen(tmpfs): {e}"),
        };
        fsconfig(fs.as_fd(), FsConfig::Create).expect("fsconfig create");
        let mnt =
            fsmount(fs.as_fd(), FsmountFlags::empty(), MountAttr::empty())
                .expect("fsmount");
        // The mount fd points at the (detached) tmpfs root directory.
        let st = statx(
            mnt.as_fd(),
            "",
            AtFlags::AT_EMPTY_PATH,
            StatxMask::BASIC_STATS,
        )
        .expect("statx of mount fd");
        assert!(st.is_dir());
    }
}

#[cfg(feature = "acl")]
mod acl {
    use std::os::fd::AsFd;
    use truenas_ros::sync_fs::acl::{
        fgetacl, Acl, Nfs4Ace, Nfs4AceType, Nfs4Acl, Nfs4AclFlag, Nfs4Flag,
        Nfs4Perm, Nfs4Who, PosixAcl, PosixPerm, PosixTag,
    };
    use truenas_ros::sync_fs::xattr::fgetxattr;

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
        assert!(acl.aces[0]
            .access_mask
            .contains(Nfs4Perm::READ_DATA | Nfs4Perm::WRITE_OWNER));
        // GROUP@ carries IDENTIFIER_GROUP.
        assert_eq!(acl.aces[1].who_type, Nfs4Who::Group);
        assert!(acl.aces[1].ace_flags.contains(Nfs4Flag::IDENTIFIER_GROUP));
        // EVERYONE@.
        assert_eq!(acl.aces[2].who_type, Nfs4Who::Everyone);

        assert_eq!(acl.to_xattr(), data);
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

        assert_eq!(acl.access_bytes(), data);
        assert!(acl.default_bytes().is_none());
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
        let acl = Nfs4Acl::from_aces(
            [inherited_allow, explicit_deny, explicit_allow],
            Nfs4AclFlag::empty(),
        );
        // Canonical order: explicit-deny, explicit-allow, then inherited-allow.
        assert_eq!(acl.aces[0].ace_type, Nfs4AceType::Deny);
        assert_eq!(acl.aces[1].ace_type, Nfs4AceType::Allow);
        assert!(!acl.aces[1].ace_flags.contains(Nfs4Flag::INHERITED));
        assert!(acl.aces[2].ace_flags.contains(Nfs4Flag::INHERITED));
    }

    #[test]
    fn fgetacl_live_nfs4_roundtrips() {
        let f = match std::fs::File::open("/NFSV4ACL/raw_bytes") {
            Ok(f) => f,
            Err(_) => return, // fixture absent; skip
        };
        match fgetacl(f.as_fd()) {
            Ok(Acl::Nfs4(acl)) => {
                let raw = fgetxattr(f.as_fd(), "system.nfs4_acl_xdr").unwrap();
                assert_eq!(acl.to_xattr(), raw);
            }
            Ok(Acl::Posix(_)) => panic!("expected an NFS4 ACL"),
            Err(_) => {} // filesystem may not support NFS4 ACLs here
        }
    }

    #[test]
    fn fgetacl_live_posix_roundtrips() {
        let f = match std::fs::File::open("/POSIXACL/raw_bytes") {
            Ok(f) => f,
            Err(_) => return,
        };
        match fgetacl(f.as_fd()) {
            Ok(Acl::Posix(acl)) => {
                let raw =
                    fgetxattr(f.as_fd(), "system.posix_acl_access").unwrap();
                assert_eq!(acl.access_bytes(), raw);
            }
            Ok(Acl::Nfs4(_)) => panic!("expected a POSIX ACL"),
            Err(_) => {}
        }
    }
}

#[cfg(feature = "fhandle")]
mod fhandle {
    use std::os::fd::AsFd;
    use truenas_ros::errno::Errno;
    use truenas_ros::sync_fs::fhandle::{
        name_to_handle_at, FhFlags, FileHandle,
    };
    use truenas_ros::sync_fs::{statx, AtFlags, OFlag, StatxMask};
    use truenas_ros::{Error, AT_FDCWD};

    #[test]
    fn name_to_handle_roundtrip_and_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("file");
        std::fs::write(&path, b"handle me").unwrap();

        let handle = match name_to_handle_at(
            AT_FDCWD,
            &path,
            FhFlags::AT_HANDLE_MNT_ID_UNIQUE,
        ) {
            Ok(h) => h,
            // Filesystem cannot encode handles here; skip.
            Err(Error::Errno(Errno::EOPNOTSUPP)) => return,
            Err(e) => panic!("name_to_handle_at: {e}"),
        };

        // Serialize / deserialize is byte-exact; mount id is carried alongside.
        let bytes = handle.to_bytes();
        let rebuilt = FileHandle::from_bytes(
            &bytes,
            handle.mount_id(),
            handle.unique_mount_id(),
        )
        .unwrap();
        assert_eq!(rebuilt.to_bytes(), bytes);

        let ino = statx(AT_FDCWD, &path, AtFlags::empty(), StatxMask::INO)
            .unwrap()
            .ino();

        // Re-open via a mount fd (the containing directory) and confirm it is
        // the same inode. open_by_handle_at needs CAP_DAC_READ_SEARCH.
        let mount_fd = std::fs::File::open(dir.path()).unwrap();
        match rebuilt.open(mount_fd.as_fd(), OFlag::O_RDONLY) {
            Ok(opened) => {
                let st = statx(
                    opened.as_fd(),
                    "",
                    AtFlags::AT_EMPTY_PATH,
                    StatxMask::INO,
                )
                .unwrap();
                assert_eq!(st.ino(), ino);
            }
            // open_by_handle_at needs CAP_DAC_READ_SEARCH and is often blocked
            // by a container seccomp filter (ENOSYS); both are environmental.
            Err(Error::Errno(Errno::EPERM | Errno::EACCES | Errno::ENOSYS)) => {
            }
            Err(e) => panic!("open_by_handle_at: {e}"),
        }
    }

    #[test]
    fn from_bytes_rejects_short_buffer() {
        let err = FileHandle::from_bytes(&[0u8; 4], 1, false).unwrap_err();
        assert!(matches!(err, Error::Validation(_)));
    }
}

#[cfg(feature = "fsiter")]
mod fsiter {
    use std::collections::BTreeSet;
    use truenas_ros::sync_fs::iter::FsIterBuilder;
    use truenas_ros::sync_fs::{statx, AtFlags, StatxMask};
    use truenas_ros::Error;

    /// The mount source of `p`, so the fsiter source-check matches on kernels
    /// that report `sb_source`. Where it is not reported (e.g. the TrueNAS 6.12
    /// kernel) this returns a placeholder and the check is skipped anyway.
    fn fs_source(p: &std::path::Path) -> String {
        truenas_ros::mount::statmount_path(p)
            .ok()
            .and_then(|sm| sm.sb_source)
            .unwrap_or_else(|| "x".to_string())
    }

    fn names(dir: &std::path::Path) -> (BTreeSet<String>, u64, u64) {
        let mut it = FsIterBuilder::new(dir, fs_source(dir)).build().unwrap();
        let mut set = BTreeSet::new();
        for res in it.by_ref() {
            let e = res.unwrap();
            set.insert(e.name().to_string_lossy().into_owned());
        }
        let s = it.stats();
        (set, s.count, s.bytes)
    }

    #[test]
    fn walks_whole_tree_depth_first() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("a/b")).unwrap();
        std::fs::write(dir.path().join("a/f1"), b"1").unwrap();
        std::fs::write(dir.path().join("a/b/f2"), b"22").unwrap();
        std::fs::write(dir.path().join("c"), b"333").unwrap();

        let (set, count, bytes) = names(dir.path());
        for n in ["a", "b", "c", "f1", "f2"] {
            assert!(set.contains(n), "missing {n}");
        }
        assert_eq!(count, 5); // a, b, c, f1, f2
        assert_eq!(bytes, 6); // 1 + 2 + 3 (files only; dirs add no bytes)
    }

    // A writer-less FIFO in the tree would hang the walk forever on a blocking
    // O_RDONLY open; it must classify as `Special` so the walk finishes without
    // opening it.
    #[test]
    fn special_files_classify_without_hanging() {
        use std::os::unix::ffi::OsStrExt;
        use truenas_ros::sync_fs::iter::EntryType;
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("regular"), b"hi").unwrap();
        let fifo = dir.path().join("pipe");
        let c = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o644) }, 0);

        let mut it = FsIterBuilder::new(dir.path(), fs_source(dir.path()))
            .build()
            .unwrap();
        let mut kinds = std::collections::BTreeMap::new();
        for res in it.by_ref() {
            let e = res.unwrap();
            kinds
                .insert(e.name().to_string_lossy().into_owned(), e.file_type());
        }
        assert_eq!(kinds.get("regular"), Some(&EntryType::File));
        assert_eq!(kinds.get("pipe"), Some(&EntryType::Special));
    }

    #[test]
    fn skip_descent_prunes_subtree() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("keep")).unwrap();
        std::fs::create_dir_all(dir.path().join("prune/hidden")).unwrap();
        std::fs::write(dir.path().join("keep/f"), b"x").unwrap();
        std::fs::write(dir.path().join("prune/secret"), b"y").unwrap();

        let mut it = FsIterBuilder::new(dir.path(), fs_source(dir.path()))
            .build()
            .unwrap();
        let mut seen = BTreeSet::new();
        while let Some(res) = it.next() {
            let e = res.unwrap();
            let name = e.name().to_string_lossy().into_owned();
            if name == "prune" {
                assert!(e.is_dir());
                it.skip_descent();
            }
            seen.insert(name);
        }
        assert!(seen.contains("keep") && seen.contains("f"));
        assert!(seen.contains("prune")); // the dir itself is yielded...
        assert!(!seen.contains("secret")); // ...but not descended into
        assert!(!seen.contains("hidden"));
    }

    #[test]
    fn yielded_fd_is_usable_and_self_closing() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("data"), b"hello world").unwrap();

        let it = FsIterBuilder::new(dir.path(), fs_source(dir.path()))
            .build()
            .unwrap();
        let file = it
            .map(Result::unwrap)
            .find(|e| e.name() == "data")
            .expect("entry not found");
        // The entry carries statx metadata directly.
        assert!(file.is_regular());
        assert_eq!(file.statx().size(), 11);
        // Its fd is a live, usable descriptor (statx via AT_EMPTY_PATH).
        let st = statx(file.fd(), "", AtFlags::AT_EMPTY_PATH, StatxMask::SIZE)
            .unwrap();
        assert_eq!(st.size(), 11);
        // Dropping `file` closes the fd automatically (no manual close).
    }

    #[test]
    fn symlinks_skipped_by_default_included_on_request() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("target"), b"t").unwrap();
        std::os::unix::fs::symlink("target", dir.path().join("link")).unwrap();

        let (default, _, _) = names(dir.path());
        assert!(!default.contains("link"), "symlink should be skipped");

        let mut it = FsIterBuilder::new(dir.path(), fs_source(dir.path()))
            .include_symlinks(true)
            .build()
            .unwrap();
        let link = it
            .by_ref()
            .map(Result::unwrap)
            .find(|e| e.name() == "link")
            .expect("symlink not yielded");
        assert!(link.is_symlink());
        assert_eq!(link.read_link().unwrap().as_os_str(), "target");
    }

    /// A small tree with globally-unique names (so a basename identifies an
    /// entry regardless of where it sits or of readdir order).
    fn sample_tree(root: &std::path::Path) {
        use std::fs::{create_dir_all, write};
        create_dir_all(root.join("d_a/d_ab")).unwrap();
        create_dir_all(root.join("d_b")).unwrap();
        write(root.join("f_c"), b"c").unwrap();
        write(root.join("d_a/f_a1"), b"a1").unwrap();
        write(root.join("d_a/f_a2"), b"a2").unwrap();
        write(root.join("d_a/d_ab/f_ab1"), b"ab1").unwrap();
        write(root.join("d_a/d_ab/f_ab2"), b"ab2").unwrap();
        write(root.join("d_b/f_b1"), b"b1").unwrap();
    }

    fn walk_names(root: &std::path::Path) -> BTreeSet<String> {
        FsIterBuilder::new(root, fs_source(root))
            .build()
            .unwrap()
            .map(|r| r.unwrap().name().to_string_lossy().into_owned())
            .collect()
    }

    // Iterate until `f_ab1` (a file deep in d_a/d_ab) is yielded, returning the
    // names seen so far and the cookie captured at that point (stack is then
    // [root, d_a, d_ab]).
    fn walk_to_f_ab1(
        root: &std::path::Path,
    ) -> (BTreeSet<String>, truenas_ros::sync_fs::iter::Cookie) {
        let mut it = FsIterBuilder::new(root, fs_source(root)).build().unwrap();
        let mut prefix = BTreeSet::new();
        let mut cookie = None;
        while let Some(res) = it.next() {
            let name = res.unwrap().name().to_string_lossy().into_owned();
            prefix.insert(name.clone());
            if name == "f_ab1" {
                cookie = Some(it.cookie());
                break;
            }
        }
        drop(it);
        (prefix, cookie.expect("f_ab1 never yielded"))
    }

    #[test]
    fn cookie_resume_is_complete_and_skips_descended_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        sample_tree(root);
        let full = walk_names(root);
        let (prefix, cookie) = walk_to_f_ab1(root);

        // Resume: the union of what we saw and what resume yields must be the
        // whole tree (nothing skipped), and the silently-descended directories
        // must not be re-yielded.
        let resumed: BTreeSet<String> =
            FsIterBuilder::new(root, fs_source(root))
                .resume_from(cookie)
                .build()
                .unwrap()
                .map(|r| r.unwrap().name().to_string_lossy().into_owned())
                .collect();

        let union: BTreeSet<_> = prefix.union(&resumed).cloned().collect();
        assert_eq!(union, full, "resume must not skip any entry");
        assert!(!resumed.contains("d_a"), "descended dir re-yielded");
        assert!(!resumed.contains("d_ab"), "descended dir re-yielded");
    }

    #[test]
    fn cookie_resume_recovers_after_deleted_directory() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        sample_tree(root);
        let (_prefix, cookie) = walk_to_f_ab1(root);

        // Delete the deepest saved directory, then try to resume from it.
        std::fs::remove_dir_all(root.join("d_a/d_ab")).unwrap();
        let err = FsIterBuilder::new(root, fs_source(root))
            .resume_from(cookie.clone())
            .build()
            .unwrap_err();
        let depth = match err {
            Error::IteratorRestore { depth, .. } => depth,
            other => panic!("expected IteratorRestore, got {other:?}"),
        };
        assert_eq!(depth, 2, "d_ab is at stack depth 2");

        // Recover by trimming to the surviving ancestor and rebuilding.
        let mut recovered = cookie;
        recovered.truncate(depth);
        let seen: BTreeSet<String> = FsIterBuilder::new(root, fs_source(root))
            .resume_from(recovered)
            .build()
            .unwrap()
            .map(|r| r.unwrap().name().to_string_lossy().into_owned())
            .collect();
        assert!(seen.contains("f_a1") && seen.contains("f_a2"));
        assert!(!seen.contains("f_ab1"), "deleted subtree must be gone");
    }
}

#[cfg(feature = "idmap")]
mod namespace {
    use std::os::fd::AsRawFd;
    use truenas_ros::errno::Errno;
    use truenas_ros::mount::idmap::{
        create_idmap_userns, IdmapCache, IdmapEntry,
    };
    use truenas_ros::Error;

    fn nsfs_link(fd: std::os::fd::RawFd) -> String {
        std::fs::read_link(format!("/proc/self/fd/{fd}"))
            .unwrap()
            .to_string_lossy()
            .into_owned()
    }

    fn skip(e: &Error) -> bool {
        matches!(
            e,
            Error::Errno(
                Errno::EPERM | Errno::ENOSYS | Errno::EACCES | Errno::EINVAL
            )
        )
    }

    #[test]
    fn idmap_entry_validation_and_accessors() {
        assert!(IdmapEntry::new(0, 0, 0).is_err()); // zero length
        assert!(IdmapEntry::new(u32::MAX, 0, 2).is_err()); // inside overflow
        assert!(IdmapEntry::new(0, u32::MAX, 2).is_err()); // outside overflow
        assert!(IdmapEntry::new(u32::MAX, 0, 1).is_ok()); // MAX+1 == 2^32, ok

        let e = IdmapEntry::new(0, 100_000, 1000).unwrap();
        assert_eq!((e.inside(), e.outside(), e.length()), (0, 100_000, 1000));
    }

    #[test]
    fn create_produces_a_user_namespace_fd() {
        let map = vec![IdmapEntry::new(0, 100_000, 65536).unwrap()];
        let fd = match create_idmap_userns(&map, &map) {
            Ok(fd) => fd,
            Err(e) if skip(&e) => return,
            Err(e) => panic!("create_idmap_userns: {e}"),
        };
        // A pinned user namespace shows up as a `user:[...]` nsfs link.
        assert!(
            nsfs_link(fd.as_raw_fd()).starts_with("user:"),
            "expected a user-namespace fd"
        );
    }

    #[test]
    fn cache_dedups_and_clear_forces_recreation() {
        // A distinct map from the other test to avoid cross-test coupling.
        let map = vec![IdmapEntry::new(0, 300_000, 1000).unwrap()];
        let cache = IdmapCache::new();
        let fd1 = match cache.get_or_create(&map, &map) {
            Ok(fd) => fd,
            Err(e) if skip(&e) => return,
            Err(e) => panic!("get_or_create: {e}"),
        };
        let fd2 = cache.get_or_create(&map, &map).expect("cached lookup");
        // Same underlying namespace...
        assert_eq!(nsfs_link(fd1.as_raw_fd()), nsfs_link(fd2.as_raw_fd()));
        // ...but independent duplicated descriptors.
        assert_ne!(fd1.as_raw_fd(), fd2.as_raw_fd());

        // Clearing drops the cached original; the earlier dup stays valid.
        cache.clear();
        assert!(nsfs_link(fd1.as_raw_fd()).starts_with("user:"));
        let fd3 = cache
            .get_or_create(&map, &map)
            .expect("recreate after clear");
        assert!(nsfs_link(fd3.as_raw_fd()).starts_with("user:"));
    }
}

#[cfg(feature = "sync-fs")]
mod io {
    use std::io::Write;
    use truenas_ros::errno::Errno;
    use truenas_ros::sync_fs::{
        atomic_replace, atomic_write, safe_open, AtomicWriteOptions, Mode,
        OFlag,
    };
    use truenas_ros::{Error, AT_FDCWD};

    #[test]
    fn atomic_replace_creates_replaces_and_leaves_no_temp() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("config");

        atomic_replace(&target, b"v1", AtomicWriteOptions::default()).unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"v1");

        // Replacing an existing file uses RENAME_EXCHANGE (atomic).
        atomic_replace(&target, b"version two", AtomicWriteOptions::default())
            .unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"version two");

        // No temporary files are left behind.
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .filter(|n| n != "config")
            .collect();
        assert!(leftovers.is_empty(), "temp files left: {leftovers:?}");
    }

    #[test]
    fn atomic_write_closure_and_noclobber() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("f");
        atomic_write(&target, AtomicWriteOptions::default(), |f| {
            f.write_all(b"hello ")?;
            f.write_all(b"world")
        })
        .unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"hello world");

        let opts = AtomicWriteOptions {
            noclobber: true,
            ..Default::default()
        };
        let err = atomic_replace(&target, b"x", opts).unwrap_err();
        assert!(matches!(err, Error::Errno(Errno::EEXIST)));
        // The original content is untouched.
        assert_eq!(std::fs::read(&target).unwrap(), b"hello world");
    }

    #[test]
    fn safe_open_rejects_symlink_in_path() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("real")).unwrap();
        std::fs::write(dir.path().join("real/file"), b"x").unwrap();
        std::os::unix::fs::symlink("real", dir.path().join("link")).unwrap();

        let via_link = dir.path().join("link/file");
        let err =
            safe_open(AT_FDCWD, &via_link, OFlag::O_RDONLY, Mode::empty())
                .unwrap_err();
        assert!(matches!(err, Error::SymlinkInPath { .. }));
    }
}

#[cfg(feature = "mount")]
mod mount_helpers {
    use std::path::Path;
    use truenas_ros::mount::{iter_mountinfo, statmount_path, LSMT_ROOT};

    #[test]
    fn statmount_path_of_root() {
        let sm = statmount_path(Path::new("/")).unwrap();
        assert_eq!(sm.mnt_point.as_deref(), Some("/"));
        assert!(sm.fs_type.is_some());
    }

    #[test]
    fn iter_mountinfo_is_nonempty() {
        let mounts = iter_mountinfo(LSMT_ROOT, false, true).unwrap();
        assert!(!mounts.is_empty());
        assert!(mounts.iter().any(|m| m.mnt_point.is_some()));
    }
}

#[cfg(feature = "shutil")]
mod shutil {
    use std::os::unix::fs::PermissionsExt;
    use truenas_ros::sync_fs::shutil::{
        copytree, copytree_reporting, CopyTreeConfig,
    };

    // A writer-less FIFO in the source must be recreated by type, not read as a
    // regular file (which would block the copy forever).
    #[test]
    fn recreates_special_files_by_type() {
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::FileTypeExt;
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        std::fs::create_dir(&src).unwrap();
        std::fs::write(src.join("f"), b"data").unwrap();
        let fifo = src.join("pipe");
        let c = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);

        let dst = tmp.path().join("dst");
        let stats = copytree(&src, &dst, &CopyTreeConfig::default()).unwrap();
        assert_eq!(stats.files, 1);
        assert_eq!(stats.specials, 1);
        let md = std::fs::symlink_metadata(dst.join("pipe")).unwrap();
        assert!(md.file_type().is_fifo());
    }

    #[test]
    fn copies_tree_with_content_and_metadata() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        let dst = tmp.path().join("dst");
        std::fs::create_dir_all(src.join("sub")).unwrap();
        std::fs::write(src.join("a.txt"), b"hello").unwrap();
        std::fs::write(src.join("sub/b.bin"), vec![7u8; 4096]).unwrap();
        std::os::unix::fs::symlink("a.txt", src.join("link")).unwrap();
        std::fs::set_permissions(
            src.join("a.txt"),
            std::fs::Permissions::from_mode(0o640),
        )
        .unwrap();
        let src_mtime = std::fs::metadata(src.join("a.txt"))
            .unwrap()
            .modified()
            .unwrap();

        let stats = copytree(&src, &dst, &CopyTreeConfig::default()).unwrap();
        assert_eq!(stats.dirs, 1); // sub
        assert_eq!(stats.files, 2); // a.txt, sub/b.bin
        assert_eq!(stats.symlinks, 1); // link
        assert_eq!(stats.bytes, 5 + 4096);

        // Content copied.
        assert_eq!(std::fs::read(dst.join("a.txt")).unwrap(), b"hello");
        assert_eq!(
            std::fs::read(dst.join("sub/b.bin")).unwrap(),
            vec![7u8; 4096]
        );
        // Symlink recreated verbatim (not followed).
        assert_eq!(
            std::fs::read_link(dst.join("link")).unwrap(),
            std::path::Path::new("a.txt")
        );
        // Permissions preserved.
        let mode = std::fs::metadata(dst.join("a.txt"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o640);
        // Nanosecond mtime preserved (would otherwise be the copy time).
        let dst_mtime = std::fs::metadata(dst.join("a.txt"))
            .unwrap()
            .modified()
            .unwrap();
        assert_eq!(src_mtime, dst_mtime);
    }

    #[test]
    fn skips_metadata_when_flags_cleared() {
        use truenas_ros::sync_fs::shutil::CopyFlags;
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("s");
        let dst = tmp.path().join("d");
        std::fs::create_dir(&src).unwrap();
        std::fs::write(src.join("f"), b"data").unwrap();

        // No metadata preservation: still copies content, no fchmod-from-ACL.
        let config = CopyTreeConfig {
            flags: CopyFlags::empty(),
            ..Default::default()
        };
        let stats = copytree(&src, &dst, &config).unwrap();
        assert_eq!(stats.files, 1);
        assert_eq!(std::fs::read(dst.join("f")).unwrap(), b"data");
    }

    #[test]
    fn reporting_callback_fires_periodically_and_finally() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        std::fs::create_dir_all(src.join("d1/d2")).unwrap();
        std::fs::write(src.join("a"), b"a").unwrap();
        std::fs::write(src.join("d1/b"), b"bb").unwrap();
        std::fs::write(src.join("d1/d2/c"), b"ccc").unwrap();

        // increment=1 → one callback per entry (5) plus the final call.
        let mut calls = 0u32;
        let mut last = None;
        let cfg = CopyTreeConfig {
            reporting_increment: 1,
            ..Default::default()
        };
        let stats = copytree_reporting(
            &src,
            &tmp.path().join("out1"),
            &cfg,
            &mut |p| {
                calls += 1;
                last = Some(p.stats);
            },
        )
        .unwrap();
        assert_eq!(stats.dirs, 2);
        assert_eq!(stats.files, 3);
        assert_eq!(stats.bytes, 6);
        assert_eq!(calls, 6, "5 entries at increment 1, plus the final call");
        assert_eq!(last.unwrap(), stats, "final call carries completed stats");

        // increment=0 → only the final call fires.
        let mut calls0 = 0u32;
        let cfg0 = CopyTreeConfig {
            reporting_increment: 0,
            ..Default::default()
        };
        copytree_reporting(&src, &tmp.path().join("out2"), &cfg0, &mut |_| {
            calls0 += 1
        })
        .unwrap();
        assert_eq!(calls0, 1, "only the final call fires when increment is 0");
    }

    #[test]
    fn traverse_without_child_mounts_matches_plain_copy() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        std::fs::create_dir_all(src.join("sub")).unwrap();
        std::fs::write(src.join("sub/f"), b"x").unwrap();
        std::fs::write(src.join("g"), b"yy").unwrap();

        let plain =
            copytree(&src, &tmp.path().join("d1"), &CopyTreeConfig::default())
                .unwrap();
        let cfg = CopyTreeConfig {
            traverse: true,
            ..Default::default()
        };
        let trav = copytree(&src, &tmp.path().join("d2"), &cfg).unwrap();
        // No child mounts nested under a tempdir → traverse is a no-op.
        assert_eq!(plain, trav);
        assert_eq!(trav.dirs, 1);
        assert_eq!(trav.files, 2);
    }

    #[test]
    fn traverse_copies_child_mount() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        use truenas_ros::libc;

        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        let dst = tmp.path().join("dst");
        std::fs::create_dir_all(src.join("child")).unwrap();
        std::fs::write(src.join("top"), b"top").unwrap();

        // Mount a tmpfs at src/child (needs privilege; skip otherwise).
        let target = src.join("child");
        let ctarget = CString::new(target.as_os_str().as_bytes()).unwrap();
        let tmpfs = CString::new("tmpfs").unwrap();
        let rc = unsafe {
            libc::mount(
                tmpfs.as_ptr(),
                ctarget.as_ptr(),
                tmpfs.as_ptr(),
                0,
                std::ptr::null(),
            )
        };
        if rc != 0 {
            return; // unprivileged sandbox → EPERM
        }
        // Lazy-unmount on the way out, even on panic, before the tempdir is
        // removed.
        struct Unmount(CString);
        impl Drop for Unmount {
            fn drop(&mut self) {
                unsafe { libc::umount2(self.0.as_ptr(), libc::MNT_DETACH) };
            }
        }
        let _guard = Unmount(ctarget.clone());

        std::fs::write(target.join("inner"), b"inner-data").unwrap();
        // The destination child directory must already exist (opened, not
        // created) so the data lands on the intended mount.
        std::fs::create_dir_all(dst.join("child")).unwrap();

        let cfg = CopyTreeConfig {
            traverse: true,
            ..Default::default()
        };
        let stats = copytree(&src, &dst, &cfg).unwrap();

        assert_eq!(std::fs::read(dst.join("top")).unwrap(), b"top");
        assert_eq!(
            std::fs::read(dst.join("child/inner")).unwrap(),
            b"inner-data"
        );
        // Primary pass copied `top`; the traverse pass copied the mount's file.
        assert_eq!(stats.files, 2);
    }
}

#[cfg(feature = "configfile")]
mod configfile {
    use std::os::unix::fs::PermissionsExt;
    use truenas_ros::configfile::ConfigFile;
    use truenas_ros::sync_fs::AtomicWriteOptions;
    use truenas_ros::Error;

    // A shallow-but-wide interpolation (one value referencing another ~2000
    // times, each ~1 KiB) expands past the output budget; the getter must error
    // rather than build a multi-megabyte string. The input stays shallow so
    // this exercises the output cap, not the depth cap.
    #[test]
    fn interpolation_output_is_bounded() {
        let big = "x".repeat(1024);
        let refs = "%(a)s".repeat(2048); // 2048 * ~1 KiB > 1 MiB budget
        let src = format!("[s]\na = {big}\nb = {refs}\n");
        let mut cfg = ConfigFile::new();
        cfg.read_str(&src).unwrap();
        assert!(
            cfg.get("s", "b").is_err(),
            "expected interpolation to be bounded"
        );
        // A modest interpolation still resolves.
        assert_eq!(cfg.get("s", "a").unwrap().as_deref(), Some(big.as_str()));
    }

    #[test]
    fn write_path_is_atomic_with_mode_and_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("app.conf");
        let mut cfg = ConfigFile::new();
        cfg.add_section("main").unwrap();
        cfg.set("main", "name", Some("value")).unwrap();
        cfg.set_int("main", "count", 7).unwrap();

        let opts = AtomicWriteOptions {
            mode: 0o600,
            ..Default::default()
        };
        cfg.write_path(&path, opts).unwrap();

        // The requested mode is applied (configparser would not do this).
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        // No temporary file is left behind by the atomic write.
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .filter(|n| n != "app.conf")
            .collect();
        assert!(leftovers.is_empty(), "temp files left: {leftovers:?}");

        // It round-trips through read_path.
        let mut back = ConfigFile::new();
        back.read_path(&path).unwrap();
        assert_eq!(back.get("main", "name").unwrap().as_deref(), Some("value"));
        assert_eq!(back.get_int("main", "count").unwrap(), Some(7));
    }

    #[test]
    fn read_path_errors_on_missing_read_paths_skips() {
        let dir = tempfile::tempdir().unwrap();
        let present = dir.path().join("a.conf");
        std::fs::write(&present, b"[s]\nk = v\n").unwrap();
        let missing = dir.path().join("nope.conf");

        // A single read of a missing file is an error.
        assert!(ConfigFile::new().read_path(&missing).is_err());

        // read_paths skips the missing file and returns those actually read.
        let mut cfg = ConfigFile::new();
        let read = cfg.read_paths([missing, present.clone()]).unwrap();
        assert_eq!(read, vec![present]);
        assert_eq!(cfg.get_raw("s", "k"), Some("v"));
    }

    #[test]
    fn read_path_rejects_symlinked_component() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("real")).unwrap();
        std::fs::write(dir.path().join("real/c.conf"), b"[s]\nk=v\n").unwrap();
        std::os::unix::fs::symlink("real", dir.path().join("link")).unwrap();
        let via_link = dir.path().join("link/c.conf");
        assert!(matches!(
            ConfigFile::new().read_path(&via_link),
            Err(Error::SymlinkInPath { .. })
        ));
    }

    #[test]
    fn on_disk_bytes_are_stable_across_reparse() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.conf");
        let mut cfg = ConfigFile::raw();
        cfg.read_str("[a]\nx = 1\n[b]\ny = two words\n").unwrap();
        cfg.write_path(&path, AtomicWriteOptions::default())
            .unwrap();

        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert_eq!(on_disk, cfg.write_string());

        let mut back = ConfigFile::raw();
        back.read_path(&path).unwrap();
        assert_eq!(back.write_string(), on_disk);
    }
}
