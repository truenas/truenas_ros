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
                assert!(names.iter().any(|n| n.as_bytes() == name.as_bytes()));
            }
            // Some filesystems (e.g. certain tmpfs configs) reject user
            // xattrs; treat that as "not applicable" rather than a failure.
            Err(Errno::EOPNOTSUPP) => {}
            Err(e) => panic!("fsetxattr failed unexpectedly: {e}"),
        }
    }

    // An xattr name need not be UTF-8; `flistxattr` must return its bytes
    // verbatim so the follow-up `fgetxattr` addresses the real attribute.
    #[test]
    fn non_utf8_name_listed_verbatim() {
        use std::ffi::CString;
        use std::os::fd::AsRawFd;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("file");
        std::fs::write(&path, b"data").unwrap();
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        // A `user.` name whose trailing bytes are not valid UTF-8. The sync
        // `fsetxattr` wrapper takes `&str`, so plant it through raw `libc`.
        let name = CString::new(&b"user.\xff\xfe"[..]).unwrap();
        // SAFETY: `file` is live; `name`/value pointers are valid for the call.
        let rc = unsafe {
            libc::fsetxattr(
                file.as_raw_fd(),
                name.as_ptr(),
                b"v".as_ptr().cast(),
                1,
                0,
            )
        };
        if rc != 0 {
            // tmpfs and some configs reject `user.` xattrs; not applicable.
            return;
        }
        let names = flistxattr(file.as_fd()).unwrap();
        assert!(
            names.iter().any(|n| n.as_bytes() == b"user.\xff\xfe"),
            "non-UTF-8 name not returned verbatim: {names:?}"
        );
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
        assert_eq!(sm.mnt_point.as_deref(), Some(std::path::Path::new("/")));
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

    /// Skip a live-fixture check. `TRUENAS_ROS_REQUIRE_ZFS` (the same gate
    /// `test/zfs.rs` uses) turns the skip into a failure, so a fixture on the
    /// wrong dataset type is caught where CI provisions one and ignored where
    /// it does not.
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
        assert!(acl.aces[0]
            .access_mask
            .contains(Nfs4Perm::READ_DATA | Nfs4Perm::WRITE_OWNER));
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
                assert_eq!(acl.to_xattr().unwrap(), raw);
            }
            // The fixture path exists but is not on an NFSv4-ACL dataset.
            Ok(Acl::Posix(_)) => require_zfs("/NFSV4ACL is not NFSv4-ACL"),
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
                assert_eq!(acl.access_bytes().unwrap(), raw);
            }
            // The fixture path exists but is not on a POSIX-ACL dataset.
            Ok(Acl::Nfs4(_)) => require_zfs("/POSIXACL is not POSIX-ACL"),
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
    fn atomic_write_follows_a_target_that_changes_while_writing() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("config");

        // A target unlinked while write_fn runs is created afresh.
        atomic_replace(&target, b"v1", AtomicWriteOptions::default()).unwrap();
        atomic_write(&target, AtomicWriteOptions::default(), |f| {
            std::fs::remove_file(&target)?;
            f.write_all(b"v2")
        })
        .unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"v2");

        // A target that appears while write_fn runs is replaced.
        std::fs::remove_file(&target).unwrap();
        atomic_write(&target, AtomicWriteOptions::default(), |f| {
            std::fs::write(&target, b"other")?;
            f.write_all(b"v3")
        })
        .unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"v3");

        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .filter(|n| n != "config")
            .collect();
        assert!(leftovers.is_empty(), "temp files left: {leftovers:?}");
    }

    #[test]
    fn atomic_write_refuses_a_directory_target() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("config");
        atomic_replace(&target, b"v1", AtomicWriteOptions::default()).unwrap();

        let err = atomic_write(&target, AtomicWriteOptions::default(), |f| {
            std::fs::remove_file(&target)?;
            std::fs::create_dir(&target)?;
            std::fs::write(target.join("kept"), b"x")?;
            f.write_all(b"v2")
        })
        .unwrap_err();
        assert!(matches!(err, Error::Errno(Errno::EISDIR)), "{err:?}");

        // The directory stays where it is, with nothing left beside it.
        assert_eq!(std::fs::read(target.join("kept")).unwrap(), b"x");
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
        assert_eq!(sm.mnt_point.as_deref(), Some(std::path::Path::new("/")));
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
    use std::ffi::CStr;
    use std::os::unix::fs::PermissionsExt;
    use truenas_ros::errno::Errno;
    use truenas_ros::sync_fs::shutil::{
        copytree, copytree_reporting, CopyTreeConfig,
    };
    use truenas_ros::Error;

    // An xattr name need not be UTF-8 (the kernel checks length and namespace
    // only, and ZFS validates names solely on the dir path under `utf8only`).
    // The copier must address such a name by its bytes and carry it across.
    #[test]
    fn copies_xattr_with_non_utf8_name() {
        use std::os::fd::AsRawFd;
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        std::fs::create_dir(&src).unwrap();
        std::fs::write(src.join("f"), b"data").unwrap();
        let f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(src.join("f"))
            .unwrap();
        let name = std::ffi::CString::new(&b"user.caf\xe9\xff"[..]).unwrap();
        // SAFETY: `f` is live; `name`/value pointers are valid for the call.
        let rc = unsafe {
            libc::fsetxattr(
                f.as_raw_fd(),
                name.as_ptr(),
                b"v".as_ptr().cast(),
                1,
                0,
            )
        };
        if rc != 0 {
            return; // the filesystem rejects `user.` xattrs here
        }
        drop(f);

        let dst = tmp.path().join("dst");
        copytree(&src, &dst, &CopyTreeConfig::default()).unwrap();

        let d = std::fs::File::open(dst.join("f")).unwrap();
        let mut buf = [0u8; 8];
        // SAFETY: `d` is live; `name` and `buf` are valid for the call.
        let n = unsafe {
            libc::fgetxattr(
                d.as_raw_fd(),
                name.as_ptr(),
                buf.as_mut_ptr().cast(),
                buf.len(),
            )
        };
        assert_eq!(
            (n, &buf[..1.max(n.max(0) as usize)]),
            (1, &b"v"[..]),
            "a non-UTF-8 xattr name must survive the copy verbatim",
        );
    }

    // `security.capability` is a file capability set, so carrying it across a
    // copy would stamp privilege onto a destination whose content came from the
    // source. The kernel permits the write (it only asks for `CAP_SETFCAP`), so
    // refusing it is the copier's job — the same refusal the asynchronous side
    // makes in `PrivilegedXattrs::allow_prefix`. The `user.` attribute alongside
    // it must still arrive, or this would pass on a copy that did nothing.
    #[test]
    fn a_file_capability_does_not_survive_a_copy() {
        use std::os::fd::AsRawFd;
        // `struct vfs_cap_data`, VFS_CAP_REVISION_2 with the effective bit and
        // CAP_SETUID (7) permitted: magic_etc, then two {permitted,inheritable}
        // words, all little-endian.
        const CAP_SETUID_EP: [u8; 20] = [
            0x01, 0x00, 0x00, 0x02, // VFS_CAP_REVISION_2 | EFFECTIVE
            0x80, 0x00, 0x00, 0x00, // permitted  = 1 << CAP_SETUID
            0x00, 0x00, 0x00, 0x00, // inheritable
            0x00, 0x00, 0x00, 0x00, // permitted  (high word)
            0x00, 0x00, 0x00, 0x00, // inheritable (high word)
        ];
        let setxattr = |fd: &std::fs::File, name: &CStr, val: &[u8]| -> i32 {
            // SAFETY: `fd` is live; name and value pointers are valid here.
            unsafe {
                libc::fsetxattr(
                    fd.as_raw_fd(),
                    name.as_ptr(),
                    val.as_ptr().cast(),
                    val.len(),
                    0,
                )
            }
        };

        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        std::fs::create_dir(&src).unwrap();
        std::fs::write(src.join("bin"), b"#!/bin/sh\n").unwrap();
        let f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(src.join("bin"))
            .unwrap();
        if setxattr(&f, c"security.capability", &CAP_SETUID_EP) != 0 {
            return; // needs CAP_SETFCAP, or the fs has no security namespace
        }
        if setxattr(&f, c"user.marker", b"v") != 0 {
            return; // the filesystem rejects `user.` xattrs here
        }
        drop(f);

        let dst = tmp.path().join("dst");
        copytree(&src, &dst, &CopyTreeConfig::default()).unwrap();

        let d = std::fs::File::open(dst.join("bin")).unwrap();
        let getxattr = |name: &CStr| -> (isize, i32) {
            let mut buf = [0u8; 32];
            // SAFETY: `d` is live; name and buffer are valid for the call.
            let n = unsafe {
                libc::fgetxattr(
                    d.as_raw_fd(),
                    name.as_ptr(),
                    buf.as_mut_ptr().cast(),
                    buf.len(),
                )
            };
            (
                n,
                std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
            )
        };

        let (n, err) = getxattr(c"security.capability");
        assert_eq!(
            (n, err),
            (-1, libc::ENODATA),
            "a file capability must not be transplanted onto the copy"
        );
        assert_eq!(
            getxattr(c"user.marker").0,
            1,
            "the copy dropped every xattr, so the check above proves nothing"
        );
    }

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

    // The kernel clears S_ISUID/S_ISGID when a non-directory is chowned
    // (`chown_common`, fs/open.c), so the copy must apply ownership before the
    // mode for a setuid/setgid file — and for a special file — to keep both
    // bits.
    #[test]
    fn preserves_setid_bits_on_files_and_specials() {
        use std::os::unix::ffi::OsStrExt;
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        std::fs::create_dir(&src).unwrap();
        std::fs::write(src.join("helper"), b"data").unwrap();
        let fifo = src.join("pipe");
        let c = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o644) }, 0);
        // Setuid and setgid on an own file, both set with the group execute bit
        // so the kernel drops them unconditionally on chown.
        for name in ["helper", "pipe"] {
            std::fs::set_permissions(
                src.join(name),
                std::fs::Permissions::from_mode(0o6755),
            )
            .unwrap();
        }

        let dst = tmp.path().join("dst");
        copytree(&src, &dst, &CopyTreeConfig::default()).unwrap();

        for name in ["helper", "pipe"] {
            let mode = std::fs::symlink_metadata(dst.join(name))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o7777, 0o6755, "{name} lost its setid bits");
        }
    }

    // setid grants the destination *owner's* identity, so preserving the mode
    // without the ownership must not preserve it: a root-run copy of an
    // unprivileged user's 4755 file would otherwise yield a setuid-root binary
    // whose contents that user wrote.
    #[test]
    fn setid_withheld_when_ownership_is_not_preserved() {
        use std::os::unix::ffi::OsStrExt;
        use truenas_ros::sync_fs::shutil::CopyFlags;
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        std::fs::create_dir(&src).unwrap();
        std::fs::write(src.join("helper"), b"data").unwrap();
        let fifo = src.join("pipe");
        let c = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        for name in ["helper", "pipe"] {
            std::fs::set_permissions(
                src.join(name),
                std::fs::Permissions::from_mode(0o4755),
            )
            .unwrap();
        }

        // OWNER cleared: the destination keeps the copier's ownership, so setid
        // must not be carried over.
        let config = CopyTreeConfig {
            flags: CopyFlags::PERMISSIONS
                | CopyFlags::XATTRS
                | CopyFlags::TIMESTAMPS,
            ..Default::default()
        };
        let dst = tmp.path().join("dst");
        copytree(&src, &dst, &config).unwrap();

        for name in ["helper", "pipe"] {
            let mode = std::fs::symlink_metadata(dst.join(name))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o6000, 0, "{name} kept setid: {mode:o}");
            assert_eq!(mode & 0o777, 0o755);
        }
    }

    // A special file's permission bits are restored through a handle on the new
    // node, never a re-resolved name: a symlink planted at the destination name
    // is not the object chmodded, and the umask-masked bits are still restored
    // on the ordinary path.
    #[test]
    fn special_file_mode_is_not_applied_through_a_symlink() {
        use std::os::unix::ffi::OsStrExt;
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        std::fs::create_dir(&src).unwrap();
        let fifo = src.join("pipe");
        let c = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o777) }, 0);
        std::fs::set_permissions(&fifo, std::fs::Permissions::from_mode(0o777))
            .unwrap();

        let victim = tmp.path().join("victim");
        std::fs::write(&victim, b"victim-content").unwrap();
        std::fs::set_permissions(
            &victim,
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();

        let dst = tmp.path().join("dst");
        std::fs::create_dir(&dst).unwrap();
        std::os::unix::fs::symlink(&victim, dst.join("pipe")).unwrap();

        // exist_ok tolerates the planted name; whether the copy errors or skips,
        // nothing may be chmodded through the symlink.
        let _ = copytree(&src, &dst, &CopyTreeConfig::default());
        assert_eq!(
            std::fs::metadata(&victim).unwrap().permissions().mode() & 0o7777,
            0o600,
            "victim's mode changed — the destination name was followed"
        );
        assert_eq!(std::fs::read(&victim).unwrap(), b"victim-content");

        // The ordinary path restores the exact bits mknodat lost to the umask.
        let dst2 = tmp.path().join("dst2");
        let stats = copytree(&src, &dst2, &CopyTreeConfig::default()).unwrap();
        assert_eq!(stats.specials, 1);
        let md = std::fs::symlink_metadata(dst2.join("pipe")).unwrap();
        assert_eq!(md.permissions().mode() & 0o7777, 0o777);
    }

    // An existing destination file must be replaced, not filled in place: the
    // copied data must never appear in an inode someone else created and may
    // still hold open.
    #[test]
    fn existing_destination_file_is_replaced_not_reused() {
        use std::io::Read;
        use std::os::unix::fs::MetadataExt;
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        std::fs::create_dir(&src).unwrap();
        std::fs::write(src.join("secret"), b"SECRET-KEY-MATERIAL").unwrap();

        // The destination name is pre-created by someone who keeps it open.
        let dst = tmp.path().join("dst");
        std::fs::create_dir(&dst).unwrap();
        std::fs::write(dst.join("secret"), b"planted").unwrap();
        let mut planted = std::fs::File::open(dst.join("secret")).unwrap();
        let planted_ino = planted.metadata().unwrap().ino();

        // exist_ok (the default) still tolerates the existing entry.
        let stats = copytree(&src, &dst, &CopyTreeConfig::default()).unwrap();
        assert_eq!(stats.files, 1);
        assert_eq!(
            std::fs::read(dst.join("secret")).unwrap(),
            b"SECRET-KEY-MATERIAL"
        );

        // A different inode, and the held descriptor never sees the copy.
        let copied_ino = std::fs::metadata(dst.join("secret")).unwrap().ino();
        assert_ne!(copied_ino, planted_ino, "the copy reused the inode");
        let mut through_held_fd = Vec::new();
        planted.read_to_end(&mut through_held_fd).unwrap();
        assert_eq!(through_held_fd, b"planted");
    }

    // The destination root's mkdir must not resolve a symlink in the path: the
    // copy fails either way, but nothing may be created outside the tree.
    #[test]
    fn destination_root_is_not_created_through_a_symlink() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        std::fs::create_dir(&src).unwrap();
        std::fs::write(src.join("f"), b"data").unwrap();

        let outside = tmp.path().join("outside");
        std::fs::create_dir(&outside).unwrap();
        let stage = tmp.path().join("stage");
        std::fs::create_dir(&stage).unwrap();
        std::os::unix::fs::symlink(&outside, stage.join("link")).unwrap();

        let dst = stage.join("link/backup");
        assert!(copytree(&src, &dst, &CopyTreeConfig::default()).is_err());
        assert!(
            !outside.join("backup").exists(),
            "destination root was created outside the intended tree"
        );
    }

    // copytree does not chmod a file that carries an access ACL: the ACL is
    // authoritative for its permissions, and on a ZFS `aclmode=restricted`
    // dataset a chmod of an object with a non-trivial ACL is rejected. So the
    // ACL is copied faithfully, but the source's setid bits (which no ACL
    // encodes) are not carried over. Matches `truenas_os`.
    #[cfg(feature = "acl")]
    #[test]
    fn acl_bearing_file_is_copied_without_chmod() {
        use std::os::fd::AsFd;
        use truenas_ros::sync_fs::acl::{
            fsetacl_posix, PosixAce, PosixAcl, PosixPerm, PosixTag,
        };
        use truenas_ros::sync_fs::xattr::fgetxattr;

        let ace = |tag, perms, id| PosixAce {
            tag,
            perms,
            id,
            default: false,
        };
        let rx = PosixPerm::READ | PosixPerm::EXECUTE;
        // A named user and a mask, so the ACL cannot be folded back into the
        // mode and the xattr is really stored.
        let acl = PosixAcl::from_aces([
            ace(PosixTag::UserObj, PosixPerm::all(), -1),
            ace(PosixTag::User, rx, 1234),
            ace(PosixTag::GroupObj, rx, -1),
            ace(PosixTag::Mask, rx, -1),
            ace(PosixTag::Other, rx, -1),
        ]);

        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        std::fs::create_dir(&src).unwrap();
        std::fs::write(src.join("helper"), b"data").unwrap();
        std::fs::set_permissions(
            src.join("helper"),
            std::fs::Permissions::from_mode(0o6755),
        )
        .unwrap();
        let f = std::fs::File::open(src.join("helper")).unwrap();
        if fsetacl_posix(f.as_fd(), &acl.access_bytes().unwrap(), None).is_err()
        {
            return; // no POSIX ACLs here (an NFSv4-ACL dataset, say)
        }
        let src_acl = fgetxattr(f.as_fd(), "system.posix_acl_access").unwrap();
        assert_eq!(
            std::fs::metadata(src.join("helper"))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o6755,
            "setting an ACL must not disturb the source's setid bits"
        );

        let dst = tmp.path().join("dst");
        copytree(&src, &dst, &CopyTreeConfig::default()).unwrap();

        let copied = std::fs::File::open(dst.join("helper")).unwrap();
        assert_eq!(
            fgetxattr(copied.as_fd(), "system.posix_acl_access").unwrap(),
            src_acl,
            "the access ACL is copied"
        );
        // No chmod is issued for an ACL-bearing file, so the source's setid
        // bits are not carried; the ACL governs the rwx bits.
        assert_eq!(
            copied.metadata().unwrap().permissions().mode() & 0o7000,
            0,
            "an ACL-bearing file must not be chmod'd (aclmode=restricted safe)"
        );
    }

    // The sticky bit has no ACL representation, and no chmod runs on the ACL
    // path, so an ACL-bearing sticky directory arrives without S_ISVTX. The
    // bit is given up to keep the ACL: on ZFS a chmod rewrites the ACL to
    // match the mode — under the default aclmode=discard it replaces it
    // outright — so restoring one bit would destroy the ACL the copy just
    // carried. Pinned here so the trade stays a decision.
    #[test]
    fn an_acl_bearing_sticky_directory_arrives_without_the_sticky_bit() {
        use std::os::fd::AsFd;
        use truenas_ros::sync_fs::acl::{
            fsetacl_posix, PosixAce, PosixAcl, PosixPerm, PosixTag,
        };
        use truenas_ros::sync_fs::xattr::fgetxattr;

        let ace = |tag, perms, id| PosixAce {
            tag,
            perms,
            id,
            default: false,
        };
        let rwx = PosixPerm::all();
        // A named user and a mask, so the ACL cannot fold back into the mode.
        let acl = PosixAcl::from_aces([
            ace(PosixTag::UserObj, rwx, -1),
            ace(PosixTag::User, rwx, 1234),
            ace(PosixTag::GroupObj, rwx, -1),
            ace(PosixTag::Mask, rwx, -1),
            ace(PosixTag::Other, rwx, -1),
        ]);

        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        std::fs::create_dir(&src).unwrap();
        // The classic sticky shape: a world-writable shared directory.
        std::fs::create_dir(src.join("shared")).unwrap();
        std::fs::write(src.join("shared/f"), b"x").unwrap();
        std::fs::set_permissions(
            src.join("shared"),
            std::fs::Permissions::from_mode(0o1777),
        )
        .unwrap();
        let d = std::fs::File::open(src.join("shared")).unwrap();
        if fsetacl_posix(d.as_fd(), &acl.access_bytes().unwrap(), None).is_err()
        {
            return; // no POSIX ACLs here (an NFSv4-ACL dataset, say)
        }
        let src_acl = fgetxattr(d.as_fd(), "system.posix_acl_access").unwrap();
        assert_eq!(
            std::fs::metadata(src.join("shared"))
                .unwrap()
                .permissions()
                .mode()
                & 0o1000,
            0o1000,
            "setting an ACL must not disturb the source's sticky bit"
        );

        let dst = tmp.path().join("dst");
        copytree(&src, &dst, &CopyTreeConfig::default()).unwrap();

        let copied = std::fs::File::open(dst.join("shared")).unwrap();
        assert_eq!(
            fgetxattr(copied.as_fd(), "system.posix_acl_access").unwrap(),
            src_acl,
            "the directory's access ACL is what the copy preserves"
        );
        assert_eq!(
            std::fs::metadata(dst.join("shared"))
                .unwrap()
                .permissions()
                .mode()
                & 0o1000,
            0,
            "S_ISVTX is given up to keep the ACL intact; see copy_permissions"
        );
    }

    // A destination subdirectory is owner-only while its contents are written,
    // as the destination root is, and takes the source's mode afterwards.
    #[test]
    fn subdirectory_mode_is_applied_after_its_contents() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        let dst = tmp.path().join("dst");
        std::fs::create_dir_all(src.join("sub")).unwrap();
        std::fs::write(src.join("sub/f"), b"x").unwrap();
        std::fs::set_permissions(
            src.join("sub"),
            std::fs::Permissions::from_mode(0o777),
        )
        .unwrap();

        // The callback fires before each entry is copied, so when the walk
        // reaches sub/f the destination's `sub` exists but is not yet complete.
        let mut mid_copy = None;
        let cfg = CopyTreeConfig {
            reporting_increment: 1,
            ..Default::default()
        };
        copytree_reporting(&src, &dst, &cfg, &mut |p| {
            if p.current.ends_with("sub/f") {
                mid_copy = Some(
                    std::fs::metadata(dst.join("sub"))
                        .unwrap()
                        .permissions()
                        .mode()
                        & 0o7777,
                );
            }
        })
        .unwrap();

        assert_eq!(mid_copy, Some(0o700), "sub was reachable mid-copy");
        assert_eq!(
            std::fs::metadata(dst.join("sub"))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o777
        );
    }

    // A read-only source subdirectory must not make the destination copy of it
    // read-only before its children exist.
    #[test]
    fn copies_into_read_only_subdirectory() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        let dst = tmp.path().join("dst");
        std::fs::create_dir_all(src.join("sub")).unwrap();
        std::fs::write(src.join("sub/f"), b"hi").unwrap();
        std::fs::set_permissions(
            src.join("sub"),
            std::fs::Permissions::from_mode(0o555),
        )
        .unwrap();

        let res = copytree(&src, &dst, &CopyTreeConfig::default());
        let dst_mode = std::fs::metadata(dst.join("sub"))
            .ok()
            .map(|m| m.permissions().mode() & 0o7777);

        // Restore write so the tempdir cleanup can remove both trees.
        for d in [src.join("sub"), dst.join("sub")] {
            let _ = std::fs::set_permissions(
                d,
                std::fs::Permissions::from_mode(0o755),
            );
        }
        let stats = res.expect("read-only subdirectory should be copied into");
        assert_eq!(stats.files, 1);
        assert_eq!(std::fs::read(dst.join("sub/f")).unwrap(), b"hi");
        // The restrictive mode is still applied — just last.
        assert_eq!(dst_mode, Some(0o555));
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

    // A source file the copier cannot read fails the copy; it must not be left
    // out of the destination under a successful return.
    #[test]
    fn unreadable_source_file_fails_the_copy() {
        // CAP_DAC_OVERRIDE reads it regardless of the mode.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        let dst = tmp.path().join("dst");
        std::fs::create_dir(&src).unwrap();
        std::fs::write(src.join("secret"), b"data").unwrap();
        std::fs::set_permissions(
            src.join("secret"),
            std::fs::Permissions::from_mode(0o000),
        )
        .unwrap();

        let err = copytree(&src, &dst, &CopyTreeConfig::default()).unwrap_err();
        assert!(
            matches!(err, Error::Errno(Errno::EACCES | Errno::EPERM)),
            "unexpected error: {err:?}"
        );
        assert!(!dst.join("secret").exists());
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
