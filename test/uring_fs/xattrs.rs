use super::*;

/// The off-loop async-fs API enumerates a file's xattrs directly (no directory walk): `flistxattr` lists names,
/// `query_xattrs` returns namespace-filtered names and values read under `who`.
#[test]
fn fs_handle_query_xattrs_reads_user_namespace() {
    use std::collections::BTreeMap;
    use truenas_ros::uring_fs::XattrNamespaces;

    with_fs(test_cfg(), |h, me, dir, _stop| {
        std::fs::write(dir.join("f.txt"), b"hi").unwrap();
        let anchor = Anchor::open(dir.as_path()).unwrap();
        let how = OpenHow::new().flags(OFlag::O_RDWR);
        let f = h.open(me, &anchor, "f.txt", how).unwrap();

        let set = |name: &str, val: &[u8]| {
            let (res, _) = h.fsetxattr(me, &f, xattr_name(name), val.to_vec(), 0);
            res
        };
        if !fd_xattr_ok("fsetxattr(user.a)", &set("user.a", b"1")) {
            return; // this kernel/fs refuses fd xattrs
        }
        set("user.b", b"22").unwrap();

        let names: Vec<String> = h
            .flistxattr(&f)
            .unwrap()
            .into_iter()
            .map(|c| c.to_string_lossy().into_owned())
            .collect();
        assert!(names.iter().any(|n| n == "user.a"));
        assert!(names.iter().any(|n| n == "user.b"));

        let got: BTreeMap<String, Vec<u8>> = h
            .query_xattrs(me, &f, XattrNamespaces::USER)
            .unwrap()
            .into_iter()
            .map(|(n, v)| (n.to_string_lossy().into_owned(), v))
            .collect();
        assert_eq!(got.get("user.a").map(Vec::as_slice), Some(&b"1"[..]));
        assert_eq!(got.get("user.b").map(Vec::as_slice), Some(&b"22"[..]));

        h.close(f).unwrap();
    });
}

/// Off-loop `query_xattrs` gates each value read under `who`: an unprivileged identity gets the world-readable `user.*`
/// attribute but never the `trusted.*` one, while a privileged identity does.
#[test]
fn fs_handle_query_xattrs_drops_unreadable_trusted() {
    use std::collections::BTreeMap;
    use truenas_ros::uring_fs::XattrNamespaces;

    if !root_or_skip("fs_handle_query_xattrs_drops_unreadable_trusted") {
        return; // broker impersonation and trusted.* both need privilege
    }
    const NOBODY_UID: u32 = 65_534;
    const NOBODY_GID: u32 = 65_534;

    with_broker(|h, creds, me, dir| {
        std::fs::write(dir.join("f.txt"), b"hi").unwrap();
        std::fs::set_permissions(dir.join("f.txt"), std::fs::Permissions::from_mode(0o644)).unwrap();
        let anchor = Anchor::open(dir).unwrap();
        let owner = h.open(me, &anchor, "f.txt", OpenHow::new().flags(OFlag::O_RDWR));
        let owner = owner.unwrap();

        let set = |name: &str, val: &[u8]| {
            let (res, _) = h.fsetxattr(me, &owner, xattr_name(name), val.to_vec(), 0);
            res
        };
        if !fd_xattr_ok("fsetxattr(user.pub)", &set("user.pub", b"public")) {
            return; // fd xattrs unsupported
        }
        set("trusted.secret", b"classified").unwrap();
        h.close(owner).unwrap();

        let peer = creds.register(&AsUser::new(NOBODY_UID, NOBODY_GID)).unwrap();
        let ns = XattrNamespaces::USER | XattrNamespaces::TRUSTED;
        let query = |who| {
            let how = OpenHow::new().flags(OFlag::O_RDONLY);
            let f = h.open(who, &anchor, "f.txt", how).unwrap();
            let got: BTreeMap<String, Vec<u8>> = h
                .query_xattrs(who, &f, ns)
                .unwrap()
                .into_iter()
                .map(|(n, v)| (n.to_string_lossy().into_owned(), v))
                .collect();
            h.close(f).unwrap();
            got
        };

        let peer_view = query(peer);
        assert!(peer_view.contains_key("user.pub"));
        assert!(
            !peer_view.contains_key("trusted.secret"),
            "trusted.* must not leak off-loop"
        );

        let root_view = query(me);
        assert_eq!(
            root_view.get("trusted.secret").map(Vec::as_slice),
            Some(&b"classified"[..]),
        );
    });
}

/// `FsHandle::fgetxattr_as_root` reads under the reactor's ambient (root) credentials, so it returns a `trusted.*`
/// value that the same fd's normal `who`-attributed read (as an unprivileged identity) is denied.
#[test]
fn fs_handle_fgetxattr_as_root_reads_trusted() {
    if !root_or_skip("fs_handle_fgetxattr_as_root_reads_trusted") {
        return; // broker impersonation and trusted.* both need privilege
    }
    const NOBODY_UID: u32 = 65_534;
    const NOBODY_GID: u32 = 65_534;

    with_broker(|h, creds, me, dir| {
        std::fs::write(dir.join("f.txt"), b"hi").unwrap();
        std::fs::set_permissions(dir.join("f.txt"), std::fs::Permissions::from_mode(0o644)).unwrap();
        let anchor = Anchor::open(dir).unwrap();
        let how = OpenHow::new().flags(OFlag::O_RDWR);
        let f = h.open(me, &anchor, "f.txt", how).unwrap();
        let name = xattr_name("trusted.secret");
        let (set, _) = h.fsetxattr(me, &f, name.clone(), b"classified".to_vec(), 0);
        if !fd_xattr_ok("fsetxattr(trusted.secret)", &set) {
            return; // fd xattrs unsupported
        }

        let peer = creds.register(&AsUser::new(NOBODY_UID, NOBODY_GID)).unwrap();
        let (peer_res, _) = h.fgetxattr(peer, &f, name.clone(), vec![0u8; 64]);
        assert!(peer_res.is_err(), "peer cannot read trusted.* as itself");

        let (root_res, buf) = h.fgetxattr_as_root(&f, name.clone(), vec![0u8; 64]);
        let n = root_res.expect("as-root read succeeds");
        assert_eq!(&buf[..n], b"classified");

        h.close(f).unwrap();
    });
}

/// `FsHandle::fgetxattr_proc` reads an xattr of a file held `O_PATH`, which `fgetxattr` refuses, and reads it as the
/// personality. So nobody reads a file of mode 0644 and is refused once it is 0600. A link held `O_PATH` with
/// `O_NOFOLLOW` is read itself, which has no `user.` attribute, rather than the file it names.
#[test]
fn fgetxattr_proc_reads_a_file_held_o_path_as_the_personality() {
    if !root_or_skip("fgetxattr_proc_reads_a_file_held_o_path_as_the_personality") {
        return; // the broker needs privilege
    }
    with_broker(|h, creds, me, dir| {
        std::fs::write(dir.join("f"), b"body").unwrap();
        std::fs::set_permissions(dir.join("f"), std::fs::Permissions::from_mode(0o644)).unwrap();
        std::os::unix::fs::symlink("f", dir.join("l")).unwrap();
        let anchor = Anchor::open(dir).unwrap();
        let name = xattr_name("user.proc");
        let rw = h.open(me, &anchor, "f", OpenHow::new().flags(OFlag::O_RDWR)).unwrap();
        let (set, _) = h.fsetxattr(me, &rw, name.clone(), b"seen".to_vec(), 0);
        if !fd_xattr_ok("fsetxattr(user.proc)", &set) {
            return; // fd xattrs unsupported
        }
        h.close(rw).unwrap();

        let how = OpenHow::new().flags(OFlag::O_PATH);
        let f = h.open(me, &anchor, "f", how).unwrap();
        let (res, _) = h.fgetxattr(me, &f, name.clone(), vec![0u8; 16]);
        assert!(
            matches!(res, Err(Error::Errno(Errno::EBADF))),
            "fgetxattr refuses an O_PATH file, got {res:?}"
        );
        let (n, buf) = h.fgetxattr_proc(me, &f, name.clone(), vec![0u8; 16]);
        assert_eq!(&buf[..n.expect("read through /proc")], b"seen");

        let nobody = creds.register(&AsUser::new(NOBODY_UID, NOBODY_GID)).unwrap();
        let (n, buf) = h.fgetxattr_proc(nobody, &f, name.clone(), vec![0u8; 16]);
        assert_eq!(&buf[..n.expect("nobody reads at 0644")], b"seen");
        std::fs::set_permissions(dir.join("f"), std::fs::Permissions::from_mode(0o600)).unwrap();
        let (res, _) = h.fgetxattr_proc(nobody, &f, name.clone(), vec![0u8; 16]);
        assert!(
            matches!(res, Err(Error::Errno(Errno::EACCES))),
            "nobody is refused at 0600, got {res:?}"
        );

        let how = OpenHow::new().flags(OFlag::O_PATH | OFlag::O_NOFOLLOW);
        let l = h.open(me, &anchor, "l", how).unwrap();
        let (res, _) = h.fgetxattr_proc(me, &l, name.clone(), vec![0u8; 16]);
        assert!(
            matches!(res, Err(Error::Errno(Errno::ENODATA))),
            "the link is read, not its target, got {res:?}"
        );

        creds.unregister(nobody).unwrap();
        h.close(f).unwrap();
        h.close(l).unwrap();
    });
}

/// The NFSv4-ACL dataset, or `None` to skip, which `TRUENAS_ROS_REQUIRE_ZFS` turns into a failure.
fn nfs4_dataset_or_skip() -> Option<PathBuf> {
    let dir = std::env::var_os("TRUENAS_ROS_NFS4_DATASET").map_or_else(|| PathBuf::from("/NFSV4ACL"), PathBuf::from);
    if zfs_dir::is_zfs(&dir) == Some(true) {
        return Some(dir);
    }
    assert!(
        std::env::var_os("TRUENAS_ROS_REQUIRE_ZFS").is_none(),
        "TRUENAS_ROS_REQUIRE_ZFS is set but {} is not a ZFS dataset",
        dir.display()
    );
    None
}

/// On an NFSv4 dataset `FsHandle::fgetxattr_proc` reads the ACL of a file and of a FIFO, both held `O_PATH`, as the
/// personality, so ZFS checks READ_ACL for it (`__zpl_xattr_nfs41acl_get` in `zpl_xattr.c`). A user an entry grants
/// READ_ACL reads what root reads, and nobody, whom no entry grants it, is refused. The FIFO is read with no open, so
/// no writer is needed.
#[test]
fn fgetxattr_proc_reads_an_nfs4_acl_as_the_personality() {
    if !root_or_skip("fgetxattr_proc_reads_an_nfs4_acl_as_the_personality") {
        return; // the broker and the ACL need privilege
    }
    let Some(ds) = nfs4_dataset_or_skip() else {
        return;
    };
    const READER: u32 = 8_675_309;
    // OWNER@ is allowed everything, READER READ_ACL, READ_ATTRIBUTES and SYNCHRONIZE, and EVERYONE@ only the last two.
    let acl = nfs4_xdr(&[
        [0, 0, 1, 0x1f_01ff, 1],
        [0, 0, 0, 0x12_0080, READER],
        [0, 0, 1, 0x10_0080, 3],
    ]);
    // An ACL takes 8 bytes of head and 20 for each of at most 1024 entries (`MAX_ACL_ENTRIES`).
    const MOST: usize = 8 + 20 * 1024;
    with_broker(|h, creds, me, _dir| {
        let anchor = Anchor::open(ds.as_path()).unwrap();
        let file = format!("rostest_procacl_{}", std::process::id());
        let fifo = format!("rostest_procfifo_{}", std::process::id());
        let _ = std::fs::remove_file(ds.join(&file));
        let _ = std::fs::remove_file(ds.join(&fifo));
        std::fs::write(ds.join(&file), b"acl").unwrap();
        mkfifo(&ds, &fifo);
        let reader = creds.register(&AsUser::new(READER, READER)).unwrap();
        let nobody = creds.register(&AsUser::new(NOBODY_UID, NOBODY_GID)).unwrap();
        let name = xattr_name("system.nfs4_acl_xdr");
        for leaf in [file.as_str(), fifo.as_str()] {
            let how = OpenHow::new().flags(OFlag::O_RDONLY);
            let open = h.open(me, &anchor, leaf, how).unwrap();
            let (set, _) = h.fsetxattr(me, &open, name.clone(), acl.clone(), 0);
            set.expect("root sets the ACL");
            let (n, stored) = h.fgetxattr(me, &open, name.clone(), vec![0; MOST]);
            let stored = stored[..n.expect("root reads the ACL")].to_vec();
            h.close(open).unwrap();

            let how = OpenHow::new().flags(OFlag::O_PATH);
            let held = h.open(me, &anchor, leaf, how).unwrap();
            let (n, got) = h.fgetxattr_proc(reader, &held, name.clone(), vec![0; MOST]);
            let n = n.unwrap_or_else(|e| panic!("{leaf} for READER: {e}"));
            assert_eq!(got[..n], stored[..], "{leaf}");
            let (res, _) = h.fgetxattr_proc(nobody, &held, name.clone(), vec![0; MOST]);
            assert!(
                matches!(res, Err(Error::Errno(Errno::EACCES))),
                "{leaf} refuses nobody READ_ACL, got {res:?}"
            );
            h.close(held).unwrap();
        }
        creds.unregister(reader).unwrap();
        creds.unregister(nobody).unwrap();
        std::fs::remove_file(ds.join(&file)).unwrap();
        std::fs::remove_file(ds.join(&fifo)).unwrap();
    });
}

/// On an NFSv4 dataset `FsHandle::fgetxattr_proc_as_root` reads the ACL of a file and of a FIFO held `O_PATH` under the
/// ring owner's credentials, whose CAP_DAC_OVERRIDE has ZFS skip the check of READ_ACL (`__zpl_xattr_nfs41acl_get` in
/// `zpl_xattr.c` passes `ATTR_NOACLCHECK`), so an ACL that grants nobody READ_ACL comes back whole where the same read
/// as nobody is refused, and `fgetxattr_as_root` refuses the `O_PATH` descriptor itself. A server that answers an
/// access check from the ACL on behalf of a caller relies on this.
#[test]
fn fgetxattr_proc_as_root_reads_an_nfs4_acl_its_entries_hide() {
    if !root_or_skip("fgetxattr_proc_as_root_reads_an_nfs4_acl_its_entries_hide") {
        return; // the broker and the ACL need privilege
    }
    let Some(ds) = nfs4_dataset_or_skip() else {
        return;
    };
    // OWNER@ is allowed everything and EVERYONE@ READ_ATTRIBUTES and SYNCHRONIZE alone, so no entry grants nobody
    // READ_ACL.
    let acl = nfs4_xdr(&[[0, 0, 1, 0x1f_01ff, 1], [0, 0, 1, 0x10_0080, 3]]);
    const MOST: usize = 8 + 20 * 1024;
    with_broker(|h, creds, me, _dir| {
        let anchor = Anchor::open(ds.as_path()).unwrap();
        let file = format!("rostest_rootacl_{}", std::process::id());
        let fifo = format!("rostest_rootfifo_{}", std::process::id());
        let _ = std::fs::remove_file(ds.join(&file));
        let _ = std::fs::remove_file(ds.join(&fifo));
        std::fs::write(ds.join(&file), b"acl").unwrap();
        mkfifo(&ds, &fifo);
        let nobody = creds.register(&AsUser::new(NOBODY_UID, NOBODY_GID)).unwrap();
        let name = xattr_name("system.nfs4_acl_xdr");
        for leaf in [file.as_str(), fifo.as_str()] {
            let how = OpenHow::new().flags(OFlag::O_RDONLY);
            let open = h.open(me, &anchor, leaf, how).unwrap();
            let (set, _) = h.fsetxattr(me, &open, name.clone(), acl.clone(), 0);
            set.expect("root sets the ACL");
            let (n, stored) = h.fgetxattr(me, &open, name.clone(), vec![0; MOST]);
            let stored = stored[..n.expect("root reads the ACL")].to_vec();
            h.close(open).unwrap();

            let how = OpenHow::new().flags(OFlag::O_PATH);
            let held = h.open(me, &anchor, leaf, how).unwrap();
            let (res, _) = h.fgetxattr_proc(nobody, &held, name.clone(), vec![0; MOST]);
            assert!(
                matches!(res, Err(Error::Errno(Errno::EACCES))),
                "{leaf} refuses nobody READ_ACL, got {res:?}"
            );
            let (res, _) = h.fgetxattr_as_root(&held, name.clone(), vec![0; MOST]);
            assert!(
                matches!(res, Err(Error::Errno(Errno::EBADF))),
                "{leaf} held O_PATH refuses fgetxattr, got {res:?}"
            );
            let (n, got) = h.fgetxattr_proc_as_root(&held, name.clone(), vec![0; MOST]);
            let n = n.unwrap_or_else(|e| panic!("{leaf} as root: {e}"));
            assert_eq!(got[..n], stored[..], "{leaf}");
            h.close(held).unwrap();
        }
        creds.unregister(nobody).unwrap();
        std::fs::remove_file(ds.join(&file)).unwrap();
        std::fs::remove_file(ds.join(&fifo)).unwrap();
    });
}

#[test]
fn query_pool_lists_directory() {
    use std::collections::BTreeSet;
    use std::ffi::CString;
    use truenas_ros::uring_fs::{EnrichSpec, QueryOptions, QueryPool};

    with_fs(test_cfg(), |h, me, dir, _stop| {
        for n in ["x.txt", "y.txt", "z.txt"] {
            std::fs::write(dir.join(n), b"hi").unwrap();
        }
        let anchor = Anchor::open(dir.as_path()).unwrap();
        let pool = QueryPool::new(h);
        let opts = QueryOptions {
            spec: EnrichSpec::STATX,
            xattr_names: vec![],
            acl_name: CString::new("system.nfs4_acl_xdr").unwrap(),
            xattr_ns: truenas_ros::uring_fs::XattrNamespaces::empty(),
            clump: 2,
            same_device_only: false,
            ..Default::default()
        };
        let handle = pool.query(me, anchor, opts);
        let mut names: BTreeSet<String> = BTreeSet::new();
        while let Some(batch) = handle.next() {
            for e in batch.unwrap() {
                names.insert(e.name.to_string_lossy().into_owned());
            }
        }
        let want: BTreeSet<String> = ["x.txt", "y.txt", "z.txt"].into_iter().map(String::from).collect();
        assert_eq!(names, want);
    });
}

#[test]
fn query_pool_runs_multiple_listings() {
    use std::collections::BTreeSet;
    use std::ffi::CString;
    use truenas_ros::uring_fs::{EnrichSpec, QueryHandle, QueryOptions, QueryPool};

    with_fs(test_cfg(), |h, me, dir, _stop| {
        let d1 = dir.join("d1");
        let d2 = dir.join("d2");
        std::fs::create_dir(&d1).unwrap();
        std::fs::create_dir(&d2).unwrap();
        std::fs::write(d1.join("a"), b"1").unwrap();
        std::fs::write(d1.join("b"), b"1").unwrap();
        std::fs::write(d2.join("c"), b"2").unwrap();

        let a1 = Anchor::open(d1.as_path()).unwrap();
        let a2 = Anchor::open(d2.as_path()).unwrap();
        let pool = QueryPool::new(h);
        let mk_opts = || QueryOptions {
            spec: EnrichSpec::STATX,
            xattr_names: vec![],
            acl_name: CString::new("system.nfs4_acl_xdr").unwrap(),
            xattr_ns: truenas_ros::uring_fs::XattrNamespaces::empty(),
            clump: 8,
            same_device_only: false,
            ..Default::default()
        };
        // Submit BOTH from this one thread before collecting either - the pool runs the walks (up to 2 concurrently),
        // decoupled from the caller.
        let h1 = pool.query(me, a1, mk_opts());
        let h2 = pool.query(me, a2, mk_opts());
        let collect = |handle: &QueryHandle| {
            let mut names = BTreeSet::new();
            while let Some(batch) = handle.next() {
                for e in batch.unwrap() {
                    names.insert(e.name.to_string_lossy().into_owned());
                }
            }
            names
        };
        let n1 = collect(&h1);
        let n2 = collect(&h2);
        let want1: BTreeSet<String> = ["a", "b"].into_iter().map(String::from).collect();
        let want2: BTreeSet<String> = ["c"].into_iter().map(String::from).collect();
        assert_eq!(n1, want1, "d1 listing");
        assert_eq!(n2, want2, "d2 listing");
    });
}

#[test]
fn pool_copy_file_range_whole() {
    use truenas_ros::uring_fs::QueryPool;

    with_fs(test_cfg(), |h, me, dir, _stop| {
        let content: Vec<u8> = (0..5000u32).map(|i| i as u8).collect();
        std::fs::write(dir.join("src"), &content).unwrap();
        std::fs::write(dir.join("dst"), b"").unwrap();
        let anchor = Anchor::open(dir.as_path()).unwrap();
        let src = h
            .open(me, &anchor, "src", OpenHow::new().flags(OFlag::O_RDONLY))
            .unwrap();
        let dst = h.open(me, &anchor, "dst", OpenHow::new().flags(OFlag::O_RDWR)).unwrap();
        let pool = QueryPool::new(h);
        // Clones inline on a block-cloning fs, else offloads a byte copy -- either way the bytes land.
        let n = match pool.copy_file_range(&src, &dst, 0, 0, content.len() as u64).wait() {
            Ok(n) => n,
            // Not a skip: every filesystem these tests run on serves copy_file_range, so an error here is the copy path
            // broken, and swallowing it is how a green suite covers nothing.
            Err(e) => panic!("copy_file_range: {e}"),
        };
        assert_eq!(n, content.len() as u64);
        assert_eq!(std::fs::read(dir.join("dst")).unwrap(), content);
    });
}

#[test]
fn pool_copy_file_range_ranged_offload() {
    use truenas_ros::uring_fs::QueryPool;

    with_fs(test_cfg(), |h, me, dir, _stop| {
        // src byte i = (i / 100): three 100-byte runs of 0, 1, 2.
        let content: Vec<u8> = (0..300u32).map(|i| (i / 100) as u8).collect();
        std::fs::write(dir.join("src"), &content).unwrap();
        std::fs::write(dir.join("dst"), vec![0xFFu8; 300]).unwrap();
        let anchor = Anchor::open(dir.as_path()).unwrap();
        let src = h
            .open(me, &anchor, "src", OpenHow::new().flags(OFlag::O_RDONLY))
            .unwrap();
        let dst = h.open(me, &anchor, "dst", OpenHow::new().flags(OFlag::O_RDWR)).unwrap();
        let pool = QueryPool::new(h);
        // A misaligned sub-block range forces the byte-copy offload path even on a block-cloning fs: copy src[100..200]
        // -> dst[50..150].
        let n = match pool.copy_file_range(&src, &dst, 100, 50, 100).wait() {
            Ok(n) => n,
            Err(e) => panic!("copy_file_range: {e}"),
        };
        assert_eq!(n, 100);
        let out = std::fs::read(dir.join("dst")).unwrap();
        assert_eq!(&out[50..150], &content[100..200], "the copied range");
        assert_eq!(out[49], 0xFF, "before the range: untouched");
        assert_eq!(out[150], 0xFF, "after the range: untouched");
    });
}

/// The `EXDEV` byte-copy fallback, entered where it actually runs.
///
/// `copy_file_range(2)` answers `EXDEV` when the endpoints are on different filesystems, and `copy_range_rw` carries
/// the bytes then. Every other copy test puts both endpoints in one tempdir, where that answer never comes, so here one
/// endpoint is on the tempdir's filesystem and the other on a ZFS dataset.
#[test]
fn pool_copy_file_range_across_filesystems_takes_the_byte_copy() {
    use truenas_ros::uring_fs::QueryPool;

    let Some(ds) = zfs_dir_or_skip() else {
        return;
    };
    let scratch = ds.join(format!("ros-xdev-{}", std::process::id()));
    std::fs::create_dir_all(&scratch).unwrap();

    let content: Vec<u8> = (0..5000u32).map(|i| i as u8).collect();
    let result = std::panic::catch_unwind({
        let scratch = scratch.clone();
        let content = content.clone();
        move || {
            with_fs(test_cfg(), |h, me, dir, _stop| {
                std::fs::write(dir.join("src"), &content).unwrap();
                std::fs::write(scratch.join("dst"), b"").unwrap();
                let a_src = Anchor::open(dir.as_path()).unwrap();
                let a_dst = Anchor::open(scratch.as_path()).unwrap();
                let src = h
                    .open(me, &a_src, "src", OpenHow::new().flags(OFlag::O_RDONLY))
                    .unwrap();
                let dst = h.open(me, &a_dst, "dst", OpenHow::new().flags(OFlag::O_RDWR)).unwrap();
                let pool = QueryPool::new(h);
                let n = pool
                    .copy_file_range(&src, &dst, 0, 0, content.len() as u64)
                    .wait()
                    .expect("the cross-filesystem copy must carry the bytes");
                assert_eq!(n, content.len() as u64);
                assert_eq!(
                    std::fs::read(scratch.join("dst")).unwrap(),
                    content,
                    "the EXDEV fallback copied the wrong bytes"
                );
            });
        }
    });
    let _ = std::fs::remove_dir_all(&scratch);
    if let Err(e) = result {
        std::panic::resume_unwind(e);
    }
}

/// The copy on a ZFS dataset, which serves it as a block clone (`zfs_clone_range`) where tmpfs serves a plain copy. The
/// other copy tests run in `crate::tempdir()`, so they assert nothing about the clone.
#[test]
fn pool_copy_file_range_on_a_dataset() {
    use truenas_ros::uring_fs::QueryPool;

    let Some(ds) = zfs_dir_or_skip() else {
        return;
    };
    let scratch = ds.join(format!("ros-clone-{}", std::process::id()));
    std::fs::create_dir_all(&scratch).unwrap();

    // Several blocks, whole-range and block-aligned: the shape that can clone. A range split below MAX_CHUNK forfeits
    // it, which no other test in the tree would notice.
    let content: Vec<u8> = (0..(1024u32 * 1024)).map(|i| i as u8).collect();
    let result = std::panic::catch_unwind({
        let scratch = scratch.clone();
        let content = content.clone();
        move || {
            with_fs(test_cfg(), |h, me, _dir, _stop| {
                std::fs::write(scratch.join("src"), &content).unwrap();
                std::fs::write(scratch.join("dst"), b"").unwrap();
                let anchor = Anchor::open(scratch.as_path()).unwrap();
                let src = h
                    .open(me, &anchor, "src", OpenHow::new().flags(OFlag::O_RDONLY))
                    .unwrap();
                let dst = h.open(me, &anchor, "dst", OpenHow::new().flags(OFlag::O_RDWR)).unwrap();
                let pool = QueryPool::new(h);
                let n = pool
                    .copy_file_range(&src, &dst, 0, 0, content.len() as u64)
                    .wait()
                    .expect("the dataset copy must carry the bytes");
                assert_eq!(n, content.len() as u64, "whole range in one call");
                assert_eq!(
                    std::fs::read(scratch.join("dst")).unwrap(),
                    content,
                    "the dataset copy produced the wrong bytes"
                );
            });
        }
    });
    let _ = std::fs::remove_dir_all(&scratch);
    if let Err(e) = result {
        std::panic::resume_unwind(e);
    }
}
