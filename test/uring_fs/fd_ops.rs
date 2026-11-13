use super::*;

// ---- fadvise / fremovexattr / copy_file_range ------------------------------

/// `fadvise` is advisory, so the assertion is that it is *accepted* and does not disturb the file - both advices ZFS
/// implements natively (`WILLNEED` is a `dmu_prefetch`, `DONTNEED` a `dmu_evict_range`) plus the whole-file `0` length
/// form.
#[test]
fn fadvise_is_accepted_and_leaves_contents_alone() {
    with_fs(test_cfg(), |h, me, dir, _stop| {
        let anchor = Anchor::open(dir.as_path()).expect("anchor");
        let f = h.open(me, &anchor, "adv.bin", creat_rw()).expect("open");
        let (n, _) = pwrite1(&h, me, &f, b"0123456789".to_vec(), 0);
        assert_eq!(n.expect("write"), 10);

        for advice in [
            Advice::Normal,
            Advice::Sequential,
            Advice::Random,
            Advice::WillNeed,
            Advice::NoReuse,
        ] {
            h.fadvise(me, &f, 0, 10, advice)
                .unwrap_or_else(|e| panic!("fadvise {advice:?}: {e}"));
        }
        // Length 0 means "to end of file" - the form used after syncing a whole object, and the one most likely to be
        // mis-encoded since the kernel reads the length from `addr`, not `len`.
        h.fadvise(me, &f, 0, 0, Advice::DontNeed).expect("dontneed");
        h.fadvise(me, &f, 4, 6, Advice::DontNeed).expect("ranged");

        let (n, buf) = pread1(&h, me, &f, vec![0u8; 10], 0);
        assert_eq!(n.expect("read"), 10);
        assert_eq!(&buf[..10], b"0123456789", "advice must not alter data");
        h.close(f).unwrap();
    });
}

/// Drive `client` against a reactor whose [`PrivilegedXattrs`] policy claims `trusted.example_`, the namespace these
/// two tests treat as server-owned.
fn with_priv_xattr_fs<F>(client: F)
where
    F: FnOnce(&FsHandle, Personality, &Path) + Send,
{
    let mut afs = match UringFs::new(test_cfg()) {
        Ok(a) => a,
        Err(e) => {
            if should_skip(&e) {
                return;
            }
            panic!("UringFs::new: {e}");
        }
    };
    afs.set_privileged_xattrs(
        PrivilegedXattrs::new()
            .allow_prefix(c"trusted.example_")
            .expect("allowlist"),
    );
    let me = afs.register_self().expect("register_self");
    let h = afs.handle();
    let stop = afs.shutdown_handle();
    let dir = truenas_ros::tempdir().expect("tempdir");
    let dir_path = dir.path().to_path_buf();
    thread::scope(|s| {
        s.spawn(move || {
            let _guard = StopGuard(stop);
            client(&h, me, &dir_path);
        });
        afs.run().expect("run");
    });
}

/// The allowlist is the whole security contract for `fremovexattr`: it takes no [`Personality`], so an attribute the
/// server does not own must be refused outright rather than removed under the reactor's credentials.
///
/// Deliberately needs no privilege - the refusal is decided from the policy before any syscall, so this runs everywhere
/// and is the half worth having unconditional coverage of.
#[test]
fn fremovexattr_refuses_attributes_outside_the_allowlist() {
    with_priv_xattr_fs(|h, me, dir| {
        let anchor = Anchor::open(dir).expect("anchor");
        let f = h.open(me, &anchor, "obj", creat_rw()).expect("open");
        let user = xattr_name("user.mine");
        h.fsetxattr(me, &f, user.clone(), b"xyz".to_vec(), 0)
            .0
            .expect("an unprivileged user.* set");

        assert!(
            matches!(h.fremovexattr(&f, user.clone()), Err(Error::Errno(Errno::EPERM))),
            "an attribute the server does not own must not be removable"
        );
        assert!(
            h.flistxattr(&f).unwrap().contains(&user),
            "the refused attribute is still there"
        );
        h.close(f).unwrap();
    });
}

/// The other half: an allowlisted attribute really is removed, and is *gone from the listing* rather than left present
/// with an empty value - which is all a zero-length `FSETXATTR` would have achieved.
///
/// Root-only: writing `trusted.*` needs `CAP_SYS_ADMIN`, and the allowlist promotion runs under the reactor's own
/// credentials, so an unprivileged reactor cannot set the attribute this removes.
#[test]
fn fremovexattr_removes_allowlisted_attributes() {
    if !root_or_skip("fremovexattr_removes_allowlisted_attributes") {
        return;
    }
    with_priv_xattr_fs(|h, me, dir| {
        let anchor = Anchor::open(dir).expect("anchor");
        let f = h.open(me, &anchor, "obj", creat_rw()).expect("open");
        let owned = xattr_name("trusted.example_etag");
        let user = xattr_name("user.mine");
        h.fsetxattr(me, &f, owned.clone(), b"abc".to_vec(), 0)
            .0
            .expect("server-owned set is promoted to the reactor's creds");
        h.fsetxattr(me, &f, user.clone(), b"xyz".to_vec(), 0)
            .0
            .expect("user set");

        h.fremovexattr(&f, owned.clone()).expect("server-owned removal");
        let names = h.flistxattr(&f).unwrap();
        assert!(!names.contains(&owned), "removed, not emptied: {names:?}");
        assert!(names.contains(&user), "the other attribute is untouched");

        // Removing what is not there is an error, not a silent success.
        assert!(h.fremovexattr(&f, owned.clone()).is_err());
        h.close(f).unwrap();
    });
}

/// A subtree that cannot be *opened* for a non-permission reason must surface as an error, not vanish from the walk the
/// way the readdir path already refuses to. A silently dropped subtree is data loss for the recursive delete/copy this
/// walk backs.
///
/// The trigger is a real race: a directory is yielded, and the descent into it is deferred to the next call so
/// `skip_descent` can cancel it - swap the directory for a regular file inside that window and the deferred
/// `O_DIRECTORY` open fails `ENOTDIR`.
///
/// Keep any provocation here *local* to the walk. A binary's tests share one process, so exhausting a process-wide
/// resource such as the fd table would fail an unrelated test.
#[test]
fn descend_open_failure_surfaces_rather_than_dropping_the_subtree() {
    with_fs(test_cfg(), |h, me, dir, _stop| {
        std::fs::create_dir(dir.join("sub")).unwrap();
        std::fs::write(dir.join("sub/f.txt"), b"x").unwrap();
        std::fs::write(dir.join("z.txt"), b"x").unwrap();
        let anchor = Anchor::open(dir.as_path()).expect("anchor");

        let mut t = query_tree(&h, me, &anchor, TreeOptions::default()).expect("query_tree");
        // "sub/" sorts before "z.txt"; its descent is deferred to the next call.
        assert_eq!(t.next().expect("some").expect("ok").key(), b"sub/");

        // The window: replace the directory with a regular file of the same name, so the deferred open of "sub" cannot
        // be a directory open.
        std::fs::remove_file(dir.join("sub/f.txt")).unwrap();
        std::fs::remove_dir(dir.join("sub")).unwrap();
        std::fs::write(dir.join("sub"), b"x").unwrap();

        match t.next() {
            Some(Err(Error::Errno(Errno::ENOTDIR))) => {}
            other => panic!("an unopenable subtree must surface an error, got {other:?}"),
        }
        // The error is per-subtree, not fatal: the walk carries on in the parent with the sibling it had already read.
        assert_eq!(
            t.next().expect("some").expect("ok").key(),
            b"z.txt",
            "a surfaced descend failure must not end the walk"
        );
    });
}

/// The other side of that race, and the common one: a directory removed between the parent's `readdir` and the deferred
/// descent leaves no subtree to list, so it drops out quietly rather than failing the walk. Any walk over a tree being
/// written to hits this routinely, and a recursive copy that aborted every time a directory went away underneath it
/// would be unusable.
#[test]
fn a_subtree_removed_under_the_walk_is_skipped_quietly() {
    with_fs(test_cfg(), |h, me, dir, _stop| {
        std::fs::create_dir(dir.join("sub")).unwrap();
        std::fs::write(dir.join("sub/f.txt"), b"x").unwrap();
        std::fs::write(dir.join("z.txt"), b"x").unwrap();
        let anchor = Anchor::open(dir.as_path()).expect("anchor");

        let mut t = query_tree(&h, me, &anchor, TreeOptions::default()).expect("query_tree");
        assert_eq!(t.next().expect("some").expect("ok").key(), b"sub/");

        // Same deferred-descent window as the ENOTDIR case, but the entry is gone rather than replaced.
        std::fs::remove_file(dir.join("sub/f.txt")).unwrap();
        std::fs::remove_dir(dir.join("sub")).unwrap();

        assert_eq!(
            t.next().expect("some").expect("ok").key(),
            b"z.txt",
            "a vanished subtree must not fail the walk"
        );
        assert!(t.next().is_none(), "the walk ends after the last sibling");
    });
}

/// An entry the listing cannot open must not report its ACL as *absent*.
///
/// A unix socket answers `ENXIO` to `O_RDONLY|O_NOFOLLOW|O_NONBLOCK` and carries a POSIX access ACL exactly as a
/// regular file does, so the ACL the caller asked for was not read. With that classed as a definite answer,
/// `DirEntry::acl` is `None` - its rustdoc's spelling of "not present" - and `xattrs_incomplete` is clear, so a
/// permissions layer mirroring ACLs out of a listing records "no ACL" for an object that has one.
///
/// A symbolic link is the opposite control and must STAY unflagged: the kernel refuses an access ACL on one outright
/// (`vfs_get_acl`), so "absent" is true of it, and flagging it would make the flag permanent for an ordinary directory.
#[test]
fn query_directory_does_not_call_an_unread_acl_absent() {
    use std::collections::BTreeMap;
    use std::ffi::CString;
    use std::os::unix::ffi::OsStringExt;
    use truenas_ros::uring_fs::{DirEntry, EnrichSpec, QueryOptions, XattrNamespaces, query_directory};

    // system.posix_acl_access: u32 version, then 8-byte (tag, perm, id). A named user, so the ACL is not equivalent to
    // the mode and the filesystem really stores one.
    let acl: Vec<u8> = {
        let mut v = Vec::new();
        v.extend_from_slice(&2u32.to_le_bytes());
        for (tag, perm, id) in [
            (0x01u16, 0o6u16, 0xFFFF_FFFFu32),
            (0x02, 0o4, 1000),
            (0x04, 0o4, 0xFFFF_FFFF),
            (0x10, 0o6, 0xFFFF_FFFF),
            (0x20, 0o0, 0xFFFF_FFFF),
        ] {
            v.extend_from_slice(&tag.to_le_bytes());
            v.extend_from_slice(&perm.to_le_bytes());
            v.extend_from_slice(&id.to_le_bytes());
        }
        v
    };
    let aclname = CString::new("system.posix_acl_access").expect("name");

    with_fs(test_cfg(), |h, me, dir, _stop| {
        std::fs::write(dir.join("f"), b"x").expect("regular file");
        let _sock = std::os::unix::net::UnixListener::bind(dir.join("s")).expect("unix socket");
        std::os::unix::fs::symlink("f", dir.join("l")).expect("symlink");

        for name in ["f", "s"] {
            let p = CString::new(dir.join(name).into_os_string().into_vec()).expect("path");
            // SAFETY: valid NUL-terminated path/name and a sized buffer.
            let rc = unsafe { libc::setxattr(p.as_ptr(), aclname.as_ptr(), acl.as_ptr().cast(), acl.len(), 0) };
            if rc != 0 {
                // Not a POSIX-ACL filesystem for this node type.
                let e = std::io::Error::last_os_error();
                assert!(
                    std::env::var_os("TRUENAS_ROS_REQUIRE_POSIX_ACL").is_none(),
                    "TRUENAS_ROS_REQUIRE_POSIX_ACL is set but the fixture \
                     filesystem refuses an access ACL on {name}: {e}"
                );
                return;
            }
        }

        let anchor = Anchor::open(dir.as_path()).expect("anchor");
        let opts = QueryOptions {
            spec: EnrichSpec::ACL,
            acl_name: aclname.clone(),
            xattr_ns: XattrNamespaces::empty(),
            ..Default::default()
        };
        let mut q = query_directory(&h, me, &anchor, opts).expect("list");
        let mut all: BTreeMap<String, DirEntry> = BTreeMap::new();
        while let Some(batch) = q.next() {
            for e in batch.expect("batch") {
                all.insert(e.name.to_string_lossy().into_owned(), e);
            }
        }

        assert_eq!(
            all["f"].acl.as_deref(),
            Some(&acl[..]),
            "the control opens, so its ACL is read"
        );
        assert!(!all["f"].xattrs_incomplete, "the control lost nothing");
        assert!(
            all["s"].acl.is_none() && all["s"].xattrs_incomplete,
            "an ACL that could not be read is unread, not absent"
        );
        assert!(
            !all["l"].xattrs_incomplete,
            "a symlink cannot hold an access ACL, so absent is the true \
             answer and the flag must stay clear"
        );
    });
}

/// The access mode, `O_NONBLOCK` and close on exec of the descriptor of `f`.
fn fd_flags(f: &File) -> (i32, bool, bool) {
    // SAFETY: `f` holds the descriptor open, and F_GETFL and F_GETFD only read its flags.
    let (fl, fd) = unsafe {
        (
            libc::fcntl(f.as_raw_fd(), libc::F_GETFL),
            libc::fcntl(f.as_raw_fd(), libc::F_GETFD),
        )
    };
    assert!(fl >= 0 && fd >= 0, "fcntl: {}", std::io::Error::last_os_error());
    (
        fl & libc::O_ACCMODE,
        fl & libc::O_NONBLOCK != 0,
        fd & libc::FD_CLOEXEC != 0,
    )
}

/// The errno of a refusal, or `None` for success.
fn errno_of<T>(res: &Result<T, Error>) -> Option<Errno> {
    match res {
        Ok(_) => None,
        Err(Error::Errno(e)) => Some(*e),
        Err(e) => panic!("not an errno: {e}"),
    }
}

/// `FsHandle::reopen_proc` opens a file held `O_PATH` again through `/proc/thread-self/fd` with the access asked, close
/// on exec and with no `O_NONBLOCK` left by the guard, and the file system checks the personality. So nobody reads a
/// file of mode 0644 but may not write it, and is refused at 0600, which the ring owner is not. The reopen skips the
/// walk to the file, so a folder nobody may not search, which refuses the open by name, does not refuse it. A link held
/// `O_PATH` with `O_NOFOLLOW` is reached itself and refused (`may_open` in `fs/namei.c`), and a FIFO answers at once.
#[test]
fn reopen_proc_opens_a_held_file_again_as_the_personality() {
    if !root_or_skip("reopen_proc_opens_a_held_file_again_as_the_personality") {
        return; // the broker needs privilege
    }
    with_broker(|h, creds, me, dir| {
        let mode = |name: &str, bits: u32| {
            std::fs::set_permissions(dir.join(name), std::fs::Permissions::from_mode(bits)).unwrap();
        };
        std::fs::write(dir.join("f"), b"body").unwrap();
        mode("f", 0o644);
        std::os::unix::fs::symlink("f", dir.join("l")).unwrap();
        mkfifo(dir, "p");
        std::fs::create_dir(dir.join("locked")).unwrap();
        mode("locked", 0o700);
        std::fs::write(dir.join("locked/g"), b"locked").unwrap();
        mode("locked/g", 0o644);
        let anchor = Anchor::open(dir).unwrap();
        let held = |name: &str, flags: OFlag| {
            let how = OpenHow::new().flags(OFlag::O_PATH | flags);
            h.open(me, &anchor, name, how).unwrap()
        };
        let f = held("f", OFlag::empty());

        for (access, want) in [
            (ReopenAccess::Read, libc::O_RDONLY),
            (ReopenAccess::Write, libc::O_WRONLY),
            (ReopenAccess::ReadWrite, libc::O_RDWR),
        ] {
            let again = h.reopen_proc(me, &f, access).unwrap();
            assert_eq!(fd_flags(&again), (want, false, true), "{access:?}");
            h.close(again).unwrap();
        }
        let again = h.reopen_proc(me, &f, ReopenAccess::Read).unwrap();
        let (n, buf) = pread1(h, me, &again, vec![0; 8], 0);
        assert_eq!(&buf[..n.unwrap()], b"body");
        h.close(again).unwrap();

        let nobody = creds.register(&AsUser::new(NOBODY_UID, NOBODY_GID)).unwrap();
        let reopened = |who, f: &File, access| {
            let res = h.reopen_proc(who, f, access);
            let errno = errno_of(&res);
            if let Ok(again) = res {
                h.close(again).unwrap();
            }
            errno
        };
        assert_eq!(reopened(nobody, &f, ReopenAccess::Read), None);
        let write = reopened(nobody, &f, ReopenAccess::Write);
        assert_eq!(write, Some(Errno::EACCES), "nobody may not write");
        mode("f", 0o600);
        let read = reopened(nobody, &f, ReopenAccess::Read);
        assert_eq!(read, Some(Errno::EACCES), "nobody is refused at 0600");
        for access in [ReopenAccess::Read, ReopenAccess::ReadWrite] {
            let again = h.reopen_proc_as_root(&f, access).unwrap();
            h.close(again).unwrap();
        }

        let g = held("locked/g", OFlag::empty());
        let how = OpenHow::new().flags(OFlag::O_RDONLY);
        let by_name = h.open(nobody, &anchor, "locked/g", how);
        assert_eq!(errno_of(&by_name), Some(Errno::EACCES), "by name");
        assert_eq!(reopened(nobody, &g, ReopenAccess::Read), None);

        let l = held("l", OFlag::O_NOFOLLOW);
        let link = reopened(me, &l, ReopenAccess::Read);
        assert_eq!(link, Some(Errno::ELOOP), "the link itself");
        let fifo = held("p", OFlag::empty());
        let again = h.reopen_proc(me, &fifo, ReopenAccess::Read).unwrap();
        assert_eq!(fd_flags(&again), (libc::O_RDONLY, false, true));
        h.close(again).unwrap();

        creds.unregister(nobody).unwrap();
        for file in [f, g, l, fifo] {
            h.close(file).unwrap();
        }
    });
}

/// On a POSIX and an NFSv4 dataset `FsHandle::reopen_proc` allows and refuses what an open by name does, for the owner
/// of a file of mode 0600, a reader an ACL entry grants reading, and a stranger, each for reading, writing and both.
/// The owner may do all three, the reader read alone and the stranger nothing, so the two agree on refusals as well as
/// on grants.
#[test]
fn reopen_proc_allows_and_refuses_what_an_open_by_name_does_on_zfs() {
    if !root_or_skip("reopen_proc_allows_and_refuses_what_an_open_by_name_does_on_zfs") {
        return; // the broker, the owners and the ACLs need privilege
    }
    const OWNER: u32 = 8_675_301;
    const READER: u32 = 8_675_302;
    const STRANGER: u32 = 8_675_303;
    let datasets: Vec<(&str, PathBuf)> = [
        ("posix", "TRUENAS_ROS_POSIX_DATASET"),
        ("nfs4", "TRUENAS_ROS_NFS4_DATASET"),
    ]
    .into_iter()
    .filter_map(|(kind, var)| {
        let dir = PathBuf::from(std::env::var_os(var)?);
        (zfs_dir::is_zfs(&dir) == Some(true)).then_some((kind, dir))
    })
    .collect();
    if datasets.len() < 2 {
        assert!(
            std::env::var_os("TRUENAS_ROS_REQUIRE_ZFS").is_none(),
            "TRUENAS_ROS_REQUIRE_ZFS is set but the POSIX and NFSv4 \
             datasets are not both ZFS"
        );
        return;
    }
    // USER_OBJ rw, USER READER r, GROUP_OBJ nothing, MASK r and OTHER nothing, as `system.posix_acl_access` holds them.
    let posix: Vec<u8> = {
        let mut v = 2u32.to_le_bytes().to_vec();
        for (tag, perm, id) in [
            (0x01u16, 0o6u16, u32::MAX),
            (0x02, 0o4, READER),
            (0x04, 0o0, u32::MAX),
            (0x10, 0o4, u32::MAX),
            (0x20, 0o0, u32::MAX),
        ] {
            v.extend(tag.to_le_bytes());
            v.extend(perm.to_le_bytes());
            v.extend(id.to_le_bytes());
        }
        v
    };
    // OWNER@ is allowed everything, READER READ_DATA, READ_ATTRIBUTES, READ_ACL and SYNCHRONIZE, and EVERYONE@ the last
    // three.
    let nfs4 = nfs4_xdr(&[
        [0, 0, 1, 0x1f_01ff, 1],
        [0, 0, 0, 0x12_0081, READER],
        [0, 0, 1, 0x12_0080, 3],
    ]);
    with_broker(|h, creds, me, _dir| {
        let people = [OWNER, READER, STRANGER].map(|uid| (uid, creds.register(&AsUser::new(uid, uid)).unwrap()));
        for (kind, ds) in &datasets {
            let folder = ds.join(format!("rostest_reopen_{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&folder);
            std::fs::create_dir(&folder).unwrap();
            std::fs::set_permissions(&folder, std::fs::Permissions::from_mode(0o777)).unwrap();
            std::fs::write(folder.join("f"), b"reopen").unwrap();
            std::os::unix::fs::chown(folder.join("f"), Some(OWNER), Some(OWNER)).unwrap();
            std::fs::set_permissions(folder.join("f"), std::fs::Permissions::from_mode(0o600)).unwrap();
            let anchor = Anchor::open(&folder).unwrap();
            let (name, acl) = match *kind {
                "posix" => ("system.posix_acl_access", posix.clone()),
                _ => ("system.nfs4_acl_xdr", nfs4.clone()),
            };
            let how = OpenHow::new().flags(OFlag::O_RDONLY);
            let open = h.open(me, &anchor, "f", how).unwrap();
            let (set, _) = h.fsetxattr(me, &open, xattr_name(name), acl, 0);
            set.unwrap_or_else(|e| panic!("{kind}: root sets the ACL: {e}"));
            h.close(open).unwrap();
            let held = h.open(me, &anchor, "f", OpenHow::new().flags(OFlag::O_PATH)).unwrap();
            for (uid, who) in people {
                for (access, flags) in [
                    (ReopenAccess::Read, OFlag::O_RDONLY),
                    (ReopenAccess::Write, OFlag::O_WRONLY),
                    (ReopenAccess::ReadWrite, OFlag::O_RDWR),
                ] {
                    let how = OpenHow::new().flags(flags);
                    let by_name = h.open(who, &anchor, "f", how);
                    let again = h.reopen_proc(who, &held, access);
                    let case = format!("{kind} uid {uid} {access:?}");
                    assert_eq!(errno_of(&again), errno_of(&by_name), "{case}");
                    let granted = uid == OWNER || (uid == READER && access == ReopenAccess::Read);
                    assert_eq!(again.is_ok(), granted, "{case}");
                    for file in [by_name, again].into_iter().flatten() {
                        h.close(file).unwrap();
                    }
                }
            }
            h.close(held).unwrap();
            std::fs::remove_dir_all(&folder).unwrap();
        }
        for (_, who) in people {
            creds.unregister(who).unwrap();
        }
    });
}

/// A path too long for the name an op slot holds, 255 bytes with its NUL, still opens, through a copy the op owns.
#[test]
fn an_open_of_a_path_longer_than_the_slot_holds_still_opens() {
    with_fs(test_cfg(), |h, me, dir, _stop| {
        let folder = "d".repeat(200);
        std::fs::create_dir(dir.join(&folder)).unwrap();
        let path = format!("{folder}/{}", "f".repeat(100));
        std::fs::write(dir.join(&path), b"far").unwrap();
        assert!(path.len() > 256, "longer than the slot holds");
        let anchor = Anchor::open(&dir).unwrap();
        let how = OpenHow::new().flags(OFlag::O_RDONLY);
        let f = h.open(me, &anchor, path.as_str(), how).expect("it opens");
        let (read, back) = pread1(&h, me, &f, vec![0; 3], 0);
        assert_eq!(read.unwrap(), 3);
        assert_eq!(back, b"far");
    });
}

/// `File::from_shared` makes a handle of the caller's own descriptor, with no `dup`: a read through it gives what was
/// written, the number is the caller's, and the caller's clone is not the last while the handle lives and is once it
/// drops, when `Arc::into_inner` gives the same descriptor.
// Under `--cfg loom` the crate's `Arc` is loom's, which a std `Arc` is not, and the loom lane runs no ring.
#[cfg(not(loom))]
#[test]
fn from_shared_reads_through_the_callers_descriptor() {
    use std::os::fd::AsRawFd;
    use std::sync::Arc;
    with_fs(test_cfg(), |h, me, dir, _stop| {
        let anchor = Anchor::open(&dir).unwrap();
        let f = h.open(me, &anchor, "f", creat_rw()).unwrap();
        let (wrote, _) = pwrite1(&h, me, &f, b"shared".to_vec(), 0);
        assert_eq!(wrote.unwrap(), 6);
        let fd = f.into_fd().expect("nothing else holds it");
        let raw = fd.as_raw_fd();
        let kept = Arc::new(fd);
        let shared = File::from_shared(Arc::clone(&kept));
        assert_eq!(shared.as_raw_fd(), raw, "the caller's descriptor");
        let (read, back) = pread1(&h, me, &shared, vec![0; 6], 0);
        assert_eq!(read.unwrap(), 6);
        assert_eq!(back, b"shared");
        assert!(Arc::strong_count(&kept) > 1, "the handle holds a clone");
        drop(shared);
        let fd = Arc::into_inner(kept).expect("the caller's clone is the last");
        assert_eq!(fd.as_raw_fd(), raw);
    });
}

/// `File::into_shared` gives back the very `Arc` its handle holds, so a caller keeps the reactor's `Arc` rather than a
/// second one.
// Under `--cfg loom` the crate's `Arc` is loom's, which a std `Arc` is not, and the loom lane runs no ring.
#[cfg(not(loom))]
#[test]
fn into_shared_gives_the_arc_the_file_holds() {
    use std::sync::Arc;
    with_fs(test_cfg(), |h, me, dir, _stop| {
        let anchor = Anchor::open(&dir).unwrap();
        let f = h.open(me, &anchor, "f", creat_rw()).unwrap();
        let kept = Arc::new(f.into_fd().expect("nothing else holds it"));
        let back = File::from_shared(Arc::clone(&kept)).into_shared();
        assert!(Arc::ptr_eq(&back, &kept), "the same Arc comes back");
    });
}

/// `File::into_fd` gives the same `File` back while a clone holds it, and once the clone drops takes out the same
/// descriptor, which then writes and reads as a `std::fs::File` the caller owns.
#[test]
fn into_fd_takes_the_descriptor_only_when_nothing_else_holds_it() {
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::fd::AsRawFd;
    with_fs(test_cfg(), |h, me, dir, _stop| {
        let anchor = Anchor::open(&dir).unwrap();
        let f = h.open(me, &anchor, "f", creat_rw()).unwrap();
        let raw = f.as_raw_fd();
        let clone = f.clone();
        let f = f.into_fd().expect_err("a clone holds it");
        assert_eq!(f.as_raw_fd(), raw, "the same file comes back");
        drop(clone);
        let fd = f.into_fd().expect("nothing else holds it");
        assert_eq!(fd.as_raw_fd(), raw);
        let mut file = std::fs::File::from(fd);
        file.write_all(b"owned").unwrap();
        file.seek(SeekFrom::Start(0)).unwrap();
        let mut back = String::new();
        file.read_to_string(&mut back).unwrap();
        assert_eq!(back, "owned");
    });
}
