use super::*;

// --- metadata --------------------------------------------------------------

#[test]
fn open_metadata_close_workflow() {
    // The shape the API is built to encourage: open once, do every metadata op against the resulting fd, close. No path
    // is named after the open.
    with_fs(test_cfg(), |h, me, dir, _stop| {
        let anchor = Anchor::open(dir.as_path()).unwrap();
        let f = h.open(me, &anchor, "doc.bin", creat_rw()).unwrap();

        let (n, _b) = pwrite1(&h, me, &f, vec![b'x'; 4096], 0);
        assert_eq!(n.unwrap(), 4096);

        let name = xattr_name("user.dosattrib");
        let (res, _v) = h.fsetxattr(me, &f, name.clone(), b"\x01\x02\x03".to_vec(), 0);
        res.expect("fsetxattr");
        let (n, val) = h.fgetxattr(me, &f, name.clone(), vec![0u8; 64]);
        assert_eq!(n.expect("fgetxattr"), 3);
        assert_eq!(&val[..3], b"\x01\x02\x03");

        // Size query with an empty buffer (the kernel's size-only form).
        let (n, _v) = h.fgetxattr(me, &f, name.clone(), Vec::new());
        assert_eq!(n.expect("size query"), 3);

        let (res, _v) = h.fgetxattr(me, &f, name.clone(), vec![0u8; 2]);
        assert!(matches!(res, Err(Error::Errno(Errno::ERANGE))));

        let (res, _v) = h.fsetxattr(me, &f, name.clone(), b"zz".to_vec(), libc::XATTR_CREATE);
        assert!(matches!(res, Err(Error::Errno(Errno::EEXIST))));

        // Oversized is E2BIG on this path too, the sync twin's contract (`sync_fs::xattr::fsetxattr`, `test/coverage.rs
        // oversize_short_circuits_to_e2big`). This is a contract test, not a control, since the kernel answers E2BIG
        // here anyway. What the crate's bound catches is the `as u32` truncation, which needs a value of 1 << 32 to
        // reach.
        use truenas_ros::sync_fs::xattr::XATTR_SIZE_MAX;
        let big = vec![0u8; XATTR_SIZE_MAX + 1];
        let (res, back) = h.fsetxattr(me, &f, name.clone(), big, 0);
        assert!(
            matches!(res, Err(Error::Errno(Errno::E2BIG))),
            "an oversized value must be refused, got {res:?}"
        );
        assert_eq!(back.len(), XATTR_SIZE_MAX + 1, "the buffer comes back");
        let (n, val) = h.fgetxattr(me, &f, name.clone(), vec![0u8; 64]);
        assert_eq!(n.expect("fgetxattr"), 3);
        assert_eq!(&val[..3], b"\x01\x02\x03");

        // ...and a *generous* read buffer is not an oversized value. The bound above belongs to the write path:
        // `FsConn::fgetxattr`'s contract is that a buffer SHORTER than the value fails ERANGE, and the sync twin
        // (`sync_fs::xattr::fgetxattr`) takes no buffer at all and never refuses on its size.
        let (n, val) = h.fgetxattr(me, &f, name.clone(), vec![0u8; 2 * XATTR_SIZE_MAX]);
        assert_eq!(n.expect("a generous read buffer still reads the value"), 3);
        assert_eq!(&val[..3], b"\x01\x02\x03");

        h.fallocate(me, &f, 0, 4096, 4096).expect("fallocate");
        assert_eq!(std::fs::metadata(dir.join("doc.bin")).unwrap().len(), 8192);

        h.fsync(me, &f).unwrap();
        h.close(f).unwrap();

        // Oracle: the xattr is really on disk, seen by a plain syscall.
        let mut out = [0u8; 8];
        let p = CString::new(dir.join("doc.bin").as_os_str().as_bytes()).unwrap();
        // SAFETY: valid path/name/buffer.
        let n = unsafe { libc::getxattr(p.as_ptr(), name.as_ptr(), out.as_mut_ptr().cast(), out.len()) };
        assert_eq!(n, 3, "attribute visible to getxattr(2)");
        assert_eq!(&out[..3], b"\x01\x02\x03");
    });
}

#[test]
fn ftruncate_by_fd_or_unsupported() {
    with_fs(test_cfg(), |h, me, dir, _stop| {
        let anchor = Anchor::open(dir.as_path()).unwrap();
        let f = h.open(me, &anchor, "t.bin", creat_rw()).unwrap();
        let (n, _b) = pwrite1(&h, me, &f, vec![b'y'; 100], 0);
        assert_eq!(n.unwrap(), 100);

        h.ftruncate(me, &f, 10).expect("ftruncate");
        assert_eq!(std::fs::metadata(dir.join("t.bin")).unwrap().len(), 10);
        h.close(f).unwrap();
    });
}

#[test]
fn fd_metadata_respects_close_last() {
    // Metadata ops hold a file reference like data ops do, so a close racing one in flight must still be the file's
    // last op: the reactor parks an `Arc<OwnedFd>` clone for the duration, and the descriptor closes when that clone
    // drops, not when the caller lets go.
    with_fs(test_cfg(), |h, me, dir, _stop| {
        let anchor = Anchor::open(dir.as_path()).unwrap();
        let f = h.open(me, &anchor, "a.bin", creat_rw()).unwrap();
        let name = xattr_name("user.k");
        let (res, _v) = h.fsetxattr(me, &f, name.clone(), b"v".to_vec(), 0);
        res.unwrap();
        h.close(f).unwrap();
        // Slot reusable immediately: the close waited for the real close.
        let f = h.open(me, &anchor, "a.bin", rdonly()).expect("reopen");
        let (n, v) = h.fgetxattr(me, &f, name.clone(), vec![0u8; 16]);
        assert_eq!(n.unwrap(), 1);
        assert_eq!(&v[..1], b"v");
        h.close(f).unwrap();
    });
}

#[test]
fn statx_by_leaf_and_anchor() {
    with_fs(test_cfg(), |h, me, dir, _stop| {
        std::fs::write(dir.join("sized"), vec![0u8; 1234]).unwrap();
        std::fs::create_dir(dir.join("sub")).unwrap();
        let anchor = Anchor::open(dir.as_path()).unwrap();

        let st = h
            .statx(me, &anchor, leaf("sized"), AtFlags::empty(), StatxMask::BASIC_STATS)
            .expect("statx leaf");
        assert_eq!(st.size(), 1234);
        // SAFETY: geteuid is always safe.
        assert_eq!(st.uid(), unsafe { libc::geteuid() });

        // The anchor itself, via AT_EMPTY_PATH - the closest to fd-based statx this interface can offer.
        let st = h
            .statx_anchor(me, &anchor, AtFlags::empty(), StatxMask::BASIC_STATS)
            .expect("statx anchor");
        assert!(st.is_dir(), "anchor is a directory");

        assert!(matches!(
            h.statx(me, &anchor, leaf("nope"), AtFlags::empty(), StatxMask::BASIC_STATS),
            Err(Error::Errno(Errno::ENOENT))
        ));

        // The async surface does not follow a terminal symlink BY DEFAULT (a peer-planted symlink can't redirect the
        // stat out of the anchor), but AT_SYMLINK_FOLLOW opts into stat'ing the target; an explicit AT_SYMLINK_NOFOLLOW
        // is the default.
        std::os::unix::fs::symlink("sized", dir.join("ln")).unwrap();
        let by_default = h
            .statx(me, &anchor, leaf("ln"), AtFlags::empty(), StatxMask::BASIC_STATS)
            .unwrap();
        assert!(by_default.is_symlink(), "does not follow by default");
        let explicit = h
            .statx(
                me,
                &anchor,
                leaf("ln"),
                AtFlags::AT_SYMLINK_NOFOLLOW,
                StatxMask::BASIC_STATS,
            )
            .unwrap();
        assert!(explicit.is_symlink(), "NOFOLLOW stats the link itself");
        let followed = h
            .statx(
                me,
                &anchor,
                leaf("ln"),
                AtFlags::AT_SYMLINK_FOLLOW,
                StatxMask::BASIC_STATS,
            )
            .unwrap();
        assert_eq!(followed.size(), 1234, "AT_SYMLINK_FOLLOW stats the target");
    });
}

#[test]
fn leaf_validation_is_the_confinement() {
    // The *at opcodes honour no RESOLVE_* flags, so the single-component rule is what keeps a directory op inside its
    // anchor. Reject anything that could walk.
    for bad in ["", ".", "..", "a/b", "/abs", "../escape", "sub/"] {
        assert!(
            matches!(Leaf::new(bad), Err(Error::Validation(_))),
            "{bad:?} must be rejected"
        );
    }
    assert!(Leaf::new("file.txt").is_ok());
    assert!(Leaf::new("..hidden").is_ok(), "only exactly `..` is special");
    assert!(Leaf::new(&b"nul\0byte"[..]).is_err());
}

#[test]
fn directory_entry_ops() {
    with_fs(test_cfg(), |h, me, dir, _stop| {
        let anchor = Anchor::open(dir.as_path()).unwrap();

        h.mkdirat(me, &anchor, leaf("d"), Mode::from_bits_truncate(0o750))
            .expect("mkdirat");
        let md = std::fs::metadata(dir.join("d")).unwrap();
        assert!(md.is_dir());
        assert_eq!(md.permissions().mode() & 0o777, 0o750);
        h.rmdirat(me, &anchor, leaf("d")).expect("rmdirat");
        assert!(!dir.join("d").exists());

        std::fs::write(dir.join("f"), b"x").unwrap();
        std::fs::create_dir(dir.join("realdir")).unwrap();
        assert!(matches!(
            h.unlinkat(me, &anchor, leaf("realdir")),
            Err(Error::Errno(Errno::EISDIR))
        ));
        assert!(matches!(
            h.rmdirat(me, &anchor, leaf("f")),
            Err(Error::Errno(Errno::ENOTDIR))
        ));
        h.unlinkat(me, &anchor, leaf("f")).expect("unlinkat");
        assert!(!dir.join("f").exists());

        // symlink: the target is content, never resolved at creation, so a dangling (and multi-component) target is
        // legal.
        h.symlinkat(me, "../elsewhere/target", &anchor, leaf("link"))
            .expect("symlinkat");
        assert_eq!(
            std::fs::read_link(dir.join("link")).unwrap(),
            Path::new("../elsewhere/target")
        );

        std::fs::write(dir.join("orig"), b"data").unwrap();
        h.linkat(me, &anchor, leaf("orig"), &anchor, leaf("hard"), AtFlags::empty())
            .expect("linkat");
        assert_eq!(std::fs::read(dir.join("hard")).unwrap(), b"data");
        assert_eq!(std::fs::metadata(dir.join("orig")).unwrap().nlink(), 2, "same inode");

        h.renameat(me, &anchor, leaf("hard"), &anchor, leaf("moved"), RenameFlags::empty())
            .expect("renameat");
        assert!(dir.join("moved").exists() && !dir.join("hard").exists());

        assert!(matches!(
            h.renameat(
                me,
                &anchor,
                leaf("moved"),
                &anchor,
                leaf("orig"),
                RenameFlags::RENAME_NOREPLACE,
            ),
            Err(Error::Errno(Errno::EEXIST))
        ));

        std::fs::write(dir.join("A"), b"a").unwrap();
        std::fs::write(dir.join("B"), b"b").unwrap();
        h.renameat(me, &anchor, leaf("A"), &anchor, leaf("B"), RenameFlags::RENAME_EXCHANGE)
            .expect("exchange");
        assert_eq!(std::fs::read(dir.join("A")).unwrap(), b"b");
        assert_eq!(std::fs::read(dir.join("B")).unwrap(), b"a");
    });
}

#[test]
fn rename_across_two_anchors() {
    with_fs(test_cfg(), |h, me, dir, _stop| {
        std::fs::create_dir(dir.join("src")).unwrap();
        std::fs::create_dir(dir.join("dst")).unwrap();
        std::fs::write(dir.join("src/f"), b"payload").unwrap();
        let a_src = Anchor::open(dir.join("src").as_path()).unwrap();
        let a_dst = Anchor::open(dir.join("dst").as_path()).unwrap();

        // Two distinct dirfds: the second rides in sqe.len per the kernel's packing, which this proves end-to-end.
        h.renameat(me, &a_src, leaf("f"), &a_dst, leaf("g"), RenameFlags::empty())
            .expect("cross-anchor rename");
        assert!(!dir.join("src/f").exists());
        assert_eq!(std::fs::read(dir.join("dst/g")).unwrap(), b"payload");
    });
}

/// An `O_TMPFILE` create is invisible until `linkat` names it, and complete the instant it becomes visible - the
/// durable-publish property an object store needs. Also pins that the file really has no name beforehand: the directory
/// stays empty while the data is being written.
#[test]
fn o_tmpfile_is_invisible_until_linkat_publishes_it() {
    with_fs(test_cfg(), |h, me, dir, _stop| {
        let anchor = Anchor::open(dir.as_path()).expect("anchor");

        // O_TMPFILE names the *directory*; the file it creates has no entry. Deliberately no O_EXCL - that is the
        // "never linkable" opt-out.
        let how = OpenHow::new()
            .flags(OFlag::O_TMPFILE | OFlag::O_RDWR)
            .mode(Mode::from_bits_truncate(0o600));
        let f = h.open(me, &anchor, ".", how).expect("open O_TMPFILE");

        let (n, _) = pwrite1(&h, me, &f, b"published atomically".to_vec(), 0);
        assert_eq!(n.expect("write"), 20);
        h.fdatasync(me, &f).expect("fdatasync");

        assert_eq!(
            std::fs::read_dir(&dir).unwrap().count(),
            0,
            "an unlinked O_TMPFILE must not appear in its directory"
        );

        h.linkat_file(me, &f, &anchor, leaf("object"))
            .expect("linkat AT_EMPTY_PATH");

        // Visible, and already whole: no window where a reader sees a partial file, which is the entire point of
        // publishing this way.
        assert_eq!(std::fs::read(dir.join("object")).unwrap(), b"published atomically");
    });
}

/// `linkat` cannot replace an existing name, so overwriting is link-to-temp then rename. Pins the `EEXIST` that forces
/// the two-step, and that the rename really does replace the old content atomically.
#[test]
fn linkat_file_cannot_replace_but_rename_can() {
    with_fs(test_cfg(), |h, me, dir, _stop| {
        let anchor = Anchor::open(dir.as_path()).expect("anchor");
        std::fs::write(dir.join("object"), b"old").unwrap();

        let how = OpenHow::new()
            .flags(OFlag::O_TMPFILE | OFlag::O_RDWR)
            .mode(Mode::from_bits_truncate(0o600));
        let f = h.open(me, &anchor, ".", how).expect("open O_TMPFILE");
        let (n, _) = pwrite1(&h, me, &f, b"new".to_vec(), 0);
        assert_eq!(n.expect("write"), 3);

        assert!(
            matches!(
                h.linkat_file(me, &f, &anchor, leaf("object")),
                Err(Error::Errno(Errno::EEXIST))
            ),
            "linkat must not clobber an existing entry"
        );
        assert_eq!(std::fs::read(dir.join("object")).unwrap(), b"old");

        h.linkat_file(me, &f, &anchor, leaf(".tmp.object"))
            .expect("link to a staging name");
        h.renameat(
            me,
            &anchor,
            leaf(".tmp.object"),
            &anchor,
            leaf("object"),
            RenameFlags::empty(),
        )
        .expect("rename over the target");

        assert_eq!(std::fs::read(dir.join("object")).unwrap(), b"new");
        assert!(!dir.join(".tmp.object").exists(), "staging name consumed");
    });
}

/// `O_EXCL` with `O_TMPFILE` is the "this inode may never be linked" opt-out: the kernel withholds `I_LINKABLE`, and
/// `vfs_link` then refuses an inode whose link count is zero. The failure is `ENOENT`, which says nothing about the
/// real cause - hence the test, and hence the warning in the docs.
#[test]
fn o_tmpfile_with_o_excl_is_unlinkable() {
    with_fs(test_cfg(), |h, me, dir, _stop| {
        let anchor = Anchor::open(dir.as_path()).expect("anchor");
        let how = OpenHow::new()
            .flags(OFlag::O_TMPFILE | OFlag::O_RDWR | OFlag::O_EXCL)
            .mode(Mode::from_bits_truncate(0o600));
        let f = h.open(me, &anchor, ".", how).expect("O_TMPFILE|O_EXCL still opens");

        assert!(
            matches!(
                h.linkat_file(me, &f, &anchor, leaf("object")),
                Err(Error::Errno(Errno::ENOENT))
            ),
            "an O_EXCL temp file is permanently anonymous"
        );
        assert!(!dir.join("object").exists());
    });
}

/// Which personality may publish an `O_TMPFILE`?
///
/// `AT_EMPTY_PATH` demands `f_cred == current_cred()` - a **pointer** comparison (`fs/namei.c:2631`). io_uring's
/// `register_personality` stores `get_current_cred()`, so two registrations taken from unchanged credentials reference
/// the same `struct cred`. This pins the consequence: two `register_self` ids are interchangeable for the link, because
/// they *are* the same credentials. The requirement therefore bites across genuinely different identities (the
/// broker's), not across id values.
#[test]
fn linkat_file_accepts_any_id_for_the_same_credentials() {
    pin_umask();
    let dir = truenas_ros::tempdir().expect("tempdir");
    let mut afs = match UringFs::new(test_cfg()) {
        Ok(a) => a,
        Err(e) => {
            if should_skip(&e) {
                return;
            }
            panic!("UringFs::new: {e}");
        }
    };
    let opener = afs.register_self().expect("first register_self");
    let linker = afs.register_self().expect("second register_self");
    assert_ne!(opener.id(), linker.id(), "two distinct personality ids");

    let h = afs.handle();
    let stop = afs.shutdown_handle();
    let dir_path = dir.path().to_path_buf();
    thread::scope(|s| {
        s.spawn(move || {
            let _guard = StopGuard(stop);
            let anchor = Anchor::open(dir_path.as_path()).expect("anchor");
            let how = OpenHow::new()
                .flags(OFlag::O_TMPFILE | OFlag::O_RDWR)
                .mode(Mode::from_bits_truncate(0o600));
            let f = h.open(opener, &anchor, ".", how).expect("open");
            let (n, _) = pwrite1(&h, opener, &f, b"x".to_vec(), 0);
            assert_eq!(n.expect("write"), 1);

            h.linkat_file(linker, &f, &anchor, leaf("object"))
                .expect("a different id over the same creds may link");
            assert_eq!(std::fs::read(dir_path.join("object")).unwrap(), b"x");
        });
        afs.run().expect("run");
    });
}

/// The allowlist's *refusals* are the security property, so they get the test. `security.` would grant file
/// capabilities, `system.` would rewrite ACLs, and `user.` needs no privilege at all - none may be elevated. A bare
/// `trusted.` is refused too: it would cover the entire namespace.
#[test]
fn privileged_xattr_prefixes_refuse_dangerous_namespaces() {
    for bad in [
        c"security.",
        c"security.capability",
        c"system.",
        c"system.posix_acl_access",
        c"user.",
        c"user.anything",
        c"trusted.", // the whole namespace: too broad
        c"",
        c"nonsense",
    ] {
        assert!(
            matches!(PrivilegedXattrs::new().allow_prefix(bad), Err(Error::Validation(_))),
            "prefix {bad:?} must be refused"
        );
    }
    // Anything naming more than the bare `trusted.` namespace is fine.
    PrivilegedXattrs::new()
        .allow_prefix(c"trusted.myserver_")
        .expect("a scoped trusted. prefix is allowed");
}

/// An allowlisted `trusted.*` write is elevated to the reactor's ambient credentials; an unlisted name in the same
/// namespace, through the same call, is not - and unprivileged callers cannot even see the elevated name.
///
/// Requires privilege to be meaningful (the `trusted.` namespace is `CAP_SYS_ADMIN`-gated), so it skips when not root -
/// and skips on kernels below 6.13, where fd-based xattrs are unavailable.
#[test]
fn privileged_xattr_allowlist_elevates_only_listed_names() {
    if !root_or_skip("privileged_xattr_allowlist_elevates_only_listed_names") {
        return;
    }
    pin_umask();
    let dir = truenas_ros::tempdir().expect("tempdir");
    // `tempdir` creates the directory 0700; the unprivileged identity must traverse it, and reaching the file is not
    // what this test probes.
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).expect("open up the scratch dir");
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
            .allow_prefix(c"trusted.truenas_test_")
            .expect("valid prefix"),
    );

    // A *brokered*, unprivileged identity: the whole point is that this personality could never write `trusted.*`
    // itself.
    let broker = match CredBroker::spawn(&[&afs]) {
        Ok(b) => b,
        Err(_) => return, // no privilege to impersonate here
    };
    let creds = broker.handle(0).expect("broker handle");
    let nobody = creds
        .register(&AsUser::new(65534, 65534))
        .expect("register an unprivileged identity");

    let h = afs.handle();
    let stop = afs.shutdown_handle();
    let dir_path = dir.path().to_path_buf();
    thread::scope(|s| {
        s.spawn(move || {
            let _guard = StopGuard(stop);
            let anchor = Anchor::open(dir_path.as_path()).expect("anchor");
            std::fs::write(dir_path.join("obj"), b"data").unwrap();
            // World-writable so the identity's failures are about the xattr namespace, not about reaching the file.
            std::fs::set_permissions(dir_path.join("obj"), std::fs::Permissions::from_mode(0o666)).unwrap();
            let f = h
                .open(nobody, &anchor, "obj", OpenHow::new().flags(OFlag::O_RDWR))
                .expect("open as the unprivileged identity");

            // Allowlisted: elevated, so it succeeds despite `nobody` holding no CAP_SYS_ADMIN.
            let (res, _) = h.fsetxattr(
                nobody,
                &f,
                xattr_name("trusted.truenas_test_meta"),
                b"server-owned".to_vec(),
                0,
            );
            res.expect("an allowlisted name is written with ambient creds");

            // Same namespace, same call, not listed: stays with the request identity and is refused by the kernel.
            let (res, _) = h.fsetxattr(nobody, &f, xattr_name("trusted.other"), b"nope".to_vec(), 0);
            assert!(
                matches!(res, Err(Error::Errno(Errno::EPERM))),
                "an unlisted trusted.* name must not be elevated, got {res:?}"
            );

            let (res, buf) = h.fgetxattr_as_root(&f, xattr_name("trusted.truenas_test_meta"), vec![0u8; 64]);
            let n = res.expect("privileged read");
            assert_eq!(&buf[..n], b"server-owned");

            let (res, _) = h.fgetxattr(nobody, &f, xattr_name("trusted.truenas_test_meta"), vec![0u8; 64]);
            assert!(
                matches!(res, Err(Error::Errno(Errno::ENODATA))),
                "trusted.* must be invisible unprivileged, got {res:?}"
            );
        });
        afs.run().expect("run");
    });
}

/// `preadv2`/`pwritev2` round-trip with a durability flag, and - the part that matters - an *unsupported* flag fails
/// the operation instead of being silently dropped. A durability flag that no-ops would be the worst possible failure
/// mode, so the degrade path is the assertion.
#[test]
fn preadv2_pwritev2_flags_apply_or_fail_loudly() {
    with_fs(test_cfg(), |h, me, dir, _stop| {
        let anchor = Anchor::open(dir.as_path()).expect("anchor");
        let f = h.open(me, &anchor, "rw2", creat_rw()).expect("open");

        let (n, _) = h.pwritev2(me, &f, vec![b"alpha".to_vec()], 0, RwFlags::empty());
        assert_eq!(n.expect("pwritev2"), 5);

        let (n, _) = h.pwritev2(me, &f, vec![b"-beta".to_vec()], 5, RwFlags::RWF_DSYNC);
        assert_eq!(n.expect("pwritev2 RWF_DSYNC"), 5);

        let (n, bufs) = h.preadv2(me, &f, vec![vec![0u8; 10]], 0, RwFlags::empty());
        assert_eq!(n.expect("preadv2"), 10);
        assert_eq!(&bufs[0][..10], b"alpha-beta");
        assert_eq!(std::fs::read(dir.join("rw2")).unwrap(), b"alpha-beta");

        // A flag the filesystem does not implement must be refused outright. `RWF_ATOMIC` needs FMODE_CAN_ATOMIC_WRITE,
        // which neither tmpfs nor ZFS sets; accept EOPNOTSUPP or EINVAL, but never a silent success.
        let (res, _) = h.pwritev2(me, &f, vec![b"x".to_vec()], 0, RwFlags::RWF_ATOMIC);
        assert!(
            matches!(res, Err(Error::Errno(Errno::EOPNOTSUPP | Errno::EINVAL))),
            "an unsupported rw flag must fail the op, got {res:?}"
        );
        assert_eq!(std::fs::read(dir.join("rw2")).unwrap(), b"alpha-beta");

        h.close(f).unwrap();
    });
}

/// `open_confined` cannot be talked out of its confinement. `open` yields to a caller that *states* a policy, which is
/// documented and fine for a general opener, but the confined form unions the guarantees in, so a `how` that buys
/// in-tree symlinks through `open` buys nothing through `open_confined`.
#[test]
fn open_confined_cannot_be_weakened_by_the_caller() {
    with_fs(test_cfg(), |h, me, dir, _stop| {
        std::fs::create_dir(dir.join("inner")).unwrap();
        std::fs::write(dir.join("outside"), b"secret").unwrap();
        std::fs::write(dir.join("inner/target"), b"in-tree").unwrap();
        let inner = Anchor::open(dir.join("inner").as_path()).unwrap();

        // A stated policy `open` honours: BENEATH without NO_SYMLINKS follows a link that stays inside the anchor.
        let stated = OpenHow::new()
            .flags(OFlag::O_RDONLY)
            .resolve(ResolveFlag::RESOLVE_BENEATH);
        std::os::unix::fs::symlink("target", dir.join("inner/in_tree")).unwrap();
        let f = h
            .open(me, &inner, "in_tree", stated)
            .expect("plain open honours a stated policy");
        h.close(f).unwrap();

        // The same `how`, confined: NO_SYMLINKS is unioned back in.
        let res = h.open_confined(me, &inner, "in_tree", stated);
        assert!(
            matches!(res, Err(Error::Errno(Errno::ELOOP))),
            "confined open must not follow even an in-tree symlink, got {res:?}"
        );

        let permissive = OpenHow::new()
            .flags(OFlag::O_RDONLY)
            .resolve(ResolveFlag::RESOLVE_NO_MAGICLINKS);
        let res = h.open(me, &inner, "../outside", permissive);
        assert!(
            matches!(res, Err(Error::Errno(Errno::EXDEV))),
            "plain open must refuse a `..` escape, got {res:?}"
        );
        let res = h.open_confined(me, &inner, "../outside", permissive);
        assert!(
            matches!(res, Err(Error::Errno(Errno::EXDEV | Errno::ELOOP))),
            "confined open must refuse a `..` escape, got {res:?}"
        );

        // A symlink pointing out of the tree is refused too, even though the path itself contains no `..`.
        std::os::unix::fs::symlink(dir.join("outside"), dir.join("inner/link")).unwrap();
        let res = h.open_confined(me, &inner, "link", permissive);
        assert!(
            matches!(res, Err(Error::Errno(Errno::ELOOP | Errno::EXDEV))),
            "confined open must not follow a symlink out, got {res:?}"
        );

        let res = h.open_confined(me, &inner, "/etc/hostname", permissive);
        assert!(res.is_err(), "confined open must refuse an absolute path");

        // `RESOLVE_IN_ROOT` is the one flag that cannot be unioned in, since the kernel refuses `BENEATH|IN_ROOT`
        // outright (`fs/open.c:1264`). It is refused at the boundary, where the message can name the fix.
        let in_root = OpenHow::new()
            .flags(OFlag::O_RDONLY)
            .resolve(ResolveFlag::RESOLVE_IN_ROOT);
        for path in ["target", "./target", "."] {
            let res = h.open_confined(me, &inner, path, in_root);
            assert!(
                matches!(res, Err(Error::Validation(_))),
                "open_confined({path:?}) with RESOLVE_IN_ROOT must be \
                 refused as a bad argument, not answered EINVAL by the \
                 kernel: got {res:?}"
            );
            // The plain opener still serves it, which is what makes the refusal a routing decision rather than a lost
            // capability.
            let f = h
                .open(me, &inner, path, in_root)
                .unwrap_or_else(|e| panic!("open({path:?}) IN_ROOT: {e}"));
            h.close(f).unwrap();
        }
    });
}

/// `mkdir_path` is `mkdir -p`, confined: it creates what is missing, tolerates what exists, and refuses to build a path
/// that would leave the anchor.
#[test]
fn mkdir_path_creates_confined_and_is_idempotent() {
    with_fs(test_cfg(), |h, me, dir, _stop| {
        let anchor = Anchor::open(dir.as_path()).expect("anchor");
        let mode = Mode::from_bits_truncate(0o755);

        let leaf_anchor = h.mkdir_path(me, &anchor, "a/b/c", mode).expect("create a nested tree");
        assert!(dir.join("a/b/c").is_dir());

        h.mkdirat(me, &leaf_anchor, leaf("d"), mode)
            .expect("mkdir through the returned anchor");
        assert!(dir.join("a/b/c/d").is_dir());

        // Idempotent: re-running changes nothing and still succeeds (this is also the lost-race outcome when two
        // callers create the same tree).
        h.mkdir_path(me, &anchor, "a/b/c", mode)
            .expect("existing tree is not an error");
        h.mkdir_path(me, &anchor, "a/b/other/deep", mode)
            .expect("extend an existing prefix");
        assert!(dir.join("a/b/other/deep").is_dir());

        // Every component must be a plain name. `a/../b` is refused though `openat2` under CONFINED_RESOLVE resolves it
        // safely, since a walk creating `b` cannot know what `a/..` will be, and the same path would name different
        // things depending on what existed. Redundant separators go too, as a sign of a caller assembling a path
        // wrongly.
        for bad in [
            "../escape",
            "a/../../escape",
            "/abs/path",
            "a/../b",
            ".",
            "..",
            "./a",
            "a/.",
            "a//b",
            "a/b/",
            "",
        ] {
            assert!(
                h.mkdir_path(me, &anchor, bad, mode).is_err(),
                "mkdir_path must refuse {bad:?}"
            );
        }
        assert!(!dir.parent().unwrap().join("escape").exists());
        // Refused on shape, so refused whether or not the tree exists: `a/b/c` is there by now and `a/b/../b/c` still
        // is not accepted.
        assert!(
            h.mkdir_path(me, &anchor, "a/b/../b/c", mode).is_err(),
            "an existing tree does not make `..` acceptable"
        );
    });
}

/// Top-level directories that sit on another filesystem, the fixture the `RESOLVE_NO_XDEV` tests need.
///
/// `symlink_metadata`, not `metadata`. A followed symlink reports its TARGET's device, so on a usr-merged root `/lib ->
/// usr/lib` would qualify while being an ordinary symlink, and the opens under test, which resolve with
/// `RESOLVE_NO_SYMLINKS`, would die `ELOOP` on it before reaching the confinement.
///
/// **Real mounts first, and the order is deterministic.** `/proc`, `/sys`, `/dev` and `/run` are top-level mounts on
/// every Linux host, so an emptiness gate could never fire and the boundary crossed would be whichever entry `read_dir`
/// yielded first. A pseudo filesystem shares neither ZFS's mount semantics nor its ACL behaviour, so the pseudo mounts
/// sort last, and `TRUENAS_ROS_REQUIRE_MOUNT_BOUNDARY=1` demands a **real** crossing, such as the QEMU job's
/// `/POSIXACL` and `/NFSV4ACL` datasets.
fn mount_crossings() -> Vec<String> {
    /// Always present, so their presence proves nothing about provisioning.
    const PSEUDO: [&str; 4] = ["proc", "sys", "dev", "run"];

    let root_dev = std::fs::metadata("/").unwrap().dev();
    let mut found: Vec<String> = std::fs::read_dir("/")
        .unwrap()
        .flatten()
        .filter_map(|e| {
            let md = std::fs::symlink_metadata(e.path()).ok()?;
            (md.is_dir() && md.dev() != root_dev).then(|| e.file_name().into_string().ok())?
        })
        .collect();
    // Alphabetical, then a stable partition - so the chosen boundary is the same on every run of the same host.
    found.sort();
    found.sort_by_key(|n| PSEUDO.contains(&n.as_str()));
    let real = found.iter().filter(|n| !PSEUDO.contains(&n.as_str())).count();
    assert!(
        real > 0 || std::env::var_os("TRUENAS_ROS_REQUIRE_MOUNT_BOUNDARY").is_none(),
        "TRUENAS_ROS_REQUIRE_MOUNT_BOUNDARY is set but the only top-level \
         mounts are pseudo filesystems ({found:?}): the datasets \
         setup-test-zfs.sh provisions are missing, and crossing into procfs \
         says nothing about ZFS"
    );
    found
}

/// A crossing this identity can **search**, which is more than [`mount_crossings`] promises, since that filters on
/// device alone and the relocation half below opens the chosen mount as its own anchor. A top-level dataset can be
/// root-only (TrueNAS ships `/audit`, `/conf` and `/root` at 0700, and they sort first).
///
/// `metadata("/<name>/.")` asks exactly that, since resolving `.` inside the directory needs the search bit the test is
/// about to need.
fn traversable_crossing() -> Option<String> {
    let all = mount_crossings();
    let pick = all
        .iter()
        .find(|n| std::fs::metadata(format!("/{n}/.")).is_ok())
        .cloned();
    assert!(
        pick.is_some() || all.is_empty() || std::env::var_os("TRUENAS_ROS_REQUIRE_MOUNT_BOUNDARY").is_none(),
        "TRUENAS_ROS_REQUIRE_MOUNT_BOUNDARY is set but none of {all:?} is \
         searchable by uid {}: the confinement test needs a crossing it can \
         open as its own anchor, not merely one that exists",
        // SAFETY: `getuid` takes no arguments and cannot fail.
        unsafe { libc::getuid() }
    );
    pick
}

/// `RESOLVE_NO_XDEV` is what makes "this tree is one filesystem" a rule the kernel enforces rather than a convention,
/// since a walk that would step onto another mount fails instead of quietly serving files from it. Uses a real mount
/// boundary on the running system (on TrueNAS, a child dataset), and self-skips where the root filesystem has no child
/// mounts.
#[test]
fn confined_open_refuses_to_cross_a_mount_point() {
    with_fs(test_cfg(), |h, me, _dir, _stop| {
        let root = Anchor::open("/").expect("anchor /");
        let Some(name) = traversable_crossing() else {
            return; // single-filesystem host: nothing to cross
        };

        let how = OpenHow::new().flags(OFlag::O_PATH | OFlag::O_DIRECTORY);

        // The default carries NO_XDEV, so an ordinary open stops too. This is the half a caller gets without asking: a
        // share anchored on a parent dataset does not serve a child dataset's files through an object key that happens
        // to name its mountpoint.
        for (what, res) in [
            ("open", h.open(me, &root, name.as_str(), how)),
            ("open_confined", h.open_confined(me, &root, name.as_str(), how)),
        ] {
            assert!(
                matches!(res, Err(Error::Errno(Errno::EXDEV))),
                "{what}: crossing into /{name} must fail EXDEV, got {res:?}"
            );
        }

        // Stating a policy replaces the policy, not the hardening that rides with it. `RESOLVE_BENEATH` is how a caller
        // asks to follow in-tree symlinks; it must not also, silently, be how they ask to leave the filesystem - the
        // kernel keeps the two questions apart (`__traverse_mounts` consults only `LOOKUP_NO_XDEV`), and so does this.
        for stated in [
            ResolveFlag::RESOLVE_BENEATH,
            ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS,
            ResolveFlag::RESOLVE_IN_ROOT,
        ] {
            let res = h.open(me, &root, name.as_str(), how.resolve(stated));
            assert!(
                matches!(res, Err(Error::Errno(Errno::EXDEV))),
                "{stated:?} must not buy a mount crossing, got {res:?}"
            );
        }

        // The capability is not lost, only relocated to where a reader can see it: anchor on the nested mount and open
        // relative to that.
        let nested = Anchor::open(format!("/{name}").as_str()).expect("anchor nested");
        h.open(me, &nested, ".", how)
            .unwrap_or_else(|e| panic!("open of /{name} as its own anchor: {e}"));
    });
}

/// An abandoned upload leaves nothing to clean up - the property that removes the need for a temp-file sweeper. Drop
/// the file instead of committing it and assert the staging directory is still empty.
#[test]
fn abandoned_tmpfile_leaves_nothing_behind() {
    with_fs(test_cfg(), |h, me, dir, _stop| {
        std::fs::create_dir(dir.join("staging")).unwrap();
        let staging = Anchor::open(dir.join("staging").as_path()).unwrap();
        let how = OpenHow::new()
            .flags(OFlag::O_TMPFILE | OFlag::O_RDWR)
            .mode(Mode::from_bits_truncate(0o644));

        for _ in 0..8 {
            let f = h.open(me, &staging, ".", how).expect("open O_TMPFILE");
            let (n, _) = pwrite1(&h, me, &f, vec![b'x'; 4096], 0);
            assert_eq!(n.expect("write"), 4096);
            drop(f); // the upload is abandoned mid-flight
        }
        assert_eq!(
            std::fs::read_dir(dir.join("staging")).unwrap().count(),
            0,
            "abandoned temp files must leave no directory entries"
        );
    });
}

/// The confinement composes with every enrichment, not only the one that takes the by-name `statx` path.
///
/// Asking for xattrs, an ACL or a name list opens a descriptor, and the device then comes from a `statx` of *that* -
/// issued in the read phase, with no by-name answer at the collection phase at all. A confinement that reads "no
/// metadata here" as a failure at the earlier phase would refuse every such listing outright.
#[test]
fn confinement_composes_with_the_descriptor_enrichments() {
    with_fs(test_cfg(), |h, me, dir, _stop| {
        std::fs::write(dir.join("a"), b"x").expect("write");
        std::fs::create_dir(dir.join("d")).expect("mkdir");
        let anchor = Anchor::open(&dir).expect("anchor");
        for spec in [
            EnrichSpec::STATX | EnrichSpec::XATTR,
            EnrichSpec::STATX | EnrichSpec::XATTR_LIST,
            EnrichSpec::STATX,
        ] {
            let opts = QueryOptions {
                spec,
                clump: 64,
                same_device_only: true,
                xattr_names: vec![xattr_name("user.nope")],
                ..Default::default()
            };
            let mut q = query_directory(&h, me, &anchor, opts).expect("list");
            let mut names = Vec::new();
            while let Some(batch) = q.next() {
                for e in batch.unwrap_or_else(|e| panic!("{spec:?} listing refused: {e}")) {
                    names.push(e.name.to_string_lossy().into_owned());
                }
            }
            names.sort();
            assert_eq!(names, ["a", "d"], "{spec:?}");
        }
    });
}

/// `readdir` honours no `RESOLVE_*` flags, so the listing side needs its own mount check - otherwise a nested dataset
/// lists as though it were part of the tree. Uses a real mount boundary; self-skips without one.
#[test]
fn listing_can_be_confined_to_one_filesystem() {
    with_fs(test_cfg(), |h, me, _dir, _stop| {
        let root = Anchor::open("/").expect("anchor /");
        let crossings = mount_crossings();
        if crossings.is_empty() {
            return; // single-filesystem host
        }

        let names = |same_device_only: bool| -> Vec<String> {
            let opts = QueryOptions {
                spec: EnrichSpec::STATX,
                clump: 64,
                same_device_only,
                ..Default::default()
            };
            let mut q = query_directory(&h, me, &root, opts).expect("list /");
            let mut out = Vec::new();
            while let Some(batch) = q.next() {
                for e in batch.expect("batch") {
                    out.push(e.name.to_string_lossy().into_owned());
                }
            }
            out
        };

        let all = names(false);
        let confined = names(true);
        for c in &crossings {
            assert!(all.contains(c), "unconfined listing should include /{c}");
            assert!(!confined.contains(c), "confined listing must drop the mount point /{c}");
        }
        assert!(all.len() > confined.len(), "confinement should drop something here");
        for n in &confined {
            assert!(all.contains(n), "confinement must not invent entries");
        }
    });
}

#[test]
fn metadata_ops_carry_the_personality() {
    // Every metadata op stamps sqe.personality; an id this ring never registered must fail at submission rather than
    // running as the daemon.
    with_fs(test_cfg(), |h, me, dir, _stop| {
        std::fs::write(dir.join("f"), b"x").unwrap();
        let anchor = Anchor::open(dir.as_path()).unwrap();
        let bogus = Personality::from_raw(4242).unwrap();

        assert!(matches!(
            h.statx(bogus, &anchor, leaf("f"), AtFlags::empty(), StatxMask::BASIC_STATS),
            Err(Error::Errno(Errno::EINVAL))
        ));
        assert!(matches!(
            h.mkdirat(bogus, &anchor, leaf("d"), Mode::from_bits_truncate(0o755)),
            Err(Error::Errno(Errno::EINVAL))
        ));
        assert!(matches!(
            h.unlinkat(bogus, &anchor, leaf("f")),
            Err(Error::Errno(Errno::EINVAL))
        ));
        assert!(dir.join("f").exists(), "the refused unlink did nothing");

        let f = h.open(me, &anchor, "f", rdonly()).unwrap();
        let name = xattr_name("user.k");
        let (res, _v) = h.fgetxattr(bogus, &f, name.clone(), vec![0u8; 8]);
        assert!(matches!(res, Err(Error::Errno(Errno::EINVAL))));
        h.close(f).unwrap();
    });
}
