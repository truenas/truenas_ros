use super::*;

/// An `O_PATH` handle is refused by name, before any syscall that would appear to work.
///
/// `O_PATH` carries no file metadata: `fchmod(2)`, `fsetxattr(2)` and `setxattrat(2)`'s empty-path form all answer
/// it `EBADF`. Two forms *do* reach the inode - `fchmodat2(2)` with `AT_EMPTY_PATH`, and
/// `setxattr("/proc/self/fd/N", ..)` - and both have been used here and removed, because they carry only the mode:
/// an ACL on the same handle still cannot travel, so the copy looks faithful and has silently dropped the access
/// control. The screen is what makes a caller that pins with `O_PATH` find out at once.
///
/// The real descriptor on the same file is the control: without it a screen that refused everything would pass this
/// too.
#[test]
fn an_o_path_handle_cannot_carry_a_mode() {
    use std::os::unix::fs::PermissionsExt;
    let d = crate::tempdir().expect("tempdir");
    let p = d.path().join("f");
    std::fs::write(&p, b"x").expect("fixture");

    let real = std::fs::File::options().read(true).write(true).open(&p).expect("open");
    fchmod_fd(real.as_fd(), 0o640).expect("a real descriptor works");

    let path_fd = openat2(
        AT_FDCWD,
        p.as_os_str(),
        OpenHow::new().flags(OFlag::O_PATH | OFlag::O_NOFOLLOW),
    )
    .expect("O_PATH open");
    assert!(is_o_path(path_fd.as_fd()).expect("F_GETFL"));
    let err = fchmod_fd(path_fd.as_fd(), 0o600).expect_err("an O_PATH handle must be refused, not worked around");
    let msg = err.to_string();
    assert!(
        msg.contains("O_PATH") && msg.contains("real descriptor"),
        "the refusal must say what is wrong: {msg}"
    );
    // And it did not take effect by some other route.
    let m = std::fs::metadata(&p).expect("stat").permissions().mode();
    assert_eq!(m & 0o777, 0o640, "the refused call changed the mode anyway");
}

/// A swallowed `copy_permissions` failure releases the creation hold - or declines, and then reports no stamp.
///
/// `creation_mode` makes every object at a `0o700`/`0o600` hold on the promise that the source's mode lands
/// afterwards, `copy_permissions` is the only thing that delivers it, and `copy_metadata` wraps that in `guard` -
/// which answers `Ok(())` when `raise_error` is false, the mode `copytree`'s own docs name for salvaging a tree. So
/// a swallowed failure left the **hold** as the final mode for the whole tree, with `copytree` answering `Ok` and
/// plausible stats.
///
/// The live trigger is an ACL-namespace mismatch - an `acltype=nfsv4` source onto an `acltype=posix` destination,
/// or either onto `acltype=off` - which fails `fsetxattr` EOPNOTSUPP for every object, every time. That needs two
/// dataset types and is a QEMU-lane fixture. The failure is provoked through the same door here: `copy_metadata`
/// takes the attribute list as a parameter, so a name the source does not have makes its `fgetxattr` answer
/// ENODATA.
///
/// Both halves matter and they pull opposite ways. Where the destination carries no ACL the hold comes off and that
/// **is** a stamp, so a borrowed root keeps it - which is what `PERMISSIONS` means when `copy_permissions`
/// succeeds. Where the destination carries one, the ACL is already the permissions and an `fchmod` would rewrite it
/// (`aclmode=discard` replaces it outright), so the release declines and reports no stamp. A fix that always
/// stamps, or never does, passes one half and fails the other.
///
/// **What this does not reach is `copytree`'s use of the answer.** `list_xattrs` reads the source's real
/// attributes, so the failure cannot be provoked through the public entry point without two filesystems that
/// disagree about an ACL namespace. That wiring is covered by reading, not by this.
#[test]
fn a_swallowed_permissions_failure_releases_the_hold() {
    use std::os::unix::fs::PermissionsExt;
    let d = crate::tempdir().expect("tempdir");
    let src = d.path().join("s");
    let dst = d.path().join("d");
    std::fs::create_dir(&src).expect("src");
    std::fs::create_dir(&dst).expect("dst");
    // The source mode the fallback must land, distinct from the hold.
    std::fs::set_permissions(&src, std::fs::Permissions::from_mode(0o755)).expect("src mode");
    let sf = std::fs::File::open(&src).expect("open src");
    let st = statx(sf.as_fd(), "", AtFlags::AT_EMPTY_PATH, META_MASK).expect("statx");
    let cfg = CopyTreeConfig {
        flags: CopyFlags::PERMISSIONS,
        raise_error: false,
        ..Default::default()
    };
    // An attribute the source does not have: `fgetxattr` answers ENODATA and `guard` swallows the failure.
    let absent = vec![c"system.posix_acl_default".to_owned()];

    // The control: nothing named, so `copy_permissions` takes its `fchmod` branch and succeeds.
    let df = std::fs::File::open(&dst).expect("open dst");
    assert!(
        copy_metadata(sf.as_fd(), df.as_fd(), &[], &st, &cfg).expect("guard swallows nothing here"),
        "a successful copy_permissions is a stamp"
    );

    // Half one: no ACL on the destination, so the hold is released and the source's mode lands. Start it back at
    // the hold to prove it.
    std::fs::set_permissions(&dst, std::fs::Permissions::from_mode(0o700)).expect("hold");
    assert!(
        copy_metadata(sf.as_fd(), df.as_fd(), &absent, &st, &cfg).expect("raise_error is false, so the copy continues"),
        "the hold was released, which is a stamp"
    );
    assert_eq!(
        std::fs::metadata(&dst).expect("stat").permissions().mode() & 0o777,
        0o755,
        "the destination is still at the creation hold"
    );

    // Half two: an ACL on the destination, so the release declines rather than rewriting it, and reports no stamp.
    let acl = dst_with_acl(&d);
    if let Some(af) = acl {
        let ast = statx(af.as_fd(), "", AtFlags::AT_EMPTY_PATH, META_MASK).expect("statx");
        let before = ast.mode() & 0o7777;
        assert!(
            !copy_metadata(sf.as_fd(), af.as_fd(), &absent, &st, &cfg).expect("raise_error is false"),
            "an ACL-governed destination must not report a stamp"
        );
        let after = statx(af.as_fd(), "", AtFlags::AT_EMPTY_PATH, META_MASK)
            .expect("statx")
            .mode()
            & 0o7777;
        assert_eq!(before, after, "the release rewrote a mode an ACL governs");
    }

    // And with `raise_error` the same call is an error rather than a quiet answer, so the two dispositions stay
    // distinguishable - the release running *before* `guard` must not swallow the cause.
    let strict = CopyTreeConfig {
        raise_error: true,
        ..cfg
    };
    assert!(
        copy_metadata(sf.as_fd(), df.as_fd(), &absent, &st, &strict).is_err(),
        "raise_error must still propagate it"
    );
}

/// A directory carrying an access ACL, or `None` where this filesystem will not hold one. Loud under
/// `TRUENAS_ROS_REQUIRE_POSIX_ACL`.
#[cfg(test)]
fn dst_with_acl(d: &crate::TempDir) -> Option<std::fs::File> {
    let p = d.path().join("acl_dst");
    std::fs::create_dir(&p).expect("acl dst");
    let f = std::fs::File::open(&p).expect("open acl dst");
    // version 2, then USER_OBJ / USER:1000 / GROUP_OBJ / MASK / OTHER.
    let mut blob = 2u32.to_le_bytes().to_vec();
    for (tag, perm, id) in [
        (0x01u16, 0o7u16, !0u32),
        (0x02, 0o4, 1000),
        (0x04, 0o7, !0),
        (0x10, 0o7, !0),
        (0x20, 0o5, !0),
    ] {
        blob.extend_from_slice(&tag.to_le_bytes());
        blob.extend_from_slice(&perm.to_le_bytes());
        blob.extend_from_slice(&id.to_le_bytes());
    }
    // SAFETY: a live descriptor, a NUL-terminated name and a sized buffer.
    let rc = unsafe {
        libc::fsetxattr(
            f.as_raw_fd(),
            c"system.posix_acl_access".as_ptr(),
            blob.as_ptr().cast(),
            blob.len(),
            0,
        )
    };
    if rc != 0 {
        let e = std::io::Error::last_os_error();
        assert!(
            std::env::var_os("TRUENAS_ROS_REQUIRE_POSIX_ACL").is_none(),
            "TRUENAS_ROS_REQUIRE_POSIX_ACL is set but a directory here \
                 will not hold a POSIX ACL: {e}"
        );
        return None;
    }
    Some(f)
}

/// A symbolic link is the fourth creator and carries the metadata flags the other three do.
///
/// Nothing touched a created link, so `CopyFlags::TIMESTAMPS` and `CopyFlags::OWNER` were both silently dropped for
/// one while `copytree` answered `Ok` and counted it in `stats.symlinks`. The timestamp is the half an unprivileged
/// run can see; ownership needs a uid to give the link away to, so it belongs to the QEMU lane (measured there: a
/// source link at uid 1234 arrived at uid 0).
///
/// The regular file beside it is the control - it always carried the stamp - and the source time is far enough in
/// the past that a link left at the copy's own clock cannot pass.
#[test]
fn a_symlink_carries_the_metadata_flags() {
    fn set_link_time(p: &std::path::Path, sec: i64) {
        let c = std::ffi::CString::new(p.as_os_str().as_encoded_bytes()).expect("a path with no interior NUL");
        let t = [
            libc::timespec {
                tv_sec: sec,
                tv_nsec: 0,
            },
            libc::timespec {
                tv_sec: sec,
                tv_nsec: 0,
            },
        ];
        // SAFETY: a valid NUL-terminated path and a two-timespec array.
        let r = unsafe { libc::utimensat(libc::AT_FDCWD, c.as_ptr(), t.as_ptr(), libc::AT_SYMLINK_NOFOLLOW) };
        assert_eq!(r, 0, "utimensat: {}", std::io::Error::last_os_error());
    }
    fn link_mtime(p: &std::path::Path) -> i64 {
        use std::os::unix::fs::MetadataExt;
        std::fs::symlink_metadata(p).expect("lstat").mtime()
    }

    const OLD: i64 = 978_307_200; // 2001-01-01T00:00:00Z
    let d = crate::tempdir().expect("tempdir");
    let src = d.path().join("src");
    std::fs::create_dir(&src).expect("src");
    std::fs::write(src.join("target"), b"x").expect("target");
    std::fs::write(src.join("plain"), b"x").expect("plain");
    std::os::unix::fs::symlink("target", src.join("link")).expect("symlink");
    set_link_time(&src.join("link"), OLD);
    set_link_time(&src.join("plain"), OLD);

    let dst = d.path().join("dst");
    copytree(
        &src,
        &dst,
        &CopyTreeConfig {
            flags: CopyFlags::all(),
            ..Default::default()
        },
    )
    .expect("copytree");

    assert_eq!(
        std::fs::read_link(dst.join("link")).expect("read_link"),
        std::path::Path::new("target"),
        "the target still travels verbatim"
    );
    assert_eq!(
        link_mtime(&dst.join("plain")),
        OLD,
        "the control: a regular file carries the stamp"
    );
    assert_eq!(
        link_mtime(&dst.join("link")),
        OLD,
        "a link was left at the copy's own clock"
    );

    // And with the flag off it is not stamped, so the row above is the flag doing the work rather than a link
    // inheriting a time.
    let bare = d.path().join("bare");
    copytree(
        &src,
        &bare,
        &CopyTreeConfig {
            flags: CopyFlags::all() - CopyFlags::TIMESTAMPS,
            ..Default::default()
        },
    )
    .expect("copytree");
    assert_ne!(
        link_mtime(&bare.join("link")),
        OLD,
        "TIMESTAMPS off must leave the link at the create time"
    );
}

/// `mkfifo`, for the special-node rows: `std::fs` has no maker for one.
fn mkfifo_at(path: &std::path::Path, mode: libc::mode_t) {
    let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).expect("a path with no interior NUL");
    // SAFETY: a valid NUL-terminated path and a mode; creates a name.
    let r = unsafe { libc::mkfifo(c.as_ptr(), mode) };
    assert_eq!(r, 0, "mkfifo: {}", std::io::Error::last_os_error());
}

/// `copytree` without `CopyFlags::PERMISSIONS` must leave a usable tree, not an owner-only one.
///
/// Every destination object is created under a temporary hold - `0o700` for a directory, `0o600` for a file -
/// because the source's mode is broader and lands later, so group and other are not granted access to bytes still
/// being written. Without the flag nothing ever landed: `copy_metadata` gates `copy_permissions` on it, so the hold
/// was final and a copy asking for `XATTRS | OWNER | TIMESTAMPS` produced `dst=0700 dst/sub=0700 dst/sub/f=0600`
/// over a `0755` tree of `0644` files - and returned `Ok`.
///
/// The property is "whatever a plain `mkdir` or `open` would have produced", so the oracle is a reference tree
/// built with exactly those calls, in the same parent and at the same depth, rather than a constant or a umask
/// arithmetic. That is what makes it hold on a filesystem where the answer is *not* the umask: on ZFS with an
/// inheritable ACE on the parent, `zfs_mode_compute` rebuilds a created object's rwx bits out of the inherited ACL
/// and discards the requested ones, and under `aclmode=restricted` the requested mode is not consulted at all.
///
/// The `PERMISSIONS` arm is the control: it must still carry the source's modes, which a creation-mode change could
/// otherwise mask away.
#[test]
fn copytree_without_permissions_matches_a_plain_create() {
    let d = crate::tempdir().expect("tempdir");
    let src = d.path().join("src");
    std::fs::create_dir_all(src.join("sub")).expect("src tree");
    std::fs::write(src.join("sub/f"), b"x").expect("src file");
    mkfifo_at(&src.join("sub/p"), 0o600);
    for (p, m) in [
        (src.clone(), 0o755u32),
        (src.join("sub"), 0o750),
        (src.join("sub/f"), 0o644),
        (src.join("sub/p"), 0o600),
    ] {
        std::fs::set_permissions(&p, std::os::unix::fs::PermissionsExt::from_mode(m)).expect("source mode");
    }
    let mode = |p: std::path::PathBuf| -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(p).expect("stat").permissions().mode() & 0o7777
    };

    // The oracle: the same shape, built the ordinary way. A special node is the third creator, and `mkfifo(0o666)`
    // is what one built outside this copy looks like.
    let r = d.path().join("ref");
    std::fs::create_dir(&r).expect("ref root");
    std::fs::create_dir(r.join("sub")).expect("ref subdir");
    std::fs::File::create(r.join("sub/f")).expect("ref file");
    mkfifo_at(&r.join("sub/p"), 0o666);

    let dst = d.path().join("plain");
    copytree(
        &src,
        &dst,
        &CopyTreeConfig {
            flags: CopyFlags::all() - CopyFlags::PERMISSIONS,
            ..Default::default()
        },
    )
    .expect("copytree");
    assert_eq!(mode(dst.clone()), mode(r.clone()), "destination root");
    assert_eq!(mode(dst.join("sub")), mode(r.join("sub")), "subdirectory");
    assert_eq!(mode(dst.join("sub/f")), mode(r.join("sub/f")), "file");
    assert_eq!(
        mode(dst.join("sub/p")),
        mode(r.join("sub/p")),
        "a special node is the third creator and takes the same rule"
    );
    // And the oracle is not itself owner-only, or every row above would pass on the very state this exists to
    // refuse.
    assert_ne!(
        mode(r.join("sub/f")) & 0o077,
        0,
        "the runner's umask leaves nothing for this test to see"
    );

    // The control: with the flag the source's modes still arrive, and a chmod is not umask-masked, so they arrive
    // exactly.
    let dst = d.path().join("perms");
    copytree(
        &src,
        &dst,
        &CopyTreeConfig {
            flags: CopyFlags::all(),
            ..Default::default()
        },
    )
    .expect("copytree");
    assert_eq!(mode(dst.clone()), 0o755, "the source root's mode");
    assert_eq!(mode(dst.join("sub")), 0o750, "the source subdir's mode");
    assert_eq!(mode(dst.join("sub/f")), 0o644, "the source file's mode");
    assert_eq!(mode(dst.join("sub/p")), 0o600, "the source fifo's mode");
}

/// The destination root is narrowed for the duration only where a later mode is coming to release it into, and
/// every row says which mode that is.
///
/// The row that is easy to lose is `(created, PERMISSIONS)`. A created root looks like it cannot need narrowing -
/// the umask only ever narrows what `mkdir` was asked for - so a guard written as "narrow a root we did not create"
/// reads as complete and is not: with an inheritable ACE on the destination's parent, `zfs_mode_compute` rebuilds a
/// created directory's rwx bits out of the inherited ACL and discards the requested ones, so `0o700` comes back
/// `0o770`. Miss the row and the hold is gone for exactly the trees that carry ACLs, invisibly on every filesystem
/// this suite can reach.
///
/// The complement is the defect that started this: narrowing a created root with no `PERMISSIONS` makes `0o700` its
/// *final* mode, because nothing would ever put a broader one there.
#[test]
fn the_root_is_narrowed_only_where_a_later_mode_is_coming() {
    // (grants_others, created, permissions) -> narrowed, and why.
    for (grants, created, perms, want, why) in [
        (true, true, true, true, "copy_permissions stamps the source's"),
        (true, true, false, false, "nothing would ever release it"),
        (true, false, true, true, "copy_permissions stamps the source's"),
        (true, false, false, true, "the borrowed mode goes back"),
        // Nothing to narrow: owner-only already.
        (false, true, true, false, "owner-only already"),
        (false, true, false, false, "owner-only already"),
        (false, false, true, false, "owner-only already"),
        (false, false, false, false, "owner-only already"),
    ] {
        assert_eq!(
            narrows_the_root(grants, created, perms),
            want,
            "grants_others={grants} created={created} \
                 permissions={perms}: {why}"
        );
    }
}

/// A root the copy *borrowed* is still narrowed for the duration and handed back exactly as it was, which is a
/// different rule from the one above: there a later mode really is coming - the caller's own.
///
/// `mkdir_at` reporting whether it created the directory is what keeps the two apart. Inferred from the mode
/// instead (`& 0o077 != 0`), a root this copy just created at the umask default reads as borrowed on any umask that
/// leaves a group or other bit.
#[test]
fn a_borrowed_root_is_handed_back_as_it_was() {
    let d = crate::tempdir().expect("tempdir");
    let src = d.path().join("src");
    std::fs::create_dir_all(src.join("sub")).expect("src tree");
    std::fs::write(src.join("sub/f"), b"x").expect("src file");
    let dst = d.path().join("borrowed");
    std::fs::create_dir(&dst).expect("dst root");
    std::fs::set_permissions(&dst, std::os::unix::fs::PermissionsExt::from_mode(0o775)).expect("dst mode");

    copytree(
        &src,
        &dst,
        &CopyTreeConfig {
            flags: CopyFlags::all() - CopyFlags::PERMISSIONS,
            exist_ok: true,
            ..Default::default()
        },
    )
    .expect("copytree");
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        std::fs::metadata(&dst).expect("stat").permissions().mode() & 0o7777,
        0o775,
        "a borrowed root goes back exactly as it was"
    );
}

/// Listing an entry's xattr names is a metadata step and honours `raise_error` like every other one.
///
/// It was the one that did not: a source whose name list the kernel refuses failed the whole copy in **both**
/// modes, and two of the three call sites are directory-frame initialisers, so one such directory killed the copy
/// of everything beneath it. `E2BIG` is reachable on a well-formed file (`listxattr`, `fs/xattr.c:989-993`,
/// clamping at `XATTR_LIST_MAX`); driven here through an `O_PATH` handle, which the whole `f*xattr` family refuses
/// with `EBADF`, because that needs no filesystem willing to hold 64 KiB of names.
#[test]
fn listing_xattr_names_honours_raise_error() {
    let dir = crate::tempdir::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("f"), b"x").expect("write");
    let fd = openat2(
        AT_FDCWD,
        &dir.path().join("f"),
        OpenHow::new().flags(OFlag::O_PATH | OFlag::O_NOFOLLOW),
    )
    .expect("O_PATH open");

    let raising = CopyTreeConfig {
        raise_error: true,
        ..Default::default()
    };
    assert!(
        matches!(list_xattrs(fd.as_fd(), &raising), Err(Error::Errno(Errno::EBADF))),
        "a refused name list must surface where the caller asked for it"
    );

    let salvaging = CopyTreeConfig {
        raise_error: false,
        ..Default::default()
    };
    assert_eq!(
        list_xattrs(fd.as_fd(), &salvaging).expect("degrades"),
        Vec::<CString>::new(),
        "the mode a migration uses to salvage a tree must not fail here"
    );

    // And with neither flag asked for, the call is never made at all.
    let bare = CopyTreeConfig {
        flags: CopyFlags::TIMESTAMPS,
        raise_error: true,
        ..Default::default()
    };
    assert_eq!(list_xattrs(fd.as_fd(), &bare).expect("no names"), Vec::<CString>::new());
}
