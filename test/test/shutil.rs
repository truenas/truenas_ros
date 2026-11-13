use std::ffi::CStr;
use std::os::unix::fs::PermissionsExt;
use truenas_ros::Error;
use truenas_ros::errno::Errno;
use truenas_ros::sync_fs::shutil::{CopyTreeConfig, copytree, copytree_reporting};

/// Two sibling subdirectories, so the walk has to *ascend* between them.
///
/// The ascent only runs with more than one subdirectory, and `parent_dst` is read from the frame stack immediately
/// after it - so a frame left unpopped puts every entry of the second subdirectory inside the first one's
/// destination (`src/b/2` landing at `dst/a/b/2`) and stamps the wrong directory's mode. `copytree` still returns
/// `Ok` with plausible stats, so the misplacement is silent.
#[test]
fn sibling_subdirectories_land_beside_each_other() {
    let tmp = truenas_ros::tempdir().unwrap();
    let src = tmp.path().join("src");
    std::fs::create_dir_all(src.join("a")).unwrap();
    std::fs::create_dir_all(src.join("b")).unwrap();
    std::fs::write(src.join("a/1"), b"one").unwrap();
    std::fs::write(src.join("b/2"), b"two").unwrap();
    // Distinct modes, so a frame stamped onto the wrong directory shows.
    std::fs::set_permissions(src.join("a"), std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::set_permissions(src.join("b"), std::fs::Permissions::from_mode(0o750)).unwrap();

    let dst = tmp.path().join("dst");
    copytree(&src, &dst, &CopyTreeConfig::default()).unwrap();

    assert_eq!(std::fs::read(dst.join("a/1")).unwrap(), b"one");
    assert_eq!(std::fs::read(dst.join("b/2")).unwrap(), b"two");
    assert!(
        !dst.join("a/b").exists(),
        "the second subdirectory was copied inside the first"
    );
    let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&dst.join("a")), 0o755, "a's mode landed on a");
    assert_eq!(mode(&dst.join("b")), 0o750, "b's mode landed on b");
}

/// A destination root the copy did not create gets its mode back.
///
/// The root is held at 0o700 while the copy runs so group and other never see a half-written tree, and only
/// `copy_permissions` under `CopyFlags::PERMISSIONS` stamps the source's mode at the end. Without that flag the restore
/// is all that keeps a borrowed destination from staying owner-only.
#[test]
fn a_borrowed_destination_root_keeps_its_mode() {
    use truenas_ros::sync_fs::shutil::CopyFlags;
    let tmp = truenas_ros::tempdir().unwrap();
    let src = tmp.path().join("src");
    std::fs::create_dir(&src).unwrap();
    std::fs::write(src.join("f"), b"x").unwrap();
    std::fs::set_permissions(&src, std::fs::Permissions::from_mode(0o755)).unwrap();

    for (what, flags, want) in [
        // Nothing re-stamps the mode, so the restore is the only thing standing between the caller and a 0o700
        // destination.
        ("no PERMISSIONS", CopyFlags::OWNER | CopyFlags::TIMESTAMPS, 0o775),
        // The control: with the flag, the source root's mode lands, as that flag says it should.
        ("all flags", CopyFlags::all(), 0o755),
    ] {
        let dst = tmp.path().join(format!("dst-{}", want));
        std::fs::create_dir(&dst).unwrap();
        std::fs::set_permissions(&dst, std::fs::Permissions::from_mode(0o775)).unwrap();

        let config = CopyTreeConfig {
            flags,
            ..Default::default()
        };
        copytree(&src, &dst, &config).unwrap_or_else(|e| panic!("{what}: {e}"));
        let mode = std::fs::metadata(&dst).unwrap().permissions().mode();
        assert_eq!(mode & 0o7777, want, "{what}: destination left {:o}", mode & 0o7777);
    }
}

/// A destination *inside* the source is skipped rather than descended into. Without the guard the walk copies its own
/// output back into itself until the depth limit or a full filesystem. `copytree` advertises the skip, and this is what
/// holds it.
#[test]
fn a_destination_inside_the_source_is_not_copied_into_itself() {
    let tmp = truenas_ros::tempdir().unwrap();
    let src = tmp.path().join("src");
    std::fs::create_dir_all(src.join("sub")).unwrap();
    std::fs::write(src.join("sub/f"), b"x").unwrap();

    let dst = src.join("backup");
    copytree(&src, &dst, &CopyTreeConfig::default()).unwrap();

    assert_eq!(std::fs::read(dst.join("sub/f")).unwrap(), b"x");
    assert!(
        !dst.join("backup").exists(),
        "the copy descended into its own destination"
    );
}

// An xattr name need not be UTF-8 (the kernel checks length and namespace only, and ZFS validates names solely on
// the dir path under `utf8only`). The copier must address such a name by its bytes and carry it across.
#[test]
fn copies_xattr_with_non_utf8_name() {
    use std::os::fd::AsRawFd;
    let tmp = truenas_ros::tempdir().unwrap();
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
    let rc = unsafe { libc::fsetxattr(f.as_raw_fd(), name.as_ptr(), b"v".as_ptr().cast(), 1, 0) };
    if rc != 0 {
        super::xattr_probe::refusal_is_allowed("fsetxattr(non-utf8 user name)", std::io::Error::last_os_error());
        return;
    }
    drop(f);

    let dst = tmp.path().join("dst");
    copytree(&src, &dst, &CopyTreeConfig::default()).unwrap();

    let d = std::fs::File::open(dst.join("f")).unwrap();
    let mut buf = [0u8; 8];
    // SAFETY: `d` is live; `name` and `buf` are valid for the call.
    let n = unsafe { libc::fgetxattr(d.as_raw_fd(), name.as_ptr(), buf.as_mut_ptr().cast(), buf.len()) };
    assert_eq!(
        (n, &buf[..1.max(n.max(0) as usize)]),
        (1, &b"v"[..]),
        "a non-UTF-8 xattr name must survive the copy verbatim",
    );
}

// `security.capability` is a file capability set, so carrying it across a copy would stamp privilege onto a
// destination whose content came from the source. The kernel permits the write (it only asks for `CAP_SETFCAP`), so
// refusing it is the copier's job - the same refusal the asynchronous side makes in
// `PrivilegedXattrs::allow_prefix`. The `user.` attribute alongside it must still arrive, or this would pass on a
// copy that did nothing.
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
        unsafe { libc::fsetxattr(fd.as_raw_fd(), name.as_ptr(), val.as_ptr().cast(), val.len(), 0) }
    };

    let tmp = truenas_ros::tempdir().unwrap();
    let src = tmp.path().join("src");
    std::fs::create_dir(&src).unwrap();
    std::fs::write(src.join("bin"), b"#!/bin/sh\n").unwrap();
    let f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(src.join("bin"))
        .unwrap();
    // The gated probe runs first. A filesystem with no xattrs refuses both names and the capability skip below is
    // unconditional, so in the other order an xattr-less filesystem would skip silently with
    // `TRUENAS_ROS_REQUIRE_XATTRS` armed.
    if setxattr(&f, c"user.marker", b"v") != 0 {
        super::xattr_probe::refusal_is_allowed("setxattr(user.marker)", std::io::Error::last_os_error());
        return;
    }
    if setxattr(&f, c"security.capability", &CAP_SETUID_EP) != 0 {
        return; // needs CAP_SETFCAP, or the fs has no security namespace
    }
    drop(f);

    let dst = tmp.path().join("dst");
    copytree(&src, &dst, &CopyTreeConfig::default()).unwrap();

    let d = std::fs::File::open(dst.join("bin")).unwrap();
    let getxattr = |name: &CStr| -> (isize, i32) {
        let mut buf = [0u8; 32];
        // SAFETY: `d` is live; name and buffer are valid for the call.
        let n = unsafe { libc::fgetxattr(d.as_raw_fd(), name.as_ptr(), buf.as_mut_ptr().cast(), buf.len()) };
        (n, std::io::Error::last_os_error().raw_os_error().unwrap_or(0))
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

/// A FIFO whose own mode denies reading is still copied.
///
/// `make_special_meta` carries metadata through a real descriptor, so it opens the new node `O_RDONLY|O_NONBLOCK`.
/// Created at the source's mode, a write-only FIFO (`0o200`, `0o000`, `0o222`) would answer its own copy `EACCES`, so
/// it is created at the creation hold and the real mode lands in the `fchmod` afterwards.
///
/// DAC denies root nothing, so as root the `EACCES` is unreachable and every assertion below would merely pass. The
/// copy therefore runs with `CAP_DAC_OVERRIDE` and `CAP_DAC_READ_SEARCH` dropped from this thread. `DacDropped::take`
/// is a no-op for a non-root caller, so the unprivileged runner is unchanged.
#[test]
fn a_write_only_fifo_is_still_copied() {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::PermissionsExt;
    let tmp = truenas_ros::tempdir().unwrap();
    let src = tmp.path().join("src");
    std::fs::create_dir(&src).unwrap();
    let c = std::ffi::CString::new(src.join("wo").as_os_str().as_bytes().to_vec()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o200) }, 0);
    // mkfifo is umask-masked; force the exact bits.
    std::fs::set_permissions(src.join("wo"), std::fs::Permissions::from_mode(0o200)).unwrap();

    let dst = tmp.path().join("dst");
    let stats = {
        let _dac = DacDropped::take();
        copytree(&src, &dst, &CopyTreeConfig::default()).expect("a write-only FIFO must not fail its own copy")
    };
    assert_eq!(stats.specials, 1);
    assert_eq!(
        std::fs::symlink_metadata(dst.join("wo")).unwrap().permissions().mode() & 0o777,
        0o200,
        "the source's mode must still travel, hold or no hold"
    );
}

/// A special node takes the source's mode and **not** its access ACL.
///
/// This pins a limitation, not a feature. The walk pins source specials `O_PATH`, which cannot read an xattr, reopening
/// the source FIFO for real would release any writer blocked in `open(O_WRONLY)` on it, and reading it by name
/// re-resolves it. So `CopyFlags::PERMISSIONS` runs only its `fchmod` half here. The regular file is the control,
/// carrying the same ACL through the same copy, so this is the special-file path and not a broken fixture.
#[test]
fn a_special_file_takes_the_mode_and_not_the_acl() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = truenas_ros::tempdir().unwrap();
    let src = tmp.path().join("src");
    std::fs::create_dir(&src).unwrap();
    std::fs::write(src.join("reg"), b"data").unwrap();
    let cpath = |p: &std::path::Path| std::ffi::CString::new(p.as_os_str().as_encoded_bytes().to_vec()).unwrap();
    let fifo = cpath(&src.join("fifo"));
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o640) }, 0);

    // version 2, then USER_OBJ / USER:1000 / GROUP_OBJ / MASK / OTHER.
    let mut blob = 2u32.to_le_bytes().to_vec();
    // Resolves to mode 0o666, which a 0o022 umask strips down to 0o644 at `mknodat` - so the destination only
    // reaches it if the mode is applied through the descriptor afterwards.
    for (tag, perm, id) in [
        (0x01u16, 0o6u16, !0u32),
        (0x02, 0o4, 1000),
        (0x04, 0o6, !0),
        (0x10, 0o6, !0),
        (0x20, 0o6, !0),
    ] {
        blob.extend_from_slice(&tag.to_le_bytes());
        blob.extend_from_slice(&perm.to_le_bytes());
        blob.extend_from_slice(&id.to_le_bytes());
    }
    let acl = c"system.posix_acl_access";
    for n in ["reg", "fifo"] {
        let c = cpath(&src.join(n));
        let rc = unsafe { libc::setxattr(c.as_ptr(), acl.as_ptr(), blob.as_ptr().cast(), blob.len(), 0) };
        if rc != 0 {
            let e = std::io::Error::last_os_error();
            assert!(
                std::env::var_os("TRUENAS_ROS_REQUIRE_POSIX_ACL").is_none(),
                "TRUENAS_ROS_REQUIRE_POSIX_ACL is set but {n} here will \
                     not hold a POSIX ACL: {e}"
            );
            return;
        }
    }
    let src_mode = std::fs::symlink_metadata(src.join("fifo"))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(src_mode, 0o666, "the fixture's own mode");

    let dst = tmp.path().join("dst");
    copytree(&src, &dst, &CopyTreeConfig::default()).unwrap();

    let has_acl = |p: &std::path::Path| -> bool {
        let c = cpath(p);
        let n = unsafe { libc::getxattr(c.as_ptr(), acl.as_ptr(), std::ptr::null_mut(), 0) };
        n >= 0
    };
    assert!(has_acl(&dst.join("reg")), "the control: a regular file carries its ACL");
    assert!(
        !has_acl(&dst.join("fifo")),
        "a special node carrying an ACL means this limitation is gone - \
             update the docs on `make_special_meta` and delete this test"
    );
    assert_eq!(
        std::fs::symlink_metadata(dst.join("fifo"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        src_mode,
        "the mode is the half that does travel, exactly"
    );
}

/// The **mode** is carried through a real descriptor or not at all.
///
/// A FIFO can be opened `O_RDONLY|O_NONBLOCK` without waiting for a writer, so it takes the full metadata set. A socket
/// refuses every `open(2)` with `ENXIO` and a device node's open runs its driver, so neither can be given one, and
/// `copytree` says so instead of reaching for `fchmodat2`'s empty-path form on an `O_PATH` pin or `/proc/self/fd/N`.
/// Those carry only the mode while an ACL or xattr cannot travel (`fsetxattr` and `setxattrat` with `AT_EMPTY_PATH`
/// both answer an `O_PATH` descriptor `EBADF`), so the copy would report `Ok` having dropped the access control.
///
/// Owner and timestamps do travel, and `a_socket_carries_everything_but_its_mode` is that half. With the three metadata
/// flags cleared there is nothing to carry, so the same socket copies as a bare node.
#[test]
fn a_socket_is_refused_rather_than_moded_through_a_path() {
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};
    use truenas_ros::sync_fs::shutil::CopyFlags;
    let tmp = truenas_ros::tempdir().unwrap();
    let src = tmp.path().join("src");
    std::fs::create_dir(&src).unwrap();
    let _sock = std::os::unix::net::UnixListener::bind(src.join("sock")).unwrap();
    std::fs::set_permissions(src.join("sock"), std::fs::Permissions::from_mode(0o666)).unwrap();

    let dst = tmp.path().join("dst");
    let err = copytree(&src, &dst, &CopyTreeConfig::default())
        .expect_err("a socket cannot carry metadata, so this must fail");
    let msg = err.to_string();
    assert!(
        msg.contains("socket") && msg.contains("real descriptor"),
        "the refusal must name the type and why: {msg}"
    );

    let bare = tmp.path().join("bare");
    let cfg = CopyTreeConfig {
        flags: CopyFlags::empty(),
        ..Default::default()
    };
    copytree(&src, &bare, &cfg).expect("a bare socket still copies");
    assert!(
        std::fs::symlink_metadata(bare.join("sock"))
            .unwrap()
            .file_type()
            .is_socket(),
        "the node itself is still recreated by type"
    );

    // The control: a FIFO in the same position takes the whole set, so this is the socket and not a broken fixture.
    let fsrc = tmp.path().join("fsrc");
    std::fs::create_dir(&fsrc).unwrap();
    let c = std::ffi::CString::new(fsrc.join("fifo").into_os_string().into_encoded_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o640) }, 0);
    let fdst = tmp.path().join("fdst");
    copytree(&fsrc, &fdst, &CopyTreeConfig::default()).expect("a FIFO carries its metadata through a real descriptor");
    assert_eq!(
        std::fs::symlink_metadata(fdst.join("fifo"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o640,
        "the FIFO's exact mode must survive the umask"
    );
}

/// A socket gives up its mode and nothing else.
///
/// Only `fchmod` needs a real descriptor. `fchownat` and `utimensat` with `AT_EMPTY_PATH` work on the `O_PATH` peek and
/// are type-agnostic in the kernel (`chown_common`, `fs/open.c:754`, tests the inode's type only to kill setid, and
/// `do_utimes_path`, `fs/utimes.c:86`, accepts the flag outright), so refusing them too would give up three attributes
/// to report one.
///
/// The mode assertion needs no knowledge of the umask, since a regular file beside the socket is created at the same
/// `creation_mode` and the two are compared to each other. The owner half only distinguishes as root, where the source
/// can be given an identity the copier does not have. The timestamp half bites everywhere, with stamps far enough from
/// now that they cannot arrive by accident.
#[test]
fn a_socket_carries_everything_but_its_mode() {
    use std::os::unix::fs::MetadataExt;
    use truenas_ros::sync_fs::shutil::CopyFlags;
    const ATIME: i64 = 1_000_000_000;
    const MTIME: i64 = 1_234_567_890;

    let tmp = truenas_ros::tempdir().unwrap();
    let src = tmp.path().join("src");
    std::fs::create_dir(&src).unwrap();
    let _sock = std::os::unix::net::UnixListener::bind(src.join("sock")).unwrap();
    // The control for the creation mode: same source mode, a type that takes the whole metadata set.
    std::fs::write(src.join("reg"), b"x").unwrap();
    for n in ["sock", "reg"] {
        std::fs::set_permissions(src.join(n), std::fs::Permissions::from_mode(0o707)).unwrap();
    }

    // Stamp the source by NAME: a socket cannot be opened to be stamped through a descriptor, which is the whole
    // reason this case exists.
    let c = std::ffi::CString::new(src.join("sock").into_os_string().into_encoded_bytes()).unwrap();
    // SAFETY: geteuid reads the caller's credentials and cannot fail.
    let uid = unsafe { libc::geteuid() };
    let want_uid = if uid == 0 { 65534 } else { uid };
    assert_eq!(
        unsafe {
            libc::fchownat(
                libc::AT_FDCWD,
                c.as_ptr(),
                want_uid,
                u32::MAX,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        },
        0,
        "could not give the source socket its own owner"
    );
    let times = [
        libc::timespec {
            tv_sec: ATIME,
            tv_nsec: 0,
        },
        libc::timespec {
            tv_sec: MTIME,
            tv_nsec: 0,
        },
    ];
    assert_eq!(
        unsafe { libc::utimensat(libc::AT_FDCWD, c.as_ptr(), times.as_ptr(), libc::AT_SYMLINK_NOFOLLOW,) },
        0,
        "could not stamp the source socket"
    );

    // Nothing this asks for is impossible, so nothing is refused.
    let dst = tmp.path().join("dst");
    let cfg = CopyTreeConfig {
        flags: CopyFlags::OWNER | CopyFlags::TIMESTAMPS,
        ..Default::default()
    };
    let stats = copytree(&src, &dst, &cfg).expect("owner and timestamps need no real descriptor");
    assert_eq!(stats.specials, 1);
    let md = std::fs::symlink_metadata(dst.join("sock")).unwrap();
    assert_eq!(md.uid(), want_uid, "the source's owner must travel");
    assert_eq!(md.atime(), ATIME, "the source's atime must travel");
    assert_eq!(md.mtime(), MTIME, "the source's mtime must travel");
    let reg_mode = std::fs::metadata(dst.join("reg")).unwrap().permissions().mode() & 0o777;
    assert_eq!(
        md.permissions().mode() & 0o777,
        reg_mode,
        "with PERMISSIONS clear the socket takes the same creation mode \
             as the file beside it"
    );
    assert_ne!(
        md.permissions().mode() & 0o777,
        0o707,
        "and the source's mode is not what travels"
    );

    // The default flags ask for the mode too, which is the one thing that cannot travel: the copy fails and says
    // so - and the two that can travel have landed on the node that is there.
    let strict = tmp.path().join("strict");
    let err = copytree(&src, &strict, &CopyTreeConfig::default()).expect_err("a socket's mode cannot travel");
    let msg = err.to_string();
    assert!(
        msg.contains("socket") && msg.contains("real descriptor") && msg.contains("mode"),
        "the refusal must name the type and the one attribute it is \
             about: {msg}"
    );
    let md = std::fs::symlink_metadata(strict.join("sock")).unwrap();
    assert_eq!(md.uid(), want_uid, "the owner travelled before the mode");
    assert_eq!(md.mtime(), MTIME, "so did the timestamps");

    // PERMISSIONS alone asks for the one thing that cannot travel, and for nothing else: the refusal fires, and
    // neither of the two calls above runs. Each is gated on its own flag, and the message says "where asked for"
    // rather than claiming a carry that never happened.
    let only = tmp.path().join("only");
    let cfg = CopyTreeConfig {
        flags: CopyFlags::PERMISSIONS,
        ..Default::default()
    };
    copytree(&src, &only, &cfg).expect_err("PERMISSIONS is the flag that cannot be served");
    let md = std::fs::symlink_metadata(only.join("sock")).unwrap();
    // Against the *copier's* identity, not against `want_uid`: the two are the same uid unless this is running as
    // root, and an inequality would then fail the unprivileged runner for being unprivileged. This says the same
    // thing where it can distinguish and nothing false where it cannot.
    assert_eq!(
        md.uid(),
        uid,
        "OWNER was not asked for, so the node keeps the copier's \
             identity"
    );
    assert_ne!(
        md.mtime(),
        MTIME,
        "TIMESTAMPS was not asked for, so no stamp may have run"
    );
}

/// The special-type refusal is a metadata-copy failure, so `raise_error: false` swallows it like every other one.
///
/// It fires only because metadata was requested, after the node itself is created and verified, and
/// `CopyTreeConfig::raise_error` documents that class as ignored when false. Returned past `guard`, one unix socket
/// anywhere in a source tree, such as an ssh-agent socket in a home directory, would fail the whole copy in both
/// dispositions.
///
/// Swallowed, the node is the bare special the refusal's own message tells the caller to ask for, and it keeps the
/// creation hold, since releasing that needs the very `fchmod` a socket cannot be given.
#[test]
fn a_refused_special_type_is_swallowed_when_errors_are_not_raised() {
    use std::os::unix::fs::FileTypeExt;
    let tmp = truenas_ros::tempdir().unwrap();
    let src = tmp.path().join("src");
    std::fs::create_dir(&src).unwrap();
    let _sock = std::os::unix::net::UnixListener::bind(src.join("sock")).unwrap();
    std::fs::write(src.join("reg"), b"payload").unwrap();

    // The control: the default `raise_error: true` still refuses, with the message unchanged.
    let strict = tmp.path().join("strict");
    let err = copytree(&src, &strict, &CopyTreeConfig::default()).expect_err("raise_error: true still refuses");
    assert!(
        err.to_string().contains("socket"),
        "the refusal must still name the type: {err}"
    );

    let dst = tmp.path().join("dst");
    let cfg = CopyTreeConfig {
        raise_error: false,
        ..Default::default()
    };
    let stats = copytree(&src, &dst, &cfg).expect("raise_error: false must not fail the copy over a socket");
    assert_eq!(stats.specials, 1, "the socket is counted");
    assert_eq!(stats.files, 1, "and the file beside it is copied");
    assert!(
        std::fs::symlink_metadata(dst.join("sock"))
            .unwrap()
            .file_type()
            .is_socket(),
        "the node is recreated by type"
    );
    assert_eq!(
        std::fs::read(dst.join("reg")).unwrap(),
        b"payload",
        "the walk continued past the socket"
    );
}

/// Drop `CAP_DAC_OVERRIDE`/`CAP_DAC_READ_SEARCH` from **this thread's** effective set for as long as the guard
/// lives.
///
/// Running as root, DAC denies nothing, so an `EACCES` path cannot be provoked at all. Capabilities are
/// per-*thread* credentials and `capset` with `pid: 0` addresses the calling thread, so this is local to the test -
/// no fork, and nothing else in the binary sees it. Only *effective* is narrowed, so permitted still holds what the
/// restore raises back.
struct DacDropped(Option<[u32; 2]>);

impl DacDropped {
    const CAP_DAC_OVERRIDE: u32 = 1;
    const CAP_DAC_READ_SEARCH: u32 = 2;

    /// `None` when the caller is not root - there is nothing to drop and the kernel is already denying, which is
    /// the state under test.
    fn take() -> Self {
        // SAFETY: reads the calling thread's uid.
        if unsafe { libc::geteuid() } != 0 {
            return DacDropped(None);
        }
        let mut data = Self::caps();
        let saved = [data[0], data[1]];
        data[0] &= !((1 << Self::CAP_DAC_OVERRIDE) | (1 << Self::CAP_DAC_READ_SEARCH));
        Self::set_effective(data);
        DacDropped(Some(saved))
    }

    /// The effective words of the calling thread, low then high.
    fn caps() -> [u32; 2] {
        let mut hdr = [0x2008_0522u32, 0]; // VERSION_3, pid 0
        let mut data = [0u32; 6]; // two {effective, permitted, inheritable}
        // SAFETY: capget fills two three-word blocks for VERSION_3.
        let r = unsafe { libc::syscall(libc::SYS_capget, hdr.as_mut_ptr(), data.as_mut_ptr()) };
        assert_eq!(r, 0, "capget");
        [data[0], data[3]]
    }

    fn set_effective(eff: [u32; 2]) {
        let mut hdr = [0x2008_0522u32, 0];
        let mut data = [0u32; 6];
        // SAFETY: as above.
        let r = unsafe { libc::syscall(libc::SYS_capget, hdr.as_mut_ptr(), data.as_mut_ptr()) };
        assert_eq!(r, 0, "capget");
        data[0] = eff[0];
        data[3] = eff[1];
        // SAFETY: capset reads the same layout back.
        let r = unsafe { libc::syscall(libc::SYS_capset, hdr.as_mut_ptr(), data.as_ptr()) };
        assert_eq!(r, 0, "capset");
    }
}

impl Drop for DacDropped {
    fn drop(&mut self) {
        if let Some(saved) = self.0 {
            Self::set_effective(saved);
        }
    }
}

/// A destination node the copy cannot open is refused **by name**.
///
/// `creation_mode`'s hold is only a request. Where the destination parent carries an inheritable ACL the umask never
/// applies and the new node's mode is narrowed through the inherited entries instead (`zpl_init_acl` ->
/// `__posix_acl_create`, `module/os/linux/zfs/zpl_xattr.c`, and `posix_acl_create`, `fs/posix_acl.c`), so a parent
/// whose entries withhold owner-read produces a node this copy cannot open for the descriptor its metadata needs. The
/// error must name that node rather than surface as a bare `EACCES`.
///
/// The fixture is a destination root carrying `default:user::-w-`, written as the raw `system.posix_acl_default` blob
/// because the narrowing is what is under test and `setfacl` is not a dependency. A filesystem that refuses the xattr
/// fails the test rather than skipping it, since every temp filesystem this runs on does POSIX ACLs.
#[test]
fn a_destination_node_without_owner_read_names_what_narrowed_it() {
    use std::os::unix::fs::PermissionsExt;
    use truenas_ros::sync_fs::xattr::{XattrFlags, fsetxattr};
    let tmp = truenas_ros::tempdir().unwrap();
    let src = tmp.path().join("src");
    std::fs::create_dir(&src).unwrap();
    let fifo = src.join("fifo");
    let c = std::ffi::CString::new(fifo.clone().into_os_string().into_encoded_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o644) }, 0);

    // `system.posix_acl_default`: version 2, then {u16 tag, u16 perm, u32 id} per entry. user:: write-only, group::
    // and other:: none -- the minimal complete set, and the owner entry is the one `posix_acl_create_masq`
    // intersects the requested mode against.
    let mut acl = 2u32.to_le_bytes().to_vec();
    for (tag, perm) in [(0x01u16, 2u16), (0x04, 0), (0x20, 0)] {
        acl.extend_from_slice(&tag.to_le_bytes());
        acl.extend_from_slice(&perm.to_le_bytes());
        acl.extend_from_slice(&u32::MAX.to_le_bytes());
    }
    // On the destination ROOT, so only what the copy creates *inside* it is narrowed: put it a level up and the
    // destination directory itself lands at 0o200 and the copy cannot even enter it.
    let dst = tmp.path().join("dst");
    std::fs::create_dir(&dst).unwrap();
    let dfd = std::fs::File::open(&dst).unwrap();
    fsetxattr(
        std::os::fd::AsFd::as_fd(&dfd),
        c"system.posix_acl_default",
        &acl,
        XattrFlags::empty(),
    )
    .expect("the temp filesystem must support POSIX default ACLs");

    let err = {
        let _dac = DacDropped::take();
        copytree(&src, &dst, &CopyTreeConfig::default()).expect_err("the new node has no owner-read to open it with")
    };
    let msg = err.to_string();
    assert!(
        msg.contains("without owner-read") && msg.contains("inherited") && msg.contains("0o200"),
        "the refusal must name the mode it measured and what set it: \
             {msg}"
    );
    // The premise, in case a filesystem ever stops narrowing: the node really was created below the hold this copy
    // asked for.
    assert_eq!(
        std::fs::symlink_metadata(dst.join("fifo"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o200,
        "the inherited entries, not the copy, chose this mode"
    );
}

// A writer-less FIFO in the source must be recreated by type, not read as a regular file (which would block the
// copy forever).
#[test]
fn recreates_special_files_by_type() {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::FileTypeExt;
    let tmp = truenas_ros::tempdir().unwrap();
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

// The kernel clears S_ISUID/S_ISGID when a non-directory is chowned (`chown_common`, fs/open.c), so the copy must
// apply ownership before the mode for a setuid/setgid file - and for a special file - to keep both bits.
#[test]
fn preserves_setid_bits_on_files_and_specials() {
    use std::os::unix::ffi::OsStrExt;
    let tmp = truenas_ros::tempdir().unwrap();
    let src = tmp.path().join("src");
    std::fs::create_dir(&src).unwrap();
    std::fs::write(src.join("helper"), b"data").unwrap();
    let fifo = src.join("pipe");
    let c = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o644) }, 0);
    // Setuid and setgid on an own file, both set with the group execute bit so the kernel drops them
    // unconditionally on chown.
    for name in ["helper", "pipe"] {
        std::fs::set_permissions(src.join(name), std::fs::Permissions::from_mode(0o6755)).unwrap();
    }

    let dst = tmp.path().join("dst");
    copytree(&src, &dst, &CopyTreeConfig::default()).unwrap();

    for name in ["helper", "pipe"] {
        let mode = std::fs::symlink_metadata(dst.join(name)).unwrap().permissions().mode();
        assert_eq!(mode & 0o7777, 0o6755, "{name} lost its setid bits");
    }
}

// setid grants the destination *owner's* identity, so preserving the mode without the ownership must not preserve
// it: a root-run copy of an unprivileged user's 4755 file would otherwise yield a setuid-root binary whose contents
// that user wrote.
#[test]
fn setid_withheld_when_ownership_is_not_preserved() {
    use std::os::unix::ffi::OsStrExt;
    use truenas_ros::sync_fs::shutil::CopyFlags;
    let tmp = truenas_ros::tempdir().unwrap();
    let src = tmp.path().join("src");
    std::fs::create_dir(&src).unwrap();
    std::fs::write(src.join("helper"), b"data").unwrap();
    let fifo = src.join("pipe");
    let c = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
    for name in ["helper", "pipe"] {
        std::fs::set_permissions(src.join(name), std::fs::Permissions::from_mode(0o4755)).unwrap();
    }

    let config = CopyTreeConfig {
        flags: CopyFlags::PERMISSIONS | CopyFlags::XATTRS | CopyFlags::TIMESTAMPS,
        ..Default::default()
    };
    let dst = tmp.path().join("dst");
    copytree(&src, &dst, &config).unwrap();

    for name in ["helper", "pipe"] {
        let mode = std::fs::symlink_metadata(dst.join(name)).unwrap().permissions().mode();
        assert_eq!(mode & 0o6000, 0, "{name} kept setid: {mode:o}");
        assert_eq!(mode & 0o777, 0o755);
    }
}

// A special file's permission bits are restored through a handle on the new node, never a re-resolved name: a
// symlink planted at the destination name is not the object chmodded, and the umask-masked bits are still restored
// on the ordinary path.
#[test]
fn special_file_mode_is_not_applied_through_a_symlink() {
    use std::os::unix::ffi::OsStrExt;
    let tmp = truenas_ros::tempdir().unwrap();
    let src = tmp.path().join("src");
    std::fs::create_dir(&src).unwrap();
    let fifo = src.join("pipe");
    let c = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o777) }, 0);
    std::fs::set_permissions(&fifo, std::fs::Permissions::from_mode(0o777)).unwrap();

    let victim = tmp.path().join("victim");
    std::fs::write(&victim, b"victim-content").unwrap();
    std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o600)).unwrap();

    let dst = tmp.path().join("dst");
    std::fs::create_dir(&dst).unwrap();
    std::os::unix::fs::symlink(&victim, dst.join("pipe")).unwrap();

    // exist_ok tolerates the planted name; whether the copy errors or skips, nothing may be chmodded through the
    // symlink.
    let _ = copytree(&src, &dst, &CopyTreeConfig::default());
    assert_eq!(
        std::fs::metadata(&victim).unwrap().permissions().mode() & 0o7777,
        0o600,
        "victim's mode changed - the destination name was followed"
    );
    assert_eq!(std::fs::read(&victim).unwrap(), b"victim-content");

    // The ordinary path restores the exact bits mknodat lost to the umask.
    let dst2 = tmp.path().join("dst2");
    let stats = copytree(&src, &dst2, &CopyTreeConfig::default()).unwrap();
    assert_eq!(stats.specials, 1);
    let md = std::fs::symlink_metadata(dst2.join("pipe")).unwrap();
    assert_eq!(md.permissions().mode() & 0o7777, 0o777);
}

// An existing destination file must be replaced, not filled in place: the copied data must never appear in an inode
// someone else created and may still hold open.
#[test]
fn existing_destination_file_is_replaced_not_reused() {
    use std::io::Read;
    use std::os::unix::fs::MetadataExt;
    let tmp = truenas_ros::tempdir().unwrap();
    let src = tmp.path().join("src");
    std::fs::create_dir(&src).unwrap();
    std::fs::write(src.join("secret"), b"SECRET-KEY-MATERIAL").unwrap();

    let dst = tmp.path().join("dst");
    std::fs::create_dir(&dst).unwrap();
    std::fs::write(dst.join("secret"), b"planted").unwrap();
    let mut planted = std::fs::File::open(dst.join("secret")).unwrap();
    let planted_ino = planted.metadata().unwrap().ino();

    let stats = copytree(&src, &dst, &CopyTreeConfig::default()).unwrap();
    assert_eq!(stats.files, 1);
    assert_eq!(std::fs::read(dst.join("secret")).unwrap(), b"SECRET-KEY-MATERIAL");

    let copied_ino = std::fs::metadata(dst.join("secret")).unwrap().ino();
    assert_ne!(copied_ino, planted_ino, "the copy reused the inode");
    let mut through_held_fd = Vec::new();
    planted.read_to_end(&mut through_held_fd).unwrap();
    assert_eq!(through_held_fd, b"planted");
}

// The destination root's mkdir must not resolve a symlink in the path: the copy fails either way, but nothing may
// be created outside the tree.
#[test]
fn destination_root_is_not_created_through_a_symlink() {
    let tmp = truenas_ros::tempdir().unwrap();
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

/// A failed POSIX ACL write must leave the access half untouched.
///
/// `PosixAcl::validate` bounds tag counts, canonical order, `rwx` bits and id representability - never *size* - and
/// nothing bounds entry count, so an oversized list encodes happily and the kernel answers `E2BIG`. The two xattr
/// writes are not atomic, so one half can be left behind, and it must never be the access ACL: that is what the
/// kernel consults on every open, so a get-modify-set widening access and failing on the default would grant the
/// wider rights while telling the caller nothing changed.
#[cfg(feature = "acl")]
#[test]
fn a_failed_posix_acl_write_leaves_the_access_half_untouched() {
    use std::os::fd::AsFd;
    use truenas_ros::sync_fs::acl::{PosixAce, PosixAcl, PosixPerm, PosixTag, fsetacl_posix};
    use truenas_ros::sync_fs::xattr::fgetxattr;

    let ace = |tag, perms, id, default| PosixAce {
        tag,
        perms,
        id,
        default,
    };
    let rx = PosixPerm::READ | PosixPerm::EXECUTE;
    let access_of = |p| {
        vec![
            ace(PosixTag::UserObj, PosixPerm::all(), -1, false),
            ace(PosixTag::User, p, 1234, false),
            ace(PosixTag::GroupObj, p, -1, false),
            ace(PosixTag::Mask, p, -1, false),
            ace(PosixTag::Other, p, -1, false),
        ]
    };
    let default_of = |p| {
        vec![
            ace(PosixTag::UserObj, PosixPerm::all(), -1, true),
            ace(PosixTag::User, p, 1234, true),
            ace(PosixTag::GroupObj, p, -1, true),
            ace(PosixTag::Mask, p, -1, true),
            ace(PosixTag::Other, p, -1, true),
        ]
    };
    let get = |f: &std::fs::File, n| fgetxattr(f.as_fd(), n).ok();
    let acc = "system.posix_acl_access";
    let def = "system.posix_acl_default";

    let tmp = truenas_ros::tempdir().unwrap();
    let d = tmp.path().join("d");
    std::fs::create_dir(&d).unwrap();
    let f = std::fs::File::open(&d).unwrap();

    let mut start = access_of(rx);
    start.extend(default_of(rx));
    let start = PosixAcl::from_aces(start);
    let sb = start.access_bytes().unwrap();
    let sd = start.default_bytes().unwrap();
    if let Err(e) = fsetacl_posix(f.as_fd(), &sb, sd.as_deref()) {
        // Every assertion below is skipped, so the refusal answers to the gate rather than passing green having
        // tested nothing.
        super::xattr_probe::posix_acl_refusal_is_allowed("fsetacl_posix", e);
        return; // no POSIX ACLs here (an NFSv4-ACL dataset, say)
    }
    let before_acc = get(&f, acc);
    let before_def = get(&f, def);
    assert!(before_acc.is_some(), "the starting ACL is stored");

    // Widen access to rwx and attach an oversized default: the default write is the one that fails.
    let mut aces = access_of(PosixPerm::all());
    aces.extend(default_of(rx));
    for i in 0..400_000i64 {
        aces.push(ace(PosixTag::User, rx, 3000 + i, true));
    }
    let big_default = PosixAcl::from_aces(aces);
    let ab = big_default.access_bytes().unwrap();
    let db = big_default.default_bytes().unwrap();
    assert!(
        fsetacl_posix(f.as_fd(), &ab, db.as_deref()).is_err(),
        "an oversized default must not be accepted"
    );
    assert_eq!(get(&f, acc), before_acc, "access widened despite the Err");
    assert_eq!(get(&f, def), before_def, "and the default moved too");

    // Now the other order: a valid default with an oversized access, so the default lands first and the access
    // write is the one that fails. The default must be put back.
    let mut aces = access_of(PosixPerm::all());
    for i in 0..400_000i64 {
        aces.push(ace(PosixTag::User, rx, 3000 + i, false));
    }
    aces.extend(default_of(PosixPerm::all()));
    let big_access = PosixAcl::from_aces(aces);
    let ab = big_access.access_bytes().unwrap();
    let db = big_access.default_bytes().unwrap();
    assert!(
        fsetacl_posix(f.as_fd(), &ab, db.as_deref()).is_err(),
        "an oversized access list must not be accepted"
    );
    assert_eq!(get(&f, acc), before_acc, "access must be untouched");
    assert_eq!(get(&f, def), before_def, "the default must be restored");
}

// copytree does not chmod a file that carries an access ACL: the ACL is authoritative for its permissions, and on a
// ZFS `aclmode=restricted` dataset a chmod of an object with a non-trivial ACL is rejected. So the ACL is copied
// faithfully, but the source's setid bits (which no ACL encodes) are not carried over. Matches `truenas_os`.
#[cfg(feature = "acl")]
#[test]
fn acl_bearing_file_is_copied_without_chmod() {
    use std::os::fd::AsFd;
    use truenas_ros::sync_fs::acl::{PosixAce, PosixAcl, PosixPerm, PosixTag, fsetacl_posix};
    use truenas_ros::sync_fs::xattr::fgetxattr;

    let ace = |tag, perms, id| PosixAce {
        tag,
        perms,
        id,
        default: false,
    };
    let rx = PosixPerm::READ | PosixPerm::EXECUTE;
    // A named user and a mask, so the ACL cannot be folded back into the mode and the xattr is really stored.
    let acl = PosixAcl::from_aces([
        ace(PosixTag::UserObj, PosixPerm::all(), -1),
        ace(PosixTag::User, rx, 1234),
        ace(PosixTag::GroupObj, rx, -1),
        ace(PosixTag::Mask, rx, -1),
        ace(PosixTag::Other, rx, -1),
    ]);

    let tmp = truenas_ros::tempdir().unwrap();
    let src = tmp.path().join("src");
    std::fs::create_dir(&src).unwrap();
    std::fs::write(src.join("helper"), b"data").unwrap();
    std::fs::set_permissions(src.join("helper"), std::fs::Permissions::from_mode(0o6755)).unwrap();
    let f = std::fs::File::open(src.join("helper")).unwrap();
    if let Err(e) = fsetacl_posix(f.as_fd(), &acl.access_bytes().unwrap(), None) {
        super::xattr_probe::posix_acl_refusal_is_allowed("fsetacl_posix", e);
        return; // no POSIX ACLs here (an NFSv4-ACL dataset, say)
    }
    let src_acl = fgetxattr(f.as_fd(), "system.posix_acl_access").unwrap();
    assert_eq!(
        std::fs::metadata(src.join("helper")).unwrap().permissions().mode() & 0o7777,
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
    // No chmod is issued for an ACL-bearing file, so the source's setid bits are not carried; the ACL governs the
    // rwx bits.
    assert_eq!(
        copied.metadata().unwrap().permissions().mode() & 0o7000,
        0,
        "an ACL-bearing file must not be chmod'd (aclmode=restricted safe)"
    );
}

// A directory's default ACL is the template its children inherit, and it is a different xattr from the access ACL.
// copy_xattrs skips the whole `system.` namespace, so if copy_permissions does not carry it, nothing does. The
// source's access ACL is left trivial on purpose: that is the branch which sets the mode and returns, and it has to
// carry the default too.
#[cfg(feature = "acl")]
#[test]
fn a_directory_default_acl_is_carried_to_the_copy() {
    use std::os::fd::AsFd;
    use truenas_ros::sync_fs::acl::{PosixAce, PosixAcl, PosixPerm, PosixTag, fsetacl_posix};
    use truenas_ros::sync_fs::xattr::fgetxattr;

    let ace = |tag, perms, id, default| PosixAce {
        tag,
        perms,
        id,
        default,
    };
    let rwx = PosixPerm::all();
    let rx = PosixPerm::READ | PosixPerm::EXECUTE;
    // Trivial access half, and a default half carrying a named user so it cannot be folded back into mode bits.
    let acl = PosixAcl::from_aces([
        ace(PosixTag::UserObj, rwx, -1, false),
        ace(PosixTag::GroupObj, rx, -1, false),
        ace(PosixTag::Other, rx, -1, false),
        ace(PosixTag::UserObj, rwx, -1, true),
        ace(PosixTag::User, rwx, 1234, true),
        ace(PosixTag::GroupObj, rx, -1, true),
        ace(PosixTag::Mask, rwx, -1, true),
        ace(PosixTag::Other, rx, -1, true),
    ]);
    let access = acl.access_bytes().unwrap();
    let default = acl.default_bytes().unwrap().unwrap();

    let tmp = truenas_ros::tempdir().unwrap();
    let src = tmp.path().join("src");
    std::fs::create_dir(&src).unwrap();
    // A nested directory too: the root gets its metadata from its own frame, everything below it on ascent.
    std::fs::create_dir(src.join("nested")).unwrap();
    std::fs::write(src.join("nested/child"), b"data").unwrap();

    for dir in [src.clone(), src.join("nested")] {
        let d = std::fs::File::open(&dir).unwrap();
        if let Err(e) = fsetacl_posix(d.as_fd(), &access, Some(&default)) {
            super::xattr_probe::posix_acl_refusal_is_allowed("fsetacl_posix", e);
            return; // no POSIX ACLs here (an NFSv4-ACL dataset, say)
        }
    }
    let d = std::fs::File::open(&src).unwrap();
    let src_default = fgetxattr(d.as_fd(), "system.posix_acl_default").unwrap();

    let dst = tmp.path().join("dst");
    copytree(&src, &dst, &CopyTreeConfig::default()).unwrap();

    for dir in [dst.clone(), dst.join("nested")] {
        let copied = std::fs::File::open(&dir).unwrap();
        assert_eq!(
            fgetxattr(copied.as_fd(), "system.posix_acl_default").unwrap(),
            src_default,
            "{dir:?} must carry the default ACL governing what its \
                 children inherit"
        );
    }
}

// The sticky bit has no ACL representation, and no chmod runs on the ACL path, so an ACL-bearing sticky directory
// arrives without S_ISVTX. The bit is given up to keep the ACL, since on ZFS a chmod rewrites the ACL to match the
// mode, and under the default aclmode=discard replaces it outright. Pinned here so the trade stays a decision.
#[cfg(feature = "acl")]
#[test]
fn an_acl_bearing_sticky_directory_arrives_without_the_sticky_bit() {
    use std::os::fd::AsFd;
    use truenas_ros::sync_fs::acl::{PosixAce, PosixAcl, PosixPerm, PosixTag, fsetacl_posix};
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

    let tmp = truenas_ros::tempdir().unwrap();
    let src = tmp.path().join("src");
    std::fs::create_dir(&src).unwrap();
    std::fs::create_dir(src.join("shared")).unwrap();
    std::fs::write(src.join("shared/f"), b"x").unwrap();
    std::fs::set_permissions(src.join("shared"), std::fs::Permissions::from_mode(0o1777)).unwrap();
    let d = std::fs::File::open(src.join("shared")).unwrap();
    if let Err(e) = fsetacl_posix(d.as_fd(), &acl.access_bytes().unwrap(), None) {
        super::xattr_probe::posix_acl_refusal_is_allowed("fsetacl_posix", e);
        return; // no POSIX ACLs here (an NFSv4-ACL dataset, say)
    }
    let src_acl = fgetxattr(d.as_fd(), "system.posix_acl_access").unwrap();
    assert_eq!(
        std::fs::metadata(src.join("shared")).unwrap().permissions().mode() & 0o1000,
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
        std::fs::metadata(dst.join("shared")).unwrap().permissions().mode() & 0o1000,
        0,
        "S_ISVTX is given up to keep the ACL intact; see copy_permissions"
    );
}

// A destination subdirectory is owner-only while its contents are written, as the destination root is, and takes
// the source's mode afterwards.
#[test]
fn subdirectory_mode_is_applied_after_its_contents() {
    let tmp = truenas_ros::tempdir().unwrap();
    let src = tmp.path().join("src");
    let dst = tmp.path().join("dst");
    std::fs::create_dir_all(src.join("sub")).unwrap();
    std::fs::write(src.join("sub/f"), b"x").unwrap();
    std::fs::set_permissions(src.join("sub"), std::fs::Permissions::from_mode(0o777)).unwrap();

    // The callback fires before each entry is copied, so when the walk reaches sub/f the destination's `sub` exists
    // but is not yet complete.
    let mut mid_copy = None;
    let cfg = CopyTreeConfig {
        reporting_increment: 1,
        ..Default::default()
    };
    copytree_reporting(&src, &dst, &cfg, &mut |p| {
        if p.current.ends_with("sub/f") {
            mid_copy = Some(std::fs::metadata(dst.join("sub")).unwrap().permissions().mode() & 0o7777);
        }
    })
    .unwrap();

    assert_eq!(mid_copy, Some(0o700), "sub was reachable mid-copy");
    assert_eq!(
        std::fs::metadata(dst.join("sub")).unwrap().permissions().mode() & 0o7777,
        0o777
    );
}

// A read-only source subdirectory must not make the destination copy of it read-only before its children exist.
#[test]
fn copies_into_read_only_subdirectory() {
    let tmp = truenas_ros::tempdir().unwrap();
    let src = tmp.path().join("src");
    let dst = tmp.path().join("dst");
    std::fs::create_dir_all(src.join("sub")).unwrap();
    std::fs::write(src.join("sub/f"), b"hi").unwrap();
    std::fs::set_permissions(src.join("sub"), std::fs::Permissions::from_mode(0o555)).unwrap();

    let res = copytree(&src, &dst, &CopyTreeConfig::default());
    let dst_mode = std::fs::metadata(dst.join("sub"))
        .ok()
        .map(|m| m.permissions().mode() & 0o7777);

    // Restore write so the tempdir cleanup can remove both trees.
    for d in [src.join("sub"), dst.join("sub")] {
        let _ = std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o755));
    }
    let stats = res.expect("read-only subdirectory should be copied into");
    assert_eq!(stats.files, 1);
    assert_eq!(std::fs::read(dst.join("sub/f")).unwrap(), b"hi");
    assert_eq!(dst_mode, Some(0o555));
}

#[test]
fn copies_tree_with_content_and_metadata() {
    let tmp = truenas_ros::tempdir().unwrap();
    let src = tmp.path().join("src");
    let dst = tmp.path().join("dst");
    std::fs::create_dir_all(src.join("sub")).unwrap();
    std::fs::write(src.join("a.txt"), b"hello").unwrap();
    std::fs::write(src.join("sub/b.bin"), vec![7u8; 4096]).unwrap();
    std::os::unix::fs::symlink("a.txt", src.join("link")).unwrap();
    std::fs::set_permissions(src.join("a.txt"), std::fs::Permissions::from_mode(0o640)).unwrap();
    let src_mtime = std::fs::metadata(src.join("a.txt")).unwrap().modified().unwrap();

    let stats = copytree(&src, &dst, &CopyTreeConfig::default()).unwrap();
    assert_eq!(stats.dirs, 1); // sub
    assert_eq!(stats.files, 2); // a.txt, sub/b.bin
    assert_eq!(stats.symlinks, 1); // link
    assert_eq!(stats.bytes, 5 + 4096);

    assert_eq!(std::fs::read(dst.join("a.txt")).unwrap(), b"hello");
    assert_eq!(std::fs::read(dst.join("sub/b.bin")).unwrap(), vec![7u8; 4096]);
    assert_eq!(
        std::fs::read_link(dst.join("link")).unwrap(),
        std::path::Path::new("a.txt")
    );
    let mode = std::fs::metadata(dst.join("a.txt")).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o640);
    let dst_mtime = std::fs::metadata(dst.join("a.txt")).unwrap().modified().unwrap();
    assert_eq!(src_mtime, dst_mtime);
}

#[test]
fn skips_metadata_when_flags_cleared() {
    use truenas_ros::sync_fs::shutil::CopyFlags;
    let tmp = truenas_ros::tempdir().unwrap();
    let src = tmp.path().join("s");
    let dst = tmp.path().join("d");
    std::fs::create_dir(&src).unwrap();
    std::fs::write(src.join("f"), b"data").unwrap();

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
    let tmp = truenas_ros::tempdir().unwrap();
    let src = tmp.path().join("src");
    std::fs::create_dir_all(src.join("d1/d2")).unwrap();
    std::fs::write(src.join("a"), b"a").unwrap();
    std::fs::write(src.join("d1/b"), b"bb").unwrap();
    std::fs::write(src.join("d1/d2/c"), b"ccc").unwrap();

    let mut calls = 0u32;
    let mut last = None;
    let cfg = CopyTreeConfig {
        reporting_increment: 1,
        ..Default::default()
    };
    let stats = copytree_reporting(&src, &tmp.path().join("out1"), &cfg, &mut |p| {
        calls += 1;
        last = Some(p.stats);
    })
    .unwrap();
    assert_eq!(stats.dirs, 2);
    assert_eq!(stats.files, 3);
    assert_eq!(stats.bytes, 6);
    assert_eq!(calls, 6, "5 entries at increment 1, plus the final call");
    assert_eq!(last.unwrap(), stats, "final call carries completed stats");

    let mut calls0 = 0u32;
    let cfg0 = CopyTreeConfig {
        reporting_increment: 0,
        ..Default::default()
    };
    copytree_reporting(&src, &tmp.path().join("out2"), &cfg0, &mut |_| calls0 += 1).unwrap();
    assert_eq!(calls0, 1, "only the final call fires when increment is 0");
}

#[test]
fn traverse_without_child_mounts_matches_plain_copy() {
    let tmp = truenas_ros::tempdir().unwrap();
    let src = tmp.path().join("src");
    std::fs::create_dir_all(src.join("sub")).unwrap();
    std::fs::write(src.join("sub/f"), b"x").unwrap();
    std::fs::write(src.join("g"), b"yy").unwrap();

    let plain = copytree(&src, &tmp.path().join("d1"), &CopyTreeConfig::default()).unwrap();
    let cfg = CopyTreeConfig {
        traverse: true,
        ..Default::default()
    };
    let trav = copytree(&src, &tmp.path().join("d2"), &cfg).unwrap();
    assert_eq!(plain, trav);
    assert_eq!(trav.dirs, 1);
    assert_eq!(trav.files, 2);
}

#[test]
fn traverse_copies_child_mount() {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use truenas_ros::libc;

    let tmp = truenas_ros::tempdir().unwrap();
    let src = tmp.path().join("src");
    let dst = tmp.path().join("dst");
    std::fs::create_dir_all(src.join("child")).unwrap();
    std::fs::write(src.join("top"), b"top").unwrap();

    let target = src.join("child");
    let ctarget = CString::new(target.as_os_str().as_bytes()).unwrap();
    let tmpfs = CString::new("tmpfs").unwrap();
    let rc = unsafe { libc::mount(tmpfs.as_ptr(), ctarget.as_ptr(), tmpfs.as_ptr(), 0, std::ptr::null()) };
    if rc != 0 {
        return; // unprivileged sandbox -> EPERM
    }
    // Lazy-unmount on the way out, even on panic, before the tempdir is removed.
    struct Unmount(CString);
    impl Drop for Unmount {
        fn drop(&mut self) {
            unsafe { libc::umount2(self.0.as_ptr(), libc::MNT_DETACH) };
        }
    }
    let _guard = Unmount(ctarget.clone());

    std::fs::write(target.join("inner"), b"inner-data").unwrap();
    // The destination child directory must already exist (opened, not created) so the data lands on the intended
    // mount.
    std::fs::create_dir_all(dst.join("child")).unwrap();

    let cfg = CopyTreeConfig {
        traverse: true,
        ..Default::default()
    };
    let stats = copytree(&src, &dst, &cfg).unwrap();

    assert_eq!(std::fs::read(dst.join("top")).unwrap(), b"top");
    assert_eq!(std::fs::read(dst.join("child/inner")).unwrap(), b"inner-data");
    // Primary pass copied `top`; the traverse pass copied the mount's file.
    assert_eq!(stats.files, 2);
}

// A source file the copier cannot read fails the copy; it must not be left out of the destination under a
// successful return.
#[test]
fn unreadable_source_file_fails_the_copy() {
    // CAP_DAC_OVERRIDE reads it regardless of the mode.
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let tmp = truenas_ros::tempdir().unwrap();
    let src = tmp.path().join("src");
    let dst = tmp.path().join("dst");
    std::fs::create_dir(&src).unwrap();
    std::fs::write(src.join("secret"), b"data").unwrap();
    std::fs::set_permissions(src.join("secret"), std::fs::Permissions::from_mode(0o000)).unwrap();

    let err = copytree(&src, &dst, &CopyTreeConfig::default()).unwrap_err();
    assert!(
        matches!(err, Error::Errno(Errno::EACCES | Errno::EPERM)),
        "unexpected error: {err:?}"
    );
    assert!(!dst.join("secret").exists());
}
