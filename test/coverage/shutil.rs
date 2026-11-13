use std::os::fd::AsFd;
use std::os::unix::fs::PermissionsExt;
use truenas_ros::errno::Errno;
use truenas_ros::sync_fs::shutil::{
    CopyFlags, CopyTreeConfig, CopyTreeOp, MAX_RW_SZ, clonefile, copy_permissions, copy_setid, copy_xattrs, copyfile,
    copysendfile, copytree, copyuserspace,
};

/// A source/destination pair on a **ZFS dataset**, or `None` to skip.
///
/// For the clone path only: tmpfs serves `copy_file_range` as a plain copy, so a tempdir fixture passes without
/// ever reaching the block clone (`zfs_clone_range`) that ships. The other copy helpers here are
/// filesystem-agnostic and keep the tempdir `pair`.
#[allow(clippy::type_complexity)]
fn zfs_pair(src: &[u8]) -> Option<(std::path::PathBuf, std::fs::File, std::fs::File)> {
    let ds = super::zfs_dir::zfs_dir_or_skip()?;
    let s = ds.join("clone_src");
    let d = ds.join("clone_dst");
    std::fs::write(&s, src).unwrap();
    let sf = std::fs::File::open(&s).unwrap();
    let df = std::fs::File::create(&d).unwrap();
    Some((ds, sf, df))
}

fn pair(src: &[u8]) -> (truenas_ros::TempDir, std::fs::File, std::fs::File) {
    let dir = truenas_ros::tempdir().unwrap();
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
    assert_eq!(std::fs::read(dir.path().join("d")).unwrap(), b"hello world");
    let (_d2, s2, d2) = pair(b"");
    assert_eq!(copyuserspace(s2.as_fd(), d2.as_fd()).unwrap(), 0);
}

#[test]
fn copysendfile_copies_and_empty_falls_back() {
    let (dir, s, d) = pair(b"abcdef");
    assert_eq!(copysendfile(s.as_fd(), d.as_fd()).unwrap(), 6);
    drop(d);
    assert_eq!(std::fs::read(dir.path().join("d")).unwrap(), b"abcdef");
    // Empty source: sendfile transfers nothing -> userspace fallback -> 0.
    let (_d2, s2, d2) = pair(b"");
    assert_eq!(copysendfile(s2.as_fd(), d2.as_fd()).unwrap(), 0);
}

/// The clone half runs on a ZFS dataset, the only place it is the code under test. `EXDEV` stays tolerated, since files
/// on different filesystems cannot clone, but on a dataset an unsupported answer is a regression.
#[test]
fn clonefile_clones_on_a_dataset() {
    let Some((ds, s, d)) = zfs_pair(b"clone me") else {
        return;
    };
    match clonefile(s.as_fd(), d.as_fd()) {
        Ok(n) => {
            assert_eq!(n, 8);
            drop(d);
            assert_eq!(std::fs::read(ds.join("clone_dst")).unwrap(), b"clone me");
        }
        Err(Errno::EXDEV) => {}
        Err(e) => panic!("clonefile on a ZFS dataset: {e}"),
    }
    let _ = std::fs::remove_file(ds.join("clone_src"));
    let _ = std::fs::remove_file(ds.join("clone_dst"));
}

/// `copyfile` lands the content whichever path it takes, so this half is filesystem-agnostic and keeps the tempdir
/// fixture.
#[test]
fn copyfile_lands_the_content() {
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
fn copy_permissions_withholds_setid_for_copy_setid() {
    let mode = |f: &std::fs::File| f.metadata().unwrap().permissions().mode();
    let (_dir, s, d) = pair(b"x");
    // copy_permissions applies the rwx bits but withholds setid.
    copy_permissions(s.as_fd(), d.as_fd(), &[], 0o104755).unwrap();
    assert_eq!(mode(&d) & 0o7777, 0o755);
    // copy_setid does nothing when the source has no setid bits...
    copy_setid(d.as_fd(), &[], 0o100755).unwrap();
    assert_eq!(mode(&d) & 0o7777, 0o755);
    // ...leaves an ACL-backed destination alone (the ACL governs mode)...
    let acl = vec![c"system.posix_acl_access".to_owned()];
    copy_setid(d.as_fd(), &acl, 0o104755).unwrap();
    assert_eq!(mode(&d) & 0o7777, 0o755);
    // ...and otherwise applies them.
    copy_setid(d.as_fd(), &[], 0o104755).unwrap();
    assert_eq!(mode(&d) & 0o7777, 0o4755);
}

#[test]
fn copy_xattrs_skips_acl_and_system() {
    use truenas_ros::sync_fs::xattr::{XattrFlags, fgetxattr, fsetxattr};
    let dir = truenas_ros::tempdir().unwrap();
    std::fs::write(dir.path().join("s"), b"x").unwrap();
    let s = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(dir.path().join("s"))
        .unwrap();
    let d = std::fs::File::create(dir.path().join("d")).unwrap();
    if let Err(e) = fsetxattr(s.as_fd(), "user.keep", b"v", XattrFlags::empty()) {
        // Every assertion below is behind this probe, so the refusal is held to the same gate as its sibling in
        // `xattr::` rather than returning silently.
        super::xattr_probe::refusal_is_allowed("fsetxattr(user.keep)", e);
        return; // user xattrs unsupported here
    }
    // A system/ACL name in the list must be skipped without error.
    let names = vec![c"user.keep".to_owned(), c"system.posix_acl_access".to_owned()];
    copy_xattrs(s.as_fd(), d.as_fd(), &names).unwrap();
    assert_eq!(fgetxattr(d.as_fd(), "user.keep").unwrap(), b"v");
    assert!(fgetxattr(d.as_fd(), "system.posix_acl_access").is_err());
}

#[test]
fn copytree_op_variants_and_exist_ok() {
    for op in [CopyTreeOp::Default, CopyTreeOp::Sendfile, CopyTreeOp::Userspace] {
        let tmp = truenas_ros::tempdir().unwrap();
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
        // exist_ok = false on an existing destination -> error.
        assert!(
            copytree(
                &src,
                &dst,
                &CopyTreeConfig {
                    exist_ok: false,
                    ..Default::default()
                }
            )
            .is_err()
        );
    }
}

/// A re-run or incremental copy must leave the destination looking like the source, whatever was at the name first.
///
/// A symlink with a different target, or an entry of a different type, is replaced rather than kept while `copytree`
/// reports it copied.
#[test]
fn copytree_replaces_a_taken_symlink_or_special() {
    let tmp = truenas_ros::tempdir().unwrap();
    let src = tmp.path().join("src");
    let dst = tmp.path().join("dst");
    std::fs::create_dir(&src).unwrap();
    std::fs::write(src.join("real"), b"NEW").unwrap();
    std::os::unix::fs::symlink("real", src.join("link")).unwrap();
    mkfifo(&src.join("pipe"));

    // A destination that already has all three names taken, two of them by the wrong kind of object.
    std::fs::create_dir(&dst).unwrap();
    std::fs::write(dst.join("other"), b"OLD").unwrap();
    std::os::unix::fs::symlink("other", dst.join("link")).unwrap();
    std::fs::write(dst.join("pipe"), b"PLANTED").unwrap();

    let stats = copytree(&src, &dst, &CopyTreeConfig::default()).unwrap();
    assert_eq!(stats.symlinks, 1);
    assert_eq!(stats.specials, 1);
    assert_eq!(
        std::fs::read_link(dst.join("link")).unwrap(),
        std::path::Path::new("real"),
        "the destination kept a link pointing somewhere else"
    );
    assert_eq!(std::fs::read(dst.join("link")).unwrap(), b"NEW");
    let m = std::fs::symlink_metadata(dst.join("pipe")).unwrap();
    assert!(
        std::os::unix::fs::FileTypeExt::is_fifo(&m.file_type()),
        "a regular file survived a FIFO source, mode {:o}",
        m.permissions().mode()
    );
}

/// A copy that fails must leave a *borrowed* destination root at the mode it found.
///
/// copytree narrows a pre-existing root to 0o700 while it writes, so group and other cannot reach half-written files. A
/// failure must put the recorded mode back, or every non-owner identity stays locked out of the destination.
#[test]
fn a_failed_copytree_puts_a_borrowed_root_s_mode_back() {
    let tmp = truenas_ros::tempdir().unwrap();
    let src = tmp.path().join("src");
    let dst = tmp.path().join("dst");
    std::fs::create_dir_all(src.join("sub")).unwrap();
    std::fs::write(src.join("sub/f"), b"x").unwrap();

    // A destination this copy did not create, and is only borrowing.
    std::fs::create_dir(&dst).unwrap();
    std::fs::set_permissions(&dst, std::fs::Permissions::from_mode(0o755)).unwrap();
    // A regular file where the source has a directory: `make_dir` swallows the `EEXIST` under `exist_ok` and the
    // `O_DIRECTORY` open behind it answers `ENOTDIR`, which is a copy that fails after the root has been narrowed.
    std::fs::write(dst.join("sub"), b"in the way").unwrap();

    let err = copytree(&src, &dst, &CopyTreeConfig::default()).expect_err("the copy must fail");
    assert!(
        matches!(err, truenas_ros::Error::Errno(Errno::ENOTDIR)),
        "unexpected failure: {err:?}"
    );
    assert_eq!(
        std::fs::metadata(&dst).unwrap().permissions().mode() & 0o7777,
        0o755,
        "a borrowed destination root was left narrowed"
    );

    // The control: a copy that succeeds ends at the source root's mode, which is what `finish_dir` stamps.
    std::fs::remove_file(dst.join("sub")).unwrap();
    copytree(&src, &dst, &CopyTreeConfig::default()).unwrap();
    assert_eq!(
        std::fs::metadata(&dst).unwrap().permissions().mode() & 0o7777,
        std::fs::metadata(&src).unwrap().permissions().mode() & 0o7777,
    );
}

fn mkfifo(p: &std::path::Path) {
    let c = std::ffi::CString::new(p.as_os_str().as_encoded_bytes()).unwrap();
    // SAFETY: a NUL-terminated path this test owns.
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0, "mkfifo");
}

#[test]
fn copytree_permissions_only_flag() {
    let tmp = truenas_ros::tempdir().unwrap();
    let src = tmp.path().join("src");
    let dst = tmp.path().join("dst");
    std::fs::create_dir(&src).unwrap();
    std::fs::write(src.join("f"), b"x").unwrap();
    std::fs::set_permissions(src.join("f"), std::fs::Permissions::from_mode(0o640)).unwrap();
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
        std::fs::metadata(dst.join("f")).unwrap().permissions().mode() & 0o777,
        0o640
    );
}

#[test]
fn copytree_defers_root_metadata_so_children_are_creatable() {
    // The destination root's permissions are applied after the walk, or a read-only source root would make it
    // unwritable before its children are created.
    let tmp = truenas_ros::tempdir().unwrap();
    let src = tmp.path().join("src");
    let dst = tmp.path().join("dst");
    std::fs::create_dir(&src).unwrap();
    std::fs::write(src.join("child"), b"hi").unwrap();
    std::fs::set_permissions(&src, std::fs::Permissions::from_mode(0o555)).unwrap();

    let config = CopyTreeConfig {
        flags: CopyFlags::PERMISSIONS,
        ..Default::default()
    };
    let res = copytree(&src, &dst, &config);

    // Restore write so the tempdir cleanup can remove the tree.
    let _ = std::fs::set_permissions(&src, std::fs::Permissions::from_mode(0o755));

    let stats = res.expect("read-only-rooted copytree should succeed");
    assert_eq!(stats.files, 1);
    assert_eq!(std::fs::read(dst.join("child")).unwrap(), b"hi");
    // The root's restrictive mode is still applied - just last.
    assert_eq!(std::fs::metadata(&dst).unwrap().permissions().mode() & 0o777, 0o555);
    let _ = std::fs::set_permissions(&dst, std::fs::Permissions::from_mode(0o755));
}
