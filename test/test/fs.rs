use std::os::fd::AsFd;
use truenas_ros::AT_FDCWD;
use truenas_ros::errno::Errno;
use truenas_ros::sync_fs::{AtFlags, OFlag, OpenHow, RenameFlags, ResolveFlag, StatxMask, openat2, renameat2, statx};

#[test]
fn statx_dot_is_a_directory() {
    let st = statx(AT_FDCWD, ".", AtFlags::empty(), StatxMask::BASIC_STATS).expect("statx . failed");
    assert!(st.is_dir());
    assert!(st.mask().contains(StatxMask::MODE));
}

#[test]
fn openat2_then_statx_by_fd() {
    let dir = truenas_ros::tempdir().unwrap();
    let path = dir.path().join("file");
    std::fs::write(&path, b"hello").unwrap();

    let how = OpenHow::new()
        .flags(OFlag::O_RDONLY)
        .resolve(ResolveFlag::RESOLVE_NO_SYMLINKS);
    let fd = openat2(AT_FDCWD, &path, how).expect("openat2 failed");

    let st = statx(fd.as_fd(), "", AtFlags::AT_EMPTY_PATH, StatxMask::BASIC_STATS).expect("statx by fd failed");
    assert!(st.is_regular());
    assert_eq!(st.size(), 5);
}

#[test]
fn openat2_no_symlinks_rejects_symlink() {
    let dir = truenas_ros::tempdir().unwrap();
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

/// Names are single components against a dirfd, which is what the component screen requires: `renameat2` honours no
/// `RESOLVE_*` flags, so a multi-component path would resolve every component but the last with symlinks followed.
#[test]
fn renameat2_noreplace_and_exchange() {
    let dir = truenas_ros::tempdir().unwrap();
    let a = dir.path().join("a");
    let b = dir.path().join("b");
    std::fs::write(&a, b"aaa").unwrap();
    std::fs::write(&b, b"bbb").unwrap();
    let at = openat2(
        AT_FDCWD,
        dir.path(),
        OpenHow::new().flags(OFlag::O_DIRECTORY | OFlag::O_CLOEXEC),
    )
    .expect("open the directory");
    let at = at.as_fd();

    // NOREPLACE must fail because `b` already exists.
    let err = renameat2(at, "a", at, "b", RenameFlags::RENAME_NOREPLACE).unwrap_err();
    assert_eq!(err, Errno::EEXIST);

    // EXCHANGE swaps the two files atomically.
    renameat2(at, "a", at, "b", RenameFlags::RENAME_EXCHANGE).expect("exchange failed");
    assert_eq!(std::fs::read(&a).unwrap(), b"bbb");
    assert_eq!(std::fs::read(&b).unwrap(), b"aaa");

    // And a multi-component name is refused rather than resolved.
    assert_eq!(
        renameat2(at, "a", at, "sub/b", RenameFlags::empty()).unwrap_err(),
        Errno::EINVAL
    );
}
