use std::io::Write;
use truenas_ros::errno::Errno;
use truenas_ros::sync_fs::{AtomicWriteOptions, Mode, OFlag, atomic_replace, atomic_write, safe_open};
use truenas_ros::{AT_FDCWD, Error};

#[test]
fn atomic_replace_creates_replaces_and_leaves_no_temp() {
    let dir = truenas_ros::tempdir().unwrap();
    let target = dir.path().join("config");

    atomic_replace(&target, b"v1", AtomicWriteOptions::default()).unwrap();
    assert_eq!(std::fs::read(&target).unwrap(), b"v1");

    // Replacing an existing file uses RENAME_EXCHANGE (atomic).
    atomic_replace(&target, b"version two", AtomicWriteOptions::default()).unwrap();
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
    let dir = truenas_ros::tempdir().unwrap();
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
    let dir = truenas_ros::tempdir().unwrap();
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
    let dir = truenas_ros::tempdir().unwrap();
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
    let dir = truenas_ros::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("real")).unwrap();
    std::fs::write(dir.path().join("real/file"), b"x").unwrap();
    std::os::unix::fs::symlink("real", dir.path().join("link")).unwrap();

    let via_link = dir.path().join("link/file");
    let err = safe_open(AT_FDCWD, &via_link, OFlag::O_RDONLY, Mode::empty()).unwrap_err();
    assert!(matches!(err, Error::SymlinkInPath { .. }));
}
