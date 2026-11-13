use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use truenas_ros::errno::Errno;
use truenas_ros::sync_fs::{AtomicWriteOptions, Mode, OFlag, atomic_replace, atomic_write, safe_open};
use truenas_ros::{AT_FDCWD, Error};

#[test]
fn atomic_write_sets_mode_and_preserves_owner() {
    let dir = truenas_ros::tempdir().unwrap();
    let target = dir.path().join("cfg");
    let (uid, gid) = unsafe { (libc::getuid() as u32, libc::getgid() as u32) };
    let opts = AtomicWriteOptions {
        uid: Some(uid),
        gid: Some(gid),
        mode: 0o600,
        noclobber: false,
    };
    atomic_replace(&target, b"secret", opts).unwrap();
    let md = std::fs::metadata(&target).unwrap();
    assert_eq!(md.permissions().mode() & 0o777, 0o600);
    assert_eq!(md.uid(), uid);
    assert_eq!(md.gid(), gid);
    assert_eq!(std::fs::read(&target).unwrap(), b"secret");
}

#[test]
fn failed_write_leaves_target_and_no_temp() {
    let dir = truenas_ros::tempdir().unwrap();
    let target = dir.path().join("cfg");
    atomic_replace(&target, b"original", AtomicWriteOptions::default()).unwrap();
    let err = atomic_write(&target, AtomicWriteOptions::default(), |f| {
        f.write_all(b"partial")?;
        Err(std::io::Error::other("boom"))
    })
    .unwrap_err();
    assert!(matches!(err, Error::Errno(_)));
    assert_eq!(std::fs::read(&target).unwrap(), b"original");
    let leftovers: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .filter(|n| n != "cfg")
        .collect();
    assert!(leftovers.is_empty(), "temp left: {leftovers:?}");
}

#[test]
fn noclobber_creates_new_but_refuses_existing() {
    let dir = truenas_ros::tempdir().unwrap();
    let target = dir.path().join("once");
    let opts = AtomicWriteOptions {
        noclobber: true,
        ..Default::default()
    };
    atomic_replace(&target, b"v1", opts).unwrap();
    assert_eq!(std::fs::read(&target).unwrap(), b"v1");
    assert!(matches!(
        atomic_replace(&target, b"v2", opts).unwrap_err(),
        Error::Errno(Errno::EEXIST)
    ));
    assert_eq!(std::fs::read(&target).unwrap(), b"v1");
}

#[test]
fn rejects_target_without_file_name() {
    assert!(matches!(
        atomic_replace(std::path::Path::new("/"), b"x", AtomicWriteOptions::default()),
        Err(Error::Validation(_))
    ));
}

#[test]
fn safe_open_returns_usable_file() {
    let dir = truenas_ros::tempdir().unwrap();
    let p = dir.path().join("f");
    std::fs::write(&p, b"hello world").unwrap();
    let mut f = safe_open(AT_FDCWD, &p, OFlag::O_RDONLY, Mode::empty()).unwrap();
    let mut s = String::new();
    f.read_to_string(&mut s).unwrap();
    assert_eq!(s, "hello world");
}

#[test]
fn safe_open_creates_a_file() {
    let dir = truenas_ros::tempdir().unwrap();
    let p = dir.path().join("new");
    let mut f = safe_open(
        AT_FDCWD,
        &p,
        OFlag::O_CREAT | OFlag::O_WRONLY,
        Mode::S_IRUSR | Mode::S_IWUSR,
    )
    .unwrap();
    f.write_all(b"data").unwrap();
    drop(f);
    assert_eq!(std::fs::read(&p).unwrap(), b"data");
}

#[test]
fn safe_open_propagates_other_errors() {
    let dir = truenas_ros::tempdir().unwrap();
    let missing = dir.path().join("nope");
    assert!(safe_open(AT_FDCWD, &missing, OFlag::O_RDONLY, Mode::empty()).is_err());
}
