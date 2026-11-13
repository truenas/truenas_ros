use std::os::fd::AsFd;
use truenas_ros::errno::Errno;
use truenas_ros::sync_fs::OFlag;
use truenas_ros::sync_fs::fhandle::{FhFlags, FileHandle, name_to_handle_at};
use truenas_ros::{AT_FDCWD, Error};

#[test]
fn from_bytes_validates_lengths() {
    assert!(matches!(
        FileHandle::from_bytes(&[0u8; 4], 1, false),
        Err(Error::Validation(_))
    ));
    assert!(matches!(
        FileHandle::from_bytes(&[0u8; 200], 1, false),
        Err(Error::Validation(_))
    ));
    // handle_bytes = 100 but no data follows.
    let mut buf = vec![0u8; 8];
    buf[0] = 100;
    assert!(matches!(
        FileHandle::from_bytes(&buf, 1, false),
        Err(Error::Validation(_))
    ));
}

#[test]
fn accessors_and_bytes_roundtrip() {
    let h = FileHandle::from_bytes(&[0u8; 8], 42, true).unwrap();
    assert_eq!(h.mount_id(), 42);
    assert!(h.unique_mount_id());
    assert_eq!(h.to_bytes(), vec![0u8; 8]);
    assert!(!FileHandle::from_bytes(&[0u8; 8], 42, false).unwrap().unique_mount_id());
}

#[test]
fn open_uninitialised_is_rejected() {
    // u64::MAX is the uninitialised sentinel.
    let h = FileHandle::from_bytes(&[0u8; 8], u64::MAX, true).unwrap();
    let root = std::fs::File::open("/").unwrap();
    assert!(matches!(
        h.open(root.as_fd(), OFlag::O_RDONLY),
        Err(Error::Validation(_))
    ));
}

#[test]
fn open_wrong_mount_id_is_rejected() {
    let h = FileHandle::from_bytes(&[0u8; 8], 1, true).unwrap();
    let root = std::fs::File::open("/").unwrap();
    match h.open(root.as_fd(), OFlag::O_RDONLY) {
        // Mount-id mismatch (expected), or a fluke match then a syscall errno (e.g. seccomp ENOSYS) - never
        // success.
        Err(Error::Validation(_)) | Err(Error::Errno(_)) => {}
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn name_to_handle_nonexistent_path() {
    assert!(matches!(
        name_to_handle_at(AT_FDCWD, "/no/such/path/xyz", FhFlags::AT_HANDLE_MNT_ID_UNIQUE).unwrap_err(),
        Error::Errno(Errno::ENOENT)
    ));
}

#[test]
fn different_paths_yield_different_handles() {
    let dir = truenas_ros::tempdir().unwrap();
    let a = dir.path().join("a");
    let b = dir.path().join("b");
    std::fs::write(&a, b"a").unwrap();
    std::fs::write(&b, b"b").unwrap();
    let ha = match name_to_handle_at(AT_FDCWD, &a, FhFlags::AT_HANDLE_MNT_ID_UNIQUE) {
        Ok(h) => h,
        Err(Error::Errno(Errno::EOPNOTSUPP)) => {
            // The fs cannot encode handles; the codec assertions below are about to be skipped, so answer to the
            // gate.
            assert!(
                std::env::var_os("TRUENAS_ROS_REQUIRE_FHANDLE").is_none(),
                "TRUENAS_ROS_REQUIRE_FHANDLE is set but \
                     name_to_handle_at: EOPNOTSUPP"
            );
            return;
        }
        Err(e) => panic!("{e}"),
    };
    let hb = name_to_handle_at(AT_FDCWD, &b, FhFlags::AT_HANDLE_MNT_ID_UNIQUE).unwrap();
    assert_ne!(ha.to_bytes(), hb.to_bytes());
    assert_eq!(ha.mount_id(), hb.mount_id());
}
