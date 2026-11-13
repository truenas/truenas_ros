use std::os::fd::AsFd;
use truenas_ros::errno::Errno;
use truenas_ros::sync_fs::fhandle::{FhFlags, FileHandle, name_to_handle_at};
use truenas_ros::sync_fs::{AtFlags, OFlag, StatxMask, statx};
use truenas_ros::{AT_FDCWD, Error};

/// Hold a file-handle refusal to `TRUENAS_ROS_REQUIRE_FHANDLE`.
///
/// Two distinct causes end this test early - a filesystem that cannot encode a handle, and a caller without
/// `CAP_DAC_READ_SEARCH` for `open_by_handle_at` (`may_decode_fh`, fs/fhandle.c) - and both leave the reopen
/// unasserted. Only this test and one on ZFS in `test/uring_fs.rs` call that syscall, so an ungated skip here
/// leaves the path off ZFS covered nowhere.
#[track_caller]
fn refusal_is_allowed(what: &str, err: impl std::fmt::Display) {
    assert!(
        std::env::var_os("TRUENAS_ROS_REQUIRE_FHANDLE").is_none(),
        "TRUENAS_ROS_REQUIRE_FHANDLE is set but {what}: {err}"
    );
}

#[test]
fn name_to_handle_roundtrip_and_reopen() {
    let dir = truenas_ros::tempdir().unwrap();
    let path = dir.path().join("file");
    std::fs::write(&path, b"handle me").unwrap();

    let handle = match name_to_handle_at(AT_FDCWD, &path, FhFlags::AT_HANDLE_MNT_ID_UNIQUE) {
        Ok(h) => h,
        Err(Error::Errno(Errno::EOPNOTSUPP)) => {
            // Filesystem cannot encode handles here; skip.
            refusal_is_allowed("name_to_handle_at", Errno::EOPNOTSUPP);
            return;
        }
        Err(e) => panic!("name_to_handle_at: {e}"),
    };

    // Serialize / deserialize is byte-exact; mount id is carried alongside.
    let bytes = handle.to_bytes();
    let rebuilt = FileHandle::from_bytes(&bytes, handle.mount_id(), handle.unique_mount_id()).unwrap();
    assert_eq!(rebuilt.to_bytes(), bytes);

    let ino = statx(AT_FDCWD, &path, AtFlags::empty(), StatxMask::INO).unwrap().ino();

    // Re-open via a mount fd (the containing directory) and confirm it is the same inode. open_by_handle_at needs
    // CAP_DAC_READ_SEARCH.
    let mount_fd = std::fs::File::open(dir.path()).unwrap();
    match rebuilt.open(mount_fd.as_fd(), OFlag::O_RDONLY) {
        Ok(opened) => {
            let st = statx(opened.as_fd(), "", AtFlags::AT_EMPTY_PATH, StatxMask::INO).unwrap();
            assert_eq!(st.ino(), ino);
        }
        // open_by_handle_at needs CAP_DAC_READ_SEARCH and is often blocked by a container seccomp filter (ENOSYS);
        // both are environmental. This arm discards the only reopen assertion the tree has, so it answers to the
        // gate rather than passing quietly.
        Err(Error::Errno(e @ (Errno::EPERM | Errno::EACCES | Errno::ENOSYS))) => {
            refusal_is_allowed("open_by_handle_at", e)
        }
        Err(e) => panic!("open_by_handle_at: {e}"),
    }
}

#[test]
fn from_bytes_rejects_short_buffer() {
    let err = FileHandle::from_bytes(&[0u8; 4], 1, false).unwrap_err();
    assert!(matches!(err, Error::Validation(_)));
}
