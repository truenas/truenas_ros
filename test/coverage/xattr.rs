use std::os::fd::AsFd;
use truenas_ros::errno::Errno;
use truenas_ros::sync_fs::xattr::{XATTR_SIZE_MAX, XattrFlags, fgetxattr, flistxattr, fremovexattr, fsetxattr};

fn tmp() -> (truenas_ros::TempDir, std::fs::File) {
    let dir = truenas_ros::tempdir().unwrap();
    let path = dir.path().join("f");
    std::fs::write(&path, b"d").unwrap();
    let f = std::fs::OpenOptions::new().read(true).write(true).open(&path).unwrap();
    (dir, f)
}

fn user_xattrs_supported(f: &std::fs::File) -> bool {
    match fsetxattr(f.as_fd(), "user.probe", b"1", XattrFlags::empty()) {
        Ok(()) => {
            let _ = fremovexattr(f.as_fd(), "user.probe");
            true
        }
        Err(Errno::EOPNOTSUPP) => {
            // Everything behind this probe is about to be skipped.
            super::xattr_probe::refusal_is_allowed("fsetxattr(user.probe)", Errno::EOPNOTSUPP);
            false
        }
        Err(e) => panic!("probe: {e}"),
    }
}

#[test]
fn size_max_constant() {
    assert_eq!(XATTR_SIZE_MAX, 2 * 1024 * 1024);
}

#[test]
fn remove_and_create_replace_semantics() {
    let (_d, f) = tmp();
    if !user_xattrs_supported(&f) {
        return;
    }
    let n = "user.tn";
    fsetxattr(f.as_fd(), n, b"v1", XattrFlags::XATTR_CREATE).unwrap();
    // CREATE again -> EEXIST, value unchanged.
    assert_eq!(
        fsetxattr(f.as_fd(), n, b"v2", XattrFlags::XATTR_CREATE).unwrap_err(),
        Errno::EEXIST
    );
    assert_eq!(fgetxattr(f.as_fd(), n).unwrap(), b"v1");
    // REPLACE existing -> ok; REPLACE missing -> ENODATA.
    fsetxattr(f.as_fd(), n, b"v3", XattrFlags::XATTR_REPLACE).unwrap();
    assert_eq!(fgetxattr(f.as_fd(), n).unwrap(), b"v3");
    assert_eq!(
        fsetxattr(f.as_fd(), "user.absent", b"x", XattrFlags::XATTR_REPLACE).unwrap_err(),
        Errno::ENODATA
    );
    // Remove, then get / re-remove both -> ENODATA.
    fremovexattr(f.as_fd(), n).unwrap();
    assert_eq!(fgetxattr(f.as_fd(), n).unwrap_err(), Errno::ENODATA);
    assert_eq!(fremovexattr(f.as_fd(), n).unwrap_err(), Errno::ENODATA);
}

#[test]
fn oversize_short_circuits_to_e2big() {
    let (_d, f) = tmp();
    // Rejected before any syscall, so filesystem support is irrelevant.
    let big = vec![0u8; XATTR_SIZE_MAX + 1];
    assert_eq!(
        fsetxattr(f.as_fd(), "user.big", &big, XattrFlags::empty()).unwrap_err(),
        Errno::E2BIG
    );
}

#[test]
fn large_value_exercises_buffer_growth() {
    let (_d, f) = tmp();
    if !user_xattrs_supported(&f) {
        return;
    }
    let val = vec![7u8; 4096];
    match fsetxattr(f.as_fd(), "user.big", &val, XattrFlags::empty()) {
        Ok(()) => {
            assert_eq!(fgetxattr(f.as_fd(), "user.big").unwrap(), val);
            assert!(
                flistxattr(f.as_fd())
                    .unwrap()
                    .iter()
                    .any(|s| s.as_bytes() == b"user.big")
            );
        }
        // Some filesystems impose a smaller per-value limit.
        Err(Errno::E2BIG | Errno::ENOSPC) => {}
        Err(e) => panic!("{e}"),
    }
}
