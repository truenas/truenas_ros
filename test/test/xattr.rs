use std::os::fd::AsFd;
use truenas_ros::errno::Errno;
use truenas_ros::sync_fs::xattr::{XattrFlags, fgetxattr, flistxattr, fsetxattr};

#[test]
fn set_get_list_roundtrip() {
    let dir = truenas_ros::tempdir().unwrap();
    let path = dir.path().join("file");
    std::fs::write(&path, b"data").unwrap();
    let file = std::fs::OpenOptions::new().read(true).write(true).open(&path).unwrap();
    let name = "user.truenas_ros_test";

    match fsetxattr(file.as_fd(), name, b"value", XattrFlags::empty()) {
        Ok(()) => {
            let got = fgetxattr(file.as_fd(), name).unwrap();
            assert_eq!(got, b"value");
            // A small value must not carry the 4096-byte first-read buffer out with it.
            assert_eq!(
                got.capacity(),
                got.len(),
                "the probe buffer was retained behind the value"
            );
            let names = flistxattr(file.as_fd()).unwrap();
            assert!(names.iter().any(|n| n.as_bytes() == name.as_bytes()));
            // A value past the first-read buffer (4096): the read answers ERANGE and the refetch must return it
            // intact, not truncated to the initial buffer.
            let big = vec![0xabu8; 6000];
            if fsetxattr(file.as_fd(), name, &big, XattrFlags::empty()).is_ok() {
                assert_eq!(fgetxattr(file.as_fd(), name).unwrap(), big);
            }
        }
        // Some filesystems (e.g. certain tmpfs configs) reject user xattrs. That is "not applicable" rather than a
        // failure - but it skips every assertion above, so where CI arms the gate it is a failure instead.
        Err(Errno::EOPNOTSUPP) => {
            super::xattr_probe::refusal_is_allowed("fsetxattr(user.truenas_ros_test)", Errno::EOPNOTSUPP)
        }
        Err(e) => panic!("fsetxattr failed unexpectedly: {e}"),
    }
}

/// A name list larger than the initial buffer has to come back whole.
///
/// `flistxattr` starts with 256 bytes and regrows on `ERANGE`, so the fixture has to outgrow the first buffer for
/// the regrow to run at all. A truncated list is not an error to any caller - it is a *shorter* list, and
/// `shutil::copy_permissions` reads exactly that list to decide whether the file carries an access ACL. Drop
/// `system.posix_acl_access` from it and the copy takes the `fchmod` branch instead of transporting the ACL, which
/// on ZFS rewrites or discards it (`zfs_acl_chmod_setattr`) - the outcome the no-fchmod decision exists to prevent.
#[test]
fn a_name_list_past_the_first_buffer_comes_back_whole() {
    use std::os::fd::AsFd;
    let dir = truenas_ros::tempdir().unwrap();
    let path = dir.path().join("many");
    std::fs::write(&path, b"x").unwrap();
    let file = std::fs::OpenOptions::new().read(true).write(true).open(&path).unwrap();

    // 20 names of ~26 bytes each: well past the 256-byte first try, well inside any filesystem's per-inode xattr
    // room.
    let mut want: Vec<String> = Vec::new();
    for i in 0..20 {
        let name = format!("user.padding_name_{i:02}");
        match fsetxattr(file.as_fd(), name.as_str(), b"", XattrFlags::empty()) {
            Ok(()) => want.push(name),
            Err(Errno::EOPNOTSUPP) => {
                super::xattr_probe::refusal_is_allowed("fsetxattr(user.padding_name_*)", Errno::EOPNOTSUPP);
                return;
            }
            // A filesystem that runs out of xattr room mid-way still proves the point with what it took, as long as
            // the names outgrow the first buffer.
            Err(Errno::ENOSPC) | Err(Errno::E2BIG) => break,
            Err(e) => panic!("fsetxattr: {e}"),
        }
    }
    let total: usize = want.iter().map(|n| n.len() + 1).sum();
    assert!(
        total > 256,
        "the fixture has to outgrow the first buffer, got {total} bytes"
    );

    let got = flistxattr(file.as_fd()).expect("list");
    for name in &want {
        assert!(
            got.iter().any(|g| g.as_bytes() == name.as_bytes()),
            "{name} missing from a list of {} - the regrow dropped it",
            got.len()
        );
    }
}

// An xattr name need not be UTF-8; `flistxattr` must return its bytes verbatim so the follow-up `fgetxattr`
// addresses the real attribute.
#[test]
fn non_utf8_name_listed_verbatim() {
    use std::ffi::CString;
    use std::os::fd::AsRawFd;
    let dir = truenas_ros::tempdir().unwrap();
    let path = dir.path().join("file");
    std::fs::write(&path, b"data").unwrap();
    let file = std::fs::OpenOptions::new().read(true).write(true).open(&path).unwrap();
    // A `user.` name whose trailing bytes are not valid UTF-8. The sync `fsetxattr` wrapper takes `&str`, so plant
    // it through raw `libc`.
    let name = CString::new(&b"user.\xff\xfe"[..]).unwrap();
    // SAFETY: `file` is live; `name`/value pointers are valid for the call.
    let rc = unsafe { libc::fsetxattr(file.as_raw_fd(), name.as_ptr(), b"v".as_ptr().cast(), 1, 0) };
    if rc != 0 {
        // Every assertion below is about to be skipped, so a scratch filesystem that drops `user.*` answers to the
        // gate.
        super::xattr_probe::refusal_is_allowed("fsetxattr(a non-UTF-8 user name)", std::io::Error::last_os_error());
        return;
    }
    let names = flistxattr(file.as_fd()).unwrap();
    assert!(
        names.iter().any(|n| n.as_bytes() == b"user.\xff\xfe"),
        "non-UTF-8 name not returned verbatim: {names:?}"
    );
}

#[test]
fn missing_xattr_is_enodata() {
    let dir = truenas_ros::tempdir().unwrap();
    let path = dir.path().join("file");
    std::fs::write(&path, b"data").unwrap();
    let file = std::fs::File::open(&path).unwrap();
    let err = fgetxattr(file.as_fd(), "user.definitely_absent").unwrap_err();
    assert!(matches!(err, Errno::ENODATA | Errno::EOPNOTSUPP));
}
