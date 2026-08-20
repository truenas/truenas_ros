//! The "does this filesystem take xattrs" probe shared by the live fixtures
//! (`test/net_server.rs`, `test/http_live.rs`).
//!
//! A refusal makes the caller skip its xattr assertions - unusual for a
//! `/tmp` (tmpfs registers a `user.*` handler, `shmem_user_xattr_handler`
//! in `mm/shmem.c`), but a runner whose scratch filesystem drops xattr
//! support would otherwise turn the flagship xattr paths green having
//! tested nothing. `TRUENAS_ROS_REQUIRE_XATTRS` turns the skip into a hard
//! failure where CI arms it, the same shape as the other REQUIRE gates.

/// Set an xattr with `libc::setxattr`, returning whether it stuck. The
/// fixtures probe `user.*` names, and the privileged-policy fixture a
/// root-set `trusted.*` one. `false` means the caller skips its xattr
/// assertions; under `TRUENAS_ROS_REQUIRE_XATTRS` the refusal is a test
/// failure instead.
pub fn set_user_xattr(
    path: &std::path::Path,
    name: &[u8],
    value: &[u8],
) -> bool {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let cpath = CString::new(path.as_os_str().as_bytes()).unwrap();
    let cname = CString::new(name).unwrap();
    // SAFETY: valid NUL-terminated path/name and a value+len for setxattr.
    let r = unsafe {
        libc::setxattr(
            cpath.as_ptr(),
            cname.as_ptr(),
            value.as_ptr().cast(),
            value.len(),
            0,
        )
    };
    if r != 0 {
        let err = std::io::Error::last_os_error();
        assert!(
            std::env::var_os("TRUENAS_ROS_REQUIRE_XATTRS").is_none(),
            "TRUENAS_ROS_REQUIRE_XATTRS is set but setxattr({}, {}) \
             failed: {err}",
            path.display(),
            String::from_utf8_lossy(name),
        );
    }
    r == 0
}
