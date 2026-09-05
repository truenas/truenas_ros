//! The "does this filesystem take xattrs" probe shared by the live fixtures
//! (`test/net_server.rs`, `test/http_live.rs`).
//!
//! A refusal makes the caller skip its xattr assertions - unusual for a
//! `/tmp` (tmpfs registers a `user.*` handler, `shmem_user_xattr_handler`
//! in `mm/shmem.c`), but a runner whose scratch filesystem drops xattr
//! support would otherwise turn the flagship xattr paths green having
//! tested nothing. `TRUENAS_ROS_REQUIRE_XATTRS` turns the skip into a hard
//! failure where CI arms it, the same shape as the other REQUIRE gates.

/// Hold a probe's refusal to the `TRUENAS_ROS_REQUIRE_XATTRS` gate.
///
/// The probe itself differs by call site - a path `setxattr` here, an fd
/// `fsetxattr` in the suites that already hold a descriptor - but what a
/// refusal means does not: every xattr assertion behind it is about to be
/// skipped, so a runner whose scratch filesystem drops xattr support must
/// fail loudly where CI arms the gate rather than pass green having tested
/// nothing.
// Each including binary uses the half it needs - the live fixtures probe by
// path, the suites that already hold a descriptor gate an `fsetxattr` - and
// a `#[path]` module is compiled fresh into every one of them, so the other
// half is dead code there and nowhere else.
#[allow(dead_code)]
pub fn refusal_is_allowed(what: &str, err: impl std::fmt::Display) {
    assert!(
        std::env::var_os("TRUENAS_ROS_REQUIRE_XATTRS").is_none(),
        "TRUENAS_ROS_REQUIRE_XATTRS is set but {what} failed: {err}"
    );
}

/// The same, for a **POSIX ACL** refusal, which is a different question
/// from the one above: a POSIX ACL is the `system.posix_acl_access` xattr,
/// and a dataset whose `acltype` is not `posixacl` refuses it `EOPNOTSUPP`
/// (`zpl_xattr_acl_set_access`, `module/os/linux/zfs/zpl_xattr.c`) while
/// taking `user.*` xattrs perfectly well. Gating one on the other would
/// redden a lane for a filesystem doing exactly what it says.
///
/// `TRUENAS_ROS_REQUIRE_POSIX_ACL` is therefore its own gate. Arming it
/// takes knowing where the fixture lands - the QEMU lane's `/POSIXACL`
/// dataset is the one place in CI that is guaranteed to answer.
#[allow(dead_code)]
pub fn posix_acl_refusal_is_allowed(what: &str, err: impl std::fmt::Display) {
    assert!(
        std::env::var_os("TRUENAS_ROS_REQUIRE_POSIX_ACL").is_none(),
        "TRUENAS_ROS_REQUIRE_POSIX_ACL is set but {what} failed: {err}"
    );
}

/// Set an xattr with `libc::setxattr`, returning whether it stuck. The
/// fixtures probe `user.*` names, and the privileged-policy fixture a
/// root-set `trusted.*` one. `false` means the caller skips its xattr
/// assertions; under `TRUENAS_ROS_REQUIRE_XATTRS` the refusal is a test
/// failure instead.
#[allow(dead_code)] // see `refusal_is_allowed`
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
        refusal_is_allowed(
            &format!(
                "setxattr({}, {})",
                path.display(),
                String::from_utf8_lossy(name)
            ),
            std::io::Error::last_os_error(),
        );
    }
    r == 0
}
