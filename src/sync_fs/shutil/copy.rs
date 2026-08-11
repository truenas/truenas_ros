//! File-level copy / clone primitives and metadata copiers.
//!
//! These operate on open file descriptors and a single source/destination
//! pair; [`super::copytree`] composes them across a tree.

use crate::errno::{self, retry_on_eintr, Errno};
use crate::error::Result;
use crate::sync_fs::xattr::{fgetxattr, fsetxattr, XattrFlags};
use std::ffi::{CStr, CString};
use std::os::fd::{AsRawFd, BorrowedFd};
use std::ptr;

/// Largest single kernel read/write, page-aligned for best `copy_file_range` /
/// `sendfile` throughput.
pub const MAX_RW_SZ: usize = 0x7FFF_FFFF & !0xFFF;

const POSIX_ACCESS: &CStr = c"system.posix_acl_access";
const POSIX_DEFAULT: &CStr = c"system.posix_acl_default";
const NFS4_ACL: &CStr = c"system.nfs4_acl_xdr";

const ACL_XATTRS: [&CStr; 3] = [POSIX_ACCESS, POSIX_DEFAULT, NFS4_ACL];
// ACLs that govern the file's own access (the POSIX *default* ACL only affects
// new children, so it is excluded).
const ACCESS_ACL_XATTRS: [&CStr; 2] = [POSIX_ACCESS, NFS4_ACL];

// The mode bits that grant the file's own owner (or group) identity to whoever
// executes it. Split out of the rest of the mode because they are only
// meaningful alongside that ownership — see [`copy_setid`].
pub(super) const SETID_BITS: libc::mode_t = libc::S_ISUID | libc::S_ISGID;

fn has_access_acl(xattr_names: &[CString]) -> bool {
    xattr_names
        .iter()
        .any(|n| ACCESS_ACL_XATTRS.contains(&n.as_c_str()))
}

/// Block-level clone via `copy_file_range(2)`. Fails with `EXDEV` across
/// filesystems / ZFS pools.
pub fn clonefile(
    src: BorrowedFd<'_>,
    dst: BorrowedFd<'_>,
) -> errno::Result<u64> {
    let (s, d) = (src.as_raw_fd(), dst.as_raw_fd());
    let mut total = 0u64;
    loop {
        let n = retry_on_eintr(|| unsafe {
            libc::copy_file_range(
                s,
                ptr::null_mut(),
                d,
                ptr::null_mut(),
                MAX_RW_SZ,
                0,
            )
        })?;
        if n == 0 {
            break;
        }
        total += n as u64;
    }
    Ok(total)
}

/// Zero-copy file copy via `sendfile(2)`, falling back to a userspace copy when
/// `sendfile` transfers nothing and the destination is still empty.
pub fn copysendfile(
    src: BorrowedFd<'_>,
    dst: BorrowedFd<'_>,
) -> errno::Result<u64> {
    let (s, d) = (src.as_raw_fd(), dst.as_raw_fd());
    let mut total = 0u64;
    loop {
        let n = retry_on_eintr(|| unsafe {
            libc::sendfile(d, s, ptr::null_mut(), MAX_RW_SZ)
        })?;
        if n <= 0 {
            break;
        }
        total += n as u64;
    }
    if total == 0 {
        // SAFETY: querying the current offset of an owned fd.
        let pos = unsafe { libc::lseek(d, 0, libc::SEEK_CUR) };
        if pos == 0 {
            return copyuserspace(src, dst);
        }
    }
    Ok(total)
}

/// Plain userspace read/write copy.
pub fn copyuserspace(
    src: BorrowedFd<'_>,
    dst: BorrowedFd<'_>,
) -> errno::Result<u64> {
    let (s, d) = (src.as_raw_fd(), dst.as_raw_fd());
    let mut buf = vec![0u8; 1 << 20];
    let mut total = 0u64;
    loop {
        let n = retry_on_eintr(|| unsafe {
            libc::read(s, buf.as_mut_ptr().cast(), buf.len())
        })? as usize;
        if n == 0 {
            break;
        }
        let mut off = 0;
        while off < n {
            let w = retry_on_eintr(|| unsafe {
                libc::write(d, buf[off..n].as_ptr().cast(), n - off)
            })? as usize;
            off += w;
        }
        total += n as u64;
    }
    Ok(total)
}

/// Try [`clonefile`]; on `EXDEV` fall back to [`copysendfile`].
pub fn copyfile(
    src: BorrowedFd<'_>,
    dst: BorrowedFd<'_>,
) -> errno::Result<u64> {
    match clonefile(src, dst) {
        Err(Errno::EXDEV) => copysendfile(src, dst),
        other => other,
    }
}

/// Copy the source's access permissions to the destination.
///
/// If the source carries an access ACL xattr (POSIX access or the ZFS NFS4
/// blob) it is copied and `fchmod` is skipped, since the ACL is authoritative
/// for the destination's permissions; otherwise `mode` is applied with
/// `fchmod`.
///
/// The ACL is authoritative on ZFS `aclmode=restricted`, where a `chmod` of an
/// object holding a non-trivial ACL is rejected with `EPERM` (`zfs_setattr`).
/// Mirrors `truenas_os` copy.py.
///
/// `S_ISUID`/`S_ISGID` are withheld — they belong to [`copy_setid`], which
/// applies them once the destination carries the source's ownership.
pub fn copy_permissions(
    src: BorrowedFd<'_>,
    dst: BorrowedFd<'_>,
    xattr_names: &[CString],
    mode: u32,
) -> Result<()> {
    if !has_access_acl(xattr_names) {
        retry_on_eintr(|| unsafe {
            libc::fchmod(
                dst.as_raw_fd(),
                mode as libc::mode_t & 0o7777 & !SETID_BITS,
            )
        })?;
        return Ok(());
    }
    for name in xattr_names
        .iter()
        .filter(|n| ACCESS_ACL_XATTRS.contains(&n.as_c_str()))
    {
        let buf = fgetxattr(src, name.as_c_str())?;
        fsetxattr(dst, name.as_c_str(), &buf, XattrFlags::empty())?;
    }
    Ok(())
}

/// Apply the `S_ISUID`/`S_ISGID` bits of `mode` that [`copy_permissions`]
/// withholds.
///
/// setid grants the identity of the file's own owner and group, so it is the
/// source's to give only when the destination carries the source's ownership
/// too: call this after a successful `fchown`, and not at all when ownership is
/// not preserved. `fchown` clears setid itself (`chown(2)`), so this runs last.
///
/// A destination whose permissions came from an ACL xattr is left alone: there
/// the mode follows the ACL, and an `fchmod` could discard it.
pub fn copy_setid(
    dst: BorrowedFd<'_>,
    xattr_names: &[CString],
    mode: u32,
) -> Result<()> {
    let mode = mode as libc::mode_t & 0o7777;
    if mode & SETID_BITS == 0 || has_access_acl(xattr_names) {
        return Ok(());
    }
    retry_on_eintr(|| unsafe { libc::fchmod(dst.as_raw_fd(), mode) })?;
    Ok(())
}

/// Copy non-ACL, non-`system.*` xattrs from source to destination.
pub fn copy_xattrs(
    src: BorrowedFd<'_>,
    dst: BorrowedFd<'_>,
    xattr_names: &[CString],
) -> Result<()> {
    for name in xattr_names {
        if ACL_XATTRS.contains(&name.as_c_str())
            || name.as_bytes().starts_with(b"system")
        {
            continue;
        }
        let buf = fgetxattr(src, name.as_c_str())?;
        fsetxattr(dst, name.as_c_str(), &buf, XattrFlags::empty())?;
    }
    Ok(())
}
