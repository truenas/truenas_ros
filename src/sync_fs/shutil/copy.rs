//! File-level copy / clone primitives and metadata copiers.
//!
//! These operate on open file descriptors and a single source/destination
//! pair; [`super::copytree`] composes them across a tree.

use crate::errno::{self, retry_on_eintr, Errno};
use crate::error::Result;
use crate::sync_fs::xattr::{fgetxattr, fsetxattr, XattrFlags};
use std::os::fd::{AsRawFd, BorrowedFd};
use std::ptr;

/// Largest single kernel read/write, page-aligned for best `copy_file_range` /
/// `sendfile` throughput.
pub const MAX_RW_SZ: usize = 0x7FFF_FFFF & !0xFFF;

const POSIX_ACCESS: &str = "system.posix_acl_access";
const POSIX_DEFAULT: &str = "system.posix_acl_default";
const NFS4_ACL: &str = "system.nfs4_acl_xdr";

const ACL_XATTRS: [&str; 3] = [POSIX_ACCESS, POSIX_DEFAULT, NFS4_ACL];
// ACLs that govern the file's own access (the POSIX *default* ACL only affects
// new children, so it is excluded).
const ACCESS_ACL_XATTRS: [&str; 2] = [POSIX_ACCESS, NFS4_ACL];

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
/// blob) those are copied and `fchmod` is skipped; otherwise `mode` is applied
/// with `fchmod`.
pub fn copy_permissions(
    src: BorrowedFd<'_>,
    dst: BorrowedFd<'_>,
    xattr_names: &[String],
    mode: u32,
) -> Result<()> {
    let access: Vec<&String> = xattr_names
        .iter()
        .filter(|n| ACCESS_ACL_XATTRS.contains(&n.as_str()))
        .collect();
    if access.is_empty() {
        retry_on_eintr(|| unsafe {
            libc::fchmod(dst.as_raw_fd(), (mode & 0o7777) as libc::mode_t)
        })?;
        return Ok(());
    }
    for name in access {
        let buf = fgetxattr(src, name)?;
        fsetxattr(dst, name, &buf, XattrFlags::empty())?;
    }
    Ok(())
}

/// Copy non-ACL, non-`system.*` xattrs from source to destination.
pub fn copy_xattrs(
    src: BorrowedFd<'_>,
    dst: BorrowedFd<'_>,
    xattr_names: &[String],
) -> Result<()> {
    for name in xattr_names {
        if ACL_XATTRS.contains(&name.as_str()) || name.starts_with("system") {
            continue;
        }
        let buf = fgetxattr(src, name)?;
        fsetxattr(dst, name, &buf, XattrFlags::empty())?;
    }
    Ok(())
}
