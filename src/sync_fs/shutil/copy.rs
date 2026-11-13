//! File-level copy / clone primitives and metadata copiers.
//!
//! These operate on open file descriptors and a single source/destination pair; [`super::copytree`] composes them
//! across a tree.

use crate::errno::{self, Errno, retry_on_eintr};
use crate::error::Result;
use crate::sync_fs::xattr::{XattrFlags, fgetxattr, fsetxattr};
use std::ffi::{CStr, CString};
use std::os::fd::{AsRawFd, BorrowedFd};
use std::ptr;

/// Largest single kernel read/write, page-aligned for best `copy_file_range` / `sendfile` throughput.
pub const MAX_RW_SZ: usize = 0x7FFF_FFFF & !0xFFF;

const POSIX_ACCESS: &CStr = c"system.posix_acl_access";
const POSIX_DEFAULT: &CStr = c"system.posix_acl_default";
const NFS4_ACL: &CStr = c"system.nfs4_acl_xdr";

const ACL_XATTRS: [&CStr; 3] = [POSIX_ACCESS, POSIX_DEFAULT, NFS4_ACL];
// ACLs that govern the file's own access (the POSIX *default* ACL only affects new children, so it is excluded).
const ACCESS_ACL_XATTRS: [&CStr; 2] = [POSIX_ACCESS, NFS4_ACL];

// The mode bits that grant the file's own owner (or group) identity to whoever executes it. Split out of the rest of
// the mode because they are only meaningful alongside that ownership - see [`copy_setid`].
pub(super) const SETID_BITS: libc::mode_t = libc::S_ISUID | libc::S_ISGID;

fn has_access_acl(xattr_names: &[CString]) -> bool {
    xattr_names.iter().any(|n| ACCESS_ACL_XATTRS.contains(&n.as_c_str()))
}

/// Whether `name` lives in a namespace [`copy_xattrs`] refuses to carry.
///
/// The dot is part of the prefix: `system` and `security` are namespace names, and matching them bare would also
/// swallow an attribute merely starting with those letters.
fn is_reserved_namespace(name: &CString) -> bool {
    let bytes = name.as_bytes();
    bytes.starts_with(b"system.") || bytes.starts_with(b"security.")
}

/// Block-level clone via `copy_file_range(2)`. Fails with `EXDEV` across filesystems / ZFS pools.
pub fn clonefile(src: BorrowedFd<'_>, dst: BorrowedFd<'_>) -> errno::Result<u64> {
    let (s, d) = (src.as_raw_fd(), dst.as_raw_fd());
    let mut total = 0u64;
    loop {
        let n =
            retry_on_eintr(|| unsafe { libc::copy_file_range(s, ptr::null_mut(), d, ptr::null_mut(), MAX_RW_SZ, 0) })?;
        if n == 0 {
            break;
        }
        total += n as u64;
    }
    Ok(total)
}

/// Zero-copy file copy via `sendfile(2)`, falling back to a userspace copy when `sendfile` transfers nothing and the
/// destination is still empty.
pub fn copysendfile(src: BorrowedFd<'_>, dst: BorrowedFd<'_>) -> errno::Result<u64> {
    let (s, d) = (src.as_raw_fd(), dst.as_raw_fd());
    let mut total = 0u64;
    loop {
        let n = retry_on_eintr(|| unsafe { libc::sendfile(d, s, ptr::null_mut(), MAX_RW_SZ) })?;
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
pub fn copyuserspace(src: BorrowedFd<'_>, dst: BorrowedFd<'_>) -> errno::Result<u64> {
    let (s, d) = (src.as_raw_fd(), dst.as_raw_fd());
    let mut buf = vec![0u8; 1 << 20];
    let mut total = 0u64;
    loop {
        let n = retry_on_eintr(|| unsafe { libc::read(s, buf.as_mut_ptr().cast(), buf.len()) })? as usize;
        if n == 0 {
            break;
        }
        let mut off = 0;
        while off < n {
            let w = retry_on_eintr(|| unsafe { libc::write(d, buf[off..n].as_ptr().cast(), n - off) })? as usize;
            off += w;
        }
        total += n as u64;
    }
    Ok(total)
}

/// Try [`clonefile`]; on `EXDEV` fall back to [`copysendfile`].
pub fn copyfile(src: BorrowedFd<'_>, dst: BorrowedFd<'_>) -> errno::Result<u64> {
    match clonefile(src, dst) {
        Err(Errno::EXDEV) => copysendfile(src, dst),
        other => other,
    }
}

/// Copy the source's permissions to the destination.
///
/// If the source carries an access ACL xattr (POSIX access or the ZFS NFS4 blob) it is copied and `fchmod` is skipped,
/// since the ACL is authoritative for the destination's permissions; otherwise `mode` is applied with `fchmod`.
///
/// A POSIX **default** ACL travels either way, since [`copy_xattrs`] skips the whole `system.` namespace.
///
/// An `EPERM` from the `fchmod` is treated as applied. On ZFS `aclmode=restricted` it means the destination already
/// holds a non-trivial ACL, perhaps inherited from its parent, and that ACL governs its mode (`zfs_setattr`).
///
/// `S_ISUID`/`S_ISGID` are withheld - they belong to [`copy_setid`], which applies them once the destination carries
/// the source's ownership.
///
/// # The sticky bit on an ACL-bearing directory
///
/// `S_ISVTX` has no ACL representation and the ACL path runs no `fchmod`, so a sticky source directory with an access
/// ACL produces a destination with `S_ISVTX` clear, on purpose. On ZFS a `chmod` rewrites the ACL to agree with the
/// mode (`zfs_acl_chmod_setattr`). The default `aclmode=discard` replaces it with an empty one (`zfs_acl_alloc`),
/// `groupmask` trims the ALLOW entries, `passthrough` re-splits the mode ACEs, and only `restricted` refuses with
/// `EPERM`. A dropped sticky bit is visible and repairable with `chmod +t`, while a discarded ACL is neither.
pub fn copy_permissions(src: BorrowedFd<'_>, dst: BorrowedFd<'_>, xattr_names: &[CString], mode: u32) -> Result<()> {
    if xattr_names.iter().any(|n| n.as_c_str() == POSIX_DEFAULT) {
        let buf = fgetxattr(src, POSIX_DEFAULT)?;
        fsetxattr(dst, POSIX_DEFAULT, &buf, XattrFlags::empty())?;
    }
    if !has_access_acl(xattr_names) {
        return super::ok_if_acl_governed(
            retry_on_eintr(|| unsafe { libc::fchmod(dst.as_raw_fd(), mode as libc::mode_t & 0o7777 & !SETID_BITS) })
                .map(drop)
                .map_err(Into::into),
        );
    }
    for name in xattr_names.iter().filter(|n| ACCESS_ACL_XATTRS.contains(&n.as_c_str())) {
        let buf = fgetxattr(src, name.as_c_str())?;
        fsetxattr(dst, name.as_c_str(), &buf, XattrFlags::empty())?;
    }
    Ok(())
}

/// Whether a `system.nfs4_acl_xdr` blob carries nothing but the mode.
///
/// The blob's first big-endian word is `vsa_aclflags` (`zfsacl_to_nfsacl41i`, `module/os/linux/zfs/zpl_xattr.c`), into
/// which `zfs_getacl` ORs `ACL_IS_TRIVIAL` from `z_pflags` (`zfs_acl.c:2063`).
///
/// Ask the blob and not `listxattr`, though `zpl_xattr_list` withholds the name of a trivial ACL, since io_uring has no
/// listxattr op (`include/uapi/linux/io_uring.h`) and this check must work on the asynchronous side too.
///
/// A blob too short to hold that word is unreadable rather than trivial, and an unreadable ACL is one a `chmod` must
/// not be let near.
fn nfs4_acl_is_trivial(blob: &[u8]) -> bool {
    // `include/os/linux/spl/sys/acl.h:87`. A ZFS extension rather than an RFC 8881 flag, which is why it sits above
    // `ACL_FLAGS_ALL` instead of among the three standard bits.
    const ACL_IS_TRIVIAL: u32 = 0x0001_0000;
    let Some(word) = blob.get(..4) else {
        return false;
    };
    let flags = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
    flags & ACL_IS_TRIVIAL != 0
}

/// Put a plain mode on a destination whose ACL copy failed, so the creation hold is not the mode it keeps. Answers
/// whether one was applied.
///
/// Under `raise_error: false`, `guard` swallows a failed [`copy_permissions`], as when an `acltype=nfsv4` source lands
/// on `acltype=posix` and `fsetxattr` fails `EOPNOTSUPP`, so without this the hold would be the final mode of every
/// object.
///
/// **Declines when the destination already carries an access ACL.** There the ACL *is* the permissions and a `chmod`
/// would rewrite it to match the mode (`zfs_acl_chmod_setattr`). A POSIX access ACL is stored only when real, so its
/// presence answers. `system.nfs4_acl_xdr` is synthesised for every object on an `acltype=nfsv4` dataset
/// (`__zpl_xattr_nfs41acl_get`), a trivial ACL included, so [`nfs4_acl_is_trivial`] asks the blob instead.
///
/// `EOPNOTSUPP` means the filesystem keeps no xattrs, so there is no ACL to damage and the mode lands. setid is
/// withheld as [`copy_permissions`] withholds it.
pub(super) fn release_creation_hold(dst: BorrowedFd<'_>, mode: u32) -> Result<bool> {
    match fgetxattr(dst, POSIX_ACCESS) {
        Ok(_) => return Ok(false),
        // No ACL of that flavour, or a filesystem that keeps none - which is the case this exists for.
        Err(Errno::ENODATA | Errno::EOPNOTSUPP) => {}
        Err(e) => return Err(e.into()),
    }
    match fgetxattr(dst, NFS4_ACL) {
        Ok(blob) if !nfs4_acl_is_trivial(&blob) => return Ok(false),
        Ok(_) => {}
        Err(Errno::ENODATA | Errno::EOPNOTSUPP) => {}
        Err(e) => return Err(e.into()),
    }
    super::ok_if_acl_governed(
        retry_on_eintr(|| unsafe { libc::fchmod(dst.as_raw_fd(), mode as libc::mode_t & 0o7777 & !SETID_BITS) })
            .map(drop)
            .map_err(Into::into),
    )?;
    Ok(true)
}

/// Apply the `S_ISUID`/`S_ISGID` bits of `mode` that [`copy_permissions`] withholds.
///
/// Call this after a successful `fchown`, and not at all when ownership is not preserved, since setid grants the
/// identity of the file's owner and group and `fchown` clears it (`chown(2)`).
///
/// A destination whose permissions came from an ACL xattr is left alone, since an `fchmod` could discard the ACL. An
/// `EPERM` from an inherited ACL is tolerated, as in [`copy_permissions`], and leaves the destination without setid.
pub fn copy_setid(dst: BorrowedFd<'_>, xattr_names: &[CString], mode: u32) -> Result<()> {
    let mode = mode as libc::mode_t & 0o7777;
    if mode & SETID_BITS == 0 || has_access_acl(xattr_names) {
        return Ok(());
    }
    super::ok_if_acl_governed(
        retry_on_eintr(|| unsafe { libc::fchmod(dst.as_raw_fd(), mode) })
            .map(drop)
            .map_err(Into::into),
    )
}

/// Copy the source's xattrs to the destination, less the two namespaces a data copy has no business re-stamping.
///
/// `system.*` is skipped because the ACLs live there and [`copy_permissions`] owns them. `security.*` is skipped
/// because it holds authority, not data. A copied `security.capability` would transplant privilege onto content the
/// caller chose, since the kernel only gates the write on `CAP_SETFCAP` (`cap_convert_nscap`), and `copy_metadata`
/// orders the `fchown` so the kernel strips it. An EVM HMAC covers its own inode, and an LSM label belongs to the
/// destination's policy. `PrivilegedXattrs::allow_prefix` refuses the same prefix on the asynchronous side.
pub fn copy_xattrs(src: BorrowedFd<'_>, dst: BorrowedFd<'_>, xattr_names: &[CString]) -> Result<()> {
    for name in xattr_names {
        if ACL_XATTRS.contains(&name.as_c_str()) || is_reserved_namespace(name) {
            continue;
        }
        let buf = fgetxattr(src, name.as_c_str())?;
        fsetxattr(dst, name.as_c_str(), &buf, XattrFlags::empty())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The trivial bit is read out of the blob at the right offset and in the right byte order.
    #[test]
    fn the_nfs4_trivial_bit_is_read_from_the_blob() {
        // XDR: [aclflags, ace_count, ...aces]. ZFS writes both big-endian.
        let blob = |flags: u32, naces: u32| {
            let mut v = flags.to_be_bytes().to_vec();
            v.extend_from_slice(&naces.to_be_bytes());
            v
        };
        // A trivial ACL is still three ACEs, which is why counting them - or asking whether the xattr exists - cannot
        // answer this.
        assert!(nfs4_acl_is_trivial(&blob(0x0001_0000, 3)));
        // ACL_IS_DIR beside it, as a directory's blob carries.
        assert!(nfs4_acl_is_trivial(&blob(0x0003_0000, 3)));
        // A real ACL: same shape, same ACE count, bit clear.
        assert!(!nfs4_acl_is_trivial(&blob(0x0002_0000, 3)));
        assert!(!nfs4_acl_is_trivial(&blob(0, 3)));
        // Little-endian would read 0x0000_0100 here and answer the opposite.
        assert!(!nfs4_acl_is_trivial(&0x0001_0000u32.to_le_bytes()));
        // Too short to hold the word: unreadable, so not trivial.
        assert!(!nfs4_acl_is_trivial(&[]));
        assert!(!nfs4_acl_is_trivial(&[0, 1, 0]));
    }
}
