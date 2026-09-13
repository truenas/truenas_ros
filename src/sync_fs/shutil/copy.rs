//! File-level copy / clone primitives and metadata copiers.
//!
//! These operate on open file descriptors and a single source/destination
//! pair; [`super::copytree`] composes them across a tree.

use crate::errno::{self, Errno, retry_on_eintr};
use crate::error::Result;
use crate::sync_fs::xattr::{XattrFlags, fgetxattr, fsetxattr};
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
// meaningful alongside that ownership - see [`copy_setid`].
pub(super) const SETID_BITS: libc::mode_t = libc::S_ISUID | libc::S_ISGID;

fn has_access_acl(xattr_names: &[CString]) -> bool {
    xattr_names
        .iter()
        .any(|n| ACCESS_ACL_XATTRS.contains(&n.as_c_str()))
}

/// Whether `name` lives in a namespace [`copy_xattrs`] refuses to carry.
///
/// The dot is part of the prefix: `system` and `security` are namespace names,
/// and matching them bare would also swallow an attribute merely starting with
/// those letters.
fn is_reserved_namespace(name: &CString) -> bool {
    let bytes = name.as_bytes();
    bytes.starts_with(b"system.") || bytes.starts_with(b"security.")
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

/// Copy the source's permissions to the destination.
///
/// If the source carries an access ACL xattr (POSIX access or the ZFS NFS4
/// blob) it is copied and `fchmod` is skipped, since the ACL is authoritative
/// for the destination's permissions; otherwise `mode` is applied with
/// `fchmod`.
///
/// A POSIX **default** ACL travels either way. It is not an access check on
/// this object at all - it is the template children inherit - so it is a
/// separate xattr from the access ACL, and a directory can carry one with no
/// access ACL at all. [`copy_xattrs`] skips the whole `system.` namespace, so
/// if it is not copied here it is not copied anywhere.
///
/// The ACL is authoritative on ZFS `aclmode=restricted`, where a `chmod` of an
/// object holding a non-trivial ACL is rejected with `EPERM` (`zfs_setattr`).
/// A destination can hold such an ACL without the source having one - it
/// inherits from the destination parent - and on `acltype=nfsv4` the source's
/// own ACL is invisible to `flistxattr`, so the `fchmod` branch is the one
/// taken. An `EPERM` there means the destination's ACL already governs its
/// mode, which is the outcome this function wants; it is treated as applied
/// rather than failing the copy, matching [`super::copytree`]'s
/// destination-root and special-node `chmod` sites.
/// Mirrors `truenas_os` copy.py.
///
/// `S_ISUID`/`S_ISGID` are withheld - they belong to [`copy_setid`], which
/// applies them once the destination carries the source's ownership.
///
/// # The sticky bit on an ACL-bearing directory
///
/// `S_ISVTX` is a mode bit with no ACL representation, and on the ACL path no
/// `fchmod` runs, so a sticky source directory that also carries an access ACL
/// produces a destination with `S_ISVTX` clear. The bit is given up on
/// purpose: carrying it costs the ACL.
///
/// Restoring it would mean an `fchmod` on exactly the objects this branch
/// exists to keep away from one, and on ZFS a `chmod` is never just a mode
/// change - `zfs_acl_chmod_setattr` rewrites the ACL to agree with the new
/// mode. Under the **default** `aclmode=discard` it replaces it with a fresh
/// empty one (`zfs_acl_alloc`), under `groupmask` it trims the ALLOW entries,
/// and even `passthrough` re-splits the mode-representing ACEs; only
/// `restricted` refuses outright with `EPERM` (`zfs_setattr`). So re-stamping
/// one bit would, on a stock dataset, destroy the ACL the copy just
/// transported. A dropped sticky bit is a visible, repairable difference on a
/// directory an admin can `chmod +t`; a silently discarded ACL is neither.
///
/// The [`copy_setid`] path withholds `S_ISUID`/`S_ISGID` from an ACL-bearing
/// destination for the same reason, and the special-node path
/// (`copy_metadata`'s `mknod` sibling) does run an `fchmod`, but only
/// because a device node cannot carry an ACL for it to damage - there the
/// `chmod` is wrapped so an ACL-governed refusal is tolerated rather than
/// failing the copy.
pub fn copy_permissions(
    src: BorrowedFd<'_>,
    dst: BorrowedFd<'_>,
    xattr_names: &[CString],
    mode: u32,
) -> Result<()> {
    if xattr_names.iter().any(|n| n.as_c_str() == POSIX_DEFAULT) {
        let buf = fgetxattr(src, POSIX_DEFAULT)?;
        fsetxattr(dst, POSIX_DEFAULT, &buf, XattrFlags::empty())?;
    }
    if !has_access_acl(xattr_names) {
        return super::ok_if_acl_governed(
            retry_on_eintr(|| unsafe {
                libc::fchmod(
                    dst.as_raw_fd(),
                    mode as libc::mode_t & 0o7777 & !SETID_BITS,
                )
            })
            .map(drop)
            .map_err(Into::into),
        );
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

/// Whether a `system.nfs4_acl_xdr` blob carries nothing but the mode.
///
/// The blob's first big-endian word is `vsa_aclflags` - `zfsacl_to_nfsacl41i`
/// writes it ahead of the ACE count (`module/os/linux/zfs/zpl_xattr.c`) - and
/// `zfs_getacl` ORs `ACL_IS_TRIVIAL` into it from `z_pflags`
/// (`zfs_acl.c:2063`; the bit is `0x10000`,
/// `include/os/linux/spl/sys/acl.h:87`). `__zpl_xattr_nfs41acl_get` asks for
/// it by requesting `VSA_ACE_ACLFLAGS`, so the bit is in every blob it
/// returns. `Nfs4AclFlag::ACL_IS_TRIVIAL` is the same bit under this crate's
/// own name, and `truenas_os`'s `NFS4ACL.trivial` reads the same word.
///
/// **Asked of the blob, and not of `listxattr`, on purpose.** `zpl_xattr_list`
/// withholds the name for a trivial ACL and would answer this too - but
/// io_uring has `FGETXATTR`/`GETXATTR`/`FSETXATTR`/`SETXATTR` and **no**
/// listxattr op at all (`include/uapi/linux/io_uring.h`), so a predicate built
/// on listing cannot follow this code to the async side. The flags word rides
/// in bytes the caller has already fetched, which costs nothing and ports.
///
/// A blob too short to hold that word is unreadable rather than trivial, and
/// an unreadable ACL is one a `chmod` must not be let near.
fn nfs4_acl_is_trivial(blob: &[u8]) -> bool {
    // `include/os/linux/spl/sys/acl.h:87`. A ZFS extension rather than an
    // RFC 8881 flag, which is why it sits above `ACL_FLAGS_ALL` instead of
    // among the three standard bits.
    const ACL_IS_TRIVIAL: u32 = 0x0001_0000;
    let Some(word) = blob.get(..4) else {
        return false;
    };
    let flags = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
    flags & ACL_IS_TRIVIAL != 0
}

/// Put a plain mode on a destination whose ACL copy failed, so the creation
/// hold is not the mode it keeps. Answers whether one was applied.
///
/// `creation_mode` makes every object at `0o700`/`0o600` on the promise that
/// the source's mode lands afterwards, and [`copy_permissions`] is the only
/// thing that delivers it. `copy_metadata` wraps that in `guard`, which
/// answers `Ok(())` when `raise_error` is false - the mode `copytree`'s own
/// documentation names for salvaging a tree - so a swallowed failure left the
/// **hold** as the final mode for every object, with `copytree` answering
/// `Ok` and plausible stats. Not a race: an `acltype=nfsv4` source onto an
/// `acltype=posix` destination, or either onto `acltype=off`, fails
/// `fsetxattr` `EOPNOTSUPP` for every object in the tree.
///
/// **Declines when the destination already carries an access ACL.** There the
/// ACL *is* the permissions and a `chmod` would rewrite it to match the mode -
/// under ZFS's default `aclmode=discard`, replace it outright
/// (`zfs_acl_chmod_setattr`, `module/os/linux/zfs/zfs_acl.c`). A destination
/// holding one is not sitting at the hold, so there is nothing to release.
///
/// **The two names are asked different questions, because they answer
/// differently.** A POSIX access ACL exists as a stored xattr only when there
/// is a real one, so its presence is the answer. `system.nfs4_acl_xdr` is
/// synthesised: `__zpl_xattr_nfs41acl_get` (`module/os/linux/zfs/zpl_xattr.c`)
/// refuses only a non-NFSv4 dataset and an empty ACL, so **every** object on
/// an `acltype=nfsv4` dataset answers it - a trivial ACL included, since that
/// is still three ACEs. Presence therefore said "ACL" for every object on that
/// row and the hold was never released there at all, which is the row a share
/// migration lands on. [`nfs4_acl_is_trivial`] asks the blob instead.
///
/// `EOPNOTSUPP` means the filesystem keeps no xattrs, so there is no ACL to
/// damage and the mode lands.
///
/// **Scope is the object whose [`copy_permissions`] failed.** Ancestors are
/// stamped by `finish_dir` on ascent, so a walk that stops keeps their holds;
/// the call site says why an aborted copy is left closed rather than widened.
///
/// setid is withheld exactly as [`copy_permissions`] withholds it;
/// [`copy_setid`] applies it afterwards when ownership was preserved.
pub(super) fn release_creation_hold(
    dst: BorrowedFd<'_>,
    mode: u32,
) -> Result<bool> {
    match fgetxattr(dst, POSIX_ACCESS) {
        Ok(_) => return Ok(false),
        // No ACL of that flavour, or a filesystem that keeps none - which is
        // the case this exists for.
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
        retry_on_eintr(|| unsafe {
            libc::fchmod(
                dst.as_raw_fd(),
                mode as libc::mode_t & 0o7777 & !SETID_BITS,
            )
        })
        .map(drop)
        .map_err(Into::into),
    )?;
    Ok(true)
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
/// the mode follows the ACL, and an `fchmod` could discard it. A destination
/// governed by an ACL it *inherited* refuses the `fchmod` with `EPERM`, which
/// is tolerated for the reason [`copy_permissions`] gives - and here the
/// tolerated outcome is a destination without setid, a reduction in what the
/// copy grants, never an increase.
pub fn copy_setid(
    dst: BorrowedFd<'_>,
    xattr_names: &[CString],
    mode: u32,
) -> Result<()> {
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

/// Copy the source's xattrs to the destination, less the two namespaces a data
/// copy has no business re-stamping.
///
/// `system.*` is skipped because the ACLs live there and [`copy_permissions`]
/// owns them. `security.*` is skipped because it is where the kernel keeps
/// authority, not data: `security.capability` is a file capability set, so
/// copying it verbatim would transplant privilege onto a destination whose
/// content came from the source - `cap_setuid+ep` on a binary the caller
/// chose. The kernel gates the write on `CAP_SETFCAP` (`cap_convert_nscap`)
/// rather than forbidding it, so a `copytree` running as root can carry it
/// across - and `copy_metadata` orders the `fchown` so the kernel
/// strips the attribute, which only holds if nothing puts it back afterwards.
/// `security.ima`/`.evm` are skipped for the same reason and because an EVM
/// HMAC covers the inode it was computed over, so a copied one is invalid
/// anyway; an LSM label belongs to whatever policy owns the destination.
///
/// This matches the refusal the asynchronous side already makes:
/// `PrivilegedXattrs::allow_prefix` rejects the whole `security.` prefix.
/// `truenas_os` copy.py and `cp --preserve=xattr` both copy the namespace --
/// this is a deliberate divergence.
pub fn copy_xattrs(
    src: BorrowedFd<'_>,
    dst: BorrowedFd<'_>,
    xattr_names: &[CString],
) -> Result<()> {
    for name in xattr_names {
        if ACL_XATTRS.contains(&name.as_c_str()) || is_reserved_namespace(name)
        {
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

    /// The trivial bit is read out of the blob, at the right offset, in the
    /// right byte order - the whole of what `release_creation_hold` decides
    /// an `acltype=nfsv4` destination on.
    ///
    /// A pure function so this runs everywhere, including the unprivileged
    /// runner: the live half needs an NFSv4 dataset and only the QEMU lane
    /// has one, which is exactly how the defect this replaced survived.
    #[test]
    fn the_nfs4_trivial_bit_is_read_from_the_blob() {
        // XDR: [aclflags, ace_count, ...aces]. ZFS writes both big-endian.
        let blob = |flags: u32, naces: u32| {
            let mut v = flags.to_be_bytes().to_vec();
            v.extend_from_slice(&naces.to_be_bytes());
            v
        };
        // A trivial ACL is still three ACEs, which is why counting them - or
        // asking whether the xattr exists - cannot answer this.
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
