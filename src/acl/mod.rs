//! NFS4 and POSIX1E access-control lists.
//!
//! [`fgetacl`] probes an open file to decide whether it carries an NFS4 ACL
//! (`system.nfs4_acl_xdr`, as used by ZFS) or a POSIX1E ACL
//! (`system.posix_acl_*`) and returns the decoded [`Acl`]. [`fsetacl`] writes
//! one back (or removes it). The wire formats and validation exactly mirror
//! the `truenas_os` C extension.

mod nfs4;
mod posix;

pub use nfs4::{
    Nfs4Ace, Nfs4AceType, Nfs4Acl, Nfs4AclFlag, Nfs4Flag, Nfs4Perm, Nfs4Who,
};
pub use posix::{PosixAce, PosixAcl, PosixPerm, PosixTag};

use crate::errno::Errno;
use crate::error::Result;
use crate::xattr::{fgetxattr, fremovexattr, fsetxattr, XattrFlags};
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};

/// A decoded ACL: either NFS4 (ZFS) or POSIX1E.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Acl {
    /// An NFS4 ACL.
    Nfs4(Nfs4Acl),
    /// A POSIX1E ACL.
    Posix(PosixAcl),
}

/// The target of an ACL validation: a real file descriptor (whose type is
/// checked with `fstat`), or the sentinel meaning "validate as if a directory".
#[derive(Clone, Copy, Debug)]
pub enum AclTarget<'fd> {
    /// Validate against this open file (directory-only rules apply if it is a
    /// directory).
    Fd(BorrowedFd<'fd>),
    /// Validate as though the target were a directory.
    AssumeDir,
}

impl<'fd> From<BorrowedFd<'fd>> for AclTarget<'fd> {
    fn from(fd: BorrowedFd<'fd>) -> Self {
        AclTarget::Fd(fd)
    }
}

fn fstat_mode(fd: BorrowedFd<'_>) -> Result<u32> {
    let mut st = MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `st` is a valid, writable `struct stat`.
    Errno::result(unsafe { libc::fstat(fd.as_raw_fd(), st.as_mut_ptr()) })?;
    // SAFETY: `fstat` succeeded, initialising `st`.
    Ok(unsafe { st.assume_init() }.st_mode)
}

fn target_is_dir(target: AclTarget<'_>) -> Result<bool> {
    match target {
        AclTarget::AssumeDir => Ok(true),
        AclTarget::Fd(fd) => {
            Ok(fstat_mode(fd)? & libc::S_IFMT == libc::S_IFDIR)
        }
    }
}

/// Read the ACL from an open file descriptor.
///
/// Returns an [`Acl::Nfs4`] on ZFS/NFS4 filesystems and an [`Acl::Posix`] on
/// POSIX1E filesystems. When the access ACL xattr is absent on a POSIX
/// filesystem, a trivial ACL is synthesised from the file's mode bits. Fails
/// with `Errno::EOPNOTSUPP` if ACLs are disabled on the filesystem entirely.
pub fn fgetacl<Fd: AsFd>(fd: Fd) -> Result<Acl> {
    let fd = fd.as_fd();
    match fgetxattr(fd, nfs4::NFS4_ACL_XATTR) {
        Ok(bytes) => Ok(Acl::Nfs4(Nfs4Acl::from_xattr(&bytes)?)),
        // Present but empty (NFS4 filesystem, no ACL set).
        Err(Errno::ENODATA) => Ok(Acl::Nfs4(Nfs4Acl::from_xattr(&[])?)),
        // Not an NFS4 filesystem — try POSIX.
        Err(Errno::EOPNOTSUPP) => fgetacl_posix(fd),
        Err(e) => Err(e.into()),
    }
}

fn fgetacl_posix(fd: BorrowedFd<'_>) -> Result<Acl> {
    let mut acl = match fgetxattr(fd, posix::POSIX_ACCESS_XATTR) {
        Ok(bytes) => PosixAcl::from_xattr(&bytes, None)?,
        // ACLs disabled entirely on this filesystem.
        Err(Errno::EOPNOTSUPP) => return Err(Errno::EOPNOTSUPP.into()),
        // No access xattr: derive a trivial ACL from the mode bits.
        Err(Errno::ENODATA) => posix::synthesize_from_mode(fstat_mode(fd)?),
        Err(e) => return Err(e.into()),
    };
    match fgetxattr(fd, posix::POSIX_DEFAULT_XATTR) {
        Ok(bytes) => acl.set_default_from_xattr(&bytes)?,
        Err(Errno::ENODATA) => {}
        Err(e) => return Err(e.into()),
    }
    Ok(Acl::Posix(acl))
}

/// Write an ACL to an open file descriptor, or remove it entirely with `None`.
///
/// The ACL is validated (as [`validate_acl`] would) before being written.
pub fn fsetacl<Fd: AsFd>(fd: Fd, acl: Option<&Acl>) -> Result<()> {
    let fd = fd.as_fd();
    match acl {
        None => fremoveacl(fd),
        Some(Acl::Nfs4(a)) => {
            a.validate(target_is_dir(AclTarget::Fd(fd))?)?;
            fsetxattr(
                fd,
                nfs4::NFS4_ACL_XATTR,
                &a.to_xattr(),
                XattrFlags::empty(),
            )?;
            Ok(())
        }
        Some(Acl::Posix(a)) => {
            a.validate(target_is_dir(AclTarget::Fd(fd))?)?;
            write_posix(fd, &a.access_bytes(), a.default_bytes().as_deref())
        }
    }
}

/// Validate an ACL against a target without writing it.
pub fn validate_acl(target: AclTarget<'_>, acl: &Acl) -> Result<()> {
    let is_dir = target_is_dir(target)?;
    match acl {
        Acl::Nfs4(a) => a.validate(is_dir),
        Acl::Posix(a) => a.validate(is_dir),
    }
}

/// Low-level: validate and write raw NFS4 XDR bytes to `system.nfs4_acl_xdr`.
pub fn fsetacl_nfs4<Fd: AsFd>(fd: Fd, data: &[u8]) -> Result<()> {
    let fd = fd.as_fd();
    Nfs4Acl::from_xattr(data)?.validate(target_is_dir(AclTarget::Fd(fd))?)?;
    fsetxattr(fd, nfs4::NFS4_ACL_XATTR, data, XattrFlags::empty())?;
    Ok(())
}

/// Low-level: validate and write raw POSIX ACL xattr bytes. A `None` default
/// removes the default ACL xattr.
pub fn fsetacl_posix<Fd: AsFd>(
    fd: Fd,
    access: &[u8],
    default: Option<&[u8]>,
) -> Result<()> {
    let fd = fd.as_fd();
    PosixAcl::from_xattr(access, default)?
        .validate(target_is_dir(AclTarget::Fd(fd))?)?;
    write_posix(fd, access, default)
}

fn write_posix(
    fd: BorrowedFd<'_>,
    access: &[u8],
    default: Option<&[u8]>,
) -> Result<()> {
    fsetxattr(fd, posix::POSIX_ACCESS_XATTR, access, XattrFlags::empty())?;
    match default {
        Some(d) => {
            fsetxattr(fd, posix::POSIX_DEFAULT_XATTR, d, XattrFlags::empty())?;
        }
        None => ignore_enodata(fremovexattr(fd, posix::POSIX_DEFAULT_XATTR))?,
    }
    Ok(())
}

fn fremoveacl(fd: BorrowedFd<'_>) -> Result<()> {
    // Probe for the NFS4 xattr to decide the filesystem's ACL type.
    match fgetxattr(fd, nfs4::NFS4_ACL_XATTR) {
        Ok(_) => ignore_enodata(fremovexattr(fd, nfs4::NFS4_ACL_XATTR)),
        // NFS4 filesystem, no ACL present — nothing to remove.
        Err(Errno::ENODATA) => Ok(()),
        Err(Errno::EOPNOTSUPP) => {
            // POSIX filesystem: remove access then default (ENODATA ignored).
            match fremovexattr(fd, posix::POSIX_ACCESS_XATTR) {
                Ok(()) | Err(Errno::ENODATA) => {}
                // ACLs disabled on the filesystem: nothing to remove.
                Err(Errno::EOPNOTSUPP) => return Ok(()),
                Err(e) => return Err(e.into()),
            }
            ignore_enodata(fremovexattr(fd, posix::POSIX_DEFAULT_XATTR))
        }
        Err(e) => Err(e.into()),
    }
}

fn ignore_enodata(r: crate::errno::Result<()>) -> Result<()> {
    match r {
        Ok(()) | Err(Errno::ENODATA) => Ok(()),
        Err(e) => Err(e.into()),
    }
}
