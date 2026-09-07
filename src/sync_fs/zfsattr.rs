//! ZFS file attributes - the upper half of `z_pflags`, by descriptor.
//!
//! These are the DOS/NFSv4 attribute bits ZFS keeps per file and exposes
//! through a pair of its own ioctls. Two of them enforce object immutability
//! at the VFS layer, which is what makes them reachable from every protocol
//! at once rather than only from whoever set them:
//!
//! - `IMMUTABLE` and `APPENDONLY` are translated into the VFS inode flags
//!   `S_IMMUTABLE`/`S_APPEND`, and `may_delete`
//!   (`fs/namei.c`) refuses to unlink or rename an `IS_IMMUTABLE` inode
//!   before any filesystem code runs. An SMB or NFS client cannot route
//!   around that, and `may_write_xattr` (`fs/xattr.c`) rejects xattr writes
//!   on such an inode for the same reason - so **any metadata a caller wants
//!   alongside an immutable file must be written before the flag is set.**
//! - Setting or clearing either one needs `CAP_LINUX_IMMUTABLE`, so an
//!   unprivileged identity cannot lift its own lock.
//!
//! `NOUNLINK` reads like the closer match for a retention lock - alter but do
//! not delete - and is a trap: the same handler gates it on file *ownership*
//! only, with no capability, so whoever owns the file can clear it and
//! delete. Where the point is that the owner must not be able to, `IMMUTABLE`
//! is the flag with teeth.
//!
//! Unlike `FS_IOC_SETFLAGS` - which reaches only immutable, append, nodump
//! and projinherit - one ioctl here carries every bit.

use crate::errno::{self, retry_on_eintr};
use std::os::fd::{AsFd, AsRawFd};

/// `_IOR(0x83, 1, uint64_t)` - read the visible attribute mask.
const ZFS_IOC_GETDOSFLAGS: libc::c_ulong = 0x8008_8301;
/// `_IOW(0x83, 2, uint64_t)` - write it.
const ZFS_IOC_SETDOSFLAGS: libc::c_ulong = 0x4008_8302;

tn_bitflags! {
    /// ZFS per-file attributes (`include/sys/fs/zfs.h`).
    ///
    /// Exactly the bits ZFS calls `ZFS_DOS_FL_USER_VISIBLE`: the getter masks
    /// its answer to these, and the setter rejects anything outside them with
    /// `EOPNOTSUPP`. The remaining `z_pflags` bits (`OPAQUE`,
    /// `AV_QUARANTINED`, `AV_MODIFIED`) are ZFS-internal and deliberately
    /// absent.
    pub struct ZfsAttr: u64 {
        /// File may not be written to - **on an `acltype=nfsv4` dataset,
        /// for a caller whose permission check reaches ZFS**. Presented
        /// to SMB clients as the READONLY DOS attribute, and deliberately
        /// fchmod-shaped: toggling does not affect existing opens or
        /// mappings, which ZFS exempts by name.
        ///
        /// Unlike `IMMUTABLE` above, no VFS `i_flags` bit exists for
        /// this, so the deny lives in the access check alone - and a
        /// plain read/write/exec check reaches ZFS only when the dataset is
        /// `acltype=nfsv4` *and* the file's ACL is non-trivial. Anywhere
        /// else - posixacl, `acltype=off`, or a mode-shaped ACL - the
        /// check falls back to `generic_permission`, which reads the
        /// mode and nothing else: **the flag sets successfully and
        /// blocks no write.** The platform contract is therefore nfsv4
        /// with non-trivial ACLs on the files; inherited ACEs satisfy
        /// it, and every create flavor takes its ACL from the directory
        /// it is born in (one shared `zfs_acl_ids_create(dzp, ..)`).
        /// `acltype` *defaults* to nfsv4 on this platform, so the
        /// failure mode is a dataset someone switched, not one never
        /// configured - and a
        /// `system.nfs4_acl_xdr` getxattr probes it, answering
        /// `EOPNOTSUPP` anywhere the deny would not hold.
        ///
        /// A latch, not a lock: a privileged caller passes on the
        /// privilege fallback, the owner can clear it through this
        /// ioctl, and an SMB client with write access can clear the DOS
        /// attribute - while NFS has no surface to clear it at all. The
        /// one unconditional refusal is a new shared-writable mmap,
        /// denied on every dataset flavor with no privilege fallback.
        /// Invisible to `statx` and `lsattr`, so a refused write presents
        /// as a bare `EACCES` on a file whose mode looks writable - the
        /// fallback re-decides the errno, and `EPERM` is what `IMMUTABLE`
        /// answers, refused by the VFS before ZFS is consulted.
        READONLY = 0x0000_0001_0000_0000;
        /// HIDDEN DOS attribute - hides the file from SMB clients.
        HIDDEN = 0x0000_0002_0000_0000;
        /// SYSTEM DOS attribute. Presented to SMB clients; no local effect.
        SYSTEM = 0x0000_0004_0000_0000;
        /// ARCHIVE DOS attribute. ZFS resets it whenever the file is
        /// modified, so it cannot be relied on to stay clear.
        ARCHIVE = 0x0000_0008_0000_0000;
        /// File may not be altered, deleted, renamed, or linked, and its
        /// extended attributes may not be written. Enforced by the VFS for
        /// every protocol; needs `CAP_LINUX_IMMUTABLE` to set or clear.
        IMMUTABLE = 0x0000_0010_0000_0000;
        /// File may be altered but not deleted. **Clearable by the file's
        /// owner** - see the module docs before using it as a lock.
        NOUNLINK = 0x0000_0020_0000_0000;
        /// File may only be opened with `O_APPEND`. Needs
        /// `CAP_LINUX_IMMUTABLE` to set or clear.
        APPENDONLY = 0x0000_0040_0000_0000;
        /// Exclude from dumps.
        NODUMP = 0x0000_0080_0000_0000;
        /// Reparse point.
        REPARSE = 0x0000_0800_0000_0000;
        /// OFFLINE DOS attribute.
        OFFLINE = 0x0000_1000_0000_0000;
        /// SPARSE DOS attribute.
        SPARSE = 0x0000_2000_0000_0000;
    }
}

/// Read `fd`'s ZFS attributes.
///
/// `fd` must be opened for real I/O: an `O_PATH` descriptor has no
/// `f_op->unlocked_ioctl`, so this fails `EBADF` on one. Fails `ENOTTY` off
/// ZFS.
///
/// [`statx`](super::statx) already reports `IMMUTABLE`/`APPENDONLY` through
/// [`StatxAttr`](super::StatxAttr) without an ioctl or a writable
/// descriptor - prefer it when those two are all that is wanted, since it
/// rides a listing's existing stat pass.
pub fn fget_zfs_attrs<Fd: AsFd>(fd: Fd) -> errno::Result<ZfsAttr> {
    let raw_fd = fd.as_fd().as_raw_fd();
    let mut flags: u64 = 0;
    retry_on_eintr(|| unsafe {
        libc::ioctl(raw_fd, ZFS_IOC_GETDOSFLAGS, &mut flags)
    })?;
    Ok(ZfsAttr::from_bits_retain(flags))
}

/// Replace `fd`'s ZFS attributes with `attrs`.
///
/// **The mask is absolute, not a delta**: every visible bit absent from
/// `attrs` is cleared. Read with [`fget_zfs_attrs`] and modify what comes
/// back rather than writing a bare constant, or unrelated attributes another
/// protocol set - a client's ARCHIVE or HIDDEN bit - are silently dropped.
///
/// Changing `IMMUTABLE` or `APPENDONLY` requires `CAP_LINUX_IMMUTABLE`
/// (`EPERM` without it); every change also requires ownership of the file or
/// `CAP_FOWNER` (`EACCES`). A bit outside [`ZfsAttr`] fails `EOPNOTSUPP`, and
/// as with the getter an `O_PATH` descriptor fails `EBADF`.
pub fn fset_zfs_attrs<Fd: AsFd>(fd: Fd, attrs: ZfsAttr) -> errno::Result<()> {
    let raw_fd = fd.as_fd().as_raw_fd();
    let flags: u64 = attrs.bits();
    retry_on_eintr(|| unsafe {
        libc::ioctl(raw_fd, ZFS_IOC_SETDOSFLAGS, &flags)
    })?;
    Ok(())
}

#[cfg(all(test, not(loom)))]
mod tests {
    use super::*;
    use crate::errno::Errno;
    use std::fs::File;

    /// The ioctl encodings, checked against `_IOR`/`_IOW` by hand so a typo
    /// in a hex literal cannot masquerade as "ZFS not present".
    #[test]
    fn the_ioctl_numbers_match_their_macros() {
        // _IOC(dir, type, nr, size) = dir<<30 | size<<16 | type<<8 | nr
        let ior = (2u64 << 30) | (8 << 16) | (0x83 << 8) | 1;
        let iow = (1u64 << 30) | (8 << 16) | (0x83 << 8) | 2;
        assert_eq!(ZFS_IOC_GETDOSFLAGS, ior, "_IOR(0x83, 1, u64)");
        assert_eq!(ZFS_IOC_SETDOSFLAGS, iow, "_IOW(0x83, 2, u64)");
    }

    /// The bits are the upper half of `z_pflags`, and the set is exactly
    /// ZFS's `ZFS_DOS_FL_USER_VISIBLE` - the mask the setter validates
    /// against. A bit added here that ZFS does not accept would fail at
    /// runtime with `EOPNOTSUPP` on every set.
    #[test]
    fn the_flag_set_is_what_zfs_calls_user_visible() {
        let visible = ZfsAttr::IMMUTABLE
            | ZfsAttr::APPENDONLY
            | ZfsAttr::NOUNLINK
            | ZfsAttr::ARCHIVE
            | ZfsAttr::NODUMP
            | ZfsAttr::SYSTEM
            | ZfsAttr::HIDDEN
            | ZfsAttr::READONLY
            | ZfsAttr::REPARSE
            | ZfsAttr::OFFLINE
            | ZfsAttr::SPARSE;
        assert_eq!(
            ZfsAttr::all(),
            visible,
            "the type must name exactly ZFS_DOS_FL_USER_VISIBLE"
        );
        assert!(
            ZfsAttr::all().bits() & 0xffff_ffff == 0,
            "every bit lives in the upper half of z_pflags"
        );
    }

    /// Off ZFS the ioctl is simply absent, and that has to be distinguishable
    /// from a permission failure so a caller can fall back rather than retry.
    #[test]
    fn a_non_zfs_filesystem_reports_enotty() {
        let dir = crate::tempdir().unwrap();
        let path = dir.path().join("f");
        std::fs::write(&path, b"x").unwrap();
        let f = File::open(&path).unwrap();

        match fget_zfs_attrs(&f) {
            Err(Errno::ENOTTY) => {}
            Ok(attrs) => {
                // A ZFS-backed tempdir: the answer must stay inside the
                // visible set the getter masks to.
                assert_eq!(attrs & !ZfsAttr::all(), ZfsAttr::empty());
            }
            Err(e) => panic!("expected ENOTTY or a valid mask, got {e:?}"),
        }
    }
}
