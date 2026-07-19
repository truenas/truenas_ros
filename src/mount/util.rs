//! Higher-level mount helpers built on `statmount`/`listmount`/`umount2`.

use super::{
    listmount, statmount, umount2, MntFlags, Statmount, StatmountMask,
};
use crate::errno::{self, Errno};
use crate::error::{Error, Result};
use crate::sync_fs::{openat2, statx, AtFlags, OFlag, OpenHow, ResolveFlag};
use crate::sync_fs::{StatxAttr, StatxMask};
use crate::AT_FDCWD;
use std::os::fd::AsFd;
use std::path::Path;

// Fields wanted for mount enumeration. FULL adds the 6.14+ `sb_source` (needed
// for ZFS-snapshot detection); older kernels reject it, so we fall back to BASE.
const INFO_FULL: StatmountMask = StatmountMask::MNT_BASIC
    .union(StatmountMask::SB_BASIC)
    .union(StatmountMask::MNT_ROOT)
    .union(StatmountMask::MNT_POINT)
    .union(StatmountMask::FS_TYPE)
    .union(StatmountMask::MNT_OPTS)
    .union(StatmountMask::SB_SOURCE);
const INFO_BASE: StatmountMask = StatmountMask::MNT_BASIC
    .union(StatmountMask::SB_BASIC)
    .union(StatmountMask::MNT_ROOT)
    .union(StatmountMask::MNT_POINT)
    .union(StatmountMask::FS_TYPE)
    .union(StatmountMask::MNT_OPTS);

fn statmount_info(mnt_id: u64) -> errno::Result<Statmount> {
    match statmount(mnt_id, INFO_FULL) {
        // Kernel too old for the 6.14+ fields: retry without them.
        Err(Errno::EINVAL) => statmount(mnt_id, INFO_BASE),
        other => other,
    }
}

/// True if `sm` describes a ZFS snapshot mount (`fs_type == "zfs"` and the
/// mount source contains `@`). Always false on kernels that do not report
/// `sb_source`.
pub fn is_zfs_snapshot(sm: &Statmount) -> bool {
    sm.fs_type.as_deref() == Some("zfs")
        && sm.sb_source.as_deref().is_some_and(|s| s.contains('@'))
}

/// Return the [`Statmount`] for the mount containing `path` (symlink-safe).
pub fn statmount_path(path: &Path) -> Result<Statmount> {
    let fd = match openat2(
        AT_FDCWD,
        path,
        OpenHow::new()
            .flags(OFlag::O_PATH)
            .resolve(ResolveFlag::RESOLVE_NO_SYMLINKS),
    ) {
        Ok(fd) => fd,
        Err(Errno::ELOOP) => {
            return Err(Error::SymlinkInPath {
                path: path.to_path_buf(),
            })
        }
        Err(e) => return Err(e.into()),
    };
    let st = statx(
        fd.as_fd(),
        "",
        AtFlags::AT_EMPTY_PATH,
        StatxMask::MNT_ID_UNIQUE,
    )?;
    Ok(statmount_info(st.mnt_id())?)
}

/// Enumerate the mounts beneath `mnt_id` (children first when `reverse`), each
/// with full `statmount` detail. ZFS snapshot mounts are omitted unless
/// `include_snapshots` is set. Mounts that vanish mid-enumeration are skipped.
pub fn iter_mountinfo(
    mnt_id: u64,
    reverse: bool,
    include_snapshots: bool,
) -> Result<Vec<Statmount>> {
    let ids = listmount(mnt_id, reverse)?;
    let mut out = Vec::new();
    for id in ids {
        let sm = match statmount_info(id) {
            Ok(sm) => sm,
            // The mount disappeared between listmount and statmount.
            Err(Errno::ENOENT) => continue,
            Err(e) => return Err(e.into()),
        };
        if include_snapshots || !is_zfs_snapshot(&sm) {
            out.push(sm);
        }
    }
    Ok(out)
}

/// Options for the higher-level [`umount`].
#[derive(Clone, Copy, Debug, Default)]
pub struct UmountOptions {
    /// Force unmount even if busy (`MNT_FORCE`; a no-op on ZFS).
    pub force: bool,
    /// Lazy/detach unmount (`MNT_DETACH`).
    pub detach: bool,
    /// Mark the mount expired (`MNT_EXPIRE`).
    pub expire: bool,
    /// Follow a symlink at `path` (otherwise `UMOUNT_NOFOLLOW` is set).
    pub follow_symlinks: bool,
    /// Recursively unmount all child mounts (children first) before the target.
    pub recursive: bool,
}

/// Unmount the filesystem at `path`.
///
/// With [`UmountOptions::recursive`], all child mounts (including transient ZFS
/// snapshot mounts) are unmounted first; `path` must be a mountpoint.
pub fn umount(path: &Path, opts: UmountOptions) -> Result<()> {
    let mut flags = MntFlags::empty();
    if opts.force {
        flags |= MntFlags::MNT_FORCE;
    }
    if opts.detach {
        flags |= MntFlags::MNT_DETACH;
    }
    if opts.expire {
        flags |= MntFlags::MNT_EXPIRE;
    }
    if !opts.follow_symlinks {
        flags |= MntFlags::UMOUNT_NOFOLLOW;
    }

    if opts.recursive {
        let st = statx(
            AT_FDCWD,
            path,
            AtFlags::empty(),
            StatxMask::MNT_ID_UNIQUE | StatxMask::BASIC_STATS,
        )?;
        if !st.attributes().contains(StatxAttr::MOUNT_ROOT) {
            return Err(Error::Validation(format!(
                "{}: not a mountpoint",
                path.display()
            )));
        }
        for mnt in iter_mountinfo(st.mnt_id(), true, true)? {
            if let Some(point) = mnt.mnt_point {
                umount2(point.as_str(), flags)?;
            }
        }
    }

    umount2(path, flags)?;
    Ok(())
}
