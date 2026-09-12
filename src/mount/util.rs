//! Higher-level mount helpers built on `statmount`/`listmount`/`umount2`.

use super::{
    MntFlags, Statmount, StatmountMask, listmount, statmount, umount2,
};
use crate::AT_FDCWD;
use crate::errno::{self, Errno};
use crate::error::{Error, Result};
use crate::sync_fs::{AtFlags, OFlag, OpenHow, ResolveFlag, openat2, statx};
use crate::sync_fs::{StatxAttr, StatxMask};
use std::collections::BTreeMap;
use std::os::fd::AsFd;
use std::path::{Path, PathBuf};

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
            });
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

/// Enumerate the mounts beneath `mnt_id`, each with full `statmount` detail.
///
/// `reverse` is [`listmount`]'s flag and orders by descending mount id, which
/// is creation order and **not** children-before-parents; see that function.
/// For unmount ordering, sort by depth over `mnt_parent_id`, as
/// [`umount`] does. ZFS snapshot mounts are omitted unless
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

/// Mount points beneath `mnt_id`, children before their parents.
///
/// **`listmount`'s reverse order is not this order.** `listmnt_next` walks an
/// rbtree keyed on `mnt_id_unique` (`fs/namespace.c`, the insert comparison),
/// and that field is `++mnt_id_ctr` assigned when the mount is *allocated* -
/// so reverse is descending creation order. It coincides with
/// children-before-parents only when every child's mount was created after
/// its parent's, and `fsmount(2)` plus `move_mount(2)` - both exported from
/// this module - make the opposite ordinary: build the filesystem, build the
/// one it will live under, then attach. Measured with a three-level tree
/// whose ids descend with depth, the reverse listing unmounts the middle
/// mount first, `umount2` answers `EBUSY`, and the caller is told the
/// unmount failed with the whole tree still mounted.
///
/// Depth is what matters, so it is computed rather than assumed. `MNT_BASIC`
/// is already requested, so `mnt_parent_id` is in hand; depth is the number
/// of parent links back to `mnt_id`, and sorting by it descending puts every
/// child before its parent - a child's depth always exceeds its parent's.
///
/// A mount whose parent chain does not reach `mnt_id` - it vanished
/// mid-enumeration, or the listing raced - stops at the depth it reached,
/// which orders it no later than its own descendants. The walk is bounded by
/// the number of mounts, so a cycle cannot hang it.
fn descendants_deepest_first(mnt_id: u64) -> Result<Vec<PathBuf>> {
    let mounts = iter_mountinfo(mnt_id, false, true)?;
    let parent_of: BTreeMap<u64, u64> = mounts
        .iter()
        .filter_map(|m| Some((m.mnt_id?, m.mnt_parent_id?)))
        .collect();
    let depth_of = |start: u64| -> usize {
        let mut id = start;
        let mut d = 0;
        while id != mnt_id && d <= mounts.len() {
            match parent_of.get(&id) {
                Some(&parent) => {
                    id = parent;
                    d += 1;
                }
                None => break,
            }
        }
        d
    };
    let mut ordered: Vec<(usize, &PathBuf)> = mounts
        .iter()
        .filter_map(|m| Some((depth_of(m.mnt_id?), m.mnt_point.as_ref()?)))
        .collect();
    ordered.sort_by_key(|&(d, _)| std::cmp::Reverse(d));
    Ok(ordered.into_iter().map(|(_, p)| p.clone()).collect())
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
/// snapshot mounts) are unmounted first; `path` must be a mountpoint under the
/// same symlink rules as the unmount itself, so unless
/// [`UmountOptions::follow_symlinks`] is set a symlinked `path` is rejected and
/// nothing is unmounted.
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
        // Resolve the target exactly as the unmount below will: under
        // UMOUNT_NOFOLLOW a symlinked path is no mountpoint of its own, so it
        // fails the check here.
        let at = if opts.follow_symlinks {
            AtFlags::empty()
        } else {
            AtFlags::AT_SYMLINK_NOFOLLOW
        };
        let st = statx(
            AT_FDCWD,
            path,
            at,
            StatxMask::MNT_ID_UNIQUE | StatxMask::BASIC_STATS,
        )?;
        if !st.attributes().contains(StatxAttr::MOUNT_ROOT) {
            return Err(Error::Validation(format!(
                "{}: not a mountpoint",
                path.display()
            )));
        }
        for point in descendants_deepest_first(st.mnt_id())? {
            // Unmount the exact bytes the kernel reported for the child.
            umount2(&point, flags)?;
        }
    }

    umount2(path, flags)?;
    Ok(())
}
