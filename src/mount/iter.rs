//! Lazy iteration over mounts (`iter_mount`) and opening a mount by id.

use super::listmount::listmount;
use super::statmount::{statmount, Statmount, StatmountMask};
use crate::errno;
use crate::sync_fs::{openat2, OFlag, OpenHow};
use crate::AT_FDCWD;
use std::os::fd::OwnedFd;

/// Iterator over [`Statmount`] records, produced by [`iter_mount`].
///
/// Each `next` performs a `statmount` and may yield an `Err` (for instance if
/// a mount disappeared between the `listmount` snapshot and the `statmount`).
#[derive(Debug)]
pub struct MountIter {
    ids: std::vec::IntoIter<u64>,
    mask: StatmountMask,
}

impl Iterator for MountIter {
    type Item = errno::Result<Statmount>;

    fn next(&mut self) -> Option<Self::Item> {
        let id = self.ids.next()?;
        Some(statmount(id, self.mask))
    }
}

/// Iterate over the mounts beneath `mnt_id` (use
/// [`LSMT_ROOT`](super::LSMT_ROOT) for the whole namespace), calling
/// `statmount` with `mask` for each.
pub fn iter_mount(
    mnt_id: u64,
    reverse: bool,
    mask: StatmountMask,
) -> errno::Result<MountIter> {
    let ids = listmount(mnt_id, reverse)?;
    Ok(MountIter {
        ids: ids.into_iter(),
        mask,
    })
}

/// Open the mount point of the mount identified by `mnt_id`.
///
/// `flags` are ordinary open flags (typically `OFlag::O_DIRECTORY`).
pub fn open_mount_by_id(mnt_id: u64, flags: OFlag) -> errno::Result<OwnedFd> {
    let sm = statmount(mnt_id, StatmountMask::MNT_POINT)?;
    let point = sm.mnt_point.unwrap_or_default();
    openat2(AT_FDCWD, point.as_str(), OpenHow::new().flags(flags))
}
