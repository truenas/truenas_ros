//! `mount_setattr(2)` — change mount attributes / propagation / idmap.

use super::{MntPropagation, MountAttr};
use crate::errno::{self, retry_on_eintr};
use crate::path::TnPath;
use crate::sync_fs::AtFlags;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};

/// Kernel `struct mount_attr` (VER0, 32 bytes).
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct RawMountAttr {
    attr_set: u64,
    attr_clr: u64,
    propagation: u64,
    userns_fd: u64,
}

const MOUNT_ATTR_SIZE_VER0: usize = 32;
const _: () =
    assert!(core::mem::size_of::<RawMountAttr>() == MOUNT_ATTR_SIZE_VER0);

/// The attribute changes to apply with [`mount_setattr`], built fluently.
#[derive(Clone, Copy, Debug, Default)]
pub struct MountSetattr<'fd> {
    attr_set: u64,
    attr_clr: u64,
    propagation: u64,
    userns: Option<BorrowedFd<'fd>>,
}

impl<'fd> MountSetattr<'fd> {
    /// A no-op attribute change.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the given attributes.
    pub fn set(mut self, attrs: MountAttr) -> Self {
        self.attr_set |= attrs.bits();
        self
    }

    /// Clear the given attributes.
    pub fn clear(mut self, attrs: MountAttr) -> Self {
        self.attr_clr |= attrs.bits();
        self
    }

    /// Set the propagation type.
    pub fn propagation(mut self, prop: MntPropagation) -> Self {
        self.propagation = prop.bits();
        self
    }

    /// Idmap the mount to the user namespace `userns` (sets
    /// [`MountAttr::IDMAP`]).
    pub fn idmap(mut self, userns: BorrowedFd<'fd>) -> Self {
        self.attr_set |= MountAttr::IDMAP.bits();
        self.userns = Some(userns);
        self
    }
}

/// Change the attributes of the mount (or subtree) at (`dirfd`, `path`).
///
/// `flags` accepts `AT_EMPTY_PATH`, `AT_RECURSIVE`, `AT_SYMLINK_NOFOLLOW`, and
/// `AT_NO_AUTOMOUNT`.
///
/// See [`mount_setattr(2)`](https://man7.org/linux/man-pages/man2/mount_setattr.2.html).
pub fn mount_setattr<P, Fd>(
    dirfd: Fd,
    path: &P,
    flags: AtFlags,
    attr: &MountSetattr<'_>,
) -> errno::Result<()>
where
    P: ?Sized + TnPath,
    Fd: AsFd,
{
    let raw = dirfd.as_fd().as_raw_fd();
    let mut a = RawMountAttr {
        attr_set: attr.attr_set,
        attr_clr: attr.attr_clr,
        propagation: attr.propagation,
        userns_fd: attr.userns.map_or(0, |f| f.as_raw_fd() as u64),
    };
    path.with_tn_path(|c| {
        retry_on_eintr(|| unsafe {
            libc::syscall(
                libc::SYS_mount_setattr,
                raw,
                c.as_ptr(),
                flags.bits(),
                &mut a as *mut RawMountAttr,
                MOUNT_ATTR_SIZE_VER0,
            )
        })
    })??;
    Ok(())
}
