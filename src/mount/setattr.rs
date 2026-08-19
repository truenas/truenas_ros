//! `mount_setattr(2)` - change mount attributes / propagation / idmap.

use super::{Atime, MntPropagation, MountAttr};
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

/// `MOUNT_ATTR__ATIME` when `attrs` names part of the atime mask, else 0. The
/// kernel takes an atime change only when the whole mask is in `attr_clr`, and
/// rejects an atime bit in `attr_set` without it.
fn atime_mask(attrs: MountAttr) -> u64 {
    if attrs.intersects(MountAttr::__ATIME) {
        MountAttr::__ATIME.bits()
    } else {
        0
    }
}

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

    /// Set the given attributes. An atime attribute also clears
    /// [`MountAttr::__ATIME`], which the kernel requires when any atime bit
    /// appears in `attr_set`; [`Self::atime`] says the same thing plainly.
    pub fn set(mut self, attrs: MountAttr) -> Self {
        self.attr_set |= attrs.bits();
        self.attr_clr |= atime_mask(attrs);
        self
    }

    /// Clear the given attributes. Clearing any atime attribute clears the
    /// whole [`MountAttr::__ATIME`] mask, leaving [`Atime::Relatime`] unless
    /// an atime attribute is also set.
    pub fn clear(mut self, attrs: MountAttr) -> Self {
        self.attr_clr |= attrs.bits() | atime_mask(attrs);
        self
    }

    /// Select the atime policy, replacing any already requested. Clears
    /// [`MountAttr::__ATIME`] and sets just this policy's bits, which is the
    /// only encoding the kernel accepts - including for [`Atime::Relatime`],
    /// whose bits are none.
    pub fn atime(mut self, atime: Atime) -> Self {
        self.attr_set &= !MountAttr::__ATIME.bits();
        self.attr_set |= atime as u64;
        self.attr_clr |= MountAttr::__ATIME.bits();
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

#[cfg(test)]
mod tests {
    use super::*;

    const MASK: u64 = 0x0000_0070;

    #[test]
    fn atime_mask_holds_every_policy_and_nothing_else() {
        assert_eq!(MountAttr::__ATIME.bits(), MASK);
        assert_eq!(MountAttr::NOATIME.bits(), Atime::Noatime as u64);
        assert_eq!(MountAttr::STRICTATIME.bits(), Atime::Strictatime as u64);
        for policy in [Atime::Relatime, Atime::Noatime, Atime::Strictatime] {
            assert_eq!(policy as u64 & !MASK, 0);
            assert_eq!(Atime::try_from(policy as u64).unwrap(), policy);
        }
        // The mask has a bit no policy uses, so not every value decodes.
        assert!(Atime::try_from(MASK).is_err());
        assert!(!MountAttr::__ATIME.intersects(
            MountAttr::RDONLY
                | MountAttr::NODIRATIME
                | MountAttr::IDMAP
                | MountAttr::NOSYMFOLLOW
        ));
    }

    #[test]
    fn atime_selects_exactly_one_policy() {
        for policy in [Atime::Relatime, Atime::Noatime, Atime::Strictatime] {
            let a = MountSetattr::new().atime(policy);
            assert_eq!(a.attr_set, policy as u64);
            assert_eq!(a.attr_clr, MASK);
        }
    }

    #[test]
    fn atime_replaces_an_earlier_policy() {
        let a = MountSetattr::new()
            .atime(Atime::Noatime)
            .atime(Atime::Relatime);
        assert_eq!(a.attr_set, Atime::Relatime as u64);
        assert_eq!(a.attr_clr, MASK);

        let a = MountSetattr::new()
            .set(MountAttr::RDONLY | MountAttr::STRICTATIME)
            .atime(Atime::Noatime);
        assert_eq!(
            a.attr_set,
            MountAttr::RDONLY.bits() | Atime::Noatime as u64
        );
        assert_eq!(a.attr_clr, MASK);
    }

    #[test]
    fn setting_an_atime_attribute_clears_the_whole_mask() {
        for attr in [MountAttr::NOATIME, MountAttr::STRICTATIME] {
            let a = MountSetattr::new().set(attr);
            assert_eq!(a.attr_set, attr.bits());
            assert_eq!(a.attr_clr, MASK);
        }
    }

    #[test]
    fn clearing_an_atime_attribute_leaves_relatime() {
        for attr in [MountAttr::NOATIME, MountAttr::__ATIME] {
            let a = MountSetattr::new().clear(attr);
            assert_eq!(a.attr_clr, MASK);
            assert_eq!(a.attr_set & MASK, Atime::Relatime as u64);
        }
    }

    #[test]
    fn non_atime_attributes_leave_the_mask_alone() {
        let a = MountSetattr::new()
            .set(MountAttr::RDONLY | MountAttr::NOEXEC)
            .clear(MountAttr::NODEV);
        assert_eq!(a.attr_set, 0x0000_0009);
        assert_eq!(a.attr_clr, MountAttr::NODEV.bits());
    }
}
