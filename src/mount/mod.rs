//! Mount-related syscalls: `statmount`, `listmount`, `iter_mount`, `open_tree`,
//! `move_mount`, `mount_setattr`, `fsopen`/`fsconfig`/`fsmount`, `umount2`.
//!
//! Targets Linux 6.18: [`Statmount`] mirrors the full 6.18 `struct statmount`
//! (through the uid/gid maps). On older kernels the newer field groups (such as
//! `sb_source`) are simply not populated, and callers that request them fall
//! back gracefully.

mod fsmount;
mod iter;
mod listmount;
mod move_mount;
mod open_tree;
mod setattr;
mod statmount;
mod umount;
mod util;

pub use fsmount::{
    fsconfig, fsmount, fsopen, FsConfig, FsConfigCmd, FsmountFlags, FsopenFlags,
};
pub use iter::{iter_mount, open_mount_by_id, MountIter};
pub use listmount::{listmount, LSMT_ROOT};
pub use move_mount::{move_mount, MoveMountFlags};
pub use open_tree::{open_tree, OpenTreeFlags};
pub use setattr::{mount_setattr, MountSetattr};
pub use statmount::{statmount, SbFlags, Statmount, StatmountMask};
pub use umount::{umount2, MntFlags};
pub use util::{
    is_zfs_snapshot, iter_mountinfo, statmount_path, umount, UmountOptions,
};

tn_bitflags! {
    /// Per-mount attribute flags (`MOUNT_ATTR_*`) reported by `statmount` and
    /// set via [`mount_setattr`] / [`fsmount`].
    pub struct MountAttr: u64 {
        /// Mount read-only.
        RDONLY = 0x0000_0001;
        /// Ignore set-user-ID and set-group-ID bits.
        NOSUID = 0x0000_0002;
        /// Disallow access to device special files.
        NODEV = 0x0000_0004;
        /// Disallow program execution.
        NOEXEC = 0x0000_0008;
        /// Do not update access times.
        NOATIME = 0x0000_0010;
        /// Always update access times.
        STRICTATIME = 0x0000_0020;
        /// Do not update directory access times.
        NODIRATIME = 0x0000_0080;
        /// Idmap the mount to the user namespace in `userns_fd`.
        IDMAP = 0x0010_0000;
        /// Do not follow symbolic links.
        NOSYMFOLLOW = 0x0020_0000;
    }
}

tn_bitflags! {
    /// Mount propagation type (`MS_SHARED`/`SLAVE`/`PRIVATE`/`UNBINDABLE`).
    pub struct MntPropagation: u64 {
        /// Shared mount (propagates events to and from peers).
        MS_SHARED = 0x0010_0000;
        /// Slave mount (receives propagation only).
        MS_SLAVE = 0x0008_0000;
        /// Private mount (no propagation).
        MS_PRIVATE = 0x0004_0000;
        /// Unbindable mount.
        MS_UNBINDABLE = 0x0002_0000;
    }
}

/// Kernel `struct mnt_id_req` (VER1, 32 bytes) used by `statmount`/`listmount`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct MntIdReq {
    pub size: u32,
    pub mnt_ns_fd: u32,
    pub mnt_id: u64,
    pub param: u64,
    pub mnt_ns_id: u64,
}

pub(crate) const MNT_ID_REQ_SIZE_VER1: u32 = 32;

const _: () = assert!(core::mem::size_of::<MntIdReq>() == 32);

// libc 0.2.186 lacks these; they are on the arch-independent "common" syscall
// line (identical on x86_64/aarch64), verified against
// arch/*/entry/syscalls/*.tbl.
pub(crate) const SYS_STATMOUNT: libc::c_long = 457;
pub(crate) const SYS_LISTMOUNT: libc::c_long = 458;
