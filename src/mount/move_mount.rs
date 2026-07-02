//! `move_mount(2)` — attach a detached mount, or move a mount.

use crate::errno::{self, retry_on_eintr};
use crate::path::TnPath;
use std::os::fd::{AsFd, AsRawFd};

tn_bitflags! {
    /// Flags for [`move_mount`] (`MOVE_MOUNT_*`).
    pub struct MoveMountFlags: libc::c_uint {
        /// Follow symlinks on the `from` path.
        MOVE_MOUNT_F_SYMLINKS = 0x0000_0001;
        /// Follow automounts on the `from` path.
        MOVE_MOUNT_F_AUTOMOUNTS = 0x0000_0002;
        /// Permit an empty `from` path (move by fd).
        MOVE_MOUNT_F_EMPTY_PATH = 0x0000_0004;
        /// Follow symlinks on the `to` path.
        MOVE_MOUNT_T_SYMLINKS = 0x0000_0010;
        /// Follow automounts on the `to` path.
        MOVE_MOUNT_T_AUTOMOUNTS = 0x0000_0020;
        /// Permit an empty `to` path (attach by fd).
        MOVE_MOUNT_T_EMPTY_PATH = 0x0000_0040;
        /// Set the sharing group instead of moving.
        MOVE_MOUNT_SET_GROUP = 0x0000_0100;
        /// Mount beneath the top mount at the destination.
        MOVE_MOUNT_BENEATH = 0x0000_0200;
    }
}

/// Move (or attach) the mount at (`from_dirfd`, `from_path`) to
/// (`to_dirfd`, `to_path`).
///
/// See [`move_mount(2)`](https://man7.org/linux/man-pages/man2/move_mount.2.html).
pub fn move_mount<P1, P2, Fd1, Fd2>(
    from_dirfd: Fd1,
    from_path: &P1,
    to_dirfd: Fd2,
    to_path: &P2,
    flags: MoveMountFlags,
) -> errno::Result<()>
where
    P1: ?Sized + TnPath,
    P2: ?Sized + TnPath,
    Fd1: AsFd,
    Fd2: AsFd,
{
    let from_raw = from_dirfd.as_fd().as_raw_fd();
    let to_raw = to_dirfd.as_fd().as_raw_fd();
    from_path.with_tn_path(|from_c| {
        to_path.with_tn_path(|to_c| {
            retry_on_eintr(|| unsafe {
                libc::syscall(
                    libc::SYS_move_mount,
                    from_raw,
                    from_c.as_ptr(),
                    to_raw,
                    to_c.as_ptr(),
                    flags.bits(),
                )
            })
        })
    })???;
    Ok(())
}
