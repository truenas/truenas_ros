//! `open_tree(2)` — clone or reference a mount tree.

use crate::errno::{self, retry_on_eintr};
use crate::fd::owned_from_raw;
use crate::path::TnPath;
use std::os::fd::{AsFd, AsRawFd, OwnedFd, RawFd};

tn_bitflags! {
    /// Flags for [`open_tree`] (`OPEN_TREE_*` plus the applicable `AT_*`).
    pub struct OpenTreeFlags: libc::c_uint {
        /// Clone the target mount tree and attach the detached clone.
        OPEN_TREE_CLONE = 0x0000_0001;
        /// Set close-on-exec on the returned fd.
        OPEN_TREE_CLOEXEC = 0x0008_0000;
        /// Operate on the fd itself when the path is empty.
        AT_EMPTY_PATH = 0x0000_1000;
        /// Do not trigger automounts.
        AT_NO_AUTOMOUNT = 0x0000_0800;
        /// Do not dereference a trailing symbolic link.
        AT_SYMLINK_NOFOLLOW = 0x0000_0100;
        /// Clone the entire subtree (with `OPEN_TREE_CLONE`).
        AT_RECURSIVE = 0x0000_8000;
    }
}

/// Open the mount object or directory tree at `path` relative to `dirfd`.
///
/// See [`open_tree(2)`](https://man7.org/linux/man-pages/man2/open_tree.2.html).
pub fn open_tree<P, Fd>(
    dirfd: Fd,
    path: &P,
    flags: OpenTreeFlags,
) -> errno::Result<OwnedFd>
where
    P: ?Sized + TnPath,
    Fd: AsFd,
{
    let raw = dirfd.as_fd().as_raw_fd();
    let fd = path.with_tn_path(|c| {
        retry_on_eintr(|| unsafe {
            libc::syscall(libc::SYS_open_tree, raw, c.as_ptr(), flags.bits())
        })
    })??;
    // SAFETY: open_tree returns a fresh owned fd on success.
    Ok(unsafe { owned_from_raw(fd as RawFd) })
}
