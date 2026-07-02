//! `renameat2(2)` — rename with flags (exchange / no-replace / whiteout).

use crate::errno::{self, retry_on_eintr};
use crate::path::TnPath;
use std::os::fd::{AsFd, AsRawFd};

tn_bitflags! {
    /// Flags for [`renameat2`] (`RENAME_*`).
    pub struct RenameFlags: libc::c_uint {
        /// Don't overwrite `new_path`; fail with `EEXIST` if it exists.
        RENAME_NOREPLACE = 0x1;
        /// Atomically exchange `old_path` and `new_path` (both must exist).
        RENAME_EXCHANGE = 0x2;
        /// Leave a whiteout at `old_path` (overlay/union filesystems only).
        RENAME_WHITEOUT = 0x4;
    }
}

/// Rename `old_path` (relative to `old_dirfd`) to `new_path` (relative to
/// `new_dirfd`), applying `flags`.
///
/// See [`renameat2(2)`](https://man7.org/linux/man-pages/man2/renameat2.2.html).
pub fn renameat2<P1, P2, Fd1, Fd2>(
    old_dirfd: Fd1,
    old_path: &P1,
    new_dirfd: Fd2,
    new_path: &P2,
    flags: RenameFlags,
) -> errno::Result<()>
where
    P1: ?Sized + TnPath,
    P2: ?Sized + TnPath,
    Fd1: AsFd,
    Fd2: AsFd,
{
    let old_raw = old_dirfd.as_fd().as_raw_fd();
    let new_raw = new_dirfd.as_fd().as_raw_fd();
    old_path.with_tn_path(|old_cstr| {
        new_path.with_tn_path(|new_cstr| {
            retry_on_eintr(|| unsafe {
                libc::syscall(
                    libc::SYS_renameat2,
                    old_raw,
                    old_cstr.as_ptr(),
                    new_raw,
                    new_cstr.as_ptr(),
                    flags.bits(),
                )
            })
        })
    })???;
    Ok(())
}
