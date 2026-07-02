//! `umount2(2)`.

use crate::errno::{self, retry_on_eintr};
use crate::path::TnPath;

tn_bitflags! {
    /// Flags for [`umount2`] (`MNT_*` / `UMOUNT_*`).
    pub struct MntFlags: libc::c_int {
        /// Force unmount even if busy (may lose data).
        MNT_FORCE;
        /// Lazy unmount: detach now, clean up references when no longer busy.
        MNT_DETACH;
        /// Mark the mount as expired; unmount only if already expired.
        MNT_EXPIRE;
        /// Do not dereference `target` if it is a symbolic link.
        UMOUNT_NOFOLLOW;
    }
}

/// Unmount the filesystem mounted at `target`.
///
/// See [`umount2(2)`](https://man7.org/linux/man-pages/man2/umount2.2.html).
pub fn umount2<P: ?Sized + TnPath>(
    target: &P,
    flags: MntFlags,
) -> errno::Result<()> {
    target.with_tn_path(|c| {
        retry_on_eintr(|| unsafe { libc::umount2(c.as_ptr(), flags.bits()) })
    })??;
    Ok(())
}
