//! `fchown(2)` - set a descriptor's owner and group.

use crate::errno::{self, retry_on_eintr};
use std::os::fd::{AsFd, AsRawFd};

/// The `(uid_t)-1` / `(gid_t)-1` the kernel reads as "leave this one
/// unchanged". Passed for whichever of `uid`/`gid` is `None`, which is
/// why both are optional rather than a caller having to know the
/// sentinel.
const UNCHANGED: libc::uid_t = libc::uid_t::MAX;

/// Set the owner and group of the file open at `fd`.
///
/// `None` leaves that half as it is; `Some` sets it. Both `None` is a
/// call the kernel still makes, and it still clears the setuid and
/// setgid bits, so it is not a no-op and is not turned into one here.
///
/// **Descriptor-based on purpose.** There is no path form in this
/// module: a path re-walks every component, so the file whose ownership
/// changes need not be the one the caller looked at. Holding the
/// descriptor pins the inode across the check and the change.
///
/// Changing ownership needs `CAP_CHOWN` unless the caller owns the file
/// and is only moving its group to one it belongs to; the group change
/// alone additionally needs `CAP_FSETID` to survive with a setgid bit
/// intact, which this does not preserve either way.
///
/// There is no io_uring opcode for this call, so a reactor doing it
/// does it on a blocking worker.
///
/// See [`fchown(2)`](https://man7.org/linux/man-pages/man2/fchown.2.html).
pub fn fchown<Fd>(
    fd: Fd,
    uid: Option<u32>,
    gid: Option<u32>,
) -> errno::Result<()>
where
    Fd: AsFd,
{
    let raw = fd.as_fd().as_raw_fd();
    let (uid, gid) = (uid.unwrap_or(UNCHANGED), gid.unwrap_or(UNCHANGED));
    retry_on_eintr(|| unsafe { libc::fchown(raw, uid, gid) })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tempdir;
    use std::os::unix::fs::MetadataExt;

    /// Every caller here already holds a descriptor, and this is the
    /// shape they hold it in: a directory, not a file.
    #[test]
    fn a_directory_descriptor_is_chownable() {
        let tmp = tempdir().unwrap();
        let dir = std::fs::File::open(tmp.path()).expect("opens");
        let before = std::fs::metadata(tmp.path()).expect("stats");
        // To its own owner, which is the one change every uid may make:
        // the test says the call reaches the inode, not that it can
        // escalate.
        fchown(&dir, Some(before.uid()), Some(before.gid())).expect("chowns");
        let after = std::fs::metadata(tmp.path()).expect("stats");
        assert_eq!(after.uid(), before.uid());
        assert_eq!(after.gid(), before.gid());
    }

    /// `None` is the kernel's `(uid_t)-1`, so the other half still
    /// moves and this one does not.
    #[test]
    fn none_leaves_that_half_alone() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("f");
        let file = std::fs::File::create(&path).expect("creates");
        let before = std::fs::metadata(&path).expect("stats");
        fchown(&file, None, None).expect("chowns nothing");
        let after = std::fs::metadata(&path).expect("stats");
        assert_eq!((after.uid(), after.gid()), (before.uid(), before.gid()));
    }

    /// A uid no unprivileged caller may give a file away to. Skipped
    /// where the test runs as root, since there the call succeeds and
    /// there is nothing to assert.
    #[test]
    fn giving_a_file_away_is_refused_without_the_capability() {
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("f");
        let file = std::fs::File::create(&path).expect("creates");
        assert_eq!(fchown(&file, Some(1), None), Err(errno::Errno::EPERM));
    }
}
