//! `unlinkat(2)` - remove a name relative to a descriptor.

use crate::errno::{self, retry_on_eintr};
use crate::path::TnPath;
use std::os::fd::{AsFd, AsRawFd};

/// Remove the entry `name` **directly inside** `dirfd`.
///
/// `dir` selects which of the two removals this is: `false` unlinks a
/// non-directory, `true` passes `AT_REMOVEDIR` and removes an empty
/// directory. They are one syscall and two different errors — a
/// directory answers `EISDIR` without the flag, a file `ENOTDIR` with
/// it — so the caller says which it means rather than discovering it.
///
/// **Single component only, for [`mkdirat`](super::mkdirat)'s reason.**
/// `unlinkat` honours no `RESOLVE_*` flags either, so a multi-component
/// path resolves every component but the last with symlinks followed,
/// and one planted by whoever owns an intermediate directory moves the
/// removal somewhere else. The check is
/// [`path::component_defect`](crate::path::component_defect), the same
/// rule [`uring_fs::Leaf`](crate::uring_fs::Leaf) enforces in the type
/// for the async sibling.
///
/// Rejected: empty, `.`, `..`, and anything containing `/`.
///
/// `ENOENT` is a normal answer wherever two removers may race, and is
/// the caller's to interpret: this reports what the kernel said and
/// invents no idempotence the syscall does not have.
///
/// See [`unlinkat(2)`](https://man7.org/linux/man-pages/man2/unlinkat.2.html).
pub fn unlinkat<P, Fd>(dirfd: Fd, name: &P, dir: bool) -> errno::Result<()>
where
    P: ?Sized + TnPath,
    Fd: AsFd,
{
    let raw = dirfd.as_fd().as_raw_fd();
    let flags = if dir { libc::AT_REMOVEDIR } else { 0 };
    name.with_tn_path(|cstr| {
        if crate::path::component_defect(cstr.to_bytes()).is_some() {
            return Err(errno::Errno::EINVAL);
        }
        retry_on_eintr(|| unsafe {
            libc::syscall(libc::SYS_unlinkat, raw, cstr.as_ptr(), flags)
        })
    })??;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync_fs::{Mode, mkdirat};
    use crate::tempdir;

    fn dir_fd(path: &std::path::Path) -> std::fs::File {
        std::fs::File::open(path).expect("opens")
    }

    #[test]
    fn removes_a_file_relative_to_the_descriptor() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("gone");
        std::fs::write(&path, b"x").unwrap();
        let root = dir_fd(tmp.path());
        unlinkat(&root, "gone", false).unwrap();
        assert!(!path.exists());
    }

    /// The flag is the whole difference, and each kind refuses the
    /// other's call rather than silently doing nothing.
    #[test]
    fn a_directory_needs_the_directory_form() {
        let tmp = tempdir().unwrap();
        let root = dir_fd(tmp.path());
        mkdirat(&root, "d", Mode::from_bits_truncate(0o700)).unwrap();
        std::fs::write(tmp.path().join("f"), b"x").unwrap();
        assert_eq!(unlinkat(&root, "d", false), Err(errno::Errno::EISDIR));
        assert_eq!(unlinkat(&root, "f", true), Err(errno::Errno::ENOTDIR));
        unlinkat(&root, "d", true).unwrap();
        unlinkat(&root, "f", false).unwrap();
        assert!(!tmp.path().join("d").exists());
        assert!(!tmp.path().join("f").exists());
    }

    /// A non-empty directory is `ENOTEMPTY`, which is what makes
    /// "claim the directory, then drain it" a safe order.
    #[test]
    fn a_populated_directory_is_notempty() {
        let tmp = tempdir().unwrap();
        let root = dir_fd(tmp.path());
        mkdirat(&root, "d", Mode::from_bits_truncate(0o700)).unwrap();
        std::fs::write(tmp.path().join("d/f"), b"x").unwrap();
        assert_eq!(unlinkat(&root, "d", true), Err(errno::Errno::ENOTEMPTY));
    }

    /// The removal cannot be carried out of the anchor by a planted
    /// symlink, and the assertion is about what survived.
    #[test]
    fn a_planted_symlink_cannot_carry_the_removal_out_of_the_anchor() {
        let tmp = tempdir().unwrap();
        let anchor_path = tmp.path().join("anchor");
        let outside = tmp.path().join("outside");
        std::fs::create_dir(&anchor_path).unwrap();
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(outside.join("victim"), b"x").unwrap();
        std::os::unix::fs::symlink(&outside, anchor_path.join("a")).unwrap();
        let anchor = dir_fd(&anchor_path);
        assert_eq!(
            unlinkat(&anchor, "a/victim", false),
            Err(errno::Errno::EINVAL)
        );
        assert!(outside.join("victim").exists());
    }

    #[test]
    fn the_non_component_names_are_refused() {
        let tmp = tempdir().unwrap();
        let root = dir_fd(tmp.path());
        for name in ["", ".", "..", "a/b", "./a", "../a", "a/"] {
            assert_eq!(
                unlinkat(&root, name, false),
                Err(errno::Errno::EINVAL),
                "{name:?} is not a single component"
            );
        }
    }
}
