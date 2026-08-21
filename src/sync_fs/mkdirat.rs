//! `mkdirat(2)` - create a directory relative to a descriptor.

use crate::errno::{self, retry_on_eintr};
use crate::path::TnPath;
use std::os::fd::{AsFd, AsRawFd};

use super::Mode;

/// Create `path` (relative to `dirfd`) with permission bits `mode`,
/// which the caller's umask still masks.
///
/// **There is no resolve-flag form.** `openat2` takes `RESOLVE_BENEATH`
/// and friends; `mkdirat` takes none, and no successor syscall provides
/// them - the kernel's newest additions (`setxattrat`, `getxattrat`,
/// `open_tree_attr`, `file_setattr`) add no directory-creating call. A
/// caller that needs the guarantee gets it by construction rather than
/// by flag: resolve one component at a time against a descriptor it
/// already holds, so there is no multi-component path for a symlink to
/// redirect. That is the same discipline [`openat2`](super::openat2)
/// callers follow for the walk itself.
///
/// `EEXIST` is a normal answer wherever two writers may create the same
/// tree, and is the caller's to interpret: this reports what the kernel
/// said and invents no idempotence the syscall does not have.
///
/// See [`mkdirat(2)`](https://man7.org/linux/man-pages/man2/mkdirat.2.html).
pub fn mkdirat<P, Fd>(dirfd: Fd, path: &P, mode: Mode) -> errno::Result<()>
where
    P: ?Sized + TnPath,
    Fd: AsFd,
{
    let raw = dirfd.as_fd().as_raw_fd();
    path.with_tn_path(|cstr| {
        retry_on_eintr(|| unsafe {
            libc::syscall(libc::SYS_mkdirat, raw, cstr.as_ptr(), mode.bits())
        })
    })??;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync_fs::{OFlag, OpenHow, ResolveFlag, openat2};
    use crate::tempdir;

    fn dir_fd(path: &std::path::Path) -> std::fs::File {
        std::fs::File::open(path).expect("opens")
    }

    #[test]
    fn creates_relative_to_the_descriptor() {
        let tmp = tempdir().unwrap();
        let root = dir_fd(tmp.path());
        mkdirat(&root, "made", Mode::from_bits_truncate(0o755)).unwrap();
        assert!(tmp.path().join("made").is_dir());
    }

    /// The caller's to interpret: a concurrent creator of the same tree
    /// is ordinary, and this reports what the kernel said.
    #[test]
    fn a_second_create_is_eexist() {
        let tmp = tempdir().unwrap();
        let root = dir_fd(tmp.path());
        let mode = Mode::from_bits_truncate(0o755);
        mkdirat(&root, "twice", mode).unwrap();
        assert_eq!(mkdirat(&root, "twice", mode), Err(errno::Errno::EEXIST));
    }

    /// One component at a time against a held descriptor, which is how a
    /// caller gets what `mkdirat` has no flag for: the walk below never
    /// hands the kernel a path a symlink could redirect.
    #[test]
    fn a_component_at_a_time_builds_a_tree() {
        let tmp = tempdir().unwrap();
        let mode = Mode::from_bits_truncate(0o755);
        let mut anchor = dir_fd(tmp.path());
        for name in ["h1", "a7", "f1"] {
            mkdirat(&anchor, name, mode).unwrap();
            anchor = openat2(
                &anchor,
                name,
                OpenHow::new()
                    .flags(OFlag::O_RDONLY | OFlag::O_DIRECTORY)
                    .resolve(
                        ResolveFlag::RESOLVE_BENEATH
                            | ResolveFlag::RESOLVE_NO_SYMLINKS,
                    ),
            )
            .expect("opens what was just made")
            .into();
        }
        assert!(tmp.path().join("h1/a7/f1").is_dir());
    }

    /// The mode reaches the inode, so a caller creating a private tree
    /// gets one rather than an umask-shaped surprise.
    #[test]
    fn the_mode_is_applied() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempdir().unwrap();
        let root = dir_fd(tmp.path());
        mkdirat(&root, "private", Mode::from_bits_truncate(0o700)).unwrap();
        let got = std::fs::metadata(tmp.path().join("private")).unwrap();
        assert_eq!(got.permissions().mode() & 0o777, 0o700);
    }

    #[test]
    fn a_missing_parent_is_enoent() {
        let tmp = tempdir().unwrap();
        let root = dir_fd(tmp.path());
        assert_eq!(
            mkdirat(&root, "absent/child", Mode::from_bits_truncate(0o755)),
            Err(errno::Errno::ENOENT)
        );
    }
}
