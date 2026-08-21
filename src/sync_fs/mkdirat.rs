//! `mkdirat(2)` - create a directory relative to a descriptor.

use crate::errno::{self, retry_on_eintr};
use crate::path::TnPath;
use std::os::fd::{AsFd, AsRawFd};

use super::Mode;

/// Create the directory `name` **directly inside** `dirfd`, with
/// permission bits `mode`, which the caller's umask still masks.
///
/// **There is no resolve-flag form, so this takes a single component
/// and refuses everything else with `EINVAL`.** `openat2` takes
/// `RESOLVE_BENEATH` and friends; `mkdirat` takes none, and no successor
/// syscall provides them - the kernel's newest additions
/// (`setxattrat`, `getxattrat`, `open_tree_attr`, `file_setattr`) add no
/// directory-creating call. With a multi-component path every component
/// but the last resolves with symlinks followed, so one planted by
/// whoever owns an intermediate directory puts the new directory
/// somewhere else entirely; an absolute path ignores `dirfd` outright.
/// The check is what makes that unrepresentable rather than merely
/// documented, and it mirrors [`uring_fs::Leaf`](crate::uring_fs::Leaf),
/// which enforces the same rule in the type for the async sibling.
///
/// To build a nested tree, alternate this with a confined walk -
/// [`openat2`](super::openat2) under `RESOLVE_BENEATH |
/// RESOLVE_NO_SYMLINKS` - so each component is created against a
/// descriptor already proven to be inside the anchor. See
/// `a_component_at_a_time_builds_a_tree`.
///
/// Rejected: empty, `.`, `..`, and anything containing `/`.
///
/// `EEXIST` is a normal answer wherever two writers may create the same
/// tree, and is the caller's to interpret: this reports what the kernel
/// said and invents no idempotence the syscall does not have.
///
/// See [`mkdirat(2)`](https://man7.org/linux/man-pages/man2/mkdirat.2.html).
pub fn mkdirat<P, Fd>(dirfd: Fd, name: &P, mode: Mode) -> errno::Result<()>
where
    P: ?Sized + TnPath,
    Fd: AsFd,
{
    let raw = dirfd.as_fd().as_raw_fd();
    name.with_tn_path(|cstr| {
        let b = cstr.to_bytes();
        // A `CStr` cannot carry an interior NUL, so `Leaf`'s remaining
        // rejections are the whole set.
        if b.is_empty() || b == b"." || b == b".." || b.contains(&b'/') {
            return Err(errno::Errno::EINVAL);
        }
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

    /// The escape the single-component rule exists to prevent. With `a` a
    /// symlink pointing out of the anchor, a two-component path resolves `a`
    /// with symlinks followed and creates the directory at its target. The
    /// assertion is about where the directory landed, not merely which errno
    /// came back: with the guard removed the call returns `Ok(())` and
    /// `outside/escaped` exists, which is what the second assert refuses.
    #[test]
    fn a_planted_symlink_cannot_carry_the_create_out_of_the_anchor() {
        let tmp = tempdir().unwrap();
        let anchor_path = tmp.path().join("anchor");
        let outside = tmp.path().join("outside");
        std::fs::create_dir(&anchor_path).unwrap();
        std::fs::create_dir(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, anchor_path.join("a")).unwrap();
        let anchor = dir_fd(&anchor_path);
        assert_eq!(
            mkdirat(&anchor, "a/escaped", Mode::from_bits_truncate(0o755)),
            Err(errno::Errno::EINVAL)
        );
        assert!(
            !outside.join("escaped").exists(),
            "a multi-component path must not create outside the anchor"
        );
    }

    /// An absolute path ignores `dirfd` altogether, so it is refused for the
    /// same reason and never reaches the syscall.
    #[test]
    fn an_absolute_path_is_refused() {
        let tmp = tempdir().unwrap();
        let outside = tmp.path().join("abs-target");
        let root = dir_fd(tmp.path());
        let abs = outside.to_str().expect("utf-8 tempdir");
        assert_eq!(
            mkdirat(&root, abs, Mode::from_bits_truncate(0o755)),
            Err(errno::Errno::EINVAL)
        );
        assert!(!outside.exists(), "dirfd must not be bypassed");
    }

    /// The rest of the rejected set, which is [`crate::uring_fs::Leaf`]'s
    /// minus the interior NUL a `CStr` cannot carry.
    #[test]
    fn the_non_component_names_are_refused() {
        let tmp = tempdir().unwrap();
        let root = dir_fd(tmp.path());
        for name in ["", ".", "..", "a/b", "./a", "../a", "a/"] {
            assert_eq!(
                mkdirat(&root, name, Mode::from_bits_truncate(0o755)),
                Err(errno::Errno::EINVAL),
                "{name:?} is not a single component"
            );
        }
    }
}
