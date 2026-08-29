//! `linkat(2)` - a second name for an inode that already has one.

use crate::errno::{self, retry_on_eintr};
use crate::path::TnPath;
use crate::sync_fs::AtFlags;
use std::os::fd::{AsFd, AsRawFd};

/// Give the inode named by `old_path` in `old_dirfd` a second name,
/// `new_path` in `new_dirfd`.
///
/// The completion of the name-manipulating set beside
/// [`mkdirat`](super::mkdirat), [`unlinkat`](super::unlinkat) and
/// [`renameat2`](super::renameat2): a rename moves a name and this one
/// adds a name, which is what a caller wants when the inode must keep
/// the name it already has. The `uring_fs` sibling exists for the
/// request path; this is for job work and set-up, which hold no ring.
///
/// **Single components only, for [`unlinkat`](super::unlinkat)'s
/// reason.** `linkat` honours no `RESOLVE_*` flags, so a
/// multi-component path resolves every component but the last with
/// symlinks followed, and one planted by whoever owns an intermediate
/// directory redirects the link. Both names are screened with
/// [`path::component_defect`](crate::path::component_defect); rejected
/// are empty, `.`, `..`, and anything containing `/`.
///
/// `flags` takes `AT_SYMLINK_FOLLOW` to link a symlink's target rather
/// than the symlink, and `AT_EMPTY_PATH` to link the descriptor itself
/// — which requires `old_path` to be empty and, in the kernel,
/// `CAP_DAC_READ_SEARCH`. The empty name is the one spelling the
/// component screen would otherwise refuse, so that flag lifts the
/// screen for `old_path` and only for it: the *new* name is always a
/// name.
///
/// `EEXIST` where `new_path` is taken, and it is the caller's to
/// interpret: `linkat` cannot replace a name, and this invents no
/// idempotence the syscall does not have.
///
/// See [`linkat(2)`](https://man7.org/linux/man-pages/man2/linkat.2.html).
pub fn linkat<P1, P2, Fd1, Fd2>(
    old_dirfd: Fd1,
    old_path: &P1,
    new_dirfd: Fd2,
    new_path: &P2,
    flags: AtFlags,
) -> errno::Result<()>
where
    P1: ?Sized + TnPath,
    P2: ?Sized + TnPath,
    Fd1: AsFd,
    Fd2: AsFd,
{
    let old_raw = old_dirfd.as_fd().as_raw_fd();
    let new_raw = new_dirfd.as_fd().as_raw_fd();
    let empty = flags.contains(AtFlags::AT_EMPTY_PATH);
    old_path.with_tn_path(|old_cstr| {
        new_path.with_tn_path(|new_cstr| {
            let old = old_cstr.to_bytes();
            let old_ok = if empty {
                old.is_empty()
            } else {
                crate::path::component_defect(old).is_none()
            };
            if !old_ok
                || crate::path::component_defect(new_cstr.to_bytes()).is_some()
            {
                return Err(errno::Errno::EINVAL);
            }
            retry_on_eintr(|| unsafe {
                libc::syscall(
                    libc::SYS_linkat,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync_fs::{Mode, mkdirat};
    use crate::tempdir;
    use std::os::unix::fs::MetadataExt;

    fn dir_fd(path: &std::path::Path) -> std::fs::File {
        std::fs::File::open(path).expect("opens")
    }

    #[test]
    fn a_second_name_reaches_the_same_inode() {
        let tmp = tempdir().unwrap();
        std::fs::write(tmp.path().join("one"), b"x").unwrap();
        let root = dir_fd(tmp.path());
        linkat(&root, "one", &root, "two", AtFlags::empty()).unwrap();

        let (a, b) = (
            std::fs::metadata(tmp.path().join("one")).unwrap(),
            std::fs::metadata(tmp.path().join("two")).unwrap(),
        );
        assert_eq!(a.ino(), b.ino(), "one inode, two names");
        assert_eq!(a.nlink(), 2);
    }

    /// The two descriptors need not be the same one, which is the
    /// whole point for a caller holding a source and a destination it
    /// resolved separately.
    #[test]
    fn the_name_may_land_in_another_directory() {
        let tmp = tempdir().unwrap();
        let root = dir_fd(tmp.path());
        mkdirat(&root, "d", Mode::from_bits_truncate(0o700)).unwrap();
        std::fs::write(tmp.path().join("src"), b"x").unwrap();
        let dest = dir_fd(&tmp.path().join("d"));

        linkat(&root, "src", &dest, "dst", AtFlags::empty()).unwrap();
        assert_eq!(
            std::fs::metadata(tmp.path().join("src")).unwrap().ino(),
            std::fs::metadata(tmp.path().join("d/dst")).unwrap().ino()
        );
    }

    /// `linkat` cannot replace a name, and a caller racing another for
    /// one needs to hear which of them got it.
    #[test]
    fn a_taken_name_is_eexist() {
        let tmp = tempdir().unwrap();
        std::fs::write(tmp.path().join("one"), b"x").unwrap();
        std::fs::write(tmp.path().join("taken"), b"y").unwrap();
        let root = dir_fd(tmp.path());
        assert_eq!(
            linkat(&root, "one", &root, "taken", AtFlags::empty()),
            Err(errno::Errno::EEXIST)
        );
    }

    /// A symlink is linked as itself unless the caller says otherwise,
    /// which is the direction that cannot be undone by surprise.
    #[test]
    fn a_symlink_is_followed_only_when_asked() {
        let tmp = tempdir().unwrap();
        std::fs::write(tmp.path().join("target"), b"x").unwrap();
        std::os::unix::fs::symlink("target", tmp.path().join("link")).unwrap();
        let root = dir_fd(tmp.path());

        linkat(&root, "link", &root, "as-link", AtFlags::empty()).unwrap();
        assert!(
            std::fs::symlink_metadata(tmp.path().join("as-link"))
                .unwrap()
                .file_type()
                .is_symlink()
        );

        linkat(
            &root,
            "link",
            &root,
            "as-target",
            AtFlags::AT_SYMLINK_FOLLOW,
        )
        .unwrap();
        assert_eq!(
            std::fs::symlink_metadata(tmp.path().join("as-target"))
                .unwrap()
                .ino(),
            std::fs::metadata(tmp.path().join("target")).unwrap().ino()
        );
    }

    /// Neither name may be carried out of its anchor by a symlink
    /// someone planted on the way, and the assertion is about what was
    /// not created.
    #[test]
    fn a_planted_symlink_cannot_carry_either_name_out() {
        let tmp = tempdir().unwrap();
        let anchor_path = tmp.path().join("anchor");
        let outside = tmp.path().join("outside");
        std::fs::create_dir(&anchor_path).unwrap();
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(outside.join("victim"), b"x").unwrap();
        std::fs::write(anchor_path.join("mine"), b"x").unwrap();
        std::os::unix::fs::symlink(&outside, anchor_path.join("a")).unwrap();
        let anchor = dir_fd(&anchor_path);

        assert_eq!(
            linkat(&anchor, "a/victim", &anchor, "stolen", AtFlags::empty()),
            Err(errno::Errno::EINVAL)
        );
        assert_eq!(
            linkat(&anchor, "mine", &anchor, "a/planted", AtFlags::empty()),
            Err(errno::Errno::EINVAL)
        );
        assert!(!outside.join("planted").exists());
        assert!(!anchor_path.join("stolen").exists());
    }

    #[test]
    fn the_non_component_names_are_refused() {
        let tmp = tempdir().unwrap();
        std::fs::write(tmp.path().join("one"), b"x").unwrap();
        let root = dir_fd(tmp.path());
        for name in ["", ".", "..", "a/b", "./a", "../a", "a/"] {
            assert_eq!(
                linkat(&root, name, &root, "new", AtFlags::empty()),
                Err(errno::Errno::EINVAL),
                "{name:?} is not a single component"
            );
            assert_eq!(
                linkat(&root, "one", &root, name, AtFlags::empty()),
                Err(errno::Errno::EINVAL),
                "{name:?} is not a single component"
            );
        }
    }

    /// The empty name is admitted only under `AT_EMPTY_PATH`, and the
    /// flag lifts the screen for the source alone: a new name is
    /// always a name.
    #[test]
    fn the_empty_name_needs_the_flag_and_lifts_nothing_else() {
        let tmp = tempdir().unwrap();
        let root = dir_fd(tmp.path());
        assert_eq!(
            linkat(&root, "", &root, "new", AtFlags::empty()),
            Err(errno::Errno::EINVAL)
        );
        assert_eq!(
            linkat(&root, "", &root, "", AtFlags::AT_EMPTY_PATH),
            Err(errno::Errno::EINVAL),
            "the destination is still screened"
        );
        assert_eq!(
            linkat(&root, "not-empty", &root, "new", AtFlags::AT_EMPTY_PATH),
            Err(errno::Errno::EINVAL),
            "the flag means the source name is empty"
        );
    }
}
