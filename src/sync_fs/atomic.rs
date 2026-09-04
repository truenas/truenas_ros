//! Atomic, symlink-safe file replacement (`atomic_write` / `atomic_replace`).

use super::{
    AtFlags, Mode, OFlag, OpenHow, RenameFlags, ResolveFlag, StatxMask,
    openat2, renameat2, statx,
};
use crate::AT_FDCWD;
use crate::errno::{Errno, retry_on_eintr};
use crate::error::{Error, Result};
use crate::path::TnPath;
use std::ffi::{OsStr, OsString};
use std::fs::{File, Permissions};
use std::io::{self, Write};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

/// Options controlling [`atomic_write`] / [`atomic_replace`].
#[derive(Clone, Copy, Debug)]
pub struct AtomicWriteOptions {
    /// Owner uid to set; `None` preserves the existing *regular* file's owner
    /// (or leaves the creator's uid when the target is new or not a regular
    /// file).
    pub uid: Option<u32>,
    /// Owner gid to set; `None` preserves the existing regular file's group.
    pub gid: Option<u32>,
    /// Permission bits for the new file.
    pub mode: u32,
    /// Fail (with `EEXIST`) if the target already exists, rather than replacing.
    pub noclobber: bool,
}

impl Default for AtomicWriteOptions {
    fn default() -> Self {
        AtomicWriteOptions {
            uid: None,
            gid: None,
            mode: 0o644,
            noclobber: false,
        }
    }
}

/// Atomically create or replace `target` with content written by `write_fn`.
///
/// A temporary file is created alongside `target` (same directory, so the same
/// filesystem), written, `fsync`ed, then moved into place with `renameat2` --
/// either a plain rename (new file), an atomic `RENAME_EXCHANGE` (replacing an
/// existing file so readers never see a partial write), or `RENAME_NOREPLACE`
/// (with [`AtomicWriteOptions::noclobber`]). The parent directory is `fsync`ed
/// last, so the entry the rename publishes survives a crash. The target is only
/// replaced if `write_fn` returns `Ok`; on error the temporary file is removed
/// and `target` is left untouched. Every path component is opened with
/// `RESOLVE_NO_SYMLINKS`.
///
/// `write_fn` receives the temporary [`File`] directly, so it can use the full
/// [`std::io`] API (or anything built on it). It is handed a file that is
/// still owner-private and at neither the requested mode nor the requested
/// owner: both land afterwards, because a write to a regular file makes the
/// kernel drop `S_ISUID`/`S_ISGID` and a chown before the write would open
/// the staged bytes to the target uid. One consequence for a `write_fn` with
/// side effects: an ownership or mode that cannot be applied is now
/// discovered **after** it has run, not before.
pub fn atomic_write<F>(
    target: &Path,
    opts: AtomicWriteOptions,
    write_fn: F,
) -> Result<()>
where
    F: FnOnce(&mut File) -> io::Result<()>,
{
    let parent = target
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let name = target.file_name().ok_or_else(|| {
        Error::Validation("target path has no file name".into())
    })?;

    // Open the destination directory symlink-safely.
    let dir = match openat2(
        AT_FDCWD,
        parent,
        OpenHow::new()
            .flags(OFlag::O_DIRECTORY | OFlag::O_CLOEXEC)
            .resolve(ResolveFlag::RESOLVE_NO_SYMLINKS),
    ) {
        Ok(fd) => fd,
        Err(Errno::ELOOP) => {
            return Err(Error::SymlinkInPath {
                path: parent.to_path_buf(),
            });
        }
        Err(e) => return Err(e.into()),
    };
    let dir = dir.as_fd();

    // Inspect the existing target (if any) for noclobber and owner-preservation.
    let existing = match statx(
        dir,
        name,
        AtFlags::AT_SYMLINK_NOFOLLOW,
        StatxMask::BASIC_STATS,
    ) {
        Ok(st) => Some(st),
        Err(Errno::ENOENT) => None,
        Err(e) => return Err(e.into()),
    };
    if opts.noclobber && existing.is_some() {
        return Err(Errno::EEXIST.into());
    }
    // Adopt the owner only of an existing *regular* file. A symlink (or any
    // other non-regular entry) statx'd with AT_SYMLINK_NOFOLLOW reports its own
    // uid/gid rather than a target's, so treat those as a new target instead of
    // fchowning the published file to that owner.
    let inherit = existing.as_ref().filter(|s| s.is_regular());
    let uid = opts.uid.or_else(|| inherit.map(|s| s.uid()));
    let gid = opts.gid.or_else(|| inherit.map(|s| s.gid()));

    // The data lands first, and the owner and mode only once it has.
    //
    // An unprivileged write to a regular file makes the kernel drop its
    // setuid/setgid bits (`file_remove_privs_flags`, `fs/inode.c`, through
    // `setattr_should_drop_suidgid`, `fs/attr.c:63-78`), so a mode applied
    // to the staging file *before* `write_fn` publishes a file that has
    // silently lost them - `mode: 0o4755` arriving as `0o755` with an `Ok`
    // return. Invisible to a privileged writer, which keeps them under
    // `CAP_FSETID`, so this order is what makes the option mean the same
    // thing for both. `copy_into` states the same rule for `copytree`.
    //
    // The same ordering closes the other half: chowning the staging file to
    // the target uid while it is still empty hands that uid a window on the
    // bytes as they are written. `create_temp` stages owner-private for as
    // long as that window lasts.
    let (tmp_name, mut file) = create_temp(dir, name)?;
    let staged = write_fn(&mut file)
        .and_then(|()| file.flush())
        .map_err(|e| Error::from(Errno::try_from(e).unwrap_or(Errno::EIO)))
        .and_then(|()| set_owner_and_mode(&file, uid, gid, opts.mode))
        .and_then(|()| {
            file.sync_all().map_err(|e| {
                Error::from(Errno::try_from(e).unwrap_or(Errno::EIO))
            })
        });
    drop(file);
    if let Err(e) = staged {
        let _ = unlinkat(dir, &tmp_name);
        return Err(e);
    }

    // Move into place.
    if let Err(e) =
        rename_into_place(dir, tmp_name.as_os_str(), name, opts.noclobber)
    {
        let _ = unlinkat(dir, &tmp_name);
        return Err(e);
    }
    // The new directory entry (and the removal of the replaced one) is only
    // durable once the directory itself is synced.
    fsync_dir(dir)?;
    Ok(())
}

/// Move `tmp_name` onto `name` within `dir`, choosing the `renameat2` mode from
/// the destination's state as it stands immediately before the rename.
///
/// `RENAME_EXCHANGE` needs an existing destination (`ENOENT` otherwise) and
/// displaces a directory found there rather than refusing it, so it is used
/// only for a non-directory destination; a plain rename covers a missing
/// destination and fails `EISDIR` on a directory. The probe races other
/// writers, so an `ENOENT` from the exchange falls back to the plain rename --
/// the destination it would have replaced is gone either way.
fn rename_into_place(
    dir: BorrowedFd<'_>,
    tmp_name: &OsStr,
    name: &OsStr,
    noclobber: bool,
) -> Result<()> {
    if noclobber {
        renameat2(dir, tmp_name, dir, name, RenameFlags::RENAME_NOREPLACE)?;
        return Ok(());
    }
    let replacing = match statx(
        dir,
        name,
        AtFlags::AT_SYMLINK_NOFOLLOW,
        StatxMask::BASIC_STATS,
    ) {
        Ok(st) => !st.is_dir(),
        Err(Errno::ENOENT) => false,
        Err(e) => return Err(e.into()),
    };
    if replacing {
        match renameat2(dir, tmp_name, dir, name, RenameFlags::RENAME_EXCHANGE)
        {
            // The old target now sits at the temp name; remove it.
            Ok(()) => {
                let _ = unlinkat(dir, tmp_name);
                return Ok(());
            }
            Err(Errno::ENOENT) => {}
            Err(e) => return Err(e.into()),
        }
    }
    renameat2(dir, tmp_name, dir, name, RenameFlags::empty())?;
    Ok(())
}

/// Atomically replace `target` with `data` (a convenience over
/// [`atomic_write`]).
pub fn atomic_replace(
    target: &Path,
    data: &[u8],
    opts: AtomicWriteOptions,
) -> Result<()> {
    atomic_write(target, opts, |f| f.write_all(data))
}

/// Create a uniquely-named temporary file beside `target_name` in `dir`.
///
/// The suffix is 128 random bits from `getrandom(2)`, so a single
/// `O_CREAT | O_EXCL` open is collision-free in practice - no retry loop and no
/// shared counter. A collision (never expected) simply surfaces as `EEXIST`.
fn create_temp(
    dir: BorrowedFd<'_>,
    target_name: &OsStr,
) -> Result<(OsString, File)> {
    let mut rand = [0u8; 16];
    // getrandom fully fills any request of <= 256 bytes (flags 0), so on success
    // the whole buffer is populated; only the error case needs handling.
    retry_on_eintr(|| unsafe {
        libc::getrandom(rand.as_mut_ptr().cast(), rand.len(), 0)
    })?;
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut suffix = String::with_capacity(rand.len() * 2);
    for b in rand {
        suffix.push(char::from(HEX[(b >> 4) as usize]));
        suffix.push(char::from(HEX[(b & 0x0f) as usize]));
    }

    let mut name = OsString::from(".");
    name.push(target_name);
    name.push(".tmp.");
    name.push(suffix);

    let how = OpenHow::new()
        .flags(
            OFlag::O_CREAT
                | OFlag::O_EXCL
                | OFlag::O_WRONLY
                | OFlag::O_NOFOLLOW
                | OFlag::O_CLOEXEC,
        )
        // Owner-private while the caller writes: the real mode - and the
        // real owner - land afterwards, so nothing else can read the file
        // through the staging name while it is being filled.
        .mode(Mode::from_bits_truncate(0o600))
        .resolve(ResolveFlag::RESOLVE_NO_SYMLINKS);
    let fd = openat2(dir, name.as_os_str(), how)?;
    Ok((name, File::from(fd)))
}

/// Set the temp file's owner and mode explicitly. A fresh `open`'s mode is
/// masked by the umask, but `fchmod` (via [`File::set_permissions`]) is not.
/// `None` uid/gid are left unchanged.
fn set_owner_and_mode(
    file: &File,
    uid: Option<u32>,
    gid: Option<u32>,
    mode: u32,
) -> Result<()> {
    if uid.is_some() || gid.is_some() {
        // (uid_t)-1 / (gid_t)-1 means "leave unchanged".
        let u = uid.unwrap_or(u32::MAX);
        let g = gid.unwrap_or(u32::MAX);
        retry_on_eintr(|| unsafe { libc::fchown(file.as_raw_fd(), u, g) })?;
    }
    file.set_permissions(Permissions::from_mode(mode & 0o7777))
        .map_err(|e| Errno::try_from(e).unwrap_or(Errno::EIO))?;
    Ok(())
}

/// `fsync` a directory fd, committing the entries created and removed in it.
fn fsync_dir(dir: BorrowedFd<'_>) -> Result<()> {
    retry_on_eintr(|| unsafe { libc::fsync(dir.as_raw_fd()) })?;
    Ok(())
}

fn unlinkat(dir: BorrowedFd<'_>, name: &OsStr) -> Result<()> {
    name.with_tn_path(|c| {
        retry_on_eintr(|| unsafe {
            libc::unlinkat(dir.as_raw_fd(), c.as_ptr(), 0)
        })
    })??;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::{FromRawFd, OwnedFd};

    #[test]
    fn fsync_dir_reports_a_failed_sync() {
        // A pipe has nothing to commit, so fsync rejects it with EINVAL.
        let mut fds = [-1; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let read_end = unsafe { OwnedFd::from_raw_fd(fds[0]) };
        let _write_end = unsafe { OwnedFd::from_raw_fd(fds[1]) };
        assert!(matches!(
            fsync_dir(read_end.as_fd()),
            Err(Error::Errno(Errno::EINVAL))
        ));
    }

    /// The mode lands **after** the data, so a setuid/setgid bit survives to
    /// the published file.
    ///
    /// An unprivileged write to a regular file makes the kernel drop those
    /// bits (`file_remove_privs_flags`, `fs/inode.c`, via
    /// `setattr_should_drop_suidgid`, `fs/attr.c:63-78`), so a mode applied
    /// to the staging file before `write_fn` publishes `0o755` for a
    /// requested `0o4755` and returns `Ok`. The effect is **invisible to a
    /// privileged writer**, which keeps the bits under `CAP_FSETID` - so
    /// what is asserted here is the order itself, which a test can see
    /// whatever it is running as: the staging file the caller is handed is
    /// still owner-private, and the mode only appears afterwards.
    #[test]
    fn the_mode_lands_after_the_data_not_before_it() {
        use std::os::unix::fs::MetadataExt;
        let dir = crate::tempdir().unwrap();
        let target = dir.path().join("cfg");

        let seen = std::cell::Cell::new(0u32);
        atomic_write(
            &target,
            AtomicWriteOptions {
                mode: 0o4755,
                ..Default::default()
            },
            |f| {
                seen.set(f.metadata()?.mode() & 0o7777);
                f.write_all(b"payload")
            },
        )
        .expect("write");

        assert_eq!(
            seen.get(),
            0o600,
            "the caller wrote into a file already at its final mode"
        );
        let st = std::fs::metadata(&target).unwrap();
        assert_eq!(st.mode() & 0o7777, 0o4755, "the published mode");
        assert_eq!(std::fs::read(&target).unwrap(), b"payload");
    }

    // A planted symlink must not be followed for the write nor adopted for the
    // published file's ownership; noclobber still treats it as existing.
    #[test]
    fn atomic_write_does_not_follow_or_adopt_a_planted_symlink() {
        use std::os::unix::fs::MetadataExt;
        let dir = crate::tempdir().unwrap();
        let outside = dir.path().join("outside");
        std::fs::write(&outside, b"outside").unwrap();

        let target = dir.path().join("cfg");
        std::os::unix::fs::symlink(&outside, &target).unwrap();
        atomic_replace(&target, b"trusted", AtomicWriteOptions::default())
            .unwrap();

        let md = std::fs::symlink_metadata(&target).unwrap();
        assert!(md.file_type().is_file());
        assert_eq!(std::fs::read(&target).unwrap(), b"trusted");
        // The link's former target is untouched.
        assert_eq!(std::fs::read(&outside).unwrap(), b"outside");
        // The publisher owns the result, not an owner adopted from the link.
        assert_eq!(md.uid(), unsafe { libc::geteuid() });

        // A symlink is still an existing entry for noclobber.
        let link2 = dir.path().join("cfg2");
        std::os::unix::fs::symlink(&outside, &link2).unwrap();
        let nc = AtomicWriteOptions {
            noclobber: true,
            ..Default::default()
        };
        assert!(matches!(
            atomic_replace(&link2, b"x", nc),
            Err(Error::Errno(Errno::EEXIST))
        ));
    }
}
