//! Atomic, symlink-safe file replacement (`atomic_write` / `atomic_replace`).

use super::{
    openat2, renameat2, statx, AtFlags, Mode, OFlag, OpenHow, RenameFlags,
    ResolveFlag, StatxMask,
};
use crate::errno::{retry_on_eintr, Errno};
use crate::error::{Error, Result};
use crate::path::TnPath;
use crate::AT_FDCWD;
use std::ffi::{OsStr, OsString};
use std::fs::{File, Permissions};
use std::io::{self, Write};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

/// Options controlling [`atomic_write`] / [`atomic_replace`].
#[derive(Clone, Copy, Debug)]
pub struct AtomicWriteOptions {
    /// Owner uid to set; `None` preserves the existing file's owner (or leaves
    /// the creator's uid when the target is new).
    pub uid: Option<u32>,
    /// Owner gid to set; `None` preserves the existing file's group.
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
/// filesystem), written, `fsync`ed, then moved into place with `renameat2` —
/// either a plain rename (new file), an atomic `RENAME_EXCHANGE` (replacing an
/// existing file so readers never see a partial write), or `RENAME_NOREPLACE`
/// (with [`AtomicWriteOptions::noclobber`]). The target is only replaced if
/// `write_fn` returns `Ok`; on error the temporary file is removed and `target`
/// is left untouched. Every path component is opened with `RESOLVE_NO_SYMLINKS`.
///
/// `write_fn` receives the temporary [`File`] directly, so it can use the full
/// [`std::io`] API (or anything built on it).
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
            })
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
    let uid = opts.uid.or_else(|| existing.as_ref().map(|s| s.uid()));
    let gid = opts.gid.or_else(|| existing.as_ref().map(|s| s.gid()));

    // Create the temp file, set its owner/mode, then hand it to the caller.
    let (tmp_name, mut file) = create_temp(dir, name, opts.mode)?;
    if let Err(e) = set_owner_and_mode(&file, uid, gid, opts.mode) {
        let _ = unlinkat(dir, &tmp_name);
        return Err(e);
    }
    let written = write_fn(&mut file)
        .and_then(|()| file.flush())
        .and_then(|()| file.sync_all());
    drop(file);
    if let Err(e) = written {
        let _ = unlinkat(dir, &tmp_name);
        return Err(Errno::try_from(e).unwrap_or(Errno::EIO).into());
    }

    // Move into place with the semantics chosen above.
    let flags = if opts.noclobber {
        RenameFlags::RENAME_NOREPLACE
    } else if existing.is_some() {
        RenameFlags::RENAME_EXCHANGE
    } else {
        RenameFlags::empty()
    };
    if let Err(e) = renameat2(dir, tmp_name.as_os_str(), dir, name, flags) {
        let _ = unlinkat(dir, &tmp_name);
        return Err(e.into());
    }
    // After EXCHANGE the old target now sits at the temp name; remove it.
    if existing.is_some() && !opts.noclobber {
        let _ = unlinkat(dir, &tmp_name);
    }
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
/// `O_CREAT | O_EXCL` open is collision-free in practice — no retry loop and no
/// shared counter. A collision (never expected) simply surfaces as `EEXIST`.
fn create_temp(
    dir: BorrowedFd<'_>,
    target_name: &OsStr,
    mode: u32,
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
        .mode(Mode::from_bits_truncate(mode as libc::mode_t))
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

fn unlinkat(dir: BorrowedFd<'_>, name: &OsStr) -> Result<()> {
    name.with_tn_path(|c| {
        retry_on_eintr(|| unsafe {
            libc::unlinkat(dir.as_raw_fd(), c.as_ptr(), 0)
        })
    })??;
    Ok(())
}
