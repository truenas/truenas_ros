//! Symlink-safe open (`safe_open`).

use super::{Mode, OFlag, OpenHow, ResolveFlag, openat2};
use crate::errno::Errno;
use crate::error::{Error, Result};
use std::fs::File;
use std::os::fd::AsFd;
use std::path::Path;

/// Open `path` relative to `dirfd` as a [`File`], rejecting any symbolic link in the path.
///
/// Uses `openat2(RESOLVE_NO_SYMLINKS)`, so a symlink at *any* component fails with [`Error::SymlinkInPath`] (rather
/// than being followed) - closing the TOCTOU window a plain `open` would leave.
pub fn safe_open<Fd: AsFd>(dirfd: Fd, path: &Path, flags: OFlag, mode: Mode) -> Result<File> {
    let how = OpenHow::new()
        .flags(flags)
        .mode(mode)
        .resolve(ResolveFlag::RESOLVE_NO_SYMLINKS);
    match openat2(dirfd, path, how) {
        Ok(fd) => Ok(File::from(fd)),
        Err(Errno::ELOOP) => Err(Error::SymlinkInPath {
            path: path.to_path_buf(),
        }),
        Err(e) => Err(e.into()),
    }
}
