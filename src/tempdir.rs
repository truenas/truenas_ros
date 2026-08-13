//! `mkdtemp(3)` — a scratch directory, removed when its handle drops.

use crate::errno::{self, Errno};
use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;
use std::path::{Path, PathBuf};

/// A directory created by [`tempdir`]. Dropping the handle removes the
/// directory and everything under it, best-effort: scratch left behind
/// by a failed removal is not worth a panic mid-drop.
#[derive(Debug)]
pub struct TempDir {
    path: PathBuf,
}

impl TempDir {
    /// The directory's path.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl AsRef<Path> for TempDir {
    fn as_ref(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Create a fresh `truenas-ros.??????` directory, mode 0700, under the
/// environment's temporary directory (`TMPDIR`, else `/tmp`), named and
/// created atomically by `mkdtemp(3)`.
pub fn tempdir() -> errno::Result<TempDir> {
    let mut template = std::env::temp_dir();
    template.push("truenas-ros.XXXXXX");
    let mut buf = template.into_os_string().into_vec();
    buf.push(0);
    // SAFETY: `buf` is writable, NUL-terminated, and ends in the XXXXXX
    // placeholder mkdtemp rewrites in place; the returned pointer is
    // `buf`'s own or null.
    let ret = unsafe { libc::mkdtemp(buf.as_mut_ptr().cast()) };
    if ret.is_null() {
        return Err(Errno::last());
    }
    buf.pop(); // the NUL
    Ok(TempDir {
        path: PathBuf::from(OsString::from_vec(buf)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The directory must exist, be a directory, and carry mkdtemp's
    /// 0700 — scratch readable by other users would leak test content.
    #[test]
    fn creates_a_private_directory() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let meta = std::fs::metadata(dir.path()).unwrap();
        assert!(meta.is_dir());
        assert_eq!(meta.permissions().mode() & 0o777, 0o700);
    }

    /// Two handles must never alias one directory.
    #[test]
    fn each_call_is_a_distinct_directory() {
        let a = tempdir().unwrap();
        let b = tempdir().unwrap();
        assert_ne!(a.path(), b.path());
    }

    /// Drop removes the directory with its contents, nested included.
    #[test]
    fn drop_removes_recursively() {
        let dir = tempdir().unwrap();
        let kept = dir.path().to_path_buf();
        std::fs::create_dir(kept.join("sub")).unwrap();
        std::fs::write(kept.join("sub/f"), b"x").unwrap();
        drop(dir);
        assert!(!kept.exists());
    }
}
