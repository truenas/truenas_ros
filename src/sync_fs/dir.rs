//! Whole-directory name reads over an already-open descriptor.
//!
//! The base layer's answer to "what does this directory hold": one
//! call, one `Vec` of raw names with the type `readdir` reported for
//! each. There is no io_uring `getdents` opcode, so an async consumer
//! runs [`read_names`] inside an offload job over a descriptor its
//! credential-checked step already opened. The traversal built on the
//! same stream is [`iter`](crate::sync_fs::iter) (feature `fsiter`),
//! which owns descent, resume and mount pinning; this module is
//! deliberately smaller — names out, nothing followed, nothing opened.

use std::ffi::CStr;
use std::os::fd::{AsFd, IntoRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::ptr::NonNull;

use crate::errno::{self, Errno};

/// The type `readdir` reported for one name, straight from `d_type`.
///
/// A hint, not a verdict: a filesystem may decline to fill it
/// ([`Unknown`](NameKind::Unknown)), and an entry can change type
/// between the read and any later open — a consumer acting on the kind
/// confirms it against the file it opens, as
/// [`iter`](crate::sync_fs::iter) does.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NameKind {
    /// `DT_DIR`.
    Dir,
    /// `DT_REG`.
    File,
    /// `DT_LNK`.
    Symlink,
    /// A FIFO, socket, or block/character device.
    Other,
    /// `DT_UNKNOWN`: the filesystem did not fill `d_type`.
    Unknown,
}

impl NameKind {
    fn from_d_type(d_type: u8) -> NameKind {
        match d_type {
            libc::DT_DIR => NameKind::Dir,
            libc::DT_REG => NameKind::File,
            libc::DT_LNK => NameKind::Symlink,
            libc::DT_UNKNOWN => NameKind::Unknown,
            _ => NameKind::Other,
        }
    }
}

/// One name from [`read_names`]: bytes exactly as the directory holds
/// them — no UTF-8 assumption — with `.` and `..` already dropped.
#[derive(Debug)]
pub struct DirEntryName {
    /// The entry's name bytes.
    pub name: Vec<u8>,
    /// What `readdir` said it is.
    pub kind: NameKind,
}

/// Read every name in the directory open at `fd`, in filesystem order.
///
/// One full drain per call: the stream is rewound first, so the result
/// is the whole directory regardless of where the descriptor's offset
/// sits. The stream runs on a dup, but a dup shares the original's file
/// description, so the caller's offset is spent by the read — this is a
/// consuming read of the position, not a peek. Order is the
/// filesystem's own (ZAP hash order on ZFS); a sorted view is the
/// caller's sort.
pub fn read_names(fd: impl AsFd) -> errno::Result<Vec<DirEntryName>> {
    let dup = fd
        .as_fd()
        .try_clone_to_owned()
        .map_err(|e| Errno::from_raw(e.raw_os_error().unwrap_or(libc::EIO)))?;
    let mut dir = Dir::from_fd(dup)?;
    dir.rewind();
    let mut names = Vec::new();
    while let Some(ent) = dir.next_entry()? {
        let bytes = ent.name.as_bytes();
        if bytes == b"." || bytes == b".." {
            continue;
        }
        names.push(DirEntryName {
            kind: NameKind::from_d_type(ent.d_type),
            name: ent.name.into_vec(),
        });
    }
    Ok(names)
}

/// One directory entry read from a [`Dir`].
pub(crate) struct DirEntry {
    pub(crate) d_type: u8,
    pub(crate) d_ino: u64,
    pub(crate) name: std::ffi::OsString,
}

/// A minimal RAII wrapper over a `DIR *` from `fdopendir`.
pub(crate) struct Dir(NonNull<libc::DIR>);

// SAFETY: a `Dir` owns its `DIR` exclusively and is never shared, so it may be
// moved between threads. It is deliberately not `Sync`: concurrent `readdir`
// on one stream is unsafe.
unsafe impl Send for Dir {}

impl Dir {
    /// Take ownership of `fd` and open a directory stream on it.
    pub(crate) fn from_fd(fd: OwnedFd) -> errno::Result<Dir> {
        let raw = fd.into_raw_fd();
        // SAFETY: `raw` is a fresh owned dir fd; fdopendir takes ownership.
        let dirp = unsafe { libc::fdopendir(raw) };
        match NonNull::new(dirp) {
            Some(p) => Ok(Dir(p)),
            None => {
                let err = Errno::last();
                // SAFETY: fdopendir failed, so it did not take ownership.
                unsafe { libc::close(raw) };
                Err(err)
            }
        }
    }

    pub(crate) fn fd(&self) -> RawFd {
        // SAFETY: `self.0` is a live DIR stream.
        unsafe { libc::dirfd(self.0.as_ptr()) }
    }

    /// Reset the stream to the directory's start.
    fn rewind(&mut self) {
        // SAFETY: `self.0` is a live DIR stream we own exclusively.
        unsafe { libc::rewinddir(self.0.as_ptr()) };
    }

    pub(crate) fn next_entry(&mut self) -> errno::Result<Option<DirEntry>> {
        // readdir signals end-of-directory and error both with NULL; clear
        // errno first to tell them apart.
        Errno::clear();
        // SAFETY: `self.0` is a live DIR stream we own exclusively.
        let ent = unsafe { libc::readdir(self.0.as_ptr()) };
        if ent.is_null() {
            return match Errno::last_raw() {
                0 => Ok(None),
                e => Err(Errno::from_raw(e)),
            };
        }
        // SAFETY: `ent` points into the DIR buffer, valid until the next
        // readdir/closedir; we copy the fields out immediately.
        let ent = unsafe { &*ent };
        let name = unsafe { CStr::from_ptr(ent.d_name.as_ptr()) };
        Ok(Some(DirEntry {
            d_type: ent.d_type,
            d_ino: ent.d_ino,
            name: std::ffi::OsStr::from_bytes(name.to_bytes()).to_os_string(),
        }))
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        // SAFETY: `self.0` is a live DIR stream; closedir closes its fd.
        unsafe { libc::closedir(self.0.as_ptr()) };
    }
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsFd;

    use super::*;

    /// The one caller shape this exists for: a directory holding every
    /// kind `readdir` can report, read whole through an fd.
    #[test]
    fn every_name_comes_back_with_its_kind() {
        let tmp = crate::tempdir().expect("tempdir");
        std::fs::write(tmp.path().join("plain"), b"x").expect("file");
        std::fs::create_dir(tmp.path().join("sub")).expect("dir");
        std::os::unix::fs::symlink("plain", tmp.path().join("link"))
            .expect("symlink");
        let fifo = std::ffi::CString::new(
            tmp.path().join("pipe").into_os_string().into_vec(),
        )
        .expect("path");
        // SAFETY: `fifo` is a NUL-terminated path we own.
        let rc = unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) };
        assert_eq!(rc, 0, "mkfifo: {}", Errno::last());

        let dirf = std::fs::File::open(tmp.path()).expect("open dir");
        let mut got = read_names(dirf.as_fd()).expect("read_names");
        got.sort_by(|a, b| a.name.cmp(&b.name));
        let view: Vec<(&[u8], NameKind)> =
            got.iter().map(|e| (&e.name[..], e.kind)).collect();
        assert_eq!(
            view,
            vec![
                (&b"link"[..], NameKind::Symlink),
                (&b"pipe"[..], NameKind::Other),
                (&b"plain"[..], NameKind::File),
                (&b"sub"[..], NameKind::Dir),
            ],
            "four entries, dot and dot-dot never among them"
        );
    }

    /// An empty directory answers an empty list, not an error.
    #[test]
    fn an_empty_directory_reads_empty() {
        let tmp = crate::tempdir().expect("tempdir");
        let dirf = std::fs::File::open(tmp.path()).expect("open dir");
        let got = read_names(dirf.as_fd()).expect("read_names");
        assert!(got.is_empty());
    }

    /// A descriptor that is not a directory is refused with the
    /// kernel's own answer rather than an empty read.
    #[test]
    fn a_non_directory_is_refused() {
        let tmp = crate::tempdir().expect("tempdir");
        let path = tmp.path().join("plain");
        std::fs::write(&path, b"x").expect("file");
        let f = std::fs::File::open(&path).expect("open file");
        let err = read_names(f.as_fd()).expect_err("must refuse");
        assert_eq!(err, Errno::ENOTDIR);
    }

    /// A consumed offset does not hide entries: the stream is rewound,
    /// so a second read over the same descriptor is the whole directory
    /// again.
    #[test]
    fn a_second_read_is_still_the_whole_directory() {
        let tmp = crate::tempdir().expect("tempdir");
        std::fs::write(tmp.path().join("a"), b"").expect("file");
        std::fs::write(tmp.path().join("b"), b"").expect("file");
        let dirf = std::fs::File::open(tmp.path()).expect("open dir");
        let first = read_names(dirf.as_fd()).expect("first");
        let second = read_names(dirf.as_fd()).expect("second");
        assert_eq!(first.len(), 2);
        assert_eq!(second.len(), 2);
    }

    /// The `d_type` mapping, pinned over the raw constants because no
    /// mountable filesystem produces `DT_UNKNOWN` on demand.
    #[test]
    fn the_d_type_mapping_is_total() {
        assert_eq!(NameKind::from_d_type(libc::DT_DIR), NameKind::Dir);
        assert_eq!(NameKind::from_d_type(libc::DT_REG), NameKind::File);
        assert_eq!(NameKind::from_d_type(libc::DT_LNK), NameKind::Symlink);
        assert_eq!(NameKind::from_d_type(libc::DT_UNKNOWN), NameKind::Unknown);
        for special in [
            libc::DT_FIFO,
            libc::DT_SOCK,
            libc::DT_CHR,
            libc::DT_BLK,
            0xEE, // a value no kernel defines stays a special, not a panic
        ] {
            assert_eq!(NameKind::from_d_type(special), NameKind::Other);
        }
    }
}
