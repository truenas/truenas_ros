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
use std::os::fd::{AsFd, IntoRawFd, OwnedFd};
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
/// One full drain per call, over a descriptor of its own: `openat2(fd,
/// ".")` gives a fresh file description, so `fd` may be an `O_PATH`
/// handle - which `fdopendir` refuses outright - and its position is left
/// where it was found.
///
/// **A `dup` cannot serve, and is not cheaper.** `fdopendir` rejects it
/// for the same `O_PATH` reason, since a dup carries the original's
/// access mode; and it *shares* the original's file description, so
/// rewinding it to read from the start rewinds the caller's stream and
/// the drain then leaves that at EOF - which makes a traversal that calls
/// this on a directory it is walking
/// ([`iter::Entry::fd`](crate::sync_fs::iter::Entry::fd), whose frame
/// descends on a dup of that same fd) lose the rest of that directory
/// with no error to say so. The dup also costs one syscall *more*: it
/// needs a `rewinddir`, and the reopen does not.
///
/// The reopen costs one right a dup does not need: search (`x`) permission
/// on the directory, under the *calling* process's credentials. A caller
/// holding a descriptor it can no longer traverse gets `EACCES`.
///
/// Order is the filesystem's own (ZAP hash order on ZFS); a sorted view is
/// the caller's sort. The result is a snapshot, not an atomic one: an entry
/// renamed while the drain runs moves relative to the cursor and can be
/// missed or reported twice, which is `readdir`'s contract and not
/// something this layer can close.
pub fn read_names(fd: impl AsFd) -> errno::Result<Vec<DirEntryName>> {
    let own = crate::sync_fs::openat2(
        fd.as_fd(),
        ".",
        crate::sync_fs::OpenHow::new()
            .flags(
                crate::sync_fs::OFlag::O_RDONLY
                    | crate::sync_fs::OFlag::O_DIRECTORY
                    | crate::sync_fs::OFlag::O_CLOEXEC,
            )
            .resolve(crate::sync_fs::ResolveFlag::RESOLVE_NO_SYMLINKS),
    )?;
    let mut dir = Dir::from_fd(own)?;
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
    /// Consulted only by the traversal's resume seek.
    #[cfg(feature = "fsiter")]
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

    /// The stream's descriptor, which the traversal opens entries
    /// relative to.
    #[cfg(feature = "fsiter")]
    pub(crate) fn fd(&self) -> std::os::fd::RawFd {
        // SAFETY: `self.0` is a live DIR stream.
        unsafe { libc::dirfd(self.0.as_ptr()) }
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
        // readdir/closedir; every field is read through `addr_of!` and
        // copied out immediately.
        //
        // A `&libc::dirent` must NOT be formed here. The reference would
        // claim all 280 bytes of the struct - `d_name` is a `[c_char; 256]`
        // - over a record only `d_reclen` bytes long: a short-named entry's
        // record is 24-40 bytes, and the last record in a filled buffer ends
        // where the buffer's valid data does. Measured on ZFS: over 5002
        // entries the tightest record left 32 valid bytes. The same idiom,
        // with the same reason, is at `uring_fs/core.rs` and
        // `uring_fs/query_dir.rs`.
        let (d_type, name) = unsafe {
            (
                std::ptr::addr_of!((*ent).d_type).read(),
                CStr::from_ptr(
                    std::ptr::addr_of!((*ent).d_name).cast::<libc::c_char>(),
                ),
            )
        };
        Ok(Some(DirEntry {
            d_type,
            #[cfg(feature = "fsiter")]
            // SAFETY: as above; `d_ino` is inside every record's fixed head.
            d_ino: unsafe { std::ptr::addr_of!((*ent).d_ino).read() },
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

    /// The record `readdir` hands back is `d_reclen` bytes, which is far
    /// less than `size_of::<libc::dirent>()` - the invariant that makes
    /// `next_entry`'s `addr_of!` reads necessary rather than stylistic.
    ///
    /// Forming a `&libc::dirent` requires all 280 bytes to be
    /// dereferenceable; a short-named entry's record is a tenth of that, and
    /// the last record in a filled buffer ends exactly where the valid data
    /// does. Driven over raw `getdents64` so the valid region is known
    /// precisely; glibc's `readdir` hands out pointers into a buffer filled
    /// the same way.
    #[test]
    fn a_directory_record_is_shorter_than_the_struct_that_describes_it() {
        use std::os::fd::AsRawFd;
        let tmp = crate::tempdir().expect("tempdir");
        for i in 0..64 {
            std::fs::write(tmp.path().join(format!("n{i:02}")), b"")
                .expect("file");
        }
        let f = std::fs::File::open(tmp.path()).expect("open dir");
        let mut buf = [0u8; 512];
        // SAFETY: a live directory fd and a buffer of its own length.
        let n = unsafe {
            libc::syscall(
                libc::SYS_getdents64,
                f.as_raw_fd(),
                buf.as_mut_ptr(),
                buf.len(),
            )
        };
        assert!(n > 0, "getdents64: {}", Errno::last());
        let n = n as usize;
        let (mut shortest, mut tightest) = (usize::MAX, usize::MAX);
        let mut off = 0usize;
        while off < n {
            // SAFETY: `off` is inside the filled region and each record's
            // fixed head is within it; `d_reclen` walks to the next.
            let reclen = unsafe {
                let ent = buf.as_ptr().add(off).cast::<libc::dirent64>();
                std::ptr::addr_of!((*ent).d_reclen).read() as usize
            };
            assert!(reclen > 0 && off + reclen <= n, "malformed d_reclen");
            shortest = shortest.min(reclen);
            tightest = tightest.min(n - off);
            off += reclen;
        }
        let claimed = std::mem::size_of::<libc::dirent>();
        assert!(
            shortest < claimed,
            "shortest record {shortest} B, &libc::dirent claims {claimed} B"
        );
        assert!(
            tightest < claimed,
            "the last record leaves {tightest} valid bytes and a \
             &libc::dirent formed there would claim {claimed}"
        );
    }

    /// A drain must not spend the position of a stream that shares the
    /// caller's file description.
    ///
    /// This is the traversal shape: `iter::FsIter` descends by `dup`ping the
    /// entry fd it just handed the caller and opening a `DIR` on the dup, so
    /// the frame and `Entry::fd()` are one description. A drain that rewound
    /// that description and walked it to EOF - which is what a `dup` plus
    /// `rewinddir` does - left the walk at end-of-directory, and the walk
    /// reported an empty subtree with no error. The frame is deliberately
    /// unread here: glibc buffers a whole `getdents64` at the first
    /// `readdir`, which would hide the moved offset on a small directory.
    #[test]
    fn a_drain_leaves_a_walk_over_the_same_descriptor_intact() {
        let tmp = crate::tempdir().expect("tempdir");
        for i in 0..50 {
            std::fs::write(tmp.path().join(format!("f{i:03}")), b"x")
                .expect("file");
        }
        let dirf = std::fs::File::open(tmp.path()).expect("open dir");
        let dup = dirf.as_fd().try_clone_to_owned().expect("dup");
        let mut walk = Dir::from_fd(dup).expect("fdopendir");

        assert_eq!(read_names(dirf.as_fd()).expect("drain").len(), 50);

        let mut seen = 0usize;
        while let Some(e) = walk.next_entry().expect("next_entry") {
            let n = e.name.as_bytes();
            if n != b"." && n != b".." {
                seen += 1;
            }
        }
        assert_eq!(
            seen, 50,
            "the drain consumed the walk's own position: it reopens rather \
             than duplicating precisely so this cannot happen"
        );
    }

    /// The caller's own offset is likewise untouched - the drain reads a
    /// file description of its own.
    #[test]
    fn a_drain_leaves_the_descriptor_offset_where_it_found_it() {
        use std::os::fd::AsRawFd;
        let tmp = crate::tempdir().expect("tempdir");
        for i in 0..8 {
            std::fs::write(tmp.path().join(format!("n{i}")), b"").expect("f");
        }
        let dirf = std::fs::File::open(tmp.path()).expect("open dir");
        // SAFETY: `dirf` is a live directory descriptor.
        let before =
            unsafe { libc::lseek(dirf.as_raw_fd(), 0, libc::SEEK_CUR) };
        assert_eq!(read_names(dirf.as_fd()).expect("drain").len(), 8);
        // SAFETY: same descriptor, still live.
        let after = unsafe { libc::lseek(dirf.as_raw_fd(), 0, libc::SEEK_CUR) };
        assert_eq!(before, after, "the drain spent the caller's position");
    }

    /// The consumer the module documents - "a descriptor its
    /// credential-checked step already opened" - hands on an `O_PATH`
    /// handle, which `fdopendir` refuses with `EBADF`. Reopening through it
    /// is what makes that shape work.
    #[test]
    fn an_o_path_descriptor_is_readable() {
        use std::os::fd::{FromRawFd, OwnedFd};
        let tmp = crate::tempdir().expect("tempdir");
        std::fs::write(tmp.path().join("a"), b"").expect("file");
        let c = std::ffi::CString::new(tmp.path().as_os_str().as_bytes())
            .expect("path");
        // SAFETY: a NUL-terminated path we own; O_PATH takes no rights.
        let raw = unsafe {
            libc::open(
                c.as_ptr(),
                libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        assert!(raw >= 0, "open O_PATH: {}", Errno::last());
        // SAFETY: `raw` is a fresh owned descriptor.
        let anchor = unsafe { OwnedFd::from_raw_fd(raw) };
        let got = read_names(anchor.as_fd()).expect("read_names on O_PATH");
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].name, b"a");
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
