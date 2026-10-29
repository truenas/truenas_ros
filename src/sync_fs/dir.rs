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
//!
//! **The descriptor contract.** Everything here reads through a descriptor
//! the caller supplies, and two properties travel with one.
//!
//! A `dup` - `F_DUPFD_CLOEXEC` included - shares the *open file
//! description*, and a directory's read position lives there rather than in
//! the descriptor. Two readers over dups of one description therefore
//! consume each other's entries, and `readdir` reports nothing when they do:
//! the loss is a short listing, not an error. **A shared description is
//! single-reader.** That is not a lock this module can take, because the
//! sharing is invisible from the descriptor number;
//! [`iter::Entry::fd`](crate::sync_fs::iter::Entry::fd) states the same rule
//! for the descriptor a walk hands out.
//!
//! Reopening would buy a private position, and would pay for it in
//! authority: a fresh open is checked against the process that opens it,
//! not against whoever obtained the descriptor it starts from - which in a
//! process running as root is no check at all. So this module dups and
//! spends the position rather than reopening and widening the right, and
//! the position is the caller's to protect.
//!
//! A listing a peer resumes, as NFS READDIR does from a cookie, is
//! [`Listing`]. It reads one entry at a time with the cookie that goes on
//! after it, and starts from any cookie an entry gave, on the same dup and
//! under the same contract.

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
/// One full drain per call: the stream is rewound first, so the result is
/// the whole directory wherever the descriptor's offset sat. The stream
/// runs on a `dup`, which shares the original's open file description, so
/// **the caller's position is spent by the read** - a consuming read of the
/// position, not a peek. A caller that is itself reading `fd`, or that has
/// handed it to a traversal, reopens for a position of its own
/// (`openat(fd, ".", O_RDONLY | O_DIRECTORY)`, as `shutil::reopen_dir`
/// does) before calling here.
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
/// **The dup is what keeps the read on the descriptor's own authority.** A
/// dup carries the access `fd` was opened with and re-checks nothing, so
/// what may be read here is what the opener was already entitled to read.
/// A fresh open would instead be authorized against whoever calls this, and
/// would need a right a dup does not - search (`x`) on the directory - so
/// it would both widen and narrow the wrong way.
///
/// An `O_PATH` handle is a reference carrying no read, and `fdopendir`
/// refuses one with `EBADF`. That refusal is the kernel's, not a check this
/// module makes, and it is why the dup matters:
/// `openat2` through an `O_PATH` descriptor *succeeds*, manufacturing the
/// access it was deliberately opened without.
/// [`Anchor`](crate::uring_fs::Anchor) is such a handle.
///
/// **Unbounded by construction.** One call, one `Vec`, every name: there is
/// no limit, cursor or streaming variant, so a caller holds the whole
/// directory at roughly 46-54 bytes and one allocation per entry. That is
/// the shape a whole-drain wants and it is fine for a directory whose size
/// the caller controls; a listing that a peer can grow belongs on
/// [`uring_fs::query_dir`](crate::uring_fs::query_dir), which pages and
/// enriches. No bounded twin is offered here rather than one being invented
/// for a caller that does not exist - this function has none outside its own
/// tests.
///
/// Order is the filesystem's own (ZAP hash order on ZFS); a sorted view is
/// the caller's sort. The result is a snapshot, not an atomic one: an entry
/// renamed while the drain runs moves relative to the cursor and can be
/// missed or reported twice, which is `readdir`'s contract and not
/// something this layer can close.
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

/// A directory read one entry at a time from a cookie, for a listing that
/// a peer resumes, as NFS READDIR does.
///
/// It reads on a dup of the descriptor it opens over, as [`read_names`]
/// does and under the same contract, so the caller's position is spent.
/// A cookie is what the kernel gives as `d_off`, the position of the entry
/// after the one it came with, and [`seek`](Listing::seek) goes on from
/// there, as `seekdir` does with what `telldir` gave. The cookie 0 is the
/// beginning. On ZFS a cookie is a serialized ZAP cursor, which holds
/// while the folder changes, and the kernel gives the last entry the
/// cursor's end. `.` and `..` are left out, as [`read_names`] leaves them
/// out, and their cookies are never given.
#[derive(Debug)]
pub struct Listing {
    dir: Dir,
    /// The record `readdir` gave last, which the entry lends from, or null
    /// before the first read and at the end.
    last: *mut libc::dirent,
}

/// One entry of a [`Listing`], lent until the next is read.
#[derive(Debug)]
pub struct Entry<'a> {
    /// The entry's name bytes, as the directory holds them.
    pub name: &'a [u8],
    /// What `readdir` said it is.
    pub kind: NameKind,
    /// Its inode number, as `readdir` gives it.
    pub ino: u64,
    /// The cookie of the position after it, which [`Listing::seek`] goes
    /// on from.
    pub cookie: u64,
}

impl Listing {
    /// Open a listing over `fd`, from the beginning, on a dup of it.
    ///
    /// An `O_PATH` descriptor is refused with `EBADF`, as [`read_names`]
    /// says, and what is not a directory with `ENOTDIR`.
    pub fn open(fd: impl AsFd) -> errno::Result<Listing> {
        let dup = fd.as_fd().try_clone_to_owned().map_err(|e| {
            Errno::from_raw(e.raw_os_error().unwrap_or(libc::EIO))
        })?;
        let mut dir = Dir::from_fd(dup)?;
        dir.rewind();
        Ok(Listing {
            dir,
            last: std::ptr::null_mut(),
        })
    }

    /// Go on from `cookie`, which an entry gave, or from the beginning
    /// for 0.
    pub fn seek(&mut self, cookie: u64) {
        self.last = std::ptr::null_mut();
        // SAFETY: `self.dir.0` is a live DIR stream we own exclusively.
        // The cookie goes through as the kernel gave it, which `seekdir`
        // takes as `telldir`'s value.
        unsafe { libc::seekdir(self.dir.0.as_ptr(), cookie as libc::c_long) };
    }

    /// The next entry, or `None` at the end.
    pub fn read(&mut self) -> errno::Result<Option<Entry<'_>>> {
        loop {
            self.last = self.dir.read_record()?;
            if self.last.is_null() {
                return Ok(None);
            }
            // SAFETY: `last` is the record `readdir` just gave, valid until
            // the next read, and the name is looked at and let go here.
            let name = unsafe { fields_of(self.last).3 };
            if name != b"." && name != b".." {
                break;
            }
        }
        // SAFETY: as above, and the entry lends the name for as long as
        // the listing is borrowed, which ends before the next read.
        let (d_type, d_ino, d_off, name) = unsafe { fields_of(self.last) };
        Ok(Some(Entry {
            name,
            kind: NameKind::from_d_type(d_type),
            ino: d_ino,
            cookie: d_off,
        }))
    }
}

/// The type, the inode, the offset after and the name of the record `ent`.
///
/// # Safety
///
/// `ent` points at a record `readdir` gave on a stream that has not been
/// read since, and the name is valid for `'a` only until that stream is
/// read again.
///
/// A `&libc::dirent` must NOT be formed here. The reference would claim all
/// 280 bytes of the struct, `d_name` being a `[c_char; 256]`, over a record
/// only `d_reclen` bytes long. A short-named entry's record is 24 to 40
/// bytes, and the last record in a filled buffer ends where the buffer's
/// valid data does. Measured on ZFS, over 5002 entries the tightest record
/// left 32 valid bytes. The same idiom, with the same reason, is at
/// `uring_fs/core.rs` and `uring_fs/query_dir.rs`. `d_ino`, `d_off` and
/// `d_type` are inside every record's fixed head, before the name.
unsafe fn fields_of<'a>(ent: *mut libc::dirent) -> (u8, u64, u64, &'a [u8]) {
    // SAFETY: the caller's, and every field is read through `addr_of!`.
    unsafe {
        (
            std::ptr::addr_of!((*ent).d_type).read(),
            std::ptr::addr_of!((*ent).d_ino).read(),
            std::ptr::addr_of!((*ent).d_off).read() as u64,
            CStr::from_ptr(
                std::ptr::addr_of!((*ent).d_name).cast::<libc::c_char>(),
            )
            .to_bytes(),
        )
    }
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
#[derive(Debug)]
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

    /// Reset the stream to the directory's start.
    ///
    /// Shared with whatever else holds this open file description, which is
    /// the consuming half of [`read_names`]' contract.
    fn rewind(&mut self) {
        // SAFETY: `self.0` is a live DIR stream we own exclusively.
        unsafe { libc::rewinddir(self.0.as_ptr()) };
    }

    pub(crate) fn next_entry(&mut self) -> errno::Result<Option<DirEntry>> {
        let ent = self.read_record()?;
        if ent.is_null() {
            return Ok(None);
        }
        // SAFETY: `ent` is the record `readdir` just gave, valid until the
        // next read, and every field is copied out before that.
        let (d_type, d_ino, _, name) = unsafe { fields_of(ent) };
        #[cfg(not(feature = "fsiter"))]
        let _ = d_ino;
        Ok(Some(DirEntry {
            d_type,
            #[cfg(feature = "fsiter")]
            d_ino,
            name: std::ffi::OsStr::from_bytes(name).to_os_string(),
        }))
    }

    /// The next record, or null at the end.
    fn read_record(&mut self) -> errno::Result<*mut libc::dirent> {
        // readdir signals end-of-directory and error both with NULL; clear
        // errno first to tell them apart.
        Errno::clear();
        // SAFETY: `self.0` is a live DIR stream we own exclusively.
        let ent = unsafe { libc::readdir(self.0.as_ptr()) };
        if ent.is_null() {
            return match Errno::last_raw() {
                0 => Ok(ent),
                e => Err(Errno::from_raw(e)),
            };
        }
        Ok(ent)
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
    fn a_listing_goes_on_from_a_cookie_and_ends_at_the_last() {
        use std::os::unix::fs::MetadataExt;
        let tmp = crate::tempdir().expect("tempdir");
        for name in ["a", "b", "c", "d", "e"] {
            std::fs::write(tmp.path().join(name), b"x").expect("file");
        }
        std::fs::create_dir(tmp.path().join("sub")).expect("dir");
        let dirf = std::fs::File::open(tmp.path()).expect("open dir");

        // Every entry once, with its inode and its kind, and the cookie of
        // each is neither 0 nor 1 nor 2, which NFS reserves.
        let mut listing = Listing::open(dirf.as_fd()).expect("listing");
        let mut seen = Vec::new();
        while let Some(entry) = listing.read().expect("read") {
            let path = tmp.path().join(std::ffi::OsStr::from_bytes(entry.name));
            let meta = std::fs::symlink_metadata(&path).expect("metadata");
            assert_eq!(entry.ino, meta.ino(), "{path:?}");
            let kind = if meta.is_dir() {
                NameKind::Dir
            } else {
                NameKind::File
            };
            let hinted = entry.kind;
            assert!(hinted == NameKind::Unknown || hinted == kind, "{path:?}");
            assert!(
                entry.cookie > 2,
                "{path:?} has the cookie {}",
                entry.cookie
            );
            seen.push((entry.name.to_vec(), entry.cookie));
        }
        assert_eq!(seen.len(), 6, "dot and dot-dot never among them");

        // From the cookie of the second entry, a fresh listing gives what
        // came after it, and from the cookie of the last, nothing.
        let after_second = seen[1].1;
        let mut rest = Listing::open(dirf.as_fd()).expect("listing");
        rest.seek(after_second);
        let mut names = Vec::new();
        while let Some(entry) = rest.read().expect("read") {
            names.push(entry.name.to_vec());
        }
        let want: Vec<Vec<u8>> =
            seen[2..].iter().map(|(n, _)| n.clone()).collect();
        assert_eq!(names, want);
        let after_last = seen[5].1;
        rest.seek(after_last);
        assert!(rest.read().expect("read").is_none());

        // The cookie 0 is the beginning again.
        rest.seek(0);
        let first = rest.read().expect("read").expect("an entry");
        assert_eq!(first.name, seen[0].0);
    }

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

    /// An `O_PATH` handle is refused, and the refusal is the kernel's.
    ///
    /// `O_PATH` is a reference carrying no read, and `fdopendir` answers one
    /// with `EBADF`. Reading through a dup is what keeps that enforcement:
    /// `openat2` through an `O_PATH` descriptor *succeeds*, manufacturing the
    /// access it was opened without and checking it against this process
    /// rather than whoever obtained the handle - which where this runs as
    /// root is no check at all. [`Anchor::open`](crate::uring_fs::Anchor)
    /// mints exactly this shape and takes `impl AsFd` to get here.
    #[test]
    fn an_o_path_descriptor_is_refused() {
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
        assert_eq!(
            read_names(anchor.as_fd()).expect_err("O_PATH must be refused"),
            Errno::EBADF,
        );

        // The same directory, opened for read, still drains - so the refusal
        // is about the descriptor's access and not about the directory.
        let ok = std::fs::File::open(tmp.path()).expect("open O_RDONLY");
        assert_eq!(read_names(ok.as_fd()).expect("readable").len(), 1);
    }

    /// The drain spends the caller's position, and the reopen the docs
    /// prescribe is what protects it.
    ///
    /// `read_names` rewinds a dup, and a dup shares the open file
    /// description, so a walk holding that same description is left at
    /// end-of-directory and reports an empty remainder with no error. That
    /// is the contract: the alternative - reopening for a private position -
    /// re-authorizes the read against whoever calls, and an `O_PATH` handle
    /// reopens just fine. Callers that care reopen first, as
    /// `shutil::reopen_dir` does.
    ///
    /// The frame is deliberately unread before the drain: glibc buffers a
    /// whole `getdents64` at the first `readdir`, which would hide the moved
    /// offset on a small directory.
    #[test]
    fn a_drain_spends_the_position_and_a_reopen_protects_it() {
        let tmp = crate::tempdir().expect("tempdir");
        for i in 0..50 {
            std::fs::write(tmp.path().join(format!("f{i:03}")), b"x")
                .expect("file");
        }

        // Sharing the description: the walk loses its remainder.
        let dirf = std::fs::File::open(tmp.path()).expect("open dir");
        let dup = dirf.as_fd().try_clone_to_owned().expect("dup");
        let mut walk = Dir::from_fd(dup).expect("fdopendir");
        assert_eq!(read_names(dirf.as_fd()).expect("drain").len(), 50);
        let mut seen = 0usize;
        while walk.next_entry().expect("walk").is_some() {
            seen += 1;
        }
        assert!(
            seen < 52,
            "a shared description is single-reader: the drain spends it"
        );

        // A description of its own: untouched.
        let dirf2 = std::fs::File::open(tmp.path()).expect("open dir");
        let own = crate::sync_fs::openat2(
            dirf2.as_fd(),
            ".",
            crate::sync_fs::OpenHow::new().flags(
                crate::sync_fs::OFlag::O_RDONLY
                    | crate::sync_fs::OFlag::O_DIRECTORY,
            ),
        )
        .expect("reopen");
        let mut walk2 = Dir::from_fd(own).expect("fdopendir");
        assert_eq!(read_names(dirf2.as_fd()).expect("drain").len(), 50);
        let mut seen2 = 0usize;
        while walk2.next_entry().expect("walk").is_some() {
            seen2 += 1;
        }
        assert_eq!(seen2, 52, "50 files plus . and .., all still there");
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
