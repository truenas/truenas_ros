//! Single-filesystem depth-first traversal (`iter_filesystem_contents`).
//!
//! [`FsIter`] is a normal [`Iterator`] yielding owned [`Entry`] values, each
//! owning an [`OwnedFd`] to the file it names. Traversal stays within one
//! filesystem (via `openat2(RESOLVE_NO_XDEV)`) and never follows symlinks
//! (`RESOLVE_NO_SYMLINKS`); entries are opened relative to their parent
//! directory fd. The caller drives the loop, so progress reporting is just the
//! caller's own bookkeeping (there is no internal callback).
//!
//! This is a from-scratch Rust rewrite, not a translation of the `truenas_os` C
//! extension's manual directory-stack / fd-recycling machinery — but it does
//! reproduce that extension's **recovery-cookie** resume feature natively (see
//! [`Cookie`]).
//!
//! # Resuming an interrupted traversal
//!
//! [`FsIter::cookie`] snapshots the current directory stack as a [`Cookie`] —
//! an ordered list of `(path, inode)` levels from the root down. Persist it
//! (via [`Cookie::to_bytes`]) alongside [`FsIter::stats`] every so often, and a
//! later run — even a fresh process after a crash — can resume *near* where it
//! left off:
//!
//! ```no_run
//! # use truenas_ros::iter::{Cookie, FsIterBuilder};
//! # let saved_bytes: Vec<u8> = Vec::new();
//! let cookie = Cookie::from_bytes(&saved_bytes).unwrap();
//! let it = FsIterBuilder::new("/mnt/tank", "tank")
//!     .resume_from(cookie)
//!     .build()
//!     .unwrap();
//! ```
//!
//! Resume is **best-effort / at-least-once**: ancestor directories continue at
//! the exact position they were interrupted, but the single deepest saved
//! directory is re-read from its start, so a few of its already-processed
//! entries may be yielded again — de-duplicate downstream if you need
//! exactly-once. If a saved directory no longer exists or changed inode,
//! [`FsIterBuilder::build`] returns [`Error::IteratorRestore`]; recover by
//! [`Cookie::truncate`]-ing to that `depth` and rebuilding.

use crate::errno::{self, retry_on_eintr, Errno};
use crate::error::{Error, Result};
use crate::fd::owned_from_raw;
use crate::fs::{
    openat2, statx, AtFlags, OFlag, OpenHow, ResolveFlag, Statx, StatxMask,
};
use crate::mount::{statmount, StatmountMask};
use crate::AT_FDCWD;
use std::ffi::{CStr, OsStr, OsString};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, IntoRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr::NonNull;

/// Upper bound on directory-tree depth (bounds simultaneously-open dir fds).
const MAX_DEPTH: usize = 2048;

const ITER_MASK: StatxMask = StatxMask::BASIC_STATS
    .union(StatxMask::BTIME)
    .union(StatxMask::MNT_ID_UNIQUE);
const ITER_AT: AtFlags =
    AtFlags::AT_EMPTY_PATH.union(AtFlags::AT_SYMLINK_NOFOLLOW);
const ITER_RESOLVE: ResolveFlag =
    ResolveFlag::RESOLVE_NO_XDEV.union(ResolveFlag::RESOLVE_NO_SYMLINKS);
const DIR_OFLAGS: OFlag = OFlag::O_NOFOLLOW.union(OFlag::O_DIRECTORY);
const OPATH_OFLAGS: OFlag = OFlag::O_PATH.union(OFlag::O_NOFOLLOW);

fn how(flags: OFlag, resolve: ResolveFlag) -> OpenHow {
    OpenHow::new().flags(flags).resolve(resolve)
}

/// What kind of filesystem object an [`Entry`] refers to.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntryType {
    /// A directory (the iterator descends into it unless `skip_descent`).
    Dir,
    /// A regular file (or any non-dir, non-link, non-mount object).
    File,
    /// A symbolic link (only yielded with `include_symlinks`; fd is `O_PATH`).
    Symlink,
    /// A child mountpoint (only with `include_mountpoints`; fd is `O_PATH`,
    /// never descended into).
    Mountpoint,
}

/// One directory level on the traversal stack.
struct DirFrame {
    path: PathBuf,
    dir: Dir,
    ino: u64,
}

/// A `(path, inode)` pair from [`FsIter::dir_stack`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirStackEntry {
    /// Absolute path of the directory.
    pub path: PathBuf,
    /// Its inode number.
    pub ino: u64,
}

/// A serializable resume token: the directory stack captured by
/// [`FsIter::cookie`], as ordered `(path, inode)` levels from the root down.
///
/// Pass one back to [`FsIterBuilder::resume_from`] to continue a traversal
/// where it left off (best-effort — see the module docs). Persist it across
/// process restarts with [`Cookie::to_bytes`] / [`Cookie::from_bytes`].
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Cookie(Vec<DirStackEntry>);

/// Magic prefixing a [`Cookie::to_bytes`] blob (`"TnCk"`, host-endian).
const COOKIE_MAGIC: u32 = u32::from_ne_bytes(*b"TnCk");
/// On-disk [`Cookie`] format version.
const COOKIE_VERSION: u16 = 1;

impl Cookie {
    /// The saved directory levels, root first.
    pub fn entries(&self) -> &[DirStackEntry] {
        &self.0
    }

    /// Number of saved directory levels.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// True if the cookie holds no levels (resuming from it is a full walk).
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Drop levels below `depth`, keeping the first `depth` entries.
    ///
    /// Use this to recover from [`Error::IteratorRestore`]: trim to the failing
    /// `depth` and rebuild the iterator, which then resumes from the surviving
    /// ancestor directory.
    pub fn truncate(&mut self, depth: usize) {
        self.0.truncate(depth);
    }

    /// Serialize to a self-describing byte blob (versioned, length-prefixed)
    /// suitable for persisting to disk. Paths are stored as raw bytes, so
    /// non-UTF-8 components round-trip exactly.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&COOKIE_MAGIC.to_ne_bytes());
        out.extend_from_slice(&COOKIE_VERSION.to_ne_bytes());
        out.extend_from_slice(&(self.0.len() as u32).to_ne_bytes());
        for e in &self.0 {
            out.extend_from_slice(&e.ino.to_ne_bytes());
            let p = e.path.as_os_str().as_bytes();
            out.extend_from_slice(&(p.len() as u32).to_ne_bytes());
            out.extend_from_slice(p);
        }
        out
    }

    /// Reconstruct a cookie from [`Cookie::to_bytes`] output. Malformed input
    /// (bad magic/version, truncated, or trailing bytes) is
    /// [`Error::Validation`].
    pub fn from_bytes(data: &[u8]) -> Result<Cookie> {
        fn take<'a>(
            cur: &mut &'a [u8],
            n: usize,
            what: &str,
        ) -> Result<&'a [u8]> {
            if cur.len() < n {
                return Err(Error::Validation(format!(
                    "cookie truncated reading {what}"
                )));
            }
            let (head, tail) = cur.split_at(n);
            *cur = tail;
            Ok(head)
        }
        let mut cur = data;
        let magic =
            u32::from_ne_bytes(take(&mut cur, 4, "magic")?.try_into().unwrap());
        if magic != COOKIE_MAGIC {
            return Err(Error::Validation(format!(
                "not a cookie blob (magic {magic:#010x})"
            )));
        }
        let version = u16::from_ne_bytes(
            take(&mut cur, 2, "version")?.try_into().unwrap(),
        );
        if version != COOKIE_VERSION {
            return Err(Error::Validation(format!(
                "unsupported cookie version {version}"
            )));
        }
        let count =
            u32::from_ne_bytes(take(&mut cur, 4, "count")?.try_into().unwrap())
                as usize;
        if count > MAX_DEPTH {
            return Err(Error::Validation(format!(
                "cookie depth {count} exceeds maximum {MAX_DEPTH}"
            )));
        }
        let mut entries = Vec::with_capacity(count);
        for _ in 0..count {
            let ino = u64::from_ne_bytes(
                take(&mut cur, 8, "inode")?.try_into().unwrap(),
            );
            let plen = u32::from_ne_bytes(
                take(&mut cur, 4, "path length")?.try_into().unwrap(),
            ) as usize;
            let path = take(&mut cur, plen, "path")?;
            entries.push(DirStackEntry {
                path: PathBuf::from(OsString::from_vec(path.to_vec())),
                ino,
            });
        }
        if !cur.is_empty() {
            return Err(Error::Validation(format!(
                "cookie has {} trailing byte(s)",
                cur.len()
            )));
        }
        Ok(Cookie(entries))
    }
}

impl From<Vec<DirStackEntry>> for Cookie {
    fn from(entries: Vec<DirStackEntry>) -> Self {
        Cookie(entries)
    }
}

/// A snapshot of iteration progress from [`FsIter::stats`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IterState {
    /// Number of entries yielded so far.
    pub count: u64,
    /// Total size in bytes of the non-directory entries yielded.
    pub bytes: u64,
    /// The directory currently being read (empty once iteration completes).
    pub current_dir: PathBuf,
}

/// An entry produced by [`FsIter`].
///
/// Carries the entry's [`Statx`] metadata and an open [`OwnedFd`] to the object
/// it names. The fd closes automatically when the `Entry` is dropped — callers
/// never close it manually. Use [`Entry::fd`] to borrow it during the entry's
/// lifetime, or [`Entry::into_fd`] to take ownership.
#[derive(Debug)]
pub struct Entry {
    parent: PathBuf,
    name: OsString,
    fd: OwnedFd,
    statx: Statx,
    file_type: EntryType,
}

impl Entry {
    /// The directory containing this entry.
    pub fn parent(&self) -> &Path {
        &self.parent
    }

    /// The entry's name (not a full path).
    pub fn name(&self) -> &OsStr {
        &self.name
    }

    /// The full path (`parent / name`).
    pub fn path(&self) -> PathBuf {
        self.parent.join(&self.name)
    }

    /// The kind of object this entry refers to.
    pub fn file_type(&self) -> EntryType {
        self.file_type
    }

    /// True if this is a directory.
    pub fn is_dir(&self) -> bool {
        self.file_type == EntryType::Dir
    }

    /// True if this is a regular (non-dir/link/mount) file.
    pub fn is_regular(&self) -> bool {
        self.file_type == EntryType::File
    }

    /// True if this is a symbolic link.
    pub fn is_symlink(&self) -> bool {
        self.file_type == EntryType::Symlink
    }

    /// True if this is a child mountpoint.
    pub fn is_mountpoint(&self) -> bool {
        self.file_type == EntryType::Mountpoint
    }

    /// The `statx` result gathered when the entry was opened.
    pub fn statx(&self) -> &Statx {
        &self.statx
    }

    /// Borrow the entry's open file descriptor.
    ///
    /// For [`EntryType::Symlink`] / [`EntryType::Mountpoint`] this is an
    /// `O_PATH` fd — usable with `statx` and [`Entry::read_link`] but not for
    /// data I/O.
    pub fn fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }

    /// Consume the entry, taking ownership of its file descriptor.
    pub fn into_fd(self) -> OwnedFd {
        self.fd
    }

    /// Read the target of a symbolic-link entry (via the `O_PATH` fd).
    pub fn read_link(&self) -> Result<PathBuf> {
        let mut buf = vec![0u8; libc::PATH_MAX as usize];
        let raw = self.fd.as_raw_fd();
        let n = retry_on_eintr(|| unsafe {
            libc::readlinkat(
                raw,
                c"".as_ptr(),
                buf.as_mut_ptr().cast(),
                buf.len(),
            )
        })? as usize;
        buf.truncate(n);
        Ok(PathBuf::from(OsString::from_vec(buf)))
    }
}

use std::os::unix::ffi::OsStringExt;

/// A depth-first, single-filesystem iterator (see the module docs).
pub struct FsIter {
    stack: Vec<DirFrame>,
    count: u64,
    bytes: u64,
    can_skip: bool,
    fatal: bool,
    btime_cutoff: i64,
    file_open_flags: OFlag,
    include_symlinks: bool,
    include_mountpoints: bool,
}

impl std::fmt::Debug for FsIter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FsIter")
            .field("depth", &self.stack.len())
            .field("count", &self.count)
            .field("bytes", &self.bytes)
            .finish_non_exhaustive()
    }
}

impl FsIter {
    /// Prevent the iterator from descending into the directory it just yielded.
    ///
    /// Call this immediately after receiving a directory [`Entry`]; it is a
    /// no-op if the last yielded entry was not a directory.
    pub fn skip_descent(&mut self) {
        if self.can_skip {
            self.stack.pop();
            self.can_skip = false;
        }
    }

    /// The current directory stack, root first.
    pub fn dir_stack(&self) -> Vec<DirStackEntry> {
        self.stack
            .iter()
            .map(|f| DirStackEntry {
                path: f.path.clone(),
                ino: f.ino,
            })
            .collect()
    }

    /// Capture a resume [`Cookie`] for the current position — the directory
    /// stack as `(path, inode)` levels. Persist it (see [`Cookie::to_bytes`])
    /// to later [`resume_from`](FsIterBuilder::resume_from) near here.
    pub fn cookie(&self) -> Cookie {
        Cookie(self.dir_stack())
    }

    /// A snapshot of iteration progress.
    pub fn stats(&self) -> IterState {
        IterState {
            count: self.count,
            bytes: self.bytes,
            current_dir: self
                .stack
                .last()
                .map(|f| f.path.clone())
                .unwrap_or_default(),
        }
    }

    /// Open and (if a directory) descend into a single directory entry.
    /// Returns `Ok(None)` for entries that are silently pruned.
    fn process(&mut self, dirent: &DirEntry) -> Result<Option<Entry>> {
        let is_dir_hint = dirent.d_type == libc::DT_DIR;
        let is_lnk = dirent.d_type == libc::DT_LNK;
        if is_lnk && !self.include_symlinks {
            return Ok(None);
        }
        let open_flags = if is_dir_hint {
            DIR_OFLAGS
        } else if is_lnk {
            OPATH_OFLAGS
        } else {
            self.file_open_flags
        };

        let parent = self.stack.last().unwrap().path.clone();
        let dfd_raw = self.stack.last().unwrap().dir.fd();
        // SAFETY: `dfd_raw` is the live directory fd owned by the top frame.
        let dfd = unsafe { BorrowedFd::borrow_raw(dfd_raw) };
        let name = dirent.name.as_os_str();

        let (fd, is_mount) =
            match openat2(dfd, name, how(open_flags, ITER_RESOLVE)) {
                Ok(fd) => (fd, false),
                // Symlink swap or delete raced us — prune this entry.
                Err(Errno::ELOOP | Errno::ENOENT) => return Ok(None),
                // Crosses a mount boundary.
                Err(Errno::EXDEV) => {
                    if !self.include_mountpoints {
                        return Ok(None);
                    }
                    let resolve = ResolveFlag::RESOLVE_NO_SYMLINKS;
                    match openat2(dfd, name, how(OPATH_OFLAGS, resolve)) {
                        Ok(fd) => (fd, true),
                        Err(Errno::ELOOP | Errno::ENOENT) => return Ok(None),
                        Err(e) => return Err(e.into()),
                    }
                }
                // Per-file access denial on a regular file: retry O_RDONLY so
                // the caller still gets a usable fd; skip if that also fails.
                Err(Errno::EPERM | Errno::EACCES)
                    if !is_dir_hint && !is_lnk =>
                {
                    let flags = OFlag::O_RDONLY | OFlag::O_NOFOLLOW;
                    match openat2(dfd, name, how(flags, ITER_RESOLVE)) {
                        Ok(fd) => (fd, false),
                        Err(_) => return Ok(None),
                    }
                }
                Err(e) => return Err(e.into()),
            };

        let st = statx(fd.as_fd(), "", ITER_AT, ITER_MASK)?;
        let is_dir = st.is_dir();

        // Skip files created after the cutoff (0 disables). Mountpoints and
        // directories are never btime-filtered.
        if !is_mount
            && !is_dir
            && self.btime_cutoff != 0
            && st.btime().sec > self.btime_cutoff
        {
            return Ok(None);
        }

        let file_type = if is_mount {
            EntryType::Mountpoint
        } else if is_lnk {
            EntryType::Symlink
        } else if is_dir {
            EntryType::Dir
        } else {
            EntryType::File
        };

        // Descend into real directories (never into a crossed mountpoint).
        if is_dir && !is_mount {
            if self.stack.len() >= MAX_DEPTH {
                return Err(Error::Validation(format!(
                    "maximum directory depth {MAX_DEPTH} exceeded"
                )));
            }
            let dup = dup_cloexec(fd.as_fd())?;
            let dir = Dir::from_fd(dup)?;
            self.stack.push(DirFrame {
                path: parent.join(name),
                dir,
                ino: st.ino(),
            });
            self.can_skip = true;
        }

        self.count += 1;
        if file_type != EntryType::Dir {
            self.bytes += st.size();
        }
        Ok(Some(Entry {
            parent,
            name: dirent.name.clone(),
            fd,
            statx: st,
            file_type,
        }))
    }
}

impl Iterator for FsIter {
    type Item = Result<Entry>;

    fn next(&mut self) -> Option<Result<Entry>> {
        if self.fatal {
            return None;
        }
        self.can_skip = false;
        loop {
            if self.stack.is_empty() {
                return None;
            }
            let read = self.stack.last_mut().unwrap().dir.next_entry();
            let dirent = match read {
                Ok(Some(d)) => d,
                Ok(None) => {
                    // Directory exhausted — ascend.
                    self.stack.pop();
                    continue;
                }
                Err(e) => {
                    self.fatal = true;
                    return Some(Err(e.into()));
                }
            };
            if is_dot(&dirent.name) {
                continue;
            }
            match self.process(&dirent) {
                Ok(None) => continue,
                Ok(Some(entry)) => return Some(Ok(entry)),
                Err(e) => {
                    self.fatal = true;
                    return Some(Err(e));
                }
            }
        }
    }
}

/// Builder for a [`FsIter`].
#[derive(Clone, Debug)]
pub struct FsIterBuilder {
    mountpoint: PathBuf,
    filesystem_name: String,
    relative_path: Option<PathBuf>,
    btime_cutoff: i64,
    file_open_flags: OFlag,
    include_symlinks: bool,
    include_mountpoints: bool,
    resume: Option<Cookie>,
    seed_count: u64,
    seed_bytes: u64,
}

impl FsIterBuilder {
    /// Start building an iterator rooted at `mountpoint`, validating that the
    /// mount's source is `filesystem_name` (validation is skipped on kernels
    /// that do not report `sb_source`).
    pub fn new(
        mountpoint: impl Into<PathBuf>,
        filesystem_name: impl Into<String>,
    ) -> Self {
        FsIterBuilder {
            mountpoint: mountpoint.into(),
            filesystem_name: filesystem_name.into(),
            relative_path: None,
            btime_cutoff: 0,
            file_open_flags: OFlag::O_RDONLY | OFlag::O_NOFOLLOW,
            include_symlinks: false,
            include_mountpoints: false,
            resume: None,
            seed_count: 0,
            seed_bytes: 0,
        }
    }

    /// Start iterating at a subdirectory relative to the mountpoint.
    pub fn relative_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.relative_path = Some(path.into());
        self
    }

    /// Skip files whose birth time is newer than `epoch_secs` (0 disables).
    pub fn btime_cutoff(mut self, epoch_secs: i64) -> Self {
        self.btime_cutoff = epoch_secs;
        self
    }

    /// Flags used to open regular files (default `O_RDONLY | O_NOFOLLOW`).
    pub fn file_open_flags(mut self, flags: OFlag) -> Self {
        self.file_open_flags = flags;
        self
    }

    /// Yield symbolic links (with an `O_PATH` fd) instead of skipping them.
    pub fn include_symlinks(mut self, yes: bool) -> Self {
        self.include_symlinks = yes;
        self
    }

    /// Yield child mountpoints (with an `O_PATH` fd) instead of skipping them.
    /// The iterator never descends into them.
    pub fn include_mountpoints(mut self, yes: bool) -> Self {
        self.include_mountpoints = yes;
        self
    }

    /// Resume an interrupted traversal from a [`Cookie`] captured by
    /// [`FsIter::cookie`]. Resume is best-effort: entries in the deepest saved
    /// directory may be re-yielded, and a saved directory that no longer exists
    /// makes [`build`](Self::build) return [`Error::IteratorRestore`]. An empty
    /// cookie is equivalent to no resume (a full traversal).
    pub fn resume_from(mut self, cookie: impl Into<Cookie>) -> Self {
        self.resume = Some(cookie.into());
        self
    }

    /// Seed the running [`stats`](FsIter::stats) totals, so a resumed traversal
    /// continues the interrupted one's cumulative `count`/`bytes` instead of
    /// restarting at zero. The cookie itself carries position only.
    pub fn seed_stats(mut self, count: u64, bytes: u64) -> Self {
        self.seed_count = count;
        self.seed_bytes = bytes;
        self
    }

    /// Open the root and build the iterator.
    pub fn build(self) -> Result<FsIter> {
        let root_path = match &self.relative_path {
            Some(rel) => self.mountpoint.join(rel),
            None => self.mountpoint.clone(),
        };
        // The root itself may be a mountpoint, so only NO_SYMLINKS here.
        let root_fd = openat2(
            AT_FDCWD,
            &root_path,
            how(DIR_OFLAGS, ResolveFlag::RESOLVE_NO_SYMLINKS),
        )?;
        let root_st = statx(root_fd.as_fd(), "", ITER_AT, ITER_MASK)?;
        if !root_st.is_dir() {
            return Err(Errno::ENOTDIR.into());
        }

        // Validate the mount source when the kernel supports sb_source.
        match statmount(
            root_st.mnt_id(),
            StatmountMask::SB_BASIC | StatmountMask::SB_SOURCE,
        ) {
            Ok(sm) => {
                if let Some(source) = sm.sb_source {
                    if source != self.filesystem_name {
                        return Err(Error::MountSourceMismatch {
                            expected: self.filesystem_name,
                            found: source,
                            path: root_path,
                        });
                    }
                }
            }
            // Kernel too old to report sb_source: skip validation.
            Err(Errno::EINVAL) => {}
            Err(e) => return Err(e.into()),
        }

        let ino = root_st.ino();
        let dir = Dir::from_fd(root_fd)?;
        let mut stack = vec![DirFrame {
            path: root_path.clone(),
            dir,
            ino,
        }];
        // Resume from a saved cookie, if one was supplied.
        if let Some(cookie) = &self.resume {
            let entries = cookie.entries();
            if !entries.is_empty() {
                if entries.len() > MAX_DEPTH {
                    return Err(Error::Validation(format!(
                        "cookie depth {} exceeds maximum {MAX_DEPTH}",
                        entries.len()
                    )));
                }
                // The root is trusted by path, but validate its inode so a
                // cookie from an unrelated tree fails cleanly (recoverable by
                // truncating to depth 0, i.e. a full walk).
                if entries[0].ino != ino {
                    return Err(Error::IteratorRestore {
                        depth: 0,
                        path: root_path,
                    });
                }
                restore_stack(&mut stack, entries)?;
            }
        }
        Ok(FsIter {
            stack,
            count: self.seed_count,
            bytes: self.seed_bytes,
            can_skip: false,
            fatal: false,
            btime_cutoff: self.btime_cutoff,
            file_open_flags: self.file_open_flags,
            include_symlinks: self.include_symlinks,
            include_mountpoints: self.include_mountpoints,
        })
    }
}

fn is_dot(name: &OsStr) -> bool {
    let b = name.as_bytes();
    b == b"." || b == b".."
}

fn dup_cloexec(fd: BorrowedFd<'_>) -> errno::Result<OwnedFd> {
    let raw = retry_on_eintr(|| unsafe {
        libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0)
    })?;
    // SAFETY: `fcntl(F_DUPFD_CLOEXEC)` returned a fresh owned fd.
    Ok(unsafe { owned_from_raw(raw as RawFd) })
}

/// Descend `stack` (initially just the root frame) along a resume `cookie`,
/// re-opening and inode-validating each saved directory level so iteration
/// continues inside the deepest one. Intermediate directories are consumed from
/// their parent's stream (never re-yielded); the deepest frame is left freshly
/// opened, so `next` re-reads it from the start — the best-effort part of the
/// contract (see the module docs). A level whose saved child can no longer be
/// found (deleted, or its inode changed) yields [`Error::IteratorRestore`]
/// carrying that depth.
fn restore_stack(
    stack: &mut Vec<DirFrame>,
    cookie: &[DirStackEntry],
) -> Result<()> {
    for (depth, entry) in cookie.iter().enumerate().skip(1) {
        let want = entry.ino;
        let pushed = loop {
            let dirent = match stack.last_mut().unwrap().dir.next_entry()? {
                Some(d) => d,
                None => {
                    // Exhausted this directory without the saved child: the
                    // tree changed under us at this depth.
                    return Err(Error::IteratorRestore {
                        depth,
                        path: stack.last().unwrap().path.clone(),
                    });
                }
            };
            if is_dot(&dirent.name) || dirent.d_ino != want {
                continue;
            }
            // The inode matches; confirm it is really the saved directory (not
            // a file the inode was recycled onto) before descending into it.
            let top = stack.last().unwrap();
            let dfd_raw = top.dir.fd();
            // SAFETY: `dfd_raw` is the live directory fd owned by the top frame.
            let dfd = unsafe { BorrowedFd::borrow_raw(dfd_raw) };
            let fd = match openat2(
                dfd,
                dirent.name.as_os_str(),
                how(DIR_OFLAGS, ITER_RESOLVE),
            ) {
                Ok(fd) => fd,
                // Recycled onto a non-dir, now a mountpoint, or raced away:
                // keep scanning — the real directory may be further along.
                Err(
                    Errno::ENOTDIR
                    | Errno::EXDEV
                    | Errno::ELOOP
                    | Errno::ENOENT,
                ) => continue,
                Err(e) => return Err(e.into()),
            };
            let st = statx(fd.as_fd(), "", ITER_AT, ITER_MASK)?;
            if !st.is_dir() || st.ino() != want {
                continue;
            }
            break DirFrame {
                path: top.path.join(&dirent.name),
                dir: Dir::from_fd(fd)?,
                ino: st.ino(),
            };
        };
        stack.push(pushed);
    }
    Ok(())
}

/// One directory entry read from a [`Dir`].
struct DirEntry {
    d_type: u8,
    d_ino: u64,
    name: OsString,
}

/// A minimal RAII wrapper over a `DIR *` from `fdopendir`.
struct Dir(NonNull<libc::DIR>);

// SAFETY: a `Dir` owns its `DIR` exclusively and is never shared, so it may be
// moved between threads. It is deliberately not `Sync`: concurrent `readdir`
// on one stream is unsafe.
unsafe impl Send for Dir {}

impl Dir {
    /// Take ownership of `fd` and open a directory stream on it.
    fn from_fd(fd: OwnedFd) -> errno::Result<Dir> {
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

    fn fd(&self) -> RawFd {
        // SAFETY: `self.0` is a live DIR stream.
        unsafe { libc::dirfd(self.0.as_ptr()) }
    }

    fn next_entry(&mut self) -> errno::Result<Option<DirEntry>> {
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
            name: OsStr::from_bytes(name.to_bytes()).to_os_string(),
        }))
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        // SAFETY: `self.0` is a live DIR stream; closedir closes its fd.
        unsafe { libc::closedir(self.0.as_ptr()) };
    }
}
