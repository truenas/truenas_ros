//! Recursive, metadata-preserving tree copy (`copytree`).
//!
//! Driven by [`crate::sync_fs::iter::FsIter`]: the source tree is walked depth-first
//! within a single filesystem, and each entry is recreated under the
//! destination - cloning file data (with a `sendfile`/userspace fallback) and
//! preserving ACLs, xattrs, ownership, and nanosecond timestamps. Directories
//! are created owner-only and get their own metadata on ascent, once their
//! children have been written.
//!
//! [`CopyTreeConfig::traverse`] extends the copy across mount boundaries: after
//! the primary filesystem, each child mount nested under `src` is copied into
//! the matching (already-existing) destination directory.
//! [`copytree_reporting`] adds a progress callback fired every N entries.
//!
//! This is a native rewrite of the `truenas_os` C extension's recursive copier:
//! the destination-side directory stack is a plain [`Vec`] reconciled against
//! each entry's parent path, rather than the C runner's manual frame
//! bookkeeping.

mod copy;

pub use copy::{
    clonefile, copy_permissions, copy_setid, copy_xattrs, copyfile,
    copysendfile, copyuserspace, MAX_RW_SZ,
};

use copy::SETID_BITS;

use crate::errno::{retry_on_eintr, Errno};
use crate::error::{Error, Result};
use crate::mount;
use crate::path::TnPath;
use crate::sync_fs::iter::{EntryType, FsIterBuilder};
use crate::sync_fs::xattr::flistxattr;
use crate::sync_fs::{
    openat2, renameat2, statx, AtFlags, OFlag, OpenHow, RenameFlags,
    ResolveFlag, Statx,
};
use crate::sync_fs::{Mode, StatxMask};
use crate::AT_FDCWD;
use std::ffi::{CString, OsStr, OsString};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStringExt;
use std::path::{Path, PathBuf};

// Fixed inode of the ZFS `.zfs` ctldir at a dataset root; used to avoid
// descending into user-visible snapshot directories.
const ZFSCTL_INO_ROOT: u64 = 0x0000_FFFF_FFFF_FFFF;

const META_MASK: StatxMask = StatxMask::BASIC_STATS.union(StatxMask::BTIME);

// Flags for opening a directory to walk or copy into: a real directory, never
// following a trailing symlink.
const DIR_OFLAGS: OFlag = OFlag::O_DIRECTORY
    .union(OFlag::O_RDONLY)
    .union(OFlag::O_NOFOLLOW);

tn_bitflags! {
    /// Which metadata categories [`copytree`] preserves.
    pub struct CopyFlags: u32 {
        /// Copy user/trusted/security-namespace xattrs.
        XATTRS = 0x1;
        /// Copy ACL xattrs, or `fchmod` when no ACL is present.
        PERMISSIONS = 0x2;
        /// Copy nanosecond atime/mtime.
        TIMESTAMPS = 0x4;
        /// Copy uid/gid.
        OWNER = 0x8;
    }
}

/// How each regular file's data is copied.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Default)]
pub enum CopyTreeOp {
    /// Try a block clone, fall back to `sendfile`, then a userspace copy.
    #[default]
    Default,
    /// Block clone only (fails if unsupported).
    Clone,
    /// `sendfile` (with a userspace fallback).
    Sendfile,
    /// Userspace read/write (for special filesystems like procfs/sysfs).
    Userspace,
}

/// Configuration for [`copytree`].
#[derive(Clone, Copy, Debug)]
pub struct CopyTreeConfig {
    /// Re-raise metadata-copy failures (xattr/permission/timestamp). When
    /// false, such failures are ignored and the copy continues. Ownership
    /// (`fchown`) failures always propagate.
    pub raise_error: bool,
    /// Do not error when a destination file/dir already exists.
    pub exist_ok: bool,
    /// Also copy child mounts nested under `src`, as a post-pass after the
    /// primary filesystem (see [`copytree`]). Each child mount's destination
    /// directory must already exist - it is opened, not created, so the data
    /// lands on the intended destination mount rather than its parent.
    pub traverse: bool,
    /// Per-file copy strategy.
    pub op: CopyTreeOp,
    /// Metadata categories to preserve.
    pub flags: CopyFlags,
    /// How often, in entries walked, a [`copytree_reporting`] callback fires.
    /// `0` disables periodic reports (only the final one fires). Ignored by
    /// [`copytree`], which supplies no callback.
    pub reporting_increment: u64,
}

impl Default for CopyTreeConfig {
    fn default() -> Self {
        CopyTreeConfig {
            raise_error: true,
            exist_ok: true,
            traverse: false,
            op: CopyTreeOp::Default,
            flags: CopyFlags::all(),
            reporting_increment: 1000,
        }
    }
}

/// Counts returned from [`copytree`].
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CopyTreeStats {
    /// Directories created.
    pub dirs: u64,
    /// Regular files copied.
    pub files: u64,
    /// Symlinks recreated.
    pub symlinks: u64,
    /// Total bytes of file data written.
    pub bytes: u64,
    /// Special files (FIFOs, sockets, devices) recreated by type.
    pub specials: u64,
}

/// A progress snapshot passed to a [`copytree_reporting`] callback.
#[derive(Clone, Copy, Debug)]
pub struct CopyTreeProgress<'a> {
    /// Running totals copied so far - cumulative across the primary filesystem
    /// and any traversed child mounts.
    pub stats: CopyTreeStats,
    /// Source path of the entry most recently walked (the destination root on
    /// the final call).
    pub current: &'a Path,
}

type CopyFn = fn(BorrowedFd<'_>, BorrowedFd<'_>) -> crate::errno::Result<u64>;

fn select_copy_fn(op: CopyTreeOp) -> CopyFn {
    match op {
        CopyTreeOp::Default => copyfile,
        CopyTreeOp::Clone => clonefile,
        CopyTreeOp::Sendfile => copysendfile,
        CopyTreeOp::Userspace => copyuserspace,
    }
}

/// Recursively copy the tree at `src` to `dst`, preserving metadata per
/// `config`. Both paths should be absolute. Symlinks are recreated verbatim,
/// and the ZFS `.zfs` ctldir plus any entry that is the destination root itself
/// are skipped.
///
/// By default the copy stays within `src`'s own filesystem. With
/// [`CopyTreeConfig::traverse`], each child mount nested under `src` is also
/// copied, as a post-pass, into the correspondingly-named destination directory
/// -- which **must already exist** (it is opened, not created, so the data lands
/// on the intended destination mount rather than its parent).
///
/// For progress reporting, use [`copytree_reporting`].
pub fn copytree(
    src: &Path,
    dst: &Path,
    config: &CopyTreeConfig,
) -> Result<CopyTreeStats> {
    copytree_reporting(src, dst, config, &mut |_: &CopyTreeProgress| {})
}

/// Like [`copytree`], but invokes `progress` every
/// [`CopyTreeConfig::reporting_increment`] entries walked, and once more at the
/// end. Each [`CopyTreeProgress`] carries the running [`CopyTreeStats`] and the
/// current source path.
///
/// (The Python original forwards a callback into its iterator; because this
/// crate's [`FsIter`](crate::sync_fs::iter::FsIter) is caller-driven, `copytree` fires
/// the callback itself and reports copy-specific stats rather than the
/// iterator's generic counts.)
pub fn copytree_reporting(
    src: &Path,
    dst: &Path,
    config: &CopyTreeConfig,
    progress: &mut dyn FnMut(&CopyTreeProgress),
) -> Result<CopyTreeStats> {
    let src_root = openat2(
        AT_FDCWD,
        src,
        OpenHow::new()
            .flags(DIR_OFLAGS)
            .resolve(ResolveFlag::RESOLVE_NO_SYMLINKS),
    )?;
    // `mkdirat` has no resolve-flag mechanism, so it must never be handed a
    // multi-component path: every component but the last would resolve with
    // symlinks followed, and the root could land outside the intended tree.
    // Open the parent with RESOLVE_NO_SYMLINKS and create the final component
    // against that handle, as the rest of this module does for every name.
    let dst_parent = dst
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let dst_name = dst.file_name().ok_or_else(|| {
        Error::Validation("destination path has no file name".into())
    })?;
    let dst_parent_fd = openat2(
        AT_FDCWD,
        dst_parent,
        OpenHow::new()
            .flags(DIR_OFLAGS)
            .resolve(ResolveFlag::RESOLVE_NO_SYMLINKS),
    )?;
    // Hold the destination root owner-only (0o700) for the duration of the
    // copy. Its real mode - which may be broader - is applied only at the end,
    // so group/other are never granted access to the files being written before
    // the copy completes. Owner keeps write, so children stay creatable even
    // when the source root is not owner-writable.
    mkdir_at(dst_parent_fd.as_fd(), dst_name, 0o700, config.exist_ok)?;
    let dst_root = openat2(
        dst_parent_fd.as_fd(),
        dst_name,
        OpenHow::new()
            .flags(DIR_OFLAGS)
            .resolve(ResolveFlag::RESOLVE_NO_SYMLINKS),
    )?;
    // dev+ino of the destination root, so the walk never copies dst into itself
    // -- applied to the primary pass and every traversed child mount.
    let dst_self_st =
        statx(dst_root.as_fd(), "", AtFlags::AT_EMPTY_PATH, META_MASK)?;
    // `mkdir_at` sets the mode only for a root it creates; with `exist_ok` it
    // swallows EEXIST, so a pre-existing root keeps whatever mode it had.
    // Narrow it when that mode grants group or other access, which is what
    // makes the 0o700 hold above true of an existing root too. Where an ACL
    // governs the mode (ZFS aclmode=restricted) the chmod is rejected; there
    // the ACL is authoritative for visibility, so proceed rather than refuse.
    if dst_self_st.mode() & 0o077 != 0 {
        ok_if_acl_governed(fchmod_fd(dst_root.as_fd(), 0o700))?;
    }

    let c_fn = select_copy_fn(config.op);
    let mut stats = CopyTreeStats::default();
    let mut counter = 0u64;

    // fsiter validates the mount source against this name on 6.18+; on older
    // kernels the check is skipped, so the value is best-effort.
    let fs_name = mount::statmount_path(src)
        .ok()
        .and_then(|sm| sm.sb_source)
        .unwrap_or_else(|| src.to_string_lossy().into_owned());

    // Primary filesystem.
    copy_one_mount(
        src_root.as_fd(),
        src,
        fs_name,
        dst_root,
        &dst_self_st,
        config,
        c_fn,
        progress,
        &mut stats,
        &mut counter,
    )?;

    // Child mounts, as a post-pass.
    if config.traverse {
        traverse_child_mounts(
            src,
            dst,
            &dst_self_st,
            config,
            c_fn,
            progress,
            &mut stats,
            &mut counter,
        )?;
    }

    progress(&CopyTreeProgress {
        stats,
        current: dst,
    });
    Ok(stats)
}

/// Copy the contents of one mounted filesystem, rooted at `src_root`
/// (mountpoint `src_path`), into the already-open directory `dst_root`, whose
/// own metadata is stamped last (after every child exists). Stats and the
/// reporting counter accumulate into the shared references.
#[allow(clippy::too_many_arguments)]
fn copy_one_mount(
    src_root: BorrowedFd<'_>,
    src_path: &Path,
    fs_name: String,
    dst_root: OwnedFd,
    dst_self_st: &Statx,
    config: &CopyTreeConfig,
    c_fn: CopyFn,
    progress: &mut dyn FnMut(&CopyTreeProgress),
    stats: &mut CopyTreeStats,
    counter: &mut u64,
) -> Result<()> {
    // fsiter never yields the start directory, so the root gets a frame of its
    // own, popped after the walk - children are then created while the root is
    // still writable and its timestamps are not bumped by those writes.
    let mut frames = vec![DirFrame {
        src_path: src_path.to_path_buf(),
        src: reopen_dir(src_root)?,
        src_st: statx(src_root, "", AtFlags::AT_EMPTY_PATH, META_MASK)?,
        xattrs: list_xattrs(src_root, config)?,
        dst: dst_root,
    }];

    let mut it = FsIterBuilder::new(src_path, fs_name)
        .include_symlinks(true)
        .build()?;

    while let Some(res) = it.next() {
        let entry = res?;

        *counter += 1;
        if config.reporting_increment != 0
            && counter.is_multiple_of(config.reporting_increment)
        {
            let cur = entry.path();
            progress(&CopyTreeProgress {
                stats: *stats,
                current: cur.as_path(),
            });
        }

        // Ascend: pop finished directories, stamping their metadata.
        while frames.last().unwrap().src_path.as_path() != entry.parent() {
            finish_dir(frames.pop().unwrap(), config)?;
        }
        let parent_dst = frames.last().unwrap().dst.as_fd();
        let st = *entry.statx();

        match entry.file_type() {
            EntryType::Dir => {
                // Never descend into the .zfs ctldir or the destination itself.
                let is_ctldir =
                    entry.name() == ".zfs" && st.ino() == ZFSCTL_INO_ROOT;
                let is_dst_self = st.dev() == dst_self_st.dev()
                    && st.ino() == dst_self_st.ino();
                if is_ctldir || is_dst_self {
                    it.skip_descent();
                    continue;
                }
                let dfd = make_dir(parent_dst, entry.name(), config)?;
                stats.dirs += 1;
                frames.push(DirFrame {
                    src_path: entry.path(),
                    src: reopen_dir(entry.fd())?,
                    src_st: st,
                    xattrs: list_xattrs(entry.fd(), config)?,
                    dst: dfd,
                });
            }
            EntryType::File => {
                let n = make_file(
                    parent_dst,
                    entry.name(),
                    entry.fd(),
                    &st,
                    config,
                    c_fn,
                )?;
                stats.files += 1;
                stats.bytes += n;
            }
            EntryType::Symlink => {
                make_symlink(parent_dst, entry.name(), entry.fd(), config)?;
                stats.symlinks += 1;
            }
            EntryType::Special => {
                make_special(parent_dst, entry.name(), &st, config)?;
                stats.specials += 1;
            }
            // Mountpoints are never yielded here (single-filesystem walk);
            // child mounts are handled by the traverse post-pass.
            EntryType::Mountpoint => {}
        }
    }

    // Stamp the directories still open, deepest first, ending with the mount
    // root now that every child exists.
    while let Some(frame) = frames.pop() {
        finish_dir(frame, config)?;
    }
    Ok(())
}

/// One level of the destination-side directory stack. The destination directory
/// is owner-only (0o700) while it is on the stack; the source's metadata is
/// applied by [`finish_dir`] when it is popped, so the source fd and xattr names
/// are held here for that long.
struct DirFrame {
    src_path: PathBuf,
    src: OwnedFd,
    src_st: Statx,
    xattrs: Vec<CString>,
    dst: OwnedFd,
}

/// Apply a finished destination directory's metadata: permissions, xattrs and
/// owner, then timestamps last (a chmod or a chown would otherwise bump ctime,
/// and the children already written bumped mtime).
fn finish_dir(frame: DirFrame, config: &CopyTreeConfig) -> Result<()> {
    copy_metadata(
        frame.src.as_fd(),
        frame.dst.as_fd(),
        &frame.xattrs,
        &frame.src_st,
        config,
    )?;
    apply_timestamps(frame.dst.as_fd(), &frame.src_st, config)
}

/// Reopen a directory the walk owns, giving the caller an fd that outlives the
/// walk's own.
fn reopen_dir(fd: BorrowedFd<'_>) -> Result<OwnedFd> {
    Ok(openat2(
        fd,
        ".",
        OpenHow::new()
            .flags(DIR_OFLAGS)
            .resolve(ResolveFlag::RESOLVE_NO_SYMLINKS),
    )?)
}

/// Copy each child mount nested under `src` into the matching directory under
/// `dst` (which must already exist). Runs once, after the primary filesystem,
/// keyed to `src`'s mount id; ZFS snapshot mounts are skipped.
#[allow(clippy::too_many_arguments)]
fn traverse_child_mounts(
    src: &Path,
    dst: &Path,
    dst_self_st: &Statx,
    config: &CopyTreeConfig,
    c_fn: CopyFn,
    progress: &mut dyn FnMut(&CopyTreeProgress),
    stats: &mut CopyTreeStats,
    counter: &mut u64,
) -> Result<()> {
    // Mount points are real (symlink-resolved) kernel paths, so compare against
    // the real path of the source root.
    let src_real = src.canonicalize().map_err(|e| {
        Error::Errno(Errno::from_raw(e.raw_os_error().unwrap_or(libc::EIO)))
    })?;
    let root_st =
        statx(AT_FDCWD, src, AtFlags::empty(), StatxMask::MNT_ID_UNIQUE)?;

    for sm in mount::iter_mountinfo(root_st.mnt_id(), false, false)? {
        let Some(child_mnt) = sm.mnt_point.as_deref() else {
            continue;
        };
        // Keep only mounts strictly beneath the source root.
        let Ok(rel) = child_mnt.strip_prefix(&src_real) else {
            continue;
        };
        if rel.as_os_str().is_empty() {
            continue;
        }
        let child_dst = dst.join(rel);
        let child_fs_name = sm
            .sb_source
            .clone()
            .unwrap_or_else(|| child_mnt.to_string_lossy().into_owned());

        let child_src_fd = openat2(
            AT_FDCWD,
            child_mnt,
            OpenHow::new()
                .flags(DIR_OFLAGS)
                .resolve(ResolveFlag::RESOLVE_NO_SYMLINKS),
        )?;
        // The destination directory must already exist (opened, not created).
        let child_dst_fd = openat2(
            AT_FDCWD,
            &child_dst,
            OpenHow::new()
                .flags(DIR_OFLAGS)
                .resolve(ResolveFlag::RESOLVE_NO_SYMLINKS),
        )?;
        copy_one_mount(
            child_src_fd.as_fd(),
            Path::new(child_mnt),
            child_fs_name,
            child_dst_fd,
            dst_self_st,
            config,
            c_fn,
            progress,
            stats,
            counter,
        )?;
    }
    Ok(())
}

fn make_dir(
    parent: BorrowedFd<'_>,
    name: &OsStr,
    config: &CopyTreeConfig,
) -> Result<OwnedFd> {
    // Created owner-only (0o700), as the destination root is; the source's
    // mode is applied by `finish_dir` on ascent, once the contents have landed.
    mkdir_at(parent, name, 0o700, config.exist_ok)?;
    Ok(openat2(
        parent,
        name,
        OpenHow::new()
            .flags(OFlag::O_DIRECTORY | OFlag::O_RDONLY | OFlag::O_NOFOLLOW)
            .resolve(ResolveFlag::RESOLVE_NO_SYMLINKS),
    )?)
}

fn make_file(
    parent: BorrowedFd<'_>,
    name: &OsStr,
    src: BorrowedFd<'_>,
    src_st: &Statx,
    config: &CopyTreeConfig,
    c_fn: CopyFn,
) -> Result<u64> {
    // Always `O_EXCL`, so the data only ever lands in an inode this copy
    // created rather than one already at the name. With `exist_ok` an existing
    // entry is replaced by filling a fresh inode under a temporary name and
    // renaming it into place below, not opened and truncated.
    // Created owner-private (0o600) until copy_permissions sets the real mode.
    let how = OpenHow::new()
        .flags(
            OFlag::O_RDWR | OFlag::O_NOFOLLOW | OFlag::O_CREAT | OFlag::O_EXCL,
        )
        .mode(Mode::from_bits_truncate(0o600))
        .resolve(ResolveFlag::RESOLVE_NO_SYMLINKS);
    let (dfd, tmp_name) = match openat2(parent, name, how) {
        Ok(fd) => (fd, None),
        Err(Errno::EEXIST) if config.exist_ok => {
            let (tmp, fd) = create_temp(parent, how)?;
            (fd, Some(tmp))
        }
        Err(e) => return Err(e.into()),
    };

    let res = copy_into(dfd.as_fd(), src, src_st, config, c_fn);
    let Some(tmp) = tmp_name else {
        return res;
    };
    // One step from the temporary name to the destination name, so a reader
    // sees either the entry that was there or the finished copy, never a
    // partial one.
    let res = res.and_then(|n| {
        renameat2(parent, tmp.as_os_str(), parent, name, RenameFlags::empty())?;
        Ok(n)
    });
    if res.is_err() {
        let _ = unlink_at(parent, &tmp);
    }
    res
}

/// Copy `src`'s data then metadata into the destination file just created at
/// `dfd`, returning the number of data bytes written. The data lands first: an
/// unprivileged write to a regular file makes the kernel drop its
/// setuid/setgid bits and `security.capability`, and it would bump the
/// timestamps.
fn copy_into(
    dfd: BorrowedFd<'_>,
    src: BorrowedFd<'_>,
    src_st: &Statx,
    config: &CopyTreeConfig,
    c_fn: CopyFn,
) -> Result<u64> {
    let xattrs = list_xattrs(src, config)?;
    let n = c_fn(src, dfd).map_err(Error::from)?;
    copy_metadata(src, dfd, &xattrs, src_st, config)?;
    apply_timestamps(dfd, src_st, config)?;
    Ok(n)
}

/// Create a file under a fresh random name in `dir`, with the same `how` as the
/// destination it will be renamed over.
///
/// The name is 128 bits from `getrandom(2)`, so a single `O_EXCL` create is
/// collision-free in practice - no retry loop and no shared counter. Its length
/// is fixed rather than derived from the destination name, which would risk
/// `ENAMETOOLONG` for a name already near `NAME_MAX`.
fn create_temp(
    dir: BorrowedFd<'_>,
    how: OpenHow,
) -> Result<(OsString, OwnedFd)> {
    let mut rand = [0u8; 16];
    // getrandom fully fills any request of <= 256 bytes (flags 0), so on success
    // the whole buffer is populated; only the error case needs handling.
    retry_on_eintr(|| unsafe {
        libc::getrandom(rand.as_mut_ptr().cast(), rand.len(), 0)
    })?;
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut name = String::from(".copytree.tmp.");
    for b in rand {
        name.push(char::from(HEX[(b >> 4) as usize]));
        name.push(char::from(HEX[(b & 0x0f) as usize]));
    }
    let name = OsString::from(name);
    let fd = openat2(dir, name.as_os_str(), how)?;
    Ok((name, fd))
}

fn make_symlink(
    parent: BorrowedFd<'_>,
    name: &OsStr,
    src: BorrowedFd<'_>,
    config: &CopyTreeConfig,
) -> Result<()> {
    let target = read_link_fd(src)?;
    let res = target.as_os_str().with_tn_path(|t| {
        name.with_tn_path(|n| {
            retry_on_eintr(|| unsafe {
                libc::symlinkat(t.as_ptr(), parent.as_raw_fd(), n.as_ptr())
            })
        })
    })?;
    match res {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(Errno::EEXIST)) if config.exist_ok => Ok(()),
        Ok(Err(e)) => Err(e.into()),
        Err(e) => Err(e.into()),
    }
}

/// Recreate a special file (FIFO, socket, or block/character device) by type
/// rather than copying contents - a special file has none, and opening one for
/// data would block (FIFO) or run a device's `open` method. Metadata is set
/// directly on the new node (no data fd exists for these types), each attribute
/// gated on its copy flag.
///
/// # Ownership, mode and timestamps only
///
/// Extended attributes and ACLs are not carried onto a special node, and
/// routing this through [`copy_xattrs`] would not carry them either. The node
/// is pinned with `O_PATH` for the reason above, and the whole `f*xattr`
/// family refuses an `O_PATH` descriptor with `EBADF`: for an empty path
/// `path_setxattrat` resolves the fd through `fdget` (`fs/xattr.c:757`), which
/// masks out `FMODE_PATH`. `setxattrat` with `AT_EMPTY_PATH` is the same call
/// -- `getname_maybe_null` returns NULL for an empty name (`fs/namei.c:233`),
/// landing on that branch. `fchmodat2` is not subject to this, which is why
/// the mode below can be set through the handle and the xattrs cannot.
///
/// What is left is re-resolving the name (which reopens the redirect window
/// the pin exists to close) or `/proc/self/fd/N`. Neither is worth it for what
/// is missed: the VFS already refuses `user.*` on anything that is not a
/// regular file or a directory (`xattr_permission`, `fs/xattr.c:154`), and
/// [`copy_xattrs`] skips `system.` and `security.` by charter, so the gap is
/// `trusted.*` plus any ACL the source node carries.
fn make_special(
    parent: BorrowedFd<'_>,
    name: &OsStr,
    src_st: &Statx,
    config: &CopyTreeConfig,
) -> Result<()> {
    // `mknodat`'s mode is umask-masked, so the exact permission bits are
    // restored below; `rdev` is 0 for FIFOs/sockets and the device number for
    // block/character devices. The `S_IFMT` bits in `mode` select the type.
    // setid is masked at creation - `vfs_mknod` passes it through, and it must
    // not land before the node's ownership is settled.
    let mode = src_st.mode() as libc::mode_t;
    let res = name.with_tn_path(|n| {
        retry_on_eintr(|| unsafe {
            libc::mknodat(
                parent.as_raw_fd(),
                n.as_ptr(),
                mode & !SETID_BITS,
                src_st.rdev(),
            )
        })
    })?;
    match res {
        Ok(_) => {}
        Err(Errno::EEXIST) if config.exist_ok => return Ok(()),
        Err(e) => return Err(e.into()),
    }

    // Pin the new node and set every attribute below through this handle, so
    // the name resolves exactly once and cannot be redirected between the
    // mknod and these calls. `O_PATH` because a FIFO or device must not be
    // opened for I/O (that would block on a peer, or run the device's `open`
    // method), and it is all the `AT_EMPTY_PATH` calls need.
    let node = openat2(
        parent,
        name,
        OpenHow::new()
            .flags(OFlag::O_PATH | OFlag::O_NOFOLLOW)
            .resolve(ResolveFlag::RESOLVE_NO_SYMLINKS),
    )?;
    // Confirm the handle is on the node `mknodat` created - same type and
    // device number, and a single link - so a different object at the name is
    // not the one adjusted below.
    let node_st = statx(node.as_fd(), "", AtFlags::AT_EMPTY_PATH, META_MASK)?;
    let ifmt = libc::S_IFMT as u16;
    if node_st.mode() & ifmt != src_st.mode() & ifmt
        || node_st.rdev() != src_st.rdev()
        || node_st.nlink() != 1
    {
        return Err(Error::Validation(format!(
            "destination special file {name:?} changed during the copy"
        )));
    }

    // Ownership before the mode: a chown clears the setuid/setgid bits of a
    // non-directory (even for root), so setid can only follow it. Ownership
    // failures always propagate (matching `copy_metadata`).
    if config.flags.contains(CopyFlags::OWNER) {
        retry_on_eintr(|| unsafe {
            libc::fchownat(
                node.as_raw_fd(),
                c"".as_ptr(),
                src_st.uid(),
                src_st.gid(),
                libc::AT_EMPTY_PATH,
            )
        })?;
    }
    if config.flags.contains(CopyFlags::PERMISSIONS) {
        // setid follows ownership: apply it only when ownership was preserved.
        // Where an ACL governs the node's mode (ZFS aclmode=restricted) the
        // chmod is rejected; the ACL is authoritative, so treat it as applied
        // rather than aborting the whole copy over one node.
        let perm = if config.flags.contains(CopyFlags::OWNER) {
            mode & 0o7777
        } else {
            mode & 0o7777 & !SETID_BITS
        };
        let r = ok_if_acl_governed(fchmod_fd(node.as_fd(), perm));
        guard(config, r)?;
    }
    if config.flags.contains(CopyFlags::TIMESTAMPS) {
        let a = src_st.atime();
        let m = src_st.mtime();
        let times = [
            libc::timespec {
                tv_sec: a.sec,
                tv_nsec: a.nsec as i64,
            },
            libc::timespec {
                tv_sec: m.sec,
                tv_nsec: m.nsec as i64,
            },
        ];
        let r = retry_on_eintr(|| unsafe {
            libc::utimensat(
                node.as_raw_fd(),
                c"".as_ptr(),
                times.as_ptr(),
                libc::AT_EMPTY_PATH,
            )
        })
        .map(drop)
        .map_err(Error::from);
        guard(config, r)?;
    }
    Ok(())
}

fn list_xattrs(
    fd: BorrowedFd<'_>,
    config: &CopyTreeConfig,
) -> Result<Vec<CString>> {
    if config
        .flags
        .intersects(CopyFlags::PERMISSIONS | CopyFlags::XATTRS)
    {
        Ok(flistxattr(fd)?)
    } else {
        Ok(Vec::new())
    }
}

fn copy_metadata(
    src: BorrowedFd<'_>,
    dst: BorrowedFd<'_>,
    xattrs: &[CString],
    src_st: &Statx,
    config: &CopyTreeConfig,
) -> Result<()> {
    let mode = src_st.mode() as u32;
    // Ownership is applied first: chowning a non-directory makes the kernel
    // clear its setuid/setgid bits and any `security.capability`, so the mode
    // and the xattrs have to land after it. Ownership failures always propagate
    // (matching the `truenas_os` C extension).
    if config.flags.contains(CopyFlags::OWNER) {
        retry_on_eintr(|| unsafe {
            libc::fchown(dst.as_raw_fd(), src_st.uid(), src_st.gid())
        })?;
    }
    if config.flags.contains(CopyFlags::PERMISSIONS) {
        guard(config, copy_permissions(src, dst, xattrs, mode))?;
    }
    if config.flags.contains(CopyFlags::XATTRS) {
        guard(config, copy_xattrs(src, dst, xattrs))?;
    }
    // setid belongs only to a destination that carries the source's ownership,
    // and `fchown` clears it, so it is applied last and only when ownership was
    // preserved.
    if config.flags.contains(CopyFlags::OWNER)
        && config.flags.contains(CopyFlags::PERMISSIONS)
    {
        guard(config, copy_setid(dst, xattrs, mode))?;
    }
    Ok(())
}

fn apply_timestamps(
    dst: BorrowedFd<'_>,
    src_st: &Statx,
    config: &CopyTreeConfig,
) -> Result<()> {
    if !config.flags.contains(CopyFlags::TIMESTAMPS) {
        return Ok(());
    }
    let a = src_st.atime();
    let m = src_st.mtime();
    let times = [
        libc::timespec {
            tv_sec: a.sec,
            tv_nsec: a.nsec as i64,
        },
        libc::timespec {
            tv_sec: m.sec,
            tv_nsec: m.nsec as i64,
        },
    ];
    let r = retry_on_eintr(|| unsafe {
        libc::futimens(dst.as_raw_fd(), times.as_ptr())
    })
    .map(drop)
    .map_err(Error::from);
    guard(config, r)
}

fn guard(config: &CopyTreeConfig, r: Result<()>) -> Result<()> {
    match r {
        Ok(()) => Ok(()),
        Err(e) if config.raise_error => Err(e),
        Err(_) => Ok(()),
    }
}

fn mkdir_at(
    dirfd: BorrowedFd<'_>,
    name: &OsStr,
    mode: libc::mode_t,
    exist_ok: bool,
) -> Result<()> {
    let res = name.with_tn_path(|c| {
        retry_on_eintr(|| unsafe {
            libc::mkdirat(dirfd.as_raw_fd(), c.as_ptr(), mode)
        })
    })?;
    match res {
        Ok(_) => Ok(()),
        Err(Errno::EEXIST) if exist_ok => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// Set `mode` on the file `fd` refers to, where `fd` may be an `O_PATH` handle.
/// `fchmod(2)` rejects those (`fdget` masks `FMODE_PATH`), so this goes through
/// `fchmodat2(2)`'s empty-path form, which resolves the handle's own path and
/// never re-resolves a name. `fchmodat2` is a raw syscall because `libc`
/// exposes no wrapper for it.
fn fchmod_fd(fd: BorrowedFd<'_>, mode: libc::mode_t) -> Result<()> {
    retry_on_eintr(|| unsafe {
        libc::syscall(
            libc::SYS_fchmodat2,
            fd.as_raw_fd(),
            c"".as_ptr(),
            mode as libc::c_uint,
            libc::AT_EMPTY_PATH,
        )
    })?;
    Ok(())
}

/// Treat a chmod rejected because an ACL governs the object's mode as done.
/// On ZFS `aclmode=restricted` the mode is derived from a non-trivial ACL and
/// `fchmod` returns `EPERM`; the ACL is then authoritative, so a copy should
/// proceed rather than fail over a mode it cannot set.
fn ok_if_acl_governed(r: Result<()>) -> Result<()> {
    match r {
        Err(Error::Errno(Errno::EPERM)) => Ok(()),
        other => other,
    }
}

fn unlink_at(dirfd: BorrowedFd<'_>, name: &OsStr) -> Result<()> {
    name.with_tn_path(|c| {
        retry_on_eintr(|| unsafe {
            libc::unlinkat(dirfd.as_raw_fd(), c.as_ptr(), 0)
        })
    })??;
    Ok(())
}

fn read_link_fd(fd: BorrowedFd<'_>) -> Result<PathBuf> {
    let mut buf = vec![0u8; libc::PATH_MAX as usize];
    let n = retry_on_eintr(|| unsafe {
        libc::readlinkat(
            fd.as_raw_fd(),
            c"".as_ptr(),
            buf.as_mut_ptr().cast(),
            buf.len(),
        )
    })? as usize;
    buf.truncate(n);
    Ok(PathBuf::from(OsString::from_vec(buf)))
}
