//! Recursive, metadata-preserving tree copy (`copytree`).
//!
//! Driven by [`crate::sync_fs::iter::FsIter`]: the source tree is walked depth-first within a single filesystem, and
//! each entry is recreated under the destination - cloning file data (with a `sendfile`/userspace fallback) and
//! preserving ACLs, xattrs, ownership, and nanosecond timestamps. Directories are created owner-only and get their own
//! metadata on ascent, once their children have been written.
//!
//! [`CopyTreeConfig::traverse`] extends the copy across mount boundaries: after the primary filesystem, each child
//! mount nested under `src` is copied into the matching (already-existing) destination directory.
//! [`copytree_reporting`] adds a progress callback fired every N entries.

mod copy;

pub use copy::{
    MAX_RW_SZ, clonefile, copy_permissions, copy_setid, copy_xattrs, copyfile, copysendfile, copyuserspace,
};

use copy::{SETID_BITS, release_creation_hold};

use crate::AT_FDCWD;
use crate::errno::{Errno, retry_on_eintr};
use crate::error::{Error, Result};
use crate::mount;
use crate::path::TnPath;
use crate::sync_fs::iter::{EntryType, FsIterBuilder};
use crate::sync_fs::xattr::flistxattr;
use crate::sync_fs::{AtFlags, OFlag, OpenHow, RenameFlags, ResolveFlag, Statx, openat2, renameat2, statx};
use crate::sync_fs::{Mode, StatxMask};
use std::ffi::{CString, OsStr, OsString};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::path::{Path, PathBuf};

// Fixed inode of the ZFS `.zfs` ctldir at a dataset root; used to avoid descending into user-visible snapshot
// directories.
const ZFSCTL_INO_ROOT: u64 = 0x0000_FFFF_FFFF_FFFF;

const META_MASK: StatxMask = StatxMask::BASIC_STATS.union(StatxMask::BTIME);

// Flags for opening a directory to walk or copy into: a real directory, never following a trailing symlink.
const DIR_OFLAGS: OFlag = OFlag::O_DIRECTORY.union(OFlag::O_RDONLY).union(OFlag::O_NOFOLLOW);

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
    /// Re-raise metadata-copy failures (xattr/permission/timestamp). When false, such failures are ignored and the copy
    /// continues. Ownership (`fchown`) failures always propagate.
    pub raise_error: bool,
    /// Do not error when a destination file/dir already exists.
    pub exist_ok: bool,
    /// Also copy child mounts nested under `src`, as a post-pass after the primary filesystem (see [`copytree`]). Each
    /// child mount's destination directory must already exist - it is opened, not created, so the data lands on the
    /// intended destination mount rather than its parent.
    pub traverse: bool,
    /// Per-file copy strategy.
    pub op: CopyTreeOp,
    /// Metadata categories to preserve.
    pub flags: CopyFlags,
    /// How often, in entries walked, a [`copytree_reporting`] callback fires. `0` disables periodic reports (only the
    /// final one fires). Ignored by [`copytree`], which supplies no callback.
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
    /// Running totals copied so far - cumulative across the primary filesystem and any traversed child mounts.
    pub stats: CopyTreeStats,
    /// Source path of the entry most recently walked (the destination root on the final call).
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

/// Recursively copy the tree at `src` to `dst`, preserving metadata per `config`. Both paths should be absolute.
/// Symlinks are recreated verbatim, and the ZFS `.zfs` ctldir plus any entry that is the destination root itself are
/// skipped.
///
/// By default the copy stays within `src`'s own filesystem. With [`CopyTreeConfig::traverse`], each child mount nested
/// under `src` is also copied, as a post-pass, into the matching destination directory, which **must already exist**.
///
/// # Hardlinks are not preserved
///
/// Each name in the source becomes its own inode in the destination, so N links to one file cost N copies of its data
/// and `stats.files` counts each name.
///
/// For progress reporting, use [`copytree_reporting`].
pub fn copytree(src: &Path, dst: &Path, config: &CopyTreeConfig) -> Result<CopyTreeStats> {
    copytree_reporting(src, dst, config, &mut |_: &CopyTreeProgress| {})
}

/// Like [`copytree`], but invokes `progress` every [`CopyTreeConfig::reporting_increment`] entries walked, and once
/// more at the end. Each [`CopyTreeProgress`] carries the running [`CopyTreeStats`] and the current source path.
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
    // `mkdirat` follows symlinks in every component but the last, so it is never handed a multi-component path. Open
    // the parent with RESOLVE_NO_SYMLINKS and create the final component against that handle.
    let dst_parent = dst
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let dst_name = dst
        .file_name()
        .ok_or_else(|| Error::Validation("destination path has no file name".into()))?;
    let dst_parent_fd = openat2(
        AT_FDCWD,
        dst_parent,
        OpenHow::new()
            .flags(DIR_OFLAGS)
            .resolve(ResolveFlag::RESOLVE_NO_SYMLINKS),
    )?;
    // Hold the destination root owner-only (0o700) until the copy completes, so group and other never reach files still
    // being written. Without `CopyFlags::PERMISSIONS` there is no hold, as [`creation_mode`] says.
    let created = mkdir_at(
        dst_parent_fd.as_fd(),
        dst_name,
        creation_mode(config, true),
        config.exist_ok,
    )?;
    let dst_root = openat2(
        dst_parent_fd.as_fd(),
        dst_name,
        OpenHow::new()
            .flags(DIR_OFLAGS)
            .resolve(ResolveFlag::RESOLVE_NO_SYMLINKS),
    )?;
    // dev+ino of the destination root, so the walk never copies dst into itself -- applied to the primary pass and
    // every traversed child mount.
    let dst_self_st = statx(dst_root.as_fd(), "", AtFlags::AT_EMPTY_PATH, META_MASK)?;
    // A root that `exist_ok` adopted is borrowed, and its mode is put back on both exits below, since nothing else
    // would and a share left at 0o700 locks out every other identity. Where an ACL governs the mode (ZFS
    // `aclmode=restricted`) the chmod is refused `EPERM`, and the ACL is authoritative, so proceed.
    let mut borrowed = None;
    let grants_others = dst_self_st.mode() & 0o077 != 0;
    if grants_others && !created {
        borrowed = Some((
            crate::fd::dup_cloexec(dst_root.as_fd())?,
            (dst_self_st.mode() & 0o7777) as libc::mode_t,
        ));
    }
    if narrows_the_root(grants_others, created, config.flags.contains(CopyFlags::PERMISSIONS)) {
        ok_if_acl_governed(fchmod_fd(dst_root.as_fd(), 0o700))?;
    }

    let c_fn = select_copy_fn(config.op);
    let mut stats = CopyTreeStats::default();
    let mut counter = 0u64;

    // fsiter validates the mount source against this name on 6.18+; on older kernels the check is skipped, so the value
    // is best-effort.
    let fs_name = mount::statmount_path(src)
        .ok()
        .and_then(|sm| sm.sb_source)
        .unwrap_or_else(|| src.to_string_lossy().into_owned());

    // Primary filesystem.
    let outcome = copy_one_mount(
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
    );

    // The primary pass's answer is the destination ROOT's - whether the walk stamped a mode over the hold. A child
    // mount's pass answers for its own root and says nothing about this one, so it is not allowed to overwrite it.
    let root_stamped = outcome.as_ref().copied().unwrap_or(false);
    let mut outcome = outcome.map(drop);

    // Child mounts, as a post-pass.
    if outcome.is_ok() && config.traverse {
        outcome = traverse_child_mounts(src, dst, &dst_self_st, config, c_fn, progress, &mut stats, &mut counter);
    }
    if let Err(e) = outcome {
        // Best-effort, and it must not displace the error that got here: the caller is being told the copy failed, and
        // a failure to put the mode back is not the thing to report instead of that.
        if let Some((fd, mode)) = borrowed {
            let _ = ok_if_acl_governed(fchmod_fd(fd.as_fd(), mode));
        }
        return Err(e);
    }
    // Put the borrowed root's mode back unless the walk stamped one over it, and surface a failure, since a caller told
    // the copy succeeded would never learn the root is still owner-only. Ask the walk, not `CopyFlags::PERMISSIONS`,
    // because `guard` swallows a failed stamp under `raise_error: false`.
    if let Some((fd, mode)) = borrowed
        && !root_stamped
    {
        ok_if_acl_governed(fchmod_fd(fd.as_fd(), mode))?;
    }

    progress(&CopyTreeProgress { stats, current: dst });
    Ok(stats)
}

/// Copy the contents of one mounted filesystem, rooted at `src_root` (mountpoint `src_path`), into the already-open
/// directory `dst_root`, whose own metadata is stamped last (after every child exists). Stats and the reporting counter
/// accumulate into the shared references.
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
) -> Result<bool> {
    // fsiter never yields the start directory, so the root gets a frame of its own, popped after the walk - children
    // are then created while the root is still writable and its timestamps are not bumped by those writes.
    let mut frames = vec![DirFrame {
        src_path: src_path.to_path_buf(),
        src: reopen_dir(src_root)?,
        src_st: statx(src_root, "", AtFlags::AT_EMPTY_PATH, META_MASK)?,
        xattrs: list_xattrs(src_root, config)?,
        dst: dst_root,
    }];

    let mut it = FsIterBuilder::new(src_path, fs_name).include_symlinks(true).build()?;

    while let Some(res) = it.next() {
        let entry = res?;

        *counter += 1;
        if config.reporting_increment != 0 && counter.is_multiple_of(config.reporting_increment) {
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
                let is_ctldir = entry.name() == ".zfs" && st.ino() == ZFSCTL_INO_ROOT;
                let is_dst_self = st.dev() == dst_self_st.dev() && st.ino() == dst_self_st.ino();
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
                let n = make_file(parent_dst, entry.name(), entry.fd(), &st, config, c_fn)?;
                stats.files += 1;
                stats.bytes += n;
            }
            EntryType::Symlink => {
                let target = entry.read_link()?;
                make_symlink(parent_dst, entry.name(), &target, &st, config)?;
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

    // Stamp the directories still open, deepest first, ending with the mount root now that every child exists - so the
    // LAST answer is the root's, which is the one the borrowed-root restore needs.
    let mut root_stamped = false;
    while let Some(frame) = frames.pop() {
        root_stamped = finish_dir(frame, config)?;
    }
    Ok(root_stamped)
}

/// One level of the destination-side directory stack. The destination directory is owner-only (0o700) while it is on
/// the stack; the source's metadata is applied by [`finish_dir`] when it is popped, so the source fd and xattr names
/// are held here for that long.
struct DirFrame {
    src_path: PathBuf,
    src: OwnedFd,
    src_st: Statx,
    xattrs: Vec<CString>,
    dst: OwnedFd,
}

/// Apply a finished destination directory's metadata: permissions, xattrs and owner, then timestamps last (a chmod or a
/// chown would otherwise bump ctime, and the children already written bumped mtime).
///
/// Returns whether this directory's mode was stamped from the source - see [`copy_metadata`]. Only the mount root's
/// answer is read, by `copytree_reporting`'s borrowed-root restore.
fn finish_dir(frame: DirFrame, config: &CopyTreeConfig) -> Result<bool> {
    let stamped = copy_metadata(
        frame.src.as_fd(),
        frame.dst.as_fd(),
        &frame.xattrs,
        &frame.src_st,
        config,
    )?;
    apply_timestamps(frame.dst.as_fd(), &frame.src_st, config)?;
    Ok(stamped)
}

/// Reopen a directory the walk owns, giving the caller an fd that outlives the walk's own.
fn reopen_dir(fd: BorrowedFd<'_>) -> Result<OwnedFd> {
    Ok(openat2(
        fd,
        ".",
        OpenHow::new()
            .flags(DIR_OFLAGS)
            .resolve(ResolveFlag::RESOLVE_NO_SYMLINKS),
    )?)
}

/// Copy each child mount nested under `src` into the matching directory under `dst` (which must already exist). Runs
/// once, after the primary filesystem, keyed to `src`'s mount id; ZFS snapshot mounts are skipped.
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
    // Mount points are real (symlink-resolved) kernel paths, so compare against the real path of the source root.
    let src_real = src
        .canonicalize()
        .map_err(|e| Error::Errno(Errno::from_raw(e.raw_os_error().unwrap_or(libc::EIO))))?;
    let root_st = statx(AT_FDCWD, src, AtFlags::empty(), StatxMask::MNT_ID_UNIQUE)?;

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

fn make_dir(parent: BorrowedFd<'_>, name: &OsStr, config: &CopyTreeConfig) -> Result<OwnedFd> {
    // Created at the hold, as the destination root is, and given the source's mode by `finish_dir` on ascent.
    // [`creation_mode`] has the whole rule.
    mkdir_at(parent, name, creation_mode(config, true), config.exist_ok)?;
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
    // Always `O_EXCL`, so the data only lands in an inode this copy created. With `exist_ok` a taken name is replaced
    // by filling a fresh inode under a temporary name and renaming it over, never opened and truncated. Its mode is the
    // one [`creation_mode`] picks.
    let how = OpenHow::new()
        .flags(OFlag::O_RDWR | OFlag::O_NOFOLLOW | OFlag::O_CREAT | OFlag::O_EXCL)
        .mode(Mode::from_bits_truncate(creation_mode(config, false)))
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
    let n = match res {
        Ok(n) => n,
        Err(e) => {
            let _ = unlink_at(parent, &tmp);
            return Err(e);
        }
    };
    rename_over(parent, tmp.as_os_str(), name)?;
    Ok(n)
}

/// Copy `src`'s data then metadata into the destination file just created at `dfd`, returning the number of data bytes
/// written. The data lands first: an unprivileged write to a regular file makes the kernel drop its setuid/setgid bits
/// and `security.capability`, and it would bump the timestamps.
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

/// Create a file under a fresh random name in `dir`, with the same `how` as the destination it will be renamed over.
fn create_temp(dir: BorrowedFd<'_>, how: OpenHow) -> Result<(OsString, OwnedFd)> {
    let name = temp_name()?;
    let fd = openat2(dir, name.as_os_str(), how)?;
    Ok((name, fd))
}

/// A fresh staging name, for the three creators that replace a taken destination by building beside it and renaming
/// over.
fn temp_name() -> Result<OsString> {
    crate::sync_fs::atomic::staging_name(".copytree.tmp.")
}

/// Move `tmp` onto `name` in `dir`, unlinking the staging entry if the rename fails. One step, so a reader sees either
/// the entry that was there or the finished copy, never a partial one.
fn rename_over(dir: BorrowedFd<'_>, tmp: &OsStr, name: &OsStr) -> Result<()> {
    let res = renameat2(dir, tmp, dir, name, RenameFlags::empty());
    if res.is_err() {
        let _ = unlink_at(dir, tmp);
    }
    res.map_err(Into::into)
}

/// Recreate a symbolic link at `name`, pointing at `target`.
///
/// With `exist_ok` a taken name is **replaced**, the way [`make_file`] replaces one, so a re-run copy does not keep an
/// entry whose type or target differs from the source.
///
/// [`CopyFlags::OWNER`] and [`CopyFlags::TIMESTAMPS`] are carried, since a link's own uid is what
/// `fs.protected_symlinks` (`may_follow_link`, `fs/namei.c`) and a sticky directory's delete rule read.
/// [`CopyFlags::PERMISSIONS`] has nothing to carry, since a link's mode is `0o777` on Linux and `fchmodat2` refuses
/// one. [`CopyFlags::XATTRS`] is skipped because the `f*xattr` family refuses an `O_PATH` descriptor, and the VFS
/// refuses `user.*` on a link anyway (`xattr_permission`, `fs/xattr.c`).
fn make_symlink(
    parent: BorrowedFd<'_>,
    name: &OsStr,
    target: &Path,
    src_st: &Statx,
    config: &CopyTreeConfig,
) -> Result<()> {
    let staged = match symlink_at(parent, name, target.as_os_str()) {
        Ok(()) => None,
        Err(Errno::EEXIST) if config.exist_ok => {
            let tmp = temp_name()?;
            symlink_at(parent, tmp.as_os_str(), target.as_os_str())?;
            Some(tmp)
        }
        Err(e) => return Err(e.into()),
    };
    // Stamp at whatever name the link is under, then move it: a reader sees the finished link or the entry that was
    // there, never one carrying the copying identity. `make_special` has the same two-step tail, and every exit from
    // here on has to take the staging entry with it.
    let at: &OsStr = staged.as_deref().unwrap_or(name);
    let outcome = make_symlink_meta(parent, at, name, src_st, config);
    match (staged, outcome) {
        (None, r) => r,
        (Some(tmp), Ok(())) => rename_over(parent, tmp.as_os_str(), name),
        (Some(tmp), Err(e)) => {
            let _ = unlink_at(parent, tmp.as_os_str());
            Err(e)
        }
    }
}

/// Set the new link's ownership and timestamps. `name` is the destination the link is destined for, and is only used to
/// name it in an error.
///
/// An `O_PATH` pin is the only way to name a link without following it, so this uses `fchownat` and `utimensat` with
/// `AT_EMPTY_PATH`, which the kernel supports on such a handle, rather than `fchown` and `futimens`, which answer it
/// `EBADF`. That is not a way round a refused call, since a link has no mode or xattrs to lose.
fn make_symlink_meta(
    parent: BorrowedFd<'_>,
    at: &OsStr,
    name: &OsStr,
    src_st: &Statx,
    config: &CopyTreeConfig,
) -> Result<()> {
    if !config.flags.intersects(CopyFlags::OWNER | CopyFlags::TIMESTAMPS) {
        return Ok(());
    }
    // Pin the link and set both attributes through this handle, so the name resolves once and cannot be redirected
    // between the `symlinkat` and these calls.
    let node = openat2(
        parent,
        at,
        OpenHow::new()
            .flags(OFlag::O_PATH | OFlag::O_NOFOLLOW)
            .resolve(ResolveFlag::RESOLVE_NO_SYMLINKS),
    )?;
    let node_st = statx(node.as_fd(), "", AtFlags::AT_EMPTY_PATH, META_MASK)?;
    if !node_st.is_symlink() || node_st.nlink() != 1 {
        return Err(Error::Validation(format!(
            "destination symbolic link {name:?} changed during the copy"
        )));
    }
    // Ownership failures always propagate (matching `copy_metadata`).
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
    utimes_at(node.as_fd(), src_st, config)
}

/// Apply `src_st`'s atime/mtime to a node pinned by an `O_PATH` handle.
///
/// `utimensat` with `AT_EMPTY_PATH` rather than [`apply_timestamps`]' `futimens`, which an `O_PATH` descriptor answers
/// `EBADF` (`fdget` masks `FMODE_PATH`). A special node and a symbolic link, which have no data descriptor, share it.
fn utimes_at(node: BorrowedFd<'_>, src_st: &Statx, config: &CopyTreeConfig) -> Result<()> {
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
        libc::utimensat(node.as_raw_fd(), c"".as_ptr(), times.as_ptr(), libc::AT_EMPTY_PATH)
    })
    .map(drop)
    .map_err(Error::from);
    guard(config, r)
}

/// `symlinkat`, with the errno surfaced so the caller can act on `EEXIST`.
fn symlink_at(parent: BorrowedFd<'_>, name: &OsStr, target: &OsStr) -> std::result::Result<(), Errno> {
    let res = target.with_tn_path(|t| {
        name.with_tn_path(|n| retry_on_eintr(|| unsafe { libc::symlinkat(t.as_ptr(), parent.as_raw_fd(), n.as_ptr()) }))
    })?;
    match res {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) | Err(e) => Err(e),
    }
}

/// Recreate a special file (FIFO, socket, or block/character device) by type rather than copying contents, since a
/// special file has none and opening one for data would block (FIFO) or run a device's `open` method.
/// [`make_special_meta`] carries the metadata and says what cannot travel.
fn make_special(parent: BorrowedFd<'_>, name: &OsStr, src_st: &Statx, config: &CopyTreeConfig) -> Result<()> {
    let mode = src_st.mode() as libc::mode_t;
    // Created at [`creation_mode`]'s hold, never at the source's mode, since `make_special_meta` opens the node
    // `O_RDONLY` and a source FIFO with no owner-read bit would refuse its own copy `EACCES`. The `S_IFMT` bits are the
    // type, which `mknodat` selects on.
    let create_mode = (mode & libc::S_IFMT) | creation_mode(config, false);
    // With `exist_ok` a taken name is replaced, the way `make_file` replaces one, by building beside it and renaming
    // over. Every exit from here on has to take the staging entry with it.
    let staged = match mknod_at(parent, name, create_mode, src_st) {
        Ok(()) => None,
        Err(Errno::EEXIST) if config.exist_ok => {
            let tmp = temp_name()?;
            mknod_at(parent, tmp.as_os_str(), create_mode, src_st)?;
            Some(tmp)
        }
        Err(e) => return Err(e.into()),
    };
    let at: &OsStr = staged.as_deref().unwrap_or(name);
    let outcome = make_special_meta(parent, at, name, src_st, config);
    // The two arms differ on purpose. A failed staged entry is scratch and goes. A node at the destination name stays
    // with the `Err`, as `make_file` leaves a partly written file and `make_symlink` its link.
    match (staged, outcome) {
        (None, r) => r,
        (Some(tmp), Ok(())) => rename_over(parent, tmp.as_os_str(), name),
        (Some(tmp), Err(e)) => {
            let _ = unlink_at(parent, tmp.as_os_str());
            Err(e)
        }
    }
}

/// `mknodat` for `src_st`'s type, with the errno surfaced so the caller can act on `EEXIST`. setid is masked at
/// creation - `vfs_mknod` passes it through, and it must not land before the node's ownership is settled.
fn mknod_at(
    parent: BorrowedFd<'_>,
    name: &OsStr,
    mode: libc::mode_t,
    src_st: &Statx,
) -> std::result::Result<(), Errno> {
    // `mknodat`'s mode is umask-masked, so the exact permission bits are restored by the caller; `rdev` is 0 for
    // FIFOs/sockets and the device number for block/character devices. The `S_IFMT` bits select the type.
    let res = name.with_tn_path(|n| {
        retry_on_eintr(|| unsafe { libc::mknodat(parent.as_raw_fd(), n.as_ptr(), mode & !SETID_BITS, src_st.rdev()) })
    })?;
    res.map(drop)
}

/// Carry the source's ownership, mode and timestamps onto the new node, through a **real descriptor** on it.
///
/// A FIFO is opened `O_RDONLY|O_NONBLOCK`, which completes at once with no writer, and the result takes the owner, mode
/// and timestamps. The type is checked through an `O_PATH` handle first, since a real open runs the file's `open`
/// method and `O_PATH` does not, and the two handles must be the same `(dev, ino)`, so a swap between the opens is
/// refused.
///
/// **A socket or a device node gives up its mode, and only its mode.** A socket answers `ENXIO` to every `open(2)` and
/// opening a device runs its driver, so neither can be given the real descriptor `fchmod` needs, and [`fchmod_fd`] says
/// why the mode is never routed round that. The refusal goes through [`guard`], so under `raise_error: false` the copy
/// continues and the node keeps the creation hold. Owner and timestamps are still carried, through `fchownat` and
/// `utimensat` with `AT_EMPTY_PATH` on the `O_PATH` handle, as [`make_symlink_meta`] does.
///
/// **No special type gets the source's ACL or xattrs.** The walk pins source specials `O_PATH`, which `fgetxattr` and
/// `getxattrat` with `AT_EMPTY_PATH` answer `EBADF`. Reopening a source FIFO for real would release a writer blocked in
/// `open(O_WRONLY)`, whose next `write` after our close gets `EPIPE`, which kills it by default, and reading by name
/// re-resolves it. The VFS refuses `user.*` on a special node anyway (`xattr_permission`, `fs/xattr.c`) and
/// [`copy_xattrs`] skips `system.` and `security.`, so the loss is `trusted.*` and any ACL.
/// `a_special_file_takes_the_mode_and_not_the_acl` pins it.
///
/// With none of the three flags set there is nothing to carry, so nothing is opened and every type is copied.
fn make_special_meta(
    parent: BorrowedFd<'_>,
    at: &OsStr,
    name: &OsStr,
    src_st: &Statx,
    config: &CopyTreeConfig,
) -> Result<()> {
    let ifmt = libc::S_IFMT as u16;
    // Verify the node first, for every type and whatever the flags say, since `make_special`'s staging path renames
    // this name into place afterwards. `O_PATH` never runs the file's `open` method, so a device node planted here is
    // looked at and not opened.
    let peek = openat2(
        parent,
        at,
        OpenHow::new()
            .flags(OFlag::O_PATH | OFlag::O_NOFOLLOW)
            .resolve(ResolveFlag::RESOLVE_NO_SYMLINKS),
    )?;
    let peek_st = statx(peek.as_fd(), "", AtFlags::AT_EMPTY_PATH, META_MASK)?;
    let changed =
        |st: &Statx| st.mode() & ifmt != src_st.mode() & ifmt || st.rdev() != src_st.rdev() || st.nlink() != 1;
    if changed(&peek_st) {
        return Err(Error::Validation(format!(
            "destination special file {name:?} changed during the copy"
        )));
    }
    if !config
        .flags
        .intersects(CopyFlags::OWNER | CopyFlags::PERMISSIONS | CopyFlags::TIMESTAMPS)
    {
        // Verified, and nothing to carry onto it.
        return Ok(());
    }
    let kind = src_st.mode() & ifmt;
    if kind != libc::S_IFIFO as u16 {
        // Only the mode is impossible here. `fchownat` and `utimensat` with `AT_EMPTY_PATH` work on an `O_PATH` handle
        // of any type (`chown_common` in `fs/open.c`, `do_utimes_path` in `fs/utimes.c`), on the peek verified above.
        // The mode's refusal comes last, so what can travel does in either disposition.
        if config.flags.contains(CopyFlags::OWNER) {
            // Ownership failures always propagate (matching `copy_metadata`).
            retry_on_eintr(|| unsafe {
                libc::fchownat(
                    peek.as_raw_fd(),
                    c"".as_ptr(),
                    src_st.uid(),
                    src_st.gid(),
                    libc::AT_EMPTY_PATH,
                )
            })?;
        }
        utimes_at(peek.as_fd(), src_st, config)?;
        if !config.flags.contains(CopyFlags::PERMISSIONS) {
            return Ok(());
        }
        let what = match u32::from(kind) {
            libc::S_IFSOCK => "socket",
            libc::S_IFCHR => "character device",
            libc::S_IFBLK => "block device",
            _ => "special file",
        };
        // Through `guard`, as any metadata-copy failure, so one socket does not fail a `raise_error: false` copy.
        // Swallowed, the node keeps the creation hold.
        return guard(
            config,
            Err(Error::Validation(format!(
                "{what} {name:?}: its mode cannot travel - this type cannot \
                 be given the real descriptor `fchmod` needs, because a \
                 socket refuses every open and a device node's open would \
                 run its driver. Only the mode is refused; owner and \
                 timestamps, where asked for, were carried. Clear \
                 CopyFlags::PERMISSIONS to copy it without its mode, which \
                 creates it at the permissive form `creation_mode` \
                 documents rather than at the source's."
            ))),
        );
    }
    // A read-open of a FIFO with `O_NONBLOCK` does not wait for a writer. `EACCES` is the copy's own doing, since the
    // hold is only a request and an inherited ACL (`__posix_acl_create`, `zfs_acl_ids_create`) or the umask can
    // withhold owner-read, so the error reports the mode the peek measured.
    let node = openat2(
        parent,
        at,
        OpenHow::new()
            .flags(OFlag::O_RDONLY | OFlag::O_NONBLOCK | OFlag::O_NOFOLLOW)
            .resolve(ResolveFlag::RESOLVE_NO_SYMLINKS),
    )
    .map_err(|e| match e {
        Errno::EACCES => Error::Validation(format!(
            "destination special file {name:?} was created at mode {:#o}, \
             without owner-read, so this copy cannot open it for the real \
             descriptor its metadata needs. A new node's mode belongs to \
             the filesystem: the destination parent's inherited (default) \
             ACL, or the umask, narrowed the {:#o} this copy asked for. \
             Grant read to the copying identity in the destination \
             parent's inherited entries, or clear CopyFlags::OWNER, \
             PERMISSIONS and TIMESTAMPS to copy this node without \
             metadata.",
            peek_st.mode() & 0o7777,
            creation_mode(config, false)
        )),
        other => Error::from(other),
    })?;
    // ...and confirm the real handle landed on the very inode just inspected, so a swap between the two opens cannot
    // slip a different object into the calls below.
    let node_st = statx(node.as_fd(), "", AtFlags::AT_EMPTY_PATH, META_MASK)?;
    if changed(&node_st) || node_st.dev() != peek_st.dev() || node_st.ino() != peek_st.ino() {
        return Err(Error::Validation(format!(
            "destination special file {name:?} changed during the copy"
        )));
    }

    // Ownership before the mode: a chown clears the setuid/setgid bits of a non-directory (even for root), so setid can
    // only follow it. Ownership failures always propagate (matching `copy_metadata`).
    if config.flags.contains(CopyFlags::OWNER) {
        retry_on_eintr(|| unsafe { libc::fchown(node.as_raw_fd(), src_st.uid(), src_st.gid()) })?;
    }
    if config.flags.contains(CopyFlags::PERMISSIONS) {
        // setid follows ownership: apply it only when ownership was preserved. Where an ACL governs the node's mode
        // (ZFS aclmode=restricted) the chmod is rejected; the ACL is authoritative, so treat it as applied rather than
        // aborting the whole copy over one node.
        let mode = src_st.mode() as libc::mode_t;
        let perm = if config.flags.contains(CopyFlags::OWNER) {
            mode & 0o7777
        } else {
            mode & 0o7777 & !SETID_BITS
        };
        let r = ok_if_acl_governed(fchmod_fd(node.as_fd(), perm));
        guard(config, r)?;
    }
    utimes_at(node.as_fd(), src_st, config)
}

/// The names to consider copying off `fd`, or an empty list where the copy flags ask for none.
///
/// Routed through [`guard`] like every other metadata step. `flistxattr` fails `E2BIG` on a well-formed file whose
/// names pass `XATTR_LIST_MAX` (`listxattr`, `fs/xattr.c`), which ZFS `xattr=sa` allows, and one such directory must
/// not kill a `raise_error: false` copy of everything beneath it. The entry still gets its mode, owner and timestamps,
/// since `copy_permissions` takes its `fchmod` branch when no ACL name is listed.
fn list_xattrs(fd: BorrowedFd<'_>, config: &CopyTreeConfig) -> Result<Vec<CString>> {
    if !config.flags.intersects(CopyFlags::PERMISSIONS | CopyFlags::XATTRS) {
        return Ok(Vec::new());
    }
    match flistxattr(fd) {
        Ok(names) => Ok(names),
        Err(e) => {
            guard(config, Err(e.into()))?;
            Ok(Vec::new())
        }
    }
}

/// `Ok(true)` when the destination's own permissions were set from the source. That is the question the borrowed
/// destination root's restore turns on: `guard` swallows a `copy_permissions` failure when `raise_error` is false, and
/// nothing downstream could tell that from a success. `false` with the flag off too - nothing was owed there, and the
/// restore is what supplies the mode instead.
fn copy_metadata(
    src: BorrowedFd<'_>,
    dst: BorrowedFd<'_>,
    xattrs: &[CString],
    src_st: &Statx,
    config: &CopyTreeConfig,
) -> Result<bool> {
    let mut stamped = false;
    let mode = src_st.mode() as u32;
    // Ownership is applied first, since chowning a non-directory clears its setuid/setgid bits and any
    // `security.capability`, so the mode and the xattrs land after it. Ownership failures always propagate.
    if config.flags.contains(CopyFlags::OWNER) {
        retry_on_eintr(|| unsafe { libc::fchown(dst.as_raw_fd(), src_st.uid(), src_st.gid()) })?;
    }
    if config.flags.contains(CopyFlags::PERMISSIONS) {
        let r = copy_permissions(src, dst, xattrs, mode);
        stamped = r.is_ok();
        if !stamped {
            // Release `creation_mode`'s hold before `guard`, so a `raise_error: false` copy cannot return `Ok` over an
            // owner-only tree. Only this object is released. An aborted walk leaves its ancestors at the hold on
            // purpose, since widening a partial tree would publish it early. A failed release keeps `r` as the cause.
            stamped = release_creation_hold(dst, mode).unwrap_or(false);
        }
        guard(config, r)?;
    }
    if config.flags.contains(CopyFlags::XATTRS) {
        guard(config, copy_xattrs(src, dst, xattrs))?;
    }
    // setid belongs only to a destination that carries the source's ownership, and `fchown` clears it, so it is applied
    // last and only when ownership was preserved.
    if config.flags.contains(CopyFlags::OWNER) && config.flags.contains(CopyFlags::PERMISSIONS) {
        guard(config, copy_setid(dst, xattrs, mode))?;
    }
    Ok(stamped)
}

fn apply_timestamps(dst: BorrowedFd<'_>, src_st: &Statx, config: &CopyTreeConfig) -> Result<()> {
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
    let r = retry_on_eintr(|| unsafe { libc::futimens(dst.as_raw_fd(), times.as_ptr()) })
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

/// `true` when this call created the directory, `false` when `exist_ok` adopted one already at the name. The
/// distinction is what tells a root this copy owns from one it borrowed, which decides whether its mode is this copy's
/// to set or someone else's to have back.
fn mkdir_at(dirfd: BorrowedFd<'_>, name: &OsStr, mode: libc::mode_t, exist_ok: bool) -> Result<bool> {
    let res =
        name.with_tn_path(|c| retry_on_eintr(|| unsafe { libc::mkdirat(dirfd.as_raw_fd(), c.as_ptr(), mode) }))?;
    match res {
        Ok(_) => Ok(true),
        Err(Errno::EEXIST) if exist_ok => Ok(false),
        Err(e) => Err(e.into()),
    }
}

/// Whether the destination root is narrowed to `0o700` for the duration of the copy.
///
/// Narrowing is a **hold**, so it is only correct where a later mode is coming to release it into, and there are
/// exactly two:
///
/// * `CopyFlags::PERMISSIONS`, under which `copy_permissions` stamps the
///   source root's mode from the root frame once the walk completes;
/// * a *borrowed* root's own mode, put back by `copytree` on both exits.
///
/// **A created root can need this too.** With an inheritable ACE on the destination's parent, ZFS rebuilds every rwx
/// bit of the new directory from the inherited ACL (`zfs_mode_compute`, `module/os/linux/zfs/zfs_acl.c`), so `0o700`
/// can come back `0o770`, and under `aclmode=restricted` the requested mode is not consulted at all (`zfs_acl_inherit`
/// clears `need_chmod`). A POSIX default ACL only intersects with the requested mode, so only `acltype=nfsv4` shows it.
fn narrows_the_root(grants_others: bool, created: bool, permissions: bool) -> bool {
    grants_others && (!created || permissions)
}

/// The mode a destination object is created with.
///
/// Under [`CopyFlags::PERMISSIONS`], `0o700`/`0o600` is a **hold** that the source's mode releases later
/// ([`finish_dir`] on ascent for a directory, [`copy_metadata`] for a file), so group and other never reach bytes still
/// being written. Without it nothing would release a hold, so the object is created at the permissive form and keeps
/// what a plain `mkdir` or `open` gives. That is the filesystem's answer, from the umask, a POSIX default ACL
/// (`posix_acl_create`, `fs/posix_acl.c`) or an inherited NFSv4 ACL (`zfs_acl_ids_create`), and none of it is this
/// function's to compute.
///
/// Do not stamp the mode afterwards instead. On ZFS a chmod rewrites the ACL to match the mode, and replaces what the
/// parent passed down under the default `aclmode=discard` (`zfs_acl_chmod_setattr`, `module/os/linux/zfs/zfs_acl.c`),
/// while `aclmode=restricted` refuses it `EPERM`.
fn creation_mode(config: &CopyTreeConfig, is_dir: bool) -> libc::mode_t {
    match (config.flags.contains(CopyFlags::PERMISSIONS), is_dir) {
        (true, true) => 0o700,
        (true, false) => 0o600,
        (false, true) => 0o777,
        (false, false) => 0o666,
    }
}

/// Set `mode` on the open file `fd` refers to, through `fchmod(2)`.
///
/// **`fd` must be a real descriptor, never `O_PATH`.** Metadata calls here are fd-based, so no name is resolved twice.
/// An `O_PATH` handle gets `EBADF` from `fchmod(2)`, `fsetxattr(2)` and `setxattrat(2)`'s empty-path form, so it cannot
/// carry metadata, and handed one this fails at once. Do not route round it with `fchmodat2(2)`'s empty-path form or
/// `/proc/self/fd/N`. Those carry the mode while the ACL and xattrs silently do not, and the copy reports `Ok`. An
/// object that cannot be opened for real is the thing to report.
fn fchmod_fd(fd: BorrowedFd<'_>, mode: libc::mode_t) -> Result<()> {
    if is_o_path(fd)? {
        return Err(Error::Validation(
            "copytree metadata needs a real descriptor, not an O_PATH handle \
             - O_PATH cannot carry a mode, an ACL or an xattr"
                .into(),
        ));
    }
    retry_on_eintr(|| unsafe { libc::fchmod(fd.as_raw_fd(), mode) })?;
    Ok(())
}

/// Whether `fd` is an `O_PATH` handle, which carries no file metadata.
fn is_o_path(fd: BorrowedFd<'_>) -> Result<bool> {
    let fl = retry_on_eintr(|| unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) })?;
    Ok(fl & libc::O_PATH != 0)
}

/// Treat a chmod rejected because an ACL governs the object's mode as done. On ZFS `aclmode=restricted` the mode is
/// derived from a non-trivial ACL and `fchmod` returns `EPERM`; the ACL is then authoritative, so a copy should proceed
/// rather than fail over a mode it cannot set.
fn ok_if_acl_governed(r: Result<()>) -> Result<()> {
    match r {
        Err(Error::Errno(Errno::EPERM)) => Ok(()),
        other => other,
    }
}

fn unlink_at(dirfd: BorrowedFd<'_>, name: &OsStr) -> Result<()> {
    name.with_tn_path(|c| retry_on_eintr(|| unsafe { libc::unlinkat(dirfd.as_raw_fd(), c.as_ptr(), 0) }))??;
    Ok(())
}

#[cfg(test)]
mod tests;
