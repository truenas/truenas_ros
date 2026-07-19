//! Recursive, metadata-preserving tree copy (`copytree`).
//!
//! Driven by [`crate::sync_fs::iter::FsIter`]: the source tree is walked depth-first
//! within a single filesystem, and each entry is recreated under the
//! destination — cloning file data (with a `sendfile`/userspace fallback) and
//! preserving ACLs, xattrs, ownership, and nanosecond timestamps. Directory
//! timestamps are stamped on ascent (after their children are written).
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
    clonefile, copy_permissions, copy_xattrs, copyfile, copysendfile,
    copyuserspace, MAX_RW_SZ,
};

use crate::errno::{retry_on_eintr, Errno};
use crate::error::{Error, Result};
use crate::mount;
use crate::path::TnPath;
use crate::sync_fs::iter::{EntryType, FsIterBuilder};
use crate::sync_fs::xattr::flistxattr;
use crate::sync_fs::{
    openat2, statx, AtFlags, OFlag, OpenHow, ResolveFlag, Statx,
};
use crate::sync_fs::{Mode, StatxMask};
use crate::AT_FDCWD;
use std::ffi::{OsStr, OsString};
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
    /// directory must already exist — it is opened, not created, so the data
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
    /// Running totals copied so far — cumulative across the primary filesystem
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
/// — which **must already exist** (it is opened, not created, so the data lands
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
    // Create the destination root owner-only (0o700) for the duration of the
    // copy. Its real mode — which may be broader — is applied only at the end,
    // so group/other are never granted access to the files being written before
    // the copy completes. Owner keeps write, so children stay creatable even
    // when the source root is not owner-writable.
    mkdir_at(AT_FDCWD, dst.as_os_str(), 0o700, config.exist_ok)?;
    let dst_root = openat2(
        AT_FDCWD,
        dst,
        OpenHow::new()
            .flags(DIR_OFLAGS)
            .resolve(ResolveFlag::RESOLVE_NO_SYMLINKS),
    )?;
    // dev+ino of the destination root, so the walk never copies dst into itself
    // — applied to the primary pass and every traversed child mount.
    let dst_self_st =
        statx(dst_root.as_fd(), "", AtFlags::AT_EMPTY_PATH, META_MASK)?;

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
    let src_root_st = statx(src_root, "", AtFlags::AT_EMPTY_PATH, META_MASK)?;
    // fsiter never yields the start directory, so its metadata is applied here,
    // deferred to *after* the walk so children are created while the root is
    // still writable and its timestamps are not bumped by those writes.
    let root_xattrs = list_xattrs(src_root, config)?;

    // (source dir path, destination dir fd, source statx for ascent timestamps)
    let mut frames: Vec<(PathBuf, OwnedFd, Statx)> =
        vec![(src_path.to_path_buf(), dst_root, src_root_st)];

    let mut it = FsIterBuilder::new(src_path, fs_name)
        .include_symlinks(true)
        .build()?;

    while let Some(res) = it.next() {
        let entry = res?;

        *counter += 1;
        if config.reporting_increment != 0
            && *counter % config.reporting_increment == 0
        {
            let cur = entry.path();
            progress(&CopyTreeProgress {
                stats: *stats,
                current: cur.as_path(),
            });
        }

        // Ascend: pop finished directories, stamping their timestamps.
        while frames.last().unwrap().0.as_path() != entry.parent() {
            let (_, dfd, st) = frames.pop().unwrap();
            apply_timestamps(dfd.as_fd(), &st, config)?;
        }
        let parent_dst = frames.last().unwrap().1.as_fd();
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
                let dfd = make_dir(
                    parent_dst,
                    entry.name(),
                    entry.fd(),
                    &st,
                    config,
                )?;
                stats.dirs += 1;
                frames.push((entry.path(), dfd, st));
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

    // Stamp subdirectory timestamps (permissions/owner were applied on
    // descent), deepest first, down to the root frame.
    while frames.len() > 1 {
        let (_, dfd, st) = frames.pop().unwrap();
        apply_timestamps(dfd.as_fd(), &st, config)?;
    }
    // Finalise the mount root last, now that every child exists: permissions,
    // xattrs, and owner, then timestamps.
    let (_, dst_root, src_root_st) = frames.pop().unwrap();
    copy_metadata(
        src_root,
        dst_root.as_fd(),
        &root_xattrs,
        &src_root_st,
        config,
    )?;
    apply_timestamps(dst_root.as_fd(), &src_root_st, config)?;
    Ok(())
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
        let Ok(rel) = Path::new(child_mnt).strip_prefix(&src_real) else {
            continue;
        };
        if rel.as_os_str().is_empty() {
            continue;
        }
        let child_dst = dst.join(rel);
        let child_fs_name = sm
            .sb_source
            .clone()
            .unwrap_or_else(|| child_mnt.to_string());

        let child_src_fd = openat2(
            AT_FDCWD,
            Path::new(child_mnt),
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
    src: BorrowedFd<'_>,
    src_st: &Statx,
    config: &CopyTreeConfig,
) -> Result<OwnedFd> {
    mkdir_at(
        parent,
        name,
        src_st.mode() as libc::mode_t & 0o7777,
        config.exist_ok,
    )?;
    let dfd = openat2(
        parent,
        name,
        OpenHow::new()
            .flags(OFlag::O_DIRECTORY | OFlag::O_RDONLY | OFlag::O_NOFOLLOW)
            .resolve(ResolveFlag::RESOLVE_NO_SYMLINKS),
    )?;
    let xattrs = list_xattrs(src, config)?;
    copy_metadata(src, dfd.as_fd(), &xattrs, src_st, config)?;
    Ok(dfd)
}

fn make_file(
    parent: BorrowedFd<'_>,
    name: &OsStr,
    src: BorrowedFd<'_>,
    src_st: &Statx,
    config: &CopyTreeConfig,
    c_fn: CopyFn,
) -> Result<u64> {
    let mut flags =
        OFlag::O_RDWR | OFlag::O_NOFOLLOW | OFlag::O_CREAT | OFlag::O_TRUNC;
    if !config.exist_ok {
        flags |= OFlag::O_EXCL;
    }
    // Created owner-private (0o600) until copy_permissions sets the real mode.
    let dfd = openat2(
        parent,
        name,
        OpenHow::new()
            .flags(flags)
            .mode(Mode::from_bits_truncate(0o600))
            .resolve(ResolveFlag::RESOLVE_NO_SYMLINKS),
    )?;
    let xattrs = list_xattrs(src, config)?;
    copy_metadata(src, dfd.as_fd(), &xattrs, src_st, config)?;
    let n = c_fn(src, dfd.as_fd()).map_err(Error::from)?;
    // Timestamps last, after the data write (which would otherwise bump mtime).
    apply_timestamps(dfd.as_fd(), src_st, config)?;
    Ok(n)
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
/// rather than copying contents — a special file has none, and opening one for
/// data would block (FIFO) or run a device's `open` method. Metadata is set
/// directly on the new node (no data fd exists for these types), each attribute
/// gated on its copy flag.
fn make_special(
    parent: BorrowedFd<'_>,
    name: &OsStr,
    src_st: &Statx,
    config: &CopyTreeConfig,
) -> Result<()> {
    // `mknodat`'s mode is umask-masked, so the exact permission bits are
    // restored below; `rdev` is 0 for FIFOs/sockets and the device number for
    // block/character devices. The `S_IFMT` bits in `mode` select the type.
    let res = name.with_tn_path(|n| {
        retry_on_eintr(|| unsafe {
            libc::mknodat(
                parent.as_raw_fd(),
                n.as_ptr(),
                src_st.mode() as libc::mode_t,
                src_st.rdev(),
            )
        })
    })?;
    match res {
        Ok(_) => {}
        Err(Errno::EEXIST) if config.exist_ok => return Ok(()),
        Err(e) => return Err(e.into()),
    }

    if config.flags.contains(CopyFlags::PERMISSIONS) {
        let r = name
            .with_tn_path(|n| {
                retry_on_eintr(|| unsafe {
                    libc::fchmodat(
                        parent.as_raw_fd(),
                        n.as_ptr(),
                        src_st.mode() as libc::mode_t & 0o7777,
                        0,
                    )
                })
            })?
            .map(drop)
            .map_err(Error::from);
        guard(config, r)?;
    }
    // Ownership failures always propagate (matching `copy_metadata`).
    if config.flags.contains(CopyFlags::OWNER) {
        name.with_tn_path(|n| {
            retry_on_eintr(|| unsafe {
                libc::fchownat(
                    parent.as_raw_fd(),
                    n.as_ptr(),
                    src_st.uid(),
                    src_st.gid(),
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            })
        })??;
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
        let r = name
            .with_tn_path(|n| {
                retry_on_eintr(|| unsafe {
                    libc::utimensat(
                        parent.as_raw_fd(),
                        n.as_ptr(),
                        times.as_ptr(),
                        libc::AT_SYMLINK_NOFOLLOW,
                    )
                })
            })?
            .map(drop)
            .map_err(Error::from);
        guard(config, r)?;
    }
    Ok(())
}

fn list_xattrs(
    fd: BorrowedFd<'_>,
    config: &CopyTreeConfig,
) -> Result<Vec<String>> {
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
    xattrs: &[String],
    src_st: &Statx,
    config: &CopyTreeConfig,
) -> Result<()> {
    if config.flags.contains(CopyFlags::PERMISSIONS) {
        guard(
            config,
            copy_permissions(src, dst, xattrs, src_st.mode() as u32),
        )?;
    }
    if config.flags.contains(CopyFlags::XATTRS) {
        guard(config, copy_xattrs(src, dst, xattrs))?;
    }
    // Ownership failures always propagate (matching the `truenas_os` C
    // extension).
    if config.flags.contains(CopyFlags::OWNER) {
        retry_on_eintr(|| unsafe {
            libc::fchown(dst.as_raw_fd(), src_st.uid(), src_st.gid())
        })?;
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
