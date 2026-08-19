//! `fstatfs(2)` - filesystem-wide space and limits, by descriptor.
//!
//! Deliberately fd-only. There is no path-taking form here: this module's
//! callers already hold a descriptor for the thing they are asking about, and
//! a path-resolving variant would be a second way to name a file that the
//! [`crate::sync_fs`] surface has otherwise avoided.
//!
//! [`statx`](super::statx) cannot answer this. Its fields are per-inode by
//! construction - `stx_blocks` is the blocks allocated to *that file*, and
//! `stx_blksize` its preferred I/O size - and no `STATX_*` request bit asks
//! about the filesystem. The two answer different scopes.

use crate::errno::{self, retry_on_eintr};
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, AsRawFd};

/// Filesystem statistics for the mount a descriptor lives on.
///
/// Block counts are in units of [`block_size`](Self::block_size), which on ZFS
/// is the dataset's `recordsize` (`zfsvfs->z_max_blksz`, `zfs_statvfs` in
/// `module/os/linux/zfs/zfs_vfsops.c`) - **not** a fixed 4096. Take the unit
/// from this struct rather than assuming one, or the byte figures are wrong by
/// whatever factor the dataset was tuned to.
#[derive(Clone, Copy, Debug)]
pub struct Statfs(libc::statfs);

impl Statfs {
    /// Block size the counts below are denominated in (`f_bsize`).
    pub fn block_size(&self) -> u64 {
        self.0.f_bsize as u64
    }

    /// Total blocks in the filesystem (`f_blocks`).
    pub fn total_blocks(&self) -> u64 {
        self.0.f_blocks
    }

    /// Free blocks (`f_bfree`).
    pub fn free_blocks(&self) -> u64 {
        self.0.f_bfree
    }

    /// Blocks available to an unprivileged caller (`f_bavail`).
    ///
    /// On ext4-style filesystems this is smaller than
    /// [`free_blocks`](Self::free_blocks) by the root reservation. **ZFS keeps
    /// no reservation and sets the two equal** (`f_bavail = f_bfree`,
    /// `zfs_vfsops.c`), so code that infers a reserve from the difference
    /// concludes there is none rather than misreporting.
    pub fn available_blocks(&self) -> u64 {
        self.0.f_bavail
    }

    /// Total size in bytes.
    pub fn total_bytes(&self) -> u64 {
        self.total_blocks().saturating_mul(self.block_size())
    }

    /// Free space in bytes.
    pub fn free_bytes(&self) -> u64 {
        self.free_blocks().saturating_mul(self.block_size())
    }

    /// Space available to an unprivileged caller, in bytes.
    pub fn available_bytes(&self) -> u64 {
        self.available_blocks().saturating_mul(self.block_size())
    }

    /// Total inodes (`f_files`), or 0 where the filesystem has no fixed
    /// count. ZFS reports an estimate that moves with free space.
    pub fn total_files(&self) -> u64 {
        self.0.f_files
    }

    /// Free inodes (`f_ffree`).
    pub fn free_files(&self) -> u64 {
        self.0.f_ffree
    }

    /// Longest filename the filesystem accepts (`f_namelen`).
    pub fn name_max(&self) -> u64 {
        self.0.f_namelen as u64
    }

    /// Filesystem type magic (`f_type`), e.g. `0x2fc12fc1` for ZFS.
    pub fn fs_type(&self) -> i64 {
        self.0.f_type
    }

    /// The raw kernel `struct statfs`.
    pub fn raw(&self) -> &libc::statfs {
        &self.0
    }
}

/// Filesystem statistics for the mount `fd` lives on.
///
/// `fd` may be an `O_PATH` descriptor - including an
/// `Anchor` - because the kernel resolves
/// through `f_path` and never consults `f_op` (`fd_statfs`, `fs/statfs.c`).
/// That is not true of every fd-taking call here: `fsync` and the ZFS
/// attribute ioctls both need a descriptor opened for real I/O.
///
/// See [`fstatfs(2)`](https://man7.org/linux/man-pages/man2/fstatfs.2.html).
pub fn fstatfs<Fd: AsFd>(fd: Fd) -> errno::Result<Statfs> {
    let raw_fd = fd.as_fd().as_raw_fd();
    let mut buf = MaybeUninit::<libc::statfs>::uninit();
    let buf_ptr = buf.as_mut_ptr();
    retry_on_eintr(|| unsafe { libc::fstatfs(raw_fd, buf_ptr) })?;
    // SAFETY: `fstatfs` succeeded, so it initialised the whole struct.
    Ok(Statfs(unsafe { buf.assume_init() }))
}

#[cfg(all(test, not(loom)))]
mod tests {
    use super::*;
    use std::fs::File;

    /// The numbers are self-consistent and the unit is the filesystem's own.
    #[test]
    fn a_descriptor_reports_its_filesystem() {
        let dir = crate::tempdir().unwrap();
        let f = File::open(dir.path()).unwrap();
        let st = fstatfs(&f).unwrap();

        assert!(st.block_size() > 0, "a block size is always reported");
        assert!(st.total_blocks() > 0, "a mounted filesystem has blocks");
        assert!(
            st.free_blocks() <= st.total_blocks(),
            "free {} exceeds total {}",
            st.free_blocks(),
            st.total_blocks()
        );
        assert!(
            st.available_blocks() <= st.free_blocks(),
            "available {} exceeds free {}",
            st.available_blocks(),
            st.free_blocks()
        );
        assert!(st.name_max() >= 255, "NAME_MAX floor");
        assert_eq!(
            st.total_bytes(),
            st.total_blocks() * st.block_size(),
            "bytes derive from the reported unit, not an assumed 4096"
        );
    }

    /// An `O_PATH` descriptor works, which is what lets an `Anchor` be asked
    /// directly. Contrast `fsync`, which `empty_fops` refuses with `EINVAL`.
    #[test]
    fn an_o_path_descriptor_is_enough() {
        use super::super::{openat2, OFlag, OpenHow};
        let dir = crate::tempdir().unwrap();
        let how = OpenHow::new().flags(OFlag::O_PATH | OFlag::O_DIRECTORY);
        let fd =
            openat2(crate::AT_FDCWD, dir.path(), how).expect("O_PATH open");
        let st = fstatfs(&fd).expect("fstatfs on an O_PATH fd");
        assert!(st.total_blocks() > 0);
    }
}
