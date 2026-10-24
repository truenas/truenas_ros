//! `statx(2)` - extended file attributes.

use super::{AtFlags, ZfsAttr};
use crate::errno::{self, retry_on_eintr};
use crate::path::TnPath;
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, AsRawFd};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

tn_bitflags! {
    /// `STATX_*` - the set of fields requested from / returned by `statx`.
    pub struct StatxMask: u32 {
        /// Want/got the file type bits of `stx_mode`.
        TYPE = 0x0000_0001;
        /// Want/got the permission bits of `stx_mode`.
        MODE = 0x0000_0002;
        /// Want/got `stx_nlink`.
        NLINK = 0x0000_0004;
        /// Want/got `stx_uid`.
        UID = 0x0000_0008;
        /// Want/got `stx_gid`.
        GID = 0x0000_0010;
        /// Want/got the last-access time.
        ATIME = 0x0000_0020;
        /// Want/got the last-modification time.
        MTIME = 0x0000_0040;
        /// Want/got the last-status-change time.
        CTIME = 0x0000_0080;
        /// Want/got `stx_ino`.
        INO = 0x0000_0100;
        /// Want/got `stx_size`.
        SIZE = 0x0000_0200;
        /// Want/got `stx_blocks`.
        BLOCKS = 0x0000_0400;
        /// The classic `struct stat` fields.
        BASIC_STATS = 0x0000_07ff;
        /// Want/got the creation (birth) time.
        BTIME = 0x0000_0800;
        /// Want/got the legacy mount id.
        MNT_ID = 0x0000_1000;
        /// Want/got the direct-I/O alignment info.
        DIOALIGN = 0x0000_2000;
        /// Want/got the extended (unique) mount id.
        MNT_ID_UNIQUE = 0x0000_4000;
        /// Want/got `stx_subvol`.
        SUBVOL = 0x0000_8000;
        /// Want/got the atomic-write fields.
        WRITE_ATOMIC = 0x0001_0000;
        /// Want/got the direct-I/O read alignment info.
        DIO_READ_ALIGN = 0x0002_0000;
        /// Want/got the ZFS flags (`stx_zfsflags`, [`Statx::zfs_attrs`],
        /// [`Statx::nfs4_acl_is_trivial`] and [`Statx::nfs4_acl_flags`]).
        ZFSFLAGS = 0x1000_0000;
        /// Want/got the inode generation (`stx_gen`, [`Statx::generation`]).
        GEN = 0x2000_0000;
        /// Want/got the change cookie (durable/persistent handle support).
        CHANGE_COOKIE = 0x4000_0000;
    }
}

tn_bitflags! {
    /// `STATX_ATTR_*` - flags reported in [`Statx::attributes`].
    pub struct StatxAttr: u64 {
        /// The file is compressed by the filesystem.
        COMPRESSED = 0x0000_0004;
        /// The file is marked immutable.
        IMMUTABLE = 0x0000_0010;
        /// The file is append-only.
        APPEND = 0x0000_0020;
        /// The file is not to be dumped.
        NODUMP = 0x0000_0040;
        /// The file requires a key to be decrypted.
        ENCRYPTED = 0x0000_0800;
        /// The directory is an automount trigger.
        AUTOMOUNT = 0x0000_1000;
        /// The file is the root of a mount.
        MOUNT_ROOT = 0x0000_2000;
        /// The file is `fs-verity` protected.
        VERITY = 0x0010_0000;
        /// The file is currently in the DAX state.
        DAX = 0x0020_0000;
        /// The file supports atomic writes.
        WRITE_ATOMIC = 0x0040_0000;
    }
}

/// Kernel `struct statx_timestamp`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
#[allow(missing_docs)]
pub struct StatxTimestampRaw {
    pub tv_sec: i64,
    pub tv_nsec: u32,
    pub __reserved: i32,
}

/// Kernel `struct statx` (kernel 6.18 layout, 256 bytes).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
#[allow(missing_docs)]
pub struct StatxRaw {
    pub stx_mask: u32,
    pub stx_blksize: u32,
    pub stx_attributes: u64,
    pub stx_nlink: u32,
    pub stx_uid: u32,
    pub stx_gid: u32,
    pub stx_mode: u16,
    pub __spare0: u16,
    pub stx_ino: u64,
    pub stx_size: u64,
    pub stx_blocks: u64,
    pub stx_attributes_mask: u64,
    pub stx_atime: StatxTimestampRaw,
    pub stx_btime: StatxTimestampRaw,
    pub stx_ctime: StatxTimestampRaw,
    pub stx_mtime: StatxTimestampRaw,
    pub stx_rdev_major: u32,
    pub stx_rdev_minor: u32,
    pub stx_dev_major: u32,
    pub stx_dev_minor: u32,
    pub stx_mnt_id: u64,
    pub stx_dio_mem_align: u32,
    pub stx_dio_offset_align: u32,
    pub stx_subvol: u64,
    pub stx_atomic_write_unit_min: u32,
    pub stx_atomic_write_unit_max: u32,
    pub stx_atomic_write_segments_max: u32,
    pub stx_dio_read_offset_align: u32,
    pub stx_atomic_write_unit_max_opt: u32,
    pub __spare2: u32,
    pub stx_change_cookie: u64,
    pub stx_gen: u64,
    pub stx_zfsflags: u64,
    pub __spare3: [u64; 5],
}

const _: () = assert!(core::mem::size_of::<StatxTimestampRaw>() == 16);
const _: () = assert!(core::mem::size_of::<StatxRaw>() == 256);
// The fork's three fields follow the atomic-write words in this order, and
// `include/uapi/linux/stat.h` marks the spare words behind them at `0xd8`.
const _: () =
    assert!(core::mem::offset_of!(StatxRaw, stx_change_cookie) == 0xc0);
const _: () = assert!(core::mem::offset_of!(StatxRaw, stx_gen) == 0xc8);
const _: () = assert!(core::mem::offset_of!(StatxRaw, stx_zfsflags) == 0xd0);

/// A timestamp from [`statx`], as whole seconds plus a nanosecond remainder.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StatxTimestamp {
    /// Seconds since the Unix epoch (may be negative).
    pub sec: i64,
    /// Nanosecond remainder in `0..1_000_000_000`.
    pub nsec: u32,
}

impl StatxTimestamp {
    /// The time as fractional seconds since the Unix epoch.
    pub fn as_secs_f64(&self) -> f64 {
        self.sec as f64 + self.nsec as f64 * 1e-9
    }

    /// The time as total nanoseconds since the Unix epoch.
    pub fn as_nanos(&self) -> i128 {
        self.sec as i128 * 1_000_000_000 + self.nsec as i128
    }

    /// Convert to a [`SystemTime`], if representable.
    pub fn to_system_time(&self) -> Option<SystemTime> {
        let total = self.as_nanos();
        if total >= 0 {
            let n = total as u128;
            UNIX_EPOCH.checked_add(Duration::new(
                (n / 1_000_000_000) as u64,
                (n % 1_000_000_000) as u32,
            ))
        } else {
            let n = total.unsigned_abs();
            UNIX_EPOCH.checked_sub(Duration::new(
                (n / 1_000_000_000) as u64,
                (n % 1_000_000_000) as u32,
            ))
        }
    }
}

/// Combine a device major/minor into a `dev_t`, matching glibc's encoding.
pub fn makedev(major: u32, minor: u32) -> u64 {
    let ma = major as u64;
    let mi = minor as u64;
    ((ma & 0xffff_f000) << 32)
        | ((ma & 0x0000_0fff) << 8)
        | ((mi & 0xffff_ff00) << 12)
        | (mi & 0x0000_00ff)
}

fn ts(raw: StatxTimestampRaw) -> StatxTimestamp {
    StatxTimestamp {
        sec: raw.tv_sec,
        nsec: raw.tv_nsec,
    }
}

/// Extended file attributes returned by [`statx`].
///
/// Unlike the Python bindings, each timestamp and device id has a single
/// representation; use [`Statx::raw`] for direct field access.
#[derive(Clone, Copy, Debug)]
pub struct Statx(StatxRaw);

impl Statx {
    /// The mask of fields the kernel actually populated.
    pub fn mask(&self) -> StatxMask {
        StatxMask::from_bits_retain(self.0.stx_mask)
    }

    /// File attribute flags (`STATX_ATTR_*`).
    pub fn attributes(&self) -> StatxAttr {
        StatxAttr::from_bits_retain(self.0.stx_attributes)
    }

    /// Which [`Statx::attributes`] bits are supported by this filesystem.
    pub fn attributes_mask(&self) -> StatxAttr {
        StatxAttr::from_bits_retain(self.0.stx_attributes_mask)
    }

    /// The file mode (type + permission bits).
    pub fn mode(&self) -> u16 {
        self.0.stx_mode
    }

    /// Number of hard links.
    pub fn nlink(&self) -> u32 {
        self.0.stx_nlink
    }

    /// Owner user id.
    pub fn uid(&self) -> u32 {
        self.0.stx_uid
    }

    /// Owner group id.
    pub fn gid(&self) -> u32 {
        self.0.stx_gid
    }

    /// Inode number.
    pub fn ino(&self) -> u64 {
        self.0.stx_ino
    }

    /// File size in bytes.
    pub fn size(&self) -> u64 {
        self.0.stx_size
    }

    /// Number of 512-byte blocks allocated.
    pub fn blocks(&self) -> u64 {
        self.0.stx_blocks
    }

    /// Preferred I/O block size.
    pub fn blksize(&self) -> u32 {
        self.0.stx_blksize
    }

    /// Unique mount id of the mount containing this file.
    pub fn mnt_id(&self) -> u64 {
        self.0.stx_mnt_id
    }

    /// Subvolume identifier - **btrfs only**.
    ///
    /// A btrfs inode number is unique only within its subvolume, so two files
    /// in different subvolumes of one filesystem can share an `st_ino`. btrfs
    /// works around that by giving each subvolume its own *anonymous* device
    /// number, which restores a unique `(dev, ino)` but costs `st_dev` its
    /// usual meaning: one mount then reports many devices, and a caller using
    /// `st_dev` to detect mount boundaries is misled.
    /// [`StatxMask::SUBVOL`] exposes the subvolume id directly so `(subvol,
    /// ino)` can be formed without inferring it from a synthetic device.
    ///
    /// **btrfs is the only filesystem in the kernel that fills this**
    /// (`fs/btrfs/inode.c`, `btrfs_getattr`). ZFS in particular does not, so
    /// this is *not* a way to identify a dataset - use the device number, or
    /// [`StatxAttr::MOUNT_ROOT`] in [`attributes`](Self::attributes) to
    /// recognise a mount root.
    ///
    /// Returns the raw field, so an unreported value reads as `0` rather than
    /// as absent. Check [`mask`](Self::mask) for [`StatxMask::SUBVOL`] to
    /// tell the two apart.
    pub fn subvol(&self) -> u64 {
        self.0.stx_subvol
    }

    /// The inode's change cookie - the NFSv4 change attribute, a per-inode
    /// counter the kernel bumps on every content or metadata modification.
    ///
    /// `None` unless [`StatxMask::CHANGE_COOKIE`] was requested *and* the
    /// filesystem supplied it (the kernel reports what it actually filled in
    /// [`mask`](Self::mask), so an unsupported filesystem is distinguishable
    /// from an unmodified file rather than silently reading as `0`).
    ///
    /// This is the exact validator for anything derived from a file and
    /// cached elsewhere - a checksum, a parsed ACL, a directory's sorted
    /// entry list. Comparing it beats comparing `(size, mtime)`, which is a
    /// timestamp-granularity heuristic. Note the value is only meaningful
    /// within one filesystem instance: it is not preserved across a
    /// `send`/`recv` to another pool, so a *persisted* cookie is worth
    /// corroborating with size and mtime.
    pub fn change_cookie(&self) -> Option<u64> {
        self.mask()
            .contains(StatxMask::CHANGE_COOKIE)
            .then_some(self.0.stx_change_cookie)
    }

    /// The inode generation, which tells a reused inode number from the
    /// file that held it before.
    ///
    /// `None` unless [`StatxMask::GEN`] was requested *and* the filesystem
    /// supplied it. Only the TrueNAS fork passes the field through
    /// `cp_statx` (under `CONFIG_TRUENAS`, fs/stat.c), and only a filesystem
    /// that sets `kstat->gen` fills it: ZFS does, from `i_generation`
    /// (`zpl_getattr_impl`, module/os/linux/zfs/zpl_inode.c). That is the
    /// creation txg truncated to 32 bits - the generation a ZFS file handle
    /// carries, before `zfs_fid` remaps a zero to one.
    pub fn generation(&self) -> Option<u64> {
        self.mask()
            .contains(StatxMask::GEN)
            .then_some(self.0.stx_gen)
    }

    /// The DOS attributes of a ZFS file, the bits
    /// [`fget_zfs_attrs`](super::fget_zfs_attrs) reads, from the same
    /// `statx` and through any descriptor, `O_PATH` included, where the ioctl
    /// needs one opened for I/O.
    ///
    /// `None` unless [`StatxMask::ZFSFLAGS`] was requested *and* the
    /// filesystem supplied it. Only the TrueNAS fork passes the field through
    /// `cp_statx` (under `CONFIG_TRUENAS`, fs/stat.c), and only ZFS fills
    /// it, from `z_pflags` cut to `ZFS_DOS_FL_USER_VISIBLE`
    /// (`zpl_getattr_impl`, module/os/linux/zfs/zpl_inode.c), the mask
    /// `zpl_ioctl_getdosflags` answers with too. The field's other bits,
    /// `ZFS_ACL_TRIVIAL` and the flags of the ACL, are
    /// [`nfs4_acl_flags`](Self::nfs4_acl_flags)'s and are left out here,
    /// since the setter refuses them.
    pub fn zfs_attrs(&self) -> Option<ZfsAttr> {
        self.mask()
            .contains(StatxMask::ZFSFLAGS)
            .then(|| ZfsAttr::from_bits_truncate(self.0.stx_zfsflags))
    }

    /// Whether ZFS holds the file's NFSv4 ACL as trivial, one the mode
    /// bits say all of (`ZFS_ACL_TRIVIAL`, include/sys/zfs_znode.h).
    ///
    /// `None` unless [`StatxMask::ZFSFLAGS`] was requested and supplied, as
    /// for [`zfs_attrs`](Self::zfs_attrs). **Meaningful on an `acltype=nfsv4`
    /// dataset alone.** `zpl_getattr_impl` reports the bit only there, since
    /// only there does a trivial ACL send the permission check back to the
    /// mode (`zpl_permission`, module/os/linux/zfs/zpl_xattr.c), so on any
    /// other acltype this is `Some(false)` whatever the file holds. It is the
    /// bit `zfs_getacl` turns into `ACL_IS_TRIVIAL` in the flags of
    /// `system.nfs4_acl_xdr` (module/os/linux/zfs/zfs_acl.c), so it answers
    /// what reading that attribute would, with no read.
    pub fn nfs4_acl_is_trivial(&self) -> Option<bool> {
        // `include/sys/zfs_znode.h`.
        const ZFS_ACL_TRIVIAL: u64 = 0x4;
        self.mask()
            .contains(StatxMask::ZFSFLAGS)
            .then_some(self.0.stx_zfsflags & ZFS_ACL_TRIVIAL != 0)
    }

    /// The flags of the file's NFSv4 ACL, auto-inherit, protected, defaulted
    /// and `ACL_IS_TRIVIAL`, as `system.nfs4_acl_xdr` gives them, with no read
    /// of the ACL.
    ///
    /// `None` unless [`StatxMask::ZFSFLAGS`] was requested and supplied, as
    /// for [`zfs_attrs`](Self::zfs_attrs). **Meaningful on an `acltype=nfsv4`
    /// dataset alone**, as for
    /// [`nfs4_acl_is_trivial`](Self::nfs4_acl_is_trivial), so on any other
    /// acltype this is empty. `zpl_getattr_impl` reports `ZFS_ACL_PROTECTED`,
    /// `ZFS_ACL_DEFAULTED` and `ZFS_ACL_AUTO_INHERIT` beside `ZFS_ACL_TRIVIAL`,
    /// the four bits of `z_pflags` that `zfs_getsecattr` turns into these
    /// flags (module/os/linux/zfs/zfs_acl.c). A ZFS module that reports the
    /// trivial bit alone leaves the other three clear. `ACL_IS_DIR` is left
    /// out, since the file type says it.
    #[cfg(feature = "acl")]
    pub fn nfs4_acl_flags(&self) -> Option<super::acl::Nfs4AclFlag> {
        use super::acl::Nfs4AclFlag;
        // `include/sys/zfs_znode.h`, in the order `zfs_getsecattr` maps them.
        const FLAGS: [(u64, Nfs4AclFlag); 4] = [
            (0x20, Nfs4AclFlag::DEFAULTED),
            (0x10, Nfs4AclFlag::PROTECTED),
            (0x40, Nfs4AclFlag::AUTO_INHERIT),
            (0x4, Nfs4AclFlag::ACL_IS_TRIVIAL),
        ];
        let raw = self.0.stx_zfsflags;
        self.mask().contains(StatxMask::ZFSFLAGS).then(|| {
            FLAGS
                .iter()
                .filter(|(bit, _)| raw & bit != 0)
                .fold(Nfs4AclFlag::empty(), |all, (_, flag)| all | *flag)
        })
    }

    /// Last access time.
    pub fn atime(&self) -> StatxTimestamp {
        ts(self.0.stx_atime)
    }

    /// Creation (birth) time.
    pub fn btime(&self) -> StatxTimestamp {
        ts(self.0.stx_btime)
    }

    /// Last status-change time.
    pub fn ctime(&self) -> StatxTimestamp {
        ts(self.0.stx_ctime)
    }

    /// Last modification time.
    pub fn mtime(&self) -> StatxTimestamp {
        ts(self.0.stx_mtime)
    }

    /// Combined `dev_t` of the containing device.
    pub fn dev(&self) -> u64 {
        makedev(self.0.stx_dev_major, self.0.stx_dev_minor)
    }

    /// Combined `dev_t` of the represented device (for block/char specials).
    pub fn rdev(&self) -> u64 {
        makedev(self.0.stx_rdev_major, self.0.stx_rdev_minor)
    }

    /// Major id of the containing device.
    pub fn dev_major(&self) -> u32 {
        self.0.stx_dev_major
    }

    /// Minor id of the containing device.
    pub fn dev_minor(&self) -> u32 {
        self.0.stx_dev_minor
    }

    /// True if this is a directory.
    pub fn is_dir(&self) -> bool {
        self.file_type() == libc::S_IFDIR
    }

    /// True if this is a regular file.
    pub fn is_regular(&self) -> bool {
        self.file_type() == libc::S_IFREG
    }

    /// True if this is a symbolic link.
    pub fn is_symlink(&self) -> bool {
        self.file_type() == libc::S_IFLNK
    }

    fn file_type(&self) -> libc::mode_t {
        self.0.stx_mode as libc::mode_t & libc::S_IFMT
    }

    /// The raw kernel `struct statx`.
    pub fn raw(&self) -> &StatxRaw {
        &self.0
    }

    /// Wrap a kernel-filled `struct statx` (the io_uring `STATX` op writes
    /// one into a buffer the completion hands back).
    #[cfg_attr(not(feature = "uring-fs"), allow(dead_code))]
    pub(crate) fn from_raw(raw: StatxRaw) -> Statx {
        Statx(raw)
    }
}

/// Retrieve extended attributes for the file named by `path` relative to
/// `dirfd`.
///
/// Combine `AtFlags::AT_EMPTY_PATH` with an empty path to stat `dirfd` itself.
///
/// See [`statx(2)`](https://man7.org/linux/man-pages/man2/statx.2.html).
pub fn statx<P, Fd>(
    dirfd: Fd,
    path: &P,
    flags: AtFlags,
    mask: StatxMask,
) -> errno::Result<Statx>
where
    P: ?Sized + TnPath,
    Fd: AsFd,
{
    let raw_dirfd = dirfd.as_fd().as_raw_fd();
    let mut buf = MaybeUninit::<StatxRaw>::uninit();
    let buf_ptr = buf.as_mut_ptr();
    let res = path.with_tn_path(|cstr| {
        retry_on_eintr(|| unsafe {
            libc::syscall(
                libc::SYS_statx,
                raw_dirfd,
                cstr.as_ptr(),
                flags.bits(),
                mask.bits(),
                buf_ptr,
            )
        })
    })?;
    res?;
    // SAFETY: `statx` succeeded, so it initialised the whole `struct statx`.
    Ok(Statx(unsafe { buf.assume_init() }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `struct statx` whose mask is `mask` and whose ZFS flags are `flags`,
    /// every other field zero.
    fn filled(mask: StatxMask, flags: u64) -> Statx {
        // SAFETY: `StatxRaw` is plain integers, for which all zero bits are
        // a valid value.
        let mut raw: StatxRaw = unsafe { std::mem::zeroed() };
        raw.stx_mask = mask.bits();
        raw.stx_zfsflags = flags;
        Statx::from_raw(raw)
    }

    /// The values are those of `include/sys/fs/zfs.h` and
    /// `include/sys/zfs_znode.h`, written out by hand. HIDDEN is
    /// 0x0000000200000000, ARCHIVE 0x0000000800000000, ZFS_ACL_TRIVIAL 0x4,
    /// and ZFS_AV_MODIFIED 0x0000040000000000, which ZFS keeps to itself.
    #[test]
    fn the_zfs_flags_split_into_the_dos_attributes_and_the_trivial_bit() {
        let flags = 0x0000_0002_0000_0000
            | 0x0000_0008_0000_0000
            | 0x4
            | 0x0000_0400_0000_0000;
        let st = filled(StatxMask::ZFSFLAGS, flags);
        assert_eq!(st.zfs_attrs(), Some(ZfsAttr::HIDDEN | ZfsAttr::ARCHIVE));
        assert_eq!(st.nfs4_acl_is_trivial(), Some(true));
        let st = filled(StatxMask::ZFSFLAGS, 0x0000_0002_0000_0000);
        assert_eq!(st.zfs_attrs(), Some(ZfsAttr::HIDDEN));
        assert_eq!(st.nfs4_acl_is_trivial(), Some(false));
        // A kernel that did not fill the field leaves its bit out of the
        // mask, and whatever the field holds then means nothing.
        let st = filled(StatxMask::BASIC_STATS, flags);
        assert_eq!(st.zfs_attrs(), None);
        assert_eq!(st.nfs4_acl_is_trivial(), None);
    }

    /// `include/sys/zfs_znode.h` has ZFS_ACL_PROTECTED 0x10,
    /// ZFS_ACL_DEFAULTED 0x20 and ZFS_ACL_AUTO_INHERIT 0x40, which
    /// `zfs_getsecattr` turns into ACL_PROTECTED 0x2, ACL_DEFAULTED 0x4 and
    /// ACL_AUTO_INHERIT 0x1, and ZFS_ACL_TRIVIAL into ACL_IS_TRIVIAL
    /// 0x10000, all written out by hand. ZFS_INHERIT_ACE 0x2 and
    /// ZFS_ACL_OBJ_ACE 0x8 are bits ZFS keeps to itself.
    #[cfg(feature = "acl")]
    #[test]
    fn the_zfs_flags_give_the_flags_of_the_acl() {
        let flags = |raw| {
            filled(StatxMask::ZFSFLAGS, raw)
                .nfs4_acl_flags()
                .map(|f| f.bits())
        };
        assert_eq!(flags(0x10), Some(0x2));
        assert_eq!(flags(0x20), Some(0x4));
        assert_eq!(flags(0x40), Some(0x1));
        assert_eq!(flags(0x4), Some(0x1_0000));
        assert_eq!(flags(0x74), Some(0x1_0007));
        let others = 0x0000_0002_0000_0000 | 0x0000_0400_0000_0000 | 0x2 | 0x8;
        assert_eq!(flags(others), Some(0));
        let st = filled(StatxMask::BASIC_STATS, 0x74);
        assert_eq!(st.nfs4_acl_flags(), None);
    }
}
