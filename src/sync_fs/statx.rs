//! `statx(2)` — extended file attributes.

use super::AtFlags;
use crate::errno::{self, retry_on_eintr};
use crate::path::TnPath;
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, AsRawFd};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

tn_bitflags! {
    /// `STATX_*` — the set of fields requested from / returned by `statx`.
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
        /// Want/got the change cookie (durable/persistent handle support).
        CHANGE_COOKIE = 0x4000_0000;
    }
}

tn_bitflags! {
    /// `STATX_ATTR_*` — flags reported in [`Statx::attributes`].
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
    pub __spare3: [u64; 7],
}

const _: () = assert!(core::mem::size_of::<StatxTimestampRaw>() == 16);
const _: () = assert!(core::mem::size_of::<StatxRaw>() == 256);

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

    /// Subvolume identifier (e.g. ZFS dataset id).
    pub fn subvol(&self) -> u64 {
        self.0.stx_subvol
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
