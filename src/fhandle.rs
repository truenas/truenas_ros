//! File handles: `name_to_handle_at(2)` / `open_by_handle_at(2)`.
//!
//! A [`FileHandle`] is an opaque, filesystem-issued reference to an inode that
//! survives across renames. It is paired with a *mount id* (carried
//! out-of-band, not in the serialized bytes) identifying the filesystem it
//! belongs to; [`FileHandle::open`] re-opens the inode given any fd on that
//! same mount.

use crate::errno::{self, retry_on_eintr};
use crate::error::{Error, Result};
use crate::fd::owned_from_raw;
use crate::fs::{statx, AtFlags, OFlag, StatxMask};
use crate::path::TnPath;
use std::os::fd::{AsFd, AsRawFd, OwnedFd, RawFd};

/// Maximum size of the opaque handle data (`MAX_HANDLE_SZ`).
const MAX_HANDLE_SZ: usize = 128;
/// `offsetof(struct file_handle, f_handle)` — the `handle_bytes` + `handle_type`
/// header.
const HEADER_SZ: usize = 8;
/// Sentinel mount id for an uninitialised handle.
const MOUNT_ID_NONE: u64 = u64::MAX;

tn_bitflags! {
    /// Flags for [`name_to_handle_at`] (`AT_*` handle flags).
    pub struct FhFlags: libc::c_int {
        /// Dereference a trailing symbolic link.
        AT_SYMLINK_FOLLOW = 0x0000_0400;
        /// Operate on `dirfd` itself when the path is empty.
        AT_EMPTY_PATH = 0x0000_1000;
        /// Request a handle suitable only for comparing file identity.
        AT_HANDLE_FID = 0x0000_0200;
        /// Request a connectable handle (one that can reach the file's parent).
        AT_HANDLE_CONNECTABLE = 0x0000_0002;
        /// Return the full 64-bit unique mount id.
        AT_HANDLE_MNT_ID_UNIQUE = 0x0000_0001;
    }
}

/// Kernel `struct file_handle` with an inline maximum-size handle buffer.
#[repr(C)]
#[derive(Clone, Copy)]
struct RawFileHandle {
    handle_bytes: u32,
    handle_type: i32,
    f_handle: [u8; MAX_HANDLE_SZ],
}

const _: () =
    assert!(core::mem::size_of::<RawFileHandle>() == HEADER_SZ + MAX_HANDLE_SZ);

/// An opaque handle to a file plus the mount it lives on.
#[derive(Clone)]
pub struct FileHandle {
    raw: RawFileHandle,
    mount_id: u64,
    unique_mount_id: bool,
}

impl std::fmt::Debug for FileHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileHandle")
            .field("handle_type", &self.raw.handle_type)
            .field("handle_bytes", &self.raw.handle_bytes)
            .field("mount_id", &self.mount_id)
            .field("unique_mount_id", &self.unique_mount_id)
            .finish()
    }
}

impl FileHandle {
    /// The mount id the handle belongs to.
    pub fn mount_id(&self) -> u64 {
        self.mount_id
    }

    /// Whether [`FileHandle::mount_id`] is the 64-bit unique mount id (as
    /// opposed to the legacy 32-bit id).
    pub fn unique_mount_id(&self) -> bool {
        self.unique_mount_id
    }

    fn handle_data_len(&self) -> usize {
        self.raw.handle_bytes as usize
    }

    /// Serialize the raw `struct file_handle` (host-endian header +
    /// `handle_bytes` of opaque data). The mount id is **not** included; keep
    /// it alongside and pass it back to [`FileHandle::from_bytes`].
    pub fn to_bytes(&self) -> Vec<u8> {
        let n = self.handle_data_len();
        let mut out = Vec::with_capacity(HEADER_SZ + n);
        out.extend_from_slice(&self.raw.handle_bytes.to_ne_bytes());
        out.extend_from_slice(&self.raw.handle_type.to_ne_bytes());
        out.extend_from_slice(&self.raw.f_handle[..n]);
        out
    }

    /// Reconstruct a handle from [`FileHandle::to_bytes`] output plus the mount
    /// id it was captured with.
    pub fn from_bytes(
        data: &[u8],
        mount_id: u64,
        unique_mount_id: bool,
    ) -> Result<Self> {
        if data.len() < HEADER_SZ {
            return Err(Error::Validation(format!(
                "file handle too small: {} bytes (min {HEADER_SZ})",
                data.len()
            )));
        }
        if data.len() > HEADER_SZ + MAX_HANDLE_SZ {
            return Err(Error::Validation(format!(
                "file handle too large: {} bytes (max {})",
                data.len(),
                HEADER_SZ + MAX_HANDLE_SZ
            )));
        }
        let handle_bytes = u32::from_ne_bytes(data[0..4].try_into().unwrap());
        let handle_type = i32::from_ne_bytes(data[4..8].try_into().unwrap());
        let n = handle_bytes as usize;
        if n > data.len() - HEADER_SZ {
            return Err(Error::Validation(format!(
                "encoded handle length {n} exceeds available {} bytes",
                data.len() - HEADER_SZ
            )));
        }
        let mut f_handle = [0u8; MAX_HANDLE_SZ];
        f_handle[..n].copy_from_slice(&data[HEADER_SZ..HEADER_SZ + n]);
        Ok(FileHandle {
            raw: RawFileHandle {
                handle_bytes,
                handle_type,
                f_handle,
            },
            mount_id,
            unique_mount_id,
        })
    }

    /// Re-open the file this handle refers to, given any fd (`mount_fd`) on the
    /// same mount.
    ///
    /// The mount id of `mount_fd` is verified against the handle's before the
    /// `open_by_handle_at` call, so a handle cannot be used against the wrong
    /// filesystem.
    ///
    /// Requires `CAP_DAC_READ_SEARCH`.
    pub fn open<Fd: AsFd>(
        &self,
        mount_fd: Fd,
        flags: OFlag,
    ) -> Result<OwnedFd> {
        if self.mount_id == MOUNT_ID_NONE {
            return Err(Error::Validation(
                "file handle is uninitialised".into(),
            ));
        }
        let mount_fd = mount_fd.as_fd();
        let mask = if self.unique_mount_id {
            StatxMask::MNT_ID_UNIQUE
        } else {
            StatxMask::MNT_ID
        };
        let st = statx(mount_fd, "", AtFlags::AT_EMPTY_PATH, mask)?;
        if st.mnt_id() != self.mount_id {
            return Err(Error::Validation(format!(
                "mount fd mount id {} does not match handle mount id {}",
                st.mnt_id(),
                self.mount_id
            )));
        }
        let fd = retry_on_eintr(|| unsafe {
            libc::syscall(
                libc::SYS_open_by_handle_at,
                mount_fd.as_raw_fd(),
                &self.raw as *const RawFileHandle,
                flags.bits(),
            )
        })
        .map_err(Error::from)?;
        // SAFETY: open_by_handle_at returns a fresh owned fd on success.
        Ok(unsafe { owned_from_raw(fd as RawFd) })
    }
}

/// Obtain a [`FileHandle`] for the file named by `path` relative to `dirfd`.
///
/// `ENOTDIR` means `dirfd` is not a directory; `EOPNOTSUPP` means the
/// filesystem cannot encode handles.
///
/// See [`name_to_handle_at(2)`](https://man7.org/linux/man-pages/man2/name_to_handle_at.2.html).
pub fn name_to_handle_at<P, Fd>(
    dirfd: Fd,
    path: &P,
    flags: FhFlags,
) -> Result<FileHandle>
where
    P: ?Sized + TnPath,
    Fd: AsFd,
{
    let mut raw = RawFileHandle {
        handle_bytes: MAX_HANDLE_SZ as u32,
        handle_type: 0,
        f_handle: [0u8; MAX_HANDLE_SZ],
    };
    // Zero-initialised so the high half is clean when the kernel writes only
    // the legacy 32-bit id (without AT_HANDLE_MNT_ID_UNIQUE).
    let mut mnt_id: u64 = 0;
    let dfd = dirfd.as_fd().as_raw_fd();
    let res: errno::Result<libc::c_long> = path.with_tn_path(|c| {
        retry_on_eintr(|| unsafe {
            libc::syscall(
                libc::SYS_name_to_handle_at,
                dfd,
                c.as_ptr(),
                &mut raw as *mut RawFileHandle,
                &mut mnt_id as *mut u64,
                flags.bits(),
            )
        })
    })?;
    res?;
    Ok(FileHandle {
        raw,
        mount_id: mnt_id,
        unique_mount_id: flags.contains(FhFlags::AT_HANDLE_MNT_ID_UNIQUE),
    })
}
