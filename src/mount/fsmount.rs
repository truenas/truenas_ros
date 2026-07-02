//! `fsopen(2)` / `fsconfig(2)` / `fsmount(2)` — the mount-context API.

use super::MountAttr;
use crate::errno::{self, retry_on_eintr};
use crate::fd::owned_from_raw;
use crate::path::cstr;
use std::ffi::c_void;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd};
use std::ptr::null;

tn_bitflags! {
    /// Flags for [`fsopen`].
    pub struct FsopenFlags: libc::c_uint {
        /// Set close-on-exec on the returned filesystem-context fd.
        FSOPEN_CLOEXEC = 0x0000_0001;
    }
}

tn_bitflags! {
    /// Flags for [`fsmount`].
    pub struct FsmountFlags: libc::c_uint {
        /// Set close-on-exec on the returned mount fd.
        FSMOUNT_CLOEXEC = 0x0000_0001;
    }
}

tn_enum! {
    /// `fsconfig` command codes (`FSCONFIG_*`).
    pub enum FsConfigCmd: u32 {
        /// Set a flag parameter (no value).
        SetFlag = 0,
        /// Set a string-valued parameter.
        SetString = 1,
        /// Set a binary-blob parameter.
        SetBinary = 2,
        /// Set a parameter from an object by path.
        SetPath = 3,
        /// Set a parameter from an object by (empty) path.
        SetPathEmpty = 4,
        /// Set a parameter from an object by file descriptor.
        SetFd = 5,
        /// Create a new (or reuse an existing) superblock.
        CmdCreate = 6,
        /// Reconfigure the superblock.
        CmdReconfigure = 7,
        /// Create a new superblock, failing if one would be reused.
        CmdCreateExcl = 8,
    }
}

/// A single [`fsconfig`] operation.
#[derive(Debug)]
pub enum FsConfig<'a> {
    /// Set a flag parameter (`key`, no value).
    Flag {
        /// Parameter name.
        key: &'a str,
    },
    /// Set a string-valued parameter.
    String {
        /// Parameter name.
        key: &'a str,
        /// Parameter value.
        value: &'a str,
    },
    /// Set a binary-blob parameter.
    Binary {
        /// Parameter name.
        key: &'a str,
        /// Parameter value.
        value: &'a [u8],
    },
    /// Set a parameter from an object referenced by a file descriptor.
    Fd {
        /// Parameter name.
        key: &'a str,
        /// The object's file descriptor (passed as the `aux` argument).
        fd: BorrowedFd<'a>,
    },
    /// Create a new superblock (or reuse an existing one).
    Create,
    /// Reconfigure the superblock.
    Reconfigure,
    /// Create a new superblock, failing if one would be reused.
    CreateExcl,
}

/// Create a new filesystem-configuration context for filesystem type
/// `fs_name`.
///
/// See [`fsopen(2)`](https://man7.org/linux/man-pages/man2/fsopen.2.html).
pub fn fsopen(fs_name: &str, flags: FsopenFlags) -> errno::Result<OwnedFd> {
    let name = cstr(fs_name)?;
    let fd = retry_on_eintr(|| unsafe {
        libc::syscall(libc::SYS_fsopen, name.as_ptr(), flags.bits())
    })?;
    // SAFETY: fsopen returns a fresh owned fd on success.
    Ok(unsafe { owned_from_raw(fd as RawFd) })
}

/// Apply a configuration operation to a filesystem context from [`fsopen`].
///
/// See [`fsconfig(2)`](https://man7.org/linux/man-pages/man2/fsconfig.2.html).
pub fn fsconfig<Fd: AsFd>(fs_fd: Fd, op: FsConfig<'_>) -> errno::Result<()> {
    let fd = fs_fd.as_fd().as_raw_fd();
    let call = |cmd: FsConfigCmd,
                key: *const libc::c_char,
                value: *const c_void,
                aux: libc::c_int|
     -> errno::Result<libc::c_long> {
        retry_on_eintr(|| unsafe {
            libc::syscall(
                libc::SYS_fsconfig,
                fd,
                cmd as libc::c_uint,
                key,
                value,
                aux,
            )
        })
    };
    match op {
        FsConfig::Flag { key } => {
            let k = cstr(key)?;
            call(FsConfigCmd::SetFlag, k.as_ptr(), null(), 0)?;
        }
        FsConfig::String { key, value } => {
            let k = cstr(key)?;
            let v = cstr(value)?;
            call(FsConfigCmd::SetString, k.as_ptr(), v.as_ptr().cast(), 0)?;
        }
        FsConfig::Binary { key, value } => {
            let k = cstr(key)?;
            call(
                FsConfigCmd::SetBinary,
                k.as_ptr(),
                value.as_ptr().cast(),
                value.len() as libc::c_int,
            )?;
        }
        FsConfig::Fd { key, fd: obj } => {
            let k = cstr(key)?;
            call(FsConfigCmd::SetFd, k.as_ptr(), null(), obj.as_raw_fd())?;
        }
        FsConfig::Create => {
            call(FsConfigCmd::CmdCreate, null(), null(), 0)?;
        }
        FsConfig::Reconfigure => {
            call(FsConfigCmd::CmdReconfigure, null(), null(), 0)?;
        }
        FsConfig::CreateExcl => {
            call(FsConfigCmd::CmdCreateExcl, null(), null(), 0)?;
        }
    }
    Ok(())
}

/// Create a mount object from a configured filesystem context.
///
/// `attr` supplies the initial per-mount attributes (`MOUNT_ATTR_*`).
///
/// See [`fsmount(2)`](https://man7.org/linux/man-pages/man2/fsmount.2.html).
pub fn fsmount<Fd: AsFd>(
    fs_fd: Fd,
    flags: FsmountFlags,
    attr: MountAttr,
) -> errno::Result<OwnedFd> {
    let fd = fs_fd.as_fd().as_raw_fd();
    let m = retry_on_eintr(|| unsafe {
        libc::syscall(
            libc::SYS_fsmount,
            fd,
            flags.bits(),
            attr.bits() as libc::c_uint,
        )
    })?;
    // SAFETY: fsmount returns a fresh owned fd on success.
    Ok(unsafe { owned_from_raw(m as RawFd) })
}
