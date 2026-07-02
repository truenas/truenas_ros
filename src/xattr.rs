//! Extended-attribute I/O on open file descriptors.
//!
//! [`fgetxattr`] / [`fsetxattr`] / [`flistxattr`] mirror the `truenas_os` C
//! extension's
//! buffer-sizing and retry behaviour and enforce TrueNAS's 2 MiB per-value cap.

use crate::errno::{self, retry_on_eintr, Errno};
use crate::path::cstr;
use std::os::fd::{AsFd, AsRawFd};

/// Maximum extended-attribute value size accepted (2 MiB), matching the C
/// extension's `TRUENAS_XATTR_SIZE_MAX`.
pub const XATTR_SIZE_MAX: usize = 2 * 1024 * 1024;

/// Kernel cap on the combined size of an xattr name list (`XATTR_LIST_MAX`).
const XATTR_LIST_MAX: usize = 64 * 1024;

tn_bitflags! {
    /// Flags for [`fsetxattr`] (`XATTR_CREATE` / `XATTR_REPLACE`).
    pub struct XattrFlags: libc::c_int {
        /// Fail with `EEXIST` if the attribute already exists.
        XATTR_CREATE;
        /// Fail with `ENODATA` if the attribute does not already exist.
        XATTR_REPLACE;
    }
}

/// Read the extended attribute `name` from an open file descriptor.
///
/// Returns `Err(Errno::ENODATA)` if the attribute is absent and
/// `Err(Errno::E2BIG)` if its value exceeds [`XATTR_SIZE_MAX`].
pub fn fgetxattr<Fd: AsFd>(fd: Fd, name: &str) -> errno::Result<Vec<u8>> {
    let name = cstr(name)?;
    let raw = fd.as_fd().as_raw_fd();
    loop {
        // Probe the current size.
        let size = retry_on_eintr(|| unsafe {
            libc::fgetxattr(raw, name.as_ptr(), std::ptr::null_mut(), 0)
        })? as usize;
        if size > XATTR_SIZE_MAX {
            return Err(Errno::E2BIG);
        }
        // Allocate at least one byte so the pointer is valid.
        let mut buf = vec![0u8; size.max(1)];
        let read = retry_on_eintr(|| unsafe {
            libc::fgetxattr(
                raw,
                name.as_ptr(),
                buf.as_mut_ptr().cast(),
                buf.len(),
            )
        });
        match read {
            Ok(n) => {
                buf.truncate(n as usize);
                return Ok(buf);
            }
            // The value grew between the probe and the read; retry.
            Err(Errno::ERANGE) => continue,
            Err(e) => return Err(e),
        }
    }
}

/// Set the extended attribute `name` to `value` on an open file descriptor.
///
/// `value` longer than [`XATTR_SIZE_MAX`] is rejected with `Err(Errno::E2BIG)`.
pub fn fsetxattr<Fd: AsFd>(
    fd: Fd,
    name: &str,
    value: &[u8],
    flags: XattrFlags,
) -> errno::Result<()> {
    if value.len() > XATTR_SIZE_MAX {
        return Err(Errno::E2BIG);
    }
    let name = cstr(name)?;
    let raw = fd.as_fd().as_raw_fd();
    retry_on_eintr(|| unsafe {
        libc::fsetxattr(
            raw,
            name.as_ptr(),
            value.as_ptr().cast(),
            value.len(),
            flags.bits(),
        )
    })?;
    Ok(())
}

/// Remove the extended attribute `name` from an open file descriptor.
///
/// Returns `Err(Errno::ENODATA)` if the attribute is absent.
pub fn fremovexattr<Fd: AsFd>(fd: Fd, name: &str) -> errno::Result<()> {
    let name = cstr(name)?;
    let raw = fd.as_fd().as_raw_fd();
    retry_on_eintr(|| unsafe { libc::fremovexattr(raw, name.as_ptr()) })?;
    Ok(())
}

/// List the names of the extended attributes on an open file descriptor.
pub fn flistxattr<Fd: AsFd>(fd: Fd) -> errno::Result<Vec<String>> {
    let raw = fd.as_fd().as_raw_fd();
    let mut buf = vec![0u8; 256];
    let len = loop {
        let res = retry_on_eintr(|| unsafe {
            libc::flistxattr(raw, buf.as_mut_ptr().cast(), buf.len())
        });
        match res {
            Ok(n) => break n as usize,
            Err(Errno::ERANGE) => {
                if buf.len() >= XATTR_LIST_MAX {
                    return Err(Errno::E2BIG);
                }
                buf = vec![0u8; XATTR_LIST_MAX];
            }
            Err(e) => return Err(e),
        }
    };
    Ok(buf[..len]
        .split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect())
}
