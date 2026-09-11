//! Extended-attribute I/O on open file descriptors.
//!
//! [`fgetxattr`] / [`fsetxattr`] / [`flistxattr`] mirror the `truenas_os` C
//! extension's
//! buffer-sizing and retry behaviour and enforce TrueNAS's 2 MiB per-value cap.

use crate::errno::{self, Errno, retry_on_eintr};
use crate::path::TnPath;
use std::ffi::{CStr, CString};
use std::os::fd::{AsFd, AsRawFd, RawFd};

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
/// `name` is any [`TnPath`] - a `&str` for a literal, or the [`CStr`] that
/// [`flistxattr`] returns for a discovered attribute whose bytes need not be
/// UTF-8.
///
/// Returns `Err(Errno::ENODATA)` if the attribute is absent and
/// `Err(Errno::E2BIG)` if its value exceeds [`XATTR_SIZE_MAX`].
pub fn fgetxattr<Fd: AsFd, N: ?Sized + TnPath>(
    fd: Fd,
    name: &N,
) -> errno::Result<Vec<u8>> {
    let raw = fd.as_fd().as_raw_fd();
    name.with_tn_path(|name| fgetxattr_cstr(raw, name))?
}

/// How many times a value that keeps growing under the reader is re-probed
/// before giving up.
pub(crate) const XATTR_SIZE_RETRIES: u32 = 4;

/// Buffer size for attempt `tries` at reading a value the kernel just sized at
/// `size`.
///
/// At least one byte, so the pointer handed to the kernel is valid even for an
/// empty value; from the first retry onward, half again, so a value growing
/// steadily under the reader converges instead of spinning at exactly its last
/// observed size. The async reader in `uring_fs::query_dir` runs the same
/// policy over the ring, and the two are only comparable if they share this.
pub(crate) fn xattr_retry_cap(size: usize, tries: u32) -> usize {
    if tries == 0 {
        size.max(1)
    } else {
        (size + size / 2).clamp(1, XATTR_SIZE_MAX)
    }
}

/// Whether an `fgetxattr` errno means "your buffer was too small", which
/// the kernel spells two ways.
///
/// `do_getxattr` (`fs/xattr.c:852-857`) ends by rewriting the filesystem's
/// `-ERANGE` to `-E2BIG` whenever the *caller's* buffer is at or above the
/// kernel's own `XATTR_SIZE_MAX`:
///
/// ```text
/// } else if (error == -ERANGE && ctx->size >= XATTR_SIZE_MAX) {
///         error = -E2BIG;
/// ```
///
/// That constant is 65536 (`uapi/linux/limits.h:16`) and the rewrite carries
/// no `IS_LARGE_XATTR` guard, even though the size clamp directly above it
/// does - so on a filesystem whose values may legitimately reach
/// `XATTR_LARGE_SIZE_MAX` (2 MiB, `limits.h:18`, which is what
/// [`XATTR_SIZE_MAX`] here follows) a retry buffer big enough for a large
/// value is exactly the buffer whose short read is reported as `E2BIG`.
/// Measured on a ZFS dataset against a 204800-byte value: buffer 4096 and
/// 65535 answer `ERANGE`, 65536 and 65537 answer `E2BIG`, 204800 answers
/// `Ok(204800)`.
///
/// Both retry loops screen the *probed* length against [`XATTR_SIZE_MAX`],
/// so a value genuinely past the cap is still refused `E2BIG` - by the
/// probe, not by this.
pub(crate) fn is_short_buffer(e: Errno) -> bool {
    matches!(e, Errno::ERANGE | Errno::E2BIG)
}

/// First-read buffer: values at or under this cost ONE syscall, no size
/// probe. The same policy as the async sibling's `DISCOVER_BUF`
/// (`uring_fs/query_dir.rs`), and the same size; probing first costs a
/// second syscall on every value to save an over-allocation on none - the
/// probe's ~2x latency is pure loss at realistic value sizes.
const INITIAL_BUF: usize = 4096;

fn fgetxattr_cstr(raw: RawFd, name: &CStr) -> errno::Result<Vec<u8>> {
    // Read first, size only on a short buffer ([`is_short_buffer`], which
    // is `ERANGE` or `E2BIG` - the kernel spells it two ways and the
    // buffer decides which): the value outgrew the buffer (or grew between
    // a probe and its read - the same race, handled the same way), so
    // probe the current size and retry a bounded number of times,
    // over-allocating on retry so a steadily growing value converges
    // rather than spinning.
    let mut cap = INITIAL_BUF;
    let mut tries = 0u32;
    loop {
        let mut buf = vec![0u8; cap];
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
                // Give the first-read buffer's surplus back when the value
                // is small: `truncate` never shrinks capacity, and callers
                // hold these values (a copied xattr set, a listing) far
                // longer than the read. The shrink's memcpy is skipped when
                // the value fills more than half the buffer, so it is only
                // paid to reclaim at least its own size.
                if buf.capacity() / 2 >= buf.len() {
                    buf.shrink_to_fit();
                }
                return Ok(buf);
            }
            Err(e) if is_short_buffer(e) => {
                tries += 1;
                if tries >= XATTR_SIZE_RETRIES {
                    return Err(Errno::ERANGE);
                }
                let size = retry_on_eintr(|| unsafe {
                    libc::fgetxattr(raw, name.as_ptr(), std::ptr::null_mut(), 0)
                })? as usize;
                if size > XATTR_SIZE_MAX {
                    return Err(Errno::E2BIG);
                }
                cap = xattr_retry_cap(size, tries);
            }
            Err(e) => return Err(e),
        }
    }
}

/// Set the extended attribute `name` to `value` on an open file descriptor.
///
/// `value` longer than [`XATTR_SIZE_MAX`] is rejected with `Err(Errno::E2BIG)`.
pub fn fsetxattr<Fd: AsFd, N: ?Sized + TnPath>(
    fd: Fd,
    name: &N,
    value: &[u8],
    flags: XattrFlags,
) -> errno::Result<()> {
    if value.len() > XATTR_SIZE_MAX {
        return Err(Errno::E2BIG);
    }
    let raw = fd.as_fd().as_raw_fd();
    name.with_tn_path(|name| {
        retry_on_eintr(|| unsafe {
            libc::fsetxattr(
                raw,
                name.as_ptr(),
                value.as_ptr().cast(),
                value.len(),
                flags.bits(),
            )
        })
    })??;
    Ok(())
}

/// Remove the extended attribute `name` from an open file descriptor.
///
/// Returns `Err(Errno::ENODATA)` if the attribute is absent.
pub fn fremovexattr<Fd: AsFd, N: ?Sized + TnPath>(
    fd: Fd,
    name: &N,
) -> errno::Result<()> {
    let raw = fd.as_fd().as_raw_fd();
    name.with_tn_path(|name| {
        retry_on_eintr(|| unsafe { libc::fremovexattr(raw, name.as_ptr()) })
    })??;
    Ok(())
}

/// List the names of the extended attributes on an open file descriptor.
///
/// Names are returned as [`CString`]s carrying the kernel's raw bytes. An xattr
/// name need not be UTF-8 (the `user.` namespace accepts arbitrary bytes), and
/// the value is the NUL-terminated string the fd-xattr syscalls take directly.
pub fn flistxattr<Fd: AsFd>(fd: Fd) -> errno::Result<Vec<CString>> {
    let raw = fd.as_fd().as_raw_fd();
    let mut buf = vec![0u8; 256];
    let len = loop {
        let res = retry_on_eintr(|| unsafe {
            libc::flistxattr(raw, buf.as_mut_ptr().cast(), buf.len())
        });
        match res {
            Ok(n) => break n as usize,
            // `ERANGE` alone, unlike the value reads' [`is_short_buffer`]:
            // `listxattr` (`fs/xattr.c:988-991`) runs the same
            // `ERANGE -> E2BIG` rewrite, but against `XATTR_LIST_MAX`, and
            // that constant really is 64 KiB on both sides
            // (`uapi/linux/limits.h:17`). So the rewrite fires exactly when
            // this loop has already grown to its ceiling and is about to
            // answer `E2BIG` itself - both routes end at the same errno,
            // and there is nothing to widen.
            Err(Errno::ERANGE) => {
                if buf.len() >= XATTR_LIST_MAX {
                    return Err(Errno::E2BIG);
                }
                buf = vec![0u8; XATTR_LIST_MAX];
            }
            Err(e) => return Err(e),
        }
    };
    // The kernel returns the names NUL-separated; each non-empty segment
    // carries no interior NUL, so it is a valid `CString` verbatim.
    Ok(buf[..len]
        .split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .filter_map(|s| CString::new(s).ok())
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The retry loops enter on "the buffer was too small" and on nothing
    /// else, and the kernel spells that two ways - see [`is_short_buffer`].
    ///
    /// The membership matters in both directions. Drop `E2BIG` and a value
    /// past ~43 KiB that grows under the reader hands the caller `E2BIG`,
    /// which this module's own rustdoc defines as "exceeds
    /// [`XATTR_SIZE_MAX`]" - so a 400 KiB attribute reads as oversized and
    /// is dropped. Widen it to every errno and an absent attribute
    /// (`ENODATA`) or an unreadable one (`EACCES`) costs a size probe and
    /// three more reads before failing anyway.
    #[test]
    fn a_short_buffer_is_the_only_retry_signal() {
        for e in [Errno::ERANGE, Errno::E2BIG] {
            assert!(is_short_buffer(e), "{e} must re-probe and retry");
        }
        for e in [
            Errno::ENODATA,
            Errno::EACCES,
            Errno::EPERM,
            Errno::EOPNOTSUPP,
            Errno::EINTR,
            Errno::EIO,
        ] {
            assert!(!is_short_buffer(e), "{e} is not a sizing failure");
        }
    }
}
