//! `memfd_secret(2)`-backed protected memory for long-lived in-process
//! secrets: the pages are removed from the kernel direct map, kept off swap,
//! and excluded from core dumps (on TrueNAS, from a support bundle). The
//! mapping is automatically `VM_LOCKED | VM_DONTDUMP` — no separate
//! `mlock`/`madvise` — and counts against `RLIMIT_MEMLOCK`.
//!
//! This is memory-access hardening, not at-rest encryption: a usable secret is
//! plaintext in the region while the process runs; what it removes are the
//! offline paths (dump, swap, cross-process kernel read). A value copied on
//! into ordinary memory (a hasher's state) is the caller's to [`scrub`]. A
//! `fork(2)` after construction shares the pages with the child (`MAP_SHARED`),
//! so build regions after the last fork.
//!
//! [`SecretMem::available`] probes secretmem (default-on, but arm64 also gates
//! on `can_set_direct_map()` and seccomp can block the syscall) so a daemon can
//! fail closed; construction returns [`Errno::ENOSYS`] when it is unavailable.
//! The kernel guarantees are asserted in the QEMU job, not container CI.

use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::sync::atomic::{compiler_fence, Ordering};

use crate::errno::{Errno, Result};

/// A fresh `memfd_secret` fd, or the `errno` (`ENOSYS` = secretmem
/// unavailable). `O_CLOEXEC` is the only flag the syscall accepts, always set.
fn memfd_secret() -> Result<OwnedFd> {
    // SAFETY: one flag word in, a new fd or -1 out; touches no caller memory.
    let ret = unsafe {
        libc::syscall(libc::SYS_memfd_secret, libc::O_CLOEXEC as libc::c_long)
    };
    if ret < 0 {
        return Err(Errno::last());
    }
    // SAFETY: `ret >= 0` is a fresh fd we exclusively own.
    Ok(unsafe { crate::fd::owned_from_raw(ret as RawFd) })
}

/// The system page size, the granularity secretmem allocates in.
fn page_size() -> usize {
    // SAFETY: `sysconf` with a valid name reads no memory and returns a long.
    let n = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if n > 0 {
        n as usize
    } else {
        4096
    }
}

/// A `memfd_secret`-backed region holding `len` secret bytes.
///
/// Sized up to whole pages so every mapped byte is backed (an unbacked
/// secretmem page faults `SIGBUS`), but the slices expose exactly `len`. Fill
/// it once via [`as_mut_slice`](Self::as_mut_slice), then treat it as
/// read-only; drop scrubs and unmaps. The memfd is closed once mapped — the
/// mapping keeps the memory alive, leaving no reopenable handle in
/// `/proc/self/fd`. Pack many secrets into one region to spare `RLIMIT_MEMLOCK`.
pub struct SecretMem {
    ptr: *mut u8,
    /// Requested length (`≤ mapped`).
    len: usize,
    /// Page-rounded mapped length, for `munmap`/scrub.
    mapped: usize,
}

// SAFETY: `SecretMem` uniquely owns its mapping and gates access through
// `&`/`&mut` like `Box<[u8]>`; the raw pointer is the only reason the derive is
// withheld. This lets the credential snapshot sit behind a shared `Arc`.
unsafe impl Send for SecretMem {}
// SAFETY: as `Send`.
unsafe impl Sync for SecretMem {}

impl SecretMem {
    /// A `len`-byte region, zero-filled. [`Errno::ENOSYS`] if secretmem is
    /// unavailable; `EAGAIN`/`ENOMEM` if it would exceed `RLIMIT_MEMLOCK`.
    pub fn with_capacity(len: usize) -> Result<SecretMem> {
        let page = page_size();
        let mapped = len
            .max(1)
            .checked_next_multiple_of(page)
            .ok_or(Errno::EINVAL)?;
        let fd = memfd_secret()?;
        // ftruncate to the page-rounded length, not `len`, or the tail page
        // SIGBUSes on first touch.
        // SAFETY: `fd` is our live memfd; `mapped` fits an `off_t`.
        let t =
            unsafe { libc::ftruncate(fd.as_raw_fd(), mapped as libc::off_t) };
        if t < 0 {
            return Err(Errno::last());
        }
        // SAFETY: null placement, `mapped > 0`, live memfd, offset 0.
        // `MAP_SHARED` is mandatory — secretmem rejects `MAP_PRIVATE`.
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                mapped,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd.as_raw_fd(),
                0,
            )
        };
        if p == libc::MAP_FAILED {
            return Err(Errno::last());
        }
        // The mapping holds its own inode reference, so drop the fd now: no
        // reopenable handle to the secret lingers in `/proc/self/fd`.
        drop(fd);
        Ok(SecretMem {
            ptr: p.cast(),
            len,
            mapped,
        })
    }

    /// Whether `memfd_secret(2)` is usable here. Call at start-up to fail
    /// closed; `false` means no `CONFIG_SECRETMEM`, it was disabled, the arch
    /// gate is unmet, or seccomp blocks it.
    pub fn available() -> bool {
        memfd_secret().is_ok()
    }

    /// The secret bytes, read-only; length is the requested `len`.
    pub fn as_slice(&self) -> &[u8] {
        // SAFETY: live mapping of `mapped ≥ len`; borrow tied to `&self`.
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }

    /// The secret bytes, writable — for filling at construction.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: as `as_slice`; `&mut self` proves exclusive access.
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.len) }
    }

    /// The number of secret bytes.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the region holds zero secret bytes.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// Prints the mapping length only, never the bytes.
impl std::fmt::Debug for SecretMem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretMem")
            .field("len", &self.len)
            .finish_non_exhaustive()
    }
}

impl Drop for SecretMem {
    fn drop(&mut self) {
        // Scrub before unmap: the kernel zeroes secretmem on free, but this
        // makes the secret gone the instant we return.
        // SAFETY: our live mapping right up to the `munmap` that releases it.
        unsafe {
            scrub(self.ptr, self.mapped);
            libc::munmap(self.ptr.cast(), self.mapped);
        }
    }
}

/// One secret in its own region, scrubbed on drop.
///
/// The single-value wrapper over [`SecretMem`] (redacted [`Debug`], no
/// `Clone`), mirroring `truenas_pam::Secret`. One memfd and a locked page each,
/// so pack many secrets into a [`SecretMem`] arena instead.
pub struct Secret(SecretMem);

impl Secret {
    /// Copy `bytes` into a fresh region. [`Errno::ENOSYS`] if secretmem is
    /// unavailable.
    pub fn new(bytes: &[u8]) -> Result<Secret> {
        let mut mem = SecretMem::with_capacity(bytes.len())?;
        mem.as_mut_slice().copy_from_slice(bytes);
        Ok(Secret(mem))
    }

    /// The secret bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }

    /// The number of secret bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the secret is the empty byte string (distinct from absent).
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Prints no content: a `Secret` reaching a log must not carry its bytes.
impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(..)")
    }
}

/// Overwrite `len` bytes at `p` with zeroes so the optimizer cannot elide it.
///
/// A per-byte `write_volatile` plus a compiler fence — the same primitives
/// `zeroize` uses internally, and what `truenas_pam::Secret` uses. A plain
/// store to soon-dead memory is a dead store the compiler will drop; a volatile
/// one it must keep. For burning a transient buffer a secret passed through.
///
/// # Safety
///
/// `p` must be valid for writes of `len` bytes.
pub unsafe fn scrub(p: *mut u8, len: usize) {
    for i in 0..len {
        // SAFETY: `i < len`, within the caller's guaranteed range.
        unsafe { p.add(i).write_volatile(0) };
    }
    compiler_fence(Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Skip a syscall-dependent test when secretmem is unavailable, unless the
    /// QEMU job's `TRUENAS_ROS_REQUIRE_SECRETMEM` demands it run (so a real
    /// kernel enforces coverage while container CI degrades to a skip).
    fn secretmem_or_skip() -> bool {
        if SecretMem::available() {
            return true;
        }
        assert!(
            std::env::var_os("TRUENAS_ROS_REQUIRE_SECRETMEM").is_none(),
            "memfd_secret unavailable but TRUENAS_ROS_REQUIRE_SECRETMEM is set"
        );
        false
    }

    #[test]
    fn scrub_zeroes_the_whole_buffer() {
        let mut buf = *b"secretsecret";
        // SAFETY: a live local array of exactly this length.
        unsafe { scrub(buf.as_mut_ptr(), buf.len()) };
        assert_eq!(buf, [0u8; 12]);
    }

    #[test]
    fn region_round_trips_a_secret() {
        if !secretmem_or_skip() {
            return;
        }
        // Access runs after `with_capacity` closed the fd — also proving the
        // mapping outlives it.
        let mut mem = SecretMem::with_capacity(40).expect("secret region");
        assert_eq!(mem.len(), 40);
        assert!(!mem.is_empty());
        mem.as_mut_slice().copy_from_slice(&[0xA5; 40]);
        assert_eq!(mem.as_slice(), &[0xA5u8; 40][..]);
    }

    #[test]
    fn a_fresh_region_is_zero_filled() {
        if !secretmem_or_skip() {
            return;
        }
        // `with_capacity` documents "zero-filled"; a packed table relies on it.
        let mem = SecretMem::with_capacity(64).expect("secret region");
        assert!(mem.as_slice().iter().all(|&b| b == 0));
    }

    #[test]
    fn region_spans_multiple_pages_without_sigbus() {
        if !secretmem_or_skip() {
            return;
        }
        // Past one page: the whole mapping must be backed, or the far end
        // SIGBUSes.
        let n = page_size() * 2 + 17;
        let mut mem = SecretMem::with_capacity(n).expect("secret region");
        mem.as_mut_slice().fill(0x5A);
        assert_eq!(mem.len(), n);
        assert_eq!(mem.as_slice()[n - 1], 0x5A);
    }

    #[test]
    fn secret_redacts_its_bytes_in_debug() {
        if !secretmem_or_skip() {
            return;
        }
        let s = Secret::new(b"AKsecret/keymaterial").expect("secret");
        assert_eq!(s.as_bytes(), b"AKsecret/keymaterial");
        assert_eq!(format!("{s:?}"), "Secret(..)");
        assert_eq!(format!("{:?}", Some(&s)), "Some(Secret(..))");
    }

    #[test]
    fn empty_secret_is_allowed() {
        if !secretmem_or_skip() {
            return;
        }
        let s = Secret::new(b"").expect("empty secret");
        assert!(s.is_empty());
        assert_eq!(s.as_bytes(), b"");
    }
}
