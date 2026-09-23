//! `memfd_secret(2)`-backed protected memory for long-lived in-process
//! secrets: the pages are removed from the kernel direct map, kept off swap,
//! and excluded from core dumps (on TrueNAS, from a support bundle).
//! `secretmem_mmap_prepare` stamps the VMA `VM_DONTDUMP` itself
//! (`mm/secretmem.c:207`) - no separate `madvise` - and the pages stay off
//! swap because the inode's mapping is unevictable
//! (`mapping_set_unevictable`, `:303`), not because the VMA is locked:
//! secretmem sets no `VM_LOCKED`. `RLIMIT_MEMLOCK` is charged page by page
//! at first touch, to the `locked_vm` of the user who created the file
//! (`:65-72`, `:275`), with no `CAP_IPC_LOCK` bypass; a fault over the
//! limit is `SIGBUS` (`:136-138`), so construction faults every page in
//! from the kernel side and reports a refusal as `EFAULT` instead. That
//! is stable 853043cb1294 (mainline 97d34aa65c29), shipped from 6.18.52.
//! Earlier 6.18 kernels stamp `VM_LOCKED` too and check the limit at
//! `mmap`.
//!
//! This is memory-access hardening, not at-rest encryption: a usable secret is
//! plaintext in the region while the process runs; what it removes are the
//! offline paths (dump, swap, cross-process kernel read). A value copied on
//! into ordinary memory (a hasher's state) is the caller's to [`scrub`].
//!
//! A forked child gets no mapping: construction marks the VMA `VM_DONTCOPY`,
//! so a region built before a fork stays the parent's alone.
//!
//! [`SecretMem::available`] probes secretmem (default-on, but arm64 also gates
//! on `can_set_direct_map()` and seccomp can block the syscall) so a daemon can
//! fail closed; construction returns [`Errno::ENOSYS`] when it is unavailable.

use std::os::fd::{AsRawFd, OwnedFd, RawFd};

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

/// Whether a failed `memfd_secret` means the kernel cannot do this at all,
/// rather than not right now - the answer a daemon disables secret handling
/// on, for the rest of its life.
///
/// `ENOSYS` is the missing syscall and `EPERM` a seccomp filter denying it;
/// both hold for the whole process. `EMFILE`/`ENFILE`/`ENOMEM` describe the
/// instant the probe ran.
fn unsupported(e: Errno) -> bool {
    matches!(e, Errno::ENOSYS | Errno::EPERM)
}

/// Fault every page of a fresh mapping in from the kernel side, by reading
/// `len` bytes of `/dev/zero` into it. A page the kernel refuses ends the
/// read short or with `EFAULT`; both come back as [`Errno::EFAULT`]. A
/// userspace touch would be `SIGBUS` instead, and `MAP_POPULATE`, `mlock`
/// and `MADV_POPULATE_WRITE` all go through `get_user_pages`, which
/// refuses secretmem outright.
fn prefault(p: *mut libc::c_void, len: usize) -> Result<()> {
    let zero = std::fs::File::open("/dev/zero")
        .map_err(|e| Errno::try_from(e).unwrap_or(Errno::EIO))?;
    let mut done = 0;
    while done < len {
        // SAFETY: `p..p+len` is our own live mapping; nothing else
        // references it yet, and the kernel writes only within it.
        let n =
            unsafe { libc::read(zero.as_raw_fd(), p.add(done), len - done) };
        if n > 0 {
            done += n as usize;
        } else if n < 0 && matches!(Errno::last(), Errno::EINTR) {
            continue;
        } else if n < 0 {
            return Err(Errno::last());
        } else {
            return Err(Errno::EFAULT);
        }
    }
    Ok(())
}

/// The system page size, the granularity secretmem allocates in.
fn page_size() -> usize {
    // SAFETY: `sysconf` with a valid name reads no memory and returns a long.
    let n = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if n > 0 { n as usize } else { 4096 }
}

/// A `memfd_secret`-backed region holding `len` secret bytes.
///
/// Sized up to whole pages so every mapped byte is backed (an unbacked
/// secretmem page faults `SIGBUS`), but the slices expose exactly `len`. Fill
/// it once via [`as_mut_slice`](Self::as_mut_slice), then treat it as
/// read-only; drop unmaps. The memfd is closed once mapped - the
/// mapping keeps the memory alive, leaving no reopenable handle in
/// `/proc/self/fd`. Pack many secrets into one region to spare `RLIMIT_MEMLOCK`.
pub struct SecretMem {
    ptr: *mut u8,
    /// Requested length (`<= mapped`).
    len: usize,
    /// Page-rounded mapped length, for `munmap`.
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
    /// unavailable.
    ///
    /// `RLIMIT_MEMLOCK` is charged here. Each page is charged when it is
    /// first touched (`secretmem_account_folio` in `secretmem_fault`,
    /// `mm/secretmem.c:136`) and a refused page is `SIGBUS` on the
    /// toucher, so every page is touched from the kernel side before this
    /// returns and a refusal is [`Errno::EFAULT`] from this call. The
    /// counter is per user across every secretmem file that user created,
    /// root included, and the limit is this task's. A 6.18 kernel before
    /// .52 checks the limit at `mmap` instead, so there this call returns
    /// `EAGAIN`.
    pub fn with_capacity(len: usize) -> Result<SecretMem> {
        let page = page_size();
        let mapped = len
            .max(1)
            .checked_next_multiple_of(page)
            .ok_or(Errno::EINVAL)?;
        let fd = memfd_secret()?;
        // Size the file to the whole mapping: `secretmem_fault` SIGBUSes a
        // fault at or past `i_size` (`mm/secretmem.c:122`), and a zero-length
        // request is one page here by the `max(1)` above.
        // SAFETY: `fd` is our live memfd; `mapped` fits an `off_t`.
        let t =
            unsafe { libc::ftruncate(fd.as_raw_fd(), mapped as libc::off_t) };
        if t < 0 {
            return Err(Errno::last());
        }
        // SAFETY: null placement, `mapped > 0`, live memfd, offset 0.
        // `MAP_SHARED` is mandatory - secretmem rejects `MAP_PRIVATE`.
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
        // Keep the region out of forked children. secretmem mandates
        // `MAP_SHARED` (`secretmem_mmap_prepare` rejects a private mapping,
        // `mm/secretmem.c:204`), so `VM_DONTCOPY` is the only thing standing
        // between a child and the same folios.
        // SAFETY: our own mapping, exactly `mapped` bytes, still live.
        if unsafe { libc::madvise(p, mapped, libc::MADV_DONTFORK) } < 0 {
            let e = Errno::last();
            // SAFETY: as above; nothing else has the mapping yet.
            unsafe { libc::munmap(p, mapped) };
            return Err(e);
        }
        if let Err(e) = prefault(p, mapped) {
            // SAFETY: as above; nothing else has the mapping yet.
            unsafe { libc::munmap(p, mapped) };
            return Err(e);
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

    /// Whether this kernel supports `memfd_secret(2)`. Call at start-up to
    /// fail closed; `false` means no `CONFIG_SECRETMEM`, it was disabled, the
    /// arch gate is unmet, or seccomp blocks the syscall.
    ///
    /// Support, not headroom: `RLIMIT_MEMLOCK` is charged by
    /// [`with_capacity`](Self::with_capacity), which returns `EFAULT` when
    /// a page is refused, so a `true` here does not promise the next region
    /// fits the limit.
    pub fn available() -> bool {
        match memfd_secret() {
            Ok(_) => true,
            Err(e) => !unsupported(e),
        }
    }

    /// The secret bytes, read-only; length is the requested `len`.
    pub fn as_slice(&self) -> &[u8] {
        // SAFETY: live mapping of `mapped >= len`; borrow tied to `&self`.
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }

    /// The secret bytes, writable - for filling at construction.
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

/// Read the region as a byte slice - lets a generic packed store borrow from a
/// `memfd_secret` arena the same way it borrows from a `Vec`.
impl AsRef<[u8]> for SecretMem {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

/// Write access for filling the region once at construction.
impl AsMut<[u8]> for SecretMem {
    fn as_mut(&mut self) -> &mut [u8] {
        self.as_mut_slice()
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
        // Unmap only: `secretmem_free_folio` zeroes the folio on last free
        // (`folio_zero_segment`, `mm/secretmem.c:229-233`), so the bytes do
        // not outlive the mapping.
        // SAFETY: our live mapping, released exactly once.
        unsafe { libc::munmap(self.ptr.cast(), self.mapped) };
    }
}

/// One secret in its own region.
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

pub use crate::scrub::scrub;

/// The `/proc/self/smaps` entry for the mapping that contains `addr` --
/// how a test proves what backs a mapping. Crate-visible so the
/// `configfile` staging test can hold a region and check the same entry.
#[cfg(test)]
pub(crate) struct Vma {
    /// The pathname field. A secretmem region shows `/secretmem (deleted)`,
    /// the pseudo-file `secretmem_file_create` allocates
    /// (`alloc_file_pseudo(.., "secretmem", ..)`, `mm/secretmem.c:295`); an
    /// anonymous mapping shows nothing and the heap shows `[heap]`.
    pub(crate) name: String,
    /// The `VmFlags:` line, space-separated mnemonics.
    pub(crate) flags: String,
}

#[cfg(test)]
pub(crate) fn vma_of(addr: usize) -> Option<Vma> {
    let smaps = std::fs::read_to_string("/proc/self/smaps").ok()?;
    let mut name: Option<String> = None;
    for line in smaps.lines() {
        if let Some(range) = line.split(' ').next()
            && let Some((lo, hi)) = range.split_once('-')
            && let (Ok(lo), Ok(hi)) =
                (usize::from_str_radix(lo, 16), usize::from_str_radix(hi, 16))
        {
            // Header line: range, perms, offset, dev, inode, then the name.
            name = (addr >= lo && addr < hi).then(|| {
                line.split_whitespace()
                    .skip(5)
                    .collect::<Vec<_>>()
                    .join(" ")
            });
        }
        if let Some(name) = &name
            && let Some(f) = line.strip_prefix("VmFlags:")
        {
            return Some(Vma {
                name: name.clone(),
                flags: f.trim().to_string(),
            });
        }
    }
    None
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
        // Access runs after `with_capacity` closed the fd - also proving the
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

    /// The region is the `/secretmem` pseudo-file and carries the two VMA
    /// flags it is for: `dd` (`VM_DONTDUMP`, out of core dumps) from
    /// `secretmem_mmap_prepare` and `dc` (`VM_DONTCOPY`) from the fork
    /// barrier. Off-swap is not a VMA flag - it is the inode's unevictable
    /// mapping (`mapping_set_unevictable`, `mm/secretmem.c:303`) - so `lo`
    /// is not asked for, and a 6.18 kernel before .52 that still sets it
    /// passes too. An ordinary allocation is the negative control.
    ///
    /// Nothing else here would notice a kernel that kept `memfd_secret`
    /// working and stopped setting them.
    #[test]
    fn the_region_is_secretmem_undumpable_and_not_forked() {
        if !secretmem_or_skip() {
            return;
        }
        let mem = SecretMem::with_capacity(64).expect("secret region");
        let vma = vma_of(mem.as_slice().as_ptr() as usize)
            .expect("no smaps entry for the region");
        assert!(
            vma.name.starts_with("/secretmem"),
            "region is not secretmem-backed: {:?}",
            vma.name
        );
        for want in ["dd", "dc"] {
            assert!(
                vma.flags.split_whitespace().any(|f| f == want),
                "secretmem VMA is missing {want:?}: {:?}",
                vma.flags
            );
        }
        let heap = Box::new([0u8; 64]);
        let plain = vma_of(heap.as_ptr() as usize)
            .expect("no smaps entry for the heap buffer");
        assert!(
            !plain.name.starts_with("/secretmem"),
            "heap buffer reads as secretmem: {:?}",
            plain.name
        );
        assert!(
            !plain
                .flags
                .split_whitespace()
                .any(|f| f == "dd" || f == "dc"),
            "heap buffer carries secretmem's flags: {:?}",
            plain.flags
        );
    }

    /// A forked child reaches neither the mapping nor the parent's bytes,
    /// and its teardown runs without faulting on what it does not have.
    #[test]
    fn a_forked_child_cannot_reach_the_region() {
        if !secretmem_or_skip() {
            return;
        }
        let mut mem = SecretMem::with_capacity(64).expect("secret region");
        mem.as_mut_slice().fill(0xAB);
        let addr = mem.as_slice().as_ptr() as usize;

        // SAFETY: the child only reads /proc, writes a byte to a pipe and
        // `_exit`s - no allocation, no Rust destructor.
        let mut fds = [0i32; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            let mapped = u8::from(vma_of(addr).is_some());
            // SAFETY: the child's own copy, dropped exactly once - the
            // teardown a forked worker runs.
            unsafe { std::ptr::drop_in_place(&mut mem) };
            unsafe {
                libc::close(fds[0]);
                libc::write(fds[1], std::ptr::addr_of!(mapped).cast(), 1);
                libc::_exit(0)
            };
        }
        let mut got = 1u8;
        let mut st = 0;
        let n = unsafe {
            libc::close(fds[1]);
            let n = libc::read(fds[0], std::ptr::addr_of_mut!(got).cast(), 1);
            libc::close(fds[0]);
            libc::waitpid(pid, &mut st, 0);
            n
        };
        // Status first: a child that faulted never reported, and its
        // silence would otherwise read as the mapping assertion failing.
        assert!(
            libc::WIFEXITED(st) && libc::WEXITSTATUS(st) == 0,
            "the child's teardown faulted: status {st}"
        );
        assert_eq!(n, 1, "the child exited without reporting");
        assert_eq!(got, 0, "the child inherited the secret's mapping");
        assert!(
            mem.as_slice().iter().all(|&b| b == 0xAB),
            "the child's teardown reached the parent's secret"
        );
    }

    /// Construction errors when no region can be made, rather than handing
    /// back ordinary memory that would swap and appear in dumps.
    ///
    /// Forced by exhausting a child's descriptor table, a kernel with
    /// secretmem being unable to stop having it. The probe should still
    /// report support: a full fd table is the instant, not the kernel.
    #[test]
    fn construction_fails_closed_when_no_region_can_be_made() {
        if !secretmem_or_skip() {
            return;
        }
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            let lim = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            // SAFETY: a valid rlimit for a limit this process may lower.
            unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &lim) };
            let no_fallback = SecretMem::with_capacity(32).is_err()
                && Secret::new(b"k").is_err();
            // Still "supported": the fd table is full, the kernel is fine.
            let still_supported = SecretMem::available();
            // SAFETY: async-signal-safe exit with the verdict as the status.
            unsafe {
                libc::_exit(i32::from(!(no_fallback && still_supported)))
            };
        }
        let mut st = 0;
        unsafe { libc::waitpid(pid, &mut st, 0) };
        assert!(
            libc::WIFEXITED(st) && libc::WEXITSTATUS(st) == 0,
            "construction did not fail closed under fd exhaustion"
        );
    }

    /// A page the limit refuses is an error from construction, never a
    /// signal on a later write. Forced in a child by lowering
    /// `RLIMIT_MEMLOCK` to one page; a kernel that charges secretmem
    /// refuses the region, one that does not hands it over, and either
    /// way the child must exit rather than die of `SIGBUS` writing to it.
    #[test]
    fn a_refused_page_is_an_error_not_a_signal() {
        if !secretmem_or_skip() {
            return;
        }
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            let page = page_size() as libc::rlim_t;
            let lim = libc::rlimit {
                rlim_cur: page,
                rlim_max: page,
            };
            // SAFETY: a valid rlimit for a limit this process may lower.
            unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &lim) };
            if let Ok(mut mem) = SecretMem::with_capacity(page_size() * 2) {
                mem.as_mut_slice().fill(0x5A);
            }
            // SAFETY: async-signal-safe exit; reaching it is the verdict.
            unsafe { libc::_exit(0) };
        }
        let mut st = 0;
        unsafe { libc::waitpid(pid, &mut st, 0) };
        assert!(
            libc::WIFEXITED(st) && libc::WEXITSTATUS(st) == 0,
            "a refused secret page killed the child instead of erroring"
        );
    }

    #[test]
    fn only_a_permanent_error_means_unsupported() {
        // ENOSYS: no CONFIG_SECRETMEM. EPERM: seccomp denied the syscall.
        assert!(unsupported(Errno::ENOSYS));
        assert!(unsupported(Errno::EPERM));
        // Transient: the kernel supports it, this instant could not do it.
        for e in [Errno::EMFILE, Errno::ENFILE, Errno::ENOMEM] {
            assert!(!unsupported(e), "{e:?} read as unsupported");
        }
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
