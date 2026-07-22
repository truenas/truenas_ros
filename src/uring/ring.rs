//! The `Ring`: mmap'd SQ/CQ/SQE regions plus the lock-free submit/reap logic.
//!
//! This is the memory-ordering core. The SQ and CQ are single-producer/
//! single-consumer queues shared with the kernel; the acquire/release pairing
//! below is liburing's `smp_load_acquire`/`smp_store_release` discipline
//! expressed in the Rust memory model. Nothing outside this file touches the
//! kernel-shared head/tail words.

use super::sys::*;
use crate::errno::{self, Errno};
use std::mem::size_of;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::ptr;
use std::sync::atomic::{AtomicU32, Ordering};

/// A single io_uring instance owned by one thread.
///
/// Holds raw pointers into the mmap'd rings, which makes it automatically
/// `!Send`/`!Sync` — the type system then forbids sharing the ring across
/// threads (see the crate's single-ring-per-thread decision).
pub(crate) struct Ring {
    fd: OwnedFd,

    // mmap regions (for munmap on drop).
    sq_ring: *mut u8,
    sq_ring_len: usize,
    cq_ring: *mut u8,
    cq_ring_len: usize, // 0 when the CQ shares the SQ mapping (SINGLE_MMAP)
    sqes: *mut IoUringSqe,
    sqes_len: usize,

    // Submission queue.
    sq_khead: *const AtomicU32, // kernel-advanced consumer head
    sq_ktail: *const AtomicU32, // we publish the producer tail here
    sq_mask: u32,
    sq_entries: u32,
    sq_tail: u32,   // our private mirror of the producer tail
    to_submit: u32, // SQEs staged since the last enter

    // Completion queue.
    cq_khead: *const AtomicU32, // we publish the consumer head here
    cq_ktail: *const AtomicU32, // kernel-advanced producer tail
    cqes: *mut IoUringCqe,
    cq_mask: u32,
    cq_head: u32, // our private mirror of the consumer head
}

impl Ring {
    /// Create a ring sized for `entries` submission slots (rounded up to a power
    /// of two by the kernel). Fails with `ENOSYS`/`EPERM` where io_uring is
    /// unavailable (old kernel, seccomp, `kernel.io_uring_disabled`).
    pub(crate) fn new(entries: u32) -> errno::Result<Ring> {
        let mut p = IoUringParams::default();
        let fd = io_uring_setup(entries, &mut p)?;
        let raw = fd.as_raw_fd();

        let single = p.features & IORING_FEAT_SINGLE_MMAP != 0;
        let sq_ring_len = (p.sq_off.array as usize)
            + (p.sq_entries as usize) * size_of::<u32>();
        let cq_ring_len = (p.cq_off.cqes as usize)
            + (p.cq_entries as usize) * size_of::<IoUringCqe>();
        let sqes_len = (p.sq_entries as usize) * size_of::<IoUringSqe>();

        // With SINGLE_MMAP the SQ and CQ share one mapping sized to the larger.
        let sq_map_len = if single {
            sq_ring_len.max(cq_ring_len)
        } else {
            sq_ring_len
        };

        let sq_ring = mmap_region(sq_map_len, raw, IORING_OFF_SQ_RING)?;
        let (cq_ring, cq_own_len) = if single {
            (sq_ring, 0usize)
        } else {
            match mmap_region(cq_ring_len, raw, IORING_OFF_CQ_RING) {
                Ok(q) => (q, cq_ring_len),
                Err(e) => {
                    // SAFETY: unmap the SQ region we just mapped.
                    unsafe { libc::munmap(sq_ring.cast(), sq_map_len) };
                    return Err(e);
                }
            }
        };
        // The SQES mapping base is page-aligned, so the IoUringSqe cast is
        // sound despite the alignment-increasing lint.
        #[allow(clippy::cast_ptr_alignment)]
        let sqes = match mmap_region(sqes_len, raw, IORING_OFF_SQES) {
            Ok(s) => s as *mut IoUringSqe,
            Err(e) => {
                // SAFETY: unmap the region(s) mapped above before returning.
                unsafe {
                    if cq_own_len != 0 {
                        libc::munmap(cq_ring.cast(), cq_own_len);
                    }
                    libc::munmap(sq_ring.cast(), sq_map_len);
                }
                return Err(e);
            }
        };

        // SAFETY: all offsets below are kernel-provided byte offsets to
        // naturally-aligned words inside the just-mapped regions.
        let sq_khead =
            unsafe { field_ptr::<AtomicU32>(sq_ring, p.sq_off.head) };
        let sq_ktail =
            unsafe { field_ptr::<AtomicU32>(sq_ring, p.sq_off.tail) };
        let sq_array = unsafe { field_ptr::<u32>(sq_ring, p.sq_off.array) };
        let cq_khead =
            unsafe { field_ptr::<AtomicU32>(cq_ring, p.cq_off.head) };
        let cq_ktail =
            unsafe { field_ptr::<AtomicU32>(cq_ring, p.cq_off.tail) };
        let cqes = unsafe { field_ptr::<IoUringCqe>(cq_ring, p.cq_off.cqes) };

        // The SQ indirection array is a fixed identity map: submission at ring
        // position `t` always uses SQE slot `t & mask`, so we fill it once and
        // never touch it again.
        for i in 0..p.sq_entries {
            // SAFETY: i < sq_entries; sq_array has that many u32 slots.
            unsafe { *sq_array.add(i as usize) = i };
        }

        Ok(Ring {
            fd,
            sq_ring,
            sq_ring_len: sq_map_len,
            cq_ring,
            cq_ring_len: cq_own_len,
            sqes,
            sqes_len,
            sq_khead: sq_khead as *const AtomicU32,
            sq_ktail: sq_ktail as *const AtomicU32,
            // sq/cq_entries are powers of two, so mask = entries - 1.
            sq_mask: p.sq_entries - 1,
            sq_entries: p.sq_entries,
            sq_tail: 0,
            to_submit: 0,
            cq_khead: cq_khead as *const AtomicU32,
            cq_ktail: cq_ktail as *const AtomicU32,
            cqes,
            cq_mask: p.cq_entries - 1,
            cq_head: 0,
        })
    }

    /// The raw ring fd (for `io_uring_register`).
    pub(crate) fn raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    /// Register the sparse file "pool" of `count` slots and confine
    /// auto-allocation to `[0, count)`.
    pub(crate) fn register_pool(&self, count: u32) -> errno::Result<()> {
        register_files_sparse(self.raw_fd(), count)?;
        register_file_alloc_range(self.raw_fd(), 0, count)
    }

    /// Register a sparse table of `pool + fs` slots but confine
    /// auto-allocation to just `[0, pool)` — the connection pool. The upper
    /// `[pool, pool + fs)` range is handed out at **explicit** indices by the
    /// embedded fs reactor, so multishot accept (which auto-allocates at each
    /// completion) can never land there, and a burst of file opens can never
    /// starve accepts. One table, two disjoint index ranges (fs-reactor
    /// design §4).
    #[cfg(all(feature = "net-server", feature = "async-fs"))]
    pub(crate) fn register_pool_with_fs(
        &self,
        pool: u32,
        fs: u32,
    ) -> errno::Result<()> {
        register_files_sparse(self.raw_fd(), pool + fs)?;
        register_file_alloc_range(self.raw_fd(), 0, pool)
    }

    /// Install a connected socket `fd` into the pool at `slot` (client-side; the
    /// server's pool fills via multishot-accept auto-allocation). The kernel
    /// takes its own reference, so `fd` may be closed after this returns.
    #[cfg(any(feature = "net-client", feature = "async-fs"))]
    pub(crate) fn install_file(
        &self,
        slot: u32,
        fd: RawFd,
    ) -> errno::Result<()> {
        register_file_update(self.raw_fd(), slot, fd)
    }

    /// Stage one SQE: obtain a zeroed slot (flushing to the kernel if the SQ is
    /// momentarily full), fill it via `fill`, and publish it.
    pub(crate) fn push_sqe(
        &mut self,
        fill: impl FnOnce(&mut IoUringSqe),
    ) -> errno::Result<()> {
        let sqe = match self.get_sqe() {
            Some(p) => p,
            None => {
                // SQ momentarily full: flush staged SQEs (the kernel consumes
                // them synchronously, freeing the whole ring) and retry once.
                self.submit()?;
                self.get_sqe().ok_or(Errno::EBUSY)?
            }
        };
        // SAFETY: `get_sqe` returned a valid, zeroed slot we solely own until
        // `advance_sqe` publishes it.
        fill(unsafe { &mut *sqe });
        self.advance_sqe();
        Ok(())
    }

    /// Stage two SQEs guaranteed to be contiguous within a single submission: an
    /// `IOSQE_IO_LINK` head and its trailing `IORING_OP_LINK_TIMEOUT`, which the
    /// kernel accepts only when both are seen in the same `io_uring_enter`. Any
    /// already-staged SQEs are flushed *first* if fewer than two slots are free,
    /// so no intervening submit can split the pair.
    pub(crate) fn push_sqe_linked(
        &mut self,
        head: impl FnOnce(&mut IoUringSqe),
        tail: impl FnOnce(&mut IoUringSqe),
    ) -> errno::Result<()> {
        if self.free_sqes() < 2 {
            self.submit()?;
            if self.free_sqes() < 2 {
                return Err(Errno::EBUSY);
            }
        }
        // SAFETY: two slots were just guaranteed free, so both `get_sqe` calls
        // return valid, zeroed slots we solely own until each `advance_sqe`.
        let sqe = self.get_sqe().expect("slot reserved above");
        head(unsafe { &mut *sqe });
        self.advance_sqe();
        let sqe = self.get_sqe().expect("slot reserved above");
        tail(unsafe { &mut *sqe });
        self.advance_sqe();
        Ok(())
    }

    /// Number of unused SQ slots (entries the kernel has not yet consumed).
    fn free_sqes(&self) -> u32 {
        // SAFETY: `sq_khead` points to the kernel-shared SQ head word.
        let head = unsafe { &*self.sq_khead }.load(Ordering::Acquire);
        self.sq_entries - self.sq_tail.wrapping_sub(head)
    }

    /// Pop one completion, or `None` if the CQ is empty.
    pub(crate) fn reap(&mut self) -> Option<IoUringCqe> {
        // SAFETY: `cq_ktail` points to the kernel-shared CQ tail word.
        let tail = unsafe { &*self.cq_ktail }.load(Ordering::Acquire);
        if self.cq_head == tail {
            return None;
        }
        let idx = (self.cq_head & self.cq_mask) as usize;
        // SAFETY: idx < cq_entries; the Acquire load above pairs with the
        // kernel's release of `tail`, so this CQE is fully written.
        let cqe = unsafe { *self.cqes.add(idx) };
        self.cq_head = self.cq_head.wrapping_add(1);
        // SAFETY: publish the new head so the kernel may reuse the slot.
        unsafe { &*self.cq_khead }.store(self.cq_head, Ordering::Release);
        Some(cqe)
    }

    /// Submit all staged SQEs without waiting.
    pub(crate) fn submit(&mut self) -> errno::Result<()> {
        while self.to_submit > 0 {
            match io_uring_enter(self.raw_fd(), self.to_submit, 0, 0) {
                Ok(0) => break,
                Ok(n) => self.to_submit -= n,
                // CQ full / temporarily unavailable: leave the rest staged;
                // the caller reaps to free space and retries.
                Err(Errno::EBUSY | Errno::EAGAIN) => break,
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// Submit all staged SQEs and block until at least `min_complete`
    /// completions are available.
    pub(crate) fn submit_and_wait(
        &mut self,
        min_complete: u32,
    ) -> errno::Result<()> {
        match io_uring_enter(
            self.raw_fd(),
            self.to_submit,
            min_complete,
            IORING_ENTER_GETEVENTS,
        ) {
            Ok(n) => self.to_submit -= n.min(self.to_submit),
            // CQ overflow/backpressure: the SQEs stay staged. Returning lets the
            // caller reap (which frees CQ space) and retry on the next tick.
            Err(Errno::EBUSY | Errno::EAGAIN) => {}
            Err(e) => return Err(e),
        }
        Ok(())
    }

    /// Reserve the next SQE slot, or `None` if the SQ is full.
    fn get_sqe(&mut self) -> Option<*mut IoUringSqe> {
        // SAFETY: `sq_khead` points to the kernel-shared SQ head word.
        let head = unsafe { &*self.sq_khead }.load(Ordering::Acquire);
        if self.sq_tail.wrapping_sub(head) >= self.sq_entries {
            return None;
        }
        let idx = (self.sq_tail & self.sq_mask) as usize;
        // SAFETY: idx < sq_entries; slot is exclusively ours until published.
        let sqe = unsafe { self.sqes.add(idx) };
        // SAFETY: zero any stale contents from a prior use of this slot.
        unsafe { *sqe = IoUringSqe::default() };
        Some(sqe)
    }

    /// Publish the SQE filled at the current tail.
    fn advance_sqe(&mut self) {
        self.sq_tail = self.sq_tail.wrapping_add(1);
        // SAFETY: Release publishes the SQE + identity-array writes before the
        // kernel (which acquire-loads this tail on the next enter) sees them.
        unsafe { &*self.sq_ktail }.store(self.sq_tail, Ordering::Release);
        self.to_submit += 1;
    }
}

impl Drop for Ring {
    fn drop(&mut self) {
        // The owner (Server) drains all in-flight ops before dropping the Ring,
        // so the kernel holds no reference to these mappings here.
        // SAFETY: each pointer/len came from `mmap` in `new`; unmapped once.
        unsafe {
            libc::munmap(self.sqes.cast(), self.sqes_len);
            if self.cq_ring_len != 0 {
                libc::munmap(self.cq_ring.cast(), self.cq_ring_len);
            }
            libc::munmap(self.sq_ring.cast(), self.sq_ring_len);
        }
        // `fd` (OwnedFd) is closed after this body runs.
    }
}

impl std::fmt::Debug for Ring {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ring")
            .field("fd", &self.fd.as_raw_fd())
            .field("sq_entries", &self.sq_entries)
            .field("to_submit", &self.to_submit)
            .finish_non_exhaustive()
    }
}

/// `mmap` one ring region. `PROT_READ|PROT_WRITE`, `MAP_SHARED|MAP_POPULATE`.
fn mmap_region(len: usize, fd: RawFd, offset: i64) -> errno::Result<*mut u8> {
    // SAFETY: anonymous placement (`addr = null`), `len > 0`, `fd` a live ring
    // fd, `offset` a valid IORING_OFF_* magic offset.
    let p = unsafe {
        libc::mmap(
            ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED | libc::MAP_POPULATE,
            fd,
            offset,
        )
    };
    if p == libc::MAP_FAILED {
        return Err(Errno::last());
    }
    Ok(p.cast())
}

/// Pointer to a `T` at kernel-provided byte offset `off` within a ring mapping.
///
/// # Safety
///
/// `off` must be a byte offset to a naturally-`T`-aligned field that lies fully
/// within the mapping at `base`.
#[allow(clippy::cast_ptr_alignment)] // kernel guarantees natural alignment
unsafe fn field_ptr<T>(base: *mut u8, off: u32) -> *mut T {
    // SAFETY: caller guarantees `off` is in-bounds and aligned for `T`.
    unsafe { base.add(off as usize).cast::<T>() }
}
