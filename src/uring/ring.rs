//! The `Ring`: mmap'd SQ/CQ/SQE regions plus the lock-free submit/reap logic.
//!
//! This is the memory-ordering core. The SQ and CQ are single-producer/
//! single-consumer queues shared with the kernel; the acquire/release pairing
//! below is liburing's `smp_load_acquire`/`smp_store_release` discipline
//! expressed in the Rust memory model. Nothing outside this file touches the
//! kernel-shared head/tail words.
//!
//! The four kernel-shared index words and the two entry arrays live behind
//! [`SqCqRings`] - one home for the ordering discipline. In production its
//! atomics are `*const AtomicU32` into the mmap and the accessors inline to the
//! exact loads/stores/derefs the ring used before. Under `--cfg loom` the same
//! accessors run against owned `loom` atomics and `loom::cell::UnsafeCell`
//! arrays, so `loom::model` can explore the user<->kernel interleavings and flag
//! any unsynchronized SQE/CQE access. See the `loom_tests` module at the bottom.

use super::sys::*;
use crate::errno::{self, Errno};
use std::mem::size_of;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::ptr;

// The atomic type is the one swappable thing between production and loom: in
// production it is `std`'s (reached through raw `*const AtomicU32` into the
// mmap); under loom it is `loom`'s (owned by value, carrying model state).
#[cfg(loom)]
use loom::cell::UnsafeCell;
#[cfg(loom)]
use loom::sync::atomic::{AtomicU32, Ordering};
#[cfg(not(loom))]
use std::sync::atomic::{AtomicU32, Ordering};

/// The kernel-shared SQ/CQ state: the four index words plus the SQE/CQE arrays.
///
/// This is the single home of the acquire/release discipline. The user-side
/// accessors ([`try_reserve`](SqCqRings::try_reserve), [`fill_sqe`](SqCqRings::fill_sqe),
/// [`advance`](SqCqRings::advance), [`reap`](SqCqRings::reap)) take the caller's
/// private ring mirrors by value / `&mut` so `SqCqRings` itself needs no interior
/// mutable bookkeeping - which lets a loom test share it behind an `Arc` between
/// the user thread and a mock-kernel thread.
///
/// Production (`cfg(not(loom))`): the four words are `*const AtomicU32` into the
/// mmap and the arrays are `*mut` into the mmap; every accessor inlines to the
/// same operation the ring performed inline before. Under `cfg(loom)`: owned
/// loom atomics and `UnsafeCell`-wrapped boxed arrays, so loom models the
/// user<->kernel data race precisely.
pub(crate) struct SqCqRings {
    #[cfg(not(loom))]
    sq_khead: *const AtomicU32, // kernel-advanced consumer head (we Acquire-load)
    #[cfg(not(loom))]
    sq_ktail: *const AtomicU32, // we Release-store the producer tail
    #[cfg(not(loom))]
    cq_khead: *const AtomicU32, // we Release-store the consumer head
    #[cfg(not(loom))]
    cq_ktail: *const AtomicU32, // kernel-advanced producer tail (we Acquire-load)
    #[cfg(not(loom))]
    sqes: *mut IoUringSqe,
    #[cfg(not(loom))]
    cqes: *mut IoUringCqe,

    #[cfg(loom)]
    sq_khead: AtomicU32,
    #[cfg(loom)]
    sq_ktail: AtomicU32,
    #[cfg(loom)]
    cq_khead: AtomicU32,
    #[cfg(loom)]
    cq_ktail: AtomicU32,
    #[cfg(loom)]
    sqes: Box<[UnsafeCell<IoUringSqe>]>,
    #[cfg(loom)]
    cqes: Box<[UnsafeCell<IoUringCqe>]>,

    sq_mask: u32,
    cq_mask: u32,
    sq_entries: u32,
}

impl SqCqRings {
    /// Build from the mmap'd regions (production). `sqes` is the SQES mapping
    /// base; the four words and the CQE array are at kernel-provided offsets in
    /// the SQ/CQ mappings.
    #[cfg(not(loom))]
    fn new(
        p: &IoUringParams,
        sq_ring: *mut u8,
        cq_ring: *mut u8,
        sqes: *mut IoUringSqe,
    ) -> SqCqRings {
        // SAFETY: every offset below is a kernel-provided byte offset to a
        // naturally-aligned word/array inside the just-mapped regions.
        unsafe {
            SqCqRings {
                sq_khead: field_ptr::<AtomicU32>(sq_ring, p.sq_off.head)
                    as *const AtomicU32,
                sq_ktail: field_ptr::<AtomicU32>(sq_ring, p.sq_off.tail)
                    as *const AtomicU32,
                cq_khead: field_ptr::<AtomicU32>(cq_ring, p.cq_off.head)
                    as *const AtomicU32,
                cq_ktail: field_ptr::<AtomicU32>(cq_ring, p.cq_off.tail)
                    as *const AtomicU32,
                sqes,
                cqes: field_ptr::<IoUringCqe>(cq_ring, p.cq_off.cqes),
                // sq/cq_entries are powers of two, so mask = entries - 1.
                sq_mask: p.sq_entries - 1,
                cq_mask: p.cq_entries - 1,
                sq_entries: p.sq_entries,
            }
        }
    }

    /// Build owned rings for a loom model (no mmap, no kernel). The entry arrays
    /// are `UnsafeCell`s so loom detects any unsynchronized access.
    #[cfg(loom)]
    fn new(
        p: &IoUringParams,
        _sq_ring: *mut u8,
        _cq_ring: *mut u8,
        _sqes: *mut IoUringSqe,
    ) -> SqCqRings {
        SqCqRings::new_owned(p.sq_entries, p.cq_entries)
    }

    /// Owned rings sized to `sq_entries`/`cq_entries` (both powers of two). Only
    /// the loom model constructs these directly.
    #[cfg(loom)]
    fn new_owned(sq_entries: u32, cq_entries: u32) -> SqCqRings {
        let sqes = (0..sq_entries)
            .map(|_| UnsafeCell::new(IoUringSqe::default()))
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let cqes = (0..cq_entries)
            .map(|_| UnsafeCell::new(IoUringCqe::default()))
            .collect::<Vec<_>>()
            .into_boxed_slice();
        SqCqRings {
            sq_khead: AtomicU32::new(0),
            sq_ktail: AtomicU32::new(0),
            cq_khead: AtomicU32::new(0),
            cq_ktail: AtomicU32::new(0),
            sqes,
            cqes,
            sq_mask: sq_entries - 1,
            cq_mask: cq_entries - 1,
            sq_entries,
        }
    }

    // ---- user side (the real submit/reap discipline) -------------------

    /// Acquire-load the kernel-advanced SQ consumer head.
    #[inline]
    fn sq_head_acquire(&self) -> u32 {
        #[cfg(not(loom))]
        // SAFETY: `sq_khead` points to the kernel-shared SQ head word.
        let v = unsafe { &*self.sq_khead }.load(Ordering::Acquire);
        #[cfg(loom)]
        let v = self.sq_khead.load(Ordering::Acquire);
        v
    }

    /// Release-store the producer SQ tail, publishing the SQEs filled below it.
    #[inline]
    fn publish_sq_tail(&self, tail: u32) {
        #[cfg(not(loom))]
        // SAFETY: `sq_ktail` points to the kernel-shared SQ tail word.
        unsafe { &*self.sq_ktail }.store(tail, Ordering::Release);
        #[cfg(loom)]
        self.sq_ktail.store(tail, Ordering::Release);
    }

    /// Acquire-load the kernel-advanced CQ producer tail.
    #[inline]
    fn cq_tail_acquire(&self) -> u32 {
        #[cfg(not(loom))]
        // SAFETY: `cq_ktail` points to the kernel-shared CQ tail word.
        let v = unsafe { &*self.cq_ktail }.load(Ordering::Acquire);
        #[cfg(loom)]
        let v = self.cq_ktail.load(Ordering::Acquire);
        v
    }

    /// Release-store the consumer CQ head, freeing the slot for kernel reuse.
    #[inline]
    fn publish_cq_head(&self, head: u32) {
        #[cfg(not(loom))]
        // SAFETY: `cq_khead` points to the kernel-shared CQ head word.
        unsafe { &*self.cq_khead }.store(head, Ordering::Release);
        #[cfg(loom)]
        self.cq_khead.store(head, Ordering::Release);
    }

    /// Reserve the SQE slot for producer position `sq_tail`, or `None` if the SQ
    /// is full (the kernel has not consumed enough). Acquire-loads the SQ head.
    #[inline]
    fn try_reserve(&self, sq_tail: u32) -> Option<usize> {
        let head = self.sq_head_acquire();
        if sq_tail.wrapping_sub(head) >= self.sq_entries {
            return None;
        }
        Some((sq_tail & self.sq_mask) as usize)
    }

    /// Number of unused SQ slots (entries the kernel has not yet consumed).
    #[inline]
    fn free_sqes(&self, sq_tail: u32) -> u32 {
        let head = self.sq_head_acquire();
        self.sq_entries - sq_tail.wrapping_sub(head)
    }

    /// Zero the SQE at `idx` and fill it via `fill`. The slot is exclusively
    /// ours until [`advance`](SqCqRings::advance) publishes it.
    #[inline]
    fn fill_sqe(&self, idx: usize, fill: impl FnOnce(&mut IoUringSqe)) {
        #[cfg(not(loom))]
        // SAFETY: idx < sq_entries and the slot is unpublished, so we hold it
        // exclusively; zero any stale contents from a prior use, then fill.
        unsafe {
            let sqe = self.sqes.add(idx);
            *sqe = IoUringSqe::default();
            fill(&mut *sqe);
        }
        #[cfg(loom)]
        self.sqes[idx].with_mut(|sqe| {
            // SAFETY: loom tracks that this slot is unpublished, so the access
            // is exclusive.
            unsafe {
                *sqe = IoUringSqe::default();
                fill(&mut *sqe);
            }
        });
    }

    /// Publish the SQE filled at `*sq_tail`: bump the mirror and Release-store it.
    #[inline]
    fn advance(&self, sq_tail: &mut u32) {
        *sq_tail = sq_tail.wrapping_add(1);
        // Release publishes the SQE writes before the kernel (which acquire-loads
        // this tail on the next enter) can observe the new tail.
        self.publish_sq_tail(*sq_tail);
    }

    /// Pop one completion at `*cq_head`, or `None` if the CQ is empty. Advances
    /// and republishes the head so the kernel may reuse the slot.
    #[inline]
    fn reap(&self, cq_head: &mut u32) -> Option<IoUringCqe> {
        let tail = self.cq_tail_acquire();
        if *cq_head == tail {
            return None;
        }
        let idx = (*cq_head & self.cq_mask) as usize;
        // The Acquire load above pairs with the kernel's release of `tail`, so
        // this CQE is fully written.
        #[cfg(not(loom))]
        // SAFETY: idx < cq_entries.
        let cqe = unsafe { *self.cqes.add(idx) };
        #[cfg(loom)]
        let cqe = self.cqes[idx].with(|p| unsafe { *p });
        *cq_head = cq_head.wrapping_add(1);
        self.publish_cq_head(*cq_head);
        Some(cqe)
    }
}

/// A ring that exists but is not yet mapped: the `io_uring_setup(2)`
/// descriptor plus the layout the kernel reported for it.
///
/// The half of ring construction that may happen on a thread other than the
/// one that will drive the ring. It holds no pointers, so it is `Send`; the
/// mapped, single-thread half (`Ring`) is built from it on the owning thread.
/// The split exists for one caller: a process that runs several reactors on
/// several threads but must fork its credential broker before any thread
/// exists, with every ring fd already created for the child to inherit. Sound
/// because these rings are never `IORING_SETUP_SINGLE_ISSUER`, so the kernel
/// does not bind a ring to the task that created it.
///
/// The fd is a credential capability (anyone holding it can register
/// personalities on the ring), so nothing here exposes it beyond what the
/// broker needs.
pub struct RingFd {
    fd: OwnedFd,
    params: IoUringParams,
}

impl RingFd {
    /// `io_uring_setup(2)` for `entries` submission slots (rounded up to a
    /// power of two by the kernel). Fails with `ENOSYS`/`EPERM` where io_uring
    /// is unavailable (old kernel, seccomp, `kernel.io_uring_disabled`).
    pub(crate) fn setup(entries: u32) -> errno::Result<RingFd> {
        let mut params = IoUringParams::default();
        let fd = io_uring_setup(entries, &mut params)?;
        Ok(RingFd { fd, params })
    }

    /// The raw ring fd (for `io_uring_register`).
    pub(crate) fn raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    /// The submission-queue depth the kernel actually allocated.
    pub(crate) fn sq_entries(&self) -> u32 {
        self.params.sq_entries
    }
}

impl std::fmt::Debug for RingFd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RingFd")
            .field("fd", &self.fd.as_raw_fd())
            .field("sq_entries", &self.params.sq_entries)
            .finish()
    }
}

impl Ring {
    /// Create and map a ring sized for `entries` submission slots in one
    /// step, on this thread. Production goes through [`RingFd::setup`] and
    /// [`Ring::from_setup`] so the two halves can run on different threads;
    /// the tests that only need a ring take this shortcut.
    #[cfg(all(test, not(loom)))]
    pub(crate) fn new(entries: u32) -> errno::Result<Ring> {
        Ring::from_setup(RingFd::setup(entries)?)
    }

    /// Map the SQ, CQ and SQE regions of an already-created ring and take
    /// ownership of it. Runs on the thread that will drive the ring; the
    /// descriptor itself may have been created on any thread of the process.
    pub(crate) fn from_setup(setup: RingFd) -> errno::Result<Ring> {
        let RingFd { fd, params: p } = setup;
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

        // The SQ indirection array is a fixed identity map: submission at ring
        // position `t` always uses SQE slot `t & mask`, so we fill it once and
        // never touch it again. (`SqCqRings` therefore never reads the array.)
        // SAFETY: `array` is a kernel-provided offset to `sq_entries` u32 slots.
        let sq_array = unsafe { field_ptr::<u32>(sq_ring, p.sq_off.array) };
        for i in 0..p.sq_entries {
            // SAFETY: i < sq_entries; sq_array has that many u32 slots.
            unsafe { *sq_array.add(i as usize) = i };
        }

        let rings = SqCqRings::new(&p, sq_ring, cq_ring, sqes);

        Ok(Ring {
            fd,
            sq_ring,
            sq_ring_len: sq_map_len,
            cq_ring,
            cq_ring_len: cq_own_len,
            sqes_map: sqes.cast::<u8>(),
            sqes_len,
            rings,
            sq_tail: 0,
            cq_head: 0,
            to_submit: 0,
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

    /// Install a connected socket `fd` into the pool at `slot` (client-side; the
    /// server's pool fills via multishot-accept auto-allocation). The kernel
    /// takes its own reference, so `fd` may be closed after this returns.
    #[cfg(any(feature = "net-client", feature = "uring-fs"))]
    pub(crate) fn install_file(
        &self,
        slot: u32,
        fd: RawFd,
    ) -> errno::Result<()> {
        register_file_update(self.raw_fd(), slot, fd)
    }

    /// Stage one SQE: reserve a slot (flushing to the kernel if the SQ is
    /// momentarily full), fill it via `fill`, and publish it.
    pub(crate) fn push_sqe(
        &mut self,
        fill: impl FnOnce(&mut IoUringSqe),
    ) -> errno::Result<()> {
        let idx = match self.rings.try_reserve(self.sq_tail) {
            Some(idx) => idx,
            None => {
                // SQ momentarily full: flush staged SQEs (the kernel consumes
                // them synchronously, freeing the whole ring) and retry once.
                self.submit()?;
                self.rings.try_reserve(self.sq_tail).ok_or(Errno::EBUSY)?
            }
        };
        self.rings.fill_sqe(idx, fill);
        self.rings.advance(&mut self.sq_tail);
        self.to_submit += 1;
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
        if self.rings.free_sqes(self.sq_tail) < 2 {
            self.submit()?;
            if self.rings.free_sqes(self.sq_tail) < 2 {
                return Err(Errno::EBUSY);
            }
        }
        // Two slots were just guaranteed free, so both reservations succeed.
        let idx = self
            .rings
            .try_reserve(self.sq_tail)
            .expect("slot reserved above");
        self.rings.fill_sqe(idx, head);
        self.rings.advance(&mut self.sq_tail);
        self.to_submit += 1;
        let idx = self
            .rings
            .try_reserve(self.sq_tail)
            .expect("slot reserved above");
        self.rings.fill_sqe(idx, tail);
        self.rings.advance(&mut self.sq_tail);
        self.to_submit += 1;
        Ok(())
    }

    /// Stage `n` SQEs guaranteed contiguous within a single submission and
    /// joined into one `IOSQE_IO_LINK` chain: the kernel runs them strictly in
    /// order, and the first failure short-circuits the rest (each survivor
    /// still posts `-ECANCELED`, so one CQE per SQE holds either way).
    ///
    /// `fill(i, sqe)` fills link `i`; the link flag is OR-ed in *after* the
    /// caller's fill, so per-op flags such as [`IOSQE_FIXED_FILE`] survive. As
    /// with [`push_sqe_linked`](Ring::push_sqe_linked), already-staged SQEs are
    /// flushed *first* when fewer than `n` slots are free, so no intervening
    /// submit can split the chain - a split chain is not a slow chain, it is a
    /// silently unordered one.
    #[cfg(feature = "uring-fs")]
    pub(crate) fn push_sqe_chain(
        &mut self,
        n: usize,
        mut fill: impl FnMut(usize, &mut IoUringSqe),
    ) -> errno::Result<()> {
        debug_assert!(n > 0, "a chain needs at least one link");
        let need = u32::try_from(n).map_err(|_| Errno::EINVAL)?;
        if self.rings.free_sqes(self.sq_tail) < need {
            self.submit()?;
            if self.rings.free_sqes(self.sq_tail) < need {
                return Err(Errno::EBUSY);
            }
        }
        for i in 0..n {
            // `need` slots were just guaranteed free, so every reservation
            // succeeds.
            let idx = self
                .rings
                .try_reserve(self.sq_tail)
                .expect("slots reserved above");
            self.rings.fill_sqe(idx, |sqe| {
                fill(i, sqe);
                if i + 1 < n {
                    sqe.flags |= IOSQE_IO_LINK;
                }
            });
            self.rings.advance(&mut self.sq_tail);
            self.to_submit += 1;
        }
        Ok(())
    }

    /// Pop one completion, or `None` if the CQ is empty.
    pub(crate) fn reap(&mut self) -> Option<IoUringCqe> {
        self.rings.reap(&mut self.cq_head)
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

    /// Read back a staged (not yet submitted) SQE, for tests that assert on the
    /// bytes actually handed to the kernel rather than on the staging call's
    /// return. Same soundness premise as [`reset_staging`](Ring::reset_staging):
    /// with no `io_uring_enter`, the kernel has not read these slots.
    #[cfg(all(test, not(loom), feature = "uring-fs"))]
    pub(crate) fn staged_sqe(&self, i: u32) -> IoUringSqe {
        assert!(i < self.to_submit, "SQE {i} is not staged");
        let idx = (i & self.rings.sq_mask) as usize;
        #[cfg(not(loom))]
        // SAFETY: idx < sq_entries, and the slot is staged-but-unpublished, so
        // no concurrent writer exists and the kernel has not read it.
        unsafe {
            *self.rings.sqes.add(idx)
        }
        #[cfg(loom)]
        self.rings.sqes[idx].with(|sqe| unsafe { *sqe })
    }

    /// Rewind SQE staging to empty, so a test that only *stages* SQEs can reuse
    /// one ring across iterations.
    ///
    /// Prefer this to a ring per iteration: an io_uring context is freed
    /// asynchronously (`io_ring_exit_work`), and since 6.13 its SQ/CQ and SQE
    /// regions are charged to `RLIMIT_MEMLOCK` for any process without
    /// `CAP_IPC_LOCK` (`io_create_region` -> `__io_account_mem`), released only
    /// when that deferred free runs. Creating rings faster than they are
    /// reclaimed therefore hits `ENOMEM` under an unprivileged process's 8 MiB
    /// limit with memory to spare; root, whose accounting is skipped, does not
    /// see it.
    ///
    /// Sound only because nothing was ever submitted: the kernel advances the
    /// SQ head solely inside `io_uring_enter`, so with no enter the head is
    /// still 0 and no staged SQE was ever read. The assert enforces exactly
    /// that - `to_submit` and `sq_tail` both count every staged SQE, and only
    /// [`submit`](Ring::submit) parts them.
    #[cfg(all(test, not(loom), feature = "uring-fs"))]
    pub(crate) fn reset_staging(&mut self) {
        assert_eq!(
            self.to_submit, self.sq_tail,
            "reset_staging after a submit: the kernel has seen these SQEs"
        );
        self.sq_tail = 0;
        self.to_submit = 0;
        self.rings.publish_sq_tail(0);
    }
}

/// A single io_uring instance owned by one thread.
///
/// Holds raw pointers into the mmap'd rings (in the mmap bookkeeping and, in
/// production, inside [`SqCqRings`]), which makes it automatically `!Send`/
/// `!Sync` - the type system then forbids sharing the ring across threads (see
/// the crate's single-ring-per-thread decision).
pub(crate) struct Ring {
    fd: OwnedFd,

    // mmap regions (for munmap on drop).
    sq_ring: *mut u8,
    sq_ring_len: usize,
    cq_ring: *mut u8,
    cq_ring_len: usize, // 0 when the CQ shares the SQ mapping (SINGLE_MMAP)
    sqes_map: *mut u8,  // SQES mapping base (same address SqCqRings reads)
    sqes_len: usize,

    // The kernel-shared SQ/CQ words + entry arrays (the ordering discipline).
    rings: SqCqRings,

    // User-thread-private mirrors.
    sq_tail: u32,   // producer tail
    cq_head: u32,   // consumer head
    to_submit: u32, // SQEs staged since the last enter
}

impl Drop for Ring {
    fn drop(&mut self) {
        // The owner (Server) drains all in-flight ops before dropping the Ring,
        // so the kernel holds no reference to these mappings here.
        // SAFETY: each pointer/len came from `mmap` in `new`; unmapped once.
        unsafe {
            libc::munmap(self.sqes_map.cast(), self.sqes_len);
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
            .field("sq_entries", &self.rings.sq_entries)
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

#[cfg(all(test, not(loom)))]
mod tests {
    use super::*;
    use std::thread;

    /// The UAPI opcode of the no-op SQE: enough to prove a round trip.
    const IORING_OP_NOP: u8 = 0;

    fn setup_or_skip(entries: u32) -> Option<RingFd> {
        match RingFd::setup(entries) {
            Ok(r) => Some(r),
            Err(e @ (Errno::ENOSYS | Errno::EPERM | Errno::EACCES)) => {
                assert!(
                    std::env::var_os("TRUENAS_ROS_REQUIRE_IO_URING").is_none(),
                    "TRUENAS_ROS_REQUIRE_IO_URING set but io_uring \
                     unavailable: {e}"
                );
                None
            }
            Err(e) => panic!("io_uring_setup: {e}"),
        }
    }

    /// The created-not-mapped half holds no pointers and may cross threads.
    #[test]
    fn ring_fd_is_send() {
        fn require_send<T: Send + Sync>(_: Option<&T>) {}
        require_send::<RingFd>(None);
    }

    /// A ring created on one thread is mapped and driven on another, and the
    /// completion comes back there: the property the multi-reactor setup
    /// order rests on (rings created before the broker forks, mapped by the
    /// threads spawned after it). Holds because the rings are never
    /// `SINGLE_ISSUER`.
    #[test]
    fn ring_created_here_is_driven_on_another_thread() {
        let Some(setup) = setup_or_skip(4) else {
            return;
        };
        let worker = thread::spawn(move || -> errno::Result<u64> {
            let mut ring = Ring::from_setup(setup)?;
            ring.push_sqe(|sqe| {
                sqe.opcode = IORING_OP_NOP;
                sqe.user_data = 0x5eed;
            })?;
            ring.submit_and_wait(1)?;
            let cqe = ring.reap().expect("a completion after waiting for one");
            assert_eq!(cqe.res, 0, "a NOP completes with 0");
            Ok(cqe.user_data)
        });
        assert_eq!(worker.join().unwrap().expect("ring io"), 0x5eed);
    }
}

// ---------------------------------------------------------------------------
// loom model of the SQ/CQ ordering discipline
// ---------------------------------------------------------------------------
//
// Run with:  RUSTFLAGS="--cfg loom" cargo test --lib --features uring-fs sq_cq
//
// The test drives the SAME `SqCqRings` accessors the production ring uses
// (`try_reserve`/`fill_sqe`/`advance`/`reap`) on a user thread, against a
// mock-kernel thread that plays liburing's/the kernel's half of the SPSC
// protocol. loom explores every user<->kernel interleaving permitted by the
// C11 memory model; because the entry arrays are `loom` `UnsafeCell`s, any
// SQE/CQE access not ordered by the Acquire/Release pairing is reported as a
// data race (weaken a `Release` to `Relaxed` and the test fails).
#[cfg(loom)]
mod loom_tests {
    use super::*;
    use loom::sync::Arc;

    impl SqCqRings {
        // --- mock-kernel half of the protocol (loom test only) ---
        fn k_sq_tail_acquire(&self) -> u32 {
            self.sq_ktail.load(Ordering::Acquire)
        }
        fn k_publish_sq_head(&self, head: u32) {
            self.sq_khead.store(head, Ordering::Release);
        }
        fn k_sqe_user_data(&self, idx: usize) -> u64 {
            self.sqes[idx].with(|p| unsafe { (*p).user_data })
        }
        fn k_write_cqe(&self, idx: usize, cqe: IoUringCqe) {
            self.cqes[idx].with_mut(|p| unsafe { *p = cqe });
        }
        fn k_publish_cq_tail(&self, tail: u32) {
            self.cq_ktail.store(tail, Ordering::Release);
        }
    }

    // The mock kernel: consume every published SQE, and for each post one CQE
    // echoing its `user_data`. Mirrors the kernel's ordering exactly - Acquire
    // the words it reads (sq_tail), Release the words it publishes (sq_head so
    // the slot is reusable; cq_tail so the CQE is visible).
    fn mock_kernel(k: &SqCqRings, n: u32) {
        let mut sq_head = 0u32; // kernel's private SQ consumer head
        let mut cq_tail = 0u32; // kernel's private CQ producer tail
        let mut produced = 0u32;
        while produced < n {
            let sq_tail = k.k_sq_tail_acquire();
            while sq_head != sq_tail && produced < n {
                let ud = k.k_sqe_user_data((sq_head & k.sq_mask) as usize);
                sq_head = sq_head.wrapping_add(1);
                k.k_publish_sq_head(sq_head); // slot now reusable
                let cidx = (cq_tail & k.cq_mask) as usize;
                k.k_write_cqe(
                    cidx,
                    IoUringCqe {
                        user_data: ud,
                        res: 0,
                        flags: 0,
                    },
                );
                cq_tail = cq_tail.wrapping_add(1);
                k.k_publish_cq_tail(cq_tail); // CQE now visible
                produced += 1;
            }
            loom::thread::yield_now();
        }
    }

    #[test]
    fn sq_cq_ordering_spsc() {
        loom::model(|| {
            // Keep tiny - loom is exhaustive. Two ops over a 2-slot ring
            // exercises publish/consume of distinct SQEs and CQEs.
            const N: u32 = 2;
            let rings = Arc::new(SqCqRings::new_owned(2, 2));

            let k = rings.clone();
            let kernel = loom::thread::spawn(move || mock_kernel(&k, N));

            // User side: publish N SQEs with distinct user_data (1..=N), then
            // reap N, asserting each user_data returns exactly once.
            let mut sq_tail = 0u32;
            let mut cq_head = 0u32;
            for i in 0..N {
                // 2-slot ring, N=2 => never full; reservation always succeeds.
                let idx = rings.try_reserve(sq_tail).expect("slot free");
                rings.fill_sqe(idx, |sqe| sqe.user_data = u64::from(i) + 1);
                rings.advance(&mut sq_tail);
            }

            let mut seen = 0u64;
            let mut count = 0u32;
            while count < N {
                match rings.reap(&mut cq_head) {
                    Some(cqe) => {
                        let bit = 1u64 << (cqe.user_data - 1);
                        assert_eq!(seen & bit, 0, "duplicate completion");
                        seen |= bit;
                        count += 1;
                    }
                    None => loom::thread::yield_now(),
                }
            }

            kernel.join().unwrap();
            assert_eq!(
                seen,
                (1u64 << N) - 1,
                "each SQE completed exactly once"
            );
        });
    }
}
