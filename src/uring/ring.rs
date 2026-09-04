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

/// Acquire-load one of the ring's shared index words.
///
/// A function, and one spelling of the ordering, so the loom model drives
/// *this* load rather than its own copy of the pairing. A model with its own
/// copy checks the memory model rather than the code: it stays green with
/// the shipping ordering weakened to `Relaxed`, which is the whole point of
/// not having one (`bufring::publish_tail` says the same).
#[inline]
fn load_acquire(cell: &AtomicU32) -> u32 {
    cell.load(Ordering::Acquire)
}

/// Release-store one of the ring's shared index words, publishing whatever
/// the entry it names was filled with. See [`load_acquire`].
#[inline]
fn store_release(cell: &AtomicU32, v: u32) {
    cell.store(v, Ordering::Release)
}

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

    // The four kernel-shared index words. A raw pointer into the mmap in a
    // real ring, an owned atomic in a model - the `cfg` picks the *cell*,
    // and nothing else, so the orderings below have one spelling each.
    #[inline]
    fn sq_khead(&self) -> &AtomicU32 {
        #[cfg(not(loom))]
        // SAFETY: points to the kernel-shared SQ head word, mapped for the
        // ring's life.
        unsafe {
            &*self.sq_khead
        }
        #[cfg(loom)]
        &self.sq_khead
    }

    #[inline]
    fn sq_ktail(&self) -> &AtomicU32 {
        #[cfg(not(loom))]
        // SAFETY: as `sq_khead`, for the SQ tail word.
        unsafe {
            &*self.sq_ktail
        }
        #[cfg(loom)]
        &self.sq_ktail
    }

    #[inline]
    fn cq_khead(&self) -> &AtomicU32 {
        #[cfg(not(loom))]
        // SAFETY: as `sq_khead`, for the CQ head word.
        unsafe {
            &*self.cq_khead
        }
        #[cfg(loom)]
        &self.cq_khead
    }

    #[inline]
    fn cq_ktail(&self) -> &AtomicU32 {
        #[cfg(not(loom))]
        // SAFETY: as `sq_khead`, for the CQ tail word.
        unsafe {
            &*self.cq_ktail
        }
        #[cfg(loom)]
        &self.cq_ktail
    }

    // ---- user side (the real submit/reap discipline) -------------------

    /// Acquire-load the kernel-advanced SQ consumer head.
    #[inline]
    fn sq_head_acquire(&self) -> u32 {
        load_acquire(self.sq_khead())
    }

    /// Release-store the producer SQ tail, publishing the SQEs filled below it.
    #[inline]
    fn publish_sq_tail(&self, tail: u32) {
        store_release(self.sq_ktail(), tail);
    }

    /// Acquire-load the kernel-advanced CQ producer tail.
    #[inline]
    fn cq_tail_acquire(&self) -> u32 {
        load_acquire(self.cq_ktail())
    }

    /// Release-store the consumer CQ head, freeing the slot for kernel reuse.
    #[inline]
    fn publish_cq_head(&self, head: u32) {
        store_release(self.cq_khead(), head);
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

/// Ring memory this process allocated and handed to the kernel: the two
/// anonymous mappings behind [`IORING_SETUP_NO_MMAP`].
///
/// Addresses, not pointers, so [`RingFd`] stays `Send`.
///
/// Owns both mappings until [`Ring::from_setup`] takes them over, so a
/// `RingFd` dropped before it is ever mapped still unmaps them.
struct RingMemory {
    rings: usize,
    rings_len: usize,
    sqes: usize,
    sqes_len: usize,
}

impl Drop for RingMemory {
    fn drop(&mut self) {
        // SAFETY: both came from `mmap_anon`, and this runs only while this
        // value still owns them - `Ring::from_setup` forgets it when it takes
        // them over, so neither region is unmapped twice.
        unsafe {
            libc::munmap(self.sqes as *mut libc::c_void, self.sqes_len);
            libc::munmap(self.rings as *mut libc::c_void, self.rings_len);
        }
    }
}

/// A ring that exists but is not yet mapped: the `io_uring_setup(2)`
/// descriptor plus the layout the kernel reported for it.
///
/// The half of ring construction that may happen on a thread other than the
/// one that will drive the ring. It holds no pointers, so it is `Send` - the
/// caller-allocated ring memory it may carry is held as an address for exactly
/// that reason; the mapped, single-thread half (`Ring`) is built from it on the
/// owning thread.
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
    /// The regions this process allocated and handed to the kernel, when the
    /// `ENOMEM` retry in [`RingFd::setup`] was taken; `None` when the kernel
    /// allocated them and [`Ring::from_setup`] maps them from the fd.
    memory: Option<RingMemory>,
}

impl RingFd {
    /// `io_uring_setup(2)` for `entries` submission slots (rounded up to a
    /// power of two by the kernel). Fails with `ENOSYS`/`EPERM` where io_uring
    /// is unavailable (old kernel, seccomp, `kernel.io_uring_disabled`).
    ///
    /// Always sets [`IORING_SETUP_NO_SQARRAY`]: the flag reached 6.10, this
    /// crate's floor is 6.18, and that floor is assumed rather than probed.
    ///
    /// On `ENOMEM`, retries once with the ring memory allocated here
    /// ([`IORING_SETUP_NO_MMAP`]) before giving up: a fragmented host refuses
    /// a large ring with memory to spare, because the kernel-allocated path
    /// needs one physically contiguous high-order block per region
    /// (`io_region_allocate_pages`, `io_uring/memmap.c`) and the scatter
    /// fallback there does not fire wherever the cgroup-v2 memory controller
    /// is on (`alloc_pages_bulk_node` refuses accounted allocations,
    /// `mm/page_alloc.c:5079`). Pages this process already owns are pinned and
    /// `vmap`'d instead, so the retry keeps the depth asked for.
    ///
    /// No help against `RLIMIT_MEMLOCK`, charged the same either way
    /// (`io_create_region` -> `__io_account_mem`, skipped only under
    /// `CAP_IPC_LOCK` - see [`Ring::reset_staging`]): surviving that ceiling
    /// means asking for a smaller ring.
    pub(crate) fn setup(entries: u32) -> errno::Result<RingFd> {
        match Self::setup_kernel_memory(entries) {
            // The retry reports its own errno. It is not always a memory
            // one: `io_uring_setup` allocates its descriptor after the ring
            // regions, so a process at its `NOFILE` limit answers `EMFILE`;
            // `kernel.io_uring_disabled` is a live sysctl, so a flip between
            // the two attempts answers `EPERM`; and a kernel that rejects
            // `IORING_SETUP_NO_MMAP` answers `EINVAL`. Test helpers treat
            // `ENOMEM` as this environment rather than a defect
            // (`super::setup_unavailable`), so reporting one of those as
            // `ENOMEM` would skip the assertions behind it instead of
            // failing. `region_bytes` is pinned against the kernel's own
            // layout by a test.
            Err(Errno::ENOMEM) => Self::setup_with_own_memory(entries),
            other => other,
        }
    }

    /// `io_uring_setup(2)` with the kernel allocating the ring memory.
    fn setup_kernel_memory(entries: u32) -> errno::Result<RingFd> {
        let mut params = IoUringParams {
            flags: IORING_SETUP_NO_SQARRAY,
            ..IoUringParams::default()
        };
        let fd = io_uring_setup(entries, &mut params)?;
        Ok(RingFd {
            fd,
            params,
            memory: None,
        })
    }

    /// [`RingFd::setup`]'s `ENOMEM` retry: map the two regions here and hand
    /// the kernel their addresses.
    ///
    /// `RingMemory` is built before the syscall so its `Drop` covers the `?`,
    /// including the `EINVAL` a kernel too old for the flag answers with.
    fn setup_with_own_memory(entries: u32) -> errno::Result<RingFd> {
        let (rings_len, sqes_len) = region_bytes(entries);
        let rings = mmap_anon(rings_len)?;
        let sqes = match mmap_anon(sqes_len) {
            Ok(s) => s,
            Err(e) => {
                // SAFETY: `rings` came from `mmap_anon` just above and is
                // unmapped once - nothing else owns it yet.
                unsafe { libc::munmap(rings.cast(), rings_len) };
                return Err(e);
            }
        };
        let memory = RingMemory {
            rings: rings as usize,
            rings_len,
            sqes: sqes as usize,
            sqes_len,
        };

        let mut params = IoUringParams {
            flags: IORING_SETUP_NO_SQARRAY | IORING_SETUP_NO_MMAP,
            ..IoUringParams::default()
        };
        // The kernel sizes each region itself and pins that much from the
        // address given, so these need only be page-aligned - `mmap` - and
        // large enough, which `region_bytes` guarantees.
        params.cq_off.user_addr = rings as u64;
        params.sq_off.user_addr = sqes as u64;
        let fd = io_uring_setup(entries, &mut params)?;
        Ok(RingFd {
            fd,
            params,
            memory: Some(memory),
        })
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

/// The regions a [`Ring`] owns, with the lengths to `munmap` them by.
///
/// Named rather than positional because two fields alias whenever the CQ
/// shares the SQ's mapping - `cq_ring` repeats `sq_ring` and `cq_ring_len` is
/// then 0, which is what keeps `Ring`'s `Drop` from unmapping it twice. A
/// swapped pair in a tuple would be exactly that double `munmap`.
struct RingMaps {
    sq_ring: *mut u8,
    sq_ring_len: usize,
    cq_ring: *mut u8,
    /// 0 when `cq_ring` aliases `sq_ring`, so the region is unmapped once.
    cq_ring_len: usize,
    sqes: *mut IoUringSqe,
    sqes_len: usize,
}

/// Take over the regions [`RingFd::setup`]'s retry mapped.
///
/// `IORING_SETUP_NO_MMAP` puts both rings in the single region the kernel took
/// from `cq_off.user_addr` (`io_allocate_scq_urings`), so the CQ aliases it.
/// Ownership moves to the `Ring`, whose `Drop` unmaps these - `RingMemory`'s
/// must therefore not also run.
fn adopt_own_memory(m: RingMemory) -> RingMaps {
    let maps = RingMaps {
        sq_ring: m.rings as *mut u8,
        sq_ring_len: m.rings_len,
        cq_ring: m.rings as *mut u8,
        cq_ring_len: 0,
        sqes: m.sqes as *mut IoUringSqe,
        sqes_len: m.sqes_len,
    };
    std::mem::forget(m);
    maps
}

/// `mmap` the regions the kernel allocated, from the ring fd.
///
/// The ring region's extent is the CQ's: with `NO_SQARRAY` dropping the index
/// array, `rings_size` ends at the CQE array and `sq_off.array` is left at 0,
/// so nothing may be derived from that field.
fn map_from_fd(p: &IoUringParams, raw: RawFd) -> errno::Result<RingMaps> {
    let ring_len = (p.cq_off.cqes as usize)
        + (p.cq_entries as usize) * size_of::<IoUringCqe>();
    let sqes_len = (p.sq_entries as usize) * size_of::<IoUringSqe>();

    let sq_ring = mmap_region(ring_len, raw, IORING_OFF_SQ_RING)?;
    let (cq_ring, cq_ring_len) = if p.features & IORING_FEAT_SINGLE_MMAP != 0 {
        (sq_ring, 0usize)
    } else {
        match mmap_region(ring_len, raw, IORING_OFF_CQ_RING) {
            Ok(q) => (q, ring_len),
            Err(e) => {
                // SAFETY: unmap the SQ region we just mapped.
                unsafe { libc::munmap(sq_ring.cast(), ring_len) };
                return Err(e);
            }
        }
    };
    // The SQES mapping base is page-aligned, so the IoUringSqe cast is sound
    // despite the alignment-increasing lint.
    #[allow(clippy::cast_ptr_alignment)]
    let sqes = match mmap_region(sqes_len, raw, IORING_OFF_SQES) {
        Ok(s) => s as *mut IoUringSqe,
        Err(e) => {
            // SAFETY: unmap the region(s) mapped above before returning.
            unsafe {
                if cq_ring_len != 0 {
                    libc::munmap(cq_ring.cast(), cq_ring_len);
                }
                libc::munmap(sq_ring.cast(), ring_len);
            }
            return Err(e);
        }
    };
    Ok(RingMaps {
        sq_ring,
        sq_ring_len: ring_len,
        cq_ring,
        cq_ring_len,
        sqes,
        sqes_len,
    })
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
        let RingFd {
            fd,
            params: p,
            memory,
        } = setup;

        debug_assert_eq!(
            memory.is_some(),
            p.flags & IORING_SETUP_NO_MMAP != 0,
            "who owns the ring memory must match the flag it was made with"
        );

        let maps = match memory {
            Some(m) => adopt_own_memory(m),
            None => map_from_fd(&p, fd.as_raw_fd())?,
        };

        let rings = SqCqRings::new(&p, maps.sq_ring, maps.cq_ring, maps.sqes);

        Ok(Ring {
            fd,
            sq_ring: maps.sq_ring,
            sq_ring_len: maps.sq_ring_len,
            cq_ring: maps.cq_ring,
            cq_ring_len: maps.cq_ring_len,
            sqes_map: maps.sqes.cast::<u8>(),
            sqes_len: maps.sqes_len,
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
        // A SHORT submit skips the wait entirely. `io_uring_enter` runs
        // `io_submit_sqes` and then
        // `if (ret != to_submit) { mutex_unlock(..); goto out; }`
        // (`io_uring/io_uring.c:3571-3574`), which jumps past the whole
        // `IORING_ENTER_GETEVENTS` block - so it returns the count submitted
        // having waited for nothing, and having flushed no CQ overflow
        // backlog either. Both reap-to-zero loops built on this treat a
        // return as "at least `min_complete` completions are available" and
        // spin at 100% CPU when it is not. Submit to empty first, then enter
        // once more purely to wait.
        while self.to_submit > 0 {
            match io_uring_enter(
                self.raw_fd(),
                self.to_submit,
                min_complete,
                IORING_ENTER_GETEVENTS,
            ) {
                // Nothing accepted and no error: the SQ is not draining, so
                // spinning here would not help. Leave the rest staged.
                Ok(0) => return Ok(()),
                Ok(n) if n >= self.to_submit => {
                    self.to_submit = 0;
                    return Ok(()); // full submit: the wait above happened
                }
                Ok(n) => self.to_submit -= n,
                // CQ overflow/backpressure: the SQEs stay staged. Returning
                // lets the caller reap (which frees CQ space) and retry on
                // the next tick.
                Err(Errno::EBUSY | Errno::EAGAIN) => return Ok(()),
                Err(e) => return Err(e),
            }
        }
        // Nothing staged (or the loop drained it short of a full submit):
        // enter for the wait alone.
        match io_uring_enter(
            self.raw_fd(),
            0,
            min_complete,
            IORING_ENTER_GETEVENTS,
        ) {
            Ok(_) | Err(Errno::EBUSY | Errno::EAGAIN) => Ok(()),
            Err(e) => Err(e),
        }
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

/// Round up to a whole number of pages.
fn page_align(n: usize) -> usize {
    n.next_multiple_of(crate::uring::page_size())
}

/// Byte sizes of the two regions an `entries`-slot ring needs: the combined
/// SQ/CQ ring region and the SQE array (`rings_size`, `io_uring/io_uring.c`).
///
/// Upper bounds, which is all that is needed - the kernel sizes each region
/// itself and pins only that much from the address given, so over-sizing
/// wastes a page and under-sizing fails the pin with `EFAULT`.
///
/// `sq_entries` is `roundup_pow_of_two(entries)` and `cq_entries` twice that
/// (`io_uring_fill_params`); this crate sets no `CQSIZE`/`SQE128`/`CQE32`, so
/// the entry sizes are the base ones, and `NO_SQARRAY` leaves the region with
/// no index array at all (`rings_size`). `IO_RINGS_HEADER_MAX` covers
/// `offsetof(struct io_rings, cqes)` for a 64- or 128-byte `L1_CACHE_BYTES`.
fn region_bytes(entries: u32) -> (usize, usize) {
    const IO_RINGS_HEADER_MAX: usize = 256;

    // Widened before rounding: `next_power_of_two` cannot overflow a `usize`
    // for any `u32`, so no input can panic here even though the only caller
    // has already had this `entries` accepted by `io_uring_setup`.
    let sq_entries = (entries.max(1) as usize).next_power_of_two();
    let cq_entries = 2 * sq_entries;

    let rings = IO_RINGS_HEADER_MAX + cq_entries * size_of::<IoUringCqe>();
    let sqes = sq_entries * size_of::<IoUringSqe>();
    (page_align(rings), page_align(sqes))
}

/// `mmap` one anonymous region to hand the kernel as ring memory.
///
/// `MAP_SHARED`, matching both the fd mapping this replaces and liburing's
/// equivalent (`io_uring_alloc_huge`, `src/setup.c`). No `MAP_POPULATE`: the
/// kernel faults every page in anyway when it pins them, and pre-faulting
/// would touch megabytes that a memlock refusal - charged identically to both
/// allocation paths - then throws away.
///
/// Deliberately no `MAP_HUGETLB`, though liburing asks for it: that needs a
/// preallocated hugetlb pool and fails without one, which on a fragmented host
/// is precisely when this path is reached. Order-0 pages make the retry work.
///
/// Kept separate from `mmap_region` rather than merged: the two differ in
/// flags, fd, offset and in this one's `madvise` step with its own unwind, so
/// a single helper would take a bool and four parameters to save six lines.
///
/// `MADV_DONTFORK` keeps the region out of forked children.
/// `CredBroker::spawn` (`uring_fs/broker.rs`) forks holding the ring fds and
/// needs only those; the kernel refuses `mmap` of a user-provided region
/// through the fd (`io_region_validate_mmap`), so without this the inherited
/// VMA would be the child's only route to ring memory - and an unasked-for
/// one, already in its address space rather than a syscall away.
fn mmap_anon(len: usize) -> errno::Result<*mut u8> {
    // SAFETY: `addr = null` lets the kernel place it, `len` is non-zero and
    // page-aligned, and an anonymous mapping takes no fd and no offset.
    let p = unsafe {
        libc::mmap(
            ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if p == libc::MAP_FAILED {
        return Err(Errno::last());
    }
    // SAFETY: `p`/`len` are the mapping just made.
    if let Err(e) =
        Errno::result(unsafe { libc::madvise(p, len, libc::MADV_DONTFORK) })
    {
        // SAFETY: same mapping, not yet owned by anything else.
        unsafe { libc::munmap(p, len) };
        return Err(e);
    }
    Ok(p.cast())
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
            Err(e) if crate::uring::setup_unavailable(e) => None,
            Err(e) => panic!("io_uring_setup: {e}"),
        }
    }

    /// The created-not-mapped half holds no pointers and may cross threads.
    /// Still true once it carries caller-allocated ring memory, which is why
    /// [`RingMemory`] holds addresses rather than pointers.
    #[test]
    fn ring_fd_is_send() {
        fn require_send<T: Send + Sync>(_: Option<&T>) {}
        require_send::<RingFd>(None);
    }

    /// The `ENOMEM` retry produces a working ring: the same NOP round trip,
    /// but over memory this process mapped and the kernel pinned. Exercises
    /// the `sq_off`/`cq_off` offsets against a base address the kernel did not
    /// choose, and the hand-off of both mappings from `RingMemory` to `Ring`.
    ///
    /// At 4096 entries, not 8: `region_bytes(8)` is one page either way, so a
    /// sizing error would be absorbed by page rounding and the test would
    /// prove only that the two `user_addr` fields are not swapped.
    ///
    /// Driven directly rather than through the `ENOMEM` that selects it in
    /// production: a test cannot fragment the host's memory on demand.
    #[test]
    fn caller_allocated_ring_round_trips() {
        let setup = match RingFd::setup_with_own_memory(4096) {
            Ok(r) => r,
            Err(e) if crate::uring::setup_unavailable(e) => return,
            Err(e) => panic!("setup_with_own_memory: {e}"),
        };
        assert!(setup.memory.is_some(), "the retry owns its ring memory");

        let mut ring = Ring::from_setup(setup).expect("map");
        ring.push_sqe(|sqe| {
            sqe.opcode = IORING_OP_NOP;
            sqe.user_data = 0xf00d;
        })
        .expect("stage");
        ring.submit_and_wait(1).expect("submit_and_wait");
        let cqe = ring.reap().expect("a completion after waiting for one");
        assert_eq!(cqe.res, 0, "a NOP completes with 0");
        assert_eq!(cqe.user_data, 0xf00d);
    }

    /// Every ring carries `NO_SQARRAY`, and the kernel answers it by leaving
    /// `sq_off.array` unset.
    ///
    /// Both halves matter and neither is self-announcing: a ring built without
    /// the flag still works, just 128 KiB larger at the maximum, and the
    /// zeroed `sq_off.array` is what `region_bytes` and `map_from_fd` are
    /// entitled to assume.
    #[test]
    fn setup_sets_no_sqarray() {
        let Some(setup) = setup_or_skip(8) else {
            return;
        };
        assert_ne!(
            setup.params.flags & IORING_SETUP_NO_SQARRAY,
            0,
            "every ring is created with NO_SQARRAY"
        );
        assert_eq!(
            setup.params.sq_off.array, 0,
            "the kernel leaves sq_off.array unset under NO_SQARRAY"
        );
    }

    /// Whether a mapping starting exactly at `addr` and spanning exactly `len`
    /// is present.
    ///
    /// Exact extent rather than "is anything mapped here": `cargo test` runs
    /// this lib's tests as threads of one process and several of them `mmap`,
    /// so a range freed here can be handed straight to another thread.
    /// Requiring both endpoints to match means a coincidental reuse would have
    /// to reproduce the geometry exactly.
    fn mapping_exists(addr: usize, len: usize) -> bool {
        let want = format!("{addr:x}-{:x} ", addr + len);
        std::fs::read_to_string("/proc/self/maps")
            .expect("/proc/self/maps")
            .lines()
            .any(|line| line.starts_with(&want))
    }

    /// A caller-allocated ring dropped before it is ever mapped releases its
    /// own memory. `RingMemory` owns both regions until `Ring::from_setup`
    /// takes them over, and this is the path where that ownership is load
    /// bearing: a ring created for a thread that then failed to start would
    /// otherwise leak both regions for the life of the process.
    ///
    /// Retried rather than asserted once. `cargo test` runs this lib's tests
    /// as threads of one process and several of them `mmap`, so a range freed
    /// here can be handed straight to another thread and read as still-mapped
    /// when the drop was perfectly correct. A leak is present on *every*
    /// attempt; a collision is present on some, so one clean attempt is proof
    /// and only an unbroken run of dirty ones is a failure.
    #[test]
    fn unmapped_caller_allocated_ring_releases_its_memory() {
        const TRIES: usize = 8;
        for attempt in 1..=TRIES {
            let setup = match RingFd::setup_with_own_memory(8) {
                Ok(r) => r,
                Err(e) if crate::uring::setup_unavailable(e) => return,
                Err(e) => panic!("setup_with_own_memory: {e}"),
            };
            let m = setup.memory.as_ref().expect("the retry owns its memory");
            let (rings, rings_len) = (m.rings, m.rings_len);
            let (sqes, sqes_len) = (m.sqes, m.sqes_len);
            assert!(mapping_exists(rings, rings_len), "mapped before the drop");
            assert!(mapping_exists(sqes, sqes_len), "mapped before the drop");

            drop(setup);

            if !mapping_exists(rings, rings_len)
                && !mapping_exists(sqes, sqes_len)
            {
                return;
            }
            assert!(
                attempt < TRIES,
                "both regions still mapped after {TRIES} drops: a leak, not \
                 a concurrent reuse of the address"
            );
        }
    }

    /// The retry's ring memory does not reach a forked child.
    ///
    /// `CredBroker::spawn` forks holding the ring fds and, by its own
    /// contract, needing only those. The kernel refuses to hand a
    /// user-provided region back through the fd (`io_region_validate_mmap`),
    /// so `MADV_DONTFORK` in `mmap_anon` is the whole of that boundary: drop
    /// it and the child gets ring memory already mapped, without asking.
    #[test]
    fn caller_allocated_ring_memory_is_not_inherited() {
        let setup = match RingFd::setup_with_own_memory(8) {
            Ok(r) => r,
            Err(e) if crate::uring::setup_unavailable(e) => return,
            Err(e) => panic!("setup_with_own_memory: {e}"),
        };
        let m = setup.memory.as_ref().expect("the retry owns its memory");
        let (rings, rings_len) = (m.rings, m.rings_len);
        assert!(mapping_exists(rings, rings_len), "mapped in the parent");

        let mut fds = [0i32; 2];
        // SAFETY: `fds` is a valid 2-element array for `pipe` to fill.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        // SAFETY: the child issues three syscalls and `_exit`s - no
        // allocation and no Rust destructor, so nothing can deadlock on a
        // lock some other thread held at the moment of the fork.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            // `msync` answers `ENOMEM` for a range that is not mapped. The
            // child is single-threaded and has done nothing since the fork,
            // so nothing can have reused the address.
            let mapped = u8::from(
                unsafe {
                    libc::msync(
                        rings as *mut libc::c_void,
                        rings_len,
                        libc::MS_ASYNC,
                    )
                } == 0,
            );
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
        // Status first: a child that faulted never reported, and its silence
        // would otherwise read as the mapping assertion passing.
        assert!(
            libc::WIFEXITED(st) && libc::WEXITSTATUS(st) == 0,
            "the child faulted: status {st}"
        );
        assert_eq!(n, 1, "the child reported nothing");
        assert_eq!(got, 0, "ring memory reached the forked child");
    }

    /// `region_bytes` must never under-size either region. The kernel pins
    /// what its own `rings_size()` asks for, and a mapping shorter than that
    /// fails the pin with a bare `EFAULT` - which `RingFd::setup` reports as
    /// the `ENOMEM` that sent it down this path, so an error here would be
    /// invisible in production. This is the only thing that catches it.
    #[test]
    fn region_bytes_covers_the_kernel_layout() {
        for entries in [1u32, 8, 512, 4096, 32768] {
            // Through the caller-allocated path deliberately. The
            // kernel-allocated one is what fails on a fragmented host, so
            // asking it for 32768 entries here makes this test a second
            // casualty of the very condition the retry exists to survive.
            let setup = match RingFd::setup_with_own_memory(entries) {
                Ok(r) => r,
                Err(e) if crate::uring::setup_unavailable(e) => return,
                Err(e) => panic!("setup_with_own_memory({entries}): {e}"),
            };
            let p = setup.params;
            // Release the fd and its memlock charge before the next size:
            // an io_uring context is freed asynchronously, and these are
            // ~3.2 MiB each at the top of the range.
            drop(setup);

            let (rings_len, sqes_len) = region_bytes(entries);
            let cq_end = (p.cq_off.cqes as usize)
                + (p.cq_entries as usize) * size_of::<IoUringCqe>();
            assert!(
                rings_len >= page_align(cq_end),
                "entries={entries}: ring region {rings_len} < {cq_end}"
            );

            let sqes_end = (p.sq_entries as usize) * size_of::<IoUringSqe>();
            assert!(
                sqes_len >= page_align(sqes_end),
                "entries={entries}: SQE region {sqes_len} < {sqes_end}"
            );
        }
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

    /// `submit_and_wait(n)` must return only once `n` completions are
    /// there to reap - both when it submits and when it only waits.
    ///
    /// A SHORT submit skips the wait entirely: `io_uring_enter` runs
    /// `io_submit_sqes` and then
    /// `if (ret != to_submit) { mutex_unlock(..); goto out; }`
    /// (`io_uring/io_uring.c:3571-3574`), jumping past the whole
    /// `IORING_ENTER_GETEVENTS` block. Both reap-to-zero loops built on this
    /// read a return as "the completions are available" and spin at 100% CPU
    /// when they are not, so the wait has to be entered separately once the
    /// SQ is empty.
    #[test]
    fn submit_and_wait_returns_with_what_it_waited_for() {
        let Some(setup) = setup_or_skip(8) else {
            return;
        };
        let mut ring = Ring::from_setup(setup).expect("map");
        for i in 0..4u64 {
            ring.push_sqe(|sqe| {
                sqe.opcode = IORING_OP_NOP;
                sqe.user_data = 0x100 + i;
            })
            .expect("stage");
        }
        ring.submit_and_wait(4).expect("submit_and_wait");
        let mut got: Vec<u64> = (0..4)
            .map(|k| {
                ring.reap()
                    .unwrap_or_else(|| {
                        panic!("waited for 4, only {k} were available")
                    })
                    .user_data
            })
            .collect();
        got.sort_unstable();
        assert_eq!(got, vec![0x100, 0x101, 0x102, 0x103]);

        // The wait-only path: nothing staged, one op already submitted --
        // and one that takes measurable time, since a NOP is reapable
        // whether or not the enter waited for it.
        let ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 60_000_000,
        };
        // The kernel copies the timespec at prep (`__io_timeout_prep` ->
        // `get_timespec64`), so it need only be valid across `submit`.
        let addr = std::ptr::addr_of!(ts) as u64;
        ring.push_sqe(|sqe| {
            sqe.opcode = IORING_OP_TIMEOUT;
            sqe.addr = addr;
            sqe.len = 1; // exactly one timespec, per the kernel
            sqe.user_data = 0xbeef;
        })
        .expect("stage");
        ring.submit().expect("submit"); // to_submit -> 0
        ring.submit_and_wait(1)
            .expect("wait with nothing to submit");
        assert_eq!(
            ring.reap()
                .expect("the wait-only enter still waited")
                .user_data,
            0xbeef
        );
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
#[cfg(all(test, loom))]
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
        fn k_cq_head_acquire(&self) -> u32 {
            self.cq_khead.load(Ordering::Acquire)
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
        let cq_entries = k.cq_mask + 1;
        while produced < n {
            let sq_tail = k.k_sq_tail_acquire();
            while sq_head != sq_tail && produced < n {
                // Wait for a CQE slot the user has finished with. This is the
                // only reader of `cq_head`, and without it `publish_cq_head`
                // has no counterparty at all: the model would write each CQE
                // index once and never overwrite one, so weakening that
                // Release could not be observed.
                while cq_tail.wrapping_sub(k.k_cq_head_acquire()) >= cq_entries
                {
                    loom::thread::yield_now();
                }
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
    fn loom_sq_cq_ordering_spsc() {
        loom::model(|| {
            // Keep tiny - loom is exhaustive - but **more ops than slots**.
            // Two ops over a *two*-slot ring reuses nothing: `try_reserve`
            // never finds the ring full, so `sq_head_acquire`'s Acquire has
            // no reuse to order `fill_sqe` against, and the kernel never
            // rewrites a CQE index, so `publish_cq_head`'s Release has no
            // reader. Both could be weakened to Relaxed with the model still
            // green. One slot forces a wrap on each side at the same op
            // count, which is what makes them observable - and is cheaper
            // than raising N, which loom explores exponentially.
            const N: u32 = 2;
            let rings = Arc::new(SqCqRings::new_owned(1, 1));

            let k = rings.clone();
            let kernel = loom::thread::spawn(move || mock_kernel(&k, N));

            // User side: publish N SQEs with distinct user_data (1..=N), then
            // reap N, asserting each user_data returns exactly once.
            let mut sq_tail = 0u32;
            let mut cq_head = 0u32;
            let mut sent = 0u32;
            let mut seen = 0u64;
            let mut count = 0u32;
            while count < N {
                // Publish while there is room, then reap. Producing and
                // consuming have to interleave now: with more ops than slots
                // the ring really does fill, and the reservation that finds
                // it full is the one whose slot the kernel is still reading.
                while sent < N {
                    let Some(idx) = rings.try_reserve(sq_tail) else {
                        break;
                    };
                    rings.fill_sqe(idx, |sqe| {
                        sqe.user_data = u64::from(sent) + 1
                    });
                    rings.advance(&mut sq_tail);
                    sent += 1;
                }
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
