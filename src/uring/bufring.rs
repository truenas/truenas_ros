//! A registered **provided-buffer ring**: buffers the kernel picks from at completion time, rather than an address each
//! SQE names.
//!
//! # Why an op, not a connection, owns a buffer
//!
//! The alternative this replaces is a buffer per connection, sized for the largest read that connection might do and
//! held for its whole life. That makes memory scale with the number of connections rather than with how much data is
//! actually moving - most of it idle, most of the time.
//!
//! Here a buffer is taken when an op completes and released when its bytes have been consumed. Nothing holds one across
//! messages, so the pool is sized for concurrent transfers instead of for the connection table.
//!
//! # The ring is a conveyor, not an allocator
//!
//! The registered region is an array of **descriptors** - each entry carries its own `addr` and `len` - and the storage
//! behind them is entirely this side's business. So the ring is registered once at its maximum entry count and buffers
//! are allocated and posted into it on demand: growing means posting one more, shrinking means not re-posting one that
//! came back.
//!
//! That is SPDK's model (`uring_sock_group_populate_buf_ring`, `module/sock/uring/uring.c`), and it is worth copying
//! for a reason beyond elasticity: **a buffer is freed only in [`BufRing::release`], which runs exactly when the kernel
//! has handed it back.** The alternative - one slab per registered group, retiring a group to shrink - has to prove no
//! buffer anywhere in the group is still lent before freeing the slab under it, which is a whole-pool invariant
//! guarding a use-after-free. Here the question is per buffer and the answer is local.
//!
//! # When a buffer is allocated, and when it is freed
//!
//! There are exactly two places, and both are named here so the hot path is not a guess:
//!
//! - **[`BufRing::post`] allocates, and only for an id that has no buffer.**
//!   An id keeps its storage across a lend/release cycle, so re-posting a buffer that came back costs nothing - it
//!   rewrites a descriptor. Posting an id that has never been used, or was given up in a shrink, allocates once.
//! - **[`BufRing::release`] frees, and only when the pool is over target.**
//!   That is the shrink, and it is the only free before `Drop`.
//!
//! So the allocation profile is: `initial` buffers at registration, one per buffer each time the target rises past
//! where it has been, one free per buffer as a lowered target drains, and **nothing at all in steady state** - a
//! connection taking a buffer, filling it, and handing it back allocates nothing, which is the whole point of pooling
//! rather than minting per message. `cycling_a_buffer_allocates_nothing` pins it.
//!
//! The allocation is fallible (`try_reserve_exact`): a server under memory pressure should hold fewer buffers, not
//! abort. Failing to grow is not an error path, it is the same outcome as reaching the ceiling.
//!
//! # The contract with the kernel
//!
//! - The ring is an array of [`IoUringBuf`] whose producer `tail` is **overlaid on entry zero's `resv` field**
//!   (`include/uapi/linux/io_uring.h`). They share storage by design; a layout that separates them silently loses every
//!   publish.
//! - The memory must be **page aligned**, and the kernel pins it for the registration's lifetime (`io_uring/memmap.c`
//!   rejects an unaligned `user_addr`). It is mapped rather than allocated for exactly that.
//! - `ring_entries` must be a power of two under 65536 (`io_uring/kbuf.c`).
//! - A completion carries a buffer **iff** `IORING_CQE_F_BUFFER` is set in `cqe.flags`, with the id in the upper 16
//!   bits. That flag is the whole rule for whether [`BufRing::release`] is owed: an op that failed before selecting
//!   one - `-ENOBUFS` especially - took nothing.
//! - A buffer cannot be **reserved**. The kernel picks one when the op completes, not when it is submitted
//!   (`io_ring_buffer_select`, `io_uring/kbuf.c`), so any number of selecting ops can be outstanding against a pool of
//!   any size. Shortage is reported as `-ENOBUFS` on the completion, which is the only place it can be answered.

use crate::errno::{self, Errno};
use crate::uring::page_size;
use crate::uring::sys::*;
use std::os::fd::RawFd;
use std::time::{Duration, Instant};
// The tail cell is `std`'s in production, reached through a raw pointer into the mapping; under loom it is loom's,
// owned by value and carrying the model state - the same split `uring::ring` makes, and for the same reason: the
// ordering below is then one store that both the kernel path and the model go through.
#[cfg(loom)]
use loom::sync::atomic::{AtomicU16, Ordering};
#[cfg(not(loom))]
use std::sync::atomic::{AtomicU16, Ordering};

/// The system page size; the granularity the ring must be aligned to.
/// Publish the producer tail.
///
/// `Release` so the kernel cannot observe a tail that names a descriptor whose fields it has not yet seen: it reads the
/// tail with `smp_load_acquire` and only then the descriptor (`io_ring_buffer_select`, `io_uring/kbuf.c:202-216`).
///
/// A function rather than a store inside [`BufRing::commit`] so that the ordering exists once and the loom model drives
/// *this* store. A model with its own copy of the pairing checks the memory model rather than the code - it passes with
/// this weakened to `Relaxed`, which is the case it is for.
#[inline]
fn publish_tail(cell: &AtomicU16, tail: u16) {
    cell.store(tail, Ordering::Release);
}

/// Where one buffer id stands.
///
/// This is the id's standing with the kernel, not whether storage sits behind it: an `Absent` id may keep the buffer a
/// shrink left it, so the next growth posts it without touching the allocator. What counts as allocated is what the
/// ring holds or has lent; kept storage is neither, and [`BufRing::trim`] is where it goes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Slot {
    /// Not in the ring and not lent, with or without storage behind it.
    Absent,
    /// Posted to the ring; the kernel may pick it at any time.
    Posted,
    /// The kernel picked it and a consumer holds it.
    Lent,
}

/// A registered ring of descriptors, plus the buffers currently behind them.
pub(crate) struct BufRing {
    /// The mapped descriptor ring. Raw because the kernel holds these pages pinned until the group is unregistered.
    ring: *mut IoUringBuf,
    /// Mapped length, for `munmap`.
    mapped: usize,
    /// Storage per id, `None` where the id holds none. Indexed by buffer id, so it is `entries` long for the ring's
    /// whole life. An `Absent` id can hold storage: a shrink stops posting a buffer, it does not free it.
    bufs: Vec<Option<Box<[std::mem::MaybeUninit<u8>]>>>,
    /// What each id is doing, parallel to `bufs`.
    slots: Vec<Slot>,
    entries: u16,
    mask: u16,
    buf_len: usize,
    bgid: u16,
    /// How many buffers to keep allocated. Growth and shrink move this; the buffers follow.
    target: u16,
    /// Ids with no buffer behind them, ready for growth to post. A stack rather than a scan because growth runs on the
    /// `-ENOBUFS` path - the one place already under load - and a per-step scan makes a doubling quadratic in
    /// `entries`.
    absent: Vec<u16>,
    posted: u16,
    lent: u16,
    /// The most lent at once since the last [`take_peak`](Self::take_peak). What the sizing policy observes: a count
    /// read at an instant is zero between two requests on a serial reactor, whatever the load.
    peak: u16,
    /// Producer index. The kernel owns the consumer side and never writes this.
    tail: u16,
    ring_fd: RawFd,
    /// Times a buffer has been handed to the allocator.
    ///
    /// Test-only. The property it exists to observe - that a cycle at target reaches the allocator not at all - cannot
    /// be seen from outside: freeing and re-allocating a same-sized buffer usually returns the same address, so
    /// comparing pointers across a cycle reports success either way. A counter nothing reads in production is a field
    /// that drifts, so it is not there in production.
    #[cfg(test)]
    allocs: u64,
}

impl BufRing {
    /// Register a ring of `entries` descriptors, and post `initial` buffers of `buf_len` bytes into it.
    ///
    /// `entries` is rounded up to a power of two, which the kernel requires, and is the **ceiling**: it can never be
    /// raised, because re-registering a live `bgid` is `-EEXIST` and unregistering one would pull buffers out from
    /// under any op still holding them. Size it for the most concurrent arrivals possible - the connection count - not
    /// for the expected load, since an unbacked descriptor slot costs 16 bytes and nothing else.
    pub(crate) fn new(ring_fd: RawFd, bgid: u16, entries: u16, buf_len: usize, initial: u16) -> errno::Result<BufRing> {
        // `checked_`, because the plain form panics in debug and wraps to zero in release for anything above 32768 - so
        // the `entries == 0` guard below could only ever fire in one of the two profiles, and the build that ships is
        // the one where a wrapped count reaches the kernel. The kernel's own ceiling is 32768 entries
        // (`io_uring/kbuf.c:633-637`); this refuses what it would.
        let entries = match entries.max(1).checked_next_power_of_two() {
            Some(e) => e,
            None => return Err(Errno::EINVAL),
        };
        // A descriptor's `len` is a `u32` (`io_uring_buf`), so a length that does not fit one cannot be published:
        // `buf_len as u32` truncates, and any nonzero multiple of 2^32 truncates to exactly the zero this guard
        // refuses. The kernel clamps a selecting read down to the descriptor it picked (`io_ring_buffer_select`,
        // `io_uring/kbuf.c`), so every read would then complete `res = 0`, which the recv path reads as a peer FIN.
        // Refuse it here, where the caller still learns.
        if buf_len == 0 || buf_len > u32::MAX as usize {
            return Err(Errno::EINVAL);
        }
        let ring_bytes = usize::from(entries) * size_of::<IoUringBuf>();
        let mapped = ring_bytes.next_multiple_of(page_size());
        // SAFETY: an anonymous private mapping of a non-zero length; the kernel chooses the address, which is page
        // aligned by construction
        // - which is what `io_create_region` demands of `user_addr`.
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                mapped,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(Errno::last());
        }
        // `MADV_DONTFORK`, as the SQ/CQ mapping sets on the same grounds (`ring::mmap_anon`): `CredBroker::spawn` forks
        // holding the ring fds, and a `MAP_PRIVATE` region is otherwise copy-on-write into the child - handing it a
        // route to descriptors naming this process's recv buffers that it never asked for and does not use.
        // SAFETY: `ptr`/`mapped` are the mapping just made.
        if let Err(e) = Errno::result(unsafe { libc::madvise(ptr, mapped, libc::MADV_DONTFORK) }) {
            // SAFETY: same mapping, not yet owned by anything else and not yet registered, so the kernel holds no pin
            // on it.
            unsafe { libc::munmap(ptr, mapped) };
            return Err(e);
        }
        let reg = IoUringBufReg {
            ring_addr: ptr as u64,
            ring_entries: u32::from(entries),
            bgid,
            ..IoUringBufReg::default()
        };
        // SAFETY: `reg` outlives the call and describes the mapping above.
        let registered = unsafe { io_uring_register(ring_fd, IORING_REGISTER_PBUF_RING, (&raw const reg).cast(), 1) };
        if let Err(e) = registered {
            // SAFETY: nothing else holds the mapping - registration failed, so the kernel took no pin on it.
            unsafe { libc::munmap(ptr, mapped) };
            return Err(e);
        }
        let mut br = BufRing {
            ring: ptr.cast::<IoUringBuf>(),
            mapped,
            bufs: (0..entries).map(|_| None).collect(),
            absent: (0..entries).rev().collect(),
            slots: vec![Slot::Absent; usize::from(entries)],
            entries,
            mask: entries - 1,
            buf_len,
            bgid,
            target: 0,
            posted: 0,
            lent: 0,
            peak: 0,
            tail: 0,
            ring_fd,
            #[cfg(test)]
            allocs: 0,
        };
        br.set_target(initial.clamp(1, entries));
        Ok(br)
    }

    /// Allocate `bid`'s buffer and write its descriptor at the current tail. Does not publish it - [`BufRing::commit`]
    /// does, so a batch of posts costs one release store.
    ///
    /// Returns false if the allocation failed, which leaves the id `Absent` and is not an error: the pool simply holds
    /// fewer buffers than it wanted, and the caller's fallback covers that.
    fn post(&mut self, bid: u16) -> bool {
        let i = usize::from(bid);
        debug_assert_eq!(self.slots[i], Slot::Absent, "posting a live buffer");
        // THE ALLOCATION SITE. An id that already has storage keeps it, so re-posting a buffer that just came back
        // through `release` costs a descriptor write and nothing else. Only a first use, or a re-use after a shrink
        // gave the storage up, reaches the allocator.
        if self.bufs[i].is_none() {
            // Fallible on purpose: a server under memory pressure should hold fewer buffers, not abort. `-ENOBUFS` then
            // drops the connection back to owning one, which is the same fallback a pool at its ceiling takes.
            // Not zeroed: every reader stops at the bytes the kernel wrote.
            let mut buf = Vec::<std::mem::MaybeUninit<u8>>::new();
            if buf.try_reserve_exact(self.buf_len).is_err() {
                return false;
            }
            // SAFETY: the capacity was just reserved, and `MaybeUninit` elements need no initialization.
            unsafe { buf.set_len(self.buf_len) };
            self.bufs[i] = Some(buf.into_boxed_slice());
            #[cfg(test)]
            {
                self.allocs += 1;
            }
        }
        let addr = self.bufs[i].as_mut().expect("just allocated").as_mut_ptr().cast::<u8>();
        let slot = usize::from(self.tail & self.mask);
        // SAFETY: `slot < entries` and the mapping covers `entries` descriptors, so the writes are in bounds.
        //
        // Field by field, **never `resv`**: on entry zero `resv` is not reserved - it is the ring's published tail,
        // which only `commit` may store. A whole-struct write here zeroes it, and every `entries`-th post lands in slot
        // zero, so the kernel would then see a tail rewound behind its head - which it reads as a nearly full ring,
        // since `tail == head` is its only emptiness test (`io_ring_buffer_select`, `io_uring/kbuf.c:202-216`) - and
        // select unpublished descriptors, taking their stale `addr` verbatim as a recv destination.
        // `a_post_never_touches_the_published_tail` pins this.
        //
        // The ring cannot be overrun: every allocated id is posted at most once at a time, so the number of descriptors
        // the kernel has not yet consumed is `posted`, which never exceeds `entries`.
        unsafe {
            let d = self.ring.add(slot);
            (&raw mut (*d).addr).write(addr as u64);
            // `new` refuses a `buf_len` past `u32::MAX`, so this is lossless; saturating rather than casting means a
            // broken invariant understates a buffer's tail instead of publishing the zero length that reads as a peer
            // FIN.
            (&raw mut (*d).len).write(self.buf_len.min(u32::MAX as usize) as u32);
            (&raw mut (*d).bid).write(bid);
        }
        self.tail = self.tail.wrapping_add(1);
        self.slots[i] = Slot::Posted;
        self.posted += 1;
        true
    }

    /// Make every descriptor written since the last commit visible.
    ///
    /// Production only. Under `cfg(loom)` there is no mapping to publish into, and the cast below must not name loom's
    /// `AtomicU16`: that type is eight bytes where the mapped `resv` field is two, at offset 14 of a 16-byte
    /// descriptor, so the reference would cover memory past the entry. `uring::ring` keeps the same separation by
    /// holding pointers into the mapping only under `cfg(not(loom))`.
    #[cfg(not(loom))]
    fn commit(&self) {
        // SAFETY: entry zero exists (`entries >= 1`) and its `resv` field is where the kernel reads the producer tail
        // from.
        let tail = unsafe { &*(&raw const (*self.ring).resv).cast::<std::sync::atomic::AtomicU16>() };
        publish_tail(tail, self.tail);
    }

    /// Under loom the ring is not mapped, so there is nothing to publish.
    #[cfg(loom)]
    fn commit(&self) {}

    /// Keep `want` buffers allocated, posting or dropping to reach it.
    ///
    /// Growth is immediate. Shrinking is not: a buffer that is lent cannot be dropped, and one that is posted cannot be
    /// retracted - the kernel owns that descriptor until it picks it - so lowering the target only takes effect as
    /// buffers come back through [`release`](Self::release).
    pub(crate) fn set_target(&mut self, want: u16) {
        self.target = want.clamp(1, self.entries);
        let mut posted_any = false;
        while self.allocated() < self.target {
            let Some(bid) = self.absent_id() else { break };
            if !self.post(bid) {
                self.absent.push(bid);
                break; // out of memory: hold what we have
            }
            posted_any = true;
        }
        if posted_any {
            self.commit();
        }
    }

    /// An id with no buffer behind it, taken. The caller posts it or, on an allocation failure, hands it back.
    fn absent_id(&mut self) -> Option<u16> {
        self.absent.pop()
    }

    /// Where `bid`'s storage begins, if it has any.
    ///
    /// The kernel writes here for as long as the buffer is lent, so this is shared with it rather than exclusively
    /// ours. That is safe because a posted id is handed to exactly one op - `release` is owed once per completion
    /// carrying `IORING_CQE_F_BUFFER` - so no two writers ever hold the same range.
    pub(crate) fn addr_of(&mut self, bid: u16) -> Option<*mut u8> {
        // `as_mut_ptr` from a mutable borrow: callers write through this pointer (a recv destination, the drain's
        // in-place copy), and a pointer cast up from `&` is UB to write through under the borrow rules even where
        // today's codegen is indifferent.
        let b = self.bufs.get_mut(usize::from(bid))?.as_mut()?;
        Some(b.as_mut_ptr().cast())
    }

    /// Record that a completion selected `bid`.
    pub(crate) fn lend(&mut self, bid: u16) {
        let Some(slot) = self.slots.get_mut(usize::from(bid)) else {
            return;
        };
        debug_assert_eq!(*slot, Slot::Posted, "kernel picked an unposted id");
        if *slot != Slot::Posted {
            return;
        }
        *slot = Slot::Lent;
        self.posted -= 1;
        self.lent += 1;
        self.peak = self.peak.max(self.lent);
    }

    /// The most lent at once since the previous call, which is what the sizing policy reads instead of the count at an
    /// instant.
    pub(crate) fn take_peak(&mut self) -> u16 {
        std::mem::replace(&mut self.peak, self.lent)
    }

    /// Give up the storage behind every id that is neither posted nor lent. Safe at any time: the kernel can name only
    /// a posted id, and a consumer only a lent one.
    pub(crate) fn trim(&mut self) {
        for (buf, slot) in self.bufs.iter_mut().zip(&self.slots) {
            if *slot == Slot::Absent {
                *buf = None;
            }
        }
    }

    /// Verify the kernel's pick and record the loan in one step: `bid` must name a slot this table holds `Posted`, with
    /// storage behind it, or nothing happens and the answer is `None`.
    ///
    /// `None` is a userspace/kernel descriptor desync - an id this table never posted, or one it already lent - and it
    /// is a *refusal*, not an assertion: the case is reachable without a bug on this side, so it must not abort the
    /// reactor, and it must not fall through to serving storage this table cannot vouch for - an absent slot has none,
    /// and a lent one belongs to another op. There is also nothing to hand back on this path: the storage the
    /// completion names is not this table's, so the caller's only sound move is to fail the read the completion
    /// answered.
    pub(crate) fn take_lent(&mut self, bid: u16) -> Option<*mut u8> {
        if self.slots.get(usize::from(bid)) != Some(&Slot::Posted) {
            return None;
        }
        let ptr = self.addr_of(bid)?;
        self.lend(bid);
        Some(ptr)
    }

    /// Hand `bid` back: re-post it, or keep it out of the ring if the pool has shrunk past what it needs.
    ///
    /// Owed exactly when a completion carried `IORING_CQE_F_BUFFER`; an op that never selected one - `-ENOBUFS` above
    /// all - must not call this, or the same id is posted twice and two ops write the same bytes.
    ///
    /// **Nothing is freed here.** A surplus buffer keeps its storage and stops being posted, so the next growth reaches
    /// for it before the allocator; [`trim`](Self::trim) is where storage goes, and the policy calls that only once the
    /// pool has stayed quiet.
    pub(crate) fn release(&mut self, bid: u16) {
        let i = usize::from(bid);
        let Some(slot) = self.slots.get_mut(i) else {
            debug_assert!(false, "buffer id outside the ring");
            return;
        };
        debug_assert_eq!(*slot, Slot::Lent, "releasing a buffer nobody took");
        if *slot != Slot::Lent {
            return;
        }
        *slot = Slot::Absent;
        self.lent -= 1;
        if self.allocated() >= self.target {
            // The target fell while this buffer was out, so it is surplus: it leaves the ring and keeps its storage.
            // Pushed last so a growth takes it before an id that would need allocating.
            self.absent.push(bid);
            return;
        }
        // At or under target: straight back into the ring, reusing the same storage - no allocator traffic on the
        // steady-state path.
        if self.post(bid) {
            self.commit();
        }
    }

    /// Buffers allocated, whether posted or lent.
    pub(crate) fn allocated(&self) -> u16 {
        self.posted + self.lent
    }

    /// Buffers posted and not yet picked.
    pub(crate) fn free(&self) -> u16 {
        self.posted
    }

    /// Buffers currently out with a consumer.
    pub(crate) fn lent(&self) -> u16 {
        self.lent
    }

    /// How many buffers the ring is trying to keep.
    pub(crate) fn target(&self) -> u16 {
        self.target
    }

    /// The most buffers this ring can ever hold.
    pub(crate) fn entries(&self) -> u16 {
        self.entries
    }

    /// The group id to stamp into `sqe.buf_group`.
    pub(crate) fn bgid(&self) -> u16 {
        self.bgid
    }

    /// The most one buffer can hold, which bounds what a read may ask for.
    pub(crate) fn buf_len(&self) -> usize {
        self.buf_len
    }
}

impl Drop for BufRing {
    fn drop(&mut self) {
        let reg = IoUringBufReg {
            bgid: self.bgid,
            ..IoUringBufReg::default()
        };
        // SAFETY: unregistering a group this ring owns; the kernel drops its pin on the mapping - and its reference to
        // every posted buffer -- before returning, which is what makes freeing them safe.
        let _ = unsafe { io_uring_register(self.ring_fd, IORING_UNREGISTER_PBUF_RING, (&raw const reg).cast(), 1) };
        // SAFETY: the mapping came from `mmap` with this length and nothing else holds it - the kernel's pin was
        // dropped above.
        unsafe {
            libc::munmap(self.ring.cast(), self.mapped);
        }
    }
}

impl std::fmt::Debug for BufRing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BufRing")
            .field("bgid", &self.bgid)
            .field("entries", &self.entries)
            .field("buf_len", &self.buf_len)
            .field("target", &self.target)
            .field("posted", &self.posted)
            .field("lent", &self.lent)
            .finish()
    }
}

/// The kernel's cap on a ring's entry count: a power of two below 65536 (`io_uring/kbuf.c:633-637`), so 32768 is the
/// largest registrable.
pub(crate) const MAX_RING_ENTRIES: u16 = 32768;

/// Descriptor slots for a ring that must cover `demand` concurrent buffers.
///
/// A ring is registered once and never resized - re-registering a live `bgid` is `-EEXIST` - so it is sized to the
/// *physical* bound, the most buffers real demand could ever hold at once, not to expected load. A descriptor slot is
/// 16 bytes, so that headroom is not a memory commitment; backing buffers are what cost, and they are allocated only as
/// demand asks. An artificial ceiling below the bound turns a burst into the malloc fallback this ring exists to
/// remove.
///
/// `BufRing::new` rounds the result up to the power of two the kernel requires, which only ever adds slots.
pub(crate) fn ring_entries(demand: u32) -> u16 {
    demand.clamp(1, u32::from(MAX_RING_ENTRIES)) as u16
}

/// Group id of the recv pool: buffers a request arrives into.
pub(crate) const BGID_RECV: u16 = 0;

/// Group id of the file-body pool: buffers a response body is read into.
///
/// A separate group because a group's buffers are interchangeable and selection is FIFO - there is no way to ask one
/// group for a particular size - and a request buffer and a file chunk are sized for different things
/// (`max_request_bytes` against `fs_body_chunk`).
#[cfg(feature = "uring-fs")]
pub(crate) const BGID_FILE_BODY: u16 = 1;

/// The fewest buffers a pool starts with, whatever its budget buys (`ServerConfig::buf_pool_initial_bytes`).
const POOL_INITIAL: u16 = 8;

/// A pool's byte budgets (`ServerConfig::buf_pool_*`).
#[derive(Clone, Copy, Debug)]
pub(crate) struct PoolSizing {
    /// Storage it starts with.
    pub(crate) initial_bytes: usize,
    /// The most storage one growth step adds.
    pub(crate) max_step_bytes: usize,
    /// The most storage it may hold; `None` leaves the demand bound.
    pub(crate) max_bytes: Option<usize>,
}

impl PoolSizing {
    /// Eight buffers to start, doubling to the demand.
    #[cfg(test)]
    pub(crate) const UNSIZED: PoolSizing = PoolSizing {
        initial_bytes: 0,
        max_step_bytes: usize::MAX,
        max_bytes: None,
    };
}

/// Consecutive idle rounds before the pool gives a buffer up. Growth is immediate and shrinking is not, because a pool
/// that shrinks on the first quiet moment spends its life allocating and freeing across a workload that merely pauses -
/// the same hysteresis hyper applies to its read sizes (`src/proto/h1/io.rs`), for the same reason.
const SHRINK_AFTER: u8 = 4;

/// The least time between two idle rounds. Observations arrive at every arm site, and one batch of completions re-arms
/// several connections within microseconds, so rounds counted per call would let a single
/// batch shrink a pool that is fully busy. A round is a second at least;
/// on a silent pool the maintenance tick, five seconds apart, is what paces them.
const IDLE_ROUND: Duration = Duration::from_secs(1);

/// Sizing policy over one [`BufRing`].
///
/// **A shortage is `-ENOBUFS`, never a free count.** A free count is observed at completion, so it cannot see the
/// selecting ops already armed against the pool - a submit gated on it looks correct, passes a single-connection test,
/// and sheds concurrent connections. The kernel is the only party that knows the pool ran dry, and it says so on the
/// completion. The free count only ever *adds* buffers ([`grow_ahead`](Self::grow_ahead)), which is safe for the reason
/// gating on it is not: an extra buffer refuses nothing.
pub(crate) struct BufPool {
    ring: BufRing,
    /// The most buffers the pool holds: its demand, or fewer under `max_bytes`.
    limit: u16,
    /// The most buffers one growth step adds.
    max_step: u16,
    /// Consecutive idle rounds, each at least [`IDLE_ROUND`] after the observation before it.
    idle_rounds: u8,
    /// When the last observation that counted was made: a loan seen, or an idle round taken.
    marked: Instant,
}

impl BufPool {
    /// Register a pool of `buf_len`-byte buffers under group id `bgid`, holding at most `entries` of them (fewer under
    /// `sizing.max_bytes`) and starting with `sizing.initial_bytes` of them - never fewer than [`POOL_INITIAL`] unless
    /// the limit is.
    ///
    /// One group per pool: a group is a set of interchangeable buffers, and selection is FIFO from the head, so a
    /// caller cannot ask a group for a particular size. Two pools that want different sizes - a recv pool sized for a
    /// request, a body pool sized for a file chunk - are two groups, and the group id is how an op says which one it
    /// wants.
    pub(crate) fn new(
        ring_fd: RawFd,
        bgid: u16,
        buf_len: usize,
        entries: u16,
        sizing: PoolSizing,
    ) -> errno::Result<BufPool> {
        let buffers = |bytes: usize| u16::try_from(bytes / buf_len.max(1)).unwrap_or(u16::MAX);
        let limit = sizing.max_bytes.map_or(entries, |b| buffers(b).min(entries)).max(1);
        let initial = buffers(sizing.initial_bytes).max(POOL_INITIAL).min(limit);
        Ok(BufPool {
            ring: BufRing::new(ring_fd, bgid, limit, buf_len, initial)?,
            limit,
            max_step: buffers(sizing.max_step_bytes).max(1),
            idle_rounds: 0,
            marked: Instant::now(),
        })
    }

    /// The group to stamp into an op's `sqe.buf_group`.
    ///
    /// There is nothing to choose and nothing to check: a full pool is answered by the kernel with `-ENOBUFS`, not by
    /// refusing to arm the op, because a provided buffer cannot be reserved at submit time.
    pub(crate) fn bgid(&self) -> u16 {
        self.ring.bgid()
    }

    /// The most one buffer from this pool can hold.
    ///
    /// The ceiling on an **exact** selecting read: the kernel clamps a selecting read down to the buffer it picks
    /// (`io_ring_buffer_select`, `io_uring/kbuf.c`), so a read that asks for more than this and insists on all of it
    /// completes short of what it asked for. A caller in that position must take an owned buffer instead of a pool one.
    pub(crate) fn buf_len(&self) -> usize {
        self.ring.buf_len()
    }

    /// Verify a completion's pick and record the loan ([`BufRing::take_lent`]): the buffer's storage and its length, or
    /// `None` for an id this pool does not hold `Posted` - a descriptor desync the caller answers by failing the read,
    /// since nothing of the pool's is behind the id.
    pub(crate) fn take_lent(&mut self, bid: u16) -> Option<(*mut u8, usize)> {
        let ptr = self.ring.take_lent(bid)?;
        self.grow_ahead();
        Some((ptr, self.ring.buf_len()))
    }

    /// A loan without [`take_lent`](Self::take_lent)'s growth, as a burst the kernel outruns leaves the pool: a test's
    /// way to a ring dry below its limit.
    #[cfg(all(test, not(loom)))]
    pub(crate) fn lend_as_the_kernel(&mut self, bid: u16) -> bool {
        self.ring.take_lent(bid).is_some()
    }

    /// Grow a step once a loan leaves a quarter or less free, ahead of `-ENOBUFS`. Shrinking needs rounds with no loan,
    /// so the two cannot chase each other.
    fn grow_ahead(&mut self) {
        let allocated = self.ring.allocated();
        let base = self.ring.target().max(allocated);
        if u32::from(self.ring.free()) * 4 > u32::from(allocated) || base >= self.limit {
            return;
        }
        self.idle_rounds = 0;
        self.ring.set_target(self.stepped(base));
    }

    /// `base` doubled, but by at most `max_step` buffers and never past the limit.
    fn stepped(&self, base: u16) -> u16 {
        base.saturating_add(base.max(1).min(self.max_step)).min(self.limit)
    }

    /// Hand a buffer back.
    pub(crate) fn release(&mut self, bid: u16) {
        self.ring.release(bid);
    }

    /// Buffers posted and not yet picked.
    pub(crate) fn free(&self) -> u16 {
        self.ring.free()
    }

    /// Buffers out with a consumer.
    pub(crate) fn lent(&self) -> u16 {
        self.ring.lent()
    }

    /// Buffers allocated, posted or lent.
    pub(crate) fn allocated(&self) -> u16 {
        self.ring.allocated()
    }

    /// Answer a completion that found the pool dry, by wanting more.
    ///
    /// A step ([`stepped`](Self::stepped)) rather than one buffer: the shortage says the pool is under its working set,
    /// and a workload that opened many connections at once would otherwise need one `-ENOBUFS` round trip per buffer to
    /// get there. Returns whether the re-armed read can find a buffer - one this call added, or one already free.
    ///
    /// The free check comes first, and it is what keeps one burst from growing the pool once per *completion* rather
    /// than once. A burst queues several `-ENOBUFS` completions into one CQE batch, and every one of them lands here;
    /// the first doubling answers them all, so the rest arrive to find free buffers and a stale shortage. Doubling per
    /// completion instead is 2^N for one batch - measured at the default config: sixteen concurrent readers ran the
    /// pool from 8 buffers to its 4096-entry ceiling, a gigabyte of resident buffers for a burst that needed four
    /// megabytes, with `free == allocated` at every doubling. The same check answers the ceiling honestly: a pool that
    /// cannot grow but holds free buffers is not exhausted, and reporting failure there would demote the connection to
    /// owned buffers for the rest of its life (`set_recv_owned` is one-way) over a shortage that no longer exists.
    ///
    /// The doubling is measured from whichever of target and allocated is larger. A real shortage means every allocated
    /// buffer is lent, and an idle stretch may have lowered the target below that count while they were out; doubling
    /// the *target* would then land at or under what is already allocated and add nothing.
    pub(crate) fn grow(&mut self, armed: u32) -> bool {
        self.idle_rounds = 0;
        // `free` records a pick only at its completion. A selecting read punted to io-wq holds its buffer for the whole
        // wait before that, so `armed` (such reads in flight) is subtracted first: a free count no larger than it is a
        // shortage the kernel can see and this side cannot.
        if u32::from(self.ring.free()) > armed {
            return true;
        }
        let allocated = self.ring.allocated();
        let base = self.ring.target().max(allocated);
        if base >= self.limit {
            return false;
        }
        self.ring.set_target(self.stepped(base));
        self.ring.allocated() > allocated
    }

    /// Lower what the pool is trying to hold, once it has been idle for long enough. Halving, to match the growth.
    ///
    /// **This lowers the target; the buffers follow as they cycle.** A posted descriptor cannot be retracted - the
    /// kernel owns that entry until it picks it - so surplus leaves the ring in [`release`](BufRing::release), as each
    /// buffer comes back, and keeps its storage there. The storage goes at the *next* shrink, through
    /// [`trim`](BufRing::trim): a pool that was quiet long enough to shrink twice has shown the surplus is not coming
    /// back, and a pool that shrank once and then grew again posts what it kept without reaching the allocator.
    ///
    /// That residue is bounded by the ring's ceiling and is no worse than what it replaces: a per-connection buffer
    /// that grew once stayed grown for the connection's life, and there were `pool_size` of them.
    ///
    /// **The observation is the peak since the last one, never the count at an instant, and idle rounds are paced by
    /// time, never by call.** The arm sites call this between two requests, when the arming connection holds no claim
    /// by definition, and on a serial reactor nothing else does either - so an instantaneous count reads zero there
    /// under any load. The peak since the previous call reads the arming connection's own loan at most arm sites; the
    /// exception is a batch of completions that re-arms several connections back to back, where no loan falls between
    /// two calls, and that is why a quiet call counts as a round only once [`IDLE_ROUND`] has passed since the last
    /// observation that counted. A pool therefore shrinks only after `SHRINK_AFTER` rounds with no loan at all, which
    /// on a silent pool the maintenance tick paces, and it holds its working set for as long as it is working.
    pub(crate) fn rebalance(&mut self) {
        self.rebalance_at(Instant::now());
    }

    /// [`rebalance`](Self::rebalance) with the clock passed in, which is what lets a test walk through idle rounds
    /// without waiting them out.
    pub(crate) fn rebalance_at(&mut self, now: Instant) {
        if self.ring.take_peak() > 0 {
            self.idle_rounds = 0;
            self.marked = now;
            return;
        }
        if now.saturating_duration_since(self.marked) < IDLE_ROUND {
            return;
        }
        self.marked = now;
        self.idle_rounds = self.idle_rounds.saturating_add(1);
        if self.idle_rounds < SHRINK_AFTER {
            return;
        }
        self.idle_rounds = 0;
        self.ring.trim();
        let want = (self.ring.target() / 2).max(1);
        if want < self.ring.target() {
            self.ring.set_target(want);
        }
    }

    /// What the pool is trying to hold. [`allocated`](Self::allocated) is what it does hold, which trails this
    /// downwards as buffers cycle.
    pub(crate) fn target(&self) -> u16 {
        self.ring.target()
    }
}

impl std::fmt::Debug for BufPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BufPool")
            .field("ring", &self.ring)
            .field("idle_rounds", &self.idle_rounds)
            .finish()
    }
}

#[cfg(all(test, not(loom)))]
mod tests;

// The publication protocol `commit` shares with the kernel, as a loom model.
//
// The real ring cannot run under loom (mmap, a registered fd), so the model stands in a plain cell for the mapping -
// but it publishes through `publish_tail`, the same function `commit` calls, so the ordering under test is the one that
// ships rather than a copy of it. Descriptor fields are plain stores, and the consumer - standing in for
// `io_ring_buffer_select`, which pairs with `smp_load_acquire(&br->tail)` (`io_uring/kbuf.c:202`) - acquires the tail
// and only then reads the descriptor. The property is that a tail naming a descriptor happens-after that descriptor's
// fields: weaken the store to `Relaxed` and loom fails this model, which no functional test can, because the
// misordering is invisible on x86 and the reader is the kernel.
#[cfg(all(test, loom))]
mod loom_tests;
