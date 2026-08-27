//! A registered **provided-buffer ring**: buffers the kernel picks from at
//! completion time, rather than an address each SQE names.
//!
//! # Why an op, not a connection, owns a buffer
//!
//! The alternative this replaces is a buffer per connection, sized for the
//! largest read that connection might do and held for its whole life. That
//! makes memory scale with the number of connections rather than with how
//! much data is actually moving - most of it idle, most of the time.
//!
//! Here a buffer is taken when an op completes and released when its bytes
//! have been consumed. Nothing holds one across messages, so the pool is
//! sized for concurrent transfers instead of for the connection table.
//!
//! # The ring is a conveyor, not an allocator
//!
//! The registered region is an array of **descriptors** - each entry carries
//! its own `addr` and `len` - and the storage behind them is entirely this
//! side's business. So the ring is registered once at its maximum entry
//! count and buffers are allocated and posted into it on demand: growing
//! means posting one more, shrinking means not re-posting one that came
//! back.
//!
//! That is SPDK's model (`uring_sock_group_populate_buf_ring`,
//! `module/sock/uring/uring.c`), and it is worth copying for a reason beyond
//! elasticity: **a buffer is freed only in [`BufRing::release`], which runs
//! exactly when the kernel has handed it back.** The alternative - one slab
//! per registered group, retiring a group to shrink - has to prove no buffer
//! anywhere in the group is still lent before freeing the slab under it,
//! which is a whole-pool invariant guarding a use-after-free. Here the
//! question is per buffer and the answer is local.
//!
//! # When a buffer is allocated, and when it is freed
//!
//! There are exactly two places, and both are named here so the hot path is
//! not a guess:
//!
//! - **[`BufRing::post`] allocates, and only for an id that has no buffer.**
//!   An id keeps its storage across a lend/release cycle, so re-posting a
//!   buffer that came back costs nothing - it rewrites a descriptor. Posting
//!   an id that has never been used, or was given up in a shrink, allocates
//!   once.
//! - **[`BufRing::release`] frees, and only when the pool is over target.**
//!   That is the shrink, and it is the only free before `Drop`.
//!
//! So the allocation profile is: `initial` buffers at registration, one per
//! buffer each time the target rises past where it has been, one free per
//! buffer as a lowered target drains, and **nothing at all in steady
//! state** - a connection taking a buffer, filling it, and handing it back
//! allocates nothing, which is the whole point of pooling rather than
//! minting per message. `cycling_a_buffer_allocates_nothing` pins it.
//!
//! The allocation is fallible (`try_reserve_exact`): a server under memory
//! pressure should hold fewer buffers, not abort. Failing to grow is not an
//! error path, it is the same outcome as reaching the ceiling.
//!
//! # The contract with the kernel
//!
//! - The ring is an array of [`IoUringBuf`] whose producer `tail` is
//!   **overlaid on entry zero's `resv` field** (`include/uapi/linux/io_uring.h`).
//!   They share storage by design; a layout that separates them silently
//!   loses every publish.
//! - The memory must be **page aligned**, and the kernel pins it for the
//!   registration's lifetime (`io_uring/memmap.c` rejects an unaligned
//!   `user_addr`). It is mapped rather than allocated for exactly that.
//! - `ring_entries` must be a power of two under 65536 (`io_uring/kbuf.c`).
//! - A completion carries a buffer **iff** `IORING_CQE_F_BUFFER` is set in
//!   `cqe.flags`, with the id in the upper 16 bits. That flag is the whole
//!   rule for whether [`BufRing::release`] is owed: an op that failed before
//!   selecting one - `-ENOBUFS` especially - took nothing.
//! - A buffer cannot be **reserved**. The kernel picks one when the op
//!   completes, not when it is submitted (`io_ring_buffer_select`,
//!   `io_uring/kbuf.c`), so any number of selecting ops can be outstanding
//!   against a pool of any size. Shortage is reported as `-ENOBUFS` on the
//!   completion, which is the only place it can be answered.

use crate::errno::{self, Errno};
use crate::uring::page_size;
use crate::uring::sys::*;
use std::os::fd::RawFd;
// The tail cell is `std`'s in production, reached through a raw pointer into
// the mapping; under loom it is loom's, owned by value and carrying the model
// state - the same split `uring::ring` makes, and for the same reason: the
// ordering below is then one store that both the kernel path and the model
// go through.
#[cfg(loom)]
use loom::sync::atomic::{AtomicU16, Ordering};
#[cfg(not(loom))]
use std::sync::atomic::{AtomicU16, Ordering};

/// The system page size; the granularity the ring must be aligned to.
/// Publish the producer tail.
///
/// `Release` so the kernel cannot observe a tail that names a descriptor
/// whose fields it has not yet seen: it reads the tail with
/// `smp_load_acquire` and only then the descriptor
/// (`io_ring_buffer_select`, `io_uring/kbuf.c:202-216`).
///
/// A function rather than a store inside [`BufRing::commit`] so that the
/// ordering exists once and the loom model drives *this* store. A model with
/// its own copy of the pairing checks the memory model rather than the code -
/// it passes with this weakened to `Relaxed`, which is the case it is for.
#[inline]
fn publish_tail(cell: &AtomicU16, tail: u16) {
    cell.store(tail, Ordering::Release);
}

/// Where one buffer id stands.
///
/// There is no `Free` - allocated but neither posted nor lent - because
/// nothing keeps a buffer in that state: a released buffer is either posted
/// straight back or dropped, decided in one place.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Slot {
    /// No buffer allocated for this id.
    Absent,
    /// Posted to the ring; the kernel may pick it at any time.
    Posted,
    /// The kernel picked it and a consumer holds it.
    Lent,
}

/// A registered ring of descriptors, plus the buffers currently behind them.
pub(crate) struct BufRing {
    /// The mapped descriptor ring. Raw because the kernel holds these pages
    /// pinned until the group is unregistered.
    ring: *mut IoUringBuf,
    /// Mapped length, for `munmap`.
    mapped: usize,
    /// Storage per id, `None` where no buffer is allocated. Indexed by
    /// buffer id, so it is `entries` long for the ring's whole life.
    bufs: Vec<Option<Box<[u8]>>>,
    /// What each id is doing, parallel to `bufs`.
    slots: Vec<Slot>,
    entries: u16,
    mask: u16,
    buf_len: usize,
    bgid: u16,
    /// How many buffers to keep allocated. Growth and shrink move this; the
    /// buffers follow.
    target: u16,
    /// Ids with no buffer behind them, ready for growth to post. A stack
    /// rather than a scan because growth runs on the `-ENOBUFS` path - the
    /// one place already under load - and a per-step scan makes a doubling
    /// quadratic in `entries`.
    absent: Vec<u16>,
    posted: u16,
    lent: u16,
    /// Producer index. The kernel owns the consumer side and never writes
    /// this.
    tail: u16,
    ring_fd: RawFd,
    /// Times a buffer has been handed to the allocator.
    ///
    /// Test-only. The property it exists to observe - that a cycle at
    /// target reaches the allocator not at all - cannot be seen from
    /// outside: freeing and re-allocating a same-sized buffer usually
    /// returns the same address, so comparing pointers across a cycle
    /// reports success either way. A counter nothing reads in production is
    /// a field that drifts, so it is not there in production.
    #[cfg(test)]
    allocs: u64,
}

impl BufRing {
    /// Register a ring of `entries` descriptors, and post `initial` buffers
    /// of `buf_len` bytes into it.
    ///
    /// `entries` is rounded up to a power of two, which the kernel requires,
    /// and is the **ceiling**: it can never be raised, because re-registering
    /// a live `bgid` is `-EEXIST` and unregistering one would pull buffers
    /// out from under any op still holding them. Size it for the most
    /// concurrent arrivals possible - the connection count - not for the
    /// expected load, since an unbacked descriptor slot costs 16 bytes and
    /// nothing else.
    pub(crate) fn new(
        ring_fd: RawFd,
        bgid: u16,
        entries: u16,
        buf_len: usize,
        initial: u16,
    ) -> errno::Result<BufRing> {
        let entries = entries.max(1).next_power_of_two();
        if entries == 0 || buf_len == 0 {
            return Err(Errno::EINVAL);
        }
        let ring_bytes = usize::from(entries) * size_of::<IoUringBuf>();
        let mapped = ring_bytes.next_multiple_of(page_size());
        // SAFETY: an anonymous private mapping of a non-zero length; the
        // kernel chooses the address, which is page aligned by construction
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
        let reg = IoUringBufReg {
            ring_addr: ptr as u64,
            ring_entries: u32::from(entries),
            bgid,
            ..IoUringBufReg::default()
        };
        // SAFETY: `reg` outlives the call and describes the mapping above.
        let registered = unsafe {
            io_uring_register(
                ring_fd,
                IORING_REGISTER_PBUF_RING,
                (&raw const reg).cast(),
                1,
            )
        };
        if let Err(e) = registered {
            // SAFETY: nothing else holds the mapping - registration failed,
            // so the kernel took no pin on it.
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
            tail: 0,
            ring_fd,
            #[cfg(test)]
            allocs: 0,
        };
        br.set_target(initial.clamp(1, entries));
        Ok(br)
    }

    /// Allocate `bid`'s buffer and write its descriptor at the current tail.
    /// Does not publish it - [`BufRing::commit`] does, so a batch of posts
    /// costs one release store.
    ///
    /// Returns false if the allocation failed, which leaves the id `Absent`
    /// and is not an error: the pool simply holds fewer buffers than it
    /// wanted, and the caller's fallback covers that.
    fn post(&mut self, bid: u16) -> bool {
        let i = usize::from(bid);
        debug_assert_eq!(self.slots[i], Slot::Absent, "posting a live buffer");
        // THE ALLOCATION SITE. An id that already has storage keeps it, so
        // re-posting a buffer that just came back through `release` costs a
        // descriptor write and nothing else. Only a first use, or a re-use
        // after a shrink gave the storage up, reaches the allocator.
        if self.bufs[i].is_none() {
            // Fallible on purpose: a server under memory pressure should
            // hold fewer buffers, not abort. `-ENOBUFS` then drops the
            // connection back to owning one, which is the same fallback a
            // pool at its ceiling takes.
            let mut buf: Vec<u8> = Vec::new();
            if buf.try_reserve_exact(self.buf_len).is_err() {
                return false;
            }
            buf.resize(self.buf_len, 0);
            self.bufs[i] = Some(buf.into_boxed_slice());
            #[cfg(test)]
            {
                self.allocs += 1;
            }
        }
        let addr = self.bufs[i].as_mut().expect("just allocated").as_mut_ptr();
        let slot = usize::from(self.tail & self.mask);
        // SAFETY: `slot < entries` and the mapping covers `entries`
        // descriptors, so the writes are in bounds.
        //
        // Field by field, **never `resv`**: on entry zero `resv` is not
        // reserved - it is the ring's published tail, which only `commit`
        // may store. A whole-struct write here zeroes it, and every
        // `entries`-th post lands in slot zero, so the kernel would then
        // see a tail rewound behind its head - which it reads as a nearly
        // full ring, since `tail == head` is its only emptiness test
        // (`io_ring_buffer_select`, `io_uring/kbuf.c:202-216`) - and select
        // unpublished descriptors, taking their stale `addr` verbatim as a
        // recv destination. `a_post_never_touches_the_published_tail` pins
        // this.
        //
        // The ring cannot be overrun: every allocated id is posted at most
        // once at a time, so the number of descriptors the kernel has not
        // yet consumed is `posted`, which never exceeds `entries`.
        unsafe {
            let d = self.ring.add(slot);
            (&raw mut (*d).addr).write(addr as u64);
            (&raw mut (*d).len).write(self.buf_len as u32);
            (&raw mut (*d).bid).write(bid);
        }
        self.tail = self.tail.wrapping_add(1);
        self.slots[i] = Slot::Posted;
        self.posted += 1;
        true
    }

    /// Make every descriptor written since the last commit visible.
    ///
    /// Production only. Under `cfg(loom)` there is no mapping to publish
    /// into, and the cast below must not name loom's `AtomicU16`: that type
    /// is eight bytes where the mapped `resv` field is two, at offset 14 of
    /// a 16-byte descriptor, so the reference would cover memory past the
    /// entry. `uring::ring` keeps the same separation by holding pointers
    /// into the mapping only under `cfg(not(loom))`.
    #[cfg(not(loom))]
    fn commit(&self) {
        // SAFETY: entry zero exists (`entries >= 1`) and its `resv` field is
        // where the kernel reads the producer tail from.
        let tail = unsafe {
            &*(&raw const (*self.ring).resv)
                .cast::<std::sync::atomic::AtomicU16>()
        };
        publish_tail(tail, self.tail);
    }

    /// Under loom the ring is not mapped, so there is nothing to publish.
    #[cfg(loom)]
    fn commit(&self) {}

    /// Keep `want` buffers allocated, posting or dropping to reach it.
    ///
    /// Growth is immediate. Shrinking is not: a buffer that is lent cannot
    /// be dropped, and one that is posted cannot be retracted - the kernel
    /// owns that descriptor until it picks it - so lowering the target only
    /// takes effect as buffers come back through [`release`](Self::release).
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

    /// An id with no buffer behind it, taken. The caller posts it or, on
    /// an allocation failure, hands it back.
    fn absent_id(&mut self) -> Option<u16> {
        self.absent.pop()
    }

    /// Where `bid`'s storage begins, if it has any.
    ///
    /// The kernel writes here for as long as the buffer is lent, so this is
    /// shared with it rather than exclusively ours. That is safe because a
    /// posted id is handed to exactly one op - `release` is owed once per
    /// completion carrying `IORING_CQE_F_BUFFER` - so no two writers ever
    /// hold the same range.
    pub(crate) fn addr_of(&mut self, bid: u16) -> Option<*mut u8> {
        // `as_mut_ptr` from a mutable borrow: callers write through this
        // pointer (a recv destination, the drain's in-place copy), and a
        // pointer cast up from `&` is UB to write through under the borrow
        // rules even where today's codegen is indifferent.
        let b = self.bufs.get_mut(usize::from(bid))?.as_mut()?;
        Some(b.as_mut_ptr())
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
    }

    /// Verify the kernel's pick and record the loan in one step: `bid` must
    /// name a slot this table holds `Posted`, with storage behind it, or
    /// nothing happens and the answer is `None`.
    ///
    /// `None` is a userspace/kernel descriptor desync - an id this table
    /// never posted, or one it already lent - and it is a *refusal*, not an
    /// assertion: the case is reachable without a bug on this side, so it
    /// must not abort the reactor, and it must not fall through to serving
    /// storage this table cannot vouch for - an absent slot has none, and a
    /// lent one belongs to another op. There is also nothing to hand back
    /// on this path: the storage the completion names is not this table's,
    /// so the caller's only sound move is to fail the read the completion
    /// answered.
    pub(crate) fn take_lent(&mut self, bid: u16) -> Option<*mut u8> {
        if self.slots.get(usize::from(bid)) != Some(&Slot::Posted) {
            return None;
        }
        let ptr = self.addr_of(bid)?;
        self.lend(bid);
        Some(ptr)
    }

    /// Hand `bid` back: re-post it, or drop it if the pool has shrunk past
    /// what it needs.
    ///
    /// Owed exactly when a completion carried `IORING_CQE_F_BUFFER`; an op
    /// that never selected one - `-ENOBUFS` above all - must not call this,
    /// or the same id is posted twice and two ops write the same bytes.
    ///
    /// **This is the only place a buffer is freed**, and it runs when the
    /// kernel has already handed the buffer back, so there is no window in
    /// which freed storage is still reachable from a descriptor.
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
            // THE FREE SITE, and the only one before `Drop`: the target
            // fell while this buffer was out, so it is surplus and goes
            // back to the allocator rather than to the ring.
            self.bufs[i] = None;
            self.absent.push(bid);
            return;
        }
        // At or under target: straight back into the ring, reusing the same
        // storage - no allocator traffic on the steady-state path.
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
        // SAFETY: unregistering a group this ring owns; the kernel drops its
        // pin on the mapping - and its reference to every posted buffer --
        // before returning, which is what makes freeing them safe.
        let _ = unsafe {
            io_uring_register(
                self.ring_fd,
                IORING_UNREGISTER_PBUF_RING,
                (&raw const reg).cast(),
                1,
            )
        };
        // SAFETY: the mapping came from `mmap` with this length and nothing
        // else holds it - the kernel's pin was dropped above.
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

/// The kernel's cap on a ring's entry count: a power of two below 65536
/// (`io_uring/kbuf.c:633-637`), so 32768 is the largest registrable.
pub(crate) const MAX_RING_ENTRIES: u16 = 32768;

/// Descriptor slots for a ring that must cover `demand` concurrent buffers.
///
/// A ring is registered once and never resized - re-registering a live
/// `bgid` is `-EEXIST` - so it is sized to the *physical* bound, the most
/// buffers real demand could ever hold at once, not to expected load. A
/// descriptor slot is 16 bytes, so that headroom is not a memory
/// commitment; backing buffers are what cost, and they are allocated only
/// as demand asks. An artificial ceiling below the bound turns a burst
/// into the malloc fallback this ring exists to remove.
///
/// `BufRing::new` rounds the result up to the power of two the kernel
/// requires, which only ever adds slots.
pub(crate) fn ring_entries(demand: u32) -> u16 {
    demand.clamp(1, u32::from(MAX_RING_ENTRIES)) as u16
}

/// Group id of the recv pool: buffers a request arrives into.
pub(crate) const BGID_RECV: u16 = 0;

/// Group id of the file-body pool: buffers a response body is read into.
///
/// A separate group because a group's buffers are interchangeable and
/// selection is FIFO - there is no way to ask one group for a particular
/// size - and a request buffer and a file chunk are sized for different
/// things (`max_request_bytes` against `fs_body_chunk`).
#[cfg(feature = "uring-fs")]
pub(crate) const BGID_FILE_BODY: u16 = 1;

/// Buffers the pool starts with, before demand has said anything.
const POOL_INITIAL: u16 = 8;

/// Consecutive idle observations before the pool gives a buffer up. Growth
/// is immediate and shrinking is not, because a pool that shrinks on the
/// first quiet moment spends its life allocating and freeing across a
/// workload that merely pauses - the same hysteresis hyper applies to its
/// read sizes (`src/proto/h1/io.rs`), for the same reason.
const SHRINK_AFTER: u8 = 4;

/// Sizing policy over one [`BufRing`].
///
/// **It grows on `-ENOBUFS` and not on a free count.** A free count is
/// observed at completion, so it cannot see the selecting ops already armed
/// against the pool - a submit gated on it looks correct, passes a
/// single-connection test, and sheds concurrent connections. The kernel is
/// the only party that knows the pool ran dry, and it says so on the
/// completion.
pub(crate) struct BufPool {
    ring: BufRing,
    /// Consecutive observations with nothing lent.
    idle_rounds: u8,
}

impl BufPool {
    /// Register a pool whose ring can hold at most `entries` buffers of
    /// `buf_len` bytes, under group id `bgid`.
    ///
    /// One group per pool: a group is a set of interchangeable buffers, and
    /// selection is FIFO from the head, so a caller cannot ask a group for a
    /// particular size. Two pools that want different sizes - a recv pool
    /// sized for a request, a body pool sized for a file chunk - are two
    /// groups, and the group id is how an op says which one it wants.
    pub(crate) fn new(
        ring_fd: RawFd,
        bgid: u16,
        buf_len: usize,
        entries: u16,
    ) -> errno::Result<BufPool> {
        Ok(BufPool {
            ring: BufRing::new(
                ring_fd,
                bgid,
                entries,
                buf_len,
                POOL_INITIAL.min(entries.max(1)),
            )?,
            idle_rounds: 0,
        })
    }

    /// The group to stamp into an op's `sqe.buf_group`.
    ///
    /// There is nothing to choose and nothing to check: a full pool is
    /// answered by the kernel with `-ENOBUFS`, not by refusing to arm the
    /// op, because a provided buffer cannot be reserved at submit time.
    pub(crate) fn bgid(&self) -> u16 {
        self.ring.bgid()
    }

    /// The most one buffer from this pool can hold.
    ///
    /// The ceiling on an **exact** selecting read: the kernel clamps a
    /// selecting read down to the buffer it picks
    /// (`io_ring_buffer_select`, `io_uring/kbuf.c`), so a read that asks
    /// for more than this and insists on all of it completes short of what
    /// it asked for. A caller in that position must take an owned buffer
    /// instead of a pool one.
    pub(crate) fn buf_len(&self) -> usize {
        self.ring.buf_len()
    }

    /// Verify a completion's pick and record the loan
    /// ([`BufRing::take_lent`]): the buffer's storage and its length, or
    /// `None` for an id this pool does not hold `Posted` - a descriptor
    /// desync the caller answers by failing the read, since nothing of the
    /// pool's is behind the id.
    pub(crate) fn take_lent(&mut self, bid: u16) -> Option<(*mut u8, usize)> {
        let ptr = self.ring.take_lent(bid)?;
        Some((ptr, self.ring.buf_len()))
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
    /// Doubling rather than stepping: the shortage says the pool is under
    /// its working set, and a workload that opened many connections at once
    /// would otherwise need one `-ENOBUFS` round trip per buffer to get
    /// there. Returns whether the re-armed read can find a buffer - one
    /// this call added, or one already free.
    ///
    /// The free check comes first, and it is what keeps one burst from
    /// growing the pool once per *completion* rather than once. A burst
    /// queues several `-ENOBUFS` completions into one CQE batch, and every
    /// one of them lands here; the first doubling answers them all, so the
    /// rest arrive to find free buffers and a stale shortage. Doubling per
    /// completion instead is 2^N for one batch - measured at the default
    /// config: sixteen concurrent readers ran the pool from 8 buffers to
    /// its 4096-entry ceiling, a gigabyte of resident buffers for a burst
    /// that needed four megabytes, with `free == allocated` at every
    /// doubling. The same check answers the ceiling honestly: a pool that
    /// cannot grow but holds free buffers is not exhausted, and reporting
    /// failure there would demote the connection to owned buffers for the
    /// rest of its life (`set_recv_owned` is one-way) over a shortage that
    /// no longer exists.
    ///
    /// The doubling is measured from whichever of target and allocated is
    /// larger. A real shortage means every allocated buffer is lent, and an
    /// idle stretch may have lowered the target below that count while they
    /// were out; doubling the *target* would then land at or under what is
    /// already allocated and add nothing.
    pub(crate) fn grow(&mut self) -> bool {
        self.idle_rounds = 0;
        if self.ring.free() > 0 {
            return true;
        }
        let allocated = self.ring.allocated();
        let base = self.ring.target().max(allocated);
        if base >= self.ring.entries() {
            return false;
        }
        self.ring.set_target(base.saturating_mul(2).max(1));
        self.ring.allocated() > allocated
    }

    /// Lower what the pool is trying to hold, once it has been idle for
    /// long enough. Halving, to match the growth.
    ///
    /// **This lowers the target; the buffers follow as they cycle.** A
    /// posted descriptor cannot be retracted - the kernel owns that entry
    /// until it picks it - so surplus storage is given up in
    /// [`release`](BufRing::release), as each buffer comes back. A pool that
    /// goes from busy to *quieter* therefore returns its surplus promptly,
    /// and one that goes from busy to *silent* holds it until traffic
    /// resumes, since nothing is cycling to hand anything back.
    ///
    /// That residue is bounded by the ring's ceiling and is no worse than
    /// what it replaces: a per-connection buffer that grew once stayed grown
    /// for the connection's life, and there were `pool_size` of them.
    ///
    /// The sample is taken at the arm sites, where the arming connection
    /// itself holds no claim by definition - so a single serial connection
    /// reads zero loans every time and walks the target down to one, which
    /// for that workload is the right size; any second active connection
    /// resets the count. The cost lands on the first burst after a quiet
    /// stretch, one honest `-ENOBUFS` round trip per doubling back up.
    /// Sampling a high-water mark since the last call instead would never
    /// read zero on any serving workload, and a pool that can never see
    /// idle never shrinks - so the sample stays instantaneous.
    pub(crate) fn rebalance(&mut self) {
        if self.ring.lent() > 0 {
            self.idle_rounds = 0;
            return;
        }
        self.idle_rounds = self.idle_rounds.saturating_add(1);
        if self.idle_rounds < SHRINK_AFTER {
            return;
        }
        self.idle_rounds = 0;
        let want = (self.ring.target() / 2).max(1);
        if want < self.ring.target() {
            self.ring.set_target(want);
        }
    }

    /// What the pool is trying to hold. [`allocated`](Self::allocated) is
    /// what it does hold, which trails this downwards as buffers cycle.
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
mod tests {
    use super::*;
    use crate::uring::ring::RingFd;

    /// A ring the kernel accepted, or `None` where io_uring is unavailable
    /// (a container without it). Skipping is loud in the caller.
    fn ring() -> Option<RingFd> {
        match RingFd::setup(8) {
            Ok(r) => Some(r),
            Err(e) if crate::uring::setup_unavailable(e) => None,
            Err(e) => panic!("io_uring_setup: {e}"),
        }
    }

    /// Registration is where the ABI is easiest to get silently wrong: the
    /// mapping has to be page aligned, the entry count a power of two, and
    /// the descriptor layout has to match what the kernel reads. A ring the
    /// kernel accepts and then releases proves all three at once.
    #[test]
    fn a_ring_registers_and_unregisters() {
        let Some(r) = ring() else {
            return;
        };
        let br = BufRing::new(r.raw_fd(), 0, 4, 64, 4).expect("registers");
        assert_eq!(br.entries(), 4);
        assert_eq!(br.buf_len(), 64);
        assert_eq!(br.lent(), 0, "nothing lent before an op runs");
        assert_eq!(br.free(), 4, "every buffer posted");
        drop(br); // unregisters; a leak would fail the next registration
        let again = BufRing::new(r.raw_fd(), 0, 4, 64, 4);
        assert!(again.is_ok(), "the id was freed: {again:?}");
    }

    /// The kernel demands a power of two and rejects anything else, so the
    /// rounding happens here rather than surfacing as `-EINVAL` from a
    /// number the caller thought was fine.
    #[test]
    fn an_entry_count_is_rounded_to_a_power_of_two() {
        let Some(r) = ring() else {
            return;
        };
        let br = BufRing::new(r.raw_fd(), 1, 5, 32, 1).expect("registers");
        assert_eq!(br.entries(), 8, "5 rounded up, not refused");
    }

    /// Entries are descriptors and buffers are allocated behind them, so a
    /// ring registered for many can start holding few. This is what makes
    /// the entry count a free ceiling rather than a commitment.
    #[test]
    fn a_ring_holds_fewer_buffers_than_it_has_entries() {
        let Some(r) = ring() else {
            return;
        };
        let mut br =
            BufRing::new(r.raw_fd(), 0, 64, 128, 2).expect("registers");
        assert_eq!(br.entries(), 64, "room for 64");
        assert_eq!(br.allocated(), 2, "but only 2 allocated");
        assert!(br.addr_of(0).is_some(), "id 0 is backed");
        assert!(br.addr_of(2).is_none(), "id 2 is not");
    }

    /// Raising the target allocates and posts; every id stays distinct, so
    /// no two ops can be handed the same storage.
    #[test]
    fn growing_posts_distinct_buffers() {
        let Some(r) = ring() else {
            return;
        };
        let mut br = BufRing::new(r.raw_fd(), 0, 8, 64, 2).expect("registers");
        br.set_target(6);
        assert_eq!(br.allocated(), 6);
        let mut seen: Vec<*mut u8> =
            (0..6).map(|b| br.addr_of(b).expect("backed")).collect();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), 6, "six ids, six distinct allocations");
    }

    /// A lend/release round trip returns the buffer to the ring rather than
    /// consuming it, so a steady workload cycles the same storage.
    #[test]
    fn a_released_buffer_returns_to_the_ring() {
        let Some(r) = ring() else {
            return;
        };
        let mut br = BufRing::new(r.raw_fd(), 0, 4, 64, 4).expect("registers");
        let before = br.addr_of(1).expect("backed");
        br.lend(1);
        assert_eq!(br.lent(), 1);
        assert_eq!(br.free(), 3, "one fewer available");
        br.release(1);
        assert_eq!(br.lent(), 0);
        assert_eq!(br.free(), 4, "back in the ring");
        assert_eq!(br.addr_of(1), Some(before), "same storage, not a new one");
    }

    /// A post must never store to the published tail. Entry zero's `resv`
    /// IS the tail, so this drives the ring until the next post lands in
    /// descriptor slot zero, posts, and reads the tail cell back before
    /// committing: a whole-struct descriptor write shows up here as the
    /// tail rewound to zero - which the kernel, whose only emptiness test
    /// is `tail == head`, reads as a nearly full ring of unpublished
    /// descriptors.
    #[test]
    fn a_post_never_touches_the_published_tail() {
        let Some(r) = ring() else {
            return;
        };
        let mut br = BufRing::new(r.raw_fd(), 0, 4, 64, 3).expect("registers");
        let tail_cell = |br: &BufRing| unsafe {
            (*(&raw const (*br.ring).resv).cast::<AtomicU16>())
                .load(Ordering::Acquire)
        };
        assert_eq!(tail_cell(&br), 3, "three posts published at setup");
        // Free two ids without re-posting them (target below allocated).
        br.set_target(1);
        br.lend(0);
        br.release(0); // freed, not re-posted: allocated >= target
        br.lend(1);
        br.release(1);
        assert_eq!(br.allocated(), 1);
        // Advance the tail to the wrap: this post lands in slot 3.
        assert!(br.post(0), "repost id 0 into slot 3");
        br.commit();
        assert_eq!(tail_cell(&br), 4);
        // The post under test: tail 4 & mask 3 = descriptor slot zero,
        // where the descriptor overlays the tail cell.
        assert!(br.post(1), "repost id 1 into slot 0");
        assert_eq!(
            tail_cell(&br),
            4,
            "a post into slot zero stored over the published tail"
        );
        br.commit();
        assert_eq!(tail_cell(&br), 5, "commit alone advances it");
    }

    /// A second release of the same id is refused before it can re-post a
    /// buffer another op still owns, or wrap the loan count.
    ///
    /// The `debug_assert` fires first, so this reaches only the debug half
    /// of the guard and only in a debug build - in a release build
    /// `should_panic` has nothing to catch. The `if` beside it is what
    /// ships, and `releasing_one_id_twice_is_refused_without_asserts`
    /// covers that.
    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "releasing a buffer nobody took")]
    fn releasing_one_id_twice_is_refused() {
        let Some(r) = ring() else {
            panic!("releasing a buffer nobody took: skipped, no io_uring");
        };
        let mut br = BufRing::new(r.raw_fd(), 0, 4, 64, 4).expect("registers");
        br.lend(1);
        br.release(1);
        assert_eq!(br.free(), 4, "the first release landed");
        br.release(1); // the second owner
    }

    /// A bid the table never posted is refused, and nothing moves.
    ///
    /// The kernel naming such an id is a userspace/kernel descriptor
    /// desync, reachable without a bug on this side, so it must not abort
    /// the reactor in any build. There is also nothing to "hand back": no
    /// storage of the table's is behind the id, so the only sound answer
    /// is a refusal the caller turns into failing the read.
    #[test]
    fn a_bid_never_posted_is_refused_without_an_abort() {
        let Some(r) = ring() else {
            return;
        };
        let mut br = BufRing::new(r.raw_fd(), 0, 8, 64, 4).expect("registers");
        let before = (br.free(), br.lent(), br.allocated());
        assert_eq!(br.take_lent(7), None, "an absent id is refused");
        assert_eq!(br.take_lent(200), None, "an out-of-range id is refused");
        assert_eq!(
            (br.free(), br.lent(), br.allocated()),
            before,
            "and the refusals moved nothing"
        );
    }

    /// A bid that is already lent is the same desync with a worse
    /// consequence: the storage belongs to another op, so a second loan
    /// would hand two consumers one buffer. Refused, with the first loan
    /// left standing.
    #[test]
    fn a_bid_already_lent_is_refused_not_reserved() {
        let Some(r) = ring() else {
            return;
        };
        let mut br = BufRing::new(r.raw_fd(), 0, 4, 64, 4).expect("registers");
        assert!(br.take_lent(1).is_some(), "a posted id lends");
        let before = (br.free(), br.lent(), br.allocated());
        assert_eq!(br.take_lent(1), None, "a second pick of it is refused");
        assert_eq!(
            (br.free(), br.lent(), br.allocated()),
            before,
            "and the first loan stands"
        );
    }

    /// The shipping half of the same refusal: with `debug_assertions` off
    /// the `if` is the whole guard, and what it must do is nothing.
    ///
    /// A fall-through re-posts an id that is already `Posted`, so the ring
    /// would carry two descriptors naming one buffer and the kernel would
    /// hand it to two ops at once. It also decrements `lent` from zero,
    /// which wraps rather than panics here, and a wrapped loan count reads
    /// as a nearly empty pool. Asserted on state instead of a panic so the
    /// test says the same thing in either build.
    #[cfg(not(debug_assertions))]
    #[test]
    fn releasing_one_id_twice_is_refused_without_asserts() {
        let Some(r) = ring() else {
            return;
        };
        let mut br = BufRing::new(r.raw_fd(), 0, 4, 64, 4).expect("registers");
        br.lend(1);
        br.release(1);
        assert_eq!(br.free(), 4, "the first release landed");
        let (free, lent, allocated) = (br.free(), br.lent(), br.allocated());
        br.release(1); // the second owner
        assert_eq!(br.free(), free, "a refused release posted nothing");
        assert_eq!(br.lent(), lent, "and retired no loan");
        assert_eq!(br.allocated(), allocated, "and allocated nothing");
    }

    /// A release naming an id the ring has no slot for: a
    /// userspace/kernel descriptor desync, refused before it can index
    /// out of the table.
    ///
    /// The `debug_assert` fires first, so this reaches only the debug half
    /// and only in a debug build.
    /// `releasing_an_id_outside_the_ring_is_refused_without_asserts`
    /// covers the `return` that ships beside it.
    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "buffer id outside the ring")]
    fn releasing_an_id_outside_the_ring_is_refused() {
        let Some(r) = ring() else {
            panic!("buffer id outside the ring: skipped, no io_uring");
        };
        let mut br = BufRing::new(r.raw_fd(), 0, 4, 64, 4).expect("registers");
        br.release(200);
    }

    /// The shipping half: with `debug_assertions` off the `let else` is the
    /// whole guard, and what it must do is nothing at all - no loan
    /// retired, since `lent` would otherwise be decremented for a buffer
    /// nobody took and a wrapped count reads as a nearly empty pool.
    #[cfg(not(debug_assertions))]
    #[test]
    fn releasing_an_id_outside_the_ring_is_refused_without_asserts() {
        let Some(r) = ring() else {
            return;
        };
        let mut br = BufRing::new(r.raw_fd(), 0, 4, 64, 4).expect("registers");
        br.lend(1);
        let before = (br.free(), br.lent(), br.allocated());
        br.release(200);
        assert_eq!(
            (br.free(), br.lent(), br.allocated()),
            before,
            "an out-of-range release moved nothing"
        );
    }

    /// The steady-state path allocates nothing.
    ///
    /// A buffer cycling lend -> release -> re-post keeps its storage: the
    /// only allocation site is `post`, guarded on the id having none, and
    /// the only free site is the over-target branch of `release`.
    ///
    /// Counted rather than compared. An earlier version of this test read
    /// the buffer's address before and after a cycle and asserted it had
    /// not moved - which passes just as happily when the storage is freed
    /// and re-allocated, because an allocator handed back a block of the
    /// same size usually returns the one it just took.
    #[test]
    fn cycling_a_buffer_allocates_nothing() {
        let Some(r) = ring() else {
            return;
        };
        let mut br = BufRing::new(r.raw_fd(), 0, 4, 64, 4).expect("registers");
        assert_eq!(br.allocs, 4, "one per buffer at registration");
        for _ in 0..32 {
            br.lend(1);
            br.release(1);
        }
        assert_eq!(br.allocs, 4, "32 cycles reached the allocator not once");
        assert_eq!(br.allocated(), 4, "and the pool is unchanged");
    }

    /// The mirror: over target, the release *does* give the storage up.
    /// Together with the test above this pins exactly when the allocator is
    /// reached.
    #[test]
    fn a_release_over_target_gives_the_storage_up() {
        let Some(r) = ring() else {
            return;
        };
        let mut br = BufRing::new(r.raw_fd(), 0, 4, 64, 4).expect("registers");
        br.lend(2);
        assert!(br.bufs[2].is_some());
        br.set_target(1);
        br.release(2);
        assert!(br.bufs[2].is_none(), "surplus storage freed, not re-posted");
    }

    /// Shrinking cannot take a buffer away from an op that holds it. The
    /// target falls, but the storage survives until the consumer releases
    /// it - which is the whole reason a buffer is freed in `release` and
    /// nowhere else.
    #[test]
    fn a_lent_buffer_survives_a_shrink() {
        let Some(r) = ring() else {
            return;
        };
        let mut br = BufRing::new(r.raw_fd(), 0, 8, 64, 8).expect("registers");
        br.lend(3);
        let held = br.addr_of(3).expect("backed");
        br.set_target(1);
        assert_eq!(
            br.addr_of(3),
            Some(held),
            "a lent buffer is still there to be written into"
        );
        assert_eq!(br.lent(), 1);
        // Only on release does it go, because only then is the kernel done.
        br.release(3);
        assert!(br.addr_of(3).is_none(), "freed once handed back");
    }

    /// Over-target buffers are given up as they come back, one release at a
    /// time, and the ring settles at the target rather than below it.
    #[test]
    fn releases_drain_down_to_the_target() {
        let Some(r) = ring() else {
            return;
        };
        let mut br = BufRing::new(r.raw_fd(), 0, 8, 64, 6).expect("registers");
        for bid in 0..6 {
            br.lend(bid);
        }
        assert_eq!(br.allocated(), 6);
        br.set_target(2);
        for bid in 0..6 {
            br.release(bid);
        }
        assert_eq!(br.allocated(), 2, "settled at the target");
        assert_eq!(br.free(), 2, "and both are posted");
        assert_eq!(br.lent(), 0);
    }

    /// Covering demand survives the power-of-two rounding: the round-up
    /// only adds slots, and the kernel cap is itself a power of two.
    #[test]
    fn ring_entries_covers_demand_up_to_the_kernel_cap() {
        assert_eq!(ring_entries(0), 1);
        assert_eq!(ring_entries(512), 512);
        assert_eq!(ring_entries(513).next_power_of_two(), 1024);
        assert_eq!(ring_entries(100_000), MAX_RING_ENTRIES);
        assert_eq!(MAX_RING_ENTRIES.next_power_of_two(), MAX_RING_ENTRIES);
    }

    /// The pool doubles on shortage rather than stepping, because the
    /// shortage says it is under its working set and a per-buffer step
    /// would need one `-ENOBUFS` round trip each to get there.
    #[test]
    fn a_pool_doubles_when_it_runs_dry() {
        let Some(r) = ring() else {
            return;
        };
        let mut p = BufPool::new(r.raw_fd(), 0, 64, 64).expect("registers");
        let start = p.allocated();
        // Dry means dry: every buffer lent. A shortage with buffers free
        // is stale - already answered by an earlier doubling - and grows
        // nothing.
        for b in 0..start {
            assert!(p.take_lent(b).is_some(), "lend {b}");
        }
        assert!(p.grow(), "room to grow");
        assert_eq!(p.allocated(), start * 2, "doubled");
    }

    /// The ceiling is not exhaustion while anything is free.
    ///
    /// `grow()`'s answer is read as "will the re-armed read find a
    /// buffer". At the ceiling with buffers free the answer is yes, and a
    /// `false` there is answered with a demotion to owned buffers that
    /// lasts the connection's life - over a shortage that no longer
    /// exists. `false` is reserved for the pool that can neither grow nor
    /// offer anything: every buffer lent, nowhere left to go.
    #[test]
    fn the_ceiling_is_not_exhaustion_while_anything_is_free() {
        let Some(r) = ring() else {
            return;
        };
        let mut p = BufPool::new(r.raw_fd(), 0, 64, 4).expect("registers");
        assert_eq!(p.allocated(), 4, "born at the ceiling");
        assert!(p.grow(), "free buffers at the ceiling answer a shortage");
        assert_eq!(p.allocated(), 4, "without growing past it");
        for b in 0..4 {
            assert!(p.take_lent(b).is_some(), "lend {b}");
        }
        assert!(
            !p.grow(),
            "everything lent and nowhere to grow is exhaustion"
        );
        p.release(0);
        assert!(p.grow(), "one freed buffer answers the next shortage");
    }

    /// One burst grows the pool once, not once per queued completion.
    ///
    /// A burst queues several `-ENOBUFS` completions into one CQE batch
    /// and each lands in `grow()`. The first doubling answers them all;
    /// without the free check the rest double a pool that already grew -
    /// 2^N for one batch, measured at a gigabyte of resident buffers on
    /// the default config for a burst that needed four megabytes.
    #[test]
    fn a_batch_of_shortages_doubles_once() {
        let Some(r) = ring() else {
            return;
        };
        let mut p = BufPool::new(r.raw_fd(), 0, 64, 4096).expect("registers");
        let start = p.allocated();
        for b in 0..start {
            assert!(p.take_lent(b).is_some(), "lend {b}");
        }
        assert!(p.grow(), "a genuine shortage grows");
        let after = p.allocated();
        assert_eq!(after, start * 2, "one doubling");
        for i in 0..16 {
            assert!(p.grow(), "queued completion {i} finds the answer");
        }
        assert_eq!(
            p.allocated(),
            after,
            "the rest of the batch rode the first doubling"
        );
    }

    /// Shrinking waits for several consecutive idle rounds. A pool that
    /// lowered its sights the moment it went quiet would spend a bursty
    /// workload allocating and freeing.
    #[test]
    fn a_pool_shrinks_only_after_staying_idle() {
        let Some(r) = ring() else {
            return;
        };
        let mut p = BufPool::new(r.raw_fd(), 0, 64, 64).expect("registers");
        p.grow();
        p.grow();
        let grown = p.target();
        assert!(grown > 1);
        for round in 0..SHRINK_AFTER - 1 {
            p.rebalance();
            assert_eq!(p.target(), grown, "still aiming high at round {round}");
        }
        p.rebalance();
        assert!(p.target() < grown, "lowered after the quiet spell");
    }

    /// Lowering the target does not free anything by itself - a posted
    /// descriptor cannot be retracted from the kernel - so the surplus goes
    /// back as each buffer completes a cycle. This is what makes a pool
    /// that quietens down return its memory, and why one that goes silent
    /// outright keeps it.
    #[test]
    fn surplus_is_given_up_as_buffers_cycle() {
        let Some(r) = ring() else {
            return;
        };
        let mut p = BufPool::new(r.raw_fd(), 0, 64, 64).expect("registers");
        p.grow();
        p.grow();
        let grown = p.allocated();
        for _ in 0..SHRINK_AFTER {
            p.rebalance();
        }
        assert!(p.target() < grown, "aiming lower");
        assert_eq!(p.allocated(), grown, "but still holding it all");
        // One cycle per buffer is what hands the surplus back.
        for bid in 0..grown {
            assert!(p.take_lent(bid).is_some(), "a posted id lends");
            p.release(bid);
        }
        assert_eq!(p.allocated(), p.target(), "settled where it was aiming");
        assert!(p.allocated() < grown, "and that is fewer than before");
    }

    /// Activity resets the count, so a pool that is busy every so often
    /// never reaches the shrink threshold.
    #[test]
    fn activity_resets_the_idle_count() {
        let Some(r) = ring() else {
            return;
        };
        let mut p = BufPool::new(r.raw_fd(), 0, 64, 64).expect("registers");
        p.grow();
        let grown = p.target();
        for _ in 0..SHRINK_AFTER * 3 {
            for _ in 0..SHRINK_AFTER - 1 {
                p.rebalance();
            }
            // One buffer in use is enough to count as busy.
            assert!(p.take_lent(0).is_some(), "a posted id lends");
            p.rebalance();
            p.release(0);
        }
        assert_eq!(p.target(), grown, "never lowered while it was working");
    }

    /// A shortage while the target sits *below* what is allocated still
    /// grows.
    ///
    /// An idle stretch lowers the target, and the surplus is given up only
    /// as buffers cycle - so a pool that goes quiet and then busy can hold
    /// more than it is aiming for, with every one of them lent. Measuring
    /// the doubling from the target lands at or under that count, adds
    /// nothing and reports failure, and the caller answers a reported
    /// failure by demoting the connection to owned buffers for the rest of
    /// its life.
    #[test]
    fn a_shortage_below_a_shrunk_target_still_grows() {
        let Some(r) = ring() else {
            return;
        };
        let Ok(mut p) = BufPool::new(r.raw_fd(), 5, 64, 64) else {
            return;
        };
        // Idle it down first: the target falls, and the surplus is given
        // up only in `release`, so nothing posted cycles and the pool goes
        // on holding what it had.
        for _ in 0..SHRINK_AFTER {
            p.rebalance();
        }
        let allocated = p.allocated();
        assert!(
            p.target() < allocated,
            "the fixture needs a target under what is held: {} vs {allocated}",
            p.target()
        );

        // Then hand every one of them out, which is what a shortage means.
        let held: Vec<u16> = (0..allocated)
            .filter(|&b| p.take_lent(b).is_some())
            .collect();
        assert_eq!(
            held.len(),
            allocated as usize,
            "the fixture has to lend them all"
        );

        assert!(
            p.grow(),
            "a dry ring holding {allocated} buffers reported no growth"
        );
        assert!(
            p.allocated() > allocated,
            "and added none: {} vs {allocated}",
            p.allocated()
        );
    }

    /// A growth that could not allocate reports failure, so the caller
    /// takes its owned-buffer fallback.
    ///
    /// `post` is fallible on purpose, and the promise attached to that
    /// fallback - the re-armed read cannot come back `-ENOBUFS` a second
    /// time - is only kept if `grow` answers on buffers posted rather than
    /// on the target it just raised. A `buf_len` no allocator can satisfy
    /// makes every `post` fail without touching the ring.
    #[test]
    fn growth_that_allocates_nothing_reports_failure() {
        let Some(r) = ring() else {
            return;
        };
        let Ok(mut p) = BufPool::new(r.raw_fd(), 3, usize::MAX / 2, 64) else {
            return;
        };
        assert_eq!(p.allocated(), 0, "nothing could be allocated at all");
        for round in 0..3 {
            assert!(
                !p.grow(),
                "round {round}: grow reported success with {} allocated",
                p.allocated()
            );
            assert_eq!(
                p.allocated(),
                0,
                "round {round}: still nothing behind the target"
            );
        }
    }

    /// The pool always keeps at least one buffer: dropping to zero would
    /// mean every recv came back `-ENOBUFS` with nothing to grow from.
    #[test]
    fn a_pool_keeps_a_last_buffer() {
        let Some(r) = ring() else {
            return;
        };
        let mut p = BufPool::new(r.raw_fd(), 0, 64, 64).expect("registers");
        for _ in 0..SHRINK_AFTER * 8 {
            p.rebalance();
        }
        assert!(p.target() >= 1, "never aims at nothing");
        assert!(p.free() >= 1, "and what it keeps is available");
    }
}

// The publication protocol `commit` shares with the kernel, as a loom model.
//
// The real ring cannot run under loom (mmap, a registered fd), so the model
// stands in a plain cell for the mapping - but it publishes through
// `publish_tail`, the same function `commit` calls, so the ordering under
// test is the one that ships rather than a copy of it. Descriptor fields are
// plain stores, and the consumer - standing in for `io_ring_buffer_select`,
// which pairs with `smp_load_acquire(&br->tail)` (`io_uring/kbuf.c:202`) -
// acquires the tail and only then reads the
// descriptor. The property is that a tail naming a descriptor
// happens-after that descriptor's fields: weaken the store to `Relaxed`
// and loom fails this model, which no functional test can, because the
// misordering is invisible on x86 and the reader is the kernel.
#[cfg(all(test, loom))]
mod loom_tests {
    use super::publish_tail;
    use loom::cell::UnsafeCell;
    use loom::sync::Arc;
    use loom::sync::atomic::{AtomicU16, Ordering};

    struct Ring {
        /// One descriptor's `addr` field: written plainly, like `post`.
        addr: UnsafeCell<u64>,
        /// The overlaid tail, published by `commit`'s own store.
        tail: AtomicU16,
    }

    // SAFETY: the tail's release/acquire pair is the only synchronization,
    // exactly as on the real ring; loom verifies the accesses race-free
    // under it.
    unsafe impl Sync for Ring {}

    #[test]
    fn loom_a_descriptor_is_published_before_the_tail_that_names_it() {
        loom::model(|| {
            let ring = Arc::new(Ring {
                addr: UnsafeCell::new(0),
                tail: AtomicU16::new(0),
            });
            let producer = Arc::clone(&ring);
            let t = loom::thread::spawn(move || {
                // `post`: the descriptor's fields...
                producer.addr.with_mut(|p| unsafe { *p = 0xB0F });
                // ...then `commit`, through the store `commit` itself uses.
                publish_tail(&producer.tail, 1);
            });
            // The kernel's side: acquire the tail; a tail that names the
            // descriptor must find its address already there.
            if ring.tail.load(Ordering::Acquire) == 1 {
                let addr = ring.addr.with(|p| unsafe { *p });
                assert_eq!(addr, 0xB0F, "tail visible before its descriptor");
            }
            t.join().unwrap();
        });
    }
}
