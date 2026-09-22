//! Reusable storage for placed and promoted request bodies.
//!
//! The recv pool serves every message that fits one pool buffer, and the
//! file-body ring already made response chunks the ring's rather than a
//! connection's. What neither covers is a *request* body larger than one
//! recv buffer: placement reads it into its own allocation, and the
//! accumulate path promotes into owned storage. Both used to mint a fresh
//! `Vec` per message — per-request allocation on exactly the bodies that
//! arrive in storms (a delete batch, a completion manifest), mmap-backed
//! at those sizes, faulted in and torn down each time.
//!
//! This pool ends that the same way the chunk ring did: the storage
//! belongs to the ring, sized by demand rather than by the connection
//! table. It is plain userspace storage, not a provided-buffer group, and
//! that is a division of labour rather than a second discipline: a
//! provided buffer is a *kernel-selected* destination — posted so the
//! kernel can pick it for whichever connection's data arrives next, its
//! group forced to one uniform `buf_len` allocated whole. A large body is
//! the opposite job: one *directed* destination of exactly the body's
//! size, filled across retries or windows and then parsed. Lending a
//! posted buffer to userspace as scratch would race the kernel picking
//! it, and sizing a group at the largest legal body would fault whole
//! maximal buffers for storms of small ones. Kernel-selected work rides
//! the rings; directed placement rides this pool; both answer to the same
//! shrink law and the same maintenance timer.
//!
//! # Policy: bytes, not buffers
//!
//! The bound that matters here is resident memory, and buffer *counts*
//! do not measure it — one retained `Vec` that once held a maximal body
//! keeps that capacity for as long as it is retained. So the law is in
//! bytes:
//!
//! - **Retention is licensed by demand, measured in bytes.** A claim
//!   that finds nothing fitting allocates (the caller's body must exist
//!   regardless) and records the *size* it needed — a sizeless count
//!   let `claim(0)` + `give(64 MiB)` license retaining sixty-four
//!   megabytes nobody asked for. When storage comes home, outstanding
//!   missed bytes license raising the retention target toward it — so
//!   the target grows toward the storm's real working set and never
//!   ahead of it.
//! - **A licence lives as long as its claim is in flight.** The
//!   reactor's claims ([`BodyPool::claim_held`]) resolve
//!   deterministically — the storage is given back, or the body leaves
//!   custody at delivery ([`BodyPool::receipt_done`]) — so their
//!   licences ride the claim itself and survive however many
//!   maintenance ticks a slow receipt spans; a licence that expired
//!   with the tick made the pool inert for exactly the slow-link
//!   uploads it exists for. Only the *windowed* pot expires: consumer
//!   claims ([`BodyRecycler`]) and delivered bodies awaiting an
//!   optional recycle, where nothing guarantees the storage ever
//!   returns.
//! - **A body is served from storage near its size.** The free list is
//!   kept sorted by capacity and taken best-fit, and a buffer more than
//!   a few times the ask is left for the body it was sized by — serving
//!   every small body from the high-water buffer is the "whole maximal
//!   buffers for storms of small ones" this module's own header rejects.
//! - **A hard budget caps the target.** Whatever demand claims, retained
//!   bytes never exceed the budget the pool was built with; storage over
//!   it is freed on the spot, and a single body larger than the budget
//!   is never retained at all. The worst case is the budget, per ring,
//!   full stop.
//! - **Quiet halves and evicts, and quiet means no *serve*.**
//!   [`BodyPool::rebalance`] is driven by the ring's maintenance timer;
//!   [`SHRINK_AFTER`] consecutive observations without a pool-served
//!   claim halve the target and free the surplus immediately. A claim
//!   the inventory cannot serve is a miss, not heat: read off claims,
//!   the detector let an inventory serving nothing pin itself at the
//!   budget for as long as any traffic flowed, which is exactly the
//!   stale working set the shrink exists to reclaim. Userspace storage
//!   has no posted-descriptor problem, so the give-back needs no
//!   traffic — this pool shrinks in silence, where the kernel rings can
//!   only lower their targets and wait for buffers to cycle home.
//! - **Under load, each buffer earns its keep.** The heat above is the
//!   pool's as a whole, so a mixed inventory serving one size class
//!   would shield another class's dead high-water buffers forever. A
//!   free entry that serves nothing for [`SHRINK_AFTER`] hot
//!   observations is evicted at the rebalance, licence and all, so
//!   *retained capacity* tracks the live working set within a few
//!   windows of a workload shift. Capacity, not resident pages: the
//!   two are named apart throughout this module because they are
//!   taken by different instruments (see [`OVERSIZE_SERVE`]), and
//!   dropping a `Vec` returns pages only as far as the allocator
//!   unmaps them — glibc raises `M_MMAP_THRESHOLD` to the size of
//!   each mmapped block it frees, so a pool cycling multi-MiB bodies
//!   migrates to arena allocations whose `free()` trims nothing.
//!   Retained capacity is the figure this pool moves and the upper
//!   bound resident can fall to; it is not a measurement of resident.
//!   Quiet windows never age entries — the halving path owns that
//!   regime — so a workload that merely pauses keeps its warm pool.
//!
//! # The loop is advisory on the consumer side
//!
//! The reactor returns promoted storage itself, but a *delivered* body
//! moves out through the handler, and only the consumer knows when its
//! bytes are dead. [`BodyRecycler::recycle`] is that seam. A handler that
//! never calls it costs exactly what the old code cost — the pool refills
//! from misses — so the call is an optimization contract, not a
//! correctness one, and nothing breaks when an error path drops a body on
//! the floor.
//!
//! # Two inventories, one law
//!
//! A direct write needs page-aligned storage ([`AlignedBuf`]), ideally
//! registered in the ring's fixed-buffer table ([`FixedTable`]) so the
//! pages are pinned once. The pool keeps one such inventory beside its
//! `Vec`s: [`FIXED_RECORD`]s in a LIFO, each registered when allocated
//! and cleared when freed, under the same `retained`/`target`/`budget`,
//! the same heat and the same shrink.
//!
//! A [`Fixed`] returns itself on `Drop`, from any thread, through a
//! returns queue the ring drains before a claim and at the tick; a
//! connection can die with one in hand on the kTLS handshake thread.
//! Its licence rides the buffer (held, never windowed).
//!
//! Slots are a bound of their own: a record past the slot range serves
//! unregistered ([`Fixed::slot`] is `None`) and is registered by the
//! claim that next serves it once a slot frees. No table at all is
//! every record in that state.
//!
//! No kind owns the budget: a give whose licence covers it (a record's
//! held licence, or the `Vec` pot) that finds the budget full evicts the
//! other kind's coldest entries down to a ceiling that leaves the asker
//! a quarter ([`KIND_FLOOR`]), and only when that makes enough room. A
//! give the pot cannot cover takes nothing; a pool serving one kind
//! alone still fills the budget.

use std::cell::RefCell;
use std::rc::Rc;

use crate::uring::aligned::AlignedBuf;
use crate::uring::fixed::FixedTable;

/// The fixed buffer size, and the unit a direct write is staged in. One
/// size only, because a filesystem takes a write direct at its block
/// size or more and lands only whole blocks (on ZFS: `zfs_setup_direct`,
/// `dmu_write_uio_dnode`). A smaller buffer could never write direct
/// against a block this large, and this one covers whole blocks at every
/// smaller block size. It is also the size from which a zero-copy send
/// would pay for itself.
pub const FIXED_RECORD: usize = 1 << 20;

/// A record in the pool: buffer, slot, and the held licence its claim
/// recorded (0 when served).
struct Returned {
    buf: AlignedBuf,
    slot: Option<u16>,
    licence: usize,
}

/// Where a dropped [`Fixed`] goes, from any thread, to be drained on
/// the ring at the next claim or tick (no poke: every claim drains
/// first).
struct Returns {
    queue: crate::sync::Mutex<std::collections::VecDeque<Returned>>,
}

impl Returns {
    fn new() -> Returns {
        Returns {
            queue: crate::sync::Mutex::new(std::collections::VecDeque::new()),
        }
    }

    fn push(&self, r: Returned) {
        self.queue
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push_back(r);
    }

    /// Swap the queue with `empty` (which keeps its capacity), so the
    /// drain owns what was queued without allocating.
    fn swap(&self, empty: &mut std::collections::VecDeque<Returned>) {
        std::mem::swap(
            &mut *self
                .queue
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            empty,
        );
    }
}

/// A [`FIXED_RECORD`]-sized page-aligned buffer from the pool, and the
/// table slot it is registered behind (`None`: slots spent or no table;
/// write by address). Derefs to [`AlignedBuf`].
///
/// Dropping it returns it to its pool, from any thread, slot and
/// licence included. One made by [`unpooled`](Fixed::unpooled) has no
/// pool and simply frees.
pub struct Fixed {
    inner: Option<Returned>,
    home: Option<crate::sync::Arc<Returns>>,
}

impl Fixed {
    /// A record with no pool and no slot, for a consumer serving off a
    /// ring. `None` if the allocator refuses.
    pub fn unpooled() -> Option<Fixed> {
        Some(Fixed {
            inner: Some(Returned {
                buf: AlignedBuf::new(FIXED_RECORD)?,
                slot: None,
                licence: 0,
            }),
            home: None,
        })
    }

    fn inner(&self) -> &Returned {
        self.inner.as_ref().expect("taken only by drop")
    }

    /// The slot the whole capacity is registered behind, if any.
    pub fn slot(&self) -> Option<u16> {
        self.inner().slot
    }
}

impl Drop for Fixed {
    fn drop(&mut self) {
        if let (Some(r), Some(home)) = (self.inner.take(), &self.home) {
            home.push(r);
        }
    }
}

impl std::ops::Deref for Fixed {
    type Target = AlignedBuf;
    fn deref(&self) -> &AlignedBuf {
        &self.inner().buf
    }
}

impl std::ops::DerefMut for Fixed {
    fn deref_mut(&mut self) -> &mut AlignedBuf {
        &mut self.inner.as_mut().expect("taken only by drop").buf
    }
}

impl AsRef<[u8]> for Fixed {
    fn as_ref(&self) -> &[u8] {
        self.inner().buf.as_ref()
    }
}

impl std::fmt::Debug for Fixed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let r = self.inner();
        f.debug_struct("Fixed")
            .field("slot", &r.slot)
            .field("len", &r.buf.len())
            .finish()
    }
}

/// The fixed inventory: a LIFO of records with their ages, and the free
/// slot indices of `[0, slots)`.
struct Records {
    free: Vec<(Returned, u8)>,
    free_slots: Vec<u16>,
}

impl Records {
    /// Slots `[0, slots)`, handed out lowest first.
    fn new(slots: u16) -> Records {
        Records {
            free: Vec::new(),
            free_slots: (0..slots).rev().collect(),
        }
    }
}

/// What the pool retains, by capacity: a `Vec` body or a record.
trait Retained {
    fn capacity(&self) -> usize;
    /// Empty it, keeping the allocation.
    fn clear(&mut self);
}

impl Retained for Vec<u8> {
    fn capacity(&self) -> usize {
        Vec::capacity(self)
    }
    fn clear(&mut self) {
        Vec::clear(self);
    }
}

impl Retained for Returned {
    fn capacity(&self) -> usize {
        AlignedBuf::capacity(&self.buf)
    }
    fn clear(&mut self) {
        AlignedBuf::clear(&mut self.buf);
    }
}

/// Which inventory a give is for, and so which pot licenses it.
#[derive(Clone, Copy)]
enum Kind {
    Vec,
    Fixed,
}

/// The best-fitting free entry for `min_cap` in one sorted inventory,
/// if serving it is not an over-provision ([`OVERSIZE_SERVE`]); its
/// capacity leaves `retained` with it, and the serve is counted as
/// heat. The one place a serve is counted.
fn take_fit_from<T: Retained>(
    free: &mut Vec<(T, u8)>,
    retained: &mut usize,
    served: &mut usize,
    min_cap: usize,
) -> Option<T> {
    // `free` is sorted by capacity, so the first entry covering the
    // ask is the best fit and *finding* it is a binary search — the
    // linear best-fit walk cost ~500 ns per claim once a storm had
    // diversified the list into hundreds of entries, against 7 ns
    // for the LIFO pop it replaced. Taking it is still O(n): the
    // `remove` below memmoves, as the sorted insert does, so the
    // pair is a win above ~100 entries and costs +18 to +27 ns per
    // body below it (n=8: 7.4→25.7 ns; n=32: 17.8→26.5; n=1024:
    // 459→318). Bucketing by `capacity().ilog2()` would be O(1) both
    // ways with best-fit-near-size and per-entry ageing intact; it is
    // not worth the shape yet at those absolutes.
    let i = free.partition_point(|(v, _)| v.capacity() < min_cap);
    let cap = free.get(i)?.0.capacity();
    if cap > min_cap.saturating_mul(OVERSIZE_SERVE).max(OVERSIZE_FLOOR) {
        return None;
    }
    // Among equal capacities take the newest (`keep_in` inserts after
    // equals). Taking the oldest rotated a same-size inventory so no
    // entry ever aged out.
    let j = free.partition_point(|(v, _)| v.capacity() <= cap) - 1;
    *retained = retained.saturating_sub(cap);
    *served = served.saturating_add(1);
    Some(free.remove(j).0)
}

/// Sorted insert into one inventory, keeping the binary-search
/// best-fit true and the shrink's pop pointed at the largest entry.
/// Age zero: a give is this buffer's demand proving itself.
fn keep_in<T: Retained>(free: &mut Vec<(T, u8)>, mut v: T) {
    v.clear();
    let cap = v.capacity();
    let at = free.partition_point(|(w, _)| w.capacity() <= cap);
    free.insert(at, (v, 0));
}

/// Age one inventory by a hot observation; returns the entries that
/// served nothing for [`SHRINK_AFTER`] of them, for the caller to
/// account and release.
fn age<T: Retained>(free: &mut Vec<(T, u8)>) -> Vec<T> {
    free.extract_if(.., |(_, age)| {
        *age = age.saturating_add(1);
        *age >= SHRINK_AFTER
    })
    .map(|(v, _)| v)
    .collect()
}

/// Consecutive quiet observations before the pool gives storage up —
/// [`BufPool`](crate::uring::bufring)'s constant, for the same reason: a
/// pool that shrinks on the first quiet moment spends its life
/// allocating and freeing across a workload that merely pauses.
const SHRINK_AFTER: u8 = 4;

/// How many times the ask a served buffer may exceed, floored at
/// [`OVERSIZE_FLOOR`]: past it the claim is treated as unmet and
/// allocates right-sized, diversifying the inventory instead of
/// carrying every small body in the high-water allocation.
///
/// Measured at **8x capacity** over-provision (384 KiB bodies carried
/// in a 3 MiB buffer, from a mixed-size ledger on the real path where
/// 4480 KiB = 384 + 1024 + 3072 accounted for every allocation), and
/// 16x possible at the shipped defaults. The cost in *resident* bytes
/// was measured separately and is not the same number: one 4 MiB body
/// raises a ring's steady-state RSS by 4.0 MB and pins it at the
/// high-water mark for a workload whose live demand never exceeds
/// 300 KiB, where the identical stream without it sees resident fall
/// 1.5 MB - a 13.65x capacity ratio, by `VmRSS`/`VmHWM` against a
/// control server sharing the process baseline.
///
/// `Vec::capacity()` is an upper bound on resident pages, not a
/// measurement of them; the two are named apart here because they
/// were taken by different instruments.
const OVERSIZE_SERVE: usize = 4;

/// Below this, over-provision is noise: refusing a 256 KiB buffer to a
/// 4 KiB ask would shed warm reuse to save kilobytes.
const OVERSIZE_FLOOR: usize = 64 * 1024;

/// The share of the budget one kind (`Vec` bodies or records) can win
/// back from the other: a licensed give that finds the budget full
/// evicts the other kind's coldest entries down to
/// `budget - budget / KIND_FLOOR`. Without it a storm of small bodies
/// held the budget outright and every staged record was allocated,
/// registered, refused on return, cleared and freed.
const KIND_FLOOR: usize = 4;

/// Ring-owned storage for bodies read outside a pool buffer.
pub(crate) struct BodyPool {
    /// Cleared, capacity-bearing Vecs awaiting reuse, sorted ascending
    /// by capacity — the sort makes best-fit a binary search — each
    /// beside the count of hot observations it sat through unserved.
    /// Under load a buffer earns its keep: one that serves nothing
    /// for [`SHRINK_AFTER`] hot windows is evicted at the rebalance,
    /// licence and all, so a shifted workload reclaims the high-water
    /// storage the old one warmed instead of shielding it with the
    /// pool's own heat. A serve resets the clock by construction (the
    /// buffer leaves the list and comes home at age zero); whole-pool
    /// quiet never ages entries, because the halving path owns that
    /// regime and a workload that merely pauses keeps its warm pool.
    free: Vec<(Vec<u8>, u8)>,
    /// The fixed inventory, aged as `free` is; its bytes count in
    /// `retained` with the rest.
    records: Records,
    /// The ring's fixed-buffer table, if it has one.
    table: Option<FixedTable>,
    /// Where a dropped [`Fixed`] lands; drained by
    /// [`drain_returns`](BodyPool::drain_returns).
    returns: crate::sync::Arc<Returns>,
    /// The drain's scratch queue, swapped with `returns`.
    spare: std::collections::VecDeque<Returned>,
    /// Total capacity retained in every inventory, in bytes — the figure
    /// every bound below is about.
    retained: usize,
    /// The most bytes `free` may retain right now. Raised by licensed
    /// demand, halved by quiet, never above `budget`.
    target: usize,
    /// The hard ceiling on `target`, set at construction: whatever a
    /// storm proves, retained storage never passes this.
    budget: usize,
    /// Bytes of demand that found nothing fitting, recorded by
    /// consumer claims at the claim and by reactor claims when their
    /// body leaves custody ([`BodyPool::receipt_done`]). Licenses
    /// target growth as storage comes home; reset every observation
    /// window, so a storm long gone cannot license a later one — the
    /// storage on this pot's clock is consumer-held, and nothing
    /// guarantees it ever returns. Capped at `budget`, which is the
    /// most it could ever license anyway.
    missed_bytes: usize,

    /// Pool-served claims since the last rebalance — the quiet
    /// detector. Serves, not claims: a claim the inventory cannot
    /// serve is evidence the retained bytes are *not* the working
    /// set, and heat read off claims let a stranded inventory (71% of
    /// the budget held with 0.65% of it servable, measured) survive
    /// the shrink for as long as any traffic flowed.
    served: usize,
    /// Consecutive rebalances that observed no serve.
    idle_rounds: u8,
}

impl BodyPool {
    /// A pool with no fixed-buffer table, for tests.
    #[cfg(all(test, not(loom)))]
    pub(crate) fn new(budget: usize) -> BodyPool {
        BodyPool::with_table(budget, None)
    }

    /// A pool registering records into every slot of `table`; a record
    /// past them serves unregistered.
    pub(crate) fn with_table(
        budget: usize,
        table: Option<FixedTable>,
    ) -> BodyPool {
        let slots = table
            .as_ref()
            .map_or(0, |t| u16::try_from(t.slots()).unwrap_or(u16::MAX));
        BodyPool {
            free: Vec::new(),
            records: Records::new(slots),
            table,
            returns: crate::sync::Arc::new(Returns::new()),
            spare: std::collections::VecDeque::new(),
            retained: 0,
            target: 0,
            budget,
            missed_bytes: 0,
            served: 0,
            idle_rounds: 0,
        }
    }

    /// Free a record: slot cleared and returned before the storage goes.
    fn release(&mut self, r: Returned) {
        let Returned { buf, slot, .. } = r;
        if let (Some(slot), Some(table)) = (slot, &self.table) {
            // A failed clear leaves the slot pinned until the ring dies;
            // it is not handed out again.
            if table.clear(slot).is_ok() {
                self.records.free_slots.push(slot);
            }
        }
        drop(buf);
    }

    /// Forget the table before the ring closes: retained records lose
    /// their slots, no install or clear is issued again, and a record
    /// still in flight comes home slotless. The ring's close unpins
    /// everything.
    pub(crate) fn detach_table(&mut self) {
        self.table = None;
        self.records.free_slots.clear();
        for (r, _) in self.records.free.iter_mut() {
            r.slot = None;
        }
    }

    /// The best-fitting free Vec for `min_cap` ([`take_fit_from`]).
    fn take_fit(&mut self, min_cap: usize) -> Option<Vec<u8>> {
        take_fit_from(
            &mut self.free,
            &mut self.retained,
            &mut self.served,
            min_cap,
        )
    }

    /// Storage for a body of at least `min_cap` bytes, consumer form: a
    /// fitting reused Vec where one waits, a fresh allocation — and
    /// `min_cap` recorded on the windowed pot — where none does. The
    /// returned Vec is empty; its capacity covers `min_cap`.
    pub(crate) fn claim(&mut self, min_cap: usize) -> Vec<u8> {
        let (v, licence) = self.claim_held(min_cap);
        self.missed_bytes =
            self.missed_bytes.saturating_add(licence).min(self.budget);
        v
    }

    /// [`claim`](BodyPool::claim) for a claimant whose storage resolves
    /// deterministically — the reactor's placed and promoted bodies.
    /// The miss, if any, comes back as a *held licence* the caller
    /// carries beside the storage and returns through
    /// [`give_held`](BodyPool::give_held) or
    /// [`receipt_done`](BodyPool::receipt_done); held licences do not
    /// expire with the observation window, so a receipt spanning
    /// maintenance ticks still licenses what it used.
    pub(crate) fn claim_held(&mut self, min_cap: usize) -> (Vec<u8>, usize) {
        match self.take_fit(min_cap) {
            Some(mut v) => {
                debug_assert!(v.is_empty(), "a pooled body kept bytes");
                v.reserve_exact(min_cap);
                (v, 0)
            }
            None => (Vec::with_capacity(min_cap), min_cap),
        }
    }

    /// A held claim's body is leaving reactor custody (delivered to
    /// the handler): its licence moves to the windowed pot, where the
    /// consumer's optional recycle can spend it before the window
    /// closes. Called **before** the handler runs, because the common
    /// recycle is synchronous, inside the handler - a licence potted
    /// after it landed one step behind the give it existed to cover,
    /// and the placed-body path never retained anything.
    pub(crate) fn receipt_done(&mut self, licence: usize) {
        self.missed_bytes =
            self.missed_bytes.saturating_add(licence).min(self.budget);
    }

    /// Whether `cap` bytes coming home may be retained, and the
    /// accounting if so: within the byte target — which outstanding
    /// missed bytes may first raise toward it, up to the budget — it
    /// is retained and counted; otherwise the caller frees it on the
    /// spot. The one admission rule, for both inventories.
    fn admit(&mut self, kind: Kind, cap: usize, licence: usize) -> bool {
        let budget = self.budget;
        // A `Vec` give's licence joins the windowed pot; a record's is
        // held and is its own pot. Taken by value: `make_room` needs
        // `&mut self`.
        let mut pot = match kind {
            Kind::Vec => self.missed_bytes,
            Kind::Fixed => 0,
        };
        pot = pot.saturating_add(licence).min(budget);
        let admitted = 'rule: {
            if cap == 0 {
                break 'rule false;
            }
            // A licensed give at a full budget takes room from the
            // other kind, down to its ceiling ([`KIND_FLOOR`]).
            if self.retained.saturating_add(cap) > budget && pot >= cap {
                self.make_room(kind, cap);
            }
            let held = self.retained.saturating_add(cap);
            if held > self.target {
                // Demand proved bytes of this order were needed while
                // nothing fitting waited; retaining toward it is what a
                // working set means — and no further than the missed
                // bytes, so one giant give cannot ride a small licence.
                // The grant is decided before it is spent: a give the
                // pot cannot cover — or one over the budget outright —
                // frees with the pot intact, where spending first
                // drained the licence into a target no storage backed
                // and the next unlicensed give rode demand that was
                // never granted it.
                let grant = (held - self.target).min(pot);
                if held > budget || self.target + grant < held {
                    break 'rule false; // freed; nothing is spent on it
                }
                self.target += grant;
                pot -= grant;
            }
            self.retained = held;
            true
        };
        if let Kind::Vec = kind {
            self.missed_bytes = pot;
        }
        admitted
    }

    /// Bytes one kind retains: the `Vec` list, or the records.
    fn kind_retained(&self, kind: Kind) -> usize {
        // Records are one size, so their bytes are a count.
        let fixed = self.records.free.len() * FIXED_RECORD;
        match kind {
            Kind::Vec => self.retained.saturating_sub(fixed),
            Kind::Fixed => fixed,
        }
    }

    /// Evict the other kind's coldest entries, licence and all, until
    /// `cap` fits or that kind is down to `budget - budget / KIND_FLOOR`.
    fn make_room(&mut self, kind: Kind, cap: usize) {
        let ceiling = self.budget - self.budget / KIND_FLOOR;
        let other = match kind {
            Kind::Vec => Kind::Fixed,
            Kind::Fixed => Kind::Vec,
        };
        let mut other_retained = self.kind_retained(other);
        // Evict only when reaching the ceiling makes enough room; an
        // eviction that still ends in a refusal is churn.
        let shortfall = self.retained.saturating_add(cap) - self.budget;
        if other_retained.saturating_sub(ceiling) < shortfall {
            return;
        }
        while self.retained.saturating_add(cap) > self.budget
            && other_retained > ceiling
        {
            let evicted = match other {
                // Oldest first, then largest.
                Kind::Vec => {
                    let Some(i) = (0..self.free.len()).max_by_key(|&i| {
                        (self.free[i].1, self.free[i].0.capacity())
                    }) else {
                        break;
                    };
                    self.free.remove(i).0.capacity()
                }
                // The bottom of the records' LIFO is its coldest entry.
                Kind::Fixed => {
                    if self.records.free.is_empty() {
                        break;
                    }
                    let (r, _) = self.records.free.remove(0);
                    let c = r.capacity();
                    self.release(r);
                    c
                }
            };
            other_retained = other_retained.saturating_sub(evicted);
            self.retained = self.retained.saturating_sub(evicted);
            self.target = self.target.saturating_sub(evicted);
        }
    }

    /// Hand storage home with the held licence its claim recorded (0
    /// for a pool-served claim). Cleared here so a claim never sees
    /// stale bytes; retained only within the byte target — which
    /// outstanding missed bytes may first raise toward it, up to the
    /// budget — and freed on the spot otherwise.
    pub(crate) fn give_held(&mut self, v: Vec<u8>, licence: usize) {
        if self.admit(Kind::Vec, v.capacity(), licence) {
            keep_in(&mut self.free, v);
        }
    }

    /// Hand storage home, consumer form: no held licence, so retention
    /// rides whatever the windowed pot holds.
    pub(crate) fn give(&mut self, v: Vec<u8>) {
        self.give_held(v, 0);
    }

    /// Admit or release every record dropped since the last drain. On
    /// the ring only.
    pub(crate) fn drain_returns(&mut self) {
        let mut q = std::mem::take(&mut self.spare);
        self.returns.swap(&mut q);
        for r in q.drain(..) {
            if self.admit(Kind::Fixed, r.capacity(), r.licence) {
                keep_in(&mut self.records.free, r);
            } else {
                self.release(r);
            }
        }
        self.spare = q;
    }

    /// A record: the most recently returned one, else a fresh allocation
    /// registered behind a free slot and carrying its miss as a held
    /// licence. Empty; returns to this pool on drop. `None` if the
    /// allocator refuses.
    pub(crate) fn claim_fixed(&mut self) -> Option<Fixed> {
        self.drain_returns();
        let home = Some(crate::sync::Arc::clone(&self.returns));
        if let Some((mut r, _age)) = self.records.free.pop() {
            let cap = r.capacity();
            self.retained = self.retained.saturating_sub(cap);
            self.served = self.served.saturating_add(1);
            debug_assert!(r.buf.is_empty(), "a kept record holds bytes");
            r.licence = 0;
            // A record born without a slot is registered once one is
            // free, or a working set left over from a connection-count
            // excursion would stay unregistered for as long as it
            // cycled.
            if r.slot.is_none() {
                r.slot = self.install(&r.buf);
            }
            return Some(Fixed {
                inner: Some(r),
                home,
            });
        }
        let buf = AlignedBuf::new(FIXED_RECORD)?;
        let licence = buf.capacity();
        let slot = self.install(&buf);
        Some(Fixed {
            inner: Some(Returned { buf, slot, licence }),
            home,
        })
    }

    /// Register `buf` behind a free slot, if there is a table and a slot;
    /// a refused install returns the slot and the record goes by address.
    fn install(&mut self, buf: &AlignedBuf) -> Option<u16> {
        let table = self.table.as_ref()?;
        let slot = self.records.free_slots.pop()?;
        match table.install(slot, buf) {
            Ok(()) => Some(slot),
            Err(_) => {
                self.records.free_slots.push(slot);
                None
            }
        }
    }

    /// The timer's observation: quiet long enough halves the target and
    /// frees the surplus now — no traffic is needed to hand anything
    /// back. The windowed pot does not survive the observation — a
    /// storm long gone cannot inflate the pool a later one holds — but
    /// held licences do: they ride the reactor claims that recorded
    /// them, whose resolution is deterministic.
    ///
    /// **Its cost scales with the entry count, and the entry count is
    /// bounded in bytes, not in entries** (deliberately — see the
    /// pool's construction in `net::server`). The ceiling is `budget /
    /// smallest retained capacity`, so an [`OVERSIZE_FLOOR`]-sized
    /// inventory reaches ~1024 entries at the default budget and one
    /// of 4 KiB bodies — [`BodyRecycler::claim`] is public and takes
    /// any `min_cap` — reaches 16x that.
    ///
    /// The walk itself is cheap; the eviction is a `free()` per entry
    /// it drops, inline on the reactor thread. Measured here, release,
    /// best of seven, 64 MiB of budget spread over `n` touched entries,
    /// non-evicting against whole-inventory-evicting:
    ///
    /// | n | entry | quiet walk | evicting |
    /// |---|---|---|---|
    /// | 21 | 3.0 MiB | 0.1 µs | 2.7 µs |
    /// | 1024 | 64 KiB | 4.1 µs | 219 µs |
    /// | 4096 | 16 KiB | 16.2 µs | 845 µs |
    /// | 16384 | 4 KiB | 65.8 µs | 3.2 ms |
    ///
    /// Big entries are mmap-backed and unmap in one call each, which is
    /// why the *largest* inventory by bytes is the cheapest to evict
    /// and a diversified small-body one is not. Once per 5 s tick, and
    /// it is deallocation the pool owes either way — but at the top of
    /// that table it is a reactor stall, which is the cost of leaving
    /// the entry count unbounded.
    pub(crate) fn rebalance(&mut self) {
        self.drain_returns();
        self.missed_bytes = 0;
        if self.served > 0 {
            self.served = 0;
            self.idle_rounds = 0;
            // Under load, each buffer earns its keep: the heat is the
            // pool's, not any one entry's, and read whole it shielded
            // exactly the stranded high-water buffers a shifted
            // workload left behind. An entry unserved for
            // `SHRINK_AFTER` hot observations is evicted, and its
            // licence dies with it - `target` follows `retained`
            // down, so a later unlicensed give cannot ride demand
            // that left with the buffer. The loan gap is untouched:
            // claimed-out capacity sits in neither figure.
            let mut evicted: usize =
                age(&mut self.free).iter().map(Vec::capacity).sum();
            for r in age(&mut self.records.free) {
                evicted += r.capacity();
                self.release(r);
            }
            self.retained = self.retained.saturating_sub(evicted);
            self.target = self.target.saturating_sub(evicted);
            return;
        }
        self.idle_rounds = self.idle_rounds.saturating_add(1);
        if self.idle_rounds < SHRINK_AFTER {
            return;
        }
        self.idle_rounds = 0;
        self.target /= 2;
        while self.retained > self.target {
            // Largest entry of either inventory first.
            let vec_cap = self.free.last().map_or(0, |(v, _)| v.capacity());
            let rec_cap =
                self.records.free.last().map_or(0, |(b, _)| b.capacity());
            let popped = if rec_cap >= vec_cap {
                self.records.free.pop().map(|(b, _)| {
                    let cap = b.capacity();
                    self.release(b);
                    cap
                })
            } else {
                self.free.pop().map(|(v, _)| v.capacity())
            };
            // Structural, not arithmetic: a `None` here means the
            // figure and the lists disagree, and subtracting nothing
            // would spin this loop on the reactor thread.
            let Some(cap) = popped else {
                debug_assert!(false, "retained bytes with no free entry");
                self.retained = 0;
                break;
            };
            self.retained = self.retained.saturating_sub(cap);
        }
    }

    #[cfg(all(test, not(loom)))]
    fn retained(&self) -> usize {
        self.retained
    }

    #[cfg(all(test, not(loom)))]
    fn target(&self) -> usize {
        self.target
    }
}

/// The consumer's end of the loop: hand a delivered body's storage back
/// to the ring it was read on.
///
/// Single-threaded by construction — the pool belongs to one ring and
/// this handle is `!Send`, so it cannot leave the ring thread that built
/// the server. Calling it from anywhere else is a compile error, not a
/// race.
#[derive(Clone)]
pub struct BodyRecycler {
    pool: Rc<RefCell<BodyPool>>,
}

impl BodyRecycler {
    pub(crate) fn new(pool: Rc<RefCell<BodyPool>>) -> BodyRecycler {
        BodyRecycler { pool }
    }

    /// Return a body's storage for reuse. The Vec's bytes are dead the
    /// moment this is called; the pool clears them before reissue.
    pub fn recycle(&self, body: Vec<u8>) {
        self.pool.borrow_mut().give(body);
    }

    /// Draw storage of at least `min_cap` bytes from the pool — a reused
    /// buffer where one waits, a fresh allocation otherwise. For a
    /// consumer that accumulates a body itself (a server buffering an
    /// operation it does not stream) rather than receiving one placed:
    /// claiming here means that accumulator cycles the same storage the
    /// placement path does, instead of minting its own per message.
    pub fn claim(&self, min_cap: usize) -> Vec<u8> {
        self.pool.borrow_mut().claim(min_cap)
    }

    /// A [`FIXED_RECORD`] from the pool, registered behind a table slot
    /// where the ring has one ([`Fixed::slot`]). Retained under the same
    /// budget as [`claim`](BodyRecycler::claim). Dropping it returns it.
    /// `None` if the allocator refuses.
    pub fn claim_fixed(&self) -> Option<Fixed> {
        self.pool.borrow_mut().claim_fixed()
    }
}

impl std::fmt::Debug for BodyRecycler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let p = self.pool.borrow();
        f.debug_struct("BodyRecycler")
            .field("retained", &p.retained)
            .field("target", &p.target)
            .field("budget", &p.budget)
            .finish()
    }
}

/// The `__fuzz` seam (`net::server::fuzz`) for the `bodypool_ops`
/// target: a tableless pool with its accounting checkable. Not API.
#[cfg(feature = "__fuzz")]
pub mod fuzz {
    use super::{BodyPool, Fixed, Kind, SHRINK_AFTER};

    /// A tableless pool with its bookkeeping inspectable.
    pub struct Pool(BodyPool);

    impl std::fmt::Debug for Pool {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("Pool")
                .field("retained", &self.0.retained)
                .field("target", &self.0.target)
                .field("budget", &self.0.budget)
                .finish()
        }
    }

    impl Pool {
        /// A pool retaining at most `budget` bytes.
        pub fn new(budget: usize) -> Pool {
            Pool(BodyPool::with_table(budget, None))
        }

        /// `BodyPool::claim`: a consumer claim on the windowed pot.
        pub fn claim(&mut self, min_cap: usize) -> Vec<u8> {
            self.0.claim(min_cap)
        }

        /// `BodyPool::give`: a consumer give, unlicensed.
        pub fn give(&mut self, v: Vec<u8>) {
            self.0.give(v);
        }

        /// `BodyPool::claim_held`: a reactor claim with its licence.
        pub fn claim_held(&mut self, min_cap: usize) -> (Vec<u8>, usize) {
            self.0.claim_held(min_cap)
        }

        /// `BodyPool::give_held`: the reactor's give with the licence.
        pub fn give_held(&mut self, v: Vec<u8>, licence: usize) {
            self.0.give_held(v, licence);
        }

        /// `BodyPool::receipt_done`: a held licence moves to the pot.
        pub fn receipt_done(&mut self, licence: usize) {
            self.0.receipt_done(licence);
        }

        /// `BodyPool::claim_fixed`: a record.
        pub fn claim_fixed(&mut self) -> Option<Fixed> {
            self.0.claim_fixed()
        }

        /// `BodyPool::drain_returns`: bring dropped fixed buffers home.
        pub fn drain_returns(&mut self) {
            self.0.drain_returns();
        }

        /// `BodyPool::rebalance`: the maintenance tick.
        pub fn rebalance(&mut self) {
            self.0.rebalance();
        }

        /// Retained bytes as the pool counts them.
        pub fn retained(&self) -> usize {
            self.0.retained
        }

        /// The byte law against the lists: `retained` is the lists' sum,
        /// `retained <= target <= budget`, pot under budget, no slots on
        /// a tableless pool, quiet counter under threshold, kept buffers
        /// empty, `Vec` list sorted.
        pub fn check(&self) {
            let p = &self.0;
            let vec = p.kind_retained(Kind::Vec);
            let fixed = p.kind_retained(Kind::Fixed);
            assert_eq!(p.retained, vec + fixed, "retained is not the lists");
            assert!(
                p.retained <= p.target,
                "retained {} > target {}",
                p.retained,
                p.target
            );
            assert!(
                p.target <= p.budget,
                "target {} > budget {}",
                p.target,
                p.budget
            );
            assert!(p.missed_bytes <= p.budget, "pot over the budget");
            assert!(
                p.idle_rounds < SHRINK_AFTER,
                "quiet counter ran past its threshold"
            );
            assert!(p.records.free_slots.is_empty());
            assert!(
                p.free.iter().all(|(v, _)| v.is_empty()),
                "a kept Vec holds bytes"
            );
            for (r, _) in p.records.free.iter() {
                assert!(r.slot.is_none(), "a slot on a tableless pool");
                assert!(r.buf.is_empty(), "a kept record holds bytes");
            }
            assert!(
                p.free
                    .windows(2)
                    .all(|w| w[0].0.capacity() <= w[1].0.capacity()),
                "the Vec list is not sorted by capacity"
            );
        }
    }
}

#[cfg(all(test, not(loom)))]
mod tests {
    use super::*;

    const MIB: usize = 1024 * 1024;

    /// A ring for the table tests, or `None` where the host has no
    /// io_uring; any other refusal panics.
    fn ring() -> Option<crate::uring::ring::RingFd> {
        if cfg!(miri) {
            return None;
        }
        match crate::uring::ring::RingFd::setup(8) {
            Ok(r) => Some(r),
            Err(e) if crate::uring::setup_unavailable(e) => None,
            Err(e) => panic!("io_uring_setup: {e}"),
        }
    }

    /// A table of `slots` on `ring`, or `None` to skip without
    /// `CAP_IPC_LOCK` (installs would be charged to `RLIMIT_MEMLOCK`);
    /// `TRUENAS_ROS_REQUIRE_ROOT` makes the skip a failure.
    fn table_on(
        ring: &crate::uring::ring::RingFd,
        slots: u32,
    ) -> Option<FixedTable> {
        if !crate::uring::fixed::ipc_lock_held() {
            assert!(
                std::env::var_os("TRUENAS_ROS_REQUIRE_ROOT").is_none(),
                "TRUENAS_ROS_REQUIRE_ROOT is set but CAP_IPC_LOCK is not held"
            );
            return None;
        }
        Some(FixedTable::register(ring.raw_fd(), slots).expect("registers"))
    }

    /// A storm reuses one allocation instead of minting per message.
    #[test]
    fn a_cycled_body_reuses_its_storage() {
        let mut p = BodyPool::new(64 * MIB);
        let a = p.claim(MIB);
        let ptr = a.as_ptr() as usize;
        p.give(a);
        assert_eq!(p.retained(), MIB);
        let b = p.claim(MIB);
        assert_eq!(b.as_ptr() as usize, ptr, "the warm Vec cycles");
        assert_eq!(p.retained(), 0, "claimed storage is out, not retained");
    }

    /// Misses license retention of what demand actually used — measured
    /// in bytes — and an unlicensed give past the target frees instead.
    #[test]
    fn misses_grow_retention_to_the_working_set_in_bytes() {
        let mut p = BodyPool::new(64 * MIB);
        let (a, b, c) = (p.claim(MIB), p.claim(MIB), p.claim(MIB));
        p.give(a);
        p.give(b);
        p.give(c);
        assert_eq!(p.retained(), 3 * MIB, "three misses, three bodies kept");
        assert_eq!(p.target(), 3 * MIB);
        // A fourth give with no outstanding miss is surplus and frees.
        let mut extra = Vec::new();
        extra.reserve_exact(MIB);
        p.give(extra);
        assert_eq!(p.retained(), 3 * MIB);
    }

    /// The budget caps the target however large demand runs: bodies over
    /// it cycle through the allocator, never through the pool.
    #[test]
    fn the_budget_is_a_hard_byte_ceiling() {
        let mut p = BodyPool::new(2 * MIB);
        let (a, b) = (p.claim(MIB), p.claim(MIB));
        let big = p.claim(8 * MIB); // over budget on its own
        p.give(big);
        assert_eq!(p.retained(), 0, "an over-budget body is never retained");
        p.give(a);
        p.give(b);
        assert_eq!(p.retained(), 2 * MIB);
        assert_eq!(p.target(), 2 * MIB, "the target stops at the budget");
        let c = p.claim(MIB);
        p.give(c);
        let mut d = Vec::new();
        d.reserve_exact(MIB);
        p.give(d);
        assert!(p.retained() <= 2 * MIB, "the budget holds under churn");
    }

    /// Quiet halves the retained bytes and frees them now; one served
    /// claim resets the count.
    #[test]
    fn quiet_shrinks_bytes_with_hysteresis_and_traffic_resets_it() {
        let mut p = BodyPool::new(64 * MIB);
        let bodies: Vec<_> = (0..4).map(|_| p.claim(MIB)).collect();
        for v in bodies {
            p.give(v);
        }
        assert_eq!(p.retained(), 4 * MIB);
        // A served claim is heat: the first observation clears it.
        let v = p.claim(MIB);
        p.give(v);
        p.rebalance();
        for _ in 0..SHRINK_AFTER - 1 {
            p.rebalance();
        }
        assert_eq!(p.retained(), 4 * MIB, "hysteresis holds through quiet");
        p.rebalance();
        assert_eq!(p.target(), 2 * MIB, "quiet halves the byte target");
        assert!(p.retained() <= 2 * MIB, "and the surplus is freed now");
        let v = p.claim(MIB);
        p.give(v);
        p.rebalance();
        assert!(p.retained() >= MIB, "a served claim resets the quiet count");
    }

    /// Retained storage that serves nothing is not a working set:
    /// claims the inventory cannot serve are misses, not heat, so the
    /// shrink still fires under load and a shifted workload reclaims
    /// what the old one warmed. Heat read off claims let high-water
    /// buffers pin themselves at the budget for as long as any traffic
    /// flowed, with the only release path ~20 s of ring-wide silence.
    #[test]
    fn unservable_traffic_does_not_pin_retention() {
        let mut p = BodyPool::new(64 * MIB);
        // Concurrent, so each claim misses and licenses its own bytes.
        let claims: Vec<_> = (0..3).map(|_| p.claim_held(5 * MIB)).collect();
        for (v, licence) in claims {
            p.give_held(v, licence);
        }
        assert_eq!(p.retained(), 15 * MIB, "the storm's working set kept");
        // The workload shifts: every claim is refused as over-provision
        // (5 MiB is past 4x 300 KiB), allocates fresh, and never comes
        // home — traffic, but not one serve.
        for _ in 0..SHRINK_AFTER {
            for _ in 0..4 {
                drop(p.claim_held(300 * 1024));
            }
            p.rebalance();
        }
        assert!(
            p.retained() < 15 * MIB,
            "an inventory serving nothing must decay under load: {}",
            p.retained()
        );
    }

    /// A held licence rides its claim, not the observation window: a
    /// body that takes longer than a maintenance tick to arrive still
    /// licenses retaining its storage when it comes home - the
    /// windowed form went inert for exactly the slow-link uploads the
    /// pool exists for, measured at three fresh allocations for three
    /// 7-second bodies with `target` never leaving zero.
    #[test]
    fn a_held_licence_survives_the_observation_window() {
        let mut p = BodyPool::new(64 * MIB);
        let (v, licence) = p.claim_held(MIB);
        assert_eq!(licence, MIB, "a dry pool records the bytes needed");
        p.rebalance(); // a tick passes mid-receipt
        p.rebalance(); // and another
        p.give_held(v, licence);
        assert_eq!(p.retained(), MIB, "the slow body still licenses itself");
        let (w, licence) = p.claim_held(MIB);
        assert_eq!(licence, 0, "and the next receipt is a pool hit");
        p.give_held(w, 0);
    }

    /// A delivered body's licence moves to the windowed pot at
    /// delivery, so the consumer's recycle window opens then - not at
    /// the arm, however long the receipt took.
    #[test]
    fn a_delivered_body_recycles_on_the_deliverys_clock() {
        let mut p = BodyPool::new(64 * MIB);
        let (v, licence) = p.claim_held(MIB);
        p.rebalance(); // the receipt spans a tick
        p.receipt_done(licence); // delivery: the body leaves custody
        drop(v); // the handler owns it now; it comes back via recycle
        let mut recycled = Vec::new();
        recycled.reserve_exact(MIB);
        p.give(recycled);
        assert_eq!(p.retained(), MIB, "recycled within the delivery window");
    }

    /// The licence is sized in bytes, so a sizeless claim licenses
    /// nothing and a giant give cannot ride a small one: `claim(0)` +
    /// `give(64 MiB)` used to set a 64 MiB target off a zero-byte miss.
    #[test]
    fn a_licence_is_bytes_not_a_count() {
        let mut p = BodyPool::new(64 * MIB);
        drop(p.claim(0));
        let mut giant = Vec::new();
        giant.reserve_exact(8 * MIB);
        p.give(giant);
        assert_eq!(p.retained(), 0, "a zero-byte miss licenses nothing");
        assert_eq!(p.target(), 0);
        // A small miss cannot license a giant either: the pot cannot
        // cover it, so the giant frees and the licence is not spent.
        drop(p.claim(64 * 1024));
        let mut giant = Vec::new();
        giant.reserve_exact(8 * MIB);
        p.give(giant);
        assert_eq!(p.retained(), 0, "the giant is freed, not retained");
        assert_eq!(p.target(), 0, "and spends no licence being freed");
    }

    /// The grant is decided before it is spent: storage the pool frees
    /// anyway must not drain the pot, or the target rises above what
    /// is retained and the licence is gone for the give it could have
    /// covered. Spending first burned a 64 KiB licence on an 8 MiB
    /// give that freed regardless, and left the quiet walk-down nine
    /// ticks instead of five.
    #[test]
    fn a_freed_give_spends_no_licence() {
        let mut p = BodyPool::new(64 * MIB);
        drop(p.claim(64 * 1024)); // a 64 KiB miss licenses the pot
        let mut giant = Vec::new();
        giant.reserve_exact(8 * MIB);
        p.give(giant); // freed: the pot cannot cover 8 MiB
        assert_eq!(p.retained(), 0);
        assert_eq!(p.target(), 0, "no licence is spent on freed storage");
        // The licence survives for the give it can cover.
        let mut fit = Vec::new();
        fit.reserve_exact(64 * 1024);
        p.give(fit);
        assert_eq!(p.retained(), 64 * 1024, "the pot still covers its size");
    }

    /// Under load, each retained buffer earns its keep: one that
    /// serves nothing for SHRINK_AFTER hot observations is evicted -
    /// with its licence, so the target follows - while the entries
    /// traffic actually cycles stay warm. Per entry, because
    /// whole-pool heat shields exactly the stranded high-water buffer
    /// a shifted workload leaves behind; whole-pool quiet still takes
    /// the halving path, so a pause is not an eviction.
    #[test]
    fn a_buffer_that_stops_serving_ages_out_under_load() {
        let mut p = BodyPool::new(64 * MIB);
        // Warm two classes concurrently: high-water and small.
        let big = p.claim_held(5 * MIB);
        let small = p.claim_held(300 * 1024);
        p.give_held(big.0, big.1);
        p.give_held(small.0, small.1);
        assert_eq!(p.retained(), 5 * MIB + 300 * 1024);
        // The workload shifts to the small class alone; every window
        // is hot with serves the big buffer never gets (a 300 KiB ask
        // refuses it as over-provision).
        for _ in 0..SHRINK_AFTER {
            let (v, licence) = p.claim_held(300 * 1024);
            assert_eq!(licence, 0, "the small class serves itself");
            p.give_held(v, 0);
            p.rebalance();
        }
        assert_eq!(
            p.retained(),
            300 * 1024,
            "the unserved high-water buffer ages out; the serving one stays"
        );
        assert_eq!(p.target(), 300 * 1024, "its licence died with it");
        let (v, licence) = p.claim_held(300 * 1024);
        assert_eq!(licence, 0, "and the survivor still serves");
        p.give_held(v, 0);
    }

    /// The free list is sorted by capacity, so a claim binary-searches
    /// to the smallest fitting buffer instead of walking a
    /// storm-diversified list entry by entry.
    #[test]
    fn a_claim_takes_the_smallest_fitting_buffer() {
        let mut p = BodyPool::new(64 * MIB);
        // Concurrent, so the inventory diversifies instead of one
        // buffer cycling through every claim.
        let claims: Vec<_> = [MIB, 3 * MIB, 2 * MIB]
            .into_iter()
            .map(|s| p.claim_held(s))
            .collect();
        for (v, licence) in claims {
            p.give_held(v, licence);
        }
        let (served, licence) = p.claim_held(MIB + MIB / 2);
        assert_eq!(licence, 0, "a fitting buffer waited");
        assert_eq!(served.capacity(), 2 * MIB, "and the best fit served");
        p.give_held(served, 0);
    }

    /// A body is served from storage near its size: the high-water
    /// buffer stays for bodies of its own order, and a much smaller
    /// claim allocates right-sized instead of faulting 8x its need -
    /// the "whole maximal buffers for storms of small ones" the module
    /// header rejects.
    #[test]
    fn a_small_body_is_not_served_from_the_high_water_buffer() {
        let mut p = BodyPool::new(64 * MIB);
        let (big, licence) = p.claim_held(3 * MIB);
        p.give_held(big, licence);
        assert_eq!(p.retained(), 3 * MIB, "the big body's storage waits");
        let (small, licence) = p.claim_held(300 * 1024);
        assert!(
            small.capacity() < MIB,
            "a 300 KiB body must not carry a 3 MiB allocation: {}",
            small.capacity()
        );
        assert_eq!(licence, 300 * 1024, "unmet at its own size, licensed");
        assert_eq!(p.retained(), 3 * MIB, "the big buffer stayed for its own");
        // Near its size, the big buffer does serve.
        let (served, licence) = p.claim_held(MIB);
        assert_eq!(served.capacity(), 3 * MIB, "a 1 MiB ask takes the 3 MiB");
        assert_eq!(licence, 0);
        p.give_held(served, 0);
        p.give_held(small, 300 * 1024);
    }

    /// A miss does not license retention across observation windows: a
    /// storm that ended cannot inflate what a later one holds.
    #[test]
    fn a_license_does_not_outlive_the_observation_window() {
        let mut p = BodyPool::new(64 * MIB);
        drop(p.claim(MIB)); // the consumer never recycled
        p.rebalance(); // the window closes; the license dies with it
        let mut late = Vec::new();
        late.reserve_exact(MIB);
        p.give(late);
        assert_eq!(p.retained(), 0, "no license, nothing retained");
        for _ in 0..SHRINK_AFTER + 1 {
            p.rebalance();
        }
        assert_eq!(p.target(), 0, "quiet walks an abandoned target down");
    }
    /// A record cycles like a body: one allocation, reused; the give
    /// is the drop.
    #[test]
    fn a_fixed_claim_cycles_its_storage() {
        let mut p = BodyPool::new(64 * MIB);
        let mut a = p.claim_fixed().expect("allocates");
        assert_eq!(a.capacity(), FIXED_RECORD);
        assert_eq!(a.slot(), None, "no table on this pool");
        let ptr = a.as_ref().as_ptr() as usize;
        assert_eq!(a.fill(&[7u8; 4096]), 4096);
        drop(a);
        assert_eq!(p.retained(), 0, "home, but not yet drained");
        p.drain_returns();
        assert_eq!(
            p.retained(),
            MIB,
            "drained: licensed by its own miss, kept"
        );
        let b = p.claim_fixed().expect("serves");
        assert_eq!(b.as_ref().as_ptr() as usize, ptr, "the warm buffer cycles");
        assert!(b.is_empty(), "cleared before reissue");
        assert_eq!(p.retained(), 0, "claimed storage is out, not retained");
    }

    /// A drop from another thread comes home too.
    #[test]
    fn a_fixed_buffer_dropped_off_ring_still_comes_home() {
        let mut p = BodyPool::new(64 * MIB);
        let a = p.claim_fixed().expect("allocates");
        std::thread::spawn(move || drop(a)).join().expect("joins");
        let b = p.claim_fixed().expect("serves after the drain");
        assert_eq!(p.retained(), 0);
        drop(b);
        p.drain_returns();
        assert_eq!(p.retained(), MIB);
    }

    /// An unpooled record frees on drop; nothing is retained.
    #[test]
    fn an_unpooled_buffer_just_frees() {
        let mut p = BodyPool::new(64 * MIB);
        let u = Fixed::unpooled().expect("allocates");
        assert_eq!(u.slot(), None);
        assert_eq!(u.capacity(), FIXED_RECORD);
        drop(u);
        p.drain_returns();
        assert_eq!(p.retained(), 0);
    }

    /// One budget caps both inventories together.
    #[test]
    fn fixed_and_vec_bytes_share_one_budget() {
        let mut p = BodyPool::new(2 * MIB);
        let a = p.claim_fixed().expect("allocates");
        let v = p.claim(MIB);
        let b = p.claim_fixed().expect("allocates");
        let mut w = Vec::new();
        w.reserve_exact(MIB);
        drop(a);
        p.drain_returns();
        p.give(v);
        assert_eq!(p.retained(), 2 * MIB, "both licensed, both kept");
        drop(b);
        p.drain_returns();
        assert_eq!(
            p.retained(),
            2 * MIB,
            "a third record is over the budget: freed"
        );
        p.give(w);
        assert_eq!(p.retained(), 2 * MIB, "a third body likewise");
        assert_eq!(p.target(), 2 * MIB, "and the target never passes it");
    }

    /// A record's licence survives a tick mid-flight; a consumer `Vec`'s
    /// windowed licence does not.
    #[test]
    fn a_fixed_licence_survives_the_observation_window() {
        let mut p = BodyPool::new(64 * MIB);
        for round in 0..3 {
            let buf = p.claim_fixed().expect("allocates");
            p.rebalance(); // the tick, mid-flight
            drop(buf);
            p.drain_returns();
            assert_eq!(p.retained(), MIB, "kept, round {round}");
        }
        let mut q = BodyPool::new(64 * MIB);
        let v = q.claim(MIB);
        q.rebalance();
        q.give(v);
        assert_eq!(
            q.retained(),
            0,
            "the windowed pot did not survive the tick"
        );
    }

    /// A record spends its own licence, never the `Vec` pot.
    #[test]
    fn a_records_give_does_not_spend_a_bodys_licence() {
        let mut p = BodyPool::new(64 * MIB);
        let v = p.claim(MIB); // 1 MiB on the Vec pot
        let a = p.claim_fixed().expect("allocates");
        drop(a);
        p.drain_returns();
        assert_eq!(p.retained(), MIB, "the record is licensed by its own miss");
        p.give(v);
        assert_eq!(
            p.retained(),
            2 * MIB,
            "and the body by its own, still unspent"
        );
        assert_eq!(p.target(), 2 * MIB);
    }

    /// A waiting `Vec` never serves a fixed ask, nor a record a body's.
    #[test]
    fn the_kinds_never_serve_each_other() {
        let mut p = BodyPool::new(64 * MIB);
        let v = p.claim(MIB);
        p.give(v);
        assert_eq!(p.retained(), MIB);
        let a = p.claim_fixed().expect("allocates rather than serves");
        assert_eq!(p.retained(), MIB, "the Vec stayed put");
        drop(a);
        p.drain_returns();
        assert_eq!(p.retained(), 2 * MIB, "and the record's miss licensed it");
        let b = p.claim(MIB);
        assert_eq!(p.retained(), MIB, "the Vec served; the record stayed put");
        p.give(b);
    }

    /// Quiet halves the shared target, largest entry first.
    #[test]
    fn quiet_frees_the_largest_entry_of_any_inventory() {
        let mut p = BodyPool::new(64 * MIB);
        let a = p.claim_fixed().expect("allocates");
        let v = p.claim(512 * 1024);
        drop(a);
        p.drain_returns();
        p.give(v);
        let all = MIB + 512 * 1024;
        assert_eq!(p.retained(), all);
        for _ in 0..SHRINK_AFTER {
            p.rebalance();
        }
        assert_eq!(p.target(), all / 2, "quiet halves the byte target");
        assert_eq!(
            p.retained(),
            512 * 1024,
            "the 1 MiB record went first; the body stays"
        );
    }

    /// An unserved record ages out under load, licence and all.
    #[test]
    fn a_fixed_entry_ages_out_under_load() {
        let mut p = BodyPool::new(64 * MIB);
        let a = p.claim_fixed().expect("allocates");
        let small = p.claim_held(300 * 1024);
        drop(a);
        p.drain_returns();
        p.give_held(small.0, small.1);
        assert_eq!(p.retained(), MIB + 300 * 1024);
        for _ in 0..SHRINK_AFTER {
            let (v, licence) = p.claim_held(300 * 1024);
            assert_eq!(licence, 0, "the body class serves itself");
            p.give_held(v, 0);
            p.rebalance();
        }
        assert_eq!(p.retained(), 300 * 1024, "the unserved record ages out");
        assert_eq!(p.target(), 300 * 1024, "its licence died with it");
    }

    /// Slots are assigned at allocation, returned at free, and a pool
    /// past its slots serves unregistered.
    #[test]
    fn slots_are_assigned_registered_and_recycled() {
        let Some(ring1) = ring() else {
            return;
        };
        let Some(table) = table_on(&ring1, 2) else {
            return;
        };
        let mut p = BodyPool::with_table(64 * MIB, Some(table));
        let r0 = p.claim_fixed().expect("allocates");
        let r1 = p.claim_fixed().expect("allocates");
        let r2 = p.claim_fixed().expect("allocates");
        assert_eq!(r0.slot(), Some(0));
        assert_eq!(r1.slot(), Some(1));
        assert_eq!(r2.slot(), None, "the slots are spent");
        // Retained records keep their slots; a freed one gives its up.
        drop(r0);
        let again = p.claim_fixed().expect("serves");
        assert_eq!(again.slot(), Some(0), "served with its slot");
        // One table per ring.
        let ring2 = ring().expect("a second ring on a host that has io_uring");
        let Some(t2) = table_on(&ring2, 2) else {
            return;
        };
        let mut tiny = BodyPool::with_table(MIB, Some(t2));
        let a = tiny.claim_fixed().expect("allocates");
        let b = tiny.claim_fixed().expect("allocates");
        assert_eq!((a.slot(), b.slot()), (Some(0), Some(1)));
        drop(a);
        drop(b); // over the one-record budget: freed, slot 1 returned
        tiny.drain_returns();
        assert_eq!(tiny.retained(), MIB);
        let c = tiny.claim_fixed().expect("serves the kept one");
        assert_eq!(c.slot(), Some(0));
        let d = tiny.claim_fixed().expect("allocates");
        assert_eq!(d.slot(), Some(1), "the freed record's slot came back");
    }

    /// A slotless record is registered by the claim that next serves it
    /// once a slot is free.
    #[test]
    fn a_slotless_buffer_is_registered_when_a_slot_frees() {
        let Some(ring1) = ring() else {
            return;
        };
        let Some(table) = table_on(&ring1, 2) else {
            return;
        };
        // Two slots, a budget of two records.
        let mut p = BodyPool::with_table(2 * MIB, Some(table));
        let s0 = p.claim_fixed().expect("allocates");
        let s1 = p.claim_fixed().expect("allocates");
        let s2 = p.claim_fixed().expect("allocates");
        assert_eq!((s0.slot(), s1.slot(), s2.slot()), (Some(0), Some(1), None));
        // Two kept, the third over budget: freed, slot back.
        drop(s2);
        drop(s1);
        drop(s0);
        p.drain_returns();
        assert_eq!(p.retained(), 2 * MIB);
        assert_eq!(p.records.free_slots, vec![0]);
        let a = p.claim_fixed().expect("serves");
        assert_eq!(a.slot(), Some(1), "the slotted one, LIFO");
        let b = p.claim_fixed().expect("serves");
        assert_eq!(b.slot(), Some(0), "the slotless one, registered now");
        assert!(p.records.free_slots.is_empty());
    }

    /// A shrink returns every evicted slot exactly once.
    #[test]
    fn a_shrink_returns_every_evicted_slot() {
        let Some(ring1) = ring() else {
            return;
        };
        let Some(table) = table_on(&ring1, 4) else {
            return;
        };
        let mut p = BodyPool::with_table(64 * MIB, Some(table));
        let bufs: Vec<_> = (0..4)
            .map(|_| p.claim_fixed().expect("allocates"))
            .collect();
        let mut slots: Vec<_> = bufs.iter().map(|b| b.slot()).collect();
        slots.sort();
        assert_eq!(slots, vec![Some(0), Some(1), Some(2), Some(3)]);
        drop(bufs);
        p.drain_returns();
        assert_eq!(p.retained(), 4 * MIB);
        for _ in 0..SHRINK_AFTER {
            p.rebalance();
        }
        assert_eq!(p.target(), 2 * MIB, "quiet halved the target");
        assert_eq!(p.retained(), 2 * MIB, "two records freed");
        assert_eq!(p.records.free_slots.len(), 2, "their slots came back");
        let again: Vec<_> = (0..4)
            .map(|_| p.claim_fixed().expect("allocates"))
            .collect();
        let mut slots: Vec<_> = again.iter().map(|b| b.slot()).collect();
        slots.sort();
        assert_eq!(
            slots,
            vec![Some(0), Some(1), Some(2), Some(3)],
            "two served with their slots, two misses behind the freed ones"
        );
        assert!(p.records.free_slots.is_empty());
    }

    /// A licensed give evicts the other kind down to its floor and no
    /// further; an unlicensed give takes nothing.
    #[test]
    fn a_licensed_give_takes_room_from_the_other_kind_down_to_its_floor() {
        let mut p = BodyPool::new(4 * MIB);
        let bodies: Vec<_> = (0..4).map(|_| p.claim(MIB)).collect();
        for v in bodies {
            p.give(v);
        }
        assert_eq!(p.retained(), 4 * MIB, "the bodies hold the whole budget");
        let a = p.claim_fixed().expect("allocates");
        let b = p.claim_fixed().expect("allocates");
        drop(a);
        p.drain_returns();
        assert_eq!(p.records.free.len(), 1, "the record is kept");
        assert_eq!(p.free.len(), 3, "one body gave way");
        assert_eq!(p.retained(), 4 * MIB);
        assert_eq!(
            p.target(),
            4 * MIB,
            "the evicted licence left, the new one came"
        );
        // A second record finds the bodies at their ceiling: refused,
        // and nothing is evicted for a give that cannot fit.
        drop(b);
        p.drain_returns();
        assert_eq!(p.records.free.len(), 1, "the floor is a quarter, not more");
        assert_eq!(p.free.len(), 3, "and no body was evicted for it");
        // The other way round.
        let mut q = BodyPool::new(4 * MIB);
        let recs: Vec<_> = (0..4)
            .map(|_| q.claim_fixed().expect("allocates"))
            .collect();
        drop(recs);
        q.drain_returns();
        assert_eq!(q.retained(), 4 * MIB);
        let mut unlicensed = Vec::new();
        unlicensed.reserve_exact(MIB);
        q.give(unlicensed);
        assert_eq!(q.records.free.len(), 4, "nothing proven, nothing taken");
        // A pot that does not cover the give takes nothing either.
        drop(q.claim(64 * 1024));
        let mut short = Vec::new();
        short.reserve_exact(MIB);
        q.give(short);
        assert_eq!(q.records.free.len(), 4, "a 64 KiB pot covers no 1 MiB");
        let (v, licence) = q.claim_held(MIB);
        q.give_held(v, licence);
        assert_eq!(q.records.free.len(), 3, "a licensed body took one record");
        assert_eq!(q.free.len(), 1);
        assert_eq!(q.retained(), 4 * MIB);
    }

    /// Equal-size bodies serve newest first, so a same-size inventory
    /// ages down to its working set.
    #[test]
    fn a_same_size_inventory_ages_down_to_its_working_set() {
        let mut p = BodyPool::new(64 * MIB);
        let bodies: Vec<_> = (0..8).map(|_| p.claim_held(MIB)).collect();
        for (v, licence) in bodies {
            p.give_held(v, licence);
        }
        assert_eq!(p.retained(), 8 * MIB);
        for _ in 0..SHRINK_AFTER {
            let (v, licence) = p.claim_held(MIB);
            assert_eq!(licence, 0, "served");
            p.give_held(v, 0);
            p.rebalance();
        }
        assert_eq!(p.retained(), MIB, "seven unserved bodies aged out");
        assert_eq!(p.target(), MIB, "their licences with them");
    }

    /// Streams cycling one record per write are served from the
    /// inventory after the first lap.
    #[test]
    fn cycling_streams_are_served_after_the_first_lap() {
        const STREAMS: usize = 8;
        const DEPTH: usize = 5;
        let mut p = BodyPool::new(64 * MIB);
        let mut held: Vec<std::collections::VecDeque<Fixed>> = (0..STREAMS)
            .map(|_| {
                (0..DEPTH)
                    .map(|_| p.claim_fixed().expect("allocates"))
                    .collect()
            })
            .collect();
        for round in 0..40 {
            // Every stream's oldest write completes...
            for h in held.iter_mut() {
                drop(h.pop_front());
            }
            // ...and every stream stages its next record.
            for h in held.iter_mut() {
                let f = p.claim_fixed().expect("serves");
                assert_eq!(
                    f.inner().licence,
                    0,
                    "round {round}: a miss where the lap before returned one"
                );
                h.push_back(f);
            }
            if round % 5 == 4 {
                p.rebalance();
            }
            assert!(p.retained() <= STREAMS * MIB, "bounded by a lap");
        }
    }

    /// No table, no slots.
    #[test]
    fn no_table_means_no_slot_bookkeeping() {
        let mut p = BodyPool::with_table(64 * MIB, None);
        assert!(p.records.free_slots.is_empty());
        let a = p.claim_fixed().expect("allocates");
        assert_eq!(a.slot(), None);
    }
}
