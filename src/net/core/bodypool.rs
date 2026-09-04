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

use std::cell::RefCell;
use std::rc::Rc;

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
    /// Total capacity retained in `free`, in bytes — the figure every
    /// bound below is about.
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
    pub(crate) fn new(budget: usize) -> BodyPool {
        BodyPool {
            free: Vec::new(),
            retained: 0,
            target: 0,
            budget,
            missed_bytes: 0,
            served: 0,
            idle_rounds: 0,
        }
    }

    /// The best-fitting free Vec for `min_cap`, if serving it is not an
    /// over-provision ([`OVERSIZE_SERVE`]); its capacity leaves
    /// `retained` with it. The one place a serve is counted as heat.
    fn take_fit(&mut self, min_cap: usize) -> Option<Vec<u8>> {
        // `free` is sorted by capacity, so the first entry covering the
        // ask is the best fit and *finding* it is a binary search — the
        // linear best-fit walk cost ~500 ns per claim once a storm had
        // diversified the list into hundreds of entries, against 7 ns
        // for the LIFO pop it replaced. Taking it is still O(n): the
        // `remove` below memmoves, as `give_held`'s `insert` does, so
        // the pair is a win above ~100 entries and costs +18 to +27 ns
        // per body below it (n=8: 7.4→25.7 ns; n=32: 17.8→26.5;
        // n=1024: 459→318). Bucketing `free` by `capacity().ilog2()`
        // would be O(1) both ways with best-fit-near-size and
        // per-entry ageing intact; it is not worth the shape yet at
        // those absolutes.
        let i = self.free.partition_point(|(v, _)| v.capacity() < min_cap);
        let cap = self.free.get(i)?.0.capacity();
        if cap > min_cap.saturating_mul(OVERSIZE_SERVE).max(OVERSIZE_FLOOR) {
            return None;
        }
        self.retained = self.retained.saturating_sub(cap);
        self.served = self.served.saturating_add(1);
        Some(self.free.remove(i).0)
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

    /// Hand storage home with the held licence its claim recorded (0
    /// for a pool-served claim). Cleared here so a claim never sees
    /// stale bytes; retained only within the byte target — which
    /// outstanding missed bytes may first raise toward it, up to the
    /// budget — and freed on the spot otherwise.
    pub(crate) fn give_held(&mut self, mut v: Vec<u8>, licence: usize) {
        self.missed_bytes =
            self.missed_bytes.saturating_add(licence).min(self.budget);
        let cap = v.capacity();
        if cap == 0 {
            return;
        }
        let held = self.retained.saturating_add(cap);
        if held > self.target {
            // Demand proved bytes of this order were needed while
            // nothing fitting waited; retaining toward it is what a
            // working set means — and no further than the missed
            // bytes, so one giant give cannot ride a small licence.
            // The grant is decided before it is spent: a give the pot
            // cannot cover — or one over the budget outright — frees
            // with the pot intact, where spending first drained the
            // licence into a target no storage backed and the next
            // unlicensed give rode demand that was never granted it.
            let grant = (held - self.target).min(self.missed_bytes);
            if held > self.budget || self.target + grant < held {
                return; // freed; nothing is spent on freed storage
            }
            self.target += grant;
            self.missed_bytes -= grant;
        }
        v.clear();
        self.retained = held;
        // Sorted insert, keeping the binary-search best-fit true and
        // the shrink's pop pointed at the largest entry. Age zero: a
        // give is this buffer's demand proving itself.
        let at = self.free.partition_point(|(w, _)| w.capacity() <= cap);
        self.free.insert(at, (v, 0));
    }

    /// Hand storage home, consumer form: no held licence, so retention
    /// rides whatever the windowed pot holds.
    pub(crate) fn give(&mut self, v: Vec<u8>) {
        self.give_held(v, 0);
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
            let mut evicted = 0usize;
            self.free.retain_mut(|(v, age)| {
                *age = age.saturating_add(1);
                if *age < SHRINK_AFTER {
                    true
                } else {
                    evicted += v.capacity();
                    false
                }
            });
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
            // The list is sorted, so this frees the largest entry
            // first — the high-water buffer a shifted workload
            // stranded is the first thing a shrink reclaims.
            let Some((v, _)) = self.free.pop() else {
                debug_assert!(false, "retained bytes with no free entry");
                self.retained = 0;
                break;
            };
            self.retained = self.retained.saturating_sub(v.capacity());
        }
    }

    #[cfg(test)]
    fn retained(&self) -> usize {
        self.retained
    }

    #[cfg(test)]
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

#[cfg(test)]
mod tests {
    use super::*;

    const MIB: usize = 1024 * 1024;

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
}
