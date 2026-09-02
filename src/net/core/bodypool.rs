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
//! - **Retention is licensed by demand.** A claim that finds the list
//!   empty allocates (the caller's body must exist regardless) and
//!   records a miss. When storage comes home, each outstanding miss
//!   licenses raising the retention target to cover it — so the target
//!   grows toward the storm's real working set, measured in the bytes
//!   the storm actually used, never ahead of it.
//! - **A hard budget caps the target.** Whatever demand claims, retained
//!   bytes never exceed the budget the pool was built with; storage over
//!   it is freed on the spot, and a single body larger than the budget
//!   is never retained at all. The worst case is the budget, per ring,
//!   full stop.
//! - **Quiet halves and evicts.** [`BodyPool::rebalance`] is driven by
//!   the ring's maintenance timer; [`SHRINK_AFTER`] consecutive quiet
//!   observations halve the target and free the surplus immediately.
//!   Userspace storage has no posted-descriptor problem, so the
//!   give-back needs no traffic — this pool shrinks in silence, where
//!   the kernel rings can only lower their targets and wait for buffers
//!   to cycle home.
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

/// Ring-owned storage for bodies read outside a pool buffer.
pub(crate) struct BodyPool {
    /// Cleared, capacity-bearing Vecs awaiting reuse. LIFO, so a storm of
    /// same-shaped bodies keeps cycling its warmest allocation.
    free: Vec<Vec<u8>>,
    /// Total capacity retained in `free`, in bytes — the figure every
    /// bound below is about.
    retained: usize,
    /// The most bytes `free` may retain right now. Raised by licensed
    /// demand, halved by quiet, never above `budget`.
    target: usize,
    /// The hard ceiling on `target`, set at construction: whatever a
    /// storm proves, retained storage never passes this.
    budget: usize,
    /// Claims that found the list empty since the last rebalance. Each
    /// licenses one retention-grow when storage comes home; reset every
    /// observation, so a storm long gone cannot license a later one. A
    /// counter rather than an outstanding ledger because a delivered
    /// body may never come back (the consumer owns it), and a ledger
    /// that cannot be decremented reliably reads as permanent load.
    misses: usize,
    /// Claims since the last rebalance — the quiet detector.
    hot: usize,
    /// Consecutive rebalances that observed no claim.
    idle_rounds: u8,
}

impl BodyPool {
    pub(crate) fn new(budget: usize) -> BodyPool {
        BodyPool {
            free: Vec::new(),
            retained: 0,
            target: 0,
            budget,
            misses: 0,
            hot: 0,
            idle_rounds: 0,
        }
    }

    /// Storage for a body of at least `min_cap` bytes: a reused Vec where
    /// one waits, a fresh allocation — and a recorded miss — where none
    /// does. The returned Vec is empty; its capacity covers `min_cap`.
    pub(crate) fn claim(&mut self, min_cap: usize) -> Vec<u8> {
        self.hot = self.hot.saturating_add(1);
        match self.free.pop() {
            Some(mut v) => {
                debug_assert!(v.is_empty(), "a pooled body kept bytes");
                self.retained = self.retained.saturating_sub(v.capacity());
                v.reserve(min_cap);
                v
            }
            None => {
                self.misses = self.misses.saturating_add(1);
                Vec::with_capacity(min_cap)
            }
        }
    }

    /// Hand storage home. Cleared here so a claim never sees stale bytes.
    /// Retained only within the byte target — which an outstanding miss
    /// may first raise to cover it, up to the budget — and freed on the
    /// spot otherwise.
    pub(crate) fn give(&mut self, mut v: Vec<u8>) {
        let cap = v.capacity();
        if cap == 0 {
            return;
        }
        let held = self.retained.saturating_add(cap);
        if held > self.target && self.misses > 0 && held <= self.budget {
            // Demand proved a body of this size was needed while the
            // list was dry; retaining it is what a working set means.
            self.misses -= 1;
            self.target = held;
        }
        if held > self.target {
            return; // freed here — over target, or over budget outright
        }
        v.clear();
        self.retained = held;
        self.free.push(v);
    }

    /// The timer's observation: quiet long enough halves the target and
    /// frees the surplus now — no traffic is needed to hand anything
    /// back. Demand licenses do not survive the observation window, so a
    /// storm long gone cannot inflate the pool a later one holds.
    pub(crate) fn rebalance(&mut self) {
        self.misses = 0;
        if self.hot > 0 {
            self.hot = 0;
            self.idle_rounds = 0;
            return;
        }
        self.idle_rounds = self.idle_rounds.saturating_add(1);
        if self.idle_rounds < SHRINK_AFTER {
            return;
        }
        self.idle_rounds = 0;
        self.target /= 2;
        while self.retained > self.target {
            let Some(v) = self.free.pop() else {
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

    /// Quiet halves the retained bytes and frees them now; one claim
    /// resets the count.
    #[test]
    fn quiet_shrinks_bytes_with_hysteresis_and_traffic_resets_it() {
        let mut p = BodyPool::new(64 * MIB);
        let bodies: Vec<_> = (0..4).map(|_| p.claim(MIB)).collect();
        for v in bodies {
            p.give(v);
        }
        assert_eq!(p.retained(), 4 * MIB);
        // The claims above count as heat: the first observation clears it.
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
        assert!(p.retained() >= MIB, "a claim resets the quiet count");
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
