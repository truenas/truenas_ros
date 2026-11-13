//! Reusable storage for placed and promoted request bodies.
//!
//! A request body larger than one recv buffer is read into storage of its own, by placement or by promotion. This pool
//! keeps that storage on the ring, sized by demand rather than by the connection table, so a storm of large bodies does
//! not allocate per message. It is plain userspace storage and not a provided-buffer group, because a large body needs
//! one directed destination of its own size. Lending a posted buffer as scratch would race the kernel picking it, and a
//! group sized at the largest legal body would fault whole maximal buffers for storms of small ones.
//!
//! The law is in bytes, since one retained `Vec` keeps whatever capacity it once held.
//!
//! - **Retention is licensed by demand in bytes.** A claim that finds nothing fitting allocates and records the size it
//!   needed, and storage coming home raises the target by no more than the outstanding missed bytes.
//! - **A held licence lives as long as its claim.** The reactor's claims ([`BodyPool::claim_held`]) resolve
//!   deterministically, so their licences survive however many maintenance ticks a slow receipt spans. Only the
//!   windowed pot expires, for consumer claims ([`BodyRecycler`]) and delivered bodies awaiting an optional recycle.
//! - **A body is served from storage near its size.** The free list is sorted by capacity and taken best-fit, and a
//!   buffer more than [`OVERSIZE_SERVE`] times the ask is left for the body it was sized by.
//! - **A hard budget caps the target.** Storage over it is freed on the spot, so the worst case is the budget per ring.
//! - **Quiet means no serve.** [`BodyPool::rebalance`] runs on the ring's maintenance timer, and [`SHRINK_AFTER`]
//!   observations without a pool-served claim halve the target and free the surplus at once. A claim the inventory
//!   cannot serve is a miss and not heat, or an inventory serving nothing would pin itself at the budget under traffic.
//! - **Under load each buffer earns its keep.** A free entry unserved for [`SHRINK_AFTER`] hot observations is evicted,
//!   licence and all. What this bounds is retained capacity, an upper bound on resident memory and not a measure of it,
//!   since glibc raises `M_MMAP_THRESHOLD` to each mmapped block it frees, moving later blocks of that size into arenas
//!   whose `free()` trims nothing.
//!
//! [`BodyRecycler::recycle`] is advisory. A handler that never calls it costs what a pool with no recycle costs, since
//! the pool refills from misses, so nothing breaks when an error path drops a body.

use super::conn::Ticket;
#[cfg(feature = "net-server")]
use crate::sync::Arc;
#[cfg(feature = "net-server")]
use crate::uring::wake::LoopShared;
use std::cell::RefCell;
use std::rc::Rc;

/// Consecutive quiet observations before the pool gives storage up — [`BufPool`](crate::uring::bufring)'s constant, for
/// the same reason: a pool that shrinks on the first quiet moment spends its life allocating and freeing across a
/// workload that merely pauses.
const SHRINK_AFTER: u8 = 4;

/// How many times the ask a served buffer may exceed, floored at [`OVERSIZE_FLOOR`]. Past it the claim is treated as
/// unmet and allocates right-sized, so small bodies are not carried in the high-water allocation.
const OVERSIZE_SERVE: usize = 4;

/// Below this, over-provision is noise: refusing a 256 KiB buffer to a 4 KiB ask would shed warm reuse to save
/// kilobytes.
const OVERSIZE_FLOOR: usize = 64 * 1024;

/// Ring-owned storage for bodies read outside a pool buffer.
pub(crate) struct BodyPool {
    /// Cleared Vecs awaiting reuse, sorted ascending by capacity so best-fit is a binary search, each beside the count
    /// of hot observations it sat through unserved. A serve resets that count, since the buffer comes home at age zero.
    /// Whole-pool quiet never ages entries, because the halving path owns that regime and a paused workload keeps its
    /// warm pool.
    free: Vec<(Vec<u8>, u8)>,
    /// Total capacity retained in `free`, in bytes — the figure every bound below is about.
    retained: usize,
    /// The most bytes `free` may retain right now. Raised by licensed demand, halved by quiet, never above `budget`.
    target: usize,
    /// The hard ceiling on `target`, set at construction: whatever a storm proves, retained storage never passes this.
    budget: usize,
    /// Bytes of demand that found nothing fitting, recorded by consumer claims at the claim and by reactor claims when
    /// their body leaves custody ([`BodyPool::receipt_done`]). Licenses target growth as storage comes home. Reset
    /// every observation window, since the storage on this pot's clock is consumer-held and may never return. Capped at
    /// `budget`.
    missed_bytes: usize,
    /// Pool-served claims since the last rebalance, the quiet detector. Serves and not claims, since a claim the
    /// inventory cannot serve shows the retained bytes are not the working set.
    served: usize,
    /// Consecutive rebalances that observed no serve.
    idle_rounds: u8,
    /// Bytes of storage out of this pool that the reactor holds, by capacity. A placed or promoted body counts from its
    /// claim until it is taken or given back, and a reply marked recycled from when it is queued on its connection
    /// until it is sent or dropped. Each give takes back exactly what its claim counted and never reads a capacity
    /// again, since storage may grow while it is held.
    ring_held: usize,
    /// Bytes the consumer counts as its own ([`BodyRecycler::take_out`]).
    out_held: usize,
    /// The ring's loop state, whose `handed` bytes are replies a `Deferred` handed to the loop that it has not yet
    /// queued or sent home, which count from that hand-off.
    #[cfg(feature = "net-server")]
    shared: Option<Arc<LoopShared>>,
    /// `ServerConfig::held_cap`, past which the ring holds back the read of the next placed body and the consumer's own
    /// calls.
    cap: Option<usize>,
    /// What the ring holds back for its held bytes to fall under the cap, the reads of placed bodies and the consumer's
    /// turns, in the order they came, so that neither keeps the other back for good. Here and not in the reactor, since
    /// the consumer's [`BodyRecycler`] reaches the pool alone.
    #[cfg(feature = "net-server")]
    held_back: std::collections::VecDeque<HeldBack>,
}

/// One thing the ring holds back for its held bytes, in [`BodyPool`]'s queue.
#[cfg(feature = "net-server")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HeldBack {
    /// The read of the placed body of the connection in `slot`, while that slot is of `generation`.
    /// `Connection::read_held` keeps a connection here once, and an entry whose slot has moved on is passed over.
    Read { slot: u32, generation: u64 },
    /// A turn the consumer queued ([`BodyRecycler::queue_turn`]), for which the server runs its held hook once.
    Turn,
}

impl BodyPool {
    pub(crate) fn new(budget: usize, cap: Option<usize>) -> BodyPool {
        BodyPool {
            free: Vec::new(),
            retained: 0,
            target: 0,
            budget,
            missed_bytes: 0,
            served: 0,
            idle_rounds: 0,
            ring_held: 0,
            out_held: 0,
            #[cfg(feature = "net-server")]
            shared: None,
            cap,
            #[cfg(feature = "net-server")]
            held_back: std::collections::VecDeque::new(),
        }
    }

    /// Whether the bytes held are at or past the cap, so that what the ring holds back waits.
    pub(crate) fn at_cap(&self) -> bool {
        self.cap.is_some_and(|cap| self.held() >= cap)
    }

    /// Whether a placed body read or a call of the consumer's may go now, the bytes held under the cap with nothing
    /// held back before it.
    #[cfg(feature = "net-server")]
    pub(crate) fn may_go(&self) -> bool {
        !self.at_cap() && self.held_back.is_empty()
    }

    /// Hold `what` back behind what is held back already.
    #[cfg(feature = "net-server")]
    pub(crate) fn hold_back(&mut self, what: HeldBack) {
        self.held_back.push_back(what);
    }

    /// The first thing held back, taken off the queue, if the bytes held are under the cap so that it goes on.
    #[cfg(feature = "net-server")]
    pub(crate) fn let_go(&mut self) -> Option<HeldBack> {
        if self.at_cap() {
            return None;
        }
        self.held_back.pop_front()
    }

    /// What is held back, in the order it came.
    #[cfg(all(test, not(loom), feature = "net-server"))]
    pub(crate) fn held_back(&self) -> Vec<HeldBack> {
        self.held_back.iter().copied().collect()
    }

    /// Count the replies handed to the ring's loop through `shared` from their hand-off.
    #[cfg(feature = "net-server")]
    pub(crate) fn count_handed(&mut self, shared: Arc<LoopShared>) {
        self.shared = Some(shared);
    }

    /// The bytes held out of this pool, the reactor's count, the replies handed to the loop that it has not yet queued
    /// or sent home, and the consumer's figure together.
    pub(crate) fn held(&self) -> usize {
        self.ring_held
            .saturating_add(self.out_held)
            .saturating_add(self.handed())
    }

    /// The bytes of replies handed to the loop that it has not yet queued or sent home.
    fn handed(&self) -> usize {
        #[cfg(feature = "net-server")]
        if let Some(shared) = &self.shared {
            return shared.handed.load(std::sync::atomic::Ordering::Relaxed);
        }
        0
    }

    /// Put storage the reactor now holds on the count.
    pub(crate) fn hold(&mut self, bytes: usize) {
        self.ring_held = self.ring_held.saturating_add(bytes);
    }

    /// Take storage the reactor no longer holds off the count.
    pub(crate) fn unhold(&mut self, bytes: usize) {
        self.ring_held = self.ring_held.saturating_sub(bytes);
    }

    /// The best-fitting free Vec for `min_cap`, if serving it is not an over-provision ([`OVERSIZE_SERVE`]); its
    /// capacity leaves `retained` with it. The one place a serve is counted as heat.
    fn take_fit(&mut self, min_cap: usize) -> Option<Vec<u8>> {
        // `free` is sorted by capacity, so the first entry covering the ask is the best fit and finding it is a binary
        // search. Taking it is still O(n), since `remove` memmoves as `give_held`'s `insert` does.
        let i = self.free.partition_point(|(v, _)| v.capacity() < min_cap);
        let cap = self.free.get(i)?.0.capacity();
        if cap > min_cap.saturating_mul(OVERSIZE_SERVE).max(OVERSIZE_FLOOR) {
            return None;
        }
        self.retained = self.retained.saturating_sub(cap);
        self.served = self.served.saturating_add(1);
        Some(self.free.remove(i).0)
    }

    /// Storage for a body of at least `min_cap` bytes, consumer form: a fitting reused Vec where one waits, a fresh
    /// allocation — and `min_cap` recorded on the windowed pot — where none does. The returned Vec is empty; its
    /// capacity covers `min_cap`.
    pub(crate) fn claim(&mut self, min_cap: usize) -> Vec<u8> {
        let (v, licence) = self.fit(min_cap);
        self.missed_bytes = self.missed_bytes.saturating_add(licence).min(self.budget);
        v
    }

    /// A fitting reused Vec where one waits, with no licence, or a fresh allocation with `min_cap` as its licence.
    fn fit(&mut self, min_cap: usize) -> (Vec<u8>, usize) {
        match self.take_fit(min_cap) {
            Some(mut v) => {
                debug_assert!(v.is_empty(), "a pooled body kept bytes");
                v.reserve_exact(min_cap);
                (v, 0)
            }
            None => (Vec::with_capacity(min_cap), min_cap),
        }
    }

    /// [`claim`](BodyPool::claim) for the reactor's placed and promoted bodies, whose storage resolves
    /// deterministically. A miss comes back as a held licence in the `Ticket`, returned through
    /// [`give_held`](BodyPool::give_held) or [`receipt_done`](BodyPool::receipt_done), and it does not expire with the
    /// observation window. The storage's capacity goes on the count of held bytes, and the ticket carries it so the
    /// give takes off what was put on.
    pub(crate) fn claim_held(&mut self, min_cap: usize) -> (Vec<u8>, Ticket) {
        let (v, licence) = self.fit(min_cap);
        let bytes = v.capacity();
        self.hold(bytes);
        (v, Ticket { licence, bytes })
    }

    /// A held claim's body is leaving reactor custody for the handler, so its licence moves to the windowed pot, where
    /// the consumer's optional recycle can spend it. Call it before the handler runs, since the common recycle happens
    /// inside the handler and a licence potted after it would miss the give it exists to cover.
    pub(crate) fn receipt_done(&mut self, licence: usize) {
        self.missed_bytes = self.missed_bytes.saturating_add(licence).min(self.budget);
    }

    /// Hand storage home with the ticket its claim recorded. The ticket's held licence, 0 for a pool-served claim,
    /// joins the pot, and its bytes leave the count. The storage is cleared so a claim never sees stale bytes, and kept
    /// only within the byte target, which outstanding missed bytes may first raise toward it up to the budget. Past
    /// that it is freed on the spot.
    pub(crate) fn give_held(&mut self, mut v: Vec<u8>, ticket: Ticket) {
        self.unhold(ticket.bytes);
        self.missed_bytes = self.missed_bytes.saturating_add(ticket.licence).min(self.budget);
        let cap = v.capacity();
        if cap == 0 {
            return;
        }
        let held = self.retained.saturating_add(cap);
        if held > self.target {
            // Missed bytes license retention toward the working set and no further, so one giant give cannot ride a
            // small licence. The grant is decided before it is spent, so a give the pot cannot cover, or one over the
            // budget, frees with the pot intact.
            let grant = (held - self.target).min(self.missed_bytes);
            if held > self.budget || self.target + grant < held {
                return; // freed; nothing is spent on freed storage
            }
            self.target += grant;
            self.missed_bytes -= grant;
        }
        v.clear();
        self.retained = held;
        // Sorted insert, keeping the binary-search best-fit true and the shrink's pop pointed at the largest entry. Age
        // zero: a give is this buffer's demand proving itself.
        let at = self.free.partition_point(|(w, _)| w.capacity() <= cap);
        self.free.insert(at, (v, 0));
    }

    /// Hand storage home, consumer form: no held licence, so retention rides whatever the windowed pot holds.
    pub(crate) fn give(&mut self, v: Vec<u8>) {
        self.give_held(v, Ticket::default());
    }

    /// The timer's observation. Quiet long enough halves the target and frees the surplus now, with no traffic needed.
    /// The windowed pot does not survive the observation, but held licences do, since they ride the reactor claims that
    /// recorded them.
    ///
    /// Its cost is a `free()` per evicted entry, inline on the reactor thread, and the entry count is bounded only by
    /// `budget` over the smallest retained capacity. [`BodyRecycler::claim`] takes any `min_cap`, so an inventory of
    /// small bodies can be large enough for its eviction to stall the ring.
    pub(crate) fn rebalance(&mut self) {
        self.missed_bytes = 0;
        if self.served > 0 {
            self.served = 0;
            self.idle_rounds = 0;
            // Each entry ages on its own, since whole-pool heat would shield the stranded high-water buffers a shifted
            // workload left behind. An evicted entry's licence dies with it, so `target` follows `retained` down and a
            // later unlicensed give cannot ride demand that left with the buffer.
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
            // The list is sorted, so this frees the largest entry first — the high-water buffer a shifted workload
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
    pub(crate) fn retained(&self) -> usize {
        self.retained
    }

    #[cfg(test)]
    fn target(&self) -> usize {
        self.target
    }
}

/// The consumer's end of the loop: hand a delivered body's storage back to the ring it was read on.
///
/// Single-threaded by construction — the pool belongs to one ring and this handle is `!Send`, so it cannot leave the
/// ring thread that built the server. Calling it from anywhere else is a compile error, not a race.
#[derive(Clone)]
pub struct BodyRecycler {
    pool: Rc<RefCell<BodyPool>>,
}

impl BodyRecycler {
    pub(crate) fn new(pool: Rc<RefCell<BodyPool>>) -> BodyRecycler {
        BodyRecycler { pool }
    }

    /// Return a body's storage for reuse. The Vec's bytes are dead the moment this is called; the pool clears them
    /// before reissue.
    pub fn recycle(&self, body: Vec<u8>) {
        self.pool.borrow_mut().give(body);
    }

    /// Draw storage of at least `min_cap` bytes from the pool — a reused buffer where one waits, a fresh allocation
    /// otherwise. For a consumer that accumulates a body itself (a server buffering an operation it does not stream)
    /// rather than receiving one placed: claiming here means that accumulator cycles the same storage the placement
    /// path does, instead of minting its own per message.
    pub fn claim(&self, min_cap: usize) -> Vec<u8> {
        self.pool.borrow_mut().claim(min_cap)
    }

    /// Count `bytes` the consumer holds in [`held`](Self::held), such as storage it claimed or a body it took. Neither
    /// is on the ring's own count, since a `Vec` the consumer drops where the pool cannot see it would stay counted for
    /// good, so the consumer counts what it holds here and gives exactly as much back.
    pub fn take_out(&self, bytes: usize) {
        let mut p = self.pool.borrow_mut();
        p.out_held = p.out_held.saturating_add(bytes);
    }

    /// Take `bytes` the consumer counted with [`take_out`](Self::take_out) off [`held`](Self::held) again. Past what it
    /// counted, the figure stops at 0.
    pub fn give_back(&self, bytes: usize) {
        let mut p = self.pool.borrow_mut();
        p.out_held = p.out_held.saturating_sub(bytes);
    }

    /// The bytes held out of the ring's body pool. The ring counts placed and promoted bodies from their claim until a
    /// handler takes them or they go back, replies sent with
    /// [`SendBuf::recycled`](crate::net::server::SendBuf::recycled) from when they are queued, and replies sent with
    /// `Deferred::reply_recycled` from that call, each until it is sent or dropped and by capacity. The consumer's own
    /// figure is added to that.
    pub fn held(&self) -> usize {
        self.pool.borrow().held()
    }

    /// Whether a call of the consumer's that holds storage of the pool may go now, the bytes [`held`](Self::held) under
    /// [`held_cap`](crate::net::server::ServerConfig::held_cap) with nothing held back, neither a placed body read nor
    /// a turn. A call that may not waits on a turn ([`queue_turn`](Self::queue_turn)), or answers in place of waiting
    /// with no turn left over. With no cap, every call may go.
    #[cfg(feature = "net-server")]
    pub fn may_go(&self) -> bool {
        self.pool.borrow().may_go()
    }

    /// Queue a turn behind what the ring holds back, the placed body reads and the turns queued before it, for which
    /// the server runs its held hook once (`Server::set_held_hook`) as its loop reaches the turn with the bytes held
    /// under the cap. The hook never runs inside this call.
    #[cfg(feature = "net-server")]
    pub fn queue_turn(&self) {
        self.pool.borrow_mut().hold_back(HeldBack::Turn);
    }
}

/// The ring's body pool, shared by the reactor, the connections and the consumer's [`BodyRecycler`] on the ring's one
/// thread.
pub(crate) type PoolHandle = Rc<RefCell<BodyPool>>;

/// The way home to the ring's body pool for storage the reactor handed on and nobody took, a placed body a handler left
/// where it lies and a reply marked recycled that never reached the wire. Whoever holds the storage gives it back
/// through this as it drops it. It carries the bytes the storage has on the pool's count, which leave the count as it
/// drops, with the storage or without it, as when a handler takes a body.
pub(crate) struct Home {
    pool: PoolHandle,
    bytes: usize,
}

impl Home {
    /// The way home for storage already on the count under `bytes`.
    pub(crate) fn new(pool: &PoolHandle, bytes: usize) -> Home {
        Home {
            pool: Rc::clone(pool),
            bytes,
        }
    }

    /// The way home for storage of `bytes` the reactor holds from now on, which puts them on the count.
    pub(crate) fn hold(pool: &PoolHandle, bytes: usize) -> Home {
        pool.borrow_mut().hold(bytes);
        Home::new(pool, bytes)
    }

    /// Give `v` back, for the pool to keep or free under its byte law.
    pub(crate) fn give(mut self, v: Vec<u8>) {
        let bytes = std::mem::take(&mut self.bytes);
        self.pool.borrow_mut().give_held(v, Ticket { licence: 0, bytes });
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        if self.bytes > 0 {
            self.pool.borrow_mut().unhold(self.bytes);
        }
    }
}

impl std::fmt::Debug for Home {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Home").field("bytes", &self.bytes).finish()
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
        let mut p = BodyPool::new(64 * MIB, None);
        let a = p.claim(MIB);
        let ptr = a.as_ptr() as usize;
        p.give(a);
        assert_eq!(p.retained(), MIB);
        let b = p.claim(MIB);
        assert_eq!(b.as_ptr() as usize, ptr, "the warm Vec cycles");
        assert_eq!(p.retained(), 0, "claimed storage is out, not retained");
    }

    /// Misses license retention of what demand actually used — measured in bytes — and an unlicensed give past the
    /// target frees instead.
    #[test]
    fn misses_grow_retention_to_the_working_set_in_bytes() {
        let mut p = BodyPool::new(64 * MIB, None);
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

    /// The budget caps the target however large demand runs: bodies over it cycle through the allocator, never through
    /// the pool.
    #[test]
    fn the_budget_is_a_hard_byte_ceiling() {
        let mut p = BodyPool::new(2 * MIB, None);
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

    /// Quiet halves the retained bytes and frees them now; one served claim resets the count.
    #[test]
    fn quiet_shrinks_bytes_with_hysteresis_and_traffic_resets_it() {
        let mut p = BodyPool::new(64 * MIB, None);
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

    /// Claims the inventory cannot serve are misses and not heat, so retained storage that serves nothing still shrinks
    /// under load.
    #[test]
    fn unservable_traffic_does_not_pin_retention() {
        let mut p = BodyPool::new(64 * MIB, None);
        // Concurrent, so each claim misses and licenses its own bytes.
        let claims: Vec<_> = (0..3).map(|_| p.claim_held(5 * MIB)).collect();
        for (v, t) in claims {
            p.give_held(v, t);
        }
        assert_eq!(p.retained(), 15 * MIB, "the storm's working set kept");
        // The workload shifts: every claim is refused as over-provision (5 MiB is past 4x 300 KiB), allocates fresh,
        // and never comes home — traffic, but not one serve.
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

    /// A held licence rides its claim and not the observation window, so a body that takes longer than a maintenance
    /// tick to arrive still licenses retaining its storage when it comes home.
    #[test]
    fn a_held_licence_survives_the_observation_window() {
        let mut p = BodyPool::new(64 * MIB, None);
        let (v, t) = p.claim_held(MIB);
        assert_eq!(t.licence, MIB, "a dry pool records the bytes needed");
        p.rebalance(); // a tick passes mid-receipt
        p.rebalance(); // and another
        p.give_held(v, t);
        assert_eq!(p.retained(), MIB, "the slow body still licenses itself");
        let (w, t) = p.claim_held(MIB);
        assert_eq!(t.licence, 0, "and the next receipt is a pool hit");
        p.give_held(w, t);
    }

    /// A delivered body's licence moves to the windowed pot at delivery, so the consumer's recycle window opens then -
    /// not at the arm, however long the receipt took.
    #[test]
    fn a_delivered_body_recycles_on_the_deliverys_clock() {
        let mut p = BodyPool::new(64 * MIB, None);
        let (v, t) = p.claim_held(MIB);
        p.rebalance(); // the receipt spans a tick
        p.receipt_done(t.licence); // delivery: the body leaves custody
        drop(v); // the handler owns it now; it comes back via recycle
        let mut recycled = Vec::new();
        recycled.reserve_exact(MIB);
        p.give(recycled);
        assert_eq!(p.retained(), MIB, "recycled within the delivery window");
    }

    /// The licence is sized in bytes, so a sizeless claim licenses nothing and a giant give cannot ride a small one.
    #[test]
    fn a_licence_is_bytes_not_a_count() {
        let mut p = BodyPool::new(64 * MIB, None);
        drop(p.claim(0));
        let mut giant = Vec::new();
        giant.reserve_exact(8 * MIB);
        p.give(giant);
        assert_eq!(p.retained(), 0, "a zero-byte miss licenses nothing");
        assert_eq!(p.target(), 0);
        // A small miss cannot license a giant either: the pot cannot cover it, so the giant frees and the licence is
        // not spent.
        drop(p.claim(64 * 1024));
        let mut giant = Vec::new();
        giant.reserve_exact(8 * MIB);
        p.give(giant);
        assert_eq!(p.retained(), 0, "the giant is freed, not retained");
        assert_eq!(p.target(), 0, "and spends no licence being freed");
    }

    /// The grant is decided before it is spent. Storage the pool frees anyway must not drain the pot, or the target
    /// rises above what is retained and the licence is gone for the give it could have covered.
    #[test]
    fn a_freed_give_spends_no_licence() {
        let mut p = BodyPool::new(64 * MIB, None);
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

    /// Under load a retained buffer that serves nothing for `SHRINK_AFTER` hot observations is evicted with its
    /// licence, while the entries traffic cycles stay warm.
    #[test]
    fn a_buffer_that_stops_serving_ages_out_under_load() {
        let mut p = BodyPool::new(64 * MIB, None);
        // Warm two classes concurrently: high-water and small.
        let big = p.claim_held(5 * MIB);
        let small = p.claim_held(300 * 1024);
        p.give_held(big.0, big.1);
        p.give_held(small.0, small.1);
        assert_eq!(p.retained(), 5 * MIB + 300 * 1024);
        // The workload shifts to the small class alone; every window is hot with serves the big buffer never gets (a
        // 300 KiB ask refuses it as over-provision).
        for _ in 0..SHRINK_AFTER {
            let (v, t) = p.claim_held(300 * 1024);
            assert_eq!(t.licence, 0, "the small class serves itself");
            p.give_held(v, t);
            p.rebalance();
        }
        assert_eq!(
            p.retained(),
            300 * 1024,
            "the unserved high-water buffer ages out; the serving one stays"
        );
        assert_eq!(p.target(), 300 * 1024, "its licence died with it");
        let (v, t) = p.claim_held(300 * 1024);
        assert_eq!(t.licence, 0, "and the survivor still serves");
        p.give_held(v, t);
    }

    /// The free list is sorted by capacity, so a claim binary-searches to the smallest fitting buffer instead of
    /// walking a storm-diversified list entry by entry.
    #[test]
    fn a_claim_takes_the_smallest_fitting_buffer() {
        let mut p = BodyPool::new(64 * MIB, None);
        // Concurrent, so the inventory diversifies instead of one buffer cycling through every claim.
        let claims: Vec<_> = [MIB, 3 * MIB, 2 * MIB].into_iter().map(|s| p.claim_held(s)).collect();
        for (v, t) in claims {
            p.give_held(v, t);
        }
        let (served, t) = p.claim_held(MIB + MIB / 2);
        assert_eq!(t.licence, 0, "a fitting buffer waited");
        assert_eq!(served.capacity(), 2 * MIB, "and the best fit served");
        p.give_held(served, t);
    }

    /// A body is served from storage near its size. The high-water buffer stays for bodies of its own order, and a much
    /// smaller claim allocates right-sized.
    #[test]
    fn a_small_body_is_not_served_from_the_high_water_buffer() {
        let mut p = BodyPool::new(64 * MIB, None);
        let (big, t) = p.claim_held(3 * MIB);
        p.give_held(big, t);
        assert_eq!(p.retained(), 3 * MIB, "the big body's storage waits");
        let (small, small_t) = p.claim_held(300 * 1024);
        assert!(
            small.capacity() < MIB,
            "a 300 KiB body must not carry a 3 MiB allocation: {}",
            small.capacity()
        );
        assert_eq!(small_t.licence, 300 * 1024, "unmet at its size, licensed");
        assert_eq!(p.retained(), 3 * MIB, "the big buffer stayed for its own");
        // Near its size, the big buffer does serve.
        let (served, t) = p.claim_held(MIB);
        assert_eq!(served.capacity(), 3 * MIB, "a 1 MiB ask takes the 3 MiB");
        assert_eq!(t.licence, 0);
        p.give_held(served, t);
        p.give_held(small, small_t);
    }

    /// The count of held bytes takes off exactly what each holder put on, whatever the storage's capacity is by then,
    /// and the consumer's own figure moves `held` beside it.
    #[test]
    fn held_bytes_come_off_as_they_went_on() {
        let pool = Rc::new(RefCell::new(BodyPool::new(64 * MIB, None)));
        let (mut v, t) = pool.borrow_mut().claim_held(MIB);
        assert_eq!(t.bytes, v.capacity(), "the ticket carries the count");
        assert_eq!(pool.borrow().held(), t.bytes, "a claim is held");
        // Grown while held, as promoted storage may be.
        v.reserve_exact(4 * MIB);
        pool.borrow_mut().give_held(v, t);
        assert_eq!(pool.borrow().held(), 0, "what went on came off");

        // A body taken out of the reactor's sight leaves the count as its way home drops, and one given back leaves it
        // too.
        let taken = Home::hold(&pool, MIB);
        let given = Home::hold(&pool, 2 * MIB);
        assert_eq!(pool.borrow().held(), 3 * MIB);
        drop(taken);
        assert_eq!(pool.borrow().held(), 2 * MIB);
        given.give(Vec::with_capacity(2 * MIB));
        assert_eq!(pool.borrow().held(), 0);

        // A consumer claim is not counted, and the consumer counts it.
        let r = BodyRecycler::new(Rc::clone(&pool));
        let claimed = r.claim(MIB);
        assert_eq!(r.held(), 0, "a consumer claim is the consumer's to count");
        r.take_out(claimed.capacity());
        assert_eq!(r.held(), claimed.capacity());
        let _ring = Home::hold(&pool, MIB);
        assert_eq!(r.held(), claimed.capacity() + MIB, "both figures add");
        r.give_back(claimed.capacity());
        assert_eq!(r.held(), MIB);
        r.give_back(1);
        assert_eq!(r.held(), MIB, "giving back past the figure stops at 0");
    }

    /// A call may go only under the cap with nothing held back, and what is held back goes in the order it came, only
    /// under the cap. With no cap everything may go.
    #[cfg(feature = "net-server")]
    #[test]
    fn a_call_may_go_only_under_the_cap_with_nothing_held_back() {
        let mut p = BodyPool::new(64 * MIB, Some(100));
        assert!(p.may_go(), "under the cap with nothing held back");
        p.hold(100);
        assert!(!p.may_go(), "at the cap");
        let read = HeldBack::Read { slot: 3, generation: 7 };
        p.hold_back(read);
        p.hold_back(HeldBack::Turn);
        assert_eq!(p.let_go(), None, "nothing goes at the cap");
        p.unhold(100);
        assert!(!p.may_go(), "under the cap, behind what is held back");
        assert_eq!(p.let_go(), Some(read), "in the order it came");
        assert!(!p.may_go(), "a turn is held back too");
        assert_eq!(p.let_go(), Some(HeldBack::Turn));
        assert_eq!(p.let_go(), None);
        assert!(p.may_go());
        let mut free = BodyPool::new(64 * MIB, None);
        free.hold(u32::MAX as usize);
        assert!(free.may_go(), "with no cap everything goes");
    }

    /// A miss does not license retention across observation windows: a storm that ended cannot inflate what a later one
    /// holds.
    #[test]
    fn a_license_does_not_outlive_the_observation_window() {
        let mut p = BodyPool::new(64 * MIB, None);
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
