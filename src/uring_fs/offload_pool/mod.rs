//! The reactor's elastic blocking-work pool - [`WorkerPool`] and its
//! lazily-spawned per-reactor handle [`SharedPool`] - with its unit tests
//! and loom models in place. The job contract consumers program against
//! lives at `FsConn::offload`; the type docs below cover the mechanics.

use std::cell::Cell;
use std::collections::VecDeque;
use std::fmt;
use std::time::{Duration, Instant};
// The pool is loom-modelled (`loom_tests` below), so its primitives come
// from `crate::sync` - std's outside `--cfg loom`.
#[cfg(loom)]
use crate::sync::atomic::AtomicUsize;
use crate::sync::atomic::{AtomicU64, Ordering};
use crate::sync::{Arc, Condvar, Mutex, OnceCell, thread};

/// Per-ring sizing for the blocking-offload pool: how many worker threads it
/// keeps warm and how far it grows.
///
/// Every field is per ring, so a deployment running several multiplies them.
/// Only `floor` is resident; workers above it exist while a job is blocked on
/// them and retire when idle, so the ceiling is a limit rather than a
/// reservation.
///
/// `#[non_exhaustive]`, so a future knob is a field addition rather than a
/// breaking change; build one by mutating [`OffloadBounds::default`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct OffloadBounds {
    /// Warm workers, spawned on first use and never retired below. Resident,
    /// so this is a standing per-ring cost. At least 1.
    pub floor: usize,
    /// Growth limit under saturation: how many concurrently stalled jobs one
    /// ring absorbs before they queue behind each other. Raised to `floor` if
    /// smaller.
    pub ceiling: usize,
}

impl Default for OffloadBounds {
    fn default() -> OffloadBounds {
        OffloadBounds {
            floor: crate::uring_fs::core::OFFLOAD_FLOOR,
            ceiling: crate::uring_fs::core::OFFLOAD_CEILING,
        }
    }
}

/// A boxed unit of work a pool worker runs. Every job is `Send` and
/// self-contained (it captures its own inputs and result channel), so the pool
/// is generic - the `!Send` `QueryDir` is built and driven *inside* the job,
/// on the worker's own thread, never sent.
pub(crate) type Job = Box<dyn FnOnce() + Send>;

/// Jobs in the queue that no outstanding claim covers. Every `notify` is
/// one worker already on its way, and a woken worker drains the queue
/// whole, so those jobs need nobody new.
fn unclaimed(g: &PoolInner) -> usize {
    g.queue.len().saturating_sub(g.notify)
}

/// Claim one parked worker and signal it. **The only place the pool issues
/// a wake**, so the test counter beside it counts signals delivered rather
/// than a number computed elsewhere.
fn claim_one(shared: &PoolShared, g: &mut PoolInner) {
    debug_assert!(g.idle > 0, "claimed a worker with none parked");
    g.idle -= 1;
    g.notify += 1;
    #[cfg(test)]
    {
        g.wakes_issued += 1;
    }
    shared.cv.notify_one();
}

/// How many jobs a caller must declare, per worker still parked, before
/// [`WorkerPool::flush`] spawns another one.
///
/// **The caller's count, not the queue's depth** - the predicate reads
/// `pending`, deliberately: sized from the queue, the off-loop
/// submitter's hard-coded `flush(1)` would spawn against a backlog the
/// reactor created, on an application thread.
/// `a_flush_of_one_does_not_grow_against_the_queue` pins that.
///
/// It is a growth threshold and not a wake ratio. It carries the parent's
/// number because the same constant answered both questions there, which
/// is what made the coupling easy to miss when the wake rule changed.
const JOBS_PER_WORKER_BEFORE_GROWTH: usize = 4;

/// Ceiling on the pool's own thread count. Not a kernel limit - a sanity
/// bound, since every one of these is a real OS thread, spawned by one
/// reactor and on the reactor thread, for work that has no io_uring opcode.
///
/// Lives here rather than in a host's config so **both** hosts screen against
/// the same number: `net`'s `ServerConfig::validate` and `UringFs::check`.
pub(crate) const MAX_OFFLOAD_THREADS: usize = 1024;

/// Growth is rate-limited to at most one new worker per this interval, so a
/// burst of microsecond-fast jobs that momentarily saturates the pool does not
/// spawn a thread per job; sustained blocking work still grows to the ceiling.
const OFFLOAD_SPAWN_COOLDOWN: Duration = Duration::from_millis(1);
/// A burst worker idle this long retires, back down to the floor.
const OFFLOAD_IDLE_TIMEOUT: Duration = Duration::from_secs(10);
struct PoolInner {
    queue: VecDeque<Job>,
    /// Live worker threads: the floor plus any grown-in burst workers.
    total: usize,
    /// Workers parked on the condvar that no submit has claimed yet. A
    /// submit takes one out of this count *before* it wakes it, so a
    /// wake is issued only for a worker that will consume it - and never
    /// at all when every worker is running, which is the case a
    /// saturated pool hits on every job.
    idle: usize,
    /// Wakes issued and not yet consumed. A woken worker decrements it;
    /// one that wakes to find it zero was woken spuriously (or by the
    /// shutdown's broadcast) and goes back to sleep unless there is work
    /// to take, the pool is closing, or its idle period expired. Without
    /// the count, the condvar's own spurious wakeups would let two
    /// workers claim one wake and double-decrement `idle`.
    notify: usize,
    /// The pool is dropping; workers drain the queue, then exit.
    closed: bool,
    /// Micros since [`PoolShared::epoch`] of the last spawn, throttling growth.
    last_spawn_us: u64,
    /// Wakes `flush` itself issued on its most recent call, written under
    /// the same guard it makes the decision under. Separate from
    /// `wakes_issued` because the chain starts moving that the instant
    /// `flush` drops the lock: a test that wants *this call's* cost cannot
    /// read a running total afterwards and know what it is looking at.
    #[cfg(test)]
    last_flush_wakes: usize,
    /// Wakes `flush` has issued over this pool's life. Test-only, and the
    /// only way to observe the wake *count* rather than its consequences:
    /// an over-wake is invisible afterwards, since the extra worker finds
    /// the queue empty, consumes its `notify` and parks again, leaving
    /// every counter balanced.
    #[cfg(test)]
    wakes_issued: usize,
}

struct PoolShared {
    inner: Mutex<PoolInner>,
    /// Signals a queued job, a shutdown, or a worker exit (`Drop` waits on it).
    cv: Condvar,
    floor: usize,
    ceiling: usize,
    epoch: Instant,
    cooldown: Duration,
    idle_timeout: Duration,
    /// Model-only: how many idle retirements to grant (see [`idle_expired`]).
    #[cfg(loom)]
    retire_next_idle: AtomicUsize,
    /// Model-only: let `Drop` take its detach branch (see
    /// [`shutdown_expired`]).
    #[cfg(loom)]
    detach_next_drop: AtomicUsize,
}

/// An elastic pool of worker threads running `Box<dyn FnOnce() + Send>` jobs,
/// the shared machinery behind both the off-loop `QueryPool` helpers and the
/// on-loop `FsConn::offload` path. It keeps `floor` threads warm and grows to
/// `ceiling` when every worker is busy (blocked on a slow `readdir` or copy),
/// so one stalled walk does not head-of-line-block the rest; burst workers
/// retire after an idle period. It runs whatever job it is handed under the
/// reactor's ambient credentials; any per-`who` permission check belongs to the
/// job, not the pool.
///
/// Growth is hysteretic: a worker spawns only when the pool is saturated
/// (no worker is parked) and at most once per cooldown, so a burst of fast
/// cached jobs clears without thread churn while genuinely blocking work grows.
/// Dropping the pool closes the queue and waits for every worker to exit, so a
/// job's effects are complete before the dropper proceeds - bounded by
/// [`SHUTDOWN_DETACH_AFTER`], after which the remaining workers are left to
/// exit on their own.
pub(crate) struct WorkerPool {
    shared: Arc<PoolShared>,
}

impl WorkerPool {
    /// An elastic pool: `floor` (at least 1) warm threads growing to `ceiling`
    /// under saturation, using the default cooldown and idle timeout. Returns
    /// the spawn error rather than panicking.
    pub(crate) fn try_elastic(
        bounds: OffloadBounds,
    ) -> std::io::Result<WorkerPool> {
        Self::try_elastic_tuned(
            bounds,
            OFFLOAD_SPAWN_COOLDOWN,
            OFFLOAD_IDLE_TIMEOUT,
        )
    }

    /// [`try_elastic`](Self::try_elastic) with explicit timings (for tests). On
    /// a partial spawn failure the workers already started are shut down and
    /// waited for before returning, so none is orphaned.
    pub(crate) fn try_elastic_tuned(
        bounds: OffloadBounds,
        cooldown: Duration,
        idle_timeout: Duration,
    ) -> std::io::Result<WorkerPool> {
        let floor = bounds.floor.max(1);
        let ceiling = bounds.ceiling.max(floor);
        let shared = Arc::new(PoolShared {
            inner: Mutex::new(PoolInner {
                queue: VecDeque::new(),
                total: 0,
                idle: 0,
                notify: 0,
                closed: false,
                last_spawn_us: 0,
                #[cfg(test)]
                last_flush_wakes: 0,
                #[cfg(test)]
                wakes_issued: 0,
            }),
            cv: Condvar::new(),
            floor,
            ceiling,
            epoch: Instant::now(),
            cooldown,
            idle_timeout,
            #[cfg(loom)]
            retire_next_idle: AtomicUsize::new(0),
            #[cfg(loom)]
            detach_next_drop: AtomicUsize::new(0),
        });
        let pool = WorkerPool {
            shared: Arc::clone(&shared),
        };
        for _ in 0..floor {
            // Spawn under the lock and count only on success -- see `submit`.
            let spawned = {
                let mut g =
                    shared.inner.lock().unwrap_or_else(|e| e.into_inner());
                spawn_worker(&shared).map(|()| g.total += 1)
            };
            if let Err(e) = spawned {
                drop(pool); // closes and waits for the workers already started
                return Err(e);
            }
        }
        Ok(pool)
    }

    /// Enqueue `job` and wake the pool for it at once: [`enqueue`] then
    /// [`flush`] of one. Production submitters go through [`SharedPool`],
    /// which batches; this is the tests' one-job spelling.
    ///
    /// [`enqueue`]: Self::enqueue
    /// [`flush`]: Self::flush
    #[cfg(test)]
    pub(crate) fn submit(&self, job: Job) {
        self.enqueue(job);
        self.flush(1);
    }

    /// Queue `job` and wake nobody. The caller owes a [`flush`](Self::flush)
    /// before it can block, or the job waits for a running worker to
    /// reach it; a loop pays that once per turn for every job the turn
    /// queued, which is what makes a batch of them one *pass* rather than
    /// a wake per `offload`. The pass still wakes one worker per job - see
    /// [`flush`](Self::flush) for why it does not ration them.
    pub(crate) fn enqueue(&self, job: Job) {
        let mut g = self.shared.inner.lock().unwrap_or_else(|e| e.into_inner());
        if g.closed {
            return;
        }
        g.queue.push_back(job);
    }

    /// Wake the pool for the jobs sitting in its queue: **one** parked
    /// worker, which hands the next on as it takes its job, and grow by one
    /// worker where the caller's count outruns those still parked and the
    /// cooldown has elapsed (a no-op if the pool is already dropping).
    ///
    /// A woken worker drains the queue whole, so one wake is *correct* for
    /// any batch - but alone it serialises the batch onto one thread, which
    /// is the opposite of what an offload pool is for. Measured on an idle
    /// sixteen-worker pool, 10 ms jobs, same binary: a one-wake-per-four
    /// rule takes 40.3 ms where the chain takes 10.1 ms, at 4, 8 and 16
    /// queued alike.
    ///
    /// So the parallelism is recruited, but not from here. Each worker
    /// claims the next as it pops its own job, under the lock it is already
    /// holding ([`worker_loop`]), which keeps this call O(1): every
    /// `notify_one` is a `futex_wake` syscall whether or not anyone is
    /// waiting, and issuing a batch of them from here means issuing them on
    /// the reactor thread, while holding the mutex the woken workers
    /// immediately need. Measured p50 of this call: ~1.1 us at 16 parked
    /// and at 64 alike, against 21 us and 77 us for a wake per job.
    ///
    /// Two things made that cost unacceptable rather than merely untidy.
    /// Below roughly 10 us of job work the wakes dominate and the batch is
    /// slower end to end than the ratio it replaced - at depth 16 with
    /// near-empty jobs, a wake per job spends 85% of the batch's wall time
    /// in this function. And [`SharedPool::submit`] reaches here from
    /// `QueryPool::query`, a public call documented non-blocking, on an
    /// application thread and with the *reactor's* queue depth: sized per
    /// job that is 1.2 us at an empty queue and 1.07 ms at a full one.
    ///
    /// `pending` is the caller's "something happened this turn" gate and
    /// the growth decision's input; it is no use as a wake count, since it
    /// over-counts a job the pool ran inline and under-counts the jobs of
    /// another submitter sharing this pool. What needs waking comes from
    /// `queue` against `notify` ([`unclaimed`]) - an outstanding `notify`
    /// is a worker already on its way. Growth keeps `pending` on purpose:
    /// see [`JOBS_PER_WORKER_BEFORE_GROWTH`] and
    /// `a_flush_of_one_does_not_grow_against_the_queue`.
    ///
    /// The growth *predicate* is the parent's; its input is not frozen and
    /// cannot be. `parked` is live `idle`, so **any** rule that recruits
    /// more workers moves when growth fires - including this one. Measured
    /// on the default bounds: four blocking jobs leave `idle == 0` here,
    /// because four workers really are running them, and the next job then
    /// grows the pool to five. The parent left `idle == 3` in the same
    /// state, with three of those jobs still queued and nobody woken for
    /// them, and so did not grow.
    ///
    /// That difference is the wake fix showing through, not a second
    /// change: `idle` now means what it says. Growing when every worker is
    /// occupied and more work has arrived is what the type's own docs
    /// describe as saturation. It does mean a loaded pool reaches its
    /// ceiling sooner than it used to, which is a behaviour change worth
    /// knowing about even though the rule generating it is unchanged.
    pub(crate) fn flush(&self, pending: usize) {
        if pending == 0 {
            return;
        }
        let mut g = self.shared.inner.lock().unwrap_or_else(|e| e.into_inner());
        if g.closed {
            return;
        }
        // Jobs with no worker coming for them: every outstanding `notify`
        // is a claim on one queued job, so the rest are what this call
        // has to cover. Taken from the queue rather than from `pending`
        // for the reasons in the doc above.
        let parked = g.idle;
        // ONE wake, whatever the batch. The worker it claims hands the next
        // one on before it goes heads-down (`worker_loop`), so a batch of N
        // still reaches N workers - but the chain is paid one link at a
        // time, by workers who are waking anyway and already hold this
        // lock, instead of N `futex_wake` syscalls issued back to back by
        // whoever called `flush` while holding the mutex those workers
        // immediately need.
        //
        // That distinction is the whole cost model. Measured p50 of this
        // call, 16 parked workers: a wake per job is 21 us at depth 16 and
        // 77 us at 64, against ~1.3 us flat here; and `SharedPool::submit`,
        // a public non-blocking API, reaches this on an application thread
        // with the reactor's queue depth, not its own.
        let claimed = usize::from(unclaimed(&g) > 0 && g.idle > 0);
        if claimed == 1 {
            claim_one(&self.shared, &mut g);
        }
        #[cfg(test)]
        {
            g.last_flush_wakes = claimed;
        }
        // Growth is the parent's rule, unchanged, on the parent's input.
        // It read `g.idle == 0 && wakes < wanted` *after* waking; with
        // `wakes = min(wanted, idle)` that is true exactly when
        // `idle < wanted`, so it says "the turn queued more than four jobs
        // per parked worker". Restated here on the pre-wake count, where
        // it reads as what it means.
        //
        // Both of its inputs are deliberate. Deriving it from the new wake
        // count would drop the threshold to one job per parked worker -
        // measured, floor 4 with three workers busy grows on 2 queued jobs
        // where the parent needs 5 - and taking it from `unclaimed` rather
        // than `pending` would let the off-loop submitter's hard-coded
        // `flush(1)` spawn against the reactor's queued jobs, which it
        // never could before. Each spawn is a `pthread_create` under this
        // lock, and `flush` runs on the reactor thread. One change in this
        // patch: the wake count.
        // No `.max(1)`: `pending == 0` returned above, so the quotient is
        // already at least one. The parent carried one for the same dead
        // reason. What the predicate really turns on is that it is
        // unconditionally true when `parked == 0` - a turn that queued
        // anything and found nobody parked grows, which is the saturated
        // case the type's docs describe.
        let saturated =
            pending.div_ceil(JOBS_PER_WORKER_BEFORE_GROWTH) > parked;
        // Spawn under the lock, counting the worker only once it has started.
        // Reserving the slot first and handing it back on failure would put a
        // third decrement of `total` on a path with none of the guards the
        // idle retire has: `Drop` waits for `total` to reach zero, and a
        // reserved slot has no worker exit coming to signal on its behalf, so
        // a submit racing a drop could lower the count in silence and park
        // `Drop` on the condvar forever. Counting only what exists leaves a
        // failed spawn touching no shared state. The cost is holding the lock
        // across a thread creation, bounded by the growth cooldown.
        if saturated
            && g.total < self.shared.ceiling
            && self.shared.claim_spawn_slot(&mut g)
            && spawn_worker(&self.shared).is_ok()
        {
            g.total += 1;
        }
        // A failed spawn leaves the job queued for a busy worker to pick up.
    }
}

impl PoolShared {
    /// Model-only: let the next `n` workers to wake take the retire branch
    /// instead of looping. Standing in for a clock loom does not have - see
    /// [`idle_expired`].
    ///
    /// A budget rather than a one-shot on purpose: with only one retirement
    /// granted the retiring worker is never the last, so a model could not
    /// tell a pool that correctly refuses to retire its final worker from one
    /// that does not.
    #[cfg(all(test, loom))]
    fn retire_idle_workers(&self, n: usize) {
        self.retire_next_idle.store(n, Ordering::Relaxed);
        self.cv.notify_all();
    }

    /// Model-only: let the next `n` `Drop`s detach instead of waiting the
    /// workers out. Standing in for a clock loom does not have - see
    /// [`shutdown_expired`].
    #[cfg(all(test, loom))]
    fn detach_next_drop(&self, n: usize) {
        self.detach_next_drop.store(n, Ordering::Relaxed);
    }

    /// True at most once per [`cooldown`](Self::cooldown), claiming the slot so
    /// concurrent submits do not all spawn at once.
    ///
    /// Takes the guard because the throttle lives in [`PoolInner`]: the only
    /// caller is `submit`, which holds the lock across the whole growth
    /// decision, so a compare-exchange here could never lose a race and would
    /// advertise a lock-free contract the code does not implement.
    fn claim_spawn_slot(&self, inner: &mut PoolInner) -> bool {
        let now = self.epoch.elapsed().as_micros() as u64;
        let cooldown = self.cooldown.as_micros() as u64;
        if now.saturating_sub(inner.last_spawn_us) < cooldown {
            return false;
        }
        inner.last_spawn_us = now;
        true
    }
}

// The identity of the pool this thread is a worker of (`Arc::as_ptr` of its
// `PoolShared`), or null off the pools. `WorkerPool::drop` can run on a
// worker when a job drops a pool's last `Arc`; the identity tells that `Drop`
// whether the join it wants would wait on the current thread itself (its own
// pool - skip it, the workers exit on `closed` alone) or only on other
// threads (a different pool - join it like any thread would). A bare "am I a
// worker" flag cannot tell those apart and leaks the exemption to every pool
// in the process. Tokio's blocking workers carry the same identity by
// entering their runtime's context at spawn (`spawn_thread`,
// `runtime/blocking/pool.rs`), and a foreign runtime dropped on one of them
// is likewise waited out (`Receiver::wait`, `runtime/blocking/shutdown.rs`).
//
// Under loom this must be loom's thread-local, not std's: loom multiplexes
// every modelled thread onto one OS thread, so a std `thread_local!` would
// let a worker's identity leak into the main thread and make `Drop` skip a
// join it really needed. (loom's macro takes no `const` initializer.)
#[cfg(not(loom))]
thread_local! {
    static ON_POOL_WORKER: Cell<*const PoolShared> =
        const { Cell::new(std::ptr::null()) };
}
#[cfg(loom)]
loom::thread_local! {
    static ON_POOL_WORKER: Cell<*const PoolShared> =
        Cell::new(std::ptr::null());
}

/// How long `WorkerPool::drop` waits for its workers before detaching them.
///
/// The wait exists so a job's effects are complete before the dropper
/// proceeds; it is bounded because the dropping thread is not always one that
/// can afford to block forever. `Drop` runs wherever the last handle falls -
/// including on ANOTHER pool's worker, or on a thread serving requests - and
/// an offload parked in a syscall against a wedged backing would otherwise
/// consume that thread for the life of the process.
///
/// A process exiting has a backstop for that and a running one does not: FUSE
/// (`fs/fuse/dev.c:212`) and sunrpc (`net/sunrpc/sched.c:346`) both wait
/// `TASK_KILLABLE`, so a supervisor's SIGKILL reaps the wedged worker at
/// teardown. Mid-run nothing does, and the symptom is a daemon quietly losing
/// threads while systemd sees a healthy unit.
///
/// Long enough that a pool draining normally is never detached (workers exit
/// as soon as they finish the job in hand), short enough to bound the damage.
const SHUTDOWN_DETACH_AFTER: Duration = Duration::from_secs(2);

/// Whether `Drop`'s bounded wait has run out and the remaining workers should
/// be detached.
///
/// In production this is the condvar's own answer. Under `--cfg loom` there is
/// no clock and `Condvar::wait_timeout` always reports `timed_out() == false`
/// (`sync.rs`), so the detach branch would be unreachable in a model. The seam
/// lets a model ask for the detach directly, the way [`idle_expired`] does for
/// the idle retire.
#[cfg(not(loom))]
fn shutdown_expired(
    wait: &std::sync::WaitTimeoutResult,
    _shared: &Arc<PoolShared>,
) -> bool {
    wait.timed_out()
}

#[cfg(loom)]
fn shutdown_expired(
    _wait: &loom::sync::WaitTimeoutResult,
    shared: &Arc<PoolShared>,
) -> bool {
    shared
        .detach_next_drop
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
            n.checked_sub(1)
        })
        .is_ok()
}

/// The deadline `Drop`'s bounded wait runs against.
///
/// Passing [`SHUTDOWN_DETACH_AFTER`] to each `wait_timeout` would restart the
/// clock on every wake, and every worker exit notifies - so a pool of `n`
/// workers with one wedged member bounds the wait at `n x
/// SHUTDOWN_DETACH_AFTER` rather than at `SHUTDOWN_DETACH_AFTER`, and a
/// spurious wake bounds it at nothing. That defeats the reason the wait is
/// bounded at all: `Drop` runs wherever the last handle falls, including on a
/// thread serving requests, and two minutes there is the harm this is
/// supposed to prevent. Detaching a pool that is still draining is sound (see
/// `Drop`), so the deadline is absolute.
///
/// Under `--cfg loom` there is no clock (`src/sync.rs`), and none is needed:
/// `wait_timeout` never times out there, so the detach is driven by
/// [`shutdown_expired`]'s model seam and the remaining duration is never read
/// for its value.
#[cfg(not(loom))]
struct ShutdownClock(Instant);

#[cfg(not(loom))]
impl ShutdownClock {
    fn start() -> ShutdownClock {
        ShutdownClock(Instant::now())
    }

    /// What is left of the budget; zero once it is spent.
    fn remaining(&self) -> Duration {
        SHUTDOWN_DETACH_AFTER.saturating_sub(self.0.elapsed())
    }
}

#[cfg(loom)]
struct ShutdownClock;

#[cfg(loom)]
impl ShutdownClock {
    fn start() -> ShutdownClock {
        ShutdownClock
    }

    fn remaining(&self) -> Duration {
        SHUTDOWN_DETACH_AFTER
    }
}

impl Drop for WorkerPool {
    fn drop(&mut self) {
        let mut g = self.shared.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.closed = true;
        self.shared.cv.notify_all();
        // Running on one of THIS pool's workers (a job dropped the pool's
        // last `Arc`): the thread is itself counted in `total`, so waiting
        // the workers out here would wait on this very thread forever. Each
        // worker owns an `Arc<PoolShared>`, so they exit and reclaim the
        // shared state on their own once `closed` is set, with no join
        // needed. A different pool's worker gets no exemption - this pool's
        // `total` does not count that thread, and skipping the join there
        // would silently void the contract below for every cross-pool drop
        // (`try_elastic_tuned`'s partial-failure unwind relies on it).
        if ON_POOL_WORKER.with(Cell::get) == Arc::as_ptr(&self.shared) {
            return;
        }
        // Wait for the workers to drain and exit, so none touches the shared
        // state after this returns (join-on-drop without tracking handles) --
        // but only up to `SHUTDOWN_DETACH_AFTER`, then leave them to it.
        //
        // Detaching is sound because `Job` is `Box<dyn FnOnce() + Send>`, hence
        // `'static`: a job cannot hold a borrow of anything the dropper is
        // about to free. Each worker owns an `Arc<PoolShared>`, so the shared
        // state outlives them too, and `closed` is already set - they exit on
        // their own with nothing left to signal. The wait buys quiescence, not
        // soundness, which is why it is worth bounding.
        //
        // One deadline for the whole wait, not one per wake: every worker exit
        // notifies, so re-passing the full timeout would multiply the bound by
        // the worker count and a spurious wake would remove it entirely. See
        // [`ShutdownClock`].
        let clock = ShutdownClock::start();
        while g.total > 0 {
            let left = clock.remaining();
            if left.is_zero() {
                break; // detached: they exit on `closed` alone
            }
            let (guard, wait) = self
                .shared
                .cv
                .wait_timeout(g, left)
                .unwrap_or_else(|e| e.into_inner());
            g = guard;
            if shutdown_expired(&wait, &self.shared) {
                break; // detached: they exit on `closed` alone
            }
        }
    }
}

/// Spawn one worker thread bound to `shared`. The caller has already accounted
/// it in `total`; the worker decrements `total` when it exits.
fn spawn_worker(shared: &Arc<PoolShared>) -> std::io::Result<()> {
    let shared = Arc::clone(shared);
    thread::Builder::new()
        .name("truenas-fs-worker".into())
        .spawn(move || worker_loop(&shared))
        .map(|_| ())
}

/// One lazily-spawned [`WorkerPool`] shared by a reactor's on-loop offloads
/// (`FsConn::offload`) and its off-loop `QueryPool`, so the reactor has a
/// single blocking-work thread budget. Cheap to clone (`Arc`); the floor
/// threads spawn on the first submit, and if a worker cannot be spawned the job
/// runs inline (a degraded loop, not a dead one).
pub(crate) struct SharedPool {
    pool: OnceCell<WorkerPool>,
    bounds: OffloadBounds,
    /// Epoch for [`retry_spawn_us`](Self::retry_spawn_us).
    epoch: Instant,
    /// Micros since `epoch` before the lazy spawn is attempted again, or `0`
    /// when none has failed.
    ///
    /// A failure backs off rather than latching. Whatever refused the thread
    /// (`EAGAIN`, an `RLIMIT_NPROC`, a cgroup `pids.max`) is usually another
    /// process's transient squeeze, and latching would demote every later job
    /// to running inline on the reactor for the rest of the process's life,
    /// the exact head-of-line stall this pool exists to prevent. Jobs still run
    /// inline while backing off; a submit past the deadline retries the spawn.
    retry_spawn_us: AtomicU64,
}

/// How long a failed lazy spawn runs jobs inline before trying again. Long
/// enough that a persistent failure does not thrash a full floor spawn per
/// submit, short enough that a transient one is not a lasting degradation.
const SPAWN_RETRY_BACKOFF: Duration = Duration::from_secs(1);

impl fmt::Debug for SharedPool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SharedPool")
            .field("spawned", &self.pool.is_set())
            .field(
                "retry_spawn_us",
                &self.retry_spawn_us.load(Ordering::Relaxed),
            )
            .finish_non_exhaustive()
    }
}

impl SharedPool {
    /// A shared pool sized by `bounds`; no threads spawn until the first
    /// [`submit`](Self::submit).
    pub(crate) fn new(bounds: OffloadBounds) -> Arc<SharedPool> {
        let floor = bounds.floor.max(1);
        Arc::new(SharedPool {
            pool: OnceCell::new(),
            bounds: OffloadBounds {
                floor,
                ceiling: bounds.ceiling.max(floor),
            },
            epoch: Instant::now(),
            retry_spawn_us: AtomicU64::new(0),
        })
    }

    /// Submit a job and wake for it at once: [`enqueue`](Self::enqueue)
    /// then a [`flush`](Self::flush) of one, for a submitter with no turn
    /// to batch in - the off-loop query helpers.
    pub(crate) fn submit(&self, job: Job) {
        self.enqueue(job);
        self.flush(1);
    }

    /// Wake the pool for `pending` jobs queued since the last flush
    /// ([`WorkerPool::flush`]); nothing to do until the pool exists,
    /// since an enqueue that found no pool ran its job inline.
    pub(crate) fn flush(&self, pending: usize) {
        self.pool.with(|pool| pool.flush(pending));
    }

    /// Queue a job without a wake, spawning the pool on first use. A lost
    /// init race just drops the surplus pool (its `Drop` joins the idle
    /// workers); a spawn failure runs the job inline rather than take the
    /// reactor down. The caller owes a [`flush`](Self::flush) before it
    /// blocks.
    pub(crate) fn enqueue(&self, job: Job) {
        // `job` is `FnOnce`, so it can only be handed to one arm; take it back
        // out of the cell when the pool was not there to receive it.
        let mut job = Some(job);
        if let Some(()) = self
            .pool
            .with(|pool| pool.enqueue(job.take().expect("first use")))
        {
            return;
        }
        let job = job.expect("untouched when the cell was empty");
        let now = self.epoch.elapsed().as_micros() as u64;
        if now < self.retry_spawn_us.load(Ordering::Relaxed) {
            return job(); // backing off a recent failure; don't retry per job
        }
        match WorkerPool::try_elastic(self.bounds) {
            Ok(pool) => {
                // A lost race just drops the surplus pool here; its `Drop`
                // joins the workers it started before they can touch anything.
                self.pool.set(pool);
                let mut job = Some(job);
                self.pool
                    .with(|pool| pool.enqueue(job.take().expect("first use")));
            }
            Err(_) => {
                self.retry_spawn_us.store(
                    now.saturating_add(SPAWN_RETRY_BACKOFF.as_micros() as u64),
                    Ordering::Relaxed,
                );
                job();
            }
        }
    }
}

/// Whether a `wait_timeout` return means the worker has been idle long enough
/// to retire.
///
/// In production this is just the condvar's own answer. Under `--cfg loom`
/// there is no clock and `Condvar::wait_timeout` always reports
/// `timed_out() == false`, which would make the retire branch below - the one
/// that decrements `total` *without* notifying, unlike the closing path --
/// unreachable in a model. The seam lets a model ask for the retirement
/// directly, so the interleaving that branch relies on can actually be
/// explored. See [`PoolShared::retire_next_idle`].
#[cfg(not(loom))]
fn idle_expired(
    wait: &std::sync::WaitTimeoutResult,
    _shared: &Arc<PoolShared>,
) -> bool {
    wait.timed_out()
}

#[cfg(loom)]
fn idle_expired(
    _wait: &loom::sync::WaitTimeoutResult,
    shared: &Arc<PoolShared>,
) -> bool {
    // The model arms a budget; each waking worker consumes one.
    shared
        .retire_next_idle
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
            n.checked_sub(1)
        })
        .is_ok()
}

/// A worker: wait for a job, run it, repeat; `K` workers run `K` jobs
/// concurrently. A burst worker idle past the idle timeout retires (never below
/// the floor); on shutdown every worker drains the queue and exits, decrementing
/// `total` so [`WorkerPool`]'s `Drop` can wait them all out.
///
/// Each job runs under `catch_unwind`, so a panicking job retires only itself,
/// not the worker: the pool keeps draining, and a later `submit` is not
/// silently dropped onto a dead thread. Any handle the job owned (a `SendDir`)
/// still closes as its unwinding frame drops.
fn worker_loop(shared: &Arc<PoolShared>) {
    // Even under loom: the identity is read by `Drop`, which the models
    // exercise (a job dropping the pool's last `Arc`).
    ON_POOL_WORKER.with(|w| w.set(Arc::as_ptr(shared)));
    let mut g = shared.inner.lock().unwrap_or_else(|e| e.into_inner());
    loop {
        // Everything queued, before parking: a submit that found no idle
        // worker queued its job and woke nobody, counting on a running
        // worker to reach it here.
        while let Some(job) = g.queue.pop_front() {
            // Hand the wake on before going heads-down. This is the rest of
            // the batch's parallelism: `flush` claims one worker, and each
            // worker claims the next while it still holds the lock it took
            // to pop its own job, so N queued jobs reach N workers at a cost
            // of one `futex_wake` per worker recruited - none of them on the
            // reactor thread, and none of them holding the lock any longer
            // than it already was.
            if unclaimed(&g) > 0 && g.idle > 0 {
                claim_one(shared, &mut g);
            }
            drop(g);
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(job));
            g = shared.inner.lock().unwrap_or_else(|e| e.into_inner());
        }
        if g.closed {
            g.total -= 1;
            shared.cv.notify_all();
            return;
        }
        g.idle += 1;
        loop {
            // A floor worker never retires, so it has no timeout to keep:
            // an untimed wait arms no hrtimer. Only a pool above its floor
            // waits on the clock, and any of its workers may be the one to
            // retire.
            let expired = if g.total > shared.floor {
                let (guard, wait) = shared
                    .cv
                    .wait_timeout(g, shared.idle_timeout)
                    .unwrap_or_else(|e| e.into_inner());
                g = guard;
                idle_expired(&wait, shared)
            } else {
                g = shared.cv.wait(g).unwrap_or_else(|e| e.into_inner());
                false
            };
            if g.notify > 0 {
                // A submit claimed this worker and already took it out of
                // `idle`; the job it queued is what the drain above finds.
                g.notify -= 1;
                break;
            }
            // **Scope.** This is a second line, not a replacement for the
            // flush contract, and it is worth being exact about what can
            // reach it. Claimless wakeups come from four places: a burst
            // worker's own `wait_timeout` expiry, the broadcast a retiring
            // worker issues, the one a worker exiting on `closed` issues,
            // and `WorkerPool::drop`'s - plus the condvar's own spurious
            // wakeups, which `PoolInner::notify`'s doc already names. Only
            // the first is periodic; the rest are events.
            //
            // A retire cannot be *caused* by the job sitting here, since
            // retiring needs `g.queue.is_empty()`, but it can still arrive
            // here: the retiring worker tests that predicate and
            // broadcasts under the guard, and an `enqueue` that lands
            // after it releases leaves a woken worker - a floor worker
            // included - looking at a queue that is no longer empty. So
            // this arm is not confined to pools above their floor, and the
            // bound is not a clean `OFFLOAD_IDLE_TIMEOUT`.
            //
            // What is true unconditionally: nothing here is periodic at
            // the floor, where every worker waits untimed. A job whose
            // flush was missed can therefore wait arbitrarily long on a
            // quiet pool, so the flush contract - every enqueue owing one
            // before its caller blocks - remains the invariant, and this
            // arm is what turns a flush that under-woke into a delay
            // rather than a stall.
            if !g.queue.is_empty() {
                // Work with no claim on it: a submit only wakes workers it
                // takes out of `idle`, so a job queued by a path that never
                // flushed has nobody coming for it. A later claimed wake
                // would still rescue it - the drain at the top of the outer
                // loop empties the queue, it does not take one job - but a
                // floor worker waits UNTIMED, so if no further work arrives
                // there is no next wake and no tick either. Breaking here
                // makes every wakeup this worker gets, claimed or not, a
                // chance to notice the job; that is the re-check the timed
                // wait used to provide for free.
                g.idle -= 1;
                break;
            }
            if g.closed {
                g.idle -= 1;
                break;
            }
            // No `g.queue.is_empty()` here: the claimless arm above
            // already broke out on a non-empty queue, under this same
            // uninterrupted guard, so it would be dead - and a dead
            // conjunct reads as a live guard to whoever reorders these
            // arms next. The ordering IS the guard.
            if expired && g.total > shared.floor {
                g.idle -= 1;
                g.total -= 1; // idle burst worker retires
                shared.cv.notify_all();
                return;
            }
            // Spurious, or the model's retire budget refused: back to sleep.
        }
    }
}

#[cfg(all(test, not(loom)))]
mod pool_tests {
    use super::*;
    use crate::sync::mpsc;

    /// Bounds with explicit floor and ceiling.
    fn bounds(floor: usize, ceiling: usize) -> OffloadBounds {
        OffloadBounds { floor, ceiling }
    }

    /// The elastic pool grows past its floor when every worker is blocked, up to
    /// the ceiling, then retires the burst workers once they sit idle.
    #[test]
    fn offload_pool_grows_under_saturation_then_reclaims_when_idle() {
        // Floor 1, ceiling 4; no growth cooldown (deterministic under the
        // start-synchronised submits below) and a quick idle timeout.
        let pool = WorkerPool::try_elastic_tuned(
            bounds(1, 4),
            Duration::ZERO,
            Duration::from_millis(50),
        )
        .expect("pool");

        let release = Arc::new((Mutex::new(false), Condvar::new()));
        let (started_tx, started_rx) = mpsc::channel::<()>();

        // Submit blocking jobs one at a time, waiting until each is actually
        // running before the next, so the growth decision sees an accurate
        // `running` count rather than racing ahead of the workers.
        for _ in 0..4 {
            let r = Arc::clone(&release);
            let s = started_tx.clone();
            pool.submit(Box::new(move || {
                s.send(()).unwrap();
                let (m, cv) = &*r;
                let mut held = m.lock().unwrap();
                while !*held {
                    held = cv.wait(held).unwrap();
                }
            }));
            started_rx.recv().unwrap();
        }

        let grown = pool.shared.inner.lock().unwrap().total;

        // Release the blocked jobs first, so a failing assertion cannot wedge
        // teardown (Drop waits for every worker to exit).
        {
            let (m, cv) = &*release;
            *m.lock().unwrap() = true;
            cv.notify_all();
        }
        assert_eq!(grown, 4, "grew from floor 1 to ceiling 4 under saturation");

        // Idle burst workers retire back to the floor.
        let mut total = grown;
        for _ in 0..200 {
            total = pool.shared.inner.lock().unwrap().total;
            if total == 1 {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(total, 1, "burst workers retired back to the floor");
    }

    /// Spin until `f` holds of the pool's inner state, then return it.
    fn settle(pool: &WorkerPool, what: &str, f: impl Fn(&PoolInner) -> bool) {
        for _ in 0..3000 {
            {
                let g = pool.shared.inner.lock().unwrap();
                if f(&g) {
                    return;
                }
            }
            thread::sleep(Duration::from_millis(1));
        }
        panic!("pool never settled: {what}");
    }

    /// Poll for `f` without panicking, so a caller holding jobs hostage can
    /// release them before it asserts. `settle` panics, which would leave
    /// blocked jobs blocked and teardown waiting them out.
    fn reaches(pool: &WorkerPool, f: impl Fn(&PoolInner) -> bool) -> bool {
        for _ in 0..3000 {
            {
                let g = pool.shared.inner.lock().unwrap();
                if f(&g) {
                    return true;
                }
            }
            thread::sleep(Duration::from_millis(1));
        }
        false
    }

    /// Every worker parked and nothing owed: the quiescent state each test
    /// below returns the pool to before asserting on its books.
    fn quiesced(g: &PoolInner) -> bool {
        g.notify == 0 && g.idle == g.total && g.queue.is_empty()
    }

    /// An `enqueue` wakes nobody; a `flush` wakes exactly one parked
    /// worker, and the chain carries the batch from there.
    ///
    /// Asserted on `wakes_issued` rather than on how the jobs then run.
    /// The wake count is the property, and it is the only one that stays
    /// observable: an extra wake leaves no trace afterwards, since the
    /// worker it woke finds the queue empty, consumes its `notify` and
    /// parks again with every counter balanced.
    #[test]
    fn an_enqueue_wakes_nobody_and_a_flush_wakes_once_for_the_batch() {
        // Three numbers that must not coincide: the jobs, the workers, and
        // `JOBS_PER_WORKER_BEFORE_GROWTH`. With all three equal - which is
        // what `bounds(JOBS, JOBS)` and `JOBS == 4` gave - every candidate
        // wake rule returns the same count and the assertion below pins
        // none of them.
        const JOBS: usize = 3;
        const FLOOR: usize = 5;
        let pool = WorkerPool::try_elastic_tuned(
            bounds(FLOOR, FLOOR),
            Duration::from_millis(1),
            Duration::from_secs(10),
        )
        .expect("pool");
        settle(&pool, "floor parked", |g| g.idle == FLOOR);

        // Each job blocks until released, so a worker that takes one
        // cannot also take the next: the batch can only reach `JOBS`
        // workers if the chain actually recruited them.
        let hold = Arc::new((Mutex::new(false), Condvar::new()));
        for _ in 0..JOBS {
            let h = Arc::clone(&hold);
            pool.enqueue(Box::new(move || {
                let (m, cv) = &*h;
                let mut held = m.lock().unwrap();
                while !*held {
                    held = cv.wait(held).unwrap();
                }
            }));
        }
        {
            let g = pool.shared.inner.lock().unwrap();
            assert_eq!(g.queue.len(), JOBS, "queued, not run");
            assert_eq!(g.wakes_issued, 0, "an enqueue woke somebody");
            assert_eq!(g.idle, FLOOR, "an enqueue claimed a worker");
        }

        pool.flush(JOBS);
        let flush_cost = pool.shared.inner.lock().unwrap().last_flush_wakes;
        let chained = reaches(&pool, |g| g.wakes_issued == JOBS);
        // Release before asserting: a failed assertion must not leave the
        // jobs blocked and `Drop` waiting them out.
        {
            let (m, cv) = &*hold;
            *m.lock().unwrap() = true;
            cv.notify_all();
        }
        assert_eq!(
            flush_cost, 1,
            "a flush must cost the caller exactly one wake, whatever the \
             batch: the rest are handed on by the workers"
        );
        assert!(chained, "the chain did not reach one worker per job");
        settle(&pool, "quiescent", quiesced);
    }

    /// A flush wakes no more workers than it has jobs for. The fixture
    /// has four times the
    /// workers it has jobs, so `unclaimed` and `parked` differ and a rule
    /// that woke `parked` would show: where `floor == jobs`, as every other
    /// fixture here has it, the two are the same number and nothing shows.
    ///
    /// This pins one direction. The other - never claiming a worker that
    /// is not parked - is guarded rather than asserted: both `claim_one`
    /// call sites test `g.idle > 0` first, and `claim_one` debug-asserts
    /// it. In release that assert is compiled out, so what actually holds
    /// it is the `idle + notify == workers-in-the-wait` invariant, which
    /// the loom model exercises.
    ///
    /// This is the wake economy the whole protocol is justified by -
    /// `notify_one` is a `futex_wake` whether or not anyone is waiting, and
    /// these are issued on the reactor thread under the queue lock.
    #[test]
    fn a_flush_wakes_no_more_workers_than_it_has_jobs_for() {
        const FLOOR: usize = 8;
        const JOBS: usize = 2;
        let pool = WorkerPool::try_elastic_tuned(
            bounds(FLOOR, FLOOR),
            Duration::from_millis(1),
            Duration::from_secs(10),
        )
        .expect("pool");
        settle(&pool, "floor parked", |g| g.idle == FLOOR);

        for _ in 0..JOBS {
            pool.enqueue(Box::new(|| {}));
        }
        pool.flush(JOBS);
        assert_eq!(
            pool.shared.inner.lock().unwrap().last_flush_wakes,
            1,
            "a flush must cost one wake whatever is parked"
        );
        settle(&pool, "quiescent", quiesced);
        assert!(
            pool.shared.inner.lock().unwrap().wakes_issued <= JOBS,
            "the chain woke workers it had no jobs for"
        );
    }

    /// `flush` takes its wake count from the queue, not from its caller.
    /// The off-loop submitter ([`SharedPool::submit`]) always passes one,
    /// having only its own job to declare, but it shares this pool with a
    /// reactor whose jobs may already be queued unflushed - so a count of
    /// one has to wake for all of them, or it serialises the lot onto the
    /// single worker it woke.
    #[test]
    fn a_flush_of_one_wakes_for_every_job_already_queued() {
        const QUEUED: usize = 5;
        let pool = WorkerPool::try_elastic_tuned(
            bounds(QUEUED, QUEUED),
            Duration::from_millis(1),
            Duration::from_secs(10),
        )
        .expect("pool");
        settle(&pool, "floor parked", |g| g.idle == QUEUED);

        let hold = Arc::new((Mutex::new(false), Condvar::new()));
        for _ in 0..QUEUED {
            let h = Arc::clone(&hold);
            pool.enqueue(Box::new(move || {
                let (m, cv) = &*h;
                let mut held = m.lock().unwrap();
                while !*held {
                    held = cv.wait(held).unwrap();
                }
            }));
        }
        // The off-loop submitter's count: one, for a queue of five.
        pool.flush(1);
        let flush_cost = pool.shared.inner.lock().unwrap().last_flush_wakes;
        let chained = reaches(&pool, |g| g.wakes_issued == QUEUED);
        {
            let (m, cv) = &*hold;
            *m.lock().unwrap() = true;
            cv.notify_all();
        }
        assert_eq!(
            flush_cost, 1,
            "an application thread paid the reactor's queue depth in wakes"
        );
        assert!(chained, "a flush of one serialised a queue of {QUEUED}");
        settle(&pool, "quiescent", quiesced);
    }

    /// Removing the one-wake-per-four batching must not move the growth
    /// threshold with it: both answers came off the same constant.
    ///
    /// Sampled either side of the boundary, because a point well inside it
    /// cannot tell the rules apart - at floor 4 the parent grows from 17
    /// jobs and a `>=` slip grows from 13, so a burst of 8 satisfies
    /// neither and pins nothing. The spawn decision is taken inside
    /// `flush` under the guard, so the count right after it returns is the
    /// decision, with no race.
    #[test]
    fn the_growth_threshold_did_not_move_with_the_wake_count() {
        const FLOOR: usize = 4;
        // ceil(n / 4) > 4 is false at 16 and true at 17.
        for (jobs, want_total, what) in
            [(16usize, FLOOR, "below"), (17, FLOOR + 1, "above")]
        {
            let pool = WorkerPool::try_elastic_tuned(
                bounds(FLOOR, 64),
                Duration::ZERO,
                Duration::from_secs(10),
            )
            .expect("pool");
            settle(&pool, "floor parked", |g| g.idle == FLOOR);
            for _ in 0..jobs {
                pool.enqueue(Box::new(|| {}));
            }
            pool.flush(jobs);
            assert_eq!(
                pool.shared.inner.lock().unwrap().total,
                want_total,
                "{jobs} jobs on a floor of {FLOOR} is {what} the growth \
                 threshold"
            );
            settle(&pool, "quiescent", quiesced);
        }
    }

    /// Growth reads `pending`; the wake count reads the queue. Nothing
    /// else in the suite holds those two inputs apart, because every other
    /// fixture flushes exactly what it queued, where the two are equal.
    ///
    /// The distinction is the whole reason growth was left alone: the
    /// off-loop submitter ([`SharedPool::submit`]) hard-codes `flush(1)`
    /// and shares this pool with a reactor whose jobs it knows nothing
    /// about. Sized by the queue, that one job would spawn a thread - a
    /// `pthread_create` under this lock - on an application thread, for a
    /// backlog the reactor created.
    #[test]
    fn a_flush_of_one_does_not_grow_against_the_queue() {
        const FLOOR: usize = 2;
        let pool = WorkerPool::try_elastic_tuned(
            bounds(FLOOR, 64),
            Duration::ZERO,
            Duration::from_secs(10),
        )
        .expect("pool");
        settle(&pool, "floor parked", |g| g.idle == FLOOR);

        // Ten queued, one declared: `ceil(1/4) > 2` is false, so no
        // growth, where `ceil(10/4) > 2` would spawn.
        for _ in 0..10 {
            pool.enqueue(Box::new(|| {}));
        }
        pool.flush(1);
        assert_eq!(
            pool.shared.inner.lock().unwrap().total,
            FLOOR,
            "growth was sized by the queue, not by what the caller queued"
        );
        settle(&pool, "quiescent", quiesced);
    }

    /// A flush owes wakes only for jobs no claim covers. Every outstanding
    /// `notify` is one worker already on its way to the queue, and a woken
    /// worker drains it whole - so re-waking for those jobs buys nothing
    /// and costs a `futex_wake` each, on the reactor thread, under the
    /// lock the woken workers immediately need.
    ///
    /// The claimed-but-not-yet-woken state is a real window - it is where
    /// every flush leaves the pool until the workers are scheduled - but
    /// it cannot be reached on a timer, so it is set up here directly. The
    /// books are left exactly as a flush would leave them: two workers
    /// taken out of `idle` with two claims standing against two queued
    /// jobs.
    #[test]
    fn a_flush_does_not_re_wake_workers_a_claim_already_covers() {
        const FLOOR: usize = 4;
        let pool = WorkerPool::try_elastic_tuned(
            bounds(FLOOR, FLOOR),
            Duration::from_millis(1),
            Duration::from_secs(10),
        )
        .expect("pool");
        settle(&pool, "floor parked", |g| g.idle == FLOOR);
        {
            let mut g = pool.shared.inner.lock().unwrap();
            g.queue.push_back(Box::new(|| {}));
            g.queue.push_back(Box::new(|| {}));
            // As a previous flush would have left it, minus the wakes it
            // would also have issued - which is the point: those workers
            // are spoken for.
            g.idle -= 2;
            g.notify += 2;
        }

        pool.flush(2);
        assert_eq!(
            pool.shared.inner.lock().unwrap().wakes_issued,
            0,
            "a flush woke again for jobs a claim already covered"
        );

        // Hand the claims back so the pool tears down on its own books.
        pool.shared.cv.notify_all();
        settle(&pool, "quiescent", quiesced);
    }

    /// A job queued by a path that never flushed carries no wake of its
    /// own, so the only thing that can find it is a worker re-checking the
    /// queue on whatever wakeup it does get.
    ///
    /// The wakeup is a burst worker's **own `wait_timeout` expiry**, not a
    /// retiring worker's broadcast: retirement needs `queue.is_empty()`,
    /// which is exactly what is false while such a job is sitting there,
    /// so no retire and no broadcast can happen until it has been taken.
    ///
    /// **Scope.** That expiry exists only above the floor - a floor worker
    /// never retires and so waits untimed - and its period is
    /// `OFFLOAD_IDLE_TIMEOUT`, 10 s on the default config. This fixture
    /// uses 50 ms, so the promptness here is the fixture's, not the
    /// pool's. It is a second line and no substitute for the flush
    /// contract. Every enqueue path pairs with a flush, with one
    /// qualification: `drain_stop_window` flushes and then delivers, and a
    /// continuation reached by that delivery can enqueue again with no
    /// flush behind it. Both hosts then go straight into a blocking
    /// teardown drain. That is not a hang - the cancel is staged first and
    /// `WorkerPool::drop`'s `closed` sweep runs the job - but it is the
    /// one place the pairing does not hold, and what this arm covers is
    /// that and a flush that under-woke.
    #[test]
    fn a_timed_wait_expiry_takes_a_job_nobody_claimed() {
        let pool = WorkerPool::try_elastic_tuned(
            bounds(1, 4),
            Duration::ZERO,
            Duration::from_millis(50),
        )
        .expect("pool");

        // Grow above the floor, so a timed wait exists at all.
        let release = Arc::new((Mutex::new(false), Condvar::new()));
        let (started_tx, started_rx) = mpsc::channel::<()>();
        for _ in 0..4 {
            let r = Arc::clone(&release);
            let st = started_tx.clone();
            pool.submit(Box::new(move || {
                st.send(()).unwrap();
                let (m, cv) = &*r;
                let mut held = m.lock().unwrap();
                while !*held {
                    held = cv.wait(held).unwrap();
                }
            }));
            started_rx.recv().unwrap();
        }
        {
            let (m, cv) = &*release;
            *m.lock().unwrap() = true;
            cv.notify_all();
        }
        settle(&pool, "workers parked", |g| {
            g.idle == g.total && g.queue.is_empty()
        });

        // The precondition, checked HERE rather than before the release:
        // if every burst worker has already retired in the meantime there
        // is no timed wait left, and the failure would name this patch
        // instead of the fixture that slipped.
        let (done_tx, done_rx) = mpsc::channel();
        {
            let mut g = pool.shared.inner.lock().unwrap();
            assert!(
                g.total > 1,
                "fixture slipped: every burst worker retired before the \
                 job was queued, leaving only untimed waits"
            );
            // Queued under the same guard, so no retire can intervene.
            g.queue.push_back(Box::new(move || {
                let _ = done_tx.send(());
            }));
            assert_eq!(g.notify, 0, "unclaimed");
        }

        done_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("a timed wait expiry must let a worker take the job");

        settle(&pool, "quiescent", quiesced);
    }

    #[test]
    fn fixed_pool_does_not_grow() {
        let pool = WorkerPool::try_elastic(bounds(2, 2)).unwrap();
        let release = Arc::new((Mutex::new(false), Condvar::new()));
        let (started_tx, started_rx) = mpsc::channel::<()>();
        for _ in 0..2 {
            let r = Arc::clone(&release);
            let s = started_tx.clone();
            pool.submit(Box::new(move || {
                s.send(()).unwrap();
                let (m, cv) = &*r;
                let mut held = m.lock().unwrap();
                while !*held {
                    held = cv.wait(held).unwrap();
                }
            }));
            started_rx.recv().unwrap();
        }
        // Two more jobs against a saturated fixed pool: they queue, no growth.
        for _ in 0..2 {
            pool.submit(Box::new(|| {}));
        }
        let total = pool.shared.inner.lock().unwrap().total;
        {
            let (m, cv) = &*release;
            *m.lock().unwrap() = true;
            cv.notify_all();
        }
        assert_eq!(total, 2, "fixed pool stayed at its worker count");
    }

    /// A job that ends up holding the pool's last `Arc` drops it on the worker
    /// it runs on, landing `WorkerPool::drop` there; that drop must not join the
    /// pool (it would wait on the running worker itself). Mirrors a
    /// `QueryPool::query` job outliving the reactor and every handle.
    #[test]
    fn dpool_query_job_holding_the_last_pool_arc_wedges_a_worker() {
        let pool = SharedPool::new(bounds(1, 1));
        // The job's own clone; once the outer `pool` drops it becomes the last.
        let held = Arc::clone(&pool);
        let (proceed_tx, proceed_rx) = mpsc::channel::<()>();
        let (done_tx, done_rx) = mpsc::channel::<()>();
        pool.submit(Box::new(move || {
            proceed_rx.recv().ok();
            // Last `Arc` -> `SharedPool::drop` -> `WorkerPool::drop`, here on
            // the worker running this job.
            drop(held);
            // Reached only if that drop returned rather than self-joining.
            done_tx.send(()).ok();
        }));
        drop(pool); // only the job's clone keeps the pool alive now
        proceed_tx.send(()).ok();
        assert!(
            done_rx.recv_timeout(Duration::from_secs(5)).is_ok(),
            "a job dropping the pool's last Arc wedged its worker",
        );
    }

    /// A worker of one pool dropping the last handle of a *different* pool
    /// joins that pool like any other thread would: the self-join exemption
    /// is keyed to the worker's own pool, not to being any pool's worker.
    /// Asserted by order, not timing - were the exemption over-broad, the
    /// drop would return while B's job is still blocked, and the first
    /// `recv_timeout` below would see "b joined" arrive early.
    #[test]
    fn dpool_foreign_pool_dropped_on_a_worker_is_still_joined() {
        let a = WorkerPool::try_elastic(bounds(1, 1)).unwrap();
        let b = WorkerPool::try_elastic(bounds(1, 1)).unwrap();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let (started_tx, started_rx) = mpsc::channel::<()>();
        let (order_tx, order_rx) = mpsc::channel::<&'static str>();

        let ot = order_tx.clone();
        b.submit(Box::new(move || {
            started_tx.send(()).ok();
            release_rx.recv().ok();
            ot.send("b job finished").ok();
        }));
        started_rx.recv().expect("B's worker picked up its job");

        a.submit(Box::new(move || {
            // B's last handle: dropping it here must wait out B's job.
            drop(b);
            order_tx.send("b joined").ok();
        }));

        // The join cannot complete while B's job is parked on `release_rx`,
        // so nothing may arrive yet; "b joined" now means the exemption
        // wrongly fired for a foreign pool.
        match order_rx.recv_timeout(Duration::from_millis(200)) {
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Ok(step) => panic!("foreign drop returned early: got {step:?}"),
            Err(e) => panic!("a worker died: {e}"),
        }
        release_tx.send(()).expect("B's job is waiting on this");
        let five = Duration::from_secs(5);
        assert_eq!(order_rx.recv_timeout(five), Ok("b job finished"));
        assert_eq!(order_rx.recv_timeout(five), Ok("b joined"));
    }
}

// ---------------------------------------------------------------------------
// loom models of the offload pool's lifecycle
// ---------------------------------------------------------------------------
//
// Run with:  RUSTFLAGS="--cfg loom" cargo test --lib --features uring-fs loom_
//
// Three protocols live in this file that no amount of timing-based testing can
// settle, because their correctness is an argument about lock ordering rather
// than about elapsed time:
//
//  * `total` is accounted under the mutex but `running` is bumped outside it,
//    so growth reads two counters at different synchronization points;
//  * `Drop` waits for `total` to reach zero, while one of the two paths that
//    decrements it - the idle retire - does so **without** notifying;
//  * a job can drop the pool's last `Arc`, re-entering `Drop` on a worker that
//    is itself counted in `total`, which is what `ON_POOL_WORKER` exists for.
//
// The models are deliberately tiny: loom is exhaustive, and `loom::MAX_THREADS`
// is 5 including the main thread. `cooldown` is zero throughout because
// `claim_spawn_slot` reads an `Instant`, which loom does not model - so growth
// is always permitted here rather than throttled.
#[cfg(all(test, loom))]
mod loom_tests {
    use super::*;

    const ZERO: Duration = Duration::ZERO;

    /// Bounds with explicit floor and ceiling.
    fn bounds(floor: usize, ceiling: usize) -> OffloadBounds {
        OffloadBounds { floor, ceiling }
    }

    /// Run a model under a preemption bound rather than exhaustively.
    ///
    /// Three threads parking and signalling on one mutex/condvar is past the
    /// point where full exploration terminates in useful time. A preemption
    /// bound keeps every interleaving with at most `N` forced context
    /// switches (the region where essentially all real concurrency bugs
    /// live) and drops the deeper ones. **These are bounded proofs, not exhaustive
    /// ones**, unlike the ring's SPSC model, which is small enough to explore
    /// in full. Each was checked against a deliberately broken variant to
    /// confirm the bound still catches the bug it is there to catch.
    fn bounded_model_with(
        preemptions: usize,
        f: impl Fn() + Sync + Send + 'static,
    ) {
        let mut b = loom::model::Builder::new();
        b.preemption_bound = Some(preemptions);
        b.check(f);
    }

    fn bounded_model(f: impl Fn() + Sync + Send + 'static) {
        bounded_model_with(3, f);
    }

    fn pool(floor: usize, ceiling: usize) -> WorkerPool {
        WorkerPool::try_elastic_tuned(bounds(floor, ceiling), ZERO, ZERO)
            .expect("the model's pool always spawns")
    }

    fn counting_job(n: &Arc<AtomicUsize>) -> Job {
        let n = Arc::clone(n);
        Box::new(move || {
            n.fetch_add(1, Ordering::Relaxed);
        })
    }

    /// Every submitted job runs exactly once, and `Drop` waits for the queue
    /// to empty and every worker to exit.
    ///
    /// **That wait is not a guarantee, and nothing rests on it being one.**
    /// `Drop` has three exits that return with work outstanding: a drop
    /// running on one of this pool's own workers, and the two
    /// `SHUTDOWN_DETACH_AFTER` breaks. Detaching is sound because `Job` is
    /// `Box<dyn FnOnce() + Send>` and therefore `'static` - no job holds a
    /// borrow of what the dropper frees - which is what `Drop`'s own comment
    /// says. This model cannot reach any of the three either: loom
    /// delegates `wait_timeout` to `wait` and hardcodes `timed_out() ==
    /// false` (`src/sync.rs`), so what it checks is the quiescent path.
    #[test]
    fn loom_pool_lifecycle() {
        loom::model(|| {
            let ran = Arc::new(AtomicUsize::new(0));
            let p = pool(1, 1);
            let shared = Arc::clone(&p.shared);

            p.submit(counting_job(&ran));
            p.submit(counting_job(&ran));
            drop(p);

            // `Drop` returned, so its contract must hold in full.
            let g = shared.inner.lock().unwrap_or_else(|e| e.into_inner());
            assert!(g.closed, "Drop returned without closing the pool");
            assert_eq!(g.total, 0, "Drop returned with workers still live");
            assert!(
                g.queue.is_empty(),
                "Drop returned with {} jobs still queued",
                g.queue.len()
            );
            drop(g);
            assert_eq!(
                ran.load(Ordering::Relaxed),
                2,
                "a queued job was dropped on the floor"
            );
        });
    }

    /// Growth never exceeds the ceiling, and a grown pool still drains and
    /// joins cleanly. `running` is read Relaxed while `total` is read under the
    /// lock, so the saturation test can see a stale pair - that may cost a
    /// spawn opportunity, but it must never overshoot.
    ///
    /// `pool(1, 1)`, deliberately: the shape is what makes the assertion bite.
    /// `submit` reads `saturated` under the same guard that just queued the
    /// job, so no worker can have picked that job up yet - with a ceiling of 2
    /// and two submits, the second can never see `running >= total` and the
    /// model is bounded at 2 whether the ceiling is checked or not. At a
    /// ceiling of 1 the second submit does see the first job running, so
    /// deleting the `g.total < ceiling` guard grows the pool to 2 and fails
    /// here.
    #[test]
    fn loom_pool_growth_respects_the_ceiling() {
        bounded_model(|| {
            let ran = Arc::new(AtomicUsize::new(0));
            let p = pool(1, 1);
            let shared = Arc::clone(&p.shared);

            p.submit(counting_job(&ran));
            p.submit(counting_job(&ran));
            {
                let g = shared.inner.lock().unwrap_or_else(|e| e.into_inner());
                assert!(
                    g.total <= shared.ceiling,
                    "pool grew to {} past its ceiling {}",
                    g.total,
                    shared.ceiling
                );
            }
            drop(p);

            let g = shared.inner.lock().unwrap_or_else(|e| e.into_inner());
            assert_eq!(g.total, 0, "Drop returned with workers still live");
            drop(g);
            assert_eq!(ran.load(Ordering::Relaxed), 2, "a job was lost");
        });
    }

    /// `Drop` returns even when a worker never exits. The wait is what makes a
    /// job's effects complete before the dropper proceeds, but the dropping
    /// thread is not always one that can afford to block forever - `Drop` runs
    /// wherever the last handle falls, including on another pool's worker - so
    /// the wait is bounded and then detaches.
    ///
    /// Modelled with a worker counted in `total` that never exists, which is
    /// what a real one parked in an uninterruptible syscall looks like from
    /// here. Remove the detach and this model does not fail, it HANGS - loom
    /// reports the deadlock, which is the negative control.
    ///
    /// loom's `wait_timeout` never reports a timeout, so the detach is
    /// requested through the `detach_next_drop` seam instead of a clock.
    #[test]
    fn loom_pool_drop_detaches_a_worker_that_never_exits() {
        bounded_model(|| {
            let p = pool(1, 1);
            let shared = Arc::clone(&p.shared);

            // A worker that is counted but will never exit.
            {
                let mut g =
                    shared.inner.lock().unwrap_or_else(|e| e.into_inner());
                g.total += 1;
            }
            shared.detach_next_drop(1);
            drop(p);

            // Reaching here at all is the property. The pool is still closed
            // to new work, and the phantom worker is still counted - detaching
            // gives up the wait, it does not falsify the books.
            let g = shared.inner.lock().unwrap_or_else(|e| e.into_inner());
            assert!(g.closed, "Drop returned without closing the pool");
            assert!(
                g.total > 0,
                "the model's phantom worker cannot have exited"
            );
        });
    }

    /// The wait loop's claimless exit decrements `idle` itself, where
    /// every other exit leaves that to the submitter that claimed the
    /// worker. So a flush and a worker taking a job on its own can both be
    /// reaching for the same parked worker, and `idle` is a `usize`: if
    /// both counted it, the second decrement underflows and panics here.
    ///
    /// **What this covers, and what it does not.** Measured by
    /// instrumenting every wakeup under the model: across 218 of them the
    /// claimless precondition (`notify == 0` with a non-empty queue) is
    /// reached **zero** times - `flush` always claims the single worker
    /// before it observes the wakeup - so this does not exercise the arm
    /// it is named for. What it does pin is the ordering the arm depends
    /// on: put the queue check ahead of the `notify` check and the same
    /// race double-counts one worker, which reddens here with an
    /// underflow. Deleting the arm, or its own `g.idle -= 1`, leaves this
    /// green. That the arm is load-bearing at all is pinned by
    /// `a_timed_wait_expiry_takes_a_job_nobody_claimed`, which fails
    /// without it.
    #[test]
    fn loom_a_claimless_take_cannot_double_count_a_claimed_worker() {
        bounded_model_with(2, || {
            let p = pool(1, 1);
            let shared = Arc::clone(&p.shared);

            // A job nobody is claimed for: queued with no wake, exactly as
            // an unflushed enqueue leaves it.
            {
                let mut g =
                    shared.inner.lock().unwrap_or_else(|e| e.into_inner());
                g.queue.push_back(Box::new(|| {}));
            }

            // One side claims the worker out of `idle`; the other lets it
            // wake with no claim and take the job itself.
            let s = Arc::clone(&shared);
            let waker = loom::thread::spawn(move || s.cv.notify_all());
            p.flush(1);
            waker.join().expect("waker");

            let g = shared.inner.lock().unwrap_or_else(|e| e.into_inner());
            assert!(
                g.idle <= g.total,
                "idle {} exceeds total {}: a worker was counted parked twice",
                g.idle,
                g.total
            );
            assert!(
                g.notify <= g.total,
                "notify {} exceeds total {}: more claims than workers",
                g.notify,
                g.total
            );
        });
    }

    /// An idle burst worker retires by decrementing `total` and returning
    /// **without** notifying, unlike the closing path. `Drop` is waiting for
    /// `total` to reach zero, so a retirement that took the count to zero
    /// silently would strand it forever.
    ///
    /// Two guards prevent that, and this model pins the fact that they are
    /// **individually sufficient**: `!g.closed` refuses to retire at all once
    /// `Drop` has run, and `g.total > shared.floor` refuses to retire the last
    /// worker regardless. Delete either one and the model still passes; delete
    /// both and loom reports the deadlock. Worth knowing before anyone
    /// "simplifies" the condition - the redundancy is the safety margin, not
    /// clutter.
    ///
    /// loom's `wait_timeout` never reports a timeout, so the retirements are
    /// requested through the `retire_next_idle` seam instead of a clock.
    #[test]
    fn loom_pool_idle_retire_cannot_strand_drop() {
        // Four threads on one condvar; a tighter bound keeps this in
        // seconds while still covering the retire-vs-close ordering.
        bounded_model_with(2, || {
            let p = pool(1, 2);
            let shared = Arc::clone(&p.shared);

            // Force a second worker to exist so one is above the floor and
            // therefore eligible to retire.
            {
                let mut g =
                    shared.inner.lock().unwrap_or_else(|e| e.into_inner());
                g.total += 1;
            }
            spawn_worker(&shared).expect("the model's worker always spawns");

            // Race the retirement against the drop.
            let s = Arc::clone(&shared);
            let retire = loom::thread::spawn(move || s.retire_idle_workers(2));
            drop(p);
            retire.join().expect("retire requester");

            let g = shared.inner.lock().unwrap_or_else(|e| e.into_inner());
            assert_eq!(
                g.total, 0,
                "Drop returned while {} worker(s) were still live",
                g.total
            );
        });
    }

    /// A job may drop the pool's last `Arc`, which runs `WorkerPool::drop` on a
    /// worker thread that is itself counted in `total`. Joining there would
    /// wait on this very thread forever; `ON_POOL_WORKER` is what prevents it.
    /// loom reports the deadlock if that guard stops working.
    #[test]
    fn loom_pool_self_join_is_avoided() {
        bounded_model(|| {
            let ran = Arc::new(AtomicUsize::new(0));
            let cell: Arc<Mutex<Option<WorkerPool>>> =
                Arc::new(Mutex::new(Some(pool(1, 1))));
            let shared = {
                let g = cell.lock().unwrap_or_else(|e| e.into_inner());
                Arc::clone(&g.as_ref().expect("just built").shared)
            };

            let c = Arc::clone(&cell);
            let n = Arc::clone(&ran);
            {
                let g = cell.lock().unwrap_or_else(|e| e.into_inner());
                g.as_ref().expect("just built").submit(Box::new(move || {
                    // The pool's last owner is this cell; taking it here runs
                    // `WorkerPool::drop` on a pool worker. Drop *before*
                    // marking the job done, so `ran == 1` means the pool has
                    // certainly been dropped by one side or the other.
                    let taken =
                        c.lock().unwrap_or_else(|e| e.into_inner()).take();
                    drop(taken);
                    n.fetch_add(1, Ordering::Relaxed);
                }));
            }

            // Whoever still holds it drops it; one of the two paths is the
            // worker's, which is the interesting one. Take it out and release
            // the cell before dropping: `WorkerPool::drop` waits for the
            // workers, and one of them may be blocked on this very lock.
            let taken = cell.lock().unwrap_or_else(|e| e.into_inner()).take();
            drop(taken);

            // If we dropped the pool, `Drop` already joined and the job has
            // run. If the worker did, it retired without a join and may still
            // be in flight - so wait for it rather than racing its epilogue.
            while ran.load(Ordering::Relaxed) == 0 {
                loom::thread::yield_now();
            }

            // The workers reclaim the shared state on their own once `closed`
            // is set, with no join - so `total` need not be zero here, but the
            // pool must be closed and no thread may be stuck. loom reports the
            // self-join as a deadlock if `ON_POOL_WORKER` stops working.
            let g = shared.inner.lock().unwrap_or_else(|e| e.into_inner());
            assert!(g.closed, "dropping the pool did not close it");
        });
    }

    /// A job may instead drop the last `Arc` of a pool it is NOT a worker
    /// of. No exemption applies there: the drop joins that pool's workers
    /// like any thread would, so the full `Drop` contract holds even when
    /// teardown happens to run on some other pool's worker. Keyed on pool
    /// identity - a bare "am I a worker" flag skips this join, and the
    /// asserts below see the un-joined worker.
    #[test]
    fn loom_pool_foreign_drop_still_joins() {
        bounded_model(|| {
            let a = pool(1, 1);
            let b = pool(1, 1);
            let b_shared = Arc::clone(&b.shared);

            // B's last handle moves into a job running on A's worker.
            a.submit(Box::new(move || drop(b)));

            // A's own drop joins its worker, so the job above has finished -
            // and with it B's drop, whose contract must have held in full.
            drop(a);
            let g = b_shared.inner.lock().unwrap_or_else(|e| e.into_inner());
            assert!(g.closed, "foreign drop did not close the pool");
            assert_eq!(
                g.total, 0,
                "foreign drop returned with workers still live"
            );
        });
    }

    /// Two first-submits race the lazy init: each may build a full pool, and
    /// the loser's is dropped inline (joining the workers it started). Exactly
    /// one pool ends up installed, and **neither job is lost**.
    #[test]
    fn loom_shared_pool_init() {
        bounded_model(|| {
            let ran = Arc::new(AtomicUsize::new(0));
            let sp = SharedPool::new(bounds(1, 1));

            let (a, b) = (Arc::clone(&sp), Arc::clone(&sp));
            let (ra, rb) = (Arc::clone(&ran), Arc::clone(&ran));
            let t = loom::thread::spawn(move || {
                a.submit(Box::new(move || {
                    ra.fetch_add(1, Ordering::Relaxed);
                }));
            });
            b.submit(Box::new(move || {
                rb.fetch_add(1, Ordering::Relaxed);
            }));
            t.join().expect("racing submitter");

            assert!(sp.pool.is_set(), "no pool was installed");
            // Dropping the *last* `Arc` drops the installed pool, whose `Drop`
            // drains the queue and joins - so by here both jobs have run. `b`
            // is still holding one, so it has to go first.
            drop(b);
            drop(sp);
            assert_eq!(
                ran.load(Ordering::Relaxed),
                2,
                "a job was lost to the init race"
            );
        });
    }
}
