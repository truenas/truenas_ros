//! The reactor's elastic blocking-work pool - [`WorkerPool`] and its lazily-spawned per-reactor handle [`SharedPool`] -
//! with its unit tests and loom models in place. The job contract consumers program against lives at `FsConn::offload`;
//! the type docs below cover the mechanics.

#[cfg(loom)]
use crate::sync::atomic::AtomicUsize;
use crate::sync::atomic::{AtomicU64, Ordering};
use crate::sync::{Arc, Condvar, Mutex, OnceCell, thread};
use crate::uring::wake::WakeHandle;
use std::cell::Cell;
use std::collections::VecDeque;
use std::fmt;
use std::time::{Duration, Instant};

/// Per-ring sizing for a blocking-offload pool, the file pool or the lookup lane, which is how many worker threads it
/// keeps warm and how far it grows.
///
/// Every field is per ring, so a deployment running several multiplies them. Only `floor` is resident; workers above it
/// exist while a job is blocked on them and retire when idle, so the ceiling is a limit rather than a reservation.
///
/// `#[non_exhaustive]`, so a future knob is a field addition rather than a breaking change; build one by mutating
/// [`OffloadBounds::default`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct OffloadBounds {
    /// Warm workers, spawned on first use and never retired below. Resident, so this is a standing per-ring cost. At
    /// least 1.
    pub floor: usize,
    /// Growth limit under saturation: how many concurrently stalled jobs one ring absorbs before they queue behind each
    /// other. Raised to `floor` if smaller.
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

/// A boxed unit of work a pool worker runs. Every job is `Send` and self-contained (it captures its own inputs and
/// result channel), so the pool is generic - the `!Send` `QueryDir` is built and driven *inside* the job, on the
/// worker's own thread, never sent.
pub(crate) type Job = Box<dyn FnOnce() + Send>;

/// Take `n` parked workers out of `idle` and count the wakes owed them. The caller issues the wakes after dropping the
/// guard, since a woken worker's first act is to take the lock.
fn claim(g: &mut PoolInner, n: usize) {
    debug_assert!(n <= g.idle, "claimed {n} workers with {} parked", g.idle);
    g.idle -= n;
    g.notify += n;
    #[cfg(test)]
    {
        g.wakes_issued += n;
    }
}

/// Queued jobs per worker a flush wakes, since a woken worker drains the whole queue. Blocking jobs get a worker each
/// from the stall rule ([`OFFLOAD_BLOCKED_AFTER`]). Also the growth threshold, counted on the caller's `pending` and
/// not the queue, so an off-loop `flush(1)` does not spawn for a backlog the reactor queued.
const JOBS_PER_WAKE: usize = 4;

/// How long a worker can be in one job before the stall rule counts it as blocked.
///
/// io-wq learns of a block from the scheduler (`io_wq_worker_sleeping`, `io_uring/io-wq.c`) and this pool cannot, so it
/// uses time. The rule runs only when the loop flushes, so the loop bounds its sleep by the deadline the flush returns.
const OFFLOAD_BLOCKED_AFTER: Duration = Duration::from_micros(50);

/// Time a claimed worker gets to reach its job before the stall rule counts it. It covers wakeup latency, including
/// exit from a deep CPU idle state; a shorter deadline wakes the loop before the worker runs.
const OFFLOAD_WAKE_ALLOWANCE: Duration = Duration::from_micros(150);

/// Ceiling on the pool's own thread count, a sanity bound since each is a real OS thread. It lives here so **both**
/// hosts screen against the same number (`net`'s `ServerConfig::validate` and `UringFs::check`).
pub(crate) const MAX_OFFLOAD_THREADS: usize = 1024;

/// The name of the file pool's threads, the pool behind `FsConn::offload`, the listers and the copies. Linux keeps 15
/// bytes of a thread's name (`TASK_COMM_LEN` in `include/linux/sched.h`), so `ps` shows `truenas-fs-work`.
pub(crate) const FILE_WORKER: &str = "truenas-fs-worker";

/// The name of the lookup lane's threads (`FsConn::offload_lookup`), short enough that `ps` shows it whole.
pub(crate) const LOOKUP_WORKER: &str = "truenas-lookup";

/// Growth is rate-limited to at most one new worker per this interval, so a burst of microsecond-fast jobs that
/// momentarily saturates the pool does not spawn a thread per job; sustained blocking work still grows to the ceiling.
const OFFLOAD_SPAWN_COOLDOWN: Duration = Duration::from_millis(1);
/// A burst worker idle this long retires, back down to the floor.
const OFFLOAD_IDLE_TIMEOUT: Duration = Duration::from_secs(10);

/// `d`, or zero under loom, which has no clock. At zero, growth and the stall rule answer the same way in every
/// interleaving.
const fn clocked(d: Duration) -> Duration {
    if cfg!(loom) { Duration::ZERO } else { d }
}

/// A value on cache lines of its own (two, for the adjacent-line prefetcher), so a reader polling it shares no line
/// with other writers.
#[repr(align(128))]
struct OwnLines<T>(T);

struct PoolInner {
    queue: VecDeque<Job>,
    /// Live worker threads: the floor plus any grown-in burst workers.
    total: usize,
    /// Parked workers no flush has claimed. A flush claims a worker before waking it, so every wake is consumed and a
    /// pool with no parked worker issues none.
    idle: usize,
    /// Wakes issued and not yet consumed. A worker that wakes to find it zero was not woken by a flush (a spurious
    /// wakeup, a broadcast). Without the count, two workers could consume one wake and decrement `idle` twice.
    notify: usize,
    /// The pool is dropping; workers drain the queue, then exit.
    closed: bool,
    /// Micros since [`PoolShared::epoch`] of the last spawn, throttling growth.
    last_spawn_us: u64,
    /// Start time of each running job, in micros since [`PoolShared::epoch`]. The stall rule reads it to tell a worker
    /// making progress from a blocked one ([`OFFLOAD_BLOCKED_AFTER`]).
    running: Vec<u64>,
    /// Wakes the last `flush` issued. Test-only.
    #[cfg(test)]
    last_flush_wakes: usize,
    /// Wakes issued over the pool's life. Test-only: an extra wake leaves no other trace, since its worker finds
    /// nothing and parks again.
    #[cfg(test)]
    wakes_issued: usize,
}

struct PoolShared {
    inner: Mutex<PoolInner>,
    /// The name each worker thread is given.
    name: &'static str,
    /// Signals a queued job, a shutdown, or a worker exit (`Drop` waits on it).
    cv: Condvar,
    floor: usize,
    ceiling: usize,
    epoch: Instant,
    cooldown: Duration,
    idle_timeout: Duration,
    /// [`OFFLOAD_BLOCKED_AFTER`] in micros. Tests set their own; loom sets zero.
    blocked_after_us: u64,
    /// The deadline the last [`WorkerPool::flush`] returned, in micros since [`epoch`](Self::epoch), or `0` for none,
    /// for the reactor to read ([`WorkerPool::recheck_owed`]). Stored under the lock and loaded without it, hence its
    /// own cache lines. Relaxed, since the poke that follows a store carries it (`WakeHandle::poke` releases, `park`
    /// and `unpark` acquire).
    recheck_at_us: OwnLines<AtomicU64>,
    /// Model-only: how many idle retirements to grant (see [`idle_expired`]).
    #[cfg(loom)]
    retire_next_idle: AtomicUsize,
    /// Model-only: let `Drop` take its detach branch (see [`shutdown_expired`]).
    #[cfg(loom)]
    detach_next_drop: AtomicUsize,
}

/// An elastic pool of worker threads running `Box<dyn FnOnce() + Send>` jobs, the shared machinery behind both the
/// off-loop `QueryPool` helpers and the on-loop `FsConn::offload` path. It keeps `floor` threads warm and grows to
/// `ceiling` when every worker is stuck in a job, and burst workers retire after an idle period. Jobs run under the
/// reactor's ambient credentials, so any per-`who` permission check belongs to the job.
///
/// Dropping the pool closes the queue and waits for every worker to exit, bounded by [`SHUTDOWN_DETACH_AFTER`].
pub(crate) struct WorkerPool {
    shared: Arc<PoolShared>,
}

impl WorkerPool {
    /// An elastic pool: `floor` (at least 1) warm threads growing to `ceiling` under saturation, using the default
    /// cooldown and idle timeout. Returns the spawn error rather than panicking.
    pub(crate) fn try_elastic(name: &'static str, bounds: OffloadBounds) -> std::io::Result<WorkerPool> {
        Self::try_elastic_tuned(
            name,
            bounds,
            clocked(OFFLOAD_SPAWN_COOLDOWN),
            OFFLOAD_IDLE_TIMEOUT,
            clocked(OFFLOAD_BLOCKED_AFTER),
        )
    }

    /// [`try_elastic`](Self::try_elastic) with explicit timings (for tests). On a partial spawn failure the workers
    /// already started are shut down and waited for before returning, so none is orphaned.
    pub(crate) fn try_elastic_tuned(
        name: &'static str,
        bounds: OffloadBounds,
        cooldown: Duration,
        idle_timeout: Duration,
        blocked_after: Duration,
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
                running: Vec::new(),
                #[cfg(test)]
                last_flush_wakes: 0,
                #[cfg(test)]
                wakes_issued: 0,
            }),
            name,
            cv: Condvar::new(),
            floor,
            ceiling,
            epoch: Instant::now(),
            cooldown,
            idle_timeout,
            blocked_after_us: blocked_after.as_micros() as u64,
            recheck_at_us: OwnLines(AtomicU64::new(0)),
            #[cfg(loom)]
            retire_next_idle: AtomicUsize::new(0),
            #[cfg(loom)]
            detach_next_drop: AtomicUsize::new(0),
        });
        let pool = WorkerPool {
            shared: Arc::clone(&shared),
        };
        for _ in 0..floor {
            // Spawn under the lock and count only on success, as `flush` explains.
            let spawned = {
                let mut g = shared.inner.lock().unwrap_or_else(|e| e.into_inner());
                spawn_worker(&shared).map(|()| g.total += 1)
            };
            if let Err(e) = spawned {
                drop(pool); // closes and waits for the workers already started
                return Err(e);
            }
        }
        Ok(pool)
    }

    /// [`enqueue`](Self::enqueue) then a [`flush`](Self::flush) of one. Test-only.
    #[cfg(test)]
    pub(crate) fn submit(&self, job: Job) {
        self.enqueue(job);
        let _ = self.flush(1);
    }

    /// Queue `job` without waking anyone. The caller must [`flush`](Self::flush) before it blocks, or the job waits for
    /// a running worker to reach it.
    pub(crate) fn enqueue(&self, job: Job) {
        let mut g = self.shared.inner.lock().unwrap_or_else(|e| e.into_inner());
        if g.closed {
            return;
        }
        g.queue.push_back(job);
    }

    /// Wake the pool for what is queued, and return how long the caller may sleep before calling this again.
    ///
    /// The `pending` jobs queued since the last flush get one parked worker per [`JOBS_PER_WAKE`]. When every running
    /// worker has been in its job past [`OFFLOAD_BLOCKED_AFTER`], each queued job gets a parked worker and the pool
    /// grows if it has too few. That rule is checked only here, so the return is when to check next, or `None` when no
    /// queued job waits on a running one. `pending` may be zero.
    pub(crate) fn flush(&self, pending: usize) -> Option<Duration> {
        let mut g = self.shared.inner.lock().unwrap_or_else(|e| e.into_inner());
        if g.closed {
            return None;
        }
        let now = self.shared.now_us();
        let parked = g.idle;
        let batch = pending.div_ceil(JOBS_PER_WAKE);
        let mut wakes = batch.min(g.idle);
        claim(&mut g, wakes);
        // More than `JOBS_PER_WAKE` new jobs per parked worker. A flush of nothing grows only through the stall rule
        // below.
        let mut saturated = batch > parked;

        let blocked_after = self.shared.blocked_after_us;
        let progressing = g
            .running
            .iter()
            .filter(|&&started| now.saturating_sub(started) < blocked_after)
            .count();
        // A claimed worker that has not reached the queue yet still counts as coming.
        if g.notify == 0 && progressing == 0 && !g.queue.is_empty() {
            let want = if g.running.is_empty() {
                // Nobody awake: jobs queued without a flush. Size the wake as the batch rule would.
                g.queue.len().div_ceil(JOBS_PER_WAKE)
            } else {
                // Every awake worker is blocked: a worker per queued job.
                g.queue.len()
            };
            let recruited = want.min(g.idle);
            claim(&mut g, recruited);
            wakes += recruited;
            saturated |= want > recruited;
        }
        #[cfg(test)]
        {
            g.last_flush_wakes = wakes;
        }
        // Count the worker only once it has started. A reserved slot handed back on failure would be a decrement of
        // `total` with no worker exit to signal it, which can park `Drop` on the condvar forever.
        if saturated
            && g.total < self.shared.ceiling
            && self.shared.claim_spawn_slot(&mut g)
            && spawn_worker(&self.shared).is_ok()
        {
            g.total += 1;
        }
        // A failed spawn leaves the job queued for a busy worker to pick up.
        let next = self.shared.next_check(&g, now);
        // `next_check` never names a zero deadline, so `0` stays "none".
        self.shared
            .recheck_at_us
            .0
            .store(next.map_or(0, |d| now + d.as_micros() as u64), Ordering::Relaxed);
        drop(g);
        for _ in 0..wakes {
            self.shared.cv.notify_one();
        }
        next
    }

    /// A [`flush`](Self::flush) of one from a thread with no loop, poking `loop_wake` when it returns a deadline. The
    /// poke follows the publish, since its release carries the relaxed deadline to the loop.
    pub(crate) fn flush_off_loop(&self, loop_wake: &WakeHandle) {
        if self.flush(1).is_some() {
            loop_wake.poke();
        }
    }

    /// Time until the stall rule is due, as the last [`flush`](Self::flush) published it, or `None` when nothing is
    /// due. A past deadline reads as `Some(ZERO)`, since `None` lets the loop sleep without a timeout.
    pub(crate) fn recheck_owed(&self) -> Option<Duration> {
        let at = self.shared.recheck_at_us.0.load(Ordering::Relaxed);
        (at != 0).then(|| Duration::from_micros(at.saturating_sub(self.shared.now_us())))
    }
}

impl PoolShared {
    /// Model-only. Let the next `n` workers to wake retire (see [`idle_expired`]). A budget, since with a single
    /// retirement the retiring worker is never the last, and a model could not catch a pool that retires its final
    /// worker.
    #[cfg(all(test, loom))]
    fn retire_idle_workers(&self, n: usize) {
        self.retire_next_idle.store(n, Ordering::Relaxed);
        self.cv.notify_all();
    }

    /// Model-only: let the next `n` `Drop`s detach instead of waiting the workers out. Standing in for a clock loom
    /// does not have - see [`shutdown_expired`].
    #[cfg(all(test, loom))]
    fn detach_next_drop(&self, n: usize) {
        self.detach_next_drop.store(n, Ordering::Relaxed);
    }

    /// Micros since [`epoch`](Self::epoch), for the growth throttle and the stall rule.
    fn now_us(&self) -> u64 {
        self.epoch.elapsed().as_micros() as u64
    }

    /// When [`WorkerPool::flush`] must run again for the stall rule, or `None` if never.
    ///
    /// `None` while every queued job has a claimed worker. Otherwise, when the last worker still making progress
    /// crosses the threshold (a claimed worker counts as starting [`OFFLOAD_WAKE_ALLOWANCE`] from now). If all have
    /// crossed, only growth is left: the end of the cooldown, or `None` at the ceiling.
    fn next_check(&self, g: &PoolInner, now: u64) -> Option<Duration> {
        if g.queue.len() <= g.notify {
            return None;
        }
        let mut at = if g.notify > 0 {
            now + OFFLOAD_WAKE_ALLOWANCE.as_micros() as u64 + self.blocked_after_us
        } else {
            0
        };
        for &started in &g.running {
            at = at.max(started + self.blocked_after_us);
        }
        if at > now {
            return Some(Duration::from_micros(at - now));
        }
        if g.total < self.ceiling {
            // Never sooner than the threshold: this flush already spawned if it could, so a deadline at an expired
            // cooldown would have the loop spin.
            let cooldown = self.cooldown.as_micros() as u64;
            let left = (g.last_spawn_us + cooldown).saturating_sub(now);
            return Some(Duration::from_micros(left.max(self.blocked_after_us).max(1)));
        }
        None
    }

    /// True at most once per [`cooldown`](Self::cooldown), claiming the slot so concurrent submits do not all spawn at
    /// once.
    ///
    /// Takes the guard, since its only caller, `flush`, holds the lock across the whole growth decision.
    fn claim_spawn_slot(&self, inner: &mut PoolInner) -> bool {
        let now = self.now_us();
        let cooldown = self.cooldown.as_micros() as u64;
        if now.saturating_sub(inner.last_spawn_us) < cooldown {
            return false;
        }
        inner.last_spawn_us = now;
        true
    }
}

// The identity of the pool this thread is a worker of (`Arc::as_ptr` of its `PoolShared`), or null off the pools, so a
// `WorkerPool::drop` run on a worker skips the join on its own pool and still joins any other. A bare "am I a worker"
// flag cannot tell those apart and leaks the exemption to every pool in the process.
//
// Under loom this must be loom's thread-local, not std's, since loom multiplexes every modelled thread onto one OS
// thread, so a std `thread_local!` would let a worker's identity leak into the main thread and make `Drop` skip a join
// it really needed. (loom's macro takes no `const` initializer.)
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
/// The wait makes a job's effects complete before the dropper proceeds. It is bounded because `Drop` runs wherever the
/// last handle falls, another pool's worker or a thread serving requests included, and an offload parked against a
/// wedged backing would otherwise hold that thread for the life of the process. At shutdown a supervisor's SIGKILL
/// reaps such a worker, since FUSE (`fs/fuse/dev.c:212`) and sunrpc (`net/sunrpc/sched.c:346`) wait `TASK_KILLABLE`,
/// but mid-run nothing does.
const SHUTDOWN_DETACH_AFTER: Duration = Duration::from_secs(2);

/// Whether `Drop`'s bounded wait has run out and the remaining workers should be detached.
///
/// In production this is the condvar's own answer. Under loom `wait_timeout` never times out (`sync.rs`), so a model
/// asks for the detach through this seam.
#[cfg(not(loom))]
fn shutdown_expired(wait: &std::sync::WaitTimeoutResult, _shared: &Arc<PoolShared>) -> bool {
    wait.timed_out()
}

#[cfg(loom)]
fn shutdown_expired(_wait: &loom::sync::WaitTimeoutResult, shared: &Arc<PoolShared>) -> bool {
    shared
        .detach_next_drop
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_sub(1))
        .is_ok()
}

/// The deadline `Drop`'s bounded wait runs against.
///
/// One deadline for the whole wait. Passing [`SHUTDOWN_DETACH_AFTER`] to each `wait_timeout` would restart the clock on
/// every wake, and every worker exit notifies, so a pool of `n` workers with one wedged member would wait
/// `n x SHUTDOWN_DETACH_AFTER`, and a spurious wake would remove the bound. Under loom there is no clock, and
/// [`shutdown_expired`]'s seam drives the detach.
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
        // On one of this pool's own workers (a job dropped the last `Arc`) the thread is counted in `total`, so waiting
        // would wait on itself, and the workers exit on `closed` alone. Another pool's worker gets no exemption, or a
        // cross-pool drop (`try_elastic_tuned`'s unwind) would skip its join.
        if ON_POOL_WORKER.with(Cell::get) == Arc::as_ptr(&self.shared) {
            return;
        }
        // Wait for the workers to exit, up to `SHUTDOWN_DETACH_AFTER` on one deadline. Detaching is sound because a
        // `Job` is `'static`, so it borrows nothing the dropper frees, and each worker owns an `Arc<PoolShared>` and
        // exits on `closed`.
        let clock = ShutdownClock::start();
        while g.total > 0 {
            let left = clock.remaining();
            if left.is_zero() {
                break; // detached: they exit on `closed` alone
            }
            let (guard, wait) = self.shared.cv.wait_timeout(g, left).unwrap_or_else(|e| e.into_inner());
            g = guard;
            if shutdown_expired(&wait, &self.shared) {
                break; // detached: they exit on `closed` alone
            }
        }
    }
}

/// Spawn one worker thread bound to `shared`. The caller holds the lock and counts the worker in `total` once this
/// succeeds, and the worker takes itself off `total` when it exits.
fn spawn_worker(shared: &Arc<PoolShared>) -> std::io::Result<()> {
    let shared = Arc::clone(shared);
    thread::Builder::new()
        .name(shared.name.into())
        .spawn(move || worker_loop(&shared))
        .map(|_| ())
}

/// One lazily-spawned [`WorkerPool`], cheap to clone. A reactor holds two, the file pool (`FsConn::offload` and the
/// off-loop `QueryPool`, one thread budget) and the lookup lane (`FsConn::offload_lookup`), whose jobs may wait seconds
/// on another machine. If a worker cannot be spawned, [`enqueue`](Self::enqueue) runs the job inline while
/// [`try_enqueue`](Self::try_enqueue) hands it back.
pub(crate) struct SharedPool {
    pool: OnceCell<WorkerPool>,
    /// The name of the pool's threads.
    name: &'static str,
    bounds: OffloadBounds,
    /// Epoch for [`retry_spawn_us`](Self::retry_spawn_us).
    epoch: Instant,
    /// Micros since `epoch` before the lazy spawn is attempted again, or `0` when none has failed.
    ///
    /// A failure backs off rather than latching, since what refused the thread (`EAGAIN`, `RLIMIT_NPROC`, a cgroup
    /// `pids.max`) is usually transient, and latching would run every later job inline on the reactor for good.
    retry_spawn_us: AtomicU64,
}

/// How long a failed lazy spawn runs jobs inline before trying again. Long enough that a persistent failure does not
/// thrash a full floor spawn per submit, short enough that a transient one is not a lasting degradation.
const SPAWN_RETRY_BACKOFF: Duration = Duration::from_secs(1);

impl fmt::Debug for SharedPool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SharedPool")
            .field("spawned", &self.pool.is_set())
            .field("retry_spawn_us", &self.retry_spawn_us.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl SharedPool {
    /// A shared pool sized by `bounds`, whose threads are called `name`. No threads spawn until the first
    /// [`submit`](Self::submit).
    pub(crate) fn new(name: &'static str, bounds: OffloadBounds) -> Arc<SharedPool> {
        let floor = bounds.floor.max(1);
        Arc::new(SharedPool {
            pool: OnceCell::new(),
            name,
            bounds: OffloadBounds {
                floor,
                ceiling: bounds.ceiling.max(floor),
            },
            epoch: Instant::now(),
            retry_spawn_us: AtomicU64::new(0),
        })
    }

    /// [`enqueue`](Self::enqueue) then a [`flush`](Self::flush) of one, for callers with no loop (the off-loop query
    /// helpers).
    ///
    /// Such a caller cannot come back for the stall rule, so `loop_wake` is poked to bring the reactor back
    /// ([`WorkerPool::flush_off_loop`]).
    pub(crate) fn submit(&self, job: Job, loop_wake: &WakeHandle) {
        self.enqueue(job);
        self.pool.with(|pool| pool.flush_off_loop(loop_wake));
    }

    /// When the stall rule is next due ([`WorkerPool::recheck_owed`]), or `None` if nothing is due or no pool exists
    /// yet.
    pub(crate) fn recheck_owed(&self) -> Option<Duration> {
        self.pool.with(|pool| pool.recheck_owed()).flatten()
    }

    /// Wake the pool for `pending` jobs queued since the last flush and return when to call again
    /// ([`WorkerPool::flush`]). Before the pool exists there is nothing to wake, since a job queued without one ran
    /// inline or was handed back.
    pub(crate) fn flush(&self, pending: usize) -> Option<Duration> {
        self.pool.with(|pool| pool.flush(pending)).flatten()
    }

    /// Parked, unclaimed workers, or `None` before the pool exists. For fixtures that wait for the floor to park before
    /// queueing: a worker still starting takes queued jobs whatever the wake rules say.
    #[cfg(all(test, not(loom)))]
    pub(crate) fn parked(&self) -> Option<usize> {
        self.pool
            .with(|pool| pool.shared.inner.lock().unwrap_or_else(|e| e.into_inner()).idle)
    }

    /// Back off as a failed first spawn does, and never stop, so a test can see what a caller does with a job no thread
    /// takes. A real failure needs a process-wide limit, which a test must not exhaust.
    #[cfg(all(test, not(loom)))]
    pub(crate) fn back_off(&self) {
        self.retry_spawn_us.store(u64::MAX, Ordering::Relaxed);
    }

    /// Queue a job without a wake, spawning the pool on first use. A spawn failure runs the job inline rather than take
    /// the reactor down. The caller must [`flush`](Self::flush) before it blocks.
    pub(crate) fn enqueue(&self, job: Job) {
        if let Err(job) = self.try_enqueue(job) {
            job();
        }
    }

    /// [`enqueue`](Self::enqueue), but a job no thread can take is handed back rather than run inline. That is when the
    /// pool's first spawn fails, and for [`SPAWN_RETRY_BACKOFF`] after it, so the caller can answer for a job that must
    /// not run on its loop.
    pub(crate) fn try_enqueue(&self, job: Job) -> Result<(), Job> {
        // `job` is `FnOnce`, so it can only be handed to one arm; take it back out of the cell when the pool was not
        // there to receive it.
        let mut job = Some(job);
        if let Some(()) = self.pool.with(|pool| pool.enqueue(job.take().expect("first use"))) {
            return Ok(());
        }
        let job = job.expect("untouched when the cell was empty");
        let now = self.epoch.elapsed().as_micros() as u64;
        if now < self.retry_spawn_us.load(Ordering::Relaxed) {
            // Backing off a recent failure, so no spawn is tried per job.
            return Err(job);
        }
        match WorkerPool::try_elastic(self.name, self.bounds) {
            Ok(pool) => {
                // A lost race just drops the surplus pool here; its `Drop` joins the workers it started before they can
                // touch anything.
                self.pool.set(pool);
                let mut job = Some(job);
                self.pool.with(|pool| pool.enqueue(job.take().expect("first use")));
                Ok(())
            }
            Err(_) => {
                self.retry_spawn_us.store(
                    now.saturating_add(SPAWN_RETRY_BACKOFF.as_micros() as u64),
                    Ordering::Relaxed,
                );
                Err(job)
            }
        }
    }
}

/// Whether a `wait_timeout` return means the worker has been idle long enough to retire.
///
/// Under loom `wait_timeout` never times out, so a model grants retirements through [`PoolShared::retire_next_idle`] to
/// reach the branch that decrements `total` *without* notifying.
#[cfg(not(loom))]
fn idle_expired(wait: &std::sync::WaitTimeoutResult, _shared: &Arc<PoolShared>) -> bool {
    wait.timed_out()
}

#[cfg(loom)]
fn idle_expired(_wait: &loom::sync::WaitTimeoutResult, shared: &Arc<PoolShared>) -> bool {
    // The model arms a budget; each waking worker consumes one.
    shared
        .retire_next_idle
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_sub(1))
        .is_ok()
}

/// One worker, which waits for a job, runs it and repeats. A burst worker idle past the idle timeout retires (never
/// below the floor), and on shutdown every worker drains the queue and exits, decrementing `total` so `Drop` can wait
/// them out. Each job runs under `catch_unwind`, so a panicking job retires only itself.
fn worker_loop(shared: &Arc<PoolShared>) {
    // Mark this thread with the pool it serves (see `ON_POOL_WORKER`).
    ON_POOL_WORKER.with(|w| w.set(Arc::as_ptr(shared)));
    let mut g = shared.inner.lock().unwrap_or_else(|e| e.into_inner());
    loop {
        // Drain the queue before parking: a flush that found no parked worker woke nobody and relies on a running
        // worker to get here.
        while let Some(job) = g.queue.pop_front() {
            // Wake nobody from here. Whether the rest of the queue needs another worker depends on how long this job
            // takes, which the loop's next flush judges from this start time.
            let started = shared.now_us();
            g.running.push(started);
            drop(g);
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(job));
            g = shared.inner.lock().unwrap_or_else(|e| e.into_inner());
            // Any entry with this start time will do: entries are read only as a count and a maximum.
            if let Some(at) = g.running.iter().position(|&s| s == started) {
                g.running.swap_remove(at);
            }
        }
        if g.closed {
            g.total -= 1;
            shared.cv.notify_all();
            return;
        }
        g.idle += 1;
        loop {
            // A floor worker never retires, so it waits without a timeout (no hrtimer). Above the floor, any worker may
            // be the one to retire.
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
                // A flush claimed this worker and has already taken it out of `idle`.
                g.notify -= 1;
                break;
            }
            // Woken without a claim and with work queued, take it, since a job queued without a flush has no claimed
            // worker and floor workers wait untimed. Keep this after the `notify` arm, or a claimed worker decrements
            // `idle` twice (`loom_a_claimless_take_cannot_double_count_a_claimed_worker`).
            if !g.queue.is_empty() {
                g.idle -= 1;
                break;
            }
            if g.closed {
                g.idle -= 1;
                break;
            }
            // Retiring needs an empty queue, which the arm above ensures.
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
mod pool_tests;

// loom models of the pool's lifecycle, whose correctness is about lock ordering rather than elapsed time. `Drop` waits
// for `total` to reach zero while the idle retire decrements it **without** notifying, and a job can drop the pool's
// last `Arc`, re-entering `Drop` on a worker counted in `total`. `cooldown` is zero throughout, since loom has no
// clock.
#[cfg(all(test, loom))]
mod loom_tests;
