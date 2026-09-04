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
use crate::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
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
    /// The pool is dropping; workers drain the queue, then exit.
    closed: bool,
    /// Micros since [`PoolShared::epoch`] of the last spawn, throttling growth.
    last_spawn_us: u64,
}

struct PoolShared {
    inner: Mutex<PoolInner>,
    /// Signals a queued job, a shutdown, or a worker exit (`Drop` waits on it).
    cv: Condvar,
    /// Workers currently executing a job; `running == total` means saturated.
    running: AtomicUsize,
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
/// (`running == total`) and at most once per cooldown, so a burst of fast
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
                closed: false,
                last_spawn_us: 0,
            }),
            cv: Condvar::new(),
            running: AtomicUsize::new(0),
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

    /// Enqueue `job`, growing the pool by one worker if it is saturated and the
    /// cooldown has elapsed (a no-op if the pool is already dropping).
    pub(crate) fn submit(&self, job: Job) {
        let mut g = self.shared.inner.lock().unwrap_or_else(|e| e.into_inner());
        if g.closed {
            return;
        }
        g.queue.push_back(job);
        self.shared.cv.notify_one();
        let saturated = self.shared.running.load(Ordering::Relaxed) >= g.total;
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
    #[cfg(loom)]
    fn retire_idle_workers(&self, n: usize) {
        self.retire_next_idle.store(n, Ordering::Relaxed);
        self.cv.notify_all();
    }

    /// Model-only: let the next `n` `Drop`s detach instead of waiting the
    /// workers out. Standing in for a clock loom does not have - see
    /// [`shutdown_expired`].
    #[cfg(loom)]
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

    /// Submit a job, spawning the pool on first use. A lost init race just
    /// drops the surplus pool (its `Drop` joins the idle workers); a spawn
    /// failure runs the job inline rather than take the reactor down.
    pub(crate) fn submit(&self, job: Job) {
        // `job` is `FnOnce`, so it can only be handed to one arm; take it back
        // out of the cell when the pool was not there to receive it.
        let mut job = Some(job);
        if let Some(()) = self
            .pool
            .with(|pool| pool.submit(job.take().expect("first use")))
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
                    .with(|pool| pool.submit(job.take().expect("first use")));
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
    // Mark this thread with the pool it serves, so a `WorkerPool::drop`
    // triggered here (a job dropping a pool's last `Arc`) can tell its own
    // pool (must not self-join) from any other (joined as usual).
    ON_POOL_WORKER.with(|w| w.set(Arc::as_ptr(shared)));
    loop {
        let job = {
            let mut g = shared.inner.lock().unwrap_or_else(|e| e.into_inner());
            loop {
                if let Some(job) = g.queue.pop_front() {
                    break Some(job);
                }
                if g.closed {
                    break None;
                }
                let (guard, wait) = shared
                    .cv
                    .wait_timeout(g, shared.idle_timeout)
                    .unwrap_or_else(|e| e.into_inner());
                g = guard;
                if idle_expired(&wait, shared)
                    && g.queue.is_empty()
                    && !g.closed
                    && g.total > shared.floor
                {
                    g.total -= 1; // idle burst worker retires
                    return;
                }
            }
        };
        let Some(job) = job else {
            // Pool closing: account the exit and wake `Drop`'s waiter.
            let mut g = shared.inner.lock().unwrap_or_else(|e| e.into_inner());
            g.total -= 1;
            shared.cv.notify_all();
            return;
        };
        shared.running.fetch_add(1, Ordering::Relaxed);
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(job));
        shared.running.fetch_sub(1, Ordering::Relaxed);
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

    /// A fixed pool (`floor == ceiling`) never grows, even when saturated.
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
    /// bound keeps every interleaving with at most `N` forced context switches
    /// - the region where essentially all real concurrency bugs live - and
    /// drops the deeper ones. **These are bounded proofs, not exhaustive
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
