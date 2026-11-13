use super::*;
use crate::sync::mpsc;

/// Bounds with explicit floor and ceiling.
fn bounds(floor: usize, ceiling: usize) -> OffloadBounds {
    OffloadBounds { floor, ceiling }
}

/// The elastic pool grows past its floor when every worker is blocked, up to the ceiling, then retires the burst
/// workers once they sit idle.
#[test]
fn offload_pool_grows_under_saturation_then_reclaims_when_idle() {
    // Floor 1, ceiling 4; no growth cooldown (deterministic under the start-synchronised submits below) and a quick
    // idle timeout.
    let pool = WorkerPool::try_elastic_tuned(
        FILE_WORKER,
        bounds(1, 4),
        Duration::ZERO,
        Duration::from_millis(50),
        OFFLOAD_BLOCKED_AFTER,
    )
    .expect("pool");

    let release = Arc::new((Mutex::new(false), Condvar::new()));
    let (started_tx, started_rx) = mpsc::channel::<()>();

    // Submit blocking jobs one at a time, waiting until each is actually running before the next, so the growth
    // decision sees an accurate `running` count rather than racing ahead of the workers.
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

    // Release the blocked jobs first, so a failing assertion cannot wedge teardown (Drop waits for every worker to
    // exit).
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

/// Spin until `f` holds of the pool's inner state; panic after 3 s.
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

/// Like `settle`, but returns `false` instead of panicking, so a caller can release held jobs before it asserts.
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

/// Every worker parked and nothing owed.
fn quiesced(g: &PoolInner) -> bool {
    g.notify == 0 && g.idle == g.total && g.queue.is_empty() && g.running.is_empty()
}

/// Jobs that block until released, each reporting its thread as it starts. A batch of them runs side by side only
/// if each got its own worker.
struct Held {
    release: Arc<(Mutex<bool>, Condvar)>,
    started: mpsc::Receiver<thread::ThreadId>,
    started_tx: mpsc::Sender<thread::ThreadId>,
}

impl Held {
    fn new() -> Held {
        let (started_tx, started) = mpsc::channel();
        Held {
            release: Arc::new((Mutex::new(false), Condvar::new())),
            started,
            started_tx,
        }
    }

    fn job(&self) -> Job {
        let r = Arc::clone(&self.release);
        let s = self.started_tx.clone();
        Box::new(move || {
            let _ = s.send(thread::current().id());
            let (m, cv) = &*r;
            let mut held = m.lock().unwrap();
            while !*held {
                held = cv.wait(held).unwrap();
            }
        })
    }

    /// The distinct threads of the first `n` held jobs to start, waiting up to 10 s for them to report.
    fn threads(&self, n: usize) -> std::collections::HashSet<thread::ThreadId> {
        let give_up = Instant::now() + Duration::from_secs(10);
        let mut seen = std::collections::HashSet::new();
        for _ in 0..n {
            let left = give_up.saturating_duration_since(Instant::now());
            match self.started.recv_timeout(left) {
                Ok(id) => {
                    seen.insert(id);
                }
                Err(_) => break,
            }
        }
        seen
    }

    fn release(&self) {
        let (m, cv) = &*self.release;
        *m.lock().unwrap() = true;
        cv.notify_all();
    }
}

/// Act as the loop: sleep to each deadline the pool returns and flush again, until it returns none. Gives up after
/// 5 s, so a pool that never recruits fails the caller's assertion instead of spinning.
fn turn_until_covered(pool: &WorkerPool, mut next: Option<Duration>) {
    let give_up = Instant::now() + Duration::from_secs(5);
    while let Some(d) = next {
        if Instant::now() > give_up {
            return;
        }
        thread::sleep(d);
        next = pool.flush(0);
    }
}

/// An `enqueue` wakes nobody; a flush wakes one parked worker per four jobs. Five jobs on eight parked workers wake
/// two, where a wake per job would wake five and a single wake one.
#[test]
fn an_enqueue_wakes_nobody_and_a_flush_wakes_a_worker_per_four_jobs() {
    const JOBS: usize = 5;
    const FLOOR: usize = 8;
    let pool = WorkerPool::try_elastic_tuned(
        FILE_WORKER,
        bounds(FLOOR, FLOOR),
        Duration::from_millis(1),
        Duration::from_secs(10),
        Duration::from_secs(10),
    )
    .expect("pool");
    settle(&pool, "floor parked", |g| g.idle == FLOOR);

    for _ in 0..JOBS {
        pool.enqueue(Box::new(|| {}));
    }
    {
        let g = pool.shared.inner.lock().unwrap();
        assert_eq!(g.queue.len(), JOBS, "queued, not run");
        assert_eq!(g.wakes_issued, 0, "an enqueue woke somebody");
        assert_eq!(g.idle, FLOOR, "an enqueue claimed a worker");
    }
    let _ = pool.flush(JOBS);
    assert_eq!(
        pool.shared.inner.lock().unwrap().last_flush_wakes,
        JOBS.div_ceil(JOBS_PER_WAKE),
        "a flush wakes a worker per four jobs"
    );
    settle(&pool, "quiescent", quiesced);
    assert_eq!(
        pool.shared.inner.lock().unwrap().wakes_issued,
        JOBS.div_ceil(JOBS_PER_WAKE),
        "something woke a worker the batch did not ask for"
    );
}

/// Jobs shorter than the stall threshold never wake extra workers, however often the loop flushes. Each job sleeps
/// 1 ms against a 50 ms threshold.
#[test]
fn short_jobs_never_trip_the_stall_rule() {
    const FLOOR: usize = 8;
    const JOBS: usize = 8;
    let pool = WorkerPool::try_elastic_tuned(
        FILE_WORKER,
        bounds(FLOOR, FLOOR),
        Duration::from_millis(1),
        Duration::from_secs(10),
        Duration::from_millis(50),
    )
    .expect("pool");
    settle(&pool, "floor parked", |g| g.idle == FLOOR);

    for _ in 0..JOBS {
        pool.enqueue(Box::new(|| thread::sleep(Duration::from_millis(1))));
    }
    let _ = pool.flush(JOBS);
    let batch = JOBS.div_ceil(JOBS_PER_WAKE);
    // Flush more often than a real loop would, to give the rule more chances to misfire.
    while !pool.shared.inner.lock().unwrap().queue.is_empty() {
        let _ = pool.flush(0);
        thread::sleep(Duration::from_micros(200));
    }
    settle(&pool, "quiescent", quiesced);
    assert_eq!(
        pool.shared.inner.lock().unwrap().wakes_issued,
        batch,
        "short jobs recruited past the batch's {batch} wakes"
    );
}

/// Blocking jobs queued together each get a worker. The flush wakes one worker for all four; once it has been in
/// its job past the threshold, the next flush gives each queued job a parked worker. The loop flushes only when the
/// pool asks, so a missing deadline would leave three jobs stuck.
#[test]
fn blocking_jobs_queued_together_each_get_a_worker() {
    const JOBS: usize = 4;
    const FLOOR: usize = 8;
    let pool = WorkerPool::try_elastic_tuned(
        FILE_WORKER,
        bounds(FLOOR, FLOOR),
        Duration::from_millis(1),
        Duration::from_secs(10),
        Duration::from_millis(2),
    )
    .expect("pool");
    settle(&pool, "floor parked", |g| g.idle == FLOOR);

    let held = Held::new();
    for _ in 0..JOBS {
        pool.enqueue(held.job());
    }
    let next = pool.flush(JOBS);
    let batch = pool.shared.inner.lock().unwrap().last_flush_wakes;
    turn_until_covered(&pool, next);
    let all_running = reaches(&pool, |g| g.running.len() == JOBS);
    let threads = held.threads(JOBS);
    let wakes = pool.shared.inner.lock().unwrap().wakes_issued;
    held.release();

    assert_eq!(batch, 1, "four jobs are one batch");
    assert!(
        all_running,
        "blocking jobs queued together ran one at a time: {} of \
             {JOBS} got a worker",
        threads.len()
    );
    assert_eq!(threads.len(), JOBS, "two jobs shared a thread");
    assert_eq!(wakes, JOBS, "a wake per blocked job, and no more");
    settle(&pool, "quiescent", quiesced);
}

/// Blocking jobs beyond the parked workers grow the pool, one worker per cooldown, until each has one, even from
/// flushes that queued nothing.
#[test]
fn blocking_jobs_past_the_floor_grow_the_pool() {
    const JOBS: usize = 4;
    const FLOOR: usize = 2;
    let pool = WorkerPool::try_elastic_tuned(
        FILE_WORKER,
        bounds(FLOOR, JOBS),
        Duration::ZERO,
        Duration::from_secs(10),
        Duration::from_millis(2),
    )
    .expect("pool");
    settle(&pool, "floor parked", |g| g.idle == FLOOR);

    let held = Held::new();
    for _ in 0..JOBS {
        pool.enqueue(held.job());
    }
    let next = pool.flush(JOBS);
    turn_until_covered(&pool, next);
    let all_running = reaches(&pool, |g| g.running.len() == JOBS);
    let total = pool.shared.inner.lock().unwrap().total;
    held.release();

    assert!(
        all_running,
        "{JOBS} blocking jobs on a floor of {FLOOR} did not all run"
    );
    assert_eq!(total, JOBS, "grew past a job each");
}

/// Growth starts above `JOBS_PER_WAKE` new jobs per parked worker. Sampled at 16 and 17 jobs on a floor of 4, where
/// a `>=` slip would already grow at 16. `flush` spawns under the lock, so the count after it returns is its
/// decision.
#[test]
fn growth_waits_for_more_than_four_jobs_per_parked_worker() {
    const FLOOR: usize = 4;
    // ceil(n / 4) > 4 is false at 16 and true at 17.
    for (jobs, want_total, what) in [(16usize, FLOOR, "below"), (17, FLOOR + 1, "above")] {
        let pool = WorkerPool::try_elastic_tuned(
            FILE_WORKER,
            bounds(FLOOR, 64),
            Duration::ZERO,
            Duration::from_secs(10),
            Duration::from_secs(10),
        )
        .expect("pool");
        settle(&pool, "floor parked", |g| g.idle == FLOOR);
        for _ in 0..jobs {
            pool.enqueue(Box::new(|| {}));
        }
        let _ = pool.flush(jobs);
        assert_eq!(
            pool.shared.inner.lock().unwrap().total,
            want_total,
            "{jobs} jobs on a floor of {FLOOR} is {what} the growth \
                 threshold"
        );
        settle(&pool, "quiescent", quiesced);
    }
}

/// Growth counts `pending`, not the queue. The off-loop submitter (`SharedPool::submit`) always flushes one and
/// shares the pool with the reactor; sized by the queue, it would spawn a thread for the reactor's backlog.
#[test]
fn a_flush_of_one_does_not_grow_against_the_queue() {
    const FLOOR: usize = 2;
    let pool = WorkerPool::try_elastic_tuned(
        FILE_WORKER,
        bounds(FLOOR, 64),
        Duration::ZERO,
        Duration::from_secs(10),
        Duration::from_secs(10),
    )
    .expect("pool");
    settle(&pool, "floor parked", |g| g.idle == FLOOR);

    // Ten queued, one declared: `ceil(1/4) > 2` is false, so no growth, where `ceil(10/4) > 2` would spawn.
    for _ in 0..10 {
        pool.enqueue(Box::new(|| {}));
    }
    let _ = pool.flush(1);
    assert_eq!(
        pool.shared.inner.lock().unwrap().total,
        FLOOR,
        "growth was sized by the queue, not by what the caller queued"
    );
    settle(&pool, "quiescent", quiesced);
}

/// Each flush publishes the deadline it returns, a passed deadline still reads as due, and a flush with nothing due
/// clears it.
#[test]
fn a_flush_publishes_the_deadline_it_returns() {
    let pool = WorkerPool::try_elastic_tuned(
        FILE_WORKER,
        bounds(1, 1),
        Duration::from_millis(1),
        Duration::from_secs(10),
        Duration::from_millis(1),
    )
    .expect("pool");
    settle(&pool, "floor parked", |g| g.idle == 1);
    assert_eq!(pool.recheck_owed(), None, "owed before any flush");

    // Two jobs and one worker parked: the flush claims it, and the second job waits on the first.
    let held = Held::new();
    pool.enqueue(held.job());
    pool.enqueue(held.job());
    let next = pool.flush(2).expect("a job waits on a claimed worker");
    let owed = pool.recheck_owed().expect("the deadline was not published");
    assert!(owed <= next, "published {owed:?}, past the {next:?} returned");

    thread::sleep(next);
    assert_eq!(
        pool.recheck_owed(),
        Some(Duration::ZERO),
        "a deadline that has passed must read as due, not as none"
    );

    held.release();
    settle(&pool, "quiescent", quiesced);
    assert_eq!(pool.flush(0), None, "owed with nothing queued");
    assert_eq!(
        pool.recheck_owed(),
        None,
        "a flush that owes nothing left its predecessor's deadline up"
    );
}

/// A job queued without a flush is taken by a worker that wakes on its own, here a burst worker's `wait_timeout`
/// expiry (50 ms in this fixture). A retiring worker's broadcast cannot stand in: retiring needs an empty queue.
/// This is a fallback; the loop's next flush would claim a worker for the job too.
#[test]
fn a_timed_wait_expiry_takes_a_job_nobody_claimed() {
    let pool = WorkerPool::try_elastic_tuned(
        FILE_WORKER,
        bounds(1, 4),
        Duration::ZERO,
        Duration::from_millis(50),
        Duration::from_secs(10),
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
    settle(&pool, "workers parked", |g| g.idle == g.total && g.queue.is_empty());

    // Checked here, not before the release: if every burst worker has retired, no timed wait is left and a failure
    // would blame the arm.
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

/// A fixed pool (`floor == ceiling`) never grows, even when saturated.
#[test]
fn fixed_pool_does_not_grow() {
    let pool = WorkerPool::try_elastic(FILE_WORKER, bounds(2, 2)).unwrap();
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

/// A pool's threads carry its name, which is how `ps` tells the lookup lane from the file pool.
#[test]
fn a_pools_threads_carry_its_name() {
    let pool = SharedPool::new(LOOKUP_WORKER, bounds(1, 1));
    let (tx, rx) = mpsc::channel();
    pool.enqueue(Box::new(move || {
        tx.send(thread::current().name().map(str::to_owned)).ok();
    }));
    let _ = pool.flush(1);
    let name = rx.recv_timeout(Duration::from_secs(5)).expect("it ran");
    assert_eq!(name.as_deref(), Some(LOOKUP_WORKER));
}

/// While a pool backs off a failed first spawn, `try_enqueue` hands a job back unrun, and `enqueue` runs it inline
/// on the caller's thread.
#[test]
fn a_pool_with_no_thread_hands_the_job_back_or_runs_it_inline() {
    let pool = SharedPool::new(LOOKUP_WORKER, bounds(1, 1));
    pool.back_off();
    let (tx, rx) = mpsc::channel();
    let early = tx.clone();
    let back = pool.try_enqueue(Box::new(move || {
        early.send("handed back").ok();
    }));
    assert!(back.is_err(), "with no thread the job comes back");
    drop(back);
    assert!(rx.try_recv().is_err(), "a job handed back has not run");
    let caller = thread::current().id();
    pool.enqueue(Box::new(move || {
        let on = thread::current().id();
        tx.send(if on == caller { "inline" } else { "worker" }).ok();
    }));
    assert_eq!(rx.try_recv(), Ok("inline"));
    assert!(!pool.pool.is_set(), "nothing spawned while backing off");
}

/// A job that ends up holding the pool's last `Arc` drops it on the worker it runs on, landing `WorkerPool::drop`
/// there; that drop must not join the pool (it would wait on the running worker itself). Mirrors a
/// `QueryPool::query` job outliving the reactor and every handle.
#[test]
fn dpool_query_job_holding_the_last_pool_arc_wedges_a_worker() {
    let pool = SharedPool::new(FILE_WORKER, bounds(1, 1));
    // The job's own clone; once the outer `pool` drops it becomes the last.
    let held = Arc::clone(&pool);
    let (proceed_tx, proceed_rx) = mpsc::channel::<()>();
    let (done_tx, done_rx) = mpsc::channel::<()>();
    let wake = WakeHandle::new().expect("wake");
    pool.submit(
        Box::new(move || {
            proceed_rx.recv().ok();
            // Last `Arc` -> `SharedPool::drop` -> `WorkerPool::drop`, here on the worker running this job.
            drop(held);
            // Reached only if that drop returned rather than self-joining.
            done_tx.send(()).ok();
        }),
        &wake,
    );
    drop(pool); // only the job's clone keeps the pool alive now
    proceed_tx.send(()).ok();
    assert!(
        done_rx.recv_timeout(Duration::from_secs(5)).is_ok(),
        "a job dropping the pool's last Arc wedged its worker",
    );
}

/// A worker of one pool dropping the last handle of a *different* pool joins that pool like any other thread would:
/// the self-join exemption is keyed to the worker's own pool, not to being any pool's worker. Asserted by order,
/// not timing - were the exemption over-broad, the drop would return while B's job is still blocked, and the first
/// `recv_timeout` below would see "b joined" arrive early.
#[test]
fn dpool_foreign_pool_dropped_on_a_worker_is_still_joined() {
    let a = WorkerPool::try_elastic(FILE_WORKER, bounds(1, 1)).unwrap();
    let b = WorkerPool::try_elastic(FILE_WORKER, bounds(1, 1)).unwrap();
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

    // The join cannot complete while B's job is parked on `release_rx`, so nothing may arrive yet; "b joined" now
    // means the exemption wrongly fired for a foreign pool.
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
