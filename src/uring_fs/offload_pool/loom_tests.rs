use super::*;

const ZERO: Duration = Duration::ZERO;

/// Bounds with explicit floor and ceiling.
fn bounds(floor: usize, ceiling: usize) -> OffloadBounds {
    OffloadBounds { floor, ceiling }
}

/// Run a model under a preemption bound rather than exhaustively.
///
/// Full exploration of three threads on one condvar does not finish in useful time, so **these are bounded proofs, not
/// exhaustive ones**.
fn bounded_model_with(preemptions: usize, f: impl Fn() + Sync + Send + 'static) {
    let mut b = loom::model::Builder::new();
    b.preemption_bound = Some(preemptions);
    b.check(f);
}

fn bounded_model(f: impl Fn() + Sync + Send + 'static) {
    bounded_model_with(3, f);
}

/// A model's pool: no growth throttle and a zero stall threshold (loom has no clock), so every running worker
/// counts as blocked at once.
fn pool(floor: usize, ceiling: usize) -> WorkerPool {
    WorkerPool::try_elastic_tuned(FILE_WORKER, bounds(floor, ceiling), ZERO, ZERO, ZERO)
        .expect("the model's pool always spawns")
}

fn counting_job(n: &Arc<AtomicUsize>) -> Job {
    let n = Arc::clone(n);
    Box::new(move || {
        n.fetch_add(1, Ordering::Relaxed);
    })
}

/// Every submitted job runs exactly once, and `Drop` waits for the queue to empty and every worker to exit.
///
/// loom's `wait_timeout` never times out, so this checks the quiescent path and none of `Drop`'s exits that leave work
/// outstanding.
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
        assert_eq!(ran.load(Ordering::Relaxed), 2, "a queued job was dropped on the floor");
    });
}

/// Growth never exceeds the ceiling, and a grown pool still drains and joins cleanly. At `pool(1, 1)` a submit can find
/// no worker parked, so deleting the `g.total < ceiling` guard grows the pool to 2 and fails here.
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

/// `Drop` returns even when a worker never exits, since its wait is bounded and then detaches (see
/// `SHUTDOWN_DETACH_AFTER`).
///
/// Modelled with a worker counted in `total` that never exists, requested through the `detach_next_drop` seam. Remove
/// the detach and this model HANGS, which loom reports as a deadlock.
#[test]
fn loom_pool_drop_detaches_a_worker_that_never_exits() {
    bounded_model(|| {
        let p = pool(1, 1);
        let shared = Arc::clone(&p.shared);

        // A worker that is counted but will never exit.
        {
            let mut g = shared.inner.lock().unwrap_or_else(|e| e.into_inner());
            g.total += 1;
        }
        shared.detach_next_drop(1);
        drop(p);

        // Reaching here at all is the property. Detaching gives up the wait, so the phantom worker is still counted.
        let g = shared.inner.lock().unwrap_or_else(|e| e.into_inner());
        assert!(g.closed, "Drop returned without closing the pool");
        assert!(g.total > 0, "the model's phantom worker cannot have exited");
    });
}

/// A flush and a worker that wakes without a claim can reach for the same parked worker. Only the claimless exit
/// decrements `idle` itself, so if both counted the worker, `idle` would underflow here.
///
/// This pins the order of the wait loop's arms, and `a_timed_wait_expiry_takes_a_job_nobody_claimed` pins the claimless
/// arm itself.
#[test]
fn loom_a_claimless_take_cannot_double_count_a_claimed_worker() {
    bounded_model_with(2, || {
        let p = pool(1, 1);
        let shared = Arc::clone(&p.shared);

        // A job queued without a wake, as an unflushed enqueue leaves it.
        {
            let mut g = shared.inner.lock().unwrap_or_else(|e| e.into_inner());
            g.queue.push_back(Box::new(|| {}));
        }

        // One side claims the worker out of `idle`; the other lets it wake with no claim and take the job itself.
        let s = Arc::clone(&shared);
        let waker = loom::thread::spawn(move || s.cv.notify_all());
        let _ = p.flush(1);
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

/// The stall rule claims workers from the loop's thread while workers take jobs, finish and park. In every order:
/// no claim beyond the parked workers (`claim`'s assertion), every job runs exactly once, and every `running` entry
/// is removed by the worker that added it.
#[test]
fn loom_the_stall_rule_and_the_workers_agree_on_the_books() {
    bounded_model(|| {
        let ran = Arc::new(AtomicUsize::new(0));
        let p = pool(2, 2);
        let shared = Arc::clone(&p.shared);

        for _ in 0..3 {
            p.enqueue(counting_job(&ran));
        }
        let _ = p.flush(3);
        let _ = p.flush(0);
        drop(p);

        let g = shared.inner.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(g.total, 0, "Drop returned with workers still live");
        assert!(
            g.running.is_empty(),
            "{} running entries outlived their jobs",
            g.running.len()
        );
        drop(g);
        assert_eq!(ran.load(Ordering::Relaxed), 3, "a job was lost or run twice");
    });
}

/// An idle burst worker retires by decrementing `total` and returning **without** notifying, unlike the closing
/// path. `Drop` is waiting for `total` to reach zero, so a retirement that took the count to zero silently would
/// strand it forever.
///
/// Two guards prevent that, and each is **sufficient alone**. `!g.closed` refuses to retire once `Drop` has run, and
/// `g.total > shared.floor` refuses to retire the last worker. Delete both and loom reports the deadlock, so do not
/// "simplify" the condition to one of them.
#[test]
fn loom_pool_idle_retire_cannot_strand_drop() {
    bounded_model_with(2, || {
        let p = pool(1, 2);
        let shared = Arc::clone(&p.shared);

        // Force a second worker to exist so one is above the floor and therefore eligible to retire.
        {
            let mut g = shared.inner.lock().unwrap_or_else(|e| e.into_inner());
            g.total += 1;
        }
        spawn_worker(&shared).expect("the model's worker always spawns");

        // Race the retirement against the drop.
        let s = Arc::clone(&shared);
        let retire = loom::thread::spawn(move || s.retire_idle_workers(2));
        drop(p);
        retire.join().expect("retire requester");

        let g = shared.inner.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(g.total, 0, "Drop returned while {} worker(s) were still live", g.total);
    });
}

/// A job may drop the pool's last `Arc`, which runs `WorkerPool::drop` on a worker thread that is itself counted in
/// `total`. Joining there would wait on this very thread forever; `ON_POOL_WORKER` is what prevents it. loom
/// reports the deadlock if that guard stops working.
#[test]
fn loom_pool_self_join_is_avoided() {
    bounded_model(|| {
        let ran = Arc::new(AtomicUsize::new(0));
        let cell: Arc<Mutex<Option<WorkerPool>>> = Arc::new(Mutex::new(Some(pool(1, 1))));
        let shared = {
            let g = cell.lock().unwrap_or_else(|e| e.into_inner());
            Arc::clone(&g.as_ref().expect("just built").shared)
        };

        let c = Arc::clone(&cell);
        let n = Arc::clone(&ran);
        {
            let g = cell.lock().unwrap_or_else(|e| e.into_inner());
            g.as_ref().expect("just built").submit(Box::new(move || {
                // Taking the cell's pool here runs `WorkerPool::drop` on a pool worker. Drop *before* marking the job
                // done, so `ran == 1` means the pool has certainly been dropped by one side or the other.
                let taken = c.lock().unwrap_or_else(|e| e.into_inner()).take();
                drop(taken);
                n.fetch_add(1, Ordering::Relaxed);
            }));
        }

        // Take the pool out and release the cell before dropping, since `WorkerPool::drop` waits for the workers and
        // one of them may be blocked on this very lock.
        let taken = cell.lock().unwrap_or_else(|e| e.into_inner()).take();
        drop(taken);

        // If we dropped the pool, `Drop` already joined and the job has run. If the worker did, it retired without
        // a join and may still be in flight - so wait for it rather than racing its epilogue.
        while ran.load(Ordering::Relaxed) == 0 {
            loom::thread::yield_now();
        }

        // A self-drop skips the join, so `total` need not be zero here, but the pool must be closed.
        let g = shared.inner.lock().unwrap_or_else(|e| e.into_inner());
        assert!(g.closed, "dropping the pool did not close it");
    });
}

/// A job may instead drop the last `Arc` of a pool it is NOT a worker of. No exemption applies there, so the drop joins
/// that pool's workers, and a bare "am I a worker" flag would fail the asserts below.
#[test]
fn loom_pool_foreign_drop_still_joins() {
    bounded_model(|| {
        let a = pool(1, 1);
        let b = pool(1, 1);
        let b_shared = Arc::clone(&b.shared);

        // B's last handle moves into a job running on A's worker.
        a.submit(Box::new(move || drop(b)));

        // A's own drop joins its worker, so the job above has finished - and with it B's drop, whose contract must
        // have held in full.
        drop(a);
        let g = b_shared.inner.lock().unwrap_or_else(|e| e.into_inner());
        assert!(g.closed, "foreign drop did not close the pool");
        assert_eq!(g.total, 0, "foreign drop returned with workers still live");
    });
}

/// A loop told of an off-loop poke can read the deadline published before it. Otherwise it would sleep without a
/// timeout while the job waits behind a busy worker.
///
/// Drives `WorkerPool` directly, since under loom `SharedPool`'s `OnceCell` takes a lock that would carry the deadline
/// itself and hide the ordering under test.
#[test]
fn loom_a_published_deadline_reaches_the_loop_it_pokes() {
    use crate::uring::wake::Park;
    bounded_model(|| {
        let wake = Arc::new(WakeHandle::new().expect("the model's wake never fails"));
        wake.activate();
        let p = Arc::new(pool(1, 1));

        let (w, q) = (Arc::clone(&wake), Arc::clone(&p));
        let submitter = loom::thread::spawn(move || {
            // Two submits: the second can find the first's claimed worker not yet arrived, the only state in which
            // a model pool's flush of one returns a deadline.
            for _ in 0..2 {
                q.enqueue(Box::new(|| {}));
                q.flush_off_loop(&w);
            }
        });

        // The loop's half, as the parker's own model spells it.
        let verdict = wake.park();
        let told = matches!(verdict, Park::Drain) || wake.try_drain() > 0;
        let owed = p.recheck_owed();
        wake.unpark();
        submitter.join().expect("submitter");

        if told {
            assert!(
                owed.is_some(),
                "the loop was told of a poke whose deadline it could \
                     not read"
            );
        }
    });
}

/// Two first-submits race the lazy init: each may build a full pool, and the loser's is dropped inline (joining the
/// workers it started). Exactly one pool ends up installed, and **neither job is lost**.
#[test]
fn loom_shared_pool_init() {
    bounded_model(|| {
        let ran = Arc::new(AtomicUsize::new(0));
        let sp = SharedPool::new(FILE_WORKER, bounds(1, 1));
        let wake = Arc::new(WakeHandle::new().expect("the model's wake never fails"));

        let (a, b) = (Arc::clone(&sp), Arc::clone(&sp));
        let (ra, rb) = (Arc::clone(&ran), Arc::clone(&ran));
        let w = Arc::clone(&wake);
        let t = loom::thread::spawn(move || {
            a.submit(
                Box::new(move || {
                    ra.fetch_add(1, Ordering::Relaxed);
                }),
                &w,
            );
        });
        b.submit(
            Box::new(move || {
                rb.fetch_add(1, Ordering::Relaxed);
            }),
            &wake,
        );
        t.join().expect("racing submitter");

        assert!(sp.pool.is_set(), "no pool was installed");
        // Dropping the *last* `Arc` drops the installed pool, whose `Drop` drains the queue and joins - so by here
        // both jobs have run. `b` is still holding one, so it has to go first.
        drop(b);
        drop(sp);
        assert_eq!(ran.load(Ordering::Relaxed), 2, "a job was lost to the init race");
    });
}
