use super::*;
use crate::sync::atomic::{AtomicU64, AtomicUsize};
use crate::uring::wake::WakeHandle;

fn bounded_model(f: impl Fn() + Sync + Send + 'static) {
    let mut b = loom::model::Builder::new();
    b.preemption_bound = Some(3);
    b.check(f);
}

fn run_shared(off_loop: bool) -> Arc<RunShared> {
    Arc::new(RunShared {
        queue: Mutex::new(VecDeque::new()),
        ready: AtomicUsize::new(0),
        draining: AtomicBool::new(false),
        model_off_loop: off_loop,
        wake: Arc::new(LoopShared {
            stop: AtomicBool::new(false),
            graceful: AtomicBool::new(false),
            grace_ms: AtomicU64::new(0),
            wake: WakeHandle::new().expect("the model's wake"),
            #[cfg(feature = "net-server")]
            handed: crate::sync::atomic::AtomicUsize::new(0),
        }),
    })
}

/// A wake racing the drain is delivered exactly once: either this pass pops it, or the poke leaves the next armed
/// READ completing immediately and that pass pops it. Zero is the lost wakeup `wake_task`'s push-then-poke order
/// exists to prevent; two would be a dedup failure.
#[test]
fn loom_a_task_wake_is_never_lost() {
    bounded_model(|| {
        // The **on-loop** branch: no pass is running, so the wake must poke for itself. Gate the poke on
        // `off_loop()` alone and this model reports a deadlock - the loop parks on an eventfd nothing wrote.
        let run = run_shared(false);
        let w = Arc::new(TaskWake {
            id: TaskId { idx: 0, generation: 0 },
            queued: AtomicBool::new(false),
            run: Arc::clone(&run),
        });

        let t = {
            let w = Arc::clone(&w);
            loom::thread::spawn(move || {
                wake_task(&w);
            })
        };

        // The loop as the hosts run it: wake (park on the eventfd stand-in), then drain the queue. Push-then-poke
        // is what makes this terminate - poke first and a schedule exists where the poke is consumed before the
        // push is visible, the pop finds nothing, and the next wait parks forever (loom reports the deadlock).
        let mut delivered = 0usize;
        while delivered == 0 {
            run.wake.wake.drain();
            while let Some(_id) = run.take_ready() {
                poll_window(&w, || ());
                delivered += 1;
            }
        }
        t.join().expect("waker thread");
        assert_eq!(delivered, 1, "one wake, {delivered} deliveries");
    });
}

/// An **off-loop** wake landing while a pass is running still pokes, since the running pass may already have passed its
/// id by. Narrow `wake_task`'s `off_loop() || !draining` to `!draining` and this model deadlocks. An on-loop wake
/// inside a pass is a poll, which is sequential, so `a_self_waking_task_cannot_monopolise_a_drain_pass` covers it.
#[test]
fn loom_an_off_loop_wake_during_a_pass_still_pokes() {
    bounded_model(|| {
        let run = run_shared(true);
        let w = Arc::new(TaskWake {
            id: TaskId { idx: 0, generation: 0 },
            queued: AtomicBool::new(false),
            run: Arc::clone(&run),
        });

        // A pass is live for the whole race, marked the way the loop marks it.
        run.begin_pass();
        let t = {
            let w = Arc::clone(&w);
            loom::thread::spawn(move || wake_task(&w))
        };

        // The loop: park on the eventfd, then drain the queue.
        let mut delivered = 0usize;
        while delivered == 0 {
            run.wake.wake.drain();
            while let Some(_id) = run.take_ready() {
                poll_window(&w, || ());
                delivered += 1;
            }
        }
        t.join().expect("waker thread");
        assert_eq!(delivered, 1, "one wake, {delivered} deliveries");
    });
}

/// Two threads race one task's dedup edge, exactly one may claim it, and the queue carries exactly one id. Two foreign
/// wakers (a completion and an off-loop hand-wake) are what exercise `queued.swap`'s losing side.
#[test]
fn loom_two_wakers_race_one_edge() {
    bounded_model(|| {
        let run = run_shared(true);
        let w = Arc::new(TaskWake {
            id: TaskId { idx: 0, generation: 0 },
            queued: AtomicBool::new(false),
            run: Arc::clone(&run),
        });

        let hands: Vec<_> = (0..2)
            .map(|_| {
                let w = Arc::clone(&w);
                loom::thread::spawn(move || wake_task(&w))
            })
            .collect();
        let enqueued: usize = hands.into_iter().map(|h| usize::from(h.join().expect("waker"))).sum();
        assert_eq!(enqueued, 1, "{enqueued} of 2 wakers claimed the edge");

        run.wake.wake.drain();
        let mut ids = 0usize;
        while let Some(_id) = run.take_ready() {
            poll_window(&w, || ());
            ids += 1;
        }
        assert_eq!(ids, 1, "the queue held {ids} ids for one edge");
    });
}

/// A pass that samples a budget of zero still leaves the id reachable. `drain` reads `ready` once and `wake_task`
/// pushes before it publishes the count, so a pass can see zero with an id queued, and the count is published before
/// the poke.
#[test]
fn loom_a_zero_budget_pass_still_delivers() {
    bounded_model(|| {
        let run = run_shared(true);
        let w = Arc::new(TaskWake {
            id: TaskId { idx: 0, generation: 0 },
            queued: AtomicBool::new(false),
            run: Arc::clone(&run),
        });

        let t = {
            let w = Arc::clone(&w);
            loom::thread::spawn(move || wake_task(&w))
        };

        // `drain`'s shape: sample once, poll no more than that.
        let mut polled = 0usize;
        for _ in 0..run.ready.load(Ordering::Acquire) {
            if run.take_ready().is_some() {
                poll_window(&w, || ());
                polled += 1;
            }
        }
        if polled == 0 {
            // Deliberately *before* the join: joining first would serialize the waker's whole epilogue and the
            // ordering this guards would be unobservable. The loop parks on the poke, so what must hold is that the
            // count is published before the poke that wakes a reader of it.
            run.wake.wake.drain();
            let budget = run.ready.load(Ordering::Acquire);
            assert!(budget > 0, "a poke woke a pass with no budget");
            let mut later = 0usize;
            for _ in 0..budget {
                if run.take_ready().is_some() {
                    poll_window(&w, || ());
                    later += 1;
                }
            }
            assert_eq!(later, 1, "the id was not reachable after");
        }
        t.join().expect("waker thread");
    });
}

/// A wake landing around a poll window is never swallowed: if the waker's call was dedup-skipped, a poll of that
/// task *starts* after it - which is all the waker contract asks. [`poll_window`] clearing the edge before the poll
/// is what makes it true; clear after the poll instead and a wake mid-poll skips against a stale edge with no later
/// poll coming, which this model reports.
#[test]
fn loom_a_wake_around_a_poll_window_is_covered() {
    bounded_model(|| {
        let run = run_shared(true);
        let w = Arc::new(TaskWake {
            id: TaskId { idx: 0, generation: 0 },
            queued: AtomicBool::new(false),
            run: Arc::clone(&run),
        });
        // First wake, on the loop side: the task is queued as a completion would leave it.
        wake_task(&w);

        let polls = Arc::new(AtomicUsize::new(0));
        let t = {
            let (w, polls) = (Arc::clone(&w), Arc::clone(&polls));
            loom::thread::spawn(move || {
                let before = polls.load(Ordering::Acquire);
                let enqueued = wake_task(&w);
                (before, enqueued)
            })
        };

        // The loop: pop, then poll inside the window.
        let mut drained = 0usize;
        while let Some(_id) = run.take_ready() {
            poll_window(&w, || {
                polls.fetch_add(1, Ordering::Release);
            });
            drained += 1;
        }
        let (before, enqueued) = t.join().expect("waker thread");
        run.wake.wake.drain();
        while let Some(_id) = run.take_ready() {
            poll_window(&w, || {
                polls.fetch_add(1, Ordering::Release);
            });
            drained += 1;
        }
        assert!(drained >= 1, "the first wake was lost");
        if !enqueued {
            // A skipped wake must be covered by a poll that had not started when the wake returned.
            assert!(
                polls.load(Ordering::Acquire) > before,
                "a dedup-skipped wake was never followed by a poll"
            );
        }
    });
}

/// The covering poll sees what the wake published, on the path where nothing else carries it.
///
/// Every model above asserts a **count**, which stays green under `Relaxed`, and this one carries a payload. The
/// **skipping** wake takes no lock, so the only edge is `queued`, which exists only because [`poll_window`] acquires
/// there. Weaken either half to `Relaxed` and this goes red. Wherever loom schedules the racing wake, the *last* poll
/// is the covering one.
#[test]
fn loom_a_deduped_wake_publishes_what_it_wrote() {
    bounded_model(|| {
        let run = run_shared(true);
        let w = Arc::new(TaskWake {
            id: TaskId { idx: 0, generation: 0 },
            queued: AtomicBool::new(false),
            run: Arc::clone(&run),
        });
        // What an off-loop waker publishes before waking: a plain cell with no ordering of its own, which is the
        // shape a lock-free waker's readiness has.
        let payload = Arc::new(AtomicUsize::new(0));

        // Latch the edge, so the racing wake below has one to skip.
        wake_task(&w);

        let t = {
            let w = Arc::clone(&w);
            let p = Arc::clone(&payload);
            loom::thread::spawn(move || {
                p.store(1, Ordering::Relaxed);
                wake_task(&w);
            })
        };

        let mut last = 0usize;
        let mut polls = 0usize;
        while let Some(_id) = run.take_ready() {
            last = poll_window(&w, || payload.load(Ordering::Relaxed));
            polls += 1;
        }
        t.join().expect("waker thread");
        // Whatever the racing wake enqueued, if anything.
        while let Some(_id) = run.take_ready() {
            last = poll_window(&w, || payload.load(Ordering::Relaxed));
            polls += 1;
        }
        assert!(polls >= 1, "the latched wake was never polled");
        assert_eq!(last, 1, "the poll covering the wake did not see what it published");
    });
}
