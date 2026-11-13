use super::*;
use crate::sync_fs::{AtFlags, Mode, OFlag, OpenHow, StatxMask};
use crate::uring::sys::{IORING_CQE_F_MORE, register_personality};
use crate::uring::user_data::{TAG_FS_DOMAIN, pack_raw, unpack_raw};
use crate::uring_fs::core::{TAG_CANCEL, TAG_WAKE, deliver_embedded, deliver_pool_completions};
use crate::uring_fs::{Anchor, Leaf, OffloadBounds, OpenStep, Personality, RwFlags, StepPath, ZfsAttr};
use std::cell::Cell as StdCell;
use std::cell::RefCell as StdRefCell;
use std::time::{Duration, Instant};

const RING_ENTRIES: u32 = 64;
const POOL: u32 = 8;

/// Build a real `Engine` or signal an environment skip (mirrors the integration suites' io_uring guard, gate
/// included).
fn engine_or_skip() -> Option<Engine> {
    // Under Miri there is no ring to set up - `io_uring_setup` is an unsupported foreign call that aborts the
    // interpreter, not an errno the arm below could catch - so the skip decision has to come first. The
    // ring-dependent tests then skip themselves exactly as they do on a ring-less host, and the Miri lane (ci.yml
    // `miri`) runs what is left: the pure-executor paths.
    if cfg!(miri) {
        return None;
    }
    match Engine::new(RING_ENTRIES, POOL) {
        Ok(e) => Some(e),
        Err(crate::Error::Errno(e)) if crate::uring::setup_unavailable(e) => None,
        Err(e) => panic!("Engine::new: {e}"),
    }
}

/// A ring, its fs tables, and a personality for the tests' own credentials - or a skip where rings cannot be
/// created.
fn rig() -> Option<(Engine, FsCore, Personality)> {
    let mut eng = engine_or_skip()?;
    let who = Personality(register_personality(eng.ring.raw_fd()).expect("register_personality"));
    // Armed because refusals deliver on the wake drain: without an armed wake the poke never surfaces as the
    // TAG_WAKE completion `turn` drains on, so a test that only ever refuses would wait for a delivery nothing can
    // make.
    eng.arm_wake(pack_raw(TAG_WAKE, 0, 0)).expect("arm wake");
    Some((eng, FsCore::new(8, OffloadBounds::default()), who))
}

/// One pass of the host loop: flush staged SQEs, then route every reaped CQE exactly as `UringFs::dispatch` does.
/// Never blocks - [`drive`] bounds a stall with a deadline instead, so a broken chain names itself rather than
/// hanging the suite.
fn turn(fs: &mut FsCore, eng: &mut Engine) -> usize {
    // Flush the pool before blocking, as the host loop does.
    fs.flush_offloads();
    eng.ring.submit().expect("submit");
    let mut reaped_n = 0;
    while let Some(cqe) = eng.ring.reap() {
        reaped_n += 1;
        if cqe.flags & IORING_CQE_F_MORE == 0 {
            eng.inflight = eng.inflight.saturating_sub(1);
        }
        let (tag, slot, gen32) = unpack_raw(cqe.user_data);
        if tag & TAG_FS_DOMAIN == 0 {
            continue;
        }
        match tag {
            TAG_WAKE => {
                eng.arm_wake(pack_raw(TAG_WAKE, 0, 0)).expect("re-arm wake");
                deliver_pool_completions(fs, eng);
            }
            TAG_CANCEL => {}
            _ => {
                let reaped = fs.on_cqe(eng, tag, slot, gen32, cqe.res);
                deliver_embedded(fs, eng, reaped);
            }
        }
    }
    reaped_n
}

/// Drive turns until `done` reads true; panic past the deadline so a stalled chain names itself instead of hanging
/// the suite.
fn drive(fs: &mut FsCore, eng: &mut Engine, done: &Rc<StdCell<bool>>, what: &str) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !done.get() {
        assert!(Instant::now() < deadline, "{what}: never finished");
        if turn(fs, eng) == 0 {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}

/// Pending pokes on the wake eventfd, read without blocking. The counter is consumed by the read, as the loop's
/// armed READ does.
fn pending_pokes(run: &RunShared) -> u64 {
    let mut buf: u64 = 0;
    // SAFETY: an 8-byte read from the live eventfd into a `u64`;
    // the fd is non-blocking, so an empty counter answers EAGAIN rather than parking the test.
    let n = unsafe {
        libc::read(
            run.wake.wake.as_raw_fd(),
            std::ptr::addr_of_mut!(buf).cast::<libc::c_void>(),
            8,
        )
    };
    if n == 8 { buf } else { 0 }
}

fn spec_dir() -> OpenHow {
    OpenHow::new().flags(OFlag::O_RDONLY | OFlag::O_DIRECTORY)
}

fn creating() -> OpenHow {
    OpenHow::new()
        .flags(OFlag::O_CREAT | OFlag::O_RDWR)
        .mode(Mode::from_bits_truncate(0o600))
}

// ---- the scoped-pointer protocol, without a ring ----------------
//
// Every test that reaches `with_current`/`with_conn` through an `FsConn` builds a real io_uring, and Miri aborts on
// `io_uring_setup` rather than taking the skip path - so these drive the same `park_in`/`reach_in` with a plain
// type, which is what lets Miri validate the module's only `unsafe`.

std::thread_local! {
    static PROBE: Cell<Option<NonNull<u32>>> = const { Cell::new(None) };
}

/// The parked value is reachable inside the extent and nowhere else, and a reach hands out a usable `&mut`.
#[test]
fn a_parked_pointer_is_reachable_only_inside_its_extent() {
    assert!(reach_in(&PROBE, |_: &mut u32| ()).is_none(), "before");
    let mut v = 7u32;
    park_in(&PROBE, NonNull::from(&mut v), || {
        let doubled = reach_in(&PROBE, |p: &mut u32| {
            *p *= 2;
            *p
        });
        assert_eq!(doubled, Some(14));
    });
    assert!(reach_in(&PROBE, |_: &mut u32| ()).is_none(), "after");
    assert_eq!(v, 14, "the reach wrote through to the parked value");
}

/// A reach nested inside a reach finds an empty cell: the pointer is *taken* for the call, so no second live `&mut`
/// to the same value can be derived. This is the aliasing claim the module's SAFETY comment rests on.
#[test]
fn a_nested_reach_cannot_alias_the_outer_borrow() {
    let mut v = 1u32;
    park_in(&PROBE, NonNull::from(&mut v), || {
        let inner = reach_in(&PROBE, |outer: &mut u32| {
            *outer += 1;
            let nested = reach_in(&PROBE, |_: &mut u32| ());
            // Still holding `outer` here: the nested reach must have found nothing.
            *outer += 1;
            nested
        });
        assert_eq!(inner, Some(None), "a nested reach aliased");
    });
    assert_eq!(v, 3);
}

/// Both halves restore the cell when their closure unwinds - a panicking task unwinds through the host loop, and a
/// cell left naming a dead frame is a dangling pointer for the next poll.
#[test]
fn an_unwind_restores_the_cell() {
    let mut v = 5u32;
    let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        park_in(&PROBE, NonNull::from(&mut v), || {
            reach_in(&PROBE, |_: &mut u32| panic!("boom"));
        });
    }));
    assert!(caught.is_err(), "the panic must propagate");
    assert!(
        reach_in(&PROBE, |_: &mut u32| ()).is_none(),
        "the cell still names a frame that is gone"
    );
}

/// Parks nest: an inner park shadows the outer and the outer is restored on the way out, so a task spawned from
/// inside a poll does not strand its parent's facade.
#[test]
fn parks_nest_and_restore_in_order() {
    let (mut outer, mut inner) = (1u32, 2u32);
    park_in(&PROBE, NonNull::from(&mut outer), || {
        park_in(&PROBE, NonNull::from(&mut inner), || {
            assert_eq!(reach_in(&PROBE, |p: &mut u32| *p), Some(2));
        });
        assert_eq!(reach_in(&PROBE, |p: &mut u32| *p), Some(1));
    });
}

/// The eager idiom the contract advertises: ops submitted while the body is being *assembled*, outside the async
/// block, must reach the ring like any other. They did not before - `body` ran before any facade was parked, so
/// each one resolved `ECANCELED` for an op that was never submitted, which reads to a task as "the connection went
/// away".
#[test]
fn a_body_may_submit_while_it_is_being_assembled() {
    let Some((mut eng, mut fs, who)) = rig() else {
        return;
    };
    let dir = crate::tempdir::tempdir().expect("tempdir");
    let anchor = Anchor::open(dir.path()).expect("anchor");
    std::fs::write(dir.path().join("eager"), b"x").expect("seed");
    let done = Rc::new(StdCell::new(false));

    {
        let done = Rc::clone(&done);
        let mut conn = FsConn::new(&mut fs, &mut eng, None);
        conn.spawn(move |t| {
            // Submitted here, before the async block exists.
            let opened = t.fut(|c, cb| c.open(who, &anchor, c"eager", OpenHow::new().flags(OFlag::O_RDONLY), cb));
            async move {
                let res = opened.await;
                assert!(
                    res.file().is_some(),
                    "an op submitted while assembling the body did \
                         not reach the ring: {:?}",
                    res.result()
                );
                done.set(true);
            }
        });
    }
    drive(&mut fs, &mut eng, &done, "eager submit from the body");
}

/// A wake from an inline `spawn` poll - on the loop thread, with no drain pass running to collect it - pokes the
/// loop. Without it the id sits queued while the host parks on a ring that has no reason to complete, and `queued`
/// then latches so even a later off-loop wake is deduped away.
#[test]
fn an_on_loop_wake_outside_a_pass_pokes_the_loop() {
    let Some((mut eng, mut fs, _who)) = rig() else {
        return;
    };

    struct WakeOnce {
        polls: Rc<StdCell<u32>>,
    }
    impl Future for WakeOnce {
        type Output = ();
        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
            self.polls.set(self.polls.get() + 1);
            if self.polls.get() == 1 {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            Poll::Ready(())
        }
    }

    let polls = Rc::new(StdCell::new(0));
    {
        let polls = Rc::clone(&polls);
        let mut conn = FsConn::new(&mut fs, &mut eng, None);
        conn.spawn(move |_t| WakeOnce { polls });
    }
    let run = Arc::clone(fs.tasks.run.as_ref().expect("run queue"));
    assert_eq!(run.ready.load(Ordering::Acquire), 1, "queued");
    assert!(
        pending_pokes(&run) > 0,
        "nothing poked: the loop will park and never schedule it"
    );
}

/// The dedup edge publishes what a deduped waker wrote - the property
/// [`loom_a_deduped_wake_publishes_what_it_wrote`] models, spelled for **Miri**, which is the only instrument on
/// x86 that can see it outside our own model. The hardware never shows the stale read (TSO), loom greens prove
/// nothing (under-exploration is its documented unsoundness), so re-weakening `poll_window`'s swap back to a plain
/// store leaves everything but that one model green - and this test, under `-Zmiri-many-seeds`, where the
/// weak-memory emulation supplies the stale value. Natively it passes vacuously and costs nothing.
///
/// **The payload must be an atomic read with `Relaxed`, and the assertion a value, not a race.** The tempting
/// probe - a non-atomic payload, expecting Miri to report the missing happens-before as a data race - is UB on the
/// *correct* code: a poll already in flight reads concurrently with the racing waker's pre-wake write, which no
/// edge orders (the coverage contract is about polls that start *after* the wake), and Miri's vector clocks flag
/// the pair even when they are seconds apart. Measured: four false races at 64 seeds with the shipped spelling. The
/// atomic form has no UB anywhere; the weakened edge shows up as this assertion instead.
#[test]
fn miri_a_deduped_wake_publishes_what_it_wrote() {
    let run = Arc::new(RunShared {
        queue: Mutex::new(VecDeque::new()),
        ready: AtomicUsize::new(0),
        draining: AtomicBool::new(false),
        wake: Arc::new(crate::uring::wake::LoopShared {
            stop: std::sync::atomic::AtomicBool::new(false),
            graceful: std::sync::atomic::AtomicBool::new(false),
            grace_ms: std::sync::atomic::AtomicU64::new(0),
            wake: crate::uring::wake::WakeHandle::new().expect("eventfd"),
            #[cfg(feature = "net-server")]
            handed: std::sync::atomic::AtomicUsize::new(0),
        }),
        loop_thread: std::thread::current().id(),
    });
    // Iterated, because one seed is one schedule: the stale-read window needs the racing thread to skip between the
    // latch and the poll, and a single race per execution leaves whole seed ranges never opening it. Miri's
    // scheduler keeps drawing from the seed across iterations, so each round is a fresh interleaving - measured,
    // this is the difference between the weakened edge surviving 16 seeds and dying inside the first.
    for round in 0..16u64 {
        let w = Arc::new(TaskWake {
            id: TaskId { idx: 0, generation: 0 },
            queued: AtomicBool::new(false),
            run: Arc::clone(&run),
        });
        let payload = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let want = round + 1;

        // Latch the edge, so the racing wake below is the deduped
        // one whenever the scheduler runs it before the window;
        // where it runs after, the wake enqueues and the post-join drain covers it through the queue lock instead.
        // Either way the last poll is the covering one - the same case split as the loom model.
        wake_task(&w);
        let t = {
            let (w, p) = (Arc::clone(&w), Arc::clone(&payload));
            std::thread::spawn(move || {
                p.store(want, std::sync::atomic::Ordering::Relaxed);
                wake_task(&w);
            })
        };
        let mut last = 0u64;
        while let Some(_id) = run.take_ready() {
            last = poll_window(&w, || payload.load(std::sync::atomic::Ordering::Relaxed));
        }
        t.join().expect("waker thread");
        while let Some(_id) = run.take_ready() {
            last = poll_window(&w, || payload.load(std::sync::atomic::Ordering::Relaxed));
        }
        assert_eq!(last, want, "the poll covering the wake did not see what it published");
    }
}

/// A nested drain ending does not un-mark the outer pass.
///
/// `PassGuard` restores the value it displaced rather than storing `false`; get that wrong and a callback that
/// calls [`FsConn::run_woken`] mid-delivery clears the mark for the rest of the outer pass, so every later on-loop
/// wake in it pokes the eventfd for work the pass's own trailing drain is already about to do. The nested-restore
/// property had no in-tree detector - reinstating the clear left the whole suite green - which is what this exists
/// to be. The nested drain is fed a woken task of its own, because a drain with nothing queued returns before its
/// guard exists.
#[test]
fn a_nested_drain_keeps_the_outer_pass_marked() {
    let Some((mut eng, mut fs, _who)) = rig() else {
        return;
    };

    // A task that parks once and hands its waker out.
    struct Park {
        waker_out: Rc<RefCell<Option<Waker>>>,
        polled: Rc<StdCell<u32>>,
    }
    impl Future for Park {
        type Output = ();
        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
            self.polled.set(self.polled.get() + 1);
            if self.polled.get() == 1 {
                *self.waker_out.borrow_mut() = Some(cx.waker().clone());
                return Poll::Pending;
            }
            Poll::Ready(())
        }
    }

    let park = || (Rc::new(RefCell::new(None::<Waker>)), Rc::new(StdCell::new(0u32)));
    let (waker_a, polled_a) = park();
    let (waker_b, polled_b) = park();
    {
        let mut conn = FsConn::new(&mut fs, &mut eng, None);
        for (w, p) in [(&waker_a, &polled_a), (&waker_b, &polled_b)] {
            let (w, p) = (Rc::clone(w), Rc::clone(p));
            drop(conn.spawn(move |_t| Park {
                waker_out: w,
                polled: p,
            }));
        }
    }
    let run = Arc::clone(fs.tasks.run.as_ref().expect("run queue"));
    let waker_a = waker_a.borrow_mut().take().expect("A parked");
    let waker_b = waker_b.borrow_mut().take().expect("B parked");

    // A is woken outside any pass - that poke is legitimate and is drained off the counter before the measurement
    // starts.
    waker_a.wake();
    let _ = pending_pokes(&run);

    in_pass(&mut fs, &mut eng, |fs, eng| {
        // The nested pass has A queued, so it really runs: marks, polls A, and its guard restores on the way out.
        drain(fs, eng);
        // An on-loop wake after it ended, still inside the outer pass: collected by the outer pass's trailing
        // drain, so a poke here is a wasted syscall.
        waker_b.wake_by_ref();
    });
    assert_eq!(polled_a.get(), 2, "the nested drain ran A");
    assert_eq!(polled_b.get(), 2, "the outer pass's drain ran B");
    assert_eq!(
        pending_pokes(&run),
        0,
        "a wake inside the outer pass poked: the nested drain \
             un-marked it"
    );
}

/// The converse, and the one that costs: a completion that resolves an op future wakes its task one statement
/// before the drain that polls it, so the wake must not spend an eventfd write, the CQE it produces and the re-arm
/// SQE that follows announcing work the same dispatch is already doing. The callback form pays none of that.
#[test]
fn a_completion_that_resolves_a_future_does_not_poke_the_loop() {
    let Some((mut eng, mut fs, who)) = rig() else {
        return;
    };
    // The wake `READ` is deliberately not armed: it would consume the eventfd counter this test is counting.
    // Nothing here needs it - every op is a ring op, delivered by `deliver_embedded`.
    let dir = crate::tempdir::tempdir().expect("tempdir");
    let anchor = Anchor::open(dir.path()).expect("anchor");
    let done = Rc::new(StdCell::new(false));

    const OPS: usize = 8;
    {
        let done = Rc::clone(&done);
        let anchor2 = anchor.clone();
        let mut conn = FsConn::new(&mut fs, &mut eng, None);
        conn.spawn(move |t| async move {
            for _ in 0..OPS {
                t.fut(|c, cb| c.open(who, &anchor2, c".", spec_dir(), cb))
                    .await
                    .file()
                    .expect("open");
            }
            done.set(true);
        });
    }
    let run = Arc::clone(fs.tasks.run.as_ref().expect("run queue"));
    // The spawn's own inline poll is outside a pass, so it pokes;
    // clear that one and count only what the completions cost.
    let _spawn_poke = pending_pokes(&run);

    let deadline = Instant::now() + Duration::from_secs(10);
    let mut pokes = 0;
    while !done.get() {
        assert!(Instant::now() < deadline, "the task never finished");
        if turn(&mut fs, &mut eng) == 0 {
            std::thread::sleep(Duration::from_millis(1));
        }
        pokes += pending_pokes(&run);
    }
    assert_eq!(
        pokes, 0,
        "{OPS} awaited ops cost {pokes} eventfd pokes for tasks the \
             same dispatch was about to poll"
    );
}

/// A re-entrant drain - `run_woken` from inside a poll - must not consume the running task's own queued wake. The
/// poll cleared
/// the dedup edge before running, so that id is the only record;
/// eat it and the task is never scheduled again.
#[test]
fn a_reentrant_drain_does_not_eat_the_running_tasks_wake() {
    let Some((mut eng, mut fs, _who)) = rig() else {
        return;
    };

    struct WakeThenReenter {
        polls: Rc<StdCell<u32>>,
    }
    impl Future for WakeThenReenter {
        type Output = ();
        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
            self.polls.set(self.polls.get() + 1);
            if self.polls.get() == 1 {
                cx.waker().wake_by_ref();
                // The documented hand-wake shape: re-enter the executor from inside the poll, through the id of
                // whichever task that is.
                let me = CURRENT_TASK.with(|c| c.get());
                with_conn(me, |c| c.run_woken());
                return Poll::Pending;
            }
            Poll::Ready(())
        }
    }

    let polls = Rc::new(StdCell::new(0));
    {
        let polls = Rc::clone(&polls);
        let mut conn = FsConn::new(&mut fs, &mut eng, None);
        conn.spawn(move |_t| WakeThenReenter { polls });
    }
    assert_eq!(polls.get(), 1, "the spawn poll");
    FsConn::new(&mut fs, &mut eng, None).run_woken();
    assert_eq!(polls.get(), 2, "the re-entrant drain consumed the task's own wake");
    assert_eq!(
        fs.tasks.free.len(),
        fs.tasks.slots.len(),
        "the task did not run to completion"
    );
}

/// A task awaits its child's output through the handle. The parent's resume rides the leftover poke: the child's
/// completion wakes the parent after the pass's budget was taken, so without the poke this join would stall with
/// nothing left in flight.
#[test]
fn a_join_handle_resolves_with_the_tasks_output() {
    let Some((mut eng, mut fs, _who)) = rig() else {
        return;
    };
    eng.arm_wake(pack_raw(TAG_WAKE, 0, 0)).expect("arm wake");
    let done = Rc::new(StdCell::new(false));

    {
        let done = Rc::clone(&done);
        let mut conn = FsConn::new(&mut fs, &mut eng, None);
        conn.spawn(move |t| async move {
            let child = t.spawn(|t2| async move { t2.offload_fut(|| Ok(40 + 2)).await.expect("child offload") });
            assert_eq!(child.await.expect("child joined"), 42);
            done.set(true);
        });
    }
    drive(&mut fs, &mut eng, &done, "join of a child task");
}

/// Dropping the handle detaches: the task still runs to its end, and only the output goes unread.
#[test]
fn a_dropped_join_handle_detaches() {
    let Some((mut eng, mut fs, _who)) = rig() else {
        return;
    };
    eng.arm_wake(pack_raw(TAG_WAKE, 0, 0)).expect("arm wake");
    let done = Rc::new(StdCell::new(false));

    {
        let done = Rc::clone(&done);
        let mut conn = FsConn::new(&mut fs, &mut eng, None);
        let handle = conn.spawn(move |t| async move {
            t.offload_fut(|| Ok(())).await.expect("offload");
            done.set(true);
            "unread"
        });
        drop(handle);
    }
    drive(&mut fs, &mut eng, &done, "detached task");
}

/// A task dropped before finishing - which only teardown does - resolves its join as `None` rather than leaving it
/// pending.
#[test]
fn a_task_dropped_at_teardown_resolves_its_join_as_none() {
    let Some((mut eng, mut fs, _who)) = rig() else {
        return;
    };

    /// Parks forever; only teardown ends it.
    struct Forever;
    impl Future for Forever {
        type Output = u32;
        fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<u32> {
            Poll::Pending
        }
    }

    let handle = {
        let mut conn = FsConn::new(&mut fs, &mut eng, None);
        conn.spawn(|_t| Forever)
    };
    drop(fs);

    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    let mut handle = std::pin::pin!(handle);
    assert!(
        matches!(handle.as_mut().poll(&mut cx), Poll::Ready(Err(JoinError::Dropped))),
        "teardown must resolve the join, not strand it"
    );
}

/// The run-queue count may not disagree with the queue it counts.
///
/// `wake_task` pushes under the queue lock and adjusts the count after releasing it, so an off-loop waker caught
/// between the two leaves the queue one longer than the count. A nested pass - a callback calling
/// [`FsConn::run_woken`] from inside a delivery - then spends count the outer pass's budget was sampled from, and
/// the outer pass pops the unaccounted id with a decrement that has nothing left to take.
///
/// It wraps, and [`drain`] samples exactly that as the per-pass entry bound: that bound is what returns this thread
/// to `submit_and_wait`, so at `usize::MAX` a task that re-wakes itself keeps one pass running and every connection
/// on the ring stops being served.
#[test]
fn a_nested_pass_cannot_run_the_ready_count_below_zero() {
    let Some((mut eng, mut fs, _who)) = rig() else {
        return;
    };

    /// Re-enters the executor from inside its own poll - the documented hand-wake shape.
    struct Reenter;
    impl Future for Reenter {
        type Output = ();
        fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
            let me = CURRENT_TASK.with(|c| c.get());
            with_conn(me, |c| c.run_woken());
            Poll::Pending
        }
    }
    struct Pend;
    impl Future for Pend {
        type Output = ();
        fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
            Poll::Pending
        }
    }

    {
        let mut conn = FsConn::new(&mut fs, &mut eng, None);
        let _reenter = conn.spawn(|_t| Reenter);
        let _pend = conn.spawn(|_t| Pend);
    }
    let run = Arc::clone(fs.tasks.run.as_ref().expect("run queue"));
    let (a, b) = (TaskId { idx: 0, generation: 0 }, TaskId { idx: 1, generation: 0 });

    // Two wakes fully accounted - what an on-loop `wake_task` leaves.
    for id in [a, b] {
        run.queue.lock().unwrap().push_back(id);
        run.ready.fetch_add(1, Ordering::Release);
    }
    // And a third from off the loop thread, caught inside `wake_task`'s window: pushed under the lock, its count
    // not landed yet.
    run.queue.lock().unwrap().push_back(a);
    assert_eq!(run.ready.load(Ordering::Acquire), 2, "setup");
    assert_eq!(run.queue.lock().unwrap().len(), 3, "setup");

    // Budget 2: pop a, which re-enters and lets a nested pass spend the count for b; the outer pass still has
    // budget for the third pop.
    drain(&mut fs, &mut eng);

    let left = run.queue.lock().unwrap().len();
    assert_eq!(
        run.ready.load(Ordering::Acquire),
        left,
        "the count disagrees with the queue it counts; a later pass \
             samples this as the entry bound that returns the thread to \
             the ring"
    );
}

mod timers;

mod allow_opens;

mod futures;

mod tasks;
