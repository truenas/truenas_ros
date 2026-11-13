use super::*;

/// Dropping a pending future abandons the result; the completion fires into an unread slot and everything after it
/// still works.
#[test]
fn a_dropped_future_leaves_its_completion_inert() {
    let Some((mut eng, mut fs, who)) = rig() else {
        return;
    };
    let dir = crate::tempdir::tempdir().expect("tempdir");
    let anchor = Anchor::open(dir.path()).expect("anchor");
    let done = Rc::new(StdCell::new(false));

    {
        let done = Rc::clone(&done);
        let mut conn = FsConn::new(&mut fs, &mut eng, None);
        let abandoned = conn.fut(|c, cb| c.open(who, &anchor, c"dropped.bin", creating(), cb));
        drop(abandoned);
        conn.spawn(move |t| async move {
            let opened = t.fut(|c, cb| c.open(who, &anchor, c"kept.bin", creating(), cb)).await;
            assert!(opened.file().is_some());
            done.set(true);
        });
    }
    drive(&mut fs, &mut eng, &done, "abandoned open");
}

/// The offload seam as a future: the job runs on the pool, the result resolves on-loop through the wake path.
#[test]
fn an_offload_future_delivers_on_loop() {
    let Some((mut eng, mut fs, _who)) = rig() else {
        return;
    };
    eng.arm_wake(pack_raw(TAG_WAKE, 0, 0)).expect("arm wake");
    let done = Rc::new(StdCell::new(false));

    {
        let done = Rc::clone(&done);
        let mut conn = FsConn::new(&mut fs, &mut eng, None);
        conn.spawn(move |t| async move {
            let n = t.offload_fut(|| Ok(41 + 1)).await.expect("offload job");
            assert_eq!(n, 42);
            done.set(true);
        });
    }
    drive(&mut fs, &mut eng, &done, "offload future");
}

/// A detached task's output is dropped by the executor, on the delivery path. Its destructor must therefore unwind
/// no further than the poll guard, or one request's output takes the reactor thread and every connection on it
/// down.
#[test]
fn a_detached_tasks_output_drops_inside_the_guard() {
    let Some((mut eng, mut fs, who)) = rig() else {
        return;
    };
    eng.arm_wake(pack_raw(TAG_WAKE, 0, 0)).expect("arm wake");
    let dir = crate::tempdir::tempdir().expect("tempdir");
    let anchor = Anchor::open(dir.path()).expect("anchor");

    struct Boom;
    impl Drop for Boom {
        fn drop(&mut self) {
            panic!("a task output's drop glue");
        }
    }

    {
        let anchor2 = anchor.clone();
        let mut conn = FsConn::new(&mut fs, &mut eng, None);
        // Detached, and pending: the handle is gone before the poll that finishes the task, so the executor holds
        // the last share of the slot the output lands in.
        drop(conn.spawn(move |t| async move {
            let _ = t.fut(|c, cb| c.open(who, &anchor2, c"boom.bin", creating(), cb)).await;
            Boom
        }));
    }

    let _quiet = crate::uring_fs::quiet_panics_on_this_thread();
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut turns = 0;
    while fs.tasks.live.get() != 0 {
        assert!(Instant::now() < deadline, "the task never finished");
        let escaped = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| turn(&mut fs, &mut eng)));
        let Ok(reaped) = escaped else {
            panic!("a drop-glue panic escaped onto the delivery path");
        };
        turns += 1;
        if reaped == 0 {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    assert!(turns > 0, "the drive never ran a turn");
}

/// A task spawned from inside a task runs, and a slot a retired task left is reused rather than grown past.
///
/// Both halves are asserted. Parent and child coexist, so the table grows to two while they run; the assertion that
/// everything retired would hold on its own even if `insert` never popped `free`, so the spawn afterwards is what
/// pins recycling.
#[test]
fn tasks_nest_and_slots_recycle() {
    let Some((mut eng, mut fs, _who)) = rig() else {
        return;
    };
    eng.arm_wake(pack_raw(TAG_WAKE, 0, 0)).expect("arm wake");
    let done = Rc::new(StdCell::new(false));

    {
        let done = Rc::clone(&done);
        let mut conn = FsConn::new(&mut fs, &mut eng, None);
        conn.spawn(move |t| async move {
            let inner_ran = Rc::new(StdCell::new(false));
            {
                let inner_ran = Rc::clone(&inner_ran);
                t.spawn(move |t2| async move {
                    // One real suspension, so the child outlives its parent's poll.
                    t2.offload_fut(|| Ok(())).await.expect("child offload");
                    inner_ran.set(true);
                });
            }
            while !inner_ran.get() {
                // Yield to the loop until the child lands.
                t.offload_fut(|| Ok(())).await.expect("tick");
            }
            done.set(true);
        });
    }
    drive(&mut fs, &mut eng, &done, "nested tasks");
    assert_eq!(
        fs.tasks.free.len(),
        fs.tasks.slots.len(),
        "a retired task left its slot occupied"
    );
    let grown = fs.tasks.slots.len();
    assert_eq!(grown, 2, "parent and child coexist");
    {
        let mut conn = FsConn::new(&mut fs, &mut eng, None);
        drop(conn.spawn(|_t| async {}));
    }
    assert_eq!(
        fs.tasks.slots.len(),
        grown,
        "a spawn after two retirements grew the table instead of \
             reusing a free slot"
    );
}

/// A stale waker - its task retired, the slot's generation moved on - is inert: draining it must not poll the
/// slot's next tenant.
#[test]
fn a_stale_waker_does_not_poll_the_slots_next_tenant() {
    let Some((mut eng, mut fs, _who)) = rig() else {
        return;
    };

    // A future that parks forever, counting its polls and leaking its waker to the test.
    struct Park {
        polls: Rc<StdCell<u32>>,
        waker_out: Rc<RefCell<Option<Waker>>>,
    }
    impl Future for Park {
        type Output = ();
        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
            self.polls.set(self.polls.get() + 1);
            *self.waker_out.borrow_mut() = Some(cx.waker().clone());
            Poll::Pending
        }
    }

    let first_waker = Rc::new(RefCell::new(None));
    let polls = Rc::new(StdCell::new(0u32));
    {
        let waker_out = Rc::clone(&first_waker);
        let polls = Rc::clone(&polls);
        let mut conn = FsConn::new(&mut fs, &mut eng, None);
        // An immediately-ready task: retires at its spawn poll.
        conn.spawn(move |_t| async move {});
        // Its slot is free again; this task takes it.
        conn.spawn(move |_t| Park { polls, waker_out });
    }
    // The parked task's waker id names (slot 0, generation 1). Rebuild a *stale* waker for generation 0 and fire
    // it.
    let stale = std::sync::Arc::new(TaskWake {
        id: TaskId { idx: 0, generation: 0 },
        queued: AtomicBool::new(false),
        run: Arc::clone(fs.tasks.run.as_ref().expect("run queue")),
    });
    wake_task(&stale);

    assert!(
        first_waker.borrow().is_some(),
        "the tenant was polled at spawn and parked"
    );
    assert_eq!(polls.get(), 1, "one spawn poll before the stale wake");
    let mut conn = FsConn::new(&mut fs, &mut eng, None);
    conn.run_woken();
    // The stale id was consumed without polling the slot's tenant.
    assert_eq!(polls.get(), 1, "tenant disturbed by a stale wake");
    assert!(fs.tasks.slots[0].entry.is_some(), "tenant evicted");
}

/// `TaskFs` reached outside a poll refuses. Debug builds assert;
/// this is the release half, where the errno is the whole report.
///
/// It must not be `ECANCELED`: that is this module's one meaning for "the reactor is going away", and a release
/// consumer reading it winds a healthy server down over a caller's bug. Teardown still answers it -
/// `a_task_dropped_at_teardown_may_reach_its_facade` is that side.
#[cfg(not(debug_assertions))]
#[test]
fn task_fs_outside_a_poll_is_refused_rather_than_torn_down() {
    let t = TaskFs::new();
    let fut = t.fut(|_c, _cb| unreachable!("no facade to submit on"));
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    let mut fut = std::pin::pin!(fut);
    let Poll::Ready(done) = fut.as_mut().poll(&mut cx) else {
        panic!("an unsubmittable op left its future pending");
    };
    assert!(done.was_refused(), "the crate refused this, not the kernel");
    assert!(
        matches!(done.result(), Err(crate::Error::Errno(Errno::EINVAL))),
        "a misused handle must not answer ECANCELED: {:?}",
        done.result()
    );
}

/// The three ways a join yields no output need three answers. A handle polled twice conflated with a task torn down
/// before it finished sends a reader looking for work that did not happen, when what happened is that the work
/// finished and this caller asked twice.
#[test]
fn a_second_join_poll_is_not_a_task_that_never_finished() {
    let Some((mut eng, mut fs, _who)) = rig() else {
        return;
    };
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);

    let handle = {
        let mut conn = FsConn::new(&mut fs, &mut eng, None);
        conn.spawn(|_t| async { 7u32 })
    };
    let mut handle = std::pin::pin!(handle);
    assert!(matches!(handle.as_mut().poll(&mut cx), Poll::Ready(Ok(7))));
    let Poll::Ready(Err(e)) = handle.as_mut().poll(&mut cx) else {
        panic!("a spent handle must resolve, not pend");
    };
    assert!(
        matches!(e, JoinError::Consumed),
        "a spent handle must not read as a task that never ran: {e}"
    );

    // And the genuine no-output case still reads as one.
    struct Park;
    impl Future for Park {
        type Output = ();
        fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
            Poll::Pending
        }
    }
    let parked = {
        let mut conn = FsConn::new(&mut fs, &mut eng, None);
        conn.spawn(|_t| Park)
    };
    drop(fs); // teardown: the task never finishes
    let mut parked = std::pin::pin!(parked);
    let Poll::Ready(Err(e)) = parked.as_mut().poll(&mut cx) else {
        panic!("a torn-down task must resolve its handle");
    };
    assert!(matches!(e, JoinError::Dropped), "want Dropped, got {e}");
}

/// A task still pending at teardown has its future dropped with no poll on the stack. A guard of the "submit on
/// drop" shape reaches `TaskFs` there, and that is not misuse - it is the documented "whatever outlives the loop is
/// dropped with the reactor's tables". In a debug build an assert there is a second panic, and a teardown that is
/// itself an unwind then aborts, replacing the first panic's diagnosis with a bare SIGABRT.
///
/// One test for both profiles: the release build never asserted, so what it pins is that the shape stays a silent
/// no-op.
#[test]
fn a_task_dropped_at_teardown_may_reach_its_facade() {
    let Some((mut eng, mut fs, _who)) = rig() else {
        return;
    };

    struct SubmitOnDrop(TaskFs);
    impl Drop for SubmitOnDrop {
        fn drop(&mut self) {
            // Refused, because there is no poll - but refused quietly, because this is teardown.
            drop(self.0.fut(|_c, _cb| {}));
        }
    }
    struct Park(#[allow(dead_code)] SubmitOnDrop);
    impl Future for Park {
        type Output = ();
        fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
            Poll::Pending
        }
    }

    {
        let mut conn = FsConn::new(&mut fs, &mut eng, None);
        drop(conn.spawn(|t| Park(SubmitOnDrop(t))));
    }
    assert_eq!(fs.tasks.live.get(), 1, "the task is parked");
    // The teardown itself: no panic, in either profile.
    drop(fs);
}

/// A nested `owner_is_gone` must not call a live owner dead.
///
/// Inside a `fut`'s submit closure the facade is parked out of the thread-local for the extent of the call, so the
/// nested reach cannot read the owner's state - and answering `true` there makes the natural helper shape, a
/// closure that both checks and submits, abandon work for a connection that is alive. Release half; the misuse
/// asserts in debug like every sibling, so the whole test is `cfg`'d the same way.
#[cfg(not(debug_assertions))]
#[test]
fn a_nested_owner_check_does_not_call_a_live_owner_gone() {
    let Some((mut eng, mut fs, _who)) = rig() else {
        return;
    };
    let owner = Some((4u32, 1u64));
    let seen: Rc<StdCell<Option<(bool, bool)>>> = Rc::new(StdCell::new(None));
    {
        let out = Rc::clone(&seen);
        let mut conn = FsConn::new(&mut fs, &mut eng, owner);
        drop(conn.spawn(move |t| async move {
            let plain = t.owner_is_gone();
            let nested = Rc::new(StdCell::new(false));
            let n2 = Rc::clone(&nested);
            let t2 = &t;
            drop(t.fut(move |_c, _cb| {
                n2.set(t2.owner_is_gone());
            }));
            out.set(Some((plain, nested.get())));
        }));
    }
    let (plain, nested) = seen.get().expect("the task ran");
    assert!(!plain, "the owner is live");
    assert!(
        !nested,
        "a nested reach reported a live owner as gone - the check \
             inside a submit closure winds a healthy handler down"
    );
}

/// A re-arming task winds down when the server drains, on the signal alone.
///
/// Every await here succeeds and the owner stays live, so neither of the other wind-down signals ever fires -
/// without [`TaskFs::draining`] this shape holds a graceful drain open to its grace deadline, which is the case the
/// net drain test can only bound from above. The task is given a generous iteration budget precisely so the signal,
/// not the budget, is what ends it: the negative control (the getter hardwired `false`) runs the budget out and
/// fails the count below.
#[test]
fn a_rearming_task_winds_down_when_the_server_drains() {
    let Some((mut eng, mut fs, _who)) = rig() else {
        return;
    };
    eng.arm_wake(pack_raw(TAG_WAKE, 0, 0)).expect("arm wake");
    let rounds = Rc::new(StdCell::new(0usize));
    let ended = Rc::new(StdCell::new(false));
    {
        let (n, e) = (Rc::clone(&rounds), Rc::clone(&ended));
        let mut conn = FsConn::new(&mut fs, &mut eng, Some((9, 1)));
        drop(conn.spawn(move |t| async move {
            for _ in 0..64 {
                let _ = t.offload_fut(|| Ok::<_, crate::Error>(1u8)).await;
                n.set(n.get() + 1);
                if t.draining() {
                    e.set(true);
                    return;
                }
            }
        }));
    }

    // A few live rounds first: the signal is off and the task runs.
    let deadline = Instant::now() + Duration::from_secs(10);
    while rounds.get() < 2 {
        assert!(Instant::now() < deadline, "a couple of live rounds never finished");
        if turn(&mut fs, &mut eng) == 0 {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    assert!(!ended.get(), "nothing has asked for a drain yet");

    // The drain request, as the net server's shutdown_graceful makes it. The task's next between-awaits check ends
    // it.
    eng.shared.request_graceful(5_000);
    drive(&mut fs, &mut eng, &ended, "the wind-down");
    assert!(
        rounds.get() < 64,
        "the task ran its whole budget: the drain signal never \
             reached it"
    );
    assert_eq!(fs.tasks.live.get(), 0, "and it retired");
}

/// A task awaiting only offloads learns its owner is gone, because nothing else will tell it.
///
/// The two signals this module names - "your ops start failing" and "the source feeding you closes" - are both
/// unreachable for this shape: an offload is never cancelled and always delivers. Left to run, it holds the live
/// gauge up and a graceful drain with it, so the reactor waits out its whole grace period on work for a connection
/// that hung up.
#[test]
fn an_offload_only_task_can_see_that_its_owner_is_gone() {
    let Some((mut eng, mut fs, _who)) = rig() else {
        return;
    };
    eng.arm_wake(pack_raw(TAG_WAKE, 0, 0)).expect("arm wake");
    let owner = Some((3u32, 1u64));
    let first = Rc::new(StdCell::new(false));
    let saw_gone = Rc::new(StdCell::new(false));

    {
        let f = Rc::clone(&first);
        let g = Rc::clone(&saw_gone);
        let mut conn = FsConn::new(&mut fs, &mut eng, owner);
        drop(conn.spawn(move |t| async move {
            for _ in 0..64 {
                let _ = t.offload_fut(|| Ok::<_, crate::Error>(1u8)).await;
                f.set(true);
                // Every await answered `Ok`; the owner's state is the only thing that ends this.
                if t.owner_is_gone() {
                    g.set(true);
                    return;
                }
            }
        }));
    }

    // Rounds with the owner live: the task keeps going.
    drive(&mut fs, &mut eng, &first, "a first offload round");
    assert_eq!(fs.tasks.live.get(), 1, "still running for a live owner");
    assert!(!saw_gone.get(), "nothing has closed yet");

    // The connection closes. The sweep cancels nothing here - the task holds no ring op - so the record it leaves
    // is the whole signal.
    fs.cancel_owned_by(&mut eng, vec![(3, 1)]);
    drive(&mut fs, &mut eng, &saw_gone, "the wind-down");
    assert_eq!(fs.tasks.live.get(), 0, "and wound down on it");
}

/// One task's destructor panicking at teardown does not take the tasks queued behind it.
///
/// The mark above suppresses the assert a submit-on-drop guard raises; it does nothing for a destructor that panics
/// for its own reasons, and that panic escapes a `Drop` impl - which aborts outright when the teardown is itself an
/// unwind. The evidence has to be a *second* task: contained means the sweep carries on, so what it drops is what
/// says so.
#[test]
fn a_teardown_panic_does_not_take_the_tasks_behind_it() {
    let Some((mut eng, mut fs, _who)) = rig() else {
        return;
    };

    struct PanicOnDrop;
    impl Drop for PanicOnDrop {
        fn drop(&mut self) {
            panic!("a task destructor");
        }
    }
    struct Note(Rc<StdCell<bool>>);
    impl Drop for Note {
        fn drop(&mut self) {
            self.0.set(true);
        }
    }
    struct Park<T>(#[allow(dead_code)] T);
    impl<T> Future for Park<T> {
        type Output = ();
        fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
            Poll::Pending
        }
    }

    let reached = Rc::new(StdCell::new(false));
    let join = {
        let mut conn = FsConn::new(&mut fs, &mut eng, None);
        let h = conn.spawn(|_t| Park(PanicOnDrop));
        let note = Rc::clone(&reached);
        drop(conn.spawn(move |_t| Park(Note(note))));
        h
    };
    assert_eq!(fs.tasks.live.get(), 2, "both tasks are parked");

    let _quiet = crate::uring_fs::quiet_panics_on_this_thread();
    drop(fs);
    assert!(reached.get(), "a panicking destructor took the task behind it");

    // And the payload reached the handle rather than the process.
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    let mut join = std::pin::pin!(join);
    let Poll::Ready(Err(JoinError::Panic(payload))) = join.as_mut().poll(&mut cx) else {
        panic!("the panicking task's handle did not learn why");
    };
    assert_eq!(
        payload.downcast_ref::<&str>(),
        Some(&"a task destructor"),
        "the payload did not survive"
    );
}

/// A `TaskFs` that left its body cannot submit under whatever task happens to be running.
///
/// Removing `Clone` does not keep it inside its body - the handle is `'static` and `!Send`, so a body can *move* it
/// into any `'static` non-`Send` place on the loop thread and something else can pick it up there. Identity is what
/// refuses it: without the check the op is submitted against the running task's facade and stamped its owner, so
/// the wrong connection's teardown sweep cancels it and the right one leaves its descriptor parked.
///
/// The debug half; `_without_asserts` is the release sibling, and the gate runs both profiles.
#[cfg(debug_assertions)]
#[test]
fn a_smuggled_task_handle_is_refused() {
    let Some((mut eng, mut fs, _who)) = rig() else {
        return;
    };
    let smuggled: Rc<StdRefCell<Option<TaskFs>>> = Rc::new(StdRefCell::new(None));

    let outcome = {
        let stash = Rc::clone(&smuggled);
        let take = Rc::clone(&smuggled);
        let mut conn = FsConn::new(&mut fs, &mut eng, None);
        // A: hands its own handle out and ends.
        drop(conn.spawn(move |t| async move {
            *stash.borrow_mut() = Some(t);
        }));
        // B: picks it up and submits through it during *its* poll.
        let _quiet = crate::uring_fs::quiet_panics_on_this_thread();
        conn.spawn(move |_t| async move {
            let other = take.borrow_mut().take().expect("A ran first");
            drop(other.fut(|_c, _cb| {}));
        })
    };

    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    let mut outcome = std::pin::pin!(outcome);
    let Poll::Ready(Err(JoinError::Panic(_))) = outcome.as_mut().poll(&mut cx) else {
        panic!("a smuggled handle submitted under the wrong task");
    };
}

/// The release half: no assert to catch it, so the state is what has to say so - the submission never happens and
/// the future resolves as one that cannot.
#[cfg(not(debug_assertions))]
#[test]
fn a_smuggled_task_handle_is_refused_without_asserts() {
    let Some((mut eng, mut fs, _who)) = rig() else {
        return;
    };
    let smuggled: Rc<StdRefCell<Option<TaskFs>>> = Rc::new(StdRefCell::new(None));
    let seen: Rc<StdCell<Option<Errno>>> = Rc::new(StdCell::new(None));

    {
        let stash = Rc::clone(&smuggled);
        let take = Rc::clone(&smuggled);
        let out = Rc::clone(&seen);
        let mut conn = FsConn::new(&mut fs, &mut eng, None);
        drop(conn.spawn(move |t| async move {
            *stash.borrow_mut() = Some(t);
        }));
        drop(conn.spawn(move |_t| async move {
            let other = take.borrow_mut().take().expect("A ran first");
            let done = other.fut(|_c, _cb| {}).await;
            out.set(match done.result() {
                Err(crate::Error::Errno(e)) => Some(e),
                _ => None,
            });
        }));
    }
    assert_eq!(
        seen.get(),
        Some(Errno::EINVAL),
        "a smuggled handle must submit nothing, and say so as a \
             refusal rather than as the reactor going away"
    );
}

/// The debug half: reaching `TaskFs` outside a poll asserts.
#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "TaskFs::fut with no facade")]
fn task_fs_outside_a_poll_debug_asserts() {
    let t = TaskFs::new();
    drop(t.fut(|_c, _cb| {}));
}

/// The live gauge an embedding host's drain reads: a spawned task counts until it retires, so a drain that consults
/// it cannot stop the loop with task work outstanding. A task pending with no op in flight is invisible to a
/// connection count, which is the case this exists for.
#[test]
fn the_task_gauge_tracks_live_tasks() {
    let Some((mut eng, mut fs, _who)) = rig() else {
        return;
    };
    let gauge = fs.task_gauge();
    assert_eq!(gauge.get(), 0, "idle");

    struct Park;
    impl Future for Park {
        type Output = ();
        fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
            Poll::Pending
        }
    }

    {
        let mut conn = FsConn::new(&mut fs, &mut eng, None);
        // Pending forever, with nothing in flight: exactly the shape a connection count cannot see.
        conn.spawn(|_t| Park);
        assert_eq!(gauge.get(), 1, "a parked task is live");
        // And one that finishes immediately does not linger.
        conn.spawn(|_t| async {});
    }
    assert_eq!(gauge.get(), 1, "the finished task retired");
}

/// A panicking task is contained: the caller that spawned it keeps running, the slot retires, and the payload
/// reaches the handle. An unwind escaping here would take the reactor thread and every connection on it.
#[test]
fn a_panicking_task_is_contained_and_reported() {
    let Some((mut eng, mut fs, _who)) = rig() else {
        return;
    };

    struct Boom;
    impl Future for Boom {
        type Output = ();
        fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
            panic!("task panic");
        }
    }

    // The default hook would print this one; it is expected. Scoped to this thread, so a concurrent test's real
    // panic still reaches the terminal.
    let handle = {
        let _quiet = crate::uring_fs::quiet_panics_on_this_thread();
        let mut conn = FsConn::new(&mut fs, &mut eng, None);
        conn.spawn(|_t| Boom)
    };

    assert_eq!(
        fs.tasks.free.len(),
        fs.tasks.slots.len(),
        "the panicking task stranded its slot"
    );

    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    let mut handle = std::pin::pin!(handle);
    let Poll::Ready(Err(JoinError::Panic(payload))) = handle.as_mut().poll(&mut cx) else {
        panic!("the handle did not report the panic");
    };
    assert_eq!(
        payload.downcast_ref::<&str>(),
        Some(&"task panic"),
        "the payload did not survive"
    );
}

/// The other three misuse guards, release halves: reaching `offload_fut`, `result_fut` or `spawn` outside a poll
/// cannot submit, so each resolves rather than pends. `CLAUDE.md` wants a test per half of a `debug_assert` + `if`
/// pair; the debug halves are below. Left untested, the `if` is free to resolve as anything - a slot that never
/// resolves at all included, which hangs the task holding `tasks.live` up and a graceful drain open with it.
///
/// `EINVAL` rather than `ECANCELED` for the two futures, on
/// `task_fs_outside_a_poll_is_refused_rather_than_torn_down`'s reasoning. `spawn` keeps `Dropped`, which its own
/// doc already covers both ways: the body never ran, and there is no third meaning for that answer to collide with.
#[cfg(not(debug_assertions))]
#[test]
fn the_other_task_fs_guards_resolve_outside_a_poll() {
    let t = TaskFs::new();
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);

    let mut off = std::pin::pin!(t.offload_fut(|| Ok::<_, crate::Error>(1)));
    assert!(
        matches!(
            off.as_mut().poll(&mut cx),
            Poll::Ready(Err(crate::Error::Errno(Errno::EINVAL)))
        ),
        "offload_fut outside a poll must resolve as a refusal"
    );

    let mut res = std::pin::pin!(t.result_fut(|_c, _cb: OnResult<u32>| {}));
    assert!(
        matches!(
            res.as_mut().poll(&mut cx),
            Poll::Ready(Err(crate::Error::Errno(Errno::EINVAL)))
        ),
        "result_fut outside a poll must resolve as a refusal"
    );

    let mut join = std::pin::pin!(t.spawn(|_t| async { 7u8 }));
    assert!(
        matches!(join.as_mut().poll(&mut cx), Poll::Ready(Err(JoinError::Dropped))),
        "a spawn that never ran must resolve its join"
    );
}

/// The debug halves of the same three guards.
#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "TaskFs::offload_fut with no facade")]
fn task_fs_offload_outside_a_poll_debug_asserts() {
    drop(TaskFs::new().offload_fut(|| Ok::<_, crate::Error>(1)));
}

/// And `result_fut`'s.
#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "TaskFs::result_fut with no facade")]
fn task_fs_result_fut_outside_a_poll_debug_asserts() {
    drop(TaskFs::new().result_fut(|_c, _cb: OnResult<u32>| {}));
}

/// And `spawn`'s.
#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "TaskFs::spawn with no facade")]
fn task_fs_spawn_outside_a_poll_debug_asserts() {
    drop(TaskFs::new().spawn(|_t| async {}));
}

/// `run_woken` drains a task woken by hand from a callback-side context, without waiting for the next completion.
#[test]
fn run_woken_polls_a_hand_woken_task() {
    let Some((mut eng, mut fs, _who)) = rig() else {
        return;
    };

    // A future that parks once, hands its waker out, and finishes on its second poll.
    struct Once {
        waker_out: Rc<RefCell<Option<Waker>>>,
        polled: bool,
    }
    impl Future for Once {
        type Output = ();
        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
            if self.polled {
                return Poll::Ready(());
            }
            self.polled = true;
            *self.waker_out.borrow_mut() = Some(cx.waker().clone());
            Poll::Pending
        }
    }

    let waker_slot = Rc::new(RefCell::new(None));
    {
        let waker_out = Rc::clone(&waker_slot);
        let mut conn = FsConn::new(&mut fs, &mut eng, None);
        conn.spawn(move |_t| Once {
            waker_out,
            polled: false,
        });
    }
    let waker: Waker = waker_slot.borrow_mut().take().expect("parked at spawn");
    waker.wake();

    let mut conn = FsConn::new(&mut fs, &mut eng, None);
    conn.run_woken();
    assert_eq!(
        fs.tasks.free.len(),
        fs.tasks.slots.len(),
        "the woken task did not run to completion"
    );
}

/// A drain pass covers exactly what was queued when it began: a task that wakes itself on every poll runs once per
/// pass and its re-wake waits for the next, instead of the pass spinning on it forever with the ring starved. The
/// guard inside the future is what a regression hits - an unbounded pass re-polls it past the cap and fails by name
/// rather than hanging the suite.
#[test]
fn a_self_waking_task_cannot_monopolise_a_drain_pass() {
    let Some((mut eng, mut fs, _who)) = rig() else {
        return;
    };

    struct Spin {
        polls: Rc<StdCell<u32>>,
    }
    impl Future for Spin {
        type Output = ();
        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
            let n = self.polls.get() + 1;
            self.polls.set(n);
            assert!(n < 10, "an unbounded drain pass kept re-polling");
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }

    let polls = Rc::new(StdCell::new(0));
    {
        let polls = Rc::clone(&polls);
        let mut conn = FsConn::new(&mut fs, &mut eng, None);
        conn.spawn(move |_t| Spin { polls });
    }
    assert_eq!(polls.get(), 1, "the spawn poll");
    drain(&mut fs, &mut eng);
    assert_eq!(polls.get(), 2, "one poll per pass");
    drain(&mut fs, &mut eng);
    assert_eq!(polls.get(), 3, "one poll per pass, again");
}
