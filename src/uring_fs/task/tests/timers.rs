use super::*;

/// A timer completes on its own ring: relative, one-shot, expiry delivered as success - and not before its duration
/// has passed.
#[test]
fn a_timer_fires_after_its_duration() {
    let Some((mut eng, mut fs, _who)) = rig() else {
        return;
    };
    let done = Rc::new(StdCell::new(false));
    let started = Instant::now();
    {
        let done = Rc::clone(&done);
        let mut conn = FsConn::new(&mut fs, &mut eng, None);
        let armed = conn.timeout(Duration::from_millis(50), move |d, _conn| {
            assert!(
                d.result().is_ok(),
                "expiry is success, not ETIME: {:?}",
                d.result().err()
            );
            done.set(true);
        });
        assert!(armed.is_some(), "an uncapped arm cannot be refused");
    }
    drive(&mut fs, &mut eng, &done, "timer");
    assert!(
        started.elapsed() >= Duration::from_millis(45),
        "fired early: {:?}",
        started.elapsed()
    );
}

/// A deadline reached early gives its op slot back, instead of holding it for the wall-clock time it was armed for.
///
/// Every other op on this facade holds a slot until an I/O completes, and the table is sized on that. A timer holds
/// one for its whole duration, so a handler arming a 30 s deadline and finishing in milliseconds spends the rest of
/// it out of the handler budget - which is what makes the retraction load-bearing rather than a convenience. The
/// kernel's half is `io_try_cancel` falling through to `io_timeout_cancel` (`io_uring/cancel.c`), which
/// `submit_cancel` reaches because it leaves `IORING_ASYNC_CANCEL_FD` clear.
#[test]
fn a_cancelled_timer_gives_its_slot_back_before_it_expires() {
    let Some(mut eng) = engine_or_skip() else {
        return;
    };
    // One slot, so holding it is observable.
    let mut fs = FsCore::new(1, OffloadBounds::default());
    let done = Rc::new(StdCell::new(false));
    let started = Instant::now();

    let timer = {
        let done = Rc::clone(&done);
        let mut conn = FsConn::new(&mut fs, &mut eng, None);
        // An hour, so nothing here can pass by expiring.
        conn.timeout(Duration::from_secs(3600), move |d, _conn| {
            assert!(
                matches!(d.result(), Err(crate::Error::Errno(Errno::ECANCELED))),
                "a retracted timer answers ECANCELED: {:?}",
                d.result()
            );
            // Marked: ECANCELED *unmarked* is the teardown verdict a task winds down on, and a healthy retraction
            // the caller asked for must not read as the reactor going away.
            assert!(d.was_refused(), "a retraction must not wear the teardown verdict");
            done.set(true);
        })
        .expect("the table armed it")
    };
    assert!(!fs.has_free_op(), "the armed timer holds the only slot");

    {
        let mut conn = FsConn::new(&mut fs, &mut eng, None);
        conn.cancel_timeout(timer);
    }
    drive(&mut fs, &mut eng, &done, "the retraction");
    assert!(
        started.elapsed() < Duration::from_secs(60),
        "it waited out the arm rather than being retracted"
    );
    assert!(fs.has_free_op(), "the slot came back with the ECANCELED completion");

    // A `Timer` outliving its own op retracts nothing: the slot is reissued under a new generation, so the token
    // names no op.
    let fired = Rc::new(StdCell::new(false));
    {
        let fired = Rc::clone(&fired);
        let mut conn = FsConn::new(&mut fs, &mut eng, None);
        conn.timeout(Duration::from_millis(30), move |d, _conn| {
            assert!(d.result().is_ok(), "the reissued timer expires");
            fired.set(true);
        })
        .expect("the freed slot serves the next arm");
        conn.cancel_timeout(timer); // the spent one
    }
    drive(&mut fs, &mut eng, &fired, "a stale retraction is inert");
}

/// A `Timer` is scoped to the reactor that minted it: another reactor on the same thread starts its table at the
/// same slot and generation, so without the identity check a retraction with a foreign token cancels whoever holds
/// that slot here.
#[test]
fn a_foreign_reactors_timer_token_retracts_nothing() {
    let Some(mut eng_a) = engine_or_skip() else {
        return;
    };
    let Some(mut eng_b) = engine_or_skip() else {
        return;
    };
    let mut fs_a = FsCore::new(1, OffloadBounds::default());
    let mut fs_b = FsCore::new(1, OffloadBounds::default());

    // A's first timer and B's first timer: same slot, same generation, different reactors.
    let fired_a = Rc::new(StdCell::new(false));
    let token_a = {
        let fired = Rc::clone(&fired_a);
        let mut conn = FsConn::new(&mut fs_a, &mut eng_a, None);
        conn.timeout(Duration::from_millis(40), move |d, _c| {
            assert!(d.result().is_ok(), "A's timer expires normally");
            fired.set(true);
        })
        .expect("A arms")
    };
    let fired_b = Rc::new(StdCell::new(false));
    {
        let fired = Rc::clone(&fired_b);
        let mut conn = FsConn::new(&mut fs_b, &mut eng_b, None);
        conn.timeout(Duration::from_millis(40), move |d, _c| {
            assert!(
                d.result().is_ok(),
                "B's timer must expire - A's token cancelled it: {:?}",
                d.result()
            );
            fired.set(true);
        })
        .expect("B arms");
    }

    // A's token handed to B's facade: inert, not a cancel of B's timer.
    {
        let mut conn = FsConn::new(&mut fs_b, &mut eng_b, None);
        conn.cancel_timeout(token_a);
    }
    drive(&mut fs_b, &mut eng_b, &fired_b, "B's expiry");
    // And A's own timer still answers - untouched by the misuse.
    drive(&mut fs_a, &mut eng_a, &fired_a, "A's expiry");
}

/// One connection's timers are bounded at the host's cap, and a completion returns the headroom.
///
/// The cap is per owner, so the tenant beside a timer-hungry connection still arms - the two-sided starvation this
/// exists to prevent had a full table refusing a *different* connection's first submission. The N+1th arm answers
/// `EBUSY` with the refusal mark, exactly like a full table: the caller holds a deadline already, and its
/// completion is when arming again makes sense - which the retraction half below proves by reclaiming the headroom
/// early.
#[test]
fn a_connections_timers_are_capped_and_a_completion_frees_one() {
    let Some((mut eng, mut fs, _who)) = rig() else {
        return;
    };
    fs.set_timer_cap(2);
    let hour = Duration::from_secs(3600);
    let arm = |fs: &mut FsCore, eng: &mut Engine, owner: (u32, u64)| {
        let mut conn = FsConn::new(fs, eng, Some(owner));
        conn.timeout(hour, |_d, _c| {})
    };

    let a1 = arm(&mut fs, &mut eng, (1, 1));
    let a2 = arm(&mut fs, &mut eng, (1, 1));
    assert!(a1.is_some() && a2.is_some(), "up to the cap arms");
    assert!(arm(&mut fs, &mut eng, (1, 1)).is_none(), "the third arm is refused");
    // And the awaited form reads the refusal with its provenance, delivered at the wake drain the queued callback
    // rides.
    let seen3: Rc<StdCell<Option<(bool, bool)>>> = Rc::new(StdCell::new(None));
    {
        let out = Rc::clone(&seen3);
        let mut conn = FsConn::new(&mut fs, &mut eng, Some((1, 1)));
        drop(conn.spawn(move |t| async move {
            let d = t
                .fut(|c, cb| {
                    // The frame's sink carries any refusal.
                    let _ = c.timeout(hour, cb);
                })
                .await;
            out.set(Some((
                matches!(d.result(), Err(crate::Error::Errno(Errno::EBUSY))),
                d.was_refused(),
            )));
        }));
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    while seen3.get().is_none() {
        assert!(Instant::now() < deadline, "the refusal never delivered");
        if turn(&mut fs, &mut eng) == 0 {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    assert_eq!(
        seen3.get(),
        Some((true, true)),
        "refused as this crate's own EBUSY, not silently"
    );

    // The tenant beside it is untouched by the neighbour's cap.
    assert!(
        arm(&mut fs, &mut eng, (2, 1)).is_some(),
        "another owner's first arm is its own"
    );

    // A retraction returns the headroom on the spot - before any CQE - so the natural retract-then-rearm inside one
    // delivery holds at the cap. (The slot itself still comes back at the retracted timer's CQE.)
    {
        let mut conn = FsConn::new(&mut fs, &mut eng, None);
        conn.cancel_timeout(a1.expect("armed above"));
    }
    assert_eq!(
        fs.armed_timers_for_test(&(1, 1)),
        1,
        "the retraction must return the headroom synchronously"
    );
    assert!(
        arm(&mut fs, &mut eng, (1, 1)).is_some(),
        "so the replacement deadline arms in the same delivery"
    );
    // And the retracted timer's own CQE must not return it twice: drive until its slot frees, then the count still
    // covers the two live arms.
    let free_before_cqe = fs.op_free_len_for_test();
    let deadline = Instant::now() + Duration::from_secs(10);
    while fs.op_free_len_for_test() != free_before_cqe + 1 {
        assert!(Instant::now() < deadline, "the retracted timer's CQE never landed");
        if turn(&mut fs, &mut eng) == 0 {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    assert_eq!(
        fs.armed_timers_for_test(&(1, 1)),
        2,
        "a retraction's headroom must not come back a second time"
    );
}

/// The retraction's early headroom is a cap trade, not a cap escape: each swap frees a *count* while its slot rides
/// to a CQE no delivery inside the same dispatch will reap, so the arm screen also refuses at `armed + retiring`
/// reaching twice the cap - the documented mid-swap slot ceiling. Asserted on the *slots*, because the shipped
/// tests asserted the count alone and a retract-rearm loop at cap 1 walked a 64-slot table to zero free with the
/// count never leaving zero.
#[test]
fn a_mid_swap_owner_is_bounded_at_twice_its_cap_in_slots() {
    let Some((mut eng, mut fs, _who)) = rig() else {
        return;
    };
    fs.set_timer_cap(1);
    let hour = Duration::from_secs(3600);
    let owner = (1u32, 1u64);
    let free_at_start = fs.op_free_len_for_test();
    let mut arms = 0u32;
    let mut refused_at = None;
    for i in 0..8 {
        let mut conn = FsConn::new(&mut fs, &mut eng, Some(owner));
        match conn.timeout(hour, |_d, _c| {}) {
            Some(t) => {
                arms += 1;
                conn.cancel_timeout(t);
            }
            None => {
                refused_at = Some(i);
                break;
            }
        }
    }
    assert_eq!(arms, 2, "one full swap holds; the next arm is refused");
    assert_eq!(refused_at, Some(2), "refused at twice the cap");
    assert_eq!(
        free_at_start - fs.op_free_len_for_test(),
        2,
        "a mid-swap owner holds at most twice its cap in slots"
    );
    assert_eq!(fs.armed_timers_for_test(&owner), 0);
    assert_eq!(fs.retiring_timers_for_test(&owner), 2);
    // The parked slots return at their CQEs, and the bound lifts with them.
    let deadline = Instant::now() + Duration::from_secs(10);
    while fs.op_free_len_for_test() != free_at_start {
        assert!(Instant::now() < deadline, "a retracted timer's slot never came home");
        if turn(&mut fs, &mut eng) == 0 {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    assert_eq!(fs.retiring_timers_for_test(&owner), 0);
    let mut conn = FsConn::new(&mut fs, &mut eng, Some(owner));
    let t = conn.timeout(hour, |_d, _c| {});
    assert!(t.is_some(), "the bound lifts when the slots come home");
    if let Some(t) = t {
        conn.cancel_timeout(t);
    }
}

/// A host refusal delivers the plain callback with its verdict at the wake drain: the marked `EBUSY` a full budget
/// answers, with `None` still returned synchronously as "no timer to retract". The synchronous `None` is not the
/// report - a plain-callback caller has no channel but the callback, and a dropped continuation is a closed
/// connection for a request handler.
#[test]
fn a_host_refusal_delivers_a_plain_callback_with_its_verdict() {
    let Some((mut eng, mut fs, _who)) = rig() else {
        return;
    };
    fs.set_timer_cap(1);
    let hour = Duration::from_secs(3600);
    {
        let mut conn = FsConn::new(&mut fs, &mut eng, Some((1, 1)));
        assert!(conn.timeout(hour, |_d, _c| {}).is_some(), "cap spender");
    }
    let seen: Rc<StdCell<Option<(bool, bool)>>> = Rc::new(StdCell::new(None));
    {
        let out = Rc::clone(&seen);
        let mut conn = FsConn::new(&mut fs, &mut eng, Some((1, 1)));
        let refused = conn.timeout(hour, move |d, _c| {
            out.set(Some((
                matches!(d.result(), Err(crate::Error::Errno(Errno::EBUSY))),
                d.was_refused(),
            )));
        });
        assert!(refused.is_none(), "no timer exists to retract");
        assert!(seen.get().is_none(), "not inline: submit holds the core");
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    while seen.get().is_none() {
        assert!(Instant::now() < deadline, "the verdict never delivered");
        if turn(&mut fs, &mut eng) == 0 {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    assert_eq!(
        seen.get(),
        Some((true, true)),
        "the callback fires with the marked EBUSY, not a drop"
    );
}

/// The swept owner's refusal delivers the same callback with teardown's own vocabulary - `ECANCELED`, unmarked - so
/// a continuation keyed on it winds down exactly as it would had the sweep caught the op in flight.
#[test]
fn a_swept_refusal_delivers_teardowns_vocabulary() {
    let Some((mut eng, mut fs, _who)) = rig() else {
        return;
    };
    fs.cancel_owned_by(&mut eng, vec![(6, 1)]);
    let seen: Rc<StdCell<Option<(bool, bool)>>> = Rc::new(StdCell::new(None));
    {
        let out = Rc::clone(&seen);
        let mut conn = FsConn::new(&mut fs, &mut eng, Some((6, 1)));
        let refused = conn.timeout(Duration::from_secs(3600), move |d, _c| {
            out.set(Some((
                matches!(d.result(), Err(crate::Error::Errno(Errno::ECANCELED))),
                d.was_refused(),
            )));
        });
        assert!(refused.is_none(), "a swept owner cannot park time");
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    while seen.get().is_none() {
        assert!(Instant::now() < deadline, "the verdict never delivered");
        if turn(&mut fs, &mut eng) == 0 {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    assert_eq!(
        seen.get(),
        Some((true, false)),
        "unmarked ECANCELED: the sweep's verdict, delivered"
    );
}

/// A refusal requeued from inside its own delivery waits for the next drain pass: one call to the drain delivers
/// exactly what was queued when it began, FIFO, so a callback that re-arms and is refused again cannot spin the
/// ring from inside one pass - each attempt costs a wake round trip.
#[test]
fn a_refusal_requeued_mid_drain_delivers_on_the_next_pass() {
    let Some((mut eng, mut fs, _who)) = rig() else {
        return;
    };
    fs.set_timer_cap(1);
    let hour = Duration::from_secs(3600);
    {
        let mut conn = FsConn::new(&mut fs, &mut eng, Some((1, 1)));
        assert!(conn.timeout(hour, |_d, _c| {}).is_some(), "cap spender");
    }
    let log: Rc<StdRefCell<Vec<&'static str>>> = Rc::new(StdRefCell::new(Vec::new()));
    {
        let (l1, l2) = (Rc::clone(&log), Rc::clone(&log));
        let mut conn = FsConn::new(&mut fs, &mut eng, Some((1, 1)));
        let requeued = Rc::clone(&log);
        assert!(
            conn.timeout(hour, move |_d, c| {
                l1.borrow_mut().push("a");
                // Still at cap: this re-arm queues mid-drain.
                let _ = c.timeout(hour, move |_d, _c| {
                    requeued.borrow_mut().push("a2");
                });
            })
            .is_none()
        );
        assert!(
            conn.timeout(hour, move |_d, _c| {
                l2.borrow_mut().push("b");
            })
            .is_none()
        );
    }
    // One pass: the two pre-queued refusals deliver, in order; the mid-drain requeue does not.
    deliver_pool_completions(&mut fs, &mut eng);
    assert_eq!(*log.borrow(), vec!["a", "b"], "bounded to the pass");
    deliver_pool_completions(&mut fs, &mut eng);
    assert_eq!(*log.borrow(), vec!["a", "b", "a2"], "next pass takes it");
}

/// The drain's trailing re-poke is load-bearing for exactly one shape: a callback that re-arms while a *sibling*
/// refusal is still queued. The push's own poke is elided then (the queue was not empty), and the pass's wake is
/// already consumed, so without the re-poke the requeued refusal strands until some unrelated wake happens by.
/// Driven through the wake alone - no direct drain calls - so eliding the re-poke fails this test instead of
/// passing it.
#[test]
fn a_requeued_refusal_is_not_stranded_behind_its_siblings() {
    let Some((mut eng, mut fs, _who)) = rig() else {
        return;
    };
    fs.set_timer_cap(1);
    let hour = Duration::from_secs(3600);
    {
        let mut conn = FsConn::new(&mut fs, &mut eng, Some((1, 1)));
        assert!(conn.timeout(hour, |_d, _c| {}).is_some(), "cap spender");
    }
    let log: Rc<StdRefCell<Vec<&'static str>>> = Rc::new(StdRefCell::new(Vec::new()));
    {
        let (l1, l2) = (Rc::clone(&log), Rc::clone(&log));
        let requeued = Rc::clone(&log);
        let mut conn = FsConn::new(&mut fs, &mut eng, Some((1, 1)));
        assert!(
            conn.timeout(hour, move |_d, c| {
                l1.borrow_mut().push("a");
                // "b" is still queued here, so this push's poke is elided; only the drain's re-poke carries it.
                let _ = c.timeout(hour, move |_d, _c| {
                    requeued.borrow_mut().push("a2");
                });
            })
            .is_none()
        );
        assert!(
            conn.timeout(hour, move |_d, _c| {
                l2.borrow_mut().push("b");
            })
            .is_none()
        );
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    while log.borrow().len() < 3 {
        assert!(
            Instant::now() < deadline,
            "the requeued refusal stranded: {:?}",
            log.borrow()
        );
        if turn(&mut fs, &mut eng) == 0 {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    assert_eq!(*log.borrow(), vec!["a", "b", "a2"]);
}

/// The `Refused` state's whole transition table, on the slot alone: a parked refusal is settled only by the
/// callback route - a real answer supersedes it, the callback dropping unfired adopts it, a second refusal cannot
/// replace it, and a refusal reaching a slot whose callback already dropped resolves at once. Pure `Rc`/`RefCell`
/// state with no ring behind it, so this one also genuinely executes under Miri, which is the instrument for the
/// aliasing on the waker and `RefCell` paths here.
#[test]
fn a_parked_refusal_is_settled_only_by_the_callback_route() {
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);

    // A real answer supersedes the parked reason.
    let s: Rc<Slot<u32>> = Slot::new();
    s.fill_refused(7);
    assert!(matches!(s.poll_take(&mut cx), Poll::Pending));
    Fire(Some(Rc::clone(&s))).fire(42);
    assert!(matches!(s.poll_take(&mut cx), Poll::Ready(Took::Value(42))));

    // The callback dropping unfired adopts it.
    let s: Rc<Slot<u32>> = Slot::new();
    s.fill_refused(7);
    drop(Fire(Some(Rc::clone(&s))));
    assert!(matches!(s.poll_take(&mut cx), Poll::Ready(Took::Value(7))));

    // The first refusal wins over a later one.
    let s: Rc<Slot<u32>> = Slot::new();
    s.fill_refused(7);
    s.fill_refused(9);
    drop(Fire(Some(Rc::clone(&s))));
    assert!(matches!(s.poll_take(&mut cx), Poll::Ready(Took::Value(7))));

    // A refusal after the callback route already ended resolves at once - there is nothing left to wait for.
    let s: Rc<Slot<u32>> = Slot::new();
    drop(Fire(Some(Rc::clone(&s))));
    s.fill_refused(7);
    assert!(matches!(s.poll_take(&mut cx), Poll::Ready(Took::Value(7))));

    // And a settled slot is final: a refusal cannot rewrite it.
    let s: Rc<Slot<u32>> = Slot::new();
    Fire(Some(Rc::clone(&s))).fire(42);
    s.fill_refused(7);
    assert!(matches!(s.poll_take(&mut cx), Poll::Ready(Took::Value(42))));
}

/// Retraction is idempotent in the headroom too: a `Timer` is `Copy`, so a caller can retract one arm twice, and
/// the second pass must return nothing - a double return would spend another live timer's count.
#[test]
fn a_double_retraction_returns_the_headroom_once() {
    let Some((mut eng, mut fs, _who)) = rig() else {
        return;
    };
    fs.set_timer_cap(2);
    let hour = Duration::from_secs(3600);
    let (t1, t2) = {
        let mut conn = FsConn::new(&mut fs, &mut eng, Some((1, 1)));
        let t1 = conn.timeout(hour, |_d, _c| {}).expect("first arm");
        let t2 = conn.timeout(hour, |_d, _c| {}).expect("second arm");
        (t1, t2)
    };
    {
        let mut conn = FsConn::new(&mut fs, &mut eng, None);
        conn.cancel_timeout(t1);
        conn.cancel_timeout(t1);
    }
    assert_eq!(
        fs.armed_timers_for_test(&(1, 1)),
        1,
        "one retraction, one return - t2's count must survive"
    );
    let mut conn = FsConn::new(&mut fs, &mut eng, None);
    conn.cancel_timeout(t2);
}

/// A connection the sweep has passed may not park time on the table. Its I/O is still welcome - finishing accepted
/// work is the sweep's own contract - but a timer holds a slot for wall-clock duration, and a re-arming tick for a
/// dead owner strands one per arm with the only `Timer` holder the dead handler itself. The answer is the sweep's
/// own verdict, so the continuation winds down the same way in either ordering.
#[test]
fn a_swept_owner_cannot_arm_a_timer() {
    let Some((mut eng, mut fs, _who)) = rig() else {
        return;
    };
    let owner = Some((6u32, 1u64));
    let seen: Rc<StdCell<Option<(bool, bool)>>> = Rc::new(StdCell::new(None));

    fs.cancel_owned_by(&mut eng, vec![(6, 1)]);
    {
        let out = Rc::clone(&seen);
        let mut conn = FsConn::new(&mut fs, &mut eng, owner);
        drop(conn.spawn(move |t| async move {
            let d = t
                .fut(|c, cb| {
                    // The frame's sink carries any refusal.
                    let _ = c.timeout(Duration::from_secs(3600), cb);
                })
                .await;
            out.set(Some((
                matches!(d.result(), Err(crate::Error::Errno(Errno::ECANCELED))),
                d.was_refused(),
            )));
        }));
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    while seen.get().is_none() {
        assert!(Instant::now() < deadline, "the verdict never delivered");
        if turn(&mut fs, &mut eng) == 0 {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    let (ecanceled, refused) = seen.get().expect("driven to delivery");
    assert!(ecanceled, "the sweep's verdict, not a strand");
    assert!(!refused, "unmarked, exactly as an in-flight timer the sweep reached");
    assert!(fs.has_free_op(), "no slot may be held for a dead connection's hour");
}
