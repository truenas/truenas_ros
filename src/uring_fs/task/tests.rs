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

/// An `Allow` open is a wall-clock hold like a timer - two slots parked until its deadline or its answer - so it
/// spends the same per-owner budget: at the cap it is refused with the marked `EBUSY` a timer arm gets, and the
/// tenant beside it still opens.
#[test]
fn an_allow_open_spends_the_owners_timer_budget() {
    let Some((mut eng, mut fs, who)) = rig() else {
        return;
    };
    fs.set_timer_cap(1);
    let dir = crate::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("plain"), b"x").expect("write");
    let at = Anchor::open(dir.path()).expect("anchor");
    let hour = Duration::from_secs(3600);

    // The owner's one hold: an hour timer.
    {
        let mut conn = FsConn::new(&mut fs, &mut eng, Some((1, 1)));
        assert!(conn.timeout(hour, |_d, _c| {}).is_some(), "first arm");
    }
    // Its `Allow` open is refused before either slot is popped, with the errno and the mark an over-cap timer arm
    // carries.
    let seen: Rc<StdCell<Option<(bool, bool)>>> = Rc::new(StdCell::new(None));
    let free_before = fs.op_free_len_for_test();
    {
        let out = Rc::clone(&seen);
        let at = at.clone();
        let mut conn = FsConn::new(&mut fs, &mut eng, Some((1, 1)));
        drop(conn.spawn(move |t| async move {
            let d = t
                .fut(|c, cb| {
                    c.open(
                        who,
                        &at,
                        c"plain",
                        crate::uring_fs::FsOpenHow::from(OpenHow::new().flags(OFlag::O_RDONLY))
                            .allow_blocking_special_files(hour),
                        cb,
                    );
                })
                .await;
            out.set(Some((
                matches!(d.result(), Err(crate::Error::Errno(Errno::EBUSY))),
                d.was_refused(),
            )));
        }));
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    while seen.get().is_none() {
        assert!(Instant::now() < deadline, "the refusal never delivered");
        if turn(&mut fs, &mut eng) == 0 {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    assert_eq!(
        seen.get(),
        Some((true, true)),
        "refused as this crate's own EBUSY, not silently"
    );
    assert_eq!(fs.op_free_len_for_test(), free_before, "a refused pair holds nothing");

    // The neighbour's budget is its own.
    let ok = Rc::new(StdCell::new(false));
    {
        let out = Rc::clone(&ok);
        let at = at.clone();
        let mut conn = FsConn::new(&mut fs, &mut eng, Some((2, 1)));
        drop(conn.spawn(move |t| async move {
            let d = t
                .fut(|c, cb| {
                    c.open(
                        who,
                        &at,
                        c"plain",
                        crate::uring_fs::FsOpenHow::from(OpenHow::new().flags(OFlag::O_RDONLY))
                            .allow_blocking_special_files(hour),
                        cb,
                    );
                })
                .await;
            out.set(d.result().is_ok());
        }));
    }
    drive(&mut fs, &mut eng, &ok, "the neighbour's Allow open");
}

/// The pair's charge is taken when the guard stages and returned when the open answers, so an in-flight `Allow`
/// open blocks the owner's next arm and its completion frees it - the same lifecycle a timer's count follows.
#[test]
fn an_allow_opens_charge_returns_when_it_answers() {
    let Some((mut eng, mut fs, who)) = rig() else {
        return;
    };
    fs.set_timer_cap(1);
    let dir = crate::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("plain"), b"x").expect("write");
    let at = Anchor::open(dir.path()).expect("anchor");

    let done = Rc::new(StdCell::new(false));
    {
        let out = Rc::clone(&done);
        let at = at.clone();
        let mut conn = FsConn::new(&mut fs, &mut eng, Some((1, 1)));
        drop(conn.spawn(move |t| async move {
            let d = t
                .fut(|c, cb| {
                    c.open(
                        who,
                        &at,
                        c"plain",
                        crate::uring_fs::FsOpenHow::from(OpenHow::new().flags(OFlag::O_RDONLY))
                            .allow_blocking_special_files(Duration::from_secs(3600)),
                        cb,
                    );
                })
                .await;
            assert!(d.result().is_ok(), "{:?}", d.result());
            out.set(true);
        }));
    }
    // Charged while in flight: the owner's next arm is refused.
    assert_eq!(fs.armed_timers_for_test(&(1, 1)), 1, "the pair charged");
    {
        let mut conn = FsConn::new(&mut fs, &mut eng, Some((1, 1)));
        assert!(
            conn.timeout(Duration::from_secs(3600), |_d, _c| {}).is_none(),
            "the hold spends the same budget a timer would"
        );
    }
    drive(&mut fs, &mut eng, &done, "allow open");
    assert_eq!(fs.armed_timers_for_test(&(1, 1)), 0, "the answer returned the charge");
}

/// The pair charges one count for two slots, so the open's CQE cannot return the whole charge: its guard is
/// retracted there and frees at its own later CQE, so a charge returned in full leaves that slot metered by neither
/// bucket and the arm screen waves a fresh pair through per unreaped guard. It parks on `retiring` instead - the
/// bucket a retracted timer uses for the same window - and the mid-swap ceiling then bounds the two classes
/// together, which is what `a_mid_swap_owner_is_bounded_at_twice_its_cap_in_slots` pins for timers alone.
#[test]
fn an_answered_allow_pair_still_meters_its_parked_guard() {
    let Some((mut eng, mut fs, who)) = rig() else {
        return;
    };
    fs.set_timer_cap(1);
    let dir = crate::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("plain"), b"x").expect("write");
    let at = Anchor::open(dir.path()).expect("anchor");
    let hour = Duration::from_secs(3600);
    let owner = (1u32, 1u64);
    let free_at_start = fs.op_free_len_for_test();

    let done = Rc::new(StdCell::new(false));
    {
        let out = Rc::clone(&done);
        let at = at.clone();
        let mut conn = FsConn::new(&mut fs, &mut eng, Some(owner));
        drop(conn.spawn(move |t| async move {
            let d = t
                .fut(|c, cb| {
                    c.open(
                        who,
                        &at,
                        c"plain",
                        crate::uring_fs::FsOpenHow::from(OpenHow::new().flags(OFlag::O_RDONLY))
                            .allow_blocking_special_files(hour),
                        cb,
                    );
                })
                .await;
            assert!(d.result().is_ok(), "{:?}", d.result());
            out.set(true);
        }));
    }
    // `drive` stops at the open's own CQE, and the cancel that retracts the guard is staged from inside that
    // dispatch - so it is not submitted until the next turn and the guard slot is still held here, which is the
    // window under test.
    drive(&mut fs, &mut eng, &done, "allow open");
    assert_eq!(
        free_at_start - fs.op_free_len_for_test(),
        1,
        "the guard slot outlives the open it bounded"
    );
    assert_eq!(
        fs.armed_timers_for_test(&owner),
        0,
        "the open's half of the charge went home"
    );
    assert_eq!(
        fs.retiring_timers_for_test(&owner),
        1,
        "the parked guard slot is metered, not free of the cap"
    );

    // One arm fits under the ceiling beside it; its retraction parks the second slot, and the arm after that is
    // refused.
    let t = {
        let mut conn = FsConn::new(&mut fs, &mut eng, Some(owner));
        conn.timeout(hour, |_d, _c| {})
    };
    let t = t.expect("one arm fits beside a single parked slot");
    {
        let mut conn = FsConn::new(&mut fs, &mut eng, Some(owner));
        conn.cancel_timeout(t);
    }
    assert_eq!(
        free_at_start - fs.op_free_len_for_test(),
        2,
        "two parked slots, which is twice the cap"
    );
    let after = {
        let mut conn = FsConn::new(&mut fs, &mut eng, Some(owner));
        conn.timeout(hour, |_d, _c| {})
    };
    assert!(
        after.is_none(),
        "an owner already holding twice its cap in counts must be \
             refused, whichever class parked them"
    );
    assert_eq!(
        free_at_start - fs.op_free_len_for_test(),
        2,
        "and the refusal pops nothing"
    );

    // And it all comes back. A count parked on `retiring` with no CQE left to return it is the failure this parking
    // introduces, and it looks exactly like a healthy cap until the owner's next arm is refused forever.
    let deadline = Instant::now() + Duration::from_secs(10);
    while fs.op_free_len_for_test() != free_at_start {
        assert!(
            Instant::now() < deadline,
            "the parked slots never came back (free {} of {})",
            fs.op_free_len_for_test(),
            free_at_start
        );
        if turn(&mut fs, &mut eng) == 0 {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    assert_eq!(fs.armed_timers_for_test(&owner), 0);
    assert_eq!(
        fs.retiring_timers_for_test(&owner),
        0,
        "a parked count with no slot left to return it"
    );
    let again = {
        let mut conn = FsConn::new(&mut fs, &mut eng, Some(owner));
        conn.timeout(hour, |_d, _c| {})
    };
    assert!(again.is_some(), "and the owner can arm again");
}

/// The other ordering, which parks nothing and must not: the deadline trips first, so the guard's slot frees while
/// the open still holds its `armed` charge, and there is no second half to meter. Parking one here would leave a
/// count on `retiring` that no CQE returns - the same cap, stuck instead of loose - so the liveness test in
/// `take_op` is what keeps the two orderings apart, and `guard.is_some()` (which stays true through both) cannot
/// make that distinction.
#[test]
fn a_tripped_allow_deadline_leaves_no_count_parked() {
    let Some((mut eng, mut fs, who)) = rig() else {
        return;
    };
    fs.set_timer_cap(1);
    let dir = crate::tempdir().expect("tempdir");
    let fifo = dir.path().join("pipe");
    let cpath = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).expect("no NUL");
    // SAFETY: a NUL-terminated path this test owns.
    assert_eq!(unsafe { libc::mkfifo(cpath.as_ptr(), 0o600) }, 0, "mkfifo");
    let at = Anchor::open(dir.path()).expect("anchor");
    let owner = (3u32, 1u64);
    let free_at_start = fs.op_free_len_for_test();

    // `O_WRONLY` on a FIFO with no reader parks the worker in `fifo_open`'s `wait_for_partner`; the deadline is
    // what ends it, which is the whole reason `Allow` carries one.
    //
    // `O_CREAT` is load-bearing and not incidental. Without a flag in `io_openat_force_async`'s set - `O_TRUNC |
    // O_CREAT | __O_TMPFILE` (`io_uring/openclose.c:42-50`) - the open takes the inline attempt, where `io_openat2`
    // adds `O_NONBLOCK` itself (`:131-135`) and only retries async on `-EAGAIN` (`:155`). A FIFO answers `-ENXIO`
    // to that, not `-EAGAIN`, so the open fails at once and no worker is ever parked: the deadline has nothing to
    // bound and this test measures nothing.
    let seen: Rc<StdCell<Option<bool>>> = Rc::new(StdCell::new(None));
    {
        let out = Rc::clone(&seen);
        let at = at.clone();
        let mut conn = FsConn::new(&mut fs, &mut eng, Some(owner));
        drop(conn.spawn(move |t| async move {
            let d = t
                .fut(|c, cb| {
                    c.open(
                        who,
                        &at,
                        c"pipe",
                        crate::uring_fs::FsOpenHow::from(
                            OpenHow::new()
                                .flags(OFlag::O_WRONLY | OFlag::O_CREAT)
                                .mode(Mode::from_bits_truncate(0o600)),
                        )
                        .allow_blocking_special_files(Duration::from_millis(50)),
                        cb,
                    );
                })
                .await;
            // `ECANCELED` marked, or `EINTR` where the cancel caught the worker mid-sleep - both are the deadline
            // working.
            out.set(Some(matches!(
                d.result(),
                Err(crate::Error::Errno(Errno::ECANCELED | Errno::EINTR))
            )));
        }));
    }
    assert_eq!(fs.armed_timers_for_test(&owner), 1, "the pair charged");

    let deadline = Instant::now() + Duration::from_secs(10);
    while seen.get().is_none() || fs.op_free_len_for_test() != free_at_start {
        assert!(
            Instant::now() < deadline,
            "the tripped deadline never recovered the pair (free {} of                  {}, answered {:?})",
            fs.op_free_len_for_test(),
            free_at_start,
            seen.get()
        );
        if turn(&mut fs, &mut eng) == 0 {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    assert_eq!(seen.get(), Some(true), "the open ended some other way");
    assert_eq!(fs.armed_timers_for_test(&owner), 0);
    assert_eq!(
        fs.retiring_timers_for_test(&owner),
        0,
        "nothing to park in this ordering, and nothing parked"
    );
    let again = {
        let mut conn = FsConn::new(&mut fs, &mut eng, Some(owner));
        conn.timeout(Duration::from_secs(3600), |_d, _c| {})
    };
    assert!(again.is_some(), "the owner's budget came back whole");
}

/// A retraction's verdict is the caller's ask, not the race. The kernel delists a timeout before posting `-ETIME`
/// (`io_timeout_fn`, `io_uring/timeout.c:254-276`), so a cancel staged after the fire reaches nothing and the
/// expiry stands - and `submit_cancel` is best-effort, so it may never have been staged at all. Reported as `Ok(0)`
/// that reads as "the deadline arrived" and runs the consumer's timeout handler for work it had already finished.
/// Driven with the `-ETIME` CQE demonstrably in hand before the retraction, so the raced ordering is the one under
/// test rather than one the scheduler might supply.
#[test]
fn a_retracted_timer_that_already_expired_is_not_an_expiry() {
    let Some((mut eng, mut fs, _who)) = rig() else {
        return;
    };
    let seen: Rc<StdCell<Option<(bool, bool)>>> = Rc::new(StdCell::new(None));
    let out = Rc::clone(&seen);
    let t = {
        let mut conn = FsConn::new(&mut fs, &mut eng, Some((1, 1)));
        conn.timeout(Duration::from_millis(1), move |d, _c| {
            out.set(Some((
                matches!(d.result(), Err(crate::Error::Errno(Errno::ECANCELED))),
                d.was_refused(),
            )));
        })
    }
    .expect("armed");
    eng.ring.submit().expect("submit");

    // Reap the expiry without routing it: the entry stays in flight, so the retraction below is the ordinary one a
    // caller makes - and the answer it will be given is already posted.
    let deadline = Instant::now() + Duration::from_secs(10);
    let expiry = loop {
        assert!(Instant::now() < deadline, "the timer never expired");
        if let Some(cqe) = eng.ring.reap() {
            break cqe;
        }
        std::thread::sleep(Duration::from_millis(1));
    };
    eng.inflight = eng.inflight.saturating_sub(1);
    assert_eq!(expiry.res, -libc::ETIME, "expected the expiry");

    {
        let mut conn = FsConn::new(&mut fs, &mut eng, Some((1, 1)));
        conn.cancel_timeout(t);
    }
    let (tag, slot, gen32) = unpack_raw(expiry.user_data);
    let reaped = fs.on_cqe(&mut eng, tag, slot, gen32, expiry.res);
    deliver_embedded(&mut fs, &mut eng, reaped);

    assert_eq!(
        seen.get(),
        Some((true, true)),
        "a retracted timer answers as the cancellation it asked \
             for, never as an expiry"
    );
    assert_eq!(
        fs.armed_timers_for_test(&(1, 1)),
        0,
        "and the cap accounting still balances"
    );
    assert_eq!(fs.retiring_timers_for_test(&(1, 1)), 0);
}

/// A connection the sweep has passed may not park an `Allow` pair on the table, for the reason its timers are
/// refused: two slots held for wall-clock time, with nothing left to retract them. Same verdict, same delivery.
#[test]
fn a_swept_owner_cannot_park_an_allow_open() {
    let Some((mut eng, mut fs, who)) = rig() else {
        return;
    };
    let dir = crate::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("plain"), b"x").expect("write");
    let at = Anchor::open(dir.path()).expect("anchor");
    let seen: Rc<StdCell<Option<(bool, bool)>>> = Rc::new(StdCell::new(None));

    fs.cancel_owned_by(&mut eng, vec![(6, 1)]);
    {
        let out = Rc::clone(&seen);
        let mut conn = FsConn::new(&mut fs, &mut eng, Some((6, 1)));
        drop(conn.spawn(move |t| async move {
            let d = t
                .fut(|c, cb| {
                    c.open(
                        who,
                        &at,
                        c"plain",
                        crate::uring_fs::FsOpenHow::from(OpenHow::new().flags(OFlag::O_RDONLY))
                            .allow_blocking_special_files(Duration::from_secs(3600)),
                        cb,
                    );
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
    assert!(fs.has_free_op(), "no slot pair may be held for a dead connection");
}

/// The timer composes with the future layer like any submission: a task awaits its tick and resumes on the loop
/// that armed it.
#[test]
fn a_task_awaits_a_timer() {
    let Some((mut eng, mut fs, _who)) = rig() else {
        return;
    };
    let done = Rc::new(StdCell::new(false));
    let started = Instant::now();
    {
        let done = Rc::clone(&done);
        let mut conn = FsConn::new(&mut fs, &mut eng, None);
        conn.spawn(move |t| async move {
            let fired = t
                .fut(|c, cb| {
                    // The frame's sink carries any refusal.
                    let _ = c.timeout(Duration::from_millis(30), cb);
                })
                .await;
            assert!(fired.result().is_ok(), "{:?}", fired.result().err());
            done.set(true);
        });
    }
    drive(&mut fs, &mut eng, &done, "task timer");
    assert!(
        started.elapsed() >= Duration::from_millis(25),
        "fired early: {:?}",
        started.elapsed()
    );
}

/// The core claim: a whole write chain - open, write, fsync, stat, read back - as one straight-line task, every hop
/// on the ring.
#[test]
fn a_task_awaits_a_whole_chain_on_the_ring() {
    let Some((mut eng, mut fs, who)) = rig() else {
        return;
    };
    let dir = crate::tempdir::tempdir().expect("tempdir");
    let anchor = Anchor::open(dir.path()).expect("anchor");
    let payload: Vec<u8> = (0..4096u32).map(|i| i as u8).collect();
    let done = Rc::new(StdCell::new(false));

    {
        let (done, payload) = (Rc::clone(&done), payload.clone());
        let mut conn = FsConn::new(&mut fs, &mut eng, None);
        conn.spawn(move |t| async move {
            let opened = t.fut(|c, cb| c.open(who, &anchor, c"demo.bin", creating(), cb)).await;
            let file = opened.file().expect("open");

            let wrote = t
                .fut(|c, cb| c.pwritev2(who, file.clone(), vec![payload.clone()], 0, RwFlags::empty(), cb))
                .await;
            assert_eq!(wrote.result().expect("write") as usize, payload.len());

            t.fut(|c, cb| c.fsync(who, file.clone(), cb))
                .await
                .result()
                .expect("fsync");

            let stat = t
                .fut(|c, cb| c.fstatx(who, &file, AtFlags::empty(), StatxMask::BASIC_STATS, cb))
                .await;
            assert_eq!(stat.stat().expect("statx").size(), payload.len() as u64);

            let read = t
                .fut(|c, cb| {
                    c.preadv2(
                        who,
                        file.clone(),
                        vec![vec![0u8; payload.len()]],
                        0,
                        RwFlags::empty(),
                        cb,
                    )
                })
                .await;
            assert_eq!(read.result().expect("read") as usize, payload.len());
            assert_eq!(read.into_bufs()[0], payload);
            done.set(true);
        });
    }
    drive(&mut fs, &mut eng, &done, "write chain");
}

/// Two futures made back to back are both in flight before either is awaited - eager submission is what overlaps
/// them.
#[test]
fn futures_submit_eagerly_and_overlap() {
    let Some((mut eng, mut fs, who)) = rig() else {
        return;
    };
    let dir = crate::tempdir::tempdir().expect("tempdir");
    let anchor = Anchor::open(dir.path()).expect("anchor");
    std::fs::write(dir.path().join("a"), b"a").expect("seed a");
    std::fs::write(dir.path().join("b"), b"bb").expect("seed b");
    let done = Rc::new(StdCell::new(false));

    {
        let done = Rc::clone(&done);
        let mut conn = FsConn::new(&mut fs, &mut eng, None);
        conn.spawn(move |t| async move {
            let ro = || OpenHow::new().flags(OFlag::O_RDONLY);
            let a = t.fut(|c, cb| c.open(who, &anchor, c"a", ro(), cb));
            let b = t.fut(|c, cb| c.open(who, &anchor, c"b", ro(), cb));
            // Both submitted above; awaiting in either order works.
            let (a, b) = (a.await, b.await);
            assert!(a.file().is_some(), "a: {:?}", a.result());
            assert!(b.file().is_some(), "b: {:?}", b.result());
            done.set(true);
        });
    }
    drive(&mut fs, &mut eng, &done, "overlapping opens");
}

/// A refused submission resolves with the reason, not a blanket `ECANCELED`: an argument the facade will never
/// accept answers `EINVAL`, and a full op table answers `EBUSY` - which a task can retry. Both arrive with no CQE
/// ever produced.
#[test]
fn a_refusal_resolves_with_the_errno_it_was_refused_for() {
    let Some((mut eng, mut fs, who)) = rig() else {
        return;
    };
    let dir = crate::tempdir::tempdir().expect("tempdir");
    let anchor = Anchor::open(dir.path()).expect("anchor");

    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);

    // An absolute path: refused by the facade, never submitted.
    let mut conn = FsConn::new(&mut fs, &mut eng, None);
    let bad = conn.fut(|c, cb| c.open(who, &anchor, c"/etc/hostname", creating(), cb));
    let mut bad = std::pin::pin!(bad);
    let Poll::Ready(done) = bad.as_mut().poll(&mut cx) else {
        panic!("a refused submission left its future pending");
    };
    assert!(
        matches!(done.result(), Err(crate::Error::Errno(Errno::EINVAL))),
        "want EINVAL, got {:?}",
        done.result()
    );

    // Fill the op table (8 slots), then more: each surplus is EBUSY, delivered at the wake drain its queued
    // callback rides.
    let mut held = Vec::new();
    for _ in 0..16 {
        held.push(conn.fut(|c, cb| c.open(who, &anchor, c".", spec_dir(), cb)));
    }
    let mut busy = false;
    let deadline = Instant::now() + Duration::from_secs(10);
    while !busy {
        assert!(
            Instant::now() < deadline,
            "a full op table must answer EBUSY, not ECANCELED"
        );
        held.retain_mut(|f| match Pin::new(&mut *f).poll(&mut cx) {
            Poll::Ready(d) => {
                if matches!(d.result(), Err(crate::Error::Errno(Errno::EBUSY))) {
                    busy = true;
                }
                false
            }
            Poll::Pending => true,
        });
        if !busy && turn(&mut fs, &mut eng) == 0 {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}

/// ZFS's `f_type` magic - `statfs(2)`, and `Statfs::fs_type`'s own doc.
const ZFS_SUPER_MAGIC: i64 = 0x2fc1_2fc1;

/// The offload-shaped half of the facade, awaited from one task: the capacity tail, the xattr list, the ZFS
/// attribute ioctl, server-side copy, and the `open_dir`/`next_batch` walk whose first step is itself a ring op.
///
/// This is also the module's only test whose result depends on which filesystem it runs on, and it needs no fixture
/// to be: it reads `f_type` through the same `fstatfs` it is exercising, then requires the attribute ioctl to
/// answer `Ok` on ZFS and `ENOTTY` anywhere else. Point `TMPDIR` at a dataset and it takes the ZFS arm; leave it on
/// tmpfs and it takes the other. Both arms are assertions, so neither silently degrades into a skip.
///
/// Outcomes are collected and asserted after the drive rather than inside the body: an `assert!` in a task body is
/// contained into its `JoinHandle`, so it would surface as this test's deadline expiring with the message lost.
#[test]
fn a_task_awaits_the_offload_shaped_ops_and_sees_the_filesystem() {
    let Some((mut eng, mut fs, who)) = rig() else {
        return;
    };
    eng.arm_wake(pack_raw(TAG_WAKE, 0, 0)).expect("arm wake");
    let dir = crate::tempdir::tempdir().expect("tempdir");
    let anchor = Anchor::open(dir.path()).expect("anchor");
    let done = Rc::new(StdCell::new(false));

    type Seen = (
        Option<i64>,                    // fstatfs f_type
        Option<usize>,                  // flistxattr count
        Option<crate::Result<ZfsAttr>>, // the ioctl, either way
        Option<crate::Result<u64>>,     // copy_file_range
        Option<usize>,                  // next_batch names
    );
    let seen: Rc<StdRefCell<Seen>> = Rc::new(StdRefCell::new(Default::default()));

    {
        let (done, seen) = (Rc::clone(&done), Rc::clone(&seen));
        let anchor2 = anchor.clone();
        let mut conn = FsConn::new(&mut fs, &mut eng, None);
        conn.spawn(move |t| async move {
            let src = t
                .fut(|c, cb| c.open(who, &anchor2, c"src.bin", creating(), cb))
                .await
                .file()
                .expect("open src");
            let wrote = t
                .fut(|c, cb| c.pwritev2(who, src.clone(), vec![b"payload".to_vec()], 0, RwFlags::empty(), cb))
                .await;
            assert_eq!(wrote.result().expect("write"), 7);

            let st = t.result_fut(|c, cb| c.fstatfs(src.clone(), cb)).await.expect("fstatfs");
            seen.borrow_mut().0 = Some(st.fs_type());

            let names = t
                .result_fut(|c, cb| c.flistxattr(src.clone(), cb))
                .await
                .expect("flistxattr");
            seen.borrow_mut().1 = Some(names.len());

            seen.borrow_mut().2 = Some(t.result_fut(|c, cb| c.fget_zfs_attrs(src.clone(), cb)).await);

            let dst = t
                .fut(|c, cb| c.open(who, &anchor2, c"dst.bin", creating(), cb))
                .await
                .file()
                .expect("open dst");
            seen.borrow_mut().3 = Some(
                t.result_fut(|c, cb| c.copy_file_range(src.clone(), dst, 0, 0, 7, cb))
                    .await,
            );

            let walk = t
                .result_fut(|c, cb| c.open_dir(who, &anchor2, cb))
                .await
                .expect("open_dir");
            let batch = t.result_fut(|c, cb| c.next_batch(&walk, cb)).await.expect("next_batch");
            seen.borrow_mut().4 = Some(batch.names.len());

            done.set(true);
        });
    }
    drive(&mut fs, &mut eng, &done, "offload-shaped ops");

    let (f_type, xattrs, zfs, copied, entries) = std::mem::take(&mut *seen.borrow_mut());
    let f_type = f_type.expect("fstatfs answered");
    assert_eq!(xattrs, Some(0), "a fresh file carries no xattrs");
    assert_eq!(copied.expect("copy answered").expect("copy"), 7);
    assert_eq!(entries, Some(2), "src.bin and dst.bin");

    let zfs = zfs.expect("the ioctl answered");
    if f_type == ZFS_SUPER_MAGIC {
        zfs.expect("a ZFS dataset must answer the attribute ioctl");
    } else {
        match zfs {
            Err(crate::Error::Errno(Errno::ENOTTY)) => {}
            other => panic!(
                "f_type {f_type:#x} is not ZFS, so the attribute ioctl \
                     must answer ENOTTY, not {other:?}"
            ),
        }
    }
}

/// A refusal hands the payload back, because the retry it advises is impossible without it: the buffers a write was
/// given are dropped on the way out of `deliver`, and nothing tells a caller to keep a second copy.
#[test]
fn a_refusal_hands_back_the_payload_it_advises_retrying() {
    let Some((mut eng, mut fs, who)) = rig() else {
        return;
    };
    let dir = crate::tempdir::tempdir().expect("tempdir");
    let anchor = Anchor::open(dir.path()).expect("anchor");
    let done = Rc::new(StdCell::new(false));
    /// Whether the refusal was marked as this crate's, and the payload it handed back.
    type Refused = Option<(bool, Vec<Vec<u8>>)>;
    let seen: Rc<StdRefCell<Refused>> = Rc::new(StdRefCell::new(None));

    {
        let (done, seen) = (Rc::clone(&done), Rc::clone(&seen));
        let anchor2 = anchor.clone();
        let mut conn = FsConn::new(&mut fs, &mut eng, None);
        conn.spawn(move |t| async move {
            let file = t
                .fut(|c, cb| c.open(who, &anchor2, c"payload.bin", creating(), cb))
                .await
                .file()
                .expect("open");
            // Fill the op table, then write through it.
            let mut held = Vec::new();
            for _ in 0..POOL {
                held.push(t.fut(|c, cb| c.open(who, &anchor2, c".", spec_dir(), cb)));
            }
            let refused = t
                .fut(|c, cb| {
                    c.pwritev2(
                        who,
                        file,
                        vec![b"the body a retry needs".to_vec()],
                        0,
                        RwFlags::empty(),
                        cb,
                    )
                })
                .await;
            assert!(
                matches!(refused.result(), Err(crate::Error::Errno(Errno::EBUSY))),
                "a full op table must answer EBUSY"
            );
            *seen.borrow_mut() = Some((refused.was_refused(), refused.into_bufs()));
            drop(held);
            done.set(true);
        });
    }
    drive(&mut fs, &mut eng, &done, "refused payload");

    let (refused, bufs) = std::mem::take(&mut *seen.borrow_mut()).expect("the write answered");
    assert!(refused, "a full op table is this crate's refusal");
    assert_eq!(
        bufs,
        vec![b"the body a retry needs".to_vec()],
        "a refusal that keeps the payload cannot be retried"
    );
}

/// The errno alone cannot say who answered. `EBUSY` from a full op table is worth retrying; `EBUSY` from the
/// kernel - a directory that is a mountpoint, which every nested dataset is - is permanent, so a task that cannot
/// tell them apart spins forever.
#[test]
fn a_refused_errno_is_marked_as_this_crates_own() {
    let Some((mut eng, mut fs, who)) = rig() else {
        return;
    };
    let dir = crate::tempdir::tempdir().expect("tempdir");
    let anchor = Anchor::open(dir.path()).expect("anchor");
    let done = Rc::new(StdCell::new(false));
    let seen: Rc<StdRefCell<Vec<(Errno, bool)>>> = Rc::new(StdRefCell::new(Vec::new()));

    {
        let (done, seen) = (Rc::clone(&done), Rc::clone(&seen));
        let anchor2 = anchor.clone();
        let mut conn = FsConn::new(&mut fs, &mut eng, None);
        conn.spawn(move |t| async move {
            // The kernel's: nothing of that name.
            let miss = t
                .fut(|c, cb| {
                    c.statx(
                        who,
                        &anchor2,
                        Leaf::new(b"absent").expect("leaf"),
                        AtFlags::empty(),
                        StatxMask::INO,
                        cb,
                    )
                })
                .await;
            let Err(crate::Error::Errno(e)) = miss.result() else {
                panic!("a missing name must fail");
            };
            seen.borrow_mut().push((e, miss.was_refused()));

            // This crate's: an absolute path the facade will not take.
            let bad = t
                .fut(|c, cb| c.open(who, &anchor2, c"/etc/hostname", creating(), cb))
                .await;
            let Err(crate::Error::Errno(e)) = bad.result() else {
                panic!("an absolute path must be refused");
            };
            seen.borrow_mut().push((e, bad.was_refused()));
            done.set(true);
        });
    }
    drive(&mut fs, &mut eng, &done, "refusal provenance");

    let seen = std::mem::take(&mut *seen.borrow_mut());
    assert_eq!(
        seen,
        vec![(Errno::ENOENT, false), (Errno::EINVAL, true)],
        "the kernel's errno must not read as a refusal, nor the reverse"
    );
}

/// A chain submits every step after the first from the fresh facade its predecessor's completion was handed. A sink
/// that one submission consumed would leave every later step reporting teardown for a refusal the caller is told to
/// retry.
#[test]
fn a_chain_step_past_the_first_still_names_its_refusal() {
    let Some((mut eng, mut fs, who)) = rig() else {
        return;
    };
    let dir = crate::tempdir::tempdir().expect("tempdir");
    std::fs::create_dir(dir.path().join("sub")).expect("mkdir sub");
    std::fs::write(dir.path().join("sub/leaf"), b"x").expect("leaf");
    let anchor = Anchor::open(dir.path()).expect("anchor");
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);

    let chained = {
        let mut conn = FsConn::new(&mut fs, &mut eng, None);
        conn.fut(|c, cb| {
            c.open_chain(
                &anchor,
                vec![
                    OpenStep {
                        path: StepPath::Fixed(c"sub".to_owned()),
                        who,
                        how: spec_dir(),
                    },
                    OpenStep {
                        path: StepPath::Fixed(c"leaf".to_owned()),
                        who,
                        how: OpenHow::new().flags(OFlag::O_RDONLY),
                    },
                ],
                cb,
            )
        })
    };
    let mut chained = std::pin::pin!(chained);

    // Take every free slot in the window `on_cqe` opens and `deliver_embedded` closes - which is exactly where the
    // net server's `redrive_parked_tail` takes one - so step two meets a full table.
    let mut stolen = false;
    let deadline = Instant::now() + Duration::from_secs(10);
    let done = loop {
        assert!(Instant::now() < deadline, "the chain never answered");
        if let Poll::Ready(d) = chained.as_mut().poll(&mut cx) {
            break d;
        }
        eng.ring.submit().expect("submit");
        let Some(cqe) = eng.ring.reap() else {
            std::thread::sleep(Duration::from_millis(1));
            continue;
        };
        if cqe.flags & IORING_CQE_F_MORE == 0 {
            eng.inflight = eng.inflight.saturating_sub(1);
        }
        let (tag, slot, gen32) = unpack_raw(cqe.user_data);
        if tag & TAG_FS_DOMAIN == 0 || tag == TAG_CANCEL {
            continue;
        }
        if tag == TAG_WAKE {
            // Step two's refusal rides the wake drain now.
            eng.arm_wake(pack_raw(TAG_WAKE, 0, 0)).expect("re-arm");
            deliver_pool_completions(&mut fs, &mut eng);
            continue;
        }
        let reaped = fs.on_cqe(&mut eng, tag, slot, gen32, cqe.res);
        if !stolen {
            stolen = true;
            let mut thief = FsConn::new(&mut fs, &mut eng, None);
            for _ in 0..POOL {
                thief.open(who, &anchor, c".", spec_dir(), |_, _| {});
            }
        }
        deliver_embedded(&mut fs, &mut eng, reaped);
    };

    assert!(
        matches!(done.result(), Err(crate::Error::Errno(Errno::EBUSY))),
        "step two's refusal must keep its errno, got {:?}",
        done.result()
    );
    assert!(done.was_refused(), "and must read as this crate's own");
}

/// A `fut` inside another `fut`'s submit closure stages a sink of its own. Assigning over the outer's would leave
/// the outer op reporting teardown for its own refusal.
#[test]
fn a_nested_fut_does_not_swallow_the_outer_ones_reason() {
    let Some((mut eng, mut fs, who)) = rig() else {
        return;
    };
    let dir = crate::tempdir::tempdir().expect("tempdir");
    let anchor = Anchor::open(dir.path()).expect("anchor");
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    let mut conn = FsConn::new(&mut fs, &mut eng, None);

    // Leave exactly one free slot: the nested `fut` takes it, so the outer's own submission is the one refused.
    let mut held = Vec::new();
    for _ in 0..POOL - 1 {
        held.push(conn.fut(|c, cb| c.open(who, &anchor, c".", spec_dir(), cb)));
    }
    let mut inner = None;
    let outer = conn.fut(|c, cb| {
        inner = Some(c.fut(|c2, cb2| c2.open(who, &anchor, c".", spec_dir(), cb2)));
        c.open(who, &anchor, c".", spec_dir(), cb);
    });
    let mut outer = std::pin::pin!(outer);
    let deadline = Instant::now() + Duration::from_secs(10);
    let done = loop {
        if let Poll::Ready(d) = outer.as_mut().poll(&mut cx) {
            break d;
        }
        assert!(Instant::now() < deadline, "the outer's refusal never delivered");
        if turn(&mut fs, &mut eng) == 0 {
            std::thread::sleep(Duration::from_millis(1));
        }
    };
    assert!(
        matches!(done.result(), Err(crate::Error::Errno(Errno::EBUSY))),
        "want the outer's own EBUSY, got {:?}",
        done.result()
    );
    assert!(done.was_refused());
    drop((inner, held));
}

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
