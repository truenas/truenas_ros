use super::*;

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
