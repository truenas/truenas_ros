use super::*;

/// The kernel-internal restart codes decode as `EINTR`, the way io_uring's own rw path folds them
/// (`io_fixup_restart_res`, `io_uring/rw.c`), and the codes between and around them stay themselves.
#[test]
fn restart_codes_fold_to_eintr_like_the_kernels_rw_path() {
    for res in [-512, -513, -514, -516] {
        assert_eq!(map_res(res), Err(Errno::EINTR), "res {res}");
    }
    // 515 is ENOIOCTLCMD, not a restart code; a range would eat it.
    assert_eq!(map_res(-515), Err(Errno::from_raw(515)));
    assert_eq!(map_res(-libc::ECANCELED), Err(Errno::ECANCELED));
    assert_eq!(map_res(7), Ok(7));
}

/// The sweep leaves a signal behind, because it cannot leave a gate behind. A task whose awaits cannot fail (an
/// offload, a timer armed after the sweep) asks `owner_is_gone`, which must answer for the swept tenant of a slot
/// without answering for the next one to take it.
#[test]
fn a_swept_owner_is_visible_to_what_runs_after_the_sweep() {
    let Some(mut eng) = engine_or_skip() else {
        return;
    };
    let mut core = FsCore::new(4, OffloadBounds::default());
    let gone = (7u32, 3u64);

    assert!(!core.owner_is_gone(Some(gone)), "nothing swept yet");
    core.cancel_owned_by(&mut eng, vec![gone]);
    assert!(core.owner_is_gone(Some(gone)), "the swept owner is gone");

    // A slot is reused, and its next tenant is not the one swept.
    assert!(
        !core.owner_is_gone(Some((gone.0, gone.1 + 1))),
        "a later tenant of the same slot is live"
    );
    // Every earlier tenant closed before this one did.
    assert!(
        core.owner_is_gone(Some((gone.0, gone.1 - 1))),
        "a tenant before the swept one is gone too"
    );
    assert!(!core.owner_is_gone(Some((8, 3))), "another slot is its own");
    assert!(
        !core.owner_is_gone(None),
        "a reactor with no owners has no connection to lose"
    );

    // And the facade a continuation is handed reads it.
    let conn = FsConn::new(&mut core, &mut eng, Some(gone));
    assert!(conn.owner_is_gone(), "the continuation facade answers");
}

/// One sweep reaches every closed owner's ops, and an idle table costs nothing to sweep.
#[test]
fn one_sweep_covers_the_batch_and_an_idle_table_is_free() {
    let Some(mut eng) = engine_or_skip() else {
        return;
    };
    let mut core = FsCore::new(8, OffloadBounds::default());
    let all_free = core.op_free_len_for_test();

    // Nothing in flight: the sweep records and returns.
    core.cancel_owned_by(&mut eng, vec![(1, 1), (2, 1), (3, 1)]);
    assert!(core.owner_is_gone(Some((2, 1))), "recorded regardless");
    assert_eq!(core.op_free_len_for_test(), all_free, "nothing taken");

    // Four owners with a parked pipe read each: only a cancel can complete one, so what is left in flight names the
    // batch.
    let mut fds = [0i32; 2];
    // SAFETY: `pipe(2)` fills {read, write}.
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe");
    // SAFETY: the fresh read end, owned here; the write end stays open so no read EOFs, and both close with the
    // process.
    let file = File::new(Arc::new(unsafe { crate::fd::owned_from_raw(fds[0]) }));
    let owners = [(10u32, 1u64), (11, 1), (12, 1), (13, 1)];
    for o in owners {
        core.submit_pump_read(&mut eng, &file, PumpDest::Owned(Vec::with_capacity(8)), 8, u64::MAX, o)
            .expect("submit");
    }
    assert_eq!(inflight(&core).len(), 4, "four parked reads");

    // One call for three of them, and the fourth is untouched. The batch arrives descending, as production `fs_closed`
    // is in close order, so a sorted batch here would pass with the sort deleted.
    core.cancel_owned_by(&mut eng, vec![(12, 1), (11, 1), (10, 1)]);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let mut reaped = Vec::new();
    while reaped.len() < 3 {
        assert!(
            std::time::Instant::now() < deadline,
            "one sweep did not reach the whole batch: {reaped:?}"
        );
        eng.ring.submit().expect("submit");
        let Some(cqe) = eng.ring.reap() else {
            std::thread::sleep(std::time::Duration::from_millis(1));
            continue;
        };
        let (tag, slot, g) = unpack_raw(cqe.user_data);
        if let ReapedFs::Pump(_, owner) = core.on_cqe(&mut eng, tag, slot, g, cqe.res) {
            reaped.push(owner);
        }
    }
    reaped.sort_unstable();
    assert_eq!(reaped, vec![(10, 1), (11, 1), (12, 1)], "exactly the batch");
    assert_eq!(inflight(&core).len(), 1, "the owner outside it stays");
    assert!(
        core.owner_is_gone(Some((11, 1))) && !core.owner_is_gone(Some((13, 1))),
        "and the record is exactly the batch too"
    );
}

/// The teardown sweep reaching an `Allow` open retracts its guard with it: the open completes through the sweep's
/// cancel, its completion marks and cancels the guard, and both slots return - no hour-long residue for a
/// connection that is gone.
#[test]
fn the_sweep_reaches_an_allow_open_and_its_guard_follows() {
    let Some(mut eng) = engine_or_skip() else {
        return;
    };
    let mut core = FsCore::new(2, OffloadBounds::default());
    let dir = crate::tempdir::tempdir().expect("tempdir");
    let fifo = dir.path().join("pipe");
    let cpath = CString::new(fifo.as_os_str().as_encoded_bytes()).expect("no NUL");
    // SAFETY: a NUL-terminated path this test owns.
    assert_eq!(unsafe { libc::mkfifo(cpath.as_ptr(), 0o600) }, 0, "mkfifo");
    let at = Anchor::open(dir.path()).expect("anchor");
    let me = crate::uring::sys::register_personality(eng.ring.raw_fd()).expect("personality");

    // The forced-async blocking shape, behind an hour's guard.
    let mut raw = OpenHow::new()
        .flags(OFlag::O_WRONLY | OFlag::O_CREAT)
        .mode(crate::sync_fs::Mode::from_bits_truncate(0o600))
        .to_raw();
    crate::uring_fs::confine_resolve(&mut raw.resolve);
    core.submit_open(
        &mut eng,
        me,
        at.clone(),
        b"pipe",
        raw,
        false,
        Some(std::time::Duration::from_secs(3600)),
        FsWaiter::Pump { owner: (5, 9) },
    );
    assert!(!core.has_free_op(), "the open and its guard hold both slots");

    core.cancel_owned_by(&mut eng, vec![(5, 9)]);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let mut open_done = false;
    while !(open_done && core.op_free_len_for_test() == 2) {
        assert!(
            std::time::Instant::now() < deadline,
            "open_done={open_done} free={}: the sweep stranded the \
                 pair for its hour",
            core.op_free_len_for_test()
        );
        eng.ring.submit().expect("submit");
        let Some(cqe) = eng.ring.reap() else {
            std::thread::sleep(std::time::Duration::from_millis(1));
            continue;
        };
        let (tag, slot, g) = unpack_raw(cqe.user_data);
        if let ReapedFs::Pump(done, owner) = core.on_cqe(&mut eng, tag, slot, g, cqe.res) {
            assert_eq!(owner, (5, 9));
            assert!(
                matches!(done.result(), Err(crate::Error::Errno(Errno::ECANCELED | Errno::EINTR))),
                "the sweep's verdict: {:?}",
                done.result()
            );
            open_done = true;
        }
    }
}

/// A deadline-tripped `Allow` open answers in its own vocabulary, never teardown's. The guard's expiry marks the open
/// before staging its cancel, so the `ECANCELED` arrives with `was_refused` true. Driven with synthesized CQEs, since
/// the live trip has two spellings and only this arm's ordering is under test.
#[test]
fn a_tripped_allow_deadline_answers_marked_not_as_teardown() {
    let Some(mut eng) = engine_or_skip() else {
        return;
    };
    let mut core = FsCore::new(2, OffloadBounds::default());
    let dir = crate::tempdir::tempdir().expect("tempdir");
    let at = Anchor::open(dir.path()).expect("anchor");
    let raw = OpenHow::new().flags(OFlag::O_WRONLY).to_raw();
    // A fresh table's LIFO free list hands out slot 0 (the open) then slot 1 (the guard), both at generation 0. The
    // SQEs stage into a ring far larger than two entries and are never submitted; the CQEs below are synthesized.
    core.submit_open(
        &mut eng,
        77,
        at.clone(),
        b"planted",
        raw,
        false,
        Some(std::time::Duration::from_secs(3600)),
        FsWaiter::Pump { owner: (5, 9) },
    );
    assert!(!core.has_free_op(), "the open and its guard hold both slots");

    // The guard fires: its arm must mark the open it cancels.
    let reaped = core.on_cqe(&mut eng, TAG_OPEN_DEADLINE, 1, 0, -libc::ETIME);
    assert!(matches!(reaped, ReapedFs::None), "the guard routes nowhere");
    // The cancel lands: the open completes `ECANCELED`, marked.
    match core.on_cqe(&mut eng, TAG_OPEN, 0, 0, -libc::ECANCELED) {
        ReapedFs::Pump(done, owner) => {
            assert_eq!(owner, (5, 9));
            assert!(
                matches!(done.result(), Err(crate::Error::Errno(Errno::ECANCELED))) && done.was_refused(),
                "a tripped deadline answered teardown's verdict: \
                     {:?} refused={}",
                done.result(),
                done.was_refused()
            );
        }
        _ => panic!("the open's completion was not routed"),
    }
    assert_eq!(core.op_free_len_for_test(), 2, "both slots returned");
}

/// A guard that ends without firing has still stopped bounding its open. The reachable ending is a prep failure, as
/// `__io_timeout_prep` runs inside `io_uring_enter` and can answer `-ENOMEM` (`io_uring/timeout.c:554-556`) with a CQE
/// under the guard's own tag, and the open must still be cancelled.
#[test]
fn a_guard_that_never_armed_still_cancels_its_open() {
    let Some(mut eng) = engine_or_skip() else {
        return;
    };
    let mut core = FsCore::new(2, OffloadBounds::default());
    let dir = crate::tempdir::tempdir().expect("tempdir");
    let at = Anchor::open(dir.path()).expect("anchor");
    let raw = OpenHow::new().flags(OFlag::O_WRONLY).to_raw();
    core.submit_open(
        &mut eng,
        77,
        at.clone(),
        b"planted",
        raw,
        false,
        Some(std::time::Duration::from_secs(3600)),
        FsWaiter::Pump { owner: (5, 9) },
    );
    assert!(!core.has_free_op(), "the open and its guard hold both");

    // The guard's prep failed: it never armed, so nothing else will ever end the open.
    let reaped = core.on_cqe(&mut eng, TAG_OPEN_DEADLINE, 1, 0, -libc::ENOMEM);
    assert!(matches!(reaped, ReapedFs::None), "the guard routes nowhere");
    match core.on_cqe(&mut eng, TAG_OPEN, 0, 0, -libc::ECANCELED) {
        ReapedFs::Pump(done, owner) => {
            assert_eq!(owner, (5, 9));
            assert!(
                done.was_refused(),
                "an open whose bound never armed ran on unmarked: \
                     {:?} refused={}",
                done.result(),
                done.was_refused()
            );
        }
        _ => panic!("the open was never cancelled"),
    }
    assert_eq!(core.op_free_len_for_test(), 2, "both slots returned");
}

/// The other half of the same screen: an *unmarked* `ECANCELED` on the guard is a sweep or teardown, which stages
/// the open's own cancel and needs its `ECANCELED` to stay in teardown's vocabulary. Marking there would tell a
/// task that its connection had one op refused, where what happened is that the connection went away.
#[test]
fn a_swept_guard_leaves_its_open_in_teardown_s_vocabulary() {
    let Some(mut eng) = engine_or_skip() else {
        return;
    };
    let mut core = FsCore::new(2, OffloadBounds::default());
    let dir = crate::tempdir::tempdir().expect("tempdir");
    let at = Anchor::open(dir.path()).expect("anchor");
    let raw = OpenHow::new().flags(OFlag::O_WRONLY).to_raw();
    core.submit_open(
        &mut eng,
        77,
        at.clone(),
        b"planted",
        raw,
        false,
        Some(std::time::Duration::from_secs(3600)),
        FsWaiter::Pump { owner: (5, 9) },
    );
    // The sweep stages a cancel for both, marking neither.
    core.cancel_owned_by(&mut eng, vec![(5, 9)]);
    let reaped = core.on_cqe(&mut eng, TAG_OPEN_DEADLINE, 1, 0, -libc::ECANCELED);
    assert!(matches!(reaped, ReapedFs::None), "the guard routes nowhere");
    match core.on_cqe(&mut eng, TAG_OPEN, 0, 0, -libc::ECANCELED) {
        ReapedFs::Pump(done, owner) => {
            assert_eq!(owner, (5, 9));
            assert!(
                !done.was_refused(),
                "a swept open answered as a refusal: {:?}",
                done.result()
            );
        }
        _ => panic!("the open's completion was not routed"),
    }
    assert_eq!(core.op_free_len_for_test(), 2, "both slots returned");
}

/// The live half of the trip: a planted FIFO with no writer parks the open on an io-wq worker, and the deadline is
/// the only way it ends. Which spelling comes back depends on where the cancel's signal catches the worker -
/// `ECANCELED` marked, or `EINTR` - so what this pins is that both slots recover and that the teardown spelling
/// (`ECANCELED` unmarked) never appears; the deterministic ordering above owns the mark itself.
#[test]
fn a_tripped_allow_deadline_recovers_both_slots() {
    let Some(mut eng) = engine_or_skip() else {
        return;
    };
    let mut core = FsCore::new(2, OffloadBounds::default());
    let dir = crate::tempdir::tempdir().expect("tempdir");
    let fifo = dir.path().join("pipe");
    let cpath = CString::new(fifo.as_os_str().as_encoded_bytes()).expect("no NUL");
    // SAFETY: a NUL-terminated path this test owns.
    assert_eq!(unsafe { libc::mkfifo(cpath.as_ptr(), 0o600) }, 0, "mkfifo");
    let at = Anchor::open(dir.path()).expect("anchor");
    let me = crate::uring::sys::register_personality(eng.ring.raw_fd()).expect("personality");

    let mut raw = OpenHow::new()
        .flags(OFlag::O_WRONLY | OFlag::O_CREAT)
        .mode(crate::sync_fs::Mode::from_bits_truncate(0o600))
        .to_raw();
    crate::uring_fs::confine_resolve(&mut raw.resolve);
    core.submit_open(
        &mut eng,
        me,
        at.clone(),
        b"pipe",
        raw,
        false,
        Some(std::time::Duration::from_millis(50)),
        FsWaiter::Pump { owner: (5, 9) },
    );

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let mut open_done = false;
    while !(open_done && core.op_free_len_for_test() == 2) {
        assert!(
            std::time::Instant::now() < deadline,
            "open_done={open_done} free={}: the deadline never \
                 recovered the pair",
            core.op_free_len_for_test()
        );
        eng.ring.submit().expect("submit");
        let Some(cqe) = eng.ring.reap() else {
            std::thread::sleep(std::time::Duration::from_millis(1));
            continue;
        };
        let (tag, slot, g) = unpack_raw(cqe.user_data);
        if let ReapedFs::Pump(done, owner) = core.on_cqe(&mut eng, tag, slot, g, cqe.res) {
            assert_eq!(owner, (5, 9));
            match done.result() {
                Err(crate::Error::Errno(Errno::ECANCELED)) => {
                    assert!(
                        done.was_refused(),
                        "a tripped deadline answered the unmarked \
                             `ECANCELED` reserved for teardown"
                    );
                }
                Err(crate::Error::Errno(Errno::EINTR)) => {}
                other => panic!("the open ended some other way: {other:?}"),
            }
            open_done = true;
        }
    }
}

#[test]
fn cancel_owned_by_reaches_a_pump_read() {
    // Connection teardown's sweep cancels fs ops by owner; a pump read parked on an empty pipe (never completing on
    // its own) must be reaped by exactly that path, and its parked fd clone released.
    let Some(mut eng) = engine_or_skip() else {
        return;
    };
    let mut core = FsCore::new(4, OffloadBounds::default());
    let mut fds = [0i32; 2];
    // SAFETY: `pipe(2)` fills {read, write}.
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe");
    // SAFETY: fds[0] is the fresh read end, owned here; fds[1] (the write end, kept open so the read never EOFs)
    // closes at the end.
    let file = File::new(Arc::new(unsafe { crate::fd::owned_from_raw(fds[0]) }));

    // `u64::MAX` offset = "the file position": a pipe rejects real offsets with ESPIPE.
    core.submit_pump_read(
        &mut eng,
        &file,
        PumpDest::Owned(Vec::with_capacity(8)),
        8,
        u64::MAX,
        (5, 9),
    )
    .expect("submit");
    assert_eq!(Arc::strong_count(&file.fd), 2, "op parks its clone");
    core.cancel_owned_by(&mut eng, vec![(5, 9)]);

    // Reap until the read's own CQE routes (the cancel's is inert). Bounded by a deadline rather than
    // `submit_and_wait`, since only `cancel_owned_by`'s `FsWaiter::Pump` arm can complete the read, and a blocking wait
    // would turn its failure into a hang.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let reaped = loop {
        assert!(
            std::time::Instant::now() < deadline,
            "the parked read was never reaped: `cancel_owned_by` no \
                 longer reaches a `FsWaiter::Pump` op, so a closed \
                 connection's body read stays in flight with its fd parked"
        );
        eng.ring.submit().expect("submit");
        let Some(cqe) = eng.ring.reap() else {
            std::thread::sleep(std::time::Duration::from_millis(1));
            continue;
        };
        let (tag, slot, g) = unpack_raw(cqe.user_data);
        match core.on_cqe(&mut eng, tag, slot, g, cqe.res) {
            ReapedFs::None => continue,
            other => break other,
        }
    };
    let ReapedFs::Pump(done, owner) = reaped else {
        panic!("the cancelled read must still route as Pump");
    };
    assert_eq!(owner, (5, 9));
    assert!(
        matches!(done.result(), Err(crate::Error::Errno(Errno::ECANCELED))),
        "an owner cancel reaps the parked read: {:?}",
        done.result()
    );
    assert_eq!(Arc::strong_count(&file.fd), 1, "clone released");
    // SAFETY: closing the test-owned write end.
    unsafe { libc::close(fds[1]) };
}
