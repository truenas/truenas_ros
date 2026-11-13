use super::*;

#[test]
fn offload_delivers_result_on_loop() {
    let (mut eng, mut fs, _me) = setup();
    let got: Rc<RefCell<Option<u64>>> = Rc::new(RefCell::new(None));
    let g2 = got.clone();
    drive(
        &mut eng,
        &mut fs,
        move |c| {
            c.offload(|| 6u64 * 7, move |r, _c| *g2.borrow_mut() = r.ok());
        },
        || got.borrow().is_some(),
    );
    assert_eq!(*got.borrow(), Some(42));
}

/// Blocking offloads queued in one iteration run side by side, though the loop sleeps right after queueing them:
/// the flush wakes one worker, and the rest get workers when the loop wakes at the returned deadline. The jobs meet
/// at a barrier, so they finish only if all four run at once.
///
/// The floor is parked first: workers still starting would take the jobs whatever the wake rules were.
#[test]
fn a_turns_blocking_offloads_run_side_by_side() {
    const JOBS: usize = 4;
    let (mut eng, mut fs, _me) = setup();
    let floor = OffloadBounds::default().floor;
    assert!(JOBS <= floor, "the fixture must not need growth");
    let pool = fs.pool_handle();
    pool.submit(Box::new(|| {}), &eng.shared.wake);
    let parking = std::time::Instant::now();
    // At least the floor: the warm-up's flush can grow the pool by one.
    while pool.parked().is_none_or(|parked| parked < floor) {
        assert!(
            parking.elapsed() < std::time::Duration::from_secs(5),
            "the pool's floor never parked"
        );
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(JOBS));
    let done = Rc::new(Cell::new(0usize));
    let d2 = done.clone();
    let began = std::time::Instant::now();
    drive(
        &mut eng,
        &mut fs,
        move |c| {
            for _ in 0..JOBS {
                let b = std::sync::Arc::clone(&barrier);
                let d = d2.clone();
                c.offload(
                    move || {
                        b.wait();
                    },
                    move |_r, _c| d.set(d.get() + 1),
                );
            }
        },
        || done.get() == JOBS,
    );
    let took = began.elapsed();
    assert!(
        took < std::time::Duration::from_millis(500),
        "the blocked jobs got their workers only after {took:?}: the \
             loop slept through the pool's deadline"
    );
}

/// A panicking job must still deliver, so the continuation runs and neither its `offload_reg` entry nor anything it
/// releases (a walk's `in_flight`) stays held.
#[test]
fn offload_delivers_even_when_the_job_panics() {
    let (mut eng, mut fs, _me) = setup();
    let got: Rc<RefCell<Option<bool>>> = Rc::new(RefCell::new(None));
    let g2 = got.clone();
    with_silent_panics(|| {
        drive(
            &mut eng,
            &mut fs,
            move |c| {
                c.offload(
                    || -> u64 { panic!("job blew up") },
                    move |r, _c| *g2.borrow_mut() = Some(r.is_err()),
                );
            },
            || got.borrow().is_some(),
        );
    });
    assert_eq!(
        *got.borrow(),
        Some(true),
        "the continuation must run, carrying the panic"
    );
    assert!(
        fs.offload_reg.is_empty(),
        "a panicked job must not strand its registry entry"
    );
}

/// A share dropped off the explicit release paths returns its buffer through the core's queue and pokes the loop;
/// one taken out by `into_bid` - a reaped write's, a taken completion's - does not return it a second time.
#[cfg(feature = "net-server")]
#[test]
fn a_dropped_share_returns_its_buffer_once() {
    let (eng, mut fs, _me) = setup();
    let returns = fs.lease_returns(&eng.shared);
    let dropped = std::sync::Arc::new(LeaseHold::new(3, returns.clone()));
    let taken = std::sync::Arc::new(LeaseHold::new(4, returns));
    let sibling = std::sync::Arc::clone(&dropped);
    drop(dropped);
    assert!(
        fs.take_pool_releases().is_empty(),
        "a share returned while a sibling still held the buffer"
    );
    drop(sibling);
    assert_eq!(fs.take_pool_releases(), [3], "the last share returns");
    assert_eq!(std::sync::Arc::into_inner(taken).map(LeaseHold::into_bid), Some(4));
    assert!(
        fs.take_pool_releases().is_empty(),
        "a share taken out explicitly returned again from its drop"
    );
}

/// Windows one `WRITEV` cannot carry are written from one in-order copy that holds no share.
#[cfg(feature = "net-server")]
#[test]
fn a_gather_past_uio_maxiov_is_written_from_a_copy() {
    let mut eng = Engine::new(256, 128).expect("engine");
    let mut fs = FsCore::new(1, OffloadBounds::default());
    let sink: OwnedFd = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/null")
        .expect("/dev/null")
        .into();
    let file = crate::uring_fs::File { fd: Arc::new(sink) };
    let bytes: Vec<u8> = (0..=UIO_MAXIOV).map(|i| i as u8).collect();
    let hold = std::sync::Arc::new(LeaseHold::detached(3));
    let windows = bytes
        .iter()
        .map(|b| LeasedWindow {
            view: LeasedBytes {
                ptr: std::ptr::from_ref(b),
                len: 1,
            },
            hold: std::sync::Arc::clone(&hold),
        })
        .collect();
    {
        let mut c = FsConn::new(&mut fs, &mut eng, OWNER0);
        c.pwritev2_leased(Personality(0), file.clone(), windows, 0, RwFlags::empty(), |_d, _c| {});
    }
    assert_eq!(std::sync::Arc::strong_count(&hold), 1, "the copy path kept a share");
    let staged: Vec<_> = fs
        .ops
        .iter()
        .filter(|e| matches!(e.state.state, FsOpState::InFlight { .. }))
        .collect();
    let [op] = staged[..] else {
        panic!("{} ops staged, want one write", staged.len());
    };
    assert_eq!(op.state.bufs, vec![bytes], "one copy, in window order");
    assert!(
        op.state.recv_lease.is_none() && op.state.recv_lease_more.is_empty(),
        "no share rides the copy"
    );
}

/// A writable descriptor nothing reads back: the refusal tests stage their writes and synthesize every completion.
#[cfg(feature = "net-server")]
fn dev_null() -> crate::uring_fs::File {
    let sink: OwnedFd = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/null")
        .expect("/dev/null")
        .into();
    crate::uring_fs::File { fd: Arc::new(sink) }
}

/// Every staged op, as `(tag, slot, generation)`.
#[cfg(feature = "net-server")]
fn staged_ops(fs: &FsCore) -> Vec<(u8, u32, u32)> {
    fs.ops
        .iter()
        .enumerate()
        .filter_map(|(i, e)| match e.state.state {
            FsOpState::InFlight { tag } => Some((tag, i as u32, e.generation as u32)),
            _ => None,
        })
        .collect()
}

/// Stage a copied write that fills the table's one slot, then a leased write of `buf` as buffer `bid`; returns
/// whether the leased write took its delivery's claim.
#[cfg(feature = "net-server")]
fn lease_behind(fs: &mut FsCore, eng: &mut Engine, file: &crate::uring_fs::File, buf: &[u8], bid: u16) -> bool {
    let taken = std::cell::Cell::new(false);
    let mut c = FsConn::new(fs, eng, OWNER0).with_recv_lease(Some(RecvWriteLease {
        ptr: buf.as_ptr(),
        cap: buf.len(),
        bid,
        taken: &taken,
    }));
    c.pwritev2(
        Personality(0),
        file.clone(),
        vec![vec![0u8; 16]],
        0,
        RwFlags::empty(),
        |_d, _c| {},
    );
    c.pwritev2_from(Personality(0), file.clone(), buf, 0, RwFlags::empty(), |_d, _c| {});
    taken.get()
}

/// A delivery's first leased write the op table cannot take is refused with a marked `EBUSY` and takes nothing: the
/// connection keeps the claim to release at consume, so the refusal returns no buffer.
#[cfg(feature = "net-server")]
#[test]
fn a_refused_leased_write_leaves_the_claim_with_the_connection() {
    let mut eng = Engine::new(256, 128).expect("engine");
    let mut fs = FsCore::new(1, OffloadBounds::default());
    let file = dev_null();
    let buf = vec![7u8; 1024];
    assert!(
        !lease_behind(&mut fs, &mut eng, &file, &buf, 5),
        "a refused write took the claim"
    );
    let Some((_, _, done)) = fs.take_refusal() else {
        panic!("the refused write is answered");
    };
    assert_eq!(done.raw_result(), Err(Errno::EBUSY));
    assert!(done.was_refused(), "a capacity refusal is marked");
    assert_eq!(staged_ops(&fs).len(), 1, "only the blocker in flight");
    assert!(
        fs.take_pool_releases().is_empty(),
        "the refusal returned a buffer the connection still releases"
    );
}

/// A leased write refused behind an earlier one of the same delivery drops only its own share: the buffer comes
/// back once, when the sibling completes.
#[cfg(feature = "net-server")]
#[test]
fn a_write_refused_behind_its_sibling_returns_the_buffer_once() {
    let mut eng = Engine::new(256, 128).expect("engine");
    let mut fs = FsCore::new(1, OffloadBounds::default());
    let file = dev_null();
    let buf = vec![7u8; 1024];
    let taken = std::cell::Cell::new(false);
    {
        let mut c = FsConn::new(&mut fs, &mut eng, OWNER0).with_recv_lease(Some(RecvWriteLease {
            ptr: buf.as_ptr(),
            cap: buf.len(),
            bid: 5,
            taken: &taken,
        }));
        for half in buf.chunks(buf.len() / 2) {
            c.pwritev2_from(Personality(0), file.clone(), half, 0, RwFlags::empty(), |_d, _c| {});
        }
    }
    assert!(taken.get(), "the first write took the claim");
    let Some((_, _, done)) = fs.take_refusal() else {
        panic!("the second write is answered");
    };
    assert!(done.was_refused(), "refused for the full table");
    assert!(
        fs.take_pool_releases().is_empty(),
        "returned while the sibling still reads it"
    );
    let [(tag, slot, generation)] = staged_ops(&fs)[..] else {
        panic!("the first write in flight");
    };
    let half = (buf.len() / 2) as i32;
    let ReapedFs::Embedded(_, mut done, _) = fs.on_cqe(&mut eng, tag, slot, generation, half) else {
        panic!("an embedded completion");
    };
    assert_eq!(done.take_recv_lease(), Some(5), "back at the sibling's CQE");
    assert!(fs.take_pool_releases().is_empty(), "and nowhere else");
}

/// A gathered write the op table cannot take is refused with a marked `EBUSY`, and each window's buffer comes back
/// once as it drops.
#[cfg(feature = "net-server")]
#[test]
fn a_refused_gathered_write_returns_each_buffer_once() {
    let mut eng = Engine::new(256, 128).expect("engine");
    let mut fs = FsCore::new(1, OffloadBounds::default());
    let file = dev_null();
    let bufs = [vec![1u8; 1024], vec![2u8; 1024]];
    let windows = bufs
        .iter()
        .zip([5u16, 6])
        .map(|(buf, bid)| LeasedWindow {
            view: LeasedBytes {
                ptr: buf.as_ptr(),
                len: buf.len(),
            },
            hold: std::sync::Arc::new(LeaseHold::new(bid, fs.lease_returns(&eng.shared))),
        })
        .collect();
    {
        let mut c = FsConn::new(&mut fs, &mut eng, OWNER0);
        c.pwritev2(
            Personality(0),
            file.clone(),
            vec![vec![0u8; 16]],
            0,
            RwFlags::empty(),
            |_d, _c| {},
        );
        c.pwritev2_leased(Personality(0), file.clone(), windows, 0, RwFlags::empty(), |_d, _c| {});
    }
    let Some((_, _, done)) = fs.take_refusal() else {
        panic!("the gathered write is answered");
    };
    assert_eq!(done.raw_result(), Err(Errno::EBUSY));
    assert!(done.was_refused(), "a capacity refusal is marked");
    let mut back = fs.take_pool_releases();
    back.sort_unstable();
    assert_eq!(back, vec![5, 6], "each buffer, once");
}

/// A facade with no recv claim sends `offload_from` down its copy path. The job sees the caller's bytes, and the result
/// comes back through the ordinary `Result` seam with a panic mapped to `EIO`. The leased path is the net server's to
/// prove (`test/recv_alloc.rs`).
#[test]
fn offload_from_copies_where_nothing_is_leased() {
    type Seen = Rc<RefCell<Option<crate::Result<(usize, u64)>>>>;
    let (mut eng, mut fs, _me) = setup();
    let seen: Seen = Rc::new(RefCell::new(None));
    let bad: Rc<RefCell<Option<crate::Result<u64>>>> = Rc::new(RefCell::new(None));
    let (s2, b2) = (seen.clone(), bad.clone());
    let bytes: Vec<u8> = (0..=255u8).cycle().take(3 * 1024 + 7).collect();
    let want: u64 = bytes.iter().map(|&b| u64::from(b)).sum();
    with_silent_panics(|| {
        drive(
            &mut eng,
            &mut fs,
            move |c| {
                c.offload_from(
                    &bytes,
                    |view| Ok((view.len(), view.iter().map(|&b| u64::from(b)).sum())),
                    move |r, _c| *s2.borrow_mut() = Some(r),
                );
                c.offload_from(
                    &[1u8, 2, 3],
                    |_view| -> crate::Result<u64> { panic!("job blew up") },
                    move |r, _c| *b2.borrow_mut() = Some(r),
                );
            },
            || seen.borrow().is_some() && bad.borrow().is_some(),
        );
    });
    assert!(
        matches!(*seen.borrow(), Some(Ok((n, sum))) if n == 3 * 1024 + 7 && sum == want),
        "the job reads the caller's bytes: {:?}",
        seen.borrow()
    );
    assert!(
        matches!(*bad.borrow(), Some(Err(crate::Error::Errno(Errno::EIO)))),
        "a panicked job is exactly EIO: {:?}",
        bad.borrow()
    );
    assert!(
        fs.offload_reg.is_empty(),
        "no continuation may be stranded in the registry"
    );
}

/// `offload_result` maps a panicked job to exactly `EIO` - the documented contract - while an `Ok` job in the same
/// drive passes its value through untouched, and neither strands its registry entry.
#[test]
fn offload_result_maps_a_panicked_job_to_eio() {
    let (mut eng, mut fs, _me) = setup();
    let ok: Rc<RefCell<Option<crate::Result<u64>>>> = Rc::new(RefCell::new(None));
    let bad: Rc<RefCell<Option<crate::Result<u64>>>> = Rc::new(RefCell::new(None));
    let (o2, b2) = (ok.clone(), bad.clone());
    with_silent_panics(|| {
        drive(
            &mut eng,
            &mut fs,
            move |c| {
                c.offload_result(|| Ok(41u64), move |r, _c| *o2.borrow_mut() = Some(r));
                c.offload_result(
                    || -> crate::Result<u64> { panic!("job blew up") },
                    move |r, _c| *b2.borrow_mut() = Some(r),
                );
            },
            || ok.borrow().is_some() && bad.borrow().is_some(),
        );
    });
    assert!(
        matches!(*ok.borrow(), Some(Ok(41))),
        "the Ok job's value passes through: {:?}",
        ok.borrow()
    );
    assert!(
        matches!(*bad.borrow(), Some(Err(crate::Error::Errno(Errno::EIO)))),
        "a panicked job is exactly EIO: {:?}",
        bad.borrow()
    );
    assert!(
        fs.offload_reg.is_empty(),
        "no continuation may be stranded in the registry"
    );
}

/// The lookup lane delivers on the loop as `offload_result` does, a panicked job as exactly `EIO`, and strands no
/// registry entry. The second lookup is queued once the lane's thread has parked, so it runs only if the loop's
/// flush wakes the lane.
#[test]
fn a_lookup_delivers_on_the_loop_and_a_panic_as_eio() {
    let (mut eng, mut fs, _me) = setup();
    let ok: Rc<RefCell<Option<crate::Result<u64>>>> = Rc::default();
    let bad: Rc<RefCell<Option<crate::Result<u64>>>> = Rc::default();
    let (o2, b2) = (ok.clone(), bad.clone());
    // One thread at most, so the lane cannot grow, and its one thread parked is the whole lane at rest.
    fs.set_lookup_bounds(OffloadBounds { floor: 1, ceiling: 1 });
    let lane = Arc::clone(&fs.lookup);
    with_silent_panics(|| {
        drive(
            &mut eng,
            &mut fs,
            move |c| {
                c.offload_lookup(
                    || Ok(41u64),
                    move |r, c| {
                        *o2.borrow_mut() = Some(r);
                        let parking = std::time::Instant::now();
                        while lane.parked() != Some(1) {
                            assert!(parking.elapsed().as_secs() < 5, "the lane's thread never parked");
                            std::thread::yield_now();
                        }
                        c.offload_lookup(
                            || -> crate::Result<u64> { panic!("lookup blew up") },
                            move |r, _c| *b2.borrow_mut() = Some(r),
                        );
                    },
                );
            },
            || ok.borrow().is_some() && bad.borrow().is_some(),
        );
    });
    assert!(
        matches!(*ok.borrow(), Some(Ok(41))),
        "the Ok lookup's value passes through: {:?}",
        ok.borrow()
    );
    assert!(
        matches!(*bad.borrow(), Some(Err(crate::Error::Errno(Errno::EIO)))),
        "a panicked lookup is exactly EIO: {:?}",
        bad.borrow()
    );
    assert!(
        fs.offload_reg.is_empty(),
        "no continuation may be stranded in the registry"
    );
}

/// A lookup that waits never holds a thread of the file pool, and the lane's ceiling holds a second lookup back.
/// Both pools are cut to one thread, so the file job runs only if the waiting lookup is on a pool of its own, and
/// the second lookup runs only once the first ends.
#[test]
fn a_waiting_lookup_holds_no_file_thread_and_its_lane_stays_bounded() {
    use std::time::{Duration, Instant};
    let mut eng = Engine::new(256, 128).expect("engine");
    let one = OffloadBounds { floor: 1, ceiling: 1 };
    let mut fs = FsCore::new(256, one);
    fs.set_lookup_bounds(one);
    let (release, held) = std::sync::mpsc::channel::<()>();
    let release = RefCell::new(Some(release));
    let order: Rc<RefCell<Vec<&str>>> = Rc::default();
    let seen: RefCell<Vec<&str>> = RefCell::default();
    let (o1, o2, o3) = (order.clone(), order.clone(), order.clone());
    let began = Instant::now();
    drive(
        &mut eng,
        &mut fs,
        move |c| {
            c.offload_lookup(
                move || {
                    // Bounded, so a lane that shares the file pool fails the order below rather than hanging the
                    // test.
                    let _ = held.recv_timeout(Duration::from_secs(10));
                    Ok(())
                },
                move |_r, _c| o1.borrow_mut().push("waiting"),
            );
            c.offload_lookup(|| Ok(()), move |_r, _c| o2.borrow_mut().push("queued"));
            c.offload(|| (), move |_r, _c| o3.borrow_mut().push("file"));
        },
        || {
            // Long past the file job, a second lane thread would have run the queued lookup, were the ceiling not
            // one.
            let late = began.elapsed() > Duration::from_millis(200);
            if late
                && order.borrow().contains(&"file")
                && let Some(release) = release.borrow_mut().take()
            {
                seen.borrow_mut().clone_from(&order.borrow());
                release.send(()).ok();
            }
            order.borrow().len() == 3
        },
    );
    assert_eq!(
        *seen.borrow(),
        ["file"],
        "the file job ran while the lookup waited, and nothing else"
    );
    assert_eq!(*order.borrow(), ["file", "waiting", "queued"]);
}

/// A lane with no thread answers `EAGAIN` on the loop, on a later pass and not inside the call, and never runs the
/// job, which may wait seconds where the loop must not.
#[test]
fn a_lane_with_no_thread_answers_eagain_without_running_the_job() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let (mut eng, mut fs, _me) = setup();
    fs.lookup.back_off();
    let ran = Arc::new(AtomicBool::new(false));
    let got: Rc<RefCell<Option<crate::Result<()>>>> = Rc::default();
    let (r2, g2, g3) = (ran.clone(), got.clone(), got.clone());
    drive(
        &mut eng,
        &mut fs,
        move |c| {
            c.offload_lookup(
                move || {
                    r2.store(true, Ordering::Relaxed);
                    Ok(())
                },
                move |r, _c| *g2.borrow_mut() = Some(r),
            );
            assert!(g3.borrow().is_none(), "answered inside the call");
        },
        || got.borrow().is_some(),
    );
    assert!(
        matches!(*got.borrow(), Some(Err(crate::Error::Errno(Errno::EAGAIN)))),
        "a lane with no thread is EAGAIN: {:?}",
        got.borrow()
    );
    assert!(!ran.load(Ordering::Relaxed), "the job ran on the loop");
    assert!(
        fs.offload_reg.is_empty(),
        "no continuation may be stranded in the registry"
    );
}

/// Lookups that wait together each get a thread of the lane, though the loop sleeps right after queueing them. The
/// lane grows past its floor only at the deadline its flush returns, so the jobs meet at the barrier in time only
/// if the loop wakes for the lane's deadline as well as the file pool's.
#[test]
fn lookups_that_wait_together_each_get_a_thread() {
    const JOBS: usize = 3;
    const { assert!(LOOKUP_FLOOR < JOBS, "the fixture must need growth") };
    let (mut eng, mut fs, _me) = setup();
    let barrier = Arc::new(std::sync::Barrier::new(JOBS));
    let done = Rc::new(Cell::new(0usize));
    let d2 = done.clone();
    let began = std::time::Instant::now();
    drive(
        &mut eng,
        &mut fs,
        move |c| {
            for _ in 0..JOBS {
                let b = Arc::clone(&barrier);
                let d = d2.clone();
                c.offload_lookup(
                    move || {
                        b.wait();
                        Ok(())
                    },
                    move |_r, _c| d.set(d.get() + 1),
                );
            }
        },
        || done.get() == JOBS,
    );
    let took = began.elapsed();
    assert!(
        took < std::time::Duration::from_millis(500),
        "the waiting lookups got their threads only after {took:?}, so \
             the loop slept through the lane's deadline"
    );
}
