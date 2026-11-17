//! A bounded fsync past the bound waits on the ring, holding its slot, and goes on as one in flight ends, in the order
//! they were asked. Each core here lets one bounded fsync be in flight, so the next waits.

use super::*;
use std::time::{Duration, Instant};

const OWNER1: Owner = Some((1, 0));

/// What each callback saw, its mark, its op's result and whether the op was refused.
type Seen = Rc<RefCell<Vec<(u32, Result<i32, Errno>, bool)>>>;

fn recording(mark: u32, seen: &Seen) -> impl FnOnce(FsDone, &mut FsConn<'_>) + 'static {
    let seen = Rc::clone(seen);
    move |done: FsDone, _: &mut FsConn<'_>| seen.borrow_mut().push((mark, done.result, done.refused))
}

/// A core of `slots` slots that lets one bounded fsync be in flight.
fn bound_of_one(slots: u32) -> (Engine, FsCore, Personality) {
    let eng = Engine::new(256, 128).expect("engine");
    let mut fs = FsCore::new(slots, OffloadBounds::default());
    fs.set_fsync_bound(Some(1));
    let me = Personality(register_personality(eng.ring.raw_fd()).expect("personality"));
    (eng, fs, me)
}

fn a_dir() -> crate::TempDir {
    let dir = crate::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("f"), b"x").expect("write");
    dir
}

/// The file `f` of `dir`, as a handle of its own.
fn a_file(dir: &crate::TempDir) -> File {
    let f = std::fs::OpenOptions::new()
        .write(true)
        .open(dir.path().join("f"))
        .expect("open");
    File::new(Arc::new(OwnedFd::from(f)))
}

/// How many fsyncs are staged and not yet reaped.
fn staged(fs: &FsCore) -> usize {
    fs.ops
        .iter()
        .filter(
            |e| matches!(e.state.state, FsOpState::InFlight { tag } if tag == TAG_FSYNC || tag == TAG_FSYNC_BOUNDED),
        )
        .count()
}

/// Submit until the ring's next completion of an fs op, and route it, without delivering what it hands back.
fn reap_next(eng: &mut Engine, fs: &mut FsCore) -> ReapedFs {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        assert!(Instant::now() < deadline, "no fsync completed");
        eng.ring.submit().expect("submit");
        let Some(cqe) = eng.ring.reap() else {
            std::thread::sleep(Duration::from_millis(1));
            continue;
        };
        eng.retire(&cqe);
        let (tag, slot, generation) = unpack_raw(cqe.user_data);
        if tag & TAG_FS_DOMAIN == 0 || tag == TAG_CANCEL || tag == TAG_WAKE {
            continue;
        }
        return fs.on_cqe(eng, tag, slot, generation, cqe.res);
    }
}

/// Deliver the refusals queued and reap and deliver completions until `seen` holds `n` outcomes.
fn run_until(eng: &mut Engine, fs: &mut FsCore, seen: &Seen, n: usize) {
    loop {
        deliver_pool_completions(fs, eng);
        if seen.borrow().len() >= n {
            return;
        }
        let reaped = reap_next(eng, fs);
        deliver_embedded(fs, eng, reaped);
    }
}

fn marks(seen: &Seen) -> Vec<u32> {
    seen.borrow().iter().map(|&(mark, _, _)| mark).collect()
}

/// A second bounded fsync asked in the same turn as the first is not staged until the first is reaped, and it is
/// staged then, before the first's callback runs.
#[test]
fn a_bounded_fsync_past_the_bound_waits_for_the_one_in_flight() {
    let (mut eng, mut fs, me) = bound_of_one(4);
    let dir = a_dir();
    let seen = Seen::default();
    {
        let mut c = FsConn::new(&mut fs, &mut eng, OWNER0);
        c.fsync_bounded(me, a_file(&dir), recording(1, &seen));
        c.fsync_bounded(me, a_file(&dir), recording(2, &seen));
    }
    assert_eq!(staged(&fs), 1, "one fsync is staged");
    assert_eq!(fs.fsyncs_waiting.len(), 1, "and the other waits");
    let first = reap_next(&mut eng, &mut fs);
    assert_eq!(staged(&fs), 1, "the second is staged as the first is reaped");
    assert!(seen.borrow().is_empty(), "before the first's callback runs");
    deliver_embedded(&mut fs, &mut eng, first);
    run_until(&mut eng, &mut fs, &seen, 2);
    assert_eq!(*seen.borrow(), [(1, Ok(0), false), (2, Ok(0), false)]);
}

/// Those waiting go on in the order they were asked, whichever connection asked them.
#[test]
fn bounded_fsyncs_go_on_in_the_order_they_came_across_owners() {
    let (mut eng, mut fs, me) = bound_of_one(8);
    let dir = a_dir();
    let seen = Seen::default();
    for (mark, owner) in [(1, OWNER0), (2, OWNER1), (3, OWNER0), (4, OWNER1)] {
        FsConn::new(&mut fs, &mut eng, owner).fsync_bounded(me, a_file(&dir), recording(mark, &seen));
    }
    assert_eq!(staged(&fs), 1, "one at a time");
    run_until(&mut eng, &mut fs, &seen, 4);
    assert_eq!(marks(&seen), [1, 2, 3, 4]);
}

/// A callback that asks another bounded fsync while others wait puts it behind them.
#[test]
fn a_callbacks_bounded_fsync_goes_in_behind_those_waiting() {
    let (mut eng, mut fs, me) = bound_of_one(8);
    let dir = a_dir();
    let seen = Seen::default();
    let (next, again) = (Rc::clone(&seen), a_file(&dir));
    let first = move |done: FsDone, c: &mut FsConn<'_>| {
        c.fsync_bounded(me, again, recording(4, &next));
        next.borrow_mut().push((1, done.result, done.refused));
    };
    {
        let mut c = FsConn::new(&mut fs, &mut eng, OWNER0);
        c.fsync_bounded(me, a_file(&dir), first);
        c.fsync_bounded(me, a_file(&dir), recording(2, &seen));
        c.fsync_bounded(me, a_file(&dir), recording(3, &seen));
    }
    run_until(&mut eng, &mut fs, &seen, 4);
    assert_eq!(marks(&seen), [1, 2, 3, 4]);
}

/// One that waits when its connection closes stays in its place and goes on in its turn, as the kernel answers it, since
/// a session can keep the reply it gives for the client's retry on another connection.
#[test]
fn a_bounded_fsync_waiting_for_a_closed_connection_goes_on() {
    let (mut eng, mut fs, me) = bound_of_one(8);
    let dir = a_dir();
    let seen = Seen::default();
    for (mark, owner) in [(1, OWNER0), (2, OWNER1), (3, OWNER0)] {
        FsConn::new(&mut fs, &mut eng, owner).fsync_bounded(me, a_file(&dir), recording(mark, &seen));
    }
    fs.cancel_owned_by(&mut eng, vec![(1, 0)]);
    assert_eq!(fs.refusals_queued(), 0, "the sweep ended nothing");
    assert_eq!(fs.fsyncs_waiting.len(), 2, "both still wait");
    run_until(&mut eng, &mut fs, &seen, 3);
    assert_eq!(
        *seen.borrow(),
        [(1, Ok(0), false), (2, Ok(0), false), (3, Ok(0), false)]
    );
}

/// One a callback asks once its connection is swept waits behind the one in flight and goes on, as an `fsync` asked
/// then does.
#[test]
fn a_bounded_fsync_asked_after_its_connection_is_swept_goes_on() {
    let (mut eng, mut fs, me) = bound_of_one(4);
    let dir = a_dir();
    let seen = Seen::default();
    FsConn::new(&mut fs, &mut eng, OWNER0).fsync_bounded(me, a_file(&dir), recording(1, &seen));
    fs.cancel_owned_by(&mut eng, vec![(1, 0)]);
    FsConn::new(&mut fs, &mut eng, OWNER1).fsync_bounded(me, a_file(&dir), recording(2, &seen));
    assert_eq!(fs.refusals_queued(), 0, "nothing refused");
    assert_eq!(fs.fsyncs_waiting.len(), 1, "it waits");
    run_until(&mut eng, &mut fs, &seen, 2);
    assert_eq!(*seen.borrow(), [(1, Ok(0), false), (2, Ok(0), false)]);
}

/// One in flight whose connection closes lets the next go on, however the cancel meets it, and so does one that fails.
#[test]
fn a_bounded_fsync_in_flight_that_is_cancelled_or_fails_lets_the_next_go() {
    let (mut eng, mut fs, me) = bound_of_one(8);
    let dir = a_dir();
    let seen = Seen::default();
    FsConn::new(&mut fs, &mut eng, OWNER1).fsync_bounded(me, a_file(&dir), recording(1, &seen));
    FsConn::new(&mut fs, &mut eng, OWNER0).fsync_bounded(me, a_file(&dir), recording(2, &seen));
    fs.cancel_owned_by(&mut eng, vec![(1, 0)]);
    run_until(&mut eng, &mut fs, &seen, 2);
    assert_eq!(marks(&seen), [1, 2]);
    assert_eq!(seen.borrow()[1], (2, Ok(0), false), "the next went on");

    // A pipe has no fsync, so the kernel answers `EINVAL` (`vfs_fsync_range`, `fs/sync.c`).
    let (reader, _writer) = std::io::pipe().expect("pipe");
    let pipe = File::new(Arc::new(OwnedFd::from(reader)));
    {
        let mut c = FsConn::new(&mut fs, &mut eng, OWNER0);
        c.fsync_bounded(me, pipe, recording(3, &seen));
        c.fsync_bounded(me, a_file(&dir), recording(4, &seen));
    }
    run_until(&mut eng, &mut fs, &seen, 4);
    assert_eq!(seen.borrow()[2..], [(3, Err(Errno::EINVAL), false), (4, Ok(0), false)]);
}

/// One whose staging fails as its turn comes is refused, and the next goes on.
#[test]
fn a_bounded_fsync_that_fails_to_stage_at_its_turn_is_refused() {
    let (mut eng, mut fs, me) = bound_of_one(8);
    let dir = a_dir();
    let seen = Seen::default();
    {
        let mut c = FsConn::new(&mut fs, &mut eng, OWNER0);
        for mark in 1..=3 {
            c.fsync_bounded(me, a_file(&dir), recording(mark, &seen));
        }
    }
    eng.stage_seam.refuse_next = true;
    let first = reap_next(&mut eng, &mut fs);
    assert_eq!(fs.refusals_queued(), 1, "the second's staging failed");
    assert_eq!(staged(&fs), 1, "and the third is staged");
    deliver_embedded(&mut fs, &mut eng, first);
    run_until(&mut eng, &mut fs, &seen, 3);
    assert_eq!(
        *seen.borrow(),
        [(1, Ok(0), false), (2, Err(Errno::EBUSY), true), (3, Ok(0), false)]
    );
}

/// The teardown drops each one still waiting as the drain drops an op in flight, never staged, its callback unrun and
/// its file let go, and the drain finishes.
#[test]
fn a_teardown_drops_the_bounded_fsyncs_still_waiting_unrun() {
    struct Drops(Rc<Cell<u32>>);
    impl Drop for Drops {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }
    let (mut eng, mut fs, me) = bound_of_one(8);
    let dir = a_dir();
    let (drops, fired) = (Rc::new(Cell::new(0)), Rc::new(Cell::new(false)));
    let files: Vec<File> = (0..3).map(|_| a_file(&dir)).collect();
    for file in &files {
        let (held, ran) = (Drops(Rc::clone(&drops)), Rc::clone(&fired));
        FsConn::new(&mut fs, &mut eng, OWNER0).fsync_bounded(me, file.clone(), move |_: FsDone, _: &mut FsConn<'_>| {
            let _held = &held;
            ran.set(true);
        });
    }
    drain_stop_window(&mut fs, &mut eng);
    assert_eq!(drops.get(), 2, "both waiting callbacks dropped");
    assert!(fs.fsyncs_waiting.is_empty(), "nothing waits");
    assert_eq!(staged(&fs), 1, "and neither was staged");
    assert_eq!(fs.op_free_len_for_test(), 7, "their slots went back");
    for file in &files[1..] {
        assert_eq!(Arc::strong_count(&file.fd), 1, "a waiting fsync's file was let go");
    }
    eng.cancel_and_reap_all(pack_raw(TAG_CANCEL, 0, 0), |cqe| fs.on_drain_cqe(cqe))
        .expect("the drain finishes");
    assert_eq!(drops.get(), 3, "and the one in flight dropped as it was reaped");
    assert!(!fired.get(), "none ran");
}

/// A full table refuses a bounded fsync with the marked `EBUSY` it refuses any op with, rather than letting it wait.
#[test]
fn a_full_table_refuses_a_bounded_fsync() {
    let (mut eng, mut fs, me) = bound_of_one(1);
    let dir = a_dir();
    let seen = Seen::default();
    {
        let mut c = FsConn::new(&mut fs, &mut eng, OWNER0);
        c.fsync_bounded(me, a_file(&dir), recording(1, &seen));
        c.fsync_bounded(me, a_file(&dir), recording(2, &seen));
    }
    assert_eq!(fs.refusals_queued(), 1, "refused at once");
    assert!(fs.fsyncs_waiting.is_empty(), "rather than waiting");
    run_until(&mut eng, &mut fs, &seen, 2);
    assert_eq!(*seen.borrow(), [(2, Err(Errno::EBUSY), true), (1, Ok(0), false)]);
}

/// With no bound set, no bounded fsync waits.
#[test]
fn no_bounded_fsync_waits_with_no_bound_set() {
    let mut eng = Engine::new(256, 128).expect("engine");
    let mut fs = FsCore::new(4, OffloadBounds::default());
    let me = Personality(register_personality(eng.ring.raw_fd()).expect("personality"));
    let dir = a_dir();
    let seen = Seen::default();
    {
        let mut c = FsConn::new(&mut fs, &mut eng, OWNER0);
        c.fsync_bounded(me, a_file(&dir), recording(1, &seen));
        c.fsync_bounded(me, a_file(&dir), recording(2, &seen));
    }
    assert_eq!(staged(&fs), 2, "both are staged at once");
    run_until(&mut eng, &mut fs, &seen, 2);
}
