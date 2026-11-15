//! A callback kept in the room of its op's slot leaves the room before another callback is parked there, and a callback
//! that cannot run from its room waits in a box. Each table here has one slot, so the next op always takes the slot a
//! callback was in, and each callback holds numbers that fill its room, so a callback written over shows.

use super::*;
use crate::uring::sys::IORING_CQE_F_MORE;
use std::time::{Duration, Instant};

/// What the callbacks saw, each its numbers and whether its op was refused.
type Seen = Rc<RefCell<Vec<([u64; 7], bool)>>>;

/// A callback of a room's size that records its numbers and its op's verdict.
fn recording(marks: [u64; 7], seen: &Seen) -> impl FnOnce(FsDone, &mut FsConn<'_>) + 'static {
    let seen = Rc::clone(seen);
    move |done: FsDone, _: &mut FsConn<'_>| seen.borrow_mut().push((marks, done.was_refused()))
}

fn a_file() -> (crate::TempDir, File) {
    let dir = crate::tempdir().expect("tempdir");
    let f = std::fs::File::create(dir.path().join("f")).expect("create");
    (dir, File::new(Arc::new(OwnedFd::from(f))))
}

fn one_slot() -> (Engine, FsCore, Personality) {
    let eng = Engine::new(256, 128).expect("engine");
    let fs = FsCore::new(1, OffloadBounds::default());
    let me = Personality(register_personality(eng.ring.raw_fd()).expect("personality"));
    (eng, fs, me)
}

/// Submit until the ring's next completion of the fs core, and reap it, without delivering what it hands back.
fn reap_next(eng: &mut Engine, fs: &mut FsCore) -> ReapedFs {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        assert!(Instant::now() < deadline, "the op never completed");
        eng.ring.submit().expect("submit");
        let Some(cqe) = eng.ring.reap() else {
            std::thread::sleep(Duration::from_millis(1));
            continue;
        };
        if cqe.flags & IORING_CQE_F_MORE == 0 {
            eng.inflight = eng.inflight.saturating_sub(1);
        }
        let (tag, slot, generation) = unpack_raw(cqe.user_data);
        if tag & TAG_FS_DOMAIN == 0 || tag == TAG_CANCEL || tag == TAG_WAKE {
            continue;
        }
        return fs.on_cqe(eng, tag, slot, generation, cqe.res);
    }
}

/// A reaped op's slot goes back at once, for a parked body read to take first, while its callback keeps the slot's room
/// until it runs. An op submitted before the callback runs takes the slot with its own callback boxed, rather than
/// written over the held one, and each runs with its numbers whole.
#[test]
fn a_reaped_callback_keeps_its_room_until_it_runs() {
    let (mut eng, mut fs, me) = one_slot();
    let (dir, file) = a_file();
    let seen: Seen = Rc::default();
    let first = recording([1, 2, 3, 4, 5, 6, 7], &seen);
    assert_eq!(size_of_val(&first), FS_CALLBACK_BYTES, "the callback fills its room");
    FsConn::new(&mut fs, &mut eng, OWNER0).fsync(me, file, first);
    let held = reap_next(&mut eng, &mut fs);
    assert!(
        matches!(held, ReapedFs::Embedded(ReapedCb::Parked { .. }, ..)),
        "the callback waits in its room"
    );
    assert_eq!(fs.op_free_len_for_test(), 1, "while its slot is free");
    let second = recording([8, 9, 10, 11, 12, 13, 14], &seen);
    FsConn::new(&mut fs, &mut eng, OWNER0).fsync(me, a_file_of(&dir), second);
    assert!(
        matches!(
            fs.ops[0].state.waiter,
            Some(FsWaiter::Embedded {
                cb: Callback::Boxed(_),
                ..
            })
        ),
        "the next op took the slot and boxed its callback"
    );
    deliver_embedded(&mut fs, &mut eng, held);
    assert_eq!(
        *seen.borrow(),
        [([1, 2, 3, 4, 5, 6, 7], false)],
        "the held callback ran whole"
    );
    let ran = Rc::clone(&seen);
    drive(&mut eng, &mut fs, |_| {}, || ran.borrow().len() == 2);
    assert_eq!(
        seen.borrow()[1],
        ([8, 9, 10, 11, 12, 13, 14], false),
        "and then the boxed one, whole"
    );
}

/// The room of a reaped op's callback is empty once the callback moves out to run, so the op the callback submits takes
/// the slot and parks its own callback in that room, and each callback runs with its own numbers.
#[test]
fn a_callbacks_next_op_takes_the_slot_it_came_from() {
    let (mut eng, mut fs, me) = one_slot();
    let (dir, file) = a_file();
    let seen: Seen = Rc::default();
    let next = Rc::clone(&seen);
    let marks = [1u64, 2, 3, 4, 5];
    let first = move |done: FsDone, c: &mut FsConn<'_>| {
        c.fsync(me, file, recording([8, 9, 10, 11, 12, 13, 14], &next));
        assert!(
            matches!(
                c.fs.ops[0].state.waiter,
                Some(FsWaiter::Embedded {
                    cb: Callback::Parked,
                    ..
                })
            ),
            "the next op's callback is in the room this one left"
        );
        let mut whole = [0; 7];
        whole[..5].copy_from_slice(&marks);
        next.borrow_mut().push((whole, done.was_refused()));
    };
    assert!(size_of_val(&first) <= FS_CALLBACK_BYTES, "the callback fits its room");
    let ran = Rc::clone(&seen);
    drive(
        &mut eng,
        &mut fs,
        |c| c.fsync(me, a_file_of(&dir), first),
        || ran.borrow().len() == 2,
    );
    assert_eq!(
        *seen.borrow(),
        [([1, 2, 3, 4, 5, 0, 0], false), ([8, 9, 10, 11, 12, 13, 14], false)],
        "neither callback was written over"
    );
}

/// The file `f` again, as another handle, for an op of its own.
fn a_file_of(dir: &crate::TempDir) -> File {
    let f = std::fs::OpenOptions::new()
        .write(true)
        .open(dir.path().join("f"))
        .expect("open");
    File::new(Arc::new(OwnedFd::from(f)))
}

/// A callback whose op is refused after it took its slot waits for the drain in a box, while the next op takes the
/// slot and parks its own callback in the room, and it runs with its numbers whole and the caller's file handed back.
#[test]
fn a_callback_refused_after_it_took_its_slot_waits_in_a_box() {
    let (mut eng, mut fs, me) = one_slot();
    let (dir, file) = a_file();
    let seen: Seen = Rc::default();
    let back: Rc<RefCell<Option<File>>> = Rc::default();
    let first = {
        let (seen, back) = (Rc::clone(&seen), Rc::clone(&back));
        let marks = [1u64, 2, 3, 4, 5, 6];
        move |done: FsDone, _: &mut FsConn<'_>| {
            *back.borrow_mut() = done.file();
            let mut whole = [0; 7];
            whole[..6].copy_from_slice(&marks);
            seen.borrow_mut().push((whole, done.was_refused()));
        }
    };
    assert!(size_of_val(&first) <= FS_CALLBACK_BYTES, "the callback fits its room");
    eng.stage_seam.refuse_next = true;
    FsConn::new(&mut fs, &mut eng, OWNER0).fsync(me, file.clone(), first);
    assert_eq!(fs.refusals_queued(), 1, "refused after it took the slot");
    assert_eq!(fs.op_free_len_for_test(), 1, "and the slot went back");
    let ran = Rc::clone(&seen);
    drive(
        &mut eng,
        &mut fs,
        |c| c.fsync(me, a_file_of(&dir), recording([8, 9, 10, 11, 12, 13, 14], &seen)),
        || ran.borrow().len() == 2,
    );
    assert_eq!(
        *ran.borrow(),
        [([1, 2, 3, 4, 5, 6, 0], true), ([8, 9, 10, 11, 12, 13, 14], false)],
        "the refused callback ran whole from its box, and the next op from the room"
    );
    let handed = back.borrow_mut().take().expect("the refusal hands the file back");
    assert!(Arc::ptr_eq(&handed.fd, &file.fd), "the caller's own file");
}

/// The teardown drain drops a callback still in its slot's room unfired as it reaps the op, as it drops a boxed one.
#[test]
fn the_teardown_drain_drops_a_callback_in_its_room() {
    struct Drops(Rc<Cell<u32>>);
    impl Drop for Drops {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }
    let (mut eng, mut fs, me) = one_slot();
    let (_dir, file) = a_file();
    let (drops, fired) = (Rc::new(Cell::new(0)), Rc::new(Cell::new(false)));
    let held = Drops(Rc::clone(&drops));
    let ran = Rc::clone(&fired);
    FsConn::new(&mut fs, &mut eng, OWNER0).fsync(me, file, move |_: FsDone, _: &mut FsConn<'_>| {
        let _held = &held;
        ran.set(true);
    });
    assert_eq!(fs.op_free_len_for_test(), 0, "the op holds the slot");
    let cqe = IoUringCqe {
        user_data: pack_raw(TAG_FSYNC, 0, fs.ops[0].generation as u32),
        res: -libc::ECANCELED,
        flags: 0,
    };
    fs.on_drain_cqe(&cqe);
    assert_eq!(drops.get(), 1, "the callback dropped as the drain reaped its op");
    assert!(!fired.get(), "unfired");
}
