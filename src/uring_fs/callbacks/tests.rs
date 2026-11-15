use super::*;
use std::cell::Cell;
use std::rc::Rc;

/// What a test's callbacks run with, the table they came from, as an op's callback reaches its core's op table, and a
/// log of what they saw.
struct Owner {
    rooms: Rooms<Log>,
    seen: Vec<u64>,
}

impl Owner {
    fn new(places: usize, bytes: usize) -> Owner {
        Owner {
            rooms: Rooms::new(places, bytes),
            seen: Vec::new(),
        }
    }
}

struct Log;

impl Sig for Log {
    type Args<'a, 'b>
        = &'a mut Owner
    where
        'b: 'a;
    type Boxed = Box<dyn FnOnce(&mut Owner)>;

    fn boxed<C: Call<Log>>(c: C) -> Self::Boxed {
        Box::new(move |owner: &mut Owner| c.call(owner))
    }
}

impl<F: FnOnce(&mut Owner) + 'static> Call<Log> for F {
    fn call<'a, 'b>(self, owner: &'a mut Owner)
    where
        'b: 'a,
    {
        self(owner)
    }
}

/// Counts its drops.
struct Drops(Rc<Cell<u32>>);

impl Drop for Drops {
    fn drop(&mut self) {
        self.0.set(self.0.get() + 1);
    }
}

/// Run the callback in the room of `place` as a core runs a reaped op's, or answer that the room was empty.
fn run(owner: &mut Owner, place: usize) -> bool {
    let Some(taken) = owner.rooms.take(place) else {
        return false;
    };
    // SAFETY: the table is `owner`'s and alive, and nothing parks in the room before the callback runs.
    unsafe { taken.run(owner) };
    true
}

/// A callback of no size and one of a room's size each run once from the room they were parked in, and a table with no
/// bytes keeps one of no size and nothing larger.
#[test]
fn callbacks_of_no_size_and_of_a_rooms_size_run_once_from_their_rooms() {
    let mut owner = Owner::new(2, 32);
    let words = [1u64, 2, 3, 4];
    assert!(
        owner.rooms.stage(move |o: &mut Owner| o.seen.extend(words)).is_ok(),
        "one of a room's size is kept"
    );
    assert!(owner.rooms.park(1), "and parked");
    assert!(
        owner.rooms.stage(|o: &mut Owner| o.seen.push(9)).is_ok(),
        "one of no size is kept"
    );
    assert!(owner.rooms.park(0), "and parked");
    assert!(run(&mut owner, 1) && run(&mut owner, 0), "both ran");
    assert_eq!(owner.seen, [1, 2, 3, 4, 9]);
    assert!(!run(&mut owner, 0) && !run(&mut owner, 1), "each ran once");

    let mut bare = Owner::new(1, 0);
    let one = 1u8;
    assert!(
        bare.rooms.stage(move |o: &mut Owner| o.seen.push(one.into())).is_err(),
        "a table with no bytes keeps nothing larger than no size"
    );
    assert!(
        bare.rooms.stage(|o: &mut Owner| o.seen.push(7)).is_ok(),
        "and keeps that"
    );
    assert!(bare.rooms.park(0) && run(&mut bare, 0), "which runs");
    assert_eq!(bare.seen, [7]);
}

/// A callback a byte larger than a room, or aligned to more than a room is, is handed back, and runs from the box its
/// caller puts it in.
#[test]
fn a_callback_a_byte_over_or_more_aligned_is_handed_back_and_runs_from_a_box() {
    #[repr(align(32))]
    #[derive(Clone, Copy)]
    struct Wide(u64);

    let mut owner = Owner::new(1, 32);
    let bytes = [5u8; 33];
    let Err(over) = owner
        .rooms
        .stage(move |o: &mut Owner| o.seen.push(bytes.iter().map(|&b| u64::from(b)).sum()))
    else {
        panic!("a byte over a room is handed back");
    };
    let wide = Wide(6);
    // Bound whole, since a closure that named only `wide.0` would capture the field alone.
    let Err(aligned) = owner.rooms.stage(move |o: &mut Owner| {
        let whole = wide;
        o.seen.push(whole.0);
    }) else {
        panic!("one aligned to more than a room is handed back");
    };
    assert!(owner.rooms.unstage().is_none(), "neither was staged");
    Log::boxed(over)(&mut owner);
    Log::boxed(aligned)(&mut owner);
    assert_eq!(owner.seen, [165, 6]);
}

/// A callback that panics as it runs drops what it held as it unwinds, and leaves its room empty, so neither its room
/// nor its table drops it again.
#[test]
fn a_callback_that_panics_leaves_nothing_to_drop_twice() {
    let drops = Rc::new(Cell::new(0));
    let mut owner = Owner::new(1, 32);
    let held = Drops(Rc::clone(&drops));
    let staged = owner.rooms.stage(move |_: &mut Owner| {
        let _held = &held;
        panic!("the callback fails");
    });
    assert!(staged.is_ok() && owner.rooms.park(0), "parked");
    let unwound = {
        let _quiet = crate::uring_fs::quiet_panics_on_this_thread();
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run(&mut owner, 0)))
    };
    assert!(unwound.is_err(), "the panic reaches the caller");
    assert_eq!(drops.get(), 1, "what it held dropped as it unwound");
    owner.rooms.discard(0);
    drop(owner);
    assert_eq!(drops.get(), 1, "and never again");
}

/// A callback dropped uncalled, as the teardown drain drops one, drops what it holds once, whether it is in a room,
/// staged, or boxed, and one still in a room or staged drops with its table.
#[test]
fn a_callback_dropped_uncalled_drops_what_it_holds_once() {
    let drops = Rc::new(Cell::new(0));
    let holding = || {
        let held = Drops(Rc::clone(&drops));
        move |_: &mut Owner| drop(held)
    };
    let mut owner = Owner::new(2, 32);
    for place in 0..2 {
        assert!(
            owner.rooms.stage(holding()).is_ok() && owner.rooms.park(place),
            "parked"
        );
    }
    owner.rooms.discard(0);
    assert_eq!(drops.get(), 1, "the one dropped from its room");
    owner.rooms.discard(0);
    assert_eq!(drops.get(), 1, "an empty room drops nothing");
    drop(Log::boxed(holding()));
    assert_eq!(drops.get(), 2, "a boxed one");
    assert!(owner.rooms.stage(holding()).is_ok(), "one left staged");
    drop(owner);
    assert_eq!(drops.get(), 4, "the one in a room and the staged one, with their table");
}

/// A callback moved into a box from its room runs whole after another callback is parked over its old bytes.
#[test]
fn a_callback_moved_into_a_box_runs_after_its_room_is_written_over() {
    let mut owner = Owner::new(1, 32);
    let first = [1u64, 2, 3, 4];
    assert!(owner.rooms.stage(move |o: &mut Owner| o.seen.extend(first)).is_ok() && owner.rooms.park(0));
    let boxed = owner.rooms.unpark(0).expect("the room held one");
    let second = [5u64, 6, 7, 8];
    assert!(owner.rooms.stage(move |o: &mut Owner| o.seen.extend(second)).is_ok());
    assert!(owner.rooms.park(0), "the room is empty once its callback is boxed");
    boxed(&mut owner);
    assert!(run(&mut owner, 0), "the second ran");
    assert_eq!(owner.seen, [1, 2, 3, 4, 5, 6, 7, 8]);
}

/// A callback running from its room may park another in that same room, as a reaped op's callback hands its slot to
/// the next op it submits, and each runs with what it holds whole.
#[test]
fn a_running_callback_may_park_another_in_its_own_room() {
    let mut owner = Owner::new(1, 32);
    let first = [1u64, 2, 3, 4];
    let staged = owner.rooms.stage(move |o: &mut Owner| {
        let second = [5u64, 6, 7, 8];
        assert!(o.rooms.stage(move |o: &mut Owner| o.seen.extend(second)).is_ok());
        assert!(o.rooms.park(0), "its own room is empty while it runs");
        o.seen.extend(first);
    });
    assert!(staged.is_ok() && owner.rooms.park(0), "parked");
    assert!(run(&mut owner, 0) && run(&mut owner, 0), "both ran");
    assert_eq!(owner.seen, [1, 2, 3, 4, 5, 6, 7, 8]);
}

/// One callback is staged at a time, and one is parked only in an empty room of a place.
#[test]
fn one_callback_is_staged_at_a_time_and_parked_only_in_an_empty_room() {
    let mut owner = Owner::new(2, 32);
    assert!(owner.rooms.stage(|o: &mut Owner| o.seen.push(1)).is_ok());
    assert!(
        owner.rooms.stage(|o: &mut Owner| o.seen.push(2)).is_err(),
        "a second is handed back while one is staged"
    );
    assert!(owner.rooms.park(0));
    assert!(owner.rooms.stage(|o: &mut Owner| o.seen.push(3)).is_ok());
    assert!(!owner.rooms.park(0), "a room that holds one takes no other");
    assert!(!owner.rooms.park(2), "the staging room is not a place");
    assert!(owner.rooms.park(1));
    assert!(!owner.rooms.park(1), "nothing is staged");
    assert!(run(&mut owner, 0) && run(&mut owner, 1));
    assert_eq!(owner.seen, [1, 3]);
}
