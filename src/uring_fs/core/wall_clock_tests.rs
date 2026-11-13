use super::WallClock;

/// The count that a broken pairing would run past zero, in the build that catches it.
#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "a wall-clock hold ended with nothing counted")]
fn a_hold_that_ends_twice_is_caught() {
    let mut w = WallClock::default();
    w.arm();
    w.ended(false);
    w.ended(false);
}

/// And in the build that ships, where the assert is not compiled: the count saturates at zero rather than wrapping
/// to `u32::MAX`.
///
/// That is the whole point of the shared impl. `refuse_wall_clock_hold` reads `armed >= cap`, so a wrapped `armed`
/// answers a marked `EBUSY` to every later timer arm and every `Allow` open by that owner for the life of the
/// reactor - and `is_empty` can never be true again, so the map entry is never reclaimed either. Saturating leaves
/// a stuck cap of one hold instead of a permanent refusal.
#[cfg(not(debug_assertions))]
#[test]
fn a_hold_that_ends_twice_saturates_rather_than_wrapping() {
    let mut w = WallClock::default();
    w.arm();
    w.ended(false);
    w.ended(false);
    assert_eq!(w.armed, 0, "the count wrapped");
    assert!(w.is_empty(), "the owner's entry can still be reclaimed");

    let mut w = WallClock::default();
    w.park();
    w.release_park();
    w.release_park();
    assert_eq!(w.retiring, 0, "the parked count wrapped");
    assert!(w.is_empty());

    let mut w = WallClock::default();
    w.retract();
    assert_eq!((w.armed, w.retiring), (0, 1), "a retraction with none armed");
}

/// The pairing itself, in both profiles: a retraction moves the count rather than returning it, and the CQE that
/// follows ends the half it moved to.
#[test]
fn a_retraction_moves_the_count_and_the_cqe_ends_it() {
    let mut w = WallClock::default();
    w.arm();
    w.retract();
    assert_eq!((w.armed, w.retiring), (0, 1));
    assert!(!w.is_empty(), "the slot has not freed yet");
    w.ended(true);
    assert!(w.is_empty());

    // An `Allow` pair: one count, two slots, so it parks on whichever frees first and goes home with the second.
    let mut w = WallClock::default();
    w.arm();
    w.ended(false);
    w.park();
    assert!(!w.is_empty(), "one count cannot go home with one of two");
    w.release_park();
    assert!(w.is_empty());
}
