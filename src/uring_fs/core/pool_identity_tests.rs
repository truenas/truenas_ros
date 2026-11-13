use super::*;

/// An iteration that queued nothing still bounds the loop's sleep by a deadline an off-loop submitter left on the
/// pool ([`SharedPool::submit`]).
#[test]
fn a_turn_that_queued_nothing_keeps_another_submitters_deadline() {
    use std::sync::{Arc, Condvar, Mutex};
    use std::time::{Duration, Instant};

    let mut core = FsCore::new(
        4,
        OffloadBounds {
            floor: 1,
            ..OffloadBounds::default()
        },
    );
    let pool = core.pool_handle();
    // No flush here. One made while the floor worker is still starting finds nothing parked, so it grows the pool or
    // leaves a deadline for growing it, and a worker that is starting takes the job with no wake.
    pool.enqueue(Box::new(|| {}));
    let parking = Instant::now();
    while pool.parked() != Some(1) {
        assert!(
            parking.elapsed() < Duration::from_secs(5),
            "the pool's floor never parked"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(core.flush_offloads(), None, "owed with nothing queued");

    // Two blocking jobs flushed as an off-loop submitter does: the one worker is claimed, and the second job waits
    // on the first.
    let gate = Arc::new((Mutex::new(false), Condvar::new()));
    for _ in 0..2 {
        let g = Arc::clone(&gate);
        pool.enqueue(Box::new(move || {
            let (m, cv) = &*g;
            let mut open = m.lock().unwrap();
            while !*open {
                open = cv.wait(open).unwrap();
            }
        }));
    }
    assert!(pool.flush(2).is_some(), "the fixture left nothing owed");
    // If the deadline has passed, this flushes, and the pool (still with a job behind a blocked worker) returns
    // another.
    let seen = core.flush_offloads();
    {
        let (m, cv) = &*gate;
        *m.lock().unwrap() = true;
        cv.notify_all();
    }
    assert!(
        seen.is_some(),
        "a turn that queued nothing dropped the deadline another \
             submitter left, and the loop would sleep untimed"
    );
}

/// A ring has exactly one offload pool, so the handle minted for off-loop submitters is the core's own pool object. A
/// path that replaced `FsCore::pool` after a handle was minted would split the thread budget across two live pools.
#[test]
fn a_pool_handle_is_the_core_pool_itself() {
    let core = FsCore::new(4, OffloadBounds::default());
    let handle = core.pool_handle();
    assert!(
        Arc::ptr_eq(&handle, &core.pool),
        "pool_handle minted a different pool object"
    );
}
