use super::*;

/// One thread's guard dropping leaves another's alone, and a nested guard un-quiets nothing when it ends.
///
/// `set_hook` is one slot, not a stack, and `cargo test` runs a binary's tests as threads - so a guard that
/// installs over the current hook and restores it on drop cannot compose. Thread B installs over A's; A's guard
/// drops and restores the *default*, discarding B's filter while B is still running; B's later drop reinstates A's
/// stale filter for the rest of the process. The hook here is installed once and reads a set instead, so the
/// property to hold is the set's.
///
/// Asserted on the set rather than on stderr because the alternative is not stable: a test that installs a counting
/// hook to watch it either sits *over* the filter, where quieting is vacuous, or replaces the filter permanently
/// for every test that runs afterwards.
#[test]
fn quieting_composes_across_threads_and_nests() {
    fn quiet(id: std::thread::ThreadId) -> bool {
        quiet_threads()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(&id)
    }
    let me = std::thread::current().id();
    let both = std::sync::Arc::new(std::sync::Barrier::new(2));
    let gone = std::sync::Arc::new(std::sync::Barrier::new(2));

    let outer = quiet_panics_on_this_thread();
    assert!(quiet(me), "this thread is quiet");

    let (b, g) = (std::sync::Arc::clone(&both), std::sync::Arc::clone(&gone));
    let other = std::thread::spawn(move || {
        let id = std::thread::current().id();
        let mine = quiet_panics_on_this_thread();
        b.wait(); // both guards alive
        g.wait(); // the other thread has dropped its outer guard
        assert!(quiet(id), "another thread's drop un-quieted this one");
        drop(mine);
        assert!(!quiet(id), "its own drop must un-quiet it");
        id
    });

    both.wait();
    drop(outer);
    assert!(!quiet(me), "this thread's own drop un-quiets it");
    gone.wait();
    let other_id = other.join().expect("the other thread");
    assert!(!quiet(other_id), "and nothing is left behind");

    // Nesting: the inner guard ending does not un-quiet the outer.
    let outer = quiet_panics_on_this_thread();
    {
        let _inner = quiet_panics_on_this_thread();
        assert!(quiet(me), "quiet, twice over");
    }
    assert!(quiet(me), "a nested guard ending un-quieted the outer one");
    drop(outer);
    assert!(!quiet(me), "the last one out turns the lights on");
}

/// The guard is added where a special file could block, and nowhere else - because it is not free.
///
/// The descriptor is stripped afterwards, which is one blocking `fcntl` on the reactor thread per open;
/// `open_dir`'s walk opens a directory per request, and a directory cannot reach the blocking `open` the flag
/// exists to defeat. The exemption is a kernel ordering, cited on the function.
#[test]
fn the_special_file_guard_skips_what_cannot_block() {
    let guard = |flags: i32| {
        let mut raw = OpenHow::new().flags(OFlag::from_bits_retain(flags)).to_raw();
        let added = apply_special_file_guard(&mut raw, SpecialFiles::Guard);
        (added, raw.flags & libc::O_NONBLOCK as u64 != 0)
    };

    assert_eq!(
        guard(libc::O_RDONLY),
        (true, true),
        "an ordinary open can name a FIFO and must be guarded"
    );
    assert_eq!(
        guard(libc::O_RDONLY | libc::O_DIRECTORY),
        (false, false),
        "O_DIRECTORY answers ENOTDIR before the file's own open"
    );
    assert_eq!(
        guard(libc::O_RDONLY | libc::O_PATH),
        (false, false),
        "O_PATH never invokes the file's open"
    );
    assert_eq!(
        guard(libc::O_RDONLY | libc::O_NONBLOCK),
        (false, true),
        "a caller's own O_NONBLOCK is theirs, and stays"
    );

    let mut raw = OpenHow::new().flags(OFlag::O_RDONLY).to_raw();
    assert!(
        !apply_special_file_guard(
            &mut raw,
            SpecialFiles::Allow {
                deadline: std::time::Duration::from_secs(1),
            },
        ),
        "the opt-out is the one place a blocking open is asked for"
    );
}

/// The liveness half of the inject-vs-shutdown race: a caller that got an `Ok` from [`FsHandle::send`] and is
/// parked in [`FsHandle::call`] on its reply channel must be woken when the loop goes away, not left there.
///
/// What wakes it is ownership, not a notification - dropping the inject receiver drops whatever was still queued,
/// and each queued `FsInject` carries the `ReplyTo::Sync` sender for its own reply. So the reply channel
/// disconnects and `recv` returns an error `call` maps to `ECONNABORTED`.
///
/// This is deliberately a real-threads test rather than a loom model: loom's `mpsc` has no sender count, so a
/// disconnected `recv` blocks in its scheduler instead of returning `Err` (see the `loom_tests` note).
#[test]
fn shutdown_disconnects_a_queued_injects_reply() {
    let (tx, rx) = mpsc::channel();
    let shared = Arc::new(crate::uring::wake::LoopShared {
        stop: std::sync::atomic::AtomicBool::new(false),
        graceful: std::sync::atomic::AtomicBool::new(false),
        grace_ms: std::sync::atomic::AtomicU64::new(0),
        wake: crate::uring::wake::WakeHandle::new().expect("eventfd"),
        #[cfg(feature = "net-server")]
        handed: std::sync::atomic::AtomicUsize::new(0),
    });
    let h = FsHandle {
        tx,
        shared,
        pool: offload_pool::SharedPool::new(offload_pool::FILE_WORKER, OffloadBounds { floor: 1, ceiling: 1 }),
    };

    // SAFETY: dup(2) returns a fresh owned descriptor or -1; stderr is always open in a test process.
    let raw = unsafe { libc::dup(2) };
    assert!(raw >= 0, "dup(2) failed");
    // SAFETY: fresh owned fd from dup().
    let file = Arc::new(unsafe { crate::fd::owned_from_raw(raw) });

    let (reply_tx, reply_rx) = mpsc::channel();
    h.send(FsInject::Fsync {
        pers: 0,
        file,
        datasync: false,
        offset: 0,
        length: 0,
        reply: ReplyTo::Sync(reply_tx),
    })
    // `send`'s error *is* the un-sent message, which has no `Debug`, so check the discriminant rather than
    // unwrapping.
    .map_err(|_| ())
    .expect("the loop has not stopped yet, so this is accepted");

    // The loop goes away with the inject still queued.
    drop(rx);

    assert!(
        reply_rx.recv().is_err(),
        "a queued inject's caller was left parked after the loop went away"
    );
}

/// A stop already visible to the caller refuses the inject, and refuses it without queueing.
///
/// This is the *sequential* half of the shutdown screen, and it is not a concurrency property at all: with the flag
/// already set, [`FsHandle::send`]'s answer is straight-line behaviour of one thread.
/// `loom_inject_after_stop_is_refused` races the stop on its own thread and asserts only that `send`'s answer and
/// the queue AGREE - which stays true with the `stop_requested()` arm of `send` deleted, because both halves of
/// that equality are produced by the same path on the same thread. Measured at bfc51e2: with that arm removed every
/// one of the 25 loom models stays green, and the only thing in the tree that notices is
/// `teardown_with_inflight_op` in `test/uring_fs.rs`, which DEADLOCKS rather than failing. A model cannot hold this
/// property; this can.
#[test]
fn a_visible_stop_refuses_a_send_without_queueing() {
    let (tx, rx) = mpsc::channel();
    let shared = Arc::new(crate::uring::wake::LoopShared {
        stop: std::sync::atomic::AtomicBool::new(false),
        graceful: std::sync::atomic::AtomicBool::new(false),
        grace_ms: std::sync::atomic::AtomicU64::new(0),
        wake: crate::uring::wake::WakeHandle::new().expect("eventfd"),
        #[cfg(feature = "net-server")]
        handed: std::sync::atomic::AtomicUsize::new(0),
    });
    // The shipping spelling, so weakening the screen fails this.
    shared.request_stop();
    let h = FsHandle {
        tx,
        shared,
        pool: offload_pool::SharedPool::new(offload_pool::FILE_WORKER, OffloadBounds { floor: 1, ceiling: 1 }),
    };

    // SAFETY: dup(2) returns a fresh owned descriptor or -1; stderr is always open in a test process.
    let raw = unsafe { libc::dup(2) };
    assert!(raw >= 0, "dup(2) failed");
    // SAFETY: fresh owned fd from dup().
    let file = Arc::new(unsafe { crate::fd::owned_from_raw(raw) });

    let (reply_tx, _reply_rx) = mpsc::channel();
    let refused = h
        .send(FsInject::Fsync {
            pers: 0,
            file,
            datasync: false,
            offset: 0,
            length: 0,
            reply: ReplyTo::Sync(reply_tx),
        })
        .is_err();

    assert!(refused, "send accepted an inject after stop was set");
    assert!(rx.try_recv().is_err(), "a refused inject was queued anyway");
}

/// The elevation decision is a pure prefix match, so it is testable on any kernel - unlike the privileged write
/// itself, which needs 6.13 plus root and therefore only runs in the QEMU job.
#[test]
fn privileged_xattrs_matches_only_listed_prefixes() {
    let empty = PrivilegedXattrs::new();
    assert!(
        !empty.permits(c"trusted.example_etag"),
        "an empty policy grants nothing"
    );

    let p = PrivilegedXattrs::new()
        .allow_prefix(c"trusted.example_")
        .expect("valid prefix");
    assert!(p.permits(c"trusted.example_etag"));
    assert!(p.permits(c"trusted.example_"), "the prefix itself");
    // Neighbouring names that merely look similar are not covered.
    assert!(!p.permits(c"trusted.example"), "one byte short");
    assert!(!p.permits(c"trusted.other"));
    assert!(!p.permits(c"security.capability"));
    assert!(!p.permits(c"user.trusted.example_etag"));
    // A prefix match is anchored at the start, never a substring search.
    assert!(!p.permits(c"x.trusted.example_etag"));
}

#[test]
fn privileged_xattrs_accumulates_prefixes() {
    let p = PrivilegedXattrs::new()
        .allow_prefix(c"trusted.a_")
        .and_then(|p| p.allow_prefix(c"trusted.b_"))
        .expect("valid prefixes");
    assert!(p.permits(c"trusted.a_one"));
    assert!(p.permits(c"trusted.b_two"));
    assert!(!p.permits(c"trusted.c_three"));
}
