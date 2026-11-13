use super::*;

/// One thread's guard dropping leaves another's alone, and a nested guard un-quiets nothing when it ends.
///
/// Asserted on the set rather than on stderr, since a counting hook would either sit over the filter or replace it
/// for every later test.
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

/// The guard is added where a special file could block, and nowhere else, since stripping it costs a blocking `fcntl`
/// per open. The exemptions are cited on the function.
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
/// Dropping the inject receiver drops each queued `FsInject` and the `ReplyTo::Sync` sender it carries, so the reply
/// channel disconnects. A real-threads test, since loom's `mpsc` cannot represent a disconnect.
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
/// `loom_inject_after_stop_is_refused` checks only that `send`'s answer and the queue agree, which stays true with the
/// `stop_requested()` arm of [`FsHandle::send`] deleted, so no model holds this property and this test does.
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
