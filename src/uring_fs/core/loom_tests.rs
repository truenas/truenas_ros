use super::*;
use crate::uring::wake::WakeHandle;

fn bounded_model(f: impl Fn() + Sync + Send + 'static) {
    let mut b = loom::model::Builder::new();
    b.preemption_bound = Some(3);
    b.check(f);
}

/// A completion pushed concurrently with a drain is never stranded: the loop either drains it on this pass, or is
/// left with a pending poke that makes its next armed READ complete immediately.
#[test]
fn loom_offload_wakeup_loses_nothing() {
    bounded_model(|| {
        let mut fs = FsCore::new(4, OffloadBounds::default());
        let sink = fs.completion_sink();
        let wake = Arc::new(WakeHandle::new().expect("the model's wake never fails"));

        // Two workers finishing at once, as `FsConn::offload` leaves them: push under the lock, then poke.
        let mut workers = Vec::new();
        for token in 0..2u64 {
            let (s, w) = (Arc::clone(&sink), Arc::clone(&wake));
            workers.push(loom::thread::spawn(move || {
                finish_offload(&s, &w, token, Box::new(token));
            }));
        }

        // The loop: wake, drain, re-arm - repeatedly, as the reactor does. `take_pool_completions` discards tokens
        // with no registered continuation, so count what actually came off the queue instead.
        let mut seen = 0usize;
        while seen < 2 {
            wake.drain();
            seen += {
                let mut q = sink.lock().unwrap_or_else(|e| e.into_inner());
                q.drain(..).count()
            };
        }

        for w in workers {
            w.join().expect("worker");
        }

        // Nothing left behind, and the registry is untouched because no continuation was registered for these
        // tokens.
        assert!(
            sink.lock().unwrap_or_else(|e| e.into_inner()).is_empty(),
            "a completion was left on the queue"
        );
        assert!(
            fs.take_pool_completions().is_empty(),
            "an unregistered token produced a delivery"
        );
    });
}

/// A completion whose continuation *is* registered comes back out of `take_pool_completions` exactly once, and the
/// registry entry is consumed with it - a second drain must not fire it again.
#[test]
fn loom_offload_delivers_each_completion_once() {
    bounded_model(|| {
        let mut fs = FsCore::new(4, OffloadBounds::default());
        // `Owner` is `Option<(slot, generation)>`; `None` scopes the continuation to the reactor rather than to a
        // connection.
        let token = fs.register_offload(None, Box::new(|_any, _conn| unreachable!("not invoked in the model")));
        let sink = fs.completion_sink();
        let wake = Arc::new(WakeHandle::new().expect("the model's wake never fails"));

        let (s, w) = (Arc::clone(&sink), Arc::clone(&wake));
        let worker = loom::thread::spawn(move || {
            finish_offload(&s, &w, token, Box::new(()));
        });

        let mut delivered = 0usize;
        while delivered == 0 {
            wake.drain();
            delivered += fs.take_pool_completions().len();
        }
        worker.join().expect("worker");

        assert_eq!(delivered, 1, "the completion was delivered {delivered} times");
        assert!(
            fs.take_pool_completions().is_empty(),
            "the continuation fired twice for one completion"
        );
    });
}

/// A recv buffer standing in for the pool's: the job reads it on a worker, the pool overwrites it when it is
/// re-issued. loom refuses any interleaving where the two overlap, which is the whole claim
/// [`FsConn::offload_from`] makes about the bytes a job reads.
#[cfg(feature = "net-server")]
struct Buffer(loom::cell::UnsafeCell<u8>);
// SAFETY: the model's point is that loom checks every access for overlap; the cell is shared only to let it.
#[cfg(feature = "net-server")]
unsafe impl Sync for Buffer {}

/// A leased buffer is re-issued only after the job that read it has finished with it. The worker reads the bytes
/// and then finishes its offload - read, push, poke, as `offload_from`'s wrapper orders them; the reactor drains,
/// takes the job's share, and only then sees the buffer id come back, at which point the pool may write the buffer
/// again. The push under the sink's mutex is what orders the read before the write; without it the reactor could
/// release a buffer a worker is still reading.
#[cfg(feature = "net-server")]
#[test]
fn loom_leased_offload_releases_after_the_job_read() {
    bounded_model(|| {
        let mut fs = FsCore::new(4, OffloadBounds::default());
        let buffer = Arc::new(Buffer(loom::cell::UnsafeCell::new(0xa5)));
        // The job's share is the registry's alone: a leased write of the same delivery would hold another, and its
        // CQE would have dropped it on the reactor - the model is the job's ordering, which is the new one.
        let hold = std::sync::Arc::new(LeaseHold::detached(7));
        let token = fs.register_leased_offload(
            None,
            Box::new(|_any, _conn| unreachable!("not invoked in the model")),
            hold,
        );
        let sink = fs.completion_sink();
        let wake = Arc::new(WakeHandle::new().expect("the model's wake never fails"));

        let (s, w, b) = (Arc::clone(&sink), Arc::clone(&wake), Arc::clone(&buffer));
        let worker = loom::thread::spawn(move || {
            // The job: read the leased bytes, then finish.
            let seen = b.0.with(|p| unsafe { *p });
            finish_offload(&s, &w, token, Box::new(seen));
        });

        let mut released = Vec::new();
        while released.is_empty() {
            wake.drain();
            let _ = fs.take_pool_completions();
            released = fs.take_pool_releases();
        }
        assert_eq!(released, [7], "the job's share frees its buffer");
        // The pool re-issues the buffer: the write a still-running job's read must never overlap.
        buffer.0.with_mut(|p| unsafe { *p = 0 });
        worker.join().expect("worker");

        assert!(fs.take_pool_releases().is_empty(), "a buffer was released twice");
    });
}

/// A share dropped off the explicit release paths - a [`LeasedWindow`] a handler let go, here on a worker thread
/// after reading the bytes - returns its buffer through the core's queue, and the pool re-issues the buffer only
/// after that read. The push under the queue's mutex in `LeaseHold`'s drop is what orders the read before the
/// write, exactly as a finished job's push does.
#[cfg(feature = "net-server")]
#[test]
fn loom_dropped_share_returns_after_its_read() {
    bounded_model(|| {
        let fs = FsCore::new(4, OffloadBounds::default());
        let buffer = Arc::new(Buffer(loom::cell::UnsafeCell::new(0xa5)));
        let wake = Arc::new(crate::uring::wake::LoopShared {
            stop: crate::sync::atomic::AtomicBool::new(false),
            graceful: crate::sync::atomic::AtomicBool::new(false),
            grace_ms: crate::sync::atomic::AtomicU64::new(0),
            wake: WakeHandle::new().expect("the model's wake never fails"),
            handed: crate::sync::atomic::AtomicUsize::new(0),
        });
        let hold = std::sync::Arc::new(LeaseHold::new(7, fs.lease_returns(&wake)));
        let mut fs = fs;

        let b = Arc::clone(&buffer);
        let worker = loom::thread::spawn(move || {
            // The holder: read the leased bytes, then let the share go.
            let seen = b.0.with(|p| unsafe { *p });
            drop(hold);
            seen
        });

        let mut released = Vec::new();
        while released.is_empty() {
            wake.wake.drain();
            released = fs.take_pool_releases();
        }
        assert_eq!(released, [7], "the dropped share frees its buffer");
        // The pool re-issues the buffer: the write must never overlap the holder's read.
        buffer.0.with_mut(|p| unsafe { *p = 0 });
        assert_eq!(worker.join().expect("worker"), 0xa5);

        assert!(fs.take_pool_releases().is_empty(), "a buffer was released twice");
    });
}
