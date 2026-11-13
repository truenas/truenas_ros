use super::*;
use crate::sync::atomic::{AtomicBool, AtomicU64};
use crate::uring::wake::{LoopShared, WakeHandle};

fn bounded_model(f: impl Fn() + Sync + Send + 'static) {
    let mut b = loom::model::Builder::new();
    b.preemption_bound = Some(3);
    b.check(f);
}

/// A throwaway fd for the inject payload. Every `FsInject` variant carries one; which fd it is does not matter,
/// only that it is owned and closes with the message.
fn scratch_fd() -> Arc<OwnedFd> {
    // SAFETY: dup(2) returns a fresh owned descriptor or -1; stderr is always open in a test process.
    let raw = unsafe { libc::dup(2) };
    assert!(raw >= 0, "dup(2) failed in the model");
    // SAFETY: fresh owned fd from dup().
    Arc::new(unsafe { crate::fd::owned_from_raw(raw) })
}

fn handle() -> (FsHandle, mpsc::Receiver<FsInject>, Arc<LoopShared>) {
    let (tx, rx) = mpsc::channel();
    let shared = Arc::new(LoopShared {
        stop: AtomicBool::new(false),
        graceful: AtomicBool::new(false),
        grace_ms: AtomicU64::new(0),
        wake: WakeHandle::new().expect("the model's wake never fails"),
        #[cfg(feature = "net-server")]
        handed: crate::sync::atomic::AtomicUsize::new(0),
    });
    let h = FsHandle {
        tx,
        shared: Arc::clone(&shared),
        pool: offload_pool::SharedPool::new(offload_pool::FILE_WORKER, OffloadBounds { floor: 1, ceiling: 1 }),
    };
    (h, rx, shared)
}

// The liveness property this file's shutdown race really turns on - an accepted inject whose receiver is dropped
// disconnects the caller's reply channel, so `call` returns `ECONNABORTED` instead of parking - is **not modelled
// here**. loom's `mpsc` tracks a message count and no sender count (`loom-0.7.2/src/sync/mpsc.rs`), so `recv()` on
// a disconnected channel blocks in its scheduler and is reported as a deadlock rather than returning `Err`.
// Disconnect is unrepresentable, so the property is covered by a real-threads test instead:
// `shutdown_disconnects_a_queued_injects_reply`.

/// An `Ok` from `send` is honoured: the message is on the queue, so the loop's final drain finds it. An `Err` hands
/// the message back intact so the caller can recover the buffers it moved in. Neither outcome may leave a message
/// accepted-but-undrainable.
///
/// Once `stop` is visible to the caller, `send` refuses and gives the message back rather than queueing onto a loop
/// that will never drain.
#[test]
fn loom_inject_after_stop_is_refused() {
    bounded_model(|| {
        let (h, rx, shared) = handle();
        let (reply_tx, _reply_rx) = mpsc::channel();

        // The stop runs on its OWN thread, which is what makes this a model at all: with the store and the send in
        // program order there is exactly one interleaving to explore, so loom runs the body once and nothing about
        // when the flag becomes visible is under test. Two threads is the race the module header describes - the
        // loop decides to stop while a caller is inside `send`.
        //
        // Measured: the in-line form explores 1 execution; this one explores 6 and reaches both answers (4
        // accepted, 2 refused), so both arms of the assertion below are exercised.
        //
        // What it checks is that `send`'s answer and the queue AGREE, not the flag's Release/Acquire pairing:
        // weakening both sides to `Relaxed` leaves this model - and every other in the lane
        // - green, because the agreement holds whatever order the flag
        // becomes visible in. That ordering has no model; do not read this one as its detector.
        let stopper = {
            let shared = Arc::clone(&shared);
            loom::thread::spawn(move || shared.request_stop())
        };
        let accepted = h
            .send(FsInject::Fsync {
                pers: 0,
                file: scratch_fd(),
                datasync: false,
                offset: 0,
                length: 0,
                reply: ReplyTo::Sync(reply_tx),
            })
            .is_ok();
        stopper.join().unwrap();

        // Either answer is legal - the stop may land before or after the screen. What is not legal is the two
        // disagreeing: an accepted inject that never reached the queue is the caller parked for ever, and a refused
        // one that did is a payload handed back while the loop still owns it.
        assert_eq!(accepted, rx.try_recv().is_ok(), "send's answer and the queue disagree");
    });
}
