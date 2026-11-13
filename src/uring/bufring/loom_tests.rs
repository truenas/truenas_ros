use super::publish_tail;
use loom::cell::UnsafeCell;
use loom::sync::Arc;
use loom::sync::atomic::{AtomicU16, Ordering};

struct Ring {
    /// One descriptor's `addr` field: written plainly, like `post`.
    addr: UnsafeCell<u64>,
    /// The overlaid tail, published by `commit`'s own store.
    tail: AtomicU16,
}

// SAFETY: the tail's release/acquire pair is the only synchronization, exactly as on the real ring; loom verifies
// the accesses race-free under it.
unsafe impl Sync for Ring {}

#[test]
fn loom_a_descriptor_is_published_before_the_tail_that_names_it() {
    loom::model(|| {
        let ring = Arc::new(Ring {
            addr: UnsafeCell::new(0),
            tail: AtomicU16::new(0),
        });
        let producer = Arc::clone(&ring);
        let t = loom::thread::spawn(move || {
            // `post`: the descriptor's fields...
            producer.addr.with_mut(|p| unsafe { *p = 0xB0F });
            // ...then `commit`, through the store `commit` itself uses.
            publish_tail(&producer.tail, 1);
        });
        // The kernel's side: acquire the tail; a tail that names the descriptor must find its address already
        // there.
        if ring.tail.load(Ordering::Acquire) == 1 {
            let addr = ring.addr.with(|p| unsafe { *p });
            assert_eq!(addr, 0xB0F, "tail visible before its descriptor");
        }
        t.join().unwrap();
    });
}
