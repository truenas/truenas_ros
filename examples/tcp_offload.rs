//! Offloading the body handler to a worker pool with `Response::Defer`.
//!
//! The library ships **no** thread pool — you bring your own (rayon, tokio, a
//! threadpool crate, …). This example uses a tiny std one to stay dependency
//! free. The pattern:
//!
//!  1. the body handler copies the OWNED inputs a worker needs (never a borrow
//!     of connection state — that stays on the ring thread, so nothing to lock),
//!  2. detaches a `Deferred` from its `Responder` and hands it to the pool,
//!  3. returns `Response::Defer`, so the single io_uring thread goes straight
//!     back to polling instead of blocking on the work.
//!
//! The worker computes the reply and calls `Deferred::reply`, which queues it and
//! wakes the server; the server sends it on the originating connection — or drops
//! it safely if that connection closed while the worker ran (the `Deferred`
//! carries a slot+generation token, not a pointer).
//!
//!   cargo run --example tcp_offload --features net-server
//!
//! Then send `[4-byte BE len][payload]`; the reply is `[4-byte BE len][UPPER]`.
//! Payloads over 64 bytes are offloaded; smaller ones are answered inline.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use truenas_ros::net::server::{
    length_prefix_header, Endian, Incoming, PrefixWidth, Protocol, Request,
    Response, Server, ServerAddr,
};

/// Frame a payload with a 4-byte BE length prefix.
fn frame(payload: &[u8]) -> Vec<u8> {
    let mut pdu = (payload.len() as u32).to_be_bytes().to_vec();
    pdu.extend_from_slice(payload);
    pdu
}

/// A minimal fixed-size worker pool built from std: one channel per worker,
/// round-robin dispatch (so no receiver is shared under a lock). A real service
/// would use rayon/tokio/etc. — the server doesn't care which.
struct Pool {
    txs: Vec<mpsc::Sender<Box<dyn FnOnce() + Send>>>,
    next: AtomicUsize,
}

impl Pool {
    fn new(workers: usize) -> Pool {
        let mut txs = Vec::with_capacity(workers);
        for _ in 0..workers {
            let (tx, rx) = mpsc::channel::<Box<dyn FnOnce() + Send>>();
            txs.push(tx);
            thread::spawn(move || {
                while let Ok(job) = rx.recv() {
                    job();
                }
            });
        }
        Pool {
            txs,
            next: AtomicUsize::new(0),
        }
    }

    fn spawn(&self, job: impl FnOnce() + Send + 'static) {
        let i = self.next.fetch_add(1, Ordering::Relaxed) % self.txs.len();
        let _ = self.txs[i].send(Box::new(job));
    }
}

/// Stand-in for CPU-heavy or blocking work that must not run on the ring thread.
fn expensive(input: &[u8]) -> Vec<u8> {
    thread::sleep(std::time::Duration::from_millis(20));
    input.to_ascii_uppercase()
}

fn main() -> truenas_ros::Result<()> {
    let pool = Arc::new(Pool::new(4));

    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(
            PrefixWidth::U32,
            Endian::Big,
            false,
        ),
        body: {
            let pool = Arc::clone(&pool);
            move |req: Request<'_, ()>| {
                let Request {
                    mut body,
                    responder,
                    ..
                } = req;
                if body.len() <= 64 {
                    // Cheap: answer inline on the ring thread.
                    Response::Reply(frame(&body.to_ascii_uppercase()))
                } else {
                    // Expensive: offload so the ring thread keeps serving others.
                    // `deferred` is the Send reply handle for the worker;
                    // `permit` entitles returning `Response::Defer`.
                    // `take()` moves the body without a copy when it was
                    // placed (>= body_placement_threshold), copies otherwise.
                    let input = body.take();
                    let (deferred, permit) = responder.defer();
                    pool.spawn(move || {
                        deferred.reply(frame(&expensive(&input)))
                    });
                    Response::Defer(permit)
                }
            }
        },
    };

    let addr = ServerAddr::Tcp("127.0.0.1:9000".parse().unwrap());
    let mut server = Server::bind([addr], proto)?;
    println!("listening on {:?}", server.local_addrs());
    server.serve_forever()
}
