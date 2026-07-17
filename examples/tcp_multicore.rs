//! Multi-core serving: N independent single-ring servers on one address via
//! `SO_REUSEPORT` — the shared-nothing io_uring answer to a work-stealing
//! runtime.
//!
//! Each thread owns one [`Server`] (and thus one ring): rings are never shared
//! (`Server` is `!Send`), there are no locks, and the kernel load-balances
//! incoming connections across the listeners bound to the same address. This
//! is ring-per-**thread**, deliberately not ring-per-connection: one ring per
//! core keeps the single blocking wait and batched submission per thread,
//! while `reuse_port` provides the fan-out.
//!
//! The trade against a work-stealing runtime (e.g. tokio's multi-thread one):
//! balancing is per-*connection* at accept time, so a skewed set of heavy
//! connections cannot rebalance to idle cores afterwards.
//!
//!   cargo run --example tcp_multicore --features net-server
//!
//! Then send `[4-byte BE len][payload]` to the printed address from several
//! clients; replies are echoed with the serving worker's index appended.
//! Press Enter to shut all workers down gracefully.

use std::net::SocketAddrV4;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;
use truenas_ros::net::server::{
    length_prefixed, ClientAddr, Endian, PrefixWidth, Server, ServerAddr,
    ServerConfig, ShutdownHandle,
};

/// Frame a payload with a 4-byte BE length prefix.
fn frame(payload: &[u8]) -> Vec<u8> {
    let mut pdu = (payload.len() as u32).to_be_bytes().to_vec();
    pdu.extend_from_slice(payload);
    pdu
}

/// One worker: a whole `Server` (ring included) living on its own thread.
///
/// `Server` is `!Send`, so it must be *created* on the thread that runs it;
/// the `ShutdownHandle` (which is `Send + Sync`) and the resolved address are
/// channeled back out.
fn worker(
    index: usize,
    addr: SocketAddrV4,
    ready: mpsc::Sender<(SocketAddrV4, ShutdownHandle)>,
) -> truenas_ros::Result<()> {
    let cfg = ServerConfig {
        reuse_port: true, // all workers bind the same address
        ..ServerConfig::default()
    };
    // The protocol is constructed per worker — closures need not be Clone.
    let proto = length_prefixed(
        PrefixWidth::U32,
        Endian::Big,
        false,
        move |_h: &[u8], body: &[u8], _p: &ClientAddr| {
            let mut reply = body.to_vec();
            reply.extend_from_slice(format!(" [worker {index}]").as_bytes());
            Some(frame(&reply))
        },
    );
    let mut server = Server::with_config([ServerAddr::Tcp(addr)], cfg, proto)?;
    let ServerAddr::Tcp(bound) = server.local_addrs().remove(0) else {
        unreachable!("TCP listener");
    };
    let stop = server.shutdown_handle();
    // Report readiness (and, for the first worker, the resolved port).
    let _ = ready.send((bound, stop));
    server.serve_forever()
}

fn main() -> truenas_ros::Result<()> {
    let workers = thread::available_parallelism().map_or(2, |n| n.get());
    let (ready_tx, ready_rx) = mpsc::channel();

    // Worker 0 binds :0 to pick the port; the rest bind exactly that address
    // (SO_REUSEPORT on every listener, including the first).
    let first_tx = ready_tx.clone();
    let mut joins = vec![thread::spawn(move || {
        worker(0, "127.0.0.1:0".parse().unwrap(), first_tx)
    })];
    let (addr, first_stop) = ready_rx.recv().expect("worker 0 ready");

    let mut stops = vec![first_stop];
    for i in 1..workers {
        let tx = ready_tx.clone();
        joins.push(thread::spawn(move || worker(i, addr, tx)));
    }
    for _ in 1..workers {
        let (_, stop) = ready_rx.recv().expect("worker ready");
        stops.push(stop);
    }

    println!("{workers} workers (one ring each) listening on {addr}");
    println!("press Enter to shut down gracefully");
    let mut line = String::new();
    let _ = std::io::stdin().read_line(&mut line);

    for stop in &stops {
        stop.shutdown_graceful(Duration::from_secs(5));
    }
    for j in joins {
        j.join().expect("worker thread panicked")?;
    }
    Ok(())
}
