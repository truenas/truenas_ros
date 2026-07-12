//! Driving the outbound `net::client` against an in-process `net::server` echo.
//!
//! `net::client` is the outbound half of the io_uring stream stack. Like the
//! server it owns one ring on one thread and is caller-driven: `next_event`
//! pumps the ring and *returns* completions (`Event`) rather than invoking
//! callbacks. This example runs the whole outbound flow against a real server,
//! entirely in one process:
//!
//!  1. an echo `net::server` is bound on an ephemeral loopback port and run on
//!     its own thread — both roles are `!Send` (one ring each), so they cannot
//!     share a thread; it hands its resolved address and a `ShutdownHandle`
//!     (both `Send`) back through a channel;
//!  2. the client opens several connections at once with `connect_start`
//!     (non-blocking) and drives them all up on the one ring;
//!  3. it fans out a batch of length-prefixed requests across them with `send`
//!     (non-blocking, so several are in flight per connection at once), plus one
//!     blocking `request` to show the simple path;
//!  4. it pumps `next_event` to collect every echo, correlating each reply to
//!     the connection (and request id) that produced it, and prints them.
//!
//! Run (loopback only):
//!   cargo run --example tcp_client --features net-server,net-client
//!
//! It prints the echoes and exits 0 — no external server or client needed.

use std::collections::HashMap;
use std::io;
use std::sync::mpsc;
use std::thread;
use truenas_ros::net::client::{
    Client, ClientConfig, ConnId, ConnectOpts, Event, RequestId,
};
use truenas_ros::net::server::{
    length_prefix_header, length_prefixed, ClientAddr, Endian, PrefixWidth,
    Server, ServerAddr, ShutdownHandle,
};

/// Frame a payload with a 4-byte big-endian length prefix (not counting
/// itself) — the wire format both roles share here.
fn frame(payload: &[u8]) -> Vec<u8> {
    let mut pdu = (payload.len() as u32).to_be_bytes().to_vec();
    pdu.extend_from_slice(payload);
    pdu
}

/// The server's echo handler: re-frame the received body so the client can
/// length-delimit the reply. `Some(bytes)` sends exactly those bytes verbatim;
/// returning `None` would close the connection instead.
fn echo(_header: &[u8], body: &[u8], _peer: &ClientAddr) -> Option<Vec<u8>> {
    Some(frame(body))
}

/// Bind the echo server, hand its resolved address + `ShutdownHandle` back on
/// `ready`, then run its loop until stopped. Runs on its own thread because
/// `Server` owns a single-thread ring (`!Send`).
fn run_server(
    ready: mpsc::Sender<(ServerAddr, ShutdownHandle)>,
) -> truenas_ros::Result<()> {
    let proto = length_prefixed(PrefixWidth::U32, Endian::Big, false, echo);
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse().unwrap());
    let mut server = Server::bind([addr], proto)?;
    // Resolve the ephemeral port and grab a stop handle, then publish both to
    // the main thread before blocking in the loop.
    let bound = server.local_addrs().remove(0);
    ready
        .send((bound, server.shutdown_handle()))
        .expect("main thread receives readiness");
    server.serve_forever()
}

fn main() -> io::Result<()> {
    // The server owns its own ring/thread; it publishes where it bound and how
    // to stop it back to us. (`Server::bind`/`serve_forever` return the crate's
    // `Result`, which `?`-bridges into this `io::Result` main.)
    let (ready_tx, ready_rx) = mpsc::channel();
    let server_thread = thread::spawn(move || run_server(ready_tx));
    let (addr, stop) = ready_rx
        .recv()
        .expect("server thread bound and published its address");
    println!("server listening on {addr:?}");

    // The client: one ring, driven from this (main) thread. Bump max_in_flight
    // so a connection can hold a batch of requests at once (pipelining); the
    // reply framer is the same 4-byte BE length prefix, over unit state `()`.
    let cfg = ClientConfig {
        max_in_flight: 8,
        ..ClientConfig::default()
    };
    let mut client = Client::new(
        cfg,
        length_prefix_header::<()>(PrefixWidth::U32, Endian::Big, false),
    )?;

    // --- Open a few connections at once (fan-out) --------------------------
    // `connect_start` is non-blocking: it returns a ConnId immediately and the
    // connection comes up later as an `Event::Connected`. Firing several before
    // pumping drives them all up on the one ring. Label each so the output is
    // readable ("conn #0", …) rather than an opaque handle.
    const CONNS: usize = 3;
    let mut label: HashMap<ConnId, usize> = HashMap::new();
    for i in 0..CONNS {
        let conn =
            client.connect_start(addr.clone(), ConnectOpts::default())?;
        label.insert(conn, i);
    }
    let mut up = 0;
    while up < CONNS {
        match client.next_event()? {
            Some(Event::Connected { conn }) => {
                println!("conn #{} connected", label[&conn]);
                up += 1;
            }
            Some(Event::ConnectFailed { conn, err }) => {
                return Err(io::Error::other(format!(
                    "conn #{} failed to connect: {err}",
                    label[&conn]
                )));
            }
            Some(other) => println!("(unexpected during connect: {other:?})"),
            None => break,
        }
    }
    let conns: Vec<ConnId> = (0..CONNS)
        .map(|i| {
            *label
                .iter()
                .find(|&(_, &l)| l == i)
                .map(|(c, _)| c)
                .expect("every label has a connection")
        })
        .collect();

    // --- The simple path: one blocking request/reply -----------------------
    // `request` sends a framed PDU and pumps until *its* reply arrives (events
    // for the other connections are buffered for the `next_event` loop below).
    let reply = client.request(conns[0], frame(b"ping"))?;
    println!(
        "conn #{} blocking request -> {}",
        label[&conns[0]],
        String::from_utf8_lossy(&reply)
    );

    // --- Fan out a batch, then collect every echo with next_event ----------
    // Send several framed requests per connection without waiting between them
    // (so they go in flight together), remembering what each (conn, id) should
    // echo back.
    const PER_CONN: usize = 3;
    let mut expected: HashMap<(ConnId, RequestId), Vec<u8>> = HashMap::new();
    for &conn in &conns {
        for j in 0..PER_CONN {
            let payload = format!("conn{}-msg{j}", label[&conn]).into_bytes();
            let id = client.send(conn, frame(&payload))?;
            expected.insert((conn, id), payload);
        }
    }

    // Collect exactly one echo per queued request. Replies can arrive in any
    // order across connections; the client FIFO-correlates each to a sent id,
    // and `next_event` returns it as it lands.
    let mut remaining = expected.len();
    while remaining > 0 {
        match client.next_event()? {
            Some(Event::Reply { conn, id, body, .. }) => {
                let want = expected
                    .remove(&(conn, id))
                    .expect("reply correlates to a sent request");
                assert_eq!(&body[..], &want[..], "echo matches the request");
                println!(
                    "conn #{} reply {id:?} -> {}",
                    label[&conn],
                    String::from_utf8_lossy(&body)
                );
                remaining -= 1;
            }
            Some(other) => println!("(ignoring {other:?})"),
            None => break,
        }
    }

    // --- Close, stop the server, join --------------------------------------
    // Close every connection, then drain the client until no connections remain
    // (each close surfaces a `Closed` event; `next_event` returns `None` once
    // nothing is left in flight).
    for &conn in &conns {
        client.close(conn);
    }
    while let Some(ev) = client.next_event()? {
        if let Event::Closed { conn, .. } = ev {
            println!("conn #{} closed", label[&conn]);
        }
    }

    stop.shutdown();
    server_thread.join().expect("server thread joins")?;
    println!("done");
    Ok(())
}
