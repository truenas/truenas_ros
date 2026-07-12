//! Integration tests for the `net::client` module — a live loopback client
//! driving a real in-process [`net::server`](truenas_ros::net::server) over a
//! 4-byte big-endian length prefix. Beyond the basic echo round-trip they cover
//! the feature-complete plain-TCP surface: blocking vs. non-blocking connect,
//! pipelined multi-in-flight (FIFO reply correlation), multi-connection fan-out
//! on one ring, the response/idle/send timeouts, zero-copy body placement, the
//! bounded [`next_event_timeout`](Client::next_event_timeout) pump, and
//! stale-`ConnId` safety.
//!
//! These are client↔server *interop* tests, so they need both roles built —
//! hence the `net-server` gate alongside `net-client`. Like `test/net_server.rs`
//! they **skip** (return early) when io_uring is unavailable (the CI/dev sandbox
//! blocks the io_uring syscalls with ENOSYS/EPERM/EACCES); set
//! `TRUENAS_ROS_REQUIRE_IO_URING=1` to turn a skip into a hard failure.
//!
//! Both `Server` and `Client` are `!Send` (each owns a single-thread ring), so
//! the server runs `serve_forever` on the test thread while the client is
//! constructed and driven on a spawned thread, stopping the server via the
//! `Send` [`ShutdownHandle`] when done.
#![cfg(all(
    target_os = "linux",
    feature = "net-client",
    feature = "net-server"
))]

use std::collections::HashMap;
use std::io;
use std::net::{SocketAddr, SocketAddrV4, TcpListener};
use std::os::fd::RawFd;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use truenas_ros::net::client::{
    Client, ClientConfig, ConnId, ConnectOpts, Event, RequestId,
};
use truenas_ros::net::server::{
    length_prefixed, Endian, Listen, PrefixWidth, Server, ServerAddr,
    ShutdownHandle,
};
use truenas_ros::net::{ClientAddr, CloseReason, Framing};
use truenas_ros::{Errno, Error};

/// Errors that mean "io_uring is unavailable here" — an environmental skip.
/// Excludes `EINVAL` (a real setup bug we want to fail on).
fn is_unavailable(e: &Error) -> bool {
    matches!(
        e,
        Error::Errno(Errno::EPERM | Errno::ENOSYS | Errno::EACCES)
    )
}

fn should_skip(e: &Error) -> bool {
    if is_unavailable(e) {
        assert!(
            std::env::var_os("TRUENAS_ROS_REQUIRE_IO_URING").is_none(),
            "TRUENAS_ROS_REQUIRE_IO_URING set but io_uring unavailable: {e}"
        );
        return true;
    }
    false
}

fn to_io(e: Error) -> io::Error {
    io::Error::other(e.to_string())
}

/// Frame a payload with a 4-byte BE length prefix (matches the server's
/// `length_prefixed(U32, Big, false, ..)` framing and its echo reply).
fn frame(payload: &[u8]) -> Vec<u8> {
    let mut pdu = (payload.len() as u32).to_be_bytes().to_vec();
    pdu.extend_from_slice(payload);
    pdu
}

/// Server echo handler: re-frame the body with a 4-byte BE length prefix.
fn echo(_header: &[u8], body: &[u8], _peer: &ClientAddr) -> Option<Vec<u8>> {
    Some(frame(body))
}

/// A server handler that replies with a bare 4-byte length prefix declaring a
/// 100-byte body it never sends. The client, having read the prefix, arms a
/// (non-idle) body recv that carries the core request clock — so its
/// `response_timeout` fires and evicts the stalled connection. A normal echo
/// handler can't express a partial frame; a hand-built prefix can.
fn stalled_reply(_h: &[u8], _b: &[u8], _p: &ClientAddr) -> Option<Vec<u8>> {
    Some(vec![0, 0, 0, 100])
}

/// The client's reply framer: a 4-byte BE length prefix over the reply.
fn client_framer() -> impl FnMut(&[u8], &mut ()) -> Framing {
    truenas_ros::net::length_prefix_header::<()>(
        PrefixWidth::U32,
        Endian::Big,
        false,
    )
}

/// Guard that stops the server if the client thread panics, so a failed assert
/// surfaces through `join` instead of hanging `serve_forever`.
struct ShutdownOnDrop(ShutdownHandle);
impl Drop for ShutdownOnDrop {
    fn drop(&mut self) {
        self.0.shutdown();
    }
}

/// Bind a single-listener TCP `net::server` with `handler`, run `client` on a
/// spawned thread against its resolved address, and propagate the client's
/// result. Skips cleanly when io_uring is unavailable. The server stays on the
/// test thread in `serve_forever`; the client owns its own ring on the spawned
/// thread and stops the server when it returns.
fn with_server<Handler, ClientBody>(handler: Handler, client: ClientBody)
where
    Handler: FnMut(&[u8], &[u8], &ClientAddr) -> Option<Vec<u8>>,
    ClientBody: FnOnce(SocketAddrV4) -> io::Result<()> + Send + 'static,
{
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let mut server = match Server::bind(
        [addr],
        length_prefixed(PrefixWidth::U32, Endian::Big, false, handler),
    ) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind: {e}"),
    };
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();
    let handle = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone());
        let r = client(v4);
        stop.shutdown();
        r
    });
    server.serve_forever().expect("serve_forever");
    handle
        .join()
        .expect("client thread join")
        .expect("client body");
}

/// Connect to `v4` (blocking), run a request round-trip for each message
/// (keep-alive on one connection), gracefully close, and return the reply
/// bodies.
fn echo_client(v4: SocketAddrV4, msgs: &[&[u8]]) -> io::Result<Vec<Vec<u8>>> {
    let mut client =
        Client::new(ClientConfig::default(), client_framer()).map_err(to_io)?;
    // Blocking connect: it returns a serving connection ready for requests.
    let conn = client.connect(ServerAddr::Tcp(v4), ConnectOpts::default())?;
    assert!(
        client.is_open(conn),
        "connection is open after a blocking connect"
    );
    assert!(
        client.conn_state(conn).is_some(),
        "state reachable while open"
    );

    let mut replies = Vec::with_capacity(msgs.len());
    for m in msgs {
        let body = client.request(conn, frame(m))?;
        replies.push(body.to_vec());
    }

    // Graceful close, then drive it to the Closed event (the idle reply recv is
    // cancelled and the teardown reclaims the slot — no other traffic is
    // expected on an echo connection).
    client.close(conn);
    match client.next_event()? {
        Some(Event::Closed { conn: c, .. }) => {
            assert_eq!(c, conn, "Closed for the wrong connection");
        }
        None => {} // connection ended without a distinct event
        Some(other) => {
            return Err(io::Error::other(format!(
                "unexpected event after close: {other:?}"
            )))
        }
    }
    assert!(!client.is_open(conn), "connection should be closed");
    Ok(replies)
}

/// Bind an echo server, run `echo_client` against it, and assert the echoes
/// come back verbatim. Skips cleanly when io_uring is unavailable.
fn run_echo(msgs: Vec<Vec<u8>>) {
    let want = msgs.clone();
    with_server(echo, move |v4| {
        let refs: Vec<&[u8]> = msgs.iter().map(Vec::as_slice).collect();
        let got = echo_client(v4, &refs)?;
        assert_eq!(got, want);
        Ok(())
    });
}

#[test]
fn tcp_echo_roundtrip() {
    run_echo(vec![
        b"hello io_uring".to_vec(),
        b"second frame".to_vec(),
        b"third".to_vec(),
    ]);
}

#[test]
fn tcp_keepalive() {
    // Several requests on ONE connection — proves the connection is reused
    // (each request's reply is FIFO-correlated to it).
    let msgs: Vec<Vec<u8>> =
        (0..12).map(|i| format!("req-{i}").into_bytes()).collect();
    run_echo(msgs);
}

#[test]
fn tcp_connect_refused() {
    // A pure client test (no server): a *blocking* connect to a dead address
    // surfaces the failure directly as an `Err`.
    let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let SocketAddr::V4(dead) = probe.local_addr().unwrap() else {
        unreachable!("bound v4");
    };
    drop(probe); // free the port so a connect is refused

    let mut client = match Client::new(ClientConfig::default(), client_framer())
    {
        Ok(c) => c,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("client new: {e}"),
    };
    let err = client
        .connect(ServerAddr::Tcp(dead), ConnectOpts::default())
        .expect_err("blocking connect to a dead port must fail");
    assert!(
        matches!(
            err.kind(),
            io::ErrorKind::ConnectionRefused
                | io::ErrorKind::ConnectionReset
                | io::ErrorKind::TimedOut
        ),
        "unexpected connect error: {err} ({:?})",
        err.kind()
    );
    // The failed connect's slot is reclaimed; with no live connections the next
    // event is `None`.
    assert!(
        client.next_event().expect("drain").is_none(),
        "expected no events after a failed blocking connect"
    );
}

#[test]
fn tcp_connect_start_refused() {
    // The non-blocking form: a refusal surfaces as an `Event::ConnectFailed`
    // from `next_event`, not as an `Err` from the call.
    let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let SocketAddr::V4(dead) = probe.local_addr().unwrap() else {
        unreachable!("bound v4");
    };
    drop(probe);

    let mut client = match Client::new(ClientConfig::default(), client_framer())
    {
        Ok(c) => c,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("client new: {e}"),
    };
    let conn = client
        .connect_start(ServerAddr::Tcp(dead), ConnectOpts::default())
        .expect("connect_start stages");

    match client.next_event().expect("next_event") {
        Some(Event::ConnectFailed { conn: c, err }) => {
            assert_eq!(c, conn, "ConnectFailed for the wrong connection");
            assert!(
                matches!(
                    err,
                    Errno::ECONNREFUSED | Errno::ECONNRESET | Errno::ETIMEDOUT
                ),
                "unexpected connect error: {err:?}"
            );
        }
        other => panic!("expected ConnectFailed, got {other:?}"),
    }
    assert!(!client.is_open(conn), "a failed connect is not open");
    assert!(
        client.next_event().expect("drain").is_none(),
        "expected no further events after connect failure"
    );
}

#[test]
fn tcp_pipelined() {
    // Send several requests before pumping any reply (true multi-in-flight),
    // then assert the replies come back in FIFO order, each correlated to the
    // right RequestId with the right echoed body.
    with_server(echo, |v4| {
        let cfg = ClientConfig {
            max_in_flight: 8,
            ..ClientConfig::default()
        };
        let mut client = Client::new(cfg, client_framer()).map_err(to_io)?;
        let conn =
            client.connect(ServerAddr::Tcp(v4), ConnectOpts::default())?;

        let payloads: Vec<Vec<u8>> =
            (0..5).map(|i| format!("pipe-{i}").into_bytes()).collect();
        let mut ids: Vec<RequestId> = Vec::new();
        for p in &payloads {
            ids.push(client.send(conn, frame(p))?);
        }

        for (expected_id, payload) in ids.iter().zip(&payloads) {
            match client.next_event()? {
                Some(Event::Reply {
                    conn: c,
                    id,
                    header,
                    body,
                }) => {
                    assert_eq!(c, conn, "reply on the wrong connection");
                    assert_eq!(
                        id, *expected_id,
                        "replies must be FIFO-correlated to sent ids"
                    );
                    assert_eq!(header.len(), 4, "4-byte length prefix header");
                    assert_eq!(&body[..], &payload[..], "echoed body");
                }
                other => {
                    return Err(io::Error::other(format!(
                        "expected Reply, got {other:?}"
                    )))
                }
            }
        }
        client.close_now(conn);
        Ok(())
    });
}

#[test]
fn tcp_multi_conn_fanout() {
    // Open N connections (non-blocking), drive them all up on one ring, send a
    // distinct request on each, and confirm every reply maps back to the right
    // ConnId.
    with_server(echo, |v4| {
        let mut client = Client::new(ClientConfig::default(), client_framer())
            .map_err(to_io)?;
        const N: usize = 4;

        let mut conns: Vec<ConnId> = Vec::new();
        for _ in 0..N {
            conns.push(
                client.connect_start(
                    ServerAddr::Tcp(v4),
                    ConnectOpts::default(),
                )?,
            );
        }
        // One ring drives all N connects to completion.
        let mut connected = 0;
        while connected < N {
            match client.next_event()? {
                Some(Event::Connected { conn }) => {
                    assert!(
                        conns.contains(&conn),
                        "Connected for an unknown connection"
                    );
                    connected += 1;
                }
                other => {
                    return Err(io::Error::other(format!(
                        "expected Connected, got {other:?}"
                    )))
                }
            }
        }

        // Send a distinct payload on each; remember which conn expects which.
        let mut expected: HashMap<ConnId, Vec<u8>> = HashMap::new();
        for (i, &conn) in conns.iter().enumerate() {
            let payload = format!("fan-{i}").into_bytes();
            client.send(conn, frame(&payload))?;
            expected.insert(conn, payload);
        }

        // Collect one reply per connection; assert each maps to its conn.
        let mut seen = 0;
        while seen < N {
            match client.next_event()? {
                Some(Event::Reply { conn, body, .. }) => {
                    let want = expected
                        .get(&conn)
                        .expect("reply for an unknown connection");
                    assert_eq!(
                        &body[..],
                        &want[..],
                        "reply body maps to its connection"
                    );
                    seen += 1;
                }
                other => {
                    return Err(io::Error::other(format!(
                        "expected Reply, got {other:?}"
                    )))
                }
            }
        }
        for &conn in &conns {
            client.close_now(conn);
        }
        Ok(())
    });
}

#[test]
fn tcp_response_timeout() {
    // The server answers with a bare length prefix (a body it never sends),
    // leaving the client mid-reply; its `response_timeout` (the core request
    // clock) fires and closes the connection with `RequestTimeout`.
    with_server(stalled_reply, |v4| {
        let cfg = ClientConfig {
            response_timeout: Some(Duration::from_millis(300)),
            ..ClientConfig::default()
        };
        let mut client = Client::new(cfg, client_framer()).map_err(to_io)?;
        let conn =
            client.connect(ServerAddr::Tcp(v4), ConnectOpts::default())?;
        client.send(conn, frame(b"trigger"))?;

        match client.next_event()? {
            Some(Event::Closed { conn: c, reason }) => {
                assert_eq!(c, conn);
                assert_eq!(
                    reason,
                    CloseReason::RequestTimeout,
                    "expected RequestTimeout, got {reason:?}"
                );
            }
            other => {
                return Err(io::Error::other(format!(
                    "expected Closed(RequestTimeout), got {other:?}"
                )))
            }
        }
        Ok(())
    });
}

#[test]
fn tcp_idle_timeout() {
    // Connect and send nothing: the connection is parked on an idle reply recv
    // that carries the idle clock, so it is reaped after the idle window.
    with_server(echo, |v4| {
        let cfg = ClientConfig {
            idle_timeout: Some(Duration::from_millis(250)),
            ..ClientConfig::default()
        };
        let mut client = Client::new(cfg, client_framer()).map_err(to_io)?;
        let conn =
            client.connect(ServerAddr::Tcp(v4), ConnectOpts::default())?;

        match client.next_event()? {
            Some(Event::Closed { conn: c, reason }) => {
                assert_eq!(c, conn);
                assert_eq!(
                    reason,
                    CloseReason::IdleTimeout,
                    "expected IdleTimeout, got {reason:?}"
                );
            }
            other => {
                return Err(io::Error::other(format!(
                    "expected Closed(IdleTimeout), got {other:?}"
                )))
            }
        }
        assert!(!client.is_open(conn), "the idle connection was reaped");
        Ok(())
    });
}

#[test]
fn tcp_body_placement() {
    // A reply body comfortably over the 64 KiB placement threshold is read into
    // its own allocation and moved out zero-copy; assert it comes back intact.
    with_server(echo, |v4| {
        let mut client = Client::new(ClientConfig::default(), client_framer())
            .map_err(to_io)?;
        let conn =
            client.connect(ServerAddr::Tcp(v4), ConnectOpts::default())?;

        let payload: Vec<u8> =
            (0..128 * 1024).map(|i| (i % 251) as u8).collect();
        let body = client.request(conn, frame(&payload))?;
        assert_eq!(body.len(), payload.len(), "placed body length");
        assert_eq!(&body[..], &payload[..], "placed body is intact");

        client.close_now(conn);
        Ok(())
    });
}

#[test]
fn tcp_next_event_timeout() {
    // A bounded wait on an idle-but-open connection (no idle_timeout): the
    // deadline fires, `next_event_timeout` returns None, and the connection is
    // left open — repeatable, so the deadline is fully reaped each call.
    with_server(echo, |v4| {
        let mut client = Client::new(ClientConfig::default(), client_framer())
            .map_err(to_io)?;
        let conn =
            client.connect(ServerAddr::Tcp(v4), ConnectOpts::default())?;

        let ev = client.next_event_timeout(Duration::from_millis(200))?;
        assert!(ev.is_none(), "expected no event within the window: {ev:?}");
        assert!(
            client.is_open(conn),
            "connection stays open after a bounded wait times out"
        );
        // A second bounded wait still finds nothing and still leaves it open
        // (the first call's deadline did not leak into this one).
        let ev = client.next_event_timeout(Duration::from_millis(80))?;
        assert!(ev.is_none(), "expected no event on the second wait: {ev:?}");
        assert!(client.is_open(conn), "still open after the second wait");

        client.close_now(conn);
        Ok(())
    });
}

#[test]
fn tcp_stale_connid() {
    // A ConnId retained past its connection's close is inert: operations return
    // NotConnected / None, and close/close_now are no-ops (never a panic).
    with_server(echo, |v4| {
        let mut client = Client::new(ClientConfig::default(), client_framer())
            .map_err(to_io)?;
        let conn =
            client.connect(ServerAddr::Tcp(v4), ConnectOpts::default())?;

        // Close and drive to the Closed event so the slot is reclaimed (its
        // generation bumped) and the ConnId goes stale.
        client.close(conn);
        match client.next_event()? {
            Some(Event::Closed { conn: c, .. }) => assert_eq!(c, conn),
            None => {}
            Some(other) => {
                return Err(io::Error::other(format!(
                    "unexpected event: {other:?}"
                )))
            }
        }

        assert!(!client.is_open(conn), "a stale conn is not open");
        assert!(
            client.conn_state(conn).is_none(),
            "no state for a stale conn"
        );
        let e = client
            .send(conn, frame(b"x"))
            .expect_err("send on a stale conn fails");
        assert_eq!(e.kind(), io::ErrorKind::NotConnected);
        let e = client
            .request(conn, frame(b"x"))
            .expect_err("request on a stale conn fails");
        assert_eq!(e.kind(), io::ErrorKind::NotConnected);
        // Graceful no-ops (must not panic).
        client.close(conn);
        client.close_now(conn);
        Ok(())
    });
}

#[test]
fn tcp_send_timeout() {
    // A raw TCP server that accepts but never reads: the client's large send
    // fills the socket buffers and then stalls, so `send_timeout` evicts the
    // connection with `SendTimeout`. Built on a raw socket (not `net::server`,
    // which always drains its peer) with a payload far larger than any
    // autotuned buffer, so the stall is reliable.
    let mut client = match Client::new(
        ClientConfig {
            send_timeout: Some(Duration::from_millis(500)),
            max_send_backlog: 64 * 1024 * 1024,
            ..ClientConfig::default()
        },
        client_framer(),
    ) {
        Ok(c) => c,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("client new: {e}"),
    };

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let SocketAddr::V4(v4) = listener.local_addr().unwrap() else {
        unreachable!("bound v4");
    };
    let server = thread::spawn(move || {
        // Accept one connection and hold it open without reading a byte, long
        // enough for the client's send_timeout to fire.
        if let Ok((stream, _)) = listener.accept() {
            thread::sleep(Duration::from_secs(2));
            drop(stream);
        }
        drop(listener);
    });

    let conn = client
        .connect(ServerAddr::Tcp(v4), ConnectOpts::default())
        .expect("connect to the raw server");
    // 16 MiB dwarfs any autotuned send/recv buffer, so the send cannot drain to
    // a peer that never reads.
    let payload = vec![0u8; 16 * 1024 * 1024];
    client.send(conn, frame(&payload)).expect("send stages");

    match client.next_event().expect("next_event") {
        Some(Event::Closed { conn: c, reason }) => {
            assert_eq!(c, conn);
            assert_eq!(
                reason,
                CloseReason::SendTimeout,
                "expected SendTimeout, got {reason:?}"
            );
        }
        other => panic!("expected Closed(SendTimeout), got {other:?}"),
    }
    server.join().ok();
}

// ---- zero-copy body splice ------------------------------------------------

/// A client reply framer that diverts every reply body straight to the sink fd
/// stashed in `U`: read the 4-byte BE length prefix (exact `Need`, so no body
/// byte is over-read into the buffer), then splice `len` body bytes to the sink
/// via `Framing::SpliceBody`. `U` is the sink fd (a pipe write end).
fn splice_framer() -> impl FnMut(&[u8], &mut RawFd) -> Framing {
    |buf: &[u8], sink: &mut RawFd| {
        if buf.len() < 4 {
            return Framing::Need(4 - buf.len());
        }
        let n = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        Framing::SpliceBody {
            header_len: 4,
            body_len: n,
            fd: *sink,
        }
    }
}

#[test]
fn tcp_splice_body() {
    // A large reply body splices straight from the socket to a blocking pipe
    // write end (stashed in `U`) — zero-copy, never buffered — surfacing as
    // `Event::Splice{body_len}`; a reader thread drains exactly that many bytes
    // off the pipe read end and checks them intact.
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: `pipe(2)` fills {read, write}.
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe");
    let (pipe_rd, pipe_wr) = (fds[0], fds[1]);

    // Several times a pipe's 64 KiB capacity, so the splice completes in
    // multiple partial steps as the reader drains (end-to-end backpressure).
    const BODY: usize = 256 * 1024;
    let payload: Vec<u8> = (0..BODY).map(|i| (i % 251) as u8).collect();
    let expected = payload.clone();

    // Reader thread: drain exactly BODY bytes off the pipe read end.
    let reader = thread::spawn(move || {
        let mut got = vec![0u8; BODY];
        let mut off = 0;
        while off < BODY {
            // SAFETY: read into `got[off..]`, within bounds.
            let n = unsafe {
                libc::read(
                    pipe_rd,
                    got.as_mut_ptr().add(off).cast(),
                    (BODY - off) as libc::size_t,
                )
            };
            assert!(n > 0, "pipe read returned {n}");
            off += n as usize;
        }
        // SAFETY: done with the read end.
        unsafe { libc::close(pipe_rd) };
        assert_eq!(got, expected, "spliced body mismatch");
    });

    with_server(echo, move |v4| {
        let mut client = Client::new(ClientConfig::default(), splice_framer())
            .map_err(to_io)?;
        // The sink fd rides in `U`; the framer reads it from there.
        let conn = client.connect_with_state(
            ServerAddr::Tcp(v4),
            ConnectOpts::default(),
            pipe_wr,
        )?;
        // Send a request whose echoed reply body is spliced to the pipe.
        let id = client.send(conn, frame(&payload))?;
        // Drive the ring to completion; the reader drains the pipe concurrently.
        match client.next_event()? {
            Some(Event::Splice {
                conn: c,
                id: rid,
                header,
                body_len,
            }) => {
                assert_eq!(c, conn, "splice on the wrong connection");
                assert_eq!(rid, id, "splice correlated to the sent request");
                assert_eq!(header.len(), 4, "4-byte length prefix header");
                assert_eq!(body_len, BODY, "spliced body length");
            }
            other => {
                return Err(io::Error::other(format!(
                    "expected Splice, got {other:?}"
                )))
            }
        }
        client.close_now(conn);
        Ok(())
    });
    reader.join().expect("reader join");
    // SAFETY: closing the test-owned write end (the client only borrowed it).
    unsafe { libc::close(pipe_wr) };
}

#[test]
fn tcp_splice_bad_fd() {
    // A NON-blocking sink fd is a consumer bug: the framer's `SpliceBody` is
    // rejected before the socket is read (else a full non-blocking pipe would
    // spin the readiness poll), closing the connection with `SpliceBadFd`.
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: `pipe(2)` fills {read, write}.
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe");
    let (pipe_rd, pipe_wr) = (fds[0], fds[1]);
    // SAFETY: make the write end non-blocking — the rejected case.
    unsafe {
        let fl = libc::fcntl(pipe_wr, libc::F_GETFL);
        libc::fcntl(pipe_wr, libc::F_SETFL, fl | libc::O_NONBLOCK);
    }

    with_server(echo, move |v4| {
        let mut client = Client::new(ClientConfig::default(), splice_framer())
            .map_err(to_io)?;
        let conn = client.connect_with_state(
            ServerAddr::Tcp(v4),
            ConnectOpts::default(),
            pipe_wr,
        )?;
        client.send(conn, frame(b"trigger"))?;
        match client.next_event()? {
            Some(Event::Closed { conn: c, reason }) => {
                assert_eq!(c, conn);
                assert_eq!(
                    reason,
                    CloseReason::SpliceBadFd,
                    "expected SpliceBadFd, got {reason:?}"
                );
            }
            other => {
                return Err(io::Error::other(format!(
                    "expected Closed(SpliceBadFd), got {other:?}"
                )))
            }
        }
        Ok(())
    });
    // SAFETY: closing the test-owned pipe fds.
    unsafe {
        libc::close(pipe_rd);
        libc::close(pipe_wr);
    }
}

// ---- kernel TLS (kTLS) connect --------------------------------------------
//
// A real end-to-end TLS handshake around the client's kernel-TLS transport:
// the server runs `SSL_accept` in its handshake worker, the client runs
// `SSL_connect` in its own — exactly the split a real consumer implements. The
// library brings no TLS crate; these tests use OpenSSL as a dev-dependency.
// Skips when the kernel lacks the `tls` ULP (or `FIXED_FD_INSTALL`); force on a
// known-good host with `TRUENAS_ROS_REQUIRE_KTLS`.

use foreign_types::ForeignType; // Ssl::as_ptr for the raw BIO/SSL_connect path
use openssl::ssl::{
    Ssl, SslAcceptor, SslContext, SslMethod, SslOptions, SslVerifyMode,
};

const SSL_OP_ENABLE_KTLS: u64 = 1 << 3; // SSL_OP_BIT(3); no named crate const
const BIO_NOCLOSE: libc::c_int = 0;
const SOL_TLS: libc::c_int = 282;
const TLS_TX: libc::c_int = 1;
const TLS_RX: libc::c_int = 2;

/// True when the `kTLS ... TLS ULP` server-bind validation fires — the kernel
/// lacks `CONFIG_TLS`. Force the test on known-good hosts with
/// `TRUENAS_ROS_REQUIRE_KTLS`.
fn ktls_unsupported(e: &Error) -> bool {
    let unsupported =
        matches!(e, Error::Validation(m) if m.contains("kernel TLS ULP"));
    if unsupported {
        assert!(
            std::env::var_os("TRUENAS_ROS_REQUIRE_KTLS").is_none(),
            "TRUENAS_ROS_REQUIRE_KTLS set but the kernel lacks the tls ULP: {e}"
        );
    }
    unsupported
}

/// True when a `tls` connect fails because this kernel can't furnish the fd
/// (`FIXED_FD_INSTALL`) or run kTLS (the ULP) — the client-side skip for the
/// raw-listener kTLS tests (the echo test skips at the server's bind instead).
fn ktls_connect_unsupported(e: &io::Error) -> bool {
    let unsupported = e.kind() == io::ErrorKind::Unsupported;
    if unsupported {
        assert!(
            std::env::var_os("TRUENAS_ROS_REQUIRE_KTLS").is_none(),
            "TRUENAS_ROS_REQUIRE_KTLS set but kTLS connect unsupported: {e}"
        );
    }
    unsupported
}

/// A throwaway self-signed cert + PKCS#8 key (PEM) for the test server.
fn self_signed() -> (Vec<u8>, Vec<u8>) {
    use openssl::asn1::Asn1Time;
    use openssl::hash::MessageDigest;
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
    use openssl::x509::{X509NameBuilder, X509};
    let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "localhost").unwrap();
    let name = name.build();
    let mut b = X509::builder().unwrap();
    b.set_version(2).unwrap();
    b.set_subject_name(&name).unwrap();
    b.set_issuer_name(&name).unwrap();
    b.set_pubkey(&key).unwrap();
    b.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    b.set_not_after(&Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    b.sign(&key, MessageDigest::sha256()).unwrap();
    (
        b.build().to_pem().unwrap(),
        key.private_key_to_pem_pkcs8().unwrap(),
    )
}

/// A kTLS-enabled OpenSSL server acceptor: `SSL_OP_ENABLE_KTLS` + no session
/// tickets (no post-handshake server write to perturb the installed sequence).
fn ktls_acceptor(cert_pem: &[u8], key_pem: &[u8]) -> SslAcceptor {
    use openssl::pkey::PKey;
    use openssl::x509::X509;
    let mut b = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
    b.set_private_key(&PKey::private_key_from_pem(key_pem).unwrap())
        .unwrap();
    b.set_certificate(&X509::from_pem(cert_pem).unwrap())
        .unwrap();
    b.check_private_key().unwrap();
    b.set_options(SslOptions::from_bits_retain(SSL_OP_ENABLE_KTLS));
    b.set_num_tickets(0).unwrap();
    b.build()
}

/// The server's handshake worker: run the blocking server TLS handshake on the
/// furnished fd over a socket BIO (so OpenSSL installs kTLS on the socket),
/// confirm kTLS engaged both directions, then close the furnished fd (the pool
/// descriptor keeps the kTLS socket).
fn ktls_server_handshake(
    fd: RawFd,
    acceptor: &SslAcceptor,
) -> Result<(), String> {
    // This worker owns the furnished fd: EVERY return path must close it (the
    // set_tls_handshake contract), or each failed handshake leaks a process fd.
    struct FdCloser(RawFd);
    impl Drop for FdCloser {
        fn drop(&mut self) {
            // SAFETY: closing the furnished fd this guard owns.
            unsafe { libc::close(self.0) };
        }
    }
    let _fd_owner = FdCloser(fd);
    // SSL_accept wants a blocking socket; io_uring recv/send ignore O_NONBLOCK.
    // SAFETY: fcntl on a live fd.
    unsafe {
        let fl = libc::fcntl(fd, libc::F_GETFL);
        libc::fcntl(fd, libc::F_SETFL, fl & !libc::O_NONBLOCK);
    }
    let ssl = Ssl::new(acceptor.context()).map_err(|e| e.to_string())?;
    // SAFETY: a BIO_NOCLOSE socket BIO over `fd`; SSL owns the BIO (freed on
    // drop), and `fd` outlives `ssl` here.
    let rc = unsafe {
        let bio = openssl_sys::BIO_new_socket(fd, BIO_NOCLOSE);
        if bio.is_null() {
            return Err("BIO_new_socket".into());
        }
        openssl_sys::SSL_set_bio(ssl.as_ptr(), bio, bio);
        openssl_sys::SSL_accept(ssl.as_ptr())
    };
    if rc != 1 {
        return Err(format!("SSL_accept returned {rc}"));
    }
    confirm_ktls(fd)?;
    drop(ssl); // BIO_NOCLOSE → fd not closed; kTLS stays on the socket
    Ok(()) // _fd_owner closes the furnished fd
}

/// A kTLS-enabled OpenSSL client context: `SSL_OP_ENABLE_KTLS` + no cert
/// verification (the server cert is self-signed).
fn ktls_client_ctx() -> SslContext {
    let mut b = SslContext::builder(SslMethod::tls()).unwrap();
    b.set_verify(SslVerifyMode::NONE);
    b.set_options(SslOptions::from_bits_retain(SSL_OP_ENABLE_KTLS));
    b.build()
}

/// The client's handshake worker: run the blocking client TLS handshake
/// (`SSL_connect`) on the furnished fd over a socket BIO (so OpenSSL installs
/// kTLS on the socket), confirm kTLS engaged both directions, then close the
/// furnished fd. The mirror of `ktls_server_handshake`, `SSL_connect` for
/// `SSL_accept` — exactly what a `Client::set_tls_handshake` worker does.
fn ktls_client_handshake(fd: RawFd, ctx: &SslContext) -> Result<(), String> {
    struct FdCloser(RawFd);
    impl Drop for FdCloser {
        fn drop(&mut self) {
            // SAFETY: closing the furnished fd this guard owns.
            unsafe { libc::close(self.0) };
        }
    }
    let _fd_owner = FdCloser(fd);
    // SSL_connect wants a blocking socket; io_uring recv/send ignore O_NONBLOCK.
    // SAFETY: fcntl on a live fd.
    unsafe {
        let fl = libc::fcntl(fd, libc::F_GETFL);
        libc::fcntl(fd, libc::F_SETFL, fl & !libc::O_NONBLOCK);
    }
    let mut ssl = Ssl::new(ctx).map_err(|e| e.to_string())?;
    ssl.set_connect_state();
    // SAFETY: a BIO_NOCLOSE socket BIO over `fd`; SSL owns the BIO (freed on
    // drop), and `fd` outlives `ssl` here.
    let rc = unsafe {
        let bio = openssl_sys::BIO_new_socket(fd, BIO_NOCLOSE);
        if bio.is_null() {
            return Err("BIO_new_socket".into());
        }
        openssl_sys::SSL_set_bio(ssl.as_ptr(), bio, bio);
        openssl_sys::SSL_connect(ssl.as_ptr())
    };
    if rc != 1 {
        return Err(format!("SSL_connect returned {rc}"));
    }
    confirm_ktls(fd)?;
    drop(ssl); // BIO_NOCLOSE → fd not closed; kTLS stays on the socket
    Ok(()) // _fd_owner closes the furnished fd
}

/// Confirm kTLS engaged on `fd` for both directions (the `SOL_TLS` TX/RX
/// getsockopts succeed only once the ULP is installed each way).
fn confirm_ktls(fd: RawFd) -> Result<(), String> {
    for (dir, label) in [(TLS_TX, "TX"), (TLS_RX, "RX")] {
        let mut buf = [0u8; 4];
        let mut len = buf.len() as libc::socklen_t;
        // SAFETY: getsockopt writes up to `len` bytes into `buf`.
        let r = unsafe {
            libc::getsockopt(
                fd,
                SOL_TLS,
                dir,
                buf.as_mut_ptr().cast(),
                &mut len,
            )
        };
        if r != 0 {
            return Err(format!("kTLS not engaged for {label}"));
        }
    }
    Ok(())
}

/// Bind a kTLS `net::server` echo server whose handshake worker runs
/// `SSL_accept`, run `client` on a spawned thread against its resolved address,
/// and propagate the client's result. The kTLS mirror of [`with_server`]; skips
/// cleanly when io_uring or the kernel TLS ULP is unavailable.
fn with_ktls_server<ClientBody>(client: ClientBody)
where
    ClientBody: FnOnce(SocketAddrV4) -> io::Result<()> + Send + 'static,
{
    let (cert, key) = self_signed();
    let acceptor = Arc::new(ktls_acceptor(&cert, &key));
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let proto = length_prefixed(
        PrefixWidth::U32,
        Endian::Big,
        false,
        |_h: &[u8], body: &[u8], _p: &ClientAddr| Some(frame(body)),
    );
    let mut server = match Server::bind([Listen::tls(addr)], proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) || ktls_unsupported(&e) => return,
        Err(e) => panic!("bind: {e}"),
    };
    server.set_tls_handshake(move |fd, _inc, deferral| {
        let acceptor = Arc::clone(&acceptor);
        thread::spawn(move || match ktls_server_handshake(fd, &acceptor) {
            Ok(()) => deferral.ready(()),
            Err(_) => deferral.reject(),
        });
    });
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();
    let handle = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone()); // shuts down even on panic
        let r = client(v4);
        stop.shutdown();
        r
    });
    server.serve_forever().expect("serve_forever");
    handle
        .join()
        .expect("client thread join")
        .expect("client body");
}

/// Build a `Client` with a `set_tls_handshake` worker that runs `SSL_connect`
/// (the mirror of the server's `SSL_accept` worker), over the given framer.
fn ktls_client<U, F>(framer: F) -> io::Result<Client<U, F>>
where
    F: FnMut(&[u8], &mut U) -> Framing,
{
    let ctx = Arc::new(ktls_client_ctx());
    let mut client =
        Client::new(ClientConfig::default(), framer).map_err(to_io)?;
    client.set_tls_handshake(move |fd, _c, deferral| {
        let ctx = Arc::clone(&ctx);
        thread::spawn(move || match ktls_client_handshake(fd, &ctx) {
            Ok(()) => deferral.ready(),
            Err(_) => deferral.reject(),
        });
    });
    Ok(client)
}

#[test]
fn ktls_echo_roundtrip() {
    // End-to-end: a kTLS listener, both sides' OpenSSL handshake workers
    // (`SSL_accept` server-side, `SSL_connect` in the client's worker), and a
    // framed echo round-trip over the kernel-TLS transport (each side sees
    // plaintext; the kernel encrypts/decrypts).
    with_ktls_server(|v4| {
        let mut client = ktls_client(client_framer())?;
        // A blocking connect resolves only once the kTLS handshake completes.
        let conn = client
            .connect(ServerAddr::Tcp(v4), ConnectOpts::default().tls())?;
        for msg in [b"tls-hello".as_slice(), b"second", b"third-and-final"] {
            let body = client.request(conn, frame(msg))?;
            assert_eq!(&body[..], msg, "kTLS echo mismatch");
        }
        // A larger payload spanning multiple TLS records still frames.
        let big = vec![0x5au8; 40 * 1024];
        let body = client.request(conn, frame(&big))?;
        assert_eq!(&body[..], &big[..], "kTLS large echo mismatch");
        client.close_now(conn);
        Ok(())
    });
}

#[test]
fn ktls_rejected_handshake() {
    // The client's handshake worker calls `reject()` → `Event::ConnectFailed`.
    // A raw TCP peer suffices (the reject is client-local): the TCP connect
    // completes, the fd is furnished, and the worker rejects.
    let mut client = match Client::new(ClientConfig::default(), client_framer())
    {
        Ok(c) => c,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("client new: {e}"),
    };
    client.set_tls_handshake(|fd, _c, deferral| {
        thread::spawn(move || {
            // SAFETY: close the furnished fd we won't use, then reject.
            unsafe { libc::close(fd) };
            deferral.reject();
        });
    });

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let SocketAddr::V4(v4) = listener.local_addr().unwrap() else {
        unreachable!("bound v4");
    };
    let server = thread::spawn(move || {
        if let Ok((stream, _)) = listener.accept() {
            thread::sleep(Duration::from_millis(500));
            drop(stream);
        }
        drop(listener);
    });

    let conn = match client
        .connect_start(ServerAddr::Tcp(v4), ConnectOpts::default().tls())
    {
        Ok(c) => c,
        Err(e) if ktls_connect_unsupported(&e) => {
            server.join().ok();
            return;
        }
        Err(e) => panic!("connect_start: {e}"),
    };
    match client.next_event().expect("next_event") {
        Some(Event::ConnectFailed { conn: c, err }) => {
            assert_eq!(c, conn, "ConnectFailed for the wrong connection");
            assert_eq!(
                err,
                Errno::ECONNABORTED,
                "a rejected handshake fails with ECONNABORTED"
            );
        }
        other => panic!("expected ConnectFailed, got {other:?}"),
    }
    assert!(!client.is_open(conn), "a rejected connect is not open");
    server.join().ok();
}

#[test]
fn ktls_handshake_timeout() {
    // The worker never calls back (it holds the deferral): the client's
    // `tls_handshake_timeout` fires → `ConnectFailed{ETIMEDOUT}`, and the parked
    // slot is reclaimed (a later `next_event` finds no work left).
    let cfg = ClientConfig {
        tls_handshake_timeout: Some(Duration::from_millis(250)),
        ..ClientConfig::default()
    };
    let mut client = match Client::new(cfg, client_framer()) {
        Ok(c) => c,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("client new: {e}"),
    };
    // Buffer the deferral (never resolving → no reject-shed) and close the fd;
    // only the timeout can reclaim the parked slot. Released when keep_rx drops.
    let (keep_tx, keep_rx) = std::sync::mpsc::channel();
    client.set_tls_handshake(move |fd, _c, deferral| {
        // SAFETY: close the furnished fd this worker won't use.
        unsafe { libc::close(fd) };
        let _ = keep_tx.send(deferral);
    });

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let SocketAddr::V4(v4) = listener.local_addr().unwrap() else {
        unreachable!("bound v4");
    };
    let server = thread::spawn(move || {
        if let Ok((stream, _)) = listener.accept() {
            thread::sleep(Duration::from_secs(2));
            drop(stream);
        }
        drop(listener);
    });

    let conn = match client
        .connect_start(ServerAddr::Tcp(v4), ConnectOpts::default().tls())
    {
        Ok(c) => c,
        Err(e) if ktls_connect_unsupported(&e) => {
            server.join().ok();
            return;
        }
        Err(e) => panic!("connect_start: {e}"),
    };
    let t0 = Instant::now();
    match client.next_event().expect("next_event") {
        Some(Event::ConnectFailed { conn: c, err }) => {
            assert_eq!(c, conn);
            assert_eq!(
                err,
                Errno::ETIMEDOUT,
                "a stalled handshake times out with ETIMEDOUT"
            );
        }
        other => panic!("expected ConnectFailed(ETIMEDOUT), got {other:?}"),
    }
    assert!(
        t0.elapsed() < Duration::from_secs(2),
        "handshake timeout fired late: {:?}",
        t0.elapsed()
    );
    assert!(!client.is_open(conn), "the parked slot was reclaimed");
    // With the parked handshake shed and no connections, the next event is
    // `None` — the leftover armed wake never wedges it.
    assert!(
        client.next_event().expect("drain").is_none(),
        "no work left after the timeout shed"
    );
    drop(keep_rx); // release the held (now stale) deferral
    server.join().ok();
}

#[test]
fn ktls_splice_body() {
    // A reply body splices zero-copy off a kTLS socket, in the clear: the kernel
    // routes the splice through `tls_sw_splice_read`, which decrypts. Same shape
    // as `tcp_splice_body`, but over the kernel-TLS transport.
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: `pipe(2)` fills {read, write}.
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe");
    let (pipe_rd, pipe_wr) = (fds[0], fds[1]);

    // Not a multiple of the 16 KiB TLS record size, and several pipe capacities.
    const BODY: usize = 200_000;
    let payload: Vec<u8> = (0..BODY).map(|i| (i % 251) as u8).collect();
    let expected = payload.clone();

    let reader = thread::spawn(move || {
        // Non-blocking + deadline-bounded so a kTLS *skip* (the client body never
        // runs, nothing is ever spliced) returns instead of blocking forever.
        // SAFETY: make the read end non-blocking so the deadline loop works.
        unsafe {
            let fl = libc::fcntl(pipe_rd, libc::F_GETFL);
            libc::fcntl(pipe_rd, libc::F_SETFL, fl | libc::O_NONBLOCK);
        }
        let mut got = vec![0u8; BODY];
        let mut off = 0;
        let deadline = Instant::now() + Duration::from_secs(10);
        while off < BODY && Instant::now() < deadline {
            // SAFETY: read into `got[off..]`, within bounds.
            let n = unsafe {
                libc::read(
                    pipe_rd,
                    got.as_mut_ptr().add(off).cast(),
                    (BODY - off) as libc::size_t,
                )
            };
            if n > 0 {
                off += n as usize;
            } else {
                thread::sleep(Duration::from_millis(5));
            }
        }
        // SAFETY: done with the read end.
        unsafe { libc::close(pipe_rd) };
        (off, got)
    });

    // Skip is decided at the server bind inside `with_ktls_server`; on a skip the
    // client body never runs, so drain the reader (it will time out) below.
    with_ktls_server(move |v4| {
        let mut client = ktls_client(splice_framer())?;
        let conn = client.connect_with_state(
            ServerAddr::Tcp(v4),
            ConnectOpts::default().tls(),
            pipe_wr,
        )?;
        let id = client.send(conn, frame(&payload))?;
        match client.next_event()? {
            Some(Event::Splice {
                conn: c,
                id: rid,
                body_len,
                ..
            }) => {
                assert_eq!(c, conn);
                assert_eq!(rid, id);
                assert_eq!(body_len, BODY, "kTLS spliced body length");
            }
            other => {
                return Err(io::Error::other(format!(
                    "expected Splice over kTLS, got {other:?}"
                )))
            }
        }
        client.close_now(conn);
        Ok(())
    });

    let (off, got) = reader.join().expect("reader join");
    // On a kTLS skip the client body never ran, so nothing was spliced; only
    // assert the transfer on a real run (off > 0 means the splice happened).
    if off > 0 {
        assert_eq!(off, BODY, "kTLS splice moved {off} of {BODY} body bytes");
        assert_eq!(got, expected, "kTLS spliced body content mismatch");
    }
    // SAFETY: closing the test-owned write end (read end closed by the reader).
    unsafe { libc::close(pipe_wr) };
}
