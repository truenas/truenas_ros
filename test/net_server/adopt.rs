use super::*;
use std::net::{TcpListener, UdpSocket};
use std::os::fd::OwnedFd;
use truenas_ros::net::server::{Lent, PushPart};

/// A server with no listeners, echoing like `noop_protocol`.
#[allow(clippy::type_complexity)]
fn bare_server() -> Option<
    Server<
        (),
        impl FnMut(Incoming<'_>) -> Option<()>,
        impl FnMut(&[u8], &mut ()) -> Framing,
        impl FnMut(Request<'_, ()>) -> Response,
    >,
> {
    bare_server_with(ServerConfig::default())
}

/// As [`bare_server`], with `cfg`.
#[allow(clippy::type_complexity)]
pub(super) fn bare_server_with(
    cfg: ServerConfig,
) -> Option<
    Server<
        (),
        impl FnMut(Incoming<'_>) -> Option<()>,
        impl FnMut(&[u8], &mut ()) -> Framing,
        impl FnMut(Request<'_, ()>) -> Response,
    >,
> {
    match Server::with_config(Vec::<ServerAddr>::new(), cfg, noop_protocol()) {
        Ok(s) => Some(s),
        Err(e) if should_skip(&e) => None,
        Err(e) => panic!("with_config: {e}"),
    }
}

/// A connected TCP pair whose server end was accepted outside any ring, like a socket another process passes on.
pub(super) fn accepted_elsewhere() -> (TcpStream, OwnedFd) {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let client = TcpStream::connect(l.local_addr().expect("local addr")).expect("connect");
    let (server_end, _) = l.accept().expect("accept");
    (client, OwnedFd::from(server_end))
}

#[test]
fn adopt_serves_a_socket_accepted_elsewhere() {
    let Some(mut server) = bare_server() else {
        return;
    };
    let closes = close_reason_channel(&mut server);
    let (client, sock) = accepted_elsewhere();
    server.adopt(sock, ()).expect("adopt");
    let stop = server.shutdown_handle();
    let worker = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone());
        let echoes = framed_roundtrips(client, &[b"one", b"two"]);
        // The close hook reports the adopted connection's end like an accepted one's.
        let reason = closes.recv_timeout(Duration::from_secs(5));
        stop.shutdown();
        (echoes, reason)
    });
    server.serve_forever().expect("serve_forever");
    let (echoes, reason) = worker.join().expect("thread join");
    assert_eq!(echoes.expect("client io"), vec![b"one".to_vec(), b"two".to_vec()]);
    assert!(matches!(reason, Ok(CloseReason::PeerClosed)), "close reason {reason:?}");
}

#[test]
fn adopt_pushes_before_the_first_request() {
    let Some(mut server) = bare_server() else {
        return;
    };
    let (mut client, sock) = accepted_elsewhere();
    let push = server.adopt(sock, ()).expect("adopt");
    push.push(echo_frame(b"hello"));
    let stop = server.shutdown_handle();
    let worker = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone());
        let r = (|| -> io::Result<(Vec<u8>, Vec<u8>)> {
            let first = recv_framed(&mut client)?;
            send_framed(&mut client, b"ping")?;
            Ok((first, recv_framed(&mut client)?))
        })();
        stop.shutdown();
        r
    });
    server.serve_forever().expect("serve_forever");
    let (first, echo) = worker.join().expect("thread join").expect("client io");
    assert_eq!(first, b"hello");
    assert_eq!(echo, b"ping");
}

#[test]
fn adopt_serves_a_unix_socketpair() {
    let Some(mut server) = bare_server() else {
        return;
    };
    let (client, server_end) = UnixStream::pair().expect("socketpair");
    server.adopt(OwnedFd::from(server_end), ()).expect("adopt");
    let stop = server.shutdown_handle();
    let worker = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone());
        let r = framed_roundtrips(client, &[b"local"]);
        stop.shutdown();
        r
    });
    server.serve_forever().expect("serve_forever");
    assert_eq!(
        worker.join().expect("thread join").expect("client io"),
        vec![b"local".to_vec()]
    );
}

#[test]
fn adopt_is_refused_where_the_kernel_picks_slots() {
    // A listener's multishot accept takes slots behind the server's back, so adopting could reuse one of them.
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let mut server = match Server::bind([addr], noop_protocol()) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind: {e}"),
    };
    let (_client, sock) = accepted_elsewhere();
    match server.adopt(sock, ()) {
        Err(Error::Validation(m)) => assert!(m.contains("no listeners"), "{m}"),
        Err(e) => panic!("expected a validation error, got {e}"),
        Ok(_) => panic!("adopt on a server with a listener"),
    }
}

#[test]
fn adopt_refuses_what_is_not_a_connected_stream() {
    let Some(mut server) = bare_server() else {
        return;
    };
    let udp = OwnedFd::from(UdpSocket::bind("127.0.0.1:0").expect("udp bind"));
    assert!(matches!(server.adopt(udp, ()), Err(Error::Errno(Errno::EPROTOTYPE))));
    // SAFETY: a fresh socket; the OwnedFd owns it from here on.
    let raw = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    assert!(raw >= 0, "socket");
    // SAFETY: `raw` is a valid descriptor that nothing else owns.
    let unconnected = unsafe { OwnedFd::from_raw_fd(raw) };
    assert!(matches!(
        server.adopt(unconnected, ()),
        Err(Error::Errno(Errno::ENOTCONN))
    ));
    let file = OwnedFd::from(std::fs::File::open("/dev/null").expect("open"));
    assert!(matches!(server.adopt(file, ()), Err(Error::Errno(Errno::ENOTSOCK))));
    // The refusals leave the server able to adopt.
    let (client, sock) = accepted_elsewhere();
    server.adopt(sock, ()).expect("adopt after refusals");
    drop(client);
}

#[test]
fn adopt_reports_a_full_pool() {
    let cfg = ServerConfig {
        pool_size: 1,
        ..ServerConfig::default()
    };
    let mut server = match Server::with_config(Vec::<ServerAddr>::new(), cfg, noop_protocol()) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("with_config: {e}"),
    };
    let (_c1, s1) = accepted_elsewhere();
    server.adopt(s1, ()).expect("first adopt");
    let (_c2, s2) = accepted_elsewhere();
    assert!(matches!(server.adopt(s2, ()), Err(Error::Errno(Errno::ENFILE))));
}

/// A lent part whose `done` reports on a channel.
pub(super) fn lend(bytes: &[u8], done: std::sync::mpsc::Sender<()>) -> PushPart {
    // SAFETY: every caller keeps `bytes` alive and unchanged until `done` has reported.
    PushPart::Lent(unsafe {
        Lent::new(bytes.as_ptr(), bytes.len(), move || {
            let _ = done.send(());
        })
    })
}

#[test]
fn push_parts_send_lent_bytes_in_place_and_hand_them_back() {
    let Some(mut server) = bare_server() else {
        return;
    };
    let (mut client, sock) = accepted_elsewhere();
    let push = server.adopt(sock, ()).expect("adopt");
    // Large enough to take more than one send, and under the default send backlog.
    let payload: Vec<u8> = (0..4 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    push.push_parts(vec![
        PushPart::Owned(b"head".to_vec()),
        lend(&payload, done_tx),
        PushPart::Owned(b"tail".to_vec()),
    ]);
    let stop = server.shutdown_handle();
    let want = payload.len() + 8;
    let worker = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone());
        let mut got = vec![0u8; want];
        let r = client.read_exact(&mut got);
        // The ring hands the bytes back once their send completes.
        let done = done_rx.recv_timeout(Duration::from_secs(5));
        stop.shutdown();
        (r, got, done)
    });
    server.serve_forever().expect("serve_forever");
    let (r, got, done) = worker.join().expect("thread join");
    r.expect("client read");
    assert_eq!(&got[..4], b"head");
    assert!(
        got[4..want - 4] == payload[..],
        "the lent bytes arrive unchanged and in place"
    );
    assert_eq!(&got[want - 4..], b"tail");
    assert!(done.is_ok(), "done runs once the lent bytes are sent");
}

#[test]
fn push_parts_that_cannot_reach_the_ring_hand_the_bytes_back() {
    let Some(mut server) = bare_server() else {
        return;
    };
    let (_client, sock) = accepted_elsewhere();
    let push = server.adopt(sock, ()).expect("adopt");
    drop(server);
    let payload = vec![7u8; 4096];
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    push.push_parts(vec![lend(&payload, done_tx)]);
    assert!(
        done_rx.recv_timeout(Duration::from_secs(1)).is_ok(),
        "a push the server never takes runs done at once"
    );
}

#[test]
fn push_parts_finished_runs_in_its_turn_on_the_loop_thread() {
    let Some(mut server) = bare_server() else {
        return;
    };
    let (mut client, sock) = accepted_elsewhere();
    let push = server.adopt(sock, ()).expect("adopt");
    let loop_thread = thread::current().id();
    let (ran_tx, ran_rx) = std::sync::mpsc::channel();
    // A lent part that the step replaces: its bytes go back unsent.
    let payload = vec![b'b'; 300_000];
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    push.push_parts(vec![PushPart::Owned(b"first".to_vec())]);
    push.push_parts_finished(
        vec![PushPart::Owned(b"<".to_vec()), lend(&payload, done_tx)],
        Box::new(move |parts| {
            let _ = ran_tx.send(thread::current().id());
            let mut all: Vec<u8> = parts.iter().flat_map(|p| p.as_slice().to_vec()).collect();
            all.make_ascii_uppercase();
            *parts = vec![PushPart::Owned(all)];
            true
        }),
    );
    push.push_parts(vec![PushPart::Owned(b"last".to_vec())]);
    let stop = server.shutdown_handle();
    let want = 5 + 1 + payload.len() + 4;
    let worker = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone());
        let mut got = vec![0u8; want];
        let r = client.read_exact(&mut got);
        stop.shutdown();
        (r, got)
    });
    server.serve_forever().expect("serve_forever");
    let (r, got) = worker.join().expect("thread join");
    r.expect("client read");
    assert_eq!(&got[..6], b"first<", "the finished push keeps its place");
    assert!(got[6..want - 4].iter().all(|&b| b == b'B'), "the step's bytes go out");
    assert_eq!(&got[want - 4..], b"last");
    assert_eq!(
        ran_rx.recv().expect("step ran"),
        loop_thread,
        "the step runs on the loop thread"
    );
    assert!(
        done_rx.recv_timeout(Duration::from_secs(5)).is_ok(),
        "the replaced lent bytes go back"
    );
}

#[test]
fn push_parts_finished_that_fails_closes_the_connection() {
    let Some(mut server) = bare_server() else {
        return;
    };
    let closes = close_reason_channel(&mut server);
    let (mut client, sock) = accepted_elsewhere();
    let push = server.adopt(sock, ()).expect("adopt");
    push.push_parts_finished(vec![PushPart::Owned(b"never".to_vec())], Box::new(|_| false));
    let stop = server.shutdown_handle();
    let worker = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone());
        let mut got = Vec::new();
        let r = client.read_to_end(&mut got);
        let reason = closes.recv_timeout(Duration::from_secs(5));
        stop.shutdown();
        (r, got, reason)
    });
    server.serve_forever().expect("serve_forever");
    let (r, got, reason) = worker.join().expect("thread join");
    r.expect("client read");
    assert!(got.is_empty(), "the parts of a failed step are not sent");
    assert!(
        matches!(reason, Ok(CloseReason::WorkerClosed)),
        "close reason {reason:?}"
    );
}

/// A push whose step would run behind a final farewell is dropped with its step unrun, as a plain push behind one is
/// dropped. The farewell keeps the connection and its reason: the step must not close it out from under the flush.
#[test]
fn a_finished_push_behind_a_farewell_keeps_its_step_unrun() {
    finished_push_behind_a_farewell(true);
}

/// As above, with a step that would refuse its PDU and so close the connection before the farewell goes out.
#[test]
fn a_refusing_step_behind_a_farewell_keeps_the_farewell() {
    finished_push_behind_a_farewell(false);
}

/// A farewell, then a push whose step returns `takes`.
fn finished_push_behind_a_farewell(takes: bool) {
    use std::sync::atomic::{AtomicBool, Ordering as AOrd};

    let Some(mut server) = bare_server() else {
        return;
    };
    let closes = close_reason_channel(&mut server);
    let (mut client, sock) = accepted_elsewhere();
    let push = server.adopt(sock, ()).expect("adopt");

    let ran = Arc::new(AtomicBool::new(false));
    // Queued in this order, so the loop takes the farewell before the finished push.
    push.push(b"farewell".to_vec());
    push.close();
    let flag = Arc::clone(&ran);
    push.push_parts_finished(
        vec![PushPart::Owned(b"never".to_vec())],
        Box::new(move |_| {
            flag.store(true, AOrd::SeqCst);
            takes
        }),
    );

    let stop = server.shutdown_handle();
    let worker = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone());
        let mut got = Vec::new();
        let r = client.read_to_end(&mut got);
        let reason = closes.recv_timeout(Duration::from_secs(5));
        stop.shutdown();
        (r, got, reason)
    });
    server.serve_forever().expect("serve_forever");
    let (r, got, reason) = worker.join().expect("thread join");
    r.expect("client read");

    assert_eq!(got, b"farewell", "the farewell flushes whole");
    assert!(
        matches!(reason, Ok(CloseReason::PushClosed)),
        "close reason {reason:?}, not the farewell's"
    );
    assert!(
        !ran.load(AOrd::SeqCst),
        "the step of a push behind a final farewell ran on the loop"
    );
}

/// One PDU pushed in parts tallies one push, as one reply in segments tallies one reply.
#[test]
fn a_push_in_parts_tallies_one_push() {
    let Some(mut server) = bare_server() else {
        return;
    };
    let stats = server.stats_handle();
    let (mut client, sock) = accepted_elsewhere();
    let push = server.adopt(sock, ()).expect("adopt");
    push.push_parts(vec![
        PushPart::Owned(b"aaaa".to_vec()),
        PushPart::Owned(b"bbbb".to_vec()),
        PushPart::Owned(b"ccccc".to_vec()),
    ]);
    push.close();

    let stop = server.shutdown_handle();
    let worker = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone());
        let mut got = Vec::new();
        let r = client.read_to_end(&mut got);
        stop.shutdown();
        (r, got)
    });
    server.serve_forever().expect("serve_forever");
    let (r, got) = worker.join().expect("thread join");
    r.expect("client read");
    assert_eq!(got, b"aaaabbbbccccc", "the parts arrive as one PDU");
    assert_eq!(stats.snapshot().pushes, 1, "three parts are one pushed PDU");
}

/// A push for a connection that has gone hands its lent bytes back.
#[test]
fn push_parts_for_a_gone_connection_hand_the_bytes_back() {
    let Some(mut server) = bare_server() else {
        return;
    };
    let closes = close_reason_channel(&mut server);
    let (client, sock) = accepted_elsewhere();
    let push = server.adopt(sock, ()).expect("adopt");
    let payload = vec![7u8; 4096];
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let part = lend(&payload, done_tx);
    let stop = server.shutdown_handle();
    let worker = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone());
        // The server sees the client go and frees the slot before the push comes.
        drop(client);
        let reason = closes.recv_timeout(Duration::from_secs(5));
        push.push_parts(vec![part]);
        let done = done_rx.recv_timeout(Duration::from_secs(5));
        stop.shutdown();
        (reason, done)
    });
    server.serve_forever().expect("serve_forever");
    let (reason, done) = worker.join().expect("thread join");
    assert!(reason.is_ok(), "the server saw the client go: {reason:?}");
    assert!(done.is_ok(), "a push for a gone connection runs done");
    drop(payload);
}

/// A push that comes while the server drains hands its lent bytes back.
#[test]
fn push_parts_while_draining_hand_the_bytes_back() {
    let Some(mut server) = bare_server() else {
        return;
    };
    let closes = close_reason_channel(&mut server);
    // The client of `a` reads none of a push larger than its socket buffers, so `a` keeps the drain and the loop
    // going. `b` is idle, so it closes when the drain begins.
    let (client_a, sock_a) = accepted_elsewhere();
    let (client_b, sock_b) = accepted_elsewhere();
    let push_a = server.adopt(sock_a, ()).expect("adopt a");
    let _push_b = server.adopt(sock_b, ()).expect("adopt b");
    push_a.push(vec![0u8; 7 * 1024 * 1024]);
    let payload = vec![7u8; 4096];
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let part = lend(&payload, done_tx);
    let stop = server.shutdown_handle();
    let worker = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone());
        stop.shutdown_graceful(Duration::from_secs(10));
        // The close of `b` shows that the loop drains.
        let reason = closes.recv_timeout(Duration::from_secs(5));
        push_a.push_parts(vec![part]);
        let done = done_rx.recv_timeout(Duration::from_secs(5));
        drop(client_a);
        drop(client_b);
        stop.shutdown();
        (reason, done)
    });
    server.serve_forever().expect("serve_forever");
    let (reason, done) = worker.join().expect("thread join");
    assert!(
        matches!(reason, Ok(CloseReason::ShuttingDown)),
        "close reason {reason:?}"
    );
    assert!(done.is_ok(), "a push behind a drain runs done");
    drop(payload);
}

/// A push past the send backlog closes the connection, sends nothing of the push and hands its lent bytes back.
#[test]
fn push_parts_past_the_backlog_hand_the_bytes_back() {
    let cfg = ServerConfig {
        max_send_backlog: 1024,
        ..ServerConfig::default()
    };
    let Some(mut server) = bare_server_with(cfg) else {
        return;
    };
    let closes = close_reason_channel(&mut server);
    let (mut client, sock) = accepted_elsewhere();
    let push = server.adopt(sock, ()).expect("adopt");
    let payload = vec![7u8; 4096];
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    push.push_parts(vec![lend(&payload, done_tx)]);
    let stop = server.shutdown_handle();
    let worker = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone());
        let done = done_rx.recv_timeout(Duration::from_secs(5));
        let reason = closes.recv_timeout(Duration::from_secs(5));
        let mut got = Vec::new();
        let r = client.read_to_end(&mut got);
        stop.shutdown();
        (done, reason, r, got)
    });
    server.serve_forever().expect("serve_forever");
    let (done, reason, r, got) = worker.join().expect("thread join");
    assert!(done.is_ok(), "a push past the backlog runs done");
    assert!(
        matches!(reason, Ok(CloseReason::SendBacklog)),
        "close reason {reason:?}"
    );
    r.expect("client read");
    assert!(got.is_empty(), "nothing of the refused push goes out");
    drop(payload);
}

/// An empty part of a push is dropped, so a lent one hands its bytes back. The other parts go out as one PDU.
#[test]
fn push_parts_drop_an_empty_part_and_hand_its_bytes_back() {
    let Some(mut server) = bare_server() else {
        return;
    };
    let (mut client, sock) = accepted_elsewhere();
    let push = server.adopt(sock, ()).expect("adopt");
    let empty: [u8; 0] = [];
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    push.push_parts(vec![
        PushPart::Owned(b"head".to_vec()),
        lend(&empty, done_tx),
        PushPart::Owned(b"tail".to_vec()),
    ]);
    push.close();
    let stop = server.shutdown_handle();
    let worker = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone());
        let done = done_rx.recv_timeout(Duration::from_secs(5));
        let mut got = Vec::new();
        let r = client.read_to_end(&mut got);
        stop.shutdown();
        (done, r, got)
    });
    server.serve_forever().expect("serve_forever");
    let (done, r, got) = worker.join().expect("thread join");
    r.expect("client read");
    assert!(done.is_ok(), "an empty lent part runs done");
    assert_eq!(got, b"headtail", "the other parts go out as one PDU");
}
