use super::adopt::{accepted_elsewhere, bare_server_with, lend};
use super::*;
use std::net::TcpListener;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::sync::mpsc;
use truenas_ros::net::server::{SendZeroCopy, ServerStats};

/// Zero-copy from 4 KiB, with `linger` for peers that do not acknowledge.
fn zero_copy_config(linger: Duration) -> ServerConfig {
    ServerConfig {
        send_zero_copy: Some(SendZeroCopy {
            threshold: 4096,
            max_pinned: 1 << 20,
            linger,
        }),
        ..ServerConfig::default()
    }
}

fn set_int(fd: RawFd, level: i32, name: i32, value: i32) {
    // SAFETY: `value` is a live int of the length given.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            std::ptr::addr_of!(value).cast(),
            size_of::<i32>() as libc::socklen_t,
        )
    };
    assert_eq!(rc, 0, "setsockopt({level}, {name}): {}", io::Error::last_os_error());
}

/// A client with a receive buffer of a few KiB, set before the handshake so that its window stays that small.
fn connect_with_small_window(addr: SocketAddrV4) -> TcpStream {
    // SAFETY: a plain socket call. The descriptor is owned just below.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    assert!(fd >= 0, "socket: {}", io::Error::last_os_error());
    // SAFETY: `fd` is the socket just made, and nothing else owns it.
    let sock = unsafe { OwnedFd::from_raw_fd(fd) };
    set_int(fd, libc::SOL_SOCKET, libc::SO_RCVBUF, 4096);
    let sin = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: addr.port().to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from(*addr.ip()).to_be(),
        },
        sin_zero: [0; 8],
    };
    // SAFETY: `sin` is a live `sockaddr_in` of the length given.
    let rc = unsafe {
        libc::connect(
            fd,
            std::ptr::addr_of!(sin).cast(),
            size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    assert_eq!(rc, 0, "connect: {}", io::Error::last_os_error());
    TcpStream::from(sock)
}

/// A connected pair whose client takes a few KiB at a time, so most of a larger reply waits unacknowledged in the
/// server's send queue. The server end's send buffer holds all of it, so the send completes all the same.
fn stalled_pair() -> (TcpStream, OwnedFd) {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let std::net::SocketAddr::V4(addr) = l.local_addr().expect("local addr") else {
        unreachable!("bound to an IPv4 address");
    };
    let client = connect_with_small_window(addr);
    let (server_end, _) = l.accept().expect("accept");
    set_int(server_end.as_raw_fd(), libc::SOL_SOCKET, libc::SO_SNDBUF, 1 << 20);
    (client, OwnedFd::from(server_end))
}

/// Wait up to `limit` for the server's counters to meet `cond`.
fn wait_for(stats: &StatsHandle, limit: Duration, what: &str, cond: impl Fn(&ServerStats) -> bool) -> ServerStats {
    let deadline = Instant::now() + limit;
    loop {
        let s = stats.snapshot();
        if cond(&s) {
            return s;
        }
        assert!(Instant::now() < deadline, "timed out waiting for {what}: {s:?}");
        thread::sleep(Duration::from_millis(5));
    }
}

/// Wait for the result of the first send.
fn sent(stats: &StatsHandle) -> ServerStats {
    wait_for(stats, Duration::from_secs(5), "the send's result", |s| {
        s.send_ops > 0 || s.zero_copy_fallbacks > 0
    })
}

/// Whether the kernel refused zero-copy, as it does past `RLIMIT_MEMLOCK` for a ring made without `CAP_IPC_LOCK`. A
/// skip, and a failure under `TRUENAS_ROS_REQUIRE_ZERO_COPY`.
fn zero_copy_refused(s: &ServerStats) -> bool {
    if s.zero_copy_fallbacks == 0 {
        return false;
    }
    assert!(
        std::env::var_os("TRUENAS_ROS_REQUIRE_ZERO_COPY").is_none(),
        "TRUENAS_ROS_REQUIRE_ZERO_COPY set but the kernel refused a zero-copy send: {s:?}"
    );
    true
}

/// 256 KiB, under the stalled pair's send buffer and over its client's window.
fn payload() -> Vec<u8> {
    (0..256 * 1024).map(|i| (i % 251) as u8).collect()
}

#[test]
fn a_lent_reply_goes_back_only_once_the_peer_acknowledges_it() {
    for zero_copy in [true, false] {
        let cfg = if zero_copy {
            zero_copy_config(Duration::from_secs(10))
        } else {
            ServerConfig::default()
        };
        let Some(mut server) = bare_server_with(cfg) else {
            return;
        };
        let stats = server.stats_handle();
        let (mut client, sock) = stalled_pair();
        let push = server.adopt(sock, ()).expect("adopt");
        let payload = payload();
        let (done_tx, done_rx) = mpsc::channel();
        push.push_parts(vec![lend(&payload, done_tx)]);
        let stop = server.shutdown_handle();
        let want = payload.len();
        let worker = thread::spawn(move || {
            let _stop = ShutdownOnDrop(stop.clone());
            let at_result = sent(&stats);
            // The client reads nothing yet, so most of the reply waits unacknowledged in the server's queue.
            let early = done_rx.recv_timeout(Duration::from_millis(300)).is_ok();
            let mut got = vec![0u8; want];
            let read = client.read_exact(&mut got);
            let late = early || done_rx.recv_timeout(Duration::from_secs(5)).is_ok();
            stop.shutdown();
            (at_result, early, read, got, late)
        });
        server.serve_forever().expect("serve_forever");
        let (at_result, early, read, got, late) = worker.join().expect("thread join");
        read.expect("client read");
        assert!(got == payload, "the reply arrives unchanged");
        if !zero_copy {
            assert!(early, "a copied send hands its bytes back at its result");
            continue;
        }
        if zero_copy_refused(&at_result) {
            return;
        }
        assert_eq!(at_result.zero_copy_sends, 1, "{at_result:?}");
        assert!(!early, "done ran while the kernel could still read the bytes");
        assert!(late, "done never ran once the peer acknowledged");
    }
}

#[test]
fn loopback_copies_so_later_sends_go_with_a_copy() {
    let Some(mut server) = bare_server_with(zero_copy_config(Duration::from_secs(10))) else {
        return;
    };
    let stats = server.stats_handle();
    let (mut client, sock) = accepted_elsewhere();
    let push = server.adopt(sock, ()).expect("adopt");
    let stop = server.shutdown_handle();
    let worker = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone());
        let mut after = Vec::new();
        for round in 0..2u8 {
            let payload = vec![round; 64 * 1024];
            let (done_tx, done_rx) = mpsc::channel();
            push.push_parts(vec![lend(&payload, done_tx)]);
            let mut got = vec![0u8; payload.len()];
            client.read_exact(&mut got).expect("client read");
            assert!(got == payload, "round {round}: the reply arrives unchanged");
            done_rx.recv_timeout(Duration::from_secs(5)).expect("done");
            // The copy report rides the first send's notification, which also ran `done`.
            let s = wait_for(&stats, Duration::from_secs(5), "the copy report", |s| {
                round == 1 || s.zero_copy_copied > 0 || s.zero_copy_fallbacks > 0
            });
            after.push(s);
        }
        stop.shutdown();
        after
    });
    server.serve_forever().expect("serve_forever");
    let after = worker.join().expect("thread join");
    if zero_copy_refused(&after[1]) {
        return;
    }
    // Local delivery copies the pages (`deliver_skb`, `net/core/dev.c`), so loopback always reports a copy.
    assert_eq!(
        (after[0].zero_copy_sends, after[0].zero_copy_copied),
        (1, 1),
        "{:?}",
        after[0]
    );
    assert_eq!(
        after[1].zero_copy_sends, 1,
        "a send after the copy report went zero-copy: {:?}",
        after[1]
    );
}

#[test]
fn a_closed_connection_keeps_its_slot_until_the_peer_acknowledges() {
    let Some(mut server) = bare_server_with(zero_copy_config(Duration::from_secs(10))) else {
        return;
    };
    let stats = server.stats_handle();
    let (mut client, sock) = stalled_pair();
    let push = server.adopt(sock, ()).expect("adopt");
    let payload = payload();
    let (done_tx, done_rx) = mpsc::channel();
    push.push_parts(vec![lend(&payload, done_tx)]);
    push.close();
    let stop = server.shutdown_handle();
    let want = payload.len();
    let worker = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone());
        let at_result = sent(&stats);
        thread::sleep(Duration::from_millis(300));
        let held = stats.snapshot();
        let early = done_rx.try_recv().is_ok();
        let mut got = vec![0u8; want];
        let read = client.read_exact(&mut got);
        let mut rest = Vec::new();
        let eof = client.read_to_end(&mut rest);
        let late = early || done_rx.recv_timeout(Duration::from_secs(5)).is_ok();
        let closed = wait_for(&stats, Duration::from_secs(5), "the close", |s| s.closed == 1);
        stop.shutdown();
        (at_result, held, early, read, got, eof, rest, late, closed)
    });
    server.serve_forever().expect("serve_forever");
    let (at_result, held, early, read, got, eof, rest, late, closed) = worker.join().expect("thread join");
    read.expect("client read");
    assert!(got == payload, "the reply arrives unchanged");
    assert!(
        eof.is_ok() && rest.is_empty(),
        "the close follows the reply: {eof:?}, {} more bytes",
        rest.len()
    );
    if zero_copy_refused(&at_result) {
        return;
    }
    assert_eq!(
        held.closed, 0,
        "the slot was freed while the kernel could still read the bytes"
    );
    assert!(!early, "done ran while the kernel could still read the bytes");
    assert!(late, "done never ran once the peer acknowledged");
    assert_eq!(closed.closed, 1);
}

#[test]
fn a_closed_connection_whose_peer_never_reads_is_reset_after_the_linger() {
    let Some(mut server) = bare_server_with(zero_copy_config(Duration::from_millis(200))) else {
        return;
    };
    let stats = server.stats_handle();
    let (client, sock) = stalled_pair();
    let push = server.adopt(sock, ()).expect("adopt");
    let payload = payload();
    let (done_tx, done_rx) = mpsc::channel();
    push.push_parts(vec![lend(&payload, done_tx)]);
    push.close();
    let stop = server.shutdown_handle();
    let worker = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone());
        let at_result = sent(&stats);
        // `TCP_USER_TIMEOUT` ends the zero-window probing (`tcp_probe_timer`), which posts the notification and lets
        // the held CLOSE go.
        let closed = (!zero_copy_refused(&at_result))
            .then(|| wait_for(&stats, Duration::from_secs(15), "the kernel's reset", |s| s.closed == 1));
        let done = done_rx.recv_timeout(Duration::from_secs(5)).is_ok();
        stop.shutdown();
        drop(client);
        (closed, done)
    });
    server.serve_forever().expect("serve_forever");
    let (closed, done) = worker.join().expect("thread join");
    if let Some(closed) = closed {
        assert_eq!(closed.closed, 1);
        assert!(done, "the bytes never went back");
    }
}

#[test]
fn a_stop_with_a_stalled_peer_resets_it_after_the_linger() {
    let linger = Duration::from_millis(200);
    let Some(mut server) = bare_server_with(zero_copy_config(linger)) else {
        return;
    };
    let stats = server.stats_handle();
    let (client, sock) = stalled_pair();
    let push = server.adopt(sock, ()).expect("adopt");
    let payload = payload();
    let (done_tx, done_rx) = mpsc::channel();
    push.push_parts(vec![lend(&payload, done_tx)]);
    let stop = server.shutdown_handle();
    let worker = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone());
        let at_result = sent(&stats);
        let asked = Instant::now();
        stop.shutdown();
        (at_result, asked, client)
    });
    server.serve_forever().expect("serve_forever");
    let returned = Instant::now();
    let (at_result, asked, _client) = worker.join().expect("thread join");
    let stats = server.stats_handle().snapshot();
    drop(server);
    if zero_copy_refused(&at_result) {
        return;
    }
    // Without the reset the drain waits for an acknowledgement that never comes.
    let took = returned.duration_since(asked);
    assert!(took < linger + Duration::from_secs(5), "the stop took {took:?}");
    assert_eq!(stats.zero_copy_resets, 1, "{stats:?}");
    assert!(
        done_rx.recv_timeout(Duration::from_secs(1)).is_ok(),
        "the bytes were not handed back after the reset freed the pages"
    );
}

#[test]
fn a_socket_with_a_ulp_sends_with_a_copy() {
    let Some(mut server) = bare_server_with(zero_copy_config(Duration::from_secs(10))) else {
        return;
    };
    let stats = server.stats_handle();
    let (mut client, sock) = accepted_elsewhere();
    // The tls ULP without keys passes bytes through, but clears `SOCK_SUPPORT_ZC` (`net/ipv4/tcp_ulp.c`), so the
    // kernel refuses a zero-copy send with `EOPNOTSUPP` (`io_send_zc`).
    // SAFETY: three bytes of a live string.
    let rc = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            libc::SOL_TCP,
            libc::TCP_ULP,
            b"tls".as_ptr().cast(),
            3,
        )
    };
    if rc != 0 {
        let e = io::Error::last_os_error();
        assert!(
            std::env::var_os("TRUENAS_ROS_REQUIRE_KTLS").is_none(),
            "TRUENAS_ROS_REQUIRE_KTLS set but the kernel lacks the tls ULP: {e}"
        );
        return;
    }
    let push = server.adopt(sock, ()).expect("adopt");
    let payload = vec![9u8; 64 * 1024];
    let (done_tx, done_rx) = mpsc::channel();
    push.push_parts(vec![lend(&payload, done_tx)]);
    let stop = server.shutdown_handle();
    let want = payload.len();
    let worker = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone());
        let mut got = vec![0u8; want];
        let read = client.read_exact(&mut got);
        let done = done_rx.recv_timeout(Duration::from_secs(5)).is_ok();
        stop.shutdown();
        (read, got, done)
    });
    server.serve_forever().expect("serve_forever");
    let (read, got, done) = worker.join().expect("thread join");
    read.expect("client read");
    assert!(got == payload, "the reply arrives unchanged");
    assert!(done);
    let s = stats.snapshot();
    assert_eq!((s.zero_copy_fallbacks, s.zero_copy_sends), (1, 0), "{s:?}");
}

#[test]
fn a_unix_peer_sends_with_a_copy() {
    let Some(mut server) = bare_server_with(zero_copy_config(Duration::from_secs(10))) else {
        return;
    };
    let stats = server.stats_handle();
    let (mut client, server_end) = UnixStream::pair().expect("socketpair");
    let push = server.adopt(OwnedFd::from(server_end), ()).expect("adopt");
    let payload = vec![5u8; 64 * 1024];
    let (done_tx, done_rx) = mpsc::channel();
    push.push_parts(vec![lend(&payload, done_tx)]);
    let stop = server.shutdown_handle();
    let want = payload.len();
    let worker = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone());
        let mut got = vec![0u8; want];
        let read = client.read_exact(&mut got);
        let done = done_rx.recv_timeout(Duration::from_secs(5)).is_ok();
        stop.shutdown();
        (read, got, done)
    });
    server.serve_forever().expect("serve_forever");
    let (read, got, done) = worker.join().expect("thread join");
    read.expect("client read");
    assert!(got == payload);
    assert!(done);
    let s = stats.snapshot();
    assert_eq!(
        (s.zero_copy_sends, s.zero_copy_fallbacks),
        (0, 0),
        "AF_UNIX was tried: {s:?}"
    );
}

#[test]
fn zero_copy_settings_are_validated() {
    let bad = [
        (
            SendZeroCopy {
                threshold: 0,
                ..SendZeroCopy::default()
            },
            "threshold",
        ),
        (
            SendZeroCopy {
                threshold: 2,
                max_pinned: 1,
                ..SendZeroCopy::default()
            },
            "max_pinned",
        ),
        (
            SendZeroCopy {
                linger: Duration::from_micros(500),
                ..SendZeroCopy::default()
            },
            "linger",
        ),
    ];
    for (zc, field) in bad {
        let cfg = ServerConfig {
            send_zero_copy: Some(zc),
            ..ServerConfig::default()
        };
        match Server::with_config(Vec::<ServerAddr>::new(), cfg, noop_protocol()) {
            Err(Error::Validation(m)) => assert!(m.contains(field), "{field}: {m}"),
            Err(e) => panic!("{field}: {e}"),
            Ok(_) => panic!("{field}: accepted"),
        }
    }
}

#[test]
fn zero_copy_refuses_a_detach_handler() {
    let Some(mut server) = bare_server_with(zero_copy_config(Duration::from_secs(10))) else {
        return;
    };
    server.set_detach_handler(|_ctx, _detached| {});
    match server.serve_forever() {
        Err(Error::Validation(m)) => assert!(m.contains("send_zero_copy"), "{m}"),
        other => panic!("serve_forever: {other:?}"),
    }
}
