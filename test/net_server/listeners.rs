use super::*;

/// Deferring echo handler that `take()`s the body - the one-pattern placement consumer (zero-copy when placed, copy
/// fallback inline).
fn take_and_defer_echo(body: &mut Body, responder: Responder) -> Response {
    let payload = body.take();
    let (deferred, permit) = responder.defer();
    thread::spawn(move || deferred.reply(echo_frame(&payload)));
    Response::Defer(permit)
}

/// Patterned payload (prime modulus catches offset/splice mistakes).
fn patterned(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

#[test]
fn tcp_body_placement_roundtrip() {
    // Bodies >= the threshold are read into their own allocation and moved out zero-copy via take(); small bodies ride
    // the accumulate buffer with take() falling back to a copy. Sequence small -> large -> small on one connection
    // proves keep-alive across a placed message (consume() drains only the header of a placed message).
    let cfg = ServerConfig {
        body_placement_threshold: Some(1024),
        ..ServerConfig::default()
    };
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(PrefixWidth::U32, Endian::Big, false),
        body: |req: Request<'_, ()>| {
            let Request {
                mut body, responder, ..
            } = req;
            take_and_defer_echo(&mut body, responder)
        },
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let mut server = match Server::with_config([addr], cfg, proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind: {e}"),
    };
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();

    let client = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone()); // fail fast on panic
        (|| -> io::Result<()> {
            let mut s = connect_tcp(v4)?;
            let large = patterned(256 * 1024);
            for payload in [b"small-1".as_slice(), &large, b"small-2"] {
                send_framed(&mut s, payload)?;
                assert_eq!(recv_framed(&mut s)?, payload, "echo mismatch at len {}", payload.len());
            }
            Ok(())
        })()
        .expect("client io");
        stop.shutdown();
    });

    server.serve_forever().expect("serve_forever");
    client.join().expect("thread join");
}

#[test]
fn tcp_body_placement_disabled() {
    // threshold None: the same take()-based handler works with every body on the accumulate path (take() copies).
    let cfg = ServerConfig {
        body_placement_threshold: None,
        ..ServerConfig::default()
    };
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(PrefixWidth::U32, Endian::Big, false),
        body: |req: Request<'_, ()>| {
            let Request {
                mut body, responder, ..
            } = req;
            take_and_defer_echo(&mut body, responder)
        },
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let mut server = match Server::with_config([addr], cfg, proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind: {e}"),
    };
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();

    let client = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone()); // fail fast on panic
        (|| -> io::Result<()> {
            let mut s = connect_tcp(v4)?;
            let large = patterned(256 * 1024);
            send_framed(&mut s, &large)?;
            assert_eq!(recv_framed(&mut s)?, large);
            Ok(())
        })()
        .expect("client io");
        stop.shutdown();
    });

    server.serve_forever().expect("serve_forever");
    client.join().expect("thread join");
}

#[test]
fn lsp_large_body_placement() {
    // More-style framer + placement: the chunk read over-reads part of the body before the verdict, exercising the
    // prefix-copy path of arm_body_recv (prefix from the accumulate buffer + remainder read straight into the placed
    // allocation).
    let cfg = ServerConfig {
        body_placement_threshold: Some(1024),
        ..ServerConfig::default()
    };
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: lsp_header,
        body: |req: Request<'_, ()>| {
            let Request {
                mut body, responder, ..
            } = req;
            take_and_defer_echo(&mut body, responder)
        },
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let mut server = match Server::with_config([addr], cfg, proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind: {e}"),
    };
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();

    let client = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone()); // fail fast on panic
        let r = (|| -> io::Result<(Vec<u8>, Vec<u8>)> {
            let mut s = connect_tcp(v4)?;
            let payload = patterned(8 * 1024);
            // One write: the server's first 4 KiB chunk read grabs the header AND a body prefix.
            let mut msg = format!("Content-Length: {}\r\n\r\n", payload.len()).into_bytes();
            msg.extend_from_slice(&payload);
            s.write_all(&msg)?;
            Ok((recv_framed(&mut s)?, payload))
        })();
        stop.shutdown();
        r
    });

    server.serve_forever().expect("serve_forever");
    let (got, want) = client.join().expect("thread join").expect("client io");
    assert_eq!(got, want, "placed LSP body echoed intact");
}

#[test]
fn multi_listener_unix_and_tcp() {
    // One server, one ring, two listeners (TCP + unix). The accept handler records which listener the connection
    // arrived on; the body echoes that plus the peer family, proving routing, framing, and identity per listener.
    let dir = truenas_ros::tempdir().unwrap();
    let path = dir.path().join("multi.sock");
    let addrs = [
        ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap()),
        ServerAddr::Unix(path.clone()),
    ];
    let proto = Protocol {
        accept: |inc: Incoming<'_>| {
            let l = match inc.listener_addr {
                ServerAddr::Tcp(_) => "tcp",
                ServerAddr::Tcp6(_) => "tcp6",
                ServerAddr::Unix(_) => "unix",
            };
            let p = match inc.peer {
                ClientAddr::Inet(_) => "inet",
                ClientAddr::Unix { .. } => "unix",
            };
            Some(format!("{l}/{p}"))
        },
        header: length_prefix_header::<String>(PrefixWidth::U32, Endian::Big, false),
        body: |req: Request<'_, String>| {
            let Request { state: tag, .. } = req;
            Response::Reply(echo_frame(tag.as_bytes()))
        },
    };
    let mut server = match Server::bind(addrs, proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind: {e}"),
    };
    let bound = server.local_addrs();
    assert_eq!(bound.len(), 2, "two listeners: {bound:?}");
    let ServerAddr::Tcp(v4) = bound[0] else {
        panic!("expected resolved Tcp first: {bound:?}");
    };
    assert_ne!(v4.port(), 0, "ephemeral port resolved");
    assert!(
        matches!(&bound[1], ServerAddr::Unix(p) if *p == path),
        "unix second: {bound:?}"
    );
    let stop = server.shutdown_handle();

    let client = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone()); // fail fast on panic
        (|| -> io::Result<()> {
            let mut t = connect_tcp(v4)?;
            send_framed(&mut t, b"hi")?;
            assert_eq!(recv_framed(&mut t)?, b"tcp/inet");
            let mut u = connect_unix(&path)?;
            send_framed(&mut u, b"hi")?;
            assert_eq!(recv_framed(&mut u)?, b"unix/unix");
            Ok(())
        })()
        .expect("client io");
        stop.shutdown();
    });

    server.serve_forever().expect("serve_forever");
    client.join().expect("thread join");
}

#[test]
fn multi_listener_per_port_policy() {
    // Two TCP listeners on one server; accept admits connections on the first port and rejects the second - the
    // listener argument drives policy.
    use std::sync::Mutex;
    let addrs = [
        ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap()),
        ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap()),
    ];
    let admit_port: Arc<Mutex<u16>> = Arc::new(Mutex::new(0));
    let proto = Protocol {
        accept: {
            let admit_port = Arc::clone(&admit_port);
            move |inc: Incoming<'_>| {
                let ServerAddr::Tcp(sa) = inc.listener_addr else {
                    return None;
                };
                (sa.port() == *admit_port.lock().unwrap()).then_some(())
            }
        },
        header: length_prefix_header::<()>(PrefixWidth::U32, Endian::Big, false),
        body: |req: Request<'_, ()>| {
            let Request { body, .. } = req;
            Response::Reply(echo_frame(&body[..]))
        },
    };
    let mut server = match Server::bind(addrs, proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind: {e}"),
    };
    let bound = server.local_addrs();
    let (ServerAddr::Tcp(a), ServerAddr::Tcp(b)) = (&bound[0], &bound[1]) else {
        panic!("expected two Tcp: {bound:?}");
    };
    let (a, b) = (*a, *b);
    *admit_port.lock().unwrap() = a.port();
    let stop = server.shutdown_handle();

    let client = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone()); // fail fast on panic
        (|| -> io::Result<()> {
            let mut ok = connect_tcp(a)?;
            send_framed(&mut ok, b"yes")?;
            assert_eq!(recv_framed(&mut ok)?, b"yes");
            // Rejected means no reply, so EOF, reset or a plain timeout with no data all confirm it, without depending
            // on the reject-close reaching us.
            let mut no = connect_tcp(b)?;
            no.set_read_timeout(Some(Duration::from_millis(300)))?;
            let _ = send_framed(&mut no, b"no");
            let mut byte = [0u8; 1];
            match no.read(&mut byte) {
                Ok(n) => assert_eq!(n, 0, "rejected conn must not echo"),
                Err(e) => assert!(
                    matches!(
                        e.kind(),
                        io::ErrorKind::ConnectionReset | io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ),
                    "unexpected error on rejected conn: {e:?}"
                ),
            }
            send_framed(&mut ok, b"again")?;
            assert_eq!(recv_framed(&mut ok)?, b"again");
            Ok(())
        })()
        .expect("client io");
        stop.shutdown();
    });

    server.serve_forever().expect("serve_forever");
    client.join().expect("thread join");
}

#[test]
fn tcp_peername_is_per_connection() {
    // Peer addresses are fetched per connection with `SO_PEERNAME`, not read from a buffer shared across a multishot
    // accept's completions, so each connect in a burst must see its own source address echoed back.
    const N: usize = 8;
    let proto = Protocol {
        accept: |inc: Incoming<'_>| match inc.peer {
            ClientAddr::Inet(sa) => Some(sa.to_string()),
            _ => None,
        },
        header: length_prefix_header::<String>(PrefixWidth::U32, Endian::Big, false),
        body: |req: Request<'_, String>| {
            let Request { state: seen, .. } = req;
            Response::Reply(echo_frame(seen.as_bytes()))
        },
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let mut server = match Server::bind([addr], proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind: {e}"),
    };
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();

    let driver = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone()); // fail fast on panic
        let clients: Vec<_> = (0..N)
            .map(|_| {
                thread::spawn(move || -> io::Result<()> {
                    // Connect within the burst, then ask who the server thinks we are.
                    let mut s = connect_tcp(v4)?;
                    let me = s.local_addr()?;
                    send_framed(&mut s, b"who")?;
                    let reply = recv_framed(&mut s)?;
                    let seen = String::from_utf8(reply).expect("utf8");
                    assert_eq!(seen, me.to_string(), "server saw a different peer than this client");
                    Ok(())
                })
            })
            .collect();
        for c in clients {
            c.join().expect("client join").expect("client io");
        }
        stop.shutdown();
    });

    server.serve_forever().expect("serve_forever");
    driver.join().expect("driver join");
}

#[test]
fn multi_listener_pool_full_rearm() {
    // With `pool_size` 1 and two listeners, a connect on listener B is shed (kernel ENFILE close) while A's connection
    // holds the slot, and once it closes, B's parked accept re-arms and serves.
    let cfg = ServerConfig {
        pool_size: 1,
        ..ServerConfig::default()
    };
    let addrs = [
        ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap()),
        ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap()),
    ];
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(PrefixWidth::U32, Endian::Big, false),
        body: |req: Request<'_, ()>| {
            let Request { body, .. } = req;
            Response::Reply(echo_frame(&body[..]))
        },
    };
    let mut server = match Server::with_config(addrs, cfg, proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind: {e}"),
    };
    let bound = server.local_addrs();
    let (ServerAddr::Tcp(a), ServerAddr::Tcp(b)) = (&bound[0], &bound[1]) else {
        panic!("expected two Tcp: {bound:?}");
    };
    let (a, b) = (*a, *b);
    let stop = server.shutdown_handle();

    let client = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone()); // fail fast on panic
        (|| -> io::Result<()> {
            let mut holder = connect_tcp(a)?;
            send_framed(&mut holder, b"hold")?;
            assert_eq!(recv_framed(&mut holder)?, b"hold");
            // Pool is full: one attempt on B is shed (accepted then closed by the kernel - ENFILE - terminating B's
            // multishot accept). Use a short timeout because a connection can also land in B's listen backlog
            // unaccepted, where a read would block indefinitely; that it does not get served is the point.
            let mut shed = connect_tcp(b)?;
            shed.set_read_timeout(Some(Duration::from_millis(200)))?;
            let mut byte = [0u8; 1];
            let _ = shed.read(&mut byte); // EOF / reset / timeout - all "shed"
            drop(shed);
            drop(holder); // free the only slot
            thread::sleep(Duration::from_millis(150)); // close + deferred re-arm
            // B's accept re-armed on the freed slot; a fresh connection serves.
            let mut ok = connect_tcp(b)?;
            send_framed(&mut ok, b"revived")?;
            assert_eq!(recv_framed(&mut ok)?, b"revived");
            Ok(())
        })()
        .expect("client io");
        stop.shutdown();
    });

    server.serve_forever().expect("serve_forever");
    client.join().expect("thread join");
}

#[test]
fn tcp_reply_coalescing() {
    // A burst of deferred replies released together is gathered into fewer SENDMSG ops. Sixteen pipelined requests all
    // defer and one worker answers them at once, so the client must receive every payload intact, in any order, and
    // `send_ops` must stay below `replies`.
    use std::sync::Mutex;
    const N: usize = 16;
    type Parked = Vec<(Vec<u8>, truenas_ros::net::server::Deferred)>;
    let parked: Arc<Mutex<Parked>> = Arc::new(Mutex::new(Vec::new()));
    let cfg = ServerConfig {
        max_in_flight_requests: N,
        ..ServerConfig::default()
    };
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(PrefixWidth::U32, Endian::Big, false),
        body: {
            let parked = Arc::clone(&parked);
            move |req: Request<'_, ()>| {
                let Request { body, responder, .. } = req;
                let (deferred, permit) = responder.defer();
                let mut guard = parked.lock().unwrap();
                guard.push((body.to_vec(), deferred));
                if guard.len() == N {
                    // Last request in: answer the whole burst back-to-back so the injection queue fills faster than the
                    // loop drains.
                    let batch = std::mem::take(&mut *guard);
                    thread::spawn(move || {
                        for (payload, d) in batch {
                            d.reply(echo_frame(&payload));
                        }
                    });
                }
                Response::Defer(permit)
            }
        },
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let mut server = match Server::with_config([addr], cfg, proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind: {e}"),
    };
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();
    let stats = server.stats_handle();

    let client = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone()); // fail fast on panic
        (|| -> io::Result<()> {
            let mut s = connect_tcp(v4)?;
            let sent: Vec<Vec<u8>> = (0..N).map(|i| format!("burst-{i:02}").into_bytes()).collect();
            for msg in &sent {
                send_framed(&mut s, msg)?; // pipelined: no reads in between
            }
            let mut got: Vec<Vec<u8>> = (0..N).map(|_| recv_framed(&mut s)).collect::<Result<_, _>>()?;
            got.sort();
            assert_eq!(got, sent, "every burst payload echoed intact");
            Ok(())
        })()
        .expect("client io");
        stop.shutdown();
    });

    server.serve_forever().expect("serve_forever");
    client.join().expect("thread join");
    let s = stats.snapshot();
    assert_eq!(s.replies, N as u64, "replies: {s:?}");
    assert!(
        s.send_ops >= 1 && s.send_ops < s.replies,
        "expected coalescing (send_ops < replies): {s:?}"
    );
}

#[test]
fn tcp_graceful_shutdown_drains() {
    // Graceful shutdown: a request already deferred to a worker completes and its reply is delivered; an idle
    // connection is closed promptly; accepting stops; serve_forever returns without waiting for the grace deadline.
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(PrefixWidth::U32, Endian::Big, false),
        body: |req: Request<'_, ()>| {
            let Request { body, responder, .. } = req;
            let input = body.to_vec();
            let (deferred, permit) = responder.defer();
            thread::spawn(move || {
                thread::sleep(Duration::from_millis(150)); // in-flight work
                deferred.reply(echo_frame(&input.to_ascii_uppercase()));
            });
            Response::Defer(permit)
        },
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let mut server = match Server::bind([addr], proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind: {e}"),
    };
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();

    let client = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone()); // fail fast on panic
        (|| -> io::Result<()> {
            let mut idle = connect_tcp(v4)?; // parked, no request
            let mut busy = connect_tcp(v4)?;
            send_framed(&mut busy, b"work")?; // now deferred to the worker

            thread::sleep(Duration::from_millis(30)); // let the defer start
            let t0 = Instant::now();
            stop.shutdown_graceful(Duration::from_secs(5));

            // In-flight work still completes and is delivered...
            let reply = recv_framed(&mut busy)?;
            assert_eq!(reply, b"WORK");
            // ...then the drained connection closes (EOF), as does the idle one -- well before the 5s grace deadline.
            let mut b = [0u8; 1];
            assert_eq!(busy.read(&mut b)?, 0, "busy conn should see EOF");
            assert_eq!(idle.read(&mut b)?, 0, "idle conn should see EOF");
            assert!(t0.elapsed() < Duration::from_secs(2), "drain took {:?}", t0.elapsed());
            Ok(())
        })()
        .expect("client io");
    });

    server.serve_forever().expect("serve_forever");
    client.join().expect("thread join");
}

#[test]
fn tcp_graceful_deadline_escalates() {
    // A worker that never resolves its `Deferred` keeps the drain from completing, so the grace deadline must escalate
    // to a hard stop and `serve_forever` must still return. The handler parks each `Deferred` in `keep_rx` rather than
    // using `mem::forget`, which leaks its channel and trips LeakSanitizer.
    let (keep_tx, keep_rx) = std::sync::mpsc::channel();
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(PrefixWidth::U32, Endian::Big, false),
        body: move |req: Request<'_, ()>| {
            let Request { responder, .. } = req;
            let (deferred, permit) = responder.defer();
            let _ = keep_tx.send(deferred); // held, never resolved
            Response::Defer(permit)
        },
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let mut server = match Server::bind([addr], proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind: {e}"),
    };
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();

    let client = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone()); // fail fast on panic
        (|| -> io::Result<TcpStream> {
            let mut s = connect_tcp(v4)?;
            send_framed(&mut s, b"stuck")?;
            thread::sleep(Duration::from_millis(30));
            stop.shutdown_graceful(Duration::from_millis(300));
            // Keep the socket open (returned) - its EOF only arrives when the abandoned connection's descriptor closes
            // at server teardown.
            Ok(s)
        })()
        .expect("client io")
    });

    let t0 = Instant::now();
    server.serve_forever().expect("serve_forever");
    assert!(
        t0.elapsed() < Duration::from_secs(2),
        "deadline escalation took {:?}",
        t0.elapsed()
    );
    let mut s = client.join().expect("thread join");
    // Hard-stop abandons the stuck connection; dropping the server closes its pool descriptor, and only then does the
    // client see EOF with no data.
    drop(server);
    let mut buf = Vec::new();
    let n = s.read_to_end(&mut buf).unwrap_or(buf.len());
    assert_eq!(n, 0, "unexpected data after abandon: {buf:?}");
    drop(keep_rx); // release the held (never-resolved) Deferreds - no leak
}

#[test]
fn tcp_graceful_drains_pipelined_deferred_reply() {
    // In pipelined mode a connection can hold a deferred reply in flight and a parked read-ahead recv at once. Graceful
    // shutdown cancels the parked recv but must still deliver the reply before closing. At the default
    // `max_in_flight_requests` no read-ahead is armed during a defer, so this shape is pipelined-only.
    let cfg = ServerConfig {
        max_in_flight_requests: 2, // pipelined -> read-ahead armed during a defer
        ..ServerConfig::default()
    };
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(PrefixWidth::U32, Endian::Big, false),
        body: |req: Request<'_, ()>| {
            let Request { body, responder, .. } = req;
            let mut reply = b"re:".to_vec();
            reply.extend_from_slice(&body);
            let (deferred, permit) = responder.defer();
            thread::spawn(move || {
                thread::sleep(Duration::from_millis(150)); // still in flight at drain
                deferred.reply(echo_frame(&reply));
            });
            Response::Defer(permit)
        },
    };
    let mut server = match Server::with_config(
        [ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap())],
        cfg,
        proto,
    ) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind: {e}"),
    };
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();

    let client = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone()); // fail fast on panic
        (|| -> io::Result<()> {
            let mut s = connect_tcp(v4)?;
            send_framed(&mut s, b"hello")?;
            // Let the defer start and the read-ahead recv arm, then drain.
            thread::sleep(Duration::from_millis(40));
            stop.shutdown_graceful(Duration::from_secs(5));
            // The deferred reply must arrive despite the drain, before EOF.
            assert_eq!(recv_framed(&mut s)?, b"re:hello");
            let mut b = [0u8; 1];
            assert_eq!(s.read(&mut b)?, 0, "EOF after the deferred reply");
            Ok(())
        })()
        .expect("client io");
    });

    server.serve_forever().expect("serve_forever");
    client.join().expect("thread join");
}

#[test]
fn tcp_idle_timeout_keeps_pipelined_deferred_reply() {
    // When `idle_timeout` fires on a parked read-ahead recv while a deferred reply is still in flight, the connection
    // is not idle and must finish that work rather than be reaped, since once `closing`, `kick_send`'s `!closing` guard
    // swallows the queued send. A plain request and reply client hits this whenever the worker outlives `idle_timeout`,
    // and only in pipelined mode.
    //
    // `WORK` being an exact multiple of `IDLE` puts the final expiry in a photo-finish with the reply's flush and the
    // client's next request, which the served-since-arm rule keeps alive in every order
    // (`tcp_idle_clock_resets_on_served_reply` pins it deterministically).
    const IDLE: Duration = Duration::from_millis(100);
    const WORK: Duration = Duration::from_millis(400); // outlives IDLE 4x
    let cfg = ServerConfig {
        max_in_flight_requests: 2, // pipelined -> read-ahead armed during a defer
        idle_timeout: Some(IDLE),
        ..ServerConfig::default()
    };
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(PrefixWidth::U32, Endian::Big, false),
        body: |req: Request<'_, ()>| {
            let Request { body, responder, .. } = req;
            let mut reply = b"re:".to_vec();
            reply.extend_from_slice(&body);
            let (deferred, permit) = responder.defer();
            thread::spawn(move || {
                thread::sleep(WORK);
                deferred.reply(echo_frame(&reply));
            });
            Response::Defer(permit)
        },
    };
    let mut server = match Server::with_config(
        [ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap())],
        cfg,
        proto,
    ) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind: {e}"),
    };
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();

    let client = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone()); // fail fast on panic
        (|| -> io::Result<()> {
            let mut s = connect_tcp(v4)?;
            // Were the connection reaped while the reply is owed, this read would hit EOF.
            send_framed(&mut s, b"hello")?;
            assert_eq!(
                recv_framed(&mut s)?,
                b"re:hello",
                "deferred reply dropped by an idle-timeout reap"
            );
            // Not reaped, so keep-alive continues, and the idle fire repeats during the second defer.
            send_framed(&mut s, b"world")?;
            assert_eq!(recv_framed(&mut s)?, b"re:world");
            Ok(())
        })()
        .expect("client io");
        stop.shutdown();
    });

    server.serve_forever().expect("serve_forever");
    client.join().expect("thread join");
}

#[test]
fn tcp_idle_clock_resets_on_served_reply() {
    // The idle clock rides the parked read-ahead recv from arm time, so it keeps counting while a deferred reply is
    // produced and flushed. Serving that reply is activity and must restart the quiet interval, or a guard that only
    // asks whether work is owed now reaps a connection it served moments ago.
    //
    // The read-ahead parks at about 0 with the clock running, the reply flushes at about `WORK` (300 ms), the stale
    // clock expires at about `IDLE` (600 ms) and must re-arm rather than reap, and the second request lands at about
    // 700 ms, inside the fresh interval, and must be answered. Margins are hundreds of ms so a loaded VM cannot flip an
    // edge.
    const IDLE: Duration = Duration::from_millis(600);
    const WORK: Duration = Duration::from_millis(300);
    const CLIENT_PAUSE: Duration = Duration::from_millis(400);
    let cfg = ServerConfig {
        max_in_flight_requests: 2, // pipelined -> read-ahead parks during defer
        idle_timeout: Some(IDLE),
        ..ServerConfig::default()
    };
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(PrefixWidth::U32, Endian::Big, false),
        body: |req: Request<'_, ()>| {
            let Request { body, responder, .. } = req;
            let mut reply = b"re:".to_vec();
            reply.extend_from_slice(&body);
            let (deferred, permit) = responder.defer();
            thread::spawn(move || {
                thread::sleep(WORK);
                deferred.reply(echo_frame(&reply));
            });
            Response::Defer(permit)
        },
    };
    let mut server = match Server::with_config(
        [ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap())],
        cfg,
        proto,
    ) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind: {e}"),
    };
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();

    let client = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone()); // fail fast on panic
        (|| -> io::Result<()> {
            let mut s = connect_tcp(v4)?;
            send_framed(&mut s, b"hello")?;
            assert_eq!(recv_framed(&mut s)?, b"re:hello");
            // Idle across the stale clock's expiry but well inside the fresh interval it must start.
            thread::sleep(CLIENT_PAUSE);
            send_framed(&mut s, b"world")?;
            assert_eq!(
                recv_framed(&mut s)?,
                b"re:world",
                "connection reaped in the quiet window after a served reply"
            );
            Ok(())
        })()
        .expect("client io");
        stop.shutdown();
    });

    server.serve_forever().expect("serve_forever");
    client.join().expect("thread join");
}

#[test]
fn tcp_default_config_never_times_out_a_deferred_request() {
    // A request handed off with `Response::Defer` is never timed out, however long the worker runs. At the default
    // `max_in_flight_requests` of 1 no read-ahead recv is armed during a defer, so an `idle_timeout` well below the
    // worker's duration fires nothing.
    const IDLE: Duration = Duration::from_millis(100);
    const WORK: Duration = Duration::from_millis(500); // 5x the idle timeout
    let cfg = ServerConfig {
        idle_timeout: Some(IDLE),  // set, but must not reach a handled request
        ..ServerConfig::default()  // max_in_flight_requests == 1
    };
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(PrefixWidth::U32, Endian::Big, false),
        body: |req: Request<'_, ()>| {
            let Request { body, responder, .. } = req;
            let echo = echo_frame(&body);
            let (deferred, permit) = responder.defer();
            thread::spawn(move || {
                thread::sleep(WORK); // outlives idle_timeout many times over
                deferred.reply(echo);
            });
            Response::Defer(permit)
        },
    };
    let mut server = match Server::with_config(
        [ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap())],
        cfg,
        proto,
    ) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind: {e}"),
    };
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();

    let client = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone());
        (|| -> io::Result<()> {
            let mut s = connect_tcp(v4)?;
            send_framed(&mut s, b"slow")?;
            assert_eq!(recv_framed(&mut s)?, b"slow");
            Ok(())
        })()
        .expect("client io");
        stop.shutdown();
    });

    server.serve_forever().expect("serve_forever");
    client.join().expect("thread join");
}

#[test]
fn tcp_close_hook_reasons() {
    // The close hook reports why each connection closed: a clean keep-alive EOF, a handler-initiated close, and an idle
    // timeout.
    use std::sync::Mutex;
    let reasons = Arc::new(Mutex::new(Vec::new()));
    let cfg = ServerConfig {
        idle_timeout: Some(Duration::from_millis(100)),
        ..ServerConfig::default()
    };
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(PrefixWidth::U32, Endian::Big, false),
        body: |req: Request<'_, ()>| {
            let Request { body, .. } = req;
            if &body[..] == b"close" {
                Response::Close
            } else {
                Response::Reply(echo_frame(&body))
            }
        },
    };
    let mut server = match Server::with_config(
        [ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap())],
        cfg,
        proto,
    ) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind: {e}"),
    };
    {
        let reasons = Arc::clone(&reasons);
        server.set_close_hook(move |_addr, reason, _state: &mut ()| {
            reasons.lock().unwrap().push(reason);
        });
    }
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();

    let client = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone()); // fail fast on panic
        (|| -> io::Result<()> {
            // (a) clean keep-alive EOF -> PeerClosed
            let mut a = connect_tcp(v4)?;
            send_framed(&mut a, b"hi")?;
            assert_eq!(recv_framed(&mut a)?, b"hi");
            drop(a);
            // (b) handler says close -> HandlerClosed
            let mut b = connect_tcp(v4)?;
            send_framed(&mut b, b"close")?;
            let mut buf = Vec::new();
            b.read_to_end(&mut buf)?; // closed without a reply
            assert!(buf.is_empty());
            // (c) parked past idle_timeout -> IdleTimeout
            let mut c = connect_tcp(v4)?;
            let mut one = [0u8; 1];
            assert_eq!(c.read(&mut one)?, 0, "idle conn should be closed");
            // Let the server retire (a)'s EOF before stopping.
            thread::sleep(Duration::from_millis(50));
            Ok(())
        })()
        .expect("client io");
        stop.shutdown();
    });

    server.serve_forever().expect("serve_forever");
    client.join().expect("thread join");
    let mut got = reasons.lock().unwrap().clone();
    got.sort_by_key(|r| format!("{r:?}"));
    assert_eq!(
        got,
        vec![
            CloseReason::HandlerClosed,
            CloseReason::IdleTimeout,
            CloseReason::PeerClosed,
        ]
    );
}

#[test]
fn tcp_multicore_two_rings() {
    // The SO_REUSEPORT multi-core recipe (examples/tcp_multicore.rs): two independent single-ring servers on one
    // address; the kernel spreads connections across them; every round-trip is served; both drain cleanly.
    fn worker(addr: SocketAddrV4, ready: std::sync::mpsc::Sender<Result<(SocketAddrV4, ShutdownHandle), Error>>) {
        let cfg = ServerConfig {
            reuse_port: true,
            ..ServerConfig::default()
        };
        let proto = length_prefixed(PrefixWidth::U32, Endian::Big, false, echo);
        let mut server = match Server::with_config([ServerAddr::Tcp(addr)], cfg, proto) {
            Ok(s) => s,
            Err(e) => {
                let _ = ready.send(Err(e));
                return;
            }
        };
        let ServerAddr::Tcp(bound) = server.local_addrs().remove(0) else {
            panic!("expected Tcp");
        };
        let stop = server.shutdown_handle();
        let _ = ready.send(Ok((bound, stop)));
        server.serve_forever().expect("serve_forever");
    }

    let (tx, rx) = std::sync::mpsc::channel();
    let tx0 = tx.clone();
    let w0 = thread::spawn(move || {
        worker("127.0.0.1:0".parse().unwrap(), tx0);
    });
    let (addr, stop0) = match rx.recv().expect("worker 0") {
        Ok(v) => v,
        Err(e) if should_skip(&e) => {
            w0.join().unwrap();
            return;
        }
        Err(e) => panic!("bind: {e}"),
    };
    let w1 = thread::spawn(move || {
        worker(addr, tx);
    });
    // As above: the second `with_config` sets up a second ring, and a box whose free memory is fragmented refuses that
    // with `ENOMEM` long before it refuses a bind.
    let (_, stop1) = match rx.recv().expect("worker 1") {
        Ok(v) => v,
        Err(e) if should_skip(&e) => {
            stop0.shutdown();
            w0.join().unwrap();
            w1.join().unwrap();
            return;
        }
        Err(e) => panic!("second Server::with_config: {e}"),
    };

    // Fresh connection per round-trip so accepts spread across both rings.
    for i in 0..16 {
        let msg = format!("m{i}");
        let echoes = connect_tcp(addr)
            .and_then(|s| framed_roundtrips(s, &[msg.as_bytes()]))
            .expect("round-trip");
        assert_eq!(echoes, vec![msg.into_bytes()]);
    }

    stop0.shutdown_graceful(Duration::from_secs(5));
    stop1.shutdown_graceful(Duration::from_secs(5));
    w0.join().expect("worker 0 join");
    w1.join().expect("worker 1 join");
}
