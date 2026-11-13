use super::*;

// ---- tests ----------------------------------------------------------------

#[test]
fn tcp_echo() {
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let mut server = match Server::bind([addr], length_prefixed(PrefixWidth::U32, Endian::Big, false, echo)) {
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
        let r = connect_tcp(v4).and_then(|s| framed_roundtrips(s, &[b"hello io_uring" as &[u8]]));
        stop.shutdown();
        r
    });

    server.serve_forever().expect("serve_forever");
    let echoes = client.join().expect("thread join").expect("client io");
    assert_eq!(echoes, vec![b"hello io_uring".to_vec()]);
}

#[test]
fn tcp_vectored_reply() {
    // A `ReplyVectored`'s segments reach the client concatenated in order (one vectored write), and the reply retires
    // its `outstanding` count exactly once - only the last segment is `is_reply` - so keep-alive keeps serving: three
    // sequential roundtrips are not stranded behind the read-ahead cap. A wrong `is_reply` count would wedge the
    // second.
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(PrefixWidth::U32, Endian::Big, false),
        body: |req: Request<'_, ()>| {
            let Request { body, .. } = req;
            // Echo as two segments: the length prefix, then the payload.
            let payload = body[..].to_vec();
            let prefix = (payload.len() as u32).to_be_bytes().to_vec();
            Response::ReplyVectored {
                segments: vec![prefix.into(), payload.into()],
                close: false,
            }
        },
    };
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
        let _stop = ShutdownOnDrop(stop.clone());
        let r = connect_tcp(v4).and_then(|s| framed_roundtrips(s, &[b"one" as &[u8], b"two", b"the third message"]));
        stop.shutdown();
        r
    });

    server.serve_forever().expect("serve_forever");
    let echoes = client.join().expect("thread join").expect("client io");
    assert_eq!(
        echoes,
        vec![b"one".to_vec(), b"two".to_vec(), b"the third message".to_vec(),]
    );
}

#[test]
fn unix_echo() {
    let dir = truenas_ros::tempdir().unwrap();
    let path = dir.path().join("echo.sock");
    let addr = ServerAddr::Unix(path.clone());
    let mut server = match Server::bind([addr], length_prefixed(PrefixWidth::U32, Endian::Big, false, echo)) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind: {e}"),
    };
    let stop = server.shutdown_handle();

    let cpath = path;
    let client = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone()); // fail fast on panic
        let r = connect_unix(&cpath).and_then(|s| framed_roundtrips(s, &[b"unix ping" as &[u8]]));
        stop.shutdown();
        r
    });

    server.serve_forever().expect("serve_forever");
    let echoes = client.join().expect("thread join").expect("client io");
    assert_eq!(echoes, vec![b"unix ping".to_vec()]);
}

#[test]
fn tcp_keepalive() {
    // Several messages on ONE connection - proves the connection is reused.
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let mut server = match Server::bind([addr], length_prefixed(PrefixWidth::U32, Endian::Big, false, echo)) {
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
        let msgs: &[&[u8]] = &[b"one", b"two", b"three", b"four"];
        let r = connect_tcp(v4).and_then(|s| framed_roundtrips(s, msgs));
        stop.shutdown();
        r
    });

    server.serve_forever().expect("serve_forever");
    let echoes = client.join().expect("thread join").expect("client io");
    assert_eq!(
        echoes,
        vec![b"one".to_vec(), b"two".to_vec(), b"three".to_vec(), b"four".to_vec()]
    );
}

#[test]
fn tcp_split_segments() {
    // Send the length prefix one byte at a time and the body in two halves, each write flushed with a gap - so
    // recv-header and recv-body each span multiple TCP segments. This passes only if MSG_WAITALL accumulates the short
    // reads in-kernel (without it, recv-header returns 1 < 4 -> close).
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let mut server = match Server::bind([addr], length_prefixed(PrefixWidth::U32, Endian::Big, false, echo)) {
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
        let r = (|| -> io::Result<Vec<u8>> {
            let mut s = connect_tcp(v4)?;
            s.set_nodelay(true)?; // one segment per write
            let payload: &[u8] = b"abcdefghij";
            for b in (payload.len() as u32).to_be_bytes() {
                s.write_all(&[b])?;
                s.flush()?;
                thread::sleep(Duration::from_millis(5));
            }
            s.write_all(&payload[..4])?;
            s.flush()?;
            thread::sleep(Duration::from_millis(5));
            s.write_all(&payload[4..])?;
            s.flush()?;
            recv_framed(&mut s)
        })();
        stop.shutdown();
        r
    });

    server.serve_forever().expect("serve_forever");
    let echo = client.join().expect("thread join").expect("client io");
    assert_eq!(echo, b"abcdefghij");
}

#[test]
fn tcp_many_concurrent() {
    // N concurrent clients, pool sized above N so none are shed. N > the kernel's MULTISHOT_MAX_RETRY (32) so the
    // multishot accept re-arms mid-run.
    const N: usize = 40;
    let cfg = ServerConfig {
        pool_size: 64,
        ..ServerConfig::default()
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let mut server = match Server::with_config([addr], cfg, length_prefixed(PrefixWidth::U32, Endian::Big, false, echo))
    {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind: {e}"),
    };
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();

    let coordinator = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone()); // fail fast on panic
        let clients: Vec<_> = (0..N).map(|i| thread::spawn(move || one_shot(v4, i))).collect();
        let results: Vec<io::Result<Vec<u8>>> = clients.into_iter().map(|c| c.join().unwrap()).collect();
        stop.shutdown();
        results
    });

    server.serve_forever().expect("serve_forever");
    let results = coordinator.join().expect("coordinator join");
    for (i, r) in results.into_iter().enumerate() {
        assert_eq!(r.expect("client io"), format!("req-{i}").into_bytes());
    }
}

#[test]
fn tcp_sequential_slot_reuse() {
    // Tiny pool, connections opened one at a time (never exceeding capacity) -- forces slot recycling and the per-slot
    // generation bump.
    const N: usize = 20;
    let cfg = ServerConfig {
        pool_size: 4,
        ..ServerConfig::default()
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let mut server = match Server::with_config([addr], cfg, length_prefixed(PrefixWidth::U32, Endian::Big, false, echo))
    {
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
        let echoes: Vec<_> = (0..N).map(|i| one_shot(v4, i)).collect();
        stop.shutdown();
        echoes
    });

    server.serve_forever().expect("serve_forever");
    let echoes = client.join().expect("thread join");
    for (i, r) in echoes.into_iter().enumerate() {
        assert_eq!(r.expect("client io"), format!("req-{i}").into_bytes());
    }
}

#[test]
fn tcp_bare_close_with_inflight_sibling_reuses_slot() {
    // SECURITY regression - fixed-slot reuse use-after-free / cross-connection corruption. When a connection is torn
    // down on a bare-CLOSE path while an op is still in flight on its descriptor, that op pins the kernel resource
    // node: the CLOSE frees the table slot and bitmap bit at issue and biases the next accept to that same index, but
    // the pinned op keeps the old socket and its buffers alive. A reuse-accept then reaches `accept_connection` and
    // overwrites the still-`Serving` slot (freed only at ops==0) - dropping the live connection under the in-flight op,
    // and, because the generation never bumps on reuse-without-free, later steering that op's completion onto whatever
    // connection now holds the slot. The fix cancels the in-flight op and defers the CLOSE until it reaps, so the slot
    // frees cleanly before any reuse-accept can land.
    //
    // Repro with a wide, deterministic window: a subscriber triggers a large push to itself, then half-closes its WRITE
    // side (the server's idle recv sees EOF -> PeerClosed, a bare close) while keeping its READ side open and never
    // reading - so the push send stalls in flight, pinning the slot indefinitely. A fresh echo then reuses the freed
    // index. Without the fix
    // the reuse corrupts the connection (wrong reply, a loop panic, or a hang);
    // with it, every echo gets its own correct reply and the server stays live.
    use std::net::Shutdown;
    use std::sync::Mutex;
    const ROUNDS: usize = 8;
    const PUSH: usize = 16 * 1024 * 1024; // stalls in flight (peer never reads it)
    let sub_handle: Arc<Mutex<Option<PushHandle>>> = Arc::new(Mutex::new(None));
    let cfg = ServerConfig {
        pool_size: 4,                       // small -> the freed index is reused
        max_send_backlog: 64 * 1024 * 1024, // keep the push queued, don't evict it
        ..ServerConfig::default()
    };
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(PrefixWidth::U32, Endian::Big, false),
        body: {
            let sub_handle = Arc::clone(&sub_handle);
            move |req: Request<'_, ()>| {
                let Request { body, responder, .. } = req;
                if &body[..] == b"sub" {
                    *sub_handle.lock().unwrap() = Some(responder.push_handle());
                    Response::Reply(echo_frame(b"ok"))
                } else if &body[..] == b"push" {
                    if let Some(h) = sub_handle.lock().unwrap().take() {
                        h.push(echo_frame(&vec![0x55u8; PUSH]));
                    }
                    Response::Reply(echo_frame(b"ok"))
                } else {
                    Response::Reply(echo_frame(&body)) // echo
                }
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
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();

    let client = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone()); // fail fast on panic
        (|| -> io::Result<()> {
            for i in 0..ROUNDS {
                // Subscribe, then push a large payload to ourselves; the server starts sending it and (keep-alive) arms
                // an idle recv.
                let mut sub = connect_tcp(v4)?;
                send_framed(&mut sub, b"sub")?;
                assert_eq!(recv_framed(&mut sub)?, b"ok");
                send_framed(&mut sub, b"push")?;
                assert_eq!(recv_framed(&mut sub)?, b"ok");
                // Half-close our WRITE side: the server's idle recv sees EOF -> PeerClosed, a bare close - but the
                // large push to us is still draining into our socket and we never read it, so its send stays in flight
                // and pins the descriptor.
                sub.shutdown(Shutdown::Write)?;
                thread::sleep(Duration::from_millis(15)); // let the bare close land
                // Reuse the just-freed index with a fresh echo; the reply must be its own, and the server must stay
                // healthy.
                let want = format!("echo-{i}");
                let mut c = connect_tcp(v4)?;
                send_framed(&mut c, want.as_bytes())?;
                assert_eq!(recv_framed(&mut c)?, want.as_bytes());
                drop(sub); // release the stalled subscriber before the next round
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
fn tcp_lsp_framing() {
    // LSP-style variable header: `Content-Length: N\r\n\r\n<body>`. The caller's `lsp_header` framer scans for
    // `\r\n\r\n` (via Framing::More chunk reads) then reads exactly N body bytes - a header the old fixed-size model
    // can't express. The body handler re-frames its reply the same way.
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: lsp_header,
        body: |req: Request<'_, ()>| {
            let Request { body, .. } = req;
            Response::Reply(
                format!("Content-Length: {}\r\n\r\n", body.len())
                    .into_bytes()
                    .into_iter()
                    .chain(body.iter().copied())
                    .collect::<Vec<u8>>(),
            )
        },
    };
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
        let r = (|| -> io::Result<Vec<u8>> {
            let mut s = connect_tcp(v4)?;
            let payload = b"{\"jsonrpc\":\"2.0\"}";
            write!(s, "Content-Length: {}\r\n\r\n", payload.len())?;
            s.write_all(payload)?;
            // Read the LSP reply: header up to \r\n\r\n, then Content-Length body.
            read_lsp(&mut s)
        })();
        stop.shutdown();
        r
    });

    server.serve_forever().expect("serve_forever");
    let body = client.join().expect("thread join").expect("client io");
    assert_eq!(body, b"{\"jsonrpc\":\"2.0\"}");
}

#[test]
fn tcp_stateful_counter() {
    // Per-connection state: `accept` creates a counter; the body handler bumps it and echoes its value, proving `&mut
    // U` reaches the handler and persists across keep-alive requests on the same connection.
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(0u32),
        header: length_prefix_header::<u32>(PrefixWidth::U32, Endian::Big, false),
        body: |req: Request<'_, u32>| {
            let Request { state: count, .. } = req;
            *count += 1;
            let n = *count;
            Response::Reply(
                (n.to_be_bytes().len() as u32)
                    .to_be_bytes()
                    .into_iter()
                    .chain(n.to_be_bytes())
                    .collect::<Vec<u8>>(),
            )
        },
    };
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
        let msgs: &[&[u8]] = &[b"a", b"b", b"c"];
        let r = connect_tcp(v4).and_then(|s| framed_roundtrips(s, msgs));
        stop.shutdown();
        r
    });

    server.serve_forever().expect("serve_forever");
    let replies = client.join().expect("thread join").expect("client io");
    let counts: Vec<u32> = replies
        .iter()
        .map(|r| u32::from_be_bytes(r[..4].try_into().unwrap()))
        .collect();
    assert_eq!(counts, vec![1, 2, 3]);
}

#[test]
fn tcp_deferred_offload() {
    // The body handler offloads work to another thread (standing in for a real pool) and returns `Response::Defer`,
    // freeing the server thread to keep polling. The worker computes the reply and hands it back via the `Deferred`;
    // the server sends it on the next wake, and keep-alive resumes -- proven by a second round-trip on the same
    // connection.
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(PrefixWidth::U32, Endian::Big, false),
        body: |req: Request<'_, ()>| {
            let Request { body, responder, .. } = req;
            // Move OWNED inputs to the worker - never a borrow of connection state - then detach the reply handle and
            // return to the loop.
            let input = body.to_vec();
            let (deferred, permit) = responder.defer();
            thread::spawn(move || {
                // Simulate work that must not block the ring thread.
                thread::sleep(Duration::from_millis(10));
                let out = input.to_ascii_uppercase();
                deferred.reply(echo_frame(&out));
            });
            Response::Defer(permit)
        },
    };
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
        let msgs: &[&[u8]] = &[b"hello", b"world"];
        let r = connect_tcp(v4).and_then(|s| framed_roundtrips(s, msgs));
        stop.shutdown();
        r
    });

    server.serve_forever().expect("serve_forever");
    let replies = client.join().expect("thread join").expect("client io");
    assert_eq!(replies, vec![b"HELLO".to_vec(), b"WORLD".to_vec()]);
}

#[test]
fn tcp_deferred_drop_closes() {
    // A lost/panicked worker: the handler detaches a `Deferred` and drops it without replying. Its Drop must close the
    // parked connection rather than leak the pool slot, so the client sees a clean EOF.
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(PrefixWidth::U32, Endian::Big, false),
        body: |req: Request<'_, ()>| {
            let Request { responder, .. } = req;
            // Detached then dropped without replying (the lost worker).
            let (_deferred, permit) = responder.defer();
            Response::Defer(permit)
        },
    };
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
        let r = (|| -> io::Result<Vec<u8>> {
            let mut s = connect_tcp(v4)?;
            let _ = send_framed(&mut s, b"hi"); // may race the close; ignore
            let mut buf = Vec::new();
            s.read_to_end(&mut buf)?; // dropped Deferred closed us -> EOF
            Ok(buf)
        })();
        stop.shutdown();
        r
    });

    server.serve_forever().expect("serve_forever");
    match client.join().expect("thread join") {
        Ok(buf) => assert!(buf.is_empty(), "expected clean EOF, got {buf:?}"),
        Err(e) => assert_eq!(e.kind(), io::ErrorKind::ConnectionReset),
    }
}

#[test]
fn tcp_redelivered_request() {
    // A body handler stashes the request in its connection state, defers, and the worker asks for a SECOND delivery via
    // `Deferred::redeliver` instead of supplying bytes - the pattern protocol glue (http) uses to complete a parked
    // request on the server thread. The rerun sees the stash, replies, and keep-alive continues: two messages each make
    // the full park-and-redeliver round trip on one connection.
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    type Stash = Option<Vec<u8>>;
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(None::<Vec<u8>>),
        header: length_prefix_header::<Stash>(PrefixWidth::U32, Endian::Big, false),
        body: |req: Request<'_, Stash>| {
            let Request {
                body, responder, state, ..
            } = req;
            match state.take() {
                // Second delivery: the frame is empty; answer from the stash.
                Some(stashed) => Response::Reply(echo_frame(&stashed.to_ascii_uppercase())),
                // First delivery: retain the request, park, redeliver later.
                None => {
                    *state = Some(body.to_vec());
                    let (deferred, permit) = responder.defer();
                    thread::spawn(move || {
                        thread::sleep(Duration::from_millis(10));
                        deferred.redeliver();
                    });
                    Response::Defer(permit)
                }
            }
        },
    };
    let mut server = match Server::bind([addr], proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind: {e}"),
    };
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stats = server.stats_handle();
    let stop = server.shutdown_handle();

    let client = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone()); // fail fast on panic
        let msgs: &[&[u8]] = &[b"hello", b"world"];
        let r = connect_tcp(v4).and_then(|s| framed_roundtrips(s, msgs));
        stop.shutdown();
        r
    });

    server.serve_forever().expect("serve_forever");
    let replies = client.join().expect("thread join").expect("client io");
    assert_eq!(replies, vec![b"HELLO".to_vec(), b"WORLD".to_vec()]);
    // Each message was delivered twice (park, then redelivery) and answered exactly once.
    let s = stats.snapshot();
    assert_eq!(s.requests, 4, "two deliveries per message");
    assert_eq!(s.deferred, 2, "one park per message");
    assert_eq!(s.replies, 2, "one reply per message");
}

#[test]
fn tcp_stale_redeliver_dropped() {
    // A handler answers INLINE while leaking a `Deferred` whose worker later calls `redeliver()`. The request was never
    // opened as deferred, so the late redelivery must be inert - no extra handler run, no extra reply -- and the
    // connection stays healthy for a second round trip.
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(PrefixWidth::U32, Endian::Big, false),
        body: |req: Request<'_, ()>| {
            let Request { body, responder, .. } = req;
            let reply = echo_frame(&body);
            let (deferred, permit) = responder.defer();
            let _ = permit; // answered inline: the Deferred goes stale
            thread::spawn(move || {
                thread::sleep(Duration::from_millis(30));
                deferred.redeliver();
            });
            Response::Reply(reply)
        },
    };
    let mut server = match Server::bind([addr], proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind: {e}"),
    };
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stats = server.stats_handle();
    let stop = server.shutdown_handle();

    let client = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone()); // fail fast on panic
        let r = (|| -> io::Result<Vec<u8>> {
            let mut s = connect_tcp(v4)?;
            let first = framed_roundtrips(&mut s, &[b"one"])?;
            // Let the stale redeliver fire against the answered request.
            thread::sleep(Duration::from_millis(60));
            let second = framed_roundtrips(&mut s, &[b"two"])?;
            Ok([first, second].concat().concat())
        })();
        stop.shutdown();
        r
    });

    server.serve_forever().expect("serve_forever");
    let bytes = client.join().expect("thread join").expect("client io");
    assert_eq!(bytes, b"onetwo".to_vec());
    // The stale redelivery ran no handler and sent nothing.
    let s = stats.snapshot();
    assert_eq!(s.requests, 2, "no handler rerun from the stale redeliver");
    assert_eq!(s.replies, 2);
}

/// Borrow a furnished detach fd as a BLOCKING stream WITHOUT owning it - the `Detached` handle owns and closes it, so
/// this must not (hence `ManuallyDrop`, whose drop is a no-op). The fd inherits the pool socket's non-blocking mode, so
/// a blocking op must clear it first.
fn detach_stream(fd: std::os::fd::RawFd) -> ManuallyDrop<TcpStream> {
    // SAFETY: `fd` aliases a live socket; wrapped non-owningly (ManuallyDrop).
    let s = ManuallyDrop::new(unsafe { TcpStream::from_raw_fd(fd) });
    s.set_nonblocking(false).expect("blocking mode");
    s
}

#[test]
fn tcp_detach_resume() {
    // A body handler DETACHES the connection: the server furnishes a real fd to a worker that does blocking I/O on the
    // socket, then RESUMES serving. The worker echoes 5 raw bytes off the fd (proving the fd is usable); after resume
    // the connection keeps serving with its per-connection state intact (the request counter), proven by a framed
    // round-trip returning `2:ping`.
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(0u32),
        header: length_prefix_header::<u32>(PrefixWidth::U32, Endian::Big, false),
        body: |req: Request<'_, u32>| {
            let Request {
                body, state, responder, ..
            } = req;
            *state += 1;
            if &body[..] == b"detach" {
                Response::Detach(responder.detach())
            } else {
                let mut out = format!("{}:", *state).into_bytes();
                out.extend_from_slice(&body[..]);
                Response::Reply(echo_frame(&out))
            }
        },
    };
    let mut server = match Server::bind([addr], proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind: {e}"),
    };
    server.set_detach_handler(|_ctx, detached| {
        thread::spawn(move || {
            let mut s = detach_stream(detached.raw_fd());
            let mut buf = [0u8; 5];
            s.read_exact(&mut buf).expect("worker read");
            s.write_all(&buf).expect("worker write");
            detached.resume();
        });
    });
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();

    let client = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone());
        let r = (|| -> io::Result<Vec<u8>> {
            let mut s = connect_tcp(v4)?;
            send_framed(&mut s, b"detach")?; // triggers detach (counter -> 1)
            s.write_all(b"raw12")?; // raw exchange with the hijack worker
            let mut echo = [0u8; 5];
            s.read_exact(&mut echo)?;
            assert_eq!(&echo, b"raw12", "worker echo");
            send_framed(&mut s, b"ping")?; // resumed serving (counter -> 2)
            recv_framed(&mut s)
        })();
        stop.shutdown();
        r
    });

    server.serve_forever().expect("serve_forever");
    let reply = client.join().expect("thread join").expect("client io");
    assert_eq!(reply, b"2:ping", "keep-alive resumed with U intact");
}

#[test]
fn tcp_detach_resume_restores_nonblocking() {
    // The furnished fd shares the pool socket's FILE DESCRIPTION, so a worker clearing O_NONBLOCK for its blocking
    // transfer (as any blocking helper does) would otherwise leave the resumed connection's socket blocking -- silently
    // disabling the splice path's EAGAIN -> readiness-poll slow-loris guard (`tcp_splice_read` takes its wait mode from
    // the file's O_NONBLOCK). `Detached::resume` must restore the flag itself. Observed through a worker-held dup() of
    // the furnished fd: same file description, still open after resume consumes the handle.
    let (flag_tx, flag_rx) = std::sync::mpsc::channel::<bool>();
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(PrefixWidth::U32, Endian::Big, false),
        body: |req: Request<'_, ()>| {
            if &req.body[..] == b"detach" {
                Response::Detach(req.responder.detach())
            } else {
                Response::Reply(echo_frame(&req.body))
            }
        },
    };
    let mut server = match Server::bind([addr], proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind: {e}"),
    };
    server.set_detach_handler(move |_ctx, detached| {
        let flag_tx = flag_tx.clone();
        thread::spawn(move || {
            let raw = detached.raw_fd();
            // SAFETY: dup a live fd; the dup shares the file description.
            let alias = unsafe { libc::dup(raw) };
            assert!(alias >= 0, "dup");
            // The blocking-transfer pattern: clear O_NONBLOCK, do the work.
            let _s = detach_stream(raw); // set_nonblocking(false)
            detached.resume();
            // resume() restored O_NONBLOCK on the shared description before signaling; the alias observes it.
            // SAFETY: fcntl on the live dup; then close it.
            let restored = unsafe {
                let fl = libc::fcntl(alias, libc::F_GETFL);
                let ok = fl >= 0 && fl & libc::O_NONBLOCK != 0;
                libc::close(alias);
                ok
            };
            let _ = flag_tx.send(restored);
        });
    });
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();

    let client = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone());
        let r = (|| -> io::Result<Vec<u8>> {
            let mut s = connect_tcp(v4)?;
            send_framed(&mut s, b"detach")?;
            // Worker resumes immediately; serving continues on the same conn.
            send_framed(&mut s, b"ping")?;
            recv_framed(&mut s)
        })();
        stop.shutdown();
        r
    });

    server.serve_forever().expect("serve_forever");
    let reply = client.join().expect("thread join").expect("client io");
    assert_eq!(reply, b"ping", "keep-alive after detach/resume");
    assert!(
        flag_rx.recv().expect("worker flag"),
        "resume() must restore O_NONBLOCK on the shared file description"
    );
}

#[test]
fn tcp_detach_close() {
    // Detach, then the worker CLOSES the connection instead of resuming (e.g. a one-shot transfer on a dedicated
    // connection): the client sees a clean EOF.
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(PrefixWidth::U32, Endian::Big, false),
        body: |req: Request<'_, ()>| Response::Detach(req.responder.detach()),
    };
    let mut server = match Server::bind([addr], proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind: {e}"),
    };
    server.set_detach_handler(|_ctx, detached| {
        thread::spawn(move || {
            let mut s = detach_stream(detached.raw_fd());
            let mut buf = [0u8; 5];
            let _ = s.read_exact(&mut buf); // uses the fd; may race, ignore
            detached.close();
        });
    });
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();

    let client = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone());
        let r = (|| -> io::Result<Vec<u8>> {
            let mut s = connect_tcp(v4)?;
            send_framed(&mut s, b"detach")?;
            let _ = s.write_all(b"raw12");
            let mut buf = Vec::new();
            s.read_to_end(&mut buf)?; // worker close() -> EOF
            Ok(buf)
        })();
        stop.shutdown();
        r
    });

    server.serve_forever().expect("serve_forever");
    match client.join().expect("thread join") {
        Ok(buf) => assert!(buf.is_empty(), "expected clean EOF, got {buf:?}"),
        Err(e) => assert_eq!(e.kind(), io::ErrorKind::ConnectionReset),
    }
}

#[test]
fn tcp_detach_drop_closes() {
    // A lost/panicked detach worker: the handler moves the `Detached` to a thread that drops it without resume/close.
    // Its Drop must close the parked connection rather than leak the pool slot, so the client sees a clean EOF.
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(PrefixWidth::U32, Endian::Big, false),
        body: |req: Request<'_, ()>| Response::Detach(req.responder.detach()),
    };
    let mut server = match Server::bind([addr], proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind: {e}"),
    };
    server.set_detach_handler(|_ctx, detached| {
        thread::spawn(move || {
            drop(detached); // lost worker -> Drop closes the connection
        });
    });
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();

    let client = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone());
        let r = (|| -> io::Result<Vec<u8>> {
            let mut s = connect_tcp(v4)?;
            let _ = send_framed(&mut s, b"detach");
            let mut buf = Vec::new();
            s.read_to_end(&mut buf)?; // dropped Detached closed us -> EOF
            Ok(buf)
        })();
        stop.shutdown();
        r
    });

    server.serve_forever().expect("serve_forever");
    match client.join().expect("thread join") {
        Ok(buf) => assert!(buf.is_empty(), "expected clean EOF, got {buf:?}"),
        Err(e) => assert_eq!(e.kind(), io::ErrorKind::ConnectionReset),
    }
}

#[test]
fn tcp_deferred_worker_close_ends_the_connection() {
    // `Deferred::close` is the worker deciding the request is fatal - distinct from dropping the handle, which closes
    // only because a lost worker must not leak the parked slot. Both end the connection and both report `WorkerClosed`,
    // so a test of the drop path says nothing about whether the deliberate one works. The close is also final: a
    // request answered this way is gone, so the pipelined follower behind it is not served.
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(PrefixWidth::U32, Endian::Big, false),
        body: |req: Request<'_, ()>| {
            let Request { body, responder, .. } = req;
            if &body[..] == b"fatal" {
                let (deferred, permit) = responder.defer();
                thread::spawn(move || {
                    thread::sleep(Duration::from_millis(10));
                    deferred.close(); // deliberate, not a dropped handle
                });
                Response::Defer(permit)
            } else {
                Response::Reply(echo_frame(&body))
            }
        },
    };
    let mut server = match Server::bind([addr], proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind: {e}"),
    };
    let reasons = close_reason_channel(&mut server);
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();

    let client = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone());
        let r = (|| -> io::Result<Vec<u8>> {
            let mut s = connect_tcp(v4)?;
            send_framed(&mut s, b"ping")?;
            assert_eq!(recv_framed(&mut s)?, b"ping", "serving before the close");
            let _ = send_framed(&mut s, b"fatal");
            let mut tail = Vec::new();
            s.read_to_end(&mut tail)?;
            Ok(tail)
        })();
        stop.shutdown();
        r
    });

    server.serve_forever().expect("serve_forever");
    match client.join().expect("thread join") {
        Ok(tail) => assert!(tail.is_empty(), "a closed request must send nothing, got {tail:?}"),
        Err(e) => assert_eq!(e.kind(), io::ErrorKind::ConnectionReset),
    }
    assert_eq!(
        reasons.try_recv().ok(),
        Some(CloseReason::WorkerClosed),
        "a worker-side close is reported as WorkerClosed",
    );
}

#[test]
fn handle_types_are_debug() {
    // The reply/push/detach handles are what a consumer holds when something goes wrong in its own worker, so they are
    // what lands in its logs. Each is `finish_non_exhaustive` and each deliberately withholds its channel and routing
    // token - a `Debug` that printed the token would put a forgeable routing capability in a log file.
    use std::sync::mpsc;
    let (seen_tx, seen_rx) = mpsc::channel::<(&'static str, String)>();
    let worker_tx = seen_tx.clone();
    let detach_tx = seen_tx.clone();
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(PrefixWidth::U32, Endian::Big, false),
        body: move |req: Request<'_, ()>| {
            let Request { body, responder, .. } = req;
            if &body[..] == b"detach" {
                return Response::Detach(responder.detach());
            }
            // `push_handle` borrows, so it can be minted before `defer` consumes the responder.
            let push = responder.push_handle();
            let _ = seen_tx.send(("push", format!("{push:?}")));
            let _ = seen_tx.send(("responder", format!("{responder:?}")));
            let (deferred, permit) = responder.defer();
            let worker_tx = worker_tx.clone();
            thread::spawn(move || {
                let _ = worker_tx.send(("deferred", format!("{deferred:?}")));
                deferred.reply(echo_frame(b"ok"));
            });
            Response::Defer(permit)
        },
    };
    let mut server = match Server::bind([addr], proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind: {e}"),
    };
    server.set_detach_handler(move |_ctx, detached| {
        let _ = detach_tx.send(("detached", format!("{detached:?}")));
        detached.close();
    });
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();

    let client = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone());
        let r = (|| -> io::Result<()> {
            let mut s = connect_tcp(v4)?;
            send_framed(&mut s, b"handles")?;
            assert_eq!(recv_framed(&mut s)?, b"ok");
            let _ = send_framed(&mut s, b"detach");
            let mut tail = Vec::new();
            let _ = s.read_to_end(&mut tail);
            Ok(())
        })();
        stop.shutdown();
        r
    });

    server.serve_forever().expect("serve_forever");
    client.join().expect("thread join").expect("client io");

    let seen: std::collections::HashMap<&str, String> = seen_rx.try_iter().collect();
    for name in ["responder", "deferred", "push", "detached"] {
        let rendered = seen.get(name).unwrap_or_else(|| panic!("{name} was never formatted"));
        assert!(
            rendered.ends_with(".. }"),
            "{name}'s Debug must stay non-exhaustive: {rendered}"
        );
        assert!(
            !rendered.contains("token") && !rendered.contains("Token"),
            "{name}'s Debug must not print its routing token: {rendered}"
        );
    }
    assert!(
        seen["responder"].starts_with("Responder {"),
        "unexpected shape: {}",
        seen["responder"]
    );
    assert!(
        seen["deferred"].starts_with("Deferred {"),
        "unexpected shape: {}",
        seen["deferred"]
    );
    // The routable handles name their slot, which is what makes one log line traceable to one connection.
    for name in ["push", "detached"] {
        assert!(
            seen[name].contains("slot"),
            "{name}'s Debug should name its slot: {}",
            seen[name]
        );
    }
}

#[test]
fn push_of_an_empty_payload_is_a_no_op() {
    // An empty push is dropped at the handle rather than travelling to the loop, so it never reaches the send queue.
    // That matters because the server frames nothing itself: a zero-length PDU handed to the socket would be an empty
    // write the peer cannot distinguish from a stall, and a queued empty push would still consume backlog accounting.
    // The client must see exactly the one real push.
    use std::sync::Mutex;
    let stash: Arc<Mutex<Option<PushHandle>>> = Arc::new(Mutex::new(None));
    let for_body = Arc::clone(&stash);
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(PrefixWidth::U32, Endian::Big, false),
        body: move |req: Request<'_, ()>| {
            *for_body.lock().unwrap() = Some(req.responder.push_handle());
            Response::Reply(echo_frame(b"ok"))
        },
    };
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
        let _stop = ShutdownOnDrop(stop.clone());
        let r = (|| -> io::Result<Vec<u8>> {
            let mut s = connect_tcp(v4)?;
            send_framed(&mut s, b"sub")?;
            assert_eq!(recv_framed(&mut s)?, b"ok");
            let push = stash.lock().unwrap().clone().expect("stashed handle");
            push.push(Vec::new()); // dropped at the handle
            push.push(echo_frame(b"real"));
            // If the empty push had been queued it would arrive first and this frame read would desynchronise.
            recv_framed(&mut s)
        })();
        stop.shutdown();
        r
    });

    server.serve_forever().expect("serve_forever");
    let got = client.join().expect("thread join").expect("client io");
    assert_eq!(got, b"real", "an empty push must not reach the wire");
}
