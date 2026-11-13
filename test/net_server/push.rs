use super::*;

#[test]
fn tcp_one_way_notification() {
    // `Response::Reply` with an empty body is a one-way message, so the connection stays open and the next request is
    // served. `tcp_builder_close_and_one_way` covers the `length_prefixed` builder.
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(PrefixWidth::U32, Endian::Big, false),
        body: |req: Request<'_, ()>| {
            let Request { body, .. } = req;
            if &body[..] == b"notify" {
                Response::Reply(Vec::new()) // one-way: no bytes sent
            } else {
                Response::Reply(echo_frame(&body))
            }
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
        let r = (|| -> io::Result<Vec<u8>> {
            let mut s = connect_tcp(v4)?;
            send_framed(&mut s, b"notify")?; // no reply expected
            send_framed(&mut s, b"ping")?;
            recv_framed(&mut s) // must be the ping echo, not a close
        })();
        stop.shutdown();
        r
    });

    server.serve_forever().expect("serve_forever");
    let got = client.join().expect("thread join").expect("client io");
    assert_eq!(got, b"ping");
}

#[test]
fn tcp_builder_close_and_one_way() {
    // The `length_prefixed` builder's Option contract: `Some(empty)` is the one-way case (sends nothing, keeps
    // serving - same as Response::Reply's documented empty semantics), `None` is the close signal.
    use std::sync::Mutex;
    let reasons = Arc::new(Mutex::new(Vec::new()));
    let proto = length_prefixed(
        PrefixWidth::U32,
        Endian::Big,
        false,
        |_h: &[u8], body: &[u8], _p: &ClientAddr| match body {
            b"notify" => Some(Vec::new()), // one-way: no bytes sent
            b"quit" => None,               // close signal
            _ => Some(echo_frame(body)),
        },
    );
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let mut server = match Server::bind([addr], proto) {
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
            let mut s = connect_tcp(v4)?;
            send_framed(&mut s, b"notify")?; // no reply expected
            send_framed(&mut s, b"ping")?;
            assert_eq!(recv_framed(&mut s)?, b"ping", "served past one-way");
            send_framed(&mut s, b"quit")?;
            let mut b = [0u8; 1];
            assert_eq!(s.read(&mut b)?, 0, "None must close");
            Ok(())
        })()
        .expect("client io");
        stop.shutdown();
    });

    server.serve_forever().expect("serve_forever");
    client.join().expect("thread join");
    let got = reasons.lock().unwrap().clone();
    assert!(
        got.contains(&CloseReason::HandlerClosed),
        "expected HandlerClosed from None, got {got:?}"
    );
}

#[test]
fn tcp_length_prefix_overflow_rejected() {
    // A u64 length prefix of !0 must not wrap the header and body total past the `TooLarge` guard in release or panic
    // the loop in debug. It must close that connection as `TooLarge` and keep serving others.
    use std::sync::Mutex;
    let reasons = Arc::new(Mutex::new(Vec::new()));
    let proto = length_prefixed(PrefixWidth::U64, Endian::Big, false, echo);
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let mut server = match Server::bind([addr], proto) {
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
        let r = (|| -> io::Result<Vec<u8>> {
            let mut s = connect_tcp(v4)?;
            s.write_all(&u64::MAX.to_be_bytes())?;
            // The server must close this connection (TooLarge), not crash.
            let mut b = [0u8; 1];
            assert_eq!(s.read(&mut b)?, 0, "expected EOF after bogus prefix");
            // ...and still serve a fresh connection (8-byte U64 framing in, `echo`'s 4-byte framing back).
            let mut ok = connect_tcp(v4)?;
            ok.write_all(&4u64.to_be_bytes())?;
            ok.write_all(b"ping")?;
            recv_framed(&mut ok)
        })();
        stop.shutdown();
        r
    });

    server.serve_forever().expect("serve_forever");
    let got = client.join().expect("thread join").expect("client io");
    assert_eq!(got, b"ping");
    let reasons = reasons.lock().unwrap().clone();
    assert!(
        reasons.contains(&CloseReason::TooLarge),
        "expected TooLarge, got {reasons:?}"
    );
}

#[test]
fn tcp_need_overflow_rejected() {
    // A custom framer that echoes a hostile wire length as `Framing::Need(n)` (the LSP pattern with an unvalidated
    // Content-Length): the server must bound the requested read against max_request_bytes up front - both the
    // overflowing and the merely-huge shape - not allocate n bytes.
    use std::sync::Mutex;
    let reasons = Arc::new(Mutex::new(Vec::new()));
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: |buf: &[u8], _state: &mut ()| match buf.first() {
            None => Framing::Need(1),
            Some(b'o') => Framing::Need(usize::MAX), // overflows buffered + n
            Some(_) => Framing::Need(1024 * 1024),   // buffered + n > max
        },
        body: |req: Request<'_, ()>| Response::Reply(echo_frame(&req.body)),
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let mut server = match Server::bind([addr], proto) {
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
            for first_byte in [b"o", b"b"] {
                let mut s = connect_tcp(v4)?;
                s.write_all(first_byte)?;
                let mut b = [0u8; 1];
                assert_eq!(s.read(&mut b)?, 0, "expected EOF after hostile Need");
            }
            Ok(())
        })()
        .expect("client io");
        stop.shutdown();
    });

    server.serve_forever().expect("serve_forever");
    client.join().expect("thread join");
    let got = reasons.lock().unwrap().clone();
    assert_eq!(
        got.iter().filter(|r| **r == CloseReason::TooLarge).count(),
        2,
        "expected both hostile Needs to close TooLarge, got {got:?}"
    );
}

#[test]
fn tcp_stale_deferred_dropped() {
    // A handler that mints a Deferred but then answers inline: the worker's late reply is for a request that was
    // already answered, so it must be dropped (per-request token gating) - not sent as a spurious extra PDU, and its
    // Drop-close must not kill the healthy connection.
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(PrefixWidth::U32, Endian::Big, false),
        body: |req: Request<'_, ()>| {
            let Request { responder, .. } = req;
            let (deferred, _permit) = responder.defer();
            thread::spawn(move || {
                thread::sleep(Duration::from_millis(30));
                deferred.reply(echo_frame(b"late")); // must be dropped
            });
            Response::Reply(echo_frame(b"inline"))
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
        let r = (|| -> io::Result<(Vec<u8>, Vec<u8>)> {
            let mut s = connect_tcp(v4)?;
            send_framed(&mut s, b"one")?;
            let first = recv_framed(&mut s)?;
            // Give the stale worker reply time to arrive (and be dropped).
            thread::sleep(Duration::from_millis(80));
            send_framed(&mut s, b"two")?;
            let second = recv_framed(&mut s)?;
            Ok((first, second))
        })();
        stop.shutdown();
        r
    });

    server.serve_forever().expect("serve_forever");
    let (first, second) = client.join().expect("thread join").expect("io");
    assert_eq!(first, b"inline");
    // If the stale reply had been enqueued, this would read "late".
    assert_eq!(second, b"inline");
}

#[test]
fn tcp_mismatched_defer_permit_closes() {
    // A DeferPermit is stamped with its request's token and verified at delivery: stashing one and returning it for a
    // LATER request (whose own defer() was never called) must close the connection - not park a request nothing can
    // ever resolve, wedging the slot until shutdown.
    use std::sync::Mutex;
    let reasons = Arc::new(Mutex::new(Vec::new()));
    struct Stash {
        pair: Option<(Deferred, DeferPermit)>,
    }
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(Stash { pair: None }),
        header: length_prefix_header::<Stash>(PrefixWidth::U32, Endian::Big, false),
        body: |req: Request<'_, Stash>| {
            let Request {
                body, state, responder, ..
            } = req;
            if &body[..] == b"mint" {
                // Keeping the `Deferred` in the stash keeps its drop-close from firing, and it goes stale once this
                // reply answers the request.
                state.pair = Some(responder.defer());
                Response::Reply(echo_frame(b"ok"))
            } else {
                let (deferred, stale_permit) = state.pair.take().unwrap();
                drop(deferred); // stale token: its Drop-close is inert
                Response::Defer(stale_permit) // wrong request's permit
            }
        },
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let mut server = match Server::bind([addr], proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind: {e}"),
    };
    {
        let reasons = Arc::clone(&reasons);
        server.set_close_hook(move |_addr, reason, _state: &mut Stash| {
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
            let mut s = connect_tcp(v4)?;
            // Bound the read: a wedged (parked-forever) connection must fail the test, not hang it.
            s.set_read_timeout(Some(Duration::from_secs(5)))?;
            send_framed(&mut s, b"mint")?;
            assert_eq!(recv_framed(&mut s)?, b"ok");
            send_framed(&mut s, b"boom")?;
            let mut b = [0u8; 1];
            assert_eq!(s.read(&mut b)?, 0, "expected close on mismatched permit");
            Ok(())
        })()
        .expect("client io");
        stop.shutdown();
    });

    server.serve_forever().expect("serve_forever");
    client.join().expect("thread join");
    let got = reasons.lock().unwrap().clone();
    assert!(
        got.contains(&CloseReason::HandlerClosed),
        "expected HandlerClosed, got {got:?}"
    );
}

#[test]
fn tcp_reuse_port_and_options() {
    // SO_REUSEPORT: a second server binds the same address iff both set the flag (otherwise EADDRINUSE). Also
    // smoke-tests the other socket options (nodelay is default-on; keepalive + TCP_USER_TIMEOUT set here).
    let cfg = ServerConfig {
        reuse_port: true,
        keepalive: Some(Duration::from_secs(30)),
        tcp_user_timeout: Some(Duration::from_secs(10)),
        ..ServerConfig::default()
    };
    let proto = || length_prefixed(PrefixWidth::U32, Endian::Big, false, echo);
    let mut server = match Server::with_config(
        [ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap())],
        cfg,
        proto(),
    ) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind: {e}"),
    };
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };

    // A second bind to the same port must succeed with `reuse_port`.
    //
    // `with_config` also sets up a ring, and a second ring needs contiguous high-order pages, which fail `ENOMEM` where
    // ARC holds most of RAM. `should_skip` answers that as environmental, and `TRUENAS_ROS_REQUIRE_IO_URING` turns it
    // red where it must not happen. The message names the call, because `bind(2)` is not what refused.
    let second = match Server::with_config([ServerAddr::Tcp(v4)], cfg, proto()) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("reuse_port second Server::with_config: {e}"),
    };
    // It is dropped before any client connects, so the kernel cannot route our test connection into its unserved
    // backlog.
    drop(second);

    // Without the flag the same bind fails with EADDRINUSE.
    //
    // `Server::bind` sets a ring up as well, so it can answer the same environmental `ENOMEM`, and must be screened
    // through `should_skip` before the errno is judged.
    let dup = Server::bind(
        [ServerAddr::Tcp(v4)],
        length_prefixed(PrefixWidth::U32, Endian::Big, false, echo),
    );
    if let Err(e) = &dup
        && should_skip(e)
    {
        return;
    }
    assert!(
        matches!(dup, Err(Error::Errno(Errno::EADDRINUSE))),
        "expected EADDRINUSE, got {dup:?}"
    );

    let stop = server.shutdown_handle();
    let client = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone()); // fail fast on panic
        let r = connect_tcp(v4).and_then(|s| framed_roundtrips(s, &[b"opts" as &[u8]]));
        stop.shutdown();
        r
    });
    server.serve_forever().expect("serve_forever");
    let echoes = client.join().expect("thread join").expect("client io");
    assert_eq!(echoes, vec![b"opts".to_vec()]);
}

#[test]
fn unix_peercred_auth() {
    // With `unix_peercred`, the accept handler receives the peer's `SO_PEERCRED`, fetched with an io_uring socket
    // command on `AF_UNIX` (Linux >= 6.18.16), and can authenticate on it. The body echoes the credentials back and the
    // client checks them against its real ids.
    let dir = truenas_ros::tempdir().unwrap();
    let path = dir.path().join("cred.sock");
    let cfg = ServerConfig {
        unix_peercred: true,
        ..ServerConfig::default()
    };
    let proto = Protocol {
        // Authenticate: only our own uid gets in; keep the creds as state.
        accept: |inc: Incoming<'_>| match inc.peer {
            ClientAddr::Unix { cred: Some(c) } => Some(*c),
            _ => None,
        },
        header: length_prefix_header::<PeerCred>(PrefixWidth::U32, Endian::Big, false),
        body: |req: Request<'_, PeerCred>| {
            let Request { state: cred, .. } = req;
            Response::Reply(echo_frame(format!("{}:{}:{}", cred.pid, cred.uid, cred.gid).as_bytes()))
        },
    };
    let mut server = match Server::with_config([ServerAddr::Unix(path.clone())], cfg, proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) || peercred_unsupported(&e) => return,
        Err(e) => panic!("bind: {e}"),
    };
    let stop = server.shutdown_handle();

    let client = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone()); // fail fast on panic
        let r = connect_unix(&path).and_then(|mut s| {
            send_framed(&mut s, b"who am i")?;
            recv_framed(&mut s)
        });
        stop.shutdown();
        r
    });

    server.serve_forever().expect("serve_forever");
    let reply = client.join().expect("thread join").expect("client io");
    let text = String::from_utf8(reply).expect("utf8");
    let mut parts = text.split(':');
    let pid: i32 = parts.next().unwrap().parse().unwrap();
    let uid: u32 = parts.next().unwrap().parse().unwrap();
    let gid: u32 = parts.next().unwrap().parse().unwrap();
    // SAFETY: getuid/getgid/getpid are trivially safe.
    unsafe {
        assert_eq!(pid, libc::getpid(), "peer pid");
        assert_eq!(uid, libc::getuid(), "peer uid");
        assert_eq!(gid, libc::getgid(), "peer gid");
    }
}

#[test]
fn tcp_push_pub_sub() {
    // A subscriber stashes its `PushHandle` and a publisher's request pushes to it. Once the subscriber disconnects,
    // pushes are dropped harmlessly and the publisher keeps working.
    use std::sync::Mutex;
    let sub_handle: Arc<Mutex<Option<PushHandle>>> = Arc::new(Mutex::new(None));
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(PrefixWidth::U32, Endian::Big, false),
        body: {
            let sub_handle = Arc::clone(&sub_handle);
            move |req: Request<'_, ()>| {
                let Request { body, responder, .. } = req;
                if &body[..] == b"sub" {
                    *sub_handle.lock().unwrap() = Some(responder.push_handle());
                    Response::Reply(echo_frame(b"subscribed"))
                } else if let Some(msg) = body.strip_prefix(b"pub:") {
                    if let Some(h) = sub_handle.lock().unwrap().as_ref() {
                        h.push(echo_frame(msg)); // unsolicited PDU to the sub
                    }
                    Response::Reply(echo_frame(b"published"))
                } else {
                    Response::Reply(echo_frame(&body))
                }
            }
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
            let mut sub = connect_tcp(v4)?;
            send_framed(&mut sub, b"sub")?;
            assert_eq!(recv_framed(&mut sub)?, b"subscribed");

            let mut publisher = connect_tcp(v4)?;
            send_framed(&mut publisher, b"pub:event-1")?;
            assert_eq!(recv_framed(&mut publisher)?, b"published");
            // The unsolicited push arrives on the subscriber's connection.
            assert_eq!(recv_framed(&mut sub)?, b"event-1");

            drop(sub);
            thread::sleep(Duration::from_millis(50)); // let the close land
            send_framed(&mut publisher, b"pub:event-2")?;
            assert_eq!(recv_framed(&mut publisher)?, b"published");
            send_framed(&mut publisher, b"ping")?;
            assert_eq!(recv_framed(&mut publisher)?, b"ping");
            Ok(())
        })()
        .expect("client io");
        stop.shutdown();
    });

    server.serve_forever().expect("serve_forever");
    client.join().expect("thread join");
}

#[test]
fn tcp_push_backlog_evicts() {
    // A subscriber that stops reading has pushes accumulate until `max_send_backlog`, then is evicted with
    // `SendBacklog`.
    use std::sync::Mutex;
    // Each push must exceed what the kernel alone absorbs, a send buffer autotuned up to `tcp_wmem[2]` plus the peer's
    // initial window, or a fully absorbed WAITALL send completes and leaves the queue empty. At 32 MiB the first push
    // is still queued when the second arrives, since `queued_bytes` counts the whole front PDU until sent, so the
    // second overflows the cap.
    const PUSH: usize = 32 * 1024 * 1024;
    let sub_handle: Arc<Mutex<Option<PushHandle>>> = Arc::new(Mutex::new(None));
    let reasons = Arc::new(Mutex::new(Vec::new()));
    let cfg = ServerConfig {
        max_send_backlog: PUSH + PUSH / 2, // between one and two pushes
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
                    if let Some(h) = sub_handle.lock().unwrap().as_ref() {
                        h.push(echo_frame(&vec![0x55; PUSH]));
                    }
                    Response::Reply(echo_frame(b"ok"))
                } else {
                    Response::Reply(echo_frame(&body))
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
            let mut sub = connect_tcp(v4)?;
            send_framed(&mut sub, b"sub")?;
            assert_eq!(recv_framed(&mut sub)?, b"ok");
            // The subscriber now goes silent (never reads its socket).

            let mut publisher = connect_tcp(v4)?;
            // First push: queued, stalls mid-send (subscriber not reading).
            send_framed(&mut publisher, b"push")?;
            assert_eq!(recv_framed(&mut publisher)?, b"ok");
            thread::sleep(Duration::from_millis(50)); // let it stall
            // Second push: queued bytes would exceed the backlog cap -> evict.
            send_framed(&mut publisher, b"push")?;
            assert_eq!(recv_framed(&mut publisher)?, b"ok");
            thread::sleep(Duration::from_millis(100)); // let eviction land
            Ok(())
        })()
        .expect("client io");
        stop.shutdown();
    });

    server.serve_forever().expect("serve_forever");
    client.join().expect("thread join");
    let got = reasons.lock().unwrap().clone();
    assert!(
        got.contains(&CloseReason::SendBacklog),
        "expected SendBacklog eviction, got {got:?}"
    );
}

#[test]
fn tcp_push_held_across_detach() {
    // PushHandle's contract is "usable for the connection's lifetime". While the connection is DETACHED its raw stream
    // belongs to the worker - a push must neither write mid-detach (corrupting the worker's transfer) nor be silently
    // dropped: it queues against the parked connection and flushes, FIFO, when the worker resumes it.
    use std::sync::Mutex;
    use std::sync::mpsc;
    let push_slot: Arc<Mutex<Option<PushHandle>>> = Arc::new(Mutex::new(None));
    let (parked_tx, parked_rx) = mpsc::channel::<()>();
    let (resume_tx, resume_rx) = mpsc::channel::<()>();
    let resume_rx = Arc::new(Mutex::new(Some(resume_rx)));

    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let stash = Arc::clone(&push_slot);
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(PrefixWidth::U32, Endian::Big, false),
        body: move |req: Request<'_, ()>| match &req.body[..] {
            b"sub" => {
                *stash.lock().unwrap() = Some(req.responder.push_handle());
                Response::Reply(echo_frame(b"ok"))
            }
            b"detach" => Response::Detach(req.responder.detach()),
            other => Response::Reply(echo_frame(other)),
        },
    };
    let mut server = match Server::bind([addr], proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind: {e}"),
    };
    {
        let resume_rx = Arc::clone(&resume_rx);
        server.set_detach_handler(move |_ctx, detached| {
            let parked_tx = parked_tx.clone();
            let rx = resume_rx.lock().unwrap().take().expect("one detach");
            thread::spawn(move || {
                parked_tx.send(()).expect("parked signal");
                rx.recv().expect("resume signal"); // hold the detach open
                detached.resume();
            });
        });
    }
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();

    let client = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone());
        let r = (|| -> io::Result<()> {
            let mut s = connect_tcp(v4)?;
            send_framed(&mut s, b"sub")?;
            assert_eq!(recv_framed(&mut s)?, b"ok");
            send_framed(&mut s, b"detach")?;
            parked_rx.recv().expect("parked");
            let push = push_slot.lock().unwrap().clone().expect("stashed handle");
            for i in 0..3u8 {
                push.push(echo_frame(format!("evt{i}").as_bytes()));
            }
            // Let the loop drain the injections while still parked (a drop would happen here, silently).
            thread::sleep(Duration::from_millis(150));
            resume_tx.send(()).expect("resume signal");
            for i in 0..3u8 {
                assert_eq!(
                    recv_framed(&mut s)?,
                    format!("evt{i}").into_bytes(),
                    "push {i} lost or reordered across the detach"
                );
            }
            // And ordinary serving resumed after the flush.
            send_framed(&mut s, b"bye")?;
            assert_eq!(recv_framed(&mut s)?, b"bye");
            Ok(())
        })();
        stop.shutdown();
        r
    });

    server.serve_forever().expect("serve_forever");
    client.join().expect("thread join").expect("client io");
}

#[test]
fn tcp_reply_close_replies_then_closes() {
    // `Response::ReplyClose`: the server speaks last. The client gets the reply and then EOF - no idle-timeout wait, no
    // relying on the peer to hang up (RFC 6455 sec. 5.5.1-style close handshakes need exactly this). A second request
    // pipelined behind the first is discarded undelivered: the farewell retires the recv side.
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};
    let delivered = Arc::new(AtomicUsize::new(0));
    let reasons = Arc::new(Mutex::new(Vec::new()));
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(PrefixWidth::U32, Endian::Big, false),
        body: {
            let delivered = Arc::clone(&delivered);
            move |req: Request<'_, ()>| {
                delivered.fetch_add(1, Ordering::SeqCst);
                Response::ReplyClose(echo_frame(&req.body))
            }
        },
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let mut server = match Server::bind([addr], proto) {
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
        let _stop = ShutdownOnDrop(stop.clone());
        let r = (|| -> io::Result<()> {
            let mut s = connect_tcp(v4)?;
            // Two requests in one write: only the first is served - the farewell is final.
            let mut wire = Vec::new();
            send_framed(&mut wire, b"bye")?;
            send_framed(&mut wire, b"ignored")?;
            s.write_all(&wire)?;
            assert_eq!(recv_framed(&mut s)?, b"bye");
            let t0 = Instant::now();
            let mut rest = Vec::new();
            s.read_to_end(&mut rest)?;
            assert!(rest.is_empty(), "bytes after the farewell: {rest:?}");
            assert!(
                t0.elapsed() < Duration::from_secs(2),
                "close after the farewell took {:?} (idle-wait, not flush)",
                t0.elapsed()
            );
            Ok(())
        })();
        stop.shutdown();
        r
    });

    server.serve_forever().expect("serve_forever");
    client.join().expect("thread join").expect("client io");
    assert_eq!(delivered.load(Ordering::SeqCst), 1, "pipelined 2nd request");
    assert_eq!(reasons.lock().unwrap().as_slice(), &[CloseReason::HandlerClosed],);
}

#[test]
fn tcp_deferred_reply_close() {
    // `Deferred::reply_close`: the worker speaks last - its final PDU is sent, then the connection closes
    // (WorkerClosed), exactly like the inline `Response::ReplyClose` but from another thread.
    use std::sync::Mutex;
    let reasons = Arc::new(Mutex::new(Vec::new()));
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(PrefixWidth::U32, Endian::Big, false),
        body: move |req: Request<'_, ()>| {
            let input = req.body.to_vec();
            let (deferred, permit) = req.responder.defer();
            thread::spawn(move || {
                deferred.reply_close(echo_frame(&input.to_ascii_uppercase()));
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
        let _stop = ShutdownOnDrop(stop.clone());
        let r = (|| -> io::Result<()> {
            let mut s = connect_tcp(v4)?;
            send_framed(&mut s, b"bye")?;
            assert_eq!(recv_framed(&mut s)?, b"BYE");
            let mut rest = Vec::new();
            s.read_to_end(&mut rest)?;
            assert!(rest.is_empty(), "bytes after the farewell: {rest:?}");
            Ok(())
        })();
        stop.shutdown();
        r
    });

    server.serve_forever().expect("serve_forever");
    client.join().expect("thread join").expect("client io");
    assert_eq!(reasons.lock().unwrap().as_slice(), &[CloseReason::WorkerClosed],);
}

#[test]
fn tcp_deferred_reply_close_empty_flushes_queued() {
    // An EMPTY `reply_close` queues no PDU of its own but still flushes whatever is already queued before closing -
    // here a push the worker issued just before it (both ride the same FIFO injection queue, so the order is
    // deterministic). `Response::Close` would drop that push.
    use std::sync::Mutex;
    let reasons = Arc::new(Mutex::new(Vec::new()));
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(PrefixWidth::U32, Endian::Big, false),
        body: move |req: Request<'_, ()>| {
            let push = req.responder.push_handle();
            let (deferred, permit) = req.responder.defer();
            thread::spawn(move || {
                push.push(echo_frame(b"last-words"));
                deferred.reply_close(Vec::new());
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
        let _stop = ShutdownOnDrop(stop.clone());
        let r = (|| -> io::Result<()> {
            let mut s = connect_tcp(v4)?;
            send_framed(&mut s, b"go")?;
            assert_eq!(recv_framed(&mut s)?, b"last-words");
            let mut rest = Vec::new();
            s.read_to_end(&mut rest)?;
            assert!(rest.is_empty(), "bytes after the flush: {rest:?}");
            Ok(())
        })();
        stop.shutdown();
        r
    });

    server.serve_forever().expect("serve_forever");
    client.join().expect("thread join").expect("client io");
    assert_eq!(reasons.lock().unwrap().as_slice(), &[CloseReason::WorkerClosed],);
}
