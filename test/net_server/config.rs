use super::*;

#[test]
fn server_config_bounds_are_rejected_at_construction() {
    // `ServerConfig::validate` runs as the first statement of `with_config`, before a socket or a ring exists, so every
    // case here is reachable with no io_uring at all. Each knob is checked for the message it produces, not merely that
    // it errored: an out-of-range value accepted here becomes a truncated completion token or a thread storm much
    // later, and the message is the only thing naming the knob that was wrong.
    use truenas_ros::net::server::Listen;
    let tcp = || ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let expect =
        |addrs: Vec<Listen>, cfg: ServerConfig, needle: &str| match Server::with_config(addrs, cfg, noop_protocol()) {
            Err(Error::Validation(m)) => assert!(
                m.contains(needle),
                "expected a validation error mentioning {needle:?}, got {m:?}",
            ),
            Err(e) => {
                panic!("expected a validation error for {needle:?}, got {e}")
            }
            Ok(_) => panic!("expected {needle:?} to be rejected"),
        };

    // The listener list itself.
    expect(Vec::new(), ServerConfig::default(), "listener count");
    expect(
        (0..257).map(|_| Listen::from(tcp())).collect(),
        ServerConfig::default(),
        "listener count",
    );
    // kTLS rides the TCP stack; a Unix listener cannot carry it.
    expect(
        vec![Listen::tls(ServerAddr::Unix("/tmp/ktls-validate".into()))],
        ServerConfig::default(),
        "kTLS listeners must be TCP",
    );

    // Numeric knobs, each at both ends of its range where it has two.
    let one = || vec![Listen::from(tcp())];
    for (cfg, needle) in [
        (
            ServerConfig {
                pool_size: 0,
                ..ServerConfig::default()
            },
            "pool_size",
        ),
        (
            ServerConfig {
                pool_size: 0x0100_0000, // one past the 24-bit slot ceiling
                ..ServerConfig::default()
            },
            "pool_size",
        ),
        (
            ServerConfig {
                max_request_bytes: 0,
                ..ServerConfig::default()
            },
            "max_request_bytes",
        ),
        (
            ServerConfig {
                max_request_bytes: usize::MAX,
                ..ServerConfig::default()
            },
            "max_request_bytes",
        ),
        (
            ServerConfig {
                max_send_backlog: 0,
                ..ServerConfig::default()
            },
            "max_send_backlog must be non-zero",
        ),
        // `listen(2)` takes a signed backlog but compares it unsigned, so a negative value is reinterpreted as enormous
        // and silently clamped to somaxconn rather than rejected; zero listens but accepts almost nothing. Neither is
        // what any caller meant.
        (
            ServerConfig {
                backlog: 0,
                ..ServerConfig::default()
            },
            "backlog must be positive",
        ),
        (
            ServerConfig {
                backlog: -1,
                ..ServerConfig::default()
            },
            "backlog must be positive",
        ),
        (
            ServerConfig {
                max_send_coalesce: 0,
                ..ServerConfig::default()
            },
            "max_send_coalesce",
        ),
        (
            ServerConfig {
                max_send_coalesce: usize::MAX,
                ..ServerConfig::default()
            },
            "max_send_coalesce",
        ),
        (
            ServerConfig {
                max_in_flight_requests: 0,
                ..ServerConfig::default()
            },
            "max_in_flight_requests",
        ),
        (
            ServerConfig {
                max_in_flight_requests: usize::MAX,
                ..ServerConfig::default()
            },
            "max_in_flight_requests",
        ),
        // A cap of 0 holds every placed body back for good.
        (
            ServerConfig {
                held_cap: Some(0),
                ..ServerConfig::default()
            },
            "held_cap must be non-zero",
        ),
    ] {
        expect(one(), cfg, needle);
    }

    // A timeout knob is optional, but `Some(0)` is never what anyone means: it would expire the moment it was armed.
    let zero = Duration::ZERO;
    for (cfg, needle) in [
        (
            ServerConfig {
                idle_timeout: Some(zero),
                ..ServerConfig::default()
            },
            "idle_timeout must be non-zero",
        ),
        (
            ServerConfig {
                send_timeout: Some(zero),
                ..ServerConfig::default()
            },
            "send_timeout must be non-zero",
        ),
        (
            ServerConfig {
                request_timeout: Some(zero),
                ..ServerConfig::default()
            },
            "request_timeout must be non-zero",
        ),
        (
            ServerConfig {
                max_receipt_time: Some(zero),
                ..ServerConfig::default()
            },
            "max_receipt_time must be non-zero",
        ),
        (
            ServerConfig {
                tls_handshake_timeout: Some(zero),
                ..ServerConfig::default()
            },
            "tls_handshake_timeout must be non-zero",
        ),
        (
            ServerConfig {
                keepalive: Some(zero),
                ..ServerConfig::default()
            },
            "keepalive must be non-zero",
        ),
        (
            ServerConfig {
                tcp_user_timeout: Some(zero),
                ..ServerConfig::default()
            },
            "tcp_user_timeout must be non-zero",
        ),
    ] {
        expect(one(), cfg, needle);
    }
}

#[cfg(feature = "uring-fs")]
#[test]
fn server_config_fs_pool_bounds_are_rejected_at_construction() {
    // The fs knobs carry their own bounds for reasons the generic ones do not: an op-slot index shares the 24-bit
    // `user_data` slot field, so an
    // oversized `fs_ops` would truncate a completion token rather than fail;
    // and the offload floor spawns eagerly on the reactor thread, so an absurd value is a thread storm at first use.
    // Both must fail here, at construction, where the message still names the knob.
    use truenas_ros::net::server::Listen;
    let one = || {
        vec![Listen::from(ServerAddr::Tcp(
            "127.0.0.1:0".parse::<SocketAddrV4>().unwrap(),
        ))]
    };
    let expect = |cfg: ServerConfig, needle: &str| match Server::with_config(one(), cfg, noop_protocol()) {
        Err(Error::Validation(m)) => assert!(
            m.contains(needle),
            "expected a validation error mentioning {needle:?}, got {m:?}",
        ),
        Err(e) => panic!("expected a validation error for {needle:?}, got {e}"),
        Ok(_) => panic!("expected {needle:?} to be rejected"),
    };

    expect(
        ServerConfig {
            // Plus the default `pool_size`, one past the 24-bit ceiling.
            fs_ops: 0x00ff_ffff,
            ..ServerConfig::default()
        },
        "fs_ops",
    );
    expect(
        ServerConfig {
            fs_offload_floor: 0,
            ..ServerConfig::default()
        },
        "fs_offload_floor",
    );
    expect(
        ServerConfig {
            fs_offload_floor: 4,
            fs_offload_ceiling: 2, // floor above ceiling
            ..ServerConfig::default()
        },
        "fs_offload_floor",
    );
    expect(
        ServerConfig {
            fs_offload_ceiling: 1025, // past MAX_OFFLOAD_THREADS
            ..ServerConfig::default()
        },
        "fs_offload_floor",
    );
    // The body chunk sizes two kernel-visible buffers per streaming connection and its read result must fit a CQE's
    // i32.
    expect(
        ServerConfig {
            fs_body_chunk: 0, // below the 4 KiB floor
            ..ServerConfig::default()
        },
        "fs_body_chunk",
    );
    expect(
        ServerConfig {
            fs_body_chunk: 16 * 1024 * 1024 + 1, // past the 16 MiB ceiling
            ..ServerConfig::default()
        },
        "fs_body_chunk",
    );
}

/// `Response::ReplyFile` on a server built WITHOUT an fs pool must refuse loudly - close before any reply byte - never
/// send the head and then a body it has no reactor to read. The `File` comes from a standalone `UringFs` host: an open
/// fd is host-independent, which is exactly the misconfiguration shape (files wired over from one reactor into a server
/// missing `fs_ops`).
#[cfg(feature = "uring-fs")]
#[test]
fn file_reply_without_an_fs_pool_sheds_loudly() {
    use std::sync::{Mutex, mpsc};
    use truenas_ros::sync_fs::{OFlag, OpenHow};
    use truenas_ros::uring_fs::{Anchor, FsConfig, UringFs};

    let dir = truenas_ros::tempdir().unwrap();
    std::fs::write(dir.path().join("f"), b"never sent").unwrap();

    // Mint a File on a standalone host, then stop it - the fd survives.
    let mut cfg = FsConfig::default();
    cfg.entries = 128;
    cfg.ops = 128;
    let mut afs = match UringFs::new(cfg) {
        Ok(a) => a,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("UringFs::new: {e}"),
    };
    let who = afs.register_self().expect("register_self");
    let handle = afs.handle();
    let stop_fs = afs.shutdown_handle();
    let anchor = Anchor::open(dir.path()).expect("anchor");
    let (ftx, frx) = mpsc::channel();
    thread::scope(|sc| {
        sc.spawn(move || {
            let r = handle.open(who, &anchor, c"f", OpenHow::new().flags(OFlag::O_RDONLY));
            let _ = ftx.send(r);
            stop_fs.shutdown();
        });
        afs.run().expect("fs host run");
    });
    let file = frx.recv().expect("open outcome").expect("open");

    let reasons = Arc::new(Mutex::new(Vec::new()));
    let file_slot = Mutex::new(Some(file));
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(PrefixWidth::U32, Endian::Big, false),
        body: move |_req: Request<'_, ()>| Response::ReplyFile {
            head: b"HEAD".to_vec(),
            file: file_slot.lock().unwrap().take().expect("one request"),
            offset: 0,
            len: 10,
            close: false,
        },
    };
    // `fs_ops` stays 0: that IS the configuration under test.
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
            let mut msg = 3u32.to_be_bytes().to_vec();
            msg.extend_from_slice(b"abc");
            s.write_all(&msg)?;
            let mut buf = Vec::new();
            s.read_to_end(&mut buf)?;
            assert!(buf.is_empty(), "refusal must be a close, not a short body: {buf:?}");
            Ok(())
        })();
        stop.shutdown();
        r
    });
    server.serve_forever().expect("serve_forever");
    client.join().expect("client join").expect("client io");
    assert_eq!(
        reasons.lock().unwrap().as_slice(),
        &[CloseReason::FileBody(Errno::EOPNOTSUPP)],
        "the pool-less server must shed with the errno in the reason"
    );
}

#[test]
fn tcp_deferred_worker_completes_with_nothing() {
    // `Deferred::reply` with an EMPTY body is the one-way case: the worker finished, there is nothing to send, and the
    // request must simply be retired. It travels as its own outcome rather than as an empty reply, because a queued
    // reply has its in-flight count retired when the send flushes and here no send will ever happen - so the count is
    // dropped where the outcome lands instead. Get that wrong and the connection keeps a phantom request forever, which
    // the request cap would eventually stall on. Proven by continuing to serve afterwards: a leaked count would still
    // be outstanding.
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(PrefixWidth::U32, Endian::Big, false),
        body: |req: Request<'_, ()>| {
            let Request { body, responder, .. } = req;
            if &body[..] == b"oneway" {
                let (deferred, permit) = responder.defer();
                thread::spawn(move || {
                    thread::sleep(Duration::from_millis(10));
                    deferred.reply(Vec::new()); // completed, nothing to send
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
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();

    let client = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone());
        let r = (|| -> io::Result<Vec<u8>> {
            let mut s = connect_tcp(v4)?;
            // Several one-way requests in a row: each must retire its own in-flight count, or the cap stalls the
            // connection well before the round-trip below completes.
            for _ in 0..4 {
                send_framed(&mut s, b"oneway")?;
            }
            send_framed(&mut s, b"ping")?;
            recv_framed(&mut s)
        })();
        stop.shutdown();
        r
    });

    server.serve_forever().expect("serve_forever");
    let reply = client.join().expect("thread join").expect("client io");
    assert_eq!(
        reply, b"ping",
        "one-way deferrals must retire their in-flight count and keep serving",
    );
}

#[test]
fn tcp_push_close_after_the_peer_is_gone_is_inert() {
    // A `PushHandle` outlives the connection it names - that is the point of a long-lived handle - so a `close` can
    // always arrive after the peer has already vanished, or after the slot has been recycled onto somebody else. It
    // must be inert rather than tearing down whoever holds the slot now. Here the subscriber disconnects, a second
    // client takes its place, and only then does the stale handle fire.
    use std::sync::Mutex;
    let stash: Arc<Mutex<Option<PushHandle>>> = Arc::new(Mutex::new(None));
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let handle_for_body = Arc::clone(&stash);
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(PrefixWidth::U32, Endian::Big, false),
        body: move |req: Request<'_, ()>| {
            let Request { body, responder, .. } = req;
            if &body[..] == b"sub" {
                *handle_for_body.lock().unwrap() = Some(responder.push_handle());
            }
            Response::Reply(echo_frame(&body))
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
            let mut first = connect_tcp(v4)?;
            send_framed(&mut first, b"sub")?;
            assert_eq!(recv_framed(&mut first)?, b"sub");
            drop(first); // the handle's connection is gone
            thread::sleep(Duration::from_millis(100)); // let the close land

            // A fresh connection, likely onto the recycled slot.
            let mut second = connect_tcp(v4)?;
            send_framed(&mut second, b"hello")?;
            assert_eq!(recv_framed(&mut second)?, b"hello");

            // Fire the stale handle: it names a dead connection (and possibly this one's slot at an older generation).
            stash.lock().unwrap().take().expect("stashed").close();
            thread::sleep(Duration::from_millis(100));

            // The survivor is untouched.
            send_framed(&mut second, b"still-here")?;
            recv_framed(&mut second)
        })();
        stop.shutdown();
        r
    });

    server.serve_forever().expect("serve_forever");
    let reply = client.join().expect("thread join").expect("client io");
    assert_eq!(
        reply, b"still-here",
        "a stale PushHandle::close must not disturb the slot's new owner",
    );
}

#[test]
fn tcp_push_close_during_a_detach_window_lands_at_resume() {
    // A `PushHandle::close` arriving while the connection is parked under a detach worker cannot act immediately: the
    // worker owns the raw stream, so writing the queued farewell or tearing the socket down would corrupt its transfer.
    // It is recorded and enacted at resume - after the pushes held during the same window, which ride ahead of it. So
    // the client must see every held push, in order, and *then* EOF, with the close attributed to the push side rather
    // than to the worker.
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
    let reasons = close_reason_channel(&mut server);
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
            send_framed(&mut s, b"detach")?;
            parked_rx.recv().expect("parked");

            let push = push_slot.lock().unwrap().clone().expect("stashed handle");
            push.push(echo_frame(b"farewell"));
            push.close(); // lands during the detach window
            // Let the loop drain both injections while still parked.
            thread::sleep(Duration::from_millis(150));
            resume_tx.send(()).expect("resume signal");

            // The held push flushes first...
            assert_eq!(
                recv_framed(&mut s)?,
                b"farewell",
                "a push queued before the close must still be delivered",
            );
            // ...then the recorded close is enacted.
            let mut tail = Vec::new();
            s.read_to_end(&mut tail)?;
            Ok(tail)
        })();
        stop.shutdown();
        r
    });

    server.serve_forever().expect("serve_forever");
    match client.join().expect("thread join") {
        Ok(tail) => assert!(tail.is_empty(), "expected EOF, got {tail:?}"),
        Err(e) => assert_eq!(e.kind(), io::ErrorKind::ConnectionReset),
    }
    assert_eq!(
        reasons.try_recv().ok(),
        Some(CloseReason::PushClosed),
        "a close held across a detach is still a push-side close",
    );
}

#[test]
fn tcp_push_close_kicks_subscriber() {
    // `PushHandle::close`: a connection is ended from outside its own request cycle (session revocation / admin kick).
    // A farewell pushed just before the close flushes first; a push after it is dropped (nothing follows the farewell);
    // repeat closes are no-ops; and the kicked connection's close hook reports PushClosed while other connections keep
    // serving.
    use std::sync::Mutex;
    let sub_handle: Arc<Mutex<Option<PushHandle>>> = Arc::new(Mutex::new(None));
    let reasons = Arc::new(Mutex::new(Vec::new()));
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
                } else if &body[..] == b"kick" {
                    if let Some(h) = sub_handle.lock().unwrap().as_ref() {
                        h.push(echo_frame(b"farewell"));
                        h.close();
                        h.close(); // repeat close: a no-op
                        h.push(echo_frame(b"too-late")); // after close: dropped
                    }
                    Response::Reply(echo_frame(b"kicked"))
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
            let mut sub = connect_tcp(v4)?;
            send_framed(&mut sub, b"sub")?;
            assert_eq!(recv_framed(&mut sub)?, b"subscribed");

            let mut admin = connect_tcp(v4)?;
            send_framed(&mut admin, b"kick")?;
            assert_eq!(recv_framed(&mut admin)?, b"kicked");

            // The subscriber gets the farewell, then EOF - and nothing after the farewell (the too-late push was
            // dropped).
            assert_eq!(recv_framed(&mut sub)?, b"farewell");
            let mut rest = Vec::new();
            sub.read_to_end(&mut rest)?;
            assert!(rest.is_empty(), "bytes after the farewell: {rest:?}");

            // The admin connection is untouched by the kick.
            send_framed(&mut admin, b"ping")?;
            assert_eq!(recv_framed(&mut admin)?, b"ping");
            Ok(())
        })();
        stop.shutdown();
        r
    });

    server.serve_forever().expect("serve_forever");
    client.join().expect("thread join").expect("client io");
    let got = reasons.lock().unwrap().clone();
    assert_eq!(
        got.iter().filter(|r| **r == CloseReason::PushClosed).count(),
        1,
        "expected exactly one PushClosed, got {got:?}"
    );
}

#[test]
fn tcp_stats_counts() {
    // The stats handle reads live counters from another thread.
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(PrefixWidth::U32, Endian::Big, false),
        body: |req: Request<'_, ()>| {
            let Request { body, responder, .. } = req;
            if &body[..] == b"defer" {
                let input = body.to_vec();
                let (deferred, permit) = responder.defer();
                thread::spawn(move || {
                    thread::sleep(Duration::from_millis(10));
                    deferred.reply(echo_frame(&input));
                });
                Response::Defer(permit)
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
    let stats = server.stats_handle();

    let client = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone()); // fail fast on panic
        (|| -> io::Result<()> {
            // Two connections; three requests total, one deferred.
            let mut a = connect_tcp(v4)?;
            send_framed(&mut a, b"one")?;
            assert_eq!(recv_framed(&mut a)?, b"one");
            send_framed(&mut a, b"defer")?;
            assert_eq!(recv_framed(&mut a)?, b"defer");
            drop(a);
            let mut b = connect_tcp(v4)?;
            send_framed(&mut b, b"two")?;
            assert_eq!(recv_framed(&mut b)?, b"two");
            drop(b);
            thread::sleep(Duration::from_millis(80)); // let closes retire
            Ok(())
        })()
        .expect("client io");
        stop.shutdown();
    });

    server.serve_forever().expect("serve_forever");
    client.join().expect("thread join");
    let s = stats.snapshot();
    assert_eq!(s.accepted, 2, "accepted: {s:?}");
    assert_eq!(s.closed, 2, "closed: {s:?}");
    assert_eq!(s.active, 0, "active: {s:?}");
    assert_eq!(s.requests, 3, "requests: {s:?}");
    assert_eq!(s.deferred, 1, "deferred: {s:?}");
    assert_eq!(s.replies, 3, "replies: {s:?}");
    assert_eq!(s.rejected, 0, "rejected: {s:?}");
    assert!(s.bytes_in > 0 && s.bytes_out > 0, "bytes: {s:?}");
    // Length-prefixed framing costs exactly two recvs per request (header, body); EOFs don't count.
    assert_eq!(s.recv_ops, 2 * s.requests, "recv_ops: {s:?}");
}
