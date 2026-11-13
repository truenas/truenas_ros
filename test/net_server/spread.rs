use super::*;

/// Two servers on one port in one [`Spread`], the first on a port of its own and the second on that one. Each answers
/// every request with its own index, so a client learns which ring serves it.
struct SpreadPair {
    addr: SocketAddrV4,
    stops: Vec<ShutdownHandle>,
    stats: Vec<StatsHandle>,
    joins: Vec<thread::JoinHandle<()>>,
}

type SpreadReady = Result<(SocketAddrV4, ShutdownHandle, StatsHandle), Error>;

impl SpreadPair {
    fn start() -> Option<SpreadPair> {
        fn worker(index: u8, addr: SocketAddrV4, spread: Spread, ready: std::sync::mpsc::Sender<SpreadReady>) {
            let cfg = ServerConfig {
                reuse_port: true,
                ..ServerConfig::default()
            };
            let which = move |_h: &[u8], _b: &[u8], _p: &ClientAddr| Some(echo_frame(&[index]));
            let proto = length_prefixed(PrefixWidth::U32, Endian::Big, false, which);
            let mut server = match Server::with_config([ServerAddr::Tcp(addr)], cfg, proto) {
                Ok(s) => s,
                Err(e) => {
                    let _ = ready.send(Err(e));
                    return;
                }
            };
            server.join_spread(&spread, usize::from(index)).expect("join_spread");
            let ServerAddr::Tcp(bound) = server.local_addrs().remove(0) else {
                panic!("expected Tcp");
            };
            let _ = ready.send(Ok((bound, server.shutdown_handle(), server.stats_handle())));
            server.serve_forever().expect("serve_forever");
        }

        let spread = Spread::new(2);
        let (tx, rx) = std::sync::mpsc::channel();
        let (first, tx0) = (spread.clone(), tx.clone());
        let w0 = thread::spawn(move || {
            worker(0, "127.0.0.1:0".parse().unwrap(), first, tx0);
        });
        let (addr, stop0, stats0) = match rx.recv().expect("worker 0") {
            Ok(v) => v,
            Err(e) if should_skip(&e) => {
                w0.join().unwrap();
                return None;
            }
            Err(e) => panic!("bind: {e}"),
        };
        let w1 = thread::spawn(move || worker(1, addr, spread, tx));
        // A second ring can be refused `ENOMEM` on a fragmented box, as `tcp_multicore_two_rings` says.
        let (_, stop1, stats1) = match rx.recv().expect("worker 1") {
            Ok(v) => v,
            Err(e) if should_skip(&e) => {
                stop0.shutdown();
                w0.join().unwrap();
                w1.join().unwrap();
                return None;
            }
            Err(e) => panic!("second Server::with_config: {e}"),
        };
        Some(SpreadPair {
            addr,
            stops: vec![stop0, stop1],
            stats: vec![stats0, stats1],
            joins: vec![w0, w1],
        })
    }

    /// Open a connection and learn which ring serves it. The reply comes after that ring has counted it, so the next
    /// connection sees the count.
    fn connect(&self) -> (TcpStream, u8) {
        let mut s = connect_tcp(self.addr).expect("connect");
        send_framed(&mut s, b"which").expect("send");
        let ring = recv_framed(&mut s).expect("served")[0];
        (s, ring)
    }

    fn settle(&self, ring: usize, active: u32) {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let st = self.stats[ring].snapshot();
            if st.active == active {
                return;
            }
            assert!(Instant::now() < deadline, "never settled: {st:?}");
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn stop(self) {
        for stop in &self.stops {
            stop.shutdown_graceful(Duration::from_secs(5));
        }
        for join in self.joins {
            join.join().expect("worker join");
        }
    }
}

/// A connection goes to the ring of the spread with the fewest, wherever the kernel's hash put it, and a closed one
/// comes off its ring's count. Connections arrive one at a time, so each is counted before the next. The hash alone
/// ends 64 even about one time in ten, and never with nothing handed off.
#[test]
fn a_spread_evens_connections_across_its_rings() {
    let Some(pair) = SpreadPair::start() else {
        return;
    };
    let mut held: Vec<(TcpStream, u8)> = (0..64).map(|_| pair.connect()).collect();
    assert_eq!((on(&held, 0), on(&held, 1)), (32, 32));
    let handed: u64 = pair.stats.iter().map(|s| s.snapshot().handed_off).sum();
    assert!(handed > 0, "the hash alone placed every connection");

    // With ring 0 emptied, the next 32 all go there.
    held.retain(|(_, ring)| *ring == 1);
    pair.settle(0, 0);
    let fresh: Vec<(TcpStream, u8)> = (0..32).map(|_| pair.connect()).collect();
    assert_eq!(on(&fresh, 0), 32, "closed connections still counted");
    drop((held, fresh));
    pair.stop();
}

/// A ring that drained takes no more: every connection stays on the ring that is left, and none is sent to the one that
/// is gone.
#[test]
fn a_ring_that_drained_is_sent_nothing() {
    let Some(mut pair) = SpreadPair::start() else {
        return;
    };
    pair.stops[1].shutdown_graceful(Duration::from_secs(5));
    pair.joins.remove(1).join().expect("worker 1 join");
    let held: Vec<(TcpStream, u8)> = (0..8).map(|_| pair.connect()).collect();
    assert_eq!(on(&held, 0), 8);
    assert_eq!(pair.stats[0].snapshot().handed_off, 0);
    drop(held);
    pair.stop();
}

/// A drain refuses new connections instead of quietly accepting them into a backlog nobody will ever read:
/// `shutdown_graceful` shuts every listener down first, so a connect from then on fails with `ECONNREFUSED` while the
/// request already in flight still finishes. The idle connection's EOF is the "drain has begun" signal (the idle sweep
/// runs after the listeners are shut), so nothing here waits on a timer.
#[test]
fn graceful_drain_refuses_new_connections() {
    let (park_tx, park_rx) = std::sync::mpsc::channel::<Deferred>();
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(PrefixWidth::U32, Endian::Big, false),
        body: move |req: Request<'_, ()>| -> Response {
            if &req.body[..] == b"park" {
                let (deferred, permit) = req.responder.defer();
                park_tx.send(deferred).expect("the test holds the receiver");
                Response::Defer(permit)
            } else {
                Response::Reply(echo_frame(&req.body))
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
    let client = thread::spawn(move || -> io::Result<()> {
        let _stop = ShutdownOnDrop(stop.clone());
        // Idle between requests: the sweep closes it, marking the drain.
        let mut idle = connect_tcp(v4)?;
        send_framed(&mut idle, b"ping")?;
        assert_eq!(recv_framed(&mut idle)?, b"ping");
        // Parked in a worker: in-flight work that holds the drain open.
        let mut parked = connect_tcp(v4)?;
        send_framed(&mut parked, b"park")?;
        let deferred = park_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("the request parked");

        stop.shutdown_graceful(Duration::from_secs(5));
        let mut b = [0u8; 1];
        assert_eq!(idle.read(&mut b)?, 0, "the sweep closes the idle peer");

        // The listeners are shut: refused, not queued.
        match TcpStream::connect(v4) {
            Err(e) => assert_eq!(
                e.kind(),
                io::ErrorKind::ConnectionRefused,
                "a connect during the drain failed some other way: {e}"
            ),
            Ok(_) => panic!("a connect during the drain was queued"),
        }

        // The parked request completes, then its connection closes.
        deferred.reply(echo_frame(b"park"));
        assert_eq!(recv_framed(&mut parked)?, b"park");
        assert_eq!(parked.read(&mut b)?, 0, "closed once nothing is owed");
        Ok(())
    });
    server.serve_forever().expect("serve_forever");
    client.join().expect("client thread").expect("client io");
}

/// Draining one `reuse_port` sibling must not take the address down: its shut listener leaves the kernel's reuseport
/// group while the server is still alive and draining, so every new connect lands on the survivor and is served rather
/// than queued on a ring that will never read it. The drained ring is held open by a parked request for the whole
/// check, so what the test proves is `shutdown(2)`, not the fd closing at drop.
#[test]
fn draining_one_reuse_port_sibling_leaves_the_other_serving() {
    type Ready = Result<(SocketAddrV4, ShutdownHandle), Error>;
    fn worker(
        idx: u8,
        addr: SocketAddrV4,
        ready: std::sync::mpsc::Sender<Ready>,
        park_tx: std::sync::mpsc::Sender<Deferred>,
    ) {
        let cfg = ServerConfig {
            reuse_port: true,
            ..ServerConfig::default()
        };
        let proto = Protocol {
            accept: |_: Incoming<'_>| Some(()),
            header: length_prefix_header::<()>(PrefixWidth::U32, Endian::Big, false),
            // Echoes are tagged with the ring that served them; "park" defers so the test can hold that ring open while
            // it drains.
            body: move |req: Request<'_, ()>| -> Response {
                if &req.body[..] == b"park" {
                    let (deferred, permit) = req.responder.defer();
                    park_tx.send(deferred).expect("the test holds the receiver");
                    return Response::Defer(permit);
                }
                let mut out = vec![idx];
                out.extend_from_slice(&req.body);
                Response::Reply(echo_frame(&out))
            },
        };
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
    let (park_tx, park_rx) = std::sync::mpsc::channel::<Deferred>();
    let (tx0, park0) = (tx.clone(), park_tx.clone());
    let w0 = thread::spawn(move || {
        worker(0, "127.0.0.1:0".parse().unwrap(), tx0, park0);
    });
    let (addr, stop0) = match rx.recv().expect("worker 0") {
        Ok(v) => v,
        Err(e) if should_skip(&e) => {
            w0.join().unwrap();
            return;
        }
        Err(e) => panic!("bind: {e}"),
    };
    let w1 = thread::spawn(move || worker(1, addr, tx, park_tx));
    let (_, stop1) = rx.recv().expect("worker 1").expect("second bind");

    // Two connections that ring 0 answered: one to park on it, one to idle on it. The kernel hashes each new connection
    // across the group, so a bounded number of tries finds them (each try is a coin flip).
    let mut on_ring0 = Vec::new();
    for _ in 0..64 {
        let mut s = connect_tcp(addr).expect("connect");
        send_framed(&mut s, b"which").expect("send");
        let reply = recv_framed(&mut s).expect("recv");
        if reply[0] == 0 {
            on_ring0.push(s);
            if on_ring0.len() == 2 {
                break;
            }
        }
    }
    let [mut parked0, mut idle0]: [TcpStream; 2] = on_ring0
        .try_into()
        .expect("the kernel never balanced two connections onto ring 0");
    send_framed(&mut parked0, b"park").expect("send");
    let deferred = park_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("the request parked on ring 0");

    stop0.shutdown_graceful(Duration::from_secs(5));
    let mut b = [0u8; 1];
    assert_eq!(idle0.read(&mut b).expect("read"), 0, "ring 0's idle sweep");

    // Ring 0 is alive, draining, and out of the group: the survivor takes every new connection.
    for i in 0..16 {
        let msg = format!("m{i}");
        let mut s = TcpStream::connect(addr).expect("a connect while a sibling drains must succeed");
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        send_framed(&mut s, msg.as_bytes()).expect("send");
        let reply = recv_framed(&mut s).expect("served by the survivor, not queued on the drained ring");
        assert_eq!(reply[0], 1, "connection {i} landed on the drained ring");
        assert_eq!(&reply[1..], msg.as_bytes());
    }

    // Release ring 0: its parked request completes and the drain ends.
    deferred.reply(echo_frame(b"park"));
    assert_eq!(recv_framed(&mut parked0).expect("recv"), b"park");
    assert_eq!(parked0.read(&mut b).expect("read"), 0, "ring 0 closed it");
    w0.join().expect("worker 0 join");
    stop1.shutdown_graceful(Duration::from_secs(5));
    w1.join().expect("worker 1 join");
}

#[test]
fn tcp_pipelined_out_of_order() {
    // Pipelined requests each defer to a worker that finishes in reverse order. With read-ahead the server reads and
    // defers them all before any reply, so replies leave out of request order, proving recv is decoupled from send.
    const N: u8 = 4;
    let cfg = ServerConfig {
        max_in_flight_requests: 8,
        ..ServerConfig::default()
    };
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(PrefixWidth::U32, Endian::Big, false),
        body: |req: Request<'_, ()>| {
            let Request { body, responder, .. } = req;
            let id = body[0];
            let (deferred, permit) = responder.defer();
            thread::spawn(move || {
                // Higher ids sleep less -> replies come back reversed.
                thread::sleep(Duration::from_millis(u64::from(N - id) * 40));
                deferred.reply(echo_frame(&[id]));
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
        let r = (|| -> io::Result<Vec<u8>> {
            let mut s = connect_tcp(v4)?;
            for id in 0..N {
                send_framed(&mut s, &[id])?; // pipeline: no waiting between sends
            }
            let mut order = Vec::new();
            for _ in 0..N {
                order.push(recv_framed(&mut s)?[0]);
            }
            Ok(order)
        })();
        stop.shutdown();
        r
    });

    server.serve_forever().expect("serve_forever");
    let order = client.join().expect("thread join").expect("client io");
    // Deterministic reversal from the inverse delays - the last request sent is answered first, which can only happen
    // if reads ran ahead of sends.
    assert_eq!(order, vec![3, 2, 1, 0]);
}

#[test]
fn tcp_pipelined_backpressure() {
    // A tight cap with more pipelined requests than the cap: read-ahead must pause at the cap and resume as replies
    // drain - every request answered, none dropped or deadlocked.
    const N: u8 = 12;
    let cfg = ServerConfig {
        max_in_flight_requests: 2,
        ..ServerConfig::default()
    };
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(PrefixWidth::U32, Endian::Big, false),
        body: |req: Request<'_, ()>| {
            let Request { body, responder, .. } = req;
            let id = body[0];
            let (deferred, permit) = responder.defer();
            thread::spawn(move || {
                thread::sleep(Duration::from_millis(5));
                deferred.reply(echo_frame(&[id]));
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
        let r = (|| -> io::Result<Vec<u8>> {
            let mut s = connect_tcp(v4)?;
            for id in 0..N {
                send_framed(&mut s, &[id])?;
            }
            let mut got = Vec::new();
            for _ in 0..N {
                got.push(recv_framed(&mut s)?[0]);
            }
            Ok(got)
        })();
        stop.shutdown();
        r
    });

    server.serve_forever().expect("serve_forever");
    let mut got = client.join().expect("thread join").expect("client io");
    got.sort_unstable();
    assert_eq!(got, (0..N).collect::<Vec<u8>>());
}

#[test]
fn tcp_large_response() {
    // A response far larger than the socket send buffer exercises the WAITALL send: io_uring accumulates the short
    // writes in-kernel and delivers the whole PDU in one op. The client reads it all back and checks it. (Runs in the
    // default sequential mode - the WAITALL send is orthogonal to pipelining.)
    const SIZE: usize = 2 * 1024 * 1024; // >> the default socket sndbuf
    let proto = length_prefixed(
        PrefixWidth::U32,
        Endian::Big,
        false,
        |_h: &[u8], _b: &[u8], _p: &ClientAddr| {
            Some(echo_frame(&(0..SIZE).map(|i| (i % 251) as u8).collect::<Vec<u8>>()))
        },
    );
    let mut server = match Server::bind([ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap())], proto) {
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
            send_framed(&mut s, b"go")?;
            recv_framed(&mut s)
        })();
        stop.shutdown();
        r
    });

    server.serve_forever().expect("serve_forever");
    let got = client.join().expect("thread join").expect("client io");
    assert_eq!(got.len(), SIZE);
    assert!(got.iter().enumerate().all(|(i, &b)| b == (i % 251) as u8));
}

#[test]
fn tcp_reject() {
    // `accept` returns None -> the connection is accepted then immediately closed before any read; the client observes
    // a clean EOF with no reply.
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let proto = Protocol {
        accept: |_: Incoming<'_>| None::<()>,
        header: length_prefix_header::<()>(PrefixWidth::U32, Endian::Big, false),
        body: |_: Request<'_, ()>| Response::Close,
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
            let _ = send_framed(&mut s, b"hello"); // may fail on a reset; ignore
            let mut buf = Vec::new();
            s.read_to_end(&mut buf)?; // rejected -> EOF, no data
            Ok(buf)
        })();
        stop.shutdown();
        r
    });

    server.serve_forever().expect("serve_forever");
    let got = client.join().expect("thread join");
    // Either a clean empty read (EOF) or a connection-reset error is acceptable.
    match got {
        Ok(buf) => assert!(buf.is_empty(), "rejected client got data: {buf:?}"),
        Err(e) => assert_eq!(e.kind(), io::ErrorKind::ConnectionReset),
    }
}

#[test]
fn server_close_reaches_peer_while_another_idles() {
    // A server-initiated close must send its FIN promptly even while another connection sits idle on a parked recv. A
    // bare CLOSE of a direct descriptor only drops the ring's file-table reference, and the socket's fput, and so the
    // FIN, can wait while the idle recv pins the ring's resource node, so the close shuts the socket down first.
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(PrefixWidth::U32, Endian::Big, false),
        // 'C' => close the connection; anything else => echo (keep-alive).
        body: |req: Request<'_, ()>| {
            let Request { body, .. } = req;
            if body.first() == Some(&b'C') {
                Response::Close
            } else {
                Response::Reply(echo_frame(&body[..]))
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
            // Idle connection: one request keeps it alive, then it parks on a recv (pinning the resource node) without
            // closing.
            let mut idle = connect_tcp(v4)?;
            send_framed(&mut idle, b"keepalive")?;
            assert_eq!(recv_framed(&mut idle)?, b"keepalive");

            // Second connection asks the server to close it. With the idle recv pinning the node, the FIN must still
            // arrive promptly.
            let mut victim = connect_tcp(v4)?;
            victim.set_read_timeout(Some(Duration::from_secs(3)))?;
            send_framed(&mut victim, b"C")?;
            let mut buf = Vec::new();
            match victim.read_to_end(&mut buf) {
                Ok(_) => assert!(buf.is_empty(), "victim got data: {buf:?}"),
                Err(e) => assert_eq!(
                    e.kind(),
                    io::ErrorKind::ConnectionReset,
                    "victim should see EOF/reset, not hang"
                ),
            }

            // The idle connection is unaffected and still serves.
            send_framed(&mut idle, b"still-here")?;
            assert_eq!(recv_framed(&mut idle)?, b"still-here");
            Ok(())
        })()
        .expect("client io");
        stop.shutdown();
    });

    server.serve_forever().expect("serve_forever");
    client.join().expect("thread join");
}
