use super::*;

/// Concurrent connections over a pool, each sending several messages, with `max_request_bytes` low enough that a pool
/// buffer is a few KiB rather than a megabyte. Proves the whole acquisition path: `IOSQE_BUFFER_SELECT` on the arm, the
/// buffer id off the completion, framing and delivery out of pool memory, and the hand-back.
///
/// The bytes are the point. A buffer adopted at the wrong offset, or released while still holding a pipelined
/// remainder, corrupts the echo rather than failing an assertion about the pool.
#[test]
fn a_pooled_server_echoes_what_an_owned_one_does() {
    const N: usize = 12;
    const PER_CONN: usize = 8;
    let cfg = ServerConfig {
        pool_size: 32,
        max_request_bytes: 8 * 1024,
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
    let stats = server.stats_handle();
    let stop = server.shutdown_handle();

    let coordinator = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone()); // fail fast on panic
        let clients: Vec<_> = (0..N)
            .map(|_i| {
                thread::spawn(move || {
                    let s = connect_tcp(v4)?;
                    // Sizes that straddle the 4 KiB scanning read, so a message spans several recvs into the same
                    // buffer.
                    let msgs: Vec<Vec<u8>> = (0..PER_CONN)
                        .map(|j| (b'a' + (j as u8), 500 + j * 900))
                        .map(|(b, n)| vec![b; n])
                        .collect();
                    let refs: Vec<&[u8]> = msgs.iter().map(Vec::as_slice).collect();
                    framed_roundtrips(s, &refs).map(|e| (msgs, e))
                })
            })
            .collect();
        let out: Vec<_> = clients.into_iter().map(|c| c.join().unwrap()).collect();
        stop.shutdown();
        out
    });

    server.serve_forever().expect("serve_forever");
    for r in coordinator.join().expect("coordinator join") {
        let (sent, got) = r.expect("client io");
        assert_eq!(got, sent, "echo must be byte-identical over a pool");
    }

    // Every connection is gone, so every buffer is back. A pool that leaks one leaks it forever: `BufPool::rebalance`
    // retires a group only at `lent() == 0`, so the pool could then never shrink either.
    let s = stats.snapshot();
    assert_pool_registered(&s);
    assert_eq!(s.recv_bufs_lent, 0, "buffers outstanding after every close");
}

/// The recv pool starts at what its config buys: capped by the lease depth or the byte cap, or the byte budget over the
/// buffer size. Read before any traffic.
#[test]
fn the_recv_pool_is_sized_by_its_config() {
    const CONNS: u32 = 2;
    const BUF: usize = 1024 * 1024;
    // More than the depth allows, so the depth bounds the start.
    const PLENTY: usize = 64 * BUF;
    // A half to spare: a buffer's scanning slack cannot cost one.
    const TWELVE: usize = 12 * BUF + BUF / 2;
    const TEN: usize = 10 * BUF + BUF / 2;
    for (depth, budget, cap, want) in [
        (4, PLENTY, None, CONNS * 5),
        (32, TWELVE, None, 12),
        (32, PLENTY, Some(TEN), 10),
    ] {
        let cfg = ServerConfig {
            pool_size: CONNS,
            recv_lease_depth: depth,
            recv_buffer_bytes: BUF,
            buf_pool_initial_bytes: budget,
            buf_pool_max_bytes: cap,
            ..ServerConfig::default()
        };
        let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
        let server = match Server::with_config([addr], cfg, length_prefixed(PrefixWidth::U32, Endian::Big, false, echo))
        {
            Ok(s) => s,
            Err(e) if should_skip(&e) => return,
            Err(e) => panic!("bind: {e}"),
        };
        let s = server.stats_handle().snapshot();
        assert_pool_registered(&s);
        assert_eq!(
            s.recv_bufs_total, want,
            "depth {depth}, budget {budget}, cap {cap:?}: {s:?}"
        );
    }
}

/// The property the pool exists for: a connection parked between requests holds no buffer, so buffer memory tracks
/// concurrent *arrivals* and not the connection count.
///
/// Measured with more idle connections than the pool starts with buffers.
#[test]
fn an_idle_pooled_connection_holds_no_buffer() {
    // Each buffer carries a chunk of slack, so the budget buys fewer than `BUDGET / BUF`, and `IDLE` connections
    // outnumber them.
    const BUF: usize = 64 * 1024;
    const BUDGET: usize = 16 * BUF;
    const IDLE: usize = BUDGET / BUF + 1;
    let cfg = ServerConfig {
        pool_size: IDLE as u32,
        recv_buffer_bytes: BUF,
        buf_pool_initial_bytes: BUDGET,
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
    let stats = server.stats_handle();
    let stop = server.shutdown_handle();
    // The premise, read off the server.
    let born = stats.snapshot().recv_bufs_total as usize;
    assert!(
        born < IDLE,
        "the pool starts with {born} buffers, so {IDLE} idle connections \
         prove nothing"
    );

    let coordinator = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone());
        let mut held = Vec::new();
        for i in 0..IDLE {
            let mut s = connect_tcp(v4).expect("connect");
            send_framed(&mut s, format!("req-{i}").as_bytes()).expect("send");
            let echo = recv_framed(&mut s).expect("recv");
            assert_eq!(echo, format!("req-{i}").into_bytes());
            held.push(s);
        }
        // All served, all parked on an idle recv. The last reply's send completion can still be in flight, so settle
        // rather than sample.
        let deadline = Instant::now() + Duration::from_secs(5);
        let idle = loop {
            let s = stats.snapshot();
            if s.active as usize == IDLE && s.recv_bufs_lent == 0 {
                break s;
            }
            assert!(Instant::now() < deadline, "never settled: {s:?}");
            thread::sleep(Duration::from_millis(20));
        };
        stop.shutdown();
        drop(held);
        idle
    });

    server.serve_forever().expect("serve_forever");
    let s = coordinator.join().expect("coordinator join");
    assert_pool_registered(&s);
    assert_eq!(
        s.recv_bufs_lent, 0,
        "{IDLE} idle connections held {} buffers",
        s.recv_bufs_lent
    );
    assert!(
        (s.recv_bufs_total as usize) < IDLE,
        "pool grew to {} for {IDLE} idle connections - buffers are being \
         held across the idle gap",
        s.recv_bufs_total
    );
}

/// The pool under kTLS, where the recv is a `RECVMSG` carrying a control buffer for the record type rather than a plain
/// `RECV`.
///
/// Worth its own test because the two features meet in the kernel's msghdr import: `io_recvmsg_copy_hdr` skips
/// `io_net_import_vec` entirely when `REQ_F_BUFFER_SELECT` is set (`io_uring/net.c:746-751`), so the iovec this side
/// supplies is never read for its address - but `io_msg_copy_hdr` still copies the iovec *struct* to take its length
/// (`net.c:327-339`, `-EINVAL` above one segment) and still honours `msg_control`. A payload spanning several TLS
/// records exercises the resume-at-an-offset continuation into a buffer the kernel chose.
#[test]
fn a_pooled_connection_still_reads_over_ktls() {
    if ktls_openssl_unsupported() {
        return;
    }
    let (cert, key) = self_signed();
    let acceptor = Arc::new(ktls_acceptor(&cert, &key));
    let cfg = ServerConfig {
        pool_size: 16,
        max_request_bytes: 128 * 1024,
        ..ServerConfig::default()
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let proto = length_prefixed(
        PrefixWidth::U32,
        Endian::Big,
        false,
        |_h: &[u8], body: &[u8], _p: &ClientAddr| Some(echo_frame(body)),
    );
    let mut server = match Server::with_config([truenas_ros::net::server::Listen::tls(addr)], cfg, proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) || ktls_unsupported(&e) => return,
        Err(e) => panic!("bind: {e}"),
    };
    {
        let acceptor = Arc::clone(&acceptor);
        server.set_tls_handshake(move |fd, _inc, deferral| {
            let acceptor = Arc::clone(&acceptor);
            thread::spawn(move || match ktls_server_handshake(fd, &acceptor) {
                Ok(()) => deferral.ready(()),
                Err(_) => deferral.reject(),
            });
        });
    }
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stats = server.stats_handle();
    let stop = server.shutdown_handle();

    let client = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop);
        (|| -> io::Result<()> {
            let mut s = tls_connect(v4)?;
            for msg in [b"tls-pooled".as_slice(), b"again"] {
                send_framed(&mut s, msg)?;
                assert_eq!(recv_framed(&mut s)?, msg, "kTLS echo over a pool");
            }
            // Well past the 16 KiB TLS record cap, so the exact read completes short and resumes at an offset into the
            // pool buffer.
            let big = vec![0x5au8; 40 * 1024];
            send_framed(&mut s, &big)?;
            assert_eq!(recv_framed(&mut s)?, big, "multi-record body");
            Ok(())
        })()
        .expect("client io");
    });

    server.serve_forever().expect("serve_forever");
    client.join().expect("thread join");
    let s = stats.snapshot();
    assert_pool_registered(&s);
    assert_eq!(s.recv_bufs_lent, 0, "buffer outstanding after close: {s:?}");
    assert!(s.requests >= 3, "requests: {s:?}");
}

/// A message larger than a pool buffer promotes to owned storage and is served whole, rather than being refused for
/// outgrowing its buffer.
///
/// This is what lets the buffer size be a free parameter instead of `max_request_bytes`: the copy is bounded by the
/// buffer, and the connection returns to the pool once the message is consumed.
#[test]
fn a_message_larger_than_a_pool_buffer_promotes_and_still_echoes() {
    let cfg = ServerConfig {
        pool_size: 8,
        max_request_bytes: 4 * 1024 * 1024,
        // Placement would divert the big body into its own allocation and the accumulate buffer would never have to
        // grow - which is a real path, but not this one.
        body_placement_threshold: None,
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
    let stats = server.stats_handle();
    let stop = server.shutdown_handle();

    let client = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone());
        let s = connect_tcp(v4).expect("connect");
        // Well past the pooled buffer, then a small one after it: the second proves the connection went back to the
        // pool rather than being left owning the promoted buffer.
        let big = vec![0xa5u8; 512 * 1024];
        let msgs: Vec<&[u8]> = vec![&big, b"after"];
        let echoes = framed_roundtrips(s, &msgs).expect("client io");
        stop.shutdown();
        echoes
    });

    server.serve_forever().expect("serve_forever");
    let echoes = client.join().expect("thread join");
    assert_eq!(echoes[0].len(), 512 * 1024, "promoted message came back");
    assert!(echoes[0].iter().all(|&b| b == 0xa5), "and came back intact");
    assert_eq!(echoes[1], b"after", "connection kept serving");
    let s = stats.snapshot();
    assert_pool_registered(&s);
    assert_eq!(s.recv_bufs_lent, 0, "buffer outstanding at close: {s:?}");
}

/// A placed body reads into its own allocation, so it must not also be handed a pool buffer.
///
/// The kernel clamps a selecting read to the length of the buffer it picks (`io_ring_buffer_select`,
/// `io_uring/kbuf.c`), so an exact read longer than a pool buffer completes short of what the frame declared - which
/// the reactor can only read as a truncated message, and the connection dies mid-request.
///
/// It takes a `header_len: 0` frame to reach: with a header buffered the connection is already holding a claim and asks
/// for nothing. That is why this carries its own framer rather than reusing the length-prefixed one.
#[test]
fn a_placed_body_never_takes_a_pool_buffer() {
    const N: usize = 512 * 1024;
    let cfg = ServerConfig {
        pool_size: 8,
        max_request_bytes: 4 * 1024 * 1024,
        // Low enough that the body below is placed, and far below the message size, so a buffer taken here would be far
        // too small.
        body_placement_threshold: Some(8 * 1024),
        ..ServerConfig::default()
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(0usize),
        header: split_header,
        body: |req: Request<'_, usize>| {
            // The body message clears the pending count; the header-only message that set it replies with nothing.
            if req.body.is_empty() {
                return Response::Reply(Vec::new());
            }
            *req.state = 0;
            Response::Reply(req.body.to_vec())
        },
    };
    let mut server = match Server::with_config([addr], cfg, proto) {
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
        let _stop = ShutdownOnDrop(stop.clone());
        let r = (|| -> io::Result<Vec<u8>> {
            let mut s = connect_tcp(v4)?;
            s.write_all(&(N as u32).to_be_bytes())?;
            s.write_all(&vec![0x3cu8; N])?;
            let mut got = vec![0u8; N];
            s.read_exact(&mut got)?;
            Ok(got)
        })();
        stop.shutdown();
        r
    });

    server.serve_forever().expect("serve_forever");
    let got = client.join().expect("thread join").expect("client io");
    assert_eq!(got.len(), N, "placed body came back whole");
    assert!(got.iter().all(|&b| b == 0x3c), "and intact");
    let s = stats.snapshot();
    assert_pool_registered(&s);
    assert_eq!(s.recv_bufs_lent, 0, "buffer outstanding at close: {s:?}");
}

/// A burst of file bodies wider than the ring's current buffer count must grow the ring and serve every one - never
/// shed.
///
/// The kernel picks a provided buffer when the read completes, so a burst can outrun what is posted and the shortage
/// arrives as `-ENOBUFS` on the pump read's completion. That is pressure, not a failed read, so the ring grows, or the
/// read is reissued with an owned buffer when it cannot. The barrier fires every request in the same instant against a
/// ring that starts with fewer buffers than their first reads want.
#[cfg(feature = "uring-fs")]
#[test]
fn a_burst_of_file_bodies_grows_the_ring_instead_of_shedding() {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Barrier, Mutex, mpsc};
    use truenas_ros::sync_fs::{OFlag, OpenHow};
    use truenas_ros::uring_fs::{Anchor, FsConfig, UringFs};

    const CONNS: usize = 24;
    // Fewer buffers to start than the burst's first reads want.
    const BUDGET: usize = 16 * 1024 * 1024;
    const CHUNK: usize = 1024 * 1024;
    const _: () = assert!(BUDGET / CHUNK < CONNS);
    // `FILE_TAIL_BUFS`: every connection's whole share in flight.
    const CHUNKS_PER_BODY: usize = 2;
    const SIZE: usize = CHUNKS_PER_BODY * CHUNK;

    let dir = truenas_ros::tempdir().unwrap();
    std::fs::write(dir.path().join("obj"), vec![0x42u8; SIZE]).expect("fixture");

    // One open through a standalone fs host, cloned per request.
    let mut afs = match UringFs::new(FsConfig::default()) {
        Ok(f) => f,
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
            let r = handle.open(who, &anchor, c"obj", OpenHow::new().flags(OFlag::O_RDONLY));
            let _ = ftx.send(r);
            stop_fs.shutdown();
        });
        afs.run().expect("fs host run");
    });
    let file = frx.recv().expect("open outcome").expect("open");

    let cfg = ServerConfig {
        pool_size: 32,
        fs_ops: 16,
        fs_body_chunk: CHUNK,
        buf_pool_initial_bytes: BUDGET,
        ..ServerConfig::default()
    };
    let sent = Arc::new(AtomicUsize::new(0));
    let held = Arc::new(AtomicBool::new(false));
    let (sent_srv, held_srv) = (Arc::clone(&sent), Arc::clone(&held));
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(PrefixWidth::U32, Endian::Big, false),
        body: move |_req: Request<'_, ()>| {
            // Hold the reactor until every request is on the wire, so the body reads go out in one submission, ahead of
            // any growth. Spread across batches, grow-ahead keeps the ring from dry.
            if !held_srv.swap(true, Ordering::Relaxed) {
                let deadline = Instant::now() + Duration::from_secs(10);
                while sent_srv.load(Ordering::Acquire) < CONNS && Instant::now() < deadline {
                    thread::sleep(Duration::from_millis(1));
                }
            }
            Response::ReplyFile {
                head: Vec::new(),
                file: file.clone(),
                offset: 0,
                len: SIZE as u64,
                close: true,
            }
        },
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let mut server = match Server::with_config([addr], cfg, proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind: {e}"),
    };
    let reasons = Arc::new(Mutex::new(Vec::new()));
    {
        let reasons = Arc::clone(&reasons);
        server.set_close_hook(move |_p, reason, _s: &mut ()| {
            reasons.lock().unwrap().push(reason);
        });
    }
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stats = server.stats_handle();
    let stop = server.shutdown_handle();

    let coordinator = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone());
        let barrier = Arc::new(Barrier::new(CONNS));
        let clients: Vec<_> = (0..CONNS)
            .map(|_| {
                let barrier = Arc::clone(&barrier);
                let sent = Arc::clone(&sent);
                thread::spawn(move || -> io::Result<()> {
                    let mut s = connect_tcp(v4)?;
                    barrier.wait(); // everyone asks in the same instant
                    send_framed(&mut s, b"g")?;
                    sent.fetch_add(1, Ordering::Release);
                    let mut got = vec![0u8; CHUNK];
                    for _ in 0..CHUNKS_PER_BODY {
                        s.read_exact(&mut got)?;
                        assert!(got.iter().all(|&b| b == 0x42), "body corrupted under buffer pressure");
                    }
                    Ok(())
                })
            })
            .collect();
        let results: Vec<_> = clients.into_iter().map(|c| c.join().unwrap()).collect();
        stop.shutdown();
        results
    });

    server.serve_forever().expect("serve_forever");
    for (i, r) in coordinator.join().expect("join").into_iter().enumerate() {
        r.unwrap_or_else(|e| panic!("client {i} shed under pressure: {e}"));
    }
    let shed: Vec<_> = reasons
        .lock()
        .unwrap()
        .iter()
        .filter(|r| matches!(r, CloseReason::FileBody(_)))
        .cloned()
        .collect();
    assert!(shed.is_empty(), "bodies shed as read failures: {shed:?}");
    let s = stats.snapshot();
    assert_eq!(s.recv_bufs_lent, 0, "buffers outstanding after close: {s:?}");
    // The premise: some read found the ring dry.
    assert!(
        s.buf_shortages > 0,
        "no read found the ring dry, so nothing was proven: {s:?}"
    );
}

/// A pump completion that closes the connection must still return its buffer to the ring.
///
/// Every completion carrying `IORING_CQE_F_BUFFER` consumed its descriptor, since the kernel puts the kbuf with no
/// guard on the result (`io_req_rw_complete`, `io_uring/rw.c:591`), and an EOF read completes `res = 0` with the flag
/// set. The truncated-body close (`n == 0`, the file shrank under a committed `Content-Length`) carries a buffer and
/// abandons the transfer, so it must requeue. Skipped, the id is stranded while `recv_bufs_lent` stays at zero, since
/// the pool still counts it posted, and the ring drains one abandoned body at a time until every read is `-ENOBUFS`.
/// The racier exits of that class, a completion on a closing or recycled slot, owe the id the same but cannot be
/// scheduled from a test.
#[cfg(feature = "uring-fs")]
#[test]
fn a_truncated_body_close_returns_its_buffer() {
    use std::sync::mpsc;
    use truenas_ros::sync_fs::{OFlag, OpenHow};
    use truenas_ros::uring_fs::{Anchor, FsConfig, UringFs};

    const CHUNK: usize = 32 * 1024;
    const POOL_SIZE: u32 = 32;

    let dir = truenas_ros::tempdir().unwrap();
    // Half a chunk on disk, four chunks declared: read one short chunk, then hit EOF - a completion with a buffer and
    // nothing in it.
    std::fs::write(dir.path().join("obj"), vec![0x51u8; CHUNK / 2]).expect("fixture");

    let mut afs = match UringFs::new(FsConfig::default()) {
        Ok(f) => f,
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
            let r = handle.open(who, &anchor, c"obj", OpenHow::new().flags(OFlag::O_RDONLY));
            let _ = ftx.send(r);
            stop_fs.shutdown();
        });
        afs.run().expect("fs host run");
    });
    let file = frx.recv().expect("open outcome").expect("open");

    let cfg = ServerConfig {
        pool_size: POOL_SIZE,
        fs_ops: 16,
        fs_body_chunk: CHUNK,
        // The body ring alone, born at its bound, so the gauge counts it.
        recv_pool: false,
        buf_pool_initial_bytes: usize::MAX,
        ..ServerConfig::default()
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(PrefixWidth::U32, Endian::Big, false),
        body: move |_req: Request<'_, ()>| Response::ReplyFile {
            head: b"H".to_vec(),
            file: file.clone(),
            offset: 0,
            len: (4 * CHUNK) as u64,
            close: true,
        },
    };
    let mut server = match Server::with_config([addr], cfg, proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind: {e}"),
    };
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stats = server.stats_handle();
    let stop = server.shutdown_handle();
    let born = stats.snapshot();
    assert_pool_registered(&born);
    // One stranded id per round: twice the ring's size runs it dry.
    let rounds = 2 * born.recv_bufs_total as usize;

    let client = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone());
        for i in 0..rounds {
            let mut s = connect_tcp(v4).expect("connect");
            // A ring of stranded ids never delivers the body: a stall fails the round instead of hanging the test.
            s.set_read_timeout(Some(Duration::from_secs(5))).expect("read timeout");
            s.write_all(&1u32.to_be_bytes()).expect("len");
            s.write_all(b"g").expect("req");
            // The server sends the head and the short chunk, then closes mid-body on the EOF. Drain to the reset/EOF.
            let mut sink = Vec::new();
            if let Err(e) = s.read_to_end(&mut sink) {
                assert!(
                    !matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut),
                    "round {i}: the body stalled after {} bytes - the ring \
                     ran out of buffers",
                    sink.len()
                );
            }
            assert!(
                sink.len() <= 1 + CHUNK / 2,
                "round {i}: a truncated body was served whole"
            );
            drop(s);
        }
        // Let the closes retire, then check the ring survived.
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let st = stats.snapshot();
            if st.active == 0 && st.recv_bufs_lent == 0 {
                break;
            }
            assert!(Instant::now() < deadline, "never settled: {st:?}");
            thread::sleep(Duration::from_millis(10));
        }
        stop.shutdown();
        stats.snapshot()
    });

    server.serve_forever().expect("serve_forever");
    let s = client.join().expect("client thread");
    assert!(s.recv_bufs_total > 0, "no ring registered: {s:?}");
    assert_eq!(s.recv_bufs_lent, 0, "buffers outstanding: {s:?}");
}
