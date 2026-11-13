use super::*;

#[test]
fn tcp_splice_body_recv() {
    // A framer diverts a DATA frame's body straight from the socket to a consumer pipe with IORING_OP_SPLICE -
    // zero-copy, the body never enters the connection buffer - while CONTROL frames deliver to the body handler as
    // usual. Proves: (a) the spliced bytes arrive intact on the pipe; (b) a body several times the pipe capacity drives
    // the partial-splice resubmit path and end-to-end backpressure (the ring never blocks - an io-wq worker does -
    // while the reader drains); (c) keep-alive framing resumes after the splice (a control frame still echoes on the
    // same connection).
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: `pipe(2)` fills the two-element array with {read, write} fds.
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe");
    let (pipe_rd, pipe_wr) = (fds[0], fds[1]);

    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: splice_header(pipe_wr),
        body: |req: Request<'_, ()>| Response::Reply(echo_frame(&req.body)),
    };
    let mut server = match Server::bind([addr], proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => {
            // SAFETY: closing the test-owned pipe fds on the skip path.
            unsafe {
                libc::close(pipe_rd);
                libc::close(pipe_wr);
            }
            return;
        }
        Err(e) => panic!("bind: {e}"),
    };
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();

    // The spliced body: several times a pipe's default 64 KiB capacity, so the splice completes in multiple partial
    // steps as the reader drains.
    const BODY: usize = 256 * 1024;
    let payload: Vec<u8> = (0..BODY).map(|i| (i % 251) as u8).collect();

    // Reader thread: drain exactly BODY bytes off the pipe read end.
    let expected = payload.clone();
    let reader = thread::spawn(move || {
        let mut got = vec![0u8; BODY];
        let mut off = 0;
        while off < BODY {
            // SAFETY: read into `got[off..]`, within bounds.
            let n = unsafe { libc::read(pipe_rd, got.as_mut_ptr().add(off).cast(), (BODY - off) as libc::size_t) };
            assert!(n > 0, "pipe read returned {n}");
            off += n as usize;
        }
        // SAFETY: done with the read end.
        unsafe { libc::close(pipe_rd) };
        assert_eq!(got, expected, "spliced body mismatch");
    });

    let client = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone());
        let r = (|| -> io::Result<Vec<u8>> {
            let mut s = connect_tcp(v4)?;
            splice_frame(&mut s, b'S', &payload)?; // spliced to the pipe
            splice_frame(&mut s, b'C', b"ping")?; // control frame -> echo
            recv_framed(&mut s) // keep-alive resumed after the splice
        })();
        stop.shutdown();
        r
    });

    server.serve_forever().expect("serve_forever");
    // Close the write end BEFORE joining the reader: if anything upstream delivered the body short, the reader then
    // sees EOF and its `n > 0` assertion fires with a real diagnostic - instead of blocking forever in read() on a pipe
    // this process still holds open (a hang, not a failure).
    // SAFETY: closing the test-owned write end (the server only borrowed it).
    unsafe { libc::close(pipe_wr) };
    reader.join().expect("reader join");
    let echo = client.join().expect("client join").expect("client io");
    assert_eq!(echo, b"ping", "keep-alive echo after splice");
}

#[test]
fn tcp_splice_body_close_mid_splice() {
    // Teardown while a body splice is genuinely IN FLIGHT - the security-critical path. A splice's SQE fd is the
    // consumer pipe, not the socket, so the fd-keyed teardown cancel can't reach it: `close_conn` must cancel the
    // splice by its user_data and defer the index-freeing CLOSE until it reaps (the splice pins the socket's fixed
    // resource node exactly like a recv, so CLOSE must be the connection's last op).
    //
    // Pin the splice in flight deterministically: a tiny pipe with NO reader, and a body larger than it. The first
    // splice fills the pipe; the next parks in the kernel `wait_for_space` (pipe full, never drained) - an in-flight
    // splice blocked on an io-wq worker. A graceful drain deliberately does NOT touch an in-flight splice
    // (`begin_drain`'s quiesced test skips `splicing` -- it cannot tell this wedged transfer from a healthy one, and
    // truncating a healthy one is the bug in `tcp_graceful_drain_lets_healthy_splice_finish`). So the wedged splice is
    // reclaimed only when the grace Deadline escalates to a hard stop: this test proves that escalation's
    // `cancel_and_reap_all` can cancel a splice BLOCKED in io-wq (whose SQE fd is the pipe, not the socket) rather than
    // hanging on it - `serve_forever` returns promptly.
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: `pipe(2)` fills {read, write}.
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe");
    let (pipe_rd, pipe_wr) = (fds[0], fds[1]);
    // Shrink the pipe to one page so a small body overruns it (never drained).
    // SAFETY: F_SETPIPE_SZ on the write end; the kernel clamps to its minimum.
    unsafe { libc::fcntl(pipe_wr, libc::F_SETPIPE_SZ, 4096) };
    const BODY: usize = 32 * 1024; // > any pipe, < the socket receive buffer

    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: splice_header(pipe_wr),
        body: |req: Request<'_, ()>| Response::Reply(echo_frame(&req.body)),
    };
    let mut server = match Server::bind([addr], proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => {
            // SAFETY: closing the test-owned pipe fds on the skip path.
            unsafe {
                libc::close(pipe_rd);
                libc::close(pipe_wr);
            }
            return;
        }
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
            // A data frame whose body overruns the unread pipe: the splice fills the pipe, then parks in flight
            // (nothing drains it).
            splice_frame(&mut s, b'S', &vec![0xABu8; BODY])?;
            thread::sleep(Duration::from_millis(150)); // let the splice park
            stop.shutdown_graceful(Duration::from_millis(300));
            // Keep the socket open (returned); the hard stop abandons the connection and its EOF arrives when the
            // server is dropped.
            Ok(s)
        })()
        .expect("client io")
    });

    let t0 = Instant::now();
    server.serve_forever().expect("serve_forever");
    assert!(
        t0.elapsed() < Duration::from_secs(3),
        "escalation hung on a blocked splice: {:?}",
        t0.elapsed()
    );
    let mut s = client.join().expect("client join");
    // Hard-stop abandoned the connection; dropping the server closes its pool descriptor and only then does the client
    // see EOF, with no data.
    drop(server);
    let mut buf = Vec::new();
    let n = s.read_to_end(&mut buf).unwrap_or(buf.len());
    assert_eq!(n, 0, "unexpected data after abandon: {buf:?}");
    // SAFETY: closing the test-owned pipe fds (the server only borrowed the write end; nothing read the read end).
    unsafe {
        libc::close(pipe_rd);
        libc::close(pipe_wr);
    }
}

#[test]
fn tcp_splice_body_close_mid_poll() {
    // Teardown while a splice is parked on its readiness POLL. A body splice off the non-blocking pool socket returns
    // `-EAGAIN` when the socket is drained mid-body; the server then waits for `POLLIN` before resubmitting. Here the
    // client sends a data-frame header but NO body, so the first splice EAGAINs and parks on the poll indefinitely. As
    // with an in-flight splice, a graceful drain leaves the parked poll alone (`splice_polling` reads as in-flight
    // work); the grace Deadline escalation then reaps it. This proves escalation doesn't hang on a parked splice poll -
    // `serve_forever` returns promptly.
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: `pipe(2)` fills {read, write}.
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe");
    let (pipe_rd, pipe_wr) = (fds[0], fds[1]);

    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: splice_header(pipe_wr),
        body: |req: Request<'_, ()>| Response::Reply(echo_frame(&req.body)),
    };
    let mut server = match Server::bind([addr], proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => {
            // SAFETY: closing the test-owned pipe fds on the skip path.
            unsafe {
                libc::close(pipe_rd);
                libc::close(pipe_wr);
            }
            return;
        }
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
            // Header only, declaring an 8 MiB body: the splice arms, finds the socket empty, EAGAINs, and parks on the
            // readiness poll.
            let mut hdr = vec![b'S'];
            hdr.extend_from_slice(&(8u32 * 1024 * 1024).to_be_bytes());
            s.write_all(&hdr)?;
            thread::sleep(Duration::from_millis(150)); // let it reach the poll
            stop.shutdown_graceful(Duration::from_millis(300));
            Ok(s) // abandoned; EOF at server drop
        })()
        .expect("client io")
    });

    let t0 = Instant::now();
    server.serve_forever().expect("serve_forever");
    assert!(
        t0.elapsed() < Duration::from_secs(3),
        "escalation hung on a parked splice poll: {:?}",
        t0.elapsed()
    );
    let mut s = client.join().expect("client join");
    drop(server);
    let mut buf = Vec::new();
    let n = s.read_to_end(&mut buf).unwrap_or(buf.len());
    assert_eq!(n, 0, "unexpected data after abandon: {buf:?}");
    // SAFETY: closing the test-owned pipe fds.
    unsafe {
        libc::close(pipe_rd);
        libc::close(pipe_wr);
    }
}

#[test]
fn tcp_splice_body_request_timeout_reclaims_stall() {
    // SECURITY (slow-loris, splice path): a peer that sends a `SpliceBody` header then withholds the body must not pin
    // its slot. The body splice EAGAINs on
    // the drained non-blocking socket and parks on its readiness poll;
    // `request_timeout` bounds that poll exactly like a body recv, so the stalled slot is reclaimed. (Without the bound
    // the poll would wait forever.)
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: `pipe(2)` fills {read, write}.
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe");
    let (pipe_rd, pipe_wr) = (fds[0], fds[1]);
    let cfg = ServerConfig {
        request_timeout: Some(Duration::from_millis(200)),
        ..ServerConfig::default()
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: splice_header(pipe_wr),
        body: |req: Request<'_, ()>| Response::Reply(echo_frame(&req.body)),
    };
    let mut server = match Server::with_config([addr], cfg, proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => {
            // SAFETY: closing the test-owned pipe fds on the skip path.
            unsafe {
                libc::close(pipe_rd);
                libc::close(pipe_wr);
            }
            return;
        }
        Err(e) => panic!("bind: {e}"),
    };
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();

    let client = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone());
        let r = (|| -> io::Result<()> {
            // A SpliceBody header declaring an 8 MiB body, then stall: the splice parks on its readiness poll and
            // request_timeout reclaims the slot.
            let mut stall = connect_tcp(v4)?;
            let mut hdr = vec![b'S'];
            hdr.extend_from_slice(&(8u32 * 1024 * 1024).to_be_bytes());
            stall.write_all(&hdr)?;
            expect_idle_close(&mut stall)?; // prompt server close (< 2s)
            Ok(())
        })();
        stop.shutdown();
        r
    });

    server.serve_forever().expect("serve_forever");
    client.join().expect("thread join").expect("client io");
    // SAFETY: closing the test-owned pipe fds.
    unsafe {
        libc::close(pipe_rd);
        libc::close(pipe_wr);
    }
}

#[test]
fn tcp_graceful_drain_lets_healthy_splice_finish() {
    // `shutdown_graceful`'s contract: work in flight runs to completion within the grace. A body mid-splice IS
    // in-flight work even though `recving` is false - the drain sweep must not classify it quiesced and cancel it (that
    // silently truncates the body in the consumer's pipe). Regression test: begin a drain while a splice is parked on
    // its readiness poll mid-body, then let the client finish; the FULL body must reach the pipe, and the connection
    // closes only after it does.
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: `pipe(2)` fills {read, write}.
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe");
    let (pipe_rd, pipe_wr) = (fds[0], fds[1]);
    // Half a default pipe: the whole body fits unread, so nothing wedges.
    const BODY: usize = 32 * 1024;

    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: splice_header(pipe_wr),
        body: |req: Request<'_, ()>| Response::Reply(echo_frame(&req.body)),
    };
    let mut server = match Server::bind([addr], proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => {
            // SAFETY: closing the test-owned pipe fds on the skip path.
            unsafe {
                libc::close(pipe_rd);
                libc::close(pipe_wr);
            }
            return;
        }
        Err(e) => panic!("bind: {e}"),
    };
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();

    let payload: Vec<u8> = (0..BODY).map(|i| (i % 251) as u8).collect();
    let sent = payload.clone();
    let client = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone());
        let r = (|| -> io::Result<()> {
            let mut s = connect_tcp(v4)?;
            // Header + first half: the splice moves what arrived, then parks on its readiness poll mid-body
            // (`splice_polling`).
            let mut first = vec![b'S'];
            first.extend_from_slice(&(BODY as u32).to_be_bytes());
            first.extend_from_slice(&sent[..BODY / 2]);
            s.write_all(&first)?;
            thread::sleep(Duration::from_millis(150)); // reach the poll

            let t0 = Instant::now();
            stop.shutdown_graceful(Duration::from_secs(5));
            thread::sleep(Duration::from_millis(100)); // let the sweep run
            s.write_all(&sent[BODY / 2..])?; // finish the transfer

            // The body completes and only THEN does the drain close us -- well inside the grace (no Deadline escalation
            // involved).
            let mut buf = Vec::new();
            s.read_to_end(&mut buf)?;
            assert!(
                t0.elapsed() < Duration::from_secs(3),
                "drain close took {:?}",
                t0.elapsed()
            );
            Ok(())
        })();
        stop.shutdown();
        r
    });

    server.serve_forever().expect("serve_forever");
    client.join().expect("client join").expect("client io");
    // EOF the pipe, then read it all back: the drain must not have truncated the spliced body.
    // SAFETY: closing the test-owned write end (the server only borrowed it).
    unsafe { libc::close(pipe_wr) };
    let mut got = Vec::new();
    // SAFETY: `pipe_rd` is a live blocking fd owned by this test.
    let mut rd = unsafe { std::fs::File::from_raw_fd(pipe_rd) };
    rd.read_to_end(&mut got).expect("pipe read");
    assert_eq!(got.len(), BODY, "drain truncated a healthy splice");
    assert_eq!(got, payload, "spliced body corrupted");
}

/// SECURITY: one destination pipe, one body. Two connections splicing to the same fd do not merely queue behind each
/// other - they **interleave**. A splice moves at most what the transport hands over in one call, and the remainder is
/// resubmitted as a fresh op, so another connection's splice can take the pipe's mutex in between and write its own
/// bytes.
/// The second body is refused rather than served corrupt.
///
/// A captured-fd framer closure is the shape that invites this, which is exactly what `splice_header` is - so this test
/// is the framer every other splice test here uses, driven by two connections instead of one.
#[test]
fn tcp_splice_body_refuses_a_destination_already_in_use() {
    use std::sync::Mutex;
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: `pipe(2)` fills {read, write}.
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe");
    let (pipe_rd, pipe_wr) = (fds[0], fds[1]);

    let reasons = Arc::new(Mutex::new(Vec::new()));
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: splice_header(pipe_wr),
        body: |req: Request<'_, ()>| Response::Reply(echo_frame(&req.body)),
    };
    let mut server = match Server::bind([addr], proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => {
            // SAFETY: closing the test-owned pipe fds on the skip path.
            unsafe {
                libc::close(pipe_rd);
                libc::close(pipe_wr);
            }
            return;
        }
        Err(e) => panic!("bind: {e}"),
    };
    {
        let seen = Arc::clone(&reasons);
        server.set_close_hook(move |_peer, why, _state| {
            seen.lock().unwrap().push(why);
        });
    }
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();

    let client = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone()); // fail fast on panic
        (|| -> io::Result<()> {
            // The first connection opens a body far larger than the pipe and never finishes it, so its splice stays in
            // flight.
            // `pipe_rd` is this thread's for the duration; the outer scope closes both ends once it has joined.
            let mut first = connect_tcp(v4)?;
            let mut hdr = vec![b'S'];
            hdr.extend_from_slice(&(8u32 * 1024 * 1024).to_be_bytes());
            first.write_all(&hdr)?;
            first.write_all(&[b'a'; 4096])?;
            first.flush()?;
            // Wait for the splice by *observing* it, not by sleeping: the bytes reaching the pipe are the proof that
            // the first body is in flight, and it stays in flight because only 4096 of the declared 8 MiB were sent.
            let mut drained = 0usize;
            let deadline = Instant::now() + Duration::from_secs(10);
            while drained < 4096 && Instant::now() < deadline {
                let mut sink = [0u8; 4096];
                // SAFETY: reading into a local buffer of its own length.
                let n = unsafe { libc::read(pipe_rd, sink.as_mut_ptr().cast(), (4096 - drained) as libc::size_t) };
                if n > 0 {
                    drained += n as usize;
                }
            }
            assert_eq!(drained, 4096, "the first body never reached the pipe");

            // The second names the same fd: refused, not queued.
            let mut second = connect_tcp(v4)?;
            second.write_all(&hdr)?;
            second.flush()?;
            let mut one = [0u8; 1];
            match second.read(&mut one) {
                Ok(0) | Err(_) => {}
                Ok(n) => panic!("unexpected {n} byte(s) on a refused body"),
            }
            Ok(())
        })()
        .expect("client io");
        stop.shutdown();
    });

    server.serve_forever().expect("serve_forever");
    client.join().expect("client join");
    assert!(
        reasons.lock().unwrap().contains(&CloseReason::SpliceFdInUse),
        "a shared splice destination must be refused, got {:?}",
        reasons.lock().unwrap()
    );
    // SAFETY: closing the test-owned pipe fds.
    unsafe {
        libc::close(pipe_rd);
        libc::close(pipe_wr);
    }
}

#[test]
fn tcp_splice_body_nonblocking_pipe_rejected() {
    // A NON-BLOCKING destination breaks the splice path's contract two ways: `do_splice` promotes the output fd's
    // O_NONBLOCK to SPLICE_F_NONBLOCK, so a full pipe fails the splice with EAGAIN before the socket is read --
    // indistinguishable from "socket empty", which would spin the readiness poll hot (POLLIN completes instantly,
    // splice EAGAINs again) - and the designed blocking-pipe backpressure never engages. The server refuses the fd at
    // body start: `CloseReason::SpliceBadFd`, kernel never sees it.
    use std::sync::Mutex;
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: `pipe(2)` fills {read, write}.
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe");
    let (pipe_rd, pipe_wr) = (fds[0], fds[1]);
    // SAFETY: flag the write end non-blocking - the misuse under test.
    unsafe {
        let fl = libc::fcntl(pipe_wr, libc::F_GETFL);
        libc::fcntl(pipe_wr, libc::F_SETFL, fl | libc::O_NONBLOCK);
    }

    let reasons = Arc::new(Mutex::new(Vec::new()));
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: splice_header(pipe_wr),
        body: |req: Request<'_, ()>| Response::Reply(echo_frame(&req.body)),
    };
    let mut server = match Server::bind([addr], proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => {
            // SAFETY: closing the test-owned pipe fds on the skip path.
            unsafe {
                libc::close(pipe_rd);
                libc::close(pipe_wr);
            }
            return;
        }
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
            splice_frame(&mut s, b'S', &[0xCD; 1024])?;
            // Rejected at body start: prompt close, nothing spliced.
            let t0 = Instant::now();
            let mut buf = Vec::new();
            s.read_to_end(&mut buf)?;
            assert!(buf.is_empty(), "unexpected reply bytes");
            assert!(
                t0.elapsed() < Duration::from_secs(2),
                "rejection close took {:?}",
                t0.elapsed()
            );
            Ok(())
        })();
        stop.shutdown();
        r
    });

    server.serve_forever().expect("serve_forever");
    client.join().expect("client join").expect("client io");
    assert_eq!(
        reasons.lock().unwrap().as_slice(),
        &[CloseReason::SpliceBadFd],
        "expected the non-blocking pipe to be refused at body start"
    );
    // SAFETY: closing the test-owned pipe fds (nothing was spliced).
    unsafe {
        libc::close(pipe_rd);
        libc::close(pipe_wr);
    }
}

#[test]
fn tcp_send_timeout_reclaims_slot() {
    // A peer that requests a huge reply and then never reads it parks a MSG_WAITALL send forever (TCP zero-window
    // probing never gives up). With `send_timeout`, the linked timeout cancels the stalled send and the connection's
    // pool slot is reclaimed - proven with pool_size=1: a second client can only ever be served if the first slot was
    // actually freed.
    const BIG: usize = 8 * 1024 * 1024; // far beyond the socket send buffer
    let cfg = ServerConfig {
        pool_size: 1,
        send_timeout: Some(Duration::from_millis(200)),
        ..ServerConfig::default()
    };
    let proto = length_prefixed(
        PrefixWidth::U32,
        Endian::Big,
        false,
        |_h: &[u8], body: &[u8], _p: &ClientAddr| {
            if body == b"big" {
                Some(echo_frame(&vec![0xAB; BIG]))
            } else {
                Some(echo_frame(body))
            }
        },
    );
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
            // Stalled reader: request the big reply, never read a byte, and keep the socket open so only the send
            // timeout can free the slot.
            let mut stalled = connect_tcp(v4)?;
            send_framed(&mut stalled, b"big")?;
            thread::sleep(Duration::from_millis(600)); // > send_timeout

            // The slot must now be free; a fresh client gets served. Retry a few times in case the pool is momentarily
            // mid-teardown (a shed connection sees accept-then-close).
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                let attempt = (|| -> io::Result<Vec<u8>> {
                    let mut s = connect_tcp(v4)?;
                    send_framed(&mut s, b"ping")?;
                    recv_framed(&mut s)
                })();
                match attempt {
                    Ok(v) => return Ok(v),
                    Err(e) if Instant::now() >= deadline => return Err(e),
                    Err(_) => thread::sleep(Duration::from_millis(50)),
                }
            }
        })();
        stop.shutdown();
        r
    });

    server.serve_forever().expect("serve_forever");
    let pong = client.join().expect("thread join").expect("client io");
    assert_eq!(pong, b"ping");
}
