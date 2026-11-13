use super::*;

#[test]
fn tcp_splice_body_recv() {
    // A framer diverts a data frame's body from the socket to a pipe with `IORING_OP_SPLICE`, while control frames
    // deliver as usual. The body must arrive intact through partial splices and backpressure, and keep-alive framing
    // resumes after it.
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
    // Teardown while a body splice is in flight. A splice's SQE fd is the consumer pipe, not the socket, so
    // `close_conn` must cancel it by its user_data and defer the index-freeing CLOSE until it reaps, since the splice
    // pins the socket's fixed resource node as a recv does.
    //
    // A one-page pipe with no reader and a larger body park the second splice in the kernel's `wait_for_space` on an
    // io-wq worker. A graceful drain leaves an in-flight splice alone, since it cannot tell a wedged transfer from a
    // healthy one (`tcp_graceful_drain_lets_healthy_splice_finish`), so only the grace deadline's escalation reclaims
    // it, and `cancel_and_reap_all` must cancel a splice blocked in io-wq rather than hang.
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
    // Teardown while a splice is parked on its readiness poll. The client sends a data frame header but no body, so the
    // first splice returns `-EAGAIN` and parks on `POLLIN`. A graceful drain leaves the parked poll alone, as it does
    // an in-flight splice, and the grace deadline's escalation must reap it without hanging.
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
    // A slow-loris guard. A peer that sends a `SpliceBody` header and withholds the body must not pin its slot. The
    // splice returns `-EAGAIN` on the drained socket and parks on its readiness poll, which `request_timeout` bounds as
    // it does a body recv.
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
    // Work in flight runs to completion within the grace, and a body mid-splice is in-flight work even though `recving`
    // is false. A drain begun while the splice is parked on its readiness poll mid-body must let the client finish, so
    // the full body reaches the pipe before the connection closes.
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

            // The body completes and only then does the drain close us, well inside the grace.
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

/// One destination pipe takes one body. Two connections splicing to one fd **interleave**, since a splice moves at most
/// one call's worth and resubmits the remainder as a fresh op, so another connection's splice can write in between. The
/// second body is refused rather than served corrupt.
///
/// A framer closure that captures an fd invites this, and `splice_header` is one, so this drives the framer every
/// splice test here uses from two connections.
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
    // A non-blocking destination breaks the splice path two ways. `do_splice` turns the output fd's O_NONBLOCK into
    // `SPLICE_F_NONBLOCK`, so a full pipe fails with EAGAIN before the socket is read, which looks like an empty socket
    // and spins the readiness poll hot, and the blocking-pipe backpressure never engages. The server refuses the fd at
    // body start with `CloseReason::SpliceBadFd`.
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
    // A peer that requests a huge reply and never reads it parks a MSG_WAITALL send forever, since zero-window probing
    // never gives up. `send_timeout` cancels the stalled send and frees the slot, which `pool_size` 1 proves, since a
    // second client is served only if the first slot was freed.
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
