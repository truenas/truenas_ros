use super::*;

/// A two-phase length-prefixed framer that delivers the prefix, then asks for the payload with `Framing::Need`, so the
/// payload read starts with nothing buffered and no claim held.
fn need_payload(buf: &[u8], pending: &mut usize) -> Framing {
    if *pending > 0 {
        if buf.len() < *pending {
            return Framing::Need(*pending - buf.len());
        }
        let n = *pending;
        *pending = 0;
        return Framing::Complete {
            header_len: 0,
            body_len: n,
        };
    }
    if buf.len() < 4 {
        return Framing::Need(4 - buf.len());
    }
    *pending = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    Framing::Complete {
        header_len: 4,
        body_len: 0,
    }
}

/// An exact read larger than one pool buffer takes an owned buffer.
///
/// `frame_step` turns a `Framing::Need(n)` up to `max_request_bytes` into an exact `ReadHeader`, which carries no
/// placement flag, so without the size test at the arm the read selects a pool buffer, the kernel clamps it to that
/// buffer (`io_ring_buffer_select`, `io_uring/kbuf.c`), and the connection dies `TruncatedMessage`. With the default
/// config every `Need` between the pool buffer size and `max_request_bytes` is in this window.
#[test]
fn an_exact_read_over_the_pool_buffer_takes_an_owned_one() {
    const N: usize = 512 * 1024;
    let cfg = ServerConfig {
        pool_size: 8,
        ..ServerConfig::default()
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(0usize),
        header: need_payload,
        body: |req: Request<'_, usize>| {
            if req.body.is_empty() {
                return Response::Reply(Vec::new());
            }
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
            s.write_all(&vec![0x77u8; N])?;
            let mut got = vec![0u8; N];
            s.read_exact(&mut got)?;
            Ok(got)
        })();
        stop.shutdown();
        r
    });
    server.serve_forever().expect("serve_forever");
    let got = client.join().expect("thread join");
    let s = stats.snapshot();
    assert_pool_registered(&s);
    let got = got.unwrap_or_else(|e| {
        panic!(
            "a {N}-byte exact read took a pool buffer and was clamped to \
             it, closing the connection: {e} / stats {s:?}"
        )
    });
    assert_eq!(got.len(), N, "the whole payload came back");
    assert!(got.iter().all(|&b| b == 0x77), "and unmangled");
    assert_eq!(s.recv_bufs_lent, 0, "the pool settles back to nothing lent: {s:?}");
}

/// A redelivery must not be handed the *read-ahead* frame.
///
/// `Deferred::redeliver` runs the handler again with an empty frame. Above the default read-ahead cap the pump may have
/// framed the next pipelined request already, its body still in flight, and delivering against that frame slices out of
/// range on an empty buffer and panics the reactor thread. Short of the panic, `deliver_one`'s epilogue drains
/// `frame_len().min(buffered)`, so a foreign frame eats the next request's header.
///
/// The in-tree http codec never reaches this (`Phase::Parked` holds pipelined bytes unframed), so the control is a
/// framer that frames whatever is buffered, as `Protocol::header` allows.
#[test]
fn a_redelivery_does_not_take_the_read_ahead_frame() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let cfg = ServerConfig {
        // Read-ahead is the precondition, since at the default cap of one the pump never frames the second request.
        max_in_flight_requests: 2,
        ..ServerConfig::default()
    };
    let seen = Arc::new(AtomicUsize::new(0));
    let seen2 = Arc::clone(&seen);
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(PrefixWidth::U32, Endian::Big, false),
        body: move |req: Request<'_, ()>| {
            let nth = seen2.fetch_add(1, Ordering::SeqCst);
            match nth {
                // Parks, and a redelivery answers it once the second request's head has been framed.
                0 => {
                    let (deferred, permit) = req.responder.defer();
                    thread::spawn(move || {
                        thread::sleep(Duration::from_millis(150));
                        deferred.redeliver();
                    });
                    Response::Defer(permit)
                }
                // The redelivery: an empty frame, whatever the pump has recorded for the request behind it.
                1 => {
                    assert!(
                        req.body.is_empty(),
                        "a redelivery must see an empty frame, got {} bytes",
                        req.body.len()
                    );
                    Response::Reply(echo_frame(b"first"))
                }
                // The pipelined request, delivered intact from its own frame.
                _ => Response::Reply(echo_frame(&req.body)),
            }
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
    let stop = server.shutdown_handle();

    let client = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone());
        let r = (|| -> io::Result<()> {
            let mut s = connect_tcp(v4)?;
            send_framed(&mut s, b"A")?;
            thread::sleep(Duration::from_millis(50));
            // Only the second request's header, so the pump frames it and arms an exact read for an unsent body.
            s.write_all(&8u32.to_be_bytes())?;
            s.flush()?;
            thread::sleep(Duration::from_millis(250)); // the redelivery lands
            s.write_all(b"BBBBBBBB")?;
            s.flush()?;
            assert_eq!(recv_framed(&mut s)?, b"first");
            assert_eq!(recv_framed(&mut s)?, b"BBBBBBBB");
            Ok(())
        })();
        stop.shutdown();
        r
    });

    server.serve_forever().expect("serve_forever");
    client.join().expect("thread join").expect("client io");
    assert_eq!(seen.load(Ordering::SeqCst), 3, "park, redelivery, pipelined");
}

/// A redelivery must not retire the receipt budget of the message behind it.
///
/// A redelivered request's budget was retired at its first delivery, so the budget armed when `redeliver` lands belongs
/// to a later message the read-ahead has begun. Cancelling it restarts the bound `max_receipt_time` makes
/// unrestartable, and with an exact body read already in flight nothing re-arms it, so a trickling peer is never
/// reclaimed.
///
/// The trickle is half `request_timeout`, so that clock is satisfied throughout and the close reason names which one
/// fired.
#[test]
fn a_redelivery_does_not_retire_the_next_message_budget() {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};
    let reasons = Arc::new(Mutex::new(Vec::new()));
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let cfg = ServerConfig {
        request_timeout: Some(Duration::from_millis(300)),
        max_receipt_time: Some(Duration::from_millis(900)),
        max_in_flight_requests: 2,
        ..ServerConfig::default()
    };
    let seen = Arc::new(AtomicUsize::new(0));
    let seen2 = Arc::clone(&seen);
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(PrefixWidth::U32, Endian::Big, false),
        body: move |req: Request<'_, ()>| {
            if seen2.fetch_add(1, Ordering::SeqCst) == 0 {
                let (deferred, permit) = req.responder.defer();
                thread::spawn(move || {
                    // After the second request's budget is armed and its exact body read is in flight.
                    thread::sleep(Duration::from_millis(400));
                    deferred.redeliver();
                });
                return Response::Defer(permit);
            }
            Response::Reply(echo_frame(b"ok"))
        },
    };
    let mut server = match Server::with_config([addr], cfg, proto) {
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
            send_framed(&mut s, b"A")?;
            thread::sleep(Duration::from_millis(50));
            s.write_all(&40u32.to_be_bytes())?;
            s.flush()?;
            for _ in 0..40 {
                if s.write_all(b"B").is_err() || s.flush().is_err() {
                    break; // closed under us, which is the point
                }
                thread::sleep(Duration::from_millis(150));
            }
            // The redelivery's own reply rides out while the second request is still trickling; drain to EOF rather
            // than asserting the connection was silent.
            s.set_read_timeout(Some(Duration::from_secs(5)))?;
            let mut sink = [0u8; 256];
            loop {
                match s.read(&mut sink) {
                    Ok(0) => break,
                    Ok(_) => {}
                    Err(e) if e.kind() == io::ErrorKind::ConnectionReset => {
                        break;
                    }
                    Err(e) => panic!("the server never closed: {e}"),
                }
            }
            Ok(())
        })();
        stop.shutdown();
        r
    });

    server.serve_forever().expect("serve_forever");
    client.join().expect("thread join").expect("client io");
    assert_eq!(
        reasons.lock().unwrap().as_slice(),
        &[CloseReason::ReceiptTimeout],
        "the pipelined request's budget must survive the redelivery - \
         nothing at all means the redelivery retired it and no later read \
         re-armed one"
    );
}

/// A spliced body is bounded per window, not whole.
///
/// `max_receipt_time` is a rate floor, so a body of any size is admitted at one window per budget. A spliced body is
/// one message however large, so it earns a budget per `receipt_window_bytes` moved. Six windows, each well inside the
/// budget, take longer than one budget, and every gap is inside both inactivity clocks, so only a total bound could
/// reap this.
///
/// Both header shapes run, because the renewal reads a mark only the splice path sets. A header read in **two** exact
/// steps arms the budget itself, since `submit_recv` does not call the second read idle, so a mark tied to whichever
/// call armed the budget never counts the body. A window larger than the body must be reaped.
#[test]
fn a_large_spliced_body_is_bounded_per_window_not_whole() {
    use std::sync::Mutex;

    const WINDOW: usize = 128 * 1024;
    const WINDOWS: usize = 6;
    const BODY: usize = WINDOW * WINDOWS;
    /// Gap between windows: inside `request_timeout`, so the readiness poll is re-armed on every one and can never be
    /// what reaps this.
    const GAP: Duration = Duration::from_millis(150);

    // A window larger than the body is never earned.
    for (what, split_header, window, renews) in [
        ("a one-read header", false, WINDOW, true),
        ("a two-read header", true, WINDOW, true),
        ("a window larger than the body", false, 2 * BODY, false),
    ] {
        let mut fds = [0 as libc::c_int; 2];
        // SAFETY: `pipe(2)` fills the two-element array with {read, write}.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe");
        let (pipe_rd, pipe_wr) = (fds[0], fds[1]);

        let reasons = Arc::new(Mutex::new(Vec::new()));
        let cfg = ServerConfig {
            // One window every 150 ms, so no window is remotely near the budget - but six of them take ~900 ms, and a
            // budget armed once for the whole transfer fires at 500 ms, mid-body.
            max_receipt_time: Some(Duration::from_millis(500)),
            // `ServerConfig` requires the receipt budget to exceed it.
            request_timeout: Some(Duration::from_millis(400)),
            idle_timeout: None,
            receipt_window_bytes: window,
            ..ServerConfig::default()
        };
        let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
        // The `splice_header` shape, read in one exact step or two, since `frame_step` requires a splice framer to
        // buffer the whole header and nothing past it.
        let header = move |buf: &[u8], _s: &mut ()| -> Framing {
            if split_header && buf.is_empty() {
                return Framing::Need(1); // the tag, then the length
            }
            if buf.len() < 5 {
                return Framing::Need(5 - buf.len());
            }
            let len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
            match buf[0] {
                b'S' => Framing::SpliceBody {
                    header_len: 5,
                    body_len: len,
                    fd: pipe_wr, // borrowed; the server never owns or closes it
                },
                b'C' => Framing::Complete {
                    header_len: 5,
                    body_len: len,
                },
                _ => Framing::Invalid,
            }
        };
        let proto = Protocol {
            accept: |_: Incoming<'_>| Some(()),
            header,
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

        // Drain the pipe for the whole run, so the splice never blocks.
        let draining = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let drain = {
            let draining = Arc::clone(&draining);
            thread::spawn(move || {
                let mut sink = vec![0u8; 64 * 1024];
                while draining.load(std::sync::atomic::Ordering::Relaxed) {
                    // SAFETY: `pipe_rd` is a live read end owned by this test.
                    let n = unsafe { libc::read(pipe_rd, sink.as_mut_ptr().cast(), sink.len()) };
                    if n <= 0 {
                        break;
                    }
                }
            })
        };

        let client = thread::spawn(move || {
            let _stop = ShutdownOnDrop(stop.clone());
            let r = (|| -> io::Result<()> {
                let mut s = connect_tcp(v4)?;
                let mut hdr = vec![b'S'];
                hdr.extend_from_slice(&(BODY as u32).to_be_bytes());
                s.write_all(&hdr)?;
                s.flush()?;
                let chunk = vec![b'x'; WINDOW];
                for _ in 0..WINDOWS {
                    s.write_all(&chunk)?;
                    s.flush()?;
                    thread::sleep(GAP);
                }
                // Alive? Then the transfer was never reaped, and the budget was retired with the message rather than
                // left armed.
                splice_frame(&mut s, b'C', b"ping")?;
                assert_eq!(recv_framed(&mut s)?, b"ping");
                Ok(())
            })();
            stop.shutdown();
            r
        });

        server.serve_forever().expect("serve_forever");
        draining.store(false, std::sync::atomic::Ordering::Relaxed);
        // SAFETY: the test owns both ends; the server never closes `pipe_wr`.
        unsafe {
            libc::close(pipe_wr);
            libc::close(pipe_rd);
        }
        let _ = drain.join();
        // A connection reaped mid-transfer cannot answer the ping, so `client io` fails first.
        let served = client.join().expect("thread join");
        // Not an equality against `[PeerClosed]`, since whether the peer-close is seen before `shutdown` is a race with
        // no bearing on the budget.
        let got = reasons.lock().unwrap().clone();
        if !renews {
            assert!(
                got.contains(&CloseReason::ReceiptTimeout),
                "{what}: no window was ever moved, so the budget should have \
                 bounded the transfer whole (reasons: {got:?})"
            );
            assert!(served.is_err(), "{what}: answered after its budget");
            continue;
        }
        assert!(
            !got.contains(&CloseReason::ReceiptTimeout),
            "{what}: a body moving a window per third of a budget is above \
             the floor: ReceiptTimeout means the budget bounded the transfer \
             whole, so wall clock capped upload size (reasons: {got:?})"
        );
        served.unwrap_or_else(|e| panic!("{what}: client io: {e}"));
    }
}

/// The receipt budget covers a spliced body, in both directions.
///
/// A `Framing::SpliceBody` body never enters `submit_recv` or `deliver_one`, so `submit_splice_recv` and
/// `on_splice_recv_complete` arm and retire the budget. Unarmed, only inactivity clocks that any arriving byte re-arms
/// bound a trickle, and left armed past the message, the budget reaps a connection that moved its body on time.
///
/// Both halves run on the plain TCP splice, the same code as the kTLS one up to the blocking or polling difference (see
/// `submit_splice_recv`).
#[test]
fn the_receipt_budget_bounds_a_spliced_body_and_ends_with_it() {
    use std::sync::Mutex;
    for (what, trickle) in [("a healthy body", false), ("a trickle", true)] {
        let mut fds = [0 as libc::c_int; 2];
        // SAFETY: `pipe(2)` fills the two-element array with {read, write}.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe");
        let (pipe_rd, pipe_wr) = (fds[0], fds[1]);

        let reasons = Arc::new(Mutex::new(Vec::new()));
        let cfg = ServerConfig {
            request_timeout: Some(Duration::from_millis(300)),
            max_receipt_time: Some(Duration::from_millis(700)),
            // Unset, so a connection that has finished its message and gone quiet has no other clock that could reap
            // it: the healthy case fails loudly if the budget is still armed.
            idle_timeout: None,
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

        // 64 bytes: well inside a pipe's capacity, so no reader is needed and nothing here can block on backpressure.
        const BODY: usize = 64;
        let client = thread::spawn(move || {
            let _stop = ShutdownOnDrop(stop.clone());
            let r = (|| -> io::Result<()> {
                let mut s = connect_tcp(v4)?;
                let mut hdr = vec![b'S'];
                hdr.extend_from_slice(&(BODY as u32).to_be_bytes());
                s.write_all(&hdr)?;
                s.flush()?;
                if trickle {
                    // One byte per 150 ms - half `request_timeout`, so the readiness poll is re-armed on every byte and
                    // never fires, while the body needs 9.6 s against a 700 ms budget.
                    for _ in 0..BODY {
                        if s.write_all(b"x").is_err() || s.flush().is_err() {
                            break; // reaped under us, which is the point
                        }
                        thread::sleep(Duration::from_millis(150));
                    }
                } else {
                    s.write_all(&[b'x'; BODY])?;
                    s.flush()?;
                    // The message is over. Stay quiet for longer than the budget: a budget left armed reaps this
                    // connection.
                    thread::sleep(Duration::from_millis(1200));
                    // Still alive? Then the framing survived too.
                    splice_frame(&mut s, b'C', b"ping")?;
                    assert_eq!(recv_framed(&mut s)?, b"ping");
                    return Ok(());
                }
                let mut sink = [0u8; 64];
                s.set_read_timeout(Some(Duration::from_secs(5)))?;
                match s.read(&mut sink) {
                    Ok(0) => Ok(()),
                    Ok(n) => panic!("answered {n} bytes to a trickled body"),
                    Err(e) if e.kind() == io::ErrorKind::ConnectionReset => Ok(()),
                    Err(e) => panic!("the slot was never reclaimed: {e}"),
                }
            })();
            stop.shutdown();
            r
        });

        server.serve_forever().expect("serve_forever");
        // SAFETY: the test owns both ends; the server never closes `pipe_wr`.
        unsafe {
            libc::close(pipe_wr);
            libc::close(pipe_rd);
        }
        client.join().expect("thread join").expect("client io");
        let got = reasons.lock().unwrap().clone();
        if trickle {
            assert_eq!(
                got.as_slice(),
                &[CloseReason::ReceiptTimeout],
                "{what}: a spliced body under the floor must read as \
                 ReceiptTimeout - nothing at all means the budget never \
                 armed, since no other clock on this path is a total bound"
            );
        } else {
            // The healthy connection ends by the client's FIN or its `shutdown` request, whichever the loop reaches
            // first, and a teardown that wins before the hook runs records nothing. That race has no bearing on the
            // budget, so any benign ending passes, but never the budget, since this connection finished on time.
            assert!(
                matches!(
                    got.as_slice(),
                    [] | [CloseReason::PeerClosed] | [CloseReason::ShuttingDown]
                ),
                "{what}: the budget must be retired when the body completes \
                 - ReceiptTimeout here is a healthy connection reaped for \
                 having finished on time (reasons: {got:?})"
            );
        }
    }
}

/// A reply the handler declared final keeps the pump gate shut even when a body is still streaming ahead of it.
///
/// `Connection::has_deferred_close` is that gate, set by a `Response::ReplyFile { close: true }` that arrives while
/// another body streams. `take_queued_file_reply` must not clear it for a deferred body that does not carry the close,
/// or the gate reopens for the whole read-ahead window and every request answered meanwhile is discarded unsent by
/// `drop_queued_file_reply` when the final body retires.
///
/// The parameter is the control. With the close on the active tail or the first deferred body the gate holds
/// regardless, and the close on the second deferred body is the case that bites.
#[cfg(feature = "uring-fs")]
#[test]
fn a_deferred_close_keeps_the_gate_shut_for_a_later_body() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc;
    use truenas_ros::sync_fs::{OFlag, OpenHow};
    use truenas_ros::uring_fs::{Anchor, FsConfig, UringFs};

    const CHUNK: usize = 16 * 1024;
    const SIZE: usize = 8 * CHUNK;
    const REQS: usize = 5;

    let dir = truenas_ros::tempdir().unwrap();
    std::fs::write(dir.path().join("obj"), vec![0x42u8; SIZE]).expect("fixture");

    // `close_at` is the 0-based request whose `ReplyFile` is declared final: 0 is the active tail, 1 the first deferred
    // body, 2 the second. The handler must run exactly `close_at + 1` times in every case.
    for close_at in [0usize, 1, 2] {
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
            pool_size: 4,
            fs_ops: 8,
            fs_body_chunk: CHUNK,
            // Read-ahead is the precondition: at the default cap of one the pump never frames a second request, so no
            // body is ever deferred behind another.
            max_in_flight_requests: 8,
            ..ServerConfig::default()
        };
        let seen = Arc::new(AtomicUsize::new(0));
        let seen2 = Arc::clone(&seen);
        let proto = Protocol {
            accept: |_: Incoming<'_>| Some(()),
            header: length_prefix_header::<()>(PrefixWidth::U32, Endian::Big, false),
            body: move |_req: Request<'_, ()>| {
                let nth = seen2.fetch_add(1, Ordering::SeqCst);
                Response::ReplyFile {
                    head: Vec::new(),
                    file: file.clone(),
                    offset: 0,
                    len: SIZE as u64,
                    close: nth == close_at,
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
        let client = thread::spawn(move || -> io::Result<(usize, bool)> {
            let _stop = ShutdownOnDrop(stop.clone());
            let mut s = connect_tcp(v4)?;
            // Every request in one write, so all of them are in the socket buffer before the first body starts
            // streaming.
            let mut wire = Vec::new();
            for _ in 0..REQS {
                wire.extend_from_slice(&1u32.to_be_bytes());
                wire.push(b'g');
            }
            s.write_all(&wire)?;
            s.flush()?;
            let mut got = Vec::new();
            // The gate shuts before the refused requests are read, and a close with unread data sends RST rather than
            // FIN (`tcp_close`, `net/ipv4/tcp.c:3165-3170`). Whether any are left is timing, and a reset can lose
            // queued bytes, so the byte count is exact only on a clean ending, while `seen` holds either way.
            let clean = match s.read_to_end(&mut got) {
                Ok(_) => true,
                Err(e) if e.kind() == io::ErrorKind::ConnectionReset => false,
                Err(e) => return Err(e),
            };
            stop.shutdown();
            Ok((got.len(), clean))
        });
        server.serve_forever().expect("serve_forever");
        let (bytes, clean) = client.join().expect("join").expect("client");
        assert_eq!(
            seen.load(Ordering::SeqCst),
            close_at + 1,
            "close_at={close_at}: requests admitted past the final reply"
        );
        let want = (close_at + 1) * SIZE;
        if clean {
            assert_eq!(bytes, want, "close_at={close_at}: bodies on the wire");
        } else {
            assert!(
                bytes <= want,
                "close_at={close_at}: {bytes} bytes on the wire, past the \
                 {want} the gate allows"
            );
        }
    }
}

/// A peer that half-closes after its request still gets its response.
///
/// `shutdown(SHUT_WR)` says the client will send nothing more and is waiting to read. It completes the parked
/// read-ahead recv with `res == 0`, `CloseReason::PeerClosed`, and the connection must still finish the work it owes,
/// since once `closing`, `kick_send` swallows the queued reply, `drain_injections` drops the worker outcome and
/// `on_pump_read` drops every file-body chunk.
///
/// `cap` is the trigger. At the default read-ahead of one nothing arms a second recv while a reply is owed, so the FIN
/// is seen only after. The handler defers because an inline reply is sent before the FIN lands.
#[test]
fn a_peer_half_close_does_not_reap_a_connection_that_owes_a_reply() {
    use std::io::{Read, Write};
    for cap in [1usize, 4] {
        let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
        let cfg = ServerConfig {
            max_in_flight_requests: cap,
            ..Default::default()
        };
        let proto = Protocol {
            accept: |_: Incoming<'_>| Some(()),
            header: length_prefix_header::<()>(PrefixWidth::U32, Endian::Big, false),
            body: |req: Request<'_, ()>| {
                let Request { body, responder, .. } = req;
                let input = body.to_vec();
                let (deferred, permit) = responder.defer();
                thread::spawn(move || {
                    thread::sleep(Duration::from_millis(20));
                    deferred.reply(echo_frame(&input));
                });
                Response::Defer(permit)
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
        let stop = server.shutdown_handle();
        let client = thread::spawn(move || -> std::io::Result<usize> {
            let _stop = ShutdownOnDrop(stop.clone());
            let mut s = connect_tcp(v4)?;
            let body = b"hello";
            let mut wire = (body.len() as u32).to_be_bytes().to_vec();
            wire.extend_from_slice(body);
            s.write_all(&wire)?;
            s.flush()?;
            // The politeness: nothing more is coming from this side.
            s.shutdown(std::net::Shutdown::Write)?;
            let mut got = Vec::new();
            let n = s.read_to_end(&mut got).unwrap_or(got.len());
            stop.shutdown();
            Ok(n)
        });
        server.serve_forever().expect("serve_forever");
        let n = client.join().expect("join").expect("client");
        assert_eq!(n, 9, "cap={cap}: a half-closed peer got {n} bytes of a 9-byte reply");
    }
}

/// A half-closed peer whose owed work completes with **nothing to send** must still have its connection closed.
///
/// `peer_closed` retires the recv side and leaves the close to the send path, but a one-way request
/// (`Deferred::reply(Vec::new())`, the `Injected::Done` arm) queues no PDU, so no send completes. The pump re-arms a
/// read, the FIN completes it at once, and the `peer_closed` arm in `on_recv_complete` must close there, or the slot
/// and fd are held for the life of the server.
///
/// `cap` is the trigger, as in `a_peer_half_close_does_not_reap_a_connection_that_owes_a_reply`.
#[test]
fn a_half_closed_peer_closes_when_its_one_way_request_finishes() {
    use std::io::{Read, Write};
    for cap in [1usize, 4] {
        let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
        let cfg = ServerConfig {
            max_in_flight_requests: cap,
            ..Default::default()
        };
        let proto = Protocol {
            accept: |_: Incoming<'_>| Some(()),
            header: length_prefix_header::<()>(PrefixWidth::U32, Endian::Big, false),
            body: |req: Request<'_, ()>| {
                let Request { responder, .. } = req;
                let (deferred, permit) = responder.defer();
                thread::spawn(move || {
                    thread::sleep(Duration::from_millis(20));
                    // One-way: the request completes with no PDU at all.
                    deferred.reply(Vec::new());
                });
                Response::Defer(permit)
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
        let stop = server.shutdown_handle();
        let client = thread::spawn(move || -> std::io::Result<bool> {
            let _stop = ShutdownOnDrop(stop.clone());
            let mut s = connect_tcp(v4)?;
            s.set_read_timeout(Some(Duration::from_secs(3)))?;
            let body = b"hello";
            let mut wire = (body.len() as u32).to_be_bytes().to_vec();
            wire.extend_from_slice(body);
            s.write_all(&wire)?;
            s.flush()?;
            s.shutdown(std::net::Shutdown::Write)?;
            // Nothing more can arrive once the one-way request is answered, so the server must close. EOF is that close
            // and a timeout is the leak.
            let mut buf = [0u8; 1];
            let eof = matches!(s.read(&mut buf), Ok(0));
            stop.shutdown();
            Ok(eof)
        });
        server.serve_forever().expect("serve_forever");
        let eof = client.join().expect("join").expect("client");
        assert!(
            eof,
            "cap={cap}: the connection was never closed after the one-way \
             request completed"
        );
    }
}

/// A file lease a body handler takes on the ring reaches the server's break handler once another opens the file for
/// writing, and the handler's release lets that opener go at once rather than after `lease-break-time`. On a temp
/// folder, and on a ZFS dataset where one is provisioned, which takes leases as any file system does
/// (`generic_setlease` in `zpl_file.c`).
#[cfg(feature = "uring-fs")]
#[test]
fn a_file_lease_break_reaches_the_server_s_handler() {
    use std::sync::Mutex;
    use std::sync::mpsc;
    use truenas_ros::uring_fs::File;
    use truenas_ros::uring_fs::file_lease::{FileLeaseId, block_signals};

    // The server runs on this thread, which its breaks are sent to.
    block_signals().unwrap();
    let temp = truenas_ros::tempdir().unwrap();
    let mut dirs = vec![temp.path().to_path_buf()];
    if let Some(ds) = zfs_dir::zfs_dir_or_skip() {
        dirs.push(ds);
    }
    for dir in dirs {
        let path = dir.join(format!("rostest_lease_{}", std::process::id()));
        std::fs::write(&path, b"x").unwrap();
        let taken: Arc<Mutex<Option<FileLeaseId>>> = Arc::new(Mutex::new(None));
        let t = Arc::clone(&taken);
        let leased = path.clone();
        let body = move |mut req: Request<'_, ()>| -> Response {
            let _ = req.body.take();
            let Some(mut fs) = req.fs.take() else {
                return Response::Close;
            };
            let read = std::fs::File::open(&leased).unwrap();
            let id = fs.file_lease(&File::from_fd(read.into()));
            *t.lock().unwrap() = id.ok();
            Response::Reply(echo_frame(b"leased"))
        };
        let protocol = Protocol {
            accept: |_: Incoming<'_>| Some(()),
            header: length_prefix_header::<()>(PrefixWidth::U32, Endian::Big, false),
            body,
        };
        let cfg = ServerConfig {
            pool_size: 8,
            fs_ops: 8,
            ..ServerConfig::default()
        };
        let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
        let mut server = match Server::with_config([addr], cfg, protocol) {
            Ok(s) => s,
            Err(e) if should_skip(&e) => return,
            Err(e) => panic!("bind with fs pool: {e}"),
        };
        let (heard, hear) = mpsc::channel();
        server.set_file_lease_break_handler(move |id, fs| {
            heard.send(id).unwrap();
            fs.release_file_lease(id).expect("give the lease back");
        });
        let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
            panic!("expected Tcp");
        };
        let stop = server.shutdown_handle();
        let writer = path.clone();
        let client = thread::spawn(move || -> io::Result<Duration> {
            let _stop = ShutdownOnDrop(stop.clone()); // fail fast on panic
            let mut s = connect_tcp(v4)?;
            send_framed(&mut s, b"go")?;
            assert_eq!(recv_framed(&mut s)?, b"leased");
            let at = Instant::now();
            std::fs::OpenOptions::new().write(true).open(&writer)?;
            let waited = at.elapsed();
            drop(s);
            stop.shutdown();
            Ok(waited)
        });
        server.serve_forever().expect("serve_forever file lease");
        let waited = client.join().unwrap().expect("client io");
        let taken = taken.lock().unwrap().expect("the handler took a lease");
        assert_eq!(hear.try_recv().ok(), Some(taken), "{dir:?}");
        assert!(waited < Duration::from_secs(10), "{dir:?} {waited:?}");
        std::fs::remove_file(&path).unwrap();
    }
}
