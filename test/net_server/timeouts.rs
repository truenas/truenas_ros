use super::*;

#[test]
fn tcp_idle_timeout() {
    // With an idle timeout set, a connection left waiting for its next request is closed and its slot reclaimed - while
    // an in-flight request is never interrupted. Covers both idle recvs: after a completed round-trip, and a connection
    // that sends nothing at all.
    let cfg = ServerConfig {
        idle_timeout: Some(Duration::from_millis(200)),
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
        let r = (|| -> io::Result<()> {
            // Serviced, then idle: the active exchange succeeds, then the idle connection is closed on the *next*
            // header recv's timeout.
            let mut s = connect_tcp(v4)?;
            send_framed(&mut s, b"ping")?;
            assert_eq!(recv_framed(&mut s)?, b"ping");
            expect_idle_close(&mut s)?;

            // Never sends: closed on the *first* header recv's timeout.
            let mut silent = connect_tcp(v4)?;
            expect_idle_close(&mut silent)?;
            Ok(())
        })();
        stop.shutdown();
        r
    });

    server.serve_forever().expect("serve_forever");
    client.join().expect("thread join").expect("client io");
}

#[test]
fn timeouts_duration_max_mean_never() {
    // `Duration::MAX`, and anything at or past 2^63 seconds, must mean never fires, so the kernel timespec conversion
    // clamps `tv_sec`. An unclamped `as i64` wraps negative, LINK_TIMEOUT prep fails `-EINVAL`, and its linked recv
    // dies `-ECANCELED`, closing every connection at its first parked read.
    let cfg = ServerConfig {
        idle_timeout: Some(Duration::MAX),
        request_timeout: Some(Duration::MAX),
        send_timeout: Some(Duration::MAX),
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
        let _stop = ShutdownOnDrop(stop.clone());
        let r = (|| -> io::Result<()> {
            let mut s = connect_tcp(v4)?;
            // Sit parked (idle clock armed) well past any instant bogus fire.
            thread::sleep(Duration::from_millis(300));
            send_framed(&mut s, b"still here")?;
            assert_eq!(recv_framed(&mut s)?, b"still here");
            // Hold the REQUEST clock across a wait too: prefix now, body later - the split parks the body recv with its
            // linked clock.
            let mut frame = echo_frame(b"split");
            let body = frame.split_off(4);
            s.write_all(&frame)?;
            thread::sleep(Duration::from_millis(250));
            s.write_all(&body)?;
            assert_eq!(recv_framed(&mut s)?, b"split");
            Ok(())
        })();
        stop.shutdown();
        r
    });

    server.serve_forever().expect("serve_forever");
    client.join().expect("thread join").expect("client io");
}

#[test]
fn tcp_request_timeout_reclaims_stalled_body() {
    // A slow-loris guard. A peer that sends a valid length prefix and withholds the body must not pin its slot, so
    // `request_timeout` bounds the request mid-frame where `idle_timeout` never would. An idle keep-alive connection is
    // left to `idle_timeout`.
    let cfg = ServerConfig {
        request_timeout: Some(Duration::from_millis(200)),
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
        let _stop = ShutdownOnDrop(stop.clone());
        let r = (|| -> io::Result<()> {
            // A normal full request round-trips (the timer never fires).
            let mut ok = connect_tcp(v4)?;
            send_framed(&mut ok, b"ping")?;
            assert_eq!(recv_framed(&mut ok)?, b"ping");

            let mut stall = connect_tcp(v4)?;
            stall.write_all(&64u32.to_be_bytes())?;
            expect_idle_close(&mut stall)?; // detects the prompt server close

            thread::sleep(Duration::from_millis(400));
            send_framed(&mut ok, b"pong")?;
            assert_eq!(recv_framed(&mut ok)?, b"pong");
            Ok(())
        })();
        stop.shutdown();
        r
    });

    server.serve_forever().expect("serve_forever");
    client.join().expect("thread join").expect("client io");
}

#[test]
fn tcp_request_timeout_partial_body_reports_request_timeout() {
    // A peer that trickles some body bytes then stalls must close as `RequestTimeout`, not `TruncatedMessage`. A
    // LINK_TIMEOUT-cancelled MSG_WAITALL recv that consumed bytes completes with `res = done_io > 0`
    // (`io_sendrecv_fail`), the same as a peer FIN mid-frame, so the server pairs the recv completion with its clock
    // CQE, `-ETIME` against `-ECANCELED`, to tell them apart.
    use std::sync::Mutex;
    let reasons = Arc::new(Mutex::new(Vec::new()));
    let cfg = ServerConfig {
        request_timeout: Some(Duration::from_millis(200)),
        ..ServerConfig::default()
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let mut server = match Server::with_config([addr], cfg, length_prefixed(PrefixWidth::U32, Endian::Big, false, echo))
    {
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
            // A valid prefix declaring 64 bytes, then only 10 of them: the body recv accrues partial progress before
            // the clock fires.
            s.write_all(&64u32.to_be_bytes())?;
            s.write_all(&[0xEE; 10])?;
            expect_idle_close(&mut s)?; // reclaimed promptly (< 2s)
            Ok(())
        })();
        stop.shutdown();
        r
    });

    server.serve_forever().expect("serve_forever");
    client.join().expect("thread join").expect("client io");
    assert_eq!(
        reasons.lock().unwrap().as_slice(),
        &[CloseReason::RequestTimeout],
        "a stalled-mid-body peer must read as RequestTimeout, \
         not TruncatedMessage"
    );
}

/// A receipt budget at or under the inactivity bound leaves the latter dead, since the message is closed before a whole
/// silent period passes. Validation refuses it, where the operator finds out.
#[test]
fn a_receipt_budget_may_not_pre_empt_the_inactivity_bound() {
    use truenas_ros::net::server::Listen;
    let one = || {
        vec![Listen::from(ServerAddr::Tcp(
            "127.0.0.1:0".parse::<SocketAddrV4>().unwrap(),
        ))]
    };
    let build = |cfg: ServerConfig| Server::with_config(one(), cfg, noop_protocol()).map(|_| ());
    let request = Duration::from_secs(30);
    for (what, receipt) in [("under", Duration::from_secs(29)), ("equal", request)] {
        let cfg = ServerConfig {
            request_timeout: Some(request),
            max_receipt_time: Some(receipt),
            ..ServerConfig::default()
        };
        match build(cfg) {
            Err(Error::Validation(m)) => {
                assert!(m.contains("must exceed request_timeout"), "{what}: wrong message {m:?}")
            }
            other => panic!("{what} must be refused, got {:?}", other.is_ok()),
        }
    }
    // One period longer is the smallest configuration that means what it says, and it is accepted. Either clock alone
    // is fine too: the budget is the rate floor, the inactivity bound is the liveness check, and neither implies the
    // other.
    for (what, cfg) in [
        (
            "both",
            ServerConfig {
                request_timeout: Some(request),
                max_receipt_time: Some(request + Duration::from_millis(1)),
                ..ServerConfig::default()
            },
        ),
        (
            "budget alone",
            ServerConfig {
                max_receipt_time: Some(request),
                ..ServerConfig::default()
            },
        ),
        (
            "inactivity alone",
            ServerConfig {
                request_timeout: Some(request),
                ..ServerConfig::default()
            },
        ),
    ] {
        match build(cfg) {
            Ok(()) => {}
            Err(e) if should_skip(&e) => return,
            Err(e) => panic!("{what} must be usable, got {e}"),
        }
    }
}

/// `request_timeout` bounds progress per period, so a peer that sends one byte just inside every period holds its slot
/// forever. A slot is taken at accept, before authentication, so `pool_size` such peers deny service.
/// `max_receipt_time` cannot be restarted by progress, since it runs from a message's first byte to its delivery.
///
/// The trickle is faster than `request_timeout`, so the inactivity guard never fires and the close reason proves which
/// clock reclaimed the slot.
#[test]
fn max_receipt_time_reclaims_a_peer_trickling_under_the_floor() {
    use std::sync::Mutex;
    let reasons = Arc::new(Mutex::new(Vec::new()));
    let cfg = ServerConfig {
        request_timeout: Some(Duration::from_millis(200)),
        max_receipt_time: Some(Duration::from_millis(700)),
        ..ServerConfig::default()
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let mut server = match Server::with_config([addr], cfg, length_prefixed(PrefixWidth::U32, Endian::Big, false, echo))
    {
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
            // Declare 64 bytes, then feed them one at a time every 100 ms -- half the request_timeout period, so that
            // clock is re-armed on every byte and never fires. At this pace the message needs 6.4 s, nine times the
            // receipt budget.
            s.write_all(&64u32.to_be_bytes())?;
            for _ in 0..64 {
                if s.write_all(&[0xEE]).is_err() {
                    break; // the server closed under us, which is the point
                }
                if s.flush().is_err() {
                    break;
                }
                thread::sleep(Duration::from_millis(100));
            }
            expect_idle_close(&mut s)?;
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
        "a peer under the rate floor must read as ReceiptTimeout - \
         RequestTimeout would mean the inactivity guard caught it, and \
         nothing at all would mean the budget never armed"
    );
}

/// The budget is not restarted by progress - the property that separates it from `request_timeout`, driven on the
/// framing that can tell them apart.
///
/// A length-prefixed body is one exact read, so a per-read re-arm is invisible there. A `More` scan re-enters
/// `submit_recv` on every chunk, so a budget cancelled and re-armed there rides the trickle forever, as the inactivity
/// clock does. The gaps are half `request_timeout`, so that clock is satisfied throughout and the close reason names
/// which one fired.
#[test]
fn a_chunk_scan_budget_is_not_restarted_by_progress() {
    use std::sync::Mutex;
    let reasons = Arc::new(Mutex::new(Vec::new()));
    let cfg = ServerConfig {
        request_timeout: Some(Duration::from_millis(200)),
        max_receipt_time: Some(Duration::from_millis(700)),
        ..ServerConfig::default()
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: lsp_header,
        body: |_req: Request<'_, ()>| Response::Reply(b"ok".to_vec()),
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
            // A header that never terminates, one byte per 100 ms: every chunk read completes and re-arms, so
            // `request_timeout` is satisfied on every one of them and never fires. Thirty bytes is 3 s of trickle
            // against a 700 ms budget.
            for _ in 0..30 {
                if s.write_all(b"x").is_err() || s.flush().is_err() {
                    break; // closed under us, which is the point
                }
                thread::sleep(Duration::from_millis(100));
            }
            expect_idle_close(&mut s)?;
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
        "a budget re-armed by each chunk never fires, and the scan runs on"
    );
}

/// Exactly one budget per message, and the retire cancels the one there is.
///
/// A `More` framer's chunk reads complete on any byte, so a trickled header is many non-idle reads of one message.
/// Arming per read stacks timers that share one `user_data`, so the retire's `ASYNC_CANCEL` reaps one and the rest fire
/// later on a connection that has done nothing wrong. The header completes well inside the budget, so any close is the
/// bug.
#[test]
fn a_trickled_header_leaves_exactly_one_receipt_budget() {
    let budget = Duration::from_millis(400);
    let cfg = ServerConfig {
        request_timeout: Some(Duration::from_millis(200)),
        max_receipt_time: Some(budget),
        ..ServerConfig::default()
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: lsp_header,
        body: |_req: Request<'_, ()>| Response::Reply(b"ok".to_vec()),
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
            // Eight chunk reads for one header, spread over 160 ms - well inside the budget, and none of the gaps near
            // the inactivity bound either.
            let head = b"Content-Length: 0\r\n\r\n";
            for b in head {
                s.write_all(&[*b])?;
                s.flush()?;
                thread::sleep(Duration::from_millis(160) / head.len() as u32);
            }
            let mut got = [0u8; 2];
            s.read_exact(&mut got)?;
            assert_eq!(&got, b"ok");

            // Sit idle for several budgets. A timer left over from the trickle fires here and takes the slot with it.
            thread::sleep(budget * 3);
            s.write_all(head)?;
            s.flush()?;
            s.read_exact(&mut got)?;
            assert_eq!(&got, b"ok", "a stale receipt budget reaped a healthy connection");
            Ok(())
        })();
        stop.shutdown();
        r
    });

    server.serve_forever().expect("serve_forever");
    client.join().expect("thread join").expect("client io");
}

/// The budget is retired at delivery, so it bounds receipt and nothing else.
///
/// A budget that outlived its message would fire during handling or between requests and kill healthy keep-alive
/// connections, and one re-armed rather than left running would degrade into the inactivity guard. Both are silent, so
/// the sleeps here are several times the budget with the connection well-behaved throughout.
#[test]
fn max_receipt_time_does_not_clock_handling_or_an_idle_connection() {
    let budget = Duration::from_millis(300);
    let cfg = ServerConfig {
        request_timeout: Some(Duration::from_millis(150)),
        max_receipt_time: Some(budget),
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
        let _stop = ShutdownOnDrop(stop.clone());
        let r = (|| -> io::Result<()> {
            let mut s = connect_tcp(v4)?;
            for i in 0..3 {
                send_framed(&mut s, b"ping")?;
                assert_eq!(recv_framed(&mut s)?, b"ping", "round {i}");
                // Idle for well over the budget between requests. A budget still armed from the last message reaps the
                // slot here.
                thread::sleep(budget * 3);
            }
            // And a message split across the budget in ONE go is fine so long as it lands inside it.
            s.write_all(&4u32.to_be_bytes())?;
            s.flush()?;
            thread::sleep(budget / 3);
            s.write_all(b"tail")?;
            s.flush()?;
            assert_eq!(recv_framed(&mut s)?, b"tail");
            Ok(())
        })();
        stop.shutdown();
        r
    });

    server.serve_forever().expect("serve_forever");
    client.join().expect("thread join").expect("client io");
}

#[test]
fn request_timeout_reclaims_stalled_more_scan() {
    // A `More` framer's chunk reads complete on any byte, so the request clock bounds them by inactivity. A peer that
    // sends a partial header and stalls has its non-idle chunk read time out and its slot reclaimed, where
    // `idle_timeout` would never fire mid-scan.
    let cfg = ServerConfig {
        request_timeout: Some(Duration::from_millis(200)),
        ..ServerConfig::default()
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: lsp_header,
        body: |_req: Request<'_, ()>| Response::Reply(b"ok".to_vec()),
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
            let mut stall = connect_tcp(v4)?;
            stall.write_all(b"Content-Length: 5\r\n")?;
            expect_idle_close(&mut stall)?;
            Ok(())
        })();
        stop.shutdown();
        r
    });

    server.serve_forever().expect("serve_forever");
    client.join().expect("thread join").expect("client io");
}
