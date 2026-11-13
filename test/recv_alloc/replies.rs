use super::*;

// ---- the reply side, replies built in storage claimed from the pool -------

/// How a reply built in storage claimed from the pool is sent.
#[derive(Clone, Copy)]
enum Sent {
    /// Inline, as one `SendBuf::recycled` segment.
    Marked,
    /// Through a `Deferred`, with `reply_recycled`.
    MarkedDeferred,
    /// Inline, as a plain owned reply, which is freed once sent.
    Plain,
}

/// Answer `warmup` then `measured` requests on one connection, each reply built in storage claimed from the ring's body
/// pool and sent as `sent` says, and return how many large allocations the measured replies cost.
fn reply_cost(warmup: usize, measured: usize, sent: Sent) -> Option<usize> {
    use std::cell::RefCell;
    use std::rc::Rc;
    use truenas_ros::net::server::{
        BodyRecycler, Endian, PrefixWidth, Protocol, Request, Response, SendBuf, length_prefix_header,
    };

    // Past `MED`, so each claim the pool cannot serve is counted.
    const ROOM: usize = 4 * 1024;
    const ANSWER: &[u8] = b"answered";

    // Filled after the server exists. The handler runs on this same thread, so the cell is never read before
    // serve_forever fills it.
    let seam: Rc<RefCell<Option<BodyRecycler>>> = Rc::new(RefCell::new(None));
    let handler_seam = Rc::clone(&seam);
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(PrefixWidth::U32, Endian::Big, false),
        body: move |req: Request<'_, ()>| {
            let mut reply = handler_seam
                .borrow()
                .as_ref()
                .expect("filled before serving")
                .claim(ROOM);
            reply.extend_from_slice(&(ANSWER.len() as u32).to_be_bytes());
            reply.extend_from_slice(ANSWER);
            match sent {
                Sent::Marked => Response::ReplyVectored {
                    segments: vec![SendBuf::recycled(reply)],
                    close: false,
                },
                Sent::MarkedDeferred => {
                    let (deferred, permit) = req.responder.defer();
                    deferred.reply_recycled(reply);
                    Response::Defer(permit)
                }
                Sent::Plain => Response::Reply(reply),
            }
        },
    };

    let cfg = ServerConfig {
        pool_size: 8,
        ..ServerConfig::default()
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let mut server = match Server::with_config([addr], cfg, proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return None,
        Err(e) => panic!("bind: {e}"),
    };
    *seam.borrow_mut() = server.body_recycler();
    assert!(seam.borrow().is_some(), "a server always carries a body pool");
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();

    let client = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone());
        let mut s = TcpStream::connect(v4).expect("connect");
        s.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
        let mut got = [0u8; 4 + ANSWER.len()];
        let mut ask = |s: &mut TcpStream| {
            s.write_all(&[0, 0, 0, 1, b'q']).expect("request");
            s.read_exact(&mut got).expect("reply");
            assert_eq!(&got[4..], ANSWER, "intact");
        };
        for _ in 0..warmup {
            ask(&mut s);
        }
        let before = MED_ALLOCS.load(Ordering::Relaxed);
        for _ in 0..measured {
            ask(&mut s);
        }
        let cost = MED_ALLOCS.load(Ordering::Relaxed) - before;
        drop(s);
        stop.shutdown();
        cost
    });

    server.serve_forever().expect("serve_forever");
    Some(client.join().expect("client thread"))
}

/// A reply built in storage claimed from the ring's body pool, and marked as the pool's, must not cost an allocation
/// per reply, whether it is given inline or through a `Deferred`.
///
/// Its storage goes home once sent, and the next claim reuses it. The same replies sent plain are freed once sent, so
/// every claim allocates again. That shows the count sees a reply's storage, and that storage no one marked never
/// reaches the pool.
#[test]
fn a_reply_claimed_from_the_pool_does_not_allocate_per_reply() {
    let _turn = MEASURING.lock().unwrap_or_else(|e| e.into_inner());
    for sent in [Sent::Marked, Sent::MarkedDeferred] {
        let Some(few) = reply_cost(8, 4, sent) else {
            return; // io_uring unavailable
        };
        let Some(many) = reply_cost(8, 64, sent) else {
            return;
        };
        // Sixty more replies, so one allocation a reply puts about sixty between the runs.
        assert!(
            many <= few + 4,
            "reply cost scales with the replies: 4 cost {few} large \
             allocations, 64 cost {many}. A sent reply's storage is not \
             reaching the pool, or the claim is not served from it."
        );
    }
    let Some(plain) = reply_cost(8, 64, Sent::Plain) else {
        return;
    };
    assert!(
        plain >= 60,
        "64 plain replies cost {plain} large allocations. Storage no one \
         marked reached the pool, or the count no longer sees a reply."
    );
}

// ---- storage that reaches no request goes home ----------------------------

/// `rounds` connections, one after another, each claiming a reply's storage from the ring's body pool, closing itself
/// through a push handle and only then replying, so the reply marked recycled reaches no request. The count of large
/// allocations is the return value.
fn spilled_cost(rounds: usize) -> Option<usize> {
    use std::cell::RefCell;
    use std::rc::Rc;
    use truenas_ros::net::server::{
        BodyRecycler, Endian, PrefixWidth, Protocol, Request, Response, length_prefix_header,
    };

    // Past `BIG`, so a claim the pool cannot serve is counted and the little a connection costs is not.
    const ROOM: usize = 256 * 1024;

    // Filled after the server exists. The handler runs on this same thread, so the cell is never read before
    // serve_forever fills it.
    let seam: Rc<RefCell<Option<BodyRecycler>>> = Rc::new(RefCell::new(None));
    let handler_seam = Rc::clone(&seam);
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(PrefixWidth::U32, Endian::Big, false),
        body: move |req: Request<'_, ()>| {
            let mut reply = handler_seam
                .borrow()
                .as_ref()
                .expect("filled before serving")
                .claim(ROOM);
            reply.extend_from_slice(b"late");
            req.responder.push_handle().close();
            let (deferred, permit) = req.responder.defer();
            deferred.reply_recycled(reply);
            Response::Defer(permit)
        },
    };

    let cfg = ServerConfig {
        pool_size: 8,
        ..ServerConfig::default()
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let mut server = match Server::with_config([addr], cfg, proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return None,
        Err(e) => panic!("bind: {e}"),
    };
    *seam.borrow_mut() = server.body_recycler();
    assert!(seam.borrow().is_some(), "a server always carries a body pool");
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();

    let client = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone());
        let before = BIG_ALLOCS.load(Ordering::Relaxed);
        for _ in 0..rounds {
            let mut s = TcpStream::connect(v4).expect("connect");
            s.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
            s.write_all(&[0, 0, 0, 1, b'q']).expect("request");
            let mut rest = Vec::new();
            s.read_to_end(&mut rest).expect("the server closes");
            assert!(rest.is_empty(), "the reply reached no connection");
        }
        let cost = BIG_ALLOCS.load(Ordering::Relaxed) - before;
        stop.shutdown();
        cost
    });

    server.serve_forever().expect("serve_forever");
    Some(client.join().expect("client thread"))
}

/// A reply marked recycled whose connection closed before it arrived goes home as the server drops it, so the next
/// connection's claim reuses its storage. Freed instead, every round claims fresh storage.
#[test]
fn a_recycled_reply_that_reaches_no_request_goes_home() {
    let _turn = MEASURING.lock().unwrap_or_else(|e| e.into_inner());
    let Some(few) = spilled_cost(2) else {
        return; // io_uring unavailable
    };
    let Some(many) = spilled_cost(10) else {
        return;
    };
    assert!(
        many <= few + 3,
        "the cost scales with the rounds: 2 cost {few} large allocations, \
         10 cost {many}. A reply that reached no request was freed rather \
         than sent home."
    );
}
