use super::*;

// ---- the buffered side: placed bodies cycle through the recycler ----------

/// N large buffered bodies on one connection, the handler recycling each delivered `Vec`, or with `take` false reading
/// each where it lies. The count of large allocations is the return value.
fn buffered_cost(messages: usize, take: bool) -> Option<usize> {
    use std::cell::RefCell;
    use std::rc::Rc;
    use truenas_ros::http::protocol_deferrable;
    use truenas_ros::net::server::BodyRecycler;

    let http = HttpConfig {
        max_body: 4 * 1024 * 1024,
        ..HttpConfig::default()
    };
    let cfg = ServerConfig {
        pool_size: 8,
        // The reactor must admit what the codec admits, or an over-cap body dies on a raw close with no HTTP response.
        max_request_bytes: http.min_request_bytes(),
        ..ServerConfig::default()
    };
    // Filled after the server exists; the handler runs on this same thread, so the cell is never read before
    // serve_forever fills it.
    let seam: Rc<RefCell<Option<BodyRecycler>>> = Rc::new(RefCell::new(None));
    let handler_seam = Rc::clone(&seam);
    let proto = protocol_deferrable(
        http,
        |_i: Incoming<'_>| Some(0usize),
        move |mut req: HttpRequest<'_>, _: &mut usize| {
            // What a consumer does: own the body for its parse, then hand the storage home. Or read it where it lies,
            // and leave the storage to go home as the body drops.
            let n = req.body.len();
            if take {
                let body = req.body.take();
                if let Some(r) = handler_seam.borrow().as_ref() {
                    r.recycle(body);
                }
            }
            HttpVerdict::Respond(HttpResponse::new(200).header("x-bytes", n.to_string()))
        },
    )
    .expect("codec config is valid");

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

    // Over one pool buffer, so every body takes the placement path the pool serves; under max_body, so none is refused.
    let payload = vec![0x5au8; 1024 * 1024];
    let mut one = format!(
        "PUT /o HTTP/1.1\r\nHost: t\r\nContent-Length: {}\r\n\r\n",
        payload.len()
    )
    .into_bytes();
    one.extend_from_slice(&payload);
    drop(payload);

    let client = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone());
        let mut s = TcpStream::connect(v4).expect("connect");
        s.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
        let before = BIG_ALLOCS.load(Ordering::Relaxed);
        for _ in 0..messages {
            s.write_all(&one).expect("write");
            let status = read_status(&mut s).expect("status");
            assert_eq!(status, 200, "buffered put refused");
        }
        let cost = BIG_ALLOCS.load(Ordering::Relaxed) - before;
        drop(s);
        stop.shutdown();
        cost
    });

    server.serve_forever().expect("serve_forever");
    Some(client.join().expect("client thread"))
}

/// The first recycle already licenses reuse, since the licence is potted before the handler runs, so message 2 serves
/// from message 1's recycled storage. Potted after the handler, the pool would bootstrap one message late, and never
/// for bodies spaced past a maintenance window, which zeroes the pot between messages.
#[test]
fn the_first_recycle_licenses_the_second_message() {
    let _turn = MEASURING.lock().unwrap_or_else(|e| e.into_inner());
    let Some(one) = buffered_cost(1, true) else {
        return; // io_uring unavailable
    };
    let Some(two) = buffered_cost(2, true) else {
        return;
    };
    assert_eq!(
        two, one,
        "the second message must reuse the first one's storage and cost \
         nothing extra: 1 message cost {one} large allocations, 2 cost \
         {two}. Above, the recycle's licence is reaching the pot one step \
         behind the give it exists to cover; below, run 1's own setup has \
         started costing more than run 2's and the comparison no longer \
         measures the pool."
    );
}

/// A recycled buffered body must not cost an allocation per message.
///
/// The first body is a miss and allocates, and every later one on the connection reuses that storage through the ring's
/// body pool. Comparing two run lengths rather than asserting an absolute keeps the fixed setup cost out of the
/// verdict, as the streaming twin does.
#[test]
fn a_recycled_buffered_body_does_not_allocate_per_message() {
    let _turn = MEASURING.lock().unwrap_or_else(|e| e.into_inner());
    let Some(small) = buffered_cost(4, true) else {
        return; // io_uring unavailable
    };
    let Some(large) = buffered_cost(16, true) else {
        return;
    };
    // Twelve more messages: a per-message allocation puts ~12 between the runs; reuse leaves the two within slack of
    // each other.
    assert!(
        large <= small + 4,
        "buffered-body cost scales with the message count: 4 messages cost \
         {small} large allocations, 16 cost {large}. A pool that is never \
         consulted on the placement path would look exactly like this."
    );
}

/// A buffered body the handler reads where it lies and never takes must not cost an allocation per message either. Its
/// storage goes back to the ring's body pool as the body drops, and the next one is placed in it. Freed instead, every
/// message placed into fresh storage.
#[test]
fn an_untaken_buffered_body_does_not_allocate_per_message() {
    let _turn = MEASURING.lock().unwrap_or_else(|e| e.into_inner());
    let Some(small) = buffered_cost(4, false) else {
        return; // io_uring unavailable
    };
    let Some(large) = buffered_cost(16, false) else {
        return;
    };
    assert!(
        large <= small + 4,
        "an untaken body's cost scales with the message count: 4 messages \
         cost {small} large allocations, 16 cost {large}. Its storage is \
         not going back to the pool as the body drops."
    );
}
