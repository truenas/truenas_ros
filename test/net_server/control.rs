use super::*;

/// A server whose replies are prefixed with a tag the control hook can swap: the reload shape. The hook and the body
/// handler share the tag through an `Rc`, which only works because both were built on the loop thread; the message that
/// crosses threads is just the new tag. Each applied message is acknowledged with the thread it ran on.
#[allow(clippy::type_complexity)]
fn tagged_server() -> Option<(
    Server<
        (),
        impl FnMut(Incoming<'_>) -> Option<()>,
        impl FnMut(&[u8], &mut ()) -> Framing,
        impl FnMut(Request<'_, ()>) -> Response,
    >,
    SocketAddrV4,
    std::sync::mpsc::Receiver<(Vec<u8>, thread::ThreadId)>,
)> {
    use std::cell::RefCell;
    use std::rc::Rc;

    let tag: Rc<RefCell<Vec<u8>>> = Rc::new(RefCell::new(b"A".to_vec()));
    let for_body = Rc::clone(&tag);
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(PrefixWidth::U32, Endian::Big, false),
        body: move |req: Request<'_, ()>| -> Response {
            let mut out = for_body.borrow().clone();
            out.extend_from_slice(&req.body);
            Response::Reply(echo_frame(&out))
        },
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let mut server = match Server::bind([addr], proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return None,
        Err(e) => panic!("bind: {e}"),
    };
    let (ack_tx, ack_rx) = std::sync::mpsc::channel();
    server.set_control_hook(move |message| {
        let new: Box<Vec<u8>> = message.downcast().expect("a tag");
        *tag.borrow_mut() = *new;
        ack_tx
            .send((tag.borrow().clone(), thread::current().id()))
            .expect("the test holds the receiver");
    });
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    Some((server, v4, ack_rx))
}

/// A control message runs on the server thread, between requests, and two sent back to back apply in order: a request
/// answered before the swap carries the old tag, one answered after it carries the new one, and nothing in between
/// carries half of either.
#[test]
fn control_message_runs_on_the_server_thread_between_requests() {
    let Some((mut server, v4, acks)) = tagged_server() else {
        return;
    };
    let loop_thread = thread::current().id();
    let control = server.control_handle();
    let stop = server.shutdown_handle();
    let client = thread::spawn(move || -> io::Result<()> {
        let _stop = ShutdownOnDrop(stop.clone());
        let mut s = connect_tcp(v4)?;
        send_framed(&mut s, b"1")?;
        assert_eq!(recv_framed(&mut s)?, b"A1");
        control.send(Box::new(b"B".to_vec()));
        control.send(Box::new(b"C".to_vec()));
        for expect in [b"B", b"C"] {
            let (tag, ran_on) = acks.recv_timeout(Duration::from_secs(10)).expect("the hook ran");
            assert_eq!(tag, expect, "applied in the order sent");
            assert_eq!(ran_on, loop_thread, "ran on the server thread");
        }
        send_framed(&mut s, b"2")?;
        assert_eq!(recv_framed(&mut s)?, b"C2", "the swap reached the handler");
        Ok(())
    });
    server.serve_forever().expect("serve_forever");
    client.join().expect("client thread").expect("client io");
}

/// A control message is still delivered while the server drains: the drain is held open by a parked request, the
/// message applies, and the parked request's reply then carries the new tag.
#[test]
fn control_message_is_delivered_while_draining() {
    use std::cell::RefCell;
    use std::rc::Rc;

    let tag: Rc<RefCell<Vec<u8>>> = Rc::new(RefCell::new(b"A".to_vec()));
    let (park_tx, park_rx) = std::sync::mpsc::channel::<Deferred>();
    let for_body = Rc::clone(&tag);
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(PrefixWidth::U32, Endian::Big, false),
        body: move |req: Request<'_, ()>| -> Response {
            if &req.body[..] == b"park" {
                let (deferred, permit) = req.responder.defer();
                park_tx.send(deferred).expect("the test holds the receiver");
                return Response::Defer(permit);
            }
            let mut out = for_body.borrow().clone();
            out.extend_from_slice(&req.body);
            Response::Reply(echo_frame(&out))
        },
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let mut server = match Server::bind([addr], proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind: {e}"),
    };
    let (ack_tx, ack_rx) = std::sync::mpsc::channel();
    let for_hook = Rc::clone(&tag);
    server.set_control_hook(move |message| {
        let new: Box<Vec<u8>> = message.downcast().expect("a tag");
        *for_hook.borrow_mut() = *new;
        ack_tx.send(()).expect("the test holds the receiver");
    });
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let control = server.control_handle();
    let stop = server.shutdown_handle();
    let client = thread::spawn(move || -> io::Result<()> {
        let _stop = ShutdownOnDrop(stop.clone());
        let mut idle = connect_tcp(v4)?;
        send_framed(&mut idle, b"x")?;
        assert_eq!(recv_framed(&mut idle)?, b"Ax");
        let mut parked = connect_tcp(v4)?;
        send_framed(&mut parked, b"park")?;
        let deferred = park_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("the request parked");
        stop.shutdown_graceful(Duration::from_secs(5));
        let mut b = [0u8; 1];
        assert_eq!(idle.read(&mut b)?, 0, "the idle sweep marks the drain");
        // Draining now. The message must still land.
        control.send(Box::new(b"B".to_vec()));
        ack_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("the hook ran during the drain");
        // Prove the swap is what the handler now sees: the parked request is redelivered after it, and its rerun (over
        // an empty frame, as a redelivery is) reads the tag.
        deferred.redeliver();
        assert_eq!(recv_framed(&mut parked)?, b"B");
        assert_eq!(parked.read(&mut b)?, 0, "closed once nothing is owed");
        Ok(())
    });
    server.serve_forever().expect("serve_forever");
    client.join().expect("client thread").expect("client io");
}

/// After the server has stopped a control message goes nowhere: the send neither fails nor runs the hook, like a late
/// push.
#[test]
fn control_message_after_shutdown_is_dropped() {
    let Some((mut server, _v4, acks)) = tagged_server() else {
        return;
    };
    let control = server.control_handle();
    let stop = server.shutdown_handle();
    stop.shutdown();
    server.serve_forever().expect("serve_forever");
    drop(server);
    control.send(Box::new(b"late".to_vec()));
    assert!(
        acks.recv_timeout(Duration::from_millis(200)).is_err(),
        "the hook must not run after the server stopped"
    );
}

/// A handle minted but never given a hook drops its messages rather than failing, and the server keeps serving.
#[test]
fn control_message_without_a_hook_is_dropped() {
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let proto = length_prefixed(PrefixWidth::U32, Endian::Big, false, echo);
    let mut server = match Server::bind([addr], proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind: {e}"),
    };
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let control: ControlHandle = server.control_handle();
    let stop = server.shutdown_handle();
    let client = thread::spawn(move || -> io::Result<()> {
        let _stop = ShutdownOnDrop(stop.clone());
        control.send(Box::new(42u32));
        let mut s = connect_tcp(v4)?;
        send_framed(&mut s, b"still here")?;
        assert_eq!(recv_framed(&mut s)?, b"still here");
        Ok(())
    });
    server.serve_forever().expect("serve_forever");
    client.join().expect("client thread").expect("client io");
}

#[test]
fn shutdown_graceful_with_zero_grace_is_a_hard_shutdown() {
    // `shutdown_graceful(0)` must be exactly `shutdown()`. Taken literally, a zero grace would arm a timer that fires
    // at once or a drain with no deadline, and a caller that reads its grace from configuration could hang the shutdown
    // by setting zero.
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(PrefixWidth::U32, Endian::Big, false),
        body: |req: Request<'_, ()>| Response::Reply(echo_frame(&req.body)),
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
        // Hold a served connection open, then stop with a zero grace.
        let r = (|| -> io::Result<TcpStream> {
            let mut s = connect_tcp(v4)?;
            send_framed(&mut s, b"ping")?;
            assert_eq!(recv_framed(&mut s)?, b"ping");
            Ok(s)
        })();
        stop.shutdown_graceful(Duration::ZERO);
        r
    });

    server.serve_forever().expect("serve_forever");
    // Reaching here at all is the assertion: an open connection did not hold the loop open, because zero grace degraded
    // to a hard stop.
    let held = client.join().expect("thread join").expect("client io");
    drop(held);
}

#[test]
fn tls_listener_without_a_handshake_handler_is_rejected() {
    // A kTLS listener needs `set_tls_handshake`, since the accept handler does not run for kTLS connections. The
    // handler is installed after `bind`, so `serve_forever` refuses to start rather than accept connections it can only
    // drop.
    use truenas_ros::net::server::Listen;
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(PrefixWidth::U32, Endian::Big, false),
        body: |req: Request<'_, ()>| Response::Reply(echo_frame(&req.body)),
    };
    let mut server = match Server::bind([Listen::tls(addr)], proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) || ktls_unsupported(&e) => return,
        // A kernel without FIXED_FD_INSTALL rejects the listener earlier, with its own validation message -
        // environmental, not the case under test.
        Err(Error::Validation(m)) if m.contains("FIXED_FD_INSTALL") => return,
        Err(e) => panic!("bind: {e}"),
    };
    // Deliberately no `set_tls_handshake`.
    match server.serve_forever() {
        Err(Error::Validation(m)) => assert!(
            m.contains("set_tls_handshake"),
            "expected the error to name the missing handler, got {m:?}",
        ),
        Err(e) => panic!("expected a validation error, got {e}"),
        Ok(()) => panic!("a kTLS listener with no handshake handler served"),
    }
}

#[test]
fn server_debug_reports_its_listeners() {
    // `Server`'s own `Debug` is what ends up in a consumer's startup log or panic message, and it is the only way to
    // see the resolved listener list after an ephemeral `:0` bind. Bound but never served: `Drop` tears the ring down
    // on its own.
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(PrefixWidth::U32, Endian::Big, false),
        body: |req: Request<'_, ()>| Response::Reply(echo_frame(&req.body)),
    };
    let server = match Server::bind([addr], proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind: {e}"),
    };
    let ServerAddr::Tcp(bound) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let rendered = format!("{server:?}");
    assert!(rendered.starts_with("Server {"), "unexpected Debug shape: {rendered}");
    assert!(
        rendered.contains(&bound.port().to_string()),
        "Debug should report the resolved listener, not the requested :0: \
         {rendered}"
    );
    assert!(
        rendered.ends_with(".. }"),
        "Server is #[non_exhaustive] in spirit; its Debug must stay open: \
         {rendered}"
    );
}

#[test]
fn tcp6_echo() {
    // The listener asks for `AF_INET6` with `IPV6_V6ONLY`, and the peer fetch must request exactly `sockaddr_in6`'s
    // size, since `SO_PEERNAME` rejects an optlen larger than the address and the completion requires the returned
    // length to match. A size mistake sheds every connection. The round trip proves the sizing, and the peer handed to
    // the accept handler proves it parsed as a real V6 address.
    use std::net::SocketAddrV6;
    let (peer_tx, peer_rx) = std::sync::mpsc::channel::<ClientAddr>();
    let addr = ServerAddr::Tcp6("[::1]:0".parse::<SocketAddrV6>().unwrap());
    let proto = Protocol {
        accept: move |inc: Incoming<'_>| {
            let _ = peer_tx.send(inc.peer.clone());
            Some(())
        },
        header: length_prefix_header::<()>(PrefixWidth::U32, Endian::Big, false),
        body: |req: Request<'_, ()>| Response::Reply(echo_frame(&req.body)),
    };
    let mut server = match Server::bind([addr], proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        // A host with IPv6 compiled out or ::1 absent is environmental, like the io_uring skip above.
        Err(Error::Errno(Errno::EAFNOSUPPORT | Errno::EADDRNOTAVAIL)) => return,
        Err(e) => panic!("bind: {e}"),
    };
    let ServerAddr::Tcp6(v6) = server.local_addrs().remove(0) else {
        panic!("expected Tcp6");
    };
    let stop = server.shutdown_handle();

    let client = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone());
        let msgs: &[&[u8]] = &[b"hello", b"world"];
        let r = retry(|| TcpStream::connect(v6)).and_then(|s| {
            s.set_read_timeout(Some(Duration::from_secs(10)))?;
            framed_roundtrips(s, msgs)
        });
        stop.shutdown();
        r
    });

    server.serve_forever().expect("serve_forever");
    let replies = client.join().expect("thread join").expect("client io");
    assert_eq!(replies, vec![b"hello".to_vec(), b"world".to_vec()]);

    match peer_rx.try_recv().expect("accept handler ran") {
        ClientAddr::Inet(std::net::SocketAddr::V6(p)) => {
            assert_eq!(p.ip(), &std::net::Ipv6Addr::LOCALHOST);
            assert_ne!(p.port(), 0, "a real ephemeral peer port");
        }
        other => panic!("expected an IPv6 peer, got {other:?}"),
    }
}

#[test]
fn tcp_detach_without_a_handler_closes() {
    // `Response::Detach` on a server with no detach handler closes the connection as `HandlerClosed`, not `RecvError`
    // or `ShuttingDown`. The kernel furnishes the fd before anything notices, so the loop must close that alias too, or
    // it pins the socket open past the close.
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(PrefixWidth::U32, Endian::Big, false),
        body: |req: Request<'_, ()>| Response::Detach(req.responder.detach()),
    };
    let mut server = match Server::bind([addr], proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind: {e}"),
    };
    // Deliberately no `set_detach_handler`.
    let reasons = close_reason_channel(&mut server);
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();

    let client = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone());
        let r = (|| -> io::Result<Vec<u8>> {
            let mut s = connect_tcp(v4)?;
            let _ = send_framed(&mut s, b"detach");
            let mut buf = Vec::new();
            s.read_to_end(&mut buf)?;
            Ok(buf)
        })();
        stop.shutdown();
        r
    });

    server.serve_forever().expect("serve_forever");
    match client.join().expect("thread join") {
        Ok(buf) => assert!(buf.is_empty(), "expected clean EOF, got {buf:?}"),
        Err(e) => assert_eq!(e.kind(), io::ErrorKind::ConnectionReset),
    }
    assert_eq!(
        reasons.try_recv().ok(),
        Some(CloseReason::HandlerClosed),
        "a detach with no handler registered is a handler-side close",
    );
}

#[test]
fn tcp_detach_with_a_foreign_permit_closes() {
    // A `DetachPermit` minted on one request and returned on a later one names a request already answered. Its token
    // check must reject it and close, rather than park a request nothing can resolve.
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(None::<truenas_ros::net::server::DetachPermit>),
        header: length_prefix_header::<Option<truenas_ros::net::server::DetachPermit>>(
            PrefixWidth::U32,
            Endian::Big,
            false,
        ),
        body: |req: Request<'_, Option<truenas_ros::net::server::DetachPermit>>| {
            let Request {
                body, state, responder, ..
            } = req;
            if &body[..] == b"stash" {
                // Mint and keep this request's permit, then answer, retiring the request it names.
                *state = Some(responder.detach());
                Response::Reply(echo_frame(b"stashed"))
            } else {
                // Replay the earlier request's permit against this one.
                Response::Detach(state.take().expect("stashed first"))
            }
        },
    };
    let mut server = match Server::bind([addr], proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind: {e}"),
    };
    // Registered, so the close cannot be blamed on a missing handler.
    server.set_detach_handler(|_ctx, detached| {
        panic!("a foreign permit must never reach the detach handler: {detached:?}");
    });
    let reasons = close_reason_channel(&mut server);
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();

    let client = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone());
        let r = (|| -> io::Result<Vec<u8>> {
            let mut s = connect_tcp(v4)?;
            send_framed(&mut s, b"stash")?;
            let first = recv_framed(&mut s)?;
            assert_eq!(first, b"stashed", "the minting request is answered");
            let _ = send_framed(&mut s, b"replay");
            let mut buf = Vec::new();
            s.read_to_end(&mut buf)?;
            Ok(buf)
        })();
        stop.shutdown();
        r
    });

    server.serve_forever().expect("serve_forever");
    match client.join().expect("thread join") {
        Ok(buf) => assert!(buf.is_empty(), "expected clean EOF, got {buf:?}"),
        Err(e) => assert_eq!(e.kind(), io::ErrorKind::ConnectionReset),
    }
    assert_eq!(
        reasons.try_recv().ok(),
        Some(CloseReason::HandlerClosed),
        "a permit from another request closes the connection",
    );
}

#[test]
fn tcp_detach_on_an_unsettled_connection_closes() {
    // Detach hands the raw socket to a worker, so it is safe only with nothing in flight and nothing buffered past this
    // request. A pipelined message already in the server's buffer belongs to the framer, so the loop must close.
    //
    // The framer must scan for this to arise. A fixed-width prefix reads exact counts and leaves a follower in the
    // socket, while `lsp_header` scans for its terminator and so buffers the second message.
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: lsp_header,
        body: |req: Request<'_, ()>| Response::Detach(req.responder.detach()),
    };
    let mut server = match Server::bind([addr], proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind: {e}"),
    };
    server.set_detach_handler(|_ctx, detached| {
        panic!("an unsettled connection must not detach: {detached:?}");
    });
    let reasons = close_reason_channel(&mut server);
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();

    let client = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone());
        let r = (|| -> io::Result<Vec<u8>> {
            let mut s = connect_tcp(v4)?;
            let mut pipelined = b"Content-Length: 6\r\n\r\ndetach".to_vec();
            pipelined.extend_from_slice(b"Content-Length: 8\r\n\r\ntrailing");
            let _ = s.write_all(&pipelined);
            let mut buf = Vec::new();
            s.read_to_end(&mut buf)?;
            Ok(buf)
        })();
        stop.shutdown();
        r
    });

    server.serve_forever().expect("serve_forever");
    match client.join().expect("thread join") {
        Ok(buf) => assert!(buf.is_empty(), "expected clean EOF, got {buf:?}"),
        Err(e) => assert_eq!(e.kind(), io::ErrorKind::ConnectionReset),
    }
    assert_eq!(
        reasons.try_recv().ok(),
        Some(CloseReason::HandlerClosed),
        "detaching with a frame still buffered closes the connection",
    );
}

#[test]
fn protocol_context_types_are_debug() {
    // These types are `#[non_exhaustive]`, so their `Debug` is reachable only from a live handler, and each withholds
    // fields. `Request` prints `header_len` rather than the header, and neither it nor `DetachContext` prints the
    // connection state, where an application keeps its secrets. Assert the shape and those omissions.
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let (tx, rx) = std::sync::mpsc::channel::<(String, String)>();
    let accept_tx = tx.clone();
    let detach_tx = tx.clone();
    let proto = Protocol {
        accept: move |inc: Incoming<'_>| {
            let _ = accept_tx.send(("incoming".into(), format!("{inc:?}")));
            Some(String::from("s3cret-state"))
        },
        header: length_prefix_header::<String>(PrefixWidth::U32, Endian::Big, false),
        body: move |req: Request<'_, String>| {
            let rendered = format!("{req:?}");
            let _ = detach_tx.send(("request".into(), rendered));
            if &req.body[..] == b"detach" {
                Response::Detach(req.responder.detach())
            } else {
                Response::Reply(echo_frame(b"ok"))
            }
        },
    };
    // `Protocol`'s own `Debug` is reachable from outside; check it before the server takes ownership.
    assert_eq!(format!("{proto:?}"), "Protocol { .. }");

    let mut server = match Server::bind([addr], proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind: {e}"),
    };
    let ctx_tx = tx.clone();
    server.set_detach_handler(move |ctx, detached| {
        let _ = ctx_tx.send(("detach_ctx".into(), format!("{ctx:?}")));
        detached.close();
    });
    drop(tx);
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();

    let client = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone());
        let r = (|| -> io::Result<()> {
            let mut s = connect_tcp(v4)?;
            send_framed(&mut s, b"hello")?;
            let _ = recv_framed(&mut s)?;
            let _ = send_framed(&mut s, b"detach");
            let mut buf = Vec::new();
            let _ = s.read_to_end(&mut buf);
            Ok(())
        })();
        stop.shutdown();
        r
    });

    server.serve_forever().expect("serve_forever");
    client.join().expect("thread join").expect("client io");

    // `try_iter`, not `iter`: the sender clones live in handler closures the server still owns, so waiting for the
    // channel to hang up would deadlock. Every send happened before `serve_forever` returned.
    let rendered: std::collections::HashMap<String, String> = rx.try_iter().collect();
    let incoming = rendered.get("incoming").expect("accept handler ran");
    assert!(
        incoming.starts_with("Incoming {") && incoming.contains("peer"),
        "Incoming Debug should name its peer: {incoming}"
    );
    assert!(
        incoming.contains("listener_addr"),
        "Incoming Debug should name the listener it arrived on: {incoming}"
    );
    assert!(
        incoming.ends_with(".. }"),
        "Incoming is #[non_exhaustive]; its Debug must stay open: {incoming}"
    );

    let request = rendered.get("request").expect("body handler ran");
    assert!(
        request.starts_with("Request {") && request.contains("header_len"),
        "Request Debug should report header_len, not the header: {request}"
    );
    assert!(
        !request.contains("s3cret-state"),
        "Request Debug must not print the connection state: {request}"
    );

    let ctx = rendered.get("detach_ctx").expect("detach handler ran");
    assert!(
        ctx.starts_with("DetachContext {") && ctx.contains("peer"),
        "DetachContext Debug should name its peer: {ctx}"
    );
    assert!(
        !ctx.contains("s3cret-state"),
        "DetachContext Debug must not print the connection state: {ctx}"
    );
}
