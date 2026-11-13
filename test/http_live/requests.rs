use super::*;

#[test]
fn get_keepalive_then_close() {
    // Two GETs on one connection prove accumulate/consume re-arms; a third with `Connection: close` gets its response
    // and then a clean FIN.
    let Some(()) = with_http_server(|v4| {
        let mut s = connect_tcp(v4)?;
        for _ in 0..2 {
            s.write_all(b"GET /hi HTTP/1.1\r\nHost: t\r\n\r\n")?;
            let (status, head, body) = read_response(&mut s)?;
            assert_eq!(status, 200);
            assert!(head.contains("\r\nDate: "), "Date header missing");
            assert!(!head.contains("\r\nConnection:"), "keep-alive is bare");
            assert_eq!(body, b"hello");
        }
        s.write_all(b"GET /hi HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n")?;
        let (status, head, body) = read_response(&mut s)?;
        assert_eq!(status, 200);
        assert!(head.contains("\r\nConnection: close\r\n"));
        assert_eq!(body, b"hello");
        assert_eof(&mut s)?;
        Ok(())
    }) else {
        return; // io_uring unavailable
    };
}

#[test]
fn content_length_put_roundtrips() {
    // A small body (inline delivery) and a 100 KiB body (placed - at the default 64 KiB threshold the reactor reads it
    // into its own allocation) both reach the handler intact and echo back.
    let Some(()) = with_http_server(|v4| {
        let mut s = connect_tcp(v4)?;
        for body in [b"hello".to_vec(), vec![b'B'; 100 * 1024]] {
            let head = format!(
                "PUT /echo HTTP/1.1\r\nHost: t\r\nContent-Length: {}\r\n\r\n",
                body.len()
            );
            s.write_all(head.as_bytes())?;
            s.write_all(&body)?;
            let (status, _, echoed) = read_response(&mut s)?;
            assert_eq!(status, 200);
            assert_eq!(echoed, body);
        }
        Ok(())
    }) else {
        return; // io_uring unavailable
    };
}

#[test]
fn chunked_put_and_trailers() {
    let Some(()) = with_http_server(|v4| {
        let mut s = connect_tcp(v4)?;
        // Multi-chunk, bare terminator: stitched entity, no trailers.
        s.write_all(
            b"PUT /echo HTTP/1.1\r\nHost: t\r\nTransfer-Encoding: chunked\r\n\r\n\
              3\r\nfoo\r\n4\r\nbars\r\n0\r\n\r\n",
        )?;
        let (status, head, body) = read_response(&mut s)?;
        assert_eq!(status, 200);
        assert!(head.contains("\r\nx-trailers: \r\n"), "no trailers");
        assert_eq!(body, b"foobars");
        // A genuine trailer is surfaced; a forbidden one (Content-Length, RFC 9110 sec. 6.5.1's framing set) is
        // consumed but never shown.
        s.write_all(
            b"PUT /echo HTTP/1.1\r\nHost: t\r\nTransfer-Encoding: chunked\r\n\r\n\
              3\r\nabc\r\n0\r\nContent-Length: 9\r\nx-amz-checksum-crc32: ok==\r\n\r\n",
        )?;
        let (status, head, body) = read_response(&mut s)?;
        assert_eq!(status, 200);
        assert!(
            head.contains("\r\nx-trailers: x-amz-checksum-crc32\r\n"),
            "trailer set wrong: {head}"
        );
        assert_eq!(body, b"abc");
        Ok(())
    }) else {
        return; // io_uring unavailable
    };
}

#[test]
fn expect_dance_flushes_interim_before_body() {
    // The ordering only a socket can prove: the client sends the head alone and BLOCKS reading the interim - if the
    // codec didn't flush `100 Continue` before seeing any body byte, this read would hang (and fail on the 10s
    // timeout). Only then is the body sent.
    let Some(()) = with_http_server(|v4| {
        let mut s = connect_tcp(v4)?;
        s.write_all(b"PUT /echo HTTP/1.1\r\nHost: t\r\nExpect: 100-continue\r\nContent-Length: 5\r\n\r\n")?;
        let mut interim = [0u8; 25];
        s.read_exact(&mut interim)?;
        assert_eq!(&interim[..], b"HTTP/1.1 100 Continue\r\n\r\n");
        s.write_all(b"hello")?;
        let (status, _, body) = read_response(&mut s)?;
        assert_eq!(status, 200);
        assert_eq!(body, b"hello");
        Ok(())
    }) else {
        return; // io_uring unavailable
    };
}

#[test]
fn botocore_golden_streaming_put() {
    // The default boto3-over-TLS PutObject shape, byte for byte. Expect and TE chunked, one HTTP chunk wrapping the
    // aws-chunked entity, the checksum trailer inside the entity, and a bare HTTP terminator. The codec de-chunks its
    // own layer only, so the aws-chunked entity must reach the handler untouched and no HTTP trailers exist.
    let Some(()) = with_http_server(|v4| {
        let mut s = connect_tcp(v4)?;
        s.write_all(
            b"PUT /echo HTTP/1.1\r\n\
              Host: 127.0.0.1:9711\r\n\
              Expect: 100-continue\r\n\
              Transfer-Encoding: chunked\r\n\
              Content-Encoding: aws-chunked\r\n\
              X-Amz-Trailer: x-amz-checksum-crc32\r\n\
              X-Amz-Decoded-Content-Length: 100\r\n\
              X-Amz-Content-SHA256: STREAMING-UNSIGNED-PAYLOAD-TRAILER\r\n\r\n",
        )?;
        let mut interim = [0u8; 25];
        s.read_exact(&mut interim)?;
        assert_eq!(&interim[..], b"HTTP/1.1 100 Continue\r\n\r\n");

        let mut wire = b"8e\r\n64\r\n".to_vec();
        wire.extend_from_slice(&[b'A'; 100]);
        wire.extend_from_slice(b"\r\n0\r\nx-amz-checksum-crc32:lZe8jQ==\r\n\r\n\r\n0\r\n\r\n");
        assert_eq!(wire.len(), 153);
        s.write_all(&wire)?;

        let mut entity = b"64\r\n".to_vec();
        entity.extend_from_slice(&[b'A'; 100]);
        entity.extend_from_slice(b"\r\n0\r\nx-amz-checksum-crc32:lZe8jQ==\r\n\r\n");
        let (status, head, body) = read_response(&mut s)?;
        assert_eq!(status, 200);
        assert!(head.contains("\r\nx-trailers: \r\n"), "no HTTP trailers");
        assert_eq!(body, entity);
        Ok(())
    }) else {
        return; // io_uring unavailable
    };
}

#[test]
fn farewells_are_real_responses() {
    // A failed connection gets a real HTTP response and then a clean FIN -- never a bare slam. Each case is its own
    // connection; read_to_end terminates because the server flush-closes.
    let Some(()) = with_http_server(|v4| {
        // Malformed head: 400 with the diagnostic body.
        let mut s = connect_tcp(v4)?;
        s.write_all(b"NOT HTTP\r\n\r\n")?;
        let mut all = Vec::new();
        s.read_to_end(&mut all)?;
        let text = String::from_utf8_lossy(&all);
        assert!(text.starts_with("HTTP/1.1 400 Bad Request\r\n"), "{text}");
        assert!(text.contains("\r\nConnection: close\r\n"));
        assert!(text.ends_with("error 400\n"));

        // A head that outruns the 16 KiB cap: 431. Sent in one write so the reactor consumes every byte before the
        // verdict (no unread tail to turn the close into an RST).
        let mut s = connect_tcp(v4)?;
        let mut req = b"GET / HTTP/1.1\r\nHost: t\r\nX-Pad: ".to_vec();
        req.extend(std::iter::repeat_n(b'a', 17 * 1024));
        s.write_all(&req)?;
        let mut all = Vec::new();
        s.read_to_end(&mut all)?;
        let text = String::from_utf8_lossy(&all);
        assert!(text.starts_with("HTTP/1.1 431 "), "{text}");

        // A dying HEAD: the status and Content-Length arrive, the body is elided (a HEAD response must not carry
        // content).
        let mut s = connect_tcp(v4)?;
        s.write_all(b"HEAD /hi HTTP/1.1\r\nHost: t\r\nContent-Length: 99999999999\r\n\r\n")?;
        let mut all = Vec::new();
        s.read_to_end(&mut all)?;
        let text = String::from_utf8_lossy(&all);
        assert!(text.starts_with("HTTP/1.1 413 "), "{text}");
        assert!(text.contains("\r\nContent-Length: 10\r\n"));
        assert!(text.ends_with("\r\n\r\n"), "farewell body not elided");
        Ok(())
    }) else {
        return; // io_uring unavailable
    };
}

#[test]
fn large_chunked_dance_takes_the_handoff_path() {
    // A 100 KiB single-chunk dance body: over the 64 KiB placement threshold, delivered body-only, so the reactor hands
    // its buffer to the codec and the entity is de-chunked in place (the owned-body path). Content equality end to end
    // is the live proof; the zero-copy pointer identity is pinned by the unit tests.
    let Some(()) = with_http_server(|v4| {
        let payload = vec![b'C'; 100 * 1024];
        let mut s = connect_tcp(v4)?;
        s.write_all(b"PUT /echo HTTP/1.1\r\nHost: t\r\nExpect: 100-continue\r\nTransfer-Encoding: chunked\r\n\r\n")?;
        let mut interim = [0u8; 25];
        s.read_exact(&mut interim)?;
        assert_eq!(&interim[..], b"HTTP/1.1 100 Continue\r\n\r\n");
        let mut wire = format!("{:x}\r\n", payload.len()).into_bytes();
        wire.extend_from_slice(&payload);
        wire.extend_from_slice(b"\r\n0\r\n\r\n");
        s.write_all(&wire)?;
        let (status, _, body) = read_response(&mut s)?;
        assert_eq!(status, 200);
        assert_eq!(body, payload);
        Ok(())
    }) else {
        return; // io_uring unavailable
    };
}

/// Bind a **deferrable** http server. `/warm` parks on a cold shared cache and a worker warms it then redrives,
/// `/deadline` parks and the worker replies 503 directly, `/drop` parks and the worker drops the handle, and `/hi`
/// answers inline. `None` means io_uring is unavailable (a skip).
fn with_parking_server<T: Send + 'static>(
    client: impl FnOnce(SocketAddrV4) -> io::Result<T> + Send + 'static,
) -> Option<T> {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use truenas_ros::http::{HttpVerdict, protocol_deferrable};

    let cache = Arc::new(AtomicBool::new(false));
    let handler = move |req: HttpRequest<'_>, _: &mut ()| {
        match (req.method, req.target) {
            ("GET", "/hi") => HttpVerdict::Respond(HttpResponse::new(200).body("hello")),
            ("GET", "/warm") => {
                if cache.load(Ordering::Acquire) {
                    HttpVerdict::Respond(HttpResponse::new(200).body("warm"))
                } else {
                    // Cold: park, warm the cache off-thread, redrive. The second invocation takes the inline path
                    // above.
                    let (deferred, permit) = req.defer();
                    let cache = Arc::clone(&cache);
                    thread::spawn(move || {
                        thread::sleep(Duration::from_millis(10));
                        cache.store(true, Ordering::Release);
                        deferred.redrive();
                    });
                    HttpVerdict::Defer(permit)
                }
            }
            ("GET", "/deadline") => {
                // The worker misses its deadline and answers 503 itself -- built off-thread, serialized on the server
                // thread.
                let (deferred, permit) = req.defer();
                thread::spawn(move || {
                    thread::sleep(Duration::from_millis(10));
                    deferred.reply(HttpResponse::new(503).header("retry-after", "1").body("slow down\n"));
                });
                HttpVerdict::Defer(permit)
            }
            ("GET", "/drop") => {
                // A lost worker: the dropped handle must close the parked connection rather than leak its slot.
                let (deferred, permit) = req.defer();
                thread::spawn(move || {
                    thread::sleep(Duration::from_millis(10));
                    drop(deferred);
                });
                HttpVerdict::Defer(permit)
            }
            _ => HttpVerdict::Respond(HttpResponse::new(404).body("no\n")),
        }
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let proto = protocol_deferrable(HttpConfig::default(), |_inc: Incoming<'_>| Some(()), handler)
        .expect("codec config is valid");
    let mut server = match Server::bind([addr], proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return None,
        Err(e) => panic!("bind: {e}"),
    };
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();
    let join = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone()); // fail fast on panic
        let r = client(v4);
        stop.shutdown();
        r
    });
    server.serve_forever().expect("serve_forever");
    Some(join.join().expect("client thread").expect("client io"))
}

/// Every reply written during a drain says `Connection: close`: the drain closes the connection once the reply is out
/// and admits no further request on it, so the peer must not reuse it. Here the reply is a worker's, for a request
/// parked before the drain began (the idle connection's EOF marks that moment), and a second request pipelined behind
/// it is dropped with the close rather than answered.
#[test]
fn replies_during_drain_say_connection_close() {
    use std::sync::mpsc;
    use truenas_ros::http::{HttpDeferred, HttpVerdict, protocol_deferrable};

    let (park_tx, park_rx) = mpsc::channel::<HttpDeferred>();
    let handler = move |req: HttpRequest<'_>, _: &mut ()| match (req.method, req.target) {
        ("GET", "/park") => {
            let (deferred, permit) = req.defer();
            park_tx.send(deferred).expect("the test holds the receiver");
            HttpVerdict::Defer(permit)
        }
        _ => HttpVerdict::Respond(HttpResponse::new(200).body("hello")),
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let proto = protocol_deferrable(HttpConfig::default(), |_inc: Incoming<'_>| Some(()), handler)
        .expect("codec config is valid");
    let mut server = match Server::bind([addr], proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind: {e}"),
    };
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();
    let join = thread::spawn(move || -> io::Result<()> {
        let _stop = ShutdownOnDrop(stop.clone()); // fail fast on panic
        let mut idle = connect_tcp(v4)?;
        idle.write_all(b"GET /hi HTTP/1.1\r\nHost: t\r\n\r\n")?;
        let (status, head, _) = read_response(&mut idle)?;
        assert_eq!(status, 200);
        assert!(!head.contains("\r\nConnection:"), "bare before the drain");

        let mut parked = connect_tcp(v4)?;
        parked.write_all(
            b"GET /park HTTP/1.1\r\nHost: t\r\n\r\n\
              GET /hi HTTP/1.1\r\nHost: t\r\n\r\n",
        )?;
        let deferred = park_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("the request parked");

        stop.shutdown_graceful(Duration::from_secs(5));
        assert_eof(&mut idle)?;

        deferred.reply(HttpResponse::new(200).body("late"));
        let (status, head, body) = read_response(&mut parked)?;
        assert_eq!(status, 200);
        assert_eq!(body, b"late");
        assert!(
            head.contains("\r\nConnection: close\r\n"),
            "a reply during the drain must say close: {head}"
        );
        // The pipelined GET is never answered: the connection is done.
        assert_eof(&mut parked)?;
        Ok(())
    });
    server.serve_forever().expect("serve_forever");
    join.join().expect("client thread").expect("client io");
}

/// The handler that starts the drain still says close on its own reply: the flag is read after the handler returns, not
/// before it runs, so an admin shutdown endpoint does not answer keep-alive and then vanish.
#[test]
fn a_handler_that_starts_the_drain_still_says_close() {
    use std::sync::{Arc, OnceLock};

    let stop_cell: Arc<OnceLock<ShutdownHandle>> = Arc::new(OnceLock::new());
    let in_handler = Arc::clone(&stop_cell);
    let handler = move |req: HttpRequest<'_>, _: &mut ()| match (req.method, req.target) {
        ("POST", "/shutdown") => {
            in_handler
                .get()
                .expect("handle set before serving")
                .shutdown_graceful(Duration::from_secs(5));
            HttpResponse::new(200).body("draining")
        }
        _ => HttpResponse::new(200).body("hello"),
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let proto = protocol(HttpConfig::default(), |_inc: Incoming<'_>| Some(()), handler).expect("codec config is valid");
    let mut server = match Server::bind([addr], proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind: {e}"),
    };
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();
    stop_cell.set(stop.clone()).expect("set once");
    let join = thread::spawn(move || -> io::Result<()> {
        let _stop = ShutdownOnDrop(stop.clone()); // fail fast on panic
        let mut s = connect_tcp(v4)?;
        s.write_all(b"GET /hi HTTP/1.1\r\nHost: t\r\n\r\n")?;
        let (status, head, _) = read_response(&mut s)?;
        assert_eq!(status, 200);
        assert!(!head.contains("\r\nConnection:"), "bare before the drain");
        s.write_all(b"POST /shutdown HTTP/1.1\r\nHost: t\r\n\r\n")?;
        let (status, head, body) = read_response(&mut s)?;
        assert_eq!(status, 200);
        assert_eq!(body, b"draining");
        assert!(
            head.contains("\r\nConnection: close\r\n"),
            "the reply that started the drain must say close: {head}"
        );
        assert_eof(&mut s)?;
        Ok(())
    });
    server.serve_forever().expect("serve_forever");
    join.join().expect("client thread").expect("client io");
}

#[test]
fn park_redrive_completes_in_one_round_trip() {
    // The cold-miss pattern end to end: the first request parks while the worker warms the cache, then redrives - ONE
    // write, ONE response, no error leg. The second request takes the warm inline path.
    let Some(()) = with_parking_server(|v4| {
        let mut s = connect_tcp(v4)?;
        s.write_all(b"GET /warm HTTP/1.1\r\nHost: t\r\n\r\n")?;
        let (status, _head, body) = read_response(&mut s)?;
        assert_eq!(status, 200);
        assert_eq!(body, b"warm");
        s.write_all(b"GET /warm HTTP/1.1\r\nHost: t\r\n\r\n")?;
        let (status, _head, body) = read_response(&mut s)?;
        assert_eq!(status, 200);
        assert_eq!(body, b"warm");
        Ok(())
    }) else {
        return; // io_uring unavailable
    };
}

#[test]
fn worker_reply_answers_and_keeps_alive() {
    // A worker-built 503 serializes on the server thread with the request's head facts, and the connection keeps
    // serving afterward.
    let Some(()) = with_parking_server(|v4| {
        let mut s = connect_tcp(v4)?;
        s.write_all(b"GET /deadline HTTP/1.1\r\nHost: t\r\n\r\n")?;
        let (status, head, body) = read_response(&mut s)?;
        assert_eq!(status, 503);
        assert!(head.contains("retry-after: 1\r\n"), "{head}");
        assert_eq!(body, b"slow down\n");
        s.write_all(b"GET /hi HTTP/1.1\r\nHost: t\r\n\r\n")?;
        let (status, _head, body) = read_response(&mut s)?;
        assert_eq!(status, 200);
        assert_eq!(body, b"hello");
        Ok(())
    }) else {
        return; // io_uring unavailable
    };
}

#[test]
fn dropped_handle_closes_the_parked_connection() {
    // No response bytes, just a close - the drop path cannot leak the slot and must not invent a reply.
    let Some(()) = with_parking_server(|v4| {
        let mut s = connect_tcp(v4)?;
        s.write_all(b"GET /drop HTTP/1.1\r\nHost: t\r\n\r\n")?;
        let mut buf = Vec::new();
        match s.read_to_end(&mut buf) {
            Ok(_) => assert!(buf.is_empty(), "expected no bytes, got {buf:?}"),
            Err(e) => assert_eq!(e.kind(), io::ErrorKind::ConnectionReset),
        }
        Ok(())
    }) else {
        return; // io_uring unavailable
    };
}

#[test]
fn pipelined_requests_answer_in_order_across_a_park() {
    // Two pipelined requests where the FIRST parks: the parked one must answer first - the codec holds the second back
    // for the park's duration, so a later request can never be answered around an earlier parked one.
    let Some(()) = with_parking_server(|v4| {
        let mut s = connect_tcp(v4)?;
        s.write_all(
            b"GET /warm HTTP/1.1\r\nHost: t\r\n\r\n\
              GET /hi HTTP/1.1\r\nHost: t\r\n\r\n",
        )?;
        let (status, _head, body) = read_response(&mut s)?;
        assert_eq!((status, body.as_slice()), (200, b"warm".as_ref()));
        let (status, _head, body) = read_response(&mut s)?;
        assert_eq!((status, body.as_slice()), (200, b"hello".as_ref()));
        Ok(())
    }) else {
        return; // io_uring unavailable
    };
}

#[test]
fn head_declared_length_reaches_the_wire_bodiless() {
    // HeadObject's live shape: a 200 HEAD answer declares the paired GET's Content-Length while sending no body bytes -
    // and the connection stays framed, proven by a follow-up GET answering on the same connection (any stray body byte
    // would land inside the GET's status line).
    let Some(()) = with_http_server(|v4| {
        let mut s = connect_tcp(v4)?;
        s.write_all(b"HEAD /sized HTTP/1.1\r\nHost: t\r\n\r\n")?;
        let (status, head) = read_head(&mut s)?;
        assert_eq!(status, 200);
        assert!(head.contains("\r\nContent-Length: 4096\r\n"), "{head}");
        s.write_all(b"GET /hi HTTP/1.1\r\nHost: t\r\n\r\n")?;
        let (status, _, body) = read_response(&mut s)?;
        assert_eq!(status, 200);
        assert_eq!(body, b"hello");
        Ok(())
    }) else {
        return; // io_uring unavailable
    };
}
