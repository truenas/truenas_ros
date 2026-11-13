use super::*;

/// [`with_http_server`] over a kTLS listener: the same [`echo_handler`] behind `Listen::tls`, with the `truenas_ktls`
/// handshake worker minting the connection state (`AcceptDeferral::ready` is the admission - the accept handler does
/// not run for kTLS connections). `None` means io_uring or kTLS is unavailable here (the caller returns - a skip; a
/// hard failure under `TRUENAS_ROS_REQUIRE_KTLS`).
fn with_ktls_http_server<T: Send + 'static>(
    cfg: ServerConfig,
    client: impl FnOnce(SocketAddrV4) -> io::Result<T> + Send + 'static,
) -> Option<T> {
    with_ktls_http_server_handle(cfg, move |v4, _stop| client(v4))
}

/// [`with_ktls_http_server`] for a client that drives the server's lifecycle itself: it also receives the
/// [`ShutdownHandle`].
fn with_ktls_http_server_handle<T: Send + 'static>(
    cfg: ServerConfig,
    client: impl FnOnce(SocketAddrV4, ShutdownHandle) -> io::Result<T> + Send + 'static,
) -> Option<T> {
    if ktls_openssl_unsupported() {
        return None;
    }
    let (cert, key) = self_signed();
    let acceptor = Arc::new(ktls_acceptor(&cert, &key));
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let proto =
        protocol(HttpConfig::default(), |_inc: Incoming<'_>| Some(()), echo_handler).expect("codec config is valid");
    let mut server = match Server::with_config([Listen::tls(addr)], cfg, proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) || ktls_unsupported(&e) => return None,
        Err(e) => panic!("bind: {e}"),
    };
    server.set_tls_handshake(move |fd, _inc, deferral| {
        let acceptor = Arc::clone(&acceptor);
        thread::spawn(move || match ktls_server_handshake(fd, &acceptor) {
            Ok(()) => deferral.ready(HttpConn::new(())),
            Err(_) => deferral.reject(),
        });
    });
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();
    let join = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone()); // fail fast on panic
        let r = client(v4, stop.clone());
        stop.shutdown();
        r
    });
    server.serve_forever().expect("serve_forever");
    Some(join.join().expect("client thread").expect("client io"))
}

/// One slow `/big` exchange on a fresh TLS connection: request, then crawl the first ~1.5 MiB slower than the send can
/// flush it - the kernel absorbs ~4 MiB (`tcp_wmem[2]`) and the rest sits in the blocked send, so a 500 ms
/// `send_timeout` cancel lands mid-body - then drain. Returns the stream (for follow-up requests) and the body read.
fn fetch_big_slowly(
    v4: SocketAddrV4,
    expected_len: usize,
) -> io::Result<(openssl::ssl::SslStream<TcpStream>, Vec<u8>)> {
    let mut s = tls_connect(v4)?;
    s.write_all(b"GET /big HTTP/1.1\r\nHost: t\r\n\r\n")?;
    let (status, head) = read_head(&mut s)?;
    assert_eq!(status, 200);
    let len: usize = head
        .lines()
        .find_map(|l| l.strip_prefix("Content-Length:"))
        .map(|v| v.trim().parse().expect("numeric length"))
        .expect("Content-Length on /big");
    assert_eq!(len, expected_len, "declared length");
    let mut body = vec![0u8; len];
    let mut got = 0;
    for _ in 0..12 {
        thread::sleep(Duration::from_millis(40));
        let upto = (got + 128 * 1024).min(len);
        s.read_exact(&mut body[got..upto])?;
        got = upto;
    }
    s.read_exact(&mut body[got..])?;
    Ok((s, body))
}

#[test]
fn ktls_vectored_bodies_arrive_intact() {
    // The S3 GET shape: head + body as two iovecs in one SENDMSG over kTLS. The client drains the 6 MiB body
    // ([`big_body`]) slower than the 500 ms `send_timeout` flushes it, so the linked timeout cancels the io-wq-blocked
    // send mid-flight and the reactor re-submits the tail from the partial CQE: every byte must arrive exactly once.
    // The canned body then rides the borrowed segment, and two more requests prove each reply retired its read-ahead
    // slot (a wrong retire count wedges them).
    //
    // A reclaim (EOF) is retried on a fresh connection: a cancel window in which the blocked send happened to write
    // nothing closes the connection as SendTimeout even though this client drains throughout -- rare, timing-dependent,
    // and a server-policy question rather than a data-path defect. A byte mismatch is NEVER retried; corruption fails
    // on the spot.
    let cfg = ServerConfig {
        send_timeout: Some(Duration::from_millis(500)),
        ..ServerConfig::default()
    };
    let Some(()) = with_ktls_http_server(cfg, |v4| {
        let expected = big_body();
        let mut attempt = 0;
        let (mut s, body) = loop {
            attempt += 1;
            match fetch_big_slowly(v4, expected.len()) {
                Ok(pair) => break pair,
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof && attempt < 3 => {
                    eprintln!(
                        "send_timeout reclaimed a draining client \
                         (attempt {attempt}); retrying"
                    );
                }
                Err(e) => return Err(e),
            }
        };
        if body != expected {
            let at = body
                .iter()
                .zip(&expected)
                .position(|(a, b)| a != b)
                .expect("lengths equal yet bytes differ");
            panic!("6 MiB body corrupted at byte {at}");
        }
        s.write_all(b"GET /canned HTTP/1.1\r\nHost: t\r\n\r\n")?;
        let (status, _, body) = read_response(&mut s)?;
        assert_eq!(status, 200);
        assert_eq!(body, CANNED.as_bytes());
        for _ in 0..2 {
            s.write_all(b"GET /hi HTTP/1.1\r\nHost: t\r\n\r\n")?;
            let (status, _, body) = read_response(&mut s)?;
            assert_eq!(status, 200);
            assert_eq!(body, b"hello");
        }
        Ok(())
    }) else {
        return; // io_uring or kTLS unavailable
    };
}

/// Assert the peer closed: a clean EOF, or the unexpected-EOF OpenSSL reports when a kernel-TLS peer closes without a
/// close_notify.
fn assert_tls_eof<R: Read>(s: &mut R) -> io::Result<()> {
    let mut b = [0u8; 1];
    match s.read(&mut b) {
        Ok(0) => Ok(()),
        Ok(n) => panic!("expected EOF, got {n} byte(s)"),
        Err(e)
            if e.kind() == io::ErrorKind::UnexpectedEof
                || e.kind() == io::ErrorKind::ConnectionReset
                || e.to_string().to_ascii_lowercase().contains("eof") =>
        {
            Ok(())
        }
        Err(e) => Err(e),
    }
}

/// The drain's `Connection: close` over kTLS, on the inline reply path. A PUT parked in the 100-continue dance is
/// in-flight work (its body read is armed, so the sweep leaves it alone): the drain begins (the idle TLS connection's
/// close marks it), the body arrives, and the echo must say close before the connection goes away.
#[test]
fn ktls_replies_during_drain_say_connection_close() {
    let cfg = truenas_ros::net::server::ServerConfig::default();
    let Some(()) = with_ktls_http_server_handle(cfg, |v4, stop| {
        let mut idle = ktls::tls_connect(v4)?;
        idle.write_all(b"GET /hi HTTP/1.1\r\nHost: t\r\n\r\n")?;
        let (status, head, body) = read_response(&mut idle)?;
        assert_eq!(status, 200);
        assert_eq!(body, b"hello");
        assert!(!head.contains("\r\nConnection:"), "bare before the drain");

        let mut mid = ktls::tls_connect(v4)?;
        mid.write_all(
            b"PUT /echo HTTP/1.1\r\nHost: t\r\nContent-Length: 5\r\n\
              Expect: 100-continue\r\n\r\n",
        )?;
        let (status, _) = read_head(&mut mid)?;
        assert_eq!(status, 100, "the dance parks the body read");

        stop.shutdown_graceful(Duration::from_secs(5));
        assert_tls_eof(&mut idle)?;

        mid.write_all(b"hello")?;
        let (status, head, body) = read_response(&mut mid)?;
        assert_eq!(status, 200);
        assert_eq!(body, b"hello");
        assert!(
            head.contains("\r\nConnection: close\r\n"),
            "a reply during the drain must say close: {head}"
        );
        assert_tls_eof(&mut mid)?;
        Ok(())
    }) else {
        return; // io_uring or kTLS unavailable
    };
}

#[test]
fn ktls_chunked_put_and_trailers_roundtrip() {
    // The boto3-over-TLS upload shape: a chunked PUT whose records the kernel decrypts before the framer sees them.
    // Each write is its own TLS record, so chunk reassembly provably spans record boundaries, and the trailer still
    // surfaces.
    let Some(()) = with_ktls_http_server(ServerConfig::default(), |v4| {
        let mut s = tls_connect(v4)?;
        s.write_all(b"PUT /echo HTTP/1.1\r\nHost: t\r\nTransfer-Encoding: chunked\r\n\r\n")?;
        s.write_all(b"3\r\nfoo\r\n")?;
        s.write_all(b"4\r\nbars\r\n")?;
        s.write_all(b"0\r\nx-amz-checksum-crc32: ok==\r\n\r\n")?;
        let (status, head, body) = read_response(&mut s)?;
        assert_eq!(status, 200);
        assert!(
            head.contains("\r\nx-trailers: x-amz-checksum-crc32\r\n"),
            "trailer set wrong: {head}"
        );
        assert_eq!(body, b"foobars");
        Ok(())
    }) else {
        return; // io_uring or kTLS unavailable
    };
}

#[test]
fn ktls_expect_dance_flushes_interim_before_body() {
    // Same ordering proof as the plain-TCP test, over kTLS: the interim must arrive (as its own TLS record) before any
    // body byte is sent, or this read hangs into its timeout.
    let Some(()) = with_ktls_http_server(ServerConfig::default(), |v4| {
        let mut s = tls_connect(v4)?;
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
        return; // io_uring or kTLS unavailable
    };
}

#[test]
fn ktls_farewells_arrive_before_the_close() {
    // A malformed request over TLS still gets the real 400 + Connection: close before the connection dies. The
    // kernel-TLS close is a plain FIN (no close_notify), so after the full farewell the client sees either EOF or a
    // truncation error - both prove the bytes beat the FIN.
    let Some(()) = with_ktls_http_server(ServerConfig::default(), |v4| {
        let mut s = tls_connect(v4)?;
        s.write_all(b"NOT HTTP\r\n\r\n")?;
        let (status, head, body) = read_response(&mut s)?;
        assert_eq!(status, 400);
        assert!(head.contains("\r\nConnection: close\r\n"), "{head}");
        assert_eq!(body, b"error 400\n");
        let mut b = [0u8; 1];
        match s.read(&mut b) {
            Ok(0) | Err(_) => {}
            Ok(n) => panic!("{n} bytes after the farewell"),
        }
        Ok(())
    }) else {
        return; // io_uring or kTLS unavailable
    };
}
