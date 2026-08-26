//! Integration tests for the `http` codec through the **real** reactor --
//! live loopback TCP, exercising the full ring path (multishot accept ->
//! recv-header -> the http framer -> recv/scan -> delivery -> handler ->
//! serialize -> send -> keep-alive re-arm). The codec's unit tests drive
//! `frame`/`step` as plain functions; these pin the seams only a socket can
//! prove: the interim `100 Continue` flushing **before** the body is sent,
//! farewell responses arriving as bytes before FIN (never a slam), buffer
//! accumulate/consume across requests on one connection, and the owned-body
//! handoff a large chunked dance takes.
//!
//! Like `test/net_server.rs`, these **skip** (return early) when io_uring is
//! unavailable - the CI/dev sandbox blocks the io_uring syscalls
//! (ENOSYS/EPERM/EACCES), so `cargo test` stays green in a bare sandbox. Set
//! `TRUENAS_ROS_REQUIRE_IO_URING=1` (as CI on a real kernel does) to turn a
//! skip into a hard failure so coverage can't silently vanish.
//!
//! `Server` is `!Send` (its ring is single-thread-owned), so it stays on the
//! test thread running `serve_forever`; the client runs on a spawned thread
//! and stops the server via the `Send` [`ShutdownHandle`] when done.
#![cfg(all(target_os = "linux", feature = "http"))]

use std::io::{self, Read, Write};
use std::net::{SocketAddrV4, TcpStream};
use std::thread;
use std::time::Duration;

use truenas_ros::http::{HttpConfig, HttpRequest, HttpResponse, protocol};
use truenas_ros::net::server::{Incoming, Server, ServerAddr, ShutdownHandle};
use truenas_ros::{Errno, Error};

/// Errors that mean "io_uring is unavailable here" - an environmental skip.
///
/// Deliberately *excludes* `EINVAL`: for io_uring that means the kernel
/// rejected our setup arguments - a real bug we want to fail on, not skip.
fn is_unavailable(e: &Error) -> bool {
    matches!(
        e,
        // ENOMEM: rings pin pages against RLIMIT_MEMLOCK, so a loaded
        // box exhausts it and ring creation fails - environmental, and
        // the REQUIRE variable turns the skip red where it must not
        // happen.
        Error::Errno(
            Errno::EPERM | Errno::ENOSYS | Errno::EACCES | Errno::ENOMEM
        )
    )
}

fn should_skip(e: &Error) -> bool {
    if is_unavailable(e) {
        assert!(
            std::env::var_os("TRUENAS_ROS_REQUIRE_IO_URING").is_none(),
            "TRUENAS_ROS_REQUIRE_IO_URING set but io_uring unavailable: {e}"
        );
        return true;
    }
    false
}

struct ShutdownOnDrop(ShutdownHandle);

impl Drop for ShutdownOnDrop {
    fn drop(&mut self) {
        self.0.shutdown();
    }
}

/// Retry a connect for up to ~1s while the server thread starts up.
fn retry<T>(mut f: impl FnMut() -> io::Result<T>) -> io::Result<T> {
    let mut last = None;
    for _ in 0..50 {
        match f() {
            Ok(v) => return Ok(v),
            Err(e) => {
                last = Some(e);
                thread::sleep(Duration::from_millis(20));
            }
        }
    }
    Err(last.unwrap())
}

fn connect_tcp(addr: SocketAddrV4) -> io::Result<TcpStream> {
    let s = retry(|| TcpStream::connect(addr))?;
    s.set_read_timeout(Some(Duration::from_secs(10)))?;
    Ok(s)
}

/// The shared echo handler behind [`with_http_server`] and
/// [`with_ktls_http_server`]: `GET /hi` answers `hello`; `GET /big` the
/// 6 MiB patterned owned body ([`big_body`]); `GET /canned` a `'static`
/// body (served from a borrowed reply segment); `HEAD /sized` a bare 200
/// declaring `Content-Length: 4096` with no bytes in hand (the HeadObject
/// shape); `PUT /echo` answers the request body verbatim, with the surfaced
/// trailer names joined into an `x-trailers` response header (so a client
/// can assert exactly which trailers reached [`HttpRequest::trailers`]);
/// other `HEAD` requests answer like GET (the codec elides the body);
/// anything else is a 404.
fn echo_handler(mut req: HttpRequest<'_>, _: &mut ()) -> HttpResponse {
    match (req.method, req.target) {
        ("GET", "/hi") | ("HEAD", "/hi") => {
            HttpResponse::new(200).body("hello")
        }
        ("GET", "/big") => HttpResponse::new(200).body(big_body()),
        ("GET", "/canned") => HttpResponse::new(200).body(CANNED),
        ("HEAD", "/sized") => HttpResponse::new(200).head_content_length(4096),
        ("PUT", "/echo") => {
            let names: Vec<&str> =
                req.trailers.iter().map(|t| t.name).collect();
            let body = req.body.take();
            HttpResponse::new(200)
                .header("x-trailers", names.join(","))
                .body(body)
        }
        _ => HttpResponse::new(404).body("not found\n"),
    }
}

/// A canned `'static` reply body - served from a borrowed segment, the path
/// a real handler's fixed error/health bodies take.
const CANNED: &str = "a canned static body, sent by reference";

/// A 6 MiB body, sized so a stalled reader forces a short send completion:
/// above what the kernel will buffer for a peer that isn't reading --
/// `tcp_wmem[2]` caps the send buffer at 4 MiB by default, and a stalled
/// reader's window stays near `tcp_rmem[1]` - and below the server's 8 MiB
/// `max_send_backlog`, so the reply is admissible. Patterned (not constant)
/// so truncation, reordering, or a send-cursor slip shows up as a byte
/// mismatch rather than a length that happens to agree.
fn big_body() -> Vec<u8> {
    (0..6 * 1024 * 1024).map(|i| (i % 251) as u8).collect()
}

/// Bind an http server with the shared [`echo_handler`], run the client
/// closure against its address on a spawned thread, and serve until the
/// client stops it. `None` means io_uring is unavailable (the caller
/// returns - a skip).
fn with_http_server<T: Send + 'static>(
    client: impl FnOnce(SocketAddrV4) -> io::Result<T> + Send + 'static,
) -> Option<T> {
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let proto = protocol(
        HttpConfig::default(),
        |_inc: Incoming<'_>| Some(()),
        echo_handler,
    )
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

/// [`with_http_server`] with the server's tuning spelled out - for the
/// tests whose subject IS a clock or a bound.
fn with_http_server_cfg<T: Send + 'static>(
    cfg: truenas_ros::net::server::ServerConfig,
    client: impl FnOnce(SocketAddrV4) -> io::Result<T> + Send + 'static,
) -> Option<T> {
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let proto = protocol(
        HttpConfig::default(),
        |_inc: Incoming<'_>| Some(()),
        echo_handler,
    )
    .expect("codec config is valid");
    let mut server = match Server::with_config([addr], cfg, proto) {
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

/// Read one response head off the stream, byte-by-byte to its CRLFCRLF (no
/// over-read - the connection may carry more). Returns `(status, head
/// text)`; any body is left unread (a HEAD answer has none to read).
fn read_head<R: Read>(s: &mut R) -> io::Result<(u16, String)> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if s.read(&mut byte)? == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "eof inside response head",
            ));
        }
        head.push(byte[0]);
        assert!(head.len() <= 64 * 1024, "unterminated response head");
    }
    let head = String::from_utf8(head).expect("response head is ascii");
    let status: u16 = head
        .strip_prefix("HTTP/1.1 ")
        .and_then(|r| r.get(..3))
        .expect("status line")
        .parse()
        .expect("numeric status");
    Ok((status, head))
}

/// Read one HTTP response off the stream: the head ([`read_head`]), then
/// exactly `Content-Length` body bytes. Returns `(status, head text, body)`.
fn read_response<R: Read>(s: &mut R) -> io::Result<(u16, String, Vec<u8>)> {
    let (status, head) = read_head(s)?;
    let len: usize = head
        .lines()
        .find_map(|l| l.strip_prefix("Content-Length:"))
        .map(|v| v.trim().parse().expect("numeric length"))
        .unwrap_or(0);
    let mut body = vec![0u8; len];
    s.read_exact(&mut body)?;
    Ok((status, head, body))
}

/// Assert the peer half-closed cleanly: the next read returns EOF.
fn assert_eof<R: Read>(s: &mut R) -> io::Result<()> {
    let mut b = [0u8; 1];
    assert_eq!(s.read(&mut b)?, 0, "expected EOF, got more bytes");
    Ok(())
}

#[test]
fn get_keepalive_then_close() {
    // Two GETs on one connection prove accumulate/consume re-arms; a third
    // with `Connection: close` gets its response and then a clean FIN.
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
        s.write_all(
            b"GET /hi HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n",
        )?;
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
    // A small body (inline delivery) and a 100 KiB body (placed - at the
    // default 64 KiB threshold the reactor reads it into its own
    // allocation) both reach the handler intact and echo back.
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
        // A genuine trailer is surfaced; a forbidden one (Content-Length,
        // RFC 9110 sec. 6.5.1's framing set) is consumed but never shown.
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
    // The ordering only a socket can prove: the client sends the head
    // alone and BLOCKS reading the interim - if the codec didn't flush
    // `100 Continue` before seeing any body byte, this read would hang
    // (and fail on the 10s timeout). Only then is the body sent.
    let Some(()) = with_http_server(|v4| {
        let mut s = connect_tcp(v4)?;
        s.write_all(
            b"PUT /echo HTTP/1.1\r\nHost: t\r\nExpect: 100-continue\r\nContent-Length: 5\r\n\r\n",
        )?;
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
    // The default boto3-over-TLS PutObject shape, byte-for-byte as captured
    // on the dev box (boto3 1.37.9): Expect + TE chunked, one HTTP chunk
    // wrapping the aws-chunked entity, checksum trailer *inside* the
    // entity, bare HTTP terminator. The codec de-chunks its own layer only
    // -- the aws-chunked entity must reach the handler untouched, and no
    // HTTP trailers exist.
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
        wire.extend_from_slice(
            b"\r\n0\r\nx-amz-checksum-crc32:lZe8jQ==\r\n\r\n\r\n0\r\n\r\n",
        );
        assert_eq!(wire.len(), 153);
        s.write_all(&wire)?;

        let mut entity = b"64\r\n".to_vec();
        entity.extend_from_slice(&[b'A'; 100]);
        entity.extend_from_slice(
            b"\r\n0\r\nx-amz-checksum-crc32:lZe8jQ==\r\n\r\n",
        );
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
    // A failed connection gets a real HTTP response and then a clean FIN --
    // never a bare slam. Each case is its own connection; read_to_end
    // terminates because the server flush-closes.
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

        // A head that outruns the 16 KiB cap: 431. Sent in one write so
        // the reactor consumes every byte before the verdict (no unread
        // tail to turn the close into an RST).
        let mut s = connect_tcp(v4)?;
        let mut req = b"GET / HTTP/1.1\r\nHost: t\r\nX-Pad: ".to_vec();
        req.extend(std::iter::repeat_n(b'a', 17 * 1024));
        s.write_all(&req)?;
        let mut all = Vec::new();
        s.read_to_end(&mut all)?;
        let text = String::from_utf8_lossy(&all);
        assert!(text.starts_with("HTTP/1.1 431 "), "{text}");

        // A dying HEAD: the status and Content-Length arrive, the body is
        // elided (a HEAD response must not carry content).
        let mut s = connect_tcp(v4)?;
        s.write_all(
            b"HEAD /hi HTTP/1.1\r\nHost: t\r\nContent-Length: 99999999999\r\n\r\n",
        )?;
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
    // A 100 KiB single-chunk dance body: over the 64 KiB placement
    // threshold, delivered body-only, so the reactor hands its buffer to
    // the codec and the entity is de-chunked in place (the owned-body
    // path). Content equality end to end is the live proof; the zero-copy
    // pointer identity is pinned by the unit tests.
    let Some(()) = with_http_server(|v4| {
        let payload = vec![b'C'; 100 * 1024];
        let mut s = connect_tcp(v4)?;
        s.write_all(
            b"PUT /echo HTTP/1.1\r\nHost: t\r\nExpect: 100-continue\r\nTransfer-Encoding: chunked\r\n\r\n",
        )?;
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

/// Bind a **deferrable** http server: `/warm` parks on a cold shared cache
/// and a worker warms it then redrives; `/deadline` parks and the worker
/// replies 503 directly; `/drop` parks and the worker drops the handle;
/// `/hi` answers inline. `None` means io_uring is unavailable (a skip).
fn with_parking_server<T: Send + 'static>(
    client: impl FnOnce(SocketAddrV4) -> io::Result<T> + Send + 'static,
) -> Option<T> {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use truenas_ros::http::{HttpVerdict, protocol_deferrable};

    let cache = Arc::new(AtomicBool::new(false));
    let handler = move |req: HttpRequest<'_>, _: &mut ()| {
        match (req.method, req.target) {
            ("GET", "/hi") => {
                HttpVerdict::Respond(HttpResponse::new(200).body("hello"))
            }
            ("GET", "/warm") => {
                if cache.load(Ordering::Acquire) {
                    HttpVerdict::Respond(HttpResponse::new(200).body("warm"))
                } else {
                    // Cold: park, warm the cache off-thread, redrive. The
                    // second invocation takes the inline path above.
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
                // The worker misses its deadline and answers 503 itself --
                // built off-thread, serialized on the server thread.
                let (deferred, permit) = req.defer();
                thread::spawn(move || {
                    thread::sleep(Duration::from_millis(10));
                    deferred.reply(
                        HttpResponse::new(503)
                            .header("retry-after", "1")
                            .body("slow down\n"),
                    );
                });
                HttpVerdict::Defer(permit)
            }
            ("GET", "/drop") => {
                // A lost worker: the dropped handle must close the parked
                // connection rather than leak its slot.
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
    let proto = protocol_deferrable(
        HttpConfig::default(),
        |_inc: Incoming<'_>| Some(()),
        handler,
    )
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

/// Every reply written during a drain says `Connection: close`: the drain
/// closes the connection once the reply is out and admits no further request
/// on it, so the peer must not reuse it. Here the reply is a worker's, for a
/// request parked before the drain began (the idle connection's EOF marks
/// that moment), and a second request pipelined behind it is dropped with
/// the close rather than answered.
#[test]
fn replies_during_drain_say_connection_close() {
    use std::sync::mpsc;
    use truenas_ros::http::{HttpDeferred, HttpVerdict, protocol_deferrable};

    let (park_tx, park_rx) = mpsc::channel::<HttpDeferred>();
    let handler = move |req: HttpRequest<'_>, _: &mut ()| match (
        req.method, req.target,
    ) {
        ("GET", "/park") => {
            let (deferred, permit) = req.defer();
            park_tx.send(deferred).expect("the test holds the receiver");
            HttpVerdict::Defer(permit)
        }
        _ => HttpVerdict::Respond(HttpResponse::new(200).body("hello")),
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let proto = protocol_deferrable(
        HttpConfig::default(),
        |_inc: Incoming<'_>| Some(()),
        handler,
    )
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

/// The handler that starts the drain still says close on its own reply:
/// the flag is read after the handler returns, not before it runs, so an
/// admin shutdown endpoint does not answer keep-alive and then vanish.
#[test]
fn a_handler_that_starts_the_drain_still_says_close() {
    use std::sync::{Arc, OnceLock};

    let stop_cell: Arc<OnceLock<ShutdownHandle>> = Arc::new(OnceLock::new());
    let in_handler = Arc::clone(&stop_cell);
    let handler = move |req: HttpRequest<'_>, _: &mut ()| match (
        req.method, req.target,
    ) {
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
    let proto = protocol(
        HttpConfig::default(),
        |_inc: Incoming<'_>| Some(()),
        handler,
    )
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
    // The cold-miss pattern end to end: the first request parks while the
    // worker warms the cache, then redrives - ONE write, ONE response, no
    // error leg. The second request takes the warm inline path.
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
    // A worker-built 503 serializes on the server thread with the request's
    // head facts, and the connection keeps serving afterward.
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
    // No response bytes, just a close - the drop path cannot leak the slot
    // and must not invent a reply.
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
    // Two pipelined requests where the FIRST parks: the parked one must
    // answer first - the codec holds the second back for the park's
    // duration, so a later request can never be answered around an earlier
    // parked one.
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
    // HeadObject's live shape: a 200 HEAD answer declares the paired GET's
    // Content-Length while sending no body bytes - and the connection stays
    // framed, proven by a follow-up GET answering on the same connection
    // (any stray body byte would land inside the GET's status line).
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

// ---- the codec over kernel TLS (kTLS) -----------------------------------
//
// The transport S3 ships on. Everything above proves the codec over plain
// TCP; these prove the same seams over the kernel-TLS transport, whose send
// path is structurally different: a plain send carries MSG_WAITALL (the
// kernel flushes the whole gather, one full-length CQE), but the kernel TLS
// sendmsg rejects that flag (`submit_send`, src/net/core/reactor/io.rs), so
// a bodied kTLS reply is a multi-iovec SENDMSG that blocks on an io-wq
// worker until the peer drains it - and only `send_timeout`'s linked
// timeout interrupts it, surfacing a partial completion the reactor's
// re-submit path must carry. Scaffolding shared with `test/net_server.rs` --
// see `test/support/ktls.rs`.

#[path = "support/ktls.rs"]
mod ktls;

use std::sync::Arc;

use ktls::{
    ktls_acceptor, ktls_openssl_unsupported, ktls_server_handshake,
    ktls_unsupported, self_signed, tls_connect,
};
use truenas_ros::http::HttpConn;
use truenas_ros::net::server::{Listen, ServerConfig};

/// [`with_http_server`] over a kTLS listener: the same [`echo_handler`]
/// behind `Listen::tls`, with the `truenas_ktls` handshake worker minting
/// the connection state (`AcceptDeferral::ready` is the admission - the
/// accept handler does not run for kTLS connections). `None` means io_uring
/// or kTLS is unavailable here (the caller returns - a skip; a hard failure
/// under `TRUENAS_ROS_REQUIRE_KTLS`).
fn with_ktls_http_server<T: Send + 'static>(
    cfg: ServerConfig,
    client: impl FnOnce(SocketAddrV4) -> io::Result<T> + Send + 'static,
) -> Option<T> {
    with_ktls_http_server_handle(cfg, move |v4, _stop| client(v4))
}

/// [`with_ktls_http_server`] for a client that drives the server's
/// lifecycle itself: it also receives the [`ShutdownHandle`].
fn with_ktls_http_server_handle<T: Send + 'static>(
    cfg: ServerConfig,
    client: impl FnOnce(SocketAddrV4, ShutdownHandle) -> io::Result<T>
    + Send
    + 'static,
) -> Option<T> {
    if ktls_openssl_unsupported() {
        return None;
    }
    let (cert, key) = self_signed();
    let acceptor = Arc::new(ktls_acceptor(&cert, &key));
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let proto = protocol(
        HttpConfig::default(),
        |_inc: Incoming<'_>| Some(()),
        echo_handler,
    )
    .expect("codec config is valid");
    let mut server = match Server::with_config([Listen::tls(addr)], cfg, proto)
    {
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

/// One slow `/big` exchange on a fresh TLS connection: request, then crawl
/// the first ~1.5 MiB slower than the send can flush it - the kernel
/// absorbs ~4 MiB (`tcp_wmem[2]`) and the rest sits in the blocked send,
/// so a 500 ms `send_timeout` cancel lands mid-body - then drain. Returns
/// the stream (for follow-up requests) and the body read.
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
    // The S3 GET shape: head + body as two iovecs in one SENDMSG over kTLS.
    // The client drains the 6 MiB body ([`big_body`]) slower than the
    // 500 ms `send_timeout` flushes it, so the linked timeout cancels the
    // io-wq-blocked send mid-flight and the reactor re-submits the tail
    // from the partial CQE: every byte must arrive exactly once. The canned
    // body then rides the borrowed segment, and two more requests prove
    // each reply retired its read-ahead slot (a wrong retire count wedges
    // them).
    //
    // A reclaim (EOF) is retried on a fresh connection: a cancel window in
    // which the blocked send happened to write nothing closes the
    // connection as SendTimeout even though this client drains throughout --
    // rare, timing-dependent, and a server-policy question rather than a
    // data-path defect. A byte mismatch is NEVER retried; corruption fails
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
                Err(e)
                    if e.kind() == io::ErrorKind::UnexpectedEof
                        && attempt < 3 =>
                {
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

/// Assert the peer closed: a clean EOF, or the unexpected-EOF OpenSSL
/// reports when a kernel-TLS peer closes without a close_notify.
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

/// The drain's `Connection: close` over kTLS, on the inline reply path. A
/// PUT parked in the 100-continue dance is in-flight work (its body read is
/// armed, so the sweep leaves it alone): the drain begins (the idle TLS
/// connection's close marks it), the body arrives, and the echo must say
/// close before the connection goes away.
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
    // The boto3-over-TLS upload shape: a chunked PUT whose records the
    // kernel decrypts before the framer sees them. Each write is its own
    // TLS record, so chunk reassembly provably spans record boundaries,
    // and the trailer still surfaces.
    let Some(()) = with_ktls_http_server(ServerConfig::default(), |v4| {
        let mut s = tls_connect(v4)?;
        s.write_all(
            b"PUT /echo HTTP/1.1\r\nHost: t\r\nTransfer-Encoding: chunked\r\n\r\n",
        )?;
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
    // Same ordering proof as the plain-TCP test, over kTLS: the interim
    // must arrive (as its own TLS record) before any body byte is sent, or
    // this read hangs into its timeout.
    let Some(()) = with_ktls_http_server(ServerConfig::default(), |v4| {
        let mut s = tls_connect(v4)?;
        s.write_all(
            b"PUT /echo HTTP/1.1\r\nHost: t\r\nExpect: 100-continue\r\nContent-Length: 5\r\n\r\n",
        )?;
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
    // A malformed request over TLS still gets the real 400 + Connection:
    // close before the connection dies. The kernel-TLS close is a plain FIN
    // (no close_notify), so after the full farewell the client sees either
    // EOF or a truncation error - both prove the bytes beat the FIN.
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

// ---------------------------------------------------------------------------
// `protocol_fs`: the handler is handed the reactor's request-bound fs facade.

/// The boxed three-argument handler [`with_http_fs_server`] serves - boxed
/// so one harness takes differently-shaped tests (dyn dispatch is fine off
/// the hot path).
#[cfg(feature = "uring-fs")]
type FsHandler<U> = Box<
    dyn FnMut(
        HttpRequest<'_>,
        &mut U,
        Option<truenas_ros::uring_fs::FsConn<'_>>,
    ) -> truenas_ros::http::HttpVerdict,
>;

/// [`with_http_server`]'s sibling for `protocol_fs`: an fs pool
/// (`fs_ops: 16`) on the server ring, the caller's per-connection state
/// and handler, and the server's own personality registered into `pers`
/// before serving. `None` means io_uring is unavailable (a skip).
#[cfg(feature = "uring-fs")]
fn with_http_fs_server<U, T>(
    state: impl FnMut() -> U + 'static,
    handler: FsHandler<U>,
    pers: std::sync::Arc<
        std::sync::OnceLock<truenas_ros::uring_fs::Personality>,
    >,
    client: impl FnOnce(SocketAddrV4) -> io::Result<T> + Send + 'static,
) -> Option<T>
where
    U: 'static,
    T: Send + 'static,
{
    use truenas_ros::net::server::ServerConfig;

    with_http_fs_server_cfg(
        ServerConfig {
            pool_size: 16,
            fs_ops: 16,
            ..ServerConfig::default()
        },
        state,
        handler,
        pers,
        client,
    )
}

/// [`with_http_fs_server`] with the server's tuning spelled out - for the
/// tests whose subject IS a bound (an op table small enough to run out).
#[cfg(feature = "uring-fs")]
fn with_http_fs_server_cfg<U, T>(
    cfg: truenas_ros::net::server::ServerConfig,
    mut state: impl FnMut() -> U + 'static,
    handler: FsHandler<U>,
    pers: std::sync::Arc<
        std::sync::OnceLock<truenas_ros::uring_fs::Personality>,
    >,
    client: impl FnOnce(SocketAddrV4) -> io::Result<T> + Send + 'static,
) -> Option<T>
where
    U: 'static,
    T: Send + 'static,
{
    use truenas_ros::http::protocol_fs;

    let proto = protocol_fs(
        HttpConfig::default(),
        move |_inc: Incoming<'_>| Some(state()),
        handler,
    )
    .expect("codec config is valid");
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let mut server = match Server::with_config([addr], cfg, proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return None,
        Err(e) => panic!("bind with fs pool: {e}"),
    };
    pers.set(server.register_self().expect("register_self"))
        .unwrap();
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

#[cfg(feature = "uring-fs")]
#[path = "support/xattr.rs"]
mod xattr_probe;
#[cfg(feature = "uring-fs")]
use xattr_probe::set_user_xattr;

/// The S3 GET preamble through the HTTP codec: the handler takes the
/// facade, parks the request, opens under the server's personality on the
/// ring, and ONE `offload_result` job runs the whole blocking metadata tail
/// (`statx` plus two xattr reads) - the reply is served from its delivery.
/// Mirrors `fs_conn_offload_result_batches_statx_and_xattrs_in_one_job`
/// (`test/net_server.rs`) with the codec in the loop.
#[cfg(feature = "uring-fs")]
#[test]
fn http_handler_reads_a_file_through_one_batched_job() {
    use std::sync::{Arc, OnceLock};
    use truenas_ros::http::HttpVerdict;
    use truenas_ros::sync_fs::xattr::fgetxattr;
    use truenas_ros::sync_fs::{AtFlags, OFlag, OpenHow, StatxMask, statx};
    use truenas_ros::uring_fs::{Anchor, Personality};

    let dir = truenas_ros::tempdir().unwrap();
    let fp = dir.path().join("f.txt");
    std::fs::write(&fp, b"hello object").unwrap();
    if !set_user_xattr(&fp, b"user.a", b"1")
        || !set_user_xattr(&fp, b"user.b", b"22")
    {
        return; // this fs refuses user xattrs
    }
    let anchor = match Anchor::open(dir.path()) {
        Ok(a) => a,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("anchor open: {e}"),
    };
    let pers: Arc<OnceLock<Personality>> = Arc::new(OnceLock::new());

    let pc = Arc::clone(&pers);
    let handler: FsHandler<()> = Box::new(move |req, _state, fs| {
        let Some(mut fs) = fs else {
            return HttpVerdict::Respond(
                HttpResponse::new(500).body("no fs pool\n"),
            );
        };
        let (deferred, permit) = req.defer();
        let who = *pc.get().expect("personality set before serving");
        let anchor = anchor.clone();
        let how = OpenHow::new().flags(OFlag::O_RDONLY);
        fs.open(who, &anchor, c"f.txt", how, move |done, fs| {
            let Some(file) = done.file() else {
                return deferred.close();
            };
            fs.offload_result(
                move || {
                    let st = statx(
                        &file,
                        c"",
                        AtFlags::AT_EMPTY_PATH,
                        StatxMask::BASIC_STATS,
                    )?;
                    let a = fgetxattr(&file, "user.a")?;
                    let b = fgetxattr(&file, "user.b")?;
                    Ok((st.size(), a, b))
                },
                move |res, _fs| match res {
                    Ok((size, a, b)) => {
                        deferred.reply(HttpResponse::new(200).body(format!(
                            "{size}:{}:{}",
                            String::from_utf8_lossy(&a),
                            String::from_utf8_lossy(&b),
                        )))
                    }
                    Err(_) => deferred.close(),
                },
            );
        });
        HttpVerdict::Defer(permit)
    });

    let Some(()) = with_http_fs_server(
        || (),
        handler,
        pers,
        |v4| {
            let mut s = connect_tcp(v4)?;
            s.set_read_timeout(Some(Duration::from_secs(5)))?;
            s.write_all(b"GET /f.txt HTTP/1.1\r\nHost: t\r\n\r\n")?;
            let (status, _head, body) = read_response(&mut s)?;
            assert_eq!(status, 200);
            assert_eq!(
                body, b"12:1:22",
                "one job returned size and both xattrs"
            );
            Ok(())
        },
    ) else {
        return; // io_uring unavailable
    };
}

/// `HttpDeferred::redrive` pins the second-open contract: continuation and
/// offload-delivery facades cannot `open`, so a handler whose next open
/// depends on an earlier result parks its progress in `U` and redrives -
/// and the redelivery's fresh facade must be open-capable, or the second
/// pass's continuation is dropped and the connection closes instead of
/// answering.
#[cfg(feature = "uring-fs")]
#[test]
fn http_redrive_hands_back_an_open_capable_facade() {
    use std::sync::{Arc, OnceLock};
    use truenas_ros::http::HttpVerdict;
    use truenas_ros::sync_fs::{OFlag, OpenHow};
    use truenas_ros::uring_fs::{Anchor, Personality};

    let dir = truenas_ros::tempdir().unwrap();
    std::fs::write(dir.path().join("f.txt"), b"x").unwrap();
    let anchor = match Anchor::open(dir.path()) {
        Ok(a) => a,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("anchor open: {e}"),
    };
    let pers: Arc<OnceLock<Personality>> = Arc::new(OnceLock::new());

    let pc = Arc::clone(&pers);
    let handler: FsHandler<bool> = Box::new(move |req, redriven, fs| {
        let Some(mut fs) = fs else {
            return HttpVerdict::Respond(
                HttpResponse::new(500).body("no fs pool\n"),
            );
        };
        if !*redriven {
            // First pass: park, and redrive from an offload delivery - the
            // seam whose facade is deliberately not open-capable.
            *redriven = true;
            let (deferred, permit) = req.defer();
            fs.offload_result(|| Ok(()), move |_res, _fs| deferred.redrive());
            HttpVerdict::Defer(permit)
        } else {
            // Second pass (the redelivery): this facade must open.
            let (deferred, permit) = req.defer();
            let who = *pc.get().expect("personality set before serving");
            let how = OpenHow::new().flags(OFlag::O_RDONLY);
            fs.open(who, &anchor, c"f.txt", how, move |done, _fs| {
                match done.file() {
                    Some(_) => {
                        deferred.reply(HttpResponse::new(200).body("opened"))
                    }
                    None => deferred.close(),
                }
            });
            HttpVerdict::Defer(permit)
        }
    });

    let Some(()) = with_http_fs_server(
        || false,
        handler,
        pers,
        |v4| {
            let mut s = connect_tcp(v4)?;
            s.set_read_timeout(Some(Duration::from_secs(5)))?;
            s.write_all(b"GET /again HTTP/1.1\r\nHost: t\r\n\r\n")?;
            let (status, _head, body) = read_response(&mut s)?;
            assert_eq!(status, 200);
            assert_eq!(body, b"opened", "the redelivered facade opened a file");
            Ok(())
        },
    ) else {
        return; // io_uring unavailable
    };
}

// ---------------------------------------------------------------------------
// `HttpResponse::file_body`: fd-sourced response bodies, streamed by the
// reactor's reply path in bounded chunks.

/// A deterministic pattern any hole, reorder, or overrun shows up in.
#[cfg(feature = "uring-fs")]
fn patterned(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

/// The property the whole seam exists for: a body spanning many chunks
/// (default `fs_body_chunk` 256 KiB, plus an odd remainder for the final
/// short chunk) served byte-exact through the codec - with a HEAD of the
/// same resource declaring the length and sending nothing, keep-alive
/// surviving the stream, and a `Connection: close` GET flushing the WHOLE
/// body before the farewell (the tail-guarded flush-close).
#[cfg(feature = "uring-fs")]
#[test]
fn http_file_body_streams_a_multi_chunk_file() {
    use std::sync::{Arc, OnceLock};
    use truenas_ros::http::HttpVerdict;
    use truenas_ros::sync_fs::{OFlag, OpenHow};
    use truenas_ros::uring_fs::{Anchor, Personality};

    const SIZE: usize = 3 * 256 * 1024 + 12_345;
    let dir = truenas_ros::tempdir().unwrap();
    let content = patterned(SIZE);
    std::fs::write(dir.path().join("obj"), &content).unwrap();
    let anchor = match Anchor::open(dir.path()) {
        Ok(a) => a,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("anchor open: {e}"),
    };
    let pers: Arc<OnceLock<Personality>> = Arc::new(OnceLock::new());

    let pc = Arc::clone(&pers);
    let handler: FsHandler<()> = Box::new(move |req, _state, fs| {
        if req.target == "/small" {
            return HttpVerdict::Respond(HttpResponse::new(200).body("after"));
        }
        let Some(mut fs) = fs else {
            return HttpVerdict::Respond(HttpResponse::new(500));
        };
        let (deferred, permit) = req.defer();
        let who = *pc.get().expect("personality set before serving");
        let anchor = anchor.clone();
        let how = OpenHow::new().flags(OFlag::O_RDONLY);
        fs.open(who, &anchor, c"obj", how, move |done, _fs| {
            match done.file() {
                Some(file) => deferred.reply(HttpResponse::new(200).file_body(
                    file,
                    0,
                    SIZE as u64,
                )),
                None => deferred.close(),
            }
        });
        HttpVerdict::Defer(permit)
    });

    let Some(()) = with_http_fs_server(
        || (),
        handler,
        pers,
        move |v4| {
            let mut s = connect_tcp(v4)?;
            s.set_read_timeout(Some(Duration::from_secs(10)))?;
            // HEAD: the length is declared, no body byte follows - the next
            // request on this same connection parses only if that held.
            s.write_all(b"HEAD /obj HTTP/1.1\r\nHost: t\r\n\r\n")?;
            let (status, head) = read_head(&mut s)?;
            assert_eq!(status, 200);
            assert!(
                head.contains(&format!("Content-Length: {SIZE}\r\n")),
                "{head}"
            );
            // GET: the streamed body, byte-exact.
            s.write_all(b"GET /obj HTTP/1.1\r\nHost: t\r\n\r\n")?;
            let (status, _head, body) = read_response(&mut s)?;
            assert_eq!(status, 200);
            assert_eq!(body.len(), SIZE);
            assert_eq!(body, content, "streamed bytes match the file");
            // Keep-alive survived the stream.
            s.write_all(b"GET /small HTTP/1.1\r\nHost: t\r\n\r\n")?;
            let (status, _head, body) = read_response(&mut s)?;
            assert_eq!(status, 200);
            assert_eq!(body, b"after");
            // A farewell GET: the whole body must flush before the close.
            s.write_all(
                b"GET /obj HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n",
            )?;
            let (status, head, body) = read_response(&mut s)?;
            assert_eq!(status, 200);
            assert!(head.contains("Connection: close\r\n"), "{head}");
            assert_eq!(body, content, "farewell body complete before close");
            assert_eof(&mut s)?;
            Ok(())
        },
    ) else {
        return; // io_uring unavailable
    };
}

/// A range is an offset and a length - and a `File` handle stashed across
/// requests serves one **inline** (no park): the first request opens and
/// stashes, the second replies `file_body` straight from the handler.
#[cfg(feature = "uring-fs")]
#[test]
fn http_file_body_serves_a_range_from_a_stashed_handle() {
    use std::sync::{Arc, Mutex, OnceLock};
    use truenas_ros::http::HttpVerdict;
    use truenas_ros::sync_fs::{OFlag, OpenHow};
    use truenas_ros::uring_fs::{Anchor, File, Personality};

    const SIZE: usize = 4096;
    let dir = truenas_ros::tempdir().unwrap();
    let content = patterned(SIZE);
    std::fs::write(dir.path().join("obj"), &content).unwrap();
    let anchor = match Anchor::open(dir.path()) {
        Ok(a) => a,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("anchor open: {e}"),
    };
    let pers: Arc<OnceLock<Personality>> = Arc::new(OnceLock::new());
    let stash: Arc<Mutex<Option<File>>> = Arc::new(Mutex::new(None));

    let pc = Arc::clone(&pers);
    let st = Arc::clone(&stash);
    let handler: FsHandler<()> = Box::new(move |req, _state, fs| {
        if req.target == "/range" {
            // Inline: the handle held from the previous request answers
            // without a park - the handler-side shape of a preamble that
            // already opened the object.
            let file = st.lock().unwrap().take().expect("stashed by /open");
            return HttpVerdict::Respond(
                HttpResponse::new(200).file_body(file, 100, 1000),
            );
        }
        let Some(mut fs) = fs else {
            return HttpVerdict::Respond(HttpResponse::new(500));
        };
        let (deferred, permit) = req.defer();
        let who = *pc.get().expect("personality set before serving");
        let anchor = anchor.clone();
        let how = OpenHow::new().flags(OFlag::O_RDONLY);
        let st = Arc::clone(&st);
        fs.open(who, &anchor, c"obj", how, move |done, _fs| {
            match done.file() {
                Some(file) => {
                    *st.lock().unwrap() = Some(file);
                    deferred.reply(HttpResponse::new(200).body("opened"));
                }
                None => deferred.close(),
            }
        });
        HttpVerdict::Defer(permit)
    });

    let Some(()) = with_http_fs_server(
        || (),
        handler,
        pers,
        move |v4| {
            let mut s = connect_tcp(v4)?;
            s.set_read_timeout(Some(Duration::from_secs(5)))?;
            s.write_all(b"GET /open HTTP/1.1\r\nHost: t\r\n\r\n")?;
            let (status, _head, body) = read_response(&mut s)?;
            assert_eq!((status, &body[..]), (200, &b"opened"[..]));
            s.write_all(b"GET /range HTTP/1.1\r\nHost: t\r\n\r\n")?;
            let (status, head, body) = read_response(&mut s)?;
            assert_eq!(status, 200);
            assert!(head.contains("Content-Length: 1000\r\n"), "{head}");
            assert_eq!(body, content[100..1100], "the requested range");
            Ok(())
        },
    ) else {
        return; // io_uring unavailable
    };
}

/// A range whose start the caller's arithmetic wrapped is refused before it
/// reaches the ring, and refusing sheds that one connection rather than the
/// server.
///
/// `u64::MAX` is `-1`, io_uring's "use the file's own position" sentinel: for a
/// regular file `io_kiocb_update_pos` (linux `io_uring/rw.c:484-490`) would
/// read `f_pos` in place of the offset asked for and `rw.c:670-671` would write
/// the new position back, so the read would SUCCEED from the wrong place and
/// move a position shared with every other holder of the descriptor - behind a
/// `Content-Length` already on the wire. A start past `i64::MAX` that is not
/// the sentinel fails much later, in `rw_verify_area`, which is also after the
/// head has committed. `bytes=-N` past the object size is how either arrives:
/// computing the start as `size - N` wraps in `u64` rather than clamping.
///
/// The last assertion is the one that matters: a *later* connection is served.
/// A closed connection alone cannot tell a clean shed from the reactor thread
/// dying on the overflow, which is what an unguarded advance does in debug.
#[cfg(feature = "uring-fs")]
#[test]
fn http_file_body_refuses_a_wrapped_range() {
    use std::io::Read as _;
    use std::sync::{Arc, Mutex, OnceLock};
    use truenas_ros::http::HttpVerdict;
    use truenas_ros::sync_fs::{OFlag, OpenHow};
    use truenas_ros::uring_fs::{Anchor, File, Personality};

    const SIZE: usize = 4096;
    let dir = truenas_ros::tempdir().unwrap();
    let content = patterned(SIZE);
    std::fs::write(dir.path().join("obj"), &content).unwrap();
    let anchor = match Anchor::open(dir.path()) {
        Ok(a) => a,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("anchor open: {e}"),
    };
    let pers: Arc<OnceLock<Personality>> = Arc::new(OnceLock::new());
    let stash: Arc<Mutex<Vec<File>>> = Arc::new(Mutex::new(Vec::new()));

    let pc = Arc::clone(&pers);
    let st = Arc::clone(&stash);
    let handler: FsHandler<()> = Box::new(move |req, _state, fs| {
        // Each target answers inline from a handle the previous `/open`
        // stashed, so the range reaches `begin_file_reply` with nothing else
        // in flight.
        let range = match req.target {
            // `size - N` for a suffix range one byte past the object.
            "/sentinel" => Some((u64::MAX, 8)),
            // Not the sentinel, but the sum still walks past `i64::MAX`.
            "/sum" => Some((i64::MAX as u64, 8)),
            "/ok" => Some((0, SIZE as u64)),
            _ => None,
        };
        if let Some((offset, len)) = range {
            let file = st.lock().unwrap().pop().expect("stashed by /open");
            return HttpVerdict::Respond(
                HttpResponse::new(200).file_body(file, offset, len),
            );
        }
        let Some(mut fs) = fs else {
            return HttpVerdict::Respond(HttpResponse::new(500));
        };
        let (deferred, permit) = req.defer();
        let who = *pc.get().expect("personality set before serving");
        let anchor = anchor.clone();
        let how = OpenHow::new().flags(OFlag::O_RDONLY);
        let st = Arc::clone(&st);
        fs.open(who, &anchor, c"obj", how, move |done, _fs| {
            match done.file() {
                Some(file) => {
                    st.lock().unwrap().push(file);
                    deferred.reply(HttpResponse::new(200).body("opened"));
                }
                None => deferred.close(),
            }
        });
        HttpVerdict::Defer(permit)
    });

    let Some(()) = with_http_fs_server(
        || (),
        handler,
        pers,
        move |v4| {
            // Each refusal gets its own connection: the shed is the point.
            for target in ["/sentinel", "/sum"] {
                let mut s = connect_tcp(v4)?;
                s.set_read_timeout(Some(Duration::from_secs(10)))?;
                s.write_all(b"GET /open HTTP/1.1\r\nHost: t\r\n\r\n")?;
                let (status, _head, body) = read_response(&mut s)?;
                assert_eq!((status, &body[..]), (200, &b"opened"[..]));

                let req = format!("GET {target} HTTP/1.1\r\nHost: t\r\n\r\n");
                s.write_all(req.as_bytes())?;
                let mut got = Vec::new();
                s.read_to_end(&mut got)?;
                assert!(
                    got.is_empty(),
                    "{target} must be refused before the head commits, \
                     got {} bytes",
                    got.len()
                );
            }

            // The server is still there, and the reply path still streams.
            let mut s = connect_tcp(v4)?;
            s.set_read_timeout(Some(Duration::from_secs(10)))?;
            s.write_all(b"GET /open HTTP/1.1\r\nHost: t\r\n\r\n")?;
            let (status, _head, body) = read_response(&mut s)?;
            assert_eq!((status, &body[..]), (200, &b"opened"[..]));
            s.write_all(b"GET /ok HTTP/1.1\r\nHost: t\r\n\r\n")?;
            let (status, head, body) = read_response(&mut s)?;
            assert_eq!(status, 200);
            assert!(
                head.contains(&format!("Content-Length: {SIZE}\r\n")),
                "{head}"
            );
            assert_eq!(body, content, "a sound range still serves");
            Ok(())
        },
    ) else {
        return; // io_uring unavailable
    };
}

/// A body read that finds the op table full WAITS for a slot instead of
/// severing the transfer.
///
/// The table is `fs_ops + pool_size`, one free list shared by handler ops and
/// the reply path's body reads, and nothing reserves either side's share. A
/// missing chunk buffer waits for a flush to recycle one, so a missing op slot
/// waits too: the same class of transient shortage must not get opposite
/// verdicts, one of them fatal to a multi-GB download mid-stream.
///
/// Both slots are pinned here by reads on a FIFO that cannot complete until
/// the client writes to it, which is what a handler fan-out looks like from
/// the reply path. The object must still arrive whole.
#[cfg(feature = "uring-fs")]
#[test]
fn http_file_body_waits_for_an_op_slot() {
    use std::io::Write as _;
    use std::sync::mpsc;
    use std::sync::{Arc, OnceLock};
    use truenas_ros::http::HttpVerdict;
    use truenas_ros::net::server::ServerConfig;
    use truenas_ros::sync_fs::{OFlag, OpenHow};
    use truenas_ros::uring_fs::{Anchor, Personality, RwFlags};

    const SIZE: usize = 300_000; // more than one 256 KiB chunk
    let dir = truenas_ros::tempdir().unwrap();
    let content = patterned(SIZE);
    std::fs::write(dir.path().join("obj"), &content).unwrap();
    let fifo = dir.path().join("fifo");
    let cpath = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes())
        .expect("path has no NUL");
    // SAFETY: a fresh path in a private tempdir; 0o600 is the mode.
    assert_eq!(unsafe { libc::mkfifo(cpath.as_ptr(), 0o600) }, 0, "mkfifo");

    let anchor = match Anchor::open(dir.path()) {
        Ok(a) => a,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("anchor open: {e}"),
    };
    let pers: Arc<OnceLock<Personality>> = Arc::new(OnceLock::new());
    // The handler says when the reply has been handed over, so the client
    // releases the pinned reads only after the body has had its chance to
    // park - not before, which would leave the wait unexercised.
    let (armed_tx, armed_rx) = mpsc::channel::<()>();

    let pc = Arc::clone(&pers);
    let handler: FsHandler<()> = Box::new(move |req, _state, fs| {
        use std::cell::RefCell;
        use std::rc::Rc;

        let Some(mut fs) = fs else {
            return HttpVerdict::Respond(HttpResponse::new(500));
        };
        let (deferred, permit) = req.defer();
        let who = *pc.get().expect("personality set before serving");
        let armed = armed_tx.clone();
        // Both opens are issued HERE: a continuation's facade cannot open
        // (`root: false`), so the second handle cannot be fetched from the
        // first's callback. Whichever completes second does the work.
        type Held = (
            Option<truenas_ros::uring_fs::File>,
            Option<truenas_ros::uring_fs::File>,
            Option<truenas_ros::http::HttpDeferred>,
        );
        let held: Rc<RefCell<Held>> =
            Rc::new(RefCell::new((None, None, Some(deferred))));
        // O_RDWR so the open does not wait for a writer and the reads below
        // never see EOF.
        let fifo_how = OpenHow::new().flags(OFlag::O_RDWR);
        let obj_how = OpenHow::new().flags(OFlag::O_RDONLY);

        // A free `fn`, not a closure: it is called from two `'static`
        // continuations and captures nothing.
        fn finish(
            fs: &mut truenas_ros::uring_fs::FsConn<'_>,
            who: Personality,
            held: &Rc<RefCell<Held>>,
            armed: &mpsc::Sender<()>,
        ) {
            let mut h = held.borrow_mut();
            let (pipe, obj, deferred) = &mut *h;
            let (Some(pipe), Some(obj)) = (pipe.as_ref(), obj.take()) else {
                return; // the other open has not landed yet
            };
            // Take every op slot the table has (`fs_ops + pool_size` = 2).
            // `u64::MAX` because a pipe refuses a real offset (ESPIPE) and
            // takes the file-position sentinel instead.
            //
            // The buffer needs a LENGTH, not just capacity: `submit_rw` sets
            // `iov_len` from `buf.len()`, so a `Vec::with_capacity(8)` asks
            // the kernel for zero bytes, completes immediately, and pins no
            // slot at all - which leaves the wait below unexercised.
            for _ in 0..2 {
                fs.preadv2(
                    who,
                    pipe.clone(),
                    vec![vec![0u8; 8]],
                    u64::MAX,
                    RwFlags::empty(),
                    |_done, _fs| {},
                );
            }
            deferred
                .take()
                .expect("one finisher")
                .reply(HttpResponse::new(200).file_body(obj, 0, SIZE as u64));
            let _ = armed.send(());
        }

        let (h1, a1) = (Rc::clone(&held), armed.clone());
        fs.open(who, &anchor, c"fifo", fifo_how, move |done, fs| {
            h1.borrow_mut().0 = Some(done.file().expect("fifo opens"));
            finish(fs, who, &h1, &a1);
        });
        let (h2, a2) = (Rc::clone(&held), armed);
        fs.open(who, &anchor, c"obj", obj_how, move |done, fs| {
            h2.borrow_mut().1 = Some(done.file().expect("obj opens"));
            finish(fs, who, &h2, &a2);
        });
        HttpVerdict::Defer(permit)
    });

    let Some(()) = with_http_fs_server_cfg(
        ServerConfig {
            pool_size: 1,
            fs_ops: 1,
            ..ServerConfig::default()
        },
        || (),
        handler,
        pers,
        move |v4| {
            let mut s = connect_tcp(v4)?;
            s.set_read_timeout(Some(Duration::from_secs(20)))?;
            s.write_all(b"GET /obj HTTP/1.1\r\nHost: t\r\n\r\n")?;
            // Wait for the reply to be handed over, then release the pinned
            // reads: their completions are what re-drive the parked body.
            armed_rx.recv().expect("handler armed the table");
            let mut w = std::fs::OpenOptions::new().write(true).open(&fifo)?;
            w.write_all(b"go")?;
            drop(w);

            let (status, head, body) = read_response(&mut s)?;
            assert_eq!(status, 200);
            assert!(
                head.contains(&format!("Content-Length: {SIZE}\r\n")),
                "{head}"
            );
            assert_eq!(body, content, "the whole object, after waiting");
            Ok(())
        },
    ) else {
        return; // io_uring unavailable
    };
}

/// A freed op slot reaches the **parked body** before the completion's own
/// continuation can take it back.
///
/// `Server::on_cqe` calls `redrive_parked_tail()` between `fs.on_cqe(...)`
/// (which returns the slot) and `match reaped` (which fires the handler
/// continuation). That statement order is the whole anti-starvation property,
/// and it reads like post-dispatch bookkeeping, so a refactor moving it below
/// the dispatch is entirely plausible. `http_file_body_waits_for_an_op_slot`
/// does not catch that: its pinned reads complete into `|_done, _fs| {}`, so
/// nothing competes for the slot they free and the test passes with the two
/// statements in either order.
///
/// Here the pinned reads' continuations re-submit, so the freed slot is
/// contended by exactly the party the ordering exists to beat. Swap the two
/// statements in `on_cqe` and the re-submitted read wins the slot, the body
/// never gets one, and this fails on the client's read timeout.
///
/// The continuations capture no `HttpDeferred`, so the one that loses the race
/// (which, with the ordering correct, is the re-submit) is dropped harmlessly
/// rather than closing the connection.
#[cfg(feature = "uring-fs")]
#[test]
fn http_a_freed_op_slot_reaches_the_parked_body_first() {
    use std::io::Write as _;
    use std::sync::mpsc;
    use std::sync::{Arc, OnceLock};
    use truenas_ros::http::HttpVerdict;
    use truenas_ros::net::server::ServerConfig;
    use truenas_ros::sync_fs::{OFlag, OpenHow};
    use truenas_ros::uring_fs::{Anchor, File, Personality, RwFlags};

    const SIZE: usize = 300_000; // more than one 256 KiB chunk
    let dir = truenas_ros::tempdir().unwrap();
    let content = patterned(SIZE);
    std::fs::write(dir.path().join("obj"), &content).unwrap();
    let fifo = dir.path().join("fifo");
    let cpath = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes())
        .expect("path has no NUL");
    // SAFETY: a fresh path in a private tempdir; 0o600 is the mode.
    assert_eq!(unsafe { libc::mkfifo(cpath.as_ptr(), 0o600) }, 0, "mkfifo");

    let anchor = match Anchor::open(dir.path()) {
        Ok(a) => a,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("anchor open: {e}"),
    };
    let pers: Arc<OnceLock<Personality>> = Arc::new(OnceLock::new());
    let (armed_tx, armed_rx) = mpsc::channel::<()>();

    let pc = Arc::clone(&pers);
    let handler: FsHandler<()> = Box::new(move |req, _state, fs| {
        use std::cell::RefCell;
        use std::rc::Rc;

        let Some(mut fs) = fs else {
            return HttpVerdict::Respond(HttpResponse::new(500));
        };
        let (deferred, permit) = req.defer();
        let who = *pc.get().expect("personality set before serving");
        let armed = armed_tx.clone();
        type Held = (
            Option<File>,
            Option<File>,
            Option<truenas_ros::http::HttpDeferred>,
        );
        let held: Rc<RefCell<Held>> =
            Rc::new(RefCell::new((None, None, Some(deferred))));
        let fifo_how = OpenHow::new().flags(OFlag::O_RDWR);
        let obj_how = OpenHow::new().flags(OFlag::O_RDONLY);

        /// Pin one op slot with a fifo read whose completion immediately
        /// asks for the slot back. `again` bounds the chain so a lost race
        /// does not spin; one re-submit is all the contention the ordering
        /// has to survive.
        fn pin(
            fs: &mut truenas_ros::uring_fs::FsConn<'_>,
            who: Personality,
            pipe: File,
            again: bool,
        ) {
            let p = pipe.clone();
            fs.preadv2(
                who,
                pipe,
                // Length, not capacity: `submit_rw` sets `iov_len` from
                // `buf.len()`, so a `Vec::with_capacity(8)` asks for ZERO
                // bytes and the read completes at once, pinning nothing.
                vec![vec![0u8; 8]],
                u64::MAX, // a pipe refuses a real offset (ESPIPE)
                RwFlags::empty(),
                move |_done, fs| {
                    if again {
                        // Contend for the slot this completion just freed.
                        // Losing is fine: nothing here captures the reply,
                        // so a dropped callback closes nothing.
                        pin(fs, who, p, false);
                    }
                },
            );
        }

        fn finish(
            fs: &mut truenas_ros::uring_fs::FsConn<'_>,
            who: Personality,
            held: &Rc<RefCell<Held>>,
            armed: &mpsc::Sender<()>,
        ) {
            let mut h = held.borrow_mut();
            let (pipe, obj, deferred) = &mut *h;
            let (Some(pipe), Some(obj)) = (pipe.as_ref(), obj.take()) else {
                return; // the other open has not landed yet
            };
            // Take every op slot the table has (`fs_ops + pool_size` = 2).
            for _ in 0..2 {
                pin(fs, who, pipe.clone(), true);
            }
            deferred
                .take()
                .expect("one finisher")
                .reply(HttpResponse::new(200).file_body(obj, 0, SIZE as u64));
            let _ = armed.send(());
        }

        let (h1, a1) = (Rc::clone(&held), armed.clone());
        fs.open(who, &anchor, c"fifo", fifo_how, move |done, fs| {
            h1.borrow_mut().0 = Some(done.file().expect("fifo opens"));
            finish(fs, who, &h1, &a1);
        });
        let (h2, a2) = (Rc::clone(&held), armed);
        fs.open(who, &anchor, c"obj", obj_how, move |done, fs| {
            h2.borrow_mut().1 = Some(done.file().expect("obj opens"));
            finish(fs, who, &h2, &a2);
        });
        HttpVerdict::Defer(permit)
    });

    let Some(()) = with_http_fs_server_cfg(
        ServerConfig {
            pool_size: 1,
            fs_ops: 1,
            ..ServerConfig::default()
        },
        || (),
        handler,
        pers,
        move |v4| {
            let mut s = connect_tcp(v4)?;
            s.set_read_timeout(Some(Duration::from_secs(20)))?;
            s.write_all(b"GET /obj HTTP/1.1\r\nHost: t\r\n\r\n")?;
            armed_rx.recv().expect("handler armed the table");
            // Release exactly one pinned read. Its completion frees one slot
            // and its continuation asks for that slot back; the body must
            // get it first.
            let mut w = std::fs::OpenOptions::new().write(true).open(&fifo)?;
            w.write_all(b"go")?;
            drop(w);

            let (status, head, body) = read_response(&mut s)?;
            assert_eq!(status, 200);
            assert!(
                head.contains(&format!("Content-Length: {SIZE}\r\n")),
                "{head}"
            );
            assert_eq!(
                body, content,
                "the parked body won the freed slot and streamed whole"
            );
            Ok(())
        },
    ) else {
        return; // io_uring unavailable
    };
}

/// Pipelined file bodies are served, in order, all of them.
///
/// One tail at a time is structural - two bodies' chunks would interleave on
/// the wire - but shedding the connection to enforce that destroys the FIRST
/// response, which is already committed: the client gets nothing, not even
/// body one. Every other PDU in this position queues behind the tail, and so
/// does a file body.
///
/// Answered INLINE from handles a preamble stashed, not through `defer`:
/// pipelining lets replies complete out of request order (`net::server`, the
/// Pipelining section), which HTTP/1.1 forbids, so a deferred reply at
/// `max_in_flight_requests > 1` is a consumer-protocol mismatch rather than
/// anything to do with the tail.
#[cfg(feature = "uring-fs")]
#[test]
fn http_pipelined_file_bodies_queue_instead_of_killing_the_connection() {
    use std::sync::{Arc, Mutex, OnceLock};
    use truenas_ros::http::HttpVerdict;
    use truenas_ros::net::server::ServerConfig;
    use truenas_ros::sync_fs::{OFlag, OpenHow};
    use truenas_ros::uring_fs::{Anchor, File, Personality};

    const SIZE: usize = 300_000; // more than one 256 KiB chunk
    const REQUESTS: usize = 3;
    let dir = truenas_ros::tempdir().unwrap();
    let content = patterned(SIZE);
    std::fs::write(dir.path().join("obj"), &content).unwrap();
    let anchor = match Anchor::open(dir.path()) {
        Ok(a) => a,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("anchor open: {e}"),
    };
    let pers: Arc<OnceLock<Personality>> = Arc::new(OnceLock::new());
    let stash: Arc<Mutex<Vec<File>>> = Arc::new(Mutex::new(Vec::new()));

    let pc = Arc::clone(&pers);
    let st = Arc::clone(&stash);
    let handler: FsHandler<()> = Box::new(move |req, _state, fs| {
        if req.target == "/obj" {
            let file = st.lock().unwrap().pop().expect("stashed by /open");
            return HttpVerdict::Respond(HttpResponse::new(200).file_body(
                file,
                0,
                SIZE as u64,
            ));
        }
        let Some(mut fs) = fs else {
            return HttpVerdict::Respond(HttpResponse::new(500));
        };
        let (deferred, permit) = req.defer();
        let who = *pc.get().expect("personality set before serving");
        let anchor = anchor.clone();
        let how = OpenHow::new().flags(OFlag::O_RDONLY);
        let st = Arc::clone(&st);
        fs.open(who, &anchor, c"obj", how, move |done, _fs| {
            match done.file() {
                Some(file) => {
                    st.lock().unwrap().push(file);
                    deferred.reply(HttpResponse::new(200).body("opened"));
                }
                None => deferred.close(),
            }
        });
        HttpVerdict::Defer(permit)
    });

    let Some(()) = with_http_fs_server_cfg(
        ServerConfig {
            pool_size: 16,
            fs_ops: 16,
            // The whole point: read-ahead deep enough that request two is
            // delivered while request one's body is still streaming.
            max_in_flight_requests: 2,
            ..ServerConfig::default()
        },
        || (),
        handler,
        pers,
        move |v4| {
            let mut s = connect_tcp(v4)?;
            s.set_read_timeout(Some(Duration::from_secs(20)))?;
            // One handle per pipelined GET, stashed one request at a time.
            for _ in 0..REQUESTS {
                s.write_all(b"GET /open HTTP/1.1\r\nHost: t\r\n\r\n")?;
                let (status, _head, body) = read_response(&mut s)?;
                assert_eq!((status, &body[..]), (200, &b"opened"[..]));
            }
            // All of them in one write, so they are genuinely pipelined.
            let mut reqs = Vec::new();
            for _ in 0..REQUESTS {
                reqs.extend_from_slice(b"GET /obj HTTP/1.1\r\nHost: t\r\n\r\n");
            }
            s.write_all(&reqs)?;
            for i in 0..REQUESTS {
                let (status, head, body) = read_response(&mut s)?;
                assert_eq!(status, 200, "response {i}");
                assert!(
                    head.contains(&format!("Content-Length: {SIZE}\r\n")),
                    "response {i}: {head}"
                );
                assert_eq!(body, content, "response {i} body");
            }
            Ok(())
        },
    ) else {
        return; // io_uring unavailable
    };
}

/// A file grown after the length was declared: reads clamp to the declared
/// length, so exactly `len` bytes arrive and the NEXT request on the same
/// connection still parses - unclamped, the surplus would arrive as the
/// start of the next response (a framing desync).
#[cfg(feature = "uring-fs")]
#[test]
fn http_file_body_clamps_a_file_grown_mid_reply() {
    use std::io::Write as _;
    use std::sync::{Arc, OnceLock};
    use truenas_ros::http::HttpVerdict;
    use truenas_ros::sync_fs::{OFlag, OpenHow};
    use truenas_ros::uring_fs::{Anchor, Personality};

    const SIZE: usize = 256 * 1024 + 10;
    let dir = truenas_ros::tempdir().unwrap();
    let content = patterned(SIZE);
    let fp = dir.path().join("obj");
    std::fs::write(&fp, &content).unwrap();
    let anchor = match Anchor::open(dir.path()) {
        Ok(a) => a,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("anchor open: {e}"),
    };
    let pers: Arc<OnceLock<Personality>> = Arc::new(OnceLock::new());

    let pc = Arc::clone(&pers);
    let handler: FsHandler<()> = Box::new(move |req, _state, fs| {
        if req.target == "/small" {
            return HttpVerdict::Respond(HttpResponse::new(200).body("after"));
        }
        let Some(mut fs) = fs else {
            return HttpVerdict::Respond(HttpResponse::new(500));
        };
        let (deferred, permit) = req.defer();
        let who = *pc.get().expect("personality set before serving");
        let anchor = anchor.clone();
        let how = OpenHow::new().flags(OFlag::O_RDONLY);
        let fp = fp.clone();
        fs.open(who, &anchor, c"obj", how, move |done, _fs| {
            match done.file() {
                Some(file) => {
                    // Grow the file between the open and the reply: the
                    // declared length is a snapshot; the surplus must never
                    // reach the wire.
                    std::fs::OpenOptions::new()
                        .append(true)
                        .open(&fp)
                        .and_then(|mut f| f.write_all(b"SURPLUS-NEVER-SENT"))
                        .expect("append");
                    deferred.reply(HttpResponse::new(200).file_body(
                        file,
                        0,
                        SIZE as u64,
                    ));
                }
                None => deferred.close(),
            }
        });
        HttpVerdict::Defer(permit)
    });

    let Some(()) = with_http_fs_server(
        || (),
        handler,
        pers,
        move |v4| {
            let mut s = connect_tcp(v4)?;
            s.set_read_timeout(Some(Duration::from_secs(10)))?;
            s.write_all(b"GET /obj HTTP/1.1\r\nHost: t\r\n\r\n")?;
            let (status, _head, body) = read_response(&mut s)?;
            assert_eq!(status, 200);
            assert_eq!(body, content, "exactly the declared length");
            // Nothing leaked past the declared length: the next request on
            // this connection frames cleanly.
            s.write_all(b"GET /small HTTP/1.1\r\nHost: t\r\n\r\n")?;
            let (status, _head, body) = read_response(&mut s)?;
            assert_eq!((status, &body[..]), (200, &b"after"[..]));
            Ok(())
        },
    ) else {
        return; // io_uring unavailable
    };
}

/// A file truncated after the length was declared: the read hits EOF short
/// of the contract, and the only honest answer is a mid-body close - the
/// client sees a truncated transfer, never a short body framed as complete.
/// (The first read also comes back short - the file shrank below one chunk
/// -- so this pins short-read continuation and EOF classification at once.)
#[cfg(feature = "uring-fs")]
#[test]
fn http_file_body_truncation_closes_mid_body() {
    use std::io::Read as _;
    use std::sync::{Arc, OnceLock};
    use truenas_ros::http::HttpVerdict;
    use truenas_ros::sync_fs::{OFlag, OpenHow};
    use truenas_ros::uring_fs::{Anchor, Personality};

    const SIZE: usize = 300_000;
    const SHRUNK: usize = 100_000;
    let dir = truenas_ros::tempdir().unwrap();
    let content = patterned(SIZE);
    let fp = dir.path().join("obj");
    std::fs::write(&fp, &content).unwrap();
    let anchor = match Anchor::open(dir.path()) {
        Ok(a) => a,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("anchor open: {e}"),
    };
    let pers: Arc<OnceLock<Personality>> = Arc::new(OnceLock::new());

    let pc = Arc::clone(&pers);
    let handler: FsHandler<()> = Box::new(move |req, _state, fs| {
        let Some(mut fs) = fs else {
            return HttpVerdict::Respond(HttpResponse::new(500));
        };
        let (deferred, permit) = req.defer();
        let who = *pc.get().expect("personality set before serving");
        let anchor = anchor.clone();
        let how = OpenHow::new().flags(OFlag::O_RDONLY);
        let fp = fp.clone();
        fs.open(who, &anchor, c"obj", how, move |done, _fs| {
            match done.file() {
                Some(file) => {
                    // Shrink after the open: the declared length becomes a
                    // promise the file can no longer keep.
                    std::fs::OpenOptions::new()
                        .write(true)
                        .open(&fp)
                        .and_then(|f| f.set_len(SHRUNK as u64))
                        .expect("truncate");
                    deferred.reply(HttpResponse::new(200).file_body(
                        file,
                        0,
                        SIZE as u64,
                    ));
                }
                None => deferred.close(),
            }
        });
        HttpVerdict::Defer(permit)
    });

    let Some(()) = with_http_fs_server(
        || (),
        handler,
        pers,
        move |v4| {
            let mut s = connect_tcp(v4)?;
            s.set_read_timeout(Some(Duration::from_secs(10)))?;
            s.write_all(b"GET /obj HTTP/1.1\r\nHost: t\r\n\r\n")?;
            let (status, head) = read_head(&mut s)?;
            assert_eq!(status, 200);
            assert!(
                head.contains(&format!("Content-Length: {SIZE}\r\n")),
                "{head}"
            );
            let mut got = Vec::new();
            s.read_to_end(&mut got)?;
            assert!(
                got.len() < SIZE,
                "the transfer must be visibly truncated, got all {SIZE}"
            );
            assert_eq!(
                got,
                content[..got.len()],
                "what did arrive is the true prefix"
            );
            Ok(())
        },
    ) else {
        return; // io_uring unavailable
    };
}

/// A file-sourced body over kernel TLS is nothing special - chunks are
/// plaintext buffers on the ordinary send path, encrypted in the kernel --
/// so the same multi-chunk stream arrives byte-exact and the connection
/// serves the next request. Worth proving once, which is what this is.
#[cfg(feature = "uring-fs")]
#[test]
fn ktls_file_body_streams_intact() {
    use std::sync::OnceLock;
    use truenas_ros::http::{HttpVerdict, protocol_fs};
    use truenas_ros::sync_fs::{OFlag, OpenHow};
    use truenas_ros::uring_fs::{Anchor, Personality};

    if ktls_openssl_unsupported() {
        return;
    }
    const SIZE: usize = 2 * 256 * 1024 + 4_321;
    let dir = truenas_ros::tempdir().unwrap();
    let content = patterned(SIZE);
    std::fs::write(dir.path().join("obj"), &content).unwrap();
    let anchor = match Anchor::open(dir.path()) {
        Ok(a) => a,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("anchor open: {e}"),
    };
    let pers: Arc<OnceLock<Personality>> = Arc::new(OnceLock::new());

    let pc = Arc::clone(&pers);
    let proto = protocol_fs(
        HttpConfig::default(),
        |_inc: Incoming<'_>| Some(()),
        move |req: HttpRequest<'_>, _state: &mut (), fs| {
            if req.target == "/small" {
                return HttpVerdict::Respond(
                    HttpResponse::new(200).body("after"),
                );
            }
            let Some(mut fs) = fs else {
                return HttpVerdict::Respond(HttpResponse::new(500));
            };
            let (deferred, permit) = req.defer();
            let who = *pc.get().expect("personality set before serving");
            let anchor = anchor.clone();
            let how = OpenHow::new().flags(OFlag::O_RDONLY);
            fs.open(who, &anchor, c"obj", how, move |done, _fs| {
                match done.file() {
                    Some(file) => deferred.reply(
                        HttpResponse::new(200).file_body(file, 0, SIZE as u64),
                    ),
                    None => deferred.close(),
                }
            });
            HttpVerdict::Defer(permit)
        },
    )
    .expect("codec config is valid");

    let (cert, key) = self_signed();
    let acceptor = Arc::new(ktls_acceptor(&cert, &key));
    let cfg = ServerConfig {
        pool_size: 16,
        fs_ops: 16,
        ..ServerConfig::default()
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let mut server = match Server::with_config([Listen::tls(addr)], cfg, proto)
    {
        Ok(s) => s,
        Err(e) if should_skip(&e) || ktls_unsupported(&e) => return,
        Err(e) => panic!("bind: {e}"),
    };
    pers.set(server.register_self().expect("register_self"))
        .unwrap();
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
        let r = (|| -> io::Result<()> {
            let mut s = tls_connect(v4)?;
            s.write_all(b"GET /obj HTTP/1.1\r\nHost: t\r\n\r\n")?;
            let (status, _head, body) = read_response(&mut s)?;
            assert_eq!(status, 200);
            assert_eq!(body, content, "kTLS-streamed bytes match the file");
            s.write_all(b"GET /small HTTP/1.1\r\nHost: t\r\n\r\n")?;
            let (status, _head, body) = read_response(&mut s)?;
            assert_eq!((status, &body[..]), (200, &b"after"[..]));
            Ok(())
        })();
        stop.shutdown();
        r
    });
    server.serve_forever().expect("serve_forever");
    join.join().expect("client thread").expect("client io");
}

/// A request pipelined behind a streaming body is answered after it, in
/// order: both requests ride one write, and the second reply follows the
/// full first body on the wire.
#[cfg(feature = "uring-fs")]
#[test]
fn http_file_body_holds_a_pipelined_request_until_the_body_completes() {
    use std::sync::{Arc, OnceLock};
    use truenas_ros::http::HttpVerdict;
    use truenas_ros::sync_fs::{OFlag, OpenHow};
    use truenas_ros::uring_fs::{Anchor, Personality};

    const SIZE: usize = 2 * 256 * 1024 + 777;
    let dir = truenas_ros::tempdir().unwrap();
    let content = patterned(SIZE);
    std::fs::write(dir.path().join("obj"), &content).unwrap();
    let anchor = match Anchor::open(dir.path()) {
        Ok(a) => a,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("anchor open: {e}"),
    };
    let pers: Arc<OnceLock<Personality>> = Arc::new(OnceLock::new());

    let pc = Arc::clone(&pers);
    let handler: FsHandler<()> = Box::new(move |req, _state, fs| {
        if req.target == "/small" {
            return HttpVerdict::Respond(HttpResponse::new(200).body("after"));
        }
        let Some(mut fs) = fs else {
            return HttpVerdict::Respond(HttpResponse::new(500));
        };
        let (deferred, permit) = req.defer();
        let who = *pc.get().expect("personality set before serving");
        let anchor = anchor.clone();
        let how = OpenHow::new().flags(OFlag::O_RDONLY);
        fs.open(who, &anchor, c"obj", how, move |done, _fs| {
            match done.file() {
                Some(file) => deferred.reply(HttpResponse::new(200).file_body(
                    file,
                    0,
                    SIZE as u64,
                )),
                None => deferred.close(),
            }
        });
        HttpVerdict::Defer(permit)
    });

    let Some(()) = with_http_fs_server(
        || (),
        handler,
        pers,
        move |v4| {
            let mut s = connect_tcp(v4)?;
            s.set_read_timeout(Some(Duration::from_secs(10)))?;
            // Both requests in one write: the second is buffered behind the
            // streaming reply and answered after it.
            s.write_all(
                b"GET /obj HTTP/1.1\r\nHost: t\r\n\r\n\
                  GET /small HTTP/1.1\r\nHost: t\r\n\r\n",
            )?;
            let (status, _head, body) = read_response(&mut s)?;
            assert_eq!(status, 200);
            assert_eq!(body, content, "first: the full streamed body");
            let (status, _head, body) = read_response(&mut s)?;
            assert_eq!((status, &body[..]), (200, &b"after"[..]));
            Ok(())
        },
    ) else {
        return; // io_uring unavailable
    };
}

/// Bind a **streaming** http server that reassembles what it is given and
/// echoes it back, so the assertion is that a body delivered in pieces is
/// the body that was sent. `None` means io_uring is unavailable (a skip).
fn with_streaming_server<T: Send + 'static>(
    max_body: u64,
    client: impl FnOnce(SocketAddrV4) -> io::Result<T> + Send + 'static,
) -> Option<T> {
    use truenas_ros::http::{HttpVerdict, Stage, protocol_streaming};

    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    // Per-connection state: what the windows have added up to, and how many
    // of them there were - the count is what proves it streamed rather than
    // arrived whole.
    let proto = protocol_streaming(
        HttpConfig::default(),
        max_body,
        |_inc: Incoming<'_>| Some((Vec::<u8>::new(), 0usize)),
        |req: HttpRequest<'_>, state: &mut (Vec<u8>, usize)| match req.stage {
            Stage::Open => {
                state.0.clear();
                state.1 = 0;
                HttpVerdict::Continue
            }
            Stage::Window => {
                state.0.extend_from_slice(&req.body[..]);
                state.1 += 1;
                HttpVerdict::Continue
            }
            Stage::End => {
                let windows = state.1;
                HttpVerdict::Respond(
                    HttpResponse::new(200)
                        .header("x-windows", windows.to_string())
                        .body(std::mem::take(&mut state.0)),
                )
            }
            Stage::Whole => HttpVerdict::Respond(HttpResponse::new(500)),
        },
    )
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
        let _stop = ShutdownOnDrop(stop.clone());
        let r = client(v4);
        stop.shutdown();
        r
    });
    server.serve_forever().expect("serve_forever");
    Some(join.join().expect("client thread").expect("client io"))
}

/// A known-length streamed PUT whose exhausting window is resolved with
/// `HttpDeferred::redrive` must not eat the next pipelined request.
///
/// `Phase::StreamDone` is the marker for "the length is spent; the End
/// stage is owed and there is no wire left to frame it from". The resume
/// route dispatches End off the park for exactly that reason. A redrive
/// that restores the phase instead leaves the connection in `StreamDone`
/// with bytes buffered, and the framer's degrade arm then declares those
/// bytes - the next request's head - as this message's header, which the
/// End dispatch parses as a trailer section. The PUT is answered while the
/// request behind it is consumed: a desync, and the reply the peer gets
/// next belongs to a request it never had answered.
#[test]
fn a_redriven_known_length_stream_does_not_eat_the_next_request() {
    use truenas_ros::http::{
        HttpDeferred, HttpVerdict, Stage, protocol_streaming,
    };

    const PUT_LEN: usize = 200 * 1024;

    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    // One deferral, on the window that exhausts the declared length.
    let proto = protocol_streaming(
        HttpConfig::default(),
        1 << 20,
        |_inc: Incoming<'_>| Some((0usize, false)),
        |req: HttpRequest<'_>, st: &mut (usize, bool)| match req.stage {
            Stage::Open => {
                *st = (0, false);
                HttpVerdict::Continue
            }
            // Defer on the window that *exhausts* the declared length -
            // the only one whose park carries the `StreamDone` marker,
            // because after it there is no wire left to frame End from.
            Stage::Window => {
                st.0 += req.body.len();
                if st.0 == PUT_LEN && !st.1 {
                    st.1 = true;
                    let (d, permit) = req.defer();
                    let d: HttpDeferred = d;
                    thread::spawn(move || {
                        thread::sleep(Duration::from_millis(20));
                        d.redrive();
                    });
                    return HttpVerdict::Defer(permit);
                }
                HttpVerdict::Continue
            }
            Stage::End => HttpVerdict::Respond(HttpResponse::new(200)),
            Stage::Whole => HttpVerdict::Respond(HttpResponse::new(204)),
        },
    )
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
    let join = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone());
        let r = (|| -> io::Result<(u16, u16)> {
            let mut s = connect_tcp(v4)?;
            s.set_read_timeout(Some(Duration::from_secs(5)))?;
            // The PUT and a plain GET behind it, in one write, so the head
            // read over-reads into the second request.
            let body = vec![b'x'; PUT_LEN];
            let mut wire = format!(
                "PUT /up HTTP/1.1\r\nHost: t\r\nContent-Length: {}\r\n\r\n",
                body.len()
            )
            .into_bytes();
            wire.extend_from_slice(&body);
            wire.extend_from_slice(b"GET /after HTTP/1.1\r\nHost: t\r\n\r\n");
            s.write_all(&wire)?;
            let (first, _h1, _b1) = read_response(&mut s)?;
            let (second, _h2, _b2) = read_response(&mut s)?;
            Ok((first, second))
        })();
        stop.shutdown();
        r
    });
    server.serve_forever().expect("serve_forever");
    let (first, second) =
        join.join().expect("client thread").expect("client io");
    assert_eq!(first, 200, "the PUT is answered");
    assert_eq!(
        second, 204,
        "the GET behind it must be framed as its own request, not eaten as \
         the PUT's trailer section"
    );
}

/// A streamed terminal chunk carries its trailers to `Stage::End`.
///
/// The trailer section is the whole point of the streaming path for an S3
/// front: `X-Amz-Trailer` promises a checksum that only arrives after the
/// last byte of payload, and a handler that never sees it cannot verify
/// what it just wrote. The buffered path is pinned by
/// `chunked_put_and_trailers`; this is the streamed twin, and it asserts on
/// the trailer *reaching the handler* rather than on any framing detail.
#[test]
fn a_streamed_terminal_chunk_carries_its_trailers() {
    use truenas_ros::http::{HttpVerdict, Stage, protocol_streaming};

    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let proto = protocol_streaming(
        HttpConfig::default(),
        1 << 20,
        |_inc: Incoming<'_>| Some(()),
        |req: HttpRequest<'_>, _s: &mut ()| match req.stage {
            Stage::Open | Stage::Window => HttpVerdict::Continue,
            Stage::End => {
                // Name and value both, so a trailer that arrives empty is
                // distinguishable from one that never arrived.
                let seen: Vec<String> = req
                    .trailers
                    .iter()
                    .map(|t| {
                        format!(
                            "{}={}",
                            t.name,
                            String::from_utf8_lossy(t.value)
                        )
                    })
                    .collect();
                HttpVerdict::Respond(
                    HttpResponse::new(200).header("x-trailers", seen.join(",")),
                )
            }
            Stage::Whole => HttpVerdict::Respond(HttpResponse::new(500)),
        },
    )
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
    let join = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone());
        let r = (|| -> io::Result<String> {
            let mut s = connect_tcp(v4)?;
            s.set_read_timeout(Some(Duration::from_secs(5)))?;
            s.write_all(
                b"PUT /up HTTP/1.1\r\nHost: t\r\n\
                  Transfer-Encoding: chunked\r\n\
                  X-Amz-Trailer: x-amz-checksum-crc32\r\n\r\n\
                  4\r\nAAAA\r\n0\r\nx-amz-checksum-crc32: sQlaLQ==\r\n\r\n",
            )?;
            let (status, head, _body) = read_response(&mut s)?;
            assert_eq!(status, 200);
            Ok(head)
        })();
        stop.shutdown();
        r
    });
    server.serve_forever().expect("serve_forever");
    let head = join.join().expect("client thread").expect("client io");
    assert!(
        head.contains("x-trailers: x-amz-checksum-crc32=sQlaLQ=="),
        "the streamed terminal chunk's trailer never reached the handler: \
         {head}"
    );
}

/// A multi-chunk PUT, streamed. The body is larger than any single window
/// and arrives in pieces the handler never sees together; what comes back
/// has to be exactly what went out, and the window count has to show it was
/// never assembled by the codec.
#[test]
fn a_streamed_body_arrives_in_windows_and_survives_them() {
    let Some(()) = with_streaming_server(1 << 20, |v4| {
        let mut s = connect_tcp(v4)?;
        let mut payload = Vec::new();
        for i in 0..5u32 {
            payload.extend_from_slice(&[b'a' + (i as u8); 4096]);
        }
        let mut wire = b"PUT /echo HTTP/1.1\r\nHost: t\r\n\
                         Transfer-Encoding: chunked\r\n\r\n"
            .to_vec();
        for part in payload.chunks(4096) {
            wire.extend_from_slice(format!("{:x}\r\n", part.len()).as_bytes());
            wire.extend_from_slice(part);
            wire.extend_from_slice(b"\r\n");
        }
        wire.extend_from_slice(b"0\r\n\r\n");
        s.write_all(&wire)?;
        let (status, head, body) = read_response(&mut s)?;
        assert_eq!(status, 200);
        assert_eq!(body, payload, "every window's bytes, in order");
        assert!(
            head.to_ascii_lowercase().contains("x-windows: 5"),
            "one delivery per chunk, not one for the body: {head}"
        );
        Ok(())
    }) else {
        return; // io_uring unavailable
    };
}

/// A chunk larger than the window arrives in several windows. The bound on
/// what this server buffers has to be one it picked: otherwise a peer that
/// sends a single large chunk decides it, and `max_request_bytes` is the
/// only thing standing between that and a megabyte per connection.
#[test]
fn one_oversized_chunk_is_delivered_in_several_windows() {
    let Some(()) = with_streaming_server(4 << 20, |v4| {
        let mut s = connect_tcp(v4)?;
        // One chunk, three windows' worth.
        let payload = vec![b'z'; 3 * 128 * 1024];
        let mut wire = b"PUT /echo HTTP/1.1\r\nHost: t\r\n\
                         Transfer-Encoding: chunked\r\n\r\n"
            .to_vec();
        wire.extend_from_slice(format!("{:x}\r\n", payload.len()).as_bytes());
        wire.extend_from_slice(&payload);
        wire.extend_from_slice(b"\r\n0\r\n\r\n");
        s.write_all(&wire)?;
        let (status, head, body) = read_response(&mut s)?;
        assert_eq!(status, 200);
        assert_eq!(body, payload, "split and rejoined without loss");
        assert!(
            head.to_ascii_lowercase().contains("x-windows: 3"),
            "one chunk, but three deliveries: {head}"
        );
        Ok(())
    }) else {
        return; // io_uring unavailable
    };
}

/// The decoded cap is measured as chunks are declared, so a body that
/// exceeds it is refused partway through rather than after being buffered --
/// which is the point, since it is never buffered.
#[test]
fn a_streamed_body_over_the_cap_is_refused_mid_stream() {
    let Some(()) = with_streaming_server(8192, |v4| {
        let mut s = connect_tcp(v4)?;
        let mut wire = b"PUT /echo HTTP/1.1\r\nHost: t\r\n\
                         Transfer-Encoding: chunked\r\n\r\n"
            .to_vec();
        for _ in 0..4 {
            wire.extend_from_slice(b"1000\r\n");
            wire.extend_from_slice(&[b'x'; 0x1000]);
            wire.extend_from_slice(b"\r\n");
        }
        wire.extend_from_slice(b"0\r\n\r\n");
        // The peer may be cut off mid-write once the server answers 413 and
        // closes; that is the refusal working, not a test failure.
        let _ = s.write_all(&wire);
        let (status, _) = read_head(&mut s)?;
        assert_eq!(status, 413, "refused as the cap was crossed");
        Ok(())
    }) else {
        return; // io_uring unavailable
    };
}

/// A handler that refuses partway through a body. The peer is still
/// sending, and nothing will read the rest, so the reply has to be final:
/// a keep-alive answer would leave the remaining chunks to be framed as the
/// next request. The client must see the status and then EOF.
#[test]
fn a_handler_refusing_mid_body_ends_the_connection() {
    use truenas_ros::http::{HttpVerdict, Stage, protocol_streaming};

    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let proto = protocol_streaming(
        HttpConfig::default(),
        1 << 20,
        |_inc: Incoming<'_>| Some(0usize),
        |req: HttpRequest<'_>, seen: &mut usize| match req.stage {
            Stage::Open => HttpVerdict::Continue,
            // Accept one window, then refuse - the shape a quota or a
            // checksum failure has.
            Stage::Window if *seen == 0 => {
                *seen += 1;
                HttpVerdict::Continue
            }
            Stage::Window => {
                HttpVerdict::Respond(HttpResponse::new(413).body("too much"))
            }
            _ => HttpVerdict::Respond(HttpResponse::new(200)),
        },
    )
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
    let join = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone());
        let r = (|| -> io::Result<()> {
            let mut s = connect_tcp(v4)?;
            let mut wire = b"PUT /o HTTP/1.1\r\nHost: t\r\n\
                             Transfer-Encoding: chunked\r\n\r\n"
                .to_vec();
            for _ in 0..4 {
                wire.extend_from_slice(b"1000\r\n");
                wire.extend_from_slice(&[b'x'; 0x1000]);
                wire.extend_from_slice(b"\r\n");
            }
            wire.extend_from_slice(b"0\r\n\r\n");
            // The refusal closes under us; a partial write is the mechanism
            // working, not a failure.
            let _ = s.write_all(&wire);
            let (status, head1) = read_head(&mut s)?;
            assert_eq!(status, 413, "the handler's refusal reached the peer");
            assert!(
                head1.to_ascii_lowercase().contains("connection: close"),
                "a refusal has to announce the close, not just perform it - \
                 a peer told keep-alive and then given EOF cannot tell \
                 whether it was answered or cut off: {head1}"
            );
            // And then nothing: the connection is finished, so a read past
            // the body sees EOF rather than another response.
            let mut rest = Vec::new();
            s.read_to_end(&mut rest)?;
            assert!(
                !rest.windows(4).any(|w| w == b"HTTP"),
                "no second response was framed from the abandoned body"
            );
            Ok(())
        })();
        stop.shutdown();
        r
    });
    server.serve_forever().expect("serve_forever");
    join.join().expect("client thread").expect("client io");
}

/// The redrive twin of the resume test above: a deferred `Open` resolved
/// by `HttpDeferred::redrive` - the handler re-runs and answers
/// `Continue` - owes the withheld interim exactly as a `resume()` does.
/// The two routes emit independently, so each carries its own pin;
/// without this one an expecting client holds its body back for its own
/// timeout.
#[test]
fn a_redriven_stream_open_still_sends_the_interim() {
    use truenas_ros::http::{HttpVerdict, Stage, protocol_streaming};

    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let proto = protocol_streaming(
        HttpConfig::default(),
        1 << 20,
        |_inc: Incoming<'_>| Some(0usize),
        |req: HttpRequest<'_>, opened: &mut usize| match req.stage {
            Stage::Open if *opened == 0 => {
                *opened = 1;
                let (d, permit) = req.defer();
                thread::spawn(move || {
                    // The off-thread decision, resolved by re-running the
                    // handler rather than by resuming the stream.
                    thread::sleep(Duration::from_millis(20));
                    d.redrive();
                });
                HttpVerdict::Defer(permit)
            }
            Stage::Open => HttpVerdict::Continue,
            Stage::Window => HttpVerdict::Continue,
            Stage::End => HttpVerdict::Respond(HttpResponse::new(200)),
            Stage::Whole => HttpVerdict::Respond(HttpResponse::new(500)),
        },
    )
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
    let join = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone());
        let r = (|| -> io::Result<()> {
            let mut s = connect_tcp(v4)?;
            s.set_read_timeout(Some(Duration::from_secs(5)))?;
            s.write_all(
                b"PUT /up HTTP/1.1\r\nHost: t\r\nExpect: 100-continue\r\n\
                  Transfer-Encoding: chunked\r\n\r\n",
            )?;
            // The client's half of the dance: no body until the interim.
            let mut interim = [0u8; 25];
            s.read_exact(&mut interim)?;
            assert_eq!(
                &interim[..],
                b"HTTP/1.1 100 Continue\r\n\r\n",
                "the redriven open swallowed the interim"
            );
            s.write_all(b"5\r\nhello\r\n0\r\n\r\n")?;
            let (status, _head, _body) = read_response(&mut s)?;
            assert_eq!(status, 200);
            Ok(())
        })();
        stop.shutdown();
        r
    });
    server.serve_forever().expect("serve_forever");
    join.join().expect("client thread").expect("client io");
}

/// A deferred stream open must still release the withheld `100 Continue`.
///
/// The interim is withheld pending the open decision, and an expecting
/// client sends no body byte until it arrives - so a handler that defers
/// that decision (an authorization check is the canonical case) and then
/// resumes must emit it from the resume path, or every expecting PUT
/// stalls for the client's own timeout against a server that thinks it is
/// waiting for a body.
#[test]
fn a_deferred_stream_open_still_sends_the_interim() {
    use truenas_ros::http::HttpStreamDeferred;

    let Some(()) = with_streaming_deferring_server(|v4| {
        let mut s = connect_tcp(v4)?;
        s.set_read_timeout(Some(Duration::from_secs(5)))?;
        s.write_all(
            b"PUT /up HTTP/1.1\r\nHost: t\r\nExpect: 100-continue\r\n\
              Transfer-Encoding: chunked\r\n\r\n",
        )?;
        // The client's half of the dance: no body until the interim.
        let mut interim = [0u8; 25];
        s.read_exact(&mut interim)?;
        assert_eq!(
            &interim[..],
            b"HTTP/1.1 100 Continue\r\n\r\n",
            "the deferred open swallowed the interim"
        );
        s.write_all(b"5\r\nhello\r\n0\r\n\r\n")?;
        let (status, _head, _body) = read_response(&mut s)?;
        assert_eq!(status, 200);
        Ok(())
    }) else {
        return; // io_uring unavailable
    };

    /// A streaming server whose `Open` handler defers off-thread and
    /// resumes a moment later - the review's reproducer shape.
    fn with_streaming_deferring_server<T: Send + 'static>(
        client: impl FnOnce(SocketAddrV4) -> io::Result<T> + Send + 'static,
    ) -> Option<T> {
        use truenas_ros::http::{HttpVerdict, Stage, protocol_streaming};

        let addr =
            ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
        let proto = protocol_streaming(
            HttpConfig::default(),
            1 << 20,
            |_inc: Incoming<'_>| Some(0usize),
            |req: HttpRequest<'_>, seen: &mut usize| match req.stage {
                Stage::Open => {
                    let (d, permit, _body) = req.defer_stream();
                    let d: HttpStreamDeferred = d;
                    thread::spawn(move || {
                        // The off-thread decision the park exists for.
                        thread::sleep(Duration::from_millis(20));
                        d.resume();
                    });
                    HttpVerdict::Defer(permit)
                }
                Stage::Window => {
                    *seen += req.body.len();
                    HttpVerdict::Continue
                }
                Stage::End => HttpVerdict::Respond(
                    HttpResponse::new(200).header("x-bytes", seen.to_string()),
                ),
                Stage::Whole => HttpVerdict::Respond(HttpResponse::new(500)),
            },
        )
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
            let _stop = ShutdownOnDrop(stop.clone());
            let r = client(v4);
            stop.shutdown();
            r
        });
        server.serve_forever().expect("serve_forever");
        Some(join.join().expect("client thread").expect("client io"))
    }
}

/// A peer pacing an exact read below `want / request_timeout` used to die
/// mid-transfer: the linked request clock cancelled the `MSG_WAITALL` recv
/// with partial progress and the short-positive completion always closed.
/// The clock-cancelled continuation (`resubmit_exact_recv`) resumes the
/// read instead, so the clock bounds progress-per-period rather than
/// imposing a throughput floor on the whole window.
///
/// 128 KiB `Content-Length` body written 16 KiB per ~150 ms against a
/// 500 ms request clock: the transfer spans ~2 clock periods, every period
/// sees progress, and the upload must complete and echo back intact.
#[test]
fn a_put_pacing_a_window_below_the_clock_floor_completes() {
    use truenas_ros::net::server::ServerConfig;

    let cfg = ServerConfig {
        request_timeout: Some(Duration::from_millis(500)),
        ..ServerConfig::default()
    };
    let Some(()) = with_http_server_cfg(cfg, |v4| {
        let body: Vec<u8> = (0..128 * 1024).map(|i| (i % 249) as u8).collect();
        // A loaded runner can stall the pacing loop past a whole clock
        // period, which is a legitimate zero-progress close - retry those.
        // The regression this pins is deterministic (the first mid-window
        // expiry kills the upload), so every attempt fails under it.
        let mut last = None;
        for _ in 0..3 {
            let r = (|| -> io::Result<Vec<u8>> {
                let mut s = connect_tcp(v4)?;
                write!(
                    s,
                    "PUT /echo HTTP/1.1\r\nHost: t\r\nContent-Length: {}\r\n\r\n",
                    body.len()
                )?;
                for chunk in body.chunks(16 * 1024) {
                    s.write_all(chunk)?;
                    thread::sleep(Duration::from_millis(150));
                }
                let (status, _, echoed) = read_response(&mut s)?;
                assert_eq!(status, 200);
                Ok(echoed)
            })();
            match r {
                Ok(echoed) => {
                    assert_eq!(
                        echoed, body,
                        "echoed body differs from what was sent"
                    );
                    return Ok(());
                }
                Err(e) => last = Some(e),
            }
        }
        Err(last.unwrap())
    }) else {
        return; // io_uring unavailable here
    };
}

/// The same pace through a STREAMED chunked upload - the default-client
/// shape (botocore frames 128 KiB HTTP chunks and ts3 consumes them as
/// stream windows). A plain accumulating handler dodges the floor by
/// accident (chunked bodies arrive through non-exact `More` scans, each
/// arrival re-arming a fresh clock); a streamed window is one exact
/// `MSG_WAITALL` read under one clock, so this is where the chunked
/// framing hit it.
#[test]
fn a_streamed_chunked_put_pacing_below_the_clock_floor_completes() {
    use std::sync::{Arc, Mutex};
    use truenas_ros::http::{HttpVerdict, Stage, protocol_streaming};
    use truenas_ros::net::server::ServerConfig;

    let body: Vec<u8> = (0..256 * 1024).map(|i| (i % 247) as u8).collect();
    let got = Arc::new(Mutex::new(Vec::new()));
    let sink = got.clone();

    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let proto = protocol_streaming(
        HttpConfig::default(),
        1 << 20,
        move |_inc: Incoming<'_>| Some(sink.clone()),
        |mut req: HttpRequest<'_>, sink: &mut Arc<Mutex<Vec<u8>>>| match req
            .stage
        {
            Stage::Open => HttpVerdict::Continue,
            Stage::Window => {
                sink.lock().unwrap().extend_from_slice(&req.body.take());
                HttpVerdict::Continue
            }
            Stage::End => HttpVerdict::Respond(HttpResponse::new(200)),
            Stage::Whole => HttpVerdict::Respond(HttpResponse::new(500)),
        },
    )
    .expect("codec config is valid");
    let cfg = ServerConfig {
        request_timeout: Some(Duration::from_millis(500)),
        ..ServerConfig::default()
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
    let sent = body.clone();
    let join = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone());
        // Same retry policy as the Content-Length twin above: a loaded
        // runner stalling a full period is a legitimate close, while the
        // pinned regression fails every attempt.
        let mut last = None;
        for _ in 0..3 {
            got.lock().unwrap().clear();
            let r = (|| -> io::Result<()> {
                let mut s = connect_tcp(v4)?;
                write!(
                    s,
                    "PUT /up HTTP/1.1\r\nHost: t\r\n\
                     Transfer-Encoding: chunked\r\n\r\n{:x}\r\n",
                    sent.len()
                )?;
                for chunk in sent.chunks(16 * 1024) {
                    s.write_all(chunk)?;
                    thread::sleep(Duration::from_millis(80));
                }
                s.write_all(b"\r\n0\r\n\r\n")?;
                let (status, _, _) = read_response(&mut s)?;
                assert_eq!(status, 200);
                Ok(())
            })();
            match r {
                Ok(()) => {
                    let delivered = got.lock().unwrap();
                    assert_eq!(
                        *delivered, sent,
                        "windows delivered differ from what was sent"
                    );
                    stop.shutdown();
                    return Ok(());
                }
                Err(e) => last = Some(e),
            }
        }
        stop.shutdown();
        Err(last.unwrap())
    });
    server.serve_forever().expect("serve_forever");
    join.join().expect("client thread").expect("client io");
}

/// The continuation must not have unseated the slow-loris guard: a transfer
/// that makes NO progress for a full request-clock period still closes. The
/// peer sends a quarter of the declared body and then stalls; the server
/// must FIN within a few periods, never answer 200.
#[test]
fn a_stalled_transfer_still_dies_by_the_request_clock() {
    use truenas_ros::net::server::ServerConfig;

    let cfg = ServerConfig {
        request_timeout: Some(Duration::from_millis(250)),
        ..ServerConfig::default()
    };
    let Some(()) = with_http_server_cfg(cfg, |v4| {
        let mut s = connect_tcp(v4)?;
        write!(
            s,
            "PUT /echo HTTP/1.1\r\nHost: t\r\nContent-Length: 131072\r\n\r\n"
        )?;
        s.write_all(&[7u8; 32 * 1024])?;
        // Stall. The read outlasts several clock periods, so anything but
        // the server closing the connection is a failure; a 200 here means
        // a quarter of a body was delivered as whole.
        s.set_read_timeout(Some(Duration::from_secs(5)))?;
        let mut b = [0u8; 512];
        match s.read(&mut b) {
            Ok(0) => Ok(()), // FIN: the clock reclaimed the slot
            Ok(n) => panic!(
                "server answered {} bytes to a stalled quarter-body: {:?}",
                n,
                String::from_utf8_lossy(&b[..n.min(64)])
            ),
            // ECONNRESET is a close with unread bytes on some paths.
            Err(e) if e.kind() == io::ErrorKind::ConnectionReset => Ok(()),
            Err(e) => panic!("expected the server to close, got {e}"),
        }
    }) else {
        return; // io_uring unavailable here
    };
}

/// A streamed body between windows is a message in progress, not an idle
/// connection - so it carries `request_timeout` and arms `max_receipt_time`.
///
/// The reactor cannot tell the two apart on its own: a streaming codec
/// consumes each window as its own message, so at a chunk boundary (and
/// after the head has gone out as `Stage::Open`) the accumulate buffer is
/// empty, which is exactly what "parked for the next request" looks like.
/// `Framing::MoreInMessage` is the framer saying otherwise.
///
/// The negative control is the configuration: `idle_timeout` is deliberately
/// unset here, so if the read is misclassified as idle it carries **no
/// clock at all** and the peer holds its pool slot - taken at accept, before
/// any authentication - forever. Reverting `known_step`/`stream_step`/
/// `scan_step` to plain `More` hangs this test rather than failing it fast,
/// which is the shape of the denial it guards.
#[test]
fn a_stalled_streamed_upload_is_reaped_mid_body() {
    use std::sync::{Arc, Mutex};
    use truenas_ros::http::{HttpConn, HttpVerdict, Stage, protocol_streaming};
    use truenas_ros::net::CloseReason;
    use truenas_ros::net::server::ServerConfig;

    for (what, trailer) in [
        // Stall the moment the head has been delivered: the framer is in
        // `StreamOpen` -> `StreamBody` with nothing buffered.
        ("after the head", None),
        // Stall at a chunk boundary, the CRLF after the payload withheld so
        // the buffer is empty there too.
        ("after one full window", Some(128 * 1024usize)),
    ] {
        let reasons = Arc::new(Mutex::new(Vec::new()));
        let cfg = ServerConfig {
            request_timeout: Some(Duration::from_millis(300)),
            max_receipt_time: Some(Duration::from_millis(900)),
            idle_timeout: None, // the control: nothing else can reap this
            ..ServerConfig::default()
        };
        let addr =
            ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
        let proto = protocol_streaming(
            HttpConfig::default(),
            1 << 30,
            |_inc: Incoming<'_>| Some(()),
            |req: HttpRequest<'_>, _s: &mut ()| match req.stage {
                Stage::End => HttpVerdict::Respond(HttpResponse::new(200)),
                Stage::Whole => HttpVerdict::Respond(HttpResponse::new(500)),
                _ => HttpVerdict::Continue,
            },
        )
        .expect("codec config is valid");
        let mut server = match Server::with_config([addr], cfg, proto) {
            Ok(s) => s,
            Err(e) if should_skip(&e) => return,
            Err(e) => panic!("bind: {e}"),
        };
        {
            let reasons = Arc::clone(&reasons);
            server.set_close_hook(move |_a, reason, _s: &mut HttpConn<()>| {
                reasons.lock().unwrap().push(reason);
            });
        }
        let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
            panic!("expected Tcp");
        };
        let stop = server.shutdown_handle();
        let join = thread::spawn(move || {
            let _stop = ShutdownOnDrop(stop.clone());
            let r = (|| -> io::Result<()> {
                let mut s = connect_tcp(v4)?;
                s.write_all(
                    b"PUT /o HTTP/1.1\r\nHost: t\r\n\
                      Transfer-Encoding: chunked\r\n\r\n",
                )?;
                s.flush()?;
                if let Some(n) = trailer {
                    s.write_all(format!("{n:x}\r\n").as_bytes())?;
                    s.write_all(&vec![b'A'; n])?;
                    s.flush()?; // no closing CRLF: the buffer drains empty
                }
                // Now stall. Only the server closing ends this read.
                s.set_read_timeout(Some(Duration::from_secs(8)))?;
                let mut b = [0u8; 64];
                match s.read(&mut b) {
                    Ok(0) => Ok(()),
                    Ok(n) => panic!(
                        "answered {n} bytes to a stalled upload: {:?}",
                        String::from_utf8_lossy(&b[..n.min(64)])
                    ),
                    Err(e) if e.kind() == io::ErrorKind::ConnectionReset => {
                        Ok(())
                    }
                    Err(e) => panic!(
                        "{what}: the server never reclaimed the slot: {e}"
                    ),
                }
            })();
            stop.shutdown();
            r
        });
        server.serve_forever().expect("serve_forever");
        join.join().expect("client thread").expect("client io");
        let got = reasons.lock().unwrap().clone();
        assert_eq!(
            got.as_slice(),
            &[CloseReason::RequestTimeout],
            "{what}: a stalled streamed body must read as RequestTimeout - \
             IdleTimeout would mean the read took the wrong clock, and \
             nothing at all means it took none"
        );
    }
}

/// The receipt budget reaches a streamed window: a peer pacing one window
/// slower than `max_receipt_time` is reclaimed even though it satisfies
/// `request_timeout` throughout.
///
/// This is the property that separates the two clocks
/// (`ServerConfig::max_receipt_time`), on the framing where the floor the
/// config documents - one window over the budget - actually has to hold.
///
/// Not a control for `Framing::MoreInMessage`: the chunk-size line leaves
/// bytes buffered, so this arm would find the budget armed either way. The
/// stall above is the case that needs the framer's verdict.
#[test]
fn a_streamed_window_paced_under_the_floor_is_reclaimed() {
    use std::sync::{Arc, Mutex};
    use truenas_ros::http::{HttpConn, HttpVerdict, Stage, protocol_streaming};
    use truenas_ros::net::CloseReason;
    use truenas_ros::net::server::ServerConfig;

    let reasons = Arc::new(Mutex::new(Vec::new()));
    let cfg = ServerConfig {
        request_timeout: Some(Duration::from_millis(300)),
        max_receipt_time: Some(Duration::from_millis(800)),
        idle_timeout: None,
        ..ServerConfig::default()
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let proto = protocol_streaming(
        HttpConfig::default(),
        1 << 30,
        |_inc: Incoming<'_>| Some(()),
        |req: HttpRequest<'_>, _s: &mut ()| match req.stage {
            Stage::End => HttpVerdict::Respond(HttpResponse::new(200)),
            Stage::Whole => HttpVerdict::Respond(HttpResponse::new(500)),
            _ => HttpVerdict::Continue,
        },
    )
    .expect("codec config is valid");
    let mut server = match Server::with_config([addr], cfg, proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind: {e}"),
    };
    {
        let reasons = Arc::clone(&reasons);
        server.set_close_hook(move |_a, reason, _s: &mut HttpConn<()>| {
            reasons.lock().unwrap().push(reason);
        });
    }
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();
    let join = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone());
        let r = (|| -> io::Result<()> {
            let mut s = connect_tcp(v4)?;
            s.write_all(
                b"PUT /o HTTP/1.1\r\nHost: t\r\n\
                  Transfer-Encoding: chunked\r\n\r\n",
            )?;
            // A chunk far larger than one window, then one byte per 150 ms --
            // half `request_timeout`, so that clock is satisfied throughout
            // while the window needs hours.
            s.write_all(b"40000\r\n")?;
            s.flush()?;
            for _ in 0..40 {
                if s.write_all(b"A").is_err() || s.flush().is_err() {
                    break; // the server closed under us, which is the point
                }
                thread::sleep(Duration::from_millis(150));
            }
            s.set_read_timeout(Some(Duration::from_secs(5)))?;
            let mut b = [0u8; 64];
            match s.read(&mut b) {
                Ok(0) => Ok(()),
                Ok(n) => panic!("answered {n} bytes to a trickling window"),
                Err(e) if e.kind() == io::ErrorKind::ConnectionReset => Ok(()),
                Err(e) => panic!("the server never reclaimed the slot: {e}"),
            }
        })();
        stop.shutdown();
        r
    });
    server.serve_forever().expect("serve_forever");
    join.join().expect("client thread").expect("client io");
    assert_eq!(
        reasons.lock().unwrap().as_slice(),
        &[CloseReason::ReceiptTimeout],
        "a window paced under the floor must read as ReceiptTimeout - \
         RequestTimeout would mean the inactivity guard caught it and the \
         budget never armed"
    );
}
