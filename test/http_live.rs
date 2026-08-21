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
        Error::Errno(Errno::EPERM | Errno::ENOSYS | Errno::EACCES)
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
    use truenas_ros::net::server::ServerConfig;

    let proto = protocol_fs(
        HttpConfig::default(),
        move |_inc: Incoming<'_>| Some(state()),
        handler,
    )
    .expect("codec config is valid");
    let cfg = ServerConfig {
        pool_size: 16,
        fs_ops: 16,
        ..ServerConfig::default()
    };
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
