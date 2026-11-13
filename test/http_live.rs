//! Integration tests for the `http` codec through the **real** reactor -- live loopback TCP, exercising the full ring
//! path (multishot accept -> recv-header -> the http framer -> recv/scan -> delivery -> handler -> serialize -> send ->
//! keep-alive re-arm). The codec's unit tests drive `frame`/`step` as plain functions; these pin the seams only a
//! socket can prove: the interim `100 Continue` flushing **before** the body is sent, farewell responses arriving as
//! bytes before FIN (never a slam), buffer accumulate/consume across requests on one connection, and the owned-body
//! handoff a large chunked dance takes.
//!
//! Like `test/net_server.rs`, these **skip** (return early) when io_uring is unavailable - the CI/dev sandbox blocks
//! the io_uring syscalls (ENOSYS/EPERM/EACCES), so `cargo test` stays green in a bare sandbox. Set
//! `TRUENAS_ROS_REQUIRE_IO_URING=1` (as CI on a real kernel does) to turn a skip into a hard failure so coverage can't
//! silently vanish.
//!
//! `Server` is `!Send` (its ring is single-thread-owned), so it stays on the test thread running `serve_forever`; the
//! client runs on a spawned thread and stops the server via the `Send` [`ShutdownHandle`] when done.
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
/// Deliberately *excludes* `EINVAL`: for io_uring that means the kernel rejected our setup arguments - a real bug we
/// want to fail on, not skip.
fn is_unavailable(e: &Error) -> bool {
    matches!(
        e,
        // ENOMEM: rings pin pages against RLIMIT_MEMLOCK, so a loaded box exhausts it and ring creation fails -
        // environmental, and the REQUIRE variable turns the skip red where it must not happen.
        Error::Errno(Errno::EPERM | Errno::ENOSYS | Errno::EACCES | Errno::ENOMEM)
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
/// 6 MiB patterned owned body ([`big_body`]); `GET /canned` a `'static` body (served from a borrowed reply segment);
/// `HEAD /sized` a bare 200 declaring `Content-Length: 4096` with no bytes in hand (the HeadObject shape); `PUT /echo`
/// answers the request body verbatim, with the surfaced trailer names joined into an `x-trailers` response header (so a
/// client
/// can assert exactly which trailers reached [`HttpRequest::trailers`]);
/// other `HEAD` requests answer like GET (the codec elides the body);
/// anything else is a 404.
fn echo_handler(mut req: HttpRequest<'_>, _: &mut ()) -> HttpResponse {
    match (req.method, req.target) {
        ("GET", "/hi") | ("HEAD", "/hi") => HttpResponse::new(200).body("hello"),
        ("GET", "/big") => HttpResponse::new(200).body(big_body()),
        ("GET", "/canned") => HttpResponse::new(200).body(CANNED),
        ("HEAD", "/sized") => HttpResponse::new(200).head_content_length(4096),
        ("PUT", "/echo") => {
            let names: Vec<&str> = req.trailers.iter().map(|t| t.name).collect();
            let body = req.body.take();
            HttpResponse::new(200).header("x-trailers", names.join(",")).body(body)
        }
        _ => HttpResponse::new(404).body("not found\n"),
    }
}

/// A canned `'static` reply body - served from a borrowed segment, the path a real handler's fixed error/health bodies
/// take.
const CANNED: &str = "a canned static body, sent by reference";

/// A 6 MiB body, sized so a stalled reader forces a short send completion: above what the kernel will buffer for a peer
/// that isn't reading -- `tcp_wmem[2]` caps the send buffer at 4 MiB by default, and a stalled reader's window stays
/// near `tcp_rmem[1]` - and below the server's 8 MiB `max_send_backlog`, so the reply is admissible. Patterned (not
/// constant) so truncation, reordering, or a send-cursor slip shows up as a byte mismatch rather than a length that
/// happens to agree.
fn big_body() -> Vec<u8> {
    (0..6 * 1024 * 1024).map(|i| (i % 251) as u8).collect()
}

/// Bind an http server with the shared [`echo_handler`], run the client closure against its address on a spawned
/// thread, and serve until the client stops it. `None` means io_uring is unavailable (the caller returns - a skip).
fn with_http_server<T: Send + 'static>(
    client: impl FnOnce(SocketAddrV4) -> io::Result<T> + Send + 'static,
) -> Option<T> {
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let proto =
        protocol(HttpConfig::default(), |_inc: Incoming<'_>| Some(()), echo_handler).expect("codec config is valid");
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

/// [`with_http_server`] with the server's tuning spelled out - for the tests whose subject IS a clock or a bound.
fn with_http_server_cfg<T: Send + 'static>(
    cfg: truenas_ros::net::server::ServerConfig,
    client: impl FnOnce(SocketAddrV4) -> io::Result<T> + Send + 'static,
) -> Option<T> {
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let proto =
        protocol(HttpConfig::default(), |_inc: Incoming<'_>| Some(()), echo_handler).expect("codec config is valid");
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

/// Read one response head off the stream, byte-by-byte to its CRLFCRLF (no over-read - the connection may carry more).
/// Returns `(status, head text)`; any body is left unread (a HEAD answer has none to read).
fn read_head<R: Read>(s: &mut R) -> io::Result<(u16, String)> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if s.read(&mut byte)? == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "eof inside response head"));
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

/// Read one HTTP response off the stream: the head ([`read_head`]), then exactly `Content-Length` body bytes. Returns
/// `(status, head text, body)`.
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

// ---- the codec over kernel TLS (kTLS) -----------------------------------
//
// The transport S3 ships on. Everything above proves the codec over plain TCP; these prove the same seams over the
// kernel-TLS transport, whose send path is structurally different: a plain send carries MSG_WAITALL (the kernel flushes
// the whole gather, one full-length CQE), but the kernel TLS sendmsg rejects that flag (`submit_send`,
// src/net/core/reactor/io.rs), so a bodied kTLS reply is a multi-iovec SENDMSG that blocks on an io-wq worker until the
// peer drains it - and only `send_timeout`'s linked timeout interrupts it, surfacing a partial completion the reactor's
// re-submit path must carry. Scaffolding shared with `test/net_server.rs` -- see `test/support/ktls.rs`.

#[path = "support/ktls.rs"]
mod ktls;

use std::sync::Arc;

use ktls::{
    ktls_acceptor, ktls_openssl_unsupported, ktls_server_handshake, ktls_unsupported, self_signed, tls_connect,
};
use truenas_ros::http::HttpConn;
use truenas_ros::net::server::{Listen, ServerConfig};

// ---------------------------------------------------------------------------
// `protocol_fs`: the handler is handed the reactor's request-bound fs facade.

/// The boxed three-argument handler [`with_http_fs_server`] serves - boxed so one harness takes differently-shaped
/// tests (dyn dispatch is fine off the hot path).
#[cfg(feature = "uring-fs")]
type FsHandler<U> = Box<
    dyn FnMut(HttpRequest<'_>, &mut U, Option<truenas_ros::uring_fs::FsConn<'_>>) -> truenas_ros::http::HttpVerdict,
>;

/// [`with_http_server`]'s sibling for `protocol_fs`: an fs pool (`fs_ops: 16`) on the server ring, the caller's
/// per-connection state and handler, and the server's own personality registered into `pers` before serving. `None`
/// means io_uring is unavailable (a skip).
#[cfg(feature = "uring-fs")]
fn with_http_fs_server<U, T>(
    state: impl FnMut() -> U + 'static,
    handler: FsHandler<U>,
    pers: std::sync::Arc<std::sync::OnceLock<truenas_ros::uring_fs::Personality>>,
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

/// [`with_http_fs_server`] with the server's tuning spelled out - for the tests whose subject IS a bound (an op table
/// small enough to run out).
#[cfg(feature = "uring-fs")]
fn with_http_fs_server_cfg<U, T>(
    cfg: truenas_ros::net::server::ServerConfig,
    mut state: impl FnMut() -> U + 'static,
    handler: FsHandler<U>,
    pers: std::sync::Arc<std::sync::OnceLock<truenas_ros::uring_fs::Personality>>,
    client: impl FnOnce(SocketAddrV4) -> io::Result<T> + Send + 'static,
) -> Option<T>
where
    U: 'static,
    T: Send + 'static,
{
    use truenas_ros::http::protocol_fs;

    let proto = protocol_fs(HttpConfig::default(), move |_inc: Incoming<'_>| Some(state()), handler)
        .expect("codec config is valid");
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let mut server = match Server::with_config([addr], cfg, proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return None,
        Err(e) => panic!("bind with fs pool: {e}"),
    };
    pers.set(server.register_self().expect("register_self")).unwrap();
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

#[path = "http_live/requests.rs"]
mod requests;

#[path = "http_live/kernel_tls.rs"]
mod kernel_tls;

#[cfg(feature = "uring-fs")]
#[path = "http_live/protocol_fs.rs"]
mod protocol_fs;

#[cfg(feature = "uring-fs")]
#[path = "http_live/file_body.rs"]
mod file_body;

#[path = "http_live/streaming.rs"]
mod streaming;
