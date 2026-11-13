//! Integration tests for the `net::server` module - live loopback echo over TCP and AF_UNIX with a 4-byte big-endian
//! length-prefix framing, exercising the full ring path (multishot accept -> recv-header -> frame -> recv-body ->
//! handler -> send -> keep-alive).
//!
//! Like `test/zfs.rs` and `test/configparser_compat.rs`, these **skip** (return early) when io_uring is unavailable -
//! the CI/dev sandbox blocks the io_uring syscalls (ENOSYS/EPERM/EACCES), so `cargo test` stays green in a bare
//! sandbox. Set `TRUENAS_ROS_REQUIRE_IO_URING=1` (as CI on a real kernel does) to turn a skip into a hard failure so
//! coverage can't silently vanish.
//!
//! `Server` is `!Send` (its ring is single-thread-owned), so it stays on the test thread running `serve_forever`; each
//! client runs on a spawned thread and stops the server via the `Send` [`ShutdownHandle`] when done.
#![cfg(all(target_os = "linux", feature = "net-server"))]

use std::io::{self, Read, Write};
use std::mem::ManuallyDrop;
use std::net::{SocketAddrV4, TcpStream};
use std::os::fd::FromRawFd;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use truenas_ros::net::server::{
    Body, ClientAddr, CloseReason, ControlHandle, DeferPermit, Deferred, Endian, Framing, Incoming, PeerCred,
    PrefixWidth, Protocol, PushHandle, Request, Responder, Response, Server, ServerAddr, ServerConfig, ShutdownHandle,
    Spread, StatsHandle, length_prefix_header, length_prefixed, setup_ring,
};
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

/// `unix_peercred` needs io_uring socket commands on `AF_UNIX` (Linux >= 6.18.16); on older kernels `with_config`'s
/// startup probe fails with a validation error. Environmental, like `should_skip` - but force the test on known-good
/// hosts with `TRUENAS_ROS_REQUIRE_PEERCRED`.
fn peercred_unsupported(e: &Error) -> bool {
    let unsupported = matches!(e, Error::Validation(m) if m.contains("unix_peercred requires"));
    if unsupported {
        assert!(
            std::env::var_os("TRUENAS_ROS_REQUIRE_PEERCRED").is_none(),
            "TRUENAS_ROS_REQUIRE_PEERCRED set but kernel lacks AF_UNIX \
             socket commands: {e}"
        );
    }
    unsupported
}

/// Frame a payload with a 4-byte BE length prefix so the client can length-delimit the reply (matches `recv_framed`).
fn echo_frame(payload: &[u8]) -> Vec<u8> {
    let mut pdu = (payload.len() as u32).to_be_bytes().to_vec();
    pdu.extend_from_slice(payload);
    pdu
}

/// Echo handler: re-frame the body with a 4-byte BE length prefix.
fn echo(_header: &[u8], body: &[u8], _peer: &ClientAddr) -> Option<Vec<u8>> {
    Some(echo_frame(body))
}

/// An LSP framer that returns `Framing::More` until the `\r\n\r\n` header terminator, then parses the `Content-Length`
/// body length.
fn lsp_header(buf: &[u8], _state: &mut ()) -> Framing {
    let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") else {
        return Framing::More;
    };
    let len = buf[..pos]
        .split(|&b| b == b'\n')
        .find_map(|line| {
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            std::str::from_utf8(line)
                .ok()?
                .strip_prefix("Content-Length:")
                .map(str::trim)
        })
        .and_then(|v| v.parse::<usize>().ok());
    match len {
        Some(body_len) => Framing::Complete {
            header_len: pos + 4,
            body_len,
        },
        None => Framing::Invalid,
    }
}

// ---- framed client I/O ----------------------------------------------------

fn send_framed<W: Write>(s: &mut W, payload: &[u8]) -> io::Result<()> {
    s.write_all(&(payload.len() as u32).to_be_bytes())?;
    s.write_all(payload)
}

fn recv_framed<R: Read>(s: &mut R) -> io::Result<Vec<u8>> {
    let mut len = [0u8; 4];
    s.read_exact(&mut len)?;
    let n = u32::from_be_bytes(len) as usize;
    let mut buf = vec![0u8; n];
    s.read_exact(&mut buf)?;
    Ok(buf)
}

/// Send each message and read its echo on one connection (keep-alive), then close so the server's next recv-header sees
/// EOF.
fn framed_roundtrips<S: Read + Write>(mut s: S, msgs: &[&[u8]]) -> io::Result<Vec<Vec<u8>>> {
    let mut echoes = Vec::with_capacity(msgs.len());
    for m in msgs {
        send_framed(&mut s, m)?;
        echoes.push(recv_framed(&mut s)?);
    }
    drop(s); // close -> keep-alive ends (server recv-header gets EOF)
    Ok(echoes)
}

/// Collect the close reasons a server reports, so a test can assert not just that a connection died but that it died
/// for the documented reason.
fn close_reason_channel<U>(
    server: &mut Server<
        U,
        impl FnMut(Incoming<'_>) -> Option<U>,
        impl FnMut(&[u8], &mut U) -> Framing,
        impl FnMut(Request<'_, U>) -> Response,
    >,
) -> std::sync::mpsc::Receiver<CloseReason> {
    let (tx, rx) = std::sync::mpsc::channel();
    server.set_close_hook(move |_peer, reason, _state| {
        let _ = tx.send(reason);
    });
    rx
}

/// A `[tag: u8][len: u32 BE]` framer for the splice tests: tag `S` diverts the next `len` body bytes straight to
/// `pipe_wr` via `Framing::SpliceBody` (zero-copy, never buffered); tag `C` is a normal control frame whose `len` body
/// is delivered to the body handler. The header is read with exact `Need`, so no body byte is ever over-read into the
/// buffer.
fn splice_header(pipe_wr: libc::c_int) -> impl FnMut(&[u8], &mut ()) -> Framing {
    move |buf: &[u8], _s: &mut ()| {
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
    }
}

/// Write a splice-test frame: the 5-byte `[tag][len BE]` header + `body`.
fn splice_frame<W: Write>(s: &mut W, tag: u8, body: &[u8]) -> io::Result<()> {
    let mut hdr = vec![tag];
    hdr.extend_from_slice(&(body.len() as u32).to_be_bytes());
    s.write_all(&hdr)?;
    s.write_all(body)
}

/// A throwaway protocol for the construction-time validation cases, which are rejected before any socket or ring exists
/// and so never reach io_uring.
// Three opaque closure types in the return, for the same reason `net::server::length_prefixed` carries this allow: they
// cannot be type-aliased on stable, and the signature IS the type.
#[allow(clippy::type_complexity)]
fn noop_protocol() -> Protocol<
    impl FnMut(Incoming<'_>) -> Option<()>,
    impl FnMut(&[u8], &mut ()) -> Framing,
    impl FnMut(Request<'_, ()>) -> Response,
> {
    Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(PrefixWidth::U32, Endian::Big, false),
        body: |req: Request<'_, ()>| Response::Reply(echo_frame(&req.body)),
    }
}

fn on(held: &[(TcpStream, u8)], ring: u8) -> usize {
    held.iter().filter(|(_, r)| *r == ring).count()
}

/// Block on a read and assert the server closes an idle connection promptly - a clean EOF (orderly close) or a reset.
/// The stream's existing read timeout turns a server that never closes into a failure rather than a hang.
fn expect_idle_close(s: &mut TcpStream) -> io::Result<()> {
    let start = Instant::now();
    let mut buf = [0u8; 1];
    match s.read(&mut buf) {
        Ok(0) => {}
        Ok(n) => panic!("idle connection unexpectedly got {n} byte(s)"),
        Err(e) if e.kind() == io::ErrorKind::ConnectionReset => {}
        Err(e) => return Err(e),
    }
    assert!(
        start.elapsed() < Duration::from_secs(2),
        "idle close took too long ({:?}) - timer may not be firing",
        start.elapsed()
    );
    Ok(())
}

/// Read an LSP-framed message: header up to `\r\n\r\n`, then `Content-Length` body bytes.
fn read_lsp<R: Read>(s: &mut R) -> io::Result<Vec<u8>> {
    let mut header = Vec::new();
    let mut byte = [0u8; 1];
    while !header.ends_with(b"\r\n\r\n") {
        s.read_exact(&mut byte)?;
        header.push(byte[0]);
    }
    let text = String::from_utf8_lossy(&header);
    let len: usize = text
        .lines()
        .find_map(|l| l.strip_prefix("Content-Length:"))
        .and_then(|v| v.trim().parse().ok())
        .expect("Content-Length");
    let mut body = vec![0u8; len];
    s.read_exact(&mut body)?;
    Ok(body)
}

/// One framed request/response over a fresh TCP connection.
fn one_shot(addr: SocketAddrV4, i: usize) -> io::Result<Vec<u8>> {
    let s = connect_tcp(addr)?;
    let msg = format!("req-{i}");
    let echoes = framed_roundtrips(s, &[msg.as_bytes()])?;
    Ok(echoes.into_iter().next().unwrap())
}

// ---- connect helpers ------------------------------------------------------

fn connect_tcp(addr: SocketAddrV4) -> io::Result<TcpStream> {
    let s = retry(|| TcpStream::connect(addr))?;
    s.set_read_timeout(Some(Duration::from_secs(10)))?;
    Ok(s)
}

fn connect_unix(path: &Path) -> io::Result<UnixStream> {
    let s = retry(|| UnixStream::connect(path))?;
    s.set_read_timeout(Some(Duration::from_secs(10)))?;
    Ok(s)
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
    Err(last.expect("at least one attempt"))
}

// ---- kernel TLS (kTLS) --------------------------------------------------
//
// The handshake/probe scaffolding - throwaway cert, `truenas_ktls` acceptor, OpenSSL client, and the ULP/engagement
// skip machinery - is shared with `test/http_live.rs`; see `test/support/ktls.rs`.

#[path = "support/ktls.rs"]
mod ktls;
use ktls::{
    ktls_acceptor, ktls_openssl_unsupported, ktls_server_handshake, ktls_unsupported, self_signed, tls_connect,
};

/// Shuts the server down when dropped. Every test here runs `serve_forever` on the test thread and drives the client
/// from a spawned thread, so a panicking client (a failed assert, an I/O expect) would otherwise skip its shutdown call
/// and strand the server - hanging the whole test binary instead of going red. A clone of the handle in this guard
/// makes the panic surface through `client.join()`.
struct ShutdownOnDrop(ShutdownHandle);

impl Drop for ShutdownOnDrop {
    fn drop(&mut self) {
        self.0.shutdown();
    }
}

#[cfg(feature = "uring-fs")]
#[path = "support/zfs_dir.rs"]
mod zfs_dir;

#[cfg(feature = "uring-fs")]
#[path = "support/xattr.rs"]
mod xattr_probe;
#[cfg(feature = "uring-fs")]
use xattr_probe::set_user_xattr;

#[cfg(feature = "uring-fs")]
#[path = "support/privilege.rs"]
mod privilege;
#[cfg(feature = "uring-fs")]
use privilege::{is_root, root_or_skip};

// ---- the registered recv-buffer pool --------------------------------------

/// Registering the ring is best-effort - a kernel that refuses leaves the server running with connections owning their
/// buffers - so every pooled test has to say out loud that it got a pool. Without this they all pass against the
/// fallback and prove nothing about the ring.
fn assert_pool_registered(s: &truenas_ros::net::server::ServerStats) {
    // Named separately, because the two reasons for `recv_bufs_total == 0` want different actions from whoever reads
    // the failure: a kernel with no provided-buffer rings is environmental, and `RLIMIT_MEMLOCK` refusing their region
    // is `ulimit -l` on this host - which the per-uid accounting makes reachable from an unrelated process.
    assert_eq!(
        s.buf_rings_refused_memlock, 0,
        "RLIMIT_MEMLOCK refused a buffer ring - raise `ulimit -l`: {s:?}"
    );
    assert!(
        s.recv_bufs_total > 0,
        "no recv buffer ring registered - this test exercised the \
         owned-buffer fallback, not the pool: {s:?}"
    );
}

/// A framer that consumes its own header, then declares a body with `header_len: 0` - the shape a streaming codec has
/// for every message after the first, and the one that puts a placed body read on a connection with nothing buffered.
fn split_header(buf: &[u8], pending: &mut usize) -> Framing {
    if *pending > 0 {
        // Header already delivered and drained: the body stands alone.
        return Framing::Complete {
            header_len: 0,
            body_len: *pending,
        };
    }
    if buf.len() < 4 {
        return Framing::Need(4 - buf.len());
    }
    *pending = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    // Deliver the header alone, so the body is framed on its own next time.
    Framing::Complete {
        header_len: 4,
        body_len: 0,
    }
}

#[path = "net_server/serving.rs"]
mod serving;

#[path = "net_server/control.rs"]
mod control;

#[path = "net_server/splice.rs"]
mod splice;

#[path = "net_server/push.rs"]
mod push;

#[path = "net_server/config.rs"]
mod config;

#[path = "net_server/listeners.rs"]
mod listeners;

#[path = "net_server/spread.rs"]
mod spread;

#[path = "net_server/timeouts.rs"]
mod timeouts;

#[path = "net_server/kernel_tls.rs"]
mod kernel_tls;

#[cfg(feature = "uring-fs")]
#[path = "net_server/fs_conn.rs"]
mod fs_conn;

#[cfg(feature = "uring-fs")]
#[path = "net_server/fs_files.rs"]
mod fs_files;

#[path = "net_server/fs_privilege.rs"]
mod fs_privilege;

#[path = "net_server/recv_pool.rs"]
mod recv_pool;

#[path = "net_server/redelivery.rs"]
mod redelivery;

#[path = "net_server/held.rs"]
mod held;
