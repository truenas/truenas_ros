//! Integration tests for the `net::server` module — live loopback echo over
//! TCP and AF_UNIX with a 4-byte big-endian length-prefix framing, exercising
//! the full ring path (multishot accept → recv-header → frame → recv-body →
//! handler → send → keep-alive).
//!
//! Like `test/zfs.rs` and `test/configparser_compat.rs`, these **skip** (return
//! early) when io_uring is unavailable — the CI/dev sandbox blocks the io_uring
//! syscalls (ENOSYS/EPERM/EACCES), so `cargo test` stays green in a bare
//! sandbox. Set `TRUENAS_ROS_REQUIRE_IO_URING=1` (as CI on a real kernel does)
//! to turn a skip into a hard failure so coverage can't silently vanish.
//!
//! `Server` is `!Send` (its ring is single-thread-owned), so it stays on the
//! test thread running `serve_forever`; each client runs on a spawned thread and
//! stops the server via the `Send` [`ShutdownHandle`] when done.
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
    length_prefix_header, length_prefixed, Body, ClientAddr, CloseReason,
    DeferPermit, Deferred, Endian, Framing, Incoming, PeerCred, PrefixWidth,
    Protocol, PushHandle, Request, Responder, Response, Server, ServerAddr,
    ServerConfig, ShutdownHandle,
};
use truenas_ros::{Errno, Error};

/// Errors that mean "io_uring is unavailable here" — an environmental skip.
///
/// Deliberately *excludes* `EINVAL`: for io_uring that means the kernel rejected
/// our setup arguments — a real bug we want to fail on, not skip.
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

/// `unix_peercred` needs io_uring socket commands on `AF_UNIX` (Linux ≥
/// 6.18.16); on older kernels `with_config`'s startup probe fails with a
/// validation error. Environmental, like `should_skip` — but force the test
/// on known-good hosts with `TRUENAS_ROS_REQUIRE_PEERCRED`.
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

/// Frame a payload with a 4-byte BE length prefix so the client can
/// length-delimit the reply (matches `recv_framed`).
fn echo_frame(payload: &[u8]) -> Vec<u8> {
    let mut pdu = (payload.len() as u32).to_be_bytes().to_vec();
    pdu.extend_from_slice(payload);
    pdu
}

/// Echo handler: re-frame the body with a 4-byte BE length prefix.
fn echo(_header: &[u8], body: &[u8], _peer: &ClientAddr) -> Option<Vec<u8>> {
    Some(echo_frame(body))
}

/// Consumer-side LSP framer: `Framing::More` until the `\r\n\r\n` header
/// terminator, then parse the `Content-Length` body length. This is the kind of
/// variable-length-header framer a caller writes — the server ships no such
/// protocol-specific (text) parser.
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

/// Send each message and read its echo on one connection (keep-alive), then
/// close so the server's next recv-header sees EOF.
fn framed_roundtrips<S: Read + Write>(
    mut s: S,
    msgs: &[&[u8]],
) -> io::Result<Vec<Vec<u8>>> {
    let mut echoes = Vec::with_capacity(msgs.len());
    for m in msgs {
        send_framed(&mut s, m)?;
        echoes.push(recv_framed(&mut s)?);
    }
    drop(s); // close → keep-alive ends (server recv-header gets EOF)
    Ok(echoes)
}

// ---- tests ----------------------------------------------------------------

#[test]
fn tcp_echo() {
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let mut server = match Server::bind(
        [addr],
        length_prefixed(PrefixWidth::U32, Endian::Big, false, echo),
    ) {
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
        let r = connect_tcp(v4)
            .and_then(|s| framed_roundtrips(s, &[b"hello io_uring" as &[u8]]));
        stop.shutdown();
        r
    });

    server.serve_forever().expect("serve_forever");
    let echoes = client.join().expect("thread join").expect("client io");
    assert_eq!(echoes, vec![b"hello io_uring".to_vec()]);
}

#[test]
fn unix_echo() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("echo.sock");
    let addr = ServerAddr::Unix(path.clone());
    let mut server = match Server::bind(
        [addr],
        length_prefixed(PrefixWidth::U32, Endian::Big, false, echo),
    ) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind: {e}"),
    };
    let stop = server.shutdown_handle();

    let cpath = path;
    let client = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone()); // fail fast on panic
        let r = connect_unix(&cpath)
            .and_then(|s| framed_roundtrips(s, &[b"unix ping" as &[u8]]));
        stop.shutdown();
        r
    });

    server.serve_forever().expect("serve_forever");
    let echoes = client.join().expect("thread join").expect("client io");
    assert_eq!(echoes, vec![b"unix ping".to_vec()]);
}

#[test]
fn tcp_keepalive() {
    // Several messages on ONE connection — proves the connection is reused.
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let mut server = match Server::bind(
        [addr],
        length_prefixed(PrefixWidth::U32, Endian::Big, false, echo),
    ) {
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
        let msgs: &[&[u8]] = &[b"one", b"two", b"three", b"four"];
        let r = connect_tcp(v4).and_then(|s| framed_roundtrips(s, msgs));
        stop.shutdown();
        r
    });

    server.serve_forever().expect("serve_forever");
    let echoes = client.join().expect("thread join").expect("client io");
    assert_eq!(
        echoes,
        vec![
            b"one".to_vec(),
            b"two".to_vec(),
            b"three".to_vec(),
            b"four".to_vec()
        ]
    );
}

#[test]
fn tcp_split_segments() {
    // Send the length prefix one byte at a time and the body in two halves,
    // each write flushed with a gap — so recv-header and recv-body each span
    // multiple TCP segments. This passes only if MSG_WAITALL accumulates the
    // short reads in-kernel (without it, recv-header returns 1 < 4 → close).
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let mut server = match Server::bind(
        [addr],
        length_prefixed(PrefixWidth::U32, Endian::Big, false, echo),
    ) {
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
        let r = (|| -> io::Result<Vec<u8>> {
            let mut s = connect_tcp(v4)?;
            s.set_nodelay(true)?; // one segment per write
            let payload: &[u8] = b"abcdefghij";
            for b in (payload.len() as u32).to_be_bytes() {
                s.write_all(&[b])?;
                s.flush()?;
                thread::sleep(Duration::from_millis(5));
            }
            s.write_all(&payload[..4])?;
            s.flush()?;
            thread::sleep(Duration::from_millis(5));
            s.write_all(&payload[4..])?;
            s.flush()?;
            recv_framed(&mut s)
        })();
        stop.shutdown();
        r
    });

    server.serve_forever().expect("serve_forever");
    let echo = client.join().expect("thread join").expect("client io");
    assert_eq!(echo, b"abcdefghij");
}

#[test]
fn tcp_many_concurrent() {
    // N concurrent clients, pool sized above N so none are shed. N > the
    // kernel's MULTISHOT_MAX_RETRY (32) so the multishot accept re-arms mid-run.
    const N: usize = 40;
    let cfg = ServerConfig {
        pool_size: 64,
        ..ServerConfig::default()
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let mut server = match Server::with_config(
        [addr],
        cfg,
        length_prefixed(PrefixWidth::U32, Endian::Big, false, echo),
    ) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind: {e}"),
    };
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();

    let coordinator = thread::spawn(move || {
        let clients: Vec<_> = (0..N)
            .map(|i| thread::spawn(move || one_shot(v4, i)))
            .collect();
        let results: Vec<io::Result<Vec<u8>>> =
            clients.into_iter().map(|c| c.join().unwrap()).collect();
        stop.shutdown();
        results
    });

    server.serve_forever().expect("serve_forever");
    let results = coordinator.join().expect("coordinator join");
    for (i, r) in results.into_iter().enumerate() {
        assert_eq!(r.expect("client io"), format!("req-{i}").into_bytes());
    }
}

#[test]
fn tcp_sequential_slot_reuse() {
    // Tiny pool, connections opened one at a time (never exceeding capacity) —
    // forces slot recycling and the per-slot generation bump.
    const N: usize = 20;
    let cfg = ServerConfig {
        pool_size: 4,
        ..ServerConfig::default()
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let mut server = match Server::with_config(
        [addr],
        cfg,
        length_prefixed(PrefixWidth::U32, Endian::Big, false, echo),
    ) {
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
        let echoes: Vec<_> = (0..N).map(|i| one_shot(v4, i)).collect();
        stop.shutdown();
        echoes
    });

    server.serve_forever().expect("serve_forever");
    let echoes = client.join().expect("thread join");
    for (i, r) in echoes.into_iter().enumerate() {
        assert_eq!(r.expect("client io"), format!("req-{i}").into_bytes());
    }
}

#[test]
fn tcp_bare_close_with_inflight_sibling_reuses_slot() {
    // SECURITY regression — fixed-slot reuse use-after-free / cross-connection
    // corruption. When a connection is torn down on a bare-CLOSE path while an
    // op is still in flight on its descriptor, that op pins the kernel resource
    // node: the CLOSE frees the table slot and bitmap bit at issue and biases
    // the next accept to that same index, but the pinned op keeps the old
    // socket and its buffers alive. A reuse-accept then reaches
    // `accept_connection` and overwrites the still-`Serving` slot (freed only
    // at ops==0) — dropping the live connection under the in-flight op, and,
    // because the generation never bumps on reuse-without-free, later steering
    // that op's completion onto whatever connection now holds the slot. The fix
    // cancels the in-flight op and defers the CLOSE until it reaps, so the slot
    // frees cleanly before any reuse-accept can land.
    //
    // Repro with a wide, deterministic window: a subscriber triggers a large
    // push to itself, then half-closes its WRITE side (the server's idle recv
    // sees EOF → PeerClosed, a bare close) while keeping its READ side open and
    // never reading — so the push send stalls in flight, pinning the slot
    // indefinitely. A fresh echo then reuses the freed index. Without the fix
    // the reuse corrupts the connection (wrong reply, a loop panic, or a hang);
    // with it, every echo gets its own correct reply and the server stays live.
    use std::net::Shutdown;
    use std::sync::Mutex;
    const ROUNDS: usize = 8;
    const PUSH: usize = 16 * 1024 * 1024; // stalls in flight (peer never reads it)
    let sub_handle: Arc<Mutex<Option<PushHandle>>> = Arc::new(Mutex::new(None));
    let cfg = ServerConfig {
        pool_size: 4, // small → the freed index is reused
        max_send_backlog: 64 * 1024 * 1024, // keep the push queued, don't evict it
        ..ServerConfig::default()
    };
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(
            PrefixWidth::U32,
            Endian::Big,
            false,
        ),
        body: {
            let sub_handle = Arc::clone(&sub_handle);
            move |req: Request<'_, ()>| {
                let Request {
                    body, responder, ..
                } = req;
                if &body[..] == b"sub" {
                    *sub_handle.lock().unwrap() = Some(responder.push_handle());
                    Response::Reply(echo_frame(b"ok"))
                } else if &body[..] == b"push" {
                    if let Some(h) = sub_handle.lock().unwrap().take() {
                        h.push(echo_frame(&vec![0x55u8; PUSH]));
                    }
                    Response::Reply(echo_frame(b"ok"))
                } else {
                    Response::Reply(echo_frame(&body)) // echo
                }
            }
        },
    };
    let mut server = match Server::with_config(
        [ServerAddr::Tcp(
            "127.0.0.1:0".parse::<SocketAddrV4>().unwrap(),
        )],
        cfg,
        proto,
    ) {
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
        (|| -> io::Result<()> {
            for i in 0..ROUNDS {
                // Subscribe, then push a large payload to ourselves; the server
                // starts sending it and (keep-alive) arms an idle recv.
                let mut sub = connect_tcp(v4)?;
                send_framed(&mut sub, b"sub")?;
                assert_eq!(recv_framed(&mut sub)?, b"ok");
                send_framed(&mut sub, b"push")?;
                assert_eq!(recv_framed(&mut sub)?, b"ok");
                // Half-close our WRITE side: the server's idle recv sees EOF →
                // PeerClosed, a bare close — but the large push to us is still
                // draining into our socket and we never read it, so its send
                // stays in flight and pins the descriptor.
                sub.shutdown(Shutdown::Write)?;
                thread::sleep(Duration::from_millis(15)); // let the bare close land
                                                          // Reuse the just-freed index with a fresh echo; the reply must
                                                          // be its own, and the server must stay healthy.
                let want = format!("echo-{i}");
                let mut c = connect_tcp(v4)?;
                send_framed(&mut c, want.as_bytes())?;
                assert_eq!(recv_framed(&mut c)?, want.as_bytes());
                drop(sub); // release the stalled subscriber before the next round
            }
            Ok(())
        })()
        .expect("client io");
        stop.shutdown();
    });

    server.serve_forever().expect("serve_forever");
    client.join().expect("thread join");
}

#[test]
fn tcp_lsp_framing() {
    // LSP-style variable header: `Content-Length: N\r\n\r\n<body>`. The caller's
    // `lsp_header` framer scans for `\r\n\r\n` (via Framing::More chunk reads)
    // then reads exactly N body bytes — a header the old fixed-size model can't
    // express. The body handler re-frames its reply the same way.
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: lsp_header,
        body: |req: Request<'_, ()>| {
            let Request { body, .. } = req;
            Response::Reply(
                format!("Content-Length: {}\r\n\r\n", body.len())
                    .into_bytes()
                    .into_iter()
                    .chain(body.iter().copied())
                    .collect::<Vec<u8>>(),
            )
        },
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
        let _stop = ShutdownOnDrop(stop.clone()); // fail fast on panic
        let r = (|| -> io::Result<Vec<u8>> {
            let mut s = connect_tcp(v4)?;
            let payload = b"{\"jsonrpc\":\"2.0\"}";
            write!(s, "Content-Length: {}\r\n\r\n", payload.len())?;
            s.write_all(payload)?;
            // Read the LSP reply: header up to \r\n\r\n, then Content-Length body.
            read_lsp(&mut s)
        })();
        stop.shutdown();
        r
    });

    server.serve_forever().expect("serve_forever");
    let body = client.join().expect("thread join").expect("client io");
    assert_eq!(body, b"{\"jsonrpc\":\"2.0\"}");
}

#[test]
fn tcp_stateful_counter() {
    // Per-connection state: `accept` creates a counter; the body handler bumps
    // it and echoes its value, proving `&mut U` reaches the handler and persists
    // across keep-alive requests on the same connection.
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(0u32),
        header: length_prefix_header::<u32>(
            PrefixWidth::U32,
            Endian::Big,
            false,
        ),
        body: |req: Request<'_, u32>| {
            let Request { state: count, .. } = req;
            *count += 1;
            let n = *count;
            Response::Reply(
                (n.to_be_bytes().len() as u32)
                    .to_be_bytes()
                    .into_iter()
                    .chain(n.to_be_bytes())
                    .collect::<Vec<u8>>(),
            )
        },
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
        let _stop = ShutdownOnDrop(stop.clone()); // fail fast on panic
        let msgs: &[&[u8]] = &[b"a", b"b", b"c"];
        let r = connect_tcp(v4).and_then(|s| framed_roundtrips(s, msgs));
        stop.shutdown();
        r
    });

    server.serve_forever().expect("serve_forever");
    let replies = client.join().expect("thread join").expect("client io");
    let counts: Vec<u32> = replies
        .iter()
        .map(|r| u32::from_be_bytes(r[..4].try_into().unwrap()))
        .collect();
    assert_eq!(counts, vec![1, 2, 3]);
}

#[test]
fn tcp_deferred_offload() {
    // The body handler offloads work to another thread (standing in for a real
    // pool) and returns `Response::Defer`, freeing the server thread to keep
    // polling. The worker computes the reply and hands it back via the
    // `Deferred`; the server sends it on the next wake, and keep-alive resumes —
    // proven by a second round-trip on the same connection.
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(
            PrefixWidth::U32,
            Endian::Big,
            false,
        ),
        body: |req: Request<'_, ()>| {
            let Request {
                body, responder, ..
            } = req;
            // Move OWNED inputs to the worker — never a borrow of connection
            // state — then detach the reply handle and return to the loop.
            let input = body.to_vec();
            let (deferred, permit) = responder.defer();
            thread::spawn(move || {
                // Simulate work that must not block the ring thread.
                thread::sleep(Duration::from_millis(10));
                let out = input.to_ascii_uppercase();
                deferred.reply(echo_frame(&out));
            });
            Response::Defer(permit)
        },
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
        let _stop = ShutdownOnDrop(stop.clone()); // fail fast on panic
        let msgs: &[&[u8]] = &[b"hello", b"world"];
        let r = connect_tcp(v4).and_then(|s| framed_roundtrips(s, msgs));
        stop.shutdown();
        r
    });

    server.serve_forever().expect("serve_forever");
    let replies = client.join().expect("thread join").expect("client io");
    assert_eq!(replies, vec![b"HELLO".to_vec(), b"WORLD".to_vec()]);
}

#[test]
fn tcp_deferred_drop_closes() {
    // A lost/panicked worker: the handler detaches a `Deferred` and drops it
    // without replying. Its Drop must close the parked connection rather than
    // leak the pool slot, so the client sees a clean EOF.
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(
            PrefixWidth::U32,
            Endian::Big,
            false,
        ),
        body: |req: Request<'_, ()>| {
            let Request { responder, .. } = req;
            // Detached then dropped without replying (the lost worker).
            let (_deferred, permit) = responder.defer();
            Response::Defer(permit)
        },
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
        let _stop = ShutdownOnDrop(stop.clone()); // fail fast on panic
        let r = (|| -> io::Result<Vec<u8>> {
            let mut s = connect_tcp(v4)?;
            let _ = send_framed(&mut s, b"hi"); // may race the close; ignore
            let mut buf = Vec::new();
            s.read_to_end(&mut buf)?; // dropped Deferred closed us → EOF
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
}

/// Borrow a furnished detach fd as a BLOCKING stream WITHOUT owning it — the
/// `Detached` handle owns and closes it, so this must not (hence `ManuallyDrop`,
/// whose drop is a no-op). The fd inherits the pool socket's non-blocking mode,
/// so a blocking op must clear it first.
fn detach_stream(fd: std::os::fd::RawFd) -> ManuallyDrop<TcpStream> {
    // SAFETY: `fd` aliases a live socket; wrapped non-owningly (ManuallyDrop).
    let s = ManuallyDrop::new(unsafe { TcpStream::from_raw_fd(fd) });
    s.set_nonblocking(false).expect("blocking mode");
    s
}

#[test]
fn tcp_detach_resume() {
    // A body handler DETACHES the connection: the server furnishes a real fd to
    // a worker that does blocking I/O on the socket, then RESUMES serving. The
    // worker echoes 5 raw bytes off the fd (proving the fd is usable); after
    // resume the connection keeps serving with its per-connection state intact
    // (the request counter), proven by a framed round-trip returning `2:ping`.
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(0u32),
        header: length_prefix_header::<u32>(
            PrefixWidth::U32,
            Endian::Big,
            false,
        ),
        body: |req: Request<'_, u32>| {
            let Request {
                body,
                state,
                responder,
                ..
            } = req;
            *state += 1;
            if &body[..] == b"detach" {
                Response::Detach(responder.detach())
            } else {
                let mut out = format!("{}:", *state).into_bytes();
                out.extend_from_slice(&body[..]);
                Response::Reply(echo_frame(&out))
            }
        },
    };
    let mut server = match Server::bind([addr], proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind: {e}"),
    };
    server.set_detach_handler(|_ctx, detached| {
        thread::spawn(move || {
            let mut s = detach_stream(detached.raw_fd());
            let mut buf = [0u8; 5];
            s.read_exact(&mut buf).expect("worker read");
            s.write_all(&buf).expect("worker write");
            detached.resume();
        });
    });
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();

    let client = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone());
        let r = (|| -> io::Result<Vec<u8>> {
            let mut s = connect_tcp(v4)?;
            send_framed(&mut s, b"detach")?; // triggers detach (counter -> 1)
            s.write_all(b"raw12")?; // raw exchange with the hijack worker
            let mut echo = [0u8; 5];
            s.read_exact(&mut echo)?;
            assert_eq!(&echo, b"raw12", "worker echo");
            send_framed(&mut s, b"ping")?; // resumed serving (counter -> 2)
            recv_framed(&mut s)
        })();
        stop.shutdown();
        r
    });

    server.serve_forever().expect("serve_forever");
    let reply = client.join().expect("thread join").expect("client io");
    assert_eq!(reply, b"2:ping", "keep-alive resumed with U intact");
}

#[test]
fn tcp_detach_resume_restores_nonblocking() {
    // The furnished fd shares the pool socket's FILE DESCRIPTION, so a worker
    // clearing O_NONBLOCK for its blocking transfer (as any blocking helper
    // does) would otherwise leave the resumed connection's socket blocking —
    // silently disabling the splice path's EAGAIN → readiness-poll slow-loris
    // guard (`tcp_splice_read` takes its wait mode from the file's
    // O_NONBLOCK). `Detached::resume` must restore the flag itself. Observed
    // through a worker-held dup() of the furnished fd: same file description,
    // still open after resume consumes the handle.
    let (flag_tx, flag_rx) = std::sync::mpsc::channel::<bool>();
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(
            PrefixWidth::U32,
            Endian::Big,
            false,
        ),
        body: |req: Request<'_, ()>| {
            if &req.body[..] == b"detach" {
                Response::Detach(req.responder.detach())
            } else {
                Response::Reply(echo_frame(&req.body))
            }
        },
    };
    let mut server = match Server::bind([addr], proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind: {e}"),
    };
    server.set_detach_handler(move |_ctx, detached| {
        let flag_tx = flag_tx.clone();
        thread::spawn(move || {
            let raw = detached.raw_fd();
            // SAFETY: dup a live fd; the dup shares the file description.
            let alias = unsafe { libc::dup(raw) };
            assert!(alias >= 0, "dup");
            // The blocking-transfer pattern: clear O_NONBLOCK, do the work.
            let _s = detach_stream(raw); // set_nonblocking(false)
            detached.resume();
            // resume() restored O_NONBLOCK on the shared description before
            // signaling; the alias observes it.
            // SAFETY: fcntl on the live dup; then close it.
            let restored = unsafe {
                let fl = libc::fcntl(alias, libc::F_GETFL);
                let ok = fl >= 0 && fl & libc::O_NONBLOCK != 0;
                libc::close(alias);
                ok
            };
            let _ = flag_tx.send(restored);
        });
    });
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();

    let client = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone());
        let r = (|| -> io::Result<Vec<u8>> {
            let mut s = connect_tcp(v4)?;
            send_framed(&mut s, b"detach")?;
            // Worker resumes immediately; serving continues on the same conn.
            send_framed(&mut s, b"ping")?;
            recv_framed(&mut s)
        })();
        stop.shutdown();
        r
    });

    server.serve_forever().expect("serve_forever");
    let reply = client.join().expect("thread join").expect("client io");
    assert_eq!(reply, b"ping", "keep-alive after detach/resume");
    assert!(
        flag_rx.recv().expect("worker flag"),
        "resume() must restore O_NONBLOCK on the shared file description"
    );
}

#[test]
fn tcp_detach_close() {
    // Detach, then the worker CLOSES the connection instead of resuming (e.g. a
    // one-shot transfer on a dedicated connection): the client sees a clean EOF.
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(
            PrefixWidth::U32,
            Endian::Big,
            false,
        ),
        body: |req: Request<'_, ()>| Response::Detach(req.responder.detach()),
    };
    let mut server = match Server::bind([addr], proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind: {e}"),
    };
    server.set_detach_handler(|_ctx, detached| {
        thread::spawn(move || {
            let mut s = detach_stream(detached.raw_fd());
            let mut buf = [0u8; 5];
            let _ = s.read_exact(&mut buf); // uses the fd; may race, ignore
            detached.close();
        });
    });
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();

    let client = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone());
        let r = (|| -> io::Result<Vec<u8>> {
            let mut s = connect_tcp(v4)?;
            send_framed(&mut s, b"detach")?;
            let _ = s.write_all(b"raw12");
            let mut buf = Vec::new();
            s.read_to_end(&mut buf)?; // worker close() -> EOF
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
}

#[test]
fn tcp_detach_drop_closes() {
    // A lost/panicked detach worker: the handler moves the `Detached` to a
    // thread that drops it without resume/close. Its Drop must close the parked
    // connection rather than leak the pool slot, so the client sees a clean EOF.
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(
            PrefixWidth::U32,
            Endian::Big,
            false,
        ),
        body: |req: Request<'_, ()>| Response::Detach(req.responder.detach()),
    };
    let mut server = match Server::bind([addr], proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind: {e}"),
    };
    server.set_detach_handler(|_ctx, detached| {
        thread::spawn(move || {
            drop(detached); // lost worker → Drop closes the connection
        });
    });
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
            s.read_to_end(&mut buf)?; // dropped Detached closed us → EOF
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
}

/// A `[tag: u8][len: u32 BE]` framer for the splice tests: tag `S` diverts the
/// next `len` body bytes straight to `pipe_wr` via `Framing::SpliceBody`
/// (zero-copy, never buffered); tag `C` is a normal control frame whose `len`
/// body is delivered to the body handler. The header is read with exact
/// `Need`, so no body byte is ever over-read into the buffer.
fn splice_header(
    pipe_wr: libc::c_int,
) -> impl FnMut(&[u8], &mut ()) -> Framing {
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

#[test]
fn tcp_splice_body_recv() {
    // A framer diverts a DATA frame's body straight from the socket to a
    // consumer pipe with IORING_OP_SPLICE — zero-copy, the body never enters
    // the connection buffer — while CONTROL frames deliver to the body handler
    // as usual. Proves: (a) the spliced bytes arrive intact on the pipe; (b) a
    // body several times the pipe capacity drives the partial-splice resubmit
    // path and end-to-end backpressure (the ring never blocks — an io-wq worker
    // does — while the reader drains); (c) keep-alive framing resumes after the
    // splice (a control frame still echoes on the same connection).
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: `pipe(2)` fills the two-element array with {read, write} fds.
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe");
    let (pipe_rd, pipe_wr) = (fds[0], fds[1]);

    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: splice_header(pipe_wr),
        body: |req: Request<'_, ()>| Response::Reply(echo_frame(&req.body)),
    };
    let mut server = match Server::bind([addr], proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => {
            // SAFETY: closing the test-owned pipe fds on the skip path.
            unsafe {
                libc::close(pipe_rd);
                libc::close(pipe_wr);
            }
            return;
        }
        Err(e) => panic!("bind: {e}"),
    };
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();

    // The spliced body: several times a pipe's default 64 KiB capacity, so the
    // splice completes in multiple partial steps as the reader drains.
    const BODY: usize = 256 * 1024;
    let payload: Vec<u8> = (0..BODY).map(|i| (i % 251) as u8).collect();

    // Reader thread: drain exactly BODY bytes off the pipe read end.
    let expected = payload.clone();
    let reader = thread::spawn(move || {
        let mut got = vec![0u8; BODY];
        let mut off = 0;
        while off < BODY {
            // SAFETY: read into `got[off..]`, within bounds.
            let n = unsafe {
                libc::read(
                    pipe_rd,
                    got.as_mut_ptr().add(off).cast(),
                    (BODY - off) as libc::size_t,
                )
            };
            assert!(n > 0, "pipe read returned {n}");
            off += n as usize;
        }
        // SAFETY: done with the read end.
        unsafe { libc::close(pipe_rd) };
        assert_eq!(got, expected, "spliced body mismatch");
    });

    let client = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone());
        let r = (|| -> io::Result<Vec<u8>> {
            let mut s = connect_tcp(v4)?;
            splice_frame(&mut s, b'S', &payload)?; // spliced to the pipe
            splice_frame(&mut s, b'C', b"ping")?; // control frame → echo
            recv_framed(&mut s) // keep-alive resumed after the splice
        })();
        stop.shutdown();
        r
    });

    server.serve_forever().expect("serve_forever");
    // Close the write end BEFORE joining the reader: if anything upstream
    // delivered the body short, the reader then sees EOF and its `n > 0`
    // assertion fires with a real diagnostic — instead of blocking forever in
    // read() on a pipe this process still holds open (a hang, not a failure).
    // SAFETY: closing the test-owned write end (the server only borrowed it).
    unsafe { libc::close(pipe_wr) };
    reader.join().expect("reader join");
    let echo = client.join().expect("client join").expect("client io");
    assert_eq!(echo, b"ping", "keep-alive echo after splice");
}

#[test]
fn tcp_splice_body_close_mid_splice() {
    // Teardown while a body splice is genuinely IN FLIGHT — the security-critical
    // path. A splice's SQE fd is the consumer pipe, not the socket, so the
    // fd-keyed teardown cancel can't reach it: `close_conn` must cancel the
    // splice by its user_data and defer the index-freeing CLOSE until it reaps
    // (the splice pins the socket's fixed resource node exactly like a recv, so
    // CLOSE must be the connection's last op).
    //
    // Pin the splice in flight deterministically: a tiny pipe with NO reader, and
    // a body larger than it. The first splice fills the pipe; the next parks in
    // the kernel `wait_for_space` (pipe full, never drained) — an in-flight
    // splice blocked on an io-wq worker. A graceful drain deliberately does NOT
    // touch an in-flight splice (`begin_drain`'s quiesced test skips `splicing`
    // — it cannot tell this wedged transfer from a healthy one, and truncating
    // a healthy one is the bug in `tcp_graceful_drain_lets_healthy_splice_finish`).
    // So the wedged splice is reclaimed only when the grace Deadline escalates to
    // a hard stop: this test proves that escalation's `cancel_and_reap_all` can
    // cancel a splice BLOCKED in io-wq (whose SQE fd is the pipe, not the socket)
    // rather than hanging on it — `serve_forever` returns promptly.
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: `pipe(2)` fills {read, write}.
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe");
    let (pipe_rd, pipe_wr) = (fds[0], fds[1]);
    // Shrink the pipe to one page so a small body overruns it (never drained).
    // SAFETY: F_SETPIPE_SZ on the write end; the kernel clamps to its minimum.
    unsafe { libc::fcntl(pipe_wr, libc::F_SETPIPE_SZ, 4096) };
    const BODY: usize = 32 * 1024; // > any pipe, < the socket receive buffer

    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: splice_header(pipe_wr),
        body: |req: Request<'_, ()>| Response::Reply(echo_frame(&req.body)),
    };
    let mut server = match Server::bind([addr], proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => {
            // SAFETY: closing the test-owned pipe fds on the skip path.
            unsafe {
                libc::close(pipe_rd);
                libc::close(pipe_wr);
            }
            return;
        }
        Err(e) => panic!("bind: {e}"),
    };
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();

    let client = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone()); // fail fast on panic
        (|| -> io::Result<TcpStream> {
            let mut s = connect_tcp(v4)?;
            // A data frame whose body overruns the unread pipe: the splice fills
            // the pipe, then parks in flight (nothing drains it).
            splice_frame(&mut s, b'S', &vec![0xABu8; BODY])?;
            thread::sleep(Duration::from_millis(150)); // let the splice park
            stop.shutdown_graceful(Duration::from_millis(300));
            // Keep the socket open (returned); the hard stop abandons the
            // connection and its EOF arrives when the server is dropped.
            Ok(s)
        })()
        .expect("client io")
    });

    let t0 = Instant::now();
    server.serve_forever().expect("serve_forever");
    assert!(
        t0.elapsed() < Duration::from_secs(3),
        "escalation hung on a blocked splice: {:?}",
        t0.elapsed()
    );
    let mut s = client.join().expect("client join");
    // Hard-stop abandoned the connection; dropping the server closes its pool
    // descriptor and only then does the client see EOF, with no data.
    drop(server);
    let mut buf = Vec::new();
    let n = s.read_to_end(&mut buf).unwrap_or(buf.len());
    assert_eq!(n, 0, "unexpected data after abandon: {buf:?}");
    // SAFETY: closing the test-owned pipe fds (the server only borrowed the
    // write end; nothing read the read end).
    unsafe {
        libc::close(pipe_rd);
        libc::close(pipe_wr);
    }
}

#[test]
fn tcp_splice_body_close_mid_poll() {
    // Teardown while a splice is parked on its readiness POLL. A body splice off
    // the non-blocking pool socket returns `-EAGAIN` when the socket is drained
    // mid-body; the server then waits for `POLLIN` before resubmitting. Here the
    // client sends a data-frame header but NO body, so the first splice EAGAINs
    // and parks on the poll indefinitely. As with an in-flight splice, a graceful
    // drain leaves the parked poll alone (`splice_polling` reads as in-flight
    // work); the grace Deadline escalation then reaps it. This proves escalation
    // doesn't hang on a parked splice poll — `serve_forever` returns promptly.
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: `pipe(2)` fills {read, write}.
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe");
    let (pipe_rd, pipe_wr) = (fds[0], fds[1]);

    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: splice_header(pipe_wr),
        body: |req: Request<'_, ()>| Response::Reply(echo_frame(&req.body)),
    };
    let mut server = match Server::bind([addr], proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => {
            // SAFETY: closing the test-owned pipe fds on the skip path.
            unsafe {
                libc::close(pipe_rd);
                libc::close(pipe_wr);
            }
            return;
        }
        Err(e) => panic!("bind: {e}"),
    };
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();

    let client = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone()); // fail fast on panic
        (|| -> io::Result<TcpStream> {
            let mut s = connect_tcp(v4)?;
            // Header only, declaring an 8 MiB body: the splice arms, finds the
            // socket empty, EAGAINs, and parks on the readiness poll.
            let mut hdr = vec![b'S'];
            hdr.extend_from_slice(&(8u32 * 1024 * 1024).to_be_bytes());
            s.write_all(&hdr)?;
            thread::sleep(Duration::from_millis(150)); // let it reach the poll
            stop.shutdown_graceful(Duration::from_millis(300));
            Ok(s) // abandoned; EOF at server drop
        })()
        .expect("client io")
    });

    let t0 = Instant::now();
    server.serve_forever().expect("serve_forever");
    assert!(
        t0.elapsed() < Duration::from_secs(3),
        "escalation hung on a parked splice poll: {:?}",
        t0.elapsed()
    );
    let mut s = client.join().expect("client join");
    drop(server);
    let mut buf = Vec::new();
    let n = s.read_to_end(&mut buf).unwrap_or(buf.len());
    assert_eq!(n, 0, "unexpected data after abandon: {buf:?}");
    // SAFETY: closing the test-owned pipe fds.
    unsafe {
        libc::close(pipe_rd);
        libc::close(pipe_wr);
    }
}

#[test]
fn tcp_splice_body_request_timeout_reclaims_stall() {
    // SECURITY (slow-loris, splice path): a peer that sends a `SpliceBody` header
    // then withholds the body must not pin its slot. The body splice EAGAINs on
    // the drained non-blocking socket and parks on its readiness poll;
    // `request_timeout` bounds that poll exactly like a body recv, so the stalled
    // slot is reclaimed. (Without the bound the poll would wait forever.)
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: `pipe(2)` fills {read, write}.
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe");
    let (pipe_rd, pipe_wr) = (fds[0], fds[1]);
    let cfg = ServerConfig {
        request_timeout: Some(Duration::from_millis(200)),
        ..ServerConfig::default()
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: splice_header(pipe_wr),
        body: |req: Request<'_, ()>| Response::Reply(echo_frame(&req.body)),
    };
    let mut server = match Server::with_config([addr], cfg, proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => {
            // SAFETY: closing the test-owned pipe fds on the skip path.
            unsafe {
                libc::close(pipe_rd);
                libc::close(pipe_wr);
            }
            return;
        }
        Err(e) => panic!("bind: {e}"),
    };
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();

    let client = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone());
        let r = (|| -> io::Result<()> {
            // A SpliceBody header declaring an 8 MiB body, then stall: the splice
            // parks on its readiness poll and request_timeout reclaims the slot.
            let mut stall = connect_tcp(v4)?;
            let mut hdr = vec![b'S'];
            hdr.extend_from_slice(&(8u32 * 1024 * 1024).to_be_bytes());
            stall.write_all(&hdr)?;
            expect_idle_close(&mut stall)?; // prompt server close (< 2s)
            Ok(())
        })();
        stop.shutdown();
        r
    });

    server.serve_forever().expect("serve_forever");
    client.join().expect("thread join").expect("client io");
    // SAFETY: closing the test-owned pipe fds.
    unsafe {
        libc::close(pipe_rd);
        libc::close(pipe_wr);
    }
}

#[test]
fn tcp_graceful_drain_lets_healthy_splice_finish() {
    // `shutdown_graceful`'s contract: work in flight runs to completion
    // within the grace. A body mid-splice IS in-flight work even though
    // `recving` is false — the drain sweep must not classify it quiesced and
    // cancel it (that silently truncates the body in the consumer's pipe).
    // Regression test: begin a drain while a splice is parked on its
    // readiness poll mid-body, then let the client finish; the FULL body must
    // reach the pipe, and the connection closes only after it does.
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: `pipe(2)` fills {read, write}.
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe");
    let (pipe_rd, pipe_wr) = (fds[0], fds[1]);
    // Half a default pipe: the whole body fits unread, so nothing wedges.
    const BODY: usize = 32 * 1024;

    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: splice_header(pipe_wr),
        body: |req: Request<'_, ()>| Response::Reply(echo_frame(&req.body)),
    };
    let mut server = match Server::bind([addr], proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => {
            // SAFETY: closing the test-owned pipe fds on the skip path.
            unsafe {
                libc::close(pipe_rd);
                libc::close(pipe_wr);
            }
            return;
        }
        Err(e) => panic!("bind: {e}"),
    };
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();

    let payload: Vec<u8> = (0..BODY).map(|i| (i % 251) as u8).collect();
    let sent = payload.clone();
    let client = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone());
        let r = (|| -> io::Result<()> {
            let mut s = connect_tcp(v4)?;
            // Header + first half: the splice moves what arrived, then parks
            // on its readiness poll mid-body (`splice_polling`).
            let mut first = vec![b'S'];
            first.extend_from_slice(&(BODY as u32).to_be_bytes());
            first.extend_from_slice(&sent[..BODY / 2]);
            s.write_all(&first)?;
            thread::sleep(Duration::from_millis(150)); // reach the poll

            let t0 = Instant::now();
            stop.shutdown_graceful(Duration::from_secs(5));
            thread::sleep(Duration::from_millis(100)); // let the sweep run
            s.write_all(&sent[BODY / 2..])?; // finish the transfer

            // The body completes and only THEN does the drain close us —
            // well inside the grace (no Deadline escalation involved).
            let mut buf = Vec::new();
            s.read_to_end(&mut buf)?;
            assert!(
                t0.elapsed() < Duration::from_secs(3),
                "drain close took {:?}",
                t0.elapsed()
            );
            Ok(())
        })();
        stop.shutdown();
        r
    });

    server.serve_forever().expect("serve_forever");
    client.join().expect("client join").expect("client io");
    // EOF the pipe, then read it all back: the drain must not have truncated
    // the spliced body.
    // SAFETY: closing the test-owned write end (the server only borrowed it).
    unsafe { libc::close(pipe_wr) };
    let mut got = Vec::new();
    // SAFETY: `pipe_rd` is a live blocking fd owned by this test.
    let mut rd = unsafe { std::fs::File::from_raw_fd(pipe_rd) };
    rd.read_to_end(&mut got).expect("pipe read");
    assert_eq!(got.len(), BODY, "drain truncated a healthy splice");
    assert_eq!(got, payload, "spliced body corrupted");
}

#[test]
fn tcp_splice_body_nonblocking_pipe_rejected() {
    // A NON-BLOCKING destination breaks the splice path's contract two ways:
    // `do_splice` promotes the output fd's O_NONBLOCK to SPLICE_F_NONBLOCK,
    // so a full pipe fails the splice with EAGAIN before the socket is read —
    // indistinguishable from "socket empty", which would spin the readiness
    // poll hot (POLLIN completes instantly, splice EAGAINs again) — and the
    // designed blocking-pipe backpressure never engages. The server refuses
    // the fd at body start: `CloseReason::SpliceBadFd`, kernel never sees it.
    use std::sync::Mutex;
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: `pipe(2)` fills {read, write}.
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe");
    let (pipe_rd, pipe_wr) = (fds[0], fds[1]);
    // SAFETY: flag the write end non-blocking — the misuse under test.
    unsafe {
        let fl = libc::fcntl(pipe_wr, libc::F_GETFL);
        libc::fcntl(pipe_wr, libc::F_SETFL, fl | libc::O_NONBLOCK);
    }

    let reasons = Arc::new(Mutex::new(Vec::new()));
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: splice_header(pipe_wr),
        body: |req: Request<'_, ()>| Response::Reply(echo_frame(&req.body)),
    };
    let mut server = match Server::bind([addr], proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => {
            // SAFETY: closing the test-owned pipe fds on the skip path.
            unsafe {
                libc::close(pipe_rd);
                libc::close(pipe_wr);
            }
            return;
        }
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
            splice_frame(&mut s, b'S', &[0xCD; 1024])?;
            // Rejected at body start: prompt close, nothing spliced.
            let t0 = Instant::now();
            let mut buf = Vec::new();
            s.read_to_end(&mut buf)?;
            assert!(buf.is_empty(), "unexpected reply bytes");
            assert!(
                t0.elapsed() < Duration::from_secs(2),
                "rejection close took {:?}",
                t0.elapsed()
            );
            Ok(())
        })();
        stop.shutdown();
        r
    });

    server.serve_forever().expect("serve_forever");
    client.join().expect("client join").expect("client io");
    assert_eq!(
        reasons.lock().unwrap().as_slice(),
        &[CloseReason::SpliceBadFd],
        "expected the non-blocking pipe to be refused at body start"
    );
    // SAFETY: closing the test-owned pipe fds (nothing was spliced).
    unsafe {
        libc::close(pipe_rd);
        libc::close(pipe_wr);
    }
}

#[test]
fn tcp_send_timeout_reclaims_slot() {
    // A peer that requests a huge reply and then never reads it parks a
    // MSG_WAITALL send forever (TCP zero-window probing never gives up). With
    // `send_timeout`, the linked timeout cancels the stalled send and the
    // connection's pool slot is reclaimed — proven with pool_size=1: a second
    // client can only ever be served if the first slot was actually freed.
    const BIG: usize = 8 * 1024 * 1024; // far beyond the socket send buffer
    let cfg = ServerConfig {
        pool_size: 1,
        send_timeout: Some(Duration::from_millis(200)),
        ..ServerConfig::default()
    };
    let proto = length_prefixed(
        PrefixWidth::U32,
        Endian::Big,
        false,
        |_h: &[u8], body: &[u8], _p: &ClientAddr| {
            if body == b"big" {
                Some(echo_frame(&vec![0xAB; BIG]))
            } else {
                Some(echo_frame(body))
            }
        },
    );
    let mut server = match Server::with_config(
        [ServerAddr::Tcp(
            "127.0.0.1:0".parse::<SocketAddrV4>().unwrap(),
        )],
        cfg,
        proto,
    ) {
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
        let r = (|| -> io::Result<Vec<u8>> {
            // Stalled reader: request the big reply, never read a byte, and
            // keep the socket open so only the send timeout can free the slot.
            let mut stalled = connect_tcp(v4)?;
            send_framed(&mut stalled, b"big")?;
            thread::sleep(Duration::from_millis(600)); // > send_timeout

            // The slot must now be free; a fresh client gets served. Retry a
            // few times in case the pool is momentarily mid-teardown (a shed
            // connection sees accept-then-close).
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                let attempt = (|| -> io::Result<Vec<u8>> {
                    let mut s = connect_tcp(v4)?;
                    send_framed(&mut s, b"ping")?;
                    recv_framed(&mut s)
                })();
                match attempt {
                    Ok(v) => return Ok(v),
                    Err(e) if Instant::now() >= deadline => return Err(e),
                    Err(_) => thread::sleep(Duration::from_millis(50)),
                }
            }
        })();
        stop.shutdown();
        r
    });

    server.serve_forever().expect("serve_forever");
    let pong = client.join().expect("thread join").expect("client io");
    assert_eq!(pong, b"ping");
}

#[test]
fn tcp_one_way_notification() {
    // `Response::Reply(empty)` means "answered, nothing to send" — a one-way
    // message. The connection stays open and the next request is served.
    // Full Protocol here; `tcp_builder_close_and_one_way` covers the same
    // contract through the `length_prefixed` builder (`Some(empty)` one-way,
    // `None` close).
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(
            PrefixWidth::U32,
            Endian::Big,
            false,
        ),
        body: |req: Request<'_, ()>| {
            let Request { body, .. } = req;
            if &body[..] == b"notify" {
                Response::Reply(Vec::new()) // one-way: no bytes sent
            } else {
                Response::Reply(echo_frame(&body))
            }
        },
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
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
        let _stop = ShutdownOnDrop(stop.clone()); // fail fast on panic
        let r = (|| -> io::Result<Vec<u8>> {
            let mut s = connect_tcp(v4)?;
            send_framed(&mut s, b"notify")?; // no reply expected
            send_framed(&mut s, b"ping")?;
            recv_framed(&mut s) // must be the ping echo, not a close
        })();
        stop.shutdown();
        r
    });

    server.serve_forever().expect("serve_forever");
    let got = client.join().expect("thread join").expect("client io");
    assert_eq!(got, b"ping");
}

#[test]
fn tcp_builder_close_and_one_way() {
    // The `length_prefixed` builder's Option contract: `Some(empty)` is the
    // one-way case (sends nothing, keeps serving — same as Response::Reply's
    // documented empty semantics), `None` is the close signal.
    use std::sync::Mutex;
    let reasons = Arc::new(Mutex::new(Vec::new()));
    let proto = length_prefixed(
        PrefixWidth::U32,
        Endian::Big,
        false,
        |_h: &[u8], body: &[u8], _p: &ClientAddr| match body {
            b"notify" => Some(Vec::new()), // one-way: no bytes sent
            b"quit" => None,               // close signal
            _ => Some(echo_frame(body)),
        },
    );
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let mut server = match Server::bind([addr], proto) {
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
        let _stop = ShutdownOnDrop(stop.clone()); // fail fast on panic
        (|| -> io::Result<()> {
            let mut s = connect_tcp(v4)?;
            send_framed(&mut s, b"notify")?; // no reply expected
            send_framed(&mut s, b"ping")?;
            assert_eq!(recv_framed(&mut s)?, b"ping", "served past one-way");
            send_framed(&mut s, b"quit")?;
            let mut b = [0u8; 1];
            assert_eq!(s.read(&mut b)?, 0, "None must close");
            Ok(())
        })()
        .expect("client io");
        stop.shutdown();
    });

    server.serve_forever().expect("serve_forever");
    client.join().expect("thread join");
    let got = reasons.lock().unwrap().clone();
    assert!(
        got.contains(&CloseReason::HandlerClosed),
        "expected HandlerClosed from None, got {got:?}"
    );
}

#[test]
fn tcp_length_prefix_overflow_rejected() {
    // A u64 length prefix of !0 once wrapped the header+body usize total past
    // the TooLarge guard (release) or panicked the loop on the add (debug) —
    // a remote crash from one 8-byte message. It must instead close that
    // connection as TooLarge and keep serving others.
    use std::sync::Mutex;
    let reasons = Arc::new(Mutex::new(Vec::new()));
    let proto = length_prefixed(PrefixWidth::U64, Endian::Big, false, echo);
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let mut server = match Server::bind([addr], proto) {
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
        let _stop = ShutdownOnDrop(stop.clone()); // fail fast on panic
        let r = (|| -> io::Result<Vec<u8>> {
            let mut s = connect_tcp(v4)?;
            s.write_all(&u64::MAX.to_be_bytes())?;
            // The server must close this connection (TooLarge), not crash.
            let mut b = [0u8; 1];
            assert_eq!(s.read(&mut b)?, 0, "expected EOF after bogus prefix");
            // ...and still serve a fresh connection (8-byte U64 framing in,
            // `echo`'s 4-byte framing back).
            let mut ok = connect_tcp(v4)?;
            ok.write_all(&4u64.to_be_bytes())?;
            ok.write_all(b"ping")?;
            recv_framed(&mut ok)
        })();
        stop.shutdown();
        r
    });

    server.serve_forever().expect("serve_forever");
    let got = client.join().expect("thread join").expect("client io");
    assert_eq!(got, b"ping");
    let reasons = reasons.lock().unwrap().clone();
    assert!(
        reasons.contains(&CloseReason::TooLarge),
        "expected TooLarge, got {reasons:?}"
    );
}

#[test]
fn tcp_need_overflow_rejected() {
    // A custom framer that echoes a hostile wire length as `Framing::Need(n)`
    // (the LSP pattern with an unvalidated Content-Length): the server must
    // bound the requested read against max_request_bytes up front — both the
    // overflowing and the merely-huge shape — not allocate n bytes.
    use std::sync::Mutex;
    let reasons = Arc::new(Mutex::new(Vec::new()));
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: |buf: &[u8], _state: &mut ()| match buf.first() {
            None => Framing::Need(1),
            Some(b'o') => Framing::Need(usize::MAX), // overflows buffered + n
            Some(_) => Framing::Need(1024 * 1024),   // buffered + n > max
        },
        body: |req: Request<'_, ()>| Response::Reply(echo_frame(&req.body)),
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let mut server = match Server::bind([addr], proto) {
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
        let _stop = ShutdownOnDrop(stop.clone()); // fail fast on panic
        (|| -> io::Result<()> {
            for first_byte in [b"o", b"b"] {
                let mut s = connect_tcp(v4)?;
                s.write_all(first_byte)?;
                let mut b = [0u8; 1];
                assert_eq!(
                    s.read(&mut b)?,
                    0,
                    "expected EOF after hostile Need"
                );
            }
            Ok(())
        })()
        .expect("client io");
        stop.shutdown();
    });

    server.serve_forever().expect("serve_forever");
    client.join().expect("thread join");
    let got = reasons.lock().unwrap().clone();
    assert_eq!(
        got.iter().filter(|r| **r == CloseReason::TooLarge).count(),
        2,
        "expected both hostile Needs to close TooLarge, got {got:?}"
    );
}

#[test]
fn tcp_stale_deferred_dropped() {
    // A handler that mints a Deferred but then answers inline: the worker's
    // late reply is for a request that was already answered, so it must be
    // dropped (per-request token gating) — not sent as a spurious extra PDU,
    // and its Drop-close must not kill the healthy connection.
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(
            PrefixWidth::U32,
            Endian::Big,
            false,
        ),
        body: |req: Request<'_, ()>| {
            let Request { responder, .. } = req;
            let (deferred, _permit) = responder.defer();
            thread::spawn(move || {
                thread::sleep(Duration::from_millis(30));
                deferred.reply(echo_frame(b"late")); // must be dropped
            });
            // Answer inline anyway — the Deferred above is now stale.
            Response::Reply(echo_frame(b"inline"))
        },
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
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
        let _stop = ShutdownOnDrop(stop.clone()); // fail fast on panic
        let r = (|| -> io::Result<(Vec<u8>, Vec<u8>)> {
            let mut s = connect_tcp(v4)?;
            send_framed(&mut s, b"one")?;
            let first = recv_framed(&mut s)?;
            // Give the stale worker reply time to arrive (and be dropped).
            thread::sleep(Duration::from_millis(80));
            send_framed(&mut s, b"two")?;
            let second = recv_framed(&mut s)?;
            Ok((first, second))
        })();
        stop.shutdown();
        r
    });

    server.serve_forever().expect("serve_forever");
    let (first, second) = client.join().expect("thread join").expect("io");
    assert_eq!(first, b"inline");
    // If the stale reply had been enqueued, this would read "late".
    assert_eq!(second, b"inline");
}

#[test]
fn tcp_mismatched_defer_permit_closes() {
    // A DeferPermit is stamped with its request's token and verified at
    // delivery: stashing one and returning it for a LATER request (whose own
    // defer() was never called) must close the connection — not park a
    // request nothing can ever resolve, wedging the slot until shutdown.
    use std::sync::Mutex;
    let reasons = Arc::new(Mutex::new(Vec::new()));
    struct Stash {
        pair: Option<(Deferred, DeferPermit)>,
    }
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(Stash { pair: None }),
        header: length_prefix_header::<Stash>(
            PrefixWidth::U32,
            Endian::Big,
            false,
        ),
        body: |req: Request<'_, Stash>| {
            let Request {
                body,
                state,
                responder,
                ..
            } = req;
            if &body[..] == b"mint" {
                // Mint and stash the pair, then answer inline. Keeping the
                // Deferred in the stash keeps its Drop-close from firing;
                // it goes stale the moment this Reply answers the request.
                state.pair = Some(responder.defer());
                Response::Reply(echo_frame(b"ok"))
            } else {
                let (deferred, stale_permit) = state.pair.take().unwrap();
                drop(deferred); // stale token: its Drop-close is inert
                Response::Defer(stale_permit) // wrong request's permit
            }
        },
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let mut server = match Server::bind([addr], proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind: {e}"),
    };
    {
        let reasons = Arc::clone(&reasons);
        server.set_close_hook(move |_addr, reason, _state: &mut Stash| {
            reasons.lock().unwrap().push(reason);
        });
    }
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();

    let client = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone()); // fail fast on panic
        (|| -> io::Result<()> {
            let mut s = connect_tcp(v4)?;
            // Bound the read: a wedged (parked-forever) connection must fail
            // the test, not hang it.
            s.set_read_timeout(Some(Duration::from_secs(5)))?;
            send_framed(&mut s, b"mint")?;
            assert_eq!(recv_framed(&mut s)?, b"ok");
            send_framed(&mut s, b"boom")?;
            let mut b = [0u8; 1];
            assert_eq!(
                s.read(&mut b)?,
                0,
                "expected close on mismatched permit"
            );
            Ok(())
        })()
        .expect("client io");
        stop.shutdown();
    });

    server.serve_forever().expect("serve_forever");
    client.join().expect("thread join");
    let got = reasons.lock().unwrap().clone();
    assert!(
        got.contains(&CloseReason::HandlerClosed),
        "expected HandlerClosed, got {got:?}"
    );
}

#[test]
fn tcp_reuse_port_and_options() {
    // SO_REUSEPORT: a second server binds the same address iff both set the
    // flag (otherwise EADDRINUSE). Also smoke-tests the other socket options
    // (nodelay is default-on; keepalive + TCP_USER_TIMEOUT set here).
    let cfg = ServerConfig {
        reuse_port: true,
        keepalive: Some(Duration::from_secs(30)),
        tcp_user_timeout: Some(Duration::from_secs(10)),
        ..ServerConfig::default()
    };
    let proto = || length_prefixed(PrefixWidth::U32, Endian::Big, false, echo);
    let mut server = match Server::with_config(
        [ServerAddr::Tcp(
            "127.0.0.1:0".parse::<SocketAddrV4>().unwrap(),
        )],
        cfg,
        proto(),
    ) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind: {e}"),
    };
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };

    // Second bind to the SAME port must succeed with reuse_port...
    let second = Server::with_config([ServerAddr::Tcp(v4)], cfg, proto());
    assert!(second.is_ok(), "reuse_port second bind: {second:?}");
    // ...and is dropped before any client connects, so the kernel cannot have
    // routed our test connection into its (never-served) backlog.
    drop(second);

    // Without the flag the same bind fails with EADDRINUSE.
    let dup = Server::bind(
        [ServerAddr::Tcp(v4)],
        length_prefixed(PrefixWidth::U32, Endian::Big, false, echo),
    );
    assert!(
        matches!(dup, Err(Error::Errno(Errno::EADDRINUSE))),
        "expected EADDRINUSE, got {dup:?}"
    );

    let stop = server.shutdown_handle();
    let client = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone()); // fail fast on panic
        let r = connect_tcp(v4)
            .and_then(|s| framed_roundtrips(s, &[b"opts" as &[u8]]));
        stop.shutdown();
        r
    });
    server.serve_forever().expect("serve_forever");
    let echoes = client.join().expect("thread join").expect("client io");
    assert_eq!(echoes, vec![b"opts".to_vec()]);
}

#[test]
fn unix_peercred_auth() {
    // With `unix_peercred`, the accept handler receives the peer's SO_PEERCRED
    // (fetched via an io_uring socket URING_CMD — Linux ≥ 6.7; this host is
    // newer) before running, and can authenticate on it. The body echoes the
    // credentials back and the client checks them against its real ids.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cred.sock");
    let cfg = ServerConfig {
        unix_peercred: true,
        ..ServerConfig::default()
    };
    let proto = Protocol {
        // Authenticate: only our own uid gets in; keep the creds as state.
        accept: |inc: Incoming<'_>| match inc.peer {
            ClientAddr::Unix { cred: Some(c) } => Some(*c),
            _ => None,
        },
        header: length_prefix_header::<PeerCred>(
            PrefixWidth::U32,
            Endian::Big,
            false,
        ),
        body: |req: Request<'_, PeerCred>| {
            let Request { state: cred, .. } = req;
            Response::Reply(echo_frame(
                format!("{}:{}:{}", cred.pid, cred.uid, cred.gid).as_bytes(),
            ))
        },
    };
    let mut server =
        match Server::with_config([ServerAddr::Unix(path.clone())], cfg, proto)
        {
            Ok(s) => s,
            Err(e) if should_skip(&e) || peercred_unsupported(&e) => return,
            Err(e) => panic!("bind: {e}"),
        };
    let stop = server.shutdown_handle();

    let client = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone()); // fail fast on panic
        let r = connect_unix(&path).and_then(|mut s| {
            send_framed(&mut s, b"who am i")?;
            recv_framed(&mut s)
        });
        stop.shutdown();
        r
    });

    server.serve_forever().expect("serve_forever");
    let reply = client.join().expect("thread join").expect("client io");
    let text = String::from_utf8(reply).expect("utf8");
    let mut parts = text.split(':');
    let pid: i32 = parts.next().unwrap().parse().unwrap();
    let uid: u32 = parts.next().unwrap().parse().unwrap();
    let gid: u32 = parts.next().unwrap().parse().unwrap();
    // SAFETY: getuid/getgid/getpid are trivially safe.
    unsafe {
        assert_eq!(pid, libc::getpid(), "peer pid");
        assert_eq!(uid, libc::getuid(), "peer uid");
        assert_eq!(gid, libc::getgid(), "peer gid");
    }
}

#[test]
fn tcp_push_pub_sub() {
    // Server push: a subscriber stashes its PushHandle via the "sub" request; a
    // publisher's "pub" request pushes an unsolicited PDU to the subscriber.
    // After the subscriber disconnects, further pushes are dropped harmlessly
    // and the publisher's connection keeps working.
    use std::sync::Mutex;
    let sub_handle: Arc<Mutex<Option<PushHandle>>> = Arc::new(Mutex::new(None));
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(
            PrefixWidth::U32,
            Endian::Big,
            false,
        ),
        body: {
            let sub_handle = Arc::clone(&sub_handle);
            move |req: Request<'_, ()>| {
                let Request {
                    body, responder, ..
                } = req;
                if &body[..] == b"sub" {
                    *sub_handle.lock().unwrap() = Some(responder.push_handle());
                    Response::Reply(echo_frame(b"subscribed"))
                } else if let Some(msg) = body.strip_prefix(b"pub:") {
                    if let Some(h) = sub_handle.lock().unwrap().as_ref() {
                        h.push(echo_frame(msg)); // unsolicited PDU to the sub
                    }
                    Response::Reply(echo_frame(b"published"))
                } else {
                    Response::Reply(echo_frame(&body))
                }
            }
        },
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
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
        let _stop = ShutdownOnDrop(stop.clone()); // fail fast on panic
        (|| -> io::Result<()> {
            let mut sub = connect_tcp(v4)?;
            send_framed(&mut sub, b"sub")?;
            assert_eq!(recv_framed(&mut sub)?, b"subscribed");

            let mut publisher = connect_tcp(v4)?;
            send_framed(&mut publisher, b"pub:event-1")?;
            assert_eq!(recv_framed(&mut publisher)?, b"published");
            // The unsolicited push arrives on the subscriber's connection.
            assert_eq!(recv_framed(&mut sub)?, b"event-1");

            // Subscriber leaves; a push to the dead connection is dropped and
            // the publisher keeps working.
            drop(sub);
            thread::sleep(Duration::from_millis(50)); // let the close land
            send_framed(&mut publisher, b"pub:event-2")?;
            assert_eq!(recv_framed(&mut publisher)?, b"published");
            send_framed(&mut publisher, b"ping")?;
            assert_eq!(recv_framed(&mut publisher)?, b"ping");
            Ok(())
        })()
        .expect("client io");
        stop.shutdown();
    });

    server.serve_forever().expect("serve_forever");
    client.join().expect("thread join");
}

#[test]
fn tcp_push_backlog_evicts() {
    // A subscriber that stops reading: pushes accumulate until
    // max_send_backlog, then the connection is evicted with SendBacklog.
    use std::sync::Mutex;
    // Each push must exceed what the kernel alone can absorb — sndbuf
    // autotunes up to tcp_wmem[2] (typically 4 MiB) plus the peer's ~128 KiB
    // initial window — because a fully-absorbed WAITALL send completes and
    // leaves the library queue empty. At 32 MiB the first push is still
    // (partially) queued when the second arrives (`queued_bytes` counts the
    // whole front PDU until fully sent), so the second deterministically
    // overflows the cap.
    const PUSH: usize = 32 * 1024 * 1024;
    let sub_handle: Arc<Mutex<Option<PushHandle>>> = Arc::new(Mutex::new(None));
    let reasons = Arc::new(Mutex::new(Vec::new()));
    let cfg = ServerConfig {
        max_send_backlog: PUSH + PUSH / 2, // between one and two pushes
        ..ServerConfig::default()
    };
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(
            PrefixWidth::U32,
            Endian::Big,
            false,
        ),
        body: {
            let sub_handle = Arc::clone(&sub_handle);
            move |req: Request<'_, ()>| {
                let Request {
                    body, responder, ..
                } = req;
                if &body[..] == b"sub" {
                    *sub_handle.lock().unwrap() = Some(responder.push_handle());
                    Response::Reply(echo_frame(b"ok"))
                } else if &body[..] == b"push" {
                    if let Some(h) = sub_handle.lock().unwrap().as_ref() {
                        h.push(echo_frame(&vec![0x55; PUSH]));
                    }
                    Response::Reply(echo_frame(b"ok"))
                } else {
                    Response::Reply(echo_frame(&body))
                }
            }
        },
    };
    let mut server = match Server::with_config(
        [ServerAddr::Tcp(
            "127.0.0.1:0".parse::<SocketAddrV4>().unwrap(),
        )],
        cfg,
        proto,
    ) {
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
        let _stop = ShutdownOnDrop(stop.clone()); // fail fast on panic
        (|| -> io::Result<()> {
            let mut sub = connect_tcp(v4)?;
            send_framed(&mut sub, b"sub")?;
            assert_eq!(recv_framed(&mut sub)?, b"ok");
            // The subscriber now goes silent (never reads its socket).

            let mut publisher = connect_tcp(v4)?;
            // First push: queued, stalls mid-send (subscriber not reading).
            send_framed(&mut publisher, b"push")?;
            assert_eq!(recv_framed(&mut publisher)?, b"ok");
            thread::sleep(Duration::from_millis(50)); // let it stall
                                                      // Second push: queued bytes would exceed the backlog cap → evict.
            send_framed(&mut publisher, b"push")?;
            assert_eq!(recv_framed(&mut publisher)?, b"ok");
            thread::sleep(Duration::from_millis(100)); // let eviction land
            Ok(())
        })()
        .expect("client io");
        stop.shutdown();
    });

    server.serve_forever().expect("serve_forever");
    client.join().expect("thread join");
    let got = reasons.lock().unwrap().clone();
    assert!(
        got.contains(&CloseReason::SendBacklog),
        "expected SendBacklog eviction, got {got:?}"
    );
}

#[test]
fn tcp_push_held_across_detach() {
    // PushHandle's contract is "usable for the connection's lifetime". While
    // the connection is DETACHED its raw stream belongs to the worker — a
    // push must neither write mid-detach (corrupting the worker's transfer)
    // nor be silently dropped: it queues against the parked connection and
    // flushes, FIFO, when the worker resumes it.
    use std::sync::mpsc;
    use std::sync::Mutex;
    let push_slot: Arc<Mutex<Option<PushHandle>>> = Arc::new(Mutex::new(None));
    let (parked_tx, parked_rx) = mpsc::channel::<()>();
    let (resume_tx, resume_rx) = mpsc::channel::<()>();
    let resume_rx = Arc::new(Mutex::new(Some(resume_rx)));

    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let stash = Arc::clone(&push_slot);
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(
            PrefixWidth::U32,
            Endian::Big,
            false,
        ),
        body: move |req: Request<'_, ()>| match &req.body[..] {
            b"sub" => {
                *stash.lock().unwrap() = Some(req.responder.push_handle());
                Response::Reply(echo_frame(b"ok"))
            }
            b"detach" => Response::Detach(req.responder.detach()),
            other => Response::Reply(echo_frame(other)),
        },
    };
    let mut server = match Server::bind([addr], proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind: {e}"),
    };
    {
        let resume_rx = Arc::clone(&resume_rx);
        server.set_detach_handler(move |_ctx, detached| {
            let parked_tx = parked_tx.clone();
            let rx = resume_rx.lock().unwrap().take().expect("one detach");
            thread::spawn(move || {
                parked_tx.send(()).expect("parked signal");
                rx.recv().expect("resume signal"); // hold the detach open
                detached.resume();
            });
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
            send_framed(&mut s, b"sub")?;
            assert_eq!(recv_framed(&mut s)?, b"ok");
            send_framed(&mut s, b"detach")?;
            parked_rx.recv().expect("parked");
            // The connection is parked with a worker: push now. These must be
            // HELD (not written — the worker owns the stream — and not
            // dropped), then flushed in order at resume.
            let push =
                push_slot.lock().unwrap().clone().expect("stashed handle");
            for i in 0..3u8 {
                push.push(echo_frame(format!("evt{i}").as_bytes()));
            }
            // Let the loop drain the injections while still parked (a drop
            // would happen here, silently).
            thread::sleep(Duration::from_millis(150));
            resume_tx.send(()).expect("resume signal");
            for i in 0..3u8 {
                assert_eq!(
                    recv_framed(&mut s)?,
                    format!("evt{i}").into_bytes(),
                    "push {i} lost or reordered across the detach"
                );
            }
            // And ordinary serving resumed after the flush.
            send_framed(&mut s, b"bye")?;
            assert_eq!(recv_framed(&mut s)?, b"bye");
            Ok(())
        })();
        stop.shutdown();
        r
    });

    server.serve_forever().expect("serve_forever");
    client.join().expect("thread join").expect("client io");
}

#[test]
fn tcp_reply_close_replies_then_closes() {
    // `Response::ReplyClose`: the server speaks last. The client gets the
    // reply and then EOF — no idle-timeout wait, no relying on the peer to
    // hang up (RFC 6455 §5.5.1-style close handshakes need exactly this).
    // A second request pipelined behind the first is discarded undelivered:
    // the farewell retires the recv side.
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;
    let delivered = Arc::new(AtomicUsize::new(0));
    let reasons = Arc::new(Mutex::new(Vec::new()));
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(
            PrefixWidth::U32,
            Endian::Big,
            false,
        ),
        body: {
            let delivered = Arc::clone(&delivered);
            move |req: Request<'_, ()>| {
                delivered.fetch_add(1, Ordering::SeqCst);
                Response::ReplyClose(echo_frame(&req.body))
            }
        },
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let mut server = match Server::bind([addr], proto) {
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
            // Two requests in one write: only the first is served — the
            // farewell is final.
            let mut wire = Vec::new();
            send_framed(&mut wire, b"bye")?;
            send_framed(&mut wire, b"ignored")?;
            s.write_all(&wire)?;
            assert_eq!(recv_framed(&mut s)?, b"bye");
            let t0 = Instant::now();
            let mut rest = Vec::new();
            s.read_to_end(&mut rest)?;
            assert!(rest.is_empty(), "bytes after the farewell: {rest:?}");
            assert!(
                t0.elapsed() < Duration::from_secs(2),
                "close after the farewell took {:?} (idle-wait, not flush)",
                t0.elapsed()
            );
            Ok(())
        })();
        stop.shutdown();
        r
    });

    server.serve_forever().expect("serve_forever");
    client.join().expect("thread join").expect("client io");
    assert_eq!(delivered.load(Ordering::SeqCst), 1, "pipelined 2nd request");
    assert_eq!(
        reasons.lock().unwrap().as_slice(),
        &[CloseReason::HandlerClosed],
    );
}

#[test]
fn tcp_deferred_reply_close() {
    // `Deferred::reply_close`: the worker speaks last — its final PDU is
    // sent, then the connection closes (WorkerClosed), exactly like the
    // inline `Response::ReplyClose` but from another thread.
    use std::sync::Mutex;
    let reasons = Arc::new(Mutex::new(Vec::new()));
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(
            PrefixWidth::U32,
            Endian::Big,
            false,
        ),
        body: move |req: Request<'_, ()>| {
            let input = req.body.to_vec();
            let (deferred, permit) = req.responder.defer();
            thread::spawn(move || {
                deferred.reply_close(echo_frame(&input.to_ascii_uppercase()));
            });
            Response::Defer(permit)
        },
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let mut server = match Server::bind([addr], proto) {
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
            send_framed(&mut s, b"bye")?;
            assert_eq!(recv_framed(&mut s)?, b"BYE");
            let mut rest = Vec::new();
            s.read_to_end(&mut rest)?;
            assert!(rest.is_empty(), "bytes after the farewell: {rest:?}");
            Ok(())
        })();
        stop.shutdown();
        r
    });

    server.serve_forever().expect("serve_forever");
    client.join().expect("thread join").expect("client io");
    assert_eq!(
        reasons.lock().unwrap().as_slice(),
        &[CloseReason::WorkerClosed],
    );
}

#[test]
fn tcp_deferred_reply_close_empty_flushes_queued() {
    // An EMPTY `reply_close` queues no PDU of its own but still flushes
    // whatever is already queued before closing — here a push the worker
    // issued just before it (both ride the same FIFO injection queue, so
    // the order is deterministic). `Response::Close` would drop that push.
    use std::sync::Mutex;
    let reasons = Arc::new(Mutex::new(Vec::new()));
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(
            PrefixWidth::U32,
            Endian::Big,
            false,
        ),
        body: move |req: Request<'_, ()>| {
            let push = req.responder.push_handle();
            let (deferred, permit) = req.responder.defer();
            thread::spawn(move || {
                push.push(echo_frame(b"last-words"));
                deferred.reply_close(Vec::new());
            });
            Response::Defer(permit)
        },
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let mut server = match Server::bind([addr], proto) {
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
            send_framed(&mut s, b"go")?;
            assert_eq!(recv_framed(&mut s)?, b"last-words");
            let mut rest = Vec::new();
            s.read_to_end(&mut rest)?;
            assert!(rest.is_empty(), "bytes after the flush: {rest:?}");
            Ok(())
        })();
        stop.shutdown();
        r
    });

    server.serve_forever().expect("serve_forever");
    client.join().expect("thread join").expect("client io");
    assert_eq!(
        reasons.lock().unwrap().as_slice(),
        &[CloseReason::WorkerClosed],
    );
}

#[test]
fn tcp_push_close_kicks_subscriber() {
    // `PushHandle::close`: a connection is ended from outside its own
    // request cycle (session revocation / admin kick). A farewell pushed
    // just before the close flushes first; a push after it is dropped
    // (nothing follows the farewell); repeat closes are no-ops; and the
    // kicked connection's close hook reports PushClosed while other
    // connections keep serving.
    use std::sync::Mutex;
    let sub_handle: Arc<Mutex<Option<PushHandle>>> = Arc::new(Mutex::new(None));
    let reasons = Arc::new(Mutex::new(Vec::new()));
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(
            PrefixWidth::U32,
            Endian::Big,
            false,
        ),
        body: {
            let sub_handle = Arc::clone(&sub_handle);
            move |req: Request<'_, ()>| {
                let Request {
                    body, responder, ..
                } = req;
                if &body[..] == b"sub" {
                    *sub_handle.lock().unwrap() = Some(responder.push_handle());
                    Response::Reply(echo_frame(b"subscribed"))
                } else if &body[..] == b"kick" {
                    if let Some(h) = sub_handle.lock().unwrap().as_ref() {
                        h.push(echo_frame(b"farewell"));
                        h.close();
                        h.close(); // repeat close: a no-op
                        h.push(echo_frame(b"too-late")); // after close: dropped
                    }
                    Response::Reply(echo_frame(b"kicked"))
                } else {
                    Response::Reply(echo_frame(&body))
                }
            }
        },
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let mut server = match Server::bind([addr], proto) {
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
            let mut sub = connect_tcp(v4)?;
            send_framed(&mut sub, b"sub")?;
            assert_eq!(recv_framed(&mut sub)?, b"subscribed");

            let mut admin = connect_tcp(v4)?;
            send_framed(&mut admin, b"kick")?;
            assert_eq!(recv_framed(&mut admin)?, b"kicked");

            // The subscriber gets the farewell, then EOF — and nothing
            // after the farewell (the too-late push was dropped).
            assert_eq!(recv_framed(&mut sub)?, b"farewell");
            let mut rest = Vec::new();
            sub.read_to_end(&mut rest)?;
            assert!(rest.is_empty(), "bytes after the farewell: {rest:?}");

            // The admin connection is untouched by the kick.
            send_framed(&mut admin, b"ping")?;
            assert_eq!(recv_framed(&mut admin)?, b"ping");
            Ok(())
        })();
        stop.shutdown();
        r
    });

    server.serve_forever().expect("serve_forever");
    client.join().expect("thread join").expect("client io");
    let got = reasons.lock().unwrap().clone();
    assert_eq!(
        got.iter()
            .filter(|r| **r == CloseReason::PushClosed)
            .count(),
        1,
        "expected exactly one PushClosed, got {got:?}"
    );
}

#[test]
fn tcp_stats_counts() {
    // The stats handle reads live counters from another thread.
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(
            PrefixWidth::U32,
            Endian::Big,
            false,
        ),
        body: |req: Request<'_, ()>| {
            let Request {
                body, responder, ..
            } = req;
            if &body[..] == b"defer" {
                let input = body.to_vec();
                let (deferred, permit) = responder.defer();
                thread::spawn(move || {
                    thread::sleep(Duration::from_millis(10));
                    deferred.reply(echo_frame(&input));
                });
                Response::Defer(permit)
            } else {
                Response::Reply(echo_frame(&body))
            }
        },
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let mut server = match Server::bind([addr], proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind: {e}"),
    };
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();
    let stats = server.stats_handle();

    let client = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone()); // fail fast on panic
        (|| -> io::Result<()> {
            // Two connections; three requests total, one deferred.
            let mut a = connect_tcp(v4)?;
            send_framed(&mut a, b"one")?;
            assert_eq!(recv_framed(&mut a)?, b"one");
            send_framed(&mut a, b"defer")?;
            assert_eq!(recv_framed(&mut a)?, b"defer");
            drop(a);
            let mut b = connect_tcp(v4)?;
            send_framed(&mut b, b"two")?;
            assert_eq!(recv_framed(&mut b)?, b"two");
            drop(b);
            thread::sleep(Duration::from_millis(80)); // let closes retire
            Ok(())
        })()
        .expect("client io");
        stop.shutdown();
    });

    server.serve_forever().expect("serve_forever");
    client.join().expect("thread join");
    let s = stats.snapshot();
    assert_eq!(s.accepted, 2, "accepted: {s:?}");
    assert_eq!(s.closed, 2, "closed: {s:?}");
    assert_eq!(s.active, 0, "active: {s:?}");
    assert_eq!(s.requests, 3, "requests: {s:?}");
    assert_eq!(s.deferred, 1, "deferred: {s:?}");
    assert_eq!(s.replies, 3, "replies: {s:?}");
    assert_eq!(s.rejected, 0, "rejected: {s:?}");
    assert!(s.bytes_in > 0 && s.bytes_out > 0, "bytes: {s:?}");
    // Length-prefixed framing costs exactly two recvs per request (header,
    // body); EOFs don't count.
    assert_eq!(s.recv_ops, 2 * s.requests, "recv_ops: {s:?}");
}

/// Deferring echo handler that `take()`s the body — the one-pattern
/// placement consumer (zero-copy when placed, copy fallback inline).
fn take_and_defer_echo(body: &mut Body, responder: Responder) -> Response {
    let payload = body.take();
    let (deferred, permit) = responder.defer();
    thread::spawn(move || deferred.reply(echo_frame(&payload)));
    Response::Defer(permit)
}

/// Patterned payload (prime modulus catches offset/splice mistakes).
fn patterned(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

#[test]
fn tcp_body_placement_roundtrip() {
    // Bodies >= the threshold are read into their own allocation and moved
    // out zero-copy via take(); small bodies ride the accumulate buffer with
    // take() falling back to a copy. Sequence small -> large -> small on one
    // connection proves keep-alive across a placed message (consume() drains
    // only the header of a placed message).
    let cfg = ServerConfig {
        body_placement_threshold: Some(1024),
        ..ServerConfig::default()
    };
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(
            PrefixWidth::U32,
            Endian::Big,
            false,
        ),
        body: |req: Request<'_, ()>| {
            let Request {
                mut body,
                responder,
                ..
            } = req;
            take_and_defer_echo(&mut body, responder)
        },
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
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
        let _stop = ShutdownOnDrop(stop.clone()); // fail fast on panic
        (|| -> io::Result<()> {
            let mut s = connect_tcp(v4)?;
            let large = patterned(256 * 1024);
            for payload in [b"small-1".as_slice(), &large, b"small-2"] {
                send_framed(&mut s, payload)?;
                assert_eq!(
                    recv_framed(&mut s)?,
                    payload,
                    "echo mismatch at len {}",
                    payload.len()
                );
            }
            Ok(())
        })()
        .expect("client io");
        stop.shutdown();
    });

    server.serve_forever().expect("serve_forever");
    client.join().expect("thread join");
}

#[test]
fn tcp_body_placement_disabled() {
    // threshold None: the same take()-based handler works with every body on
    // the accumulate path (take() copies).
    let cfg = ServerConfig {
        body_placement_threshold: None,
        ..ServerConfig::default()
    };
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(
            PrefixWidth::U32,
            Endian::Big,
            false,
        ),
        body: |req: Request<'_, ()>| {
            let Request {
                mut body,
                responder,
                ..
            } = req;
            take_and_defer_echo(&mut body, responder)
        },
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
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
        let _stop = ShutdownOnDrop(stop.clone()); // fail fast on panic
        (|| -> io::Result<()> {
            let mut s = connect_tcp(v4)?;
            let large = patterned(256 * 1024);
            send_framed(&mut s, &large)?;
            assert_eq!(recv_framed(&mut s)?, large);
            Ok(())
        })()
        .expect("client io");
        stop.shutdown();
    });

    server.serve_forever().expect("serve_forever");
    client.join().expect("thread join");
}

#[test]
fn lsp_large_body_placement() {
    // More-style framer + placement: the chunk read over-reads part of the
    // body before the verdict, exercising the prefix-copy path of
    // arm_body_recv (prefix from the accumulate buffer + remainder read
    // straight into the placed allocation).
    let cfg = ServerConfig {
        body_placement_threshold: Some(1024),
        ..ServerConfig::default()
    };
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: lsp_header,
        body: |req: Request<'_, ()>| {
            let Request {
                mut body,
                responder,
                ..
            } = req;
            take_and_defer_echo(&mut body, responder)
        },
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
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
        let _stop = ShutdownOnDrop(stop.clone()); // fail fast on panic
        let r = (|| -> io::Result<(Vec<u8>, Vec<u8>)> {
            let mut s = connect_tcp(v4)?;
            let payload = patterned(8 * 1024);
            // One write: the server's first 4 KiB chunk read grabs the header
            // AND a body prefix.
            let mut msg = format!("Content-Length: {}\r\n\r\n", payload.len())
                .into_bytes();
            msg.extend_from_slice(&payload);
            s.write_all(&msg)?;
            Ok((recv_framed(&mut s)?, payload))
        })();
        stop.shutdown();
        r
    });

    server.serve_forever().expect("serve_forever");
    let (got, want) = client.join().expect("thread join").expect("client io");
    assert_eq!(got, want, "placed LSP body echoed intact");
}

#[test]
fn multi_listener_unix_and_tcp() {
    // One server, one ring, two listeners (TCP + unix). The accept handler
    // records which listener the connection arrived on; the body echoes that
    // plus the peer family, proving routing, framing, and identity per
    // listener.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("multi.sock");
    let addrs = [
        ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap()),
        ServerAddr::Unix(path.clone()),
    ];
    let proto = Protocol {
        accept: |inc: Incoming<'_>| {
            let l = match inc.listener_addr {
                ServerAddr::Tcp(_) => "tcp",
                ServerAddr::Tcp6(_) => "tcp6",
                ServerAddr::Unix(_) => "unix",
            };
            let p = match inc.peer {
                ClientAddr::Inet(_) => "inet",
                ClientAddr::Unix { .. } => "unix",
            };
            Some(format!("{l}/{p}"))
        },
        header: length_prefix_header::<String>(
            PrefixWidth::U32,
            Endian::Big,
            false,
        ),
        body: |req: Request<'_, String>| {
            let Request { state: tag, .. } = req;
            Response::Reply(echo_frame(tag.as_bytes()))
        },
    };
    let mut server = match Server::bind(addrs, proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind: {e}"),
    };
    let bound = server.local_addrs();
    assert_eq!(bound.len(), 2, "two listeners: {bound:?}");
    let ServerAddr::Tcp(v4) = bound[0] else {
        panic!("expected resolved Tcp first: {bound:?}");
    };
    assert_ne!(v4.port(), 0, "ephemeral port resolved");
    assert!(
        matches!(&bound[1], ServerAddr::Unix(p) if *p == path),
        "unix second: {bound:?}"
    );
    let stop = server.shutdown_handle();

    let client = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone()); // fail fast on panic
        (|| -> io::Result<()> {
            let mut t = connect_tcp(v4)?;
            send_framed(&mut t, b"hi")?;
            assert_eq!(recv_framed(&mut t)?, b"tcp/inet");
            let mut u = connect_unix(&path)?;
            send_framed(&mut u, b"hi")?;
            assert_eq!(recv_framed(&mut u)?, b"unix/unix");
            Ok(())
        })()
        .expect("client io");
        stop.shutdown();
    });

    server.serve_forever().expect("serve_forever");
    client.join().expect("thread join");
}

#[test]
fn multi_listener_per_port_policy() {
    // Two TCP listeners on one server; accept admits connections on the first
    // port and rejects the second — the listener argument drives policy.
    use std::sync::Mutex;
    let addrs = [
        ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap()),
        ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap()),
    ];
    let admit_port: Arc<Mutex<u16>> = Arc::new(Mutex::new(0));
    let proto = Protocol {
        accept: {
            let admit_port = Arc::clone(&admit_port);
            move |inc: Incoming<'_>| {
                let ServerAddr::Tcp(sa) = inc.listener_addr else {
                    return None;
                };
                (sa.port() == *admit_port.lock().unwrap()).then_some(())
            }
        },
        header: length_prefix_header::<()>(
            PrefixWidth::U32,
            Endian::Big,
            false,
        ),
        body: |req: Request<'_, ()>| {
            let Request { body, .. } = req;
            Response::Reply(echo_frame(&body[..]))
        },
    };
    let mut server = match Server::bind(addrs, proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind: {e}"),
    };
    let bound = server.local_addrs();
    let (ServerAddr::Tcp(a), ServerAddr::Tcp(b)) = (&bound[0], &bound[1])
    else {
        panic!("expected two Tcp: {bound:?}");
    };
    let (a, b) = (*a, *b);
    *admit_port.lock().unwrap() = a.port();
    let stop = server.shutdown_handle();

    let client = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone()); // fail fast on panic
        (|| -> io::Result<()> {
            // Admitted port echoes.
            let mut ok = connect_tcp(a)?;
            send_framed(&mut ok, b"yes")?;
            assert_eq!(recv_framed(&mut ok)?, b"yes");
            // Rejected port: no echo comes back. A short read must NOT yield
            // the payload (rejected means no reply); EOF, reset, or a plain
            // timeout with no data all confirm "not admitted". (This asserts
            // policy without depending on the reject-close reaching us — see
            // the close-propagation note on the ignored tests.)
            let mut no = connect_tcp(b)?;
            no.set_read_timeout(Some(Duration::from_millis(300)))?;
            let _ = send_framed(&mut no, b"no");
            let mut byte = [0u8; 1];
            match no.read(&mut byte) {
                Ok(n) => assert_eq!(n, 0, "rejected conn must not echo"),
                Err(e) => assert!(
                    matches!(
                        e.kind(),
                        io::ErrorKind::ConnectionReset
                            | io::ErrorKind::WouldBlock
                            | io::ErrorKind::TimedOut
                    ),
                    "unexpected error on rejected conn: {e:?}"
                ),
            }
            // The admitted listener still works afterwards.
            send_framed(&mut ok, b"again")?;
            assert_eq!(recv_framed(&mut ok)?, b"again");
            Ok(())
        })()
        .expect("client io");
        stop.shutdown();
    });

    server.serve_forever().expect("serve_forever");
    client.join().expect("thread join");
}

#[test]
fn tcp_peername_is_per_connection() {
    // Peer addresses are fetched per connection (SO_PEERNAME), not read from
    // a buffer shared across a multishot accept's completions — so a burst of
    // simultaneous connects must each see THEIR OWN source address echoed
    // back. (Under the old shared-buffer scheme a burst misattributes.)
    const N: usize = 8;
    let proto = Protocol {
        accept: |inc: Incoming<'_>| match inc.peer {
            ClientAddr::Inet(sa) => Some(sa.to_string()),
            _ => None,
        },
        header: length_prefix_header::<String>(
            PrefixWidth::U32,
            Endian::Big,
            false,
        ),
        body: |req: Request<'_, String>| {
            let Request { state: seen, .. } = req;
            Response::Reply(echo_frame(seen.as_bytes()))
        },
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let mut server = match Server::bind([addr], proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind: {e}"),
    };
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();

    let driver = thread::spawn(move || {
        let clients: Vec<_> = (0..N)
            .map(|_| {
                thread::spawn(move || -> io::Result<()> {
                    // Connect within the burst, then ask who the server
                    // thinks we are.
                    let mut s = connect_tcp(v4)?;
                    let me = s.local_addr()?;
                    send_framed(&mut s, b"who")?;
                    let reply = recv_framed(&mut s)?;
                    let seen = String::from_utf8(reply).expect("utf8");
                    assert_eq!(
                        seen,
                        me.to_string(),
                        "server saw a different peer than this client"
                    );
                    Ok(())
                })
            })
            .collect();
        for c in clients {
            c.join().expect("client join").expect("client io");
        }
        stop.shutdown();
    });

    server.serve_forever().expect("serve_forever");
    driver.join().expect("driver join");
}

#[test]
fn multi_listener_pool_full_rearm() {
    // pool_size = 1 with two listeners: while the slot is held by listener
    // A's connection, a connect on listener B is shed (kernel ENFILE close);
    // once A's connection closes, B's parked accept re-arms and serves.
    let cfg = ServerConfig {
        pool_size: 1,
        ..ServerConfig::default()
    };
    let addrs = [
        ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap()),
        ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap()),
    ];
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(
            PrefixWidth::U32,
            Endian::Big,
            false,
        ),
        body: |req: Request<'_, ()>| {
            let Request { body, .. } = req;
            Response::Reply(echo_frame(&body[..]))
        },
    };
    let mut server = match Server::with_config(addrs, cfg, proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind: {e}"),
    };
    let bound = server.local_addrs();
    let (ServerAddr::Tcp(a), ServerAddr::Tcp(b)) = (&bound[0], &bound[1])
    else {
        panic!("expected two Tcp: {bound:?}");
    };
    let (a, b) = (*a, *b);
    let stop = server.shutdown_handle();

    let client = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone()); // fail fast on panic
        (|| -> io::Result<()> {
            let mut holder = connect_tcp(a)?;
            send_framed(&mut holder, b"hold")?;
            assert_eq!(recv_framed(&mut holder)?, b"hold");
            // Pool is full: one attempt on B is shed (accepted then closed by
            // the kernel — ENFILE — terminating B's multishot accept). Use a
            // short timeout because a connection can also land in B's listen
            // backlog unaccepted, where a read would block indefinitely; that
            // it does not get served is the point.
            let mut shed = connect_tcp(b)?;
            shed.set_read_timeout(Some(Duration::from_millis(200)))?;
            let mut byte = [0u8; 1];
            let _ = shed.read(&mut byte); // EOF / reset / timeout — all "shed"
            drop(shed);
            drop(holder); // free the only slot
            thread::sleep(Duration::from_millis(150)); // close + deferred re-arm
                                                       // B's accept re-armed on the freed slot; a fresh connection serves.
            let mut ok = connect_tcp(b)?;
            send_framed(&mut ok, b"revived")?;
            assert_eq!(recv_framed(&mut ok)?, b"revived");
            Ok(())
        })()
        .expect("client io");
        stop.shutdown();
    });

    server.serve_forever().expect("serve_forever");
    client.join().expect("thread join");
}

#[test]
fn tcp_reply_coalescing() {
    // A burst of deferred replies released together is gathered into fewer
    // SENDMSG ops (writev coalescing): 16 pipelined requests all defer; one
    // worker answers all 16 at once; the client must receive every payload
    // intact (order-independent — deferred replies may egress out of request
    // order) and the stats must show send_ops < replies.
    use std::sync::Mutex;
    const N: usize = 16;
    type Parked = Vec<(Vec<u8>, truenas_ros::net::server::Deferred)>;
    let parked: Arc<Mutex<Parked>> = Arc::new(Mutex::new(Vec::new()));
    let cfg = ServerConfig {
        max_in_flight_requests: N,
        ..ServerConfig::default()
    };
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(
            PrefixWidth::U32,
            Endian::Big,
            false,
        ),
        body: {
            let parked = Arc::clone(&parked);
            move |req: Request<'_, ()>| {
                let Request {
                    body, responder, ..
                } = req;
                let (deferred, permit) = responder.defer();
                let mut guard = parked.lock().unwrap();
                guard.push((body.to_vec(), deferred));
                if guard.len() == N {
                    // Last request in: answer the whole burst back-to-back so
                    // the injection queue fills faster than the loop drains.
                    let batch = std::mem::take(&mut *guard);
                    thread::spawn(move || {
                        for (payload, d) in batch {
                            d.reply(echo_frame(&payload));
                        }
                    });
                }
                Response::Defer(permit)
            }
        },
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let mut server = match Server::with_config([addr], cfg, proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind: {e}"),
    };
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();
    let stats = server.stats_handle();

    let client = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone()); // fail fast on panic
        (|| -> io::Result<()> {
            let mut s = connect_tcp(v4)?;
            let sent: Vec<Vec<u8>> = (0..N)
                .map(|i| format!("burst-{i:02}").into_bytes())
                .collect();
            for msg in &sent {
                send_framed(&mut s, msg)?; // pipelined: no reads in between
            }
            let mut got: Vec<Vec<u8>> = (0..N)
                .map(|_| recv_framed(&mut s))
                .collect::<Result<_, _>>()?;
            got.sort();
            assert_eq!(got, sent, "every burst payload echoed intact");
            Ok(())
        })()
        .expect("client io");
        stop.shutdown();
    });

    server.serve_forever().expect("serve_forever");
    client.join().expect("thread join");
    let s = stats.snapshot();
    assert_eq!(s.replies, N as u64, "replies: {s:?}");
    assert!(
        s.send_ops >= 1 && s.send_ops < s.replies,
        "expected coalescing (send_ops < replies): {s:?}"
    );
}

#[test]
fn tcp_graceful_shutdown_drains() {
    // Graceful shutdown: a request already deferred to a worker completes and
    // its reply is delivered; an idle connection is closed promptly; accepting
    // stops; serve_forever returns without waiting for the grace deadline.
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(
            PrefixWidth::U32,
            Endian::Big,
            false,
        ),
        body: |req: Request<'_, ()>| {
            let Request {
                body, responder, ..
            } = req;
            let input = body.to_vec();
            let (deferred, permit) = responder.defer();
            thread::spawn(move || {
                thread::sleep(Duration::from_millis(150)); // in-flight work
                deferred.reply(echo_frame(&input.to_ascii_uppercase()));
            });
            Response::Defer(permit)
        },
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
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
        let _stop = ShutdownOnDrop(stop.clone()); // fail fast on panic
        (|| -> io::Result<()> {
            let mut idle = connect_tcp(v4)?; // parked, no request
            let mut busy = connect_tcp(v4)?;
            send_framed(&mut busy, b"work")?; // now deferred to the worker

            thread::sleep(Duration::from_millis(30)); // let the defer start
            let t0 = Instant::now();
            stop.shutdown_graceful(Duration::from_secs(5));

            // In-flight work still completes and is delivered...
            let reply = recv_framed(&mut busy)?;
            assert_eq!(reply, b"WORK");
            // ...then the drained connection closes (EOF), as does the idle one
            // — well before the 5s grace deadline.
            let mut b = [0u8; 1];
            assert_eq!(busy.read(&mut b)?, 0, "busy conn should see EOF");
            assert_eq!(idle.read(&mut b)?, 0, "idle conn should see EOF");
            assert!(
                t0.elapsed() < Duration::from_secs(2),
                "drain took {:?}",
                t0.elapsed()
            );
            Ok(())
        })()
        .expect("client io");
    });

    server.serve_forever().expect("serve_forever");
    client.join().expect("thread join");
}

#[test]
fn tcp_graceful_deadline_escalates() {
    // A worker that never resolves its Deferred: the graceful drain cannot
    // complete, so the grace deadline must escalate to a hard stop and
    // serve_forever must still return. The handler parks each Deferred in
    // `keep_rx` and never resolves it — rather than `mem::forget`, which leaks
    // its channel Sender + Arc and trips LeakSanitizer — releasing it only at
    // test end, long after the drain has been forced to escalate.
    let (keep_tx, keep_rx) = std::sync::mpsc::channel();
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(
            PrefixWidth::U32,
            Endian::Big,
            false,
        ),
        body: move |req: Request<'_, ()>| {
            let Request { responder, .. } = req;
            let (deferred, permit) = responder.defer();
            let _ = keep_tx.send(deferred); // held, never resolved
            Response::Defer(permit)
        },
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
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
        let _stop = ShutdownOnDrop(stop.clone()); // fail fast on panic
        (|| -> io::Result<TcpStream> {
            let mut s = connect_tcp(v4)?;
            send_framed(&mut s, b"stuck")?;
            thread::sleep(Duration::from_millis(30));
            stop.shutdown_graceful(Duration::from_millis(300));
            // Keep the socket open (returned) — its EOF only arrives when the
            // abandoned connection's descriptor closes at server teardown.
            Ok(s)
        })()
        .expect("client io")
    });

    let t0 = Instant::now();
    server.serve_forever().expect("serve_forever");
    assert!(
        t0.elapsed() < Duration::from_secs(2),
        "deadline escalation took {:?}",
        t0.elapsed()
    );
    let mut s = client.join().expect("thread join");
    // Hard-stop abandons the stuck connection; dropping the server closes its
    // pool descriptor, and only then does the client see EOF with no data.
    drop(server);
    let mut buf = Vec::new();
    let n = s.read_to_end(&mut buf).unwrap_or(buf.len());
    assert_eq!(n, 0, "unexpected data after abandon: {buf:?}");
    drop(keep_rx); // release the held (never-resolved) Deferreds — no leak
}

#[test]
fn tcp_graceful_drains_pipelined_deferred_reply() {
    // Regression (#3): in pipelined mode a connection can hold a deferred reply
    // in flight AND a read-ahead recv parked at once. Graceful shutdown must
    // still deliver that reply — `begin_drain` cancels the parked recv, but the
    // connection must finish its outstanding work before closing, not be torn
    // down (which dropped the reply before the fix). At the default
    // `max_in_flight_requests` the read-ahead is never armed during a defer, so
    // this shape is pipelined-only.
    let cfg = ServerConfig {
        max_in_flight_requests: 2, // pipelined → read-ahead armed during a defer
        ..ServerConfig::default()
    };
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(
            PrefixWidth::U32,
            Endian::Big,
            false,
        ),
        body: |req: Request<'_, ()>| {
            let Request {
                body, responder, ..
            } = req;
            let mut reply = b"re:".to_vec();
            reply.extend_from_slice(&body);
            let (deferred, permit) = responder.defer();
            thread::spawn(move || {
                thread::sleep(Duration::from_millis(150)); // still in flight at drain
                deferred.reply(echo_frame(&reply));
            });
            Response::Defer(permit)
        },
    };
    let mut server = match Server::with_config(
        [ServerAddr::Tcp(
            "127.0.0.1:0".parse::<SocketAddrV4>().unwrap(),
        )],
        cfg,
        proto,
    ) {
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
        (|| -> io::Result<()> {
            let mut s = connect_tcp(v4)?;
            send_framed(&mut s, b"hello")?;
            // Let the defer start and the read-ahead recv arm, then drain.
            thread::sleep(Duration::from_millis(40));
            stop.shutdown_graceful(Duration::from_secs(5));
            // The deferred reply must arrive despite the drain, before EOF.
            assert_eq!(recv_framed(&mut s)?, b"re:hello");
            let mut b = [0u8; 1];
            assert_eq!(s.read(&mut b)?, 0, "EOF after the deferred reply");
            Ok(())
        })()
        .expect("client io");
    });

    server.serve_forever().expect("serve_forever");
    client.join().expect("thread join");
}

#[test]
fn tcp_idle_timeout_keeps_pipelined_deferred_reply() {
    // Regression (sibling of `tcp_graceful_drains_pipelined_deferred_reply`, for
    // the idle-timeout cancellation instead of the drain one): in pipelined mode
    // a connection can hold a deferred reply in flight AND a parked read-ahead
    // recv at once. When `idle_timeout` fires on that read-ahead recv the
    // connection is NOT idle — it still owes the deferred reply — so it must
    // finish that work, not be reaped (which dropped the reply before the fix:
    // once `closing`, `kick_send`'s `!closing` guard swallows the queued send).
    // A perfectly normal request/response client (send one request, await its
    // reply before the next) hits this whenever the worker outlives
    // `idle_timeout`. At the default `max_in_flight_requests` no read-ahead is
    // armed during a defer, so this shape is pipelined-only.
    //
    // `WORK` being an exact multiple of `IDLE` also lands the final clock
    // expiry in a photo-finish with the reply's flush and the client's
    // immediate next request — the served-since-arm rule keeps every ordering
    // of that race alive (pinned deterministically, with wide margins, by
    // `tcp_idle_clock_resets_on_served_reply`).
    const IDLE: Duration = Duration::from_millis(100);
    const WORK: Duration = Duration::from_millis(400); // outlives IDLE 4x
    let cfg = ServerConfig {
        max_in_flight_requests: 2, // pipelined → read-ahead armed during a defer
        idle_timeout: Some(IDLE),
        ..ServerConfig::default()
    };
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(
            PrefixWidth::U32,
            Endian::Big,
            false,
        ),
        body: |req: Request<'_, ()>| {
            let Request {
                body, responder, ..
            } = req;
            let mut reply = b"re:".to_vec();
            reply.extend_from_slice(&body);
            let (deferred, permit) = responder.defer();
            thread::spawn(move || {
                // Outlives `idle_timeout`, so the read-ahead recv's idle timeout
                // fires while this reply is still in flight.
                thread::sleep(WORK);
                deferred.reply(echo_frame(&reply));
            });
            Response::Defer(permit)
        },
    };
    let mut server = match Server::with_config(
        [ServerAddr::Tcp(
            "127.0.0.1:0".parse::<SocketAddrV4>().unwrap(),
        )],
        cfg,
        proto,
    ) {
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
        (|| -> io::Result<()> {
            let mut s = connect_tcp(v4)?;
            // Send one request, then just wait for its reply — the read-ahead
            // recv parks and its idle timeout fires long before the worker
            // replies. Before the fix the server closed the connection here, so
            // this read hit EOF; the reply must instead still arrive.
            send_framed(&mut s, b"hello")?;
            assert_eq!(
                recv_framed(&mut s)?,
                b"re:hello",
                "deferred reply dropped by an idle-timeout reap"
            );
            // The connection was not reaped, so keep-alive continues: a second
            // round-trip on the same socket succeeds (also exercises the idle
            // fire during the *second* defer).
            send_framed(&mut s, b"world")?;
            assert_eq!(recv_framed(&mut s)?, b"re:world");
            Ok(())
        })()
        .expect("client io");
        stop.shutdown();
    });

    server.serve_forever().expect("serve_forever");
    client.join().expect("thread join");
}

#[test]
fn tcp_idle_clock_resets_on_served_reply() {
    // Regression — the deterministic form of the race its sibling above only
    // hits on a slow box (where it flaked in CI): the idle clock rides the
    // parked read-ahead recv from ARM time, so while a deferred reply is
    // produced and flushed the clock keeps counting. Serving that reply is
    // activity — the quiet interval must restart — yet a guard that only asks
    // "owes work NOW?" sees nothing outstanding at the next expiry and reaps
    // the connection out from under a client it served moments ago (the
    // client's follow-up request then hits EOF/reset).
    //
    // Timeline pinned here, margins in the hundreds of ms so a loaded VM
    // cannot flip any edge: the read-ahead parks at ~0 with the clock running;
    // the deferred reply flushes at ~WORK (300 ms); the stale clock expires at
    // ~IDLE (600 ms) — an interval that SAW a served reply, so it must re-arm
    // a fresh quiet interval, not reap — and the client's second request lands
    // at ~700 ms, inside that fresh interval, and must be answered.
    const IDLE: Duration = Duration::from_millis(600);
    const WORK: Duration = Duration::from_millis(300);
    const CLIENT_PAUSE: Duration = Duration::from_millis(400);
    let cfg = ServerConfig {
        max_in_flight_requests: 2, // pipelined → read-ahead parks during defer
        idle_timeout: Some(IDLE),
        ..ServerConfig::default()
    };
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(
            PrefixWidth::U32,
            Endian::Big,
            false,
        ),
        body: |req: Request<'_, ()>| {
            let Request {
                body, responder, ..
            } = req;
            let mut reply = b"re:".to_vec();
            reply.extend_from_slice(&body);
            let (deferred, permit) = responder.defer();
            thread::spawn(move || {
                thread::sleep(WORK);
                deferred.reply(echo_frame(&reply));
            });
            Response::Defer(permit)
        },
    };
    let mut server = match Server::with_config(
        [ServerAddr::Tcp(
            "127.0.0.1:0".parse::<SocketAddrV4>().unwrap(),
        )],
        cfg,
        proto,
    ) {
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
        (|| -> io::Result<()> {
            let mut s = connect_tcp(v4)?;
            send_framed(&mut s, b"hello")?;
            assert_eq!(recv_framed(&mut s)?, b"re:hello");
            // Idle across the stale clock's expiry (but well inside the fresh
            // interval that expiry must start): served-then-quiet, the exact
            // window the flag-less guard reaped.
            thread::sleep(CLIENT_PAUSE);
            send_framed(&mut s, b"world")?;
            assert_eq!(
                recv_framed(&mut s)?,
                b"re:world",
                "connection reaped in the quiet window after a served reply"
            );
            Ok(())
        })()
        .expect("client io");
        stop.shutdown();
    });

    server.serve_forever().expect("serve_forever");
    client.join().expect("thread join");
}

#[test]
fn tcp_default_config_never_times_out_a_deferred_request() {
    // The handler/worker phase is un-timed: a request delivered and offloaded
    // via `Response::Defer` must never be timed out, however long the worker
    // runs. At the default `max_in_flight_requests` (1) no read-ahead recv is
    // armed while a defer is outstanding, so even with `idle_timeout` set well
    // below the worker's duration nothing fires — the reply still arrives.
    const IDLE: Duration = Duration::from_millis(100);
    const WORK: Duration = Duration::from_millis(500); // 5x the idle timeout
    let cfg = ServerConfig {
        idle_timeout: Some(IDLE), // set, but must not reach a handled request
        ..ServerConfig::default()  // max_in_flight_requests == 1
    };
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(
            PrefixWidth::U32,
            Endian::Big,
            false,
        ),
        body: |req: Request<'_, ()>| {
            let Request {
                body, responder, ..
            } = req;
            let echo = echo_frame(&body);
            let (deferred, permit) = responder.defer();
            thread::spawn(move || {
                thread::sleep(WORK); // outlives idle_timeout many times over
                deferred.reply(echo);
            });
            Response::Defer(permit)
        },
    };
    let mut server = match Server::with_config(
        [ServerAddr::Tcp(
            "127.0.0.1:0".parse::<SocketAddrV4>().unwrap(),
        )],
        cfg,
        proto,
    ) {
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
        (|| -> io::Result<()> {
            let mut s = connect_tcp(v4)?;
            send_framed(&mut s, b"slow")?;
            // The worker sleeps far longer than idle_timeout; the reply must
            // still come back — the handled request is never timed out.
            assert_eq!(recv_framed(&mut s)?, b"slow");
            Ok(())
        })()
        .expect("client io");
        stop.shutdown();
    });

    server.serve_forever().expect("serve_forever");
    client.join().expect("thread join");
}

#[test]
fn tcp_close_hook_reasons() {
    // The close hook reports why each connection closed: a clean keep-alive
    // EOF, a handler-initiated close, and an idle timeout.
    use std::sync::Mutex;
    let reasons = Arc::new(Mutex::new(Vec::new()));
    let cfg = ServerConfig {
        idle_timeout: Some(Duration::from_millis(100)),
        ..ServerConfig::default()
    };
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(
            PrefixWidth::U32,
            Endian::Big,
            false,
        ),
        body: |req: Request<'_, ()>| {
            let Request { body, .. } = req;
            if &body[..] == b"close" {
                Response::Close
            } else {
                Response::Reply(echo_frame(&body))
            }
        },
    };
    let mut server = match Server::with_config(
        [ServerAddr::Tcp(
            "127.0.0.1:0".parse::<SocketAddrV4>().unwrap(),
        )],
        cfg,
        proto,
    ) {
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
        let _stop = ShutdownOnDrop(stop.clone()); // fail fast on panic
        (|| -> io::Result<()> {
            // (a) clean keep-alive EOF → PeerClosed
            let mut a = connect_tcp(v4)?;
            send_framed(&mut a, b"hi")?;
            assert_eq!(recv_framed(&mut a)?, b"hi");
            drop(a);
            // (b) handler says close → HandlerClosed
            let mut b = connect_tcp(v4)?;
            send_framed(&mut b, b"close")?;
            let mut buf = Vec::new();
            b.read_to_end(&mut buf)?; // closed without a reply
            assert!(buf.is_empty());
            // (c) parked past idle_timeout → IdleTimeout
            let mut c = connect_tcp(v4)?;
            let mut one = [0u8; 1];
            assert_eq!(c.read(&mut one)?, 0, "idle conn should be closed");
            // Let the server retire (a)'s EOF before stopping.
            thread::sleep(Duration::from_millis(50));
            Ok(())
        })()
        .expect("client io");
        stop.shutdown();
    });

    server.serve_forever().expect("serve_forever");
    client.join().expect("thread join");
    let mut got = reasons.lock().unwrap().clone();
    got.sort_by_key(|r| format!("{r:?}"));
    assert_eq!(
        got,
        vec![
            CloseReason::HandlerClosed,
            CloseReason::IdleTimeout,
            CloseReason::PeerClosed,
        ]
    );
}

#[test]
fn tcp_multicore_two_rings() {
    // The SO_REUSEPORT multi-core recipe (examples/tcp_multicore.rs): two
    // independent single-ring servers on one address; the kernel spreads
    // connections across them; every round-trip is served; both drain cleanly.
    fn worker(
        addr: SocketAddrV4,
        ready: std::sync::mpsc::Sender<
            Result<(SocketAddrV4, ShutdownHandle), Error>,
        >,
    ) {
        let cfg = ServerConfig {
            reuse_port: true,
            ..ServerConfig::default()
        };
        let proto = length_prefixed(PrefixWidth::U32, Endian::Big, false, echo);
        let mut server =
            match Server::with_config([ServerAddr::Tcp(addr)], cfg, proto) {
                Ok(s) => s,
                Err(e) => {
                    let _ = ready.send(Err(e));
                    return;
                }
            };
        let ServerAddr::Tcp(bound) = server.local_addrs().remove(0) else {
            panic!("expected Tcp");
        };
        let stop = server.shutdown_handle();
        let _ = ready.send(Ok((bound, stop)));
        server.serve_forever().expect("serve_forever");
    }

    let (tx, rx) = std::sync::mpsc::channel();
    let tx0 = tx.clone();
    let w0 = thread::spawn(move || {
        worker("127.0.0.1:0".parse().unwrap(), tx0);
    });
    let (addr, stop0) = match rx.recv().expect("worker 0") {
        Ok(v) => v,
        Err(e) if should_skip(&e) => {
            w0.join().unwrap();
            return;
        }
        Err(e) => panic!("bind: {e}"),
    };
    let w1 = thread::spawn(move || {
        worker(addr, tx);
    });
    let (_, stop1) = rx.recv().expect("worker 1").expect("second bind");

    // Fresh connection per round-trip so accepts spread across both rings.
    for i in 0..16 {
        let msg = format!("m{i}");
        let echoes = connect_tcp(addr)
            .and_then(|s| framed_roundtrips(s, &[msg.as_bytes()]))
            .expect("round-trip");
        assert_eq!(echoes, vec![msg.into_bytes()]);
    }

    stop0.shutdown_graceful(Duration::from_secs(5));
    stop1.shutdown_graceful(Duration::from_secs(5));
    w0.join().expect("worker 0 join");
    w1.join().expect("worker 1 join");
}

#[test]
fn tcp_pipelined_out_of_order() {
    // Pipelined (max_in_flight > 1): the client sends several requests without
    // waiting; each is deferred to a worker that finishes in REVERSE order. With
    // read-ahead the server reads and defers all of them before any reply, so
    // replies egress out of request order — proving recv is decoupled from send.
    // The body carries a 1-byte id the client matches replies against.
    const N: u8 = 4;
    let cfg = ServerConfig {
        max_in_flight_requests: 8,
        ..ServerConfig::default()
    };
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(
            PrefixWidth::U32,
            Endian::Big,
            false,
        ),
        body: |req: Request<'_, ()>| {
            let Request {
                body, responder, ..
            } = req;
            let id = body[0];
            let (deferred, permit) = responder.defer();
            thread::spawn(move || {
                // Higher ids sleep less → replies come back reversed.
                thread::sleep(Duration::from_millis(u64::from(N - id) * 40));
                deferred.reply(echo_frame(&[id]));
            });
            Response::Defer(permit)
        },
    };
    let mut server = match Server::with_config(
        [ServerAddr::Tcp(
            "127.0.0.1:0".parse::<SocketAddrV4>().unwrap(),
        )],
        cfg,
        proto,
    ) {
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
        let r = (|| -> io::Result<Vec<u8>> {
            let mut s = connect_tcp(v4)?;
            for id in 0..N {
                send_framed(&mut s, &[id])?; // pipeline: no waiting between sends
            }
            let mut order = Vec::new();
            for _ in 0..N {
                order.push(recv_framed(&mut s)?[0]);
            }
            Ok(order)
        })();
        stop.shutdown();
        r
    });

    server.serve_forever().expect("serve_forever");
    let order = client.join().expect("thread join").expect("client io");
    // Deterministic reversal from the inverse delays — the last request sent is
    // answered first, which can only happen if reads ran ahead of sends.
    assert_eq!(order, vec![3, 2, 1, 0]);
}

#[test]
fn tcp_pipelined_backpressure() {
    // A tight cap with more pipelined requests than the cap: read-ahead must
    // pause at the cap and resume as replies drain — every request answered,
    // none dropped or deadlocked.
    const N: u8 = 12;
    let cfg = ServerConfig {
        max_in_flight_requests: 2,
        ..ServerConfig::default()
    };
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(
            PrefixWidth::U32,
            Endian::Big,
            false,
        ),
        body: |req: Request<'_, ()>| {
            let Request {
                body, responder, ..
            } = req;
            let id = body[0];
            let (deferred, permit) = responder.defer();
            thread::spawn(move || {
                thread::sleep(Duration::from_millis(5));
                deferred.reply(echo_frame(&[id]));
            });
            Response::Defer(permit)
        },
    };
    let mut server = match Server::with_config(
        [ServerAddr::Tcp(
            "127.0.0.1:0".parse::<SocketAddrV4>().unwrap(),
        )],
        cfg,
        proto,
    ) {
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
        let r = (|| -> io::Result<Vec<u8>> {
            let mut s = connect_tcp(v4)?;
            for id in 0..N {
                send_framed(&mut s, &[id])?;
            }
            let mut got = Vec::new();
            for _ in 0..N {
                got.push(recv_framed(&mut s)?[0]);
            }
            Ok(got)
        })();
        stop.shutdown();
        r
    });

    server.serve_forever().expect("serve_forever");
    let mut got = client.join().expect("thread join").expect("client io");
    got.sort_unstable();
    assert_eq!(got, (0..N).collect::<Vec<u8>>());
}

#[test]
fn tcp_large_response() {
    // A response far larger than the socket send buffer exercises the WAITALL
    // send: io_uring accumulates the short writes in-kernel and delivers the
    // whole PDU in one op. The client reads it all back and checks it. (Runs in
    // the default sequential mode — the WAITALL send is orthogonal to pipelining.)
    const SIZE: usize = 2 * 1024 * 1024; // >> the default socket sndbuf
    let proto = length_prefixed(
        PrefixWidth::U32,
        Endian::Big,
        false,
        |_h: &[u8], _b: &[u8], _p: &ClientAddr| {
            Some(echo_frame(
                &(0..SIZE).map(|i| (i % 251) as u8).collect::<Vec<u8>>(),
            ))
        },
    );
    let mut server = match Server::bind(
        [ServerAddr::Tcp(
            "127.0.0.1:0".parse::<SocketAddrV4>().unwrap(),
        )],
        proto,
    ) {
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
        let r = (|| -> io::Result<Vec<u8>> {
            let mut s = connect_tcp(v4)?;
            send_framed(&mut s, b"go")?;
            recv_framed(&mut s)
        })();
        stop.shutdown();
        r
    });

    server.serve_forever().expect("serve_forever");
    let got = client.join().expect("thread join").expect("client io");
    assert_eq!(got.len(), SIZE);
    assert!(got.iter().enumerate().all(|(i, &b)| b == (i % 251) as u8));
}

#[test]
fn tcp_reject() {
    // `accept` returns None → the connection is accepted then immediately closed
    // before any read; the client observes a clean EOF with no reply.
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let proto = Protocol {
        accept: |_: Incoming<'_>| None::<()>,
        header: length_prefix_header::<()>(
            PrefixWidth::U32,
            Endian::Big,
            false,
        ),
        body: |_: Request<'_, ()>| Response::Close,
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
        let _stop = ShutdownOnDrop(stop.clone()); // fail fast on panic
        let r = (|| -> io::Result<Vec<u8>> {
            let mut s = connect_tcp(v4)?;
            let _ = send_framed(&mut s, b"hello"); // may fail on a reset; ignore
            let mut buf = Vec::new();
            s.read_to_end(&mut buf)?; // rejected → EOF, no data
            Ok(buf)
        })();
        stop.shutdown();
        r
    });

    server.serve_forever().expect("serve_forever");
    let got = client.join().expect("thread join");
    // Either a clean empty read (EOF) or a connection-reset error is acceptable.
    match got {
        Ok(buf) => assert!(buf.is_empty(), "rejected client got data: {buf:?}"),
        Err(e) => assert_eq!(e.kind(), io::ErrorKind::ConnectionReset),
    }
}

#[test]
fn server_close_reaches_peer_while_another_idles() {
    // A server-initiated close must send the peer its FIN promptly even when
    // another connection sits idle on a parked recv. A bare CLOSE of a direct
    // descriptor only drops the ring's file-table reference; the socket's
    // fput (and thus the FIN) can be deferred while the idle connection's
    // in-flight recv pins the ring's resource node — so the closed peer would
    // hang fully connected. The pre-close SHUTDOWN fixes that; this is the
    // regression guard.
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(
            PrefixWidth::U32,
            Endian::Big,
            false,
        ),
        // 'C' => close the connection; anything else => echo (keep-alive).
        body: |req: Request<'_, ()>| {
            let Request { body, .. } = req;
            if body.first() == Some(&b'C') {
                Response::Close
            } else {
                Response::Reply(echo_frame(&body[..]))
            }
        },
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
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
        let _stop = ShutdownOnDrop(stop.clone()); // fail fast on panic
        (|| -> io::Result<()> {
            // Idle connection: one request keeps it alive, then it parks on a
            // recv (pinning the resource node) without closing.
            let mut idle = connect_tcp(v4)?;
            send_framed(&mut idle, b"keepalive")?;
            assert_eq!(recv_framed(&mut idle)?, b"keepalive");

            // Second connection asks the server to close it. With the idle
            // recv pinning the node, the FIN must still arrive promptly.
            let mut victim = connect_tcp(v4)?;
            victim.set_read_timeout(Some(Duration::from_secs(3)))?;
            send_framed(&mut victim, b"C")?;
            let mut buf = Vec::new();
            match victim.read_to_end(&mut buf) {
                Ok(_) => assert!(buf.is_empty(), "victim got data: {buf:?}"),
                Err(e) => assert_eq!(
                    e.kind(),
                    io::ErrorKind::ConnectionReset,
                    "victim should see EOF/reset, not hang"
                ),
            }

            // The idle connection is unaffected and still serves.
            send_framed(&mut idle, b"still-here")?;
            assert_eq!(recv_framed(&mut idle)?, b"still-here");
            Ok(())
        })()
        .expect("client io");
        stop.shutdown();
    });

    server.serve_forever().expect("serve_forever");
    client.join().expect("thread join");
}

/// Block on a read and assert the server closes an idle connection promptly — a
/// clean EOF (orderly close) or a reset. The stream's existing read timeout
/// turns a server that never closes into a failure rather than a hang.
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
        "idle close took too long ({:?}) — timer may not be firing",
        start.elapsed()
    );
    Ok(())
}

#[test]
fn tcp_idle_timeout() {
    // With an idle timeout set, a connection left waiting for its next request
    // is closed and its slot reclaimed — while an in-flight request is never
    // interrupted. Covers both idle recvs: after a completed round-trip, and a
    // connection that sends nothing at all.
    let cfg = ServerConfig {
        idle_timeout: Some(Duration::from_millis(200)),
        ..ServerConfig::default()
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let mut server = match Server::with_config(
        [addr],
        cfg,
        length_prefixed(PrefixWidth::U32, Endian::Big, false, echo),
    ) {
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
            // Serviced, then idle: the active exchange succeeds, then the idle
            // connection is closed on the *next* header recv's timeout.
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
    // `Duration::MAX` (and anything >= 2^63 seconds) must mean "never fires",
    // not "fires instantly": the kernel-timespec conversion clamps tv_sec. An
    // unclamped `as i64` cast wraps negative, LINK_TIMEOUT prep then fails
    // -EINVAL and takes its linked recv down -ECANCELED — misreported as
    // IdleTimeout/RequestTimeout — closing every connection at its first
    // parked read: the server could not hold a single client.
    let cfg = ServerConfig {
        idle_timeout: Some(Duration::MAX),
        request_timeout: Some(Duration::MAX),
        send_timeout: Some(Duration::MAX),
        ..ServerConfig::default()
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let mut server = match Server::with_config(
        [addr],
        cfg,
        length_prefixed(PrefixWidth::U32, Endian::Big, false, echo),
    ) {
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
            // Hold the REQUEST clock across a wait too: prefix now, body
            // later — the split parks the body recv with its linked clock.
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
    // SECURITY (slow-loris): a peer that sends a valid length prefix and then
    // withholds the body must not pin its pool slot. `request_timeout` bounds
    // an in-progress request even though `idle_timeout` (unset here) never
    // would — the connection is not idle, it is mid-frame. An idle keep-alive
    // connection is left untouched (that is `idle_timeout`'s job, not this).
    let cfg = ServerConfig {
        request_timeout: Some(Duration::from_millis(200)),
        ..ServerConfig::default()
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let mut server = match Server::with_config(
        [addr],
        cfg,
        length_prefixed(PrefixWidth::U32, Endian::Big, false, echo),
    ) {
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

            // Prefix declaring a 64-byte body, then nothing: the body recv
            // stalls and the slot is reclaimed within request_timeout.
            let mut stall = connect_tcp(v4)?;
            stall.write_all(&64u32.to_be_bytes())?;
            expect_idle_close(&mut stall)?; // detects the prompt server close

            // The idle keep-alive `ok` is NOT reclaimed by request_timeout: it
            // still serves after well over the timeout window.
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
    // Close-reason fidelity for the slow-loris guard: a peer that trickles
    // SOME body bytes then stalls must be reported as RequestTimeout, not
    // TruncatedMessage. A LINK_TIMEOUT-cancelled MSG_WAITALL recv that had
    // consumed bytes completes with res = done_io > 0 (io_sendrecv_fail) —
    // bit-identical to a peer FIN mid-frame — so the server pairs the recv
    // completion with its clock CQE (-ETIME vs -ECANCELED) to classify.
    // Operators tuning slow-loris defenses read these reasons; "the peer
    // vanished mid-message" for a live, merely-stalled peer sends them
    // chasing the wrong problem.
    use std::sync::Mutex;
    let reasons = Arc::new(Mutex::new(Vec::new()));
    let cfg = ServerConfig {
        request_timeout: Some(Duration::from_millis(200)),
        ..ServerConfig::default()
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let mut server = match Server::with_config(
        [addr],
        cfg,
        length_prefixed(PrefixWidth::U32, Endian::Big, false, echo),
    ) {
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
            // A valid prefix declaring 64 bytes, then only 10 of them: the
            // body recv accrues partial progress before the clock fires.
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

#[test]
fn request_timeout_reclaims_stalled_more_scan() {
    // SECURITY (slow-loris, chunk-read path): a `More`/delimiter framer reads
    // in chunks that complete on any byte, so the request clock bounds them by
    // inactivity. A peer that sends a partial header (no `\r\n\r\n`) then stalls
    // has its non-idle chunk read time out and its slot reclaimed — the
    // `idle_timeout` clock (unset here) would never fire mid-scan.
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
            // A partial LSP header with no `\r\n\r\n` terminator, then stall:
            // the scan's next chunk read waits for a byte that never comes.
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

/// Read an LSP-framed message: header up to `\r\n\r\n`, then `Content-Length`
/// body bytes.
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
// A real end-to-end TLS handshake around the server's kernel-TLS transport.
// The library brings no TLS crate; these tests use OpenSSL as a dev-dependency
// for both the consumer-side handshake worker and the client — exactly the
// split a real consumer implements. Skips when the kernel lacks the `tls` ULP,
// or when libssl cannot engage kTLS at all ([`ktls_engages`] — Ubuntu ships
// OpenSSL 3.0 without `enable-ktls`).

use foreign_types::ForeignType; // Ssl::as_ptr for the raw BIO/SSL_accept path
use openssl::ssl::{
    Ssl, SslAcceptor, SslConnector, SslMethod, SslOptions, SslVerifyMode,
};
use std::net::TcpListener;
use std::os::fd::{AsRawFd, RawFd};

const SSL_OP_ENABLE_KTLS: u64 = 1 << 3; // SSL_OP_BIT(3); no named crate const
const BIO_NOCLOSE: libc::c_int = 0;
const SOL_TLS: libc::c_int = 282;
const TLS_TX: libc::c_int = 1;
const TLS_RX: libc::c_int = 2;

/// True when the `kTLS listener requires ... TLS ULP` validation fires — the
/// dev kernel lacks `CONFIG_TLS`. Force the test on known-good hosts with
/// `TRUENAS_ROS_REQUIRE_KTLS`.
fn ktls_unsupported(e: &Error) -> bool {
    let unsupported =
        matches!(e, Error::Validation(m) if m.contains("kernel TLS ULP"));
    if unsupported {
        assert!(
            std::env::var_os("TRUENAS_ROS_REQUIRE_KTLS").is_none(),
            "TRUENAS_ROS_REQUIRE_KTLS set but the kernel lacks the tls ULP: {e}"
        );
    }
    unsupported
}

/// A throwaway self-signed cert + PKCS#8 key (PEM) for the test server.
fn self_signed() -> (Vec<u8>, Vec<u8>) {
    use openssl::asn1::Asn1Time;
    use openssl::hash::MessageDigest;
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
    use openssl::x509::{X509NameBuilder, X509};
    let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "localhost").unwrap();
    let name = name.build();
    let mut b = X509::builder().unwrap();
    b.set_version(2).unwrap();
    b.set_subject_name(&name).unwrap();
    b.set_issuer_name(&name).unwrap();
    b.set_pubkey(&key).unwrap();
    b.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    b.set_not_after(&Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    b.sign(&key, MessageDigest::sha256()).unwrap();
    (
        b.build().to_pem().unwrap(),
        key.private_key_to_pem_pkcs8().unwrap(),
    )
}

/// Build a kTLS-enabled OpenSSL acceptor (mirrors jsonrpc_rust's `build_acceptor`
/// for `TlsMode::Kernel`): `SSL_OP_ENABLE_KTLS` + no session tickets (so there
/// is no post-handshake server write to perturb the installed TX sequence).
fn ktls_acceptor(cert_pem: &[u8], key_pem: &[u8]) -> SslAcceptor {
    use openssl::pkey::PKey;
    use openssl::x509::X509;
    let mut b = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
    b.set_private_key(&PKey::private_key_from_pem(key_pem).unwrap())
        .unwrap();
    b.set_certificate(&X509::from_pem(cert_pem).unwrap())
        .unwrap();
    b.check_private_key().unwrap();
    b.set_options(SslOptions::from_bits_retain(SSL_OP_ENABLE_KTLS));
    b.set_num_tickets(0).unwrap();
    b.build()
}

/// The consumer's handshake worker: run the blocking server TLS handshake on
/// the furnished fd over a socket BIO (so OpenSSL installs kTLS on the socket),
/// confirm kTLS engaged both directions, then close the furnished fd (the pool
/// descriptor keeps the kTLS socket). Mirrors jsonrpc_rust's `ktls_accept`.
/// Shuts the server down when dropped. Every test here runs `serve_forever`
/// on the test thread and drives the client from a spawned thread, so a
/// panicking client (a failed assert, an I/O expect) would otherwise skip
/// its shutdown call and strand the server — hanging the whole test binary
/// instead of going red. A clone of the handle in this guard makes the
/// panic surface through `client.join()`.
struct ShutdownOnDrop(ShutdownHandle);

impl Drop for ShutdownOnDrop {
    fn drop(&mut self) {
        self.0.shutdown();
    }
}

fn ktls_server_handshake(
    fd: RawFd,
    acceptor: &SslAcceptor,
) -> Result<(), String> {
    // This helper owns the furnished fd: EVERY return path — the three error
    // returns included — must close it (the set_tls_handshake contract), or
    // each failed handshake leaks a process fd that pins the socket past the
    // server's teardown. The BIO below is BIO_NOCLOSE, so dropping the SSL
    // never closes the fd; this guard does, and the pool descriptor keeps the
    // kTLS socket alive for serving.
    struct FdCloser(RawFd);
    impl Drop for FdCloser {
        fn drop(&mut self) {
            // SAFETY: closing the furnished fd this guard owns.
            unsafe { libc::close(self.0) };
        }
    }
    let _fd_owner = FdCloser(fd);
    // SSL_accept wants a blocking socket. The furnished fd aliases the pool
    // descriptor's file, but io_uring recv/send are unaffected by O_NONBLOCK.
    // SAFETY: fcntl on a live fd.
    unsafe {
        let fl = libc::fcntl(fd, libc::F_GETFL);
        libc::fcntl(fd, libc::F_SETFL, fl & !libc::O_NONBLOCK);
    }
    let ssl = Ssl::new(acceptor.context()).map_err(|e| e.to_string())?;
    // SAFETY: a BIO_NOCLOSE socket BIO over `fd`; SSL owns the BIO (freed on
    // drop), and `fd` outlives `ssl` here.
    let rc = unsafe {
        let bio = openssl_sys::BIO_new_socket(fd, BIO_NOCLOSE);
        if bio.is_null() {
            return Err("BIO_new_socket".into());
        }
        openssl_sys::SSL_set_bio(ssl.as_ptr(), bio, bio);
        openssl_sys::SSL_accept(ssl.as_ptr())
    };
    if rc != 1 {
        return Err(format!("SSL_accept returned {rc}"));
    }
    for (dir, label) in [(TLS_TX, "TX"), (TLS_RX, "RX")] {
        let mut buf = [0u8; 4];
        let mut len = buf.len() as libc::socklen_t;
        // SAFETY: getsockopt writes up to `len` bytes into `buf`.
        let r = unsafe {
            libc::getsockopt(
                fd,
                SOL_TLS,
                dir,
                buf.as_mut_ptr().cast(),
                &mut len,
            )
        };
        if r != 0 {
            return Err(format!("kTLS not engaged for {label}"));
        }
    }
    drop(ssl); // BIO_NOCLOSE → fd not closed; kTLS stays on the socket
    Ok(()) // _fd_owner closes the furnished fd
}

/// A TLS client that connects, handshakes (no cert verification — the server
/// cert is self-signed), and returns the `SslStream` for framed I/O.
fn tls_connect(
    v4: SocketAddrV4,
) -> io::Result<openssl::ssl::SslStream<TcpStream>> {
    let mut cb = SslConnector::builder(SslMethod::tls()).unwrap();
    cb.set_verify(SslVerifyMode::NONE);
    let connector = cb.build();
    let tcp = connect_tcp(v4)?;
    let mut ssl = connector
        .configure()
        .unwrap()
        .verify_hostname(false)
        .into_ssl("localhost")
        .unwrap();
    ssl.set_connect_state();
    let mut stream = openssl::ssl::SslStream::new(ssl, tcp).unwrap();
    stream.connect().map_err(io::Error::other)?;
    Ok(stream)
}

/// `SSL_OP_ENABLE_KTLS` is best-effort: when OpenSSL cannot install kTLS it
/// silently falls back to userspace TLS records — a libssl built without
/// `enable-ktls` (Debian/Ubuntu only enable it from 3.2), a TLS 1.3 RX gap
/// (OpenSSL < 3.2), or a kernel missing the `tls` module. The handshake then
/// completes but the TX/RX confirmation fails, the worker rejects every
/// connection, and the kTLS data-path tests would fail rather than skip.
/// Probe once with a loopback handshake — the same acceptor, client, and
/// confirmation the tests use — so those tests can skip when this host's
/// OpenSSL cannot engage kTLS.
fn ktls_engages() -> &'static Result<(), String> {
    static PROBE: std::sync::OnceLock<Result<(), String>> =
        std::sync::OnceLock::new();
    PROBE.get_or_init(|| {
        let (cert, key) = self_signed();
        let acceptor = ktls_acceptor(&cert, &key);
        let listener =
            TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
        let std::net::SocketAddr::V4(v4) =
            listener.local_addr().map_err(|e| e.to_string())?
        else {
            return Err("bound v4".into());
        };
        let server = thread::spawn(move || -> Result<(), String> {
            let (stream, _) = listener.accept().map_err(|e| e.to_string())?;
            // `ktls_server_handshake` owns (and closes) the fd it is given;
            // hand it a dup and let the `TcpStream` keep the socket.
            // SAFETY: dup of a live fd.
            let fd = unsafe { libc::dup(stream.as_raw_fd()) };
            if fd < 0 {
                return Err("dup".into());
            }
            ktls_server_handshake(fd, &acceptor)
        });
        match tls_connect(v4) {
            Ok(stream) => {
                let served = server
                    .join()
                    .map_err(|_| "probe server panicked".to_string())?;
                drop(stream); // keep the session open until the server confirmed
                served
            }
            Err(e) => {
                // The client end is already gone, so the server side unblocks
                // on EOF by itself; don't wait on it.
                drop(server);
                Err(e.to_string())
            }
        }
    })
}

/// The OpenSSL-side skip for the kTLS data-path tests: `false` when this host
/// engages kTLS end to end, `true` (with a visible note) when it cannot — or
/// a hard failure when `TRUENAS_ROS_REQUIRE_KTLS` says skipping is forbidden.
fn ktls_openssl_unsupported() -> bool {
    match ktls_engages() {
        Ok(()) => false,
        Err(e) => {
            assert!(
                std::env::var_os("TRUENAS_ROS_REQUIRE_KTLS").is_none(),
                "TRUENAS_ROS_REQUIRE_KTLS set but {} cannot engage kTLS: {e}",
                openssl::version::version(),
            );
            eprintln!(
                "skipping kTLS data-path test: {} cannot engage kTLS ({e})",
                openssl::version::version(),
            );
            true
        }
    }
}

#[test]
fn ktls_echo_roundtrip() {
    // End-to-end: a kTLS listener, the consumer's OpenSSL handshake worker, and
    // a real TLS client. Requests/replies frame with the usual 4-byte prefix
    // over the kernel-TLS transport; the server sees plaintext (kernel decrypts)
    // and the framer is unchanged.
    use std::sync::Mutex;
    if ktls_openssl_unsupported() {
        return;
    }
    let (cert, key) = self_signed();
    let acceptor = Arc::new(ktls_acceptor(&cert, &key));
    let seen_listener: Arc<Mutex<Option<ServerAddr>>> =
        Arc::new(Mutex::new(None));
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let proto = length_prefixed(
        PrefixWidth::U32,
        Endian::Big,
        false,
        |_h: &[u8], body: &[u8], _p: &ClientAddr| Some(echo_frame(body)),
    );
    let mut server = match Server::bind(
        [truenas_ros::net::server::Listen::tls(addr)],
        proto,
    ) {
        Ok(s) => s,
        Err(e) if should_skip(&e) || ktls_unsupported(&e) => return,
        Err(e) => panic!("bind: {e}"),
    };
    {
        let acceptor = Arc::clone(&acceptor);
        let seen = Arc::clone(&seen_listener);
        server.set_tls_handshake(move |fd, inc, deferral| {
            // The handshake handler is the kTLS per-listener policy hook.
            *seen.lock().unwrap() = Some(inc.listener_addr.clone());
            let acceptor = Arc::clone(&acceptor);
            thread::spawn(move || match ktls_server_handshake(fd, &acceptor) {
                Ok(()) => deferral.ready(()),
                Err(_) => deferral.reject(),
            });
        });
    }
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();

    let client = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop); // shuts down even if this panics
        (|| -> io::Result<()> {
            let mut s = tls_connect(v4)?;
            for msg in [b"tls-hello".as_slice(), b"second", b"third-and-final"]
            {
                send_framed(&mut s, msg)?;
                assert_eq!(recv_framed(&mut s)?, msg, "kTLS echo mismatch");
            }
            // A larger payload spanning multiple TLS records still frames.
            let big = vec![0x5au8; 40 * 1024];
            send_framed(&mut s, &big)?;
            assert_eq!(recv_framed(&mut s)?, big);
            Ok(())
        })()
        .expect("client io");
    });

    server.serve_forever().expect("serve_forever");
    client.join().expect("thread join");
    // The handshake handler saw the resolved listener the connection hit.
    let seen = seen_listener.lock().unwrap().clone();
    assert!(
        matches!(seen, Some(ServerAddr::Tcp(a)) if a == v4),
        "handshake handler got listener {seen:?}, expected {v4}"
    );
}

#[test]
fn ktls_rejected_handshake_sheds() {
    // A handshake that fails (the client speaks plaintext, not TLS) must reject
    // cleanly — the worker calls deferral.reject(), the slot is shed — and the
    // server keeps serving later TLS connections.
    if ktls_openssl_unsupported() {
        return;
    }
    let (cert, key) = self_signed();
    let acceptor = Arc::new(ktls_acceptor(&cert, &key));
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let proto = length_prefixed(
        PrefixWidth::U32,
        Endian::Big,
        false,
        |_h: &[u8], body: &[u8], _p: &ClientAddr| Some(echo_frame(body)),
    );
    let mut server = match Server::bind(
        [truenas_ros::net::server::Listen::tls(addr)],
        proto,
    ) {
        Ok(s) => s,
        Err(e) if should_skip(&e) || ktls_unsupported(&e) => return,
        Err(e) => panic!("bind: {e}"),
    };
    {
        let acceptor = Arc::clone(&acceptor);
        server.set_tls_handshake(move |fd, _inc, deferral| {
            let acceptor = Arc::clone(&acceptor);
            thread::spawn(move || match ktls_server_handshake(fd, &acceptor) {
                Ok(()) => deferral.ready(()),
                Err(_) => deferral.reject(),
            });
        });
    }
    let stats = server.stats_handle();
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();

    let client = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop); // shuts down even if this panics
        (|| -> io::Result<()> {
            // Plaintext junk → the server's SSL_accept fails → reject → shed.
            let mut bad = connect_tcp(v4)?;
            bad.set_read_timeout(Some(Duration::from_secs(3)))?;
            let _ = bad.write_all(b"not a TLS ClientHello\r\n\r\n");
            let mut buf = Vec::new();
            let _ = bad.read_to_end(&mut buf); // EOF / reset / timeout
            drop(bad);
            // A real TLS client still works afterwards.
            let mut s = tls_connect(v4)?;
            send_framed(&mut s, b"after-reject")?;
            assert_eq!(recv_framed(&mut s)?, b"after-reject");
            Ok(())
        })()
        .expect("client io");
    });

    server.serve_forever().expect("serve_forever");
    client.join().expect("thread join");
    // The client read the rejected connection to EOF (the shed's FIN) before its
    // real TLS roundtrip, so the reject-shed is already counted here.
    assert!(
        stats.snapshot().shed >= 1,
        "the rejected handshake should be shed (shed={})",
        stats.snapshot().shed
    );
}

#[test]
fn ktls_handshake_timeout_sheds_parked_slot() {
    // SECURITY (#2): a kTLS connection whose handshake never completes (the
    // consumer's worker never calls back) parks a pool slot — it holds a
    // descriptor but has no in-flight recv/send, so neither idle_timeout nor
    // request_timeout (both linked to a recv) can reach it. With
    // `tls_handshake_timeout` set the park is bounded: the slot is shed. Here
    // the handshake handler closes the furnished fd and *holds* the deferral
    // (never resolving, so no reject-shed), leaving only the timeout to reclaim.
    let cfg = ServerConfig {
        tls_handshake_timeout: Some(Duration::from_millis(250)),
        pool_size: 4,
        ..ServerConfig::default()
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let proto = length_prefixed(
        PrefixWidth::U32,
        Endian::Big,
        false,
        |_h: &[u8], body: &[u8], _p: &ClientAddr| Some(echo_frame(body)),
    );
    let mut server = match Server::with_config(
        [truenas_ros::net::server::Listen::tls(addr)],
        cfg,
        proto,
    ) {
        Ok(s) => s,
        Err(e) if should_skip(&e) || ktls_unsupported(&e) => return,
        Err(e) => panic!("bind: {e}"),
    };
    // Buffer each deferral (never resolving it → no reject-shed) and close the
    // fd we won't use; the held deferrals are released when `keep_rx` drops.
    let (keep_tx, keep_rx) = std::sync::mpsc::channel();
    server.set_tls_handshake(move |fd, _inc, deferral| {
        // SAFETY: closing the furnished fd this handler owns and won't use.
        unsafe { libc::close(fd) };
        let _ = keep_tx.send(deferral);
    });
    let stats = server.stats_handle();
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();

    let client = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone()); // fail fast on panic
                                                  // Connect (raw TCP); the server furnishes the fd and parks. We never
                                                  // handshake — the park timeout must shed each slot.
        let peers: Vec<_> =
            (0..3).map(|_| connect_tcp(v4).expect("connect")).collect();
        let t0 = Instant::now();
        while stats.snapshot().shed < 3 && t0.elapsed() < Duration::from_secs(3)
        {
            thread::sleep(Duration::from_millis(20));
        }
        assert!(
            stats.snapshot().shed >= 3,
            "parked handshakes should be shed by tls_handshake_timeout (shed={})",
            stats.snapshot().shed
        );
        drop(peers);
        stop.shutdown();
    });

    server.serve_forever().expect("serve_forever");
    client.join().expect("thread join");
    drop(keep_rx); // release the held (now stale) deferrals
}

#[test]
fn ktls_close_notify_reports_tls_control() {
    // A polite TLS client ends its session with close_notify — on the wire a
    // 2-byte alert record. The server's parked exact header read completes
    // SHORT with record type 21 (alert), which must classify as TlsControl —
    // the documented reason for a peer's clean TLS close — not as
    // TruncatedMessage.
    use std::sync::Mutex;
    if ktls_openssl_unsupported() {
        return;
    }
    let (cert, key) = self_signed();
    let acceptor = Arc::new(ktls_acceptor(&cert, &key));
    let reasons = Arc::new(Mutex::new(Vec::new()));
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let proto = length_prefixed(
        PrefixWidth::U32,
        Endian::Big,
        false,
        |_h: &[u8], body: &[u8], _p: &ClientAddr| Some(echo_frame(body)),
    );
    let mut server = match Server::bind(
        [truenas_ros::net::server::Listen::tls(addr)],
        proto,
    ) {
        Ok(s) => s,
        Err(e) if should_skip(&e) || ktls_unsupported(&e) => return,
        Err(e) => panic!("bind: {e}"),
    };
    {
        let acceptor = Arc::clone(&acceptor);
        server.set_tls_handshake(move |fd, _inc, deferral| {
            let acceptor = Arc::clone(&acceptor);
            thread::spawn(move || match ktls_server_handshake(fd, &acceptor) {
                Ok(()) => deferral.ready(()),
                Err(_) => deferral.reject(),
            });
        });
    }
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
        let _stop = ShutdownOnDrop(stop.clone()); // fail fast on panic
        (|| -> io::Result<()> {
            let mut s = tls_connect(v4)?;
            send_framed(&mut s, b"bye-soon")?;
            assert_eq!(recv_framed(&mut s)?, b"bye-soon");
            // Clean TLS teardown: the close_notify lands on the server's
            // idle header read.
            s.shutdown().map_err(io::Error::other)?;
            // Give the alert time to complete the parked recv and close.
            thread::sleep(Duration::from_millis(100));
            Ok(())
        })()
        .expect("client io");
        stop.shutdown();
    });

    server.serve_forever().expect("serve_forever");
    client.join().expect("thread join");
    let got = reasons.lock().unwrap().clone();
    assert!(
        got.contains(&CloseReason::TlsControl),
        "close_notify must report TlsControl, got {got:?}"
    );
    assert!(
        !got.contains(&CloseReason::TruncatedMessage),
        "clean TLS close misread as truncation: {got:?}"
    );
}

#[test]
fn tcp_splice_body_over_ktls() {
    // A body splices zero-copy off a SOFTWARE kTLS socket, in the clear: the
    // kernel routes the splice through `tls_sw_splice_read`, which decrypts.
    //
    // The subtle case this pins down is the recvmsg→splice handoff. kTLS
    // decrypts a whole TLS record at a time, so when the 5-byte header read
    // lands inside a record that also carries body bytes, the kernel decrypts
    // the entire record, hands us 5 bytes, and stashes the record's ~16 KiB
    // plaintext remainder (all body) in its receive list; the splice must pick
    // that up before pulling the next record or it would silently truncate.
    //
    // Force the straddle: the client writes header+body as ONE buffer, so TLS
    // record 1 = [5-byte header][~16 KiB body prefix]. A bounded reader asserts
    // the FULL body arrives, in order.
    if ktls_openssl_unsupported() {
        return;
    }
    let (cert, key) = self_signed();
    let acceptor = Arc::new(ktls_acceptor(&cert, &key));
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: `pipe(2)` fills {read, write}.
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe");
    let (pipe_rd, pipe_wr) = (fds[0], fds[1]);

    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: splice_header(pipe_wr),
        body: |req: Request<'_, ()>| Response::Reply(echo_frame(&req.body)),
    };
    let mut server = match Server::bind(
        [truenas_ros::net::server::Listen::tls(addr)],
        proto,
    ) {
        Ok(s) => s,
        Err(e) if should_skip(&e) || ktls_unsupported(&e) => {
            // SAFETY: closing the test-owned pipe fds on the skip path.
            unsafe {
                libc::close(pipe_rd);
                libc::close(pipe_wr);
            }
            return;
        }
        Err(e) => panic!("bind: {e}"),
    };
    {
        let acceptor = Arc::clone(&acceptor);
        server.set_tls_handshake(move |fd, _inc, deferral| {
            let acceptor = Arc::clone(&acceptor);
            thread::spawn(move || match ktls_server_handshake(fd, &acceptor) {
                Ok(()) => deferral.ready(()),
                Err(_) => deferral.reject(),
            });
        });
    }
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();

    // Deliberately not a multiple of the 16 KiB TLS record size.
    const BODY: usize = 200_000;
    let payload: Vec<u8> = (0..BODY).map(|i| (i % 251) as u8).collect();

    // Bounded reader: drain up to BODY bytes off the pipe with a deadline (so a
    // truncating splice fails the assertion instead of hanging).
    let expected = payload.clone();
    let reader_stop = stop.clone();
    let reader = thread::spawn(move || {
        // SAFETY: make the read end non-blocking so the deadline loop works.
        unsafe {
            let fl = libc::fcntl(pipe_rd, libc::F_GETFL);
            libc::fcntl(pipe_rd, libc::F_SETFL, fl | libc::O_NONBLOCK);
        }
        let mut got = vec![0u8; BODY];
        let mut off = 0;
        let deadline = Instant::now() + Duration::from_secs(10);
        while off < BODY && Instant::now() < deadline {
            // SAFETY: read into `got[off..]`, within bounds.
            let n = unsafe {
                libc::read(
                    pipe_rd,
                    got.as_mut_ptr().add(off).cast(),
                    (BODY - off) as libc::size_t,
                )
            };
            if n > 0 {
                off += n as usize;
            } else {
                thread::sleep(Duration::from_millis(5));
            }
        }
        // SAFETY: done with the read end.
        unsafe { libc::close(pipe_rd) };
        // Graceful (not hard) shutdown so the now-idle connection is closed with
        // a FIN, unblocking the client's read promptly instead of leaving it on
        // its socket read-timeout.
        reader_stop.shutdown_graceful(Duration::from_secs(2));
        (off, got)
    });

    let client = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone());
        (|| -> io::Result<()> {
            let mut s = tls_connect(v4)?;
            // One combined write: header + body share TLS record boundaries.
            let mut frame = vec![b'S'];
            frame.extend_from_slice(&(BODY as u32).to_be_bytes());
            frame.extend_from_slice(&payload);
            s.write_all(&frame)?;
            s.flush()?;
            // Keep the connection open through the splice; unblocks when the
            // reader triggers the graceful shutdown and the server closes us.
            let mut buf = Vec::new();
            let _ = s.read_to_end(&mut buf);
            Ok(())
        })()
        .expect("client io");
    });

    server.serve_forever().expect("serve_forever");
    client.join().expect("client join");
    let (off, got) = reader.join().expect("reader join");
    assert_eq!(
        off, BODY,
        "kTLS splice moved {off} of {BODY} body bytes — rx_list truncation?"
    );
    assert_eq!(got, expected, "kTLS spliced body content mismatch");
    // SAFETY: closing the test-owned write end (the server only borrowed it).
    unsafe { libc::close(pipe_wr) };
}

#[test]
fn ktls_splice_body_slow_but_progressing_survives() {
    // The other half of the watchdog contract (the race the standalone-timeout
    // design must NOT lose): a kTLS splice that keeps making progress — even
    // slowly, spanning several `request_timeout` periods — must run to
    // completion. The watchdog re-arms on progress (`splice_remaining` fell
    // below its watermark) and only cancels on a full period of ZERO progress,
    // so a steadily-fed transfer is never mistaken for a stall.
    use std::sync::Mutex;
    if ktls_openssl_unsupported() {
        return;
    }
    let (cert, key) = self_signed();
    let acceptor = Arc::new(ktls_acceptor(&cert, &key));
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: `pipe(2)` fills {read, write}.
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe");
    let (pipe_rd, pipe_wr) = (fds[0], fds[1]);

    let reasons = Arc::new(Mutex::new(Vec::new()));
    let cfg = ServerConfig {
        request_timeout: Some(Duration::from_millis(200)),
        ..ServerConfig::default()
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: splice_header(pipe_wr),
        body: |req: Request<'_, ()>| Response::Reply(echo_frame(&req.body)),
    };
    let mut server = match Server::with_config(
        [truenas_ros::net::server::Listen::tls(addr)],
        cfg,
        proto,
    ) {
        Ok(s) => s,
        Err(e) if should_skip(&e) || ktls_unsupported(&e) => {
            // SAFETY: closing the test-owned pipe fds on the skip path.
            unsafe {
                libc::close(pipe_rd);
                libc::close(pipe_wr);
            }
            return;
        }
        Err(e) => panic!("bind: {e}"),
    };
    {
        let acceptor = Arc::clone(&acceptor);
        server.set_tls_handshake(move |fd, _inc, deferral| {
            let acceptor = Arc::clone(&acceptor);
            thread::spawn(move || match ktls_server_handshake(fd, &acceptor) {
                Ok(()) => deferral.ready(()),
                Err(_) => deferral.reject(),
            });
        });
    }
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

    // Six chunks fed ~120ms apart (< the 200ms timeout, so never a full idle
    // period), total wall time ~720ms = 3.6 timeout periods. A total-transfer
    // bound would kill this; the inactivity watchdog must not.
    const CHUNK: usize = 4096;
    const CHUNKS: usize = 6;
    const BODY: usize = CHUNK * CHUNKS;
    let payload: Vec<u8> = (0..BODY).map(|i| (i % 251) as u8).collect();
    let expected = payload.clone();

    let reader_stop = stop.clone();
    let reader = thread::spawn(move || {
        // SAFETY: non-blocking read end so the deadline loop works.
        unsafe {
            let fl = libc::fcntl(pipe_rd, libc::F_GETFL);
            libc::fcntl(pipe_rd, libc::F_SETFL, fl | libc::O_NONBLOCK);
        }
        let mut got = vec![0u8; BODY];
        let mut off = 0;
        let deadline = Instant::now() + Duration::from_secs(10);
        while off < BODY && Instant::now() < deadline {
            // SAFETY: read into `got[off..]`, within bounds.
            let n = unsafe {
                libc::read(
                    pipe_rd,
                    got.as_mut_ptr().add(off).cast(),
                    (BODY - off) as libc::size_t,
                )
            };
            if n > 0 {
                off += n as usize;
            } else {
                thread::sleep(Duration::from_millis(5));
            }
        }
        // SAFETY: done with the read end.
        unsafe { libc::close(pipe_rd) };
        reader_stop.shutdown_graceful(Duration::from_secs(2));
        (off, got)
    });

    let client = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone());
        (|| -> io::Result<()> {
            let mut s = tls_connect(v4)?;
            let mut hdr = vec![b'S'];
            hdr.extend_from_slice(&(BODY as u32).to_be_bytes());
            s.write_all(&hdr)?;
            s.flush()?;
            for c in 0..CHUNKS {
                thread::sleep(Duration::from_millis(120)); // < request_timeout
                s.write_all(&payload[c * CHUNK..(c + 1) * CHUNK])?;
                s.flush()?;
            }
            let mut buf = Vec::new();
            let _ = s.read_to_end(&mut buf);
            Ok(())
        })()
        .expect("client io");
    });

    server.serve_forever().expect("serve_forever");
    client.join().expect("client join");
    let (off, got) = reader.join().expect("reader join");
    assert_eq!(
        off, BODY,
        "slow-but-progressing splice was cut short at {off}"
    );
    assert_eq!(got, expected, "spliced body content mismatch");
    assert!(
        !reasons
            .lock()
            .unwrap()
            .contains(&CloseReason::RequestTimeout),
        "a progressing transfer was wrongly reclaimed: {:?}",
        reasons.lock().unwrap()
    );
    // SAFETY: closing the test-owned write end (read end closed by the reader).
    unsafe { libc::close(pipe_wr) };
}

#[test]
fn ktls_splice_body_stall_reclaimed() {
    // SECURITY (slow-loris, kTLS splice): `tls_sw_splice_read` blocks an
    // io-wq worker waiting for the next TLS record — it honors only
    // SPLICE_F_NONBLOCK (which the server must not set) and, unlike
    // `tcp_splice_read`, never the socket's O_NONBLOCK — so the plain-TCP
    // EAGAIN → readiness-poll path that carries the request clock NEVER runs
    // for kTLS. The clock is therefore linked to the kTLS splice itself: a
    // peer that completes the handshake, sends a SpliceBody header, and then
    // goes silent must be reclaimed by `request_timeout` — not pin its pool
    // slot plus a kernel io-wq thread until full shutdown (pool_size such
    // clients would deny all service, immune to every other timeout).
    use std::sync::Mutex;
    if ktls_openssl_unsupported() {
        return;
    }
    let (cert, key) = self_signed();
    let acceptor = Arc::new(ktls_acceptor(&cert, &key));
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: `pipe(2)` fills {read, write}.
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe");
    let (pipe_rd, pipe_wr) = (fds[0], fds[1]);

    let reasons = Arc::new(Mutex::new(Vec::new()));
    let cfg = ServerConfig {
        request_timeout: Some(Duration::from_millis(300)),
        ..ServerConfig::default()
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: splice_header(pipe_wr),
        body: |req: Request<'_, ()>| Response::Reply(echo_frame(&req.body)),
    };
    let mut server = match Server::with_config(
        [truenas_ros::net::server::Listen::tls(addr)],
        cfg,
        proto,
    ) {
        Ok(s) => s,
        Err(e) if should_skip(&e) || ktls_unsupported(&e) => {
            // SAFETY: closing the test-owned pipe fds on the skip path.
            unsafe {
                libc::close(pipe_rd);
                libc::close(pipe_wr);
            }
            return;
        }
        Err(e) => panic!("bind: {e}"),
    };
    {
        let acceptor = Arc::clone(&acceptor);
        server.set_tls_handshake(move |fd, _inc, deferral| {
            let acceptor = Arc::clone(&acceptor);
            thread::spawn(move || match ktls_server_handshake(fd, &acceptor) {
                Ok(()) => deferral.ready(()),
                Err(_) => deferral.reject(),
            });
        });
    }
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
        (|| -> io::Result<()> {
            let mut s = tls_connect(v4)?;
            // SpliceBody header declaring 1 MiB, then silence: the kTLS
            // splice blocks awaiting a record; only its linked clock can
            // reclaim the slot.
            let mut hdr = vec![b'S'];
            hdr.extend_from_slice(&(1024u32 * 1024).to_be_bytes());
            s.write_all(&hdr)?;
            s.flush()?;
            let t0 = Instant::now();
            let mut one = [0u8; 1];
            // Server closes us at the clock: EOF, reset, or a TLS-layer
            // error — anything but a hang (the underlying socket carries a
            // 10s read timeout that would surface as an error here).
            match s.read(&mut one) {
                Ok(0) | Err(_) => {}
                Ok(n) => panic!("unexpected {n} byte(s) from a stalled conn"),
            }
            assert!(
                t0.elapsed() < Duration::from_millis(2500),
                "stalled kTLS splice reclaimed only after {:?}",
                t0.elapsed()
            );
            // The slot is free again: a fresh connection round-trips.
            let mut ok = tls_connect(v4)?;
            splice_frame(&mut ok, b'C', b"after")?;
            assert_eq!(recv_framed(&mut ok)?, b"after");
            Ok(())
        })()
        .expect("client io");
        stop.shutdown();
    });

    server.serve_forever().expect("serve_forever");
    client.join().expect("client join");
    assert!(
        reasons
            .lock()
            .unwrap()
            .contains(&CloseReason::RequestTimeout),
        "stalled kTLS splice must close as RequestTimeout, got {:?}",
        reasons.lock().unwrap()
    );
    // SAFETY: closing the test-owned pipe fds (nothing was spliced).
    unsafe {
        libc::close(pipe_rd);
        libc::close(pipe_wr);
    }
}
