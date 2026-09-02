//! Integration tests for the `net::server` module - live loopback echo over
//! TCP and AF_UNIX with a 4-byte big-endian length-prefix framing, exercising
//! the full ring path (multishot accept -> recv-header -> frame -> recv-body ->
//! handler -> send -> keep-alive).
//!
//! Like `test/zfs.rs` and `test/configparser_compat.rs`, these **skip** (return
//! early) when io_uring is unavailable - the CI/dev sandbox blocks the io_uring
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
    Body, ClientAddr, CloseReason, ControlHandle, DeferPermit, Deferred,
    Endian, Framing, Incoming, PeerCred, PrefixWidth, Protocol, PushHandle,
    Request, Responder, Response, Server, ServerAddr, ServerConfig,
    ShutdownHandle, length_prefix_header, length_prefixed, setup_ring,
};
use truenas_ros::{Errno, Error};

/// Errors that mean "io_uring is unavailable here" - an environmental skip.
///
/// Deliberately *excludes* `EINVAL`: for io_uring that means the kernel rejected
/// our setup arguments - a real bug we want to fail on, not skip.
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

/// `unix_peercred` needs io_uring socket commands on `AF_UNIX` (Linux >=
/// 6.18.16); on older kernels `with_config`'s startup probe fails with a
/// validation error. Environmental, like `should_skip` - but force the test
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
/// variable-length-header framer a caller writes - the server ships no such
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
    drop(s); // close -> keep-alive ends (server recv-header gets EOF)
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
fn tcp_vectored_reply() {
    // A `ReplyVectored`'s segments reach the client concatenated in order (one
    // vectored write), and the reply retires its `outstanding` count exactly
    // once - only the last segment is `is_reply` - so keep-alive keeps
    // serving: three sequential roundtrips are not stranded behind the
    // read-ahead cap. A wrong `is_reply` count would wedge the second.
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(
            PrefixWidth::U32,
            Endian::Big,
            false,
        ),
        body: |req: Request<'_, ()>| {
            let Request { body, .. } = req;
            // Echo as two segments: the length prefix, then the payload.
            let payload = body[..].to_vec();
            let prefix = (payload.len() as u32).to_be_bytes().to_vec();
            Response::ReplyVectored {
                segments: vec![prefix.into(), payload.into()],
                close: false,
            }
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
        let _stop = ShutdownOnDrop(stop.clone());
        let r = connect_tcp(v4).and_then(|s| {
            framed_roundtrips(
                s,
                &[b"one" as &[u8], b"two", b"the third message"],
            )
        });
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
            b"the third message".to_vec(),
        ]
    );
}

#[test]
fn unix_echo() {
    let dir = truenas_ros::tempdir().unwrap();
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
    // Several messages on ONE connection - proves the connection is reused.
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
    // each write flushed with a gap - so recv-header and recv-body each span
    // multiple TCP segments. This passes only if MSG_WAITALL accumulates the
    // short reads in-kernel (without it, recv-header returns 1 < 4 -> close).
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
    // Tiny pool, connections opened one at a time (never exceeding capacity) --
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
    // SECURITY regression - fixed-slot reuse use-after-free / cross-connection
    // corruption. When a connection is torn down on a bare-CLOSE path while an
    // op is still in flight on its descriptor, that op pins the kernel resource
    // node: the CLOSE frees the table slot and bitmap bit at issue and biases
    // the next accept to that same index, but the pinned op keeps the old
    // socket and its buffers alive. A reuse-accept then reaches
    // `accept_connection` and overwrites the still-`Serving` slot (freed only
    // at ops==0) - dropping the live connection under the in-flight op, and,
    // because the generation never bumps on reuse-without-free, later steering
    // that op's completion onto whatever connection now holds the slot. The fix
    // cancels the in-flight op and defers the CLOSE until it reaps, so the slot
    // frees cleanly before any reuse-accept can land.
    //
    // Repro with a wide, deterministic window: a subscriber triggers a large
    // push to itself, then half-closes its WRITE side (the server's idle recv
    // sees EOF -> PeerClosed, a bare close) while keeping its READ side open
    // and never reading - so the push send stalls in flight, pinning the slot
    // indefinitely. A fresh echo then reuses the freed index. Without the fix
    // the reuse corrupts the connection (wrong reply, a loop panic, or a hang);
    // with it, every echo gets its own correct reply and the server stays live.
    use std::net::Shutdown;
    use std::sync::Mutex;
    const ROUNDS: usize = 8;
    const PUSH: usize = 16 * 1024 * 1024; // stalls in flight (peer never reads it)
    let sub_handle: Arc<Mutex<Option<PushHandle>>> = Arc::new(Mutex::new(None));
    let cfg = ServerConfig {
        pool_size: 4, // small -> the freed index is reused
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
                // Half-close our WRITE side: the server's idle recv sees EOF ->
                // PeerClosed, a bare close - but the large push to us is still
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
    // then reads exactly N body bytes - a header the old fixed-size model can't
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
    // `Deferred`; the server sends it on the next wake, and keep-alive resumes --
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
            // Move OWNED inputs to the worker - never a borrow of connection
            // state - then detach the reply handle and return to the loop.
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
            s.read_to_end(&mut buf)?; // dropped Deferred closed us -> EOF
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
fn tcp_redelivered_request() {
    // A body handler stashes the request in its connection state, defers, and
    // the worker asks for a SECOND delivery via `Deferred::redeliver` instead
    // of supplying bytes - the pattern protocol glue (http) uses to complete a
    // parked request on the server thread. The rerun sees the stash, replies,
    // and keep-alive continues: two messages each make the full
    // park-and-redeliver round trip on one connection.
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    type Stash = Option<Vec<u8>>;
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(None::<Vec<u8>>),
        header: length_prefix_header::<Stash>(
            PrefixWidth::U32,
            Endian::Big,
            false,
        ),
        body: |req: Request<'_, Stash>| {
            let Request {
                body,
                responder,
                state,
                ..
            } = req;
            match state.take() {
                // Second delivery: the frame is empty; answer from the stash.
                Some(stashed) => {
                    Response::Reply(echo_frame(&stashed.to_ascii_uppercase()))
                }
                // First delivery: retain the request, park, redeliver later.
                None => {
                    *state = Some(body.to_vec());
                    let (deferred, permit) = responder.defer();
                    thread::spawn(move || {
                        thread::sleep(Duration::from_millis(10));
                        deferred.redeliver();
                    });
                    Response::Defer(permit)
                }
            }
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
    let stats = server.stats_handle();
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
    // Each message was delivered twice (park, then redelivery) and answered
    // exactly once.
    let s = stats.snapshot();
    assert_eq!(s.requests, 4, "two deliveries per message");
    assert_eq!(s.deferred, 2, "one park per message");
    assert_eq!(s.replies, 2, "one reply per message");
}

#[test]
fn tcp_stale_redeliver_dropped() {
    // A handler answers INLINE while leaking a `Deferred` whose worker later
    // calls `redeliver()`. The request was never opened as deferred, so the
    // late redelivery must be inert - no extra handler run, no extra reply --
    // and the connection stays healthy for a second round trip.
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
            let reply = echo_frame(&body);
            let (deferred, permit) = responder.defer();
            let _ = permit; // answered inline: the Deferred goes stale
            thread::spawn(move || {
                thread::sleep(Duration::from_millis(30));
                deferred.redeliver();
            });
            Response::Reply(reply)
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
    let stats = server.stats_handle();
    let stop = server.shutdown_handle();

    let client = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone()); // fail fast on panic
        let r = (|| -> io::Result<Vec<u8>> {
            let mut s = connect_tcp(v4)?;
            let first = framed_roundtrips(&mut s, &[b"one"])?;
            // Let the stale redeliver fire against the answered request.
            thread::sleep(Duration::from_millis(60));
            let second = framed_roundtrips(&mut s, &[b"two"])?;
            Ok([first, second].concat().concat())
        })();
        stop.shutdown();
        r
    });

    server.serve_forever().expect("serve_forever");
    let bytes = client.join().expect("thread join").expect("client io");
    assert_eq!(bytes, b"onetwo".to_vec());
    // The stale redelivery ran no handler and sent nothing.
    let s = stats.snapshot();
    assert_eq!(s.requests, 2, "no handler rerun from the stale redeliver");
    assert_eq!(s.replies, 2);
}

/// Borrow a furnished detach fd as a BLOCKING stream WITHOUT owning it - the
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
    // does) would otherwise leave the resumed connection's socket blocking --
    // silently disabling the splice path's EAGAIN -> readiness-poll slow-loris
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
            drop(detached); // lost worker -> Drop closes the connection
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
            s.read_to_end(&mut buf)?; // dropped Detached closed us -> EOF
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
fn tcp_deferred_worker_close_ends_the_connection() {
    // `Deferred::close` is the worker deciding the request is fatal - distinct
    // from dropping the handle, which closes only because a lost worker must
    // not leak the parked slot. Both end the connection and both report
    // `WorkerClosed`, so a test of the drop path says nothing about whether
    // the deliberate one works. The close is also final: a request answered
    // this way is gone, so the pipelined follower behind it is not served.
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
            if &body[..] == b"fatal" {
                let (deferred, permit) = responder.defer();
                thread::spawn(move || {
                    thread::sleep(Duration::from_millis(10));
                    deferred.close(); // deliberate, not a dropped handle
                });
                Response::Defer(permit)
            } else {
                Response::Reply(echo_frame(&body))
            }
        },
    };
    let mut server = match Server::bind([addr], proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind: {e}"),
    };
    let reasons = close_reason_channel(&mut server);
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();

    let client = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone());
        let r = (|| -> io::Result<Vec<u8>> {
            let mut s = connect_tcp(v4)?;
            send_framed(&mut s, b"ping")?;
            assert_eq!(
                recv_framed(&mut s)?,
                b"ping",
                "serving before the close"
            );
            let _ = send_framed(&mut s, b"fatal");
            let mut tail = Vec::new();
            s.read_to_end(&mut tail)?;
            Ok(tail)
        })();
        stop.shutdown();
        r
    });

    server.serve_forever().expect("serve_forever");
    match client.join().expect("thread join") {
        Ok(tail) => assert!(
            tail.is_empty(),
            "a closed request must send nothing, got {tail:?}"
        ),
        Err(e) => assert_eq!(e.kind(), io::ErrorKind::ConnectionReset),
    }
    assert_eq!(
        reasons.try_recv().ok(),
        Some(CloseReason::WorkerClosed),
        "a worker-side close is reported as WorkerClosed",
    );
}

#[test]
fn handle_types_are_debug() {
    // The reply/push/detach handles are what a consumer holds when something
    // goes wrong in its own worker, so they are what lands in its logs. Each
    // is `finish_non_exhaustive` and each deliberately withholds its channel
    // and routing token - a `Debug` that printed the token would put a
    // forgeable routing capability in a log file.
    use std::sync::mpsc;
    let (seen_tx, seen_rx) = mpsc::channel::<(&'static str, String)>();
    let worker_tx = seen_tx.clone();
    let detach_tx = seen_tx.clone();
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(
            PrefixWidth::U32,
            Endian::Big,
            false,
        ),
        body: move |req: Request<'_, ()>| {
            let Request {
                body, responder, ..
            } = req;
            if &body[..] == b"detach" {
                return Response::Detach(responder.detach());
            }
            // `push_handle` borrows, so it can be minted before `defer`
            // consumes the responder.
            let push = responder.push_handle();
            let _ = seen_tx.send(("push", format!("{push:?}")));
            let _ = seen_tx.send(("responder", format!("{responder:?}")));
            let (deferred, permit) = responder.defer();
            let worker_tx = worker_tx.clone();
            thread::spawn(move || {
                let _ = worker_tx.send(("deferred", format!("{deferred:?}")));
                deferred.reply(echo_frame(b"ok"));
            });
            Response::Defer(permit)
        },
    };
    let mut server = match Server::bind([addr], proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind: {e}"),
    };
    server.set_detach_handler(move |_ctx, detached| {
        let _ = detach_tx.send(("detached", format!("{detached:?}")));
        detached.close();
    });
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();

    let client = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone());
        let r = (|| -> io::Result<()> {
            let mut s = connect_tcp(v4)?;
            send_framed(&mut s, b"handles")?;
            assert_eq!(recv_framed(&mut s)?, b"ok");
            let _ = send_framed(&mut s, b"detach");
            let mut tail = Vec::new();
            let _ = s.read_to_end(&mut tail);
            Ok(())
        })();
        stop.shutdown();
        r
    });

    server.serve_forever().expect("serve_forever");
    client.join().expect("thread join").expect("client io");

    let seen: std::collections::HashMap<&str, String> =
        seen_rx.try_iter().collect();
    for name in ["responder", "deferred", "push", "detached"] {
        let rendered = seen
            .get(name)
            .unwrap_or_else(|| panic!("{name} was never formatted"));
        assert!(
            rendered.ends_with(".. }"),
            "{name}'s Debug must stay non-exhaustive: {rendered}"
        );
        assert!(
            !rendered.contains("token") && !rendered.contains("Token"),
            "{name}'s Debug must not print its routing token: {rendered}"
        );
    }
    assert!(
        seen["responder"].starts_with("Responder {"),
        "unexpected shape: {}",
        seen["responder"]
    );
    assert!(
        seen["deferred"].starts_with("Deferred {"),
        "unexpected shape: {}",
        seen["deferred"]
    );
    // The routable handles name their slot, which is what makes one log line
    // traceable to one connection.
    for name in ["push", "detached"] {
        assert!(
            seen[name].contains("slot"),
            "{name}'s Debug should name its slot: {}",
            seen[name]
        );
    }
}

#[test]
fn push_of_an_empty_payload_is_a_no_op() {
    // An empty push is dropped at the handle rather than travelling to the
    // loop, so it never reaches the send queue. That matters because the
    // server frames nothing itself: a zero-length PDU handed to the socket
    // would be an empty write the peer cannot distinguish from a stall, and a
    // queued empty push would still consume backlog accounting. The client
    // must see exactly the one real push.
    use std::sync::Mutex;
    let stash: Arc<Mutex<Option<PushHandle>>> = Arc::new(Mutex::new(None));
    let for_body = Arc::clone(&stash);
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(
            PrefixWidth::U32,
            Endian::Big,
            false,
        ),
        body: move |req: Request<'_, ()>| {
            *for_body.lock().unwrap() = Some(req.responder.push_handle());
            Response::Reply(echo_frame(b"ok"))
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
        let _stop = ShutdownOnDrop(stop.clone());
        let r = (|| -> io::Result<Vec<u8>> {
            let mut s = connect_tcp(v4)?;
            send_framed(&mut s, b"sub")?;
            assert_eq!(recv_framed(&mut s)?, b"ok");
            let push = stash.lock().unwrap().clone().expect("stashed handle");
            push.push(Vec::new()); // dropped at the handle
            push.push(echo_frame(b"real"));
            // If the empty push had been queued it would arrive first and this
            // frame read would desynchronise.
            recv_framed(&mut s)
        })();
        stop.shutdown();
        r
    });

    server.serve_forever().expect("serve_forever");
    let got = client.join().expect("thread join").expect("client io");
    assert_eq!(got, b"real", "an empty push must not reach the wire");
}

/// A server whose replies are prefixed with a tag the control hook can
/// swap: the reload shape. The hook and the body handler share the tag
/// through an `Rc`, which only works because both were built on the loop
/// thread; the message that crosses threads is just the new tag. Each
/// applied message is acknowledged with the thread it ran on.
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
        header: length_prefix_header::<()>(
            PrefixWidth::U32,
            Endian::Big,
            false,
        ),
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

/// A control message runs on the server thread, between requests, and two
/// sent back to back apply in order: a request answered before the swap
/// carries the old tag, one answered after it carries the new one, and
/// nothing in between carries half of either.
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
            let (tag, ran_on) = acks
                .recv_timeout(Duration::from_secs(10))
                .expect("the hook ran");
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

/// A control message is still delivered while the server drains: the drain
/// is held open by a parked request, the message applies, and the parked
/// request's reply then carries the new tag.
#[test]
fn control_message_is_delivered_while_draining() {
    use std::cell::RefCell;
    use std::rc::Rc;

    let tag: Rc<RefCell<Vec<u8>>> = Rc::new(RefCell::new(b"A".to_vec()));
    let (park_tx, park_rx) = std::sync::mpsc::channel::<Deferred>();
    let for_body = Rc::clone(&tag);
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(
            PrefixWidth::U32,
            Endian::Big,
            false,
        ),
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
        // Prove the swap is what the handler now sees: the parked request
        // is redelivered after it, and its rerun (over an empty frame, as a
        // redelivery is) reads the tag.
        deferred.redeliver();
        assert_eq!(recv_framed(&mut parked)?, b"B");
        assert_eq!(parked.read(&mut b)?, 0, "closed once nothing is owed");
        Ok(())
    });
    server.serve_forever().expect("serve_forever");
    client.join().expect("client thread").expect("client io");
}

/// After the server has stopped a control message goes nowhere: the send
/// neither fails nor runs the hook, like a late push.
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

/// A handle minted but never given a hook drops its messages rather than
/// failing, and the server keeps serving.
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
    // `shutdown_graceful(0)` is documented as exactly `shutdown()`. The
    // distinction is not cosmetic: the graceful path arms a grace-period
    // TIMEOUT op and waits for connections to quiesce, so a zero duration
    // taken literally would arm a timer that fires immediately - or, worse,
    // a drain with no deadline at all. Delegating instead means a caller
    // computing a grace from configuration cannot accidentally hang the
    // shutdown by configuring zero.
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(
            PrefixWidth::U32,
            Endian::Big,
            false,
        ),
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
        // Serve one request so the loop is definitely running, hold the
        // connection open, then stop with a zero grace: a drain that waited
        // for this connection to quiesce would never return.
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
    // Reaching here at all is the assertion: an open connection did not hold
    // the loop open, because zero grace degraded to a hard stop.
    let held = client.join().expect("thread join").expect("client io");
    drop(held);
}

#[test]
fn tls_listener_without_a_handshake_handler_is_rejected() {
    // A kTLS listener cannot serve itself: the accept handler does not run for
    // kTLS connections, so `set_tls_handshake` IS the admission decision as
    // well as the handshake. Construction cannot catch a missing one - the
    // handler is installed after `bind` returns - so `serve_forever` refuses
    // to start rather than accept connections it can only drop. Fail-fast at
    // startup, not per connection at runtime.
    use truenas_ros::net::server::Listen;
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(
            PrefixWidth::U32,
            Endian::Big,
            false,
        ),
        body: |req: Request<'_, ()>| Response::Reply(echo_frame(&req.body)),
    };
    let mut server = match Server::bind([Listen::tls(addr)], proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        // A kernel without FIXED_FD_INSTALL rejects the listener earlier, with
        // its own validation message - environmental, not the case under test.
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
    // `Server`'s own `Debug` is what ends up in a consumer's startup log or
    // panic message, and it is the only way to see the resolved listener list
    // after an ephemeral `:0` bind. Bound but never served: `Drop` tears the
    // ring down on its own.
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(
            PrefixWidth::U32,
            Endian::Big,
            false,
        ),
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
    assert!(
        rendered.starts_with("Server {"),
        "unexpected Debug shape: {rendered}"
    );
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
    // IPv6 is not just IPv4 with a longer address here: the listener asks
    // for `AF_INET6` and sets
    // `IPV6_V6ONLY`, and the per-connection peer fetch has to request exactly
    // `sockaddr_in6`'s size - the kernel's `SO_PEERNAME` rejects an optlen
    // LARGER than the actual address, and the completion then requires the
    // returned length to match exactly, failing closed otherwise. So an
    // address-family size mistake does not corrupt an address, it sheds every
    // connection. A round-trip proves the sizing on both sides, and the peer
    // handed to the accept handler proves it parsed as a real V6 address
    // rather than something salvaged from a short pad.
    use std::net::SocketAddrV6;
    let (peer_tx, peer_rx) = std::sync::mpsc::channel::<ClientAddr>();
    let addr = ServerAddr::Tcp6("[::1]:0".parse::<SocketAddrV6>().unwrap());
    let proto = Protocol {
        accept: move |inc: Incoming<'_>| {
            let _ = peer_tx.send(inc.peer.clone());
            Some(())
        },
        header: length_prefix_header::<()>(
            PrefixWidth::U32,
            Endian::Big,
            false,
        ),
        body: |req: Request<'_, ()>| Response::Reply(echo_frame(&req.body)),
    };
    let mut server = match Server::bind([addr], proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        // A host with IPv6 compiled out or ::1 absent is environmental, like
        // the io_uring skip above.
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

/// Collect the close reasons a server reports, so a test can assert not just
/// that a connection died but that it died for the documented reason.
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

#[test]
fn tcp_detach_without_a_handler_closes() {
    // A body handler returns `Response::Detach` on a server that never called
    // `set_detach_handler` - a misconfiguration. The fd is furnished by the
    // kernel before anything notices, so the loop has to close the alias it
    // will not use, reattach the parked connection to `Serving`, and tear it
    // down; leaking the alias would pin the socket open past the close.
    // Reported as `HandlerClosed`, distinguishing the misconfig from an install
    // failure (`RecvError`) and from shutdown (`ShuttingDown`).
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
    // `DetachPermit` proves `Responder::detach` ran, but only its token proves
    // it ran for THIS request. A handler that mints a permit on one request,
    // stashes it in the connection state, and returns it on a later one is
    // claiming a detach the loop cannot route: the request it names is already
    // answered. The token check must reject it and close, rather than park a
    // request nothing can ever resolve.
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let proto = Protocol {
        accept: |_: Incoming<'_>| {
            Some(None::<truenas_ros::net::server::DetachPermit>)
        },
        header: length_prefix_header::<
            Option<truenas_ros::net::server::DetachPermit>,
        >(PrefixWidth::U32, Endian::Big, false),
        body: |req: Request<
            '_,
            Option<truenas_ros::net::server::DetachPermit>,
        >| {
            let Request {
                body,
                state,
                responder,
                ..
            } = req;
            if &body[..] == b"stash" {
                // Mint this request's permit and keep it; answer normally, so
                // the request it is stamped with is retired.
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
        panic!(
            "a foreign permit must never reach the detach handler: {detached:?}"
        );
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
    // Detach hands the raw socket to a worker, so the bytes that follow belong
    // to the fd rather than the framer. It is only safe on a fully settled
    // connection - nothing in flight and nothing buffered past this request.
    // A pipelined second message still sitting in the server's buffer is
    // exactly that: the worker would consume bytes the framer already owns, so
    // the loop must close instead.
    //
    // The framer has to be a scanning one for this to arise. A fixed-width
    // length prefix asks for exact byte counts, so a pipelined follower stays
    // in the socket and never reaches the buffer - the connection reads as
    // settled. `lsp_header` scans for a `\r\n\r\n` terminator and so consumes
    // opportunistically, which is what leaves the second message buffered.
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
            // Two complete LSP-framed messages in one write, so the scanning
            // framer buffers the second while the first is being handled.
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
    // `Incoming`, `Request` and `DetachContext` are `#[non_exhaustive]`, so a
    // consumer cannot build one to print - their `Debug` impls are reachable
    // only from inside a live handler. They are the types that end up in a
    // consumer's error logs, and each one
    // deliberately withholds fields: `Request` prints `header_len` rather than
    // the header, and neither it nor `DetachContext` prints the connection
    // state, which is where an application keeps its secrets. Assert the shape
    // and those omissions, not merely that formatting does not panic.
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let (tx, rx) = std::sync::mpsc::channel::<(String, String)>();
    let accept_tx = tx.clone();
    let detach_tx = tx.clone();
    let proto = Protocol {
        accept: move |inc: Incoming<'_>| {
            let _ = accept_tx.send(("incoming".into(), format!("{inc:?}")));
            Some(String::from("s3cret-state"))
        },
        header: length_prefix_header::<String>(
            PrefixWidth::U32,
            Endian::Big,
            false,
        ),
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
    // `Protocol`'s own `Debug` is reachable from outside; check it before the
    // server takes ownership.
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

    // `try_iter`, not `iter`: the sender clones live in handler closures the
    // server still owns, so waiting for the channel to hang up would deadlock.
    // Every send happened before `serve_forever` returned.
    let rendered: std::collections::HashMap<String, String> =
        rx.try_iter().collect();
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
    // consumer pipe with IORING_OP_SPLICE - zero-copy, the body never enters
    // the connection buffer - while CONTROL frames deliver to the body handler
    // as usual. Proves: (a) the spliced bytes arrive intact on the pipe; (b) a
    // body several times the pipe capacity drives the partial-splice resubmit
    // path and end-to-end backpressure (the ring never blocks - an io-wq worker
    // does - while the reader drains); (c) keep-alive framing resumes after the
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
            splice_frame(&mut s, b'C', b"ping")?; // control frame -> echo
            recv_framed(&mut s) // keep-alive resumed after the splice
        })();
        stop.shutdown();
        r
    });

    server.serve_forever().expect("serve_forever");
    // Close the write end BEFORE joining the reader: if anything upstream
    // delivered the body short, the reader then sees EOF and its `n > 0`
    // assertion fires with a real diagnostic - instead of blocking forever in
    // read() on a pipe this process still holds open (a hang, not a failure).
    // SAFETY: closing the test-owned write end (the server only borrowed it).
    unsafe { libc::close(pipe_wr) };
    reader.join().expect("reader join");
    let echo = client.join().expect("client join").expect("client io");
    assert_eq!(echo, b"ping", "keep-alive echo after splice");
}

#[test]
fn tcp_splice_body_close_mid_splice() {
    // Teardown while a body splice is genuinely IN FLIGHT - the security-critical
    // path. A splice's SQE fd is the consumer pipe, not the socket, so the
    // fd-keyed teardown cancel can't reach it: `close_conn` must cancel the
    // splice by its user_data and defer the index-freeing CLOSE until it reaps
    // (the splice pins the socket's fixed resource node exactly like a recv, so
    // CLOSE must be the connection's last op).
    //
    // Pin the splice in flight deterministically: a tiny pipe with NO reader, and
    // a body larger than it. The first splice fills the pipe; the next parks in
    // the kernel `wait_for_space` (pipe full, never drained) - an in-flight
    // splice blocked on an io-wq worker. A graceful drain deliberately does NOT
    // touch an in-flight splice (`begin_drain`'s quiesced test skips `splicing`
    // -- it cannot tell this wedged transfer from a healthy one, and truncating
    // a healthy one is the bug in `tcp_graceful_drain_lets_healthy_splice_finish`).
    // So the wedged splice is reclaimed only when the grace Deadline escalates to
    // a hard stop: this test proves that escalation's `cancel_and_reap_all` can
    // cancel a splice BLOCKED in io-wq (whose SQE fd is the pipe, not the socket)
    // rather than hanging on it - `serve_forever` returns promptly.
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
    // doesn't hang on a parked splice poll - `serve_forever` returns promptly.
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
    // `recving` is false - the drain sweep must not classify it quiesced and
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

            // The body completes and only THEN does the drain close us --
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
    // so a full pipe fails the splice with EAGAIN before the socket is read --
    // indistinguishable from "socket empty", which would spin the readiness
    // poll hot (POLLIN completes instantly, splice EAGAINs again) - and the
    // designed blocking-pipe backpressure never engages. The server refuses
    // the fd at body start: `CloseReason::SpliceBadFd`, kernel never sees it.
    use std::sync::Mutex;
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: `pipe(2)` fills {read, write}.
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe");
    let (pipe_rd, pipe_wr) = (fds[0], fds[1]);
    // SAFETY: flag the write end non-blocking - the misuse under test.
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
    // connection's pool slot is reclaimed - proven with pool_size=1: a second
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
    // `Response::Reply(empty)` means "answered, nothing to send" - a one-way
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
    // one-way case (sends nothing, keeps serving - same as Response::Reply's
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
    // the TooLarge guard (release) or panicked the loop on the add (debug) --
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
    // bound the requested read against max_request_bytes up front - both the
    // overflowing and the merely-huge shape - not allocate n bytes.
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
    // dropped (per-request token gating) - not sent as a spurious extra PDU,
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
            // Answer inline anyway - the Deferred above is now stale.
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
    // defer() was never called) must close the connection - not park a
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
    // (fetched via an io_uring socket URING_CMD - Linux >= 6.7; this host is
    // newer) before running, and can authenticate on it. The body echoes the
    // credentials back and the client checks them against its real ids.
    let dir = truenas_ros::tempdir().unwrap();
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
    // Each push must exceed what the kernel alone can absorb - sndbuf
    // autotunes up to tcp_wmem[2] (typically 4 MiB) plus the peer's ~128 KiB
    // initial window - because a fully-absorbed WAITALL send completes and
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
            // Second push: queued bytes would exceed the backlog cap -> evict.
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
    // the connection is DETACHED its raw stream belongs to the worker - a
    // push must neither write mid-detach (corrupting the worker's transfer)
    // nor be silently dropped: it queues against the parked connection and
    // flushes, FIFO, when the worker resumes it.
    use std::sync::Mutex;
    use std::sync::mpsc;
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
            // HELD (not written - the worker owns the stream - and not
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
    // reply and then EOF - no idle-timeout wait, no relying on the peer to
    // hang up (RFC 6455 sec. 5.5.1-style close handshakes need exactly this).
    // A second request pipelined behind the first is discarded undelivered:
    // the farewell retires the recv side.
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};
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
            // Two requests in one write: only the first is served - the
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
    // `Deferred::reply_close`: the worker speaks last - its final PDU is
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
    // whatever is already queued before closing - here a push the worker
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

/// A throwaway protocol for the construction-time validation cases, which are
/// rejected before any socket or ring exists and so never reach io_uring.
// Three opaque closure types in the return, for the same reason
// `net::server::length_prefixed` carries this allow: they cannot be
// type-aliased on stable, and the signature IS the type.
#[allow(clippy::type_complexity)]
fn noop_protocol() -> Protocol<
    impl FnMut(Incoming<'_>) -> Option<()>,
    impl FnMut(&[u8], &mut ()) -> Framing,
    impl FnMut(Request<'_, ()>) -> Response,
> {
    Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(
            PrefixWidth::U32,
            Endian::Big,
            false,
        ),
        body: |req: Request<'_, ()>| Response::Reply(echo_frame(&req.body)),
    }
}

#[test]
fn server_config_bounds_are_rejected_at_construction() {
    // `ServerConfig::validate` runs as the first statement of `with_config`,
    // before a socket or a ring exists, so every case here is reachable with
    // no io_uring at all. Each knob is checked for the message it produces,
    // not merely that it errored: an out-of-range value accepted here becomes
    // a truncated completion token or a thread storm much later, and the
    // message is the only thing naming the knob that was wrong.
    use truenas_ros::net::server::Listen;
    let tcp =
        || ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let expect = |addrs: Vec<Listen>, cfg: ServerConfig, needle: &str| {
        match Server::with_config(addrs, cfg, noop_protocol()) {
            Err(Error::Validation(m)) => assert!(
                m.contains(needle),
                "expected a validation error mentioning {needle:?}, got {m:?}",
            ),
            Err(e) => {
                panic!("expected a validation error for {needle:?}, got {e}")
            }
            Ok(_) => panic!("expected {needle:?} to be rejected"),
        }
    };

    // The listener list itself.
    expect(Vec::new(), ServerConfig::default(), "listener count");
    expect(
        (0..257).map(|_| Listen::from(tcp())).collect(),
        ServerConfig::default(),
        "listener count",
    );
    // kTLS rides the TCP stack; a Unix listener cannot carry it.
    expect(
        vec![Listen::tls(ServerAddr::Unix("/tmp/ktls-validate".into()))],
        ServerConfig::default(),
        "kTLS listeners must be TCP",
    );

    // Numeric knobs, each at both ends of its range where it has two.
    let one = || vec![Listen::from(tcp())];
    for (cfg, needle) in [
        (
            ServerConfig {
                pool_size: 0,
                ..ServerConfig::default()
            },
            "pool_size",
        ),
        (
            ServerConfig {
                pool_size: 0x0100_0000, // one past the 24-bit slot ceiling
                ..ServerConfig::default()
            },
            "pool_size",
        ),
        (
            ServerConfig {
                max_request_bytes: 0,
                ..ServerConfig::default()
            },
            "max_request_bytes",
        ),
        (
            ServerConfig {
                max_request_bytes: usize::MAX,
                ..ServerConfig::default()
            },
            "max_request_bytes",
        ),
        (
            ServerConfig {
                max_send_backlog: 0,
                ..ServerConfig::default()
            },
            "max_send_backlog must be non-zero",
        ),
        // `listen(2)` takes a signed backlog but compares it unsigned, so a
        // negative value is reinterpreted as enormous and silently clamped to
        // somaxconn rather than rejected; zero listens but accepts almost
        // nothing. Neither is what any caller meant.
        (
            ServerConfig {
                backlog: 0,
                ..ServerConfig::default()
            },
            "backlog must be positive",
        ),
        (
            ServerConfig {
                backlog: -1,
                ..ServerConfig::default()
            },
            "backlog must be positive",
        ),
        (
            ServerConfig {
                max_send_coalesce: 0,
                ..ServerConfig::default()
            },
            "max_send_coalesce",
        ),
        (
            ServerConfig {
                max_send_coalesce: usize::MAX,
                ..ServerConfig::default()
            },
            "max_send_coalesce",
        ),
        (
            ServerConfig {
                max_in_flight_requests: 0,
                ..ServerConfig::default()
            },
            "max_in_flight_requests",
        ),
        (
            ServerConfig {
                max_in_flight_requests: usize::MAX,
                ..ServerConfig::default()
            },
            "max_in_flight_requests",
        ),
    ] {
        expect(one(), cfg, needle);
    }

    // A timeout knob is optional, but `Some(0)` is never what anyone means:
    // it would expire the moment it was armed.
    let zero = Duration::ZERO;
    for (cfg, needle) in [
        (
            ServerConfig {
                idle_timeout: Some(zero),
                ..ServerConfig::default()
            },
            "idle_timeout must be non-zero",
        ),
        (
            ServerConfig {
                send_timeout: Some(zero),
                ..ServerConfig::default()
            },
            "send_timeout must be non-zero",
        ),
        (
            ServerConfig {
                request_timeout: Some(zero),
                ..ServerConfig::default()
            },
            "request_timeout must be non-zero",
        ),
        (
            ServerConfig {
                max_receipt_time: Some(zero),
                ..ServerConfig::default()
            },
            "max_receipt_time must be non-zero",
        ),
        (
            ServerConfig {
                tls_handshake_timeout: Some(zero),
                ..ServerConfig::default()
            },
            "tls_handshake_timeout must be non-zero",
        ),
        (
            ServerConfig {
                keepalive: Some(zero),
                ..ServerConfig::default()
            },
            "keepalive must be non-zero",
        ),
        (
            ServerConfig {
                tcp_user_timeout: Some(zero),
                ..ServerConfig::default()
            },
            "tcp_user_timeout must be non-zero",
        ),
    ] {
        expect(one(), cfg, needle);
    }
}

#[cfg(feature = "uring-fs")]
#[test]
fn server_config_fs_pool_bounds_are_rejected_at_construction() {
    // The fs knobs carry their own bounds for reasons the generic ones do not:
    // an op-slot index shares the 24-bit `user_data` slot field, so an
    // oversized `fs_ops` would truncate a completion token rather than fail;
    // and the offload floor spawns eagerly
    // on the reactor thread, so an absurd value is a thread storm at first use.
    // Both must fail here, at construction, where the message still names the
    // knob.
    use truenas_ros::net::server::Listen;
    let one = || {
        vec![Listen::from(ServerAddr::Tcp(
            "127.0.0.1:0".parse::<SocketAddrV4>().unwrap(),
        ))]
    };
    let expect = |cfg: ServerConfig, needle: &str| match Server::with_config(
        one(),
        cfg,
        noop_protocol(),
    ) {
        Err(Error::Validation(m)) => assert!(
            m.contains(needle),
            "expected a validation error mentioning {needle:?}, got {m:?}",
        ),
        Err(e) => panic!("expected a validation error for {needle:?}, got {e}"),
        Ok(_) => panic!("expected {needle:?} to be rejected"),
    };

    expect(
        ServerConfig {
            // Plus the default `pool_size`, one past the 24-bit ceiling.
            fs_ops: 0x00ff_ffff,
            ..ServerConfig::default()
        },
        "fs_ops",
    );
    expect(
        ServerConfig {
            fs_offload_floor: 0,
            ..ServerConfig::default()
        },
        "fs_offload_floor",
    );
    expect(
        ServerConfig {
            fs_offload_floor: 4,
            fs_offload_ceiling: 2, // floor above ceiling
            ..ServerConfig::default()
        },
        "fs_offload_floor",
    );
    expect(
        ServerConfig {
            fs_offload_ceiling: 1025, // past MAX_OFFLOAD_THREADS
            ..ServerConfig::default()
        },
        "fs_offload_floor",
    );
    // The body chunk sizes two kernel-visible buffers per streaming
    // connection and its read result must fit a CQE's i32.
    expect(
        ServerConfig {
            fs_body_chunk: 0, // below the 4 KiB floor
            ..ServerConfig::default()
        },
        "fs_body_chunk",
    );
    expect(
        ServerConfig {
            fs_body_chunk: 16 * 1024 * 1024 + 1, // past the 16 MiB ceiling
            ..ServerConfig::default()
        },
        "fs_body_chunk",
    );
}

/// `Response::ReplyFile` on a server built WITHOUT an fs pool must refuse
/// loudly - close before any reply byte - never send the head and then a
/// body it has no reactor to read. The `File` comes from a standalone
/// `UringFs` host: an open fd is host-independent, which is exactly the
/// misconfiguration shape (files wired over from one reactor into a server
/// missing `fs_ops`).
#[cfg(feature = "uring-fs")]
#[test]
fn file_reply_without_an_fs_pool_sheds_loudly() {
    use std::sync::{Mutex, mpsc};
    use truenas_ros::sync_fs::{OFlag, OpenHow};
    use truenas_ros::uring_fs::{Anchor, FsConfig, UringFs};

    let dir = truenas_ros::tempdir().unwrap();
    std::fs::write(dir.path().join("f"), b"never sent").unwrap();

    // Mint a File on a standalone host, then stop it - the fd survives.
    let mut cfg = FsConfig::default();
    cfg.entries = 128;
    cfg.ops = 128;
    let mut afs = match UringFs::new(cfg) {
        Ok(a) => a,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("UringFs::new: {e}"),
    };
    let who = afs.register_self().expect("register_self");
    let handle = afs.handle();
    let stop_fs = afs.shutdown_handle();
    let anchor = Anchor::open(dir.path()).expect("anchor");
    let (ftx, frx) = mpsc::channel();
    thread::scope(|sc| {
        sc.spawn(move || {
            let r = handle.open(
                who,
                &anchor,
                c"f",
                OpenHow::new().flags(OFlag::O_RDONLY),
            );
            let _ = ftx.send(r);
            stop_fs.shutdown();
        });
        afs.run().expect("fs host run");
    });
    let file = frx.recv().expect("open outcome").expect("open");

    let reasons = Arc::new(Mutex::new(Vec::new()));
    let file_slot = Mutex::new(Some(file));
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(
            PrefixWidth::U32,
            Endian::Big,
            false,
        ),
        body: move |_req: Request<'_, ()>| Response::ReplyFile {
            head: b"HEAD".to_vec(),
            file: file_slot.lock().unwrap().take().expect("one request"),
            offset: 0,
            len: 10,
            close: false,
        },
    };
    // `fs_ops` stays 0: that IS the configuration under test.
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
            let mut msg = 3u32.to_be_bytes().to_vec();
            msg.extend_from_slice(b"abc");
            s.write_all(&msg)?;
            let mut buf = Vec::new();
            s.read_to_end(&mut buf)?;
            assert!(
                buf.is_empty(),
                "refusal must be a close, not a short body: {buf:?}"
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
        &[CloseReason::FileBody(Errno::EOPNOTSUPP)],
        "the pool-less server must shed with the errno in the reason"
    );
}

#[test]
fn tcp_deferred_worker_completes_with_nothing() {
    // `Deferred::reply` with an EMPTY body is the one-way case: the worker
    // finished, there is nothing to send, and the request must simply be
    // retired. It travels as its own outcome rather than as an empty reply,
    // because a queued reply has its in-flight count retired when the send
    // flushes and here no send will ever happen - so the count is dropped
    // where the outcome lands instead. Get that wrong and the connection
    // keeps a phantom request forever, which the request cap would eventually
    // stall on. Proven by continuing to serve afterwards: a leaked count would
    // still be outstanding.
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
            if &body[..] == b"oneway" {
                let (deferred, permit) = responder.defer();
                thread::spawn(move || {
                    thread::sleep(Duration::from_millis(10));
                    deferred.reply(Vec::new()); // completed, nothing to send
                });
                Response::Defer(permit)
            } else {
                Response::Reply(echo_frame(&body))
            }
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
        let _stop = ShutdownOnDrop(stop.clone());
        let r = (|| -> io::Result<Vec<u8>> {
            let mut s = connect_tcp(v4)?;
            // Several one-way requests in a row: each must retire its own
            // in-flight count, or the cap stalls the connection well before
            // the round-trip below completes.
            for _ in 0..4 {
                send_framed(&mut s, b"oneway")?;
            }
            send_framed(&mut s, b"ping")?;
            recv_framed(&mut s)
        })();
        stop.shutdown();
        r
    });

    server.serve_forever().expect("serve_forever");
    let reply = client.join().expect("thread join").expect("client io");
    assert_eq!(
        reply, b"ping",
        "one-way deferrals must retire their in-flight count and keep serving",
    );
}

#[test]
fn tcp_push_close_after_the_peer_is_gone_is_inert() {
    // A `PushHandle` outlives the connection it names - that is the point of a
    // long-lived handle - so a `close` can always arrive after the peer has
    // already vanished, or after the slot has been recycled onto somebody
    // else. It must be inert rather than tearing down whoever holds the slot
    // now. Here the subscriber disconnects, a second client takes its place,
    // and only then does the stale handle fire.
    use std::sync::Mutex;
    let stash: Arc<Mutex<Option<PushHandle>>> = Arc::new(Mutex::new(None));
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let handle_for_body = Arc::clone(&stash);
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(
            PrefixWidth::U32,
            Endian::Big,
            false,
        ),
        body: move |req: Request<'_, ()>| {
            let Request {
                body, responder, ..
            } = req;
            if &body[..] == b"sub" {
                *handle_for_body.lock().unwrap() =
                    Some(responder.push_handle());
            }
            Response::Reply(echo_frame(&body))
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
        let _stop = ShutdownOnDrop(stop.clone());
        let r = (|| -> io::Result<Vec<u8>> {
            let mut first = connect_tcp(v4)?;
            send_framed(&mut first, b"sub")?;
            assert_eq!(recv_framed(&mut first)?, b"sub");
            drop(first); // the handle's connection is gone
            thread::sleep(Duration::from_millis(100)); // let the close land

            // A fresh connection, likely onto the recycled slot.
            let mut second = connect_tcp(v4)?;
            send_framed(&mut second, b"hello")?;
            assert_eq!(recv_framed(&mut second)?, b"hello");

            // Fire the stale handle: it names a dead connection (and possibly
            // this one's slot at an older generation).
            stash.lock().unwrap().take().expect("stashed").close();
            thread::sleep(Duration::from_millis(100));

            // The survivor is untouched.
            send_framed(&mut second, b"still-here")?;
            recv_framed(&mut second)
        })();
        stop.shutdown();
        r
    });

    server.serve_forever().expect("serve_forever");
    let reply = client.join().expect("thread join").expect("client io");
    assert_eq!(
        reply, b"still-here",
        "a stale PushHandle::close must not disturb the slot's new owner",
    );
}

#[test]
fn tcp_push_close_during_a_detach_window_lands_at_resume() {
    // A `PushHandle::close` arriving while the connection is parked under a
    // detach worker cannot act immediately: the worker owns the raw stream, so
    // writing the queued farewell or tearing the socket down would corrupt its
    // transfer. It is recorded and enacted at resume - after the pushes held
    // during the same window, which ride ahead of it. So the client must see
    // every held push, in order, and *then* EOF, with the close attributed to
    // the push side rather than to the worker.
    use std::sync::Mutex;
    use std::sync::mpsc;
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
    let reasons = close_reason_channel(&mut server);
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();

    let client = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone());
        let r = (|| -> io::Result<Vec<u8>> {
            let mut s = connect_tcp(v4)?;
            send_framed(&mut s, b"sub")?;
            assert_eq!(recv_framed(&mut s)?, b"ok");
            send_framed(&mut s, b"detach")?;
            parked_rx.recv().expect("parked");

            let push =
                push_slot.lock().unwrap().clone().expect("stashed handle");
            push.push(echo_frame(b"farewell"));
            push.close(); // lands during the detach window
            // Let the loop drain both injections while still parked.
            thread::sleep(Duration::from_millis(150));
            resume_tx.send(()).expect("resume signal");

            // The held push flushes first...
            assert_eq!(
                recv_framed(&mut s)?,
                b"farewell",
                "a push queued before the close must still be delivered",
            );
            // ...then the recorded close is enacted.
            let mut tail = Vec::new();
            s.read_to_end(&mut tail)?;
            Ok(tail)
        })();
        stop.shutdown();
        r
    });

    server.serve_forever().expect("serve_forever");
    match client.join().expect("thread join") {
        Ok(tail) => assert!(tail.is_empty(), "expected EOF, got {tail:?}"),
        Err(e) => assert_eq!(e.kind(), io::ErrorKind::ConnectionReset),
    }
    assert_eq!(
        reasons.try_recv().ok(),
        Some(CloseReason::PushClosed),
        "a close held across a detach is still a push-side close",
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

            // The subscriber gets the farewell, then EOF - and nothing
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

/// Deferring echo handler that `take()`s the body - the one-pattern
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
    let dir = truenas_ros::tempdir().unwrap();
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
    // port and rejects the second - the listener argument drives policy.
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
            // policy without depending on the reject-close reaching us - see
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
    // a buffer shared across a multishot accept's completions - so a burst of
    // simultaneous connects must each see THEIR OWN source address echoed
    // back. (A single shared address buffer would misattribute under a burst.)
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
            // the kernel - ENFILE - terminating B's multishot accept). Use a
            // short timeout because a connection can also land in B's listen
            // backlog unaccepted, where a read would block indefinitely; that
            // it does not get served is the point.
            let mut shed = connect_tcp(b)?;
            shed.set_read_timeout(Some(Duration::from_millis(200)))?;
            let mut byte = [0u8; 1];
            let _ = shed.read(&mut byte); // EOF / reset / timeout - all "shed"
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
    // intact (order-independent - deferred replies may egress out of request
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
            // -- well before the 5s grace deadline.
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
    // `keep_rx` and never resolves it - rather than `mem::forget`, which leaks
    // its channel Sender + Arc and trips LeakSanitizer - releasing it only at
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
            // Keep the socket open (returned) - its EOF only arrives when the
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
    drop(keep_rx); // release the held (never-resolved) Deferreds - no leak
}

#[test]
fn tcp_graceful_drains_pipelined_deferred_reply() {
    // Regression: in pipelined mode a connection can hold a deferred reply
    // in flight AND a read-ahead recv parked at once. Graceful shutdown must
    // still deliver that reply - `begin_drain` cancels the parked recv, but the
    // connection must finish its outstanding work before closing; tearing it
    // down would drop the reply. At the default
    // `max_in_flight_requests` the read-ahead is never armed during a defer, so
    // this shape is pipelined-only.
    let cfg = ServerConfig {
        max_in_flight_requests: 2, // pipelined -> read-ahead armed during a defer
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
    // connection is NOT idle - it still owes the deferred reply - so it must
    // finish that work, not be reaped (reaping it would drop the reply: once
    // `closing`, `kick_send`'s `!closing` guard swallows the queued send).
    // A perfectly normal request/response client (send one request, await its
    // reply before the next) hits this whenever the worker outlives
    // `idle_timeout`. At the default `max_in_flight_requests` no read-ahead is
    // armed during a defer, so this shape is pipelined-only.
    //
    // `WORK` being an exact multiple of `IDLE` also lands the final clock
    // expiry in a photo-finish with the reply's flush and the client's
    // immediate next request - the served-since-arm rule keeps every ordering
    // of that race alive (pinned deterministically, with wide margins, by
    // `tcp_idle_clock_resets_on_served_reply`).
    const IDLE: Duration = Duration::from_millis(100);
    const WORK: Duration = Duration::from_millis(400); // outlives IDLE 4x
    let cfg = ServerConfig {
        max_in_flight_requests: 2, // pipelined -> read-ahead armed during a defer
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
            // Send one request, then just wait for its reply - the read-ahead
            // recv parks and its idle timeout fires long before the worker
            // replies. Were the server to close the connection here, this read
            // would hit EOF; the reply must instead still arrive.
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
    // Regression - the deterministic form of the race its sibling above only
    // hits on a slow box: the idle clock rides the
    // parked read-ahead recv from ARM time, so while a deferred reply is
    // produced and flushed the clock keeps counting. Serving that reply is
    // activity - the quiet interval must restart - yet a guard that only asks
    // "owes work NOW?" sees nothing outstanding at the next expiry and reaps
    // the connection out from under a client it served moments ago (the
    // client's follow-up request then hits EOF/reset).
    //
    // Timeline pinned here, margins in the hundreds of ms so a loaded VM
    // cannot flip any edge: the read-ahead parks at ~0 with the clock running;
    // the deferred reply flushes at ~WORK (300 ms); the stale clock expires at
    // ~IDLE (600 ms) - an interval that SAW a served reply, so it must re-arm
    // a fresh quiet interval, not reap - and the client's second request lands
    // at ~700 ms, inside that fresh interval, and must be answered.
    const IDLE: Duration = Duration::from_millis(600);
    const WORK: Duration = Duration::from_millis(300);
    const CLIENT_PAUSE: Duration = Duration::from_millis(400);
    let cfg = ServerConfig {
        max_in_flight_requests: 2, // pipelined -> read-ahead parks during defer
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
    // below the worker's duration nothing fires - the reply still arrives.
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
            // still come back - the handled request is never timed out.
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
            // (a) clean keep-alive EOF -> PeerClosed
            let mut a = connect_tcp(v4)?;
            send_framed(&mut a, b"hi")?;
            assert_eq!(recv_framed(&mut a)?, b"hi");
            drop(a);
            // (b) handler says close -> HandlerClosed
            let mut b = connect_tcp(v4)?;
            send_framed(&mut b, b"close")?;
            let mut buf = Vec::new();
            b.read_to_end(&mut buf)?; // closed without a reply
            assert!(buf.is_empty());
            // (c) parked past idle_timeout -> IdleTimeout
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

/// A drain refuses new connections instead of quietly accepting them into a
/// backlog nobody will ever read: `shutdown_graceful` shuts every listener
/// down first, so a connect from then on fails with `ECONNREFUSED` while the
/// request already in flight still finishes. The idle connection's EOF is
/// the "drain has begun" signal (the idle sweep runs after the listeners are
/// shut), so nothing here waits on a timer.
#[test]
fn graceful_drain_refuses_new_connections() {
    let (park_tx, park_rx) = std::sync::mpsc::channel::<Deferred>();
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(
            PrefixWidth::U32,
            Endian::Big,
            false,
        ),
        body: move |req: Request<'_, ()>| -> Response {
            if &req.body[..] == b"park" {
                let (deferred, permit) = req.responder.defer();
                park_tx.send(deferred).expect("the test holds the receiver");
                Response::Defer(permit)
            } else {
                Response::Reply(echo_frame(&req.body))
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
    let client = thread::spawn(move || -> io::Result<()> {
        let _stop = ShutdownOnDrop(stop.clone());
        // Idle between requests: the sweep closes it, marking the drain.
        let mut idle = connect_tcp(v4)?;
        send_framed(&mut idle, b"ping")?;
        assert_eq!(recv_framed(&mut idle)?, b"ping");
        // Parked in a worker: in-flight work that holds the drain open.
        let mut parked = connect_tcp(v4)?;
        send_framed(&mut parked, b"park")?;
        let deferred = park_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("the request parked");

        stop.shutdown_graceful(Duration::from_secs(5));
        let mut b = [0u8; 1];
        assert_eq!(idle.read(&mut b)?, 0, "the sweep closes the idle peer");

        // The listeners are shut: refused, not queued.
        match TcpStream::connect(v4) {
            Err(e) => assert_eq!(
                e.kind(),
                io::ErrorKind::ConnectionRefused,
                "a connect during the drain failed some other way: {e}"
            ),
            Ok(_) => panic!("a connect during the drain was queued"),
        }

        // The parked request completes, then its connection closes.
        deferred.reply(echo_frame(b"park"));
        assert_eq!(recv_framed(&mut parked)?, b"park");
        assert_eq!(parked.read(&mut b)?, 0, "closed once nothing is owed");
        Ok(())
    });
    server.serve_forever().expect("serve_forever");
    client.join().expect("client thread").expect("client io");
}

/// Draining one `reuse_port` sibling must not take the address down: its
/// shut listener leaves the kernel's reuseport group while the server is
/// still alive and draining, so every new connect lands on the survivor and
/// is served rather than queued on a ring that will never read it. The
/// drained ring is held open by a parked request for the whole check, so
/// what the test proves is `shutdown(2)`, not the fd closing at drop.
#[test]
fn draining_one_reuse_port_sibling_leaves_the_other_serving() {
    type Ready = Result<(SocketAddrV4, ShutdownHandle), Error>;
    fn worker(
        idx: u8,
        addr: SocketAddrV4,
        ready: std::sync::mpsc::Sender<Ready>,
        park_tx: std::sync::mpsc::Sender<Deferred>,
    ) {
        let cfg = ServerConfig {
            reuse_port: true,
            ..ServerConfig::default()
        };
        let proto = Protocol {
            accept: |_: Incoming<'_>| Some(()),
            header: length_prefix_header::<()>(
                PrefixWidth::U32,
                Endian::Big,
                false,
            ),
            // Echoes are tagged with the ring that served them; "park"
            // defers so the test can hold that ring open while it drains.
            body: move |req: Request<'_, ()>| -> Response {
                if &req.body[..] == b"park" {
                    let (deferred, permit) = req.responder.defer();
                    park_tx
                        .send(deferred)
                        .expect("the test holds the receiver");
                    return Response::Defer(permit);
                }
                let mut out = vec![idx];
                out.extend_from_slice(&req.body);
                Response::Reply(echo_frame(&out))
            },
        };
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
    let (park_tx, park_rx) = std::sync::mpsc::channel::<Deferred>();
    let (tx0, park0) = (tx.clone(), park_tx.clone());
    let w0 = thread::spawn(move || {
        worker(0, "127.0.0.1:0".parse().unwrap(), tx0, park0);
    });
    let (addr, stop0) = match rx.recv().expect("worker 0") {
        Ok(v) => v,
        Err(e) if should_skip(&e) => {
            w0.join().unwrap();
            return;
        }
        Err(e) => panic!("bind: {e}"),
    };
    let w1 = thread::spawn(move || worker(1, addr, tx, park_tx));
    let (_, stop1) = rx.recv().expect("worker 1").expect("second bind");

    // Two connections that ring 0 answered: one to park on it, one to idle
    // on it. The kernel hashes each new connection across the group, so a
    // bounded number of tries finds them (each try is a coin flip).
    let mut on_ring0 = Vec::new();
    for _ in 0..64 {
        let mut s = connect_tcp(addr).expect("connect");
        send_framed(&mut s, b"which").expect("send");
        let reply = recv_framed(&mut s).expect("recv");
        if reply[0] == 0 {
            on_ring0.push(s);
            if on_ring0.len() == 2 {
                break;
            }
        }
    }
    let [mut parked0, mut idle0]: [TcpStream; 2] = on_ring0
        .try_into()
        .expect("the kernel never balanced two connections onto ring 0");
    send_framed(&mut parked0, b"park").expect("send");
    let deferred = park_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("the request parked on ring 0");

    stop0.shutdown_graceful(Duration::from_secs(5));
    let mut b = [0u8; 1];
    assert_eq!(idle0.read(&mut b).expect("read"), 0, "ring 0's idle sweep");

    // Ring 0 is alive, draining, and out of the group: the survivor takes
    // every new connection.
    for i in 0..16 {
        let msg = format!("m{i}");
        let mut s = TcpStream::connect(addr)
            .expect("a connect while a sibling drains must succeed");
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        send_framed(&mut s, msg.as_bytes()).expect("send");
        let reply = recv_framed(&mut s)
            .expect("served by the survivor, not queued on the drained ring");
        assert_eq!(reply[0], 1, "connection {i} landed on the drained ring");
        assert_eq!(&reply[1..], msg.as_bytes());
    }

    // Release ring 0: its parked request completes and the drain ends.
    deferred.reply(echo_frame(b"park"));
    assert_eq!(recv_framed(&mut parked0).expect("recv"), b"park");
    assert_eq!(parked0.read(&mut b).expect("read"), 0, "ring 0 closed it");
    w0.join().expect("worker 0 join");
    stop1.shutdown_graceful(Duration::from_secs(5));
    w1.join().expect("worker 1 join");
}

#[test]
fn tcp_pipelined_out_of_order() {
    // Pipelined (max_in_flight > 1): the client sends several requests without
    // waiting; each is deferred to a worker that finishes in REVERSE order. With
    // read-ahead the server reads and defers all of them before any reply, so
    // replies egress out of request order - proving recv is decoupled from send.
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
                // Higher ids sleep less -> replies come back reversed.
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
    // Deterministic reversal from the inverse delays - the last request sent is
    // answered first, which can only happen if reads ran ahead of sends.
    assert_eq!(order, vec![3, 2, 1, 0]);
}

#[test]
fn tcp_pipelined_backpressure() {
    // A tight cap with more pipelined requests than the cap: read-ahead must
    // pause at the cap and resume as replies drain - every request answered,
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
    // the default sequential mode - the WAITALL send is orthogonal to pipelining.)
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
    // `accept` returns None -> the connection is accepted then immediately closed
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
            s.read_to_end(&mut buf)?; // rejected -> EOF, no data
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
    // in-flight recv pins the ring's resource node - so the closed peer would
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

/// Block on a read and assert the server closes an idle connection promptly - a
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
        "idle close took too long ({:?}) - timer may not be firing",
        start.elapsed()
    );
    Ok(())
}

#[test]
fn tcp_idle_timeout() {
    // With an idle timeout set, a connection left waiting for its next request
    // is closed and its slot reclaimed - while an in-flight request is never
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
    // -EINVAL and takes its linked recv down -ECANCELED - misreported as
    // IdleTimeout/RequestTimeout - closing every connection at its first
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
            // later - the split parks the body recv with its linked clock.
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
    // would - the connection is not idle, it is mid-frame. An idle keep-alive
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
    // consumed bytes completes with res = done_io > 0 (io_sendrecv_fail) --
    // bit-identical to a peer FIN mid-frame - so the server pairs the recv
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

/// A receipt budget at or under the inactivity bound leaves the latter dead:
/// the message is closed before a whole silent period can be observed, so
/// `request_timeout` never fires and the pair reads as one knob with two
/// names. Refused at validation, where the operator finds out, rather than
/// tolerated into a configuration that means something else.
#[test]
fn a_receipt_budget_may_not_pre_empt_the_inactivity_bound() {
    use truenas_ros::net::server::Listen;
    let one = || {
        vec![Listen::from(ServerAddr::Tcp(
            "127.0.0.1:0".parse::<SocketAddrV4>().unwrap(),
        ))]
    };
    let build = |cfg: ServerConfig| {
        Server::with_config(one(), cfg, noop_protocol()).map(|_| ())
    };
    let request = Duration::from_secs(30);
    for (what, receipt) in
        [("under", Duration::from_secs(29)), ("equal", request)]
    {
        let cfg = ServerConfig {
            request_timeout: Some(request),
            max_receipt_time: Some(receipt),
            ..ServerConfig::default()
        };
        match build(cfg) {
            Err(Error::Validation(m)) => assert!(
                m.contains("must exceed request_timeout"),
                "{what}: wrong message {m:?}"
            ),
            other => panic!("{what} must be refused, got {:?}", other.is_ok()),
        }
    }
    // One period longer is the smallest configuration that means what it
    // says, and it is accepted. Either clock alone is fine too: the budget
    // is the rate floor, the inactivity bound is the liveness check, and
    // neither implies the other.
    for (what, cfg) in [
        (
            "both",
            ServerConfig {
                request_timeout: Some(request),
                max_receipt_time: Some(request + Duration::from_millis(1)),
                ..ServerConfig::default()
            },
        ),
        (
            "budget alone",
            ServerConfig {
                max_receipt_time: Some(request),
                ..ServerConfig::default()
            },
        ),
        (
            "inactivity alone",
            ServerConfig {
                request_timeout: Some(request),
                ..ServerConfig::default()
            },
        ),
    ] {
        match build(cfg) {
            Ok(()) => {}
            Err(e) if should_skip(&e) => return,
            Err(e) => panic!("{what} must be usable, got {e}"),
        }
    }
}

/// SECURITY (slow-loris, the case `request_timeout` cannot reach):
/// `request_timeout` bounds progress per period, so a peer that sends one
/// byte just inside every period re-arms it forever and holds its pool slot
/// indefinitely. A slot is taken at accept, before authentication, and accept
/// is gated on a free slot - so `pool_size` such peers deny service.
/// `max_receipt_time` is the bound that cannot be restarted by progress: it
/// runs from a message's first byte to its delivery.
///
/// The trickle here is deliberately faster than `request_timeout`, so the
/// inactivity guard never fires and the close reason proves which clock did
/// the reclaiming.
#[test]
fn max_receipt_time_reclaims_a_peer_trickling_under_the_floor() {
    use std::sync::Mutex;
    let reasons = Arc::new(Mutex::new(Vec::new()));
    let cfg = ServerConfig {
        request_timeout: Some(Duration::from_millis(200)),
        max_receipt_time: Some(Duration::from_millis(700)),
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
            // Declare 64 bytes, then feed them one at a time every 100 ms --
            // half the request_timeout period, so that clock is re-armed on
            // every byte and never fires. At this pace the message needs
            // 6.4 s, nine times the receipt budget.
            s.write_all(&64u32.to_be_bytes())?;
            for _ in 0..64 {
                if s.write_all(&[0xEE]).is_err() {
                    break; // the server closed under us, which is the point
                }
                if s.flush().is_err() {
                    break;
                }
                thread::sleep(Duration::from_millis(100));
            }
            expect_idle_close(&mut s)?;
            Ok(())
        })();
        stop.shutdown();
        r
    });

    server.serve_forever().expect("serve_forever");
    client.join().expect("thread join").expect("client io");
    assert_eq!(
        reasons.lock().unwrap().as_slice(),
        &[CloseReason::ReceiptTimeout],
        "a peer under the rate floor must read as ReceiptTimeout - \
         RequestTimeout would mean the inactivity guard caught it, and \
         nothing at all would mean the budget never armed"
    );
}

/// The budget is not restarted by progress - the property that separates it
/// from `request_timeout`, driven on the framing that can tell them apart.
///
/// A length-prefixed body is a single exact read, so the arm happens once
/// whatever the code does afterwards and a per-read re-arm is invisible. A
/// `More`/delimiter scan re-enters `submit_recv` on every chunk, so a budget
/// that is cancelled and re-armed there rides the trickle forever, exactly
/// as the inactivity clock does. The gaps here are half `request_timeout`,
/// so that clock is satisfied throughout and the close reason names which
/// one fired.
#[test]
fn a_chunk_scan_budget_is_not_restarted_by_progress() {
    use std::sync::Mutex;
    let reasons = Arc::new(Mutex::new(Vec::new()));
    let cfg = ServerConfig {
        request_timeout: Some(Duration::from_millis(200)),
        max_receipt_time: Some(Duration::from_millis(700)),
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
            // A header that never terminates, one byte per 100 ms: every
            // chunk read completes and re-arms, so `request_timeout` is
            // satisfied on every one of them and never fires. Thirty bytes
            // is 3 s of trickle against a 700 ms budget.
            for _ in 0..30 {
                if s.write_all(b"x").is_err() || s.flush().is_err() {
                    break; // closed under us, which is the point
                }
                thread::sleep(Duration::from_millis(100));
            }
            expect_idle_close(&mut s)?;
            Ok(())
        })();
        stop.shutdown();
        r
    });

    server.serve_forever().expect("serve_forever");
    client.join().expect("thread join").expect("client io");
    assert_eq!(
        reasons.lock().unwrap().as_slice(),
        &[CloseReason::ReceiptTimeout],
        "a budget re-armed by each chunk never fires, and the scan runs on"
    );
}

/// Exactly one budget per message, and the retire cancels the one there is.
///
/// A `More`/delimiter framer reads in chunks that complete on any byte, so a
/// trickled header is many non-idle reads of one message - the shape that
/// tells an idempotent arm from a per-read one. Arming per read stacks a
/// timer each time, and they all carry the same `user_data`, so the retire's
/// `ASYNC_CANCEL` reaps one and leaves the rest to fire later against a
/// connection that has done nothing wrong. The header here completes well
/// inside the budget, so a close of any kind is the bug.
#[test]
fn a_trickled_header_leaves_exactly_one_receipt_budget() {
    let budget = Duration::from_millis(400);
    let cfg = ServerConfig {
        request_timeout: Some(Duration::from_millis(200)),
        max_receipt_time: Some(budget),
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
            let mut s = connect_tcp(v4)?;
            // Eight chunk reads for one header, spread over 160 ms - well
            // inside the budget, and none of the gaps near the inactivity
            // bound either.
            let head = b"Content-Length: 0\r\n\r\n";
            for b in head {
                s.write_all(&[*b])?;
                s.flush()?;
                thread::sleep(Duration::from_millis(160) / head.len() as u32);
            }
            let mut got = [0u8; 2];
            s.read_exact(&mut got)?;
            assert_eq!(&got, b"ok");

            // Sit idle for several budgets. A timer left over from the
            // trickle fires here and takes the slot with it.
            thread::sleep(budget * 3);
            s.write_all(head)?;
            s.flush()?;
            s.read_exact(&mut got)?;
            assert_eq!(
                &got, b"ok",
                "a stale receipt budget reaped a healthy connection"
            );
            Ok(())
        })();
        stop.shutdown();
        r
    });

    server.serve_forever().expect("serve_forever");
    client.join().expect("thread join").expect("client io");
}

/// The budget is retired at delivery, so it bounds receipt and nothing else.
///
/// Two ways this could go wrong and both are silent: a budget that outlives
/// its message would fire during handling or while the connection sits idle
/// between requests, killing healthy keep-alive connections on a timer; and
/// one that is re-armed rather than left running would degrade into the
/// inactivity guard it exists beside. The sleeps here are several times the
/// budget with the connection well-behaved throughout.
#[test]
fn max_receipt_time_does_not_clock_handling_or_an_idle_connection() {
    let budget = Duration::from_millis(300);
    let cfg = ServerConfig {
        request_timeout: Some(Duration::from_millis(150)),
        max_receipt_time: Some(budget),
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
            for i in 0..3 {
                send_framed(&mut s, b"ping")?;
                assert_eq!(recv_framed(&mut s)?, b"ping", "round {i}");
                // Idle for well over the budget between requests. A budget
                // still armed from the last message reaps the slot here.
                thread::sleep(budget * 3);
            }
            // And a message split across the budget in ONE go is fine so
            // long as it lands inside it.
            s.write_all(&4u32.to_be_bytes())?;
            s.flush()?;
            thread::sleep(budget / 3);
            s.write_all(b"tail")?;
            s.flush()?;
            assert_eq!(recv_framed(&mut s)?, b"tail");
            Ok(())
        })();
        stop.shutdown();
        r
    });

    server.serve_forever().expect("serve_forever");
    client.join().expect("thread join").expect("client io");
}

#[test]
fn request_timeout_reclaims_stalled_more_scan() {
    // SECURITY (slow-loris, chunk-read path): a `More`/delimiter framer reads
    // in chunks that complete on any byte, so the request clock bounds them by
    // inactivity. A peer that sends a partial header (no `\r\n\r\n`) then stalls
    // has its non-idle chunk read time out and its slot reclaimed - the
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
// The handshake/probe scaffolding - throwaway cert, `truenas_ktls` acceptor,
// OpenSSL client, and the ULP/engagement skip machinery - is shared with
// `test/http_live.rs`; see `test/support/ktls.rs`.

#[path = "support/ktls.rs"]
mod ktls;
use ktls::{
    ktls_acceptor, ktls_openssl_unsupported, ktls_server_handshake,
    ktls_unsupported, self_signed, tls_connect,
};

/// Shuts the server down when dropped. Every test here runs `serve_forever`
/// on the test thread and drives the client from a spawned thread, so a
/// panicking client (a failed assert, an I/O expect) would otherwise skip
/// its shutdown call and strand the server - hanging the whole test binary
/// instead of going red. A clone of the handle in this guard makes the
/// panic surface through `client.join()`.
struct ShutdownOnDrop(ShutdownHandle);

impl Drop for ShutdownOnDrop {
    fn drop(&mut self) {
        self.0.shutdown();
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
            // 512 KiB is above `RECV_POOL_BUF`, so the body is *placed* -
            // read into its own allocation rather than the pool buffer -
            // which is the arm the kTLS continuation's bound has to follow.
            // Well under the 1 MiB `max_request_bytes` a server advertises,
            // so this is an ordinary message, not an edge.
            let big = vec![0x5au8; 512 * 1024];
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
    // cleanly - the worker calls deferral.reject(), the slot is shed - and the
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
            // Plaintext junk -> the server's SSL_accept fails -> reject -> shed.
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

/// A worker's `ready()` alone does not make a socket encrypted: the
/// deferral reads the kernel's per-direction key state back
/// (`getsockopt(SOL_TLS, TLS_TX/TLS_RX)`) and sheds a connection whose
/// keys the kernel does not hold. Without the readback a hook that never
/// ran a handshake - or a library that silently fell back to userspace
/// records - has the server framing plaintext as TLS; this test's client
/// speaks bare TCP and must be shed unanswered.
#[test]
fn ktls_ready_without_kernel_keys_is_shed() {
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
    server.set_tls_handshake(move |fd, _inc, deferral| {
        thread::spawn(move || {
            // No handshake at all: claim success on an untouched TCP
            // socket. The furnished fd is closed first, as a worker done
            // with it would - the readback rides the deferral's own dup,
            // not a number that may be reused.
            // SAFETY: the furnished fd is the worker's to close.
            unsafe { libc::close(fd) };
            deferral.ready(());
        });
    });
    let stats = server.stats_handle();
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();
    let client = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop); // shuts down even if this panics
        (|| -> io::Result<()> {
            let mut s = connect_tcp(v4)?;
            s.set_read_timeout(Some(Duration::from_secs(3)))?;
            send_framed(&mut s, b"clear?")?;
            let mut one = [0u8; 1];
            match s.read(&mut one) {
                Ok(0) => Ok(()), // shed: EOF, nothing served
                Ok(_) => panic!(
                    "a ready() with no kernel keys was served in the clear"
                ),
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::ConnectionReset
                            | io::ErrorKind::UnexpectedEof
                    ) =>
                {
                    Ok(())
                }
                Err(e) => Err(e),
            }
        })()
        .expect("client io");
    });
    server.serve_forever().expect("serve_forever");
    client.join().expect("thread join");
    let s = stats.snapshot();
    assert!(s.shed >= 1, "the unkeyed connection was shed: {s:?}");
    assert_eq!(s.replies, 0, "and nothing was answered: {s:?}");
}

/// A shutdown that lands while bytes are arriving must not abort.
///
/// Stopping the reactor reaps outstanding completions rather than
/// dispatching them, so a recv the kernel has already chosen a provided
/// buffer for is drained without that buffer ever being adopted. Its
/// descriptor is consumed and the connection is going away, which is
/// correct - but it means the kernel's consumer head and this side's
/// posted count legitimately disagree at teardown, and any drain-time
/// equality check between them fires on an ordinary shutdown. `Server`
/// drains from `Drop`, where a panic aborts the process rather than
/// failing a test, so such a check costs a crash on a correct path.
#[test]
fn a_shutdown_amid_arrivals_tears_down_quietly() {
    let cfg = ServerConfig {
        pool_size: 8,
        ..ServerConfig::default()
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let proto = length_prefixed(
        PrefixWidth::U32,
        Endian::Big,
        false,
        |_h: &[u8], body: &[u8], _p: &ClientAddr| Some(echo_frame(body)),
    );
    let mut server = match Server::with_config([addr], cfg, proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind: {e}"),
    };
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stats = server.stats_handle();
    let stop = server.shutdown_handle();
    let client = thread::spawn(move || {
        // One full round trip first, so the fixture is known to have been
        // accepted and served before anything races - the shutdown below
        // is deliberately concurrent and would otherwise be free to win
        // before the first accept.
        let mut first = connect_tcp(v4).expect("connect");
        send_framed(&mut first, b"warmup").expect("send");
        assert_eq!(recv_framed(&mut first).expect("echo"), b"warmup");

        // Then several connections delivering at the moment the reactor
        // stops, so a recv completes with a buffer already selected and is
        // reaped rather than dispatched.
        let mut socks = Vec::new();
        for _ in 0..6 {
            let mut s = connect_tcp(v4).expect("connect");
            s.write_all(&64u32.to_be_bytes()).expect("prefix");
            socks.push(s);
        }
        for s in socks.iter_mut() {
            let _ = s.write_all(&[7u8; 64]);
        }
        stop.shutdown();
        for s in socks.iter_mut() {
            let _ = s.write_all(&64u32.to_be_bytes());
            let _ = s.write_all(&[7u8; 64]);
        }
        thread::sleep(Duration::from_millis(50));
        drop(socks);
        drop(first);
    });
    server.serve_forever().expect("serve_forever");
    client.join().expect("thread join");
    // Reaching here at all is the assertion: the drop below must not abort.
    let s = stats.snapshot();
    assert!(s.replies >= 1, "the fixture was served: {s:?}");
}

/// Half a handshake is not a handshake: a socket the kernel keyed in only
/// **one** direction passes the other direction's bytes in the clear, so
/// `ready()` sheds it exactly as it sheds an unkeyed one.
///
/// The unkeyed case cannot see this distinction. A predicate that ORs the
/// two directions instead of ANDing them still refuses a socket with no
/// keys at all - passing `ktls_ready_without_kernel_keys_is_shed` - while
/// admitting this one, whose TX side is plaintext on the wire. The hook
/// installs the RX key only, leaving `tx_conf` at `TLS_BASE`, which is the
/// shape a handshake library with a TLS 1.3 RX/TX gap produces.
#[test]
fn ktls_ready_with_only_one_direction_keyed_is_shed() {
    const SOL_TLS: libc::c_int = 282;
    const TLS_RX: libc::c_int = 2;
    const TCP_ULP: libc::c_int = 31;
    // `struct tls12_crypto_info_aes_gcm_128`. The contents do not matter -
    // only that the kernel accepts them and sets `crypto_recv.info`.
    #[repr(C)]
    struct AesGcm128 {
        version: u16,
        cipher_type: u16,
        iv: [u8; 8],
        key: [u8; 16],
        salt: [u8; 4],
        rec_seq: [u8; 8],
    }

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
    server.set_tls_handshake(move |fd, _inc, deferral| {
        thread::spawn(move || {
            // Attach the ULP and key RX only, so everything the server
            // sends goes out in the clear.
            // SAFETY: setsockopt on the furnished fd this worker owns.
            let keyed_one_way = unsafe {
                let tls = b"tls\0";
                libc::setsockopt(
                    fd,
                    libc::IPPROTO_TCP,
                    TCP_ULP,
                    tls.as_ptr().cast(),
                    tls.len() as libc::socklen_t,
                ) == 0
                    && {
                        let ci = AesGcm128 {
                            version: 0x0303, // TLS_1_2_VERSION
                            cipher_type: 51, // TLS_CIPHER_AES_GCM_128
                            iv: [1; 8],
                            key: [2; 16],
                            salt: [3; 4],
                            rec_seq: [0; 8],
                        };
                        libc::setsockopt(
                            fd,
                            SOL_TLS,
                            TLS_RX,
                            (&raw const ci).cast(),
                            size_of::<AesGcm128>() as libc::socklen_t,
                        ) == 0
                    }
            };
            // SAFETY: the furnished fd is the worker's to close. The
            // readback rides the deferral's own dup.
            unsafe { libc::close(fd) };
            if keyed_one_way {
                deferral.ready(()); // "success" on a half-keyed socket
            } else {
                deferral.reject(); // this kernel would not key it
            }
        });
    });
    let stats = server.stats_handle();
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();
    let client = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop);
        (|| -> io::Result<()> {
            let mut s = connect_tcp(v4)?;
            s.set_read_timeout(Some(Duration::from_secs(3)))?;
            send_framed(&mut s, b"clear?")?;
            let mut one = [0u8; 1];
            match s.read(&mut one) {
                Ok(0) => Ok(()),
                Ok(_) => {
                    panic!("a half-keyed ready() was served in the clear")
                }
                // WouldBlock is tolerated because an admitted half-keyed
                // connection answers nothing either - the read alone cannot
                // separate the two. The stats assertion below is what does.
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::ConnectionReset
                            | io::ErrorKind::UnexpectedEof
                            | io::ErrorKind::WouldBlock
                            | io::ErrorKind::TimedOut
                    ) =>
                {
                    Ok(())
                }
                Err(e) => Err(e),
            }
        })()
        .expect("client io");
    });
    server.serve_forever().expect("serve_forever");
    client.join().expect("thread join");
    let s = stats.snapshot();
    // Shed, not installed-then-closed: under an OR predicate the connection
    // is admitted, so `shed` stays 0 and the teardown counts as `closed`.
    assert!(s.shed >= 1, "the half-keyed connection was shed: {s:?}");
    assert_eq!(s.replies, 0, "and nothing was answered: {s:?}");
}

#[test]
fn ktls_handshake_timeout_sheds_parked_slot() {
    // SECURITY: a kTLS connection whose handshake never completes (the
    // consumer's worker never calls back) parks a pool slot - it holds a
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
    // Buffer each deferral (never resolving it -> no reject-shed) and close the
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
        // handshake - the park timeout must shed each slot.
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
    // A polite TLS client ends its session with close_notify - on the wire a
    // 2-byte alert record. The server's parked exact header read completes
    // SHORT with record type 21 (alert), which must classify as TlsControl --
    // the documented reason for a peer's clean TLS close - not as
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
    // The subtle case this pins down is the recvmsg->splice handoff. kTLS
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
        "kTLS splice moved {off} of {BODY} body bytes - rx_list truncation?"
    );
    assert_eq!(got, expected, "kTLS spliced body content mismatch");
    // SAFETY: closing the test-owned write end (the server only borrowed it).
    unsafe { libc::close(pipe_wr) };
}

#[test]
fn ktls_splice_body_slow_but_progressing_survives() {
    // The other half of the watchdog contract (the race the standalone-timeout
    // design must NOT lose): a kTLS splice that keeps making progress - even
    // slowly, spanning several `request_timeout` periods - must run to
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
    // io-wq worker waiting for the next TLS record - it honors only
    // SPLICE_F_NONBLOCK (which the server must not set) and, unlike
    // `tcp_splice_read`, never the socket's O_NONBLOCK - so the plain-TCP
    // EAGAIN -> readiness-poll path that carries the request clock NEVER runs
    // for kTLS. The clock is therefore linked to the kTLS splice itself: a
    // peer that completes the handshake, sends a SpliceBody header, and then
    // goes silent must be reclaimed by `request_timeout` - not pin its pool
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
            // error - anything but a hang (the underlying socket carries a
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

#[cfg(feature = "uring-fs")]
#[test]
fn server_builds_with_fs_pool() {
    // A server with `fs_ops` set drives an fs reactor on the same ring, its
    // op table sized `fs_ops + pool_size`. Open files are plain raw fds, not
    // registered-table slots, so the connection pool stays `pool_size`.
    // Constructing it exercises that path on a real ring; a plain echo still
    // serves over the same ring.
    let cfg = ServerConfig {
        pool_size: 16,
        fs_ops: 16,
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
        Err(e) => panic!("bind with fs pool: {e}"),
    };
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();
    let client = thread::spawn(move || {
        let r = one_shot(v4, 0);
        stop.shutdown();
        r
    });
    server.serve_forever().expect("serve_forever with fs pool");
    assert_eq!(client.join().unwrap().expect("client io"), b"req-0");
}

/// A graceful drain waits for a task, and stops as soon as it retires.
///
/// The wait is deliberate - a task outlives the connection that spawned
/// it - but the quiescence test has to be re-read somewhere the gauge
/// falling can reach, or the drain sits out its whole grace period and
/// leaves through the `Deadline` hard stop instead. The grace here is
/// long and the task is short, so the two outcomes are seconds apart.
///
/// **Bounded on both sides, because both failures are silent.** The
/// upper bound catches a drain that hangs to its deadline. The lower
/// one catches the opposite and worse mutation - a drain that stops
/// ignoring tasks altogether, dropping their work on the floor - which
/// on a `SIGTERM` with a long grace looks exactly like a clean
/// shutdown. Without it, discarding the task gauge entirely leaves this
/// test green.
#[cfg(feature = "uring-fs")]
#[test]
fn a_graceful_drain_ends_when_its_last_task_retires() {
    let cfg = ServerConfig {
        pool_size: 4,
        fs_ops: 8,
        ..ServerConfig::default()
    };
    let body = move |mut req: Request<'_, ()>| -> Response {
        let Some(mut fs) = req.fs.take() else {
            return Response::Close;
        };
        // Pending with no connection and no ring op: the shape a
        // connection count cannot see. It outlives the reply below and
        // the close that follows it.
        drop(fs.spawn(|t| async move {
            let _ = t
                .offload_fut(|| {
                    thread::sleep(Duration::from_millis(300));
                    Ok(())
                })
                .await;
        }));
        Response::Reply(echo_frame(b"spawned"))
    };
    let protocol = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(
            PrefixWidth::U32,
            Endian::Big,
            false,
        ),
        body,
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let mut server = match Server::with_config([addr], cfg, protocol) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind with fs pool: {e}"),
    };
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();
    const GRACE: Duration = Duration::from_secs(5);
    let client = thread::spawn(move || -> io::Result<()> {
        let mut c = connect_tcp(v4)?;
        send_framed(&mut c, b"go")?;
        assert_eq!(recv_framed(&mut c)?, b"spawned");
        // The task is still pending; the table empties behind it.
        drop(c);
        stop.shutdown_graceful(GRACE);
        Ok(())
    });
    let began = Instant::now();
    server.serve_forever().expect("serve_forever");
    let took = began.elapsed();
    client.join().expect("client thread").expect("client io");
    assert!(
        took < GRACE / 2,
        "the drain ran to its grace deadline ({took:?}) rather than \
         stopping when the task retired"
    );
    assert!(
        took >= Duration::from_millis(250),
        "the drain stopped in {took:?}, inside the task's own 300 ms - so \
         it did not wait for the task at all and dropped its work"
    );
}

/// The M4 headline: a static-file server. Each request names a file; the body
/// handler opens it on the server's own ring under a per-connection
/// [`Personality`], reads it, and replies with its contents - all inline on the
/// loop thread via `Request::fs` and the `Deferred` reuse (open -> read -> reply,
/// no worker thread, no blocking the ring). Two requests on one keep-alive
/// connection prove the fixed-file slot is opened and freed per request rather
/// than leaked.
#[cfg(feature = "uring-fs")]
#[test]
fn fs_static_file_server_open_read_reply() {
    use std::ffi::CString;
    use std::sync::OnceLock;
    use truenas_ros::sync_fs::{OFlag, OpenHow};
    use truenas_ros::uring_fs::{Anchor, Personality, RwFlags};

    let dir = truenas_ros::tempdir().unwrap();
    std::fs::write(dir.path().join("hello.txt"), b"contents of hello").unwrap();
    std::fs::write(dir.path().join("second.txt"), b"the second file").unwrap();

    // The reactor's own creds, minted after construction; the handler reads it
    // through a shared cell (the closure is moved into the server first).
    let pers: Arc<OnceLock<Personality>> = Arc::new(OnceLock::new());
    let anchor = match Anchor::open(dir.path()) {
        Ok(a) => a,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("anchor open: {e}"),
    };

    let pc = Arc::clone(&pers);
    let body = move |mut req: Request<'_, ()>| -> Response {
        let name = req.body.take(); // the requested filename
        let (deferred, permit) = req.responder.defer();
        let Some(mut fs) = req.fs.take() else {
            return Response::Close; // built without an fs pool
        };
        let who = *pc.get().expect("personality set before serving");
        let anchor = anchor.clone();
        let Ok(path) = CString::new(name) else {
            deferred.close();
            return Response::Defer(permit);
        };
        let how = OpenHow::new().flags(OFlag::O_RDONLY);
        fs.open(who, &anchor, &path, how, move |done, fs| {
            let Some(file) = done.file() else {
                deferred.close(); // open failed (ENOENT/EACCES - the personality working)
                return;
            };
            fs.preadv2(
                who,
                file.clone(),
                vec![vec![0u8; 4096]],
                0,
                RwFlags::empty(),
                move |done, fs| {
                    fs.close(file); // fire-and-forget: free the slot
                    match done.result() {
                        Ok(n) => {
                            let mut buf =
                                done.into_bufs().pop().unwrap_or_default();
                            buf.truncate(n as usize);
                            deferred.reply(echo_frame(&buf));
                        }
                        Err(_) => deferred.close(),
                    }
                },
            );
        });
        Response::Defer(permit)
    };
    let protocol = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(
            PrefixWidth::U32,
            Endian::Big,
            false,
        ),
        body,
    };
    let cfg = ServerConfig {
        pool_size: 16,
        fs_ops: 16,
        ..ServerConfig::default()
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let mut server = match Server::with_config([addr], cfg, protocol) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind with fs pool: {e}"),
    };
    pers.set(server.register_self().expect("register_self"))
        .unwrap();
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();
    let client = thread::spawn(move || -> io::Result<(Vec<u8>, Vec<u8>)> {
        let mut s = connect_tcp(v4)?;
        // Two files on ONE keep-alive connection: proves per-request open/close.
        send_framed(&mut s, b"hello.txt")?;
        let first = recv_framed(&mut s)?;
        send_framed(&mut s, b"second.txt")?;
        let second = recv_framed(&mut s)?;
        drop(s);
        stop.shutdown();
        Ok((first, second))
    });
    server.serve_forever().expect("serve_forever static-file");
    let (first, second) = client.join().unwrap().expect("client io");
    assert_eq!(first, b"contents of hello");
    assert_eq!(second, b"the second file");
}

/// A directory listing replies through the wake drain. The handler lists on the
/// ring via `open_dir`/`next_batch`, both delivered by off-loop worker jobs
/// that poke the wake, and answers with the entry count via its `Deferred`.
/// The reply only arrives if `on_wake` drains the fs offload pool; without that
/// drain the completion is stranded, the request never answers, and the client
/// read times out. The socket read timeout makes that regression a failure
/// rather than a hang.
#[cfg(feature = "uring-fs")]
#[test]
fn fs_dir_listing_replies_through_the_wake_drain() {
    use std::rc::Rc;
    use std::sync::OnceLock;
    use std::time::Duration;
    use truenas_ros::uring_fs::{Anchor, Personality};

    let dir = truenas_ros::tempdir().unwrap();
    for i in 0..3 {
        std::fs::write(dir.path().join(format!("f{i}")), b"x").unwrap();
    }

    let pers: Arc<OnceLock<Personality>> = Arc::new(OnceLock::new());
    let anchor = match Anchor::open(dir.path()) {
        Ok(a) => a,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("anchor open: {e}"),
    };

    let pc = Arc::clone(&pers);
    let body = move |mut req: Request<'_, ()>| -> Response {
        let (deferred, permit) = req.responder.defer();
        let Some(mut fs) = req.fs.take() else {
            return Response::Close; // built without an fs pool
        };
        let who = *pc.get().expect("personality set before serving");
        let anchor = anchor.clone();
        fs.open_dir(who, &anchor, move |res, fs| {
            let walk = match res {
                Ok(w) => Rc::new(w),
                Err(_) => return deferred.close(),
            };
            // Hold the walk alive through the batch delivery: the `keep` clone
            // rides in the continuation, so the `DIR*` is not dropped mid-flight.
            let keep = Rc::clone(&walk);
            fs.next_batch(&walk, move |res, _fs| {
                let _keep = keep;
                match res {
                    Ok(batch) => {
                        deferred.reply(echo_frame(
                            batch.names.len().to_string().as_bytes(),
                        ));
                    }
                    Err(_) => deferred.close(),
                }
            });
        });
        Response::Defer(permit)
    };
    let protocol = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(
            PrefixWidth::U32,
            Endian::Big,
            false,
        ),
        body,
    };
    let cfg = ServerConfig {
        pool_size: 16,
        fs_ops: 16,
        ..ServerConfig::default()
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let mut server = match Server::with_config([addr], cfg, protocol) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind with fs pool: {e}"),
    };
    pers.set(server.register_self().expect("register_self"))
        .unwrap();
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();
    let client = thread::spawn(move || -> io::Result<Vec<u8>> {
        let mut s = connect_tcp(v4)?;
        s.set_read_timeout(Some(Duration::from_secs(5)))?;
        send_framed(&mut s, b"list")?;
        let reply = recv_framed(&mut s); // times out if the drain is missing
        drop(s);
        stop.shutdown(); // unconditional: unblock serve_forever even on timeout
        reply
    });
    server.serve_forever().expect("serve_forever dir-listing");
    let reply = client.join().unwrap().expect("client io");
    assert_eq!(reply, b"3", "listing counted the three entries and replied");
}

/// `FsConn::flistxattr` enumerates a file's xattr names on-loop: it opens the
/// file on the ring, offloads the `flistxattr` to the pool, and delivers the
/// names on the loop, answered via `Deferred` (same drain path as the listing).
#[cfg(feature = "uring-fs")]
#[test]
fn fs_conn_flistxattr_lists_file_xattrs() {
    use std::ffi::CString;
    use std::sync::OnceLock;
    use std::time::Duration;
    use truenas_ros::sync_fs::{OFlag, OpenHow};
    use truenas_ros::uring_fs::{Anchor, Personality};

    let dir = truenas_ros::tempdir().unwrap();
    let fp = dir.path().join("f.txt");
    std::fs::write(&fp, b"x").unwrap();
    // Seed two user xattrs with a plain syscall (independent of fd-xattr
    // support, which only gates the ring read/write ops).
    let cpath = CString::new(fp.to_string_lossy().as_bytes().to_vec()).unwrap();
    for (name, val) in [("user.a", b"1".as_slice()), ("user.b", b"22")] {
        let cname = CString::new(name).unwrap();
        // SAFETY: `cpath`/`cname` are valid NUL-terminated C strings; `val` is a
        // valid buffer of `val.len()` bytes for the syscall's duration.
        let rc = unsafe {
            libc::setxattr(
                cpath.as_ptr(),
                cname.as_ptr(),
                val.as_ptr().cast(),
                val.len(),
                0,
            )
        };
        if rc != 0 {
            return; // this fs refuses user xattrs
        }
    }

    let pers: Arc<OnceLock<Personality>> = Arc::new(OnceLock::new());
    let anchor = match Anchor::open(dir.path()) {
        Ok(a) => a,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("anchor open: {e}"),
    };

    let pc = Arc::clone(&pers);
    let body = move |mut req: Request<'_, ()>| -> Response {
        let (deferred, permit) = req.responder.defer();
        let Some(mut fs) = req.fs.take() else {
            return Response::Close;
        };
        let who = *pc.get().expect("personality set before serving");
        let anchor = anchor.clone();
        let how = OpenHow::new().flags(OFlag::O_RDONLY);
        fs.open(who, &anchor, c"f.txt", how, move |done, fs| {
            let Some(file) = done.file() else {
                return deferred.close();
            };
            fs.flistxattr(file, move |res, _fs| match res {
                Ok(names) => {
                    let joined = names
                        .iter()
                        .map(|c| c.to_string_lossy().into_owned())
                        .collect::<Vec<_>>()
                        .join("\n");
                    deferred.reply(echo_frame(joined.as_bytes()));
                }
                Err(_) => deferred.close(),
            });
        });
        Response::Defer(permit)
    };
    let protocol = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(
            PrefixWidth::U32,
            Endian::Big,
            false,
        ),
        body,
    };
    let cfg = ServerConfig {
        pool_size: 16,
        fs_ops: 16,
        ..ServerConfig::default()
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let mut server = match Server::with_config([addr], cfg, protocol) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind with fs pool: {e}"),
    };
    pers.set(server.register_self().expect("register_self"))
        .unwrap();
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();
    let client = thread::spawn(move || -> io::Result<Vec<u8>> {
        let mut s = connect_tcp(v4)?;
        s.set_read_timeout(Some(Duration::from_secs(5)))?;
        send_framed(&mut s, b"list")?;
        let reply = recv_framed(&mut s);
        drop(s);
        stop.shutdown();
        reply
    });
    server.serve_forever().expect("serve_forever flistxattr");
    let reply = client.join().unwrap().expect("client io");
    let text = String::from_utf8_lossy(&reply);
    assert!(
        text.contains("user.a"),
        "flistxattr listed user.a: {text:?}"
    );
    assert!(
        text.contains("user.b"),
        "flistxattr listed user.b: {text:?}"
    );
}

/// `FsConn::fstatfs`/`fstatfs_anchor` answer on-loop: each offloads to the
/// pool (io_uring has no statfs opcode) and delivers through the completion
/// sink. Both name the same filesystem, so their answers must agree - and the
/// anchor form proves an `O_PATH` descriptor is accepted, which is what lets a
/// caller ask a whole tree's capacity without opening anything inside it.
#[cfg(feature = "uring-fs")]
#[test]
fn fs_conn_fstatfs_agrees_from_file_and_anchor() {
    use std::sync::OnceLock;
    use std::time::Duration;
    use truenas_ros::sync_fs::{OFlag, OpenHow};
    use truenas_ros::uring_fs::{Anchor, Personality};

    let dir = truenas_ros::tempdir().unwrap();
    std::fs::write(dir.path().join("f.txt"), b"x").unwrap();

    let pers: Arc<OnceLock<Personality>> = Arc::new(OnceLock::new());
    let anchor = match Anchor::open(dir.path()) {
        Ok(a) => a,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("anchor open: {e}"),
    };

    let pc = Arc::clone(&pers);
    let body = move |mut req: Request<'_, ()>| -> Response {
        let (deferred, permit) = req.responder.defer();
        let Some(mut fs) = req.fs.take() else {
            return Response::Close;
        };
        let who = *pc.get().expect("personality set before serving");
        let anchor = anchor.clone();
        let how = OpenHow::new().flags(OFlag::O_RDONLY);
        // `open` first, then the offloads chain behind it - the chain
        // is what this test is about. (Every facade can open, an
        // offload-delivery continuation's included; the gate that once
        // said otherwise is gone.)
        fs.open(who, &anchor.clone(), c"f.txt", how, move |done, fs| {
            let Some(file) = done.file() else {
                return deferred.reply(echo_frame(
                    format!("OPEN {:?}", done.result()).as_bytes(),
                ));
            };
            fs.fstatfs(file, move |by_file, fs| {
                let by_file = match by_file {
                    Ok(v) => v,
                    Err(e) => {
                        return deferred
                            .reply(echo_frame(format!("FILE {e}").as_bytes()));
                    }
                };
                // offload -> offload: the second continuation still reaches
                // the pool, and an O_PATH anchor is a valid target.
                fs.fstatfs_anchor(&anchor, move |by_anchor, _fs| {
                    let msg = match by_anchor {
                        Ok(a) => {
                            let ok = a.block_size() > 0
                                && a.total_blocks() > 0
                                && a.block_size() == by_file.block_size()
                                && a.total_blocks() == by_file.total_blocks()
                                && a.available_blocks() <= a.free_blocks()
                                && a.total_bytes()
                                    == a.total_blocks() * a.block_size();
                            format!(
                                "{} bs={} total={}",
                                if ok { "agree" } else { "DISAGREE" },
                                a.block_size(),
                                a.total_blocks()
                            )
                        }
                        Err(e) => format!("ANCHOR {e}"),
                    };
                    deferred.reply(echo_frame(msg.as_bytes()));
                });
            });
        });
        Response::Defer(permit)
    };
    let protocol = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(
            PrefixWidth::U32,
            Endian::Big,
            false,
        ),
        body,
    };
    let cfg = ServerConfig {
        pool_size: 16,
        fs_ops: 16,
        ..ServerConfig::default()
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let mut server = match Server::with_config([addr], cfg, protocol) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind with fs pool: {e}"),
    };
    pers.set(server.register_self().expect("register_self"))
        .unwrap();
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();
    let client = thread::spawn(move || -> io::Result<Vec<u8>> {
        let mut s = connect_tcp(v4)?;
        s.set_read_timeout(Some(Duration::from_secs(5)))?;
        send_framed(&mut s, b"statfs")?;
        let reply = recv_framed(&mut s);
        drop(s);
        stop.shutdown();
        reply
    });
    server.serve_forever().expect("serve_forever fstatfs");
    let reply = client.join().unwrap().expect("client io");
    let text = String::from_utf8_lossy(&reply);
    assert!(
        text.starts_with("agree "),
        "file and anchor must report one filesystem: {text:?}"
    );
}

/// `FsConn::fget_zfs_attrs`/`fset_zfs_attrs` on-loop: read the mask, set
/// `IMMUTABLE`, read it back, and restore - each hop an offload delivered
/// through the completion sink.
///
/// Needs a real ZFS dataset; on tmpfs the ioctl is `ENOTTY`. Resolved the way
/// `test/zfs.rs` does, and skipped loudly under `TRUENAS_ROS_REQUIRE_ZFS` so a
/// runner that stopped provisioning one goes red rather than reporting a green
/// suite that exercised nothing.
#[cfg(feature = "uring-fs")]
#[test]
fn fs_conn_zfs_attrs_round_trip_through_the_pool() {
    use std::path::PathBuf;
    use std::sync::OnceLock;
    use std::time::Duration;
    use truenas_ros::sync_fs::{OFlag, OpenHow, ZfsAttr};
    use truenas_ros::uring_fs::{Anchor, Personality};

    let ds = ["TRUENAS_ROS_NFS4_DATASET", "TRUENAS_ROS_POSIX_DATASET"]
        .iter()
        .filter_map(|v| std::env::var_os(v).map(PathBuf::from))
        .chain(["/NFSV4ACL", "/POSIXACL"].iter().map(PathBuf::from))
        .find(|d| d.is_dir());
    let Some(ds) = ds else {
        assert!(
            std::env::var_os("TRUENAS_ROS_REQUIRE_ZFS").is_none(),
            "TRUENAS_ROS_REQUIRE_ZFS is set but no ZFS dataset is present"
        );
        return;
    };
    let fp = ds.join("ros-fsconn-zfsattr.bin");
    let _ = std::fs::remove_file(&fp);
    std::fs::write(&fp, b"x").unwrap();

    let pers: Arc<OnceLock<Personality>> = Arc::new(OnceLock::new());
    let anchor = match Anchor::open(ds.as_path()) {
        Ok(a) => a,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("anchor open: {e}"),
    };

    let pc = Arc::clone(&pers);
    let body = move |mut req: Request<'_, ()>| -> Response {
        let (deferred, permit) = req.responder.defer();
        let Some(mut fs) = req.fs.take() else {
            return Response::Close;
        };
        let who = *pc.get().expect("personality set before serving");
        let anchor = anchor.clone();
        let how = OpenHow::new().flags(OFlag::O_RDWR);
        fs.open(
            who,
            &anchor,
            c"ros-fsconn-zfsattr.bin",
            how,
            move |done, fs| {
                let Some(file) = done.file() else {
                    return deferred.reply(echo_frame(
                        format!("OPEN {:?}", done.result()).as_bytes(),
                    ));
                };
                let f2 = file.clone();
                let f3 = file.clone();
                fs.fget_zfs_attrs(file, move |before, fs| {
                    let before = match before {
                        Ok(v) => v,
                        Err(e) => {
                            return deferred.reply(echo_frame(
                                format!("GET {e}").as_bytes(),
                            ));
                        }
                    };
                    fs.fset_zfs_attrs(
                        f2,
                        before | ZfsAttr::IMMUTABLE,
                        move |set, fs| {
                            if let Err(e) = set {
                                return deferred.reply(echo_frame(
                                    format!("SET {e}").as_bytes(),
                                ));
                            }
                            fs.fget_zfs_attrs(f3.clone(), move |after, fs| {
                                let locked = matches!(&after, Ok(a)
                                    if a.contains(ZfsAttr::IMMUTABLE));
                                // Restore before answering, or the dataset is
                                // left with an undeletable file.
                                fs.fset_zfs_attrs(f3, before, move |r, _fs| {
                                    let msg = if !locked {
                                        format!("NOTLOCKED {after:?}")
                                    } else if r.is_err() {
                                        "UNLOCK-FAILED".to_string()
                                    } else {
                                        "locked-then-restored".to_string()
                                    };
                                    deferred.reply(echo_frame(msg.as_bytes()));
                                });
                            });
                        },
                    );
                });
            },
        );
        Response::Defer(permit)
    };
    let protocol = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(
            PrefixWidth::U32,
            Endian::Big,
            false,
        ),
        body,
    };
    let cfg = ServerConfig {
        pool_size: 16,
        fs_ops: 16,
        ..ServerConfig::default()
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let mut server = match Server::with_config([addr], cfg, protocol) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind with fs pool: {e}"),
    };
    pers.set(server.register_self().expect("register_self"))
        .unwrap();
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();
    let client = thread::spawn(move || -> io::Result<Vec<u8>> {
        let mut s = connect_tcp(v4)?;
        s.set_read_timeout(Some(Duration::from_secs(5)))?;
        send_framed(&mut s, b"attrs")?;
        let reply = recv_framed(&mut s);
        drop(s);
        stop.shutdown();
        reply
    });
    server.serve_forever().expect("serve_forever zfs attrs");
    let reply = client.join().unwrap().expect("client io");
    let text = String::from_utf8_lossy(&reply).into_owned();
    let _ = std::fs::remove_file(&fp);
    // Unprivileged, setting IMMUTABLE is refused - which is the property
    // under test, so assert that rather than treating it as a skip.
    if text.starts_with("SET ") {
        assert!(
            text.contains("EPERM") && !is_root(),
            "only an unprivileged caller may be refused: {text:?}"
        );
        return;
    }
    assert_eq!(text, "locked-then-restored", "round trip through the pool");
}

/// The batched-blocking-offload consumer shape, end to end: the
/// credential-checked open runs on the ring as a personality-stamped SQE,
/// then ONE `FsConn::offload_result` job runs the whole blocking metadata
/// tail - `statx` plus two xattr reads on the already-authorized fd (`File`
/// is `AsFd`) - and the delivery arrives through the wake path's
/// `drain_fs_offloads` on an owner-scoped continuation facade.
#[cfg(feature = "uring-fs")]
#[test]
fn fs_conn_offload_result_batches_statx_and_xattrs_in_one_job() {
    use std::sync::OnceLock;
    use std::time::Duration;
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

    let pers: Arc<OnceLock<Personality>> = Arc::new(OnceLock::new());
    let anchor = match Anchor::open(dir.path()) {
        Ok(a) => a,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("anchor open: {e}"),
    };

    let pc = Arc::clone(&pers);
    let body = move |mut req: Request<'_, ()>| -> Response {
        let (deferred, permit) = req.responder.defer();
        let Some(mut fs) = req.fs.take() else {
            return Response::Close;
        };
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
                        let msg = format!(
                            "{size}:{}:{}",
                            String::from_utf8_lossy(&a),
                            String::from_utf8_lossy(&b),
                        );
                        deferred.reply(echo_frame(msg.as_bytes()));
                    }
                    Err(_) => deferred.close(),
                },
            );
        });
        Response::Defer(permit)
    };
    let protocol = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(
            PrefixWidth::U32,
            Endian::Big,
            false,
        ),
        body,
    };
    let cfg = ServerConfig {
        pool_size: 16,
        fs_ops: 16,
        ..ServerConfig::default()
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let mut server = match Server::with_config([addr], cfg, protocol) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind with fs pool: {e}"),
    };
    pers.set(server.register_self().expect("register_self"))
        .unwrap();
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();
    let client = thread::spawn(move || -> io::Result<Vec<u8>> {
        let mut s = connect_tcp(v4)?;
        s.set_read_timeout(Some(Duration::from_secs(5)))?;
        send_framed(&mut s, b"head")?;
        let reply = recv_framed(&mut s);
        drop(s);
        stop.shutdown();
        reply
    });
    server
        .serve_forever()
        .expect("serve_forever offload_result");
    let reply = client.join().unwrap().expect("client io");
    assert_eq!(
        String::from_utf8_lossy(&reply),
        "12:1:22",
        "one job returned size and both xattr values"
    );
}

/// Read `name` off `path` with `libc::getxattr`, `None` on any failure -
/// the out-of-band witness for the privileged-xattr policy test below.
#[cfg(feature = "uring-fs")]
fn get_xattr_raw(path: &Path, name: &std::ffi::CStr) -> Option<Vec<u8>> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let cpath = CString::new(path.as_os_str().as_bytes()).unwrap();
    let mut buf = vec![0u8; 256];
    // SAFETY: valid NUL-terminated path/name and an owned out-buffer.
    let n = unsafe {
        libc::getxattr(
            cpath.as_ptr(),
            name.as_ptr(),
            buf.as_mut_ptr().cast(),
            buf.len(),
        )
    };
    if n < 0 {
        return None;
    }
    buf.truncate(n as usize);
    Some(buf)
}

/// `Server::set_privileged_xattrs` reaches the embedded reactor. With a
/// policy allowing `trusted.test_`: a covered `fsetxattr` through the
/// request facade lands (promoted to the reactor's own credentials), an
/// **uncovered** `fremovexattr` stays `EPERM`, and a **covered**
/// `fremovexattr` succeeds - the leg that bites, since that path is gated
/// on the allowlist alone and fails `EPERM` under the default empty policy
/// whether or not the caller is privileged. The `trusted.` namespace needs
/// `CAP_SYS_ADMIN`: unprivileged, the covered write's refusal is itself the
/// asserted property (the promotion escalates to the daemon's own identity,
/// which has nothing to escalate to). The qemu lane runs as root and takes
/// the full path.
#[cfg(feature = "uring-fs")]
#[test]
fn server_privileged_xattr_policy_reaches_the_embedded_reactor() {
    use std::sync::OnceLock;
    use std::time::Duration;
    use truenas_ros::sync_fs::{OFlag, OpenHow};
    use truenas_ros::uring_fs::{Anchor, Personality, PrivilegedXattrs};

    let dir = truenas_ros::tempdir().unwrap();
    let fp = dir.path().join("f.txt");
    std::fs::write(&fp, b"x").unwrap();
    if is_root() && !set_user_xattr(&fp, b"trusted.probe", b"1") {
        return; // this fs refuses trusted xattrs even to root
    }

    let pers: Arc<OnceLock<Personality>> = Arc::new(OnceLock::new());
    let anchor = match Anchor::open(dir.path()) {
        Ok(a) => a,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("anchor open: {e}"),
    };

    let pc = Arc::clone(&pers);
    let body = move |mut req: Request<'_, ()>| -> Response {
        let (deferred, permit) = req.responder.defer();
        let Some(mut fs) = req.fs.take() else {
            return Response::Close;
        };
        let who = *pc.get().expect("personality set before serving");
        let anchor = anchor.clone();
        let how = OpenHow::new().flags(OFlag::O_RDONLY);
        fs.open(who, &anchor, c"f.txt", how, move |done, fs| {
            let Some(file) = done.file() else {
                return deferred.reply(echo_frame(
                    format!("OPEN {:?}", done.result()).as_bytes(),
                ));
            };
            let f2 = file.clone();
            let f3 = file.clone();
            fs.fsetxattr(
                who,
                file,
                c"trusted.test_x",
                b"v1".to_vec(),
                0,
                move |set, fs| {
                    if let Err(e) = set.result() {
                        return deferred
                            .reply(echo_frame(format!("SET {e}").as_bytes()));
                    }
                    fs.fremovexattr(
                        f2,
                        c"trusted.other".into(),
                        move |out, fs| {
                            if out.is_ok() {
                                return deferred
                                    .reply(echo_frame(b"UNCOVERED-REMOVED"));
                            }
                            fs.fremovexattr(
                                f3,
                                c"trusted.test_x".into(),
                                move |cov, _fs| match cov {
                                    Ok(()) => deferred
                                        .reply(echo_frame(b"policy-enforced")),
                                    Err(e) => deferred.reply(echo_frame(
                                        format!("RM-COVERED {e}").as_bytes(),
                                    )),
                                },
                            );
                        },
                    );
                },
            );
        });
        Response::Defer(permit)
    };
    let protocol = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(
            PrefixWidth::U32,
            Endian::Big,
            false,
        ),
        body,
    };
    let cfg = ServerConfig {
        pool_size: 16,
        fs_ops: 16,
        ..ServerConfig::default()
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let mut server = match Server::with_config([addr], cfg, protocol) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind with fs pool: {e}"),
    };
    server.set_privileged_xattrs(
        PrivilegedXattrs::new()
            .allow_prefix(c"trusted.test_")
            .expect("a trusted.-rooted prefix is accepted"),
    );
    pers.set(server.register_self().expect("register_self"))
        .unwrap();
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();
    let client = thread::spawn(move || -> io::Result<Vec<u8>> {
        let mut s = connect_tcp(v4)?;
        s.set_read_timeout(Some(Duration::from_secs(5)))?;
        send_framed(&mut s, b"go")?;
        let reply = recv_framed(&mut s);
        drop(s);
        stop.shutdown();
        reply
    });
    server.serve_forever().expect("serve_forever priv xattrs");
    let reply = client.join().unwrap().expect("client io");
    let text = String::from_utf8_lossy(&reply).into_owned();
    if text.starts_with("SET ") {
        assert!(
            text.contains("EPERM") && !is_root(),
            "only an unprivileged daemon may be refused: {text:?}"
        );
        return;
    }
    assert_eq!(text, "policy-enforced", "unexpected chain result");
    // Out of band: the covered remove really removed - `trusted.test_x` is
    // gone while the probe attribute survives (so absence is not ENOTSUP).
    assert!(get_xattr_raw(&fp, c"trusted.probe").is_some());
    assert!(get_xattr_raw(&fp, c"trusted.test_x").is_none());
}

/// `FsConn::fgetxattr_as_root` reads an xattr under the reactor's ambient
/// (root) credentials (`sqe.personality = 0`) - the sanctioned privileged-read
/// path for a `trusted.*`/`security.*` attribute a request's own identity
/// can't see. Here it reads a seeded `user.*` value end to end; the full
/// privilege boundary (a non-root peer vs. a root-only xattr) isn't reproduced,
/// since on this root dev host the peer identity is itself root - the point is
/// exercising the `personality = 0` SQE path end to end.
#[cfg(feature = "uring-fs")]
#[test]
fn fs_file_carries_personality_and_as_root() {
    use std::ffi::CString;
    use std::sync::OnceLock;
    use truenas_ros::sync_fs::{OFlag, OpenHow};
    use truenas_ros::uring_fs::{Anchor, Personality};

    let dir = truenas_ros::tempdir().unwrap();
    let fpath = dir.path().join("f.txt");
    std::fs::write(&fpath, b"payload").unwrap();
    // Seed an xattr to read back through the ambient-root path; skip if the
    // filesystem refuses user xattrs (some `/tmp` configs).
    if !set_user_xattr(&fpath, b"user.tr_test", b"secret") {
        return;
    }

    let pers: Arc<OnceLock<Personality>> = Arc::new(OnceLock::new());
    let anchor = match Anchor::open(dir.path()) {
        Ok(a) => a,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("anchor open: {e}"),
    };

    let pc = Arc::clone(&pers);
    let body = move |mut req: Request<'_, ()>| -> Response {
        let _ = req.body.take();
        let (deferred, permit) = req.responder.defer();
        let Some(mut fs) = req.fs.take() else {
            return Response::Close;
        };
        let who = *pc.get().expect("personality set before serving");
        let anchor = anchor.clone();
        let path = CString::new("f.txt").unwrap();
        let how = OpenHow::new().flags(OFlag::O_RDONLY);
        fs.open(who, &anchor, &path, how, move |done, fs| {
            let Some(file) = done.file() else {
                deferred.close();
                return;
            };
            // Read the seeded xattr under ambient root (personality 0) - no
            // `who`. On this root host the peer is itself root, so this
            // exercises the `personality = 0` SQE path end to end rather than a
            // privilege boundary.
            let name = CString::new("user.tr_test").unwrap();
            fs.fgetxattr_as_root(
                file.clone(),
                &name,
                vec![0u8; 64],
                move |d, fs| {
                    fs.close(file);
                    match d.result() {
                        Ok(n) => {
                            let mut v = d.into_bufs().pop().unwrap_or_default();
                            v.truncate(n as usize);
                            deferred.reply(echo_frame(&v));
                        }
                        Err(_) => deferred.reply(echo_frame(b"xattr-err")),
                    }
                },
            );
        });
        Response::Defer(permit)
    };
    let protocol = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(
            PrefixWidth::U32,
            Endian::Big,
            false,
        ),
        body,
    };
    let cfg = ServerConfig {
        pool_size: 8,
        fs_ops: 8,
        ..ServerConfig::default()
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let mut server = match Server::with_config([addr], cfg, protocol) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind with fs pool: {e}"),
    };
    pers.set(server.register_self().expect("register_self"))
        .unwrap();
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();
    let client = thread::spawn(move || -> io::Result<Vec<u8>> {
        let mut s = connect_tcp(v4)?;
        send_framed(&mut s, b"go")?;
        let r = recv_framed(&mut s)?;
        drop(s);
        stop.shutdown();
        Ok(r)
    });
    server.serve_forever().expect("serve_forever as_root xattr");
    let reply = client.join().unwrap().expect("client io");
    // The ambient-root fgetxattr read the seeded value end to end.
    assert_eq!(reply, b"secret");
}

#[cfg(feature = "uring-fs")]
#[path = "support/xattr.rs"]
mod xattr_probe;
#[cfg(feature = "uring-fs")]
use xattr_probe::set_user_xattr;

/// The rest of the embedded op sweep over the ring: `renameat` (the
/// `submit_path_op` two-anchor route), `ftruncate` (the `submit_fd_meta`
/// route), and an `fgetxattr` read - each stamped with the per-connection
/// personality, driven from the body handler and resolved through a
/// `Deferred`. The two version-gated ops (`ftruncate` >= 6.9, fixed-file xattr
/// >= 6.13) run only where the server reports support; `renameat` always does.
#[cfg(feature = "uring-fs")]
#[test]
fn fs_metadata_ops_rename_truncate_xattr() {
    use std::ffi::CString;
    use std::sync::OnceLock;
    use truenas_ros::sync_fs::{OFlag, OpenHow, RenameFlags};
    use truenas_ros::uring_fs::{Anchor, Leaf, Personality};

    let dir = truenas_ros::tempdir().unwrap();
    let orig = dir.path().join("orig.txt");
    std::fs::write(&orig, b"payload-7").unwrap(); // 9 bytes
    let xattr_set = set_user_xattr(&orig, b"user.color", b"blue");

    let pers: Arc<OnceLock<Personality>> = Arc::new(OnceLock::new());
    let anchor = match Anchor::open(dir.path()) {
        Ok(a) => a,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("anchor open: {e}"),
    };

    let pc = Arc::clone(&pers);
    let body = move |mut req: Request<'_, ()>| -> Response {
        let cmd = req.body.take();
        let (deferred, permit) = req.responder.defer();
        let Some(mut fs) = req.fs.take() else {
            return Response::Close;
        };
        let who = *pc.get().expect("personality set before serving");
        let anchor = anchor.clone();
        match cmd.as_slice() {
            b"getxattr" => {
                let path = CString::new("orig.txt").unwrap();
                let how = OpenHow::new().flags(OFlag::O_RDONLY);
                fs.open(who, &anchor, &path, how, move |done, fs| {
                    let Some(file) = done.file() else {
                        deferred.close();
                        return;
                    };
                    let name = CString::new("user.color").unwrap();
                    fs.fgetxattr(
                        who,
                        file.clone(),
                        &name,
                        vec![0u8; 64],
                        move |d, fs| {
                            fs.close(file);
                            match d.result() {
                                Ok(n) => {
                                    let mut v =
                                        d.into_bufs().pop().unwrap_or_default();
                                    v.truncate(n as usize);
                                    deferred.reply(echo_frame(&v));
                                }
                                Err(_) => {
                                    deferred.reply(echo_frame(b"xattr-err"))
                                }
                            }
                        },
                    );
                });
            }
            b"truncate" => {
                let path = CString::new("orig.txt").unwrap();
                let how = OpenHow::new().flags(OFlag::O_WRONLY);
                fs.open(who, &anchor, &path, how, move |done, fs| {
                    let Some(file) = done.file() else {
                        deferred.close();
                        return;
                    };
                    fs.ftruncate(who, file.clone(), 3, move |d, fs| {
                        fs.close(file);
                        match d.result() {
                            Ok(_) => deferred.reply(echo_frame(b"ok")),
                            Err(_) => deferred.reply(echo_frame(b"trunc-err")),
                        }
                    });
                });
            }
            b"rename" => {
                let old = Leaf::new("orig.txt").unwrap();
                let new = Leaf::new("renamed.txt").unwrap();
                fs.renameat(
                    who,
                    &anchor,
                    old,
                    &anchor,
                    new,
                    RenameFlags::empty(),
                    move |d, _fs| match d.result() {
                        Ok(_) => deferred.reply(echo_frame(b"renamed-ok")),
                        Err(_) => deferred.reply(echo_frame(b"renamed-err")),
                    },
                );
            }
            _ => deferred.close(),
        }
        Response::Defer(permit)
    };
    let protocol = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(
            PrefixWidth::U32,
            Endian::Big,
            false,
        ),
        body,
    };
    let cfg = ServerConfig {
        pool_size: 8,
        fs_ops: 16,
        ..ServerConfig::default()
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let mut server = match Server::with_config([addr], cfg, protocol) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind with fs pool: {e}"),
    };
    pers.set(server.register_self().expect("register_self"))
        .unwrap();
    let do_xattr = xattr_set;
    let do_truncate = true;
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();
    // (optional getxattr reply, optional truncate reply, rename reply).
    type MetaReplies = io::Result<(Option<Vec<u8>>, Option<Vec<u8>>, Vec<u8>)>;
    let client = thread::spawn(move || -> MetaReplies {
        let mut s = connect_tcp(v4)?;
        // getxattr and truncate read/modify orig.txt; rename moves it last.
        let xattr = if do_xattr {
            send_framed(&mut s, b"getxattr")?;
            Some(recv_framed(&mut s)?)
        } else {
            None
        };
        let trunc = if do_truncate {
            send_framed(&mut s, b"truncate")?;
            Some(recv_framed(&mut s)?)
        } else {
            None
        };
        send_framed(&mut s, b"rename")?;
        let renamed = recv_framed(&mut s)?;
        drop(s);
        stop.shutdown();
        Ok((xattr, trunc, renamed))
    });
    server.serve_forever().expect("serve_forever metadata");
    let (xattr, trunc, renamed) = client.join().unwrap().expect("client io");

    assert_eq!(renamed, b"renamed-ok");
    assert!(
        dir.path().join("renamed.txt").exists(),
        "rename took effect"
    );
    assert!(!orig.exists(), "orig.txt is gone after rename");
    if let Some(v) = xattr {
        assert_eq!(v, b"blue", "fgetxattr read the value back");
    }
    if let Some(t) = trunc {
        assert_eq!(t, b"ok");
        // ftruncate shrank orig.txt to 3 bytes before it was renamed.
        let len = std::fs::metadata(dir.path().join("renamed.txt"))
            .unwrap()
            .len();
        assert_eq!(len, 3, "ftruncate shrank the file to 3 bytes");
    }
}

/// The connection-close owned-file sweep. A handler opens a file on every
/// request and **never closes it** - a deliberate leak. Across many sequential
/// connections (each opening one file, then dropping), the process would run
/// out of descriptors if the files were not reclaimed; the sweep closes each
/// connection's still-open files as it closes, so every open succeeds. (Mirrors `tcp_sequential_slot_reuse`: a small pool with
/// slack absorbs the asynchronous close, so one-at-a-time connections never
/// outrun the sweep.)
#[cfg(feature = "uring-fs")]
#[test]
fn fs_owned_files_swept_on_connection_close() {
    use std::ffi::CString;
    use std::sync::OnceLock;
    use truenas_ros::sync_fs::{OFlag, OpenHow};
    use truenas_ros::uring_fs::{Anchor, Personality};

    const N: usize = 16;
    let dir = truenas_ros::tempdir().unwrap();
    std::fs::write(dir.path().join("f.txt"), b"data").unwrap();

    let pers: Arc<OnceLock<Personality>> = Arc::new(OnceLock::new());
    let anchor = match Anchor::open(dir.path()) {
        Ok(a) => a,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("anchor open: {e}"),
    };

    let pc = Arc::clone(&pers);
    let body = move |mut req: Request<'_, ()>| -> Response {
        let _ = req.body.take();
        let (deferred, permit) = req.responder.defer();
        let Some(mut fs) = req.fs.take() else {
            return Response::Close;
        };
        let who = *pc.get().expect("personality set before serving");
        let anchor = anchor.clone();
        let path = CString::new("f.txt").unwrap();
        let how = OpenHow::new().flags(OFlag::O_RDONLY);
        fs.open(who, &anchor, &path, how, move |done, _fs| {
            // Deliberately DO NOT close the file: the connection-close sweep is
            // the only thing that can reclaim its pool slot.
            if done.file().is_some() {
                deferred.reply(echo_frame(b"opened"));
            } else {
                deferred.reply(echo_frame(b"open-err")); // pool exhausted / open failed
            }
        });
        Response::Defer(permit)
    };
    let protocol = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(
            PrefixWidth::U32,
            Endian::Big,
            false,
        ),
        body,
    };
    let cfg = ServerConfig {
        pool_size: 8,
        fs_ops: 8, // far fewer than N: reuse across closes is mandatory
        ..ServerConfig::default()
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let mut server = match Server::with_config([addr], cfg, protocol) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind with fs pool: {e}"),
    };
    pers.set(server.register_self().expect("register_self"))
        .unwrap();
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();
    let client = thread::spawn(move || -> io::Result<Vec<Vec<u8>>> {
        // Sequential connections, each opening one (never-closed) file, then
        // closing - the sweep must reclaim its slot before the pool exhausts.
        let mut replies = Vec::with_capacity(N);
        for _ in 0..N {
            let mut s = connect_tcp(v4)?;
            send_framed(&mut s, b"open")?;
            replies.push(recv_framed(&mut s)?);
            drop(s); // close -> triggers the owned-file sweep
        }
        stop.shutdown();
        Ok(replies)
    });
    server.serve_forever().expect("serve_forever sweep");
    let replies = client.join().unwrap().expect("client io");
    assert_eq!(replies.len(), N);
    for (i, r) in replies.iter().enumerate() {
        assert_eq!(
            r, b"opened",
            "connection {i} opened a file - the sweep must have freed the \
             earlier connections' descriptors (else the process runs out)"
        );
    }
}

/// A continuation may open, and doing so reclaims its slot like any
/// other op.
///
/// This used to assert the opposite - that the facade refused - on the
/// grounds that a file minted after `close_conn` had already swept the
/// connection would hold its slot until server teardown. It does not.
/// `close_owned_by` is gone; `cancel_owned_by` cancels in-flight *ops*
/// so their parked fds are released, and the fds themselves close by
/// `Arc`-drop whether or not anyone takes them. An `openat2` completes,
/// so its entry is reaped either way.
///
/// The pool is deliberately smaller than the connection count, and each
/// connection leaves its *first* file open while chaining a second from
/// the completion. If a chained open leaked a slot, the later
/// connections would find none and answer `open-err` - which is what
/// makes this a measurement rather than a restatement.
#[cfg(feature = "uring-fs")]
#[test]
fn fs_continuation_may_open_and_its_slot_comes_back() {
    use std::ffi::CString;
    use std::sync::OnceLock;
    use truenas_ros::sync_fs::{OFlag, OpenHow};
    use truenas_ros::uring_fs::{Anchor, Personality};

    const N: usize = 6;
    let dir = truenas_ros::tempdir().unwrap();
    std::fs::write(dir.path().join("a.txt"), b"first").unwrap();
    std::fs::write(dir.path().join("b.txt"), b"second").unwrap();

    let pers: Arc<OnceLock<Personality>> = Arc::new(OnceLock::new());
    let anchor = match Anchor::open(dir.path()) {
        Ok(a) => a,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("anchor open: {e}"),
    };

    let pc = Arc::clone(&pers);
    let body = move |mut req: Request<'_, ()>| -> Response {
        let _ = req.body.take();
        let (deferred, permit) = req.responder.defer();
        let Some(mut fs) = req.fs.take() else {
            return Response::Close;
        };
        let who = *pc.get().expect("personality set before serving");
        let (a1, a2) = (anchor.clone(), anchor.clone());
        let first = CString::new("a.txt").unwrap();
        let second = CString::new("b.txt").unwrap();
        let how = OpenHow::new().flags(OFlag::O_RDONLY);
        fs.open(who, &a1, &first, how, move |done, fs| {
            if done.file().is_none() {
                deferred.reply(echo_frame(b"open-err"));
                return;
            }
            // The first file stays open on purpose: this connection is
            // holding a slot while it asks for another.
            fs.open(who, &a2, &second, how, move |d, _fs| match d.file() {
                Some(_) => deferred.reply(echo_frame(b"chained")),
                None => deferred.reply(echo_frame(b"open-err")),
            });
        });
        Response::Defer(permit)
    };
    let protocol = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(
            PrefixWidth::U32,
            Endian::Big,
            false,
        ),
        body,
    };
    let cfg = ServerConfig {
        pool_size: 8,
        fs_ops: 4, // < N: the sweep must recycle between connections
        ..ServerConfig::default()
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let mut server = match Server::with_config([addr], cfg, protocol) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind with fs pool: {e}"),
    };
    pers.set(server.register_self().expect("register_self"))
        .unwrap();
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();
    let client = thread::spawn(move || -> Vec<io::Result<Vec<u8>>> {
        let mut out = Vec::with_capacity(N);
        for _ in 0..N {
            let mut s = connect_tcp(v4).expect("connect");
            send_framed(&mut s, b"go").expect("send");
            out.push(recv_framed(&mut s));
        }
        stop.shutdown();
        out
    });
    server.serve_forever().expect("serve_forever");
    let replies = client.join().unwrap();
    assert_eq!(replies.len(), N);
    for (i, r) in replies.iter().enumerate() {
        let b = r.as_ref().unwrap_or_else(|e| {
            panic!("connection {i}: the chained open must answer, got {e:?}")
        });
        assert_eq!(
            b, b"chained",
            "connection {i}: every connection past the pool must still find \
             a slot, so nothing the chain opened was left holding one"
        );
    }
}

#[cfg(feature = "uring-fs")]
#[path = "support/privilege.rs"]
mod privilege;
#[cfg(feature = "uring-fs")]
use privilege::{is_root, root_or_skip};

/// The end-to-end proof that a server acts as *authenticated peers*: the
/// personality genuinely gates namespace access, it is not a stamp. The
/// credential broker (spawned on the **server's** ring) registers an
/// unprivileged uid; the handler then opens a root-owned `0600` file two ways --
/// under the daemon's own personality it opens and reads back, under the peer's
/// it is refused (`EACCES`, so `done.file()` is `None`). Pure `open` + `pread`,
/// so it runs live wherever io_uring + root are available (no xattr / 6.13
/// gate). The divergence is at **open** by design: DAC is checked there, not on
/// each read of an already-open fd.
///
/// Root-only (the broker needs `CAP_SETUID` to become the peer); skipped
/// otherwise.
#[cfg(feature = "uring-fs")]
#[test]
fn fs_broker_personality_gates_open() {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::sync::OnceLock;
    use truenas_ros::sync_fs::{OFlag, OpenHow};
    use truenas_ros::uring_fs::{
        Anchor, AsUser, CredBroker, Personality, RwFlags,
    };

    if !root_or_skip("fs_broker_personality_gates_open") {
        return; // the broker cannot become another uid without CAP_SETUID
    }
    // A uid/gid that owns nothing here - its personality has only what "other"
    // grants, and "other" is nothing on a 0600 file.
    const NOBODY_UID: u32 = 65_534;
    const NOBODY_GID: u32 = 65_534;

    let dir = truenas_ros::tempdir().unwrap();
    // A root-owned, owner-only file: openable by the daemon, not by the peer.
    let secret = dir.path().join("secret.txt");
    std::fs::write(&secret, b"topsecret").unwrap();
    let cpath = CString::new(secret.as_os_str().as_bytes()).unwrap();
    // SAFETY: valid path; chmod cannot corrupt memory.
    assert_eq!(unsafe { libc::chmod(cpath.as_ptr(), 0o600) }, 0);

    // (root-daemon personality, unprivileged-peer personality), minted after
    // construction and read by the handler.
    let cell: Arc<OnceLock<(Personality, Personality)>> =
        Arc::new(OnceLock::new());
    let anchor = match Anchor::open(dir.path()) {
        Ok(a) => a,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("anchor open: {e}"),
    };

    let pc = Arc::clone(&cell);
    let body = move |mut req: Request<'_, ()>| -> Response {
        let cmd = req.body.take();
        let (deferred, permit) = req.responder.defer();
        let Some(mut fs) = req.fs.take() else {
            return Response::Close;
        };
        let (root_pers, peer_pers) =
            *pc.get().expect("personalities set before serving");
        let anchor = anchor.clone();
        let ro = OpenHow::new().flags(OFlag::O_RDONLY);
        // Open the 0600 file as the daemon (`as-root`) or the peer, then, if it
        // opened, read it back - proving the daemon both opens AND reads while
        // the peer is refused at open.
        let who = if cmd == b"as-root" {
            root_pers
        } else {
            peer_pers
        };
        let path = CString::new("secret.txt").unwrap();
        fs.open(who, &anchor, &path, ro, move |done, fs| {
            let Some(file) = done.file() else {
                // EACCES - the personality gated the open.
                deferred.reply(echo_frame(b"denied"));
                return;
            };
            fs.preadv2(
                who,
                file.clone(),
                vec![vec![0u8; 64]],
                0,
                RwFlags::empty(),
                move |d, fs| {
                    fs.close(file);
                    match d.result() {
                        Ok(n) => {
                            let mut out = b"read:".to_vec();
                            let mut v = d.into_bufs().pop().unwrap_or_default();
                            v.truncate(n as usize);
                            out.extend_from_slice(&v);
                            deferred.reply(echo_frame(&out));
                        }
                        Err(_) => deferred.reply(echo_frame(b"read-err")),
                    }
                },
            );
        });
        Response::Defer(permit)
    };
    let protocol = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(
            PrefixWidth::U32,
            Endian::Big,
            false,
        ),
        body,
    };
    let cfg = ServerConfig {
        pool_size: 8,
        fs_ops: 16,
        ..ServerConfig::default()
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    // The ring must exist before the broker forks (it inherits the fd), and the
    // broker must fork before any threads - so build, register, spawn, all
    // before the client thread below.
    let mut server = match Server::with_config([addr], cfg, protocol) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind with fs pool: {e}"),
    };
    let root_pers = server.register_self().expect("register_self");
    let broker = match CredBroker::spawn(&[&server]) {
        Ok(b) => b,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("CredBroker::spawn: {e}"),
    };
    let creds = broker.handle(0).expect("broker handle");
    let peer_pers = creds
        .register(&AsUser::new(NOBODY_UID, NOBODY_GID))
        .expect("register peer");
    cell.set((root_pers, peer_pers)).unwrap();

    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();
    let client = thread::spawn(move || -> io::Result<(Vec<u8>, Vec<u8>)> {
        let mut s = connect_tcp(v4)?;
        send_framed(&mut s, b"as-peer")?;
        let peer = recv_framed(&mut s)?;
        send_framed(&mut s, b"as-root")?;
        let root = recv_framed(&mut s)?;
        drop(s);
        stop.shutdown();
        Ok((peer, root))
    });
    server.serve_forever().expect("serve_forever broker");
    let (peer, root) = client.join().unwrap().expect("client io");

    assert_eq!(
        root, b"read:topsecret",
        "the daemon's own identity opens and reads its 0600 file"
    );
    assert_eq!(
        peer, b"denied",
        "the unprivileged peer is refused at open - the personality gates DAC"
    );
}

/// `open_chain`'s whole point: a directory the caller could never
/// traverse, opened as the daemon, with the file inside it still gated
/// on the caller.
///
/// This is the property the split credential exists for. A `0700`
/// daemon-owned tree grants nothing, so opening something under it as
/// the daemon proves nothing about the caller — the last step has to
/// name the caller for the kernel to decide their access to the file
/// they actually asked for.
///
/// Three chains over the same tree say it three ways: the daemon
/// reaches the file; the peer is refused at the file even though the
/// directory above it opened; and the peer is refused at the directory
/// when it is the one traversing. The second is the one that matters —
/// a chain that leaked the daemon's credential into the last step would
/// hand the peer a file it may not read.
///
/// Root-only (the broker needs `CAP_SETUID` to become the peer);
/// skipped otherwise.
#[cfg(feature = "uring-fs")]
#[test]
fn fs_open_chain_gates_the_last_step_on_its_own_personality() {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::sync::OnceLock;
    use truenas_ros::sync_fs::{OFlag, OpenHow};
    use truenas_ros::uring_fs::{
        Anchor, AsUser, CredBroker, OpenStep, Personality, StepPath,
    };

    if !root_or_skip("fs_open_chain_gates_the_last_step") {
        return; // the broker cannot become another uid without CAP_SETUID
    }
    const NOBODY_UID: u32 = 65_534;
    const NOBODY_GID: u32 = 65_534;

    let dir = truenas_ros::tempdir().unwrap();
    // `private/` is the daemon-owned tree: 0700, so the peer cannot even
    // traverse it. `obj` inside it is 0600, so the peer cannot read it
    // either — two separate refusals, one per step.
    let private = dir.path().join("private");
    std::fs::create_dir(&private).unwrap();
    let obj = private.join("obj");
    std::fs::write(&obj, b"topsecret").unwrap();
    for (path, mode) in [(&private, 0o700), (&obj, 0o600)] {
        let c = CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: valid path; chmod cannot corrupt memory.
        assert_eq!(unsafe { libc::chmod(c.as_ptr(), mode) }, 0);
    }

    let cell: Arc<OnceLock<(Personality, Personality)>> =
        Arc::new(OnceLock::new());
    let anchor = match Anchor::open(dir.path()) {
        Ok(a) => a,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("anchor open: {e}"),
    };

    let pc = Arc::clone(&cell);
    let body = move |mut req: Request<'_, ()>| -> Response {
        let cmd = req.body.take();
        let (deferred, permit) = req.responder.defer();
        let Some(mut fs) = req.fs.take() else {
            return Response::Close;
        };
        let (root_pers, peer_pers) =
            *pc.get().expect("personalities set before serving");
        let anchor = anchor.clone();
        // Who walks the directory, and who opens the file under it.
        let (dir_who, leaf_who) = match cmd.as_slice() {
            b"root-root" => (root_pers, root_pers),
            b"root-peer" => (root_pers, peer_pers),
            _ => (peer_pers, peer_pers),
        };
        fs.open_chain(
            &anchor,
            vec![
                OpenStep {
                    path: StepPath::Fixed(c"private".to_owned()),
                    who: dir_who,
                    how: OpenHow::new()
                        .flags(OFlag::O_PATH | OFlag::O_DIRECTORY),
                },
                OpenStep {
                    path: StepPath::Fixed(c"obj".to_owned()),
                    who: leaf_who,
                    how: OpenHow::new().flags(OFlag::O_RDONLY),
                },
            ],
            move |done, fs| match done.file() {
                Some(file) => {
                    fs.close(file);
                    deferred.reply(echo_frame(b"opened"));
                }
                None => deferred.reply(echo_frame(b"denied")),
            },
        );
        Response::Defer(permit)
    };
    let protocol = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(
            PrefixWidth::U32,
            Endian::Big,
            false,
        ),
        body,
    };
    let cfg = ServerConfig {
        pool_size: 8,
        fs_ops: 16,
        ..ServerConfig::default()
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let mut server = match Server::with_config([addr], cfg, protocol) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind with fs pool: {e}"),
    };
    let root_pers = server.register_self().expect("register_self");
    let broker = match CredBroker::spawn(&[&server]) {
        Ok(b) => b,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("CredBroker::spawn: {e}"),
    };
    let creds = broker.handle(0).expect("broker handle");
    let peer_pers = creds
        .register(&AsUser::new(NOBODY_UID, NOBODY_GID))
        .expect("register peer");
    cell.set((root_pers, peer_pers)).unwrap();

    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();
    let client = thread::spawn(move || -> io::Result<Vec<Vec<u8>>> {
        let mut s = connect_tcp(v4)?;
        let mut out = Vec::new();
        for cmd in [b"root-root".as_slice(), b"root-peer", b"peer-peer"] {
            send_framed(&mut s, cmd)?;
            out.push(recv_framed(&mut s)?);
        }
        drop(s);
        stop.shutdown();
        Ok(out)
    });
    server.serve_forever().expect("serve_forever broker");
    let got = client.join().unwrap().expect("client io");

    assert_eq!(
        got[0], b"opened",
        "the daemon's own identity walks its 0700 tree and opens the file"
    );
    assert_eq!(
        got[1], b"denied",
        "the peer is refused at the file even though the daemon opened \
         the directory above it - the last step's personality is what \
         decides, and a chain that leaked the daemon's would hand over a \
         file the peer may not read"
    );
    assert_eq!(
        got[2], b"denied",
        "the peer cannot traverse the 0700 directory either"
    );
}

/// The multi-reactor shape: rings created on the main thread before the
/// broker forks, servers built on worker threads after it, and the peer's
/// personality minted on each ring before the thread that owns it has even
/// mapped it. The broker's personalities then gate opens on every ring
/// exactly as they do on a server that built its own ring, which is the
/// proof that `setup_ring` + `with_ring` is the same server, constructed in
/// two halves on two threads.
///
/// A ring created **before** the thread that will serve on it, mapped and
/// driven by that thread, serves real requests.
///
/// This is the unprivileged half of the multi-reactor recipe: `setup_ring`
/// builds each ring on this thread with no other thread alive, then each
/// worker takes one and calls `Server::with_ring`, which does the mapping on
/// the thread that will drive it. Nothing here needs a credential broker, so
/// it runs on `ci.yml`'s unprivileged runner - the job that gates merges,
/// where `fs_broker_serves_rings_mapped_on_worker_threads` can only skip.
///
/// Two rings, so the per-ring construction is exercised more than once and
/// the servers are proven independent rather than aliased.
#[test]
fn rings_created_before_the_threads_that_serve_them() {
    use std::sync::mpsc;

    const RINGS: usize = 2;
    let cfg = ServerConfig {
        pool_size: 4,
        ..ServerConfig::default()
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());

    // Every ring first, on this thread, with no other thread alive yet.
    let mut rings = Vec::new();
    for _ in 0..RINGS {
        match setup_ring([addr.clone()], &cfg) {
            Ok(r) => rings.push(r),
            Err(e) if should_skip(&e) => return,
            Err(e) => panic!("setup_ring: {e}"),
        }
    }

    let (tx, rx) = mpsc::channel::<(usize, SocketAddrV4, ShutdownHandle)>();
    let mut workers = Vec::new();
    for (i, ring) in rings.into_iter().enumerate() {
        let (addr, tx) = (addr.clone(), tx.clone());
        workers.push(thread::spawn(move || {
            // Answer with this ring's index, so a reply proves which server
            // served it and two rings cannot be one.
            let body = move |mut req: Request<'_, ()>| -> Response {
                let got = req.body.take();
                let mut out = got;
                out.extend_from_slice(format!("@{i}").as_bytes());
                Response::Reply(echo_frame(&out))
            };
            let protocol = Protocol {
                accept: |_: Incoming<'_>| Some(()),
                header: length_prefix_header::<()>(
                    PrefixWidth::U32,
                    Endian::Big,
                    false,
                ),
                body,
            };
            let mut server = Server::with_ring([addr], cfg, protocol, ring)
                .expect("with_ring on a ring created by another thread");
            let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
                panic!("expected Tcp");
            };
            tx.send((i, v4, server.shutdown_handle())).unwrap();
            server.serve_forever().expect("serve_forever");
        }));
    }
    drop(tx);

    let mut served = 0usize;
    for (i, v4, stop) in rx.iter() {
        let mut s = connect_tcp(v4).expect("connect");
        send_framed(&mut s, b"ping").expect("send");
        let got = recv_framed(&mut s).expect("recv");
        drop(s);
        stop.shutdown();
        assert_eq!(
            got,
            format!("ping@{i}").into_bytes(),
            "ring {i} served its own request on the thread that mapped it"
        );
        served += 1;
    }
    assert_eq!(served, RINGS, "every ring served");
    for w in workers {
        w.join().expect("worker");
    }
}

/// Root-only, because the **broker** half needs `CAP_SETUID` to become
/// another uid. The skip is loud: `TRUENAS_ROS_REQUIRE_CRED_BROKER=1` (armed
/// in the QEMU job, which runs as root) turns a mis-provisioned runner red
/// instead of green. The unprivileged half of the same feature - a ring
/// created on one thread and mapped, built and driven on another - is covered
/// without privilege by `rings_created_before_the_threads_that_serve_them`.
#[cfg(feature = "uring-fs")]
#[test]
fn fs_broker_serves_rings_mapped_on_worker_threads() {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::sync::OnceLock;
    use std::sync::mpsc;
    use truenas_ros::sync_fs::{OFlag, OpenHow};
    use truenas_ros::uring_fs::{
        Anchor, AsUser, CredBroker, Personality, RwFlags,
    };

    if !is_root() {
        assert!(
            std::env::var_os("TRUENAS_ROS_REQUIRE_CRED_BROKER").is_none(),
            "TRUENAS_ROS_REQUIRE_CRED_BROKER is set but this process is not \
             root: the broker cannot become another uid without CAP_SETUID"
        );
        return;
    }
    const NOBODY_UID: u32 = 65_534;
    const NOBODY_GID: u32 = 65_534;
    const RINGS: u8 = 2;

    let dir = truenas_ros::tempdir().unwrap();
    let secret = dir.path().join("secret.txt");
    std::fs::write(&secret, b"topsecret").unwrap();
    let cpath = CString::new(secret.as_os_str().as_bytes()).unwrap();
    // SAFETY: valid path; chmod cannot corrupt memory.
    assert_eq!(unsafe { libc::chmod(cpath.as_ptr(), 0o600) }, 0);
    let anchor = match Anchor::open(dir.path()) {
        Ok(a) => a,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("anchor open: {e}"),
    };

    let cfg = ServerConfig {
        pool_size: 8,
        fs_ops: 16,
        ..ServerConfig::default()
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());

    // Every ring first, on this thread, with no other thread alive yet; then
    // the broker over all of them.
    let mut rings = Vec::new();
    for _ in 0..RINGS {
        match setup_ring([addr.clone()], &cfg) {
            Ok(r) => rings.push(r),
            Err(e) if should_skip(&e) => return,
            Err(e) => panic!("setup_ring: {e}"),
        }
    }
    let broker = match CredBroker::spawn(&rings.iter().collect::<Vec<_>>()) {
        Ok(b) => b,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("CredBroker::spawn: {e}"),
    };

    // Each worker mints the peer on its still-unmapped ring, maps it, builds
    // the server around it, and reports its address and stop handle before
    // serving.
    let (tx, rx) = mpsc::channel::<(usize, SocketAddrV4, ShutdownHandle)>();
    let mut workers = Vec::new();
    for (i, ring) in rings.into_iter().enumerate() {
        let creds = broker.handle(i as u8).expect("broker handle");
        let anchor = anchor.clone();
        let addr = addr.clone();
        let tx = tx.clone();
        workers.push(thread::spawn(move || {
            let cell: Arc<OnceLock<(Personality, Personality)>> =
                Arc::new(OnceLock::new());
            let pc = Arc::clone(&cell);
            let body = move |mut req: Request<'_, ()>| -> Response {
                let cmd = req.body.take();
                let (deferred, permit) = req.responder.defer();
                let Some(mut fs) = req.fs.take() else {
                    return Response::Close;
                };
                let (root_pers, peer_pers) =
                    *pc.get().expect("personalities set before serving");
                let anchor = anchor.clone();
                let ro = OpenHow::new().flags(OFlag::O_RDONLY);
                let who = if cmd == b"as-root" {
                    root_pers
                } else {
                    peer_pers
                };
                let path = CString::new("secret.txt").unwrap();
                fs.open(who, &anchor, &path, ro, move |done, fs| {
                    let Some(file) = done.file() else {
                        deferred.reply(echo_frame(b"denied"));
                        return;
                    };
                    fs.preadv2(
                        who,
                        file.clone(),
                        vec![vec![0u8; 64]],
                        0,
                        RwFlags::empty(),
                        move |d, fs| {
                            fs.close(file);
                            match d.result() {
                                Ok(n) => {
                                    let mut out = b"read:".to_vec();
                                    let mut v =
                                        d.into_bufs().pop().unwrap_or_default();
                                    v.truncate(n as usize);
                                    out.extend_from_slice(&v);
                                    deferred.reply(echo_frame(&out));
                                }
                                Err(_) => {
                                    deferred.reply(echo_frame(b"read-err"))
                                }
                            }
                        },
                    );
                });
                Response::Defer(permit)
            };
            let protocol = Protocol {
                accept: |_: Incoming<'_>| Some(()),
                header: length_prefix_header::<()>(
                    PrefixWidth::U32,
                    Endian::Big,
                    false,
                ),
                body,
            };
            // The broker needs only the fd: the peer is minted on this ring
            // before this thread maps it.
            let peer_pers = creds
                .register(&AsUser::new(NOBODY_UID, NOBODY_GID))
                .expect("register peer on a ring not yet mapped");
            let mut server = Server::with_ring([addr], cfg, protocol, ring)
                .expect("with_ring on a ring created by another thread");
            let root_pers = server.register_self().expect("register_self");
            cell.set((root_pers, peer_pers)).unwrap();
            let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
                panic!("expected Tcp");
            };
            tx.send((i, v4, server.shutdown_handle())).unwrap();
            server.serve_forever().expect("serve_forever");
        }));
    }
    drop(tx);

    // Drive each ring in turn: both identities, both verdicts, then stop it.
    let mut served = 0u8;
    for (i, v4, stop) in rx.iter() {
        let mut s = connect_tcp(v4).expect("connect");
        send_framed(&mut s, b"as-peer").expect("send");
        let peer = recv_framed(&mut s).expect("recv");
        send_framed(&mut s, b"as-root").expect("send");
        let root = recv_framed(&mut s).expect("recv");
        drop(s);
        stop.shutdown();
        assert_eq!(
            root, b"read:topsecret",
            "ring {i}: the daemon's own identity reads its 0600 file"
        );
        assert_eq!(
            peer, b"denied",
            "ring {i}: the peer is refused at open by a personality minted \
             before the ring was mapped"
        );
        served += 1;
    }
    assert_eq!(served, RINGS, "every worker served");
    for w in workers {
        w.join().expect("worker");
    }
}

/// Real privilege boundary for `fgetxattr_as_root`: a `trusted.*` attribute is
/// invisible to an unprivileged reader (the kernel hides it without
/// `CAP_SYS_ADMIN`, returning `ENODATA`), while the ambient-root path
/// (`personality = 0`) holds the capability and returns the value. The peer
/// opens a world-readable file, then reads the attribute both ways.
///
/// Root-only (the broker needs `CAP_SETUID`); skipped otherwise, and skipped if
/// the fs refuses `trusted.*` or the kernel lacks fd-xattr (< 6.13).
#[cfg(feature = "uring-fs")]
#[test]
fn fs_as_root_reads_trusted_xattr_across_privilege() {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::OnceLock;
    use truenas_ros::sync_fs::{OFlag, OpenHow};
    use truenas_ros::uring_fs::{Anchor, AsUser, CredBroker, Personality};

    if !root_or_skip("fs_as_root_reads_trusted_xattr_across_privilege") {
        return;
    }
    const NOBODY_UID: u32 = 65_534;
    const NOBODY_GID: u32 = 65_534;

    let dir = truenas_ros::tempdir().unwrap();
    // `tempdir` creates the scratch directory 0700; the unprivileged peer
    // must traverse it to reach the file, and DAC on the path is not the
    // boundary under test.
    std::fs::set_permissions(
        dir.path(),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    let f = dir.path().join("t.txt");
    std::fs::write(&f, b"body").unwrap();
    let cpath = CString::new(f.as_os_str().as_bytes()).unwrap();
    // World-readable so the unprivileged peer can OPEN it - the boundary under
    // test is the xattr `CAP_SYS_ADMIN` check, not DAC on open.
    // SAFETY: valid path; chmod cannot corrupt memory.
    assert_eq!(unsafe { libc::chmod(cpath.as_ptr(), 0o644) }, 0);
    // Seed a `trusted.*` attribute (root/CAP_SYS_ADMIN only); skip if the fs
    // refuses it.
    let tname = CString::new("trusted.tr_test").unwrap();
    // SAFETY: valid path/name and a 3-byte value.
    let seeded = unsafe {
        libc::setxattr(
            cpath.as_ptr(),
            tname.as_ptr(),
            b"cap".as_ptr().cast(),
            3,
            0,
        )
    };
    if seeded != 0 {
        return; // filesystem refuses trusted.* here
    }

    let cell: Arc<OnceLock<Personality>> = Arc::new(OnceLock::new());
    let anchor = match Anchor::open(dir.path()) {
        Ok(a) => a,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("anchor open: {e}"),
    };

    let pc = Arc::clone(&cell);
    let body = move |mut req: Request<'_, ()>| -> Response {
        let _ = req.body.take();
        let (deferred, permit) = req.responder.defer();
        let Some(mut fs) = req.fs.take() else {
            return Response::Close;
        };
        let peer = *pc.get().expect("peer personality set before serving");
        let anchor = anchor.clone();
        let ro = OpenHow::new().flags(OFlag::O_RDONLY);
        let path = CString::new("t.txt").unwrap();
        fs.open(peer, &anchor, &path, ro, move |done, fs| {
            let Some(file) = done.file() else {
                deferred.reply(echo_frame(b"open-denied"));
                return;
            };
            let name = CString::new("trusted.tr_test").unwrap();
            // (1) As the unprivileged peer: trusted.* is hidden -> ENODATA.
            fs.fgetxattr(
                peer,
                file.clone(),
                &name,
                vec![0u8; 32],
                move |d1, fs| {
                    let peer_failed = d1.result().is_err();
                    let name2 = CString::new("trusted.tr_test").unwrap();
                    // (2) As ambient root: CAP_SYS_ADMIN -> the value.
                    fs.fgetxattr_as_root(
                        file,
                        &name2,
                        vec![0u8; 32],
                        move |d2, _fs| {
                            let mut out = Vec::new();
                            out.push(if peer_failed { b'1' } else { b'0' });
                            out.push(b':');
                            match d2.result() {
                                Ok(n) => {
                                    let mut v = d2
                                        .into_bufs()
                                        .pop()
                                        .unwrap_or_default();
                                    v.truncate(n as usize);
                                    out.extend_from_slice(&v);
                                }
                                Err(_) => out.extend_from_slice(b"root-err"),
                            }
                            deferred.reply(echo_frame(&out));
                        },
                    );
                },
            );
        });
        Response::Defer(permit)
    };
    let protocol = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(
            PrefixWidth::U32,
            Endian::Big,
            false,
        ),
        body,
    };
    let cfg = ServerConfig {
        pool_size: 8,
        fs_ops: 16,
        ..ServerConfig::default()
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let mut server = match Server::with_config([addr], cfg, protocol) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind with fs pool: {e}"),
    };
    let _root = server.register_self().expect("register_self");
    let broker = match CredBroker::spawn(&[&server]) {
        Ok(b) => b,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("CredBroker::spawn: {e}"),
    };
    let creds = broker.handle(0).expect("broker handle");
    let peer = creds
        .register(&AsUser::new(NOBODY_UID, NOBODY_GID))
        .expect("register peer");
    cell.set(peer).unwrap();

    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();
    let client = thread::spawn(move || -> io::Result<Vec<u8>> {
        let mut s = connect_tcp(v4)?;
        send_framed(&mut s, b"go")?;
        let r = recv_framed(&mut s)?;
        drop(s);
        stop.shutdown();
        Ok(r)
    });
    server.serve_forever().expect("serve_forever trusted-xattr");
    let reply = client.join().unwrap().expect("client io");
    // "1" = the peer's read failed (trusted.* hidden without CAP_SYS_ADMIN);
    // ":cap" = the ambient-root read returned the value.
    assert_eq!(
        reply, b"1:cap",
        "as-root read the trusted.* the unprivileged peer cannot see"
    );
}

/// An fd opened for a connection torn down **mid-chain** is reclaimed when the
/// connection closes. A handler opens a FIFO and submits a read that blocks
/// forever (no writer sends data), then the peer disconnects before the read
/// completes. Plain-fd files close by `Arc`-drop, but an in-flight op parks the
/// fd until its CQE - so the connection-teardown sweep (`cancel_owned_by`)
/// cancels the op; it completes `ECANCELED`, the parked `Arc` drops, and the fd
/// closes without waiting for whole-server teardown. Validates the Arc-model
/// replacement for the old `close_owned_by`.
#[cfg(feature = "uring-fs")]
#[test]
fn fs_fd_reclaimed_on_connection_close_midchain() {
    use std::ffi::CString;
    use std::os::fd::RawFd;
    use std::os::unix::ffi::OsStrExt;
    use std::sync::OnceLock;
    use std::time::Duration;
    use truenas_ros::sync_fs::{OFlag, OpenHow};
    use truenas_ros::uring_fs::{Anchor, Personality, RwFlags};

    let dir = truenas_ros::tempdir().unwrap();
    let fifo = dir.path().join("f.fifo");
    let cfifo = CString::new(fifo.as_os_str().as_bytes()).unwrap();
    // SAFETY: valid NUL-terminated path.
    if unsafe { libc::mkfifo(cfifo.as_ptr(), 0o600) } != 0 {
        return;
    }
    // Hold the FIFO open O_RDWR so the handler's O_RDONLY open succeeds without
    // blocking and its reads block (no data is ever written).
    // SAFETY: valid path; O_RDWR|O_NONBLOCK on a FIFO does not block.
    let keep =
        unsafe { libc::open(cfifo.as_ptr(), libc::O_RDWR | libc::O_NONBLOCK) };
    assert!(keep >= 0, "open fifo O_RDWR");

    let opened: Arc<OnceLock<RawFd>> = Arc::new(OnceLock::new());
    let pers: Arc<OnceLock<Personality>> = Arc::new(OnceLock::new());
    let anchor = match Anchor::open(dir.path()) {
        Ok(a) => a,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("anchor open: {e}"),
    };

    let oc = Arc::clone(&opened);
    let pc = Arc::clone(&pers);
    let body = move |mut req: Request<'_, ()>| -> Response {
        let _ = req.body.take();
        let (deferred, permit) = req.responder.defer();
        let Some(mut fs) = req.fs.take() else {
            return Response::Close;
        };
        let who = *pc.get().expect("personality set before serving");
        let anchor = anchor.clone();
        let oc = Arc::clone(&oc);
        let path = CString::new("f.fifo").unwrap();
        let how = OpenHow::new().flags(OFlag::O_RDONLY);
        fs.open(who, &anchor, &path, how, move |done, fs| {
            let Some(file) = done.file() else {
                deferred.close();
                return;
            };
            let _ = oc.set(file.as_raw_fd());
            // Reply now, then submit a read that never completes (FIFO, no
            // data): it parks the file's `Arc` in the op entry. The peer will
            // disconnect with this read still in flight.
            deferred.reply(echo_frame(b"opened"));
            fs.preadv2(
                who,
                file.clone(),
                vec![vec![0u8; 16]],
                0,
                RwFlags::empty(),
                move |_d, fs| {
                    fs.close(file); // never reached - the read blocks forever
                },
            );
        });
        Response::Defer(permit)
    };
    let protocol = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(
            PrefixWidth::U32,
            Endian::Big,
            false,
        ),
        body,
    };
    let cfg = ServerConfig {
        pool_size: 8,
        fs_ops: 8,
        ..ServerConfig::default()
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let mut server = match Server::with_config([addr], cfg, protocol) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind with fs pool: {e}"),
    };
    pers.set(server.register_self().expect("register_self"))
        .unwrap();
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();
    let oc2 = Arc::clone(&opened);
    let client = thread::spawn(move || -> io::Result<bool> {
        let mut s = connect_tcp(v4)?;
        send_framed(&mut s, b"go")?;
        let _ = recv_framed(&mut s)?; // "opened": fd recorded, read in flight
        drop(s); // disconnect mid-chain, read still in flight
        let fd = *oc2.get().expect("handler recorded the fd");
        let link = format!("/proc/self/fd/{fd}");
        // Poll for reclamation: the fd is reclaimed iff /proc/self/fd/N stops
        // resolving to the FIFO (closed, or reused for a different file).
        let mut leaked = true;
        for _ in 0..80 {
            thread::sleep(Duration::from_millis(10));
            match std::fs::read_link(&link) {
                Ok(t) if t == fifo => {}
                _ => {
                    leaked = false;
                    break;
                }
            }
        }
        stop.shutdown();
        Ok(leaked)
    });
    server.serve_forever().expect("serve_forever fd-leak");
    let leaked = client.join().unwrap().expect("client io");
    // SAFETY: closing our own kept fd.
    unsafe { libc::close(keep) };
    assert!(
        !leaked,
        "the fd opened for a connection torn down mid-chain was not reclaimed \
         after the connection closed (leaked until server teardown)"
    );
}

/// `FsConn::mkdir_path` builds a missing tree on-loop and hands back the
/// deepest directory as a real descriptor.
///
/// Two requests, because the two paths through it differ: the first walks
/// a tree that does not exist, the second takes the fast path over the
/// tree the first made. The reply is the `fsync` of the returned handle,
/// which an `O_PATH` directory would answer `EBADF`.
#[cfg(feature = "uring-fs")]
#[test]
fn fs_conn_mkdir_path_builds_a_tree_and_answers_a_real_directory() {
    use std::sync::OnceLock;
    use std::time::Duration;
    use truenas_ros::sync_fs::{Mode, OFlag, OpenHow};
    use truenas_ros::uring_fs::{Anchor, Personality};

    let dir = truenas_ros::tempdir().unwrap();
    let pers: Arc<OnceLock<Personality>> = Arc::new(OnceLock::new());
    let anchor = match Anchor::open(dir.path()) {
        Ok(a) => a,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("anchor open: {e}"),
    };

    let pc = Arc::clone(&pers);
    let body = move |mut req: Request<'_, ()>| -> Response {
        let (deferred, permit) = req.responder.defer();
        let Some(mut fs) = req.fs.take() else {
            return Response::Close;
        };
        let who = *pc.get().expect("personality set before serving");
        let anchor = anchor.clone();
        let how = OpenHow::new().flags(OFlag::O_RDONLY | OFlag::O_DIRECTORY);
        let mode = Mode::from_bits_truncate(0o755);
        fs.mkdir_path(who, &anchor, c"a/b/c", mode, how, move |done, fs| {
            let Some(deepest) = done.file() else {
                return deferred.close();
            };
            fs.fsync(who, deepest, move |res, _fs| match res.result() {
                Ok(_) => deferred.reply(echo_frame(b"ok")),
                Err(_) => deferred.close(),
            });
        });
        Response::Defer(permit)
    };
    let protocol = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(
            PrefixWidth::U32,
            Endian::Big,
            false,
        ),
        body,
    };
    let cfg = ServerConfig {
        pool_size: 16,
        fs_ops: 16,
        ..ServerConfig::default()
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let mut server = match Server::with_config([addr], cfg, protocol) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind with fs pool: {e}"),
    };
    pers.set(server.register_self().expect("register_self"))
        .unwrap();
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();
    let client = thread::spawn(move || -> io::Result<(Vec<u8>, Vec<u8>)> {
        // Shut down on every exit: one that skipped it would strand
        // `serve_forever` and hang rather than fail.
        let out = (|| {
            let mut s = connect_tcp(v4)?;
            s.set_read_timeout(Some(Duration::from_secs(5)))?;
            // The walk: nothing of `a/b/c` exists yet.
            send_framed(&mut s, b"walk")?;
            let walked = recv_framed(&mut s)?;
            // The fast path: the tree is whole, so one open settles it.
            send_framed(&mut s, b"again")?;
            let again = recv_framed(&mut s)?;
            Ok((walked, again))
        })();
        stop.shutdown();
        out
    });
    server.serve_forever().expect("serve_forever mkdir_path");
    let (walked, again) = client.join().unwrap().expect("client io");
    assert_eq!(walked, b"ok", "the walk answered a flushable directory");
    assert_eq!(again, b"ok", "an existing tree is not an error");
    assert!(dir.path().join("a/b/c").is_dir(), "the tree was created");
}

/// `FsConn::mkdir_path` refuses a path whose components it cannot rebuild,
/// and refuses it on **shape** rather than on whether the kernel resolves
/// it.
///
/// `a/../b` is the case worth pinning: `openat2` under `CONFINED_RESOLVE`
/// resolves it, so a probe-first order would answer it with a directory
/// wherever the tree happened to exist and refuse it everywhere else - one
/// path meaning two things. A walk that has to create `b` cannot know what
/// `a/..` names, so the answer is the same either way: refused, before
/// anything is submitted.
///
/// An invalid argument answers `on_done` before `mkdir_path` returns,
/// with `EINVAL` and the refusal mark - so the handler replies to the
/// peer instead of the connection being shed over a caller bug, and the
/// callback runs inline while the handler is still on its way to
/// `Response::Defer`. That ordering is the other thing this pins: a
/// `Deferred::reply` made before the `Defer(permit)` verdict is
/// processed rides the injection queue and lands once the park exists.
#[cfg(feature = "uring-fs")]
#[test]
fn fs_conn_mkdir_path_refuses_a_path_it_cannot_rebuild() {
    use std::sync::OnceLock;
    use std::time::Duration;
    use truenas_ros::sync_fs::{Mode, OFlag, OpenHow};
    use truenas_ros::uring_fs::{Anchor, Personality};

    let dir = truenas_ros::tempdir().unwrap();
    // `a` exists, so `a/../b` is a path the kernel WOULD resolve if the
    // walk ever let it near `openat2`.
    std::fs::create_dir(dir.path().join("a")).unwrap();
    let pers: Arc<OnceLock<Personality>> = Arc::new(OnceLock::new());
    let anchor = match Anchor::open(dir.path()) {
        Ok(a) => a,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("anchor open: {e}"),
    };

    let pc = Arc::clone(&pers);
    let body = move |mut req: Request<'_, ()>| -> Response {
        let (deferred, permit) = req.responder.defer();
        let Some(mut fs) = req.fs.take() else {
            return Response::Close;
        };
        let who = *pc.get().expect("personality set before serving");
        let anchor = anchor.clone();
        let how = OpenHow::new().flags(OFlag::O_RDONLY | OFlag::O_DIRECTORY);
        let mode = Mode::from_bits_truncate(0o755);
        fs.mkdir_path(who, &anchor, c"a/../b", mode, how, move |d, _fs| {
            // Fired inline, before `mkdir_path` returned: the screen
            // answers rather than dropping, and the reply below is
            // injected ahead of the `Defer` verdict being processed.
            let verdict = match d.result() {
                Err(truenas_ros::Error::Errno(e)) if d.was_refused() => {
                    format!("refused:{e:?}")
                }
                other => format!("wrong:{other:?}"),
            };
            deferred.reply(echo_frame(verdict.as_bytes()));
        });
        Response::Defer(permit)
    };
    let protocol = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(
            PrefixWidth::U32,
            Endian::Big,
            false,
        ),
        body,
    };
    let cfg = ServerConfig {
        pool_size: 16,
        fs_ops: 16,
        ..ServerConfig::default()
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let mut server = match Server::with_config([addr], cfg, protocol) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind with fs pool: {e}"),
    };
    pers.set(server.register_self().expect("register_self"))
        .unwrap();
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();
    let client = thread::spawn(move || -> io::Result<io::Result<Vec<u8>>> {
        let out = (|| {
            let mut s = connect_tcp(v4)?;
            s.set_read_timeout(Some(Duration::from_secs(5)))?;
            send_framed(&mut s, b"go")?;
            Ok(recv_framed(&mut s))
        })();
        stop.shutdown();
        out
    });
    server
        .serve_forever()
        .expect("serve_forever mkdir_path refusal");
    let got = client.join().unwrap().expect("client io");
    assert_eq!(
        got.expect("the handler answered instead of shedding the peer"),
        b"refused:EINVAL".to_vec(),
        "the callback saw the marked refusal"
    );
    assert!(
        !dir.path().join("b").exists() && !dir.path().join("a/b").exists(),
        "a refused path creates nothing"
    );
}
/// `FsConn::mkdir_path` answers with a directory or with nothing: a `how`
/// that would make the final open produce a *file* is refused.
///
/// `O_CREAT` is the case that bites. The probe opens the whole path, so
/// with `a/b` present and `c` missing it would create a regular file `c`
/// and hand it back as though the tree had been built - success, wrong
/// object, nothing on the wire to say so. The kernel does refuse
/// `O_DIRECTORY | O_CREAT` (`build_open_flags`, `fs/open.c:1278-1284`),
/// but only at the syscall, by which point the walk has created the tree;
/// the refusal here happens before anything is submitted.
///
/// `O_TMPFILE` is the case that hides: it is `__O_TMPFILE | O_DIRECTORY`,
/// so forcing `O_DIRECTORY` does not exclude it and a naive
/// `flags & O_TMPFILE` test matches every plain directory open.
///
/// Both refusals answer the callback inline with a marked `EINVAL`;
/// the handler replies, and the peer keeps its connection.
#[cfg(feature = "uring-fs")]
#[test]
fn fs_conn_mkdir_path_refuses_a_how_that_would_answer_with_a_file() {
    use std::sync::OnceLock;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    use truenas_ros::sync_fs::{Mode, OFlag, OpenHow};
    use truenas_ros::uring_fs::{Anchor, Personality};

    let dir = truenas_ros::tempdir().unwrap();
    // The parents exist and the leaf does not - exactly the shape where an
    // `O_CREAT` probe would succeed by creating a regular file.
    std::fs::create_dir_all(dir.path().join("a/b")).unwrap();
    let pers: Arc<OnceLock<Personality>> = Arc::new(OnceLock::new());
    let anchor = match Anchor::open(dir.path()) {
        Ok(a) => a,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("anchor open: {e}"),
    };

    // Which request is being served: 0 => O_CREAT, 1 => O_TMPFILE.
    let nth = Arc::new(AtomicUsize::new(0));
    let pc = Arc::clone(&pers);
    let nc = Arc::clone(&nth);
    let body = move |mut req: Request<'_, ()>| -> Response {
        let (deferred, permit) = req.responder.defer();
        let Some(mut fs) = req.fs.take() else {
            return Response::Close;
        };
        let who = *pc.get().expect("personality set before serving");
        let anchor = anchor.clone();
        let flags = match nc.fetch_add(1, Ordering::Relaxed) {
            0 => OFlag::O_RDONLY | OFlag::O_CREAT,
            _ => OFlag::O_RDWR | OFlag::O_TMPFILE,
        };
        let how = OpenHow::new()
            .flags(flags)
            .mode(Mode::from_bits_truncate(0o644));
        let mode = Mode::from_bits_truncate(0o755);
        fs.mkdir_path(who, &anchor, c"a/b/c", mode, how, move |d, _fs| {
            // Fired inline with the marked refusal; see the sibling
            // test for the ordering this rides on.
            let ok = matches!(
                d.result(),
                Err(truenas_ros::Error::Errno(
                    truenas_ros::errno::Errno::EINVAL
                ))
            ) && d.was_refused();
            deferred.reply(echo_frame(if ok { b"refused" } else { b"wrong" }));
        });
        Response::Defer(permit)
    };
    let protocol = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(
            PrefixWidth::U32,
            Endian::Big,
            false,
        ),
        body,
    };
    let cfg = ServerConfig {
        pool_size: 16,
        fs_ops: 16,
        ..ServerConfig::default()
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let mut server = match Server::with_config([addr], cfg, protocol) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind with fs pool: {e}"),
    };
    pers.set(server.register_self().expect("register_self"))
        .unwrap();
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();
    let client = thread::spawn(move || -> io::Result<[bool; 2]> {
        let out = (|| {
            let mut got = [false; 2];
            for slot in got.iter_mut() {
                let mut s = connect_tcp(v4)?;
                s.set_read_timeout(Some(Duration::from_secs(5)))?;
                send_framed(&mut s, b"go")?;
                *slot = recv_framed(&mut s)? == b"refused";
            }
            Ok(got)
        })();
        stop.shutdown();
        out
    });
    server
        .serve_forever()
        .expect("serve_forever mkdir_path how");
    let answered = client.join().unwrap().expect("client io");
    assert_eq!(
        answered,
        [true, true],
        "both O_CREAT and O_TMPFILE must be refused, with the refusal \
         answered to the handler rather than the connection shed"
    );
    let leaf = dir.path().join("a/b/c");
    assert!(
        !leaf.exists(),
        "a refused `how` must not leave anything at the leaf, least of all \
         a regular file standing in for the directory"
    );
}

// ---- the registered recv-buffer pool --------------------------------------

/// Registering the ring is best-effort - a kernel that refuses leaves the
/// server running with connections owning their buffers - so every pooled
/// test has to say out loud that it got a pool. Without this they all pass
/// against the fallback and prove nothing about the ring.
fn assert_pool_registered(s: &truenas_ros::net::server::ServerStats) {
    assert!(
        s.recv_bufs_total > 0,
        "no recv buffer ring registered - this test exercised the \
         owned-buffer fallback, not the pool: {s:?}"
    );
}

/// Concurrent connections over a pool, each sending several messages, with
/// `max_request_bytes` low enough that a pool buffer is a few KiB rather than
/// a megabyte. Proves the whole acquisition path: `IOSQE_BUFFER_SELECT` on the
/// arm, the buffer id off the completion, framing and delivery out of pool
/// memory, and the hand-back.
///
/// The bytes are the point. A buffer adopted at the wrong offset, or released
/// while still holding a pipelined remainder, corrupts the echo rather than
/// failing an assertion about the pool.
#[test]
fn a_pooled_server_echoes_what_an_owned_one_does() {
    const N: usize = 12;
    const PER_CONN: usize = 8;
    let cfg = ServerConfig {
        pool_size: 32,
        max_request_bytes: 8 * 1024,
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
    let stats = server.stats_handle();
    let stop = server.shutdown_handle();

    let coordinator = thread::spawn(move || {
        let clients: Vec<_> = (0..N)
            .map(|_i| {
                thread::spawn(move || {
                    let s = connect_tcp(v4)?;
                    // Sizes that straddle the 4 KiB scanning read, so a
                    // message spans several recvs into the same buffer.
                    let msgs: Vec<Vec<u8>> = (0..PER_CONN)
                        .map(|j| (b'a' + (j as u8), 500 + j * 900))
                        .map(|(b, n)| vec![b; n])
                        .collect();
                    let refs: Vec<&[u8]> =
                        msgs.iter().map(Vec::as_slice).collect();
                    framed_roundtrips(s, &refs).map(|e| (msgs, e))
                })
            })
            .collect();
        let out: Vec<_> =
            clients.into_iter().map(|c| c.join().unwrap()).collect();
        stop.shutdown();
        out
    });

    server.serve_forever().expect("serve_forever");
    for r in coordinator.join().expect("coordinator join") {
        let (sent, got) = r.expect("client io");
        assert_eq!(got, sent, "echo must be byte-identical over a pool");
    }

    // Every connection is gone, so every buffer is back. A pool that leaks
    // one leaks it forever: `BufPool::rebalance` retires a group only at
    // `lent() == 0`, so the pool could then never shrink either.
    let s = stats.snapshot();
    assert_pool_registered(&s);
    assert_eq!(s.recv_bufs_lent, 0, "buffers outstanding after every close");
}

/// The property the pool exists for: a connection parked between requests
/// holds no buffer, so buffer memory tracks concurrent *arrivals* and not the
/// connection count.
///
/// Measured with more idle connections than the pool has buffers - which an
/// owned-buffer server would need one apiece for, and which a pool that held
/// them across the idle gap would have to grow to cover.
#[test]
fn an_idle_pooled_connection_holds_no_buffer() {
    const IDLE: usize = 16;
    let cfg = ServerConfig {
        pool_size: 32,
        max_request_bytes: 8 * 1024,
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
    let stats = server.stats_handle();
    let stop = server.shutdown_handle();

    let coordinator = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone());
        // Open them all, round-trip once each so each has certainly been
        // served, then hold them open and idle.
        let mut held = Vec::new();
        for i in 0..IDLE {
            let mut s = connect_tcp(v4).expect("connect");
            send_framed(&mut s, format!("req-{i}").as_bytes()).expect("send");
            let echo = recv_framed(&mut s).expect("recv");
            assert_eq!(echo, format!("req-{i}").into_bytes());
            held.push(s);
        }
        // All served, all parked on an idle recv. The last reply's send
        // completion can still be in flight, so settle rather than sample.
        let deadline = Instant::now() + Duration::from_secs(5);
        let idle = loop {
            let s = stats.snapshot();
            if s.active as usize == IDLE && s.recv_bufs_lent == 0 {
                break s;
            }
            assert!(Instant::now() < deadline, "never settled: {s:?}");
            thread::sleep(Duration::from_millis(20));
        };
        stop.shutdown();
        drop(held);
        idle
    });

    server.serve_forever().expect("serve_forever");
    let s = coordinator.join().expect("coordinator join");
    assert_pool_registered(&s);
    assert_eq!(
        s.recv_bufs_lent, 0,
        "{IDLE} idle connections held {} buffers",
        s.recv_bufs_lent
    );
    assert!(
        (s.recv_bufs_total as usize) < IDLE,
        "pool grew to {} for {IDLE} idle connections - buffers are being \
         held across the idle gap",
        s.recv_bufs_total
    );
}

/// The pool under kTLS, where the recv is a `RECVMSG` carrying a control
/// buffer for the record type rather than a plain `RECV`.
///
/// Worth its own test because the two features meet in the kernel's msghdr
/// import: `io_recvmsg_copy_hdr` skips `io_net_import_vec` entirely when
/// `REQ_F_BUFFER_SELECT` is set (`io_uring/net.c:746-751`), so the iovec this
/// side supplies is never read for its address - but `io_msg_copy_hdr` still
/// copies the iovec *struct* to take its length
/// (`net.c:327-339`, `-EINVAL` above one segment) and still honours
/// `msg_control`. A payload spanning several TLS records exercises the
/// resume-at-an-offset continuation into a buffer the kernel chose.
#[test]
fn a_pooled_connection_still_reads_over_ktls() {
    if ktls_openssl_unsupported() {
        return;
    }
    let (cert, key) = self_signed();
    let acceptor = Arc::new(ktls_acceptor(&cert, &key));
    let cfg = ServerConfig {
        pool_size: 16,
        max_request_bytes: 128 * 1024,
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
    let stats = server.stats_handle();
    let stop = server.shutdown_handle();

    let client = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop);
        (|| -> io::Result<()> {
            let mut s = tls_connect(v4)?;
            for msg in [b"tls-pooled".as_slice(), b"again"] {
                send_framed(&mut s, msg)?;
                assert_eq!(recv_framed(&mut s)?, msg, "kTLS echo over a pool");
            }
            // Well past the 16 KiB TLS record cap, so the exact read
            // completes short and resumes at an offset into the pool buffer.
            let big = vec![0x5au8; 40 * 1024];
            send_framed(&mut s, &big)?;
            assert_eq!(recv_framed(&mut s)?, big, "multi-record body");
            Ok(())
        })()
        .expect("client io");
    });

    server.serve_forever().expect("serve_forever");
    client.join().expect("thread join");
    let s = stats.snapshot();
    assert_pool_registered(&s);
    assert_eq!(s.recv_bufs_lent, 0, "buffer outstanding after close: {s:?}");
    assert!(s.requests >= 3, "requests: {s:?}");
}

/// A message larger than a pool buffer promotes to owned storage and is
/// served whole, rather than being refused for outgrowing its buffer.
///
/// This is what lets the buffer size be a free parameter instead of
/// `max_request_bytes`: the copy is bounded by the buffer, and the
/// connection returns to the pool once the message is consumed.
#[test]
fn a_message_larger_than_a_pool_buffer_promotes_and_still_echoes() {
    let cfg = ServerConfig {
        pool_size: 8,
        max_request_bytes: 4 * 1024 * 1024,
        // Placement would divert the big body into its own allocation and
        // the accumulate buffer would never have to grow - which is a real
        // path, but not this one.
        body_placement_threshold: None,
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
    let stats = server.stats_handle();
    let stop = server.shutdown_handle();

    let client = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone());
        let s = connect_tcp(v4).expect("connect");
        // Well past the pooled buffer, then a small one after it: the
        // second proves the connection went back to the pool rather than
        // being left owning the promoted buffer.
        let big = vec![0xa5u8; 512 * 1024];
        let msgs: Vec<&[u8]> = vec![&big, b"after"];
        let echoes = framed_roundtrips(s, &msgs).expect("client io");
        stop.shutdown();
        echoes
    });

    server.serve_forever().expect("serve_forever");
    let echoes = client.join().expect("thread join");
    assert_eq!(echoes[0].len(), 512 * 1024, "promoted message came back");
    assert!(echoes[0].iter().all(|&b| b == 0xa5), "and came back intact");
    assert_eq!(echoes[1], b"after", "connection kept serving");
    let s = stats.snapshot();
    assert_pool_registered(&s);
    assert_eq!(s.recv_bufs_lent, 0, "buffer outstanding at close: {s:?}");
}

/// A framer that consumes its own header, then declares a body with
/// `header_len: 0` - the shape a streaming codec has for every message
/// after the first, and the one that puts a placed body read on a
/// connection with nothing buffered.
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

/// A placed body reads into its own allocation, so it must not also be
/// handed a pool buffer.
///
/// The kernel clamps a selecting read to the length of the buffer it picks
/// (`io_ring_buffer_select`, `io_uring/kbuf.c`), so an exact read longer
/// than a pool buffer completes short of what the frame declared - which the
/// reactor can only read as a truncated message, and the connection dies
/// mid-request.
///
/// It takes a `header_len: 0` frame to reach: with a header buffered the
/// connection is already holding a claim and asks for nothing. That is why
/// this carries its own framer rather than reusing the length-prefixed one.
#[test]
fn a_placed_body_never_takes_a_pool_buffer() {
    const N: usize = 512 * 1024;
    let cfg = ServerConfig {
        pool_size: 8,
        max_request_bytes: 4 * 1024 * 1024,
        // Low enough that the body below is placed, and far below the
        // message size, so a buffer taken here would be far too small.
        body_placement_threshold: Some(8 * 1024),
        ..ServerConfig::default()
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(0usize),
        header: split_header,
        body: |req: Request<'_, usize>| {
            // The body message clears the pending count; the header-only
            // message that set it replies with nothing.
            if req.body.is_empty() {
                return Response::Reply(Vec::new());
            }
            *req.state = 0;
            Response::Reply(req.body.to_vec())
        },
    };
    let mut server = match Server::with_config([addr], cfg, proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind: {e}"),
    };
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stats = server.stats_handle();
    let stop = server.shutdown_handle();

    let client = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone());
        let r = (|| -> io::Result<Vec<u8>> {
            let mut s = connect_tcp(v4)?;
            s.write_all(&(N as u32).to_be_bytes())?;
            s.write_all(&vec![0x3cu8; N])?;
            let mut got = vec![0u8; N];
            s.read_exact(&mut got)?;
            Ok(got)
        })();
        stop.shutdown();
        r
    });

    server.serve_forever().expect("serve_forever");
    let got = client.join().expect("thread join").expect("client io");
    assert_eq!(got.len(), N, "placed body came back whole");
    assert!(got.iter().all(|&b| b == 0x3c), "and intact");
    let s = stats.snapshot();
    assert_pool_registered(&s);
    assert_eq!(s.recv_bufs_lent, 0, "buffer outstanding at close: {s:?}");
}

/// A burst of file bodies wider than the ring's current buffer count must
/// grow the ring and serve every one - never shed.
///
/// The kernel picks a provided buffer when the read completes, so a burst
/// can always outrun what is posted and the shortage arrives as `-ENOBUFS`
/// on the pump read's completion. Treating that as a read failure closes
/// the connection mid-body; it is pressure, and the answer is to grow (or,
/// if the pool cannot, to re-issue the read with an owned buffer). The
/// barrier makes the burst genuinely simultaneous: every client fires its
/// request in the same instant against a pool that starts at eight.
#[cfg(feature = "uring-fs")]
#[test]
fn a_burst_of_file_bodies_grows_the_ring_instead_of_shedding() {
    use std::sync::{Barrier, Mutex, mpsc};
    use truenas_ros::sync_fs::{OFlag, OpenHow};
    use truenas_ros::uring_fs::{Anchor, FsConfig, UringFs};

    const CONNS: usize = 24;
    const CHUNK: usize = 16 * 1024;
    const SIZE: usize = 8 * CHUNK;

    let dir = truenas_ros::tempdir().unwrap();
    std::fs::write(dir.path().join("obj"), vec![0x42u8; SIZE])
        .expect("fixture");

    // One open through a standalone fs host, cloned per request.
    let mut afs = match UringFs::new(FsConfig::default()) {
        Ok(f) => f,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("UringFs::new: {e}"),
    };
    let who = afs.register_self().expect("register_self");
    let handle = afs.handle();
    let stop_fs = afs.shutdown_handle();
    let anchor = Anchor::open(dir.path()).expect("anchor");
    let (ftx, frx) = mpsc::channel();
    thread::scope(|sc| {
        sc.spawn(move || {
            let r = handle.open(
                who,
                &anchor,
                c"obj",
                OpenHow::new().flags(OFlag::O_RDONLY),
            );
            let _ = ftx.send(r);
            stop_fs.shutdown();
        });
        afs.run().expect("fs host run");
    });
    let file = frx.recv().expect("open outcome").expect("open");

    let cfg = ServerConfig {
        pool_size: 32,
        fs_ops: 16,
        fs_body_chunk: CHUNK,
        ..ServerConfig::default()
    };
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(
            PrefixWidth::U32,
            Endian::Big,
            false,
        ),
        body: move |_req: Request<'_, ()>| Response::ReplyFile {
            head: Vec::new(),
            file: file.clone(),
            offset: 0,
            len: SIZE as u64,
            close: true,
        },
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let mut server = match Server::with_config([addr], cfg, proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind: {e}"),
    };
    let reasons = Arc::new(Mutex::new(Vec::new()));
    {
        let reasons = Arc::clone(&reasons);
        server.set_close_hook(move |_p, reason, _s: &mut ()| {
            reasons.lock().unwrap().push(reason);
        });
    }
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stats = server.stats_handle();
    let stop = server.shutdown_handle();

    let coordinator = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone());
        let barrier = Arc::new(Barrier::new(CONNS));
        let clients: Vec<_> = (0..CONNS)
            .map(|_| {
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || -> io::Result<()> {
                    let mut s = connect_tcp(v4)?;
                    barrier.wait(); // everyone asks in the same instant
                    send_framed(&mut s, b"g")?;
                    let mut got = vec![0u8; SIZE];
                    s.read_exact(&mut got)?;
                    assert!(
                        got.iter().all(|&b| b == 0x42),
                        "body corrupted under buffer pressure"
                    );
                    Ok(())
                })
            })
            .collect();
        let results: Vec<_> =
            clients.into_iter().map(|c| c.join().unwrap()).collect();
        stop.shutdown();
        results
    });

    server.serve_forever().expect("serve_forever");
    for (i, r) in coordinator.join().expect("join").into_iter().enumerate() {
        r.unwrap_or_else(|e| panic!("client {i} shed under pressure: {e}"));
    }
    let shed: Vec<_> = reasons
        .lock()
        .unwrap()
        .iter()
        .filter(|r| matches!(r, CloseReason::FileBody(_)))
        .cloned()
        .collect();
    assert!(shed.is_empty(), "bodies shed as read failures: {shed:?}");
    let s = stats.snapshot();
    assert_eq!(
        s.recv_bufs_lent, 0,
        "buffers outstanding after close: {s:?}"
    );
}

/// A pump completion that closes the connection must still return its
/// buffer to the ring.
///
/// Every completion carrying `IORING_CQE_F_BUFFER` consumed its
/// descriptor: the kernel puts the kbuf with no guard on the result
/// (`io_req_rw_complete`, `io_uring/rw.c:591`), and an EOF read is the
/// measured proof - it completes `res = 0` with the flag set and the
/// ring's head advanced. So the truncated-body close (`n == 0`, the file
/// shrank under a committed `Content-Length`) is a completion that both
/// carries a buffer and abandons the transfer: exactly the exit class that
/// must requeue. Skipping it strands the id, `recv_bufs_lent` stays
/// innocently at zero while the pool replaces each loss with a fresh
/// allocation, and the ring drains one abandoned body at a time. The same
/// duty holds on the racier exits of that class (a completion landing on a
/// closing or recycled slot), which share this arm's fix but cannot be
/// scheduled deterministically from a test; `rw.c:591` is the authority
/// that they owe the id all the same.
#[cfg(feature = "uring-fs")]
#[test]
fn a_truncated_body_close_returns_its_buffer() {
    use std::sync::mpsc;
    use truenas_ros::sync_fs::{OFlag, OpenHow};
    use truenas_ros::uring_fs::{Anchor, FsConfig, UringFs};

    const ROUNDS: usize = 20;
    const CHUNK: usize = 32 * 1024;

    let dir = truenas_ros::tempdir().unwrap();
    // Half a chunk on disk, four chunks declared: read one short chunk,
    // then hit EOF - a completion with a buffer and nothing in it.
    std::fs::write(dir.path().join("obj"), vec![0x51u8; CHUNK / 2])
        .expect("fixture");

    let mut afs = match UringFs::new(FsConfig::default()) {
        Ok(f) => f,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("UringFs::new: {e}"),
    };
    let who = afs.register_self().expect("register_self");
    let handle = afs.handle();
    let stop_fs = afs.shutdown_handle();
    let anchor = Anchor::open(dir.path()).expect("anchor");
    let (ftx, frx) = mpsc::channel();
    thread::scope(|sc| {
        sc.spawn(move || {
            let r = handle.open(
                who,
                &anchor,
                c"obj",
                OpenHow::new().flags(OFlag::O_RDONLY),
            );
            let _ = ftx.send(r);
            stop_fs.shutdown();
        });
        afs.run().expect("fs host run");
    });
    let file = frx.recv().expect("open outcome").expect("open");

    let cfg = ServerConfig {
        // Wide enough that a stranded-id drain has room to snowball: each
        // loss forces a replacement, the ring doubles toward its 64-entry
        // wall, and the gauge shows a climb no sizing noise can reach.
        pool_size: 32,
        fs_ops: 16,
        fs_body_chunk: CHUNK,
        ..ServerConfig::default()
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(
            PrefixWidth::U32,
            Endian::Big,
            false,
        ),
        body: move |_req: Request<'_, ()>| Response::ReplyFile {
            head: b"H".to_vec(),
            file: file.clone(),
            offset: 0,
            len: (4 * CHUNK) as u64,
            close: true,
        },
    };
    let mut server = match Server::with_config([addr], cfg, proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind: {e}"),
    };
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stats = server.stats_handle();
    let stop = server.shutdown_handle();

    let client = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone());
        for i in 0..ROUNDS {
            let mut s = connect_tcp(v4).expect("connect");
            s.write_all(&1u32.to_be_bytes()).expect("len");
            s.write_all(b"g").expect("req");
            // The server sends the head and the short chunk, then closes
            // mid-body on the EOF. Drain to the reset/EOF.
            let mut sink = Vec::new();
            let _ = s.read_to_end(&mut sink);
            assert!(
                sink.len() <= 1 + CHUNK / 2,
                "round {i}: a truncated body was served whole"
            );
            drop(s);
        }
        // Let the closes retire, then check the ring survived.
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let st = stats.snapshot();
            if st.active == 0 && st.recv_bufs_lent == 0 {
                break;
            }
            assert!(Instant::now() < deadline, "never settled: {st:?}");
            thread::sleep(Duration::from_millis(10));
        }
        stop.shutdown();
        stats.snapshot()
    });

    server.serve_forever().expect("serve_forever");
    let s = client.join().expect("client thread");
    assert!(s.recv_bufs_total > 0, "no ring registered: {s:?}");
    assert_eq!(s.recv_bufs_lent, 0, "buffers outstanding: {s:?}");
    // Both rings start at 8 and these sequential one-body rounds never
    // need more (the recv side may even shrink), so the settled total sits
    // at 16 or below. A stranded id per truncation drains the body ring
    // dry every eight rounds, and each drain doubles it toward the wall -
    // 20 rounds drove the total past 30 with the requeue removed - while
    // `lent` stayed flat throughout, which is why the total is the only
    // gauge that can see this.
    assert!(
        s.recv_bufs_total <= 20,
        "the ring drained under truncated-body closes: {s:?}"
    );
}

/// A two-phase length-prefixed framer: deliver the 4-byte prefix, then ask
/// for the payload with `Framing::Need`. The payload read therefore starts
/// with nothing buffered and no claim held, which is the state that reaches
/// the pool-buffer decision.
fn need_payload(buf: &[u8], pending: &mut usize) -> Framing {
    if *pending > 0 {
        if buf.len() < *pending {
            return Framing::Need(*pending - buf.len());
        }
        let n = *pending;
        *pending = 0;
        return Framing::Complete {
            header_len: 0,
            body_len: n,
        };
    }
    if buf.len() < 4 {
        return Framing::Need(4 - buf.len());
    }
    *pending = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    Framing::Complete {
        header_len: 4,
        body_len: 0,
    }
}

/// An exact read larger than one pool buffer takes an owned buffer.
///
/// `frame_step` admits a `Framing::Need(n)` up to `max_request_bytes` and
/// turns it into an *exact* `ReadHeader`, and `ReadHeader` carries no
/// placement flag - so without the size test at the arm this read is armed
/// with `IOSQE_BUFFER_SELECT`, the kernel clamps it to the buffer it picked
/// (`io_ring_buffer_select`, `io_uring/kbuf.c`), and the connection dies
/// `TruncatedMessage` having answered nothing. Default config: the pool
/// buffer is 266 240 bytes and `max_request_bytes` is 1 MiB, so every
/// `Need` between them is in this window.
#[test]
fn an_exact_read_over_the_pool_buffer_takes_an_owned_one() {
    const N: usize = 512 * 1024;
    let cfg = ServerConfig {
        pool_size: 8,
        ..ServerConfig::default()
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(0usize),
        header: need_payload,
        body: |req: Request<'_, usize>| {
            if req.body.is_empty() {
                return Response::Reply(Vec::new());
            }
            Response::Reply(req.body.to_vec())
        },
    };
    let mut server = match Server::with_config([addr], cfg, proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind: {e}"),
    };
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stats = server.stats_handle();
    let stop = server.shutdown_handle();
    let client = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone());
        let r = (|| -> io::Result<Vec<u8>> {
            let mut s = connect_tcp(v4)?;
            s.write_all(&(N as u32).to_be_bytes())?;
            s.write_all(&vec![0x77u8; N])?;
            let mut got = vec![0u8; N];
            s.read_exact(&mut got)?;
            Ok(got)
        })();
        stop.shutdown();
        r
    });
    server.serve_forever().expect("serve_forever");
    let got = client.join().expect("thread join");
    let s = stats.snapshot();
    assert_pool_registered(&s);
    let got = got.unwrap_or_else(|e| {
        panic!(
            "a {N}-byte exact read took a pool buffer and was clamped to \
             it, closing the connection: {e} / stats {s:?}"
        )
    });
    assert_eq!(got.len(), N, "the whole payload came back");
    assert!(got.iter().all(|&b| b == 0x77), "and unmangled");
    assert_eq!(
        s.recv_bufs_lent, 0,
        "the pool settles back to nothing lent: {s:?}"
    );
}

/// A redelivery must not be handed the *read-ahead* frame.
///
/// `Deferred::redeliver` documents that the handler runs again "with an
/// empty frame (the original bytes were consumed at first delivery)".
/// Nothing enforced it. Above the default read-ahead cap the pump can have
/// framed the next pipelined request already - `set_frame(header_len,
/// body_len)` recorded, its body still in flight - and the redelivery then
/// built that message's `Body` out of a buffer holding only its header:
/// `Body::inline(&rest[..body_len])` with `rest` empty, an out-of-range
/// slice that panics the reactor thread and takes `serve_forever` with it.
/// Bounds checks ship, so release panicked too.
///
/// Even short of the panic the state was wrong: `deliver_one`'s epilogue
/// drains `frame_len().min(buffered)`, so a foreign frame ate the next
/// request's header and desynced the stream.
///
/// The in-tree http codec never reaches this (`Phase::Parked` holds
/// pipelined bytes unframed), so the control has to be a framer that does
/// what `Protocol::header` allows: frame whatever is buffered.
#[test]
fn a_redelivery_does_not_take_the_read_ahead_frame() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let cfg = ServerConfig {
        // Read-ahead is the precondition: at the default cap of one the pump
        // stops while the first request is outstanding and never frames the
        // second.
        max_in_flight_requests: 2,
        ..ServerConfig::default()
    };
    let seen = Arc::new(AtomicUsize::new(0));
    let seen2 = Arc::clone(&seen);
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(
            PrefixWidth::U32,
            Endian::Big,
            false,
        ),
        body: move |req: Request<'_, ()>| {
            let nth = seen2.fetch_add(1, Ordering::SeqCst);
            match nth {
                // The first request parks, and is answered off-thread by a
                // redelivery long enough afterwards for the peer's second
                // request head to have landed and been framed.
                0 => {
                    let (deferred, permit) = req.responder.defer();
                    thread::spawn(move || {
                        thread::sleep(Duration::from_millis(150));
                        deferred.redeliver();
                    });
                    Response::Defer(permit)
                }
                // The redelivery: an empty frame, whatever the pump has
                // recorded for the request behind it.
                1 => {
                    assert!(
                        req.body.is_empty(),
                        "a redelivery must see an empty frame, got {} bytes",
                        req.body.len()
                    );
                    Response::Reply(echo_frame(b"first"))
                }
                // The pipelined request, delivered from its own frame once
                // its body arrives - intact, not short a header.
                _ => Response::Reply(echo_frame(&req.body)),
            }
        },
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
            let mut s = connect_tcp(v4)?;
            send_framed(&mut s, b"A")?;
            thread::sleep(Duration::from_millis(50));
            // The second request's *header* only: the pump frames it and
            // arms an exact read for a body that has not been sent.
            s.write_all(&8u32.to_be_bytes())?;
            s.flush()?;
            thread::sleep(Duration::from_millis(250)); // the redelivery lands
            s.write_all(b"BBBBBBBB")?;
            s.flush()?;
            assert_eq!(recv_framed(&mut s)?, b"first");
            assert_eq!(recv_framed(&mut s)?, b"BBBBBBBB");
            Ok(())
        })();
        stop.shutdown();
        r
    });

    server.serve_forever().expect("serve_forever");
    client.join().expect("thread join").expect("client io");
    assert_eq!(
        seen.load(Ordering::SeqCst),
        3,
        "park, redelivery, pipelined"
    );
}

/// A redelivery must not retire the receipt budget of the message behind it.
///
/// The budget belongs to whatever is *arriving*. A redelivered request was
/// consumed - and its own budget retired - at its first delivery, so the
/// only budget armed when a worker's `redeliver` lands belongs to a later
/// message the read-ahead has begun. Cancelling it there restarts the one
/// bound `max_receipt_time` exists to make un-restartable, and when the
/// next read is already in flight (an exact body read) nothing re-arms it
/// at all: the trickling peer is then never reclaimed.
///
/// The trickle is half `request_timeout`, so that clock is satisfied
/// throughout and the close reason names which one fired.
#[test]
fn a_redelivery_does_not_retire_the_next_message_budget() {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};
    let reasons = Arc::new(Mutex::new(Vec::new()));
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let cfg = ServerConfig {
        request_timeout: Some(Duration::from_millis(300)),
        max_receipt_time: Some(Duration::from_millis(900)),
        max_in_flight_requests: 2,
        ..ServerConfig::default()
    };
    let seen = Arc::new(AtomicUsize::new(0));
    let seen2 = Arc::clone(&seen);
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(
            PrefixWidth::U32,
            Endian::Big,
            false,
        ),
        body: move |req: Request<'_, ()>| {
            if seen2.fetch_add(1, Ordering::SeqCst) == 0 {
                let (deferred, permit) = req.responder.defer();
                thread::spawn(move || {
                    // After the second request's budget is armed and its
                    // exact body read is in flight.
                    thread::sleep(Duration::from_millis(400));
                    deferred.redeliver();
                });
                return Response::Defer(permit);
            }
            Response::Reply(echo_frame(b"ok"))
        },
    };
    let mut server = match Server::with_config([addr], cfg, proto) {
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
            send_framed(&mut s, b"A")?;
            thread::sleep(Duration::from_millis(50));
            s.write_all(&40u32.to_be_bytes())?;
            s.flush()?;
            for _ in 0..40 {
                if s.write_all(b"B").is_err() || s.flush().is_err() {
                    break; // closed under us, which is the point
                }
                thread::sleep(Duration::from_millis(150));
            }
            // The redelivery's own reply rides out while the second request
            // is still trickling; drain to EOF rather than asserting the
            // connection was silent.
            s.set_read_timeout(Some(Duration::from_secs(5)))?;
            let mut sink = [0u8; 256];
            loop {
                match s.read(&mut sink) {
                    Ok(0) => break,
                    Ok(_) => {}
                    Err(e) if e.kind() == io::ErrorKind::ConnectionReset => {
                        break;
                    }
                    Err(e) => panic!("the server never closed: {e}"),
                }
            }
            Ok(())
        })();
        stop.shutdown();
        r
    });

    server.serve_forever().expect("serve_forever");
    client.join().expect("thread join").expect("client io");
    assert_eq!(
        reasons.lock().unwrap().as_slice(),
        &[CloseReason::ReceiptTimeout],
        "the pipelined request's budget must survive the redelivery - \
         nothing at all means the redelivery retired it and no later read \
         re-armed one"
    );
}

/// A spliced body is bounded per window, not whole.
///
/// `max_receipt_time` is a rate floor: `ServerConfig` promises "each window
/// is its own message, so an upload of any size is admitted", and tells the
/// operator to pick it "from the slowest client worth serving, not from the
/// largest upload". A buffered body earns that by construction - the framer
/// splits anything above `STREAM_WINDOW` into windows, each its own message
/// with its own budget. A spliced body is one message however large, so a
/// budget armed once for the whole transfer made wall clock cap upload
/// *size*.
///
/// Here: six windows, each moved in under a third of the budget, but the
/// whole body needing longer than one budget. Every gap is far inside both
/// inactivity clocks, so nothing but a total bound can reap this - and a
/// total bound is what this must not be.
///
/// Run over both header shapes, because the renewal reads a mark that only
/// the splice path sets. A header the framer reads in **two** exact steps
/// arms the budget itself - the second read has bytes buffered, so
/// `submit_recv` does not classify it idle - and a mark tied to whichever
/// call armed the budget is then never set for the body at all: `moved`
/// stays zero, no window is ever earned, and the transfer is bounded whole
/// again. A one-read header hides that entirely, which is why it cannot be
/// the only case here.
///
/// The pipe is drained continuously; at 768 KiB the body is many times a
/// pipe's capacity, so without a reader the splice would block on
/// backpressure and the test would measure that instead.
#[test]
fn a_large_spliced_body_is_bounded_per_window_not_whole() {
    use std::sync::Mutex;

    const WINDOW: usize = 128 * 1024;
    const WINDOWS: usize = 6;
    const BODY: usize = WINDOW * WINDOWS;
    /// Gap between windows: inside `request_timeout`, so the readiness poll
    /// is re-armed on every one and can never be what reaps this.
    const GAP: Duration = Duration::from_millis(150);

    for (what, split_header) in
        [("a one-read header", false), ("a two-read header", true)]
    {
        let mut fds = [0 as libc::c_int; 2];
        // SAFETY: `pipe(2)` fills the two-element array with {read, write}.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe");
        let (pipe_rd, pipe_wr) = (fds[0], fds[1]);

        let reasons = Arc::new(Mutex::new(Vec::new()));
        let cfg = ServerConfig {
            // One window every 150 ms, so no window is remotely near the
            // budget - but six of them take ~900 ms, and a budget armed once
            // for the whole transfer fires at 500 ms, mid-body.
            max_receipt_time: Some(Duration::from_millis(500)),
            // Above the per-window gap, so the readiness poll is re-armed by
            // every window and cannot be what reaps this. `ServerConfig` also
            // requires the receipt budget to exceed it.
            request_timeout: Some(Duration::from_millis(400)),
            idle_timeout: None,
            ..ServerConfig::default()
        };
        let addr =
            ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
        // The same 5-byte `[tag][len BE]` header as `splice_header`, read in
        // one exact step or two. Both are well-formed: `frame_step` requires
        // a splice framer to read its header with exact `Framing::Need`, so
        // that the whole header and nothing past it is buffered.
        let header = move |buf: &[u8], _s: &mut ()| -> Framing {
            if split_header && buf.is_empty() {
                return Framing::Need(1); // the tag, then the length
            }
            if buf.len() < 5 {
                return Framing::Need(5 - buf.len());
            }
            let len =
                u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
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
        };
        let proto = Protocol {
            accept: |_: Incoming<'_>| Some(()),
            header,
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

        // Drain the pipe for the whole run, so the splice never blocks.
        let draining = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let drain = {
            let draining = Arc::clone(&draining);
            thread::spawn(move || {
                let mut sink = vec![0u8; 64 * 1024];
                while draining.load(std::sync::atomic::Ordering::Relaxed) {
                    // SAFETY: `pipe_rd` is a live read end owned by this test.
                    let n = unsafe {
                        libc::read(
                            pipe_rd,
                            sink.as_mut_ptr().cast(),
                            sink.len(),
                        )
                    };
                    if n <= 0 {
                        break;
                    }
                }
            })
        };

        let client = thread::spawn(move || {
            let _stop = ShutdownOnDrop(stop.clone());
            let r = (|| -> io::Result<()> {
                let mut s = connect_tcp(v4)?;
                let mut hdr = vec![b'S'];
                hdr.extend_from_slice(&(BODY as u32).to_be_bytes());
                s.write_all(&hdr)?;
                s.flush()?;
                let chunk = vec![b'x'; WINDOW];
                for _ in 0..WINDOWS {
                    s.write_all(&chunk)?;
                    s.flush()?;
                    thread::sleep(GAP);
                }
                // Alive? Then the transfer was never reaped, and the budget
                // was retired with the message rather than left armed.
                splice_frame(&mut s, b'C', b"ping")?;
                assert_eq!(recv_framed(&mut s)?, b"ping");
                Ok(())
            })();
            stop.shutdown();
            r
        });

        server.serve_forever().expect("serve_forever");
        draining.store(false, std::sync::atomic::Ordering::Relaxed);
        // SAFETY: the test owns both ends; the server never closes `pipe_wr`.
        unsafe {
            libc::close(pipe_wr);
            libc::close(pipe_rd);
        }
        let _ = drain.join();
        // The client completing its ping is half the proof: a connection
        // reaped mid-transfer cannot answer one, so `client io` fails first.
        let served = client.join().expect("thread join");
        // The other half. Not an equality against `[PeerClosed]`: whether the
        // peer-close is observed before `shutdown` tears the loop down is a
        // race with no bearing on the budget, and it is lost in a release
        // build.
        let got = reasons.lock().unwrap().clone();
        assert!(
            !got.contains(&CloseReason::ReceiptTimeout),
            "{what}: a body moving a window per third of a budget is above \
             the floor: ReceiptTimeout means the budget bounded the transfer \
             whole, so wall clock capped upload size (reasons: {got:?})"
        );
        served.unwrap_or_else(|e| panic!("{what}: client io: {e}"));
    }
}

/// The receipt budget covers a spliced body, in both directions.
///
/// `arm_receipt_deadline` is reachable only from `submit_recv`, which a
/// `Framing::SpliceBody` body never enters, so the one clock that progress
/// cannot restart did not reach the splice path at all - the two that do
/// (`request_timeout` on the readiness poll, the kTLS watchdog) are both
/// inactivity bounds any arriving byte re-arms. And where a multi-read
/// header had armed one, nothing retired it: there is no `deliver_one` on
/// this path, so the budget outlived the message it belonged to and reaped
/// a connection that had transferred its body on time.
///
/// Both halves on the plain-TCP splice, which is the same code as the kTLS
/// one up to the blocking-vs-poll difference (see `submit_splice_recv`).
#[test]
fn the_receipt_budget_bounds_a_spliced_body_and_ends_with_it() {
    use std::sync::Mutex;
    for (what, trickle) in [("a healthy body", false), ("a trickle", true)] {
        let mut fds = [0 as libc::c_int; 2];
        // SAFETY: `pipe(2)` fills the two-element array with {read, write}.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe");
        let (pipe_rd, pipe_wr) = (fds[0], fds[1]);

        let reasons = Arc::new(Mutex::new(Vec::new()));
        let cfg = ServerConfig {
            request_timeout: Some(Duration::from_millis(300)),
            max_receipt_time: Some(Duration::from_millis(700)),
            // Unset, so a connection that has finished its message and gone
            // quiet has no other clock that could reap it: the healthy case
            // fails loudly if the budget is still armed.
            idle_timeout: None,
            ..ServerConfig::default()
        };
        let addr =
            ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
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

        // 64 bytes: well inside a pipe's capacity, so no reader is needed
        // and nothing here can block on backpressure.
        const BODY: usize = 64;
        let client = thread::spawn(move || {
            let _stop = ShutdownOnDrop(stop.clone());
            let r = (|| -> io::Result<()> {
                let mut s = connect_tcp(v4)?;
                let mut hdr = vec![b'S'];
                hdr.extend_from_slice(&(BODY as u32).to_be_bytes());
                s.write_all(&hdr)?;
                s.flush()?;
                if trickle {
                    // One byte per 150 ms - half `request_timeout`, so the
                    // readiness poll is re-armed on every byte and never
                    // fires, while the body needs 9.6 s against a 700 ms
                    // budget.
                    for _ in 0..BODY {
                        if s.write_all(b"x").is_err() || s.flush().is_err() {
                            break; // reaped under us, which is the point
                        }
                        thread::sleep(Duration::from_millis(150));
                    }
                } else {
                    s.write_all(&[b'x'; BODY])?;
                    s.flush()?;
                    // The message is over. Stay quiet for longer than the
                    // budget: a budget left armed reaps this connection.
                    thread::sleep(Duration::from_millis(1200));
                    // Still alive? Then the framing survived too.
                    splice_frame(&mut s, b'C', b"ping")?;
                    assert_eq!(recv_framed(&mut s)?, b"ping");
                    return Ok(());
                }
                let mut sink = [0u8; 64];
                s.set_read_timeout(Some(Duration::from_secs(5)))?;
                match s.read(&mut sink) {
                    Ok(0) => Ok(()),
                    Ok(n) => panic!("answered {n} bytes to a trickled body"),
                    Err(e) if e.kind() == io::ErrorKind::ConnectionReset => {
                        Ok(())
                    }
                    Err(e) => panic!("the slot was never reclaimed: {e}"),
                }
            })();
            stop.shutdown();
            r
        });

        server.serve_forever().expect("serve_forever");
        // SAFETY: the test owns both ends; the server never closes `pipe_wr`.
        unsafe {
            libc::close(pipe_wr);
            libc::close(pipe_rd);
        }
        client.join().expect("thread join").expect("client io");
        let got = reasons.lock().unwrap().clone();
        if trickle {
            assert_eq!(
                got.as_slice(),
                &[CloseReason::ReceiptTimeout],
                "{what}: a spliced body under the floor must read as \
                 ReceiptTimeout - nothing at all means the budget never \
                 armed, since no other clock on this path is a total bound"
            );
        } else {
            assert_eq!(
                got.as_slice(),
                &[CloseReason::PeerClosed],
                "{what}: the budget must be retired when the body completes \
                 - ReceiptTimeout here is a healthy connection reaped for \
                 having finished on time"
            );
        }
    }
}
