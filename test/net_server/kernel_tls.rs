use super::*;

#[test]
fn ktls_echo_roundtrip() {
    // A kTLS listener, the consumer's OpenSSL handshake worker and a real TLS client. The kernel decrypts, so the
    // server sees plaintext and the framer is unchanged.
    use std::sync::Mutex;
    if ktls_openssl_unsupported() {
        return;
    }
    let (cert, key) = self_signed();
    let acceptor = Arc::new(ktls_acceptor(&cert, &key));
    let seen_listener: Arc<Mutex<Option<ServerAddr>>> = Arc::new(Mutex::new(None));
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let proto = length_prefixed(
        PrefixWidth::U32,
        Endian::Big,
        false,
        |_h: &[u8], body: &[u8], _p: &ClientAddr| Some(echo_frame(body)),
    );
    let mut server = match Server::bind([truenas_ros::net::server::Listen::tls(addr)], proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) || ktls_unsupported(&e) => return,
        Err(e) => panic!("bind: {e}"),
    };
    {
        let acceptor = Arc::clone(&acceptor);
        let seen = Arc::clone(&seen_listener);
        server.set_tls_handshake(move |fd, inc, deferral| {
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
            for msg in [b"tls-hello".as_slice(), b"second", b"third-and-final"] {
                send_framed(&mut s, msg)?;
                assert_eq!(recv_framed(&mut s)?, msg, "kTLS echo mismatch");
            }
            // 512 KiB spans many records and exceeds the default `recv_buffer_bytes`, so the body is placed, the arm
            // the kTLS continuation's bound has to follow.
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
    // A handshake that fails (the client speaks plaintext, not TLS) must reject cleanly - the worker calls
    // deferral.reject(), the slot is shed - and the server keeps serving later TLS connections.
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
    let mut server = match Server::bind([truenas_ros::net::server::Listen::tls(addr)], proto) {
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
    // The client read the rejected connection to EOF (the shed's FIN) before its real TLS roundtrip, so the reject-shed
    // is already counted here.
    assert!(
        stats.snapshot().shed >= 1,
        "the rejected handshake should be shed (shed={})",
        stats.snapshot().shed
    );
}

/// A worker's `ready()` alone does not make a socket encrypted. The deferral reads the kernel's key state back
/// (`getsockopt(SOL_TLS, TLS_TX/TLS_RX)`) and sheds a connection whose keys the kernel does not hold, so a hook that
/// never ran a handshake cannot have plaintext framed as TLS.
#[test]
fn ktls_ready_without_kernel_keys_is_shed() {
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let proto = length_prefixed(
        PrefixWidth::U32,
        Endian::Big,
        false,
        |_h: &[u8], body: &[u8], _p: &ClientAddr| Some(echo_frame(body)),
    );
    let mut server = match Server::bind([truenas_ros::net::server::Listen::tls(addr)], proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) || ktls_unsupported(&e) => return,
        Err(e) => panic!("bind: {e}"),
    };
    server.set_tls_handshake(move |fd, _inc, deferral| {
        thread::spawn(move || {
            // No handshake at all: claim success on an untouched TCP socket. The furnished fd is closed first, as a
            // worker done with it would - the readback rides the deferral's own dup, not a number that may be reused.
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
                Ok(_) => panic!("a ready() with no kernel keys was served in the clear"),
                Err(e) if matches!(e.kind(), io::ErrorKind::ConnectionReset | io::ErrorKind::UnexpectedEof) => Ok(()),
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
/// Stopping the reactor reaps outstanding completions rather than dispatching them, so a recv the kernel already chose
/// a provided buffer for is drained without adopting it. The kernel's consumer head and this side's posted count then
/// legitimately disagree at teardown, and `Server` drains from `Drop`, where a drain-time equality check between them
/// would abort the process on a correct path.
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
        let _stop = ShutdownOnDrop(stop.clone()); // fail fast on panic
        // One full round trip first, so the fixture is known to have been accepted and served before anything races -
        // the shutdown below is deliberately concurrent and would otherwise be free to win before the first accept.
        let mut first = connect_tcp(v4).expect("connect");
        send_framed(&mut first, b"warmup").expect("send");
        assert_eq!(recv_framed(&mut first).expect("echo"), b"warmup");

        // Then several connections delivering at the moment the reactor stops, so a recv completes with a buffer
        // already selected and is reaped rather than dispatched.
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

/// Half a handshake is not a handshake. A socket keyed in only **one** direction passes the other direction's bytes in
/// the clear, so `ready()` sheds it as it sheds an unkeyed one.
///
/// A predicate that ORs the two directions instead of ANDing them still passes `ktls_ready_without_kernel_keys_is_shed`
/// while admitting this one. The hook installs the RX key only, leaving `tx_conf` at `TLS_BASE`, the shape a handshake
/// library with a TLS 1.3 RX/TX gap produces.
#[test]
fn ktls_ready_with_only_one_direction_keyed_is_shed() {
    const SOL_TLS: libc::c_int = 282;
    const TLS_RX: libc::c_int = 2;
    const TCP_ULP: libc::c_int = 31;
    // `struct tls12_crypto_info_aes_gcm_128`. The contents do not matter - only that the kernel accepts them and sets
    // `crypto_recv.info`.
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
    let mut server = match Server::bind([truenas_ros::net::server::Listen::tls(addr)], proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) || ktls_unsupported(&e) => return,
        Err(e) => panic!("bind: {e}"),
    };
    server.set_tls_handshake(move |fd, _inc, deferral| {
        thread::spawn(move || {
            // Attach the ULP and key RX only, so everything the server sends goes out in the clear.
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
            // SAFETY: the furnished fd is the worker's to close. The readback rides the deferral's own dup.
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
                // WouldBlock is tolerated because an admitted half-keyed connection answers nothing either - the read
                // alone cannot separate the two. The stats assertion below is what does.
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
    // Shed, not installed-then-closed: under an OR predicate the connection is admitted, so `shed` stays 0 and the
    // teardown counts as `closed`.
    assert!(s.shed >= 1, "the half-keyed connection was shed: {s:?}");
    assert_eq!(s.replies, 0, "and nothing was answered: {s:?}");
}

#[test]
fn ktls_handshake_timeout_sheds_parked_slot() {
    // A kTLS connection whose handshake never completes parks a slot with no recv or send in flight, so neither
    // `idle_timeout` nor `request_timeout` reaches it, and `tls_handshake_timeout` must shed it. The handler closes the
    // fd and holds the deferral unresolved, so only the timeout can reclaim the slot.
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
    let mut server = match Server::with_config([truenas_ros::net::server::Listen::tls(addr)], cfg, proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) || ktls_unsupported(&e) => return,
        Err(e) => panic!("bind: {e}"),
    };
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
        let peers: Vec<_> = (0..3).map(|_| connect_tcp(v4).expect("connect")).collect();
        let t0 = Instant::now();
        while stats.snapshot().shed < 3 && t0.elapsed() < Duration::from_secs(3) {
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
    // A polite TLS client ends its session with close_notify - on the wire a 2-byte alert record. The server's parked
    // exact header read completes SHORT with record type 21 (alert), which must classify as TlsControl -- the
    // documented reason for a peer's clean TLS close - not as TruncatedMessage.
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
    let mut server = match Server::bind([truenas_ros::net::server::Listen::tls(addr)], proto) {
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
            // Clean TLS teardown: the close_notify lands on the server's idle header read.
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

/// A peer's TLS 1.3 KeyUpdate closes the connection as `TlsControl`, and the request behind it is not answered.
///
/// Unlike an alert, which completes the parked idle read short (`on_recv_complete`'s `ktls_control_record` arm), a
/// KeyUpdate arrives mid-conversation with a request queued behind it. The kernel does not absorb an RX KeyUpdate for
/// the server, so the record reaches the reactor, and a change that starts handling rekey or reclassifies the record
/// goes red here.
#[test]
fn ktls_peer_key_update_closes_as_tls_control() {
    use foreign_types::ForeignTypeRef;
    use std::sync::Mutex;
    // Not bound by the `openssl` crate (nor by `openssl-sys`), so declare the two libssl entry points this needs.
    unsafe extern "C" {
        fn SSL_key_update(ssl: *mut openssl_sys::SSL, updatetype: std::os::raw::c_int) -> std::os::raw::c_int;
        fn SSL_do_handshake(ssl: *mut openssl_sys::SSL) -> std::os::raw::c_int;
    }
    const SSL_KEY_UPDATE_NOT_REQUESTED: std::os::raw::c_int = 0;

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
    let mut server = match Server::bind([truenas_ros::net::server::Listen::tls(addr)], proto) {
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
    let answered = Arc::new(Mutex::new(None::<bool>));
    let answered2 = Arc::clone(&answered);

    let client = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone());
        let mut s = tls_connect(v4).expect("tls connect");
        assert_eq!(s.ssl().version_str(), "TLSv1.3", "KeyUpdate is a TLS 1.3 message");
        // The control: the connection serves normally before the rekey, so a failure after it is the rekey and not the
        // fixture.
        send_framed(&mut s, b"before-rekey").expect("send 1");
        assert_eq!(recv_framed(&mut s).expect("recv 1"), b"before-rekey");

        // Post-handshake KeyUpdate, flushed immediately.
        assert_eq!(
            unsafe { SSL_key_update(s.ssl().as_ptr(), SSL_KEY_UPDATE_NOT_REQUESTED) },
            1,
            "SSL_key_update"
        );
        assert_eq!(unsafe { SSL_do_handshake(s.ssl().as_ptr()) }, 1, "flush the KeyUpdate");

        // The request behind it rides the new keys. The server has already closed on the control record, so it is never
        // answered.
        let _ = send_framed(&mut s, b"after-rekey");
        *answered2.lock().unwrap() = Some(recv_framed(&mut s).is_ok());
        thread::sleep(Duration::from_millis(150));
        stop.shutdown();
    });

    server.serve_forever().expect("serve_forever");
    client.join().expect("thread join");
    let got = reasons.lock().unwrap().clone();
    assert!(
        got.contains(&CloseReason::TlsControl),
        "a peer KeyUpdate must report TlsControl, got {got:?}"
    );
    assert!(
        !got.contains(&CloseReason::TruncatedMessage),
        "a rekey misread as truncation: {got:?}"
    );
    assert_eq!(
        *answered.lock().unwrap(),
        Some(false),
        "the request behind a KeyUpdate is not answered"
    );
}

/// SECURITY: a kTLS body splice with no `request_timeout` is refused.
///
/// That clock is the **only** bound one has, since `tls_sw_splice_read` blocks an io-wq worker that no linked timeout
/// can reach, the kernel arming one only after the head op's `issue()` returns. Unset, a silent peer holds its slot, an
/// io-wq worker and its pipe's mutex indefinitely. Plain TCP is not refused, since its `-EAGAIN` readiness-poll path is
/// already clocked, and `tcp_splice_body_recv` splices there with no `request_timeout`.
#[test]
fn ktls_splice_body_without_a_clock_is_refused() {
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
    let close_pipe = move || {
        // SAFETY: closing the test-owned pipe fds.
        unsafe {
            libc::close(pipe_rd);
            libc::close(pipe_wr);
        }
    };

    let reasons = Arc::new(Mutex::new(Vec::new()));
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: splice_header(pipe_wr),
        body: |req: Request<'_, ()>| Response::Reply(echo_frame(&req.body)),
    };
    // No `request_timeout`, which is the default.
    let mut server = match Server::bind([truenas_ros::net::server::Listen::tls(addr)], proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) || ktls_unsupported(&e) => {
            close_pipe();
            return;
        }
        Err(e) => panic!("bind: {e}"),
    };
    {
        let seen = Arc::clone(&reasons);
        server.set_close_hook(move |_peer, why, _state: &mut ()| {
            seen.lock().unwrap().push(why);
        });
    }
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

    let client = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone()); // fail fast on panic
        (|| -> io::Result<()> {
            let mut s = tls_connect(v4)?;
            let mut hdr = vec![b'S'];
            hdr.extend_from_slice(&(1024u32 * 1024).to_be_bytes());
            s.write_all(&hdr)?;
            s.flush()?;
            let mut one = [0u8; 1];
            match s.read(&mut one) {
                Ok(0) | Err(_) => {}
                Ok(n) => panic!("unexpected {n} byte(s) on a refused body"),
            }
            Ok(())
        })()
        .expect("client io");
        stop.shutdown();
    });

    server.serve_forever().expect("serve_forever");
    client.join().expect("client join");
    assert!(
        reasons.lock().unwrap().contains(&CloseReason::SpliceUnbounded),
        "an unbounded kTLS splice must be refused, got {:?}",
        reasons.lock().unwrap()
    );
    close_pipe();
}

#[test]
fn tcp_splice_body_over_ktls() {
    // A body splices zero-copy off a software kTLS socket in the clear, since `tls_sw_splice_read` decrypts. A 5-byte
    // header read inside a record that also carries body leaves the record's plaintext remainder in the kernel's
    // receive list, and the splice must take it before the next record or it truncates, so the client writes header and
    // body as one buffer.
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
    // Required for a kTLS splice (`CloseReason::SpliceUnbounded`), and generous, since nothing here stalls.
    let cfg = ServerConfig {
        request_timeout: Some(Duration::from_secs(10)),
        ..ServerConfig::default()
    };
    let mut server = match Server::with_config([truenas_ros::net::server::Listen::tls(addr)], cfg, proto) {
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

    // Bounded reader: drain up to BODY bytes off the pipe with a deadline (so a truncating splice fails the assertion
    // instead of hanging).
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
            let n = unsafe { libc::read(pipe_rd, got.as_mut_ptr().add(off).cast(), (BODY - off) as libc::size_t) };
            if n > 0 {
                off += n as usize;
            } else {
                thread::sleep(Duration::from_millis(5));
            }
        }
        // SAFETY: done with the read end.
        unsafe { libc::close(pipe_rd) };
        // Graceful (not hard) shutdown so the now-idle connection is closed with a FIN, unblocking the client's read
        // promptly instead of leaving it on its socket read-timeout.
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
            // Keep the connection open through the splice; unblocks when the reader triggers the graceful shutdown and
            // the server closes us.
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
    // A kTLS splice that keeps making progress, however slowly and across several `request_timeout` periods, must run
    // to completion. The watchdog re-arms whenever `splice_remaining` falls below its watermark and cancels only on a
    // full period with no progress.
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
    let mut server = match Server::with_config([truenas_ros::net::server::Listen::tls(addr)], cfg, proto) {
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

    // Six chunks fed ~120ms apart (< the 200ms timeout, so never a full idle period), total wall time ~720ms = 3.6
    // timeout periods. A total-transfer bound would kill this; the inactivity watchdog must not.
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
            let n = unsafe { libc::read(pipe_rd, got.as_mut_ptr().add(off).cast(), (BODY - off) as libc::size_t) };
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
    assert_eq!(off, BODY, "slow-but-progressing splice was cut short at {off}");
    assert_eq!(got, expected, "spliced body content mismatch");
    assert!(
        !reasons.lock().unwrap().contains(&CloseReason::RequestTimeout),
        "a progressing transfer was wrongly reclaimed: {:?}",
        reasons.lock().unwrap()
    );
    // SAFETY: closing the test-owned write end (read end closed by the reader).
    unsafe { libc::close(pipe_wr) };
}

#[test]
fn ktls_splice_body_stall_reclaimed() {
    // `tls_sw_splice_read` honors only `SPLICE_F_NONBLOCK`, not the socket's O_NONBLOCK as `tcp_splice_read` does, so
    // the readiness-poll path that carries the request clock never runs and the clock is linked to the kTLS splice
    // itself. A peer that sends a `SpliceBody` header and goes silent must be reclaimed by `request_timeout`.
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
    let mut server = match Server::with_config([truenas_ros::net::server::Listen::tls(addr)], cfg, proto) {
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
            // SpliceBody header declaring 1 MiB, then silence: the kTLS splice blocks awaiting a record; only its
            // linked clock can reclaim the slot.
            let mut hdr = vec![b'S'];
            hdr.extend_from_slice(&(1024u32 * 1024).to_be_bytes());
            s.write_all(&hdr)?;
            s.flush()?;
            let t0 = Instant::now();
            let mut one = [0u8; 1];
            // Server closes us at the clock: EOF, reset, or a TLS-layer error - anything but a hang (the underlying
            // socket carries a 10s read timeout that would surface as an error here).
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
        reasons.lock().unwrap().contains(&CloseReason::RequestTimeout),
        "stalled kTLS splice must close as RequestTimeout, got {:?}",
        reasons.lock().unwrap()
    );
    // SAFETY: closing the test-owned pipe fds (nothing was spliced).
    unsafe {
        libc::close(pipe_rd);
        libc::close(pipe_wr);
    }
}
