use super::*;

const SSL_OP_ENABLE_KTLS: u64 = 1 << 3; // SSL_OP_BIT(3); no named crate const
const BIO_NOCLOSE: libc::c_int = 0;
const SOL_TLS: libc::c_int = 282;
const TLS_TX: libc::c_int = 1;
const TLS_RX: libc::c_int = 2;

/// True when the `kTLS ... TLS ULP` server-bind validation fires - the kernel lacks `CONFIG_TLS`. Force the test on
/// known-good hosts with `TRUENAS_ROS_REQUIRE_KTLS`.
fn ktls_unsupported(e: &Error) -> bool {
    let unsupported = matches!(e, Error::Validation(m) if m.contains("kernel TLS ULP"));
    if unsupported {
        assert!(
            std::env::var_os("TRUENAS_ROS_REQUIRE_KTLS").is_none(),
            "TRUENAS_ROS_REQUIRE_KTLS set but the kernel lacks the tls ULP: {e}"
        );
    }
    unsupported
}

/// True when a `tls` connect fails because this kernel can't furnish the fd (`FIXED_FD_INSTALL`) or run kTLS (the
/// ULP) - the client-side skip for the raw-listener kTLS tests (the echo test skips at the server's bind instead).
fn ktls_connect_unsupported(e: &io::Error) -> bool {
    let unsupported = e.kind() == io::ErrorKind::Unsupported;
    if unsupported {
        assert!(
            std::env::var_os("TRUENAS_ROS_REQUIRE_KTLS").is_none(),
            "TRUENAS_ROS_REQUIRE_KTLS set but kTLS connect unsupported: {e}"
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
    use openssl::x509::{X509, X509NameBuilder};
    let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "localhost").unwrap();
    let name = name.build();
    let mut b = X509::builder().unwrap();
    b.set_version(2).unwrap();
    b.set_subject_name(&name).unwrap();
    b.set_issuer_name(&name).unwrap();
    b.set_pubkey(&key).unwrap();
    b.set_not_before(&Asn1Time::days_from_now(0).unwrap()).unwrap();
    b.set_not_after(&Asn1Time::days_from_now(1).unwrap()).unwrap();
    b.sign(&key, MessageDigest::sha256()).unwrap();
    (b.build().to_pem().unwrap(), key.private_key_to_pem_pkcs8().unwrap())
}

/// Build a [`truenas_ktls::Acceptor`] over a throwaway cert. The acceptor is
/// built from PEM files, read eagerly, so the directory may drop on return;
/// kTLS installation and ticket disablement live inside the crate.
fn ktls_acceptor(cert_pem: &[u8], key_pem: &[u8]) -> Acceptor {
    let dir = truenas_ros::tempdir().unwrap();
    let cert = dir.path().join("cert.pem");
    let key = dir.path().join("key.pem");
    std::fs::write(&cert, cert_pem).unwrap();
    std::fs::write(&key, key_pem).unwrap();
    Acceptor::from_pem_files(&cert, &key).unwrap()
}

/// The server's handshake worker: run the blocking server TLS handshake on the furnished fd through `truenas_ktls` -
/// which installs kernel TLS on the socket and refuses the connection unless the readback shows it engaged both
/// directions - then close the furnished fd (the pool descriptor keeps the kTLS socket).
fn ktls_server_handshake(fd: RawFd, acceptor: &Acceptor) -> Result<(), KtlsProbe> {
    // This worker owns the furnished fd: EVERY return path must close it (the set_tls_handshake contract), or each
    // failed handshake leaks a process fd.
    struct FdCloser(RawFd);
    impl Drop for FdCloser {
        fn drop(&mut self) {
            // SAFETY: closing the furnished fd this guard owns.
            unsafe { libc::close(self.0) };
        }
    }
    let _fd_owner = FdCloser(fd);
    // The handshake wants a blocking socket; io_uring recv/send ignore O_NONBLOCK.
    // SAFETY: fcntl on a live fd.
    unsafe {
        let fl = libc::fcntl(fd, libc::F_GETFL);
        libc::fcntl(fd, libc::F_SETFL, fl & !libc::O_NONBLOCK);
    }
    // SAFETY: `fd` stays open for the borrow - `_fd_owner` closes it only on return.
    let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };
    acceptor.accept(borrowed).map(|_| ()).map_err(KtlsProbe::from)
}

/// Why a probe handshake did not engage kTLS, which is two answers and not one.
///
/// [`KtlsProbe::NotEngaged`] is this **host's** verdict (libssl built without `enable-ktls`, OpenSSL's TLS 1.3 RX gap,
/// no `tls` module), and the data-path tests skip on it. [`KtlsProbe::Broken`] is the probe's own failure, descriptor
/// exhaustion above all, which a soft `NOFILE` of 1024 reaches. Folded into one, an unarmed run would skip silently and
/// an armed one would blame OpenSSL for a failed `dup`.
///
/// `test/support/ktls.rs` gets this split from `truenas_ktls::Error::NotEngaged`. The client half has no such type,
/// since `SSL_connect` and the `SOL_TLS` readback are two questions asked of one `unsafe` block, so it is spelled out
/// here.
#[derive(Debug)]
enum KtlsProbe {
    /// This host cannot engage kTLS.
    NotEngaged(String),
    /// The probe itself failed; nothing about kTLS was measured.
    Broken(String),
}

impl From<truenas_ktls::Error> for KtlsProbe {
    fn from(e: truenas_ktls::Error) -> KtlsProbe {
        match e {
            truenas_ktls::Error::NotEngaged { .. } => KtlsProbe::NotEngaged(e.to_string()),
            other => KtlsProbe::Broken(other.to_string()),
        }
    }
}

impl std::fmt::Display for KtlsProbe {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KtlsProbe::NotEngaged(m) | KtlsProbe::Broken(m) => f.write_str(m),
        }
    }
}

/// A kTLS-enabled OpenSSL client context: `SSL_OP_ENABLE_KTLS` + no cert verification (the server cert is self-signed).
fn ktls_client_ctx() -> SslContext {
    let mut b = SslContext::builder(SslMethod::tls()).unwrap();
    b.set_verify(SslVerifyMode::NONE);
    b.set_options(SslOptions::from_bits_retain(SSL_OP_ENABLE_KTLS));
    b.build()
}

/// The client's handshake worker: run the blocking client TLS handshake (`SSL_connect`) on the furnished fd over a
/// socket BIO (so OpenSSL installs kTLS on the socket), confirm kTLS engaged both directions, then close the furnished
/// fd. The mirror of `ktls_server_handshake`, `SSL_connect` for `SSL_accept` - exactly what a
/// `Client::set_tls_handshake` worker does.
fn ktls_client_handshake(fd: RawFd, ctx: &SslContext) -> Result<(), KtlsProbe> {
    struct FdCloser(RawFd);
    impl Drop for FdCloser {
        fn drop(&mut self) {
            // SAFETY: closing the furnished fd this guard owns.
            unsafe { libc::close(self.0) };
        }
    }
    let _fd_owner = FdCloser(fd);
    // SSL_connect wants a blocking socket; io_uring recv/send ignore O_NONBLOCK.
    // SAFETY: fcntl on a live fd.
    unsafe {
        let fl = libc::fcntl(fd, libc::F_GETFL);
        libc::fcntl(fd, libc::F_SETFL, fl & !libc::O_NONBLOCK);
    }
    let mut ssl = Ssl::new(ctx).map_err(|e| KtlsProbe::Broken(e.to_string()))?;
    ssl.set_connect_state();
    // SAFETY: a BIO_NOCLOSE socket BIO over `fd`; SSL owns the BIO (freed on drop), and `fd` outlives `ssl` here.
    let rc = unsafe {
        let bio = openssl_sys::BIO_new_socket(fd, BIO_NOCLOSE);
        if bio.is_null() {
            return Err(KtlsProbe::Broken("BIO_new_socket".into()));
        }
        openssl_sys::SSL_set_bio(ssl.as_ptr(), bio, bio);
        openssl_sys::SSL_connect(ssl.as_ptr())
    };
    if rc != 1 {
        // The handshake completes even where engagement cannot - the fallback is userspace records - so a failure here
        // is the probe's, not this host's kTLS answer.
        return Err(KtlsProbe::Broken(format!("SSL_connect returned {rc}")));
    }
    confirm_ktls(fd).map_err(KtlsProbe::NotEngaged)?;
    drop(ssl); // BIO_NOCLOSE -> fd not closed; kTLS stays on the socket
    Ok(()) // _fd_owner closes the furnished fd
}

/// Confirm kTLS engaged on `fd` for both directions (the `SOL_TLS` TX/RX getsockopts succeed only once the ULP is
/// installed each way).
fn confirm_ktls(fd: RawFd) -> Result<(), String> {
    for (dir, label) in [(TLS_TX, "TX"), (TLS_RX, "RX")] {
        let mut buf = [0u8; 4];
        let mut len = buf.len() as libc::socklen_t;
        // SAFETY: getsockopt writes up to `len` bytes into `buf`.
        let r = unsafe { libc::getsockopt(fd, SOL_TLS, dir, buf.as_mut_ptr().cast(), &mut len) };
        if r != 0 {
            return Err(format!("kTLS not engaged for {label}"));
        }
    }
    Ok(())
}

/// kTLS installation is best-effort in libssl. A build without `enable-ktls` (Debian and Ubuntu enable it only from
/// 3.2), a TLS 1.3 RX gap (OpenSSL < 3.2), or a kernel missing the `tls` module all fall back to userspace records. The
/// handshake then completes but the acceptor's readback (server side) and `confirm_ktls` (client side) refuse, so the
/// data-path tests would fail rather than skip. Probe once with a loopback handshake, using the same acceptor, client
/// context and confirmation the tests use, so those tests can skip when this host's OpenSSL cannot engage kTLS.
fn ktls_engages() -> &'static Result<(), KtlsProbe> {
    static PROBE: std::sync::OnceLock<Result<(), KtlsProbe>> = std::sync::OnceLock::new();
    PROBE.get_or_init(|| {
        // The probe's own scaffolding panics at source rather than returning: a loopback socket it cannot get is not a
        // kTLS verdict, and `KtlsProbe` exists so nothing downstream has to guess which it was reading
        // (`test/support/ktls.rs` panics here too).
        let (cert, key) = self_signed();
        let acceptor = ktls_acceptor(&cert, &key);
        let listener = TcpListener::bind("127.0.0.1:0").expect("probe bind");
        let addr = listener.local_addr().expect("probe local_addr");
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("probe accept");
            // The handshake helpers own (and close) the fd they are given;
            // hand each a dup and let the `TcpStream`s keep the sockets.
            // SAFETY: dup of a live fd.
            let fd = unsafe { libc::dup(stream.as_raw_fd()) };
            assert!(fd >= 0, "probe dup");
            ktls_server_handshake(fd, &acceptor)
        });
        let stream = TcpStream::connect(addr).expect("probe connect");
        // SAFETY: dup of a live fd (see above).
        let fd = unsafe { libc::dup(stream.as_raw_fd()) };
        assert!(fd >= 0, "probe dup");
        let client = ktls_client_handshake(fd, &ktls_client_ctx());
        if client.is_err() {
            drop(stream); // EOF unblocks a server still mid-handshake
            let _ = server.join();
            return client;
        }
        let served = server.join().expect("probe server thread");
        drop(stream); // keep the socket open until the server side confirmed
        served
    })
}

/// The OpenSSL-side skip for the kTLS data-path tests: `false` when this host engages kTLS end to end, `true` (with a
/// visible note) when it cannot - or a hard failure when `TRUENAS_ROS_REQUIRE_KTLS` says skipping is forbidden.
fn ktls_openssl_unsupported() -> bool {
    match ktls_engages() {
        Ok(()) => false,
        Err(KtlsProbe::NotEngaged(e)) => {
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
        // Not a verdict about this host's kTLS, so neither skipping nor blaming OpenSSL for it is honest.
        Err(KtlsProbe::Broken(e)) => {
            panic!("kTLS probe failed before it could measure engagement: {e}")
        }
    }
}

/// Bind a kTLS `net::server` echo server whose handshake worker drives `truenas_ktls`, run `client` on a spawned thread
/// against its resolved address, and propagate the client's result. The kTLS mirror of [`with_server`]; skips cleanly
/// when io_uring, the kernel TLS ULP, or OpenSSL-side kTLS is unavailable.
fn with_ktls_server<ClientBody>(client: ClientBody)
where
    ClientBody: FnOnce(SocketAddrV4) -> io::Result<()> + Send + 'static,
{
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
        |_h: &[u8], body: &[u8], _p: &ClientAddr| Some(frame(body)),
    );
    let mut server = match Server::bind([Listen::tls(addr)], proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) || ktls_unsupported(&e) => return,
        Err(e) => panic!("bind: {e}"),
    };
    server.set_tls_handshake(move |fd, _inc, deferral| {
        let acceptor = Arc::clone(&acceptor);
        thread::spawn(move || match ktls_server_handshake(fd, &acceptor) {
            Ok(()) => deferral.ready(()),
            Err(_) => deferral.reject(),
        });
    });
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();
    let handle = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone()); // shuts down even on panic
        let r = client(v4);
        stop.shutdown();
        r
    });
    server.serve_forever().expect("serve_forever");
    handle.join().expect("client thread join").expect("client body");
}

/// Build a `Client` with a `set_tls_handshake` worker that runs `SSL_connect` (the mirror of the server's `SSL_accept`
/// worker), over the given framer.
fn ktls_client<U, F>(framer: F) -> io::Result<Client<U, F>>
where
    F: FnMut(&[u8], &mut U) -> Framing,
{
    let ctx = Arc::new(ktls_client_ctx());
    // A kTLS body splice is refused without a response clock (`CloseReason::SpliceUnbounded`): it blocks an io-wq
    // worker awaiting the next TLS record, where no linked timeout reaches it, so the standalone watchdog this maps to
    // is its only bound. Generous - none of these tests stall.
    let cfg = ClientConfig {
        response_timeout: Some(Duration::from_secs(10)),
        ..ClientConfig::default()
    };
    let mut client = Client::new(cfg, framer).map_err(to_io)?;
    client.set_tls_handshake(move |fd, _c, deferral| {
        let ctx = Arc::clone(&ctx);
        thread::spawn(move || match ktls_client_handshake(fd, &ctx) {
            Ok(()) => deferral.ready(),
            Err(_) => deferral.reject(),
        });
    });
    Ok(client)
}

#[test]
fn ktls_echo_roundtrip() {
    // End-to-end: a kTLS listener, both sides' OpenSSL handshake workers (`SSL_accept` server-side, `SSL_connect` in
    // the client's worker), and a framed echo round-trip over the kernel-TLS transport (each side sees plaintext; the
    // kernel encrypts/decrypts).
    with_ktls_server(|v4| {
        let mut client = ktls_client(client_framer())?;
        // A blocking connect resolves only once the kTLS handshake completes.
        let conn = client.connect(ServerAddr::Tcp(v4), ConnectOpts::default().tls())?;
        for msg in [b"tls-hello".as_slice(), b"second", b"third-and-final"] {
            let body = client.request(conn, frame(msg))?;
            assert_eq!(&body[..], msg, "kTLS echo mismatch");
        }
        // A larger payload spanning multiple TLS records still frames.
        let big = vec![0x5au8; 40 * 1024];
        let body = client.request(conn, frame(&big))?;
        assert_eq!(&body[..], &big[..], "kTLS large echo mismatch");
        client.close_now(conn);
        Ok(())
    });
}

#[test]
fn ktls_rejected_handshake() {
    // The client's handshake worker calls `reject()` -> `Event::ConnectFailed`. A raw TCP peer suffices (the reject is
    // client-local): the TCP connect completes, the fd is furnished, and the worker rejects.
    let mut client = match Client::new(ClientConfig::default(), client_framer()) {
        Ok(c) => c,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("client new: {e}"),
    };
    client.set_tls_handshake(|fd, _c, deferral| {
        thread::spawn(move || {
            // SAFETY: close the furnished fd we won't use, then reject.
            unsafe { libc::close(fd) };
            deferral.reject();
        });
    });

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let SocketAddr::V4(v4) = listener.local_addr().unwrap() else {
        unreachable!("bound v4");
    };
    let server = thread::spawn(move || {
        if let Ok((stream, _)) = listener.accept() {
            thread::sleep(Duration::from_millis(500));
            drop(stream);
        }
        drop(listener);
    });

    let conn = match client.connect_start(ServerAddr::Tcp(v4), ConnectOpts::default().tls()) {
        Ok(c) => c,
        Err(e) if ktls_connect_unsupported(&e) => {
            // Unblock the helper's accept() so the join below returns.
            let _ = TcpStream::connect(v4);
            server.join().ok();
            return;
        }
        Err(e) => panic!("connect_start: {e}"),
    };
    match client.next_event().expect("next_event") {
        Some(Event::ConnectFailed { conn: c, err }) => {
            assert_eq!(c, conn, "ConnectFailed for the wrong connection");
            assert_eq!(err, Errno::ECONNABORTED, "a rejected handshake fails with ECONNABORTED");
        }
        other => panic!("expected ConnectFailed, got {other:?}"),
    }
    assert!(!client.is_open(conn), "a rejected connect is not open");
    server.join().ok();
}

/// The client-side twin of the server's key readback: a worker's `ready()` on a socket the kernel never keyed fails the
/// connect rather than installing a "kTLS" connection the kernel is passing through in the clear. A raw TCP peer
/// suffices: the TCP connect completes, the fd is furnished, and the worker claims success without a handshake.
#[test]
fn ktls_ready_without_kernel_keys_fails_the_connect() {
    let mut client = match Client::new(ClientConfig::default(), client_framer()) {
        Ok(c) => c,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("client new: {e}"),
    };
    client.set_tls_handshake(|fd, _c, deferral| {
        thread::spawn(move || {
            // SAFETY: close the furnished fd we won't use; the readback rides the deferral's own dup, not a number that
            // may be reused.
            unsafe { libc::close(fd) };
            deferral.ready();
        });
    });

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let SocketAddr::V4(v4) = listener.local_addr().unwrap() else {
        unreachable!("bound v4");
    };
    let server = thread::spawn(move || {
        if let Ok((stream, _)) = listener.accept() {
            thread::sleep(Duration::from_millis(500));
            drop(stream);
        }
        drop(listener);
    });

    let conn = match client.connect_start(ServerAddr::Tcp(v4), ConnectOpts::default().tls()) {
        Ok(c) => c,
        Err(e) if ktls_connect_unsupported(&e) => {
            // Unblock the helper's accept() so the join below returns.
            let _ = TcpStream::connect(v4);
            server.join().ok();
            return;
        }
        Err(e) => panic!("connect_start: {e}"),
    };
    match client.next_event().expect("next_event") {
        Some(Event::ConnectFailed { conn: c, err }) => {
            assert_eq!(c, conn, "ConnectFailed for the wrong connection");
            assert_eq!(err, Errno::ECONNABORTED, "an unkeyed ready() fails the connect");
        }
        other => panic!("a ready() with no kernel keys installed a connection: {other:?}"),
    }
    assert!(!client.is_open(conn), "an unkeyed connect is not open");
    server.join().ok();
}

#[test]
fn ktls_handshake_timeout() {
    // The worker never calls back (it holds the deferral): the client's `tls_handshake_timeout` fires ->
    // `ConnectFailed{ETIMEDOUT}`, and the parked slot is reclaimed (a later `next_event` finds no work left).
    let cfg = ClientConfig {
        tls_handshake_timeout: Some(Duration::from_millis(250)),
        ..ClientConfig::default()
    };
    let mut client = match Client::new(cfg, client_framer()) {
        Ok(c) => c,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("client new: {e}"),
    };
    // Buffer the deferral (never resolving -> no reject-shed) and close the fd;
    // only the timeout can reclaim the parked slot. Released when keep_rx drops.
    let (keep_tx, keep_rx) = std::sync::mpsc::channel();
    client.set_tls_handshake(move |fd, _c, deferral| {
        // SAFETY: close the furnished fd this worker won't use.
        unsafe { libc::close(fd) };
        let _ = keep_tx.send(deferral);
    });

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let SocketAddr::V4(v4) = listener.local_addr().unwrap() else {
        unreachable!("bound v4");
    };
    let server = thread::spawn(move || {
        if let Ok((stream, _)) = listener.accept() {
            thread::sleep(Duration::from_secs(2));
            drop(stream);
        }
        drop(listener);
    });

    let conn = match client.connect_start(ServerAddr::Tcp(v4), ConnectOpts::default().tls()) {
        Ok(c) => c,
        Err(e) if ktls_connect_unsupported(&e) => {
            // Unblock the helper's accept() so the join below returns.
            let _ = TcpStream::connect(v4);
            server.join().ok();
            return;
        }
        Err(e) => panic!("connect_start: {e}"),
    };
    let t0 = Instant::now();
    match client.next_event().expect("next_event") {
        Some(Event::ConnectFailed { conn: c, err }) => {
            assert_eq!(c, conn);
            assert_eq!(err, Errno::ETIMEDOUT, "a stalled handshake times out with ETIMEDOUT");
        }
        other => panic!("expected ConnectFailed(ETIMEDOUT), got {other:?}"),
    }
    assert!(
        t0.elapsed() < Duration::from_secs(2),
        "handshake timeout fired late: {:?}",
        t0.elapsed()
    );
    assert!(!client.is_open(conn), "the parked slot was reclaimed");
    // With the parked handshake shed and no connections, the next event is `None` - the leftover armed wake never
    // wedges it.
    assert!(
        client.next_event().expect("drain").is_none(),
        "no work left after the timeout shed"
    );
    drop(keep_rx); // release the held (now stale) deferral
    server.join().ok();
}

#[test]
fn ktls_splice_body() {
    // A reply body splices zero-copy off a kTLS socket, in the clear: the kernel routes the splice through
    // `tls_sw_splice_read`, which decrypts. Same shape as `tcp_splice_body`, but over the kernel-TLS transport.
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: `pipe(2)` fills {read, write}.
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe");
    let (pipe_rd, pipe_wr) = (fds[0], fds[1]);

    // Not a multiple of the 16 KiB TLS record size, and several pipe capacities.
    const BODY: usize = 200_000;
    let payload: Vec<u8> = (0..BODY).map(|i| (i % 251) as u8).collect();
    let expected = payload.clone();

    // The same reader as `tcp_splice_body`. Its EOF arm ends a kTLS skip, where nothing is spliced, at the main
    // thread's close below.
    let reader = thread::spawn(move || {
        let mut got = vec![0u8; BODY];
        let mut off = 0;
        while off < BODY {
            // SAFETY: read into `got[off..]`, within bounds.
            let n = unsafe { libc::read(pipe_rd, got.as_mut_ptr().add(off).cast(), (BODY - off) as libc::size_t) };
            if n == 0 {
                break; // write end closed: nothing more is coming
            }
            assert!(n > 0, "pipe read: {}", std::io::Error::last_os_error());
            off += n as usize;
        }
        // SAFETY: done with the read end.
        unsafe { libc::close(pipe_rd) };
        (off, got)
    });

    // The skip is decided at the server bind inside `with_ktls_server`. On a skip the client body never runs, which
    // `ran` records, and the reader ends at the EOF below.
    let ran = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let ran_in = Arc::clone(&ran);
    with_ktls_server(move |v4| {
        ran_in.store(true, std::sync::atomic::Ordering::SeqCst);
        let mut client = ktls_client(splice_framer())?;
        let conn = client.connect_with_state(ServerAddr::Tcp(v4), ConnectOpts::default().tls(), pipe_wr)?;
        let id = client.send(conn, frame(&payload))?;
        match client.next_event()? {
            Some(Event::Splice {
                conn: c,
                id: rid,
                body_len,
                ..
            }) => {
                assert_eq!(c, conn);
                assert_eq!(rid, id);
                assert_eq!(body_len, BODY, "kTLS spliced body length");
            }
            other => {
                return Err(io::Error::other(format!("expected Splice over kTLS, got {other:?}")));
            }
        }
        client.close_now(conn);
        Ok(())
    });

    // Before the join, not after: this close is the reader's EOF.
    // SAFETY: closing the test-owned write end (read end closed by the reader).
    unsafe { libc::close(pipe_wr) };
    let (off, got) = reader.join().expect("reader join");
    // Assert only when the client body ran. `off > 0` does not prove a splice happened, since one aimed at the wrong
    // sink completes and reports the declared length with this pipe empty.
    if ran.load(std::sync::atomic::Ordering::SeqCst) {
        assert_eq!(off, BODY, "kTLS splice moved {off} of {BODY} body bytes");
        assert_eq!(got, expected, "kTLS spliced body content mismatch");
    }
}
