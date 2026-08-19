//! Kernel-TLS (kTLS) scaffolding shared by the live test targets
//! (`test/net_server.rs`, `test/http_live.rs`): a real end-to-end TLS
//! handshake around the server's kernel-TLS transport. The library brings no
//! TLS crate; the handshake worker drives `truenas_ktls` - the packaged
//! accept side: a blocking handshake that installs kernel TLS and refuses
//! the connection unless the readback shows it engaged both directions - and
//! the client is OpenSSL, exactly the split a real consumer implements.
//! Tests skip when the kernel lacks the `tls` ULP ([`ktls_unsupported`]) or
//! when libssl cannot engage kTLS at all ([`ktls_openssl_unsupported`] --
//! Ubuntu ships OpenSSL 3.0 without `enable-ktls`); either skip turns into a
//! hard failure under `TRUENAS_ROS_REQUIRE_KTLS`.

use std::io;
use std::net::{SocketAddrV4, TcpListener, TcpStream};
use std::os::fd::{AsRawFd, BorrowedFd, RawFd};
use std::thread;
use std::time::Duration;

use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use truenas_ktls::Acceptor;
use truenas_ros::Error;

/// True when the `kTLS listener requires ... TLS ULP` validation fires - the
/// dev kernel lacks `CONFIG_TLS`. Force the test on known-good hosts with
/// `TRUENAS_ROS_REQUIRE_KTLS`.
pub fn ktls_unsupported(e: &Error) -> bool {
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
pub fn self_signed() -> (Vec<u8>, Vec<u8>) {
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

/// Build a [`truenas_ktls::Acceptor`] over a throwaway cert. The acceptor is
/// built from PEM files, read eagerly, so the directory may drop on return;
/// kTLS installation and ticket disablement live inside the crate.
pub fn ktls_acceptor(cert_pem: &[u8], key_pem: &[u8]) -> Acceptor {
    let dir = truenas_ros::tempdir().unwrap();
    let cert = dir.path().join("cert.pem");
    let key = dir.path().join("key.pem");
    std::fs::write(&cert, cert_pem).unwrap();
    std::fs::write(&key, key_pem).unwrap();
    Acceptor::from_pem_files(&cert, &key).unwrap()
}

/// The consumer's handshake worker: run the blocking server TLS handshake on
/// the furnished fd through `truenas_ktls` - which installs kernel TLS on the
/// socket and refuses the connection unless the readback shows it engaged
/// both directions - then close the furnished fd (the pool descriptor keeps
/// the kTLS socket).
pub fn ktls_server_handshake(
    fd: RawFd,
    acceptor: &Acceptor,
) -> Result<(), truenas_ktls::Error> {
    // This helper owns the furnished fd: EVERY return path must close it (the
    // set_tls_handshake contract), or each failed handshake leaks a process
    // fd that pins the socket past the server's teardown. The acceptor only
    // borrows the descriptor; this guard closes it, and the pool descriptor
    // keeps the kTLS socket alive for serving.
    struct FdCloser(RawFd);
    impl Drop for FdCloser {
        fn drop(&mut self) {
            // SAFETY: closing the furnished fd this guard owns.
            unsafe { libc::close(self.0) };
        }
    }
    let _fd_owner = FdCloser(fd);
    // The handshake wants a blocking socket. The furnished fd aliases the pool
    // descriptor's file, but io_uring recv/send are unaffected by O_NONBLOCK.
    // SAFETY: fcntl on a live fd.
    unsafe {
        let fl = libc::fcntl(fd, libc::F_GETFL);
        libc::fcntl(fd, libc::F_SETFL, fl & !libc::O_NONBLOCK);
    }
    // SAFETY: `fd` stays open for the borrow - `_fd_owner` closes it only on
    // return.
    let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };
    acceptor.accept(borrowed).map(|_| ())
}

/// A TLS client that connects (retrying while the server thread starts up),
/// handshakes (no cert verification - the server cert is self-signed), and
/// returns the `SslStream` for framed I/O.
pub fn tls_connect(
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

/// Connect with a ~1s retry (the server thread may still be binding) and a
/// read timeout so a wedged test goes red instead of hanging the binary.
fn connect_tcp(addr: SocketAddrV4) -> io::Result<TcpStream> {
    let mut last = None;
    for _ in 0..50 {
        match TcpStream::connect(addr) {
            Ok(s) => {
                s.set_read_timeout(Some(Duration::from_secs(10)))?;
                return Ok(s);
            }
            Err(e) => {
                last = Some(e);
                thread::sleep(Duration::from_millis(20));
            }
        }
    }
    Err(last.expect("at least one attempt"))
}

/// kTLS installation is best-effort in libssl: a build without `enable-ktls`
/// (Debian/Ubuntu only enable it from 3.2), a TLS 1.3 RX gap (OpenSSL < 3.2),
/// or a kernel missing the `tls` module all fall back to userspace records.
/// The handshake then completes, the acceptor's readback refuses the
/// connection, the worker rejects, and the kTLS data-path tests would fail
/// rather than skip. Probe once with a loopback handshake - the same
/// acceptor, client, and refusal the tests use - so those tests can skip
/// when this host cannot engage kTLS.
fn ktls_engages() -> &'static Result<(), truenas_ktls::Error> {
    static PROBE: std::sync::OnceLock<Result<(), truenas_ktls::Error>> =
        std::sync::OnceLock::new();
    PROBE.get_or_init(|| {
        let (cert, key) = self_signed();
        let acceptor = ktls_acceptor(&cert, &key);
        let listener = TcpListener::bind("127.0.0.1:0").expect("probe bind");
        let std::net::SocketAddr::V4(v4) =
            listener.local_addr().expect("probe local_addr")
        else {
            panic!("bound v4");
        };
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("probe accept");
            // `ktls_server_handshake` owns (and closes) the fd it is given;
            // hand it a dup and let the `TcpStream` keep the socket.
            // SAFETY: dup of a live fd.
            let fd = unsafe { libc::dup(stream.as_raw_fd()) };
            assert!(fd >= 0, "dup");
            ktls_server_handshake(fd, &acceptor)
        });
        // The handshake completes even where engagement cannot (the fallback
        // is userspace records; the refusal is the acceptor's, on readback),
        // so a client-side failure is the probe's own fault and panics.
        let stream = tls_connect(v4).expect("probe client handshake");
        let served = server.join().expect("probe server thread");
        drop(stream); // keep the session open until the server confirmed
        served
    })
}

/// The engagement skip for the kTLS data-path tests: `false` when this host
/// engages kTLS end to end, `true` (with a visible note) when the acceptor
/// refused an unengaged connection - or a hard failure when
/// `TRUENAS_ROS_REQUIRE_KTLS` says skipping is forbidden. Any probe failure
/// other than that refusal is the suite's own and panics.
pub fn ktls_openssl_unsupported() -> bool {
    match ktls_engages() {
        Ok(()) => false,
        Err(e @ truenas_ktls::Error::NotEngaged { .. }) => {
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
        Err(e) => panic!("kTLS probe failed before engagement: {e}"),
    }
}
