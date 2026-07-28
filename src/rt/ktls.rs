//! [`KtlsStream`]: kernel TLS as a plain tokio byte stream.
//!
//! After a userspace TLS handshake installs kernel TLS on a socket
//! (`SOL_TLS` `TLS_TX`/`TLS_RX` — OpenSSL's `SSL_OP_ENABLE_KTLS` does this
//! itself when it handshakes over a real socket BIO), the kernel encrypts
//! on write and decrypts on read: plain syscalls carry plaintext, and
//! anything speaking `AsyncRead + AsyncWrite` — tungstenite, a
//! `FrameReader`, a copy loop — layers straight on top. This type is that
//! adapter: readiness via tokio's `AsyncFd`, reads via `recvmsg` with a
//! control buffer (the one kTLS subtlety — a plain `read` fails `-EIO` on
//! any non-data TLS record, so the record type must be read from the
//! `TLS_GET_RECORD_TYPE` cmsg), writes via plain `send`.
//!
//! The core type is TLS-crate-free: the library never owns TLS policy. The
//! `rt-tls-openssl` feature adds two convenience handshake helpers
//! ([`ktls_server_handshake`] / [`ktls_client_handshake`]) mirroring the
//! pattern the kTLS integration tests prove out.
//!
//! Zero-copy interplay: a `KtlsStream` is `AsRawFd`, so the
//! [`Bridge`](super::Bridge) works over it — `recv_to_file` splices
//! decrypted plaintext (`tls_sw_splice_read`), `send_file` feeds the
//! encrypt path page-by-page (`MSG_SPLICE_PAGES`), and `send_zc` detects
//! the kTLS `EOPNOTSUPP` and falls back to plain sends (which SW kTLS
//! already input-zerocopies in-kernel).

use crate::errno::Errno;
use crate::uring::sys::{SOL_TLS, TLS_GET_RECORD_TYPE, TLS_RECORD_TYPE_DATA};
use std::io;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// A generous control-message buffer for a kTLS recv (`CMSG_SPACE(1)` is 24
/// bytes on 64-bit Linux; 64 leaves ample headroom so the record-type cmsg
/// is never truncated).
const KTLS_CONTROL_LEN: usize = 64;

/// The TLS alert record type; a `close_notify` alert (description 0) is the
/// peer's clean end-of-stream.
const TLS_RECORD_TYPE_ALERT: u8 = 21;

/// A kernel-TLS socket as an async byte stream (`AsyncRead + AsyncWrite +
/// AsRawFd`). Build one with [`from_kernel_tls`](KtlsStream::from_kernel_tls)
/// once both TLS directions are installed on the fd.
///
/// Record semantics on read: application data flows through; the peer's
/// `close_notify` alert reads as clean EOF; any *other* control record (a
/// TLS 1.3 `KeyUpdate`, a warning alert) fails the read with an
/// `io::Error` — renegotiation-style traffic is out of scope for a data
/// stream, matching the io_uring reactor's `TlsControl` close.
#[derive(Debug)]
pub struct KtlsStream {
    io: AsyncFd<OwnedFd>,
}

impl KtlsStream {
    /// Wrap an fd whose kernel TLS is already engaged in **both**
    /// directions (verified here via `getsockopt(SOL_TLS, TLS_TX/TLS_RX)` —
    /// OpenSSL's `SSL_OP_ENABLE_KTLS` is best-effort and silently falls
    /// back to userspace records, so trusting the handshake alone would
    /// yield a stream that reads ciphertext). Sets the fd nonblocking.
    pub fn from_kernel_tls(fd: OwnedFd) -> crate::Result<KtlsStream> {
        for (dir, label) in [(1, "TX"), (2, "RX")] {
            let mut buf = [0u8; 4];
            let mut len = buf.len() as libc::socklen_t;
            // SAFETY: getsockopt writes at most `len` bytes into `buf`.
            let r = unsafe {
                libc::getsockopt(
                    fd.as_raw_fd(),
                    SOL_TLS,
                    dir,
                    buf.as_mut_ptr().cast(),
                    &mut len,
                )
            };
            if r != 0 {
                return Err(crate::Error::Validation(format!(
                    "kernel TLS is not engaged for {label} on this socket \
                     (the handshake fell back to userspace TLS records?)"
                )));
            }
        }
        // SAFETY: plain fcntl on a live fd.
        unsafe {
            let fl = libc::fcntl(fd.as_raw_fd(), libc::F_GETFL);
            Errno::result(libc::fcntl(
                fd.as_raw_fd(),
                libc::F_SETFL,
                fl | libc::O_NONBLOCK,
            ))?;
        }
        let io = AsyncFd::new(fd).map_err(io_to_crate_err)?;
        Ok(KtlsStream { io })
    }

    /// One nonblocking `recvmsg` with the record-type control buffer.
    /// Returns the byte count and the record type (`None` = no cmsg =
    /// application data).
    fn recvmsg_once(
        fd: RawFd,
        dst: &mut [u8],
    ) -> io::Result<(usize, Option<u8>)> {
        let mut control = [0u8; KTLS_CONTROL_LEN];
        let mut iov = libc::iovec {
            iov_base: dst.as_mut_ptr().cast(),
            iov_len: dst.len(),
        };
        // SAFETY: msghdr is plain data; every pointer below outlives the call.
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = KTLS_CONTROL_LEN;
        // SAFETY: `msg` is fully initialized for a 1-iovec recvmsg.
        let n = unsafe { libc::recvmsg(fd, &mut msg, libc::MSG_DONTWAIT) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        if msg.msg_flags & libc::MSG_CTRUNC != 0 {
            return Err(io::Error::other(
                "kTLS record-type control message truncated",
            ));
        }
        let mut rtype = None;
        // SAFETY: the kernel initialized the control region within
        // `msg_controllen`; the CMSG_* macros walk it within those bounds.
        unsafe {
            let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
            while !cmsg.is_null() {
                if (*cmsg).cmsg_level == SOL_TLS
                    && (*cmsg).cmsg_type == TLS_GET_RECORD_TYPE
                {
                    rtype = Some(*libc::CMSG_DATA(cmsg));
                    break;
                }
                cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
            }
        }
        Ok((n as usize, rtype))
    }
}

impl AsRawFd for KtlsStream {
    fn as_raw_fd(&self) -> RawFd {
        self.io.get_ref().as_raw_fd()
    }
}

impl AsyncRead for KtlsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let fd = self.as_raw_fd();
        loop {
            let mut guard = std::task::ready!(self.io.poll_read_ready(cx))?;
            let dst = buf.initialize_unfilled();
            match Self::recvmsg_once(fd, dst) {
                Ok((0, _)) => return Poll::Ready(Ok(())), // EOF
                Ok((n, rtype)) => match rtype {
                    // Application data (no cmsg, or an explicit data type).
                    None | Some(TLS_RECORD_TYPE_DATA) => {
                        buf.advance(n);
                        return Poll::Ready(Ok(()));
                    }
                    // The peer's clean close: a close_notify alert
                    // (2 bytes: level, description 0) reads as EOF.
                    Some(TLS_RECORD_TYPE_ALERT) if n == 2 && dst[1] == 0 => {
                        return Poll::Ready(Ok(()));
                    }
                    Some(t) => {
                        return Poll::Ready(Err(io::Error::other(format!(
                            "unexpected TLS control record (type {t})"
                        ))));
                    }
                },
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    guard.clear_ready();
                }
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
    }
}

impl AsyncWrite for KtlsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let fd = self.as_raw_fd();
        loop {
            let mut guard = std::task::ready!(self.io.poll_write_ready(cx))?;
            // SAFETY: sending `buf.len()` bytes from a live slice; NOSIGNAL
            // keeps a dead peer an error, not a SIGPIPE.
            let n = unsafe {
                libc::send(
                    fd,
                    buf.as_ptr().cast(),
                    buf.len(),
                    libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
                )
            };
            if n >= 0 {
                return Poll::Ready(Ok(n as usize));
            }
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::WouldBlock {
                guard.clear_ready();
                continue;
            }
            return Poll::Ready(Err(e));
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(())) // sends are unbuffered
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        // SAFETY: shutdown(2) on a live fd. (A TLS close_notify is the
        // handshake layer's business; the kernel sends only data records.)
        let r = unsafe { libc::shutdown(self.as_raw_fd(), libc::SHUT_WR) };
        if r != 0 {
            return Poll::Ready(Err(io::Error::last_os_error()));
        }
        Poll::Ready(Ok(()))
    }
}

fn io_to_crate_err(e: io::Error) -> crate::Error {
    e.raw_os_error()
        .map(Errno::from_raw)
        .unwrap_or(Errno::EIO)
        .into()
}

/// OpenSSL handshake helpers producing an engaged [`KtlsStream`].
#[cfg(feature = "rt-tls-openssl")]
mod openssl_helpers {
    use super::*;
    use foreign_types::ForeignType;
    use openssl::ssl::{Ssl, SslAcceptor, SslConnector};
    use std::sync::Arc;

    const BIO_NOCLOSE: libc::c_int = 0;

    /// Run the blocking server-side TLS handshake over `sock`'s fd on a
    /// **socket BIO** — the shape under which OpenSSL (built with
    /// `enable-ktls`, given `SSL_OP_ENABLE_KTLS` on the acceptor) installs
    /// kernel TLS itself — then hand back the engaged [`KtlsStream`].
    /// Runs on `spawn_blocking`; the socket is made blocking for the
    /// handshake and nonblocking again by `from_kernel_tls`.
    ///
    /// The acceptor is the consumer's policy: certificates, versions,
    /// `SSL_OP_ENABLE_KTLS`, `set_num_tickets(0)` (recommended, so no
    /// post-handshake ticket write perturbs the installed TX sequence).
    pub async fn ktls_server_handshake(
        sock: std::net::TcpStream,
        acceptor: Arc<SslAcceptor>,
    ) -> crate::Result<KtlsStream> {
        run_handshake(sock, move |fd| {
            let ssl =
                Ssl::new(acceptor.context()).map_err(|e| e.to_string())?;
            // SAFETY: a BIO_NOCLOSE socket BIO over `fd`; the SSL owns the
            // BIO (freed on drop) and `fd` outlives the SSL here.
            let rc = unsafe {
                let bio = openssl_sys::BIO_new_socket(fd, BIO_NOCLOSE);
                if bio.is_null() {
                    return Err("BIO_new_socket failed".into());
                }
                openssl_sys::SSL_set_bio(ssl.as_ptr(), bio, bio);
                openssl_sys::SSL_accept(ssl.as_ptr())
            };
            if rc != 1 {
                return Err(format!("SSL_accept returned {rc}"));
            }
            Ok(ssl) // dropped by the caller AFTER engagement is verified
        })
        .await
    }

    /// The client-side twin of [`ktls_server_handshake`]: `SSL_connect`
    /// over a socket BIO with `domain` for SNI/verification (the
    /// connector's verify mode is the consumer's policy).
    pub async fn ktls_client_handshake(
        sock: std::net::TcpStream,
        connector: Arc<SslConnector>,
        domain: &str,
    ) -> crate::Result<KtlsStream> {
        let domain = domain.to_string();
        run_handshake(sock, move |fd| {
            let ssl = connector
                .configure()
                .map_err(|e| e.to_string())?
                .into_ssl(&domain)
                .map_err(|e| e.to_string())?;
            // SAFETY: as in the server helper.
            let rc = unsafe {
                let bio = openssl_sys::BIO_new_socket(fd, BIO_NOCLOSE);
                if bio.is_null() {
                    return Err("BIO_new_socket failed".into());
                }
                openssl_sys::SSL_set_bio(ssl.as_ptr(), bio, bio);
                openssl_sys::SSL_connect(ssl.as_ptr())
            };
            if rc != 1 {
                return Err(format!("SSL_connect returned {rc}"));
            }
            Ok(ssl)
        })
        .await
    }

    async fn run_handshake(
        sock: std::net::TcpStream,
        shake: impl FnOnce(RawFd) -> Result<Ssl, String> + Send + 'static,
    ) -> crate::Result<KtlsStream> {
        tokio::task::spawn_blocking(move || {
            let fd = sock.as_raw_fd();
            // SSL_accept/SSL_connect want a blocking socket (a tokio
            // `into_std` conversion leaves it nonblocking).
            // SAFETY: plain fcntl on a live fd.
            unsafe {
                let fl = libc::fcntl(fd, libc::F_GETFL);
                libc::fcntl(fd, libc::F_SETFL, fl & !libc::O_NONBLOCK);
            }
            let ssl = shake(fd).map_err(crate::Error::Validation)?;
            // BIO_NOCLOSE: dropping the SSL never closes the fd; the kernel
            // TLS state lives on the socket, not the SSL.
            drop(ssl);
            KtlsStream::from_kernel_tls(OwnedFd::from(sock))
        })
        .await
        .map_err(|_| {
            crate::Error::Validation("handshake task panicked".into())
        })?
    }
}

#[cfg(feature = "rt-tls-openssl")]
pub use openssl_helpers::{ktls_client_handshake, ktls_server_handshake};
