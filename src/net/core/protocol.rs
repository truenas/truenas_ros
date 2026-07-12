//! Role-agnostic protocol vocabulary shared across the net roles: addresses,
//! framing verdicts, close reasons, message bodies, and the reusable
//! length-prefix framer. No ring code lives here.

use crate::errno::Errno;
#[cfg(all(doc, feature = "net-server"))]
use crate::net::server::{DeferPermit, Deferred, PushHandle, Response, Server};
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::RawFd;
use std::path::PathBuf;

/// Stream server type and bind address in one type-safe enum: the variant *is*
/// the server type (the Rust-idiomatic take on `socketserver`'s server class +
/// `server_address`), so an illegal type/address pairing cannot be expressed.
#[derive(Clone, Debug)]
pub enum ServerAddr {
    /// IPv4 TCP (`AF_INET`, `SOCK_STREAM`).
    Tcp(SocketAddrV4),
    /// IPv6 TCP (`AF_INET6`, `SOCK_STREAM`).
    Tcp6(SocketAddrV6),
    /// Unix-domain stream (`AF_UNIX`, `SOCK_STREAM`) at a filesystem path.
    Unix(PathBuf),
}

/// The peer address handed to the accept/header/body handlers.
#[derive(Clone, Debug)]
pub enum ClientAddr {
    /// A TCP/TCP6 peer.
    Inet(SocketAddr),
    /// A Unix-domain peer (stream clients are unnamed).
    Unix {
        /// The peer's credentials (`SO_PEERCRED`), fetched between accept and
        /// the accept handler when `ServerConfig::unix_peercred` is enabled —
        /// the basis for local authentication. `None` when disabled.
        cred: Option<PeerCred>,
    },
}

/// Unix-domain peer credentials (`SO_PEERCRED`): the process on the other end
/// of the socket as of `connect(2)`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerCred {
    /// Peer process id.
    pub pid: i32,
    /// Peer effective user id.
    pub uid: u32,
    /// Peer effective group id.
    pub gid: u32,
}

/// A header framer's verdict, given the message bytes accumulated so far.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Framing {
    /// Read exactly `n` more bytes (one `MSG_WAITALL` recv), then re-check.
    /// Use when the remaining length is known (a length prefix, or a body once
    /// its length is parsed) — efficient, and never over-reads.
    Need(usize),
    /// Read whatever the peer has sent (a chunk, no `MSG_WAITALL`), then
    /// re-check. Use when scanning for a delimiter of unknown position.
    More,
    /// The message is completely framed: its header is the first
    /// `header_len` accumulated bytes and its body is `body_len` bytes. The
    /// server reads any body bytes not already buffered, then delivers the
    /// message to the body handler.
    Complete {
        /// Length of the header portion.
        header_len: usize,
        /// Length of the body portion.
        body_len: usize,
    },
    /// The message is completely framed, but its **body** should be spliced
    /// straight from the socket to `fd` (a consumer-owned pipe, e.g. feeding a
    /// ZFS `lzc_receive`) instead of read into the connection buffer — zero-copy
    /// (`IORING_OP_SPLICE`). The first `header_len` accumulated bytes are the
    /// header; the next `body_len` bytes are spliced to `fd`. The server never
    /// owns or closes `fd`; the framer must read its header with exact
    /// [`Framing::Need`] so no body byte is over-read into the buffer.
    ///
    /// Works over plain TCP/unix **and kernel TLS**: the kernel routes the
    /// splice through the socket's `splice_read`, which for kTLS is
    /// `tls_sw_splice_read` — it decrypts and moves plaintext, so the body
    /// splices in the clear, and body bytes the header read left buffered in
    /// the kernel's TLS receive list are picked up too. A mid-stream TLS
    /// control record (a TLS 1.3 KeyUpdate, or an alert) cannot be spliced and
    /// closes the connection with [`CloseReason::TlsControl`]. NIC-offloaded
    /// kTLS RX (`tls_device`) uses this **same** `tls_sw_splice_read` path (the
    /// NIC decrypts, the software layer still frames records with a decrypt
    /// fallback), so splice is expected to work there too — though it is
    /// untested without offload-capable hardware. The legacy `TLS_HW_RECORD`
    /// full-offload mode (TOE-style) delivers a plain stream and is out of
    /// scope.
    ///
    /// `fd` must be **blocking** (its `O_NONBLOCK` clear); a non-blocking
    /// destination is rejected with [`CloseReason::SpliceBadFd`] — see that
    /// variant for why. Backpressure is the pipe itself: a full pipe blocks
    /// the splice on an io-wq worker (never the ring), TCP flow control
    /// pushes back on the sender, and the ring keeps serving other
    /// connections. Over kTLS, `ServerConfig::request_timeout` (when set)
    /// also clocks each spliced record — including time blocked on a full
    /// pipe, which the kernel cannot distinguish from a stalled peer — so a
    /// consumer draining slower than a record per period is evicted as a
    /// slow-loris would be.
    SpliceBody {
        /// Length of the header portion (buffered).
        header_len: usize,
        /// Length of the body portion (spliced to `fd`).
        body_len: usize,
        /// Consumer-owned destination fd (borrowed; e.g. a **blocking** pipe
        /// write end).
        fd: RawFd,
    },
    /// The input is malformed; close the connection.
    Invalid,
}

/// Why a connection is being closed, as reported to the close hook
/// ([`Server::set_close_hook`]).
///
/// Rejected (`accept` returned `None`) and load-shed (pool-full) connections
/// never had per-connection state, so the hook does not fire for them.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CloseReason {
    /// The peer ended the keep-alive cleanly (EOF between messages).
    PeerClosed,
    /// The peer vanished mid-message (EOF or short read inside a frame).
    TruncatedMessage,
    /// The header framer returned [`Framing::Invalid`] (or an impossible frame,
    /// e.g. a zero-byte need or a zero-length message).
    Malformed,
    /// A message exceeded `ServerConfig::max_request_bytes`.
    TooLarge,
    /// The body handler ended the connection: it returned [`Response::Close`]
    /// or [`Response::ReplyClose`], or a [`Response::Defer`] whose permit was
    /// minted for a different request (see [`DeferPermit`]).
    HandlerClosed,
    /// A worker resolved the request with [`Deferred::close`] or
    /// [`Deferred::reply_close`], or its [`Deferred`] was dropped unresolved
    /// (lost worker).
    WorkerClosed,
    /// An application thread ended the connection via [`PushHandle::close`] —
    /// outside any request cycle (session revocation, an administrative
    /// kick). PDUs already queued, including pushes issued before the close,
    /// were flushed first.
    PushClosed,
    /// The `idle_timeout` fired while parked for the next request.
    IdleTimeout,
    /// The `request_timeout` fired: a request had begun arriving (a body, or
    /// an exact header remainder) but was not fully received in time — the
    /// slow-loris guard (see `ServerConfig::request_timeout`).
    RequestTimeout,
    /// The `send_timeout` fired while a reply was stalled (peer not reading).
    SendTimeout,
    /// Closed by shutdown (graceful drain, or the connection quiesced during
    /// one).
    ShuttingDown,
    /// A push overflowed `ServerConfig::max_send_backlog` — the peer is not
    /// draining its socket (slow-consumer eviction).
    SendBacklog,
    /// A receive failed with this errno.
    RecvError(Errno),
    /// A send failed with this errno.
    SendError(Errno),
    /// A kTLS connection delivered a non-`application_data` record (a
    /// post-handshake handshake message, TLS 1.3 KeyUpdate, or alert). The
    /// server closes rather than handle it (renegotiation/rekey are out of
    /// scope); a `close_notify` from the peer surfaces here too.
    TlsControl,
    /// The fd a framer handed to [`Framing::SpliceBody`] was unusable: closed,
    /// or opened **non-blocking**. This is a consumer bug, not peer behavior.
    /// The destination must be a blocking pipe write end: `splice` promotes
    /// the output fd's `O_NONBLOCK` to `SPLICE_F_NONBLOCK`, making a full
    /// pipe fail `-EAGAIN` before the socket is read — indistinguishable
    /// from "no socket data", which would spin the readiness poll at full
    /// CPU. A blocking pipe blocks the splice on an io-wq worker instead:
    /// that is the transfer's designed backpressure.
    SpliceBadFd,
}

/// The current message's body, as handed to the `body` handler.
///
/// Dereferences to `[u8]` for in-place reads. [`Body::take`] yields the bytes
/// as an owned `Vec<u8>` — a zero-copy move when the body was **placed** in
/// its own allocation (bodies at or over
/// `ServerConfig::body_placement_threshold`), a copy-out otherwise — so a
/// handler that offloads work writes one pattern that is never wrong:
/// `let payload = body.take();`. After `take` the body reads as empty.
pub struct Body<'a> {
    inner: BodyInner<'a>,
}

enum BodyInner<'a> {
    /// Borrowed from the connection's accumulate buffer.
    Inline(&'a [u8]),
    /// Placed in its own allocation; `None` once taken.
    Placed(Option<Vec<u8>>),
}

impl<'a> Body<'a> {
    pub(crate) fn inline(bytes: &'a [u8]) -> Body<'a> {
        Body {
            inner: BodyInner::Inline(bytes),
        }
    }

    pub(crate) fn placed(bytes: Vec<u8>) -> Body<'a> {
        Body {
            inner: BodyInner::Placed(Some(bytes)),
        }
    }

    /// Take ownership of the body bytes: a zero-copy move when placed, a copy
    /// otherwise. The body reads as empty afterwards.
    pub fn take(&mut self) -> Vec<u8> {
        match &mut self.inner {
            BodyInner::Inline(bytes) => {
                let out = bytes.to_vec();
                *bytes = &[];
                out
            }
            BodyInner::Placed(bytes) => bytes.take().unwrap_or_default(),
        }
    }
}

impl std::ops::Deref for Body<'_> {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        match &self.inner {
            BodyInner::Inline(bytes) => bytes,
            BodyInner::Placed(Some(bytes)) => bytes,
            BodyInner::Placed(None) => &[],
        }
    }
}

impl std::fmt::Debug for Body<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Body")
            .field("len", &self.len())
            .field("placed", &matches!(self.inner, BodyInner::Placed(_)))
            .finish()
    }
}

/// Width of a fixed-size length prefix.
#[derive(Clone, Copy, Debug)]
pub enum PrefixWidth {
    /// 1-byte length.
    U8,
    /// 2-byte length.
    U16,
    /// 4-byte length.
    U32,
    /// 8-byte length.
    U64,
}

impl PrefixWidth {
    fn bytes(self) -> usize {
        match self {
            PrefixWidth::U8 => 1,
            PrefixWidth::U16 => 2,
            PrefixWidth::U32 => 4,
            PrefixWidth::U64 => 8,
        }
    }
}

/// Byte order of a length prefix.
#[derive(Clone, Copy, Debug)]
pub enum Endian {
    /// Big-endian (network order).
    Big,
    /// Little-endian.
    Little,
}

fn read_prefix(header: &[u8], width: PrefixWidth, endian: Endian) -> u64 {
    let mut v = 0u64;
    match endian {
        Endian::Big => {
            for &b in &header[..width.bytes()] {
                v = (v << 8) | b as u64;
            }
        }
        Endian::Little => {
            for (i, &b) in header[..width.bytes()].iter().enumerate() {
                v |= (b as u64) << (8 * i);
            }
        }
    }
    v
}

/// A reusable header framer for a fixed-width length prefix: the first `width`
/// bytes are an unsigned integer giving the message length; `includes_self`
/// means that length counts the prefix itself. Works with any state `U`.
pub fn length_prefix_header<U>(
    width: PrefixWidth,
    endian: Endian,
    includes_self: bool,
) -> impl FnMut(&[u8], &mut U) -> Framing {
    let hlen = width.bytes();
    move |buf: &[u8], _state: &mut U| {
        if buf.len() < hlen {
            return Framing::Need(hlen - buf.len());
        }
        let total = read_prefix(buf, width, endian);
        let body = if includes_self {
            match total.checked_sub(hlen as u64) {
                Some(b) => b,
                None => return Framing::Invalid,
            }
        } else {
            total
        };
        match usize::try_from(body) {
            Ok(body_len) => Framing::Complete {
                header_len: hlen,
                body_len,
            },
            Err(_) => Framing::Invalid,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn length_prefix_header_verdicts() {
        let mut h =
            length_prefix_header::<()>(PrefixWidth::U32, Endian::Big, false);
        assert_eq!(h(&[], &mut ()), Framing::Need(4));
        assert_eq!(h(&[0, 0], &mut ()), Framing::Need(2));
        assert_eq!(
            h(&[0, 0, 0, 5], &mut ()),
            Framing::Complete {
                header_len: 4,
                body_len: 5
            }
        );
    }

    #[test]
    fn length_prefix_includes_self() {
        let mut h =
            length_prefix_header::<()>(PrefixWidth::U16, Endian::Big, true);
        // total length 10 includes the 2-byte prefix → body is 8.
        assert_eq!(
            h(&[0, 10], &mut ()),
            Framing::Complete {
                header_len: 2,
                body_len: 8
            }
        );
        // total length < prefix width is malformed.
        assert_eq!(h(&[0, 1], &mut ()), Framing::Invalid);
    }
}
