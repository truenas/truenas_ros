//! The client's public event vocabulary: connection/request identifiers, the
//! [`Event`] the caller drains from [`next_event`](super::Client::next_event),
//! and the per-connect [`ConnectOpts`].

use crate::errno::Errno;
use crate::net::core::protocol::{Body, CloseReason};
use std::net::SocketAddr;
use std::time::Duration;

/// The 24-bit pool slot a `ConnId`/`RequestId` packs, mirroring the codec's
/// `SLOT_MASK`.
const SLOT_BITS: u32 = 24;
const SLOT_MASK: u64 = (1 << SLOT_BITS) - 1;

/// A stale-safe handle to one client connection: its pool slot plus the slot's
/// generation, so a handle retained past the connection's close never aliases a
/// later connection recycled into the same slot.
///
/// Packed into a `u64` — the slot in the low 24 bits (identical to the kernel
/// routing codec) and the generation above it. The generation is the
/// full loop-side counter (used for the `slot_matches` liveness check); a
/// client runs on one thread and never approaches 2^40 recycles on a single
/// slot, so the high-bit truncation is unobservable.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct ConnId(u64);

impl ConnId {
    pub(super) fn new(slot: u32, generation: u64) -> ConnId {
        ConnId((u64::from(slot) & SLOT_MASK) | (generation << SLOT_BITS))
    }

    /// `(slot, generation)` for the liveness check and kernel routing.
    pub(super) fn parts(self) -> (u32, u64) {
        ((self.0 & SLOT_MASK) as u32, self.0 >> SLOT_BITS)
    }
}

/// A client-global monotonic request identifier, assigned by
/// [`send`](super::Client::send) and echoed back in the matching
/// [`Event::Reply`] so a caller can correlate replies (the client itself
/// correlates a connection's replies to its sent requests in FIFO order).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd, Debug)]
pub struct RequestId(pub(super) u64);

impl RequestId {
    /// The id reported for a reply that arrived with no request awaiting it on
    /// its connection — an unsolicited server push (only expected when
    /// [`ClientConfig::expect_server_push`](super::ClientConfig::expect_server_push)
    /// is set).
    pub const UNSOLICITED: RequestId = RequestId(u64::MAX);
}

/// A completion the caller drains from [`next_event`](super::Client::next_event).
///
/// `#[non_exhaustive]`: further variants (e.g. a spliced-body notification)
/// slot in without a breaking change — destructure with `..`.
#[non_exhaustive]
#[derive(Debug)]
pub enum Event {
    /// An outbound connect completed: the connection is now serving and can be
    /// sent requests.
    Connected {
        /// The connection that came up.
        conn: ConnId,
    },
    /// An outbound connect failed (refused, timed out, unreachable, …); its
    /// slot has been reclaimed and the [`ConnId`] is now stale.
    ConnectFailed {
        /// The connection that failed to come up.
        conn: ConnId,
        /// The failure errno (`ETIMEDOUT` when a `connect_timeout` fired).
        err: Errno,
    },
    /// A framed reply arrived. `header` is the framer-declared header bytes and
    /// `body` the owned body (a zero-copy move when the body was placed).
    Reply {
        /// The connection the reply arrived on.
        conn: ConnId,
        /// The request this reply answers (FIFO-correlated), or
        /// [`RequestId::UNSOLICITED`] for a server push.
        id: RequestId,
        /// The frame header bytes.
        header: Vec<u8>,
        /// The owned reply body.
        body: Body<'static>,
    },
    /// A framed reply whose **body** was spliced straight to the caller's sink
    /// fd (a framer returned [`Framing`](crate::net::Framing)`::SpliceBody`)
    /// instead of read into a buffer — zero-copy. The body never enters an
    /// event; it already went to the sink fd (a blocking pipe write end the
    /// caller stashed in `U`). `header` is the buffered header bytes and
    /// `body_len` the number of bytes moved to the sink.
    Splice {
        /// The connection the reply arrived on.
        conn: ConnId,
        /// The request this reply answers (FIFO-correlated), or
        /// [`RequestId::UNSOLICITED`] for a server push.
        id: RequestId,
        /// The frame header bytes (the body was spliced, not delivered here).
        header: Vec<u8>,
        /// The number of body bytes moved to the sink fd.
        body_len: usize,
    },
    /// A connection finished closing (peer EOF, a transport error, or a local
    /// [`close`](super::Client::close)); its slot is reclaimed and the
    /// [`ConnId`] is now stale.
    Closed {
        /// The connection that closed.
        conn: ConnId,
        /// Why it closed.
        reason: CloseReason,
    },
}

/// Per-connect options. `Default` connects immediately with no timeout, no
/// local bind, and no TLS.
#[derive(Clone, Debug, Default)]
pub struct ConnectOpts {
    /// Bound on how long the `IORING_OP_CONNECT` may take before it is
    /// cancelled (a linked timeout); the connect then fails with
    /// [`Event::ConnectFailed`]. `None` uses the kernel's own connect timeout.
    pub connect_timeout: Option<Duration>,
    /// Bind the client socket to this local address before connecting (source
    /// address/port selection). `None` lets the kernel pick.
    pub local_addr: Option<SocketAddr>,
    /// Layer kernel TLS over the connection once the TCP connect completes: the
    /// client furnishes a real fd to the
    /// [`set_tls_handshake`](super::Client::set_tls_handshake) worker, which
    /// runs the TLS handshake (installing kTLS) and hands the connection back.
    /// Requires a handshake handler and a kernel with
    /// `IORING_OP_FIXED_FD_INSTALL` (Linux >= 6.8) + the TLS ULP; a `tls`
    /// connect without them fails cleanly. `false` (the default) is plain TCP.
    pub tls: bool,
}

impl ConnectOpts {
    /// Layer kernel TLS over this connection (see [`tls`](ConnectOpts::tls)).
    /// Requires [`Client::set_tls_handshake`](super::Client::set_tls_handshake).
    pub fn tls(mut self) -> ConnectOpts {
        self.tls = true;
        self
    }
}
