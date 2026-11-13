//! The consumer-facing protocol vocabulary: addresses, framing verdicts, responses, close reasons, message bodies, and
//! the [`Protocol`] handler bundle with its length-prefix builders. No ring code lives here.

use super::{DeferPermit, DetachPermit, Responder};
#[cfg(doc)]
use super::{Deferred, Detached, PushHandle, Server};
#[cfg(doc)]
use crate::net::core::protocol::CloseReason;
use crate::net::core::protocol::{
    Body, ClientAddr, Endian, Framing, PrefixWidth, SendBuf, ServerAddr, length_prefix_header,
};

/// A body handler's decision for one request.
#[derive(Debug)]
pub enum Response {
    /// Send this reply now. An empty vector sends nothing (a one-way message): the request is complete and the
    /// connection keeps serving.
    Reply(Vec<u8>),
    /// Send this reply, then close the connection once it and everything queued before it has flushed, for protocols
    /// where the server speaks last (a WebSocket Close acknowledgement, an error before hanging up). The recv side is
    /// retired at once, so buffered pipelined requests are discarded and later worker outcomes and pushes are dropped.
    /// An **empty** vector queues no PDU and closes after flushing what is already queued, unlike [`Response::Close`],
    /// which tears down without flushing. The close hook reports [`CloseReason::HandlerClosed`]. With no recv armed,
    /// only `ServerConfig::send_timeout` or `tcp_user_timeout` reclaims a peer that stops reading before the farewell
    /// drains, so set one when serving untrusted peers.
    ReplyClose(Vec<u8>),
    /// Send this reply as ordered byte segments gathered into one vectored write, so a protocol can hand over a header
    /// and a payload without concatenating them. Each segment is a [`SendBuf`], where owned bytes move and `'static`
    /// bytes are sent by reference. Empty segments are skipped, and an all-empty reply sends nothing (a one-way
    /// message).
    ///
    /// `close` selects the disposition: `false` behaves like [`Reply`] (keep serving), `true` like [`ReplyClose`]
    /// (flush everything queued, then close, reported as [`CloseReason::HandlerClosed`]).
    ///
    /// [`Reply`]: Response::Reply
    /// [`ReplyClose`]: Response::ReplyClose
    ReplyVectored {
        /// The reply's byte segments, in send order.
        segments: Vec<SendBuf>,
        /// Close the connection once the reply (and everything queued before it) has flushed.
        close: bool,
    },
    /// Send `head`, then stream exactly `len` bytes of `file` from `offset` as the rest of this reply, read on the
    /// server's own ring in `ServerConfig::fs_body_chunk` chunks and sent as they arrive, so the copy in flight is
    /// bounded by the chunk size, never the body size.
    ///
    /// Requires an fs pool (`ServerConfig::fs_ops`), and without one the connection is closed
    /// ([`CloseReason::FileBody`]) rather than a short body sent. `len` is a contract the protocol already framed, so
    /// reads are clamped to it, and an EOF before `len` closes the connection mid-body
    /// ([`CloseReason::FileBodyTruncated`]) rather than present a short body as complete. `len == 0` behaves as
    /// [`Reply`](Response::Reply)`(head)`.
    ///
    /// While the body streams, every other PDU for this connection queues behind it, a second `ReplyFile` included,
    /// which starts once the first finishes. `close` matches [`ReplyVectored`](Response::ReplyVectored)'s,
    /// flush-closing once the body and everything before it drains, and then only `ServerConfig::send_timeout` or
    /// `tcp_user_timeout` reclaims a peer that stops reading mid-body.
    #[cfg(feature = "uring-fs")]
    ReplyFile {
        /// The reply's leading bytes (the protocol's header), sent before the file bytes.
        head: Vec<u8>,
        /// The source file. Reference-counted: the reactor and each in-flight read hold it, so the fd cannot close
        /// under a read even once the handler's clone is gone.
        file: crate::uring_fs::File,
        /// File offset the body starts at (a range is an offset and a length - no separate mechanism).
        offset: u64,
        /// Exactly how many bytes to send.
        len: u64,
        /// Close the connection once the reply has fully flushed.
        close: bool,
    },
    /// The reply will arrive later through a [`Deferred`]. The [`DeferPermit`] comes from **this request's**
    /// [`Responder::defer`], and its token is checked at delivery, so one from another request closes the connection
    /// rather than park a request nothing can resolve. The worker resolves it with [`Deferred::reply`], with
    /// [`Deferred::redeliver`] to run the body handler again on the server thread, or with [`Deferred::close`].
    Defer(DeferPermit),
    /// **Detach** the connection: hand its socket fd to your own worker for a blocking operation (e.g. ZFS send/recv),
    /// then resume or close it. Carries the [`DetachPermit`] proof minted by **this request's** [`Responder::detach`];
    /// the loop materializes a real fd and delivers it, with a [`Detached`] handle, to the
    /// [`Server::set_detach_handler`] handler. The permit's token is verified at delivery - one from a different
    /// request closes the connection instead. Only valid on a fully settled connection (no other request in flight,
    /// nothing buffered past this one); otherwise the connection is closed.
    Detach(DetachPermit),
    /// Close the connection now without replying.
    Close,
}

/// An incoming connection, as handed to the `accept` handler.
///
/// `#[non_exhaustive]`, so future context becomes a field addition rather than a breaking signature change; destructure
/// with `..`.
#[non_exhaustive]
pub struct Incoming<'a> {
    /// The peer's identity (fetched per connection - race-free).
    pub peer: &'a ClientAddr,
    /// Resolved bind address of the listener this connection arrived on, as [`Server::local_addrs`] reports it, for
    /// per-listener policy. On a wildcard bind it is not the connection's local address, which would need
    /// `SOCKET_URING_OP_GETSOCKNAME`, newer than the target kernel.
    pub listener_addr: &'a ServerAddr,
}

impl std::fmt::Debug for Incoming<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Incoming")
            .field("peer", self.peer)
            .field("listener_addr", self.listener_addr)
            .finish_non_exhaustive()
    }
}

/// Context handed to the detach handler ([`Server::set_detach_handler`]) when a connection is detached, alongside the
/// [`Detached`] handle that carries the furnished fd.
///
/// `#[non_exhaustive]`; destructure with `..`.
#[non_exhaustive]
pub struct DetachContext<'a, U> {
    /// The peer's identity.
    pub peer: &'a ClientAddr,
    /// The connection's state - where the `body` handler that returned [`Response::Detach`] stashed what the worker
    /// should do.
    pub state: &'a mut U,
}

impl<U> std::fmt::Debug for DetachContext<'_, U> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DetachContext")
            .field("peer", self.peer)
            .finish_non_exhaustive()
    }
}

/// One framed request, as handed to the `body` handler.
///
/// Fields are public and borrow independently - `body` can be [taken](Body::take) while `state` is mutably borrowed,
/// because field accesses split. `#[non_exhaustive]`, so future context becomes a field addition rather than a breaking
/// signature change; destructure with `..`.
#[non_exhaustive]
pub struct Request<'a, U> {
    /// The frame header the framer declared (`header_len` bytes).
    pub header: &'a [u8],
    /// The message body - deref for in-place reads, [`Body::take`] to move the bytes to a worker (zero-copy when
    /// placed).
    pub body: Body<'a>,
    /// The peer's identity.
    pub peer: &'a ClientAddr,
    /// The connection's state, minted by the `accept` handler.
    pub state: &'a mut U,
    /// The reply ticket: ignore it for a synchronous [`Response::Reply`], or [`Responder::defer`] to offload; also
    /// mints [`PushHandle`](Responder::push_handle)s.
    pub responder: Responder,
    /// The request-bound fs submission facade - `Some` when the server was built with an fs pool
    /// (`ServerConfig::fs_ops`), else `None`. Take it (`req.fs.take()`) to open/read/stat files on the server's own
    /// ring under a per-request [`Personality`](crate::uring_fs::Personality): the first op parks the request through a
    /// [`Deferred`](Responder::defer) the callback captures, so pair it with `Response::Defer`. Present only with the
    /// `uring-fs` feature.
    #[cfg(feature = "uring-fs")]
    pub fs: Option<crate::uring_fs::FsConn<'a>>,
}

impl<U> std::fmt::Debug for Request<'_, U> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Request")
            .field("header_len", &self.header.len())
            .field("body", &self.body)
            .field("peer", self.peer)
            .finish_non_exhaustive()
    }
}

/// How a caller's protocol frames messages, plus its per-connection state.
///
/// See the module docs. Construct via [`length_prefixed`] for the common fixed-width length prefix, or directly for a
/// custom `header` framer (e.g. an LSP-style variable header) and/or per-connection state.
pub struct Protocol<AcceptFn, HeaderFn, BodyFn> {
    /// Admission: [`Incoming`]` -> Option<U>`, once per accepted connection. `None` rejects the connection (closed
    /// before any read); `Some(state)` accepts and stores `state` as the connection's `U`.
    pub accept: AcceptFn,
    /// Framing: given the bytes accumulated so far and the connection's state, decide what to read next or where the
    /// message boundary is.
    pub header: HeaderFn,
    /// Application: [`Request`]` -> `[`Response`]. Reply synchronously ([`Response::Reply`]), offload via
    /// [`Request::responder`] and return [`Response::Defer`], or [`Response::Close`].
    pub body: BodyFn,
}

impl<AcceptFn, HeaderFn, BodyFn> std::fmt::Debug for Protocol<AcceptFn, HeaderFn, BodyFn> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Protocol").finish_non_exhaustive()
    }
}

/// Build a stateless [`Protocol`] for a fixed-width length prefix: the caller supplies only a `(header, body, peer) ->
/// Option<reply>` handler (no per-connection state, every connection accepted).
///
/// The handler's return maps onto [`Response`] without inverting it: `Some(bytes)` sends exactly those bytes (frame the
/// reply yourself - it goes out verbatim), `Some` of an **empty** vector sends nothing and keeps serving (the one-way
/// case, as [`Response::Reply`] documents), and `None` closes the connection - the bare handler's [`Response::Close`].
// The lint scores the three opaque closures in the generic return; they can't be type-aliased on stable (`impl Trait`
// in a type alias is unstable), and boxing them would put dyn dispatch on the hot path. Nothing is hidden here: the
// "complex type" IS the whole signature.
#[allow(clippy::type_complexity)]
pub fn length_prefixed<Handler>(
    width: PrefixWidth,
    endian: Endian,
    includes_self: bool,
    mut body: Handler,
) -> Protocol<
    impl FnMut(Incoming<'_>) -> Option<()>,
    impl FnMut(&[u8], &mut ()) -> Framing,
    impl FnMut(Request<'_, ()>) -> Response,
>
where
    Handler: FnMut(&[u8], &[u8], &ClientAddr) -> Option<Vec<u8>>,
{
    Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(width, endian, includes_self),
        body: move |req: Request<'_, ()>| match body(req.header, &req.body[..], req.peer) {
            Some(out) => Response::Reply(out),
            None => Response::Close,
        },
    }
}
