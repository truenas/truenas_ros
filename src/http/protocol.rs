//! Glue: build a [`net::server::Protocol`](Protocol) from an HTTP handler.
//! The `header` handler is the framer step; the `body` handler drives the
//! phase machine - pairing stashed heads with their bodies, sending the
//! `100 Continue` interim, serializing responses, and mapping keep-alive
//! onto [`Response::Reply`] vs [`Response::ReplyClose`]. The whole body
//! handler lives in [`step`], a plain function over the delivered message
//! and the connection's phase, so tests drive the real glue without a
//! reactor.

use std::borrow::Cow;
use std::sync::PoisonError;
use std::time::{SystemTime, UNIX_EPOCH};

// The answer cell is cross-thread state (a worker fills it, the loop takes
// it), so it rides `crate::sync` - std in production, loom's in the model
// below, which is what lets the model see the fill/redeliver ordering.
use crate::sync::{Arc, Mutex};

use crate::net::ClientAddr;
use crate::net::server::{
    Body, DeferPermit, Deferred, Incoming, Protocol, Request, Responder,
    Response,
};

use super::chunked;
use super::date::DateCache;
use super::framer::{HttpConfig, HttpConn, Phase, frame};
use super::head::{
    Head, HeaderView, MAX_HEADERS, Version, method_is_head, parse_head,
};
use super::response::{
    ConnHeader, HttpResponse, Serialized, serialize, serialize_reply,
};

/// One HTTP request, as handed to the consumer's handler.
///
/// Everything borrows from the connection buffer (or the codec's head stash
/// on the 100-continue path); the header index is a slice into a fixed array
/// on the caller's stack, so a request costs no per-request heap allocation.
/// `raw_head` is the head block verbatim, byte-for-byte as the client sent
/// it, kept for the diagnostic echo in a `SignatureDoesNotMatch` reply;
/// SigV4 canonicalizes from the parsed [`headers`](HttpRequest::headers)
/// views, not this block (see the field). `#[non_exhaustive]`, so future
/// context becomes a field addition rather than a breaking change.
#[non_exhaustive]
pub struct HttpRequest<'a> {
    /// Request method, verbatim (methods are case-sensitive tokens).
    pub method: &'a str,
    /// Request-target in **origin form** (`/path?query`), undecoded - S3 keys
    /// percent-decode at the S3 layer, where encoding is semantically
    /// load-bearing.
    ///
    /// One shape, whatever the client sent. Absolute-form is accepted (RFC
    /// 9112 sec. 3.2.2 requires an origin server to) only when its authority
    /// matches `Host`, and is reduced to its path here; asterisk-form
    /// survives as `*`, and only for `OPTIONS`; every other form is answered
    /// 400 before a handler runs. So this never carries a second authority
    /// for a consumer to reconcile - but note that `//host/path` is ordinary
    /// origin-form and reaches a handler verbatim, so a consumer re-parsing
    /// this as a URI *reference* must not read that as an authority.
    pub target: &'a str,
    /// Protocol version (1.0 or 1.1; anything else died with 505).
    pub version: Version,
    /// Parsed header index, wire order preserved.
    pub headers: &'a [HeaderView<'a>],
    /// The request body (complete - bounded by [`HttpConfig::max_body`]).
    /// Deref for in-place reads; [`Body::take`] moves the bytes out - a
    /// zero-copy move when the reactor placed the body in its own
    /// allocation, and for a chunked body delivered owned (the 100-continue
    /// dance path at or over the placement threshold) an in-place truncate
    /// of the de-chunked wire - so a handler that keeps the payload (an S3
    /// PUT) never pays a second copy.
    pub body: Body<'a>,
    /// The head block verbatim, including the terminating CRLFCRLF - the
    /// diagnostic to echo in a `SignatureDoesNotMatch` reply. Build the SigV4
    /// canonical request from [`headers`](HttpRequest::headers) (borrows into
    /// this buffer, values verbatim minus edge-trim), never by re-splitting
    /// this block: the tokenizer accepts a bare LF as a line terminator
    /// (RFC 9112 sec. 2.2), so a CRLF-strict re-parse would draw header
    /// boundaries the request is not served on - the header-smuggling
    /// differential the parsed view does not have.
    pub raw_head: &'a [u8],
    /// Trailer fields from a chunked body (RFC 9112 sec. 7.1.2), parsed but not
    /// interpreted; empty for non-chunked requests and for chunked bodies
    /// whose trailer section is bare. Names forbidden in trailers --
    /// framing, routing, and credentials (RFC 9110 sec. 6.5.1) - are dropped by
    /// the codec and never appear here, so merging these with the headers
    /// cannot rewrite either. (botocore's checksum trailer rides *inside*
    /// the aws-chunked entity, not here - this surfaces genuine HTTP
    /// trailers for whichever clients send them.)
    pub trailers: &'a [HeaderView<'a>],
    /// The peer's identity.
    pub peer: &'a ClientAddr,
    /// Where this delivery sits in the body. [`Stage::Whole`] for every
    /// non-streaming builder; a streaming connection walks
    /// `Open` -> `Window`* -> `End`.
    pub stage: Stage,
    /// The reply ticket, consumed by [`HttpRequest::defer`].
    responder: Responder,
}

impl<'a> HttpRequest<'a> {
    /// Park this request for deferred completion: retain the head verbatim,
    /// the body (an owned move when the reactor placed it), and the
    /// trailers, and detach the `Send` completion handle. Move the
    /// [`HttpDeferred`] into your worker and return the permit as
    /// [`HttpVerdict::Defer`]. Only a [`protocol_deferrable`] handler has a
    /// verdict to return it through.
    pub fn defer(self) -> (HttpDeferred, HttpDeferPermit) {
        let HttpRequest {
            mut body,
            raw_head,
            trailers,
            responder,
            ..
        } = self;
        let (deferred, permit) = responder.defer();
        let answer = Arc::new(Mutex::new(None));
        let req = Box::new(ParkedRequest {
            head: raw_head.to_vec(),
            body: body.take(),
            trailers: trailers
                .iter()
                .map(|h| (Box::from(h.name), h.value.to_vec()))
                .collect(),
            answer: Arc::clone(&answer),
        });
        (
            HttpDeferred {
                answer,
                inner: deferred,
            },
            HttpDeferPermit { permit, req },
        )
    }

    /// Park a **streamed** delivery ([`Stage::Open`] or [`Stage::Window`])
    /// while an async operation - typically a file write of this very
    /// window - completes, without retaining the window.
    ///
    /// [`HttpRequest::defer`] copies the body into the park so
    /// [`HttpDeferred::redrive`] can re-run the handler on it. A stream
    /// park resolved by [`HttpStreamDeferred::resume`] never re-runs the
    /// handler - the stream just moves to its next read - so the copy buys
    /// nothing, and for a window written straight from the receive buffer
    /// (`pwritev2_from`) it is the allocation the whole path exists to
    /// remove. The head is still retained (it is small and
    /// [`HttpStreamDeferred::fail`] serializes against it); the body is
    /// not, which is why this deferral cannot redrive. The window itself
    /// comes back to the caller: the park no longer holds it, and the
    /// operation this deferral waits on is usually *of* those bytes - they
    /// stay valid for the delivery (the reactor recycles the buffer only
    /// after the write that borrows it completes).
    pub fn defer_stream(
        self,
    ) -> (HttpStreamDeferred, HttpDeferPermit, Body<'a>) {
        let HttpRequest {
            raw_head,
            responder,
            body,
            ..
        } = self;
        let (deferred, permit) = responder.defer();
        let answer = Arc::new(Mutex::new(None));
        let req = Box::new(ParkedRequest {
            head: raw_head.to_vec(),
            body: Vec::new(),
            trailers: Vec::new(),
            answer: Arc::clone(&answer),
        });
        (
            HttpStreamDeferred {
                answer,
                inner: deferred,
            },
            HttpDeferPermit { permit, req },
            body,
        )
    }
}

impl std::fmt::Debug for HttpRequest<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpRequest")
            .field("method", &self.method)
            .field("target", &self.target)
            .field("version", &self.version)
            .field("header_count", &self.headers.len())
            .field("body_len", &self.body.len())
            .field("peer", self.peer)
            .finish_non_exhaustive()
    }
}

/// A request retained across a park: everything a redelivery needs to
/// re-present the identical request view, plus the answer cell a worker's
/// [`HttpDeferred::reply`] fills. Fully owned - the connection buffer it was
/// parsed from is recycled while the request is parked.
pub(crate) struct ParkedRequest {
    /// The head block verbatim (`raw_head`), re-parsed at completion so no
    /// negotiated fact is copied aside where it could drift.
    head: Vec<u8>,
    /// The body, taken owned at [`HttpRequest::defer`] (zero-copy when the
    /// reactor placed it).
    body: Vec<u8>,
    /// Owned trailer fields.
    trailers: Vec<(Box<str>, Vec<u8>)>,
    /// `Some` once a worker chose [`HttpDeferred::reply`] or
    /// [`HttpStreamDeferred::resume`]; the redelivery acts on it instead of
    /// re-running the handler.
    answer: Arc<Mutex<Option<ParkAnswer>>>,
}

/// What a worker decided for a parked request.
pub(crate) enum ParkAnswer {
    /// Serialize this response ([`HttpDeferred::reply`]). Boxed so the
    /// resume variant does not carry a response-sized cell.
    Reply(Box<HttpResponse>),
    /// A streamed window is done with: put the streaming phase back and
    /// answer nothing, without re-running the handler - which is what lets
    /// a stream park retain no body ([`HttpRequest::defer_stream`]).
    Resume,
}

impl std::fmt::Debug for ParkedRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ParkedRequest")
            .field("head_len", &self.head.len())
            .field("body_len", &self.body.len())
            .finish_non_exhaustive()
    }
}

/// Where a delivery sits in a body.
///
/// Every non-streaming builder delivers [`Stage::Whole`] and nothing else --
/// the whole body, once, as those builders document. A streaming connection
/// never delivers `Whole`: it opens with [`Stage::Open`] before a body byte
/// exists, hands each chunk over as [`Stage::Window`], and closes with
/// [`Stage::End`] once the terminal chunk and its trailers have landed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stage {
    /// The whole body arrived at once.
    Whole,
    /// A streamed body's head, before any body byte. The one place to
    /// refuse a body the server does not want - and, when the client sent
    /// `Expect: 100-continue`, refusing here means the interim line is never
    /// sent at all rather than sent and then contradicted.
    Open,
    /// One chunk of a streamed body; `body` is this window's payload and
    /// nothing is retained between windows.
    Window,
    /// A streamed body is complete and `trailers` are parsed. The response
    /// belongs here.
    End,
}

/// A deferrable handler's decision for one request.
// The verdict is built and consumed within one dispatch - it never rests
// anywhere - so boxing the response to level the variant sizes would buy
// nothing but a per-response allocation on the hot path.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum HttpVerdict {
    /// Answer now - exactly what a [`protocol`] handler returns.
    Respond(HttpResponse),
    /// The request is parked; the detached [`HttpDeferred`] completes it.
    Defer(HttpDeferPermit),
    /// Accepted; read on. Only meaningful on a streamed delivery
    /// ([`Stage::Open`] or [`Stage::Window`]) - it is how a consumer says
    /// "no reply yet, send me the next window". Returning it from
    /// [`Stage::Whole`] or [`Stage::End`] would leave the request
    /// unanswered, so it closes the connection instead.
    Continue,
}

impl From<HttpResponse> for HttpVerdict {
    fn from(resp: HttpResponse) -> Self {
        HttpVerdict::Respond(resp)
    }
}

/// Proof that [`HttpRequest::defer`] was called for this request, carrying
/// the retained request. Returning it as [`HttpVerdict::Defer`] files the
/// request into the connection's parked phase; the inner permit's token is
/// verified at delivery exactly as for a raw
/// [`Response::Defer`](crate::net::server::Response::Defer), so a permit
/// stashed from another request closes the connection instead of parking
/// one nothing could resolve.
#[derive(Debug)]
#[must_use = "return HttpVerdict::Defer(permit) from the handler"]
pub struct HttpDeferPermit {
    permit: DeferPermit,
    req: Box<ParkedRequest>,
}

/// An owned, `Send` completion handle for a parked HTTP request. Exactly one
/// of the three methods consumes it; dropping it unresolved closes the
/// connection (the inner net handle's drop), so a lost or panicked worker
/// cannot leak a parked slot.
#[must_use = "dropping an HttpDeferred unresolved closes the connection"]
pub struct HttpDeferred {
    answer: Arc<Mutex<Option<ParkAnswer>>>,
    inner: Deferred,
}

impl HttpDeferred {
    /// Re-dispatch the retained request through the handler on the server
    /// thread: the second invocation sees the identical request view - for
    /// a worker that warmed the state the first pass was missing. The rerun
    /// may respond, defer again, or close.
    pub fn redrive(self) {
        self.inner.redeliver();
    }

    /// Complete the request with `resp`, built on the worker. Serialization
    /// still happens on the server thread against the request's own
    /// negotiated head facts - HEAD body elision, keep-alive vs close, the
    /// smuggling forced-close, the `Date` cache - so no response policy is
    /// duplicated off-thread.
    pub fn reply(self, resp: HttpResponse) {
        // The cell write happens-before the redeliver's channel send, so
        // the completion pass observes it (modelled by `loom_tests`).
        *self.answer.lock().unwrap_or_else(PoisonError::into_inner) =
            Some(ParkAnswer::Reply(Box::new(resp)));
        self.inner.redeliver();
    }

    /// Close the connection without a response.
    pub fn close(self) {
        self.inner.close();
    }
}

/// The completion handle of a [`defer_stream`](HttpRequest::defer_stream)
/// park: resume the stream, fail it, or close - never redrive, because the
/// park retained no body to re-run the handler on.
#[must_use = "dropping an HttpStreamDeferred unresolved closes the connection"]
pub struct HttpStreamDeferred {
    answer: Arc<Mutex<Option<ParkAnswer>>>,
    inner: Deferred,
}

impl HttpStreamDeferred {
    /// The parked window is dealt with: resume the stream at its next read.
    /// The handler is not re-run; the next thing it sees is the next
    /// window (or [`Stage::End`]).
    pub fn resume(self) {
        // The cell write happens-before the redeliver's channel send, so
        // the completion pass observes it (modelled by `loom_tests`).
        *self.answer.lock().unwrap_or_else(PoisonError::into_inner) =
            Some(ParkAnswer::Resume);
        self.inner.redeliver();
    }

    /// Refuse the stream with `resp` - a mid-body answer, so the reply is
    /// forced final and the connection flush-closes, exactly as an inline
    /// mid-body [`HttpVerdict::Respond`] would.
    pub fn fail(self, resp: HttpResponse) {
        *self.answer.lock().unwrap_or_else(PoisonError::into_inner) =
            Some(ParkAnswer::Reply(Box::new(resp)));
        self.inner.redeliver();
    }

    /// Close the connection without a response.
    pub fn close(self) {
        self.inner.close();
    }
}

impl std::fmt::Debug for HttpStreamDeferred {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpStreamDeferred").finish_non_exhaustive()
    }
}

impl std::fmt::Debug for HttpDeferred {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpDeferred").finish_non_exhaustive()
    }
}

// Moved into worker threads.
const _: fn() = || {
    fn assert_send<T: Send>() {}
    assert_send::<HttpDeferred>();
};

/// Wall-clock seconds for the `Date` header; the one impurity, kept at the
/// edge so everything under it stays deterministic.
fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Serialize `resp` against what `head` negotiated and pick the reactor
/// verdict: keep-alive replies, farewells flush-close. `dates` is the
/// per-reactor cache rendering the `Date` value once a second, not once a
/// response. `draining` forces the close: the reply goes out with a close
/// disposition, so the reactor discards anything buffered behind it and
/// closes once it is sent, and the head says so rather than let the peer
/// find out on its next request.
/// Force a reply to end the connection.
///
/// A response produced while a body is still arriving has abandoned the
/// rest of it: nothing will read those bytes, so a keep-alive answer would
/// leave the framer to take them for the next request - a desync that
/// presents to the client as a spurious second response. The keep-alive
/// disposition sits in a different field for each reply shape, which is why
/// this exists rather than a match at each of the three call sites: the one
/// that only handled `Response::Reply` silently missed every response with
/// a body, because those are `ReplyVectored`.
fn force_final(resp: Response) -> Response {
    match resp {
        Response::Reply(b) => Response::ReplyClose(b),
        Response::ReplyVectored { segments, .. } => Response::ReplyVectored {
            segments,
            close: true,
        },
        #[cfg(feature = "uring-fs")]
        Response::ReplyFile {
            head,
            file,
            offset,
            len,
            ..
        } => Response::ReplyFile {
            head,
            file,
            offset,
            len,
            close: true,
        },
        // Already final, or not a reply at all.
        other => other,
    }
}

fn respond(
    head: &Head<'_>,
    resp: HttpResponse,
    dates: &mut DateCache,
    draining: bool,
    // A reply made while a body is still arriving abandons the rest of it,
    // so the connection cannot persist and the header must say so - a peer
    // told keep-alive and then given EOF has to guess whether it was
    // answered or cut off.
    abandons_body: bool,
) -> Response {
    // A head carrying both Content-Length and Transfer-Encoding frames as
    // chunked here because the transfer coding wins under RFC 9112 section
    // 6.3. A front end that prefers Content-Length would frame the same
    // bytes with a different boundary, and that difference is the CL.TE
    // smuggling primitive. Keep the coding preference for client
    // compatibility and make the exchange non pipelinable instead. The
    // reply drops keep alive so no pipelined request rides behind a
    // smuggled prefix on this connection.
    let (keep_alive, cl_te_conflict) = head.response_disposition();
    let keep = keep_alive
        && !resp.close
        && !cl_te_conflict
        && !draining
        && !abandons_body;
    let conn = match (keep, head.version) {
        (true, Version::Http11) => ConnHeader::None,
        (true, Version::Http10) => ConnHeader::KeepAlive,
        (false, _) => ConnHeader::Close,
    };
    let head_only = head.method == "HEAD";
    match serialize_reply(resp, head_only, dates.get(now_secs()), conn) {
        // A response with a body hands its head and body as separate segments,
        // scattered vectored so the body is never copied into the head buffer;
        // a HEAD or bodyless response is just the head. Keep-alive vs close is
        // the same disposition either way.
        Serialized::Split {
            head: head_bytes,
            body,
        } => Response::ReplyVectored {
            segments: vec![head_bytes.into(), body.into()],
            close: !keep,
        },
        // A file-sourced body: the reactor streams it behind the head
        // (`HttpResponse::file_body`). The serializer already applied the
        // HEAD/bodyless elisions, so a tail reaching here always streams.
        #[cfg(feature = "uring-fs")]
        Serialized::FileTail {
            head: head_bytes,
            file,
            offset,
            len,
        } => Response::ReplyFile {
            head: head_bytes,
            file,
            offset,
            len,
            close: !keep,
        },
        Serialized::HeadOnly(bytes) => {
            if keep {
                Response::Reply(bytes)
            } else {
                Response::ReplyClose(bytes)
            }
        }
    }
}

/// The farewell for a connection the framer failed: a real status line, then
/// flush-close. Tiny text body so a captured trace is self-explanatory --
/// elided when the dying request was a HEAD (`head_only`), whose responses
/// must not carry content lest the client read the body bytes as the next
/// response's head.
fn farewell(status: u16, head_only: bool, dates: &mut DateCache) -> Response {
    let resp = HttpResponse::new(status).body(format!("error {status}\n"));
    Response::ReplyClose(serialize(
        &resp,
        head_only,
        dates.get(now_secs()),
        ConnHeader::Close,
    ))
}

/// The per-delivery fs facade threaded through [`step`] to every dispatching
/// arm: the reactor's request-bound
/// [`FsConn`](crate::uring_fs::FsConn) (`None` when the server has no fs
/// pool) under `uring-fs`.
#[cfg(feature = "uring-fs")]
pub(crate) type FsSlot<'a> = Option<crate::uring_fs::FsConn<'a>>;
/// Without `uring-fs`: a zero-sized placeholder, so [`dispatch`]/[`step`]
/// keep one shape and the handler bound one arity in both builds.
#[cfg(not(feature = "uring-fs"))]
pub(crate) type FsSlot<'a> = std::marker::PhantomData<&'a ()>;

/// A second facade over the slot, for the one arm that dispatches twice
/// (the window exhausting a known-length stream carries the End stage
/// too). The recv-buffer claim moves to the split-off facade.
#[cfg(feature = "uring-fs")]
fn split_slot<'s>(fs: &'s mut FsSlot<'_>) -> FsSlot<'s> {
    fs.as_mut().map(|c| c.reborrow())
}
#[cfg(not(feature = "uring-fs"))]
fn split_slot<'s>(fs: &'s mut FsSlot<'_>) -> FsSlot<'s> {
    *fs
}

/// What one handler invocation produced: a reactor verdict, or a park to
/// file into the connection's phase.
enum Dispatched {
    Done(Response),
    /// The consumer accepted a streamed delivery and wants the next one.
    Continue,
    Park {
        permit: DeferPermit,
        req: Box<ParkedRequest>,
    },
}

/// Re-parse a head the framer already accepted into the caller's array, or
/// the `500` farewell a re-parse divergence (a codec bug) is answered with.
/// Shared by the inline dispatch and the parked completion so the header-count
/// cap and the farewell shape cannot drift between them.
fn reparse_or_farewell<'a, 'buf>(
    head_bytes: &'buf [u8],
    headers: &'a mut [HeaderView<'buf>; MAX_HEADERS],
    dates: &mut DateCache,
) -> std::result::Result<Head<'a>, Response> {
    match parse_head(head_bytes, headers) {
        Err(_) | Ok(None) => {
            Err(farewell(500, method_is_head(head_bytes), dates))
        }
        Ok(Some(h)) => Ok(h),
    }
}

/// Parse a delivered head and run the consumer's handler against it - the
/// shared tail of the normal path, the 100-continue dance, and a parked
/// request's redelivery, so all three hand handlers an identical request
/// view by construction.
// The parts are the request itself plus the ticket, the connection state,
// and the serialization context; bundling them would be artificial here.
#[allow(clippy::too_many_arguments)]
fn dispatch<U, H>(
    head_bytes: &[u8],
    body: Body<'_>,
    trailers: &[HeaderView<'_>],
    peer: &ClientAddr,
    responder: Responder,
    fs: FsSlot<'_>,
    state: &mut U,
    dates: &mut DateCache,
    handler: &mut H,
    stage: Stage,
) -> Dispatched
where
    H: FnMut(HttpRequest<'_>, &mut U, FsSlot<'_>) -> HttpVerdict,
{
    let mut headers: [HeaderView<'_>; MAX_HEADERS] =
        [HeaderView::EMPTY; MAX_HEADERS];
    let h = match reparse_or_farewell(head_bytes, &mut headers, dates) {
        Ok(h) => h,
        Err(resp) => return Dispatched::Done(resp),
    };
    // Minted before the responder moves into the handler, read after it
    // returns: a handler that starts the drain itself (an admin shutdown
    // endpoint) still sends the close with its own reply.
    let drain = responder.drain_probe();
    match handler(
        HttpRequest {
            method: h.method,
            target: h.target,
            version: h.version,
            headers: h.headers,
            body,
            raw_head: head_bytes,
            trailers,
            peer,
            responder,
            stage,
        },
        state,
        fs,
    ) {
        HttpVerdict::Respond(resp) => {
            Dispatched::Done(respond(
                &h,
                resp,
                dates,
                drain.draining(),
                // A reply at Open or Window is a refusal: the body it
                // declined is still coming and nothing will read it.
                matches!(stage, Stage::Open | Stage::Window),
            ))
        }
        HttpVerdict::Defer(p) => Dispatched::Park {
            permit: p.permit,
            req: p.req,
        },
        // A delivery that owes a reply cannot be continued past: nothing
        // would ever answer it, and the connection would hang until a
        // timeout. Close rather than leak the slot.
        HttpVerdict::Continue if matches!(stage, Stage::Whole | Stage::End) => {
            Dispatched::Done(Response::Close)
        }
        HttpVerdict::Continue => Dispatched::Continue,
    }
}

/// Serialize a worker-built reply against the parked request's own head --
/// the same [`respond`] policy the inline path applies, so keep-alive, HEAD
/// elision, and the smuggling forced-close cannot fork between the two.
fn respond_parked(
    head_bytes: &[u8],
    resp: HttpResponse,
    dates: &mut DateCache,
    draining: bool,
    abandons_body: bool,
) -> Response {
    let mut headers: [HeaderView<'_>; MAX_HEADERS] =
        [HeaderView::EMPTY; MAX_HEADERS];
    match reparse_or_farewell(head_bytes, &mut headers, dates) {
        Ok(h) => respond(&h, resp, dates, draining, abandons_body),
        Err(farewell) => farewell,
    }
}

/// One delivered message against the connection's phase - the entire `body`
/// handler as a plain function (the closure in [`protocol_deferrable`] is a
/// one-line adapter), so tests exercise the real
/// dance/keep-alive/park/farewell code.
// The parts are the delivered message, its reply ticket and fs facade, the
// connection state, and the serialization context; bundling them would be
// artificial here (the same shape `dispatch` allows).
#[allow(clippy::too_many_arguments)]
fn step<U, H>(
    header: &[u8],
    mut body: Body<'_>,
    peer: &ClientAddr,
    responder: Responder,
    fs: FsSlot<'_>,
    conn: &mut HttpConn<U>,
    dates: &mut DateCache,
    handler: &mut H,
) -> Response
where
    H: FnMut(HttpRequest<'_>, &mut U, FsSlot<'_>) -> HttpVerdict,
{
    /// File a park into the phase, or pass the verdict through - the shared
    /// tail of every dispatching arm.
    fn settle<U>(
        conn: &mut HttpConn<U>,
        d: Dispatched,
        resume: Option<super::framer::StreamPark>,
    ) -> Response {
        match d {
            Dispatched::Done(resp) => resp,
            Dispatched::Park { permit, req } => {
                conn.phase = Phase::Parked {
                    req,
                    resume: resume.map(Box::new),
                };
                Response::Defer(permit)
            }
            // Only a streamed delivery produces this, and those arms handle
            // it themselves - reaching here would mean a request went
            // unanswered.
            Dispatched::Continue => Response::Close,
        }
    }
    match std::mem::replace(&mut conn.phase, Phase::Head) {
        // The framer's farewell: everything buffered was delivered as a
        // degenerate message; answer and flush-close. The HEAD flag rides
        // in the phase from the moment the failure was declared - after the
        // dance the head bytes are consumed and the delivered bytes are the
        // client's body, so sniffing them here would let a body that spells
        // "HEAD " force an incomplete farewell (and a real HEAD's farewell
        // grow a body its client would read as the next response).
        Phase::Fail { status, head_only } => farewell(status, head_only, dates),
        // Dance message 1: the head alone. Queue the interim line verbatim
        // (Reply sends raw bytes) and advance the phase; the framer will
        // declare the body next.
        Phase::ExpectHead { head, body } => {
            // A drain reads no body this connection has not started: the
            // interim would invite one and the connection would then close
            // under it. Refuse now, with a close, so the peer retries
            // elsewhere instead of sending into a connection that is gone.
            if responder.draining() {
                return farewell(503, method_is_head(&head), dates);
            }
            conn.phase = Phase::ExpectBody { head, body };
            Response::Reply(b"HTTP/1.1 100 Continue\r\n\r\n".to_vec())
        }
        // Dance message 2: the body alone, paired with the stash. (A
        // chunked dance never lands here - the framer morphs ExpectBody
        // into the scan phase before declaring anything.)
        Phase::ExpectBody { head: stash, .. } => {
            let d = dispatch(
                &stash,
                body,
                &[],
                peer,
                responder,
                fs,
                &mut conn.state,
                dates,
                handler,
                Stage::Whole,
            );
            settle(conn, d, None)
        }
        // A complete chunked message: de-chunk the wire extent, then
        // dispatch the entity against the in-buffer head or the dance's
        // stash. When the reactor handed the wire allocation over (the
        // dance delivers the body alone, and large bodies arrive owned),
        // de-chunk **in place**: ownership moves and the entity stays in
        // the same allocation - the single-chunk shape default botocore
        // sends moves no bytes at all, and the handler's take() truncates
        // instead of copying. A borrowed delivery keeps the borrowing
        // paths: a single-chunk entity is a borrow of the wire, only
        // stitched multi-chunk entities allocate. The framer's scan
        // accepted these exact bytes, so a de-chunk failure is a codec
        // bug, answered as one.
        Phase::ChunkedDone { stash } => {
            let head_bytes = stash.as_deref().unwrap_or(header);
            if let Some(mut wire) = body.try_take_owned() {
                return match chunked::compact(&mut wire) {
                    Ok(c) => match c.trailers() {
                        Ok(trailers) => {
                            let d = dispatch(
                                head_bytes,
                                Body::owned_range(wire, c.start, c.len),
                                &trailers,
                                peer,
                                responder,
                                fs,
                                &mut conn.state,
                                dates,
                                handler,
                                Stage::Whole,
                            );
                            settle(conn, d, None)
                        }
                        Err(()) => {
                            farewell(500, method_is_head(head_bytes), dates)
                        }
                    },
                    Err(()) => farewell(500, method_is_head(head_bytes), dates),
                };
            }
            match chunked::decode(&body) {
                Ok((entity, trailers)) => {
                    let entity = match entity {
                        Cow::Borrowed(span) => Body::inline(span),
                        Cow::Owned(v) => Body::placed(v),
                    };
                    let d = dispatch(
                        head_bytes,
                        entity,
                        &trailers,
                        peer,
                        responder,
                        fs,
                        &mut conn.state,
                        dates,
                        handler,
                        Stage::Whole,
                    );
                    settle(conn, d, None)
                }
                Err(()) => farewell(500, method_is_head(head_bytes), dates),
            }
        }
        // Mid-scan delivery cannot happen (the framer only answers `More`
        // in this phase); total for the same reason as Fail above.
        Phase::ChunkedBody { stash, .. } => farewell(
            500,
            method_is_head(stash.as_deref().unwrap_or(header)),
            dates,
        ),
        // The normal path: head + body in one message.
        Phase::Head => {
            let d = dispatch(
                header,
                body,
                &[],
                peer,
                responder,
                fs,
                &mut conn.state,
                dates,
                handler,
                Stage::Whole,
            );
            settle(conn, d, None)
        }
        // A parked request's completion, arriving as a redelivery (the frame
        // is empty; everything real was retained at the park). A worker
        // `reply` left the response in the cell - serialize it against the
        // retained head. Otherwise this is a `redrive`: run the handler
        // again over the identical request view; it may respond, park
        // again, or close.
        // A streamed body opens with its head and no bytes. This is the
        // consumer's one chance to refuse before the peer commits to
        // sending - and when the client asked for `100-continue`, the
        // interim line is withheld until the consumer has actually
        // accepted, so a refusal goes out *instead* of it rather than
        // after inviting a body nobody wanted.
        Phase::StreamOpen { head, expect, body } => {
            if responder.draining() {
                return farewell(503, method_is_head(&head), dates);
            }
            let next = match body {
                super::framer::StreamedBody::Chunked => Phase::StreamBody {
                    head: head.clone(),
                    chunk_left: 0,
                    after_payload: false,
                    decoded: 0,
                },
                super::framer::StreamedBody::Known(len) => Phase::StreamKnown {
                    head: head.clone(),
                    remaining: len,
                },
            };
            let d = dispatch(
                &head,
                Body::inline(&[]),
                &[],
                peer,
                responder,
                fs,
                &mut conn.state,
                dates,
                handler,
                Stage::Open,
            );
            match d {
                Dispatched::Continue => {
                    conn.phase = next;
                    if expect {
                        Response::Reply(
                            b"HTTP/1.1 100 Continue\r\n\r\n".to_vec(),
                        )
                    } else {
                        Response::Reply(Vec::new())
                    }
                }
                // Refused, or parked to decide off-thread. A refusal is
                // final: the body it declined is still coming and nothing
                // will read it, so the reply closes rather than leaves the
                // connection framing a body against the next request.
                Dispatched::Done(resp) => force_final(resp),
                d => settle(
                    conn,
                    d,
                    Some(super::framer::StreamPark {
                        next,
                        stage: Stage::Open,
                        // The interim was withheld pending this very
                        // decision; the resume owes it, or the client
                        // never sends the body it is parked deciding on.
                        expect_interim: expect,
                    }),
                ),
            }
        }
        // One chunk of a streamed body. Nothing is retained between
        // windows: the reactor's `consume` drops each one, which is what
        // stops the body's size bounding what the server can accept.
        Phase::StreamBody {
            head,
            chunk_left,
            after_payload,
            decoded,
        } => {
            let delivered = body.len();
            // How much of this chunk is still owed. Mid-chunk the answer is
            // carried; on a chunk's first window it comes from re-reading
            // the size line, which is exactly what `header` holds. The
            // framer cannot leave it here instead: it re-runs for the same
            // window while the payload arrives, and a second run would then
            // take the mid-chunk branch and declare a different message.
            let owed = if chunk_left > 0 {
                chunk_left
            } else {
                match chunked::step(header, after_payload) {
                    chunked::Step::Chunk { payload, .. } => payload,
                    // The framer accepted these bytes a moment ago, so a
                    // disagreement is a codec bug; treat the window as the
                    // whole chunk rather than desync on it.
                    _ => delivered,
                }
            };
            let left = owed.saturating_sub(delivered);
            let next = Phase::StreamBody {
                head: head.clone(),
                chunk_left: left,
                // Only a fully delivered chunk owes the CRLF that closes
                // it; a split one is still mid-payload.
                after_payload: left == 0,
                // Counted here, once per delivery, because the framer
                // re-runs for the same window while its bytes arrive.
                decoded: decoded.saturating_add(delivered),
            };
            let d = dispatch(
                &head,
                body,
                &[],
                peer,
                responder,
                fs,
                &mut conn.state,
                dates,
                handler,
                Stage::Window,
            );
            match d {
                Dispatched::Continue => {
                    conn.phase = next;
                    Response::Reply(Vec::new())
                }
                Dispatched::Done(resp) => force_final(resp),
                d => settle(
                    conn,
                    d,
                    Some(super::framer::StreamPark {
                        next,
                        stage: Stage::Window,
                        // Mid-body: any interim went out when the open was
                        // answered.
                        expect_interim: false,
                    }),
                ),
            }
        }
        // One window of a known-length streamed body: raw payload, no
        // framing of its own, counted down against the declared length.
        // The delivery that exhausts the length also carries the End
        // stage: no wire byte is left to frame one from (the reactor
        // refuses a zero-length message), so it runs here on the spot -
        // or, if this window parks, when the park resumes.
        Phase::StreamKnown { head, remaining } => {
            let left = remaining.saturating_sub(body.len() as u64);
            let mut fs = fs;
            let d = dispatch(
                &head,
                body,
                &[],
                peer,
                responder.split(),
                split_slot(&mut fs),
                &mut conn.state,
                dates,
                handler,
                Stage::Window,
            );
            match d {
                Dispatched::Continue if left == 0 => {
                    let d = dispatch(
                        &head,
                        Body::inline(&[]),
                        &[],
                        peer,
                        responder,
                        fs,
                        &mut conn.state,
                        dates,
                        handler,
                        Stage::End,
                    );
                    settle(conn, d, None)
                }
                Dispatched::Continue => {
                    conn.phase = Phase::StreamKnown {
                        head,
                        remaining: left,
                    };
                    Response::Reply(Vec::new())
                }
                Dispatched::Done(resp) => force_final(resp),
                d => settle(
                    conn,
                    d,
                    Some(super::framer::StreamPark {
                        // An exhausted length owes only the End stage;
                        // `StreamDone` is what the resume arm reads as
                        // "dispatch it now, nothing further to frame".
                        next: if left == 0 {
                            // A known-length body has no terminal block at
                            // all; the End stage is dispatched from the
                            // resume with nothing to parse.
                            Phase::StreamDone { head, block_at: 0 }
                        } else {
                            Phase::StreamKnown {
                                head,
                                remaining: left,
                            }
                        },
                        stage: Stage::Window,
                        // Mid-body: any interim went out when the open was
                        // answered.
                        expect_interim: false,
                    }),
                ),
            }
        }
        // The terminal chunk: the delivered header IS the trailer section,
        // so the trailers are parsed from it here rather than carried.
        Phase::StreamDone { head, block_at } => {
            // The terminal block is itself a complete (empty) chunked
            // message, so the whole-message compactor parses its trailer
            // section. It has to outlive the dispatch: the views borrow it.
            // `block_at` skips the CRLF that closed the last payload, which
            // the compactor would read as an empty - malformed - size line
            // and refuse, losing every trailer with it.
            let mut wire = header[block_at.min(header.len())..].to_vec();
            let compacted = chunked::compact(&mut wire).ok();
            let trailers = compacted
                .as_ref()
                .and_then(|c| c.trailers().ok())
                .unwrap_or_default();
            let d = dispatch(
                &head,
                Body::inline(&[]),
                &trailers,
                peer,
                responder,
                fs,
                &mut conn.state,
                dates,
                handler,
                Stage::End,
            );
            settle(conn, d, None)
        }
        Phase::Parked { req, resume } => {
            let ParkedRequest {
                head,
                body: parked,
                trailers,
                answer,
            } = *req;
            let chosen =
                answer.lock().unwrap_or_else(PoisonError::into_inner).take();
            match chosen {
                // The stream's parked window is dealt with: back to reading,
                // nothing to send, handler not re-run. A resume with no
                // streaming phase to put back is a misuse of `defer_stream`
                // outside a stream - nothing can be resumed, so close.
                Some(ParkAnswer::Resume) => match resume {
                    // A known-length stream whose exhausting window parked:
                    // the length is fully consumed, so nothing remains to
                    // frame an End delivery from. Dispatch it here instead,
                    // off the resume itself.
                    Some(r) if matches!(r.next, Phase::StreamDone { .. }) => {
                        let d = dispatch(
                            &head,
                            Body::inline(&[]),
                            &[],
                            peer,
                            responder,
                            fs,
                            &mut conn.state,
                            dates,
                            handler,
                            Stage::End,
                        );
                        settle(conn, d, None)
                    }
                    Some(r) => {
                        conn.phase = r.next;
                        // A deferred open accepted: release the withheld
                        // interim, or the expecting client holds its body
                        // back until its own timeout and the stream this
                        // resume opened never starts.
                        Response::Reply(if r.expect_interim {
                            b"HTTP/1.1 100 Continue\r\n\r\n".to_vec()
                        } else {
                            Vec::new()
                        })
                    }
                    None => Response::Close,
                },
                Some(ParkAnswer::Reply(resp)) => {
                    let resp = *resp;
                    let out = respond_parked(
                        &head,
                        resp,
                        dates,
                        responder.draining(),
                        // A park taken mid-body that answers has abandoned
                        // the rest of it, exactly as an inline reply there
                        // would have.
                        resume.is_some(),
                    );
                    // A worker that answered mid-body abandoned a body the
                    // peer is still sending. Nothing can read the rest, so
                    // the reply is final: send it and flush-close, rather
                    // than resume framing bytes that belong to a request
                    // already answered.
                    match resume {
                        Some(_) => force_final(out),
                        None => out,
                    }
                }
                None => {
                    let views: Vec<HeaderView<'_>> = trailers
                        .iter()
                        .map(|(n, v)| HeaderView { name: n, value: v })
                        .collect();
                    let stage =
                        resume.as_ref().map_or(Stage::Whole, |r| r.stage);
                    // The handles are split because a redriven window that
                    // exhausted a known length owes an End dispatch as well
                    // (below), exactly as the inline path does.
                    let mut fs = fs;
                    let d = dispatch(
                        &head,
                        Body::placed(parked),
                        &views,
                        peer,
                        responder.split(),
                        split_slot(&mut fs),
                        &mut conn.state,
                        dates,
                        handler,
                        stage,
                    );
                    match (d, resume) {
                        // Redriven and accepted with content to read on:
                        // put the streaming phase back, and release any
                        // interim a parked open was still withholding -
                        // the redrive route owes it exactly as the resume
                        // route does.
                        //
                        // `StreamDone` is not a phase to restore. It marks a
                        // known length already spent, so no wire remains to
                        // frame an End delivery from - and the framer's
                        // degrade arm would declare whatever is buffered,
                        // i.e. the *next* pipelined request's head, as this
                        // message's header. Dispatch End here instead, which
                        // is what the resume route does with the same marker.
                        (Dispatched::Continue, Some(r))
                            if matches!(r.next, Phase::StreamDone { .. }) =>
                        {
                            let d = dispatch(
                                &head,
                                Body::inline(&[]),
                                &[],
                                peer,
                                responder,
                                fs,
                                &mut conn.state,
                                dates,
                                handler,
                                Stage::End,
                            );
                            settle(conn, d, None)
                        }
                        (Dispatched::Continue, Some(r)) => {
                            conn.phase = r.next;
                            Response::Reply(if r.expect_interim {
                                b"HTTP/1.1 100 Continue\r\n\r\n".to_vec()
                            } else {
                                Vec::new()
                            })
                        }
                        (d, resume) => settle(conn, d, resume.map(|r| *r)),
                    }
                }
            }
        }
    }
}

/// The shared constructor behind [`protocol`], [`protocol_deferrable`], and
/// `protocol_fs`: one body closure, one [`step`], with the handler taking
/// the per-delivery [`FsSlot`] so the phase machine keeps a single shape.
/// Each public constructor adapts its own handler bound down to this one --
/// only `protocol_fs` is feature-gated, so every feature builds alone.
#[allow(clippy::type_complexity)]
fn build<U, A, H>(
    cfg: HttpConfig,
    stream_cap: Option<u64>,
    mut accept: A,
    mut handler: H,
) -> crate::Result<
    Protocol<
        impl FnMut(Incoming<'_>) -> Option<HttpConn<U>>,
        impl FnMut(&[u8], &mut HttpConn<U>) -> crate::net::Framing,
        impl FnMut(Request<'_, HttpConn<U>>) -> Response,
    >,
>
where
    A: FnMut(Incoming<'_>) -> Option<U>,
    H: FnMut(HttpRequest<'_>, &mut U, FsSlot<'_>) -> HttpVerdict,
{
    cfg.validate()?;
    // One date cache per protocol instance - instances are per reactor and
    // handlers run on the reactor thread, so the `Date` value renders once
    // a second instead of once a response, with no synchronization.
    let mut dates = DateCache::default();
    Ok(Protocol {
        accept: move |inc: Incoming<'_>| {
            accept(inc).map(|state| match stream_cap {
                Some(cap) => HttpConn::new_streaming(state, cap),
                None => HttpConn::new(state),
            })
        },
        header: move |buf: &[u8], conn: &mut HttpConn<U>| {
            // The accept wrapper above is not the only admission. A kTLS
            // listener is admitted by `AcceptDeferral::ready`, which takes
            // the connection state directly and never runs it
            // (`net/server/accept.rs`: `install_conn` has exactly two
            // callers, and only the plain-TCP one goes through the accept
            // handler). A worker that hands back `HttpConn::new` there
            // would otherwise get a connection with no cap at all - and
            // `stream_cap` is not merely the streaming switch, it *is* the
            // body limit, so the ceiling would silently become
            // `HttpConfig::max_body` instead of the `max_body_bytes` this
            // protocol was built with. A limit that holds on one transport
            // and not the other is worse than no limit: a deployment sets
            // it, tests it over plain HTTP and ships it.
            //
            // Adopting it here rather than at admission covers every route
            // in, present and future. Safe at this point by construction -
            // `HttpConn::new` leaves `Phase::Head`, so no body is ever in
            // progress the first time this runs - and `is_none` leaves a
            // connection minted `new_streaming` with its own cap.
            if conn.stream_cap.is_none() {
                conn.stream_cap = stream_cap;
            }
            frame(buf, conn, &cfg)
        },
        body: move |req: Request<'_, HttpConn<U>>| {
            #[cfg(feature = "uring-fs")]
            let fs = req.fs;
            #[cfg(not(feature = "uring-fs"))]
            let fs = FsSlot::default();
            let Request {
                header,
                body,
                peer,
                state: conn,
                responder,
                ..
            } = req;
            step(
                header,
                body,
                peer,
                responder,
                fs,
                conn,
                &mut dates,
                &mut handler,
            )
        },
    })
}

/// Build the reactor [`Protocol`] for an HTTP/1.1 endpoint whose handler may
/// also reach the server's **request-bound fs facade**.
///
/// The handler is [`protocol_deferrable`]'s with one more argument: the
/// reactor's per-request [`FsConn`](crate::uring_fs::FsConn) - `Some` when
/// the server was built with an fs pool
/// ([`ServerConfig::fs_ops`](crate::net::server::ServerConfig::fs_ops)),
/// else `None`. A `Protocol` is built before its `Server`, so this
/// constructor cannot check; for a handler that asked for this constructor,
/// `None` is a deployment misconfiguration, and answering `500` is the
/// honest response.
///
/// The consumer's model, in full:
///
/// - **The facade is per delivery.** It borrows the reactor for the call and
///   cannot be stored; every invocation of the handler - first delivery or
///   redelivery - receives a fresh one.
/// - **Fs work parks the request.** Take the facade, then
///   [`HttpRequest::defer`] the request (defer consumes it), capture the
///   [`HttpDeferred`] in the op's continuation, and return
///   [`HttpVerdict::Defer`]; the continuation, or a later offload delivery,
///   resolves it via [`HttpDeferred::reply`].
/// - **A continuation may `open`, and owns what it opens.**
///   [`open`](crate::uring_fs::FsConn::open) works on every facade,
///   including the one a continuation or offload delivery receives. That
///   facade runs for an owner that may already be gone, and nothing
///   sweeps a descriptor opened after its connection closed, so a chain
///   that opens must reach a step that closes. A handler that would
///   rather re-enter with a fresh delivery can still park its progress
///   in the connection state `U` and call [`HttpDeferred::redrive`].
/// - **Offload jobs are never cancelled**
///   ([`FsConn::offload`](crate::uring_fs::FsConn::offload)): a delivery
///   may fire for a request that is gone, and a resolved [`HttpDeferred`]
///   for a vanished request is a generation-checked no-op rather than a
///   hazard.
///
/// The parking discipline is [`protocol_deferrable`]'s, including its
/// `max_in_flight_requests` guidance. Errors when `cfg` fails
/// [`HttpConfig::validate`].
#[cfg(feature = "uring-fs")]
#[allow(clippy::type_complexity)]
pub fn protocol_fs<U, A, H>(
    cfg: HttpConfig,
    accept: A,
    handler: H,
) -> crate::Result<
    Protocol<
        impl FnMut(Incoming<'_>) -> Option<HttpConn<U>>,
        impl FnMut(&[u8], &mut HttpConn<U>) -> crate::net::Framing,
        impl FnMut(Request<'_, HttpConn<U>>) -> Response,
    >,
>
where
    A: FnMut(Incoming<'_>) -> Option<U>,
    H: FnMut(
        HttpRequest<'_>,
        &mut U,
        Option<crate::uring_fs::FsConn<'_>>,
    ) -> HttpVerdict,
{
    build(cfg, None, accept, handler)
}

/// Build the reactor [`Protocol`] for an HTTP/1.1 endpoint whose handler
/// may **park** a request for deferred completion.
///
/// `accept` is the standard admission hook returning the consumer's
/// per-connection state `U`; `handler` runs once per delivery with the
/// parsed [`HttpRequest`] view and `&mut U`, and returns an
/// [`HttpVerdict`]: [`Respond`](HttpVerdict::Respond) answers inline
/// (exactly a [`protocol`] handler), or - after [`HttpRequest::defer`] --
/// [`Defer`](HttpVerdict::Defer) parks the request while the reactor keeps
/// polling. The worker then completes it through the [`HttpDeferred`]:
/// [`redrive`](HttpDeferred::redrive) re-runs the handler on the server
/// thread once state is warm, [`reply`](HttpDeferred::reply) delivers a
/// worker-built response (serialized on the server thread), and
/// [`close`](HttpDeferred::close) hangs up. Handlers still run on the
/// server thread and must not block.
///
/// Intended for the default `max_in_flight_requests == 1`: while a request
/// is parked nothing later is read or delivered, so reply order is request
/// order. Above that cap the framer still holds pipelined requests back
/// during a park, but the armed read-ahead then carries `request_timeout`
/// while parked - run deferrable endpoints at the default cap.
///
/// Errors when `cfg` fails [`HttpConfig::validate`] - a codec that can
/// admit no request is refused here, not discovered one 431 at a time.
// Same shape and rationale as `length_prefixed`: the three opaque closures
// ARE the signature; boxing them would put dyn dispatch on the hot path.
#[allow(clippy::type_complexity)]
pub fn protocol_deferrable<U, A, H>(
    cfg: HttpConfig,
    accept: A,
    mut handler: H,
) -> crate::Result<
    Protocol<
        impl FnMut(Incoming<'_>) -> Option<HttpConn<U>>,
        impl FnMut(&[u8], &mut HttpConn<U>) -> crate::net::Framing,
        impl FnMut(Request<'_, HttpConn<U>>) -> Response,
    >,
>
where
    A: FnMut(Incoming<'_>) -> Option<U>,
    H: FnMut(HttpRequest<'_>, &mut U) -> HttpVerdict,
{
    build(
        cfg,
        None,
        accept,
        move |req: HttpRequest<'_>, state: &mut U, _fs: FsSlot<'_>| {
            handler(req, state)
        },
    )
}

/// Build the reactor [`Protocol`] for an HTTP/1.1 endpoint that **streams**
/// request bodies rather than buffering them.
///
/// A chunked body is delivered a chunk at a time instead of once when its
/// terminal chunk lands, and a `Content-Length` body above one window a
/// window at a time, so the largest body the endpoint accepts stops being
/// a buffer size. The handler walks [`Stage::Open`] (the head, before any
/// body byte), then [`Stage::Window`] per chunk or window, then
/// [`Stage::End`] once any trailers are parsed - and answers with
/// [`HttpVerdict::Continue`] until `End`, where the response belongs.
///
/// `max_body_bytes` bounds the body: for chunked the decoded size, checked
/// as each chunk is declared; for `Content-Length` the declared length,
/// checked at the head. It is a parameter rather than a field on
/// [`HttpConfig`] because [`HttpConfig::max_body`] is the bound a
/// *buffered* delivery checks before reading; whoever knows the protocol
/// above knows this number (an S3 front bounds a part at 5 GiB).
///
/// # What a streamed request does differently
///
/// - **A refusal closes the connection.** The body it declined is still
///   being sent and nothing will read it, so a keep-alive reply would frame
///   the remainder as the next request. That applies to a refusal at `Open`
///   and to one mid-body alike.
/// - **`Expect: 100-continue` is answered by the handler, not ahead of it.**
///   The interim line is withheld until the handler returns
///   [`HttpVerdict::Continue`] from `Open`, so a refusal goes out *instead*
///   of the interim rather than after having invited a body. (A
///   `Content-Length` body at or under one window takes the buffered path,
///   where the interim invites at most one window's worth - there is no
///   stream for a veto to save.)
/// - **Nothing is retained between windows.** Each window's payload is
///   dropped once the handler returns, so a handler that needs the body
///   must consume it as it arrives.
///
/// Errors when `cfg` fails [`HttpConfig::validate`].
///
/// **A kTLS listener needs the cap passed by hand.** The streaming
/// decision is made in this function's accept closure, and a kTLS
/// connection is admitted by `AcceptDeferral::ready` instead - the
/// accept handler never runs for one. A handshake worker that hands
/// back [`HttpConn::new`] therefore gets a buffering connection whose
/// effective ceiling is `max_request_bytes`; use
/// [`HttpConn::new_streaming`] with `max_body_bytes` there.
#[allow(clippy::type_complexity)]
pub fn protocol_streaming<U, A, H>(
    cfg: HttpConfig,
    max_body_bytes: u64,
    accept: A,
    mut handler: H,
) -> crate::Result<
    Protocol<
        impl FnMut(Incoming<'_>) -> Option<HttpConn<U>>,
        impl FnMut(&[u8], &mut HttpConn<U>) -> crate::net::Framing,
        impl FnMut(Request<'_, HttpConn<U>>) -> Response,
    >,
>
where
    A: FnMut(Incoming<'_>) -> Option<U>,
    H: FnMut(HttpRequest<'_>, &mut U) -> HttpVerdict,
{
    build(
        cfg,
        Some(max_body_bytes),
        accept,
        move |req: HttpRequest<'_>, state: &mut U, _fs: FsSlot<'_>| {
            handler(req, state)
        },
    )
}

/// [`protocol_streaming`] with the per-request fs facade, as `protocol_fs`
/// is to [`protocol_deferrable`] - a streaming handler that writes what it
/// receives needs somewhere to put each window, and that is the ring the
/// server already drives.
///
/// Errors when `cfg` fails [`HttpConfig::validate`].
///
/// **A kTLS listener needs the cap passed by hand.** The streaming
/// decision is made in this function's accept closure, and a kTLS
/// connection is admitted by `AcceptDeferral::ready` instead - the
/// accept handler never runs for one. A handshake worker that hands
/// back [`HttpConn::new`] therefore gets a buffering connection whose
/// effective ceiling is `max_request_bytes`; use
/// [`HttpConn::new_streaming`] with `max_body_bytes` there.
#[cfg(feature = "uring-fs")]
#[allow(clippy::type_complexity)]
pub fn protocol_streaming_fs<U, A, H>(
    cfg: HttpConfig,
    max_body_bytes: u64,
    accept: A,
    handler: H,
) -> crate::Result<
    Protocol<
        impl FnMut(Incoming<'_>) -> Option<HttpConn<U>>,
        impl FnMut(&[u8], &mut HttpConn<U>) -> crate::net::Framing,
        impl FnMut(Request<'_, HttpConn<U>>) -> Response,
    >,
>
where
    A: FnMut(Incoming<'_>) -> Option<U>,
    H: FnMut(
        HttpRequest<'_>,
        &mut U,
        Option<crate::uring_fs::FsConn<'_>>,
    ) -> HttpVerdict,
{
    build(cfg, Some(max_body_bytes), accept, handler)
}

/// Build the reactor [`Protocol`] for an HTTP/1.1 endpoint.
///
/// `accept` is the standard admission hook returning the consumer's
/// per-connection state `U`; `handler` is invoked once per request with the
/// parsed [`HttpRequest`] view and `&mut U`, and returns the
/// [`HttpResponse`] to serialize. Handlers run on the server thread --
/// compute inline like any reactor `body` handler; a handler that must
/// wait on other threads uses [`protocol_deferrable`] instead, and one
/// that must also touch the filesystem, `protocol_fs` (with the
/// `uring-fs` feature).
///
/// Errors when `cfg` fails [`HttpConfig::validate`].
#[allow(clippy::type_complexity)]
pub fn protocol<U, A, H>(
    cfg: HttpConfig,
    accept: A,
    mut handler: H,
) -> crate::Result<
    Protocol<
        impl FnMut(Incoming<'_>) -> Option<HttpConn<U>>,
        impl FnMut(&[u8], &mut HttpConn<U>) -> crate::net::Framing,
        impl FnMut(Request<'_, HttpConn<U>>) -> Response,
    >,
>
where
    A: FnMut(Incoming<'_>) -> Option<U>,
    H: FnMut(HttpRequest<'_>, &mut U) -> HttpResponse,
{
    protocol_deferrable(cfg, accept, move |req: HttpRequest<'_>, state| {
        HttpVerdict::Respond(handler(req, state))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::framer::{Phase, STREAM_WINDOW};
    use crate::net::Framing;

    /// A streaming protocol streams - and bounds - a connection its accept
    /// wrapper never minted.
    ///
    /// A kTLS listener is admitted by `AcceptDeferral::ready`, which takes
    /// the connection state directly and never runs the accept handler, so
    /// a handshake worker can hand back `HttpConn::new`. `stream_cap` is
    /// not merely the streaming switch - it *is* the body limit and it
    /// lifts `HttpConfig::max_body` - so without this the endpoint's
    /// declared `max_body_bytes` would not apply on the TLS transport at
    /// all, and the effective ceiling would be `max_body` instead. A limit
    /// that holds on one transport and not the other is worse than no
    /// limit.
    #[test]
    fn a_streaming_protocol_bounds_a_connection_it_did_not_mint() {
        let cfg = HttpConfig {
            max_head: 1024,
            max_body: 8 * 1024 * 1024,
        };
        const CAP: u64 = 256 * 1024;
        assert!(
            CAP as usize > STREAM_WINDOW && (CAP as usize) < cfg.max_body,
            "the cap has to sit between the window and `max_body` for \
             either assertion below to mean anything"
        );
        let mut proto = protocol_streaming(
            cfg,
            CAP,
            |_i: Incoming<'_>| Some(()),
            |_r: HttpRequest<'_>, _s: &mut ()| HttpVerdict::Continue,
        )
        .expect("build");

        // A body over one window streams, on a connection minted the way a
        // kTLS handshake worker mints one.
        let mut conn = HttpConn::new(());
        let head = format!(
            "PUT /k HTTP/1.1\r\nHost: h\r\nContent-Length: {}\r\n\r\n",
            STREAM_WINDOW + 1
        );
        assert_eq!(
            (proto.header)(head.as_bytes(), &mut conn),
            Framing::Complete {
                header_len: head.len(),
                body_len: 0
            }
        );
        assert!(
            matches!(conn.phase, Phase::StreamOpen { .. }),
            "buffered a body the protocol was built to stream: {:?}",
            conn.phase
        );

        // And the cap is the cap, not `max_body`.
        let mut conn = HttpConn::new(());
        let head = format!(
            "PUT /k HTTP/1.1\r\nHost: h\r\nContent-Length: {}\r\n\r\n",
            CAP + 1
        );
        let _ = (proto.header)(head.as_bytes(), &mut conn);
        assert!(
            matches!(conn.phase, Phase::Fail { status: 413, .. }),
            "a body over `max_body_bytes` was admitted against \
             `HttpConfig::max_body` instead: {:?}",
            conn.phase
        );

        // A connection the wrapper *did* mint keeps its own cap - this must
        // adopt, never overwrite.
        let mut conn = HttpConn::new_streaming((), 1024);
        let head =
            b"PUT /k HTTP/1.1\r\nHost: h\r\nContent-Length: 2048\r\n\r\n";
        let _ = (proto.header)(head, &mut conn);
        assert!(
            matches!(conn.phase, Phase::Fail { status: 413, .. }),
            "the protocol's cap overwrote the connection's own: {:?}",
            conn.phase
        );
    }

    /// [`step`] with a throwaway date cache and responder - the tests assert
    /// nothing about `Date` freshness (pinned in `date.rs`) or the injection
    /// channel (pinned in the net-layer tests). Plain-response handlers ride
    /// the same `Respond` wrapper [`protocol`] applies.
    fn drive<U, H>(
        header: &[u8],
        body: Body<'_>,
        peer: &ClientAddr,
        conn: &mut HttpConn<U>,
        handler: &mut H,
    ) -> Response
    where
        H: FnMut(HttpRequest<'_>, &mut U) -> HttpResponse,
    {
        drive_verdict(header, body, peer, conn, &mut |req, state| {
            HttpVerdict::Respond(handler(req, state))
        })
    }

    /// [`drive`] for verdict handlers - the park tests' entry.
    fn drive_verdict<U, H>(
        header: &[u8],
        body: Body<'_>,
        peer: &ClientAddr,
        conn: &mut HttpConn<U>,
        handler: &mut H,
    ) -> Response
    where
        H: FnMut(HttpRequest<'_>, &mut U) -> HttpVerdict,
    {
        step(
            header,
            body,
            peer,
            Responder::test_responder(),
            FsSlot::default(),
            conn,
            &mut DateCache::default(),
            &mut |req, state, _fs: FsSlot<'_>| handler(req, state),
        )
    }

    fn peer() -> ClientAddr {
        ClientAddr::Inet("127.0.0.1:9000".parse().unwrap())
    }

    fn cfg() -> HttpConfig {
        HttpConfig::default()
    }

    /// Reply bytes as text, whatever the verdict - a vectored reply is
    /// flattened, since on the wire its segments are one contiguous PDU.
    fn text(resp: &Response) -> String {
        let bytes = match resp {
            Response::Reply(b) | Response::ReplyClose(b) => b.clone(),
            Response::ReplyVectored { segments, .. } => {
                segments.iter().fold(Vec::new(), |mut all, seg| {
                    all.extend_from_slice(seg);
                    all
                })
            }
            other => panic!("expected reply bytes, got {other:?}"),
        };
        String::from_utf8(bytes).expect("responses are ascii here")
    }

    /// A keep-alive reply (`Reply`, or a vectored reply that keeps serving).
    fn is_keep(resp: &Response) -> bool {
        matches!(
            resp,
            Response::Reply(_) | Response::ReplyVectored { close: false, .. }
        )
    }

    /// A flush-close reply (`ReplyClose`, or a vectored reply that closes).
    fn is_close(resp: &Response) -> bool {
        matches!(
            resp,
            Response::ReplyClose(_)
                | Response::ReplyVectored { close: true, .. }
        )
    }

    /// Frame one complete single-message request and run the glue on it,
    /// mirroring the reactor's consume: `header` is the declared head,
    /// `body` the declared body bytes.
    fn roundtrip<U>(
        raw: &[u8],
        conn: &mut HttpConn<U>,
        handler: &mut impl FnMut(HttpRequest<'_>, &mut U) -> HttpResponse,
    ) -> Response {
        let verdict = frame(raw, conn, &cfg());
        let Framing::Complete {
            header_len,
            body_len,
        } = verdict
        else {
            panic!("expected a complete frame, got {verdict:?}");
        };
        assert_eq!(header_len + body_len, raw.len());
        let p = peer();
        drive(
            &raw[..header_len],
            Body::inline(&raw[header_len..]),
            &p,
            conn,
            handler,
        )
    }

    #[test]
    fn protocol_rejects_a_codec_that_admits_nothing() {
        // The validator runs when the protocol is built, so a zero cap is
        // a construction error, not a server that 431s/413s every request.
        let bad = HttpConfig {
            max_head: 0,
            max_body: 1024,
        };
        assert!(
            protocol(
                bad,
                |_: Incoming<'_>| Some(()),
                |_: HttpRequest<'_>, _: &mut ()| HttpResponse::new(200),
            )
            .is_err()
        );
    }

    #[test]
    fn get_roundtrip_keeps_alive() {
        let mut conn = HttpConn::new(0u32);
        let mut handler = |req: HttpRequest<'_>, hits: &mut u32| {
            *hits += 1;
            assert_eq!(req.method, "GET");
            assert_eq!(req.target, "/hi");
            HttpResponse::new(200).body("hello")
        };
        let resp = roundtrip(
            b"GET /hi HTTP/1.1\r\nHost: h\r\n\r\n",
            &mut conn,
            &mut handler,
        );
        assert!(is_keep(&resp));
        let s = text(&resp);
        assert!(s.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(s.contains("Content-Length: 5\r\n"));
        assert!(!s.contains("Connection:"));
        assert!(s.ends_with("\r\n\r\nhello"));
        assert_eq!(conn.state, 1);
        assert!(matches!(conn.phase, Phase::Head));
    }

    #[test]
    fn a_body_response_splits_head_and_body_into_segments() {
        // A response carrying a body is handed over as separate head and body
        // segments (sent vectored, never concatenated); flattened they are a
        // well-formed response with the body after the head.
        let mut handler = |_: HttpRequest<'_>, _: &mut ()| {
            HttpResponse::new(200).body("hello, body")
        };
        let resp = roundtrip(
            b"GET /x HTTP/1.1\r\nHost: h\r\n\r\n",
            &mut HttpConn::new(()),
            &mut handler,
        );
        let Response::ReplyVectored { segments, close } = &resp else {
            panic!("a body response must be vectored, got {resp:?}");
        };
        assert!(!close, "keep-alive request -> no close");
        assert_eq!(segments.len(), 2, "head + body");
        assert!(segments[0].starts_with(b"HTTP/1.1 200 OK\r\n"));
        assert!(
            segments[0].ends_with(b"\r\n\r\n"),
            "head ends at blank line"
        );
        assert_eq!(&segments[1][..], b"hello, body", "body is its own segment");
        let s = text(&resp);
        assert!(s.contains("Content-Length: 11\r\n"));
        assert!(s.ends_with("\r\n\r\nhello, body"));
    }

    #[test]
    fn a_bodyless_response_stays_one_buffer() {
        // No body (an empty-body 200, and a status that forbids one) -> a
        // single head buffer, not a vectored reply.
        let mut empty = |_: HttpRequest<'_>, _: &mut ()| HttpResponse::new(200);
        let resp = roundtrip(
            b"GET / HTTP/1.1\r\nHost: h\r\n\r\n",
            &mut HttpConn::new(()),
            &mut empty,
        );
        assert!(matches!(resp, Response::Reply(_)), "empty body: {resp:?}");
        let mut no_content =
            |_: HttpRequest<'_>, _: &mut ()| HttpResponse::new(204);
        let resp = roundtrip(
            b"GET / HTTP/1.1\r\nHost: h\r\n\r\n",
            &mut HttpConn::new(()),
            &mut no_content,
        );
        assert!(matches!(resp, Response::Reply(_)), "204: {resp:?}");
    }

    #[test]
    fn keep_alive_matrix() {
        let mut ok = |_: HttpRequest<'_>, _: &mut ()| HttpResponse::new(200);
        // HTTP/1.0 defaults to close.
        let resp = roundtrip(
            b"GET / HTTP/1.0\r\n\r\n",
            &mut HttpConn::new(()),
            &mut ok,
        );
        assert!(is_close(&resp));
        assert!(text(&resp).contains("Connection: close\r\n"));
        // HTTP/1.0 with negotiated keep-alive echoes it.
        let resp = roundtrip(
            b"GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n",
            &mut HttpConn::new(()),
            &mut ok,
        );
        assert!(is_keep(&resp));
        assert!(text(&resp).contains("Connection: keep-alive\r\n"));
        // HTTP/1.1 with Connection: close farewells.
        let resp = roundtrip(
            b"GET / HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n",
            &mut HttpConn::new(()),
            &mut ok,
        );
        assert!(is_close(&resp));
        assert!(text(&resp).contains("Connection: close\r\n"));
        // Handler-forced close overrides negotiated keep-alive.
        let mut closer =
            |_: HttpRequest<'_>, _: &mut ()| HttpResponse::new(200).close();
        let resp = roundtrip(
            b"GET / HTTP/1.1\r\nHost: h\r\n\r\n",
            &mut HttpConn::new(()),
            &mut closer,
        );
        assert!(is_close(&resp));
    }

    #[test]
    fn cl_te_conflict_forces_connection_close() {
        // This head carries both Content-Length and Transfer-Encoding, and
        // it frames as chunked because the transfer coding wins. The pair
        // is the CL.TE smuggling differential, so the reply must drop keep
        // alive and the connection cannot be reused behind a smuggled
        // prefix. The body still decodes by the chunked framing.
        let head = b"PUT /k HTTP/1.1\r\nHost: h\r\n\
                     Content-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n";
        let mut raw = head.to_vec();
        raw.extend_from_slice(b"5\r\nhello\r\n0\r\n\r\n");
        let mut handler = |req: HttpRequest<'_>, _: &mut ()| {
            assert_eq!(&req.body[..], b"hello", "TE framing still wins");
            HttpResponse::new(200)
        };
        let resp = roundtrip(&raw, &mut HttpConn::new(()), &mut handler);
        assert!(is_close(&resp), "CL plus TE must farewell, got {resp:?}");
        assert!(text(&resp).contains("Connection: close\r\n"));

        // A chunked request without a Content-Length is no conflict and it
        // stays keep alive. The forced close is specific to the pair.
        let head =
            b"PUT /k HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n";
        let mut raw = head.to_vec();
        raw.extend_from_slice(b"5\r\nhello\r\n0\r\n\r\n");
        let mut ok = |_: HttpRequest<'_>, _: &mut ()| HttpResponse::new(200);
        let resp = roundtrip(&raw, &mut HttpConn::new(()), &mut ok);
        assert!(is_keep(&resp), "TE only stays keep alive, got {resp:?}");
        assert!(!text(&resp).contains("Connection: close"));
    }

    #[test]
    fn head_response_elides_body() {
        let mut handler = |_: HttpRequest<'_>, _: &mut ()| {
            HttpResponse::new(200).body("hello")
        };
        let resp = roundtrip(
            b"HEAD /x HTTP/1.1\r\nHost: h\r\n\r\n",
            &mut HttpConn::new(()),
            &mut handler,
        );
        let s = text(&resp);
        assert!(s.contains("Content-Length: 5\r\n"));
        assert!(s.ends_with("\r\n\r\n"));
    }

    #[test]
    fn head_declaration_rides_the_request_method() {
        // One handler, two requests: the declaration reaches the wire on the
        // HEAD and is dropped on the GET. The method decides, so a handler
        // that declares a length unconditionally still cannot promise bytes
        // a GET will not send.
        let mut handler = |_: HttpRequest<'_>, _: &mut ()| {
            HttpResponse::new(200).head_content_length(4096)
        };
        let head = roundtrip(
            b"HEAD /x HTTP/1.1\r\nHost: h\r\n\r\n",
            &mut HttpConn::new(()),
            &mut handler,
        );
        let s = text(&head);
        assert!(s.contains("Content-Length: 4096\r\n"), "{s}");
        assert!(s.ends_with("\r\n\r\n"), "{s}");
        let get = roundtrip(
            b"GET /x HTTP/1.1\r\nHost: h\r\n\r\n",
            &mut HttpConn::new(()),
            &mut handler,
        );
        let s = text(&get);
        assert!(s.contains("Content-Length: 0\r\n"), "{s}");
        assert!(!s.contains("4096"), "{s}");
    }

    #[cfg(feature = "uring-fs")]
    #[test]
    fn a_file_body_response_becomes_a_reply_file() {
        fn dev_null() -> crate::uring_fs::File {
            let fd: std::os::fd::OwnedFd =
                std::fs::File::open("/dev/null").expect("open").into();
            crate::uring_fs::File::new(crate::sync::Arc::new(fd))
        }
        let mut handler = |_: HttpRequest<'_>, _: &mut ()| {
            HttpResponse::new(200).file_body(dev_null(), 32, 1024)
        };
        // GET: the reactor streams the tail; the head already carries the
        // declared length, and the range is the handler's.
        let resp = roundtrip(
            b"GET /f HTTP/1.1\r\nHost: h\r\n\r\n",
            &mut HttpConn::new(()),
            &mut handler,
        );
        let Response::ReplyFile {
            head,
            offset,
            len,
            close,
            ..
        } = &resp
        else {
            panic!("a file body must stream, got {resp:?}");
        };
        assert!(!close, "keep-alive request keeps serving");
        assert_eq!((*offset, *len), (32, 1024));
        let s = std::str::from_utf8(head).unwrap();
        assert!(s.contains("Content-Length: 1024\r\n"), "{s}");
        assert!(s.ends_with("\r\n\r\n"), "{s}");

        // Connection: close rides into the tail's disposition.
        let resp = roundtrip(
            b"GET /f HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n",
            &mut HttpConn::new(()),
            &mut handler,
        );
        assert!(
            matches!(resp, Response::ReplyFile { close: true, .. }),
            "{resp:?}"
        );

        // HEAD: the length is declared, nothing streams (the handle-drop
        // proof is pinned beside `serialize_reply`).
        let resp = roundtrip(
            b"HEAD /f HTTP/1.1\r\nHost: h\r\n\r\n",
            &mut HttpConn::new(()),
            &mut handler,
        );
        let Response::Reply(bytes) = &resp else {
            panic!("a HEAD must not stream, got {resp:?}");
        };
        let s = std::str::from_utf8(bytes).unwrap();
        assert!(s.contains("Content-Length: 1024\r\n"), "{s}");
        assert!(s.ends_with("\r\n\r\n"), "{s}");
    }

    #[test]
    fn expect_dance_through_the_real_glue() {
        let head =
            b"PUT /k HTTP/1.1\r\nHost: h\r\nExpect: 100-continue\r\nContent-Length: 3\r\n\r\n";
        let mut conn = HttpConn::new(());
        let p = peer();
        let mut handler = |req: HttpRequest<'_>, _: &mut ()| {
            assert_eq!(req.method, "PUT");
            assert_eq!(req.raw_head, &head[..]);
            assert_eq!(&req.body[..], b"abc");
            HttpResponse::new(200)
        };

        // Message 1: the head alone -> the interim, and the phase advances.
        assert_eq!(
            frame(head, &mut conn, &cfg()),
            Framing::Complete {
                header_len: head.len(),
                body_len: 0
            }
        );
        let interim =
            drive(head, Body::inline(b""), &p, &mut conn, &mut handler);
        match &interim {
            Response::Reply(bytes) => {
                assert_eq!(bytes.as_slice(), b"HTTP/1.1 100 Continue\r\n\r\n");
            }
            other => panic!("expected interim reply, got {other:?}"),
        }
        assert!(matches!(conn.phase, Phase::ExpectBody { .. }));

        // Message 2: the body alone, paired with the stash.
        assert_eq!(
            frame(b"abc", &mut conn, &cfg()),
            Framing::Complete {
                header_len: 0,
                body_len: 3
            }
        );
        let resp =
            drive(b"", Body::inline(b"abc"), &p, &mut conn, &mut handler);
        assert!(is_keep(&resp));
        assert!(text(&resp).starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(matches!(conn.phase, Phase::Head));
    }

    /// An expecting client on a *streaming* endpoint gets its interim when
    /// the handler accepts at `Stage::Open`.
    ///
    /// Three routes owe the withheld interim and each carries its own
    /// pin: the two deferred ones park first
    /// (`a_deferred_stream_open_still_sends_the_interim`,
    /// `a_redriven_stream_open_still_sends_the_interim`), and this is the
    /// inline one. An interim withheld here stalls an expecting upload for
    /// the client's own timeout.
    #[test]
    fn an_accepted_streamed_open_releases_the_withheld_interim() {
        let head = b"PUT /up HTTP/1.1\r\nHost: h\r\n\
                     Expect: 100-continue\r\n\
                     Transfer-Encoding: chunked\r\n\r\n";
        let mut conn = HttpConn::new_streaming((), 1 << 20);
        let p = peer();
        assert_eq!(
            frame(head, &mut conn, &cfg()),
            Framing::Complete {
                header_len: head.len(),
                body_len: 0
            }
        );
        let resp = drive_verdict(
            head,
            Body::inline(b""),
            &p,
            &mut conn,
            &mut |req: HttpRequest<'_>, _: &mut ()| {
                assert!(matches!(req.stage, Stage::Open));
                HttpVerdict::Continue
            },
        );
        assert_eq!(
            text(&resp),
            "HTTP/1.1 100 Continue\r\n\r\n",
            "an accepted streamed open owes the interim it withheld"
        );
        assert!(
            matches!(conn.phase, Phase::StreamBody { .. }),
            "and the body phase is armed to receive what it just invited"
        );
    }

    /// A refusal at `Stage::Open` goes out *instead of* the interim, and
    /// closes.
    ///
    /// This is the whole point of dispatching the head before a body byte:
    /// the peer has not committed yet. Answering while leaving the
    /// connection open would let the declined body be framed as the next
    /// request, and answering *after* a `100 Continue` would have invited a
    /// body in order to refuse it.
    ///
    /// Two mechanisms close it here - `force_final` on this arm, and
    /// `respond`'s own `abandons_body` disposition - so this asserts the
    /// contract rather than either one, and it takes removing both to make
    /// it fail.
    #[test]
    fn a_refused_streamed_open_answers_instead_of_inviting() {
        let head = b"PUT /up HTTP/1.1\r\nHost: h\r\n\
                     Expect: 100-continue\r\n\
                     Transfer-Encoding: chunked\r\n\r\n";
        let mut conn = HttpConn::new_streaming((), 1 << 20);
        let p = peer();
        let _ = frame(head, &mut conn, &cfg());
        let resp = drive_verdict(
            head,
            Body::inline(b""),
            &p,
            &mut conn,
            &mut |_: HttpRequest<'_>, _: &mut ()| {
                HttpVerdict::Respond(HttpResponse::new(403))
            },
        );
        let s = text(&resp);
        assert!(s.starts_with("HTTP/1.1 403 "), "{s}");
        assert!(
            !s.contains("100 Continue"),
            "the refusal must replace the interim, not follow it: {s}"
        );
        assert!(is_close(&resp), "a declined body leaves nothing to frame");
        assert!(s.contains("Connection: close\r\n"), "{s}");
    }

    /// A stream open during a drain is refused 503, not invited.
    ///
    /// The buffered twin is `dance_while_draining_is_refused_not_invited`,
    /// and the reasoning is identical: a drain that accepts an upload it
    /// will not read closes under a client mid-body, which the client
    /// cannot tell from a truncation.
    #[test]
    fn a_streamed_open_while_draining_is_refused() {
        let head = b"PUT /up HTTP/1.1\r\nHost: h\r\n\
                     Expect: 100-continue\r\n\
                     Transfer-Encoding: chunked\r\n\r\n";
        let mut conn = HttpConn::new_streaming((), 1 << 20);
        let p = peer();
        let _ = frame(head, &mut conn, &cfg());
        let resp = step(
            head,
            Body::inline(b""),
            &p,
            Responder::test_responder_draining(),
            FsSlot::default(),
            &mut conn,
            &mut DateCache::default(),
            &mut |_: HttpRequest<'_>, _: &mut (), _fs: FsSlot<'_>| {
                panic!("the handler must not run: the drain refuses first")
            },
        );
        let s = text(&resp);
        assert!(s.starts_with("HTTP/1.1 503 "), "{s}");
        assert!(is_close(&resp), "a refusal, not the keep-alive interim");
        assert!(
            matches!(conn.phase, Phase::Head),
            "nothing waits for a body that was never invited"
        );
    }

    /// A delivery that owes a reply cannot be continued past.
    ///
    /// `Continue` is the streamed stages' verdict; at `Whole` or `End`
    /// there is nothing further to read, so nothing would ever answer and
    /// the connection would sit until a timeout. It closes instead, which
    /// presents as slot exhaustion rather than a hang under load.
    ///
    /// Guarded twice - the `Stage`-testing arm in `dispatch` and `settle`'s
    /// backstop - so this asserts the contract rather than either arm, and
    /// it takes removing both to make it fail.
    #[test]
    fn continuing_past_a_delivery_that_owes_a_reply_closes() {
        let head = b"GET /k HTTP/1.1\r\nHost: h\r\n\r\n";
        let mut conn = HttpConn::new(());
        let p = peer();
        let _ = frame(head, &mut conn, &cfg());
        let resp = drive_verdict(
            head,
            Body::inline(b""),
            &p,
            &mut conn,
            &mut |req: HttpRequest<'_>, _: &mut ()| {
                assert!(matches!(req.stage, Stage::Whole));
                HttpVerdict::Continue
            },
        );
        assert!(
            matches!(resp, Response::Close),
            "a Whole delivery answered with Continue owes a reply nobody \
             will send"
        );
    }

    /// While draining, the dance's first message is refused with a close
    /// instead of being invited to send a body the drain will not read.
    #[test]
    fn dance_while_draining_is_refused_not_invited() {
        let head =
            b"PUT /k HTTP/1.1\r\nHost: h\r\nExpect: 100-continue\r\nContent-Length: 3\r\n\r\n";
        let mut conn = HttpConn::new(());
        let p = peer();
        assert_eq!(
            frame(head, &mut conn, &cfg()),
            Framing::Complete {
                header_len: head.len(),
                body_len: 0
            }
        );
        let resp = step(
            head,
            Body::inline(b""),
            &p,
            Responder::test_responder_draining(),
            FsSlot::default(),
            &mut conn,
            &mut DateCache::default(),
            &mut |_: HttpRequest<'_>, _: &mut (), _fs: FsSlot<'_>| {
                panic!("the handler must not run: no body was read")
            },
        );
        assert!(is_close(&resp), "a refusal, not the keep-alive interim");
        let s = text(&resp);
        assert!(s.starts_with("HTTP/1.1 503 "), "{s}");
        assert!(s.contains("Connection: close\r\n"), "{s}");
        assert!(
            matches!(conn.phase, Phase::Head),
            "the dance is over, nothing waits for a body"
        );
    }

    #[test]
    fn farewell_carries_status_and_body() {
        let mut conn = HttpConn::new(());
        let junk = b"NOT HTTP\r\n\r\n";
        frame(junk, &mut conn, &cfg());
        assert!(matches!(conn.phase, Phase::Fail { status: 400, .. }));
        let p = peer();
        let mut unreached =
            |_: HttpRequest<'_>, _: &mut ()| panic!("handler must not run");
        let resp =
            drive(junk, Body::inline(b""), &p, &mut conn, &mut unreached);
        assert!(is_close(&resp));
        let s = text(&resp);
        assert!(s.starts_with("HTTP/1.1 400 Bad Request\r\n"));
        assert!(s.contains("Connection: close\r\n"));
        assert!(s.ends_with("error 400\n"));
    }

    #[test]
    fn farewell_to_head_elides_body() {
        // A HEAD that dies on a policy check still parses as HEAD; the
        // farewell must not carry content the client won't read as a body.
        let mut conn = HttpConn::new(());
        let req = b"HEAD /x HTTP/1.1\r\nHost: h\r\nContent-Length: 99999999999\r\n\r\n";
        frame(req, &mut conn, &cfg());
        assert!(matches!(conn.phase, Phase::Fail { status: 413, .. }));
        let p = peer();
        let mut unreached =
            |_: HttpRequest<'_>, _: &mut ()| panic!("handler must not run");
        let resp = drive(req, Body::inline(b""), &p, &mut conn, &mut unreached);
        let s = text(&resp);
        assert!(s.starts_with("HTTP/1.1 413"));
        // The HEAD contract: length declared, no body bytes.
        assert!(s.contains("Content-Length: 10\r\n"));
        assert!(s.ends_with("\r\n\r\n"));
    }

    #[test]
    fn farewell_after_dance_ignores_body_bytes() {
        // After the interim the head is consumed; a failing scan delivers
        // body bytes alone. A body crafted to begin "HEAD " must not turn
        // the farewell into a bodyless HEAD response - a declared
        // Content-Length with no content is an incomplete message.
        let head = b"PUT /k HTTP/1.1\r\nHost: h\r\nExpect: 100-continue\r\nTransfer-Encoding: chunked\r\n\r\n";
        let mut conn = HttpConn::new(());
        let p = peer();
        let mut unreached =
            |_: HttpRequest<'_>, _: &mut ()| panic!("handler must not run");
        frame(head, &mut conn, &cfg());
        drive(head, Body::inline(b""), &p, &mut conn, &mut unreached);
        // Message 2: garbage chunk framing that happens to spell "HEAD ".
        let body = b"HEAD /x HTTP/1.1\r\n\r\n";
        frame(body, &mut conn, &cfg());
        assert!(matches!(
            conn.phase,
            Phase::Fail {
                status: 400,
                head_only: false
            }
        ));
        let resp =
            drive(body, Body::inline(b""), &p, &mut conn, &mut unreached);
        let s = text(&resp);
        assert!(s.starts_with("HTTP/1.1 400"));
        // The PUT's farewell carries its diagnostic body.
        assert!(s.ends_with("error 400\n"));
    }

    #[test]
    fn head_farewell_elides_body_after_dance() {
        // The converse: a real HEAD whose dance fails must still elide the
        // farewell body, even though the delivered bytes no longer start
        // with the method.
        let head = b"HEAD /k HTTP/1.1\r\nHost: h\r\nExpect: 100-continue\r\nTransfer-Encoding: chunked\r\n\r\n";
        let mut conn = HttpConn::new(());
        let p = peer();
        let mut unreached =
            |_: HttpRequest<'_>, _: &mut ()| panic!("handler must not run");
        frame(head, &mut conn, &cfg());
        drive(head, Body::inline(b""), &p, &mut conn, &mut unreached);
        // Message 2: a malformed chunk-size line kills the scan.
        let body = b"zz\r\n";
        frame(body, &mut conn, &cfg());
        assert!(matches!(
            conn.phase,
            Phase::Fail {
                status: 400,
                head_only: true
            }
        ));
        let resp =
            drive(body, Body::inline(b""), &p, &mut conn, &mut unreached);
        let s = text(&resp);
        assert!(s.starts_with("HTTP/1.1 400"));
        assert!(s.contains("Content-Length: 10\r\n"));
        assert!(s.ends_with("\r\n\r\n"));
    }

    #[test]
    fn chunked_roundtrip_through_the_real_glue() {
        let head =
            b"PUT /k HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n";
        let mut raw = head.to_vec();
        raw.extend_from_slice(b"3\r\nfoo\r\n4\r\nbars\r\n0\r\n\r\n");
        let mut handler = |req: HttpRequest<'_>, hits: &mut u32| {
            *hits += 1;
            assert_eq!(&req.body[..], b"foobars");
            assert!(req.trailers.is_empty());
            HttpResponse::new(200)
        };
        let mut conn = HttpConn::new(0u32);
        let resp = roundtrip(&raw, &mut conn, &mut handler);
        assert!(is_keep(&resp));
        assert_eq!(conn.state, 1);
        assert!(matches!(conn.phase, Phase::Head));
    }

    #[test]
    fn chunked_trailers_exposed() {
        let head =
            b"PUT /t HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n";
        let mut raw = head.to_vec();
        raw.extend_from_slice(
            b"3\r\nabc\r\n0\r\nx-amz-checksum-crc32: lZe8jQ==\r\n\r\n",
        );
        let mut handler = |req: HttpRequest<'_>, _: &mut ()| {
            assert_eq!(&req.body[..], b"abc");
            assert_eq!(req.trailers.len(), 1);
            assert_eq!(req.trailers[0].name, "x-amz-checksum-crc32");
            assert_eq!(req.trailers[0].value, b"lZe8jQ==");
            HttpResponse::new(200)
        };
        let resp = roundtrip(&raw, &mut HttpConn::new(()), &mut handler);
        assert!(is_keep(&resp));
    }

    #[test]
    fn botocore_streaming_put_golden() {
        // The default boto3-over-TLS PutObject shape, as captured on the
        // dev box (boto3 1.37.9): Expect + TE chunked, one HTTP chunk
        // wrapping the aws-chunked entity, checksum trailer *inside* the
        // entity, bare HTTP terminator. The HTTP band de-chunks its own
        // layer only - the aws-chunked entity must pass through untouched.
        let head = b"PUT /bkt/hello.txt HTTP/1.1\r\n\
                     Host: 127.0.0.1:9711\r\n\
                     Expect: 100-continue\r\n\
                     Transfer-Encoding: chunked\r\n\
                     Content-Encoding: aws-chunked\r\n\
                     X-Amz-Trailer: x-amz-checksum-crc32\r\n\
                     X-Amz-Decoded-Content-Length: 100\r\n\
                     X-Amz-Content-SHA256: STREAMING-UNSIGNED-PAYLOAD-TRAILER\r\n\r\n";
        let mut wire = b"8e\r\n64\r\n".to_vec();
        wire.extend_from_slice(&[b'A'; 100]);
        wire.extend_from_slice(
            b"\r\n0\r\nx-amz-checksum-crc32:lZe8jQ==\r\n\r\n\r\n0\r\n\r\n",
        );
        assert_eq!(wire.len(), 153);
        let mut entity = b"64\r\n".to_vec();
        entity.extend_from_slice(&[b'A'; 100]);
        entity.extend_from_slice(
            b"\r\n0\r\nx-amz-checksum-crc32:lZe8jQ==\r\n\r\n",
        );

        let mut conn = HttpConn::new(());
        let p = peer();
        let mut handler = |mut req: HttpRequest<'_>, _: &mut ()| {
            assert_eq!(req.method, "PUT");
            assert_eq!(req.target, "/bkt/hello.txt");
            assert_eq!(req.raw_head, &head[..]);
            assert_eq!(req.body.take(), entity);
            assert!(req.trailers.is_empty());
            HttpResponse::new(200)
        };

        // Message 1: the head alone -> the interim, and the phase advances.
        assert_eq!(
            frame(head, &mut conn, &cfg()),
            Framing::Complete {
                header_len: head.len(),
                body_len: 0
            }
        );
        let interim =
            drive(head, Body::inline(b""), &p, &mut conn, &mut handler);
        assert!(matches!(
            &interim,
            Response::Reply(b) if b.as_slice() == b"HTTP/1.1 100 Continue\r\n\r\n"
        ));

        // Message 2: the chunked body, scanned then delivered whole.
        assert_eq!(
            frame(&wire, &mut conn, &cfg()),
            Framing::Complete {
                header_len: 0,
                body_len: wire.len()
            }
        );
        let resp = drive(b"", Body::inline(&wire), &p, &mut conn, &mut handler);
        assert!(is_keep(&resp));
        assert!(text(&resp).starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(matches!(conn.phase, Phase::Head));
    }

    #[test]
    fn handler_can_take_body_ownership() {
        // Body::take is the zero-copy seam: a placed body moves out whole.
        let mut handler = |mut req: HttpRequest<'_>, _: &mut ()| {
            let owned = req.body.take();
            assert_eq!(owned, b"hello");
            assert!(req.body.is_empty());
            HttpResponse::new(200)
        };
        let head = b"PUT /k HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\n";
        let mut conn = HttpConn::new(());
        let mut buf = head.to_vec();
        buf.extend_from_slice(b"hello");
        assert_eq!(
            frame(&buf, &mut conn, &cfg()),
            Framing::Complete {
                header_len: head.len(),
                body_len: 5
            }
        );
        let p = peer();
        let resp = drive(
            head,
            Body::placed(b"hello".to_vec()),
            &p,
            &mut conn,
            &mut handler,
        );
        assert!(is_keep(&resp));
    }

    #[test]
    fn owned_dance_body_takes_from_the_same_allocation() {
        // The reactor hands the dance's body-only delivery its buffer (at
        // or over the placement threshold); the de-chunked entity must
        // reach the handler's take() from that same allocation - ownership
        // moved, bytes didn't (single chunk), nothing allocated. The A3
        // contract, pointer-checked, on the golden botocore shape.
        let head = b"PUT /bkt/k HTTP/1.1\r\n\
                     Host: h\r\n\
                     Expect: 100-continue\r\n\
                     Transfer-Encoding: chunked\r\n\r\n";
        let mut wire = b"8e\r\n64\r\n".to_vec();
        wire.extend_from_slice(&[b'A'; 100]);
        wire.extend_from_slice(
            b"\r\n0\r\nx-amz-checksum-crc32:lZe8jQ==\r\n\r\n\r\n0\r\n\r\n",
        );
        let mut entity = b"64\r\n".to_vec();
        entity.extend_from_slice(&[b'A'; 100]);
        entity.extend_from_slice(
            b"\r\n0\r\nx-amz-checksum-crc32:lZe8jQ==\r\n\r\n",
        );
        let p0 = wire.as_ptr() as usize;

        let mut conn = HttpConn::new(());
        let p = peer();
        let mut handler = |mut req: HttpRequest<'_>, _: &mut ()| {
            let owned = req.body.take();
            assert_eq!(owned, entity);
            assert_eq!(
                owned.as_ptr() as usize,
                p0,
                "entity taken from the delivered allocation"
            );
            assert!(req.trailers.is_empty());
            HttpResponse::new(200)
        };
        frame(head, &mut conn, &cfg());
        drive(head, Body::inline(b""), &p, &mut conn, &mut handler);
        assert_eq!(
            frame(&wire, &mut conn, &cfg()),
            Framing::Complete {
                header_len: 0,
                body_len: wire.len()
            }
        );
        let resp = drive(b"", Body::placed(wire), &p, &mut conn, &mut handler);
        assert!(is_keep(&resp));
        assert!(text(&resp).starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(matches!(conn.phase, Phase::Head));
    }

    #[test]
    fn owned_delivery_surfaces_trailers_and_drops_forbidden() {
        // A non-dance chunked message delivered with the wire owned: the
        // in-place path must surface genuine trailers (copied aside, so the
        // entity can own the allocation) and still drop the forbidden set.
        let head =
            b"PUT /t HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n";
        let mut raw = head.to_vec();
        raw.extend_from_slice(
            b"3\r\nabc\r\n0\r\nContent-Length: 9\r\nx-amz-checksum-crc32: lZe8jQ==\r\n\r\n",
        );
        let mut conn = HttpConn::new(());
        let verdict = frame(&raw, &mut conn, &cfg());
        let Framing::Complete {
            header_len,
            body_len,
        } = verdict
        else {
            panic!("expected complete, got {verdict:?}");
        };
        assert_eq!(header_len, head.len());
        let p = peer();
        let mut handler = |mut req: HttpRequest<'_>, _: &mut ()| {
            assert_eq!(req.body.take(), b"abc");
            assert_eq!(req.trailers.len(), 1);
            assert_eq!(req.trailers[0].name, "x-amz-checksum-crc32");
            assert_eq!(req.trailers[0].value, b"lZe8jQ==");
            HttpResponse::new(200)
        };
        let resp = drive(
            &raw[..header_len],
            Body::placed(raw[header_len..header_len + body_len].to_vec()),
            &p,
            &mut conn,
            &mut handler,
        );
        assert!(is_keep(&resp));
    }

    // ---- parking ----

    use std::cell::RefCell;

    /// [`roundtrip`] for verdict handlers.
    fn roundtrip_verdict<U>(
        raw: &[u8],
        conn: &mut HttpConn<U>,
        handler: &mut impl FnMut(HttpRequest<'_>, &mut U) -> HttpVerdict,
    ) -> Response {
        let verdict = frame(raw, conn, &cfg());
        let Framing::Complete {
            header_len,
            body_len,
        } = verdict
        else {
            panic!("expected a complete frame, got {verdict:?}");
        };
        assert_eq!(header_len + body_len, raw.len());
        let p = peer();
        drive_verdict(
            &raw[..header_len],
            Body::inline(&raw[header_len..]),
            &p,
            conn,
            handler,
        )
    }

    /// A parked request's completion: the redelivery is an empty frame
    /// against the parked phase.
    fn complete_parked<U>(
        conn: &mut HttpConn<U>,
        handler: &mut impl FnMut(HttpRequest<'_>, &mut U) -> HttpVerdict,
    ) -> Response {
        let p = peer();
        drive_verdict(b"", Body::inline(b""), &p, conn, handler)
    }

    /// A handler for completions that must not re-run the handler (a worker
    /// `reply` was left in the cell).
    fn unreached_verdict<U>(_: HttpRequest<'_>, _: &mut U) -> HttpVerdict {
        panic!("handler must not run when a worker reply is present")
    }

    #[test]
    fn park_and_redrive_identical_view() {
        let head = b"PUT /k HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\n";
        let mut raw = head.to_vec();
        raw.extend_from_slice(b"hello");
        let mut conn = HttpConn::new(0u32);
        let parked: RefCell<Option<HttpDeferred>> = RefCell::new(None);
        let mut handler = |req: HttpRequest<'_>, hits: &mut u32| {
            *hits += 1;
            match *hits {
                1 => {
                    assert_eq!(req.method, "PUT");
                    assert_eq!(&req.body[..], b"hello");
                    let (deferred, permit) = req.defer();
                    parked.borrow_mut().replace(deferred);
                    HttpVerdict::Defer(permit)
                }
                _ => {
                    // The redelivered view is the first one, byte for byte.
                    assert_eq!(req.method, "PUT");
                    assert_eq!(req.target, "/k");
                    assert_eq!(req.raw_head, &head[..]);
                    assert_eq!(&req.body[..], b"hello");
                    assert!(req.trailers.is_empty());
                    HttpVerdict::Respond(HttpResponse::new(200).body("done"))
                }
            }
        };
        let resp = roundtrip_verdict(&raw, &mut conn, &mut handler);
        assert!(matches!(resp, Response::Defer(_)), "got {resp:?}");
        assert!(matches!(conn.phase, Phase::Parked { .. }));
        // The worker warms its state and asks for the rerun.
        parked.borrow_mut().take().expect("parked").redrive();
        let done = complete_parked(&mut conn, &mut handler);
        assert!(is_keep(&done), "got {done:?}");
        assert!(text(&done).starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(text(&done).ends_with("\r\n\r\ndone"));
        assert_eq!(conn.state, 2, "one park, one rerun");
        assert!(matches!(conn.phase, Phase::Head));
    }

    /// Park a HEAD; the worker replies with a declared length. The
    /// completion must apply the HEAD contract - length on the wire, no
    /// body bytes - proving the reply serializes against the parked head.
    #[test]
    fn worker_reply_keeps_the_head_contract() {
        let head = b"HEAD /x HTTP/1.1\r\nHost: h\r\n\r\n";
        let mut conn = HttpConn::new(());
        let parked: RefCell<Option<HttpDeferred>> = RefCell::new(None);
        let mut park_once = |req: HttpRequest<'_>, _: &mut ()| {
            let (deferred, permit) = req.defer();
            parked.borrow_mut().replace(deferred);
            HttpVerdict::Defer(permit)
        };
        let resp = roundtrip_verdict(head, &mut conn, &mut park_once);
        assert!(matches!(resp, Response::Defer(_)));
        parked
            .borrow_mut()
            .take()
            .expect("parked")
            .reply(HttpResponse::new(200).head_content_length(4096));
        let done = complete_parked(&mut conn, &mut unreached_verdict);
        assert!(is_keep(&done), "got {done:?}");
        let s = text(&done);
        assert!(s.contains("Content-Length: 4096\r\n"), "{s}");
        assert!(s.ends_with("\r\n\r\n"), "{s}");
    }

    /// A parked CL+TE request (the smuggling differential): the worker's
    /// reply must still force the connection closed, exactly as the inline
    /// path would.
    #[test]
    fn worker_reply_keeps_the_smuggling_close() {
        let head = b"PUT /k HTTP/1.1\r\nHost: h\r\n\
                     Content-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n";
        let mut raw = head.to_vec();
        raw.extend_from_slice(b"5\r\nhello\r\n0\r\n\r\n");
        let mut conn = HttpConn::new(());
        let parked: RefCell<Option<HttpDeferred>> = RefCell::new(None);
        let mut park_once = |req: HttpRequest<'_>, _: &mut ()| {
            assert_eq!(&req.body[..], b"hello", "TE framing still wins");
            let (deferred, permit) = req.defer();
            parked.borrow_mut().replace(deferred);
            HttpVerdict::Defer(permit)
        };
        let resp = roundtrip_verdict(&raw, &mut conn, &mut park_once);
        assert!(matches!(resp, Response::Defer(_)));
        parked
            .borrow_mut()
            .take()
            .expect("parked")
            .reply(HttpResponse::new(200));
        let done = complete_parked(&mut conn, &mut unreached_verdict);
        assert!(
            is_close(&done),
            "CL plus TE must farewell after a park too, got {done:?}"
        );
        assert!(text(&done).contains("Connection: close\r\n"));
    }

    /// HTTP/1.0 negotiated keep-alive survives a park: the worker's reply
    /// still echoes `Connection: keep-alive` and stays open.
    #[test]
    fn worker_reply_keeps_http10_keepalive() {
        let head = b"GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n";
        let mut conn = HttpConn::new(());
        let parked: RefCell<Option<HttpDeferred>> = RefCell::new(None);
        let mut park_once = |req: HttpRequest<'_>, _: &mut ()| {
            let (deferred, permit) = req.defer();
            parked.borrow_mut().replace(deferred);
            HttpVerdict::Defer(permit)
        };
        let resp = roundtrip_verdict(head, &mut conn, &mut park_once);
        assert!(matches!(resp, Response::Defer(_)));
        parked
            .borrow_mut()
            .take()
            .expect("parked")
            .reply(HttpResponse::new(200));
        let done = complete_parked(&mut conn, &mut unreached_verdict);
        assert!(is_keep(&done));
        assert!(text(&done).contains("Connection: keep-alive\r\n"));
    }

    /// A park through the 100-continue dance: the redelivered view carries
    /// the stashed head and the dance's body.
    #[test]
    fn park_through_the_dance() {
        let head = b"PUT /k HTTP/1.1\r\nHost: h\r\n\
                     Expect: 100-continue\r\nContent-Length: 3\r\n\r\n";
        let mut conn = HttpConn::new(0u32);
        let p = peer();
        let parked: RefCell<Option<HttpDeferred>> = RefCell::new(None);
        let mut handler = |req: HttpRequest<'_>, hits: &mut u32| {
            *hits += 1;
            assert_eq!(req.raw_head, &head[..]);
            assert_eq!(&req.body[..], b"abc");
            match *hits {
                1 => {
                    let (deferred, permit) = req.defer();
                    parked.borrow_mut().replace(deferred);
                    HttpVerdict::Defer(permit)
                }
                _ => HttpVerdict::Respond(HttpResponse::new(200)),
            }
        };
        // Message 1: the head alone -> the interim; the handler never runs.
        assert_eq!(
            frame(head, &mut conn, &cfg()),
            Framing::Complete {
                header_len: head.len(),
                body_len: 0
            }
        );
        let interim =
            drive_verdict(head, Body::inline(b""), &p, &mut conn, &mut handler);
        assert!(matches!(&interim, Response::Reply(b)
            if b.as_slice() == b"HTTP/1.1 100 Continue\r\n\r\n"));
        // Message 2: the body -> the park.
        assert_eq!(
            frame(b"abc", &mut conn, &cfg()),
            Framing::Complete {
                header_len: 0,
                body_len: 3
            }
        );
        let resp = drive_verdict(
            b"",
            Body::inline(b"abc"),
            &p,
            &mut conn,
            &mut handler,
        );
        assert!(matches!(resp, Response::Defer(_)));
        parked.borrow_mut().take().expect("parked").redrive();
        let done = complete_parked(&mut conn, &mut handler);
        assert!(is_keep(&done));
        assert!(text(&done).starts_with("HTTP/1.1 200 OK\r\n"));
        assert_eq!(conn.state, 2);
    }

    /// Chunked trailers survive a park: the redelivered view re-presents
    /// them from the retained copies.
    #[test]
    fn park_preserves_chunked_trailers() {
        let head =
            b"PUT /t HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n";
        let mut raw = head.to_vec();
        raw.extend_from_slice(
            b"3\r\nabc\r\n0\r\nx-amz-checksum-crc32: lZe8jQ==\r\n\r\n",
        );
        let mut conn = HttpConn::new(0u32);
        let parked: RefCell<Option<HttpDeferred>> = RefCell::new(None);
        let mut handler = |req: HttpRequest<'_>, hits: &mut u32| {
            *hits += 1;
            assert_eq!(&req.body[..], b"abc");
            assert_eq!(req.trailers.len(), 1);
            assert_eq!(req.trailers[0].name, "x-amz-checksum-crc32");
            assert_eq!(req.trailers[0].value, b"lZe8jQ==");
            match *hits {
                1 => {
                    let (deferred, permit) = req.defer();
                    parked.borrow_mut().replace(deferred);
                    HttpVerdict::Defer(permit)
                }
                _ => HttpVerdict::Respond(HttpResponse::new(200)),
            }
        };
        let resp = roundtrip_verdict(&raw, &mut conn, &mut handler);
        assert!(matches!(resp, Response::Defer(_)));
        parked.borrow_mut().take().expect("parked").redrive();
        let done = complete_parked(&mut conn, &mut handler);
        assert!(is_keep(&done));
        assert_eq!(conn.state, 2);
    }

    /// A redriven handler may park again: the second park files a fresh
    /// retained request and completes like the first.
    #[test]
    fn a_redrive_may_park_again() {
        let head = b"GET /slow HTTP/1.1\r\nHost: h\r\n\r\n";
        let mut conn = HttpConn::new(0u32);
        let parked: RefCell<Option<HttpDeferred>> = RefCell::new(None);
        let mut handler = |req: HttpRequest<'_>, hits: &mut u32| {
            *hits += 1;
            match *hits {
                1 | 2 => {
                    let (deferred, permit) = req.defer();
                    parked.borrow_mut().replace(deferred);
                    HttpVerdict::Defer(permit)
                }
                _ => panic!("the second park replied from the worker"),
            }
        };
        let resp = roundtrip_verdict(head, &mut conn, &mut handler);
        assert!(matches!(resp, Response::Defer(_)));
        parked.borrow_mut().take().expect("first park").redrive();
        let again = complete_parked(&mut conn, &mut handler);
        assert!(matches!(again, Response::Defer(_)), "got {again:?}");
        assert!(matches!(conn.phase, Phase::Parked { .. }));
        parked
            .borrow_mut()
            .take()
            .expect("second park")
            .reply(HttpResponse::new(204));
        let done = complete_parked(&mut conn, &mut unreached_verdict);
        assert!(is_keep(&done));
        assert!(text(&done).starts_with("HTTP/1.1 204 No Content\r\n"));
        assert_eq!(conn.state, 2);
    }

    /// While a request is parked the framer holds pipelined bytes unframed,
    /// so a later request cannot be answered around the parked one.
    #[test]
    fn parked_phase_holds_framing() {
        let mut conn = HttpConn::new(());
        conn.phase = Phase::Parked {
            resume: None,
            req: Box::new(ParkedRequest {
                head: b"GET / HTTP/1.1\r\nHost: h\r\n\r\n".to_vec(),
                body: Vec::new(),
                trailers: Vec::new(),
                answer: Arc::new(Mutex::new(None)),
            }),
        };
        let next = b"GET /next HTTP/1.1\r\nHost: h\r\n\r\n";
        assert!(matches!(frame(next, &mut conn, &cfg()), Framing::More));
    }
}

// ---------------------------------------------------------------------------
// loom model of the parked reply hand-off
// ---------------------------------------------------------------------------
//
// Run with:  RUSTFLAGS="--cfg loom" cargo test --lib --features http loom_
//
// The park's cross-thread protocol, the one edge in this module two threads
// share:
//
//   worker (HttpDeferred::reply)        loop (drain, then step on Parked)
//   *answer.lock() = Some(resp)         wake.drain()
//   tx.send(Redeliver); wake.poke()     rx.try_recv() -> Redeliver
//                                       answer.lock().take()
//
// The cell is filled before the redeliver is sent, and the completion pass
// takes the cell only after consuming the wake, so a `reply` can never be
// observed as a redrive. Break either half - fill after the send, or take
// before the wake - and a schedule exists where the completion pass takes
// `None`: the handler reruns against a consumed handle and the worker's
// response is lost. The model drives the real `defer`/`reply`/`step`, with
// the loop's recv order supplied by the probe.
#[cfg(all(test, loom))]
mod loom_tests {
    use super::*;
    use crate::net::ClientAddr;
    use crate::net::server::Body;
    use crate::sync::thread;

    fn unreached(_: HttpRequest<'_>, _: &mut (), _: FsSlot<'_>) -> HttpVerdict {
        panic!("worker reply surfaced as a redrive")
    }

    #[test]
    fn loom_worker_reply_is_never_a_redrive() {
        loom::model(|| {
            let (responder, probe) = Responder::test_responder_with_probe();
            let peer = ClientAddr::Inet("127.0.0.1:9000".parse().unwrap());
            let req = HttpRequest {
                method: "GET",
                target: "/",
                version: Version::Http11,
                headers: &[],
                body: Body::inline(b""),
                raw_head: b"GET / HTTP/1.1\r\nHost: h\r\n\r\n",
                trailers: &[],
                peer: &peer,
                stage: Stage::Whole,
                responder,
            };
            let (deferred, permit) = req.defer();
            let HttpDeferPermit {
                permit: _permit,
                req: parked,
            } = permit;
            let mut conn: HttpConn<()> = HttpConn::new(());
            conn.phase = Phase::Parked {
                req: parked,
                resume: None,
            };

            let worker = thread::spawn(move || {
                deferred.reply(HttpResponse::new(204));
            });

            probe.recv_redeliver();
            let resp = step(
                b"",
                Body::inline(b""),
                &peer,
                Responder::test_responder(),
                FsSlot::default(),
                &mut conn,
                &mut DateCache::default(),
                &mut unreached,
            );
            let Response::Reply(bytes) = resp else {
                panic!("expected the worker's reply, got {resp:?}");
            };
            assert!(bytes.starts_with(b"HTTP/1.1 204"));
            worker.join().unwrap();
        });
    }
}
