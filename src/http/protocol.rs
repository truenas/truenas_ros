//! Glue: build a [`net::server::Protocol`](Protocol) from an HTTP handler. The `header` handler is the framer step; the
//! `body` handler drives the phase machine - pairing stashed heads with their bodies, sending the `100 Continue`
//! interim, serializing responses, and mapping keep-alive onto [`Response::Reply`] vs [`Response::ReplyClose`]. The
//! whole body handler lives in [`step`], a plain function over the delivered message and the connection's phase, so
//! tests drive the real glue without a reactor.

use std::borrow::Cow;
use std::sync::PoisonError;
use std::time::{SystemTime, UNIX_EPOCH};

// The answer cell is cross-thread state (a worker fills it, the loop takes it), so it rides `crate::sync` - std in
// production, loom's in the model below, which is what lets the model see the fill/redeliver ordering.
use crate::sync::{Arc, Mutex};

use crate::net::ClientAddr;
use crate::net::server::{Body, DeferPermit, Deferred, Incoming, Protocol, Request, Responder, Response};

use super::chunked;
use super::date::DateCache;
use super::framer::{HttpConfig, HttpConn, Phase, frame};
use super::head::{Head, HeadIndex, HeaderView, MAX_HEADERS, Version, head_view, method_is_head};
use super::response::{ConnHeader, HttpResponse, Serialized, serialize, serialize_reply};

/// One HTTP request, as handed to the consumer's handler.
///
/// Everything borrows from the connection buffer (or the codec's head stash on the 100-continue path); the header index
/// is a slice into a fixed array on the caller's stack, so a request costs no per-request heap allocation. `raw_head`
/// is the head block verbatim, byte-for-byte as the client sent
/// it, kept for the diagnostic echo in a `SignatureDoesNotMatch` reply;
/// SigV4 canonicalizes from the parsed [`headers`](HttpRequest::headers) views, not this block (see the field).
/// `#[non_exhaustive]`, so future context becomes a field addition rather than a breaking change.
#[non_exhaustive]
pub struct HttpRequest<'a> {
    /// Request method, verbatim (methods are case-sensitive tokens).
    pub method: &'a str,
    /// Request-target in **origin form** (`/path?query`), undecoded - S3 keys percent-decode at the S3 layer, where
    /// encoding is semantically load-bearing.
    ///
    /// One shape, whatever the client sent. Absolute-form is accepted (RFC 9112 sec. 3.2.2 requires an origin server
    /// to) only when its authority matches `Host`, and is reduced to its path here; asterisk-form survives as `*`, and
    /// only for `OPTIONS`; every other form is answered 400 before a handler runs. So this never carries a second
    /// authority for a consumer to reconcile - but note that `//host/path` is ordinary origin-form and reaches a
    /// handler verbatim, so a consumer re-parsing this as a URI *reference* must not read that as an authority.
    pub target: &'a str,
    /// Protocol version (1.0 or 1.1; anything else died with 505).
    pub version: Version,
    /// Parsed header index, wire order preserved.
    pub headers: &'a [HeaderView<'a>],
    /// The request body (complete - bounded by [`HttpConfig::max_body`]). Deref for in-place reads; [`Body::take`]
    /// moves the bytes out - a zero-copy move when the reactor placed the body in its own allocation, and for a chunked
    /// body delivered owned (the 100-continue dance path at or over the placement threshold) an in-place truncate of
    /// the de-chunked wire - so a handler that keeps the payload (an S3 PUT) never pays a second copy.
    pub body: Body<'a>,
    /// The head block verbatim, including the terminating CRLFCRLF - the diagnostic to echo in a
    /// `SignatureDoesNotMatch` reply. Build the SigV4 canonical request from [`headers`](HttpRequest::headers) (borrows
    /// into this buffer, values verbatim minus edge-trim), never by re-splitting this block: the tokenizer accepts a
    /// bare LF as a line terminator (RFC 9112 sec. 2.2), so a CRLF-strict re-parse would draw header boundaries the
    /// request is not served on - the header-smuggling differential the parsed view does not have.
    pub raw_head: &'a [u8],
    /// Trailer fields from a chunked body (RFC 9112 sec. 7.1.2), parsed but not interpreted; empty for non-chunked
    /// requests and for chunked bodies whose trailer section is bare. Names forbidden in trailers -- framing, routing,
    /// and credentials (RFC 9110 sec. 6.5.1) - are dropped by the codec and never appear here, so merging these with
    /// the headers cannot rewrite either. (botocore's checksum trailer rides *inside* the aws-chunked entity, not
    /// here - this surfaces genuine HTTP trailers for whichever clients send them.)
    pub trailers: &'a [HeaderView<'a>],
    /// The peer's identity.
    pub peer: &'a ClientAddr,
    /// Where this delivery sits in the body. [`Stage::Whole`] for every non-streaming builder; a streaming connection
    /// walks `Open` -> `Window`* -> `End` for a body it streams and still delivers `Whole` for the rest (see
    /// [`Stage`]).
    pub stage: Stage,
    /// The reply ticket, consumed by [`HttpRequest::defer`].
    responder: Responder,
}

impl<'a> HttpRequest<'a> {
    /// Park this request for deferred completion: retain the head verbatim, the body (an owned move when the reactor
    /// placed it), and the trailers, and detach the `Send` completion handle. Move the [`HttpDeferred`] into your
    /// worker and return the permit as [`HttpVerdict::Defer`]. Only a [`protocol_deferrable`] handler has a verdict to
    /// return it through.
    pub fn defer(self) -> (HttpDeferred, HttpDeferPermit) {
        let HttpRequest {
            mut body,
            raw_head,
            trailers,
            responder,
            stage,
            ..
        } = self;
        let (deferred, permit) = responder.defer();
        let answer = Arc::new(Mutex::new(None));
        let req = Box::new(ParkedRequest {
            head: raw_head.to_vec(),
            stage,
            body: body.take(),
            trailers: trailers.iter().map(|h| (Box::from(h.name), h.value.to_vec())).collect(),
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

    /// Park a **streamed** delivery ([`Stage::Open`] or [`Stage::Window`]) while an async operation - typically a file
    /// write of this very window - completes, without retaining the window.
    ///
    /// [`HttpRequest::defer`] copies the body into the park so [`HttpDeferred::redrive`] can re-run the handler on it.
    /// A stream park resolved by [`HttpStreamDeferred::resume`] never re-runs the handler - the stream just moves to
    /// its next read - so the copy buys nothing, and for a window written straight from the receive buffer
    /// (`pwritev2_from`) it is the allocation the whole path exists to remove. The head is still retained (it is small
    /// and [`HttpStreamDeferred::fail`] serializes against it); the body is not, which is why this deferral cannot
    /// redrive. The window itself comes back to the caller: the park no longer holds it, and the operation this
    /// deferral waits on is usually *of* those bytes - they stay valid for the delivery (the reactor recycles the
    /// buffer only after the write that borrows it completes).
    pub fn defer_stream(self) -> (HttpStreamDeferred, HttpDeferPermit, Body<'a>) {
        let HttpRequest {
            raw_head,
            responder,
            body,
            stage,
            ..
        } = self;
        let (deferred, permit) = responder.defer();
        let answer = Arc::new(Mutex::new(None));
        let req = Box::new(ParkedRequest {
            head: raw_head.to_vec(),
            stage,
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

/// A request retained across a park: everything a redelivery needs to re-present the identical request view, plus the
/// answer cell a worker's [`HttpDeferred::reply`] fills. Fully owned - the connection buffer it was parsed from is
/// recycled while the request is parked.
pub(crate) struct ParkedRequest {
    /// The head block verbatim (`raw_head`), viewed again at completion so no negotiated fact is copied aside where it
    /// could drift.
    head: Vec<u8>,
    /// The stage this delivery was made at, so a redrive re-presents it as itself. The resume phase cannot answer for
    /// it: an `End` park carries no resume state at all (`settle(conn, d, None)` on both End arms), which is
    /// indistinguishable there from a park taken at `Whole`.
    stage: Stage,
    /// The body, taken owned at [`HttpRequest::defer`] (zero-copy when the reactor placed it).
    body: Vec<u8>,
    /// Owned trailer fields.
    trailers: Vec<(Box<str>, Vec<u8>)>,
    /// `Some` once a worker chose [`HttpDeferred::reply`] or [`HttpStreamDeferred::resume`]; the redelivery acts on it
    /// instead of re-running the handler.
    answer: Arc<Mutex<Option<ParkAnswer>>>,
}

/// What a worker decided for a parked request.
pub(crate) enum ParkAnswer {
    /// Serialize this response ([`HttpDeferred::reply`]). Boxed so the resume variant does not carry a response-sized
    /// cell.
    Reply(Box<HttpResponse>),
    /// A streamed window is done with: put the streaming phase back and answer nothing, without re-running the
    /// handler - which is what lets a stream park retain no body ([`HttpRequest::defer_stream`]).
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
/// Every non-streaming builder delivers [`Stage::Whole`] and nothing else -- the whole body, once, as those builders
/// document.
///
/// A streaming connection opens with [`Stage::Open`] before a body byte exists, hands each window over as
/// [`Stage::Window`], and closes with [`Stage::End`] - **for the bodies it streams**. It delivers `Whole` for
/// everything else it carries: a bodyless request, and a `Content-Length` body at or under one window, both of which
/// take the buffered path because a whole delivery there is already one pooled read. So a streaming handler has to
/// answer a `Whole` delivery the way a non-streaming one would; [`HttpVerdict::Continue`] is refused at `Whole` and at
/// `End` alike, and refusing it closes the connection with no HTTP response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stage {
    /// The whole body arrived at once.
    Whole,
    /// A streamed body's head, before any body byte. The one place to refuse a body the server does not want - and,
    /// when the client sent `Expect: 100-continue`, refusing here means the interim line is never sent at all rather
    /// than sent and then contradicted.
    Open,
    /// One chunk of a streamed body; `body` is this window's payload and nothing is retained between windows.
    Window,
    /// A streamed body is complete and `trailers` are parsed. The response belongs here.
    End,
}

/// A deferrable handler's decision for one request.
// The verdict is built and consumed within one dispatch - it never rests anywhere - so boxing the response to level the
// variant sizes would buy nothing but a per-response allocation on the hot path.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum HttpVerdict {
    /// Answer now - exactly what a [`protocol`] handler returns.
    Respond(HttpResponse),
    /// The request is parked; the detached [`HttpDeferred`] completes it.
    Defer(HttpDeferPermit),
    /// Accepted; read on. Only meaningful on a streamed delivery ([`Stage::Open`] or [`Stage::Window`]) - it is how a
    /// consumer says "no reply yet, send me the next window". Returning it from [`Stage::Whole`] or [`Stage::End`]
    /// would leave the request unanswered, so it closes the connection instead.
    Continue,
}

impl From<HttpResponse> for HttpVerdict {
    fn from(resp: HttpResponse) -> Self {
        HttpVerdict::Respond(resp)
    }
}

/// Proof that [`HttpRequest::defer`] was called for this request, carrying the retained request. Returning it as
/// [`HttpVerdict::Defer`] files the request into the connection's parked phase; the inner permit's token is verified at
/// delivery exactly as for a raw [`Response::Defer`](crate::net::server::Response::Defer), so a permit stashed from
/// another request closes the connection instead of parking one nothing could resolve.
#[derive(Debug)]
#[must_use = "return HttpVerdict::Defer(permit) from the handler"]
pub struct HttpDeferPermit {
    permit: DeferPermit,
    req: Box<ParkedRequest>,
}

/// An owned, `Send` completion handle for a parked HTTP request. Exactly one of the three methods consumes it; dropping
/// it unresolved closes the connection (the inner net handle's drop), so a lost or panicked worker cannot leak a parked
/// slot.
#[must_use = "dropping an HttpDeferred unresolved closes the connection"]
pub struct HttpDeferred {
    answer: Arc<Mutex<Option<ParkAnswer>>>,
    inner: Deferred,
}

impl HttpDeferred {
    /// Re-dispatch the retained request through the handler on the server thread: the second invocation sees the
    /// identical request view - for a worker that warmed the state the first pass was missing. The rerun may respond,
    /// defer again, or close.
    pub fn redrive(self) {
        self.inner.redeliver();
    }

    /// Complete the request with `resp`, built on the worker. Serialization still happens on the server thread against
    /// the request's own negotiated head facts - HEAD body elision, keep-alive vs close, the smuggling forced-close,
    /// the `Date` cache - so no response policy is duplicated off-thread.
    pub fn reply(self, resp: HttpResponse) {
        // The cell write happens-before the redeliver's channel send, so the completion pass observes it (modelled by
        // `loom_tests`).
        *self.answer.lock().unwrap_or_else(PoisonError::into_inner) = Some(ParkAnswer::Reply(Box::new(resp)));
        self.inner.redeliver();
    }

    /// Close the connection without a response.
    pub fn close(self) {
        self.inner.close();
    }
}

/// The completion handle of a [`defer_stream`](HttpRequest::defer_stream) park: resume the stream, fail it, or close -
/// never redrive, because the park retained no body to re-run the handler on.
#[must_use = "dropping an HttpStreamDeferred unresolved closes the connection"]
pub struct HttpStreamDeferred {
    answer: Arc<Mutex<Option<ParkAnswer>>>,
    inner: Deferred,
}

impl HttpStreamDeferred {
    /// The parked window is dealt with: resume the stream at its next read. The handler is not re-run; the next thing
    /// it sees is the next window (or [`Stage::End`]).
    pub fn resume(self) {
        // The cell write happens-before the redeliver's channel send, so the completion pass observes it (modelled by
        // `loom_tests`).
        *self.answer.lock().unwrap_or_else(PoisonError::into_inner) = Some(ParkAnswer::Resume);
        self.inner.redeliver();
    }

    /// Refuse the stream with `resp` - a mid-body answer, so the reply is forced final and the connection flush-closes,
    /// exactly as an inline mid-body [`HttpVerdict::Respond`] would.
    pub fn fail(self, resp: HttpResponse) {
        *self.answer.lock().unwrap_or_else(PoisonError::into_inner) = Some(ParkAnswer::Reply(Box::new(resp)));
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

/// Wall-clock seconds for the `Date` header; the one impurity, kept at the edge so everything under it stays
/// deterministic.
fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Serialize `resp` against what `head` negotiated and pick the reactor verdict: keep-alive replies, farewells
/// flush-close. `dates` is the per-reactor cache rendering the `Date` value once a second, not once a response.
/// `draining` forces the close: the reply goes out with a close disposition, so the reactor discards anything buffered
/// behind it and closes once it is sent, and the head says so rather than let the peer find out on its next request.
/// Force a reply to end the connection.
///
/// A response produced while a body is still arriving has abandoned the rest of it: nothing will read those bytes, so a
/// keep-alive answer would leave the framer to take them for the next request - a desync that presents to the client as
/// a spurious second response. The keep-alive disposition sits in a different field for each reply shape, which is why
/// this exists rather than a match at each of the three call sites: the one that only handled `Response::Reply`
/// silently missed every response with a body, because those are `ReplyVectored`.
fn force_final(resp: Response) -> Response {
    match resp {
        Response::Reply(b) => Response::ReplyClose(b),
        Response::ReplyVectored { segments, .. } => Response::ReplyVectored { segments, close: true },
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
    // A reply made while a body is still arriving abandons the rest of it, so the connection cannot persist and the
    // header must say so - a peer told keep-alive and then given EOF has to guess whether it was answered or cut off.
    abandons_body: bool,
) -> Response {
    // A head carrying both Content-Length and Transfer-Encoding frames as chunked here because the transfer coding wins
    // under RFC 9112 section 6.3. A front end that prefers Content-Length would frame the same bytes with a different
    // boundary, and that difference is the CL.TE smuggling primitive. Keep the coding preference for client
    // compatibility and make the exchange non pipelinable instead. The reply drops keep alive so no pipelined request
    // rides behind a smuggled prefix on this connection.
    let (keep_alive, cl_te_conflict) = head.response_disposition();
    let keep = keep_alive && !resp.close && !cl_te_conflict && !draining && !abandons_body;
    let conn = match (keep, head.version) {
        (true, Version::Http11) => ConnHeader::None,
        (true, Version::Http10) => ConnHeader::KeepAlive,
        (false, _) => ConnHeader::Close,
    };
    let head_only = head.method == "HEAD";
    match serialize_reply(resp, head_only, dates.get(now_secs()), conn) {
        // A response with a body hands its head and body as separate segments,
        // scattered vectored so the body is never copied into the head buffer;
        // a HEAD or bodyless response is just the head. Keep-alive vs close is the same disposition either way.
        Serialized::Split { head: head_bytes, body } => Response::ReplyVectored {
            segments: vec![head_bytes.into(), body.into()],
            close: !keep,
        },
        // A file-sourced body: the reactor streams it behind the head (`HttpResponse::file_body`). The serializer
        // already applied the HEAD/bodyless elisions, so a tail reaching here always streams.
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

/// The one interim this codec sends (RFC 9110 sec. 10.1.1), as wire bytes. `Response::Reply` sends them verbatim - the
/// interim never travels through [`HttpResponse`], which replaces a 1xx with 500. Four arms release it and they must
/// release the same bytes, so there is one copy of them.
const CONTINUE_LINE: &[u8] = b"HTTP/1.1 100 Continue\r\n\r\n";

/// The farewell for a connection the framer failed: a real status line, then flush-close. Tiny text body so a captured
/// trace is self-explanatory -- elided when the dying request was a HEAD (`head_only`), whose responses must not carry
/// content lest the client read the body bytes as the next response's head.
fn farewell(status: u16, head_only: bool, dates: &mut DateCache) -> Response {
    let resp = HttpResponse::new(status).body(format!("error {status}\n"));
    Response::ReplyClose(serialize(&resp, head_only, dates.get(now_secs()), ConnHeader::Close))
}

/// The per-delivery fs facade threaded through [`step`] to every dispatching arm: the reactor's request-bound
/// [`FsConn`](crate::uring_fs::FsConn) (`None` when the server has no fs pool) under `uring-fs`.
#[cfg(feature = "uring-fs")]
pub(crate) type FsSlot<'a> = Option<crate::uring_fs::FsConn<'a>>;
/// Without `uring-fs`: a zero-sized placeholder, so [`dispatch`]/[`step`] keep one shape and the handler bound one
/// arity in both builds.
#[cfg(not(feature = "uring-fs"))]
pub(crate) type FsSlot<'a> = std::marker::PhantomData<&'a ()>;

/// A second facade over the slot, for the one arm that dispatches twice (the window exhausting a known-length stream
/// carries the End stage too). The recv-buffer claim moves to the split-off facade.
#[cfg(feature = "uring-fs")]
fn split_slot<'s>(fs: &'s mut FsSlot<'_>) -> FsSlot<'s> {
    fs.as_mut().map(|c| c.reborrow())
}
#[cfg(not(feature = "uring-fs"))]
fn split_slot<'s>(fs: &'s mut FsSlot<'_>) -> FsSlot<'s> {
    *fs
}

/// What one handler invocation produced: a reactor verdict, or a park to file into the connection's phase.
enum Dispatched {
    Done(Response),
    /// The consumer accepted a streamed delivery and wants the next one.
    Continue,
    Park {
        permit: DeferPermit,
        req: Box<ParkedRequest>,
    },
}

/// View a head the framer already accepted through the caller's array, or the `500` farewell a head that no longer
/// reads (a codec bug) is answered with. The view comes from the connection's [`HeadIndex`], so the head is not
/// tokenized a second time. Shared by the inline dispatch and the parked completion so the header-count cap and the
/// farewell shape cannot drift between them.
fn head_or_farewell<'a, 'buf>(
    head_bytes: &'buf [u8],
    index: &HeadIndex,
    headers: &'a mut [HeaderView<'buf>; MAX_HEADERS],
    dates: &mut DateCache,
) -> std::result::Result<Head<'a>, Response> {
    match head_view(index, head_bytes, headers) {
        Err(_) | Ok(None) => Err(farewell(500, method_is_head(head_bytes), dates)),
        Ok(Some(h)) => Ok(h),
    }
}

/// View a delivered head and run the consumer's handler against it - the shared tail of the normal path, the
/// 100-continue dance, and a parked request's redelivery, so all three hand handlers an identical request view by
/// construction.
// The parts are the request itself plus the ticket, the connection state, and the serialization context; bundling them
// would be artificial here.
#[allow(clippy::too_many_arguments)]
fn dispatch<U, H>(
    head_bytes: &[u8],
    index: &HeadIndex,
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
    let mut headers: [HeaderView<'_>; MAX_HEADERS] = [HeaderView::EMPTY; MAX_HEADERS];
    let h = match head_or_farewell(head_bytes, index, &mut headers, dates) {
        Ok(h) => h,
        Err(resp) => return Dispatched::Done(resp),
    };
    // Minted before the responder moves into the handler, read after it returns: a handler that starts the drain itself
    // (an admin shutdown endpoint) still sends the close with its own reply.
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
                // A reply at Open or Window is a refusal: the body it declined is still coming and nothing will read
                // it.
                matches!(stage, Stage::Open | Stage::Window),
            ))
        }
        HttpVerdict::Defer(p) => Dispatched::Park {
            permit: p.permit,
            req: p.req,
        },
        // A delivery that owes a reply cannot be continued past: nothing would ever answer it, and the connection would
        // hang until a timeout. Close rather than leak the slot.
        HttpVerdict::Continue if matches!(stage, Stage::Whole | Stage::End) => Dispatched::Done(Response::Close),
        HttpVerdict::Continue => Dispatched::Continue,
    }
}

/// Serialize a worker-built reply against the parked request's own head -- the same [`respond`] policy the inline path
/// applies, so keep-alive, HEAD elision, and the smuggling forced-close cannot fork between the two.
fn respond_parked(
    head_bytes: &[u8],
    index: &HeadIndex,
    resp: HttpResponse,
    dates: &mut DateCache,
    draining: bool,
    abandons_body: bool,
) -> Response {
    let mut headers: [HeaderView<'_>; MAX_HEADERS] = [HeaderView::EMPTY; MAX_HEADERS];
    match head_or_farewell(head_bytes, index, &mut headers, dates) {
        Ok(h) => respond(&h, resp, dates, draining, abandons_body),
        Err(farewell) => farewell,
    }
}

/// One delivered message against the connection's phase - the entire `body` handler as a plain function (the closure in
/// [`protocol_deferrable`] is a one-line adapter), so tests exercise the real dance/keep-alive/park/farewell code.
// The parts are the delivered message, its reply ticket and fs facade, the connection state, and the serialization
// context; bundling them would be artificial here (the same shape `dispatch` allows).
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
    /// File a park into the phase, or pass the verdict through - the shared tail of every dispatching arm.
    fn settle<U>(conn: &mut HttpConn<U>, d: Dispatched, resume: Option<super::framer::StreamPark>) -> Response {
        match d {
            Dispatched::Done(resp) => resp,
            Dispatched::Park { permit, req } => {
                conn.phase = Phase::Parked {
                    req,
                    resume: resume.map(Box::new),
                };
                Response::Defer(permit)
            }
            // Only a streamed delivery produces this, and those arms handle it themselves - reaching here would mean a
            // request went unanswered.
            Dispatched::Continue => Response::Close,
        }
    }
    /// Release, or withhold, the interim a streamed open owed. Three arms reach this - the inline open, the deferred
    /// resume, and the redrive - and an arm that answered `Vec::new()` where the others answered the interim would
    /// leave an expecting client waiting on its own timeout for a body the stream is already open for.
    fn interim(expect: bool) -> Response {
        Response::Reply(if expect { CONTINUE_LINE.to_vec() } else { Vec::new() })
    }

    match std::mem::replace(&mut conn.phase, Phase::Head) {
        // The framer's farewell: everything buffered was delivered as a degenerate message; answer and flush-close. The
        // HEAD flag rides in the phase from the moment the failure was declared - after the dance the head bytes are
        // consumed and the delivered bytes are the client's body, so sniffing them here would let a body that spells
        // "HEAD " force an incomplete farewell (and a real HEAD's farewell grow a body its client would read as the
        // next response).
        Phase::Fail { status, head_only } => farewell(status, head_only, dates),
        // Dance message 1: the head alone. Queue the interim line verbatim (Reply sends raw bytes) and advance the
        // phase; the framer will declare the body next.
        Phase::ExpectHead { head, body } => {
            // A drain reads no body this connection has not started: the interim would invite one and the connection
            // would then close under it. Refuse now, with a close, so the peer retries elsewhere instead of sending
            // into a connection that is gone.
            if responder.draining() {
                return farewell(503, method_is_head(&head), dates);
            }
            conn.phase = Phase::ExpectBody { head, body };
            Response::Reply(CONTINUE_LINE.to_vec())
        }
        // Dance message 2: the body alone, paired with the stash. (A chunked dance never lands here - the framer morphs
        // ExpectBody into the scan phase before declaring anything.)
        Phase::ExpectBody { head: stash, .. } => {
            let d = dispatch(
                &stash,
                &conn.index,
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
        // A complete chunked message: de-chunk the wire extent, then dispatch the entity against the in-buffer head or
        // the dance's stash. When the reactor handed the wire allocation over (the dance delivers the body alone, and
        // large bodies arrive owned), de-chunk **in place**: ownership moves and the entity stays in the same
        // allocation - the single-chunk shape default botocore sends moves no bytes at all, and the handler's take()
        // truncates instead of copying. A borrowed delivery keeps the borrowing paths: a single-chunk entity is a
        // borrow of the wire, only stitched multi-chunk entities allocate. The framer's scan accepted these exact
        // bytes, so a de-chunk failure is a codec bug, answered as one.
        Phase::ChunkedDone { stash } => {
            let head_bytes = stash.as_deref().unwrap_or(header);
            if let Some((mut wire, _)) = body.take_owned() {
                return match chunked::compact(&mut wire) {
                    Ok(c) => match c.trailers() {
                        Ok(trailers) => {
                            let d = dispatch(
                                head_bytes,
                                &conn.index,
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
                        Err(()) => farewell(500, method_is_head(head_bytes), dates),
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
                        &conn.index,
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
        // Mid-scan delivery cannot happen (the framer only answers `More` in this phase); total for the same reason as
        // Fail above.
        Phase::ChunkedBody { stash, .. } => farewell(500, method_is_head(stash.as_deref().unwrap_or(header)), dates),
        // The normal path: head + body in one message.
        Phase::Head => {
            let d = dispatch(
                header,
                &conn.index,
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
        // A parked request's completion, arriving as a redelivery (the frame is empty; everything real was retained at
        // the park). A worker `reply` left the response in the cell - serialize it against the retained head. Otherwise
        // this is a `redrive`: run the handler again over the identical request view; it may respond, park again, or
        // close.
        // A streamed body opens with its head and no bytes. This is the consumer's one chance to refuse before the peer
        // commits to sending - and when the client asked for `100-continue`, the interim line is withheld until the
        // consumer has actually accepted, so a refusal goes out *instead* of it rather than after inviting a body
        // nobody wanted.
        Phase::StreamOpen { head, expect, body } => {
            if responder.draining() {
                return farewell(503, method_is_head(&head), dates);
            }
            let d = dispatch(
                &head,
                &conn.index,
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
            // Built after the dispatch, which only borrows the head, so the head moves into the phase it opens instead
            // of being copied alongside a borrow that is already finished with it.
            let next = match body {
                super::framer::StreamedBody::Chunked => Phase::StreamBody {
                    head,
                    chunk_left: 0,
                    after_payload: false,
                    decoded: 0,
                },
                super::framer::StreamedBody::Known(len) => Phase::StreamKnown { head, remaining: len },
            };
            match d {
                Dispatched::Continue => {
                    conn.phase = next;
                    interim(expect)
                }
                // Refused, or parked to decide off-thread. A refusal is final: the body it declined is still coming and
                // nothing will read it, so the reply closes rather than leaves the connection framing a body against
                // the next request.
                Dispatched::Done(resp) => force_final(resp),
                d => settle(
                    conn,
                    d,
                    Some(super::framer::StreamPark {
                        next,
                        // The interim was withheld pending this very decision; the resume owes it, or the client never
                        // sends the body it is parked deciding on.
                        expect_interim: expect,
                    }),
                ),
            }
        }
        // One chunk of a streamed body. Nothing is retained between windows: the reactor's `consume` drops each one,
        // which is what stops the body's size bounding what the server can accept.
        Phase::StreamBody {
            head,
            chunk_left,
            after_payload,
            decoded,
        } => {
            let delivered = body.len();
            // How much of this chunk is still owed. Mid-chunk the answer is carried; on a chunk's first window it comes
            // from re-reading the size line, which is exactly what `header` holds. The framer cannot leave it here
            // instead: it re-runs for the same window while the payload arrives, and a second run would then take the
            // mid-chunk branch and declare a different message.
            let owed = if chunk_left > 0 {
                chunk_left
            } else {
                match chunked::step(header, after_payload) {
                    chunked::Step::Chunk { payload, .. } => payload,
                    // The framer accepted these bytes a moment ago, so a disagreement is a codec bug; treat the window
                    // as the whole chunk rather than desync on it.
                    _ => delivered,
                }
            };
            let left = owed.saturating_sub(delivered);
            let d = dispatch(
                &head,
                &conn.index,
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
            // After the dispatch, which only borrows the head: this arm runs once per window for the life of the
            // upload, so a clone here is a head copy per 128 KiB. Its known-length twin below already moves.
            let next = Phase::StreamBody {
                head,
                chunk_left: left,
                // Only a fully delivered chunk owes the CRLF that closes it; a split one is still mid-payload.
                after_payload: left == 0,
                // Counted here, once per delivery, because the framer re-runs for the same window while its bytes
                // arrive.
                decoded: decoded.saturating_add(delivered),
            };
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
                        // Mid-body: any interim went out when the open was answered.
                        expect_interim: false,
                    }),
                ),
            }
        }
        // One window of a known-length streamed body: raw payload, no framing of its own, counted down against the
        // declared length. The delivery that exhausts the length also carries the End stage: no wire byte is left to
        // frame one from (the reactor refuses a zero-length message), so it runs here on the spot - or, if this window
        // parks, when the park resumes.
        Phase::StreamKnown { head, remaining } => {
            let left = remaining.saturating_sub(body.len() as u64);
            let mut fs = fs;
            let d = dispatch(
                &head,
                &conn.index,
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
                        &conn.index,
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
                    conn.phase = Phase::StreamKnown { head, remaining: left };
                    Response::Reply(Vec::new())
                }
                Dispatched::Done(resp) => force_final(resp),
                d => settle(
                    conn,
                    d,
                    Some(super::framer::StreamPark {
                        // An exhausted length owes only the End stage;
                        // `StreamDone` is what the resume arm reads as "dispatch it now, nothing further to frame".
                        next: if left == 0 {
                            // A known-length body has no terminal block at all; the End stage is dispatched from the
                            // resume with nothing to parse.
                            Phase::StreamDone { head, block_at: 0 }
                        } else {
                            Phase::StreamKnown { head, remaining: left }
                        },
                        // Mid-body: any interim went out when the open was answered.
                        expect_interim: false,
                    }),
                ),
            }
        }
        // The terminal chunk: the delivered header IS the trailer section, so the trailers are parsed from it here
        // rather than carried.
        Phase::StreamDone { head, block_at } => {
            // The terminal block is itself a complete (empty) chunked message, so the whole-message compactor parses
            // its trailer section. It has to outlive the dispatch: the views borrow it. `block_at` skips the CRLF that
            // closed the last payload, which the compactor would read as an empty - malformed - size line and refuse,
            // losing every trailer with it.
            let mut wire = header[block_at.min(header.len())..].to_vec();
            let compacted = chunked::compact(&mut wire).ok();
            let trailers = compacted.as_ref().and_then(|c| c.trailers().ok()).unwrap_or_default();
            let d = dispatch(
                &head,
                &conn.index,
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
                stage,
                body: parked,
                trailers,
                answer,
            } = *req;
            let chosen = answer.lock().unwrap_or_else(PoisonError::into_inner).take();
            match chosen {
                // The stream's parked window is dealt with: back to reading, nothing to send, handler not re-run. A
                // resume with no streaming phase to put back is a misuse of `defer_stream` outside a stream - nothing
                // can be resumed, so close.
                Some(ParkAnswer::Resume) => match resume {
                    // A known-length stream whose exhausting window parked: the length is fully consumed, so nothing
                    // remains to frame an End delivery from. Dispatch it here instead, off the resume itself.
                    Some(r) if matches!(r.next, Phase::StreamDone { .. }) => {
                        let d = dispatch(
                            &head,
                            &conn.index,
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
                        // A deferred open accepted: release the withheld interim, or the expecting client holds its
                        // body back until its own timeout and the stream this resume opened never starts.
                        interim(r.expect_interim)
                    }
                    None => Response::Close,
                },
                Some(ParkAnswer::Reply(resp)) => {
                    let resp = *resp;
                    let out = respond_parked(
                        &head,
                        &conn.index,
                        resp,
                        dates,
                        responder.draining(),
                        // A park taken mid-body that answers has abandoned the rest of it, exactly as an inline reply
                        // there would have.
                        resume.is_some(),
                    );
                    // A worker that answered mid-body abandoned a body the peer is still sending. Nothing can read the
                    // rest, so the reply is final: send it and flush-close, rather than resume framing bytes that
                    // belong to a request already answered.
                    match resume {
                        Some(_) => force_final(out),
                        None => out,
                    }
                }
                None => {
                    let views: Vec<HeaderView<'_>> =
                        trailers.iter().map(|(n, v)| HeaderView { name: n, value: v }).collect();
                    // The handles are split because a redriven window that exhausted a known length owes an End
                    // dispatch as well (below), exactly as the inline path does.
                    let mut fs = fs;
                    let d = dispatch(
                        &head,
                        &conn.index,
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
                        // put the streaming phase back, and release any interim a parked open was still withholding -
                        // the redrive route owes it exactly as the resume route does.
                        //
                        // `StreamDone` is not a phase to restore. It marks a known length already spent, so no wire
                        // remains to frame an End delivery from - and the framer's degrade arm would declare whatever
                        // is buffered, i.e. the *next* pipelined request's head, as this message's header. Dispatch End
                        // here instead, which is what the resume route does with the same marker.
                        (Dispatched::Continue, Some(r)) if matches!(r.next, Phase::StreamDone { .. }) => {
                            let d = dispatch(
                                &head,
                                &conn.index,
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
                            interim(r.expect_interim)
                        }
                        (d, resume) => settle(conn, d, resume.map(|r| *r)),
                    }
                }
            }
        }
    }
}

/// The shared constructor behind [`protocol`], [`protocol_deferrable`], and `protocol_fs`: one body closure, one
/// [`step`], with the handler taking the per-delivery [`FsSlot`] so the phase machine keeps a single shape. Each public
/// constructor adapts its own handler bound down to this one -- only `protocol_fs` is feature-gated, so every feature
/// builds alone.
#[allow(clippy::type_complexity)]
fn build<U, A, H>(
    cfg: HttpConfig,
    stream_cap: Option<std::num::NonZeroU64>,
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
    // One date cache per protocol instance - instances are per reactor and handlers run on the reactor thread, so the
    // `Date` value renders once a second instead of once a response, with no synchronization.
    let mut dates = DateCache::default();
    Ok(Protocol {
        accept: move |inc: Incoming<'_>| {
            accept(inc).map(|state| match stream_cap {
                Some(cap) => HttpConn::new_streaming(state, cap),
                None => HttpConn::new(state),
            })
        },
        header: move |buf: &[u8], conn: &mut HttpConn<U>| {
            // The accept wrapper above is not the only admission. A kTLS listener is admitted by
            // `AcceptDeferral::ready`, which takes the connection state directly and never runs it
            // (`net/server/accept.rs`: `install_conn` has exactly two callers, and only the plain-TCP one goes through
            // the accept handler). A worker that hands back `HttpConn::new` there would otherwise get a connection with
            // no cap at all - and `stream_cap` is not merely the streaming switch, it *is* the body limit, so the
            // ceiling would silently become `HttpConfig::max_body` instead of the `max_body_bytes` this protocol was
            // built with. A limit that holds on one transport and not the other is worse than no limit: a deployment
            // sets it, tests it over plain HTTP and ships it.
            //
            // Adopting it here rather than at admission covers every route in, present and future. Safe at this point
            // by construction - `HttpConn::new` leaves `Phase::Head`, so no body is ever in progress the first time
            // this runs - and `is_none` leaves a connection minted `new_streaming` with its own cap.
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
            step(header, body, peer, responder, fs, conn, &mut dates, &mut handler)
        },
    })
}

/// Build the reactor [`Protocol`] for an HTTP/1.1 endpoint whose handler may also reach the server's **request-bound fs
/// facade**.
///
/// The handler is [`protocol_deferrable`]'s with one more argument: the reactor's per-request
/// [`FsConn`](crate::uring_fs::FsConn) - `Some` when the server was built with an fs pool
/// ([`ServerConfig::fs_ops`](crate::net::server::ServerConfig::fs_ops)), else `None`. A `Protocol` is built before its
/// `Server`, so this constructor cannot check; for a handler that asked for this constructor, `None` is a deployment
/// misconfiguration, and answering `500` is the honest response.
///
/// The consumer's model, in full:
///
/// - **The facade is per delivery.** It borrows the reactor for the call and cannot be stored; every invocation of the
///   handler - first delivery or redelivery - receives a fresh one.
/// - **Fs work parks the request.** Take the facade, then [`HttpRequest::defer`] the request (defer consumes it),
///   capture the [`HttpDeferred`] in the op's continuation, and return [`HttpVerdict::Defer`]; the continuation, or a
///   later offload delivery, resolves it via [`HttpDeferred::reply`].
/// - **A continuation may `open`, and owns what it opens.** [`open`](crate::uring_fs::FsConn::open) works on every
///   facade, including the one a continuation or offload delivery receives. That facade runs for an owner that may
///   already be gone, and nothing sweeps a descriptor opened after its connection closed, so a chain that opens must
///   reach a step that closes. A handler that would rather re-enter with a fresh delivery can still park its progress
///   in the connection state `U` and call [`HttpDeferred::redrive`].
/// - **Offload jobs are never cancelled** ([`FsConn::offload`](crate::uring_fs::FsConn::offload)): a delivery may fire
///   for a request that is gone, and a resolved [`HttpDeferred`] for a vanished request is a generation-checked no-op
///   rather than a hazard.
///
/// The parking discipline is [`protocol_deferrable`]'s, including its `max_in_flight_requests` guidance. Errors when
/// `cfg` fails [`HttpConfig::validate`].
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
    H: FnMut(HttpRequest<'_>, &mut U, Option<crate::uring_fs::FsConn<'_>>) -> HttpVerdict,
{
    build(cfg, None, accept, handler)
}

/// Build the reactor [`Protocol`] for an HTTP/1.1 endpoint whose handler may **park** a request for deferred
/// completion.
///
/// `accept` is the standard admission hook returning the consumer's per-connection state `U`; `handler` runs once per
/// delivery with the parsed [`HttpRequest`] view and `&mut U`, and returns an
/// [`HttpVerdict`]: [`Respond`](HttpVerdict::Respond) answers inline
/// (exactly a [`protocol`] handler), or - after [`HttpRequest::defer`] -- [`Defer`](HttpVerdict::Defer) parks the
/// request while the reactor keeps polling. The worker then completes it through the [`HttpDeferred`]:
/// [`redrive`](HttpDeferred::redrive) re-runs the handler on the server thread once state is warm,
/// [`reply`](HttpDeferred::reply) delivers a worker-built response (serialized on the server thread), and
/// [`close`](HttpDeferred::close) hangs up. Handlers still run on the server thread and must not block.
///
/// Intended for the default `max_in_flight_requests == 1`: while a request is parked nothing later is read or
/// delivered, so reply order is request order. Above that cap the framer still holds pipelined requests back during a
/// park, but the armed read-ahead then carries `request_timeout` while parked - run deferrable endpoints at the default
/// cap.
///
/// Errors when `cfg` fails [`HttpConfig::validate`] - a codec that can admit no request is refused here, not discovered
/// one 431 at a time.
// Same shape and rationale as `length_prefixed`: the three opaque closures ARE the signature; boxing them would put dyn
// dispatch on the hot path.
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
        move |req: HttpRequest<'_>, state: &mut U, _fs: FsSlot<'_>| handler(req, state),
    )
}

/// The streaming cap as the type the connection state holds.
///
/// The cap IS the body limit on a streaming connection - `stream_cap` bounds every body, buffered or not - so a zero is
/// the same "admits nothing" configuration [`HttpConfig::validate`] exists to refuse: every request carrying a byte of
/// body would be answered 413 while a bodyless GET was served normally, an endpoint that reads healthy and admits no
/// payload. `HttpConfig::validate` cannot see it, because the cap is a builder argument rather than a config field.
///
/// The builders take a plain `u64` and refuse zero here, so a misconfiguration is a named `Validation` rather than a
/// type error at the call site. Past this point it is `NonZeroU64` and there is nothing left to check - which is the
/// half that matters, since [`HttpConn::new_streaming`](super::HttpConn::new_streaming) is public and reaches the same
/// state without passing through any builder.
fn stream_cap(max_body_bytes: u64) -> crate::Result<std::num::NonZeroU64> {
    std::num::NonZeroU64::new(max_body_bytes)
        .ok_or_else(|| crate::Error::Validation("http streaming max_body_bytes must be non-zero".into()))
}

/// Build the reactor [`Protocol`] for an HTTP/1.1 endpoint that **streams** request bodies rather than buffering them.
///
/// A chunked body is delivered a chunk at a time instead of once when its terminal chunk lands, and a `Content-Length`
/// body above one window a window at a time, so the largest body the endpoint accepts stops being a buffer size. The
/// handler walks [`Stage::Open`] (the head, before any body byte), then [`Stage::Window`] per chunk or window, then
/// [`Stage::End`] once any trailers are parsed - and answers with [`HttpVerdict::Continue`] until `End`, where the
/// response belongs.
///
/// `max_body_bytes` bounds the body: for chunked the decoded size, checked as each chunk is declared; for
/// `Content-Length` the declared length, checked at the head. It is a parameter rather than a field on [`HttpConfig`]
/// because [`HttpConfig::max_body`] is the bound a *buffered* delivery checks before reading; whoever knows the
/// protocol above knows this number (an S3 front bounds a part at 5 GiB).
///
/// # What a streamed request does differently
///
/// - **A refusal closes the connection.** The body it declined is still being sent and nothing will read it, so a
///   keep-alive reply would frame the remainder as the next request. That applies to a refusal at `Open` and to one
///   mid-body alike.
/// - **`Expect: 100-continue` is answered by the handler, not ahead of it.** The interim line is withheld until the
///   handler returns [`HttpVerdict::Continue`] from `Open`, so a refusal goes out *instead* of the interim rather than
///   after having invited a body. (A `Content-Length` body at or under one window takes the buffered path, where the
///   interim invites at most one window's worth - there is no stream for a veto to save.)
/// - **Nothing is retained between windows.** Each window's payload is dropped once the handler returns, so a handler
///   that needs the body must consume it as it arrives.
///
/// Errors when `cfg` fails [`HttpConfig::validate`].
///
/// **A kTLS listener needs the cap passed by hand.** The streaming decision is made in this function's accept closure,
/// and a kTLS connection is admitted by `AcceptDeferral::ready` instead - the accept handler never runs for one. A
/// handshake worker that hands back [`HttpConn::new`] therefore gets a buffering connection whose effective ceiling is
/// `max_request_bytes`; use [`HttpConn::new_streaming`] with `max_body_bytes` there.
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
        Some(stream_cap(max_body_bytes)?),
        accept,
        move |req: HttpRequest<'_>, state: &mut U, _fs: FsSlot<'_>| handler(req, state),
    )
}

/// [`protocol_streaming`] with the per-request fs facade, as `protocol_fs` is to [`protocol_deferrable`] - a streaming
/// handler that writes what it receives needs somewhere to put each window, and that is the ring the server already
/// drives.
///
/// Errors when `cfg` fails [`HttpConfig::validate`].
///
/// **A kTLS listener needs the cap passed by hand.** The streaming decision is made in this function's accept closure,
/// and a kTLS connection is admitted by `AcceptDeferral::ready` instead - the accept handler never runs for one. A
/// handshake worker that hands back [`HttpConn::new`] therefore gets a buffering connection whose effective ceiling is
/// `max_request_bytes`; use [`HttpConn::new_streaming`] with `max_body_bytes` there.
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
    H: FnMut(HttpRequest<'_>, &mut U, Option<crate::uring_fs::FsConn<'_>>) -> HttpVerdict,
{
    build(cfg, Some(stream_cap(max_body_bytes)?), accept, handler)
}

/// Build the reactor [`Protocol`] for an HTTP/1.1 endpoint.
///
/// `accept` is the standard admission hook returning the consumer's per-connection state `U`; `handler` is invoked once
/// per request with the parsed [`HttpRequest`] view and `&mut U`, and returns the [`HttpResponse`] to serialize.
/// Handlers run on the server thread -- compute inline like any reactor `body` handler; a handler that must wait on
/// other threads uses [`protocol_deferrable`] instead, and one that must also touch the filesystem, `protocol_fs` (with
/// the `uring-fs` feature).
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
mod tests;

// ---------------------------------------------------------------------------
// loom model of the parked reply hand-off
// ---------------------------------------------------------------------------
//
// Run with:  RUSTFLAGS="--cfg loom" cargo test --lib --features http loom_
//
// The park's cross-thread protocol, the one edge in this module two threads share:
//
//   worker (HttpDeferred::reply)        loop (drain, then step on Parked)
//   *answer.lock() = Some(resp)         wake.drain()
//   tx.send(Redeliver); wake.poke()     rx.try_recv() -> Redeliver
//                                       answer.lock().take()
//
// The cell is filled before the redeliver is sent, and the completion pass takes the cell only after consuming the
// wake, so a `reply` can never be observed as a redrive. Break either half - fill after the send, or take before the
// wake - and a schedule exists where the completion pass takes `None`: the handler reruns against a consumed handle and
// the worker's response is lost. The model drives the real `defer`/`reply`/`step`, with the loop's recv order supplied
// by the probe.
#[cfg(all(test, loom))]
mod loom_tests;
