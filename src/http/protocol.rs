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
/// Everything borrows from the connection buffer, or the codec's head stash, and the header index is a slice into a
/// fixed array on the caller's stack, so a request costs no heap allocation.
#[non_exhaustive]
pub struct HttpRequest<'a> {
    /// Request method, verbatim (methods are case-sensitive tokens).
    pub method: &'a str,
    /// Request-target in **origin form** (`/path?query`), undecoded. An absolute-form target is accepted only when its
    /// authority matches `Host` and is reduced to its path here, and asterisk-form survives as `*` for `OPTIONS` only,
    /// so this never carries a second authority. `//host/path` is ordinary origin-form and arrives verbatim, so a
    /// consumer re-parsing this as a URI *reference* must not read that as an authority.
    pub target: &'a str,
    /// Protocol version (1.0 or 1.1; anything else died with 505).
    pub version: Version,
    /// Parsed header index, wire order preserved.
    pub headers: &'a [HeaderView<'a>],
    /// The request body, whole at [`Stage::Whole`] and bounded by [`HttpConfig::max_body`], or this window's payload on
    /// a streamed delivery. Deref for in-place reads. [`Body::take`] moves the bytes out without a copy when the
    /// reactor placed the body in its own allocation, including an owned chunked body de-chunked in place.
    pub body: Body<'a>,
    /// The head block verbatim, including the terminating CRLFCRLF, for diagnostics. Anything that canonicalizes the
    /// request builds from [`headers`](HttpRequest::headers) and never re-splits this block, since the tokenizer
    /// accepts a bare LF as a line terminator (RFC 9112 sec. 2.2) and a CRLF-strict re-parse would draw header
    /// boundaries the request is not served on.
    pub raw_head: &'a [u8],
    /// Trailer fields from a chunked body (RFC 9112 sec. 7.1.2), parsed but not interpreted, and empty otherwise. Names
    /// forbidden in trailers, being framing, routing and credentials (RFC 9110 sec. 6.5.1), are dropped by the codec,
    /// so merging these with the headers cannot rewrite either.
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

    /// Park a **streamed** delivery ([`Stage::Open`] or [`Stage::Window`]) while an async operation, typically a write
    /// of this very window, completes, without retaining the window.
    ///
    /// This exists because [`HttpRequest::defer`] copies the body into the park so [`HttpDeferred::redrive`] can re-run
    /// the handler on it. A stream park resolved by [`HttpStreamDeferred::resume`] never re-runs the handler, so the
    /// copy buys nothing, and for a window written straight from the receive buffer (`pwritev2_from`) it is the
    /// allocation the path exists to remove. The park keeps the head only, for [`HttpStreamDeferred::fail`] to
    /// serialize against, which is why it cannot redrive. The window comes back to the caller and stays valid for the
    /// delivery, since the reactor recycles the buffer only after the write that borrows it completes.
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
/// Every non-streaming builder delivers [`Stage::Whole`] and nothing else. A streaming connection opens with
/// [`Stage::Open`] before a body byte exists, hands each window over as [`Stage::Window`], and closes with
/// [`Stage::End`], **for the bodies it streams**. It still delivers `Whole` for a bodyless request and for a
/// `Content-Length` body at or under one window, so a streaming handler answers `Whole` as a non-streaming one would.
/// [`HttpVerdict::Continue`] at `Whole` or `End` closes the connection with no HTTP response.
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

/// Force a reply to end the connection.
///
/// A response made while a body is still arriving has abandoned the rest of it, and a keep-alive answer would leave the
/// framer to take those bytes for the next request. The keep-alive disposition sits in a different field for each reply
/// shape, so every call site goes through here rather than matching `Response::Reply` alone and missing the vectored
/// and file replies.
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

/// Serialize `resp` against what `head` negotiated and pick the reactor verdict, where keep-alive replies and farewells
/// flush-close. `dates` renders the `Date` value once a second. `draining` forces the close, and the head says so
/// rather than let the peer find out on its next request.
fn respond(
    head: &Head<'_>,
    resp: HttpResponse,
    dates: &mut DateCache,
    draining: bool,
    // A reply made while a body is still arriving abandons the rest of it, so the connection cannot persist and the
    // header must say so - a peer told keep-alive and then given EOF has to guess whether it was answered or cut off.
    abandons_body: bool,
) -> Response {
    // A CL+TE head frames as chunked (RFC 9112 sec. 6.3), the CL.TE smuggling differential, so the reply drops
    // keep-alive and nothing rides behind a smuggled prefix on this connection.
    let (keep_alive, cl_te_conflict) = head.response_disposition();
    let keep = keep_alive && !resp.close && !cl_te_conflict && !draining && !abandons_body;
    let conn = match (keep, head.version) {
        (true, Version::Http11) => ConnHeader::None,
        (true, Version::Http10) => ConnHeader::KeepAlive,
        (false, _) => ConnHeader::Close,
    };
    let head_only = head.method == "HEAD";
    match serialize_reply(resp, head_only, dates.get(now_secs()), conn) {
        // A body goes as its own segment, sent vectored so it is never copied into the head buffer.
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
    /// Release, or withhold, the interim a streamed open owed. The inline open, the deferred resume and the redrive all
    /// answer through here, so none can leave an expecting client waiting on its own timeout.
    fn interim(expect: bool) -> Response {
        Response::Reply(if expect { CONTINUE_LINE.to_vec() } else { Vec::new() })
    }

    match std::mem::replace(&mut conn.phase, Phase::Head) {
        // The framer's farewell. The HEAD flag rides in the phase from when the failure was declared, since after the
        // dance the delivered bytes are the client's body, and sniffing them would let a body spelling "HEAD " change
        // the farewell.
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
        // A complete chunked message, de-chunked and dispatched against the in-buffer head or the dance's stash. An
        // owned delivery is de-chunked **in place**, so a single-chunk entity moves no bytes and the handler's take()
        // truncates. The framer's scan accepted these bytes, so a de-chunk failure is a codec bug.
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
        // A streamed body opens with its head and no bytes, the consumer's one chance to refuse before the peer
        // commits. A requested interim is withheld until the consumer accepts, so a refusal goes out *instead* of it.
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
            // How much of this chunk is still owed, carried mid-chunk and read off the size line in `header` on a
            // chunk's first window. The framer cannot leave it in the phase, since it re-runs for the same window and
            // would then declare a different message.
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
            // Built after the dispatch, which only borrows the head, so the head moves rather than being cloned once
            // per window.
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
                        // An exhausted length owes only the End stage, which the resume dispatches on seeing
                        // `StreamDone`.
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
            // The terminal block is itself a complete empty chunked message, so the compactor parses its trailers, and
            // the wire must outlive the dispatch since the views borrow it. `block_at` skips the CRLF that closed the
            // last payload, which would read as a malformed size line.
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
        // A parked request's completion, arriving as a redelivery with an empty frame. A worker's `reply` left a
        // response in the cell and a `resume` left a marker, and an empty cell is a `redrive`, which runs the handler
        // again over the identical request view.
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
                    // Final for the same reason, rather than resume framing bytes that belong to a request already
                    // answered.
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
                        // `StreamDone` is not a phase to restore. A spent known length leaves no wire to frame End
                        // from, and the framer's degrade arm would declare the next pipelined request's head as this
                        // message, so dispatch End here as the resume route does.
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
                        // Redriven and accepted with content to read on. Put the streaming phase back and release any
                        // interim a parked open still withheld, as the resume route does.
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
            // Adopt the protocol's cap on a connection admitted without the accept wrapper, as `AcceptDeferral::ready`
            // admits a kTLS one, since the cap is the body limit and not only the streaming switch. `Phase::Head` holds
            // no body the first time this runs, and `is_none` keeps a cap minted by `new_streaming`.
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
/// The handler is [`protocol_deferrable`]'s with one more argument, the reactor's per-request
/// [`FsConn`](crate::uring_fs::FsConn). It is `Some` when the server was built with an fs pool
/// ([`ServerConfig::fs_ops`](crate::net::server::ServerConfig::fs_ops)) and else `None`, a misconfiguration the handler
/// answers `500`.
///
/// - **The facade is per delivery.** It borrows the reactor for the call and cannot be stored.
/// - **Fs work parks the request.** [`HttpRequest::defer`] it, capture the [`HttpDeferred`] in the op's continuation,
///   return [`HttpVerdict::Defer`], and resolve it with [`HttpDeferred::reply`].
/// - **A continuation that opens owns what it opens.** Its facade may outlive the connection, and nothing sweeps a
///   descriptor opened after its connection closed, so a chain that opens must reach a step that closes.
/// - **Offload jobs are never cancelled** ([`FsConn::offload`](crate::uring_fs::FsConn::offload)). A resolved
///   [`HttpDeferred`] for a vanished request is a generation-checked no-op.
///
/// The parking discipline is [`protocol_deferrable`]'s. Errors when `cfg` fails [`HttpConfig::validate`].
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
/// `accept` returns the consumer's per-connection state `U`, and `handler` runs once per delivery with the parsed
/// [`HttpRequest`] and `&mut U`. It returns [`Respond`](HttpVerdict::Respond) to answer inline, or, after
/// [`HttpRequest::defer`], [`Defer`](HttpVerdict::Defer) to park the request while the reactor keeps polling. The
/// worker completes it with [`redrive`](HttpDeferred::redrive), [`reply`](HttpDeferred::reply) or
/// [`close`](HttpDeferred::close). Handlers run on the server thread and must not block.
///
/// Run it at the default `max_in_flight_requests == 1`. Above that the framer still holds pipelined requests during a
/// park, but the armed read-ahead carries `request_timeout` while parked.
///
/// Errors when `cfg` fails [`HttpConfig::validate`].
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

/// The streaming cap as the type the connection state holds. A zero would answer 413 to every body while serving a
/// bodyless GET, the configuration that admits nothing, which [`HttpConfig::validate`] refuses but cannot see here,
/// since the cap is a builder argument. The builders refuse it as a named `Validation`.
fn stream_cap(max_body_bytes: u64) -> crate::Result<std::num::NonZeroU64> {
    std::num::NonZeroU64::new(max_body_bytes)
        .ok_or_else(|| crate::Error::Validation("http streaming max_body_bytes must be non-zero".into()))
}

/// Build the reactor [`Protocol`] for an HTTP/1.1 endpoint that **streams** request bodies rather than buffering them.
///
/// A chunked body is delivered a chunk at a time and a `Content-Length` body above one window a window at a time. The
/// handler walks [`Stage::Open`] (the head, before any body byte), then [`Stage::Window`] per chunk or window, then
/// [`Stage::End`] once any trailers are parsed, answering [`HttpVerdict::Continue`] until `End`, where the response
/// belongs.
///
/// `max_body_bytes` bounds every body on the connection, the decoded size for chunked as each chunk is declared and the
/// declared length for `Content-Length` at the head. [`HttpConfig::max_body`] still bounds a body that arrives as one
/// delivery.
///
/// - **A refusal closes the connection**, at `Open` or mid-body, since the declined body is still being sent.
/// - **`Expect: 100-continue` is answered by the handler.** The interim is withheld until the handler returns
///   [`HttpVerdict::Continue`] from `Open`, so a refusal goes out instead of it. A body at or under one window takes
///   the buffered path, where the interim invites at most one window.
/// - **Nothing is retained between windows**, so a handler that needs the body consumes it as it arrives.
///
/// A connection admitted without the accept handler, as a kTLS handshake worker's is, adopts this cap at its first
/// frame unless it was minted with [`HttpConn::new_streaming`]. Errors when `cfg` fails [`HttpConfig::validate`].
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

/// [`protocol_streaming`] with the per-request fs facade, as `protocol_fs` is to [`protocol_deferrable`], so a
/// streaming handler can write each window on the ring the server already drives.
///
/// Errors when `cfg` fails [`HttpConfig::validate`].
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
/// `accept` returns the consumer's per-connection state `U`, and `handler` runs once per request with the parsed
/// [`HttpRequest`] and `&mut U` and returns the [`HttpResponse`] to serialize. Handlers run on the server thread, so
/// one that must wait on other threads uses [`protocol_deferrable`], and one that touches the filesystem `protocol_fs`
/// (with `uring-fs`).
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
// A worker's `reply` fills the answer cell before it sends the redeliver, and the completion pass takes the cell only
// after consuming the wake, so a `reply` is never observed as a redrive. Break either half and a schedule exists where
// the pass takes `None`, reruns the handler against a consumed handle and loses the worker's response. The model drives
// the real `defer`, `reply` and `step`.
#[cfg(all(test, loom))]
mod loom_tests;
