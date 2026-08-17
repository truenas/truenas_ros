//! Glue: build a [`net::server::Protocol`](Protocol) from an HTTP handler.
//! The `header` handler is the framer step; the `body` handler drives the
//! phase machine — pairing stashed heads with their bodies, sending the
//! `100 Continue` interim, serializing responses, and mapping keep-alive
//! onto [`Response::Reply`] vs [`Response::ReplyClose`]. The whole body
//! handler lives in [`step`], a plain function over the delivered message
//! and the connection's phase, so tests drive the real glue without a
//! reactor.

use std::borrow::Cow;
use std::sync::PoisonError;
use std::time::{SystemTime, UNIX_EPOCH};

// The answer cell is cross-thread state (a worker fills it, the loop takes
// it), so it rides `crate::sync` — std in production, loom's in the model
// below, which is what lets the model see the fill/redeliver ordering.
use crate::sync::{Arc, Mutex};

use crate::net::server::{
    Body, DeferPermit, Deferred, Incoming, Protocol, Request, Responder,
    Response,
};
use crate::net::ClientAddr;

use super::chunked;
use super::date::DateCache;
use super::framer::{frame, HttpConfig, HttpConn, Phase};
use super::head::{
    method_is_head, parse_head, Head, HeaderView, Version, MAX_HEADERS,
};
use super::response::{
    serialize, serialize_reply, ConnHeader, HttpResponse, Serialized,
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
    /// Request-target, verbatim and undecoded (S3 keys percent-decode at the
    /// S3 layer, where encoding is semantically load-bearing).
    pub target: &'a str,
    /// Protocol version (1.0 or 1.1; anything else died with 505).
    pub version: Version,
    /// Parsed header index, wire order preserved.
    pub headers: &'a [HeaderView<'a>],
    /// The request body (complete — bounded by [`HttpConfig::max_body`]).
    /// Deref for in-place reads; [`Body::take`] moves the bytes out — a
    /// zero-copy move when the reactor placed the body in its own
    /// allocation, and for a chunked body delivered owned (the 100-continue
    /// dance path at or over the placement threshold) an in-place truncate
    /// of the de-chunked wire — so a handler that keeps the payload (an S3
    /// PUT) never pays a second copy.
    pub body: Body<'a>,
    /// The head block verbatim, including the terminating CRLFCRLF — the
    /// diagnostic to echo in a `SignatureDoesNotMatch` reply. Build the SigV4
    /// canonical request from [`headers`](HttpRequest::headers) (borrows into
    /// this buffer, values verbatim minus edge-trim), never by re-splitting
    /// this block: the tokenizer accepts a bare LF as a line terminator
    /// (RFC 9112 §2.2), so a CRLF-strict re-parse would draw header
    /// boundaries the request is not served on — the header-smuggling
    /// differential the parsed view does not have.
    pub raw_head: &'a [u8],
    /// Trailer fields from a chunked body (RFC 9112 §7.1.2), parsed but not
    /// interpreted; empty for non-chunked requests and for chunked bodies
    /// whose trailer section is bare. Names forbidden in trailers —
    /// framing, routing, and credentials (RFC 9110 §6.5.1) — are dropped by
    /// the codec and never appear here, so merging these with the headers
    /// cannot rewrite either. (botocore's checksum trailer rides *inside*
    /// the aws-chunked entity, not here — this surfaces genuine HTTP
    /// trailers for whichever clients send them.)
    pub trailers: &'a [HeaderView<'a>],
    /// The peer's identity.
    pub peer: &'a ClientAddr,
    /// The reply ticket, consumed by [`HttpRequest::defer`].
    responder: Responder,
}

impl HttpRequest<'_> {
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
/// [`HttpDeferred::reply`] fills. Fully owned — the connection buffer it was
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
    /// `Some` once a worker chose [`HttpDeferred::reply`]; the redelivery
    /// serializes it instead of re-running the handler.
    answer: Arc<Mutex<Option<HttpResponse>>>,
}

impl std::fmt::Debug for ParkedRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ParkedRequest")
            .field("head_len", &self.head.len())
            .field("body_len", &self.body.len())
            .finish_non_exhaustive()
    }
}

/// A deferrable handler's decision for one request.
// The verdict is built and consumed within one dispatch — it never rests
// anywhere — so boxing the response to level the variant sizes would buy
// nothing but a per-response allocation on the hot path.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum HttpVerdict {
    /// Answer now — exactly what a [`protocol`] handler returns.
    Respond(HttpResponse),
    /// The request is parked; the detached [`HttpDeferred`] completes it.
    Defer(HttpDeferPermit),
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
    answer: Arc<Mutex<Option<HttpResponse>>>,
    inner: Deferred,
}

impl HttpDeferred {
    /// Re-dispatch the retained request through the handler on the server
    /// thread: the second invocation sees the identical request view — for
    /// a worker that warmed the state the first pass was missing. The rerun
    /// may respond, defer again, or close.
    pub fn redrive(self) {
        self.inner.redeliver();
    }

    /// Complete the request with `resp`, built on the worker. Serialization
    /// still happens on the server thread against the request's own
    /// negotiated head facts — HEAD body elision, keep-alive vs close, the
    /// smuggling forced-close, the `Date` cache — so no response policy is
    /// duplicated off-thread.
    pub fn reply(self, resp: HttpResponse) {
        // The cell write happens-before the redeliver's channel send, so
        // the completion pass observes it (modelled by `loom_tests`).
        *self.answer.lock().unwrap_or_else(PoisonError::into_inner) =
            Some(resp);
        self.inner.redeliver();
    }

    /// Close the connection without a response.
    pub fn close(self) {
        self.inner.close();
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
/// response.
fn respond(
    head: &Head<'_>,
    resp: HttpResponse,
    dates: &mut DateCache,
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
    let keep = keep_alive && !resp.close && !cl_te_conflict;
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
/// flush-close. Tiny text body so a captured trace is self-explanatory —
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

/// What one handler invocation produced: a reactor verdict, or a park to
/// file into the connection's phase.
enum Dispatched {
    Done(Response),
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

/// Parse a delivered head and run the consumer's handler against it — the
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
    state: &mut U,
    dates: &mut DateCache,
    handler: &mut H,
) -> Dispatched
where
    H: FnMut(HttpRequest<'_>, &mut U) -> HttpVerdict,
{
    let mut headers: [HeaderView<'_>; MAX_HEADERS] =
        [HeaderView::EMPTY; MAX_HEADERS];
    let h = match reparse_or_farewell(head_bytes, &mut headers, dates) {
        Ok(h) => h,
        Err(resp) => return Dispatched::Done(resp),
    };
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
        },
        state,
    ) {
        HttpVerdict::Respond(resp) => {
            Dispatched::Done(respond(&h, resp, dates))
        }
        HttpVerdict::Defer(p) => Dispatched::Park {
            permit: p.permit,
            req: p.req,
        },
    }
}

/// Serialize a worker-built reply against the parked request's own head —
/// the same [`respond`] policy the inline path applies, so keep-alive, HEAD
/// elision, and the smuggling forced-close cannot fork between the two.
fn respond_parked(
    head_bytes: &[u8],
    resp: HttpResponse,
    dates: &mut DateCache,
) -> Response {
    let mut headers: [HeaderView<'_>; MAX_HEADERS] =
        [HeaderView::EMPTY; MAX_HEADERS];
    match reparse_or_farewell(head_bytes, &mut headers, dates) {
        Ok(h) => respond(&h, resp, dates),
        Err(farewell) => farewell,
    }
}

/// One delivered message against the connection's phase — the entire `body`
/// handler as a plain function (the closure in [`protocol_deferrable`] is a
/// one-line adapter), so tests exercise the real
/// dance/keep-alive/park/farewell code.
fn step<U, H>(
    header: &[u8],
    mut body: Body<'_>,
    peer: &ClientAddr,
    responder: Responder,
    conn: &mut HttpConn<U>,
    dates: &mut DateCache,
    handler: &mut H,
) -> Response
where
    H: FnMut(HttpRequest<'_>, &mut U) -> HttpVerdict,
{
    /// File a park into the phase, or pass the verdict through — the shared
    /// tail of every dispatching arm.
    fn settle<U>(conn: &mut HttpConn<U>, d: Dispatched) -> Response {
        match d {
            Dispatched::Done(resp) => resp,
            Dispatched::Park { permit, req } => {
                conn.phase = Phase::Parked { req };
                Response::Defer(permit)
            }
        }
    }
    match std::mem::replace(&mut conn.phase, Phase::Head) {
        // The framer's farewell: everything buffered was delivered as a
        // degenerate message; answer and flush-close. The HEAD flag rides
        // in the phase from the moment the failure was declared — after the
        // dance the head bytes are consumed and the delivered bytes are the
        // client's body, so sniffing them here would let a body that spells
        // "HEAD " force an incomplete farewell (and a real HEAD's farewell
        // grow a body its client would read as the next response).
        Phase::Fail { status, head_only } => farewell(status, head_only, dates),
        // Dance message 1: the head alone. Queue the interim line verbatim
        // (Reply sends raw bytes) and advance the phase; the framer will
        // declare the body next.
        Phase::ExpectHead { head, body } => {
            conn.phase = Phase::ExpectBody { head, body };
            Response::Reply(b"HTTP/1.1 100 Continue\r\n\r\n".to_vec())
        }
        // Dance message 2: the body alone, paired with the stash. (A
        // chunked dance never lands here — the framer morphs ExpectBody
        // into the scan phase before declaring anything.)
        Phase::ExpectBody { head: stash, .. } => {
            let d = dispatch(
                &stash,
                body,
                &[],
                peer,
                responder,
                &mut conn.state,
                dates,
                handler,
            );
            settle(conn, d)
        }
        // A complete chunked message: de-chunk the wire extent, then
        // dispatch the entity against the in-buffer head or the dance's
        // stash. When the reactor handed the wire allocation over (the
        // dance delivers the body alone, and large bodies arrive owned),
        // de-chunk **in place**: ownership moves and the entity stays in
        // the same allocation — the single-chunk shape default botocore
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
                                &mut conn.state,
                                dates,
                                handler,
                            );
                            settle(conn, d)
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
                        &mut conn.state,
                        dates,
                        handler,
                    );
                    settle(conn, d)
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
                &mut conn.state,
                dates,
                handler,
            );
            settle(conn, d)
        }
        // A parked request's completion, arriving as a redelivery (the frame
        // is empty; everything real was retained at the park). A worker
        // `reply` left the response in the cell — serialize it against the
        // retained head. Otherwise this is a `redrive`: run the handler
        // again over the identical request view; it may respond, park
        // again, or close.
        Phase::Parked { req } => {
            let ParkedRequest {
                head,
                body: parked,
                trailers,
                answer,
            } = *req;
            let chosen =
                answer.lock().unwrap_or_else(PoisonError::into_inner).take();
            match chosen {
                Some(resp) => respond_parked(&head, resp, dates),
                None => {
                    let views: Vec<HeaderView<'_>> = trailers
                        .iter()
                        .map(|(n, v)| HeaderView { name: n, value: v })
                        .collect();
                    let d = dispatch(
                        &head,
                        Body::placed(parked),
                        &views,
                        peer,
                        responder,
                        &mut conn.state,
                        dates,
                        handler,
                    );
                    settle(conn, d)
                }
            }
        }
    }
}

/// Build the reactor [`Protocol`] for an HTTP/1.1 endpoint whose handler
/// may **park** a request for deferred completion.
///
/// `accept` is the standard admission hook returning the consumer's
/// per-connection state `U`; `handler` runs once per delivery with the
/// parsed [`HttpRequest`] view and `&mut U`, and returns an
/// [`HttpVerdict`]: [`Respond`](HttpVerdict::Respond) answers inline
/// (exactly a [`protocol`] handler), or — after [`HttpRequest::defer`] —
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
/// while parked — run deferrable endpoints at the default cap.
///
/// Errors when `cfg` fails [`HttpConfig::validate`] — a codec that can
/// admit no request is refused here, not discovered one 431 at a time.
// Same shape and rationale as `length_prefixed`: the three opaque closures
// ARE the signature; boxing them would put dyn dispatch on the hot path.
#[allow(clippy::type_complexity)]
pub fn protocol_deferrable<U, A, H>(
    cfg: HttpConfig,
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
    H: FnMut(HttpRequest<'_>, &mut U) -> HttpVerdict,
{
    cfg.validate()?;
    // One date cache per protocol instance — instances are per reactor and
    // handlers run on the reactor thread, so the `Date` value renders once
    // a second instead of once a response, with no synchronization.
    let mut dates = DateCache::default();
    Ok(Protocol {
        accept: move |inc: Incoming<'_>| accept(inc).map(HttpConn::new),
        header: move |buf: &[u8], conn: &mut HttpConn<U>| {
            frame(buf, conn, &cfg)
        },
        body: move |req: Request<'_, HttpConn<U>>| {
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
                conn,
                &mut dates,
                &mut handler,
            )
        },
    })
}

/// Build the reactor [`Protocol`] for an HTTP/1.1 endpoint.
///
/// `accept` is the standard admission hook returning the consumer's
/// per-connection state `U`; `handler` is invoked once per request with the
/// parsed [`HttpRequest`] view and `&mut U`, and returns the
/// [`HttpResponse`] to serialize. Handlers run on the server thread —
/// compute inline like any reactor `body` handler; a handler that must
/// wait on other threads uses [`protocol_deferrable`] instead.
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
    use crate::net::Framing;

    /// [`step`] with a throwaway date cache and responder — the tests assert
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

    /// [`drive`] for verdict handlers — the park tests' entry.
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
            conn,
            &mut DateCache::default(),
            handler,
        )
    }

    fn peer() -> ClientAddr {
        ClientAddr::Inet("127.0.0.1:9000".parse().unwrap())
    }

    fn cfg() -> HttpConfig {
        HttpConfig::default()
    }

    /// Reply bytes as text, whatever the verdict — a vectored reply is
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
        assert!(protocol(
            bad,
            |_: Incoming<'_>| Some(()),
            |_: HttpRequest<'_>, _: &mut ()| HttpResponse::new(200),
        )
        .is_err());
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
        assert!(!close, "keep-alive request → no close");
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
        // No body (an empty-body 200, and a status that forbids one) → a
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

        // Message 1: the head alone → the interim, and the phase advances.
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
        // the farewell into a bodyless HEAD response — a declared
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
        // layer only — the aws-chunked entity must pass through untouched.
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

        // Message 1: the head alone → the interim, and the phase advances.
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
        // reach the handler's take() from that same allocation — ownership
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
    /// completion must apply the HEAD contract — length on the wire, no
    /// body bytes — proving the reply serializes against the parked head.
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
        // Message 1: the head alone → the interim; the handler never runs.
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
        // Message 2: the body → the park.
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
// observed as a redrive. Break either half — fill after the send, or take
// before the wake — and a schedule exists where the completion pass takes
// `None`: the handler reruns against a consumed handle and the worker's
// response is lost. The model drives the real `defer`/`reply`/`step`, with
// the loop's recv order supplied by the probe.
#[cfg(all(test, loom))]
mod loom_tests {
    use super::*;
    use crate::net::server::Body;
    use crate::net::ClientAddr;
    use crate::sync::thread;

    fn unreached(_: HttpRequest<'_>, _: &mut ()) -> HttpVerdict {
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
                responder,
            };
            let (deferred, permit) = req.defer();
            let HttpDeferPermit {
                permit: _permit,
                req: parked,
            } = permit;
            let mut conn: HttpConn<()> = HttpConn::new(());
            conn.phase = Phase::Parked { req: parked };

            let worker = thread::spawn(move || {
                deferred.reply(HttpResponse::new(204));
            });

            probe.recv_redeliver();
            let resp = step(
                b"",
                Body::inline(b""),
                &peer,
                Responder::test_responder(),
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
