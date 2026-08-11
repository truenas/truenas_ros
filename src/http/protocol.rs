//! Glue: build a [`net::server::Protocol`](Protocol) from an HTTP handler.
//! The `header` handler is the framer step; the `body` handler drives the
//! phase machine — pairing stashed heads with their bodies, sending the
//! `100 Continue` interim, serializing responses, and mapping keep-alive
//! onto [`Response::Reply`] vs [`Response::ReplyClose`]. The whole body
//! handler lives in [`step`], a plain function over the delivered message
//! and the connection's phase, so tests drive the real glue without a
//! reactor.

use std::borrow::Cow;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::net::server::{Body, Incoming, Protocol, Request, Response};
use crate::net::ClientAddr;

use super::chunked;
use super::date::HttpDate;
use super::framer::{frame, HttpConfig, HttpConn, Phase};
use super::head::{parse_head, Head, HeaderView, Version, MAX_HEADERS};
use super::response::{serialize, ConnHeader, HttpResponse};

/// One HTTP request, as handed to the consumer's handler.
///
/// Everything borrows from the connection buffer (or the codec's head stash
/// on the 100-continue path); the header index is a slice into a fixed array
/// on the caller's stack, so a request costs no per-request heap allocation.
/// `raw_head` is the head block verbatim, byte-for-byte as the client
/// sent it: signature schemes that canonicalize "headers as sent" (SigV4)
/// read from here, never from a cooked view. `#[non_exhaustive]`, so future
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
    /// allocation, so a handler that keeps the payload (an S3 PUT) never
    /// pays a second copy.
    pub body: Body<'a>,
    /// The head block verbatim, including the terminating CRLFCRLF.
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

/// Wall-clock seconds for the `Date` header; the one impurity, kept at the
/// edge so everything under it stays deterministic.
fn now() -> HttpDate {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    HttpDate::from_unix(secs)
}

/// Serialize `resp` against what `head` negotiated and pick the reactor
/// verdict: keep-alive replies, farewells flush-close.
fn respond(head: &Head<'_>, resp: HttpResponse) -> Response {
    let keep = head.keep_alive() && !resp.close;
    let conn = match (keep, head.version) {
        (true, Version::Http11) => ConnHeader::None,
        (true, Version::Http10) => ConnHeader::KeepAlive,
        (false, _) => ConnHeader::Close,
    };
    let bytes = serialize(&resp, head.method == "HEAD", now(), conn);
    if keep {
        Response::Reply(bytes)
    } else {
        Response::ReplyClose(bytes)
    }
}

/// The farewell for a connection the framer failed: a real status line, then
/// flush-close. Tiny text body so a captured trace is self-explanatory —
/// elided when the dying request was a HEAD (`head_only`), whose responses
/// must not carry content lest the client read the body bytes as the next
/// response's head.
fn farewell(status: u16, head_only: bool) -> Response {
    let resp = HttpResponse::new(status).body(format!("error {status}\n"));
    Response::ReplyClose(serialize(&resp, head_only, now(), ConnHeader::Close))
}

/// Parse a delivered head and run the consumer's handler against it — the
/// shared tail of the normal path and the 100-continue dance, so the two
/// hand handlers an identical request view by construction.
fn dispatch<U, H>(
    head_bytes: &[u8],
    body: Body<'_>,
    trailers: &[HeaderView<'_>],
    peer: &ClientAddr,
    state: &mut U,
    handler: &mut H,
) -> Response
where
    H: FnMut(HttpRequest<'_>, &mut U) -> HttpResponse,
{
    let mut headers: [HeaderView<'_>; MAX_HEADERS] =
        [HeaderView::EMPTY; MAX_HEADERS];
    match parse_head(head_bytes, &mut headers) {
        // The framer completed on these exact bytes (or on the stash it
        // parsed once already); a divergence here is a codec bug, answered
        // as such.
        Err(_) | Ok(None) => farewell(500, head_bytes.starts_with(b"HEAD ")),
        Ok(Some(h)) => {
            let resp = handler(
                HttpRequest {
                    method: h.method,
                    target: h.target,
                    version: h.version,
                    headers: h.headers,
                    body,
                    raw_head: head_bytes,
                    trailers,
                    peer,
                },
                state,
            );
            respond(&h, resp)
        }
    }
}

/// One delivered message against the connection's phase — the entire `body`
/// handler as a plain function (the closure in [`protocol`] is a one-line
/// adapter), so tests exercise the real dance/keep-alive/farewell code.
fn step<U, H>(
    header: &[u8],
    body: Body<'_>,
    peer: &ClientAddr,
    conn: &mut HttpConn<U>,
    handler: &mut H,
) -> Response
where
    H: FnMut(HttpRequest<'_>, &mut U) -> HttpResponse,
{
    match std::mem::replace(&mut conn.phase, Phase::Head) {
        // The framer's farewell: everything buffered was delivered as a
        // degenerate message; answer and flush-close. The HEAD flag rides
        // in the phase from the moment the failure was declared — after the
        // dance the head bytes are consumed and the delivered bytes are the
        // client's body, so sniffing them here would let a body that spells
        // "HEAD " force an incomplete farewell (and a real HEAD's farewell
        // grow a body its client would read as the next response).
        Phase::Fail { status, head_only } => farewell(status, head_only),
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
            dispatch(&stash, body, &[], peer, &mut conn.state, handler)
        }
        // A complete chunked message: de-chunk the wire extent, then
        // dispatch the entity against the in-buffer head or the dance's
        // stash. A single-chunk message decodes to a borrow of the wire
        // (no copy — the shape default botocore sends); only stitched
        // multi-chunk entities carry their own allocation. The framer's
        // scan accepted these exact bytes, so a decode failure is a codec
        // bug, answered as one.
        Phase::ChunkedDone { stash } => {
            let head_bytes = stash.as_deref().unwrap_or(header);
            match chunked::decode(&body) {
                Ok((entity, trailers)) => {
                    let entity = match entity {
                        Cow::Borrowed(span) => Body::inline(span),
                        Cow::Owned(v) => Body::placed(v),
                    };
                    dispatch(
                        head_bytes,
                        entity,
                        &trailers,
                        peer,
                        &mut conn.state,
                        handler,
                    )
                }
                Err(()) => farewell(500, head_bytes.starts_with(b"HEAD ")),
            }
        }
        // Mid-scan delivery cannot happen (the framer only answers `More`
        // in this phase); total for the same reason as Fail above.
        Phase::ChunkedBody { stash, .. } => farewell(
            500,
            stash.as_deref().unwrap_or(header).starts_with(b"HEAD "),
        ),
        // The normal path: head + body in one message.
        Phase::Head => {
            dispatch(header, body, &[], peer, &mut conn.state, handler)
        }
    }
}

/// Build the reactor [`Protocol`] for an HTTP/1.1 endpoint.
///
/// `accept` is the standard admission hook returning the consumer's
/// per-connection state `U`; `handler` is invoked once per request with the
/// parsed [`HttpRequest`] view and `&mut U`, and returns the
/// [`HttpResponse`] to serialize. Handlers run on the server thread —
/// compute inline like any reactor `body` handler. (`Response::Defer`
/// offload for HTTP handlers is a planned follow-up on this seam.)
// Same shape and rationale as `length_prefixed`: the three opaque closures
// ARE the signature; boxing them would put dyn dispatch on the hot path.
#[allow(clippy::type_complexity)]
pub fn protocol<U, A, H>(
    cfg: HttpConfig,
    mut accept: A,
    mut handler: H,
) -> Protocol<
    impl FnMut(Incoming<'_>) -> Option<HttpConn<U>>,
    impl FnMut(&[u8], &mut HttpConn<U>) -> crate::net::Framing,
    impl FnMut(Request<'_, HttpConn<U>>) -> Response,
>
where
    A: FnMut(Incoming<'_>) -> Option<U>,
    H: FnMut(HttpRequest<'_>, &mut U) -> HttpResponse,
{
    Protocol {
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
                ..
            } = req;
            step(header, body, peer, conn, &mut handler)
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::Framing;

    fn peer() -> ClientAddr {
        ClientAddr::Inet("127.0.0.1:9000".parse().unwrap())
    }

    fn cfg() -> HttpConfig {
        HttpConfig::default()
    }

    /// Reply bytes as text, whatever the verdict.
    fn text(resp: &Response) -> &str {
        match resp {
            Response::Reply(b) | Response::ReplyClose(b) => {
                std::str::from_utf8(b).expect("responses are ascii here")
            }
            other => panic!("expected reply bytes, got {other:?}"),
        }
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
        step(
            &raw[..header_len],
            Body::inline(&raw[header_len..]),
            &p,
            conn,
            handler,
        )
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
        assert!(matches!(resp, Response::Reply(_)));
        let s = text(&resp);
        assert!(s.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(s.contains("Content-Length: 5\r\n"));
        assert!(!s.contains("Connection:"));
        assert!(s.ends_with("\r\n\r\nhello"));
        assert_eq!(conn.state, 1);
        assert!(matches!(conn.phase, Phase::Head));
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
        assert!(matches!(resp, Response::ReplyClose(_)));
        assert!(text(&resp).contains("Connection: close\r\n"));
        // HTTP/1.0 with negotiated keep-alive echoes it.
        let resp = roundtrip(
            b"GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n",
            &mut HttpConn::new(()),
            &mut ok,
        );
        assert!(matches!(resp, Response::Reply(_)));
        assert!(text(&resp).contains("Connection: keep-alive\r\n"));
        // HTTP/1.1 with Connection: close farewells.
        let resp = roundtrip(
            b"GET / HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n",
            &mut HttpConn::new(()),
            &mut ok,
        );
        assert!(matches!(resp, Response::ReplyClose(_)));
        assert!(text(&resp).contains("Connection: close\r\n"));
        // Handler-forced close overrides negotiated keep-alive.
        let mut closer =
            |_: HttpRequest<'_>, _: &mut ()| HttpResponse::new(200).close();
        let resp = roundtrip(
            b"GET / HTTP/1.1\r\nHost: h\r\n\r\n",
            &mut HttpConn::new(()),
            &mut closer,
        );
        assert!(matches!(resp, Response::ReplyClose(_)));
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
            step(head, Body::inline(b""), &p, &mut conn, &mut handler);
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
        let resp = step(b"", Body::inline(b"abc"), &p, &mut conn, &mut handler);
        assert!(matches!(resp, Response::Reply(_)));
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
        let resp = step(junk, Body::inline(b""), &p, &mut conn, &mut unreached);
        assert!(matches!(resp, Response::ReplyClose(_)));
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
        let resp = step(req, Body::inline(b""), &p, &mut conn, &mut unreached);
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
        step(head, Body::inline(b""), &p, &mut conn, &mut unreached);
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
        let resp = step(body, Body::inline(b""), &p, &mut conn, &mut unreached);
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
        step(head, Body::inline(b""), &p, &mut conn, &mut unreached);
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
        let resp = step(body, Body::inline(b""), &p, &mut conn, &mut unreached);
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
        assert!(matches!(resp, Response::Reply(_)));
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
        assert!(matches!(resp, Response::Reply(_)));
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
            step(head, Body::inline(b""), &p, &mut conn, &mut handler);
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
        let resp = step(b"", Body::inline(&wire), &p, &mut conn, &mut handler);
        assert!(matches!(resp, Response::Reply(_)));
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
        let resp = step(
            head,
            Body::placed(b"hello".to_vec()),
            &p,
            &mut conn,
            &mut handler,
        );
        assert!(matches!(resp, Response::Reply(_)));
    }
}
