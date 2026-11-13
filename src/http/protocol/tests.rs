use super::*;
use crate::http::framer::{Phase, STREAM_WINDOW};
use crate::net::Framing;

/// The streaming cap as `new_streaming` takes it. Every literal here is non-zero by inspection; a zero is the
/// configuration the builders refuse and the type no longer represents.
fn nz(n: u64) -> std::num::NonZeroU64 {
    std::num::NonZeroU64::new(n).expect("a non-zero literal cap")
}

/// A streaming protocol streams - and bounds - a connection its accept wrapper never minted.
///
/// A kTLS listener is admitted by `AcceptDeferral::ready`, which takes the connection state directly and never runs
/// the accept handler, so a handshake worker can hand back `HttpConn::new`. `stream_cap` is not merely the
/// streaming switch - it *is* the body limit and it lifts `HttpConfig::max_body` - so without this the endpoint's
/// declared `max_body_bytes` would not apply on the TLS transport at all, and the effective ceiling would be
/// `max_body` instead. A limit that holds on one transport and not the other is worse than no limit.
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

    // A body over one window streams, on a connection minted the way a kTLS handshake worker mints one.
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
    let head = format!("PUT /k HTTP/1.1\r\nHost: h\r\nContent-Length: {}\r\n\r\n", CAP + 1);
    let _ = (proto.header)(head.as_bytes(), &mut conn);
    assert!(
        matches!(conn.phase, Phase::Fail { status: 413, .. }),
        "a body over `max_body_bytes` was admitted against \
             `HttpConfig::max_body` instead: {:?}",
        conn.phase
    );

    // A connection the wrapper *did* mint keeps its own cap - this must adopt, never overwrite.
    let mut conn = HttpConn::new_streaming((), nz(1024));
    let head = b"PUT /k HTTP/1.1\r\nHost: h\r\nContent-Length: 2048\r\n\r\n";
    let _ = (proto.header)(head, &mut conn);
    assert!(
        matches!(conn.phase, Phase::Fail { status: 413, .. }),
        "the protocol's cap overwrote the connection's own: {:?}",
        conn.phase
    );
}

/// [`step`] with a throwaway date cache and responder - the tests assert nothing about `Date` freshness (pinned in
/// `date.rs`) or the injection channel (pinned in the net-layer tests). Plain-response handlers ride the same
/// `Respond` wrapper [`protocol`] applies.
fn drive<U, H>(header: &[u8], body: Body<'_>, peer: &ClientAddr, conn: &mut HttpConn<U>, handler: &mut H) -> Response
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

/// Reply bytes as text, whatever the verdict - a vectored reply is flattened, since on the wire its segments are
/// one contiguous PDU.
fn text(resp: &Response) -> String {
    let bytes = match resp {
        Response::Reply(b) | Response::ReplyClose(b) => b.clone(),
        Response::ReplyVectored { segments, .. } => segments.iter().fold(Vec::new(), |mut all, seg| {
            all.extend_from_slice(seg);
            all
        }),
        other => panic!("expected reply bytes, got {other:?}"),
    };
    String::from_utf8(bytes).expect("responses are ascii here")
}

/// A keep-alive reply (`Reply`, or a vectored reply that keeps serving).
fn is_keep(resp: &Response) -> bool {
    matches!(resp, Response::Reply(_) | Response::ReplyVectored { close: false, .. })
}

/// A flush-close reply (`ReplyClose`, or a vectored reply that closes).
fn is_close(resp: &Response) -> bool {
    matches!(
        resp,
        Response::ReplyClose(_) | Response::ReplyVectored { close: true, .. }
    )
}

/// Frame one complete single-message request and run the glue on it, mirroring the reactor's consume: `header` is
/// the declared head, `body` the declared body bytes.
fn roundtrip<U>(
    raw: &[u8],
    conn: &mut HttpConn<U>,
    handler: &mut impl FnMut(HttpRequest<'_>, &mut U) -> HttpResponse,
) -> Response {
    let verdict = frame(raw, conn, &cfg());
    let Framing::Complete { header_len, body_len } = verdict else {
        panic!("expected a complete frame, got {verdict:?}");
    };
    assert_eq!(header_len + body_len, raw.len());
    let p = peer();
    drive(&raw[..header_len], Body::inline(&raw[header_len..]), &p, conn, handler)
}

/// A streaming endpoint whose cap is zero admits no body at all, which is the same refusal `HttpConfig::validate`
/// makes for a zero `max_head`/`max_body` - and `HttpConfig::validate` cannot see this one, because the cap is a
/// builder argument rather than a config field.
#[test]
fn a_streaming_protocol_rejects_a_zero_body_cap() {
    // The builder's half. The constructor's half is not a test: it is `NonZeroU64` in `HttpConn::new_streaming`'s
    // signature, so a zero cap is unrepresentable rather than refused. That matters because the adoption site fills
    // `stream_cap` only when it is `None` - a connection minted with its own cap keeps it, and a kTLS handshake
    // worker mints exactly that way (`a_streaming_protocol_bounds_a_connection_it_did_not_mint`), so a check here
    // could never have covered it.
    assert!(
        protocol_streaming(
            cfg(),
            0,
            |_: Incoming<'_>| Some(()),
            |_: HttpRequest<'_>, _: &mut ()| HttpVerdict::Continue,
        )
        .is_err(),
        "a zero streaming cap 413s every body-bearing request"
    );
    // The control: a real cap still builds.
    assert!(
        protocol_streaming(
            cfg(),
            1 << 20,
            |_: Incoming<'_>| Some(()),
            |_: HttpRequest<'_>, _: &mut ()| HttpVerdict::Continue,
        )
        .is_ok()
    );
    // And the non-streaming builders are untouched (`stream_cap: None`).
    assert!(
        protocol(
            cfg(),
            |_: Incoming<'_>| Some(()),
            |_: HttpRequest<'_>, _: &mut ()| HttpResponse::new(200),
        )
        .is_ok()
    );
}

#[test]
fn protocol_rejects_a_codec_that_admits_nothing() {
    // The validator runs when the protocol is built, so a zero cap is a construction error, not a server that
    // 431s/413s every request.
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
    let resp = roundtrip(b"GET /hi HTTP/1.1\r\nHost: h\r\n\r\n", &mut conn, &mut handler);
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
    // A response carrying a body is handed over as separate head and body segments (sent vectored, never
    // concatenated); flattened they are a well-formed response with the body after the head.
    let mut handler = |_: HttpRequest<'_>, _: &mut ()| HttpResponse::new(200).body("hello, body");
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
    assert!(segments[0].ends_with(b"\r\n\r\n"), "head ends at blank line");
    assert_eq!(&segments[1][..], b"hello, body", "body is its own segment");
    let s = text(&resp);
    assert!(s.contains("Content-Length: 11\r\n"));
    assert!(s.ends_with("\r\n\r\nhello, body"));
}

#[test]
fn a_bodyless_response_stays_one_buffer() {
    // No body (an empty-body 200, and a status that forbids one) -> a single head buffer, not a vectored reply.
    let mut empty = |_: HttpRequest<'_>, _: &mut ()| HttpResponse::new(200);
    let resp = roundtrip(b"GET / HTTP/1.1\r\nHost: h\r\n\r\n", &mut HttpConn::new(()), &mut empty);
    assert!(matches!(resp, Response::Reply(_)), "empty body: {resp:?}");
    let mut no_content = |_: HttpRequest<'_>, _: &mut ()| HttpResponse::new(204);
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
    let resp = roundtrip(b"GET / HTTP/1.0\r\n\r\n", &mut HttpConn::new(()), &mut ok);
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
    let mut closer = |_: HttpRequest<'_>, _: &mut ()| HttpResponse::new(200).close();
    let resp = roundtrip(
        b"GET / HTTP/1.1\r\nHost: h\r\n\r\n",
        &mut HttpConn::new(()),
        &mut closer,
    );
    assert!(is_close(&resp));
}

#[test]
fn cl_te_conflict_forces_connection_close() {
    // This head carries both Content-Length and Transfer-Encoding, and it frames as chunked because the transfer
    // coding wins. The pair is the CL.TE smuggling differential, so the reply must drop keep alive and the
    // connection cannot be reused behind a smuggled prefix. The body still decodes by the chunked framing.
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

    // A chunked request without a Content-Length is no conflict and it stays keep alive. The forced close is
    // specific to the pair.
    let head = b"PUT /k HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n";
    let mut raw = head.to_vec();
    raw.extend_from_slice(b"5\r\nhello\r\n0\r\n\r\n");
    let mut ok = |_: HttpRequest<'_>, _: &mut ()| HttpResponse::new(200);
    let resp = roundtrip(&raw, &mut HttpConn::new(()), &mut ok);
    assert!(is_keep(&resp), "TE only stays keep alive, got {resp:?}");
    assert!(!text(&resp).contains("Connection: close"));
}

#[test]
fn head_response_elides_body() {
    let mut handler = |_: HttpRequest<'_>, _: &mut ()| HttpResponse::new(200).body("hello");
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
    // One handler, two requests: the declaration reaches the wire on the HEAD and is dropped on the GET. The method
    // decides, so a handler that declares a length unconditionally still cannot promise bytes a GET will not send.
    let mut handler = |_: HttpRequest<'_>, _: &mut ()| HttpResponse::new(200).head_content_length(4096);
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
        let fd: std::os::fd::OwnedFd = std::fs::File::open("/dev/null").expect("open").into();
        crate::uring_fs::File::new(crate::sync::Arc::new(fd))
    }
    let mut handler = |_: HttpRequest<'_>, _: &mut ()| HttpResponse::new(200).file_body(dev_null(), 32, 1024);
    // GET: the reactor streams the tail; the head already carries the declared length, and the range is the
    // handler's.
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
    assert!(matches!(resp, Response::ReplyFile { close: true, .. }), "{resp:?}");

    // HEAD: the length is declared, nothing streams (the handle-drop proof is pinned beside `serialize_reply`).
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
    let head = b"PUT /k HTTP/1.1\r\nHost: h\r\nExpect: 100-continue\r\nContent-Length: 3\r\n\r\n";
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
    let interim = drive(head, Body::inline(b""), &p, &mut conn, &mut handler);
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
    let resp = drive(b"", Body::inline(b"abc"), &p, &mut conn, &mut handler);
    assert!(is_keep(&resp));
    assert!(text(&resp).starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(matches!(conn.phase, Phase::Head));
}

/// An expecting client on a *streaming* endpoint gets its interim when the handler accepts at `Stage::Open`.
///
/// Three routes owe the withheld interim and each carries its own pin: the two deferred ones park first
/// (`a_deferred_stream_open_still_sends_the_interim`, `a_redriven_stream_open_still_sends_the_interim`), and this
/// is the inline one. An interim withheld here stalls an expecting upload for the client's own timeout.
#[test]
fn an_accepted_streamed_open_releases_the_withheld_interim() {
    let head = b"PUT /up HTTP/1.1\r\nHost: h\r\n\
                     Expect: 100-continue\r\n\
                     Transfer-Encoding: chunked\r\n\r\n";
    let mut conn = HttpConn::new_streaming((), nz(1 << 20));
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

/// A refusal at `Stage::Open` goes out *instead of* the interim, and closes.
///
/// This is the whole point of dispatching the head before a body byte: the peer has not committed yet. Answering
/// while leaving the connection open would let the declined body be framed as the next request, and answering
/// *after* a `100 Continue` would have invited a body in order to refuse it.
///
/// Two mechanisms close it here - `force_final` on this arm, and `respond`'s own `abandons_body` disposition - so
/// this asserts the contract rather than either one, and it takes removing both to make it fail.
#[test]
fn a_refused_streamed_open_answers_instead_of_inviting() {
    let head = b"PUT /up HTTP/1.1\r\nHost: h\r\n\
                     Expect: 100-continue\r\n\
                     Transfer-Encoding: chunked\r\n\r\n";
    let mut conn = HttpConn::new_streaming((), nz(1 << 20));
    let p = peer();
    let _ = frame(head, &mut conn, &cfg());
    let resp = drive_verdict(
        head,
        Body::inline(b""),
        &p,
        &mut conn,
        &mut |_: HttpRequest<'_>, _: &mut ()| HttpVerdict::Respond(HttpResponse::new(403)),
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
/// The buffered twin is `dance_while_draining_is_refused_not_invited`, and the reasoning is identical: a drain that
/// accepts an upload it will not read closes under a client mid-body, which the client cannot tell from a
/// truncation.
#[test]
fn a_streamed_open_while_draining_is_refused() {
    let head = b"PUT /up HTTP/1.1\r\nHost: h\r\n\
                     Expect: 100-continue\r\n\
                     Transfer-Encoding: chunked\r\n\r\n";
    let mut conn = HttpConn::new_streaming((), nz(1 << 20));
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
/// `Continue` is the streamed stages' verdict; at `Whole` or `End` there is nothing further to read, so nothing
/// would ever answer and the connection would sit until a timeout. It closes instead, which presents as slot
/// exhaustion rather than a hang under load.
///
/// Guarded twice - the `Stage`-testing arm in `dispatch` and `settle`'s backstop - so this asserts the contract
/// rather than either arm, and it takes removing both to make it fail.
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

/// A streaming connection delivers [`Stage::Whole`] too, and both shapes that reach it are ordinary: a bodyless
/// request, and a `Content-Length` body at or under one window - each takes the buffered path because a whole
/// delivery there is already one pooled read.
///
/// This is the contract a handler is written against. Read as "a streaming connection never delivers `Whole`", such
/// a handler answers [`HttpVerdict::Continue`] for a stage it was told cannot occur and the connection closes with
/// no HTTP response (`continuing_past_a_delivery_that_owes_a_reply_closes`).
#[test]
fn a_streaming_connection_still_delivers_whole() {
    let cap = 4 * STREAM_WINDOW as u64;
    for (what, head, body) in [
        (
            "a bodyless request",
            b"GET /k HTTP/1.1\r\nHost: h\r\n\r\n".to_vec(),
            Vec::new(),
        ),
        (
            "a sub-window body",
            b"PUT /k HTTP/1.1\r\nHost: h\r\nContent-Length: 4\r\n\r\n".to_vec(),
            b"abcd".to_vec(),
        ),
    ] {
        let mut conn = HttpConn::new_streaming((), nz(cap));
        let mut wire = head.clone();
        wire.extend_from_slice(&body);
        assert!(
            matches!(
                frame(&wire, &mut conn, &cfg()),
                Framing::Complete { body_len, .. } if body_len == body.len()
            ),
            "{what}: not a buffered delivery"
        );
        let mut seen = None;
        let _ = drive_verdict(
            &head,
            Body::inline(&body),
            &peer(),
            &mut conn,
            &mut |req: HttpRequest<'_>, _: &mut ()| {
                seen = Some(req.stage);
                HttpVerdict::Respond(HttpResponse::new(200))
            },
        );
        assert!(
            matches!(seen, Some(Stage::Whole)),
            "{what} on a streaming connection presented as {seen:?}"
        );
    }
}

/// While draining, the dance's first message is refused with a close instead of being invited to send a body the
/// drain will not read.
#[test]
fn dance_while_draining_is_refused_not_invited() {
    let head = b"PUT /k HTTP/1.1\r\nHost: h\r\nExpect: 100-continue\r\nContent-Length: 3\r\n\r\n";
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
        &mut |_: HttpRequest<'_>, _: &mut (), _fs: FsSlot<'_>| panic!("the handler must not run: no body was read"),
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
    let mut unreached = |_: HttpRequest<'_>, _: &mut ()| panic!("handler must not run");
    let resp = drive(junk, Body::inline(b""), &p, &mut conn, &mut unreached);
    assert!(is_close(&resp));
    let s = text(&resp);
    assert!(s.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(s.contains("Connection: close\r\n"));
    assert!(s.ends_with("error 400\n"));
}

#[test]
fn farewell_to_head_elides_body() {
    // A HEAD that dies on a policy check still parses as HEAD; the farewell must not carry content the client won't
    // read as a body.
    let mut conn = HttpConn::new(());
    let req = b"HEAD /x HTTP/1.1\r\nHost: h\r\nContent-Length: 99999999999\r\n\r\n";
    frame(req, &mut conn, &cfg());
    assert!(matches!(conn.phase, Phase::Fail { status: 413, .. }));
    let p = peer();
    let mut unreached = |_: HttpRequest<'_>, _: &mut ()| panic!("handler must not run");
    let resp = drive(req, Body::inline(b""), &p, &mut conn, &mut unreached);
    let s = text(&resp);
    assert!(s.starts_with("HTTP/1.1 413"));
    // The HEAD contract: length declared, no body bytes.
    assert!(s.contains("Content-Length: 10\r\n"));
    assert!(s.ends_with("\r\n\r\n"));
}

#[test]
fn farewell_after_dance_ignores_body_bytes() {
    // After the interim the head is consumed; a failing scan delivers body bytes alone. A body crafted to begin
    // "HEAD " must not turn the farewell into a bodyless HEAD response - a declared Content-Length with no content
    // is an incomplete message.
    let head = b"PUT /k HTTP/1.1\r\nHost: h\r\nExpect: 100-continue\r\nTransfer-Encoding: chunked\r\n\r\n";
    let mut conn = HttpConn::new(());
    let p = peer();
    let mut unreached = |_: HttpRequest<'_>, _: &mut ()| panic!("handler must not run");
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
    let resp = drive(body, Body::inline(b""), &p, &mut conn, &mut unreached);
    let s = text(&resp);
    assert!(s.starts_with("HTTP/1.1 400"));
    // The PUT's farewell carries its diagnostic body.
    assert!(s.ends_with("error 400\n"));
}

#[test]
fn head_farewell_elides_body_after_dance() {
    // The converse: a real HEAD whose dance fails must still elide the farewell body, even though the delivered
    // bytes no longer start with the method.
    let head = b"HEAD /k HTTP/1.1\r\nHost: h\r\nExpect: 100-continue\r\nTransfer-Encoding: chunked\r\n\r\n";
    let mut conn = HttpConn::new(());
    let p = peer();
    let mut unreached = |_: HttpRequest<'_>, _: &mut ()| panic!("handler must not run");
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
    let resp = drive(body, Body::inline(b""), &p, &mut conn, &mut unreached);
    let s = text(&resp);
    assert!(s.starts_with("HTTP/1.1 400"));
    assert!(s.contains("Content-Length: 10\r\n"));
    assert!(s.ends_with("\r\n\r\n"));
}

#[test]
fn chunked_roundtrip_through_the_real_glue() {
    let head = b"PUT /k HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n";
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
    let head = b"PUT /t HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n";
    let mut raw = head.to_vec();
    raw.extend_from_slice(b"3\r\nabc\r\n0\r\nx-amz-checksum-crc32: lZe8jQ==\r\n\r\n");
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
    // The default boto3-over-TLS PutObject shape, as captured on the dev box (boto3 1.37.9): Expect + TE chunked,
    // one HTTP chunk wrapping the aws-chunked entity, checksum trailer *inside* the entity, bare HTTP terminator.
    // The HTTP band de-chunks its own layer only - the aws-chunked entity must pass through untouched.
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
    wire.extend_from_slice(b"\r\n0\r\nx-amz-checksum-crc32:lZe8jQ==\r\n\r\n\r\n0\r\n\r\n");
    assert_eq!(wire.len(), 153);
    let mut entity = b"64\r\n".to_vec();
    entity.extend_from_slice(&[b'A'; 100]);
    entity.extend_from_slice(b"\r\n0\r\nx-amz-checksum-crc32:lZe8jQ==\r\n\r\n");

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
    let interim = drive(head, Body::inline(b""), &p, &mut conn, &mut handler);
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
    let resp = drive(head, Body::placed(b"hello".to_vec()), &p, &mut conn, &mut handler);
    assert!(is_keep(&resp));
}

#[test]
fn owned_dance_body_takes_from_the_same_allocation() {
    // The reactor hands the dance's body-only delivery its buffer (at or over the placement threshold); the
    // de-chunked entity must reach the handler's take() from that same allocation - ownership moved, bytes didn't
    // (single chunk), nothing allocated. The A3 contract, pointer-checked, on the golden botocore shape.
    let head = b"PUT /bkt/k HTTP/1.1\r\n\
                     Host: h\r\n\
                     Expect: 100-continue\r\n\
                     Transfer-Encoding: chunked\r\n\r\n";
    let mut wire = b"8e\r\n64\r\n".to_vec();
    wire.extend_from_slice(&[b'A'; 100]);
    wire.extend_from_slice(b"\r\n0\r\nx-amz-checksum-crc32:lZe8jQ==\r\n\r\n\r\n0\r\n\r\n");
    let mut entity = b"64\r\n".to_vec();
    entity.extend_from_slice(&[b'A'; 100]);
    entity.extend_from_slice(b"\r\n0\r\nx-amz-checksum-crc32:lZe8jQ==\r\n\r\n");
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
    // A non-dance chunked message delivered with the wire owned: the in-place path must surface genuine trailers
    // (copied aside, so the entity can own the allocation) and still drop the forbidden set.
    let head = b"PUT /t HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n";
    let mut raw = head.to_vec();
    raw.extend_from_slice(b"3\r\nabc\r\n0\r\nContent-Length: 9\r\nx-amz-checksum-crc32: lZe8jQ==\r\n\r\n");
    let mut conn = HttpConn::new(());
    let verdict = frame(&raw, &mut conn, &cfg());
    let Framing::Complete { header_len, body_len } = verdict else {
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
    let Framing::Complete { header_len, body_len } = verdict else {
        panic!("expected a complete frame, got {verdict:?}");
    };
    assert_eq!(header_len + body_len, raw.len());
    let p = peer();
    drive_verdict(&raw[..header_len], Body::inline(&raw[header_len..]), &p, conn, handler)
}

/// A parked request's completion: the redelivery is an empty frame against the parked phase.
fn complete_parked<U>(
    conn: &mut HttpConn<U>,
    handler: &mut impl FnMut(HttpRequest<'_>, &mut U) -> HttpVerdict,
) -> Response {
    let p = peer();
    drive_verdict(b"", Body::inline(b""), &p, conn, handler)
}

/// A handler for completions that must not re-run the handler (a worker `reply` was left in the cell).
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

/// Park a HEAD; the worker replies with a declared length. The completion must apply the HEAD contract - length on
/// the wire, no body bytes - proving the reply serializes against the parked head.
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

/// A parked CL+TE request (the smuggling differential): the worker's reply must still force the connection closed,
/// exactly as the inline path would.
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

/// HTTP/1.0 negotiated keep-alive survives a park: the worker's reply still echoes `Connection: keep-alive` and
/// stays open.
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

/// A park through the 100-continue dance: the redelivered view carries the stashed head and the dance's body.
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
    let interim = drive_verdict(head, Body::inline(b""), &p, &mut conn, &mut handler);
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
    let resp = drive_verdict(b"", Body::inline(b"abc"), &p, &mut conn, &mut handler);
    assert!(matches!(resp, Response::Defer(_)));
    parked.borrow_mut().take().expect("parked").redrive();
    let done = complete_parked(&mut conn, &mut handler);
    assert!(is_keep(&done));
    assert!(text(&done).starts_with("HTTP/1.1 200 OK\r\n"));
    assert_eq!(conn.state, 2);
}

/// Chunked trailers survive a park: the redelivered view re-presents them from the retained copies.
#[test]
fn park_preserves_chunked_trailers() {
    let head = b"PUT /t HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n";
    let mut raw = head.to_vec();
    raw.extend_from_slice(b"3\r\nabc\r\n0\r\nx-amz-checksum-crc32: lZe8jQ==\r\n\r\n");
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

/// A redriven handler may park again: the second park files a fresh retained request and completes like the first.
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

/// A park taken at [`Stage::End`] is redriven as `End`.
///
/// An `End` park carries no resume state - `settle(conn, d, None)` is what both End arms file - so the stage cannot
/// be read back off the resume phase, and a handler that finalises an upload at `End` would be handed its terminal
/// delivery as if the whole body had arrived in one piece.
#[test]
fn a_park_at_end_is_redriven_as_end() {
    let head = b"PUT /up HTTP/1.1\r\nHost: h\r\n\
                     Transfer-Encoding: chunked\r\n\r\n";
    let mut conn = HttpConn::new_streaming(Vec::<Stage>::new(), nz(1 << 20));
    let p = peer();
    let parked: RefCell<Option<HttpDeferred>> = RefCell::new(None);
    let park_once = std::cell::Cell::new(false);
    let mut handler = |req: HttpRequest<'_>, seen: &mut Vec<Stage>| {
        seen.push(req.stage);
        match req.stage {
            Stage::End if !park_once.replace(true) => {
                let (deferred, permit) = req.defer();
                parked.borrow_mut().replace(deferred);
                HttpVerdict::Defer(permit)
            }
            Stage::End => HttpVerdict::Respond(HttpResponse::new(200)),
            _ => HttpVerdict::Continue,
        }
    };

    // Open, one window, then the terminal chunk - which parks.
    let _ = frame(head, &mut conn, &cfg());
    let _ = drive_verdict(head, Body::inline(b""), &p, &mut conn, &mut handler);
    let win = b"3\r\nabc\r\n";
    let f = frame(win, &mut conn, &cfg());
    let Framing::Complete { header_len, body_len } = f else {
        panic!("window: {f:?}")
    };
    let _ = drive_verdict(
        &win[..header_len],
        Body::inline(&win[header_len..header_len + body_len]),
        &p,
        &mut conn,
        &mut handler,
    );
    // The window consumed its payload but not the CRLF that closes it.
    let last = b"\r\n0\r\n\r\n";
    let f = frame(last, &mut conn, &cfg());
    let Framing::Complete { header_len, .. } = f else {
        panic!("terminal: {f:?}")
    };
    let resp = drive_verdict(&last[..header_len], Body::inline(b""), &p, &mut conn, &mut handler);
    assert!(matches!(resp, Response::Defer(_)), "got {resp:?}");
    assert_eq!(
        conn.state,
        vec![Stage::Open, Stage::Window, Stage::End],
        "the inline walk"
    );

    parked.borrow_mut().take().expect("parked").redrive();
    let done = complete_parked(&mut conn, &mut handler);
    assert!(text(&done).starts_with("HTTP/1.1 200 OK\r\n"), "{done:?}");
    assert_eq!(
        conn.state.last(),
        Some(&Stage::End),
        "the redrive re-presented an End park as {:?}",
        conn.state.last()
    );
}

/// The framer tokenizes a head and every dispatch after it views that head through the recorded index. A streamed
/// upload dispatches its head at the open, at each window, at the end and again when a park is redriven, and none
/// of those may tokenize it again.
///
/// The second half is the fallback. A head that no index describes is tokenized at dispatch and served all the
/// same.
#[test]
fn a_head_is_tokenized_once_however_often_it_is_dispatched() {
    use super::super::head::REPARSED;

    let head = b"PUT /up HTTP/1.1\r\nHost: h\r\nX-Tag: one\r\n\
                     Transfer-Encoding: chunked\r\n\r\n";
    let mut conn = HttpConn::new_streaming(Vec::<Stage>::new(), nz(1 << 20));
    let p = peer();
    let parked: RefCell<Option<HttpDeferred>> = RefCell::new(None);
    let park_once = std::cell::Cell::new(false);
    let mut handler = |req: HttpRequest<'_>, seen: &mut Vec<Stage>| {
        assert_eq!(req.method, "PUT");
        assert_eq!(req.target, "/up");
        let tag = req.headers.iter().find(|h| h.name == "X-Tag");
        assert_eq!(tag.map(|h| h.value), Some(&b"one"[..]));
        seen.push(req.stage);
        match req.stage {
            Stage::End if !park_once.replace(true) => {
                let (deferred, permit) = req.defer();
                parked.borrow_mut().replace(deferred);
                HttpVerdict::Defer(permit)
            }
            Stage::End => HttpVerdict::Respond(HttpResponse::new(200)),
            _ => HttpVerdict::Continue,
        }
    };
    let before = REPARSED.get();

    let _ = frame(head, &mut conn, &cfg());
    let _ = drive_verdict(head, Body::inline(b""), &p, &mut conn, &mut handler);
    let win = b"3\r\nabc\r\n";
    let f = frame(win, &mut conn, &cfg());
    let Framing::Complete { header_len, body_len } = f else {
        panic!("window: {f:?}")
    };
    let _ = drive_verdict(
        &win[..header_len],
        Body::inline(&win[header_len..header_len + body_len]),
        &p,
        &mut conn,
        &mut handler,
    );
    let last = b"\r\n0\r\n\r\n";
    let f = frame(last, &mut conn, &cfg());
    let Framing::Complete { header_len, .. } = f else {
        panic!("terminal: {f:?}")
    };
    let resp = drive_verdict(&last[..header_len], Body::inline(b""), &p, &mut conn, &mut handler);
    assert!(matches!(resp, Response::Defer(_)), "got {resp:?}");
    parked.borrow_mut().take().expect("parked").redrive();
    let done = complete_parked(&mut conn, &mut handler);
    assert!(text(&done).starts_with("HTTP/1.1 200 OK\r\n"), "{done:?}");
    assert_eq!(conn.state, vec![Stage::Open, Stage::Window, Stage::End, Stage::End]);

    // The next request on the connection replaces the index.
    let next = b"GET /after HTTP/1.1\r\nHost: h\r\n\r\n";
    let mut saw = None;
    let resp = roundtrip(next, &mut conn, &mut |req, _| {
        saw = Some(req.target.to_owned());
        HttpResponse::new(204)
    });
    assert!(is_keep(&resp));
    assert_eq!(saw.as_deref(), Some("/after"));
    assert_eq!(
        REPARSED.get(),
        before,
        "a head the framer indexed was tokenized again at dispatch"
    );

    // A connection the framer never ran on has no index to view through.
    let mut bare = HttpConn::new(());
    let mut saw = None;
    let resp = drive(
        next,
        Body::inline(b""),
        &p,
        &mut bare,
        &mut |req: HttpRequest<'_>, _: &mut ()| {
            saw = Some(req.target.to_owned());
            HttpResponse::new(204)
        },
    );
    assert!(is_keep(&resp));
    assert_eq!(saw.as_deref(), Some("/after"));
    assert_eq!(REPARSED.get(), before + 1, "the fallback did not run");
}

/// While a request is parked the framer holds pipelined bytes unframed, so a later request cannot be answered
/// around the parked one.
#[test]
fn parked_phase_holds_framing() {
    let mut conn = HttpConn::new(());
    conn.phase = Phase::Parked {
        resume: None,
        req: Box::new(ParkedRequest {
            head: b"GET / HTTP/1.1\r\nHost: h\r\n\r\n".to_vec(),
            stage: Stage::Whole,
            body: Vec::new(),
            trailers: Vec::new(),
            answer: Arc::new(Mutex::new(None)),
        }),
    };
    let next = b"GET /next HTTP/1.1\r\nHost: h\r\n\r\n";
    assert!(matches!(frame(next, &mut conn, &cfg()), Framing::More));
}
