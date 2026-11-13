use super::*;

/// The streaming cap as `new_streaming` takes it. Every literal here is non-zero by inspection; a zero is the
/// configuration the builders refuse and the type no longer represents.
fn nz(n: u64) -> std::num::NonZeroU64 {
    std::num::NonZeroU64::new(n).expect("a non-zero literal cap")
}

fn conn() -> HttpConn<()> {
    HttpConn::new(())
}

fn cfg() -> HttpConfig {
    HttpConfig::default()
}

/// Every degrade arm must deliver a message the reactor will actually hand back, or the 500 farewell it just armed
/// never goes out. `frame_step` closes a zero-length `Complete` as `Malformed` - a raw close with no HTTP
/// response - so an arm that answers `Complete { 0, 0 }` has silently swapped the promised farewell for a slam.
#[test]
fn a_degrade_arm_delivers_something_to_farewell_with() {
    let cfg = cfg();
    let buf = b"some bytes already in the buffer";
    // Each of the four helpers reached with the wrong phase installed.
    let mut c = conn();
    c.phase = Phase::Head;
    assert_ne!(
        known_step(buf, &mut c),
        Framing::Complete {
            header_len: 0,
            body_len: 0
        },
        "known_step's degrade arm answers an undeliverable message"
    );
    let mut c = conn();
    c.phase = Phase::Head;
    assert_ne!(
        stream_step(buf, &mut c),
        Framing::Complete {
            header_len: 0,
            body_len: 0
        }
    );
    let mut c = conn();
    c.phase = Phase::Head;
    assert_ne!(
        scan_step(buf, &mut c, &cfg),
        Framing::Complete {
            header_len: 0,
            body_len: 0
        }
    );
}

#[test]
fn validate_rejects_zero_caps() {
    assert!(HttpConfig::default().validate().is_ok());
    assert!(
        HttpConfig {
            max_head: 0,
            max_body: 1024,
        }
        .validate()
        .is_err()
    );
    assert!(
        HttpConfig {
            max_head: 1024,
            max_body: 0,
        }
        .validate()
        .is_err()
    );
}

/// While the framer is still asking for bytes, everything buffered is inside the bound it publishes. The chunk caps are
/// measured on the scanned extent, so a peer pausing mid-trailer-line parks a line's worth of bytes the caps never see.
/// The fixture first asserts it reaches past `max_head + max_body + CHUNK_WIRE_OVERHEAD`, or it would prove nothing.
#[test]
fn a_paused_trailer_line_is_inside_the_published_bound() {
    let cfg = HttpConfig {
        max_head: 16 * 1024,
        max_body: 128 * 1024,
    };
    // A head padded to exactly `max_head`.
    let mut head = b"PUT /u HTTP/1.1\r\nHost: h\r\n\
                         Transfer-Encoding: chunked\r\nX-Pad: "
        .to_vec();
    let tail = b"\r\n\r\n";
    head.resize(cfg.max_head - tail.len(), b'a');
    head.extend_from_slice(tail);
    assert_eq!(head.len(), cfg.max_head);

    // 48-byte payloads, six bytes of framing each: the wire extent lands just under `max_body +
    // CHUNK_WIRE_OVERHEAD` with the decoded size just under `max_body`.
    let mut wire = head.clone();
    for _ in 0..2730 {
        wire.extend_from_slice(b"30\r\n");
        wire.extend_from_slice(&[b'x'; 48]);
        wire.extend_from_slice(b"\r\n");
    }
    wire.extend_from_slice(b"0\r\n");
    // The most a trailer line can hold unscanned: one byte short of the length at which `find_crlf` answers
    // `TooLong`.
    wire.extend_from_slice(&vec![b'v'; TRAILER_LINE_MAX + 1]);

    let mut c = conn();
    assert_eq!(
        frame(&wire, &mut c, &cfg),
        Framing::MoreInMessage,
        "the codec is still asking for bytes at {} buffered",
        wire.len()
    );
    assert!(
        wire.len() > cfg.max_head + cfg.max_body + CHUNK_WIRE_OVERHEAD,
        "fixture at {} does not reach past the three-term bound, so it \
             cannot show the in-flight line is budgeted",
        wire.len()
    );
    assert!(
        wire.len() <= cfg.min_request_bytes(),
        "buffered {} past the published minimum {}: the reactor closes \
             TooLarge here, with no HTTP response",
        wire.len(),
        cfg.min_request_bytes()
    );
}

/// A streamed window is a message this codec declares and `max_body` does not bound, so the published minimum
/// admits one whatever `max_body` is set to.
#[test]
fn the_published_bound_admits_one_streamed_window() {
    let cfg = HttpConfig {
        max_head: 1024,
        max_body: 4 * 1024,
    };
    let head = b"PUT /u HTTP/1.1\r\nHost: h\r\n\
                     Transfer-Encoding: chunked\r\n\r\n";
    let mut c = HttpConn::new_streaming((), nz(1 << 30));
    assert!(matches!(frame(head, &mut c, &cfg), Framing::Complete { .. }));
    // The glue accepts the open and advances, as the protocol does.
    c.phase = Phase::StreamBody {
        head: head.to_vec(),
        chunk_left: 0,
        after_payload: false,
        decoded: 0,
    };

    let mut wire = format!("{:x}\r\n", STREAM_WINDOW).into_bytes();
    wire.extend_from_slice(&vec![b'x'; STREAM_WINDOW]);
    wire.extend_from_slice(b"\r\n");
    let Framing::Complete { header_len, body_len } = frame(&wire, &mut c, &cfg) else {
        panic!("a streamed window frames as one message");
    };
    assert_eq!(body_len, STREAM_WINDOW);
    assert!(
        header_len + body_len <= cfg.min_request_bytes(),
        "a window this codec declares ({} + {}) is past the minimum it \
             publishes ({}): `frame_step` closes TooLarge on it",
        header_len,
        body_len,
        cfg.min_request_bytes()
    );
}

#[test]
fn default_caps_compose_with_the_reactor() {
    // The codec's default min request size equals the reactor's default message cap, so the default codec on the
    // default server has no dead band. Pinned here because raising max_body without raising max_request_bytes in
    // step is what opens one.
    use crate::net::server::ServerConfig;
    assert_eq!(
        HttpConfig::default().min_request_bytes(),
        ServerConfig::default().max_request_bytes
    );
}

#[test]
fn single_message_with_body() {
    let mut c = conn();
    let req = b"PUT /b/k HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\nhello";
    let head_len = req.len() - 5;
    // Drip-feed the head: every prefix is More.
    for cut in 0..head_len {
        assert_eq!(frame(&req[..cut], &mut c, &cfg()), Framing::More);
    }
    assert_eq!(
        frame(&req[..head_len], &mut c, &cfg()),
        Framing::Complete {
            header_len: head_len,
            body_len: 5
        }
    );
    assert!(matches!(c.phase, Phase::Head));
}

#[test]
fn bodyless_get() {
    let mut c = conn();
    let req = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n";
    assert_eq!(
        frame(req, &mut c, &cfg()),
        Framing::Complete {
            header_len: req.len(),
            body_len: 0
        }
    );
}

#[test]
fn expect_dance() {
    let mut c = conn();
    let head = b"PUT /k HTTP/1.1\r\nHost: h\r\nExpect: 100-continue\r\nContent-Length: 3\r\n\r\n";
    // Message 1: the head alone, stashed.
    assert_eq!(
        frame(head, &mut c, &cfg()),
        Framing::Complete {
            header_len: head.len(),
            body_len: 0
        }
    );
    let Phase::ExpectHead {
        head: stash,
        body: BodyKind::Known(body_len),
    } = &c.phase
    else {
        panic!("expected ExpectHead, got {:?}", c.phase);
    };
    assert_eq!(*body_len, 3);
    assert_eq!(stash.as_slice(), head.as_slice());
    // Glue advances the phase after queuing the interim response.
    let Phase::ExpectHead { head: stash, body } = std::mem::replace(&mut c.phase, Phase::Head) else {
        unreachable!()
    };
    c.phase = Phase::ExpectBody { head: stash, body };
    // Message 2: the body alone, empty header.
    assert_eq!(
        frame(b"abc", &mut c, &cfg()),
        Framing::Complete {
            header_len: 0,
            body_len: 3
        }
    );
}

#[test]
fn expect_with_empty_body_is_normal() {
    let mut c = conn();
    let req = b"PUT /k HTTP/1.1\r\nHost: h\r\nExpect: 100-continue\r\nContent-Length: 0\r\n\r\n";
    assert_eq!(
        frame(req, &mut c, &cfg()),
        Framing::Complete {
            header_len: req.len(),
            body_len: 0
        }
    );
    assert!(matches!(c.phase, Phase::Head));
}

#[test]
fn expect_on_http10_is_ignored() {
    // RFC 9110 sec. 10.1.1: no interim responses to a 1.0 client - the request frames as one ordinary message, no
    // dance.
    let mut c = conn();
    let req = b"PUT /k HTTP/1.0\r\nExpect: 100-continue\r\nContent-Length: 3\r\n\r\nabc";
    let head_len = req.len() - 3;
    assert_eq!(
        frame(req, &mut c, &cfg()),
        Framing::Complete {
            header_len: head_len,
            body_len: 3
        }
    );
    assert!(matches!(c.phase, Phase::Head));
}

#[test]
fn missing_host_fails_400() {
    let mut c = conn();
    let req = b"GET / HTTP/1.1\r\n\r\n";
    assert_eq!(
        frame(req, &mut c, &cfg()),
        Framing::Complete {
            header_len: req.len(),
            body_len: 0
        }
    );
    assert!(matches!(c.phase, Phase::Fail { status: 400, .. }));
}

#[test]
fn malformed_head_fails_400() {
    let mut c = conn();
    let junk = b"NOT HTTP\r\n\r\n";
    assert_eq!(
        frame(junk, &mut c, &cfg()),
        Framing::Complete {
            header_len: junk.len(),
            body_len: 0
        }
    );
    assert!(matches!(c.phase, Phase::Fail { status: 400, .. }));
}

#[test]
fn oversized_head_fails_431() {
    let mut c = conn();
    let small = HttpConfig {
        max_head: 64,
        max_body: 1024,
    };
    // An incomplete head that already exceeds the cap.
    let mut buf = b"GET / HTTP/1.1\r\nX-Pad: ".to_vec();
    buf.extend(std::iter::repeat_n(b'a', 100));
    assert_eq!(
        frame(&buf, &mut c, &small),
        Framing::Complete {
            header_len: buf.len(),
            body_len: 0
        }
    );
    assert!(matches!(c.phase, Phase::Fail { status: 431, .. }));

    // A head that completes in one arrival but lands over the cap.
    let mut c = conn();
    let mut req = b"GET / HTTP/1.1\r\nHost: h\r\nX-Pad: ".to_vec();
    req.extend(std::iter::repeat_n(b'a', 60));
    req.extend_from_slice(b"\r\n\r\n");
    assert_eq!(
        frame(&req, &mut c, &small),
        Framing::Complete {
            header_len: req.len(),
            body_len: 0
        }
    );
    assert!(matches!(c.phase, Phase::Fail { status: 431, .. }));
}

#[test]
fn over_cap_head_keeps_the_promised_431() {
    // A host-less head is a 400, but this one only completes past the cap - no verdict was reachable within it, so
    // the cap's promised 431 wins over the screen that fired on past-the-cap bytes.
    let small = HttpConfig {
        max_head: 64,
        max_body: 1024,
    };
    let mut c = conn();
    let mut req = b"GET / HTTP/1.1\r\nX-Pad: ".to_vec();
    req.extend(std::iter::repeat_n(b'a', 60));
    req.extend_from_slice(b"\r\n\r\n");
    frame(&req, &mut c, &small);
    assert!(matches!(c.phase, Phase::Fail { status: 431, .. }));

    // The same screen within the cap keeps its specific status.
    let mut c = conn();
    frame(b"GET / HTTP/1.1\r\nX-P: a\r\n\r\n", &mut c, &small);
    assert!(matches!(c.phase, Phase::Fail { status: 400, .. }));
}

#[test]
fn oversized_body_fails_413() {
    let mut c = conn();
    let small = HttpConfig {
        max_head: 1024,
        max_body: 10,
    };
    let req = b"PUT /k HTTP/1.1\r\nHost: h\r\nContent-Length: 11\r\n\r\n";
    assert_eq!(
        frame(req, &mut c, &small),
        Framing::Complete {
            header_len: req.len(),
            body_len: 0
        }
    );
    assert!(matches!(c.phase, Phase::Fail { status: 413, .. }));
}

#[test]
fn chunked_single_arrival() {
    // Head + whole chunked body in one buffer: the framer must scan and complete in the same call (`More` would
    // stall - no bytes follow).
    let mut c = conn();
    let head = b"PUT /k HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n";
    let mut raw = head.to_vec();
    raw.extend_from_slice(b"5\r\nhello\r\n0\r\n\r\n");
    assert_eq!(
        frame(&raw, &mut c, &cfg()),
        Framing::Complete {
            header_len: head.len(),
            body_len: raw.len() - head.len(),
        }
    );
    assert!(matches!(c.phase, Phase::ChunkedDone { stash: None }));
}

#[test]
fn chunked_drip_fed() {
    // Every prefix asks for more, and the scan resumes rather than restarting.
    let mut c = conn();
    let head = b"PUT /k HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n";
    let mut raw = head.to_vec();
    raw.extend_from_slice(b"3\r\nfoo\r\n4\r\nbars\r\n0\r\n\r\n");
    for cut in 0..raw.len() {
        // Inside the head the connection waits for a request, and from the terminator on a body is arriving and the
        // scan says so.
        let want = if cut < head.len() {
            Framing::More
        } else {
            Framing::MoreInMessage
        };
        assert_eq!(frame(&raw[..cut], &mut c, &cfg()), want, "cut {cut}");
    }
    assert_eq!(
        frame(&raw, &mut c, &cfg()),
        Framing::Complete {
            header_len: head.len(),
            body_len: raw.len() - head.len(),
        }
    );
}

#[test]
fn chunked_expect_dance() {
    // The real boto3 shape: Expect and TE chunked together. Message 1 is the head alone; after the glue advances
    // the phase, the chunk scan runs against body-only bytes with the head stashed.
    let mut c = conn();
    let head = b"PUT /k HTTP/1.1\r\nHost: h\r\nExpect: 100-continue\r\nTransfer-Encoding: chunked\r\n\r\n";
    assert_eq!(
        frame(head, &mut c, &cfg()),
        Framing::Complete {
            header_len: head.len(),
            body_len: 0
        }
    );
    let Phase::ExpectHead {
        head: stash,
        body: BodyKind::Chunked,
    } = std::mem::replace(&mut c.phase, Phase::Head)
    else {
        panic!("expected chunked ExpectHead");
    };
    c.phase = Phase::ExpectBody {
        head: stash,
        body: BodyKind::Chunked,
    };
    let wire = b"5\r\nhello\r\n0\r\n\r\n";
    assert_eq!(
        frame(&wire[..4], &mut c, &cfg()),
        Framing::MoreInMessage,
        "partial body resumes the dance into a scan - and the dance \
             consumed the head, so this scan can run on an empty buffer"
    );
    assert_eq!(
        frame(wire, &mut c, &cfg()),
        Framing::Complete {
            header_len: 0,
            body_len: wire.len()
        }
    );
    let Phase::ChunkedDone { stash: Some(stash) } = &c.phase else {
        panic!("expected stashed ChunkedDone, got {:?}", c.phase);
    };
    assert_eq!(stash.as_slice(), head.as_slice());
}

#[test]
fn chunked_decoded_over_cap_fails_413() {
    // The decoded cap trips mid-stream, before the terminal chunk.
    let mut c = conn();
    let small = HttpConfig {
        max_head: 1024,
        max_body: 10,
    };
    let head = b"PUT /k HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n";
    let mut raw = head.to_vec();
    raw.extend_from_slice(b"b\r\n0123456789A");
    assert_eq!(
        frame(&raw, &mut c, &small),
        Framing::Complete {
            header_len: raw.len(),
            body_len: 0
        }
    );
    assert!(matches!(c.phase, Phase::Fail { status: 413, .. }));
}

/// The streaming cap bounds a body under one window too. `max_body_bytes` is what the endpoint declares it accepts, and
/// gating the check on `body_len > STREAM_WINDOW` would leave a smaller body bounded only by `max_body`, so an endpoint
/// that declared 1 KiB takes 100 KiB.
#[test]
fn a_known_body_under_one_window_still_meets_the_stream_cap() {
    let cfg = HttpConfig {
        max_head: 1024,
        max_body: 8 * 1024 * 1024,
    };
    let over = 100 * 1024;
    assert!(over < STREAM_WINDOW, "the point is a sub-window body");

    let mut c = HttpConn::new_streaming((), nz(1024));
    let head = format!("PUT /k HTTP/1.1\r\nHost: h\r\nContent-Length: {over}\r\n\r\n");
    assert_eq!(
        frame(head.as_bytes(), &mut c, &cfg),
        Framing::Complete {
            header_len: head.len(),
            body_len: 0
        }
    );
    assert!(
        matches!(c.phase, Phase::Fail { status: 413, .. }),
        "a {over}-byte body was admitted against a 1 KiB cap: {:?}",
        c.phase
    );

    // And the legitimate case still frames: at the cap, not over it.
    let mut c = HttpConn::new_streaming((), nz(1024));
    let head = b"PUT /k HTTP/1.1\r\nHost: h\r\nContent-Length: 1024\r\n\r\n";
    let _ = frame(head, &mut c, &cfg);
    assert!(
        !matches!(c.phase, Phase::Fail { .. }),
        "a body exactly at the cap is accepted: {:?}",
        c.phase
    );
}

/// The decoded cap holds on a *completing* arrival too. A body whose head, chunks and terminator land in one read never
/// passes the mid-stream branch, and without the check on this arm a single-segment request bypasses `max_body`.
#[test]
fn chunked_decoded_over_cap_fails_413_on_completion() {
    let mut c = conn();
    let small = HttpConfig {
        max_head: 1024,
        max_body: 10,
    };
    let head = b"PUT /k HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n";
    let mut raw = head.to_vec();
    // 11 decoded bytes, terminator included, all in one arrival.
    raw.extend_from_slice(b"b\r\n0123456789A\r\n0\r\n\r\n");
    assert_eq!(
        frame(&raw, &mut c, &small),
        Framing::Complete {
            header_len: raw.len(),
            body_len: 0
        }
    );
    assert!(
        matches!(c.phase, Phase::Fail { status: 413, .. }),
        "a body that completes in one read still has to meet the cap: \
             {:?}",
        c.phase
    );
}

#[test]
fn chunked_wire_overhead_fails_400() {
    // Decoded size stays in bounds but one-byte chunks inflate the wire extent past max_body + CHUNK_WIRE_OVERHEAD:
    // framing abuse, 400.
    let mut c = conn();
    let small = HttpConfig {
        max_head: 1024,
        max_body: 4096,
    };
    let head = b"PUT /k HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n";
    let mut raw = head.to_vec();
    // 6 wire bytes per decoded byte; stop short of the decoded cap.
    for _ in 0..4000 {
        raw.extend_from_slice(b"1\r\nX\r\n");
    }
    frame(&raw, &mut c, &small);
    assert!(matches!(c.phase, Phase::Fail { status: 400, .. }));
}

/// A body that is both over the cap **and** malformed answers the same status whichever way the peer's writes fell. 413
/// and 400 say different things to a client, so TCP segmentation must not choose between them. The control is the
/// second half, where a malformed body within the cap keeps its framing error.
#[test]
fn a_chunked_verdict_does_not_depend_on_segmentation() {
    let small = HttpConfig {
        max_head: 1024,
        max_body: 64,
    };
    let head = b"PUT /k HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n";
    // 16 bytes per chunk, well past max_body, then a size line no radix accepts - over-cap and malformed in one
    // body.
    let mut raw = head.to_vec();
    let boundary = raw.len() + 10 * b"10\r\n0123456789abcdef\r\n".len();
    for _ in 0..10 {
        raw.extend_from_slice(b"10\r\n0123456789abcdef\r\n");
    }
    raw.extend_from_slice(b"zz\r\n");

    // Whole body in one arrival: the scan meets the malformation.
    let mut whole = conn();
    frame(&raw, &mut whole, &small);
    let Phase::Fail { status: at_once, .. } = whole.phase else {
        panic!("expected a failure for the whole body");
    };

    // Split on a chunk boundary: the scan reports progress first.
    let mut split = conn();
    frame(&raw[..boundary], &mut split, &small);
    frame(&raw, &mut split, &small);
    let Phase::Fail { status: segmented, .. } = split.phase else {
        panic!("expected a failure for the segmented body");
    };

    assert_eq!(
        at_once, segmented,
        "the same bytes answered {at_once} whole and {segmented} split - \
             segmentation decided the status"
    );
    assert_eq!(at_once, 413, "over the cap is the stronger verdict");

    // The control: malformed but within the cap keeps the framing error.
    let mut ok_size = conn();
    let mut short = head.to_vec();
    short.extend_from_slice(b"4\r\nabcd\r\n");
    short.extend_from_slice(b"zz\r\n");
    frame(&short, &mut ok_size, &small);
    assert!(
        matches!(ok_size.phase, Phase::Fail { status: 400, .. }),
        "a malformed body inside the cap is still 400"
    );
}

#[test]
fn chunked_wire_overhead_fails_400_on_completion() {
    // The same wire shape with its terminal chunk in the same call: the scan completes rather than reporting
    // progress, and the wire cap must fire on the completion branch too - the verdict cannot depend on how the
    // bytes were segmented.
    let mut c = conn();
    let small = HttpConfig {
        max_head: 1024,
        max_body: 4096,
    };
    let head = b"PUT /k HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n";
    let mut raw = head.to_vec();
    for _ in 0..4000 {
        raw.extend_from_slice(b"1\r\nX\r\n");
    }
    raw.extend_from_slice(b"0\r\n\r\n");
    frame(&raw, &mut c, &small);
    assert!(matches!(c.phase, Phase::Fail { status: 400, .. }));
}

#[test]
fn head_flag_survives_leading_empty_lines() {
    // httparse skips empty lines before the request line (RFC 9112 sec. 2.2), so `\r\nHEAD ...` parses as a HEAD;
    // the failure flag must agree, or this farewell carries a body the client reads as the next response's head.
    let mut c = conn();
    let req = b"\r\nHEAD /x HTTP/1.1\r\nHost: h\r\nContent-Length: 99999999999\r\n\r\n";
    frame(req, &mut c, &cfg());
    assert!(matches!(
        c.phase,
        Phase::Fail {
            status: 413,
            head_only: true
        }
    ));

    // Bare LF, dying on a screen that parses no facts (missing Host): the flag is judged from the method bytes
    // alone.
    let mut c = conn();
    frame(b"\nHEAD / HTTP/1.1\r\n\r\n", &mut c, &cfg());
    assert!(matches!(
        c.phase,
        Phase::Fail {
            status: 400,
            head_only: true
        }
    ));

    // A non-HEAD behind the same empty line keeps its farewell body.
    let mut c = conn();
    frame(b"\r\nGET / HTTP/1.1\r\n\r\n", &mut c, &cfg());
    assert!(matches!(
        c.phase,
        Phase::Fail {
            status: 400,
            head_only: false
        }
    ));
}

#[test]
fn chunked_malformed_fails_400() {
    let mut c = conn();
    let head = b"PUT /k HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n";
    let mut raw = head.to_vec();
    raw.extend_from_slice(b"FFFFFFFFFFFFFFFFF\r\n");
    frame(&raw, &mut c, &cfg());
    assert!(matches!(c.phase, Phase::Fail { status: 400, .. }));
}

#[test]
fn te_with_unimplemented_coding_fails_501() {
    let mut c = conn();
    let req = b"PUT /k HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: gzip, chunked\r\n\r\n";
    frame(req, &mut c, &cfg());
    assert!(matches!(c.phase, Phase::Fail { status: 501, .. }));
}

#[test]
fn pipelined_next_head_frames_cleanly() {
    let mut c = conn();
    // After a complete message is consumed, the framer starts over on the remaining bytes - simulate the reactor's
    // consume-and-recheck.
    let two = b"GET /a HTTP/1.1\r\nHost: h\r\n\r\nGET /b HTTP/1.1\r\nHost: h\r\n\r\n";
    let first = b"GET /a HTTP/1.1\r\nHost: h\r\n\r\n".len();
    assert_eq!(
        frame(two, &mut c, &cfg()),
        Framing::Complete {
            header_len: first,
            body_len: 0
        }
    );
    assert_eq!(
        frame(&two[first..], &mut c, &cfg()),
        Framing::Complete {
            header_len: two.len() - first,
            body_len: 0
        }
    );
}

#[test]
fn empty_buffer_wants_more() {
    let mut c = conn();
    assert_eq!(frame(b"", &mut c, &cfg()), Framing::More);
}

/// A `Content-Length` body above one window opens alone, then streams as full windows counted down against the length.
#[test]
fn a_known_length_body_streams_above_one_window() {
    let mut c = HttpConn::new_streaming((), nz(1 << 30));
    let len = STREAM_WINDOW * 2 + 5;
    let head = format!("PUT /o HTTP/1.1\r\nHost: t\r\nContent-Length: {len}\r\n\r\n");
    assert_eq!(
        frame(head.as_bytes(), &mut c, &cfg()),
        Framing::Complete {
            header_len: head.len(),
            body_len: 0
        },
        "the head goes out alone, exactly as a chunked open does"
    );
    assert!(matches!(
        c.phase,
        Phase::StreamOpen {
            expect: false,
            body: StreamedBody::Known(n),
            ..
        } if n == len as u64
    ));

    // The glue accepts and advances. Windows count the length down, each a full window whatever is buffered.
    c.phase = Phase::StreamKnown {
        head: head.as_bytes().to_vec(),
        remaining: len as u64,
    };
    assert_eq!(
        frame(&[], &mut c, &cfg()),
        Framing::MoreInMessage,
        "an empty buffer between windows is a message in progress, not \
             an idle park - `More` here puts the read on `idle_timeout` and \
             arms no receipt budget"
    );
    let burst = vec![0u8; STREAM_WINDOW + 9];
    assert_eq!(
        frame(&burst, &mut c, &cfg()),
        Framing::Complete {
            header_len: 0,
            body_len: STREAM_WINDOW
        },
        "a full window caps the delivery"
    );
    assert_eq!(
        frame(&burst[..7], &mut c, &cfg()),
        Framing::Complete {
            header_len: 0,
            body_len: STREAM_WINDOW
        },
        "a short buffer still declares a full window; the exact read \
             completes it from the pool"
    );
    c.phase = Phase::StreamKnown {
        head: head.as_bytes().to_vec(),
        remaining: 5,
    };
    assert_eq!(
        frame(&burst, &mut c, &cfg()),
        Framing::Complete {
            header_len: 0,
            body_len: 5
        },
        "the tail stops at the length; what follows is the next request"
    );

    // The glue retires the phase on the exhausting delivery, so a zero remaining here is a codec bug and gets the
    // farewell rather than a delivery that could eat pipelined bytes.
    c.phase = Phase::StreamKnown {
        head: head.as_bytes().to_vec(),
        remaining: 0,
    };
    frame(b"GET /next HTTP/1.1\r\n", &mut c, &cfg());
    assert!(matches!(c.phase, Phase::Fail { status: 500, .. }));
}

/// The boundary: at one window a whole delivery is one pool-buffered read already, so nothing streams; one byte
/// past it does.
#[test]
fn the_known_stream_threshold_is_one_window() {
    let mut c = HttpConn::new_streaming((), nz(1 << 30));
    let head = format!(
        "PUT /o HTTP/1.1\r\nHost: t\r\nContent-Length: {}\r\n\r\n",
        STREAM_WINDOW
    );
    assert_eq!(
        frame(head.as_bytes(), &mut c, &cfg()),
        Framing::Complete {
            header_len: head.len(),
            body_len: STREAM_WINDOW
        },
        "at the window the body is delivered whole"
    );

    // On a plain connection nothing streams at any size the cap admits, so the streaming branch cannot leak into
    // buffered servers.
    let mut plain = conn();
    let head = format!(
        "PUT /o HTTP/1.1\r\nHost: t\r\nContent-Length: {}\r\n\r\n",
        STREAM_WINDOW + 1
    );
    assert!(matches!(
        frame(head.as_bytes(), &mut plain, &cfg()),
        Framing::Complete { body_len, .. } if body_len == STREAM_WINDOW + 1
    ));
}

/// A declared length past the stream cap is refused at the head, and `max_body` no longer bounds what streams.
#[test]
fn a_known_stream_is_bounded_by_the_stream_cap() {
    let mut c = HttpConn::new_streaming((), nz(1 << 20));
    let head = format!(
        "PUT /o HTTP/1.1\r\nHost: t\r\nContent-Length: {}\r\n\r\n",
        (1 << 20) + 1
    );
    frame(head.as_bytes(), &mut c, &cfg());
    assert!(matches!(c.phase, Phase::Fail { status: 413, .. }));

    // Between max_body and the cap: streams rather than 413s.
    let mut c = HttpConn::new_streaming((), nz(1 << 30));
    let over_max_body = cfg().max_body + 1;
    let head = format!(
        "PUT /o HTTP/1.1\r\nHost: t\r\nContent-Length: \
             {over_max_body}\r\n\r\n"
    );
    frame(head.as_bytes(), &mut c, &cfg());
    assert!(
        matches!(c.phase, Phase::StreamOpen { .. }),
        "a streamed body is not the buffer max_body protects"
    );
}

/// `Expect: 100-continue` on a streaming known-length body takes the open — where the interim is withheld for the
/// consumer's verdict — never the buffered dance.
#[test]
fn an_expecting_known_stream_opens_instead_of_dancing() {
    let mut c = HttpConn::new_streaming((), nz(1 << 30));
    let head = format!(
        "PUT /o HTTP/1.1\r\nHost: t\r\nExpect: 100-continue\r\n\
             Content-Length: {}\r\n\r\n",
        STREAM_WINDOW + 1
    );
    assert_eq!(
        frame(head.as_bytes(), &mut c, &cfg()),
        Framing::Complete {
            header_len: head.len(),
            body_len: 0
        }
    );
    assert!(matches!(
        c.phase,
        Phase::StreamOpen {
            expect: true,
            body: StreamedBody::Known(_),
            ..
        }
    ));
}

/// The shape boto3 sends over TLS, walked a chunk at a time. The head goes out alone, each HTTP chunk is declared as
/// its own message, and the terminal chunk closes it. No verdict names more than one chunk, which keeps the reactor's
/// buffer off the body's size.
#[test]
fn a_streamed_body_is_declared_one_chunk_at_a_time() {
    let mut c = HttpConn::new_streaming((), nz(1 << 20));
    let head = b"PUT /o HTTP/1.1\r\nHost: t\r\n\
                     Transfer-Encoding: chunked\r\n\r\n";
    // The head, alone.
    assert_eq!(
        frame(head, &mut c, &cfg()),
        Framing::Complete {
            header_len: head.len(),
            body_len: 0
        }
    );
    assert!(matches!(c.phase, Phase::StreamOpen { expect: false, .. }));

    // The glue accepts and advances; from here the buffer holds body.
    c.phase = Phase::StreamBody {
        head: head.to_vec(),
        chunk_left: 0,
        after_payload: false,
        decoded: 0,
    };
    let body = b"4\r\nAAAA\r\n3\r\nBBB\r\n0\r\n\r\n";
    assert_eq!(
        frame(body, &mut c, &cfg()),
        Framing::Complete {
            header_len: 3,
            body_len: 4
        },
        "the first chunk's size line, then its payload"
    );

    // Consume it as the reactor would, and advance as the glue does.
    let rest = &body[3 + 4..];
    c.phase = Phase::StreamBody {
        head: head.to_vec(),
        chunk_left: 0,
        after_payload: true,
        decoded: 4,
    };
    assert_eq!(
        frame(rest, &mut c, &cfg()),
        Framing::Complete {
            header_len: 5,
            body_len: 3
        },
        "the CRLF closing the last payload rides in this chunk's framing"
    );

    let rest = &rest[5 + 3..];
    c.phase = Phase::StreamBody {
        head: head.to_vec(),
        chunk_left: 0,
        after_payload: true,
        decoded: 7,
    };
    assert_eq!(
        frame(rest, &mut c, &cfg()),
        Framing::Complete {
            header_len: rest.len(),
            body_len: 0
        },
        "the terminal chunk, header only"
    );
    assert!(matches!(c.phase, Phase::StreamDone { .. }));
}

/// `frame` runs again for the same chunk while its payload is still arriving, so it must answer the same way every
/// time. Advancing `after_payload` inside it would eat a second CRLF on the re-run and mis-frame the body.
#[test]
fn a_streamed_chunk_is_declared_the_same_way_on_every_re_entry() {
    let body = b"20000\r\n";
    let mut c = HttpConn::new_streaming((), nz(1 << 20));
    c.phase = Phase::StreamBody {
        head: b"PUT / HTTP/1.1\r\nHost: t\r\n\r\n".to_vec(),
        chunk_left: 0,
        after_payload: false,
        decoded: 0,
    };
    let first = frame(body, &mut c, &cfg());
    assert_eq!(
        first,
        Framing::Complete {
            header_len: 7,
            body_len: 0x20000
        }
    );
    // The payload has not arrived; the pump reads and re-frames.
    for _ in 0..3 {
        assert_eq!(frame(body, &mut c, &cfg()), first, "re-entrant");
    }
    // And no per-chunk state moved while it did. Counting the chunk on every re-entry would walk `decoded` toward
    // the cap on a body that has not delivered a byte, refusing it partway through.
    let Phase::StreamBody {
        decoded, after_payload, ..
    } = &c.phase
    else {
        panic!("still streaming");
    };
    assert_eq!(*decoded, 0, "the chunk is counted once, on delivery");
    assert!(!*after_payload, "and the cursor has not moved either");
}

/// The decoded cap is checked as each chunk is declared, because a streamed body is never buffered whole - there is
/// no "after" to check at. The bound is the builder's, not `max_body`.
#[test]
fn a_streamed_body_is_capped_as_it_is_declared() {
    let mut c = HttpConn::new_streaming((), nz(6));
    c.phase = Phase::StreamBody {
        head: b"PUT / HTTP/1.1\r\nHost: t\r\n\r\n".to_vec(),
        chunk_left: 0,
        after_payload: false,
        decoded: 4,
    };
    // 4 already declared, 3 more would be 7 against a cap of 6.
    let v = frame(b"3\r\nBBB\r\n", &mut c, &cfg());
    assert!(
        matches!(c.phase, Phase::Fail { status: 413, .. }),
        "over the cap mid-stream, got {v:?}"
    );
}
