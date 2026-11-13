use super::*;

/// Build a *server-style* (unmasked) frame for the parser to eat.
fn server_frame(fin: bool, opcode: u8, payload_len: usize) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(if fin { 0x80 } else { 0 } | opcode);
    match payload_len {
        n if n < 126 => out.push(n as u8),
        n if n <= 0xFFFF => {
            out.push(126);
            out.extend_from_slice(&(n as u16).to_be_bytes());
        }
        n => {
            out.push(127);
            out.extend_from_slice(&(n as u64).to_be_bytes());
        }
    }
    out
}

/// RFC 6455 §1.3's worked handshake pair.
#[test]
fn accept_matches_the_rfc_vector() {
    assert_eq!(accept_for("dGhlIHNhbXBsZSBub25jZQ=="), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
}

/// The client handshake check: a well-formed `101` with the right accept passes, and each way it can be wrong is
/// refused as itself.
#[test]
fn validate_101_accepts_a_good_upgrade_and_names_each_failure() {
    let key = "the-key";
    let good = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\
             Connection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n",
        accept_for(key)
    );
    assert!(validate_101(good.as_bytes(), key).is_ok());

    let not_101 = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
    assert!(matches!(
        validate_101(not_101, key),
        Err(HandshakeError::NotSwitching { status: 404, .. })
    ));

    let wrong_accept = "HTTP/1.1 101 Switching Protocols\r\n\
             Upgrade: websocket\r\nConnection: Upgrade\r\n\
             Sec-WebSocket-Accept: bm90LXRoZS1kaWdlc3Q=\r\n\r\n";
    assert!(matches!(
        validate_101(wrong_accept.as_bytes(), key),
        Err(HandshakeError::BadAccept)
    ));

    let no_upgrade = format!(
        "HTTP/1.1 101 Switching Protocols\r\n\
             Sec-WebSocket-Accept: {}\r\n\r\n",
        accept_for(key)
    );
    assert!(matches!(
        validate_101(no_upgrade.as_bytes(), key),
        Err(HandshakeError::NotUpgraded)
    ));
}

/// Every prefix of every length form answers the exact missing count, and the full header parses back the declared
/// length. The lengths cross both extended-form boundaries.
#[test]
fn frame_head_is_total_over_prefixes() {
    for &len in &[0usize, 1, 125, 126, 127, 65_535, 65_536, 8 * 1024 * 1024] {
        let head = server_frame(true, OP_TEXT, len);
        for cut in 0..head.len() {
            let want_need = match cut {
                0 | 1 => 2 - cut,
                _ => head.len() - cut,
            };
            assert_eq!(
                frame_head(&head[..cut]),
                HeadVerdict::Incomplete { need: want_need },
                "len {len}, prefix {cut}"
            );
        }
        match frame_head(&head) {
            HeadVerdict::Done(h) => {
                assert!(h.fin);
                assert_eq!(h.opcode, OP_TEXT);
                assert_eq!(h.header_len, head.len());
                assert_eq!(h.payload_len, len, "len {len}");
            }
            other => panic!("len {len}: {other:?}"),
        }
    }
}

/// Each §5 violation a client can detect is refused, not delivered.
#[test]
fn frame_head_refuses_protocol_violations() {
    // A masked server frame.
    let mut f = server_frame(true, OP_TEXT, 5);
    f[1] |= 0x80;
    assert!(matches!(frame_head(&f), HeadVerdict::Invalid(_)), "mask");
    // RSV bits without a negotiated extension.
    let mut f = server_frame(true, OP_TEXT, 5);
    f[0] |= 0x40;
    assert!(matches!(frame_head(&f), HeadVerdict::Invalid(_)), "rsv");
    // Reserved opcodes, data and control ranges both.
    for op in [0x3, 0x7, 0xB, 0xF] {
        let f = server_frame(true, op, 0);
        assert!(matches!(frame_head(&f), HeadVerdict::Invalid(_)), "opcode {op:#x}");
    }
    // A fragmented control frame.
    let f = server_frame(false, OP_PING, 0);
    assert!(matches!(frame_head(&f), HeadVerdict::Invalid(_)), "control FIN=0");
    // A control frame declaring more than 125 bytes - both extended forms. 200 encodes as the 126 indicator; a raw
    // 127 indicator on a control opcode is equally illegal (libwebsockets rejects both at `illegal_ctl_length`,
    // client-parser-ws.c:336-348).
    let f = server_frame(true, OP_CLOSE, 200);
    assert!(matches!(frame_head(&f), HeadVerdict::Invalid(_)), "control 126-length");
    for op in [OP_CLOSE, OP_PING, OP_PONG] {
        let f = [0x80 | op, 126];
        assert!(
            matches!(frame_head(&f), HeadVerdict::Invalid(_)),
            "control 126 indicator, op {op:#x}"
        );
        let f = [0x80 | op, 127];
        assert!(
            matches!(frame_head(&f), HeadVerdict::Invalid(_)),
            "control 127 indicator, op {op:#x}"
        );
    }
    // Non-minimal encodings: a 16-bit form holding a 7-bit value, a 64-bit form holding a 16-bit value.
    let f = [0x80 | OP_TEXT, 126, 0, 125];
    assert!(matches!(frame_head(&f), HeadVerdict::Invalid(_)), "non-minimal 16");
    let mut f = vec![0x80 | OP_TEXT, 127];
    f.extend_from_slice(&65_535u64.to_be_bytes());
    assert!(matches!(frame_head(&f), HeadVerdict::Invalid(_)), "non-minimal 64");
    // The 64-bit sign bit (libwebsockets `b63 of length must be zero`, client-parser-ws.c:387-392).
    let mut f = vec![0x80 | OP_TEXT, 127];
    f.extend_from_slice(&(1u64 << 63).to_be_bytes());
    assert!(matches!(frame_head(&f), HeadVerdict::Invalid(_)), "sign bit");
}

/// A well-formed control frame at the size limit is accepted, with FIN=1 and a payload of 0..=125 in the 7-bit form.
#[test]
fn frame_head_accepts_well_formed_control_frames() {
    for op in [OP_CLOSE, OP_PING, OP_PONG] {
        for len in [0usize, 2, 125] {
            let f = server_frame(true, op, len);
            match frame_head(&f) {
                HeadVerdict::Done(h) => {
                    assert!(h.fin);
                    assert_eq!(h.opcode, op);
                    assert_eq!(h.header_len, 2, "control uses the 7-bit form");
                    assert_eq!(h.payload_len, len);
                }
                other => panic!("op {op:#x} len {len}: {other:?}"),
            }
        }
    }
}

/// The handshake phase: idle park on empty, in-message on a begun head, an exact cut at the blank line (bytes past
/// it left for the frame phase), and the head cap.
#[test]
fn handshake_phase_cuts_the_head_exactly() {
    let mut st = WsState::default();
    assert_eq!(ws_frame(b"", &mut st), Framing::More);
    assert_eq!(
        ws_frame(b"HTTP/1.1 101 Switching Protocols\r\nUpg", &mut st),
        Framing::MoreInMessage
    );
    // Split *inside* the terminator: still mid-message.
    let head = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n";
    assert_eq!(ws_frame(&head[..head.len() - 1], &mut st), Framing::MoreInMessage);
    // The full head with a coalesced first frame behind it: the cut is the head alone, and the phase flips.
    let mut wire = head.to_vec();
    wire.extend_from_slice(&server_frame(true, OP_TEXT, 3));
    wire.extend_from_slice(b"abc");
    assert_eq!(
        ws_frame(&wire, &mut st),
        Framing::Complete {
            header_len: head.len(),
            body_len: 0
        }
    );
    // Frame phase now: the coalesced remainder frames as a message.
    assert_eq!(
        ws_frame(&wire[head.len()..], &mut st),
        Framing::Complete {
            header_len: 2,
            body_len: 3
        }
    );
}

/// A non-101 head is still delivered - the session reports the status line - and junk that never terminates is
/// refused at the cap.
#[test]
fn handshake_phase_delivers_refusals_and_caps_junk() {
    let mut st = WsState::default();
    let head = b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n";
    assert_eq!(
        ws_frame(head, &mut st),
        Framing::Complete {
            header_len: head.len(),
            body_len: 0
        }
    );

    let mut st = WsState::default();
    let junk = vec![b'x'; MAX_HEAD + 1];
    assert_eq!(ws_frame(&junk, &mut st), Framing::Invalid);
}

/// The frame phase: idle `Need(2)` on empty, exact in-message asks on a begun header, `Complete` splitting header
/// from payload - the empty-payload control frame included (`frame_step` refuses only a zero-length *message*, and
/// header_len is never zero here).
#[test]
fn frame_phase_asks_exactly() {
    let mut st = WsState { phase: Phase::Frames };
    assert_eq!(ws_frame(b"", &mut st), Framing::Need(2));
    let f = server_frame(true, OP_TEXT, 70_000);
    assert_eq!(ws_frame(&f[..1], &mut st), Framing::NeedInMessage(1));
    assert_eq!(ws_frame(&f[..2], &mut st), Framing::NeedInMessage(8));
    assert_eq!(
        ws_frame(&f, &mut st),
        Framing::Complete {
            header_len: 10,
            body_len: 70_000
        }
    );
    // An empty pong: Complete{2, 0}.
    let f = server_frame(true, OP_PONG, 0);
    assert_eq!(
        ws_frame(&f, &mut st),
        Framing::Complete {
            header_len: 2,
            body_len: 0
        }
    );
    // A malformed header closes the connection.
    let mut f = server_frame(true, OP_TEXT, 5);
    f[1] |= 0x80;
    assert_eq!(ws_frame(&f, &mut st), Framing::Invalid);
}

/// Encoding picks the minimal length form at each boundary, masks the payload, and round-trips: unmasking by hand
/// recovers the payload, and the header parses (as a client frame it must carry MASK, which the server-side parser
/// rejects - asserted as the negative).
#[test]
fn encode_round_trips_and_masks() {
    for &len in &[0usize, 1, 125, 126, 65_535, 65_536] {
        let payload: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        let mask = [0x11, 0x22, 0x33, 0x44];
        let f = encode_frame(OP_TEXT, &payload, mask);
        assert_eq!(f[0], 0x80 | OP_TEXT, "FIN always set");
        assert!(f[1] & 0x80 != 0, "client frames are masked");
        let (header_len, declared) = match f[1] & 0x7F {
            126 => (4, usize::from(u16::from_be_bytes([f[2], f[3]]))),
            127 => (10, u64::from_be_bytes(f[2..10].try_into().unwrap()) as usize),
            n => (2, usize::from(n)),
        };
        assert_eq!(declared, len);
        // Minimal form at each boundary.
        let want_header = match len {
            n if n < 126 => 2,
            n if n <= 0xFFFF => 4,
            _ => 10,
        };
        assert_eq!(header_len, want_header, "len {len}");
        assert_eq!(&f[header_len..header_len + 4], &mask);
        let unmasked: Vec<u8> = f[header_len + 4..]
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ mask[i % 4])
            .collect();
        assert_eq!(unmasked, payload, "len {len}");
        if len > 0 {
            assert_ne!(
                &f[header_len + 4..],
                &payload[..],
                "the mask must actually apply (len {len})"
            );
        }
        // The server-side parser refuses it - client frames are not server frames.
        assert!(matches!(frame_head(&f), HeadVerdict::Invalid(_)));
    }
}

/// The upgrade request is byte-exact, the head the reference client sends.
#[test]
fn upgrade_request_is_byte_exact() {
    let req = upgrade_request("/api/current", "AAAA").unwrap();
    assert_eq!(
        std::str::from_utf8(&req).unwrap(),
        "GET /api/current HTTP/1.1\r\n\
             Host: localhost\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Key: AAAA\r\n\
             Sec-WebSocket-Version: 13\r\n\r\n"
    );
}

/// Keys draw fresh entropy, the cheapest observable that the plumbing is wired at all. A collision has odds of
/// 2^-128.
#[test]
fn keys_are_fresh() {
    assert_ne!(ws_key(), ws_key());
    let key = ws_key();
    assert_eq!(key.len(), 24, "16 bytes base64-encode to 24 chars");
    assert!(key.ends_with("=="), "16 bytes pad with ==");
}

/// The server direction inverts the mask rule: `server_frame_head` *requires* the client mask bit (libwebsockets'
/// server refuses an unmasked client frame, `ops-ws.c:270-276`) and folds the 4-byte key into `header_len`, while
/// `frame_head` still refuses a masked one.
#[test]
fn server_frame_head_requires_the_client_mask() {
    // A client frame (what encode_frame produces): masked.
    let client = encode_frame(OP_TEXT, b"hello", [1, 2, 3, 4]);
    match server_frame_head(&client) {
        HeadVerdict::Done(h) => {
            assert_eq!(h.opcode, OP_TEXT);
            assert_eq!(h.payload_len, 5);
            assert_eq!(h.header_len, 6, "2 base + 4 mask key");
        }
        other => panic!("a masked client frame should parse: {other:?}"),
    }
    // The client parser refuses that same masked frame.
    assert!(matches!(frame_head(&client), HeadVerdict::Invalid(_)));
    // And the server parser refuses an *unmasked* frame.
    let unmasked = encode_server_frame(OP_TEXT, b"hello");
    assert!(matches!(server_frame_head(&unmasked), HeadVerdict::Invalid(_)));
}

/// A client frame round-trips through the server path: encode masked, parse the header, and `unmask` recovers the
/// payload from the key in the delivered header. Every extended-length form.
#[test]
fn a_masked_frame_round_trips_through_the_server_path() {
    for &len in &[0usize, 5, 125, 126, 65_535, 65_536] {
        let payload: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        let frame = encode_frame(OP_TEXT, &payload, mask_key());
        let HeadVerdict::Done(h) = server_frame_head(&frame) else {
            panic!("len {len}: masked header should parse");
        };
        assert_eq!(h.payload_len, len);
        let base = match len {
            n if n < 126 => 2,
            n if n <= 0xFFFF => 4,
            _ => 10,
        };
        assert_eq!(h.header_len, base + 4, "len {len}: base + mask key");
        let mut body = frame[h.header_len..].to_vec();
        unmask(&frame[..h.header_len], &mut body);
        assert_eq!(body, payload, "len {len}: unmask recovers payload");
    }
}

/// The server framer cuts the client's GET upgrade head, then masked frames - the twin of the client framer's
/// phases.
#[test]
fn ws_server_frame_cuts_head_then_masked_frames() {
    let mut st = WsState::default();
    let req = b"GET /api/current HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: k\r\nSec-WebSocket-Version: 13\r\n\r\n";
    let mut wire = req.to_vec();
    wire.extend_from_slice(&encode_frame(OP_TEXT, b"hi", [9, 9, 9, 9]));
    assert_eq!(
        ws_server_frame(&wire, &mut st),
        Framing::Complete {
            header_len: req.len(),
            body_len: 0
        }
    );
    // Frame phase: the coalesced masked frame (2 base + 4 mask key).
    assert_eq!(
        ws_server_frame(&wire[req.len()..], &mut st),
        Framing::Complete {
            header_len: 6,
            body_len: 2
        }
    );
}

/// The server handshake: a well-formed GET upgrade yields its key, and upgrade_response answers the accept the
/// client will check; each way the request can be wrong is refused as itself.
#[test]
fn validate_upgrade_request_reads_the_key_and_refuses_bad_requests() {
    let good = b"GET /api/current HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
    let key = validate_upgrade_request(good).expect("a valid upgrade");
    assert_eq!(key, "dGhlIHNhbXBsZSBub25jZQ==");
    // The 101 the server would send round-trips through the client's own validator (server accept == what the
    // client expects).
    let resp = upgrade_response(&key);
    assert!(validate_101(&resp, &key).is_ok());

    // Not a GET.
    let post = b"POST /x HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: k\r\nSec-WebSocket-Version: 13\r\n\r\n";
    assert!(matches!(
        validate_upgrade_request(post),
        Err(HandshakeError::NotUpgradeRequest)
    ));
    // Missing key.
    let no_key = b"GET /x HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\n\r\n";
    assert!(matches!(
        validate_upgrade_request(no_key),
        Err(HandshakeError::MissingKey)
    ));
    // Wrong version.
    let bad_ver = b"GET /x HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: k\r\nSec-WebSocket-Version: 8\r\n\r\n";
    assert!(matches!(
        validate_upgrade_request(bad_ver),
        Err(HandshakeError::BadVersion)
    ));
    // Missing upgrade tokens.
    let no_up = b"GET /x HTTP/1.1\r\nSec-WebSocket-Key: k\r\nSec-WebSocket-Version: 13\r\n\r\n";
    assert!(matches!(
        validate_upgrade_request(no_up),
        Err(HandshakeError::NotUpgradeRequest)
    ));
}

/// A client masks *every* frame it sends, control frames included - libwebsockets applies the mask block
/// unconditionally on the client role (ops-ws.c:2008-2025, not opcode-gated). So a close/ping/pong carries the mask
/// bit and its (tiny) payload is masked too.
#[test]
fn control_frames_are_masked_too() {
    let mask = [0xDE, 0xAD, 0xBE, 0xEF];
    for (op, payload) in [
        (OP_CLOSE, &b"\x03\xe9"[..]), // status 1001, big-endian
        (OP_PING, b"ping-me"),
        (OP_PONG, b""),
    ] {
        let f = encode_frame(op, payload, mask);
        assert_eq!(f[0], 0x80 | op, "FIN + opcode");
        assert!(f[1] & 0x80 != 0, "control frames are masked");
        assert_eq!(usize::from(f[1] & 0x7f), payload.len(), "7-bit len");
        assert_eq!(&f[2..6], &mask, "mask key present");
        let got: Vec<u8> = f[6..].iter().enumerate().map(|(i, b)| b ^ mask[i % 4]).collect();
        assert_eq!(got, payload, "payload unmasks to the original");
    }
}

/// A repeated `Connection` is combined as one list (RFC 9110 §5.3), while a repeated `Upgrade`, nonce, version or
/// negotiation slot is refused.
#[test]
fn a_repeated_header_is_combined_or_refused_by_what_it_is() {
    let key = "dGhlIHNhbXBsZSBub25jZQ==";
    // --- lists: split across lines, and in either order ---
    for split in [
        "Connection: keep-alive\r\nConnection: Upgrade\r\n",
        "Connection: Upgrade\r\nConnection: keep-alive\r\n",
        "Connection: keep-alive, Upgrade\r\n",
    ] {
        let head = format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\
                 {split}Sec-WebSocket-Accept: {}\r\n\r\n",
            accept_for(key)
        );
        assert!(
            validate_101(head.as_bytes(), key).is_ok(),
            "a combinable Connection must be read across lines: {split:?}"
        );
    }
    // `Upgrade` is NOT a token search. RFC 6455 sec. 4.1 fails a 101 whose Upgrade "contains a value that is not an
    // ASCII case-insensitive match for the value websocket", and libwebsockets' client is a plain `strcmp`
    // (client-ws.c). A token search here would accept this; both refuse it.
    let head = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: h2c, websocket\r\n\
             Connection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n",
        accept_for(key)
    );
    assert!(
        matches!(validate_101(head.as_bytes(), key), Err(HandshakeError::NotUpgraded)),
        "Upgrade must equal websocket, not merely contain it"
    );
    // ...and a second Upgrade line is a duplicate, not a merge.
    let twice = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\
             Upgrade: h2c\r\nConnection: Upgrade\r\n\
             Sec-WebSocket-Accept: {}\r\n\r\n",
        accept_for(key)
    );
    assert!(matches!(
        validate_101(twice.as_bytes(), key),
        Err(HandshakeError::DuplicateHeader { header: "Upgrade" })
    ));

    // --- the request direction, same rule ---
    let req = |extra: &str| {
        format!(
            "GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n\
                 {extra}Sec-WebSocket-Version: 13\r\n\r\n"
        )
    };
    let combined = req("Connection: keep-alive\r\nConnection: Upgrade\r\n\
                            Sec-WebSocket-Key: abc\r\n");
    assert_eq!(
        validate_upgrade_request(combined.as_bytes()).ok().as_deref(),
        Some("abc"),
    );

    // --- singletons: a second line is refused, not preferred ---
    let two_keys = req("Connection: Upgrade\r\nSec-WebSocket-Key: attacker\r\n\
             Sec-WebSocket-Key: victim\r\n");
    assert!(
        matches!(
            validate_upgrade_request(two_keys.as_bytes()),
            Err(HandshakeError::DuplicateHeader {
                header: "Sec-WebSocket-Key"
            })
        ),
        "two nonces must not resolve to one of them"
    );
    // --- the two negotiation slots, at most one per response (§11.3.2, §11.3.4) ---
    for header in ["Sec-WebSocket-Extensions", "Sec-WebSocket-Protocol"] {
        let twice = format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\
                 Connection: Upgrade\r\n{header}: \r\n{header}: \r\n\
                 Sec-WebSocket-Accept: {}\r\n\r\n",
            accept_for(key)
        );
        assert!(
            matches!(
                validate_101(twice.as_bytes(), key),
                Err(HandshakeError::DuplicateHeader { header: h }) if h == header
            ),
            "a repeated {header} must be refused in a response"
        );
    }

    // The request direction needs the `Upgrade` duplicate rule too.
    let two_upgrades = "GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n\
             Upgrade: h2c\r\nConnection: Upgrade\r\n\
             Sec-WebSocket-Key: abc\r\nSec-WebSocket-Version: 13\r\n\r\n";
    assert!(
        matches!(
            validate_upgrade_request(two_upgrades.as_bytes()),
            Err(HandshakeError::DuplicateHeader { header: "Upgrade" })
        ),
        "a repeated Upgrade must be refused in a request too"
    );
    let two_versions = "GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n\
             Connection: Upgrade\r\nSec-WebSocket-Key: abc\r\n\
             Sec-WebSocket-Version: 8\r\nSec-WebSocket-Version: 13\r\n\r\n";
    assert!(
        matches!(
            validate_upgrade_request(two_versions.as_bytes()),
            Err(HandshakeError::DuplicateHeader {
                header: "Sec-WebSocket-Version"
            })
        ),
        "a second version line must not excuse the first"
    );
}

/// A target that would end the request line early, and so forge a header or a second request, is refused before it
/// reaches the wire.
#[test]
fn a_request_target_that_would_split_the_request_is_refused() {
    for good in [
        "/",
        "/api/current",
        "/api/v26.0.0",
        "/api/current?x=1&y=%20",
        "/a/b/c#frag",
    ] {
        assert!(validate_request_target(good).is_ok(), "{good:?} must be accepted");
        assert!(upgrade_request(good, "AAAA").is_ok());
    }
    for bad in [
        "",                              // no target at all
        "api/current",                   // not origin-form
        "/api/cur rent",                 // ends the target
        "/api/current\r\nX-Injected: 1", // forges a header
        "/a HTTP/1.1\r\n\r\nGET /admin", // forges a request
        "/api/\ncurrent",                // bare LF
        "/api/\u{0}current",             // NUL
        "/api/\u{7f}current",            // DEL
        "/api/café",                     // non-ASCII
        &format!("/{}", "a".repeat(MAX_TARGET)),
    ] {
        assert!(
            matches!(validate_request_target(bad), Err(HandshakeError::BadTarget { .. })),
            "{bad:?} must be refused"
        );
        assert!(
            upgrade_request(bad, "AAAA").is_err(),
            "{bad:?} must not reach a request line"
        );
    }
    // The screen is the whole defence, so pin what it defends: one request line, five headers, and the blank line
    // that ends the head - seven CRLFs and no more.
    let req = upgrade_request("/api/current", "AAAA").unwrap();
    assert!(req.starts_with(b"GET /api/current HTTP/1.1\r\n"));
    assert_eq!(
        req.windows(2).filter(|w| w == b"\r\n").count(),
        7,
        "the head is a request line, five headers and a blank line"
    );
}

/// A `101` selecting an extension or subprotocol this client never offered is refused (§4.1 items 5 and 6), and so
/// is a second `Sec-WebSocket-Accept` (§11.3.3).
#[test]
fn validate_101_refuses_unoffered_negotiation_and_duplicate_accepts() {
    let key = "dGhlIHNhbXBsZSBub25jZQ==";
    let head = |extra: &str| {
        format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\
                 Connection: Upgrade\r\n{extra}Sec-WebSocket-Accept: {}\r\n\r\n",
            accept_for(key)
        )
    };
    assert!(validate_101(head("").as_bytes(), key).is_ok(), "the control");
    for extra in [
        "Sec-WebSocket-Extensions: permessage-deflate\r\n",
        "sec-websocket-extensions: x-webkit-deflate-frame\r\n",
        "Sec-WebSocket-Protocol: chat\r\n",
    ] {
        assert!(
            matches!(
                validate_101(head(extra).as_bytes(), key),
                Err(HandshakeError::Unrequested { .. })
            ),
            "must refuse {extra:?}"
        );
    }
    // An empty value selects nothing and is not a refusal.
    assert!(
        validate_101(head("Sec-WebSocket-Protocol: \r\n").as_bytes(), key).is_ok(),
        "an empty selection is no selection"
    );
    // §11.3.3, both orders - a duplicate is refused either way.
    let dup = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\
             Connection: Upgrade\r\nSec-WebSocket-Accept: \
             bm90LXRoZS1kaWdlc3Q=\r\nSec-WebSocket-Accept: {}\r\n\r\n",
        accept_for(key)
    );
    assert!(
        matches!(
            validate_101(dup.as_bytes(), key),
            Err(HandshakeError::DuplicateHeader {
                header: "Sec-WebSocket-Accept"
            })
        ),
        "a wrong accept is not excused by a right one behind it"
    );
    let dup_rev = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\
             Connection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\
             Sec-WebSocket-Accept: bm90LXRoZS1kaWdlc3Q=\r\n\r\n",
        accept_for(key)
    );
    assert!(matches!(
        validate_101(dup_rev.as_bytes(), key),
        Err(HandshakeError::DuplicateHeader {
            header: "Sec-WebSocket-Accept"
        })
    ));
}

/// §7.4.1's send bound, and the echo it produces. The reserved values an endpoint MUST NOT set never reach the
/// wire; a sendable code is passed through unchanged.
#[test]
fn close_echo_refuses_the_codes_no_endpoint_may_send() {
    // 1012-1014 are the IANA registrations §7.4.2 provides for. Nothing else fails if the range narrows back to
    // `1007..=1011`.
    for code in [1000u16, 1001, 1002, 1003, 1007, 1011, 1012, 1013, 1014, 3000, 4999] {
        assert!(is_sendable_close_code(code), "{code} is sendable");
        assert_eq!(
            close_echo_code(&code.to_be_bytes()),
            Some(code),
            "{code} echoes unchanged"
        );
    }
    // §7.4.1's reserved values, and the ranges with no assigned meaning.
    for code in [0u16, 999, 1004, 1005, 1006, 1015, 1016, 2999, 5000] {
        assert!(!is_sendable_close_code(code), "{code} is not sendable");
        assert_eq!(
            close_echo_code(&code.to_be_bytes()),
            Some(CLOSE_PROTOCOL_ERROR),
            "{code} is answered 1002, not reflected"
        );
    }
    // No body stays no body; a one-byte body is a malformed frame.
    assert_eq!(close_echo_code(&[]), None);
    assert_eq!(close_echo_code(&[0x03]), Some(CLOSE_PROTOCOL_ERROR));
    // §5.5.1/§8.1: the reason must be UTF-8.
    let mut bad = 1000u16.to_be_bytes().to_vec();
    bad.extend_from_slice(&[0xFF, 0xFE]);
    assert_eq!(close_echo_code(&bad), Some(CLOSE_INVALID_PAYLOAD));
    let mut good = 1000u16.to_be_bytes().to_vec();
    good.extend_from_slice(b"bye");
    assert_eq!(close_echo_code(&good), Some(1000));
}
