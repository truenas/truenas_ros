//! RFC 6455 WebSocket, as a codec over the [`net`](crate::net) protocol
//! seam - the WebSocket analogue of the `http` codec, and like it a
//! codec rather than a server.
//!
//! A WebSocket connection speaks three shapes in sequence: one HTTP
//! upgrade request, one HTTP response head, then RFC 6455 frames. This
//! module owns all three as *pure* pieces and does no I/O and no dispatch.
//! Both directions are present as mirror pairs:
//!
//! - **Framers** ([`Framing`]): [`ws_frame`] drives a `net::client` (cut
//!   the `101` head, then server frames); [`ws_server_frame`] drives a
//!   `net::server` (cut the `GET` upgrade head, then client frames).
//! - **Header parse**: [`frame_head`] (client reading the server - refuses
//!   a mask) and [`server_frame_head`] (server reading a client - requires
//!   the mask, folds its key into `header_len`; [`unmask`] recovers the
//!   payload). Both the framer and a consumer re-reading a delivered
//!   header use these.
//! - **Encode**: [`encode_frame`] (client, masked) and
//!   [`encode_server_frame`] (server, unmasked).
//! - **Handshake**: [`upgrade_request`] + [`validate_101`] on the client;
//!   [`validate_upgrade_request`] + [`upgrade_response`] on the server;
//!   [`accept_for`]/[`ws_key`]/[`mask_key`] shared.
//!
//! What a frame *means* - request/response, the ping and close
//! disciplines, continuation reassembly - is the consumer's: a framer
//! cannot send, so every frame (control frames included) is delivered
//! whole and answered from the pump.
//!
//! The framer never answers `More` in the frame phase: every WebSocket
//! frame declares its length in its first 2..=14 bytes, so exact
//! `Need`/`NeedInMessage` asks read the header and let the reactor read
//! the payload in one exact recv (`More` reads 4 KiB chunks and re-scans -
//! the delimiter-hunting shape, right only for the HTTP head).
//!
//! # Direction and strictness
//!
//! §5.1's mask rule is the only asymmetry: a client masks what it sends
//! and refuses a masked server frame; a server requires the client mask
//! and sends unmasked. The frame length codec, control-frame rules, SHA-1,
//! and base64 are shared.
//!
//! Behaviour is checked against **libwebsockets** (`/CODE/libwebsockets`),
//! the canonical implementation, rather than the RFC prose alone: the
//! accept digest is what its client verifies at `lib/roles/ws/client-ws.c`
//! and its server emits at `lib/roles/ws/server-ws.c:687`.
//!
//! Where this parser is *stricter* than libwebsockets' client, on purpose,
//! because the peer is one specific server (aiohttp) that never exercises
//! the lenient corners and strictness is free safety:
//!
//! - **Any RSV bit is refused.** This crate negotiates no extension, so
//!   RSV1/2/3 are all illegal. lws-client only rejects RSV when no
//!   extension is active and, with permessage-deflate on, accepts RSV2/3
//!   without a per-bit check (`client-parser-ws.c:281-290`).
//! - **A non-minimal length is refused** (a 16-bit form under 126, a
//!   64-bit form at or under `0xFFFF`). RFC 6455 §5.2 requires the sender
//!   use the minimal form; lws-client does not check on receive.
//! - **UTF-8 is not validated here.** A text frame is JSON, and a
//!   `serde_json` decode rejects non-UTF-8, so the codec does not need to
//!   look - lws-client validates UTF-8 only when the context opts in
//!   (`client-parser-ws.c:228-231`). **That is about detection, not about
//!   the verdict**, and the two are not the same: RFC 6455 §8.1 requires
//!   *failing the connection* on invalid UTF-8, while bad JSON is an
//!   application error a role may answer and serve past. Each consumer
//!   therefore owns its own screen - `Session::on_message` faults on any
//!   non-JSON text, and `JsonRpcServer::on_message` checks the encoding
//!   explicitly because it answers `-32700` and keeps serving otherwise.
//!   A role that leaves this to `serde_json` alone will answer an
//!   invalid-UTF-8 frame instead of failing on it.
//!
//! Two behaviours are consciously *not* enforced, because the framer is a
//! per-frame cutter and the peer is well-behaved: the receipt clock is not
//! held across the frames of a fragmented message (each frame is its own
//! delivery, and middlewared never fragments - see [`ws_frame`]), and a
//! peer close code is echoed verbatim rather than sanitised to `1002`
//! (the connection closes immediately either way).

use crate::net::Framing;

/// Continuation of a fragmented message (RFC 6455 §5.4).
pub const OP_CONT: u8 = 0x0;
/// A text data frame - the JSON-RPC payload opcode.
pub const OP_TEXT: u8 = 0x1;
/// A binary data frame.
pub const OP_BINARY: u8 = 0x2;
/// Connection close (§5.5.1).
pub const OP_CLOSE: u8 = 0x8;
/// Ping - must be answered with a pong carrying the same payload (§5.5.2).
pub const OP_PING: u8 = 0x9;
/// Pong (§5.5.3).
pub const OP_PONG: u8 = 0xA;

/// The GUID §1.3 fixes for the accept digest (libwebsockets
/// `client-ws.c:217`, `server-ws.c:687`).
const ACCEPT_GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// §7.4.1's 1002: the connection is ending because of a protocol error.
pub const CLOSE_PROTOCOL_ERROR: u16 = 1002;
/// §7.4.1's 1007: data inside a message was inconsistent with the message
/// type - non-UTF-8 where §5.6/§5.5.1 require UTF-8.
pub const CLOSE_INVALID_PAYLOAD: u16 = 1007;

/// Bound on the HTTP response head. A 101 is a few hundred bytes; anything
/// that reaches this without a blank line is not a WebSocket handshake.
const MAX_HEAD: usize = 16 * 1024;

/// One parsed frame header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameHead {
    /// Whether this frame ends its message (`FIN`).
    pub fin: bool,
    /// The 4-bit opcode.
    pub opcode: u8,
    /// Header length in bytes: 2, 4, or 10 for an unmasked (server->client)
    /// frame, plus 4 for the masking key on a masked (client->server) one,
    /// so 6, 8, or 14.
    pub header_len: usize,
    /// Declared payload length.
    pub payload_len: usize,
}

/// [`frame_head`]'s verdict over however many bytes have accumulated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HeadVerdict {
    /// The header is incomplete; read exactly this many more bytes.
    Incomplete {
        /// Bytes missing to the next decision point.
        need: usize,
    },
    /// The bytes cannot be a valid frame header for the parsed direction;
    /// the reason is for a log or an assertion, never the wire.
    Invalid(&'static str),
    /// A complete header.
    Done(FrameHead),
}

/// Parse a **server -> client** frame header (the peer must not mask; RFC
/// §5.1) from the front of `buf`. This is the client-direction parse; a ws
/// server reading client frames uses [`server_frame_head`].
///
/// Total over any prefix: short input is `Incomplete` with an exact byte
/// count (never a guess - `MSG_WAITALL` reads can still complete short on
/// EOF, so re-entry with fewer bytes than asked must re-answer). Every
/// protocol violation §5 lets a client detect is `Invalid`: a MASK bit
/// (§5.1: a server MUST NOT mask), a RSV bit (no extension was negotiated,
/// §5.2), a reserved opcode, a fragmented or over-long control frame
/// (§5.5), and a non-minimal or sign-bit extended length (§5.2).
pub fn frame_head(buf: &[u8]) -> HeadVerdict {
    parse_head(buf, false)
}

/// Parse a **client -> server** frame header (the peer MUST mask; RFC
/// §5.1) from the front of `buf` - the server-direction twin of
/// [`frame_head`]. The 4-byte masking key is part of the header, so a
/// masked header is 6, 8, or 14 bytes and [`FrameHead::header_len`]
/// includes it; the payload arrives masked and is recovered with
/// [`unmask`]. Every other rejection is identical to [`frame_head`], only
/// the mask rule inverts (an *unmasked* client frame is refused, matching
/// libwebsockets' server `client unmasked`, `ops-ws.c:270-276`).
pub fn server_frame_head(buf: &[u8]) -> HeadVerdict {
    parse_head(buf, true)
}

/// The shared frame-header parse. `require_mask` selects the direction:
/// `false` refuses a masked frame (client reading the server), `true`
/// requires it and folds the 4-byte key into `header_len` (server reading
/// a client). Everything else - RSV, opcode, control-frame and
/// extended-length rules - is direction-neutral.
fn parse_head(buf: &[u8], require_mask: bool) -> HeadVerdict {
    if buf.len() < 2 {
        return HeadVerdict::Incomplete {
            need: 2 - buf.len(),
        };
    }
    let (b0, b1) = (buf[0], buf[1]);
    if b0 & 0x70 != 0 {
        return HeadVerdict::Invalid("RSV bits set with no extension");
    }
    let fin = b0 & 0x80 != 0;
    let opcode = b0 & 0x0F;
    if !matches!(
        opcode,
        OP_CONT | OP_TEXT | OP_BINARY | OP_CLOSE | OP_PING | OP_PONG
    ) {
        return HeadVerdict::Invalid("reserved opcode");
    }
    let masked = b1 & 0x80 != 0;
    if masked && !require_mask {
        return HeadVerdict::Invalid("a server frame must not be masked");
    }
    if !masked && require_mask {
        return HeadVerdict::Invalid("a client frame must be masked");
    }
    let len7 = usize::from(b1 & 0x7F);
    if opcode >= OP_CLOSE {
        // §5.5: control frames are never fragmented and carry <= 125 bytes.
        if !fin {
            return HeadVerdict::Invalid("fragmented control frame");
        }
        if len7 > 125 {
            return HeadVerdict::Invalid("control frame over 125 bytes");
        }
    }
    let (base_header_len, payload_len) = match len7 {
        126 => {
            if buf.len() < 4 {
                return HeadVerdict::Incomplete {
                    need: 4 - buf.len(),
                };
            }
            let n = usize::from(u16::from_be_bytes([buf[2], buf[3]]));
            if n < 126 {
                return HeadVerdict::Invalid("non-minimal 16-bit length");
            }
            (4, n)
        }
        127 => {
            if buf.len() < 10 {
                return HeadVerdict::Incomplete {
                    need: 10 - buf.len(),
                };
            }
            let n = u64::from_be_bytes([
                buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8], buf[9],
            ]);
            if n & (1 << 63) != 0 {
                return HeadVerdict::Invalid("64-bit length sign bit set");
            }
            if n <= 0xFFFF {
                return HeadVerdict::Invalid("non-minimal 64-bit length");
            }
            let Ok(n) = usize::try_from(n) else {
                return HeadVerdict::Invalid("length exceeds usize");
            };
            (10, n)
        }
        n => (2, n),
    };
    // A masked header carries the 4-byte key after the length; the whole
    // header must be buffered before the payload extent is known to the
    // reactor.
    let header_len = base_header_len + if masked { 4 } else { 0 };
    if buf.len() < header_len {
        return HeadVerdict::Incomplete {
            need: header_len - buf.len(),
        };
    }
    HeadVerdict::Done(FrameHead {
        fin,
        opcode,
        header_len,
        payload_len,
    })
}

/// Recover a masked client frame's payload in place, using the 4-byte key
/// at the tail of its `header` - the header [`server_frame_head`] framed,
/// and only that.
///
/// **This is not a no-op on an unmasked header, and cannot be made one.**
/// The mask bit lives in the header's second byte, but a masked header is
/// 6, 8 or 14 bytes and an unmasked one 2, 4 or 10 (RFC 6455 §5.2), so
/// the last four bytes of an unmasked 4- or 10-byte header are its own
/// length field - XORing a payload with those silently corrupts it, and a
/// 2-byte unmasked header trips the length assert below, which is a plain
/// `assert!` and so fires in release too. Server-to-client frames are
/// never masked (§5.3), which is why [`frame_head`]'s output must not be
/// passed here.
pub fn unmask(header: &[u8], payload: &mut [u8]) {
    assert!(
        header.len() >= 4,
        "unmask needs the 4-byte key server_frame_head put in the header"
    );
    let key = &header[header.len() - 4..];
    for (i, b) in payload.iter_mut().enumerate() {
        *b ^= key[i % 4];
    }
}

/// Whether `code` may be *sent* as a Close frame status code (RFC 6455
/// §7.4.1, §7.4.2). The sendable defined codes are 1000-1003 and
/// 1007-1014, plus 3000-4999 for libraries, frameworks and private
/// agreement. 1004, 1005, 1006 and 1015 are reserved values §7.4.1 says an
/// endpoint MUST NOT set, and the rest carries no meaning to send: 0-999 is
/// "not used", and 1016-2999 and 5000+ are undefined by this revision.
/// 1012-1014 are absent from RFC 6455 itself but registered with IANA
/// since, which §7.4.2 provides for - see the body comment.
///
/// A code arriving from a peer is a different question - a receiver reports
/// whatever it was told. This bounds only what goes back out, which is why
/// [`close_echo_code`] and not this is what the close discipline calls.
pub fn is_sendable_close_code(code: u16) -> bool {
    // 1000-1011 are §7.4.1's own definitions, less the three it forbids an
    // endpoint to send (1004 undefined, 1005 and 1006 reserved-not-on-wire).
    // 1012-1014 (Service Restart, Try Again Later, Bad Gateway) appear
    // nowhere in RFC 6455 - they are later IANA registrations, which §7.4.2
    // provides for ("reserved for definition by this protocol, its future
    // revisions, and extensions specified in a permanent and readily
    // available public specification"), so they are sendable and echoable.
    // 1015 stays out: §7.4.1 forbids setting it. 3000-3999 are registered
    // library/framework codes and 4000-4999 private, both sendable.
    //
    // **This diverges from libwebsockets**, which the module is otherwise
    // checked against: `ops-ws.c`'s peer-close arm rewrites 1012, 1013 and
    // 1014 to 1002 along with the codes §7.4.1 really forbids. Two other
    // implementations take the range this does, and one of them is the
    // server this crate talks to: aiohttp's `ALLOWED_CLOSE_CODES` is built
    // from a `WSCloseCode` enum that includes all three
    // (`aiohttp/_websocket/models.py`), and Python `websockets` lists them
    // in `EXTERNAL_CLOSE_CODES` (`websockets/frames.py`) with the same
    // `3000..=4999` tail. Rewriting a peer's 1013 "try again later" to
    // 1002 would answer a graceful retry request with a protocol-error
    // accusation, and middlewared's own stack would have accepted the
    // 1013. The narrow set is the older reading; this is the registry's.
    matches!(code, 1000..=1003 | 1007..=1014 | 3000..=4999)
}

/// The status code to answer a peer's close frame with, given its whole
/// close body: §5.5.1 has the endpoint echo the code it received, and
/// §7.4.1 bounds which codes it may put on the wire, so this is the echo
/// with that bound applied.
///
/// - No body: `None` - answer with no body either.
/// - A one-byte body: [`CLOSE_PROTOCOL_ERROR`]. §5.5.1 - "If there is a
///   body, the first two bytes of the body MUST be a 2-byte unsigned
///   integer" - so one byte is a malformed frame, not a code.
/// - A code [`is_sendable_close_code`] refuses: [`CLOSE_PROTOCOL_ERROR`],
///   because reflecting it would be this endpoint setting it.
/// - A reason that is not valid UTF-8: [`CLOSE_INVALID_PAYLOAD`] (§5.5.1
///   makes /reason/ UTF-8; §8.1 makes an invalid stream fatal).
/// - Otherwise the peer's own code.
pub fn close_echo_code(payload: &[u8]) -> Option<u16> {
    match payload.len() {
        0 => None,
        1 => Some(CLOSE_PROTOCOL_ERROR),
        _ => {
            let code = u16::from_be_bytes([payload[0], payload[1]]);
            if !is_sendable_close_code(code) {
                Some(CLOSE_PROTOCOL_ERROR)
            } else if std::str::from_utf8(&payload[2..]).is_err() {
                Some(CLOSE_INVALID_PAYLOAD)
            } else {
                Some(code)
            }
        }
    }
}

/// Which shape the connection is receiving.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum Phase {
    /// Before the HTTP response head has been cut: the upgrade is out, the
    /// `101` (or a refusal) is inbound.
    #[default]
    Handshake,
    /// WebSocket frames.
    Frames,
}

/// Per-connection framer state: the phase, and nothing else. Everything
/// stateful about *messages* (fragment reassembly, close progress) belongs
/// to the session, which sees every frame this framer cuts.
#[derive(Clone, Copy, Debug, Default)]
pub struct WsState {
    phase: Phase,
}

/// The `net::client` reply framer for a middlewared connection.
///
/// Handshake phase: scan for the head's terminating blank line - the one
/// delimiter of unknown position this protocol has, so the `More` family
/// is right here and only here. The whole head is delivered as a message
/// of `header_len == the head` and no body; a non-101 status is delivered
/// too (not `Invalid`), so the session can report the status line instead
/// of a bare close. Anything past the blank line - a server that coalesced
/// its first frame into the same flush - stays buffered for the frame
/// phase, which this verdict switches to.
///
/// Frame phase: exact asks. An empty buffer answers `Need(2)` - between
/// messages the connection is parked idle, which is the [`Framing::Need`]
/// contract - and a begun header answers `NeedInMessage` so the response
/// clock covers the remainder. A complete header is
/// `Complete { header_len, body_len: payload }`: the reactor reads exactly
/// the payload (placing large ones in their own allocation) and delivers
/// `Event::Reply { header: <raw frame header>, body: <payload> }`, which
/// the session re-parses with [`frame_head`] for FIN/opcode.
///
/// The framer is a per-frame cutter with no memory of fragmentation, so a
/// server that sends a non-final frame and then stalls is clocked as idle
/// between frames (`Need(2)`), not mid-message. Reassembly and its bound
/// live in the session, which sees each frame; middlewared never
/// fragments, so the gap is theoretical here.
pub fn ws_frame(buf: &[u8], st: &mut WsState) -> Framing {
    match st.phase {
        Phase::Handshake => head_step(buf, st),
        Phase::Frames => frame_step(buf, frame_head),
    }
}

/// The `net::server` reply framer for a WebSocket connection - the twin of
/// [`ws_frame`]. Handshake phase cuts the client's `GET` upgrade request
/// head identically (blank-line delimited); frame phase parses masked
/// client frames with [`server_frame_head`], so `Event`'s delivered header
/// carries the 4-byte key and the body is masked (recover it with
/// [`unmask`]).
pub fn ws_server_frame(buf: &[u8], st: &mut WsState) -> Framing {
    match st.phase {
        Phase::Handshake => head_step(buf, st),
        Phase::Frames => frame_step(buf, server_frame_head),
    }
}

/// The handshake phase, shared by both framers: scan for the head's
/// terminating blank line - the one delimiter of unknown position this
/// protocol has, so the `More` family is right here and only here. The
/// whole head is delivered as a message of `header_len == the head` and no
/// body (a non-101/non-GET head is delivered too, not `Invalid`, so the
/// consumer can report the status/request line). Anything past the blank
/// line - a peer that coalesced its first frame into the same flush -
/// stays buffered for the frame phase, which this verdict switches to.
fn head_step(buf: &[u8], st: &mut WsState) -> Framing {
    if buf.is_empty() {
        return Framing::More;
    }
    if let Some(at) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
        st.phase = Phase::Frames;
        return Framing::Complete {
            header_len: at + 4,
            body_len: 0,
        };
    }
    if buf.len() > MAX_HEAD {
        return Framing::Invalid;
    }
    Framing::MoreInMessage
}

/// The frame phase, parameterized by the direction's header parser. Exact
/// asks: an empty buffer answers `Need(2)` - between messages the
/// connection is parked idle, which is the [`Framing::Need`] contract -
/// and a begun header answers `NeedInMessage` so the receive clock covers
/// the remainder. A complete header is `Complete { header_len, body_len }`:
/// the reactor reads exactly the payload and delivers
/// `Event::Reply { header, body }`, which the consumer re-parses with the
/// same header parser for FIN/opcode.
///
/// The framer is a per-frame cutter with no memory of fragmentation, so a
/// peer that sends a non-final frame and then stalls is clocked as idle
/// between frames (`Need(2)`), not mid-message. Reassembly and its bound
/// live in the session, which sees each frame.
fn frame_step(buf: &[u8], parse: fn(&[u8]) -> HeadVerdict) -> Framing {
    if buf.is_empty() {
        return Framing::Need(2);
    }
    match parse(buf) {
        HeadVerdict::Incomplete { need } => Framing::NeedInMessage(need),
        HeadVerdict::Invalid(_) => Framing::Invalid,
        HeadVerdict::Done(h) => Framing::Complete {
            header_len: h.header_len,
            body_len: h.payload_len,
        },
    }
}

/// Encode one **client -> server** frame: FIN always set (the outbound
/// size guard keeps every message in one frame), minimal length form, and
/// the §5.3 mask applied. A fresh mask per frame comes from [`mask_key`].
pub fn encode_frame(opcode: u8, payload: &[u8], mask: [u8; 4]) -> Vec<u8> {
    encode(opcode, payload, Some(mask))
}

/// Encode one **server -> client** frame - the twin of [`encode_frame`],
/// unmasked (RFC §5.1: a server MUST NOT mask). Used by the ws server
/// role and by test harnesses that answer a client.
pub fn encode_server_frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
    encode(opcode, payload, None)
}

/// The shared frame encoder. `mask` present masks the payload and sets the
/// mask bit (client direction); absent leaves it clear (server direction).
fn encode(opcode: u8, payload: &[u8], mask: Option<[u8; 4]>) -> Vec<u8> {
    let mask_bit = if mask.is_some() { 0x80 } else { 0 };
    let mut out = Vec::with_capacity(14 + payload.len());
    out.push(0x80 | (opcode & 0x0F));
    match payload.len() {
        n if n < 126 => out.push(mask_bit | n as u8),
        n if n <= 0xFFFF => {
            out.push(mask_bit | 126);
            out.extend_from_slice(&(n as u16).to_be_bytes());
        }
        n => {
            out.push(mask_bit | 127);
            out.extend_from_slice(&(n as u64).to_be_bytes());
        }
    }
    match mask {
        Some(m) => {
            out.extend_from_slice(&m);
            out.extend(payload.iter().enumerate().map(|(i, b)| b ^ m[i % 4]));
        }
        None => out.extend_from_slice(payload),
    }
    out
}

/// Bound on an endpoint. A request-target this long is not a mistake
/// anyone makes by hand, and the request line has to fit a head the peer
/// will read.
const MAX_TARGET: usize = 2048;

/// Whether `endpoint` may be spliced into a request line: non-empty, no
/// longer than 2048 bytes, beginning with `/`, and every byte a visible
/// ASCII character.
///
/// RFC 9112 §3 makes `request-line = method SP request-target SP
/// HTTP-version CRLF`, so a target carrying CR, LF or a space does not
/// produce a longer request line - it produces *more lines*. A `\r\n`
/// closes the request line and everything after it is read as a header
/// field, or as a second request; that is request splitting, and the
/// endpoint is the one field of this handshake a deployment supplies.
/// Rejecting every byte outside `0x21..=0x7E` also covers NUL, DEL, the
/// C0 controls and anything non-ASCII, none of which belong in an
/// origin-form target either (RFC 9110 §4.1 keeps a target to US-ASCII,
/// percent-encoding the rest).
///
/// This is a bound on shape, not a URI parser: a target that clears it
/// can still be a path middlewared does not serve, which the server
/// answers for itself.
pub fn validate_request_target(endpoint: &str) -> Result<(), HandshakeError> {
    let bad = |value: &str| {
        Err(HandshakeError::BadTarget {
            value: value.escape_default().to_string(),
        })
    };
    if endpoint.is_empty() || endpoint.len() > MAX_TARGET {
        return bad(endpoint);
    }
    if !endpoint.starts_with('/') {
        return bad(endpoint);
    }
    if !endpoint.bytes().all(|b| (0x21..=0x7E).contains(&b)) {
        return bad(endpoint);
    }
    Ok(())
}

/// The upgrade request for `endpoint` (e.g. `/api/current`), carrying
/// `key` as `Sec-WebSocket-Key`.
///
/// `endpoint` goes into the request line verbatim, so it is screened by
/// [`validate_request_target`] first and this refuses rather than
/// splicing - the screen is the whole defence against request splitting
/// through a configured endpoint, and a caller that could skip it would
/// be the hole. `key` is minted by [`ws_key`] and is base64 by
/// construction.
///
/// `Host: localhost` is what the reference Python client sends over the
/// unix socket (it dials the path itself and hands its WebSocket layer a
/// dummy `ws://localhost/...` URL), so it is the value every middlewared
/// deployment has been accepting since the JSON-RPC API shipped.
pub fn upgrade_request(
    endpoint: &str,
    key: &str,
) -> Result<Vec<u8>, HandshakeError> {
    validate_request_target(endpoint)?;
    let mut out = Vec::with_capacity(160 + endpoint.len());
    out.extend_from_slice(b"GET ");
    out.extend_from_slice(endpoint.as_bytes());
    out.extend_from_slice(b" HTTP/1.1\r\nHost: localhost\r\n");
    out.extend_from_slice(b"Upgrade: websocket\r\nConnection: Upgrade\r\n");
    out.extend_from_slice(b"Sec-WebSocket-Key: ");
    out.extend_from_slice(key.as_bytes());
    out.extend_from_slice(b"\r\nSec-WebSocket-Version: 13\r\n\r\n");
    Ok(out)
}

/// The `Sec-WebSocket-Accept` value that proves the peer parsed `key`:
/// base64 of SHA-1 over the key with §1.3's GUID appended. Compared
/// byte-exact - base64 is case-sensitive - after trimming optional
/// whitespace around the header value.
///
/// `pub` because the server side of a handshake needs exactly this digest
/// too: a peer answering an upgrade (a test's scripted server, or a future
/// `ws` server role) computes it the same way libwebsockets does at
/// `server-ws.c:687`.
///
/// The SHA-1 is openssl's. It is RFC 6455-mandated and non-security (a
/// handshake tag, not a secret), so if a FIPS-hardened OpenSSL ever
/// refuses SHA-1 and breaks this, the fix is a FIPS-agnostic pure-Rust
/// sha1 here rather than libcrypto - see the `openssl` dep in `Cargo.toml`.
pub fn accept_for(key: &str) -> String {
    let mut seed = Vec::with_capacity(key.len() + ACCEPT_GUID.len());
    seed.extend_from_slice(key.as_bytes());
    seed.extend_from_slice(ACCEPT_GUID);
    openssl::base64::encode_block(&openssl::sha::sha1(&seed))
}

/// Why a WebSocket upgrade was refused.
#[derive(Debug)]
#[non_exhaustive]
pub enum HandshakeError {
    /// The endpoint answered a status other than `101 Switching
    /// Protocols` - the status line is the diagnosis (a `404` names a
    /// wrong endpoint path, a `400` a rejected upgrade).
    NotSwitching {
        /// The HTTP status code.
        status: u16,
        /// The reason phrase, when the head carried one.
        reason: String,
    },
    /// The `101` head did not carry `Upgrade: websocket` +
    /// `Connection: upgrade`.
    NotUpgraded,
    /// `Sec-WebSocket-Accept` was absent or did not match the digest of
    /// the key this connection sent - the peer did not parse our
    /// handshake.
    BadAccept,
    /// The head was not parseable HTTP.
    NotHttp,
    /// (Server side) the request was not a `GET` carrying
    /// `Upgrade: websocket` + `Connection: upgrade`.
    NotUpgradeRequest,
    /// (Server side) the request carried no `Sec-WebSocket-Key`.
    MissingKey,
    /// (Server side) `Sec-WebSocket-Version` was not `13`.
    BadVersion,
    /// The `101` selected an extension or subprotocol this client never
    /// offered - RFC 6455 §4.1 items 5 and 6 make either one fatal, and
    /// [`upgrade_request`] offers neither, so any value at all is
    /// unrequested. `header` names which one.
    Unrequested {
        /// `Sec-WebSocket-Extensions` or `Sec-WebSocket-Protocol`.
        header: &'static str,
        /// What the server put there, for the diagnosis.
        value: String,
    },
    /// A header the handshake allows at most once appeared twice. Not
    /// `MissingKey`/`BadVersion`/`BadAccept`: the field is present, and
    /// twice is a different failure from absent or wrong.
    DuplicateHeader {
        /// Which one, canonically spelled.
        header: &'static str,
    },
    /// The endpoint is not a request-target that can go in a request line
    /// (see [`validate_request_target`]).
    BadTarget {
        /// The offending endpoint, escaped, for the diagnosis.
        value: String,
    },
}

impl std::fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotSwitching { status, reason } => {
                write!(f, "endpoint answered {status} {reason}, not 101")
            }
            Self::NotUpgraded => {
                f.write_str("101 head carried no websocket upgrade")
            }
            Self::BadAccept => {
                f.write_str("Sec-WebSocket-Accept did not match our key")
            }
            Self::NotHttp => f.write_str("response head was not HTTP"),
            Self::NotUpgradeRequest => {
                f.write_str("request was not a GET websocket upgrade")
            }
            Self::MissingKey => {
                f.write_str("request carried no Sec-WebSocket-Key")
            }
            Self::BadVersion => f.write_str("Sec-WebSocket-Version was not 13"),
            Self::Unrequested { header, value } => {
                write!(f, "server selected {header}: {value}, never offered")
            }
            Self::DuplicateHeader { header } => {
                write!(f, "{header} appeared more than once")
            }
            Self::BadTarget { value } => {
                write!(f, "endpoint is not a usable request-target: {value}")
            }
        }
    }
}

impl std::error::Error for HandshakeError {}

/// Whether a list-valued header field carries `token`, case-insensitively.
///
/// **Only `Connection` gets this.** RFC 6455 §4.1 words its two upgrade
/// checks differently and means it: the `Connection` field "doesn't
/// contain a token that is an ASCII case-insensitive match for the value
/// `Upgrade`" - a token search - while `Upgrade` is failed when it
/// "contains a value that is not an ASCII case-insensitive match for the
/// value `websocket`", which is an equality test on the whole field.
/// Two references draw the same line. libwebsockets' client tokenizes
/// `Connection` with `LWS_TOKENIZE_F_COMMA_SEP_LIST` and runs a plain
/// `strcmp(p, "websocket")` over `Upgrade` (`lib/roles/ws/client-ws.c`);
/// Python `websockets` flattens every `Connection` field line and asks
/// `any(== "upgrade")`, then requires `len(upgrade) == 1 and upgrade[0]
/// == "websocket"` (`websockets/server.py`). Handing `Upgrade` a token
/// search would accept `Upgrade: h2c, websocket`, which both refuse.
///
/// `websocket-client` - the library the canonical TrueNAS Python client
/// is built on - is the outlier: it treats both as token lists
/// (`_handshake.py`'s `_HEADERS_TO_CHECK`) and would accept that. It is
/// also the least strict of the three, and RFC 6455 §4.1's own wording
/// is the equality one, so the strict reading wins here.
///
/// A sender may still split `Connection` across field lines of the same
/// name; RFC 9110 §5.3 says combining them does not change the meaning,
/// so `|=`-ing this over every matching line is the combined search.
///
/// A non-UTF-8 value carries no token rather than poisoning the scan: it
/// cannot equal one, and the verdict is decided by whether the tokens
/// that matter were found at all.
fn has_token(value: &[u8], token: &str) -> bool {
    std::str::from_utf8(value).is_ok_and(|v| {
        v.split(',').any(|t| t.trim().eq_ignore_ascii_case(token))
    })
}

/// Validate a server's `101` upgrade response against the `key` this
/// connection sent (RFC 6455 §4.2.2 / §4.1, the checks libwebsockets'
/// client runs at `lib/roles/ws/client-ws.c`): the status is `101`,
/// `Upgrade`/`Connection` carry the websocket tokens (case-insensitively),
/// and `Sec-WebSocket-Accept` is byte-exactly [`accept_for`]`(key)` (base64
/// is case-sensitive, so only surrounding whitespace is trimmed).
///
/// Two rules bound what else the head may carry. §4.1 items 5 and 6 make a
/// server-selected extension or subprotocol fatal when the client did not
/// offer it, and [`upgrade_request`] offers neither, so a non-empty
/// `Sec-WebSocket-Extensions` or `Sec-WebSocket-Protocol` is always
/// [`HandshakeError::Unrequested`]. That matters here beyond conformance:
/// [`frame_head`] refuses every RSV bit, so an extension accepted at the
/// handshake would surface as an unexplained `Framing::Invalid` on the
/// peer's first extended frame instead of a named handshake failure.
/// §11.3.3 makes `Sec-WebSocket-Accept` appear at most once, and a
/// last-wins scan would let a right value excuse a wrong one behind it, so
/// a second occurrence is [`HandshakeError::BadAccept`].
///
/// `head` is the whole response head through its terminating blank line -
/// what the framer's handshake phase cuts and delivers.
pub fn validate_101(head: &[u8], key: &str) -> Result<(), HandshakeError> {
    let mut slots = [httparse::EMPTY_HEADER; 32];
    let mut resp = httparse::Response::new(&mut slots);
    match resp.parse(head) {
        Ok(httparse::Status::Complete(_)) => {}
        // The framer only delivers a head it saw terminate, so a partial
        // parse here means the bytes were not HTTP.
        Ok(httparse::Status::Partial) | Err(_) => {
            return Err(HandshakeError::NotHttp);
        }
    }
    let status = resp.code.ok_or(HandshakeError::NotHttp)?;
    if status != 101 {
        return Err(HandshakeError::NotSwitching {
            status,
            reason: resp.reason.unwrap_or("").to_owned(),
        });
    }
    let mut upgraded: Option<bool> = None;
    let mut connection = false;
    let mut accept_ok: Option<bool> = None;
    // §11.3.2 and §11.3.4 word these two the same way: each MAY appear
    // multiple times in a *request* and "MUST NOT appear more than once in
    // an HTTP response". They are the two negotiation slots, so they are
    // tracked as two flags rather than a set.
    let mut extensions_seen = false;
    let mut protocol_seen = false;
    for h in resp.headers.iter() {
        if h.name.eq_ignore_ascii_case("upgrade") {
            // Equality, and at most once: two lines cannot combine into a
            // value equal to `websocket`, so a second is a refusal rather
            // than a merge.
            if upgraded.is_some() {
                return Err(HandshakeError::DuplicateHeader {
                    header: "Upgrade",
                });
            }
            upgraded = Some(
                std::str::from_utf8(h.value)
                    .is_ok_and(|v| v.trim().eq_ignore_ascii_case("websocket")),
            );
        } else if h.name.eq_ignore_ascii_case("connection") {
            connection |= has_token(h.value, "upgrade");
        } else if h.name.eq_ignore_ascii_case("sec-websocket-accept") {
            if accept_ok.is_some() {
                return Err(HandshakeError::DuplicateHeader {
                    header: "Sec-WebSocket-Accept",
                });
            }
            accept_ok = Some(
                std::str::from_utf8(h.value)
                    .is_ok_and(|v| v.trim() == accept_for(key)),
            );
        } else if let Some(header) = unrequested_negotiation(h.name) {
            // At most once in a response (§11.3.2, §11.3.4), checked
            // before the value is read: a single *empty* line selects
            // nothing and is tolerated, so without this a server could
            // send two of them and neither would be refused - the one
            // repeat rule in the handshake with no arm here.
            let seen = if header == "Sec-WebSocket-Extensions" {
                &mut extensions_seen
            } else {
                &mut protocol_seen
            };
            if std::mem::replace(seen, true) {
                return Err(HandshakeError::DuplicateHeader { header });
            }
            // §4.1 items 5 and 6. An empty value selects nothing, so only a
            // populated one is a selection.
            let value = String::from_utf8_lossy(h.value).trim().to_owned();
            if !value.is_empty() {
                return Err(HandshakeError::Unrequested { header, value });
            }
        }
    }
    if upgraded != Some(true) || !connection {
        return Err(HandshakeError::NotUpgraded);
    }
    if accept_ok != Some(true) {
        return Err(HandshakeError::BadAccept);
    }
    Ok(())
}

/// The canonical name of a negotiation header this client never offers, or
/// `None` for anything else. [`upgrade_request`] sends no
/// `Sec-WebSocket-Extensions` and no `Sec-WebSocket-Protocol`, so a server
/// naming either has selected something that was not on offer (RFC 6455
/// §4.1 items 5 and 6, and §9's "A server MUST NOT respond with any
/// extension not requested by the client").
fn unrequested_negotiation(name: &str) -> Option<&'static str> {
    if name.eq_ignore_ascii_case("sec-websocket-extensions") {
        Some("Sec-WebSocket-Extensions")
    } else if name.eq_ignore_ascii_case("sec-websocket-protocol") {
        Some("Sec-WebSocket-Protocol")
    } else {
        None
    }
}

/// Validate a client's `GET` upgrade request and return its
/// `Sec-WebSocket-Key` (the server-direction twin of [`validate_101`], the
/// checks libwebsockets' server runs before it replies `101`): the method
/// is `GET`, `Upgrade`/`Connection` carry the websocket tokens, the key is
/// present, and `Sec-WebSocket-Version` is `13`. The returned key feeds
/// [`upgrade_response`]. `head` is the whole request head through its
/// terminating blank line - what [`ws_server_frame`]'s handshake phase
/// cuts and delivers.
pub fn validate_upgrade_request(head: &[u8]) -> Result<String, HandshakeError> {
    let mut slots = [httparse::EMPTY_HEADER; 32];
    let mut req = httparse::Request::new(&mut slots);
    match req.parse(head) {
        Ok(httparse::Status::Complete(_)) => {}
        Ok(httparse::Status::Partial) | Err(_) => {
            return Err(HandshakeError::NotHttp);
        }
    }
    if req.method != Some("GET") {
        return Err(HandshakeError::NotUpgradeRequest);
    }
    let mut upgraded: Option<bool> = None;
    let mut connection = false;
    let mut version: Option<bool> = None;
    let mut key: Option<String> = None;
    for h in req.headers.iter() {
        if h.name.eq_ignore_ascii_case("upgrade") {
            if upgraded.is_some() {
                return Err(HandshakeError::DuplicateHeader {
                    header: "Upgrade",
                });
            }
            upgraded = Some(
                std::str::from_utf8(h.value)
                    .is_ok_and(|v| v.trim().eq_ignore_ascii_case("websocket")),
            );
        } else if h.name.eq_ignore_ascii_case("connection") {
            connection |= has_token(h.value, "upgrade");
        } else if h.name.eq_ignore_ascii_case("sec-websocket-version") {
            // A singleton, and refused rather than overwritten for the
            // same reason as the key below: a second line would decide a
            // verdict the first line already gave.
            if version.is_some() {
                return Err(HandshakeError::DuplicateHeader {
                    header: "Sec-WebSocket-Version",
                });
            }
            version = Some(
                std::str::from_utf8(h.value).is_ok_and(|v| v.trim() == "13"),
            );
        } else if h.name.eq_ignore_ascii_case("sec-websocket-key") {
            // The nonce is what the `101` proves possession of, so a
            // repeated one is not a merge question - it is two different
            // claims about which value the peer chose. Taking the last
            // makes this endpoint compute `accept_for` over a nonce the
            // client need never have sent, which is the whole thing the
            // digest exists to rule out. Refuse instead of picking.
            if key.is_some() {
                return Err(HandshakeError::DuplicateHeader {
                    header: "Sec-WebSocket-Key",
                });
            }
            key = Some(
                std::str::from_utf8(h.value)
                    .map(|v| v.trim().to_owned())
                    .unwrap_or_default(),
            );
        }
    }
    let version_ok = version.unwrap_or(false);
    if upgraded != Some(true) || !connection {
        return Err(HandshakeError::NotUpgradeRequest);
    }
    if !version_ok {
        return Err(HandshakeError::BadVersion);
    }
    key.filter(|k| !k.is_empty())
        .ok_or(HandshakeError::MissingKey)
}

/// The `101 Switching Protocols` response answering an upgrade whose
/// `Sec-WebSocket-Key` was `key` (the server side of the handshake): it
/// carries `Sec-WebSocket-Accept: `[`accept_for`]`(key)`, which is what
/// the client's [`validate_101`] checks.
pub fn upgrade_response(key: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(130);
    out.extend_from_slice(b"HTTP/1.1 101 Switching Protocols\r\n");
    out.extend_from_slice(b"Upgrade: websocket\r\nConnection: Upgrade\r\n");
    out.extend_from_slice(b"Sec-WebSocket-Accept: ");
    out.extend_from_slice(accept_for(key).as_bytes());
    out.extend_from_slice(b"\r\n\r\n");
    out
}

/// A fresh `Sec-WebSocket-Key`: 16 random bytes, base64-encoded (§4.1).
pub fn ws_key() -> String {
    let mut raw = [0u8; 16];
    getrandom_exact(&mut raw);
    openssl::base64::encode_block(&raw)
}

/// A fresh 4-byte frame mask (§5.3 wants it unpredictable per frame).
pub fn mask_key() -> [u8; 4] {
    let mut raw = [0u8; 4];
    getrandom_exact(&mut raw);
    raw
}

/// Fill `buf` from `getrandom(2)`, retrying `EINTR` and short reads.
///
/// Any other failure panics: on this crate's kernel floor the call cannot
/// fail for a small already-mapped buffer, and a client that cannot mask
/// cannot speak the protocol at all.
fn getrandom_exact(buf: &mut [u8]) {
    let mut done = 0;
    while done < buf.len() {
        // SAFETY: the pointer/length name the unfilled tail of a live,
        // writable buffer; getrandom writes at most that many bytes.
        let n = unsafe {
            libc::getrandom(
                buf[done..].as_mut_ptr().cast(),
                buf.len() - done,
                0,
            )
        };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            panic!("getrandom: {err}");
        }
        done += n as usize;
    }
}

#[cfg(test)]
mod tests {
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
        assert_eq!(
            accept_for("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    /// The client handshake check: a well-formed `101` with the right
    /// accept passes, and each way it can be wrong is refused as itself.
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

    /// Every prefix of every length form answers the exact missing count,
    /// and the full header parses back the declared length. The lengths
    /// cross both extended-form boundaries.
    #[test]
    fn frame_head_is_total_over_prefixes() {
        for &len in &[0usize, 1, 125, 126, 127, 65_535, 65_536, 8 * 1024 * 1024]
        {
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
            assert!(
                matches!(frame_head(&f), HeadVerdict::Invalid(_)),
                "opcode {op:#x}"
            );
        }
        // A fragmented control frame.
        let f = server_frame(false, OP_PING, 0);
        assert!(
            matches!(frame_head(&f), HeadVerdict::Invalid(_)),
            "control FIN=0"
        );
        // A control frame declaring more than 125 bytes - both extended
        // forms. 200 encodes as the 126 indicator; a raw 127 indicator on
        // a control opcode is equally illegal (libwebsockets rejects both
        // at `illegal_ctl_length`, client-parser-ws.c:336-348).
        let f = server_frame(true, OP_CLOSE, 200);
        assert!(
            matches!(frame_head(&f), HeadVerdict::Invalid(_)),
            "control 126-length"
        );
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
        // Non-minimal encodings: a 16-bit form holding a 7-bit value, a
        // 64-bit form holding a 16-bit value.
        let f = [0x80 | OP_TEXT, 126, 0, 125];
        assert!(
            matches!(frame_head(&f), HeadVerdict::Invalid(_)),
            "non-minimal 16"
        );
        let mut f = vec![0x80 | OP_TEXT, 127];
        f.extend_from_slice(&65_535u64.to_be_bytes());
        assert!(
            matches!(frame_head(&f), HeadVerdict::Invalid(_)),
            "non-minimal 64"
        );
        // The 64-bit sign bit (libwebsockets `b63 of length must be
        // zero`, client-parser-ws.c:387-392).
        let mut f = vec![0x80 | OP_TEXT, 127];
        f.extend_from_slice(&(1u64 << 63).to_be_bytes());
        assert!(
            matches!(frame_head(&f), HeadVerdict::Invalid(_)),
            "sign bit"
        );
    }

    /// A well-formed control frame at the size limit is accepted: FIN=1,
    /// payload 0..=125 in the 7-bit form. (The rejection is only the
    /// extended-length forms and FIN=0, tested above.)
    #[test]
    fn frame_head_accepts_well_formed_control_frames() {
        for op in [OP_CLOSE, OP_PING, OP_PONG] {
            for len in [0usize, 2, 125] {
                let f = server_frame(true, op, len);
                match frame_head(&f) {
                    HeadVerdict::Done(h) => {
                        assert!(h.fin);
                        assert_eq!(h.opcode, op);
                        assert_eq!(
                            h.header_len, 2,
                            "control uses the 7-bit form"
                        );
                        assert_eq!(h.payload_len, len);
                    }
                    other => panic!("op {op:#x} len {len}: {other:?}"),
                }
            }
        }
    }

    /// The handshake phase: idle park on empty, in-message on a begun
    /// head, an exact cut at the blank line (bytes past it left for the
    /// frame phase), and the head cap.
    #[test]
    fn handshake_phase_cuts_the_head_exactly() {
        let mut st = WsState::default();
        assert_eq!(ws_frame(b"", &mut st), Framing::More);
        assert_eq!(
            ws_frame(b"HTTP/1.1 101 Switching Protocols\r\nUpg", &mut st),
            Framing::MoreInMessage
        );
        // Split *inside* the terminator: still mid-message.
        let head =
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n";
        assert_eq!(
            ws_frame(&head[..head.len() - 1], &mut st),
            Framing::MoreInMessage
        );
        // The full head with a coalesced first frame behind it: the cut is
        // the head alone, and the phase flips.
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

    /// A non-101 head is still delivered - the session reports the status
    /// line - and junk that never terminates is refused at the cap.
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

    /// The frame phase: idle `Need(2)` on empty, exact in-message asks on
    /// a begun header, `Complete` splitting header from payload - the
    /// empty-payload control frame included (`frame_step` refuses only a
    /// zero-length *message*, and header_len is never zero here).
    #[test]
    fn frame_phase_asks_exactly() {
        let mut st = WsState {
            phase: Phase::Frames,
        };
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

    /// Encoding picks the minimal length form at each boundary, masks the
    /// payload, and round-trips: unmasking by hand recovers the payload,
    /// and the header parses (as a client frame it must carry MASK, which
    /// the server-side parser rejects - asserted as the negative).
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
                127 => (
                    10,
                    u64::from_be_bytes(f[2..10].try_into().unwrap()) as usize,
                ),
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
            // The server-side parser refuses it - client frames are not
            // server frames.
            assert!(matches!(frame_head(&f), HeadVerdict::Invalid(_)));
        }
    }

    /// The upgrade request is byte-exact: the head middlewared's aiohttp
    /// route has been accepting from the reference client.
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

    /// Keys and masks draw fresh entropy: two draws differing is the
    /// cheapest observable that the plumbing is wired at all (a collision
    /// is 2^-128 / 2^-32 - the latter would flake once per four billion
    /// runs, which is acceptable for what it buys).
    #[test]
    fn keys_are_fresh() {
        assert_ne!(ws_key(), ws_key());
        let key = ws_key();
        assert_eq!(key.len(), 24, "16 bytes base64-encode to 24 chars");
        assert!(key.ends_with("=="), "16 bytes pad with ==");
    }

    /// The server direction inverts the mask rule: `server_frame_head`
    /// *requires* the client mask bit (libwebsockets' server refuses an
    /// unmasked client frame, `ops-ws.c:270-276`) and folds the 4-byte key
    /// into `header_len`, while `frame_head` still refuses a masked one.
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
        assert!(matches!(
            server_frame_head(&unmasked),
            HeadVerdict::Invalid(_)
        ));
    }

    /// A client frame round-trips through the server path: encode masked,
    /// parse the header, and `unmask` recovers the payload from the key in
    /// the delivered header. Every extended-length form.
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

    /// The server framer cuts the client's GET upgrade head, then masked
    /// frames - the twin of the client framer's phases.
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

    /// The server handshake: a well-formed GET upgrade yields its key, and
    /// upgrade_response answers the accept the client will check; each way
    /// the request can be wrong is refused as itself.
    #[test]
    fn validate_upgrade_request_reads_the_key_and_refuses_bad_requests() {
        let good = b"GET /api/current HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
        let key = validate_upgrade_request(good).expect("a valid upgrade");
        assert_eq!(key, "dGhlIHNhbXBsZSBub25jZQ==");
        // The 101 the server would send round-trips through the client's
        // own validator (server accept == what the client expects).
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

    /// A client masks *every* frame it sends, control frames included -
    /// libwebsockets applies the mask block unconditionally on the client
    /// role (ops-ws.c:2008-2025, not opcode-gated). So a close/ping/pong
    /// carries the mask bit and its (tiny) payload is masked too.
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
            let got: Vec<u8> = f[6..]
                .iter()
                .enumerate()
                .map(|(i, b)| b ^ mask[i % 4])
                .collect();
            assert_eq!(got, payload, "payload unmasks to the original");
        }
    }

    /// The two rules a repeated header field gets, and which one each
    /// slot takes.
    ///
    /// `Upgrade` and `Connection` are comma-separated lists, so splitting
    /// one across field lines means what the joined list means (RFC 9110
    /// §5.3) and a validator must look in all of them. The nonce and the
    /// version are single claims: a second line is not more of the same
    /// value, it is a different answer, and taking the last would let a
    /// peer choose which of two nonces this endpoint proves.
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
        // `Upgrade` is NOT a token search. RFC 6455 sec. 4.1 fails a 101
        // whose Upgrade "contains a value that is not an ASCII
        // case-insensitive match for the value websocket", and
        // libwebsockets' client is a plain `strcmp` (client-ws.c). A
        // token search here would accept this; both refuse it.
        let head = format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: h2c, websocket\r\n\
             Connection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n",
            accept_for(key)
        );
        assert!(
            matches!(
                validate_101(head.as_bytes(), key),
                Err(HandshakeError::NotUpgraded)
            ),
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
            validate_upgrade_request(combined.as_bytes())
                .ok()
                .as_deref(),
            Some("abc"),
        );

        // --- singletons: a second line is refused, not preferred ---
        let two_keys =
            req("Connection: Upgrade\r\nSec-WebSocket-Key: attacker\r\n\
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
        // --- the two negotiation slots, which §11.3.2 and §11.3.4 also
        // --- cap at one per response. An *empty* one selects nothing and
        // --- is tolerated, so the repeat is the only thing to catch.
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

        // The request direction needs the `Upgrade` duplicate rule too -
        // the response-direction case above does not exercise this
        // validator.
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

    /// An endpoint reaches the wire inside `request-line = method SP
    /// request-target SP HTTP-version CRLF` (RFC 9112 §3), so a target
    /// carrying CR, LF or a space does not lengthen that line - it ends
    /// it, and what follows is read as a header field or a second
    /// request. The screen is what keeps a configured endpoint from
    /// forging either.
    #[test]
    fn a_request_target_that_would_split_the_request_is_refused() {
        for good in [
            "/",
            "/api/current",
            "/api/v26.0.0",
            "/api/current?x=1&y=%20",
            "/a/b/c#frag",
        ] {
            assert!(
                validate_request_target(good).is_ok(),
                "{good:?} must be accepted"
            );
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
                matches!(
                    validate_request_target(bad),
                    Err(HandshakeError::BadTarget { .. })
                ),
                "{bad:?} must be refused"
            );
            assert!(
                upgrade_request(bad, "AAAA").is_err(),
                "{bad:?} must not reach a request line"
            );
        }
        // The screen is the whole defence, so pin what it defends: one
        // request line, five headers, and the blank line that ends the
        // head - seven CRLFs and no more.
        let req = upgrade_request("/api/current", "AAAA").unwrap();
        assert!(req.starts_with(b"GET /api/current HTTP/1.1\r\n"));
        assert_eq!(
            req.windows(2).filter(|w| w == b"\r\n").count(),
            7,
            "the head is a request line, five headers and a blank line"
        );
    }

    /// §4.1 items 5 and 6: this client offers no extension and no
    /// subprotocol, so a `101` selecting either is fatal - and it must be,
    /// because `frame_head` refuses the RSV bits a negotiated extension
    /// would then set. §11.3.3: `Sec-WebSocket-Accept` at most once, so a
    /// right value behind a wrong one does not excuse it.
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
        assert!(
            validate_101(head("").as_bytes(), key).is_ok(),
            "the control"
        );
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
            validate_101(head("Sec-WebSocket-Protocol: \r\n").as_bytes(), key)
                .is_ok(),
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

    /// §7.4.1's send bound, and the echo it produces. The reserved values
    /// an endpoint MUST NOT set never reach the wire; a sendable code is
    /// passed through unchanged.
    #[test]
    fn close_echo_refuses_the_codes_no_endpoint_may_send() {
        // 1012, 1013 and 1014 are the IANA registrations §7.4.2 provides
        // for and are the reason this bound is not the RFC's own 1007-1011:
        // without them here, narrowing the range back to `1007..=1011`
        // passes every test in both workspaces.
        for code in [
            1000u16, 1001, 1002, 1003, 1007, 1011, 1012, 1013, 1014, 3000, 4999,
        ] {
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
}
