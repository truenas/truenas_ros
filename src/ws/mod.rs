//! RFC 6455 WebSocket, as a codec over the [`net`](crate::net) protocol seam - the WebSocket analogue of the `http`
//! codec, and like it a codec rather than a server.
//!
//! A WebSocket connection speaks three shapes in sequence: one HTTP upgrade request, one HTTP response head, then RFC
//! 6455 frames. This module owns all three as *pure* pieces for both directions and does no I/O and no dispatch.
//! [`ws_frame`] frames a `net::client` connection and [`ws_server_frame`] a `net::server` one.
//!
//! What a frame *means*, from request and response to the ping and close disciplines and continuation reassembly, is
//! the consumer's. A framer cannot send, so every frame, control frames included, is delivered whole and answered from
//! the pump.
//!
//! §5.1's mask rule is the only asymmetry between the directions. Behaviour is checked against libwebsockets
//! (`/CODE/libwebsockets`), and this parser is stricter than its client on purpose.
//!
//! - **Any RSV bit is refused**, since this crate negotiates no extension. lws-client accepts RSV2/3 with
//!   permessage-deflate on (`client-parser-ws.c:281-290`).
//! - **A non-minimal length is refused**, as RFC 6455 §5.2 requires the minimal form. lws-client does not check.
//! - **UTF-8 is not validated here.** lws-client validates it only when the context opts in
//!   (`client-parser-ws.c:228-231`). RFC 6455 §8.1 requires *failing the connection* on invalid UTF-8, so each
//!   consumer must screen text frames itself. A role that leaves it to a JSON decode answers an invalid-UTF-8 frame as
//!   bad JSON instead of failing.

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

/// The GUID §1.3 fixes for the accept digest (libwebsockets `client-ws.c:217`, `server-ws.c:687`).
const ACCEPT_GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// §7.4.1's 1002: the connection is ending because of a protocol error.
pub const CLOSE_PROTOCOL_ERROR: u16 = 1002;
/// §7.4.1's 1007: data inside a message was inconsistent with the message type - non-UTF-8 where §5.6/§5.5.1 require
/// UTF-8.
pub const CLOSE_INVALID_PAYLOAD: u16 = 1007;

/// Bound on the HTTP response head. A 101 is a few hundred bytes; anything that reaches this without a blank line is
/// not a WebSocket handshake.
const MAX_HEAD: usize = 16 * 1024;

/// One parsed frame header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameHead {
    /// Whether this frame ends its message (`FIN`).
    pub fin: bool,
    /// The 4-bit opcode.
    pub opcode: u8,
    /// Header length in bytes: 2, 4, or 10 for an unmasked (server->client) frame, plus 4 for the masking key on a
    /// masked (client->server) one, so 6, 8, or 14.
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

/// Parse a **server -> client** frame header (the peer must not mask; RFC §5.1) from the front of `buf`. This is the
/// client-direction parse; a ws server reading client frames uses [`server_frame_head`].
///
/// Total over any prefix. Short input is `Incomplete` with an exact byte count, since a `MSG_WAITALL` read can still
/// complete short on EOF and re-entry with fewer bytes than asked must re-answer. Every protocol violation §5 lets a
/// client detect is `Invalid`, namely a MASK bit (§5.1), a RSV bit (§5.2), a reserved opcode, a fragmented or over-long
/// control frame (§5.5), and a non-minimal or sign-bit extended length (§5.2).
pub fn frame_head(buf: &[u8]) -> HeadVerdict {
    parse_head(buf, false)
}

/// Parse a **client -> server** frame header (the peer MUST mask; RFC §5.1) from the front of `buf` - the
/// server-direction twin of [`frame_head`]. The 4-byte masking key is part of the header, so a masked header is 6, 8,
/// or 14 bytes and [`FrameHead::header_len`] includes it; the payload arrives masked and is recovered with [`unmask`].
/// Every other rejection is identical to [`frame_head`], only the mask rule inverts (an *unmasked* client frame is
/// refused, matching libwebsockets' server `client unmasked`, `ops-ws.c:270-276`).
pub fn server_frame_head(buf: &[u8]) -> HeadVerdict {
    parse_head(buf, true)
}

/// The shared frame-header parse. `require_mask` selects the direction: `false` refuses a masked frame (client reading
/// the server), `true` requires it and folds the 4-byte key into `header_len` (server reading a client). Everything
/// else - RSV, opcode, control-frame and extended-length rules - is direction-neutral.
fn parse_head(buf: &[u8], require_mask: bool) -> HeadVerdict {
    if buf.len() < 2 {
        return HeadVerdict::Incomplete { need: 2 - buf.len() };
    }
    let (b0, b1) = (buf[0], buf[1]);
    if b0 & 0x70 != 0 {
        return HeadVerdict::Invalid("RSV bits set with no extension");
    }
    let fin = b0 & 0x80 != 0;
    let opcode = b0 & 0x0F;
    if !matches!(opcode, OP_CONT | OP_TEXT | OP_BINARY | OP_CLOSE | OP_PING | OP_PONG) {
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
                return HeadVerdict::Incomplete { need: 4 - buf.len() };
            }
            let n = usize::from(u16::from_be_bytes([buf[2], buf[3]]));
            if n < 126 {
                return HeadVerdict::Invalid("non-minimal 16-bit length");
            }
            (4, n)
        }
        127 => {
            if buf.len() < 10 {
                return HeadVerdict::Incomplete { need: 10 - buf.len() };
            }
            let n = u64::from_be_bytes([buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8], buf[9]]);
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
    // A masked header carries the 4-byte key after the length; the whole header must be buffered before the payload
    // extent is known to the reactor.
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

/// Recover a masked client frame's payload in place, using the 4-byte key at the tail of its `header` - the header
/// [`server_frame_head`] framed, and only that.
///
/// **This is not a no-op on an unmasked header, and cannot be made one.** An unmasked header is 2, 4 or 10 bytes (RFC
/// 6455 §5.2), so the last four bytes of a 4- or 10-byte one are its own length field and XORing with them silently
/// corrupts the payload. A 2-byte one trips the plain `assert!` below, in release too. Server-to-client frames are
/// never masked (§5.3), which is why [`frame_head`]'s output must not be passed here.
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

/// Whether `code` may be *sent* as a Close frame status code (RFC 6455 §7.4.1, §7.4.2), which is 1000-1003, 1007-1014
/// and 3000-4999. 1004, 1005, 1006 and 1015 are reserved values §7.4.1 says an endpoint MUST NOT set, and the rest
/// carry no meaning to send.
///
/// A receiver reports whatever code a peer sent. This bounds only what goes back out, which is why the close
/// discipline calls [`close_echo_code`] and not this.
pub fn is_sendable_close_code(code: u16) -> bool {
    // 1012-1014 appear nowhere in RFC 6455. They are later IANA registrations, which §7.4.2 provides for, so they are
    // sendable and echoable.
    //
    // **This diverges from libwebsockets**, whose peer-close arm in `ops-ws.c` rewrites 1012, 1013 and 1014 to 1002.
    // aiohttp's `ALLOWED_CLOSE_CODES` (`aiohttp/_websocket/models.py`) and Python `websockets`' `EXTERNAL_CLOSE_CODES`
    // (`websockets/frames.py`) take this range, and rewriting a peer's 1013 "try again later" to 1002 would answer a
    // graceful retry request with a protocol error.
    matches!(code, 1000..=1003 | 1007..=1014 | 3000..=4999)
}

/// The status code to answer a peer's close frame with, given its whole close body: §5.5.1 has the endpoint echo the
/// code it received, and §7.4.1 bounds which codes it may put on the wire, so this is the echo with that bound applied.
///
/// - No body: `None` - answer with no body either.
/// - A one-byte body: [`CLOSE_PROTOCOL_ERROR`]. §5.5.1 - "If there is a body, the first two bytes of the body MUST be a
///   2-byte unsigned integer" - so one byte is a malformed frame, not a code.
/// - A code [`is_sendable_close_code`] refuses: [`CLOSE_PROTOCOL_ERROR`], because reflecting it would be this endpoint
///   setting it.
/// - A reason that is not valid UTF-8: [`CLOSE_INVALID_PAYLOAD`] (§5.5.1 makes /reason/ UTF-8; §8.1 makes an invalid
///   stream fatal).
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
    /// Before the HTTP response head has been cut: the upgrade is out, the `101` (or a refusal) is inbound.
    #[default]
    Handshake,
    /// WebSocket frames.
    Frames,
}

/// Per-connection framer state: the phase, and nothing else. Everything stateful about *messages* (fragment reassembly,
/// close progress) belongs to the session, which sees every frame this framer cuts.
#[derive(Clone, Copy, Debug, Default)]
pub struct WsState {
    phase: Phase,
}

/// The `net::client` reply framer for a WebSocket connection.
///
/// It first delivers the whole HTTP response head as a message with no body, a non-101 head included, so the consumer
/// can report the status line rather than a bare close. Bytes past the head stay buffered for the frame phase. Each
/// frame is then delivered as `Event::Reply` with the raw frame header and the payload as body, and the consumer
/// re-parses the header with [`frame_head`] for FIN and opcode.
///
/// Each frame is its own delivery, so a server that stalls after a non-final frame is clocked as idle rather than
/// mid-message. Reassembly and its bound are the consumer's.
pub fn ws_frame(buf: &[u8], st: &mut WsState) -> Framing {
    match st.phase {
        Phase::Handshake => head_step(buf, st),
        Phase::Frames => frame_step(buf, frame_head),
    }
}

/// The `net::server` reply framer for a WebSocket connection, the twin of [`ws_frame`]. It cuts the client's `GET`
/// upgrade head the same way, then parses masked client frames with [`server_frame_head`], so the delivered header
/// carries the 4-byte key and the body arrives masked (recover it with [`unmask`]).
pub fn ws_server_frame(buf: &[u8], st: &mut WsState) -> Framing {
    match st.phase {
        Phase::Handshake => head_step(buf, st),
        Phase::Frames => frame_step(buf, server_frame_head),
    }
}

/// The handshake phase, shared by both framers. The head's blank line is the one delimiter of unknown position this
/// protocol has, so the `More` family is right here and only here.
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

/// The frame phase, parameterized by the direction's header parser. Every frame declares its length in its first
/// 2..=14 bytes, so it never answers `More`, whose chunked re-scan suits only the head. An empty buffer answers
/// `Need(2)`, since between messages the connection is parked idle (the [`Framing::Need`] contract), and a begun header
/// answers `NeedInMessage` so the receive clock covers the rest.
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

/// Encode one **client -> server** frame: FIN always set (the outbound size guard keeps every message in one frame),
/// minimal length form, and the §5.3 mask applied. A fresh mask per frame comes from [`mask_key`].
pub fn encode_frame(opcode: u8, payload: &[u8], mask: [u8; 4]) -> Vec<u8> {
    encode(opcode, payload, Some(mask))
}

/// Encode one **server -> client** frame - the twin of [`encode_frame`], unmasked (RFC §5.1: a server MUST NOT mask).
pub fn encode_server_frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
    encode(opcode, payload, None)
}

/// The shared frame encoder. `mask` present masks the payload and sets the mask bit (client direction); absent leaves
/// it clear (server direction).
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

/// Bound on an endpoint. A request-target this long is not a mistake anyone makes by hand, and the request line has to
/// fit a head the peer will read.
const MAX_TARGET: usize = 2048;

/// Whether `endpoint` may be spliced into a request line: non-empty, no longer than 2048 bytes, beginning with `/`, and
/// every byte a visible ASCII character.
///
/// A CR, LF or space in a target ends the request line (RFC 9112 §3), and what follows is read as a header field or a
/// second request. Refusing every byte outside `0x21..=0x7E` also keeps the target to US-ASCII (RFC 9110 §4.1). This
/// bounds shape only and is not a URI parser.
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

/// The upgrade request for `endpoint` (e.g. `/api/current`), carrying `key` as `Sec-WebSocket-Key`.
///
/// `endpoint` goes into the request line verbatim, so it is screened by [`validate_request_target`] here and refused
/// rather than spliced. The screen is the whole defence against request splitting, so no caller may be able to skip
/// it. `key` is minted by [`ws_key`] and is base64 by construction.
///
/// `Host: localhost` is what the reference Python client sends over the unix socket, so every server accepts it.
pub fn upgrade_request(endpoint: &str, key: &str) -> Result<Vec<u8>, HandshakeError> {
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

/// The `Sec-WebSocket-Accept` value that proves the peer parsed `key`: base64 of SHA-1 over the key with §1.3's GUID
/// appended, as libwebsockets computes it at `server-ws.c:687`. Compared byte-exact, since base64 is case-sensitive,
/// after trimming optional whitespace around the header value.
pub fn accept_for(key: &str) -> String {
    let mut seed = Vec::with_capacity(key.len() + ACCEPT_GUID.len());
    seed.extend_from_slice(key.as_bytes());
    seed.extend_from_slice(ACCEPT_GUID);
    // This SHA-1 is a handshake tag, not a secret. If a FIPS-hardened OpenSSL ever refuses it, the fix is a pure-Rust
    // sha1 here rather than more libcrypto (see the `openssl` dep in `Cargo.toml`).
    openssl::base64::encode_block(&openssl::sha::sha1(&seed))
}

/// Why a WebSocket upgrade was refused.
#[derive(Debug)]
#[non_exhaustive]
pub enum HandshakeError {
    /// The endpoint answered a status other than `101 Switching Protocols` - the status line is the diagnosis (a `404`
    /// names a wrong endpoint path, a `400` a rejected upgrade).
    NotSwitching {
        /// The HTTP status code.
        status: u16,
        /// The reason phrase, when the head carried one.
        reason: String,
    },
    /// The `101` head did not carry `Upgrade: websocket` + `Connection: upgrade`.
    NotUpgraded,
    /// `Sec-WebSocket-Accept` was absent or did not match the digest of the key this connection sent - the peer did not
    /// parse our handshake.
    BadAccept,
    /// The head was not parseable HTTP.
    NotHttp,
    /// (Server side) the request was not a `GET` carrying `Upgrade: websocket` + `Connection: upgrade`.
    NotUpgradeRequest,
    /// (Server side) the request carried no `Sec-WebSocket-Key`.
    MissingKey,
    /// (Server side) `Sec-WebSocket-Version` was not `13`.
    BadVersion,
    /// The `101` selected an extension or subprotocol this client never offered - RFC 6455 §4.1 items 5 and 6 make
    /// either one fatal, and [`upgrade_request`] offers neither, so any value at all is unrequested. `header` names
    /// which one.
    Unrequested {
        /// `Sec-WebSocket-Extensions` or `Sec-WebSocket-Protocol`.
        header: &'static str,
        /// What the server put there, for the diagnosis.
        value: String,
    },
    /// A header the handshake allows at most once appeared twice. Not `MissingKey`/`BadVersion`/`BadAccept`: the field
    /// is present, and twice is a different failure from absent or wrong.
    DuplicateHeader {
        /// Which one, canonically spelled.
        header: &'static str,
    },
    /// The endpoint is not a request-target that can go in a request line (see [`validate_request_target`]).
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
            Self::NotUpgraded => f.write_str("101 head carried no websocket upgrade"),
            Self::BadAccept => f.write_str("Sec-WebSocket-Accept did not match our key"),
            Self::NotHttp => f.write_str("response head was not HTTP"),
            Self::NotUpgradeRequest => f.write_str("request was not a GET websocket upgrade"),
            Self::MissingKey => f.write_str("request carried no Sec-WebSocket-Key"),
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
/// **Only `Connection` gets this.** RFC 6455 §4.1 fails `Connection` when it lacks an `Upgrade` token, but fails
/// `Upgrade` when it "contains a value that is not an ASCII case-insensitive match for the value `websocket`", an
/// equality test on the whole field. libwebsockets' client (`lib/roles/ws/client-ws.c`) and Python `websockets`
/// (`websockets/server.py`) draw the same line, and a token search on `Upgrade` would accept `Upgrade: h2c, websocket`,
/// which both refuse. `websocket-client` treats both as token lists (`_handshake.py`), but §4.1's wording is the
/// equality one.
///
/// A `Connection` split across field lines means the joined list (RFC 9110 §5.3), so callers `|=` this over every
/// matching line. A non-UTF-8 value carries no token.
fn has_token(value: &[u8], token: &str) -> bool {
    std::str::from_utf8(value).is_ok_and(|v| v.split(',').any(|t| t.trim().eq_ignore_ascii_case(token)))
}

/// Validate a server's `101` upgrade response against the `key` this connection sent (RFC 6455 §4.2.2 / §4.1, the
/// checks libwebsockets' client runs at `lib/roles/ws/client-ws.c`): the status is `101`, `Upgrade`/`Connection` carry
/// the websocket tokens (case-insensitively), and `Sec-WebSocket-Accept` is byte-exactly [`accept_for`]`(key)` (base64
/// is case-sensitive, so only surrounding whitespace is trimmed).
///
/// A non-empty `Sec-WebSocket-Extensions` or `Sec-WebSocket-Protocol` is [`HandshakeError::Unrequested`] (§4.1 items 5
/// and 6), since [`upgrade_request`] offers neither and [`frame_head`] could not frame an extension's RSV bits. A
/// second `Sec-WebSocket-Accept` is [`HandshakeError::DuplicateHeader`] (§11.3.3), so a right value never excuses a
/// wrong one.
///
/// `head` is the whole response head through its terminating blank line, as the framer's handshake phase delivers it.
pub fn validate_101(head: &[u8], key: &str) -> Result<(), HandshakeError> {
    let mut slots = [httparse::EMPTY_HEADER; 32];
    let mut resp = httparse::Response::new(&mut slots);
    match resp.parse(head) {
        Ok(httparse::Status::Complete(_)) => {}
        // The framer only delivers a head it saw terminate, so a partial parse here means the bytes were not HTTP.
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
    // Each "MUST NOT appear more than once in an HTTP response" (§11.3.2, §11.3.4).
    let mut extensions_seen = false;
    let mut protocol_seen = false;
    for h in resp.headers.iter() {
        if h.name.eq_ignore_ascii_case("upgrade") {
            // Equality, and at most once: two lines cannot combine into a value equal to `websocket`, so a second is a
            // refusal rather than a merge.
            if upgraded.is_some() {
                return Err(HandshakeError::DuplicateHeader { header: "Upgrade" });
            }
            upgraded = Some(std::str::from_utf8(h.value).is_ok_and(|v| v.trim().eq_ignore_ascii_case("websocket")));
        } else if h.name.eq_ignore_ascii_case("connection") {
            connection |= has_token(h.value, "upgrade");
        } else if h.name.eq_ignore_ascii_case("sec-websocket-accept") {
            if accept_ok.is_some() {
                return Err(HandshakeError::DuplicateHeader {
                    header: "Sec-WebSocket-Accept",
                });
            }
            accept_ok = Some(std::str::from_utf8(h.value).is_ok_and(|v| v.trim() == accept_for(key)));
        } else if let Some(header) = unrequested_negotiation(h.name) {
            // Checked before the value, since one empty line is tolerated and two would otherwise both pass.
            let seen = if header == "Sec-WebSocket-Extensions" {
                &mut extensions_seen
            } else {
                &mut protocol_seen
            };
            if std::mem::replace(seen, true) {
                return Err(HandshakeError::DuplicateHeader { header });
            }
            // §4.1 items 5 and 6. An empty value selects nothing, so only a populated one is a selection.
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

/// The canonical name of a negotiation header [`upgrade_request`] never offers, or `None` for anything else.
fn unrequested_negotiation(name: &str) -> Option<&'static str> {
    if name.eq_ignore_ascii_case("sec-websocket-extensions") {
        Some("Sec-WebSocket-Extensions")
    } else if name.eq_ignore_ascii_case("sec-websocket-protocol") {
        Some("Sec-WebSocket-Protocol")
    } else {
        None
    }
}

/// Validate a client's `GET` upgrade request and return its `Sec-WebSocket-Key` (the server-direction twin of
/// [`validate_101`], the checks libwebsockets' server runs before it replies `101`): the method is `GET`,
/// `Upgrade`/`Connection` carry the websocket tokens, the key is present, and `Sec-WebSocket-Version` is `13`. The
/// returned key feeds [`upgrade_response`]. `head` is the whole request head through its terminating blank line - what
/// [`ws_server_frame`]'s handshake phase cuts and delivers.
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
                return Err(HandshakeError::DuplicateHeader { header: "Upgrade" });
            }
            upgraded = Some(std::str::from_utf8(h.value).is_ok_and(|v| v.trim().eq_ignore_ascii_case("websocket")));
        } else if h.name.eq_ignore_ascii_case("connection") {
            connection |= has_token(h.value, "upgrade");
        } else if h.name.eq_ignore_ascii_case("sec-websocket-version") {
            // A second line would decide a verdict the first already gave, so it is refused like the key below.
            if version.is_some() {
                return Err(HandshakeError::DuplicateHeader {
                    header: "Sec-WebSocket-Version",
                });
            }
            version = Some(std::str::from_utf8(h.value).is_ok_and(|v| v.trim() == "13"));
        } else if h.name.eq_ignore_ascii_case("sec-websocket-key") {
            // The `101` proves possession of this nonce, so a second one is a different claim. Taking the last would
            // compute `accept_for` over a nonce the client need never have sent, which the digest exists to rule out.
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
    key.filter(|k| !k.is_empty()).ok_or(HandshakeError::MissingKey)
}

/// The `101 Switching Protocols` response answering an upgrade whose `Sec-WebSocket-Key` was `key` (the server side of
/// the handshake): it carries `Sec-WebSocket-Accept: `[`accept_for`]`(key)`, which is what the client's
/// [`validate_101`] checks.
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
/// Any other failure panics: on this crate's kernel floor the call cannot fail for a small already-mapped buffer, and a
/// client that cannot mask cannot speak the protocol at all.
fn getrandom_exact(buf: &mut [u8]) {
    let mut done = 0;
    while done < buf.len() {
        // SAFETY: the pointer/length name the unfilled tail of a live, writable buffer; getrandom writes at most that
        // many bytes.
        let n = unsafe { libc::getrandom(buf[done..].as_mut_ptr().cast(), buf.len() - done, 0) };
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
mod tests;
