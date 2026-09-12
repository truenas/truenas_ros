//! A sans-io JSON-RPC *server* session over the `ws` server codec - the
//! mirror of [`session`](crate::session)'s client half.
//!
//! It is the receiving end of the same protocol the client speaks: it
//! accepts the upgrade (rather than requesting it), reads masked client
//! frames (rather than unmasked server ones), and surfaces inbound
//! *requests* for the application to answer (rather than correlating
//! responses to its own calls). Like the client session it does no I/O: a
//! driver feeds it the request head and unmasked frame payloads, and turns
//! the [`ServerAct`]s it returns into socket writes. `tests/loopback.rs`
//! drives it over a plain `UnixStream`; nothing in the parent crate can,
//! since the dependency runs this way round and `net::server` cannot name
//! a type from here.
//!
//! A driver reads a frame's payload before the session ever sees it, so
//! the inbound bound has to be consulted at the header: ask
//! [`JsonRpcServer::max_message_bytes`] about the frame's declared
//! `payload_len` and refuse the frame rather than allocating what the peer
//! declared.
//!
//! What it deliberately does *not* do is dispatch: which methods exist and
//! what they return is the application's, so a request surfaces as
//! [`ServerAct::Request`] and the app answers with [`JsonRpcServer::reply`]
//! / [`JsonRpcServer::reply_error`], and pushes events with
//! [`JsonRpcServer::notify`]. This is exactly the boundary
//! `truenas_jsonrpc` draws ("no method registry and no dispatch").

use serde::Serialize;
use serde_json::value::RawValue;
use truenas_jsonrpc::{Call, Caller, ErrorObject, Id, Incoming, Response};
use truenas_ros::ws::{
    self, FrameHead, HandshakeError, OP_BINARY, OP_CLOSE, OP_CONT, OP_PING,
    OP_PONG, OP_TEXT,
};

/// The outcome of feeding the server the client's upgrade request head.
#[derive(Debug)]
pub enum ServerStep {
    /// The upgrade is valid; send these `101` bytes, then serve frames.
    Accept(Vec<u8>),
    /// The request was not a valid websocket upgrade; close.
    Reject(HandshakeError),
}

/// What the driver must do after feeding the server one frame.
#[derive(Debug)]
pub enum ServerAct {
    /// Put these bytes on the wire (a pong, a close echo, or an error
    /// response the session built for a malformed request).
    Send(Vec<u8>),
    /// A well-formed request the application must answer, with
    /// [`JsonRpcServer::reply`] / [`JsonRpcServer::reply_error`].
    Request {
        /// The id to answer against.
        id: Id,
        /// The method name.
        method: String,
        /// The unparsed `params`, or `None` when the member was omitted.
        ///
        /// JSON-RPC §4.2 admits either structure, so this is an Array *or*
        /// an Object - middlewared rejects by-name params server-side, and
        /// an application mirroring it should answer `-32602` for an
        /// Object rather than assume an Array.
        params: Option<Box<RawValue>>,
    },
    /// A §4.1 notification from the client (no `id`); it is not answered.
    Notification {
        /// The method name.
        method: String,
        /// The unparsed `params`, or `None`.
        params: Option<Box<RawValue>>,
    },
    /// The client sent a close frame; the echo is queued (a preceding
    /// [`ServerAct::Send`]) - flush it and close.
    PeerClosing,
    /// The client violated the protocol; close and abandon the connection.
    Fault(&'static str),
}

/// Where the server session is in its life.
enum Phase {
    /// Awaiting the client's HTTP upgrade request head.
    AwaitingRequest,
    /// Serving frames.
    Open,
    /// A close frame has been sent; teardown completes at the transport.
    Closing,
}

/// The sans-io JSON-RPC server session.
pub struct JsonRpcServer {
    phase: Phase,
    frag: Option<Vec<u8>>,
    max_inbound: usize,
    close_reason: Option<String>,
}

impl std::fmt::Debug for JsonRpcServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JsonRpcServer").finish_non_exhaustive()
    }
}

impl JsonRpcServer {
    /// A server session bounding a single (possibly reassembled) inbound
    /// message at `max_message_bytes`.
    pub fn new(max_message_bytes: usize) -> JsonRpcServer {
        JsonRpcServer {
            phase: Phase::AwaitingRequest,
            frag: None,
            max_inbound: max_message_bytes,
            close_reason: None,
        }
    }

    /// The inbound message bound this session was built with.
    ///
    /// A driver must check it against a frame's declared `payload_len`
    /// *before* reading the payload: the framer places no ceiling on a
    /// declared length, and by the time [`JsonRpcServer::on_frame`] is
    /// called the bytes have already been allocated.
    pub fn max_message_bytes(&self) -> usize {
        self.max_inbound
    }

    /// Feed the client's upgrade request head (through its blank line, as
    /// the framer's handshake phase cuts it). On success the session moves
    /// to serving frames and the driver must send the returned `101`.
    ///
    /// Valid once: a second call on a session already serving frames is
    /// refused, so a re-sent head cannot move a closing session back to
    /// open.
    pub fn on_head(&mut self, head: &[u8]) -> ServerStep {
        if !matches!(self.phase, Phase::AwaitingRequest) {
            return ServerStep::Reject(HandshakeError::NotUpgradeRequest);
        }
        match ws::validate_upgrade_request(head) {
            Ok(key) => {
                self.phase = Phase::Open;
                ServerStep::Accept(ws::upgrade_response(&key))
            }
            Err(e) => ServerStep::Reject(e),
        }
    }

    /// Feed one complete client frame. `payload` must already be unmasked
    /// (the driver holds the frame header, so it calls
    /// [`ws::unmask`]; client frames are always
    /// masked, unlike the server frames the client session reads).
    pub fn on_frame(
        &mut self,
        head: FrameHead,
        payload: Vec<u8>,
    ) -> Vec<ServerAct> {
        if matches!(self.phase, Phase::AwaitingRequest) {
            return vec![ServerAct::Fault("frame before the upgrade")];
        }
        let closing = matches!(self.phase, Phase::Closing);
        match head.opcode {
            // §5.5.2: a Ping is answered with a Pong "unless it already
            // received a Close frame".
            OP_PING if closing => Vec::new(),
            OP_PING => {
                vec![ServerAct::Send(ws::encode_server_frame(
                    OP_PONG, &payload,
                ))]
            }
            OP_PONG => Vec::new(),
            OP_CLOSE => self.on_close_frame(&payload),
            OP_BINARY => vec![ServerAct::Fault("binary frame")],
            // §5.5.1: "there is no guarantee that the endpoint that has
            // already sent a Close frame will continue to process data",
            // and answering one would put a data frame after our own
            // Close, which the same section forbids. So a message arriving
            // once either side has closed is dropped, not surfaced.
            OP_TEXT | OP_CONT if closing => Vec::new(),
            OP_TEXT if !head.fin => {
                if self.frag.is_some() {
                    return vec![ServerAct::Fault(
                        "new data frame inside a fragmented message",
                    )];
                }
                if payload.len() > self.max_inbound {
                    return vec![ServerAct::Fault(
                        "message exceeds the inbound cap",
                    )];
                }
                self.frag = Some(payload);
                Vec::new()
            }
            OP_TEXT => {
                if self.frag.is_some() {
                    return vec![ServerAct::Fault(
                        "new data frame inside a fragmented message",
                    )];
                }
                if payload.len() > self.max_inbound {
                    return vec![ServerAct::Fault(
                        "message exceeds the inbound cap",
                    )];
                }
                self.on_message(&payload)
            }
            OP_CONT => {
                let Some(mut buf) = self.frag.take() else {
                    return vec![ServerAct::Fault(
                        "continuation with no message open",
                    )];
                };
                if buf.len().saturating_add(payload.len()) > self.max_inbound {
                    return vec![ServerAct::Fault(
                        "fragmented message exceeds the inbound cap",
                    )];
                }
                buf.extend_from_slice(&payload);
                if head.fin {
                    self.on_message(&buf)
                } else {
                    self.frag = Some(buf);
                    Vec::new()
                }
            }
            // `server_frame_head` refuses the reserved opcodes, so a
            // driver that framed this head cannot reach here - but
            // `on_frame` is `pub` and `FrameHead` is a plain struct with
            // public fields and no constructor, so the invariant is
            // asserted about a function the caller need not have used.
            // Fault the session rather than panicking the thread that
            // called us.
            _ => vec![ServerAct::Fault("reserved opcode")],
        }
    }

    /// The reason string for a completed peer close, once
    /// [`ServerAct::PeerClosing`] has been seen.
    pub fn close_reason(&self) -> Option<&str> {
        self.close_reason.as_deref()
    }

    fn on_close_frame(&mut self, payload: &[u8]) -> Vec<ServerAct> {
        // Nothing goes back out once this side has closed: §5.5.1 has an
        // endpoint consider the connection closed after both sending and
        // receiving a Close, so a second Close of ours would be a frame
        // after the handshake finished. This guard sits above the length
        // check because a *malformed* re-close is still a re-close - with
        // the two in the other order a one-byte second body put another
        // Close frame on a connection already closing, while a two-byte
        // one was correctly silent.
        if matches!(self.phase, Phase::Closing) {
            return Vec::new();
        }
        // §5.5.1: "If there is a body, the first two bytes of the body
        // MUST be a 2-byte unsigned integer ... representing a status
        // code". One byte is neither a status code nor an absent body, so
        // it fails the connection instead of completing the handshake.
        // (`server_frame_head` bounds a control frame above, not below.)
        if payload.len() == 1 {
            self.phase = Phase::Closing;
            return vec![
                ServerAct::Send(ws::encode_server_frame(
                    OP_CLOSE,
                    &CLOSE_PROTOCOL_ERROR.to_be_bytes(),
                )),
                ServerAct::Fault("close body shorter than a status code"),
            ];
        }
        let code = (payload.len() >= 2)
            .then(|| u16::from_be_bytes([payload[0], payload[1]]));
        self.phase = Phase::Closing;
        // As in `close`: the message stream ends here, so an unfinished
        // reassembly is released rather than held to the session's own end.
        self.frag = None;
        self.close_reason = Some(match code {
            Some(code) => format!("client closed ({code})"),
            None => "client closed".to_owned(),
        });
        // §5.5.1 says an endpoint "typically echos the status code it
        // received", but §7.4.1 forbids ever *setting* 1005/1006/1015 and
        // §7.4.2 leaves 0-999 unused and above 4999 undefined - so a code
        // this endpoint may not send is answered with 1002 rather than
        // mirrored back onto the wire. `close_echo_code` is the whole
        // discipline, and it also catches the case an open-coded
        // `is_sendable_close_code` test misses: §5.5.1 makes /reason/ UTF-8
        // and §8.1 makes an invalid stream fatal, so a reason that is not
        // UTF-8 is answered 1007 rather than echoed. `None` means the
        // peer sent no body, and the helper documents it as "answer with
        // no body either" - which is what the client role does, so this
        // role does it too rather than inventing a 1000 the peer never
        // sent.
        let echo = match ws::close_echo_code(payload) {
            Some(code) => code.to_be_bytes().to_vec(),
            None => Vec::new(),
        };
        vec![
            ServerAct::Send(ws::encode_server_frame(OP_CLOSE, &echo)),
            ServerAct::PeerClosing,
        ]
    }

    fn on_message(&mut self, text: &[u8]) -> Vec<ServerAct> {
        // RFC 6455 §8.1: a text frame whose payload is not valid UTF-8
        // fails the connection. This is not the same fault as bad JSON -
        // that is a JSON-RPC error, answered `-32700` with the session
        // still serving, which is what middlewared does and what the arms
        // below implement. Only the encoding violation is a *WebSocket*
        // one, and it is the codec's to catch: `ws` declines UTF-8
        // validation on the grounds that `serde_json` rejects non-UTF-8
        // anyway, which is true of *detecting* it and says nothing about
        // what each role then does. The client role reaches `Act::Fault`
        // and closes; this role answered and kept serving, so a peer could
        // stream arbitrarily many invalid-UTF-8 frames on a connection
        // that should have been failed at the first.
        if std::str::from_utf8(text).is_err() {
            self.phase = Phase::Closing;
            self.frag = None;
            return vec![
                ServerAct::Send(ws::encode_server_frame(
                    OP_CLOSE,
                    &CLOSE_INVALID_PAYLOAD.to_be_bytes(),
                )),
                ServerAct::Fault("text frame is not valid UTF-8"),
            ];
        }
        match truenas_jsonrpc::parse(text) {
            Incoming::Single(Call::Valid(req)) => {
                let method = req.method().to_owned();
                let params = req.params().map(|p| p.get().to_owned());
                match req.id() {
                    None => vec![ServerAct::Notification { method, params }],
                    Some(id) => vec![ServerAct::Request {
                        id: id.clone(),
                        method,
                        params,
                    }],
                }
            }
            // A structurally invalid request is answered with §5.1's error
            // against the id it could recover.
            Incoming::Single(Call::Invalid { id, error, .. }) => {
                vec![ServerAct::Send(error_frame(id, error))]
            }
            // middlewared refuses batches, but it does not close over
            // one: `parse_message` raises `ValueError('Batch messages are
            // not supported at this time')`
            // (`middlewared/utils/limits.py`) and the handler answers
            // `-32700` and `continue`s
            // (`api/base/server/ws_handler/rpc.py`). Mirroring it means
            // answering, not faulting - a client that sends a batch by
            // mistake gets an error and keeps its other calls.
            Incoming::Batch(_) => {
                vec![ServerAct::Send(error_frame(
                    Id::Null,
                    not_an_object(text),
                ))]
            }
            // middlewared splits these two by *shape*, not by content,
            // and one step earlier than this codec does. `parse_message`
            // runs before any JSON-RPC validation: it raises for
            // unparseable bytes, for a list, and for anything else
            // without `.get` - and every one of those becomes
            // `-32700` against a null id, after which the handler
            // `continue`s (`middlewared/utils/limits.py`,
            // `api/base/server/ws_handler/rpc.py`). Only a top-level
            // *object* survives to `validate_message`, whose failures are
            // `-32600` against the id it could recover.
            //
            // So the rule is the top-level shape: an object may be
            // `-32600`, and everything else - a bare string, a number,
            // `null`, an array empty or not, or bytes that are not JSON
            // at all - is `-32700`.
            Incoming::Invalid { error, .. } => {
                if text.trim_ascii_start().first() == Some(&b'{') {
                    vec![ServerAct::Send(error_frame(Id::Null, error))]
                } else {
                    vec![ServerAct::Send(error_frame(
                        Id::Null,
                        not_an_object(text),
                    ))]
                }
            }
        }
    }

    /// Build the framed response bytes for a successful call, encoding
    /// `result` once into the `result` member.
    pub fn reply<T: Serialize + ?Sized>(
        &self,
        id: Id,
        result: &T,
    ) -> Result<Vec<u8>, serde_json::Error> {
        let resp = Response::success(id, result)?;
        Ok(ws::encode_server_frame(OP_TEXT, &resp.to_bytes()))
    }

    /// Build the framed response bytes for a failed call.
    pub fn reply_error(&self, id: Id, error: ErrorObject) -> Vec<u8> {
        error_frame(id, error)
    }

    /// Build a framed server->client notification (a §4.1 request with no
    /// `id`, which the client must not answer) - a pushed event.
    pub fn notify<T: Serialize + ?Sized>(
        &self,
        method: &str,
        params: Option<&T>,
    ) -> Result<Vec<u8>, truenas_jsonrpc::BuildError> {
        // A notification mints no id, so a throwaway Caller is stateless
        // here; it is the same envelope middlewared's send_notification
        // builds.
        let bytes = Caller::new().notification(method, params)?;
        Ok(ws::encode_server_frame(OP_TEXT, &bytes))
    }

    /// Begin a local close: the 1000 (normal closure) frame.
    ///
    /// After this the session answers no more requests - §5.5.1 forbids a
    /// data frame after a Close - so an inbound message is dropped rather
    /// than surfaced, and a Ping goes unanswered (§5.5.2).
    ///
    /// **Returns empty when this session has already closed**, because
    /// §5.5.1 forbids sending anything after a Close and that includes a
    /// second Close. The peer's own Close puts the session here too, and it
    /// has already been echoed, so a caller that then closes locally would
    /// otherwise put two Close frames on the wire. `Session::start_close`
    /// guards from the same signature; this is the same rule for the role
    /// whose version of it is public. Write nothing when the answer is
    /// empty.
    pub fn close(&mut self) -> Vec<u8> {
        if matches!(self.phase, Phase::Closing) {
            return Vec::new();
        }
        self.phase = Phase::Closing;
        // Nothing will be reassembled onto this session again; §5.5.1 ends
        // the message stream here, so an open fragment is dead weight.
        self.frag = None;
        ws::encode_server_frame(OP_CLOSE, &CLOSE_NORMAL.to_be_bytes())
    }

    /// Whether a Close frame has been sent or received, so nothing more
    /// may go out on this connection but the flush of what is queued.
    pub fn is_closing(&self) -> bool {
        matches!(self.phase, Phase::Closing)
    }
}

/// RFC 6455 §7.4.1's 1000, normal closure.
const CLOSE_NORMAL: u16 = 1000;

/// RFC 6455 §7.4.1's 1002, "terminating the connection due to a protocol
/// error".
const CLOSE_PROTOCOL_ERROR: u16 = 1002;

/// RFC 6455 §7.4.1's 1007, "data within a message that was not consistent
/// with the type of the message" - a text frame that is not valid UTF-8.
const CLOSE_INVALID_PAYLOAD: u16 = 1007;

/// middlewared's answer to anything that is not a top-level JSON object:
/// `parse_message` raises before any JSON-RPC validation and the handler
/// turns the `ValueError` into `INVALID_JSON` (`-32700`) against a `None`
/// id, then keeps serving (`middlewared/utils/limits.py`,
/// `api/base/server/ws_handler/rpc.py`). Its own text for the list case
/// is kept, since a batch is the shape a client is most likely to send
/// on purpose.
fn not_an_object(text: &[u8]) -> ErrorObject {
    let e = ErrorObject::parse_error();
    if text.trim_ascii_start().first() == Some(&b'[') {
        return e.with_reason("Batch messages are not supported at this time");
    }
    // Well-formed JSON that is simply not an object - a bare string, a
    // number, `true`, `null`. middlewared reaches these through the same
    // `except Exception` and says something different, so this does too:
    // telling a client that sent `"hello"` that batches are unsupported
    // diagnoses the wrong thing.
    if serde_json::from_slice::<serde_json::Value>(text).is_ok() {
        return e.with_reason("Invalid Message Format");
    }
    // Not JSON at all. middlewared forwards the decoder's own message
    // here; ours is the code's standard text rather than an invented one.
    e
}

/// One error-response frame (unmasked server text frame).
fn error_frame(id: Id, error: ErrorObject) -> Vec<u8> {
    ws::encode_server_frame(OP_TEXT, &Response::error(id, error).to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn head(fin: bool, opcode: u8, payload_len: usize) -> FrameHead {
        FrameHead {
            fin,
            opcode,
            header_len: if payload_len < 126 { 6 } else { 8 },
            payload_len,
        }
    }

    /// Decode a server->client frame the session emitted (unmasked) into
    /// (opcode, payload).
    fn decode(f: &[u8]) -> (u8, Vec<u8>) {
        assert!(f[0] & 0x80 != 0, "FIN");
        assert!(f[1] & 0x80 == 0, "server frames are unmasked");
        let (hdr, len) = match f[1] & 0x7f {
            126 => (4, usize::from(u16::from_be_bytes([f[2], f[3]]))),
            127 => (
                10,
                u64::from_be_bytes(f[2..10].try_into().unwrap()) as usize,
            ),
            n => (2, usize::from(n)),
        };
        (f[0] & 0x0f, f[hdr..hdr + len].to_vec())
    }

    /// The client's `GET` upgrade request, verbatim.
    const UPGRADE: &[u8] = b"GET /api/current HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";

    fn open_server() -> JsonRpcServer {
        open_capped(65_536)
    }

    /// An upgraded session bounding an inbound message at `cap`.
    fn open_capped(cap: usize) -> JsonRpcServer {
        let mut s = JsonRpcServer::new(cap);
        let req = UPGRADE;
        match s.on_head(req) {
            ServerStep::Accept(resp) => {
                // The 101 the client's validator accepts.
                assert!(
                    truenas_ros::ws::validate_101(
                        &resp,
                        "dGhlIHNhbXBsZSBub25jZQ=="
                    )
                    .is_ok()
                );
            }
            ServerStep::Reject(e) => panic!("valid upgrade rejected: {e}"),
        }
        s
    }

    #[test]
    fn a_bad_upgrade_is_rejected() {
        let mut s = JsonRpcServer::new(65_536);
        match s.on_head(b"POST /x HTTP/1.1\r\n\r\n") {
            ServerStep::Reject(_) => {}
            ServerStep::Accept(_) => panic!("a POST is not an upgrade"),
        }
    }

    #[test]
    fn a_request_surfaces_and_replies_frame_back() {
        let mut s = open_server();
        let msg =
            br#"{"jsonrpc":"2.0","method":"core.ping","params":[],"id":1}"#;
        let acts = s.on_frame(head(true, OP_TEXT, msg.len()), msg.to_vec());
        let (id, method) = match acts.as_slice() {
            [ServerAct::Request { id, method, params }] => {
                assert_eq!(method, "core.ping");
                assert_eq!(params.as_ref().map(|p| p.get()), Some("[]"));
                (id.clone(), method.clone())
            }
            other => panic!("expected a Request, got {other:?}"),
        };
        assert_eq!(method, "core.ping");
        let frame = s.reply(id, "pong").expect("encode");
        let (op, payload) = decode(&frame);
        assert_eq!(op, OP_TEXT);
        assert_eq!(
            payload,
            br#"{"jsonrpc":"2.0","result":"pong","id":1}"#.to_vec()
        );
    }

    #[test]
    fn a_notification_surfaces_without_an_id() {
        let mut s = open_server();
        let msg = br#"{"jsonrpc":"2.0","method":"tick","params":[1]}"#;
        let acts = s.on_frame(head(true, OP_TEXT, msg.len()), msg.to_vec());
        assert!(
            matches!(acts.as_slice(), [ServerAct::Notification { method, .. }] if method == "tick"),
            "{acts:?}"
        );
    }

    #[test]
    fn a_ping_is_ponged_and_binary_faults() {
        let mut s = open_server();
        match s
            .on_frame(head(true, OP_PING, 2), b"hi".to_vec())
            .as_slice()
        {
            [ServerAct::Send(f)] => {
                assert_eq!(decode(f), (OP_PONG, b"hi".to_vec()))
            }
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            s.on_frame(head(true, OP_BINARY, 1), b"x".to_vec())
                .as_slice(),
            [ServerAct::Fault(_)]
        ));
    }

    #[test]
    fn a_malformed_request_is_answered_with_an_error() {
        let mut s = open_server();
        // Missing `method`: structurally invalid, answered against its id.
        let msg = br#"{"jsonrpc":"2.0","id":7}"#;
        match s
            .on_frame(head(true, OP_TEXT, msg.len()), msg.to_vec())
            .as_slice()
        {
            [ServerAct::Send(f)] => {
                let (op, payload) = decode(f);
                assert_eq!(op, OP_TEXT);
                let v: serde_json::Value =
                    serde_json::from_slice(&payload).unwrap();
                assert_eq!(v["error"]["code"], json!(-32600));
                assert_eq!(v["id"], json!(7));
            }
            other => panic!("expected an error response, got {other:?}"),
        }
    }

    /// `on_frame` is public and `FrameHead` has no constructor, so a
    /// reserved opcode arrives here whatever `server_frame_head` would
    /// have refused. It must fault the session, not panic the caller's
    /// thread.
    #[test]
    fn a_reserved_opcode_faults_rather_than_panicking() {
        for opcode in [0x3, 0x7, 0xB, 0xF] {
            let mut s = open_server();
            match s.on_frame(head(true, opcode, 0), Vec::new()).as_slice() {
                [ServerAct::Fault(why)] => {
                    assert_eq!(*why, "reserved opcode")
                }
                other => panic!("opcode {opcode:#x}: {other:?}"),
            }
        }
    }

    /// The inbound cap bounds every message, not just a reassembled one:
    /// a single over-cap frame and an over-cap first fragment both fault.
    #[test]
    fn the_inbound_cap_bounds_a_single_frame_too() {
        // An *open* session, so a refusal cannot be the pre-handshake
        // fault standing in for the cap.
        let mut s = open_capped(64);
        assert_eq!(s.max_message_bytes(), 64);
        let msg = format!(
            r#"{{"jsonrpc":"2.0","method":"m","params":["{}"],"id":1}}"#,
            "x".repeat(256)
        );
        match s
            .on_frame(head(true, OP_TEXT, msg.len()), msg.into_bytes())
            .as_slice()
        {
            [ServerAct::Fault(why)] => {
                assert_eq!(*why, "message exceeds the inbound cap")
            }
            other => panic!("an over-cap single frame must fault: {other:?}"),
        }

        let mut s = open_capped(64);
        match s
            .on_frame(head(false, OP_TEXT, 256), vec![b'a'; 256])
            .as_slice()
        {
            [ServerAct::Fault(why)] => {
                assert_eq!(*why, "message exceeds the inbound cap")
            }
            other => {
                panic!("an over-cap first fragment must fault: {other:?}")
            }
        }

        // ...and a message inside the cap still goes through.
        let mut s = open_capped(64);
        let ok = br#"{"jsonrpc":"2.0","method":"p","params":[],"id":1}"#;
        assert!(
            ok.len() <= 64,
            "the positive control must be inside the cap"
        );
        assert!(matches!(
            s.on_frame(head(true, OP_TEXT, ok.len()), ok.to_vec())
                .as_slice(),
            [ServerAct::Request { .. }]
        ));
    }

    /// middlewared splits `-32700` from `-32600` by the top-level shape
    /// and one step earlier than this codec does: only an object reaches
    /// `validate_message`, and everything else fails in `parse_message`.
    #[test]
    fn only_a_top_level_object_can_be_invalid_request() {
        // -32700: not an object, however well-formed the JSON is.
        for body in [
            &b"[]"[..],
            br#"[{"jsonrpc":"2.0","method":"m","id":1}]"#,
            br#""just a string""#,
            b"42",
            b"null",
            b"not json at all",
        ] {
            let mut s = open_server();
            match s
                .on_frame(head(true, OP_TEXT, body.len()), body.to_vec())
                .as_slice()
            {
                [ServerAct::Send(f)] => {
                    let v: serde_json::Value =
                        serde_json::from_slice(&decode(f).1).expect("JSON");
                    assert_eq!(
                        v["error"]["code"], -32700,
                        "{body:?} is not an object, so middlewared answers \
                         -32700"
                    );
                    assert!(v["id"].is_null());
                    // ...and says which of the three it was, as
                    // middlewared does: the batch text belongs to a list,
                    // well-formed JSON that is not an object gets
                    // "Invalid Message Format", and bytes that are not
                    // JSON at all get no invented reason.
                    let reason = v["error"]["data"].as_str();
                    let want = if body.trim_ascii_start().first() == Some(&b'[')
                    {
                        Some("Batch messages are not supported at this time")
                    } else if serde_json::from_slice::<serde_json::Value>(body)
                        .is_ok()
                    {
                        Some("Invalid Message Format")
                    } else {
                        None
                    };
                    assert_eq!(reason, want, "{body:?} got the wrong reason");
                }
                other => panic!("{body:?} must be answered: {other:?}"),
            }
        }
        // -32600: an object, but not a valid request.
        let mut s = open_server();
        let body = br#"{"jsonrpc":"2.0","id":1}"#;
        match s
            .on_frame(head(true, OP_TEXT, body.len()), body.to_vec())
            .as_slice()
        {
            [ServerAct::Send(f)] => {
                let v: serde_json::Value =
                    serde_json::from_slice(&decode(f).1).expect("JSON");
                assert_eq!(
                    v["error"]["code"], -32600,
                    "an object reaches request validation"
                );
            }
            other => panic!("must be answered: {other:?}"),
        }
    }

    /// `close_echo_code` documents `None` as "answer with no body
    /// either", and both roles must mean the same thing by it: a peer
    /// that sent no code gets no code back, not a 1000 it never sent.
    #[test]
    fn an_empty_close_body_is_answered_with_an_empty_body() {
        let mut s = open_server();
        match s.on_frame(head(true, OP_CLOSE, 0), Vec::new()).as_slice() {
            [ServerAct::Send(f), ServerAct::PeerClosing] => {
                let (op, payload) = decode(f);
                assert_eq!(op, OP_CLOSE);
                assert!(
                    payload.is_empty(),
                    "an absent code is echoed absent, got {payload:?}"
                );
            }
            other => panic!("expected a close echo: {other:?}"),
        }
    }

    /// A text frame that is not valid UTF-8 fails the connection
    /// (RFC 6455 §8.1), rather than being answered and served past.
    ///
    /// This is a narrower rule than "bad input closes": JSON that is valid
    /// UTF-8 but not a JSON-RPC message is answered `-32700` with the
    /// session still open, because that is a JSON-RPC error and what
    /// middlewared does. Only the encoding violation is a WebSocket
    /// protocol one. The two controls below are what separate them - the
    /// codec declines UTF-8 validation on the grounds that `serde_json`
    /// rejects non-UTF-8 anyway, which is true of detecting it and says
    /// nothing about what the role then does, and this role answered and
    /// kept serving where the client role faults.
    #[test]
    fn invalid_utf8_in_a_text_frame_fails_the_connection() {
        // 0xFF is not a valid UTF-8 byte anywhere.
        let mut s = open_server();
        let bad = vec![b'{', 0xFF, b'}'];
        let acts = s.on_frame(head(true, OP_TEXT, bad.len()), bad);
        match acts.as_slice() {
            [ServerAct::Send(f), ServerAct::Fault(why)] => {
                assert_eq!(
                    decode(f),
                    (OP_CLOSE, 1007u16.to_be_bytes().to_vec()),
                    "the close must carry 1007"
                );
                assert!(why.contains("UTF-8"), "the fault must say why: {why}");
            }
            other => {
                panic!("invalid UTF-8 must fail the connection: {other:?}")
            }
        }
        assert!(s.is_closing(), "the session must be closing");

        // Control: valid UTF-8 that is not JSON is answered, not failed -
        // a JSON-RPC error keeps the session serving.
        let mut ok = open_server();
        let acts = ok.on_frame(head(true, OP_TEXT, 5), b"hello".to_vec());
        assert!(
            matches!(acts.as_slice(), [ServerAct::Send(_)]),
            "valid UTF-8 that is not JSON is answered, not failed: {acts:?}"
        );
        assert!(!ok.is_closing(), "...and the session keeps serving");

        // Control: a well-formed call still works, so the screen is not
        // rejecting everything.
        let mut good = open_server();
        let call = br#"{"jsonrpc":"2.0","id":1,"method":"core.ping"}"#;
        let acts =
            good.on_frame(head(true, OP_TEXT, call.len()), call.to_vec());
        assert!(
            acts.iter().any(|a| matches!(a, ServerAct::Request { .. })),
            "a valid call must still surface: {acts:?}"
        );
    }

    /// Only one Close ever goes out, whoever started it.
    ///
    /// §5.5.1 forbids sending anything after a Close, and that includes a
    /// second Close. The peer's Close already puts this session in
    /// `Closing` and has been echoed, so a caller that then closes locally
    /// would put two on the wire. `Session::start_close` guards from the
    /// same signature and is `pub(crate)`; this one is `pub`, so it is the
    /// one a consumer can trip.
    ///
    /// The two controls are what make this more than "close returns empty":
    /// a lone local close must still emit, and a *second* peer Close must
    /// not be echoed either.
    #[test]
    fn only_one_close_frame_goes_out() {
        // The peer closed first; the echo is that one Close.
        let mut s = open_server();
        let acts = s.on_frame(head(true, OP_CLOSE, 2), vec![0x03, 0xE8]);
        let echoed = acts
            .iter()
            .filter(|a| matches!(a, ServerAct::Send(_)))
            .count();
        assert_eq!(echoed, 1, "the peer's close is echoed once");
        assert!(s.is_closing());
        assert!(
            s.close().is_empty(),
            "a local close after the peer's put a second Close on the wire"
        );

        // Control: with no peer close, the local one must still be sent.
        let mut lone = open_server();
        let f = lone.close();
        assert!(!f.is_empty(), "a lone local close must emit");
        assert_eq!(decode(&f).0, OP_CLOSE);
        assert!(lone.close().is_empty(), "...and only once");

        // Control: a second *peer* Close is not echoed either.
        let mut twice = open_server();
        let _ = twice.on_frame(head(true, OP_CLOSE, 2), vec![0x03, 0xE8]);
        let again = twice.on_frame(head(true, OP_CLOSE, 2), vec![0x03, 0xE8]);
        assert!(
            !again.iter().any(|a| matches!(a, ServerAct::Send(_))),
            "a re-close must stay silent: {again:?}"
        );
    }

    /// A close releases the reassembly buffer instead of holding it to the
    /// session's own end. `Session` does this; this role did not.
    #[test]
    fn a_close_releases_an_open_reassembly() {
        for close_locally in [true, false] {
            let mut s = open_server();
            // Open a fragmented message and leave it open.
            let _ = s.on_frame(head(false, OP_TEXT, 3), b"{\"a".to_vec());
            assert!(s.frag.is_some(), "the fixture did not open a fragment");
            if close_locally {
                let _ = s.close();
            } else {
                let _ = s.on_frame(head(true, OP_CLOSE, 2), vec![0x03, 0xE8]);
            }
            assert!(
                s.frag.is_none(),
                "close_locally={close_locally}: the reassembly was held"
            );
        }
    }

    /// A close body must carry a whole status code (§5.5.1), and a code
    /// this endpoint may not send is never echoed back (§7.4.1/§7.4.2).
    #[test]
    fn a_close_body_is_validated_and_the_echo_sanitised() {
        let mut s = open_server();
        match s.on_frame(head(true, OP_CLOSE, 1), vec![0x03]).as_slice() {
            [ServerAct::Send(f), ServerAct::Fault(_)] => {
                assert_eq!(decode(f), (OP_CLOSE, vec![0x03, 0xEA]))
            }
            other => panic!("a one-byte close body must fault: {other:?}"),
        }

        for (sent, echoed) in [
            (1000u16, 1000u16),
            (1001, 1001),
            (1005, 1002),
            (1006, 1002),
            (1015, 1002),
            (0, 1002),
            (999, 1002),
            (65535, 1002),
            (4999, 4999),
        ] {
            let mut s = open_server();
            let mut body = sent.to_be_bytes().to_vec();
            body.extend_from_slice(b"why");
            match s
                .on_frame(head(true, OP_CLOSE, body.len()), body)
                .as_slice()
            {
                [ServerAct::Send(f), ServerAct::PeerClosing] => {
                    let (op, p) = decode(f);
                    assert_eq!(op, OP_CLOSE);
                    assert_eq!(
                        u16::from_be_bytes([p[0], p[1]]),
                        echoed,
                        "close {sent} should be answered {echoed}"
                    );
                }
                other => panic!("{other:?}"),
            }
            assert_eq!(
                s.close_reason(),
                Some(format!("client closed ({sent})").as_str())
            );
        }

        // An empty body is legal, and answered empty - see
        // `an_empty_close_body_is_answered_with_an_empty_body`, which
        // owns that case and says why both roles must agree on it.
    }

    /// The mirror of the client role's
    /// `a_close_code_no_endpoint_may_send_is_not_echoed_back`: §5.5.1 makes
    /// /reason/ UTF-8 and §8.1 makes an invalid stream fatal, so a close
    /// body whose reason is not UTF-8 is answered 1007, not echoed.
    #[test]
    fn cr5_a_non_utf8_close_reason_is_answered_1007() {
        let mut s = open_server();
        let mut body = 1000u16.to_be_bytes().to_vec();
        body.extend_from_slice(&[0xFF, 0xFE, 0x80]);
        match s
            .on_frame(head(true, OP_CLOSE, body.len()), body)
            .as_slice()
        {
            [ServerAct::Send(f), ..] => {
                let (op, p) = decode(f);
                assert_eq!(op, OP_CLOSE);
                assert_eq!(
                    u16::from_be_bytes([p[0], p[1]]),
                    1007,
                    "a non-UTF-8 reason must be answered 1007"
                );
            }
            other => panic!("expected a close echo, got {other:?}"),
        }
    }

    /// §5.5.1: once a Close has been both sent and received the
    /// connection is closed, so no second Close goes out - including for a
    /// re-close whose body is malformed, which the length check used to
    /// answer ahead of the closing guard.
    #[test]
    fn cr5_a_malformed_re_close_stays_silent() {
        let mut s = open_server();
        // First close: normal, 2-byte body. Session goes to Closing.
        let acts = s.on_frame(head(true, OP_CLOSE, 2), vec![0x03, 0xE8]);
        assert!(matches!(acts.as_slice(), [ServerAct::Send(_), _]));
        // A SECOND close with a 2-byte body is correctly silent.
        let quiet = s.on_frame(head(true, OP_CLOSE, 2), vec![0x03, 0xE8]);
        assert!(quiet.is_empty(), "2-byte re-close is silent: {quiet:?}");
        // A second close with a ONE-byte body is not: the length check sits
        // above the Phase::Closing guard, so it emits a second Close frame.
        let again = s.on_frame(head(true, OP_CLOSE, 1), vec![0x03]);
        assert!(
            again.is_empty(),
            "a re-close must not put a second Close frame on the wire: \
             {again:?}"
        );
        // And the one-byte body is still a fault on a *first* close.
        let mut fresh = open_server();
        assert!(matches!(
            fresh
                .on_frame(head(true, OP_CLOSE, 1), vec![0x03])
                .as_slice(),
            [ServerAct::Send(_), ServerAct::Fault(_)]
        ));
    }

    /// Nothing is answered once a Close has been sent or received: no pong
    /// (§5.5.2), no request surfaced (§5.5.1), and a re-fed head cannot
    /// reopen the session.
    #[test]
    fn a_closed_session_answers_nothing() {
        let msg =
            br#"{"jsonrpc":"2.0","method":"core.ping","params":[],"id":9}"#;

        // The peer closed.
        let mut s = open_server();
        let _ =
            s.on_frame(head(true, OP_CLOSE, 2), 1000u16.to_be_bytes().to_vec());
        assert!(s.is_closing());
        assert!(
            s.on_frame(head(true, OP_PING, 2), b"hi".to_vec())
                .is_empty(),
            "no pong after receiving a Close"
        );
        assert!(
            s.on_frame(head(true, OP_TEXT, msg.len()), msg.to_vec())
                .is_empty(),
            "no request surfaced after receiving a Close"
        );

        // We closed.
        let mut s = open_server();
        let bye = s.close();
        assert_eq!(decode(&bye), (OP_CLOSE, 1000u16.to_be_bytes().to_vec()));
        assert!(
            s.on_frame(head(true, OP_TEXT, msg.len()), msg.to_vec())
                .is_empty(),
            "no request surfaced after sending a Close"
        );
        assert!(matches!(s.on_head(UPGRADE), ServerStep::Reject(_)));
        assert!(
            s.is_closing(),
            "a re-fed head cannot reopen a closed session"
        );
    }

    /// A frame before the upgrade is a driver fault, not a request.
    #[test]
    fn a_frame_before_the_handshake_faults() {
        let mut s = JsonRpcServer::new(65_536);
        let msg =
            br#"{"jsonrpc":"2.0","method":"core.ping","params":[],"id":9}"#;
        assert!(matches!(
            s.on_frame(head(true, OP_TEXT, msg.len()), msg.to_vec())
                .as_slice(),
            [ServerAct::Fault(_)]
        ));
    }

    #[test]
    fn a_notify_builds_a_pushed_event() {
        let s = open_server();
        let frame = s
            .notify("collection_update", Some(&json!({"msg": "added"})))
            .expect("encode");
        let (op, payload) = decode(&frame);
        assert_eq!(op, OP_TEXT);
        let v: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!(v["method"], json!("collection_update"));
        assert_eq!(v["params"]["msg"], json!("added"));
        assert!(v.get("id").is_none(), "a notification has no id");
    }
}
