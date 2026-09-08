//! A sans-io JSON-RPC *server* session over the `ws` server codec - the
//! mirror of [`session`](crate::session)'s client half.
//!
//! It is the receiving end of the same protocol the client speaks: it
//! accepts the upgrade (rather than requesting it), reads masked client
//! frames (rather than unmasked server ones), and surfaces inbound
//! *requests* for the application to answer (rather than correlating
//! responses to its own calls). Like the client session it does no I/O: a
//! driver feeds it the request head and unmasked frame payloads, and turns
//! the [`ServerAct`]s it returns into socket writes. The parent crate's
//! [`net::server`](truenas_ros::net::server) is one such driver; a test
//! harness on a plain socket is another.
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
        /// The unparsed `params` array, or `None` when omitted.
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

    /// Feed the client's upgrade request head (through its blank line, as
    /// the framer's handshake phase cuts it). On success the session moves
    /// to serving frames and the driver must send the returned `101`.
    pub fn on_head(&mut self, head: &[u8]) -> ServerStep {
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
    /// [`ws::unmask`](truenas_ros::ws::unmask); client frames are always
    /// masked, unlike the server frames the client session reads).
    pub fn on_frame(
        &mut self,
        head: FrameHead,
        payload: Vec<u8>,
    ) -> Vec<ServerAct> {
        match head.opcode {
            OP_PING => {
                vec![ServerAct::Send(ws::encode_server_frame(
                    OP_PONG, &payload,
                ))]
            }
            OP_PONG => Vec::new(),
            OP_CLOSE => self.on_close_frame(&payload),
            OP_BINARY => vec![ServerAct::Fault("binary frame")],
            OP_TEXT if !head.fin => {
                if self.frag.is_some() {
                    return vec![ServerAct::Fault(
                        "new data frame inside a fragmented message",
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
            _ => unreachable!("server_frame_head refused reserved opcodes"),
        }
    }

    /// The reason string for a completed peer close, once
    /// [`ServerAct::PeerClosing`] has been seen.
    pub fn close_reason(&self) -> Option<&str> {
        self.close_reason.as_deref()
    }

    fn on_close_frame(&mut self, payload: &[u8]) -> Vec<ServerAct> {
        let reason = if payload.len() >= 2 {
            let code = u16::from_be_bytes([payload[0], payload[1]]);
            format!("client closed ({code})")
        } else {
            "client closed".to_owned()
        };
        if matches!(self.phase, Phase::Closing) {
            return Vec::new();
        }
        self.phase = Phase::Closing;
        self.close_reason = Some(reason);
        let echo = if payload.len() >= 2 {
            &payload[..2]
        } else {
            &[][..]
        };
        vec![
            ServerAct::Send(ws::encode_server_frame(OP_CLOSE, echo)),
            ServerAct::PeerClosing,
        ]
    }

    fn on_message(&mut self, text: &[u8]) -> Vec<ServerAct> {
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
            // middlewared rejects batches; mirror it by refusing the
            // connection rather than answering a batch it would never send.
            Incoming::Batch(_) => vec![ServerAct::Fault("batch not supported")],
            Incoming::Invalid { error, .. } => {
                vec![ServerAct::Send(error_frame(Id::Null, error))]
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
    pub fn close(&mut self) -> Vec<u8> {
        self.phase = Phase::Closing;
        ws::encode_server_frame(OP_CLOSE, &1000u16.to_be_bytes())
    }
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

    fn open_server() -> JsonRpcServer {
        let mut s = JsonRpcServer::new(65_536);
        let req = b"GET /api/current HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
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
