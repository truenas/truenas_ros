//! The per-connection session state machine, sans-io.
//!
//! Everything protocol-stateful lives here - handshake validation, the
//! response/notification split, fragment reassembly, the ping and close
//! disciplines, call correlation, and the outbound budget against
//! middlewared's per-connection semaphore - as a pure machine: bytes and
//! parsed frames in, [`Act`]s out. The driver (`ApiClient`) owns the ring
//! and performs the sends; this module can be unit-tested without a
//! socket anywhere.

use crate::error::{ApiError, from_rpc_error};
use crate::{CallId, SubscriptionId};
use serde::Deserialize;
use serde_json::Value;
use serde_json::value::RawValue;
use std::collections::{HashMap, VecDeque};
use std::time::Instant;
use truenas_jsonrpc::{Answer, Call, Caller, Id, Incoming, Outcome};
use truenas_ros::ws::{
    self, FrameHead, HandshakeError, OP_BINARY, OP_CLOSE, OP_CONT, OP_PING,
    OP_PONG, OP_TEXT,
};

/// Concurrent calls this session keeps in flight before queueing locally.
/// middlewared's per-connection semaphore is soft 10 / hard 20; staying
/// under the soft limit means the server never delays us and the hard
/// `-32000` refusal is unreachable from a single well-behaved session.
const CALL_BUDGET: usize = 8;

/// What one pending entry is for, which decides how its answer surfaces.
pub(crate) enum Kind {
    /// The session-setup `core.set_options` call; its answer gates
    /// [`Act::Ready`].
    SetOptions,
    /// A caller's own method call.
    User,
    /// A `core.subscribe`; the result is the server's subscription ident.
    Subscribe {
        /// The event/collection name subscribed to.
        collection: String,
        /// The local id the caller will use to unsubscribe.
        sub: SubscriptionId,
    },
    /// A `core.unsubscribe` for `sub`.
    Unsubscribe {
        /// The subscription being torn down.
        sub: SubscriptionId,
    },
}

/// One outstanding call.
pub(crate) struct Pending {
    pub(crate) call: CallId,
    pub(crate) kind: Kind,
    /// When the call times out locally ([`ApiError::Timeout`]); the entry
    /// then stays as a tombstone so the late answer is recognized and
    /// dropped.
    pub(crate) deadline: Option<Instant>,
    pub(crate) abandoned: bool,
}

/// Where the session is in its life.
pub(crate) enum Phase {
    /// The upgrade request is out; the HTTP response head is inbound.
    AwaitingHead,
    /// Serving: calls flow, notifications arrive.
    Open,
    /// A close frame has been sent (ours or the echo of the peer's); the
    /// transport-level close completes the teardown.
    Closing,
}

/// What the driver must do after feeding the session an input.
#[derive(Debug)]
pub(crate) enum Act {
    /// Put these bytes on the wire (already a complete masked frame, or
    /// the upgrade request).
    Send(Vec<u8>),
    /// The session finished its setup and serves calls now.
    Ready,
    /// The handshake failed; close the connection and report the session.
    Failed(HandshakeError),
    /// Session setup ran but its `core.set_options` was refused; the
    /// session cannot serve with the semantics it promised.
    SetupFailed(ApiError),
    /// A call completed (a user call, or a subscribe/unsubscribe that
    /// failed - those surface their errors as the call's).
    CallDone {
        call: CallId,
        result: Result<Box<RawValue>, ApiError>,
    },
    /// A `core.subscribe` completed; events for its collection will now
    /// arrive.
    Subscribed { call: CallId, sub: SubscriptionId },
    /// A `core.unsubscribe` completed.
    Unsubscribed { call: CallId, sub: SubscriptionId },
    /// A `collection_update` notification.
    Update(CollectionUpdate),
    /// The server ended a subscription (`notify_unsubscribed`).
    SubscriptionEnded {
        collection: String,
        error: Option<Value>,
    },
    /// A notification this client does not model - forward compatibility
    /// surfaced rather than dropped or fataled.
    Notification {
        method: String,
        params: Option<Value>,
    },
    /// The peer sent a close frame; the echo has been queued (a preceding
    /// [`Act::Send`]) - flush it and close the connection gracefully. The
    /// close report is in [`Session::close_reason`], read at the
    /// transport-level close.
    PeerClosing,
    /// The peer violated the protocol; close immediately and fail
    /// everything outstanding.
    Fault(&'static str),
}

/// A decoded `collection_update` event.
#[derive(Clone, Debug, Deserialize)]
pub struct CollectionUpdate {
    /// What happened: `added`, `changed`, or `removed`.
    pub msg: String,
    /// The collection (the subscription name it matches).
    pub collection: String,
    /// The affected entity's id, when the event names one.
    #[serde(default)]
    pub id: Option<Value>,
    /// The entity's fields (present on `added`/`changed`).
    #[serde(default)]
    pub fields: Option<Value>,
    /// Anything else the emitter attached.
    #[serde(default)]
    pub extra: Option<Value>,
}

/// The `notify_unsubscribed` payload.
#[derive(Debug, Deserialize)]
struct NotifyUnsubscribed {
    collection: String,
    #[serde(default)]
    error: Option<Value>,
}

/// The response-vs-notification sniff: a JSON-RPC frame from middlewared
/// either answers a call (`result`/`error`, no `method`) or notifies
/// (`method`, no `id`). Unknown members are ignored so decoration cannot
/// break the split.
#[derive(Deserialize)]
struct Probe {
    #[serde(default)]
    method: Option<String>,
}

/// One live subscription.
struct SubEntry {
    collection: String,
    /// The server-issued ident, present once the subscribe completed.
    ident: Option<String>,
}

pub(crate) struct Session {
    pub(crate) phase: Phase,
    /// The `Sec-WebSocket-Key` this connection sent, for validating the
    /// accept digest.
    key: String,
    caller: Caller,
    pending: HashMap<Id, Pending>,
    /// A fragmented text message under reassembly.
    frag: Option<Vec<u8>>,
    subs: HashMap<SubscriptionId, SubEntry>,
    /// Remaining concurrent-call slots against [`CALL_BUDGET`].
    budget: usize,
    /// Built-but-unsent frames (raw JSON, encoded at drain so each send
    /// gets a fresh mask) waiting for budget.
    backlog: VecDeque<(Id, Vec<u8>)>,
    /// Reassembly bound: a fragmented message may not exceed what a
    /// single frame may (the reactor enforces per-frame, this enforces
    /// the sum).
    max_inbound: usize,
    /// Refuse outbound messages beyond this (middlewared kills the
    /// connection on oversize instead of failing the call).
    max_outbound: usize,
    /// Whether session setup skips `core.set_options` (legacy job ids).
    legacy_jobs: bool,
    /// The peer-close report, captured when the close frame arrives so
    /// the transport-level close can name it.
    pub(crate) close_reason: Option<String>,
}

impl Session {
    pub(crate) fn new(
        key: String,
        legacy_jobs: bool,
        max_outbound: usize,
        max_inbound: usize,
    ) -> Session {
        Session {
            phase: Phase::AwaitingHead,
            key,
            caller: Caller::new(),
            pending: HashMap::new(),
            frag: None,
            subs: HashMap::new(),
            budget: CALL_BUDGET,
            backlog: VecDeque::new(),
            max_inbound,
            max_outbound,
            legacy_jobs,
            close_reason: None,
        }
    }

    /// The upgrade request to send once the transport connects.
    ///
    /// Fails on an endpoint `ws::validate_request_target` refuses;
    /// `ApiClient::connect_start` screens the same value before it dials,
    /// so reaching this is a caller that went around it.
    pub(crate) fn upgrade(
        &self,
        endpoint: &str,
    ) -> Result<Vec<u8>, HandshakeError> {
        ws::upgrade_request(endpoint, &self.key)
    }

    /// The HTTP response head arrived: validate the upgrade, then either
    /// declare the session ready (legacy jobs) or issue the setup
    /// `core.set_options` whose answer will.
    pub(crate) fn on_head(&mut self, head: &[u8], next: CallId) -> Vec<Act> {
        match ws::validate_101(head, &self.key) {
            Err(e) => vec![Act::Failed(e)],
            Ok(()) => {
                self.phase = Phase::Open;
                if self.legacy_jobs {
                    return vec![Act::Ready];
                }
                // The reference client's session setup: answers arrive
                // when jobs finish, not as bare job ids.
                let params = serde_json::value::to_raw_value(&[
                    serde_json::json!({ "legacy_jobs": false }),
                ])
                .expect("a literal object encodes");
                match self.submit(
                    next,
                    Kind::SetOptions,
                    "core.set_options",
                    &params,
                    None,
                ) {
                    Ok(acts) => acts,
                    Err(e) => vec![Act::SetupFailed(e)],
                }
            }
        }
    }

    /// Build and account one call. `params` must already be a JSON Array
    /// (the caller validated the first byte). Returns the send when the
    /// budget allows, queues otherwise.
    pub(crate) fn submit(
        &mut self,
        call: CallId,
        kind: Kind,
        method: &str,
        params: &RawValue,
        deadline: Option<Instant>,
    ) -> Result<Vec<Act>, ApiError> {
        let (id, frame) = self
            .caller
            .request(method, Some(params))
            .map_err(|e| ApiError::Build(e.to_string()))?;
        if frame.len() > self.max_outbound {
            // The id is minted but never sent; a gap in the sequence is
            // harmless (ids are correlation keys, nothing more).
            return Err(ApiError::TooLarge {
                len: frame.len(),
                cap: self.max_outbound,
            });
        }
        self.pending.insert(
            id.clone(),
            Pending {
                call,
                kind,
                deadline,
                abandoned: false,
            },
        );
        if self.budget > 0 {
            self.budget -= 1;
            Ok(vec![Act::Send(ws::encode_frame(
                OP_TEXT,
                &frame,
                ws::mask_key(),
            ))])
        } else {
            self.backlog.push_back((id, frame));
            Ok(Vec::new())
        }
    }

    /// One completed inbound WebSocket frame.
    pub(crate) fn on_frame(
        &mut self,
        head: FrameHead,
        payload: Vec<u8>,
    ) -> Vec<Act> {
        match head.opcode {
            OP_PING => {
                // §5.5.2/§5.5.3: pong back the same payload. Control
                // frames may interleave a fragmented message; reassembly
                // state is untouched.
                vec![Act::Send(ws::encode_frame(
                    OP_PONG,
                    &payload,
                    ws::mask_key(),
                ))]
            }
            OP_PONG => Vec::new(),
            OP_CLOSE => self.on_close_frame(&payload),
            OP_BINARY => vec![Act::Fault("binary frame")],
            OP_TEXT if !head.fin => {
                if self.frag.is_some() {
                    return vec![Act::Fault(
                        "new data frame inside a fragmented message",
                    )];
                }
                self.frag = Some(payload);
                Vec::new()
            }
            OP_TEXT => {
                if self.frag.is_some() {
                    return vec![Act::Fault(
                        "new data frame inside a fragmented message",
                    )];
                }
                self.on_message(&payload)
            }
            OP_CONT => {
                let Some(mut buf) = self.frag.take() else {
                    return vec![Act::Fault(
                        "continuation with no message open",
                    )];
                };
                if buf.len().saturating_add(payload.len()) > self.max_inbound {
                    return vec![Act::Fault(
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
            _ => unreachable!("frame_head refused reserved opcodes"),
        }
    }

    /// A close frame from the peer: echo it (once), remember why, and let
    /// the driver run the transport close.
    fn on_close_frame(&mut self, payload: &[u8]) -> Vec<Act> {
        let reason = if payload.len() >= 2 {
            let code = u16::from_be_bytes([payload[0], payload[1]]);
            let text = String::from_utf8_lossy(&payload[2..]);
            if text.is_empty() {
                format!("peer closed ({code})")
            } else {
                format!("peer closed ({code}: {text})")
            }
        } else {
            "peer closed".to_owned()
        };
        if matches!(self.phase, Phase::Closing) {
            // Our close is out already; this is the peer's echo, and the
            // transport-level teardown finishes the job.
            return Vec::new();
        }
        self.phase = Phase::Closing;
        self.close_reason = Some(reason.clone());
        // §5.5.1: echo the status code back.
        let echo = if payload.len() >= 2 {
            &payload[..2]
        } else {
            &[][..]
        };
        vec![
            Act::Send(ws::encode_frame(OP_CLOSE, echo, ws::mask_key())),
            Act::PeerClosing,
        ]
    }

    /// Begin a local close: the 1000 (normal closure) frame. The driver
    /// flushes it and closes the transport.
    pub(crate) fn start_close(&mut self) -> Vec<Act> {
        if matches!(self.phase, Phase::Closing) {
            return Vec::new();
        }
        self.phase = Phase::Closing;
        vec![Act::Send(ws::encode_frame(
            OP_CLOSE,
            &1000u16.to_be_bytes(),
            ws::mask_key(),
        ))]
    }

    /// One complete JSON-RPC text message: a response to something
    /// pending, or a server notification.
    fn on_message(&mut self, text: &[u8]) -> Vec<Act> {
        let Ok(probe) = serde_json::from_slice::<Probe>(text) else {
            return vec![Act::Fault("text frame is not a JSON object")];
        };
        if probe.method.is_some() {
            self.on_notification(text)
        } else {
            self.on_answer(text)
        }
    }

    fn on_notification(&mut self, text: &[u8]) -> Vec<Act> {
        let Incoming::Single(Call::Valid(req)) = truenas_jsonrpc::parse(text)
        else {
            return vec![Act::Fault("malformed notification")];
        };
        if !req.is_notification() {
            // middlewared never issues requests toward the client.
            return vec![Act::Fault("server sent a request")];
        }
        let params = req.params().map(|p| p.get());
        match req.method() {
            "collection_update" => {
                let Some(raw) = params else {
                    return vec![Act::Fault(
                        "collection_update without params",
                    )];
                };
                match serde_json::from_str::<CollectionUpdate>(raw.get()) {
                    Ok(update) => vec![Act::Update(update)],
                    // Shape drift is surfaced, not fatal and not dropped.
                    Err(_) => vec![Act::Notification {
                        method: "collection_update".into(),
                        params: serde_json::from_str(raw.get()).ok(),
                    }],
                }
            }
            "notify_unsubscribed" => {
                let decoded = params.and_then(|raw| {
                    serde_json::from_str::<NotifyUnsubscribed>(raw.get()).ok()
                });
                match decoded {
                    Some(n) => {
                        self.subs.retain(|_, e| e.collection != n.collection);
                        vec![Act::SubscriptionEnded {
                            collection: n.collection,
                            error: n.error,
                        }]
                    }
                    None => vec![Act::Notification {
                        method: "notify_unsubscribed".into(),
                        params: None,
                    }],
                }
            }
            other => vec![Act::Notification {
                method: other.to_owned(),
                params: params.and_then(|r| serde_json::from_str(r.get()).ok()),
            }],
        }
    }

    fn on_answer(&mut self, text: &[u8]) -> Vec<Act> {
        let reply = match truenas_jsonrpc::parse_answer(text) {
            Answer::Single(reply) => reply,
            // middlewared rejects batch requests and so never answers with
            // an Array; one appearing is not this protocol.
            Answer::Batch(_) => return vec![Act::Fault("batch answer")],
            Answer::Invalid(_) => {
                return vec![Act::Fault("unparseable response")];
            }
        };
        let Some(p) = self.pending.remove(reply.id()) else {
            return vec![Act::Fault("response to no outstanding call")];
        };
        // The server slot is free again either way; refill and drain.
        self.budget += 1;
        let mut acts = self.drain_backlog();
        if p.abandoned {
            // Timed out locally; the late answer is dropped by design.
            return acts;
        }
        let outcome = match reply.outcome() {
            Outcome::Result(raw) => Ok(raw.to_owned()),
            Outcome::Failure(e) => Err(from_rpc_error(e)),
        };
        match p.kind {
            Kind::SetOptions => match outcome {
                Ok(_) => acts.push(Act::Ready),
                Err(e) => acts.push(Act::SetupFailed(e)),
            },
            Kind::User => acts.push(Act::CallDone {
                call: p.call,
                result: outcome,
            }),
            Kind::Subscribe { collection, sub } => match outcome {
                Ok(raw) => match serde_json::from_str::<String>(raw.get()) {
                    Ok(ident) => {
                        self.subs.insert(
                            sub,
                            SubEntry {
                                collection,
                                ident: Some(ident),
                            },
                        );
                        acts.push(Act::Subscribed { call: p.call, sub });
                    }
                    Err(e) => acts.push(Act::CallDone {
                        call: p.call,
                        result: Err(ApiError::Decode(e)),
                    }),
                },
                Err(e) => acts.push(Act::CallDone {
                    call: p.call,
                    result: Err(e),
                }),
            },
            Kind::Unsubscribe { sub } => match outcome {
                Ok(_) => {
                    self.subs.remove(&sub);
                    acts.push(Act::Unsubscribed { call: p.call, sub });
                }
                Err(e) => acts.push(Act::CallDone {
                    call: p.call,
                    result: Err(e),
                }),
            },
        }
        acts
    }

    /// Send whatever the refilled budget admits.
    fn drain_backlog(&mut self) -> Vec<Act> {
        let mut acts = Vec::new();
        while self.budget > 0 {
            let Some((id, frame)) = self.backlog.pop_front() else {
                break;
            };
            // A queued call that timed out before it ever reached the
            // wire: drop it here, and free its tombstone - no answer can
            // exist for a call that was never sent.
            if self.pending.get(&id).is_some_and(|p| p.abandoned) {
                self.pending.remove(&id);
                continue;
            }
            self.budget -= 1;
            acts.push(Act::Send(ws::encode_frame(
                OP_TEXT,
                &frame,
                ws::mask_key(),
            )));
        }
        acts
    }

    /// The server-issued ident for `sub`, once subscribed.
    pub(crate) fn sub_ident(&self, sub: SubscriptionId) -> Option<&str> {
        self.subs.get(&sub).and_then(|e| e.ident.as_deref())
    }

    /// This session's outbound message cap, for sizing a `core.bulk`
    /// flush chunk.
    pub(crate) fn max_outbound(&self) -> usize {
        self.max_outbound
    }

    /// The earliest live call deadline, for the pump's wait computation.
    pub(crate) fn next_deadline(&self) -> Option<Instant> {
        self.pending
            .values()
            .filter(|p| !p.abandoned)
            .filter_map(|p| p.deadline)
            .min()
    }

    /// Time out every live call whose deadline has passed. The entries
    /// stay as tombstones (their answers are still owed by the server and
    /// must be recognized when they land); a tombstone still in the
    /// backlog is dropped at drain instead.
    pub(crate) fn expire(&mut self, now: Instant) -> Vec<Act> {
        let mut acts = Vec::new();
        for p in self.pending.values_mut() {
            if !p.abandoned && p.deadline.is_some_and(|d| d <= now) {
                p.abandoned = true;
                // The setup call has no caller-visible id; its timeout
                // surfaces through the blocking connect's own deadline.
                if !matches!(p.kind, Kind::SetOptions) {
                    acts.push(Act::CallDone {
                        call: p.call,
                        result: Err(ApiError::Timeout),
                    });
                }
            }
        }
        acts
    }

    /// Every live call, failed at once - the session is going away.
    pub(crate) fn fail_all(&mut self, why: &str) -> Vec<Act> {
        let mut acts = Vec::new();
        for (_, p) in self.pending.drain() {
            if !p.abandoned && !matches!(p.kind, Kind::SetOptions) {
                acts.push(Act::CallDone {
                    call: p.call,
                    result: Err(ApiError::Closed {
                        reason: why.to_owned(),
                    }),
                });
            }
        }
        self.backlog.clear();
        acts
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use truenas_ros::ws::FrameHead;

    fn session() -> Session {
        let mut s = Session::new("test-key".into(), false, 65_536, 1024);
        // on_frame does not gate on phase, but a realistic session is Open.
        s.phase = Phase::Open;
        s
    }

    /// A server->style FrameHead (unmasked) for feeding on_frame directly.
    fn head(fin: bool, opcode: u8, payload_len: usize) -> FrameHead {
        FrameHead {
            fin,
            opcode,
            header_len: if payload_len < 126 { 2 } else { 4 },
            payload_len,
        }
    }

    /// Unmask a client frame the session emitted, returning (opcode,
    /// payload) - the session always masks what it sends.
    fn unmask(f: &[u8]) -> (u8, Vec<u8>) {
        assert!(f[0] & 0x80 != 0, "FIN set");
        assert!(f[1] & 0x80 != 0, "client frame is masked");
        let (hdr, len) = match f[1] & 0x7f {
            126 => (4, usize::from(u16::from_be_bytes([f[2], f[3]]))),
            127 => (
                10,
                u64::from_be_bytes(f[2..10].try_into().unwrap()) as usize,
            ),
            n => (2, usize::from(n)),
        };
        let mask = &f[hdr..hdr + 4];
        let payload = f[hdr + 4..hdr + 4 + len]
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ mask[i % 4])
            .collect();
        (f[0] & 0x0f, payload)
    }

    /// The libwebsockets/Autobahn fragmentation faults, on the receive
    /// side (client-parser-ws.c Findings 9a/9b): a continuation with no
    /// message in progress, and a fresh data frame while one is owed a
    /// FIN, each fail the connection.
    #[test]
    fn a_continuation_with_no_message_open_faults() {
        let mut s = session();
        let acts = s.on_frame(head(true, OP_CONT, 3), b"abc".to_vec());
        assert!(
            matches!(acts.as_slice(), [Act::Fault(_)]),
            "orphan continuation is a protocol fault: {acts:?}"
        );
    }

    #[test]
    fn a_new_data_frame_mid_fragment_faults() {
        let mut s = session();
        // Open a fragmented text message (FIN=0), then send a *new* text
        // frame instead of a continuation.
        assert!(
            s.on_frame(head(false, OP_TEXT, 1), b"{".to_vec())
                .is_empty()
        );
        let acts = s.on_frame(head(false, OP_TEXT, 1), b"[".to_vec());
        assert!(
            matches!(acts.as_slice(), [Act::Fault(_)]),
            "a data frame owing a FIN is a fault: {acts:?}"
        );
    }

    /// A binary frame: middlewared is text-only, so it is a fault (mirrors
    /// the session's OP_BINARY arm; the codec accepts the opcode, the
    /// session rejects the type).
    #[test]
    fn a_binary_frame_faults() {
        let mut s = session();
        let acts = s.on_frame(head(true, OP_BINARY, 2), b"hi".to_vec());
        assert!(matches!(acts.as_slice(), [Act::Fault(_)]), "{acts:?}");
    }

    /// A valid fragmented message reassembles across a continuation and is
    /// dispatched once whole - here a notification, so it surfaces as an
    /// Update.
    #[test]
    fn a_fragmented_message_reassembles() {
        let mut s = session();
        let whole = br#"{"jsonrpc":"2.0","method":"collection_update","params":{"msg":"added","collection":"c"}}"#;
        let (a, b) = whole.split_at(40);
        assert!(
            s.on_frame(head(false, OP_TEXT, a.len()), a.to_vec())
                .is_empty()
        );
        let acts = s.on_frame(head(true, OP_CONT, b.len()), b.to_vec());
        assert!(
            acts.iter().any(|act| matches!(act, Act::Update(_))),
            "the reassembled notification dispatched: {acts:?}"
        );
    }

    /// A control frame may interleave a fragmented message without
    /// disturbing reassembly (RFC §5.4; lws control opcodes never touch
    /// the continuation state): a ping between fragments is answered with
    /// a pong echoing its payload, and the message still completes.
    #[test]
    fn a_ping_interleaves_a_fragment_and_is_ponged() {
        let mut s = session();
        let whole = br#"{"jsonrpc":"2.0","method":"collection_update","params":{"msg":"added","collection":"c"}}"#;
        let (a, b) = whole.split_at(40);
        assert!(
            s.on_frame(head(false, OP_TEXT, a.len()), a.to_vec())
                .is_empty()
        );
        // Ping mid-fragment -> a single masked pong with the same payload.
        let acts = s.on_frame(head(true, OP_PING, 4), b"body".to_vec());
        match acts.as_slice() {
            [Act::Send(frame)] => {
                assert_eq!(unmask(frame), (OP_PONG, b"body".to_vec()));
            }
            other => panic!("expected one pong, got {other:?}"),
        }
        // The fragment still completes afterward.
        let acts = s.on_frame(head(true, OP_CONT, b.len()), b.to_vec());
        assert!(
            acts.iter().any(|act| matches!(act, Act::Update(_))),
            "{acts:?}"
        );
    }

    /// A reassembled message may not exceed the inbound cap - the sum over
    /// fragments is bounded, not just each frame (the reactor bounds a
    /// single frame; this bounds the whole message).
    #[test]
    fn an_oversized_reassembly_faults() {
        let mut s = Session::new("k".into(), false, 65_536, 8);
        s.phase = Phase::Open;
        assert!(
            s.on_frame(head(false, OP_TEXT, 6), vec![b'x'; 6])
                .is_empty()
        );
        let acts = s.on_frame(head(false, OP_CONT, 6), vec![b'x'; 6]);
        assert!(
            matches!(acts.as_slice(), [Act::Fault(_)]),
            "12 bytes over an 8-byte cap faults: {acts:?}"
        );
    }

    /// A ping outside any fragment is answered with a pong of the same
    /// payload (RFC §5.5.2).
    #[test]
    fn a_ping_is_answered_with_a_matching_pong() {
        let mut s = session();
        let acts = s.on_frame(head(true, OP_PING, 5), b"hello".to_vec());
        match acts.as_slice() {
            [Act::Send(frame)] => {
                assert_eq!(unmask(frame), (OP_PONG, b"hello".to_vec()));
            }
            other => panic!("expected a pong, got {other:?}"),
        }
    }

    /// A peer close echoes a close frame and hands the driver PeerClosing;
    /// the status code is captured for the session-closed report.
    #[test]
    fn a_peer_close_echoes_and_reports() {
        let mut s = session();
        // 1001 "going away", big-endian.
        let acts = s.on_frame(head(true, OP_CLOSE, 2), vec![0x03, 0xe9]);
        assert!(
            acts.iter().any(|a| matches!(a, Act::PeerClosing)),
            "the driver is told to close: {acts:?}"
        );
        match acts.first() {
            Some(Act::Send(frame)) => {
                let (op, payload) = unmask(frame);
                assert_eq!(op, OP_CLOSE);
                assert_eq!(payload, vec![0x03, 0xe9], "the code is echoed");
            }
            other => panic!("expected a close echo first, got {other:?}"),
        }
        assert!(
            s.close_reason
                .as_deref()
                .is_some_and(|r| r.contains("1001")),
            "the close code is captured: {:?}",
            s.close_reason
        );
    }
}
