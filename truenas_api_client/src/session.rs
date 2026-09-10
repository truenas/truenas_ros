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
use std::time::{Duration, Instant};
use truenas_jsonrpc::{Answer, Call, Caller, Id, Incoming, Outcome};
use truenas_ros::ws::{
    self, FrameHead, HandshakeError, OP_BINARY, OP_CLOSE, OP_CONT, OP_PING,
    OP_PONG, OP_TEXT,
};

/// Concurrent calls this session keeps in flight; further calls queue
/// behind the answers.
///
/// A mirror of middlewared's own per-connection semaphore, which is soft
/// 10 / hard 20 (`SoftHardSemaphore(10, 20)`,
/// `middlewared/api/base/server/ws_handler/rpc.py`, over
/// `middlewared/utils/lock.py`): under the soft limit the server never
/// delays us, and the hard `-32000` refusal is out of reach of the calls
/// one session has outstanding at once.
///
/// The ceiling sits under the soft limit rather than at it because with
/// `legacy_jobs` off a job method holds its server-side slot for the
/// whole job - `method.call` awaits `result.wait()` *inside* the
/// semaphore - so concurrency there is scarce and long-held.
///
/// It counts what the *server* is holding, not what this client still
/// cares about, and those differ: a slot is spent when the request goes
/// out and returned only by its answer. Timing a call out, or failing it
/// on an unattributable error, tells the caller it is over and tells
/// middlewared nothing - the method is still running inside the
/// semaphore. Crediting the slot there would let repeated timeouts put
/// more work in front of the server than this number, which is the only
/// way a session that obeys this ceiling can reach `-32000` at all.
/// Calls that arrive while the slots are out queue in `backlog` and go
/// when an answer frees one; `submit` refuses with
/// [`ApiError::QueueFull`] once that queue hits its own bound, so the
/// pushback is visible rather than silent.
pub const CALL_BUDGET: usize = 8;

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
    /// Whether this call's frame actually reached the wire. A call still
    /// in `backlog` has spent no budget, so timing it out must not credit
    /// a slot it never took.
    sent: bool,
    pub(crate) call: CallId,
    pub(crate) kind: Kind,
    /// When the call times out locally ([`ApiError::Timeout`]); the entry
    /// then stays as a tombstone so the late answer is recognized and
    /// dropped.
    pub(crate) deadline: Option<Instant>,
    pub(crate) abandoned: bool,
    /// The encoded request, kept so a `-32000` can be reissued without
    /// troubling the caller: middlewared raises at its hard limit before
    /// the call is entered, so the method provably did not run.
    ///
    /// `None` for calls at the extended cap (the exempt upload methods,
    /// 32x the ordinary one) and for session setup. Retention is bounded
    /// by [`CALL_BUDGET`] frames at the *ordinary* cap; letting a 2 MiB
    /// upload in would multiply that by 32 for the calls least likely to
    /// want a silent reissue.
    retry_frame: Option<Vec<u8>>,
    /// Reissues so far, against [`MAX_CALL_RETRIES`].
    retries: u32,
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
    /// The server reported an error against no call of ours - a
    /// `id: null` Response. Diagnostic: the session stays up.
    ServerError(ApiError),
}

/// A decoded `collection_update` event.
///
/// [`Debug`] reports the payload members by size, not content: a
/// `core.get_jobs` update carries the job's own result in `fields`, so
/// `{:?}` on the event is the same disclosure [`OwnedResult`]'s `Debug`
/// avoids.
///
/// [`OwnedResult`]: crate::OwnedResult
#[derive(Clone, Deserialize)]
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

impl std::fmt::Debug for CollectionUpdate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use crate::Opaque;
        f.debug_struct("CollectionUpdate")
            .field("msg", &self.msg)
            .field("collection", &self.collection)
            .field("id", &Opaque(self.id.as_ref()))
            .field("fields", &Opaque(self.fields.as_ref()))
            .field("extra", &Opaque(self.extra.as_ref()))
            .finish()
    }
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
    /// Bound on `backlog`'s length (`ApiConfig::max_queued_calls`).
    max_queued: usize,
    /// Bound on `backlog`'s bytes (`ApiConfig::max_queued_bytes`).
    max_queued_bytes: usize,
    /// Bytes currently held in `backlog`, kept rather than summed: a
    /// submission is on the hot path and the queue can be hundreds deep.
    queued_bytes: usize,
    /// Whether session setup skips `core.set_options` (legacy job ids).
    legacy_jobs: bool,
    /// The peer-close report, captured when the close frame arrives so
    /// the transport-level close can name it.
    pub(crate) close_reason: Option<String>,
    /// A `-32000` arrived and the backoff has not been given a clock yet.
    /// `on_answer` has no `Instant` (this half of the client is sans-io),
    /// so the refusal is recorded here and `expire` - which the driver
    /// calls with `now` on every pump iteration - turns it into
    /// `backoff_until`.
    backoff_armed: bool,
    /// While set, `drain_backlog` sends nothing. Cleared by `expire` once
    /// the instant passes; published through `next_deadline` so the pump
    /// wakes for it.
    backoff_until: Option<Instant>,
    /// Consecutive `-32000` refusals, the exponent for [`BACKOFF_BASE`].
    /// Reset by any answer that is not a refusal.
    backoff_step: u32,
}

/// Reissues of one call after a `-32000` before its caller is told.
///
/// A refusal at the peer's hard concurrency limit is raised before the
/// method is entered, so nothing ran and reissuing cannot double the
/// call. This is how many times that is done silently. The
/// caller's own `call_timeout` is the real bound - `expire` abandons the
/// call whatever this says - so this exists to stop an unbounded reissue
/// loop on a session with no call deadline set.
pub const MAX_CALL_RETRIES: u32 = 4;

/// First pause after a `-32000`, doubled per consecutive refusal up to
/// [`BACKOFF_CAP`].
const BACKOFF_BASE: Duration = Duration::from_millis(100);

/// Ceiling for the pause. What has to drain before the peer has room is
/// other work - this client is not the only one against the limit - and a
/// job method holds its slot for the whole job (`method.call` awaits
/// `result.wait()` *inside* the semaphore,
/// `api/base/server/ws_handler/rpc.py`), so the wait is seconds rather
/// than milliseconds. Past this, waiting longer only delays noticing
/// that the peer has recovered.
const BACKOFF_CAP: Duration = Duration::from_secs(5);

impl Session {
    pub(crate) fn new(
        key: String,
        legacy_jobs: bool,
        max_outbound: usize,
        max_inbound: usize,
        max_queued: usize,
        max_queued_bytes: usize,
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
            max_queued,
            max_queued_bytes,
            queued_bytes: 0,
            backoff_armed: false,
            backoff_until: None,
            backoff_step: 0,
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
    /// budget allows, queues otherwise - and refuses rather than queueing
    /// once the backlog is at [`Session::max_queued`].
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
        // Per method, as middlewared applies it: the whitelisted upload
        // methods are exempt from the ordinary cap and nothing else is.
        let cap = crate::config::outbound_cap(self.max_outbound, method);
        if frame.len() > cap {
            // The id is minted but never sent; a gap in the sequence is
            // harmless (ids are correlation keys, nothing more).
            return Err(ApiError::TooLarge {
                len: frame.len(),
                cap,
            });
        }
        // A running backoff holds new calls too, not only the ones
        // already queued. `-32000` frees a slot as it arrives - it is an
        // answer - so a caller submitting on the next line would find
        // `budget > 0` and go straight out into the same refusal,
        // stepping around `drain_backlog`'s gate entirely.
        let sending = self.budget > 0 && !self.backing_off();
        // A backlog with no bound turns a caller that ignores backpressure
        // into unbounded memory: every queued call holds its encoded
        // frame, up to `max_outbound` each. Refuse the submission instead,
        // in the vocabulary `queue_bulk` already uses for the same
        // question. The refusal is before `pending.insert`, so a refused
        // call leaves no tombstone to be answered.
        if !sending {
            // Two caps, and the first one tripped refuses. The count is a
            // pipelining depth; the bytes are what actually bound memory,
            // because a frame's ceiling is per method and the upload
            // methods are 32x the ordinary one - so a count alone leaves
            // the worst case at the wrong number by that factor.
            if self.backlog.len() >= self.max_queued {
                return Err(ApiError::QueueFull {
                    queue: "this session's call backlog, in calls",
                    cap: self.max_queued,
                });
            }
            if self.queued_bytes.saturating_add(frame.len())
                > self.max_queued_bytes
            {
                return Err(ApiError::QueueFull {
                    queue: "this session's call backlog, in bytes",
                    cap: self.max_queued_bytes,
                });
            }
        }
        let retry_frame = (matches!(kind, Kind::User)
            && frame.len() <= self.max_outbound)
            .then(|| frame.clone());
        self.pending.insert(
            id.clone(),
            Pending {
                sent: sending,
                call,
                kind,
                deadline,
                abandoned: false,
                retry_frame,
                retries: 0,
            },
        );
        if sending {
            self.budget -= 1;
            Ok(vec![Act::Send(ws::encode_frame(
                OP_TEXT,
                &frame,
                ws::mask_key(),
            ))])
        } else {
            self.queued_bytes += frame.len();
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
                // The cap has to bind here, not only where the pieces are
                // joined: a first fragment is held until a continuation
                // arrives, and a peer that never sends one holds whatever
                // it declared for as long as the connection lives.
                if payload.len() > self.max_inbound {
                    return vec![Act::Fault(
                        "fragmented message exceeds the inbound cap",
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
                // The cap covers an unfragmented message too, not only a
                // reassembled one. The transport bounds this today -
                // `ApiConfig::max_message_bytes` feeds both
                // `max_reply_bytes` and `max_inbound`, so the reactor
                // closes first - but the session is sans-io and states
                // its own bound; a driver that framed these bytes some
                // other way would otherwise hand `on_message` whatever
                // the peer declared.
                if payload.len() > self.max_inbound {
                    return vec![Act::Fault("message exceeds the inbound cap")];
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
        // §5.5.1 makes /reason/ UTF-8 and its first two bytes a code, so a
        // lossy decode would report a reason the peer never sent and a
        // one-byte body would report no code at all rather than a
        // malformed frame. Say which it was instead.
        let reason = match payload.len() {
            0 => "peer closed".to_owned(),
            1 => "peer closed (malformed close body)".to_owned(),
            _ => {
                let code = u16::from_be_bytes([payload[0], payload[1]]);
                match std::str::from_utf8(&payload[2..]) {
                    Ok("") => format!("peer closed ({code})"),
                    Ok(text) => format!("peer closed ({code}: {text})"),
                    Err(_) => {
                        format!("peer closed ({code}: invalid UTF-8 reason)")
                    }
                }
            }
        };
        if matches!(self.phase, Phase::Closing) {
            // Our close is out already; this is the peer's echo, and the
            // transport-level teardown finishes the job.
            return Vec::new();
        }
        self.phase = Phase::Closing;
        self.close_reason = Some(reason);
        // No continuation can arrive now, so an open reassembly is dead
        // weight - up to `max_inbound` of it - held until the driver gets
        // round to dropping the session.
        self.frag = None;

        // §5.5.1 echoes the status code back, bounded by §7.4.1: 1004,
        // 1005, 1006, 1015 and the unassigned ranges MUST NOT be set by an
        // endpoint, so an unsendable peer code is answered 1002 rather than
        // reflected - a peer that checks would fail the connection over our
        // echo and turn a graceful close into an abnormal one.
        let echo = match ws::close_echo_code(payload) {
            Some(code) => code.to_be_bytes().to_vec(),
            None => Vec::new(),
        };
        vec![
            Act::Send(ws::encode_frame(OP_CLOSE, &echo, ws::mask_key())),
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
        // JSON-RPC 2.0 §5: a Response carries `id: null` when the server
        // could not recover an id from what it was answering - a parse
        // error, or its own message failing to serialise. middlewared
        // sends exactly that and keeps serving
        // (`app.send_error(None, ...)` then `continue`,
        // `api/base/server/ws_handler/rpc.py`), so it names no call of
        // ours and tearing the session down over it would fail every
        // healthy call in flight for a message the server already moved
        // past. Surface it and carry on.
        if matches!(reply.id(), Id::Null) {
            let report = match reply.outcome() {
                Outcome::Failure(e) => from_rpc_error(e),
                Outcome::Result(_) => ApiError::Protocol(
                    "a result Response with a null id names no call",
                ),
            };
            // §5 gives `null` one meaning: the server could not work out
            // which request the error belongs to. So it belongs to none of
            // ours in particular and to any of them in general - and the
            // one that provoked it will never be answered, because the
            // answer it would have had is this one. Leaving them pending
            // strands each caller and keeps their budget slots: `expire`
            // only abandons an entry with a deadline, `call_timeout` is
            // `None` by default, so nothing would ever return them and
            // `CALL_BUDGET` of these would wedge a healthy session.
            let mut acts = vec![Act::ServerError(report)];
            acts.extend(self.fail_outstanding(
                "the server reported an error it could not attribute to a \
                 request; every call in flight was failed with it",
            ));
            return acts;
        }
        let Some(p) = self.pending.remove(reply.id()) else {
            return vec![Act::Fault("response to no outstanding call")];
        };
        // An answer naming a call that never reached the wire is not a
        // Response: JSON-RPC 2.0 §5 requires a Response's id to be the id
        // of a Request the peer received, and this one was never sent. It
        // is still sitting in `backlog`, so crediting a slot it never
        // spent would put it on the wire with no `pending` entry - its
        // real answer would then fault the session, after a fabricated
        // result had already been handed to the caller.
        if !p.sent {
            return vec![Act::Fault("answer for a call never sent")];
        }
        // The answer is the only thing that says the server has let this
        // call go, so it is the only thing that returns its slot -
        // abandoned or not. A caller giving up does not free the server.
        self.budget += 1;
        debug_assert!(
            self.budget <= CALL_BUDGET,
            "budget {} exceeded CALL_BUDGET {CALL_BUDGET}",
            self.budget
        );
        // A `-32000` says the peer is at its hard concurrency limit
        // (`SoftHardSemaphore(10, 20)`, `api/base/server/ws_handler
        // /rpc.py`). Arm the backoff *before* draining, or this answer's
        // freed slot immediately sends a queued call into the same
        // refusal. Abandoned or not: the refusal describes the server,
        // not the call.
        let refused = matches!(
            reply.outcome(),
            Outcome::Failure(e)
                if e.code() == crate::error::TOO_MANY_CONCURRENT_CALLS
        );
        if refused {
            self.backoff_armed = true;
            self.backoff_step = self.backoff_step.saturating_add(1);
            // The limit is the server's, and this client is not the only
            // one against it, so the call was refused for load it did not
            // create and its caller has nothing to fix. Reissue it after
            // the pause instead of reporting it - `__aenter__` raises
            // above `hardlimit` before `counter += 1` and before
            // `method.call` (`middlewared/utils/lock.py`), so the method
            // did not run and a reissue cannot double it.
            if !p.abandoned
                && p.retries < MAX_CALL_RETRIES
                && let Some(frame) = p.retry_frame.clone()
            {
                self.queued_bytes =
                    self.queued_bytes.saturating_add(frame.len());
                self.backlog.push_front((reply.id().clone(), frame));
                self.pending.insert(
                    reply.id().clone(),
                    Pending {
                        sent: false,
                        retries: p.retries + 1,
                        ..p
                    },
                );
                // No `drain_backlog`: the backoff is armed, so it would
                // send nothing, and the entry is back in `pending` for
                // `expire` to release when the pause ends.
                return Vec::new();
            }
        } else {
            // Any answer that is not a refusal means the peer has room
            // again, so the next refusal starts from the base delay.
            self.backoff_step = 0;
        }
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
                // The server echoes the options it put in force, and the
                // echo is the authority - not the request. Asking for
                // modern job answering and being given legacy answering
                // silently would make every job call's result the job's
                // integer id where the caller expects the job's result.
                Ok(raw) => match legacy_jobs_in_force(&raw) {
                    Some(false) => acts.push(Act::Ready),
                    Some(true) => {
                        acts.push(Act::SetupFailed(ApiError::Protocol(
                            "core.set_options answered legacy_jobs: true \
                             after this session asked for modern job \
                             answering",
                        )))
                    }
                    None => acts.push(Act::SetupFailed(ApiError::Protocol(
                        "core.set_options did not report legacy_jobs, so \
                         this API version cannot honour it and the \
                         session would decode job ids as results",
                    ))),
                },
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
        // §5.5.1: "MUST NOT send any more data frames after sending a
        // Close frame". A queued call is a data frame, and the answer that
        // frees a budget slot can arrive after our Close has gone out -
        // the peer's own close, echoed here, or a local `close()` - so
        // without this the next `on_answer` puts a fresh `core.*` request
        // on a connection this endpoint already considers closed. The
        // server role refuses the whole class one level up
        // (`OP_TEXT | OP_CONT if closing`, `server.rs`); the client keeps
        // reading, because an answer that has already arrived is worth
        // delivering, and refuses only the sending. `fail_all` clears the
        // backlog and fails those calls when the transport close lands.
        if matches!(self.phase, Phase::Closing) {
            return acts;
        }
        // Backing off from a `-32000`. The queued calls are exactly the
        // ones that would walk into the same wall, and the server clears
        // its own backlog by finishing work, not by being asked again.
        if self.backing_off() {
            return acts;
        }
        while self.budget > 0 {
            let Some((id, frame)) = self.backlog.pop_front() else {
                break;
            };
            self.queued_bytes = self.queued_bytes.saturating_sub(frame.len());
            // A queued call that timed out before it ever reached the
            // wire: drop it here, and free its tombstone - no answer can
            // exist for a call that was never sent.
            if self.pending.get(&id).is_some_and(|p| p.abandoned) {
                self.pending.remove(&id);
                continue;
            }
            // A queued frame whose `pending` entry has gone is not
            // sendable: nothing would correlate its answer. Drop it rather
            // than emitting a call the session cannot account for.
            if !self.pending.contains_key(&id) {
                continue;
            }
            self.budget -= 1;
            if let Some(p) = self.pending.get_mut(&id) {
                p.sent = true;
            }
            acts.push(Act::Send(ws::encode_frame(
                OP_TEXT,
                &frame,
                ws::mask_key(),
            )));
        }
        acts
    }

    /// Whether a `-32000` backoff is holding this session's sends. True
    /// from the moment the refusal is parsed (`backoff_armed`) until
    /// `expire` retires the instant it was given, so there is no window
    /// between the two in which a send slips out.
    fn backing_off(&self) -> bool {
        self.backoff_armed || self.backoff_until.is_some()
    }

    /// The server-issued ident for `sub`, once subscribed.
    pub(crate) fn sub_ident(&self, sub: SubscriptionId) -> Option<&str> {
        self.subs.get(&sub).and_then(|e| e.ident.as_deref())
    }

    /// This session's *ordinary* outbound cap, for sizing a `core.bulk`
    /// flush chunk. `core.bulk` is not one of the methods middlewared
    /// exempts, so the ordinary cap is the one that binds it.
    pub(crate) fn max_outbound(&self) -> usize {
        self.max_outbound
    }

    /// The earliest live call deadline, for the pump's wait computation.
    /// A running backoff is one of them: nothing else would wake the pump
    /// to release the calls it is holding.
    pub(crate) fn next_deadline(&self) -> Option<Instant> {
        self.pending
            .values()
            .filter(|p| !p.abandoned)
            .filter_map(|p| p.deadline)
            .chain(self.backoff_until)
            .min()
    }

    /// Time out every live call whose deadline has passed. The entries
    /// stay as tombstones (their answers are still owed by the server and
    /// must be recognized when they land); a tombstone still in the
    /// backlog is dropped at drain instead.
    ///
    /// Abandoning a call does **not** return its concurrency slot. The
    /// caller has been handed [`ApiError::Timeout`] and is free to issue
    /// another call, but middlewared was told nothing and is still running
    /// the method inside its semaphore; crediting the slot here would put
    /// more work in front of the server than [`CALL_BUDGET`] and walk into
    /// the `-32000` that ceiling exists to stay clear of. The slot comes
    /// back where every slot does, in `on_answer`, when the answer this
    /// tombstone is waiting for lands.
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
        // The backoff's clock. `on_answer` armed it without one; give it
        // an instant here, and retire it once that instant has passed so
        // the drain below can run.
        if self.backoff_armed {
            let step = self.backoff_step.saturating_sub(1).min(16);
            let full =
                BACKOFF_BASE.saturating_mul(1u32 << step).min(BACKOFF_CAP);
            // Equal jitter: half the window, plus a random part of the
            // rest. The limit is shared, so every client against it is
            // refused at the same moment and a fixed delay would march
            // them back in step - the thundering herd re-forming on each
            // retry. Entropy from `getrandom(2)`, the source the frame
            // masks already use, rather than a new dependency.
            let r = u32::from_be_bytes(ws::mask_key());
            let half = full / 2;
            let delay = half
                + half.mul_f64(f64::from(r) / f64::from(u32::MAX)).min(half);
            // `checked_add` for the reason every other deadline site uses
            // it: `Instant + Duration` panics on overflow.
            self.backoff_until = now.checked_add(delay);
            self.backoff_armed = false;
        } else if self.backoff_until.is_some_and(|t| t <= now) {
            self.backoff_until = None;
        }
        acts.extend(self.drain_backlog());
        acts
    }

    /// Every live call, failed at once - the session is going away.
    /// Fail every call this session has accepted, and keep serving.
    ///
    /// The teardown twin below drains `pending` outright, because a
    /// session being dropped will never see another answer. This one is
    /// called on a session that survives, so **a sent call keeps its
    /// entry and its slot**: telling the caller the call is over says
    /// nothing to the server, which is still running it and still owes an
    /// answer. Dropping the entry makes that answer match nothing and
    /// fault the session with "response to no outstanding call" - the
    /// exact teardown this is here to avoid. Marking it abandoned is what
    /// `expire` does for the same reason, and the slot comes back where
    /// every other slot does, in `on_answer`.
    ///
    /// `Kind::SetOptions` is not failed at all: it has no caller-visible
    /// id to report against. A setup that never completes is what
    /// `connect_timeout` is for.
    pub(crate) fn fail_outstanding(&mut self, why: &'static str) -> Vec<Act> {
        let mut acts = Vec::new();
        self.pending.retain(|_, p| {
            if p.sent {
                if !p.abandoned && !matches!(p.kind, Kind::SetOptions) {
                    acts.push(Act::CallDone {
                        call: p.call,
                        result: Err(ApiError::Protocol(why)),
                    });
                    p.abandoned = true;
                }
                return true;
            }
            // Never reached the wire, so nothing is owed for it and it
            // holds no slot. Its frame is in the backlog being cleared
            // just below.
            if !p.abandoned && !matches!(p.kind, Kind::SetOptions) {
                acts.push(Act::CallDone {
                    call: p.call,
                    result: Err(ApiError::Protocol(why)),
                });
            }
            false
        });
        self.backlog.clear();
        self.queued_bytes = 0;
        acts
    }

    pub(crate) fn fail_all(&mut self, why: &str) -> Vec<Act> {
        self.frag = None;
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
        self.queued_bytes = 0;
        acts
    }
}

/// What `core.set_options` reports it put in force, or `None` if it
/// reports nothing.
///
/// middlewared echoes the applied options and the reference Python client
/// reads `legacy_jobs` back out of that echo rather than trusting its own
/// request (`truenas_api_client/__init__.py`, the `_set_options_call`
/// arm).
///
/// **`None` is a refusal, not a shrug.** Every API version that honours
/// the option answers with a required object -
/// `CoreSetOptionsResult { result: CoreOptions }`, and `CoreOptions`
/// declares `legacy_jobs` (`middlewared/api/v26_0_0/core.py`). A version
/// that does not honour it is exactly the one that answers nothing:
/// `api/v25_04_1/core.py` accepts only `py_exceptions` and drops the rest
/// (`extra="ignore"`), and `CoreSetOptionsResult.to_previous` in
/// `api/v25_10_0/core.py` rewrites the echo to `null` on the way down.
/// Its `App.legacy_jobs` then stays at its default of `true`. So a silent
/// echo means legacy answering is in force, and the session must not
/// proceed believing otherwise. [`validate_endpoint`] refuses those API
/// versions up front; this is the check that does not depend on the
/// endpoint being read correctly.
fn legacy_jobs_in_force(raw: &RawValue) -> Option<bool> {
    serde_json::from_str::<serde_json::Value>(raw.get())
        .ok()?
        .get("legacy_jobs")?
        .as_bool()
}

#[cfg(test)]
mod tests {
    use super::*;
    use truenas_ros::ws::FrameHead;

    fn session() -> Session {
        let mut s = Session::new(
            "test-key".into(),
            false,
            65_536,
            1024,
            256,
            16 * 1024 * 1024,
        );
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
        let mut s =
            Session::new("k".into(), false, 65_536, 8, 256, 16 * 1024 * 1024);
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

    /// middlewared grants the extended cap per *method*, after parsing -
    /// `parse_message` returns early for a whitelisted one and applies
    /// the ordinary cap to everything else - so a single per-session
    /// number cannot mirror it. An upload gets the extended cap without
    /// the session's other calls getting it too.
    #[test]
    fn the_extended_cap_applies_to_the_upload_methods_only() {
        use serde_json::value::RawValue;
        let mut s = Session::new(
            "k".into(),
            false,
            65_536,
            1024,
            256,
            16 * 1024 * 1024,
        );
        s.phase = Phase::Open;
        // A params array comfortably over the ordinary 64 KiB cap and
        // under the extended 2 MiB one.
        let big = format!("[\"{}\"]", "x".repeat(100_000));
        let args = RawValue::from_string(big).unwrap();
        let mut n = 0;
        let mut go = |s: &mut Session, method: &str| {
            n += 1;
            s.submit(crate::CallId(n), Kind::User, method, &args, None)
        };
        for method in crate::MSG_SIZE_EXTENDED_METHODS {
            assert!(
                matches!(go(&mut s, method).as_deref(), Ok([Act::Send(_)])),
                "{method} must be allowed the extended cap"
            );
        }
        match go(&mut s, "pool.dataset.create") {
            Err(ApiError::TooLarge { cap, .. }) => {
                assert_eq!(cap, crate::MIDDLEWARE_MSG_CAP)
            }
            other => panic!("an ordinary method must be refused: {other:?}"),
        }
        // The exemption is a larger cap, not the absence of one:
        // `parse_message` refuses above it before it reads the method
        // at all.
        let huge =
            format!("[\"{}\"]", "x".repeat(crate::MIDDLEWARE_MSG_CAP_EXTENDED));
        let huge = RawValue::from_string(huge).unwrap();
        match s.submit(
            crate::CallId(99),
            Kind::User,
            "filesystem.file_receive",
            &huge,
            None,
        ) {
            Err(ApiError::TooLarge { cap, .. }) => {
                assert_eq!(cap, crate::MIDDLEWARE_MSG_CAP_EXTENDED)
            }
            other => panic!("the extended cap still bounds: {other:?}"),
        }
    }

    /// The backlog has two caps and refuses on whichever trips first.
    /// The count is a pipelining depth; the bytes are what bound memory,
    /// because a frame's ceiling is per method and the upload methods
    /// carry 32x the ordinary one - so a count alone leaves the worst
    /// case at the wrong number by that factor.
    #[test]
    fn a_full_backlog_is_refused_by_bytes_as_well_as_by_count() {
        use serde_json::value::RawValue;
        // Room for many frames, but only a little memory.
        let mut s =
            Session::new("k".into(), false, 2_097_152, 1024, 1024, 200_000);
        s.phase = Phase::Open;
        let big = format!("[\"{}\"]", "x".repeat(60_000));
        let args = RawValue::from_string(big).unwrap();
        let mut n = 0;
        let mut put = |s: &mut Session| {
            n += 1;
            s.submit(crate::CallId(n), Kind::User, "core.ping", &args, None)
        };
        // Spend the budget on the wire, then fill the queue by bytes.
        for _ in 0..CALL_BUDGET {
            put(&mut s).expect("under budget");
        }
        let mut queued = 0;
        loop {
            match put(&mut s) {
                Ok(_) => queued += 1,
                Err(ApiError::QueueFull { cap, .. }) => {
                    assert_eq!(cap, 200_000, "the byte cap is what refused");
                    break;
                }
                other => panic!("unexpected: {other:?}"),
            }
            assert!(queued < 50, "the byte cap must bite long before 1024");
        }
        assert!(
            s.queued_bytes <= 200_000,
            "the queue stays inside its byte bound: {}",
            s.queued_bytes
        );
        // Draining gives the bytes back.
        s.budget = CALL_BUDGET;
        let _ = s.drain_backlog();
        assert_eq!(s.queued_bytes, 0, "a drained queue charges nothing");
    }

    /// JSON-RPC 2.0 §5 reserves `id: null` for an error the server could
    /// not attribute to a request - a parse failure, or its own message
    /// failing to serialise. middlewared answers exactly that and keeps
    /// the connection serving, so treating it as "a response to no
    /// outstanding call" would fail every healthy call in flight over a
    /// message the server has already moved past.
    #[test]
    fn a_null_id_error_reports_without_killing_the_session() {
        let mut s = session();
        let body = r#"{"jsonrpc":"2.0","error":{"code":-32700,
                       "message":"Parse error"},"id":null}"#;
        let acts = s.on_frame(
            head(true, OP_TEXT, body.len()),
            body.as_bytes().to_vec(),
        );
        match acts.as_slice() {
            [Act::ServerError(e)] => {
                assert!(
                    format!("{e}").contains("Parse error"),
                    "the server's report reaches the caller: {e}"
                );
            }
            other => panic!("expected a report, not a teardown: {other:?}"),
        }
        assert!(!matches!(s.phase, Phase::Closing), "the session stays open");
    }

    /// An `id: null` Response names no call of ours, and under 2.0 that
    /// has exactly one meaning: the server could not work out which
    /// request the error belongs to. The call that provoked it will
    /// therefore never be answered - so it, and every other call in
    /// flight, is failed to its caller.
    ///
    /// The tombstones stay. The server was told nothing by our giving up
    /// and is still running those calls, so their answers are still
    /// coming: dropping the entries makes each one fault the session with
    /// "response to no outstanding call", which is the teardown this
    /// tolerance exists to prevent. The slots come back with the answers.
    #[test]
    fn a_null_id_error_fails_the_calls_in_flight_but_keeps_their_tombstones() {
        use serde_json::value::RawValue;
        let mut s = session();
        let args = RawValue::from_string("[]".to_owned()).unwrap();
        let mut ids = Vec::new();
        for i in 0..3u64 {
            let acts = s
                .submit(crate::CallId(i), Kind::User, "core.ping", &args, None)
                .expect("submits");
            let [Act::Send(frame)] = acts.as_slice() else {
                panic!("call {i} should have gone out: {acts:?}")
            };
            let (_op, payload) = unmask(frame);
            let v: serde_json::Value =
                serde_json::from_slice(&payload).expect("a JSON request");
            ids.push(v.get("id").cloned().expect("a request carries an id"));
        }
        assert_eq!(s.budget, CALL_BUDGET - 3);

        let body = r#"{"jsonrpc":"2.0","error":{"code":-32700,
                       "message":"Parse error"},"id":null}"#;
        let acts = s.on_frame(
            head(true, OP_TEXT, body.len()),
            body.as_bytes().to_vec(),
        );
        let done = acts
            .iter()
            .filter(|a| matches!(a, Act::CallDone { .. }))
            .count();
        assert!(
            matches!(acts.first(), Some(Act::ServerError(_))),
            "the server's report still surfaces: {acts:?}"
        );
        assert_eq!(done, 3, "every call in flight is answered: {acts:?}");
        assert_eq!(
            s.pending.len(),
            3,
            "the server still owes three answers; the tombstones wait"
        );
        assert_eq!(s.budget, CALL_BUDGET - 3, "and still holds their slots");
        assert!(
            !matches!(s.phase, Phase::Closing),
            "the session keeps serving"
        );

        // The answers land. Each is recognised and dropped, and each
        // returns its slot. A fault here is the defect.
        for (n, id) in ids.iter().enumerate() {
            let body =
                serde_json::json!({"jsonrpc":"2.0","id":id,"result":null})
                    .to_string();
            let len = body.len();
            let acts = s.on_frame(head(true, OP_TEXT, len), body.into_bytes());
            assert!(
                acts.is_empty(),
                "late answer {n} must be dropped, not faulted: {acts:?}"
            );
            assert_eq!(s.budget, CALL_BUDGET - 2 + n);
        }
        assert!(s.pending.is_empty(), "every tombstone retired");
        assert!(
            !matches!(s.phase, Phase::Closing),
            "and the session is still serving"
        );
    }

    /// A session still in setup keeps its `core.set_options` tombstone
    /// through the same report. Dropping it would leave the setup answer
    /// matching no entry, and the session would then fault itself with
    /// "response to no outstanding call" - a diagnosis of the wrong
    /// thing. Its budget slot stays spent with it.
    #[test]
    fn a_null_id_error_does_not_strand_a_session_still_in_setup() {
        let mut s =
            Session::new("k".into(), false, 65_536, 65_536, 256, 1 << 20);
        // The setup call, exactly as `on_head` issues it once the 101
        // validates: `core.set_options` under `Kind::SetOptions`.
        let params = serde_json::value::RawValue::from_string(
            r#"[{"legacy_jobs":false}]"#.to_owned(),
        )
        .unwrap();
        s.phase = Phase::Open;
        s.submit(
            crate::CallId(0),
            Kind::SetOptions,
            "core.set_options",
            &params,
            None,
        )
        .expect("the setup call goes out");
        assert_eq!(s.pending.len(), 1, "the setup call is outstanding");

        let body = r#"{"jsonrpc":"2.0","error":{"code":-32700,
                       "message":"Parse error"},"id":null}"#;
        let _ = s.on_frame(
            head(true, OP_TEXT, body.len()),
            body.as_bytes().to_vec(),
        );
        assert_eq!(
            s.pending.len(),
            1,
            "the setup tombstone survives, or its answer faults the session"
        );
        assert_eq!(
            s.budget,
            CALL_BUDGET - 1,
            "and the slot it holds is not handed back twice"
        );
    }

    /// The inbound cap covers an unfragmented message, not only a
    /// reassembled one.
    #[test]
    fn the_inbound_cap_covers_an_unfragmented_message() {
        let mut s =
            Session::new("k".into(), false, 65_536, 64, 256, 16 * 1024 * 1024);
        s.phase = Phase::Open;
        match s
            .on_frame(head(true, OP_TEXT, 256), vec![b'a'; 256])
            .as_slice()
        {
            [Act::Fault(why)] => {
                assert_eq!(*why, "message exceeds the inbound cap")
            }
            other => panic!("an over-cap message must fault: {other:?}"),
        }
    }

    /// §5.5.1: no data frame goes out after our Close.
    ///
    /// The backlog is the one place a data frame can be born from an
    /// *inbound* event: an answer frees a concurrency slot, `on_answer`
    /// drains the queue, and each drained call is a fresh request frame.
    /// Nothing gated that on the phase, so a Response arriving between our
    /// Close and the transport teardown put a new `core.ping` on the wire.
    #[test]
    fn no_data_frame_goes_out_after_our_close() {
        use serde_json::value::RawValue;
        let mut s = session();
        let args = RawValue::from_string("[]".to_owned()).unwrap();
        for i in 0..CALL_BUDGET {
            let _ = s
                .submit(
                    crate::CallId(100 + i as u64),
                    Kind::User,
                    "core.ping",
                    &args,
                    None,
                )
                .expect("under budget");
        }
        let _ = s
            .submit(crate::CallId(999), Kind::User, "core.ping", &args, None)
            .expect("queues");
        assert_eq!(s.backlog.len(), 1, "one call is queued");

        // The peer closes; we echo and go to Closing.
        let close = s.on_frame(head(true, OP_CLOSE, 2), vec![0x03, 0xE8]);
        assert!(matches!(close.as_slice(), [Act::Send(_), Act::PeerClosing]));
        assert!(matches!(s.phase, Phase::Closing));

        // Now one of the outstanding answers lands.
        let answered = s
            .pending
            .iter()
            .find(|(_, p)| p.sent)
            .map(|(k, _)| k.clone())
            .expect("a sent call");
        let body = serde_json::json!({
            "jsonrpc": "2.0", "id": answered, "result": "pong",
        })
        .to_string();
        let len = body.len();
        let acts = s.on_frame(head(true, OP_TEXT, len), body.into_bytes());
        let sent: Vec<u8> = acts
            .iter()
            .filter_map(|a| match a {
                Act::Send(b) => Some(b[0] & 0x0F),
                _ => None,
            })
            .collect();
        assert!(
            sent.is_empty(),
            "no frame may follow our Close; sent opcodes {sent:?}"
        );
        // The answer itself is still delivered - only the sending stops.
        assert!(
            acts.iter().any(|a| matches!(a, Act::CallDone { .. })),
            "the answer that already arrived is still surfaced: {acts:?}"
        );
        assert_eq!(s.backlog.len(), 1, "the queued call stays queued");
    }

    /// The reachable half of the same rule: `expire` drains the backlog
    /// too, and `pump` runs it before it reaps a single completion.
    ///
    /// So with `call_timeout` set and more than `CALL_BUDGET` calls in
    /// flight, one `close()` + one `pump()` was enough to put a queued
    /// request on the wire after the Close - and the caller was told that
    /// same call had failed `Closed`, while its frame was already gone.
    #[test]
    fn expire_does_not_drain_the_backlog_after_our_close() {
        use serde_json::value::RawValue;
        use std::time::Duration;
        let mut s = session();
        let args = RawValue::from_string("[]".to_owned()).unwrap();
        let t0 = Instant::now();
        // Budget spent, every one of them due to time out...
        for i in 0..CALL_BUDGET {
            let _ = s
                .submit(
                    crate::CallId(100 + i as u64),
                    Kind::User,
                    "core.ping",
                    &args,
                    Some(t0),
                )
                .expect("under budget");
        }
        // ...and one queued call that is NOT due, so expiry frees slots
        // for it rather than dropping it.
        let _ = s
            .submit(crate::CallId(999), Kind::User, "core.ping", &args, None)
            .expect("queues");
        assert_eq!(s.backlog.len(), 1);

        let close = s.on_frame(head(true, OP_CLOSE, 2), vec![0x03, 0xE8]);
        assert!(matches!(close.as_slice(), [Act::Send(_), Act::PeerClosing]));

        let acts = s.expire(t0 + Duration::from_secs(1));
        let sent: Vec<u8> = acts
            .iter()
            .filter_map(|a| match a {
                Act::Send(b) => Some(b[0] & 0x0F),
                _ => None,
            })
            .collect();
        assert!(
            sent.is_empty(),
            "expire must not put a frame on a closing connection; sent \
             opcodes {sent:?}"
        );
        assert_eq!(s.backlog.len(), 1, "the queued call stays queued");
    }

    /// A first fragment is held until a continuation arrives, so it is
    /// bounded where it is stored, not only where the pieces are joined -
    /// otherwise a peer opens a fragmented message, sends nothing more,
    /// and holds whatever it declared for the connection's life. Closing
    /// releases it: no continuation can arrive after that.
    #[test]
    fn an_open_reassembly_is_bounded_and_released_at_close() {
        let mut s =
            Session::new("k".into(), false, 65_536, 64, 256, 16 * 1024 * 1024);
        s.phase = Phase::Open;
        // Over the cap in the very first fragment.
        match s
            .on_frame(head(false, OP_TEXT, 256), vec![b'a'; 256])
            .as_slice()
        {
            [Act::Fault(why)] => {
                assert_eq!(*why, "fragmented message exceeds the inbound cap")
            }
            other => {
                panic!("an over-cap first fragment must fault: {other:?}")
            }
        }
        assert!(s.frag.is_none(), "a refused fragment is not stored");

        // Under the cap: held, then released when the peer closes.
        let mut s =
            Session::new("k".into(), false, 65_536, 64, 256, 16 * 1024 * 1024);
        s.phase = Phase::Open;
        assert!(
            s.on_frame(head(false, OP_TEXT, 32), vec![b'a'; 32])
                .is_empty()
        );
        assert!(s.frag.is_some(), "the control: it really is held");
        let _ =
            s.on_frame(head(true, OP_CLOSE, 2), 1000u16.to_be_bytes().to_vec());
        assert!(s.frag.is_none(), "closing releases the reassembly");
    }

    /// Past the concurrency budget calls queue; past the queue's own
    /// bound they are refused, in `queue_bulk`'s vocabulary. Without the
    /// bound a caller that ignores the queueing holds one encoded frame
    /// per call, up to `max_outbound` each, with nothing to stop it.
    #[test]
    fn a_full_backlog_refuses_rather_than_growing() {
        use serde_json::value::RawValue;
        const QUEUED: usize = 4;
        let mut s =
            Session::new("k".into(), false, 65_536, 1024, QUEUED, usize::MAX);
        s.phase = Phase::Open;
        let args = RawValue::from_string("[]".to_owned()).unwrap();
        let put = |s: &mut Session, i: usize| {
            s.submit(
                crate::CallId(i as u64),
                Kind::User,
                "core.ping",
                &args,
                None,
            )
        };
        // The budget's worth go to the wire.
        for i in 0..CALL_BUDGET {
            let acts = put(&mut s, i).expect("under budget");
            assert!(
                matches!(acts.as_slice(), [Act::Send(_)]),
                "call {i} should have gone out"
            );
        }
        // The queue's worth are accepted and held.
        for i in 0..QUEUED {
            let acts = put(&mut s, CALL_BUDGET + i).expect("queues");
            assert!(acts.is_empty(), "a queued call sends nothing");
        }
        assert_eq!(s.backlog.len(), QUEUED);
        // One more is refused, and leaves nothing behind: no tombstone
        // for an answer to find, and no growth.
        let pending_before = s.pending.len();
        match put(&mut s, 999) {
            Err(ApiError::QueueFull { cap, .. }) => {
                assert_eq!(cap, QUEUED)
            }
            other => panic!("expected QueueFull, got {other:?}"),
        }
        assert_eq!(s.backlog.len(), QUEUED, "a refusal does not queue");
        assert_eq!(
            s.pending.len(),
            pending_before,
            "a refusal leaves no tombstone"
        );
    }

    /// A locally timed-out call returns its concurrency slot at `expire`,
    /// keeps its tombstone so a late answer is still recognised, and that
    /// late answer credits nothing a second time.
    ///
    /// Before the fix this covers, `expire` left every slot spent, so
    /// `CALL_BUDGET` unanswered timeouts pinned `budget` at 0 for the life
    /// of the session: later calls went to `backlog`, `drain_backlog` never
    /// ran (its guard is `while self.budget > 0`), and the session accepted
    /// calls and sent none with nothing surfaced to the caller.
    #[test]
    fn a_timed_out_call_frees_its_slot_and_a_late_answer_credits_once() {
        use serde_json::value::RawValue;
        let mut s = session();
        let args = RawValue::from_string("[]".to_owned()).unwrap();
        let past = Instant::now();

        // Fill the budget, every call already past its deadline. Keep the
        // ids so one can be answered late.
        let mut ids = Vec::new();
        for i in 0..CALL_BUDGET {
            let acts = s
                .submit(
                    crate::CallId(100 + i as u64),
                    Kind::User,
                    "core.ping",
                    &args,
                    Some(past),
                )
                .expect("submits under budget");
            let [Act::Send(frame)] = acts.as_slice() else {
                panic!("call {i} should have gone to the wire: {acts:?}")
            };
            let (_op, payload) = unmask(frame);
            let v: serde_json::Value =
                serde_json::from_slice(&payload).expect("a JSON request");
            ids.push(v.get("id").cloned().expect("a request carries an id"));
        }
        assert_eq!(s.budget, 0, "every slot is spent while the calls live");

        // The clock crosses every deadline.
        let later = past + std::time::Duration::from_secs(1);
        let acts = s.expire(later);
        assert_eq!(
            acts.len(),
            CALL_BUDGET,
            "every abandoned call surfaces its Timeout"
        );
        assert_eq!(
            s.pending.len(),
            CALL_BUDGET,
            "tombstones stay, so a late answer is still recognised"
        );
        assert_eq!(
            s.budget, 0,
            "the caller gave up; the server did not, so it still holds \
             every slot"
        );

        // So a further call is queued, not sent: the peer's concurrency
        // limit is counted by the peer, and it has not answered anything.
        let acts = s
            .submit(crate::CallId(999), Kind::User, "core.ping", &args, None)
            .expect("submits");
        assert!(acts.is_empty(), "queued behind the server's own work");
        assert_eq!(s.backlog.len(), 1);

        // The answer is what frees the server, so it is what frees the
        // slot - and it releases the queued call.
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": ids[0],
            "result": null,
        })
        .to_string();
        let len = body.len();
        let acts = s.on_frame(head(true, OP_TEXT, len), body.into_bytes());
        assert!(
            matches!(acts.as_slice(), [Act::Send(_)]),
            "the late answer's slot goes to the queued call: {acts:?}"
        );
        assert_eq!(s.budget, 0, "which spends it again immediately");
        assert!(s.backlog.is_empty(), "the backlog drained");
        assert_eq!(
            s.pending.len(),
            CALL_BUDGET,
            "one tombstone retired, one live call added"
        );
    }

    /// Read a request frame's `id` out of a `Send`.
    fn sent_id(acts: &[Act]) -> serde_json::Value {
        let [Act::Send(frame)] = acts else {
            panic!("expected exactly one Send: {acts:?}")
        };
        let (_op, payload) = unmask(frame);
        let v: serde_json::Value =
            serde_json::from_slice(&payload).expect("a JSON request");
        v.get("id").cloned().expect("a request carries an id")
    }

    /// Build a `-32000` answer for `id`.
    fn refusal(id: &serde_json::Value) -> String {
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {
                "code": crate::error::TOO_MANY_CONCURRENT_CALLS,
                "message": "Maximum number of concurrent calls (20) has \
                            exceeded",
            },
        })
        .to_string()
    }

    /// A `-32000` is the shared limit saying "not now", not a verdict on
    /// the call: middlewared raises it before entering the method
    /// (`SoftHardSemaphore.__aenter__` is above `hardlimit` before
    /// `counter += 1` and before `method.call`), so nothing ran. The call
    /// is reissued after a pause rather than reported, and while that
    /// pause runs nothing else goes out either - not the queued calls,
    /// and not a call submitted meanwhile on the slot the refusal itself
    /// just returned.
    #[test]
    fn a_concurrency_refusal_is_reissued_after_a_pause() {
        use serde_json::value::RawValue;
        let mut s = session();
        let args = RawValue::from_string("[]".to_owned()).unwrap();

        let mut ids = Vec::new();
        for i in 0..CALL_BUDGET {
            let acts = s
                .submit(
                    crate::CallId(100 + i as u64),
                    Kind::User,
                    "core.ping",
                    &args,
                    None,
                )
                .expect("submits under budget");
            ids.push(sent_id(&acts));
        }
        s.submit(crate::CallId(999), Kind::User, "core.ping", &args, None)
            .expect("submits");
        assert_eq!(s.backlog.len(), 1, "queued behind the budget");

        // The refusal lands.
        let body = refusal(&ids[0]);
        let len = body.len();
        let acts = s.on_frame(head(true, OP_TEXT, len), body.into_bytes());
        assert!(
            acts.is_empty(),
            "nothing is reported and nothing goes out: {acts:?}"
        );
        assert_eq!(s.backlog.len(), 2, "the refused call is requeued");
        let front: serde_json::Value = serde_json::from_slice(
            &s.backlog.front().expect("a queued frame").1,
        )
        .expect("a JSON request");
        assert_eq!(
            front.get("id"),
            Some(&ids[0]),
            "and requeued at the front, ahead of what was already waiting"
        );

        // A call submitted during the pause queues too: the refusal
        // returned a slot, so `submit` would otherwise find budget and go
        // straight out around the drain's gate.
        let acts = s
            .submit(crate::CallId(1000), Kind::User, "core.ping", &args, None)
            .expect("submits");
        assert!(acts.is_empty(), "a fresh call queues too: {acts:?}");
        assert_eq!(s.backlog.len(), 3);

        // `expire` gives the pause a clock and publishes it.
        let t0 = Instant::now();
        assert!(s.expire(t0).is_empty(), "still paused");
        let until = s.next_deadline().expect("the pause is a pump deadline");
        assert!(until > t0 && until <= t0 + BACKOFF_CAP, "bounded");
        assert!(
            s.expire(until - Duration::from_millis(1)).is_empty(),
            "the pause holds"
        );
        assert_eq!(s.backlog.len(), 3, "all three still held");

        // One answer came back, so one slot did: the reissue goes, and
        // the rest wait for further answers.
        let acts = s.expire(until);
        assert_eq!(
            sent_id(&acts),
            ids[0],
            "the reissued call is the one that goes"
        );
        assert_eq!(s.backlog.len(), 2, "held by the budget, not the pause");
        assert_eq!(
            s.next_deadline(),
            None,
            "and the pause is no longer a deadline"
        );
    }

    /// A call refused past [`MAX_CALL_RETRIES`] reaches its caller. The
    /// reissue is a courtesy against a busy peer, not an unbounded loop -
    /// a session with no `call_timeout` has nothing else to end it.
    #[test]
    fn a_call_refused_past_its_retry_bound_reaches_its_caller() {
        use serde_json::value::RawValue;
        let mut s = session();
        let args = RawValue::from_string("[]".to_owned()).unwrap();

        let acts = s
            .submit(crate::CallId(1), Kind::User, "core.ping", &args, None)
            .expect("submits");
        let mut id = sent_id(&acts);

        for attempt in 0..MAX_CALL_RETRIES {
            let body = refusal(&id);
            let len = body.len();
            let acts = s.on_frame(head(true, OP_TEXT, len), body.into_bytes());
            assert!(
                acts.is_empty(),
                "reissue {attempt} must not report: {acts:?}"
            );
            // Clear the pause; the reissue goes out with the same id.
            let t0 = Instant::now();
            s.expire(t0);
            let until = s.next_deadline().expect("a pause");
            let acts = s.expire(until);
            assert_eq!(sent_id(&acts), id, "reissued under its own id");
            id = sent_id(&acts);
        }

        // One more refusal, and the caller hears about it.
        let body = refusal(&id);
        let len = body.len();
        let acts = s.on_frame(head(true, OP_TEXT, len), body.into_bytes());
        assert!(
            matches!(
                acts.as_slice(),
                [Act::CallDone {
                    result: Err(ApiError::TooManyConcurrentCalls { .. }),
                    ..
                }]
            ),
            "the bound is reached and the refusal surfaces: {acts:?}"
        );
        assert!(s.backlog.is_empty(), "and it is not requeued again");
    }

    /// Consecutive refusals lengthen the pause, and an answer that is not
    /// a refusal resets it - without that, a session that hit the limit
    /// once carries the longest delay for the rest of its life.
    ///
    /// Each pause is jittered, so the assertion is on the window rather
    /// than on an exact figure: equal jitter puts it in
    /// `[full/2, full]` for that step's `full`.
    #[test]
    fn the_backoff_grows_and_an_ordinary_answer_resets_it() {
        use serde_json::value::RawValue;
        let mut s = session();
        let args = RawValue::from_string("[]".to_owned()).unwrap();

        // Answer one call and return the pause that answer produced.
        let answer = |s: &mut Session, n: u64, refused: bool| -> Duration {
            let acts = s
                .submit(crate::CallId(n), Kind::User, "core.ping", &args, None)
                .expect("submits");
            let id = sent_id(&acts);
            let body = if refused {
                refusal(&id)
            } else {
                serde_json::json!({"jsonrpc":"2.0","id":id,"result":null})
                    .to_string()
            };
            let len = body.len();
            s.on_frame(head(true, OP_TEXT, len), body.into_bytes());
            let t0 = Instant::now();
            s.expire(t0);
            let d = s.next_deadline().map_or(Duration::ZERO, |t| t - t0);
            // Clear whatever pause was set, so the next measurement is
            // not taken through this one.
            s.expire(t0 + d);
            d
        };
        // The window `full` for the nth consecutive refusal.
        let window = |n: u32| -> Duration {
            BACKOFF_BASE.saturating_mul(1 << n).min(BACKOFF_CAP)
        };
        let in_window = |d: Duration, n: u32| {
            let full = window(n);
            assert!(
                d >= full / 2 && d <= full,
                "refusal {} paused {d:?}, outside [{:?}, {full:?}]",
                n + 1,
                full / 2
            );
        };

        in_window(answer(&mut s, 1, true), 0);
        in_window(answer(&mut s, 2, true), 1);
        in_window(answer(&mut s, 3, true), 2);

        // A good answer resets the exponent.
        assert_eq!(answer(&mut s, 4, false), Duration::ZERO, "no pause");
        in_window(answer(&mut s, 5, true), 0);

        // And the pause is actually jittered, not merely inside the
        // window a fixed delay would also satisfy. Every client against
        // this shared limit is refused at the same moment; identical
        // delays march them back in step, which is the herd re-forming.
        // A fresh session per sample: a reissued call this test never
        // answers would hold its slot and starve the next submission.
        let first_pause = |n: u64| -> Duration {
            let mut s = session();
            let args = RawValue::from_string("[]".to_owned()).unwrap();
            let acts = s
                .submit(crate::CallId(n), Kind::User, "core.ping", &args, None)
                .expect("submits");
            let body = refusal(&sent_id(&acts));
            let len = body.len();
            s.on_frame(head(true, OP_TEXT, len), body.into_bytes());
            let t0 = Instant::now();
            s.expire(t0);
            s.next_deadline().map_or(Duration::ZERO, |t| t - t0)
        };
        let seen: Vec<Duration> = (0..8u64).map(first_pause).collect();
        assert!(
            seen.iter().any(|d| *d != seen[0]),
            "eight first-step pauses were all {:?}: no jitter",
            seen[0]
        );
    }

    /// A peer that answers an id it was never sent must be refused, not
    /// believed. `submit` inserts into `pending` for the backlogged branch
    /// too, so before the fix this covers, such an answer refunded a slot
    /// the call never spent, handed the caller a fabricated `CallDone`,
    /// let `drain_backlog` put the call on the wire with no `pending`
    /// entry, and then faulted the whole session when the genuine answer
    /// arrived - failing every other in-flight call with it.
    #[test]
    fn an_answer_for_a_never_sent_call_is_refused() {
        use serde_json::value::RawValue;
        let mut s = session();
        let args = RawValue::from_string("[]".to_owned()).unwrap();

        // Fill the budget, then one more so it is queued rather than sent.
        for i in 0..CALL_BUDGET {
            let acts = s
                .submit(
                    crate::CallId(100 + i as u64),
                    Kind::User,
                    "core.ping",
                    &args,
                    None,
                )
                .expect("submits under budget");
            assert!(matches!(acts.as_slice(), [Act::Send(_)]), "call {i}");
        }
        let acts = s
            .submit(crate::CallId(999), Kind::User, "core.ping", &args, None)
            .expect("submits");
        assert!(acts.is_empty(), "the ninth call is queued, not sent");
        assert_eq!(s.backlog.len(), 1);
        let queued_id = s.backlog.front().expect("a queued frame").0.clone();
        let budget_before = s.budget;

        // The peer answers the id it has not been sent.
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": queued_id,
            "result": "early",
        })
        .to_string();
        let len = body.len();
        let acts = s.on_frame(head(true, OP_TEXT, len), body.into_bytes());

        assert!(
            matches!(acts.as_slice(), [Act::Fault(_)]),
            "an answer for a call never sent is a protocol fault: {acts:?}"
        );
        assert_eq!(
            s.budget, budget_before,
            "no slot is credited for a call that never spent one"
        );
    }

    /// §7.4.1: 1005 is a reserved value an endpoint MUST NOT set as a
    /// status code, so the echo answers 1002 while the report still names
    /// what the peer actually sent. Same for a malformed one-byte body and
    /// a reason that is not UTF-8 (§5.5.1, §8.1).
    #[test]
    fn a_close_code_no_endpoint_may_send_is_not_echoed_back() {
        for code in [1004u16, 1005, 1006, 1015, 0, 2999] {
            let mut s = session();
            let acts = s
                .on_frame(head(true, OP_CLOSE, 2), code.to_be_bytes().to_vec());
            match acts.first() {
                Some(Act::Send(frame)) => {
                    let (op, payload) = unmask(frame);
                    assert_eq!(op, OP_CLOSE);
                    assert_eq!(
                        payload,
                        1002u16.to_be_bytes().to_vec(),
                        "peer sent {code}; the echo must be 1002"
                    );
                }
                other => panic!("expected a close echo, got {other:?}"),
            }
            assert!(
                s.close_reason
                    .as_deref()
                    .is_some_and(|r| r.contains(&code.to_string())),
                "the report still names {code}: {:?}",
                s.close_reason
            );
        }
        // A one-byte body is not a code (§5.5.1).
        let mut s = session();
        let acts = s.on_frame(head(true, OP_CLOSE, 1), vec![0x03]);
        match acts.first() {
            Some(Act::Send(frame)) => {
                assert_eq!(unmask(frame).1, 1002u16.to_be_bytes().to_vec());
            }
            other => panic!("expected a close echo, got {other:?}"),
        }
        assert!(
            s.close_reason
                .as_deref()
                .is_some_and(|r| r.contains("malformed")),
            "a one-byte body is reported as malformed: {:?}",
            s.close_reason
        );
        // A non-UTF-8 reason is answered 1007, not echoed as 1000.
        let mut s = session();
        let mut body = 1000u16.to_be_bytes().to_vec();
        body.extend_from_slice(&[0xFF, 0xFE, 0x80]);
        let acts = s.on_frame(head(true, OP_CLOSE, body.len()), body);
        match acts.first() {
            Some(Act::Send(frame)) => {
                assert_eq!(unmask(frame).1, 1007u16.to_be_bytes().to_vec());
            }
            other => panic!("expected a close echo, got {other:?}"),
        }
    }
}
