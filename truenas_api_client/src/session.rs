//! The per-connection session state machine, sans-io.
//!
//! Everything protocol-stateful lives here - handshake validation, the response/notification split, fragment
//! reassembly, the ping and close disciplines, call correlation, and the outbound budget against middlewared's
//! per-connection semaphore - as a pure machine: bytes and parsed frames in, [`Act`]s out. The driver (`ApiClient`)
//! owns the ring and performs the sends; this module can be unit-tested without a socket anywhere.

use crate::error::{ApiError, from_rpc_error};
use crate::{CallId, SubscriptionId};
use serde::Deserialize;
use serde_json::Value;
use serde_json::value::RawValue;
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};
use truenas_jsonrpc::{Answer, Call, Caller, Id, Incoming, Outcome};
use truenas_ros::ws::{self, FrameHead, HandshakeError, OP_BINARY, OP_CLOSE, OP_CONT, OP_PING, OP_PONG, OP_TEXT};

/// Concurrent calls this session keeps in flight; further calls queue behind the answers.
///
/// It mirrors middlewared's per-connection semaphore, soft 10 and hard 20 (`SoftHardSemaphore(10, 20)`,
/// `middlewared/api/base/server/ws_handler/rpc.py`), and sits under the soft limit because with `legacy_jobs` off a job
/// method holds its server-side slot for the whole job.
///
/// It counts what the server holds. A slot is spent when the request goes out and comes back only with its answer, so a
/// call that times out locally keeps its slot until middlewared answers it. Calls past the budget queue, and past the
/// queue's own bound they are refused with [`ApiError::QueueFull`].
pub const CALL_BUDGET: usize = 8;

/// What one pending entry is for, which decides how its answer surfaces.
pub(crate) enum Kind {
    /// The session-setup `core.set_options` call; its answer gates [`Act::Ready`].
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
    /// Whether this call's frame actually reached the wire. A call still in `backlog` has spent no budget, so timing it
    /// out must not credit a slot it never took.
    sent: bool,
    pub(crate) call: CallId,
    pub(crate) kind: Kind,
    /// When the call times out locally ([`ApiError::Timeout`]); the entry then stays as a tombstone so the late answer
    /// is recognized and dropped.
    pub(crate) deadline: Option<Instant>,
    pub(crate) abandoned: bool,
    /// The encoded request, kept so a `-32000` can be reissued, since middlewared refuses at its hard limit before the
    /// method runs. `None` for anything but a caller's own call and for a frame above the ordinary cap, so retention
    /// stays within [`CALL_BUDGET`] ordinary frames.
    retry_frame: Option<Vec<u8>>,
    /// Reissues so far, against [`MAX_CALL_RETRIES`].
    retries: u32,
}

/// Where the session is in its life.
pub(crate) enum Phase {
    /// The upgrade request is out; the HTTP response head is inbound.
    AwaitingHead,
    /// The `101` is in and `core.set_options` is on the wire, unanswered.
    ///
    /// No caller's call may join yet, which is what makes [`Phase::Open`] mean ready to the public guards. Until the
    /// echo lands the peer's `App.legacy_jobs` is still `true` (`api/base/server/app.py`), so a job method would answer
    /// with its job id rather than its result.
    Setup,
    /// Serving: calls flow, notifications arrive.
    Open,
    /// A close frame has been sent (ours or the echo of the peer's); the transport-level close completes the teardown.
    Closing,
}

/// What the driver must do after feeding the session an input.
#[derive(Debug)]
pub(crate) enum Act {
    /// Put these bytes on the wire (already a complete masked frame, or the upgrade request).
    Send(Vec<u8>),
    /// The session finished its setup and serves calls now.
    Ready,
    /// The handshake failed; close the connection and report the session.
    Failed(HandshakeError),
    /// Session setup ran but its `core.set_options` was refused; the session cannot serve with the semantics it
    /// promised.
    SetupFailed(ApiError),
    /// A call completed (a user call, or a subscribe/unsubscribe that failed - those surface their errors as the
    /// call's).
    CallDone {
        call: CallId,
        result: Result<Box<RawValue>, ApiError>,
    },
    /// A `core.subscribe` completed; events for its collection will now arrive.
    Subscribed { call: CallId, sub: SubscriptionId },
    /// A `core.unsubscribe` completed.
    Unsubscribed { call: CallId, sub: SubscriptionId },
    /// A `collection_update` notification.
    Update(CollectionUpdate),
    /// The server ended a subscription (`notify_unsubscribed`).
    SubscriptionEnded { collection: String, error: Option<Value> },
    /// A notification this client does not model - forward compatibility surfaced rather than dropped or fataled.
    Notification { method: String, params: Option<Value> },
    /// The peer sent a close frame; the echo has been queued (a preceding [`Act::Send`]) - flush it and close the
    /// connection gracefully. The close report is in [`Session::close_reason`], read at the transport-level close.
    PeerClosing,
    /// The peer violated the protocol; close immediately and fail everything outstanding.
    Fault(&'static str),
    /// The server reported an error against no call of ours - a `id: null` Response. Diagnostic: the session stays up.
    ServerError(ApiError),
}

/// A decoded `collection_update` event.
///
/// [`Debug`] reports the payload members by size, not content: a `core.get_jobs` update carries the job's own result in
/// `fields`, so `{:?}` on the event is the same disclosure [`OwnedResult`]'s `Debug` avoids.
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

/// The response-vs-notification sniff: a JSON-RPC frame from middlewared either answers a call (`result`/`error`, no
/// `method`) or notifies (`method`, no `id`). Unknown members are ignored so decoration cannot break the split.
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
    /// The `Sec-WebSocket-Key` this connection sent, for validating the accept digest.
    key: String,
    caller: Caller,
    pending: HashMap<Id, Pending>,
    /// A fragmented text message under reassembly.
    frag: Option<Vec<u8>>,
    subs: HashMap<SubscriptionId, SubEntry>,
    /// Remaining concurrent-call slots against [`CALL_BUDGET`].
    budget: usize,
    /// Built-but-unsent frames (raw JSON, encoded at drain so each send gets a fresh mask) waiting for budget.
    backlog: VecDeque<(Id, Vec<u8>)>,
    /// Reassembly bound: a fragmented message may not exceed what a single frame may (the reactor enforces per-frame,
    /// this enforces the sum).
    max_inbound: usize,
    /// Refuse outbound messages beyond this (middlewared kills the connection on oversize instead of failing the call).
    max_outbound: usize,
    /// Bound on `backlog`'s length (`ApiConfig::max_queued_calls`).
    max_queued: usize,
    /// Bound on `backlog`'s bytes (`ApiConfig::max_queued_bytes`).
    max_queued_bytes: usize,
    /// Bytes currently held in `backlog`, kept rather than summed: a submission is on the hot path and the queue can be
    /// hundreds deep.
    queued_bytes: usize,
    /// Whether session setup skips `core.set_options` (legacy job ids).
    legacy_jobs: bool,
    /// The peer-close report, captured when the close frame arrives so the transport-level close can name it.
    pub(crate) close_reason: Option<String>,
    /// A `-32000` arrived and the backoff has no clock yet, since `on_answer` has no `Instant`. `expire` turns it into
    /// `backoff_until`.
    backoff_armed: bool,
    /// While set, `drain_backlog` sends nothing. Cleared by `expire` once the instant passes; published through
    /// `next_deadline` so the pump wakes for it.
    backoff_until: Option<Instant>,
    /// Consecutive `-32000` refusals, the exponent for [`BACKOFF_BASE`]. Reset by any answer that is not a refusal.
    backoff_step: u32,
}

/// Reissues of one call after a `-32000` before its caller is told.
///
/// The refusal comes before the method runs, so a reissue cannot double the call. A `call_timeout` still ends the call
/// whatever this says, and this bound stops an endless reissue loop on a session without one.
pub const MAX_CALL_RETRIES: u32 = 4;

/// First pause after a `-32000`, doubled per consecutive refusal up to [`BACKOFF_CAP`].
const BACKOFF_BASE: Duration = Duration::from_millis(100);

/// Ceiling for the pause. A job method holds its server slot for the whole job, so the wait can be seconds, but past
/// this a longer wait only delays noticing that the peer has recovered.
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
    /// `ApiClient::connect_start` screens the same value before it dials, so reaching this is a caller that went around
    /// it.
    pub(crate) fn upgrade(&self, endpoint: &str) -> Result<Vec<u8>, HandshakeError> {
        ws::upgrade_request(endpoint, &self.key)
    }

    /// The HTTP response head arrived: validate the upgrade, then either declare the session ready (legacy jobs) or
    /// issue the setup `core.set_options` whose answer will.
    pub(crate) fn on_head(&mut self, head: &[u8], next: CallId) -> Vec<Act> {
        match ws::validate_101(head, &self.key) {
            Err(e) => vec![Act::Failed(e)],
            Ok(()) => {
                if self.legacy_jobs {
                    // Nothing to negotiate: legacy answering is what the peer already does, so this session is ready
                    // here.
                    self.phase = Phase::Open;
                    return vec![Act::Ready];
                }
                self.phase = Phase::Setup;
                // The reference client's session setup: answers arrive when jobs finish, not as bare job ids.
                let params = serde_json::value::to_raw_value(&[serde_json::json!({ "legacy_jobs": false })])
                    .expect("a literal object encodes");
                match self.submit(next, Kind::SetOptions, "core.set_options", &params, None) {
                    Ok(acts) => acts,
                    Err(e) => vec![Act::SetupFailed(e)],
                }
            }
        }
    }

    /// Build and account one call. `params` must already be a JSON Array (the caller validated the first byte). Returns
    /// the send when the budget allows, queues otherwise - and refuses rather than queueing once the backlog is at
    /// [`Session::max_queued`].
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
        // Per method, as middlewared applies it: the whitelisted upload methods are exempt from the ordinary cap and
        // nothing else is.
        let cap = crate::config::outbound_cap(self.max_outbound, method);
        if frame.len() > cap {
            // The id is minted but never sent; a gap in the sequence is harmless (ids are correlation keys, nothing
            // more).
            return Err(ApiError::TooLarge { len: frame.len(), cap });
        }
        // A running backoff holds new calls too. A `-32000` frees a slot as it arrives, so a call submitted next would
        // find `budget > 0` and walk into the same refusal.
        let sending = self.budget > 0 && !self.backing_off();
        // Refuse before `pending.insert`, so a refused call leaves no tombstone to be answered.
        if !sending {
            // The count bounds pipelining depth and the bytes bound memory, since an upload method's frame may be 32
            // times an ordinary one.
            if self.backlog.len() >= self.max_queued {
                return Err(ApiError::QueueFull {
                    queue: "this session's call backlog, in calls",
                    cap: self.max_queued,
                });
            }
            if self.queued_bytes.saturating_add(frame.len()) > self.max_queued_bytes {
                return Err(ApiError::QueueFull {
                    queue: "this session's call backlog, in bytes",
                    cap: self.max_queued_bytes,
                });
            }
        }
        let retry_frame = (matches!(kind, Kind::User) && frame.len() <= self.max_outbound).then(|| frame.clone());
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
            Ok(vec![Act::Send(ws::encode_frame(OP_TEXT, &frame, ws::mask_key()))])
        } else {
            self.queued_bytes += frame.len();
            self.backlog.push_back((id, frame));
            Ok(Vec::new())
        }
    }

    /// One completed inbound WebSocket frame.
    pub(crate) fn on_frame(&mut self, head: FrameHead, payload: Vec<u8>) -> Vec<Act> {
        match head.opcode {
            OP_PING => {
                // §5.5.2/§5.5.3: pong back the same payload. Control frames may interleave a fragmented message;
                // reassembly state is untouched.
                vec![Act::Send(ws::encode_frame(OP_PONG, &payload, ws::mask_key()))]
            }
            OP_PONG => Vec::new(),
            OP_CLOSE => self.on_close_frame(&payload),
            OP_BINARY => vec![Act::Fault("binary frame")],
            OP_TEXT if !head.fin => {
                if self.frag.is_some() {
                    return vec![Act::Fault("new data frame inside a fragmented message")];
                }
                // The cap has to bind here, not only where the pieces are joined: a first fragment is held until a
                // continuation arrives, and a peer that never sends one holds whatever it declared for as long as the
                // connection lives.
                if payload.len() > self.max_inbound {
                    return vec![Act::Fault("fragmented message exceeds the inbound cap")];
                }
                self.frag = Some(payload);
                Vec::new()
            }
            OP_TEXT => {
                if self.frag.is_some() {
                    return vec![Act::Fault("new data frame inside a fragmented message")];
                }
                // The cap covers an unfragmented message too. The reactor already enforces it, but the session is
                // sans-io and states its own bound for any other driver.
                if payload.len() > self.max_inbound {
                    return vec![Act::Fault("message exceeds the inbound cap")];
                }
                self.on_message(&payload)
            }
            OP_CONT => {
                let Some(mut buf) = self.frag.take() else {
                    return vec![Act::Fault("continuation with no message open")];
                };
                if buf.len().saturating_add(payload.len()) > self.max_inbound {
                    return vec![Act::Fault("fragmented message exceeds the inbound cap")];
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

    /// A close frame from the peer: echo it (once), remember why, and let the driver run the transport close.
    fn on_close_frame(&mut self, payload: &[u8]) -> Vec<Act> {
        // §5.5.1 makes /reason/ UTF-8 and its first two bytes a code, so a lossy decode would report a reason the peer
        // never sent and a one-byte body would report no code at all rather than a malformed frame. Say which it was
        // instead.
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
            // Our close is out already; this is the peer's echo, and the transport-level teardown finishes the job.
            return Vec::new();
        }
        self.phase = Phase::Closing;
        self.close_reason = Some(reason);
        // No continuation can arrive now, so an open reassembly is dead weight - up to `max_inbound` of it - held until
        // the driver gets round to dropping the session.
        self.frag = None;

        // §5.5.1 echoes the status code back, bounded by §7.4.1: 1004, 1005, 1006, 1015 and the unassigned ranges MUST
        // NOT be set by an endpoint, so an unsendable peer code is answered 1002 rather than reflected - a peer that
        // checks would fail the connection over our echo and turn a graceful close into an abnormal one.
        let echo = match ws::close_echo_code(payload) {
            Some(code) => code.to_be_bytes().to_vec(),
            None => Vec::new(),
        };
        vec![
            Act::Send(ws::encode_frame(OP_CLOSE, &echo, ws::mask_key())),
            Act::PeerClosing,
        ]
    }

    /// Begin a local close: the 1000 (normal closure) frame. The driver flushes it and closes the transport.
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

    /// One complete JSON-RPC text message: a response to something pending, or a server notification.
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
        let Incoming::Single(Call::Valid(req)) = truenas_jsonrpc::parse(text) else {
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
                    return vec![Act::Fault("collection_update without params")];
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
                let decoded = params.and_then(|raw| serde_json::from_str::<NotifyUnsubscribed>(raw.get()).ok());
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
            // middlewared rejects batch requests and so never answers with an Array; one appearing is not this
            // protocol.
            Answer::Batch(_) => return vec![Act::Fault("batch answer")],
            Answer::Invalid(_) => {
                return vec![Act::Fault("unparseable response")];
            }
        };
        // JSON-RPC 2.0 §5 gives `id: null` to an error the server could not attribute. middlewared sends one and keeps
        // serving (`api/base/server/ws_handler/rpc.py`), so it is reported and the session stays up.
        if matches!(reply.id(), Id::Null) {
            let report = match reply.outcome() {
                Outcome::Failure(e) => from_rpc_error(e),
                Outcome::Result(_) => ApiError::Protocol("a result Response with a null id names no call"),
            };
            // The call that provoked it will never be answered, and with no `call_timeout` nothing else would end it,
            // so every call in flight is failed. See `fail_outstanding` for what they keep.
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
        // An answer for a call still in `backlog` names a request the peer never received (JSON-RPC 2.0 §5). Crediting
        // it would send that call with no `pending` entry.
        if !p.sent {
            return vec![Act::Fault("answer for a call never sent")];
        }
        // The answer is the only thing that says the server has let this call go, so it is the only thing that returns
        // its slot - abandoned or not. A caller giving up does not free the server.
        self.budget += 1;
        debug_assert!(
            self.budget <= CALL_BUDGET,
            "budget {} exceeded CALL_BUDGET {CALL_BUDGET}",
            self.budget
        );
        // A `-32000` means the peer is at its hard limit. Arm the backoff before draining, or this answer's freed slot
        // sends a queued call into the same refusal, whether or not this call was abandoned.
        let refused = matches!(
            reply.outcome(),
            Outcome::Failure(e)
                if e.code() == crate::error::TOO_MANY_CONCURRENT_CALLS
        );
        if refused {
            self.backoff_armed = true;
            self.backoff_step = self.backoff_step.saturating_add(1);
            // Reissue the call after the pause rather than report it. `__aenter__` raises above `hardlimit` before
            // `method.call` (`middlewared/utils/lock.py`), so the method did not run.
            if !p.abandoned
                && p.retries < MAX_CALL_RETRIES
                && let Some(frame) = p.retry_frame.clone()
            {
                self.queued_bytes = self.queued_bytes.saturating_add(frame.len());
                self.backlog.push_front((reply.id().clone(), frame));
                self.pending.insert(
                    reply.id().clone(),
                    Pending {
                        sent: false,
                        retries: p.retries + 1,
                        ..p
                    },
                );
                // No `drain_backlog`: the backoff is armed, so it would send nothing, and the entry is back in
                // `pending` for `expire` to release when the pause ends.
                return Vec::new();
            }
        } else {
            // Any answer that is not a refusal means the peer has room again, so the next refusal starts from the base
            // delay.
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
                // The echo is the authority, not the request (see `legacy_jobs_in_force`).
                Ok(raw) => match legacy_jobs_in_force(&raw) {
                    Some(false) => {
                        // The echo is in force, so this is the moment the session may take a caller's call:
                        // `Phase::Open` is what the public guards read, and it means ready, not merely upgraded.
                        self.phase = Phase::Open;
                        acts.push(Act::Ready);
                    }
                    Some(true) => acts.push(Act::SetupFailed(ApiError::Protocol(
                        "core.set_options answered legacy_jobs: true \
                             after this session asked for modern job \
                             answering",
                    ))),
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
        // RFC 6455 §5.5.1 forbids data frames after our Close, and an answer that frees a slot can arrive after it.
        // Answers are still delivered, nothing queued is sent, and `fail_all` fails the backlog at the transport close.
        if matches!(self.phase, Phase::Closing) {
            return acts;
        }
        // Backing off from a `-32000`. The queued calls are exactly the ones that would walk into the same wall, and
        // the server clears its own backlog by finishing work, not by being asked again.
        if self.backing_off() {
            return acts;
        }
        while self.budget > 0 {
            let Some((id, frame)) = self.backlog.pop_front() else {
                break;
            };
            self.queued_bytes = self.queued_bytes.saturating_sub(frame.len());
            // A queued call that timed out before it ever reached the wire: drop it here, and free its tombstone - no
            // answer can exist for a call that was never sent.
            if self.pending.get(&id).is_some_and(|p| p.abandoned) {
                self.pending.remove(&id);
                continue;
            }
            // A queued frame whose `pending` entry has gone is not sendable: nothing would correlate its answer. Drop
            // it rather than emitting a call the session cannot account for.
            if !self.pending.contains_key(&id) {
                continue;
            }
            self.budget -= 1;
            if let Some(p) = self.pending.get_mut(&id) {
                p.sent = true;
            }
            acts.push(Act::Send(ws::encode_frame(OP_TEXT, &frame, ws::mask_key())));
        }
        acts
    }

    /// Whether a `-32000` backoff is holding this session's sends. True from the moment the refusal is parsed
    /// (`backoff_armed`) until `expire` retires the instant it was given, so there is no window between the two in
    /// which a send slips out.
    fn backing_off(&self) -> bool {
        self.backoff_armed || self.backoff_until.is_some()
    }

    /// The server-issued ident for `sub`, once subscribed.
    pub(crate) fn sub_ident(&self, sub: SubscriptionId) -> Option<&str> {
        self.subs.get(&sub).and_then(|e| e.ident.as_deref())
    }

    /// This session's *ordinary* outbound cap, for sizing a `core.bulk` flush chunk. `core.bulk` is not one of the
    /// methods middlewared exempts, so the ordinary cap is the one that binds it.
    pub(crate) fn max_outbound(&self) -> usize {
        self.max_outbound
    }

    /// The earliest live call deadline, for the pump's wait computation. A running backoff is one of them: nothing else
    /// would wake the pump to release the calls it is holding.
    pub(crate) fn next_deadline(&self) -> Option<Instant> {
        self.pending
            .values()
            .filter(|p| !p.abandoned)
            .filter_map(|p| p.deadline)
            .chain(self.backoff_until)
            .min()
    }

    /// Time out every live call whose deadline has passed. The entries stay as tombstones (their answers are still owed
    /// by the server and must be recognized when they land); a tombstone still in the backlog is dropped at drain
    /// instead.
    ///
    /// Abandoning a call does **not** return its concurrency slot. middlewared is still running the method, so the slot
    /// comes back in `on_answer` when the late answer lands.
    pub(crate) fn expire(&mut self, now: Instant) -> Vec<Act> {
        let mut acts = Vec::new();
        for p in self.pending.values_mut() {
            if !p.abandoned && p.deadline.is_some_and(|d| d <= now) {
                p.abandoned = true;
                // The setup call has no caller-visible id; its timeout surfaces through the blocking connect's own
                // deadline.
                if !matches!(p.kind, Kind::SetOptions) {
                    acts.push(Act::CallDone {
                        call: p.call,
                        result: Err(ApiError::Timeout),
                    });
                }
            }
        }
        // The backoff's clock. `on_answer` armed it without one; give it an instant here, and retire it once that
        // instant has passed so the drain below can run.
        if self.backoff_armed {
            let step = self.backoff_step.saturating_sub(1).min(16);
            let full = BACKOFF_BASE.saturating_mul(1u32 << step).min(BACKOFF_CAP);
            // Equal jitter, half the window plus a random part of the rest, so clients refused together do not come
            // back in step. The entropy is the frame masks' `getrandom(2)`.
            let r = u32::from_be_bytes(ws::mask_key());
            let half = full / 2;
            let delay = half + half.mul_f64(f64::from(r) / f64::from(u32::MAX)).min(half);
            // `checked_add` for the reason every other deadline site uses it: `Instant + Duration` panics on overflow.
            self.backoff_until = now.checked_add(delay);
            self.backoff_armed = false;
        } else if self.backoff_until.is_some_and(|t| t <= now) {
            self.backoff_until = None;
        }
        acts.extend(self.drain_backlog());
        acts
    }

    /// Fail every call this session has accepted, and keep serving.
    ///
    /// **A sent call keeps its entry and its slot**, marked abandoned as `expire` does, because the server still owes
    /// its answer and a dropped entry would make that answer fault the session. `Kind::SetOptions` is not failed, since
    /// it has no caller-visible id, and `connect_timeout` covers a setup that never completes.
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
            // Never reached the wire, so nothing is owed for it and it holds no slot. Its frame is in the backlog being
            // cleared just below.
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

    /// Every live call, failed at once - the session is going away.
    pub(crate) fn fail_all(&mut self, why: &str) -> Vec<Act> {
        self.frag = None;
        let mut acts = Vec::new();
        for (_, p) in self.pending.drain() {
            if !p.abandoned && !matches!(p.kind, Kind::SetOptions) {
                acts.push(Act::CallDone {
                    call: p.call,
                    result: Err(ApiError::Closed { reason: why.to_owned() }),
                });
            }
        }
        self.backlog.clear();
        self.queued_bytes = 0;
        acts
    }
}

/// What `core.set_options` reports it put in force, or `None` if it reports nothing.
///
/// The echo, not the request, is the authority, as in the reference Python client (`truenas_api_client/__init__.py`).
///
/// **`None` is a refusal.** Every API version that honours the option echoes `legacy_jobs`
/// (`middlewared/api/v26_0_0/core.py`), and older ones drop it and echo `null` (`api/v25_04_1/core.py`,
/// `CoreSetOptionsResult.to_previous` in `api/v25_10_0/core.py`), leaving legacy answering in force.
/// [`validate_endpoint`] refuses those versions up front, and this check does not depend on the endpoint.
fn legacy_jobs_in_force(raw: &RawValue) -> Option<bool> {
    serde_json::from_str::<serde_json::Value>(raw.get())
        .ok()?
        .get("legacy_jobs")?
        .as_bool()
}

#[cfg(test)]
mod tests;
