//! A non-blocking client for TrueNAS middlewared's JSON-RPC 2.0 API.
//!
//! middlewared serves JSON-RPC only behind a WebSocket route (`GET
//! /api/current`, text frames) on its AF_UNIX socket - the socket is an
//! HTTP server; `AF_UNIX` changes the transport and adds `SO_PEERCRED`,
//! not the protocol stack. This crate speaks that stack on `truenas_ros`'s
//! io_uring `net-client` role: one upgrade request and one `101` head per
//! connection, RFC 6455 client frames after that, JSON-RPC inside them.
//!
//! Everything is **submit-and-pump**: [`ApiClient::call_start`] returns a
//! [`CallId`] immediately, and [`ApiClient::pump`] surfaces completions
//! and server notifications as [`ApiEvent`]s - no thread per call, ever.
//! Blocking conveniences ([`ApiClient::connect`], [`ApiClient::call`])
//! are thin pump-until wrappers for tools and tests, not the model.
//!
//! # Identity
//!
//! A session dials under an io_uring [`Personality`], so middlewared's
//! peer-credential auto-auth sees the minted identity: uid 0 from a
//! non-interactive daemon is a full-admin session, any other uid
//! authenticates as that TrueNAS user when its groups compose a privilege
//! and PAM admits it. There are no passwords or keys anywhere in this
//! crate - `SO_PEERCRED` is the whole mechanism. Minting non-root
//! personalities takes the parent crate's credential broker on a ring
//! created *before* the broker forks: [`ApiClient::setup_ring`] →
//! [`CredBroker::spawn`] → [`ApiClient::with_ring`], then
//! [`SessionOpts::personality`] per session.
//!
//! # Correlation
//!
//! The transport's reply pairing is FIFO-positional and means nothing
//! under a multiplexed RPC protocol; the JSON-RPC `id` is the only
//! correlator, and this crate never looks at the transport's
//! `RequestId`s. Inbound frames are split by shape: a `method` member is
//! a notification, otherwise it answers whatever `id` it names.

#![deny(unsafe_code)]

mod bulk;
mod config;
mod error;
mod server;
mod session;

pub use config::{
    ApiConfig, MIDDLEWARE_MSG_CAP, MIDDLEWARE_MSG_CAP_EXTENDED,
    MIN_API_VERSION, MSG_SIZE_EXTENDED_METHODS, SessionOpts, validate_endpoint,
};
pub use error::{
    ApiError, CALL_ERROR, CallError, ExtraError, INVALID_PARAMS,
    TOO_MANY_CONCURRENT_CALLS, Trace,
};
pub use server::{JsonRpcServer, ServerAct, ServerStep};
pub use session::{CALL_BUDGET, CollectionUpdate, MAX_CALL_RETRIES};
// The WebSocket codec is the parent crate's `ws` module; the middlewared
// specifics (JSON-RPC, sessions, the bulk queue) are what live here. A
// consumer that wants the handshake-refusal reason, or a mock answering a
// live handshake, reaches these through us rather than a second import.
pub use truenas_ros::ws::{HandshakeError, accept_for};

// The broker recipe's vocabulary, so a consumer needs no direct
// `truenas_ros` import to mint identities: create the ring, fork the
// broker over it, build the client on it, register `AsUser`s per tenant.
pub use truenas_ros::net::client::{Personality, RingFd};
pub use truenas_ros::uring_fs::{
    AsUser, Caps, CredBroker, CredHandle, IdentityCache, Lease,
};

use bulk::BulkQueue;
use serde::Deserialize;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use serde_json::value::RawValue;
use session::{Act, Kind, Phase, Session};
use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::time::{Duration, Instant};
use truenas_ros::net::client::{Client, ConnId, ConnectOpts, Event};
use truenas_ros::net::{Framing, ServerAddr};
use truenas_ros::ws::{self, WsState};

/// Re-exported for the [`params!`] macro's expansion; not API.
#[doc(hidden)]
pub use serde_json as __json;

/// Build the positional-params array middlewared requires: `params!()` is
/// the empty array (send it for zero-argument methods - middlewared
/// defaults an absent member, but an explicit `[]` keeps every call the
/// same shape), `params!(a, b)` is `[a, b]` with mixed types welcome.
#[macro_export]
macro_rules! params {
    () => { $crate::__json::json!([]) };
    ($($v:expr),+ $(,)?) => { $crate::__json::json!([$($v),+]) };
}

/// A live session: one connection, one identity, one JSON-RPC id space.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct SessionId(ConnId);

/// One submitted call, to be matched against
/// [`ApiEvent::CallDone`]/[`ApiEvent::SubscriptionReady`].
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct CallId(u64);

/// One subscription, usable with [`ApiClient::unsubscribe_start`].
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct SubscriptionId(pub(crate) u64);

/// One item queued into the deferred [`queue_bulk`](ApiClient::queue_bulk)
/// path, matched against [`ApiEvent::BulkItemDone`].
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct BulkTicket(u64);

/// An owned, still-encoded JSON-RPC `result`: decode it into the type the
/// method returns, or keep it raw.
///
/// [`Debug`] reports its size and not its content. A method's result is
/// whatever the caller asked middlewared for - `auth.*` tokens, a
/// `datastore.query` row, a key - and `{:?}` on an event is how it would
/// reach a log file. middlewared draws the same line: results go to the
/// caller intact and through `remove_secrets` on the way to the audit
/// record (`api/base/handler/remove_secrets.py`, used by
/// `handler/dump_params.py`). [`OwnedResult::get`] and
/// [`OwnedResult::decode`] are the caller's side of it.
pub struct OwnedResult(Box<RawValue>);

impl fmt::Debug for OwnedResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "OwnedResult(<{} bytes>)", self.0.get().len())
    }
}

impl OwnedResult {
    /// Decode into `R`.
    pub fn decode<R: DeserializeOwned>(&self) -> Result<R, ApiError> {
        serde_json::from_str(self.0.get()).map_err(ApiError::Decode)
    }

    /// The raw JSON text.
    pub fn get(&self) -> &str {
        self.0.get()
    }
}

/// What [`ApiClient::pump`] surfaces.
///
/// Its [`Debug`] is written out rather than derived, and the `match` in
/// it is exhaustive on purpose: every variant that carries server data
/// has to decide whether `{:?}` prints it, and a new one will not
/// compile until someone does. See [`OwnedResult`] for the line being
/// drawn.
#[non_exhaustive]
pub enum ApiEvent {
    /// The session finished its handshake and setup; calls flow.
    SessionReady(SessionId),
    /// The session never became ready (dial, upgrade, or setup failed);
    /// its id is dead.
    SessionFailed {
        /// The session that failed.
        session: SessionId,
        /// Why.
        error: ApiError,
    },
    /// A call completed - the result, or the failure middlewared
    /// reported.
    CallDone {
        /// The call this answers.
        call: CallId,
        /// The outcome.
        result: Result<OwnedResult, ApiError>,
    },
    /// A [`subscribe_start`](ApiClient::subscribe_start) completed;
    /// [`ApiEvent::CollectionUpdate`]s for its collection follow.
    SubscriptionReady {
        /// The subscribe call.
        call: CallId,
        /// The subscription handle.
        sub: SubscriptionId,
    },
    /// An [`unsubscribe_start`](ApiClient::unsubscribe_start) completed.
    Unsubscribed {
        /// The unsubscribe call.
        call: CallId,
        /// The subscription that ended.
        sub: SubscriptionId,
    },
    /// A `collection_update` event.
    CollectionUpdate {
        /// The session it arrived on.
        session: SessionId,
        /// The decoded event.
        update: CollectionUpdate,
    },
    /// The server ended a subscription (`notify_unsubscribed`).
    SubscriptionEnded {
        /// The session it arrived on.
        session: SessionId,
        /// The collection whose subscription ended.
        collection: String,
        /// The server's error, when it sent one.
        error: Option<Value>,
    },
    /// A notification this client does not model - forward compatibility,
    /// surfaced rather than dropped.
    Notification {
        /// The session it arrived on.
        session: SessionId,
        /// The JSON-RPC method member.
        method: String,
        /// Its params, when decodable.
        params: Option<Value>,
    },
    /// One deferred item's result, from the `core.bulk` batch it rode.
    BulkItemDone {
        /// The item this answers.
        ticket: BulkTicket,
        /// Its per-item outcome.
        result: Result<OwnedResult, ApiError>,
    },
    /// One `core.bulk` batch was *sent*: `items` of `method` went out
    /// together this flush. Emitted when the batch leaves; each item's
    /// [`ApiEvent::BulkItemDone`] follows when the batch completes.
    BulkFlushed {
        /// The method every item in the batch called.
        method: String,
        /// How many items the batch carried.
        items: usize,
    },
    /// The server reported an error naming no call of ours: a Response
    /// with `id: null`, which JSON-RPC 2.0 §5 reserves for an error the
    /// server could not attribute. middlewared sends one when a message
    /// of ours does not parse, or when its own notification fails to
    /// serialise, and keeps the connection serving - so this is a report,
    /// not a teardown, and every call in flight is unaffected.
    ServerError {
        /// The session it arrived on.
        session: SessionId,
        /// What the server said.
        error: ApiError,
    },
    /// The session is gone (peer close, protocol fault, transport close,
    /// or a local [`close`](ApiClient::close)); every call still pending
    /// on it has already surfaced as a failed [`ApiEvent::CallDone`].
    SessionClosed {
        /// The session that ended.
        session: SessionId,
        /// Why, as well as the transport could tell.
        reason: String,
    },
}

impl fmt::Debug for ApiEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SessionReady(s) => {
                f.debug_tuple("SessionReady").field(s).finish()
            }
            Self::SessionFailed { session, error } => f
                .debug_struct("SessionFailed")
                .field("session", session)
                .field("error", error)
                .finish(),
            Self::CallDone { call, result } => f
                .debug_struct("CallDone")
                .field("call", call)
                .field("result", result)
                .finish(),
            Self::SubscriptionReady { call, sub } => f
                .debug_struct("SubscriptionReady")
                .field("call", call)
                .field("sub", sub)
                .finish(),
            Self::Unsubscribed { call, sub } => f
                .debug_struct("Unsubscribed")
                .field("call", call)
                .field("sub", sub)
                .finish(),
            Self::CollectionUpdate { session, update } => f
                .debug_struct("CollectionUpdate")
                .field("session", session)
                .field("update", update)
                .finish(),
            // An error payload, not a result: it exists to be reported.
            Self::SubscriptionEnded {
                session,
                collection,
                error,
            } => f
                .debug_struct("SubscriptionEnded")
                .field("session", session)
                .field("collection", collection)
                .field("error", error)
                .finish(),
            // A notification this client does not model, so its params
            // are unread server data - the same question a result asks.
            Self::Notification {
                session,
                method,
                params,
            } => f
                .debug_struct("Notification")
                .field("session", session)
                .field("method", method)
                .field("params", &Opaque(params.as_ref()))
                .finish(),
            Self::BulkItemDone { ticket, result } => f
                .debug_struct("BulkItemDone")
                .field("ticket", ticket)
                .field("result", result)
                .finish(),
            Self::BulkFlushed { method, items } => f
                .debug_struct("BulkFlushed")
                .field("method", method)
                .field("items", items)
                .finish(),
            Self::ServerError { session, error } => f
                .debug_struct("ServerError")
                .field("session", session)
                .field("error", error)
                .finish(),
            Self::SessionClosed { session, reason } => f
                .debug_struct("SessionClosed")
                .field("session", session)
                .field("reason", reason)
                .finish(),
        }
    }
}

/// A `Value` reported by size rather than content, for the same reason
/// [`OwnedResult`]'s [`Debug`] is.
pub(crate) struct Opaque<'a>(pub(crate) Option<&'a Value>);

impl fmt::Debug for Opaque<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            None => f.write_str("None"),
            Some(v) => write!(f, "<{} bytes>", v.to_string().len()),
        }
    }
}

/// The reply framer type driving the underlying client.
type Framer = fn(&[u8], &mut WsState) -> Framing;

/// The non-blocking middlewared client: one io_uring ring, any number of
/// sessions, caller-pumped. `!Send` like the client it embeds - one ring,
/// one thread.
/// `now + d`, or `None` when there is no bound - which is what `None`
/// already means everywhere this feeds, and what an unrepresentable one
/// has to mean.
///
/// `Instant + Duration` panics on overflow, and the durations here are
/// caller-supplied: `ApiConfig::call_timeout` and `connect_timeout` are
/// plain `Option<Duration>` fields, and `pump`'s argument is whatever the
/// caller passes - `Duration::MAX` being an ordinary way to spell "wait
/// as long as it takes". A library must not abort the process over that.
fn deadline_in(d: Option<Duration>) -> Option<Instant> {
    Instant::now().checked_add(d?)
}

pub struct ApiClient {
    client: Client<WsState, Framer>,
    cfg: ApiConfig,
    sessions: HashMap<ConnId, Session>,
    /// Ready-to-return events (the pump's hand-off queue).
    out: VecDeque<ApiEvent>,
    next_call: u64,
    next_sub: u64,
    /// The deferred, tick-batched submission queues: one per session,
    /// because `core.bulk` executes its items under the calling session's
    /// credentials, so an item's session is part of what it *is*. Held in
    /// first-queued order so a flush is deterministic; the count is
    /// bounded by `max_sessions`, which makes the linear lookup free.
    bulk: Vec<(ConnId, BulkQueue)>,
    /// core.bulk calls in flight, each mapped to what it carries, so the
    /// batch's array result fans back out to per-item events.
    bulk_carriers: HashMap<CallId, (String, Vec<BulkTicket>)>,
    next_ticket: u64,
    /// When the deferred queue last flushed, for the tick clock.
    last_tick: Option<Instant>,
}

impl ApiClient {
    /// A client on its own fresh ring. Sessions dial as the daemon itself;
    /// for minted identities use [`setup_ring`](ApiClient::setup_ring) /
    /// [`with_ring`](ApiClient::with_ring) so the credential broker can
    /// inherit the ring at its fork.
    pub fn new(cfg: ApiConfig) -> Result<ApiClient, ApiError> {
        let client = Client::new(cfg.to_client(), ws::ws_frame as Framer)
            .map_err(ros_err)?;
        Ok(Self::assemble(client, cfg))
    }

    /// Create the ring a client under `cfg` will run on, without building
    /// the client - the broker recipe's first step, on the main thread
    /// before any other thread exists.
    pub fn setup_ring(cfg: &ApiConfig) -> Result<RingFd, ApiError> {
        truenas_ros::net::client::setup_ring(&cfg.to_client()).map_err(ros_err)
    }

    /// A client on a ring from [`setup_ring`](ApiClient::setup_ring) -
    /// after the broker forked over it, on the thread that will pump it.
    pub fn with_ring(
        cfg: ApiConfig,
        ring: RingFd,
    ) -> Result<ApiClient, ApiError> {
        let client =
            Client::with_ring(cfg.to_client(), ws::ws_frame as Framer, ring)
                .map_err(ros_err)?;
        Ok(Self::assemble(client, cfg))
    }

    fn assemble(client: Client<WsState, Framer>, cfg: ApiConfig) -> ApiClient {
        ApiClient {
            client,
            cfg,
            sessions: HashMap::new(),
            out: VecDeque::new(),
            next_call: 1,
            next_sub: 1,
            bulk: Vec::new(),
            bulk_carriers: HashMap::new(),
            next_ticket: 1,
            last_tick: None,
        }
    }

    /// Open a session without blocking: the dial, the upgrade, and the
    /// setup all ride the pump, which surfaces
    /// [`ApiEvent::SessionReady`] (or [`ApiEvent::SessionFailed`]).
    /// Calls submitted before ready are refused with
    /// [`ApiError::Closed`].
    pub fn connect_start(
        &mut self,
        opts: SessionOpts,
    ) -> Result<SessionId, ApiError> {
        // Before the dial: the endpoint is spliced into the request line
        // and decides which API version answers, so both refusals belong
        // here rather than at a half-open connection.
        crate::config::validate_endpoint(&self.cfg.endpoint)?;
        let mut copts = ConnectOpts::default();
        if let Some(who) = opts.personality {
            copts = copts.personality(who);
        }
        let conn = self
            .client
            .connect_start(
                ServerAddr::Unix(self.cfg.socket_path.clone()),
                copts,
            )
            .map_err(ApiError::Io)?;
        self.sessions.insert(
            conn,
            Session::new(
                ws::ws_key(),
                opts.legacy_jobs,
                opts.max_outbound_bytes,
                self.cfg.max_message_bytes,
                self.cfg.max_queued_calls,
                self.cfg.max_queued_bytes,
            ),
        );
        Ok(SessionId(conn))
    }

    /// Open a session and pump until it is ready - the blocking
    /// convenience over [`connect_start`](ApiClient::connect_start),
    /// bounded by [`ApiConfig::connect_timeout`]. On a timeout the
    /// half-open session is closed before returning.
    pub fn connect(
        &mut self,
        opts: SessionOpts,
    ) -> Result<SessionId, ApiError> {
        let sid = self.connect_start(opts)?;
        let deadline = deadline_in(self.cfg.connect_timeout);
        let got = self.wait_for(deadline, |ev| {
            matches!(ev, ApiEvent::SessionReady(s) if *s == sid)
                || matches!(
                    ev,
                    ApiEvent::SessionFailed { session, .. } if *session == sid
                )
        });
        match got {
            Ok(ApiEvent::SessionReady(_)) => Ok(sid),
            Ok(ApiEvent::SessionFailed { error, .. }) => Err(error),
            Ok(_) => unreachable!("wait_for returns only matched events"),
            Err(e) => {
                self.close(sid);
                Err(e)
            }
        }
    }

    /// Submit one call and return its handle immediately; the outcome
    /// arrives as [`ApiEvent::CallDone`]. `params` must serialize to a
    /// JSON Array ([`params!`] builds one) - middlewared rejects named
    /// params. Calls beyond the per-session concurrency budget queue
    /// locally and go out as earlier answers land.
    pub fn call_start<P: Serialize + ?Sized>(
        &mut self,
        session: SessionId,
        method: &str,
        params: &P,
    ) -> Result<CallId, ApiError> {
        let raw = array_params(params)?;
        let call = self.mint_call();
        let deadline = deadline_in(self.cfg.call_timeout);
        let acts = {
            let sess = self.session_mut(session)?;
            if !matches!(sess.phase, Phase::Open) {
                return Err(ApiError::Closed {
                    reason: "session is not open".into(),
                });
            }
            sess.submit(call, Kind::User, method, &raw, deadline)?
        };
        self.apply(session.0, acts);
        Ok(call)
    }

    /// Subscribe to `collection` (`core.subscribe`); completion arrives
    /// as [`ApiEvent::SubscriptionReady`], the events themselves as
    /// [`ApiEvent::CollectionUpdate`]. `"*"` subscribes to everything.
    pub fn subscribe_start(
        &mut self,
        session: SessionId,
        collection: &str,
    ) -> Result<CallId, ApiError> {
        let raw = array_params(&[collection])?;
        let call = self.mint_call();
        let sub = SubscriptionId(self.next_sub);
        self.next_sub += 1;
        let deadline = deadline_in(self.cfg.call_timeout);
        let acts = {
            let sess = self.session_mut(session)?;
            if !matches!(sess.phase, Phase::Open) {
                return Err(ApiError::Closed {
                    reason: "session is not open".into(),
                });
            }
            sess.submit(
                call,
                Kind::Subscribe {
                    collection: collection.to_owned(),
                    sub,
                },
                "core.subscribe",
                &raw,
                deadline,
            )?
        };
        self.apply(session.0, acts);
        Ok(call)
    }

    /// Tear down a subscription (`core.unsubscribe` with the ident the
    /// server issued); completion arrives as [`ApiEvent::Unsubscribed`].
    pub fn unsubscribe_start(
        &mut self,
        session: SessionId,
        sub: SubscriptionId,
    ) -> Result<CallId, ApiError> {
        let call = self.mint_call();
        let deadline = deadline_in(self.cfg.call_timeout);
        let acts = {
            let sess = self.session_mut(session)?;
            // The guard `call_start` and `subscribe_start` carry, and the
            // route the backlog gate cannot reach: this call reaches
            // `Act::Send` through `submit`, not `drain_backlog`, so
            // without it one public call after `close()` puts a data frame
            // on the wire behind the session's own Close frame - which
            // RFC 6455 §5.5.1 forbids ("The application MUST NOT send any
            // more data frames after sending a Close frame").
            if !matches!(sess.phase, Phase::Open) {
                return Err(ApiError::Closed {
                    reason: "session is not open".into(),
                });
            }
            let Some(ident) = sess.sub_ident(sub) else {
                return Err(ApiError::UnknownSession);
            };
            let raw = array_params(&[ident])?;
            sess.submit(
                call,
                Kind::Unsubscribe { sub },
                "core.unsubscribe",
                &raw,
                deadline,
            )?
        };
        self.apply(session.0, acts);
        Ok(call)
    }

    /// Queue one call for deferred, batched submission on `session` and
    /// return its ticket immediately - nothing goes on the wire until the
    /// next tick ([`ApiConfig::bulk_tick`]), when every queued method
    /// flushes as one `core.bulk` call. The per-item outcome arrives as
    /// [`ApiEvent::BulkItemDone`], and each batch's dispatch as
    /// [`ApiEvent::BulkFlushed`].
    ///
    /// `args` is the argument array for one call of `method` (the same
    /// Array shape a direct call takes; [`params!`] builds one). Use this
    /// for background work whose latency does not matter and whose volume
    /// would otherwise flood middlewared - a per-item request becomes a
    /// per-method-per-tick one.
    ///
    /// `core.bulk` runs the items under `session`'s own credentials, so
    /// each item is queued *against* the session named here and flushes on
    /// that session and no other - queueing against a second session opens
    /// a second queue rather than re-aiming the first. Whichever session
    /// an item names must be one whose identity may make that call.
    /// [`ApiConfig::max_queued_bulk_items`] bounds the client's queues
    /// together, not each one.
    pub fn queue_bulk<P: Serialize + ?Sized>(
        &mut self,
        session: SessionId,
        method: &str,
        args: &P,
    ) -> Result<BulkTicket, ApiError> {
        // The session must exist so a flush has somewhere to go; the
        // credential check is middlewared's, per item.
        if !self.sessions.contains_key(&session.0) {
            return Err(ApiError::UnknownSession);
        }
        let raw = array_params(args)?;
        // The cap is client-wide, so charge it against every session's
        // queue rather than letting each hold `max_queued_bulk_items`.
        let cap = self.cfg.max_queued_bulk_items;
        let queued: usize = self.bulk.iter().map(|(_, q)| q.len()).sum();
        if queued >= cap {
            return Err(ApiError::QueueFull {
                queue: "the deferred bulk queue, in items",
                cap,
            });
        }
        // The count is a depth; this is the memory. An item carries its
        // own encoded params and nothing bounds those at enqueue, so
        // without this the queue's ceiling is the item cap times whatever
        // the caller queues.
        let bytes_cap = self.cfg.max_queued_bulk_bytes;
        let queued_bytes: usize =
            self.bulk.iter().map(|(_, q)| q.bytes()).sum();
        if queued_bytes.saturating_add(raw.get().len()) > bytes_cap {
            return Err(ApiError::QueueFull {
                queue: "the deferred bulk queue, in bytes",
                cap: bytes_cap,
            });
        }
        let ticket = BulkTicket(self.next_ticket);
        self.next_ticket += 1;
        let queue = match self.bulk.iter_mut().find(|(id, _)| *id == session.0)
        {
            Some((_, q)) => q,
            None => {
                self.bulk.push((session.0, BulkQueue::default()));
                &mut self.bulk.last_mut().expect("just pushed").1
            }
        };
        // The cap was charged client-wide just above, so the per-queue
        // bound is not the one that governs here.
        queue.enqueue(ticket, method, raw, usize::MAX)?;
        Ok(ticket)
    }

    /// Flush the deferred queue now rather than waiting for the tick -
    /// every queued method goes out as one `core.bulk` call at once.
    pub fn flush_bulk(&mut self) {
        self.flush_bulk_now();
    }

    /// Close a session: the WebSocket close handshake, then the
    /// transport teardown, surfaced as [`ApiEvent::SessionClosed`]. Calls
    /// still pending fail with [`ApiError::Closed`].
    pub fn close(&mut self, session: SessionId) {
        let Some(sess) = self.sessions.get_mut(&session.0) else {
            return;
        };
        let acts = sess.start_close();
        self.apply(session.0, acts);
        // Flush the close frame, then FIN; the Closed event completes it.
        self.client.close(session.0);
    }

    /// Drive everything: transport completions, control-frame replies,
    /// handshake steps, call deadlines. Returns the next [`ApiEvent`], or
    /// `None` when `timeout` elapsed first (or, with no timeout, when no
    /// session remains).
    pub fn pump(
        &mut self,
        timeout: Option<Duration>,
    ) -> Result<Option<ApiEvent>, ApiError> {
        let until = deadline_in(timeout);
        loop {
            if let Some(ev) = self.out.pop_front() {
                // A core.bulk carrier's answer is not a user CallDone: fan
                // it out to the tickets it carried instead of surfacing it.
                if let ApiEvent::CallDone { call, .. } = &ev
                    && let Some((method, tickets)) =
                        self.bulk_carriers.remove(call)
                {
                    let ApiEvent::CallDone { result, .. } = ev else {
                        unreachable!("matched CallDone just above");
                    };
                    for e in self
                        .fan_out_bulk(method, tickets, result)
                        .into_iter()
                        .rev()
                    {
                        self.out.push_front(e);
                    }
                    continue;
                }
                return Ok(Some(ev));
            }
            // Fire whatever deadlines have passed, and flush the deferred
            // queue if its tick came up, before deciding how long to wait.
            let now = Instant::now();
            self.expire(now);
            if self.bulk_tick_due(now) {
                self.flush_bulk_now();
            }
            if !self.out.is_empty() {
                continue;
            }
            let next_deadline = self
                .sessions
                .values()
                .filter_map(Session::next_deadline)
                .min();
            // `checked_add` for the same reason the five deadline sites
            // use it: `bulk_tick` is a caller-supplied `Duration` on a
            // plain public field, and `Instant + Duration` panics on
            // overflow. An unrepresentable tick means "not yet", which
            // `None` already means to the wait computation below.
            let next_tick = self
                .bulk_pending()
                .then(|| {
                    self.last_tick.map_or(Some(now), |last| {
                        last.checked_add(self.cfg.bulk_tick)
                    })
                })
                .flatten();
            let base_wait = match (until, next_deadline) {
                (Some(u), Some(d)) => Some(u.min(d)),
                (Some(u), None) => Some(u),
                (None, Some(d)) => Some(d),
                (None, None) => None,
            };
            let wait = [base_wait, next_tick].into_iter().flatten().min();
            let ev = match wait {
                Some(at) => {
                    let dur = at
                        .saturating_duration_since(now)
                        .max(Duration::from_millis(1));
                    self.client.next_event_timeout(dur).map_err(ApiError::Io)?
                }
                None => self.client.next_event().map_err(ApiError::Io)?,
            };
            match ev {
                Some(ev) => self.on_transport(ev),
                None => {
                    // A timeout tick, or no live work at all. Deadlines
                    // and the bulk tick may have come due; loop to fire
                    // them. Only report idle when the caller's own bound
                    // elapsed, or nothing is left to wait on.
                    if let Some(u) = until
                        && Instant::now() >= u
                    {
                        return Ok(None);
                    }
                    if wait.is_none() {
                        return Ok(None);
                    }
                }
            }
        }
    }

    /// [`call_start`](ApiClient::call_start), pumped to completion and
    /// decoded - the blocking convenience. Events for other sessions and
    /// calls are queued for later pumps, not lost.
    pub fn call<P: Serialize + ?Sized, R: DeserializeOwned>(
        &mut self,
        session: SessionId,
        method: &str,
        params: &P,
    ) -> Result<R, ApiError> {
        let call = self.call_start(session, method, params)?;
        let ev = self.wait_for(
            None,
            |ev| matches!(ev, ApiEvent::CallDone { call: c, .. } if *c == call),
        )?;
        let ApiEvent::CallDone { result, .. } = ev else {
            unreachable!("wait_for returns only matched events");
        };
        result.and_then(|r| r.decode())
    }

    /// Pump until `pred` claims an event and return it, keeping every
    /// other event (in order) for later pumps. `deadline` bounds the
    /// whole wait; expiry is [`ApiError::Timeout`]. With no deadline and
    /// nothing left alive, [`ApiError::Closed`] - a blocking wait on a
    /// dead client would otherwise never return.
    fn wait_for(
        &mut self,
        deadline: Option<Instant>,
        mut pred: impl FnMut(&ApiEvent) -> bool,
    ) -> Result<ApiEvent, ApiError> {
        let mut skipped: VecDeque<ApiEvent> = VecDeque::new();
        // Events already queued when this wait began are not buffered by
        // it: `wait_for` restores its set-aside to the front of `self.out`
        // on the way out, and `pump` drains `self.out` before it touches
        // the transport, so moving one from `self.out` into `skipped`
        // frees no memory and allocates none. Counting them made the
        // refusal self-sustaining - the wait tripped the cap on the
        // previous wait's own restored stash, without pumping any I/O, so
        // once the client held `max_waiting_events` events every later
        // `call`/`connect` was refused and the frames they had just
        // handed the transport were never flushed. Only what arrives
        // during this wait is new memory, so only that is counted.
        let mut carried = self.out.len();
        let mut buffered = 0usize;
        let out = loop {
            let remaining = match deadline {
                Some(d) => {
                    let now = Instant::now();
                    if now >= d {
                        break Err(ApiError::Timeout);
                    }
                    Some(d - now)
                }
                None => None,
            };
            match self.pump(remaining) {
                Err(e) => break Err(e),
                Ok(Some(ev)) if pred(&ev) => break Ok(ev),
                Ok(Some(ev)) if carried > 0 => {
                    // Already queued before the wait began: set it aside
                    // without charging it. See `carried` above.
                    carried -= 1;
                    skipped.push_back(ev);
                }
                Ok(Some(ev)) => {
                    // The one queue the peer fills. A subscribed session
                    // pushes `collection_update`s for as long as the call
                    // takes, and nothing else here grows with the peer's
                    // rate, so an unbounded set-aside is the peer's memory
                    // budget rather than ours. Fail the wait instead;
                    // `pump` is the unbuffered path and stays available.
                    if buffered >= self.cfg.max_waiting_events {
                        skipped.push_back(ev);
                        break Err(ApiError::QueueFull {
                            queue: "events set aside by a blocking wait",
                            cap: self.cfg.max_waiting_events,
                        });
                    }
                    buffered += 1;
                    skipped.push_back(ev);
                }
                Ok(None) => {
                    break Err(if deadline.is_some() {
                        ApiError::Timeout
                    } else {
                        ApiError::Closed {
                            reason: "no live session to wait on".into(),
                        }
                    });
                }
            }
        };
        // Whatever was skipped goes back in front of anything queued
        // meanwhile, preserving arrival order.
        skipped.append(&mut self.out);
        self.out = skipped;
        out
    }

    /// Whether `session` is still known (not yet closed).
    pub fn is_open(&self, session: SessionId) -> bool {
        self.sessions.contains_key(&session.0)
    }

    fn mint_call(&mut self) -> CallId {
        let id = CallId(self.next_call);
        self.next_call += 1;
        id
    }

    fn session_mut(
        &mut self,
        session: SessionId,
    ) -> Result<&mut Session, ApiError> {
        self.sessions
            .get_mut(&session.0)
            .ok_or(ApiError::UnknownSession)
    }

    /// Route one transport event into its session.
    fn on_transport(&mut self, ev: Event) {
        match ev {
            Event::Connected { conn } => {
                // The dial is up: the upgrade request goes out, the head
                // comes back through the framer's handshake phase.
                let Some(sess) = self.sessions.get(&conn) else {
                    return;
                };
                match sess.upgrade(&self.cfg.endpoint) {
                    Ok(up) => self.send_or_fault(conn, up),
                    Err(e) => self.apply(conn, vec![Act::Failed(e)]),
                }
            }
            Event::ConnectFailed { conn, err } => {
                if self.sessions.remove(&conn).is_some() {
                    self.out.push_back(ApiEvent::SessionFailed {
                        session: SessionId(conn),
                        error: ApiError::Io(err.into()),
                    });
                }
            }
            Event::Reply {
                conn,
                header,
                mut body,
                ..
            } => {
                let Some(sess) = self.sessions.get_mut(&conn) else {
                    return;
                };
                let acts = if matches!(sess.phase, Phase::AwaitingHead) {
                    // The setup call's id: internal, surfaced only as
                    // Ready/SetupFailed. (Field-disjoint with the live
                    // `sess` borrow of `self.sessions`.)
                    let call = CallId(self.next_call);
                    self.next_call += 1;
                    sess.on_head(&header, call)
                } else {
                    // The framer only completes frames whose header it
                    // validated, so this parse cannot fail.
                    let ws::HeadVerdict::Done(head) = ws::frame_head(&header)
                    else {
                        unreachable!("framer delivered an unparsed header");
                    };
                    sess.on_frame(head, body.take())
                };
                self.apply(conn, acts);
            }
            Event::Closed { conn, reason } => {
                if let Some(mut sess) = self.sessions.remove(&conn) {
                    let why = sess
                        .close_reason
                        .take()
                        .unwrap_or_else(|| format!("{reason:?}"));
                    let acts = sess.fail_all(&why);
                    for act in acts {
                        self.surface(conn, act);
                    }
                    self.out.push_back(ApiEvent::SessionClosed {
                        session: SessionId(conn),
                        reason: why,
                    });
                }
            }
            // No framer in this crate returns SpliceBody, and the
            // connect/TLS surfaces that could produce other events are
            // unused; anything else reaching here is a routing bug.
            other => unreachable!("unexpected transport event: {other:?}"),
        }
    }

    /// Perform a session's actions: sends go to the wire, the rest become
    /// [`ApiEvent`]s.
    fn apply(&mut self, conn: ConnId, acts: Vec<Act>) {
        for act in acts {
            match act {
                Act::Send(bytes) => self.send_or_fault(conn, bytes),
                other => self.surface(conn, other),
            }
        }
    }

    /// Translate one non-send action into its [`ApiEvent`].
    fn surface(&mut self, conn: ConnId, act: Act) {
        let session = SessionId(conn);
        match act {
            Act::Send(_) => unreachable!("apply() routes sends"),
            Act::Ready => self.out.push_back(ApiEvent::SessionReady(session)),
            Act::Failed(e) => {
                let why = e.to_string();
                self.fail_session(conn, &why);
                self.out.push_back(ApiEvent::SessionFailed {
                    session,
                    error: ApiError::Handshake(e),
                });
            }
            Act::SetupFailed(e) => {
                let why = e.to_string();
                self.fail_session(conn, &why);
                self.out
                    .push_back(ApiEvent::SessionFailed { session, error: e });
            }
            Act::CallDone { call, result } => {
                self.out.push_back(ApiEvent::CallDone {
                    call,
                    result: result.map(OwnedResult),
                });
            }
            Act::Subscribed { call, sub } => {
                self.out
                    .push_back(ApiEvent::SubscriptionReady { call, sub });
            }
            Act::Unsubscribed { call, sub } => {
                self.out.push_back(ApiEvent::Unsubscribed { call, sub });
            }
            Act::Update(update) => {
                self.out
                    .push_back(ApiEvent::CollectionUpdate { session, update });
            }
            Act::SubscriptionEnded { collection, error } => {
                self.out.push_back(ApiEvent::SubscriptionEnded {
                    session,
                    collection,
                    error,
                });
            }
            Act::Notification { method, params } => {
                self.out.push_back(ApiEvent::Notification {
                    session,
                    method,
                    params,
                });
            }
            Act::PeerClosing => {
                // The echo is queued (a Send preceding this act); flush
                // it and FIN. The Closed event finishes the story.
                self.client.close(conn);
            }
            Act::ServerError(error) => {
                self.out.push_back(ApiEvent::ServerError { session, error });
            }
            Act::Fault(what) => {
                self.client.close_now(conn);
                if let Some(mut sess) = self.sessions.remove(&conn) {
                    let why = format!("protocol violation: {what}");
                    for act in sess.fail_all(&why) {
                        self.surface(conn, act);
                    }
                    self.out.push_back(ApiEvent::SessionClosed {
                        session,
                        reason: why,
                    });
                }
            }
        }
    }

    /// Drop `conn` and fail everything it had accepted.
    ///
    /// Every route that removes a session has to come through here. The
    /// session owns the only record of the calls in flight on it
    /// (`Session::pending`), so removing it without draining that record
    /// strands each one: the caller was handed a `CallId` and no
    /// `CallDone` will ever answer it, and `ApiClient::call` - which
    /// waits on exactly that event - blocks for as long as
    /// `call_timeout` allows, which is for ever by default.
    ///
    /// `SessionFailed` does not substitute. A caller waiting on a
    /// specific call is not watching for it, and `wait_for`'s predicate
    /// is per-event: the session-level report is stashed as a skipped
    /// event, not delivered as the call's answer.
    fn fail_session(&mut self, conn: ConnId, why: &str) {
        self.client.close_now(conn);
        let Some(mut sess) = self.sessions.remove(&conn) else {
            return;
        };
        for act in sess.fail_all(why) {
            self.surface(conn, act);
        }
    }

    /// Send, or treat a refused send as the session's death (a backlog
    /// past its transport cap, or a race with the close path).
    fn send_or_fault(&mut self, conn: ConnId, bytes: Vec<u8>) {
        if let Err(e) = self.client.send(conn, bytes) {
            self.client.close_now(conn);
            if let Some(mut sess) = self.sessions.remove(&conn) {
                let why = format!("send failed: {e}");
                for act in sess.fail_all(&why) {
                    self.surface(conn, act);
                }
                self.out.push_back(ApiEvent::SessionClosed {
                    session: SessionId(conn),
                    reason: why,
                });
            }
        }
    }

    /// Fire expired call deadlines across every session.
    ///
    /// `pump` calls this on every iteration that has no event ready, so it
    /// runs far more often than any deadline actually fires. Collecting
    /// straight into `(conn, acts)` pairs - rather than every session's
    /// `ConnId` up front, the borrow-checker workaround `apply`'s `&mut
    /// self` would otherwise force - means the common case (nothing due)
    /// touches the allocator not at all: an untouched `Vec` never
    /// allocates.
    fn expire(&mut self, now: Instant) {
        let mut due: Vec<(ConnId, Vec<Act>)> = Vec::new();
        for (&conn, sess) in self.sessions.iter_mut() {
            let acts = sess.expire(now);
            if !acts.is_empty() {
                due.push((conn, acts));
            }
        }
        for (conn, acts) in due {
            self.apply(conn, acts);
        }
    }

    /// Send every queued method as one `core.bulk` call on the nominated
    /// session. Items too large to fit a frame even alone fail their
    /// tickets here rather than wedging the queue.
    fn flush_bulk_now(&mut self) {
        self.last_tick = Some(Instant::now());
        // Each session's queue flushes on that session: `core.bulk` runs
        // its items under the calling session's credentials, so sending
        // one session's items on another would execute them as the wrong
        // principal.
        for conn in self.bulk.iter().map(|(id, _)| *id).collect::<Vec<_>>() {
            // A dead session drops its own queue with a clear failure
            // rather than silently holding items no flush can ever send.
            let Some(cap) = self.sessions.get(&conn).map(|s| s.max_outbound())
            else {
                self.drain_bulk_to_closed(conn, "bulk session is gone");
                continue;
            };
            let session = SessionId(conn);
            for method in self.bulk_methods(conn) {
                loop {
                    let mut oversized = Vec::new();
                    let chunk = self.bulk_queue(conn).and_then(|q| {
                        q.take_chunk(&method, cap, &mut oversized)
                    });
                    for (ticket, len) in oversized {
                        self.out.push_back(ApiEvent::BulkItemDone {
                            ticket,
                            result: Err(ApiError::TooLarge { len, cap }),
                        });
                    }
                    let Some(chunk) = chunk else { break };
                    let n = chunk.tickets.len();
                    // chunk.params is the whole `core.bulk` argument array
                    // already: `[method, [[args]...]]`. core.bulk is a job,
                    // so with legacy_jobs off its answer is the per-item
                    // array when the batch finishes.
                    match self.call_start(session, "core.bulk", &chunk.params) {
                        Ok(call) => {
                            self.bulk_carriers
                                .insert(call, (method.clone(), chunk.tickets));
                            self.out.push_back(ApiEvent::BulkFlushed {
                                method: method.clone(),
                                items: n,
                            });
                        }
                        Err(e) => {
                            // The flush call itself could not be submitted;
                            // fail this chunk's tickets and stop the method.
                            let reason = e.to_string();
                            for ticket in chunk.tickets {
                                self.out.push_back(ApiEvent::BulkItemDone {
                                    ticket,
                                    result: Err(ApiError::Closed {
                                        reason: reason.clone(),
                                    }),
                                });
                            }
                            break;
                        }
                    }
                }
            }
        }
        self.bulk.retain(|(_, q)| !q.is_empty());
    }

    /// `conn`'s deferred queue, if it has one.
    fn bulk_queue(&mut self, conn: ConnId) -> Option<&mut BulkQueue> {
        self.bulk
            .iter_mut()
            .find(|(id, _)| *id == conn)
            .map(|(_, q)| q)
    }

    /// The methods `conn` has queued, in flush order.
    fn bulk_methods(&self, conn: ConnId) -> Vec<String> {
        self.bulk
            .iter()
            .find(|(id, _)| *id == conn)
            .map(|(_, q)| q.methods())
            .unwrap_or_default()
    }

    /// Whether the tick has elapsed since the last flush (or nothing has
    /// flushed yet and items are waiting).
    fn bulk_tick_due(&self, now: Instant) -> bool {
        if !self.bulk_pending() {
            return false;
        }
        match self.last_tick {
            None => true,
            Some(last) => now.duration_since(last) >= self.cfg.bulk_tick,
        }
    }

    /// Whether any session has deferred items waiting.
    fn bulk_pending(&self) -> bool {
        self.bulk.iter().any(|(_, q)| !q.is_empty())
    }

    /// Fail every item `conn` has queued (its session died before a
    /// flush).
    fn drain_bulk_to_closed(&mut self, conn: ConnId, why: &str) {
        let mut oversized = Vec::new();
        for method in self.bulk_methods(conn) {
            while let Some(chunk) = self
                .bulk_queue(conn)
                .and_then(|q| q.take_chunk(&method, usize::MAX, &mut oversized))
            {
                for ticket in chunk.tickets {
                    self.out.push_back(ApiEvent::BulkItemDone {
                        ticket,
                        result: Err(ApiError::Closed {
                            reason: why.to_owned(),
                        }),
                    });
                }
            }
        }
    }

    /// A `core.bulk` carrier call resolved: translate its array result
    /// into one [`ApiEvent::BulkItemDone`] per ticket it carried, in the
    /// batch's order (the `BulkFlushed` marker was queued at flush).
    fn fan_out_bulk(
        &mut self,
        method: String,
        tickets: Vec<BulkTicket>,
        result: Result<OwnedResult, ApiError>,
    ) -> Vec<ApiEvent> {
        let mut events = Vec::with_capacity(tickets.len());
        match result {
            Err(e) => {
                // The whole batch failed (transport, or core.bulk itself
                // erroring); every item shares the fate.
                let reason = format!("core.bulk[{method}] failed: {e}");
                for ticket in tickets {
                    events.push(ApiEvent::BulkItemDone {
                        ticket,
                        result: Err(ApiError::Closed {
                            reason: reason.clone(),
                        }),
                    });
                }
            }
            Ok(res) => {
                // core.bulk answers a per-item array `[{result, error},
                // ...]` in submission order.
                #[derive(Deserialize)]
                struct BulkItem {
                    #[serde(default)]
                    result: Option<Box<RawValue>>,
                    #[serde(default)]
                    error: Option<Value>,
                }
                let items: Result<Vec<BulkItem>, _> =
                    serde_json::from_str(res.get());
                match items {
                    Ok(items) if items.len() == tickets.len() => {
                        for (ticket, item) in tickets.into_iter().zip(items) {
                            let r = match item.error {
                                Some(Value::Null) | None => Ok(OwnedResult(
                                    item.result.unwrap_or_else(null_raw),
                                )),
                                Some(err) => Err(ApiError::Call(Box::new(
                                    bulk_item_error(&err),
                                ))),
                            };
                            events.push(ApiEvent::BulkItemDone {
                                ticket,
                                result: r,
                            });
                        }
                    }
                    _ => {
                        // A shape we cannot trust to split safely: fail the
                        // batch rather than mis-pair results.
                        for ticket in tickets {
                            events.push(ApiEvent::BulkItemDone {
                                ticket,
                                result: Err(ApiError::Protocol(
                                    "core.bulk result shape",
                                )),
                            });
                        }
                    }
                }
            }
        }
        events
    }
}

/// A JSON `null` as an owned `RawValue`.
fn null_raw() -> Box<RawValue> {
    RawValue::from_string("null".to_owned()).expect("null is valid JSON")
}

/// Render one `core.bulk` per-item `error` (middlewared sends a string
/// there) into a [`CallError`].
fn bulk_item_error(err: &Value) -> CallError {
    let reason = match err {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    };
    CallError {
        message: "bulk item failed".to_owned(),
        errno: None,
        errname: None,
        reason: Some(reason),
        trace: None,
        extra: None,
        extra_raw: None,
    }
}

/// Serialize `params` and require the one shape middlewared accepts.
fn array_params<P: Serialize + ?Sized>(
    params: &P,
) -> Result<Box<RawValue>, ApiError> {
    let raw = serde_json::value::to_raw_value(params)
        .map_err(|e| ApiError::Build(e.to_string()))?;
    if raw.get().as_bytes().first() != Some(&b'[') {
        return Err(ApiError::ParamsNotArray);
    }
    Ok(raw)
}

/// Map the parent crate's error into ours, keeping a raw errno raw so a
/// caller (and the test skip discipline) can still read it.
fn ros_err(e: truenas_ros::Error) -> ApiError {
    match e {
        truenas_ros::Error::Errno(no) => {
            ApiError::Io(std::io::Error::from_raw_os_error(no as i32))
        }
        other => ApiError::Io(std::io::Error::other(other.to_string())),
    }
}
