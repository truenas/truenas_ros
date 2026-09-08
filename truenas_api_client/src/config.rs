//! [`ApiConfig`] (per-client) and [`SessionOpts`] (per-session), and the
//! projection into the underlying `net::client` tuning.

use std::path::PathBuf;
use std::time::Duration;
use truenas_ros::net::client::{ClientConfig, Personality};

/// middlewared's per-message inbound cap for an authenticated session
/// (`MsgSizeLimit.AUTHENTICATED`) - root included. Above it the server does
/// not fail the call, it **closes the connection** (WS close 1009), so the
/// client refuses locally at this bound instead
/// ([`ApiError::TooLarge`](crate::ApiError::TooLarge)).
pub const MIDDLEWARE_MSG_CAP: usize = 65_536;

/// middlewared's extended cap, honored only for the two whitelisted
/// upload-shaped methods (`filesystem.file_receive`,
/// `failover.datastore.sql`). A session that calls those raises
/// [`SessionOpts::max_outbound_bytes`] to this.
pub const MIDDLEWARE_MSG_CAP_EXTENDED: usize = 2_097_152;

/// Client-wide configuration. `Default` talks to the production middlewared
/// socket at `/api/current`.
#[derive(Clone, Debug)]
pub struct ApiConfig {
    /// The middlewared unix socket.
    pub socket_path: PathBuf,
    /// The WebSocket endpoint. `/api/current` (the default) tracks the
    /// newest API like the reference client; pin `/api/v27.0.0`-style to
    /// freeze schemas across a middleware upgrade (`GET /api/versions`
    /// enumerates what a server offers).
    pub endpoint: String,
    /// Maximum concurrent sessions (one connection each).
    pub max_sessions: u32,
    /// Cap on one inbound message (a call result or an event). Server to
    /// client is unbounded at the source - a big `query` result arrives as
    /// one WebSocket text frame - so this is the client's own memory
    /// guard; a message above it closes that session.
    pub max_message_bytes: usize,
    /// Bound on dial + upgrade for one session.
    pub connect_timeout: Option<Duration>,
    /// Default bound on one call, measured from submission to its
    /// completion event. `None` never times a call out - job methods
    /// legitimately run for hours with `legacy_jobs` off.
    pub call_timeout: Option<Duration>,
    /// How often the deferred queue
    /// ([`queue_bulk`](crate::ApiClient::queue_bulk)) flushes: each tick,
    /// every method with queued items goes out as one `core.bulk` call.
    /// Batching this way keeps background work from overloading
    /// middlewared with a request per item.
    pub bulk_tick: Duration,
    /// Cap on items held in the deferred queue at once. `queue_bulk`
    /// refuses past it ([`ApiError::QueueFull`](crate::ApiError::QueueFull))
    /// rather than growing without bound while middlewared is unreachable.
    pub max_queued_bulk_items: usize,
}

impl Default for ApiConfig {
    fn default() -> Self {
        ApiConfig {
            socket_path: PathBuf::from("/var/run/middleware/middlewared.sock"),
            endpoint: "/api/current".into(),
            max_sessions: 32,
            max_message_bytes: 64 * 1024 * 1024,
            connect_timeout: Some(Duration::from_secs(10)),
            call_timeout: None,
            bulk_tick: Duration::from_secs(10),
            max_queued_bulk_items: 10_000,
        }
    }
}

impl ApiConfig {
    /// The `net::client` tuning this projects to.
    ///
    /// `expect_server_push` is unconditional: notifications arrive with
    /// nothing awaiting, and correlation is by JSON-RPC id, never the
    /// transport's FIFO pairing. `max_in_flight` is a transport-accounting
    /// ceiling, not the concurrency limit (that is the per-session budget
    /// against middlewared's own semaphore): control replies and pushes
    /// drain the transport's FIFO out of step with sends, so the only
    /// requirement is "never reachable in practice". The idle and response
    /// clocks stay off - a subscribed session is legitimately silent for
    /// hours, and a unix-socket peer is not a slow-loris to defend
    /// against.
    pub(crate) fn to_client(&self) -> ClientConfig {
        ClientConfig {
            pool_size: self.max_sessions,
            max_reply_bytes: self.max_message_bytes,
            max_in_flight: 1024,
            connect_timeout: self.connect_timeout,
            expect_server_push: true,
            ..ClientConfig::default()
        }
    }
}

/// Per-session options: the identity to dial under, the job answering
/// mode, and the outbound cap.
#[derive(Clone, Debug)]
pub struct SessionOpts {
    /// Dial under this registered personality, so middlewared's
    /// SO_PEERCRED auto-auth sees the minted identity: uid 0 (from a
    /// non-interactive daemon) authenticates as full admin, and any other
    /// uid authenticates as that TrueNAS user - **iff** the uid maps to a
    /// user whose groups compose at least one privilege and PAM's
    /// `middleware-unix` stack admits it. A uid that clears neither is
    /// connected but unauthenticated: only the `authentication_required=
    /// False` methods answer, everything else fails `ENOTAUTHENTICATED`.
    ///
    /// `None` dials as the daemon itself (ambient credentials). The id
    /// must come from the ring this client runs on - see
    /// [`Personality`].
    pub personality: Option<Personality>,
    /// Keep middlewared's legacy job answering: a job method's result is
    /// the integer job id, immediately. `false` (the default) sends
    /// `core.set_options {"legacy_jobs": false}` at session setup - the
    /// reference client's behavior - so a job call's result arrives when
    /// the job finishes.
    pub legacy_jobs: bool,
    /// Refuse an outbound message longer than this before it reaches the
    /// wire. The default is middlewared's authenticated cap
    /// ([`MIDDLEWARE_MSG_CAP`]); raise to
    /// [`MIDDLEWARE_MSG_CAP_EXTENDED`] only for a session that calls the
    /// two whitelisted upload methods.
    pub max_outbound_bytes: usize,
}

impl Default for SessionOpts {
    fn default() -> Self {
        SessionOpts {
            personality: None,
            legacy_jobs: false,
            max_outbound_bytes: MIDDLEWARE_MSG_CAP,
        }
    }
}

impl SessionOpts {
    /// Dial under `who` (see [`SessionOpts::personality`]).
    pub fn personality(mut self, who: Personality) -> SessionOpts {
        self.personality = Some(who);
        self
    }

    /// Keep legacy job answering (see [`SessionOpts::legacy_jobs`]).
    pub fn legacy_jobs(mut self) -> SessionOpts {
        self.legacy_jobs = true;
        self
    }
}
