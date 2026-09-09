//! [`ApiConfig`] (per-client) and [`SessionOpts`] (per-session), and the
//! projection into the underlying `net::client` tuning.

use crate::error::ApiError;
use std::path::PathBuf;
use std::time::Duration;
use truenas_ros::net::client::{ClientConfig, Personality};

/// middlewared's per-message inbound cap for an authenticated session
/// (`MsgSizeLimit.AUTHENTICATED`, `middlewared/utils/limits.py`) - root
/// included. Above it the server does not fail the call, it **closes the
/// connection** (WS close 1009), so the client refuses locally at this
/// bound instead ([`ApiError::TooLarge`](crate::ApiError::TooLarge)).
///
/// An *unauthenticated* session's cap is 8192, and this default does not
/// use it on purpose. This client dials the unix socket, where
/// middlewared's `core.on_connect` hook authenticates the peer by
/// `SO_PEERCRED` *before* the first message is parsed
/// (`check_permission`, `middlewared/plugins/auth.py`), so a session that
/// is going to authenticate already has. One that is not - a uid PAM or
/// privilege composition refuses - answers `ENOTAUTHENTICATED` to every
/// call it can make anyway, so defaulting to 8192 would buy a tidier
/// failure on a session that is already useless and cost every ordinary
/// session the 8 KiB to 64 KiB range the server accepts. Set
/// [`SessionOpts::max_outbound_bytes`] to 8192 for a session expected to
/// stay unauthenticated.
pub const MIDDLEWARE_MSG_CAP: usize = 65_536;

/// middlewared's extended cap, honored only for the whitelisted
/// upload-shaped methods ([`MSG_SIZE_EXTENDED_METHODS`]). Applied per
/// method, because that is how the server applies it - see
/// [`SessionOpts::max_outbound_bytes`].
pub const MIDDLEWARE_MSG_CAP_EXTENDED: usize = 2_097_152;

/// The methods middlewared exempts from [`MIDDLEWARE_MSG_CAP`], allowing
/// them [`MIDDLEWARE_MSG_CAP_EXTENDED`] instead
/// (`MSG_SIZE_EXTENDED_METHODS` in `middlewared/utils/limits.py`). The
/// exemption is why they are also the methods middlewared does not audit.
pub const MSG_SIZE_EXTENDED_METHODS: [&str; 2] =
    ["filesystem.file_receive", "failover.datastore.sql"];

/// The outbound cap that applies to `method` on a session whose ordinary
/// cap is `ordinary`.
///
/// middlewared decides this per message, after parsing, and only then:
/// `parse_message` (`middlewared/utils/limits.py`) refuses above
/// [`MIDDLEWARE_MSG_CAP_EXTENDED`] outright, reads `method`, returns
/// early for a whitelisted one, and applies the ordinary cap to
/// everything else. A single per-session number cannot mirror that - it
/// is either too small for the upload or too large for every other call
/// on the same session - so the cap is chosen per call here too.
pub(crate) fn outbound_cap(ordinary: usize, method: &str) -> usize {
    if MSG_SIZE_EXTENDED_METHODS.contains(&method) {
        MIDDLEWARE_MSG_CAP_EXTENDED
    } else {
        ordinary
    }
}

/// Client-wide configuration. `Default` talks to the production middlewared
/// socket at `/api/current`.
#[derive(Clone, Debug)]
pub struct ApiConfig {
    /// The middlewared unix socket.
    pub socket_path: PathBuf,
    /// The WebSocket endpoint. `/api/current` (the default) tracks the
    /// newest API like the reference client; pin `/api/v26.0.0`-style to
    /// freeze schemas across a middleware upgrade (`GET /api/versions`
    /// enumerates what a server offers).
    ///
    /// Screened by [`validate_endpoint`] before the dial: it goes into
    /// the request line verbatim, and an API version below
    /// [`MIN_API_VERSION`] cannot honour this client's job model.
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
    /// Cap on calls one session holds queued behind its concurrency
    /// budget ([`CALL_BUDGET`](crate::CALL_BUDGET)). A submission past it
    /// is refused with [`ApiError::QueueFull`](crate::ApiError::QueueFull)
    /// rather than accepted into a queue with no bound.
    ///
    /// The queue holds encoded frames, so the memory it can reach is this
    /// times [`SessionOpts::max_outbound_bytes`] - 16 MiB per session at
    /// the defaults. It is the depth a caller may pipeline *beyond* what
    /// middlewared will run at once, so a few hundred is already far more
    /// outstanding work than the server's own semaphore admits; the point
    /// of the number is that there is one.
    pub max_queued_calls: usize,
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
            max_queued_calls: 256,
        }
    }
}

/// The oldest API version this client speaks: middlewared serves every
/// version concurrently, one per directory under `middlewared/api/`
/// (`Middleware._load_api_versions`), so which one is in force is chosen
/// by [`ApiConfig::endpoint`] and not by the appliance release.
///
/// The floor is a job-model requirement, not a preference. `core.set_options`
/// grew `legacy_jobs` in `api/v25_10_0/core.py`; every version below that
/// accepts only `py_exceptions` and drops the rest (`extra="ignore"`,
/// `api/v25_04_1/core.py`), leaves `App.legacy_jobs` at its default of
/// `true`, and has `CoreSetOptionsResult.to_previous` rewrite the echo to
/// `null` on the way down. A session pinned there would ask for modern job
/// answering, be refused in silence, and then decode every job's integer id
/// as the caller's result.
pub const MIN_API_VERSION: (u32, u32, u32) = (26, 0, 0);

/// Screen an endpoint before it reaches the wire: a usable request-target
/// (`ws::validate_request_target` - the endpoint is spliced into the
/// request line, so CR, LF or a space there splits the request), and, when
/// it names an API version, one at or above [`MIN_API_VERSION`].
///
/// `/api/current` and any path that does not look like a version pin pass
/// the version test: `current` is whatever the server calls newest, and a
/// deployment may front middlewared on some other path. Only an explicit
/// `/api/v<major>.<minor>[.<patch>]` is compared, which is the form
/// `Middleware._load_api_versions` derives from its own directory names.
pub fn validate_endpoint(endpoint: &str) -> Result<(), ApiError> {
    truenas_ros::ws::validate_request_target(endpoint)
        .map_err(ApiError::Handshake)?;
    let Some(v) = pinned_api_version(endpoint) else {
        return Ok(());
    };
    if v < MIN_API_VERSION {
        return Err(ApiError::UnsupportedApiVersion {
            pinned: v,
            minimum: MIN_API_VERSION,
        });
    }
    Ok(())
}

/// The `(major, minor, patch)` an endpoint pins, or `None` when it names
/// no version. Absent components read as 0, so `/api/v26.0` is
/// `(26, 0, 0)`.
fn pinned_api_version(endpoint: &str) -> Option<(u32, u32, u32)> {
    let rest = endpoint.strip_prefix("/api/v")?;
    let rest = rest.split('/').next()?;
    let mut it = rest.split('.');
    let major = it.next()?.parse().ok()?;
    let minor = it.next().map_or(Some(0), |p| p.parse().ok())?;
    let patch = it.next().map_or(Some(0), |p| p.parse().ok())?;
    if it.next().is_some() {
        return None;
    }
    Some((major, minor, patch))
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
    /// ([`MIDDLEWARE_MSG_CAP`]).
    ///
    /// This is the cap for an *ordinary* call. The whitelisted upload
    /// methods ([`MSG_SIZE_EXTENDED_METHODS`]) get
    /// [`MIDDLEWARE_MSG_CAP_EXTENDED`] automatically, because that is
    /// how the server grants it - per method, after parsing, not per
    /// connection. Raising this by hand for an upload would lift the cap
    /// on every other call the session makes, and the server would close
    /// the connection over the first one above 64 KiB rather than
    /// answering it.
    ///
    /// Lower it to bound what this session may send; raising it above
    /// [`MIDDLEWARE_MSG_CAP`] only moves the refusal from here to the
    /// server, which answers with a close rather than an error.
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
