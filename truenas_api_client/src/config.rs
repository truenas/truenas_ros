//! [`ApiConfig`] (per-client) and [`SessionOpts`] (per-session), and the projection into the underlying `net::client`
//! tuning.

use crate::error::ApiError;
use std::path::PathBuf;
use std::time::Duration;
use truenas_ros::net::client::{ClientConfig, Personality};

/// middlewared's per-message inbound cap for an authenticated session (`MsgSizeLimit.AUTHENTICATED`,
/// `middlewared/utils/limits.py`) - root included. Above it the server does not fail the call, it **closes the
/// connection** (WS close 1009), so the client refuses locally at this bound instead
/// ([`ApiError::TooLarge`](crate::ApiError::TooLarge)).
///
/// An unauthenticated session's cap is 8192. Over the unix socket middlewared authenticates the peer by `SO_PEERCRED`
/// before the first message (`check_permission`, `middlewared/plugins/auth.py`), but it can leave the session
/// unauthenticated without telling the client, when the uid has no passwd entry or PAM refuses it. Such a session can
/// still call `auth.login*` and the other exempt methods, under the 8192 cap. For a session expected to stay
/// unauthenticated, set [`SessionOpts::max_outbound_bytes`] to 8192, which then binds the [`MSG_SIZE_EXTENDED_METHODS`]
/// too.
pub const MIDDLEWARE_MSG_CAP: usize = 65_536;

/// middlewared's extended cap, honored only for the whitelisted upload-shaped methods ([`MSG_SIZE_EXTENDED_METHODS`]).
/// Applied per method, because that is how the server applies it - see [`SessionOpts::max_outbound_bytes`].
pub const MIDDLEWARE_MSG_CAP_EXTENDED: usize = 2_097_152;

/// The methods middlewared exempts from [`MIDDLEWARE_MSG_CAP`], allowing them [`MIDDLEWARE_MSG_CAP_EXTENDED`] instead
/// (`MSG_SIZE_EXTENDED_METHODS` in `middlewared/utils/limits.py`).
pub const MSG_SIZE_EXTENDED_METHODS: [&str; 2] = ["filesystem.file_receive", "failover.datastore.sql"];

/// The outbound cap that applies to `method` on a session whose ordinary cap is `ordinary`.
///
/// middlewared decides per message, after parsing (`parse_message`, `middlewared/utils/limits.py`). It refuses above
/// [`MIDDLEWARE_MSG_CAP_EXTENDED`] outright and applies the ordinary cap to every method but the whitelisted ones.
pub(crate) fn outbound_cap(ordinary: usize, method: &str) -> usize {
    // The exemption only raises a session at the ordinary cap. One lowered below it was constrained on purpose, and
    // `parse_message` refuses an unauthenticated message above 8192 before it reads `method` anyway.
    if ordinary >= MIDDLEWARE_MSG_CAP && MSG_SIZE_EXTENDED_METHODS.contains(&method) {
        MIDDLEWARE_MSG_CAP_EXTENDED
    } else {
        ordinary
    }
}

/// Client-wide configuration. `Default` talks to the production middlewared socket at `/api/current`.
#[derive(Clone, Debug)]
pub struct ApiConfig {
    /// The middlewared unix socket.
    pub socket_path: PathBuf,
    /// The WebSocket endpoint. `/api/current` (the default) tracks the newest API like the reference client; pin
    /// `/api/v26.0.0`-style to freeze schemas across a middleware upgrade (`GET /api/versions` enumerates what a server
    /// offers).
    ///
    /// Screened by [`validate_endpoint`] before the dial: it goes into the request line verbatim, and an API version
    /// below [`MIN_API_VERSION`] cannot honour this client's job model.
    pub endpoint: String,
    /// Maximum concurrent sessions (one connection each).
    pub max_sessions: u32,
    /// Cap on one inbound message (a call result or an event). Server to client is unbounded at the source - a big
    /// `query` result arrives as one WebSocket text frame - so this is the client's own memory guard; a message above
    /// it closes that session.
    pub max_message_bytes: usize,
    /// Bound on dial + upgrade for one session.
    pub connect_timeout: Option<Duration>,
    /// Default bound on one call, measured from submission to its completion event. `None` never times a call out - job
    /// methods legitimately run for hours with `legacy_jobs` off.
    pub call_timeout: Option<Duration>,
    /// How often the deferred queue ([`queue_bulk`](crate::ApiClient::queue_bulk)) flushes: each tick, every method
    /// with queued items goes out as one `core.bulk` call. Batching this way keeps background work from overloading
    /// middlewared with a request per item.
    pub bulk_tick: Duration,
    /// Cap on items held in the deferred queue at once, across every session. `queue_bulk` refuses past it
    /// ([`ApiError::QueueFull`](crate::ApiError::QueueFull)).
    ///
    /// A count does not bound memory, so [`ApiConfig::max_queued_bulk_bytes`] does that. An item too large to flush is
    /// still accepted, and fails at the flush with [`ApiError::TooLarge`](crate::ApiError::TooLarge).
    pub max_queued_bulk_items: usize,
    /// Cap on the bytes the deferred queue holds at once, across every session. Charged against the encoded params, and
    /// refused with [`ApiError::QueueFull`](crate::ApiError::QueueFull) like the item count, whichever trips first.
    pub max_queued_bulk_bytes: usize,
    /// Cap on calls one session holds queued behind its concurrency budget ([`CALL_BUDGET`](crate::CALL_BUDGET)). A
    /// submission past it is refused with [`ApiError::QueueFull`](crate::ApiError::QueueFull) rather than accepted into
    /// a queue with no bound.
    ///
    /// A count does not bound memory, since an upload method's frame may be [`MIDDLEWARE_MSG_CAP_EXTENDED`], so
    /// [`ApiConfig::max_queued_bytes`] does that.
    pub max_queued_calls: usize,
    /// Cap on the bytes one session holds queued behind its concurrency budget. A submission that would push the
    /// backlog past this is refused with [`ApiError::QueueFull`](crate::ApiError::QueueFull), whichever of the two caps
    /// it trips first.
    pub max_queued_bytes: usize,
    /// Cap on the events a *blocking* helper ([`ApiClient::call`](crate::ApiClient::call),
    /// [`ApiClient::connect`](crate::ApiClient::connect)) may set aside while it waits for the one it wants. Past it
    /// the wait fails with [`ApiError::QueueFull`](crate::ApiError::QueueFull) rather than buffering without limit.
    ///
    /// The peer fills this queue, at whatever rate a subscribed session's updates arrive.
    /// [`ApiClient::pump`](crate::ApiClient::pump) buffers nothing, so a consumer that wants no bound uses it instead.
    pub max_waiting_events: usize,
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
            max_queued_bulk_bytes: 64 * 1024 * 1024,
            max_queued_calls: 256,
            max_queued_bytes: 16 * 1024 * 1024,
            max_waiting_events: 4096,
        }
    }
}

/// The oldest API version this client speaks. middlewared serves every version at once
/// (`Middleware._load_api_versions`), so [`ApiConfig::endpoint`] picks the version and not the appliance release.
///
/// Below this, `core.set_options` drops `legacy_jobs` and leaves `App.legacy_jobs` at `true` (`api/v25_04_1/core.py`,
/// and `CoreSetOptionsResult.to_previous` in `api/v25_10_0/core.py`), so every job call would answer with its job id
/// rather than its result.
pub const MIN_API_VERSION: (u32, u32, u32) = (26, 0, 0);

/// Screen an endpoint before it reaches the wire. It must be a usable request-target, since it is spliced into the
/// request line, and an API version it names must be at or above [`MIN_API_VERSION`].
///
/// Only an explicit `/api/v<major>.<minor>[.<patch>]` is compared, and `/api/current` or any other path passes the
/// version test. A bad target fails with [`ApiError::Handshake`] and an old version with
/// [`ApiError::UnsupportedApiVersion`].
pub fn validate_endpoint(endpoint: &str) -> Result<(), ApiError> {
    truenas_ros::ws::validate_request_target(endpoint).map_err(ApiError::Handshake)?;
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

/// The `(major, minor, patch)` an endpoint pins, or `None` when it names no version. Absent components read as 0, so
/// `/api/v26.0` is `(26, 0, 0)`.
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
    /// `expect_server_push` is unconditional, since notifications arrive with nothing awaiting. `max_in_flight` is only
    /// a transport accounting ceiling that must never be reached, since correlation is by JSON-RPC id and the
    /// concurrency limit is the session budget. The idle and response clocks stay off, as a subscribed session may be
    /// silent for hours.
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

/// Per-session options: the identity to dial under, the job answering mode, and the outbound cap.
#[derive(Clone, Debug)]
pub struct SessionOpts {
    /// Dial under this registered personality, so middlewared's SO_PEERCRED auto-auth sees the minted identity: uid 0
    /// (from a non-interactive daemon) authenticates as full admin, and any other uid authenticates as that TrueNAS
    /// user - **iff** the uid maps to a user whose groups compose at least one privilege and PAM's `middleware-unix`
    /// stack admits it. A uid that clears neither is connected but unauthenticated: only the `authentication_required=
    /// False` methods answer, everything else fails `ENOTAUTHENTICATED`.
    ///
    /// `None` dials as the daemon itself (ambient credentials). The id must come from the ring this client runs on -
    /// see [`Personality`].
    pub personality: Option<Personality>,
    /// Keep middlewared's legacy job answering: a job method's result is the integer job id, immediately. `false` (the
    /// default) sends `core.set_options {"legacy_jobs": false}` at session setup - the reference client's behavior - so
    /// a job call's result arrives when the job finishes.
    pub legacy_jobs: bool,
    /// Refuse an outbound message longer than this before it reaches the wire. The default is middlewared's
    /// authenticated cap ([`MIDDLEWARE_MSG_CAP`]).
    ///
    /// This is the cap for an ordinary call. The upload methods ([`MSG_SIZE_EXTENDED_METHODS`]) get
    /// [`MIDDLEWARE_MSG_CAP_EXTENDED`] automatically while this is at least [`MIDDLEWARE_MSG_CAP`], as the server
    /// grants it per method. Do not raise this for an upload, since the server closes the connection over the first
    /// ordinary call above its cap. Lower it to bound what this session may send.
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

#[cfg(test)]
mod tests {
    use super::{MIDDLEWARE_MSG_CAP, MIDDLEWARE_MSG_CAP_EXTENDED, MSG_SIZE_EXTENDED_METHODS, outbound_cap};

    /// The extended cap is an exemption from the ordinary one, so it may only ever raise a session that has the
    /// ordinary one, and never one lowered to 8192 for an unauthenticated session.
    #[test]
    fn the_extended_cap_cannot_raise_a_lowered_session() {
        for m in MSG_SIZE_EXTENDED_METHODS {
            // The control: an ordinary session still gets the exemption.
            assert_eq!(
                outbound_cap(MIDDLEWARE_MSG_CAP, m),
                MIDDLEWARE_MSG_CAP_EXTENDED,
                "{m}: an ordinary session must keep the exemption"
            );
            // ...and a session lowered below the ordinary cap does not.
            assert_eq!(
                outbound_cap(8192, m),
                8192,
                "{m}: the exemption overrode a deliberately lowered cap"
            );
            // A cap raised above the ordinary one keeps it too.
            assert_eq!(
                outbound_cap(MIDDLEWARE_MSG_CAP * 2, m),
                MIDDLEWARE_MSG_CAP_EXTENDED,
                "{m}: above the ordinary cap the exemption still applies"
            );
        }
        // Every other method is the caller's cap, whatever it is.
        for cap in [8192, MIDDLEWARE_MSG_CAP, MIDDLEWARE_MSG_CAP_EXTENDED] {
            assert_eq!(outbound_cap(cap, "core.ping"), cap);
        }
    }
}
