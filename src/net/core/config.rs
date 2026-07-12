//! [`CoreConfig`]: the engine-read subset of a role config, shared by the core.

use std::time::Duration;

/// The engine-read tuning knobs a role config projects into the reactor core.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug)]
pub(crate) struct CoreConfig {
    pub(crate) max_request_bytes: usize,
    pub(crate) body_placement_threshold: Option<usize>,
    pub(crate) max_send_coalesce: usize,
    pub(crate) max_send_backlog: usize,
    pub(crate) max_in_flight_requests: usize,
    pub(crate) idle_timeout: Option<Duration>,
    pub(crate) request_timeout: Option<Duration>,
    pub(crate) send_timeout: Option<Duration>,
    pub(crate) tls_handshake_timeout: Option<Duration>,
}
