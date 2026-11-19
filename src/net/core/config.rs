//! [`CoreConfig`]: the engine-read subset of a role config, shared by the core.

use crate::uring::force_async::ForceAsync;
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
    pub(crate) max_receipt_time: Option<Duration>,
    pub(crate) receipt_window_bytes: usize,
    pub(crate) send_timeout: Option<Duration>,
    pub(crate) tls_handshake_timeout: Option<Duration>,
    pub(crate) recv_shortage_retry: Option<Duration>,
    pub(crate) force_async: ForceAsync,
    /// The smallest gather sent zero-copy. `usize::MAX` turns zero-copy off.
    pub(crate) zc_threshold: usize,
    pub(crate) zc_max_pinned: usize,
    pub(crate) zc_linger: Duration,
}

impl CoreConfig {
    #[cfg(feature = "net-server")]
    pub(crate) fn zero_copy(&self) -> bool {
        self.zc_threshold != usize::MAX
    }
}
