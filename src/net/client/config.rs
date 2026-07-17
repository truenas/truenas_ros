//! [`ClientConfig`]: client tuning, its validation, and its projection into the
//! engine-read [`CoreConfig`].

use crate::error::Error;
use crate::net::core::config::CoreConfig;
use std::time::Duration;

/// The largest usable pool slot (the `user_data` codec reserves 24 bits).
const MAX_POOL: u32 = 0x00ff_ffff;
/// Upper bound on `max_in_flight` (bounds per-connection pipelining).
const MAX_IN_FLIGHT: usize = 4096;
/// Upper bound on `max_send_coalesce` (the kernel's `UIO_MAXIOV`).
const MAX_SEND_COALESCE: usize = 1024;

/// Client tuning knobs (the outbound analogue of `ServerConfig`).
#[derive(Clone, Copy, Debug)]
pub struct ClientConfig {
    /// Maximum concurrent connections (size of the registered-file pool).
    pub pool_size: u32,
    /// Maximum bytes accepted for one reply (header + body) — a memory guard
    /// that also bounds header scanning. Projects to the engine's request cap.
    pub max_reply_bytes: usize,
    /// Maximum requests in flight per connection before [`send`] returns
    /// `WouldBlock`. `1` (the default) is strict request/reply: one request is
    /// answered before the next is sent. `N > 1` pipelines — the connection's
    /// protocol must then carry ids so replies (delivered in FIFO order) can be
    /// correlated.
    ///
    /// [`send`]: super::Client::send
    pub max_in_flight: usize,
    /// Read reply bodies at least this large into their own allocation, moved
    /// out zero-copy. `None` disables placement. Default 64 KiB.
    pub body_placement_threshold: Option<usize>,
    /// Maximum bytes queued to send on one connection before [`send`] returns
    /// `WouldBlock` (a peer not draining its socket). Default 8 MiB.
    ///
    /// [`send`]: super::Client::send
    pub max_send_backlog: usize,
    /// Maximum queued PDUs gathered into one `SENDMSG` (writev coalescing).
    /// `1` disables coalescing; capped at 1024. Default 8.
    pub max_send_coalesce: usize,
    /// Set `TCP_NODELAY` on the socket (no Nagle delay on whole framed
    /// messages). Default `true`. Ignored for unix.
    pub nodelay: bool,
    /// Enable `SO_KEEPALIVE` with `TCP_KEEPIDLE` at this duration (rounded up
    /// to a whole second). `None` (the default) leaves keepalive off. Ignored
    /// for unix.
    pub keepalive: Option<Duration>,
    /// Set `TCP_USER_TIMEOUT` (unacknowledged-data abort window). `None` (the
    /// default) uses the system default. Ignored for unix.
    pub tcp_user_timeout: Option<Duration>,
    /// Default bound on an `IORING_OP_CONNECT` (a linked timeout);
    /// per-connect [`ConnectOpts::connect_timeout`](super::ConnectOpts) overrides
    /// it. `None` (the default) uses the kernel's own connect timeout.
    pub connect_timeout: Option<Duration>,
    /// If set, close a connection whose in-progress reply is not fully received
    /// within this duration (a reverse slow-loris guard). Projects to the
    /// engine's `request_timeout`. `None` (the default) never times a reply out —
    /// so a framer that returns a `SpliceBody` verdict should set this: otherwise
    /// a server that sends a body header then stalls mid-splice pins the
    /// connection's pool slot indefinitely (the splice inactivity watchdog is
    /// gated on `response_timeout`).
    pub response_timeout: Option<Duration>,
    /// If set, close a connection whose in-flight send makes no progress for
    /// this long (a peer that stopped reading). `None` (the default) never
    /// times sends out.
    pub send_timeout: Option<Duration>,
    /// If set, close a connection left idle — no request in flight, no reply
    /// awaited — for longer than this, reclaiming its slot. `None` (the
    /// default) keeps idle connections open.
    pub idle_timeout: Option<Duration>,
    /// If set, bound a kTLS connect handshake: a connection parked while its
    /// consumer handshake worker runs `SSL_connect` is shed with `ConnectFailed`
    /// if the worker does not call back within this duration. `None` (the default)
    /// never times a handshake out.
    pub tls_handshake_timeout: Option<Duration>,
    /// Whether the server may send unsolicited PDUs (pushes) — a reply arriving
    /// with no request awaiting it. `false` (the default) treats one as a
    /// protocol violation and closes the connection; `true` surfaces it as an
    /// [`Event::Reply`](super::Event::Reply) with
    /// [`RequestId::UNSOLICITED`](super::RequestId::UNSOLICITED).
    pub expect_server_push: bool,
}

impl Default for ClientConfig {
    fn default() -> Self {
        ClientConfig {
            pool_size: 512,
            max_reply_bytes: 1024 * 1024,
            max_in_flight: 1,
            body_placement_threshold: Some(64 * 1024),
            max_send_backlog: 8 * 1024 * 1024,
            max_send_coalesce: 8,
            nodelay: true,
            keepalive: None,
            tcp_user_timeout: None,
            connect_timeout: None,
            response_timeout: None,
            send_timeout: None,
            idle_timeout: None,
            tls_handshake_timeout: None,
            expect_server_push: false,
        }
    }
}

impl ClientConfig {
    /// Construction-time validation, mirroring `ServerConfig::validate`:
    /// [`Client::new`](super::Client::new) fails with a validation error on the
    /// first violated bound before any socket or ring is created.
    pub(super) fn validate(&self) -> crate::Result<()> {
        if self.pool_size == 0 || self.pool_size > MAX_POOL {
            return Err(Error::Validation(format!(
                "pool_size must be in 1..={MAX_POOL}"
            )));
        }
        if self.max_reply_bytes == 0 || self.max_reply_bytes > i32::MAX as usize
        {
            return Err(Error::Validation(format!(
                "max_reply_bytes must be in 1..={}",
                i32::MAX
            )));
        }
        if self.max_in_flight == 0 || self.max_in_flight > MAX_IN_FLIGHT {
            return Err(Error::Validation(format!(
                "max_in_flight must be in 1..={MAX_IN_FLIGHT}"
            )));
        }
        if self.max_send_backlog == 0 {
            return Err(Error::Validation(
                "max_send_backlog must be non-zero".into(),
            ));
        }
        if self.max_send_coalesce == 0
            || self.max_send_coalesce > MAX_SEND_COALESCE
        {
            return Err(Error::Validation(format!(
                "max_send_coalesce must be in 1..={MAX_SEND_COALESCE}"
            )));
        }
        for (name, d) in [
            ("connect_timeout", self.connect_timeout),
            ("response_timeout", self.response_timeout),
            ("send_timeout", self.send_timeout),
            ("idle_timeout", self.idle_timeout),
            ("tls_handshake_timeout", self.tls_handshake_timeout),
            ("keepalive", self.keepalive),
            ("tcp_user_timeout", self.tcp_user_timeout),
        ] {
            if matches!(d, Some(d) if d.is_zero()) {
                return Err(Error::Validation(format!(
                    "{name} must be non-zero"
                )));
            }
        }
        Ok(())
    }

    /// Project the engine-read subset into the reactor core. `response_timeout`
    /// maps to the engine's `request_timeout` slot (both bound the receipt of a
    /// framed message that has begun arriving), and `max_reply_bytes` to its
    /// message cap.
    pub(super) fn to_core(self) -> CoreConfig {
        CoreConfig {
            max_request_bytes: self.max_reply_bytes,
            body_placement_threshold: self.body_placement_threshold,
            max_send_coalesce: self.max_send_coalesce,
            max_send_backlog: self.max_send_backlog,
            max_in_flight_requests: self.max_in_flight,
            idle_timeout: self.idle_timeout,
            request_timeout: self.response_timeout,
            send_timeout: self.send_timeout,
            tls_handshake_timeout: self.tls_handshake_timeout,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_validates() {
        ClientConfig::default()
            .validate()
            .expect("default is valid");
    }

    #[test]
    fn rejects_bad_knobs() {
        let bad = ClientConfig {
            pool_size: 0,
            ..ClientConfig::default()
        };
        assert!(bad.validate().is_err());
        let bad = ClientConfig {
            max_in_flight: 0,
            ..ClientConfig::default()
        };
        assert!(bad.validate().is_err());
        let bad = ClientConfig {
            connect_timeout: Some(Duration::ZERO),
            ..ClientConfig::default()
        };
        assert!(bad.validate().is_err());
    }

    #[test]
    fn maps_response_timeout_to_request_timeout() {
        let cfg = ClientConfig {
            response_timeout: Some(Duration::from_secs(3)),
            max_reply_bytes: 4096,
            ..ClientConfig::default()
        };
        let core = cfg.to_core();
        assert_eq!(core.request_timeout, Some(Duration::from_secs(3)));
        assert_eq!(core.max_request_bytes, 4096);
    }
}
