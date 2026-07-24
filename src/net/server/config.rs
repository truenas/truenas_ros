//! Server tuning: [`ServerConfig`], the per-address [`Listen`] opt-in, and
//! the validation limits they are checked against.

#[cfg(doc)]
use super::protocol::Response;
#[cfg(doc)]
use super::{PushHandle, Server};
use crate::error::Error;
use crate::net::core::protocol::ServerAddr;
#[cfg(doc)]
use crate::net::core::protocol::{Body, ClientAddr, CloseReason};
use std::time::Duration;

/// The largest usable pool slot (the `user_data` codec reserves 24 bits).
const MAX_POOL: u32 = 0x00ff_ffff;
/// Upper bound on `max_in_flight_requests` (bounds per-connection read-ahead).
const MAX_IN_FLIGHT: usize = 4096;
/// Upper bound on `max_send_coalesce` (the kernel's `UIO_MAXIOV` — the most
/// iovecs one `msghdr` may carry).
const MAX_SEND_COALESCE: usize = 1024;
/// Upper bound on listeners per server (the index rides the `user_data`
/// slot field of the accept ops).
const MAX_LISTENERS: usize = 256;

/// Server tuning knobs.
#[derive(Clone, Copy, Debug)]
pub struct ServerConfig {
    /// Maximum concurrent connections (size of the registered-file pool),
    /// per **server** — one ring/thread; a `reuse_port` multicore deployment
    /// multiplies it by the server count, but the kernel's reuseport hash is
    /// load-blind, so size each ring's pool for a skewed share rather than
    /// the even split. Worst-case buffer memory is bounded by roughly
    /// `pool_size × max_request_bytes` (every slot held by a near-cap
    /// request, plus per-socket kernel buffers) — the defaults give a
    /// ~512 MiB ceiling. Empty slots are near-free (~32 bytes each), so
    /// headroom costs nothing at idle.
    pub pool_size: u32,
    /// Maximum concurrently-open files for the embedded fs reactor
    /// ([`Request::fs`](super::Request::fs)), or `0` (the default) to disable
    /// it. When non-zero the server registers one shared fixed-file table of
    /// `pool_size + fs_files` slots — connections auto-allocate in
    /// `[0, pool_size)`, opened files take explicit indices in the upper
    /// range — and drives an `async_fs` reactor on this same ring, so a
    /// protocol handler can do filesystem work bound to a request, stamped
    /// with the connection's personality. Requires the `async-fs` feature.
    #[cfg(feature = "async-fs")]
    pub fs_files: u32,
    /// Maximum bytes accepted for one message (header + body), a memory guard
    /// that also bounds header scanning. Enforced strictly for length-prefixed
    /// frames; for a `More`/delimiter-scanning framer the accumulate buffer can
    /// transiently reach `max_request_bytes` plus one chunk read (~4 KiB) — the
    /// chunk lands before the next over-cap check closes the connection — so
    /// budget that slack if a scanning framer's peak allocation matters.
    pub max_request_bytes: usize,
    /// `listen(2)` backlog.
    pub backlog: i32,
    /// For `AF_UNIX`, unlink a stale socket path before binding.
    pub unlink_unix: bool,
    /// If set, close a connection left idle — armed for the next request with no
    /// bytes yet received — for longer than this, reclaiming its pool slot.
    /// `None` (the default) keeps idle connections open indefinitely. Enforced
    /// by a kernel `LINK_TIMEOUT` on the idle recv, so an idle connection costs
    /// no timer wakeups until it either sends or expires. Serving the peer
    /// counts as activity: a completed send (a deferred reply flushing, a
    /// push) restarts the quiet interval, so the connection is reaped only
    /// after a full `idle_timeout` of neither receiving from nor sending to
    /// the peer — never in the instant after a reply it was still waiting on.
    /// Does not interrupt a message already in progress (see `request_timeout`
    /// to bound that).
    pub idle_timeout: Option<Duration>,
    /// If set, close a connection whose in-progress request is not fully
    /// received within this duration, reclaiming its pool slot. Bounds a peer
    /// that sends part of a frame — e.g. a valid length prefix — then stalls,
    /// which `idle_timeout` does not cover (a half-sent request is not idle).
    /// One of the slow-loris guards — see the module *Capacity and overload*
    /// section for how it pairs with `idle_timeout` and `tls_handshake_timeout`.
    ///
    /// Bounds only the *receipt* of a request from the peer, **never its
    /// handling**: once a request reaches the body handler it carries no receive
    /// timer, so one offloaded via [`Response::Defer`] to a worker may run
    /// arbitrarily long without the connection being closed. While a deferred
    /// reply is outstanding, a parked read-ahead recv's `idle_timeout` likewise
    /// does not reap the connection — the pending reply is allowed to arrive.
    /// (The clock still rides a *pipelined* connection's recv reading the **next**
    /// request's bytes, so a peer that starts a further request and then stalls
    /// is reclaimed as usual.)
    ///
    /// Enforced by a kernel `LINK_TIMEOUT` on every in-progress recv, so it
    /// costs no wakeups unless a request actually stalls. For an exact read — a
    /// length-prefixed body or a `Need` header remainder — it bounds the whole
    /// transfer; for a `More`/delimiter scan or a segmented kTLS body it bounds
    /// inactivity between reads (a steadily progressing transfer resets it, a
    /// stalled one is reclaimed). `None` (the default) never times a request out.
    ///
    /// A **spliced** body ([`Framing::SpliceBody`]) is clocked the same way:
    /// on plain TCP the clock rides the readiness poll between splice chunks;
    /// over kTLS it is linked to each record's splice — which otherwise
    /// blocks an io-wq worker with no recv for any timeout to cancel, leaving
    /// a stalled peer pinning the slot forever. On the kTLS path the kernel
    /// cannot distinguish a stalled *peer* from a stalled *consumer* (a full
    /// destination pipe blocks the same op), so a consumer draining slower
    /// than one record per period is evicted too — size accordingly.
    ///
    /// [`Framing::SpliceBody`]: super::Framing::SpliceBody
    pub request_timeout: Option<Duration>,
    /// Maximum requests in flight per connection before read-ahead pauses.
    /// `1` (the default) is strict sequential keep-alive: one request is fully
    /// answered before the next is read. `N > 1` **pipelines** — while a request
    /// is deferred to a worker, up to `N-1` further requests are read and
    /// processed, so responses can complete out of order. In that mode the
    /// consumer's protocol must carry request ids and correlate replies itself;
    /// the server sends replies in production order and never reorders them.
    pub max_in_flight_requests: usize,
    /// If set, close a connection whose in-flight send makes no progress for
    /// this long (a kernel `LINK_TIMEOUT` on each send op). This reclaims the
    /// pool slot from a peer that stops reading while a reply is outstanding —
    /// without it such a connection is held until server shutdown, since TCP
    /// zero-window probing never gives up on its own. The clock resets on
    /// progress: a slow-but-draining peer is not cut off, only a stalled one.
    /// `None` (the default) never times sends out. See also `tcp_user_timeout`.
    pub send_timeout: Option<Duration>,
    /// If set, shed a kTLS connection whose handshake has not completed within
    /// this duration. Between furnishing the real fd to
    /// [`Server::set_tls_handshake`] and the worker calling back, the slot is
    /// parked — it holds a pool descriptor but has no in-flight recv/send, so
    /// neither `idle_timeout` nor `request_timeout` (both linked to a recv) can
    /// reach it. The kTLS-park slow-loris guard — see the module *Capacity and
    /// overload* section.
    ///
    /// A standalone kernel `TIMEOUT` bounds the park; on expiry the slot is shed
    /// (a late `ready()`/`reject()` then hits the bumped generation and is
    /// dropped). Set this whenever `set_tls_handshake` runs a blocking handshake
    /// with no deadline of its own. `None` (the default) never times a handshake
    /// out; ignored for non-TLS listeners.
    pub tls_handshake_timeout: Option<Duration>,
    /// Set `TCP_NODELAY` on TCP listeners — inherited by every accepted
    /// connection on Linux — so each reply PDU is sent immediately rather than
    /// Nagle-delayed. Defaults to `true`: this server writes whole framed
    /// messages, for which Nagle only adds latency (notably when several
    /// pipelined replies are sent back-to-back). Ignored for `AF_UNIX`.
    pub nodelay: bool,
    /// Set `SO_REUSEPORT` on TCP listeners, letting several independent
    /// `Server`s (one ring/thread each) bind the same address and have the
    /// kernel load-balance incoming connections across them — the shared-nothing
    /// multi-core recipe. Each server keeps its own `pool_size` pool, and a
    /// full pool parks only that server's listener while the reuseport hash
    /// keeps routing its share there (no rebalancing to emptier rings), so
    /// provision per-ring pools for uneven placement. Defaults to `false`.
    /// Ignored for `AF_UNIX`.
    pub reuse_port: bool,
    /// Enable `SO_KEEPALIVE` with `TCP_KEEPIDLE` set to this duration (rounded
    /// up to a whole second) on TCP listeners, inherited by accepted
    /// connections. Detects dead peers on otherwise-idle connections at the TCP
    /// level. `None` (the default) leaves keepalive off. Ignored for `AF_UNIX`.
    pub keepalive: Option<Duration>,
    /// Set `TCP_USER_TIMEOUT` (maximum time transmitted data may remain
    /// unacknowledged before TCP aborts the connection) on TCP listeners,
    /// inherited by accepted connections. A transport-level backstop to
    /// `send_timeout`. `None` (the default) uses the system default. Ignored
    /// for `AF_UNIX`.
    pub tcp_user_timeout: Option<Duration>,
    /// For `AF_UNIX` listeners: fetch each peer's credentials (`SO_PEERCRED`,
    /// via an io_uring socket command) before running the accept handler,
    /// delivering them as [`ClientAddr::Unix`]`{ cred: Some(..) }` for local
    /// authentication. Requires a kernel that accepts socket commands on
    /// `AF_UNIX` — Linux ≥ 6.18.16 (the interface exists since 6.7 but was
    /// rejected with `EOPNOTSUPP` on `AF_UNIX` until the cmd_net ioctl-guard
    /// fix); [`Server::with_config`] probes once at construction and fails
    /// with a validation error on unsupported kernels. If a per-connection
    /// fetch fails the connection is shed, never delivered credential-less.
    /// Defaults to `false` (one extra ring round-trip per accept). Ignored
    /// for TCP.
    pub unix_peercred: bool,
    /// Maximum bytes queued to send on one connection before a **push**
    /// ([`PushHandle::push`]) closes it as a slow consumer
    /// ([`CloseReason::SendBacklog`]). Request replies are not evicted by this
    /// bound — they are already limited by `max_in_flight_requests`. Default
    /// 8 MiB.
    pub max_send_backlog: usize,
    /// Maximum queued PDUs (replies and pushes) gathered into one `SENDMSG`
    /// — writev-style reply coalescing. Sends stay one op at a time per
    /// connection in FIFO PDU order, and only PDUs *already queued* when the
    /// send is armed are gathered, so a lone reply is never delayed; what
    /// changes is that a burst of pipelined replies leaves in one syscall/op
    /// (and, with `nodelay`, fewer small segments). `send_timeout` bounds the
    /// whole gathered op. The default (8) matches the kernel's inline-iovec
    /// fast path (`UIO_FASTIOV`); `1` disables coalescing; capped at 1024
    /// (`UIO_MAXIOV`).
    pub max_send_coalesce: usize,
    /// Read message bodies at least this large into their **own** allocation
    /// instead of the connection's accumulate buffer — delivered through
    /// [`Body::take`] as a zero-copy owned `Vec<u8>`, which makes deferring
    /// MB-scale payloads to workers copy-free, and bounds the accumulate
    /// buffer's idle high-water mark. Applies when the body still has bytes
    /// to read at the frame verdict (always, for `Need`-style framers; a
    /// `More`-style framer that already over-read the whole body delivers it
    /// inline, where [`Body::take`] falls back to a copy). `None` disables
    /// placement. Default 64 KiB.
    pub body_placement_threshold: Option<usize>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        ServerConfig {
            pool_size: 512,
            #[cfg(feature = "async-fs")]
            fs_files: 0,
            max_request_bytes: 1024 * 1024,
            backlog: 128,
            unlink_unix: true,
            idle_timeout: None,
            request_timeout: None,
            max_in_flight_requests: 1,
            send_timeout: None,
            tls_handshake_timeout: None,
            nodelay: true,
            reuse_port: false,
            keepalive: None,
            tcp_user_timeout: None,
            unix_peercred: false,
            max_send_backlog: 8 * 1024 * 1024,
            max_send_coalesce: 8,
            body_placement_threshold: Some(64 * 1024),
        }
    }
}

impl ServerConfig {
    /// Construction-time validation of the knobs and the listener list —
    /// [`Server::with_config`] fails with a validation error on the first
    /// violated bound, before any socket or ring is created.
    pub(super) fn validate(&self, addrs: &[Listen]) -> crate::Result<()> {
        if addrs.is_empty() || addrs.len() > MAX_LISTENERS {
            return Err(Error::Validation(format!(
                "listener count must be in 1..={MAX_LISTENERS}"
            )));
        }
        if let Some(bad) = addrs.iter().find(|l| {
            l.tls && !matches!(l.addr, ServerAddr::Tcp(_) | ServerAddr::Tcp6(_))
        }) {
            return Err(Error::Validation(format!(
                "kTLS listeners must be TCP; got {:?}",
                bad.addr
            )));
        }
        if self.pool_size == 0 || self.pool_size > MAX_POOL {
            return Err(Error::Validation(format!(
                "pool_size must be in 1..={MAX_POOL}"
            )));
        }
        // The fs pool shares the one registered file table with the connection
        // pool, so `pool_size + fs_files` (and `fs_files * 2` op slots) must fit
        // the 24-bit slot space — bound it here (checked in u64) rather than
        // overflow the `pool + fs` add in `Engine::new_with_fs`/`FsCore::new`.
        #[cfg(feature = "async-fs")]
        if u64::from(self.pool_size) + u64::from(self.fs_files)
            > u64::from(MAX_POOL)
        {
            return Err(Error::Validation(format!(
                "pool_size + fs_files must not exceed {MAX_POOL}"
            )));
        }
        // Each fs file needs two op slots (`fs_files * 2`), and an op-slot index
        // is packed into the same 24-bit `user_data` slot field as a pool slot.
        // Bound it here so an oversized `fs_files` fails as a clean Validation
        // rather than truncating a completion token later (`MAX_POOL` is that
        // 24-bit ceiling — the `user_data::SLOT_MASK`).
        #[cfg(feature = "async-fs")]
        if u64::from(self.fs_files).saturating_mul(2) > u64::from(MAX_POOL) {
            return Err(Error::Validation(format!(
                "fs_files * 2 must not exceed {MAX_POOL}"
            )));
        }
        if self.max_request_bytes == 0
            || self.max_request_bytes > i32::MAX as usize
        {
            return Err(Error::Validation(format!(
                "max_request_bytes must be in 1..={}",
                i32::MAX
            )));
        }
        if matches!(self.idle_timeout, Some(d) if d.is_zero()) {
            return Err(Error::Validation(
                "idle_timeout must be non-zero".into(),
            ));
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
        if self.max_in_flight_requests == 0
            || self.max_in_flight_requests > MAX_IN_FLIGHT
        {
            return Err(Error::Validation(format!(
                "max_in_flight_requests must be in 1..={MAX_IN_FLIGHT}"
            )));
        }
        for (name, d) in [
            ("send_timeout", self.send_timeout),
            ("request_timeout", self.request_timeout),
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
}

impl ServerConfig {
    #[allow(dead_code)]
    pub(crate) fn to_core(self) -> crate::net::core::config::CoreConfig {
        crate::net::core::config::CoreConfig {
            max_request_bytes: self.max_request_bytes,
            body_placement_threshold: self.body_placement_threshold,
            max_send_coalesce: self.max_send_coalesce,
            max_send_backlog: self.max_send_backlog,
            max_in_flight_requests: self.max_in_flight_requests,
            idle_timeout: self.idle_timeout,
            request_timeout: self.request_timeout,
            send_timeout: self.send_timeout,
            tls_handshake_timeout: self.tls_handshake_timeout,
        }
    }
}

/// One listen address, optionally kernel-TLS. `ServerAddr` converts with TLS
/// off, so a plain `bind([addr])` is unchanged; [`Listen::tls`] opts a single
/// address in.
#[derive(Clone, Debug)]
pub struct Listen {
    pub(super) addr: ServerAddr,
    pub(super) tls: bool,
}

impl Listen {
    /// This address, served over kernel TLS (requires a
    /// [`Server::set_tls_handshake`] handler and a TCP address).
    pub fn tls(addr: ServerAddr) -> Listen {
        Listen { addr, tls: true }
    }
}

impl From<ServerAddr> for Listen {
    fn from(addr: ServerAddr) -> Listen {
        Listen { addr, tls: false }
    }
}
