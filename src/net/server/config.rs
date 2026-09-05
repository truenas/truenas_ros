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

/// Ceiling on the fs offload pool's own thread count - the pool's own
/// constant, shared with the standalone host, which screens the same bound
/// in `UringFs::check`.
#[cfg(feature = "uring-fs")]
use crate::uring_fs::offload_pool::MAX_OFFLOAD_THREADS;
/// Bounds for `fs_body_chunk`: below 4 KiB a multi-GB body is all per-op
/// overhead; above 16 MiB two buffers per streaming connection stop being
/// "bounded" in any useful sense (and a read result must fit an i32).
#[cfg(feature = "uring-fs")]
const MIN_FS_BODY_CHUNK: usize = 4096;
#[cfg(feature = "uring-fs")]
const MAX_FS_BODY_CHUNK: usize = 16 * 1024 * 1024;
/// Upper bound on `max_in_flight_requests` (bounds per-connection read-ahead).
const MAX_IN_FLIGHT: usize = 4096;
/// Upper bound on `max_send_coalesce` (the kernel's `UIO_MAXIOV` - the most
/// iovecs one `msghdr` may carry).
const MAX_SEND_COALESCE: usize = 1024;
/// Upper bound on listeners per server (the index rides the `user_data`
/// slot field of the accept ops).
const MAX_LISTENERS: usize = 256;

/// Server tuning knobs.
#[derive(Clone, Copy, Debug)]
pub struct ServerConfig {
    /// Maximum concurrent connections (size of the registered-file pool),
    /// per **server** - one ring/thread; a `reuse_port` multicore deployment
    /// multiplies it by the server count, but the kernel's reuseport hash is
    /// load-blind, so size each ring's pool for a skewed share rather than
    /// the even split. Worst-case buffer memory is bounded by roughly
    /// `pool_size x max_request_bytes` (every slot held by a near-cap
    /// request, plus per-socket kernel buffers) - the defaults give a
    /// ~512 MiB ceiling. Empty slots are near-free (~32 bytes each), so
    /// headroom costs nothing at idle.
    pub pool_size: u32,
    /// Op-table slots for the embedded fs reactor
    /// ([`Request::fs`](super::Request::fs)), or `0` (the default) to disable
    /// it. When non-zero the server drives an `uring_fs` reactor on this same
    /// ring, and this is the maximum number of **concurrently in-flight fs
    /// operations** a handler may have — the same axis as
    /// [`FsConfig::ops`](crate::uring_fs::FsConfig::ops), and the ceiling a
    /// fan-out actually hits: submitting past it fails `EBUSY` however deep
    /// the ring is.
    ///
    /// **It bounds operations, not open files.** Files are plain raw fds
    /// (`Arc<OwnedFd>`) closed by `Arc`-drop, never registered-table slots,
    /// so nothing here caps how many a handler holds — only how many ops it
    /// may have outstanding at once. A linked chain counts each of its SQEs,
    /// so size this against the deepest chain a handler submits times the
    /// connections that can be mid-chain, not against a file count.
    ///
    /// Plain heap at ~180 bytes a slot, so this is the cheap axis to raise:
    /// 1024 slots is 184 KiB, 128K is 23 MiB. The server adds `pool_size`
    /// slots of its own on top, one per connection for the reply path's body
    /// reads, so a full pool of streaming bodies cannot exhaust the table out
    /// from under handler ops. Requires the `uring-fs` feature.
    #[cfg(feature = "uring-fs")]
    pub fs_ops: u32,
    /// Warm floor of offload worker threads for the embedded fs reactor's
    /// blocking work (`readdir`/`fdopendir`, byte copies), which has no io_uring
    /// opcode and so cannot run on the ring. Default
    /// `uring_fs::core::OFFLOAD_FLOOR`.
    ///
    /// **Per server/ring, and resident.** These spawn on first use and the
    /// idle retire never goes below them, so this is the pool's standing cost,
    /// multiplied by however many servers a deployment runs. Lower it if a
    /// ring's first listings can afford to wait on a thread spawn.
    #[cfg(feature = "uring-fs")]
    pub fs_offload_floor: usize,
    /// Ceiling the offload pool grows to when every worker is blocked (a cold or
    /// huge directory, an NFS/FUSE backing, a stalled copy), so one stalled walk
    /// does not head-of-line-block the rest; burst threads retire when idle.
    /// Default `uring_fs::core::OFFLOAD_CEILING`.
    ///
    /// **Per server/ring**, so the peak is `ceiling x servers` - but only
    /// under load that actually stalls that many operations at once: workers
    /// spawn on demand, one per millisecond, and retire when idle. Size it to
    /// how many concurrently blocked operations one ring should absorb before
    /// they queue, not to request volume.
    #[cfg(feature = "uring-fs")]
    pub fs_offload_ceiling: usize,
    /// Chunk size for file-sourced reply bodies (`Response::ReplyFile`): each
    /// body read moves at most this many bytes, into a ring buffer the
    /// kernel picks at completion. Default 256 KiB; validated to
    /// 4 KiB..=16 MiB.
    ///
    /// Also the size of each buffer in the file-body ring
    /// ([`fs_body_pool`](ServerConfig::fs_body_pool)), which the chunks
    /// come from: resident memory tracks bodies in flight, not the
    /// connection table, and `pool_size x 2 x fs_body_chunk` is the ceiling
    /// only when every connection is mid-body at once. A connection has at
    /// most two chunks out - one landing while the previous one sends -
    /// and that count is fixed, not configurable: on ZFS every ring
    /// read is punted to an io-wq worker (`zpl_file.c` sets no
    /// `FMODE_NOWAIT`), so a deeper pipeline would only deepen that bounded
    /// worker class's queue, and it is the count of connections mid-body,
    /// not the per-connection depth, that multiplies the load.
    #[cfg(feature = "uring-fs")]
    pub fs_body_chunk: usize,
    /// Draw file-body chunk buffers from a registered provided-buffer ring
    /// (`true`, the default), or have each read supply its own.
    ///
    /// There is nothing to size. The ring is registered once with room for
    /// every chunk the server could have in flight at the same moment -
    /// `pool_size` connections times the two-chunks-per-body cap, clamped
    /// to the kernel's 32768-entry limit - and a descriptor slot is 16
    /// bytes, so that headroom is not a memory commitment. Backing buffers
    /// of [`fs_body_chunk`](ServerConfig::fs_body_chunk) bytes are
    /// allocated as demand asks: starting small, doubling when a read finds
    /// the ring dry, halving after idle rounds. Resident memory therefore
    /// tracks bodies in flight, never the connection table.
    #[cfg(feature = "uring-fs")]
    pub fs_body_pool: bool,
    /// Maximum bytes accepted for one message (header + body), a memory guard
    /// that also bounds header scanning. Enforced strictly for length-prefixed
    /// frames; for a `More`/delimiter-scanning framer the accumulate buffer can
    /// transiently reach `max_request_bytes` plus one chunk read (~4 KiB) - the
    /// chunk lands before the next over-cap check closes the connection - so
    /// budget that slack if a scanning framer's peak allocation matters.
    pub max_request_bytes: usize,
    /// Draw receive buffers from a registered provided-buffer ring
    /// (`true`, the default), or have every connection own its receive
    /// buffer.
    ///
    /// A pooled connection holds a buffer only while a message is arriving:
    /// the kernel picks one at *completion* (`IOSQE_BUFFER_SELECT`), so a
    /// keep-alive connection parked on an idle recv holds none, and buffer
    /// memory scales with concurrent arrivals rather than with
    /// [`pool_size`](ServerConfig::pool_size). Watch
    /// [`recv_bufs_lent`](super::ServerStats::recv_bufs_lent): at rest it
    /// settles to zero however many connections are open.
    ///
    /// There is nothing to size here either. The ring is registered with
    /// descriptor slots for every buffer demand can hold at once - each
    /// connection's arriving message plus the leased writes that may still
    /// hold theirs (`RECV_LEASE_DEPTH`) - and backing buffers are allocated
    /// as demand asks, doubling when a completion finds the ring dry and
    /// halving after idle rounds. A message that outgrows its buffer moves
    /// to owned storage and carries on, and a kernel without
    /// provided-buffer rings degrades to owned buffers rather than failing
    /// to bind.
    pub recv_pool: bool,
    /// How the recv side answers a read that found the buffer pool
    /// **genuinely exhausted** - the ring at its registered bound with every
    /// buffer lent, which growth cannot answer. `Some(backoff)` (the
    /// default, 10 ms) parks the read and retries it on a kernel `TIMEOUT`
    /// that period later: the socket is simply not read, its buffer fills,
    /// and TCP pushes back on the peer until a buffer comes home - pool
    /// memory stays at its bound. `None` falls back to reading into a
    /// buffer the connection allocates and owns, which keeps every
    /// connection moving through the spike at the cost of unpooled
    /// allocation scaling with it.
    ///
    /// Ordinary shortage - the pool under its working set but under its
    /// bound too - is not this: it grows the pool and re-arms immediately,
    /// whichever way this is set. The bound is `pool_size` recv slots plus
    /// `RECV_LEASE_DEPTH` leased windows per connection, so only leases
    /// held past their message - a pipelined ingest handler floating
    /// writes - can reach it.
    pub recv_shortage_retry: Option<Duration>,
    /// `listen(2)` backlog.
    pub backlog: i32,
    /// For `AF_UNIX`, unlink a stale socket path before binding.
    pub unlink_unix: bool,
    /// If set, close a connection left idle - armed for the next request with no
    /// bytes yet received - for longer than this, reclaiming its pool slot.
    /// `None` (the default) keeps idle connections open indefinitely. Enforced
    /// by a kernel `LINK_TIMEOUT` on the idle recv, so an idle connection costs
    /// no timer wakeups until it either sends or expires. Serving the peer
    /// counts as activity: a completed send (a deferred reply flushing, a
    /// push) restarts the quiet interval, so the connection is reaped only
    /// after a full `idle_timeout` of neither receiving from nor sending to
    /// the peer - never in the instant after a reply it was still waiting on.
    /// Does not interrupt a message already in progress (see `request_timeout`
    /// to bound that).
    pub idle_timeout: Option<Duration>,
    /// If set, close a connection whose in-progress request is not fully
    /// received within this duration, reclaiming its pool slot. Bounds a peer
    /// that sends part of a frame - e.g. a valid length prefix - then stalls,
    /// which `idle_timeout` does not cover (a half-sent request is not idle).
    /// One of the slow-loris guards - see the module *Capacity and overload*
    /// section for how it pairs with `idle_timeout` and `tls_handshake_timeout`.
    ///
    /// Bounds only the *receipt* of a request from the peer, **never its
    /// handling**: once a request reaches the body handler it carries no receive
    /// timer, so one offloaded via [`Response::Defer`] to a worker may run
    /// arbitrarily long without the connection being closed. While a deferred
    /// reply is outstanding, a parked read-ahead recv's `idle_timeout` likewise
    /// does not reap the connection - the pending reply is allowed to arrive.
    /// (The clock still rides a *pipelined* connection's recv reading the **next**
    /// request's bytes, so a peer that starts a further request and then stalls
    /// is reclaimed as usual.)
    ///
    /// Enforced by a kernel `LINK_TIMEOUT` on every in-progress recv, so it
    /// costs no wakeups unless a request actually stalls. The bound is
    /// **progress per period**, uniformly: a `More`/delimiter scan re-arms on
    /// each arrival, a segmented kTLS body on each record batch, and an exact
    /// read - a length-prefixed body, a streamed window, a `Need` header
    /// remainder - whose clock fires mid-transfer resumes from the bytes that
    /// landed under a fresh clock. A period with zero progress closes the
    /// connection; any progress buys exactly one more period. The corollary
    /// is that this is an inactivity guard, not a rate floor: a transfer's
    /// total time scales with how slowly the peer sends (a trickle of one
    /// byte per period holds the slot indefinitely on every framing, exact
    /// reads included), so a deployment that needs to bound total receipt
    /// time must meter above this layer. `None` (the default) never times a
    /// request out.
    ///
    /// A **spliced** body ([`Framing::SpliceBody`]) is clocked the same way:
    /// on plain TCP the clock rides the readiness poll between splice chunks;
    /// over kTLS it is linked to each record's splice - which otherwise
    /// blocks an io-wq worker with no recv for any timeout to cancel, leaving
    /// a stalled peer pinning the slot forever. On the kTLS path the kernel
    /// cannot distinguish a stalled *peer* from a stalled *consumer* (a full
    /// destination pipe blocks the same op), so a consumer draining slower
    /// than one record per period is evicted too - size accordingly.
    ///
    /// [`Framing::SpliceBody`]: super::Framing::SpliceBody
    pub request_timeout: Option<Duration>,
    /// If set, close a connection that has not **finished receiving** the
    /// message it started within this duration, reclaiming its pool slot.
    ///
    /// `request_timeout` bounds inactivity: any arriving byte buys another
    /// period, so a peer trickling one byte per period holds its slot for as
    /// long as it likes. That is the honest primitive for "is this peer still
    /// there", and it is not a rate floor. This is the rate floor: the clock
    /// starts when a message's first byte arrives and is cancelled when the
    /// message is delivered, so it is never restarted by progress and a
    /// receipt that takes longer than this is closed however busy the wire
    /// was.
    ///
    /// It bounds one **message**, which is what makes it composable with a
    /// streamed body: each window is its own message, so an upload of any
    /// size is admitted while the floor it sets a peer stays
    /// `STREAM_WINDOW / max_receipt_time`. A buffered request is bounded
    /// whole, at `size / max_receipt_time`. Pick it from the slowest client
    /// worth serving, not from the largest upload.
    ///
    /// Bounds only receipt, never handling: the clock is cancelled at
    /// delivery, so a request offloaded via [`Response::Defer`] may run as
    /// long as it likes. A standalone kernel `TIMEOUT`, one per connection,
    /// so it costs no wakeups unless a message is actually in progress.
    /// `None` (the default) never bounds total receipt.
    ///
    /// A slot is taken at **accept**, before any authentication, and accept
    /// is gated on a free slot - so with this unset, `pool_size` peers each
    /// sending one byte per `request_timeout` deny service to everyone else.
    ///
    /// [`Response::Defer`]: super::Response::Defer
    pub max_receipt_time: Option<Duration>,
    /// Maximum requests in flight per connection before read-ahead pauses.
    /// `1` (the default) is strict sequential keep-alive: one request is fully
    /// answered before the next is read. `N > 1` **pipelines** - while a request
    /// is deferred to a worker, up to `N-1` further requests are read and
    /// processed, so responses can complete out of order. In that mode the
    /// consumer's protocol must carry request ids and correlate replies itself;
    /// the server sends replies in production order and never reorders them.
    pub max_in_flight_requests: usize,
    /// If set, close a connection whose in-flight send makes no progress for
    /// this long (a kernel `LINK_TIMEOUT` on each send op). This reclaims the
    /// pool slot from a peer that stops reading while a reply is outstanding --
    /// without it such a connection is held until server shutdown, since TCP
    /// zero-window probing never gives up on its own. The clock resets on
    /// progress: a slow-but-draining peer is not cut off, only a stalled one.
    /// `None` (the default) never times sends out. See also `tcp_user_timeout`.
    pub send_timeout: Option<Duration>,
    /// If set, shed a kTLS connection whose handshake has not completed within
    /// this duration. Between furnishing the real fd to
    /// [`Server::set_tls_handshake`] and the worker calling back, the slot is
    /// parked - it holds a pool descriptor but has no in-flight recv/send, so
    /// neither `idle_timeout` nor `request_timeout` (both linked to a recv) can
    /// reach it. The kTLS-park slow-loris guard - see the module *Capacity and
    /// overload* section.
    ///
    /// A standalone kernel `TIMEOUT` bounds the park; on expiry the slot is shed
    /// (a late `ready()`/`reject()` then hits the bumped generation and is
    /// dropped). Set this whenever `set_tls_handshake` runs a blocking handshake
    /// with no deadline of its own. `None` (the default) never times a handshake
    /// out; ignored for non-TLS listeners.
    pub tls_handshake_timeout: Option<Duration>,
    /// Set `TCP_NODELAY` on TCP listeners - inherited by every accepted
    /// connection on Linux - so each reply PDU is sent immediately rather than
    /// Nagle-delayed. Defaults to `true`: this server writes whole framed
    /// messages, for which Nagle only adds latency (notably when several
    /// pipelined replies are sent back-to-back). Ignored for `AF_UNIX`.
    pub nodelay: bool,
    /// Set `SO_REUSEPORT` on TCP listeners, letting several independent
    /// `Server`s (one ring/thread each) bind the same address and have the
    /// kernel load-balance incoming connections across them - the shared-nothing
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
    /// `AF_UNIX` - Linux >= 6.18.16 (the interface exists since 6.7 but was
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
    /// bound - they are already limited by `max_in_flight_requests`. Default
    /// 8 MiB.
    pub max_send_backlog: usize,
    /// Maximum queued PDUs (replies and pushes) gathered into one `SENDMSG`
    /// -- writev-style reply coalescing. Sends stay one op at a time per
    /// connection in FIFO PDU order, and only PDUs *already queued* when the
    /// send is armed are gathered, so a lone reply is never delayed; what
    /// changes is that a burst of pipelined replies leaves in one syscall/op
    /// (and, with `nodelay`, fewer small segments). `send_timeout` bounds the
    /// whole gathered op. The default (8) matches the kernel's inline-iovec
    /// fast path (`UIO_FASTIOV`); `1` disables coalescing; capped at 1024
    /// (`UIO_MAXIOV`).
    pub max_send_coalesce: usize,
    /// Read message bodies at least this large into their **own** allocation
    /// instead of the connection's accumulate buffer - delivered through
    /// [`Body::take`] as a zero-copy owned `Vec<u8>`, which makes deferring
    /// MB-scale payloads to workers copy-free, and bounds the accumulate
    /// buffer's idle high-water mark. Applies when the body still has bytes
    /// to read at the frame verdict (always, for `Need`-style framers; a
    /// `More`-style framer that already over-read the whole body delivers it
    /// inline, where [`Body::take`] falls back to a copy - except a
    /// **body-only** message at or over this threshold whose extent is
    /// exactly the buffered bytes, which hands the accumulate buffer itself
    /// over: the shape the http 100-continue dance delivers chunked bodies
    /// in, so those arrive owned too). `None` disables placement. Default
    /// 64 KiB.
    pub body_placement_threshold: Option<usize>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        ServerConfig {
            pool_size: 512,
            #[cfg(feature = "uring-fs")]
            fs_ops: 0,
            #[cfg(feature = "uring-fs")]
            fs_offload_floor: crate::uring_fs::core::OFFLOAD_FLOOR,
            #[cfg(feature = "uring-fs")]
            fs_offload_ceiling: crate::uring_fs::core::OFFLOAD_CEILING,
            #[cfg(feature = "uring-fs")]
            fs_body_chunk: 256 * 1024,
            #[cfg(feature = "uring-fs")]
            fs_body_pool: true,
            max_request_bytes: 1024 * 1024,
            recv_pool: true,
            recv_shortage_retry: Some(Duration::from_millis(10)),
            backlog: 128,
            unlink_unix: true,
            idle_timeout: None,
            request_timeout: None,
            max_receipt_time: None,
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
    /// Construction-time validation of the knobs and the listener list --
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
        // The op table holds the handler's whole budget (`fs_ops`) plus one
        // slot per connection for the reply path's body read - a file tail
        // keeps at most one in flight - and an op-slot index is packed into
        // the 24-bit `user_data` slot field. Bound the sum here so an
        // oversized configuration fails as a clean Validation rather than
        // truncating a completion token later (`MAX_POOL` is that 24-bit
        // ceiling - the `user_data::SLOT_MASK`).
        #[cfg(feature = "uring-fs")]
        if self.fs_ops > 0
            && u64::from(self.fs_ops).saturating_add(u64::from(self.pool_size))
                > u64::from(MAX_POOL)
        {
            return Err(Error::Validation(format!(
                "fs_ops + pool_size must not exceed {MAX_POOL}"
            )));
        }
        // The floor spawns eagerly on the reactor thread at first use, so an
        // absurd value is a thread storm rather than a slow server. Bound both
        // ends here so it fails as a clean Validation at construction.
        #[cfg(feature = "uring-fs")]
        if self.fs_offload_floor == 0
            || self.fs_offload_floor > self.fs_offload_ceiling
            || self.fs_offload_ceiling > MAX_OFFLOAD_THREADS
        {
            return Err(Error::Validation(format!(
                "fs_offload_floor must be in \
                 1..=fs_offload_ceiling..={MAX_OFFLOAD_THREADS}"
            )));
        }
        // A chunk sizes one of two per-connection body buffers, and a read's
        // result rides a CQE's i32 - bound both ends so a pathological value
        // fails at construction (the worst case, `pool_size x 2 x
        // fs_body_chunk`, is documented on the field).
        #[cfg(feature = "uring-fs")]
        if self.fs_body_chunk < MIN_FS_BODY_CHUNK
            || self.fs_body_chunk > MAX_FS_BODY_CHUNK
        {
            return Err(Error::Validation(format!(
                "fs_body_chunk must be in \
                 {MIN_FS_BODY_CHUNK}..={MAX_FS_BODY_CHUNK}"
            )));
        }
        // A body chunk is queued whole and counts toward `queued_bytes`, which
        // is what a push is measured against before it is accepted
        // (`wake.rs`, `CloseReason::SendBacklog`). So a connection streaming a
        // body can exceed the backlog on its own chunks alone, and a push
        // arriving mid-body would evict a transfer that is keeping up.
        //
        // The count is `FILE_TAIL_BUFS`, which is every chunk buffer the
        // connection has: the pool lives on the connection and mints that
        // many for its whole life, so a body can queue all of them and no
        // more. At the defaults that is 512 KiB against 8 MiB.
        //
        // It bounds ONE tail's chunks and nothing else. A reply head, PDUs
        // released from a retired tail's diversion, and an earlier pipelined
        // body's chunks not yet flushed are all queued too, and they scale
        // with `max_in_flight_requests` rather than with anything here. A
        // consumer that pushes against a deeply pipelined connection still
        // has to size the backlog for its own traffic; what this refuses is
        // the configuration where a single body cannot coexist with a push.
        #[cfg(feature = "uring-fs")]
        if self.fs_ops > 0
            && usize::from(crate::net::core::conn::FILE_TAIL_BUFS)
                .saturating_mul(self.fs_body_chunk)
                > self.max_send_backlog
        {
            return Err(Error::Validation(format!(
                "max_send_backlog must cover a tail's queued chunks: \
                 {} x fs_body_chunk ({}) exceeds {}",
                crate::net::core::conn::FILE_TAIL_BUFS,
                self.fs_body_chunk,
                self.max_send_backlog
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
        if self.backlog <= 0 {
            // `listen(2)` takes a signed backlog but compares it unsigned
            // (`__sys_listen_socket`, net/socket.c: `if ((unsigned int)backlog >
            // somaxconn) backlog = somaxconn`), so a negative value is
            // reinterpreted as enormous and silently clamped to somaxconn; zero
            // leaves a listener that accepts almost nothing.
            return Err(Error::Validation("backlog must be positive".into()));
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
            ("max_receipt_time", self.max_receipt_time),
            ("tls_handshake_timeout", self.tls_handshake_timeout),
            ("recv_shortage_retry", self.recv_shortage_retry),
            ("keepalive", self.keepalive),
            ("tcp_user_timeout", self.tcp_user_timeout),
        ] {
            if matches!(d, Some(d) if d.is_zero()) {
                return Err(Error::Validation(format!(
                    "{name} must be non-zero"
                )));
            }
        }
        // A receipt bound at or under the inactivity bound makes the latter
        // dead: the message is closed before a period of silence can be
        // observed, so `request_timeout` never fires and the two knobs read
        // as one. Refused rather than tolerated, because the configuration
        // then means something other than what it says.
        if let (Some(receipt), Some(request)) =
            (self.max_receipt_time, self.request_timeout)
            && receipt <= request
        {
            return Err(Error::Validation(format!(
                "max_receipt_time ({receipt:?}) must exceed request_timeout \
                 ({request:?}), which it would otherwise pre-empt"
            )));
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
            max_receipt_time: self.max_receipt_time,
            send_timeout: self.send_timeout,
            tls_handshake_timeout: self.tls_handshake_timeout,
            recv_shortage_retry: self.recv_shortage_retry,
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

#[cfg(all(test, feature = "uring-fs"))]
mod tests {
    use super::*;

    fn addrs() -> Vec<Listen> {
        vec![Listen::from(ServerAddr::Unix("/tmp/x".into()))]
    }

    /// The offload bounds spawn real threads on the reactor thread at first
    /// use, so they are bounded at construction like every other sizing knob.
    #[test]
    fn validate_bounds_the_offload_pool() {
        let a = addrs();
        assert!(ServerConfig::default().validate(&a).is_ok());
        for (floor, ceiling) in [
            (0, 8),                       // a floor of zero
            (9, 8),                       // floor above ceiling
            (1, MAX_OFFLOAD_THREADS + 1), // ceiling past the cap
            (usize::MAX, usize::MAX),     // the thread storm
        ] {
            let cfg = ServerConfig {
                fs_offload_floor: floor,
                fs_offload_ceiling: ceiling,
                ..ServerConfig::default()
            };
            let e = cfg.validate(&a).unwrap_err().to_string();
            assert!(
                e.contains("fs_offload_floor"),
                "({floor}, {ceiling}) accepted or wrong error: {e}"
            );
        }
    }
}
