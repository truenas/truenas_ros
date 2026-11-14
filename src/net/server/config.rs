//! Server tuning: [`ServerConfig`], the per-address [`Listen`] opt-in, and the validation limits they are checked
//! against.

#[cfg(doc)]
use super::protocol::Response;
#[cfg(doc)]
use super::{PushHandle, Server};
use crate::error::Error;
use crate::net::core::protocol::ServerAddr;
#[cfg(doc)]
use crate::net::core::protocol::{Body, ClientAddr, CloseReason};
use crate::uring::force_async::ForceAsync;
use std::time::Duration;

/// The largest usable pool slot (the `user_data` codec reserves 24 bits).
const MAX_POOL: u32 = 0x00ff_ffff;

/// Ceiling on the fs offload pool's own thread count - the pool's own constant, shared with the standalone host, which
/// screens the same bound in `UringFs::check`.
#[cfg(feature = "uring-fs")]
use crate::uring_fs::offload_pool::MAX_OFFLOAD_THREADS;
/// Bounds for `fs_body_chunk`: below 4 KiB a multi-GB body is all per-op overhead; above 16 MiB two buffers per
/// streaming connection stop being "bounded" in any useful sense (and a read result must fit an i32).
#[cfg(feature = "uring-fs")]
const MIN_FS_BODY_CHUNK: usize = 4096;
#[cfg(feature = "uring-fs")]
const MAX_FS_BODY_CHUNK: usize = 16 * 1024 * 1024;
/// Bounds for `recv_buffer_bytes`: one chunked read at least, and at most what one arrival should pin.
const MIN_RECV_BUFFER: usize = 4096;
const MAX_RECV_BUFFER: usize = 16 * 1024 * 1024;
/// Upper bound on `max_in_flight_requests` (bounds per-connection read-ahead).
const MAX_IN_FLIGHT: usize = 4096;
/// Upper bound on `max_send_coalesce` (the kernel's `UIO_MAXIOV` - the most iovecs one `msghdr` may carry).
const MAX_SEND_COALESCE: usize = 1024;
/// Upper bound on listeners per server (the index rides the `user_data` slot field of the accept ops).
const MAX_LISTENERS: usize = 256;

/// Server tuning knobs.
#[derive(Clone, Copy, Debug)]
pub struct ServerConfig {
    /// Maximum concurrent connections, the size of the registered-file pool, per server. The kernel's reuseport hash is
    /// load-blind, so size each ring's pool for a skewed share unless the servers share a [`Spread`](super::Spread).
    /// Worst-case buffer memory is about `pool_size x max_request_bytes`, and an empty slot costs about 32 bytes.
    /// Default 512.
    pub pool_size: u32,
    /// Op-table slots for the embedded fs reactor ([`Request::fs`](super::Request::fs)), or `0` (the default) to
    /// disable it. This is the most fs operations a handler may have in flight at once, the axis of
    /// [`FsConfig::ops`](crate::uring_fs::FsConfig::ops), and a submit past it fails `EBUSY` however deep the ring is.
    ///
    /// It bounds operations, not open files, since files are plain fds closed as their last `Arc` drops. A linked chain
    /// counts each of its SQEs, so size it for the deepest chain a handler submits times the connections that can be
    /// mid-chain. A slot is 616 bytes of heap, so this is the cheap axis to raise. The server adds `pool_size` slots of
    /// its own for the reply path's body reads. Requires the `uring-fs` feature.
    #[cfg(feature = "uring-fs")]
    pub fs_ops: u32,
    /// Warm floor of offload worker threads for the embedded fs reactor's blocking work (`readdir`, byte copies), which
    /// has no io_uring opcode. Per ring, and resident once first used, so it is a standing cost times the servers a
    /// deployment runs. Default `uring_fs::core::OFFLOAD_FLOOR`.
    #[cfg(feature = "uring-fs")]
    pub fs_offload_floor: usize,
    /// Ceiling the offload pool grows to when every worker is blocked, so one stalled walk does not hold up the rest.
    /// Per ring. Workers spawn on demand and retire when idle, so size it to how many blocked operations one ring
    /// should absorb before they queue, not to request volume. Default `uring_fs::core::OFFLOAD_CEILING`.
    #[cfg(feature = "uring-fs")]
    pub fs_offload_ceiling: usize,
    /// Warm floor of the lookup lane, each ring's second offload pool, for jobs that wait on another machine
    /// (`FsConn::offload_lookup`). Per ring, and resident once the lane is first used. Default
    /// `uring_fs::core::LOOKUP_FLOOR`.
    #[cfg(feature = "uring-fs")]
    pub lookup_offload_floor: usize,
    /// Ceiling the lookup lane grows to when every one of its workers waits. Per ring. A job may hold a socket until a
    /// remote service answers or times out, so this bounds the lane's sockets as well as its threads, and jobs past it
    /// wait in the queue holding neither. Default `uring_fs::core::LOOKUP_CEILING`.
    #[cfg(feature = "uring-fs")]
    pub lookup_offload_ceiling: usize,
    /// Chunk size for file-sourced reply bodies (`Response::ReplyFile`), and the size of each buffer in the file-body
    /// ring ([`fs_body_pool`](ServerConfig::fs_body_pool)). A connection has at most two chunks out, so
    /// `pool_size x 2 x fs_body_chunk` is the ceiling when every connection is mid-body. The count is fixed, since on
    /// ZFS every ring read is punted to an io-wq worker and a deeper pipeline would only deepen that bounded queue.
    /// Default 256 KiB, validated to 4 KiB..=16 MiB.
    #[cfg(feature = "uring-fs")]
    pub fs_body_chunk: usize,
    /// Draw file-body chunk buffers from a registered provided-buffer ring (`true`, the default), or have each read
    /// supply its own. There is nothing to size. The ring has a 16-byte descriptor for every chunk that could be in
    /// flight, and buffers follow demand from [`buf_pool_initial_bytes`](ServerConfig::buf_pool_initial_bytes).
    #[cfg(feature = "uring-fs")]
    pub fs_body_pool: bool,
    /// Maximum bytes for one message, header and body, a memory guard that also bounds header scanning. A scanning
    /// framer's buffer can briefly reach this plus one chunk read before the over-cap check closes the connection.
    /// Default 1 MiB.
    pub max_request_bytes: usize,
    /// Draw receive buffers from a registered provided-buffer ring (`true`, the default), or have every connection own
    /// its receive buffer.
    ///
    /// The kernel picks a pooled buffer at completion, so a connection holds one only while a message arrives and
    /// buffer memory scales with arrivals rather than with [`pool_size`](ServerConfig::pool_size). At rest
    /// [`recv_bufs_lent`](super::ServerStats::recv_bufs_lent) settles to zero. A message that outgrows its buffer moves
    /// to owned storage, and a kernel without provided-buffer rings gets owned buffers rather than a bind failure.
    pub recv_pool: bool,
    /// Receive buffers a connection's handler may hold past the message they arrived with (leased writes, leased jobs,
    /// held windows), on top of the one an arriving message takes. The pool grows to at most
    /// `pool_size x (recv_lease_depth + 1)` buffers, clamped to 32768 and to
    /// [`buf_pool_max_bytes`](ServerConfig::buf_pool_max_bytes), and past that reads park or fall back to owned buffers
    /// ([`recv_shortage_retry`](ServerConfig::recv_shortage_retry)). A handler that holds windows until more of its
    /// stream arrives must stay within its depth, or its parked read waits on a buffer it holds.
    ///
    /// The cost is descriptor slots, 16 bytes of locked memory each, charged to an unprivileged process's
    /// `RLIMIT_MEMLOCK` (`__io_account_mem`), not buffers. Default 4.
    pub recv_lease_depth: u32,
    /// Size of a pooled receive buffer, capped at [`max_request_bytes`](ServerConfig::max_request_bytes). A message
    /// that outgrows its buffer costs one copy to owned storage, so size it to hold a codec's streamed window with its
    /// framing. It must hold any body under [`body_placement_threshold`](ServerConfig::body_placement_threshold), which
    /// `validate` checks, since such a body, or a header read in one exact step, that does not fit moves its connection
    /// to owned buffers for good. Below 16 KiB, kTLS decrypts full-size records aside and copies them
    /// (`to_decrypt <= len` in `tls_sw_recvmsg`). Default 256 KiB, 4 KiB to 16 MiB.
    pub recv_buffer_bytes: usize,
    /// Buffer storage each ring (receive, file body) starts with, per ring and per reactor, allocated when the server
    /// is built. Too little and a burst pays a failed read per growth step; too much and small requests rotate through
    /// cold buffers. Default 16 MiB.
    pub buf_pool_initial_bytes: usize,
    /// The most storage one growth step adds to a ring; a step otherwise doubles it. Default 16 MiB.
    pub buf_pool_max_step_bytes: usize,
    /// The most storage each ring may hold, per reactor. At the cap a receive parks or falls back to an owned buffer
    /// ([`recv_shortage_retry`](ServerConfig::recv_shortage_retry)) and a file-body read uses an owned buffer, so a
    /// handler holding windows must fit its share. `None` (the default): no cap below the demand.
    pub buf_pool_max_bytes: Option<usize>,
    /// The bytes of body pool storage a ring may hold, as
    /// [`BodyRecycler::held`](crate::net::server::BodyRecycler::held) counts them with the consumer's own figure,
    /// before it holds back the next message that would take storage of the pool, at the read of its placed body or at
    /// one that would promote what it has buffered. A message is let in once, and no later read of it waits, since what
    /// it would wait on is its own bytes. A held-back read keeps what its connection has buffered and waits in one
    /// queue with the consumer's turns ([`BodyRecycler::queue_turn`](crate::net::server::BodyRecycler::queue_turn)),
    /// going on in the order they came once the count is under the cap. So what is held back passes the cap by one at
    /// most, a body larger than the cap still goes on, and the ring passes it further only by what the messages under
    /// way take as the rest of them arrives, one message at most for each connection. Its
    /// [`max_receipt_time`](ServerConfig::max_receipt_time) does not run while it waits. `None`, the default, sets no
    /// cap, and 0 is refused, since it would hold every placed body back for good.
    pub held_cap: Option<usize>,
    /// How a read answers a buffer pool that is genuinely exhausted, at its registered bound with every buffer lent.
    /// `Some(backoff)` (the default, 10 ms) parks the read and retries it a `backoff` later on a kernel `TIMEOUT`, so
    /// TCP pushes back on the peer and pool memory stays at its bound. `None` reads into a buffer the connection owns,
    /// which keeps every connection moving at the cost of allocation that scales with the spike.
    ///
    /// Ordinary shortage under the bound grows the pool and re-arms at once either way, so only claims held past their
    /// message, such as a pipelined ingest handler's floating writes, can reach this.
    pub recv_shortage_retry: Option<Duration>,
    /// `listen(2)` backlog.
    pub backlog: i32,
    /// For `AF_UNIX`, unlink a stale socket path before binding.
    pub unlink_unix: bool,
    /// If set, close a connection that waits for its next request with no bytes received for longer than this. A
    /// completed send restarts the interval, so the connection is reaped only after a full period of neither receiving
    /// nor sending, and never while a deferred reply is outstanding. It does not interrupt a message in progress (see
    /// `request_timeout`). A kernel `LINK_TIMEOUT` on the idle recv, so it costs no wakeups. `None` (the default) keeps
    /// idle connections open.
    pub idle_timeout: Option<Duration>,
    /// If set, close a connection whose request in progress makes no progress for this long, such as a peer that sends
    /// a length prefix and stalls, which `idle_timeout` does not cover. Any progress buys one more period, so this asks
    /// whether the peer is still there and is not a rate floor (see `max_receipt_time`). It bounds receipt only, never
    /// handling, so a request offloaded with [`Response::Defer`] may run as long as it likes. A kernel `LINK_TIMEOUT`
    /// on each recv in progress, so it costs no wakeups until a stall. `None` (the default) never times a request out.
    ///
    /// A spliced body ([`Framing::SpliceBody`]) is clocked the same way. Over kTLS this is the splice's only bound, and
    /// a kTLS splice is refused without it. There the kernel cannot tell a stalled peer from a full destination pipe,
    /// so a consumer draining slower than one record per period is evicted too.
    ///
    /// [`Framing::SpliceBody`]: super::Framing::SpliceBody
    pub request_timeout: Option<Duration>,
    /// If set, close a connection that has not finished receiving the message it started within this long. The clock
    /// runs from a message's first byte to its delivery and progress never restarts it, so this is the rate floor
    /// `request_timeout` is not. It bounds one message, so each window of a streamed body has its own budget (for a
    /// spliced body, each [`receipt_window_bytes`](ServerConfig::receipt_window_bytes)), and an upload of any size is
    /// admitted at one window per period. Pick it from the slowest client worth serving, not from the largest upload.
    ///
    /// Handling is not clocked, so a request offloaded with [`Response::Defer`] may run as long as it likes. A
    /// standalone kernel `TIMEOUT`, one per connection. `None` (the default) never bounds receipt. Without it,
    /// `pool_size` peers each sending one byte per `request_timeout` hold every slot, since a slot is taken at accept,
    /// before any authentication. It must exceed `request_timeout`.
    ///
    /// [`Response::Defer`]: super::Response::Defer
    pub max_receipt_time: Option<Duration>,
    /// Bytes of a spliced body that earn another [`max_receipt_time`](ServerConfig::max_receipt_time) budget. A spliced
    /// body is one message however large, so without renewal the budget would cap its size by wall clock; a peer slower
    /// than one window per budget is still closed. Set it to the codec's window (`HttpConfig::receipt_window_bytes`).
    /// Default 128 KiB.
    pub receipt_window_bytes: usize,
    /// Maximum requests in flight per connection before read-ahead pauses. `1` (the default) answers each request
    /// before reading the next. `N > 1` pipelines, reading and processing up to `N-1` further requests while one is
    /// deferred, so replies can complete out of order and the consumer's protocol must carry request ids. The server
    /// sends replies in production order and never reorders them.
    pub max_in_flight_requests: usize,
    /// If set, close a connection whose send makes no progress for this long, a kernel `LINK_TIMEOUT` on each send.
    /// Without it a peer that stops reading holds its slot until shutdown, since TCP zero-window probing never gives
    /// up. Progress resets the clock. `None` (the default) never times sends out. See also `tcp_user_timeout`.
    pub send_timeout: Option<Duration>,
    /// If set, shed a kTLS connection whose handshake has not completed within this long. The slot is parked across the
    /// handshake with no recv or send, so neither recv clock reaches it, and a late `ready()` or `reject()` finds a new
    /// generation and is dropped. Set it whenever the [`Server::set_tls_handshake`] handler has no deadline of its own.
    /// `None` (the default) never times a handshake out, and non-TLS listeners ignore it.
    pub tls_handshake_timeout: Option<Duration>,
    /// Set `TCP_NODELAY` on TCP listeners - inherited by every accepted connection on Linux - so each reply PDU is sent
    /// immediately rather than Nagle-delayed. Defaults to `true`: this server writes whole framed messages, for which
    /// Nagle only adds latency (notably when several pipelined replies are sent back-to-back). Ignored for `AF_UNIX`.
    pub nodelay: bool,
    /// Set `SO_REUSEPORT` on TCP listeners, so several servers, one ring each, bind one address and the kernel spreads
    /// connections across them. Each keeps its own pool, a full pool parks only its own listener, and the kernel's hash
    /// is load-blind, so provision for uneven placement, or join the servers in one [`Spread`](super::Spread), which
    /// sends each new connection to the ring with the fewest. Defaults to `false`. Ignored for `AF_UNIX`.
    pub reuse_port: bool,
    /// Enable `SO_KEEPALIVE` with `TCP_KEEPIDLE` set to this duration (rounded up to a whole second) on TCP listeners,
    /// inherited by accepted connections. Detects dead peers on otherwise-idle connections at the TCP level. `None`
    /// (the default) leaves keepalive off. Ignored for `AF_UNIX`.
    pub keepalive: Option<Duration>,
    /// Set `TCP_USER_TIMEOUT` (maximum time transmitted data may remain unacknowledged before TCP aborts the
    /// connection) on TCP listeners, inherited by accepted connections. A transport-level backstop to `send_timeout`.
    /// `None` (the default) uses the system default. Ignored for `AF_UNIX`.
    pub tcp_user_timeout: Option<Duration>,
    /// For `AF_UNIX` listeners, fetch each peer's credentials (`SO_PEERCRED`, through an io_uring socket command)
    /// before the accept handler runs, delivered as [`ClientAddr::Unix`]`{ cred: Some(..) }`. Needs socket commands on
    /// `AF_UNIX` (Linux 6.18.16), which [`Server::with_config`] probes, failing with a validation error where they are
    /// missing. A failed fetch sheds the connection rather than deliver it without credentials. Defaults to `false`,
    /// since it costs a ring round trip per accept. Ignored for TCP.
    pub unix_peercred: bool,
    /// Maximum bytes queued to send on one connection before a **push** ([`PushHandle::push`]) closes it as a slow
    /// consumer ([`CloseReason::SendBacklog`]). Request replies are not evicted by this bound - they are already
    /// limited by `max_in_flight_requests`. Default 8 MiB.
    pub max_send_backlog: usize,
    /// Maximum queued PDUs, replies and pushes, gathered into one `SENDMSG`. Only PDUs already queued when a send is
    /// armed are gathered, so a lone reply is never delayed, and `send_timeout` bounds the whole op. Default 8, the
    /// kernel's inline iovec fast path (`UIO_FASTIOV`). `1` disables coalescing, and the cap is 1024 (`UIO_MAXIOV`).
    pub max_send_coalesce: usize,
    /// Read a message body at least this large into storage of its own, claimed from the ring's body pool, instead of
    /// the connection's buffer, so [`Body::take`] moves it with no copy. It applies when the body still has bytes to
    /// read at the frame verdict. A body a scanning framer already read whole is delivered in place, where `take`
    /// copies, except a body-only message at or over the threshold whose extent is exactly the buffered bytes, which
    /// hands the buffer itself over. `None` disables placement. Default 64 KiB.
    pub body_placement_threshold: Option<usize>,
    /// Which operation classes this server submits with `IOSQE_ASYNC`:
    /// the socket sends and receives its connections run, and the file reads and writes it submits on their behalf (a
    /// body pump read, a leased upload window, and a consumer's own reads and writes through
    /// [`fs_ops`](ServerConfig::fs_ops)).
    ///
    /// Empty by default. [`ForceAsync`] says what the flag costs each class, since the kernel decides by whether the
    /// file polls, and why the classes are separate knobs.
    pub force_async: ForceAsync,
    /// The most io-wq workers this server's ring runs at once for bounded work, or `None`, the default, which keeps the
    /// kernel's own bound, the lesser of the ring's submission entries and four for each CPU (`io_init_wq_offload`,
    /// `io_uring/tctx.c`).
    ///
    /// It bounds every operation on a regular file the ring sends to a worker, not reads alone, since io-wq counts work
    /// as unbound only when its file is not regular (`io_prep_async_work`, `io_uring/io_uring.c`). A read that waits on
    /// a disk holds its worker, so this is also how many such reads wait at once.
    ///
    /// io-wq belongs to the thread, not the ring. The server registers the bound when it is built, before its ring's
    /// first submission, and a thread's io-wq takes the bounds of the first ring it submits to
    /// (`__io_uring_add_tctx_node`, `io_uring/tctx.c`), or those registered while it runs. So give every server one
    /// thread drives the same bound. 0 and a count past `i32::MAX`, which the kernel refuses, are refused at
    /// validation.
    pub iowq_bounded_workers: Option<u32>,
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
            lookup_offload_floor: crate::uring_fs::core::LOOKUP_FLOOR,
            #[cfg(feature = "uring-fs")]
            lookup_offload_ceiling: crate::uring_fs::core::LOOKUP_CEILING,
            #[cfg(feature = "uring-fs")]
            fs_body_chunk: 256 * 1024,
            #[cfg(feature = "uring-fs")]
            fs_body_pool: true,
            max_request_bytes: 1024 * 1024,
            recv_pool: true,
            recv_lease_depth: 4,
            recv_buffer_bytes: 256 * 1024,
            buf_pool_initial_bytes: 16 * 1024 * 1024,
            buf_pool_max_step_bytes: 16 * 1024 * 1024,
            buf_pool_max_bytes: None,
            held_cap: None,
            recv_shortage_retry: Some(Duration::from_millis(10)),
            backlog: 128,
            unlink_unix: true,
            idle_timeout: None,
            request_timeout: None,
            max_receipt_time: None,
            receipt_window_bytes: 128 * 1024,
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
            force_async: ForceAsync::empty(),
            iowq_bounded_workers: None,
        }
    }
}

impl ServerConfig {
    /// Construction-time validation of the knobs and the listener list -- [`Server::with_config`] fails with a
    /// validation error on the first violated bound, before any socket or ring is created.
    pub(super) fn validate(&self, addrs: &[Listen]) -> crate::Result<()> {
        if addrs.is_empty() || addrs.len() > MAX_LISTENERS {
            return Err(Error::Validation(format!(
                "listener count must be in 1..={MAX_LISTENERS}"
            )));
        }
        if let Some(bad) = addrs
            .iter()
            .find(|l| l.tls && !matches!(l.addr, ServerAddr::Tcp(_) | ServerAddr::Tcp6(_)))
        {
            return Err(Error::Validation(format!(
                "kTLS listeners must be TCP; got {:?}",
                bad.addr
            )));
        }
        if self.pool_size == 0 || self.pool_size > MAX_POOL {
            return Err(Error::Validation(format!("pool_size must be in 1..={MAX_POOL}")));
        }
        // 0 would leave the kernel's bound as it is rather than bound anything, and the kernel refuses a count past
        // `INT_MAX` (`io_register_iowq_max_workers`, `io_uring/register.c`).
        if let Some(workers) = self.iowq_bounded_workers
            && (workers == 0 || i32::try_from(workers).is_err())
        {
            return Err(Error::Validation(format!(
                "iowq_bounded_workers must be in 1..={}",
                i32::MAX
            )));
        }
        // An op-slot index is packed into the 24-bit `user_data` slot field (`user_data::SLOT_MASK`, which `MAX_POOL`
        // mirrors), so the whole op table, `fs_ops` plus a slot per connection for body reads, must fit it. Refused
        // here rather than truncate a completion token later.
        #[cfg(feature = "uring-fs")]
        if self.fs_ops > 0 && u64::from(self.fs_ops).saturating_add(u64::from(self.pool_size)) > u64::from(MAX_POOL) {
            return Err(Error::Validation(format!(
                "fs_ops + pool_size must not exceed {MAX_POOL}"
            )));
        }
        // The floor spawns eagerly on the reactor thread at first use, so an absurd value is a thread storm rather than
        // a slow server. Bound both ends here so it fails as a clean Validation at construction.
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
        #[cfg(feature = "uring-fs")]
        if self.lookup_offload_floor == 0
            || self.lookup_offload_floor > self.lookup_offload_ceiling
            || self.lookup_offload_ceiling > MAX_OFFLOAD_THREADS
        {
            return Err(Error::Validation(format!(
                "lookup_offload_floor must be in \
                 1..=lookup_offload_ceiling..={MAX_OFFLOAD_THREADS}"
            )));
        }
        // A chunk sizes one of two per-connection body buffers, and a read's result rides a CQE's i32 - bound both ends
        // so a pathological value fails at construction (the worst case, `pool_size x 2 x fs_body_chunk`, is documented
        // on the field).
        #[cfg(feature = "uring-fs")]
        if self.fs_body_chunk < MIN_FS_BODY_CHUNK || self.fs_body_chunk > MAX_FS_BODY_CHUNK {
            return Err(Error::Validation(format!(
                "fs_body_chunk must be in \
                 {MIN_FS_BODY_CHUNK}..={MAX_FS_BODY_CHUNK}"
            )));
        }
        // A body chunk counts toward `queued_bytes`, which a push is measured against (`CloseReason::SendBacklog`), so
        // a backlog smaller than one body's chunks would evict a transfer that keeps up the moment a push arrives. A
        // connection has at most `FILE_TAIL_BUFS` chunks out, so that is all one body can queue.
        //
        // This bounds one body's chunks and nothing else. Reply heads, PDUs released from a retired tail's diversion
        // and an earlier pipelined body's unflushed chunks scale with `max_in_flight_requests`, so a consumer that
        // pushes on a deeply pipelined connection sizes the backlog for that itself.
        #[cfg(feature = "uring-fs")]
        if self.fs_ops > 0
            && usize::from(crate::net::core::conn::FILE_TAIL_BUFS).saturating_mul(self.fs_body_chunk)
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
        if self.max_request_bytes == 0 || self.max_request_bytes > i32::MAX as usize {
            return Err(Error::Validation(format!(
                "max_request_bytes must be in 1..={}",
                i32::MAX
            )));
        }
        if self.recv_buffer_bytes < MIN_RECV_BUFFER || self.recv_buffer_bytes > MAX_RECV_BUFFER {
            return Err(Error::Validation(format!(
                "recv_buffer_bytes must be in \
                 {MIN_RECV_BUFFER}..={MAX_RECV_BUFFER}"
            )));
        }
        // See `recv_buffer_bytes`: an unplaced body must fit a pool buffer.
        if self.recv_pool
            && let Some(threshold) = self.body_placement_threshold
            && self.recv_buffer_bytes.min(self.max_request_bytes) < threshold.min(self.max_request_bytes)
        {
            return Err(Error::Validation(format!(
                "recv_buffer_bytes ({}) must hold a body below \
                 body_placement_threshold ({threshold})",
                self.recv_buffer_bytes
            )));
        }
        if self.buf_pool_max_step_bytes == 0 {
            return Err(Error::Validation("buf_pool_max_step_bytes must be non-zero".into()));
        }
        if self.buf_pool_max_bytes == Some(0) {
            return Err(Error::Validation("buf_pool_max_bytes must be non-zero".into()));
        }
        if self.held_cap == Some(0) {
            return Err(Error::Validation("held_cap must be non-zero".into()));
        }
        if self.receipt_window_bytes == 0 {
            return Err(Error::Validation("receipt_window_bytes must be non-zero".into()));
        }
        if matches!(self.idle_timeout, Some(d) if d.is_zero()) {
            return Err(Error::Validation("idle_timeout must be non-zero".into()));
        }
        if self.backlog <= 0 {
            // `listen(2)` takes a signed backlog but compares it unsigned (`__sys_listen_socket`, net/socket.c: `if
            // ((unsigned int)backlog > somaxconn) backlog = somaxconn`), so a negative value is reinterpreted as
            // enormous and silently clamped to somaxconn; zero leaves a listener that accepts almost nothing.
            return Err(Error::Validation("backlog must be positive".into()));
        }
        if self.max_send_backlog == 0 {
            return Err(Error::Validation("max_send_backlog must be non-zero".into()));
        }
        if self.max_send_coalesce == 0 || self.max_send_coalesce > MAX_SEND_COALESCE {
            return Err(Error::Validation(format!(
                "max_send_coalesce must be in 1..={MAX_SEND_COALESCE}"
            )));
        }
        if self.max_in_flight_requests == 0 || self.max_in_flight_requests > MAX_IN_FLIGHT {
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
                return Err(Error::Validation(format!("{name} must be non-zero")));
            }
        }
        // Two clocks, because neither does the other's job. `request_timeout` is re-armed by every recv, so it asks
        // whether the peer is still there and is no rate floor, and alone it leaves `pool_size` unauthenticated peers
        // holding every slot at a byte a period. `max_receipt_time` is that floor. At or under `request_timeout` it
        // closes a message before a silent period can be seen, so the inactivity clock never fires and the two knobs
        // read as one. Refused, since the configuration would mean something other than what it says.
        if let (Some(receipt), Some(request)) = (self.max_receipt_time, self.request_timeout)
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
            receipt_window_bytes: self.receipt_window_bytes,
            send_timeout: self.send_timeout,
            tls_handshake_timeout: self.tls_handshake_timeout,
            recv_shortage_retry: self.recv_shortage_retry,
            force_async: self.force_async,
        }
    }
}

/// One listen address, optionally kernel-TLS. `ServerAddr` converts with TLS off, so a plain `bind([addr])` is
/// unchanged; [`Listen::tls`] opts a single address in.
#[derive(Clone, Debug)]
pub struct Listen {
    pub(super) addr: ServerAddr,
    pub(super) tls: bool,
}

impl Listen {
    /// This address, served over kernel TLS (requires a [`Server::set_tls_handshake`] handler and a TCP address).
    pub fn tls(addr: ServerAddr) -> Listen {
        Listen { addr, tls: true }
    }
}

impl From<ServerAddr> for Listen {
    fn from(addr: ServerAddr) -> Listen {
        Listen { addr, tls: false }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addrs() -> Vec<Listen> {
        vec![Listen::from(ServerAddr::Unix("/tmp/x".into()))]
    }

    /// A bound of io-wq workers is 1 to `i32::MAX`, since 0 would bound nothing and the kernel refuses more, and none
    /// keeps the kernel's own.
    #[test]
    fn validate_bounds_the_io_wq_workers() {
        let addrs = [Listen::from(ServerAddr::Tcp("127.0.0.1:0".parse().unwrap()))];
        for (workers, ok) in [
            (None, true),
            (Some(1), true),
            (Some(i32::MAX as u32), true),
            (Some(0), false),
            (Some(i32::MAX as u32 + 1), false),
        ] {
            let cfg = ServerConfig {
                iowq_bounded_workers: workers,
                ..ServerConfig::default()
            };
            assert_eq!(cfg.validate(&addrs).is_ok(), ok, "{workers:?}");
        }
    }

    /// The offload bounds spawn real threads on the reactor thread at first use, so they are bounded at construction
    /// like every other sizing knob, for the file pool and the lookup lane alike.
    #[cfg(feature = "uring-fs")]
    #[test]
    fn validate_bounds_both_offload_pools() {
        let a = addrs();
        assert!(ServerConfig::default().validate(&a).is_ok());
        for (floor, ceiling) in [
            (0, 8),                       // a floor of zero
            (9, 8),                       // floor above ceiling
            (1, MAX_OFFLOAD_THREADS + 1), // ceiling past the cap
            (usize::MAX, usize::MAX),     // the thread storm
        ] {
            let file = ServerConfig {
                fs_offload_floor: floor,
                fs_offload_ceiling: ceiling,
                ..ServerConfig::default()
            };
            let lookup = ServerConfig {
                lookup_offload_floor: floor,
                lookup_offload_ceiling: ceiling,
                ..ServerConfig::default()
            };
            for (cfg, knob) in [(file, "fs_offload_floor"), (lookup, "lookup_offload_floor")] {
                let e = cfg.validate(&a).unwrap_err().to_string();
                assert!(
                    e.contains(knob),
                    "{knob} ({floor}, {ceiling}) accepted or wrong error: {e}"
                );
            }
        }
    }

    /// `recv_buffer_bytes` is bounded, and a zero receipt window - which would renew a spliced body's budget on no
    /// progress - is refused, as is a zero pool step or cap.
    #[test]
    fn validate_bounds_the_receive_buffers() {
        let a = addrs();
        for bytes in [0, MIN_RECV_BUFFER - 1, MAX_RECV_BUFFER + 1] {
            let cfg = ServerConfig {
                recv_buffer_bytes: bytes,
                ..ServerConfig::default()
            };
            let e = cfg.validate(&a).unwrap_err().to_string();
            assert!(e.contains("recv_buffer_bytes"), "{bytes} accepted or wrong error: {e}");
        }
        for bytes in [MIN_RECV_BUFFER, MAX_RECV_BUFFER] {
            let cfg = ServerConfig {
                recv_buffer_bytes: bytes,
                body_placement_threshold: Some(MIN_RECV_BUFFER),
                ..ServerConfig::default()
            };
            assert!(cfg.validate(&a).is_ok(), "{bytes} refused");
        }
        let cfg = ServerConfig {
            receipt_window_bytes: 0,
            ..ServerConfig::default()
        };
        let e = cfg.validate(&a).unwrap_err().to_string();
        assert!(
            e.contains("receipt_window_bytes"),
            "a zero window accepted or wrong error: {e}"
        );
        for (cfg, field) in [
            (
                ServerConfig {
                    buf_pool_max_step_bytes: 0,
                    ..ServerConfig::default()
                },
                "buf_pool_max_step_bytes",
            ),
            (
                ServerConfig {
                    buf_pool_max_bytes: Some(0),
                    ..ServerConfig::default()
                },
                "buf_pool_max_bytes",
            ),
        ] {
            let e = cfg.validate(&a).unwrap_err().to_string();
            assert!(e.contains(field), "zero {field} accepted: {e}");
        }
    }

    /// The buffer must hold every body placement leaves to it, unless there is no pool, no placement, or a request cap
    /// below the buffer.
    #[test]
    fn validate_keeps_unplaced_bodies_inside_a_pool_buffer() {
        const BUF: usize = 32 * 1024;
        let a = addrs();
        let below = ServerConfig {
            recv_buffer_bytes: BUF,
            body_placement_threshold: Some(2 * BUF),
            ..ServerConfig::default()
        };
        let e = below.validate(&a).unwrap_err().to_string();
        assert!(
            e.contains("body_placement_threshold"),
            "a buffer below the threshold accepted or wrong error: {e}"
        );
        for fine in [
            ServerConfig {
                body_placement_threshold: Some(BUF),
                ..below
            },
            ServerConfig {
                body_placement_threshold: None,
                ..below
            },
            ServerConfig {
                recv_pool: false,
                ..below
            },
            ServerConfig {
                max_request_bytes: BUF,
                ..below
            },
        ] {
            assert!(fine.validate(&a).is_ok(), "refused: {fine:?}");
        }
    }
}
