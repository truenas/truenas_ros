//! An io_uring stream server whose API mirrors Python's `socketserver`.
//!
//! [`Server`] runs a single io_uring ring on one thread, driven by a completion
//! (CQE) loop. The listening socket is armed with a **multishot accept** that
//! auto-allocates each connection into a registered-file "pool" (direct
//! descriptors); every accepted connection is then driven through
//! `recv-header → frame → recv-body → handler → send`, looping back to
//! recv-header for the next message (keep-alive), each step a new SQE on the
//! same ring.
//!
//! # Framing
//!
//! A `SOCK_STREAM` byte stream has no message boundaries, and a receive may
//! return fewer bytes than the application message (verified against the
//! kernel: without `MSG_WAITALL`, `io_recv`/`io_recvmsg` call `sock_recvmsg`
//! once and return whatever was buffered). So message framing is the caller's, declared
//! up front via a [`Protocol`] — unlike `socketserver`, which can hand the
//! handler a *blocking* `rfile` because it is thread-per-connection.
//!
//! A [`Protocol`] supplies three closures:
//! * `accept: FnMut(Incoming<'_>) -> Option<U>` — runs once per connection;
//!   the [`Incoming`] carries the peer's identity and the (resolved) listener
//!   address it arrived on (per-listener policy). `None` rejects it (closed
//!   before any read), `Some(state)` stores per-connection state `U` (a cache
//!   handle, counters, a session);
//! * `header: FnMut(&[u8], &mut U) -> Framing` — the framer, consulted
//!   *iteratively* on the bytes accumulated so far, returning a [`Framing`]
//!   verdict (read more, the completed header/body split, a body **spliced**
//!   straight to a consumer fd — [`Framing::SpliceBody`], see *Large bodies*
//!   below — or invalid; see [`Framing`]). This handles fixed length prefixes
//!   *and* variable/delimiter headers (e.g. LSP's
//!   `Content-Length: …\r\n\r\n`);
//! * `body: FnMut(Request<'_, U>) -> Response` — the [`Request`] bundles the
//!   frame `header`, the [`Body`] (deref for in-place reads; [`Body::take`]
//!   moves the bytes out for a worker — zero-copy when placed, see *Large
//!   bodies* below), the `peer`, the connection's `state`, and the
//!   [`Responder`]. Return [`Response::Reply`] with the complete PDU (it
//!   frames its own reply; an empty PDU sends nothing — the
//!   one-way/notification case), [`Response::ReplyClose`] to send a **final**
//!   PDU and close once it flushes (the server speaks last: a WebSocket
//!   Close ack, an error before hanging up), [`Response::Close`],
//!   [`Response::Defer`] to
//!   offload the work to another thread (see *Offloading work* below), or
//!   [`Response::Detach`] to hand the connection's socket fd to your own
//!   worker for a blocking bulk transfer (ZFS send/receive style) and take
//!   it back afterwards ([`Server::set_detach_handler`]). Both context
//!   structs are `#[non_exhaustive]`, so future fields arrive without
//!   breaking handlers.
//!
//! `MSG_WAITALL` makes io_uring accumulate short reads *in the kernel*
//! (re-arming its own poll) so a `Need`/body recv completes only once the full
//! slice has arrived — no application-level read loop. Shared state (vs.
//! per-connection `U`) comes via the closures' own captures. The server never
//! parses the header, staying byte-agnostic.
//!
//! [`length_prefixed`] builds a stateless `Protocol` for the common fixed-width
//! length-prefix case (caller writes only the body handler);
//! [`length_prefix_header`] is a reusable binary framer for custom `Protocol`s
//! (e.g. with per-connection state). A variable/delimiter header (LSP-style
//! `Content-Length`) is a few lines of `header` closure in the caller — the
//! server itself ships no protocol-specific (text) parsers, staying purely
//! byte-oriented.
//!
//! # Concurrency
//!
//! One ring, one thread, no synchronization on submit/complete — the frame and
//! handler run inline on the loop thread. [`Server`] is `!Send`/`!Sync`, so the
//! ring cannot be shared across threads. To use multiple cores, run one
//! independent `Server` (and ring) per thread — never share a ring (per Jens
//! Axboe's guidance).
//!
//! # Offloading work
//!
//! Handlers run inline on the ring thread, so slow work would stall every other
//! connection. To offload, the `body` handler takes the owned inputs a worker
//! needs (`req.body.take()`, never a borrow of connection state), detaches a
//! [`Deferred`] — `let (deferred, permit) = req.responder.defer()` — hands the
//! `Deferred` to a pool (rayon, tokio, raw threads — the library ships none),
//! and returns [`Response::Defer`]`(permit)`; the ring thread returns
//! immediately to polling. The [`DeferPermit`] is proof a `Deferred` exists
//! (it is stamped with the request's routing token and verified at delivery),
//! so a parked request always has an eventual outcome: the worker calls
//! [`Deferred::reply`] (or [`Deferred::reply_close`] for a final PDU that
//! closes once flushed, [`Deferred::close`]; dropping it unresolved also
//! closes), which queues the outcome and wakes the loop through the same
//! eventfd used for shutdown — workers never touch the ring, so the single-ring
//! rule holds. The reply is sent on the originating connection, or dropped
//! safely if that connection closed — or the request was already answered —
//! while the worker ran (the [`Deferred`] carries a slot+generation+request
//! token, not a pointer into the connection). Per-connection state never
//! crosses a thread boundary, so there is nothing to lock; see
//! `examples/tcp_offload.rs`.
//!
//! # Large bodies (placement)
//!
//! A message body at or over `ServerConfig::body_placement_threshold`
//! (default 64 KiB; `None` disables) is read **into its own allocation**
//! rather than the connection's accumulate buffer — the transport-level
//! equivalent of Samba's probe-then-carve read path: one recv for the frame
//! header, one recv landing the payload in its final resting place. The
//! handler receives it through the same [`Body`] parameter; [`Body::take`]
//! then *moves* the buffer (no copy) — which is what makes deferring MB-scale
//! payloads to workers copy-free. Below the threshold, bodies ride the
//! accumulate buffer as always and `take()` falls back to a copy, so one
//! handler pattern is correct at every size. Placement also bounds the
//! accumulate buffer's idle high-water mark at roughly the threshold.
//!
//! Bodies that should never enter userspace at all — multi-GB upload
//! streams — can be **spliced**: the framer returns [`Framing::SpliceBody`]
//! and the body moves socket → consumer fd in-kernel (`IORING_OP_SPLICE`,
//! zero-copy), with only the header ever buffered. The destination must be a
//! **blocking** pipe write end ([`CloseReason::SpliceBadFd`] otherwise): a
//! full pipe blocking the splice on an io-wq worker — never the ring — is
//! the transfer's backpressure. Works over plain TCP/unix and software kTLS
//! (bodies splice decrypted); see [`Framing::SpliceBody`] for the framer
//! contract and timeout interaction.
//!
//! # Server push
//!
//! [`Responder::push_handle`] returns a `Clone + Send + Sync` [`PushHandle`]
//! for **unsolicited** server→client PDUs (notifications, pub/sub events,
//! SMB-style breaks) on that connection, from any thread, for the connection's
//! lifetime. Pushes queue FIFO behind pending replies (never interleaving
//! mid-PDU), are dropped if the connection has closed, are **held** while it
//! is detached to a worker (flushed on [`Detached::resume`] — the worker owns
//! the raw stream, so nothing may write mid-detach), and evict a peer that
//! stops reading once `ServerConfig::max_send_backlog` is exceeded
//! ([`CloseReason::SendBacklog`]; during a detach the eviction lands at
//! resume). [`PushHandle::close`] ends the connection from any thread,
//! outside any request cycle (session revocation, an administrative kick):
//! everything already queued — pushes included — flushes first, then the
//! connection closes ([`CloseReason::PushClosed`]; during a detach the close,
//! like the eviction, lands at resume). Pair with the close hook to prune
//! stored handles.
//!
//! # Multiple listeners
//!
//! [`Server::bind`] takes one **or more** addresses — any mix of TCP and
//! unix — all served by the one ring/thread (the single-threaded daemon
//! shape: a trusted local unix socket plus a network TCP port). Connections
//! from every listener share the pool, limits, and handlers;
//! [`Incoming::listener_addr`] says which listener a connection arrived on.
//! [`Server::local_addrs`] returns the resolved bound addresses in order.
//!
//! # Peer identity
//!
//! Peer identity is fetched **per connection**, after the accept, through a
//! socket command on the connection itself: `SO_PEERNAME` for TCP peers
//! (delivered as [`ClientAddr::Inet`]) and `SO_PEERCRED` for unix peers when
//! `ServerConfig::unix_peercred` is set. A multishot accept's own
//! peer-address argument is deliberately unused: the kernel writes every
//! accepted connection's address into the *same* buffer, so a burst of
//! accepts would misattribute peers — unacceptable for address-based accept
//! policy. The per-connection fetch is race-free by construction; if it
//! fails, the connection is shed, never delivered with a wrong identity.
//!
//! # Local authentication (`AF_UNIX`)
//!
//! With `ServerConfig::unix_peercred`, the server fetches each unix peer's
//! `SO_PEERCRED` (pid/uid/gid) via an io_uring socket command *before* the
//! accept handler runs, delivering it as
//! [`ClientAddr::Unix`]`{ cred: Some(`[`PeerCred`]`) }` — accept can then
//! authenticate by uid/gid. The command interface exists since Linux 6.7, but
//! kernels before the cmd_net ioctl-guard fix (6.18.16 in the 6.18 series)
//! reject every socket command on `AF_UNIX`, so [`Server::with_config`]
//! probes once at construction and fails with a validation error on
//! unsupported kernels rather than shedding every connection at accept. If a
//! per-connection fetch fails the connection is shed, never delivered
//! credential-less.
//!
//! # Transport security (kTLS)
//!
//! A listener marked [`Listen::tls`] serves its connections over **kernel
//! TLS**: the bulk record crypto runs in the kernel, so recv/send move plain
//! application bytes and the framer stays byte-agnostic. The library brings no
//! TLS library — the *consumer* runs the handshake. For each accepted kTLS
//! connection the server materializes a real socket fd and calls the
//! [`Server::set_tls_handshake`] handler with
//! `(fd, `[`Incoming`]`, `[`AcceptDeferral`]`)` — the [`Incoming`] carries the
//! peer and the listener the connection arrived on (per-listener policy,
//! since the `accept` handler does not run for kTLS connections);
//! the handler hands both to its **own worker** (never the ring thread — a
//! handshake blocks on client round-trips), runs the TLS handshake there (which
//! installs kTLS on the socket, e.g. OpenSSL with `SSL_OP_ENABLE_KTLS`), and
//! calls [`AcceptDeferral::ready`] with the per-connection state — or
//! [`AcceptDeferral::reject`]. The connection is parked until then, then served
//! over the kernel-TLS receive transport.
//!
//! Scope: application data flows transparently; any **control record** (a
//! post-handshake handshake message, TLS 1.3 KeyUpdate, renegotiation, or an
//! alert / `close_notify`) closes the connection ([`CloseReason::TlsControl`]) —
//! renegotiation/rekey are out of scope — and close is a truncation-close (no
//! `close_notify` is emitted). Needs the kernel TLS ULP (`CONFIG_TLS`), probed
//! at construction. Protocols that carry their **own** message encryption
//! (SMB3-style transform headers) need none of this — they encrypt in the body
//! handler.
//!
//! **Body splicing works over kTLS.** A [`Framing::SpliceBody`] body moves
//! through the socket's in-kernel `splice_read`, which for kTLS is
//! `tls_sw_splice_read` — it *decrypts* each record and moves the plaintext to
//! the consumer fd, so the body streams zero-copy **and in the clear**, with
//! neither the ciphertext nor the plaintext passing through userspace. One
//! non-obvious invariant makes this correct: the header recv decrypts a whole
//! TLS record, so when that record also carried the first body bytes the
//! kernel strands their plaintext in its TLS receive list; the splice drains
//! that stranded remainder *before* pulling the next record (missing it would
//! silently truncate the body). A control record met mid-splice is refused by
//! the kernel and closes the connection ([`CloseReason::TlsControl`]), exactly
//! as on the buffered path. NIC-offloaded kTLS RX (`tls_device`) routes through
//! this **same** `tls_sw_splice_read` — the NIC decrypts, the software layer
//! still frames records with a decrypt fallback — so splice is expected to
//! work there too, though it is untested without offload-capable hardware
//! (the legacy `TLS_HW_RECORD` full-offload mode delivers a plain stream and
//! is out of scope). The one real constraint is the timeout: a kTLS splice
//! *blocks* in the kernel awaiting the next record (it never returns `EAGAIN`
//! the way a plain-socket splice does, so no readiness-poll clock and no
//! linkable timeout can reach it), so its inactivity bound is
//! [`ServerConfig::request_timeout`] enforced by a standalone watchdog that
//! cancels a stalled splice — see [`Framing::SpliceBody`] for the framer
//! contract.
//!
//! # Observability
//!
//! [`Server::stats_handle`] returns a `Send + Sync` [`StatsHandle`] whose
//! [`StatsHandle::snapshot`] reads live counters ([`ServerStats`]: accepts,
//! rejections, sheds, accept-retries, closes, active, requests, deferrals,
//! replies, pushes, recv/send ops, bytes in/out) from any thread.
//!
//! # Pipelining
//!
//! By default ([`ServerConfig`]'s `max_in_flight_requests == 1`) a connection is
//! strictly sequential: one request is fully answered before the next is read.
//! Setting `N > 1` **pipelines** — while a request is deferred to a worker, the
//! server reads and processes up to `N-1` further requests on that connection,
//! so recv and send run concurrently over the one fd (each direction has its own
//! `msghdr`, like tokio's `ReadHalf`/`WriteHalf`). Two consequences: replies can
//! complete **out of request order** (a fast reply overtakes an earlier deferred
//! one), so the consumer's protocol must carry request ids and correlate replies
//! itself — the server sends them in production order and never reorders to match
//! requests; and read-ahead is bounded by `N` (reading pauses at `N` in-flight
//! requests and resumes as replies drain). Byte order *within* the reply stream
//! is still the library's job: one `MSG_WAITALL` send at a time, in FIFO
//! production order — with up to `ServerConfig::max_send_coalesce` already-queued
//! PDUs gathered into each send (writev-style reply coalescing), so a burst of
//! pipelined replies leaves in one op without ever delaying a lone reply.
//!
//! # Design notes
//!
//! Three load-bearing decisions, recorded so future work does not trade them
//! away:
//!
//! * **The receive path stays single-shot, caller-owned-buffer recvs**
//!   (`MSG_WAITALL`, armed per state-machine step). Because each recv is an
//!   explicit step with a caller-chosen destination, parsing a header and
//!   then diverting the message *body* somewhere other than the connection
//!   buffer is directly expressible — this is exactly what
//!   [`Framing::SpliceBody`] does (body → consumer pipe in-kernel, Samba's
//!   `recvfile` shape, no userspace copy) and what body *placement* does at
//!   the allocation level. Multishot receive / provided buffer rings (where
//!   the kernel picks the landing buffer) would forfeit that per-message
//!   control, so they could only ever become an opt-in alternate path,
//!   never a replacement.
//! * **The event loop is deliberately synchronous — it is the reactor.**
//!   Async consumers integrate at the offload boundary ([`Deferred`],
//!   [`PushHandle`]: `Send` handles + the eventfd wake), e.g. spawning the
//!   work onto a tokio runtime and replying from the task. The protocol loop
//!   itself will not become async: every kernel-touched buffer stays owned by
//!   loop-owned connection slots (nothing can be dropped mid-op, so io_uring's
//!   future-cancellation/buffer-ownership problem never arises), per-
//!   connection state never crosses threads, and completion-native features
//!   (multishot accept and the body splice today; `SEND_ZC` later) stay
//!   directly expressible. An async executor for fs-op trees, if built, lives
//!   *behind* the Defer boundary on its own ring — not inside this one.
//! * **No signal machinery.** `io_uring_enter` is deliberately called without
//!   a sigmask (the `pselect`-style atomic-unmask argument): nothing in the
//!   loop is signal-driven — every wakeup, including cross-thread ones, is a
//!   CQE (socket completions; the eventfd `READ`), so there is no
//!   check-flag-then-sleep race for a mask to close, and a library should
//!   never mutate process-global signal state. `EINTR` — from real signals
//!   and from the kernel's own task-work notifications — is simply retried.
//!   Consumers integrate signals the standard daemon way: block them
//!   process-wide, `sigwait` on a dedicated thread, and call
//!   [`ShutdownHandle::shutdown`] (an eventfd poke).
//!
//! # Safety model
//!
//! Every buffer the kernel touches (the accumulating recv buffer, the queued
//! response buffers, and the send gather's `iovec`s/`msghdr`) lives inside a
//! `Box<Connection>` in a slab keyed by the pool slot, so its address is stable
//! from SQE submission until the matching CQE. The recv and send sides have
//! **separate** descriptors and buffers, so a recv and a send may be in flight
//! at once (pipelined mode) without either op's `msghdr` being clobbered by the
//! other; an optional linked idle-timeout rides on the recv but reads only a
//! shared, stable timespec, never the connection. A connection is freed only
//! after **all** of its in-flight ops (recv, send, and the final `close`) have
//! reaped — so the kernel never writes into freed memory — and on shutdown every
//! outstanding op is cancelled and reaped to zero before any buffer or the ring
//! is released.
//!
//! # Capacity and overload
//!
//! [`ServerConfig`]'s `pool_size` is the maximum number of concurrent
//! connections: it sizes the registered-file pool multishot accept allocates
//! into.
//! Because the kernel *dequeues* a connection before trying to place it in a
//! pool slot, a connection offered while the pool is full is accepted and then
//! immediately closed (the client sees `ECONNRESET`) — i.e. the server sheds
//! load rather than queueing unboundedly. Size `pool_size` to your peak
//! expected concurrency; the server keeps draining the backlog as slots free.
//!
//! **Slow-loris coverage.** A peer that seizes a pool slot and then makes no
//! progress ties it up; enough such peers exhaust `pool_size` and deny service.
//! Three timeouts each bound one stall surface — a hardened deployment sets all
//! that apply:
//! * `idle_timeout` — parked between requests with **nothing buffered** (the
//!   connect-and-stay-silent variant); a kernel `LINK_TIMEOUT` on the idle recv.
//! * `request_timeout` — a request has **begun** (a body, or an exact header
//!   remainder) but stalls half-sent, which `idle_timeout` does not cover (a
//!   half-sent request is not idle); a `LINK_TIMEOUT` on the in-progress recv.
//!   It also clocks a spliced body's progress: the readiness poll between
//!   splice chunks (plain TCP), or each record of a kTLS splice — which would
//!   otherwise block an io-wq worker with no cancellable recv for any other
//!   timeout to reach (see [`Framing::SpliceBody`]).
//! * `tls_handshake_timeout` — a kTLS connection **parked across its handshake**
//!   (no recv/send yet), which neither recv-linked timeout reaches; a standalone
//!   `TIMEOUT` on the park.
//!
//! The recv-linked timeouts cost no wakeups until a stall and never interrupt a
//! steadily progressing transfer. All default to `None`; set them especially
//! when `pool_size` is tight and idle keep-alive would crowd out live traffic.
//!
//! `send_timeout` is the send-side counterpart: a `LINK_TIMEOUT` on each send
//! that closes a connection whose reply stalls (a peer that stopped reading) —
//! without it, TCP retries such a send forever and the slot is held until
//! shutdown. It is what covers a connection that has **retired its recv side
//! to speak last** — [`Response::ReplyClose`], [`Deferred::reply_close`], or
//! [`PushHandle::close`]: while flush-closing no recv is armed, so
//! `idle_timeout`/`request_timeout` cannot reap a peer that stops reading
//! before the farewell drains, leaving `send_timeout` (or `tcp_user_timeout`)
//! the only reclaim path short of shutdown. Of the TCP-level backstops,
//! `tcp_user_timeout` aborts such a zero-window peer, but `keepalive` does not
//! — it detects a *dead* peer (missing ACKs), not a live one that stopped
//! reading. `reuse_port` lets several independent single-ring servers share one
//! address for multi-core (the kernel balances connections across them) — see
//! `examples/tcp_multicore.rs`.
//!
//! # Shutdown
//!
//! [`ShutdownHandle::shutdown`] stops immediately: all in-flight operations
//! are cancelled. [`ShutdownHandle::shutdown_graceful`] drains instead:
//! accepting stops and idle connections close at once, while requests already
//! in flight — reads in progress, deferred worker replies, queued sends —
//! run to completion, each connection closing as it quiesces; if the drain
//! outlives the grace period, the remainder is cancelled. For visibility into
//! why connections close (clean EOF, malformed input, timeouts, errors,
//! shutdown), install a [`Server::set_close_hook`] — it receives
//! `(peer, `[`CloseReason`]`, &mut state)` once per connection as it begins
//! closing.
//!
//! # Kernel support
//!
//! Requires io_uring with multishot accept + direct-descriptor allocation
//! (Linux ≥ 5.19; the crate targets 6.18). Where io_uring is unavailable
//! (old kernel, seccomp, `kernel.io_uring_disabled`), [`Server::bind`] fails
//! with [`Errno::ENOSYS`]/`EPERM`/`EACCES`. TCP listeners additionally need
//! socket commands (Linux ≥ 6.7) for the per-connection `SO_PEERNAME` fetch,
//! and `unix_peercred` needs them working on `AF_UNIX` (Linux ≥ 6.18.16) —
//! both probed at construction with a clear validation error. kTLS listeners
//! and [`Response::Detach`] additionally need `IORING_OP_FIXED_FD_INSTALL`
//! (Linux ≥ 6.8) to furnish the real fd — probed via `IORING_REGISTER_PROBE`
//! (kTLS fails construction; Detach fails `serve_forever` once a detach
//! handler is installed).
//!
//! [`Errno::ENOSYS`]: crate::errno::Errno::ENOSYS
//!
//! # Example
//!
//! ```no_run
//! use truenas_ros::net::server::{
//!     length_prefixed, ClientAddr, Endian, PrefixWidth, Server, ServerAddr,
//! };
//!
//! // Echo server framed by a 4-byte big-endian length prefix (not counting
//! // itself), on an ephemeral loopback TCP port.
//! let addr = ServerAddr::Tcp("127.0.0.1:0".parse().unwrap());
//! let proto = length_prefixed(
//!     PrefixWidth::U32,
//!     Endian::Big,
//!     false,
//!     |_header: &[u8], body: &[u8], _peer: &ClientAddr| {
//!         // Re-frame the echo so the client can length-delimit the reply
//!         // (`None` would close the connection instead).
//!         let mut reply = (body.len() as u32).to_be_bytes().to_vec();
//!         reply.extend_from_slice(body);
//!         Some(reply)
//!     },
//! );
//! let mut server = Server::bind([addr], proto)?;
//!
//! let stop = server.shutdown_handle();
//! // `stop` is Send + Sync: hand it to another thread and call
//! // `stop.shutdown()` to make `serve_forever` return.
//! std::thread::spawn(move || stop.shutdown());
//!
//! server.serve_forever()?;
//! # Ok::<(), truenas_ros::Error>(())
//! ```

// The whole module assumes the 64-bit little-endian kernel ABI (x86_64 /
// aarch64 — the only TrueNAS targets): SQE/CQE field offsets, `__aligned_u64`
// == `u64`, and the libc `msghdr`/`iovec` layout all depend on it.
#[cfg(not(all(target_pointer_width = "64", target_endian = "little")))]
compile_error!("the net stack requires a 64-bit little-endian target");

// The completion loop and the public `Server` live in this file; the sibling
// files hold the server's role halves by lifecycle stage — `accept` (admission
// and peer identity), `io` (the request data plane), `close` (teardown),
// `wake` (cross-thread work delivery and graceful drain), and `handles` (the
// cross-thread contract). The shared engine those halves drive — framing,
// recv/send, splice, and the SQE staging / slot bookkeeping — lives in
// `net::core::reactor` (`Reactor`), which this `Server` embeds as `self.core`.
pub(crate) mod accept;
mod close;
mod config;
mod handles;
mod io;
mod listen;
mod protocol;
mod wake;

pub use crate::net::core::handles::AcceptDeferral;
pub use crate::net::core::protocol::{
    length_prefix_header, Body, ClientAddr, CloseReason, Endian, Framing,
    PeerCred, PrefixWidth, ServerAddr,
};
pub use config::{Listen, ServerConfig};
pub use handles::{
    DeferPermit, Deferred, DetachPermit, Detached, PushHandle, Responder,
    ServerStats, ShutdownHandle, StatsHandle,
};
pub use protocol::{
    length_prefixed, DetachContext, Incoming, Protocol, Request, Response,
};

/// The pure framing decision, re-exported only under the `__fuzz` feature for
/// `fuzz/fuzz_targets/framing_arithmetic.rs`. Not part of the stable API. It
/// lives in `net::core` now (the engine that enacts it is core); re-exported
/// here to keep the `net::server` fuzz path stable.
#[cfg(feature = "__fuzz")]
pub use crate::net::core::reactor::{frame_step, FrameStep};

use crate::errno::{self};
use crate::error::Error;
use crate::net::core::conn::{unpack, Op};
use crate::net::core::handles::{
    create_eventfd, HandshakeOutcome, LoopShared, StatsInner, WakeHandle,
};
use crate::net::core::probe::{probe_ktls, probe_tcp_cmd, probe_unix_peercred};
use crate::net::core::reactor::{KernelPads, Reactor};
use crate::net::core::ring::Ring;
use crate::net::core::sock;
use crate::net::core::sys::*;
use crate::net::core::table::ConnTable;
use handles::Injected;
use listen::listen_socket;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::Duration;

/// Kernel cap on SQ ring entries.
const MAX_RING_ENTRIES: u32 = 32768;
/// Backoff before re-arming a listener's accept after a transient error
/// (resource pressure) — throttles the retry so it can't spin at 100% CPU.
const ACCEPT_RETRY_MS: u64 = 20;

/// The kTLS handshake handler ([`Server::set_tls_handshake`]):
/// `(furnished_fd, incoming, deferral)`, once per connection on a kTLS
/// listener. The consumer moves the fd + deferral to its own worker, runs
/// the TLS handshake, and hands the connection back.
pub(super) type TlsHandshakeFn<U> =
    Box<dyn FnMut(RawFd, Incoming<'_>, AcceptDeferral<U>)>;

/// The detach handler ([`Server::set_detach_handler`]): `(context, detached)`,
/// called once per detached connection when its real fd is materialized. The
/// consumer moves the [`Detached`] (owning the fd) to its own worker, does the
/// blocking op, and resumes or closes the connection.
pub(super) type DetachFn<U> = Box<dyn FnMut(DetachContext<'_, U>, Detached)>;

/// The consumer's code: the three [`Protocol`] closures plus the two
/// registered hooks. Grouped so a stage can call a handler while holding a
/// borrow of a *different* `Server` field (e.g. the connection being
/// delivered) — field-path borrows are disjoint — and so "what runs user
/// code" is one named place.
///
/// Deliberately bound-free (like `Server` itself): bounds here would force
/// themselves onto every impl block, including the teardown paths that run
/// no user code.
struct Handlers<U, AcceptFn, HeaderFn, BodyFn> {
    accept: AcceptFn,
    header: HeaderFn,
    body: BodyFn,
    /// Required iff any listener is kTLS ([`Server::set_tls_handshake`]).
    tls_handshake: Option<TlsHandshakeFn<U>>,
    /// Required iff a `body` handler ever returns [`Response::Detach`]
    /// ([`Server::set_detach_handler`]).
    detach: Option<DetachFn<U>>,
}

/// Work injected by other threads, drained on each wake: deferred replies
/// and pushes (`inject_*`), and kTLS handshake outcomes (`accept_*` — typed
/// over `U`, kept separate so [`Injected`] stays non-generic).
struct Mailbox<U> {
    inject_tx: mpsc::Sender<Injected>,
    inject_rx: mpsc::Receiver<Injected>,
    handshake_tx: mpsc::Sender<HandshakeOutcome<U>>,
    handshake_rx: mpsc::Receiver<HandshakeOutcome<U>>,
}

/// One bound listener: its fd, its (resolved) address — handed to the accept
/// handler as the connection's arrival point — and whether its multishot
/// accept is parked on a full pool awaiting a freed slot.
struct Listener {
    fd: OwnedFd,
    addr: ServerAddr,
    awaiting_slot: bool,
    /// A kTLS listener: each accepted connection is furnished a real fd for
    /// the consumer's TLS handshake, then served over the kernel-TLS recv
    /// transport (see [`Server::set_tls_handshake`]).
    tls: bool,
}

/// A single-threaded io_uring stream server.
///
/// Parameterized by the per-connection state `U` and the three handler closures
/// (see [`Protocol`]). Holds raw ring pointers, so it is `!Send`/`!Sync`: the
/// ring is owned by exactly one thread (single-ring-per-thread model).
pub struct Server<U, AcceptFn, HeaderFn, BodyFn> {
    // The role-agnostic io_uring engine the server drives: the ring, the
    // connection table, the projected `CoreConfig`, the shared cross-thread
    // flags/stats, the kernel-touched pads, and the close hook. Its own field
    // order (table before ring) keeps the buffers-before-unmap invariant, so
    // the whole engine drops safely as one unit.
    core: Reactor<U>,
    // The consumer's closures and hooks.
    handlers: Handlers<U, AcceptFn, HeaderFn, BodyFn>,
    listeners: Vec<Listener>,
    // Cross-thread work, delivered by a wake poke and drained in `on_wake`.
    mailbox: Mailbox<U>,
    // Server-only tuning: the pool/listen/socket knobs the engine does not read
    // (the engine-read subset is projected into `core.cfg`).
    cfg: ServerConfig,
}

impl<U, AcceptFn, HeaderFn, BodyFn> Server<U, AcceptFn, HeaderFn, BodyFn>
where
    AcceptFn: FnMut(Incoming<'_>) -> Option<U>,
    HeaderFn: FnMut(&[u8], &mut U) -> Framing,
    BodyFn: FnMut(Request<'_, U>) -> Response,
{
    /// Bind + listen + set up the ring and pool with the default config.
    ///
    /// `addrs` is one or more listen addresses (any mix of TCP and unix), all
    /// served by this one ring/thread; a single address is `[addr]`. Each item
    /// is `impl Into<`[`Listen`]`>` — a bare [`ServerAddr`] is plain, or
    /// [`Listen::tls`]`(addr)` opts that address into kernel TLS (which needs a
    /// [`Server::set_tls_handshake`] handler). Connections from every listener
    /// share the pool and all limits.
    pub fn bind(
        addrs: impl IntoIterator<Item = impl Into<Listen>>,
        protocol: Protocol<AcceptFn, HeaderFn, BodyFn>,
    ) -> crate::Result<Self> {
        Self::with_config(addrs, ServerConfig::default(), protocol)
    }

    /// As [`Server::bind`], with explicit tuning.
    pub fn with_config(
        addrs: impl IntoIterator<Item = impl Into<Listen>>,
        cfg: ServerConfig,
        protocol: Protocol<AcceptFn, HeaderFn, BodyFn>,
    ) -> crate::Result<Self> {
        let addrs: Vec<Listen> = addrs.into_iter().map(Into::into).collect();
        cfg.validate(&addrs)?;

        // Peak SQEs a connection can hold at once: a recv, a concurrent send
        // (only when pipelining), and a linked timeout on each timed op. Size
        // the ring so a full pool's peak never forces a mid-batch flush (which
        // would also split a linked op+timeout pair).
        let per_conn = (if cfg.max_in_flight_requests > 1 { 2 } else { 1 })
            + u32::from(
                cfg.idle_timeout.is_some() || cfg.request_timeout.is_some(),
            )
            + u32::from(cfg.send_timeout.is_some())
            + u32::from(cfg.tls_handshake_timeout.is_some());
        let entries = cfg
            .pool_size
            .saturating_mul(per_conn)
            .saturating_add(1 + addrs.len() as u32)
            .next_power_of_two()
            .min(MAX_RING_ENTRIES);
        let mut ring = Ring::new(entries)?;
        ring.register_pool(cfg.pool_size)?;

        // Fail fast — before binding — on kernels whose io_uring can't serve
        // the per-connection peer-identity fetches; otherwise every affected
        // connection would be silently shed at accept.
        if cfg.unix_peercred
            && addrs.iter().any(|l| matches!(l.addr, ServerAddr::Unix(_)))
        {
            probe_unix_peercred(&mut ring)?;
        }
        if addrs
            .iter()
            .any(|l| matches!(l.addr, ServerAddr::Tcp(_) | ServerAddr::Tcp6(_)))
        {
            probe_tcp_cmd(&mut ring)?;
        }
        // Fail fast if kTLS was requested but the kernel lacks the `tls` ULP.
        if addrs.iter().any(|l| l.tls) {
            probe_ktls()?;
        }
        // `FIXED_FD_INSTALL` (Linux ≥ 6.8) furnishes the real fd behind every
        // kTLS handshake and every `Response::Detach`. kTLS is known now —
        // fail construction; Detach is a runtime decision, so the flag is
        // kept and checked when a detach handler is installed
        // (`serve_forever`).
        let fixed_fd_install =
            crate::net::core::probe::probe_fixed_fd_install(&ring);
        if !fixed_fd_install && addrs.iter().any(|l| l.tls) {
            return Err(Error::Validation(
                "kTLS listeners require IORING_OP_FIXED_FD_INSTALL \
                 (Linux ≥ 6.8); this kernel's io_uring does not support it"
                    .into(),
            ));
        }

        let mut listeners = Vec::with_capacity(addrs.len());
        for l in addrs {
            let fd = listen_socket(&l.addr, &cfg)?;
            // Resolve ephemeral ports now; `local_addrs` reads stored values.
            let addr = sock::local_addr(fd.as_raw_fd(), &l.addr)?;
            listeners.push(Listener {
                fd,
                addr,
                awaiting_slot: false,
                tls: l.tls,
            });
        }

        let ts_of = |d: Duration| KernelTimespec {
            // Clamp: `Duration::MAX.as_secs()` (or anything >= 2^63) would
            // wrap the `as i64` cast negative, and the kernel rejects a
            // negative tv_sec with -EINVAL — a LINK_TIMEOUT that fails prep
            // takes its linked op down with -ECANCELED, inverting "never"
            // into "instantly" (every connection closed at its first parked
            // read). i64::MAX seconds ≈ 2.9e11 years IS "never".
            tv_sec: d.as_secs().min(i64::MAX as u64) as i64,
            tv_nsec: d.subsec_nanos() as i64,
        };
        let pads = Box::new(KernelPads {
            wake_buf: 0,
            deadline: KernelTimespec::default(),
            accept_retry: ts_of(Duration::from_millis(ACCEPT_RETRY_MS)),
            idle_timeout: cfg.idle_timeout.map(ts_of).unwrap_or_default(),
            send_timeout: cfg.send_timeout.map(ts_of).unwrap_or_default(),
            request_timeout: cfg.request_timeout.map(ts_of).unwrap_or_default(),
            tls_handshake: cfg
                .tls_handshake_timeout
                .map(ts_of)
                .unwrap_or_default(),
        });

        let shared = Arc::new(LoopShared {
            stop: AtomicBool::new(false),
            graceful: AtomicBool::new(false),
            grace_ms: AtomicU64::new(0),
            wake: WakeHandle {
                fd: create_eventfd()?,
            },
        });
        let (inject_tx, inject_rx) = mpsc::channel();
        let (handshake_tx, handshake_rx) = mpsc::channel();

        // The role-agnostic engine. `on_close` starts unset (installed by
        // `set_close_hook`); `cfg.to_core()` projects the engine-read knobs.
        let core = Reactor {
            table: ConnTable::new(cfg.pool_size),
            cfg: cfg.to_core(),
            stats: Arc::new(StatsInner::default()),
            shared,
            pads,
            on_close: None,
            inflight: 0,
            draining: false,
            fixed_fd_install,
            pool_freed: false,
            ring,
        };
        Ok(Server {
            core,
            handlers: Handlers {
                accept: protocol.accept,
                header: protocol.header,
                body: protocol.body,
                tls_handshake: None,
                detach: None,
            },
            listeners,
            mailbox: Mailbox {
                inject_tx,
                inject_rx,
                handshake_tx,
                handshake_rx,
            },
            cfg,
        })
    }

    /// Run the event loop until a [`ShutdownHandle`] stops it or a fatal ring
    /// error occurs. In-flight operations are drained before returning.
    pub fn serve_forever(&mut self) -> crate::Result<()> {
        if self.listeners.iter().any(|l| l.tls)
            && self.handlers.tls_handshake.is_none()
        {
            return Err(Error::Validation(
                "a kTLS listener requires Server::set_tls_handshake".into(),
            ));
        }
        // A detach handler means `Response::Detach` is on the table, and each
        // detach needs `IORING_OP_FIXED_FD_INSTALL` (Linux ≥ 6.8; probed at
        // construction). Fail here with a clear error instead of closing
        // every detached connection with a mysterious EINVAL at runtime.
        if self.handlers.detach.is_some() && !self.core.fixed_fd_install {
            return Err(Error::Validation(
                "Response::Detach requires IORING_OP_FIXED_FD_INSTALL \
                 (Linux ≥ 6.8); this kernel's io_uring does not support it"
                    .into(),
            ));
        }
        self.core.arm_wake()?;
        for lidx in 0..self.listeners.len() as u32 {
            self.arm_accept(lidx)?;
        }
        let run = self.run_loop();
        let drained = self.core.cancel_and_reap_all();
        run?;
        drained?;
        Ok(())
    }

    fn run_loop(&mut self) -> errno::Result<()> {
        while !self.core.stopping() {
            if self.core.inflight == 0 {
                break; // nothing outstanding; avoid blocking forever
            }
            // submit_and_wait always enters with GETEVENTS, which also flushes
            // any IORING_SQ_CQ_OVERFLOW backlog, so completions can't be
            // stranded even under NODROP.
            self.core.ring.submit_and_wait(1)?;
            while let Some(cqe) = self.core.ring.reap() {
                self.dispatch(cqe)?;
                // A slot freed during this dispatch (`Reactor::reclaim_slot`
                // raised the flag): re-arm any listener parked on a full pool.
                // Kept out of the core reclaim so the drain path
                // (`cancel_and_reap_all`, which never drains this flag) can't
                // re-arm accepts while tearing down.
                if self.core.take_pool_freed() {
                    self.rearm_parked_accepts()?;
                }
            }
        }
        Ok(())
    }

    fn dispatch(&mut self, cqe: IoUringCqe) -> errno::Result<()> {
        let (op, slot, generation) = unpack(cqe.user_data);
        // Count the reaped CQE off `inflight` BEFORE its handler runs: the
        // arms below `?`-propagate, and skipping the decrement on an error
        // would leave the count permanently high — `cancel_and_reap_all`
        // would then wait forever for a completion that will never come
        // (turning a fatal-error return into a hang in `serve_forever` and
        // `Drop`).
        if cqe.flags & IORING_CQE_F_MORE == 0 {
            self.core.inflight = self.core.inflight.saturating_sub(1);
        }
        match op {
            // For accept ops the slot field carries the listener index.
            Some(Op::Accept) => self.on_accept(slot, &cqe)?,
            Some(Op::Wake) => self.on_wake()?,
            Some(op @ (Op::RecvHeader | Op::RecvBody)) => {
                self.on_recv(slot, generation, cqe.res, op)?
            }
            // A framed body finished splicing straight to a consumer fd;
            // `cqe.res` is bytes moved (or `<= 0` on EOF/cancel/error/`EAGAIN`).
            Some(Op::SpliceRecv) => {
                self.on_splice_recv(slot, generation, cqe.res)?
            }
            // A splice-readiness poll fired: the socket is readable again after
            // a splice hit `-EAGAIN`; resubmit the splice for the remainder.
            Some(Op::SplicePoll) => {
                self.core.on_splice_poll(slot, generation, cqe.res)?
            }
            Some(Op::Send) => self.on_send(slot, generation, cqe.res)?,
            Some(Op::Close) => self.core.on_closed(slot)?,
            // The graceful-shutdown grace period expired (or the op was
            // cancelled at teardown): if still draining, escalate to a hard
            // stop — `serve_forever`'s drain cancels whatever remains.
            Some(Op::Deadline) => {
                if self.core.draining && !self.core.stopping() {
                    self.core.shared.stop.store(true, Ordering::Release);
                }
            }
            // A peer-identity fetch — the slot's PendingPeer pad says which.
            Some(Op::Cred | Op::Peername) => {
                self.on_peer_fetch(slot, generation, cqe.res)?
            }
            // A pre-close SHUTDOWN completed; submit the CLOSE that frees the
            // slot. (Its result is irrelevant — see `on_shutdown`.)
            Some(Op::Shutdown) => self.core.on_shutdown(slot, generation)?,
            // A furnished-fd install for a kTLS connection completed; `cqe.res`
            // is the new real fd (or `-errno`).
            Some(Op::FdInstall) => {
                self.on_fd_install(slot, generation, cqe.res)?
            }
            // A detach fd-install completed; `cqe.res` is the furnished real fd
            // (or `-errno`). Hand it to the detach handler and park, or close.
            Some(Op::DetachInstall) => {
                self.on_detach_install(slot, generation, cqe.res)?
            }
            // Accept-retry backoff elapsed (or was cancelled at shutdown): the
            // slot field is the listener index. Re-arm its accept unless
            // shutting down.
            Some(Op::AcceptRetry) => {
                if !self.core.stopping() && !self.core.draining {
                    self.arm_accept(slot)?;
                }
            }
            // A parked kTLS handshake's timeout fired (or was cancelled on
            // resolve): shed the slot if it is still parked.
            Some(Op::HandshakeTimeout) => {
                self.on_handshake_timeout(slot, generation)?
            }
            // A recv's linked idle/request clock: pairs with its recv CQE to
            // disambiguate a cancelled-with-progress short read from a peer
            // FIN mid-frame (`on_recv_clock`). Like `LinkTimeout`, not
            // counted in `conn.ops`.
            Some(Op::RecvClock) => {
                self.core.on_recv_clock(slot, generation, cqe.res)?
            }
            Some(Op::LinkTimeout) => {}
            // A kTLS body-splice inactivity watchdog fired or was cancelled.
            Some(Op::SpliceDeadline) => {
                self.core.on_splice_deadline(slot, generation, cqe.res)?
            }
            // The client's outbound-connect op; a server never dials out.
            Some(Op::Connect) => unreachable!("server never connects"),
            Some(Op::Cancel) | None => {}
        }
        Ok(())
    }
}

// Methods that touch none of the handler closures — usable from `Drop`.
impl<U, AcceptFn, HeaderFn, BodyFn> Server<U, AcceptFn, HeaderFn, BodyFn> {
    /// The bound addresses, in the order given to [`Server::bind`] (ephemeral
    /// `:0` TCP ports come back resolved).
    pub fn local_addrs(&self) -> Vec<ServerAddr> {
        self.listeners.iter().map(|l| l.addr.clone()).collect()
    }

    /// A `Send + Sync` handle that stops [`Server::serve_forever`] from another
    /// thread. Obtain it before calling `serve_forever`.
    pub fn shutdown_handle(&self) -> ShutdownHandle {
        ShutdownHandle {
            shared: Arc::clone(&self.core.shared),
        }
    }

    /// A `Clone + Send + Sync` handle for reading this server's counters from
    /// any thread while it runs (see [`ServerStats`]).
    pub fn stats_handle(&self) -> StatsHandle {
        StatsHandle {
            inner: Arc::clone(&self.core.stats),
        }
    }

    /// Install a hook invoked once per connection as it begins closing:
    /// `(peer, reason, &mut state)` — for logging/metrics; the state is dropped
    /// with the connection shortly after. Connections that never passed
    /// `accept` (rejected, load-shed, or arriving mid-shutdown) have no state
    /// and are not reported.
    pub fn set_close_hook<F>(&mut self, hook: F)
    where
        F: FnMut(&ClientAddr, CloseReason, &mut U) + 'static,
    {
        self.core.on_close = Some(Box::new(hook));
    }

    /// Install the kernel-TLS handshake handler, required when any listener is
    /// [`Listen::tls`]. Called once per accepted kTLS connection with
    /// `(fd, incoming, deferral)`: a **real** socket fd (materialized from the
    /// pool descriptor), the [`Incoming`] context — peer identity plus the
    /// listener the connection arrived on, the per-listener
    /// certificate/admission hook, since the `accept` handler does not run
    /// for kTLS connections ([`AcceptDeferral::ready`] *is* the admission) —
    /// and the [`AcceptDeferral`] itself. Move the fd and the deferral to
    /// your own worker (never block the ring thread), run the TLS handshake
    /// there — which installs kTLS on the socket (e.g. OpenSSL with
    /// `SSL_OP_ENABLE_KTLS`) — then call [`AcceptDeferral::ready`] with the
    /// per-connection state, or [`AcceptDeferral::reject`] on failure. Close
    /// the furnished fd once the handshake is done; the connection is then
    /// served over the pool descriptor (kTLS lives on the shared socket).
    /// The per-connection state `U` must be `Send` (it crosses back from the
    /// worker).
    pub fn set_tls_handshake<F>(&mut self, handler: F)
    where
        F: FnMut(RawFd, Incoming<'_>, AcceptDeferral<U>) + 'static,
    {
        self.handlers.tls_handshake = Some(Box::new(handler));
    }

    /// Install the **detach** handler, required when a `body` handler ever
    /// returns [`Response::Detach`]. Called once per detached connection with
    /// `(context, detached)`: the [`DetachContext`] (peer + `&mut state`, where
    /// the body handler stashed the job) and a [`Detached`] handle owning a real
    /// socket fd (materialized from the pool descriptor, aliasing it). Move the
    /// [`Detached`] to your own worker (never block the ring thread), do the
    /// blocking work on [`Detached::raw_fd`] (e.g. `lzc_send`/`lzc_receive`),
    /// then call [`Detached::resume`] to keep serving or [`Detached::close`].
    /// The connection is parked until then; a dropped handle closes it.
    pub fn set_detach_handler<F>(&mut self, handler: F)
    where
        F: FnMut(DetachContext<'_, U>, Detached) + 'static,
    {
        self.handlers.detach = Some(Box::new(handler));
    }
}

impl<U, AcceptFn, HeaderFn, BodyFn> Drop
    for Server<U, AcceptFn, HeaderFn, BodyFn>
{
    fn drop(&mut self) {
        // If `serve_forever` ran it already drained (no-op here); otherwise
        // (early drop / panic unwind) ensure no op is in flight before the
        // buffers and ring are freed.
        let _ = self.core.cancel_and_reap_all();
    }
}

impl<U, AcceptFn, HeaderFn, BodyFn> std::fmt::Debug
    for Server<U, AcceptFn, HeaderFn, BodyFn>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Server")
            .field("addrs", &self.local_addrs())
            .field("cfg", &self.cfg)
            .field("inflight", &self.core.inflight)
            .field("ring", &self.core.ring)
            .finish_non_exhaustive()
    }
}
