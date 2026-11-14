//! An io_uring stream server whose API mirrors Python's `socketserver`.
//!
//! [`Server`] runs one io_uring ring on one thread. Each listener is armed with a multishot accept that places each
//! connection in a registered-file pool, and each connection loops through receiving a header, framing it, receiving
//! the body, running the handler and sending, one SQE at a time. The caller frames messages through a [`Protocol`],
//! since a stream has no message boundaries and a receive may return less than one message, and the server never parses
//! a header itself. [`length_prefixed`] covers the fixed-width length prefix.
//!
//! Handlers run inline on the ring thread, so slow work goes to a worker. A handler takes the owned inputs the worker
//! needs ([`Body::take`]), detaches a [`Deferred`] with [`Responder::defer`], hands it to its own pool and returns
//! [`Response::Defer`]. Workers never touch the ring. A reply, push or close crosses back on a queue and an eventfd
//! wake, and is dropped if its connection closed or its slot was recycled meanwhile. The loop is synchronous by design,
//! and an async consumer meets it at that boundary, since loop-owned slots are what keep every kernel-touched buffer
//! alive across its op. [`Server`] is `!Send`, so a process that wants more cores runs one server per thread, sharing a
//! port through [`reuse_port`](ServerConfig::reuse_port) and balanced by a [`Spread`].
//!
//! Every buffer the kernel touches stays at a stable address from submission until its completion is reaped. A
//! connection is freed only after all of its in-flight ops have reaped, and shutdown cancels and reaps every op before
//! any buffer or the ring is released. The loop passes no sigmask and installs no signal handler, since every wakeup is
//! a completion and `EINTR` is retried, so a consumer stops it from its own signal thread with
//! [`ShutdownHandle::shutdown`].
//!
//! A multishot accept writes every peer address into one shared buffer, so peer identity is fetched per connection
//! (`SO_PEERNAME`, or `SO_PEERCRED` with `ServerConfig::unix_peercred`), and a failed fetch sheds the connection rather
//! than deliver it with a wrong identity. A pool slot is taken at accept, before any authentication, and a connection
//! offered while the pool is full is accepted and closed at once. A server facing untrusted peers sets the timeouts
//! that apply, `idle_timeout`, `request_timeout`, `max_receipt_time`, `tls_handshake_timeout` and `send_timeout`, each
//! documented on [`ServerConfig`].
//!
//! A [`Framing::SpliceBody`] body moves from the socket to a consumer pipe in the kernel. Over kTLS the splice holds
//! the destination pipe's mutex while it waits for the next TLS record (`splice_file_to_pipe` in `fs/splice.c`, then
//! `tls_sw_splice_read`), so one silent peer would stall every body spliced to the same pipe. Give each connection its
//! own pipe. A shared one is refused with [`CloseReason::SpliceFdInUse`], and a kTLS splice with no `request_timeout`
//! with [`CloseReason::SpliceUnbounded`].
//!
//! Requires io_uring with multishot accept and direct descriptors, and [`Server::bind`] fails with `ENOSYS`, `EPERM` or
//! `EACCES` where io_uring is unavailable. TCP listeners need socket commands (Linux 6.7), `unix_peercred` needs them
//! on `AF_UNIX` (Linux 6.18.16), and kTLS listeners need `IORING_OP_FIXED_FD_INSTALL` (Linux 6.8), each probed at
//! construction. [`Response::Detach`] needs it too, checked by [`Server::serve_forever`] once a detach handler is
//! installed.
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

// The whole module assumes the 64-bit little-endian kernel ABI (x86_64 / aarch64 - the only TrueNAS targets): SQE/CQE
// field offsets, `__aligned_u64` == `u64`, and the libc `msghdr`/`iovec` layout all depend on it.
#[cfg(not(all(target_pointer_width = "64", target_endian = "little")))]
compile_error!("the net stack requires a 64-bit little-endian target");

pub(crate) mod accept;
mod close;
mod config;
mod handles;
mod io;
mod listen;
mod protocol;
pub(crate) mod spread;
mod wake;

pub use crate::net::core::bodypool::BodyRecycler;
pub use crate::net::core::handles::AcceptDeferral;
pub use crate::net::core::protocol::{
    Body, ClientAddr, CloseReason, Endian, Framing, PeerCred, PrefixWidth, SendBuf, ServerAddr, length_prefix_header,
};
pub use crate::uring::force_async::ForceAsync;
pub use crate::uring::ring::RingFd;
pub use config::{Listen, ServerConfig};
pub use handles::{
    ControlHandle, DeferPermit, Deferred, DetachPermit, Detached, PushHandle, Responder, ServerStats, ShutdownHandle,
    StatsHandle,
};
pub use protocol::{DetachContext, Incoming, Protocol, Request, Response, length_prefixed};
pub use spread::{Spread, physical_cores};

/// Adopt a registered buffer ring, counting a `RLIMIT_MEMLOCK` refusal (`ENOMEM`) in
/// `ServerStats::buf_rings_refused_memlock`. `EINVAL` or `ENOSYS` is a kernel with no provided-buffer rings, whose
/// designed answer is the owned-buffer fallback, so it is not counted.
#[cfg(feature = "net-server")]
fn count_memlock_refusal(
    stats: &crate::net::core::handles::StatsInner,
    r: errno::Result<crate::uring::bufring::BufPool>,
) -> Option<crate::uring::bufring::BufPool> {
    match r {
        Ok(p) => Some(p),
        Err(crate::errno::Errno::ENOMEM) => {
            stats
                .buf_rings_refused_memlock
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            None
        }
        Err(_) => None,
    }
}

/// The internals `fuzz/fuzz_targets/framing_arithmetic.rs` drives, re-exported from `net::core` so the target's path
/// stays with the role whose framer contract it fuzzes. Never part of the stable API, and `__fuzz` is outside both
/// `default` and `full`.
#[cfg(feature = "__fuzz")]
pub mod fuzz {
    pub use crate::net::core::reactor::{FrameStep, frame_step};
}

use crate::errno::{self};
use crate::error::Error;
use crate::net::core::conn::{Op, unpack};
use crate::net::core::handles::HandshakeOutcome;
use crate::net::core::probe::{probe_ktls, probe_tcp_cmd, probe_unix_peercred};
use crate::net::core::reactor::{KernelPads, Reactor};
use crate::net::core::sock;
use crate::sync::Arc;
use crate::uring::engine::Engine;
use crate::uring::sys::*;
use handles::Injected;
use listen::listen_socket;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::sync::mpsc;
use std::time::Duration;

/// Kernel cap on SQ ring entries.
const MAX_RING_ENTRIES: u32 = 32768;
/// Backoff before re-arming a listener's accept after a transient error (resource pressure) - throttles the retry so it
/// can't spin at 100% CPU.
const ACCEPT_RETRY_MS: u64 = 20;

/// How often a ring observes its buffer pools. Pressure arrives on completions but quiet does not, so without this tick
/// a ring gone silent would keep its burst-peak buffers until traffic resumed. Against the body pool's `SHRINK_AFTER`
/// of 4 that is about twenty seconds of silence before the first give-back.
const MAINTAIN_TICK_SECS: u64 = 5;

/// The most bytes one ring's body pool may retain for reuse, a ceiling over its demand-led target. Bounded in bytes
/// rather than buffers, since retained capacity is what costs and a count would let a few maximal bodies keep what many
/// small ones should. Bodies in use are bounded separately, by what a connection admits times the connections mid-body.
const BODY_POOL_BUDGET: usize = 64 * 1024 * 1024;

/// The kTLS handshake handler ([`Server::set_tls_handshake`]), called once per connection on a kTLS listener.
pub(super) type TlsHandshakeFn<U> = Box<dyn FnMut(RawFd, Incoming<'_>, AcceptDeferral<U>)>;

/// The detach handler ([`Server::set_detach_handler`]), called once per detached connection.
pub(super) type DetachFn<U> = Box<dyn FnMut(DetachContext<'_, U>, Detached)>;

/// The consumer's closures and hooks, grouped so a stage can call one while it borrows a different `Server` field.
/// Bound-free like `Server` itself, since bounds here would spread to every impl block, the teardown paths included.
struct Handlers<U, AcceptFn, HeaderFn, BodyFn> {
    accept: AcceptFn,
    header: HeaderFn,
    body: BodyFn,
    /// Required iff any listener is kTLS ([`Server::set_tls_handshake`]).
    tls_handshake: Option<TlsHandshakeFn<U>>,
    /// Required iff a `body` handler ever returns [`Response::Detach`] ([`Server::set_detach_handler`]).
    detach: Option<DetachFn<U>>,
    /// Runs each [`ControlHandle::send`] message on the loop thread ([`Server::set_control_hook`]); without one the
    /// messages are dropped.
    control: Option<ControlFn>,
    /// Runs once for each turn the consumer queued, as the loop reaches it ([`Server::set_held_hook`]).
    held: Option<Box<dyn FnMut()>>,
}

/// The control hook: the message, on the loop thread, nothing else - the state it acts on is whatever it captured when
/// it was built there.
type ControlFn = Box<dyn FnMut(Box<dyn std::any::Any + Send>)>;

/// Work injected by other threads, drained on each wake. Deferred replies, pushes and control messages ride `inject_*`,
/// and kTLS handshake outcomes ride `handshake_*`, typed over `U` and kept apart so [`Injected`] stays non-generic.
struct Mailbox<U> {
    inject_tx: mpsc::Sender<Injected>,
    inject_rx: mpsc::Receiver<Injected>,
    handshake_tx: mpsc::Sender<HandshakeOutcome<U>>,
    handshake_rx: mpsc::Receiver<HandshakeOutcome<U>>,
}

/// One bound listener: its fd, its (resolved) address - handed to the accept handler as the connection's arrival
/// point - and whether its multishot accept is parked on a full pool awaiting a freed slot.
struct Listener {
    fd: OwnedFd,
    addr: ServerAddr,
    awaiting_slot: bool,
    /// A kTLS listener: each accepted connection is furnished a real fd for the consumer's TLS handshake, then served
    /// over the kernel-TLS recv transport (see [`Server::set_tls_handshake`]).
    tls: bool,
}

/// A single-threaded io_uring stream server.
///
/// Parameterized by the per-connection state `U` and the three handler closures (see [`Protocol`]). Holds raw ring
/// pointers, so it is `!Send`/`!Sync`: the ring is owned by exactly one thread (single-ring-per-thread model).
pub struct Server<U, AcceptFn, HeaderFn, BodyFn> {
    // The embedded fs reactor, when `ServerConfig::fs_ops` is set. Declared before `core` so its kernel-visible op
    // buffers drop before the ring is unmapped.
    #[cfg(feature = "uring-fs")]
    fs: Option<crate::uring_fs::core::FsCore>,
    // The engine the server drives. Its own field order (table before ring) keeps its buffers alive until the ring is
    // unmapped, so it drops safely as one unit.
    core: Reactor<U>,
    // The consumer's closures and hooks.
    handlers: Handlers<U, AcceptFn, HeaderFn, BodyFn>,
    listeners: Vec<Listener>,
    // Cross-thread work, delivered by a wake poke and drained in `on_wake`.
    mailbox: Mailbox<U>,
    // Connections whose next body read waits on a free fs op slot, in arrival order. `FileTail::parked` is the dedup
    // key, set on push and cleared on pop, that holds this to one entry per connection.
    #[cfg(feature = "uring-fs")]
    parked_tails: std::collections::VecDeque<(u32, u64)>,
    // Server-only tuning: the pool/listen/socket knobs the engine does not read (the engine-read subset is projected
    // into `core.cfg`).
    cfg: ServerConfig,
}

/// Create the ring a server for `addrs` under `cfg` will run on, without building the server.
///
/// For a process that runs several servers on several threads behind a credential broker. The broker must inherit every
/// ring fd at fork and the fork must precede every thread, while a [`Server`] can only be built on the thread that runs
/// it. So create each ring here, on the main thread, spawn the broker over the [`RingFd`]s, then build each server on
/// its own thread with [`Server::with_ring`]. A process with one server needs none of this; [`Server::with_config`]
/// creates its own ring.
pub fn setup_ring(addrs: impl IntoIterator<Item = impl Into<Listen>>, cfg: &ServerConfig) -> crate::Result<RingFd> {
    let addrs: Vec<Listen> = addrs.into_iter().map(Into::into).collect();
    cfg.validate(&addrs)?;
    Ok(RingFd::setup(ring_entries(cfg, &addrs))?)
}

/// Op-table size for the embedded fs reactor, 0 when disabled. The handler's budget (`fs_ops`) plus one slot per
/// connection for the reply path's body reads. A file tail keeps at most one read in flight (`FileTail::reading`) and
/// connections never exceed `pool_size`, so streaming bodies cannot take the slots handler ops need.
#[cfg(feature = "uring-fs")]
fn fs_op_slots(cfg: &ServerConfig) -> u32 {
    if cfg.fs_ops > 0 {
        cfg.fs_ops.saturating_add(cfg.pool_size)
    } else {
        0
    }
}

/// Submission-queue depth for a server on `addrs` under `cfg`.
fn ring_entries(cfg: &ServerConfig, addrs: &[Listen]) -> u32 {
    // Peak SQEs a connection can hold at once: a recv, a concurrent send (only when pipelining), and a linked timeout
    // on each timed op. Size the ring so a full pool's peak never forces a mid-batch flush (which would also split a
    // linked op+timeout pair).
    let per_conn = (if cfg.max_in_flight_requests > 1 { 2 } else { 1 })
        + u32::from(cfg.idle_timeout.is_some() || cfg.request_timeout.is_some())
        + u32::from(cfg.send_timeout.is_some())
        + u32::from(cfg.tls_handshake_timeout.is_some());
    #[cfg(feature = "uring-fs")]
    let fs_op_slots = fs_op_slots(cfg);
    #[cfg(not(feature = "uring-fs"))]
    let fs_op_slots = 0u32;
    cfg.pool_size
        .saturating_mul(per_conn)
        .saturating_add(1 + addrs.len() as u32)
        .saturating_add(fs_op_slots)
        .next_power_of_two()
        .min(MAX_RING_ENTRIES)
}

impl<U, AcceptFn, HeaderFn, BodyFn> Server<U, AcceptFn, HeaderFn, BodyFn>
where
    AcceptFn: FnMut(Incoming<'_>) -> Option<U>,
    HeaderFn: FnMut(&[u8], &mut U) -> Framing,
    BodyFn: FnMut(Request<'_, U>) -> Response,
{
    /// Bind + listen + set up the ring and pool with the default config.
    ///
    /// `addrs` is one or more listen addresses (any mix of TCP and unix), all served by this one ring/thread; a single
    /// address is `[addr]`. Each item is `impl Into<`[`Listen`]`>` - a bare [`ServerAddr`] is plain, or
    /// [`Listen::tls`]`(addr)` opts that address into kernel TLS (which needs a [`Server::set_tls_handshake`] handler).
    /// Connections from every listener share the pool and all limits.
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
        let ring = RingFd::setup(ring_entries(&cfg, &addrs))?;
        Self::build(addrs, cfg, protocol, ring)
    }

    /// As [`Server::with_config`], on a ring from [`setup_ring`].
    ///
    /// `addrs` and `cfg` must be the ones the ring was set up for. The ring is sized from them, and one too shallow for
    /// this configuration is refused with [`Error::Validation`] rather than run with a queue that forces mid-batch
    /// flushes.
    pub fn with_ring(
        addrs: impl IntoIterator<Item = impl Into<Listen>>,
        cfg: ServerConfig,
        protocol: Protocol<AcceptFn, HeaderFn, BodyFn>,
        ring: RingFd,
    ) -> crate::Result<Self> {
        let addrs: Vec<Listen> = addrs.into_iter().map(Into::into).collect();
        cfg.validate(&addrs)?;
        let need = ring_entries(&cfg, &addrs);
        if ring.sq_entries() < need {
            return Err(Error::Validation(format!(
                "ring has {} submission entries, this configuration needs \
                 {need}",
                ring.sq_entries()
            )));
        }
        Self::build(addrs, cfg, protocol, ring)
    }

    fn build(
        addrs: Vec<Listen>,
        cfg: ServerConfig,
        protocol: Protocol<AcceptFn, HeaderFn, BodyFn>,
        ring: RingFd,
    ) -> crate::Result<Self> {
        // FS ops submit on raw fds, not the registered table, so the pool holds only the `pool_size` connection slots.
        let mut engine = Engine::on_ring(ring, cfg.pool_size)?;
        if let Some(workers) = cfg.iowq_bounded_workers {
            engine.ring.bound_iowq_workers(workers)?;
        }

        // Fail before binding on a kernel that cannot serve the per-connection peer fetches, which would otherwise shed
        // every connection at accept.
        if cfg.unix_peercred && addrs.iter().any(|l| matches!(l.addr, ServerAddr::Unix(_))) {
            probe_unix_peercred(&mut engine.ring)?;
        }
        if addrs
            .iter()
            .any(|l| matches!(l.addr, ServerAddr::Tcp(_) | ServerAddr::Tcp6(_)))
        {
            probe_tcp_cmd(&mut engine.ring)?;
        }
        if addrs.iter().any(|l| l.tls) {
            probe_ktls()?;
        }
        // Detach needs `FIXED_FD_INSTALL` as well, but its handler is installed after construction, so `serve_forever`
        // checks it.
        if !engine.fixed_fd_install && addrs.iter().any(|l| l.tls) {
            return Err(Error::Validation(
                "kTLS listeners require IORING_OP_FIXED_FD_INSTALL \
                 (Linux >= 6.8); this kernel's io_uring does not support it"
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
            // A cast past `i64::MAX` wraps negative, the kernel refuses a negative `tv_sec`, and a `LINK_TIMEOUT` that
            // fails prep takes its linked op down with it, so an unclamped "never" would close every connection at its
            // first parked read.
            tv_sec: d.as_secs().min(i64::MAX as u64) as i64,
            tv_nsec: d.subsec_nanos() as i64,
        };
        let pads = Box::new(KernelPads {
            deadline: KernelTimespec::default(),
            accept_retry: ts_of(Duration::from_millis(ACCEPT_RETRY_MS)),
            idle_timeout: cfg.idle_timeout.map(ts_of).unwrap_or_default(),
            send_timeout: cfg.send_timeout.map(ts_of).unwrap_or_default(),
            request_timeout: cfg.request_timeout.map(ts_of).unwrap_or_default(),
            max_receipt_time: cfg.max_receipt_time.map(ts_of).unwrap_or_default(),
            tls_handshake: cfg.tls_handshake_timeout.map(ts_of).unwrap_or_default(),
            recv_retry: cfg.recv_shortage_retry.map(ts_of).unwrap_or_default(),
            maintain: ts_of(Duration::from_secs(MAINTAIN_TICK_SECS)),
        });

        let (inject_tx, inject_rx) = mpsc::channel();
        let (handshake_tx, handshake_rx) = mpsc::channel();

        #[cfg(feature = "uring-fs")]
        let fs = (cfg.fs_ops > 0).then(|| {
            // FS ops submit on raw fds, never `IOSQE_FIXED_FILE`, so this sizes the op table alone and nothing here
            // bounds open files.
            crate::uring_fs::core::FsCore::new(
                fs_op_slots(&cfg),
                crate::uring_fs::OffloadBounds {
                    floor: cfg.fs_offload_floor,
                    ceiling: cfg.fs_offload_ceiling,
                },
            )
        });
        #[cfg(feature = "uring-fs")]
        let fs = fs.map(|mut fs| {
            // One timer per request in flight is the consumer discipline, so the cap follows the knob that bounds
            // requests in flight.
            fs.set_timer_cap(u32::try_from(cfg.max_in_flight_requests).unwrap_or(u32::MAX));
            // The file half of `ServerConfig::force_async`. The core reads only `READ` and `WRITE` from it; passing the
            // whole set keeps one knob rather than two halves that can drift.
            fs.set_force_async(cfg.force_async);
            fs.set_lookup_bounds(crate::uring_fs::OffloadBounds {
                floor: cfg.lookup_offload_floor,
                ceiling: cfg.lookup_offload_ceiling,
            });
            fs
        });
        let mut core = Reactor::from_parts(engine, cfg.pool_size, cfg.to_core(), pads);
        // The drain waits on tasks too; see `maybe_finish_drain`.
        #[cfg(feature = "uring-fs")]
        if let Some(fs) = fs.as_ref() {
            core.pending_tasks = fs.task_gauge();
        }
        let mut body_pool = crate::net::core::bodypool::BodyPool::new(BODY_POOL_BUDGET, cfg.held_cap);
        body_pool.count_handed(Arc::clone(&core.engine.shared));
        core.body_pool = Some(std::rc::Rc::new(std::cell::RefCell::new(body_pool)));
        // Registering a buffer ring is best effort. A kernel or sandbox that refuses one gets connections that own
        // their receive buffers, the same fallback a dry pool takes, and `count_memlock_refusal` counts the refusal an
        // operator can act on.
        let sizing = crate::uring::bufring::PoolSizing {
            initial_bytes: cfg.buf_pool_initial_bytes,
            max_step_bytes: cfg.buf_pool_max_step_bytes,
            max_bytes: cfg.buf_pool_max_bytes,
        };
        if cfg.recv_pool {
            // Per connection: the handler's claims plus the message arriving.
            let r = crate::uring::bufring::BufPool::new(
                core.engine.ring.raw_fd(),
                crate::uring::bufring::BGID_RECV,
                crate::net::core::reactor::recv_pool_buf_len(cfg.recv_buffer_bytes, cfg.max_request_bytes),
                crate::uring::bufring::ring_entries(
                    cfg.pool_size.saturating_mul(cfg.recv_lease_depth.saturating_add(1)),
                ),
                sizing,
            );
            core.recv_bufs = count_memlock_refusal(&core.stats, r);
        }
        #[cfg(feature = "uring-fs")]
        if cfg.fs_ops > 0 && cfg.fs_body_pool {
            let r = crate::uring::bufring::BufPool::new(
                core.engine.ring.raw_fd(),
                crate::uring::bufring::BGID_FILE_BODY,
                cfg.fs_body_chunk,
                crate::uring::bufring::ring_entries(
                    cfg.pool_size
                        .saturating_mul(u32::from(crate::net::core::conn::FILE_TAIL_BUFS)),
                ),
                sizing,
            );
            core.body_bufs = count_memlock_refusal(&core.stats, r);
        }
        // Publish the starting budget, not zero until a buffer moves.
        core.sync_recv_buf_stats();
        // Only a server with an fs pool sweeps closed connections; tell the shared reactor so `close_conn` records into
        // `fs_closed` here and not on a client (which would never drain it).
        #[cfg(feature = "uring-fs")]
        {
            core.has_fs_pool = cfg.fs_ops > 0;
        }
        Ok(Server {
            #[cfg(feature = "uring-fs")]
            fs,
            #[cfg(feature = "uring-fs")]
            parked_tails: std::collections::VecDeque::new(),
            core,
            handlers: Handlers {
                accept: protocol.accept,
                header: protocol.header,
                body: protocol.body,
                tls_handshake: None,
                detach: None,
                control: None,
                held: None,
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

    /// Run the event loop until a [`ShutdownHandle`] stops it or a fatal ring error occurs. In-flight operations are
    /// drained before returning.
    ///
    /// Call at most once, even after an error: the arming below is not idempotent (a second wake `READ` into the shared
    /// buffer, a second maintenance timer, duplicate multishot accepts).
    pub fn serve_forever(&mut self) -> crate::Result<()> {
        if self.listeners.iter().any(|l| l.tls) && self.handlers.tls_handshake.is_none() {
            return Err(Error::Validation(
                "a kTLS listener requires Server::set_tls_handshake".into(),
            ));
        }
        // A detach handler means `Response::Detach` is on the table, and each detach needs `IORING_OP_FIXED_FD_INSTALL`
        // (Linux >= 6.8; probed at construction). Fail here with a clear error instead of closing every detached
        // connection with a mysterious EINVAL at runtime.
        if self.handlers.detach.is_some() && !self.core.engine.fixed_fd_install {
            return Err(Error::Validation(
                "Response::Detach requires IORING_OP_FIXED_FD_INSTALL \
                 (Linux >= 6.8); this kernel's io_uring does not support it"
                    .into(),
            ));
        }
        self.core.arm_wake()?;
        self.core.engine.shared.wake.activate();
        self.submit_maintain()?;
        for lidx in 0..self.listeners.len() as u32 {
            self.arm_accept(lidx)?;
        }
        let run = self.run_loop();
        // Deliver what the stop window left queued before the reap, while the ring is still whole - the same gap the
        // standalone host closes (`uring_fs::core::drain_stop_window`).
        #[cfg(feature = "uring-fs")]
        if let Some(fs) = self.fs.as_mut() {
            crate::uring_fs::core::drain_stop_window(fs, &mut self.core.engine);
        }
        // fs ops ride this ring too, and this drain does not dispatch, so route their completions to the fs core as
        // they are reaped: an `openat2` finishing here carries a real process fd in `cqe.res` that nothing else will
        // ever own. The standalone fs host does the same (`uring_fs::host`'s `drain_or_leak`).
        #[cfg(feature = "uring-fs")]
        let drained = {
            let fs = &mut self.fs;
            self.core.cancel_and_reap_all(&mut |cqe| {
                if let Some(fs) = fs.as_mut() {
                    fs.on_drain_cqe(cqe);
                }
            })
        };
        #[cfg(not(feature = "uring-fs"))]
        let drained = self.core.cancel_and_reap_all(&mut |_| {});
        run?;
        drained?;
        Ok(())
    }

    fn run_loop(&mut self) -> errno::Result<()> {
        while !self.core.stopping() {
            if self.core.engine.inflight == 0 {
                break; // nothing outstanding; avoid blocking forever
            }
            // `submit_and_wait` waits, and flushes a CQ overflow backlog, only once the SQ is empty, since a short
            // submit skips the whole GETEVENTS block (`io_uring/io_uring.c`). The `Drain` arm does not wait, so it
            // flushes the overflow itself.
            //
            // Wake the offload pool for what this turn queued and bound the sleep by its next deadline
            // (`FsCore::flush_offloads`). A poke that landed while the loop was awake wrote no eventfd and is drained
            // by the `Drain` arm (`WakeHandle::park`).
            #[cfg(feature = "uring-fs")]
            let recheck = self.fs.as_mut().and_then(|fs| fs.flush_offloads());
            #[cfg(not(feature = "uring-fs"))]
            let recheck = None;
            match self.core.engine.shared.wake.park() {
                crate::uring::wake::Park::Block => {
                    let waited = self.core.engine.ring.submit_and_wait_for(1, recheck);
                    self.core.engine.shared.wake.unpark();
                    waited?;
                }
                crate::uring::wake::Park::Drain => {
                    self.drain_wake_sources()?;
                    self.core.engine.submit_and_flush_overflow()?;
                }
            }
            while let Some(cqe) = self.core.engine.ring.reap() {
                self.dispatch(cqe)?;
                // A slot freed during this dispatch (`Reactor::reclaim_slot` raised the flag): re-arm any listener
                // parked on a full pool. Kept out of the core reclaim so the drain path (`cancel_and_reap_all`, which
                // never drains this flag) can't re-arm accepts while tearing down.
                if self.core.take_pool_freed() {
                    self.rearm_parked_accepts()?;
                }
            }
            // Reap loop drained: sweep the fs files any connection that closed during it left open (batched here so it
            // runs after every fs completion for those connections has been routed).
            #[cfg(feature = "uring-fs")]
            self.sweep_closed_fs();
            // What this turn gave back may let what the cap holds back go on, the reads and the consumer's turns, in
            // the order they came.
            self.redrive_held_reads()?;
            // A drain's quiescence, re-read where everything that can reach it has already run. `reclaim_slot` is
            // edge-triggered on connections and cannot see a task retire; see `maybe_finish_drain`. Inert unless
            // draining.
            self.core.maybe_finish_drain();
        }
        Ok(())
    }

    /// Reclaim the fs fds still held by connections that closed since the last sweep. Fire-and-forget:
    /// `cancel_owned_by` cancels each closed connection's in-flight fs ops, so their parked `Arc<OwnedFd>`s drop on the
    /// resulting CQEs and the fds close (close-last) - a handler that opened a file without closing it, or a connection
    /// that died mid-chain, can't pin an fd until server teardown.
    #[cfg(feature = "uring-fs")]
    fn sweep_closed_fs(&mut self) {
        if self.core.fs_closed.is_empty() {
            return;
        }
        let owners: Vec<(u32, u64)> = std::mem::take(&mut self.core.fs_closed);
        if let Some(fs) = self.fs.as_mut() {
            // One call, not one per owner: the scan walks the whole op table and the batch shares it.
            fs.cancel_owned_by(&mut self.core.engine, owners);
        }
    }

    fn dispatch(&mut self, cqe: IoUringCqe) -> errno::Result<()> {
        let (op, slot, generation) = unpack(cqe.user_data);
        // Retire the CQE before its handler runs. The arms below `?`-propagate, and a skipped decrement would leave
        // `cancel_and_reap_all` waiting forever, a hang in `serve_forever` and `Drop`.
        self.core.engine.retire(&cqe);
        // fs-domain completions belong to the embedded fs reactor. Route them before the stream `match`, whose
        // unknown-tag arm would swallow them.
        #[cfg(feature = "uring-fs")]
        if cqe.user_data as u8 & crate::uring::user_data::TAG_FS_DOMAIN != 0 {
            use crate::uring_fs::core::ReapedFs;
            let Some(fs) = self.fs.as_mut() else {
                return Ok(());
            };
            let (tag, fslot, fgen) = crate::uring::user_data::unpack_raw(cqe.user_data);
            let reaped = fs.on_cqe(&mut self.core.engine, tag, fslot, fgen, cqe.res);
            // Offer the slot `on_cqe` just freed to the longest-waiting parked body read before this completion's
            // continuation can take it, or a streaming connection would recycle the slot while a parked one never
            // advanced. Handler ops keep their `fs_ops` slots (see `fs_op_slots`).
            self.redrive_parked_tail()?;
            match reaped {
                // A reply-path pump read: routed here rather than through a callback, so the tail advances with the
                // whole loop in hand.
                ReapedFs::Pump(done, owner) => {
                    // The buffer the kernel picked, if this read selected one. Read here rather than inside `on_cqe`
                    // because this is where the CQE still is - the fs core routes by tag and never sees the flags.
                    let bid = if cqe.flags & crate::uring::sys::IORING_CQE_F_BUFFER != 0 {
                        Some((cqe.flags >> crate::uring::sys::IORING_CQE_BUFFER_SHIFT) as u16)
                    } else {
                        None
                    };
                    self.on_pump_read(owner, done, bid)?;
                }
                // A continuation facade, for an owner that may already be gone: a file it opens is its own to close,
                // since nothing sweeps one opened after the connection did.
                mut reaped => {
                    // A leased write's buffer comes back to the pool here, before the callback runs: the op is over
                    // whatever the connection did in the meantime, and the pool - which only this dispatch can reach -
                    // is the one owner left.
                    if let crate::uring_fs::core::ReapedFs::Embedded(_, done, _) = &mut reaped {
                        let first = done.take_recv_lease();
                        let more = done.take_recv_lease_more();
                        if first.is_some() || !more.is_empty() {
                            if let Some(pool) = self.core.recv_bufs.as_mut() {
                                for bid in first.into_iter().chain(more) {
                                    pool.release(bid);
                                }
                            }
                            self.core.sync_recv_buf_stats();
                        }
                    }
                    if let Some(fs) = self.fs.as_mut() {
                        crate::uring_fs::core::deliver_embedded(fs, &mut self.core.engine, reaped);
                    }
                }
            }
            return Ok(());
        }
        match op {
            // For accept ops the slot field carries the listener index.
            Some(Op::Accept) => self.on_accept(slot, &cqe)?,
            Some(Op::Wake) => self.on_wake()?,
            Some(op @ (Op::RecvHeader | Op::RecvBody)) => self.on_recv(slot, generation, cqe.res, cqe.flags, op)?,
            // A framed body finished splicing straight to a consumer fd;
            // `cqe.res` is bytes moved (or `<= 0` on EOF/cancel/error/`EAGAIN`).
            Some(Op::SpliceRecv) => self.on_splice_recv(slot, generation, cqe.res)?,
            // A splice-readiness poll fired: the socket is readable again after a splice hit `-EAGAIN`; resubmit the
            // splice for the remainder.
            Some(Op::SplicePoll) => self.core.on_splice_poll(slot, generation, cqe.res)?,
            Some(Op::Send) => self.on_send(slot, generation, cqe.res)?,
            Some(Op::Close) => self.core.on_closed(slot)?,
            // The graceful-shutdown grace period expired (or the op was cancelled at teardown): if still draining,
            // escalate to a hard stop - `serve_forever`'s drain cancels whatever remains.
            Some(Op::Deadline) => {
                if self.core.draining && !self.core.stopping() {
                    self.core.engine.shared.request_stop();
                }
            }
            // A peer-identity fetch - the slot's PendingPeer pad says which.
            Some(Op::Cred | Op::Peername) => self.on_peer_fetch(slot, generation, cqe.res)?,
            // A pre-close SHUTDOWN completed; submit the CLOSE that frees the slot. (Its result is irrelevant - see
            // `on_shutdown`.)
            Some(Op::Shutdown) => self.core.on_shutdown(slot, generation)?,
            // A furnished-fd install for a kTLS connection completed; `cqe.res` is the new real fd (or `-errno`).
            Some(Op::FdInstall) => self.on_fd_install(slot, generation, cqe.res)?,
            // A detach fd-install completed; `cqe.res` is the furnished real fd (or `-errno`). Hand it to the detach
            // handler and park, or close.
            Some(Op::DetachInstall) => self.on_detach_install(slot, generation, cqe.res)?,
            // Accept-retry backoff elapsed (or was cancelled at shutdown): the slot field is the listener index. Re-arm
            // its accept unless shutting down.
            Some(Op::AcceptRetry) => {
                if !self.core.stopping() && !self.core.draining {
                    self.arm_accept(slot)?;
                }
            }
            // The maintenance tick: the one observation quiet pools get. Pressure rides completions; silence rides
            // this.
            Some(Op::Maintain) => {
                if let Some(p) = self.core.recv_bufs.as_mut() {
                    p.rebalance();
                }
                #[cfg(feature = "uring-fs")]
                if let Some(p) = self.core.body_bufs.as_mut() {
                    p.rebalance();
                }
                if let Some(p) = self.core.body_pool.as_ref() {
                    p.borrow_mut().rebalance();
                }
                if !self.core.stopping() {
                    self.submit_maintain()?;
                }
            }
            // A parked kTLS handshake's timeout fired (or was cancelled on resolve): shed the slot if it is still
            // parked.
            Some(Op::HandshakeTimeout) => self.on_handshake_timeout(slot, generation)?,
            // A recv's linked idle/request clock: pairs with its recv CQE to disambiguate a cancelled-with-progress
            // short read from a peer FIN mid-frame (`on_recv_clock`). Like `LinkTimeout`, not counted in `conn.ops`.
            Some(Op::RecvClock) => self.core.on_recv_clock(slot, generation, cqe.res)?,
            Some(Op::LinkTimeout) => {}
            // A kTLS body-splice inactivity watchdog fired or was cancelled.
            Some(Op::SpliceDeadline) => self.core.on_splice_deadline(slot, generation, cqe.res)?,
            // A parked read's pool-shortage backoff elapsed. Re-pump the connection unless something else got there
            // first.
            Some(Op::RecvRetry) => self.on_recv_retry(slot, generation)?,
            // The total-receipt budget for the message in flight elapsed (or its retire-cancel completed).
            Some(Op::ReceiptDeadline) => self.core.on_receipt_deadline(slot, generation, cqe.res)?,
            // Our hand-off to another ring of the spread completed. The generation field carries the listener index.
            Some(Op::Handoff) => self.on_handoff(slot, generation, cqe.res)?,
            // Another ring of the spread sent a connection; the slot field carries the listener index and `res` the
            // slot it arrived in.
            Some(Op::Handed) => self.on_handed(slot, cqe.res)?,
            Some(Op::Connect) => unreachable!("server never connects"),
            Some(Op::Cancel) | None => {}
        }
        Ok(())
    }
}

// Methods that touch none of the handler closures - usable from `Drop`.
impl<U, AcceptFn, HeaderFn, BodyFn> Server<U, AcceptFn, HeaderFn, BodyFn> {
    /// The bound addresses, in the order given to [`Server::bind`] (ephemeral `:0` TCP ports come back resolved).
    pub fn local_addrs(&self) -> Vec<ServerAddr> {
        self.listeners.iter().map(|l| l.addr.clone()).collect()
    }

    /// The consumer's end of the body-storage loop: recycle a delivered body's `Vec` so the next placed or promoted
    /// body on this ring reuses it instead of allocating. `!Send` by construction - it belongs to this ring's thread,
    /// like the server itself once serving.
    pub fn body_recycler(&self) -> Option<BodyRecycler> {
        self.core
            .body_pool
            .as_ref()
            .map(|p| crate::net::core::bodypool::BodyRecycler::new(p.clone()))
    }

    /// Take `place` in `spread`, the set of servers on this port, one per ring. From then on a TCP connection this
    /// server accepts while another ring of the spread holds fewer goes to that ring, and this ring serves the ones
    /// sent to it. Connections are counted from their accept to their slot's release, ties stay where they were
    /// accepted, and a ring that drains or drops takes no more.
    ///
    /// Every server of a spread binds the same addresses in the same order, with
    /// [`reuse_port`](ServerConfig::reuse_port), since a connection keeps its listener's index when it moves. A server
    /// on other addresses, a place out of range or one already taken is refused with [`Error::Validation`]. Join before
    /// [`Server::serve_forever`], so the first connections are counted too.
    pub fn join_spread(&mut self, spread: &Spread, place: usize) -> crate::Result<()> {
        if self.core.spread.is_some() {
            return Err(Error::Validation("this server is in a spread already".into()));
        }
        let taken = self.core.table.active();
        spread.join(place, self.core.engine.ring.raw_fd(), self.local_addrs(), taken)?;
        self.core.spread = Some(spread::Joined::new(spread.clone(), place, taken));
        Ok(())
    }

    /// A `Send + Sync` handle that stops [`Server::serve_forever`] from another thread. Obtain it before calling
    /// `serve_forever`.
    pub fn shutdown_handle(&self) -> ShutdownHandle {
        ShutdownHandle {
            shared: Arc::clone(&self.core.engine.shared),
        }
    }

    /// A `Clone + Send + Sync` handle for running the control hook on this server's thread from any other
    /// ([`ControlHandle::send`]). Take it before [`Server::serve_forever`], like [`Server::shutdown_handle`].
    pub fn control_handle(&self) -> ControlHandle {
        ControlHandle {
            tx: self.mailbox.inject_tx.clone(),
            shared: Arc::clone(&self.core.engine.shared),
        }
    }

    /// A `Clone + Send + Sync` handle for reading this server's counters from any thread while it runs (see
    /// [`ServerStats`]).
    pub fn stats_handle(&self) -> StatsHandle {
        StatsHandle {
            inner: Arc::clone(&self.core.stats),
        }
    }

    /// Register the calling process's **current** credentials as a [`Personality`](crate::uring_fs::Personality) on
    /// this server's ring -- the identity a [`Request`]`::fs` op runs as.
    ///
    /// Unprivileged (registering your own creds needs no capability); the snapshot is frozen at this call. Only
    /// meaningful with an fs pool (`ServerConfig::fs_ops`); ids come from a credential broker for acting as
    /// authenticated peers (see [`CredBroker`](crate::uring_fs::CredBroker), which also registers on this ring).
    /// Requires the `uring-fs` feature.
    #[cfg(feature = "uring-fs")]
    pub fn register_self(&self) -> crate::Result<crate::uring_fs::Personality> {
        let id = crate::uring::sys::register_personality(self.core.engine.ring.raw_fd())?;
        crate::uring_fs::Personality::from_raw(id).ok_or_else(|| crate::Error::from(errno::Errno::EINVAL))
    }

    /// Declare which extended attributes this server's embedded fs reactor writes under its **own ambient credentials**
    /// rather than a request's [`Personality`](crate::uring_fs::Personality) - the allowlist behind the
    /// [`FsConn::fsetxattr`](crate::uring_fs::FsConn::fsetxattr) promotion and the whole of
    /// [`FsConn::fremovexattr`](crate::uring_fs::FsConn::fremovexattr). See
    /// [`PrivilegedXattrs`](crate::uring_fs::PrivilegedXattrs) for the rules (prefixes must sit under `trusted.`) and
    /// the reasoning.
    ///
    /// Setup time only, since [`Server::serve_forever`] borrows `&mut self` for the life of the loop. Replaces any
    /// previous policy, and the default permits nothing. Inert on a server with no fs pool ([`ServerConfig::fs_ops`] of
    /// 0).
    #[cfg(feature = "uring-fs")]
    pub fn set_privileged_xattrs(&mut self, policy: crate::uring_fs::PrivilegedXattrs) {
        if let Some(fs) = self.fs.as_mut() {
            fs.set_privileged_xattrs(policy);
        }
    }

    /// Install the hook that receives every [`ControlHandle::send`] message, on the loop thread, between two batches of
    /// completions. Built here, before serving, it can share state with the protocol handlers (an `Rc` both captured)
    /// and swap it in place; the message it is handed is the `Send` part, which it downcasts. A message arriving with
    /// no hook installed is dropped.
    pub fn set_control_hook<F>(&mut self, hook: F)
    where
        F: FnMut(Box<dyn std::any::Any + Send>) + 'static,
    {
        self.handlers.control = Some(Box::new(hook));
    }

    /// Install a hook that runs on the loop thread once for each turn the consumer queues with
    /// [`BodyRecycler::queue_turn`], as the loop reaches the turn with [`BodyRecycler::held`] under
    /// [`held_cap`](ServerConfig::held_cap). Turns and the reads the cap holds back go on in one queue in the order
    /// they came, so a call held for bytes goes on with no tick and no poll, even when every connection waits, and
    /// neither kind keeps the other back for good. The hook never runs inside [`BodyRecycler::queue_turn`] or any other
    /// call of the consumer's. What it takes out ([`BodyRecycler::take_out`]) counts before the next thing held back is
    /// looked at, so what is held back passes the cap by one at most. A turn whose call the consumer no longer has runs
    /// it with nothing to let go. A second call replaces the first hook.
    pub fn set_held_hook<F>(&mut self, hook: F)
    where
        F: FnMut() + 'static,
    {
        self.handlers.held = Some(Box::new(hook));
    }

    /// Install a hook invoked once per connection as it begins closing:
    /// `(peer, reason, &mut state)` - for logging/metrics; the state is dropped with the connection shortly after.
    /// Connections that never passed `accept` (rejected, load-shed, or arriving mid-shutdown) have no state and are not
    /// reported.
    pub fn set_close_hook<F>(&mut self, hook: F)
    where
        F: FnMut(&ClientAddr, CloseReason, &mut U) + 'static,
    {
        self.core.on_close = Some(Box::new(hook));
    }

    /// Install the kernel-TLS handshake handler, required when any listener is [`Listen::tls`]. It is called once per
    /// accepted kTLS connection with a real socket fd, the [`Incoming`] context and an [`AcceptDeferral`]. The `accept`
    /// handler does not run for kTLS connections, so per-listener admission happens here and [`AcceptDeferral::ready`]
    /// is the admission. Move the fd and the deferral to your own worker, never blocking the ring thread, run the
    /// handshake there so it installs kTLS on the socket, then call [`AcceptDeferral::ready`] with the connection state
    /// or [`AcceptDeferral::reject`]. `ready` sheds a connection whose two TLS directions do not both hold kernel keys,
    /// so a failed kTLS install is never served in the clear. Close the furnished fd once the handshake is done, since
    /// the connection is served over the pool descriptor. `U` must be `Send`, since it crosses back from the worker.
    pub fn set_tls_handshake<F>(&mut self, handler: F)
    where
        F: FnMut(RawFd, Incoming<'_>, AcceptDeferral<U>) + 'static,
    {
        self.handlers.tls_handshake = Some(Box::new(handler));
    }

    /// Install the handler a break of a file lease this server's ring holds reaches, once for each break, with the
    /// lease and a facade on the ring that no connection owns
    /// ([`FsConn::file_lease`](crate::uring_fs::FsConn::file_lease)). A ring with no handler takes no lease, since its
    /// breaks would go unheard. Give the lease back
    /// ([`FsConn::release_file_lease`](crate::uring_fs::FsConn::release_file_lease)) once what it guards is done, since
    /// whoever broke it waits on it for up to `/proc/sys/fs/lease-break-time` seconds. A server with no fs reactor
    /// (`fs_ops` of 0) takes no lease, and drops the handler.
    #[cfg(feature = "uring-fs")]
    pub fn set_file_lease_break_handler<F>(&mut self, handler: F)
    where
        F: FnMut(crate::uring_fs::file_lease::FileLeaseId, &mut crate::uring_fs::FsConn<'_>) + 'static,
    {
        if let Some(fs) = self.fs.as_mut() {
            fs.file_leases.set_handler(Box::new(handler));
        }
    }

    /// Install the **detach** handler, required when a `body` handler ever returns [`Response::Detach`]. Called once
    /// per detached connection with `(context, detached)`: the [`DetachContext`] (peer + `&mut state`, where the body
    /// handler stashed the job) and a [`Detached`] handle owning a real socket fd (materialized from the pool
    /// descriptor, aliasing it). Move the [`Detached`] to your own worker (never block the ring thread), do the
    /// blocking work on [`Detached::raw_fd`] (e.g. `lzc_send`/`lzc_receive`), then call [`Detached::resume`] to keep
    /// serving or [`Detached::close`]. The connection is parked until then; a dropped handle closes it.
    pub fn set_detach_handler<F>(&mut self, handler: F)
    where
        F: FnMut(DetachContext<'_, U>, Detached) + 'static,
    {
        self.handlers.detach = Some(Box::new(handler));
    }
}

// A server with an fs pool can act as authenticated peers: the credential broker registers personalities on its ring.
// The ring exists before the broker forks and the fork precedes every thread (as for `UringFs`), so a server built on
// main passes itself here; a server that will run on its own thread passes the `RingFd` from `setup_ring` instead.
#[cfg(feature = "uring-fs")]
impl<U, AcceptFn, HeaderFn, BodyFn> crate::uring_fs::BrokerReactor for Server<U, AcceptFn, HeaderFn, BodyFn> {
    fn broker_ring_fd(&self) -> RawFd {
        self.core.engine.ring.raw_fd()
    }
}

impl<U, AcceptFn, HeaderFn, BodyFn> Drop for Server<U, AcceptFn, HeaderFn, BodyFn> {
    fn drop(&mut self) {
        // No ring of the spread sends here from now on. A send another ring chose before it saw this lands in a table
        // no one reads, and that socket stays open until the spread, which holds a copy of this ring's descriptor, is
        // dropped.
        if let Some(joined) = self.core.spread.as_mut() {
            joined.close();
        }
        // If `serve_forever` ran it already drained (no-op here); otherwise (early drop / panic unwind) ensure no op is
        // in flight before the buffers and ring are freed - and if that drain fails, leak the buffers rather than free
        // them under a still-live op.
        #[cfg(feature = "uring-fs")]
        let leaked = {
            let fs = &mut self.fs;
            self.core.drain_or_leak(&mut |cqe| {
                if let Some(fs) = fs.as_mut() {
                    fs.on_drain_cqe(cqe);
                }
            })
        };
        #[cfg(not(feature = "uring-fs"))]
        let leaked = self.core.drain_or_leak(&mut |_| {});
        // fs ops share this ring; on a failed drain they may still be in flight, so leak the fs op buffers alongside
        // the connection buffers rather than free memory the kernel might yet write into.
        #[cfg(feature = "uring-fs")]
        if leaked && let Some(fs) = self.fs.as_mut() {
            fs.leak();
        }
        let _ = leaked;
    }
}

impl<U, AcceptFn, HeaderFn, BodyFn> std::fmt::Debug for Server<U, AcceptFn, HeaderFn, BodyFn> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Server")
            .field("addrs", &self.local_addrs())
            .field("cfg", &self.cfg)
            .field("inflight", &self.core.engine.inflight)
            .field("ring", &self.core.engine.ring)
            .finish_non_exhaustive()
    }
}

#[cfg(all(test, not(loom)))]
mod iowq_tests {
    use super::*;

    /// The bounds of bounded and unbounded io-wq work that the thread which built a server over TCP holds once it is
    /// built, read by registering zeros. The TCP probe of `build` submits on the ring, so the thread's io-wq exists by
    /// then.
    fn built_with(workers: Option<u32>) -> Option<([u32; 2], u32)> {
        std::thread::spawn(move || {
            let addrs: Vec<Listen> = vec![ServerAddr::Tcp("127.0.0.1:0".parse().unwrap()).into()];
            let cfg = ServerConfig {
                iowq_bounded_workers: workers,
                ..ServerConfig::default()
            };
            let entries = ring_entries(&cfg, &addrs).next_power_of_two();
            let protocol = Protocol {
                accept: |_: Incoming<'_>| Some(()),
                header: length_prefix_header::<()>(PrefixWidth::U32, Endian::Big, false),
                body: |_: Request<'_, ()>| Response::Close,
            };
            let server = match Server::with_config(addrs, cfg, protocol) {
                Ok(server) => server,
                Err(Error::Errno(e)) if crate::uring::setup_unavailable(e) => {
                    return None;
                }
                Err(e) => panic!("Server::with_config: {e}"),
            };
            let held = server.core.engine.ring.bound_iowq_workers(0);
            Some((held.expect("the bounds read back"), entries))
        })
        .join()
        .expect("the thread that built the server")
    }

    /// A server built with a bound runs its thread's io-wq with it, and one built without keeps the kernel's own, the
    /// lesser of the ring's submission entries and four for each CPU (`io_init_wq_offload`, `io_uring/tctx.c`).
    /// Registering zeros to read them changes nothing.
    #[test]
    fn a_server_bounds_its_threads_io_wq_workers() {
        let Some(([bounded, _], _)) = built_with(Some(3)) else {
            return;
        };
        assert_eq!(bounded, 3, "the bound the server was built with");
        let Some(([bounded, _], entries)) = built_with(None) else {
            return;
        };
        // SAFETY: sysconf reads a value and touches no memory of ours.
        let online = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
        let kernel = entries.min(4 * online as u32);
        assert_eq!(bounded, kernel, "the kernel's own bound");
    }
}
