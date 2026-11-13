//! `net::client` - the outbound stream client role on the shared reactor core.
//!
//! A [`Client`] embeds the shared reactor core (the same io_uring engine the server drives) and adds outbound
//! connection establishment, a framed request/reply data plane, and a caller-driven event pump. Like the server it is
//! `!Send` (one ring, one thread) and caller-driven: [`Client::next_event`] pumps the ring and *returns* completions
//! rather than invoking callbacks. The framing, zero-copy, timeout and teardown machinery all live in the reactor core.

mod config;
mod connect;
mod event;
mod io;
mod tls;

pub use config::ClientConfig;
pub use event::{ConnId, ConnectOpts, Event, RequestId};
pub use tls::{ConnectDeferral, TlsConnectContext};

// Named by the `setup_ring` -> `CredBroker::spawn` -> `with_ring` recipe.
pub use crate::uring::personality::Personality;
pub use crate::uring::ring::RingFd;

use crate::error::Error;
use crate::net::core::conn::{Op, unpack};
use crate::net::core::probe::probe_ktls;
use crate::net::core::protocol::{CloseReason, Framing};
use crate::net::core::reactor::{KernelPads, Reactor};
use crate::uring::engine::Engine;
use crate::uring::sys::*;
use io::PendingSplice;
use std::collections::{HashMap, VecDeque};
use std::os::fd::RawFd;
use std::sync::mpsc;
use tls::{HandshakeResult, TlsConnectFn};

/// Kernel cap on SQ ring entries.
const MAX_RING_ENTRIES: u32 = 32768;

/// Submission-queue depth for a client under `config`.
fn ring_entries(config: &ClientConfig) -> u32 {
    // Peak SQEs a connection holds at once. A full pool's peak must never force a mid-batch flush, which would split a
    // linked op and timeout pair.
    let per_conn = (if config.max_in_flight > 1 { 2 } else { 1 })
        + u32::from(config.idle_timeout.is_some() || config.response_timeout.is_some())
        + u32::from(config.send_timeout.is_some())
        + u32::from(config.connect_timeout.is_some())
        + u32::from(config.tls_handshake_timeout.is_some());
    config
        .pool_size
        .saturating_mul(per_conn)
        .saturating_add(2)
        .next_power_of_two()
        .min(MAX_RING_ENTRIES)
}

/// Create the ring a client under `config` will run on, without building the client.
///
/// For a process that dials as minted identities. The credential broker must inherit every ring fd at a fork that
/// precedes every thread, while a [`Client`] is built on the thread that runs it. So create the ring here on the main
/// thread, spawn the broker over the [`RingFd`], then build the client on its own thread with [`Client::with_ring`] and
/// dial with [`ConnectOpts::personality`].
pub fn setup_ring(config: &ClientConfig) -> crate::Result<RingFd> {
    config.validate()?;
    Ok(RingFd::setup(ring_entries(config))?)
}

/// A single-threaded io_uring stream client.
///
/// Parameterized by the per-connection state `U` and the framer `F`, which frames the next reply from the bytes
/// accumulated so far (see [`Framing`]). Holds the ring, so it is `!Send`/`!Sync`.
pub struct Client<U, F>
where
    F: FnMut(&[u8], &mut U) -> Framing,
{
    // The reactor's own field order (table before ring) keeps the buffers-before-unmap invariant.
    core: Reactor<U>,
    framer: F,
    events: VecDeque<Event>,
    // Per-slot FIFO of request ids awaiting replies. `send` pushes, `deliver_reply` pops the front, since an in-order
    // server answers in send order. A closed connection's entry is removed.
    awaiting: HashMap<u32, VecDeque<RequestId>>,
    next_req: u64,
    // At most one per slot, removed with the connection.
    splicing_frames: HashMap<u32, PendingSplice>,
    tls_connect: Option<TlsConnectFn>,
    // Handshake workers send their outcome here and poke the wake eventfd, and `on_wake` drains it.
    handshake_tx: mpsc::Sender<HandshakeResult>,
    handshake_rx: mpsc::Receiver<HandshakeResult>,
    // Connections parked mid-kTLS-handshake. They are live work that `inflight` does not count beyond the wake READ,
    // so `next_event` must not report "no connections" while one is outstanding (see `no_live_work`).
    parked_handshakes: u32,
    // Armed lazily on the first parked handshake, so a plain-TCP client keeps its `inflight == 0` test exact.
    wake_armed: bool,
    ktls_supported: bool,
    // The engine-read subset is projected into `core.cfg`.
    cfg: ClientConfig,
    // The `next_event_timeout` deadline's timespec. Owned by the client rather than the stack, so a deadline still
    // staged when a fatal ring error unwinds the call stays valid until `Drop`'s reap. Kept off the shared `KernelPads`
    // so it can never alias the core's own timers.
    deadline_pad: Box<KernelTimespec>,
    // A call that unwinds on a fatal ring error leaves its deadline in flight, and the next call reaps it before
    // staging a fresh one. Two deadlines with one `user_data` must never coexist, since the stale one would end the new
    // call early with `None`.
    deadline_inflight: bool,
}

impl<U, F> Client<U, F>
where
    F: FnMut(&[u8], &mut U) -> Framing,
{
    /// Set up the ring and pool for a client with the given config and reply `framer`. Where io_uring is unavailable it
    /// fails with an `ENOSYS`, `EPERM` or `EACCES` [`Errno`](crate::Errno), which a caller may treat as an environment
    /// skip.
    pub fn new(config: ClientConfig, framer: F) -> crate::Result<Self> {
        config.validate()?;
        Self::build(config, framer, RingFd::setup(ring_entries(&config))?)
    }

    /// As [`Client::new`], on a ring from [`setup_ring`].
    ///
    /// `config` must be the one the ring was set up for. The ring is sized from it, and one too shallow for this
    /// configuration is refused with [`Error::Validation`] rather than run with a queue that forces mid-batch flushes.
    pub fn with_ring(config: ClientConfig, framer: F, ring: RingFd) -> crate::Result<Self> {
        config.validate()?;
        let need = ring_entries(&config);
        if ring.sq_entries() < need {
            return Err(Error::Validation(format!(
                "ring has {} submission entries, this configuration needs \
                 {need}",
                ring.sq_entries()
            )));
        }
        Self::build(config, framer, ring)
    }

    fn build(config: ClientConfig, framer: F, ring: RingFd) -> crate::Result<Self> {
        // A kernel without `FIXED_FD_INSTALL` or the TLS ULP fails a `tls` connect cleanly and leaves plain TCP alone.
        let engine = Engine::on_ring(ring, config.pool_size)?;
        let ktls_supported = probe_ktls().is_ok();

        let ts_of = connect::ts_of;
        let pads = Box::new(KernelPads {
            deadline: KernelTimespec::default(),
            // Server-only. The connect timeout is per connect, stored in each `PendingConnect`.
            accept_retry: KernelTimespec::default(),
            maintain: KernelTimespec::default(),
            idle_timeout: config.idle_timeout.map(ts_of).unwrap_or_default(),
            send_timeout: config.send_timeout.map(ts_of).unwrap_or_default(),
            request_timeout: config.response_timeout.map(ts_of).unwrap_or_default(),
            tls_handshake: config.tls_handshake_timeout.map(ts_of).unwrap_or_default(),
            // Server-only, since only a server registers a recv pool.
            recv_retry: KernelTimespec::default(),
            // Server-only, since only a server defends a pool slot against the peer that took it.
            max_receipt_time: KernelTimespec::default(),
        });

        let core = Reactor::from_parts(engine, config.pool_size, config.to_core(), pads);
        let (handshake_tx, handshake_rx) = mpsc::channel();
        Ok(Client {
            core,
            framer,
            events: VecDeque::new(),
            awaiting: HashMap::new(),
            next_req: 0,
            splicing_frames: HashMap::new(),
            tls_connect: None,
            handshake_tx,
            handshake_rx,
            parked_handshakes: 0,
            wake_armed: false,
            ktls_supported,
            cfg: config,
            deadline_pad: Box::new(KernelTimespec::default()),
            deadline_inflight: false,
        })
    }

    /// Install the kernel-TLS handshake handler, required for a [`tls`](ConnectOpts::tls) connect.
    ///
    /// Called once per `tls` connect after its TCP connect completes, with a real socket fd, a [`TlsConnectContext`]
    /// and a [`ConnectDeferral`]. Move the fd and the deferral to your own worker, never blocking the loop thread, and
    /// run the TLS handshake there so it installs kTLS on the socket (OpenSSL with `SSL_OP_ENABLE_KTLS`, for example).
    /// Then call [`ConnectDeferral::ready`] or [`ConnectDeferral::reject`], and close the furnished fd. The connection
    /// is served over the pool descriptor, which shares the socket and its kTLS state.
    pub fn set_tls_handshake<H>(&mut self, handler: H)
    where
        H: FnMut(RawFd, TlsConnectContext<'_>, ConnectDeferral) + 'static,
    {
        self.tls_connect = Some(Box::new(handler));
    }

    /// Whether the client has no live work left, with no connection serving or connecting and no kTLS handshake parked.
    /// The only op that may still be in flight is the wake READ, so `inflight` must equal its 0 or 1.
    fn no_live_work(&self) -> bool {
        self.parked_handshakes == 0 && self.core.engine.inflight == u64::from(self.wake_armed)
    }

    /// A wake poke was heard (a handshake worker handed back an outcome): drain the outcomes, then re-arm the wake READ
    /// if any handshake is still parked (else leave it disarmed - the just-completed READ is not renewed).
    pub(super) fn on_wake(&mut self) -> crate::errno::Result<()> {
        self.wake_armed = false;
        self.drain_handshake_outcomes()?;
        if self.parked_handshakes > 0 {
            self.core.arm_wake()?;
            self.wake_armed = true;
        }
        Ok(())
    }

    /// Whether `conn` is still an open, serving connection (not closed, stale, or still connecting).
    pub fn is_open(&self, conn: ConnId) -> bool {
        let (slot, generation) = conn.parts();
        self.core.table.slot_matches(slot, generation)
    }

    /// The per-connection state `U` for `conn`, or `None` if it is not an open serving connection - e.g. to stash a
    /// framing sink the reply framer reads.
    pub fn conn_state(&mut self, conn: ConnId) -> Option<&mut U> {
        let (slot, generation) = conn.parts();
        if self.core.table.slot_matches(slot, generation) {
            Some(&mut self.core.table.conn_mut(slot).state)
        } else {
            None
        }
    }

    /// Gracefully close `conn`: flush anything already queued to send, force the FIN, then reclaim the slot - surfaced
    /// as an [`Event::Closed`]. A stale/unknown `conn` is a no-op.
    pub fn close(&mut self, conn: ConnId) {
        let (slot, generation) = conn.parts();
        if !self.core.table.slot_matches(slot, generation) {
            return;
        }
        let has_queued = {
            let c = self.core.table.conn(slot);
            c.sending || c.has_pending_send()
        };
        // `CloseReason` has no client-only variant, so a local close reports `ShuttingDown`.
        if has_queued {
            self.core.table.conn_mut(slot).close_on_flush = Some(CloseReason::ShuttingDown);
            let _ = self.core.drive_flush_close(slot, generation as u32);
        } else {
            let _ = self.core.close_conn(slot, generation as u32, CloseReason::ShuttingDown);
        }
    }

    /// Close `conn` immediately, discarding anything queued to send. A stale/unknown `conn` is a no-op.
    pub fn close_now(&mut self, conn: ConnId) {
        let (slot, generation) = conn.parts();
        if self.core.table.slot_matches(slot, generation) {
            let _ = self.core.close_conn(slot, generation as u32, CloseReason::ShuttingDown);
        }
    }

    /// Route one reaped completion to its handler. Server-only tags route to `unreachable!` so the match stays
    /// wildcard-free and a stray tag is never silently ignored.
    pub(super) fn dispatch(&mut self, cqe: IoUringCqe) -> crate::errno::Result<()> {
        let (op, slot, generation) = unpack(cqe.user_data);
        // Count the CQE off before its handler runs. The arms propagate with `?`, and a skipped decrement would hang
        // `cancel_and_reap_all`.
        if cqe.flags & IORING_CQE_F_MORE == 0 {
            self.core.engine.inflight = self.core.engine.inflight.saturating_sub(1);
        }
        match op {
            Some(Op::Connect) => self.on_connect(slot, generation, cqe.res)?,
            Some(Op::RecvRetry) => {
                unreachable!("client never parks a recv on a pool")
            }
            Some(Op::ReceiptDeadline) => {
                unreachable!("client never bounds total receipt")
            }
            Some(op @ (Op::RecvHeader | Op::RecvBody)) => self.on_recv(slot, generation, cqe.res, op)?,
            Some(Op::Send) => self.on_send(slot, generation, cqe.res)?,
            Some(Op::Close) => self.on_closed(slot)?,
            Some(Op::Shutdown) => self.core.on_shutdown(slot, generation)?,
            Some(Op::FdInstall) => self.on_fd_install(slot, generation, cqe.res)?,
            Some(Op::HandshakeTimeout) => self.on_handshake_timeout(slot, generation)?,
            Some(Op::Wake) => self.on_wake()?,
            Some(Op::RecvClock) => self.core.on_recv_clock(slot, generation, cqe.res)?,
            Some(Op::SpliceRecv) => self.on_splice_recv(slot, generation, cqe.res)?,
            Some(Op::SplicePoll) => self.core.on_splice_poll(slot, generation, cqe.res)?,
            Some(Op::SpliceDeadline) => self.core.on_splice_deadline(slot, generation, cqe.res)?,
            // Its cancel of the linked op does the work.
            Some(Op::LinkTimeout) => {}
            // `next_event_timeout` reaps its own deadline, so one reaching here is the stray of a call that unwound.
            // Consuming it retires the flag, or the next call would wait for a completion already reaped.
            Some(Op::Deadline) => self.deadline_inflight = false,
            Some(Op::Cancel) | None => {}
            Some(
                Op::Accept
                | Op::AcceptRetry
                | Op::Cred
                | Op::Peername
                | Op::DetachInstall
                | Op::Maintain
                | Op::Handoff
                | Op::Handed,
            ) => unreachable!("client never issues {op:?}"),
        }
        Ok(())
    }

    /// The CLOSE that reclaims a connection's descriptor completed. A serving connection emits [`Event::Closed`] and
    /// drops its correlation queue. A connect-failure CLOSE frees silently, since `ConnectFailed` was already emitted.
    fn on_closed(&mut self, slot: u32) -> crate::errno::Result<()> {
        let pre = self
            .core
            .table
            .get_conn(slot)
            .map(|c| c.close_reason.unwrap_or(CloseReason::PeerClosed));
        let generation = self.core.table.generation(slot);
        self.core.on_closed(slot)?;
        if let Some(reason) = pre {
            // `get_conn` is `None` now iff the slot was freed this call.
            if self.core.table.get_conn(slot).is_none() {
                let conn = ConnId::new(slot, generation);
                self.events.push_back(Event::Closed { conn, reason });
                self.awaiting.remove(&slot);
                self.splicing_frames.remove(&slot);
            }
        }
        Ok(())
    }
}

impl<U, F> Drop for Client<U, F>
where
    F: FnMut(&[u8], &mut U) -> Framing,
{
    fn drop(&mut self) {
        // A failed drain leaks the buffers rather than free them under a still-live op.
        self.core.drain_or_leak(&mut |_| {});
    }
}

impl<U, F> std::fmt::Debug for Client<U, F>
where
    F: FnMut(&[u8], &mut U) -> Framing,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("cfg", &self.cfg)
            .field("inflight", &self.core.engine.inflight)
            .field("pending_events", &self.events.len())
            .finish_non_exhaustive()
    }
}
