//! `net::client` — the outbound stream client role on the shared reactor core.
//!
//! A [`Client`] embeds the shared reactor core (the same io_uring engine the
//! server drives) and adds outbound connection establishment, a framed
//! request/reply data plane, and a caller-driven event pump. Like the server it
//! is `!Send` (one ring, one thread) and caller-driven: [`Client::next_event`]
//! pumps the ring and *returns* completions rather than invoking callbacks.
//!
//! The engine is reused verbatim: the framing, zero-copy, timeout, and teardown
//! machinery all live in the reactor core. The client-specific code is the
//! connect subsystem (`connect`), the kTLS-connect hand-off (`tls`), the
//! recv/deliver pump and completion wrappers (`io`), the event/config vocabulary
//! (`event`, `config`), and this file's construction, dispatch, and connection
//! lifecycle.

mod config;
mod connect;
mod event;
mod io;
mod tls;

pub use config::ClientConfig;
pub use event::{ConnId, ConnectOpts, Event, RequestId};
pub use tls::{ConnectDeferral, TlsConnectContext};

use crate::net::core::conn::{unpack, Op};
use crate::net::core::handles::{
    create_eventfd, LoopShared, StatsInner, WakeHandle,
};
use crate::net::core::probe::{probe_fixed_fd_install, probe_ktls};
use crate::net::core::protocol::{CloseReason, Framing};
use crate::net::core::reactor::{KernelPads, Reactor};
use crate::net::core::ring::Ring;
use crate::net::core::sys::*;
use crate::net::core::table::ConnTable;
use io::PendingSplice;
use std::collections::{HashMap, VecDeque};
use std::os::fd::RawFd;
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::{mpsc, Arc};
use tls::{HandshakeResult, TlsConnectFn};

/// Kernel cap on SQ ring entries.
const MAX_RING_ENTRIES: u32 = 32768;

/// A single-threaded io_uring stream client.
///
/// Parameterized by the per-connection state `U` and the framer `F` (given the
/// bytes accumulated so far and the connection's state, it decides how to frame
/// the next reply — see [`Framing`]). Holds the ring, so it is `!Send`/`!Sync`.
pub struct Client<U, F>
where
    F: FnMut(&[u8], &mut U) -> Framing,
{
    // The role-agnostic io_uring engine (ring, connection table, projected
    // CoreConfig, shared flags/stats, kernel pads). Its own field order (table
    // before ring) keeps the buffers-before-unmap invariant.
    core: Reactor<U>,
    // The reply framer, consulted on each connection's accumulated bytes.
    framer: F,
    // The ready queue the caller drains via `next_event`.
    events: VecDeque<Event>,
    // Per-slot FIFO of request ids awaiting replies, for correlation: `send`
    // pushes an id, `deliver_reply` pops the front (an in-order server answers
    // in send order). Keyed by slot; a closed connection's entry is removed.
    awaiting: HashMap<u32, VecDeque<RequestId>>,
    // Client-global monotonic request id source.
    next_req: u64,
    // Per-slot in-flight body-splice snapshot (correlated id + header + length;
    // see `PendingSplice`). At most one per slot; removed with the connection.
    splicing_frames: HashMap<u32, PendingSplice>,
    // The optional kTLS handshake hook (`set_tls_handshake`), invoked once per
    // `tls` connect after its TCP connect completes.
    tls_connect: Option<TlsConnectFn>,
    // The channel client kTLS handshake workers hand their outcome back on,
    // drained in `on_wake` (the outbound, state-free twin of the server's
    // mailbox handshake channel — a poke on the shared wake eventfd delivers it).
    handshake_tx: mpsc::Sender<HandshakeResult>,
    handshake_rx: mpsc::Receiver<HandshakeResult>,
    // Connections parked mid-kTLS-handshake (in `TlsConnecting`): live work that
    // is not counted in `inflight` beyond its wake READ, so `next_event` must not
    // report "no connections" while one is outstanding (see `no_live_work`).
    parked_handshakes: u32,
    // Whether a wake READ is in flight. Armed lazily on the first parked
    // handshake (a plain-TCP client never arms it, keeping its `inflight == 0`
    // "no connections" test exact) and kept armed to hear worker outcomes.
    wake_armed: bool,
    // Whether this kernel has the TLS ULP (probed at construction); a `tls`
    // connect fails cleanly without it (and without `fixed_fd_install`).
    ktls_supported: bool,
    // Client tuning (the engine-read subset is projected into `core.cfg`).
    cfg: ClientConfig,
    // The `next_event_timeout` deadline's timespec: a durable, client-owned
    // landing pad (rewritten each call), so a `Deadline` still staged when a
    // fatal ring error unwinds the call outlives `Drop`'s reap — unlike a
    // stack box. Kept off the shared `KernelPads` so it can never alias the
    // core's own timers.
    deadline_pad: Box<KernelTimespec>,
}

impl<U, F> Client<U, F>
where
    F: FnMut(&[u8], &mut U) -> Framing,
{
    /// Set up the ring and pool for a client with the given config and reply
    /// `framer`. Mirrors `Server::with_config`'s engine build. Fails skippably
    /// (like `Server::bind`) where io_uring is unavailable — an
    /// `ENOSYS`/`EPERM`/`EACCES` [`Errno`](crate::Errno) — so a caller can treat
    /// that as an environment skip.
    pub fn new(config: ClientConfig, framer: F) -> crate::Result<Self> {
        config.validate()?;

        // Peak SQEs a connection holds at once: a recv, a concurrent send (only
        // when pipelining), each timed op's linked timeout, plus the connect
        // pair. Size the ring so a full pool's peak never forces a mid-batch
        // flush (which would split a linked op+timeout pair).
        let per_conn = (if config.max_in_flight > 1 { 2 } else { 1 })
            + u32::from(
                config.idle_timeout.is_some()
                    || config.response_timeout.is_some(),
            )
            + u32::from(config.send_timeout.is_some())
            + u32::from(config.connect_timeout.is_some())
            + u32::from(config.tls_handshake_timeout.is_some());
        let entries = config
            .pool_size
            .saturating_mul(per_conn)
            .saturating_add(2)
            .next_power_of_two()
            .min(MAX_RING_ENTRIES);
        let ring = Ring::new(entries)?;
        ring.register_pool(config.pool_size)?;

        // `FIXED_FD_INSTALL` (Linux >= 6.8) furnishes the real fd behind a kTLS
        // handshake; the TLS ULP is what makes kTLS work at all. Probe both once
        // and keep the flags (a runtime decision, like the server's detach) —
        // a `tls` connect on a kernel missing either fails cleanly, while a
        // plain-TCP client is unaffected.
        let fixed_fd_install = probe_fixed_fd_install(&ring);
        let ktls_supported = probe_ktls().is_ok();

        let ts_of = connect::ts_of; // shared duration → timespec clamp
        let pads = Box::new(KernelPads {
            wake_buf: 0,
            deadline: KernelTimespec::default(),
            // Client-unused (only a server arms accept retries). The connect
            // timeout is per-connect, stored in each `PendingConnect`.
            accept_retry: KernelTimespec::default(),
            idle_timeout: config.idle_timeout.map(ts_of).unwrap_or_default(),
            send_timeout: config.send_timeout.map(ts_of).unwrap_or_default(),
            request_timeout: config
                .response_timeout
                .map(ts_of)
                .unwrap_or_default(),
            tls_handshake: config
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

        let core = Reactor {
            table: ConnTable::new(config.pool_size),
            cfg: config.to_core(),
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
        })
    }

    /// Install the kernel-TLS handshake handler, required for a
    /// [`tls`](ConnectOpts::tls) connect. Called once per `tls` connect after
    /// its TCP connect completes, with `(fd, context, deferral)`: a **real**
    /// socket fd (materialized from the pool descriptor), a
    /// [`TlsConnectContext`] (which connection, and the endpoint it dialed), and
    /// a [`ConnectDeferral`]. Move the fd and the deferral to your own worker
    /// (never block the loop thread), run the client TLS handshake there — which
    /// installs kTLS on the socket (e.g. OpenSSL with `SSL_OP_ENABLE_KTLS`) —
    /// then call [`ConnectDeferral::ready`] on success or
    /// [`ConnectDeferral::reject`] on failure. Close the furnished fd once the
    /// handshake is done; the connection is then served over the pool descriptor
    /// (kTLS lives on the shared socket).
    ///
    /// Unlike the server's handshake handler, no per-connection state crosses
    /// here — the client already holds it (from `connect`), so the deferral is
    /// state-free and the handler needs no `U: Send` bound.
    pub fn set_tls_handshake<H>(&mut self, handler: H)
    where
        H: FnMut(RawFd, TlsConnectContext<'_>, ConnectDeferral) + 'static,
    {
        self.tls_connect = Some(Box::new(handler));
    }

    /// Whether the client has no live work left — no connections serving or
    /// connecting, and no kTLS handshake parked. The only op that may still be
    /// in flight is the wake READ (armed once a kTLS handshake is ever parked
    /// and then kept armed): `inflight` equals exactly its 0-or-1 contribution.
    /// A plain-TCP client never arms the wake, so this stays `inflight == 0`.
    fn no_live_work(&self) -> bool {
        self.parked_handshakes == 0
            && self.core.inflight == u64::from(self.wake_armed)
    }

    /// A wake poke was heard (a handshake worker handed back an outcome): drain
    /// the outcomes, then re-arm the wake READ if any handshake is still parked
    /// (else leave it disarmed — the just-completed READ is not renewed).
    pub(super) fn on_wake(&mut self) -> crate::errno::Result<()> {
        self.wake_armed = false;
        self.drain_handshake_outcomes()?;
        if self.parked_handshakes > 0 {
            self.core.arm_wake()?;
            self.wake_armed = true;
        }
        Ok(())
    }

    /// Whether `conn` is still an open, serving connection (not closed,
    /// stale, or still connecting).
    pub fn is_open(&self, conn: ConnId) -> bool {
        let (slot, generation) = conn.parts();
        self.core.table.slot_matches(slot, generation)
    }

    /// The per-connection state `U` for `conn`, or `None` if it is not an open
    /// serving connection — e.g. to stash a framing sink the reply framer reads.
    pub fn conn_state(&mut self, conn: ConnId) -> Option<&mut U> {
        let (slot, generation) = conn.parts();
        if self.core.table.slot_matches(slot, generation) {
            Some(&mut self.core.table.conn_mut(slot).state)
        } else {
            None
        }
    }

    /// Gracefully close `conn`: flush anything already queued to send, force
    /// the FIN, then reclaim the slot — surfaced as an [`Event::Closed`]. A
    /// stale/unknown `conn` is a no-op.
    pub fn close(&mut self, conn: ConnId) {
        let (slot, generation) = conn.parts();
        if !self.core.table.slot_matches(slot, generation) {
            return;
        }
        let has_queued = {
            let c = self.core.table.conn(slot);
            c.sending || c.has_pending_send()
        };
        // A client-initiated close is reported as `ShuttingDown` (the closest
        // shared reason for "this side is tearing the connection down"; the
        // vocab is server-oriented and gains no client-only variant here).
        if has_queued {
            self.core.table.conn_mut(slot).close_on_flush =
                Some(CloseReason::ShuttingDown);
            let _ = self.core.drive_flush_close(slot, generation as u32);
        } else {
            let _ = self.core.close_conn(
                slot,
                generation as u32,
                CloseReason::ShuttingDown,
            );
        }
    }

    /// Close `conn` immediately, discarding anything queued to send. A
    /// stale/unknown `conn` is a no-op.
    pub fn close_now(&mut self, conn: ConnId) {
        let (slot, generation) = conn.parts();
        if self.core.table.slot_matches(slot, generation) {
            let _ = self.core.close_conn(
                slot,
                generation as u32,
                CloseReason::ShuttingDown,
            );
        }
    }

    /// Route one reaped completion to its handler. Client op arms only: the
    /// server-only tags route to `unreachable!` so the match stays wildcard-free
    /// (a stray tag is a routing bug, not silently ignored).
    pub(super) fn dispatch(
        &mut self,
        cqe: IoUringCqe,
    ) -> crate::errno::Result<()> {
        let (op, slot, generation) = unpack(cqe.user_data);
        // Count the CQE off `inflight` before its handler runs (the arms
        // `?`-propagate; a skipped decrement would hang `cancel_and_reap_all`).
        if cqe.flags & IORING_CQE_F_MORE == 0 {
            self.core.inflight = self.core.inflight.saturating_sub(1);
        }
        match op {
            // An outbound connect completed (`cqe.res == 0` up, `< 0` failed).
            Some(Op::Connect) => self.on_connect(slot, generation, cqe.res)?,
            // A reply header/body recv completed.
            Some(op @ (Op::RecvHeader | Op::RecvBody)) => {
                self.on_recv(slot, generation, cqe.res, op)?
            }
            // A request send completed.
            Some(Op::Send) => self.on_send(slot, generation, cqe.res)?,
            // The index-freeing CLOSE completed: reclaim the slot and, if a
            // serving connection was reclaimed, emit `Event::Closed`.
            Some(Op::Close) => self.on_closed(slot)?,
            // A pre-close SHUTDOWN completed; submit the CLOSE (result moot).
            Some(Op::Shutdown) => self.core.on_shutdown(slot, generation)?,
            // A kTLS-connect furnished-fd install completed; `cqe.res` is the
            // real fd (or `-errno`). Park + hand it to the handshake worker, or
            // fail the connect.
            Some(Op::FdInstall) => {
                self.on_fd_install(slot, generation, cqe.res)?
            }
            // A parked kTLS handshake's timeout fired (or was cancelled on
            // resolve): fail the connect if it is still parked.
            Some(Op::HandshakeTimeout) => {
                self.on_handshake_timeout(slot, generation)?
            }
            // A worker poked the wake eventfd: drain kTLS handshake outcomes.
            Some(Op::Wake) => self.on_wake()?,
            // A recv's linked idle/request clock: pairs with its recv CQE to
            // disambiguate a short read from a timeout (`on_recv_clock`).
            Some(Op::RecvClock) => {
                self.core.on_recv_clock(slot, generation, cqe.res)?
            }
            // A reply-body splice completed (a `Framing::SpliceBody` framer);
            // `cqe.res` is bytes moved (or `<= 0` on EOF/cancel/error/EAGAIN).
            Some(Op::SpliceRecv) => {
                self.on_splice_recv(slot, generation, cqe.res)?
            }
            // A splice-readiness poll fired after a splice hit `-EAGAIN`.
            Some(Op::SplicePoll) => {
                self.core.on_splice_poll(slot, generation, cqe.res)?
            }
            // A kTLS body-splice inactivity watchdog fired or was cancelled.
            Some(Op::SpliceDeadline) => {
                self.core.on_splice_deadline(slot, generation, cqe.res)?
            }
            // A generic linked timeout (a send timeout, or a connect timeout):
            // its cancel of the linked op does the work; only count this one.
            Some(Op::LinkTimeout) => {}
            // A standalone TIMEOUT armed by `next_event_timeout`, which reaps its
            // own deadline inline and cancel-reaps a pending one before returning
            // — one reaching dispatch is a harmless stray (already counted off).
            Some(Op::Deadline) => {}
            // The cancel control op, and any unrecognized tag.
            Some(Op::Cancel) | None => {}
            // Server-only tags: never issued here, so a completion carrying one
            // is a routing bug — panic, don't ignore.
            Some(
                Op::Accept
                | Op::AcceptRetry
                | Op::Cred
                | Op::Peername
                | Op::DetachInstall,
            ) => unreachable!("client never issues {op:?}"),
        }
        Ok(())
    }

    /// The CLOSE that reclaims a connection's descriptor completed. Capture the
    /// stashed close reason and the pre-free generation, let the core reclaim
    /// the slot, then — if a serving connection was actually reclaimed — emit
    /// [`Event::Closed`] and drop the connection's correlation queue. A
    /// connect-failure CLOSE (the slot was `Connecting`, never serving) frees
    /// silently: `ConnectFailed` was already emitted.
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
        // Ensure no op is in flight before the buffers and ring are freed.
        let _ = self.core.cancel_and_reap_all();
    }
}

impl<U, F> std::fmt::Debug for Client<U, F>
where
    F: FnMut(&[u8], &mut U) -> Framing,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("cfg", &self.cfg)
            .field("inflight", &self.core.inflight)
            .field("pending_events", &self.events.len())
            .finish_non_exhaustive()
    }
}
