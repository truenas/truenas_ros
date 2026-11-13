//! The cross-thread contract: every handle that lets other threads talk to the single-threaded server loop - deferred
//! replies, pushes, the kTLS handshake hand-back, shutdown, stats - plus the wake eventfd and routing tokens they ride
//! on. Every hand-off is a queue send + an eventfd poke.

#[cfg(doc)]
use super::Server;
use crate::net::core::handles::{StatsInner, Token};
#[cfg(doc)]
use crate::net::core::protocol::CloseReason;
#[cfg(doc)]
use crate::net::server::protocol::Response;
use crate::sync::Arc;
use crate::uring::wake::LoopShared;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::time::Duration;

/// Proof that [`Responder::defer`] was called for this request.
///
/// Stamped with that request's routing token, so returning [`Response::Defer`]`(permit)` guarantees a [`Deferred`]
/// exists whose answer or drop will resolve the parked request. A permit from another request closes the connection
/// ([`CloseReason::HandlerClosed`]) rather than park a request nothing could resolve.
#[derive(Debug)]
#[must_use = "return Response::Defer(permit) from the body handler"]
pub struct DeferPermit {
    pub(super) token: Token,
}

/// Proof that [`Responder::detach`] was called for this request.
///
/// Like [`DeferPermit`], for [`Response::Detach`]`(permit)`, which has the loop hand a real fd and a [`Detached`] to
/// the [`Server::set_detach_handler`] handler. A permit from another request closes the connection
/// ([`CloseReason::HandlerClosed`]).
#[derive(Debug)]
#[must_use = "return Response::Detach(permit) from the body handler"]
pub struct DetachPermit {
    pub(super) token: Token,
}

/// Handed to the body handler for one request; the ticket for replying later.
///
/// On the synchronous path, ignore it and return [`Response::Reply`]. To offload the work, call [`Responder::defer`] to
/// detach an owned, `Send` [`Deferred`], move it into your own worker, and return [`Response::Defer`] with the
/// accompanying [`DeferPermit`].
pub struct Responder {
    pub(super) token: Token,
    pub(super) tx: mpsc::Sender<Injected>,
    pub(super) shared: Arc<LoopShared>,
}

/// A `draining()` probe that outlives the [`Responder`] it came from, for glue that must read the flag after a handler
/// consumed the responder. The HTTP codec is its only consumer.
#[cfg(feature = "http")]
pub(crate) struct DrainProbe {
    shared: Arc<LoopShared>,
}

#[cfg(feature = "http")]
impl DrainProbe {
    pub(crate) fn draining(&self) -> bool {
        self.shared.graceful_requested().is_some() || self.shared.stop_requested()
    }
}

impl Responder {
    /// Whether the server has been asked to stop, gracefully or not.
    ///
    /// Advisory, and `true` does not make this reply the connection's last. A draining loop reads no new request off
    /// this connection but still delivers those already buffered, each seeing `true`, and closes the connection once
    /// nothing is outstanding. A protocol that wants this reply to be the last returns [`Response::ReplyClose`] or
    /// [`Response::ReplyVectored`]` { close: true }`, and should say so on the wire (HTTP sends `Connection: close`) so
    /// the peer does not race the close with its next request. The close hook then reports
    /// [`CloseReason::HandlerClosed`], not `ShuttingDown`.
    pub fn draining(&self) -> bool {
        self.shared.graceful_requested().is_some() || self.shared.stop_requested()
    }

    /// A second responder for the same request, for the one dispatch step that runs the handler twice (the window
    /// exhausting a known-length stream carries the End stage too). The dispatches are sequential and at most one may
    /// defer; the shared token keeps the one-answer-per-request guard intact either way.
    #[cfg(feature = "http")]
    pub(crate) fn split(&self) -> Responder {
        Responder {
            token: self.token,
            tx: self.tx.clone(),
            shared: Arc::clone(&self.shared),
        }
    }

    #[cfg(feature = "http")]
    pub(crate) fn drain_probe(&self) -> DrainProbe {
        DrainProbe {
            shared: Arc::clone(&self.shared),
        }
    }

    /// Detach an owned, `Send` handle for delivering this request's reply later from any thread, plus the
    /// [`DeferPermit`] to return as [`Response::Defer`]`(permit)`. Dropping the [`Deferred`] unanswered closes the
    /// connection, so a lost worker cannot leak a parked one.
    pub fn defer(self) -> (Deferred, DeferPermit) {
        (
            Deferred {
                token: self.token,
                tx: self.tx,
                shared: self.shared,
                done: false,
            },
            DeferPermit { token: self.token },
        )
    }

    /// A long-lived `Clone + Send + Sync` handle for **pushing** unsolicited PDUs to this connection from any thread,
    /// for the connection's lifetime. Pushes to a connection that has closed are dropped.
    pub fn push_handle(&self) -> PushHandle {
        PushHandle {
            slot: self.token.slot,
            generation: self.token.generation,
            tx: self.tx.clone(),
            shared: Arc::clone(&self.shared),
        }
    }

    /// **Detach** this connection. Return the [`DetachPermit`] as [`Response::Detach`]`(permit)` to hand the socket to
    /// your own worker for a blocking operation, such as a ZFS send. The loop delivers a real fd aliasing the pool
    /// socket, with a [`Detached`], to the [`Server::set_detach_handler`] handler, and parks the connection until
    /// [`Detached::resume`] or [`Detached::close`]. Stash what the worker should do in the connection state before
    /// returning.
    pub fn detach(self) -> DetachPermit {
        DetachPermit { token: self.token }
    }
}

impl std::fmt::Debug for Responder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Responder").finish_non_exhaustive()
    }
}

// The http glue's unit tests are the only consumer: `net-server` alone builds these tests without them, and dead code
// is an error under the feature matrix's `-D warnings`.
#[cfg(all(test, feature = "http"))]
impl Responder {
    /// A live responder backed by a throwaway channel and wake, for unit tests that drive protocol glue (the http
    /// `step`) without a reactor. The receiver is dropped, so outcomes sent through its handles vanish.
    pub(crate) fn test_responder() -> Responder {
        Self::test_wired().0
    }

    /// [`Responder::test_responder`] whose server is already draining.
    pub(crate) fn test_responder_draining() -> Responder {
        let r = Self::test_wired().0;
        r.shared.request_graceful(0);
        r
    }

    fn test_wired() -> (Responder, mpsc::Receiver<Injected>) {
        // `crate::sync` atomics, matching `LoopShared`'s fields, so this constructs under `--cfg loom` too.
        use crate::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize};
        let (tx, rx) = mpsc::channel();
        let shared = Arc::new(LoopShared {
            stop: AtomicBool::new(false),
            graceful: AtomicBool::new(false),
            grace_ms: AtomicU64::new(0),
            wake: crate::uring::wake::WakeHandle::new().expect("wake"),
            handed: AtomicUsize::new(0),
        });
        let token = Token {
            slot: 0,
            generation: 1,
            req_id: 0,
        };
        (Responder { token, tx, shared }, rx)
    }

    /// [`test_responder`](Self::test_responder) keeping the loop side: the injection receiver and the wake, so a model
    /// consumes a worker outcome exactly as the reactor's drain does. Model-only, because the blocking half rides
    /// [`WakeHandle`]'s loom stand-in.
    #[cfg(loom)]
    pub(crate) fn test_responder_with_probe() -> (Responder, RedeliverProbe) {
        let (responder, rx) = Self::test_wired();
        let shared = Arc::clone(&responder.shared);
        (responder, RedeliverProbe { rx, shared })
    }
}

/// The loop side of a [`Responder::test_responder_with_probe`] pair.
#[cfg(all(test, loom, feature = "http"))]
pub(crate) struct RedeliverProbe {
    rx: mpsc::Receiver<Injected>,
    shared: Arc<LoopShared>,
}

#[cfg(all(test, loom, feature = "http"))]
impl RedeliverProbe {
    /// Consume the worker's outcome the way the loop does: block on the wake (the armed `READ`), then take the queued
    /// injection - asserting it is the redelivery the http completion pass runs on.
    pub(crate) fn recv_redeliver(&self) {
        self.shared.wake.drain();
        assert!(
            matches!(self.rx.try_recv(), Ok(Injected::Redeliver(_))),
            "wake poked with no redelivery queued"
        );
    }
}

/// An owned, `Send` handle that delivers a deferred reply from any thread.
///
/// Obtained from [`Responder::defer`]. Call [`Deferred::reply`] once with the reply PDU, where an **empty** reply
/// completes the request with nothing sent, or [`Deferred::reply_close`] or [`Deferred::close`]. Dropping it unanswered
/// closes the connection, so a lost worker cannot leak it. The answer is sent only if the connection is still open and
/// this request still awaits it, and is dropped otherwise, which is why the ticket is a slot, generation and request
/// token rather than a pointer into the connection.
#[must_use = "dropping a Deferred without replying closes the connection"]
pub struct Deferred {
    token: Token,
    tx: mpsc::Sender<Injected>,
    shared: Arc<LoopShared>,
    done: bool,
}

impl Deferred {
    /// Deliver the reply for this request. An empty reply completes the request without sending anything (one-way
    /// message). Consumes the handle.
    pub fn reply(self, bytes: Vec<u8>) {
        self.deliver(bytes, Injected::Reply);
    }

    /// As [`reply`](Self::reply), for bytes in storage claimed from the ring's body pool. Once sent, the storage goes
    /// back to the pool, as a [`SendBuf::recycled`](crate::net::server::SendBuf::recycled) segment's does in a reply
    /// given inline. The reply counts in [`BodyRecycler::held`](crate::net::server::BodyRecycler::held) from this call,
    /// before the loop has it. Consumes the handle.
    pub fn reply_recycled(self, bytes: Vec<u8>) {
        // An empty reply goes as `Done` and its storage is freed there, so it adds nothing the loop would take off. The
        // add comes before the send, so the loop never takes off a figure not yet added.
        if !bytes.is_empty() {
            self.shared.handed.fetch_add(bytes.capacity(), Ordering::Relaxed);
        }
        self.deliver(bytes, Injected::ReplyRecycled);
    }

    fn deliver(mut self, bytes: Vec<u8>, reply: fn(Token, Vec<u8>) -> Injected) {
        self.done = true;
        let msg = if bytes.is_empty() {
            Injected::Done(self.token)
        } else {
            reply(self.token, bytes)
        };
        // The server owns the receiver for its whole life; a send error just means it has already shut down, in which
        // case the reply is moot.
        let _ = self.tx.send(msg);
        self.shared.wake.poke();
    }

    /// Deliver the reply and then close the connection once it - and everything queued before it - has flushed: the
    /// deferred twin of [`Response::ReplyClose`] (the worker speaks last). An empty reply queues no PDU and closes
    /// after flushing what is already queued. The close hook reports [`CloseReason::WorkerClosed`], as for
    /// [`Deferred::close`]. Consumes the handle.
    pub fn reply_close(mut self, bytes: Vec<u8>) {
        self.done = true;
        let _ = self.tx.send(Injected::ReplyClose(self.token, bytes));
        self.shared.wake.poke();
    }

    /// Close the connection instead of replying (e.g. the worker decided the request is fatal). Consumes the handle.
    pub fn close(mut self) {
        self.done = true;
        let _ = self.tx.send(Injected::Close(self.token));
        self.shared.wake.poke();
    }

    /// Re-deliver this request to the body handler instead of supplying bytes, for protocol glue that kept the request
    /// in its connection state and completes it on the server thread. The handler runs again with an empty frame, as a
    /// fresh delivery, and may reply, defer again or close. A redelivery for a request already answered, or whose
    /// connection closed or slot was recycled, is dropped. Consumes the handle.
    pub fn redeliver(mut self) {
        self.done = true;
        let _ = self.tx.send(Injected::Redeliver(self.token));
        self.shared.wake.poke();
    }
}

impl Drop for Deferred {
    fn drop(&mut self) {
        if !self.done {
            // Lost worker (dropped/panicked without replying): close the parked connection rather than leak its pool
            // slot forever.
            let _ = self.tx.send(Injected::Close(self.token));
            self.shared.wake.poke();
        }
    }
}

/// The ticket a **detach** worker uses to hand a connection back to the server after its blocking operation on the
/// furnished fd.
///
/// Move it to your own worker, do the blocking work on [`Detached::raw_fd`], then call [`Detached::resume`] to keep
/// serving or [`Detached::close`]. Dropping it closes the connection, so a lost worker cannot leak the slot. The handle
/// owns the furnished fd and closes it when consumed, and the pool socket survives.
#[must_use = "call resume() or close(), or the connection is closed"]
pub struct Detached {
    pub(super) slot: u32,
    pub(super) generation: u64,
    pub(super) fd: OwnedFd,
    pub(super) tx: mpsc::Sender<Injected>,
    pub(super) shared: Arc<LoopShared>,
    pub(super) done: bool,
}

impl Detached {
    /// The furnished socket fd (aliasing the connection's pool socket), for the worker's blocking operation. Valid
    /// until this handle is consumed/dropped.
    pub fn raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    /// The worker finished, so **resume** serving the connection. Consumes the handle, closing the furnished fd.
    ///
    /// The furnished fd shares the pool socket's file description, so a flag the worker changed on it outlives the
    /// detach. A worker doing a blocking transfer typically clears `O_NONBLOCK`, which the splice path's readiness-poll
    /// guard needs (`tcp_splice_read` takes its wait mode from the file), so `resume` sets it again.
    pub fn resume(mut self) {
        // Best-effort: on any fcntl failure the fd is dead or dying, and the resumed loop's next op surfaces that as a
        // normal close.
        // SAFETY: `self.fd` is a live owned fd; F_GETFL/F_SETFL read/write no user memory.
        unsafe {
            let fl = libc::fcntl(self.fd.as_raw_fd(), libc::F_GETFL);
            if fl >= 0 && fl & libc::O_NONBLOCK == 0 {
                libc::fcntl(self.fd.as_raw_fd(), libc::F_SETFL, fl | libc::O_NONBLOCK);
            }
        }
        self.done = true;
        self.signal(true);
    }

    /// The worker finished (or decided to end the connection); **close** it. Consumes the handle (closing the furnished
    /// fd).
    pub fn close(mut self) {
        self.done = true;
        self.signal(false);
    }

    fn signal(&mut self, resume: bool) {
        let msg = if resume {
            Injected::DetachResume {
                slot: self.slot,
                generation: self.generation,
            }
        } else {
            Injected::DetachClose {
                slot: self.slot,
                generation: self.generation,
            }
        };
        // The server owns the receiver for its whole life; a send error just means it has shut down, in which case the
        // outcome is moot.
        let _ = self.tx.send(msg);
        self.shared.wake.poke();
    }
}

impl Drop for Detached {
    fn drop(&mut self) {
        if !self.done {
            self.signal(false); // lost worker -> close the parked connection
        }
    }
}

impl std::fmt::Debug for Detached {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Detached")
            .field("slot", &self.slot)
            .field("generation", &self.generation)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for Deferred {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Deferred").finish_non_exhaustive()
    }
}

/// A `Clone + Send + Sync` handle for pushing unsolicited PDUs to one connection, obtained from
/// [`Responder::push_handle`].
///
/// A push is a complete, caller-framed PDU queued behind pending replies and sent one at a time, so it never
/// interleaves with a reply. A push to a closed or recycled connection is dropped, one that would overflow
/// `ServerConfig::max_send_backlog` closes the connection as a slow consumer, and pushes are discarded while the server
/// drains. A push issued inside a body handler is queued after that handler's own inline reply.
#[derive(Clone)]
pub struct PushHandle {
    slot: u32,
    generation: u64,
    tx: mpsc::Sender<Injected>,
    shared: Arc<LoopShared>,
}

impl PushHandle {
    /// Queue `bytes` as an unsolicited PDU on this connection and wake the server loop. Empty `bytes` is a no-op.
    ///
    /// Pushes cross to the loop on an unbounded channel. `ServerConfig::max_send_backlog` bounds what is queued on a
    /// connection but not this channel, so a producer that outpaces the loop grows memory without limit. Deferred
    /// replies are bounded by `max_in_flight_requests`, but pushes are not, so pace them to the loop or gate them
    /// behind a bound of your own.
    pub fn push(&self, bytes: Vec<u8>) {
        if bytes.is_empty() {
            return;
        }
        let _ = self.tx.send(Injected::Push {
            slot: self.slot,
            generation: self.generation,
            bytes,
        });
        self.shared.wake.poke();
    }

    /// Close this connection from any thread, outside any request cycle, such as for a session revocation or an
    /// administrative kick. Everything already queued, pushes included, flushes first, bounded by
    /// `ServerConfig::send_timeout` when set, and nothing further is read, delivered or queued. The close hook reports
    /// [`CloseReason::PushClosed`].
    ///
    /// Closing a connection that has already closed, or whose slot was recycled, is a no-op, as are repeat calls. On a
    /// connection parked under a detach worker the close lands at [`Detached::resume`], after the pushes held during
    /// the detach, since the worker owns the stream until then.
    pub fn close(&self) {
        let _ = self.tx.send(Injected::PushClose {
            slot: self.slot,
            generation: self.generation,
        });
        self.shared.wake.poke();
    }
}

impl std::fmt::Debug for PushHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PushHandle")
            .field("slot", &self.slot)
            .field("generation", &self.generation)
            .finish_non_exhaustive()
    }
}

// `Deferred` is moved to worker threads and `PushHandle` is shared across them, so both must be `Send` (and the handle
// `Sync`).
const _: fn() = || {
    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}
    assert_send::<Deferred>();
    assert_send::<Detached>();
    assert_send::<PushHandle>();
    assert_sync::<PushHandle>();
};

/// A snapshot of server counters ([`Server::stats_handle`]). Each counter is individually exact, but they are read
/// independently (relaxed atomics), so a snapshot is not a single consistent cut: derived relations across counters
/// (e.g. `accepted - closed == active`) may not hold at the instant it is taken, only settle in the steady state.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default)]
pub struct ServerStats {
    /// Connections accepted (having passed the accept handler).
    pub accepted: u64,
    /// Connections rejected by the accept handler (`None`).
    pub rejected: u64,
    /// Connections shed, for a full pool, out of range, arriving during shutdown, a failed credential fetch, or on a
    /// kTLS listener the process out of file descriptors.
    ///
    /// A parked kTLS handshake holds two process descriptors, the furnished fd and the deferral's dup of it, so
    /// `RLIMIT_NOFILE` bounds handshakes in flight apart from `pool_size`. Both the install (`io_install_fixed_fd` ->
    /// `receive_fd` -> `get_unused_fd_flags`) and the dup answer `EMFILE` by shedding, and nothing else reports it.
    pub shed: u64,
    /// Transient accept errors (resource pressure) that triggered a backoff re-arm instead of terminating the server.
    pub accept_retries: u64,
    /// Connections this ring accepted and sent to a ring of its [`Spread`](super::Spread) holding fewer. They count in
    /// [`accepted`](ServerStats::accepted) on the ring that serves them.
    pub handed_off: u64,
    /// Listeners whose `shutdown(SHUT_RD)` failed at the start of a graceful drain. Non-zero means refuse-on-connect
    /// did not take effect for that listener: its backlog keeps filling with clients nobody will answer until the fd
    /// closes at server drop.
    pub drain_listener_shutdown_failed: u64,
    /// Connections fully closed (slot released).
    pub closed: u64,
    /// Connections currently live.
    pub active: u32,
    /// Requests delivered to the body handler.
    pub requests: u64,
    /// Requests deferred to workers.
    pub deferred: u64,
    /// Reply PDUs fully sent.
    pub replies: u64,
    /// Pushed PDUs fully sent.
    pub pushes: u64,
    /// Send operations completed. With reply coalescing one op can carry several PDUs, so this is <= `replies +
    /// pushes`.
    pub send_ops: u64,
    /// Receive operations that completed with data (header and body reads).
    pub recv_ops: u64,
    /// Payload bytes received.
    pub bytes_in: u64,
    /// Payload bytes sent.
    pub bytes_out: u64,
    /// Ring buffers currently held, by a connection mid-message or a file body's chunk in flight or queued, when
    /// [`ServerConfig::recv_pool`](super::ServerConfig::recv_pool) is set, and always `0` otherwise. At rest this
    /// settles to zero however many connections are open, so a value that tracks the connection count means buffers are
    /// not being handed back.
    pub recv_bufs_lent: u32,
    /// Buffers allocated across both registered rings (receive and file body). It starts at each ring's
    /// [`buf_pool_initial_bytes`](super::ServerConfig::buf_pool_initial_bytes), doubles as a ring runs low and drains
    /// back after idle rounds, so a steady value is a pool at its working set. A stranded id, consumed by the kernel
    /// and never returned, moves neither this nor [`recv_bufs_lent`](ServerStats::recv_bufs_lent).
    pub recv_bufs_total: u32,
    /// Reads parked on the [`recv_shortage_retry`] backoff because the buffer pool was genuinely exhausted, counting
    /// each retry that found it still dry. Zero under any load the pool's growth can answer.
    ///
    /// [`recv_shortage_retry`]: super::ServerConfig::recv_shortage_retry
    pub recv_shortage_parks: u64,
    /// Reads that found a buffer ring dry (`-ENOBUFS`) and were re-armed. A count that climbs under steady load says
    /// bursts outrun the pools' growth.
    pub buf_shortages: u64,
    /// Provided-buffer rings this server asked for and did not get because `RLIMIT_MEMLOCK` refused their region.
    ///
    /// Nonzero means permanently degraded, not absent. Registration is charged against that limit
    /// (`io_register_pbuf_ring` -> `io_create_region` -> `__io_account_mem`, `io_uring/rsrc.c`), and once refused every
    /// read falls back to the per-read allocation the ring exists to remove while the server answers and every other
    /// counter looks healthy. `__io_account_mem` charges a per-uid counter, so an unrelated process of the same user
    /// can cause it. The remedy is to raise the limit (`LimitMEMLOCK=` in the unit, or `setrlimit` before
    /// [`Server::bind`](super::Server::bind)).
    ///
    /// A kernel with no provided-buffer rings answers `EINVAL` or `ENOSYS` and is not counted, since falling back is
    /// right for it. [`recv_bufs_total`](ServerStats::recv_bufs_total) reads 0 in both cases, so only this counter
    /// tells them apart.
    pub buf_rings_refused_memlock: u64,
}

/// A `Clone + Send + Sync` handle for reading a running server's counters from any thread ([`Server::stats_handle`]).
#[derive(Clone, Debug)]
pub struct StatsHandle {
    pub(super) inner: Arc<StatsInner>,
}

impl StatsHandle {
    /// A point-in-time snapshot of the counters.
    pub fn snapshot(&self) -> ServerStats {
        let s = &self.inner;
        ServerStats {
            accepted: s.accepted.load(Ordering::Relaxed),
            rejected: s.rejected.load(Ordering::Relaxed),
            shed: s.shed.load(Ordering::Relaxed),
            accept_retries: s.accept_retries.load(Ordering::Relaxed),
            handed_off: s.handed_off.load(Ordering::Relaxed),
            drain_listener_shutdown_failed: s.drain_listener_shutdown_failed.load(Ordering::Relaxed),
            closed: s.closed.load(Ordering::Relaxed),
            active: s.active.load(Ordering::Relaxed) as u32,
            requests: s.requests.load(Ordering::Relaxed),
            deferred: s.deferred.load(Ordering::Relaxed),
            replies: s.replies.load(Ordering::Relaxed),
            pushes: s.pushes.load(Ordering::Relaxed),
            send_ops: s.send_ops.load(Ordering::Relaxed),
            recv_ops: s.recv_ops.load(Ordering::Relaxed),
            bytes_in: s.bytes_in.load(Ordering::Relaxed),
            bytes_out: s.bytes_out.load(Ordering::Relaxed),
            recv_bufs_lent: s.recv_bufs_lent.load(Ordering::Relaxed) as u32,
            recv_shortage_parks: s.recv_shortage_parks.load(Ordering::Relaxed),
            buf_shortages: s.buf_shortages.load(Ordering::Relaxed),
            recv_bufs_total: s.recv_bufs_total.load(Ordering::Relaxed) as u32,
            buf_rings_refused_memlock: s.buf_rings_refused_memlock.load(Ordering::Relaxed),
        }
    }
}

/// Work another thread hands to the loop, delivered on its next wake.
pub(super) enum Injected {
    /// Send these bytes as the request's reply.
    Reply(Token, Vec<u8>),
    /// As `Reply`, with storage that goes back to the ring's body pool once sent ([`Deferred::reply_recycled`]).
    ReplyRecycled(Token, Vec<u8>),
    /// Send these bytes as the request's **final** reply, then close once the connection's send queue drains
    /// ([`Deferred::reply_close`]). Empty bytes queue no PDU: flush what is queued and close.
    ReplyClose(Token, Vec<u8>),
    /// The request is complete with nothing to send (one-way message).
    Done(Token),
    /// Close the connection (explicit worker decision, or a dropped/lost [`Deferred`]).
    Close(Token),
    /// Run the body handler again for this request ([`Deferred::redeliver`]) -- the frame is empty; the consumer's
    /// protocol glue retained what it needs in its connection state.
    Redeliver(Token),
    /// An unsolicited push ([`PushHandle::push`]) - not tied to any request.
    Push { slot: u32, generation: u64, bytes: Vec<u8> },
    /// Close the connection once everything already queued on it has flushed ([`PushHandle::close`]) - not tied to any
    /// request.
    PushClose { slot: u32, generation: u64 },
    /// A detached connection's worker signalled **resume** - re-arm serving.
    DetachResume { slot: u32, generation: u64 },
    /// A detached connection's worker signalled **close** (or dropped its [`Detached`] handle unresolved).
    DetachClose { slot: u32, generation: u64 },
    /// A consumer's own message for its control hook ([`ControlHandle::send`]) - not tied to any connection.
    Control(Box<dyn std::any::Any + Send>),
}

/// A `Clone + Send + Sync` handle for running a consumer's own work on the server thread ([`Server::control_handle`]).
///
/// A control message crosses on the injection channel, and the loop hands it to the hook installed with
/// [`Server::set_control_hook`] between two batches of completions, so a swap the hook makes is never seen half done by
/// a request. The hook was built on the loop thread, so it can share state with the handlers (an `Rc`) that the `Send`
/// message cannot carry. Messages are delivered during a graceful drain too, and dropped after the server stops.
#[derive(Clone, Debug)]
pub struct ControlHandle {
    pub(super) tx: mpsc::Sender<Injected>,
    pub(super) shared: Arc<LoopShared>,
}

impl ControlHandle {
    /// Queue `message` for the control hook and wake the loop. Messages from one handle arrive in the order they were
    /// sent, interleaved first-in first-out with deferred replies and pushes. Without a hook installed the message is
    /// dropped when it is reached.
    pub fn send(&self, message: Box<dyn std::any::Any + Send>) {
        let _ = self.tx.send(Injected::Control(message));
        self.shared.wake.poke();
    }
}

/// A `Clone + Send + Sync` stop signal for a running [`Server`] (an extra clone makes a good panic guard: shut down on
/// drop so a failing driver thread cannot strand the loop).
#[derive(Clone, Debug)]
pub struct ShutdownHandle {
    pub(super) shared: Arc<LoopShared>,
}

impl ShutdownHandle {
    /// Stop the server loop immediately: every in-flight operation is cancelled (requests mid-read, replies mid-send,
    /// deferred work is abandoned) and `serve_forever` returns. Safe to call from any thread and more than once.
    /// Infallible: it is a flag store plus an eventfd poke whose errors are meaningless by design (a full counter has
    /// already signalled; a closed fd means the server is gone).
    pub fn shutdown(&self) {
        self.shared.request_stop();
        self.shared.wake.poke();
    }

    /// Stop the server **gracefully**. Every listener is shut down so a new connect is refused at once, idle
    /// connections close, and requests already in flight, reads in progress, deferred work and queued replies, finish,
    /// each connection closing as it quiesces.
    ///
    /// A replacement server can bind the same TCP address during the drain, since every TCP listener here carries
    /// `SO_REUSEADDR`, though the draining socket keeps its port until its fd closes (`tcp_set_state` skips
    /// `inet_put_port` under `SOCK_BINDPORT_LOCK`). A Unix listener's path stays bound, so a replacement bind fails
    /// `EADDRINUSE` for the whole grace period unless it unlinks the path first (`ServerConfig::unlink_unix`).
    ///
    /// Whatever remains after `grace` is cancelled as in [`ShutdownHandle::shutdown`], and a zero `grace` is exactly
    /// `shutdown()`. Safe to call from any thread, and a concurrent hard `shutdown` wins. Infallible, like
    /// [`ShutdownHandle::shutdown`].
    pub fn shutdown_graceful(&self, grace: Duration) {
        if grace.is_zero() {
            return self.shutdown();
        }
        let ms = u64::try_from(grace.as_millis()).unwrap_or(u64::MAX);
        self.shared.request_graceful(ms);
        self.shared.wake.poke();
    }
}
