//! The cross-thread contract: every handle that lets other threads talk to
//! the single-threaded server loop - deferred replies, pushes, the kTLS
//! handshake hand-back, shutdown, stats - plus the wake eventfd and routing
//! tokens they ride on. Every hand-off is a queue send + an eventfd poke.

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
/// Only obtainable from [`Responder::defer`], and stamped with that request's
/// routing token: returning [`Response::Defer`]`(permit)` guarantees a
/// [`Deferred`] exists whose reply, explicit close, or drop will eventually
/// resolve the parked request. The token is verified at delivery - a permit
/// stashed from an earlier request and returned for a different one proves
/// no such `Deferred` exists, so the server closes the connection (reported
/// as [`CloseReason::HandlerClosed`]) rather than park a request nothing
/// could ever resolve.
#[derive(Debug)]
#[must_use = "return Response::Defer(permit) from the body handler"]
pub struct DeferPermit {
    pub(super) token: Token,
}

/// Proof that [`Responder::detach`] was called for this request.
///
/// Like [`DeferPermit`], obtainable only from [`Responder::detach`] and stamped
/// with that request's routing token; returning [`Response::Detach`]`(permit)`
/// guarantees the loop will materialize a real fd and hand it, with a
/// [`Detached`], to the [`Server::set_detach_handler`] handler. A permit stashed
/// from a different request is verified at delivery and closes the connection
/// instead ([`CloseReason::HandlerClosed`]).
#[derive(Debug)]
#[must_use = "return Response::Detach(permit) from the body handler"]
pub struct DetachPermit {
    pub(super) token: Token,
}

/// Handed to the body handler for one request; the ticket for replying later.
///
/// On the synchronous path, ignore it and return [`Response::Reply`]. To offload
/// the work, call [`Responder::defer`] to detach an owned, `Send` [`Deferred`],
/// move it into your worker (thread pool, async runtime, ...), and return
/// [`Response::Defer`] with the accompanying [`DeferPermit`]. The library provides
/// no worker pool - that is the consumer's choice; it provides only the safe
/// hand-back path.
pub struct Responder {
    pub(super) token: Token,
    pub(super) tx: mpsc::Sender<Injected>,
    pub(super) shared: Arc<LoopShared>,
}

/// A `draining()` probe that outlives the [`Responder`] it came from, for
/// glue that must read the flag after a handler consumed the responder.
/// The HTTP codec is its only consumer.
#[cfg(feature = "http")]
pub(crate) struct DrainProbe {
    shared: Arc<LoopShared>,
}

#[cfg(feature = "http")]
impl DrainProbe {
    pub(crate) fn draining(&self) -> bool {
        self.shared.graceful_requested().is_some()
            || self.shared.stop_requested()
    }
}

impl Responder {
    /// Whether the server has been asked to stop, gracefully or not.
    ///
    /// Advisory: the shutdown thread sets the flag and the loop acts on it
    /// when it next wakes. Once draining, the loop reads no new request off
    /// this connection, but requests already buffered are still delivered
    /// (each sees `true` here), and the connection closes only once nothing
    /// is left outstanding. `true` therefore does not make this reply the
    /// connection's last. A protocol that wants it to be must return a close
    /// disposition - [`Response::ReplyClose`] or
    /// [`Response::ReplyVectored`]` { close: true }` - which retires the
    /// recv side and discards the buffered rest, and should say so on the
    /// wire if it can (HTTP sends `Connection: close` and flush-closes), so
    /// the peer does not reuse a connection about to go away and race the
    /// close with its next request. A close forced this way is the
    /// handler's verdict, so the close hook reports
    /// [`CloseReason::HandlerClosed`], not `ShuttingDown`, which is kept for
    /// connections the drain itself closes.
    pub fn draining(&self) -> bool {
        self.shared.graceful_requested().is_some()
            || self.shared.stop_requested()
    }

    /// A second responder for the same request, for the one dispatch step
    /// that runs the handler twice (the window exhausting a known-length
    /// stream carries the End stage too). The dispatches are sequential
    /// and at most one may defer; the shared token keeps the
    /// one-answer-per-request guard intact either way.
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

    /// Detach an owned, `Send` handle for delivering this request's reply later
    /// from any thread, plus the [`DeferPermit`] proof to return as
    /// [`Response::Defer`]`(permit)`. Move the [`Deferred`] into your worker;
    /// dropping it without calling [`Deferred::reply`] closes the connection, so
    /// a dropped/panicked worker can't leak a parked connection.
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

    /// A long-lived, `Clone + Send + Sync` handle for **pushing** unsolicited
    /// PDUs to this connection later (server-initiated messages: notifications,
    /// pub/sub events, SMB-style breaks). Independent of this request - stash it
    /// in shared state and use it from any thread for the connection's
    /// lifetime; pushes to a connection that has closed are dropped safely.
    pub fn push_handle(&self) -> PushHandle {
        PushHandle {
            slot: self.token.slot,
            generation: self.token.generation,
            tx: self.tx.clone(),
            shared: Arc::clone(&self.shared),
        }
    }

    /// **Detach** this connection: return the [`DetachPermit`] as
    /// [`Response::Detach`]`(permit)` to hand the connection's socket fd to your
    /// own worker for a blocking operation on the socket (e.g. a ZFS send/recv
    /// ioctl). The loop materializes a real fd (aliasing the pool socket) and
    /// delivers it, with a [`Detached`] handle, to the
    /// [`Server::set_detach_handler`] handler; the connection is parked until the
    /// worker calls [`Detached::resume`] (keep serving) or [`Detached::close`].
    /// Stash what the worker should do in the connection state (`&mut U`) before
    /// returning. Consumes the responder.
    pub fn detach(self) -> DetachPermit {
        DetachPermit { token: self.token }
    }
}

impl std::fmt::Debug for Responder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Responder").finish_non_exhaustive()
    }
}

// The http glue's unit tests are the only consumer: `net-server` alone
// builds these tests without them, and dead code is an error under the
// feature matrix's `-D warnings`.
#[cfg(all(test, feature = "http"))]
impl Responder {
    /// A live responder backed by a throwaway channel and wake - for unit
    /// tests that drive protocol glue (the http `step`) without a reactor.
    /// The receiver is dropped, so outcomes sent through handles minted
    /// from this responder vanish silently - the injection channel's
    /// behavior is the net layer's own tests' business, not the glue's.
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
        // `crate::sync` atomics, matching `LoopShared`'s fields, so this
        // constructs under `--cfg loom` too.
        use crate::sync::atomic::{AtomicBool, AtomicU64};
        let (tx, rx) = mpsc::channel();
        let shared = Arc::new(LoopShared {
            stop: AtomicBool::new(false),
            graceful: AtomicBool::new(false),
            grace_ms: AtomicU64::new(0),
            wake: crate::uring::wake::WakeHandle::new().expect("wake"),
        });
        let token = Token {
            slot: 0,
            generation: 1,
            req_id: 0,
        };
        (Responder { token, tx, shared }, rx)
    }

    /// [`test_responder`](Self::test_responder) keeping the loop side: the
    /// injection receiver and the wake, so a model consumes a worker outcome
    /// exactly as the reactor's drain does. Model-only, because the blocking
    /// half rides [`WakeHandle`]'s loom stand-in.
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
    /// Consume the worker's outcome the way the loop does: block on the
    /// wake (the armed `READ`), then take the queued injection - asserting
    /// it is the redelivery the http completion pass runs on.
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
/// Obtained from [`Responder::defer`]. Call [`Deferred::reply`] exactly once
/// with the reply PDU (an **empty** reply completes the request without sending
/// anything - the one-way case; [`Deferred::reply_close`] sends a final PDU
/// and then closes; [`Deferred::close`] closes the connection; dropping
/// without any of these closes it too, so a lost worker can't leak a parked
/// connection). The reply is queued and the server loop woken; it is sent on
/// the originating connection **iff that connection is still open and this
/// request is still awaiting its reply**. A reply for a request that was
/// already answered, or whose connection closed (or pool slot was recycled)
/// while the worker ran, is dropped safely - which is exactly why the ticket is
/// a slot+generation+request token, not a pointer into the connection.
#[must_use = "dropping a Deferred without replying closes the connection"]
pub struct Deferred {
    token: Token,
    tx: mpsc::Sender<Injected>,
    shared: Arc<LoopShared>,
    done: bool,
}

impl Deferred {
    /// Deliver the reply for this request. An empty reply completes the request
    /// without sending anything (one-way message). Consumes the handle.
    pub fn reply(mut self, bytes: Vec<u8>) {
        self.done = true;
        let msg = if bytes.is_empty() {
            Injected::Done(self.token)
        } else {
            Injected::Reply(self.token, bytes)
        };
        // The server owns the receiver for its whole life; a send error just
        // means it has already shut down, in which case the reply is moot.
        let _ = self.tx.send(msg);
        self.shared.wake.poke();
    }

    /// Deliver the reply and then close the connection once it - and
    /// everything queued before it - has flushed: the deferred twin of
    /// [`Response::ReplyClose`] (the worker speaks last). An empty reply
    /// queues no PDU and closes after flushing what is already queued. The
    /// close hook reports [`CloseReason::WorkerClosed`], as for
    /// [`Deferred::close`]. Consumes the handle.
    pub fn reply_close(mut self, bytes: Vec<u8>) {
        self.done = true;
        let _ = self.tx.send(Injected::ReplyClose(self.token, bytes));
        self.shared.wake.poke();
    }

    /// Close the connection instead of replying (e.g. the worker decided the
    /// request is fatal). Consumes the handle.
    pub fn close(mut self) {
        self.done = true;
        let _ = self.tx.send(Injected::Close(self.token));
        self.shared.wake.poke();
    }

    /// Re-deliver this request to the body handler instead of supplying bytes
    /// -- for protocol glue that retained the request in its connection state
    /// (`&mut U`) and completes it on the server thread, where the state and
    /// the serialization context live. The handler runs again with an empty
    /// frame (the original bytes were consumed at first delivery), counted as
    /// a fresh delivery; it may reply, defer again, or close. Rides the same
    /// token gauntlet as a reply: a redelivery for a request already answered,
    /// or whose connection closed or slot was recycled, is dropped safely.
    /// Consumes the handle.
    pub fn redeliver(mut self) {
        self.done = true;
        let _ = self.tx.send(Injected::Redeliver(self.token));
        self.shared.wake.poke();
    }
}

impl Drop for Deferred {
    fn drop(&mut self) {
        if !self.done {
            // Lost worker (dropped/panicked without replying): close the parked
            // connection rather than leak its pool slot forever.
            let _ = self.tx.send(Injected::Close(self.token));
            self.shared.wake.poke();
        }
    }
}

/// The ticket a **detach** worker uses to hand a connection back to the server
/// after its blocking operation on the furnished fd.
///
/// Furnished - owning a real socket fd aliasing the pool socket - to the
/// [`Server::set_detach_handler`] handler for one detached connection. Move it
/// to your own worker, do the blocking work on [`Detached::raw_fd`] (e.g.
/// `lzc_send`/`lzc_receive`), then call [`Detached::resume`] to re-arm serving
/// (keep-alive) or [`Detached::close`] to close. Dropping it without either
/// **closes** the connection, so a panicked/lost worker can't leak the parked
/// slot. The handle owns the furnished fd and closes it when consumed/dropped;
/// the pool socket survives (the loop keeps serving on the registered
/// descriptor).
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
    /// The furnished socket fd (aliasing the connection's pool socket), for the
    /// worker's blocking operation. Valid until this handle is consumed/dropped.
    pub fn raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    /// The worker finished; **resume** serving the connection (re-arm the recv
    /// keep-alive loop). Consumes the handle (closing the furnished fd).
    ///
    /// The furnished fd **shares the pool socket's file description**, so any
    /// file-status flag the worker changed on it outlives the detach. The one
    /// that matters is `O_NONBLOCK` - a worker doing a blocking transfer
    /// typically clears it, and a resumed connection whose socket went
    /// blocking would defeat the splice path's `-EAGAIN` -> readiness-poll
    /// slow-loris guard (`tcp_splice_read` takes its wait mode from the
    /// file's `O_NONBLOCK`) - so `resume` restores `O_NONBLOCK` itself before
    /// handing the connection back. Recv/send are unaffected either way
    /// (io_uring passes `MSG_DONTWAIT` per op).
    pub fn resume(mut self) {
        // Best-effort: on any fcntl failure the fd is dead or dying, and the
        // resumed loop's next op surfaces that as a normal close.
        // SAFETY: `self.fd` is a live owned fd; F_GETFL/F_SETFL read/write no
        // user memory.
        unsafe {
            let fl = libc::fcntl(self.fd.as_raw_fd(), libc::F_GETFL);
            if fl >= 0 && fl & libc::O_NONBLOCK == 0 {
                libc::fcntl(
                    self.fd.as_raw_fd(),
                    libc::F_SETFL,
                    fl | libc::O_NONBLOCK,
                );
            }
        }
        self.done = true;
        self.signal(true);
    }

    /// The worker finished (or decided to end the connection); **close** it.
    /// Consumes the handle (closing the furnished fd).
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
        // The server owns the receiver for its whole life; a send error just
        // means it has shut down, in which case the outcome is moot.
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

/// A `Clone + Send + Sync` handle for pushing unsolicited PDUs to one
/// connection, obtained from [`Responder::push_handle`].
///
/// A push is a complete, caller-framed PDU queued behind any pending replies
/// (FIFO, one `MSG_WAITALL` send at a time - pushes never interleave with
/// replies mid-PDU). Fire-and-forget: a push to a connection that has closed
/// (or was recycled) is dropped, and a push that would overflow
/// `ServerConfig::max_send_backlog` closes the connection as a slow consumer.
/// Pushes are discarded while the server is draining. An empty push is a no-op.
///
/// Ordering note: pushes travel through the same queue-and-wake path as
/// deferred replies, so a push issued *inside* a body handler is queued after
/// that handler's own inline `Reply`.
#[derive(Clone)]
pub struct PushHandle {
    slot: u32,
    generation: u64,
    tx: mpsc::Sender<Injected>,
    shared: Arc<LoopShared>,
}

impl PushHandle {
    /// Queue `bytes` as an unsolicited PDU on this connection and wake the
    /// server loop. Empty `bytes` is a no-op.
    ///
    /// Backpressure note: pushes cross to the loop on an **unbounded** internal
    /// channel, drained on each wake. `ServerConfig::max_send_backlog` bounds
    /// the bytes queued *on a connection* (evicting a slow reader), but not this
    /// channel - a producer that sustainedly pushes faster than the single loop
    /// thread drains grows memory without limit. Deferred replies are self-
    /// limiting (at most `max_in_flight_requests` outstanding per connection);
    /// only pushes are open-ended, so pace them to the loop or gate them behind
    /// the consumer's own bound.
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

    /// Close this connection, from any thread, outside any request cycle --
    /// session revocation, an administrative kick, a cross-connection
    /// takeover (an SMB `PreviousSessionId`-style teardown). Everything
    /// already queued - including pushes issued before this call - flushes
    /// first (whole-PDU FIFO, bounded by `ServerConfig::send_timeout` when
    /// set); nothing further is read, delivered, or queued after it. The
    /// close hook reports [`CloseReason::PushClosed`].
    ///
    /// Fire-and-forget like [`PushHandle::push`]: closing a connection that
    /// has already closed (or whose slot was recycled) is a no-op, as are
    /// repeat calls. On a connection parked under a detach worker the close
    /// lands at [`Detached::resume`] - after the pushes held during the
    /// window - since the worker owns the raw stream mid-detach
    /// ([`Detached::close`] is the worker's own path).
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

// `Deferred` is moved to worker threads and `PushHandle` is shared across
// them, so both must be `Send` (and the handle `Sync`).
const _: fn() = || {
    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}
    assert_send::<Deferred>();
    assert_send::<Detached>();
    assert_send::<PushHandle>();
    assert_sync::<PushHandle>();
};

/// A snapshot of server counters ([`Server::stats_handle`]). Each counter is
/// individually exact, but they are read independently (relaxed atomics), so a
/// snapshot is not a single consistent cut: derived relations across counters
/// (e.g. `accepted - closed == active`) may not hold at the instant it is
/// taken, only settle in the steady state.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default)]
pub struct ServerStats {
    /// Connections accepted (having passed the accept handler).
    pub accepted: u64,
    /// Connections rejected by the accept handler (`None`).
    pub rejected: u64,
    /// Connections shed: pool full, out of range, arriving during shutdown, or
    /// a failed credential fetch.
    pub shed: u64,
    /// Transient accept errors (resource pressure) that triggered a backoff
    /// re-arm instead of terminating the server.
    pub accept_retries: u64,
    /// Listeners whose `shutdown(SHUT_RD)` failed at the start of a graceful
    /// drain. Non-zero means refuse-on-connect did not take effect for that
    /// listener: its backlog keeps filling with clients nobody will answer
    /// until the fd closes at server drop.
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
    /// Send operations completed. With reply coalescing one op can carry
    /// several PDUs, so this is <= `replies + pushes`.
    pub send_ops: u64,
    /// Receive operations that completed with data (header and body reads).
    pub recv_ops: u64,
    /// Payload bytes received.
    pub bytes_in: u64,
    /// Payload bytes sent.
    pub bytes_out: u64,
    /// Ring buffers currently held - a connection mid-message, or a file
    /// body's chunk in flight or queued - when
    /// [`ServerConfig::recv_pool`](super::ServerConfig::recv_pool)
    /// is set; always `0` otherwise.
    ///
    /// A buffer is held only while a message is arriving, so at rest this
    /// settles to zero however many connections are open - that it does is
    /// the property the pool exists for. A value that tracks the connection
    /// count instead means buffers are not being handed back.
    pub recv_bufs_lent: u32,
    /// Buffers allocated across both registered rings (receive and file
    /// body). Grows a doubling at a time when a completion finds a ring dry
    /// and drains back after idle rounds, so a steady value is a pool at
    /// its working set and a climbing one is a pool still finding it - but
    /// one that climbs while [`recv_bufs_lent`](ServerStats::recv_bufs_lent)
    /// stays flat is a **leak**, not sizing: ids are being stranded (the
    /// kernel consumed their descriptors, nothing returned them) and the
    /// pool is replacing them, which sizing noise never looks like. That
    /// signature needs traffic behind it - a strand on a quiet server
    /// moves neither gauge, which is what the debug-build drain check
    /// against the kernel's consumer head exists to catch.
    pub recv_bufs_total: u32,
    /// Reads parked on the [`recv_shortage_retry`] backoff because the
    /// buffer pool was genuinely exhausted - at its registered bound with
    /// every buffer lent. Counts parks, not connections: one connection
    /// waiting through several backoff periods counts each retry that
    /// found the pool still dry. Zero under any load the pool's growth
    /// can answer; a nonzero value is the backpressure path engaging.
    ///
    /// [`recv_shortage_retry`]: super::ServerConfig::recv_shortage_retry
    pub recv_shortage_parks: u64,
    /// Provided-buffer rings this server asked for and did not get because
    /// `RLIMIT_MEMLOCK` refused their region.
    ///
    /// **Nonzero means permanently degraded, not absent.** Registering a
    /// ring is charged page by page against that limit
    /// (`io_register_pbuf_ring` -> `io_create_region` -> `__io_account_mem`,
    /// `io_uring/rsrc.c:39-57`) - the same path the SQ/CQ is charged on,
    /// where the failure *is* reported. Refused here, every read falls back
    /// to the per-read allocation the ring exists to remove (measured at
    /// 1.22 -> 2.23 allocations per 128 KiB streamed window) while the
    /// server answers 200 and every other counter looks healthy. The remedy
    /// is the operator's: raise the limit (`LimitMEMLOCK=` in the unit, or
    /// `setrlimit` before [`Server::bind`](super::Server::bind)).
    ///
    /// It is not decided by this server's own configuration.
    /// `__io_account_mem` charges `user->locked_vm`, a **per-uid** counter,
    /// so an unrelated process of the same user can push a previously
    /// healthy server into the refusing band on its next restart.
    ///
    /// A kernel with no provided-buffer rings at all answers
    /// `EINVAL`/`ENOSYS` and is **not** counted here: falling back silently
    /// is right for that, and conflating the two is what left this
    /// invisible. Distinguishing it from a pool that was never asked for
    /// takes this counter, because
    /// [`recv_bufs_total`](ServerStats::recv_bufs_total) reads 0 either way.
    pub buf_rings_refused_memlock: u64,
}

/// A `Clone + Send + Sync` handle for reading a running server's counters from
/// any thread ([`Server::stats_handle`]).
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
            drain_listener_shutdown_failed: s
                .drain_listener_shutdown_failed
                .load(Ordering::Relaxed),
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
            recv_bufs_total: s.recv_bufs_total.load(Ordering::Relaxed) as u32,
            buf_rings_refused_memlock: s
                .buf_rings_refused_memlock
                .load(Ordering::Relaxed),
        }
    }
}

/// A reply handed back by an offloaded worker, delivered on the next loop wake.
pub(super) enum Injected {
    /// Send these bytes as the request's reply.
    Reply(Token, Vec<u8>),
    /// Send these bytes as the request's **final** reply, then close once the
    /// connection's send queue drains ([`Deferred::reply_close`]). Empty
    /// bytes queue no PDU: flush what is queued and close.
    ReplyClose(Token, Vec<u8>),
    /// The request is complete with nothing to send (one-way message).
    Done(Token),
    /// Close the connection (explicit worker decision, or a dropped/lost
    /// [`Deferred`]).
    Close(Token),
    /// Run the body handler again for this request ([`Deferred::redeliver`])
    /// -- the frame is empty; the consumer's protocol glue retained what it
    /// needs in its connection state.
    Redeliver(Token),
    /// An unsolicited push ([`PushHandle::push`]) - not tied to any request.
    Push {
        slot: u32,
        generation: u64,
        bytes: Vec<u8>,
    },
    /// Close the connection once everything already queued on it has flushed
    /// ([`PushHandle::close`]) - not tied to any request.
    PushClose { slot: u32, generation: u64 },
    /// A detached connection's worker signalled **resume** - re-arm serving.
    DetachResume { slot: u32, generation: u64 },
    /// A detached connection's worker signalled **close** (or dropped its
    /// [`Detached`] handle unresolved).
    DetachClose { slot: u32, generation: u64 },
    /// A consumer's own message for its control hook
    /// ([`ControlHandle::send`]) - not tied to any connection.
    Control(Box<dyn std::any::Any + Send>),
}

/// A `Clone + Send + Sync` handle for running a consumer's own work on the
/// server thread ([`Server::control_handle`]).
///
/// The loop owns the protocol handlers and everything they capture, and
/// runs them on one thread; nothing another thread holds can reach that
/// state directly. A control message is the way in: it crosses on the
/// injection channel, and the loop hands it to the hook installed with
/// [`Server::set_control_hook`] between two batches of completions - so a
/// swap the hook performs is never observed half-done by a request, and
/// requests already answered keep sending through it. The hook was built on
/// the loop thread, so it can share state with the handlers (an `Rc`) that
/// the message itself, which must be `Send`, cannot carry.
///
/// Delivered during a graceful drain too (a reload applied to a draining
/// server is harmless, and the consumer may want to know it was seen). After
/// the server stops the message is dropped, silently, like a late push.
#[derive(Clone, Debug)]
pub struct ControlHandle {
    pub(super) tx: mpsc::Sender<Injected>,
    pub(super) shared: Arc<LoopShared>,
}

impl ControlHandle {
    /// Queue `message` for the control hook and wake the loop. Messages
    /// from one handle arrive in the order they were sent, interleaved
    /// first-in first-out with deferred replies and pushes. Without a hook
    /// installed the message is dropped when it is reached.
    pub fn send(&self, message: Box<dyn std::any::Any + Send>) {
        let _ = self.tx.send(Injected::Control(message));
        self.shared.wake.poke();
    }
}

/// A `Clone + Send + Sync` stop signal for a running [`Server`] (an extra
/// clone makes a good panic guard: shut down on drop so a failing driver
/// thread cannot strand the loop).
#[derive(Clone, Debug)]
pub struct ShutdownHandle {
    pub(super) shared: Arc<LoopShared>,
}

impl ShutdownHandle {
    /// Stop the server loop immediately: every in-flight operation is
    /// cancelled (requests mid-read, replies mid-send, deferred work is
    /// abandoned) and `serve_forever` returns. Safe to call from any thread and
    /// more than once. Infallible: it is a flag store plus an eventfd poke
    /// whose errors are meaningless by design (a full counter has already
    /// signalled; a closed fd means the server is gone).
    pub fn shutdown(&self) {
        self.shared.request_stop();
        self.shared.wake.poke();
    }

    /// Stop the server **gracefully**: every listener is shut down so a new
    /// connect is refused at once (not queued in a backlog nobody will
    /// drain), idle connections close immediately, but requests already in
    /// flight - reads in progress, work deferred to workers, and queued
    /// replies - are allowed to finish (each connection closes as it
    /// quiesces; keep-alive does not admit new requests).
    ///
    /// **Whether a replacement server can bind the same address during the
    /// drain depends on the address family.** A TCP listener can be replaced,
    /// but not because it stops listening: `__inet_bind` set
    /// `SOCK_BINDPORT_LOCK` for the explicit port
    /// (`net/ipv4/af_inet.c:557`), and `tcp_set_state`'s `TCP_CLOSE` arm
    /// skips `inet_put_port` while that is set (`net/ipv4/tcp.c:2998-3000`),
    /// so the draining socket keeps its port reservation until its fd
    /// closes. The rebind succeeds only because both sockets carry
    /// `SO_REUSEADDR`, which this crate sets for every TCP listener
    /// (`listen.rs`). A **Unix** listener cannot be replaced: it stays
    /// `TCP_LISTEN` with `RCV_SHUTDOWN` (see `begin_drain`), and its address
    /// is a filesystem node that `shutdown(2)` does not remove - so a bind
    /// to the same path fails `EADDRINUSE` for the whole grace period unless
    /// the replacement unlinks it first (`ServerConfig::unlink_unix`).
    ///
    /// If the drain has not
    /// completed within `grace`, whatever remains is cancelled as in
    /// [`ShutdownHandle::shutdown`]. A zero `grace` is exactly `shutdown()`.
    /// Safe to call from any thread; a concurrent hard `shutdown` wins.
    /// Infallible, like [`ShutdownHandle::shutdown`].
    pub fn shutdown_graceful(&self, grace: Duration) {
        if grace.is_zero() {
            return self.shutdown();
        }
        let ms = u64::try_from(grace.as_millis()).unwrap_or(u64::MAX);
        self.shared.request_graceful(ms);
        self.shared.wake.poke();
    }
}
