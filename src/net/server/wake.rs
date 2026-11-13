//! The wake-eventfd path: draining work injected by other threads (deferred replies, pushes, kTLS handshake outcomes,
//! shutdown requests) and the graceful-drain state machine a shutdown request can enter. Arming the wake `READ` and the
//! drain-quiescence check are role-agnostic and live on [`Reactor`](crate::net::core::reactor); the delivery here is
//! server code.

use super::Server;
use super::handles::Injected;
use super::io::Delivery;
use crate::errno;
use crate::net::core::conn::{Op, pack};
use crate::net::core::handles::stat;
use crate::net::core::protocol::{CloseReason, Framing, SendBuf};
use crate::net::core::table::SlotState;
use crate::net::server::protocol::{Incoming, Request, Response};
use crate::uring::sys::*;
use std::os::fd::AsRawFd;

// Wake-driven work can re-enter any stage - kTLS accept outcomes install connections and deferred replies re-enter the
// pump - so this block carries the full handler bounds.
impl<U, AcceptFn, HeaderFn, BodyFn> Server<U, AcceptFn, HeaderFn, BodyFn>
where
    AcceptFn: FnMut(Incoming<'_>) -> Option<U>,
    HeaderFn: FnMut(&[u8], &mut U) -> Framing,
    BodyFn: FnMut(Request<'_, U>) -> Response,
{
    pub(super) fn on_wake(&mut self) -> errno::Result<()> {
        // The READ already drained the eventfd counter. Deliver what the wake announced, then re-arm unless stopping.
        //
        // Finished fs offloads go first, so a continuation that answers through a `Deferred` has its reply drained in
        // this pass, and they go unconditionally, as in the standalone host (`uring_fs::host`'s `TAG_WAKE` arm gates
        // only the re-arm). This drain is the only consumer of the host refusal queue (`FsCore::refuse`), and the
        // teardown routes reaped CQEs to `on_drain_cqe` without touching it, so a refusal gated out here dies unfired
        // with its callback and payload. Gate the re-arm and the injection drain, never `drain_fs_offloads`.
        self.drain_wake_sources()?;
        if !self.core.stopping() {
            self.core.arm_wake()?;
        }
        Ok(())
    }

    /// Drain every wake source without re-arming the wake `READ`: `Op::Wake` re-arms after consuming the read, and
    /// `Park::Drain` (`WakeHandle::park`) runs this with the read still armed.
    pub(super) fn drain_wake_sources(&mut self) -> errno::Result<()> {
        #[cfg(feature = "uring-fs")]
        self.drain_fs_offloads()?;
        if !self.core.stopping() {
            self.drain_injections()?;
            self.drain_handshake_outcomes()?;
            if self.core.engine.shared.graceful_requested().is_some() && !self.core.draining {
                self.begin_drain()?;
            }
        }
        Ok(())
    }

    /// Deliver the results of finished fs offload jobs ([`FsConn::offload`] and the hybrid directory lister), each with
    /// a fresh owner-scoped `FsConn` for an owner that may already be gone, so a file one opens is its own to close.
    /// This is also where the fs reactor's woken tasks are polled (`deliver_pool_completions` ends in `task::in_pass`'s
    /// drain). Without it an offloaded request never resolves and a walk's `DIR*` leaks.
    #[cfg(feature = "uring-fs")]
    fn drain_fs_offloads(&mut self) -> errno::Result<()> {
        if let Some(fs) = self.fs.as_mut() {
            crate::uring_fs::core::deliver_pool_completions(fs, &mut self.core.engine);
            // A job that digested a leased recv buffer released its share as its completion was taken above, and a
            // share dropped anywhere else, on any thread, queued its id and poked this wake. Both come back to the pool
            // here, the one place that can reach it.
            let released = fs.take_pool_releases();
            if !released.is_empty() {
                if let Some(pool) = self.core.recv_bufs.as_mut() {
                    for bid in released {
                        pool.release(bid);
                    }
                }
                self.core.sync_recv_buf_stats();
            }
        }
        Ok(())
    }
}

// The drain state machine runs no handler code - bounds-free.
impl<U, AcceptFn, HeaderFn, BodyFn> Server<U, AcceptFn, HeaderFn, BodyFn> {
    /// Drop an outcome that reaches no request. A reply marked recycled still sends its storage to the ring's body
    /// pool, as one queued on a connection that closes does, and leaves the count of held bytes.
    fn spill(&self, msg: Injected) {
        if let Injected::ReplyRecycled(_, bytes) = msg {
            self.unhand(bytes.capacity());
            if let Some(pool) = self.core.body_pool.as_ref() {
                pool.borrow_mut().give(bytes);
            }
        }
    }

    /// Take the `bytes` of a reply that `Deferred::reply_recycled` handed to the loop off the figure its hand-off added
    /// to the count of held bytes. Nothing has touched the reply's storage since, so its capacity is what was added.
    fn unhand(&self, bytes: usize) {
        self.core
            .engine
            .shared
            .handed
            .fetch_sub(bytes, std::sync::atomic::Ordering::Relaxed);
    }

    /// Enter graceful drain: stop accepting, close idle connections, let in-flight requests (reads in progress,
    /// deferred work, queued sends) finish, and arm the grace-period deadline that escalates to a hard stop.
    fn begin_drain(&mut self) -> errno::Result<()> {
        self.core.draining = true;
        // Before the listeners stop: no ring of a spread sends here once this is seen, and one sent before is shed as a
        // drain sheds.
        if let Some(joined) = self.core.spread.as_mut() {
            joined.close();
        }

        // Refuse new connections now, not when the fd closes at drop. Cancelling the accept only stops this loop
        // dequeuing, while the kernel keeps completing handshakes into a backlog nobody answers. A TCP listener leaves
        // TCP_LISTEN (`inet_shutdown` -> `tcp_disconnect` -> `tcp_set_state(TCP_CLOSE)`), which takes it out of its
        // `reuse_port` group and resets what it had queued (`inet_csk_listen_stop`), so a connect is refused or lands
        // on a sibling. A unix listener keeps TCP_LISTEN with RCV_SHUTDOWN set, so `unix_stream_connect` refuses, while
        // accept still dequeues the queued embryos for `accept_connection` to shed. `on_accept` ignores the TCP
        // accept's `-EINVAL` and the unix one's final `-ECANCELED` while draining. Best effort, since a failure only
        // leaves the backlog filling until the fd closes.
        //
        // **`draining` must already be set when this runs.** `accept_error_is_fatal` classes the TCP accept's `-EINVAL`
        // as fatal, and only `on_accept`'s early return for a draining server keeps it from ending `serve_forever`.
        debug_assert!(
            self.core.draining,
            "listeners are shut down only once `draining` is set: the \
             accept's -EINVAL is fatal to `on_accept` otherwise"
        );
        for l in &self.listeners {
            // SAFETY: `l.fd` is a live listening socket this server owns;
            // shutdown(2) touches no memory.
            let rc = unsafe { libc::shutdown(l.fd.as_raw_fd(), libc::SHUT_RD) };
            if rc != 0 {
                // Best effort, but not silent: refuse-on-connect did not take effect for this listener and its backlog
                // keeps filling until the fd closes, which an operator cannot otherwise see.
                stat!(self.core, drain_listener_shutdown_failed);
            }
        }

        // Stop accepting by cancelling each listener's multishot accept. One parked on a full pool has nothing to
        // cancel, and the re-arm guards check `draining`, so it stays down either way.
        for lidx in 0..self.listeners.len() as u32 {
            let accept_ud = pack(Op::Accept, lidx, 0);
            self.core.stage(pack(Op::Cancel, 0, 0), move |sqe| {
                sqe.opcode = IORING_OP_ASYNC_CANCEL;
                sqe.fd = -1;
                sqe.addr = accept_ud;
            })?;
        }

        // Grace-period deadline (a standalone TIMEOUT op).
        let ms = self.core.engine.shared.graceful_requested().unwrap_or(0).max(1);
        self.core.pads.deadline = KernelTimespec {
            tv_sec: (ms / 1000) as i64,
            tv_nsec: ((ms % 1000) * 1_000_000) as i64,
        };
        let ts = std::ptr::addr_of!(self.core.pads.deadline) as u64;
        self.core.stage(pack(Op::Deadline, 0, 0), move |sqe| {
            sqe.opcode = IORING_OP_TIMEOUT;
            sqe.addr = ts;
            sqe.len = 1; // exactly one timespec, per the kernel
        })?;

        // One sweep over the table. Close idle serving connections now, through a cancel of their parked recv whose
        // `-ECANCELED` drives the normal close, and leave connections with work in flight to drain through `pump` and
        // `on_send`. Connections parked mid-handshake hold a socket with no op to cancel, so they are torn down here,
        // and a late worker callback finds a new generation.
        let mut idle: Vec<(u32, u32, bool)> = Vec::new();
        let mut tls_parked: Vec<u32> = Vec::new();
        for (slot, entry) in self.core.table.iter() {
            match &entry.state {
                SlotState::Serving(c) if !c.closing => {
                    let parked = c.recving && c.recv_idle;
                    // A connection mid-splice has work in flight though `recving` is false. Treated as quiesced, the
                    // drain would cancel a healthy transfer and truncate the body in the consumer's pipe, so it drains
                    // through `pump`, and a wedged one is cut off by the grace deadline.
                    let quiesced = !c.recving
                        && !c.sending
                        && !c.splicing
                        && !c.splice_polling
                        && c.outstanding == 0
                        && !c.has_pending_send();
                    if parked || quiesced {
                        // Kernel-side use (cancel by user_data / close_conn) -> low 32.
                        idle.push((slot, entry.generation as u32, parked));
                    }
                }
                SlotState::TlsParked(_) => tls_parked.push(slot),
                _ => {}
            }
        }
        for (slot, generation, parked) in idle {
            if parked {
                let target = pack(Op::RecvHeader, slot, generation);
                self.core.stage(pack(Op::Cancel, 0, 0), move |sqe| {
                    sqe.opcode = IORING_OP_ASYNC_CANCEL;
                    sqe.fd = -1;
                    sqe.addr = target;
                })?;
            } else {
                self.core.close_conn(slot, generation, CloseReason::ShuttingDown)?;
            }
        }
        for slot in tls_parked {
            self.core.table.take_tls_parked(slot);
            let generation = self.core.table.generation_low(slot);
            self.core.submit_teardown(slot, generation, true)?;
        }

        self.core.maybe_finish_drain();
        Ok(())
    }
}

// Deferred-reply/push delivery re-enters the pump, so it needs the framer and body-handler bounds (never the accept
// handler).
impl<U, AcceptFn, HeaderFn, BodyFn> Server<U, AcceptFn, HeaderFn, BodyFn>
where
    HeaderFn: FnMut(&[u8], &mut U) -> Framing,
    BodyFn: FnMut(Request<'_, U>) -> Response,
{
    /// Deliver replies handed back by offloaded workers via [`Deferred`]. Each is applied to its originating connection
    /// only if that connection is still open (generation check) **and** its request is still awaiting a deferred reply
    /// (`take_deferred`) - so a reply for a closed connection, a recycled slot, or a request that was already answered
    /// inline is dropped instead of duplicated or misdelivered.
    fn drain_injections(&mut self) -> errno::Result<()> {
        while let Ok(msg) = self.mailbox.inject_rx.try_recv() {
            // A control message concerns no connection, so it needs no liveness check, and it runs here between
            // completion batches whatever the loop's state, a drain included.
            if let Injected::Control(message) = msg {
                if let Some(hook) = self.handlers.control.as_mut() {
                    hook(message);
                }
                continue;
            }
            // Pushes are request-independent: no `take_deferred` gating, no `outstanding` accounting - just the
            // liveness + backlog checks.
            if let Injected::Push {
                slot,
                generation,
                bytes,
            } = msg
            {
                if self.core.draining {
                    continue; // shutting down
                }
                // A push reaches the connection in any live state, since `PushHandle` promises the connection's
                // lifetime. A serving connection sends now, and a detached one only queues, since the worker owns the
                // raw stream, and flushes at resume.
                let (overflow, serving) = {
                    // `self.core.table` vs `self.core.cfg`: disjoint borrows.
                    let Some((conn, serving)) = self.core.table.push_conn_mut(slot, generation) else {
                        continue; // connection gone (or slot recycled)
                    };
                    if conn.close_on_flush.is_some() {
                        // Flush-closing, so the farewell is final and a later push is dropped.
                        continue;
                    }
                    if conn.queued_bytes() + bytes.len() > self.core.cfg.max_send_backlog {
                        if !serving {
                            // Can't tear down under the worker; evict with `SendBacklog` at resume instead.
                            conn.evict_on_resume = true;
                        }
                        (true, serving)
                    } else {
                        conn.enqueue_push(bytes);
                        (false, serving)
                    }
                };
                if overflow && serving {
                    // Slow consumer, evict rather than queue without bound.
                    self.core
                        .close_conn(slot, generation as u32, CloseReason::SendBacklog)?;
                } else if !overflow && serving {
                    self.core.kick_send(slot, generation as u32)?;
                }
                continue;
            }
            // A cross-thread close (`PushHandle::close`) reaches any live state, like a push. A serving connection
            // flushes and closes, and one parked under a detach worker is only marked, the close landing at resume.
            // Processed while draining too, since it can only speed the drain.
            if let Injected::PushClose { slot, generation } = msg {
                let serving = {
                    let Some((conn, serving)) = self.core.table.push_conn_mut(slot, generation) else {
                        continue; // connection gone (or slot recycled)
                    };
                    if conn.teardown_owns_slot() {
                        continue; // already closing (repeat close: a no-op)
                    }
                    conn.close_on_flush = Some(CloseReason::PushClosed);
                    serving
                };
                if serving {
                    self.core.drive_flush_close(slot, generation as u32)?;
                }
                continue;
            }
            // Detach outcomes are slot-scoped, with the full u64 generation since a worker may hold the handle across
            // recycles. Reattach only a slot still detached, so a stale or duplicate outcome is inert, then resume
            // serving or close.
            if let Injected::DetachResume { slot, generation } = msg {
                if self.core.table.generation(slot) == generation && self.core.table.reattach(slot) {
                    // Pushes queued during the detach flush now, and an overflow during it evicts now, since neither
                    // could act under the worker.
                    let (evict, flush, pending) = {
                        let conn = self.core.table.conn_mut(slot);
                        (
                            std::mem::take(&mut conn.evict_on_resume),
                            conn.close_on_flush.is_some(),
                            conn.has_pending_send(),
                        )
                    };
                    if evict {
                        self.core
                            .close_conn(slot, generation as u32, CloseReason::SendBacklog)?;
                        continue;
                    }
                    if flush {
                        // A `PushHandle::close` that landed during the detach. Flush what was held, the pushes from the
                        // window ahead of it, then close.
                        self.core.drive_flush_close(slot, generation as u32)?;
                        continue;
                    }
                    if pending {
                        self.core.kick_send(slot, generation as u32)?;
                    }
                    self.pump(slot, generation as u32)?;
                }
                continue;
            }
            if let Injected::DetachClose { slot, generation } = msg {
                if self.core.table.generation(slot) == generation && self.core.table.reattach(slot) {
                    self.core
                        .close_conn(slot, generation as u32, CloseReason::WorkerClosed)?;
                }
                continue;
            }
            let token = match &msg {
                Injected::Reply(t, _)
                | Injected::ReplyRecycled(t, _)
                | Injected::ReplyClose(t, _)
                | Injected::Done(t)
                | Injected::Close(t)
                | Injected::Redeliver(t) => *t,
                Injected::Push { .. }
                | Injected::PushClose { .. }
                | Injected::DetachResume { .. }
                | Injected::DetachClose { .. }
                | Injected::Control(_) => {
                    unreachable!("handled above")
                }
            };
            if !self.core.table.slot_matches(token.slot, token.generation) {
                self.spill(msg);
                continue; // connection gone (or slot recycled)
            }
            {
                let conn = self.core.table.conn(token.slot);
                // Flush-closing: the farewell is final - a worker outcome landing after it is dropped, exactly like a
                // late push (the request it resolves dies with the connection). `closing` is the same rule for the
                // teardown that does not flush, and `pump_gate` already refuses one for it. A `redeliver` slipped past
                // here re-enters the body handler mid-teardown, and a `Response::Detach` from that rerun parks the slot
                // with an op still outstanding, which `on_closed` then frees untracked.
                if conn.teardown_owns_slot() {
                    self.spill(msg);
                    continue;
                }
            }
            if !self.core.table.conn_mut(token.slot).take_deferred(token.req_id) {
                self.spill(msg);
                continue; // request already answered - stale Deferred
            }
            match msg {
                Injected::Reply(_, bytes) => {
                    // Queue the deferred reply behind any already-queued ones and start sending if the send side is
                    // idle. `on_send` drops the request's `outstanding` count once flushed.
                    self.core.table.conn_mut(token.slot).enqueue_reply(bytes);
                    self.core.kick_send(token.slot, token.generation as u32)?;
                }
                Injected::ReplyRecycled(_, bytes) => {
                    // As `Reply`, marked so its storage goes home once sent, and off the hand-off's figure as the
                    // queueing puts it on the ring's count.
                    self.unhand(bytes.capacity());
                    self.core
                        .table
                        .conn_mut(token.slot)
                        .enqueue_reply(SendBuf::recycled(bytes));
                    self.core.kick_send(token.slot, token.generation as u32)?;
                }
                Injected::ReplyClose(_, bytes) => {
                    // The worker speaks last: queue its final PDU (nothing, when empty) and flush-close - the deferred
                    // twin of `Response::ReplyClose`, reported as `WorkerClosed` like `Deferred::close`.
                    {
                        let conn = self.core.table.conn_mut(token.slot);
                        if bytes.is_empty() {
                            // No PDU: retire the request's in-flight count here (a queued reply is retired by
                            // `on_send`).
                            conn.outstanding = conn.outstanding.saturating_sub(1);
                        } else {
                            conn.enqueue_reply(bytes);
                        }
                        conn.close_on_flush = Some(CloseReason::WorkerClosed);
                    }
                    self.core.drive_flush_close(token.slot, token.generation as u32)?;
                }
                Injected::Done(_) => {
                    // Complete with nothing to send: free the in-flight slot and resume reading if the cap had paused
                    // it.
                    let conn = self.core.table.conn_mut(token.slot);
                    conn.outstanding = conn.outstanding.saturating_sub(1);
                    self.pump(token.slot, token.generation as u32)?;
                }
                Injected::Close(_) => {
                    self.core
                        .close_conn(token.slot, token.generation as u32, CloseReason::WorkerClosed)?;
                }
                Injected::Redeliver(_) => {
                    // The worker asks for a second delivery instead of supplying bytes. Retire the parked request's
                    // count, then run the body handler again over the empty current frame, which may reply, defer again
                    // or close. It runs during a graceful drain like a `Reply`, since the drain promises deferred work
                    // finishes.
                    {
                        let conn = self.core.table.conn_mut(token.slot);
                        conn.outstanding = conn.outstanding.saturating_sub(1);
                    }
                    self.deliver_one(token.slot, token.generation as u32, Delivery::Redelivery)?;
                    self.pump(token.slot, token.generation as u32)?;
                }
                Injected::Push { .. }
                | Injected::PushClose { .. }
                | Injected::DetachResume { .. }
                | Injected::DetachClose { .. }
                | Injected::Control(_) => {
                    unreachable!("handled above")
                }
            }
        }
        Ok(())
    }
}
