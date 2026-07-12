//! The wake-eventfd path: draining work injected by other threads (deferred
//! replies, pushes, kTLS handshake outcomes, shutdown requests) and the
//! graceful-drain state machine a shutdown request can enter. Arming the wake
//! `READ` and the drain-quiescence check are role-agnostic and live on
//! [`Reactor`](crate::net::core::reactor); the delivery here is server code.

use super::handles::Injected;
use super::Server;
use crate::errno;
use crate::net::core::conn::{pack, Op};
use crate::net::core::protocol::{CloseReason, Framing};
use crate::net::core::sys::*;
use crate::net::core::table::SlotState;
use crate::net::server::protocol::{Incoming, Request, Response};
use std::sync::atomic::Ordering;

// Wake-driven work can re-enter any stage — kTLS accept outcomes install
// connections and deferred replies re-enter the pump — so this block carries
// the full handler bounds.
impl<U, AcceptFn, HeaderFn, BodyFn> Server<U, AcceptFn, HeaderFn, BodyFn>
where
    AcceptFn: FnMut(Incoming<'_>) -> Option<U>,
    HeaderFn: FnMut(&[u8], &mut U) -> Framing,
    BodyFn: FnMut(Request<'_, U>) -> Response,
{
    pub(super) fn on_wake(&mut self) -> errno::Result<()> {
        // The READ already drained the eventfd counter into `pads.wake_buf`. A
        // poke means a shutdown request and/or replies handed back by offloaded
        // workers; deliver those, then re-arm (unless we're shutting down).
        if !self.core.stopping() {
            self.drain_injections()?;
            self.drain_handshake_outcomes()?;
            if self.core.shared.graceful.load(Ordering::Acquire)
                && !self.core.draining
            {
                self.begin_drain()?;
            }
            self.core.arm_wake()?;
        }
        Ok(())
    }
}

// The drain state machine runs no handler code — bounds-free.
impl<U, AcceptFn, HeaderFn, BodyFn> Server<U, AcceptFn, HeaderFn, BodyFn> {
    /// Enter graceful drain: stop accepting, close idle connections, let
    /// in-flight requests (reads in progress, deferred work, queued sends)
    /// finish, and arm the grace-period deadline that escalates to a hard stop.
    fn begin_drain(&mut self) -> errno::Result<()> {
        self.core.draining = true;

        // Stop accepting: cancel each listener's multishot accept by its
        // user_data. If one was parked as `deferred` (pool full) the cancel
        // finds nothing; the re-arm guards check `draining`, so it stays down
        // either way.
        for lidx in 0..self.listeners.len() as u32 {
            let accept_ud = pack(Op::Accept, lidx, 0);
            self.core.stage(pack(Op::Cancel, 0, 0), move |sqe| {
                sqe.opcode = IORING_OP_ASYNC_CANCEL;
                sqe.fd = -1;
                sqe.addr = accept_ud;
            })?;
        }

        // Grace-period deadline (a standalone TIMEOUT op).
        let ms = self.core.shared.grace_ms.load(Ordering::Relaxed).max(1);
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

        // One sweep over the table: close idle serving connections now
        // (cancel their parked recv — the -ECANCELED completion drives the
        // normal close path; connections with work in flight drain via the
        // `pump`/`on_send` rules), and close connections parked mid-TLS-
        // handshake — they hold a socket but have no in-flight op to cancel,
        // so nothing else would reclaim them. (A late worker callback then
        // hits the bumped generation and is dropped; parked slots are not
        // counted live, so no drain accounting.)
        let mut idle: Vec<(u32, u32, bool)> = Vec::new();
        let mut tls_parked: Vec<u32> = Vec::new();
        for (slot, entry) in self.core.table.iter() {
            match &entry.state {
                SlotState::Serving(c) if !c.closing => {
                    let parked = c.recving && c.recv_idle;
                    // A connection mid-body-splice (or awaiting its readiness
                    // poll) has work in flight even though `recving` is false
                    // — it must NOT be treated as quiesced, or the drain
                    // would cancel a healthy in-flight transfer and truncate
                    // the body in the consumer's pipe. It drains naturally:
                    // the splice completes, `pump` sees `draining` and closes
                    // once nothing is owed; a WEDGED transfer is cut off by
                    // the grace Deadline's escalation.
                    let quiesced = !c.recving
                        && !c.sending
                        && !c.splicing
                        && !c.splice_polling
                        && c.outstanding == 0
                        && !c.has_pending_send();
                    if parked || quiesced {
                        // Kernel-side use (cancel by user_data / close_conn) → low 32.
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
                self.core.close_conn(
                    slot,
                    generation,
                    CloseReason::ShuttingDown,
                )?;
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

// Deferred-reply/push delivery re-enters the pump, so it needs the framer
// and body-handler bounds (never the accept handler).
impl<U, AcceptFn, HeaderFn, BodyFn> Server<U, AcceptFn, HeaderFn, BodyFn>
where
    HeaderFn: FnMut(&[u8], &mut U) -> Framing,
    BodyFn: FnMut(Request<'_, U>) -> Response,
{
    /// Deliver replies handed back by offloaded workers via [`Deferred`]. Each is
    /// applied to its originating connection only if that connection is still
    /// open (generation check) **and** its request is still awaiting a deferred
    /// reply (`take_deferred`) — so a reply for a closed connection, a recycled
    /// slot, or a request that was already answered inline is dropped instead
    /// of duplicated or misdelivered.
    fn drain_injections(&mut self) -> errno::Result<()> {
        while let Ok(msg) = self.mailbox.inject_rx.try_recv() {
            // Pushes are request-independent: no `take_deferred` gating, no
            // `outstanding` accounting — just the liveness + backlog checks.
            if let Injected::Push {
                slot,
                generation,
                bytes,
            } = msg
            {
                if self.core.draining {
                    continue; // shutting down
                }
                // A push reaches the connection in ANY live state — Serving,
                // or parked across a detach (`PushHandle`'s contract is "for
                // the connection's lifetime", and a detach window must not
                // silently drop). A Serving connection sends now; a
                // Detaching/Detached one only QUEUES — the worker owns the
                // raw stream, so writing would corrupt its transfer — and
                // the queue flushes when the worker resumes it.
                let (overflow, serving) = {
                    // `self.core.table` vs `self.core.cfg`: disjoint borrows.
                    let Some((conn, serving)) =
                        self.core.table.push_conn_mut(slot, generation)
                    else {
                        continue; // connection gone (or slot recycled)
                    };
                    if conn.close_on_flush.is_some() {
                        // Flush-closing: the farewell is final — a push
                        // arriving after it is dropped, never queued behind.
                        continue;
                    }
                    if conn.queued_bytes() + bytes.len()
                        > self.core.cfg.max_send_backlog
                    {
                        if !serving {
                            // Can't tear down under the worker; evict with
                            // `SendBacklog` at resume instead.
                            conn.evict_on_resume = true;
                        }
                        (true, serving)
                    } else {
                        conn.enqueue_push(bytes);
                        (false, serving)
                    }
                };
                if overflow && serving {
                    // Slow consumer: evict rather than queue unboundedly.
                    // Liveness checked full-u64 above; kernel op → low 32.
                    self.core.close_conn(
                        slot,
                        generation as u32,
                        CloseReason::SendBacklog,
                    )?;
                } else if !overflow && serving {
                    self.core.kick_send(slot, generation as u32)?;
                }
                continue;
            }
            // A cross-thread close (`PushHandle::close`): flush-close the
            // connection. Like a push it reaches any live state — a Serving
            // connection flushes its queue and closes; one parked under a
            // detach worker is only marked, the close landing at resume
            // (after the pushes held during the window), like the backlog
            // eviction. Processed even while draining: it can only speed the
            // drain up.
            if let Injected::PushClose { slot, generation } = msg {
                let serving = {
                    let Some((conn, serving)) =
                        self.core.table.push_conn_mut(slot, generation)
                    else {
                        continue; // connection gone (or slot recycled)
                    };
                    if conn.closing || conn.close_on_flush.is_some() {
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
            // Detach outcomes are slot-scoped (no request token). Generation is
            // the full u64 — a worker may retain the handle across recycles;
            // reattach only if the slot is still detached (a stale/duplicate
            // outcome is inert). Then re-arm serving (resume) or close.
            if let Injected::DetachResume { slot, generation } = msg {
                if self.core.table.generation(slot) == generation
                    && self.core.table.reattach(slot)
                {
                    // Pushes queued during the detach window flush now; an
                    // overflow during the window evicts now (it could not
                    // tear down under the worker — see `drain_injections`'
                    // push arm).
                    let (evict, flush, pending) = {
                        let conn = self.core.table.conn_mut(slot);
                        (
                            std::mem::take(&mut conn.evict_on_resume),
                            conn.close_on_flush.is_some(),
                            conn.has_pending_send(),
                        )
                    };
                    if evict {
                        self.core.close_conn(
                            slot,
                            generation as u32,
                            CloseReason::SendBacklog,
                        )?;
                        continue;
                    }
                    if flush {
                        // A `PushHandle::close` that landed during the detach
                        // window: flush what was held (pushes queued in the
                        // window ride ahead of it), then close — the same
                        // lands-at-resume rule as the backlog eviction.
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
                if self.core.table.generation(slot) == generation
                    && self.core.table.reattach(slot)
                {
                    self.core.close_conn(
                        slot,
                        generation as u32,
                        CloseReason::WorkerClosed,
                    )?;
                }
                continue;
            }
            let token = match &msg {
                Injected::Reply(t, _)
                | Injected::ReplyClose(t, _)
                | Injected::Done(t)
                | Injected::Close(t) => *t,
                Injected::Push { .. }
                | Injected::PushClose { .. }
                | Injected::DetachResume { .. }
                | Injected::DetachClose { .. } => {
                    unreachable!("handled above")
                }
            };
            if !self.core.table.slot_matches(token.slot, token.generation) {
                continue; // connection gone (or slot recycled)
            }
            if self.core.table.conn(token.slot).close_on_flush.is_some() {
                // Flush-closing: the farewell is final — a worker outcome
                // landing after it is dropped, exactly like a late push (the
                // request it resolves dies with the connection).
                continue;
            }
            if !self
                .core
                .table
                .conn_mut(token.slot)
                .take_deferred(token.req_id)
            {
                continue; // request already answered — stale Deferred
            }
            match msg {
                Injected::Reply(_, bytes) => {
                    // Queue the deferred reply behind any already-queued ones
                    // and start sending if the send side is idle. `on_send`
                    // drops the request's `outstanding` count once flushed.
                    self.core.table.conn_mut(token.slot).enqueue_reply(bytes);
                    self.core.kick_send(token.slot, token.generation as u32)?;
                }
                Injected::ReplyClose(_, bytes) => {
                    // The worker speaks last: queue its final PDU (nothing,
                    // when empty) and flush-close — the deferred twin of
                    // `Response::ReplyClose`, reported as `WorkerClosed`
                    // like `Deferred::close`.
                    {
                        let conn = self.core.table.conn_mut(token.slot);
                        if bytes.is_empty() {
                            // No PDU: retire the request's in-flight count
                            // here (a queued reply is retired by `on_send`).
                            conn.outstanding =
                                conn.outstanding.saturating_sub(1);
                        } else {
                            conn.enqueue_reply(bytes);
                        }
                        conn.close_on_flush = Some(CloseReason::WorkerClosed);
                    }
                    self.core.drive_flush_close(
                        token.slot,
                        token.generation as u32,
                    )?;
                }
                Injected::Done(_) => {
                    // Complete with nothing to send: free the in-flight slot
                    // and resume reading if the cap had paused it.
                    let conn = self.core.table.conn_mut(token.slot);
                    conn.outstanding = conn.outstanding.saturating_sub(1);
                    self.pump(token.slot, token.generation as u32)?;
                }
                Injected::Close(_) => {
                    self.core.close_conn(
                        token.slot,
                        token.generation as u32,
                        CloseReason::WorkerClosed,
                    )?;
                }
                Injected::Push { .. }
                | Injected::PushClose { .. }
                | Injected::DetachResume { .. }
                | Injected::DetachClose { .. } => {
                    unreachable!("handled above")
                }
            }
        }
        Ok(())
    }
}
