//! The per-connection request data plane's ROLE half: the header-framer pump
//! skeleton, the recv/send/splice completion wrappers (their heavy bookkeeping
//! is core — see [`Reactor`](crate::net::core::reactor)), request delivery to
//! the body handler, and the detach install/handoff. What stays here is exactly
//! the code that runs consumer closures (the framer, the body handler, the
//! detach hook) or touches server-only fields (`handlers`, `mailbox`).

use super::handles::{Detached, Responder};
use super::Server;
use crate::errno::{self, Errno};
use crate::fd::owned_from_raw;
use crate::net::core::conn::{pack, Op};
use crate::net::core::handles::{stat, Token};
use crate::net::core::protocol::{CloseReason, Framing};
use crate::net::core::reactor::{
    Enacted, Gate, RecvStep, SendStep, SpliceStep,
};
use crate::net::core::sys::*;
use crate::net::server::protocol::{DetachContext, Request, Response};
use std::sync::Arc;

// The stages that run the consumer's framer/body handler — the only bounds
// this file needs (the accept handler never runs here).
impl<U, AcceptFn, HeaderFn, BodyFn> Server<U, AcceptFn, HeaderFn, BodyFn>
where
    HeaderFn: FnMut(&[u8], &mut U) -> Framing,
    BodyFn: FnMut(Request<'_, U>) -> Response,
{
    /// The per-connection read/deliver pump: consult the header framer on the
    /// accumulated bytes and either read more, deliver a buffered request, or
    /// close. In pipelined mode it delivers every already-buffered request and
    /// arms the next recv — up to the `max_in_flight_requests` cap — so a
    /// deferred request doesn't stall reading the client's next ones.
    ///
    /// A thin skeleton over the core: [`Reactor::pump_gate`] runs the loop-top
    /// busy/cap/drain/oversize guards and [`Reactor::enact_frame_step`] enacts
    /// the framer's verdict; only the framer call (a role closure, reached via
    /// the disjoint `self.core.table` + `self.handlers` borrows) and the
    /// `Deliver` seam stay here.
    pub(super) fn pump(
        &mut self,
        slot: u32,
        generation: u32,
    ) -> errno::Result<()> {
        loop {
            match self.core.pump_gate(slot, generation)? {
                Gate::Stop => return Ok(()),
                Gate::Proceed => {}
            }
            let verdict = {
                // `self.core.table` and `self.handlers` are disjoint fields, so
                // the framer can run while the connection is borrowed.
                let conn = self.core.table.conn_mut(slot);
                let (buf, state) = conn.frame_parts();
                (self.handlers.header)(buf, state)
            };
            match self.core.enact_frame_step(slot, generation, verdict)? {
                Enacted::Done => return Ok(()),
                Enacted::Deliver => self.deliver_one(slot, generation)?,
            }
        }
    }

    /// A recv completed; `op` says which kind (`RecvHeader`/`RecvBody`). All
    /// the completion bookkeeping is core ([`Reactor::on_recv_complete`]); the
    /// returned [`RecvStep`] drives the delivery/pump tail — a completed body
    /// delivers then pumps, a completed header re-pumps, everything else is
    /// self-contained.
    pub(super) fn on_recv(
        &mut self,
        slot: u32,
        generation: u32,
        res: i32,
        op: Op,
    ) -> errno::Result<()> {
        match self.core.on_recv_complete(slot, generation, res, op)? {
            RecvStep::Deliver => {
                self.deliver_one(slot, generation)?;
                self.pump(slot, generation)
            }
            RecvStep::Pump => self.pump(slot, generation),
            RecvStep::Done => Ok(()),
        }
    }

    /// A body splice completed (`Op::SpliceRecv`). All the completion
    /// bookkeeping is core ([`Reactor::on_splice_recv_complete`]); a fully moved
    /// body pumps the next frame. The body never entered the buffer, so there is
    /// **no** `deliver_one` — the framer that returned `SpliceBody` was the
    /// per-frame consumer hook.
    pub(super) fn on_splice_recv(
        &mut self,
        slot: u32,
        generation: u32,
        res: i32,
    ) -> errno::Result<()> {
        match self.core.on_splice_recv_complete(slot, generation, res)? {
            SpliceStep::Pump => self.pump(slot, generation),
            SpliceStep::Done => Ok(()),
        }
    }

    /// Run the body handler for the current message, drop the request from the
    /// recv buffer, and act on the [`Response`]: queue a reply (and start
    /// sending), park for a deferred reply, or close.
    fn deliver_one(&mut self, slot: u32, generation: u32) -> errno::Result<()> {
        // Borrow-split: `self.handlers`, `self.core.table`, and `self.mailbox` are
        // disjoint fields; within the connection, buf/addr (immutable) vs
        // userdata (mutable). The Responder holds owned channel clones.
        // The token carries the FULL u64 generation — a worker may retain it
        // across recycles — whereas the kernel routing used the low 32 bits.
        let gen64 = self.core.table.generation(slot);
        let (resp, req_id) = {
            let conn = self.core.table.conn_mut(slot);
            let req_id = conn.begin_request();
            let responder = Responder {
                token: Token {
                    slot,
                    generation: gen64,
                    req_id,
                },
                tx: self.mailbox.inject_tx.clone(),
                shared: Arc::clone(&self.core.shared),
            };
            let (header, body, peer, state) = conn.deliver_parts();
            (
                (self.handlers.body)(Request {
                    header,
                    body,
                    peer,
                    state,
                    responder,
                }),
                req_id,
            )
        };
        // The handler has taken what it needs; drop the request from the recv
        // buffer so the next request can be read into it.
        self.core.table.conn_mut(slot).consume();
        stat!(self.core, requests);
        match resp {
            Response::Close => self.core.close_conn(
                slot,
                generation,
                CloseReason::HandlerClosed,
            ),
            Response::Defer(permit) => {
                // The permit type proves defer() was called — but only its
                // token proves it was called for THIS request. A stashed
                // permit returned for a later request has no live Deferred
                // carrying that request's id, so parking it would wedge the
                // connection (and its pool slot) until shutdown. Verify, and
                // close on a mismatch instead.
                let t = permit.token;
                if (t.slot, t.generation, t.req_id) != (slot, gen64, req_id) {
                    return self.core.close_conn(
                        slot,
                        generation,
                        CloseReason::HandlerClosed,
                    );
                }
                // Reply arrives later via `inject_rx`; count it outstanding and
                // record the open request so exactly one Deferred outcome can
                // resolve it (stale/duplicate ones are dropped at drain time).
                let conn = self.core.table.conn_mut(slot);
                conn.outstanding += 1;
                conn.open_deferred(req_id);
                stat!(self.core, deferred);
                Ok(())
            }
            Response::Detach(permit) => {
                // Like Defer: the permit type proves detach() ran, but only its
                // token proves it ran for THIS request.
                let t = permit.token;
                if (t.slot, t.generation, t.req_id) != (slot, gen64, req_id) {
                    return self.core.close_conn(
                        slot,
                        generation,
                        CloseReason::HandlerClosed,
                    );
                }
                // Detach hands the socket fd to a worker for a blocking op, so
                // it is only safe on a fully settled connection: no other
                // request in flight, and nothing buffered past this one (the raw
                // stream that follows belongs to the fd, not the framer).
                let settled = {
                    let conn = self.core.table.conn(slot);
                    !conn.recving
                        && !conn.sending
                        && conn.outstanding == 0
                        && conn.buffered() == 0
                        && !conn.has_pending_send()
                };
                if !settled {
                    return self.core.close_conn(
                        slot,
                        generation,
                        CloseReason::HandlerClosed,
                    );
                }
                // Park as `Detaching` and materialize the real fd; the parked
                // connection resumes or closes when the worker signals.
                self.submit_detach_install(slot, generation)
            }
            // Answered inline with nothing to send (one-way message): the
            // request is complete; keep reading. Any Deferred minted for it is
            // now stale (its `req_id` was never opened).
            Response::Reply(bytes) if bytes.is_empty() => Ok(()),
            Response::Reply(bytes) => {
                {
                    let conn = self.core.table.conn_mut(slot);
                    conn.outstanding += 1;
                    conn.enqueue_reply(bytes);
                }
                self.core.kick_send(slot, generation)
            }
            Response::ReplyClose(bytes) => {
                // The server speaks last: queue the final PDU (nothing, when
                // empty) and mark the flush-close. The pump gate retires the
                // recv side — buffered pipelined requests are discarded —
                // and the connection closes once the send queue drains
                // (`drive_flush_close` now, or `on_send` when it empties).
                // Reported as `HandlerClosed`, like `Response::Close`.
                {
                    let conn = self.core.table.conn_mut(slot);
                    if !bytes.is_empty() {
                        conn.outstanding += 1;
                        conn.enqueue_reply(bytes);
                    }
                    conn.close_on_flush = Some(CloseReason::HandlerClosed);
                }
                self.core.drive_flush_close(slot, generation)
            }
        }
    }

    /// A send completed (`Op::Send`). All the completion bookkeeping — the
    /// gather-advance accounting, the partial-send re-arm, the next-batch kick,
    /// the flush-close finish — is core ([`Reactor::on_send_complete`]); a fully
    /// flushed gather resumes the pump.
    pub(super) fn on_send(
        &mut self,
        slot: u32,
        generation: u32,
        res: i32,
    ) -> errno::Result<()> {
        match self.core.on_send_complete(slot, generation, res)? {
            SendStep::Pump => self.pump(slot, generation),
            SendStep::Done => Ok(()),
        }
    }
}

// Recv/send submission and transport checks — no handler runs here, so no
// closure bounds.
impl<U, AcceptFn, HeaderFn, BodyFn> Server<U, AcceptFn, HeaderFn, BodyFn> {
    /// Materialize a real fd from the pool descriptor for a `body`-handler
    /// **detach** and park the connection as `Detaching`. `on_detach_install`
    /// then furnishes the fd (aliasing the pool socket) to the detach handler.
    /// The SQE is staged before the state transition, so a stage failure leaves
    /// the connection serving.
    pub(super) fn submit_detach_install(
        &mut self,
        slot: u32,
        generation: u32,
    ) -> errno::Result<()> {
        self.core.stage(
            pack(Op::DetachInstall, slot, generation),
            move |sqe| {
                sqe.opcode = IORING_OP_FIXED_FD_INSTALL;
                sqe.fd = slot as i32;
                sqe.flags = IOSQE_FIXED_FILE;
            },
        )?;
        self.core.table.begin_detach(slot);
        Ok(())
    }

    /// A detach `FIXED_FD_INSTALL` completed (`Op::DetachInstall`): `res` is the
    /// furnished real fd (aliasing the pool socket) or `-errno`. Hand the fd and
    /// a [`Detached`] to the detach handler and park the connection; on install
    /// failure, during drain, or with no handler registered, close it instead.
    pub(super) fn on_detach_install(
        &mut self,
        slot: u32,
        generation: u32,
        res: i32,
    ) -> errno::Result<()> {
        // Kernel completion → low 32 bits. The slot is `Detaching`, not
        // `Serving`, so `slot_matches_cqe` doesn't apply — check directly.
        if self.core.table.generation_low(slot) != generation {
            return Ok(()); // slot recycled under a stale completion
        }
        // Close instead of handing off on: install failure/cancel, shutdown, or
        // a missing handler (a body handler returned Detach with none set).
        if res < 0 || self.core.draining || self.handlers.detach.is_none() {
            if res >= 0 {
                // SAFETY: `res` is the freshly installed fd; close the alias we
                // won't use (the pool socket survives on the direct descriptor).
                unsafe { libc::close(res) };
            }
            // Reattach to `Serving` so close_conn/active reuse the serving path.
            if self.core.table.reattach(slot) {
                let reason = if res < 0 {
                    CloseReason::RecvError(Errno::from_raw(-res))
                } else if self.core.draining {
                    CloseReason::ShuttingDown
                } else {
                    // No detach handler registered (a body handler returned
                    // Response::Detach without set_detach_handler): a misconfig.
                    CloseReason::HandlerClosed
                };
                return self.core.close_conn(slot, generation, reason);
            }
            return Ok(()); // no longer detaching (stale)
        }
        // Hand off: take the connection out (the slot is momentarily `Empty`, as
        // the kTLS install→park does), build the fd-owning handle, run the
        // handler, and park.
        let gen64 = self.core.table.generation(slot);
        let Some(mut conn) = self.core.table.take_detaching(slot) else {
            // SAFETY: nobody will consume the fd; close the alias.
            unsafe { libc::close(res) };
            return Ok(());
        };
        // SAFETY: `res` is a fresh owned fd materialized by FIXED_FD_INSTALL.
        let fd = unsafe { owned_from_raw(res) };
        let detached = Detached {
            slot,
            generation: gen64,
            fd,
            tx: self.mailbox.inject_tx.clone(),
            shared: Arc::clone(&self.core.shared),
            done: false,
        };
        // Disjoint-field borrow: `self.handlers` vs the local `conn`.
        let handler = self.handlers.detach.as_mut().expect("checked is_some");
        handler(
            DetachContext {
                peer: &conn.peer,
                state: &mut conn.state,
            },
            detached,
        );
        self.core.table.park_detached(slot, conn);
        Ok(())
    }
}
