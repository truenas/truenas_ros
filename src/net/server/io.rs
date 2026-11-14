//! The request data plane's role half, the code that runs consumer closures (the framer, the body handler, the detach
//! hook) or touches server-only fields. The completion bookkeeping is core ([`Reactor`](crate::net::core::reactor)).

use super::Server;
use super::handles::{Detached, Responder};
use crate::errno::{self, Errno};
use crate::fd::owned_from_raw;
use crate::net::core::bodypool::HeldBack;
#[cfg(feature = "uring-fs")]
use crate::net::core::conn::PendingFile;
use crate::net::core::conn::{Op, pack};
use crate::net::core::handles::{Token, stat};
use crate::net::core::protocol::{CloseReason, Framing};
use crate::net::core::reactor::{Enacted, Gate, RecvStep, SendStep, SpliceStep};
use crate::net::server::protocol::{DetachContext, Request, Response};

/// Which delivery [`Server::deliver_one`] is running.
///
/// The two differ in what belongs to the message being delivered. A wire delivery owns the connection's current frame
/// and the receipt budget armed for it; a redelivery owns neither - its bytes were consumed and its budget retired at
/// its first delivery, and anything set on the connection now belongs to a *later* message the read-ahead has begun.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Delivery {
    /// A message the framer just declared over what was read.
    FromWire,
    /// A worker's re-entry for a request the protocol glue retained ([`super::Deferred::redeliver`]).
    Redelivery,
}
use crate::sync::Arc;
use crate::uring::sys::*;

// The stages that run the consumer's framer/body handler - the only bounds this file needs (the accept handler never
// runs here).
impl<U, AcceptFn, HeaderFn, BodyFn> Server<U, AcceptFn, HeaderFn, BodyFn>
where
    HeaderFn: FnMut(&[u8], &mut U) -> Framing,
    BodyFn: FnMut(Request<'_, U>) -> Response,
{
    /// The per-connection read/deliver pump: consult the header framer on the accumulated bytes and either read more,
    /// deliver a buffered request, or close. In pipelined mode it delivers every already-buffered request and arms the
    /// next recv - up to the `max_in_flight_requests` cap - so a deferred request doesn't stall reading the client's
    /// next ones.
    pub(super) fn pump(&mut self, slot: u32, generation: u32) -> errno::Result<()> {
        loop {
            match self.core.pump_gate(slot, generation)? {
                Gate::Stop => return Ok(()),
                Gate::Proceed => {}
            }
            let verdict = {
                // `self.core.table` and `self.handlers` are disjoint fields, so the framer can run while the connection
                // is borrowed.
                let conn = self.core.table.conn_mut(slot);
                let (buf, state) = conn.frame_parts();
                (self.handlers.header)(buf, state)
            };
            match self.core.enact_frame_step(slot, generation, verdict)? {
                Enacted::Done => return Ok(()),
                Enacted::Deliver => self.deliver_one(slot, generation, Delivery::FromWire)?,
            }
        }
    }

    /// A recv completed. The bookkeeping is core ([`Reactor::on_recv_complete`]), and the returned [`RecvStep`] says
    /// whether to deliver, pump or stop.
    pub(super) fn on_recv(
        &mut self,
        slot: u32,
        generation: u32,
        res: i32,
        cqe_flags: u32,
        op: Op,
    ) -> errno::Result<()> {
        // Adopt a pool buffer the completion selected before reading its bytes. A refused adopt names a buffer the pool
        // cannot vouch for, so its bytes cannot be located and framing would read garbage as the peer's. Fail the read
        // instead.
        if !self.core.adopt_recv_buffer(slot, generation, cqe_flags) {
            if !self.core.table.slot_matches_cqe(slot, generation) {
                return Ok(()); // stale completion; the slot moved on
            }
            // Retire the op before closing, exactly as a completion does. `close_conn` defers teardown while `ops` is
            // charged, so skipping this leaves the slot, its fixed descriptor and the socket held for the reactor's
            // life, with the peer getting neither a reply nor a FIN.
            self.core.table.conn_mut(slot).recving = false;
            if !self.core.op_done(slot)? {
                return Ok(()); // already tearing down
            }
            return self
                .core
                .close_conn(slot, generation, CloseReason::RecvError(errno::Errno::EIO));
        }
        match self.core.on_recv_complete(slot, generation, res, op)? {
            RecvStep::Deliver => {
                self.deliver_one(slot, generation, Delivery::FromWire)?;
                self.pump(slot, generation)
            }
            RecvStep::Pump => self.pump(slot, generation),
            RecvStep::Done => Ok(()),
        }
    }

    /// A parked read's pool-shortage backoff elapsed (`Op::RecvRetry`). Re-pump the connection, which re-arms exactly
    /// the read that found the pool dry, or parks it again if the pool is still dry. `pump_gate` decides every state
    /// the connection may have reached meanwhile, so this adds no gating beyond clearing the timer's flag. Not counted
    /// in `conn.ops`, like the other standalone timers.
    pub(super) fn on_recv_retry(&mut self, slot: u32, generation: u32) -> errno::Result<()> {
        if !self.core.table.slot_matches_cqe(slot, generation) {
            // Left set, this flag reads to `recv_buffer_shortage` as "a timer is pending", so every later shortage
            // parks the read with nothing able to wake it and the connection holds its slot with no op in flight. See
            // `conn_at_cqe_mut`.
            if let Some(conn) = self.core.table.conn_at_cqe_mut(slot, generation) {
                conn.recv_retry_armed = false;
            }
            return Ok(());
        }
        self.core.table.conn_mut(slot).recv_retry_armed = false;
        if self.core.stopping() {
            return Ok(());
        }
        self.pump(slot, generation)
    }

    /// Let what `ServerConfig::held_cap` holds back go on, the reads that would take storage of the body pool and the
    /// consumer's turns, in the order they came, while the ring holds less than the cap. Checked again after each,
    /// since a read claims its storage and the held hook takes out what it lets go for a turn, so what is held back
    /// passes the cap by one at most. A stale read (the connection closed, or its slot was recycled) is passed over.
    /// The hook runs with no borrow of the pool, which it reaches itself.
    pub(super) fn redrive_held_reads(&mut self) -> errno::Result<()> {
        loop {
            if self.core.stopping() {
                return Ok(());
            }
            let next = match self.core.body_pool.as_ref() {
                Some(pool) => pool.borrow_mut().let_go(),
                None => None,
            };
            let (slot, gen64) = match next {
                None => return Ok(()),
                Some(HeldBack::Turn) => {
                    if let Some(hook) = self.handlers.held.as_mut() {
                        hook();
                    }
                    continue;
                }
                Some(HeldBack::Read { slot, generation }) => (slot, generation),
            };
            if self.core.table.generation(slot) != gen64 {
                continue; // slot recycled under the wait
            }
            match self.core.table.get_conn_mut(slot) {
                Some(conn) if conn.read_held => conn.read_held = false,
                _ => continue, // closing, or no longer waiting
            }
            // The pump frames the message again and reaches the same read, which the check lets go on this once.
            self.core.held_turn = Some(slot);
            let pumped = self.pump(slot, gen64 as u32);
            self.core.held_turn = None;
            pumped?;
        }
    }

    /// A body splice completed (`Op::SpliceRecv`), with the bookkeeping in [`Reactor::on_splice_recv_complete`]. The
    /// body never entered the buffer, so there is no `deliver_one`.
    pub(super) fn on_splice_recv(&mut self, slot: u32, generation: u32, res: i32) -> errno::Result<()> {
        match self.core.on_splice_recv_complete(slot, generation, res)? {
            SpliceStep::Pump => self.pump(slot, generation),
            SpliceStep::Done => Ok(()),
        }
    }

    /// Run the body handler for the current message, drop the request from the recv buffer, and act on the
    /// [`Response`]: queue a reply (and start sending), park for a deferred reply, or close. Also the re-entry point
    /// for [`Deferred::redeliver`] ([`Delivery::Redelivery`]), where the handler works from its own retained state.
    pub(super) fn deliver_one(&mut self, slot: u32, generation: u32, which: Delivery) -> errno::Result<()> {
        // A redelivery owns neither the budget nor the frame (see `Delivery`). With a read-ahead cap above one the pump
        // may already have framed the next request, which the handler must not be handed and `consume` must not drop,
        // so deliver against an empty frame and put the pending one back afterwards.
        let saved = match which {
            Delivery::FromWire => {
                // Receipt is over the moment the message is handed to the handler, so the budget is retired here rather
                // than when the next read is armed. Anything later would clock the *handling* too, and a request
                // offloaded with `Response::Defer` may legitimately run for as long as it likes.
                self.core.cancel_receipt_deadline(slot, generation)?;
                None
            }
            Delivery::Redelivery => {
                let conn = self.core.table.conn_mut(slot);
                let frame = conn.frame();
                conn.set_frame(0, 0);
                Some(frame)
            }
        };
        // The token carries the full u64 generation, since a worker may hold it across recycles, while kernel routing
        // uses the low 32 bits.
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
                shared: Arc::clone(&self.core.engine.shared),
            };
            // The leased form also hands out the recv claim, so a handler's `pwritev2_from` can write the body straight
            // from the buffer.
            #[cfg(feature = "uring-fs")]
            let (header, mut body, peer, state, lease, delivered) =
                conn.deliver_parts_leased(self.core.cfg.body_placement_threshold);
            #[cfg(not(feature = "uring-fs"))]
            let (header, mut body, peer, state, delivered) = conn.deliver_parts(self.core.cfg.body_placement_threshold);
            // A placed body's licence joins the pool's windowed pot before the handler runs, so a recycle made inside
            // the handler finds it spendable. The storage itself goes home if the handler drops the body untaken.
            if let Some(pool) = self.core.body_pool.as_ref() {
                if delivered.licence > 0 {
                    pool.borrow_mut().receipt_done(delivered.licence);
                }
                body.set_home(pool, delivered.bytes);
            }
            // The fs facade borrows the engine and the fs tables, disjoint from the table `conn` holds and from
            // `self.handlers`.
            #[cfg(feature = "uring-fs")]
            let fs = self.fs.as_mut().map(|fc| {
                crate::uring_fs::core::FsConn::new(fc, &mut self.core.engine, Some((slot, gen64)))
                    .with_recv_lease(lease)
            });
            (
                (self.handlers.body)(Request {
                    header,
                    body,
                    peer,
                    state,
                    responder,
                    #[cfg(feature = "uring-fs")]
                    fs,
                }),
                req_id,
            )
        };
        // The handler has taken what it needs; drop the request from the recv buffer so the next request can be read
        // into it. (A redelivery's frame is empty, so this drains nothing - see `take_body_handoff`.)
        self.core.table.conn_mut(slot).consume();
        // Nothing buffered means nothing to hold a buffer for: give it back so a connection waiting on its next request
        // costs none.
        self.core.release_recv_buffer(slot);
        // Hand the read-ahead frame back to the message it describes.
        if let Some((header_len, body_len)) = saved
            && let Some(conn) = self.core.table.get_conn_mut(slot)
        {
            conn.set_frame(header_len, body_len);
        }
        stat!(self.core, requests);
        match resp {
            Response::Close => self.core.close_conn(slot, generation, CloseReason::HandlerClosed),
            Response::Defer(permit) => {
                // Only the permit's token proves `defer()` ran for this request. A permit stashed from another request
                // has no live `Deferred`, so parking would wedge the connection until shutdown.
                let t = permit.token;
                if (t.slot, t.generation, t.req_id) != (slot, gen64, req_id) {
                    return self.core.close_conn(slot, generation, CloseReason::HandlerClosed);
                }
                // Reply arrives later via `inject_rx`; count it outstanding and record the open request so exactly one
                // Deferred outcome can resolve it (stale/duplicate ones are dropped at drain time).
                let conn = self.core.table.conn_mut(slot);
                conn.outstanding += 1;
                conn.open_deferred(req_id);
                stat!(self.core, deferred);
                Ok(())
            }
            Response::Detach(permit) => {
                // Like Defer: the permit type proves detach() ran, but only its token proves it ran for THIS request.
                let t = permit.token;
                if (t.slot, t.generation, t.req_id) != (slot, gen64, req_id) {
                    return self.core.close_conn(slot, generation, CloseReason::HandlerClosed);
                }
                // Detach hands the socket fd to a worker for a blocking op, so it is only safe on a fully settled
                // connection: no other request in flight, and nothing buffered past this one (the raw stream that
                // follows belongs to the fd, not the framer).
                let settled = {
                    let conn = self.core.table.conn(slot);
                    // `closing`/`ops`: a teardown already in flight owns this slot's remaining completions, and parking
                    // it as `Detaching` would take it out of the state those completions are accounted against.
                    !conn.closing
                        && conn.ops == 0
                        && !conn.recving
                        && !conn.sending
                        && !conn.splicing
                        && !conn.splice_polling
                        && conn.outstanding == 0
                        && conn.buffered() == 0
                        && !conn.has_pending_send()
                };
                if !settled {
                    return self.core.close_conn(slot, generation, CloseReason::HandlerClosed);
                }
                // Park as `Detaching` and materialize the real fd; the parked connection resumes or closes when the
                // worker signals.
                self.submit_detach_install(slot, generation)
            }
            // Answered inline with nothing to send (one-way message): the request is complete; keep reading. Any
            // Deferred minted for it is now stale (its `req_id` was never opened).
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
                // The server speaks last. Queue the final PDU, if any, and mark the flush-close, so the pump gate
                // retires the recv side and the connection closes once the send queue drains.
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
            // Bump `outstanding` once if any bytes are queued, since the segment helper flags only the last non-empty
            // segment, then keep serving or flush-close.
            Response::ReplyVectored { segments, close } => {
                let queued = {
                    let conn = self.core.table.conn_mut(slot);
                    let queued = conn.enqueue_reply_segments(segments);
                    if queued {
                        conn.outstanding += 1;
                    }
                    if close {
                        conn.close_on_flush = Some(CloseReason::HandlerClosed);
                    }
                    queued
                };
                if close {
                    self.core.drive_flush_close(slot, generation)
                } else if queued {
                    self.core.kick_send(slot, generation)
                } else {
                    Ok(())
                }
            }
            // A file-sourced body: queue the head as a non-final segment, install the tail, and issue the first read.
            // The final chunk's `ReplyLast` retires the reply, so the read-ahead cap holds pipelined requests until the
            // body completes and a flush-close waits for it (the dry checks are tail-guarded).
            #[cfg(feature = "uring-fs")]
            Response::ReplyFile {
                head,
                file,
                offset,
                len,
                close,
            } => self.begin_file_reply(slot, generation, head, file, offset, len, close),
        }
    }

    /// A send completed (`Op::Send`), with the bookkeeping in [`Reactor::on_send_complete`]. A fully flushed gather
    /// resumes the pump.
    pub(super) fn on_send(&mut self, slot: u32, generation: u32, res: i32) -> errno::Result<()> {
        let step = self.core.on_send_complete(slot, generation, res)?;
        // Flushed tail chunks gave back their shares (`advance_sent`), so a read waiting on one can go now. A no-op on
        // a closed connection or without an active tail.
        #[cfg(feature = "uring-fs")]
        self.drive_file_tail(slot, generation, false)?;
        match step {
            SendStep::Pump => self.pump(slot, generation),
            SendStep::Done => Ok(()),
        }
    }
}

// Recv/send submission and transport checks - no handler runs here, so no closure bounds.
impl<U, AcceptFn, HeaderFn, BodyFn> Server<U, AcceptFn, HeaderFn, BodyFn> {
    /// Materialize a real fd from the pool descriptor for a `body`-handler **detach** and park the connection as
    /// `Detaching`. `on_detach_install` then furnishes the fd (aliasing the pool socket) to the detach handler. The SQE
    /// is staged before the state transition, so a stage failure leaves the connection serving.
    pub(super) fn submit_detach_install(&mut self, slot: u32, generation: u32) -> errno::Result<()> {
        self.core.stage(pack(Op::DetachInstall, slot, generation), move |sqe| {
            sqe.opcode = IORING_OP_FIXED_FD_INSTALL;
            sqe.fd = slot as i32;
            sqe.flags = IOSQE_FIXED_FILE;
        })?;
        self.core.table.begin_detach(slot);
        Ok(())
    }

    /// A detach `FIXED_FD_INSTALL` completed (`Op::DetachInstall`): `res` is the furnished real fd (aliasing the pool
    /// socket) or `-errno`. Hand the fd and a [`Detached`] to the detach handler and park the connection; on install
    /// failure, during drain, or with no handler registered, close it instead.
    pub(super) fn on_detach_install(&mut self, slot: u32, generation: u32, res: i32) -> errno::Result<()> {
        // Kernel completion -> low 32 bits. The slot is `Detaching`, not `Serving`, so `slot_matches_cqe` doesn't
        // apply - check directly.
        if self.core.table.generation_low(slot) != generation {
            if res >= 0 {
                // The kernel furnished the fd before the slot was recycled. Every path that does not hand the fd to a
                // `Detached` closes it.
                // SAFETY: `res` is the freshly installed fd, owned by us and consumed by nobody (the pool socket
                // survives on the direct descriptor).
                unsafe { libc::close(res) };
            }
            return Ok(()); // slot recycled under a stale completion
        }
        // Close instead of handing off on: install failure/cancel, shutdown, or a missing handler (a body handler
        // returned Detach with none set).
        if res < 0 || self.core.draining || self.handlers.detach.is_none() {
            if res >= 0 {
                // SAFETY: `res` is the freshly installed fd; close the alias we won't use (the pool socket survives on
                // the direct descriptor).
                unsafe { libc::close(res) };
            }
            // Reattach to `Serving` so close_conn/active reuse the serving path.
            if self.core.table.reattach(slot) {
                let reason = if res < 0 {
                    CloseReason::RecvError(Errno::from_raw(-res))
                } else if self.core.draining {
                    CloseReason::ShuttingDown
                } else {
                    // No detach handler registered (a body handler returned Response::Detach without
                    // set_detach_handler): a misconfig.
                    CloseReason::HandlerClosed
                };
                return self.core.close_conn(slot, generation, reason);
            }
            return Ok(()); // no longer detaching (stale)
        }
        // Hand off. Park first, then run the handler against the parked slot, as the kTLS install->park does
        // (`park_tls` precedes its handshake handler): the connection must not leave the table across consumer code -
        // see `park_detached_in_place`.
        let gen64 = self.core.table.generation(slot);
        let Some(conn) = self.core.table.park_detached_in_place(slot) else {
            // No longer detaching (stale): nobody will consume the fd.
            // SAFETY: `res` is the freshly installed fd, owned and unconsumed.
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
            shared: Arc::clone(&self.core.engine.shared),
            done: false,
        };
        // Disjoint-field borrow: `self.handlers` vs `self.core.table`.
        let handler = self.handlers.detach.as_mut().expect("checked is_some");
        handler(
            DetachContext {
                peer: &conn.peer,
                state: &mut conn.state,
            },
            detached,
        );
        Ok(())
    }

    /// Enact [`Response::ReplyFile`]. Queue the head, install the tail, and issue the first read. With no fs pool to
    /// read on, or a range whose arithmetic wrapped, the connection closes, never a short body.
    ///
    /// A body already streaming is not a refusal and must not become one. Two tails' chunks would interleave on the
    /// wire, but the first response's head is already sent, so shedding the connection would destroy the response that
    /// did nothing wrong. The second queues behind the current body through the diversion every other PDU uses, and
    /// installs when it retires.
    #[cfg(feature = "uring-fs")]
    #[allow(clippy::too_many_arguments)] // a Response variant unpacked
    pub(super) fn begin_file_reply(
        &mut self,
        slot: u32,
        generation: u32,
        head: Vec<u8>,
        file: crate::uring_fs::File,
        offset: u64,
        len: u64,
        close: bool,
    ) -> errno::Result<()> {
        if self.fs.is_none() {
            return self
                .core
                .close_conn(slot, generation, CloseReason::FileBody(Errno::EOPNOTSUPP));
        }
        // Nothing to stream: the head is the whole reply (mirrors the ReplyVectored disposition, including the empty
        // one-way case).
        if len == 0 {
            let queued = {
                let conn = self.core.table.conn_mut(slot);
                let queued = !head.is_empty();
                if queued {
                    conn.outstanding += 1;
                    conn.enqueue_reply(head);
                }
                if close {
                    conn.close_on_flush = Some(CloseReason::HandlerClosed);
                }
                queued
            };
            return if close {
                self.core.drive_flush_close(slot, generation)
            } else if queued {
                self.core.kick_send(slot, generation)
            } else {
                Ok(())
            };
        }
        // Bound the range here, the one place an untrusted one enters, never in the submit path. The kernel reads each
        // offset as a signed `loff_t`. `u64::MAX` is `-1`, the use-the-file-position sentinel, so on a regular file
        // `io_kiocb_update_pos` (`io_uring/rw.c`) would read from `f_pos` in place of the offset asked for and write
        // the new position back, a read that succeeds from the wrong place behind a correctly framed `Content-Length`.
        // ZFS sets neither `FMODE_STREAM` nor `FMODE_UNSIGNED_OFFSET`, and anything else past `i64::MAX` fails
        // `rw_verify_area` (`fs/read_write.c`) after the head has committed.
        //
        // The sum is bounded, not just the start. A suffix range past the object's size wraps `size - N`, and the tail
        // walks to `offset + len`, which this also keeps from wrapping in `on_pump_read`. In the submit path `u64::MAX`
        // is the right idiom for a stream file with no position (`cancel_owned_by_reaches_a_pump_read`).
        if offset.checked_add(len).is_none_or(|end| end > i64::MAX as u64) {
            return self
                .core
                .close_conn(slot, generation, CloseReason::FileBody(Errno::EINVAL));
        }
        let next = PendingFile {
            head,
            file,
            offset,
            len,
            close,
        };
        // Counted outstanding here rather than at install, so it is counted exactly once either way: the read-ahead cap
        // must see an answered request whether its body starts now or waits its turn.
        let conn = self.core.table.conn_mut(slot);
        conn.outstanding += 1;
        if conn.tail_active() {
            // A body is already streaming: hold this one behind it, in arrival order with the PDUs the same diversion
            // is holding.
            conn.defer_file_reply(next);
            return Ok(());
        }
        self.install_file_reply(slot, generation, next)
    }

    /// Queue a file reply's head, install its tail, and issue the first read. The count against the read-ahead cap is
    /// the caller's - a body deferred behind another was counted when it was deferred.
    #[cfg(feature = "uring-fs")]
    fn install_file_reply(&mut self, slot: u32, generation: u32, next: PendingFile) -> errno::Result<()> {
        let close = next.close;
        {
            let conn = self.core.table.conn_mut(slot);
            // Head first - the diversion is not yet on - then the tail; its chunks follow as reads complete, the last
            // one `ReplyLast`.
            conn.enqueue_reply_head(next.head);
            conn.install_file_tail(next.file, next.offset, next.len);
            if close {
                conn.close_on_flush = Some(CloseReason::HandlerClosed);
            }
        }
        // The dry checks are tail-guarded, so a flush-close armed here waits for the last chunk rather than truncating
        // the body.
        if close {
            self.core.drive_flush_close(slot, generation)?;
        } else {
            self.core.kick_send(slot, generation)?;
        }
        self.drive_file_tail(slot, generation, false)
    }

    /// Issue the tail's next read when it is idle, bytes remain, and both a chunk buffer and an fs op slot are free, at
    /// install, after each read completes and after sends flush. Reads are clamped to `min(fs_body_chunk, unread)`.
    ///
    /// Neither shortage is fatal. A missing buffer waits for a flush, which is the body's memory bound, and a full op
    /// table parks the connection in `parked_tails` for the next completing fs op, since severing a large transfer
    /// because a handler fan-out took the last slot would make one shortage fatal and the other free. Only a staging
    /// failure sheds the connection ([`CloseReason::FileBody`]), never the server.
    ///
    /// `owned` makes the read bring its own buffer instead of selecting from the ring, the retry for a shortage the
    /// pool could not grow past.
    #[cfg(feature = "uring-fs")]
    pub(super) fn drive_file_tail(&mut self, slot: u32, generation: u32, owned: bool) -> errno::Result<()> {
        let chunk = self.cfg.fs_body_chunk;
        {
            let Some(conn) = self.core.table.get_conn_mut(slot) else {
                return Ok(()); // closed or parked under a stale call
            };
            if conn.closing {
                return Ok(()); // teardown owns the slot
            }
            let Some(tail) = conn.file_tail.as_ref() else {
                return Ok(()); // no body streaming
            };
            if tail.reading || tail.unread == 0 {
                return Ok(()); // busy, or the last chunk is already queued
            }
        }
        // Shrinking is the maintenance tick's job (`Op::Maintain`), so this path reads no clock.
        let gen64 = self.core.table.generation(slot);
        // Before a buffer is committed to it: a submit that fails on a full table would drop the buffer with the op
        // entry, and this path must be able to retry.
        if !self.fs.as_ref().expect("tail exists only with a pool").has_free_op() {
            let conn = self.core.table.conn_mut(slot);
            let tail = conn.file_tail.as_mut().expect("checked above");
            if !tail.parked {
                tail.parked = true;
                self.parked_tails.push_back((slot, gen64));
            }
            return Ok(()); // a completing fs op frees a slot and re-drives us
        }
        if !self.core.table.conn_mut(slot).tail_claim_chunk() {
            return Ok(()); // this body's share is out; a flush frees one
        }
        // The ring picks the buffer when the read completes. Without one registered the read supplies its own, freed
        // when the chunk flushes - the same degradation the recv path takes.
        let dest = match (&self.core.body_bufs, owned) {
            (Some(_), false) => crate::uring_fs::core::PumpDest::Group(crate::uring::bufring::BGID_FILE_BODY),
            _ => crate::uring_fs::core::PumpDest::Owned(Vec::with_capacity(chunk)),
        };
        let staged = {
            // Disjoint fields, the same split `deliver_one` relies on.
            let fs = self.fs.as_mut().expect("tail exists only with a pool");
            let conn = self.core.table.conn_mut(slot);
            let tail = conn.file_tail.as_mut().expect("checked above");
            let want = tail.unread.min(chunk as u64) as usize;
            let r = fs.submit_pump_read(
                &mut self.core.engine,
                &tail.file,
                dest,
                want,
                tail.next_offset,
                (slot, gen64),
            );
            if r.is_ok() {
                tail.reading = true;
            }
            // `parked` is NOT cleared here: it is the parked list's dedup key, and this connection's entry is still
            // queued. Clearing it without removing the entry would let the same connection be pushed a second time.
            // `redrive_parked_tail` pops and clears together; the entry it then drives finds `reading` set and returns,
            // which is the ordinary no-op.
            r
        };
        if let Err(e) = staged {
            // The claim was taken for a read that never went out.
            self.core.table.conn_mut(slot).tail_release_chunk();
            return self.core.close_conn(slot, generation, CloseReason::FileBody(e));
        }
        Ok(())
    }

    /// Re-drive the connection at the head of `parked_tails`, the one that found the op table full, discarding stale
    /// entries on the way.
    ///
    /// This runs once per fs-domain CQE, which is not once per freed slot, since `FsCore::on_cqe` frees nothing for a
    /// cancel completion or a stale-generation miss. So the free-slot check comes first, or the longest-waiting
    /// connection would be popped with nothing to give it and re-parked at the back, the starvation this list exists to
    /// prevent.
    #[cfg(feature = "uring-fs")]
    pub(super) fn redrive_parked_tail(&mut self) -> errno::Result<()> {
        if !self.fs.as_ref().is_some_and(|fs| fs.has_free_op()) {
            return Ok(());
        }
        while let Some((slot, gen64)) = self.parked_tails.pop_front() {
            if self.core.table.generation(slot) != gen64 {
                continue; // slot recycled under the wait
            }
            match self.core.table.get_conn_mut(slot) {
                Some(conn) if conn.file_tail.is_some() => {
                    conn.file_tail.as_mut().expect("checked is_some").parked = false;
                }
                _ => continue, // parked, freed, or the tail is already shed
            }
            return self.drive_file_tail(slot, gen64 as u32, false);
        }
        Ok(())
    }

    /// A pump read completed. Advance the tail and queue the chunk. A stale owner, whose connection closed or slot was
    /// recycled while the read was in flight, is dropped, its op entry and fd clone already freed.
    #[cfg(feature = "uring-fs")]
    pub(super) fn on_pump_read(
        &mut self,
        owner: (u32, u64),
        done: crate::uring_fs::core::FsDone,
        bid: Option<u16>,
    ) -> errno::Result<()> {
        let (slot, gen64) = owner;
        // The kernel consumed this completion's descriptor whatever happens below (see `requeue_body_bid`), so every
        // exit that does not queue the buffer for send gives it back first. An aborted download (`conn.closing`) is the
        // routine one, and a leak there drains the ring one cancelled read at a time.
        if self.core.table.generation(slot) != gen64 {
            self.core.requeue_body_bid(bid);
            return Ok(()); // slot recycled under the read
        }
        let generation = gen64 as u32;
        let res = {
            let Some(conn) = self.core.table.get_conn_mut(slot) else {
                self.core.requeue_body_bid(bid);
                return Ok(()); // parked (detaching) or already freed
            };
            // Only `closing` stops the tail - deliberately NOT `teardown_owns_slot()`: with `close_on_flush` set the
            // tail IS the farewell body (the flush-close dry checks wait on it), so a pending flush-close must keep
            // streaming, never drop chunks.
            if conn.closing {
                self.core.requeue_body_bid(bid);
                return Ok(()); // teardown owns the slot; the sweep cancelled us
            }
            let Some(tail) = conn.file_tail.as_mut() else {
                self.core.requeue_body_bid(bid);
                return Ok(()); // tail already shed
            };
            tail.reading = false;
            done.raw_result()
        };
        let n = match res {
            // A dry ring is pressure, not a failed transfer, since the read never started. Grow the pool, and where it
            // cannot grow, which at its physical bound means only an allocation failure, re-issue the read with an
            // owned buffer so progress never waits on the pool.
            Err(errno::Errno::ENOBUFS) => {
                stat!(self.core, buf_shortages);
                let armed = self.fs.as_ref().map_or(0, |fs| fs.pump_selecting());
                let grew = self.core.body_bufs.as_mut().is_some_and(|p| p.grow(armed));
                self.core.sync_recv_buf_stats();
                self.core.table.conn_mut(slot).tail_release_chunk();
                return self.drive_file_tail(slot, generation, !grew);
            }
            Err(e) => {
                self.core.requeue_body_bid(bid);
                return self.core.close_conn(slot, generation, CloseReason::FileBody(e));
            }
            Ok(n) => n as u64,
        };
        if n == 0 {
            // EOF before the declared length: the file shrank after the header committed to a Content-Length. The
            // framing cannot renegotiate, so close mid-body - the peer sees a truncated transfer, never a short body
            // presented as complete.
            self.core.requeue_body_bid(bid);
            return self.core.close_conn(slot, generation, CloseReason::FileBodyTruncated);
        }
        let seg = match bid {
            // The kernel filled a ring buffer and named it. The segment borrows it and the id goes back when the chunk
            // flushes.
            Some(bid) => {
                // The verified pick: refused for an id the pool does not hold `Posted` - a descriptor desync. Nothing
                // of the pool's is behind such an id, so there is nothing to requeue; the chunk's bytes cannot be
                // located, so the body cannot continue.
                let Some((ptr, _cap)) = self.core.body_bufs.as_mut().and_then(|p| p.take_lent(bid)) else {
                    return self
                        .core
                        .close_conn(slot, generation, CloseReason::FileBody(errno::Errno::EIO));
                };
                // The loan may have grown the pool.
                self.core.sync_recv_buf_stats();
                // SAFETY: `n` bytes of buffer `bid`, which stays lent until the chunk flushes and `advance_sent` hands
                // the id back.
                unsafe { crate::net::core::protocol::SendBuf::pooled(ptr, n as usize, bid) }
            }
            None => {
                let mut bufs = done.into_bufs();
                let mut buf = bufs.pop().expect("a pump read carries exactly one buf");
                // SAFETY: the op's iovec targeted this Vec's spare capacity with `iov_len >= n`, and the CQE count
                // proves the kernel initialized the first `n` bytes.
                unsafe { buf.set_len(n as usize) };
                crate::net::core::protocol::SendBuf::from(buf)
            }
        };
        let last = self.core.table.conn_mut(slot).advance_file_tail(seg);
        self.core.kick_send(slot, generation)?;
        if !last {
            return self.drive_file_tail(slot, generation, false);
        }
        // The retired tail may have been holding a file body that arrived behind it; install it now that the wire is
        // free. A flush-close armed for the body that just finished makes that farewell final, so a body still queued
        // behind it is dropped rather than sent after it.
        let next = {
            let conn = self.core.table.conn_mut(slot);
            if conn.close_on_flush.is_some() {
                conn.drop_queued_file_reply();
                None
            } else {
                conn.take_queued_file_reply()
            }
        };
        match next {
            Some(next) => self.install_file_reply(slot, generation, next),
            None => Ok(()),
        }
    }
}
