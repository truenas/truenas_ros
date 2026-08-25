//! The per-connection request data plane's ROLE half: the header-framer pump
//! skeleton, the recv/send/splice completion wrappers (their heavy bookkeeping
//! is core - see [`Reactor`](crate::net::core::reactor)), request delivery to
//! the body handler, and the detach install/handoff. What stays here is exactly
//! the code that runs consumer closures (the framer, the body handler, the
//! detach hook) or touches server-only fields (`handlers`, `mailbox`).

use super::Server;
use super::handles::{Detached, Responder};
use crate::errno::{self, Errno};
use crate::fd::owned_from_raw;
#[cfg(feature = "uring-fs")]
use crate::net::core::conn::PendingFile;
use crate::net::core::conn::{Op, pack};
use crate::net::core::handles::{Token, stat};
use crate::net::core::protocol::{CloseReason, Framing};
use crate::net::core::reactor::{
    Enacted, Gate, RecvStep, SendStep, SpliceStep,
};
use crate::net::server::protocol::{DetachContext, Request, Response};
use crate::sync::Arc;
use crate::uring::sys::*;

// The stages that run the consumer's framer/body handler - the only bounds
// this file needs (the accept handler never runs here).
impl<U, AcceptFn, HeaderFn, BodyFn> Server<U, AcceptFn, HeaderFn, BodyFn>
where
    HeaderFn: FnMut(&[u8], &mut U) -> Framing,
    BodyFn: FnMut(Request<'_, U>) -> Response,
{
    /// The per-connection read/deliver pump: consult the header framer on the
    /// accumulated bytes and either read more, deliver a buffered request, or
    /// close. In pipelined mode it delivers every already-buffered request and
    /// arms the next recv - up to the `max_in_flight_requests` cap - so a
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
    /// returned [`RecvStep`] drives the delivery/pump tail - a completed body
    /// delivers then pumps, a completed header re-pumps, everything else is
    /// self-contained.
    pub(super) fn on_recv(
        &mut self,
        slot: u32,
        generation: u32,
        res: i32,
        cqe_flags: u32,
        op: Op,
    ) -> errno::Result<()> {
        // A completion carrying `IORING_CQE_F_BUFFER` selected one from the
        // pool: adopt it before the bytes are read, so the framer sees them
        // where the kernel put them. A refused adopt means the completion
        // names a buffer the pool cannot vouch for, so its bytes cannot be
        // located and framing from the (never-installed) claim would read
        // garbage as the peer's - fail the read instead.
        if !self.core.adopt_recv_buffer(slot, generation, cqe_flags) {
            if !self.core.table.slot_matches_cqe(slot, generation) {
                return Ok(()); // stale completion; the slot moved on
            }
            // Retire the op before closing, exactly as a completion does.
            // `close_conn` defers teardown while `ops` is charged, so
            // skipping this leaves the slot, its fixed descriptor and the
            // socket held for the reactor's life, with the peer getting
            // neither a reply nor a FIN.
            self.core.table.conn_mut(slot).recving = false;
            if !self.core.op_done(slot)? {
                return Ok(()); // already tearing down
            }
            return self.core.close_conn(
                slot,
                generation,
                CloseReason::RecvError(errno::Errno::EIO),
            );
        }
        match self.core.on_recv_complete(slot, generation, res, op)? {
            RecvStep::Deliver => {
                self.deliver_one(slot, generation)?;
                self.pump(slot, generation)
            }
            RecvStep::Pump => self.pump(slot, generation),
            RecvStep::Done => Ok(()),
        }
    }

    /// A parked read's pool-shortage backoff elapsed (`Op::RecvRetry`).
    /// Re-pump the connection - the framer is pure over what is buffered,
    /// so this re-arms exactly the read that found the pool dry, and a
    /// pool still dry parks it again. The 10 ms window between park and
    /// retry admits arbitrary progress on the connection - a deferred
    /// reply resolving, a splice arming, a flush-close, teardown - and
    /// `pump_gate` is the single authority on every one of those states,
    /// so beyond clearing the timer's dedup flag this adds no gating of
    /// its own (a stale slot is refused before the flag is touched; a
    /// stopping reactor stages nothing new). Not counted in `conn.ops`,
    /// exactly like the other standalone timers.
    pub(super) fn on_recv_retry(
        &mut self,
        slot: u32,
        generation: u32,
    ) -> errno::Result<()> {
        if !self.core.table.slot_matches_cqe(slot, generation) {
            // Left set, this flag reads to `recv_buffer_shortage` as "a
            // timer is pending", so every later shortage parks the read
            // with nothing able to wake it and the connection holds its
            // slot with no op in flight. See `conn_at_cqe_mut`.
            if let Some(conn) =
                self.core.table.conn_at_cqe_mut(slot, generation)
            {
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

    /// A body splice completed (`Op::SpliceRecv`). All the completion
    /// bookkeeping is core ([`Reactor::on_splice_recv_complete`]); a fully moved
    /// body pumps the next frame. The body never entered the buffer, so there is
    /// **no** `deliver_one` - the framer that returned `SpliceBody` was the
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
    /// sending), park for a deferred reply, or close. Also the re-entry point
    /// for [`Deferred::redeliver`], where the current frame is empty and the
    /// handler works from its own retained state.
    pub(super) fn deliver_one(
        &mut self,
        slot: u32,
        generation: u32,
    ) -> errno::Result<()> {
        // Borrow-split: `self.handlers`, `self.core.table`, and `self.mailbox` are
        // disjoint fields; within the connection, buf/addr (immutable) vs
        // userdata (mutable). The Responder holds owned channel clones.
        // The token carries the FULL u64 generation - a worker may retain it
        // across recycles - whereas the kernel routing used the low 32 bits.
        // Receipt is over the moment the message is handed to the handler,
        // so the budget is retired here rather than when the next read is
        // armed. Anything later would clock the *handling* too, and a
        // request offloaded with `Response::Defer` may legitimately run for
        // as long as it likes.
        self.core.cancel_receipt_deadline(slot, generation)?;
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
            // The leased form also hands out the recv claim, so a
            // handler's `pwritev2_from` can write the body straight from
            // the buffer.
            #[cfg(feature = "uring-fs")]
            let (header, body, peer, state, lease) = conn
                .deliver_parts_leased(self.core.cfg.body_placement_threshold);
            #[cfg(not(feature = "uring-fs"))]
            let (header, body, peer, state) =
                conn.deliver_parts(self.core.cfg.body_placement_threshold);
            // The fs facade borrows the engine and the fs tables - fields
            // disjoint from `self.core.table` (which `conn` holds) and
            // `self.handlers`, so all three borrows coexist for the handler
            // call. `None` when no fs pool was configured.
            #[cfg(feature = "uring-fs")]
            let fs = self.fs.as_mut().map(|fc| {
                crate::uring_fs::core::FsConn::new(
                    fc,
                    &mut self.core.engine,
                    Some((slot, gen64)),
                    // Request-handler facade: `open` may mint a new file here.
                    true,
                )
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
        // The handler has taken what it needs; drop the request from the recv
        // buffer so the next request can be read into it.
        self.core.table.conn_mut(slot).consume();
        // Nothing buffered means nothing to hold a buffer for: give it back
        // so a connection waiting on its next request costs none.
        self.core.release_recv_buffer(slot);
        stat!(self.core, requests);
        match resp {
            Response::Close => self.core.close_conn(
                slot,
                generation,
                CloseReason::HandlerClosed,
            ),
            Response::Defer(permit) => {
                // The permit type proves defer() was called - but only its
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
                    // `closing`/`ops`: a teardown already in flight owns this
                    // slot's remaining completions, and parking it as
                    // `Detaching` would take it out of the state those
                    // completions are accounted against.
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
                // recv side - buffered pipelined requests are discarded --
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
            // One logical reply sent as vectored segments (a header + payload
            // the protocol handed over separately). Mirrors Reply/ReplyClose:
            // bump `outstanding` once iff any bytes are queued - the segment
            // helper flags only the last non-empty segment, so the retire
            // count stays one - then keep serving or flush-close on `close`.
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
            // A file-sourced body: queue the head as a non-final segment,
            // install the tail, and issue the first read. The final chunk's
            // `ReplyLast` retires the reply, so the read-ahead cap holds
            // pipelined requests until the body completes and a flush-close
            // waits for it (the dry checks are tail-guarded).
            #[cfg(feature = "uring-fs")]
            Response::ReplyFile {
                head,
                file,
                offset,
                len,
                close,
            } => self.begin_file_reply(
                slot, generation, head, file, offset, len, close,
            ),
        }
    }

    /// A send completed (`Op::Send`). All the completion bookkeeping - the
    /// gather-advance accounting, the partial-send re-arm, the next-batch kick,
    /// the flush-close finish - is core ([`Reactor::on_send_complete`]); a fully
    /// flushed gather resumes the pump.
    pub(super) fn on_send(
        &mut self,
        slot: u32,
        generation: u32,
        res: i32,
    ) -> errno::Result<()> {
        let step = self.core.on_send_complete(slot, generation, res)?;
        // Flushed tail chunks just recycled their buffers into the spare
        // pool (`advance_sent`); a read that was waiting on one can go now.
        // A no-op on a closed connection or without an active tail.
        #[cfg(feature = "uring-fs")]
        self.drive_file_tail(slot, generation, false)?;
        match step {
            SendStep::Pump => self.pump(slot, generation),
            SendStep::Done => Ok(()),
        }
    }
}

// Recv/send submission and transport checks - no handler runs here, so no
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
        // Kernel completion -> low 32 bits. The slot is `Detaching`, not
        // `Serving`, so `slot_matches_cqe` doesn't apply - check directly.
        if self.core.table.generation_low(slot) != generation {
            if res >= 0 {
                // The kernel furnished the fd before the slot was recycled, so
                // declining it here still leaks it unless we close it. Every
                // path that does not hand the fd to a `Detached` owns closing
                // it - this one included.
                // SAFETY: `res` is the freshly installed fd, owned by us and
                // consumed by nobody (the pool socket survives on the direct
                // descriptor).
                unsafe { libc::close(res) };
            }
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
        // Hand off. Park first, then run the handler against the parked slot,
        // as the kTLS install->park does (`park_tls` precedes its handshake
        // handler): the connection must not leave the table across consumer
        // code - see `park_detached_in_place`.
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

    /// Enact [`Response::ReplyFile`]: queue the head, install the tail, and
    /// issue the first read. Refusals are loud - a close, never a short body:
    /// no fs pool to read on, or a range whose arithmetic wrapped.
    ///
    /// A body already streaming is NOT a refusal, and must not become one.
    /// One tail at a time is structural (two tails' chunks would interleave on
    /// the wire), but by the time a second arrives the first response is
    /// committed - its head and `Content-Length` are on the wire - so shedding
    /// the connection destroys that one too, and it is the one that did
    /// nothing wrong. The second queues behind the current body through the
    /// same diversion every other PDU uses, and installs when it retires.
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
            return self.core.close_conn(
                slot,
                generation,
                CloseReason::FileBody(Errno::EOPNOTSUPP),
            );
        }
        // Nothing to stream: the head is the whole reply (mirrors the
        // ReplyVectored disposition, including the empty one-way case).
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
        // Every offset this tail submits lands in `sqe.off_addr2`, which the
        // kernel reads as a signed `loff_t`, so the range has to be bounded
        // here - the one place an untrusted one enters. `u64::MAX` is `-1`,
        // io_uring's "use the file's own position" sentinel: for a regular
        // file `io_kiocb_update_pos` (linux `io_uring/rw.c:484-490`) would set
        // `REQ_F_CUR_POS`, read `f_pos` in place of the offset asked for, and
        // `rw.c:670-671` would write the new position back - a read that
        // SUCCEEDS from the wrong place, mutating a position shared with every
        // other holder of the descriptor, behind a correctly framed
        // `Content-Length`. ZFS sets neither `FMODE_STREAM` nor
        // `FMODE_UNSIGNED_OFFSET`, so neither kernel escape applies. Anything
        // else past `i64::MAX` is refused by `rw_verify_area`
        // (`fs/read_write.c:463`) - after the head has committed.
        //
        // A suffix range is how a wrapped value arrives: `bytes=-N` past the
        // object size is legal, and computing the start as `size - N` wraps in
        // `u64` rather than clamping at zero. The SUM is bounded, not just the
        // start, because `next_offset` walks to `offset + len` - which is also
        // what keeps the advance in `on_pump_read` from wrapping.
        //
        // The check belongs here and not in the submit path: down there
        // `u64::MAX` is the correct idiom for a stream file with no position,
        // which `cancel_owned_by_reaches_a_pump_read` reads a pipe with.
        if offset
            .checked_add(len)
            .is_none_or(|end| end > i64::MAX as u64)
        {
            return self.core.close_conn(
                slot,
                generation,
                CloseReason::FileBody(Errno::EINVAL),
            );
        }
        let next = PendingFile {
            head,
            file,
            offset,
            len,
            close,
        };
        // Counted outstanding here rather than at install, so it is counted
        // exactly once either way: the read-ahead cap must see an answered
        // request whether its body starts now or waits its turn.
        let conn = self.core.table.conn_mut(slot);
        conn.outstanding += 1;
        if conn.tail_active() {
            // A body is already streaming: hold this one behind it, in
            // arrival order with the PDUs the same diversion is holding.
            conn.defer_file_reply(next);
            return Ok(());
        }
        self.install_file_reply(slot, generation, next)
    }

    /// Queue a file reply's head, install its tail, and issue the first read.
    /// The count against the read-ahead cap is the caller's - a body deferred
    /// behind another was counted when it was deferred.
    #[cfg(feature = "uring-fs")]
    fn install_file_reply(
        &mut self,
        slot: u32,
        generation: u32,
        next: PendingFile,
    ) -> errno::Result<()> {
        let close = next.close;
        {
            let conn = self.core.table.conn_mut(slot);
            // Head first - the diversion is not yet on - then the tail; its
            // chunks follow as reads complete, the last one `ReplyLast`.
            conn.enqueue_reply_head(next.head);
            conn.install_file_tail(next.file, next.offset, next.len);
            if close {
                conn.close_on_flush = Some(CloseReason::HandlerClosed);
            }
        }
        // The dry checks are tail-guarded, so a flush-close armed here waits
        // for the last chunk rather than truncating the body.
        if close {
            self.core.drive_flush_close(slot, generation)?;
        } else {
            self.core.kick_send(slot, generation)?;
        }
        self.drive_file_tail(slot, generation, false)
    }

    /// Issue the tail's next read when it is idle, bytes remain, and both a
    /// chunk buffer and an fs op slot are free - at install, after each read
    /// completes, and after sends flush (which recycle buffers). Reads are
    /// clamped to `min(fs_body_chunk, unread)`.
    ///
    /// Neither shortage is fatal, and deliberately so: they are the same kind
    /// of transient. A missing buffer waits for a flush to recycle one - that
    /// wait is the body's memory bound - and a full op table parks the
    /// connection in `parked_tails` for the next completing fs op to re-drive.
    /// Severing a multi-GB transfer because a handler fan-out momentarily took
    /// the last slot would make the one shortage fatal and the other free.
    /// A staging failure (the ring itself refused the SQE) still sheds THIS
    /// connection ([`CloseReason::FileBody`]), never the server.
    ///
    /// `owned` forces the read to bring its own buffer instead of selecting
    /// from the ring - the retry path for a shortage the pool could not
    /// grow past, so progress never waits on the pool.
    #[cfg(feature = "uring-fs")]
    pub(super) fn drive_file_tail(
        &mut self,
        slot: u32,
        generation: u32,
        owned: bool,
    ) -> errno::Result<()> {
        let chunk = self.cfg.fs_body_chunk;
        // The pool's shrink cadence: pressure is answered where the kernel
        // reports it (`-ENOBUFS` in `on_pump_read`), but quiet has no
        // completion to ride, so it is observed here, where every body read
        // begins.
        if let Some(p) = self.core.body_bufs.as_mut() {
            p.rebalance();
        }
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
        let gen64 = self.core.table.generation(slot);
        // Before a buffer is committed to it: a submit that fails on a full
        // table would drop the buffer with the op entry, and this path must be
        // able to retry.
        if !self
            .fs
            .as_ref()
            .expect("tail exists only with a pool")
            .has_free_op()
        {
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
        // The ring picks the buffer when the read completes. Without one
        // registered the read supplies its own, freed when the chunk
        // flushes - the same degradation the recv path takes.
        let dest = match (&self.core.body_bufs, owned) {
            (Some(_), false) => crate::uring_fs::core::PumpDest::Group(
                crate::uring::bufring::BGID_FILE_BODY,
            ),
            _ => crate::uring_fs::core::PumpDest::Owned(Vec::with_capacity(
                chunk,
            )),
        };
        let staged = {
            // Disjoint fields: `self.fs`, `self.core.engine`,
            // `self.core.table` - the same split `deliver_one` relies on.
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
            // `parked` is NOT cleared here: it is the parked list's dedup
            // key, and this connection's entry is still queued. Clearing it
            // without removing the entry would let the same connection be
            // pushed a second time. `redrive_parked_tail` pops and clears
            // together; the entry it then drives finds `reading` set and
            // returns, which is the ordinary no-op.
            r
        };
        if let Err(e) = staged {
            // The claim was taken for a read that never went out.
            self.core.table.conn_mut(slot).tail_release_chunk();
            return self.core.close_conn(
                slot,
                generation,
                CloseReason::FileBody(e),
            );
        }
        Ok(())
    }

    /// Re-drive the connection at the head of `parked_tails` - the one that
    /// found the op table full. Stale entries (the connection closed or its
    /// slot was recycled) are discarded on the way past.
    ///
    /// Called once per completing fs-domain CQE, which is **not** the same as
    /// once per freed slot: `FsCore::on_cqe` returns early for a cancel
    /// completion and for a stale-generation miss, and neither frees
    /// anything. So the free-slot check comes first - popping the
    /// longest-waiting connection when there is nothing to give it would
    /// re-park it at the back and hand its turn to whoever is behind it,
    /// which is the starvation this list exists to prevent.
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
                    conn.file_tail.as_mut().expect("checked is_some").parked =
                        false;
                }
                _ => continue, // parked, freed, or the tail is already shed
            }
            return self.drive_file_tail(slot, gen64 as u32, false);
        }
        Ok(())
    }

    /// A pump read completed ([`ReapedFs`](crate::uring_fs::core::ReapedFs)
    /// `::Pump`): advance the tail and queue the chunk. A stale owner - the
    /// connection closed or its slot recycled while the read was in flight
    /// (the closed-connection sweep's cancel, or a completion racing
    /// teardown) - is dropped; the op entry already freed and its parked fd
    /// clone dropped with it.
    #[cfg(feature = "uring-fs")]
    pub(super) fn on_pump_read(
        &mut self,
        owner: (u32, u64),
        done: crate::uring_fs::core::FsDone,
        bid: Option<u16>,
    ) -> errno::Result<()> {
        let (slot, gen64) = owner;
        // The kernel consumed this completion's descriptor whatever happens
        // below (`requeue_body_bid`'s doc has the citation), so every exit
        // that does not queue the buffer into a send segment owes it back
        // first - the aborted-download path (`conn.closing`) is the routine
        // one, and it is exactly the exit a leak turns into a slow drain of
        // the whole ring, one cancelled GET at a time.
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
            // Only `closing` stops the tail - deliberately NOT
            // `teardown_owns_slot()`: with `close_on_flush` set the tail IS
            // the farewell body (the flush-close dry checks wait on it), so
            // a pending flush-close must keep streaming, never drop chunks.
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
            // A dry ring is pressure, not a failed transfer: the read never
            // started and nothing was lost. Doubling converges on the burst
            // in a few round trips; a pool that cannot grow further - its
            // ceiling is already the physical bound, so only an allocation
            // failure - re-issues the read with an owned buffer, so
            // progress never waits on the pool.
            Err(errno::Errno::ENOBUFS) => {
                let grew =
                    self.core.body_bufs.as_mut().is_some_and(|p| p.grow());
                self.core.sync_recv_buf_stats();
                self.core.table.conn_mut(slot).tail_release_chunk();
                return self.drive_file_tail(slot, generation, !grew);
            }
            Err(e) => {
                self.core.requeue_body_bid(bid);
                return self.core.close_conn(
                    slot,
                    generation,
                    CloseReason::FileBody(e),
                );
            }
            Ok(n) => n as u64,
        };
        if n == 0 {
            // EOF before the declared length: the file shrank after the
            // header committed to a Content-Length. The framing cannot
            // renegotiate, so close mid-body - the peer sees a truncated
            // transfer, never a short body presented as complete.
            self.core.requeue_body_bid(bid);
            return self.core.close_conn(
                slot,
                generation,
                CloseReason::FileBodyTruncated,
            );
        }
        let seg = match bid {
            // The kernel filled a ring buffer and named it. The segment
            // borrows it and the id goes back when the chunk flushes.
            Some(bid) => {
                // The verified pick: refused for an id the pool does not
                // hold `Posted` - a descriptor desync. Nothing of the
                // pool's is behind such an id, so there is nothing to
                // requeue; the chunk's bytes cannot be located, so the
                // body cannot continue.
                let Some((ptr, _cap)) =
                    self.core.body_bufs.as_mut().and_then(|p| p.take_lent(bid))
                else {
                    return self.core.close_conn(
                        slot,
                        generation,
                        CloseReason::FileBody(errno::Errno::EIO),
                    );
                };
                // SAFETY: `n` bytes of buffer `bid`, which stays lent until
                // the chunk flushes and `advance_sent` hands the id back.
                unsafe {
                    crate::net::core::protocol::SendBuf::pooled(
                        ptr, n as usize, bid,
                    )
                }
            }
            None => {
                let mut bufs = done.into_bufs();
                let mut buf =
                    bufs.pop().expect("a pump read carries exactly one buf");
                // SAFETY: the op's iovec targeted this Vec's spare capacity
                // with `iov_len >= n`, and the CQE count proves the kernel
                // initialized the first `n` bytes.
                unsafe { buf.set_len(n as usize) };
                crate::net::core::protocol::SendBuf::from(buf)
            }
        };
        let last = self.core.table.conn_mut(slot).advance_file_tail(seg);
        self.core.kick_send(slot, generation)?;
        if !last {
            return self.drive_file_tail(slot, generation, false);
        }
        // The retired tail may have been holding a file body that arrived
        // behind it; install it now that the wire is free. A flush-close armed
        // for the body that just finished makes that farewell final, so a body
        // still queued behind it is dropped rather than sent after it.
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
