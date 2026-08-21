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
        self.drive_file_tail(slot, generation)?;
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
    /// issue the first read. Refusals are loud - a close, never a short
    /// body: no fs pool to read on, or a body already streaming (a second
    /// tail's chunks would interleave with the first's on the wire).
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
        if self.core.table.conn(slot).tail_active() {
            return self.core.close_conn(
                slot,
                generation,
                CloseReason::FileBody(Errno::EBUSY),
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
        {
            let conn = self.core.table.conn_mut(slot);
            conn.outstanding += 1;
            // Head first - the diversion is not yet on - then the tail; its
            // chunks follow as reads complete, the last one `ReplyLast`.
            conn.enqueue_reply_head(head);
            conn.install_file_tail(file, offset, len);
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
        self.drive_file_tail(slot, generation)
    }

    /// Issue the tail's next read when it is idle, bytes remain, and a chunk
    /// buffer is free - at install, after each read completes, and after
    /// sends flush (which recycle buffers). Reads are clamped to
    /// `min(fs_body_chunk, unread)`, and a missing buffer just waits for a
    /// flush to recycle one: that wait is the body's memory bound. A full fs
    /// op table or staging failure sheds THIS connection
    /// ([`CloseReason::FileBody`]), never the server.
    #[cfg(feature = "uring-fs")]
    pub(super) fn drive_file_tail(
        &mut self,
        slot: u32,
        generation: u32,
    ) -> errno::Result<()> {
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
        let Some(buf) = self.core.table.conn_mut(slot).tail_take_buf(chunk)
        else {
            return Ok(()); // all buffers queued/sending; a flush recycles one
        };
        let gen64 = self.core.table.generation(slot);
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
                buf,
                want,
                tail.next_offset,
                (slot, gen64),
            );
            if r.is_ok() {
                tail.reading = true;
            }
            r
        };
        if let Err(e) = staged {
            return self.core.close_conn(
                slot,
                generation,
                CloseReason::FileBody(e),
            );
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
    ) -> errno::Result<()> {
        let (slot, gen64) = owner;
        if self.core.table.generation(slot) != gen64 {
            return Ok(()); // slot recycled under the read
        }
        let generation = gen64 as u32;
        let res = {
            let Some(conn) = self.core.table.get_conn_mut(slot) else {
                return Ok(()); // parked (detaching) or already freed
            };
            // Only `closing` stops the tail - deliberately NOT
            // `teardown_owns_slot()`: with `close_on_flush` set the tail IS
            // the farewell body (the flush-close dry checks wait on it), so
            // a pending flush-close must keep streaming, never drop chunks.
            if conn.closing {
                return Ok(()); // teardown owns the slot; the sweep cancelled us
            }
            let Some(tail) = conn.file_tail.as_mut() else {
                return Ok(()); // tail already shed
            };
            tail.reading = false;
            done.raw_result()
        };
        let n = match res {
            Err(e) => {
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
            return self.core.close_conn(
                slot,
                generation,
                CloseReason::FileBodyTruncated,
            );
        }
        let mut bufs = done.into_bufs();
        let mut buf = bufs.pop().expect("a pump read carries exactly one buf");
        // SAFETY: the op's iovec targeted this Vec's spare capacity with
        // `iov_len >= n`, and the CQE count proves the kernel initialized
        // the first `n` bytes (the stream recv path's discipline).
        unsafe { buf.set_len(n as usize) };
        let last = {
            let conn = self.core.table.conn_mut(slot);
            let tail = conn.file_tail.as_mut().expect("checked above");
            tail.next_offset += n;
            // `n <= iov_len = min(chunk, unread)`, so this never underflows;
            // a short read just leaves more for the next iteration, which
            // continues from the offset actually reached.
            tail.unread -= n;
            let last = tail.unread == 0;
            conn.enqueue_file_chunk(buf, last);
            if last {
                // The body is fully queued: retire the tail and release the
                // PDUs the diversion held behind it.
                conn.finish_file_tail();
            }
            last
        };
        self.core.kick_send(slot, generation)?;
        if last {
            Ok(())
        } else {
            self.drive_file_tail(slot, generation)
        }
    }
}
