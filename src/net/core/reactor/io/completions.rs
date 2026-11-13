use super::*;

impl<U> Reactor<U> {
    pub(crate) fn on_recv_complete(&mut self, slot: u32, generation: u32, res: i32, op: Op) -> errno::Result<RecvStep> {
        if !self.table.slot_matches_cqe(slot, generation) {
            return Ok(RecvStep::Done);
        }
        // Only header reads are ever armed idle (parked between requests);
        // body reads - and every kTLS continuation - are active transfers.
        let was_idle = {
            let conn = self.table.conn_mut(slot);
            conn.recving = false;
            op == Op::RecvHeader && conn.recv_idle
        };
        if res > 0 {
            stat!(self, bytes_in, res as u64);
            stat!(self, recv_ops);
        }
        if !self.op_done(slot)? {
            return Ok(RecvStep::Done); // tearing down (maybe just freed)
        }
        // Flush-closing (`close_on_flush`): the recv side is retired. Data is left unexposed in spare capacity (never
        // delivered - the pump is gated), an EOF or error is moot (a peer half-close must not beat the farewell out of
        // the queue), and nothing re-arms; the send side owns the close once the queue drains (`on_send`), with a
        // genuinely dead peer surfacing there as a send failure. `recv_result` is skipped: its buffer/cursor
        // bookkeeping only matters to a next read that will never be armed.
        if self.table.conn(slot).close_on_flush.is_some() {
            return Ok(RecvStep::Done);
        }
        // Same answer for a peer that half-closed while a reply was owed: this completion does not re-pump. A FIN
        // re-completes a re-armed recv immediately, so answering `Pump` here - what the idle clock does - spins the
        // loop instead of waiting, measured at 465ms of CPU against 62ms over the same 800ms of owed work.
        //
        // `pump_gate` retires the recv side on this flag as well, so nothing re-arms a read while it is set and this
        // arm is a backstop rather than the steady state. It stays because what losing it costs is the spin above; it
        // is not a closing path.
        // The close belongs to `pump_gate` when the owed work ends with nothing on the wire, and to `on_send_complete`
        // when bytes flush.
        if self.table.conn(slot).peer_closed.is_some() {
            return Ok(RecvStep::Done);
        }
        // Not a transfer outcome: the read never started, because the pool had no buffer to select. Grow (or fall back
        // to owning one) and re-pump - the framer is pure over what is buffered, and nothing was received, so it
        // re-arms exactly this read.
        #[cfg(feature = "net-server")]
        if res < 0 && Errno::from_raw(-res) == Errno::ENOBUFS {
            return Ok(if self.recv_buffer_shortage(slot, generation)? {
                RecvStep::Pump
            } else {
                RecvStep::Done
            });
        }
        match self.table.conn_mut(slot).recv_result(res) {
            // EOF (half-close / keep-alive ended), truncation, cancel, error.
            RecvOutcome::Failed => {
                // A short-POSITIVE exact read never re-enters the pump: the peer made partial progress, and those bytes
                // sit unexposed in the recv buffer's spare capacity - a re-pump would re-frame from before them and
                // desync the stream. It either closes or (request clock fired on an active plain-TCP transfer) resumes
                // the same read past them (`resubmit_exact_recv`). The verdict may be deferred:
                //
                // A kTLS control record can complete an exact read short (the kernel stops the RECVMSG at the record
                // boundary): a peer's clean close_notify is TlsControl, not TruncatedMessage.
                if res > 0 && self.ktls_control_record(slot) {
                    self.close_conn(slot, generation, CloseReason::TlsControl)?;
                    return Ok(RecvStep::Done);
                }
                // Otherwise a short exact read is AMBIGUOUS when the recv carried a linked clock: a cancelled
                // `MSG_WAITALL` recv that had consumed bytes completes with `res = done_io > 0` (io_uring/net.c
                // `io_sendrecv_fail`) - bit-identical to a peer FIN mid-frame. Only the clock's own CQE
                // (`Op::RecvClock`: `-ETIME` fired vs `-ECANCELED` this recv won) tells RequestTimeout/IdleTimeout from
                // a truncation, so park the close on it when it hasn't reaped yet - both CQEs of a linked pair are
                // queued by the same task-work run, so the stash resolves within this same reap batch.
                if res > 0 {
                    // Progress first, verdict second: advance the cursor past the partial bytes unconditionally,
                    // because every path out of here either closes (the cursor dies with the connection) or continues
                    // the read from it - and the stash path resolves without the count in hand.
                    self.table.conn_mut(slot).advance_exact_partial(res as usize);
                    let (armed, fired) = {
                        let c = self.table.conn(slot);
                        (c.recv_clock_armed, c.recv_clock_fired)
                    };
                    let fired = match (armed, fired) {
                        (false, _) => false,
                        (true, Some(fired)) => fired,
                        (true, None) => {
                            self.table.conn_mut(slot).recv_close_stash = Some((was_idle, op));
                            return Ok(RecvStep::Done);
                        }
                    };
                    if self.exact_partial_continues(slot, fired, was_idle) {
                        self.resubmit_exact_recv(slot, generation, op)?;
                        return Ok(RecvStep::Done);
                    }
                    let reason = self.short_recv_reason(fired, was_idle);
                    self.close_conn(slot, generation, reason)?;
                    return Ok(RecvStep::Done);
                }
                // A zero-progress cancel/EOF (`res <= 0`) MAY re-enter the pump (drain / idle-owes-work) - nothing was
                // consumed, so nothing desyncs. `finish_failed_recv` applies that rule.
                let reason = self.recv_close_reason(res, was_idle);
                self.finish_failed_recv(slot, generation, reason)
            }
            // kTLS short read: the rest of the frame is still in flight.
            RecvOutcome::Again => {
                self.resubmit_ktls_recv(slot, generation, op)?;
                Ok(RecvStep::Done)
            }
            RecvOutcome::Complete => {
                if self.ktls_control_record(slot) {
                    self.close_conn(slot, generation, CloseReason::TlsControl)?;
                    return Ok(RecvStep::Done);
                }
                // A completed body read finishes the current message (split already set by `pump`): deliver it, then
                // pump for the next pipelined request. A completed header read just re-enters the pump.
                if op == Op::RecvBody {
                    Ok(RecvStep::Deliver)
                } else {
                    Ok(RecvStep::Pump)
                }
            }
        }
    }

    /// Close out a `Failed` recv with `reason` - unless it is a parked read-ahead recv (nothing buffered) cancelled
    /// while the connection still owes work, which must NOT close: the graceful drain (`begin_drain` cancels parked
    /// recvs, which `shutdown_graceful` promises to let that work finish), or `idle_timeout` firing on a *pipelined*
    /// connection's read-ahead recv while a `Response::Defer` is still outstanding (a normal client that sends one
    /// request and awaits its reply before sending the next parks this recv while the worker runs -- closing here would
    /// drop that reply, since once `closing`, `kick_send`'s `!closing` guard suppresses the send that
    /// `drain_injections` still enqueues).
    ///
    /// Those re-enter the `pump` (returns [`RecvStep::Pump`]): it re-arms the read-ahead recv and lets the outstanding
    /// work complete (`on_send`/`Injected::Done` re-pump). The drain path closes once quiesced; a non-draining
    /// connection closes on the next `idle_timeout` fire once it is genuinely idle (no work in flight) - so this
    /// reclaims a real slow-loris while never dropping an owed reply. A mid-message recv (buffered>0) is a real request
    /// stall - it closes ([`RecvStep::Done`]).
    ///
    /// `served_since_idle_arm` extends "owes work" to the fire that RACES the finish of that work: the idle clock runs
    /// from recv ARM time, so it keeps counting while a deferred reply is produced and flushed. A fire whose interval
    /// saw a completed send measured busy time, not quiet - it re-arms a fresh clock (clearing the flag) instead of
    /// reaping, which otherwise races the just-served client's next request (reply flushed, clock expired, client's
    /// follow-up hits EOF).
    /// Only a fire whose whole interval was quiet - nothing owed, nothing flushed - closes. A peer can never set the
    /// flag itself (it marks server-initiated sends), so an idle-forever connection still closes on its first expiry.
    fn finish_failed_recv(&mut self, slot: u32, generation: u32, reason: CloseReason) -> errno::Result<RecvStep> {
        if self.table.conn(slot).buffered() == 0 {
            if self.draining && matches!(reason, CloseReason::ShuttingDown) {
                return Ok(RecvStep::Pump);
            }
            if matches!(reason, CloseReason::IdleTimeout) {
                let owes_work = {
                    let c = self.table.conn(slot);
                    c.outstanding > 0 || c.sending || c.has_pending_send() || c.served_since_idle_arm
                };
                if owes_work {
                    return Ok(RecvStep::Pump);
                }
            }
            // A peer that half-closed after its request is being polite, not gone: `shutdown(SHUT_WR)` completes the
            // parked read-ahead recv with `res == 0`, which is `PeerClosed` rather than `IdleTimeout`, so the guard
            // above never saw it and the connection was torn down with the reply still owed. `closing` then makes
            // `kick_send` swallow the queued reply, `drain_injections` drop the worker outcome and `on_pump_read` drop
            // every file-body chunk - a correctly framed GET answering zero bytes. Only reachable above a read-ahead of
            // one, which is the default, so nothing in tree meets it yet.
            //
            // It cannot re-pump like the clock does (a FIN re-completes at once and the loop spins) and it cannot arm
            // `close_on_flush` (that makes `teardown_owns_slot()` true, and the outcome is dropped anyway). So the recv
            // side retires here and the send side closes when nothing is owed.
            //
            // **`PeerClosed` only, and do not widen this.** `recv_close_reason` answers it for `res == 0` on an *idle*
            // recv - the read-ahead parked between requests, which is where a peer that finished asking and half-closed
            // lands. The same `res == 0` on a non-idle recv is `TruncatedMessage`: the peer went away mid-message, that
            // request can never complete, and holding the connection open for it would wait on bytes that are not
            // coming.
            //
            // Note also what is *not* in `owes_work` here: `served_since_idle_arm`, which the clock above needs. That
            // asks "has this connection served anything since the timer was armed", which is a question about the idle
            // measurement, not about whether a response is owed now.
            if matches!(reason, CloseReason::PeerClosed) {
                let c = self.table.conn_mut(slot);
                let owes_work = c.outstanding > 0 || c.sending || c.has_pending_send() || c.tail_active();
                if owes_work {
                    c.peer_closed = Some(reason);
                    return Ok(RecvStep::Done);
                }
            }
        }
        self.close_conn(slot, generation, reason)?;
        Ok(RecvStep::Done)
    }

    /// A splice-readiness `POLL_ADD` completed (`Op::SplicePoll`): the socket is readable again after a body splice hit
    /// `-EAGAIN`. Resubmit the splice for the remaining bytes. A poll cancelled at teardown drives `op_done` (which
    /// bails); a genuine poll error closes the connection. Fully core: the body never entered the buffer, so no
    /// delivery/pump seam.
    pub(crate) fn on_splice_poll(&mut self, slot: u32, generation: u32, res: i32) -> errno::Result<()> {
        if !self.table.slot_matches_cqe(slot, generation) {
            return Ok(());
        }
        self.table.conn_mut(slot).splice_polling = false;
        if !self.op_done(slot)? {
            return Ok(()); // tearing down (poll cancelled by close_conn)
        }
        if res < 0 {
            // A cancel bailed in `op_done` above; any other negative is a real poll failure. Close on it (the socket
            // won't become readable).
            let reason = self.recv_close_reason(res, false);
            return self.close_conn(slot, generation, reason);
        }
        // Readable (POLLIN, possibly with POLLERR/POLLHUP in the revents mask): resubmit the splice, which now finds
        // data - or surfaces EOF/error and closes through the normal `on_splice_recv` path.
        let (fd, remaining) = {
            let conn = self.table.conn(slot);
            (conn.splice_fd, conn.splice_remaining)
        };
        self.submit_splice_recv(slot, generation, fd, remaining, false)
    }

    /// The core of a body-splice completion (`Op::SpliceRecv`): the stat, the op-count drain,
    /// `-EAGAIN`->readiness-poll, the kTLS control/deadline/EOF close classification, the short-splice resubmit, and -
    /// on a fully moved body - retiring the watchdog and dropping the header. Returns the [`SpliceStep`] its role
    /// wrapper enacts. The body never entered the buffer, so a full body pumps the *next* frame (`Pump`); there is no
    /// `deliver_one` - the framer that returned `SpliceBody` was the per-frame consumer hook.
    pub(crate) fn on_splice_recv_complete(
        &mut self,
        slot: u32,
        generation: u32,
        res: i32,
    ) -> errno::Result<SpliceStep> {
        if !self.table.slot_matches_cqe(slot, generation) {
            return Ok(SpliceStep::Done);
        }
        self.table.conn_mut(slot).splicing = false;
        if res > 0 {
            stat!(self, bytes_in, res as u64);
        }
        if !self.op_done(slot)? {
            return Ok(SpliceStep::Done); // tearing down (deferred-teardown cancel)
        }
        if res < 0 {
            let e = Errno::from_raw(-res);
            // `-EAGAIN` is NOT an error: the non-blocking pool socket had no data the moment this splice ran on io-wq
            // (io_uring forces splice async and, unlike RECV, never poll-retries it). Wait for the socket to be
            // readable, then resubmit the splice for the remainder. Only plain sockets surface this -
            // `tls_sw_splice_read` blocks for a record.
            if e == Errno::EAGAIN {
                self.submit_splice_poll(slot, generation)?;
                return Ok(SpliceStep::Done);
            }
            // On a kTLS splice, `-EINVAL` is the kernel refusing to splice a control record (a TLS 1.3 KeyUpdate, or an
            // alert / close_notify): `tls_sw_splice_read` requeues the record and returns `-EINVAL`. Classify it as
            // `TlsControl`, matching the buffered kTLS path's "close on any non-`application_data` record" policy. A
            // teardown cancel's `-ECANCELED` never reaches here (`op_done` bailed above), so a cancel here is the
            // inactivity WATCHDOG cancelling a stalled kTLS splice (`on_splice_deadline` -> `submit_cancel_splice`):
            // `-ECANCELED` when the splice hadn't started on io-wq yet, or the signal-interrupted record wait when it
            // was blocked - which surfaces raw as `-ERESTARTSYS` (512), since io_uring's splice op, unlike its net ops,
            // posts `do_splice`'s return verbatim (kernel io_uring/splice.c) with no `-EINTR` conversion.
            const ERESTARTSYS: i32 = 512; // kernel-internal; no libc constant
            let ktls = self.table.conn(slot).is_ktls();
            let reason = if e == Errno::EINVAL && ktls {
                CloseReason::TlsControl
            } else if ktls
                && self.cfg.request_timeout.is_some()
                && (e == Errno::ECANCELED || e == Errno::EINTR || -res == ERESTARTSYS)
            {
                CloseReason::RequestTimeout
            } else {
                self.recv_close_reason(res, false)
            };
            self.close_conn(slot, generation, reason)?;
            return Ok(SpliceStep::Done);
        }
        if res == 0 {
            // Peer EOF mid-body: the socket closed before `body_len` was moved.
            let reason = self.recv_close_reason(0, false);
            self.close_conn(slot, generation, reason)?;
            return Ok(SpliceStep::Done);
        }
        if !self.table.conn_mut(slot).advance_splice(res as usize) {
            // Short splice: continue the remainder from the same fd.
            let (fd, remaining) = {
                let conn = self.table.conn(slot);
                (conn.splice_fd, conn.splice_remaining)
            };
            self.submit_splice_recv(slot, generation, fd, remaining, false)?;
            return Ok(SpliceStep::Done);
        }
        // Whole body spliced: retire the inactivity watchdog (kTLS only; a no-op otherwise) and the receipt budget,
        // drop the header from the buffer (the body never entered it), and frame the next message.
        //
        // The budget MUST be retired here. There is no `deliver_one` on this path - the framer that returned
        // `SpliceBody` was the per-frame consumer hook - so this is the only place the message ends, and a budget left
        // armed reaps the connection mid-idle for having completed a transfer on time. Until it fired it also
        // suppressed the budget of every later message, `arm_receipt_deadline` being idempotent on the flag.
        self.cancel_splice_deadline(slot, generation)?;
        #[cfg(feature = "net-server")]
        self.cancel_receipt_deadline(slot, generation)?;
        self.table.conn_mut(slot).consume();
        Ok(SpliceStep::Pump)
    }

    /// The core of a send completion (`Op::Send`): the slot-match, the op-count drain, the failure close, the
    /// gather-advance accounting (retiring flushed replies), the partial-send re-arm, the next-batch kick, and the
    /// flush-close finish. Returns the [`SendStep`] its role wrapper enacts -- `Pump` when the gather is fully sent and
    /// reading should resume, `Done` otherwise.
    pub(crate) fn on_send_complete(&mut self, slot: u32, generation: u32, res: i32) -> errno::Result<SendStep> {
        if !self.table.slot_matches_cqe(slot, generation) {
            return Ok(SendStep::Done);
        }
        self.table.conn_mut(slot).sending = false;
        if !self.op_done(slot)? {
            return Ok(SendStep::Done);
        }
        if res <= 0 {
            let reason = self.send_close_reason(res);
            self.close_conn(slot, generation, reason)?;
            return Ok(SendStep::Done);
        }
        stat!(self, bytes_out, res as u64);
        stat!(self, send_ops);
        // Retire the PDUs the gather flushed: replies free read-ahead slots (pushes don't participate in the cap).
        let progress = {
            let conn = self.table.conn_mut(slot);
            let progress = conn.advance_sent(res as usize);
            conn.outstanding = conn.outstanding.saturating_sub(progress.replies);
            // Bytes flushed to the peer: any idle clock armed before this completion measured a non-quiet interval
            // (`finish_failed_recv`).
            conn.served_since_idle_arm = true;
            progress
        };
        stat!(self, replies, u64::from(progress.replies));
        stat!(self, pushes, u64::from(progress.pushes));
        // Chunks that reached the peer give their ring buffers back. Only here, because only the reactor holds the
        // pool.
        #[cfg(all(feature = "net-server", feature = "uring-fs"))]
        if progress.freed > 0 {
            if let Some(pool) = self.body_bufs.as_mut() {
                for &bid in &progress.freed_bids[..progress.freed as usize] {
                    pool.release(bid);
                }
            }
            self.sync_recv_buf_stats();
        }
        if progress.armed_remaining > 0 {
            // Under WAITALL a short send happens on a mid-flight error or a > 2 GiB gather (the kernel clamps every op
            // at `MAX_RW_COUNT`, and `send_single` clamps its SQE length to match); the re-submit - re-armed from the
            // cursor - continues the tail or surfaces the error as a close.
            self.submit_send(slot, generation)?;
            return Ok(SendStep::Done);
        }
        // The gather is fully sent: start the next batch, then resume reading (read-ahead slots freed up).
        self.kick_send(slot, generation)?;
        // A pending flush-close finishes here: the pump is gated while it is set, so once the queue is dry this
        // completion is the only driver left to submit the teardown.
        let flush = {
            let conn = self.table.conn_mut(slot);
            // `tail_active`: a streaming body's queue can read dry between chunks (the next read still in flight) - the
            // flush-close waits for the tail's last chunk, or it would truncate the farewell.
            let dry = !conn.sending && !conn.has_pending_send() && !conn.tail_active();
            if conn.close_on_flush.is_some() && dry {
                conn.close_on_flush.take()
            } else if conn.peer_closed.is_some() && dry && conn.outstanding == 0 {
                // The half-closed peer's reply has reached the wire and nothing else is owed, so the connection can go.
                // The `outstanding` test is what a flush-close does not need: that one is a farewell and nothing
                // follows it, while this connection was still answering, and a pipelined request admitted before the
                // FIN may still be in a handler.
                conn.peer_closed.take()
            } else {
                None
            }
        };
        if let Some(reason) = flush {
            self.close_conn(slot, generation, reason)?;
            return Ok(SendStep::Done);
        }
        Ok(SendStep::Pump)
    }

    /// The loop-top gate of the role pump: the busy/closing/stash/flush-close checks, the `max_in_flight` cap, the
    /// draining "close when idle" branch, and the oversize-buffer close. Returns [`Gate::Stop`] (after performing any
    /// close itself) or [`Gate::Proceed`] to consult the framer. Fully core -- the framer call and delivery stay in the
    /// role wrapper.
    pub(crate) fn pump_gate(&mut self, slot: u32, generation: u32) -> errno::Result<Gate> {
        // A prior `deliver_one` this loop may have detached or closed the connection (leaving `Serving`) - stop pumping
        // if so.
        let Some(conn) = self.table.get_conn(slot) else {
            return Ok(Gate::Stop);
        };
        // Already reading, splicing a body (or awaiting its readiness poll), tearing down, or at the read-ahead cap.
        // `splicing` / `splice_polling` are distinct from `recving` but equally mean "the recv side is busy": the
        // header is still buffered until the splice completes (`consume` runs in `on_splice_recv`), so re-framing here
        // would re-emit the same `SpliceBody` and submit a second splice. A concurrent push send's completion can call
        // `pump` mid-splice - this makes it a no-op; the splice (or its poll) completion re-drives the pump.
        // A pending `recv_close_stash` counts as recv-busy too: the failed recv's close is merely parked on its clock
        // CQE (`on_recv_clock`), so nothing may re-arm the recv side.
        // A pending flush-close (`close_on_flush`) retires the recv side outright: the farewell PDU is final - buffered
        // pipelined requests are discarded, nothing is re-armed -- and `on_send` closes once the queue drains. A
        // closing reply whose file body is still queued behind another one (`has_deferred_close`) has not armed that
        // flag yet and stops the gate just the same: the handler declared the reply final when it returned it, not when
        // its body reaches the wire.
        if conn.recving
            || conn.splicing
            || conn.splice_polling
            || conn.closing
            || conn.recv_close_stash.is_some()
            || conn.close_on_flush.is_some()
            || conn.has_deferred_close()
        {
            return Ok(Gate::Stop);
        }
        if conn.outstanding as usize >= self.cfg.max_in_flight_requests {
            return Ok(Gate::Stop);
        }
        // Draining: never start reading a NEW request. Anything already buffered is still processed; once nothing is
        // left in flight, close (otherwise wait - on_send/Done completions re-pump).
        if self.draining && conn.buffered() == 0 {
            if conn.outstanding == 0 && !conn.sending && !conn.has_pending_send() {
                self.close_conn(slot, generation, CloseReason::ShuttingDown)?;
                return Ok(Gate::Stop);
            }
            return Ok(Gate::Stop);
        }
        // A peer that half-closed while work was owed (`peer_closed`). The flag is only set on an *idle* read-ahead
        // recv over an empty buffer, so nothing is pending and nothing more can arrive: the recv side is retired here,
        // the way `close_on_flush` retires it, without making a teardown own the slot (which would drop the reply that
        // is still coming).
        //
        // This is also the only place such a connection can close when its owed work ends with **nothing on the
        // wire** - a one-way `Injected::Done`, a `Redeliver` answering empty, an inline empty `Response::Reply`. Those
        // retire `outstanding` and queue no PDU, so `on_send_complete` - which owns the case where bytes flush -- never
        // runs, and the slot and the fd would be held until the server exits.
        if let Some(reason) = conn.peer_closed {
            let dry = conn.outstanding == 0 && !conn.sending && !conn.has_pending_send() && !conn.tail_active();
            if dry {
                self.table.conn_mut(slot).peer_closed = None;
                self.close_conn(slot, generation, reason)?;
            }
            return Ok(Gate::Stop);
        }
        // Unbounded-header guard: a framer that never completes can't grow the buffer past the message cap.
        if conn.buffered() > self.cfg.max_request_bytes {
            self.close_conn(slot, generation, CloseReason::TooLarge)?;
            return Ok(Gate::Stop);
        }
        Ok(Gate::Proceed)
    }

    /// Enact one framer [`Framing`] verdict on behalf of the role pump: run the pure [`frame_step`] and carry out
    /// `Close`/`ReadHeader`/`ReadBody`/
    /// `SpliceBody` (each submits-or-closes and returns [`Enacted::Done`]);
    /// `Deliver` records the split and returns [`Enacted::Deliver`] - the one outcome the role handles (running the
    /// body handler). The framer can't mutate the buffer, so `buffered` read here matches what the role passed the
    /// framer.
    pub(crate) fn enact_frame_step(&mut self, slot: u32, generation: u32, verdict: Framing) -> errno::Result<Enacted> {
        let buffered = self.table.conn(slot).buffered();
        match frame_step(
            verdict,
            buffered,
            self.cfg.max_request_bytes,
            self.cfg.body_placement_threshold,
        ) {
            FrameStep::Close(reason) => {
                self.close_conn(slot, generation, reason)?;
                Ok(Enacted::Done)
            }
            FrameStep::ReadHeader {
                want,
                exact,
                in_message,
            } => {
                self.submit_recv(slot, generation, Op::RecvHeader, want, exact, false, in_message)?;
                Ok(Enacted::Done)
            }
            FrameStep::ReadBody {
                want,
                header_len,
                body_len,
                place,
            } => {
                // Placement buys a move on delivery by directing the body into storage of its own (pool-claimed and
                // reused, but still a buffer beside the recv rings). The rings make that a bad trade twice over: a held
                // claim big enough for the body means a second buffer is pure churn, and a connection with *no* claim
                // gets one free with the read itself (the kernel picks at completion)
                // - so placing there forfeits a zero-copy buffer to
                // claim a copied one. In a streamed body the no-claim case is every window after the first in a codec
                // frame, once the previous window leased the claim to a write. `frame_step` is state-free and cannot
                // see this.
                //
                // The trade is a copy for a handler that wants to own the body (`Body::take` on a borrowed body copies,
                // where a placed one moves). Handlers that stream a body out - the reason a body is this large - take
                // nothing. Placement remains for what the pool cannot serve: a body larger than one pool buffer, and a
                // connection that fell back to owned storage.
                let total = header_len.saturating_add(body_len);
                let place = place && !self.table.conn(slot).recv_buf_covers(total);
                #[cfg(feature = "net-server")]
                let place = place
                    && !(self.table.conn(slot).recv_needs_buffer()
                        && self.recv_bufs.as_ref().is_some_and(|pool| total <= pool.buf_len()));
                #[cfg(feature = "net-server")]
                if place && self.hold_back(slot, generation)? {
                    return Ok(Enacted::Done);
                }
                self.table.conn_mut(slot).set_frame(header_len, body_len);
                self.submit_recv(
                    slot,
                    generation,
                    Op::RecvBody,
                    want,
                    true,
                    place,
                    // A body read is an active transfer whatever is buffered.
                    true,
                )?;
                Ok(Enacted::Done)
            }
            FrameStep::Deliver { header_len, body_len } => {
                // Full message buffered: record the split and hand delivery back to the role, which delivers then loops
                // to try the next pipelined request (bounded by the cap guard).
                self.table.conn_mut(slot).set_frame(header_len, body_len);
                Ok(Enacted::Deliver)
            }
            FrameStep::SpliceBody {
                header_len,
                body_len,
                fd,
            } => {
                // SECURITY: the consumer's destination fd must be BLOCKING. `do_splice` promotes the *output* fd's
                // O_NONBLOCK to `SPLICE_F_NONBLOCK` (fs/splice.c), so a full non-blocking pipe fails the splice with
                // `-EAGAIN` *before the socket is read* - indistinguishable from "socket empty", which would turn the
                // readiness poll into a hot loop (POLLIN completes instantly while the pipe stays full). A blocking
                // pipe blocks the splice on io-wq instead: the designed backpressure. One fcntl per body; a bad fd
                // (consumer closed it early) fails here too, before the kernel sees it.
                let fl = unsafe { libc::fcntl(fd, libc::F_GETFL) };
                if fl < 0 || fl & libc::O_NONBLOCK != 0 {
                    self.close_conn(slot, generation, CloseReason::SpliceBadFd)?;
                    return Ok(Enacted::Done);
                }
                // SECURITY: one destination, one body. A splice moves at most what the transport hands over in one
                // call - over kTLS, one TLS record - and `on_splice_recv_complete` resubmits the remainder as a *fresh*
                // op. Between the two, another connection's splice can take the pipe's mutex and write its own bytes,
                // so two bodies sharing a destination interleave. The head-of-line stall a shared pipe also causes is
                // the same configuration seen from the other end.
                //
                // A scan, not a set: this runs once per body (the resubmits go straight to `submit_splice_recv`), it is
                // bounded by `pool_size`, and it carries no lifecycle of its own - a set would need unwinding on every
                // teardown path, which is exactly where a leak would hide.
                if self.splice_fd_in_use(slot, fd) {
                    self.close_conn(slot, generation, CloseReason::SpliceFdInUse)?;
                    return Ok(Enacted::Done);
                }
                // SECURITY: a kTLS body splice has exactly one bound - the standalone watchdog keyed on
                // `request_timeout`, because it blocks on an io-wq worker awaiting the next record where no linked
                // timeout can reach it (see `submit_splice_recv`). Unset, a peer that handshakes, declares a large body
                // and goes silent holds its slot, an io-wq worker and this pipe's mutex for as long as it likes. Refuse
                // rather than serve it unbounded: the remedy is one configuration line (`request_timeout`, or its
                // client spelling `response_timeout` - both project onto this field), and an unbounded stall is not
                // something an operator can find. Plain TCP is unaffected - its readiness-poll path is already clocked.
                if self.table.conn(slot).is_ktls() && self.cfg.request_timeout.is_none() {
                    self.close_conn(slot, generation, CloseReason::SpliceUnbounded)?;
                    return Ok(Enacted::Done);
                }
                // Transport-agnostic: the kernel routes the splice through
                // the socket's `splice_read`. Plain sockets move raw bytes;
                // kTLS routes to `tls_sw_splice_read` (both software and NIC-offloaded RX - the ops table aliases
                // them), which decrypts, drains the recvmsg-stranded `rx_list` remainder, and moves PLAINTEXT - so a
                // framed body splices in the clear over kTLS too. A mid-stream TLS control record is fail-closed by the
                // kernel (`-EINVAL`), which `on_splice_recv` maps to `TlsControl`.
                self.table.conn_mut(slot).set_frame(header_len, body_len);
                self.submit_splice_recv(slot, generation, fd, body_len, true)?;
                Ok(Enacted::Done)
            }
        }
    }
}
