use super::*;

impl<U> Reactor<U> {
    /// The core of a recv completion (`RecvHeader`/`RecvBody`), returning the [`RecvStep`] its role wrapper enacts.
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
        // Flush-closing retires the recv side. Data stays undelivered, an EOF or error is moot since a half-close must
        // not beat the farewell out, and the send side owns the close once the queue drains (`on_send`).
        if self.table.conn(slot).close_on_flush.is_some() {
            return Ok(RecvStep::Done);
        }
        // Same for a peer that half-closed while a reply was owed. A FIN re-completes a re-armed recv at once, so
        // `Pump` here would spin the loop. `pump_gate` retires the recv side on this flag too, so this is a backstop,
        // and the close belongs to `pump_gate` or `on_send_complete`.
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
                // A short positive exact read never re-enters the pump, since its bytes sit unexposed past the cursor
                // and a re-pump would re-frame from before them and desync the stream. It closes, or resumes past them
                // when the request clock fired on an active plain TCP transfer (`resubmit_exact_recv`).
                //
                // A kTLS control record can end an exact read short, and a clean close_notify is `TlsControl`.
                if res > 0 && self.ktls_control_record(slot) {
                    self.close_conn(slot, generation, CloseReason::TlsControl)?;
                    return Ok(RecvStep::Done);
                }
                // Otherwise a short exact read with a linked clock is ambiguous. A cancelled `MSG_WAITALL` recv that
                // had consumed bytes completes `res = done_io > 0` (`io_sendrecv_fail`), just like a FIN mid-frame, and
                // only the clock's own CQE (`Op::RecvClock`) tells them apart. If it has not reaped, the close parks on
                // it, and both CQEs of a linked pair are queued by one task-work run, so the stash resolves this batch.
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

    /// Close out a `Failed` recv with `reason`, unless it is a parked read-ahead recv (nothing buffered) cancelled
    /// while the connection owes work, by the graceful drain or by `idle_timeout` while a `Response::Defer` is
    /// outstanding. Closing there would drop the owed reply, so those return [`RecvStep::Pump`] and re-arm.
    ///
    /// `served_since_idle_arm` counts as owing work. The idle clock runs from the recv's arm, so a fire whose interval
    /// saw a completed send measured busy time, and closing would race the client's next request. A peer cannot set the
    /// flag, since it marks server sends, so a connection idle for good still closes on its first expiry.
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
            // A peer that half-closed after its request is polite, not gone. Its `shutdown(SHUT_WR)` completes the
            // parked read-ahead with `res == 0`, and closing would make `kick_send`, `drain_injections` and
            // `on_pump_read` drop the owed reply. It cannot re-pump either, since a FIN re-completes at once, nor arm
            // `close_on_flush`, which makes a teardown own the slot. So the recv side retires and the send side closes.
            //
            // **`PeerClosed` only, and do not widen this.** A `res == 0` on a non-idle recv is `TruncatedMessage`, a
            // request that can never complete. And `served_since_idle_arm` stays out of `owes_work` here, since it is
            // about the idle measurement, not about a reply owed now.
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

    /// A splice-readiness `POLL_ADD` completed (`Op::SplicePoll`), so the socket is readable again after a body splice
    /// hit `-EAGAIN`. Resubmit the splice for the remaining bytes. A poll cancelled at teardown bails in `op_done`, and
    /// a genuine poll error closes the connection.
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

    /// The core of a body-splice completion (`Op::SpliceRecv`), returning the [`SpliceStep`] its role wrapper enacts.
    /// The body never entered the buffer, so a whole body pumps the next frame (`Pump`) and there is no `deliver_one`.
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
            // On a kTLS splice `-EINVAL` is a refused control record (`tls_sw_splice_read`), so it is `TlsControl` as
            // on the buffered path. A teardown cancel bailed in `op_done`, so a cancel here is the watchdog's
            // (`on_splice_deadline`). It surfaces as `-ECANCELED`, or as raw `-ERESTARTSYS` when the record wait was
            // interrupted, since the splice op posts `do_splice`'s return verbatim (`io_uring/splice.c`).
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
        // Whole body spliced. Retire the kTLS watchdog and the receipt budget, drop the header, and frame the next
        // message. The budget must be retired here, since this path has no `deliver_one`, and one left armed reaps the
        // connection for finishing on time and suppresses every later budget.
        self.cancel_splice_deadline(slot, generation)?;
        #[cfg(feature = "net-server")]
        self.cancel_receipt_deadline(slot, generation)?;
        self.table.conn_mut(slot).consume();
        Ok(SpliceStep::Pump)
    }

    /// The core of a send completion (`Op::Send`), returning the [`SendStep`] its role wrapper enacts, `Pump` when the
    /// gather is fully sent and reading should resume.
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
                // The half-closed peer's reply is on the wire. Unlike a flush-close this needs `outstanding == 0`,
                // since a pipelined request admitted before the FIN may still be in a handler.
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

    /// The loop-top gate of the role pump. Returns [`Gate::Stop`], after performing any close itself, or
    /// [`Gate::Proceed`] to consult the framer.
    pub(crate) fn pump_gate(&mut self, slot: u32, generation: u32) -> errno::Result<Gate> {
        // A prior `deliver_one` this loop may have detached or closed the connection (leaving `Serving`) - stop pumping
        // if so.
        let Some(conn) = self.table.get_conn(slot) else {
            return Ok(Gate::Stop);
        };
        // The recv side is busy or retired. A splice and its readiness poll count, since the header stays buffered
        // until the splice completes and re-framing would submit a second splice. A parked `recv_close_stash` counts,
        // since its close waits on the clock CQE. A flush-close retires the recv side, and so does a closing reply
        // whose body is still queued (`has_deferred_close`), since the handler declared it final when it returned it.
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
        // A peer that half-closed while work was owed. The recv side retires here as `close_on_flush` retires it, with
        // no teardown owning the slot. This is also the only place such a connection closes when its owed work ends
        // with nothing on the wire (a one-way `Injected::Done`, an empty reply), since `on_send_complete` never runs.
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

    /// Enact one framer [`Framing`] verdict for the role pump through the pure [`frame_step`]. Every step but `Deliver`
    /// is carried out here and returns [`Enacted::Done`]. `Deliver` records the split and returns [`Enacted::Deliver`]
    /// for the role to run the body handler. The framer cannot mutate the buffer, so `buffered` here is what it saw.
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
                // A pooled connection does not place a body the pool can serve. Against a held claim that covers it, a
                // second buffer is churn. With no claim the read gets a pool buffer free, and placing would trade it
                // for one `pwritev2_from` must copy, which in a streamed body is every window after the first.
                // `frame_step` is state-free and cannot see this. Placement remains for a body larger than one pool
                // buffer and for a connection that fell back to owned storage.
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
                // O_NONBLOCK to `SPLICE_F_NONBLOCK` (`fs/splice.c`), so a full pipe would fail the splice `-EAGAIN`
                // before the socket is read and turn the readiness poll into a hot loop. A blocking pipe blocks on
                // io-wq instead, which is the backpressure.
                let fl = unsafe { libc::fcntl(fd, libc::F_GETFL) };
                if fl < 0 || fl & libc::O_NONBLOCK != 0 {
                    self.close_conn(slot, generation, CloseReason::SpliceBadFd)?;
                    return Ok(Enacted::Done);
                }
                // SECURITY: one destination, one body. A splice moves at most what the transport hands over in one
                // call, over kTLS one record, and the remainder is a fresh op, so two bodies sharing a pipe interleave.
                // A scan, not a set, since a set would need unwinding on every teardown path, where a leak would hide.
                if self.splice_fd_in_use(slot, fd) {
                    self.close_conn(slot, generation, CloseReason::SpliceFdInUse)?;
                    return Ok(Enacted::Done);
                }
                // SECURITY: a kTLS body splice has exactly one bound - the standalone watchdog keyed on
                // `request_timeout` (see `submit_splice_recv`). Unset, a silent peer holds its slot, an io-wq worker
                // and the pipe's mutex for good, so refuse rather than serve it unbounded. Plain TCP's poll is clocked.
                if self.table.conn(slot).is_ktls() && self.cfg.request_timeout.is_none() {
                    self.close_conn(slot, generation, CloseReason::SpliceUnbounded)?;
                    return Ok(Enacted::Done);
                }
                // The kernel routes the splice through the socket's `splice_read`. For kTLS that is
                // `tls_sw_splice_read`, which drains what recvmsg left in `rx_list` and moves plaintext. A mid-stream
                // control record fails closed (`-EINVAL`), which `on_splice_recv` maps to `TlsControl`.
                self.table.conn_mut(slot).set_frame(header_len, body_len);
                self.submit_splice_recv(slot, generation, fd, body_len, true)?;
                Ok(Enacted::Done)
            }
        }
    }
}
