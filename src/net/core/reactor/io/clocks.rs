use super::*;

impl<U> Reactor<U> {
    /// Arm the standalone kTLS-splice inactivity watchdog: a single `TIMEOUT` per connection (the
    /// `splice_deadline_armed` flag makes it idempotent -- at most one is ever in flight, which is what keeps a stale
    /// expiry from ever aliasing a later body's splice). On expiry `on_splice_deadline` re-arms if the body made
    /// progress, or cancels the stalled splice. Keyed `(slot, generation)` so a recycled slot's expiry is inert. No-op
    /// unless `request_timeout` is set (the watchdog is that clock for the kTLS splice, which no linked timeout can
    /// reach).
    pub(super) fn arm_splice_deadline(&mut self, slot: u32, generation: u32) -> errno::Result<()> {
        if self.cfg.request_timeout.is_none() {
            return Ok(());
        }
        {
            let conn = self.table.conn_mut(slot);
            if conn.splice_deadline_armed {
                return Ok(()); // one watchdog per connection - never a second
            }
            conn.splice_deadline_armed = true;
            // Watermark the remaining bytes: the next expiry compares against this to tell "made progress, re-arm" from
            // "stalled, cancel".
            conn.splice_watermark = conn.splice_remaining;
        }
        let ts = std::ptr::addr_of!(self.pads.request_timeout) as u64;
        self.stage(pack(Op::SpliceDeadline, slot, generation), move |sqe| {
            sqe.opcode = IORING_OP_TIMEOUT;
            sqe.addr = ts;
            sqe.len = 1; // exactly one timespec, per the kernel
        })
    }

    /// Cancel the kTLS-splice watchdog once its body finishes (or its connection closes): clears the flag, counts the
    /// completion the timer still owes ([`Connection::splice_deadline_owed`]) and issues an `ASYNC_CANCEL` for the
    /// in-flight `TIMEOUT`. Either ending - the cancel's `-ECANCELED` or an expiry that beat it - is consumed against
    /// that count, because the successor watchdog is armed one dispatch later under identical `user_data`.
    pub(crate) fn cancel_splice_deadline(&mut self, slot: u32, generation: u32) -> errno::Result<()> {
        let armed = match self.table.get_conn_mut(slot) {
            Some(conn) if conn.splice_deadline_armed => {
                conn.splice_deadline_armed = false;
                // Owed whether or not the cancel below stages, and whether or not it wins: the timer is in flight, so a
                // completion is coming either way.
                conn.splice_deadline_owed += 1;
                true
            }
            _ => false,
        };
        if !armed {
            return Ok(());
        }
        let target = pack(Op::SpliceDeadline, slot, generation);
        self.stage(pack(Op::Cancel, 0, 0), move |sqe| {
            sqe.opcode = IORING_OP_ASYNC_CANCEL;
            sqe.fd = -1;
            sqe.addr = target;
        })
    }

    /// The kTLS-splice inactivity watchdog fired or was cancelled. Acts ONLY on a genuine expiry (`-ETIME`) of the
    /// CURRENT watchdog on a live slot:
    ///  * not `-ETIME` -> a cancel completion (body done / close) - ignore;
    ///  * slot recycled / not serving / disarmed -> stale - ignore;
    ///  * body no longer actively splicing (finished, or the brief gap
    ///    between records) -> self-stop;
    ///  * `splice_remaining` fell below the watermark -> progress -> re-arm against the new remaining (never cancels a
    ///    healthy transfer, even
    ///    if the expiry raced a record landing);
    ///  * remaining unchanged for a whole `request_timeout` -> stalled -> cancel the blocked splice by `user_data`; its
    ///    `-ECANCELED`/interrupted completion is classified `RequestTimeout` in `on_splice_recv`.
    pub(crate) fn on_splice_deadline(&mut self, slot: u32, generation: u32, res: i32) -> errno::Result<()> {
        // A retired watchdog still owes one completion, and the retire only staged its cancel - `run_loop` submits at
        // the top of the next iteration, after this reap loop drains. So the old timer's `-ETIME` can already be posted
        // when its body finishes "just inside" the period, while the successor is armed one dispatch later inside the
        // same batch (`on_splice_recv_complete` -> pump -> `submit_splice_recv`). Read off the flag alone that expiry
        // takes the live path and reaches `Next::Cancel` - `splice_watermark` equals `splice_remaining` at every arm -
        // so it cancels the *successor's* splice, which completes `-ECANCELED` and is classified `RequestTimeout`: a
        // healthy transfer killed at its first record, with the watchdog now disarmed.
        if let Some(conn) = self.table.conn_at_cqe_mut(slot, generation)
            && conn.splice_deadline_owed > 0
        {
            conn.splice_deadline_owed -= 1;
            return Ok(());
        }
        if res != -libc::ETIME {
            return Ok(()); // a cancel completion - not a real expiry
        }
        if !self.table.slot_matches_cqe(slot, generation) {
            // Left set, this flag disables the watchdog permanently, and it is the only clock that reaches a kTLS body
            // splice. See `conn_at_cqe_mut`.
            if let Some(conn) = self.table.conn_at_cqe_mut(slot, generation) {
                conn.splice_deadline_armed = false;
            }
            return Ok(()); // slot recycled / gone
        }
        enum Next {
            Stop,
            ReArm,
            Cancel,
        }
        let next = {
            let conn = self.table.conn_mut(slot);
            if !conn.splice_deadline_armed {
                return Ok(()); // superseded / already cancelled
            }
            // The flag tracked one in-flight timer; it just completed.
            conn.splice_deadline_armed = false;
            if !conn.splicing && !conn.splice_polling {
                Next::Stop
            } else if conn.splice_remaining < conn.splice_watermark {
                Next::ReArm
            } else {
                Next::Cancel
            }
        };
        match next {
            Next::Stop => Ok(()),
            Next::ReArm => self.arm_splice_deadline(slot, generation),
            Next::Cancel => self.submit_cancel_splice(slot, generation),
        }
    }

    /// Arm the total-receipt budget for the message now arriving: a single standalone `TIMEOUT` per connection,
    /// idempotent on `receipt_deadline_armed`.
    ///
    /// **Never cancel before arming here.** A `More`/delimiter scan re-enters `submit_recv` on every chunk, so a
    /// cancel-then-arm rides the trickle and reproduces `request_timeout` under a second name
    /// (`a_chunk_scan_budget_is_not_restarted_by_progress`). The early return below is dedup only - one timer in flight
    /// rather than one per chunk read; a stacked timer would not break the bound, since `on_receipt_deadline` charges
    /// an expiry it did not arm to the retired count instead.
    ///
    /// Keyed `(slot, generation)`, so a recycled slot's expiry is inert.
    /// That is the slot's generation, not the timer's, so it does **not** tell one budget from its successor -
    /// `receipt_deadline_owed` is what does.
    /// No-op unless `max_receipt_time` is set.
    #[cfg(feature = "net-server")]
    pub(super) fn arm_receipt_deadline(&mut self, slot: u32, generation: u32) -> errno::Result<()> {
        if self.cfg.max_receipt_time.is_none() {
            return Ok(());
        }
        {
            let conn = self.table.conn_mut(slot);
            if conn.receipt_deadline_armed {
                return Ok(()); // one timer per message, not per read
            }
            conn.receipt_deadline_armed = true;
        }
        let ts = std::ptr::addr_of!(self.pads.max_receipt_time) as u64;
        self.stage(pack(Op::ReceiptDeadline, slot, generation), move |sqe| {
            sqe.opcode = IORING_OP_TIMEOUT;
            sqe.addr = ts;
            sqe.len = 1; // exactly one timespec, per the kernel
        })
    }

    /// Cancel a parked read's pool-shortage retry timer, for a connection that is closing.
    ///
    /// The same reason the other two standalone timers are cancelled there: it is not an `ops`-counted op, so nothing
    /// else reaps it, and an uncancelled one keeps `inflight` up until it expires - delaying an otherwise idle
    /// `serve_forever`'s exit. It is also the only one armed by default (`recv_shortage_retry`), so it is the one most
    /// likely to be pending at a close.
    #[cfg(feature = "net-server")]
    pub(crate) fn cancel_recv_retry(&mut self, slot: u32, generation: u32) -> errno::Result<()> {
        let armed = match self.table.get_conn_mut(slot) {
            Some(conn) if conn.recv_retry_armed => {
                conn.recv_retry_armed = false;
                true
            }
            _ => false,
        };
        if !armed {
            return Ok(());
        }
        let target = pack(Op::RecvRetry, slot, generation);
        self.stage(pack(Op::Cancel, 0, 0), move |sqe| {
            sqe.opcode = IORING_OP_ASYNC_CANCEL;
            sqe.fd = -1;
            sqe.addr = target;
        })
    }

    /// Retire the receipt budget: the message was delivered, or its connection is closing. Clears the flag and cancels
    /// the in-flight `TIMEOUT`; the cancelled timer completes `-ECANCELED`, which `on_receipt_deadline` ignores.
    ///
    /// Called at **delivery**, which is what keeps this a bound on receipt and not on handling: a request offloaded to
    /// a worker has already had its clock retired by the time the handler runs.
    #[cfg(feature = "net-server")]
    pub(crate) fn cancel_receipt_deadline(&mut self, slot: u32, generation: u32) -> errno::Result<()> {
        let armed = match self.table.get_conn_mut(slot) {
            Some(conn) if conn.receipt_deadline_armed => {
                conn.receipt_deadline_armed = false;
                // See `splice_deadline_owed`: the completion is owed whatever the cancel below does.
                conn.receipt_deadline_owed += 1;
                true
            }
            _ => false,
        };
        if !armed {
            return Ok(());
        }
        let target = pack(Op::ReceiptDeadline, slot, generation);
        self.stage(pack(Op::Cancel, 0, 0), move |sqe| {
            sqe.opcode = IORING_OP_ASYNC_CANCEL;
            sqe.addr = target;
        })
    }

    /// Whether the read of a placed body waits for the ring's held bytes to fall under `ServerConfig::held_cap`. It
    /// waits while they are at or past the cap, and behind any read or turn of the consumer's already held back, so
    /// that both go on in the order they came, and the server lets each go on in turn (`held_turn`). The connection
    /// keeps its header and frame and claims no storage until then. The budget of its message is retired, since
    /// handling is not clocked, and `submit_recv` arms a fresh one as the read goes on, so only the peer's own time
    /// counts.
    #[cfg(feature = "net-server")]
    pub(super) fn hold_back(&mut self, slot: u32, generation: u32) -> errno::Result<bool> {
        if self.held_turn == Some(slot) {
            self.held_turn = None;
            return Ok(false);
        }
        if !self.table.conn(slot).read_held {
            let Some(pool) = self.body_pool.as_ref() else {
                return Ok(false);
            };
            let mut pool = pool.borrow_mut();
            if pool.may_go() {
                return Ok(false);
            }
            let read = crate::net::core::bodypool::HeldBack::Read {
                slot,
                generation: self.table.generation(slot),
            };
            pool.hold_back(read);
            drop(pool);
            self.table.conn_mut(slot).read_held = true;
        }
        self.cancel_receipt_deadline(slot, generation)?;
        Ok(true)
    }

    /// The receipt budget elapsed (`Op::ReceiptDeadline`). The message that armed it is still arriving, so the peer is
    /// under the floor the deployment set: close and reclaim the slot.
    ///
    /// A `-ECANCELED` is the retire path's own cancel and means the message landed in time. A stale `-ETIME` - the
    /// timer expiring after its cancel was staged - is consumed against [`Connection::receipt_deadline_owed`], not
    /// against the flag: the successor can be armed before the stale expiry is reaped, and the two carry identical
    /// `user_data`.
    #[cfg(feature = "net-server")]
    pub(crate) fn on_receipt_deadline(&mut self, slot: u32, generation: u32, res: i32) -> errno::Result<()> {
        // The retired budget's own completion - see `Connection::receipt_deadline_owed`. `deliver_one` retires and
        // `pump -> submit_recv -> arm_receipt_deadline` re-arms inside one dispatch, and the retire is where the old
        // deadline sits, so a peer that finished just inside its budget posts an `-ETIME` that the successor's flag
        // would answer with `ReceiptTimeout` on a connection that did nothing wrong.
        if let Some(conn) = self.table.conn_at_cqe_mut(slot, generation)
            && conn.receipt_deadline_owed > 0
        {
            conn.receipt_deadline_owed -= 1;
            return Ok(());
        }
        if res != -libc::ETIME {
            return Ok(()); // a cancel completion - not a real expiry
        }
        if !self.table.slot_matches_cqe(slot, generation) {
            // Left set, this flag suppresses the budget for every later message on the connection. See
            // `conn_at_cqe_mut`.
            if let Some(conn) = self.table.conn_at_cqe_mut(slot, generation) {
                conn.receipt_deadline_armed = false;
            }
            return Ok(());
        }
        let earned_another = {
            let conn = self.table.conn_mut(slot);
            if !conn.receipt_deadline_armed {
                return Ok(()); // delivered already; this expiry lost the race
            }
            conn.receipt_deadline_armed = false;
            // A spliced body is one message however large: renew its budget per whole window moved
            // (`ServerConfig::receipt_window_bytes`). A buffered message has no mark set and falls through to the
            // close.
            let moved = conn.receipt_window_mark.saturating_sub(conn.splice_remaining);
            let splicing = conn.splicing || conn.splice_polling;
            if splicing && moved >= self.cfg.receipt_window_bytes {
                conn.receipt_window_mark = conn.splice_remaining;
                true
            } else {
                false
            }
        };
        if earned_another {
            return self.arm_receipt_deadline(slot, generation);
        }
        self.close_conn(slot, generation, CloseReason::ReceiptTimeout)
    }
}
