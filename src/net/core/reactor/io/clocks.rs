use super::*;

impl<U> Reactor<U> {
    /// Arm the standalone kTLS-splice inactivity watchdog, one armed `TIMEOUT` per connection, idempotent on
    /// `splice_deadline_armed`. On expiry `on_splice_deadline` re-arms if the body made progress, or cancels the
    /// stalled splice. A no-op unless `request_timeout` is set, since the watchdog is that clock for the kTLS splice.
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

    /// The kTLS-splice inactivity watchdog fired or was cancelled. It acts only on a genuine expiry (`-ETIME`) of the
    /// current watchdog on a live slot.
    ///  * A body no longer splicing stops the watchdog.
    ///  * A body whose `splice_remaining` fell below the watermark made progress, so the watchdog re-arms against the
    ///    new remaining and never cancels a healthy transfer.
    ///  * A body unchanged for a whole `request_timeout` is stalled, and its splice is cancelled by `user_data`. That
    ///    completion is classified `RequestTimeout` in `on_splice_recv`.
    pub(crate) fn on_splice_deadline(&mut self, slot: u32, generation: u32, res: i32) -> errno::Result<()> {
        // A retired watchdog still owes one completion, and its cancel is only staged until the next loop pass. Its
        // `-ETIME` can arrive after the successor was armed in the same batch, and read off the flag alone it would
        // cancel the successor's healthy splice, since `splice_watermark` equals `splice_remaining` at every arm.
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

    /// Arm the total-receipt budget for the message now arriving, one standalone `TIMEOUT` per connection, idempotent
    /// on `receipt_deadline_armed`. A no-op unless `max_receipt_time` is set.
    ///
    /// **Never cancel before arming here.** A `More` scan re-enters `submit_recv` on every chunk, so cancel-then-arm
    /// would restart the budget on every trickle (`a_chunk_scan_budget_is_not_restarted_by_progress`).
    ///
    /// Keyed `(slot, generation)`, the slot's generation and not the timer's, so the key does not tell one budget from
    /// its successor. `receipt_deadline_owed` does.
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

    /// Cancel a parked read's pool-shortage retry timer, for a connection that is closing (see `close_conn`).
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

    /// Retire the receipt budget, since the message was delivered or its connection is closing.
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

    /// Whether a read of the message being framed waits at `ServerConfig::held_cap` ([`hold_back`](Self::hold_back)).
    /// A message is let in at the cap once, before it first takes storage of the body pool, by the read of its placed
    /// body or by one that would promote what it has buffered. No later read of a message let in waits
    /// (`Connection::let_in`), since what it would wait on is its own bytes.
    #[cfg(feature = "net-server")]
    pub(super) fn read_waits(&mut self, slot: u32, generation: u32, place: bool, want: usize) -> errno::Result<bool> {
        let conn = self.table.conn(slot);
        if conn.let_in || !(place || conn.recv_outgrown_by(want)) {
            return Ok(false);
        }
        self.hold_back(slot, generation)
    }

    /// Whether a read that would take storage of the body pool waits for the ring's held bytes to fall under
    /// `ServerConfig::held_cap`. It waits while they are at or past the cap, and behind any read or turn of the
    /// consumer's already held back, so that both go on in the order they came, and the server lets each go on in turn
    /// (`held_turn`). The connection keeps what it has buffered, and its receive buffer, and claims no storage until
    /// then. The budget of its message is retired, since handling is not clocked, and `submit_recv` arms a fresh one as
    /// the read goes on, so only the peer's own time counts.
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
    /// A retired budget's completion, its cancel or an `-ETIME` that beat the cancel, is consumed against
    /// [`Connection::receipt_deadline_owed`] and not the flag, since the successor can be armed before it is reaped and
    /// the two carry identical `user_data`.
    #[cfg(feature = "net-server")]
    pub(crate) fn on_receipt_deadline(&mut self, slot: u32, generation: u32, res: i32) -> errno::Result<()> {
        // Read off the flag alone, a peer that finished just inside its budget would be closed with `ReceiptTimeout`.
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
