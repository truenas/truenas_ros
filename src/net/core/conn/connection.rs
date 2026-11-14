use super::*;

impl<U> Connection<U> {
    /// Whether a teardown already owns this connection's remaining completions, either the flushing kind
    /// (`close_on_flush`, the farewell is final) or the immediate kind (`closing`, a SHUTDOWN or CLOSE is staged).
    ///
    /// A late arrival for such a connection (a worker outcome, a redelivery, a stashed recv) must be dropped, since the
    /// teardown path frees the slot and re-entering the connection can walk it into a state that path does not account
    /// for. Not used at every site that tests one of the flags. Some check only `close_on_flush` because the immediate
    /// case cannot reach them, and swapping this in there would change behaviour.
    pub(crate) fn teardown_owns_slot(&self) -> bool {
        self.closing || self.close_on_flush.is_some()
    }

    /// Allocate a connection with per-connection state `state` and a send gather of up to `max_send_coalesce` PDUs.
    /// Returned boxed so its interior addresses never move.
    pub(crate) fn new(peer: ClientAddr, state: U, max_send_coalesce: usize) -> Box<Connection<U>> {
        Box::new(Connection {
            peer,
            state,
            recv_buf: RecvBuf::default(),
            header_len: 0,
            body_len: 0,
            recv_at: 0,
            recv_want: 0,
            recv_exact: true,
            transport: Transport::Plain,
            body_buf: None,
            #[cfg(feature = "net-server")]
            body_ticket: Ticket::default(),
            recv_into_body: false,
            splicing: false,
            splice_polling: false,
            splice_fd: -1,
            splice_remaining: 0,
            splice_deadline_armed: false,
            splice_deadline_owed: 0,
            splice_watermark: 0,
            receipt_window_mark: 0,
            send_queue: VecDeque::new(),
            queued_bytes: 0,
            #[cfg(feature = "net-server")]
            body_pool: None,
            front_sent: 0,
            armed_bytes: 0,
            // SAFETY: iovec/msghdr are plain data; zeroed is a valid initial value and both are re-pointed by
            // `arm_send` before kernel use.
            send_iovs: vec![unsafe { std::mem::zeroed() }; max_send_coalesce].into_boxed_slice(),
            send_msg: unsafe { std::mem::zeroed() },
            recving: false,
            recv_idle: false,
            served_since_idle_arm: false,
            recv_clock_armed: false,
            recv_clock_fired: None,
            recv_close_stash: None,
            recv_retry_armed: false,
            #[cfg(feature = "net-server")]
            receipt_deadline_armed: false,
            #[cfg(feature = "net-server")]
            receipt_deadline_owed: 0,
            #[cfg(feature = "net-server")]
            read_held: false,
            evict_on_resume: false,
            close_on_flush: None,
            peer_closed: None,
            #[cfg(feature = "net-client")]
            close_reason: None,
            sending: false,
            closing: false,
            teardown_deferred: false,
            teardown_shutdown_first: false,
            #[cfg(all(feature = "net-server", feature = "uring-fs"))]
            file_tail: None,
            #[cfg(all(feature = "net-server", feature = "uring-fs"))]
            next_file: None,
            #[cfg(all(feature = "net-server", feature = "uring-fs"))]
            next_file_pending: Vec::new(),
            #[cfg(all(feature = "net-server", feature = "uring-fs"))]
            chunk_out: 0,
            #[cfg(all(feature = "net-server", feature = "uring-fs"))]
            #[cfg(all(feature = "net-server", feature = "uring-fs"))]
            deferred_close: false,
            outstanding: 0,
            ops: 0,
            next_req_id: 0,
            open_req_ids: Vec::new(),
        })
    }

    /// Switch this connection to the kernel-TLS receive transport (called once, when a handshake completes, before the
    /// first recv is armed).
    pub(crate) fn install_ktls(&mut self) {
        self.transport = Transport::Ktls(KtlsRecv::new());
    }

    /// Whether this connection receives over kernel TLS.
    pub(crate) fn is_ktls(&self) -> bool {
        matches!(self.transport, Transport::Ktls(_))
    }

    /// For a kTLS connection, point its `RECVMSG` `msghdr` at the destination `recv_ptr` just computed (with `want`
    /// bytes) and return the stable `msghdr` address for the SQE. Panics if called on a plain connection.
    pub(crate) fn arm_ktls_recv(&mut self, base: u64, want: usize) -> u64 {
        match &mut self.transport {
            Transport::Ktls(k) => {
                k.arm(base, want);
                k.msg_ptr()
            }
            Transport::Plain => unreachable!("arm_ktls_recv on a plain conn"),
        }
    }

    /// After a kTLS recv completes, the record's TLS content type (from the control message). `Some(23)` is
    /// `application_data`; any other value -- or `None` (truncated / absent cmsg) - is a control record the server
    /// closes on. Meaningless (and unused) for a plain connection.
    pub(crate) fn ktls_record_type(&self) -> Option<u8> {
        match &self.transport {
            Transport::Ktls(k) => k.record_type(),
            Transport::Plain => None,
        }
    }

    /// Assign the next request id (delivery order). `u64` so a `Deferred` retained across 2^32 requests on one
    /// connection can never collide with a live open request; it never rides `user_data`, so the width is free.
    pub(crate) fn begin_request(&mut self) -> u64 {
        let req_id = self.next_req_id;
        self.next_req_id = self.next_req_id.wrapping_add(1);
        req_id
    }

    /// Record `req_id` as deferred: awaiting exactly one worker outcome.
    pub(crate) fn open_deferred(&mut self, req_id: u64) {
        self.open_req_ids.push(req_id);
    }

    /// Claim the deferred request `req_id`: `true` exactly once per opened id, `false` for a stale/duplicate outcome
    /// (never opened, or already claimed).
    pub(crate) fn take_deferred(&mut self, req_id: u64) -> bool {
        match self.open_req_ids.iter().position(|&r| r == req_id) {
            Some(i) => {
                self.open_req_ids.swap_remove(i);
                true
            }
            None => false,
        }
    }

    /// Total bytes accumulated so far (what the header framer sees) and the per-connection state, borrow-split for the
    /// framer call.
    pub(crate) fn frame_parts(&mut self) -> (&[u8], &mut U) {
        (&self.recv_buf, &mut self.state)
    }

    /// The current message's header bytes and body length for a body being spliced (`Framing::SpliceBody`). The client
    /// snapshots it as the splice is armed, so its `Event::Splice` carries the header that `consume` later drops.
    #[cfg(feature = "net-client")]
    pub(crate) fn splice_frame_parts(&self) -> (&[u8], usize) {
        (&self.recv_buf[..self.header_len], self.body_len)
    }

    /// `(header, body, peer, state, ticket)` for a complete message, borrow-split for the body handler call. The ticket
    /// is the placed body's (default otherwise), for the delivery to pot before the handler runs. A placed body is
    /// moved out of `body_buf` and an inline body borrows `buf`, except a **body-only** message (`header_len == 0`)
    /// whose extent is exactly the buffered bytes. At or over `handoff_threshold` its accumulate buffer itself is
    /// handed over, so the handler's [`Body::take`] is as free as a placed body's.
    // Dead only in a server-with-fs build that carries no client: the server's delivery takes the leased twin below and
    // the client is the remaining caller.
    #[cfg_attr(
        all(feature = "net-server", feature = "uring-fs", not(feature = "net-client")),
        allow(dead_code)
    )]
    pub(crate) fn deliver_parts(
        &mut self,
        handoff_threshold: Option<usize>,
    ) -> (&[u8], Body<'_>, &ClientAddr, &mut U, Ticket) {
        let placed = self.take_placed_body();
        if placed.is_none()
            && let Some((buf, ticket)) = self.take_body_handoff(handoff_threshold)
        {
            return (&[], Body::placed(buf), &self.peer, &mut self.state, ticket);
        }
        let (header, rest) = self.recv_buf.deliver_mut(self.header_len, self.body_len);
        let (body, ticket) = match placed {
            Some((bytes, ticket)) => (Body::placed(bytes), ticket),
            None => (Body::inline_mut(rest), Ticket::default()),
        };
        (header, body, &self.peer, &mut self.state, ticket)
    }

    /// As [`deliver_parts`](Self::deliver_parts), plus the recv claim as a write lease - the server's delivery form,
    /// where a handler's `pwritev2_from` may write the body straight from the buffer. A twin rather than one method
    /// because the lease shares `recv_buf` with the body borrow, which the other callers' tuple shape has no room for.
    #[cfg(all(feature = "net-server", feature = "uring-fs"))]
    pub(crate) fn deliver_parts_leased(
        &mut self,
        handoff_threshold: Option<usize>,
    ) -> (
        &[u8],
        Body<'_>,
        &ClientAddr,
        &mut U,
        Option<crate::uring_fs::core::RecvWriteLease<'_>>,
        Ticket,
    ) {
        let placed = self.take_placed_body();
        if placed.is_none()
            && let Some((buf, ticket)) = self.take_body_handoff(handoff_threshold)
        {
            return (&[], Body::placed(buf), &self.peer, &mut self.state, None, ticket);
        }
        let (header, rest, lease) = self.recv_buf.deliver_leased_mut(self.header_len, self.body_len);
        let (body, ticket) = match placed {
            Some((bytes, ticket)) => (Body::placed(bytes), ticket),
            None => (Body::inline_mut(rest), Ticket::default()),
        };
        (header, body, &self.peer, &mut self.state, lease, ticket)
    }

    /// The placed body, if it is this delivery's to hand over.
    ///
    /// `body_buf` is the destination of an in-flight `RECV` while `recv_into_body` is set (`recv_ptr`), so moving it
    /// out would give the handler a Vec the kernel is still writing into. A wire delivery never meets that, since
    /// `finish_body_recv` clears the flag. A redelivery can, when the pump has already armed the next message's body,
    /// and gets an empty body to match its zeroed frame.
    fn take_placed_body(&mut self) -> Option<(Vec<u8>, Ticket)> {
        if self.recv_into_body {
            return None;
        }
        let body = self.body_buf.take()?;
        // The body leaves custody with the handler; its held licence rides out beside it, for the delivery to pot
        // **before** the handler runs. A recycle inside the handler must find the licence spendable - potted
        // afterwards, the pool freed exactly the storage the recycle seam exists to keep.
        #[cfg(feature = "net-server")]
        let ticket = std::mem::take(&mut self.body_ticket);
        #[cfg(not(feature = "net-server"))]
        let ticket = Ticket::default();
        Some((body, ticket))
    }

    /// Teardown's take of everything the ring's body pool can reuse: the placed body's storage and the promoted/owned
    /// accumulate storage, each with the held licence its claim recorded. The connection is going away, so the bytes
    /// have no reader left and the pool clears before reissue.
    #[cfg(feature = "net-server")]
    pub(crate) fn forfeit_body_storage(&mut self) -> (Option<HeldStorage>, Option<HeldStorage>) {
        let placed = self.body_buf.take().map(|v| (v, std::mem::take(&mut self.body_ticket)));
        (placed, self.recv_buf.forfeit_owned())
    }

    /// The owned-buffer handoff predicate shared by both delivery forms.
    ///
    /// `body_len > 0` keeps a redelivery's zero-length frame out, since with a zero threshold it would take the
    /// accumulate buffer while a read-ahead recv may be writing into its spare capacity.
    fn take_body_handoff(&mut self, handoff_threshold: Option<usize>) -> Option<(Vec<u8>, Ticket)> {
        if self.header_len == 0
            && self.body_len > 0
            && self.recv_buf.len() == self.body_len
            && matches!(handoff_threshold, Some(t) if self.body_len >= t)
        {
            return self.recv_buf.take_owned();
        }
        None
    }

    /// `(peer, state)` borrow-split for the close hook.
    pub(crate) fn close_parts(&mut self) -> (&ClientAddr, &mut U) {
        (&self.peer, &mut self.state)
    }

    /// The current message's header/body split, for a caller that must put it back - a redelivery, whose own frame is
    /// empty, delivering while a read-ahead recv already carries the next message's extent.
    pub(crate) fn frame(&self) -> (usize, usize) {
        (self.header_len, self.body_len)
    }

    /// Record the current message's header/body split (from a `Complete` verdict).
    pub(crate) fn set_frame(&mut self, header_len: usize, body_len: usize) {
        self.header_len = header_len;
        self.body_len = body_len;
    }

    /// Bytes of the current message (header + body). `frame_step` proves the sum fits `max_request_bytes` before any
    /// `set_frame`, so the saturation is a guard that never fires.
    pub(crate) fn frame_len(&self) -> usize {
        self.header_len.saturating_add(self.body_len)
    }

    /// Whether an armed recv must acquire a pool buffer.
    pub(crate) fn recv_needs_buffer(&self) -> bool {
        self.recv_buf.needs_buffer()
    }

    /// Adopt the buffer a completion selected.
    pub(crate) fn install_recv_buf(&mut self, claim: RecvClaim) {
        self.recv_buf.install(claim);
    }

    /// Hand the recv buffer back once nothing is buffered, so the next read acquires afresh and an idle connection
    /// holds none.
    ///
    /// **Refused while a recv is in flight.** [`recv_ptr`](Connection::recv_ptr) handed the kernel a pointer into this
    /// storage, and a released claim is reposted for another connection's read, or freed by a shrinking pool, while
    /// this recv still writes into it. [`RecvBuf::release`]'s `filled > 0` is not that check, since both partial paths
    /// advance `recv_at` and leave `filled` alone, and a spliced body consumes its header without releasing the claim.
    ///
    /// A wire delivery cannot reach this with `recving` set, since `on_recv_complete` clears it first. The redelivery
    /// route from `drain_injections` can, and the buffer is not stranded, since the completing recv re-enters the pump
    /// and the next delivery releases it.
    pub(crate) fn release_recv_buf(&mut self) -> (Option<RecvClaim>, Option<(Vec<u8>, Ticket)>) {
        if self.recving {
            return (None, None);
        }
        self.recv_buf.release()
    }

    /// Draw recv buffers from a pool rather than owning them.
    pub(crate) fn set_recv_pooled(&mut self) {
        self.recv_buf.set_pooled();
    }

    /// Whether the pool buffer this connection holds already covers a message of `total` bytes, so it needs no
    /// allocation of its own.
    pub(crate) fn recv_buf_covers(&self, total: usize) -> bool {
        self.recv_buf.covers(total)
    }

    /// Move accumulation off a pool buffer too small for the next read.
    pub(crate) fn promote_recv_buf(
        &mut self,
        at: usize,
        want: usize,
        seed: impl FnOnce() -> Option<(Vec<u8>, Ticket)>,
    ) -> Option<RecvClaim> {
        self.recv_buf.promote_for(at, want, seed)
    }

    /// Surrender the pool buffer unconditionally, for teardown.
    pub(crate) fn forfeit_recv_buf(&mut self) -> Option<RecvClaim> {
        self.recv_buf.forfeit()
    }

    /// Give up on the pool and own the recv buffer instead.
    pub(crate) fn set_recv_owned(&mut self) {
        self.recv_buf.set_owned();
    }

    /// The bytes the receive storage has on the body pool's count ([`RecvBuf::held_bytes`]).
    #[cfg(feature = "net-server")]
    pub(crate) fn recv_held_bytes(&self) -> usize {
        self.recv_buf.held_bytes()
    }

    /// Bytes already accumulated in `buf`.
    pub(crate) fn buffered(&self) -> usize {
        self.recv_buf.len()
    }

    /// Drop the delivered message from the front of `buf`, keeping any pipelined remainder for the next message. A
    /// placed body never entered `buf` (only its header did), so at most `buf.len()` bytes are drained.
    pub(crate) fn consume(&mut self) {
        let drained = self.frame_len().min(self.recv_buf.len());
        self.recv_buf.drain_front(drained);
        self.header_len = 0;
        self.body_len = 0;
    }

    // ---- recv side ----

    /// Reserve `want` bytes past what is buffered as the next recv's destination. `exact` selects an `MSG_WAITALL` read
    /// or a chunk read. Returns the length armed, which is `want` except against a pool buffer with less room
    /// (`RecvBuf::reserve_at`). Only the completion's count extends what is buffered (`recv_result`).
    pub(crate) fn arm_recv(&mut self, want: usize, exact: bool) -> usize {
        self.recv_at = self.recv_buf.len();
        let want = self.recv_buf.reserve_at(self.recv_at, want);
        self.recv_want = want;
        self.recv_exact = exact;
        self.recv_into_body = false;
        want
    }

    /// Arm a recv for the current message's body into its **own** allocation (placement). Any body prefix already
    /// accumulated past the header is copied over (`More`-style framers can over-read; at most one chunk), `buf` is
    /// truncated back to the header, and the remainder is read directly into the new buffer's spare capacity as an
    /// exact `MSG_WAITALL` recv. Returns the byte count to read.
    ///
    /// Caller guarantees the header is fully buffered and the body is not (`header_len <= buf.len() < header_len +
    /// body_len`).
    pub(crate) fn arm_body_recv(&mut self, reuse: Option<(Vec<u8>, Ticket)>) -> usize {
        let prefix = self.recv_buf.len() - self.header_len;
        // Reused storage from the ring's body pool where one waits; the pool cleared it before reissue, so only
        // capacity carries over. The licence beside it is a missed claim's held share (`BodyPool::claim_held`), parked
        // on the connection until the body leaves custody so a receipt spanning maintenance ticks keeps it.
        #[cfg_attr(not(feature = "net-server"), allow(unused_variables))]
        let (mut body, ticket) = reuse.unwrap_or_default();
        #[cfg(feature = "net-server")]
        {
            self.body_ticket = ticket;
        }
        debug_assert!(body.is_empty(), "a reused body kept bytes");
        // Exact, since a pooled `Vec` grown amortized ends at twice its old capacity, and the spare is never written
        // but charged in full to the byte budget.
        body.reserve_exact(self.body_len);
        body.extend_from_slice(&self.recv_buf[self.header_len..]);
        self.recv_buf.truncate(self.header_len);
        self.recv_at = prefix;
        self.recv_want = self.body_len - prefix;
        self.recv_exact = true;
        self.recv_into_body = true;
        self.body_buf = Some(body);
        self.recv_want
    }

    /// Kernel-visible destination of the armed recv (for the SQE `addr` field). Stable until the CQE: neither `buf` nor
    /// `body_buf` is touched while `recving`.
    pub(crate) fn recv_ptr(&mut self) -> u64 {
        match &mut self.body_buf {
            Some(body) if self.recv_into_body => {
                // Points into the Vec's spare capacity ([prefix, body_len)); the kernel initializes it and
                // `finish_body_recv` sets the length.
                // SAFETY: `recv_at <= body_len <= capacity`, so the offset stays within the allocation.
                unsafe { body.as_mut_ptr().add(self.recv_at) as u64 }
            }
            // SAFETY: `arm_recv` reserved through `recv_at + recv_want`, and the kTLS continuation re-arms the same
            // range advanced by what completed (`recv_armed_within` asserts it), so the offset stays within the
            // allocation.
            _ => self.recv_buf.write_ptr(self.recv_at) as u64,
        }
    }

    /// Process a recv result. An exact read completes only at the requested count, and a chunk read with any `res > 0`.
    ///
    /// A kTLS exact read can also complete short and healthy. io_uring cannot `MSG_WAITALL`-accumulate a `RECVMSG` that
    /// carries a control buffer (`io_recvmsg` sets `min_ret` only when `msg_controllen == 0`, io_uring/net.c), so a
    /// short, positive `application_data` read advances the cursor and returns [`RecvOutcome::Again`] for the caller to
    /// re-arm. A short plain-TCP exact read still means EOF mid-frame.
    pub(crate) fn recv_result(&mut self, res: i32) -> RecvOutcome {
        if self.recv_exact {
            if res == self.recv_want as i32 {
                if self.recv_into_body {
                    self.finish_body_recv();
                } else {
                    // The exact completion - with any earlier kTLS partials that advanced `recv_at` - proves the kernel
                    // wrote the armed region up to this end.
                    self.recv_buf.set_filled(self.recv_at + self.recv_want);
                }
                return RecvOutcome::Complete;
            }
            if res > 0
                && (res as usize) < self.recv_want
                && self.is_ktls()
                && self.ktls_record_type() == Some(crate::uring::sys::TLS_RECORD_TYPE_DATA)
            {
                // The buffer length is NOT advanced here: the partial bytes sit in spare capacity until the
                // continuation completes (a Failed continuation then never exposes them).
                self.recv_at += res as usize;
                self.recv_want -= res as usize;
                return RecvOutcome::Again;
            }
            RecvOutcome::Failed
        } else if res > 0 {
            // SAFETY: the kernel wrote `res` bytes at the cursor (chunk reads never target `body_buf`), all within the
            // reserved region.
            self.recv_buf.set_filled(self.recv_at + res as usize);
            RecvOutcome::Complete
        } else {
            RecvOutcome::Failed
        }
    }

    /// Bytes the armed (or continuing) recv still wants.
    pub(crate) fn recv_want(&self) -> usize {
        self.recv_want
    }

    /// Record partial progress on an exact read the request clock cut short, so the continuation resumes where the
    /// kernel stopped - the same bookkeeping a kTLS partial does in `recv_result`. The buffer length is NOT advanced:
    /// the bytes sit in spare capacity until the continuation completes, exactly as a kTLS continuation leaves them.
    pub(crate) fn advance_exact_partial(&mut self, n: usize) {
        debug_assert!(n <= self.recv_want, "progress past the armed want");
        let n = n.min(self.recv_want);
        self.recv_at += n;
        self.recv_want -= n;
    }

    /// Whether the armed range `[recv_at, recv_at + recv_want)` stays inside the buffer behind it. A guard for the kTLS
    /// continuation, which re-arms off the advanced cursor without a fresh reserve.
    pub(crate) fn recv_armed_within(&self) -> bool {
        // The same two arms as `recv_ptr`, since this bounds the allocation that call names. A placed body is bounded
        // by `body_len`, not `body.capacity()`, since a pooled buffer carries whatever capacity its largest tenant left
        // and the bytes past `body_len` are a previous message's. Every partial path keeps `recv_at + recv_want ==
        // body_len`.
        match &self.body_buf {
            Some(_) if self.recv_into_body => self
                .recv_at
                .checked_add(self.recv_want)
                .is_some_and(|end| end <= self.body_len),
            _ => self.recv_buf.armed_within(self.recv_at, self.recv_want),
        }
    }

    /// Complete a placed-body recv: the whole body is now initialized, so the buffer's length can cover it.
    fn finish_body_recv(&mut self) {
        self.recv_into_body = false;
        if let Some(body) = &mut self.body_buf {
            // SAFETY: capacity is at least `body_len` and bytes `[0, body_len)` are initialized - the prefix by
            // `extend_from_slice`, the rest by the kernel (the exact `MSG_WAITALL` recv completed with the full count).
            unsafe { body.set_len(self.body_len) };
        }
    }

    // ---- spliced body ----

    /// Arm a zero-copy body splice: record the borrowed destination `fd` and the full body length still to move.
    /// `submit_splice_recv` sets the scheduling flags and stages the op; `advance_splice` tracks the cursor across
    /// partial completions (a socket->pipe splice, like a kTLS recv, can't carry `MSG_WAITALL`, so it may complete
    /// short).
    pub(crate) fn arm_splice(&mut self, fd: RawFd, body_len: usize) {
        self.splice_fd = fd;
        self.splice_remaining = body_len;
    }

    /// Account `n` spliced bytes; returns `true` once the whole body has moved (the cursor reached zero).
    /// `saturating_sub` is defence-in-depth - a completion never reports more than the armed remainder.
    pub(crate) fn advance_splice(&mut self, n: usize) -> bool {
        self.splice_remaining = self.splice_remaining.saturating_sub(n);
        self.splice_remaining == 0
    }

    // ---- send side ----

    /// Queue a request reply (FIFO, production order; frees a `max_in_flight` read-ahead slot once fully sent).
    pub(crate) fn enqueue_reply(&mut self, bytes: impl Into<SendBuf>) {
        self.enqueue(bytes, SendKind::ReplyLast);
    }

    /// Queue a multi-segment reply, sent vectored (the segments are separate buffers `arm_send` gathers). The whole
    /// reply is one logical response: only its **last non-empty** segment is [`SendKind::ReplyLast`], so `advance_sent`
    /// retires the request's `outstanding` count exactly once, when the final segment flushes - not once per segment.
    /// Empty segments are dropped. Returns whether any bytes were queued; an all-empty reply queues nothing (a one-way
    /// message), for which the caller must not bump `outstanding`.
    pub(crate) fn enqueue_reply_segments(&mut self, segments: Vec<SendBuf>) -> bool {
        let Some(last) = segments.iter().rposition(|s| !s.is_empty()) else {
            return false;
        };
        for (i, seg) in segments.into_iter().enumerate() {
            if seg.is_empty() {
                continue;
            }
            self.enqueue(
                seg,
                if i == last {
                    SendKind::ReplyLast
                } else {
                    SendKind::ReplyPart
                },
            );
        }
        true
    }

    /// Queue a pushed PDU (FIFO behind everything already queued; pushes never count against the read-ahead cap).
    pub(crate) fn enqueue_push(&mut self, bytes: Vec<u8>) {
        self.enqueue(bytes, SendKind::Push);
    }

    pub(super) fn enqueue(&mut self, bytes: impl Into<SendBuf>, kind: SendKind) {
        #[cfg_attr(not(feature = "net-server"), allow(unused_mut))]
        let mut bytes = bytes.into();
        self.queued_bytes += bytes.len();
        #[cfg(feature = "net-server")]
        // Counted as the ring's from here until it is sent or dropped.
        let home = match (&self.body_pool, bytes.recycled_mut()) {
            (Some(pool), Some(v)) => Some(super::bodypool::Home::hold(pool, v.capacity())),
            _ => None,
        };
        let item = SendItem {
            bytes,
            kind,
            #[cfg(all(feature = "net-server", feature = "uring-fs"))]
            reclaim: false,
            #[cfg(feature = "net-server")]
            home,
        };
        // Mid-file-tail, any other PDU would land between two chunks of the streaming body on the wire; hold it (still
        // counted in `queued_bytes`, so the backlog bound sees it) until the tail's last chunk is queued.
        #[cfg(all(feature = "net-server", feature = "uring-fs"))]
        if let Some(tail) = self.file_tail.as_mut() {
            tail.pending.push(PendingItem::Pdu(item));
            return;
        }
        self.send_queue.push_back(item);
    }

    /// Install a file tail: the reply path streams `len` bytes of `file` from `offset` behind whatever is already
    /// queued. The caller enqueued the reply's head first (as a non-final segment) and checked no tail is active.
    #[cfg(all(feature = "net-server", feature = "uring-fs"))]
    pub(crate) fn install_file_tail(&mut self, file: crate::uring_fs::File, offset: u64, len: u64) {
        debug_assert!(self.file_tail.is_none(), "one tail at a time");
        self.file_tail = Some(FileTail {
            file,
            next_offset: offset,
            unread: len,
            reading: false,
            // Anything that arrived behind this body while it waited its turn stays behind it.
            pending: std::mem::take(&mut self.next_file_pending),
            parked: false,
        });
    }

    /// Whether a file-sourced body is still being produced (its last chunk not yet queued). While true, a queue that
    /// reads dry can still owe bytes - the flush-close dry checks consult this.
    #[cfg(all(feature = "net-server", feature = "uring-fs"))]
    pub(crate) fn tail_active(&self) -> bool {
        self.file_tail.is_some()
    }

    /// Without a server-side fs pool no tail can exist.
    #[cfg(not(all(feature = "net-server", feature = "uring-fs")))]
    pub(crate) fn tail_active(&self) -> bool {
        false
    }

    /// Claim this connection's share of the ring for one more chunk.
    ///
    /// `false` when it already holds [`FILE_TAIL_BUFS`] - one being read into, the rest queued or sending. The read
    /// then waits for a flush, and that wait is the body's memory bound. Nothing is allocated here: the buffer comes
    /// from the reactor's ring, chosen by the kernel when the read completes.
    #[cfg(all(feature = "net-server", feature = "uring-fs"))]
    pub(crate) fn tail_claim_chunk(&mut self) -> bool {
        if self.file_tail.is_none() || self.chunk_out >= FILE_TAIL_BUFS {
            return false;
        }
        self.chunk_out += 1;
        true
    }

    /// Give a claim back without a chunk having been queued - a read that failed or hit EOF.
    #[cfg(all(feature = "net-server", feature = "uring-fs"))]
    pub(crate) fn tail_release_chunk(&mut self) {
        self.chunk_out = self.chunk_out.saturating_sub(1);
    }

    /// Pool buffer ids still sitting in the send queue, taken.
    ///
    /// Teardown: the connection is going away with segments that name ring buffers, and a buffer never handed back is
    /// one the pool can neither reissue nor free. The entries drop here, so a reply marked recycled goes home with
    /// them.
    #[cfg(all(feature = "net-server", feature = "uring-fs"))]
    pub(crate) fn drain_pooled_bids(&mut self) -> Vec<u16> {
        let mut out = Vec::new();
        for item in self.send_queue.drain(..) {
            if let Some(bid) = item.bytes.pooled_bid() {
                out.push(bid);
            }
        }
        self.queued_bytes = 0;
        self.chunk_out = 0;
        out
    }

    /// Queue the leading segment of a reply whose final segment arrives later (a file tail's head): a non-final part,
    /// so the reply retires exactly once - when the tail's last chunk flushes. Call before
    /// [`Connection::install_file_tail`], while the diversion is still off.
    #[cfg(all(feature = "net-server", feature = "uring-fs"))]
    pub(crate) fn enqueue_reply_head(&mut self, bytes: Vec<u8>) {
        if !bytes.is_empty() {
            self.enqueue(bytes, SendKind::ReplyPart);
        }
    }

    /// Queue one tail chunk (bypassing the diversion - it IS the tail). `last` marks the final chunk `ReplyLast`,
    /// retiring the reply's read-ahead slot when it flushes.
    #[cfg(all(feature = "net-server", feature = "uring-fs"))]
    pub(crate) fn enqueue_file_chunk(&mut self, bytes: SendBuf, last: bool) {
        self.queued_bytes += bytes.len();
        self.send_queue.push_back(SendItem {
            bytes,
            kind: if last { SendKind::ReplyLast } else { SendKind::ReplyPart },
            reclaim: true,
            home: None,
        });
    }

    /// Advance the tail past a completed body read and queue its bytes as the next chunk. `true` when that was the last
    /// of the declared length, which also retires the tail and releases the diversion.
    ///
    /// The advance is the count the read returned, never the length asked for. Short reads are ordinary on ZFS, where
    /// every ring read is punted to an io-wq worker, and advancing by the request would skip the unread bytes and send
    /// a body correct in its framing and wrong in its content. The read carries no `IOSQE_IO_LINK` for the same reason.
    #[cfg(all(feature = "net-server", feature = "uring-fs"))]
    pub(crate) fn advance_file_tail(&mut self, buf: SendBuf) -> bool {
        let n = buf.len() as u64;
        let last = {
            let tail = self.file_tail.as_mut().expect("a tail is streaming");
            // `n <= iov_len = min(chunk, unread)`, so this never underflows, and the advance never passes `offset +
            // len` - which `begin_file_reply` bounded at `i64::MAX` before the first read.
            tail.next_offset += n;
            tail.unread -= n;
            tail.unread == 0
        };
        self.enqueue_file_chunk(buf, last);
        if last {
            self.finish_file_tail();
        }
        last
    }

    /// Retire the tail (its last chunk is queued) and release what the diversion held behind it, in arrival order - up
    /// to the first deferred file body, which cannot simply be queued: it has to be installed as the next tail, and
    /// only the reply path can issue its read. That one is left in
    /// [`take_queued_file_reply`](Self::take_queued_file_reply), and anything behind it waits for it, so responses keep
    /// request order.
    #[cfg(all(feature = "net-server", feature = "uring-fs"))]
    pub(crate) fn finish_file_tail(&mut self) {
        let Some(tail) = self.file_tail.take() else {
            return;
        };
        let mut rest = tail.pending.into_iter();
        for item in rest.by_ref() {
            match item {
                PendingItem::Pdu(pdu) => self.send_queue.push_back(pdu),
                PendingItem::File(next) => {
                    self.next_file = Some(next);
                    break;
                }
            }
        }
        self.next_file_pending = rest.collect();
    }

    /// Hold a `ReplyFile` that arrived while a body was already streaming. The caller has counted it in `outstanding` -
    /// it is an answered request either way, and the read-ahead cap must see it.
    #[cfg(all(feature = "net-server", feature = "uring-fs"))]
    pub(crate) fn defer_file_reply(&mut self, next: PendingFile) {
        self.deferred_close |= next.close;
        self.file_tail
            .as_mut()
            .expect("only deferred behind an active tail")
            .pending
            .push(PendingItem::File(next));
    }

    /// Whether a reply the handler declared final is queued behind the active body. The pump gate stops on this exactly
    /// as it stops on `close_on_flush`: both mean no further request may be admitted, and which of the two holds
    /// depends only on whether the closing reply's body has reached the wire yet.
    #[cfg(all(feature = "net-server", feature = "uring-fs"))]
    pub(crate) fn has_deferred_close(&self) -> bool {
        self.deferred_close
    }

    /// Without a server-side fs pool no body can be deferred.
    #[cfg(not(all(feature = "net-server", feature = "uring-fs")))]
    pub(crate) fn has_deferred_close(&self) -> bool {
        false
    }

    /// The file body the last tail handed on, if any - installed by the reply path, which is the only place a read can
    /// be issued.
    #[cfg(all(feature = "net-server", feature = "uring-fs"))]
    pub(crate) fn take_queued_file_reply(&mut self) -> Option<PendingFile> {
        let next = self.next_file.take();
        // Installing this one arms `close_on_flush` from its own `close`, but this flag covers every deferred body, so
        // recompute it from the followers rather than clearing it. Cleared, the gate admits requests whose answers
        // `drop_queued_file_reply` then discards unsent.
        self.deferred_close = self
            .next_file_pending
            .iter()
            .any(|item| matches!(item, PendingItem::File(f) if f.close));
        next
    }

    /// Drop a deferred file body **and everything queued behind it**, since the connection is flush-closing and the
    /// deferred response will never be sent.
    ///
    /// A response is tied to its request by position, so queueing the followers would put the next response where the
    /// dropped one belonged, and the peer would read it as the answer to the wrong request. A peer that sees the close
    /// knows what went unanswered and can retry it.
    #[cfg(all(feature = "net-server", feature = "uring-fs"))]
    pub(crate) fn drop_queued_file_reply(&mut self) {
        // Every discarded item was charged to `outstanding` as it was delivered, and nothing here will flush to credit
        // it, so the charges are returned by hand. The read-ahead gate, the idle timeout and the drain all read
        // `outstanding`.
        let mut charged = u32::from(self.next_file.is_some());
        self.next_file = None;
        // Whatever close a discarded body carried is subsumed by the `close_on_flush` that brought us here.
        self.deferred_close = false;
        let mut bytes = 0usize;
        for item in std::mem::take(&mut self.next_file_pending) {
            match item {
                // A deferred body has queued no bytes yet - a file tail is queued a chunk at a time, and this one never
                // started.
                PendingItem::File(_) => charged += 1,
                // Only a reply's final segment carries a charge, and a push carries none. `enqueue` counted the bytes
                // into `queued_bytes` before the diversion held them back, so they come off here too. None is a pooled
                // buffer, since `enqueue_file_chunk` bypasses the diversion.
                PendingItem::Pdu(pdu) => {
                    bytes += pdu.bytes.len();
                    if matches!(pdu.kind, SendKind::ReplyLast) {
                        charged += 1;
                    }
                }
            }
        }
        self.outstanding = self.outstanding.saturating_sub(charged);
        self.queued_bytes = self.queued_bytes.saturating_sub(bytes);
    }

    /// Whether any PDU is queued (or being sent).
    pub(crate) fn has_pending_send(&self) -> bool {
        !self.send_queue.is_empty()
    }

    /// Total bytes queued (including the partially-sent front PDU).
    pub(crate) fn queued_bytes(&self) -> usize {
        self.queued_bytes
    }

    /// Point the send `msghdr` at up to `max_send_coalesce` queued PDUs - a writev-style gather starting at the front
    /// PDU's unsent tail. Whole-PDU FIFO order is preserved; only already-queued PDUs are gathered, so a lone reply is
    /// never delayed. Records and returns the armed byte count.
    pub(crate) fn arm_send(&mut self) -> usize {
        let mut total = 0usize;
        let mut k = 0usize;
        for (i, item) in self.send_queue.iter().take(self.send_iovs.len()).enumerate() {
            let off = if i == 0 { self.front_sent } else { 0 };
            let tail = &item.bytes[off..];
            self.send_iovs[i].iov_base = tail.as_ptr() as *mut c_void;
            self.send_iovs[i].iov_len = tail.len();
            total += tail.len();
            k = i + 1;
        }
        assert!(k > 0, "arm_send: empty queue");
        self.send_msg.msg_iov = self.send_iovs.as_mut_ptr();
        self.send_msg.msg_iovlen = k;
        self.send_msg.msg_name = ptr::null_mut();
        self.send_msg.msg_namelen = 0;
        self.send_msg.msg_control = ptr::null_mut();
        self.send_msg.msg_controllen = 0;
        self.send_msg.msg_flags = 0;
        self.armed_bytes = total;
        total
    }

    /// Advance the send cursor by `n` bytes (clamped to the armed gather): fully-sent PDUs are popped and tallied by
    /// kind; a partially-sent leader updates the front cursor. A popped [`SendBuf::recycled`] segment's storage goes
    /// back to the ring's body pool as it drops.
    pub(crate) fn advance_sent(&mut self, n: usize) -> SendProgress {
        let mut n = n.min(self.armed_bytes);
        self.armed_bytes -= n;
        let mut progress = SendProgress {
            replies: 0,
            pushes: 0,
            armed_remaining: self.armed_bytes,
            #[cfg(all(feature = "net-server", feature = "uring-fs"))]
            freed_bids: [0; FILE_TAIL_BUFS as usize],
            #[cfg(all(feature = "net-server", feature = "uring-fs"))]
            freed: 0,
        };
        while n > 0 {
            let front_remaining = self
                .send_queue
                .front()
                .expect("advance_sent: cursor past queue")
                .bytes
                .len()
                - self.front_sent;
            if n < front_remaining {
                self.front_sent += n;
                break;
            }
            n -= front_remaining;
            self.front_sent = 0;
            let item = self.send_queue.pop_front().unwrap();
            self.queued_bytes -= item.bytes.len();
            match item.kind {
                SendKind::ReplyLast => progress.replies += 1,
                SendKind::Push => progress.pushes += 1,
                // Tallied by the reply's final ReplyLast segment.
                SendKind::ReplyPart => {}
            }
            // A flushed tail chunk frees this connection's share of the ring, and its buffer goes back to the pool -
            // which only the reactor can do, so the id rides out on the progress. Not conditioned on a tail being
            // installed: a chunk can still be flushing after its tail retired.
            #[cfg(all(feature = "net-server", feature = "uring-fs"))]
            if item.reclaim {
                self.chunk_out = self.chunk_out.saturating_sub(1);
                if let Some(bid) = item.bytes.pooled_bid() {
                    // `tail_claim_chunk` refuses past `FILE_TAIL_BUFS`, so a flush can never pop more reclaim segments
                    // than this array holds. If the two ever diverge, `get_mut` drops a bid the pool can neither
                    // reissue nor free, which the assert guards.
                    debug_assert!(
                        (progress.freed as usize) < progress.freed_bids.len(),
                        "at most FILE_TAIL_BUFS chunks can be queued at once"
                    );
                    if let Some(cell) = progress.freed_bids.get_mut(progress.freed as usize) {
                        *cell = bid;
                        progress.freed += 1;
                    }
                }
            }
        }
        progress
    }

    /// Stable pointer to the send `msghdr` for an SQE `addr` field.
    pub(crate) fn send_msg_ptr(&self) -> u64 {
        ptr::addr_of!(self.send_msg) as u64
    }

    /// The armed gather's lone segment as `(ptr, len)` when it has exactly one, for the plain `SEND` fast path.
    ///
    /// The length is clamped to `i32::MAX`, never cast-wrapped, since an SQE length is `u32` and a CQE result `i32`,
    /// and a wrapped length can become a 0-byte send read as a fatal `SendError`. A clamped send completes short and
    /// the re-submit carries the rest, like any partial send.
    pub(crate) fn send_single(&self) -> Option<(u64, u32)> {
        (self.send_msg.msg_iovlen == 1).then(|| {
            (
                self.send_iovs[0].iov_base as u64,
                self.send_iovs[0].iov_len.min(i32::MAX as usize) as u32,
            )
        })
    }
}
