//! The client's request/reply data plane: the reply-framer pump skeleton, the
//! recv/send/splice completion wrappers (their heavy bookkeeping is core — see
//! [`Reactor`](crate::net::core::reactor)), reply delivery into the event queue,
//! and the caller-facing `send`/`request`/`next_event` pump.
//!
//! These mirror the server's `io.rs` wrappers exactly, except the framer is the
//! client's `self.framer` (not a handler bundle) and a delivered message becomes
//! an [`Event::Reply`] via `deliver_reply` rather than a body-handler call.

use super::connect::ts_of;
use super::event::{ConnId, Event, RequestId};
use super::Client;
use crate::errno;
use crate::net::core::conn::{pack, unpack, Op};
use crate::net::core::protocol::{Body, CloseReason, Framing};
use crate::net::core::reactor::{
    Enacted, Gate, RecvStep, SendStep, SpliceStep,
};
use crate::uring::sys::*;
use std::collections::VecDeque;
use std::io;
use std::time::Duration;

/// An in-flight body splice's delivery context, snapshotted when the splice is
/// armed and emitted as [`Event::Splice`] once the body finishes moving to the
/// sink fd — the header would otherwise be gone (the core `consume`s it on
/// completion). One per splicing connection (the pump gates the recv side while
/// splicing).
pub(super) struct PendingSplice {
    /// The request this spliced reply answers (FIFO-correlated).
    id: RequestId,
    /// The buffered header bytes.
    header: Vec<u8>,
    /// The body length being spliced to the sink fd.
    body_len: usize,
}

impl<U, F> Client<U, F>
where
    F: FnMut(&[u8], &mut U) -> Framing,
{
    /// The per-connection read/deliver pump: consult the reply framer on the
    /// accumulated bytes and either read more, deliver a buffered reply, or
    /// close. A thin skeleton over the core: [`Reactor::pump_gate`] runs the
    /// loop-top guards and [`Reactor::enact_frame_step`] enacts the framer's
    /// verdict; only the framer call (via the disjoint `self.core.table` +
    /// `self.framer` borrows) and the `Deliver` seam stay here.
    ///
    /// [`Reactor::pump_gate`]: crate::net::core::reactor
    /// [`Reactor::enact_frame_step`]: crate::net::core::reactor
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
                // `self.core.table` and `self.framer` are disjoint fields, so
                // the framer can run while the connection is borrowed.
                let conn = self.core.table.conn_mut(slot);
                let (buf, state) = conn.frame_parts();
                (self.framer)(buf, state)
            };
            match self.core.enact_frame_step(slot, generation, verdict)? {
                Enacted::Done => {
                    // If this iteration armed a body splice
                    // (`Framing::SpliceBody`), correlate it and snapshot its
                    // header now — the `Event::Splice` emitted when the body
                    // finishes moving needs them, but the core `consume`s the
                    // header then. The pump gate stops on `splicing`, so a
                    // `splicing` connection here was armed this iteration.
                    if self
                        .core
                        .table
                        .get_conn(slot)
                        .is_some_and(|c| c.splicing)
                    {
                        self.begin_splice(slot, generation)?;
                    }
                    return Ok(());
                }
                Enacted::Deliver => self.deliver_reply(slot, generation)?,
            }
        }
    }

    /// A body splice was just armed (`Framing::SpliceBody`): correlate it to the
    /// oldest request awaiting a reply on this connection (FIFO) and snapshot the
    /// buffered header + body length, stashed until the body finishes moving
    /// (`deliver_splice` then emits [`Event::Splice`]). A splice with no request
    /// awaiting it is an unsolicited push — stashed with
    /// [`RequestId::UNSOLICITED`] when the caller opted in, otherwise a protocol
    /// violation that closes the connection (the in-flight splice is cancelled).
    fn begin_splice(
        &mut self,
        slot: u32,
        generation: u32,
    ) -> errno::Result<()> {
        let id =
            match self.awaiting.get_mut(&slot).and_then(VecDeque::pop_front) {
                Some(id) => id,
                None if self.cfg.expect_server_push => RequestId::UNSOLICITED,
                None => {
                    return self.core.close_conn(
                        slot,
                        generation,
                        CloseReason::Malformed,
                    );
                }
            };
        let (header, body_len) = {
            let (h, bl) = self.core.table.conn(slot).splice_frame_parts();
            (h.to_vec(), bl)
        };
        self.splicing_frames.insert(
            slot,
            PendingSplice {
                id,
                header,
                body_len,
            },
        );
        Ok(())
    }

    /// A reply recv completed (`RecvHeader`/`RecvBody`). All the completion
    /// bookkeeping is core; the returned [`RecvStep`] drives the delivery/pump
    /// tail — a completed body delivers then pumps, a completed header re-pumps.
    pub(super) fn on_recv(
        &mut self,
        slot: u32,
        generation: u32,
        res: i32,
        op: Op,
    ) -> errno::Result<()> {
        match self.core.on_recv_complete(slot, generation, res, op)? {
            RecvStep::Deliver => {
                self.deliver_reply(slot, generation)?;
                self.pump(slot, generation)
            }
            RecvStep::Pump => self.pump(slot, generation),
            RecvStep::Done => Ok(()),
        }
    }

    /// A request send completed (`Op::Send`). All the completion bookkeeping is
    /// core; a fully flushed gather resumes the pump.
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

    /// A reply-body splice completed (`Op::SpliceRecv`) — for a framer that
    /// returned [`Framing::SpliceBody`]. The body never entered the buffer (it
    /// went straight to the caller's sink fd), so a fully moved body emits an
    /// [`Event::Splice`] (the header stayed buffered/snapshotted; only the body
    /// length is reported) and pumps the next frame. Error/EOF/deadline paths
    /// close through the core and surface as [`Event::Closed`].
    pub(super) fn on_splice_recv(
        &mut self,
        slot: u32,
        generation: u32,
        res: i32,
    ) -> errno::Result<()> {
        match self.core.on_splice_recv_complete(slot, generation, res)? {
            SpliceStep::Pump => {
                self.deliver_splice(slot);
                self.pump(slot, generation)
            }
            SpliceStep::Done => Ok(()),
        }
    }

    /// Emit the [`Event::Splice`] for a fully-moved body: pop the stash
    /// `begin_splice` recorded (the correlated request id + the header snapshot +
    /// the body length) and queue the event. The body already went to the sink
    /// fd. A missing stash (the splice was cancelled before it ever moved a full
    /// body) emits nothing.
    fn deliver_splice(&mut self, slot: u32) {
        let Some(pending) = self.splicing_frames.remove(&slot) else {
            return;
        };
        let gen64 = self.core.table.generation(slot);
        self.events.push_back(Event::Splice {
            conn: ConnId::new(slot, gen64),
            id: pending.id,
            header: pending.header,
            body_len: pending.body_len,
        });
    }

    /// Turn a fully-buffered reply into an [`Event::Reply`]: correlate it to the
    /// oldest request awaiting a reply on this connection (FIFO), copy out the
    /// header and move out the (owned) body, drop the frame from the buffer, and
    /// queue the event. A reply with no request awaiting it is an unsolicited
    /// push — surfaced with [`RequestId::UNSOLICITED`] when the caller opted in,
    /// otherwise a protocol violation that closes the connection.
    fn deliver_reply(
        &mut self,
        slot: u32,
        generation: u32,
    ) -> errno::Result<()> {
        let gen64 = self.core.table.generation(slot);
        let conn = ConnId::new(slot, gen64);
        let id =
            match self.awaiting.get_mut(&slot).and_then(VecDeque::pop_front) {
                Some(id) => id,
                None if self.cfg.expect_server_push => RequestId::UNSOLICITED,
                None => {
                    return self.core.close_conn(
                        slot,
                        generation,
                        CloseReason::Malformed,
                    );
                }
            };
        // Own the reply bytes (the connection buffer is reused for the next
        // frame): the header is copied, the body is moved (zero-copy when it was
        // placed, a copy when inline).
        let (header, body) = {
            let c = self.core.table.conn_mut(slot);
            let (h, mut b, _peer, _state) = c.deliver_parts();
            (h.to_vec(), b.take())
        };
        self.core.table.conn_mut(slot).consume();
        self.events.push_back(Event::Reply {
            conn,
            id,
            header,
            body: Body::placed(body),
        });
        Ok(())
    }

    /// Queue `pdu` as a request on `conn` and start sending, returning its
    /// [`RequestId`] (the reply is FIFO-correlated to it). `WouldBlock` when the
    /// per-connection in-flight cap (`max_in_flight`) or the send backlog
    /// (`max_send_backlog`) is reached; `NotConnected` for a stale/unconnected
    /// handle. The `pdu` is sent verbatim — frame it yourself.
    pub fn send(
        &mut self,
        conn: ConnId,
        pdu: Vec<u8>,
    ) -> io::Result<RequestId> {
        let (slot, generation) = conn.parts();
        if !self.core.table.slot_matches(slot, generation) {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "not a live connection",
            ));
        }
        let in_flight = self.awaiting.get(&slot).map_or(0, VecDeque::len);
        if in_flight >= self.cfg.max_in_flight {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "max_in_flight requests already outstanding",
            ));
        }
        if self.core.table.conn(slot).queued_bytes() + pdu.len()
            > self.cfg.max_send_backlog
        {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "send backlog is full",
            ));
        }
        let id = RequestId(self.next_req);
        self.next_req = self.next_req.wrapping_add(1);
        self.core.table.conn_mut(slot).enqueue_reply(pdu);
        self.awaiting.entry(slot).or_default().push_back(id);
        self.core.kick_send(slot, generation as u32)?;
        Ok(id)
    }

    /// Send `pdu` on `conn` and pump until its matching reply arrives, returning
    /// the reply body. Events for other connections/requests seen while waiting
    /// are buffered back for later [`next_event`](Client::next_event) calls. The
    /// connection closing before the reply (or all connections ending) is an
    /// error.
    ///
    /// Because this blocks until *this* connection replies, other connections'
    /// events accumulate in memory meanwhile. With untrusted peers — especially
    /// `expect_server_push` connections, which may stream unsolicited PDUs — a
    /// peer that withholds this reply while another floods events can grow that
    /// buffer without bound. Drive such workloads with
    /// [`next_event`](Client::next_event) /
    /// [`next_event_timeout`](Client::next_event_timeout) and your own
    /// backpressure rather than the blocking helpers.
    pub fn request(
        &mut self,
        conn: ConnId,
        pdu: Vec<u8>,
    ) -> io::Result<Body<'static>> {
        let id = self.send(conn, pdu)?;
        let mut stash: VecDeque<Event> = VecDeque::new();
        let out = loop {
            match self.next_event()? {
                Some(Event::Reply {
                    conn: c,
                    id: rid,
                    body,
                    ..
                }) if c == conn && rid == id => break Ok(body),
                Some(Event::Closed { conn: c, reason }) if c == conn => {
                    break Err(io::Error::new(
                        io::ErrorKind::ConnectionReset,
                        format!("connection closed before reply: {reason:?}"),
                    ))
                }
                Some(Event::ConnectFailed { conn: c, err }) if c == conn => {
                    break Err(io::Error::from(err))
                }
                Some(ev) => stash.push_back(ev),
                None => {
                    break Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "no reply before all connections ended",
                    ))
                }
            }
        };
        // Restore the buffered events ahead of any queued after them.
        stash.append(&mut self.events);
        self.events = stash;
        out
    }

    /// Pump the ring and return the next [`Event`]: drain a ready event, else
    /// block for completions and dispatch them until one is produced. `None`
    /// exactly when no connections remain (nothing in flight and no ready
    /// events).
    pub fn next_event(&mut self) -> io::Result<Option<Event>> {
        loop {
            if let Some(ev) = self.events.pop_front() {
                return Ok(Some(ev));
            }
            if self.no_live_work() {
                return Ok(None); // no connections/connects/handshakes left
            }
            self.core.engine.ring.submit_and_wait(1)?;
            while let Some(cqe) = self.core.engine.ring.reap() {
                self.dispatch(cqe)?;
            }
            // The client has no listener to re-arm on a freed slot; clear the
            // core's flag so slot reclamation stays fully accounted.
            let _ = self.core.take_pool_freed();
        }
    }

    /// Like [`next_event`](Client::next_event) but bounded: return the next
    /// [`Event`] if one becomes ready within `dur`, else `Ok(None)` — "no event
    /// within `dur`". A `None` here does **not** mean "no connections left" (as
    /// it does for `next_event`); the connections stay open and untouched, so
    /// call again to keep waiting.
    ///
    /// Buffered events are drained first (an immediate return). Otherwise a
    /// standalone `IORING_OP_TIMEOUT` is armed over the client's own deadline
    /// pad — never a shared core pad, so a repeated call can't alias one still
    /// in flight — and the ring is pumped until either an event is produced or
    /// the deadline fires. If an event wins the race, the still-pending deadline
    /// is cancelled and reaped before returning, so it never leaks into a later
    /// call.
    pub fn next_event_timeout(
        &mut self,
        dur: Duration,
    ) -> io::Result<Option<Event>> {
        // Ready events return at once — no deadline, no blocking.
        if let Some(ev) = self.events.pop_front() {
            return Ok(Some(ev));
        }
        // No live work, so nothing can complete: no event to wait for.
        if self.no_live_work() {
            return Ok(None);
        }
        // A prior call that unwound on a fatal ring error (a `?` below) returns
        // with its deadline still in flight — the `deadline_pad` is durable for
        // exactly this reason. Reap it before staging a new one so two
        // identical-`user_data` deadlines never coexist: a stale one reaped by
        // this call would be counted as ours and return a premature `None`.
        if self.deadline_inflight {
            self.cancel_and_reap_deadline(pack(Op::Deadline, 0, 0))?;
            self.deadline_inflight = false;
        }
        // Arm the deadline over the durable `deadline_pad` (see its field doc for
        // why it outlives a fatal-error `Drop`). `Op::Deadline` with slot/gen 0
        // is unique on the client ring (it arms no other timer).
        *self.deadline_pad = ts_of(dur);
        let ts_ptr = std::ptr::addr_of!(*self.deadline_pad) as u64;
        let deadline_ud = pack(Op::Deadline, 0, 0);
        self.core.stage(deadline_ud, move |sqe| {
            sqe.opcode = IORING_OP_TIMEOUT;
            sqe.addr = ts_ptr;
            sqe.len = 1; // exactly one timespec, per the kernel
        })?;
        self.deadline_inflight = true;
        // Pump until an event is queued or the deadline fires. The deadline CQE
        // is reaped inline here (not via `dispatch`) so its firing is
        // observable; every other completion routes through `dispatch`, which
        // may queue an event.
        let mut fired = false;
        let out = loop {
            self.core.engine.ring.submit_and_wait(1)?;
            while let Some(cqe) = self.core.engine.ring.reap() {
                let (op, _, _) = unpack(cqe.user_data);
                if matches!(op, Some(Op::Deadline)) {
                    // Not multishot — count it off exactly as `dispatch` would.
                    self.core.engine.inflight =
                        self.core.engine.inflight.saturating_sub(1);
                    fired = true;
                } else {
                    self.dispatch(cqe)?;
                }
            }
            let _ = self.core.take_pool_freed();
            if let Some(ev) = self.events.pop_front() {
                break Some(ev);
            }
            if fired {
                break None;
            }
            // A completion that produced no event (e.g. a send finishing) and
            // no deadline yet: wait again — the deadline still bounds the wait.
        };
        // An event won the race: the deadline is still in flight. Cancel and
        // reap it so it can't fire on a later call (its pad is rewritten then).
        if !fired {
            self.cancel_and_reap_deadline(deadline_ud)?;
        }
        self.deadline_inflight = false;
        Ok(out)
    }

    /// Cancel the still-pending `next_event_timeout` deadline (identified by its
    /// `user_data`) and reap until its terminal completion is seen — so the pad
    /// is free to rewrite next call and `inflight` stays exact. Any real events
    /// reaped meanwhile are dispatched (queued for a later `next_event`).
    fn cancel_and_reap_deadline(
        &mut self,
        deadline_ud: u64,
    ) -> errno::Result<()> {
        self.core.stage(pack(Op::Cancel, 0, 0), move |sqe| {
            sqe.opcode = IORING_OP_ASYNC_CANCEL;
            sqe.fd = -1;
            sqe.addr = deadline_ud;
        })?;
        loop {
            self.core.engine.ring.submit_and_wait(1)?;
            let mut done = false;
            while let Some(cqe) = self.core.engine.ring.reap() {
                let (op, _, _) = unpack(cqe.user_data);
                if matches!(op, Some(Op::Deadline)) {
                    // The cancelled deadline's own completion (`-ECANCELED`, or
                    // `-ETIME` if it fired concurrently). Count it off inline.
                    self.core.engine.inflight =
                        self.core.engine.inflight.saturating_sub(1);
                    done = true;
                } else {
                    // Includes the `Cancel` control op's completion, which
                    // `dispatch` counts off and ignores.
                    self.dispatch(cqe)?;
                }
            }
            let _ = self.core.take_pool_freed();
            if done {
                break;
            }
        }
        Ok(())
    }
}
