//! The client's request/reply data plane. It holds the reply-framer pump, the recv, send and splice completion wrappers
//! over the [`Reactor`](crate::net::core::reactor) core, reply delivery into the event queue, and the caller-facing
//! `send`, `request` and `next_event`.

use super::Client;
use super::connect::ts_of;
use super::event::{ConnId, Event, RequestId};
use crate::errno;
use crate::net::core::conn::{Op, pack, unpack};
use crate::net::core::protocol::{Body, CloseReason, Framing};
use crate::net::core::reactor::{Enacted, Gate, RecvStep, SendStep, SpliceStep};
use crate::uring::sys::*;
use std::collections::VecDeque;
use std::io;
use std::time::Duration;

/// An in-flight body splice's delivery context, snapshotted when the splice is armed because the core `consume`s the
/// header on completion. Emitted as [`Event::Splice`] once the body has moved.
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
    /// The per-connection read/deliver pump: consult the reply framer on the accumulated bytes and either read more,
    /// deliver a buffered reply, or close. [`Reactor::pump_gate`] runs the loop-top guards and
    /// [`Reactor::enact_frame_step`] enacts the framer's verdict.
    ///
    /// [`Reactor::pump_gate`]: crate::net::core::reactor
    /// [`Reactor::enact_frame_step`]: crate::net::core::reactor
    pub(super) fn pump(&mut self, slot: u32, generation: u32) -> errno::Result<()> {
        loop {
            match self.core.pump_gate(slot, generation)? {
                Gate::Stop => return Ok(()),
                Gate::Proceed => {}
            }
            let verdict = {
                // `self.core.table` and `self.framer` are disjoint fields, so the framer can run while the connection
                // is borrowed.
                let conn = self.core.table.conn_mut(slot);
                let (buf, state) = conn.frame_parts();
                (self.framer)(buf, state)
            };
            match self.core.enact_frame_step(slot, generation, verdict)? {
                Enacted::Done => {
                    // The pump gate stops on `splicing`, so a splicing connection here was armed this iteration. Its
                    // header must be snapshotted now, before the core `consume`s it.
                    if self.core.table.get_conn(slot).is_some_and(|c| c.splicing) {
                        self.begin_splice(slot, generation)?;
                    }
                    return Ok(());
                }
                Enacted::Deliver => self.deliver_reply(slot, generation)?,
            }
        }
    }

    /// A body splice was just armed. Correlate it to the oldest request awaiting a reply and stash the header and body
    /// length for `deliver_splice`. With no request awaiting, it is an unsolicited push, stashed with
    /// [`RequestId::UNSOLICITED`] when the caller opted in and otherwise closing the connection.
    fn begin_splice(&mut self, slot: u32, generation: u32) -> errno::Result<()> {
        let id = match self.awaiting.get_mut(&slot).and_then(VecDeque::pop_front) {
            Some(id) => id,
            None if self.cfg.expect_server_push => RequestId::UNSOLICITED,
            None => {
                return self.core.close_conn(slot, generation, CloseReason::Malformed);
            }
        };
        let (header, body_len) = {
            let (h, bl) = self.core.table.conn(slot).splice_frame_parts();
            (h.to_vec(), bl)
        };
        self.splicing_frames
            .insert(slot, PendingSplice { id, header, body_len });
        Ok(())
    }

    /// A reply recv completed. The core does the bookkeeping, and the returned [`RecvStep`] says whether to deliver.
    pub(super) fn on_recv(&mut self, slot: u32, generation: u32, res: i32, op: Op) -> errno::Result<()> {
        match self.core.on_recv_complete(slot, generation, res, op)? {
            RecvStep::Deliver => {
                self.deliver_reply(slot, generation)?;
                self.pump(slot, generation)
            }
            RecvStep::Pump => self.pump(slot, generation),
            RecvStep::Done => Ok(()),
        }
    }

    /// A request send completed. A fully flushed gather resumes the pump.
    pub(super) fn on_send(&mut self, slot: u32, generation: u32, res: i32) -> errno::Result<()> {
        match self.core.on_send_complete(slot, generation, res)? {
            SendStep::Pump => self.pump(slot, generation),
            SendStep::Done => Ok(()),
        }
    }

    /// A reply-body splice completed. A fully moved body emits an [`Event::Splice`] and pumps the next frame. Error,
    /// EOF and deadline paths close through the core and surface as [`Event::Closed`].
    pub(super) fn on_splice_recv(&mut self, slot: u32, generation: u32, res: i32) -> errno::Result<()> {
        match self.core.on_splice_recv_complete(slot, generation, res)? {
            SpliceStep::Pump => {
                self.deliver_splice(slot);
                self.pump(slot, generation)
            }
            SpliceStep::Done => Ok(()),
        }
    }

    /// Emit the [`Event::Splice`] for a fully moved body from the stash `begin_splice` recorded. A missing stash emits
    /// nothing.
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

    /// Turn a fully buffered reply into an [`Event::Reply`] correlated to the oldest request awaiting a reply. With no
    /// request awaiting, it is an unsolicited push, surfaced with [`RequestId::UNSOLICITED`] when the caller opted in
    /// and otherwise closing the connection.
    fn deliver_reply(&mut self, slot: u32, generation: u32) -> errno::Result<()> {
        let gen64 = self.core.table.generation(slot);
        let conn = ConnId::new(slot, gen64);
        let id = match self.awaiting.get_mut(&slot).and_then(VecDeque::pop_front) {
            Some(id) => id,
            None if self.cfg.expect_server_push => RequestId::UNSOLICITED,
            None => {
                return self.core.close_conn(slot, generation, CloseReason::Malformed);
            }
        };
        // The connection buffer is reused for the next frame, so the header is copied and the body moved out.
        let (header, body) = {
            let c = self.core.table.conn_mut(slot);
            let (h, mut b, _peer, _state, _ticket) = c.deliver_parts(None);
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

    /// Queue `pdu` as a request on `conn` and start sending, returning the [`RequestId`] its reply will carry. The
    /// `pdu` is sent verbatim, so frame it yourself.
    ///
    /// # Errors
    ///
    /// `WouldBlock` at `max_in_flight` or `max_send_backlog`, `NotConnected` for a stale or unconnected handle, and
    /// `InvalidInput` for an empty `pdu`, since a request holds a correlation slot until its reply arrives.
    pub fn send(&mut self, conn: ConnId, pdu: Vec<u8>) -> io::Result<RequestId> {
        let (slot, generation) = conn.parts();
        if !self.core.table.slot_matches(slot, generation) {
            return Err(io::Error::new(io::ErrorKind::NotConnected, "not a live connection"));
        }
        if pdu.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "an empty request PDU has no reply to correlate",
            ));
        }
        let in_flight = self.awaiting.get(&slot).map_or(0, VecDeque::len);
        if in_flight >= self.cfg.max_in_flight {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "max_in_flight requests already outstanding",
            ));
        }
        if self.core.table.conn(slot).queued_bytes() + pdu.len() > self.cfg.max_send_backlog {
            return Err(io::Error::new(io::ErrorKind::WouldBlock, "send backlog is full"));
        }
        let id = RequestId(self.next_req);
        self.next_req = self.next_req.wrapping_add(1);
        self.core.table.conn_mut(slot).enqueue_reply(pdu);
        self.awaiting.entry(slot).or_default().push_back(id);
        self.core.kick_send(slot, generation as u32)?;
        Ok(id)
    }

    /// Send `pdu` on `conn` and pump until its matching reply arrives, returning the reply body. Events for other
    /// connections/requests seen while waiting are buffered back for later [`next_event`](Client::next_event) calls.
    /// The connection closing before the reply (or all connections ending) is an error.
    ///
    /// Other connections' events accumulate in memory meanwhile, so with untrusted peers, `expect_server_push` ones
    /// above all, that buffer has no bound. Drive such workloads with [`next_event`](Client::next_event) or
    /// [`next_event_timeout`](Client::next_event_timeout) and your own backpressure.
    pub fn request(&mut self, conn: ConnId, pdu: Vec<u8>) -> io::Result<Body<'static>> {
        let id = self.send(conn, pdu)?;
        let mut stash: VecDeque<Event> = VecDeque::new();
        let out = loop {
            match self.next_event()? {
                Some(Event::Reply {
                    conn: c, id: rid, body, ..
                }) if c == conn && rid == id => break Ok(body),
                Some(Event::Closed { conn: c, reason }) if c == conn => {
                    break Err(io::Error::new(
                        io::ErrorKind::ConnectionReset,
                        format!("connection closed before reply: {reason:?}"),
                    ));
                }
                Some(Event::ConnectFailed { conn: c, err }) if c == conn => {
                    break Err(io::Error::from(err));
                }
                Some(ev) => stash.push_back(ev),
                None => {
                    break Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "no reply before all connections ended",
                    ));
                }
            }
        };
        // Restore the buffered events ahead of any queued after them.
        stash.append(&mut self.events);
        self.events = stash;
        out
    }

    /// Pump the ring and return the next [`Event`]: drain a ready event, else block for completions and dispatch them
    /// until one is produced. `None` exactly when no connections remain (nothing in flight and no ready events).
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
            // The client has no listener to re-arm on a freed slot, so the flag is only cleared.
            let _ = self.core.take_pool_freed();
        }
    }

    /// Like [`next_event`](Client::next_event) but bounded: return the next [`Event`] if one becomes ready within
    /// `dur`, else `Ok(None)` - "no event within `dur`". A `None` here does **not** mean "no connections left" (as it
    /// does for `next_event`). The connections stay open and untouched, so call again to keep waiting.
    pub fn next_event_timeout(&mut self, dur: Duration) -> io::Result<Option<Event>> {
        if let Some(ev) = self.events.pop_front() {
            return Ok(Some(ev));
        }
        if self.no_live_work() {
            return Ok(None);
        }
        // Reap the deadline of a call that unwound (see `deadline_inflight`).
        if self.deadline_inflight {
            self.cancel_and_reap_deadline(pack(Op::Deadline, 0, 0))?;
            self.deadline_inflight = false;
        }
        // `Op::Deadline` with slot and generation 0 is unique on the client ring, which arms no other such timer.
        *self.deadline_pad = ts_of(dur);
        let ts_ptr = std::ptr::addr_of!(*self.deadline_pad) as u64;
        let deadline_ud = pack(Op::Deadline, 0, 0);
        self.core.stage(deadline_ud, move |sqe| {
            sqe.opcode = IORING_OP_TIMEOUT;
            sqe.addr = ts_ptr;
            sqe.len = 1; // exactly one timespec, per the kernel
        })?;
        self.deadline_inflight = true;
        // The deadline CQE is reaped here rather than in `dispatch`, so its firing is observable.
        let mut fired = false;
        let out = loop {
            self.core.engine.ring.submit_and_wait(1)?;
            while let Some(cqe) = self.core.engine.ring.reap() {
                let (op, _, _) = unpack(cqe.user_data);
                if matches!(op, Some(Op::Deadline)) {
                    // Not multishot - count it off exactly as `dispatch` would.
                    self.core.engine.inflight = self.core.engine.inflight.saturating_sub(1);
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
        };
        // An event won the race, so the deadline is still in flight and must not fire on a later call.
        if !fired {
            self.cancel_and_reap_deadline(deadline_ud)?;
        }
        self.deadline_inflight = false;
        Ok(out)
    }

    /// Cancel the pending `next_event_timeout` deadline and reap until its terminal completion, so the pad is free to
    /// rewrite and `inflight` stays exact. Other completions reaped meanwhile are dispatched. A cancel completing
    /// `-ENOENT` matched nothing, so no `Op::Deadline` completion is owed.
    fn cancel_and_reap_deadline(&mut self, deadline_ud: u64) -> errno::Result<()> {
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
                    // `-ECANCELED`, or `-ETIME` if it fired concurrently.
                    self.core.engine.inflight = self.core.engine.inflight.saturating_sub(1);
                    done = true;
                } else {
                    // `-ENOENT` on the cancel means it found no target, so the deadline is gone.
                    let gone = matches!(op, Some(Op::Cancel)) && cqe.res == -libc::ENOENT;
                    self.dispatch(cqe)?;
                    done |= gone;
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

// `not(loom)`: this module builds a real ring and drives real threads, neither of which a model run has. See
// `src/sync.rs`.
#[cfg(all(test, not(loom)))]
mod tests {
    use super::*;
    use crate::net::client::{ClientConfig, ConnectOpts};
    use crate::net::core::protocol::ServerAddr;
    use crate::uring::sys::IoUringCqe;
    use std::net::{SocketAddr, TcpListener};
    use std::thread;
    use std::time::Instant;

    /// A stateless framer type the test client is generic over.
    type Framer = fn(&[u8], &mut ()) -> Framing;

    /// A client for a white-box deadline test, or `None` where io_uring is unavailable - the environment skip the
    /// integration suites also take.
    fn client() -> Option<Client<(), Framer>> {
        fn framer(_buf: &[u8], _state: &mut ()) -> Framing {
            Framing::More
        }
        let framer: Framer = framer;
        match Client::new(ClientConfig::default(), framer) {
            Ok(c) => Some(c),
            Err(crate::Error::Errno(e)) if crate::uring::setup_unavailable(e) => None,
            Err(e) => panic!("client new: {e}"),
        }
    }

    #[test]
    fn dispatch_of_a_stray_deadline_retires_the_flag() {
        let Some(mut client) = client() else { return };
        // The state a `next_event_timeout` that unwound leaves behind: the flag set, its `Op::Deadline` still counted
        // in flight.
        client.deadline_inflight = true;
        client.core.engine.inflight = 1;
        client
            .dispatch(IoUringCqe {
                user_data: pack(Op::Deadline, 0, 0),
                res: -libc::ETIME,
                flags: 0,
            })
            .expect("dispatch the deadline");
        assert!(!client.deadline_inflight, "consuming the deadline retires the flag");
        assert_eq!(client.core.engine.inflight, 0, "counted off exactly once");
    }

    #[test]
    fn bounded_wait_recovers_from_an_unarmed_deadline_flag() {
        let Some(mut client) = client() else { return };
        // A peer that accepts and then sits idle, so the client has live work (an armed reply recv) and no completion
        // of its own to reap.
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let SocketAddr::V4(v4) = listener.local_addr().expect("local_addr") else {
            unreachable!("bound v4");
        };
        let peer = thread::spawn(move || {
            let held = listener.accept().expect("accept");
            thread::sleep(Duration::from_millis(500));
            drop(held);
        });
        let conn = client
            .connect(ServerAddr::Tcp(v4), ConnectOpts::default())
            .expect("connect to the idle peer");

        // The flag set with no `Op::Deadline` armed: the reap-side cancel matches nothing (`-ENOENT`), which is the
        // whole of what is owed, so the call goes on to arm its own deadline and time out normally.
        client.deadline_inflight = true;
        let t0 = Instant::now();
        let ev = client
            .next_event_timeout(Duration::from_millis(100))
            .expect("bounded wait");
        assert!(ev.is_none(), "expected no event, got {ev:?}");
        assert!(
            t0.elapsed() < Duration::from_millis(400),
            "the bounded wait took {:?}",
            t0.elapsed()
        );
        assert!(client.is_open(conn), "the connection is left open");

        client.close_now(conn);
        peer.join().ok();
    }
}
