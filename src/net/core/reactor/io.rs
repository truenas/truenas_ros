//! The core half of the per-connection request data plane: recv/send submission, the send-kick and flush-close drivers,
//! the kTLS recv continuation, the body-splice submit/poll/deadline helpers, and the two pure recv-classification
//! helpers. No consumer code runs here (the framer and body handler are role state), so this is fully core.

use super::Reactor;
use crate::errno::{self, Errno};
use crate::net::core::conn::{Op, RecvOutcome, pack};
use crate::net::core::handles::stat;
use crate::net::core::protocol::{CloseReason, Framing};
use crate::uring::force_async::ForceAsync;
use crate::uring::sys::*;
use std::os::fd::RawFd;

/// Bytes to request per chunked (`Framing::More`) recv.
const RECV_CHUNK: usize = 4096;

/// Point a staged recv at a provided-buffer group, if one was chosen.
///
/// `buf_index` is the union field the kernel reads as `buf_group`; the SQE's address is ignored once the flag is set,
/// since the kernel supplies the buffer.
#[cfg(feature = "net-server")]
fn stamp_select(sqe: &mut IoUringSqe, select: Option<u16>) {
    if let Some(bgid) = select {
        sqe.flags |= IOSQE_BUFFER_SELECT;
        sqe.buf_index = bgid;
    }
}

/// Without the server role nothing registers a buffer ring, so `select` is always `None`.
#[cfg(not(feature = "net-server"))]
fn stamp_select(_sqe: &mut IoUringSqe, _select: Option<u16>) {}

/// How large a pooled recv buffer is: the configured working size (`ServerConfig::recv_buffer_bytes`), capped at what a
/// request may be.
///
/// The `RECV_CHUNK` term is slack, not rounding: `pump_gate` closes a connection only *above* `max_request_bytes`, so a
/// scanning (`Framing::More`) read can be armed at that offset and still ask for `RECV_CHUNK` more. Including it means
/// a server whose cap already sits below the working size gets a buffer no legal read can overrun, so the promote path
/// never fires there.
#[cfg(feature = "net-server")]
pub(crate) fn recv_pool_buf_len(buffer_bytes: usize, max_request_bytes: usize) -> usize {
    buffer_bytes.min(max_request_bytes).saturating_add(RECV_CHUNK)
}

/// The action the pump takes for one framer [`Framing`] verdict - the output of [`frame_step`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameStep {
    /// Close the connection (malformed frame, or one over a size cap).
    Close(CloseReason),
    /// Read `want` more header bytes - `exact` is `MSG_WAITALL`, otherwise a chunk scan for a delimiter.
    ReadHeader {
        /// Bytes to read next.
        want: usize,
        /// `MSG_WAITALL` (exact count) vs a chunk read.
        exact: bool,
        /// The framer says a message is already under way, so this read is an active transfer even with nothing
        /// buffered ([`Framing::MoreInMessage`]).
        in_message: bool,
    },
    /// Read the message body: `want` more bytes (exact), recording the `header_len`/`body_len` split; `place` reads
    /// into an own allocation.
    ReadBody {
        /// Body bytes still to read.
        want: usize,
        /// Header length of the framed message.
        header_len: usize,
        /// Body length of the framed message.
        body_len: usize,
        /// Read the body into its own allocation (placement).
        place: bool,
    },
    /// The whole message is buffered; deliver it with this split.
    Deliver {
        /// Header length of the framed message.
        header_len: usize,
        /// Body length of the framed message.
        body_len: usize,
    },
    /// Splice the message body straight from the socket to a consumer fd (zero-copy), keeping only the `header_len`
    /// header bytes in the buffer.
    SpliceBody {
        /// Header length (fully buffered).
        header_len: usize,
        /// Body length to splice to `fd`.
        body_len: usize,
        /// Consumer-owned destination fd (borrowed; e.g. a pipe write end).
        fd: RawFd,
    },
}

/// The shared body of [`Framing::Need`] and [`Framing::NeedInMessage`]: an exact read of `n`, with `in_message` the
/// only difference between them.
///
/// `n` is framer-supplied - typically echoed straight off the wire - so the post-read total is capped exactly like a
/// `Complete` frame, and one verdict cannot size a recv allocation past `max_request_bytes`.
///
/// Which clock the read carries is the framer's to state and cannot be inferred here: a `Need` from an empty buffer is
/// the next message's first read for a length-prefix framer and a body continuation for one that consumed its head, and
/// the two want opposite timeouts.
fn need_step(n: usize, buffered: usize, max_request_bytes: usize, in_message: bool) -> FrameStep {
    if n == 0 {
        return FrameStep::Close(CloseReason::Malformed);
    }
    match buffered.checked_add(n) {
        Some(total) if total <= max_request_bytes => FrameStep::ReadHeader {
            want: n,
            exact: true,
            in_message,
        },
        _ => FrameStep::Close(CloseReason::TooLarge),
    }
}

/// The pump's per-verdict framing decision, factored out as a **pure** function so it can be exhaustively fuzzed
/// (`fuzz/fuzz_targets/framing_arithmetic.rs`) independently of the io_uring loop: given a framer's [`Framing`]
/// verdict, the bytes currently buffered, and the two size limits, decide what to do next -- read more, deliver, or
/// close - applying every overflow and cap guard.
///
/// The safety contract the fuzzer verifies for **every** input: a [`FrameStep::Deliver`] implies `header_len +
/// body_len` does not overflow and is `<= buffered` (so delivery's `buf[..header_len]` then `[..body_len]` slices stay
/// in bounds); a placing [`FrameStep::ReadBody`] implies `header_len <= buffered < header_len + body_len` (so the
/// placement carve cannot underflow); a [`FrameStep::SpliceBody`] implies `buffered == header_len` (the whole header,
/// and nothing past it, is buffered - the body is spliced, never sliced from `buf`) and that `header_len + body_len`
/// does not overflow. Any verdict that would breach a cap or overflow becomes [`FrameStep::Close`], never an
/// out-of-bounds action.
pub fn frame_step(
    verdict: Framing,
    buffered: usize,
    max_request_bytes: usize,
    body_placement_threshold: Option<usize>,
) -> FrameStep {
    match verdict {
        Framing::Invalid => FrameStep::Close(CloseReason::Malformed),
        Framing::Need(n) => need_step(n, buffered, max_request_bytes, false),
        // Same read; the flag is the whole difference. See `Framing::NeedInMessage`.
        Framing::NeedInMessage(n) => need_step(n, buffered, max_request_bytes, true),
        Framing::More => FrameStep::ReadHeader {
            want: RECV_CHUNK,
            exact: false,
            in_message: false,
        },
        // Same read; the flag is the whole difference. See `Framing::MoreInMessage`.
        Framing::MoreInMessage => FrameStep::ReadHeader {
            want: RECV_CHUNK,
            exact: false,
            in_message: true,
        },
        Framing::Complete { header_len, body_len } => {
            // Both lengths are framer-supplied: a sum that overflows is over any cap, and must not wrap past the
            // TooLarge guard (a u64 length prefix of `!0` would otherwise wrap to a tiny total and deliver an
            // out-of-bounds body slice).
            let Some(total) = header_len.checked_add(body_len) else {
                return FrameStep::Close(CloseReason::TooLarge);
            };
            if total == 0 {
                return FrameStep::Close(CloseReason::Malformed);
            }
            if total > max_request_bytes {
                return FrameStep::Close(CloseReason::TooLarge);
            }
            if buffered >= total {
                FrameStep::Deliver { header_len, body_len }
            } else {
                // Large bodies are *placed*: read into storage of their own, claimed from the ring's body pool where
                // the role has one (zero-copy `Body::take`). Requires the header to be fully buffered (always true for
                // `Need` framers).
                let place = buffered >= header_len && matches!(body_placement_threshold, Some(t) if body_len >= t);
                FrameStep::ReadBody {
                    want: total - buffered,
                    header_len,
                    body_len,
                    place,
                }
            }
        }
        Framing::SpliceBody {
            header_len,
            body_len,
            fd,
        } => {
            if header_len == 0 || body_len == 0 {
                // A splice needs a header (the frame that triggered it) and some body to move; an empty body would
                // splice zero bytes and misread as EOF. Use `Complete` for empty-body frames.
                return FrameStep::Close(CloseReason::Malformed);
            }
            // Only the header is buffered, so only the header is bounded by the request cap; the body is spliced
            // straight to `fd` and never enters the buffer (splicing bodies larger than `max_request_bytes` -- multi-GB
            // streams - is the whole point).
            if header_len > max_request_bytes {
                return FrameStep::Close(CloseReason::TooLarge);
            }
            // `consume` drains `frame_len().min(buffered)` and `frame_len` is a saturating_add, so an overflowing sum
            // can't misdrain - reject it anyway to keep the cursor arithmetic exact.
            if header_len.checked_add(body_len).is_none() {
                return FrameStep::Close(CloseReason::TooLarge);
            }
            // A well-formed splice framer reads its header with exact `Framing::Need`, so the whole header - and
            // nothing past it - is buffered when it returns `SpliceBody`. A `More`-style over-read leaves body bytes in
            // `buf` that can't be spliced; close rather than tear the body across buffer and socket.
            if buffered != header_len {
                return FrameStep::Close(CloseReason::Malformed);
            }
            FrameStep::SpliceBody {
                header_len,
                body_len,
                fd,
            }
        }
    }
}

/// The step [`Reactor::on_recv_complete`] hands its role wrapper: all the recv bookkeeping is core, only the
/// delivery/pump tail is role-specific.
#[derive(Clone, Copy)]
pub(crate) enum RecvStep {
    /// Nothing more to do (closed, parked, tearing down, or resubmitted).
    Done,
    /// A full message body arrived: deliver it, then pump.
    Deliver,
    /// A header completed (or a failed recv re-enters): pump.
    Pump,
}

/// The step [`Reactor::on_send_complete`] hands its role wrapper.
#[derive(Clone, Copy)]
pub(crate) enum SendStep {
    /// Nothing more to do (closed, tearing down, or re-armed).
    Done,
    /// The gather fully flushed: pump for the next request.
    Pump,
}

/// The step [`Reactor::on_splice_recv_complete`] hands its role wrapper.
#[derive(Clone, Copy)]
pub(crate) enum SpliceStep {
    /// Nothing more to do (closed, tearing down, EAGAIN-polled, or resubmitted).
    Done,
    /// The whole body spliced: pump for the next frame.
    Pump,
}

/// The verdict [`Reactor::pump_gate`] hands the role pump: whether to consult the framer this iteration or stop (any
/// close it needed it performed itself).
#[derive(Clone, Copy)]
pub(crate) enum Gate {
    /// Run the framer and enact its step.
    Proceed,
    /// Stop pumping (busy, capped, closed, or draining).
    Stop,
}

/// The step [`Reactor::enact_frame_step`] hands the role pump: `Deliver` is the only outcome that needs role code (the
/// body handler); every other framing action is enacted in core.
#[derive(Clone, Copy)]
pub(crate) enum Enacted {
    /// The step was fully enacted in core (read armed, closed, or spliced).
    Done,
    /// The whole message is buffered: the role must deliver it, then loop.
    Deliver,
}

impl<U> Reactor<U> {
    /// For a kTLS connection, whether the just-completed recv delivered a non-`application_data` record (post-handshake
    /// handshake message, KeyUpdate, alert / close_notify) - which the server closes on rather than handle. Always
    /// false for a plain connection.
    pub(crate) fn ktls_control_record(&self, slot: u32) -> bool {
        let conn = self.table.conn(slot);
        conn.is_ktls() && conn.ktls_record_type() != Some(TLS_RECORD_TYPE_DATA)
    }

    /// Start sending the queued responses if the send side is idle.
    pub(crate) fn kick_send(&mut self, slot: u32, generation: u32) -> errno::Result<()> {
        let idle = {
            let conn = self.table.conn(slot);
            !conn.sending && !conn.closing && conn.has_pending_send()
        };
        if idle {
            self.submit_send(slot, generation)
        } else {
            Ok(())
        }
    }

    /// Drive a pending flush-close (`close_on_flush`): close now if the send side is already dry, otherwise (re)start
    /// sending - `on_send` submits the teardown once the queue drains. The recv side needs no cancel here: the pump
    /// gate keeps it from re-arming, `on_recv` swallows a completion still in flight, and one that never completes (a
    /// parked idle read) is reaped by `close_conn`'s own cancel at teardown.
    pub(crate) fn drive_flush_close(&mut self, slot: u32, generation: u32) -> errno::Result<()> {
        let dry = {
            let conn = self.table.conn(slot);
            // An active file tail owes bytes even when the queue reads dry (its next chunk is still being read);
            // closing here would truncate the farewell body.
            !conn.sending && !conn.has_pending_send() && !conn.tail_active()
        };
        if dry {
            let reason = self
                .table
                .conn_mut(slot)
                .close_on_flush
                .take()
                .expect("drive_flush_close without a pending flush-close");
            return self.close_conn(slot, generation, reason);
        }
        self.kick_send(slot, generation)
    }

    /// Continue a kTLS exact recv whose completion came up short: io_uring cannot `MSG_WAITALL`-accumulate a `RECVMSG`
    /// carrying a control buffer, so the remainder is read with a fresh op. The connection's cursor was
    /// already advanced ([`crate::net::core::conn::RecvOutcome::Again`]);
    /// re-point the `msghdr` (which also resets the control buffer for the next record-type cmsg) and re-arm. Like the
    /// initial recv it carries the request clock (a continuation is mid-request), so a kTLS body that stalls after its
    /// first record segment is still reclaimed; the clock bounds inactivity between segments (a steadily-arriving body
    /// resets it). See `request_timeout`.
    pub(crate) fn resubmit_ktls_recv(&mut self, slot: u32, generation: u32, op: Op) -> errno::Result<()> {
        // The continuation re-arms off the advanced cursor with no fresh reserve, so `recv_ptr`'s SAFETY contract - the
        // offset stays within the allocation - rests on the initial arm having refused a pool buffer an exact read
        // would overrun (`submit_recv`). Checked in every build rather than asserted: what is on the other side is the
        // kernel writing past that allocation, and a `debug_assert` is compiled out of the build that ships, so the
        // case it exists for would be silent exactly where it matters. One `checked_add` and a comparison, before
        // anything is armed or counted, so the refusal needs no unwind - closing is what this reactor answers every
        // other unusable recv with.
        if !self.table.conn(slot).recv_armed_within() {
            debug_assert!(false, "kTLS continuation would arm past the recv buffer");
            return self.close_conn(slot, generation, CloseReason::RecvError(errno::Errno::EIO));
        }
        let conn = self.table.conn_mut(slot);
        conn.recving = true;
        // A continuation is an active mid-message transfer regardless of how the original read was armed (close reasons
        // depend on this).
        conn.recv_idle = false;
        conn.ops += 1;
        let want = conn.recv_want();
        let ptr = conn.recv_ptr();
        let addr = conn.arm_ktls_recv(ptr, want);
        // SECURITY: carry the request clock onto the continuation too (see `request_timeout`) - else a kTLS peer could
        // send one record then stall and pin the slot past the initial recv's timeout.
        //
        // NOTE: a continuation cancelled with partial progress completes `Again` (positive `done_io`, data record) and
        // re-arms with a FRESH clock - so a trickling kTLS slow-loris can cost one extra timeout period per fired clock
        // before the zero-progress `-ECANCELED` (or the paired short-read classification) finally closes it. Bounded,
        // and strictly better than not carrying the clock at all.
        let timeout_ts = self
            .cfg
            .request_timeout
            .is_some()
            .then_some(std::ptr::addr_of!(self.pads.request_timeout) as u64);
        {
            // Fresh clock pair for this recv (see `on_recv_clock`).
            let conn = self.table.conn_mut(slot);
            conn.recv_clock_armed = timeout_ts.is_some();
            conn.recv_clock_fired = None;
        }
        let force = self.cfg.force_async.sqe_bit(ForceAsync::RECV);
        match timeout_ts {
            None => self.stage(pack(op, slot, generation), move |sqe| {
                sqe.opcode = IORING_OP_RECVMSG;
                sqe.fd = slot as i32;
                sqe.flags = IOSQE_FIXED_FILE | force;
                sqe.addr = addr;
                sqe.op_flags = libc::MSG_WAITALL as u32;
            }),
            Some(ts) => self.stage_linked(
                pack(op, slot, generation),
                move |sqe| {
                    sqe.opcode = IORING_OP_RECVMSG;
                    sqe.fd = slot as i32;
                    sqe.flags = IOSQE_FIXED_FILE | IOSQE_IO_LINK | force;
                    sqe.addr = addr;
                    sqe.op_flags = libc::MSG_WAITALL as u32;
                },
                pack(Op::RecvClock, slot, generation),
                move |sqe| fill_link_timeout(sqe, ts),
            ),
        }
    }

    /// Submit an `IORING_OP_SPLICE` moving up to `len` body bytes from the connection's pool socket (the **fixed
    /// input**) straight to the consumer's `fd` (a regular pipe write-end - the output), zero-copy. Records the splice
    /// cursor and marks the connection `splicing`, a distinct in-flight flag from `recving`: the SQE's `fd` is the
    /// pipe, not the socket, so `close_conn`'s fd-keyed cancel can't reach it (it cancels the splice by `user_data`
    /// instead - see `submit_cancel_splice`).
    ///
    /// A socket->pipe splice, like a kTLS recv, cannot carry `MSG_WAITALL`, so a completion may be short (the socket
    /// had less buffered, or the pipe filled); `on_splice_recv` resubmits the remainder. A full pipe blocks the splice
    /// on an io-wq worker - never the ring - which is the transfer's automatic backpressure: the consumer's reader
    /// drains the pipe, TCP flow control pushes back on the sender, and the ring keeps serving other connections
    /// throughout.
    ///
    /// `first` says whether this call opens a body or continues one. Only the caller knows: a short splice and a
    /// readiness poll both resubmit through here with the remainder, and the connection flags read the same at every
    /// entry (`splicing` is cleared on each completion). It sets the receipt budget's window mark - see
    /// `ServerConfig::receipt_window_bytes`.
    pub(crate) fn submit_splice_recv(
        &mut self,
        slot: u32,
        generation: u32,
        fd: RawFd,
        len: usize,
        first: bool,
    ) -> errno::Result<()> {
        let ktls = {
            let conn = self.table.conn_mut(slot);
            conn.arm_splice(fd, len);
            conn.splicing = true;
            conn.ops += 1;
            conn.is_ktls()
        };
        // Clamp to i32::MAX: the SQE len is u32 and the CQE res an i32 (the kernel itself clamps each splice at
        // MAX_RW_COUNT), so a > 2 GiB body completes short and the resubmit carries the tail.
        let chunk = len.min(i32::MAX as usize) as u32;
        self.stage(pack(Op::SpliceRecv, slot, generation), move |sqe| {
            sqe.opcode = IORING_OP_SPLICE;
            // Output: the consumer's pipe write-end - a *regular* fd (not registered), so no `IOSQE_FIXED_FILE`.
            sqe.fd = fd;
            // Input: the connection's pool socket at `slot` - the *fixed* descriptor. `splice_fd_in` overlays
            // `file_index`; the 0-based fixed index goes here (unlike CLOSE's 1-based `file_index`), and
            // `SPLICE_F_FD_IN_FIXED` marks it registered.
            sqe.file_index = slot;
            sqe.op_flags = SPLICE_F_MOVE | SPLICE_F_FD_IN_FIXED;
            // Both endpoints are non-seekable streams: `splice_off_in` (addr) and `off_out` (off_addr2) are both -1.
            sqe.addr = u64::MAX;
            sqe.off_addr2 = u64::MAX;
            sqe.len = chunk;
        })?;
        // SECURITY: a kTLS splice BLOCKS on an io-wq worker awaiting the next TLS record - `tls_sw_splice_read` honors
        // only `SPLICE_F_NONBLOCK` (which must stay unset: it would also make a full pipe `-EAGAIN`, see the `pump`
        // fcntl guard) and, unlike `tcp_splice_read`, never the socket's own O_NONBLOCK - so the plain-TCP `-EAGAIN` ->
        // readiness-poll path (whose linked timeout carries the request clock) never runs.
        // A LINK_TIMEOUT can't cover it either: the kernel arms a linked timeout only AFTER the head op's `issue()`
        // returns, and a blocking splice's `issue()` doesn't return until the splice completes. So a stalled kTLS
        // splice would pin the slot AND an io-wq worker past every timeout. Bound it with a STANDALONE inactivity
        // watchdog (`arm_splice_deadline`) whose expiry issues an explicit `ASYNC_CANCEL` of the blocked splice - that
        // DOES signal the io-wq worker (`__io_wq_worker_cancel` -> `__set_notify_signal`), and the record wait returns
        // via `signal_pending`. Plain-TCP splices need none of this (their poll path is already clocked).
        if ktls {
            self.arm_splice_deadline(slot, generation)?;
        }
        // The total-receipt budget covers a spliced body like any other. It cannot arm itself here the way a buffered
        // message does: the only arm site is `submit_recv`, and a spliced body never enters it, so without this the one
        // clock that is not restarted by progress does not reach the framing that needs it most - both clocks above are
        // inactivity bounds that any arriving byte re-arms. Idempotent on `receipt_deadline_armed`, so the resubmit and
        // readiness-poll paths extend the message's budget rather than restarting it, and a header that already armed
        // one keeps it.
        #[cfg(feature = "net-server")]
        {
            // The mark is where this body started, so it is set once, when the body is opened. A short-splice resubmit
            // must not move it, or no expiry could tell a window's progress from a stall.
            //
            // Not "when this call armed the budget": a framer whose header takes more than one read arms it in
            // `submit_recv` (the second header read has bytes buffered, so it is not idle), leaving the mark at the
            // previous message's - zero on the connection's first - and `moved` pinned at zero for the whole body. The
            // renewal below can then never fire, which is the whole-transfer bound this window exists to remove.
            if first {
                let conn = self.table.conn_mut(slot);
                conn.receipt_window_mark = conn.splice_remaining;
            }
            self.arm_receipt_deadline(slot, generation)?;
        }
        // The receipt budget is a server-role bound, and it is `first`'s only reader.
        #[cfg(not(feature = "net-server"))]
        let _ = first;
        Ok(())
    }

    /// Arm a one-shot `POLL_ADD` for `POLLIN` on the connection's socket after a body splice returned `-EAGAIN` (the
    /// non-blocking pool socket was drained the moment the splice ran). Its completion (`on_splice_poll`) resubmits the
    /// splice. The poll rides the fixed socket fd, so `close_conn`'s fd-keyed cancel reaches it (unlike the splice,
    /// cancelled by `user_data`); it is counted as one op and marks `splice_polling` so the recv side reads busy.
    pub(crate) fn submit_splice_poll(&mut self, slot: u32, generation: u32) -> errno::Result<()> {
        let conn = self.table.conn_mut(slot);
        conn.splice_polling = true;
        conn.ops += 1;
        let fill = move |sqe: &mut IoUringSqe| {
            sqe.opcode = IORING_OP_POLL_ADD;
            sqe.fd = slot as i32;
            sqe.flags = IOSQE_FIXED_FILE;
            // `poll32_events` overlays `op_flags`; POLLERR/POLLHUP are implicit.
            sqe.op_flags = libc::POLLIN as u32;
        };
        // SECURITY: the poll is the splice's slow-loris guard. Without a bound, a peer that sends a `SpliceBody` header
        // then stalls mid-body parks this poll forever and pins the slot. Carry the request-receive clock (like a body
        // recv): each arriving segment completes the poll and re-arms it, so the timeout bounds inactivity between body
        // segments.
        let timeout_ts = self
            .cfg
            .request_timeout
            .is_some()
            .then_some(std::ptr::addr_of!(self.pads.request_timeout) as u64);
        match timeout_ts {
            None => self.stage(pack(Op::SplicePoll, slot, generation), fill),
            Some(ts) => self.stage_linked(
                pack(Op::SplicePoll, slot, generation),
                move |sqe| {
                    fill(sqe);
                    sqe.flags |= IOSQE_IO_LINK;
                },
                pack(Op::LinkTimeout, slot, generation),
                move |sqe| fill_link_timeout(sqe, ts),
            ),
        }
    }

    #[allow(clippy::too_many_arguments)] // one frame step unpacked, not an API
    pub(crate) fn submit_recv(
        &mut self,
        slot: u32,
        generation: u32,
        op: Op,
        want: usize,
        exact: bool,
        place_body: bool,
        in_message: bool,
    ) -> errno::Result<()> {
        // A connection with no buffer acquires one with the read itself: `IOSQE_BUFFER_SELECT` has the kernel pick at
        // completion, so an idle recv costs nothing until bytes actually land.
        //
        // Nothing is reserved here and nothing can be: the pick happens at completion, so every parked connection can
        // have a selecting recv armed against a pool of any size. Arming one the pool cannot cover is therefore normal,
        // not an error - `-ENOBUFS` comes back on the completion and `recv_buffer_shortage` grows and re-arms. The
        // rebalance here is the pool's shrink cadence and its response to pressure it *can* see.
        //
        // A placed body is exempt: it reads into its own allocation, so it needs no buffer and must not be given one.
        // The kernel clamps a selecting read to the buffer it picked (`io_ring_buffer_select`, `io_uring/kbuf.c`), so
        // an exact read longer than a pool buffer would complete short of what the frame declared and close the
        // connection as truncated.
        #[cfg(feature = "net-server")]
        let select = if !place_body && self.table.conn(slot).recv_needs_buffer() {
            let g = match self.recv_bufs.as_mut() {
                // An exact read larger than one pool buffer must not take one, for the reason stated just above: the
                // kernel clamps the selection and the read then completes short of what the frame declared.
                // `promote_recv_buffer` below cannot cover this - it moves bytes out of a claim the connection already
                // holds, and a connection reaches here precisely when it holds none - so the escape is to own the
                // buffer, exactly as a placed body does. Reachable from `Framing::Need(n)`, which `frame_step` admits
                // up to `max_request_bytes` and turns into an *exact* `ReadHeader`, where there is no placement to opt
                // into.
                Some(p) if exact && want > p.buf_len() => None,
                // Shrink cadence lives on the maintenance tick now, not here. This arm no longer reads the clock on
                // every selecting recv.
                Some(p) => Some(p.bgid()),
                None => None,
            };
            if g.is_none() {
                self.table.conn_mut(slot).set_recv_owned();
            }
            self.sync_recv_buf_stats();
            g
        } else {
            None
        };
        #[cfg(not(feature = "net-server"))]
        let select: Option<u16> = None;
        // A pool buffer is one fixed size and a message is not. Rather than size every buffer for the largest message
        // the server accepts, a read that would overrun the one held moves what is accumulated into owned storage and
        // gives the buffer back.
        #[cfg(feature = "net-server")]
        if !place_body {
            self.promote_recv_buffer(slot, want);
        }
        // The connection is idle - parked for the next request - when this is a header read with nothing yet
        // accumulated *and the framer has not said otherwise*. Only such reads carry the idle timeout; body and
        // mid-header continuation reads are active transfers.
        //
        // `buffered() == 0` alone cannot answer this. A streaming codec consumes each window as its own message, so
        // between windows - and after a 100-continue dance has consumed the head - the buffer is empty while the
        // request is very much in progress. `in_message` carries the framer's own verdict (`Framing::MoreInMessage`),
        // which is the only place that distinction exists.
        let idle = op == Op::RecvHeader && !in_message && self.table.conn(slot).buffered() == 0;
        // SECURITY: a message is under way, so its total-receipt budget runs from here - the one place that knows the
        // read belongs to a message already begun.
        #[cfg(feature = "net-server")]
        if !idle {
            self.arm_receipt_deadline(slot, generation)?;
        }
        // Reused storage for a placed body, claimed before the table borrow: the pool cleared it, so only capacity
        // carries over. The client role has no pool and places into fresh storage as before. Claimed at the body's real
        // size - the frame declared it - so a miss records the bytes actually needed, and held, so the licence survives
        // however many maintenance ticks a slow-link receipt spans.
        #[cfg(feature = "net-server")]
        let reuse = place_body
            .then(|| {
                let need = self.table.conn(slot).frame().1;
                self.body_pool.as_ref().map(|p| p.borrow_mut().claim_held(need))
            })
            .flatten();
        #[cfg(not(feature = "net-server"))]
        let reuse = None;
        let conn = self.table.conn_mut(slot);
        let want = if place_body {
            // Placement: the body reads into its own allocation; the exact remainder is computed from what
            // `arm_body_recv` carved.
            conn.arm_body_recv(reuse)
        } else {
            let granted = conn.arm_recv(want, exact);
            if granted < want && exact {
                // Unreachable: the promote above leaves either a claim that covers this read or no claim at all.
                // Reading less than the frame declared would deliver a short message as whole, so a promote that ever
                // fails to fire fails closed here.
                self.close_conn(slot, generation, CloseReason::TooLarge)?;
                return Ok(());
            }
            granted
        };
        conn.recving = true;
        conn.recv_idle = idle;
        conn.ops += 1;
        let ptr = conn.recv_ptr();
        // Plain connections use `RECV` (destination in the SQE, no msghdr import). kTLS connections use `RECVMSG` with
        // a control buffer so the record type can be read - a plain recv returns -EIO on any non-data record. With
        // MSG_WAITALL a plain exact read fills the whole buffer before completing (io_uring accumulates in-kernel). For
        // kTLS it
        // CANNOT: io_uring disables its WAITALL accumulation whenever the msghdr carries a control buffer (`io_recvmsg`
        // sets `min_ret` only when `msg_controllen == 0`), so a kTLS exact read completes with whatever fully-arrived
        // records the TLS layer had - `recv_result` answers `Again` and `resubmit_ktls_recv` continues the read. A
        // chunk read takes whatever is available.
        let (opcode, addr, len) = if conn.is_ktls() {
            (IORING_OP_RECVMSG, conn.arm_ktls_recv(ptr, want), 0u32)
        } else {
            (IORING_OP_RECV, ptr, want as u32)
        };
        let flags = if exact { libc::MSG_WAITALL as u32 } else { 0 };
        // A recv carries at most one linked timeout. An idle header read -- parked for the next request with nothing
        // buffered - uses the idle clock; any read for a request already in progress (a body, a `Need` header
        // remainder, or a `More` chunk scan) uses the request-receive clock.
        //
        // SECURITY: the request clock is the slow-loris guard. Without it a peer that sends a partial frame (e.g. a
        // valid length prefix) then stalls pins its pool slot forever - `idle_timeout` can't fire, the connection is no
        // longer idle - so a few such peers exhaust the pool. For an exact read (`MSG_WAITALL`) the clock bounds the
        // whole transfer; for a chunk read it bounds inactivity (each arriving byte completes the read and re-arms),
        // which still reclaims a stalled slot.
        let timeout_ts = if idle && self.cfg.idle_timeout.is_some() {
            Some(std::ptr::addr_of!(self.pads.idle_timeout) as u64)
        } else if !idle && self.cfg.request_timeout.is_some() {
            Some(std::ptr::addr_of!(self.pads.request_timeout) as u64)
        } else {
            None
        };
        {
            // Fresh clock pair for this recv (see `on_recv_clock`).
            let conn = self.table.conn_mut(slot);
            conn.recv_clock_armed = timeout_ts.is_some();
            conn.recv_clock_fired = None;
            if idle {
                // A fresh idle clock opens a new quiet interval.
                conn.served_since_idle_arm = false;
            }
        }
        let force = self.cfg.force_async.sqe_bit(ForceAsync::RECV);
        match timeout_ts {
            None => self.stage(pack(op, slot, generation), move |sqe| {
                sqe.opcode = opcode;
                sqe.fd = slot as i32;
                sqe.flags = IOSQE_FIXED_FILE | force;
                sqe.addr = addr;
                sqe.len = len;
                sqe.op_flags = flags;
                stamp_select(sqe, select);
            }),
            Some(ts) => self.stage_linked(
                pack(op, slot, generation),
                move |sqe| {
                    sqe.opcode = opcode;
                    sqe.fd = slot as i32;
                    // Link the trailing timeout to this recv.
                    sqe.flags = IOSQE_FIXED_FILE | IOSQE_IO_LINK | force;
                    sqe.addr = addr;
                    sqe.len = len;
                    sqe.op_flags = flags;
                    stamp_select(sqe, select);
                },
                pack(Op::RecvClock, slot, generation),
                move |sqe| fill_link_timeout(sqe, ts),
            ),
        }
    }

    pub(crate) fn submit_send(&mut self, slot: u32, generation: u32) -> errno::Result<()> {
        let conn = self.table.conn_mut(slot);
        conn.arm_send();
        conn.sending = true;
        conn.ops += 1;
        let single = conn.send_single();
        let ktls = conn.is_ktls();
        // SECURITY: over kTLS, a positive send completion is NOT delivery, and this reactor cannot make it one.
        //
        // `tls_sw_sendmsg` accepts bytes into records that may still sit in the layer's own `tx_list`. The teardown's
        // `SHUTDOWN(SHUT_RDWR)` is not a TLS operation - the ULP overrides `close` and `sendmsg`, never `shutdown`
        // (`net/tls/tls_main.c:949-976`) - so it sets `SEND_SHUTDOWN`, and the `CLOSE` behind it finds every remaining
        // record unsendable: `tls_sw_release_resources_tx` (`net/tls/tls_sw.c:2602`) does try `tls_tx_records` first,
        // but `tcp_sendmsg_locked` refuses a shut-down socket, so the loop below it frees them. The peer reads a clean
        // FIN and this server counts a reply. Measured at one whole 16384-byte record.
        //
        // **The obvious remedy is closed, and it is worth saying which.** What decides it is whether the `sendmsg`
        // carries `MSG_DONTWAIT`: `tls_tx_records(sk, -1)` at close replays each record's own `rec->tx_flags`, so a
        // record queued blocking would be pushed blocking. io_uring adds `MSG_DONTWAIT` whenever it issues with
        // `IO_URING_F_NONBLOCK` (`io_uring/net.c:566-567`, `:664-665`), and `IOSQE_ASYNC` does **not** take that away
        // for a socket: `io_wq_submit_work` puts the flag straight back for any pollable opcode on a pollable file
        // (`io_uring/io_uring.c:1982-1988`), and `SEND`/`SENDMSG` are both `.pollout = 1`. Measured on this kernel: a
        // forced-async `SEND` of 4 MiB into a 4 KiB sndbuf with the peer not reading returns a short count of 8064 in 5
        // ms rather than blocking. On `-EAGAIN` the same loop arms poll and returns, so the blocking retry two lines
        // further down is unreachable for a socket as well. There is no SQE flag that yields a blocking `sendmsg` here.
        //
        // What is left is a policy call the reactor cannot make for the deployment: drop the `SHUT_RDWR` for kTLS so
        // the close at least attempts the flush (partial - the records still carry `MSG_DONTWAIT`, so it pushes only
        // what the sndbuf takes at that instant, and `close` on a socket with unread receive data sends RST rather than
        // FIN), or delay the teardown after the last send by a grace period, which is a duration nothing here can
        // derive.
        let msg = conn.send_msg_ptr();
        // A one-PDU gather takes the plain `SEND` opcode (ptr/len in the SQE, no msghdr import); `SENDMSG` is reserved
        // for real multi-PDU gathers.
        // MSG_NOSIGNAL: never raise SIGPIPE - the library must not depend on the host runtime ignoring it (Rust's does;
        // an embedding might not).
        //
        // MSG_WAITALL flushes the whole gather in-kernel (one CQE per fully-sent batch, no userspace partial-send
        // loop) - but the kernel TLS sendmsg rejects MSG_WAITALL (-EOPNOTSUPP; it validates flags strictly), so kTLS
        // sends omit it and lean on `on_send`'s partial-send re-submit instead.
        let flags = if ktls {
            libc::MSG_NOSIGNAL as u32
        } else {
            (libc::MSG_WAITALL | libc::MSG_NOSIGNAL) as u32
        };
        let force = self.cfg.force_async.sqe_bit(ForceAsync::SEND);
        let fill = move |sqe: &mut IoUringSqe| {
            match single {
                Some((ptr, len)) => {
                    sqe.opcode = IORING_OP_SEND;
                    sqe.addr = ptr;
                    sqe.len = len;
                }
                None => {
                    sqe.opcode = IORING_OP_SENDMSG;
                    sqe.addr = msg;
                }
            }
            sqe.fd = slot as i32;
            sqe.flags = IOSQE_FIXED_FILE | force;
            sqe.op_flags = flags;
        };
        let send_ts = (self.cfg.send_timeout.is_some()).then_some(std::ptr::addr_of!(self.pads.send_timeout) as u64);
        match send_ts {
            None => self.stage(pack(Op::Send, slot, generation), fill),
            // Stall guard: a linked timeout cancels a send that sits with no progress for `send_timeout` (a peer that
            // stopped reading). On a cancelled partial send the CQE carries the progress made, so a slow-but-draining
            // peer resets the clock via the re-submit path.
            Some(ts) => self.stage_linked(
                pack(Op::Send, slot, generation),
                move |sqe| {
                    fill(sqe);
                    sqe.flags |= IOSQE_IO_LINK;
                },
                pack(Op::LinkTimeout, slot, generation),
                move |sqe| fill_link_timeout(sqe, ts),
            ),
        }
    }

    /// Classify a short-positive exact recv completion: `fired` is whether the recv's linked clock reported `-ETIME`. A
    /// drain/stop cancel wins first (`begin_drain`'s ASYNC_CANCEL also produces short-positive completions -- same
    /// `io_sendrecv_fail` path - but never a fired clock); a fired clock maps exactly like a zero-progress cancel;
    /// anything else is the peer's FIN mid-frame.
    pub(crate) fn short_recv_reason(&self, fired: bool, was_idle: bool) -> CloseReason {
        if self.draining || self.stopping() {
            return CloseReason::ShuttingDown;
        }
        if fired {
            return self.recv_close_reason(-libc::ECANCELED, was_idle);
        }
        CloseReason::TruncatedMessage
    }

    /// Whether a short-positive exact read continues instead of closing: its request clock fired (the peer was making
    /// progress, just not at the armed read's pace within one period), on an active transfer (the idle clock guards the
    /// keep-alive gap, not a transfer), on a reactor that is not shutting down, over plain TCP (a kTLS short is `Again`
    /// or a control record, classified before this is asked).
    fn exact_partial_continues(&self, slot: u32, fired: bool, was_idle: bool) -> bool {
        fired && !was_idle && !self.draining && !self.stopping() && !self.table.conn(slot).is_ktls()
    }

    /// Re-arm a plain-TCP exact read whose request clock cancelled it with partial progress (the cursor already
    /// advanced past what landed, [`Connection::advance_exact_partial`]). io_uring accumulates a plain `MSG_WAITALL`
    /// recv itself, so unlike kTLS a short completion here is never healthy - this continuation exists only for the
    /// clock-cancelled case. Closing there imposes a throughput floor of `recv_want / request_timeout` on every exact
    /// read: a peer pacing a streamed window slower than that dies mid-body, with the window's consumed bytes
    /// unrecoverable.
    ///
    /// Like the kTLS continuation it re-arms with a FRESH request clock, so the clock bounds progress-per-period rather
    /// than the whole transfer: a trickling slow-loris costs one timeout period per fired clock, bounded by the armed
    /// read's length (for a header, by `max_request_bytes`) - the same trade `resubmit_ktls_recv` documents. A period
    /// with NO progress still closes (the zero-progress `-ECANCELED` never reaches here), and an idle partial still
    /// closes.
    ///
    /// [`Connection::advance_exact_partial`]: crate::net::core::conn::Connection::advance_exact_partial
    pub(crate) fn resubmit_exact_recv(&mut self, slot: u32, generation: u32, op: Op) -> errno::Result<()> {
        // Same guard as the kTLS continuation, for the same reason: the re-arm points `recv_ptr` past the advanced
        // cursor with no fresh reserve, and what is on the other side of a miscount is the kernel writing past the
        // allocation.
        if !self.table.conn(slot).recv_armed_within() {
            debug_assert!(false, "exact continuation would arm past the recv buffer");
            return self.close_conn(slot, generation, CloseReason::RecvError(errno::Errno::EIO));
        }
        let conn = self.table.conn_mut(slot);
        conn.recving = true;
        // An active mid-message transfer regardless of how the original read was armed (close reasons depend on this).
        conn.recv_idle = false;
        conn.ops += 1;
        let want = conn.recv_want();
        let addr = conn.recv_ptr();
        // No buffer select: the partial bytes already landed in the storage the connection now holds (the claim the
        // short completion adopted, its owned buffer, or a placed body), and the remainder must land right behind them.
        let timeout_ts = self
            .cfg
            .request_timeout
            .is_some()
            .then_some(std::ptr::addr_of!(self.pads.request_timeout) as u64);
        {
            // Fresh clock pair for this recv (see `on_recv_clock`).
            let conn = self.table.conn_mut(slot);
            conn.recv_clock_armed = timeout_ts.is_some();
            conn.recv_clock_fired = None;
        }
        let force = self.cfg.force_async.sqe_bit(ForceAsync::RECV);
        match timeout_ts {
            None => self.stage(pack(op, slot, generation), move |sqe| {
                sqe.opcode = IORING_OP_RECV;
                sqe.fd = slot as i32;
                sqe.flags = IOSQE_FIXED_FILE | force;
                sqe.addr = addr;
                sqe.len = want as u32;
                sqe.op_flags = libc::MSG_WAITALL as u32;
            }),
            Some(ts) => self.stage_linked(
                pack(op, slot, generation),
                move |sqe| {
                    sqe.opcode = IORING_OP_RECV;
                    sqe.fd = slot as i32;
                    sqe.flags = IOSQE_FIXED_FILE | IOSQE_IO_LINK | force;
                    sqe.addr = addr;
                    sqe.len = want as u32;
                    sqe.op_flags = libc::MSG_WAITALL as u32;
                },
                pack(Op::RecvClock, slot, generation),
                move |sqe| fill_link_timeout(sqe, ts),
            ),
        }
    }

    /// A recv's linked idle/request clock reaped (`Op::RecvClock`): `-ETIME` when it fired (and cancelled its recv),
    /// `-ECANCELED` when the recv completed first. Not counted in `conn.ops` (exactly like the generic `LinkTimeout`
    /// CQEs this op split from). Resolves a parked short-positive recv (`recv_close_stash`) or records the outcome for
    /// a recv CQE later in this batch; on an already-closing (or recycled) slot it is inert.
    pub(crate) fn on_recv_clock(&mut self, slot: u32, generation: u32, res: i32) -> errno::Result<()> {
        if !self.table.slot_matches_cqe(slot, generation) {
            return Ok(());
        }
        let fired = res == -libc::ETIME;
        let (was_idle, op) = {
            let conn = self.table.conn_mut(slot);
            if conn.teardown_owns_slot() {
                // Torn down by another path while the stash waited (the close already ran with that path's reason), or
                // a flush-close arrived meanwhile - its farewell flush owns the teardown, and a recv-side reason must
                // not preempt it.
                conn.recv_close_stash = None;
                return Ok(());
            }
            match conn.recv_close_stash.take() {
                Some(stash) => stash,
                None => {
                    // No recv is parked on this clock. Record ONLY a genuine expiry, for a recv still in flight to read
                    // when it completes short. A `-ECANCELED` here is never the current recv timing out - it is the
                    // recv having already won its link (handled in `on_recv`), or a STALE clock
                    // from a prior kTLS `Again` continuation whose recv won;
                    // recording its `false` would clobber the fresh recv's state and misclassify a real timeout as a
                    // truncation.
                    //
                    // A stale `-ETIME` cannot be told apart: a clock that fires in the same instant its recv completes
                    // in full posts `-ETIME` with nothing cancelled (`io_link_timeout_fn` finds `timeout->head` NULL
                    // and `io_req_task_link_timeout` completes `-ETIME`, io_uring/timeout.c:340-343), and by the time
                    // it is reaped the next recv - armed while ITS recv's CQE was dispatched earlier in this same
                    // batch - owns these fields. The pollution is bounded: it misreads only a short-POSITIVE on that
                    // successor (an EOF partial resumes once and re-completes empty into the same truncation close; a
                    // real expiry records true twice), never a zero-progress close, and the next arm resets it. The
                    // fired clock's failed cancel can likewise surface `ret` instead of `-ETIME` (`ret ?: -ETIME`,
                    // timeout.c:337) and read as "recv won": that race needs the recv already completing on its own, so
                    // the truncation verdict it produces is the truth.
                    if fired {
                        conn.recv_clock_fired = Some(true);
                    }
                    return Ok(());
                }
            }
        };
        // The parked short-positive recv resolves now, and never re-pumps (see the `on_recv` `res > 0` branch): a
        // request-clock expiry on an active transfer resumes the read - the cursor advanced before the stash - and
        // every other outcome closes.
        if self.exact_partial_continues(slot, fired, was_idle) {
            return self.resubmit_exact_recv(slot, generation, op);
        }
        let reason = self.short_recv_reason(fired, was_idle);
        self.close_conn(slot, generation, reason)
    }

    /// The core of a recv completion (`RecvHeader`/`RecvBody`): all the bookkeeping - the stat, the op-count drain, the
    /// flush-close swallow, the `recv_result` trichotomy (failed/kTLS-again/complete), the short-positive
    /// stash-vs-close, the kTLS control-record close - returning the [`RecvStep`] its role wrapper enacts
    /// (`Deliver`/`Pump` re-enter role code; `Done` is self-contained). The two recv kinds share the whole skeleton and
    /// differ only in idle eligibility and the delivery tail.
    /// Hand back a file-body buffer whose pump read will not queue it.
    ///
    /// Owed on **every** exit that saw `IORING_CQE_F_BUFFER`: the kernel puts the kbuf and advances its head with no
    /// guard on the result (`io_req_rw_complete`, `io_uring/rw.c:591`), so a failed, truncated or stale-slot completion
    /// has taken its descriptor off the ring exactly like a served one. An exit that skips this strands the id -
    /// userspace still counts it posted, so it is neither reissued nor replaced, the kernel will never offer it again,
    /// and the ring loses a buffer per strand while `recv_bufs_lent` stays innocently at zero.
    ///
    /// Lend-then-release through the verified pick ([`BufPool::take_lent`](crate::uring::bufring::BufPool::take_lent)):
    /// `release` is the only repost and requires the loan recorded first, and a bid the pool does not hold `Posted` is
    /// dropped rather than recorded, since nothing of the pool's is behind it.
    #[cfg(all(feature = "net-server", feature = "uring-fs"))]
    pub(crate) fn requeue_body_bid(&mut self, bid: Option<u16>) {
        let Some(bid) = bid else { return };
        if let Some(pool) = self.body_bufs.as_mut() {
            // The pick is verified before the loan is recorded: an id the pool does not hold `Posted` is a descriptor
            // desync with nothing of the pool's behind it, so there is nothing to hand back - and a blind release would
            // retire a loan some other op still holds, reposting a buffer out from under it.
            if pool.take_lent(bid).is_some() {
                pool.release(bid);
            }
        }
        self.sync_recv_buf_stats();
    }

    /// Answer a recv that found the pool dry (`-ENOBUFS`). Returns whether the caller should re-pump now; `false` means
    /// the read is parked on a `RecvRetry` timer and the pump is that timer's to run.
    ///
    /// The kernel picks a provided buffer at completion, so a shortage cannot be seen at submit and this is the only
    /// place it is reported. Growing here sizes the pool to concurrent *arrivals*, which is the quantity that actually
    /// bounds it - and bounds it at `pool_size` buffers, no worse than the per-connection buffer the pool replaced.
    ///
    /// Growth failing means the ring is at its registered bound with every buffer lent - only leases held past their
    /// message can get there, so it is sustained pressure, not sizing. `recv_shortage_retry` picks the answer: park the
    /// read and retry on a timer (backpressure - the unread socket fills and TCP slows the peer, while pool memory
    /// holds at its bound), or drop the connection back to owning its buffer (progress through the spike, paid in
    /// unpooled allocation). Either way the read cannot come back `-ENOBUFS` unanswered: the owned fallback cannot want
    /// a pool buffer at all, and a parked retry that finds the pool still dry parks again.
    ///
    /// One live timer per connection (`recv_retry_armed`): a park re-entered while the timer is pending - another path
    /// pumped the connection into the still-dry pool - keeps the pending timer rather than stacking a second.
    #[cfg(feature = "net-server")]
    pub(crate) fn recv_buffer_shortage(&mut self, slot: u32, generation: u32) -> errno::Result<bool> {
        stat!(self, buf_shortages);
        // Nothing to subtract: a recv picks its buffer when data arrives, so the pool's free count is already what the
        // kernel sees.
        let grew = self.recv_bufs.as_mut().is_some_and(|p| p.grow(0));
        if grew {
            self.sync_recv_buf_stats();
            return Ok(true);
        }
        if self.recv_bufs.is_some() && self.cfg.recv_shortage_retry.is_some() {
            // The pool guard is belt-and-braces: only a buffer-select recv can complete `-ENOBUFS`, and only a pooled
            // server arms one. It keeps the contract literal - parking waits for POOL buffers to come home, so a
            // shortage with no pool behind it (whatever produced it) takes the owned fallback below, which needs
            // nothing returned to it.
            self.sync_recv_buf_stats();
            stat!(self, recv_shortage_parks);
            let conn = self.table.conn_mut(slot);
            if conn.recv_retry_armed {
                return Ok(false);
            }
            conn.recv_retry_armed = true;
            let ts = std::ptr::addr_of!(self.pads.recv_retry) as u64;
            self.stage(pack(Op::RecvRetry, slot, generation), move |sqe| {
                sqe.opcode = IORING_OP_TIMEOUT;
                sqe.addr = ts;
                sqe.len = 1; // exactly one timespec, per the kernel
            })?;
            return Ok(false);
        }
        self.table.conn_mut(slot).set_recv_owned();
        self.sync_recv_buf_stats();
        Ok(true)
    }

    /// Whether a connection other than `slot` is currently splicing a body to `fd` - the destination-sharing refusal
    /// ([`CloseReason::SpliceFdInUse`]).
    ///
    /// `splice_fd` is only meaningful while one of the two in-flight marks is set: it keeps its last value after a body
    /// finishes, and a connection that has never spliced holds `-1`.
    ///
    /// Every state that owns a `Connection`, not just `Serving`. A body in flight is what makes the destination unsafe
    /// to share, and the cost of missing one is two bodies interleaved on the same pipe - so the scan is deliberately
    /// wider than the states that can reach it today.
    pub(crate) fn splice_fd_in_use(&self, slot: u32, fd: RawFd) -> bool {
        use crate::net::core::table::SlotState;
        self.table.iter().any(|(i, e)| {
            if i == slot {
                return false;
            }
            let (SlotState::Serving(c) | SlotState::Detaching(c) | SlotState::Detached(c)) = &e.state else {
                return false;
            };
            (c.splicing || c.splice_polling) && c.splice_fd == fd
        })
    }

    /// Hand back a pool buffer the next read has outgrown, so the read can be armed against storage that fits.
    #[cfg(feature = "net-server")]
    pub(crate) fn promote_recv_buffer(&mut self, slot: u32, want: usize) {
        let at = self.table.conn(slot).buffered();
        // Lazy: only a promote that actually fires claims reused storage, because a claim is a demand signal the pool
        // sizes itself by. Sized at what the promoted read needs, and held, so the licence rides the storage rather
        // than one observation window.
        let pool = self.body_pool.as_ref();
        let seed = || pool.map(|p| p.borrow_mut().claim_held(at.saturating_add(want)));
        let Some(claim) = self.table.conn_mut(slot).promote_recv_buf(at, want, seed) else {
            return;
        };
        if let Some(pool) = self.recv_bufs.as_mut() {
            pool.release(claim.bid);
        }
        self.sync_recv_buf_stats();
    }

    /// Republish the pool gauges. Called wherever the pool's lend count or group count can have moved - the numbers are
    /// cheap (a sum over a handful of groups) and a gauge that is only mostly current is worse than none, since the
    /// property it reports is "settles to zero".
    #[cfg(feature = "net-server")]
    pub(crate) fn sync_recv_buf_stats(&self) {
        #[cfg_attr(not(all(feature = "net-server", feature = "uring-fs")), allow(unused_mut))]
        let (mut lent, mut total) = match self.recv_bufs.as_ref() {
            Some(p) => (u64::from(p.lent()), u64::from(p.allocated())),
            None => (0, 0),
        };
        // Both pools report as one figure: an operator cares how much buffer memory the ring holds, not which group it
        // sits in.
        #[cfg(all(feature = "net-server", feature = "uring-fs"))]
        if let Some(p) = self.body_bufs.as_ref() {
            lent += u64::from(p.lent());
            total += u64::from(p.allocated());
        }
        self.stats
            .recv_bufs_lent
            .store(lent, std::sync::atomic::Ordering::Relaxed);
        self.stats
            .recv_bufs_total
            .store(total, std::sync::atomic::Ordering::Relaxed);
    }

    /// Hand a connection's recv buffer back once nothing is buffered.
    ///
    /// Called after every consume: the point of the pool is that a keep-alive connection waiting for its next request
    /// holds no buffer, and this is where that happens.
    #[cfg(feature = "net-server")]
    pub(crate) fn release_recv_buffer(&mut self, slot: u32) {
        let (claim, surplus) = self.table.conn_mut(slot).release_recv_buf();
        if let Some(pool) = self.body_pool.as_ref() {
            // A delivered placed body's licence is potted by the delivery itself, before its handler runs
            // (`deliver_one`). Promoted storage comes home with the message that outgrew the pool buffer - licence
            // attached - and the next promotion anywhere on the ring reuses it.
            if let Some((v, ticket)) = surplus {
                pool.borrow_mut().give_held(v, ticket);
            }
        }
        let Some(claim) = claim else {
            return;
        };
        if let Some(pool) = self.recv_bufs.as_mut() {
            pool.release(claim.bid);
        }
        self.sync_recv_buf_stats();
    }

    /// Adopt the pool buffer a completion selected, if it carried one.
    ///
    /// `IORING_CQE_F_BUFFER` is the whole rule for whether a buffer was taken: an op that failed before selecting one -
    /// `-ENOBUFS` above all
    /// - carries nothing and owes nothing back.
    ///
    /// `false` means the completion is unusable: it names a buffer this reactor cannot vouch for (a descriptor desync,
    /// or a flag with no pool behind it), so its bytes cannot be located and the read it answered must fail - the
    /// caller closes the connection rather than framing from a buffer that was never installed.
    #[cfg(feature = "net-server")]
    pub(crate) fn adopt_recv_buffer(&mut self, slot: u32, generation: u32, cqe_flags: u32) -> bool {
        if cqe_flags & IORING_CQE_F_BUFFER == 0 {
            return true;
        }
        let bid = (cqe_flags >> IORING_CQE_BUFFER_SHIFT) as u16;
        let Some(pool) = self.recv_bufs.as_mut() else {
            return false;
        };
        // The verified pick: `Posted`, storage behind it, loan recorded. Refused for an id the pool never posted or
        // already lent - a userspace/kernel descriptor desync. There is nothing to strand *or* return on that path: the
        // storage the completion names is not this pool's, and "handing it back" through the state machine would either
        // abort (the id is not lent) or retire a loan some other op still holds.
        let Some((ptr, cap)) = pool.take_lent(bid) else {
            return false;
        };
        // A guard, not a handled case: a slot is freed only once nothing is in flight on it, so a recv completion
        // should never outlive its connection. It is here because the cost of being wrong is a panic (`conn_mut` on a
        // slot that is not serving) or a buffer installed on whoever holds the slot now, and because the buffer is owed
        // back either way - `on_recv_complete` makes the same check a moment later and by then it would be too late to
        // return it.
        if !self.table.slot_matches_cqe(slot, generation) {
            pool.release(bid);
            self.sync_recv_buf_stats();
            return true;
        }
        self.sync_recv_buf_stats();
        self.table
            .conn_mut(slot)
            .install_recv_buf(crate::net::core::conn::RecvClaim { bid, ptr, cap });
        true
    }
}

#[cfg(all(test, not(loom)))]
mod tests;

mod clocks;

mod completions;
