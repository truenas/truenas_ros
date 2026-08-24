//! The core half of the per-connection request data plane: recv/send
//! submission, the send-kick and flush-close drivers, the kTLS recv
//! continuation, the body-splice submit/poll/deadline helpers, and the two
//! pure recv-classification helpers. No consumer code runs here (the framer
//! and body handler are role state), so this is fully core.

use super::Reactor;
use crate::errno::{self, Errno};
use crate::net::core::conn::{Op, RecvOutcome, pack};
use crate::net::core::handles::stat;
use crate::net::core::protocol::{CloseReason, Framing};
#[cfg(feature = "net-server")]
use crate::uring::bufring::BufPool;
use crate::uring::sys::*;
use std::os::fd::RawFd;

/// Bytes to request per chunked (`Framing::More`) recv.
const RECV_CHUNK: usize = 4096;

/// Point a staged recv at a provided-buffer group, if one was chosen.
///
/// `buf_index` is the union field the kernel reads as `buf_group`; the SQE's
/// address is ignored once the flag is set, since the kernel supplies the
/// buffer.
#[cfg(feature = "net-server")]
fn stamp_select(sqe: &mut IoUringSqe, select: Option<u16>) {
    if let Some(bgid) = select {
        sqe.flags |= IOSQE_BUFFER_SELECT;
        sqe.buf_index = bgid;
    }
}

/// Without the server role nothing registers a buffer ring, so `select` is
/// always `None`.
#[cfg(not(feature = "net-server"))]
fn stamp_select(_sqe: &mut IoUringSqe, _select: Option<u16>) {}

/// Working size of a pooled recv buffer, before the scanning read's slack.
///
/// A free parameter, not a derived bound: a message that outgrows its buffer
/// promotes to owned storage (`RecvBuf::promote_for`) rather than being
/// refused, so this trades one bounded copy on outsized messages against
/// holding a large buffer per arrival on all of them.
///
/// **It has to cover a streamed body's window, or the pool is decorative.**
/// `http::framer::STREAM_WINDOW` is 128 KiB and
/// `body_placement_threshold` defaults to 64 KiB, so a window sits above
/// the placement threshold: a buffer that could not hold one would send
/// every window off to its own allocation and the pool would serve request
/// heads and nothing that carries data. At 256 KiB a window plus its chunk
/// header plus a pipelined remainder stay in the buffer, and the upload
/// path allocates nothing per window.
///
/// It also clears the 16 KiB TLS record size kTLS zero-copy needs
/// (`TLS_MAX_PAYLOAD_SIZE`, `include/net/tls.h`) many times over.
#[cfg(feature = "net-server")]
const RECV_POOL_BUF: usize = 256 * 1024;

/// How large a pooled recv buffer is.
///
/// The `RECV_CHUNK` term is slack, not rounding: `pump_gate` closes a
/// connection only *above* `max_request_bytes`, so a scanning
/// (`Framing::More`) read can be armed at that offset and still ask for
/// `RECV_CHUNK` more. Including it means a server whose cap already sits
/// below the working size gets a buffer no legal read can overrun, so the
/// promote path never fires there.
#[cfg(feature = "net-server")]
pub(crate) fn recv_pool_buf_len(max_request_bytes: usize) -> usize {
    RECV_POOL_BUF
        .min(max_request_bytes)
        .saturating_add(RECV_CHUNK)
}

/// The action the pump takes for one framer [`Framing`] verdict - the output of
/// [`frame_step`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameStep {
    /// Close the connection (malformed frame, or one over a size cap).
    Close(CloseReason),
    /// Read `want` more header bytes - `exact` is `MSG_WAITALL`, otherwise a
    /// chunk scan for a delimiter.
    ReadHeader {
        /// Bytes to read next.
        want: usize,
        /// `MSG_WAITALL` (exact count) vs a chunk read.
        exact: bool,
    },
    /// Read the message body: `want` more bytes (exact), recording the
    /// `header_len`/`body_len` split; `place` reads into an own allocation.
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
    /// Splice the message body straight from the socket to a consumer fd
    /// (zero-copy), keeping only the `header_len` header bytes in the buffer.
    SpliceBody {
        /// Header length (fully buffered).
        header_len: usize,
        /// Body length to splice to `fd`.
        body_len: usize,
        /// Consumer-owned destination fd (borrowed; e.g. a pipe write end).
        fd: RawFd,
    },
}

/// The pump's per-verdict framing decision, factored out as a **pure** function
/// so it can be exhaustively fuzzed (`fuzz/fuzz_targets/framing_arithmetic.rs`)
/// independently of the io_uring loop: given a framer's [`Framing`] verdict, the
/// bytes currently buffered, and the two size limits, decide what to do next --
/// read more, deliver, or close - applying every overflow and cap guard.
///
/// The safety contract the fuzzer verifies for **every** input: a
/// [`FrameStep::Deliver`] implies `header_len + body_len` does not overflow and
/// is `<= buffered` (so delivery's `buf[..header_len]` then `[..body_len]`
/// slices stay in bounds); a placing [`FrameStep::ReadBody`] implies
/// `header_len <= buffered < header_len + body_len` (so the placement carve
/// cannot underflow); a [`FrameStep::SpliceBody`] implies `buffered ==
/// header_len` (the whole header, and nothing past it, is buffered - the body
/// is spliced, never sliced from `buf`) and that `header_len + body_len` does
/// not overflow. Any verdict that would breach a cap or overflow becomes
/// [`FrameStep::Close`], never an out-of-bounds action.
pub fn frame_step(
    verdict: Framing,
    buffered: usize,
    max_request_bytes: usize,
    body_placement_threshold: Option<usize>,
) -> FrameStep {
    match verdict {
        Framing::Invalid => FrameStep::Close(CloseReason::Malformed),
        Framing::Need(n) => {
            if n == 0 {
                return FrameStep::Close(CloseReason::Malformed);
            }
            // `n` is framer-supplied (typically echoed straight off the wire):
            // cap the post-read total exactly like a `Complete` frame, so one
            // verdict can't size a recv allocation past `max_request_bytes`.
            match buffered.checked_add(n) {
                Some(total) if total <= max_request_bytes => {
                    FrameStep::ReadHeader {
                        want: n,
                        exact: true,
                    }
                }
                _ => FrameStep::Close(CloseReason::TooLarge),
            }
        }
        Framing::More => FrameStep::ReadHeader {
            want: RECV_CHUNK,
            exact: false,
        },
        Framing::Complete {
            header_len,
            body_len,
        } => {
            // Both lengths are framer-supplied: a sum that overflows is over any
            // cap, and must not wrap past the TooLarge guard (a u64 length
            // prefix of `!0` would otherwise wrap to a tiny total and deliver an
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
                FrameStep::Deliver {
                    header_len,
                    body_len,
                }
            } else {
                // Large bodies are *placed*: read into their own allocation
                // (zero-copy `Body::take`). Requires the header to be fully
                // buffered (always true for `Need` framers).
                let place = buffered >= header_len
                    && matches!(body_placement_threshold, Some(t) if body_len >= t);
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
                // A splice needs a header (the frame that triggered it) and
                // some body to move; an empty body would splice zero bytes and
                // misread as EOF. Use `Complete` for empty-body frames.
                return FrameStep::Close(CloseReason::Malformed);
            }
            // Only the header is buffered, so only the header is bounded by the
            // request cap; the body is spliced straight to `fd` and never
            // enters the buffer (splicing bodies larger than `max_request_bytes`
            // -- multi-GB streams - is the whole point).
            if header_len > max_request_bytes {
                return FrameStep::Close(CloseReason::TooLarge);
            }
            // `consume` drains `frame_len().min(buffered)` and `frame_len` is a
            // saturating_add, so an overflowing sum can't misdrain - reject it
            // anyway to keep the cursor arithmetic exact.
            if header_len.checked_add(body_len).is_none() {
                return FrameStep::Close(CloseReason::TooLarge);
            }
            // A well-formed splice framer reads its header with exact
            // `Framing::Need`, so the whole header - and nothing past it - is
            // buffered when it returns `SpliceBody`. A `More`-style over-read
            // leaves body bytes in `buf` that can't be spliced; close rather
            // than tear the body across buffer and socket.
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

/// The step [`Reactor::on_recv_complete`] hands its role wrapper: all the recv
/// bookkeeping is core, only the delivery/pump tail is role-specific.
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

/// The verdict [`Reactor::pump_gate`] hands the role pump: whether to consult
/// the framer this iteration or stop (any close it needed it performed itself).
#[derive(Clone, Copy)]
pub(crate) enum Gate {
    /// Run the framer and enact its step.
    Proceed,
    /// Stop pumping (busy, capped, closed, or draining).
    Stop,
}

/// The step [`Reactor::enact_frame_step`] hands the role pump: `Deliver` is the
/// only outcome that needs role code (the body handler); every other framing
/// action is enacted in core.
#[derive(Clone, Copy)]
pub(crate) enum Enacted {
    /// The step was fully enacted in core (read armed, closed, or spliced).
    Done,
    /// The whole message is buffered: the role must deliver it, then loop.
    Deliver,
}

impl<U> Reactor<U> {
    /// For a kTLS connection, whether the just-completed recv delivered a
    /// non-`application_data` record (post-handshake handshake message,
    /// KeyUpdate, alert / close_notify) - which the server closes on rather
    /// than handle. Always false for a plain connection.
    pub(crate) fn ktls_control_record(&self, slot: u32) -> bool {
        let conn = self.table.conn(slot);
        conn.is_ktls() && conn.ktls_record_type() != Some(TLS_RECORD_TYPE_DATA)
    }

    /// Start sending the queued responses if the send side is idle.
    pub(crate) fn kick_send(
        &mut self,
        slot: u32,
        generation: u32,
    ) -> errno::Result<()> {
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

    /// Drive a pending flush-close (`close_on_flush`): close now if the send
    /// side is already dry, otherwise (re)start sending - `on_send` submits
    /// the teardown once the queue drains. The recv side needs no cancel
    /// here: the pump gate keeps it from re-arming, `on_recv` swallows a
    /// completion still in flight, and one that never completes (a parked
    /// idle read) is reaped by `close_conn`'s own cancel at teardown.
    pub(crate) fn drive_flush_close(
        &mut self,
        slot: u32,
        generation: u32,
    ) -> errno::Result<()> {
        let dry = {
            let conn = self.table.conn(slot);
            // An active file tail owes bytes even when the queue reads dry
            // (its next chunk is still being read); closing here would
            // truncate the farewell body.
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

    /// Continue a kTLS exact recv whose completion came up short: io_uring
    /// cannot `MSG_WAITALL`-accumulate a `RECVMSG` carrying a control buffer,
    /// so the remainder is read with a fresh op. The connection's cursor was
    /// already advanced ([`crate::net::core::conn::RecvOutcome::Again`]);
    /// re-point the `msghdr` (which also resets the control buffer for the next
    /// record-type cmsg) and re-arm. Like the initial recv it carries the
    /// request clock (a continuation is mid-request), so a kTLS body that
    /// stalls after its first record segment is still reclaimed; the clock
    /// bounds inactivity between segments (a steadily-arriving body resets it).
    /// See `request_timeout`.
    pub(crate) fn resubmit_ktls_recv(
        &mut self,
        slot: u32,
        generation: u32,
        op: Op,
    ) -> errno::Result<()> {
        let conn = self.table.conn_mut(slot);
        conn.recving = true;
        // A continuation is an active mid-message transfer regardless of how
        // the original read was armed (close reasons depend on this).
        conn.recv_idle = false;
        conn.ops += 1;
        let want = conn.recv_want();
        let ptr = conn.recv_ptr();
        let addr = conn.arm_ktls_recv(ptr, want);
        // SECURITY: carry the request clock onto the continuation too (see
        // `request_timeout`) - else a kTLS peer could send one record then
        // stall and pin the slot past the initial recv's timeout.
        //
        // NOTE: a continuation cancelled with partial progress completes
        // `Again` (positive `done_io`, data record) and re-arms with a FRESH
        // clock - so a trickling kTLS slow-loris can cost one extra timeout
        // period per fired clock before the zero-progress `-ECANCELED` (or
        // the paired short-read classification) finally closes it. Bounded,
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
        match timeout_ts {
            None => self.stage(pack(op, slot, generation), move |sqe| {
                sqe.opcode = IORING_OP_RECVMSG;
                sqe.fd = slot as i32;
                sqe.flags = IOSQE_FIXED_FILE;
                sqe.addr = addr;
                sqe.op_flags = libc::MSG_WAITALL as u32;
            }),
            Some(ts) => self.stage_linked(
                pack(op, slot, generation),
                move |sqe| {
                    sqe.opcode = IORING_OP_RECVMSG;
                    sqe.fd = slot as i32;
                    sqe.flags = IOSQE_FIXED_FILE | IOSQE_IO_LINK;
                    sqe.addr = addr;
                    sqe.op_flags = libc::MSG_WAITALL as u32;
                },
                pack(Op::RecvClock, slot, generation),
                move |sqe| {
                    sqe.opcode = IORING_OP_LINK_TIMEOUT;
                    sqe.fd = -1;
                    sqe.addr = ts;
                    sqe.len = 1; // exactly one timespec, per the kernel
                },
            ),
        }
    }

    /// Submit an `IORING_OP_SPLICE` moving up to `len` body bytes from the
    /// connection's pool socket (the **fixed input**) straight to the
    /// consumer's `fd` (a regular pipe write-end - the output), zero-copy.
    /// Records the splice cursor and marks the connection `splicing`, a
    /// distinct in-flight flag from `recving`: the SQE's `fd` is the pipe, not
    /// the socket, so `close_conn`'s fd-keyed cancel can't reach it (it cancels
    /// the splice by `user_data` instead - see `submit_cancel_splice`).
    ///
    /// A socket->pipe splice, like a kTLS recv, cannot carry `MSG_WAITALL`, so
    /// a completion may be short (the socket had less buffered, or the pipe
    /// filled); `on_splice_recv` resubmits the remainder. A full pipe blocks
    /// the splice on an io-wq worker - never the ring - which is the transfer's
    /// automatic backpressure: the consumer's reader drains the pipe, TCP flow
    /// control pushes back on the sender, and the ring keeps serving other
    /// connections throughout.
    pub(crate) fn submit_splice_recv(
        &mut self,
        slot: u32,
        generation: u32,
        fd: RawFd,
        len: usize,
    ) -> errno::Result<()> {
        let ktls = {
            let conn = self.table.conn_mut(slot);
            conn.arm_splice(fd, len);
            conn.splicing = true;
            conn.ops += 1;
            conn.is_ktls()
        };
        // Clamp to i32::MAX: the SQE len is u32 and the CQE res an i32 (the
        // kernel itself clamps each splice at MAX_RW_COUNT), so a > 2 GiB body
        // completes short and the resubmit carries the tail.
        let chunk = len.min(i32::MAX as usize) as u32;
        self.stage(pack(Op::SpliceRecv, slot, generation), move |sqe| {
            sqe.opcode = IORING_OP_SPLICE;
            // Output: the consumer's pipe write-end - a *regular* fd (not
            // registered), so no `IOSQE_FIXED_FILE`.
            sqe.fd = fd;
            // Input: the connection's pool socket at `slot` - the *fixed*
            // descriptor. `splice_fd_in` overlays `file_index`; the 0-based
            // fixed index goes here (unlike CLOSE's 1-based `file_index`), and
            // `SPLICE_F_FD_IN_FIXED` marks it registered.
            sqe.file_index = slot;
            sqe.op_flags = SPLICE_F_MOVE | SPLICE_F_FD_IN_FIXED;
            // Both endpoints are non-seekable streams: `splice_off_in` (addr)
            // and `off_out` (off_addr2) are both -1.
            sqe.addr = u64::MAX;
            sqe.off_addr2 = u64::MAX;
            sqe.len = chunk;
        })?;
        // SECURITY: a kTLS splice BLOCKS on an io-wq worker awaiting the next
        // TLS record - `tls_sw_splice_read` honors only `SPLICE_F_NONBLOCK`
        // (which must stay unset: it would also make a full pipe `-EAGAIN`,
        // see the `pump` fcntl guard) and, unlike `tcp_splice_read`, never the
        // socket's own O_NONBLOCK - so the plain-TCP `-EAGAIN` -> readiness-poll
        // path (whose linked timeout carries the request clock) never runs.
        // A LINK_TIMEOUT can't cover it either: the kernel arms a linked
        // timeout only AFTER the head op's `issue()` returns, and a blocking
        // splice's `issue()` doesn't return until the splice completes. So a
        // stalled kTLS splice would pin the slot AND an io-wq worker past
        // every timeout. Bound it with a STANDALONE inactivity watchdog
        // (`arm_splice_deadline`) whose expiry issues an explicit
        // `ASYNC_CANCEL` of the blocked splice - that DOES signal the io-wq
        // worker (`__io_wq_worker_cancel` -> `__set_notify_signal`), and the
        // record wait returns via `signal_pending`. Plain-TCP splices need
        // none of this (their poll path is already clocked).
        if ktls {
            self.arm_splice_deadline(slot, generation)?;
        }
        Ok(())
    }

    /// Arm the standalone kTLS-splice inactivity watchdog: a single `TIMEOUT`
    /// per connection (the `splice_deadline_armed` flag makes it idempotent --
    /// at most one is ever in flight, which is what keeps a stale expiry from
    /// ever aliasing a later body's splice). On expiry `on_splice_deadline`
    /// re-arms if the body made progress, or cancels the stalled splice. Keyed
    /// `(slot, generation)` so a recycled slot's expiry is inert. No-op unless
    /// `request_timeout` is set (the watchdog is that clock for the kTLS
    /// splice, which no linked timeout can reach).
    fn arm_splice_deadline(
        &mut self,
        slot: u32,
        generation: u32,
    ) -> errno::Result<()> {
        if self.cfg.request_timeout.is_none() {
            return Ok(());
        }
        {
            let conn = self.table.conn_mut(slot);
            if conn.splice_deadline_armed {
                return Ok(()); // one watchdog per connection - never a second
            }
            conn.splice_deadline_armed = true;
            // Watermark the remaining bytes: the next expiry compares against
            // this to tell "made progress, re-arm" from "stalled, cancel".
            conn.splice_watermark = conn.splice_remaining;
        }
        let ts = std::ptr::addr_of!(self.pads.request_timeout) as u64;
        self.stage(pack(Op::SpliceDeadline, slot, generation), move |sqe| {
            sqe.opcode = IORING_OP_TIMEOUT;
            sqe.addr = ts;
            sqe.len = 1; // exactly one timespec, per the kernel
        })
    }

    /// Cancel the kTLS-splice watchdog once its body finishes (or its
    /// connection closes): clears the flag and issues an `ASYNC_CANCEL` for
    /// the in-flight `TIMEOUT`. The cancelled timer completes `-ECANCELED`,
    /// which `on_splice_deadline` ignores (it acts only on `-ETIME`).
    pub(crate) fn cancel_splice_deadline(
        &mut self,
        slot: u32,
        generation: u32,
    ) -> errno::Result<()> {
        let armed = match self.table.get_conn_mut(slot) {
            Some(conn) if conn.splice_deadline_armed => {
                conn.splice_deadline_armed = false;
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

    /// The kTLS-splice inactivity watchdog fired or was cancelled. Acts ONLY
    /// on a genuine expiry (`-ETIME`) of the CURRENT watchdog on a live slot:
    ///  * not `-ETIME` -> a cancel completion (body done / close) - ignore;
    ///  * slot recycled / not serving / disarmed -> stale - ignore;
    ///  * body no longer actively splicing (finished, or the brief gap
    ///    between records) -> self-stop;
    ///  * `splice_remaining` fell below the watermark -> progress -> re-arm
    ///    against the new remaining (never cancels a healthy transfer, even
    ///    if the expiry raced a record landing);
    ///  * remaining unchanged for a whole `request_timeout` -> stalled -> cancel
    ///    the blocked splice by `user_data`; its `-ECANCELED`/interrupted
    ///    completion is classified `RequestTimeout` in `on_splice_recv`.
    pub(crate) fn on_splice_deadline(
        &mut self,
        slot: u32,
        generation: u32,
        res: i32,
    ) -> errno::Result<()> {
        if res != -libc::ETIME {
            return Ok(()); // a cancel completion - not a real expiry
        }
        if !self.table.slot_matches_cqe(slot, generation) {
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

    /// Arm a one-shot `POLL_ADD` for `POLLIN` on the connection's socket after a
    /// body splice returned `-EAGAIN` (the non-blocking pool socket was drained
    /// the moment the splice ran). Its completion (`on_splice_poll`) resubmits
    /// the splice. The poll rides the fixed socket fd, so `close_conn`'s fd-keyed
    /// cancel reaches it (unlike the splice, cancelled by `user_data`); it is
    /// counted as one op and marks `splice_polling` so the recv side reads busy.
    pub(crate) fn submit_splice_poll(
        &mut self,
        slot: u32,
        generation: u32,
    ) -> errno::Result<()> {
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
        // SECURITY: the poll is the splice's slow-loris guard. Without a bound, a
        // peer that sends a `SpliceBody` header then stalls mid-body parks this
        // poll forever and pins the slot. Carry the request-receive clock (like a
        // body recv): each arriving segment completes the poll and re-arms it, so
        // the timeout bounds inactivity between body segments.
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
                move |sqe| {
                    sqe.opcode = IORING_OP_LINK_TIMEOUT;
                    sqe.fd = -1;
                    sqe.addr = ts;
                    sqe.len = 1; // exactly one timespec, per the kernel
                },
            ),
        }
    }

    pub(crate) fn submit_recv(
        &mut self,
        slot: u32,
        generation: u32,
        op: Op,
        want: usize,
        exact: bool,
        place_body: bool,
    ) -> errno::Result<()> {
        // A connection with no buffer acquires one with the read itself:
        // `IOSQE_BUFFER_SELECT` has the kernel pick at completion, so an
        // idle recv costs nothing until bytes actually land.
        //
        // Nothing is reserved here and nothing can be: the pick happens at
        // completion, so every parked connection can have a selecting recv
        // armed against a pool of any size. Arming one the pool cannot cover
        // is therefore normal, not an error - `-ENOBUFS` comes back on the
        // completion and `recv_buffer_shortage` grows and re-arms. The
        // rebalance here is the pool's shrink cadence and its response to
        // pressure it *can* see.
        //
        // A placed body is exempt: it reads into its own allocation, so it
        // needs no buffer and must not be given one. The kernel clamps a
        // selecting read to the buffer it picked
        // (`io_ring_buffer_select`, `io_uring/kbuf.c`), so an exact read
        // longer than a pool buffer would complete short of what the frame
        // declared and close the connection as truncated.
        #[cfg(feature = "net-server")]
        let select = if !place_body && self.table.conn(slot).recv_needs_buffer()
        {
            let g = match self.recv_bufs.as_mut() {
                Some(p) => {
                    p.rebalance();
                    Some(p.bgid())
                }
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
        // A pool buffer is one fixed size and a message is not. Rather than
        // size every buffer for the largest message the server accepts, a
        // read that would overrun the one held moves what is accumulated
        // into owned storage and gives the buffer back.
        #[cfg(feature = "net-server")]
        if !place_body {
            self.promote_recv_buffer(slot, want);
        }
        let conn = self.table.conn_mut(slot);
        // The connection is idle - parked for the next request - when this is a
        // header read with nothing yet accumulated. Only such reads carry the
        // idle timeout; body and mid-header continuation reads are active
        // transfers.
        let idle = op == Op::RecvHeader && conn.buffered() == 0;
        let want = if place_body {
            // Placement: the body reads into its own allocation; the exact
            // remainder is computed from what `arm_body_recv` carved.
            conn.arm_body_recv()
        } else {
            let granted = conn.arm_recv(want, exact);
            if granted < want && exact {
                // Unreachable: the promote above leaves either a claim that
                // covers this read or no claim at all. Reading less than the
                // frame declared would deliver a short message as whole, so
                // a promote that ever fails to fire fails closed here.
                self.close_conn(slot, generation, CloseReason::TooLarge)?;
                return Ok(());
            }
            granted
        };
        conn.recving = true;
        conn.recv_idle = idle;
        conn.ops += 1;
        let ptr = conn.recv_ptr();
        // Plain connections use `RECV` (destination in the SQE, no msghdr
        // import). kTLS connections use `RECVMSG` with a control buffer so the
        // record type can be read - a plain recv returns -EIO on any non-data
        // record. With MSG_WAITALL a plain exact read fills the whole buffer
        // before completing (io_uring accumulates in-kernel). For kTLS it
        // CANNOT: io_uring disables its WAITALL accumulation whenever the
        // msghdr carries a control buffer (`io_recvmsg` sets `min_ret` only
        // when `msg_controllen == 0`), so a kTLS exact read completes with
        // whatever fully-arrived records the TLS layer had - `recv_result`
        // answers `Again` and `resubmit_ktls_recv` continues the read. A
        // chunk read takes whatever is available.
        let (opcode, addr, len) = if conn.is_ktls() {
            (IORING_OP_RECVMSG, conn.arm_ktls_recv(ptr, want), 0u32)
        } else {
            (IORING_OP_RECV, ptr, want as u32)
        };
        let flags = if exact { libc::MSG_WAITALL as u32 } else { 0 };
        // A recv carries at most one linked timeout. An idle header read --
        // parked for the next request with nothing buffered - uses the idle
        // clock; any read for a request already in progress (a body, a `Need`
        // header remainder, or a `More` chunk scan) uses the request-receive
        // clock.
        //
        // SECURITY: the request clock is the slow-loris guard. Without it a
        // peer that sends a partial frame (e.g. a valid length prefix) then
        // stalls pins its pool slot forever - `idle_timeout` can't fire, the
        // connection is no longer idle - so a few such peers exhaust the pool.
        // For an exact read (`MSG_WAITALL`) the clock bounds the whole
        // transfer; for a chunk read it bounds inactivity (each arriving byte
        // completes the read and re-arms), which still reclaims a stalled slot.
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
        match timeout_ts {
            None => self.stage(pack(op, slot, generation), move |sqe| {
                sqe.opcode = opcode;
                sqe.fd = slot as i32;
                sqe.flags = IOSQE_FIXED_FILE;
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
                    sqe.flags = IOSQE_FIXED_FILE | IOSQE_IO_LINK;
                    sqe.addr = addr;
                    sqe.len = len;
                    sqe.op_flags = flags;
                    stamp_select(sqe, select);
                },
                pack(Op::RecvClock, slot, generation),
                move |sqe| {
                    sqe.opcode = IORING_OP_LINK_TIMEOUT;
                    sqe.fd = -1;
                    sqe.addr = ts;
                    sqe.len = 1; // exactly one timespec, per the kernel
                },
            ),
        }
    }

    pub(crate) fn submit_send(
        &mut self,
        slot: u32,
        generation: u32,
    ) -> errno::Result<()> {
        let conn = self.table.conn_mut(slot);
        conn.arm_send();
        conn.sending = true;
        conn.ops += 1;
        let single = conn.send_single();
        let ktls = conn.is_ktls();
        let msg = conn.send_msg_ptr();
        // A one-PDU gather takes the plain `SEND` opcode (ptr/len in the SQE,
        // no msghdr import); `SENDMSG` is reserved for real multi-PDU gathers.
        // MSG_NOSIGNAL: never raise SIGPIPE - the library must not depend on
        // the host runtime ignoring it (Rust's does; an embedding might not).
        //
        // MSG_WAITALL flushes the whole gather in-kernel (one CQE per
        // fully-sent batch, no userspace partial-send loop) - but the kernel
        // TLS sendmsg rejects MSG_WAITALL (-EOPNOTSUPP; it validates flags
        // strictly), so kTLS sends omit it and lean on `on_send`'s
        // partial-send re-submit instead.
        let flags = if ktls {
            libc::MSG_NOSIGNAL as u32
        } else {
            (libc::MSG_WAITALL | libc::MSG_NOSIGNAL) as u32
        };
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
            sqe.flags = IOSQE_FIXED_FILE;
            sqe.op_flags = flags;
        };
        let send_ts = (self.cfg.send_timeout.is_some())
            .then_some(std::ptr::addr_of!(self.pads.send_timeout) as u64);
        match send_ts {
            None => self.stage(pack(Op::Send, slot, generation), fill),
            // Stall guard: a linked timeout cancels a send that sits with no
            // progress for `send_timeout` (a peer that stopped reading). On a
            // cancelled partial send the CQE carries the progress made, so a
            // slow-but-draining peer resets the clock via the re-submit path.
            Some(ts) => self.stage_linked(
                pack(Op::Send, slot, generation),
                move |sqe| {
                    fill(sqe);
                    sqe.flags |= IOSQE_IO_LINK;
                },
                pack(Op::LinkTimeout, slot, generation),
                move |sqe| {
                    sqe.opcode = IORING_OP_LINK_TIMEOUT;
                    sqe.fd = -1;
                    sqe.addr = ts;
                    sqe.len = 1; // exactly one timespec, per the kernel
                },
            ),
        }
    }

    /// Classify a short-positive exact recv completion: `fired` is whether the
    /// recv's linked clock reported `-ETIME`. A drain/stop cancel wins first
    /// (`begin_drain`'s ASYNC_CANCEL also produces short-positive completions
    /// -- same `io_sendrecv_fail` path - but never a fired clock); a fired
    /// clock maps exactly like a zero-progress cancel; anything else is the
    /// peer's FIN mid-frame.
    pub(crate) fn short_recv_reason(
        &self,
        fired: bool,
        was_idle: bool,
    ) -> CloseReason {
        if self.draining || self.stopping() {
            return CloseReason::ShuttingDown;
        }
        if fired {
            return self.recv_close_reason(-libc::ECANCELED, was_idle);
        }
        CloseReason::TruncatedMessage
    }

    /// A recv's linked idle/request clock reaped (`Op::RecvClock`): `-ETIME`
    /// when it fired (and cancelled its recv), `-ECANCELED` when the recv
    /// completed first. Not counted in `conn.ops` (exactly like the generic
    /// `LinkTimeout` CQEs this op split from). Resolves a parked
    /// short-positive close (`recv_close_stash`) or records the outcome for a
    /// recv CQE later in this batch; on an already-closing (or recycled) slot
    /// it is inert.
    pub(crate) fn on_recv_clock(
        &mut self,
        slot: u32,
        generation: u32,
        res: i32,
    ) -> errno::Result<()> {
        if !self.table.slot_matches_cqe(slot, generation) {
            return Ok(());
        }
        let fired = res == -libc::ETIME;
        let was_idle = {
            let conn = self.table.conn_mut(slot);
            if conn.teardown_owns_slot() {
                // Torn down by another path while the stash waited (the close
                // already ran with that path's reason), or a flush-close
                // arrived meanwhile - its farewell flush owns the teardown,
                // and a recv-side reason must not preempt it.
                conn.recv_close_stash = None;
                return Ok(());
            }
            match conn.recv_close_stash.take() {
                Some(was_idle) => was_idle,
                None => {
                    // No recv is parked on this clock. Record ONLY a genuine
                    // expiry, for a recv still in flight to read when it
                    // completes short. A `-ECANCELED` here is never the
                    // current recv timing out - it is the recv having already
                    // won its link (handled in `on_recv`), or a STALE clock
                    // from a prior kTLS `Again` continuation whose recv won;
                    // recording its `false` would clobber the fresh recv's
                    // state and misclassify a real timeout as a truncation.
                    if fired {
                        conn.recv_clock_fired = Some(true);
                    }
                    return Ok(());
                }
            }
        };
        // The parked short-positive recv resolves now. Partial progress -> it
        // always closes (see the `on_recv` `res > 0` branch), never re-pumps.
        let reason = self.short_recv_reason(fired, was_idle);
        self.close_conn(slot, generation, reason)
    }

    /// The core of a recv completion (`RecvHeader`/`RecvBody`): all the
    /// bookkeeping - the stat, the op-count drain, the flush-close swallow, the
    /// `recv_result` trichotomy (failed/kTLS-again/complete), the short-positive
    /// stash-vs-close, the kTLS control-record close - returning the [`RecvStep`]
    /// its role wrapper enacts (`Deliver`/`Pump` re-enter role code; `Done` is
    /// self-contained). The two recv kinds share the whole skeleton and differ
    /// only in idle eligibility and the delivery tail.
    /// Answer a recv that found the pool dry (`-ENOBUFS`).
    ///
    /// The kernel picks a provided buffer at completion, so a shortage
    /// cannot be seen at submit and this is the only place it is reported.
    /// Growing here sizes the pool to concurrent *arrivals*, which is the
    /// quantity that actually bounds it - and bounds it at `pool_size`
    /// buffers, no worse than the per-connection buffer the pool replaced.
    ///
    /// Progress does not depend on growth succeeding: a pool that will not
    /// grow drops this connection back to owning its buffer, so the re-armed
    /// read cannot come back `-ENOBUFS` a second time. Returns whether the
    /// caller should re-arm.
    #[cfg(feature = "net-server")]
    pub(crate) fn recv_buffer_shortage(&mut self, slot: u32) -> bool {
        let grew = self.recv_bufs.as_mut().is_some_and(BufPool::grow);
        if !grew {
            self.table.conn_mut(slot).set_recv_owned();
        }
        self.sync_recv_buf_stats();
        true
    }

    /// Hand back a pool buffer the next read has outgrown, so the read can
    /// be armed against storage that fits.
    #[cfg(feature = "net-server")]
    pub(crate) fn promote_recv_buffer(&mut self, slot: u32, want: usize) {
        let at = self.table.conn(slot).buffered();
        let Some(claim) = self.table.conn_mut(slot).promote_recv_buf(at, want)
        else {
            return;
        };
        if let Some(pool) = self.recv_bufs.as_mut() {
            pool.release(claim.bid);
        }
        self.sync_recv_buf_stats();
    }

    /// Republish the pool gauges. Called wherever the pool's lend count or
    /// group count can have moved - the numbers are cheap (a sum over a
    /// handful of groups) and a gauge that is only mostly current is worse
    /// than none, since the property it reports is "settles to zero".
    #[cfg(feature = "net-server")]
    pub(crate) fn sync_recv_buf_stats(&self) {
        #[cfg_attr(not(feature = "uring-fs"), allow(unused_mut))]
        let (mut lent, mut total) = match self.recv_bufs.as_ref() {
            Some(p) => (u64::from(p.lent()), u64::from(p.allocated())),
            None => (0, 0),
        };
        // Both pools report as one figure: an operator cares how much buffer
        // memory the ring holds, not which group it sits in.
        #[cfg(feature = "uring-fs")]
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
    /// Called after every consume: the point of the pool is that a
    /// keep-alive connection waiting for its next request holds no buffer,
    /// and this is where that happens.
    #[cfg(feature = "net-server")]
    pub(crate) fn release_recv_buffer(&mut self, slot: u32) {
        let Some(claim) = self.table.conn_mut(slot).release_recv_buf() else {
            return;
        };
        if let Some(pool) = self.recv_bufs.as_mut() {
            pool.release(claim.bid);
        }
        self.sync_recv_buf_stats();
    }

    /// Adopt the pool buffer a completion selected, if it carried one.
    ///
    /// `IORING_CQE_F_BUFFER` is the whole rule for whether a buffer was
    /// taken: an op that failed before selecting one - `-ENOBUFS` above all
    /// - carries nothing and owes nothing back.
    #[cfg(feature = "net-server")]
    pub(crate) fn adopt_recv_buffer(
        &mut self,
        slot: u32,
        generation: u32,
        cqe_flags: u32,
    ) {
        if cqe_flags & IORING_CQE_F_BUFFER == 0 {
            return;
        }
        let bid = (cqe_flags >> IORING_CQE_BUFFER_SHIFT) as u16;
        let Some(pool) = self.recv_bufs.as_mut() else {
            return;
        };
        let Some((ptr, cap)) = pool.addr_of(bid) else {
            return;
        };
        pool.lend(bid);
        // A guard, not a handled case: a slot is freed only once nothing is
        // in flight on it, so a recv completion should never outlive its
        // connection. It is here because the cost of being wrong is a panic
        // (`conn_mut` on a slot that is not serving) or a buffer installed
        // on whoever holds the slot now, and because the buffer is owed back
        // either way - `on_recv_complete` makes the same check a moment
        // later and by then it would be too late to return it.
        if !self.table.slot_matches_cqe(slot, generation) {
            pool.release(bid);
            self.sync_recv_buf_stats();
            return;
        }
        self.sync_recv_buf_stats();
        self.table.conn_mut(slot).install_recv_buf(
            crate::net::core::conn::RecvClaim { bid, ptr, cap },
        );
    }

    pub(crate) fn on_recv_complete(
        &mut self,
        slot: u32,
        generation: u32,
        res: i32,
        op: Op,
    ) -> errno::Result<RecvStep> {
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
        // Flush-closing (`close_on_flush`): the recv side is retired. Data is
        // left unexposed in spare capacity (never delivered - the pump is
        // gated), an EOF or error is moot (a peer half-close must not beat
        // the farewell out of the queue), and nothing re-arms; the send side
        // owns the close once the queue drains (`on_send`), with a genuinely
        // dead peer surfacing there as a send failure. `recv_result` is
        // skipped: its buffer/cursor bookkeeping only matters to a next read
        // that will never be armed.
        if self.table.conn(slot).close_on_flush.is_some() {
            return Ok(RecvStep::Done);
        }
        // Not a transfer outcome: the read never started, because the pool
        // had no buffer to select. Grow (or fall back to owning one) and
        // re-pump - the framer is pure over what is buffered, and nothing
        // was received, so it re-arms exactly this read.
        #[cfg(feature = "net-server")]
        if res < 0
            && Errno::from_raw(-res) == Errno::ENOBUFS
            && self.recv_buffer_shortage(slot)
        {
            return Ok(RecvStep::Pump);
        }
        match self.table.conn_mut(slot).recv_result(res) {
            // EOF (half-close / keep-alive ended), truncation, cancel, error.
            RecvOutcome::Failed => {
                // A short-POSITIVE exact read always CLOSES (never re-enters
                // the pump): the peer made partial progress, and those bytes
                // sit unexposed in the recv buffer's spare capacity - a
                // re-pump would re-frame from before them and desync the
                // stream. Only its close REASON is deferred:
                //
                // A kTLS control record can complete an exact read short (the
                // kernel stops the RECVMSG at the record boundary): a peer's
                // clean close_notify is TlsControl, not TruncatedMessage.
                if res > 0 && self.ktls_control_record(slot) {
                    self.close_conn(slot, generation, CloseReason::TlsControl)?;
                    return Ok(RecvStep::Done);
                }
                // Otherwise a short exact read is AMBIGUOUS when the recv
                // carried a linked clock: a cancelled `MSG_WAITALL` recv that
                // had consumed bytes completes with `res = done_io > 0`
                // (io_uring/net.c `io_sendrecv_fail`) - bit-identical to a
                // peer FIN mid-frame. Only the clock's own CQE
                // (`Op::RecvClock`: `-ETIME` fired vs `-ECANCELED` this recv
                // won) tells RequestTimeout/IdleTimeout from a truncation,
                // so park the close on it when it hasn't reaped yet - both
                // CQEs of a linked pair are queued by the same task-work
                // run, so the stash resolves within this same reap batch.
                if res > 0 {
                    let (armed, fired) = {
                        let c = self.table.conn(slot);
                        (c.recv_clock_armed, c.recv_clock_fired)
                    };
                    let fired = match (armed, fired) {
                        (false, _) => false,
                        (true, Some(fired)) => fired,
                        (true, None) => {
                            self.table.conn_mut(slot).recv_close_stash =
                                Some(was_idle);
                            return Ok(RecvStep::Done);
                        }
                    };
                    let reason = self.short_recv_reason(fired, was_idle);
                    self.close_conn(slot, generation, reason)?;
                    return Ok(RecvStep::Done);
                }
                // A zero-progress cancel/EOF (`res <= 0`) MAY re-enter the pump
                // (drain / idle-owes-work) - nothing was consumed, so nothing
                // desyncs. `finish_failed_recv` applies that rule.
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
                // A completed body read finishes the current message (split
                // already set by `pump`): deliver it, then pump for the next
                // pipelined request. A completed header read just re-enters
                // the pump.
                if op == Op::RecvBody {
                    Ok(RecvStep::Deliver)
                } else {
                    Ok(RecvStep::Pump)
                }
            }
        }
    }

    /// Close out a `Failed` recv with `reason` - unless it is a parked
    /// read-ahead recv (nothing buffered) cancelled while the connection
    /// still owes work, which must NOT close: the graceful drain
    /// (`begin_drain` cancels parked recvs, which `shutdown_graceful` promises
    /// to let that work finish), or `idle_timeout` firing on a *pipelined*
    /// connection's read-ahead recv while a `Response::Defer` is still
    /// outstanding (a normal client that sends one request and awaits its
    /// reply before sending the next parks this recv while the worker runs --
    /// closing here would drop that reply, since once `closing`,
    /// `kick_send`'s `!closing` guard suppresses the send that
    /// `drain_injections` still enqueues).
    ///
    /// Those re-enter the `pump` (returns [`RecvStep::Pump`]): it re-arms the
    /// read-ahead recv and lets the outstanding work complete
    /// (`on_send`/`Injected::Done` re-pump). The drain path closes once
    /// quiesced; a non-draining connection closes on the next `idle_timeout`
    /// fire once it is genuinely idle (no work in flight) - so this reclaims a
    /// real slow-loris while never dropping an owed reply. A mid-message recv
    /// (buffered>0) is a real request stall - it closes ([`RecvStep::Done`]).
    ///
    /// `served_since_idle_arm` extends "owes work" to the fire that RACES the
    /// finish of that work: the idle clock runs from recv ARM time, so it
    /// keeps counting while a deferred reply is produced and flushed. A fire
    /// whose interval saw a completed send measured busy time, not quiet - it
    /// re-arms a fresh clock (clearing the flag) instead of reaping, which
    /// otherwise races the just-served client's next request (reply flushed,
    /// clock expired, client's follow-up hits EOF).
    /// Only a fire whose whole interval was quiet - nothing owed, nothing
    /// flushed - closes. A peer can never set the flag itself (it marks
    /// server-initiated sends), so an idle-forever connection still closes on
    /// its first expiry.
    fn finish_failed_recv(
        &mut self,
        slot: u32,
        generation: u32,
        reason: CloseReason,
    ) -> errno::Result<RecvStep> {
        if self.table.conn(slot).buffered() == 0 {
            if self.draining && matches!(reason, CloseReason::ShuttingDown) {
                return Ok(RecvStep::Pump);
            }
            if matches!(reason, CloseReason::IdleTimeout) {
                let owes_work = {
                    let c = self.table.conn(slot);
                    c.outstanding > 0
                        || c.sending
                        || c.has_pending_send()
                        || c.served_since_idle_arm
                };
                if owes_work {
                    return Ok(RecvStep::Pump);
                }
            }
        }
        self.close_conn(slot, generation, reason)?;
        Ok(RecvStep::Done)
    }

    /// A splice-readiness `POLL_ADD` completed (`Op::SplicePoll`): the socket is
    /// readable again after a body splice hit `-EAGAIN`. Resubmit the splice for
    /// the remaining bytes. A poll cancelled at teardown drives `op_done` (which
    /// bails); a genuine poll error closes the connection. Fully core: the body
    /// never entered the buffer, so no delivery/pump seam.
    pub(crate) fn on_splice_poll(
        &mut self,
        slot: u32,
        generation: u32,
        res: i32,
    ) -> errno::Result<()> {
        if !self.table.slot_matches_cqe(slot, generation) {
            return Ok(());
        }
        self.table.conn_mut(slot).splice_polling = false;
        if !self.op_done(slot)? {
            return Ok(()); // tearing down (poll cancelled by close_conn)
        }
        if res < 0 {
            // A cancel bailed in `op_done` above; any other negative is a real
            // poll failure. Close on it (the socket won't become readable).
            let reason = self.recv_close_reason(res, false);
            return self.close_conn(slot, generation, reason);
        }
        // Readable (POLLIN, possibly with POLLERR/POLLHUP in the revents mask):
        // resubmit the splice, which now finds data - or surfaces EOF/error and
        // closes through the normal `on_splice_recv` path.
        let (fd, remaining) = {
            let conn = self.table.conn(slot);
            (conn.splice_fd, conn.splice_remaining)
        };
        self.submit_splice_recv(slot, generation, fd, remaining)
    }

    /// The core of a body-splice completion (`Op::SpliceRecv`): the stat, the
    /// op-count drain, `-EAGAIN`->readiness-poll, the kTLS control/deadline/EOF
    /// close classification, the short-splice resubmit, and - on a fully moved
    /// body - retiring the watchdog and dropping the header. Returns the
    /// [`SpliceStep`] its role wrapper enacts. The body never entered the
    /// buffer, so a full body pumps the *next* frame (`Pump`); there is no
    /// `deliver_one` - the framer that returned `SpliceBody` was the per-frame
    /// consumer hook.
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
            // `-EAGAIN` is NOT an error: the non-blocking pool socket had no data
            // the moment this splice ran on io-wq (io_uring forces splice async
            // and, unlike RECV, never poll-retries it). Wait for the socket to be
            // readable, then resubmit the splice for the remainder. Only plain
            // sockets surface this - `tls_sw_splice_read` blocks for a record.
            if e == Errno::EAGAIN {
                self.submit_splice_poll(slot, generation)?;
                return Ok(SpliceStep::Done);
            }
            // On a kTLS splice, `-EINVAL` is the kernel refusing to splice a
            // control record (a TLS 1.3 KeyUpdate, or an alert / close_notify):
            // `tls_sw_splice_read` requeues the record and returns `-EINVAL`.
            // Classify it as `TlsControl`, matching the buffered kTLS path's
            // "close on any non-`application_data` record" policy. A teardown
            // cancel's `-ECANCELED` never reaches here (`op_done` bailed above),
            // so a cancel here is the inactivity WATCHDOG cancelling a stalled
            // kTLS splice (`on_splice_deadline` -> `submit_cancel_splice`):
            // `-ECANCELED` when the splice hadn't started on io-wq yet, or the
            // signal-interrupted record wait when it was blocked - which
            // surfaces raw as `-ERESTARTSYS` (512), since io_uring's splice op,
            // unlike its net ops, posts `do_splice`'s return verbatim (kernel
            // io_uring/splice.c) with no `-EINTR` conversion.
            const ERESTARTSYS: i32 = 512; // kernel-internal; no libc constant
            let ktls = self.table.conn(slot).is_ktls();
            let reason = if e == Errno::EINVAL && ktls {
                CloseReason::TlsControl
            } else if ktls
                && self.cfg.request_timeout.is_some()
                && (e == Errno::ECANCELED
                    || e == Errno::EINTR
                    || -res == ERESTARTSYS)
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
            self.submit_splice_recv(slot, generation, fd, remaining)?;
            return Ok(SpliceStep::Done);
        }
        // Whole body spliced: retire the inactivity watchdog (kTLS only; a
        // no-op otherwise), drop the header from the buffer (the body never
        // entered it), and frame the next message.
        self.cancel_splice_deadline(slot, generation)?;
        self.table.conn_mut(slot).consume();
        Ok(SpliceStep::Pump)
    }

    /// The core of a send completion (`Op::Send`): the slot-match, the op-count
    /// drain, the failure close, the gather-advance accounting (retiring
    /// flushed replies), the partial-send re-arm, the next-batch kick, and the
    /// flush-close finish. Returns the [`SendStep`] its role wrapper enacts --
    /// `Pump` when the gather is fully sent and reading should resume, `Done`
    /// otherwise.
    pub(crate) fn on_send_complete(
        &mut self,
        slot: u32,
        generation: u32,
        res: i32,
    ) -> errno::Result<SendStep> {
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
        // Retire the PDUs the gather flushed: replies free read-ahead slots
        // (pushes don't participate in the cap).
        let progress = {
            let conn = self.table.conn_mut(slot);
            let progress = conn.advance_sent(res as usize);
            conn.outstanding =
                conn.outstanding.saturating_sub(progress.replies);
            // Bytes flushed to the peer: any idle clock armed before this
            // completion measured a non-quiet interval (`finish_failed_recv`).
            conn.served_since_idle_arm = true;
            progress
        };
        stat!(self, replies, u64::from(progress.replies));
        stat!(self, pushes, u64::from(progress.pushes));
        // Chunks that reached the peer give their ring buffers back. Only
        // here, because only the reactor holds the pool.
        #[cfg(feature = "uring-fs")]
        if progress.freed > 0 {
            if let Some(pool) = self.body_bufs.as_mut() {
                for &bid in &progress.freed_bids[..progress.freed as usize] {
                    pool.release(bid);
                }
            }
            self.sync_recv_buf_stats();
        }
        if progress.armed_remaining > 0 {
            // Under WAITALL a short send happens on a mid-flight error or a
            // > 2 GiB gather (the kernel clamps every op at `MAX_RW_COUNT`,
            // and `send_single` clamps its SQE length to match); the
            // re-submit - re-armed from the cursor - continues the tail or
            // surfaces the error as a close.
            self.submit_send(slot, generation)?;
            return Ok(SendStep::Done);
        }
        // The gather is fully sent: start the next batch, then resume reading
        // (read-ahead slots freed up).
        self.kick_send(slot, generation)?;
        // A pending flush-close finishes here: the pump is gated while it is
        // set, so once the queue is dry this completion is the only driver
        // left to submit the teardown.
        let flush = {
            let conn = self.table.conn_mut(slot);
            // `tail_active`: a streaming body's queue can read dry between
            // chunks (the next read still in flight) - the flush-close waits
            // for the tail's last chunk, or it would truncate the farewell.
            if conn.close_on_flush.is_some()
                && !conn.sending
                && !conn.has_pending_send()
                && !conn.tail_active()
            {
                conn.close_on_flush.take()
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

    /// The loop-top gate of the role pump: the busy/closing/stash/flush-close
    /// checks, the `max_in_flight` cap, the draining "close when idle" branch,
    /// and the oversize-buffer close. Returns [`Gate::Stop`] (after performing
    /// any close itself) or [`Gate::Proceed`] to consult the framer. Fully core
    /// -- the framer call and delivery stay in the role wrapper.
    pub(crate) fn pump_gate(
        &mut self,
        slot: u32,
        generation: u32,
    ) -> errno::Result<Gate> {
        // A prior `deliver_one` this loop may have detached or closed the
        // connection (leaving `Serving`) - stop pumping if so.
        let Some(conn) = self.table.get_conn(slot) else {
            return Ok(Gate::Stop);
        };
        // Already reading, splicing a body (or awaiting its readiness
        // poll), tearing down, or at the read-ahead cap. `splicing` /
        // `splice_polling` are distinct from `recving` but equally mean
        // "the recv side is busy": the header is still buffered until the
        // splice completes (`consume` runs in `on_splice_recv`), so
        // re-framing here would re-emit the same `SpliceBody` and submit
        // a second splice. A concurrent push send's completion can call
        // `pump` mid-splice - this makes it a no-op; the splice (or its
        // poll) completion re-drives the pump.
        // A pending `recv_close_stash` counts as recv-busy too: the
        // failed recv's close is merely parked on its clock CQE
        // (`on_recv_clock`), so nothing may re-arm the recv side.
        // A pending flush-close (`close_on_flush`) retires the recv
        // side outright: the farewell PDU is final - buffered
        // pipelined requests are discarded, nothing is re-armed --
        // and `on_send` closes once the queue drains. A closing reply
        // whose file body is still queued behind another one
        // (`has_deferred_close`) has not armed that flag yet and stops
        // the gate just the same: the handler declared the reply final
        // when it returned it, not when its body reaches the wire.
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
        // Draining: never start reading a NEW request. Anything already
        // buffered is still processed; once nothing is left in flight,
        // close (otherwise wait - on_send/Done completions re-pump).
        if self.draining && conn.buffered() == 0 {
            if conn.outstanding == 0
                && !conn.sending
                && !conn.has_pending_send()
            {
                self.close_conn(slot, generation, CloseReason::ShuttingDown)?;
                return Ok(Gate::Stop);
            }
            return Ok(Gate::Stop);
        }
        // Unbounded-header guard: a framer that never completes can't
        // grow the buffer past the message cap.
        if conn.buffered() > self.cfg.max_request_bytes {
            self.close_conn(slot, generation, CloseReason::TooLarge)?;
            return Ok(Gate::Stop);
        }
        Ok(Gate::Proceed)
    }

    /// Enact one framer [`Framing`] verdict on behalf of the role pump: run the
    /// pure [`frame_step`] and carry out `Close`/`ReadHeader`/`ReadBody`/
    /// `SpliceBody` (each submits-or-closes and returns [`Enacted::Done`]);
    /// `Deliver` records the split and returns [`Enacted::Deliver`] - the one
    /// outcome the role handles (running the body handler). The framer can't
    /// mutate the buffer, so `buffered` read here matches what the role passed
    /// the framer.
    pub(crate) fn enact_frame_step(
        &mut self,
        slot: u32,
        generation: u32,
        verdict: Framing,
    ) -> errno::Result<Enacted> {
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
            FrameStep::ReadHeader { want, exact } => {
                self.submit_recv(
                    slot,
                    generation,
                    Op::RecvHeader,
                    want,
                    exact,
                    false,
                )?;
                Ok(Enacted::Done)
            }
            FrameStep::ReadBody {
                want,
                header_len,
                body_len,
                place,
            } => {
                // Placement buys a move on delivery by allocating a buffer
                // per body. A pooled connection already has one big enough,
                // so paying for a second is pure churn - and on a streamed
                // upload it is churn *per window*, which is the allocation
                // this pool exists to remove. `frame_step` cannot see this:
                // it is deliberately state-free, and this is connection
                // state.
                //
                // The trade is a copy for a handler that wants to own the
                // body (`Body::take` on a borrowed body copies, where a
                // placed one moves). Handlers that stream a body out - the
                // reason a body is this large - take nothing.
                let place = place
                    && !self
                        .table
                        .conn(slot)
                        .recv_buf_covers(header_len.saturating_add(body_len));
                self.table.conn_mut(slot).set_frame(header_len, body_len);
                self.submit_recv(
                    slot,
                    generation,
                    Op::RecvBody,
                    want,
                    true,
                    place,
                )?;
                Ok(Enacted::Done)
            }
            FrameStep::Deliver {
                header_len,
                body_len,
            } => {
                // Full message buffered: record the split and hand delivery
                // back to the role, which delivers then loops to try the next
                // pipelined request (bounded by the cap guard).
                self.table.conn_mut(slot).set_frame(header_len, body_len);
                Ok(Enacted::Deliver)
            }
            FrameStep::SpliceBody {
                header_len,
                body_len,
                fd,
            } => {
                // SECURITY: the consumer's destination fd must be
                // BLOCKING. `do_splice` promotes the *output* fd's
                // O_NONBLOCK to `SPLICE_F_NONBLOCK` (fs/splice.c), so a
                // full non-blocking pipe fails the splice with `-EAGAIN`
                // *before the socket is read* - indistinguishable from
                // "socket empty", which would turn the readiness poll
                // into a hot loop (POLLIN completes instantly while the
                // pipe stays full). A blocking pipe blocks the splice on
                // io-wq instead: the designed backpressure. One fcntl per
                // body; a bad fd (consumer closed it early) fails here
                // too, before the kernel sees it.
                let fl = unsafe { libc::fcntl(fd, libc::F_GETFL) };
                if fl < 0 || fl & libc::O_NONBLOCK != 0 {
                    self.close_conn(
                        slot,
                        generation,
                        CloseReason::SpliceBadFd,
                    )?;
                    return Ok(Enacted::Done);
                }
                // Transport-agnostic: the kernel routes the splice through
                // the socket's `splice_read`. Plain sockets move raw bytes;
                // kTLS routes to `tls_sw_splice_read` (both software and
                // NIC-offloaded RX - the ops table aliases them), which
                // decrypts, drains the recvmsg-stranded `rx_list` remainder,
                // and moves PLAINTEXT - so a framed body splices in the
                // clear over kTLS too. A mid-stream TLS control record is
                // fail-closed by the kernel (`-EINVAL`), which
                // `on_splice_recv` maps to `TlsControl`.
                self.table.conn_mut(slot).set_frame(header_len, body_len);
                self.submit_splice_recv(slot, generation, fd, body_len)?;
                Ok(Enacted::Done)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAX: usize = 1024 * 1024;

    #[test]
    fn frame_step_needs_and_caps() {
        // A zero-byte need is malformed.
        assert_eq!(
            frame_step(Framing::Need(0), 0, MAX, None),
            FrameStep::Close(CloseReason::Malformed)
        );
        // A normal need reads exactly that many header bytes.
        assert_eq!(
            frame_step(Framing::Need(4), 0, MAX, None),
            FrameStep::ReadHeader {
                want: 4,
                exact: true
            }
        );
        // A need whose post-read total exceeds the cap closes TooLarge...
        assert_eq!(
            frame_step(Framing::Need(MAX), 1, MAX, None),
            FrameStep::Close(CloseReason::TooLarge)
        );
        // ...including one that would overflow usize.
        assert_eq!(
            frame_step(Framing::Need(usize::MAX), 1, MAX, None),
            FrameStep::Close(CloseReason::TooLarge)
        );
        // More is always a chunk read.
        assert_eq!(
            frame_step(Framing::More, 7, MAX, None),
            FrameStep::ReadHeader {
                want: RECV_CHUNK,
                exact: false
            }
        );
        // Invalid closes.
        assert_eq!(
            frame_step(Framing::Invalid, 0, MAX, None),
            FrameStep::Close(CloseReason::Malformed)
        );
    }

    #[test]
    fn frame_step_complete_paths() {
        // Overflowing header+body is rejected before any slice (the U64-prefix
        // remote-panic class the fuzzer rediscovered).
        assert_eq!(
            frame_step(
                Framing::Complete {
                    header_len: 8,
                    body_len: usize::MAX
                },
                0,
                MAX,
                None
            ),
            FrameStep::Close(CloseReason::TooLarge)
        );
        // A zero-length message is malformed.
        assert_eq!(
            frame_step(
                Framing::Complete {
                    header_len: 0,
                    body_len: 0
                },
                0,
                MAX,
                None
            ),
            FrameStep::Close(CloseReason::Malformed)
        );
        // Over the cap closes.
        assert_eq!(
            frame_step(
                Framing::Complete {
                    header_len: 4,
                    body_len: MAX
                },
                0,
                MAX,
                None
            ),
            FrameStep::Close(CloseReason::TooLarge)
        );
        // Fully buffered -> deliver with the split.
        assert_eq!(
            frame_step(
                Framing::Complete {
                    header_len: 4,
                    body_len: 16
                },
                20,
                MAX,
                None
            ),
            FrameStep::Deliver {
                header_len: 4,
                body_len: 16
            }
        );
        // Body not yet buffered -> read the remainder; no placement (small).
        assert_eq!(
            frame_step(
                Framing::Complete {
                    header_len: 4,
                    body_len: 16
                },
                4,
                MAX,
                Some(64 * 1024)
            ),
            FrameStep::ReadBody {
                want: 16,
                header_len: 4,
                body_len: 16,
                place: false
            }
        );
        // A large body at/over the threshold is placed (header fully buffered).
        assert_eq!(
            frame_step(
                Framing::Complete {
                    header_len: 4,
                    body_len: 128 * 1024
                },
                4,
                MAX,
                Some(64 * 1024)
            ),
            FrameStep::ReadBody {
                want: 128 * 1024,
                header_len: 4,
                body_len: 128 * 1024,
                place: true
            }
        );
    }
}
