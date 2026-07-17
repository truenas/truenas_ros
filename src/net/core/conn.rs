//! Per-connection state and the `user_data` completion-routing codec.
//!
//! A [`Connection`] owns every buffer the kernel touches on its behalf — one
//! accumulating receive buffer, the queued send PDUs, and the send gather's
//! `iovec`s/`msghdr` (recvs are plain `RECV` ops whose destination rides in
//! the SQE; only multi-PDU send gathers need a `msghdr`) — plus the caller's
//! per-connection state `U`. Connections are stored boxed
//! (`Box<Connection<U>>`) in the server's slab, so their addresses are stable:
//! the kernel-visible pointers set up here stay valid from SQE submission
//! until the matching CQE.
//!
//! A message is read into `buf` in phases: the caller's header framer is
//! consulted on the accumulated bytes (`MSG_WAITALL` for a known count, or a
//! chunk read while scanning), then the frame-declared body is read, then the
//! delivered message is drained and any pipelined remainder is re-framed.

use super::protocol::{Body, ClientAddr, CloseReason};
use std::collections::VecDeque;
use std::ffi::c_void;
use std::os::fd::RawFd;
use std::ptr;

/// The operation a completion refers to (low 8 bits of `user_data`).
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Op {
    Accept = 0,
    RecvHeader = 1,
    RecvBody = 2,
    Send = 3,
    Close = 4,
    Wake = 5,
    Cancel = 6,
    LinkTimeout = 7,
    /// The graceful-shutdown grace-period timer (a standalone `TIMEOUT` op).
    Deadline = 8,
    /// A `SO_PEERCRED` fetch (`URING_CMD`) between accept and the accept
    /// handler, when `unix_peercred` is enabled.
    Cred = 9,
    /// A `SHUTDOWN` that precedes a connection's `CLOSE`, forcing the peer's
    /// FIN out immediately (a bare `CLOSE` of a direct descriptor can defer
    /// the socket's teardown while another connection's op pins the ring's
    /// resource node).
    Shutdown = 10,
    /// A `SO_PEERNAME` fetch (`URING_CMD`) between a TCP accept and the
    /// accept handler — per-connection, race-free peer addresses.
    Peername = 11,
    /// A `FIXED_FD_INSTALL` that materializes a real fd for a kTLS listener's
    /// connection, furnished to the consumer's handshake worker.
    FdInstall = 12,
    /// A backoff `TIMEOUT` after a transient accept error, whose completion
    /// re-arms that listener's multishot accept (the slot field is the
    /// listener index) — avoids a hot spin under resource pressure.
    AcceptRetry = 13,
    /// A standalone `TIMEOUT` bounding a `TlsParked` slot's handshake; on
    /// expiry, if the slot is still parked, it is shed (`tls_handshake_timeout`).
    HandshakeTimeout = 14,
    /// A `FIXED_FD_INSTALL` for a `body`-handler connection **detach** — like
    /// `FdInstall` but from a `Serving` slot, furnishing the real fd to the
    /// consumer's detach worker (`Response::Detach`).
    DetachInstall = 15,
    /// An `IORING_OP_SPLICE` moving a framed message body from the connection's
    /// socket straight to a consumer fd (`Framing::SpliceBody`), zero-copy.
    SpliceRecv = 16,
    /// A one-shot `POLL_ADD` for `POLLIN` on a splicing connection's socket,
    /// armed when the body splice returned `-EAGAIN` (the non-blocking pool
    /// socket was momentarily drained mid-body); its completion resubmits the
    /// splice for the remainder.
    SplicePoll = 17,
    /// The `LINK_TIMEOUT` linked to a recv as its idle/request clock. Distinct
    /// from the generic `LinkTimeout` (sends, splices) because its completion
    /// disambiguates a short recv: a cancelled `MSG_WAITALL` recv that had
    /// consumed bytes completes with `res = done_io > 0` — bit-identical to a
    /// peer FIN mid-frame — and only this CQE (`-ETIME` fired vs `-ECANCELED`
    /// the recv won) tells a timeout from a truncation (`on_recv_clock`).
    RecvClock = 18,
    /// A standalone `TIMEOUT` bounding a kTLS body splice's inactivity. A
    /// blocking kTLS splice can't carry a `LINK_TIMEOUT` (the kernel arms a
    /// linked timeout only after the head's blocking `issue()` returns), so a
    /// separate watchdog whose expiry issues an `ASYNC_CANCEL` of the splice
    /// is the only clock that reaches it (`arm_splice_deadline`).
    SpliceDeadline = 19,
    /// An `IORING_OP_CONNECT` establishing an outbound connection on a socket
    /// installed into the pool. Client-only — the server never dials out (its
    /// `dispatch` routes this tag to `unreachable!`), so the shared codec keeps
    /// one `Op`. Constructed by `from_u8` under every role, so no dead code.
    Connect = 20,
}

impl Op {
    fn from_u8(v: u8) -> Option<Op> {
        Some(match v {
            0 => Op::Accept,
            1 => Op::RecvHeader,
            2 => Op::RecvBody,
            3 => Op::Send,
            4 => Op::Close,
            5 => Op::Wake,
            6 => Op::Cancel,
            7 => Op::LinkTimeout,
            8 => Op::Deadline,
            9 => Op::Cred,
            10 => Op::Shutdown,
            11 => Op::Peername,
            12 => Op::FdInstall,
            13 => Op::AcceptRetry,
            14 => Op::HandshakeTimeout,
            15 => Op::DetachInstall,
            16 => Op::SpliceRecv,
            17 => Op::SplicePoll,
            18 => Op::RecvClock,
            19 => Op::SpliceDeadline,
            20 => Op::Connect,
            _ => return None,
        })
    }
}

const SLOT_MASK: u64 = 0x00ff_ffff; // 24 bits

/// Encode `(op, slot, generation)` into an SQE `user_data` token.
pub(crate) fn pack(op: Op, slot: u32, generation: u32) -> u64 {
    (op as u64) | ((slot as u64 & SLOT_MASK) << 8) | ((generation as u64) << 32)
}

/// Decode a CQE `user_data` token. `op` is `None` for an unrecognized tag.
pub(crate) fn unpack(user_data: u64) -> (Option<Op>, u32, u32) {
    let op = Op::from_u8((user_data & 0xff) as u8);
    let slot = ((user_data >> 8) & SLOT_MASK) as u32;
    let generation = (user_data >> 32) as u32;
    (op, slot, generation)
}

/// One outgoing PDU: a request reply or a push.
struct SendItem {
    bytes: Vec<u8>,
    is_reply: bool,
}

/// A connection's receive transport, installed at setup (mirrors the kernel's
/// own per-socket TLS ULP, which swaps `sk->sk_prot`). Selects how recvs are
/// submitted and completed; sends are unchanged (kTLS encrypts transparently).
pub(crate) enum Transport {
    /// Plain TCP/unix: `IORING_OP_RECV` straight into the destination.
    Plain,
    /// Kernel TLS: `IORING_OP_RECVMSG` with a control buffer, so the record
    /// type can be read — a plain recv returns `-EIO` on any non-data record.
    /// Boxed so plain connections carry none of this weight.
    Ktls(Box<KtlsRecv>),
}

/// A generous control-message buffer for a kTLS recv. `CMSG_SPACE(1)` is 24
/// bytes on 64-bit Linux (a 16-byte `cmsghdr` + the 1-byte record type, 8-
/// aligned); 64 leaves ample headroom so the record-type cmsg is never
/// truncated (`MSG_CTRUNC`).
const KTLS_CONTROL_LEN: usize = 64;

/// The `RECVMSG` scaffolding for a kTLS connection: a one-entry gather at the
/// same destination a plain recv would use, plus a control buffer the kernel
/// fills with the `TLS_GET_RECORD_TYPE` message.
pub(crate) struct KtlsRecv {
    iov: libc::iovec,
    msg: libc::msghdr,
    control: Box<[u8; KTLS_CONTROL_LEN]>,
}

impl KtlsRecv {
    fn new() -> Box<KtlsRecv> {
        Box::new(KtlsRecv {
            // SAFETY: iovec/msghdr are plain data; zeroed is valid and both
            // are re-pointed by `arm` before any kernel use.
            iov: unsafe { std::mem::zeroed() },
            msg: unsafe { std::mem::zeroed() },
            control: Box::new([0u8; KTLS_CONTROL_LEN]),
        })
    }

    /// Point the `msghdr` at `[base, base+len)` for the data, with the control
    /// buffer reset to full length for the record-type cmsg.
    fn arm(&mut self, base: u64, len: usize) {
        self.iov.iov_base = base as *mut c_void;
        self.iov.iov_len = len;
        self.msg.msg_iov = ptr::addr_of_mut!(self.iov);
        self.msg.msg_iovlen = 1;
        self.msg.msg_name = ptr::null_mut();
        self.msg.msg_namelen = 0;
        self.msg.msg_control = self.control.as_mut_ptr().cast::<c_void>();
        self.msg.msg_controllen = KTLS_CONTROL_LEN;
        self.msg.msg_flags = 0;
    }

    /// Stable pointer to the `msghdr` for the SQE `addr` field.
    fn msg_ptr(&self) -> u64 {
        ptr::addr_of!(self.msg) as u64
    }

    /// The TLS record content type of the just-completed recv, read from the
    /// `TLS_GET_RECORD_TYPE` control message. `None` if the control buffer was
    /// truncated (`MSG_CTRUNC`) or carried no such message — either way the
    /// caller treats a non-`application_data` result as a control record.
    fn record_type(&self) -> Option<u8> {
        if self.msg.msg_flags & libc::MSG_CTRUNC != 0 {
            return None;
        }
        // SAFETY: `msg` was just used by the kernel for a RECVMSG; its control
        // region (`msg_control`/`msg_controllen`) is initialized by the kernel
        // and the CMSG_* macros walk it within those bounds.
        unsafe {
            let mut cmsg = libc::CMSG_FIRSTHDR(&self.msg);
            while !cmsg.is_null() {
                if (*cmsg).cmsg_level == super::sys::SOL_TLS
                    && (*cmsg).cmsg_type == super::sys::TLS_GET_RECORD_TYPE
                {
                    return Some(*libc::CMSG_DATA(cmsg));
                }
                cmsg = libc::CMSG_NXTHDR(&self.msg, cmsg);
            }
        }
        None
    }
}

/// One accepted connection: the caller's state `U` plus all memory the kernel
/// accesses on its behalf.
///
/// In pipelined mode a recv and a send can be in flight at once; the two
/// directions are fully independent (the recv destination rides in its own
/// SQE, the send gather has its own `iovec`s/`msghdr`) — the same "two
/// independent handles over one fd" shape as tokio's `ReadHalf`/`WriteHalf`.
pub(crate) struct Connection<U> {
    pub peer: ClientAddr,
    pub state: U,
    // ---- recv side ----
    recv_buf: Vec<u8>, // accumulated message bytes (+ pipelined remainder)
    header_len: usize, // current message's header length (from the Complete verdict)
    body_len: usize,   // current message's body length
    recv_at: usize,    // destination offset the in-flight recv writes to
    recv_want: usize,  // bytes the in-flight recv targets
    recv_exact: bool,  // MSG_WAITALL (exact) vs chunk read
    // The receive transport, installed at setup: `Plain` (RECV) or `Ktls`
    // (RECVMSG with a record-type control buffer). Sends are transport-agnostic.
    pub transport: Transport,
    // ---- placed body ----
    // A body being read into its own allocation instead of `buf` (bodies at
    // or over `ServerConfig::body_placement_threshold`). The kernel writes
    // into the Vec's spare capacity; `finish_body_recv` sets the length once
    // the exact-count CQE proves it is initialized.
    body_buf: Option<Vec<u8>>,
    recv_into_body: bool, // the in-flight recv targets `body_buf`, not `buf`
    // ---- spliced body ----
    // A framed body spliced straight from the socket to a consumer fd
    // (`Framing::SpliceBody`) instead of read into a buffer — zero-copy. The fd
    // is borrowed (consumer-owned). `splicing` is a distinct in-flight flag
    // because a splice's SQE `fd` is the pipe, not the socket, so `close_conn`'s
    // fd-keyed cancel can't reach it (it cancels the splice by `user_data`).
    pub splicing: bool, // an `IORING_OP_SPLICE` is in flight
    // Waiting on a `POLL_ADD` for the socket to become readable, after a splice
    // returned `-EAGAIN` (the non-blocking pool socket drained mid-body). Unlike
    // `splicing`, this op rides the SOCKET fd, so `close_conn`'s fd-keyed cancel
    // reaches it (it is not cancelled by `user_data`).
    pub splice_polling: bool,
    pub splice_fd: RawFd, // consumer destination fd (borrowed)
    pub splice_remaining: usize, // body bytes still to splice
    // kTLS-splice inactivity watchdog state (a standalone `TIMEOUT`; see
    // `arm_splice_deadline` for the one-per-connection idempotency invariant).
    // `splice_watermark` is the remaining byte count at the last arm; the next
    // expiry re-arms if it dropped (progress) or cancels the splice if unchanged
    // (stall).
    pub splice_deadline_armed: bool,
    pub splice_watermark: usize,
    // ---- send side ----
    // Outgoing PDUs (request replies and pushes) queued FIFO in production
    // order; the leading PDUs are (partially) in flight while `sending`.
    // Enqueuing more while a send is in flight is safe: the armed `Vec`s' heap
    // data does not move even if the deque reallocates.
    send_queue: VecDeque<SendItem>,
    queued_bytes: usize, // total bytes across `send_queue` (backlog bound)
    front_sent: usize,   // bytes of the front PDU already sent
    armed_bytes: usize,  // bytes of the in-flight gather still unsent
    // The writev gather (up to `max_send_coalesce` entries). Heap-allocated so the
    // kernel-visible array address is stable for the life of the op.
    send_iovs: Box<[libc::iovec]>,
    send_msg: libc::msghdr,
    // ---- scheduling / lifecycle (owned by the server's state machine) ----
    pub recving: bool, // a recv op is in flight
    // The in-flight recv is an idle header read (armed with nothing buffered —
    // parked for the next request). Captured at arm time — a property of the
    // armed read; a kTLS continuation clears it (mid-message is never idle).
    pub recv_idle: bool,
    // The peer was served — a send (reply or push) completed — since the idle
    // clock was last armed. The clock runs from recv ARM time, so on a
    // pipelined connection it keeps counting while a deferred reply is
    // produced and flushed; a fire whose interval saw a completed send
    // measured busy time, not quiet, and `finish_failed_recv` re-arms a fresh
    // clock instead of reaping (the reap would race the served client's next
    // request). Cleared each idle arm; set by `on_send_complete`.
    pub served_since_idle_arm: bool,
    // ---- recv clock pairing (short-read disambiguation) ----
    // Whether the in-flight recv carries a linked idle/request clock
    // (`Op::RecvClock`). A cancelled `MSG_WAITALL` recv that had consumed
    // bytes completes with `res = done_io > 0` — indistinguishable from a
    // peer FIN mid-frame — so classification waits for the clock's own CQE
    // (`-ETIME` = it fired). All three fields are (re)set at recv arm time.
    pub recv_clock_armed: bool,
    // The current pair's clock CQE result, when it reaped before the recv's
    // (CQE order within a pair is not guaranteed): `Some(fired)`.
    pub recv_clock_fired: Option<bool>,
    // A short-positive recv completion parked until its clock CQE resolves
    // its close reason: carries the recv's `was_idle`. While set, the pump
    // must not re-arm the recv side. Both CQEs of a linked pair are queued by
    // the same task-work run, so the stash resolves within the same reap batch.
    pub recv_close_stash: Option<bool>,
    // A push overflowed `max_send_backlog` while the connection was detached
    // (its worker owns the raw stream, so it cannot be torn down mid-detach):
    // evict with `SendBacklog` when the worker resumes it.
    pub evict_on_resume: bool,
    // A flush-close is pending: the connection's FINAL PDU (if any) is queued —
    // close with this reason once the send queue fully drains. Set by
    // `Response::ReplyClose`, `Deferred::reply_close`, and `PushHandle::close`
    // ("the server speaks last": a WebSocket Close ack, an HTTP error before
    // hanging up, an SMB negotiate failure). While set, the recv side is
    // retired — nothing is delivered or re-armed — and later injected
    // outcomes/pushes for this connection are dropped: nothing follows the
    // farewell. On a detached connection it is only marked; the close lands at
    // resume (like `evict_on_resume`).
    pub close_on_flush: Option<CloseReason>,
    // The reason this connection began closing, stashed by `close_conn` so the
    // client can report it in `Event::Closed` when the slot is reclaimed. The
    // server reports closes through its close hook and never reads this, so the
    // field (and its write) are net-client-only — no dead-code weight on the
    // server build.
    #[cfg(feature = "net-client")]
    pub close_reason: Option<CloseReason>,
    pub sending: bool, // a send op is in flight
    pub closing: bool, // being torn down; completions just decrement `ops`
    // A teardown is owed once the recv/send in flight at close time — cancelled
    // there — have drained. Deferring the index-freeing CLOSE until then keeps
    // it the connection's LAST op, so the kernel can't reuse the descriptor's
    // index under a surviving op (a use-after-free — see `close_conn`).
    pub teardown_deferred: bool,
    pub teardown_shutdown_first: bool, // SHUTDOWN-first for the deferred teardown
    pub outstanding: u32, // delivered-but-not-yet-fully-sent requests (read-ahead cap)
    pub ops: u32, // in-flight recv+send+close ops; free the slot only at 0
    next_req_id: u64, // per-connection request id, assigned as requests deliver
    // Requests answered via `Response::Defer`, awaiting their worker's single
    // outcome. A `Deferred` whose request is not (or no longer) in this set is
    // stale and its outcome is dropped — this is what makes a duplicate or
    // outlived `Deferred` inert rather than a double reply or bogus close.
    open_req_ids: Vec<u64>,
}

impl<U> Connection<U> {
    /// Allocate a connection with per-connection state `state` and a send
    /// gather of up to `max_send_coalesce` PDUs. Returned boxed so its interior
    /// addresses never move.
    pub(crate) fn new(
        peer: ClientAddr,
        state: U,
        max_send_coalesce: usize,
    ) -> Box<Connection<U>> {
        Box::new(Connection {
            peer,
            state,
            recv_buf: Vec::new(),
            header_len: 0,
            body_len: 0,
            recv_at: 0,
            recv_want: 0,
            recv_exact: true,
            transport: Transport::Plain,
            body_buf: None,
            recv_into_body: false,
            splicing: false,
            splice_polling: false,
            splice_fd: -1,
            splice_remaining: 0,
            splice_deadline_armed: false,
            splice_watermark: 0,
            send_queue: VecDeque::new(),
            queued_bytes: 0,
            front_sent: 0,
            armed_bytes: 0,
            // SAFETY: iovec/msghdr are plain data; zeroed is a valid initial
            // value and both are re-pointed by `arm_send` before kernel use.
            send_iovs: vec![unsafe { std::mem::zeroed() }; max_send_coalesce]
                .into_boxed_slice(),
            send_msg: unsafe { std::mem::zeroed() },
            recving: false,
            recv_idle: false,
            served_since_idle_arm: false,
            recv_clock_armed: false,
            recv_clock_fired: None,
            recv_close_stash: None,
            evict_on_resume: false,
            close_on_flush: None,
            #[cfg(feature = "net-client")]
            close_reason: None,
            sending: false,
            closing: false,
            teardown_deferred: false,
            teardown_shutdown_first: false,
            outstanding: 0,
            ops: 0,
            next_req_id: 0,
            open_req_ids: Vec::new(),
        })
    }

    /// Switch this connection to the kernel-TLS receive transport (called once,
    /// when a handshake completes, before the first recv is armed).
    pub(crate) fn install_ktls(&mut self) {
        self.transport = Transport::Ktls(KtlsRecv::new());
    }

    /// Whether this connection receives over kernel TLS.
    pub(crate) fn is_ktls(&self) -> bool {
        matches!(self.transport, Transport::Ktls(_))
    }

    /// For a kTLS connection, point its `RECVMSG` `msghdr` at the destination
    /// `recv_ptr` just computed (with `want` bytes) and return the stable
    /// `msghdr` address for the SQE. Panics if called on a plain connection.
    pub(crate) fn arm_ktls_recv(&mut self, base: u64, want: usize) -> u64 {
        match &mut self.transport {
            Transport::Ktls(k) => {
                k.arm(base, want);
                k.msg_ptr()
            }
            Transport::Plain => unreachable!("arm_ktls_recv on a plain conn"),
        }
    }

    /// After a kTLS recv completes, the record's TLS content type (from the
    /// control message). `Some(23)` is `application_data`; any other value —
    /// or `None` (truncated / absent cmsg) — is a control record the server
    /// closes on. Meaningless (and unused) for a plain connection.
    pub(crate) fn ktls_record_type(&self) -> Option<u8> {
        match &self.transport {
            Transport::Ktls(k) => k.record_type(),
            Transport::Plain => None,
        }
    }

    /// Assign the next request id (delivery order). `u64` so a `Deferred`
    /// retained across 2^32 requests on one connection can never collide with a
    /// live open request; it never rides `user_data`, so the width is free.
    pub(crate) fn begin_request(&mut self) -> u64 {
        let req_id = self.next_req_id;
        self.next_req_id = self.next_req_id.wrapping_add(1);
        req_id
    }

    /// Record `req_id` as deferred: awaiting exactly one worker outcome.
    pub(crate) fn open_deferred(&mut self, req_id: u64) {
        self.open_req_ids.push(req_id);
    }

    /// Claim the deferred request `req_id`: `true` exactly once per opened id,
    /// `false` for a stale/duplicate outcome (never opened, or already claimed).
    pub(crate) fn take_deferred(&mut self, req_id: u64) -> bool {
        match self.open_req_ids.iter().position(|&r| r == req_id) {
            Some(i) => {
                self.open_req_ids.swap_remove(i);
                true
            }
            None => false,
        }
    }

    /// Total bytes accumulated so far (what the header framer sees) and the
    /// per-connection state, borrow-split for the framer call.
    pub(crate) fn frame_parts(&mut self) -> (&[u8], &mut U) {
        (&self.recv_buf, &mut self.state)
    }

    /// The current message's `(header bytes, body length)` for a body being
    /// spliced (`Framing::SpliceBody`): the header is the buffered prefix
    /// (`buffered == header_len` when a splice is armed) and the body length is
    /// the count being moved to the sink fd. Snapshotted by the client when the
    /// splice is armed, so its `Event::Splice` carries the header even though
    /// `consume` drops it from the buffer once the body finishes moving.
    #[cfg(feature = "net-client")]
    pub(crate) fn splice_frame_parts(&self) -> (&[u8], usize) {
        (&self.recv_buf[..self.header_len], self.body_len)
    }

    /// `(header, body, peer, state)` for a complete message, borrow-split for
    /// the body handler call. A placed body is moved out of `body_buf`; an
    /// inline body borrows `buf`.
    pub(crate) fn deliver_parts(
        &mut self,
    ) -> (&[u8], Body<'_>, &ClientAddr, &mut U) {
        let placed = self.body_buf.take();
        let (header, rest) = self.recv_buf.split_at(self.header_len);
        let body = match placed {
            Some(bytes) => Body::placed(bytes),
            None => Body::inline(&rest[..self.body_len]),
        };
        (header, body, &self.peer, &mut self.state)
    }

    /// `(peer, state)` borrow-split for the close hook.
    pub(crate) fn close_parts(&mut self) -> (&ClientAddr, &mut U) {
        (&self.peer, &mut self.state)
    }

    /// Record the current message's header/body split (from a `Complete` verdict).
    pub(crate) fn set_frame(&mut self, header_len: usize, body_len: usize) {
        self.header_len = header_len;
        self.body_len = body_len;
    }

    /// Bytes of the current message (header + body). `frame_step` proves the
    /// sum fits `max_request_bytes` (≤ `i32::MAX`) before any `set_frame`, so
    /// the `saturating_add` never saturates in a reachable state — it is a
    /// defence-in-depth guard against a future caller that skips that check.
    pub(crate) fn frame_len(&self) -> usize {
        self.header_len.saturating_add(self.body_len)
    }

    /// Bytes already accumulated in `buf`.
    pub(crate) fn buffered(&self) -> usize {
        self.recv_buf.len()
    }

    /// Drop the delivered message from the front of `buf`, keeping any pipelined
    /// remainder for the next message. A placed body never entered `buf` (only
    /// its header did), so at most `buf.len()` bytes are drained.
    pub(crate) fn consume(&mut self) {
        let drained = self.frame_len().min(self.recv_buf.len());
        self.recv_buf.drain(..drained);
        self.header_len = 0;
        self.body_len = 0;
    }

    // ---- recv side ----

    /// Reserve `want` bytes of spare capacity past the buffer tail as the
    /// next recv's destination. `exact` selects an `MSG_WAITALL` read vs a
    /// chunk read.
    ///
    /// The destination is **spare capacity**, exactly like a placed body: the
    /// kernel initializes it and `recv_result` sets the length from the CQE
    /// count (a `resize` here would memset up to `want` bytes the kernel
    /// immediately overwrites — pure hot-path waste, since the zeros are
    /// never observable: the framer runs only while no recv is armed, an
    /// exact read either fills the whole region or closes the connection,
    /// and a chunk read exposes only the bytes that arrived).
    pub(crate) fn arm_recv(&mut self, want: usize, exact: bool) {
        self.recv_at = self.recv_buf.len();
        self.recv_want = want;
        self.recv_exact = exact;
        self.recv_into_body = false;
        self.recv_buf.reserve(want);
    }

    /// Arm a recv for the current message's body into its **own** allocation
    /// (placement). Any body prefix already accumulated past the header is
    /// copied over (`More`-style framers can over-read; at most one chunk),
    /// `buf` is truncated back to the header, and the remainder is read
    /// directly into the new buffer's spare capacity as an exact
    /// `MSG_WAITALL` recv. Returns the byte count to read.
    ///
    /// Caller guarantees the header is fully buffered and the body is not
    /// (`header_len <= buf.len() < header_len + body_len`).
    pub(crate) fn arm_body_recv(&mut self) -> usize {
        let prefix = self.recv_buf.len() - self.header_len;
        let mut body = Vec::with_capacity(self.body_len);
        body.extend_from_slice(&self.recv_buf[self.header_len..]);
        self.recv_buf.truncate(self.header_len);
        self.recv_at = prefix;
        self.recv_want = self.body_len - prefix;
        self.recv_exact = true;
        self.recv_into_body = true;
        self.body_buf = Some(body);
        self.recv_want
    }

    /// Kernel-visible destination of the armed recv (for the SQE `addr`
    /// field). Stable until the CQE: neither `buf` nor `body_buf` is touched
    /// while `recving`.
    pub(crate) fn recv_ptr(&mut self) -> u64 {
        match &mut self.body_buf {
            Some(body) if self.recv_into_body => {
                // Points into the Vec's spare capacity ([prefix, body_len)); the
                // kernel initializes it and `finish_body_recv` sets the length.
                // SAFETY: `recv_at <= body_len <= capacity`, so the offset stays
                // within the allocation.
                unsafe { body.as_mut_ptr().add(self.recv_at) as u64 }
            }
            // The accumulate buffer's cursor likewise points into spare
            // capacity (`recv_at` sits at — or, mid-kTLS-continuation, past —
            // the length). SAFETY: `arm_recv` reserved through
            // `recv_at + recv_want`, so the offset stays within the
            // allocation.
            _ => unsafe { self.recv_buf.as_mut_ptr().add(self.recv_at) as u64 },
        }
    }

    /// Process a recv result. An exact read completes only at the requested
    /// count; a chunk read completes with any `res > 0` (`recv_buf` truncated
    /// to the bytes actually received).
    ///
    /// kTLS exact reads have one extra healthy shape: io_uring cannot
    /// `MSG_WAITALL`-accumulate a `RECVMSG` that carries a control buffer
    /// (`io_recvmsg` sets `min_ret` only when `msg_controllen == 0` —
    /// io_uring/net.c), so the completion delivers however many fully-arrived
    /// records the TLS layer had and stops. A short, positive,
    /// `application_data` read therefore advances the cursor and returns
    /// [`RecvOutcome::Again`] for the caller to re-arm. Plain-TCP exact reads
    /// never complete short healthy (io_uring itself accumulates), so there a
    /// short read still means EOF mid-frame.
    pub(crate) fn recv_result(&mut self, res: i32) -> RecvOutcome {
        if self.recv_exact {
            if res == self.recv_want as i32 {
                if self.recv_into_body {
                    self.finish_body_recv();
                } else {
                    // SAFETY: `[0, recv_at)` was initialized before arming,
                    // and the exact completion — together with any earlier
                    // kTLS partials that advanced `recv_at` — proves the
                    // kernel wrote the armed region up to this end.
                    unsafe {
                        self.recv_buf.set_len(self.recv_at + self.recv_want)
                    };
                }
                return RecvOutcome::Complete;
            }
            if res > 0
                && (res as usize) < self.recv_want
                && self.is_ktls()
                && self.ktls_record_type()
                    == Some(super::sys::TLS_RECORD_TYPE_DATA)
            {
                // The buffer length is NOT advanced here: the partial bytes
                // sit in spare capacity until the continuation completes
                // (a Failed continuation then never exposes them).
                self.recv_at += res as usize;
                self.recv_want -= res as usize;
                return RecvOutcome::Again;
            }
            RecvOutcome::Failed
        } else if res > 0 {
            // SAFETY: the kernel wrote `res` bytes at the cursor (chunk reads
            // never target `body_buf`), all within the reserved region.
            unsafe { self.recv_buf.set_len(self.recv_at + res as usize) };
            RecvOutcome::Complete
        } else {
            RecvOutcome::Failed
        }
    }

    /// Bytes the armed (or continuing) recv still wants.
    pub(crate) fn recv_want(&self) -> usize {
        self.recv_want
    }

    /// Complete a placed-body recv: the whole body is now initialized, so the
    /// buffer's length can cover it.
    fn finish_body_recv(&mut self) {
        self.recv_into_body = false;
        if let Some(body) = &mut self.body_buf {
            // SAFETY: capacity is at least `body_len` and bytes `[0, body_len)` are
            // initialized — the prefix by `extend_from_slice`, the rest by the
            // kernel (the exact `MSG_WAITALL` recv completed with the full
            // count).
            unsafe { body.set_len(self.body_len) };
        }
    }

    // ---- spliced body ----

    /// Arm a zero-copy body splice: record the borrowed destination `fd` and
    /// the full body length still to move. `submit_splice_recv` sets the
    /// scheduling flags and stages the op; `advance_splice` tracks the cursor
    /// across partial completions (a socket→pipe splice, like a kTLS recv,
    /// can't carry `MSG_WAITALL`, so it may complete short).
    pub(crate) fn arm_splice(&mut self, fd: RawFd, body_len: usize) {
        self.splice_fd = fd;
        self.splice_remaining = body_len;
    }

    /// Account `n` spliced bytes; returns `true` once the whole body has moved
    /// (the cursor reached zero). `saturating_sub` is defence-in-depth — a
    /// completion never reports more than the armed remainder.
    pub(crate) fn advance_splice(&mut self, n: usize) -> bool {
        self.splice_remaining = self.splice_remaining.saturating_sub(n);
        self.splice_remaining == 0
    }

    // ---- send side ----

    /// Queue a request reply (FIFO, production order; frees a
    /// `max_in_flight` read-ahead slot once fully sent).
    pub(crate) fn enqueue_reply(&mut self, bytes: Vec<u8>) {
        self.enqueue(bytes, true);
    }

    /// Queue a pushed PDU (FIFO behind everything already queued; pushes
    /// never count against the read-ahead cap).
    pub(crate) fn enqueue_push(&mut self, bytes: Vec<u8>) {
        self.enqueue(bytes, false);
    }

    fn enqueue(&mut self, bytes: Vec<u8>, is_reply: bool) {
        self.queued_bytes += bytes.len();
        self.send_queue.push_back(SendItem { bytes, is_reply });
    }

    /// Whether any PDU is queued (or being sent).
    pub(crate) fn has_pending_send(&self) -> bool {
        !self.send_queue.is_empty()
    }

    /// Total bytes queued (including the partially-sent front PDU).
    pub(crate) fn queued_bytes(&self) -> usize {
        self.queued_bytes
    }

    /// Point the send `msghdr` at up to `max_send_coalesce` queued PDUs — a
    /// writev-style gather starting at the front PDU's unsent tail. Whole-PDU
    /// FIFO order is preserved; only already-queued PDUs are gathered, so a
    /// lone reply is never delayed. Records and returns the armed byte count.
    pub(crate) fn arm_send(&mut self) -> usize {
        let mut total = 0usize;
        let mut k = 0usize;
        for (i, item) in self
            .send_queue
            .iter()
            .take(self.send_iovs.len())
            .enumerate()
        {
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

    /// Advance the send cursor by `n` bytes (clamped to the armed gather):
    /// fully-sent PDUs are popped and tallied by kind; a partially-sent
    /// leader updates the front cursor.
    pub(crate) fn advance_sent(&mut self, n: usize) -> SendProgress {
        let mut n = n.min(self.armed_bytes);
        self.armed_bytes -= n;
        let mut progress = SendProgress {
            replies: 0,
            pushes: 0,
            armed_remaining: self.armed_bytes,
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
            if item.is_reply {
                progress.replies += 1;
            } else {
                progress.pushes += 1;
            }
        }
        progress
    }

    /// Stable pointer to the send `msghdr` for an SQE `addr` field.
    pub(crate) fn send_msg_ptr(&self) -> u64 {
        ptr::addr_of!(self.send_msg) as u64
    }

    /// The armed gather's lone segment when it has exactly one — the plain
    /// `SEND` fast path (no per-op `msghdr` import): `(ptr, len)`.
    ///
    /// The length is clamped to `i32::MAX`, never cast-wrapped: an SQE length
    /// is `u32` and a CQE result `i32` (the kernel itself clamps every iter at
    /// `MAX_RW_COUNT`), so a ≥ 4 GiB PDU would otherwise wrap — worst case to
    /// a 0-byte send that reads as a fatal `SendError`. A clamped send
    /// completes short and the re-submit carries the tail, exactly like any
    /// partial send.
    pub(crate) fn send_single(&self) -> Option<(u64, u32)> {
        (self.send_msg.msg_iovlen == 1).then(|| {
            (
                self.send_iovs[0].iov_base as u64,
                self.send_iovs[0].iov_len.min(i32::MAX as usize) as u32,
            )
        })
    }
}

/// Outcome of a recv completion, from [`Connection::recv_result`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RecvOutcome {
    /// The armed read is satisfied (exact: full count; chunk: some bytes).
    Complete,
    /// kTLS only: a clean partial — the completion consumed the
    /// fully-arrived `application_data` records but the remainder is still
    /// in flight. The cursor advanced; re-arm for the rest.
    Again,
    /// EOF, truncation, or error: close the connection.
    Failed,
}

/// Outcome of advancing the send cursor over a completion's byte count.
pub(crate) struct SendProgress {
    /// Request replies fully sent (each frees a read-ahead slot).
    pub replies: u32,
    /// Pushed PDUs fully sent.
    pub pushes: u32,
    /// Bytes of the armed gather still unsent (> 0 only on a mid-flight
    /// error under `MSG_WAITALL`; the re-submit surfaces it).
    pub armed_remaining: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn send_gather_and_advance() {
        let mut c = Connection::new(ClientAddr::Unix { cred: None }, (), 2);
        c.enqueue(vec![1; 10], true);
        c.enqueue(vec![2; 20], false);
        c.enqueue(vec![3; 30], true);
        assert_eq!(c.queued_bytes(), 60);

        // Gather caps at max_send_coalesce (2): PDUs 1+2 armed, PDU 3 waits.
        assert_eq!(c.arm_send(), 30);
        // Partial completion mid-PDU-2: PDU 1 (a reply) finishes, cursor
        // lands inside PDU 2.
        let p = c.advance_sent(15);
        assert_eq!((p.replies, p.pushes, p.armed_remaining), (1, 0, 15));
        assert_eq!(c.queued_bytes(), 50);
        // Error-recovery re-arm from the cursor: PDU 2's tail + PDU 3.
        assert_eq!(c.arm_send(), 15 + 30);
        let p = c.advance_sent(45);
        assert_eq!((p.replies, p.pushes, p.armed_remaining), (1, 1, 0));
        assert_eq!(c.queued_bytes(), 0);
        assert!(!c.has_pending_send());

        // A completion never advances past what was armed.
        c.enqueue(vec![4; 8], true);
        assert_eq!(c.arm_send(), 8);
        let p = c.advance_sent(usize::MAX);
        assert_eq!((p.replies, p.armed_remaining), (1, 0));
    }

    #[test]
    fn body_placement_bookkeeping() {
        let mut c = Connection::new(ClientAddr::Unix { cred: None }, (), 8);
        // Frame a 4-byte header + 30 already-buffered body bytes (a More-style
        // over-read), then place the 100-byte body.
        c.arm_recv(34, true);
        {
            // Play the kernel: recvs land in reserved spare capacity, and
            // only the completion (recv_result) extends the length over the
            // initialized bytes.
            let ptr = c.recv_ptr() as *mut u8;
            // SAFETY: recv_ptr points at the 34 reserved-but-uninit bytes.
            unsafe { std::ptr::write_bytes(ptr, 0, 34) };
        }
        assert_eq!(c.recv_result(34), RecvOutcome::Complete);
        c.set_frame(4, 100);
        let want = c.arm_body_recv();
        assert_eq!(want, 70, "prefix of 30 already copied in");
        assert_eq!(c.buffered(), 4, "buf truncated back to the header");
        // Play the kernel: fill the armed spare capacity, then complete.
        let ptr = c.recv_ptr() as *mut u8;
        // SAFETY: recv_ptr points at `want` reserved-but-uninit bytes.
        unsafe { std::ptr::write_bytes(ptr, 0xCD, want) };
        assert_eq!(c.recv_result(want as i32), RecvOutcome::Complete);
        {
            let (header, mut body, _addr, _state) = c.deliver_parts();
            assert_eq!(header.len(), 4);
            assert_eq!(body.len(), 100);
            assert!(body[..30].iter().all(|&b| b == 0), "copied prefix");
            assert!(body[30..].iter().all(|&b| b == 0xCD), "kernel-read tail");
            let owned = body.take();
            assert_eq!(owned.len(), 100);
            assert_eq!(body.len(), 0, "take leaves the body empty");
            assert_eq!(body.take(), Vec::<u8>::new(), "second take is empty");
        }
        c.consume();
        assert_eq!(c.buffered(), 0, "placed body never re-enters buf");
    }

    #[test]
    fn deferred_request_gating() {
        let mut c = Connection::new(ClientAddr::Unix { cred: None }, (), 8);
        let a = c.begin_request();
        let b = c.begin_request();
        assert_ne!(a, b);
        c.open_deferred(a);
        c.open_deferred(b);
        assert!(c.take_deferred(b)); // out-of-order claim is fine
        assert!(!c.take_deferred(b)); // exactly once
        assert!(c.take_deferred(a));
        assert!(!c.take_deferred(a));
        // A request that was never opened (answered inline) can't be claimed.
        let inline = c.begin_request();
        assert!(!c.take_deferred(inline));
    }

    #[test]
    fn user_data_round_trip() {
        // Force this test to be revisited whenever a variant is added: the
        // compiler errors here, and the count assert below then proves the
        // new variant is reachable through `from_u8` (i.e. was added to its
        // table — `SpliceRecv`'s token doubles as an ASYNC_CANCEL match key,
        // so a `from_u8` gap silently breaks mid-splice teardown).
        const OP_COUNT: usize = {
            match Op::Accept {
                Op::Accept
                | Op::RecvHeader
                | Op::RecvBody
                | Op::Send
                | Op::Close
                | Op::Wake
                | Op::Cancel
                | Op::LinkTimeout
                | Op::Deadline
                | Op::Cred
                | Op::Shutdown
                | Op::Peername
                | Op::FdInstall
                | Op::AcceptRetry
                | Op::HandshakeTimeout
                | Op::DetachInstall
                | Op::SpliceRecv
                | Op::SplicePoll
                | Op::RecvClock
                | Op::SpliceDeadline
                | Op::Connect => {}
            }
            21
        };
        // Every decodable op value: `from_u8` must invert the discriminant
        // (a renumbered enum with a stale table shows up here), and the
        // decoded set must cover every variant.
        let ops: Vec<Op> = (0..=u8::MAX).filter_map(Op::from_u8).collect();
        assert_eq!(ops.len(), OP_COUNT, "Op::from_u8 table out of sync");
        for (v, op) in ops.iter().enumerate() {
            assert_eq!(*op as u8, v as u8, "discriminant vs from_u8 drift");
        }
        for op in ops {
            for &(slot, generation) in
                &[(0u32, 0u32), (1, 7), (0x00ff_ffff, u32::MAX), (128, 3)]
            {
                let (o, s, g) = unpack(pack(op, slot, generation));
                assert_eq!(o, Some(op));
                assert_eq!(s, slot);
                assert_eq!(g, generation);
            }
        }
    }

    #[test]
    fn accept_and_wake_sentinels_distinct() {
        let acc = pack(Op::Accept, 0, 0);
        let wake = pack(Op::Wake, 0, 0);
        assert_ne!(acc, wake);
        assert_eq!(unpack(acc).0, Some(Op::Accept));
        assert_eq!(unpack(wake).0, Some(Op::Wake));
    }

    #[test]
    fn unknown_op_tag() {
        assert_eq!(unpack(0xff).0, None);
    }
}
