//! Per-connection state and the `user_data` completion-routing codec.
//!
//! A [`Connection`] owns every buffer the kernel touches on its behalf - one
//! accumulating receive buffer, the queued send PDUs, and the send gather's
//! `iovec`s/`msghdr` (recvs are plain `RECV` ops whose destination rides in
//! the SQE; only multi-PDU send gathers need a `msghdr`) - plus the caller's
//! per-connection state `U`. Connections are stored boxed
//! (`Box<Connection<U>>`) in the server's slab, so their addresses are stable:
//! the kernel-visible pointers set up here stay valid from SQE submission
//! until the matching CQE.
//!
//! A message is read into `buf` in phases: the caller's header framer is
//! consulted on the accumulated bytes (`MSG_WAITALL` for a known count, or a
//! chunk read while scanning), then the frame-declared body is read, then the
//! delivered message is drained and any pipelined remainder is re-framed.

use super::protocol::{Body, ClientAddr, CloseReason, SendBuf};
use crate::uring::user_data::{pack_raw, unpack_raw};
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
    /// accept handler - per-connection, race-free peer addresses.
    Peername = 11,
    /// A `FIXED_FD_INSTALL` that materializes a real fd for a kTLS listener's
    /// connection, furnished to the consumer's handshake worker.
    FdInstall = 12,
    /// A backoff `TIMEOUT` after a transient accept error, whose completion
    /// re-arms that listener's multishot accept (the slot field is the
    /// listener index) - avoids a hot spin under resource pressure.
    AcceptRetry = 13,
    /// A standalone `TIMEOUT` bounding a `TlsParked` slot's handshake; on
    /// expiry, if the slot is still parked, it is shed (`tls_handshake_timeout`).
    HandshakeTimeout = 14,
    /// A `FIXED_FD_INSTALL` for a `body`-handler connection **detach** - like
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
    /// consumed bytes completes with `res = done_io > 0` - bit-identical to a
    /// peer FIN mid-frame - and only this CQE (`-ETIME` fired vs `-ECANCELED`
    /// the recv won) tells a timeout from a truncation (`on_recv_clock`).
    RecvClock = 18,
    /// A standalone `TIMEOUT` bounding a kTLS body splice's inactivity. A
    /// blocking kTLS splice can't carry a `LINK_TIMEOUT` (the kernel arms a
    /// linked timeout only after the head's blocking `issue()` returns), so a
    /// separate watchdog whose expiry issues an `ASYNC_CANCEL` of the splice
    /// is the only clock that reaches it (`arm_splice_deadline`).
    SpliceDeadline = 19,
    /// An `IORING_OP_CONNECT` establishing an outbound connection on a socket
    /// installed into the pool. Client-only - the server never dials out (its
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

/// Encode `(op, slot, generation)` into an SQE `user_data` token - the
/// stream vocabulary over the shared raw codec. Stream tags stay inside the
/// `0x00..=0x7F` domain (`user_data::TAG_FS_DOMAIN` marks the other half).
pub(crate) fn pack(op: Op, slot: u32, generation: u32) -> u64 {
    pack_raw(op as u8, slot, generation)
}

/// Decode a CQE `user_data` token. `op` is `None` for an unrecognized tag.
pub(crate) fn unpack(user_data: u64) -> (Option<Op>, u32, u32) {
    let (tag, slot, generation) = unpack_raw(user_data);
    (Op::from_u8(tag), slot, generation)
}

/// What one outgoing PDU is, for read-ahead accounting. A vectored reply is
/// several PDUs but one logical response, so only its final segment retires
/// the request's `outstanding` slot; the earlier segments are `ReplyPart` and
/// count as neither a reply nor a push.
#[derive(Clone, Copy)]
enum SendKind {
    /// The last (or only) segment of a request reply: retires one read-ahead
    /// slot and tallies one reply.
    ReplyLast,
    /// A non-final segment of a vectored reply (e.g. the head): already part
    /// of a reply the final segment will retire, so it tallies nothing.
    ReplyPart,
    /// An out-of-band pushed PDU.
    Push,
}

/// A connection's hold on a pool buffer: which buffer, and where it lives.
///
/// Raw because the pool owns the allocation and outlives every connection
/// drawing from it - `Reactor` declares `table` before `recv_bufs`, so
/// connections drop first - and because `BufPool::rebalance` never retires a
/// group while any buffer is lent, which a live claim counts as.
#[derive(Clone, Copy, Debug)]
pub(crate) struct RecvClaim {
    /// The buffer id to hand back.
    pub(crate) bid: u16,
    /// Start of the buffer's storage.
    pub(crate) ptr: *mut u8,
    /// How much it holds.
    pub(crate) cap: usize,
}

/// The bytes a connection has accumulated for the message it is framing.
///
/// A seam, not an abstraction for its own sake: this used to be a bare
/// `Vec<u8>` reached through twenty-odd call sites - `len`, `reserve`,
/// `drain`, `truncate`, `set_len`, and a raw destination pointer - scattered
/// across the recv path. Gathering them here is what let the storage become
/// a buffer drawn from the registered provided-buffer ring
/// (`crate::uring::bufring`), held only while a message is arriving, without
/// touching any of those sites. It derefs to `[u8]`, so every *read* of the
/// buffer is unchanged; only the mutating operations are named here.
#[derive(Default)]
pub(crate) struct RecvBuf {
    /// Backing storage when no pool is behind this role - the client, and a
    /// server built without one. Empty and unallocated while a claim is
    /// held, so it costs nothing to carry.
    owned: Vec<u8>,
    /// The pool buffer being accumulated into, when one is held.
    claim: Option<RecvClaim>,
    /// Set when this connection draws from a pool, so an armed recv with no
    /// claim acquires one rather than growing `owned`.
    pooled: bool,
    /// Set when a leased write took this claim: the buffer's bytes are a
    /// file write's iovec until its CQE, so consume surrenders the claim to
    /// the op instead of draining and recycling it. A `Cell` because the
    /// handler that arms the write holds the body - a shared borrow of this
    /// same connection - for its whole run.
    #[cfg(all(feature = "net-server", feature = "uring-fs"))]
    write_leased: std::cell::Cell<bool>,
    /// Bytes filled. Tracked separately from `owned.len()` because the
    /// kernel writes into space reserved past the tail and the count only
    /// becomes known at completion.
    filled: usize,
}

impl RecvBuf {
    /// Bytes filled. Named as `Vec::len` was, so the sites this replaced
    /// read the same.
    pub(crate) fn len(&self) -> usize {
        self.filled
    }

    /// Draw from the pool rather than owning storage.
    pub(crate) fn set_pooled(&mut self) {
        self.pooled = true;
    }

    /// Fall back to owning storage, for the rest of this connection's life.
    ///
    /// The pool refusing to grow is a memory-pressure signal, not a reason
    /// to shed a connection: owning the buffer is what every connection did
    /// before the pool existed, so this degrades to that rather than
    /// failing. Per connection and one-way, so a pool under sustained
    /// pressure does not re-try on every read; the next connection to be
    /// accepted starts pooled again.
    pub(crate) fn set_owned(&mut self) {
        self.pooled = false;
    }

    /// Whether an armed recv must acquire a buffer - pool-backed, none
    /// held, and nothing accumulated. The submit answers this by setting
    /// `IOSQE_BUFFER_SELECT`.
    ///
    /// The `filled` term is what distinguishes a connection waiting to
    /// acquire from one that has [`promoted`](RecvBuf::promote_for) off a
    /// buffer mid-message: both are pooled and hold no claim, but the second
    /// is accumulating into `owned` and a fresh claim would orphan it.
    pub(crate) fn needs_buffer(&self) -> bool {
        self.pooled && self.claim.is_none() && self.filled == 0
    }

    /// Adopt the buffer a completion selected.
    pub(crate) fn install(&mut self, claim: RecvClaim) {
        debug_assert!(self.claim.is_none(), "a claim would be leaked");
        self.claim = Some(claim);
        self.filled = 0;
    }

    /// The claim as a write lease, for a delivery's fs facade.
    #[cfg(all(feature = "net-server", feature = "uring-fs"))]
    pub(crate) fn write_lease(
        &self,
    ) -> Option<crate::uring_fs::core::RecvWriteLease<'_>> {
        let c = self.claim.as_ref()?;
        Some(crate::uring_fs::core::RecvWriteLease {
            ptr: c.ptr,
            cap: c.cap,
            bid: c.bid,
            taken: &self.write_leased,
        })
    }

    /// Give the buffer up, for the caller to hand back to the pool. Only
    /// once nothing is buffered: the bytes live in it.
    ///
    /// Also drops any storage a promote left behind, so one oversized
    /// message does not leave the connection carrying its buffer for the
    /// rest of its life - which is the retention the pool exists to end.
    pub(crate) fn release(&mut self) -> Option<RecvClaim> {
        if self.filled > 0 {
            return None;
        }
        #[cfg(all(feature = "net-server", feature = "uring-fs"))]
        if self.write_leased.get() {
            // A write op owns the buffer; it will be released through the
            // completion's lease, never through the connection.
            return None;
        }
        if self.pooled && !self.owned.is_empty() {
            self.owned = Vec::new();
        }
        self.claim.take()
    }

    /// Whether the buffer in hand covers a whole message of `total` bytes.
    ///
    /// Only true of a pool buffer. Owned storage grows to whatever is asked
    /// of it, so the question does not arise there - and answering `true`
    /// would suppress placement for every connection, not just the ones
    /// that have somewhere to put the body.
    pub(crate) fn covers(&self, total: usize) -> bool {
        self.claim.is_some_and(|c| c.cap >= total)
    }

    /// Move accumulation off a pool buffer that cannot hold what is about
    /// to be read, handing the buffer back for the caller to return.
    ///
    /// A pool buffer is a fixed size and the message being framed is not:
    /// the alternative to promoting is sizing every buffer for the largest
    /// message the server accepts, which is what kept the pool off by
    /// default. The copy is bounded by the buffer, not by the message - at
    /// most one buffer's worth, once, on the read that overflows it - and
    /// the connection then behaves exactly as an unpooled one for the rest
    /// of the message.
    ///
    /// Chaining buffers instead is what SPDK's uring sock does
    /// (`module/sock/uring/uring.c`, `sock->recv_stream`), and it works
    /// there because its consumer gathers out of the list into its own
    /// iovecs. A head scan cannot: `httparse` needs the bytes contiguous,
    /// so a chain would have to be joined before framing and the join is
    /// the copy this whole mechanism exists to avoid.
    pub(crate) fn promote_for(
        &mut self,
        at: usize,
        want: usize,
    ) -> Option<RecvClaim> {
        // Unreachable while a leased write holds the claim - no recv is
        // armed between the write's submit and the delivery's consume - and
        // moving the bytes out from under the DMA would tear the write, so
        // fail closed on the impossible rather than corrupt on it.
        #[cfg(all(feature = "net-server", feature = "uring-fs"))]
        if self.write_leased.get() {
            debug_assert!(false, "promote under a leased write");
            return None;
        }
        let c = self.claim?;
        if at.saturating_add(want) <= c.cap {
            return None;
        }
        self.owned.clear();
        self.owned.reserve(at.saturating_add(want));
        // SAFETY: `filled <= cap` by construction, and the pool outlives
        // this connection - see `RecvClaim`.
        self.owned.extend_from_slice(unsafe {
            std::slice::from_raw_parts(c.ptr, self.filled)
        });
        self.claim = None;
        Some(c)
    }

    /// Give the buffer up whatever is in it - the connection is going away,
    /// so the bytes have no reader left.
    ///
    /// `None` while a leased write holds the buffer: the op's completion
    /// releases the id, and handing it back here as well would let the pool
    /// reissue it under the DMA.
    pub(crate) fn forfeit(&mut self) -> Option<RecvClaim> {
        self.filled = 0;
        #[cfg(all(feature = "net-server", feature = "uring-fs"))]
        if self.write_leased.get() {
            self.claim = None;
            return None;
        }
        self.claim.take()
    }

    /// Make room for `want` bytes past `at`, and answer how many were
    /// granted.
    ///
    /// A claim cannot grow - it is one fixed buffer - so the grant is capped
    /// at what remains of it. That cap is unreachable when the pool is sized
    /// as `recv_pool_buf_len` computes: `at` cannot exceed
    /// `max_request_bytes` (`pump_gate` closes the connection above it) and
    /// `want` cannot exceed `RECV_CHUNK` for the one read that is not
    /// already bounded by the frame. It is here because the alternative to a
    /// bound is a write past the buffer, and the caller treats a short grant
    /// on an exact read as fatal rather than reading less than it framed.
    ///
    /// Owned storage grows as the `Vec` this replaced did, so its grant is
    /// always the full `want`.
    pub(crate) fn reserve_at(&mut self, at: usize, want: usize) -> usize {
        if let Some(c) = &self.claim {
            return want.min(c.cap.saturating_sub(at));
        }
        if self.needs_buffer() {
            return want; // the kernel supplies it
        }
        let need = at.saturating_add(want);
        if need > self.owned.len() {
            self.owned.resize(need, 0);
        }
        want
    }

    /// Destination for a recv writing at `at`.
    /// Destination for a recv writing at `at`. Null when a buffer has yet
    /// to be acquired - the SQE's address is ignored under
    /// `IOSQE_BUFFER_SELECT`, since the kernel supplies it.
    pub(crate) fn write_ptr(&mut self, at: usize) -> *mut u8 {
        match &self.claim {
            // SAFETY: `at` stays within the claim; the framer never
            // accumulates past `max_request_bytes`, which sizes the buffer.
            Some(c) => unsafe { c.ptr.add(at) },
            None if self.needs_buffer() => std::ptr::null_mut(),
            // SAFETY: `reserve_at` sized the backing to cover `at`.
            None => unsafe { self.owned.as_mut_ptr().add(at) },
        }
    }

    /// Record how far the kernel wrote, once a completion proves it.
    pub(crate) fn set_filled(&mut self, filled: usize) {
        self.filled = filled;
    }

    /// Drop `n` bytes from the front, keeping any pipelined remainder - the
    /// next message then starts at offset zero.
    pub(crate) fn drain_front(&mut self, n: usize) {
        // A leased claim's bytes are a write op's iovec: the memmove below
        // would tear the write, and recycling the buffer would hand it to
        // the next recv while the DMA still reads it. Surrender the claim
        // to the op - its completion releases the id - and keep only the
        // pipelined remainder, copied out into owned storage. On the
        // streaming hot path the remainder is empty (exact reads stop at
        // the message boundary), so this costs nothing there.
        #[cfg(all(feature = "net-server", feature = "uring-fs"))]
        if self.write_leased.get() {
            let Some(c) = self.claim.take() else {
                debug_assert!(false, "leased with no claim");
                self.write_leased.set(false);
                return;
            };
            let n = n.min(self.filled);
            let rest = self.filled - n;
            self.owned.clear();
            if rest > 0 {
                self.owned.reserve(rest);
                // SAFETY: `[n, filled)` lies within the claim, which the
                // write op keeps alive past this copy.
                self.owned.extend_from_slice(unsafe {
                    std::slice::from_raw_parts(c.ptr.add(n), rest)
                });
            }
            self.filled = rest;
            self.write_leased.set(false);
            return;
        }
        let n = n.min(self.filled);
        if n == 0 {
            return;
        }
        let rest = self.filled - n;
        match &self.claim {
            Some(c) if rest > 0 => {
                // SAFETY: both ranges lie within `filled <= cap`, and
                // `copy` is the overlapping form.
                unsafe { std::ptr::copy(c.ptr.add(n), c.ptr, rest) };
            }
            Some(_) => {}
            None => self.owned.copy_within(n..self.filled, 0),
        }
        self.filled = rest;
    }

    /// Forget everything past `n`.
    pub(crate) fn truncate(&mut self, n: usize) {
        self.filled = self.filled.min(n);
    }

    /// The whole buffer, moved out, leaving this empty - the delivery
    /// handoff that gives a body-only message's storage to the handler
    /// rather than copying it.
    ///
    /// This is the one operation a pool-backed buffer will not be able to
    /// serve, since that memory belongs to the ring: it will answer `None`
    /// and the body will be delivered borrowed, with a handler that wants to
    /// own it paying the copy `Body::take` already documents.
    pub(crate) fn take_owned(&mut self) -> Option<Vec<u8>> {
        if self.claim.is_some() || self.pooled {
            return None;
        }
        let mut v = std::mem::take(&mut self.owned);
        v.truncate(self.filled);
        self.filled = 0;
        Some(v)
    }
}

impl std::ops::Deref for RecvBuf {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        match &self.claim {
            // SAFETY: `filled` never exceeds the claim's capacity, and the
            // pool outlives this connection - see `RecvClaim`.
            Some(c) => unsafe {
                std::slice::from_raw_parts(c.ptr, self.filled)
            },
            None => &self.owned[..self.filled.min(self.owned.len())],
        }
    }
}

impl std::fmt::Debug for RecvBuf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecvBuf")
            .field("pooled", &self.pooled)
            .field("held", &self.claim.is_some())
            .field("filled", &self.filled)
            .finish()
    }
}

/// One outgoing PDU: a request reply or a push.
struct SendItem {
    bytes: SendBuf,
    kind: SendKind,
    /// A file-tail chunk whose `Vec` returns to the tail's spare pool once
    /// flushed - never a consumer PDU, whose allocation the consumer chose.
    #[cfg(all(feature = "net-server", feature = "uring-fs"))]
    reclaim: bool,
}

/// Chunk buffers a file-sourced response body cycles through: one being
/// read into while the previous one sends. Fixed rather than configurable:
/// on ZFS every ring read is an io-wq punt, so a deeper pipeline only
/// deepens the bounded worker class's queue - the chunk *size* is the knob
/// (`fs_body_chunk`), not the count.
#[cfg(all(feature = "net-server", feature = "uring-fs"))]
pub(crate) const FILE_TAIL_BUFS: u8 = 2;

/// A `Response::ReplyFile` that arrived while another body was still
/// streaming, held until that one retires. One body at a time is structural -
/// two tails' chunks would interleave on the wire - so a second one queues
/// behind the current body, through the same diversion every other PDU uses.
///
/// # Each one pins a descriptor for as long as the body in front streams
///
/// `file` is an `Arc<OwnedFd>`, so a queued body holds its fd open from the
/// moment the handler answers until its turn comes - which for a multi-GB
/// range on a slow link is minutes. The per-connection hold is therefore the
/// active tail plus every deferred body, bounded by
/// `max_in_flight_requests`, and the process-wide hold is that times
/// `pool_size`. Nothing in `ServerConfig::validate` relates the product to
/// anything, and at the extremes of the validated space (`MAX_IN_FLIGHT`
/// 4096 x default `pool_size` 512) it is far past any `RLIMIT_NOFILE`.
///
/// That is a deployment-sizing constraint, not a bug to fix here: queueing
/// rather than shedding is deliberate (the first response's head and
/// `Content-Length` are already on the wire when the second arrives), and a
/// cap chosen inside the library would be a different arbitrary number. But
/// the exhaustion is process-wide and hits accept and every handler open,
/// and the connections holding the descriptors are the ones making progress,
/// so nothing sheds them. A consumer serving file bodies to pipelined
/// clients has to size `max_in_flight_requests` x `pool_size` against its
/// own fd limit; `CLAUDE.md`'s note about reproducing at `ulimit -Sn 1024`
/// is where that bites first.
#[cfg(all(feature = "net-server", feature = "uring-fs"))]
pub(crate) struct PendingFile {
    pub(crate) head: Vec<u8>,
    pub(crate) file: crate::uring_fs::File,
    pub(crate) offset: u64,
    pub(crate) len: u64,
    pub(crate) close: bool,
}

/// One entry in a tail's diversion, in arrival order: bytes already framed, or
/// a file body still to be installed. Both kinds have to share one list -
/// splitting them would let a reply queued after a deferred body reach the
/// wire before it, which for a pipelined peer is a response out of order.
#[cfg(all(feature = "net-server", feature = "uring-fs"))]
enum PendingItem {
    Pdu(SendItem),
    File(PendingFile),
}

/// A file-sourced response body mid-stream (`Response::ReplyFile`): the
/// reply path reads `unread` more bytes from `file` in bounded chunks, each
/// entering the send queue as its own segment, the final one `ReplyLast` so
/// the reply retires exactly once. While a tail is active every OTHER
/// enqueue (a push, a deferred reply for a pipelined request) is diverted to
/// `pending` - its bytes would otherwise land between two chunks of this
/// body on the wire - and released in arrival order once the last chunk is
/// queued.
#[cfg(all(feature = "net-server", feature = "uring-fs"))]
pub(crate) struct FileTail {
    /// The source file. Each in-flight read parks its own fd clone, so
    /// dropping this with the tail (or the connection) never closes the fd
    /// under a read.
    pub(crate) file: crate::uring_fs::File,
    /// File offset of the next read.
    pub(crate) next_offset: u64,
    /// Bytes of the declared body no read has returned yet. Every read is
    /// clamped to `min(chunk, unread)`: the header's Content-Length is a
    /// snapshot, and an unclamped read of a file grown mid-send would push
    /// bytes past the declared length - which a keep-alive peer parses as
    /// the start of the next response (a framing desync).
    pub(crate) unread: u64,
    /// A pump read is in flight. At most one: chunks must enter the send
    /// queue in offset order, and a single outstanding read makes that
    /// order structural instead of re-sorted.
    pub(crate) reading: bool,
    /// PDUs and deferred file bodies diverted while this tail is active, in
    /// arrival order (see the struct docs).
    pending: Vec<PendingItem>,
    /// The connection has an entry in the reply path's parked list, waiting
    /// for an fs op slot. **Set exactly when the entry is pushed and cleared
    /// exactly when it is popped** - it is the list's dedup key
    /// (`drive_file_tail` is called from three places), so clearing it
    /// anywhere else lets the same connection be recorded twice, which
    /// unbounds a list whose length is supposed to be capped by the
    /// connection count and destroys its longest-waiting-first order.
    ///
    /// It therefore does **not** track whether a read is in flight; a tail
    /// driven by some other path while its entry is still queued keeps the
    /// flag until `redrive_parked_tail` pops it. `reading` is the field that
    /// answers "is a read in flight".
    pub(crate) parked: bool,
}

/// A connection's receive transport, installed at setup (mirrors the kernel's
/// own per-socket TLS ULP, which swaps `sk->sk_prot`). Selects how recvs are
/// submitted and completed; sends are unchanged (kTLS encrypts transparently).
pub(crate) enum Transport {
    /// Plain TCP/unix: `IORING_OP_RECV` straight into the destination.
    Plain,
    /// Kernel TLS: `IORING_OP_RECVMSG` with a control buffer, so the record
    /// type can be read - a plain recv returns `-EIO` on any non-data record.
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
    /// truncated (`MSG_CTRUNC`) or carried no such message - either way the
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
                if (*cmsg).cmsg_level == crate::uring::sys::SOL_TLS
                    && (*cmsg).cmsg_type
                        == crate::uring::sys::TLS_GET_RECORD_TYPE
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
/// SQE, the send gather has its own `iovec`s/`msghdr`) - the same "two
/// independent handles over one fd" shape as tokio's `ReadHalf`/`WriteHalf`.
pub(crate) struct Connection<U> {
    pub peer: ClientAddr,
    pub state: U,
    // ---- recv side ----
    // Accumulated message bytes (+ pipelined remainder). Pool-backed when
    // a pool is behind this role; owned otherwise. See `RecvBuf`.
    recv_buf: RecvBuf,
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
    // (`Framing::SpliceBody`) instead of read into a buffer - zero-copy. The fd
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
    // The in-flight recv is an idle header read (armed with nothing buffered --
    // parked for the next request). Captured at arm time - a property of the
    // armed read; a kTLS continuation clears it (mid-message is never idle).
    pub recv_idle: bool,
    // The peer was served - a send (reply or push) completed - since the idle
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
    // bytes completes with `res = done_io > 0` - indistinguishable from a
    // peer FIN mid-frame - so classification waits for the clock's own CQE
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
    // A flush-close is pending: the connection's FINAL PDU (if any) is queued --
    // close with this reason once the send queue fully drains. Set by
    // `Response::ReplyClose`, `Deferred::reply_close`, and `PushHandle::close`
    // ("the server speaks last": a WebSocket Close ack, an HTTP error before
    // hanging up, an SMB negotiate failure). While set, the recv side is
    // retired - nothing is delivered or re-armed - and later injected
    // outcomes/pushes for this connection are dropped: nothing follows the
    // farewell. On a detached connection it is only marked; the close lands at
    // resume (like `evict_on_resume`).
    pub close_on_flush: Option<CloseReason>,
    // The reason this connection began closing, stashed by `close_conn` so the
    // client can report it in `Event::Closed` when the slot is reclaimed. The
    // server reports closes through its close hook and never reads this, so the
    // field (and its write) are net-client-only - no dead-code weight on the
    // server build.
    #[cfg(feature = "net-client")]
    pub close_reason: Option<CloseReason>,
    pub sending: bool, // a send op is in flight
    pub closing: bool, // being torn down; completions just decrement `ops`
    // A teardown is owed once the recv/send in flight at close time - cancelled
    // there - have drained. Deferring the index-freeing CLOSE until then keeps
    // it the connection's LAST op, so the kernel can't reuse the descriptor's
    // index under a surviving op (a use-after-free - see `close_conn`).
    pub teardown_deferred: bool,
    pub teardown_shutdown_first: bool, // SHUTDOWN-first for the deferred teardown
    // A file-sourced response body mid-stream, driven by the server's reply
    // path (`Response::ReplyFile`). Server-only: a client never installs one,
    // so its `tail_active()` is constantly false there.
    #[cfg(all(feature = "net-server", feature = "uring-fs"))]
    pub(crate) file_tail: Option<FileTail>,
    // The file body the retiring tail handed on, and whatever was queued
    // behind it - both consumed by the reply path's install, which is where a
    // read can actually be issued.
    #[cfg(all(feature = "net-server", feature = "uring-fs"))]
    next_file: Option<PendingFile>,
    #[cfg(all(feature = "net-server", feature = "uring-fs"))]
    next_file_pending: Vec<PendingItem>,
    /// Chunk buffers this connection currently holds - one being read into,
    /// the rest queued or sending. Capped at [`FILE_TAIL_BUFS`], which is
    /// the whole backpressure: a body cannot run ahead of the wire.
    ///
    /// **A count, not a pool.** The buffers belong to the reactor's ring and
    /// are shared by every connection on it, so what a connection owns is a
    /// share of that ring, not storage of its own. A per-connection pool -
    /// which this used to be - made buffer memory scale with the connection
    /// table rather than with how many bodies are actually moving:
    /// `pool_size` x [`FILE_TAIL_BUFS`] x `fs_body_chunk`, held from a
    /// connection's first file reply until it closes.
    #[cfg(all(feature = "net-server", feature = "uring-fs"))]
    chunk_out: u8,
    // A deferred file body carries `close`. `close_on_flush` cannot be armed
    // for it yet - the body in front is still streaming, and the flush-close
    // dry checks would then belong to the wrong body - but the handler has
    // already declared its reply final, so the recv side must stop admitting
    // requests now rather than when the body eventually installs. Handed off
    // to `close_on_flush` at install.
    #[cfg(all(feature = "net-server", feature = "uring-fs"))]
    deferred_close: bool,
    pub outstanding: u32, // delivered-but-not-yet-fully-sent requests (read-ahead cap)
    pub ops: u32, // in-flight recv+send+close ops; free the slot only at 0
    next_req_id: u64, // per-connection request id, assigned as requests deliver
    // Requests answered via `Response::Defer`, awaiting their worker's single
    // outcome. A `Deferred` whose request is not (or no longer) in this set is
    // stale and its outcome is dropped - this is what makes a duplicate or
    // outlived `Deferred` inert rather than a double reply or bogus close.
    open_req_ids: Vec<u64>,
}

impl<U> Connection<U> {
    /// Whether a teardown already owns this connection's remaining
    /// completions: either the flushing kind (`close_on_flush`, the farewell
    /// is final) or the immediate kind (`closing`, a SHUTDOWN/CLOSE is staged).
    ///
    /// A late arrival for such a connection (a worker outcome, a redelivery,
    /// a stashed recv) must be dropped rather than acted on: the teardown
    /// path is what will free the slot, and re-entering the connection can
    /// walk it into a state that path does not account for.
    ///
    /// Deliberately not used at every site that tests one of the two flags.
    /// Some check only `close_on_flush` because the immediate case cannot
    /// reach them, and swapping this predicate in there would be a behaviour
    /// change, not a refactor. Analyse the site before widening it.
    pub(crate) fn teardown_owns_slot(&self) -> bool {
        self.closing || self.close_on_flush.is_some()
    }

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
            recv_buf: RecvBuf::default(),
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
    /// control message). `Some(23)` is `application_data`; any other value --
    /// or `None` (truncated / absent cmsg) - is a control record the server
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
    /// inline body borrows `buf` - except a **body-only** message (an http
    /// 100-continue dance body, delivered with `header_len == 0`) whose
    /// extent is exactly the buffered bytes: at or over `handoff_threshold`,
    /// the accumulate buffer itself is handed over, so the handler's
    /// [`Body::take`] is as free as a placed body's. The same "large bodies
    /// arrive owned" policy as placement - and gated the same way, because
    /// the reactor grows a fresh buffer afterwards.
    // Dead only in a server-with-fs build that carries no client: the
    // server's delivery takes the leased twin below and the client is the
    // remaining caller.
    #[cfg_attr(
        all(
            feature = "net-server",
            feature = "uring-fs",
            not(feature = "net-client")
        ),
        allow(dead_code)
    )]
    pub(crate) fn deliver_parts(
        &mut self,
        handoff_threshold: Option<usize>,
    ) -> (&[u8], Body<'_>, &ClientAddr, &mut U) {
        let placed = self.body_buf.take();
        if placed.is_none()
            && let Some(buf) = self.take_body_handoff(handoff_threshold)
        {
            return (&[], Body::placed(buf), &self.peer, &mut self.state);
        }
        let (header, rest) = self.recv_buf.split_at(self.header_len);
        let body = match placed {
            Some(bytes) => Body::placed(bytes),
            None => Body::inline(&rest[..self.body_len]),
        };
        (header, body, &self.peer, &mut self.state)
    }

    /// As [`deliver_parts`](Self::deliver_parts), plus the recv claim as a
    /// write lease - the server's delivery form, where a handler's
    /// `pwritev2_from` may write the body straight from the buffer. A twin
    /// rather than one method because the lease shares `recv_buf` with the
    /// body borrow, which the other callers' tuple shape has no room for.
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
    ) {
        let placed = self.body_buf.take();
        if placed.is_none()
            && let Some(buf) = self.take_body_handoff(handoff_threshold)
        {
            return (&[], Body::placed(buf), &self.peer, &mut self.state, None);
        }
        let lease = self.recv_buf.write_lease();
        let (header, rest) = self.recv_buf.split_at(self.header_len);
        let body = match placed {
            Some(bytes) => Body::placed(bytes),
            None => Body::inline(&rest[..self.body_len]),
        };
        (header, body, &self.peer, &mut self.state, lease)
    }

    /// The owned-buffer handoff predicate shared by both delivery forms.
    ///
    /// `body_len > 0` keeps a zero-length frame (a redelivery, where the
    /// original bytes were already consumed) out of the handoff: with a
    /// zero threshold it would otherwise `take` the accumulate buffer while
    /// a read-ahead recv may be writing into its spare capacity. `consume`
    /// drains `frame_len().min(buf.len())` = 0 afterwards, so the handoff
    /// composes with the normal delivery epilogue.
    fn take_body_handoff(
        &mut self,
        handoff_threshold: Option<usize>,
    ) -> Option<Vec<u8>> {
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

    /// Record the current message's header/body split (from a `Complete` verdict).
    pub(crate) fn set_frame(&mut self, header_len: usize, body_len: usize) {
        self.header_len = header_len;
        self.body_len = body_len;
    }

    /// Bytes of the current message (header + body). `frame_step` proves the
    /// sum fits `max_request_bytes` (<= `i32::MAX`) before any `set_frame`, so
    /// the `saturating_add` never saturates in a reachable state - it is a
    /// defence-in-depth guard against a future caller that skips that check.
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

    /// Hand the recv buffer back once nothing is buffered, so the next read
    /// acquires afresh and an idle connection holds none.
    pub(crate) fn release_recv_buf(&mut self) -> Option<RecvClaim> {
        self.recv_buf.release()
    }

    /// Draw recv buffers from a pool rather than owning them.
    pub(crate) fn set_recv_pooled(&mut self) {
        self.recv_buf.set_pooled();
    }

    /// Whether the pool buffer this connection holds already covers a
    /// message of `total` bytes, so it needs no allocation of its own.
    pub(crate) fn recv_buf_covers(&self, total: usize) -> bool {
        self.recv_buf.covers(total)
    }

    /// Move accumulation off a pool buffer too small for the next read.
    pub(crate) fn promote_recv_buf(
        &mut self,
        at: usize,
        want: usize,
    ) -> Option<RecvClaim> {
        self.recv_buf.promote_for(at, want)
    }

    /// Surrender the pool buffer unconditionally, for teardown.
    pub(crate) fn forfeit_recv_buf(&mut self) -> Option<RecvClaim> {
        self.recv_buf.forfeit()
    }

    /// Give up on the pool and own the recv buffer instead.
    pub(crate) fn set_recv_owned(&mut self) {
        self.recv_buf.set_owned();
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
        self.recv_buf.drain_front(drained);
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
    /// immediately overwrites - pure hot-path waste, since the zeros are
    /// never observable: the framer runs only while no recv is armed, an
    /// exact read either fills the whole region or closes the connection,
    /// and a chunk read exposes only the bytes that arrived).
    /// Returns the length actually armed, which is `want` except against a
    /// pool buffer with less room than that - see `RecvBuf::reserve_at`.
    pub(crate) fn arm_recv(&mut self, want: usize, exact: bool) -> usize {
        self.recv_at = self.recv_buf.len();
        let want = self.recv_buf.reserve_at(self.recv_at, want);
        self.recv_want = want;
        self.recv_exact = exact;
        self.recv_into_body = false;
        want
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
            // capacity (`recv_at` sits at - or, mid-kTLS-continuation, past --
            // the length). SAFETY: `arm_recv` reserved through
            // `recv_at + recv_want`, so the offset stays within the
            // allocation.
            _ => self.recv_buf.write_ptr(self.recv_at) as u64,
        }
    }

    /// Process a recv result. An exact read completes only at the requested
    /// count; a chunk read completes with any `res > 0` (`recv_buf` truncated
    /// to the bytes actually received).
    ///
    /// kTLS exact reads have one extra healthy shape: io_uring cannot
    /// `MSG_WAITALL`-accumulate a `RECVMSG` that carries a control buffer
    /// (`io_recvmsg` sets `min_ret` only when `msg_controllen == 0` --
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
                    // The exact completion - with any earlier kTLS
                    // partials that advanced `recv_at` - proves the kernel
                    // wrote the armed region up to this end.
                    self.recv_buf.set_filled(self.recv_at + self.recv_want);
                }
                return RecvOutcome::Complete;
            }
            if res > 0
                && (res as usize) < self.recv_want
                && self.is_ktls()
                && self.ktls_record_type()
                    == Some(crate::uring::sys::TLS_RECORD_TYPE_DATA)
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

    /// Complete a placed-body recv: the whole body is now initialized, so the
    /// buffer's length can cover it.
    fn finish_body_recv(&mut self) {
        self.recv_into_body = false;
        if let Some(body) = &mut self.body_buf {
            // SAFETY: capacity is at least `body_len` and bytes `[0, body_len)` are
            // initialized - the prefix by `extend_from_slice`, the rest by the
            // kernel (the exact `MSG_WAITALL` recv completed with the full
            // count).
            unsafe { body.set_len(self.body_len) };
        }
    }

    // ---- spliced body ----

    /// Arm a zero-copy body splice: record the borrowed destination `fd` and
    /// the full body length still to move. `submit_splice_recv` sets the
    /// scheduling flags and stages the op; `advance_splice` tracks the cursor
    /// across partial completions (a socket->pipe splice, like a kTLS recv,
    /// can't carry `MSG_WAITALL`, so it may complete short).
    pub(crate) fn arm_splice(&mut self, fd: RawFd, body_len: usize) {
        self.splice_fd = fd;
        self.splice_remaining = body_len;
    }

    /// Account `n` spliced bytes; returns `true` once the whole body has moved
    /// (the cursor reached zero). `saturating_sub` is defence-in-depth - a
    /// completion never reports more than the armed remainder.
    pub(crate) fn advance_splice(&mut self, n: usize) -> bool {
        self.splice_remaining = self.splice_remaining.saturating_sub(n);
        self.splice_remaining == 0
    }

    // ---- send side ----

    /// Queue a request reply (FIFO, production order; frees a
    /// `max_in_flight` read-ahead slot once fully sent).
    pub(crate) fn enqueue_reply(&mut self, bytes: Vec<u8>) {
        self.enqueue(bytes, SendKind::ReplyLast);
    }

    /// Queue a multi-segment reply, sent vectored (the segments are separate
    /// buffers `arm_send` gathers). The whole reply is one logical response:
    /// only its **last non-empty** segment is [`SendKind::ReplyLast`], so
    /// `advance_sent` retires the request's `outstanding` count exactly once,
    /// when the final segment flushes - not once per segment. Empty segments
    /// are dropped. Returns whether any bytes were queued; an all-empty reply
    /// queues nothing (a one-way message), for which the caller must not bump
    /// `outstanding`.
    pub(crate) fn enqueue_reply_segments(
        &mut self,
        segments: Vec<SendBuf>,
    ) -> bool {
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

    /// Queue a pushed PDU (FIFO behind everything already queued; pushes
    /// never count against the read-ahead cap).
    pub(crate) fn enqueue_push(&mut self, bytes: Vec<u8>) {
        self.enqueue(bytes, SendKind::Push);
    }

    fn enqueue(&mut self, bytes: impl Into<SendBuf>, kind: SendKind) {
        let bytes = bytes.into();
        self.queued_bytes += bytes.len();
        let item = SendItem {
            bytes,
            kind,
            #[cfg(all(feature = "net-server", feature = "uring-fs"))]
            reclaim: false,
        };
        // Mid-file-tail, any other PDU would land between two chunks of the
        // streaming body on the wire; hold it (still counted in
        // `queued_bytes`, so the backlog bound sees it) until the tail's
        // last chunk is queued.
        #[cfg(all(feature = "net-server", feature = "uring-fs"))]
        if let Some(tail) = self.file_tail.as_mut() {
            tail.pending.push(PendingItem::Pdu(item));
            return;
        }
        self.send_queue.push_back(item);
    }

    /// Install a file tail: the reply path streams `len` bytes of `file`
    /// from `offset` behind whatever is already queued. The caller enqueued
    /// the reply's head first (as a non-final segment) and checked no tail
    /// is active.
    #[cfg(all(feature = "net-server", feature = "uring-fs"))]
    pub(crate) fn install_file_tail(
        &mut self,
        file: crate::uring_fs::File,
        offset: u64,
        len: u64,
    ) {
        debug_assert!(self.file_tail.is_none(), "one tail at a time");
        self.file_tail = Some(FileTail {
            file,
            next_offset: offset,
            unread: len,
            reading: false,
            // Anything that arrived behind this body while it waited its
            // turn stays behind it.
            pending: std::mem::take(&mut self.next_file_pending),
            parked: false,
        });
    }

    /// Whether a file-sourced body is still being produced (its last chunk
    /// not yet queued). While true, a queue that reads dry can still owe
    /// bytes - the flush-close dry checks consult this.
    #[cfg(all(feature = "net-server", feature = "uring-fs"))]
    pub(crate) fn tail_active(&self) -> bool {
        self.file_tail.is_some()
    }

    /// Without a server-side fs pool no tail can exist; the flush-close dry
    /// checks compile to their old shape.
    #[cfg(not(all(feature = "net-server", feature = "uring-fs")))]
    pub(crate) fn tail_active(&self) -> bool {
        false
    }

    /// Claim this connection's share of the ring for one more chunk.
    ///
    /// `false` when it already holds [`FILE_TAIL_BUFS`] - one being read
    /// into, the rest queued or sending. The read then waits for a flush,
    /// and that wait is the body's memory bound. Nothing is allocated here:
    /// the buffer comes from the reactor's ring, chosen by the kernel when
    /// the read completes.
    #[cfg(all(feature = "net-server", feature = "uring-fs"))]
    pub(crate) fn tail_claim_chunk(&mut self) -> bool {
        if self.file_tail.is_none() || self.chunk_out >= FILE_TAIL_BUFS {
            return false;
        }
        self.chunk_out += 1;
        true
    }

    /// Give a claim back without a chunk having been queued - a read that
    /// failed or hit EOF.
    #[cfg(all(feature = "net-server", feature = "uring-fs"))]
    pub(crate) fn tail_release_chunk(&mut self) {
        self.chunk_out = self.chunk_out.saturating_sub(1);
    }

    /// Pool buffer ids still sitting in the send queue, taken.
    ///
    /// Teardown: the connection is going away with segments that name ring
    /// buffers, and a buffer never handed back is one the pool can neither
    /// reissue nor free.
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

    /// Queue the leading segment of a reply whose final segment arrives
    /// later (a file tail's head): a non-final part, so the reply retires
    /// exactly once - when the tail's last chunk flushes. Call before
    /// [`Connection::install_file_tail`], while the diversion is still off.
    #[cfg(all(feature = "net-server", feature = "uring-fs"))]
    pub(crate) fn enqueue_reply_head(&mut self, bytes: Vec<u8>) {
        if !bytes.is_empty() {
            self.enqueue(bytes, SendKind::ReplyPart);
        }
    }

    /// Queue one tail chunk (bypassing the diversion - it IS the tail).
    /// `last` marks the final chunk `ReplyLast`, retiring the reply's
    /// read-ahead slot when it flushes.
    #[cfg(all(feature = "net-server", feature = "uring-fs"))]
    pub(crate) fn enqueue_file_chunk(&mut self, bytes: SendBuf, last: bool) {
        self.queued_bytes += bytes.len();
        self.send_queue.push_back(SendItem {
            bytes,
            kind: if last {
                SendKind::ReplyLast
            } else {
                SendKind::ReplyPart
            },
            reclaim: true,
        });
    }

    /// Advance the tail past a completed body read and queue its bytes as the
    /// next chunk; `true` when that was the last of the declared length, which
    /// also retires the tail and releases the diversion.
    ///
    /// The advance is the segment's length and nothing else - the count the
    /// read
    /// ACTUALLY returned, which is why the requested length is not a parameter
    /// here. A short read must leave the rest for the next iteration and
    /// continue from the offset it reached; advancing by the length asked for
    /// would skip the unread bytes and send whatever the next read landed on in
    /// their place, a body correct in its framing and wrong in its content.
    /// That is the failure the deliberate absence of `IOSQE_IO_LINK` on the
    /// read exists to prevent, and short reads are ordinary on ZFS, where every
    /// ring read is punted to an io-wq worker.
    #[cfg(all(feature = "net-server", feature = "uring-fs"))]
    pub(crate) fn advance_file_tail(&mut self, buf: SendBuf) -> bool {
        let n = buf.len() as u64;
        let last = {
            let tail = self.file_tail.as_mut().expect("a tail is streaming");
            // `n <= iov_len = min(chunk, unread)`, so this never underflows,
            // and the advance never passes `offset + len` - which
            // `begin_file_reply` bounded at `i64::MAX` before the first read.
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

    /// Retire the tail (its last chunk is queued) and release what the
    /// diversion held behind it, in arrival order - up to the first deferred
    /// file body, which cannot simply be queued: it has to be installed as the
    /// next tail, and only the reply path can issue its read. That one is left
    /// in [`take_queued_file_reply`](Self::take_queued_file_reply), and
    /// anything behind it waits for it, so responses keep request order.
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

    /// Hold a `ReplyFile` that arrived while a body was already streaming.
    /// The caller has counted it in `outstanding` - it is an answered request
    /// either way, and the read-ahead cap must see it.
    #[cfg(all(feature = "net-server", feature = "uring-fs"))]
    pub(crate) fn defer_file_reply(&mut self, next: PendingFile) {
        self.deferred_close |= next.close;
        self.file_tail
            .as_mut()
            .expect("only deferred behind an active tail")
            .pending
            .push(PendingItem::File(next));
    }

    /// Whether a reply the handler declared final is queued behind the active
    /// body. The pump gate stops on this exactly as it stops on
    /// `close_on_flush`: both mean no further request may be admitted, and
    /// which of the two holds depends only on whether the closing reply's
    /// body has reached the wire yet.
    #[cfg(all(feature = "net-server", feature = "uring-fs"))]
    pub(crate) fn has_deferred_close(&self) -> bool {
        self.deferred_close
    }

    /// Without a server-side fs pool no body can be deferred.
    #[cfg(not(all(feature = "net-server", feature = "uring-fs")))]
    pub(crate) fn has_deferred_close(&self) -> bool {
        false
    }

    /// The file body the last tail handed on, if any - installed by the reply
    /// path, which is the only place a read can be issued.
    #[cfg(all(feature = "net-server", feature = "uring-fs"))]
    pub(crate) fn take_queued_file_reply(&mut self) -> Option<PendingFile> {
        // Installing it arms `close_on_flush` from its own `close`, which
        // takes the gate over from here.
        self.deferred_close = false;
        self.next_file.take()
    }

    /// Drop a deferred file body **and everything queued behind it** - the
    /// connection is flush-closing, so the deferred response will never be
    /// sent.
    ///
    /// The followers go with it because a response's association with its
    /// request is its position: queueing them here would put the next
    /// response on the wire where the dropped one belonged, and the peer
    /// would read it as the answer to a request it does not answer. That is
    /// the same "response out of order" this diversion exists to prevent
    /// ([`PendingItem`]), arriving by the close path instead of the send
    /// path. A peer that sees the close knows what went unanswered and can
    /// retry it; a peer that sees the wrong body cannot tell.
    #[cfg(all(feature = "net-server", feature = "uring-fs"))]
    pub(crate) fn drop_queued_file_reply(&mut self) {
        // Every discarded item was charged to `outstanding` when it was
        // delivered - a file body at `begin_file_reply`, an ordinary reply
        // credited back only when its `ReplyLast` segment flushes. Nothing
        // here will flush, so the charges are returned by hand or they leak:
        // the read-ahead gate, the idle timeout's owes-work test and the
        // drain's quiesced predicate all read `outstanding`.
        let mut charged = u32::from(self.next_file.is_some());
        self.next_file = None;
        // Whatever close a discarded body carried is subsumed by the
        // `close_on_flush` that brought us here.
        self.deferred_close = false;
        for item in std::mem::take(&mut self.next_file_pending) {
            match item {
                PendingItem::File(_) => charged += 1,
                // A reply retires on its final segment, so only that one
                // carries a charge; `Push` segments carry none.
                PendingItem::Pdu(pdu) => {
                    if matches!(pdu.kind, SendKind::ReplyLast) {
                        charged += 1;
                    }
                }
            }
        }
        self.outstanding = self.outstanding.saturating_sub(charged);
    }

    /// Whether any PDU is queued (or being sent).
    pub(crate) fn has_pending_send(&self) -> bool {
        !self.send_queue.is_empty()
    }

    /// Total bytes queued (including the partially-sent front PDU).
    pub(crate) fn queued_bytes(&self) -> usize {
        self.queued_bytes
    }

    /// Point the send `msghdr` at up to `max_send_coalesce` queued PDUs - a
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
            // A flushed tail chunk frees this connection's share of the
            // ring, and its buffer goes back to the pool - which only the
            // reactor can do, so the id rides out on the progress. Not
            // conditioned on a tail being installed: a chunk can still be
            // flushing after its tail retired.
            #[cfg(all(feature = "net-server", feature = "uring-fs"))]
            if item.reclaim {
                self.chunk_out = self.chunk_out.saturating_sub(1);
                if let Some(bid) = item.bytes.pooled_bid() {
                    debug_assert!(
                        (progress.freed as usize) < progress.freed_bids.len(),
                        "at most FILE_TAIL_BUFS chunks can be queued at once"
                    );
                    if let Some(cell) =
                        progress.freed_bids.get_mut(progress.freed as usize)
                    {
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

    /// The armed gather's lone segment when it has exactly one - the plain
    /// `SEND` fast path (no per-op `msghdr` import): `(ptr, len)`.
    ///
    /// The length is clamped to `i32::MAX`, never cast-wrapped: an SQE length
    /// is `u32` and a CQE result `i32` (the kernel itself clamps every iter at
    /// `MAX_RW_COUNT`), so a >= 4 GiB PDU would otherwise wrap - worst case to
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
    /// kTLS only: a clean partial - the completion consumed the
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
    /// Ring buffer ids whose segments flushed, owed back to the pool. Only
    /// the reactor holds the pool, so they ride out to it here. Bounded by
    /// [`FILE_TAIL_BUFS`], which is what caps a connection's chunks.
    #[cfg(all(feature = "net-server", feature = "uring-fs"))]
    pub freed_bids: [u16; FILE_TAIL_BUFS as usize],
    /// How many of `freed_bids` are set.
    #[cfg(all(feature = "net-server", feature = "uring-fs"))]
    pub freed: u8,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn send_gather_and_advance() {
        let mut c = Connection::new(ClientAddr::Unix { cred: None }, (), 2);
        c.enqueue(vec![1; 10], SendKind::ReplyLast);
        c.enqueue(vec![2; 20], SendKind::Push);
        c.enqueue(vec![3; 30], SendKind::ReplyLast);
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
        c.enqueue(vec![4; 8], SendKind::ReplyLast);
        assert_eq!(c.arm_send(), 8);
        let p = c.advance_sent(usize::MAX);
        assert_eq!((p.replies, p.armed_remaining), (1, 0));
    }

    #[test]
    fn vectored_reply_head_counts_as_one_reply_no_push() {
        let mut c = Connection::new(ClientAddr::Unix { cred: None }, (), 2);
        // A vectored reply: head + body as separate segments. The head is a
        // non-final segment; it must not be tallied as a push.
        assert!(c.enqueue_reply_segments(vec![
            vec![b'H'; 12].into(),
            vec![b'B'; 40].into(),
        ]));
        assert_eq!(c.arm_send(), 12 + 40);
        let p = c.advance_sent(12 + 40);
        assert_eq!((p.replies, p.pushes, p.armed_remaining), (1, 0, 0));
    }

    #[test]
    fn a_static_segment_is_armed_at_its_own_address() {
        // A `'static` segment is sent from where it lives: the armed iovec
        // must point at the static bytes themselves, proving no copy sits
        // anywhere between enqueue and the gather.
        static BODY: &[u8] = b"the canned body, sent by reference";
        let mut c = Connection::new(ClientAddr::Unix { cred: None }, (), 2);
        assert!(
            c.enqueue_reply_segments(vec![vec![b'H'; 8].into(), BODY.into()])
        );
        assert_eq!(c.arm_send(), 8 + BODY.len());
        assert_eq!(c.send_iovs[1].iov_base as *const u8, BODY.as_ptr());
        assert_eq!(c.send_iovs[1].iov_len, BODY.len());
        let p = c.advance_sent(8 + BODY.len());
        assert_eq!((p.replies, p.pushes), (1, 0));
        assert_eq!(c.queued_bytes(), 0);
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
            let (header, mut body, _addr, _state) = c.deliver_parts(None);
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
    fn body_only_delivery_hands_over_the_buffer() {
        // The http dance shape: the head was consumed with a previous
        // delivery, the framer declared `Complete { 0, body_len }`, and the
        // whole extent is buffered. At or over the handoff threshold the
        // accumulate buffer itself moves out - ownership, not bytes.
        let mut c = Connection::new(ClientAddr::Unix { cred: None }, (), 8);
        c.arm_recv(100, true);
        let ptr = c.recv_ptr() as *mut u8;
        // SAFETY: recv_ptr points at the 100 reserved-but-uninit bytes.
        unsafe { std::ptr::write_bytes(ptr, 0xEE, 100) };
        assert_eq!(c.recv_result(100), RecvOutcome::Complete);
        c.set_frame(0, 100);
        let p0 = c.recv_buf.as_ptr() as usize;
        {
            let (header, mut body, _addr, _state) = c.deliver_parts(Some(64));
            assert!(header.is_empty());
            assert_eq!(body.len(), 100);
            let owned = body.take();
            assert_eq!(owned.as_ptr() as usize, p0, "the buffer itself moved");
            assert!(owned.iter().all(|&b| b == 0xEE));
        }
        c.consume();
        assert_eq!(c.buffered(), 0, "handoff composes with consume");

        // Below the threshold the delivery stays inline (borrowed).
        c.arm_recv(10, true);
        let ptr = c.recv_ptr() as *mut u8;
        // SAFETY: as above - 10 reserved bytes.
        unsafe { std::ptr::write_bytes(ptr, 0xAA, 10) };
        assert_eq!(c.recv_result(10), RecvOutcome::Complete);
        c.set_frame(0, 10);
        let p_small = c.recv_buf.as_ptr() as usize;
        {
            let (_h, mut body, _addr, _state) = c.deliver_parts(Some(64));
            assert_eq!(body.len(), 10);
            let copied = body.take();
            assert_ne!(
                copied.as_ptr() as usize,
                p_small,
                "small body copies out of the retained buffer"
            );
        }
        c.consume();
        assert_eq!(c.buffered(), 0);

        // A pipelined remainder blocks the handoff - the tail belongs to
        // the next message.
        c.arm_recv(120, true);
        let ptr = c.recv_ptr() as *mut u8;
        // SAFETY: as above - 120 reserved bytes.
        unsafe { std::ptr::write_bytes(ptr, 0xBB, 120) };
        assert_eq!(c.recv_result(120), RecvOutcome::Complete);
        c.set_frame(0, 100);
        {
            let (_h, body, _addr, _state) = c.deliver_parts(Some(64));
            assert_eq!(body.len(), 100);
        }
        c.consume();
        assert_eq!(c.buffered(), 20, "remainder kept for the next message");
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
        // table - `SpliceRecv`'s token doubles as an ASYNC_CANCEL match key,
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

    #[cfg(all(feature = "net-server", feature = "uring-fs"))]
    #[test]
    fn file_tail_diverts_reclaims_and_releases_in_order() {
        let mut c = Connection::new(ClientAddr::Unix { cred: None }, (), 8);
        let fd: std::os::fd::OwnedFd =
            std::fs::File::open("/dev/null").expect("open").into();
        let file = crate::uring_fs::File::new(crate::sync::Arc::new(fd));

        // Head first (the diversion is not yet on), then the tail.
        c.enqueue_reply_head(b"HEAD".to_vec());
        c.install_file_tail(file, 0, 20);
        assert!(c.tail_active());

        // A body holds at most two chunks at once; a third read waits for
        // a flush. The buffers themselves come from the reactor's ring, so
        // what is capped here is this connection's share of it.
        assert!(c.tail_claim_chunk(), "first chunk");
        assert!(c.tail_claim_chunk(), "second chunk");
        assert!(!c.tail_claim_chunk(), "capped at two");
        c.tail_release_chunk(); // the second read never happened

        // Mid-tail enqueues divert - their bytes may not land between two
        // chunks on the wire - but stay in the backlog accounting.
        c.enqueue_push(b"PU".to_vec());
        c.enqueue_reply(b"RRR".to_vec());
        assert_eq!(c.queued_bytes(), 4 + 2 + 3);

        // The tail's own chunks go straight through.
        c.enqueue_file_chunk(SendBuf::from(vec![b'a'; 8]), false);
        assert_eq!(c.arm_send(), 4 + 8, "head + chunk, no diverted bytes");
        let p = c.advance_sent(12);
        assert_eq!(
            (p.replies, p.pushes),
            (0, 0),
            "nothing retires before the last chunk"
        );
        // The flush freed this connection's share, so a read can be armed
        // again.
        assert!(c.tail_claim_chunk(), "the flush freed a chunk");

        // The final chunk retires the tail; the diverted PDUs follow in
        // arrival order behind it.
        c.enqueue_file_chunk(SendBuf::from(vec![b'z'; 12]), true);
        c.finish_file_tail();
        assert!(!c.tail_active());
        assert_eq!(c.arm_send(), 12 + 2 + 3);
        assert_eq!(c.send_iovs[0].iov_len, 12);
        assert_eq!(c.send_iovs[1].iov_len, 2, "push held until the tail");
        assert_eq!(c.send_iovs[2].iov_len, 3, "deferred reply after it");
        let p = c.advance_sent(12 + 2 + 3);
        assert_eq!(
            (p.replies, p.pushes),
            (2, 1),
            "the tail's reply, the diverted reply, and the push"
        );
        assert_eq!(c.queued_bytes(), 0);
        assert!(!c.has_pending_send());
    }

    /// A short read continues from the offset it REACHED. The declared length
    /// is a promise about the body's size, not about how many bytes any one
    /// read returns, so the tail's cursor tracks the count actually delivered.
    /// Advance by the length asked for instead and the unread bytes are
    /// skipped, with the next read's bytes framed in their place.
    #[cfg(all(feature = "net-server", feature = "uring-fs"))]
    #[test]
    fn a_short_read_continues_from_the_offset_it_reached() {
        let mut c = Connection::new(ClientAddr::Unix { cred: None }, (), 8);
        let fd: std::os::fd::OwnedFd =
            std::fs::File::open("/dev/null").expect("open").into();
        let file = crate::uring_fs::File::new(crate::sync::Arc::new(fd));
        // A range of 300 bytes starting 1000 in.
        c.install_file_tail(file, 1000, 300);

        // 200 bytes came back where a whole chunk was asked for.
        assert!(
            !c.advance_file_tail(SendBuf::from(vec![b'a'; 200])),
            "100 still owed"
        );
        {
            let t = c.file_tail.as_ref().expect("still streaming");
            assert_eq!(t.next_offset, 1200, "advanced by the count read");
            assert_eq!(t.unread, 100, "the rest is still owed");
        }

        // The remainder retires the tail exactly once.
        assert!(
            c.advance_file_tail(SendBuf::from(vec![b'b'; 100])),
            "the declared length"
        );
        assert!(!c.tail_active(), "the last chunk retires the tail");
        assert_eq!(c.queued_bytes(), 300, "both chunks queued, nothing else");
    }

    /// The pool outlives the body that minted it. A connection serving many
    /// file responses mints `FILE_TAIL_BUFS` buffers **once** and cycles
    /// them for the rest of its life. Scoped to `FileTail` instead, every
    /// `ReplyFile` started from an empty pool and minted again - two fresh
    /// allocations per response, and `fs_body_chunk` is a megabyte in a
    /// realistic deployment.
    #[cfg(all(feature = "net-server", feature = "uring-fs"))]
    #[test]
    fn chunk_buffers_outlive_the_body_that_minted_them() {
        let mut c = Connection::new(ClientAddr::Unix { cred: None }, (), 8);
        let file = || {
            let fd: std::os::fd::OwnedFd =
                std::fs::File::open("/dev/null").expect("open").into();
            crate::uring_fs::File::new(crate::sync::Arc::new(fd))
        };
        let serve = |c: &mut Connection<()>, buf: SendBuf| {
            c.enqueue_file_chunk(buf, true);
            c.finish_file_tail();
            assert_eq!(c.arm_send(), 4);
            let _ = c.advance_sent(4);
        };

        // A body claims a share, and the flush gives it back - so the
        // next body starts from the same place however many ran before it.
        for round in 0..3 {
            c.install_file_tail(file(), 0, 4);
            assert!(c.tail_claim_chunk(), "round {round}: claimed");
            assert!(c.tail_claim_chunk(), "round {round}: and again");
            assert!(!c.tail_claim_chunk(), "round {round}: capped at two");
            c.tail_release_chunk();
            serve(&mut c, SendBuf::from(b"aaaa".to_vec()));
            assert_eq!(
                c.chunk_out, 0,
                "round {round}: the flush released the share"
            );
        }
    }

    /// A chunk can still be flushing when its tail retires. Its ring
    /// buffer has to come back anyway: conditioning the release on a tail
    /// being installed strands the buffer in the pool forever, where it can
    /// be neither reissued nor freed.
    #[cfg(all(feature = "net-server", feature = "uring-fs"))]
    #[test]
    fn a_chunk_outliving_its_tail_still_frees_its_buffer() {
        let mut c = Connection::new(ClientAddr::Unix { cred: None }, (), 8);
        let fd: std::os::fd::OwnedFd =
            std::fs::File::open("/dev/null").expect("open").into();
        let file = crate::uring_fs::File::new(crate::sync::Arc::new(fd));
        c.install_file_tail(file, 0, 4);
        assert!(c.tail_claim_chunk());
        // SAFETY: a test buffer that outlives the segment.
        let buf = Box::leak(Box::new([b'a'; 4]));
        let seg = unsafe { SendBuf::pooled(buf.as_mut_ptr(), 4, 7) };
        c.enqueue_file_chunk(seg, true);
        // The tail retires with its chunk still queued, and nothing follows
        // it - so at the flush there is no tail to hand anything to.
        c.finish_file_tail();
        assert!(!c.tail_active(), "no successor");
        assert_eq!(c.arm_send(), 4);
        let p = c.advance_sent(4);
        assert_eq!(c.chunk_out, 0, "the share came back");
        assert_eq!(p.freed, 1, "and the buffer id rode out to the pool");
        assert_eq!(p.freed_bids[0], 7, "the one the segment held");
    }
}
