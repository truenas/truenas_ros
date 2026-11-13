//! Per-connection state and the `user_data` completion-routing codec.
//!
//! A [`Connection`] owns every buffer the kernel touches on its behalf, the receive buffer, the queued send PDUs and
//! the send gather's `iovec`s and `msghdr`, plus the caller's per-connection state `U`. Connections are stored boxed in
//! the server's slab, so the kernel-visible pointers set up here stay valid from SQE submission until the matching CQE.
//!
//! A message is read in phases. The caller's header framer is consulted on the accumulated bytes, then the
//! frame-declared body is read, then the delivered message is drained and any pipelined remainder is framed again.

#[cfg(feature = "net-server")]
use super::bodypool;
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
    /// A `SO_PEERCRED` fetch (`URING_CMD`) between accept and the accept handler, when `unix_peercred` is enabled.
    Cred = 9,
    /// A `SHUTDOWN` that precedes a connection's `CLOSE`, forcing the peer's FIN out immediately (a bare `CLOSE` of a
    /// direct descriptor can defer the socket's teardown while another connection's op pins the ring's resource node).
    Shutdown = 10,
    /// A `SO_PEERNAME` fetch (`URING_CMD`) between a TCP accept and the accept handler - per-connection, race-free peer
    /// addresses.
    Peername = 11,
    /// A `FIXED_FD_INSTALL` that materializes a real fd for a kTLS listener's connection, furnished to the consumer's
    /// handshake worker.
    FdInstall = 12,
    /// A backoff `TIMEOUT` after a transient accept error, whose completion re-arms that listener's multishot accept
    /// (the slot field is the listener index) - avoids a hot spin under resource pressure.
    AcceptRetry = 13,
    /// A standalone `TIMEOUT` bounding a `TlsParked` slot's handshake; on expiry, if the slot is still parked, it is
    /// shed (`tls_handshake_timeout`).
    HandshakeTimeout = 14,
    /// A `FIXED_FD_INSTALL` for a `body`-handler connection **detach** - like `FdInstall` but from a `Serving` slot,
    /// furnishing the real fd to the consumer's detach worker (`Response::Detach`).
    DetachInstall = 15,
    /// An `IORING_OP_SPLICE` moving a framed message body from the connection's socket straight to a consumer fd
    /// (`Framing::SpliceBody`), zero-copy.
    SpliceRecv = 16,
    /// A one-shot `POLL_ADD` for `POLLIN` on a splicing connection's socket, armed when the body splice returned
    /// `-EAGAIN`. Its completion resubmits the splice for the remainder.
    SplicePoll = 17,
    /// The `LINK_TIMEOUT` linked to a recv as its idle or request clock. Kept apart from `LinkTimeout` because a
    /// cancelled `MSG_WAITALL` recv that had consumed bytes completes with `res = done_io > 0`, the same as a peer FIN
    /// mid-frame, and only this CQE tells a timeout (`-ETIME`) from a truncation (`on_recv_clock`).
    RecvClock = 18,
    /// A standalone `TIMEOUT` bounding a kTLS body splice's inactivity. The kernel arms a linked timeout only after the
    /// head's blocking `issue()` returns, so a blocking kTLS splice cannot carry a `LINK_TIMEOUT`, and this watchdog
    /// cancels the splice with `ASYNC_CANCEL` instead (`arm_splice_deadline`).
    SpliceDeadline = 19,
    /// An `IORING_OP_CONNECT` establishing an outbound connection on a socket installed into the pool. Client-only, and
    /// the server's `dispatch` routes it to `unreachable!`.
    Connect = 20,
    /// A backoff `TIMEOUT` for a recv parked on an exhausted buffer pool (`recv_shortage_retry`), whose completion
    /// re-pumps the connection. Server-only, and not counted in `conn.ops`.
    RecvRetry = 21,
    /// A standalone `TIMEOUT` bounding the **total** receipt of one message (`ServerConfig::max_receipt_time`), armed
    /// as the message's first byte lands and retired as it is delivered. Server-only, and not counted in `conn.ops`.
    ReceiptDeadline = 22,
    /// The ring's periodic maintenance `TIMEOUT` (server-only): its completion rebalances the buffer pools - the one
    /// observation quiet rings get, since pressure rides completions and silence has none -- and re-arms itself.
    Maintain = 23,
    /// An `IORING_OP_MSG_RING` sending an accepted connection's descriptor to the ring of a spread with the fewest
    /// connections (server-only). The slot field is this ring's slot and the generation field the listener index.
    Handoff = 24,
    /// The completion another ring's `Handoff` posts here: `res` is the slot the kernel installed the connection in,
    /// and the slot field is the listener index (server-only). Its tag is
    /// [`TAG_POSTED`](crate::uring::user_data::TAG_POSTED), since nothing on this ring staged it.
    Handed = crate::uring::user_data::TAG_POSTED,
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
            21 => Op::RecvRetry,
            22 => Op::ReceiptDeadline,
            23 => Op::Maintain,
            24 => Op::Handoff,
            crate::uring::user_data::TAG_POSTED => Op::Handed,
            _ => return None,
        })
    }
}

/// Encode `(op, slot, generation)` into an SQE `user_data` token - the stream vocabulary over the shared raw codec.
/// Stream tags stay inside the `0x00..=0x7F` domain (`user_data::TAG_FS_DOMAIN` marks the other half).
pub(crate) fn pack(op: Op, slot: u32, generation: u32) -> u64 {
    pack_raw(op as u8, slot, generation)
}

/// Decode a CQE `user_data` token. `op` is `None` for an unrecognized tag.
pub(crate) fn unpack(user_data: u64) -> (Option<Op>, u32, u32) {
    let (tag, slot, generation) = unpack_raw(user_data);
    (Op::from_u8(tag), slot, generation)
}

/// What one outgoing PDU is, for read-ahead accounting. A vectored reply is several PDUs but one logical response, so
/// only its final segment retires the request's `outstanding` slot; the earlier segments are `ReplyPart` and count as
/// neither a reply nor a push.
#[derive(Clone, Copy)]
enum SendKind {
    /// The last (or only) segment of a request reply: retires one read-ahead slot and tallies one reply.
    ReplyLast,
    /// A non-final segment of a vectored reply (e.g. the head): already part of a reply the final segment will retire,
    /// so it tallies nothing.
    ReplyPart,
    /// An out-of-band pushed PDU.
    Push,
}

/// A connection's hold on a pool buffer: which buffer, and where it lives.
///
/// Raw because the pool owns the allocation and outlives every connection drawing from it - `Reactor` declares `table`
/// before `recv_bufs`, so connections drop first - and because `BufPool::rebalance` never retires a group while any
/// buffer is lent, which a live claim counts as.
#[derive(Clone, Copy, Debug)]
pub(crate) struct RecvClaim {
    /// The buffer id to hand back.
    pub(crate) bid: u16,
    /// Start of the buffer's storage.
    pub(crate) ptr: *mut u8,
    /// How much it holds.
    pub(crate) cap: usize,
}

/// What storage the reactor claimed from the ring's body pool owes the pool as it leaves, the held licence the claim's
/// miss recorded and the bytes the claim put on the pool's count of held storage (`BodyPool::claim_held`). Zero for
/// storage that came from elsewhere.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct Ticket {
    pub(crate) licence: usize,
    pub(crate) bytes: usize,
}

/// Storage going home to the ring's body pool with the ticket its claim recorded ([`BodyPool::claim_held`]).
///
/// [`BodyPool::claim_held`]: super::bodypool::BodyPool::claim_held
#[cfg(feature = "net-server")]
pub(crate) type HeldStorage = (Vec<u8>, Ticket);

/// The bytes a connection has accumulated for the message it is framing.
///
/// The storage is a buffer drawn from the registered provided-buffer ring (`crate::uring::bufring`) while a message is
/// arriving, or owned storage where no pool is behind the role. It derefs to `[u8]`, so only the mutating operations
/// are named here.
#[derive(Default)]
pub(crate) struct RecvBuf {
    /// Backing storage when no pool is behind this role - the client, and a server built without one. Empty and
    /// unallocated while a claim is held, so it costs nothing to carry.
    owned: Vec<u8>,
    /// The pool buffer being accumulated into, when one is held.
    claim: Option<RecvClaim>,
    /// Set when this connection draws from a pool, so an armed recv with no claim acquires one rather than growing
    /// `owned`.
    pooled: bool,
    /// Set when a leased write took this claim: the buffer's bytes are a file write's iovec until its CQE, so consume
    /// surrenders the claim to the op instead of draining and recycling it. A `Cell` because the handler that arms the
    /// write holds the body - a shared borrow of this same connection - for its whole run.
    #[cfg(all(feature = "net-server", feature = "uring-fs"))]
    write_leased: std::cell::Cell<bool>,
    /// Bytes filled. Tracked separately from `owned.len()` because the kernel writes into space reserved past the tail
    /// and the count only becomes known at completion.
    filled: usize,
    /// The ticket a promote's claim recorded ([`BodyPool::claim_held`](super::bodypool::BodyPool::claim_held)), carried
    /// until `owned` goes home so a receipt spanning maintenance ticks keeps the licence it is owed, and the count
    /// loses what the claim put on it.
    #[cfg(feature = "net-server")]
    owned_ticket: Ticket,
}

impl RecvBuf {
    /// Bytes filled.
    pub(crate) fn len(&self) -> usize {
        self.filled
    }

    /// Draw from the pool rather than owning storage.
    pub(crate) fn set_pooled(&mut self) {
        self.pooled = true;
    }

    /// Fall back to owning storage, for the rest of this connection's life.
    ///
    /// A pool that will not grow is memory pressure, not a reason to shed a connection. One-way per connection, so a
    /// pool under sustained pressure is not retried on every read, and the next accepted connection starts pooled
    /// again.
    pub(crate) fn set_owned(&mut self) {
        self.pooled = false;
    }

    /// Whether an armed recv must acquire a buffer, being pool-backed with none held and no destination of its own. The
    /// submit answers this by setting `IOSQE_BUFFER_SELECT`.
    ///
    /// **`filled` alone cannot say so.** A promote off a spliced body's held claim copies nothing yet leaves storage of
    /// its own, which a fresh claim would orphan, and `submit_recv` decides the select before it promotes. Non-empty
    /// `owned` is the mark, which `promote_for` sets and only `release`, `take_owned` and `forfeit_owned` clear.
    pub(crate) fn needs_buffer(&self) -> bool {
        self.pooled && self.claim.is_none() && self.filled == 0 && self.owned.is_empty()
    }

    /// Adopt the buffer a completion selected.
    pub(crate) fn install(&mut self, claim: RecvClaim) {
        debug_assert!(self.claim.is_none(), "a claim would be leaked");
        self.claim = Some(claim);
        self.filled = 0;
    }

    /// The message at the front of the buffer, split for a delivery, the header as it is and the body lent mutably, so
    /// that a handler may transform the message where it lies.
    pub(crate) fn deliver_mut(&mut self, header_len: usize, body_len: usize) -> (&[u8], &mut [u8]) {
        let bytes = filled_mut(self.claim.as_ref(), &mut self.owned, self.filled);
        let (header, rest) = bytes.split_at_mut(header_len);
        // A placed body left the buffer, so the rest may be shorter than the body, and the delivery takes the placed
        // one instead.
        let end = body_len.min(rest.len());
        (header, &mut rest[..end])
    }

    /// The claim as a write lease over `extent` bytes, as a delivery makes one, for the tests of the lease.
    #[cfg(all(test, feature = "net-server", feature = "uring-fs"))]
    pub(crate) fn write_lease(&self, extent: usize) -> Option<crate::uring_fs::core::RecvWriteLease<'_>> {
        lease_of(self.claim.as_ref(), &self.write_leased, extent)
    }

    /// As [`deliver_mut`](Self::deliver_mut), plus the claim as a write lease over the message, for a delivery's fs
    /// facade, in one borrow of the buffer's parts, since the lease borrows the flag alone and the body the bytes.
    #[cfg(all(feature = "net-server", feature = "uring-fs"))]
    pub(crate) fn deliver_leased_mut(
        &mut self,
        header_len: usize,
        body_len: usize,
    ) -> (&[u8], &mut [u8], Option<crate::uring_fs::core::RecvWriteLease<'_>>) {
        let extent = header_len + body_len;
        let lease = lease_of(self.claim.as_ref(), &self.write_leased, extent);
        let bytes = filled_mut(self.claim.as_ref(), &mut self.owned, self.filled);
        let (header, rest) = bytes.split_at_mut(header_len);
        let end = body_len.min(rest.len());
        (header, &mut rest[..end], lease)
    }

    /// Give the buffer up, for the caller to hand back to the pool. Refused while anything is buffered, since the bytes
    /// live in it.
    ///
    /// Also surrenders storage a promote left, with its ticket, for the ring's body pool to keep or free, so one
    /// oversized message does not leave the connection carrying its buffer for the rest of its life.
    pub(crate) fn release(&mut self) -> (Option<RecvClaim>, Option<(Vec<u8>, Ticket)>) {
        if self.filled > 0 {
            return (None, None);
        }
        #[cfg(all(feature = "net-server", feature = "uring-fs"))]
        if self.write_leased.get() {
            // A write op owns the buffer; it will be released through the completion's lease, never through the
            // connection.
            return (None, None);
        }
        let surplus = (self.pooled && !self.owned.is_empty()).then(|| {
            let owned = std::mem::take(&mut self.owned);
            (owned, self.take_owned_ticket())
        });
        (self.claim.take(), surplus)
    }

    /// The ticket riding `owned`, taken, and empty where no pool exists.
    fn take_owned_ticket(&mut self) -> Ticket {
        #[cfg(feature = "net-server")]
        {
            std::mem::take(&mut self.owned_ticket)
        }
        #[cfg(not(feature = "net-server"))]
        {
            Ticket::default()
        }
    }

    /// Teardown's take of the promoted/owned storage, licence included: the connection is going away, and storage
    /// dropped on the floor is one warm buffer out of the pool's loop per close.
    #[cfg(feature = "net-server")]
    pub(crate) fn forfeit_owned(&mut self) -> Option<(Vec<u8>, Ticket)> {
        let ticket = std::mem::take(&mut self.owned_ticket);
        // A licence with no storage under it is still handed over, since `give_held` pots it before it looks at the
        // capacity, so an empty `Vec` carries it home. `promote_for` writes the licence and the capacity separately, so
        // the two can come apart.
        (self.owned.capacity() > 0 || ticket != Ticket::default()).then(|| (std::mem::take(&mut self.owned), ticket))
    }

    /// Whether the buffer in hand covers a whole message of `total` bytes.
    ///
    /// Only true of a pool buffer. Owned storage grows to whatever is asked of it, and answering `true` there would
    /// suppress placement for every connection.
    pub(crate) fn covers(&self, total: usize) -> bool {
        self.claim.is_some_and(|c| c.cap >= total)
    }

    /// Move accumulation off a pool buffer that cannot hold what is about to be read, handing the buffer back for the
    /// caller to return.
    ///
    /// Promoting is what lets a pool buffer stay smaller than the largest message the server accepts. The copy is
    /// bounded by the buffer, at most one buffer's worth once, on the read that overflows it, and the connection then
    /// behaves as an unpooled one for the rest of the message.
    ///
    /// Chaining buffers instead, as SPDK's uring sock does (`module/sock/uring/uring.c`, `sock->recv_stream`), does not
    /// transfer here. A head scan needs the bytes contiguous, so a chain would be joined before framing, and the join
    /// is the copy the ring exists to avoid.
    pub(crate) fn promote_for(
        &mut self,
        at: usize,
        want: usize,
        seed: impl FnOnce() -> Option<(Vec<u8>, Ticket)>,
    ) -> Option<RecvClaim> {
        // Unreachable while a leased write holds the claim - no recv is armed between the write's submit and the
        // delivery's consume - and moving the bytes out from under the DMA would tear the write, so fail closed on the
        // impossible rather than corrupt on it.
        #[cfg(all(feature = "net-server", feature = "uring-fs"))]
        if self.write_leased.get() {
            debug_assert!(false, "promote under a leased write");
            return None;
        }
        let c = self.claim?;
        if at.saturating_add(want) <= c.cap {
            return None;
        }
        // Reused storage from the ring's body pool where one waits. Deferred to here so a call that promotes nothing
        // claims nothing, since a claim is a demand signal and a false one grows the pool. A missed claim's ticket
        // rides the storage (`owned_ticket`) until it goes home.
        #[cfg_attr(not(feature = "net-server"), allow(unused_variables))]
        if let Some((s, ticket)) = seed() {
            debug_assert!(s.is_empty(), "a reused body kept bytes");
            self.owned = s;
            #[cfg(feature = "net-server")]
            {
                self.owned_ticket = ticket;
            }
        }
        self.owned.clear();
        // Exact, since a pooled `Vec` grown amortized ends at twice its old capacity, and the spare is never written
        // but charged in full to the byte budget.
        self.owned.reserve_exact(at.saturating_add(want));
        // SAFETY: `filled <= cap` by construction, and the pool outlives this connection - see `RecvClaim`.
        self.owned
            .extend_from_slice(unsafe { std::slice::from_raw_parts(c.ptr, self.filled) });
        // Sized here rather than left to `reserve_at`, so non-empty storage is the mark `needs_buffer` reads even when
        // the promote copies nothing. It only ever grows because `at` must equal the `filled` just copied, and a caller
        // that disagreed would resize below those bytes.
        debug_assert_eq!(at, self.filled, "a promote at the wrong offset");
        self.owned.resize(at.saturating_add(want), 0);
        self.claim = None;
        Some(c)
    }

    /// Give the buffer up whatever is in it - the connection is going away, so the bytes have no reader left.
    ///
    /// `None` while a leased write holds the buffer: the op's completion releases the id, and handing it back here as
    /// well would let the pool reissue it under the DMA.
    pub(crate) fn forfeit(&mut self) -> Option<RecvClaim> {
        self.filled = 0;
        #[cfg(all(feature = "net-server", feature = "uring-fs"))]
        if self.write_leased.get() {
            self.claim = None;
            return None;
        }
        self.claim.take()
    }

    /// Make room for `want` bytes past `at`, and answer how many were granted.
    ///
    /// A claim cannot grow, so its grant is capped at what remains of it. The reactor never asks a claim for more,
    /// since an overrunning read is promoted first (`promote_recv_buffer`) and an exact read larger than one pool
    /// buffer never takes one (`submit_recv`). The cap stays because the alternative is a write past the buffer, and
    /// the caller treats a short grant on an exact read as fatal. Owned storage grows, so its grant is always the full
    /// `want`.
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

    /// Destination for a recv writing at `at`. Null when a buffer has yet to be acquired, since the kernel supplies the
    /// address under `IOSQE_BUFFER_SELECT`.
    pub(crate) fn write_ptr(&mut self, at: usize) -> *mut u8 {
        match &self.claim {
            // SAFETY: `at` is at most the claim's `cap`, since `arm_recv` starts it at `filled` and a continuation
            // advances it only inside the range `reserve_at` granted (`armed_within`).
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

    /// Whether a recv armed to write `[at, at + want)` stays inside the storage behind it, the claim's `cap` for a pool
    /// buffer or `owned.len()` for owned storage. The kTLS continuation re-arms without a fresh reserve, so this checks
    /// that its offset has not walked past the buffer.
    pub(crate) fn armed_within(&self, at: usize, want: usize) -> bool {
        let end = match at.checked_add(want) {
            Some(e) => e,
            None => return false,
        };
        match &self.claim {
            Some(c) => end <= c.cap,
            None => end <= self.owned.len(),
        }
    }

    /// Drop `n` bytes from the front, keeping any pipelined remainder - the next message then starts at offset zero.
    pub(crate) fn drain_front(&mut self, n: usize) {
        // A leased claim's bytes are a write op's iovec, so a memmove would tear the write and recycling the buffer
        // would hand it to the next recv under the DMA. The claim goes to the op, whose completion releases the id, and
        // only the pipelined remainder is copied out to owned storage. On the streaming hot path that remainder is
        // empty.
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
                // SAFETY: `[n, filled)` lies within the claim, which the write op keeps alive past this copy.
                self.owned
                    .extend_from_slice(unsafe { std::slice::from_raw_parts(c.ptr.add(n), rest) });
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
                // SAFETY: both ranges lie within `filled <= cap`, and `copy` is the overlapping form.
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

    /// The whole buffer, moved out with its ticket, the delivery handoff that gives a body-only message's storage to
    /// the handler rather than copying it. `None` for a pool-backed buffer, whose memory belongs to the ring.
    ///
    /// **The ticket goes with the storage**, as it does from `release` and `forfeit_owned`, and the delivery pots its
    /// licence as it does a placed body's ([`BodyPool::receipt_done`](super::bodypool::BodyPool::receipt_done)).
    /// Storage promoted off a pool buffer reaches here once `set_owned` clears `pooled`, and a licence dropped here is
    /// demand the pool met and never counted.
    pub(crate) fn take_owned(&mut self) -> Option<(Vec<u8>, Ticket)> {
        if self.claim.is_some() || self.pooled {
            return None;
        }
        let mut v = std::mem::take(&mut self.owned);
        v.truncate(self.filled);
        self.filled = 0;
        Some((v, self.take_owned_ticket()))
    }
}

/// The claim as a write lease over `extent` bytes, for a delivery's fs facade, borrowing the flag `taken` alone.
#[cfg(all(feature = "net-server", feature = "uring-fs"))]
fn lease_of<'a>(
    claim: Option<&RecvClaim>,
    taken: &'a std::cell::Cell<bool>,
    extent: usize,
) -> Option<crate::uring_fs::core::RecvWriteLease<'a>> {
    // A zero extent is a redelivery, whose bytes were consumed at its first delivery. Minted anyway, the lease names
    // the claim and `pwritev2_from`'s bounds test admits the empty `Body` at its base, so a write with no bytes takes
    // the claim a read-ahead recv is armed into. `take_body_handoff` excludes the same case with its `body_len > 0`.
    if extent == 0 {
        return None;
    }
    let c = claim?;
    Some(crate::uring_fs::core::RecvWriteLease {
        ptr: c.ptr,
        // Bounded to the delivered message, never the buffer, since bytes past the extent are the next pipelined
        // request's, or a previous holder's, as a recycled buffer is not zeroed, so a slice reaching into them must
        // fall to the copy path rather than be committed into a stored object.
        cap: c.cap.min(extent),
        bid: c.bid,
        taken,
    })
}

/// The `filled` bytes of the claim, or of `owned` without one, mutably.
fn filled_mut<'a>(claim: Option<&RecvClaim>, owned: &'a mut [u8], filled: usize) -> &'a mut [u8] {
    match claim {
        // SAFETY: as the shared view below, and the kernel writes only past `filled`, so the bytes a handler changes
        // are its own message's.
        Some(c) => unsafe { std::slice::from_raw_parts_mut(c.ptr, filled) },
        None => {
            let end = filled.min(owned.len());
            &mut owned[..end]
        }
    }
}

impl std::ops::Deref for RecvBuf {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        match &self.claim {
            // SAFETY: `filled` never exceeds the claim's capacity, and the pool outlives this connection - see
            // `RecvClaim`.
            Some(c) => unsafe { std::slice::from_raw_parts(c.ptr, self.filled) },
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
    /// A file-tail chunk, whose flush gives this connection's share of the ring back and its buffer id to the pool.
    /// Never a consumer PDU.
    #[cfg(all(feature = "net-server", feature = "uring-fs"))]
    reclaim: bool,
    /// Where a segment marked recycled goes as this entry drops, whether it was sent or its connection went first.
    #[cfg(feature = "net-server")]
    home: Option<super::bodypool::Home>,
}

#[cfg(feature = "net-server")]
impl Drop for SendItem {
    fn drop(&mut self) {
        if let Some(home) = self.home.take()
            && let Some(v) = self.bytes.recycled_mut()
        {
            home.give(std::mem::take(v));
        }
    }
}

/// Chunk buffers a file-sourced response body cycles through: one being read into while the previous one sends. Fixed
/// rather than configurable: on ZFS every ring read is an io-wq punt, so a deeper pipeline only deepens the bounded
/// worker class's queue - the chunk *size* is the knob (`fs_body_chunk`), not the count.
#[cfg(all(feature = "net-server", feature = "uring-fs"))]
pub(crate) const FILE_TAIL_BUFS: u8 = 2;

/// A `Response::ReplyFile` that arrived while another body was still streaming, held until that one retires. Two tails'
/// chunks would interleave on the wire, so a second body queues behind the current one through the same diversion every
/// other PDU uses.
///
/// Each queued body holds its fd open until its turn, minutes for a large range on a slow link, so the process-wide
/// hold is bounded only by `max_in_flight_requests` x `pool_size`, which `ServerConfig::validate` does not check
/// against `RLIMIT_NOFILE`. Queueing rather than shedding is deliberate, since the first response's head is already on
/// the wire, so a consumer serving file bodies to pipelined clients sizes that product against its own fd limit.
#[cfg(all(feature = "net-server", feature = "uring-fs"))]
pub(crate) struct PendingFile {
    pub(crate) head: Vec<u8>,
    pub(crate) file: crate::uring_fs::File,
    pub(crate) offset: u64,
    pub(crate) len: u64,
    pub(crate) close: bool,
}

/// One entry in a tail's diversion, in arrival order: bytes already framed, or a file body still to be installed. Both
/// kinds have to share one list - splitting them would let a reply queued after a deferred body reach the wire before
/// it, which for a pipelined peer is a response out of order.
#[cfg(all(feature = "net-server", feature = "uring-fs"))]
enum PendingItem {
    Pdu(SendItem),
    File(PendingFile),
}

/// A file-sourced response body mid-stream (`Response::ReplyFile`): the reply path reads `unread` more bytes from
/// `file` in bounded chunks, each entering the send queue as its own segment, the final one `ReplyLast` so the reply
/// retires exactly once. While a tail is active every OTHER enqueue (a push, a deferred reply for a pipelined request)
/// is diverted to `pending` - its bytes would otherwise land between two chunks of this body on the wire - and released
/// in arrival order once the last chunk is queued.
#[cfg(all(feature = "net-server", feature = "uring-fs"))]
pub(crate) struct FileTail {
    /// The source file. Each in-flight read parks its own fd clone, so dropping this with the tail (or the connection)
    /// never closes the fd under a read.
    pub(crate) file: crate::uring_fs::File,
    /// File offset of the next read.
    pub(crate) next_offset: u64,
    /// Bytes of the declared body no read has returned yet. Every read is clamped to `min(chunk, unread)`: the header's
    /// Content-Length is a snapshot, and an unclamped read of a file grown mid-send would push bytes past the declared
    /// length - which a keep-alive peer parses as the start of the next response (a framing desync).
    pub(crate) unread: u64,
    /// A pump read is in flight. At most one: chunks must enter the send queue in offset order, and a single
    /// outstanding read makes that order structural instead of re-sorted.
    pub(crate) reading: bool,
    /// PDUs and deferred file bodies diverted while this tail is active, in arrival order (see the struct docs).
    pending: Vec<PendingItem>,
    /// The connection has an entry in the reply path's parked list, waiting for an fs op slot. **Set exactly when the
    /// entry is pushed and cleared exactly when it is popped**, since it is the list's dedup key. Cleared anywhere
    /// else, one connection is recorded twice, which unbounds a list the connection count should cap and breaks its
    /// longest-waiting-first order.
    ///
    /// It does **not** say whether a read is in flight, which `reading` answers. A tail driven by another path keeps
    /// the flag until `redrive_parked_tail` pops its entry.
    pub(crate) parked: bool,
}

/// A connection's receive transport, installed at setup. Selects how recvs are submitted and completed, while sends are
/// unchanged since kTLS encrypts transparently.
pub(crate) enum Transport {
    /// Plain TCP/unix: `IORING_OP_RECV` straight into the destination.
    Plain,
    /// Kernel TLS: `IORING_OP_RECVMSG` with a control buffer, so the record type can be read - a plain recv returns
    /// `-EIO` on any non-data record. Boxed so plain connections carry none of this weight.
    Ktls(Box<KtlsRecv>),
}

/// A control-message buffer for a kTLS recv. `CMSG_SPACE(1)` is 24 bytes on 64-bit Linux, and 64 leaves headroom so the
/// record-type cmsg is never truncated (`MSG_CTRUNC`).
const KTLS_CONTROL_LEN: usize = 64;

/// The `RECVMSG` scaffolding for a kTLS connection: a one-entry gather at the same destination a plain recv would use,
/// plus a control buffer the kernel fills with the `TLS_GET_RECORD_TYPE` message.
pub(crate) struct KtlsRecv {
    iov: libc::iovec,
    msg: libc::msghdr,
    control: Box<[u8; KTLS_CONTROL_LEN]>,
}

impl KtlsRecv {
    fn new() -> Box<KtlsRecv> {
        Box::new(KtlsRecv {
            // SAFETY: iovec/msghdr are plain data; zeroed is valid and both are re-pointed by `arm` before any kernel
            // use.
            iov: unsafe { std::mem::zeroed() },
            msg: unsafe { std::mem::zeroed() },
            control: Box::new([0u8; KTLS_CONTROL_LEN]),
        })
    }

    /// Point the `msghdr` at `[base, base+len)` for the data, with the control buffer reset to full length for the
    /// record-type cmsg.
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

    /// The TLS record content type of the just-completed recv, read from the `TLS_GET_RECORD_TYPE` control message.
    /// `None` if the control buffer was truncated (`MSG_CTRUNC`) or carried no such message - either way the caller
    /// treats a non-`application_data` result as a control record.
    fn record_type(&self) -> Option<u8> {
        if self.msg.msg_flags & libc::MSG_CTRUNC != 0 {
            return None;
        }
        // SAFETY: `msg` was just used by the kernel for a RECVMSG; its control region (`msg_control`/`msg_controllen`)
        // is initialized by the kernel and the CMSG_* macros walk it within those bounds.
        unsafe {
            let mut cmsg = libc::CMSG_FIRSTHDR(&self.msg);
            while !cmsg.is_null() {
                if (*cmsg).cmsg_level == crate::uring::sys::SOL_TLS
                    && (*cmsg).cmsg_type == crate::uring::sys::TLS_GET_RECORD_TYPE
                {
                    return Some(*libc::CMSG_DATA(cmsg));
                }
                cmsg = libc::CMSG_NXTHDR(&self.msg, cmsg);
            }
        }
        None
    }
}

/// One accepted connection: the caller's state `U` plus all memory the kernel accesses on its behalf.
///
/// A recv and a send can be in flight at once in pipelined mode. The two directions are independent, since the recv
/// destination rides in its own SQE and the send gather has its own `iovec`s and `msghdr`.
pub(crate) struct Connection<U> {
    pub peer: ClientAddr,
    pub state: U,
    // ---- recv side ----
    // Accumulated message bytes (+ pipelined remainder). Pool-backed when a pool is behind this role; owned otherwise.
    // See `RecvBuf`.
    recv_buf: RecvBuf,
    header_len: usize, // current message's header length (from the Complete verdict)
    body_len: usize,   // current message's body length
    recv_at: usize,    // destination offset the in-flight recv writes to
    recv_want: usize,  // bytes the in-flight recv targets
    recv_exact: bool,  // MSG_WAITALL (exact) vs chunk read
    // The receive transport, installed at setup: `Plain` (RECV) or `Ktls` (RECVMSG with a record-type control buffer).
    // Sends are transport-agnostic.
    pub transport: Transport,
    // ---- placed body ----
    // A body being read into its own allocation instead of `buf` (bodies at or over
    // `ServerConfig::body_placement_threshold`). The kernel writes into the Vec's spare capacity; `finish_body_recv`
    // sets the length once the exact-count CQE proves it is initialized.
    body_buf: Option<Vec<u8>>,
    recv_into_body: bool, // the in-flight recv targets `body_buf`, not `buf`
    /// The held body-pool licence `body_buf`'s missed claim recorded, riding the storage until it leaves custody - so a
    /// body arriving slower than the pool's maintenance tick keeps what it is owed.
    #[cfg(feature = "net-server")]
    body_ticket: Ticket,
    // ---- spliced body ----
    // A framed body spliced straight from the socket to a borrowed consumer fd (`Framing::SpliceBody`). `splicing` is
    // its own in-flight flag because a splice's SQE `fd` is the pipe, so `close_conn` cancels it by `user_data` rather
    // than by fd.
    pub splicing: bool, // an `IORING_OP_SPLICE` is in flight
    // Waiting on a `POLL_ADD` for the socket after a splice returned `-EAGAIN`. Unlike `splicing`, this op rides the
    // socket fd, so `close_conn`'s fd-keyed cancel reaches it.
    pub splice_polling: bool,
    pub splice_fd: RawFd,        // consumer destination fd (borrowed)
    pub splice_remaining: usize, // body bytes still to splice
    // kTLS-splice inactivity watchdog state (a standalone `TIMEOUT`; see `arm_splice_deadline` for the
    // one-per-connection idempotency invariant). `splice_watermark` is the remaining byte count at the last arm; the
    // next expiry re-arms if it dropped (progress) or cancels the splice if unchanged (stall).
    pub splice_deadline_armed: bool,
    /// Watchdogs retired but not yet reaped. A retire clears the flag and only stages the cancel, so the old timer's
    /// `-ETIME` can arrive after the successor is armed, with the same `user_data` since that carries the slot's
    /// generation. This count tells them apart. Each retired timer owes exactly one completion, and they come back in
    /// order, since the successor is armed later with the same duration.
    pub splice_deadline_owed: u32,
    pub splice_watermark: usize,
    /// `splice_remaining` when the current body opened, or when its last receipt budget was renewed, so an expiry can
    /// tell a window's worth of progress from a stall. Only the splice path sets it; a buffered message is bounded
    /// whole and needs no mark. See `ServerConfig::receipt_window_bytes`.
    pub receipt_window_mark: usize,
    // ---- send side ----
    // Outgoing PDUs (request replies and pushes) queued FIFO in production order; the leading PDUs are (partially) in
    // flight while `sending`. Enqueuing more while a send is in flight is safe: the armed `Vec`s' heap data does not
    // move even if the deque reallocates.
    send_queue: VecDeque<SendItem>,
    queued_bytes: usize, // total bytes across `send_queue` (backlog bound)
    /// The ring's body pool, where a reply marked recycled goes once sent or dropped. Set by the server as it installs
    /// the connection.
    #[cfg(feature = "net-server")]
    pub(crate) body_pool: Option<super::bodypool::PoolHandle>,
    front_sent: usize,  // bytes of the front PDU already sent
    armed_bytes: usize, // bytes of the in-flight gather still unsent
    // The writev gather (up to `max_send_coalesce` entries). Heap-allocated so the kernel-visible array address is
    // stable for the life of the op.
    send_iovs: Box<[libc::iovec]>,
    send_msg: libc::msghdr,
    // ---- scheduling / lifecycle (owned by the server's state machine) ----
    pub recving: bool, // a recv op is in flight
    // The in-flight recv is an idle header read (armed with nothing buffered -- parked for the next request). Captured
    // at arm time - a property of the armed read; a kTLS continuation clears it (mid-message is never idle).
    pub recv_idle: bool,
    // A send completed since the idle clock was last armed. The clock runs from recv arm time, so a fire whose interval
    // saw a completed send measured busy time, and `finish_failed_recv` re-arms a fresh clock instead of reaping.
    // Cleared each idle arm, set by `on_send_complete`.
    pub served_since_idle_arm: bool,
    // ---- recv clock pairing (short-read disambiguation) ----
    // Whether the in-flight recv carries a linked clock (`Op::RecvClock`). A cancelled `MSG_WAITALL` recv that had
    // consumed bytes looks like a peer FIN mid-frame, so classification waits for the clock's own CQE (`-ETIME` means
    // it fired). All three fields are set at recv arm time.
    pub recv_clock_armed: bool,
    // The current pair's clock CQE result, when it reaped before the recv's (CQE order within a pair is not
    // guaranteed): `Some(fired)`.
    pub recv_clock_fired: Option<bool>,
    // A short positive recv completion parked until its clock CQE resolves it, with the recv's `was_idle` and op, since
    // a fired clock on an active transfer resumes the read. The pump must not re-arm the recv side while set. Both CQEs
    // of a linked pair come from one task-work run, so the stash resolves in the same reap batch.
    pub recv_close_stash: Option<(bool, Op)>,
    // A `RecvRetry` backoff timer is pending for this connection's parked read. Set at arm, cleared when the timer's
    // CQE is consumed - the dedup that keeps a connection whose park is re-entered (another path pumped it meanwhile
    // and hit the dry pool again) at one live timer.
    pub recv_retry_armed: bool,
    // A `ReceiptDeadline` timer is in flight for the message this connection is receiving. The dedup key for the arm:
    // cleared by the cancel at delivery or by the expiry itself, and nowhere else.
    #[cfg(feature = "net-server")]
    pub receipt_deadline_armed: bool,
    /// Budgets retired but not yet reaped - see [`Connection::splice_deadline_owed`], which this mirrors exactly.
    #[cfg(feature = "net-server")]
    pub receipt_deadline_owed: u32,
    /// The read of this connection's placed body waits in the body pool's queue of what is held back for the ring's
    /// held bytes to fall under `ServerConfig::held_cap`. The queue's dedup key, set as the read is held and cleared as
    /// it is taken off the queue, and nowhere else.
    #[cfg(feature = "net-server")]
    pub(crate) read_held: bool,
    // A push overflowed `max_send_backlog` while the connection was detached (its worker owns the raw stream, so it
    // cannot be torn down mid-detach): evict with `SendBacklog` when the worker resumes it.
    pub evict_on_resume: bool,
    // A flush-close is pending. The connection's final PDU, if any, is queued, and it closes with this reason once the
    // send queue drains (`Response::ReplyClose`, `Deferred::reply_close`, `PushHandle::close`). While set the recv side
    // is retired, and later injected outcomes and pushes for this connection are dropped. On a detached connection it
    // is only marked, and the close lands at resume like `evict_on_resume`.
    pub close_on_flush: Option<CloseReason>,
    // The peer half-closed (`shutdown(SHUT_WR)`, or a plain close) while this connection still owed a response. It must
    // stay distinct from `close_on_flush`.
    //
    //   - it retires the recv side the same way, because a FIN re-completes a re-armed recv at once and re-pumping one
    //     spins the loop,
    //   - but it does **not** mean a teardown owns the slot. The reply is still coming, and `teardown_owns_slot()`
    //     drops a worker outcome, a redelivery or a push, so arming `close_on_flush` here would close with the reply
    //     never produced.
    //
    // The close lands from the send path once nothing is owed, and from `pump_gate` when the owed work ends with no
    // bytes on the wire (a one-way `Injected::Done`, an empty `Redeliver` or inline `Response::Reply`), since no send
    // completes there. Without that second arm the one-way case holds the slot and the fd for the life of the server.
    pub peer_closed: Option<CloseReason>,
    // The reason this connection began closing, stashed by `close_conn` for the client's `Event::Closed`. Net-client
    // only, since the server reports closes through its close hook.
    #[cfg(feature = "net-client")]
    pub close_reason: Option<CloseReason>,
    pub sending: bool, // a send op is in flight
    pub closing: bool, // being torn down; completions just decrement `ops`
    // A teardown is owed once the recv/send in flight at close time - cancelled there - have drained. Deferring the
    // index-freeing CLOSE until then keeps it the connection's LAST op, so the kernel can't reuse the descriptor's
    // index under a surviving op (a use-after-free - see `close_conn`).
    pub teardown_deferred: bool,
    pub teardown_shutdown_first: bool, // SHUTDOWN-first for the deferred teardown
    // A file-sourced response body mid-stream, driven by the server's reply path (`Response::ReplyFile`). Server-only:
    // a client never installs one, so its `tail_active()` is constantly false there.
    #[cfg(all(feature = "net-server", feature = "uring-fs"))]
    pub(crate) file_tail: Option<FileTail>,
    // The file body the retiring tail handed on, and whatever was queued behind it - both consumed by the reply path's
    // install, which is where a read can actually be issued.
    #[cfg(all(feature = "net-server", feature = "uring-fs"))]
    next_file: Option<PendingFile>,
    #[cfg(all(feature = "net-server", feature = "uring-fs"))]
    next_file_pending: Vec<PendingItem>,
    /// Chunk buffers this connection holds, one being read into and the rest queued or sending. Capped at
    /// [`FILE_TAIL_BUFS`], which is the whole backpressure, so a body cannot run ahead of the wire.
    ///
    /// **A count, not a pool.** The buffers belong to the reactor's ring and are shared by every connection on it, so
    /// buffer memory scales with the bodies moving rather than with the connection table.
    #[cfg(all(feature = "net-server", feature = "uring-fs"))]
    chunk_out: u8,
    // A deferred file body carries `close`. `close_on_flush` cannot be armed yet, since the body in front still streams
    // and the flush-close dry checks would belong to it, but the recv side must stop admitting requests now. Handed to
    // `close_on_flush` at install.
    #[cfg(all(feature = "net-server", feature = "uring-fs"))]
    deferred_close: bool,
    pub outstanding: u32, // delivered-but-not-yet-fully-sent requests (read-ahead cap)
    pub ops: u32,         // in-flight recv+send+close ops; free the slot only at 0
    next_req_id: u64,     // per-connection request id, assigned as requests deliver
    // Requests answered via `Response::Defer`, awaiting their worker's single outcome. A `Deferred` whose request is
    // not (or no longer) in this set is stale and its outcome is dropped - this is what makes a duplicate or outlived
    // `Deferred` inert rather than a double reply or bogus close.
    open_req_ids: Vec<u64>,
}

/// Outcome of a recv completion, from [`Connection::recv_result`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RecvOutcome {
    /// The armed read is satisfied (exact: full count; chunk: some bytes).
    Complete,
    /// kTLS only: a clean partial - the completion consumed the fully-arrived `application_data` records but the
    /// remainder is still in flight. The cursor advanced; re-arm for the rest.
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
    /// Bytes of the armed gather still unsent (> 0 only on a mid-flight error under `MSG_WAITALL`; the re-submit
    /// surfaces it).
    pub armed_remaining: usize,
    /// Ring buffer ids whose segments flushed, owed back to the pool. Only the reactor holds the pool, so they ride out
    /// to it here. Bounded by [`FILE_TAIL_BUFS`], which is what caps a connection's chunks.
    #[cfg(all(feature = "net-server", feature = "uring-fs"))]
    pub freed_bids: [u16; FILE_TAIL_BUFS as usize],
    /// How many of `freed_bids` are set.
    #[cfg(all(feature = "net-server", feature = "uring-fs"))]
    pub freed: u8,
}

#[cfg(test)]
mod tests;

mod connection;
