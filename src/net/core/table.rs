//! The connection table: one typed state machine per pool slot.
//!
//! A slot is always in exactly one [`SlotState`] state — the union makes the
//! "never a `Connection` and a pending peer fetch at once" invariant a type
//! rather than a discipline — and carries the generation that outlives every
//! state transition (bumped on free, so tokens minted for a recycled slot go
//! stale). Accessors here borrow only the reactor's `table` field, which is what
//! lets a stage hold a connection across a role callback (`self.core.table` vs
//! the role's disjoint `handlers`/framer field, so the callback runs while a
//! connection is borrowed).

use crate::net::core::conn::Connection;
use crate::net::core::protocol::ClientAddr;
#[cfg(feature = "net-client")]
use crate::net::core::protocol::ServerAddr;
#[cfg(feature = "net-client")]
use crate::net::core::sock::SockAddr;
#[cfg(feature = "net-client")]
use crate::net::core::sys::KernelTimespec;

/// The landing pad for a post-accept peer-identity fetch: stable boxed
/// storage the kernel writes while the `URING_CMD` is in flight, held in the
/// slot's [`SlotState::PeerFetch`](crate::net::core::table::SlotState) state between an accept and
/// its completion. Carries the listener index through to `finish_accept`.
/// (Peer identity is fetched per connection — never through a buffer shared
/// across accepts — so a burst of accepts cannot misattribute addresses.)
pub(crate) enum PendingPeer {
    /// `SO_PEERCRED` for a unix connection (`unix_peercred`).
    Cred {
        listener: u32,
        pad: Box<libc::ucred>,
    },
    /// `SO_PEERNAME` for a TCP connection.
    Name {
        listener: u32,
        pad: Box<libc::sockaddr_storage>,
    },
}

/// The pending state of an outbound connect: the boxed target sockaddr (the
/// kernel copies it at `IORING_OP_CONNECT` prep, so it must outlive submission —
/// the slot holds it), the resolved peer address, the caller's initial
/// per-connection state, and whether this connect layers kernel TLS once the
/// TCP connect completes. Client-only.
///
/// The state (`U`) rides here on the loop thread across the whole connect —
/// including a kTLS handshake, where it is retained in the parked slot rather
/// than crossing to the consumer's worker (the client's handshake deferral is
/// state-free). It is never accessed from another thread.
#[cfg(feature = "net-client")]
pub(crate) struct PendingConnect<U> {
    pub addr: Box<SockAddr>,
    pub peer: ClientAddr,
    pub state: U,
    /// The dialed address, retained for the kTLS handshake context
    /// (`TlsConnectContext::server_addr`) — the client's per-endpoint policy
    /// hook, since a client has no listener to name.
    pub server_addr: ServerAddr,
    /// The connect-timeout timespec, boxed with the pending state so its
    /// address is stable and per-connect (a shared pad would alias when several
    /// connects are staged before submission). Zero when no timeout is armed;
    /// only pointed at by a `LINK_TIMEOUT` when one is.
    pub timeout: KernelTimespec,
    /// Layer kernel TLS once the TCP connect completes: `on_connect` furnishes a
    /// real fd for the consumer's handshake worker instead of installing the
    /// connection immediately.
    pub tls: bool,
}

/// One pool slot's lifecycle state.
pub(crate) enum SlotState<U> {
    /// Free (or freed and awaiting reuse; the entry's generation was bumped).
    Empty,
    /// An outbound `IORING_OP_CONNECT` is in flight on a client socket installed
    /// into this slot; holds the pending-connect state until the connect
    /// completes (client-only — the server never dials out). A kTLS connect
    /// stays in this state across the follow-on `FIXED_FD_INSTALL` too (the
    /// pending state is retained until the slot parks for the handshake).
    #[cfg(feature = "net-client")]
    Connecting(Box<PendingConnect<U>>),
    /// A client kTLS connection parked across the consumer's handshake worker: a
    /// real fd was furnished and the slot holds the pending-connect state (its
    /// `U` + peer, retained on the loop thread — the client's deferral is
    /// state-free) until the worker signals via its `ConnectDeferral`. The
    /// outbound analogue of the server's `TlsParked`, but retaining `U` (the
    /// caller supplied it at connect; the worker only signals success/failure).
    /// Client-only.
    #[cfg(feature = "net-client")]
    TlsConnecting(Box<PendingConnect<U>>),
    /// A `SO_PEERCRED`/`SO_PEERNAME` `URING_CMD` is in flight; holds its
    /// stable landing pad.
    PeerFetch(PendingPeer),
    /// A kTLS connection whose real-fd `FIXED_FD_INSTALL` is in flight;
    /// carries the listener index through to the install completion (the
    /// handshake handler receives it as `Incoming::listener_addr`).
    TlsInstalling {
        /// Index of the listener the connection arrived on.
        listener: u32,
    },
    /// A kTLS connection parked across the consumer's handshake worker: a
    /// real fd was furnished and the slot is held (no `Connection`, no
    /// in-flight ring op) until the worker signals via its `AcceptDeferral`.
    /// Carries the peer address for the eventual install; tracked so
    /// shutdown can close the socket a lost worker would otherwise abandon.
    TlsParked(Box<ClientAddr>),
    /// Serving requests.
    Serving(Box<Connection<U>>),
    /// A `body`-handler connection whose detach `FIXED_FD_INSTALL` is in
    /// flight. Holds the live connection so resume restores its `U`/buffers
    /// (unlike `TlsInstalling`, which precedes any connection).
    Detaching(Box<Connection<U>>),
    /// A connection detached to the consumer's worker: a real fd was furnished
    /// and the slot is parked — holding the live connection, no in-flight ring
    /// op — until the worker signals via its `Detached` handle. Like
    /// `TlsParked`, but retains the `Connection` for resume.
    Detached(Box<Connection<U>>),
}

/// A slot plus the generation guarding its reuse. The generation is `u64` so a
/// long-retained cross-thread handle (a `Deferred`/`PushHandle`, which travels
/// by channel — not `user_data`) can never alias a future incarnation of the
/// same slot after 2^32 recycles. The kernel routing token packs only its low
/// 32 bits, which is ample there: a completion never outlives its op's
/// incarnation (the slot frees only at `ops == 0`), so the low bits match
/// exactly.
pub(crate) struct SlotEntry<U> {
    pub(crate) generation: u64,
    pub(crate) state: SlotState<U>,
}

/// All pool slots plus the live-connection count.
pub(crate) struct ConnTable<U> {
    slots: Vec<SlotEntry<U>>,
    active: u32,
}

impl<U> ConnTable<U> {
    pub(crate) fn new(pool_size: u32) -> ConnTable<U> {
        let mut slots = Vec::new();
        slots.resize_with(pool_size as usize, || SlotEntry {
            generation: 0,
            state: SlotState::Empty,
        });
        ConnTable { slots, active: 0 }
    }

    pub(crate) fn len(&self) -> usize {
        self.slots.len()
    }

    /// Connections currently `Serving`.
    pub(crate) fn active(&self) -> u32 {
        self.active
    }

    /// Whether any slot is `Empty` — i.e. whether the pool could admit
    /// another accept. (`active` alone undercounts occupancy: the
    /// `PeerFetch`/`TlsInstalling`/`TlsParked` states hold their table
    /// entries too.) `Empty` slots whose teardown `CLOSE` is still in flight
    /// make this optimistic; the caller's retry path absorbs that window.
    pub(crate) fn has_free_slot(&self) -> bool {
        self.slots
            .iter()
            .any(|e| matches!(e.state, SlotState::Empty))
    }

    /// The slot's current generation (valid in every state, including
    /// `Empty` — it guards reuse).
    pub(crate) fn generation(&self, slot: u32) -> u64 {
        self.slots[slot as usize].generation
    }

    /// The low 32 bits of the slot's generation — the value a kernel op packs
    /// into its `user_data` (see [`SlotEntry`]). Use this when routing/matching
    /// a kernel completion; use [`ConnTable::generation`] for a channel handle.
    pub(crate) fn generation_low(&self, slot: u32) -> u32 {
        self.slots[slot as usize].generation as u32
    }

    /// The serving connection in `slot`. For paths where the slot was just
    /// generation-checked (or a completion landed on it while it holds ops)
    /// — a missing connection there is a state-machine bug, so this panics
    /// rather than propagating an impossible `None`.
    pub(crate) fn conn(&self, slot: u32) -> &Connection<U> {
        match &self.slots[slot as usize].state {
            SlotState::Serving(conn) => conn,
            _ => panic!("slot {slot} is not serving"),
        }
    }

    /// As [`ConnTable::conn`], mutably.
    pub(crate) fn conn_mut(&mut self, slot: u32) -> &mut Connection<U> {
        match &mut self.slots[slot as usize].state {
            SlotState::Serving(conn) => conn,
            _ => panic!("slot {slot} is not serving"),
        }
    }

    /// The serving connection in `slot`, or `None` when the slot is out of
    /// range or not serving — for teardown paths where "nothing to track" is
    /// a normal case (reject/out-of-range closes).
    pub(crate) fn get_conn_mut(
        &mut self,
        slot: u32,
    ) -> Option<&mut Connection<U>> {
        match self.slots.get_mut(slot as usize)?.state {
            SlotState::Serving(ref mut conn) => Some(conn),
            _ => None,
        }
    }

    /// The serving connection in `slot`, immutably, or `None` when out of range
    /// or not serving — for the pump loop, which must stop cleanly if a handler
    /// just detached or closed the connection (see [`ConnTable::get_conn_mut`]).
    pub(crate) fn get_conn(&self, slot: u32) -> Option<&Connection<U>> {
        match self.slots.get(slot as usize)?.state {
            SlotState::Serving(ref conn) => Some(conn),
            _ => None,
        }
    }

    /// Whether `slot` holds a serving connection of exactly `generation` (the
    /// full `u64`) — the liveness check behind every injected reply/push, whose
    /// token may have been retained across arbitrarily many recycles.
    pub(crate) fn slot_matches(&self, slot: u32, generation: u64) -> bool {
        self.slots.get(slot as usize).is_some_and(|e| {
            e.generation == generation
                && matches!(e.state, SlotState::Serving(_))
        })
    }

    /// The live connection in `slot` at exactly `generation` (full `u64`) for
    /// **push** delivery: `Serving`, or parked across a detach
    /// (`Detaching`/`Detached` — the connection is alive and will resume, so
    /// pushes queue rather than drop). The `bool` is "serving": only then may
    /// the caller kick a send — a detached connection's raw stream belongs to
    /// its worker.
    pub(crate) fn push_conn_mut(
        &mut self,
        slot: u32,
        generation: u64,
    ) -> Option<(&mut Connection<U>, bool)> {
        let e = self.slots.get_mut(slot as usize)?;
        if e.generation != generation {
            return None;
        }
        match &mut e.state {
            SlotState::Serving(conn) => Some((conn, true)),
            SlotState::Detaching(conn) | SlotState::Detached(conn) => {
                Some((conn, false))
            }
            _ => None,
        }
    }

    /// As [`ConnTable::slot_matches`] but for a kernel completion, whose
    /// `user_data` carried only the low 32 bits of the generation. A completion
    /// never outlives its op's incarnation (the slot frees only at `ops == 0`),
    /// so the low bits are an exact match — this is belt-and-suspenders on that
    /// invariant.
    pub(crate) fn slot_matches_cqe(&self, slot: u32, generation: u32) -> bool {
        self.slots.get(slot as usize).is_some_and(|e| {
            e.generation as u32 == generation
                && matches!(e.state, SlotState::Serving(_))
        })
    }

    /// Install a connection and count it live.
    pub(crate) fn install(&mut self, slot: u32, conn: Box<Connection<U>>) {
        self.slots[slot as usize].state = SlotState::Serving(conn);
        self.active += 1;
    }

    /// Record an in-flight peer-identity fetch (its stable landing pad).
    pub(crate) fn begin_peer_fetch(&mut self, slot: u32, pad: PendingPeer) {
        self.slots[slot as usize].state = SlotState::PeerFetch(pad);
    }

    /// Take the in-flight peer fetch, if that is the slot's state (a stale
    /// completion for a slot in any other state gets `None` and changes
    /// nothing).
    pub(crate) fn take_peer_fetch(&mut self, slot: u32) -> Option<PendingPeer> {
        let e = self.slots.get_mut(slot as usize)?;
        if !matches!(e.state, SlotState::PeerFetch(_)) {
            return None;
        }
        match std::mem::replace(&mut e.state, SlotState::Empty) {
            SlotState::PeerFetch(pad) => Some(pad),
            _ => unreachable!(),
        }
    }

    /// Reserve a free slot for an outbound connect, parking the pending-connect
    /// state in it. Returns the slot index, or `None` if the pool is full. (No
    /// `active` bump — a `Connecting` slot isn't serving yet, and `has_free_slot`
    /// already excludes it since it is non-`Empty`.)
    #[cfg(feature = "net-client")]
    pub(crate) fn reserve_connecting(
        &mut self,
        pending: Box<PendingConnect<U>>,
    ) -> Option<u32> {
        let slot = self
            .slots
            .iter()
            .position(|e| matches!(e.state, SlotState::Empty))?
            as u32;
        self.slots[slot as usize].state = SlotState::Connecting(pending);
        Some(slot)
    }

    /// The stable kernel address and length of a `Connecting` slot's boxed
    /// target sockaddr, for filling the `IORING_OP_CONNECT` SQE after the
    /// pending state has been parked in the slot. The sockaddr lives behind a
    /// `Box`, so its address is stable across the reserve — the kernel copies it
    /// at prep, but it must be valid at submission. `None` if the slot is not
    /// connecting.
    #[cfg(feature = "net-client")]
    pub(crate) fn connecting_addr(&self, slot: u32) -> Option<(u64, u32, u64)> {
        match &self.slots.get(slot as usize)?.state {
            SlotState::Connecting(p) => Some((
                std::ptr::addr_of!(p.addr.storage) as u64,
                p.addr.len,
                std::ptr::addr_of!(p.timeout) as u64,
            )),
            _ => None,
        }
    }

    /// Whether the `Connecting` slot's pending connect layers kTLS (peeked
    /// without taking the pending state, so `on_connect` can branch to the
    /// furnish-fd path while leaving `U` parked). `false` if the slot is not
    /// connecting.
    #[cfg(feature = "net-client")]
    pub(crate) fn connecting_tls(&self, slot: u32) -> bool {
        matches!(
            self.slots.get(slot as usize).map(|e| &e.state),
            Some(SlotState::Connecting(p)) if p.tls
        )
    }

    /// Take the in-flight connect's pending state, if that is the slot's state (a
    /// stale completion for a slot in any other state gets `None` and changes
    /// nothing). Leaves the slot `Empty` — the caller then `install`s the serving
    /// connection (success) or `free`s the slot (failure).
    #[cfg(feature = "net-client")]
    pub(crate) fn take_connecting(
        &mut self,
        slot: u32,
    ) -> Option<Box<PendingConnect<U>>> {
        let e = self.slots.get_mut(slot as usize)?;
        if !matches!(e.state, SlotState::Connecting(_)) {
            return None;
        }
        match std::mem::replace(&mut e.state, SlotState::Empty) {
            SlotState::Connecting(p) => Some(p),
            _ => unreachable!(),
        }
    }

    /// Park a client kTLS connection across the consumer's handshake, retaining
    /// its pending-connect state (`U` + peer + dialed address) in the slot. The
    /// outbound twin of `park_tls`, but holding `U` on the loop thread (the
    /// worker only signals success/failure).
    #[cfg(feature = "net-client")]
    pub(crate) fn park_tls_connecting(
        &mut self,
        slot: u32,
        pending: Box<PendingConnect<U>>,
    ) {
        self.slots[slot as usize].state = SlotState::TlsConnecting(pending);
    }

    /// The dialed address of a slot parked mid-kTLS-handshake, for the handshake
    /// context handed to the consumer's worker. `None` if the slot is not parked.
    #[cfg(feature = "net-client")]
    pub(crate) fn tls_connecting_server_addr(
        &self,
        slot: u32,
    ) -> Option<&ServerAddr> {
        match &self.slots.get(slot as usize)?.state {
            SlotState::TlsConnecting(p) => Some(&p.server_addr),
            _ => None,
        }
    }

    /// Take the parked kTLS connect's pending state, if the slot is parked
    /// mid-handshake (a stale/duplicate outcome for a slot in any other state
    /// gets `None` and changes nothing — exactly like a stale deferred reply).
    /// Leaves the slot `Empty`; the caller then `install`s the serving
    /// connection (the handshake succeeded) or re-parks + sheds it (rejected).
    #[cfg(feature = "net-client")]
    pub(crate) fn take_tls_connecting(
        &mut self,
        slot: u32,
    ) -> Option<Box<PendingConnect<U>>> {
        let e = self.slots.get_mut(slot as usize)?;
        if !matches!(e.state, SlotState::TlsConnecting(_)) {
            return None;
        }
        match std::mem::replace(&mut e.state, SlotState::Empty) {
            SlotState::TlsConnecting(p) => Some(p),
            _ => unreachable!(),
        }
    }

    /// Record an in-flight kTLS fd install (holds the listener index).
    pub(crate) fn begin_tls_install(&mut self, slot: u32, listener: u32) {
        self.slots[slot as usize].state = SlotState::TlsInstalling { listener };
    }

    /// Take the in-flight install's listener index, if that is the slot's
    /// state (a stale completion for a slot in any other state gets `None`
    /// and changes nothing).
    pub(crate) fn take_tls_installing(&mut self, slot: u32) -> Option<u32> {
        let e = self.slots.get_mut(slot as usize)?;
        let SlotState::TlsInstalling { listener } = e.state else {
            return None;
        };
        e.state = SlotState::Empty;
        Some(listener)
    }

    /// Park a kTLS connection across the consumer's handshake.
    pub(crate) fn park_tls(&mut self, slot: u32, peer: Box<ClientAddr>) {
        self.slots[slot as usize].state = SlotState::TlsParked(peer);
    }

    /// Take the parked kTLS peer address, if the slot is parked (a stale
    /// handshake outcome for a slot in any other state gets `None` and
    /// changes nothing — exactly like a stale deferred reply).
    pub(crate) fn take_tls_parked(
        &mut self,
        slot: u32,
    ) -> Option<Box<ClientAddr>> {
        let e = self.slots.get_mut(slot as usize)?;
        if !matches!(e.state, SlotState::TlsParked(_)) {
            return None;
        }
        match std::mem::replace(&mut e.state, SlotState::Empty) {
            SlotState::TlsParked(addr) => Some(addr),
            _ => unreachable!(),
        }
    }

    /// Move a serving connection into `Detaching` (its detach `FIXED_FD_INSTALL`
    /// is now in flight). Keeps the `Connection` and the live count — the
    /// connection is parked, not gone.
    pub(crate) fn begin_detach(&mut self, slot: u32) {
        let e = &mut self.slots[slot as usize];
        let conn = match std::mem::replace(&mut e.state, SlotState::Empty) {
            SlotState::Serving(conn) => conn,
            _ => panic!("begin_detach on non-serving slot {slot}"),
        };
        e.state = SlotState::Detaching(conn);
    }

    /// Take the detaching connection out (leaving the slot momentarily `Empty`,
    /// as the kTLS install→park transition does) so the fd-install completion
    /// can hand its peer/state to the detach handler, then `park_detached` it.
    /// `None` if the slot is not `Detaching` (a stale completion).
    pub(crate) fn take_detaching(
        &mut self,
        slot: u32,
    ) -> Option<Box<Connection<U>>> {
        let e = self.slots.get_mut(slot as usize)?;
        if !matches!(e.state, SlotState::Detaching(_)) {
            return None;
        }
        match std::mem::replace(&mut e.state, SlotState::Empty) {
            SlotState::Detaching(conn) => Some(conn),
            _ => unreachable!(),
        }
    }

    /// Park a detached connection across the consumer's worker.
    pub(crate) fn park_detached(
        &mut self,
        slot: u32,
        conn: Box<Connection<U>>,
    ) {
        self.slots[slot as usize].state = SlotState::Detached(conn);
    }

    /// Move a `Detaching`/`Detached` connection back to `Serving` in place (the
    /// live count is unchanged — it was counted throughout the detach). Used by
    /// resume (then re-arm recv) and by detach-close (then `close_conn`, so
    /// teardown/active accounting reuse the serving path). Returns whether the
    /// slot was in a detach state (a stale outcome gets `false`, unchanged).
    pub(crate) fn reattach(&mut self, slot: u32) -> bool {
        let Some(e) = self.slots.get_mut(slot as usize) else {
            return false;
        };
        let conn = match std::mem::replace(&mut e.state, SlotState::Empty) {
            SlotState::Detaching(conn) | SlotState::Detached(conn) => conn,
            other => {
                e.state = other;
                return false;
            }
        };
        e.state = SlotState::Serving(conn);
        true
    }

    /// Empty the slot (whatever its state) and bump its generation so
    /// outstanding tokens go stale. Returns whether a live connection was freed
    /// — `Serving` or a detach state (the caller counts those; peer fetches and
    /// TLS parks were never counted live).
    pub(crate) fn free(&mut self, slot: u32) -> bool {
        let Some(e) = self.slots.get_mut(slot as usize) else {
            return false;
        };
        let was_live = matches!(
            e.state,
            SlotState::Serving(_)
                | SlotState::Detaching(_)
                | SlotState::Detached(_)
        );
        e.state = SlotState::Empty;
        e.generation = e.generation.wrapping_add(1);
        if was_live {
            self.active = self.active.saturating_sub(1);
        }
        was_live
    }

    /// All entries with their slot numbers (for drain sweeps).
    pub(crate) fn iter(
        &self,
    ) -> impl Iterator<Item = (u32, &SlotEntry<U>)> + '_ {
        self.slots
            .iter()
            .enumerate()
            .map(|(slot, e)| (slot as u32, e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slot_lifecycle() {
        let mut t: ConnTable<()> = ConnTable::new(2);
        assert_eq!(t.len(), 2);
        assert_eq!(t.active(), 0);
        assert!(t.has_free_slot());
        assert_eq!(t.generation(0), 0);
        assert!(!t.slot_matches(0, 0));
        assert!(t.get_conn_mut(0).is_none());
        assert!(t.get_conn_mut(9).is_none()); // out of range is a clean None

        // Peer fetch parks and takes exactly once.
        let pad = PendingPeer::Cred {
            listener: 3,
            // SAFETY: ucred is plain data; zeroed is a valid value.
            pad: Box::new(unsafe { std::mem::zeroed::<libc::ucred>() }),
        };
        t.begin_peer_fetch(0, pad);
        assert!(!t.slot_matches(0, 0)); // fetching, not serving
        assert!(t.take_tls_parked(0).is_none()); // wrong state: untouched
        assert!(t.take_tls_installing(0).is_none()); // wrong state too
        let taken = t.take_peer_fetch(0).expect("fetch parked");
        assert!(matches!(taken, PendingPeer::Cred { listener: 3, .. }));
        assert!(t.take_peer_fetch(0).is_none()); // second take is stale

        // A kTLS install parks the listener index and takes exactly once.
        t.begin_tls_install(1, 7);
        assert_eq!(t.take_tls_installing(1), Some(7));
        assert!(t.take_tls_installing(1).is_none()); // second take is stale

        // Install + match + free bumps the generation and the live count.
        let conn = crate::net::core::conn::Connection::new(
            ClientAddr::Unix { cred: None },
            (),
            2,
        );
        t.install(0, conn);
        assert_eq!(t.active(), 1);
        assert!(t.has_free_slot(), "slot 1 is still Empty");
        assert!(t.slot_matches(0, 0));
        assert!(!t.slot_matches(0, 1)); // wrong generation
        t.conn_mut(0).closing = true; // accessor reaches the connection
        assert!(t.free(0));
        assert_eq!(t.active(), 0);
        assert_eq!(t.generation(0), 1);
        assert!(!t.slot_matches(0, 0)); // token minted for gen 0 is stale
        assert!(!t.free(0)); // freeing an empty slot counts nothing
        assert_eq!(t.generation(0), 2); // but still bumps (mirrors today)
    }

    #[test]
    fn generation_width_split() {
        // The generation is u64 so a long-retained channel handle can't alias a
        // future incarnation, but the kernel routing token packs only its low 32
        // bits. 2^32 recycles are untestable end to end, so force the generation
        // past u32::MAX and check the two matchers honour that split. Model the
        // ABA: a handle minted at generation 5 (before the wrap) vs a slot now at
        // (1<<32)|5, whose low 32 bits are again 5.
        let mut t: ConnTable<()> = ConnTable::new(1);
        let conn = crate::net::core::conn::Connection::new(
            ClientAddr::Unix { cred: None },
            (),
            1,
        );
        t.install(0, conn);
        t.slots[0].generation = (1u64 << 32) | 5;

        // Channel side (full u64): the pre-wrap handle's generation `5` does NOT
        // match — no cross-connection injection.
        assert!(t.slot_matches(0, (1u64 << 32) | 5));
        assert!(!t.slot_matches(0, 5));
        assert_eq!(t.generation(0), (1u64 << 32) | 5);

        // Kernel side (low 32): a completion only ever carried the low bits, and
        // never outlives its incarnation, so it still matches exactly.
        assert!(t.slot_matches_cqe(0, 5));
        assert!(!t.slot_matches_cqe(0, 6));
        assert_eq!(t.generation_low(0), 5);
    }
}
