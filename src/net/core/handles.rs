//! Core cross-thread primitives shared by the server and client roles: the
//! wake eventfd and the routing tokens hand-offs ride on, the generation-
//! stamped handshake hand-back, the shared loop flags, and the stats cells the
//! loop increments. Each role builds its own public handles (deferred replies,
//! pushes, shutdown) on top of these.

use crate::net::core::protocol::{ClientAddr, CloseReason};
#[cfg(all(doc, feature = "net-server"))]
use crate::net::server::{
    Deferred, Protocol, PushHandle, Server, ShutdownHandle, StatsHandle,
};
use crate::uring::wake::LoopShared;
use std::sync::atomic::AtomicU64;
use std::sync::mpsc;
use std::sync::Arc;

/// The ticket a kTLS handshake worker uses to hand a connection back to the
/// server once the handshake finishes (or fails).
///
/// Furnished — with a real socket fd — to the [`Server::set_tls_handshake`]
/// handler for one accepted connection. Move it (and the fd) to your own
/// worker, run the TLS handshake (which installs kTLS on the socket), and call
/// [`AcceptDeferral::ready`] with the per-connection state on success, or
/// [`AcceptDeferral::reject`] on failure. Dropping it without either **rejects**
/// the connection, so a panicked/lost worker can't leak the parked slot. The
/// state `U` crosses to the loop thread here (hence `Send` when `U: Send`), but
/// only once, before serving begins — there is never concurrent access.
#[must_use = "call ready(state) or reject(), or the connection is dropped"]
pub struct AcceptDeferral<U> {
    pub(crate) slot: u32,
    pub(crate) generation: u64,
    pub(crate) tx: mpsc::Sender<HandshakeOutcome<U>>,
    pub(crate) shared: Arc<LoopShared>,
    pub(crate) done: bool,
}

impl<U> AcceptDeferral<U> {
    /// The handshake succeeded and kTLS is active on the socket: install the
    /// connection with per-connection state `state` and begin serving it over
    /// the kernel-TLS transport. Consumes the handle.
    pub fn ready(mut self, state: U) {
        self.done = true;
        self.send(Ok(state));
    }

    /// The handshake failed (or the connection is unwanted): shed it. Consumes
    /// the handle.
    pub fn reject(mut self) {
        self.done = true;
        self.send(Err(()));
    }

    fn send(&mut self, result: Result<U, ()>) {
        // The server owns the receiver for its whole life; a send error just
        // means it has shut down, in which case the outcome is moot.
        let _ = self.tx.send(HandshakeOutcome {
            slot: self.slot,
            generation: self.generation,
            result,
        });
        self.shared.wake.poke();
    }
}

impl<U> Drop for AcceptDeferral<U> {
    fn drop(&mut self) {
        if !self.done {
            self.send(Err(())); // lost worker → shed the parked connection
        }
    }
}

impl<U> std::fmt::Debug for AcceptDeferral<U> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AcceptDeferral")
            .field("slot", &self.slot)
            .field("generation", &self.generation)
            .finish_non_exhaustive()
    }
}

/// A handshake worker's outcome, delivered on the next loop wake.
pub(crate) struct HandshakeOutcome<U> {
    pub(crate) slot: u32,
    pub(crate) generation: u64,
    pub(crate) result: Result<U, ()>,
}

/// Shared counter cells behind [`StatsHandle`]; the loop thread is the single
/// writer (Relaxed increments), snapshots read Relaxed.
#[derive(Debug, Default)]
pub(crate) struct StatsInner {
    pub(crate) accepted: AtomicU64,
    pub(crate) rejected: AtomicU64,
    pub(crate) shed: AtomicU64,
    pub(crate) accept_retries: AtomicU64,
    pub(crate) closed: AtomicU64,
    pub(crate) active: AtomicU64,
    pub(crate) requests: AtomicU64,
    pub(crate) deferred: AtomicU64,
    pub(crate) replies: AtomicU64,
    pub(crate) pushes: AtomicU64,
    pub(crate) send_ops: AtomicU64,
    pub(crate) recv_ops: AtomicU64,
    pub(crate) bytes_in: AtomicU64,
    pub(crate) bytes_out: AtomicU64,
}

/// Bump a stats counter (single-writer loop thread; Relaxed is sufficient).
macro_rules! stat {
    // Absolute `Ordering` path: the macro expands in the sibling stage
    // modules, which do not all import it.
    ($self:expr, $field:ident) => {
        $self
            .stats
            .$field
            .fetch_add(1, ::std::sync::atomic::Ordering::Relaxed)
    };
    ($self:expr, $field:ident, $n:expr) => {
        $self
            .stats
            .$field
            .fetch_add($n, ::std::sync::atomic::Ordering::Relaxed)
    };
}
pub(crate) use stat;

/// Routing key for a deferred reply: which pool slot, which connection
/// generation (so a reply for a recycled slot is dropped), and which request on
/// that connection (so a reply for a request that was already answered — e.g. a
/// worker outliving an inline reply — is dropped instead of duplicated).
#[derive(Clone, Copy, Debug)]
pub(crate) struct Token {
    pub(crate) slot: u32,
    pub(crate) generation: u64,
    pub(crate) req_id: u64,
}

/// The close hook ([`Server::set_close_hook`]): `(peer, reason, &mut state)`,
/// once per connection at its first transition to closing. Boxed dyn: cold
/// path, keeps [`Protocol`] at three closures.
pub(crate) type CloseHook<U> = Box<dyn FnMut(&ClientAddr, CloseReason, &mut U)>;
