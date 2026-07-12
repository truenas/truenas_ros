//! kTLS connect: the outbound furnish → park → deferral → install arc, the
//! mirror of the server's kTLS accept path (`net::server`'s `accept.rs`) but
//! triggered by an `IORING_OP_CONNECT` completion instead of an accept, running
//! `SSL_connect` (not `SSL_accept`) in the consumer's worker, and skipping any
//! peer fetch (the client dialed its peer).
//!
//! The defining difference from the server: the per-connection state `U` never
//! crosses to the worker. The caller supplied it at `connect`, so it is retained
//! in the parked slot ([`SlotState::TlsConnecting`](crate::net::core::table))
//! on the loop thread, and the [`ConnectDeferral`] handed to the worker is
//! **state-free** — it signals only success or failure. That drops the `U: Send`
//! bound the server's `AcceptDeferral` needs.

use super::event::{ConnId, Event};
use super::Client;
use crate::errno::{self, Errno};
use crate::net::core::conn::{pack, Connection, Op};
use crate::net::core::handles::LoopShared;
use crate::net::core::protocol::{ClientAddr, Framing, ServerAddr};
use crate::net::core::sys::*;
use crate::net::core::table::PendingConnect;
use std::os::fd::RawFd;
use std::sync::atomic::Ordering;
use std::sync::{mpsc, Arc};

/// The client kTLS handshake handler ([`Client::set_tls_handshake`]):
/// `(furnished_fd, context, deferral)`, once per `tls` connect after its TCP
/// connect completes. The consumer moves the fd + deferral to its own worker,
/// runs `SSL_connect` (which installs kTLS on the socket), then signals through
/// the deferral. Unlike the server's handler, no `U` crosses here.
pub(super) type TlsConnectFn =
    Box<dyn FnMut(RawFd, TlsConnectContext<'_>, ConnectDeferral)>;

/// Context handed to the [`set_tls_handshake`](Client::set_tls_handshake)
/// handler alongside the furnished fd: which connection this is and the endpoint
/// it dialed — the client's per-endpoint policy hook (e.g. SNI / cert pinning),
/// since a client has no listener to name.
#[non_exhaustive]
#[derive(Debug)]
pub struct TlsConnectContext<'a> {
    /// The connection whose handshake this is (matches the later
    /// [`Event::Connected`]/[`Event::ConnectFailed`]).
    pub conn: ConnId,
    /// The address this connection dialed.
    pub server_addr: &'a ServerAddr,
}

/// The ticket a client kTLS handshake worker uses to hand a connection back once
/// the handshake finishes (or fails).
///
/// Furnished — with a real socket fd — to the
/// [`Client::set_tls_handshake`] handler for one `tls` connect. Move it (and the
/// fd) to your own worker, run `SSL_connect` (which installs kTLS on the
/// socket), and call [`ready`](ConnectDeferral::ready) on success or
/// [`reject`](ConnectDeferral::reject) on failure. Dropping it without either
/// **rejects** the connection, so a panicked/lost worker can't strand the parked
/// pool slot.
///
/// **State-free** and `Send`: the client already holds the per-connection state
/// `U` in the parked slot, so nothing but success/failure crosses back — the
/// deferral never carries `U`, and so never forces a `U: Send` bound.
#[must_use = "call ready() or reject(), or the connection is dropped"]
pub struct ConnectDeferral {
    slot: u32,
    // The full u64 generation: retained across the worker's handshake, so it
    // must not alias a future incarnation of the same slot.
    generation: u64,
    tx: mpsc::Sender<HandshakeResult>,
    shared: Arc<LoopShared>,
    done: bool,
}

impl ConnectDeferral {
    /// The handshake succeeded and kTLS is active on the socket: install the
    /// connection (with the state the caller supplied at connect) and begin
    /// serving it over the kernel-TLS transport. Consumes the handle.
    pub fn ready(mut self) {
        self.done = true;
        self.send(true);
    }

    /// The handshake failed (or the connection is unwanted): fail the connect
    /// and reclaim the slot ([`Event::ConnectFailed`]). Consumes the handle.
    pub fn reject(mut self) {
        self.done = true;
        self.send(false);
    }

    fn send(&mut self, ready: bool) {
        // The client owns the receiver for its whole life; a send error just
        // means it has been dropped, in which case the outcome is moot.
        let _ = self.tx.send(HandshakeResult {
            slot: self.slot,
            generation: self.generation,
            ready,
        });
        self.shared.wake.poke();
    }
}

impl Drop for ConnectDeferral {
    fn drop(&mut self) {
        if !self.done {
            self.send(false); // lost worker → fail the parked connect
        }
    }
}

impl std::fmt::Debug for ConnectDeferral {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectDeferral")
            .field("slot", &self.slot)
            .field("generation", &self.generation)
            .finish_non_exhaustive()
    }
}

/// A client kTLS handshake worker's outcome, delivered on the next loop wake —
/// the client-side, state-free analogue of the core `HandshakeOutcome<U>` (the
/// server ships `U` through that channel; the client holds `U` in the slot and
/// signals only `ready`).
pub(super) struct HandshakeResult {
    pub(super) slot: u32,
    pub(super) generation: u64,
    pub(super) ready: bool,
}

impl<U, F> Client<U, F>
where
    F: FnMut(&[u8], &mut U) -> Framing,
{
    /// Materialize a real fd from the pool descriptor for a kTLS connection, so
    /// the consumer's handshake worker can drive `SSL_connect` on a normal
    /// socket. The slot stays `Connecting` (still holding the pending connect,
    /// `U` included) across the install; `on_fd_install` then parks it as
    /// `TlsConnecting` and hands the fd to the worker.
    pub(super) fn submit_fd_install(
        &mut self,
        slot: u32,
        generation: u32,
    ) -> errno::Result<()> {
        self.core
            .stage(pack(Op::FdInstall, slot, generation), move |sqe| {
                sqe.opcode = IORING_OP_FIXED_FD_INSTALL;
                sqe.fd = slot as i32;
                sqe.flags = IOSQE_FIXED_FILE;
                // Default install flags → an `O_CLOEXEC` furnished fd.
            })
    }

    /// A furnished-fd install completed (`Op::FdInstall`): `res` is the real fd
    /// (aliasing the pool socket) or `-errno`. On success, park the slot across
    /// the handshake (retaining `U` + peer), arm the handshake timeout, arm the
    /// wake so the worker's outcome is heard, and hand the fd + a state-free
    /// [`ConnectDeferral`] to the consumer's handshake handler. On failure, fail
    /// the connect and shed the pool descriptor.
    pub(super) fn on_fd_install(
        &mut self,
        slot: u32,
        generation: u32,
        res: i32,
    ) -> errno::Result<()> {
        // Kernel completion → low 32 bits. The slot is still `Connecting` (we
        // kept the pending across the install), non-`Empty`, so it cannot
        // recycle under us — this only guards a stale out-of-order CQE.
        if self.core.table.generation_low(slot) != generation {
            return Ok(());
        }
        if res < 0 {
            // Install failed (or was cancelled at teardown): nothing was
            // furnished. The slot stays `Connecting` (non-`Empty`) through the
            // shedding CLOSE, so no concurrent connect can reuse it; `on_closed`
            // frees it (dropping the pending `U`). The connect established
            // (TCP up), so force the FIN out.
            let gen64 = self.core.table.generation(slot);
            self.events.push_back(Event::ConnectFailed {
                conn: ConnId::new(slot, gen64),
                err: Errno::ECONNABORTED,
            });
            return self.core.submit_teardown(slot, generation, true);
        }
        let fd = res; // a real O_CLOEXEC process fd aliasing the pool socket
                      // Take the pending out of `Connecting` and re-park it as `TlsConnecting`
                      // (holding `U` + peer + dialed address) across the handshake.
        let Some(pending) = self.core.table.take_connecting(slot) else {
            // Not connecting (stale — reaped at teardown): close the furnished
            // fd nobody will consume.
            // SAFETY: `fd` is the freshly installed fd we will not deliver.
            unsafe { libc::close(fd) };
            return Ok(());
        };
        self.core.table.park_tls_connecting(slot, pending);
        // Arm the park's bounds BEFORE handing off the fd: the handshake-timeout
        // (so a stalled worker can't pin the slot forever — no-op unless
        // `tls_handshake_timeout` is set) and a wake READ (so the worker's outcome
        // is heard). Both are ring-staging ops that can only fail on a wedged ring;
        // on that near-impossible failure, roll the park back — close the furnished
        // fd and force the pool descriptor closed (re-parked non-`Empty` so the
        // slot can't recycle mid-teardown, mirroring `shed_parked`) — so nothing
        // leaks or strands. `parked_handshakes` is bumped only once both succeed,
        // so a failure can never later underflow it.
        if let Err(e) = self
            .arm_handshake_timeout(slot, generation)
            .and_then(|()| self.ensure_wake_armed())
        {
            // SAFETY: `fd` is the furnished fd we never delivered to a worker.
            unsafe { libc::close(fd) };
            if let Some(p) = self.core.table.take_tls_connecting(slot) {
                self.core.table.park_tls(slot, Box::new(p.peer));
                let _ = self.core.submit_teardown(slot, generation, true);
            }
            return Err(e);
        }
        self.parked_handshakes += 1;
        // Hand the fd + a state-free deferral to the consumer's handshake
        // handler. Disjoint-field borrows: the handshake channel + shared flags
        // (for the deferral), the table (for the dialed address), and the hook.
        let gen64 = self.core.table.generation(slot);
        let deferral = ConnectDeferral {
            slot,
            generation: gen64,
            tx: self.handshake_tx.clone(),
            shared: Arc::clone(&self.core.shared),
            done: false,
        };
        let conn = ConnId::new(slot, gen64);
        match self.tls_connect.as_mut() {
            Some(hook) => {
                let server_addr = self
                    .core
                    .table
                    .tls_connecting_server_addr(slot)
                    .expect("slot just parked as TlsConnecting");
                hook(fd, TlsConnectContext { conn, server_addr }, deferral);
            }
            None => {
                // Guarded at connect time (a `tls` connect requires the hook),
                // so unreachable in practice.
                drop(deferral); // → reject via Drop, drained next wake
                                // SAFETY: close the furnished fd we won't use.
                unsafe { libc::close(fd) };
            }
        }
        Ok(())
    }

    /// Ensure a wake READ is in flight (to hear a worker's handshake outcome),
    /// arming it if not already. `wake_armed` flips only on a successful arm, so a
    /// staging failure leaves no partial state.
    fn ensure_wake_armed(&mut self) -> errno::Result<()> {
        if !self.wake_armed {
            self.core.arm_wake()?;
            self.wake_armed = true;
        }
        Ok(())
    }

    /// Drain kTLS handshake outcomes posted by consumer workers: install the
    /// connection (kTLS transport, emitting [`Event::Connected`]) on success, or
    /// fail the connect (emitting [`Event::ConnectFailed`]) on rejection. A stale
    /// outcome (slot recycled, or no longer parked) is dropped, exactly like a
    /// stale deferred reply.
    pub(super) fn drain_handshake_outcomes(&mut self) -> errno::Result<()> {
        while let Ok(outcome) = self.handshake_rx.try_recv() {
            let HandshakeResult {
                slot,
                generation,
                ready,
            } = outcome;
            if self.core.table.generation(slot) != generation {
                continue; // slot recycled; outcome moot
            }
            let Some(pending) = self.core.table.take_tls_connecting(slot)
            else {
                continue; // not parked (already resolved); outcome moot
            };
            self.parked_handshakes -= 1;
            // Resolved in time — cancel the handshake timeout so it doesn't fire
            // later and find the slot no longer parked. No-op unless armed.
            self.cancel_handshake_timeout(slot, generation as u32)?;
            if ready {
                // Install the kTLS connection with the state the caller supplied.
                let PendingConnect { peer, state, .. } = *pending;
                let mut conn = Connection::new(
                    peer,
                    state,
                    self.core.cfg.max_send_coalesce,
                );
                conn.install_ktls();
                self.core.table.install(slot, conn);
                self.core.stats.active.store(
                    u64::from(self.core.table.active()),
                    Ordering::Relaxed,
                );
                let gen_low = self.core.table.generation_low(slot);
                let gen64 = self.core.table.generation(slot);
                self.events.push_back(Event::Connected {
                    conn: ConnId::new(slot, gen64),
                });
                // Arm the first reply recv (the pump frames `Need(header)` on
                // the empty buffer and submits it — a kTLS RECVMSG here).
                self.pump(slot, gen_low)?;
            } else {
                // Rejected (or a lost worker's Drop-reject): shed the pool
                // descriptor and fail the connect.
                let PendingConnect { peer, .. } = *pending;
                self.shed_parked(slot, peer, Errno::ECONNABORTED)?;
            }
        }
        Ok(())
    }

    /// A parked kTLS slot's handshake timeout fired (or was cancelled — its
    /// result is irrelevant): if the slot is still parked at this generation the
    /// worker did not call back in time, so fail the connect and shed it (a late
    /// `ready()`/`reject()` then hits the taken slot and is dropped). Otherwise
    /// it already resolved (or the slot recycled) — nothing to do.
    pub(super) fn on_handshake_timeout(
        &mut self,
        slot: u32,
        generation: u32,
    ) -> errno::Result<()> {
        if self.core.table.generation_low(slot) != generation {
            return Ok(()); // slot recycled
        }
        let Some(pending) = self.core.table.take_tls_connecting(slot) else {
            return Ok(()); // resolved (no longer parked)
        };
        self.parked_handshakes -= 1;
        // The timeout already fired — no cancel owed.
        let PendingConnect { peer, .. } = *pending;
        self.shed_parked(slot, peer, Errno::ETIMEDOUT)
    }

    /// Shed a taken parked slot: re-park it as `TlsParked` (holding `peer`, no
    /// pending state) so it stays non-`Empty` — a concurrent `connect_start`
    /// scanning for a free slot must not reuse it while its shedding CLOSE is in
    /// flight — then queue the failure and force the FIN out. `on_closed` frees
    /// the slot when the CLOSE reaps. The caller has already taken the pending
    /// and decremented `parked_handshakes`.
    fn shed_parked(
        &mut self,
        slot: u32,
        peer: ClientAddr,
        err: Errno,
    ) -> errno::Result<()> {
        let gen64 = self.core.table.generation(slot);
        self.core.table.park_tls(slot, Box::new(peer));
        self.events.push_back(Event::ConnectFailed {
            conn: ConnId::new(slot, gen64),
            err,
        });
        // The connect established (TCP up) and TLS may have partly handshaken:
        // force the FIN out (shutdown-first), like the server sheds a park.
        self.core.submit_teardown(slot, gen64 as u32, true)
    }

    /// Arm the standalone `TIMEOUT` bounding a parked kTLS handshake, keyed to
    /// `(slot, generation)`; on expiry `on_handshake_timeout` sheds the slot if
    /// still parked. No-op unless `tls_handshake_timeout` is set.
    fn arm_handshake_timeout(
        &mut self,
        slot: u32,
        generation: u32,
    ) -> errno::Result<()> {
        if self.core.cfg.tls_handshake_timeout.is_none() {
            return Ok(());
        }
        let ts = std::ptr::addr_of!(self.core.pads.tls_handshake) as u64;
        self.core.stage(
            pack(Op::HandshakeTimeout, slot, generation),
            move |sqe| {
                sqe.opcode = IORING_OP_TIMEOUT;
                sqe.addr = ts;
                sqe.len = 1; // exactly one timespec, per the kernel
            },
        )
    }

    /// Cancel a parked slot's handshake timeout once its handshake resolves.
    fn cancel_handshake_timeout(
        &mut self,
        slot: u32,
        generation: u32,
    ) -> errno::Result<()> {
        if self.core.cfg.tls_handshake_timeout.is_none() {
            return Ok(());
        }
        let target = pack(Op::HandshakeTimeout, slot, generation);
        self.core.stage(pack(Op::Cancel, 0, 0), move |sqe| {
            sqe.opcode = IORING_OP_ASYNC_CANCEL;
            sqe.fd = -1;
            sqe.addr = target;
        })
    }
}
