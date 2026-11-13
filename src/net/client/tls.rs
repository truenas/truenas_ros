//! kTLS connect. A real fd is furnished after an `IORING_OP_CONNECT` completes, the slot is parked while the consumer's
//! worker runs `SSL_connect`, and the connection is installed on the worker's verdict.
//!
//! The per-connection state `U` never crosses to the worker. It stays in the parked slot
//! ([`SlotState::TlsConnecting`](crate::net::core::table)) on the loop thread, so the [`ConnectDeferral`] carries only
//! success or failure and needs no `U: Send` bound.

use super::Client;
use super::event::{ConnId, Event};
use crate::errno::{self, Errno};
use crate::net::core::conn::{Connection, Op, pack};
use crate::net::core::protocol::{ClientAddr, Framing, ServerAddr};
use crate::net::core::table::PendingConnect;
use crate::uring::sys::*;
use crate::uring::wake::LoopShared;
use std::os::fd::RawFd;
use std::sync::atomic::Ordering;
// Matches `LoopShared`'s own `Arc`, since under `--cfg loom` the `std` one is a distinct type.
use crate::sync::Arc;
use std::sync::mpsc;

/// The client kTLS handshake handler ([`Client::set_tls_handshake`]), called with `(furnished_fd, context, deferral)`.
pub(super) type TlsConnectFn = Box<dyn FnMut(RawFd, TlsConnectContext<'_>, ConnectDeferral)>;

/// Context handed to the [`set_tls_handshake`](Client::set_tls_handshake) handler alongside the furnished fd, naming
/// the connection and the endpoint it dialed for per-endpoint policy such as SNI or certificate pinning.
#[non_exhaustive]
#[derive(Debug)]
pub struct TlsConnectContext<'a> {
    /// The connection whose handshake this is (matches the later [`Event::Connected`]/[`Event::ConnectFailed`]).
    pub conn: ConnId,
    /// The address this connection dialed.
    pub server_addr: &'a ServerAddr,
}

/// The ticket a client kTLS handshake worker uses to hand a connection back once the handshake finishes (or fails).
///
/// Handed with a real socket fd to the [`Client::set_tls_handshake`] handler for one `tls` connect. Move both to your
/// own worker, run `SSL_connect` there, and call [`ready`](ConnectDeferral::ready) or
/// [`reject`](ConnectDeferral::reject). Dropping it without either **rejects** the connection, so a lost worker cannot
/// strand the parked pool slot. It is `Send` and never carries `U`.
#[must_use = "call ready() or reject(), or the connection is dropped"]
pub struct ConnectDeferral {
    slot: u32,
    // The full generation, since it is held across the handshake and must not match a later use of the slot.
    generation: u64,
    tx: mpsc::Sender<HandshakeResult>,
    shared: Arc<LoopShared>,
    done: bool,
    /// The deferral's own dup of the socket, for `ready`'s key readback. The worker owns the furnished fd and may close
    /// it, and its number can be reused while an open description cannot.
    sock: std::os::fd::OwnedFd,
}

impl ConnectDeferral {
    /// The handshake succeeded and kTLS is active on the socket: install the connection (with the state the caller
    /// supplied at connect) and begin serving it over the kernel-TLS transport. Consumes the handle.
    ///
    /// Both TLS directions must hold kernel keys (`getsockopt(SOL_TLS, TLS_TX/TLS_RX)`), or the connect fails as if
    /// rejected. A handshake library that fell back to userspace records, or keyed one direction, would otherwise have
    /// plaintext served as TLS.
    pub fn ready(mut self) {
        self.done = true;
        let keyed = crate::net::core::probe::ktls_keyed_both_ways(std::os::fd::AsRawFd::as_raw_fd(&self.sock));
        self.send(keyed);
    }

    /// The handshake failed (or the connection is unwanted): fail the connect and reclaim the slot
    /// ([`Event::ConnectFailed`]). Consumes the handle.
    pub fn reject(mut self) {
        self.done = true;
        self.send(false);
    }

    fn send(&mut self, ready: bool) {
        // A send error means the client was dropped, so the outcome is moot.
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
            self.send(false); // lost worker -> fail the parked connect
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

/// A client kTLS handshake worker's outcome, delivered on the next loop wake.
pub(super) struct HandshakeResult {
    pub(super) slot: u32,
    pub(super) generation: u64,
    pub(super) ready: bool,
}

impl<U, F> Client<U, F>
where
    F: FnMut(&[u8], &mut U) -> Framing,
{
    /// Materialize a real fd from the pool descriptor for the consumer's handshake worker. The slot stays `Connecting`,
    /// holding `U`, until `on_fd_install` parks it.
    pub(super) fn submit_fd_install(&mut self, slot: u32, generation: u32) -> errno::Result<()> {
        self.core.stage(pack(Op::FdInstall, slot, generation), move |sqe| {
            sqe.opcode = IORING_OP_FIXED_FD_INSTALL;
            sqe.fd = slot as i32;
            sqe.flags = IOSQE_FIXED_FILE;
            // Default install flags -> an `O_CLOEXEC` furnished fd.
        })
    }

    /// A furnished-fd install completed, with `res` the real fd or `-errno`. On success, park the slot, arm the
    /// handshake timeout and the wake, and hand the fd and a [`ConnectDeferral`] to the handshake handler. On failure,
    /// fail the connect and shed the pool descriptor.
    pub(super) fn on_fd_install(&mut self, slot: u32, generation: u32, res: i32) -> errno::Result<()> {
        // The slot is still `Connecting` and cannot recycle, so this guards only a stale out-of-order CQE.
        if self.core.table.generation_low(slot) != generation {
            return Ok(());
        }
        if res < 0 {
            // The slot stays `Connecting` through the shedding CLOSE, so no other connect can reuse it. TCP is up, so
            // force the FIN out.
            let gen64 = self.core.table.generation(slot);
            // `FIXED_FD_INSTALL` charges the process fd table (`io_install_fixed_fd` -> `receive_fd` ->
            // `get_unused_fd_flags`, `fs/file.c:1367`), so report the kernel's errno, since `EMFILE` does not mean the
            // peer went away. Only a teardown cancellation answers `ECONNABORTED`.
            let err = if res == -libc::ECANCELED {
                Errno::ECONNABORTED
            } else {
                Errno::from_raw(-res)
            };
            self.events.push_back(Event::ConnectFailed {
                conn: ConnId::new(slot, gen64),
                err,
            });
            return self.core.submit_teardown(slot, generation, true);
        }
        let fd = res; // a real O_CLOEXEC process fd aliasing the pool socket
        let Some(pending) = self.core.table.take_connecting(slot) else {
            // Reaped at teardown, so nobody will consume the furnished fd.
            // SAFETY: `fd` is the freshly installed fd we will not deliver.
            unsafe { libc::close(fd) };
            return Ok(());
        };
        self.core.table.park_tls_connecting(slot, pending);
        // Arm the handshake timeout and the wake READ before handing off the fd. If either fails, roll the park back,
        // re-parked non-`Empty` as in `shed_parked` so the slot cannot recycle mid-teardown. `parked_handshakes` is
        // bumped only once both succeed, so it cannot underflow.
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
        let gen64 = self.core.table.generation(slot);
        // Fail closed like the staging arm above, since a connection whose keys can never be confirmed must not be
        // servable.
        // SAFETY: `fd` is the furnished fd, live for this call.
        let sock = match crate::fd::dup_cloexec(unsafe { std::os::fd::BorrowedFd::borrow_raw(fd) }) {
            Ok(s) => s,
            Err(err) => {
                // SAFETY: `fd` is the furnished fd, never delivered to a worker.
                unsafe { libc::close(fd) };
                self.parked_handshakes -= 1;
                // Every connect must resolve to exactly one of `Connected` or `ConnectFailed`, since `await_connect`
                // blocks on it. The errno is the dup's own, since running out of descriptors does not mean the peer
                // went away.
                self.events.push_back(Event::ConnectFailed {
                    conn: ConnId::new(slot, gen64),
                    err,
                });
                if let Some(p) = self.core.table.take_tls_connecting(slot) {
                    self.core.table.park_tls(slot, Box::new(p.peer));
                    let _ = self.core.submit_teardown(slot, generation, true);
                }
                return Ok(());
            }
        };
        let deferral = ConnectDeferral {
            slot,
            generation: gen64,
            tx: self.handshake_tx.clone(),
            shared: Arc::clone(&self.core.engine.shared),
            done: false,
            sock,
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
                // Unreachable, since a `tls` connect requires the hook.
                drop(deferral); // -> reject via Drop, drained next wake
                // SAFETY: close the furnished fd we won't use.
                unsafe { libc::close(fd) };
            }
        }
        Ok(())
    }

    /// Ensure a wake READ is in flight (to hear a worker's handshake outcome), arming it if not already. `wake_armed`
    /// flips only on a successful arm, so a staging failure leaves no partial state.
    fn ensure_wake_armed(&mut self) -> errno::Result<()> {
        if !self.wake_armed {
            self.core.arm_wake()?;
            self.wake_armed = true;
        }
        Ok(())
    }

    /// Drain kTLS handshake outcomes, installing the connection with [`Event::Connected`] or failing it with
    /// [`Event::ConnectFailed`]. A stale outcome, for a recycled or no longer parked slot, is dropped.
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
            let Some(pending) = self.core.table.take_tls_connecting(slot) else {
                continue; // not parked (already resolved); outcome moot
            };
            self.parked_handshakes -= 1;
            self.cancel_handshake_timeout(slot, generation as u32)?;
            if ready {
                let PendingConnect { peer, state, .. } = *pending;
                let mut conn = Connection::new(peer, state, self.core.cfg.max_send_coalesce);
                conn.install_ktls();
                self.core.table.install(slot, conn);
                self.core
                    .stats
                    .active
                    .store(u64::from(self.core.table.active()), Ordering::Relaxed);
                let gen_low = self.core.table.generation_low(slot);
                let gen64 = self.core.table.generation(slot);
                self.events.push_back(Event::Connected {
                    conn: ConnId::new(slot, gen64),
                });
                self.pump(slot, gen_low)?;
            } else {
                let PendingConnect { peer, .. } = *pending;
                self.shed_parked(slot, peer, Errno::ECONNABORTED)?;
            }
        }
        Ok(())
    }

    /// A parked kTLS slot's handshake timeout fired or was cancelled. If the slot is still parked at this generation,
    /// fail the connect and shed it, and a late `ready()` or `reject()` is then dropped as stale.
    pub(super) fn on_handshake_timeout(&mut self, slot: u32, generation: u32) -> errno::Result<()> {
        if self.core.table.generation_low(slot) != generation {
            return Ok(()); // slot recycled
        }
        let Some(pending) = self.core.table.take_tls_connecting(slot) else {
            return Ok(()); // resolved (no longer parked)
        };
        self.parked_handshakes -= 1;
        // The timeout already fired - no cancel owed.
        let PendingConnect { peer, .. } = *pending;
        self.shed_parked(slot, peer, Errno::ETIMEDOUT)
    }

    /// Shed a taken parked slot, queue the failure and force the FIN out. It is re-parked as `TlsParked` so it stays
    /// non-`Empty`, and `connect_start` cannot reuse it while its CLOSE is in flight. The caller has already taken the
    /// pending connect and decremented `parked_handshakes`.
    fn shed_parked(&mut self, slot: u32, peer: ClientAddr, err: Errno) -> errno::Result<()> {
        let gen64 = self.core.table.generation(slot);
        self.core.table.park_tls(slot, Box::new(peer));
        self.events.push_back(Event::ConnectFailed {
            conn: ConnId::new(slot, gen64),
            err,
        });
        // TCP is up and TLS may have partly handshaken, so shut down before the close.
        self.core.submit_teardown(slot, gen64 as u32, true)
    }

    /// Arm the standalone `TIMEOUT` bounding a parked kTLS handshake, keyed to `(slot, generation)`. No-op unless
    /// `tls_handshake_timeout` is set.
    fn arm_handshake_timeout(&mut self, slot: u32, generation: u32) -> errno::Result<()> {
        if self.core.cfg.tls_handshake_timeout.is_none() {
            return Ok(());
        }
        let ts = std::ptr::addr_of!(self.core.pads.tls_handshake) as u64;
        self.core
            .stage(pack(Op::HandshakeTimeout, slot, generation), move |sqe| {
                sqe.opcode = IORING_OP_TIMEOUT;
                sqe.addr = ts;
                sqe.len = 1; // exactly one timespec, per the kernel
            })
    }

    /// Cancel a parked slot's handshake timeout once its handshake resolves.
    fn cancel_handshake_timeout(&mut self, slot: u32, generation: u32) -> errno::Result<()> {
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
