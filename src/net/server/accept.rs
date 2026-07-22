//! The accept arc: multishot-accept completions, per-connection peer-identity
//! fetches (`SO_PEERNAME` / `SO_PEERCRED`), the accept handler, connection
//! installation — and the kTLS variant that furnishes a real fd and parks the
//! slot across the consumer's handshake.

use super::Server;
use crate::errno::{self, Errno};
use crate::net::core::conn::{pack, Connection, Op};
use crate::net::core::handles::{stat, AcceptDeferral, HandshakeOutcome};
use crate::net::core::probe::fill_getsockopt_cmd;
use crate::net::core::protocol::{ClientAddr, Framing, PeerCred, ServerAddr};
use crate::net::core::sock;
use crate::net::core::table::PendingPeer;
use crate::net::server::protocol::{Incoming, Request, Response};
use crate::uring::sys::*;
use std::mem::size_of;
use std::os::fd::AsRawFd;
use std::sync::atomic::Ordering;
use std::sync::Arc;

// The admission path runs the accept handler and, once a connection is
// installed, enters the pump — so this block carries the full handler bounds.
impl<U, AcceptFn, HeaderFn, BodyFn> Server<U, AcceptFn, HeaderFn, BodyFn>
where
    AcceptFn: FnMut(Incoming<'_>) -> Option<U>,
    HeaderFn: FnMut(&[u8], &mut U) -> Framing,
    BodyFn: FnMut(Request<'_, U>) -> Response,
{
    pub(super) fn on_accept(
        &mut self,
        lidx: u32,
        cqe: &IoUringCqe,
    ) -> errno::Result<()> {
        if cqe.res >= 0 {
            self.accept_connection(cqe.res as u32, lidx)?;
        }
        // Any error CQE clears F_MORE, terminating this listener's multishot
        // accept (verified in the kernel); a successful accept keeps F_MORE.
        if cqe.flags & IORING_CQE_F_MORE != 0 {
            return Ok(());
        }
        if cqe.res >= 0 || self.core.stopping() || self.core.draining {
            // A multishot that ended without an error (rare) still needs a
            // re-arm; shutdown paths leave it down.
            if cqe.res >= 0 && !self.core.stopping() && !self.core.draining {
                self.arm_accept(lidx)?;
            }
            return Ok(());
        }
        let e = Errno::from_raw(-cqe.res);
        if e == Errno::ENFILE {
            // A full fixed-file table reports ENFILE — but so does a
            // system-wide file-table exhaustion. Park only when the pool
            // really is full, where the next Close re-arms the accept via
            // `reclaim_slot`; with free slots no slot-free event is coming,
            // so a park would idle the listener forever — back off and
            // retry like any other transient shortage instead.
            if self.core.table.has_free_slot() {
                stat!(self.core, accept_retries);
                self.submit_accept_retry(lidx)?;
            } else {
                stat!(self.core, shed);
                if let Some(l) = self.listeners.get_mut(lidx as usize) {
                    l.awaiting_slot = true;
                }
            }
        } else if accept_error_is_fatal(e) {
            // A broken listener/setup (EBADF/EINVAL/…): retrying can't help.
            return Err(e);
        } else {
            // Transient (ENOMEM/ENOBUFS/ECONNABORTED/EMFILE/EINTR/…): never
            // fatal — re-arm after a backoff so a sustained resource shortage
            // can't spin the loop at 100% CPU (matches Samba's accept throttle
            // and tokio's never-die accept). No accepted connection to shed.
            stat!(self.core, accept_retries);
            self.submit_accept_retry(lidx)?;
        }
        Ok(())
    }

    fn accept_connection(&mut self, slot: u32, lidx: u32) -> errno::Result<()> {
        if slot as usize >= self.core.table.len() {
            stat!(self.core, shed);
            return self.core.submit_teardown(slot, 0, true); // out of range
        }
        if self.core.draining {
            stat!(self.core, shed);
            return self.core.submit_teardown(slot, 0, true); // shed on drain
        }
        // A kTLS listener furnishes a real fd for the consumer's handshake
        // (the peer address is derived from that fd, so no peername fetch).
        if self.listeners[lidx as usize].tls {
            return self.submit_fd_install(slot, lidx);
        }
        // Peer identity is fetched per connection — race-free, unlike a
        // peer-address buffer shared across a multishot accept's completions
        // — and the accept handler runs from that fetch's completion.
        match self.listeners[lidx as usize].addr {
            ServerAddr::Tcp(_) | ServerAddr::Tcp6(_) => {
                self.submit_peername(slot, lidx)
            }
            ServerAddr::Unix(_) if self.cfg.unix_peercred => {
                self.submit_cred(slot, lidx)
            }
            // Unix stream peers are unnamed: nothing to fetch.
            ServerAddr::Unix(_) => {
                self.finish_accept(slot, ClientAddr::Unix { cred: None }, lidx)
            }
        }
    }

    /// Materialize a real fd from the pool descriptor for a kTLS connection,
    /// so the consumer's handshake worker can drive TLS on a normal socket.
    /// The slot holds `TlsInstalling` (carrying the listener index) while the
    /// install op is in flight, then parks as `TlsParked` across the
    /// handshake; `on_fd_install` furnishes the fd.
    fn submit_fd_install(&mut self, slot: u32, lidx: u32) -> errno::Result<()> {
        let generation = self.core.table.generation_low(slot);
        // A shutdown mid-install cancels the op; `on_fd_install` gets
        // `-ECANCELED` and sheds (the teardown clears the slot state).
        self.core.table.begin_tls_install(slot, lidx);
        self.core
            .stage(pack(Op::FdInstall, slot, generation), move |sqe| {
                sqe.opcode = IORING_OP_FIXED_FD_INSTALL;
                sqe.fd = slot as i32;
                sqe.flags = IOSQE_FIXED_FILE;
                // Default install flags: `install_fd_flags` overlays `op_flags`
                // (left 0 here) → `O_CLOEXEC` on the furnished fd.
            })
    }

    /// A furnished-fd install completed: hand the real fd + an `AcceptDeferral`
    /// to the consumer's TLS handshake handler. The slot stays parked
    /// (`TlsParked`: no `Connection`, no in-flight op) until the worker calls
    /// back through the deferral, drained in `on_wake`.
    pub(super) fn on_fd_install(
        &mut self,
        slot: u32,
        generation: u32,
        res: i32,
    ) -> errno::Result<()> {
        // Generation before take (see `on_peer_fetch`): don't clear a recycled
        // slot's fresh state on a stale completion. Kernel completion → low 32.
        if self.core.table.generation_low(slot) != generation {
            return Ok(()); // slot recycled under us
        }
        let Some(lidx) = self.core.table.take_tls_installing(slot) else {
            return Ok(()); // stale (state already cleared at teardown)
        };
        if res < 0 {
            // Install failed (or was cancelled at shutdown): nothing was
            // furnished; shed the parked slot.
            stat!(self.core, shed);
            return self.core.submit_teardown(slot, generation, true);
        }
        let fd = res; // a real, O_CLOEXEC process fd aliasing the pool socket
        if self.core.draining {
            // SAFETY: `fd` is the freshly installed fd; close it before shedding.
            unsafe { libc::close(fd) };
            stat!(self.core, shed);
            return self.core.submit_teardown(slot, generation, true);
        }
        // Derive the peer from the real fd (getpeername is a cheap in-kernel
        // read, fine on the loop thread). Fail CLOSED on any failure — the
        // peer reset between accept and install, or the fd is not the TCP
        // socket a kTLS listener guarantees: shed rather than deliver the
        // consumer's handshake handler a connection with a wrong identity
        // (mirrors the plain-TCP `on_peer_fetch` policy). Then park the
        // slot: hold it (no `Connection`, no in-flight op) until the worker
        // signals.
        let Some(peer) = sock::peer_from_fd(fd) else {
            // SAFETY: close the freshly furnished fd we will not deliver.
            unsafe { libc::close(fd) };
            stat!(self.core, shed);
            return self.core.submit_teardown(slot, generation, true);
        };
        self.core.table.park_tls(slot, Box::new(peer.clone()));
        // Bound the park: if the consumer's handshake worker never calls back in
        // time, shed the slot (SECURITY: else a stalled TLS handshake pins a
        // pool slot indefinitely). No-op unless `tls_handshake_timeout` is set.
        self.arm_handshake_timeout(slot, generation)?;
        let deferral = AcceptDeferral {
            slot,
            // Channel handle: carry the full u64 generation (retained across the
            // consumer's handshake, so it must not alias a future incarnation).
            generation: self.core.table.generation(slot),
            tx: self.mailbox.handshake_tx.clone(),
            shared: Arc::clone(&self.core.engine.shared),
            done: false,
        };
        match self.handlers.tls_handshake.as_mut() {
            // Disjoint fields: the handler runs while `self.listeners` is
            // borrowed for the Incoming. The accept handler never runs for
            // kTLS connections (ready(state) IS the admission), so this
            // Incoming is their per-listener-policy hook.
            Some(h) => h(
                fd,
                Incoming {
                    peer: &peer,
                    listener_addr: &self.listeners[lidx as usize].addr,
                },
                deferral,
            ),
            None => {
                // Guarded at serve_forever, so unreachable in practice.
                drop(deferral); // → reject via Drop, drained next wake
                                // SAFETY: close the furnished fd we won't use.
                unsafe { libc::close(fd) };
            }
        }
        Ok(())
    }

    /// Drain kTLS handshake outcomes posted by consumer workers: install the
    /// connection (kTLS transport) on success, shed on failure or during
    /// shutdown. A stale outcome (slot recycled or no longer parked) is
    /// dropped, exactly like a stale deferred reply.
    pub(super) fn drain_handshake_outcomes(&mut self) -> errno::Result<()> {
        while let Ok(outcome) = self.mailbox.handshake_rx.try_recv() {
            let HandshakeOutcome {
                slot,
                generation,
                result,
            } = outcome;
            if self.core.table.generation(slot) != generation {
                continue; // slot recycled; outcome moot
            }
            let Some(peer) = self.core.table.take_tls_parked(slot) else {
                continue; // not parked (already resolved); outcome moot
            };
            // Resolved in time — cancel the handshake timeout so it doesn't fire
            // later and find the slot no longer parked. No-op unless armed. The
            // cancel targets a kernel op's user_data → low 32 bits.
            self.cancel_handshake_timeout(slot, generation as u32)?;
            match result {
                Ok(u) if !self.core.draining => {
                    self.install_conn(slot, *peer, u, true)?;
                }
                // Rejected, or ready but shutting down: shed the parked slot.
                _ => {
                    stat!(self.core, shed);
                    self.core.submit_teardown(slot, generation as u32, true)?;
                }
            }
        }
        Ok(())
    }

    /// Arm the standalone `TIMEOUT` bounding a parked kTLS handshake, keyed to
    /// `(slot, generation)`. On expiry `on_handshake_timeout` sheds the slot if
    /// it is still parked; a handshake that resolves first cancels it
    /// (`cancel_handshake_timeout`). No-op unless `tls_handshake_timeout` is set.
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

    /// Cancel a parked slot's handshake timeout once the handshake resolves.
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

    /// A parked kTLS slot's handshake timeout fired (or was cancelled — the
    /// result is irrelevant): if the slot is still parked at this generation the
    /// worker did not call back in time, so shed it (a late `ready()`/`reject()`
    /// then hits the bumped generation and is dropped). Otherwise it already
    /// resolved (or the slot recycled) — nothing to do.
    pub(super) fn on_handshake_timeout(
        &mut self,
        slot: u32,
        generation: u32,
    ) -> errno::Result<()> {
        if self.core.table.generation_low(slot) != generation {
            return Ok(()); // slot recycled
        }
        if self.core.table.take_tls_parked(slot).is_none() {
            return Ok(()); // resolved (no longer parked)
        }
        stat!(self.core, shed);
        self.core.submit_teardown(slot, generation, true)
    }

    /// Run the accept handler and install the connection (the tail of accept,
    /// after any peer-identity fetch).
    fn finish_accept(
        &mut self,
        slot: u32,
        peer: ClientAddr,
        lidx: u32,
    ) -> errno::Result<()> {
        let state = match (self.handlers.accept)(Incoming {
            peer: &peer,
            listener_addr: &self.listeners[lidx as usize].addr,
        }) {
            Some(u) => u,
            None => {
                stat!(self.core, rejected);
                return self.core.submit_teardown(slot, 0, true); // rejected
            }
        };
        self.install_conn(slot, peer, state, false)
    }

    /// Install a `Connection` into `slot` and start serving it. `ktls` selects
    /// the receive transport (a kTLS connection was already handshaken by the
    /// consumer's worker, so there is no accept handler to run here).
    fn install_conn(
        &mut self,
        slot: u32,
        peer: ClientAddr,
        state: U,
        ktls: bool,
    ) -> errno::Result<()> {
        let generation = self.core.table.generation_low(slot);
        let mut conn =
            Connection::new(peer, state, self.core.cfg.max_send_coalesce);
        if ktls {
            conn.install_ktls();
        }
        self.core.table.install(slot, conn);
        stat!(self.core, accepted);
        self.core
            .stats
            .active
            .store(u64::from(self.core.table.active()), Ordering::Relaxed);
        self.pump(slot, generation)
    }

    /// Fetch `SO_PEERCRED` for a just-accepted unix connection via a socket
    /// `URING_CMD` (kernel support verified up front by the startup probe).
    /// The landing pad parks in the slot (stable Box) until the completion.
    fn submit_cred(&mut self, slot: u32, lidx: u32) -> errno::Result<()> {
        let generation = self.core.table.generation_low(slot);
        // SAFETY: ucred is plain data; zeroed is a valid initial value.
        let pad: Box<libc::ucred> = Box::new(unsafe { std::mem::zeroed() });
        let optval = std::ptr::addr_of!(*pad) as u64;
        self.core.table.begin_peer_fetch(
            slot,
            PendingPeer::Cred {
                listener: lidx,
                pad,
            },
        );
        self.core
            .stage(pack(Op::Cred, slot, generation), move |sqe| {
                fill_getsockopt_cmd(
                    sqe,
                    libc::SO_PEERCRED,
                    optval,
                    size_of::<libc::ucred>() as u32,
                );
                sqe.fd = slot as i32;
                sqe.flags = IOSQE_FIXED_FILE;
            })
    }

    /// Fetch `SO_PEERNAME` for a just-accepted TCP connection via a socket
    /// `URING_CMD` (kernel support verified up front by the startup probe):
    /// a per-connection peer address, immune to the buffer-sharing race a
    /// multishot accept's addr argument would have.
    fn submit_peername(&mut self, slot: u32, lidx: u32) -> errno::Result<()> {
        let generation = self.core.table.generation_low(slot);
        // The kernel's SO_PEERNAME rejects an optlen LARGER than the actual
        // address (`if (lv < len) -EINVAL`), so request exactly the listener
        // family's sockaddr size. The landing pad is storage-sized regardless,
        // and `parse_peer` reads the family from it.
        let optlen = match self.listeners[lidx as usize].addr {
            ServerAddr::Tcp6(_) => size_of::<libc::sockaddr_in6>(),
            _ => size_of::<libc::sockaddr_in>(),
        } as u32;
        // SAFETY: sockaddr_storage is plain data; zeroed is valid.
        let pad: Box<libc::sockaddr_storage> =
            Box::new(unsafe { std::mem::zeroed() });
        let optval = std::ptr::addr_of!(*pad) as u64;
        self.core.table.begin_peer_fetch(
            slot,
            PendingPeer::Name {
                listener: lidx,
                pad,
            },
        );
        self.core
            .stage(pack(Op::Peername, slot, generation), move |sqe| {
                fill_getsockopt_cmd(sqe, libc::SO_PEERNAME, optval, optlen);
                sqe.fd = slot as i32;
                sqe.flags = IOSQE_FIXED_FILE;
            })
    }

    /// A peer-identity fetch (`SO_PEERCRED` or `SO_PEERNAME`) completed: shed
    /// the connection on a failed fetch, or run the deferred accept path with
    /// the peer identity. The stored [`PendingPeer`] variant says which fetch
    /// this was (the op and its landing pad are always set together), so one
    /// completion skeleton serves both — only the result validation and the
    /// pad parsing differ.
    pub(super) fn on_peer_fetch(
        &mut self,
        slot: u32,
        generation: u32,
        res: i32,
    ) -> errno::Result<()> {
        // Check the generation BEFORE taking the state: a stale completion for
        // a recycled slot must not clear the new incarnation's pending fetch
        // (matches `drain_handshake_outcomes`). Kernel completion →
        // compare only the low 32 bits the op's user_data carried.
        if self.core.table.generation_low(slot) != generation {
            return Ok(()); // slot recycled under us
        }
        let Some(pending) = self.core.table.take_peer_fetch(slot) else {
            return Ok(()); // stale (reaped at teardown)
        };
        let (listener, peer) = match pending {
            PendingPeer::Cred { listener, pad } => {
                if res != size_of::<libc::ucred>() as i32 {
                    // Fetch failed: fail closed — never deliver a
                    // credential-less connection when peercred was asked
                    // for. (Kernel support itself was verified by the
                    // startup probe.)
                    stat!(self.core, shed);
                    return self.core.submit_teardown(slot, 0, true);
                }
                let peer = ClientAddr::Unix {
                    cred: Some(PeerCred {
                        pid: pad.pid,
                        uid: pad.uid,
                        gid: pad.gid,
                    }),
                };
                (listener, peer)
            }
            PendingPeer::Name { listener, pad } => {
                // res = the address length written, or -errno (e.g. the peer
                // already reset — `ENOTCONN`). Require EXACTLY the requested
                // family size (16/28): a short or rewritten result — as a
                // cgroup getsockopt BPF program can produce — is not a
                // trustworthy address, so fail closed. `parse_peer` then
                // re-checks the family, so a correct-length-but-rewritten pad
                // also sheds rather than reading as a local `Unix` peer.
                let want = match self.listeners[listener as usize].addr {
                    ServerAddr::Tcp6(_) => size_of::<libc::sockaddr_in6>(),
                    _ => size_of::<libc::sockaddr_in>(),
                };
                let peer = (res >= 0 && res as usize == want)
                    .then(|| {
                        sock::parse_peer(
                            &pad,
                            &self.listeners[listener as usize].addr,
                        )
                    })
                    .flatten();
                let Some(peer) = peer else {
                    stat!(self.core, shed);
                    return self.core.submit_teardown(slot, 0, true);
                };
                (listener, peer)
            }
        };
        if self.core.draining {
            stat!(self.core, shed);
            return self.core.submit_teardown(slot, 0, true);
        }
        self.finish_accept(slot, peer, listener)
    }
}

// Arming the listener (and its retry backoff) runs no handler code —
// bounds-free, so the teardown path can re-arm a parked accept.
impl<U, AcceptFn, HeaderFn, BodyFn> Server<U, AcceptFn, HeaderFn, BodyFn> {
    /// Arm a short backoff `TIMEOUT`; its completion re-arms `lidx`'s accept.
    fn submit_accept_retry(&mut self, lidx: u32) -> errno::Result<()> {
        let ts = std::ptr::addr_of!(self.core.pads.accept_retry) as u64;
        self.core.stage(pack(Op::AcceptRetry, lidx, 0), move |sqe| {
            sqe.opcode = IORING_OP_TIMEOUT;
            sqe.addr = ts;
            sqe.len = 1; // exactly one timespec, per the kernel
        })
    }

    pub(super) fn arm_accept(&mut self, lidx: u32) -> errno::Result<()> {
        let fd = self.listeners[lidx as usize].fd.as_raw_fd();
        // No peer-address buffer: a multishot accept writes each connection's
        // address into the SAME buffer, so a burst misattributes peers. Peer
        // identity is instead fetched per connection after the accept
        // (`submit_peername`/`submit_cred`), race-free.
        self.core.stage(pack(Op::Accept, lidx, 0), move |sqe| {
            sqe.opcode = IORING_OP_ACCEPT;
            sqe.fd = fd;
            sqe.ioprio = IORING_ACCEPT_MULTISHOT;
            // SOCK_CLOEXEC is rejected for direct (pool) descriptors.
            sqe.op_flags = libc::SOCK_NONBLOCK as u32;
            sqe.file_index = IORING_FILE_INDEX_ALLOC;
        })?;
        self.listeners[lidx as usize].awaiting_slot = false;
        Ok(())
    }
}

/// Whether an accept error means the listener/setup is broken (retrying can't
/// help → propagate) rather than a transient resource shortage (retry with
/// backoff). Conservative: only genuinely unrecoverable errnos are fatal;
/// everything else — `ENOMEM`/`ENOBUFS`/`ECONNABORTED`/`EMFILE`/`EINTR`/… — is
/// treated as transient so a resource storm can't kill the server.
///
/// The fatal set is exactly the structural errors — the listener fd or the
/// accept SQE itself is wrong, so every re-arm fails identically:
/// * `EBADF` — the listener descriptor is not a valid open fd (closed, or never
///   registered).
/// * `EINVAL` — the socket is not `listen()`ing, or the accept arguments are
///   malformed.
/// * `EFAULT` — an address/length argument points outside our address space (a
///   bug in how the SQE was built).
/// * `ENOTSOCK` — the descriptor is not a socket (the wrong fd was registered).
///
/// Everything else can succeed on a later accept, so it backs off rather than
/// propagating: resource pressure (`ENOMEM`/`ENOBUFS`/`EMFILE`/`ENFILE`),
/// per-connection races (`ECONNABORTED`/`ECONNRESET`/`EPERM`), and `EINTR`.
fn accept_error_is_fatal(e: Errno) -> bool {
    matches!(
        e,
        Errno::EBADF | Errno::EINVAL | Errno::EFAULT | Errno::ENOTSOCK
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accept_errno_classification() {
        // Genuinely unrecoverable listener/setup errors are fatal.
        for e in [Errno::EBADF, Errno::EINVAL, Errno::EFAULT, Errno::ENOTSOCK] {
            assert!(accept_error_is_fatal(e), "{e:?} should be fatal");
        }
        // Transient resource-pressure errors must NOT be fatal (they back off
        // and retry rather than killing the server).
        for e in [
            Errno::ENOMEM,
            Errno::ENOBUFS,
            Errno::ECONNABORTED,
            Errno::EMFILE,
            Errno::EINTR,
            Errno::ECONNRESET,
            Errno::EPERM,
        ] {
            assert!(!accept_error_is_fatal(e), "{e:?} should be transient");
        }
    }
}
