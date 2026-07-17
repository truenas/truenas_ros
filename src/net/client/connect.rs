//! Outbound connection establishment — the one client-specific subsystem.
//!
//! `connect_socket` creates the non-blocking client socket (CPython
//! `_connect_sock` mechanics, minus DNS), which is installed into the pool and
//! dialed with `IORING_OP_CONNECT`; `on_connect` turns the completion into a
//! serving connection (arming its first reply recv) or an
//! [`Event::ConnectFailed`](super::Event::ConnectFailed).

use super::{Client, ConnId, ConnectOpts, Event};
use crate::errno::{self, Errno};
use crate::fd::owned_from_raw;
use crate::net::core::conn::{pack, Connection, Op};
use crate::net::core::protocol::{ClientAddr, Framing, ServerAddr};
use crate::net::core::sock::{build_sockaddr, set_opt};
use crate::net::core::sys::*;
use crate::net::core::table::PendingConnect;
use std::collections::VecDeque;
use std::io;
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::atomic::Ordering;
use std::time::Duration;

/// Build a `__kernel_timespec` from a duration, clamping so an over-large value
/// can't wrap `tv_sec` negative — the kernel rejects that and cancels the
/// timeout's linked op, inverting "never" into "instantly".
pub(super) fn ts_of(d: Duration) -> KernelTimespec {
    KernelTimespec {
        tv_sec: d.as_secs().min(i64::MAX as u64) as i64,
        tv_nsec: d.subsec_nanos() as i64,
    }
}

/// Create a non-blocking client stream socket for `domain` and apply the
/// `cfg`'s TCP options (skipped for unix), optionally binding a local address
/// first. **`SOCK_NONBLOCK` is load-bearing**: the reply-body splice path's
/// `-EAGAIN` → readiness-poll slow-loris guard honors the file's `O_NONBLOCK`.
fn connect_socket(
    domain: libc::c_int,
    cfg: &super::ClientConfig,
    local_addr: Option<SocketAddr>,
) -> crate::Result<OwnedFd> {
    // SAFETY: standard socket() call; result checked against the -1 sentinel.
    let raw = Errno::result(unsafe {
        libc::socket(
            domain,
            libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        )
    })?;
    // SAFETY: socket() returned a fresh owned fd.
    let fd = unsafe { owned_from_raw(raw) };

    if matches!(domain, libc::AF_INET | libc::AF_INET6) {
        if cfg.nodelay {
            set_opt(&fd, libc::IPPROTO_TCP, libc::TCP_NODELAY, 1)?;
        }
        if let Some(idle) = cfg.keepalive {
            set_opt(&fd, libc::SOL_SOCKET, libc::SO_KEEPALIVE, 1)?;
            // TCP_KEEPIDLE is whole seconds, >= 1; the config doc rounds UP.
            let secs =
                idle.as_secs()
                    .saturating_add(u64::from(idle.subsec_nanos() != 0))
                    .clamp(1, i32::MAX as u64) as libc::c_int;
            set_opt(&fd, libc::IPPROTO_TCP, libc::TCP_KEEPIDLE, secs)?;
        }
        if let Some(t) = cfg.tcp_user_timeout {
            // TCP_USER_TIMEOUT is milliseconds.
            let ms = t.as_millis().clamp(1, i32::MAX as u128) as libc::c_int;
            set_opt(&fd, libc::IPPROTO_TCP, libc::TCP_USER_TIMEOUT, ms)?;
        }
    }

    if let Some(la) = local_addr {
        let bind_addr = match la {
            SocketAddr::V4(v4) => ServerAddr::Tcp(v4),
            SocketAddr::V6(v6) => ServerAddr::Tcp6(v6),
        };
        let sa = build_sockaddr(&bind_addr)?;
        // SAFETY: `sa.storage`/`sa.len` describe a valid sockaddr for `la`.
        Errno::result(unsafe {
            libc::bind(
                fd.as_raw_fd(),
                (&sa.storage as *const libc::sockaddr_storage)
                    .cast::<libc::sockaddr>(),
                sa.len,
            )
        })?;
    }
    Ok(fd)
}

/// The `ClientAddr` for a dialed address — the client knows its peer, so no
/// post-connect peer fetch is needed.
fn peer_of(addr: &ServerAddr) -> ClientAddr {
    match addr {
        ServerAddr::Tcp(v4) => ClientAddr::Inet(SocketAddr::V4(*v4)),
        ServerAddr::Tcp6(v6) => ClientAddr::Inet(SocketAddr::V6(*v6)),
        ServerAddr::Unix(_) => ClientAddr::Unix { cred: None },
    }
}

impl<U, F> Client<U, F>
where
    F: FnMut(&[u8], &mut U) -> Framing,
{
    /// Dial `addr` with a default `U`, blocking until the connection is
    /// established, and return its [`ConnId`] — already `Serving`, so `send`
    /// and `request` work on it immediately (the simple
    /// `connect()?`/`request()?` path).
    ///
    /// Pumps the ring until *this* connection comes up, buffering any events
    /// for other connections seen meanwhile for a later
    /// [`next_event`](Client::next_event). Returns `Err` if the connect fails
    /// (refused, timed out, unreachable) or on a synchronous setup failure
    /// (socket/bind, a full pool, or the ring). For the non-blocking form —
    /// readiness delivered as an [`Event`] — see
    /// [`connect_start`](Client::connect_start).
    pub fn connect(
        &mut self,
        addr: ServerAddr,
        opts: ConnectOpts,
    ) -> io::Result<ConnId>
    where
        U: Default,
    {
        self.connect_with_state(addr, opts, U::default())
    }

    /// As [`connect`](Client::connect), with an explicit initial per-connection
    /// state `state`.
    pub fn connect_with_state(
        &mut self,
        addr: ServerAddr,
        opts: ConnectOpts,
        state: U,
    ) -> io::Result<ConnId> {
        let conn = self.connect_start_with_state(addr, opts, state)?;
        self.await_connect(conn)
    }

    /// Dial `addr` with a default `U` and return the connection's [`ConnId`]
    /// immediately, **without** blocking. Its readiness is delivered as
    /// [`Event::Connected`] (or [`Event::ConnectFailed`]) from a later
    /// [`next_event`](Client::next_event); until then the connection is not yet
    /// serving, so `send`/`request` on it return
    /// [`NotConnected`](std::io::ErrorKind::NotConnected). `Err` only for a
    /// synchronous setup failure (socket/bind, a full pool, or the ring).
    pub fn connect_start(
        &mut self,
        addr: ServerAddr,
        opts: ConnectOpts,
    ) -> io::Result<ConnId>
    where
        U: Default,
    {
        self.connect_start_with_state(addr, opts, U::default())
    }

    /// As [`connect_start`](Client::connect_start), with an explicit initial
    /// per-connection state `state`.
    pub fn connect_start_with_state(
        &mut self,
        addr: ServerAddr,
        opts: ConnectOpts,
        state: U,
    ) -> io::Result<ConnId> {
        if opts.tls {
            // A `tls` connect needs the handshake hook plus a kernel that can
            // furnish a real fd (`FIXED_FD_INSTALL`, Linux >= 6.8) and run kTLS
            // (the TLS ULP) — fail cleanly here rather than mid-handshake.
            if self.tls_connect.is_none() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "a tls connect requires Client::set_tls_handshake",
                ));
            }
            if !self.core.fixed_fd_install || !self.ktls_supported {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "kTLS connect requires IORING_OP_FIXED_FD_INSTALL \
                     (Linux >= 6.8) and the kernel TLS ULP",
                ));
            }
        }
        let domain = match addr {
            ServerAddr::Tcp(_) => libc::AF_INET,
            ServerAddr::Tcp6(_) => libc::AF_INET6,
            ServerAddr::Unix(_) => libc::AF_UNIX,
        };
        let fd = connect_socket(domain, &self.cfg, opts.local_addr)?;
        let target = build_sockaddr(&addr)?;
        let peer = peer_of(&addr);
        let effective_timeout =
            opts.connect_timeout.or(self.cfg.connect_timeout);

        let pending = Box::new(PendingConnect {
            addr: Box::new(target),
            peer,
            state,
            server_addr: addr,
            timeout: effective_timeout.map(ts_of).unwrap_or_default(),
            tls: opts.tls,
        });
        let Some(slot) = self.core.table.reserve_connecting(pending) else {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "connection pool is full",
            ));
        };
        // Install the connected socket into the pool at `slot`; the kernel takes
        // its own reference, so the userspace fd is closed right after.
        if let Err(e) = self.core.ring.install_file(slot, fd.as_raw_fd()) {
            // Nothing was installed: drop the pending state and free the slot.
            self.core.table.take_connecting(slot);
            self.core.table.free(slot);
            return Err(e.into());
        }
        drop(fd);

        let generation = self.core.table.generation_low(slot);
        let (addr_ptr, addr_len, ts_ptr) = self
            .core
            .table
            .connecting_addr(slot)
            .expect("slot just reserved as Connecting");
        let connect_ud = pack(Op::Connect, slot, generation);
        let fill = move |sqe: &mut IoUringSqe| {
            sqe.opcode = IORING_OP_CONNECT;
            // Fixed (pool) descriptor at `slot`; addr@16, addr len@8. The
            // kernel rejects a non-zero len/op_flags/buf_index/file_index, so
            // leave them zeroed (the SQE arrives zeroed).
            sqe.fd = slot as i32;
            sqe.flags = IOSQE_FIXED_FILE;
            sqe.addr = addr_ptr;
            sqe.off_addr2 = u64::from(addr_len);
        };
        let staged = if effective_timeout.is_some() {
            self.core.stage_linked(
                connect_ud,
                move |sqe| {
                    fill(sqe);
                    sqe.flags |= IOSQE_IO_LINK;
                },
                pack(Op::LinkTimeout, slot, generation),
                move |sqe| {
                    sqe.opcode = IORING_OP_LINK_TIMEOUT;
                    sqe.fd = -1;
                    sqe.addr = ts_ptr;
                    sqe.len = 1; // exactly one timespec, per the kernel
                },
            )
        } else {
            self.core.stage(connect_ud, fill)
        };
        if let Err(e) = staged {
            // The socket is installed but the CONNECT never staged: uninstall
            // the fixed descriptor (dropping the kernel's ref closes it) and
            // free the slot.
            let _ = self.core.ring.install_file(slot, -1);
            self.core.table.take_connecting(slot);
            self.core.table.free(slot);
            return Err(e.into());
        }
        let gen64 = self.core.table.generation(slot);
        Ok(ConnId::new(slot, gen64))
    }

    /// The blocking half of [`connect_with_state`](Client::connect_with_state):
    /// pump the ring until `conn` reaches [`Event::Connected`] (→ `Ok(conn)`)
    /// or [`Event::ConnectFailed`] (→ `Err`), buffering every *other*
    /// connection's events for a later [`next_event`](Client::next_event)
    /// exactly as [`request`](Client::request) does. The connect op is in
    /// flight when this is called, so the pump always resolves to one of the
    /// two outcomes for `conn`.
    fn await_connect(&mut self, conn: ConnId) -> io::Result<ConnId> {
        let mut stash: VecDeque<Event> = VecDeque::new();
        let out = loop {
            match self.next_event()? {
                Some(Event::Connected { conn: c }) if c == conn => {
                    break Ok(conn)
                }
                Some(Event::ConnectFailed { conn: c, err }) if c == conn => {
                    break Err(err.into())
                }
                Some(ev) => stash.push_back(ev),
                None => {
                    break Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "connection ended before it was established",
                    ))
                }
            }
        };
        // Restore the buffered events ahead of any queued after them.
        stash.append(&mut self.events);
        self.events = stash;
        out
    }

    /// An `IORING_OP_CONNECT` completed: `res == 0` established the connection —
    /// install it, emit [`Event::Connected`], and arm its first reply recv;
    /// `res < 0` failed — emit [`Event::ConnectFailed`] and reclaim the slot
    /// (closing the installed descriptor).
    pub(super) fn on_connect(
        &mut self,
        slot: u32,
        generation: u32,
        res: i32,
    ) -> errno::Result<()> {
        // Kernel completion → low 32 bits. A recycled slot (stale completion)
        // no longer matches; a `Connecting` slot cannot recycle underneath us
        // (`reserve_connecting` skips non-`Empty` slots), so this only guards
        // an out-of-order stale CQE.
        if self.core.table.generation_low(slot) != generation {
            return Ok(());
        }
        if res == 0 {
            // A kTLS connect furnishes a real fd for the handshake worker
            // instead of installing the connection now; the slot stays
            // `Connecting` (holding `U` + peer) until `on_fd_install` parks it.
            if self.core.table.connecting_tls(slot) {
                return self.submit_fd_install(slot, generation);
            }
            let Some(pending) = self.core.table.take_connecting(slot) else {
                return Ok(()); // not connecting (already resolved)
            };
            let PendingConnect { peer, state, .. } = *pending;
            let max_send_coalesce = self.core.cfg.max_send_coalesce;
            let conn = Connection::new(peer, state, max_send_coalesce);
            self.core.table.install(slot, conn);
            self.core
                .stats
                .active
                .store(u64::from(self.core.table.active()), Ordering::Relaxed);
            let gen64 = self.core.table.generation(slot);
            self.events.push_back(Event::Connected {
                conn: ConnId::new(slot, gen64),
            });
            // Arm the reply recv exactly as the server arms its first read: the
            // pump frames `Need(header)` on the empty buffer and submits it.
            self.pump(slot, generation)?;
            Ok(())
        } else {
            // Report the failure, then reclaim: the slot stays `Connecting`
            // (non-`Empty`, so no concurrent connect can grab it) until the
            // CLOSE frees it — closing the installed descriptor. A cancelled
            // connect is the linked connect-timeout firing.
            let gen64 = self.core.table.generation(slot);
            let err = if res == -libc::ECANCELED {
                Errno::ETIMEDOUT
            } else {
                Errno::from_raw(-res)
            };
            self.events.push_back(Event::ConnectFailed {
                conn: ConnId::new(slot, gen64),
                err,
            });
            // Close the pool descriptor; `on_closed` frees the (non-serving)
            // slot when it completes. No SHUTDOWN — the connect never
            // established, so there is no FIN owed.
            self.core
                .stage(pack(Op::Close, slot, generation), move |sqe| {
                    sqe.opcode = IORING_OP_CLOSE;
                    sqe.fd = 0;
                    sqe.file_index = slot + 1;
                })
        }
    }
}
