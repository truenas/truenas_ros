//! Construction-time kernel capability probes (and the getsockopt `URING_CMD`
//! filler they share): fail fast with a clear validation error instead of
//! mysteriously shedding every connection at accept time.

use crate::errno::Errno;
use crate::error::Error;
use crate::fd::owned_from_raw;
use crate::net::core::ring::Ring;
use crate::net::core::sys::*;
use std::mem::size_of;
use std::os::fd::AsRawFd;

/// Fill `sqe` as a `SOCKET_URING_OP_GETSOCKOPT(SOL_SOCKET, optname)` command
/// reading `optlen` bytes into `optval` (which must be a stable address until
/// the CQE reaps). See `SOCKET_URING_OP_GETSOCKOPT` in `sys.rs` for the SQE
/// field overlay. The caller sets `fd` (plus `IOSQE_FIXED_FILE` for a pool
/// slot) and `user_data`; the CQE `res` is the written optlen or `-errno`.
pub(crate) fn fill_getsockopt_cmd(
    sqe: &mut IoUringSqe,
    optname: i32,
    optval: u64,
    optlen: u32,
) {
    sqe.opcode = IORING_OP_URING_CMD;
    // cmd_op lives in the low half of off/addr2.
    sqe.off_addr2 = u64::from(SOCKET_URING_OP_GETSOCKOPT);
    // level (low) and optname (high) overlay the addr field (LE).
    sqe.addr =
        (libc::SOL_SOCKET as u32 as u64) | ((optname as u32 as u64) << 32);
    // optlen overlays file_index; optval overlays addr3.
    sqe.file_index = optlen;
    sqe.addr3 = optval;
}

/// Probe whether this kernel accepts socket `URING_CMD`s on `AF_UNIX`.
///
/// The getsockopt command exists since Linux 6.7, but a too-strict
/// `prot->ioctl` guard rejected every socket command on `AF_UNIX` (whose
/// `struct proto` has no ioctl) with `EOPNOTSUPP` until the cmd_net fix
/// (6.18.16 in the 6.18 series). Probing a throwaway socketpair through the
/// just-created — and otherwise idle — ring turns "every unix connection
/// mysteriously shed" into an immediate, actionable construction error.
pub(crate) fn probe_unix_peercred(ring: &mut Ring) -> crate::Result<()> {
    let mut fds = [0i32; 2];
    // SAFETY: `fds` is a valid out-array for the two descriptors.
    Errno::result(unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            0,
            fds.as_mut_ptr(),
        )
    })?;
    // SAFETY: socketpair returned two fresh owned fds (closed on all paths).
    let pair = unsafe { (owned_from_raw(fds[0]), owned_from_raw(fds[1])) };

    // Boxed so the kernel's landing pad can outlive an (unreachable) error
    // path below without ever pointing at a dead stack frame.
    // SAFETY: ucred is plain data; zeroed is a valid initial value.
    let mut cred: Box<libc::ucred> = Box::new(unsafe { std::mem::zeroed() });
    let optval = std::ptr::addr_of_mut!(*cred) as u64;
    ring.push_sqe(|sqe| {
        fill_getsockopt_cmd(
            sqe,
            libc::SO_PEERCRED,
            optval,
            size_of::<libc::ucred>() as u32,
        );
        sqe.fd = pair.0.as_raw_fd();
        sqe.user_data = u64::MAX; // reaped below; never reaches the loop
    })?;
    let res = loop {
        if let Err(e) = ring.submit_and_wait(1) {
            // Enter failed with the op state unknowable: keep the landing pad
            // alive rather than risk a kernel write into freed memory.
            std::mem::forget(cred);
            return Err(e.into());
        }
        // `submit_and_wait` returns without a completion only on CQ
        // backpressure — impossible on this idle ring — so this cannot spin.
        if let Some(cqe) = ring.reap() {
            break cqe.res;
        }
    };
    if res == size_of::<libc::ucred>() as i32 {
        return Ok(());
    }
    Err(Error::Validation(format!(
        "unix_peercred requires io_uring socket commands on AF_UNIX \
         (Linux ≥ 6.18.16, the cmd_net ioctl-guard fix); probe got {}",
        if res < 0 {
            Errno::from_raw(-res).to_string()
        } else {
            format!("optlen {res}")
        }
    )))
}

/// Probe whether this kernel routes socket `URING_CMD`s for TCP (Linux ≥
/// 6.7) — the per-connection `SO_PEERNAME` fetch every TCP accept depends on.
/// A `SIOCOUTQ` command on a fresh, unconnected TCP socket needs no
/// bind/connect: it returns 0 (empty send queue) where supported and an error
/// where not, turning "every TCP connection mysteriously shed" into an
/// immediate, actionable construction error.
pub(crate) fn probe_tcp_cmd(ring: &mut Ring) -> crate::Result<()> {
    // SAFETY: standard socket() call; result checked against the sentinel.
    let raw = Errno::result(unsafe {
        libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0)
    })?;
    // SAFETY: socket() returned a fresh owned fd.
    let sock = unsafe { owned_from_raw(raw) };
    // SIOCOUTQ takes no operands and writes no user memory, so the early
    // error returns below leave nothing for the kernel to dangle on.
    ring.push_sqe(|sqe| {
        sqe.opcode = IORING_OP_URING_CMD;
        sqe.fd = sock.as_raw_fd();
        sqe.off_addr2 = u64::from(SOCKET_URING_OP_SIOCOUTQ);
        sqe.user_data = u64::MAX; // reaped below; never reaches the loop
    })?;
    let res = loop {
        ring.submit_and_wait(1)?;
        // `submit_and_wait` returns without a completion only on CQ
        // backpressure — impossible on this idle ring — so this cannot spin.
        if let Some(cqe) = ring.reap() {
            break cqe.res;
        }
    };
    drop(sock);
    if res >= 0 {
        return Ok(());
    }
    Err(Error::Validation(format!(
        "TCP listeners require io_uring socket commands (Linux ≥ 6.7) for \
         per-connection peer addresses; probe got {}",
        Errno::from_raw(-res)
    )))
}

/// Probe whether this kernel has the TLS ULP (the `tls` module / `CONFIG_TLS`)
/// that kernel-TLS listeners require. Attaching `TCP_ULP="tls"` to a fresh,
/// unconnected TCP socket returns `ENOPROTOOPT` when the ULP is absent and
/// something else (`ENOTCONN` — the ULP init wants an established socket) when
/// present, so it distinguishes availability without a handshake. Turns "every
/// kTLS connection mysteriously shed" into a clear construction error.
pub(crate) fn probe_ktls() -> crate::Result<()> {
    // SAFETY: standard socket() call; result checked against the -1 sentinel.
    let raw = Errno::result(unsafe {
        libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0)
    })?;
    // SAFETY: socket() returned a fresh owned fd (closed on drop).
    let sock = unsafe { owned_from_raw(raw) };
    let tls = b"tls\0";
    // SAFETY: setsockopt reads `tls` (4 bytes) as the ULP name; the fd is live.
    let rc = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            libc::IPPROTO_TCP,
            TCP_ULP,
            tls.as_ptr().cast(),
            tls.len() as libc::socklen_t,
        )
    };
    if rc == 0 {
        return Ok(()); // attached (unusual on an unconnected socket, but fine)
    }
    let err = Errno::last();
    // Fail CLOSED, like `probe_tcp_cmd`. On an unconnected socket the only
    // signal the ULP is actually present is the TLS ULP's own init refusing a
    // non-established socket with `ENOTCONN` (net/tls: `tls_init` checks
    // `sk_state == TCP_ESTABLISHED`). Every other result means it is absent:
    // an unregistered ULP name (`CONFIG_TLS=n`, or the `tls` module isn't
    // loaded — the common case) reports `ENOENT` from
    // `__tcp_ulp_find_autoload`, not `ENOPROTOOPT`; a kernel with no TCP_ULP
    // support at all reports `ENOPROTOOPT`. The previous test keyed only on
    // `ENOPROTOOPT` and so fell through the real `ENOENT` to `Ok`, defeating
    // this very gate (every kTLS connection would then be silently shed at its
    // first recv).
    if err == Errno::ENOTCONN {
        return Ok(());
    }
    Err(Error::Validation(format!(
        "kTLS listeners require the kernel TLS ULP (CONFIG_TLS / the `tls` \
         module); the setsockopt(TCP_ULP=\"tls\") probe got {err}"
    )))
}

/// Whether this kernel's io_uring supports `IORING_OP_FIXED_FD_INSTALL`
/// (Linux ≥ 6.8) — required to furnish a real fd for every kTLS handshake
/// (`Op::FdInstall`) and every connection detach (`Op::DetachInstall`).
/// Without this probe, a 6.7 kernel passes the socket-cmd and TLS-ULP probes
/// and then fails opcode 54 with `-EINVAL` at runtime: every kTLS accept is
/// silently shed and every `Response::Detach` closes its connection — the
/// mysterious failure mode this module exists to prevent.
///
/// Asks via `IORING_REGISTER_PROBE` (a control syscall on the already-built
/// ring; available far below our 6.7 floor), which reports per-opcode support
/// without executing anything. Any register failure reads as "unsupported" —
/// fail closed; the callers turn `false` into a clear validation error.
pub(crate) fn probe_fixed_fd_install(ring: &Ring) -> bool {
    #[repr(C)]
    struct ProbeBuf {
        header: IoUringProbeHeader,
        ops: [IoUringProbeOp; 256],
    }
    // SAFETY: all-integer plain data; zeroed is a valid initial value (the
    // kernel requires the probe argument zeroed and fills it).
    let mut buf: Box<ProbeBuf> = Box::new(unsafe { std::mem::zeroed() });
    // SAFETY: `buf` is a valid, zeroed probe argument sized for 256 op
    // entries, live across the call; the ring fd is live.
    let rc = unsafe {
        io_uring_register(
            ring.raw_fd(),
            IORING_REGISTER_PROBE,
            (&mut *buf as *mut ProbeBuf).cast(),
            buf.ops.len() as u32,
        )
    };
    if rc.is_err() {
        return false;
    }
    let op = IORING_OP_FIXED_FD_INSTALL;
    buf.header.last_op >= op
        && buf.ops[op as usize].flags & IO_URING_OP_SUPPORTED != 0
}
