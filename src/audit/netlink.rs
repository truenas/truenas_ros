//! The `NETLINK_AUDIT` socket — one `nlmsghdr` per record, then the kernel's
//! `NLMSG_ERROR` ack.
//!
//! Writing needs `CAP_AUDIT_WRITE`; without it (or with kernel audit compiled
//! out / nobody listening) the kernel replies `EPERM`/`ECONNREFUSED`, which is
//! reported as [`SendStatus::Unavailable`] — a benign no-op, matching
//! libaudit's `audit_send_user_message`. That distinction is what lets a
//! caller's loop treat an unaudited host as "nothing to do" rather than a
//! failure to retry.
//!
//! This owns the syscall surface directly rather than linking libaudit: the
//! wire format is a fixed 16-byte header plus `key=value` text, and the whole
//! binding is under 200 lines.

use super::record::{AuditEvent, AuditType};
use crate::errno::{retry_on_eintr, Errno, Result};
use std::fmt;
use std::fmt::Write as _;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

/// `NETLINK_AUDIT` protocol number (`linux/netlink.h`).
const NETLINK_AUDIT: libc::c_int = 9;
/// `nlmsghdr` flags (`linux/netlink.h`): a request that wants an ack.
const NLM_F_REQUEST: u16 = 0x01;
const NLM_F_ACK: u16 = 0x04;
/// `nlmsghdr` type for an error/ack reply (`linux/netlink.h`).
const NLMSG_ERROR: u16 = 0x2;
/// The fixed `nlmsghdr` size, 4-byte aligned: len(u32) type(u16) flags(u16)
/// seq(u32) pid(u32).
const NLMSG_HDRLEN: usize = 16;
/// `AUDIT_MESSAGE_TEXT_MAX` (`include/uapi/linux/audit.h`). The kernel formats
/// a user-space record as `msg='%.*s'` with this as the precision
/// (`kernel/audit.c`); longer text is truncated there.
const AUDIT_MESSAGE_TEXT_MAX: usize = 8560;
/// libaudit's `MAX_AUDIT_MESSAGE_LENGTH`, which bounds the datagram rather
/// than the text. The kernel carries it only as a comment in
/// `include/uapi/linux/audit.h`.
const MAX_AUDIT_MESSAGE_LENGTH: usize = 8970;
/// How long to wait for the ack. The kernel acks promptly, so this is only a
/// safety net against wedging the caller.
const ACK_TIMEOUT_MS: libc::c_int = 1000;
/// How many datagrams to scan for our sequence number before giving up. An ack
/// whose `poll` timed out on an earlier send can still be queued ahead of ours.
const ACK_SCAN_LIMIT: usize = 4;

/// The largest record text `send_text` accepts. Bounded by the kernel's text
/// limit, not the datagram's, so longer text is rejected `EMSGSIZE` rather
/// than truncated in the log.
pub const MAX_RECORD_LEN: usize = AUDIT_MESSAGE_TEXT_MAX;

/// A full-length record, framed with its header and trailing NUL, fits one
/// datagram.
const _: () = assert!(MAX_RECORD_LEN + NLMSG_HDRLEN < MAX_AUDIT_MESSAGE_LENGTH);

/// The outcome of one emit attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SendStatus {
    /// The kernel accepted (ack'd) the record.
    ///
    /// Not proof that it was logged: with `audit_enabled == 0` the kernel acks
    /// success and discards every user message except `AUDIT_USER_AVC`.
    Delivered,
    /// Audit is benignly unavailable — no `CAP_AUDIT_WRITE` (`EPERM`), or
    /// kernel audit compiled out / nobody listening (`ECONNREFUSED`). A no-op,
    /// not an error.
    Unavailable,
}

/// An open `NETLINK_AUDIT` socket plus its per-socket sequence counter and
/// reusable buffers.
///
/// Single-owner by construction (`send` takes `&mut self`): concurrent use
/// would race the ack reads and the counter.
///
/// # Blocking
///
/// [`send`](Self::send) can block the calling thread **uninterruptibly** for up
/// to `audit_backlog_wait_time` (default 60 s). Once the kernel's queue exceeds
/// `audit_backlog_limit`, `kernel/audit.c:audit_receive()` parks the *sender*
/// in `TASK_UNINTERRUPTIBLE` in its own syscall context. That stall is gated on
/// backlog depth, **not** on the socket's `O_NONBLOCK` flag, so it cannot be
/// avoided by making the socket non-blocking or by polling for writability.
/// Do not call this from a latency-critical thread — give it a thread of its
/// own, or a work loop that tolerates the stall.
pub struct AuditSocket {
    fd: OwnedFd,
    seq: u32,
    /// The datagram (header + payload), rebuilt per send.
    buf: Vec<u8>,
    /// The rendered record text, rebuilt per send.
    msg: String,
}

impl fmt::Debug for AuditSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuditSocket")
            .field("fd", &self.fd.as_raw_fd())
            .field("seq", &self.seq)
            .finish_non_exhaustive()
    }
}

impl AuditSocket {
    /// Open the audit netlink socket.
    ///
    /// Succeeds without `CAP_AUDIT_WRITE` — the capability is checked per
    /// message, and a send without it reports
    /// [`SendStatus::Unavailable`] rather than failing.
    pub fn open() -> Result<AuditSocket> {
        // SAFETY: socket(2) with constant arguments; returns a fresh fd or -1
        // with errno set.
        let raw = Errno::result(unsafe {
            libc::socket(
                libc::PF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                NETLINK_AUDIT,
            )
        })?;
        // SAFETY: `raw` is a fresh, valid, owned fd (checked >= 0); `OwnedFd`
        // takes ownership and closes it on drop.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        Ok(AuditSocket {
            fd,
            seq: 0,
            buf: Vec::with_capacity(512),
            msg: String::with_capacity(512),
        })
    }

    /// Render `event` and send it as one audit record.
    ///
    /// The text is built into a buffer this socket owns, so an event costs no
    /// allocation once the buffers have grown.
    ///
    /// See the [type-level blocking note](Self#blocking) before calling this
    /// from a thread that must stay responsive.
    pub fn send(&mut self, event: &AuditEvent<'_>) -> Result<SendStatus> {
        // Move the buffer out so `send_text` can take `&mut self`, then put it
        // back with its capacity intact.
        let mut msg = std::mem::take(&mut self.msg);
        msg.clear();
        event.write_message(&mut msg);
        let sent = self.send_text(event.kind, &msg);
        self.msg = msg;
        sent
    }

    /// Send a record whose text the caller already built (via
    /// [`AuditEvent::write_message`] or by hand).
    pub fn send_raw(
        &mut self,
        kind: AuditType,
        msg: &str,
    ) -> Result<SendStatus> {
        self.send_text(kind, msg)
    }

    /// Report that `n` records were dropped before reaching this socket, so
    /// the log shows the gap rather than silently missing events — the kernel
    /// signals its own overflow the same way.
    ///
    /// A convenience for an application queueing records ahead of this socket:
    /// the count is formatted into the socket's own buffer, which a borrowed
    /// [`AuditEvent`] could not do.
    pub fn send_lost(&mut self, service: &str, n: u64) -> Result<SendStatus> {
        let mut count = String::new();
        let _ = write!(count, "{n}");
        self.send(&AuditEvent {
            kind: AuditType::TRUSTED_APP,
            service,
            verb: "audit_lost",
            fields: &[("lost", &count)],
            success: false,
            ..Default::default()
        })
    }

    /// Frame and send one `AUDIT_*` user message, then read its ack.
    fn send_text(&mut self, kind: AuditType, msg: &str) -> Result<SendStatus> {
        if msg.is_empty() {
            // The kernel rejects a payload shorter than two bytes ("exit early
            // if there isn't at least one character to print").
            return Err(Errno::EINVAL);
        }
        if msg.len() > MAX_RECORD_LEN {
            return Err(Errno::EMSGSIZE);
        }
        self.seq = self.seq.wrapping_add(1).max(1); // never 0
        let seq = self.seq;
        frame(&mut self.buf, seq, kind.raw(), msg);

        let addr = kernel_addr();
        // SAFETY: sendto(2) reads `buf.len()` bytes at `buf` and a
        // `sockaddr_nl` at `&addr` (both valid for the call) and writes
        // nothing through them. Returns bytes sent or -1.
        let sent = retry_on_eintr(|| unsafe {
            libc::sendto(
                self.fd.as_raw_fd(),
                self.buf.as_ptr().cast(),
                self.buf.len(),
                0,
                std::ptr::addr_of!(addr).cast(),
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        });
        match sent {
            Ok(_) => {}
            Err(Errno::EPERM | Errno::ECONNREFUSED) => {
                return Ok(SendStatus::Unavailable)
            }
            Err(e) => return Err(e),
        }
        self.read_ack(seq)
    }

    /// Read the kernel's `NLMSG_ERROR` ack for `seq`: `error == 0` is success,
    /// `-EPERM`/`-ECONNREFUSED` is benign unavailability, any other negative
    /// errno is an error.
    ///
    /// Acks carrying a different sequence number are stale — a previous send
    /// whose `poll` timed out — and are skipped rather than misattributed. A
    /// timeout is treated as delivered rather than wedging the caller.
    fn read_ack(&self, seq: u32) -> Result<SendStatus> {
        for _ in 0..ACK_SCAN_LIMIT {
            let mut pfd = libc::pollfd {
                fd: self.fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: poll(2) reads one valid `pollfd` and writes only its
            // `revents`; nothing else is touched.
            let ready = retry_on_eintr(|| unsafe {
                libc::poll(&mut pfd, 1, ACK_TIMEOUT_MS)
            })?;
            if ready == 0 {
                return Ok(SendStatus::Delivered); // timed out: best-effort
            }

            let mut buf = [0u8; 256];
            let mut src: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
            let mut srclen =
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t;
            // SAFETY: recvfrom(2) writes up to `buf.len()` bytes into `buf` and
            // the peer address into `src` (with `srclen` in/out); both are valid
            // for the call. Returns bytes read or -1.
            let n = retry_on_eintr(|| unsafe {
                libc::recvfrom(
                    self.fd.as_raw_fd(),
                    buf.as_mut_ptr().cast(),
                    buf.len(),
                    0,
                    std::ptr::addr_of_mut!(src).cast(),
                    &mut srclen,
                )
            })? as usize;
            // The kernel sends from port id 0. Any other port is a userspace
            // peer: skip rather than attribute the ack to it.
            if srclen as usize != std::mem::size_of::<libc::sockaddr_nl>()
                || src.nl_pid != 0
            {
                continue;
            }
            if n < NLMSG_HDRLEN {
                continue; // runt: not an ack we can attribute
            }
            if u32::from_ne_bytes([buf[8], buf[9], buf[10], buf[11]]) != seq {
                continue; // an earlier record's ack, arriving late
            }
            let ty = u16::from_ne_bytes([buf[4], buf[5]]);
            if ty == NLMSG_ERROR && n >= NLMSG_HDRLEN + 4 {
                // An NLMSG_ERROR carries a negative errno immediately after
                // the header (0 for a plain ack).
                let err =
                    i32::from_ne_bytes([buf[16], buf[17], buf[18], buf[19]]);
                return match err.unsigned_abs() as i32 {
                    0 => Ok(SendStatus::Delivered),
                    libc::EPERM | libc::ECONNREFUSED => {
                        Ok(SendStatus::Unavailable)
                    }
                    e => Err(Errno::from_raw(e)),
                };
            }
            return Ok(SendStatus::Delivered);
        }
        Ok(SendStatus::Delivered)
    }
}

/// Serialize one `nlmsghdr` plus its NUL-terminated payload into `buf`.
///
/// `nlmsg_pid` is left 0 so the kernel assigns the port id, and the payload is
/// NUL-terminated because libaudit sends `strlen(msg) + 1`.
fn frame(buf: &mut Vec<u8>, seq: u32, msg_type: u16, msg: &str) {
    let len = NLMSG_HDRLEN + msg.len() + 1;
    buf.clear();
    buf.reserve(len);
    buf.extend_from_slice(&(len as u32).to_ne_bytes()); // nlmsg_len
    buf.extend_from_slice(&msg_type.to_ne_bytes()); // nlmsg_type
    buf.extend_from_slice(&(NLM_F_REQUEST | NLM_F_ACK).to_ne_bytes()); // flags
    buf.extend_from_slice(&seq.to_ne_bytes()); // nlmsg_seq
    buf.extend_from_slice(&0u32.to_ne_bytes()); // nlmsg_pid
    buf.extend_from_slice(msg.as_bytes());
    buf.push(0);
}

/// A `sockaddr_nl` addressed to the kernel (`nl_pid = 0`, `nl_groups = 0`).
fn kernel_addr() -> libc::sockaddr_nl {
    // SAFETY: `sockaddr_nl` is a plain repr(C) struct of integers; an all-zero
    // value is valid (nl_pid = 0 = the kernel, nl_groups = 0). Only the family
    // is then set.
    let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    addr
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_lays_out_the_nlmsghdr() {
        let mut buf = Vec::new();
        frame(&mut buf, 7, AuditType::TRUSTED_APP.raw(), "op=svc:x");
        assert_eq!(buf.len(), NLMSG_HDRLEN + 8 + 1);
        assert_eq!(
            u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]),
            buf.len() as u32
        );
        assert_eq!(u16::from_ne_bytes([buf[4], buf[5]]), 1121);
        assert_eq!(u16::from_ne_bytes([buf[6], buf[7]]), 0x05); // REQUEST|ACK
        assert_eq!(u32::from_ne_bytes([buf[8], buf[9], buf[10], buf[11]]), 7);
        assert_eq!(
            u32::from_ne_bytes([buf[12], buf[13], buf[14], buf[15]]),
            0 // nlmsg_pid: the kernel assigns
        );
        assert_eq!(&buf[NLMSG_HDRLEN..buf.len() - 1], b"op=svc:x");
        assert_eq!(buf[buf.len() - 1], 0, "payload must be NUL-terminated");
    }

    #[test]
    fn frame_reuses_the_buffer() {
        let mut buf = Vec::new();
        frame(&mut buf, 1, 1121, "first-record");
        let first = buf.len();
        frame(&mut buf, 2, 1121, "x");
        assert!(buf.len() < first, "the buffer is cleared, not appended to");
        assert_eq!(&buf[NLMSG_HDRLEN..buf.len() - 1], b"x");
    }

    #[test]
    fn kernel_addr_is_af_netlink_to_pid_zero() {
        let addr = kernel_addr();
        assert_eq!(addr.nl_family, libc::AF_NETLINK as libc::sa_family_t);
        assert_eq!(addr.nl_pid, 0);
        assert_eq!(addr.nl_groups, 0);
    }

    #[test]
    fn empty_and_oversize_records_are_rejected_before_the_syscall() {
        // Needs no privilege: opening the socket is unprivileged, and both
        // guards run before any send.
        let Ok(mut sock) = AuditSocket::open() else {
            return; // no NETLINK_AUDIT here (sandbox/old kernel)
        };
        assert_eq!(
            sock.send_raw(AuditType::TEST, ""),
            Err(Errno::EINVAL),
            "the kernel rejects a payload under two bytes"
        );
        let huge = "x".repeat(MAX_RECORD_LEN + 1);
        assert_eq!(sock.send_raw(AuditType::TEST, &huge), Err(Errno::EMSGSIZE));
    }
}
