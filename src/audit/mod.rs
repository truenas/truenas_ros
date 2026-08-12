//! Linux kernel audit (`NETLINK_AUDIT`) — describe an event, send the record.
//!
//! [`AuditSocket`] writes one record per event to the kernel audit subsystem,
//! so a service's own events land in `/var/log/audit/audit.log` and are
//! queryable with `ausearch`/`aureport` alongside PAM's. This replaces
//! linking libaudit: the wire format is a 16-byte `nlmsghdr` plus
//! `key=value` text, and the whole binding is one small module.
//!
//! # The record
//!
//! Records follow linux-PAM's field conventions — `op=<service>:<verb>`,
//! `acct=`, `addr=`, and `res=success|failed` last — with an [`AuditType`]
//! naming the event class the way `ausearch -m` selects on. Everything beyond
//! that vocabulary rides as plain [`fields`](AuditEvent::fields), one
//! `key=value` pair each. Values are libaudit-encoded (`key="value"` when
//! clean, `key=HEX` otherwise), so a value can never split a record.
//!
//! There is no serialization layer here, by design: the caller knows its own
//! data and renders it into fields.
//!
//! ```no_run
//! use truenas_ros::audit::{AuditEvent, AuditPrincipal, AuditSocket, AuditType};
//!
//! let mut sock = AuditSocket::open()?;
//! sock.send(&AuditEvent {
//!     kind: AuditType::USER_AUTH,
//!     service: "truenas-api",
//!     verb: "authentication",
//!     principal: AuditPrincipal {
//!         user: Some("admin"),
//!         addr: Some("10.0.0.5:5234"),
//!         cred: Some("API_KEY"),
//!         ..Default::default()
//!     },
//!     fields: &[("method", "auth.login")],
//!     success: true,
//! })?;
//! # Ok::<(), truenas_ros::Errno>(())
//! ```
//!
//! yields, once the kernel has added its own `pid`/`uid`/`auid`/`ses` prefix:
//!
//! ```text
//! type=USER_AUTH msg=audit(1754899200.123:456): pid=931 uid=0 auid=0 ses=1
//!   msg='op=truenas-api:authentication acct="admin" addr="10.0.0.5:5234"
//!        cred="API_KEY" method="auth.login" res=success'
//! ```
//!
//! # Delivery is synchronous, and can block
//!
//! [`AuditSocket::send`] performs the `sendto` and reads the ack on the
//! calling thread. Under kernel-audit backpressure — `auditd` behind, backlog
//! over `audit_backlog_limit` — that send parks the calling thread in
//! `TASK_UNINTERRUPTIBLE` for up to `audit_backlog_wait_time` (default 60 s).
//! The stall is gated on backlog depth, **not** on the socket's `O_NONBLOCK`
//! flag, so no amount of non-blocking I/O avoids it.
//!
//! This module deliberately ships no queue, thread, or sink: an application
//! that cannot tolerate that stall on its hot path owns the policy — give the
//! socket a dedicated thread, or drive it from a work loop, and shed load the
//! way that suits it. [`AuditSocket::send_lost`] reports what such a policy
//! dropped, so the log shows the gap.
//!
//! # When audit is not available
//!
//! Missing `CAP_AUDIT_WRITE`, or a kernel with audit compiled out, is not an
//! error: the send reports [`SendStatus::Unavailable`] so a caller's loop can
//! treat it as "nothing to do" rather than a failure to retry. Note also that
//! with `audit_enabled == 0` the kernel *acks* every user message and discards
//! it, so [`SendStatus::Delivered`] means accepted, not necessarily logged.

mod netlink;
mod record;

pub use netlink::{AuditSocket, SendStatus, MAX_RECORD_LEN};
pub use record::{AuditEvent, AuditPrincipal, AuditType};

/// The netlink ack decoder, exposed to the fuzz crate (`fuzz/`) under `__fuzz`
/// only — `netlink` is a private module. Never part of the stable API.
///
/// Driven by `fuzz/fuzz_targets/audit_ack.rs`: the bytes arrive on a socket
/// every netlink peer can write to, so the decoder's length guards must hold
/// for a datagram of any shape.
#[cfg(feature = "__fuzz")]
pub mod fuzz {
    /// Interpret one received netlink datagram as an ack for `seq`; `None`
    /// means "not attributable, keep scanning".
    pub fn decode_ack(
        buf: &[u8],
        seq: u32,
    ) -> Option<crate::errno::Result<super::SendStatus>> {
        super::netlink::decode_ack(buf, seq)
    }
}
