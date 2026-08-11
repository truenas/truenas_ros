//! Describing an event and rendering its record text — pure string work, no
//! syscalls, so every rule below is unit tested directly.
//!
//! The field layout mirrors linux-PAM's (`op=<service>:<verb>`, `acct=`,
//! `addr=`, … `res=success|failed`), so a record built here sits beside PAM's
//! in `/var/log/audit/audit.log` and answers the same `ausearch`/`aureport`
//! queries. Values are libaudit-encoded: a clean value is `key="value"`, a
//! value needing encoding becomes `key=HEX` (uppercase, unquoted) — the shape
//! `auparse` decodes transparently.

use std::fmt::Write;

/// The `AUDIT_*` type of a record: its event class, and what `ausearch -m`
/// selects on.
///
/// The values are the userspace message range, `AUDIT_FIRST_USER_MSG` ..=
/// `AUDIT_LAST_USER_MSG` (`linux/audit.h`) — the types a process holding
/// `CAP_AUDIT_WRITE` may originate. The kernel uapi header names only the few
/// it treats specially, so the constants below carry the audit-userspace names
/// from `audit-records.h`; the numbers are what matters on the wire.
///
/// [`AuditType::new`] admits any value in the two userspace ranges, so a type
/// this crate predates is still reachable; anything else (a kernel-originated
/// or `CAP_AUDIT_CONTROL` type) is rejected rather than sent for the kernel to
/// refuse with `EINVAL`/`EPERM`.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AuditType(u16);

impl AuditType {
    /// `AUDIT_USER_AUTH` — user-space authentication (PAM's `auth` phase).
    pub const USER_AUTH: AuditType = AuditType(1100);
    /// `AUDIT_USER_ACCT` — user-space authorization (PAM's `account` phase);
    /// the type for an access denial.
    pub const USER_ACCT: AuditType = AuditType(1101);
    /// `AUDIT_USER_MGMT` — a user-account attribute changed.
    pub const USER_MGMT: AuditType = AuditType(1102);
    /// `AUDIT_CRED_ACQ` — a user credential was acquired.
    pub const CRED_ACQ: AuditType = AuditType(1103);
    /// `AUDIT_CRED_DISP` — a user credential was disposed of.
    pub const CRED_DISP: AuditType = AuditType(1104);
    /// `AUDIT_USER_START` — a user session started.
    pub const USER_START: AuditType = AuditType(1105);
    /// `AUDIT_USER_END` — a user session ended.
    pub const USER_END: AuditType = AuditType(1106);
    /// `AUDIT_USER_AVC` — a user-space AVC (MAC) message. The one user type
    /// the kernel still records while auditing is otherwise disabled.
    pub const USER_AVC: AuditType = AuditType(1107);
    /// `AUDIT_USER_CHAUTHTOK` — an account password or PIN changed.
    pub const USER_CHAUTHTOK: AuditType = AuditType(1108);
    /// `AUDIT_USER_ERR` — an account state error.
    pub const USER_ERR: AuditType = AuditType(1109);
    /// `AUDIT_CRED_REFR` — a user credential was refreshed.
    pub const CRED_REFR: AuditType = AuditType(1110);
    /// `AUDIT_USYS_CONFIG` — a user-space system configuration change.
    pub const USYS_CONFIG: AuditType = AuditType(1111);
    /// `AUDIT_USER_LOGIN` — a user logged in.
    pub const USER_LOGIN: AuditType = AuditType(1112);
    /// `AUDIT_USER_LOGOUT` — a user logged out.
    pub const USER_LOGOUT: AuditType = AuditType(1113);
    /// `AUDIT_ADD_USER` — a user account was added.
    pub const ADD_USER: AuditType = AuditType(1114);
    /// `AUDIT_DEL_USER` — a user account was deleted.
    pub const DEL_USER: AuditType = AuditType(1115);
    /// `AUDIT_ADD_GROUP` — a group account was added.
    pub const ADD_GROUP: AuditType = AuditType(1116);
    /// `AUDIT_DEL_GROUP` — a group account was deleted.
    pub const DEL_GROUP: AuditType = AuditType(1117);
    /// `AUDIT_DAC_CHECK` — a user-space DAC decision.
    pub const DAC_CHECK: AuditType = AuditType(1118);
    /// `AUDIT_CHGRP_ID` — a user-space group ID changed.
    pub const CHGRP_ID: AuditType = AuditType(1119);
    /// `AUDIT_TEST` — reserved for testing that the audit path works.
    pub const TEST: AuditType = AuditType(1120);
    /// `AUDIT_TRUSTED_APP` — a trusted application's own event, free-form
    /// text. The catch-all for a service auditing its own operations, and the
    /// [`Default`].
    pub const TRUSTED_APP: AuditType = AuditType(1121);
    /// `AUDIT_USER_SELINUX_ERR` — a user-space SELinux error.
    pub const USER_SELINUX_ERR: AuditType = AuditType(1122);
    /// `AUDIT_USER_CMD` — a shell command and its arguments.
    pub const USER_CMD: AuditType = AuditType(1123);
    /// `AUDIT_USER_TTY` — non-ICANON TTY input. Framed differently by the
    /// kernel (raw data, not `key=value` text), so it is not what this module
    /// builds — listed for completeness.
    pub const USER_TTY: AuditType = AuditType(1124);
    /// `AUDIT_CHUSER_ID` — supplemental data for a changed user ID.
    pub const CHUSER_ID: AuditType = AuditType(1125);
    /// `AUDIT_GRP_AUTH` — authentication against a group password.
    pub const GRP_AUTH: AuditType = AuditType(1126);
    /// `AUDIT_SYSTEM_BOOT` — the system booted.
    pub const SYSTEM_BOOT: AuditType = AuditType(1127);
    /// `AUDIT_SYSTEM_SHUTDOWN` — the system shut down.
    pub const SYSTEM_SHUTDOWN: AuditType = AuditType(1128);
    /// `AUDIT_SYSTEM_RUNLEVEL` — the system runlevel changed.
    pub const SYSTEM_RUNLEVEL: AuditType = AuditType(1129);
    /// `AUDIT_SERVICE_START` — a daemon started.
    pub const SERVICE_START: AuditType = AuditType(1130);
    /// `AUDIT_SERVICE_STOP` — a daemon stopped.
    pub const SERVICE_STOP: AuditType = AuditType(1131);
    /// `AUDIT_GRP_MGMT` — a group-account attribute changed.
    pub const GRP_MGMT: AuditType = AuditType(1132);
    /// `AUDIT_GRP_CHAUTHTOK` — a group password or PIN changed.
    pub const GRP_CHAUTHTOK: AuditType = AuditType(1133);
    /// `AUDIT_MAC_CHECK` — a user-space MAC decision.
    pub const MAC_CHECK: AuditType = AuditType(1134);
    /// `AUDIT_ACCT_LOCK` — an account was locked by an administrator.
    pub const ACCT_LOCK: AuditType = AuditType(1135);
    /// `AUDIT_ACCT_UNLOCK` — an account was unlocked by an administrator.
    pub const ACCT_UNLOCK: AuditType = AuditType(1136);
    /// `AUDIT_USER_DEVICE` — a user-space hotplug device change.
    pub const USER_DEVICE: AuditType = AuditType(1137);
    /// `AUDIT_SOFTWARE_UPDATE` — a software update event.
    pub const SOFTWARE_UPDATE: AuditType = AuditType(1138);

    /// First/last of the two userspace message ranges (`linux/audit.h`:
    /// `AUDIT_FIRST_USER_MSG`/`AUDIT_LAST_USER_MSG` and their `…MSG2` twins).
    const FIRST_USER_MSG: u16 = 1100;
    const LAST_USER_MSG: u16 = 1199;
    const FIRST_USER_MSG2: u16 = 2100;
    const LAST_USER_MSG2: u16 = 2999;

    /// Wrap a raw `AUDIT_*` number, rejecting anything outside the userspace
    /// ranges with [`Errno::EINVAL`] — those types are the kernel's own or
    /// need `CAP_AUDIT_CONTROL`, and sending one only earns an `EINVAL`/`EPERM`
    /// ack (or, worse, a control message we never meant to send).
    ///
    /// [`Errno::EINVAL`]: crate::errno::Errno::EINVAL
    pub const fn new(raw: u16) -> crate::errno::Result<AuditType> {
        match raw {
            Self::FIRST_USER_MSG..=Self::LAST_USER_MSG
            | Self::FIRST_USER_MSG2..=Self::LAST_USER_MSG2 => {
                Ok(AuditType(raw))
            }
            _ => Err(crate::errno::Errno::EINVAL),
        }
    }

    /// The raw `AUDIT_*` number placed in `nlmsg_type`.
    pub const fn raw(self) -> u16 {
        self.0
    }
}

impl Default for AuditType {
    /// [`AuditType::TRUSTED_APP`] — a service's own free-form event.
    fn default() -> Self {
        AuditType::TRUSTED_APP
    }
}

/// The principal an event describes, in linux-PAM's vocabulary.
///
/// Every field is optional: an unauthenticated or anonymous event still
/// audits, just with fewer fields. Anything outside this vocabulary —
/// credential ids, object names, operation arguments — goes on the event as a
/// plain [`AuditEvent::fields`] entry.
///
/// The kernel prefixes every user-space record with the *sending* process's
/// `pid`/`uid`/`auid`/`ses`, so these fields describe the principal the
/// service acted **for**, never the service's own process identity.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AuditPrincipal<'a> {
    /// Account name, emitted as `acct=` — the field `ausearch -ua` matches.
    pub user: Option<&'a str>,
    /// The account's Unix uid, emitted as `acct_uid=`. Deliberately *not*
    /// `uid=`: the kernel already stamps that with the sending process's uid,
    /// and a second `uid=` inside the message would collide with it.
    pub uid: Option<u32>,
    /// Client origin, emitted as `addr=` — e.g. `10.0.0.5:5234`, `unix:uid=0`.
    pub addr: Option<&'a str>,
    /// Credential class, emitted as `cred=` — e.g. `API_KEY`, `USER_SESSION`.
    pub cred: Option<&'a str>,
}

/// One audit event: what happened, to whom, and whether it worked.
///
/// Borrowed throughout, so describing an event allocates nothing — the record
/// text is rendered straight into a caller-owned buffer by
/// [`write_message`](Self::write_message), or into its own by
/// [`AuditSocket::send`](super::AuditSocket::send).
///
/// ```
/// use truenas_ros::audit::{AuditEvent, AuditPrincipal, AuditType};
///
/// let event = AuditEvent {
///     kind: AuditType::TRUSTED_APP,
///     service: "truenas-api",
///     verb: "method",
///     principal: AuditPrincipal {
///         user: Some("admin"),
///         addr: Some("10.0.0.5:5234"),
///         ..Default::default()
///     },
///     fields: &[("method", "pool.query")],
///     success: true,
/// };
///
/// let mut msg = String::new();
/// event.write_message(&mut msg);
/// assert!(msg.starts_with(r#"op=truenas-api:method acct="admin""#));
/// assert!(msg.ends_with(r#"method="pool.query" res=success"#));
/// ```
#[derive(Clone, Copy, Debug, Default)]
pub struct AuditEvent<'a> {
    /// The record's `AUDIT_*` class (what `ausearch -m` selects on).
    pub kind: AuditType,
    /// Operation namespace — emitted as `op=<service>:<verb>`, PAM-style.
    pub service: &'a str,
    /// The operation itself, e.g. `authentication`, `session_close`, `method`.
    pub verb: &'a str,
    /// Who the service acted for.
    pub principal: AuditPrincipal<'a>,
    /// Extra fields, emitted in order after the principal and before `res=`.
    /// Keys are sanitized and values encoded, so neither can split the record.
    pub fields: &'a [(&'a str, &'a str)],
    /// Emitted as `res=success` or `res=failed` — what `ausearch --success`
    /// filters on. PAM writes it last; so does this.
    pub success: bool,
}

impl AuditEvent<'_> {
    /// Append this event's `key=value` record text to `out`.
    ///
    /// Appends rather than replaces, so a caller can reuse one buffer across
    /// records by clearing it; [`AuditSocket`](super::AuditSocket) does
    /// exactly that.
    pub fn write_message(&self, out: &mut String) {
        // PAM writes `op=` as a bare token and readers take it verbatim, so
        // keep that shape when both halves are clean. The value always
        // contains the `:`, so a bare `op=` can never be mistaken for a
        // hex-encoded value (those are hex digits only). A caller-supplied
        // verb carrying a space or a quote would break the record, so that
        // case falls back to the encoded form.
        if needs_encoding(self.service) || needs_encoding(self.verb) {
            let mut op =
                String::with_capacity(self.service.len() + self.verb.len() + 1);
            op.push_str(self.service);
            op.push(':');
            op.push_str(self.verb);
            encode_nv(out, "op", &op);
        } else {
            separate(out);
            out.push_str("op=");
            out.push_str(self.service);
            out.push(':');
            out.push_str(self.verb);
        }

        push_opt(out, "acct", self.principal.user);
        if let Some(uid) = self.principal.uid {
            // Digits never need encoding, so write them straight into the
            // quoted value rather than through a formatted temporary.
            separate(out);
            out.push_str("acct_uid=\"");
            let _ = write!(out, "{uid}");
            out.push('"');
        }
        push_opt(out, "addr", self.principal.addr);
        push_opt(out, "cred", self.principal.cred);

        for (key, value) in self.fields {
            push_field(out, key, value);
        }

        separate(out);
        out.push_str(if self.success {
            "res=success"
        } else {
            "res=failed"
        });
    }
}

/// Append one `key=value` field, sanitizing the key. The common case — a key
/// already made of `[A-Za-z0-9_]` — borrows it as-is; only a key needing
/// repair allocates.
fn push_field(out: &mut String, key: &str, value: &str) {
    if key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
        encode_nv(out, key, value);
    } else {
        encode_nv(out, &sanitize_key(key), value);
    }
}

/// Append ` key=<encoded>` for a present value; write nothing if `None`.
fn push_opt(out: &mut String, key: &str, value: Option<&str>) {
    if let Some(v) = value {
        encode_nv(out, key, v);
    }
}

/// Space-separate this field from whatever precedes it.
fn separate(out: &mut String) {
    if !out.is_empty() {
        out.push(' ');
    }
}

/// Append `key="value"` (clean) or `key=HEX` (needs encoding), libaudit-style.
fn encode_nv(out: &mut String, key: &str, value: &str) {
    separate(out);
    out.push_str(key);
    out.push('=');
    if needs_encoding(value) {
        for b in value.bytes() {
            // `from_digit` cannot fail: both nibbles are < 16.
            let hi = char::from_digit(u32::from(b >> 4), 16).unwrap_or('0');
            let lo = char::from_digit(u32::from(b & 0x0f), 16).unwrap_or('0');
            out.push(hi.to_ascii_uppercase());
            out.push(lo.to_ascii_uppercase());
        }
    } else {
        out.push('"');
        out.push_str(value);
        out.push('"');
    }
}

/// The kernel's rule, from `audit_string_contains_control` (`kernel/audit.c`):
/// a `"`, or any byte outside `0x21..=0x7e`. The kernel walks the value as
/// `unsigned char`, so that range excludes `0x7f` and `0x80..=0xff` alike. An
/// empty value is encoded too, so it cannot be confused with a bare token.
///
/// One addition: `'` also forces encoding. The kernel wraps a user-space
/// record's text in `msg='…'` (`kernel/audit.c`) and does not encode an
/// apostrophe itself, so one inside a value closes that quote early.
fn needs_encoding(value: &str) -> bool {
    value.is_empty()
        || value
            .bytes()
            .any(|b| b == b'"' || b == b'\'' || !(0x21..=0x7e).contains(&b))
}

/// Keep a field name usable as an audit key (no spaces, `=`, or quotes): map
/// anything outside `[A-Za-z0-9_]` to `_`.
fn sanitize_key(key: &str) -> String {
    key.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errno::Errno;

    /// Render one event to its record text.
    fn msg(event: &AuditEvent<'_>) -> String {
        let mut out = String::new();
        event.write_message(&mut out);
        out
    }

    #[test]
    fn clean_value_is_quoted_dirty_is_hex() {
        let mut b = String::new();
        encode_nv(&mut b, "acct", "admin");
        encode_nv(&mut b, "x", "a b"); // space -> encode
        encode_nv(&mut b, "y", "he\"llo"); // quote -> encode
        assert_eq!(b, "acct=\"admin\" x=612062 y=6865226C6C6F");
        assert!(
            needs_encoding("a b") && needs_encoding("\"") && needs_encoding("")
        );
        assert!(!needs_encoding("admin") && !needs_encoding("API_KEY"));
    }

    #[test]
    fn high_bytes_are_encoded_like_the_kernel_encodes_them() {
        assert!(needs_encoding("café"));
        let mut b = String::new();
        encode_nv(&mut b, "acct", "café");
        // UTF-8 'é' is C3 A9; the whole value goes to hex, unquoted.
        assert_eq!(b, "acct=636166C3A9");
        assert!(!b.contains('"'));
        // The boundary: 0x7e is clean, 0x7f and 0x80 are not.
        assert!(!needs_encoding("~"));
        assert!(needs_encoding("\u{7f}"));
        assert!(needs_encoding(core::str::from_utf8(&[0xC2, 0x80]).unwrap()));
    }

    #[test]
    fn apostrophe_is_encoded_so_the_kernel_msg_quote_survives() {
        // The kernel logs our text as msg='<text>'; a bare `'` would end that
        // quote mid-record. libaudit lets it through, we do not.
        assert!(needs_encoding("o'brien"));
        let mut b = String::new();
        encode_nv(&mut b, "acct", "o'brien");
        assert_eq!(b, "acct=6F27627269656E");
        assert!(!b.contains('\''));
    }

    #[test]
    fn event_orders_fields_and_encodes_them() {
        let event = AuditEvent {
            kind: AuditType::TRUSTED_APP,
            service: "truenas-api",
            verb: "method",
            principal: AuditPrincipal {
                user: Some("admin"),
                uid: Some(0),
                addr: Some("10.0.0.5:5234"),
                cred: Some("API_KEY"),
            },
            fields: &[
                ("method", "pool.query"),
                ("event_desc", "query pools"), // has a space -> hex
            ],
            success: true,
        };
        assert_eq!(
            msg(&event),
            "op=truenas-api:method acct=\"admin\" acct_uid=\"0\" \
             addr=\"10.0.0.5:5234\" cred=\"API_KEY\" method=\"pool.query\" \
             event_desc=717565727920706F6F6C73 res=success"
        );
    }

    #[test]
    fn absent_principal_fields_are_skipped() {
        let event = AuditEvent {
            kind: AuditType::USER_AUTH,
            service: "svc",
            verb: "authentication",
            success: false,
            ..Default::default()
        };
        assert_eq!(msg(&event), "op=svc:authentication res=failed");
    }

    #[test]
    fn dirty_op_falls_back_to_the_encoded_form() {
        // A verb with a space cannot be a bare token without splitting the
        // record into two fields.
        let dirty = AuditEvent {
            service: "svc",
            verb: "a verb",
            success: true,
            ..Default::default()
        };
        assert_eq!(msg(&dirty), "op=7376633A612076657262 res=success");
        // ...while a clean one keeps PAM's bare shape.
        let clean = AuditEvent {
            service: "svc",
            verb: "verb",
            success: true,
            ..Default::default()
        };
        assert_eq!(msg(&clean), "op=svc:verb res=success");
    }

    #[test]
    fn field_keys_are_sanitized() {
        let event = AuditEvent {
            service: "svc",
            verb: "op",
            fields: &[("event data=x", "1"), ("plain_key9", "2")],
            success: true,
            ..Default::default()
        };
        assert_eq!(
            msg(&event),
            "op=svc:op event_data_x=\"1\" plain_key9=\"2\" res=success"
        );
    }

    #[test]
    fn write_message_appends_to_a_reused_buffer() {
        let event = AuditEvent {
            service: "svc",
            verb: "op",
            success: true,
            ..Default::default()
        };
        let mut buf = String::from("existing");
        event.write_message(&mut buf);
        assert_eq!(buf, "existing op=svc:op res=success");
        // Clearing is how a caller reuses one allocation per record.
        buf.clear();
        event.write_message(&mut buf);
        assert_eq!(buf, "op=svc:op res=success");
    }

    #[test]
    fn default_type_is_the_trusted_app_catch_all() {
        assert_eq!(AuditType::default(), AuditType::TRUSTED_APP);
        assert_eq!(AuditEvent::default().kind, AuditType::TRUSTED_APP);
    }

    #[test]
    fn audit_type_admits_only_the_userspace_ranges() {
        assert_eq!(AuditType::new(1121), Ok(AuditType::TRUSTED_APP));
        assert_eq!(AuditType::TRUSTED_APP.raw(), 1121);
        assert!(AuditType::new(1100).is_ok() && AuditType::new(1199).is_ok());
        assert!(AuditType::new(2100).is_ok() && AuditType::new(2999).is_ok());
        // Kernel-originated and control types are not ours to send.
        assert_eq!(AuditType::new(1099), Err(Errno::EINVAL)); // AUDIT_SET etc.
        assert_eq!(AuditType::new(1200), Err(Errno::EINVAL)); // daemon range
        assert_eq!(AuditType::new(1300), Err(Errno::EINVAL)); // SYSCALL
        assert_eq!(AuditType::new(3000), Err(Errno::EINVAL));
    }
}
