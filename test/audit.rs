//! Integration tests for `truenas_ros::audit` (mirrors `src/`, nix
//! convention).
//!
//! These send **real records** to the kernel audit subsystem. Three
//! environments are tolerated, because all three are legitimate:
//!
//! * no `NETLINK_AUDIT` at all (a sandbox, or audit compiled out) - the socket
//!   cannot open, and the suite skips;
//! * a socket but no `CAP_AUDIT_WRITE` - the kernel answers `EPERM`, surfaced
//!   as [`SendStatus::Unavailable`], which is a pass;
//! * the real thing - records are accepted and land in `audit.log`
//!   (`ausearch -m TEST,TRUSTED_APP -ts recent` to see them).
//!
//! Set `TRUENAS_ROS_REQUIRE_AUDIT=1` to turn the first two into hard failures,
//! the way `TRUENAS_ROS_REQUIRE_IO_URING` does for the net suites.
#![cfg(all(target_os = "linux", feature = "audit"))]

use truenas_ros::audit::{
    AuditEvent, AuditPrincipal, AuditSocket, AuditType, MAX_RECORD_LEN,
    SendStatus,
};
use truenas_ros::errno::Errno;

/// Whether a missing audit subsystem should fail rather than skip.
fn audit_required() -> bool {
    std::env::var_os("TRUENAS_ROS_REQUIRE_AUDIT").is_some_and(|v| v == "1")
}

/// Open the audit socket, or skip (unless the env var demands otherwise).
fn socket() -> Option<AuditSocket> {
    match AuditSocket::open() {
        Ok(sock) => Some(sock),
        Err(e) if audit_required() => {
            panic!("TRUENAS_ROS_REQUIRE_AUDIT=1 but the socket failed: {e}")
        }
        Err(_) => None,
    }
}

/// Assert a send succeeded, holding `Unavailable` to the same env-var rule.
fn check(status: truenas_ros::errno::Result<SendStatus>) {
    match status {
        Ok(SendStatus::Delivered) => {}
        Ok(SendStatus::Unavailable) if audit_required() => panic!(
            "TRUENAS_ROS_REQUIRE_AUDIT=1 but audit is unavailable \
             (no CAP_AUDIT_WRITE, or kernel audit is off)"
        ),
        Ok(SendStatus::Unavailable) => {}
        Err(e) => panic!("audit send failed: {e}"),
    }
}

#[test]
fn sends_a_test_record() {
    let Some(mut sock) = socket() else { return };
    check(sock.send(&AuditEvent {
        kind: AuditType::TEST,
        service: "truenas-ros-test",
        verb: "self_test",
        principal: AuditPrincipal {
            user: Some("root"),
            uid: Some(0),
            addr: Some("unix:uid=0"),
            cred: Some("TEST"),
        },
        fields: &[("suite", "audit"), ("desc", "a value with spaces")],
        success: true,
    }));
}

#[test]
fn sends_a_burst_over_one_socket() {
    // The sequence counter advances per record and each ack is matched to its
    // own send; a burst is where a mismatch would show up.
    let Some(mut sock) = socket() else { return };
    for i in 0..32 {
        let n = i.to_string();
        check(sock.send(&AuditEvent {
            kind: AuditType::TRUSTED_APP,
            service: "truenas-ros-test",
            verb: "burst",
            fields: &[("seq", &n)],
            success: i % 2 == 0,
            ..Default::default()
        }));
    }
}

#[test]
fn sends_a_failure_and_a_lost_report() {
    let Some(mut sock) = socket() else { return };
    check(sock.send(&AuditEvent {
        kind: AuditType::USER_ACCT,
        service: "truenas-ros-test",
        verb: "accounting",
        principal: AuditPrincipal {
            user: Some("nobody"),
            ..Default::default()
        },
        fields: &[("event_error", "Not authorized")],
        success: false,
    }));
    check(sock.send_lost("truenas-ros-test", 7));
}

#[test]
fn sends_pre_rendered_text() {
    let Some(mut sock) = socket() else { return };
    let event = AuditEvent {
        kind: AuditType::TRUSTED_APP,
        service: "truenas-ros-test",
        verb: "prerendered",
        success: true,
        ..Default::default()
    };
    // The text an application built (or logged) elsewhere goes out verbatim.
    let mut msg = String::new();
    event.write_message(&mut msg);
    assert_eq!(msg, "op=truenas-ros-test:prerendered res=success");
    check(sock.send_raw(event.kind, &msg));
}

#[test]
fn rejects_empty_and_oversize_records() {
    let Some(mut sock) = socket() else { return };
    // Guarded before the syscall, so these hold with or without privilege.
    assert_eq!(sock.send_raw(AuditType::TEST, ""), Err(Errno::EINVAL));
    let huge = "x".repeat(MAX_RECORD_LEN + 1);
    assert_eq!(sock.send_raw(AuditType::TEST, &huge), Err(Errno::EMSGSIZE));
    // ...and a record right at the cap is accepted by the length check.
    let (prefix, suffix) = ("op=truenas-ros-test:cap desc=", " res=success");
    let fill = "x".repeat(MAX_RECORD_LEN - prefix.len() - suffix.len());
    let at_cap = format!("{prefix}{fill}{suffix}");
    assert_eq!(at_cap.len(), MAX_RECORD_LEN);
    check(sock.send_raw(AuditType::TEST, &at_cap));
}

#[test]
fn kernel_only_types_are_rejected_without_a_socket() {
    // Needs no audit subsystem at all: the type is validated in userspace.
    assert_eq!(AuditType::new(1300), Err(Errno::EINVAL)); // AUDIT_SYSCALL
    assert_eq!(AuditType::new(1121), Ok(AuditType::TRUSTED_APP));
}
