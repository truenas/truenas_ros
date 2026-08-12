#![no_main]

//! Fuzz audit-record rendering for **log injection**.
//!
//! Every string on an `AuditEvent` is caller-supplied and, in practice,
//! attacker-influenced: an account name, a client address, a method argument.
//! The rendered text is wrapped by the kernel in `msg='…'` and later split back
//! into `key=value` pairs by `ausearch`. So no input may be able to
//! - introduce a space, and with it a token boundary that forges a new field,
//! - close the value's `"` early,
//! - close the kernel's `'` early,
//! - or embed a newline and forge a whole record.
//!
//! `needs_encoding` is the kernel's own rule (`audit_string_contains_control`)
//! plus `'`: a value is emitted bare-quoted only when every byte is in
//! `0x21..=0x7e` and none is `"` or `'`. Otherwise it is hex. This target
//! asserts the consequence — the record tokenizes into exactly the fields that
//! were put on it, and every value is either a clean quoted run or pure hex.

use libfuzzer_sys::fuzz_target;
use truenas_ros::audit::{AuditEvent, AuditPrincipal, AuditType};

/// A value is well-formed iff it is `"…"` with no quote, apostrophe, or byte
/// outside the printable range inside, or an even-length run of uppercase hex.
fn value_is_safe(v: &str) -> bool {
    if let Some(inner) = v.strip_prefix('"').and_then(|s| s.strip_suffix('"')) {
        // An empty value is the quoted empty string, matching the kernel's
        // rule (its control-character loop does not run for zero bytes).
        return inner
            .bytes()
            .all(|b| (0x21..=0x7e).contains(&b) && b != b'"' && b != b'\'');
    }
    !v.is_empty()
        && v.len() % 2 == 0
        && v.bytes()
            .all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b))
}

fuzz_target!(|input: (
    u16,
    String,
    String,
    Option<String>,
    Option<u32>,
    Option<String>,
    Option<String>,
    Vec<(String, String)>,
    bool,
)| {
    let (raw_kind, service, verb, user, uid, addr, cred, fields, success) =
        input;

    let fields: Vec<(&str, &str)> = fields
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let event = AuditEvent {
        kind: AuditType::new(raw_kind).unwrap_or_default(),
        service: &service,
        verb: &verb,
        principal: AuditPrincipal {
            user: user.as_deref(),
            uid,
            addr: addr.as_deref(),
            cred: cred.as_deref(),
        },
        fields: &fields,
        success,
    };

    let mut msg = String::new();
    event.write_message(&mut msg);

    // Nothing may break out of the kernel's `msg='…'` wrapper or forge a
    // record boundary.
    assert!(
        !msg.contains('\n') && !msg.contains('\r'),
        "record carries a line break: {msg:?}"
    );
    assert!(
        !msg.contains('\''),
        "record carries an apostrophe, closing the kernel's quote: {msg:?}"
    );

    // Values never contain a space, so splitting on one recovers exactly the
    // emitted tokens.
    let tokens: Vec<&str> = msg.split(' ').collect();
    let expected = 1 // op=
        + usize::from(user.is_some())
        + usize::from(uid.is_some())
        + usize::from(addr.is_some())
        + usize::from(cred.is_some())
        + fields.len()
        + 1; // res=
    assert_eq!(
        tokens.len(),
        expected,
        "record tokenized into {} fields, expected {expected}: {msg:?}",
        tokens.len()
    );

    // Three tokens are written bare, all of them chosen by the crate rather
    // than by a caller: the leading `op=`, which keeps PAM's unquoted shape
    // when both halves are clean (its value always carries the `:`, which no
    // hex run can, so it stays unambiguous), and the trailing `res=`, a fixed
    // literal. Everything between them is caller-supplied and must be quoted
    // or hex.
    //
    // Position, not key name, decides which rule applies. A service may name
    // one of its own `fields` "res" or "op" — key sanitizing constrains the
    // charset, not the vocabulary — so a token keyed `res` in the middle of
    // the record is an ordinary caller field and gets the strict rule.
    let last = tokens.len() - 1;
    for (i, token) in tokens.iter().enumerate() {
        let (key, value) = token
            .split_once('=')
            .unwrap_or_else(|| panic!("token is not key=value: {token:?}"));
        assert!(
            key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'),
            "key was not sanitized: {key:?}"
        );
        if i == 0 {
            assert_eq!(key, "op", "the record must open with op=");
            assert!(
                value_is_safe(value)
                    || (value.contains(':')
                        && value.bytes().all(|b| {
                            (0x21..=0x7e).contains(&b)
                                && b != b'"'
                                && b != b'\''
                        })),
                "unsafe op value: {value:?}"
            );
        } else if i == last {
            assert_eq!(
                *token,
                if success { "res=success" } else { "res=failed" },
                "the record must close with the outcome: {msg:?}"
            );
        } else {
            assert!(value_is_safe(value), "unsafe value for {key}: {value:?}");
        }
    }

    // Appending reuses the buffer: a second render must not disturb the first.
    let mut again = msg.clone();
    event.write_message(&mut again);
    assert!(
        again.starts_with(&msg),
        "appending a second record rewrote the first"
    );
});
