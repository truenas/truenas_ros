#![no_main]

//! Fuzz the request-head analysis (`http::fuzz::head_facts`): `httparse` tokenizing plus the semantic screens (body
//! framing, Host, `Expect`) over arbitrary bytes.
//!
//! Never panics; a complete head's declared length fits the input; a failed head dies with one of the codec's promised
//! statuses; and — the production shape — the facts computed on the full buffer are reproduced exactly when the
//! declared head bytes are re-parsed alone, because that is what the glue's dispatch does with the framer's
//! `header_len` when no index describes the head. When one does, dispatch rebuilds the view from the index instead, so
//! that view must equal a tokenize of the same bytes.

use libfuzzer_sys::fuzz_target;
use truenas_ros::http::fuzz::{head_facts, index_agrees};

fuzz_target!(|data: &[u8]| {
    match head_facts(data) {
        Ok(Some((len, expects_continue, body_ok, target))) => {
            assert!(
                len > 0 && len <= data.len(),
                "head len {len} out of bounds for {}",
                data.len()
            );
            // An origin server serves origin-form, and `*` only for OPTIONS. An absolute-form that kept its authority,
            // or an authority-form, must have died, since a front end routing on one authority and this server on the
            // other disagree about the bucket. Only the shape is asserted, since `GET /://k` is legal origin-form.
            assert!(
                target.starts_with('/') || target == "*",
                "unreduced target handed on: {target:?}"
            );
            // The glue re-parses exactly the declared head bytes; the two walks must agree byte for byte.
            match head_facts(&data[..len]) {
                Ok(Some(again)) => assert_eq!(
                    again,
                    (len, expects_continue, body_ok, target),
                    "re-parse of the declared head diverged"
                ),
                other => {
                    panic!("declared head no longer parses: {other:?}")
                }
            }
            // The glue views the head through the index the framer recorded. Every complete head must be described by
            // its index, and the view must be the one a tokenize gives.
            assert_eq!(
                index_agrees(data),
                Some(true),
                "the head index and a parse of the head diverged"
            );
        }
        // Need more bytes.
        Ok(None) => {}
        // The promised die statuses: 400 malformed/Host rules, 431 too many headers, 505 unsupported version.
        Err(status) => assert!(matches!(status, 400 | 431 | 505), "unpromised die status {status}"),
    }
});
