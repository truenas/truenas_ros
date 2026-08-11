#![no_main]

//! Fuzz the request-head analysis (`http::fuzz::head_facts`): `httparse`
//! tokenizing plus the semantic screens (body framing, Host, `Expect`) over
//! arbitrary bytes.
//!
//! Never panics; a complete head's declared length fits the input; a failed
//! head dies with one of the codec's promised statuses; and — the production
//! shape — the facts computed on the full buffer are reproduced exactly when
//! the declared head bytes are re-parsed alone, because that is what the
//! glue's dispatch does with the framer's `header_len`.

use libfuzzer_sys::fuzz_target;
use truenas_ros::http::fuzz::head_facts;

fuzz_target!(|data: &[u8]| {
    match head_facts(data) {
        Ok(Some((len, expects_continue, body_ok))) => {
            assert!(
                len > 0 && len <= data.len(),
                "head len {len} out of bounds for {}",
                data.len()
            );
            // The glue re-parses exactly the declared head bytes; the two
            // walks must agree byte for byte.
            match head_facts(&data[..len]) {
                Ok(Some(again)) => assert_eq!(
                    again,
                    (len, expects_continue, body_ok),
                    "re-parse of the declared head diverged"
                ),
                other => {
                    panic!("declared head no longer parses: {other:?}")
                }
            }
        }
        // Need more bytes.
        Ok(None) => {}
        // The promised die statuses: 400 malformed/Host rules, 431 too many
        // headers, 505 unsupported version.
        Err(status) => assert!(
            matches!(status, 400 | 431 | 505),
            "unpromised die status {status}"
        ),
    }
});
