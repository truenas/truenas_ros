#![no_main]

//! Fuzz the http codec's framing state machine end to end
//! (`http::fuzz::drive_frame`): arbitrary bytes drip-fed through the real
//! per-connection phase walk, prefix by prefix, exactly as a byte-at-a-time
//! socket drives it — so the resumable phases (chunk scan, head re-parse,
//! the 100-continue stash) all run.
//!
//! The framer must never panic, and its terminal verdict must be one the
//! reactor can act on safely: only `More` or `Complete`. A `Complete`'s
//! header bytes must be buffered (the delivery slices `buf[..header_len]`
//! straight away; a declared body the reactor hasn't read yet is legal —
//! `frame_step` reads the remainder), the sum must not overflow, and the
//! total must stay inside what the codec's caps admit — no adversarial
//! stream can make the framer declare a message the caps would not.

use libfuzzer_sys::fuzz_target;
use truenas_ros::http::HttpConfig;
use truenas_ros::http::fuzz::drive_frame;
use truenas_ros::net::Framing;

fuzz_target!(|data: &[u8]| {
    match drive_frame(data) {
        // Terminal: a framed message, a dance interim, or a farewell
        // delivery. Whatever it was, it fired on some prefix of `data`.
        Framing::Complete {
            header_len,
            body_len,
        } => {
            assert!(
                header_len <= data.len(),
                "Complete: header {header_len} not buffered in {}",
                data.len()
            );
            let total = header_len
                .checked_add(body_len)
                .expect("Complete: header+body overflows usize");
            // A declared (Content-Length) body is capped by max_body, a
            // chunked wire extent by max_body + the wire overhead, the
            // head by max_head — together min_request_bytes. The one shape
            // past it is a farewell delivery, which flushes exactly the
            // buffered bytes.
            let cap = HttpConfig::default().min_request_bytes();
            assert!(
                total <= cap.max(data.len()),
                "Complete: total {total} over cap {cap} and driven {}",
                data.len()
            );
        }
        // Ran out of bytes: parked for the next message (`More`) or still
        // receiving one already begun (`MoreInMessage`).
        Framing::More | Framing::MoreInMessage => {}
        // The http framer never asks for exact counts, never splices, and
        // never returns Invalid — failures become Phase::Fail plus a
        // degenerate Complete so the glue can answer with a real status.
        other => panic!("http framer returned {other:?}"),
    }
});
