#![no_main]

//! Fuzz the chunked scanner/decoder pair (`http::fuzz::chunk_scan`,
//! `http::fuzz::chunk_decode`). The framer's progress oracle and the glue's
//! decoder share one state machine and must never disagree about a message's
//! extent — the glue answers a disagreement as a codec bug (500), so the
//! fuzzer's job is to prove that path unreachable from wire bytes.

use libfuzzer_sys::fuzz_target;
use truenas_ros::http::fuzz::{chunk_decode, chunk_scan};

/// RFC 9110 §6.5.1's framing/routing/credential set: the codec consumes
/// these trailer names without surfacing them, and that must hold for every
/// wire shape the scanner accepts.
const FORBIDDEN: [&str; 5] = [
    "transfer-encoding",
    "content-length",
    "host",
    "authorization",
    "cookie",
];

fuzz_target!(|data: &[u8]| {
    match chunk_scan(data) {
        Ok(Some(extent)) => {
            assert!(
                extent <= data.len(),
                "extent {extent} > input {}",
                data.len()
            );
            // A scan-accepted extent MUST decode: the seam the glue trusts
            // (the scan said complete; decode runs on those exact bytes).
            let (entity, trailers) = chunk_decode(&data[..extent])
                .expect("scan-accepted extent failed to decode");
            // De-chunking only removes framing; it never grows the payload.
            assert!(
                entity.len() <= extent,
                "entity {} larger than its wire {extent}",
                entity.len()
            );
            for t in &trailers {
                assert!(
                    !FORBIDDEN.iter().any(|f| t.name.eq_ignore_ascii_case(f)),
                    "forbidden trailer {:?} surfaced",
                    t.name
                );
            }
        }
        // Incomplete: the decoder must agree (it requires the message to
        // occupy its input exactly).
        Ok(None) => assert!(
            chunk_decode(data).is_err(),
            "decode accepted what the scan called incomplete"
        ),
        // The promised die statuses: 400 malformed, 431 oversized trailers.
        Err(status) => {
            assert!(
                matches!(status, 400 | 431),
                "unpromised die status {status}"
            );
            assert!(
                chunk_decode(data).is_err(),
                "decode accepted what the scan rejected"
            );
        }
    }
});
