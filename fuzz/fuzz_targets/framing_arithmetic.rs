#![no_main]

//! Fuzz the pump's framing decision (`frame_step`) — the guard arithmetic a
//! *malicious or buggy* consumer framer must never be able to turn into an
//! out-of-bounds action.
//!
//! For an arbitrary framer verdict + buffer state + size limits, `frame_step`
//! must (a) never panic, and (b) only ever return an action the server can
//! carry out safely: a `Deliver`/`ReadBody` whose `header_len + body_len`
//! wouldn't overflow or under-buffer the delivery slices, and a placing
//! `ReadBody` whose placement carve can't underflow. Anything else must be a
//! `Close`, never an OOB. This is the invariant that keeps a lying framer
//! (e.g. a u64 length prefix near `u64::MAX`) from crashing the loop.

use libfuzzer_sys::fuzz_target;
use truenas_ros::net::server::{frame_step, FrameStep, Framing};

fuzz_target!(|input: (u8, u64, u64, u64, u64, Option<u64>)| {
    let (sel, a, b, buffered, max_request_bytes, threshold) = input;
    // u64 == usize here (64-bit), so the full range — including the overflow
    // edges — is reachable.
    let verdict = match sel % 5 {
        0 => Framing::Need(a as usize),
        1 => Framing::More,
        2 => Framing::Complete {
            header_len: a as usize,
            body_len: b as usize,
        },
        3 => Framing::SpliceBody {
            header_len: a as usize,
            body_len: b as usize,
            fd: -1, // frame_step passes the fd through untouched
        },
        _ => Framing::Invalid,
    };
    let buffered = buffered as usize;
    let max_request_bytes = max_request_bytes as usize;
    let threshold = threshold.map(|t| t as usize);

    match frame_step(verdict, buffered, max_request_bytes, threshold) {
        FrameStep::Deliver {
            header_len,
            body_len,
        } => {
            // Delivery slices buf[..header_len] then rest[..body_len]; both must
            // fit within the `buffered` bytes, so the total can't overflow and
            // can't exceed what's buffered.
            let total = header_len
                .checked_add(body_len)
                .expect("Deliver: header+body overflows usize");
            assert!(total > 0, "Deliver: empty frame");
            assert!(
                total <= buffered,
                "Deliver: total {total} > buffered {buffered}"
            );
        }
        FrameStep::ReadBody {
            want,
            header_len,
            body_len,
            place,
        } => {
            let total = header_len
                .checked_add(body_len)
                .expect("ReadBody: header+body overflows usize");
            assert!(
                total <= max_request_bytes,
                "ReadBody: total {total} over cap {max_request_bytes}"
            );
            assert!(
                buffered < total,
                "ReadBody: buffered {buffered} >= total {total}"
            );
            assert_eq!(want, total - buffered, "ReadBody: want != total-buffered");
            assert!(want > 0, "ReadBody: zero want");
            if place {
                // arm_body_recv computes prefix = buffered - header_len and
                // reads into [prefix, body_len); this needs
                // header_len <= buffered < header_len + body_len.
                assert!(
                    buffered >= header_len,
                    "placement underflow: buffered {buffered} < header {header_len}"
                );
                assert!(
                    buffered - header_len < body_len,
                    "placement over-read"
                );
            }
        }
        FrameStep::ReadHeader { want, exact } => {
            assert!(want > 0, "ReadHeader: zero want");
            if exact {
                // From Need(n): n > 0 and buffered + n <= cap.
                let after = buffered
                    .checked_add(want)
                    .expect("ReadHeader exact: overflow");
                assert!(
                    after <= max_request_bytes,
                    "ReadHeader exact: {after} over cap {max_request_bytes}"
                );
            }
        }
        FrameStep::SpliceBody {
            header_len,
            body_len,
            ..
        } => {
            // Splice keeps only the header buffered; the body streams to `fd`,
            // never sliced from `buf`. The invariant: header+body doesn't
            // overflow, both are non-zero, the header fits the cap, and the
            // whole header (and nothing past it) is buffered.
            let total = header_len
                .checked_add(body_len)
                .expect("SpliceBody: header+body overflows usize");
            assert!(total > 0, "SpliceBody: empty frame");
            assert!(header_len > 0 && body_len > 0, "SpliceBody: zero part");
            assert!(
                header_len <= max_request_bytes,
                "SpliceBody: header {header_len} over cap {max_request_bytes}"
            );
            assert_eq!(
                buffered, header_len,
                "SpliceBody: buffered {buffered} != header {header_len}"
            );
        }
        // A close is always safe.
        FrameStep::Close(_) => {}
    }
});
