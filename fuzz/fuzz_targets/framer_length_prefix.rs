#![no_main]

//! Fuzz the shipped fixed-width length-prefix framer.
//!
//! For arbitrary wire bytes and every `(width, endian, includes_self)`
//! configuration, `length_prefix_header` must never panic, and every verdict
//! it returns must satisfy the contract the server relies on downstream — so a
//! malformed or adversarial prefix can never drive an out-of-bounds slice when
//! the message is delivered (`buf[..header_len]` then `[..body_len]`).

use libfuzzer_sys::fuzz_target;
use truenas_ros::net::server::{
    length_prefix_header, Endian, Framing, PrefixWidth,
};

const WIDTHS: [(PrefixWidth, usize); 4] = [
    (PrefixWidth::U8, 1),
    (PrefixWidth::U16, 2),
    (PrefixWidth::U32, 4),
    (PrefixWidth::U64, 8),
];

fuzz_target!(|data: &[u8]| {
    for (width, hlen) in WIDTHS {
        for endian in [Endian::Big, Endian::Little] {
            for includes_self in [false, true] {
                let mut framer =
                    length_prefix_header::<()>(width, endian, includes_self);
                // Every distinct behavior is reached within the prefix width:
                // empty..(hlen-1) -> Need, exactly hlen -> Complete/Invalid.
                let probe = hlen.min(data.len());
                for end in 0..=probe {
                    match framer(&data[..end], &mut ()) {
                        Framing::Need(n) => {
                            // Only before the prefix is buffered, asking for at
                            // most the missing prefix bytes.
                            assert!(
                                n >= 1 && n <= hlen,
                                "Need({n}) out of range for hlen {hlen}"
                            );
                            assert!(
                                end < hlen,
                                "Need after prefix complete (end={end})"
                            );
                        }
                        Framing::Complete {
                            header_len,
                            body_len,
                        } => {
                            // The header is exactly the prefix and was fully
                            // buffered. body_len is whatever the prefix decodes
                            // to and is deliberately UNBOUNDED at this layer: a
                            // u64 prefix near u64::MAX yields a body_len whose
                            // sum with header_len overflows usize. Capping it is
                            // the pump's job, not the framer's (checked_add +
                            // max_request_bytes -> TooLarge close; the framer
                            // only reports what it parsed). So the framer-level
                            // invariants are just the header shape + buffering.
                            assert_eq!(header_len, hlen);
                            assert!(end >= hlen, "Complete before prefix");
                            let _ = body_len;
                        }
                        // A fixed-width prefix framer never scans for a
                        // delimiter, and never diverts a body to a splice fd.
                        Framing::More => {
                            panic!("length prefix framer returned More")
                        }
                        Framing::SpliceBody { .. } => {
                            panic!("length prefix framer returned SpliceBody")
                        }
                        Framing::Invalid => {}
                    }
                }
            }
        }
    }
});
