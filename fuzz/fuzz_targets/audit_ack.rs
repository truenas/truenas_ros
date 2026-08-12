#![no_main]

//! Fuzz the netlink ack decoder.
//!
//! `NETLINK_AUDIT` is a shared bus: the socket can receive a datagram from any
//! peer with the privilege to write one, at any length, at any moment. The
//! decoder indexes fixed offsets — the sequence number at `[8..12]`, the
//! message type at `[4..6]`, the errno at `[16..20]` — behind two length
//! guards, and gets the buffer straight from `recvfrom`. Those guards are the
//! only thing between a 5-byte datagram and an out-of-bounds index.
//!
//! Beyond not panicking, the decoder must not **misattribute**: a reply
//! carrying someone else's sequence number has to be skipped so the scan keeps
//! reading, never mistaken for the ack of the record we just sent. Reporting a
//! stale success would mean an audit record silently lost.

use libfuzzer_sys::fuzz_target;
use truenas_ros::audit::{fuzz::decode_ack, SendStatus};

/// `NLMSG_HDRLEN`.
const HDRLEN: usize = 16;
/// `NLMSG_ERROR`.
const NLMSG_ERROR: u16 = 0x2;

fuzz_target!(|data: &[u8]| {
    // The decoder only reaches its interesting half when `seq` matches the
    // sequence word the datagram carries at [8..12]. Drawing the two
    // independently would hit that one time in 2^32, so the leading selector
    // byte chooses: take the datagram's own sequence, or a foreign one. Both
    // paths matter — the second is what proves misattribution impossible.
    let Some((&sel, buf)) = data.split_first() else {
        return;
    };
    let seq = if sel & 1 == 0 && buf.len() >= 12 {
        u32::from_ne_bytes([buf[8], buf[9], buf[10], buf[11]])
    } else {
        u32::from(sel)
    };

    let verdict = decode_ack(buf, seq);

    // A datagram too short to carry a header, or carrying a different
    // sequence, is never attributed to `seq`.
    if buf.len() < HDRLEN {
        assert!(
            verdict.is_none(),
            "a runt datagram was attributed to seq {seq}"
        );
        return;
    }
    let carried = u32::from_ne_bytes([buf[8], buf[9], buf[10], buf[11]]);
    if carried != seq {
        assert!(
            verdict.is_none(),
            "a datagram for seq {carried} was attributed to seq {seq}"
        );
        return;
    }

    // Matching sequence: the scan must terminate with an answer rather than
    // spinning on a datagram it has already accepted as ours.
    let verdict = verdict.expect("a matching sequence must be terminal");

    // Only an NLMSG_ERROR long enough to carry one can report a failure;
    // anything else is a plain ack.
    let ty = u16::from_ne_bytes([buf[4], buf[5]]);
    if ty != NLMSG_ERROR || buf.len() < HDRLEN + 4 {
        assert_eq!(
            verdict.ok(),
            Some(SendStatus::Delivered),
            "a non-error netlink message must read as delivered"
        );
    } else {
        let err = i32::from_ne_bytes([buf[16], buf[17], buf[18], buf[19]]);
        match verdict {
            Ok(SendStatus::Delivered) => {
                assert_eq!(err, 0, "a non-zero errno was reported as delivered")
            }
            Ok(SendStatus::Unavailable) => assert!(
                matches!(
                    err.unsigned_abs() as i32,
                    libc::EPERM | libc::ECONNREFUSED
                ),
                "errno {err} is not the benign-unavailability class"
            ),
            Err(_) => {
                assert_ne!(err, 0, "a zero errno was reported as a failure")
            }
        }
    }

    // Decoding is pure.
    assert_eq!(
        decode_ack(buf, seq).map(|r| r.is_ok()),
        Some(decode_ack(buf, seq).expect("terminal").is_ok()),
        "decoding is not deterministic"
    );
});
