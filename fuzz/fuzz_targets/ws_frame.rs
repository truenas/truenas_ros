//! Lane T2: the WebSocket frame-header parser and both framers over
//! attacker-controlled bytes - the target `src/ws/mod.rs` never had.
#![no_main]

use libfuzzer_sys::fuzz_target;
use truenas_ros::net::Framing;
use truenas_ros::ws::{
    self, FrameHead, HeadVerdict, WsState, encode_frame, frame_head,
    server_frame_head, unmask,
};

/// Every verdict a header parse can give must be actionable: an
/// `Incomplete` ask is non-zero (a zero ask is a wedge - the reactor
/// answers `Need(0)` with `Close(Malformed)`), and a `Done` header's
/// declared extent must not overflow `usize` (the reactor slices
/// `header_len` then `body_len` out of one buffer).
fn check_verdict(v: HeadVerdict, data: &[u8], masked: bool) {
    match v {
        HeadVerdict::Incomplete { need } => {
            assert!(need > 0, "a zero-byte ask cannot make progress");
            assert!(
                data.len() + need <= 14,
                "a frame header is at most 14 bytes; asked {need} at {}",
                data.len()
            );
        }
        HeadVerdict::Invalid(_) => {}
        HeadVerdict::Done(FrameHead {
            header_len,
            payload_len,
            opcode,
            fin,
        }) => {
            assert!(
                header_len.checked_add(payload_len).is_some(),
                "header+payload overflows usize"
            );
            // RFC 6455 sec. 5.2: 2 bytes, plus 2 or 8 for the extended
            // length, plus 4 for a masking key. So the legal header
            // lengths are exactly these, and which set applies is the
            // whole difference between the two framers.
            let want: &[usize] = if masked { &[6, 8, 14] } else { &[2, 4, 10] };
            assert!(
                want.contains(&header_len),
                "header_len {header_len} is not one of {want:?}"
            );
            assert!(
                data.len() >= header_len,
                "Done with fewer bytes than the header it declares"
            );
            // RFC 6455 sec. 5.5: control frames are never fragmented and
            // carry at most 125 bytes.
            if opcode >= ws::OP_CLOSE {
                assert!(fin, "fragmented control frame accepted");
                assert!(
                    payload_len <= 125,
                    "control frame of {payload_len} bytes accepted"
                );
            }
        }
    }
}

/// The framing invariant the reactor relies on, mirroring
/// `framing_arithmetic`: a `Complete` verdict's two lengths must sum
/// without overflow, and a `Need` must never ask for zero.
fn check_framing(v: Framing) {
    match v {
        Framing::Complete {
            header_len,
            body_len,
        } => {
            assert!(
                header_len.checked_add(body_len).is_some(),
                "Complete: header+body overflows usize"
            );
        }
        Framing::Need(n) | Framing::NeedInMessage(n) => {
            assert!(n > 0, "a zero-byte Need wedges the connection");
        }
        _ => {}
    }
}

fuzz_target!(|data: &[u8]| {
    // Both directions, over every prefix - a drip-fed socket drives the
    // resumable asks exactly this way.
    for end in 0..=data.len().min(64) {
        let d = &data[..end];
        check_verdict(frame_head(d), d, false);
        check_verdict(server_frame_head(d), d, true);
    }

    // Both framers, drip-fed through the handshake phase and then *past*
    // it into frames.
    //
    // The break has to consume, not stop. A framer answers `More` only
    // while the handshake head is still arriving; the verdict that ends
    // that phase is a `Complete` naming the head's extent, and stopping
    // there is stopping exactly at the point the frame phase begins - so
    // the loop that was meant to reach `frame_step` never did. Consume
    // each `Complete` and carry on from the remainder, which is what a
    // driver does.
    for framer in [
        ws::ws_frame as fn(&[u8], &mut WsState) -> Framing,
        ws::ws_server_frame as fn(&[u8], &mut WsState) -> Framing,
    ] {
        let mut st = WsState::default();
        let mut buf: &[u8] = data;
        loop {
            // Drip-feed the current message: every prefix, so a resumable
            // ask is exercised at each byte boundary.
            //
            // A resumable ask is any of the FOUR - `Need`, `NeedInMessage`,
            // `More`, `MoreInMessage` - not the two the handshake phase
            // happens to use. The frame phase asks with `Need`/`NeedInMessage`
            // (`ws::frame_step` answers `Need(2)` for an empty buffer), so a
            // predicate naming only `More`/`MoreInMessage` reads the frame
            // phase's very first ask as a terminal verdict, the `let else`
            // below finds it is not a `Complete`, and the outer loop breaks
            // at `end == 0` having consumed nothing. That is why the frame
            // phase still ran no frames after the loop was rewritten to
            // consume them: `frame_step` was entered, but only ever through
            // its empty-buffer early return, so its `parse` was never called
            // at all.
            //
            // Measured: a `panic!` on `frame_step`'s `Framing::Complete` arm
            // survived 400 000 runs with the two-variant predicate and
            // crashes on the seeded corpus with this one.
            let mut verdict = None;
            for end in 0..=buf.len() {
                let v = framer(&buf[..end], &mut st);
                check_framing(v);
                if !matches!(
                    v,
                    Framing::More
                        | Framing::MoreInMessage
                        | Framing::Need(_)
                        | Framing::NeedInMessage(_)
                ) {
                    verdict = Some((v, end));
                    break;
                }
            }
            // Ran out of bytes without a verdict, or the framer refused.
            let Some((
                Framing::Complete {
                    header_len,
                    body_len,
                },
                _,
            )) = verdict
            else {
                break;
            };
            let Some(total) = header_len.checked_add(body_len) else {
                break;
            };
            if total == 0 || total > buf.len() {
                break;
            }
            buf = &buf[total..];
        }
    }

    // Handshake validators: total over arbitrary bytes, never a panic.
    let _ = ws::validate_101(data, "dGhlIHNhbXBsZSBub25jZQ==");
    let _ = ws::validate_upgrade_request(data);

    // Round trip: what the client encoder masks, the server parser frames
    // and `unmask` recovers byte-for-byte.
    if !data.is_empty() {
        let mask = [data[0], 0x5a, 0xa5, data[data.len() - 1]];
        let payload = &data[..data.len().min(4096)];
        let mut wire = encode_frame(ws::OP_TEXT, payload, mask);
        let HeadVerdict::Done(h) = server_frame_head(&wire) else {
            panic!("our own encoder produced a header we refuse");
        };
        assert_eq!(h.payload_len, payload.len(), "length round trip");
        assert_eq!(
            h.header_len + h.payload_len,
            wire.len(),
            "encoded extent disagrees with the parsed header"
        );
        let (header, body) = wire.split_at_mut(h.header_len);
        unmask(header, body);
        assert_eq!(body, payload, "mask round trip");
    }
});
