//! Message framing: the pure decision core every transport shares.
//!
//! Hoisted from the io_uring net reactor (whose pump enforced it) so any
//! byte-stream driver — today the tokio [`rt`](crate::rt) `FrameReader` —
//! applies the same fuzz-verified guard arithmetic: a malicious or buggy
//! framer verdict can produce a refusal ([`FrameStep::Close`]), never an
//! out-of-bounds action. Dependency-free by design.
//!
//! A **framer** inspects the bytes accumulated so far and returns a
//! [`Framing`] verdict; [`frame_step`] turns that verdict plus the buffer
//! state and size caps into the one action the driver may take next.

/// Bytes a chunked ([`Framing::More`]) read requests per step.
pub const RECV_CHUNK: usize = 4096;

/// A header framer's verdict, given the message bytes accumulated so far.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Framing {
    /// Read exactly `n` more bytes, then re-check. Use when the remaining
    /// length is known (a length prefix, or a body once its length is
    /// parsed) — efficient, and never over-reads.
    Need(usize),
    /// Read whatever the peer has sent (a chunk), then re-check. Use when
    /// scanning for a delimiter of unknown position.
    More,
    /// The message is completely framed: its header is the first
    /// `header_len` accumulated bytes and its body is `body_len` bytes. The
    /// driver reads any body bytes not already buffered, then delivers.
    Complete {
        /// Length of the header portion.
        header_len: usize,
        /// Length of the body portion.
        body_len: usize,
    },
    /// The message is completely framed, but its **body** should be moved
    /// zero-copy (a bridge splice to a file) instead of read into the
    /// buffer. The first `header_len` accumulated bytes are the header; the
    /// next `body_len` bytes belong to the body phase the caller drives
    /// (e.g. [`Bridge::recv_to_file`](crate::rt::Bridge::recv_to_file)).
    /// The framer must read its header with exact [`Framing::Need`] so no
    /// body byte is over-read into the buffer — enforced by [`frame_step`].
    SpliceBody {
        /// Length of the header portion (fully buffered, nothing past it).
        header_len: usize,
        /// Length of the body portion (moved out-of-band by the caller).
        body_len: usize,
    },
    /// The input is malformed; close the connection.
    Invalid,
}

/// Why [`frame_step`] refused a verdict.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameFault {
    /// The frame is malformed (an impossible verdict for the buffer state).
    Malformed,
    /// A length breaches `max_request_bytes` (or overflows).
    TooLarge,
}

/// The action a driver takes for one framer [`Framing`] verdict — the
/// output of [`frame_step`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameStep {
    /// Close the connection (malformed frame, or one over a size cap).
    Close(FrameFault),
    /// Read `want` more header bytes — `exact` means an exact count
    /// (`MSG_WAITALL`-style), otherwise a chunk scan for a delimiter.
    ReadHeader {
        /// Bytes to read next.
        want: usize,
        /// Exact count vs a chunk read.
        exact: bool,
    },
    /// Read the message body: `want` more bytes (exact), recording the
    /// `header_len`/`body_len` split; `place` reads into an own allocation.
    ReadBody {
        /// Body bytes still to read.
        want: usize,
        /// Header length of the framed message.
        header_len: usize,
        /// Body length of the framed message.
        body_len: usize,
        /// Read the body into its own allocation (placement).
        place: bool,
    },
    /// The whole message is buffered; deliver it with this split.
    Deliver {
        /// Header length of the framed message.
        header_len: usize,
        /// Body length of the framed message.
        body_len: usize,
    },
    /// Hand the body phase to the caller's zero-copy path, keeping only the
    /// `header_len` header bytes buffered.
    SpliceBody {
        /// Header length (fully buffered).
        header_len: usize,
        /// Body length the caller moves out-of-band.
        body_len: usize,
    },
}

/// The per-verdict framing decision, factored out as a **pure** function so
/// it can be exhaustively fuzzed (`fuzz/fuzz_targets/framing_arithmetic.rs`)
/// independently of any I/O driver: given a framer's [`Framing`] verdict,
/// the bytes currently buffered, and the two size limits, decide what to do
/// next — read more, deliver, or close — applying every overflow and cap
/// guard.
///
/// The safety contract the fuzzer verifies for **every** input: a
/// [`FrameStep::Deliver`] implies `header_len + body_len` does not overflow
/// and is `<= buffered` (delivery's `buf[..header_len]` then `[..body_len]`
/// slices stay in bounds); a placing [`FrameStep::ReadBody`] implies
/// `header_len <= buffered < header_len + body_len` (the placement carve
/// cannot underflow); a [`FrameStep::SpliceBody`] implies `buffered ==
/// header_len` (the whole header, and nothing past it, is buffered — the
/// body is moved out-of-band, never sliced from the buffer) and that
/// `header_len + body_len` does not overflow. Any verdict that would breach
/// a cap or overflow becomes [`FrameStep::Close`], never an out-of-bounds
/// action.
pub fn frame_step(
    verdict: Framing,
    buffered: usize,
    max_request_bytes: usize,
    body_placement_threshold: Option<usize>,
) -> FrameStep {
    match verdict {
        Framing::Invalid => FrameStep::Close(FrameFault::Malformed),
        Framing::Need(n) => {
            if n == 0 {
                return FrameStep::Close(FrameFault::Malformed);
            }
            // `n` is framer-supplied (typically echoed straight off the
            // wire): cap the post-read total exactly like a `Complete`
            // frame, so one verdict can't size a recv allocation past
            // `max_request_bytes`.
            match buffered.checked_add(n) {
                Some(total) if total <= max_request_bytes => {
                    FrameStep::ReadHeader {
                        want: n,
                        exact: true,
                    }
                }
                _ => FrameStep::Close(FrameFault::TooLarge),
            }
        }
        Framing::More => FrameStep::ReadHeader {
            want: RECV_CHUNK,
            exact: false,
        },
        Framing::Complete {
            header_len,
            body_len,
        } => {
            // Both lengths are framer-supplied: a sum that overflows is over
            // any cap, and must not wrap past the TooLarge guard (a u64
            // length prefix of `!0` would otherwise wrap to a tiny total and
            // deliver an out-of-bounds body slice).
            let Some(total) = header_len.checked_add(body_len) else {
                return FrameStep::Close(FrameFault::TooLarge);
            };
            if total == 0 {
                return FrameStep::Close(FrameFault::Malformed);
            }
            if total > max_request_bytes {
                return FrameStep::Close(FrameFault::TooLarge);
            }
            if buffered >= total {
                FrameStep::Deliver {
                    header_len,
                    body_len,
                }
            } else {
                // Large bodies are *placed*: read into their own allocation.
                // Requires the header to be fully buffered (always true for
                // `Need` framers).
                let place = buffered >= header_len
                    && matches!(body_placement_threshold, Some(t) if body_len >= t);
                FrameStep::ReadBody {
                    want: total - buffered,
                    header_len,
                    body_len,
                    place,
                }
            }
        }
        Framing::SpliceBody {
            header_len,
            body_len,
        } => {
            if header_len == 0 || body_len == 0 {
                // A splice needs a header (the frame that triggered it) and
                // some body to move; an empty body would splice zero bytes
                // and misread as EOF. Use `Complete` for empty-body frames.
                return FrameStep::Close(FrameFault::Malformed);
            }
            // Only the header is buffered, so only the header is bounded by
            // the request cap; the body goes out-of-band and never enters
            // the buffer (bodies larger than `max_request_bytes` — multi-GB
            // streams — are the whole point).
            if header_len > max_request_bytes {
                return FrameStep::Close(FrameFault::TooLarge);
            }
            if header_len.checked_add(body_len).is_none() {
                return FrameStep::Close(FrameFault::TooLarge);
            }
            // A well-formed splice framer reads its header with exact
            // `Framing::Need`, so the whole header — and nothing past it —
            // is buffered when it returns `SpliceBody`. A `More`-style
            // over-read leaves body bytes buffered that can't be moved
            // out-of-band; close rather than tear the body across buffer
            // and socket.
            if buffered != header_len {
                return FrameStep::Close(FrameFault::Malformed);
            }
            FrameStep::SpliceBody {
                header_len,
                body_len,
            }
        }
    }
}

/// Width of a fixed-size length prefix.
#[derive(Clone, Copy, Debug)]
pub enum PrefixWidth {
    /// 1-byte length.
    U8,
    /// 2-byte length.
    U16,
    /// 4-byte length.
    U32,
    /// 8-byte length.
    U64,
}

impl PrefixWidth {
    fn bytes(self) -> usize {
        match self {
            PrefixWidth::U8 => 1,
            PrefixWidth::U16 => 2,
            PrefixWidth::U32 => 4,
            PrefixWidth::U64 => 8,
        }
    }
}

/// Byte order of a length prefix.
#[derive(Clone, Copy, Debug)]
pub enum Endian {
    /// Big-endian (network order).
    Big,
    /// Little-endian.
    Little,
}

fn read_prefix(header: &[u8], width: PrefixWidth, endian: Endian) -> u64 {
    let mut v = 0u64;
    match endian {
        Endian::Big => {
            for &b in &header[..width.bytes()] {
                v = (v << 8) | b as u64;
            }
        }
        Endian::Little => {
            for (i, &b) in header[..width.bytes()].iter().enumerate() {
                v |= (b as u64) << (8 * i);
            }
        }
    }
    v
}

/// A reusable header framer for a fixed-width length prefix: the first
/// `width` bytes are an unsigned integer giving the message length;
/// `includes_self` means that length counts the prefix itself.
pub fn length_prefix_header(
    width: PrefixWidth,
    endian: Endian,
    includes_self: bool,
) -> impl FnMut(&[u8]) -> Framing {
    let hlen = width.bytes();
    move |buf: &[u8]| {
        if buf.len() < hlen {
            return Framing::Need(hlen - buf.len());
        }
        let total = read_prefix(buf, width, endian);
        let body = if includes_self {
            match total.checked_sub(hlen as u64) {
                Some(b) => b,
                None => return Framing::Invalid,
            }
        } else {
            total
        };
        match usize::try_from(body) {
            Ok(body_len) => Framing::Complete {
                header_len: hlen,
                body_len,
            },
            Err(_) => Framing::Invalid,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn length_prefix_header_verdicts() {
        let mut h = length_prefix_header(PrefixWidth::U32, Endian::Big, false);
        assert_eq!(h(&[]), Framing::Need(4));
        assert_eq!(h(&[0, 0]), Framing::Need(2));
        assert_eq!(
            h(&[0, 0, 0, 5]),
            Framing::Complete {
                header_len: 4,
                body_len: 5
            }
        );
    }

    #[test]
    fn length_prefix_includes_self() {
        let mut h = length_prefix_header(PrefixWidth::U16, Endian::Big, true);
        // total length 10 includes the 2-byte prefix → body is 8.
        assert_eq!(
            h(&[0, 10]),
            Framing::Complete {
                header_len: 2,
                body_len: 8
            }
        );
        // total length < prefix width is malformed.
        assert_eq!(h(&[0, 1]), Framing::Invalid);
    }

    #[test]
    fn splice_requires_exact_header_discipline() {
        let v = Framing::SpliceBody {
            header_len: 8,
            body_len: 1 << 30,
        };
        // Exactly the header buffered: the body phase is handed out.
        assert_eq!(
            frame_step(v, 8, 64, None),
            FrameStep::SpliceBody {
                header_len: 8,
                body_len: 1 << 30
            }
        );
        // One byte over-read: refused, never torn across buffer and socket.
        assert_eq!(
            frame_step(v, 9, 64, None),
            FrameStep::Close(FrameFault::Malformed)
        );
        // The body is deliberately NOT bounded by max_request_bytes.
        assert_eq!(
            frame_step(v, 8, 64, Some(16)),
            FrameStep::SpliceBody {
                header_len: 8,
                body_len: 1 << 30
            }
        );
    }
}
