//! `Transfer-Encoding: chunked` - an incremental, resumable scanner over the
//! wire form, plus the one-shot decoder the glue runs once a body is fully
//! framed. Everything is a pure function of `(bytes, state)` - no I/O, no
//! config - and the scanner and decoder share one state machine ([`run`]),
//! so the framer's progress oracle and the glue's decoder can never disagree
//! about where a chunked message ends.
//!
//! Strictness (RFC 9112 sec. 7.1): hex chunk sizes with checked arithmetic
//! (overflow is a 400, not a wraparound), CRLF line endings only, chunk
//! extensions parsed and ignored (a recipient MUST ignore unrecognized
//! extensions), trailer field names token-validated (with the
//! framing/routing/credential set dropped - [`FORBIDDEN_TRAILERS`]). Every
//! line is capped
//! ([`CHUNK_LINE_MAX`], [`TRAILER_LINE_MAX`]) so a peer can neither wedge
//! the scanner short of a terminator nor drip an unbounded "line", and the
//! whole trailer section is capped ([`TRAILER_MAX`] -> 431, the oversized-
//! header-fields answer).

use std::borrow::Cow;
use std::ops::Range;

use super::head::{has_field_break, is_token_byte, HeaderView};

/// Chunk-size line cap (hex digits + optional extensions, CRLF excluded).
/// Real chunk-size lines are under 20 bytes; the headroom is for extensions,
/// which are ignored but must still terminate.
pub(crate) const CHUNK_LINE_MAX: usize = 256;

/// Single trailer field-line cap. Checksum trailers (the real-world use:
/// `x-amz-checksum-*`) are well under 100 bytes.
pub(crate) const TRAILER_LINE_MAX: usize = 1024;

/// Whole trailer section cap, terminator included. This byte bound is also
/// the field-count bound: the smallest field line runs a few bytes, so the
/// cap admits at most a couple of thousand trailers before answering 431,
/// which is why there is no separate count cap.
pub(crate) const TRAILER_MAX: usize = 8 * 1024;

/// Where the scanner stands inside the chunk stream.
#[derive(Debug, Clone, Copy, Default)]
enum State {
    /// At the start of a chunk-size line.
    #[default]
    Size,
    /// Inside a chunk's payload, `remaining` bytes still to consume.
    Data {
        /// Payload bytes of the current chunk not yet consumed.
        remaining: usize,
    },
    /// Expecting the CRLF that closes a chunk's payload.
    DataCrlf,
    /// In the trailer section (after the zero-size chunk), consuming field
    /// lines until the empty line.
    Trailer,
    /// The terminator has been consumed; the message's extent is final.
    Done,
}

/// Resumable scan state. Offsets index the body region (the bytes after the
/// head) from its start; the region only ever grows while a scan is live, so
/// they stay valid across calls.
#[derive(Debug, Default)]
pub(crate) struct ChunkScan {
    /// Bytes fully scanned - the resume point, and the message extent once
    /// [`State::Done`] is reached.
    pub consumed: usize,
    /// Decoded payload bytes seen so far - the entity size, so far. The
    /// framer reads this to enforce its decoded-body cap mid-stream.
    pub decoded: usize,
    /// Trailer-section bytes seen so far (for the [`TRAILER_MAX`] cap).
    trailer_bytes: usize,
    state: State,
}

/// A CRLF search bounded by a line cap.
enum Find {
    /// Line of this length, CRLF next.
    At(usize),
    /// No CRLF yet, and the cap not yet exceeded.
    NeedMore,
    /// Enough bytes have arrived that a compliant CRLF can no longer appear.
    TooLong,
}

fn find_crlf(rest: &[u8], max_line: usize) -> Find {
    let window = rest.len().min(max_line + 2);
    if let Some(i) = rest[..window].windows(2).position(|w| w == b"\r\n") {
        return Find::At(i);
    }
    if rest.len() >= max_line + 2 {
        Find::TooLong
    } else {
        Find::NeedMore
    }
}

/// Whether a CRLF-delimited line (size or trailer) carries a bare CR or LF.
/// The chunked grammar terminates these lines with CRLF only (RFC 9112
/// sec. 7.1). Since [`find_crlf`] stops at the first CRLF, a bare CR or LF
/// earlier in the line - a chunk extension is the usual place - must be
/// rejected here rather than left in place, or a recipient that treats a
/// lone LF as a line ending could frame the body differently.
fn line_has_bare_crlf(line: &[u8]) -> bool {
    line.iter().any(|&b| matches!(b, b'\r' | b'\n'))
}

/// Parse a chunk-size line: `1*HEXDIG`, then nothing or an (ignored)
/// extension introduced by `;` after optional whitespace. Checked
/// arithmetic - a size that overflows `usize` is malformed, full stop.
fn parse_size_line(line: &[u8]) -> Option<usize> {
    let mut digits = 0usize;
    let mut n = 0usize;
    for &b in line {
        let d = match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            _ => break,
        };
        digits += 1;
        n = n.checked_mul(16)?.checked_add(usize::from(d))?;
    }
    if digits == 0 {
        return None;
    }
    let rest = trim_ows_start(&line[digits..]);
    if rest.is_empty() || rest[0] == b';' {
        Some(n)
    } else {
        None
    }
}

fn trim_ows_start(mut v: &[u8]) -> &[u8] {
    while let [b' ' | b'\t', rest @ ..] = v {
        v = rest;
    }
    v
}

/// Split a trailer field line into `(name, value)`. `None` when the name is
/// empty, not a token, the colon is missing, or the value carries a control
/// byte - the line is malformed. The value screen is load-bearing: lines are
/// delimited on CRLF only, so a bare LF or CR *inside* a value would let a
/// permitted-named trailer carry a forbidden field line past the name-only
/// [`FORBIDDEN_TRAILERS`] screen.
fn split_trailer(line: &[u8]) -> Option<(&[u8], &[u8])> {
    let colon = line.iter().position(|&b| b == b':')?;
    if colon == 0 || !line[..colon].iter().all(|&b| is_token_byte(b)) {
        return None;
    }
    let value = line[colon + 1..].trim_ascii();
    if has_field_break(value) {
        return None;
    }
    Some((&line[..colon], value))
}

/// Field names that must not ride in a trailer section (RFC 9110 sec. 6.5.1):
/// message framing, routing, and credentials. A conforming sender never puts
/// these there, and surfacing them tempts any consumer that merges headers
/// and trailers into letting a trailer rewrite framing or auth after the
/// body - so a well-formed line bearing one is consumed and dropped, never
/// surfaced.
const FORBIDDEN_TRAILERS: [&str; 5] = [
    "transfer-encoding",
    "content-length",
    "host",
    "authorization",
    "cookie",
];

fn forbidden_trailer(name: &[u8]) -> bool {
    FORBIDDEN_TRAILERS
        .iter()
        .any(|f| name.eq_ignore_ascii_case(f.as_bytes()))
}

/// The one state machine under [`scan`], [`decode`], and [`compact`]:
/// advance over `body` from where `s` left off, reporting payload spans and
/// validated trailer lines to the sinks **as ranges into `body`** - so an
/// in-place caller can record positions without borrowing against a buffer
/// it means to mutate. `Ok(Some(extent))` - the message occupies exactly the
/// first `extent` bytes of `body`; `Ok(None)` - need more bytes;
/// `Err(status)` - malformed (400) or oversized trailers (431).
fn run(
    body: &[u8],
    s: &mut ChunkScan,
    on_payload: &mut impl FnMut(Range<usize>),
    on_trailer: &mut impl FnMut(Range<usize>),
) -> Result<Option<usize>, u16> {
    loop {
        if matches!(s.state, State::Done) {
            return Ok(Some(s.consumed));
        }
        let Some(rest) = body.get(s.consumed..) else {
            // The buffer shrank beneath the resume point - a caller contract
            // break (the accumulate buffer only grows), not wire data.
            return Err(400);
        };
        match s.state {
            State::Done => unreachable!("handled above"),
            State::Size => match find_crlf(rest, CHUNK_LINE_MAX) {
                Find::NeedMore => return Ok(None),
                Find::TooLong => return Err(400),
                Find::At(i) => {
                    if line_has_bare_crlf(&rest[..i]) {
                        return Err(400);
                    }
                    let size = parse_size_line(&rest[..i]).ok_or(400u16)?;
                    s.consumed += i + 2;
                    s.state = if size == 0 {
                        State::Trailer
                    } else {
                        State::Data { remaining: size }
                    };
                }
            },
            State::Data { remaining } => {
                let take = remaining.min(rest.len());
                if take > 0 {
                    on_payload(s.consumed..s.consumed + take);
                    s.consumed += take;
                    s.decoded += take;
                }
                if take == remaining {
                    s.state = State::DataCrlf;
                } else {
                    s.state = State::Data {
                        remaining: remaining - take,
                    };
                    return Ok(None);
                }
            }
            State::DataCrlf => {
                if rest.len() < 2 {
                    return Ok(None);
                }
                if &rest[..2] != b"\r\n" {
                    return Err(400);
                }
                s.consumed += 2;
                s.state = State::Size;
            }
            State::Trailer => match find_crlf(rest, TRAILER_LINE_MAX) {
                Find::NeedMore => return Ok(None),
                Find::TooLong => return Err(431),
                Find::At(i) => {
                    s.trailer_bytes += i + 2;
                    if s.trailer_bytes > TRAILER_MAX {
                        return Err(431);
                    }
                    let start = s.consumed;
                    let line = &rest[..i];
                    s.consumed += i + 2;
                    if line_has_bare_crlf(line) {
                        return Err(400);
                    }
                    if line.is_empty() {
                        s.state = State::Done;
                    } else {
                        match split_trailer(line) {
                            // Forbidden names (framing/routing/credentials)
                            // are consumed but never surfaced.
                            Some((name, _)) if forbidden_trailer(name) => {}
                            Some(_) => on_trailer(start..start + i),
                            None => return Err(400),
                        }
                    }
                }
            },
        }
    }
}

/// Advance the scan over `body` (the byte region after the head), resuming
/// from where the previous call stopped. See [`run`] for the verdicts.
pub(crate) fn scan(
    body: &[u8],
    s: &mut ChunkScan,
) -> Result<Option<usize>, u16> {
    run(body, s, &mut |_| {}, &mut |_| {})
}

/// Accumulator for the decoded entity: a message whose payload is one
/// contiguous span (the single-chunk shape default botocore sends) stays a
/// borrow of the wire; only a second span forces the stitch into an owned
/// buffer.
enum Entity<'b> {
    /// No payload seen yet.
    Empty,
    /// Exactly one payload span so far - still zero-copy.
    Span(&'b [u8]),
    /// Multiple spans, stitched into an owned buffer.
    Stitched(Vec<u8>),
}

/// One-shot decode of a fully framed chunked message: the de-chunked entity
/// plus the parsed trailer fields. A single-chunk message borrows its
/// payload straight from `wire` (`Cow::Borrowed`) - no copy; only multi-chunk
/// messages stitch into an owned buffer. The framer's scan already accepted
/// these exact bytes as a complete message, so any failure here is a codec
/// bug - callers answer it as one (500), never as a client error.
pub(crate) fn decode(
    wire: &[u8],
) -> Result<(Cow<'_, [u8]>, Vec<HeaderView<'_>>), ()> {
    let mut s = ChunkScan::default();
    let mut entity = Entity::Empty;
    let mut lines: Vec<&[u8]> = Vec::new();
    // Spill capacity: the decoded entity never exceeds its wire form.
    let cap = wire.len();
    match run(
        wire,
        &mut s,
        &mut |r| {
            let p = &wire[r];
            entity = match std::mem::replace(&mut entity, Entity::Empty) {
                Entity::Empty => Entity::Span(p),
                Entity::Span(first) => {
                    let mut v = Vec::with_capacity(cap);
                    v.extend_from_slice(first);
                    v.extend_from_slice(p);
                    Entity::Stitched(v)
                }
                Entity::Stitched(mut v) => {
                    v.extend_from_slice(p);
                    Entity::Stitched(v)
                }
            };
        },
        &mut |r| lines.push(&wire[r]),
    ) {
        Ok(Some(extent)) if extent == wire.len() => {}
        _ => return Err(()),
    }
    let mut trailers = Vec::with_capacity(lines.len());
    for line in lines {
        let (name, value) = split_trailer(line).ok_or(())?;
        let name = std::str::from_utf8(name).map_err(|_| ())?;
        trailers.push(HeaderView { name, value });
    }
    let entity = match entity {
        Entity::Empty => Cow::Borrowed(&[][..]),
        Entity::Span(span) => Cow::Borrowed(span),
        Entity::Stitched(v) => Cow::Owned(v),
    };
    Ok((entity, trailers))
}

/// The de-chunked layout of a wire buffer after [`compact`]: where the
/// entity now lies inside it, plus the trailer lines copied out of it (tiny,
/// usually none) - copied so the buffer itself is free to move on as the
/// entity's own allocation while the views borrow this struct instead.
pub(crate) struct Compacted {
    /// Entity offset within the wire buffer.
    pub start: usize,
    /// Entity length.
    pub len: usize,
    /// Verbatim trailer field lines, copied out of the wire (CRLF stripped).
    trailer_lines: Vec<Vec<u8>>,
}

impl Compacted {
    /// The trailer views, borrowing this struct rather than the wire buffer
    /// -- the reason the lines were copied out. The scan validated every line
    /// already, so a failure here is a codec bug (callers answer 500).
    pub(crate) fn trailers(&self) -> Result<Vec<HeaderView<'_>>, ()> {
        let mut out = Vec::with_capacity(self.trailer_lines.len());
        for line in &self.trailer_lines {
            let (name, value) = split_trailer(line).ok_or(())?;
            let name = std::str::from_utf8(name).map_err(|_| ())?;
            out.push(HeaderView { name, value });
        }
        Ok(out)
    }
}

/// The in-place twin of [`decode`], for a caller that **owns** the wire
/// buffer: walk the same state machine, then make the entity contiguous
/// inside `wire` without leaving the allocation. A single-payload message
/// (the default botocore shape) moves no bytes at all - the entity is
/// reported where it lies; a multi-payload message compacts its spans over
/// the framing bytes with overlapping moves. The single-span, bare-trailer
/// path allocates nothing. The framer's scan accepted these exact bytes as a
/// complete message, so any failure is a codec bug - callers answer it as
/// one (500), never as a client error.
pub(crate) fn compact(wire: &mut [u8]) -> Result<Compacted, ()> {
    let mut s = ChunkScan::default();
    let mut first: Option<Range<usize>> = None;
    // Empty Vecs never allocate: these stay unallocated unless the message
    // is multi-chunk / carries trailers.
    let mut rest_spans: Vec<Range<usize>> = Vec::new();
    let mut trailer_lines: Vec<Vec<u8>> = Vec::new();
    {
        let w: &[u8] = wire;
        match run(
            w,
            &mut s,
            &mut |r| {
                if first.is_none() {
                    first = Some(r);
                } else {
                    rest_spans.push(r);
                }
            },
            &mut |r| trailer_lines.push(w[r].to_vec()),
        ) {
            Ok(Some(extent)) if extent == w.len() => {}
            _ => return Err(()),
        }
    }
    let Some(head_span) = first else {
        return Ok(Compacted {
            start: 0,
            len: 0,
            trailer_lines,
        });
    };
    let start = head_span.start;
    let mut end = head_span.end;
    for r in rest_spans {
        // The destination never overtakes the source (framing bytes precede
        // every span), and overlapping moves are copy_within's contract.
        wire.copy_within(r.clone(), end);
        end += r.len();
    }
    debug_assert_eq!(end - start, s.decoded);
    Ok(Compacted {
        start,
        len: end - start,
        trailer_lines,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The default boto3-over-TLS PutObject body, byte-for-byte as captured
    /// on the dev box (boto3 1.37.9): one HTTP chunk wrapping the whole
    /// aws-chunked entity, whose checksum trailer is *inside* the entity;
    /// the HTTP layer terminates bare.
    fn botocore_wire() -> Vec<u8> {
        let mut wire = b"8e\r\n64\r\n".to_vec();
        wire.extend_from_slice(&[b'A'; 100]);
        wire.extend_from_slice(
            b"\r\n0\r\nx-amz-checksum-crc32:lZe8jQ==\r\n\r\n\r\n0\r\n\r\n",
        );
        assert_eq!(wire.len(), 153);
        wire
    }

    fn botocore_entity() -> Vec<u8> {
        let mut entity = b"64\r\n".to_vec();
        entity.extend_from_slice(&[b'A'; 100]);
        entity.extend_from_slice(
            b"\r\n0\r\nx-amz-checksum-crc32:lZe8jQ==\r\n\r\n",
        );
        assert_eq!(entity.len(), 0x8e);
        entity
    }

    #[test]
    fn botocore_golden() {
        let wire = botocore_wire();
        let mut s = ChunkScan::default();
        assert_eq!(scan(&wire, &mut s), Ok(Some(153)));
        assert_eq!(s.decoded, 0x8e);
        let (entity, trailers) = decode(&wire).expect("decodes");
        // The HTTP band de-chunks its own layer only: the aws-chunked
        // entity passes through untouched, and there are no HTTP trailers.
        assert_eq!(&entity[..], botocore_entity());
        assert!(trailers.is_empty());
        // One HTTP chunk -> the entity is a borrow of the wire, not a copy.
        assert!(matches!(entity, Cow::Borrowed(_)));
    }

    #[test]
    fn resumes_at_every_split_point() {
        // Sans-io parsers fail on resumption, not on well-formed input:
        // drip the golden body one byte at a time through a single
        // persistent scan and assert the verdicts and extent.
        let wire = botocore_wire();
        let mut s = ChunkScan::default();
        for cut in 0..wire.len() {
            assert_eq!(scan(&wire[..cut], &mut s), Ok(None), "cut {cut}");
            assert!(s.consumed <= cut);
        }
        assert_eq!(scan(&wire, &mut s), Ok(Some(wire.len())));
        assert_eq!(s.decoded, 0x8e);
    }

    #[test]
    fn multi_chunk_and_empty_entity() {
        let (entity, trailers) =
            decode(b"3\r\nfoo\r\n4\r\nbars\r\n0\r\n\r\n").expect("decodes");
        assert_eq!(&entity[..], b"foobars");
        assert!(trailers.is_empty());
        // Two payload spans force the stitch into an owned buffer.
        assert!(matches!(entity, Cow::Owned(_)));
        let (entity, trailers) = decode(b"0\r\n\r\n").expect("decodes");
        assert!(entity.is_empty());
        assert!(trailers.is_empty());
        assert!(matches!(entity, Cow::Borrowed(_)));
    }

    #[test]
    fn trailers_parsed_and_trimmed() {
        let (entity, trailers) =
            decode(b"0\r\nx-amz-checksum-crc32: abc==\r\nx-two:v\r\n\r\n")
                .expect("decodes");
        assert!(entity.is_empty());
        assert_eq!(trailers.len(), 2);
        assert_eq!(trailers[0].name, "x-amz-checksum-crc32");
        assert_eq!(trailers[0].value, b"abc==");
        assert_eq!(trailers[1].name, "x-two");
        assert_eq!(trailers[1].value, b"v");
    }

    #[test]
    fn forbidden_trailer_fields_dropped() {
        // Framing, routing, and credential names cannot ride in trailers
        // (RFC 9110 sec. 6.5.1): well-formed lines bearing them are consumed
        // but never surfaced, so a consumer merging headers and trailers
        // cannot have its framing or auth rewritten after the body.
        let wire = b"0\r\n\
            Content-Length: 999\r\n\
            Transfer-Encoding: chunked\r\n\
            HOST: evil\r\n\
            Authorization: Basic abc\r\n\
            Cookie: sid=1\r\n\
            x-amz-checksum-crc32: ok==\r\n\r\n";
        let (entity, trailers) = decode(wire).expect("decodes");
        assert!(entity.is_empty());
        assert_eq!(trailers.len(), 1);
        assert_eq!(trailers[0].name, "x-amz-checksum-crc32");
        // The scan sees the same message extent (shared state machine).
        assert_eq!(scan(wire, &mut ChunkScan::default()), Ok(Some(wire.len())));
    }

    #[test]
    fn extensions_ignored() {
        let (entity, _) =
            decode(b"5;name=val\r\nhello\r\n0\r\n\r\n").expect("decodes");
        assert_eq!(&entity[..], b"hello");
        let (entity, _) =
            decode(b"5 ;x\r\nhello\r\n0\r\n\r\n").expect("decodes");
        assert_eq!(&entity[..], b"hello");
    }

    fn scan_err(wire: &[u8]) -> u16 {
        scan(wire, &mut ChunkScan::default())
            .expect_err("expected a scan error")
    }

    #[test]
    fn malformed_is_400() {
        // Non-hex size; garbage after digits; bare-LF line; missing CRLF
        // after payload; size overflow (17 hex digits).
        assert_eq!(scan_err(b"zz\r\n"), 400);
        assert_eq!(scan_err(b"5x\r\nhello\r\n0\r\n\r\n"), 400);
        assert_eq!(scan_err(b"5\nhello\r\n0\r\n\r\n"), 400);
        assert_eq!(scan_err(b"3\r\nfooXX0\r\n\r\n"), 400);
        assert_eq!(scan_err(b"FFFFFFFFFFFFFFFFF\r\n"), 400);
        // Trailer lines: no colon, empty name, non-token name.
        assert_eq!(scan_err(b"0\r\nbadline\r\n\r\n"), 400);
        assert_eq!(scan_err(b"0\r\n:v\r\n\r\n"), 400);
        assert_eq!(scan_err(b"0\r\nbad name:v\r\n\r\n"), 400);
    }

    #[test]
    fn a_trailer_value_cannot_carry_a_field_line() {
        // A bare LF or CR inside a value smuggles a forbidden field past
        // the name-only screen the moment any consumer splits the surfaced
        // value on line breaks; RFC 9110 sec. 5.5 admits no control byte in a
        // field value, so the line is malformed, not data.
        assert_eq!(
            scan_err(b"0\r\nx-ok: v\nAuthorization: Basic Zm9v\r\n\r\n"),
            400
        );
        assert_eq!(scan_err(b"0\r\nx-ok: v\rHost: evil\r\n\r\n"), 400);
        assert_eq!(scan_err(b"0\r\nx-ok: a\x00b\r\n\r\n"), 400);
        assert_eq!(scan_err(b"0\r\nx-ok: a\x7fb\r\n\r\n"), 400);
        // Horizontal tab is the one control byte a value admits.
        let (_, trailers) =
            decode(b"0\r\nx-ok: a\tb\r\n\r\n").expect("decodes");
        assert_eq!(trailers[0].value, b"a\tb");
    }

    #[test]
    fn line_caps() {
        // A chunk-size "line" that never terminates dies at the cap...
        let mut junk = b"1;".to_vec();
        junk.extend_from_slice(&[b'a'; CHUNK_LINE_MAX + 2]);
        assert_eq!(scan_err(&junk), 400);
        // ...an oversized single trailer line answers 431...
        let mut t = b"0\r\nx: ".to_vec();
        t.extend_from_slice(&[b'v'; TRAILER_LINE_MAX + 2]);
        assert_eq!(scan_err(&t), 431);
        // ...and so does a trailer section over the section cap.
        let mut t = b"0\r\n".to_vec();
        let line = [b"x: ".as_slice(), &[b'v'; 96], b"\r\n"].concat();
        while t.len() <= TRAILER_MAX + line.len() {
            t.extend_from_slice(&line);
        }
        t.extend_from_slice(b"\r\n");
        assert_eq!(scan_err(&t), 431);
    }

    #[test]
    fn bare_cr_or_lf_in_a_size_or_trailer_line_is_400() {
        // A bare CR or LF earlier in a size line, usually inside a chunk
        // extension, is rejected rather than left in place: the line is
        // CRLF-terminated, and accepting it would let an LF-tolerant peer
        // frame the body differently.
        assert_eq!(scan_err(b"1;x\n1\r\nA\r\n0\r\n\r\n"), 400);
        assert_eq!(scan_err(b"1;a\rb\r\nA\r\n0\r\n\r\n"), 400);
        assert_eq!(scan_err(b"2;\nxx\r\n0\r\n\r\n"), 400);
        // The same rule on a trailer line, including a leading bare CR that
        // trimming the value would otherwise hide.
        assert_eq!(scan_err(b"0\r\nx-ok: \rvalue\r\n\r\n"), 400);
        assert_eq!(scan_err(b"0\r\nx-a\n: 1\r\n\r\n"), 400);
    }

    // Edge cases for the size, footer, and trailer grammar.

    #[test]
    fn empty_chunk_size_line_is_400() {
        // A CRLF where a chunk size is expected has no hex digit; treating it
        // as a zero-size terminator would leave a stray CRLF in front of the
        // next message.
        assert_eq!(scan_err(b"\r\n\r\n"), 400);
        assert_eq!(scan_err(b"1\r\nZ\r\n\r\n\r\n"), 400);
    }

    #[test]
    fn chunk_data_shorter_than_declared_is_400() {
        // Five bytes declared, three supplied: the footer check sees "0\r"
        // instead of CRLF, so the message is malformed, not complete.
        assert_eq!(scan_err(b"5\r\nabc\r\n0\r\n\r\n"), 400);
    }

    #[test]
    fn chunk_size_radix_and_sign_is_400() {
        // A chunk size is bare hex: no 0x prefix, no sign, no leading space.
        // 0x0 is the case a lax parser could misread as the terminator.
        assert_eq!(scan_err(b"0x5\r\nhello\r\n0\r\n\r\n"), 400);
        assert_eq!(scan_err(b"0x0\r\n\r\n"), 400);
        assert_eq!(scan_err(b"+5\r\nhello\r\n0\r\n\r\n"), 400);
        assert_eq!(scan_err(b"-5\r\nhello\r\n0\r\n\r\n"), 400);
        assert_eq!(scan_err(b" 5\r\nhello\r\n0\r\n\r\n"), 400);
    }

    #[test]
    fn max_chunk_size_is_accepted_awaiting_payload() {
        // Sixteen hex digits is usize::MAX: parsed without overflow, then
        // awaiting payload. The size parse does not bound the body - the
        // decoded-size cap does - and seventeen digits overflow to 400.
        assert_eq!(
            scan(b"ffffffffffffffff\r\n", &mut ChunkScan::default()),
            Ok(None)
        );
    }

    #[test]
    fn chunk_footer_requires_exact_crlf() {
        // Both bytes of a chunk's trailing CRLF are checked, including when
        // the two arrive in separate reads.
        assert_eq!(scan_err(b"3\r\nabcX\r\n1a\r\n"), 400); // first byte
        assert_eq!(scan_err(b"3\r\nabc\rX\r\n1a\r\n"), 400); // second byte
        let mut s = ChunkScan::default();
        assert_eq!(scan(b"3\r\nabc\r", &mut s), Ok(None));
        assert_eq!(scan(b"3\r\nabc\rX\r\n", &mut s), Err(400));
    }

    #[test]
    fn scan_does_not_grow_past_the_terminal_chunk() {
        // Once the terminal chunk is seen the extent is fixed; bytes of a
        // following pipelined message are not absorbed into it.
        let mut s = ChunkScan::default();
        assert_eq!(scan(b"0\r\n\r\n", &mut s), Ok(Some(5)));
        assert_eq!(
            scan(b"0\r\n\r\nGET /next HTTP/1.1\r\n\r\n", &mut s),
            Ok(Some(5))
        );
    }

    #[test]
    fn lf_only_line_endings_never_complete() {
        // LF-only line endings are not CRLF, so the scan keeps asking for
        // more and never completes on a lone LF.
        assert_eq!(
            scan(b"5\nhello\n0\n\n", &mut ChunkScan::default()),
            Ok(None)
        );
        assert_eq!(scan(b"0\n\n", &mut ChunkScan::default()), Ok(None));
    }

    #[test]
    fn resumes_through_a_trailer_section() {
        // Feed a multi-chunk body with a trailer section one byte at a time
        // through a single scan: every prefix asks for more, then the whole
        // extent completes, and the trailer-section byte count is not
        // double-counted across re-entry.
        let wire = b"3\r\nfoo\r\n4\r\nbars\r\n0\r\nx-a: 1\r\nx-b: 2\r\n\r\n";
        let mut s = ChunkScan::default();
        for cut in 0..wire.len() {
            assert_eq!(scan(&wire[..cut], &mut s), Ok(None), "cut {cut}");
        }
        assert_eq!(scan(wire, &mut s), Ok(Some(wire.len())));
        let (entity, trailers) = decode(wire).expect("decodes");
        assert_eq!(&entity[..], b"foobars");
        assert_eq!(trailers.len(), 2);
    }

    #[test]
    fn decode_rejects_trailing_garbage() {
        // decode requires the message to occupy the wire exactly - the
        // framer only ever hands it a complete extent.
        assert!(decode(b"0\r\n\r\nEXTRA").is_err());
        assert!(decode(b"0\r\n").is_err());
    }

    #[test]
    fn compact_single_chunk_moves_nothing() {
        // The default botocore shape is one payload span: compact reports
        // the entity where it lies and the wire is byte-for-byte untouched.
        let mut wire = botocore_wire();
        let orig = wire.clone();
        let c = compact(&mut wire).expect("compacts");
        assert_eq!(wire, orig, "single span: no byte moved");
        assert_eq!((c.start, c.len), (4, 0x8e), "entity after \"8e\\r\\n\"");
        assert_eq!(&wire[c.start..c.start + c.len], botocore_entity());
        assert!(c.trailers().expect("parses").is_empty());
    }

    #[test]
    fn compact_multi_chunk_stays_in_the_allocation() {
        let mut wire = b"3\r\nfoo\r\n4\r\nbars\r\n0\r\n\r\n".to_vec();
        let p0 = wire.as_ptr() as usize;
        let c = compact(&mut wire).expect("compacts");
        assert_eq!(&wire[c.start..c.start + c.len], b"foobars");
        assert_eq!(c.start, 3, "entity abuts the first span's position");
        assert_eq!(wire.as_ptr() as usize, p0, "no reallocation");
    }

    #[test]
    fn compact_agrees_with_decode() {
        // The in-place twin against the copying oracle, across the shapes
        // that matter: golden, multi-chunk, empty entity, trailers (with
        // the forbidden set dropped), extensions.
        let shapes: Vec<Vec<u8>> = vec![
            botocore_wire(),
            b"3\r\nfoo\r\n4\r\nbars\r\n0\r\n\r\n".to_vec(),
            b"0\r\n\r\n".to_vec(),
            b"0\r\nx-amz-checksum-crc32: abc==\r\nx-two:v\r\n\r\n".to_vec(),
            b"3\r\nabc\r\n0\r\nContent-Length: 9\r\nx-ok: v\r\n\r\n".to_vec(),
            b"5;name=val\r\nhello\r\n0\r\n\r\n".to_vec(),
        ];
        for wire in shapes {
            let (entity, trailers) = decode(&wire).expect("decodes");
            let mut w = wire.clone();
            let c = compact(&mut w).expect("compacts");
            assert_eq!(
                &w[c.start..c.start + c.len],
                &entity[..],
                "entity mismatch for {wire:?}"
            );
            let ct = c.trailers().expect("parses");
            assert_eq!(ct.len(), trailers.len());
            for (a, b) in ct.iter().zip(trailers.iter()) {
                assert_eq!(a.name, b.name);
                assert_eq!(a.value, b.value);
            }
        }
    }

    #[test]
    fn compact_rejects_what_decode_rejects() {
        assert!(compact(&mut b"0\r\n\r\nEXTRA".to_vec()).is_err());
        assert!(compact(&mut b"0\r\n".to_vec()).is_err());
        assert!(compact(&mut b"zz\r\n".to_vec()).is_err());
    }
}
