//! The consumer-facing response type and its wire serialization. The codec
//! owns the framing-critical headers — `Content-Length`, `Connection`,
//! `Date` — and silently drops consumer attempts to set them: a handler that
//! could desynchronize framing from the actual byte stream would reintroduce
//! the smuggling class the head parser screens out. The single exception is
//! [`HttpResponse::head_content_length`], honored only when the request was
//! a HEAD, where the protocol forbids a body outright and so leaves nothing
//! for a declared length to desynchronize. The same policy covers
//! the header bytes themselves: names that are not RFC 9110 tokens and
//! values with any byte outside RFC 9110's field-value grammar are dropped
//! too, so handler-echoed input can never split a response, and statuses
//! that don't fit the three-digit
//! status-line grammar are replaced with 500.

use std::borrow::Cow;

// Serialization takes the rendered date bytes; only the tests build an
// `HttpDate` themselves.
#[cfg(test)]
use super::date::HttpDate;

/// A response under construction, returned by the consumer's handler.
///
/// Builder-style: `HttpResponse::new(200).header("etag", "\"abc\"").body(xml)`.
/// Status text, `Date`, and `Content-Length` are supplied by the codec at
/// serialization time.
///
/// Header names, values, and the body are stored as `Cow<'static, _>`:
/// literals (the overwhelmingly common case for names, and common for
/// values and error bodies) are kept as borrows, so building a response
/// from static parts allocates nothing.
#[derive(Debug)]
pub struct HttpResponse {
    pub(crate) status: u16,
    pub(crate) headers: Headers,
    pub(crate) body: Cow<'static, [u8]>,
    pub(crate) close: bool,
    /// The `Content-Length` to report when this answers a HEAD, set by
    /// [`HttpResponse::head_content_length`]; ignored on every other
    /// request, where the measured body is the only truth.
    pub(crate) head_len: Option<u64>,
}

/// Conversion into stored response bytes — the `Cow`-aware analogue of
/// `Into<Vec<u8>>` for [`HttpResponse::header`] values and
/// [`HttpResponse::body`]. (`Into<Cow<'static, [u8]>>` alone would reject
/// the `&'static str` and `String` shapes handlers pass most, since std
/// provides no str-to-byte-`Cow` conversions.) Static inputs stay borrows;
/// owned inputs move without copying.
pub trait IntoBytes {
    /// Convert into the bytes to store.
    fn into_bytes(self) -> Cow<'static, [u8]>;
}

impl IntoBytes for &'static str {
    fn into_bytes(self) -> Cow<'static, [u8]> {
        Cow::Borrowed(self.as_bytes())
    }
}

impl IntoBytes for String {
    fn into_bytes(self) -> Cow<'static, [u8]> {
        Cow::Owned(self.into())
    }
}

impl IntoBytes for &'static [u8] {
    fn into_bytes(self) -> Cow<'static, [u8]> {
        Cow::Borrowed(self)
    }
}

impl<const N: usize> IntoBytes for &'static [u8; N] {
    fn into_bytes(self) -> Cow<'static, [u8]> {
        Cow::Borrowed(self)
    }
}

impl IntoBytes for Vec<u8> {
    fn into_bytes(self) -> Cow<'static, [u8]> {
        Cow::Owned(self)
    }
}

impl IntoBytes for Cow<'static, [u8]> {
    fn into_bytes(self) -> Cow<'static, [u8]> {
        self
    }
}

/// A response header pair: name and undecoded value, both `Cow<'static, _>`
/// so a response built from literals borrows rather than allocates.
pub(crate) type Header = (Cow<'static, str>, Cow<'static, [u8]>);

/// Inline capacity for [`Headers`]. Every response this codec emits carries
/// well under this many fields, so the common case never touches the heap.
const INLINE_HEADERS: usize = 8;

/// Response headers, stored inline until they spill. The first
/// [`INLINE_HEADERS`] pairs live in a stack array; only fields past that go to
/// `spilled`, whose backing `Vec` stays unallocated until then. The common
/// case — an S3 200 carries a handful of fields — allocates nothing for its
/// headers.
#[derive(Debug)]
pub(crate) struct Headers {
    /// The first fields, in wire order; `inline_len` slots are filled.
    inline: [Option<Header>; INLINE_HEADERS],
    /// How many `inline` slots are filled.
    inline_len: usize,
    /// Fields past the inline capacity; empty (and unallocated) until spill.
    spilled: Vec<Header>,
}

impl Default for Headers {
    fn default() -> Self {
        Headers {
            inline: std::array::from_fn(|_| None),
            inline_len: 0,
            spilled: Vec::new(),
        }
    }
}

impl Headers {
    /// Append a pair in wire order, spilling to the heap past the inline cap.
    fn push(&mut self, h: Header) {
        if self.inline_len < INLINE_HEADERS {
            self.inline[self.inline_len] = Some(h);
            self.inline_len += 1;
        } else {
            self.spilled.push(h);
        }
    }

    /// The stored pairs in wire order.
    fn iter(&self) -> impl Iterator<Item = &Header> {
        self.inline[..self.inline_len]
            .iter()
            .map(|slot| slot.as_ref().expect("slot below len is filled"))
            .chain(&self.spilled)
    }
}

impl HttpResponse {
    /// Start a response with `status` (e.g. `200`), empty body, no headers.
    ///
    /// The status line's grammar is exactly three digits (RFC 9112 §4); a
    /// status outside `100..=999` would serialize as a head no client can
    /// parse, so it is replaced with `500` here rather than desynchronizing
    /// the connection at the wire.
    pub fn new(status: u16) -> Self {
        Self {
            status: if (100..=999).contains(&status) {
                status
            } else {
                500
            },
            headers: Headers::default(),
            body: Cow::Borrowed(&[]),
            close: false,
            head_len: None,
        }
    }

    /// Append a header. `Content-Length`, `Connection`, `Date`, and
    /// `Transfer-Encoding` are codec-owned and ignored here (see module
    /// docs). Also ignored: names that are not RFC 9110 tokens and values
    /// with a byte outside RFC 9110 §5.5's field-value grammar (CR, LF, NUL,
    /// the other C0 controls, or DEL) — serializing those verbatim would let
    /// handler-echoed bytes terminate the field line early and inject
    /// response framing (response splitting).
    ///
    /// A `&'static str` name and a static value are stored as borrows —
    /// no allocation.
    pub fn header(
        mut self,
        name: impl Into<Cow<'static, str>>,
        value: impl IntoBytes,
    ) -> Self {
        let name = name.into();
        let value = value.into_bytes();
        if is_token(&name) && !has_field_break(&value) && !is_codec_owned(&name)
        {
            self.headers.push((name, value));
        }
        self
    }

    /// Set the body. `Content-Length` follows automatically; for a HEAD
    /// request the bytes are measured but not sent. On a bodyless status
    /// (1xx/204/304) the bytes are never sent — see `serialize`. Static
    /// bytes are stored as a borrow — no copy.
    pub fn body(mut self, body: impl IntoBytes) -> Self {
        self.body = body.into_bytes();
        self
    }

    /// Declare the `Content-Length` this response reports **when it answers
    /// a HEAD**, in place of the measured body length. Ignored otherwise,
    /// and ignored on a bodyless status (1xx/204/304), which carries no
    /// `Content-Length` at all.
    ///
    /// A HEAD answer is the one place a declared length cannot desynchronize
    /// framing: RFC 9110 §9.3.2 forbids content on it, the serializer elides
    /// the body regardless, and the client reads zero body bytes whatever
    /// the header says. So the usual codec-owned rule
    /// ([`HttpResponse::header`] drops a `Content-Length` outright) can be
    /// relaxed here without opening the smuggling class it exists to close —
    /// and only here, which is why this is a typed method on the HEAD path
    /// rather than a header a handler may set.
    ///
    /// The requirement is S3's: `HeadObject` reports the object's size,
    /// which a handler with no bytes in hand cannot express by measuring
    /// anything. Whether the request was a HEAD is decided by the parsed
    /// request method, never by the handler.
    pub fn head_content_length(mut self, len: u64) -> Self {
        self.head_len = Some(len);
        self
    }

    /// Close the connection after this response flushes, regardless of what
    /// the request's keep-alive negotiation said.
    pub fn close(mut self) -> Self {
        self.close = true;
        self
    }

    /// The response status.
    pub fn status(&self) -> u16 {
        self.status
    }
}

/// Headers the serializer emits itself; consumer copies are dropped.
fn is_codec_owned(name: &str) -> bool {
    name.eq_ignore_ascii_case("content-length")
        || name.eq_ignore_ascii_case("connection")
        || name.eq_ignore_ascii_case("date")
        || name.eq_ignore_ascii_case("transfer-encoding")
}

/// RFC 9110 `token` — the field-name grammar `httparse` enforces on the
/// request side, applied to what handlers emit. Anything else (spaces,
/// colons, CTLs) could rewrite the field line it rides in.
fn is_token(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

/// Whether a field value carries a byte a serialized field line may not.
/// RFC 9110 §5.5 admits only field-vchar (VCHAR `0x21..=0x7E` / obs-text
/// `0x80..=0xFF`), SP, and HTAB; every other byte is rejected — the CR/LF/NUL
/// that split a response, and the rest of the C0 controls and DEL, which S3
/// echoes verbatim in `x-amz-meta-*`. The write-side twin of the parser's
/// smuggling screens; mirrors httparse's request-side header-value map.
fn has_field_break(value: &[u8]) -> bool {
    value.iter().any(|&b| (b < 0x20 && b != b'\t') || b == 0x7f)
}

/// The `Connection` header the response should carry, if any: HTTP/1.1
/// keep-alive is implicit, everything else is explicit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConnHeader {
    /// Say nothing (HTTP/1.1, staying open).
    None,
    /// `Connection: keep-alive` (HTTP/1.0 client that negotiated it).
    KeepAlive,
    /// `Connection: close` (this response is the farewell).
    Close,
}

/// Serialize to wire bytes. `head_only` elides the body while keeping its
/// `Content-Length` (the HEAD contract), or reporting
/// [`HttpResponse::head_content_length`] in its place when the handler
/// declared one; `date` is the rendered IMF-fixdate value, injected by the
/// caller so this stays a pure function (and so the glue's per-reactor
/// [`DateCache`](super::date::DateCache) renders it once a second, not once
/// a response).
///
/// 1xx/204/304 responses never carry content (RFC 9110 §6.4.1): body bytes
/// are elided regardless of `head_only`, and so is `Content-Length` — a
/// client reads zero body bytes after these statuses no matter what the
/// header claims, so emitting one would desynchronize the next response on
/// the connection.
pub(crate) fn serialize(
    resp: &HttpResponse,
    head_only: bool,
    date: &[u8],
    conn: ConnHeader,
) -> Vec<u8> {
    use std::io::Write;

    let bodyless = matches!(resp.status, 100..=199 | 204 | 304);
    let mut out = Vec::with_capacity(
        128 + resp
            .headers
            .iter()
            .map(|(n, v)| n.len() + v.len() + 4)
            .sum::<usize>()
            + if head_only || bodyless {
                0
            } else {
                resp.body.len()
            },
    );
    // Vec<u8> Write is infallible; unwraps here cannot fire.
    write!(out, "HTTP/1.1 {} {}\r\n", resp.status, reason(resp.status))
        .unwrap();
    out.extend_from_slice(b"Date: ");
    out.extend_from_slice(date);
    out.extend_from_slice(b"\r\n");
    if !bodyless {
        // A declared length is honored only on the HEAD path, where no body
        // bytes follow to disagree with it.
        let declared = match resp.head_len {
            Some(len) if head_only => len,
            _ => resp.body.len() as u64,
        };
        write!(out, "Content-Length: {declared}\r\n").unwrap();
    }
    match conn {
        ConnHeader::None => {}
        ConnHeader::KeepAlive => {
            out.extend_from_slice(b"Connection: keep-alive\r\n")
        }
        ConnHeader::Close => out.extend_from_slice(b"Connection: close\r\n"),
    }
    for (name, value) in resp.headers.iter() {
        write!(out, "{name}: ").unwrap();
        out.extend_from_slice(value);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");
    if !head_only && !bodyless {
        out.extend_from_slice(&resp.body);
    }
    out
}

/// Reason phrase for the statuses this stack emits; empty for the rest
/// (RFC 9112 allows an empty reason).
fn reason(status: u16) -> &'static str {
    match status {
        100 => "Continue",
        200 => "OK",
        204 => "No Content",
        206 => "Partial Content",
        301 => "Moved Permanently",
        304 => "Not Modified",
        307 => "Temporary Redirect",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        411 => "Length Required",
        412 => "Precondition Failed",
        413 => "Content Too Large",
        416 => "Range Not Satisfiable",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        503 => "Service Unavailable",
        505 => "HTTP Version Not Supported",
        _ => "",
    }
}

#[cfg(test)]
impl HttpResponse {
    /// Whether the headers still fit the inline array (no heap spill yet).
    fn headers_inline(&self) -> bool {
        self.headers.spilled.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn date() -> Vec<u8> {
        // Sun, 06 Nov 1994 08:49:37 GMT — recognizable in assertions.
        HttpDate::from_unix(784_111_777).to_string().into_bytes()
    }

    fn text(bytes: &[u8]) -> &str {
        std::str::from_utf8(bytes).expect("responses are ascii here")
    }

    #[test]
    fn full_response() {
        let resp = HttpResponse::new(200)
            .header("x-amz-request-id", "abc123")
            .body("hello");
        let out = serialize(&resp, false, &date(), ConnHeader::None);
        assert_eq!(
            text(&out),
            "HTTP/1.1 200 OK\r\n\
             Date: Sun, 06 Nov 1994 08:49:37 GMT\r\n\
             Content-Length: 5\r\n\
             x-amz-request-id: abc123\r\n\
             \r\n\
             hello"
        );
    }

    #[test]
    fn headers_inline_then_spill_in_order() {
        // Distinct names so the wire order is checkable across the spill.
        let names: [&str; INLINE_HEADERS + 1] = [
            "x-0", "x-1", "x-2", "x-3", "x-4", "x-5", "x-6", "x-7", "x-8",
        ];
        let mut r = HttpResponse::new(200);
        for (i, n) in names.iter().enumerate() {
            r = r.header(*n, "v");
            // Inline until the array fills; the pair past the cap spills.
            assert_eq!(r.headers_inline(), i < INLINE_HEADERS, "after {i}");
        }
        let out = serialize(&r, false, &date(), ConnHeader::None);
        let s = text(&out);
        let positions: Vec<usize> = names
            .iter()
            .map(|n| {
                s.find(&format!("{n}: v"))
                    .unwrap_or_else(|| panic!("{n} missing:\n{s}"))
            })
            .collect();
        assert!(
            positions.windows(2).all(|w| w[0] < w[1]),
            "push order not preserved:\n{s}"
        );
    }

    #[test]
    fn head_elides_body_keeps_length() {
        let resp = HttpResponse::new(200).body("hello");
        let out = serialize(&resp, true, &date(), ConnHeader::None);
        let s = text(&out);
        assert!(s.contains("Content-Length: 5\r\n"));
        assert!(s.ends_with("\r\n\r\n"));
    }

    #[test]
    fn head_declaration_reports_a_length_with_no_bytes() {
        // HeadObject's shape: the object's size, no bytes in hand.
        let resp = HttpResponse::new(200).head_content_length(4096);
        let out = serialize(&resp, true, &date(), ConnHeader::None);
        let s = text(&out);
        assert!(s.contains("Content-Length: 4096\r\n"), "{s}");
        assert!(s.ends_with("\r\n\r\n"), "{s}");
    }

    #[test]
    fn head_declaration_is_ignored_off_the_head_path() {
        // The same response answering a GET reports what it actually
        // carries. A declaration that outlived its HEAD would promise bytes
        // the serializer never writes, and the client would read the next
        // response's head as this one's body.
        let resp = HttpResponse::new(200)
            .head_content_length(4096)
            .body("hello");
        let out = serialize(&resp, false, &date(), ConnHeader::None);
        let s = text(&out);
        assert!(s.contains("Content-Length: 5\r\n"), "{s}");
        assert!(!s.contains("4096"), "{s}");
        assert!(s.ends_with("\r\n\r\nhello"), "{s}");
    }

    #[test]
    fn head_declaration_does_not_revive_a_bodyless_status() {
        // 1xx/204/304 carry no Content-Length at all, and a HEAD asking for
        // one changes nothing — S3 answers a conditional HeadObject with a
        // bare 304.
        for status in [100, 204, 304] {
            let resp = HttpResponse::new(status).head_content_length(4096);
            let out = serialize(&resp, true, &date(), ConnHeader::None);
            let s = text(&out);
            assert!(!s.contains("Content-Length"), "{status}: {s}");
            assert!(s.ends_with("\r\n\r\n"), "{status}: {s}");
        }
    }

    #[test]
    fn connection_variants() {
        let resp = HttpResponse::new(204);
        let close = serialize(&resp, false, &date(), ConnHeader::Close);
        assert!(text(&close).contains("Connection: close\r\n"));
        let ka = serialize(&resp, false, &date(), ConnHeader::KeepAlive);
        assert!(text(&ka).contains("Connection: keep-alive\r\n"));
        let none = serialize(&resp, false, &date(), ConnHeader::None);
        assert!(!text(&none).contains("Connection:"));
    }

    #[test]
    fn codec_owned_headers_dropped() {
        let resp = HttpResponse::new(200)
            .header("Content-Length", "999")
            .header("connection", "upgrade")
            .header("Transfer-Encoding", "chunked")
            .header("date", "yesterday")
            .body("ok");
        let out = serialize(&resp, false, &date(), ConnHeader::None);
        let s = text(&out);
        assert!(s.contains("Content-Length: 2\r\n"));
        assert!(!s.contains("999"));
        assert!(!s.contains("upgrade"));
        assert!(!s.contains("chunked"));
        assert!(!s.contains("yesterday"));
    }

    #[test]
    fn unknown_status_empty_reason() {
        let out = serialize(
            &HttpResponse::new(299),
            false,
            &date(),
            ConnHeader::None,
        );
        assert!(text(&out).starts_with("HTTP/1.1 299 \r\n"));
    }

    #[test]
    fn out_of_range_status_becomes_500() {
        // 0-99 and 1000+ don't fit the three-digit status-line grammar.
        for bad in [0, 99, 1000, u16::MAX] {
            assert_eq!(HttpResponse::new(bad).status(), 500, "{bad}");
        }
        assert_eq!(HttpResponse::new(100).status(), 100);
        assert_eq!(HttpResponse::new(999).status(), 999);
    }

    #[test]
    fn splitting_attempts_dropped() {
        // CR/LF (or NUL) in a value, and non-token names, are dropped whole —
        // the response-splitting guard.
        let resp = HttpResponse::new(302)
            .header(
                "location",
                "/x\r\nContent-Length: 0\r\n\r\nHTTP/1.1 200 OK",
            )
            .header("x-lf", "a\nb")
            .header("x-nul", &b"a\0b"[..])
            .header("x evil", "v")
            .header("x-colon:", "v")
            .header("", "v")
            .header("x-ok", "kept");
        let out = serialize(&resp, false, &date(), ConnHeader::None);
        let s = text(&out);
        assert!(s.contains("x-ok: kept\r\n"));
        assert!(!s.contains("location"));
        assert!(!s.contains("x-lf"));
        assert!(!s.contains("x-nul"));
        assert!(!s.contains("x evil"));
        assert!(!s.contains("x-colon"));
        // Exactly one response head on the wire.
        assert_eq!(s.matches("HTTP/1.1").count(), 1);
    }

    #[test]
    fn field_value_restricted_to_rfc9110_grammar() {
        // Beyond CR/LF/NUL, the other C0 controls and DEL can't ride into a
        // field line; HTAB, SP, VCHAR, and obs-text may.
        let resp = HttpResponse::new(200)
            .header("x-vt", &b"a\x0bb"[..]) // vertical tab
            .header("x-ff", &b"a\x0cb"[..]) // form feed
            .header("x-soh", &b"a\x01b"[..]) // C0 control
            .header("x-us", &b"a\x1fb"[..]) // unit separator
            .header("x-del", &b"a\x7fb"[..]) // DEL
            .header("x-tab", &b"a\tb"[..]) // HTAB — allowed
            .header("x-obs", &b"caf\xe9"[..]) // obs-text — allowed
            .header("x-ok", "plain");
        let out = serialize(&resp, false, &date(), ConnHeader::None);
        let has =
            |needle: &[u8]| out.windows(needle.len()).any(|w| w == needle);
        for dropped in [&b"x-vt"[..], b"x-ff", b"x-soh", b"x-us", b"x-del"] {
            assert!(
                !has(dropped),
                "{} not dropped",
                String::from_utf8_lossy(dropped)
            );
        }
        // Allowed values survive verbatim, in wire form.
        assert!(has(b"x-tab: a\tb\r\n"));
        assert!(has(b"x-obs: caf\xe9\r\n"));
        assert!(has(b"x-ok: plain\r\n"));
    }

    #[test]
    fn bodyless_statuses_carry_no_content() {
        // 1xx/204/304 MUST NOT carry content; a handler-set body is elided
        // and no Content-Length is emitted at all.
        for status in [100, 204, 304] {
            let resp = HttpResponse::new(status).body("diagnostic");
            let out = serialize(&resp, false, &date(), ConnHeader::None);
            let s = text(&out);
            assert!(!s.contains("Content-Length"), "{status}: {s}");
            assert!(s.ends_with("\r\n\r\n"), "{status}: {s}");
        }
        // A 200 with an empty body still declares its length.
        let ok = serialize(
            &HttpResponse::new(200),
            false,
            &date(),
            ConnHeader::None,
        );
        assert!(text(&ok).contains("Content-Length: 0\r\n"));
    }
}
