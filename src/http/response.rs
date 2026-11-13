//! The consumer-facing response type and its wire serialization.
//!
//! The codec owns the framing-critical headers, `Content-Length`, `Connection`, `Date` and `Transfer-Encoding`, and
//! drops a handler's attempt to set them, since a handler that could desynchronize framing would reopen the smuggling
//! class the head parser screens out. [`HttpResponse::head_content_length`] is the one exception, honored only on a
//! HEAD, where no body follows to disagree. Header names that are not RFC 9110 tokens and values with a byte outside
//! its field-value grammar are dropped too, so handler-echoed input cannot split a response, and a status outside
//! `200..=999` becomes 500. Every field is screened once, by [`HttpResponse::header`] or by [`ScreenedHeader::new`], so
//! nothing reaches the wire unscreened.

use std::borrow::Cow;

// Serialization takes the rendered date bytes; only the tests build an `HttpDate` themselves.
#[cfg(test)]
use super::date::HttpDate;
use super::head::{has_field_break, is_token_byte};

/// A response under construction, returned by the consumer's handler.
///
/// Built as `HttpResponse::new(200).header("etag", "\"abc\"").body(xml)`. The codec supplies the status text, `Date`
/// and `Content-Length` at serialization. Names, values and the body are `Cow<'static, _>`, so a response built from
/// literals allocates nothing.
#[derive(Debug)]
pub struct HttpResponse {
    pub(crate) status: u16,
    pub(crate) headers: Headers,
    pub(crate) body: BodySource,
    pub(crate) close: bool,
    /// The `Content-Length` to report when this answers a HEAD, set by [`HttpResponse::head_content_length`]; ignored
    /// on every other request, where the measured body is the only truth.
    pub(crate) head_len: Option<u64>,
}

/// Where a response's body comes from: bytes in hand, or a file the reactor streams behind the head. One source per
/// response - [`HttpResponse::body`] and [`HttpResponse::file_body`] both set it, last call wins - so the serializer
/// has exactly one origin to frame.
#[derive(Debug)]
pub(crate) enum BodySource {
    /// Buffered bytes (the only source without `uring-fs`).
    Bytes(Cow<'static, [u8]>),
    /// `len` bytes of `file` from `offset`, read and sent in bounded chunks by the reactor's reply path
    /// ([`HttpResponse::file_body`]).
    #[cfg(feature = "uring-fs")]
    File {
        file: crate::uring_fs::File,
        offset: u64,
        len: u64,
    },
}

impl BodySource {
    /// The `Content-Length` a GET of this source declares: measured for bytes, the caller's contract for a file.
    fn declared_len(&self) -> u64 {
        match self {
            BodySource::Bytes(b) => b.len() as u64,
            #[cfg(feature = "uring-fs")]
            BodySource::File { len, .. } => *len,
        }
    }
}

/// Conversion into stored response bytes, the `Cow`-aware analogue of `Into<Vec<u8>>` for [`HttpResponse::header`]
/// values and [`HttpResponse::body`]. `Into<Cow<'static, [u8]>>` alone would reject the `&'static str` and `String`
/// shapes handlers pass most. Static inputs stay borrows and owned inputs move without copying.
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
impl IntoBytes for Cow<'static, str> {
    fn into_bytes(self) -> Cow<'static, [u8]> {
        match self {
            Cow::Borrowed(s) => Cow::Borrowed(s.as_bytes()),
            Cow::Owned(s) => Cow::Owned(s.into()),
        }
    }
}

/// A response header pair: name and undecoded value, both `Cow<'static, _>` so a response built from literals borrows
/// rather than allocates.
pub(crate) type Header = (Cow<'static, str>, Cow<'static, [u8]>);

/// A response field that passed the codec's screen ([`header_pair_ok`]) when it was built, so
/// [`HttpResponse::header_screened`] stores it without screening it again. [`ScreenedHeader::new`] is the only
/// constructor: a value of this type is the proof, and a consumer that keeps its fields in this type keeps that proof
/// with them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScreenedHeader {
    name: Cow<'static, str>,
    value: Cow<'static, [u8]>,
}

impl ScreenedHeader {
    /// Screen `name: value`; `None` is a pair the codec would not carry. A `&'static str` name and a static value are
    /// stored as borrows.
    #[inline]
    pub fn new(name: impl Into<Cow<'static, str>>, value: impl IntoBytes) -> Option<Self> {
        let name = name.into();
        let value = value.into_bytes();
        header_pair_ok(&name, &value).then_some(ScreenedHeader { name, value })
    }

    /// The field name, as given.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The field value, undecoded.
    pub fn value(&self) -> &[u8] {
        &self.value
    }
}

/// Inline capacity for [`Headers`]. Every response this codec emits carries well under this many fields, so the common
/// case never touches the heap.
const INLINE_HEADERS: usize = 8;

/// Response headers, stored inline until they spill. The first [`INLINE_HEADERS`] pairs live in an array and only
/// fields past that go to `spilled`, so a typical response allocates nothing for its headers.
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
    /// A status outside `200..=999` is replaced with `500`. Below 100 or above 999 it would serialize as a head no
    /// client can parse (RFC 9112 sec. 4). A 1xx is interim (RFC 9110 sec. 15.2), so a client receiving one keeps
    /// waiting while the codec has already answered and re-armed, and a `101` would tell the peer the connection left
    /// HTTP/1.1. The one interim this codec sends, `100 Continue`, is written as raw bytes and never travels through
    /// this type. A protocol switch needs a protocol that models one ([`ws`](crate::ws)).
    pub fn new(status: u16) -> Self {
        Self {
            status: if (200..=999).contains(&status) { status } else { 500 },
            headers: Headers::default(),
            body: BodySource::Bytes(Cow::Borrowed(&[])),
            close: false,
            head_len: None,
        }
    }

    /// Append a header. `Content-Length`, `Connection`, `Date` and `Transfer-Encoding` are codec-owned and ignored, and
    /// so are names that are not RFC 9110 tokens and values with a byte outside RFC 9110 sec. 5.5's field-value grammar
    /// (CR, LF, NUL, the other C0 controls or DEL), which would let handler-echoed bytes split the response. A
    /// `&'static str` name and a static value are stored as borrows.
    pub fn header(mut self, name: impl Into<Cow<'static, str>>, value: impl IntoBytes) -> Self {
        let name = name.into();
        let value = value.into_bytes();
        if header_pair_ok(&name, &value) {
            self.headers.push((name, value));
        }
        self
    }

    /// Store a field the screen already admitted — a [`ScreenedHeader`] is only ever the product of [`header_pair_ok`]
    /// — without walking its name and value a second time.
    pub fn header_screened(mut self, field: ScreenedHeader) -> Self {
        self.headers.push((field.name, field.value));
        self
    }

    /// Set the body. `Content-Length` follows automatically; for a HEAD request the bytes are measured but not sent. On
    /// a bodyless status (1xx/204/304) the bytes are never sent - see `serialize`. Static bytes are stored as a
    /// borrow - no copy. A response has one body source: this and [`HttpResponse::file_body`] set the same slot, last
    /// call wins.
    pub fn body(mut self, body: impl IntoBytes) -> Self {
        self.body = BodySource::Bytes(body.into_bytes());
        self
    }

    /// Send `len` bytes of `file` from `offset` as this response's body, read on the server's ring and sent in bounded
    /// chunks (`ServerConfig::fs_body_chunk`) rather than buffered. A range is an `offset` and `len`.
    ///
    /// `len` IS the `Content-Length`. Reads are clamped to it, so growth mid-send is invisible, and a file that shrinks
    /// below it closes the connection mid-body ([`CloseReason`](crate::net::server::CloseReason)
    /// `::FileBodyTruncated`). On a HEAD the length is declared
    /// ([`head_content_length`](HttpResponse::head_content_length) still overrides it) and no read is issued, and on a
    /// bodyless status (1xx/204/304) the handle is dropped unread. This and [`body`](HttpResponse::body) set the same
    /// slot, and the last call wins.
    ///
    /// `offset + len` must fit in an `i64`, since `u64::MAX` reaches the ring as io_uring's "read from the file's own
    /// position" sentinel. A range that does not fit closes the connection
    /// ([`CloseReason`](crate::net::server::CloseReason)`::FileBody`), which is what a suffix range computed as
    /// `size - n` looks like once it has wrapped, so clamp that at zero.
    ///
    /// The reactor holds the handle until the last chunk flushes or the connection dies. Serving this needs the
    /// server's fs pool (`ServerConfig::fs_ops`), or the connection closes at reply time. A peer that stops reading is
    /// reclaimed only by `ServerConfig::send_timeout` or `tcp_user_timeout`, so set both when serving untrusted peers.
    #[cfg(feature = "uring-fs")]
    pub fn file_body(mut self, file: crate::uring_fs::File, offset: u64, len: u64) -> Self {
        self.body = BodySource::File { file, offset, len };
        self
    }

    /// Declare the `Content-Length` this response reports **when it answers a HEAD**, in place of the measured body
    /// length. Ignored on every other request, and on a bodyless status (1xx/204/304), which carries no
    /// `Content-Length`.
    ///
    /// A HEAD answer carries no content (RFC 9110 sec. 9.3.2), so a declared length cannot desynchronize framing there,
    /// and only there, which is why this is a typed method and not a header a handler may set. It lets a handler report
    /// an object's size with no bytes in hand. The parsed request method decides whether the request was a HEAD.
    pub fn head_content_length(mut self, len: u64) -> Self {
        self.head_len = Some(len);
        self
    }

    /// Close the connection after this response flushes, regardless of what the request's keep-alive negotiation said.
    pub fn close(mut self) -> Self {
        self.close = true;
        self
    }

    /// The response status.
    pub fn status(&self) -> u16 {
        self.status
    }
}

/// Whether the codec carries `name: value` as a response field: `name` is a non-empty RFC 9110 token that the codec
/// does not write itself, and `value` has no byte that would end the field line early (CR, LF, NUL, the other C0
/// controls, or DEL). The one rule [`HttpResponse::header`] screens with and [`ScreenedHeader::new`] proves, exported
/// so a caller's own boundary can apply the codec's rule rather than a copy that can drift from it. Inlined because
/// that boundary is in another crate and runs once per field of every response.
#[inline]
pub fn header_pair_ok(name: &str, value: &[u8]) -> bool {
    is_token(name) && !is_codec_owned(name) && !has_field_break(value)
}

/// Headers the serializer emits itself; consumer copies are dropped.
fn is_codec_owned(name: &str) -> bool {
    name.eq_ignore_ascii_case("content-length")
        || name.eq_ignore_ascii_case("connection")
        || name.eq_ignore_ascii_case("date")
        || name.eq_ignore_ascii_case("transfer-encoding")
}

/// RFC 9110 `token` (a non-empty run of [`is_token_byte`]s) - the field-name grammar `httparse` enforces on the request
/// side, applied to what handlers emit. Anything else (spaces, colons, CTLs) could rewrite the field line it rides in.
fn is_token(name: &str) -> bool {
    !name.is_empty() && name.bytes().all(is_token_byte)
}

/// The `Connection` header the response should carry, if any: HTTP/1.1 keep-alive is implicit, everything else is
/// explicit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConnHeader {
    /// Say nothing (HTTP/1.1, staying open).
    None,
    /// `Connection: keep-alive` (HTTP/1.0 client that negotiated it).
    KeepAlive,
    /// `Connection: close` (this response is the farewell).
    Close,
}

/// Serialize to wire bytes. `head_only` elides the body but keeps its `Content-Length`, or reports
/// [`HttpResponse::head_content_length`] instead when the handler declared one. `date` is the rendered IMF-fixdate,
/// supplied by the caller so this stays pure.
///
/// 1xx/204/304 responses never carry content (RFC 9110 sec. 6.4.1), so body bytes and `Content-Length` are both elided
/// whatever `head_only` says, since a stray length would desynchronize the next response.
pub(crate) fn serialize(resp: &HttpResponse, head_only: bool, date: &[u8], conn: ConnHeader) -> Vec<u8> {
    let bodyless = status_is_bodyless(resp.status);
    // Only in-hand bytes can ride this by-ref serializer; a file-sourced body serializes as its head alone (the reactor
    // streams the bytes -- that path goes through `serialize_reply`).
    let body: &[u8] = match &resp.body {
        BodySource::Bytes(b) if !head_only && !bodyless => b,
        _ => &[],
    };
    let mut out = Vec::with_capacity(head_capacity(resp) + body.len());
    write_head(&mut out, resp, head_only, date, conn);
    out.extend_from_slice(body);
    out
}

/// The response head (status line through the terminating blank line) alone, no body - for [`serialize_reply`]'s split
/// path, where the body rides its own send segment instead of being copied in here.
pub(crate) fn serialize_head(resp: &HttpResponse, head_only: bool, date: &[u8], conn: ConnHeader) -> Vec<u8> {
    let mut out = Vec::with_capacity(head_capacity(resp));
    write_head(&mut out, resp, head_only, date, conn);
    out
}

/// Head-buffer capacity estimate (status line + `Date` + `Content-Length` + `Connection` + the consumer headers +
/// terminators); the body is accounted separately by [`serialize`].
fn head_capacity(resp: &HttpResponse) -> usize {
    128 + resp.headers.iter().map(|(n, v)| n.len() + v.len() + 4).sum::<usize>()
}

/// Whether `status` forbids a response body (RFC 9110 sec. 6.4.1): 1xx, 204, and 304 carry neither body bytes nor a
/// `Content-Length`. The head/body/reply serializers share this one predicate so their framing decisions cannot drift
/// apart.
fn status_is_bodyless(status: u16) -> bool {
    matches!(status, 100..=199 | 204 | 304)
}

/// Write the response head into `out`: status line, `Date`, `Content-Length` (elided for 1xx/204/304), the `Connection`
/// header, the consumer headers, and the terminating blank line. No body.
fn write_head(out: &mut Vec<u8>, resp: &HttpResponse, head_only: bool, date: &[u8], conn: ConnHeader) {
    // Bytes pushed directly rather than `write!`: the formatter's per-call setup and padding path cost more than the
    // status line and the numbers themselves, once per response on the reactor thread.
    let bodyless = status_is_bodyless(resp.status);
    out.extend_from_slice(b"HTTP/1.1 ");
    push_decimal(out, u64::from(resp.status));
    out.push(b' ');
    out.extend_from_slice(reason(resp.status).as_bytes());
    out.extend_from_slice(b"\r\nDate: ");
    out.extend_from_slice(date);
    out.extend_from_slice(b"\r\n");
    if !bodyless {
        // A declared length is honored only on the HEAD path, where no body bytes follow to disagree with it. A
        // file-sourced body's `len` is the caller's contract on both paths: a HEAD declares the length a GET would have
        // sent (RFC 9110 sec. 9.3.2) without reading a byte.
        let declared = match resp.head_len {
            Some(len) if head_only => len,
            _ => resp.body.declared_len(),
        };
        out.extend_from_slice(b"Content-Length: ");
        push_decimal(out, declared);
        out.extend_from_slice(b"\r\n");
    }
    match conn {
        ConnHeader::None => {}
        ConnHeader::KeepAlive => out.extend_from_slice(b"Connection: keep-alive\r\n"),
        ConnHeader::Close => out.extend_from_slice(b"Connection: close\r\n"),
    }
    for (name, value) in resp.headers.iter() {
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");
}

/// Append `n` in decimal.
fn push_decimal(out: &mut Vec<u8>, mut n: u64) {
    let mut digits = [0u8; 20];
    let mut i = digits.len();
    loop {
        i -= 1;
        digits[i] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    out.extend_from_slice(&digits[i..]);
}

/// A serialized response, ready to hand the reactor as a reply.
pub(crate) enum Serialized {
    /// The head alone - a HEAD or bodyless (1xx/204/304) response carries no body, so there is one buffer and nothing
    /// to scatter.
    HeadOnly(Vec<u8>),
    /// Head and body as separate buffers, sent vectored so the body is never copied into the head buffer.
    Split {
        /// The response head (status line through the blank line).
        head: Vec<u8>,
        /// The response body, its own send segment: owned bytes moved, `'static` bytes borrowed - the handler's storage
        /// either way.
        body: Cow<'static, [u8]>,
    },
    /// Head plus a file-sourced tail: the reactor streams `len` bytes of `file` from `offset` behind the head
    /// ([`HttpResponse::file_body`] -> `Response::ReplyFile`).
    #[cfg(feature = "uring-fs")]
    FileTail {
        /// The response head (status line through the blank line).
        head: Vec<u8>,
        /// The body's source file, moved to the reactor.
        file: crate::uring_fs::File,
        /// File offset the body starts at.
        offset: u64,
        /// Exactly the declared `Content-Length`.
        len: u64,
    },
}

/// Serialize `resp` into a head buffer and, when it carries a body, the body as its own segment, so the send path
/// scatters both with one vectored write. A HEAD, a bodyless status or an empty body yields [`Serialized::HeadOnly`], a
/// byte body splits, and a file body becomes [`Serialized::FileTail`]. It consumes `resp` so a byte body rides into its
/// segment without a copy and a file handle moves.
pub(crate) fn serialize_reply(resp: HttpResponse, head_only: bool, date: &[u8], conn: ConnHeader) -> Serialized {
    let bodyless = status_is_bodyless(resp.status);
    let head = serialize_head(&resp, head_only, date, conn);
    match resp.body {
        BodySource::Bytes(body) => {
            if head_only || bodyless || body.is_empty() {
                Serialized::HeadOnly(head)
            } else {
                Serialized::Split { head, body }
            }
        }
        // A HEAD (its length was declared by `write_head`) or a bodyless status drops the handle unread - no read is
        // ever issued for a response that sends no body - and a zero-length body has nothing to stream.
        #[cfg(feature = "uring-fs")]
        BodySource::File { file, offset, len } => {
            if head_only || bodyless || len == 0 {
                drop(file);
                Serialized::HeadOnly(head)
            } else {
                Serialized::FileTail {
                    head,
                    file,
                    offset,
                    len,
                }
            }
        }
    }
}

/// Reason phrase for the statuses this stack emits; empty for the rest (RFC 9112 allows an empty reason).
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
        // Sun, 06 Nov 1994 08:49:37 GMT - recognizable in assertions.
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

    /// A field screened ahead of its response reaches the wire exactly as one screened at `header` does, and the screen
    /// it passed is the same one: what `header` drops, `ScreenedHeader::new` refuses.
    #[test]
    fn a_screened_field_is_carried_and_an_unscreenable_one_is_refused() {
        let screened = ScreenedHeader::new("x-amz-request-id", "abc123").expect("a token name and a clean value");
        assert_eq!(screened.name(), "x-amz-request-id");
        assert_eq!(screened.value(), b"abc123");
        let via_screen = HttpResponse::new(200).header_screened(screened).body("hello");
        let via_header = HttpResponse::new(200)
            .header("x-amz-request-id", "abc123")
            .body("hello");
        assert_eq!(
            serialize(&via_screen, false, &date(), ConnHeader::None),
            serialize(&via_header, false, &date(), ConnHeader::None)
        );
        for (name, value) in [
            ("content-length", "0"),
            ("Transfer-Encoding", "chunked"),
            ("x y", "1"),
            ("", "1"),
            ("x-amz-meta-bad", "a\r\nx-injected: 1"),
            ("x-amz-meta-nul", "a\0b"),
        ] {
            assert!(ScreenedHeader::new(name, value).is_none(), "{name:?}: {value:?}");
            assert!(!header_pair_ok(name, value.as_bytes()), "{name:?}");
        }
        // Static inputs stay borrows; the value keeps HTAB and obs-text.
        let kept = ScreenedHeader::new(Cow::Borrowed("x"), "a\tb\u{e9}").expect("field content");
        assert!(matches!(kept.name, Cow::Borrowed(_)));
        assert_eq!(kept.value(), "a\tb\u{e9}".as_bytes());
    }

    /// The hand-rolled decimal matches `std` at every edge the head renders: the smallest and largest lengths, a length
    /// that fills the digit buffer, and a three-digit status.
    #[test]
    fn push_decimal_matches_std_at_the_edges() {
        for n in [
            0u64,
            1,
            9,
            10,
            99,
            100,
            4096,
            u64::from(u32::MAX),
            10_000_000_000_000_000_000,
            u64::MAX - 1,
            u64::MAX,
        ] {
            let mut out = Vec::new();
            push_decimal(&mut out, n);
            assert_eq!(text(&out), n.to_string(), "{n}");
        }
        let resp = HttpResponse::new(999).body("");
        let out = serialize(&resp, true, &date(), ConnHeader::None);
        assert!(text(&out).starts_with("HTTP/1.1 999 "), "{}", text(&out));
        let resp = HttpResponse::new(200).head_content_length(u64::MAX);
        let out = serialize(&resp, true, &date(), ConnHeader::None);
        assert!(
            text(&out).contains("Content-Length: 18446744073709551615\r\n"),
            "{}",
            text(&out)
        );
    }

    #[test]
    fn headers_inline_then_spill_in_order() {
        // Distinct names so the wire order is checkable across the spill.
        let names: [&str; INLINE_HEADERS + 1] = ["x-0", "x-1", "x-2", "x-3", "x-4", "x-5", "x-6", "x-7", "x-8"];
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
        // The same response answering a GET reports what it actually carries. A declaration that outlived its HEAD
        // would promise bytes the serializer never writes, and the client would read the next response's head as this
        // one's body.
        let resp = HttpResponse::new(200).head_content_length(4096).body("hello");
        let out = serialize(&resp, false, &date(), ConnHeader::None);
        let s = text(&out);
        assert!(s.contains("Content-Length: 5\r\n"), "{s}");
        assert!(!s.contains("4096"), "{s}");
        assert!(s.ends_with("\r\n\r\nhello"), "{s}");
    }

    /// An interim status is not a final response, so it never reaches the wire as one: `HttpResponse::new` normalizes
    /// 1xx to 500. Pinned because the failure is silent on this side - the response serializes and the connection keeps
    /// serving - and shows up only as a hung client.
    #[test]
    fn an_interim_status_cannot_be_a_final_response() {
        for interim in [100u16, 101, 102, 103, 199] {
            assert_eq!(
                HttpResponse::new(interim).status(),
                500,
                "{interim} was accepted as a final status"
            );
        }
        // The control: the neighbouring statuses are untouched, so the check above is a 1xx rule and not a blanket
        // rewrite.
        for ok in [200u16, 204, 304, 400, 413, 431, 500, 505, 999] {
            assert_eq!(HttpResponse::new(ok).status(), ok);
        }
    }

    #[test]
    fn head_declaration_does_not_revive_a_bodyless_status() {
        // 204/304 (and 1xx, which cannot get here - see `an_interim_status_cannot_be_a_final_response`) carry no
        // Content-Length at all, and a HEAD asking for one changes nothing -- S3 answers a conditional HeadObject with
        // a bare 304.
        for status in [204, 304] {
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
        let out = serialize(&HttpResponse::new(299), false, &date(), ConnHeader::None);
        assert!(text(&out).starts_with("HTTP/1.1 299 \r\n"));
    }

    #[test]
    fn out_of_range_status_becomes_500() {
        // 0-99 and 1000+ don't fit the three-digit status-line grammar.
        for bad in [0, 99, 1000, u16::MAX] {
            assert_eq!(HttpResponse::new(bad).status(), 500, "{bad}");
        }
        // 1xx fits the grammar but is not a *final* response, and is normalized too -
        // `an_interim_status_cannot_be_a_final_response`.
        assert_eq!(HttpResponse::new(100).status(), 500);
        assert_eq!(HttpResponse::new(200).status(), 200);
        assert_eq!(HttpResponse::new(999).status(), 999);
    }

    #[test]
    fn splitting_attempts_dropped() {
        // CR/LF (or NUL) in a value, and non-token names, are dropped whole -- the response-splitting guard.
        let resp = HttpResponse::new(302)
            .header("location", "/x\r\nContent-Length: 0\r\n\r\nHTTP/1.1 200 OK")
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
        // Beyond CR/LF/NUL, the other C0 controls and DEL can't ride into a field line; HTAB, SP, VCHAR, and obs-text
        // may.
        let resp = HttpResponse::new(200)
            .header("x-vt", &b"a\x0bb"[..]) // vertical tab
            .header("x-ff", &b"a\x0cb"[..]) // form feed
            .header("x-soh", &b"a\x01b"[..]) // C0 control
            .header("x-us", &b"a\x1fb"[..]) // unit separator
            .header("x-del", &b"a\x7fb"[..]) // DEL
            .header("x-tab", &b"a\tb"[..]) // HTAB - allowed
            .header("x-obs", &b"caf\xe9"[..]) // obs-text - allowed
            .header("x-ok", "plain");
        let out = serialize(&resp, false, &date(), ConnHeader::None);
        let has = |needle: &[u8]| out.windows(needle.len()).any(|w| w == needle);
        for dropped in [&b"x-vt"[..], b"x-ff", b"x-soh", b"x-us", b"x-del"] {
            assert!(!has(dropped), "{} not dropped", String::from_utf8_lossy(dropped));
        }
        // Allowed values survive verbatim, in wire form.
        assert!(has(b"x-tab: a\tb\r\n"));
        assert!(has(b"x-obs: caf\xe9\r\n"));
        assert!(has(b"x-ok: plain\r\n"));
    }

    #[test]
    fn bodyless_statuses_carry_no_content() {
        // 1xx/204/304 MUST NOT carry content, so a handler-set body is elided and no Content-Length is emitted. A 1xx
        // cannot reach the serializer as a final response, so the predicate's 1xx arm is asserted directly.
        assert!(status_is_bodyless(100) && status_is_bodyless(199));
        for status in [204, 304] {
            let resp = HttpResponse::new(status).body("diagnostic");
            let out = serialize(&resp, false, &date(), ConnHeader::None);
            let s = text(&out);
            assert!(!s.contains("Content-Length"), "{status}: {s}");
            assert!(s.ends_with("\r\n\r\n"), "{status}: {s}");
        }
        // A 200 with an empty body still declares its length.
        let ok = serialize(&HttpResponse::new(200), false, &date(), ConnHeader::None);
        assert!(text(&ok).contains("Content-Length: 0\r\n"));
    }

    #[test]
    fn split_sends_a_static_body_by_reference() {
        // The zero-copy contract: a `'static` body rides into its segment as the same bytes at the same address. A copy
        // reintroduced anywhere in serialize_reply moves the pointer and fails here.
        static BODY: &[u8] = b"hello, body";
        let resp = HttpResponse::new(200).body(BODY);
        let Serialized::Split { body, .. } = serialize_reply(resp, false, &date(), ConnHeader::None) else {
            panic!("a bodied response must split");
        };
        assert_eq!(body.as_ptr(), BODY.as_ptr());
        assert_eq!(&body[..], BODY);
    }

    #[test]
    fn split_moves_an_owned_body_without_copying() {
        // Same contract for the owned shape: the handler's allocation is the segment - moved, not reallocated.
        let owned = b"hello, body".to_vec();
        let ptr = owned.as_ptr();
        let resp = HttpResponse::new(200).body(owned);
        let Serialized::Split { body, .. } = serialize_reply(resp, false, &date(), ConnHeader::None) else {
            panic!("a bodied response must split");
        };
        assert_eq!(body.as_ptr(), ptr);
    }
}

#[cfg(all(test, feature = "uring-fs", not(loom)))]
mod file_body_tests {
    use super::*;
    use crate::http::HttpDate;
    use crate::sync::Arc;
    use crate::uring_fs::File;
    use std::os::fd::OwnedFd;

    fn date() -> Vec<u8> {
        HttpDate::from_unix(784_111_777).to_string().into_bytes()
    }

    fn text(bytes: &[u8]) -> &str {
        std::str::from_utf8(bytes).expect("responses are ascii here")
    }

    /// A file handle plus the `Arc` behind it, so a test can prove the handle was dropped (strong count back to 1) -
    /// the "no read is ever issued" half of the elision contract, observable without a reactor.
    fn probe_file() -> (File, Arc<OwnedFd>) {
        let fd: OwnedFd = std::fs::File::open("/dev/null").expect("open /dev/null").into();
        let arc = Arc::new(fd);
        (File::new(Arc::clone(&arc)), arc)
    }

    #[test]
    fn a_get_streams_the_declared_range() {
        let (file, _held) = probe_file();
        let resp = HttpResponse::new(200).file_body(file, 7, 4096);
        let Serialized::FileTail { head, offset, len, .. } = serialize_reply(resp, false, &date(), ConnHeader::None)
        else {
            panic!("a file body must stream");
        };
        let s = text(&head);
        assert!(s.contains("Content-Length: 4096\r\n"), "{s}");
        assert!(s.ends_with("\r\n\r\n"), "{s}");
        assert_eq!((offset, len), (7, 4096), "the range is the caller's");
    }

    #[test]
    fn a_head_declares_the_length_and_drops_the_handle_unread() {
        // The HEAD contract: the length a GET would have sent goes on the wire, no byte is read, and the handle is
        // released - the strong count proves `serialize_reply` dropped it rather than parking it anywhere a read could
        // still be issued from.
        let (file, held) = probe_file();
        let resp = HttpResponse::new(200).file_body(file, 0, 4096);
        let Serialized::HeadOnly(head) = serialize_reply(resp, true, &date(), ConnHeader::None) else {
            panic!("a HEAD must not stream");
        };
        let s = text(&head);
        assert!(s.contains("Content-Length: 4096\r\n"), "{s}");
        assert!(s.ends_with("\r\n\r\n"), "{s}");
        assert_eq!(Arc::strong_count(&held), 1, "handle dropped unread");
    }

    #[test]
    fn head_content_length_still_overrides_on_the_head_path() {
        let (file, _held) = probe_file();
        let resp = HttpResponse::new(200).head_content_length(9).file_body(file, 0, 4096);
        let Serialized::HeadOnly(head) = serialize_reply(resp, true, &date(), ConnHeader::None) else {
            panic!("a HEAD must not stream");
        };
        assert!(text(&head).contains("Content-Length: 9\r\n"));
    }

    #[test]
    fn bodyless_statuses_drop_the_handle_and_the_length() {
        for status in [204, 304] {
            let (file, held) = probe_file();
            let resp = HttpResponse::new(status).file_body(file, 0, 4096);
            let Serialized::HeadOnly(head) = serialize_reply(resp, false, &date(), ConnHeader::None) else {
                panic!("{status}: a bodyless status must not stream");
            };
            assert!(!text(&head).contains("Content-Length"), "{status}");
            assert_eq!(Arc::strong_count(&held), 1, "{status}: dropped");
        }
    }

    #[test]
    fn a_zero_length_file_body_is_a_plain_head() {
        let (file, held) = probe_file();
        let resp = HttpResponse::new(200).file_body(file, 0, 0);
        let Serialized::HeadOnly(head) = serialize_reply(resp, false, &date(), ConnHeader::None) else {
            panic!("nothing to stream");
        };
        assert!(text(&head).contains("Content-Length: 0\r\n"));
        assert_eq!(Arc::strong_count(&held), 1);
    }

    #[test]
    fn one_body_one_origin_last_call_wins() {
        let (file, _held) = probe_file();
        let resp = HttpResponse::new(200).body("bytes").file_body(file, 0, 3);
        assert!(matches!(
            serialize_reply(resp, false, &date(), ConnHeader::None),
            Serialized::FileTail { len: 3, .. }
        ));
        let (file, held) = probe_file();
        let resp = HttpResponse::new(200).file_body(file, 0, 3).body("bytes");
        let Serialized::Split { body, .. } = serialize_reply(resp, false, &date(), ConnHeader::None) else {
            panic!("the byte body won");
        };
        assert_eq!(&body[..], b"bytes");
        assert_eq!(Arc::strong_count(&held), 1, "overwritten handle dropped");
    }
}
