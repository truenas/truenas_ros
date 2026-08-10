//! The consumer-facing response type and its wire serialization. The codec
//! owns the framing-critical headers — `Content-Length`, `Connection`,
//! `Date` — and silently drops consumer attempts to set them: a handler that
//! could desynchronize framing from the actual byte stream would reintroduce
//! the smuggling class the head parser screens out. The same policy covers
//! the header bytes themselves: names that are not RFC 9110 tokens and
//! values carrying CR/LF/NUL are dropped too, so handler-echoed input can
//! never split a response, and statuses that don't fit the three-digit
//! status-line grammar are replaced with 500.

use super::date::HttpDate;

/// A response under construction, returned by the consumer's handler.
///
/// Builder-style: `HttpResponse::new(200).header("etag", "\"abc\"").body(xml)`.
/// Status text, `Date`, and `Content-Length` are supplied by the codec at
/// serialization time.
#[derive(Debug)]
pub struct HttpResponse {
    pub(crate) status: u16,
    pub(crate) headers: Vec<(String, Vec<u8>)>,
    pub(crate) body: Vec<u8>,
    pub(crate) close: bool,
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
            headers: Vec::new(),
            body: Vec::new(),
            close: false,
        }
    }

    /// Append a header. `Content-Length`, `Connection`, `Date`, and
    /// `Transfer-Encoding` are codec-owned and ignored here (see module
    /// docs). Also ignored: names that are not RFC 9110 tokens and values
    /// containing CR, LF, or NUL — serializing those verbatim would let
    /// handler-echoed bytes terminate the field line early and inject
    /// response framing (response splitting).
    pub fn header(
        mut self,
        name: impl Into<String>,
        value: impl Into<Vec<u8>>,
    ) -> Self {
        let name = name.into();
        let value = value.into();
        if is_token(&name) && !has_field_break(&value) && !is_codec_owned(&name)
        {
            self.headers.push((name, value));
        }
        self
    }

    /// Set the body. `Content-Length` follows automatically; for a HEAD
    /// request the bytes are measured but not sent. On a bodyless status
    /// (1xx/204/304) the bytes are never sent — see [`serialize`].
    pub fn body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = body.into();
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

/// CR, LF, or NUL in a field value ends the field line before the serializer
/// meant it to — the write-side twin of the parser's smuggling screens.
fn has_field_break(value: &[u8]) -> bool {
    value.iter().any(|&b| matches!(b, b'\r' | b'\n' | b'\0'))
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
/// `Content-Length` (the HEAD contract); `date` is injected by the caller so
/// this stays a pure function.
///
/// 1xx/204/304 responses never carry content (RFC 9110 §6.4.1): body bytes
/// are elided regardless of `head_only`, and so is `Content-Length` — a
/// client reads zero body bytes after these statuses no matter what the
/// header claims, so emitting one would desynchronize the next response on
/// the connection.
pub(crate) fn serialize(
    resp: &HttpResponse,
    head_only: bool,
    date: HttpDate,
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
    write!(out, "Date: {date}\r\n").unwrap();
    if !bodyless {
        write!(out, "Content-Length: {}\r\n", resp.body.len()).unwrap();
    }
    match conn {
        ConnHeader::None => {}
        ConnHeader::KeepAlive => {
            out.extend_from_slice(b"Connection: keep-alive\r\n")
        }
        ConnHeader::Close => out.extend_from_slice(b"Connection: close\r\n"),
    }
    for (name, value) in &resp.headers {
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
mod tests {
    use super::*;

    fn date() -> HttpDate {
        // Sun, 06 Nov 1994 08:49:37 GMT — recognizable in assertions.
        HttpDate::from_unix(784_111_777)
    }

    fn text(bytes: &[u8]) -> &str {
        std::str::from_utf8(bytes).expect("responses are ascii here")
    }

    #[test]
    fn full_response() {
        let resp = HttpResponse::new(200)
            .header("x-amz-request-id", "abc123")
            .body("hello");
        let out = serialize(&resp, false, date(), ConnHeader::None);
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
    fn head_elides_body_keeps_length() {
        let resp = HttpResponse::new(200).body("hello");
        let out = serialize(&resp, true, date(), ConnHeader::None);
        let s = text(&out);
        assert!(s.contains("Content-Length: 5\r\n"));
        assert!(s.ends_with("\r\n\r\n"));
    }

    #[test]
    fn connection_variants() {
        let resp = HttpResponse::new(204);
        let close = serialize(&resp, false, date(), ConnHeader::Close);
        assert!(text(&close).contains("Connection: close\r\n"));
        let ka = serialize(&resp, false, date(), ConnHeader::KeepAlive);
        assert!(text(&ka).contains("Connection: keep-alive\r\n"));
        let none = serialize(&resp, false, date(), ConnHeader::None);
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
        let out = serialize(&resp, false, date(), ConnHeader::None);
        let s = text(&out);
        assert!(s.contains("Content-Length: 2\r\n"));
        assert!(!s.contains("999"));
        assert!(!s.contains("upgrade"));
        assert!(!s.contains("chunked"));
        assert!(!s.contains("yesterday"));
    }

    #[test]
    fn unknown_status_empty_reason() {
        let out =
            serialize(&HttpResponse::new(299), false, date(), ConnHeader::None);
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
        let out = serialize(&resp, false, date(), ConnHeader::None);
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
    fn bodyless_statuses_carry_no_content() {
        // 1xx/204/304 MUST NOT carry content; a handler-set body is elided
        // and no Content-Length is emitted at all.
        for status in [100, 204, 304] {
            let resp = HttpResponse::new(status).body("diagnostic");
            let out = serialize(&resp, false, date(), ConnHeader::None);
            let s = text(&out);
            assert!(!s.contains("Content-Length"), "{status}: {s}");
            assert!(s.ends_with("\r\n\r\n"), "{status}: {s}");
        }
        // A 200 with an empty body still declares its length.
        let ok =
            serialize(&HttpResponse::new(200), false, date(), ConnHeader::None);
        assert!(text(&ok).contains("Content-Length: 0\r\n"));
    }
}
