//! Request-head analysis: `httparse` tokenizing plus the semantic checks the
//! tokenizer deliberately leaves to the server - body length, smuggling
//! rules, Host enforcement, keep-alive, `Expect`. Pure functions over byte
//! slices. The framer (to place message boundaries) calls [`frame_facts`] and
//! the glue (to build the [`HttpRequest`](super::HttpRequest) view) calls
//! [`parse_head`]; both run the same tokenizer and the same semantic rules
//! over the same header views, so the two can never disagree about what a
//! head means - [`frame_facts`] merely skips building the header index the
//! framer would throw away.

/// Header-count cap handed to `httparse`. Sized for S3: AWS caps user
/// metadata at 2 KiB total, but short keys can spread that budget across
/// ~130 `x-amz-meta-*` fields, on top of the auth/content/standard fields a
/// signed request carries - so 96 slots rejected requests inside AWS's own
/// limits. 160 covers the worst legitimate shape with headroom (the arrays
/// this sizes are transient stack frames, 32 B a slot), and overflow maps
/// to 431 rather than a parse wedge.
pub(crate) const MAX_HEADERS: usize = 160;

/// How a request's body is framed on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BodyKind {
    /// `Content-Length` (or no body headers at all): exactly this many bytes.
    Known(usize),
    /// `Transfer-Encoding: chunked`: the length is discovered by walking the
    /// chunk stream ([`chunked`](super::chunked)).
    Chunked,
}

/// HTTP version of a parsed request head.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Version {
    /// HTTP/1.0 - closes by default; persists only on `Connection: keep-alive`.
    Http10,
    /// HTTP/1.1 - persists by default; closes on `Connection: close`.
    Http11,
}

/// One request header as sent: name (case as sent, `httparse`-validated
/// token) and raw value bytes (leading/trailing whitespace trimmed by the
/// tokenizer, otherwise verbatim).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeaderView<'a> {
    /// Header field name.
    pub name: &'a str,
    /// Header field value, undecoded.
    pub value: &'a [u8],
}

impl HeaderView<'_> {
    /// The filler a caller uses to initialize a fixed `[HeaderView; N]` before
    /// [`parse_head`] overwrites the first `n` slots. Its targets are
    /// `'static`, so the array adopts whatever buffer lifetime the parse needs.
    pub(crate) const EMPTY: HeaderView<'static> = HeaderView {
        name: "",
        value: &[],
    };
}

/// A completely tokenized request head. Method and target borrow the
/// connection buffer; the header index borrows a fixed array the caller owns
/// (so tokenizing a head allocates nothing). (Its length is not carried: the
/// glue always parses exactly the head bytes the framer declared, so the span
/// is the input itself.)
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Head<'a> {
    /// Request method, verbatim (`httparse` guarantees a valid token).
    pub method: &'a str,
    /// Request-target, verbatim.
    pub target: &'a str,
    /// Protocol version.
    pub version: Version,
    /// Headers in wire order, borrowed from the caller's array.
    pub headers: &'a [HeaderView<'a>],
}

/// The facts framing needs from a complete head - everything [`frame`]
/// consumes, computed without allocating the header index [`parse_head`]
/// builds (the framer would discard it unread).
///
/// [`frame`]: super::framer::frame
pub(crate) struct FrameFacts {
    /// Bytes the head occupies, including the terminating CRLFCRLF.
    pub len: usize,
    /// The declared body framing, or the status the connection should die
    /// with. Kept as a `Result` so the framer sequences its own cap checks
    /// (431 before the body verdict) exactly as it would with a full parse.
    pub body: Result<BodyKind, u16>,
    /// Whether the 100-continue dance applies: an HTTP/1.1 request carrying
    /// the `100-continue` expectation (RFC 9110 sec. 10.1.1 forbids interim
    /// responses to HTTP/1.0 clients, which would parse one as final).
    pub expects_continue: bool,
}

/// Whether `tok` is an `HTTP-version` (RFC 9110 sec. 2.5): the uppercase name
/// `HTTP`, a slash, then one digit, a dot, and one digit.
fn is_http_version(tok: &[u8]) -> bool {
    matches!(
        tok,
        [b'H', b'T', b'T', b'P', b'/', major, b'.', minor]
            if major.is_ascii_digit() && minor.is_ascii_digit()
    )
}

/// The status for a request line `httparse` rejected as `Error::Version`. It
/// compares the eight version bytes against `HTTP/1.0` and `HTTP/1.1` and
/// rejects everything else the same way - a real but unsupported version
/// like `HTTP/2.0`, and the byte soup of a malformed request line alike.
/// Answering 505 for the latter tells the client to retry at a lower HTTP
/// version it never named, so read the version token off the request line
/// and answer 505 only when it is a well-formed `HTTP/<DIGIT>.<DIGIT>`.
fn version_status(buf: &[u8]) -> u16 {
    let line_end = buf
        .iter()
        .position(|&b| b == b'\r' || b == b'\n')
        .unwrap_or(buf.len());
    let line = &buf[..line_end];
    match line.iter().rposition(|&b| b == b' ') {
        Some(sp) if is_http_version(&line[sp + 1..]) => 505,
        _ => 400,
    }
}

/// Shared tokenize step: `httparse` plus the version and Host checks every
/// caller applies. `Ok(None)` means "need more bytes"; `Err(status)` is the
/// response status the connection should die with (400 malformed / Host
/// rules, 431 too many headers, 505 unsupported version).
fn tokenize<'s, 'b>(
    buf: &'b [u8],
    slots: &'s mut [httparse::Header<'b>; MAX_HEADERS],
) -> Result<Option<(httparse::Request<'s, 'b>, usize, Version)>, u16> {
    let mut req = httparse::Request::new(&mut slots[..]);
    let len = match req.parse(buf) {
        Ok(httparse::Status::Complete(len)) => len,
        Ok(httparse::Status::Partial) => return Ok(None),
        Err(httparse::Error::TooManyHeaders) => return Err(431),
        // `httparse` reports both a real unsupported version and a malformed
        // request line as `Error::Version`; separate them (505 vs 400).
        Err(httparse::Error::Version) => return Err(version_status(buf)),
        Err(_) => return Err(400),
    };
    let version = match req.version {
        Some(0) => Version::Http10,
        Some(1) => Version::Http11,
        _ => return Err(505),
    };
    host_check(req.headers.iter().map(view), version)?;
    Ok(Some((req, len, version)))
}

fn view<'b>(h: &httparse::Header<'b>) -> HeaderView<'b> {
    HeaderView {
        name: h.name,
        value: h.value,
    }
}

/// RFC 9112 sec. 3.2: an HTTP/1.1 request without a `Host` field, or any request
/// with more than one, MUST be answered 400. Enforced at tokenize time so a
/// Host-less request never reaches routing code (virtual-hosted S3 derives
/// the bucket from `Host`).
fn host_check<'h>(
    headers: impl Iterator<Item = HeaderView<'h>>,
    version: Version,
) -> Result<(), u16> {
    let mut hosts = headers.filter(|h| h.name.eq_ignore_ascii_case("host"));
    match (hosts.next(), version) {
        (Some(_), _) if hosts.next().is_some() => Err(400),
        (Some(_), _) | (None, Version::Http10) => Ok(()),
        (None, Version::Http11) => Err(400),
    }
}

/// Tokenize a (possibly incomplete) request head into the full [`Head`] view.
/// The header index is written into `headers`, which the caller owns, so the
/// parse needs no heap allocation; the returned head borrows the first `n`
/// filled slots.
///
/// `Ok(None)` means "need more bytes"; `Ok(Some(head))` is a complete head;
/// `Err(status)` is the response status the connection should die with.
pub(crate) fn parse_head<'a, 'buf>(
    buf: &'buf [u8],
    headers: &'a mut [HeaderView<'buf>; MAX_HEADERS],
) -> Result<Option<Head<'a>>, u16> {
    let mut slots = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let Some((req, _len, version)) = tokenize(buf, &mut slots)? else {
        return Ok(None);
    };
    let n = req.headers.len();
    for (dst, h) in headers.iter_mut().zip(req.headers.iter()) {
        *dst = view(h);
    }
    Ok(Some(Head {
        // Complete parses always carry method/path; treat absence as malformed
        // rather than panicking on a tokenizer contract we don't control.
        method: req.method.ok_or(400u16)?,
        target: req.path.ok_or(400u16)?,
        version,
        headers: &headers[..n],
    }))
}

/// Whether raw head bytes name the `HEAD` method. `httparse` skips empty
/// lines before the request line (RFC 9112 sec. 2.2 robustness), so this must
/// skip them too: judging the method from byte 0 would call `\r\nHEAD ...`
/// a non-HEAD, and its farewell would carry a body the client reads as the
/// next response's head. Usable on heads no facts were parsed from (the
/// malformed / missing-Host / bad-version failures), where the parsed
/// method does not exist.
pub(crate) fn method_is_head(mut head: &[u8]) -> bool {
    while let [b'\r', b'\n', rest @ ..] | [b'\n', rest @ ..] = head {
        head = rest;
    }
    head.starts_with(b"HEAD ")
}

/// Tokenize a (possibly incomplete) request head into just the
/// [`FrameFacts`] the framer consumes - same rules as [`parse_head`], no
/// header-index allocation.
pub(crate) fn frame_facts(buf: &[u8]) -> Result<Option<FrameFacts>, u16> {
    let mut slots = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let Some((req, len, version)) = tokenize(buf, &mut slots)? else {
        return Ok(None);
    };
    Ok(Some(FrameFacts {
        len,
        body: body_from(req.headers.iter().map(view), version),
        expects_continue: version == Version::Http11
            && has_token(
                req.headers.iter().map(view),
                "expect",
                b"100-continue",
            ),
    }))
}

impl Head<'_> {
    fn views(&self) -> impl Iterator<Item = HeaderView<'_>> {
        self.headers.iter().copied()
    }

    /// First value of `name` (ASCII case-insensitive), if present.
    /// (Semantic rules read *all* field lines; a first-line view is only a
    /// test convenience.)
    #[cfg(test)]
    pub fn header(&self, name: &str) -> Option<&[u8]> {
        self.headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(name))
            .map(|h| h.value)
    }

    /// The declared body framing, applying RFC 9112 sec. 6.3's receiver rules
    /// plus the codec's own screens:
    ///
    /// - `Transfer-Encoding` with `chunked` as the sole coding -> chunked; a
    ///   lone well-formed `Content-Length` sent alongside is **ignored** (TE
    ///   wins - the receiver rule; verified by wire capture, default
    ///   botocore-over-TLS sends exactly this pair, CL carrying the
    ///   *decoded* length);
    /// - codings before a final `chunked` (`gzip, chunked`) -> 501 (framing
    ///   is determinable, the coding is unimplemented);
    /// - `chunked` missing, repeated, or non-final -> 400 (body length
    ///   unknowable - the smuggling class);
    /// - `Transfer-Encoding` on HTTP/1.0 -> 400 (RFC 9112 sec. 6.1: treat the
    ///   framing as faulty);
    /// - multiple `Content-Length` values -> 400 even when they agree (and
    ///   even alongside TE) - agreement is what a smuggling payload would
    ///   fake;
    /// - non-digit / overflowing `Content-Length` -> 400;
    /// - neither header -> `Known(0)` (no body).
    ///
    /// At runtime the framer reads this via [`FrameFacts`]; the method
    /// remains as the tests' oracle asserting the two paths agree.
    #[cfg(test)]
    pub fn body(&self) -> Result<BodyKind, u16> {
        body_from(self.views(), self.version)
    }

    /// Whether the client asked for a `100 Continue` interim response.
    ///
    /// True only for HTTP/1.1: RFC 9110 sec. 10.1.1 says a server MUST ignore
    /// the expectation on an HTTP/1.0 request (and MUST NOT send interim
    /// responses to a 1.0 client that would parse one as final). `Expect` is
    /// a list-typed field, so the token is honored wherever it appears --
    /// any field line, any list position.
    ///
    /// At runtime the framer reads this via [`FrameFacts`]; the method
    /// remains as the tests' oracle asserting the two paths agree.
    #[cfg(test)]
    pub fn expects_continue(&self) -> bool {
        self.version == Version::Http11
            && has_token(self.views(), "expect", b"100-continue")
    }

    /// Whether the connection persists after this exchange, per the version
    /// default and any `Connection` header tokens. `Connection` is
    /// list-typed: tokens count no matter which field line carries them
    /// (RFC 9110 sec. 5.3 - repeated field lines are one combined list).
    ///
    /// At runtime the glue reads this via
    /// [`response_disposition`](Self::response_disposition); the method remains
    /// as the tests' oracle asserting the one-pass read agrees.
    #[cfg(test)]
    pub fn keep_alive(&self) -> bool {
        match self.version {
            Version::Http11 => !has_token(self.views(), "connection", b"close"),
            Version::Http10 => {
                has_token(self.views(), "connection", b"keep-alive")
            }
        }
    }

    /// Whether this head carried both a `Content-Length` and a
    /// `Transfer-Encoding` field. The codec resolves the pair by letting the
    /// transfer coding win, per the receiver rule in RFC 9112 section 6.3,
    /// and ignores the length. A front end that prefers the length instead
    /// would frame the same bytes with a different message boundary, and
    /// that difference is the CL.TE request smuggling primitive. The server
    /// keeps the coding preference for client compatibility, since botocore
    /// sends exactly this pair, and instead makes the exchange non
    /// pipelinable. The response glue forces the connection to close on a
    /// conflict, so no later request shares the connection with a smuggled
    /// prefix.
    ///
    /// At runtime the glue reads this via
    /// [`response_disposition`](Self::response_disposition); the method remains
    /// as the tests' oracle.
    #[cfg(test)]
    pub fn cl_te_conflict(&self) -> bool {
        let mut has_cl = false;
        let mut has_te = false;
        for h in self.views() {
            if h.name.eq_ignore_ascii_case("content-length") {
                has_cl = true;
            } else if h.name.eq_ignore_ascii_case("transfer-encoding") {
                has_te = true;
            }
        }
        has_cl && has_te
    }

    /// The two facts the response glue needs, resolved in a single pass over
    /// the header list: `(keep_alive, cl_te_conflict)`. Equivalent to
    /// [`keep_alive`](Self::keep_alive) and
    /// [`cl_te_conflict`](Self::cl_te_conflict) (kept as the oracle), computed
    /// together so `respond` walks the headers once rather than twice.
    ///
    /// The `Connection` read below open-codes `has_token`'s RFC 9110 sec. 5.3
    /// list grammar (comma split, OWS trim, case-fold) rather than calling
    /// it, so the walk stays single-pass; a grammar change in `has_token`
    /// must land here too, and `response_disposition_agrees_with_the_oracle`
    /// is the fence that catches drift between the two readers.
    pub fn response_disposition(&self) -> (bool, bool) {
        let mut conn_close = false;
        let mut conn_keep = false;
        let mut has_cl = false;
        let mut has_te = false;
        for h in self.views() {
            if h.name.eq_ignore_ascii_case("connection") {
                for t in h.value.split(|&b| b == b',') {
                    let t = t.trim_ascii();
                    if t.eq_ignore_ascii_case(b"close") {
                        conn_close = true;
                    } else if t.eq_ignore_ascii_case(b"keep-alive") {
                        conn_keep = true;
                    }
                }
            } else if h.name.eq_ignore_ascii_case("content-length") {
                has_cl = true;
            } else if h.name.eq_ignore_ascii_case("transfer-encoding") {
                has_te = true;
            }
        }
        let keep_alive = match self.version {
            Version::Http11 => !conn_close,
            Version::Http10 => conn_keep,
        };
        (keep_alive, has_cl && has_te)
    }
}

/// Whether any comma-separated element of any `name` field line equals
/// `token` (ASCII case-insensitive) - the RFC 9110 sec. 5.3 combined-list read
/// of a repeatable list-typed field.
fn has_token<'h>(
    headers: impl Iterator<Item = HeaderView<'h>>,
    name: &str,
    token: &[u8],
) -> bool {
    headers
        .filter(|h| h.name.eq_ignore_ascii_case(name))
        .any(|h| {
            h.value
                .split(|&b| b == b',')
                .any(|t| t.trim_ascii().eq_ignore_ascii_case(token))
        })
}

/// The body-framing rules (documented on [`Head::body`]), over any header
/// view sequence - one pass, no allocation. `Transfer-Encoding` is
/// list-typed, so codings combine across repeated field lines exactly like
/// `Connection` tokens do.
fn body_from<'h>(
    headers: impl Iterator<Item = HeaderView<'h>>,
    version: Version,
) -> Result<BodyKind, u16> {
    let mut te_any = false;
    let mut te_chunked = 0u32;
    let mut te_other = 0u32;
    let mut te_last_chunked = false;
    let mut length: Option<&[u8]> = None;
    let mut duplicate = false;
    for h in headers {
        if h.name.eq_ignore_ascii_case("transfer-encoding") {
            te_any = true;
            for t in h.value.split(|&b| b == b',') {
                let t = t.trim_ascii();
                if t.is_empty() {
                    // Empty list elements are parsed and ignored
                    // (RFC 9110 sec. 5.6.1).
                    continue;
                }
                if t.eq_ignore_ascii_case(b"chunked") {
                    te_chunked += 1;
                    te_last_chunked = true;
                } else {
                    te_other += 1;
                    te_last_chunked = false;
                }
            }
        } else if h.name.eq_ignore_ascii_case("content-length") {
            if length.is_some() {
                duplicate = true;
            } else {
                length = Some(h.value);
            }
        }
    }
    if duplicate {
        return Err(400);
    }
    if te_any {
        if version == Version::Http10 {
            return Err(400);
        }
        if te_chunked != 1 || !te_last_chunked {
            return Err(400);
        }
        // TE wins over a Content-Length sent alongside (the RFC 9112 sec. 6.3
        // receiver rule) - but the CL must at least be well-formed; a
        // malformed one is a broken client, not a framing choice.
        if length.is_some_and(|v| parse_content_length(v).is_none()) {
            return Err(400);
        }
        if te_other > 0 {
            return Err(501);
        }
        return Ok(BodyKind::Chunked);
    }
    let Some(value) = length else {
        return Ok(BodyKind::Known(0));
    };
    parse_content_length(value).map(BodyKind::Known).ok_or(400)
}

/// RFC 9110 `token` bytes - the field-name grammar. `httparse` enforces it
/// on request header names; the codec applies the same set to trailer names
/// off the wire and to handler-emitted response header names, so the two
/// sides cannot disagree about which names are valid.
pub(crate) fn is_token_byte(b: u8) -> bool {
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
}

/// Whether a field value carries a byte a field line may not. RFC 9110 sec. 5.5
/// admits only field-vchar (VCHAR `0x21..=0x7E` / obs-text `0x80..=0xFF`),
/// SP, and HTAB; every other byte is rejected - the CR/LF/NUL that split a
/// field line, and the rest of the C0 controls and DEL. Applied to
/// handler-emitted response values (which S3 echoes verbatim from
/// `x-amz-meta-*`) and to trailer values off the wire; mirrors httparse's
/// request-side header-value map.
pub(crate) fn has_field_break(value: &[u8]) -> bool {
    value.iter().any(|&b| (b < 0x20 && b != b'\t') || b == 0x7f)
}

/// Strict `Content-Length`: ASCII digits only, no sign, no whitespace beyond
/// what the tokenizer already trimmed, checked arithmetic.
fn parse_content_length(v: &[u8]) -> Option<usize> {
    if v.is_empty() {
        return None;
    }
    let mut n: usize = 0;
    for &b in v {
        if !b.is_ascii_digit() {
            return None;
        }
        n = n.checked_mul(10)?.checked_add(usize::from(b - b'0'))?;
    }
    Some(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parse a complete head and run `f` against it. The header array must
    /// outlive the borrow, so the helper owns it and hands the head to a
    /// closure rather than returning it.
    fn complete<R>(buf: &[u8], f: impl FnOnce(&Head<'_>) -> R) -> R {
        let mut headers: [HeaderView<'_>; MAX_HEADERS] =
            [HeaderView::EMPTY; MAX_HEADERS];
        let head = parse_head(buf, &mut headers)
            .expect("parse ok")
            .expect("head complete");
        f(&head)
    }

    #[test]
    fn metadata_heavy_request_fits_the_slots() {
        // AWS's 2 KiB metadata budget spread across 130 short keys - the
        // worst legitimate S3 shape - must parse, not 431 on slot count.
        let mut req = b"PUT /b/k HTTP/1.1\r\nHost: h\r\n".to_vec();
        for i in 0..130 {
            req.extend_from_slice(format!("x-amz-meta-{i}: v\r\n").as_bytes());
        }
        req.extend_from_slice(b"\r\n");
        let facts = frame_facts(&req).expect("parses").expect("complete");
        assert_eq!(facts.len, req.len());
    }

    #[test]
    fn simple_get() {
        complete(
            b"GET /bucket/key?list-type=2 HTTP/1.1\r\nHost: s\r\n\r\n",
            |h| {
                assert_eq!(h.method, "GET");
                assert_eq!(h.target, "/bucket/key?list-type=2");
                assert_eq!(h.version, Version::Http11);
                assert_eq!(h.body(), Ok(BodyKind::Known(0)));
                assert!(h.keep_alive());
                assert_eq!(h.header("host"), Some(&b"s"[..]));
                assert_eq!(h.header("HOST"), Some(&b"s"[..]));
            },
        );
    }

    #[test]
    fn partial_then_complete() {
        let full = b"PUT /k HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\n";
        let mut headers: [HeaderView<'_>; MAX_HEADERS] =
            [HeaderView::EMPTY; MAX_HEADERS];
        for cut in 0..full.len() {
            assert!(
                parse_head(&full[..cut], &mut headers)
                    .expect("partial ok")
                    .is_none()
            );
        }
        let facts = frame_facts(full).expect("parse ok").expect("complete");
        assert_eq!(facts.len, full.len());
        complete(full, |h| assert_eq!(h.body(), Ok(BodyKind::Known(5))));
    }

    #[test]
    fn malformed_is_400() {
        let mut headers: [HeaderView<'_>; MAX_HEADERS] =
            [HeaderView::EMPTY; MAX_HEADERS];
        assert_eq!(
            parse_head(b"GET\x00/ HTTP/1.1\r\n\r\n", &mut headers),
            Err(400)
        );
    }

    #[test]
    fn version_gate() {
        let mut headers: [HeaderView<'_>; MAX_HEADERS] =
            [HeaderView::EMPTY; MAX_HEADERS];
        assert_eq!(
            parse_head(b"GET / HTTP/2.0\r\n\r\n", &mut headers),
            Err(505)
        );
        complete(b"GET / HTTP/1.0\r\n\r\n", |h10| {
            assert_eq!(h10.version, Version::Http10);
            assert!(!h10.keep_alive());
        });
    }

    #[test]
    fn malformed_request_line_is_400_not_505() {
        let status = |buf: &[u8]| {
            let mut headers = [HeaderView::EMPTY; MAX_HEADERS];
            parse_head(buf, &mut headers).err()
        };
        // A non-version token or a lowercase name where the version belongs
        // is a malformed request line, not an unsupported version: 400, so
        // the client is not told to retry at a version it never used.
        assert_eq!(status(b"GET / XYZZY\r\nHost: h\r\n\r\n"), Some(400));
        assert_eq!(status(b"GET / http/1.1\r\nHost: h\r\n\r\n"), Some(400));
        // A well-formed but unsupported version keeps its 505.
        for v in [&b"HTTP/2.0"[..], b"HTTP/9.9", b"HTTP/1.2"] {
            let mut buf = b"GET / ".to_vec();
            buf.extend_from_slice(v);
            buf.extend_from_slice(b"\r\nHost: h\r\n\r\n");
            assert_eq!(status(&buf), Some(505), "{v:?}");
        }
    }

    #[test]
    fn host_enforcement() {
        let mut headers: [HeaderView<'_>; MAX_HEADERS] =
            [HeaderView::EMPTY; MAX_HEADERS];
        // HTTP/1.1 without Host: 400 (RFC 9112 sec. 3.2).
        assert_eq!(
            parse_head(b"GET / HTTP/1.1\r\n\r\n", &mut headers),
            Err(400)
        );
        // HTTP/1.0 predates Host; absence is fine.
        assert!(parse_head(b"GET / HTTP/1.0\r\n\r\n", &mut headers).is_ok());
        // Duplicate Host: 400 on any version.
        assert_eq!(
            parse_head(
                b"GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n",
                &mut headers
            ),
            Err(400)
        );
        assert_eq!(
            parse_head(
                b"GET / HTTP/1.0\r\nHost: a\r\nHost: b\r\n\r\n",
                &mut headers
            ),
            Err(400)
        );
    }

    #[test]
    fn transfer_encoding_rules() {
        let body = |req: &[u8]| complete(req, |h| h.body());
        // TE chunked alone: the chunked framing path.
        assert_eq!(
            body(b"PUT / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n"),
            Ok(BodyKind::Chunked)
        );
        // TE + CL together: TE wins, CL ignored - the shape default
        // botocore-over-TLS actually sends (captured 2026-08-07).
        assert_eq!(
            body(b"PUT / HTTP/1.1\r\nHost: h\r\nContent-Length: 100\r\nTransfer-Encoding: chunked\r\n\r\n"),
            Ok(BodyKind::Chunked)
        );
        // ...but a malformed CL alongside TE is a broken client.
        assert_eq!(
            body(b"PUT / HTTP/1.1\r\nHost: h\r\nContent-Length: 1x\r\nTransfer-Encoding: chunked\r\n\r\n"),
            Err(400)
        );
        // Codings before a final chunked: framing valid, coding
        // unimplemented.
        assert_eq!(
            body(b"PUT / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: gzip, chunked\r\n\r\n"),
            Err(501)
        );
        // Chunked non-final / absent / repeated: length unknowable.
        assert_eq!(
            body(b"PUT / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked, gzip\r\n\r\n"),
            Err(400)
        );
        assert_eq!(
            body(
                b"PUT / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: gzip\r\n\r\n"
            ),
            Err(400)
        );
        assert_eq!(
            body(b"PUT / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n"),
            Err(400)
        );
        assert_eq!(
            body(b"PUT / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding:\r\n\r\n"),
            Err(400)
        );
        // TE on HTTP/1.0: faulty framing (RFC 9112 sec. 6.1).
        assert_eq!(
            body(b"PUT / HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n"),
            Err(400)
        );
        // List semantics: codings combine across field lines; empty
        // elements are ignored.
        assert_eq!(
            body(b"PUT / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n"),
            Err(501)
        );
        assert_eq!(
            body(b"PUT / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked,\r\n\r\n"),
            Ok(BodyKind::Chunked)
        );
    }

    #[test]
    fn duplicate_content_length_rules() {
        complete(
            b"PUT / HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\nContent-Length: 3\r\n\r\n",
            |dup| assert_eq!(dup.body(), Err(400)),
        );
        // Duplicate CL stays fatal even when TE would win the framing.
        complete(
            b"PUT / HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n",
            |dup_te| assert_eq!(dup_te.body(), Err(400)),
        );
    }

    #[test]
    fn content_length_strictness() {
        for bad in [&b"+5"[..], b"-1", b"5x", b"", b"18446744073709551616"] {
            assert!(parse_content_length(bad).is_none(), "{bad:?}");
        }
        assert_eq!(parse_content_length(b"0"), Some(0));
        assert_eq!(
            parse_content_length(b"18446744073709551615"),
            Some(usize::MAX)
        );
    }

    // Head-grammar edge cases. Several assert screens the tokenizer
    // (httparse) enforces rather than this module, so they also guard against
    // a parser upgrade quietly loosening them.

    fn head_err(buf: &[u8]) -> Option<u16> {
        let mut headers = [HeaderView::EMPTY; MAX_HEADERS];
        parse_head(buf, &mut headers).err()
    }

    fn head_ok(buf: &[u8]) -> bool {
        let mut headers = [HeaderView::EMPTY; MAX_HEADERS];
        matches!(parse_head(buf, &mut headers), Ok(Some(_)))
    }

    #[test]
    fn obsolete_line_folding_is_rejected() {
        // Obsolete line folding (RFC 9112 sec. 5.2) is rejected; here the
        // folded value would otherwise reconstruct to a Transfer-Encoding of
        // "chunked", a hidden-header vector.
        assert_eq!(
            head_err(b"GET /t HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chun\r\n ked\r\n\r\n"),
            Some(400)
        );
    }

    #[test]
    fn header_field_spacing_is_rejected() {
        // Whitespace before the colon (RFC 9112 sec. 5.1) or before the first
        // header name is rejected; both are classic proxy-differential
        // smuggling shapes.
        assert_eq!(
            head_err(
                b"GET / HTTP/1.1\r\nHost: a\r\nContent-Length : 5\r\n\r\n"
            ),
            Some(400)
        );
        assert_eq!(
            head_err(
                b"GET / HTTP/1.1\r\nHost: a\r\nContent-Length\t: 5\r\n\r\n"
            ),
            Some(400)
        );
        assert_eq!(head_err(b"GET / HTTP/1.1\r\n Host: a\r\n\r\n"), Some(400));
    }

    #[test]
    fn control_bytes_in_a_header_value_are_rejected() {
        // A bare CR, NUL, or other C0 control byte in a value is rejected --
        // any of them could split or truncate the field line - while obs-text
        // (0x80..=0xFF) is allowed.
        let bad: &[&[u8]] = &[
            b"GET / HTTP/1.1\r\nHost: a\r\nX: v\rTransfer-Encoding: chunked\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: a\r\nX: a\x00b\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: a\r\nX: a\x01b\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: a\r\nX: a\x7fb\r\n\r\n",
        ];
        for b in bad {
            assert_eq!(head_err(b), Some(400), "{b:?}");
        }
        // obs-text is accepted (the value is bytes, never assumed UTF-8).
        assert!(head_ok(b"GET / HTTP/1.1\r\nHost: a\r\nX: \xc3\xa9\r\n\r\n"));
    }

    #[test]
    fn empty_header_name_is_rejected() {
        // A colon with no preceding name is not a valid field line.
        assert_eq!(
            head_err(b"GET / HTTP/1.1\r\nHost: a\r\n: v\r\n\r\n"),
            Some(400)
        );
    }

    #[test]
    fn comma_list_content_length_is_rejected() {
        // A comma-separated Content-Length is rejected outright, even when
        // the values agree: it is the shape that desyncs a first-element-wins
        // parser from a last-element-wins one.
        assert!(parse_content_length(b"5, 6").is_none());
        assert!(parse_content_length(b"0, 0").is_none());
    }

    #[test]
    fn duplicate_host_is_case_insensitive() {
        // Two Host lines differing only in case still count as duplicates.
        assert_eq!(
            head_err(b"GET /t HTTP/1.1\r\nhost: evil\r\nHost: good\r\n\r\n"),
            Some(400)
        );
    }

    #[test]
    fn header_slot_overflow_is_431() {
        // More header lines than the parser has slots for answers 431 rather
        // than failing some other way.
        let mut buf = b"GET /b/k HTTP/1.1\r\nHost: h\r\n".to_vec();
        for i in 0..MAX_HEADERS {
            buf.extend_from_slice(format!("x-h-{i}: v\r\n").as_bytes());
        }
        buf.extend_from_slice(b"\r\n");
        assert_eq!(head_err(&buf), Some(431));
    }

    #[test]
    fn request_target_byte_classes() {
        // A NUL or otherwise invalid-UTF-8 request target is rejected; a valid
        // UTF-8 target (such as an S3 key) is accepted, since it is exposed as
        // a &str.
        assert_eq!(
            head_err(b"GET /a\x00b HTTP/1.1\r\nHost: h\r\n\r\n"),
            Some(400)
        );
        assert_eq!(
            head_err(b"GET /a\xffb HTTP/1.1\r\nHost: h\r\n\r\n"),
            Some(400)
        );
        assert!(head_ok(b"GET /caf\xc3\xa9 HTTP/1.1\r\nHost: h\r\n\r\n"));
    }

    #[test]
    fn expect_and_connection_tokens() {
        complete(
            b"PUT / HTTP/1.1\r\nHost: h\r\nExpect: 100-Continue\r\nConnection: foo, Close\r\nContent-Length: 1\r\n\r\n",
            |h| {
                assert!(h.expects_continue());
                assert!(!h.keep_alive());
            },
        );
        complete(b"GET / HTTP/1.0\r\nConnection: Keep-Alive\r\n\r\n", |h10| {
            assert!(h10.keep_alive())
        });
    }

    #[test]
    fn response_disposition_agrees_with_the_oracle() {
        // The one-pass method must equal the two individual walks across the
        // keep-alive and CL/TE shapes that decide the response disposition.
        let cases: &[&[u8]] = &[
            b"GET / HTTP/1.1\r\nHost: h\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: h\r\nConnection: keep-alive, foo\r\n\r\n",
            b"GET / HTTP/1.0\r\n\r\n",
            b"GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n",
            b"GET / HTTP/1.0\r\nConnection: close\r\n\r\n",
            b"PUT / HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n",
            b"PUT / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n",
            b"PUT / HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\n",
            b"PUT / HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\nConnection: close\r\nTransfer-Encoding: chunked\r\n\r\n",
        ];
        for c in cases {
            complete(c, |h| {
                assert_eq!(
                    h.response_disposition(),
                    (h.keep_alive(), h.cl_te_conflict()),
                    "{c:?}"
                );
            });
        }
    }

    #[test]
    fn list_fields_combine_across_lines() {
        // Connection tokens count on any field line (RFC 9110 sec. 5.3).
        complete(
            b"GET / HTTP/1.1\r\nHost: h\r\nConnection: upgrade\r\nConnection: close\r\n\r\n",
            |h| assert!(!h.keep_alive()),
        );
        complete(
            b"GET / HTTP/1.0\r\nConnection: foo\r\nConnection: keep-alive\r\n\r\n",
            |h10| assert!(h10.keep_alive()),
        );
        // Expect: honored as a list member or on a later field line.
        complete(
            b"PUT / HTTP/1.1\r\nHost: h\r\nExpect: ext, 100-continue\r\nContent-Length: 1\r\n\r\n",
            |list| assert!(list.expects_continue()),
        );
        complete(
            b"PUT / HTTP/1.1\r\nHost: h\r\nExpect: ext\r\nExpect: 100-continue\r\nContent-Length: 1\r\n\r\n",
            |second| assert!(second.expects_continue()),
        );
    }

    #[test]
    fn expect_ignored_on_http10() {
        // RFC 9110 sec. 10.1.1: a 1.0 client can't parse an interim response.
        complete(
            b"PUT / HTTP/1.0\r\nExpect: 100-continue\r\nContent-Length: 1\r\n\r\n",
            |h| assert!(!h.expects_continue()),
        );
    }

    #[test]
    fn frame_facts_agrees_with_parse_head() {
        let reqs: &[&[u8]] = &[
            b"GET / HTTP/1.1\r\nHost: h\r\n\r\n",
            b"PUT /k HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\n",
            b"PUT /k HTTP/1.1\r\nHost: h\r\nExpect: 100-continue\r\nContent-Length: 3\r\n\r\n",
            b"PUT /k HTTP/1.0\r\nExpect: 100-continue\r\nContent-Length: 3\r\n\r\n",
            b"PUT / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n",
        ];
        for req in reqs {
            complete(req, |head| {
                let facts =
                    frame_facts(req).expect("parse ok").expect("complete");
                assert_eq!(facts.body, head.body());
                assert_eq!(facts.expects_continue, head.expects_continue());
            });
        }
        // Error and partial verdicts agree too.
        assert_eq!(frame_facts(b"GET / HTTP/1.1\r\n\r\n").err(), Some(400));
        assert!(frame_facts(b"GET / HTT").expect("partial ok").is_none());
    }
}
