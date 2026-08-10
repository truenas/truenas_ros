//! Request-head analysis: `httparse` tokenizing plus the semantic checks the
//! tokenizer deliberately leaves to the server — body length, smuggling
//! rules, Host enforcement, keep-alive, `Expect`. Pure functions over byte
//! slices. The framer (to place message boundaries) calls [`frame_facts`] and
//! the glue (to build the [`HttpRequest`](super::HttpRequest) view) calls
//! [`parse_head`]; both run the same tokenizer and the same semantic rules
//! over the same header views, so the two can never disagree about what a
//! head means — [`frame_facts`] merely skips building the header index the
//! framer would throw away.

/// Header-count cap handed to `httparse`. S3 requests carry many `x-amz-*`
/// headers but AWS caps user metadata at 2 KiB total; 96 slots is comfortable
/// headroom, and overflow maps to 431 rather than a parse wedge.
pub(crate) const MAX_HEADERS: usize = 96;

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
    /// HTTP/1.0 — closes by default; persists only on `Connection: keep-alive`.
    Http10,
    /// HTTP/1.1 — persists by default; closes on `Connection: close`.
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

/// A completely tokenized request head, borrowed from the connection buffer.
/// (Its length is not carried: the glue always parses exactly the head bytes
/// the framer declared, so the span is the input itself.)
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Head<'a> {
    /// Request method, verbatim (`httparse` guarantees a valid token).
    pub method: &'a str,
    /// Request-target, verbatim.
    pub target: &'a str,
    /// Protocol version.
    pub version: Version,
    /// Headers in wire order.
    pub headers: Vec<HeaderView<'a>>,
}

/// The facts framing needs from a complete head — everything [`frame`]
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
    /// the `100-continue` expectation (RFC 9110 §10.1.1 forbids interim
    /// responses to HTTP/1.0 clients, which would parse one as final).
    pub expects_continue: bool,
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
        // The tokenizer only admits literal `HTTP/1.x` version strings, so
        // an HTTP/2 (or other) request line surfaces here, not below.
        Err(httparse::Error::Version) => return Err(505),
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

/// RFC 9112 §3.2: an HTTP/1.1 request without a `Host` field, or any request
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
///
/// `Ok(None)` means "need more bytes"; `Ok(Some(head))` is a complete head;
/// `Err(status)` is the response status the connection should die with.
pub(crate) fn parse_head(buf: &[u8]) -> Result<Option<Head<'_>>, u16> {
    let mut slots = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let Some((req, _len, version)) = tokenize(buf, &mut slots)? else {
        return Ok(None);
    };
    Ok(Some(Head {
        // Complete parses always carry method/path; treat absence as malformed
        // rather than panicking on a tokenizer contract we don't control.
        method: req.method.ok_or(400u16)?,
        target: req.path.ok_or(400u16)?,
        version,
        headers: req.headers.iter().map(view).collect(),
    }))
}

/// Tokenize a (possibly incomplete) request head into just the
/// [`FrameFacts`] the framer consumes — same rules as [`parse_head`], no
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

    /// The declared body framing, applying RFC 9112 §6.3's receiver rules
    /// plus the codec's own screens:
    ///
    /// - `Transfer-Encoding` with `chunked` as the sole coding → chunked; a
    ///   lone well-formed `Content-Length` sent alongside is **ignored** (TE
    ///   wins — the receiver rule; verified by wire capture, default
    ///   botocore-over-TLS sends exactly this pair, CL carrying the
    ///   *decoded* length);
    /// - codings before a final `chunked` (`gzip, chunked`) → 501 (framing
    ///   is determinable, the coding is unimplemented);
    /// - `chunked` missing, repeated, or non-final → 400 (body length
    ///   unknowable — the smuggling class);
    /// - `Transfer-Encoding` on HTTP/1.0 → 400 (RFC 9112 §6.1: treat the
    ///   framing as faulty);
    /// - multiple `Content-Length` values → 400 even when they agree (and
    ///   even alongside TE) — agreement is what a smuggling payload would
    ///   fake;
    /// - non-digit / overflowing `Content-Length` → 400;
    /// - neither header → `Known(0)` (no body).
    ///
    /// At runtime the framer reads this via [`FrameFacts`]; the method
    /// remains as the tests' oracle asserting the two paths agree.
    #[cfg(test)]
    pub fn body(&self) -> Result<BodyKind, u16> {
        body_from(self.views(), self.version)
    }

    /// Whether the client asked for a `100 Continue` interim response.
    ///
    /// True only for HTTP/1.1: RFC 9110 §10.1.1 says a server MUST ignore
    /// the expectation on an HTTP/1.0 request (and MUST NOT send interim
    /// responses to a 1.0 client that would parse one as final). `Expect` is
    /// a list-typed field, so the token is honored wherever it appears —
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
    /// (RFC 9110 §5.3 — repeated field lines are one combined list).
    pub fn keep_alive(&self) -> bool {
        match self.version {
            Version::Http11 => !has_token(self.views(), "connection", b"close"),
            Version::Http10 => {
                has_token(self.views(), "connection", b"keep-alive")
            }
        }
    }
}

/// Whether any comma-separated element of any `name` field line equals
/// `token` (ASCII case-insensitive) — the RFC 9110 §5.3 combined-list read
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
/// view sequence — one pass, no allocation. `Transfer-Encoding` is
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
                    // (RFC 9110 §5.6.1).
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
        // TE wins over a Content-Length sent alongside (the RFC 9112 §6.3
        // receiver rule) — but the CL must at least be well-formed; a
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

    fn complete(buf: &[u8]) -> Head<'_> {
        parse_head(buf).expect("parse ok").expect("head complete")
    }

    #[test]
    fn simple_get() {
        let h = complete(
            b"GET /bucket/key?list-type=2 HTTP/1.1\r\nHost: s\r\n\r\n",
        );
        assert_eq!(h.method, "GET");
        assert_eq!(h.target, "/bucket/key?list-type=2");
        assert_eq!(h.version, Version::Http11);
        assert_eq!(h.body(), Ok(BodyKind::Known(0)));
        assert!(h.keep_alive());
        assert_eq!(h.header("host"), Some(&b"s"[..]));
        assert_eq!(h.header("HOST"), Some(&b"s"[..]));
    }

    #[test]
    fn partial_then_complete() {
        let full = b"PUT /k HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\n";
        for cut in 0..full.len() {
            assert!(parse_head(&full[..cut]).expect("partial ok").is_none());
        }
        let facts = frame_facts(full).expect("parse ok").expect("complete");
        assert_eq!(facts.len, full.len());
        assert_eq!(complete(full).body(), Ok(BodyKind::Known(5)));
    }

    #[test]
    fn malformed_is_400() {
        assert_eq!(parse_head(b"GET\x00/ HTTP/1.1\r\n\r\n"), Err(400));
    }

    #[test]
    fn version_gate() {
        assert_eq!(parse_head(b"GET / HTTP/2.0\r\n\r\n"), Err(505));
        let h10 = complete(b"GET / HTTP/1.0\r\n\r\n");
        assert_eq!(h10.version, Version::Http10);
        assert!(!h10.keep_alive());
    }

    #[test]
    fn host_enforcement() {
        // HTTP/1.1 without Host: 400 (RFC 9112 §3.2).
        assert_eq!(parse_head(b"GET / HTTP/1.1\r\n\r\n"), Err(400));
        // HTTP/1.0 predates Host; absence is fine.
        assert!(parse_head(b"GET / HTTP/1.0\r\n\r\n").is_ok());
        // Duplicate Host: 400 on any version.
        assert_eq!(
            parse_head(b"GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n"),
            Err(400)
        );
        assert_eq!(
            parse_head(b"GET / HTTP/1.0\r\nHost: a\r\nHost: b\r\n\r\n"),
            Err(400)
        );
    }

    #[test]
    fn transfer_encoding_rules() {
        let body = |req: &[u8]| complete(req).body();
        // TE chunked alone: the chunked framing path.
        assert_eq!(
            body(b"PUT / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n"),
            Ok(BodyKind::Chunked)
        );
        // TE + CL together: TE wins, CL ignored — the shape default
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
        // TE on HTTP/1.0: faulty framing (RFC 9112 §6.1).
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
        let dup = complete(
            b"PUT / HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\nContent-Length: 3\r\n\r\n",
        );
        assert_eq!(dup.body(), Err(400));
        // Duplicate CL stays fatal even when TE would win the framing.
        let dup_te = complete(
            b"PUT / HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n",
        );
        assert_eq!(dup_te.body(), Err(400));
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

    #[test]
    fn expect_and_connection_tokens() {
        let h = complete(
            b"PUT / HTTP/1.1\r\nHost: h\r\nExpect: 100-Continue\r\nConnection: foo, Close\r\nContent-Length: 1\r\n\r\n",
        );
        assert!(h.expects_continue());
        assert!(!h.keep_alive());
        let h10 = complete(b"GET / HTTP/1.0\r\nConnection: Keep-Alive\r\n\r\n");
        assert!(h10.keep_alive());
    }

    #[test]
    fn list_fields_combine_across_lines() {
        // Connection tokens count on any field line (RFC 9110 §5.3).
        let h = complete(
            b"GET / HTTP/1.1\r\nHost: h\r\nConnection: upgrade\r\nConnection: close\r\n\r\n",
        );
        assert!(!h.keep_alive());
        let h10 = complete(
            b"GET / HTTP/1.0\r\nConnection: foo\r\nConnection: keep-alive\r\n\r\n",
        );
        assert!(h10.keep_alive());
        // Expect: honored as a list member or on a later field line.
        let list = complete(
            b"PUT / HTTP/1.1\r\nHost: h\r\nExpect: ext, 100-continue\r\nContent-Length: 1\r\n\r\n",
        );
        assert!(list.expects_continue());
        let second = complete(
            b"PUT / HTTP/1.1\r\nHost: h\r\nExpect: ext\r\nExpect: 100-continue\r\nContent-Length: 1\r\n\r\n",
        );
        assert!(second.expects_continue());
    }

    #[test]
    fn expect_ignored_on_http10() {
        // RFC 9110 §10.1.1: a 1.0 client can't parse an interim response.
        let h = complete(
            b"PUT / HTTP/1.0\r\nExpect: 100-continue\r\nContent-Length: 1\r\n\r\n",
        );
        assert!(!h.expects_continue());
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
            let head = complete(req);
            let facts = frame_facts(req).expect("parse ok").expect("complete");
            assert_eq!(facts.body, head.body());
            assert_eq!(facts.expects_continue, head.expects_continue());
        }
        // Error and partial verdicts agree too.
        assert_eq!(frame_facts(b"GET / HTTP/1.1\r\n\r\n").err(), Some(400));
        assert!(frame_facts(b"GET / HTT").expect("partial ok").is_none());
    }
}
