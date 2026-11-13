//! Request-head analysis: `httparse` tokenizing plus the semantic checks the tokenizer deliberately leaves to the
//! server - body length, smuggling rules, Host enforcement, keep-alive, `Expect`. Pure functions over byte slices. The
//! framer (to place message boundaries) calls [`frame_facts_indexed`], which tokenizes the head once and records where
//! its parts sit in a [`HeadIndex`]. The glue (to build the [`HttpRequest`](super::HttpRequest) view) calls
//! [`head_view`], which rebuilds the view from that index instead of tokenizing again, so the two can never disagree
//! about what a head means. [`parse_head`] is the full tokenize behind [`head_view`] for a head no index describes.

use std::mem::MaybeUninit;

/// Header-count cap handed to `httparse`. It admits about 130 short `x-amz-meta-*` fields, which a 2 KiB user-metadata
/// budget allows, on top of the auth, content and standard fields a signed request carries. The arrays it sizes are
/// transient stack frames (32 B a slot), and overflow answers 431 rather than wedging the parse.
pub(crate) const MAX_HEADERS: usize = 160;

/// How a request's body is framed on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BodyKind {
    /// `Content-Length` (or no body headers at all): exactly this many bytes.
    Known(usize),
    /// `Transfer-Encoding: chunked`: the length is discovered by walking the chunk stream
    /// ([`chunked`](super::chunked)).
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

/// One request header as sent: name (case as sent, `httparse`-validated token) and raw value bytes (leading/trailing
/// whitespace trimmed by the tokenizer, otherwise verbatim).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeaderView<'a> {
    /// Header field name.
    pub name: &'a str,
    /// Header field value, undecoded.
    pub value: &'a [u8],
}

impl HeaderView<'_> {
    /// The filler a caller uses to initialize a fixed `[HeaderView; N]` before [`parse_head`] overwrites the first `n`
    /// slots. Its targets are `'static`, so the array adopts whatever buffer lifetime the parse needs.
    pub(crate) const EMPTY: HeaderView<'static> = HeaderView { name: "", value: &[] };
}

/// A completely tokenized request head. Method and target borrow the connection buffer; the header index borrows a
/// fixed array the caller owns (so tokenizing a head allocates nothing). (Its length is not carried: the glue always
/// views exactly the head bytes the framer declared, so the span is the input itself.)
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Head<'a> {
    /// Request method, verbatim (`httparse` guarantees a valid token).
    pub method: &'a str,
    /// Request-target in origin form, undecoded. Screened and, for absolute-form, reduced by [`target_check`].
    pub target: &'a str,
    /// Protocol version.
    pub version: Version,
    /// Headers in wire order, borrowed from the caller's array.
    pub headers: &'a [HeaderView<'a>],
}

/// The facts framing needs from a complete head - everything [`frame`] consumes.
///
/// [`frame`]: super::framer::frame
pub(crate) struct FrameFacts<'a> {
    /// Bytes the head occupies, including the terminating CRLFCRLF.
    pub len: usize,
    /// The screened request-target, reduced to origin form, carried out so the fuzz seam (`http::fuzz::head_facts`) can
    /// assert on the screen. Only that `__fuzz` seam reads it, but the field stays unconditional because the struct's
    /// lifetime is borrowed through it alone.
    #[cfg_attr(not(feature = "__fuzz"), allow(dead_code))]
    pub target: &'a str,
    /// The declared body framing, or the status the connection should die with. Kept as a `Result` so the framer
    /// sequences its own cap checks (431 before the body verdict) exactly as it would with a full parse.
    pub body: Result<BodyKind, u16>,
    /// Whether the 100-continue dance applies: an HTTP/1.1 request carrying the `100-continue` expectation (RFC 9110
    /// sec. 10.1.1 forbids interim responses to HTTP/1.0 clients, which would parse one as final).
    pub expects_continue: bool,
}

/// Where one part of a head sits, as an offset from the front of the head.
#[derive(Debug, Clone, Copy)]
struct Span {
    at: u32,
    len: u32,
}

impl Span {
    /// Where `part` sits in `buf`, or `None` when it is not a slice of `buf` or does not fit the width.
    fn of(buf: &[u8], part: &[u8]) -> Option<Span> {
        // An empty part has no bytes to find, and the tokenizer does not promise that an empty value points into the
        // buffer.
        if part.is_empty() {
            return Some(Span { at: 0, len: 0 });
        }
        Some(Span {
            at: u32::try_from(buf.subslice_range(part)?.start).ok()?,
            len: u32::try_from(part.len()).ok()?,
        })
    }

    fn bytes(self, head: &[u8]) -> Option<&[u8]> {
        head.get(self.at as usize..)?.get(..self.len as usize)
    }

    fn text(self, head: &[u8]) -> Option<&str> {
        std::str::from_utf8(self.bytes(head)?).ok()
    }
}

/// Where the parts of one tokenized head sit, so the glue rebuilds the [`Head`] view without tokenizing the same bytes
/// again, once per request and once per window of a streamed body.
///
/// The parts are offsets from the front of the head because the head bytes move between framing and delivery, and an
/// offset still finds its part where a pointer would not.
///
/// The index describes the last head that tokenized complete. Only the framer's `Head` phase tokenizes, and a request
/// in the dance, mid-stream or parked keeps the connection in another phase, so no other head is tokenized before that
/// request's last dispatch. The length check in [`head_view`] is a tripwire behind that reasoning, so a new framer
/// phase that tokenizes has to keep it true.
#[derive(Debug, Default)]
pub(crate) struct HeadIndex {
    /// The head described, or `None` when none is.
    head: Option<IndexedHead>,
    /// Name and value of each header in wire order. The storage is reused from one head to the next, so a connection
    /// allocates it once.
    headers: Vec<(Span, Span)>,
    /// Set when a head is recorded and cleared by the first view, which debug builds check against a tokenize. Once per
    /// head and not per view, since a tokenize per streamed window slows dispatch enough to skew the timing tests.
    /// Atomic so the type is `Sync` in both builds.
    #[cfg(debug_assertions)]
    unchecked: std::sync::atomic::AtomicBool,
}

#[derive(Debug)]
struct IndexedHead {
    /// Length of the head the offsets were taken from.
    len: usize,
    method: Span,
    /// `None` is the `/` that [`target_check`] gives an absolute-form target with no path. That one is a literal, not a
    /// slice of the head.
    target: Option<Span>,
    version: Version,
}

impl HeadIndex {
    /// Where the tokenizer found each part of the head at the front of `buf`. `None` when a part cannot be placed,
    /// which leaves the index describing nothing, and [`head_view`] then tokenizes instead.
    fn place(
        &mut self,
        buf: &[u8],
        len: usize,
        req: &httparse::Request<'_, '_>,
        version: Version,
        target: &str,
    ) -> Option<IndexedHead> {
        self.headers.clear();
        for h in req.headers.iter() {
            self.headers
                .push((Span::of(buf, h.name.as_bytes())?, Span::of(buf, h.value)?));
        }
        let target = match Span::of(buf, target.as_bytes()) {
            Some(span) => Some(span),
            None if target == "/" => None,
            None => return None,
        };
        let method = Span::of(buf, req.method?.as_bytes())?;
        #[cfg(debug_assertions)]
        {
            *self.unchecked.get_mut() = true;
        }
        Some(IndexedHead {
            len,
            method,
            target,
            version,
        })
    }

    /// The head described, when `head` is that head by length.
    fn described(&self, head: &[u8]) -> Option<&IndexedHead> {
        self.head.as_ref().filter(|at| at.len == head.len())
    }

    /// The view of `head` rebuilt from the offsets, written through `headers`. `None` when the index does not describe
    /// `head`.
    pub(crate) fn view<'a, 'buf>(
        &self,
        head: &'buf [u8],
        headers: &'a mut [HeaderView<'buf>; MAX_HEADERS],
    ) -> Option<Head<'a>> {
        let at = self.described(head)?;
        let filled = headers.get_mut(..self.headers.len())?;
        for (dst, (name, value)) in filled.iter_mut().zip(&self.headers) {
            *dst = HeaderView {
                name: name.text(head)?,
                value: value.bytes(head)?,
            };
        }
        let view = Head {
            method: at.method.text(head)?,
            target: match at.target {
                Some(span) => span.text(head)?,
                None => "/",
            },
            version: at.version,
            headers: filled,
        };
        #[cfg(debug_assertions)]
        if self.unchecked.swap(false, std::sync::atomic::Ordering::Relaxed) {
            assert!(
                tokenizes_to(head, &view),
                "the head index disagrees with a parse of the same bytes"
            );
        }
        Some(view)
    }
}

/// Whether a tokenize of `head` gives `view`. Out of line so that its header arrays take stack only while it runs, and
/// not in every frame of [`HeadIndex::view`].
#[cfg(debug_assertions)]
#[inline(never)]
fn tokenizes_to(head: &[u8], view: &Head<'_>) -> bool {
    matches!(
        parse_head(head, &mut [HeaderView::EMPTY; MAX_HEADERS]),
        Ok(Some(ref parsed)) if parsed == view
    )
}

/// Whether `tok` is an `HTTP-version` (RFC 9110 sec. 2.5): the uppercase name `HTTP`, a slash, then one digit, a dot,
/// and one digit.
fn is_http_version(tok: &[u8]) -> bool {
    matches!(
        tok,
        [b'H', b'T', b'T', b'P', b'/', major, b'.', minor]
            if major.is_ascii_digit() && minor.is_ascii_digit()
    )
}

/// The status for a request line `httparse` rejected as `Error::Version`, which it raises for an unsupported version
/// like `HTTP/2.0` and for a malformed request line alike. Only a well-formed `HTTP/<DIGIT>.<DIGIT>` in the third field
/// of `request-line = method SP request-target SP HTTP-version` (RFC 9112 sec. 3) answers 505, since 505 tells the
/// client to retry at a version it may never have named. Anything else, including a version token after a space inside
/// the target, is 400. Leading empty lines are skipped as `httparse` skips them (RFC 9112 sec. 2.2).
///
/// `None` means the request line has not terminated yet. `httparse` raises `Error::Version` before the field is whole,
/// comparing against `HTTP/1.` a byte at a time (`httparse-1.10.1/src/lib.rs:782-788`), so deciding now would make the
/// status depend on TCP segmentation. The caller waits, bounded by
/// [`HttpConfig::max_head`](super::HttpConfig::max_head).
fn version_status(buf: &[u8]) -> Option<u16> {
    let mut buf = buf;
    while let [b'\r', b'\n', rest @ ..] | [b'\n', rest @ ..] = buf {
        buf = rest;
    }
    // `Error::Version` is only reachable once `method SP target SP` has been consumed, so the first CR/LF from here is
    // the request line's end.
    let line_end = buf.iter().position(|&b| b == b'\r' || b == b'\n')?;
    let mut fields = buf[..line_end].split(|&b| b == b' ');
    Some(match (fields.next(), fields.next(), fields.next(), fields.next()) {
        (Some(_), Some(_), Some(version), None) if is_http_version(version) => 505,
        _ => 400,
    })
}

/// Shared tokenize step, `httparse` plus the version and Host checks every caller applies. `Ok(None)` means more bytes
/// are needed, and `Err(status)` is the status the connection dies with (400 malformed or Host rules, 431 too many
/// headers, 505 unsupported version).
///
/// `slots` is uninitialized on purpose. httparse writes only the slots it fills, and initializing all `MAX_HEADERS`
/// would be a 5 KiB stack fill per head on the reactor thread.
#[allow(clippy::type_complexity)] // one parse's outputs, not an API
fn tokenize<'s, 'b>(
    buf: &'b [u8],
    slots: &'s mut [MaybeUninit<httparse::Header<'b>>; MAX_HEADERS],
) -> Result<Option<(httparse::Request<'s, 'b>, usize, Version, &'b str)>, u16> {
    let mut req = httparse::Request::new(&mut []);
    let len = match req.parse_with_uninit_headers(buf, &mut slots[..]) {
        Ok(httparse::Status::Complete(len)) => len,
        Ok(httparse::Status::Partial) => return Ok(None),
        Err(httparse::Error::TooManyHeaders) => return Err(431),
        // `httparse` reports both a real unsupported version and a malformed request line as `Error::Version`; separate
        // them (505 vs 400) - and only once the request line is whole, since the tokenizer raises the error before it
        // is (see `version_status`).
        Err(httparse::Error::Version) => match version_status(buf) {
            Some(status) => return Err(status),
            None => return Ok(None),
        },
        Err(_) => return Err(400),
    };
    let version = match req.version {
        Some(0) => Version::Http10,
        Some(1) => Version::Http11,
        _ => return Err(505),
    };
    let host = host_check(req.headers.iter().map(view), version)?;
    // Complete parses always carry method/path; treat absence as malformed rather than panicking on a tokenizer
    // contract we don't control.
    let (method, path) = match (req.method, req.path) {
        (Some(m), Some(p)) => (m, p),
        _ => return Err(400),
    };
    let target = target_check(method, path, host)?;
    Ok(Some((req, len, version, target)))
}

/// RFC 9112 sec. 3.2, which request-target forms an **origin** server serves and what the effective target is.
///
/// An absolute-form target carries its own authority, which sec. 3.2.1 says replaces `Host`. Left unchecked, two
/// authorities arrive in one request, and a front end routing on one and this server on the other disagree about what
/// the request names. So absolute-form is accepted (sec. 3.2.2) only when its authority *equals* `Host`, and is reduced
/// to its path so every handler sees one target shape. `userinfo` and an empty authority fall out as mismatches.
///
/// Refused are authority-form (`CONNECT`, for a proxy), `*` outside `OPTIONS`, an absolute-form with no path to reduce
/// to (`http://h?q`), and any other shape. `//host/path` is ordinary origin-form and passes through, so a consumer
/// re-parsing a target as a URI reference must not read that as an authority.
fn target_check<'b>(method: &str, target: &'b str, host: Option<&[u8]>) -> Result<&'b str, u16> {
    if target.starts_with('/') {
        return Ok(target); // origin-form: the shape this server serves
    }
    if target == "*" {
        // Asterisk-form is a request about the server itself, and OPTIONS is the only method that asks one.
        return if method == "OPTIONS" { Ok(target) } else { Err(400) };
    }
    let Some(rest) = strip_scheme(target) else {
        // Authority-form (`host:port`) or nonsense. The former is CONNECT's alone; this is an origin server, not a
        // proxy.
        return Err(400);
    };
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, path) = rest.split_at(end);
    match host {
        Some(h) if h.eq_ignore_ascii_case(authority.as_bytes()) => {}
        _ => return Err(400),
    }
    match path.as_bytes().first() {
        None => Ok("/"),
        Some(b'/') => Ok(path),
        _ => Err(400), // `?`/`#` with no path; see the doc above
    }
}

/// Strip a `scheme "://"` prefix, returning what follows. `None` when the target does not start with one - `scheme =
/// ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )`, RFC 3986 sec. 3.1, so a bare `host:80` is not one.
fn strip_scheme(target: &str) -> Option<&str> {
    let bytes = target.as_bytes();
    if !bytes.first().is_some_and(u8::is_ascii_alphabetic) {
        return None;
    }
    let end = bytes
        .iter()
        .position(|b| !(b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.')))?;
    target[end..].strip_prefix("://")
}

fn view<'b>(h: &httparse::Header<'b>) -> HeaderView<'b> {
    HeaderView {
        name: h.name,
        value: h.value,
    }
}

/// Whether `value` is a well-formed `Host`, `uri-host [ ":" port ]` per RFC 3986 sec. 3.2.2-3.2.3.
///
/// The point is what it excludes. `@`, SP, `/` and every control byte are outside `reg-name`, so a `userinfo`, a path
/// or a header-splitting byte cannot ride into the routing key. [`target_check`] compares an absolute-form authority
/// against this value, so an unchecked `Host` would let a malformed authority match itself. The empty `reg-name` is
/// refused too, since `target_check` relies on an empty authority never matching.
fn host_is_valid(value: &[u8]) -> bool {
    if value.is_empty() {
        return false;
    }
    // A `:` inside an IP-literal belongs to the address, not to a port.
    let (host, port) = match value.iter().rposition(|&b| b == b':') {
        Some(i) if !value[i..].contains(&b']') => (&value[..i], Some(&value[i + 1..])),
        _ => (value, None),
    };
    // `port = *DIGIT`; empty is legal (`host:`) and means the default.
    if let Some(port) = port
        && !port.iter().all(u8::is_ascii_digit)
    {
        return false;
    }
    if let Some(inner) = host.strip_prefix(b"[").and_then(|h| h.strip_suffix(b"]")) {
        // `IP-literal = "[" ( IPv6address / IPvFuture ) "]"`. Bound the character set rather than re-implementing the
        // address grammar: the job here is keeping a routing key free of delimiters, and a malformed address fails to
        // resolve on its own.
        return !inner.is_empty()
            && inner
                .iter()
                .all(|b| b.is_ascii_hexdigit() || matches!(b, b':' | b'.' | b'v' | b'V'));
    }
    // `reg-name = *( unreserved / pct-encoded / sub-delims )`.
    !host.is_empty()
        && host.iter().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'-' | b'.'
                        | b'_'
                        | b'~'
                        | b'%'
                        | b'!'
                        | b'$'
                        | b'&'
                        | b'\''
                        | b'('
                        | b')'
                        | b'*'
                        | b'+'
                        | b','
                        | b';'
                        | b'='
                )
        })
}

/// RFC 9112 sec. 3.2 makes an HTTP/1.1 request without a `Host` field, or any request with more than one, a 400. It is
/// enforced at tokenize time so such a request never reaches routing code that derives a name from `Host`. The value
/// must also be a valid `uri-host` (RFC 9110 sec. 7.2), or it is answered 400 rather than handed on.
fn host_check<'h>(headers: impl Iterator<Item = HeaderView<'h>>, version: Version) -> Result<Option<&'h [u8]>, u16> {
    let mut hosts = headers.filter(|h| h.name.eq_ignore_ascii_case("host"));
    match (hosts.next(), version) {
        (Some(_), _) if hosts.next().is_some() => Err(400),
        (Some(h), _) if !host_is_valid(h.value) => Err(400),
        (Some(h), _) => Ok(Some(h.value)),
        (None, Version::Http10) => Ok(None),
        (None, Version::Http11) => Err(400),
    }
}

/// Tokenize a (possibly incomplete) request head into the full [`Head`] view. The header index is written into
/// `headers`, which the caller owns, so the parse needs no heap allocation; the returned head borrows the first `n`
/// filled slots.
///
/// `Ok(None)` means "need more bytes"; `Ok(Some(head))` is a complete head;
/// `Err(status)` is the response status the connection should die with.
pub(crate) fn parse_head<'a, 'buf>(
    buf: &'buf [u8],
    headers: &'a mut [HeaderView<'buf>; MAX_HEADERS],
) -> Result<Option<Head<'a>>, u16> {
    let mut slots = [const { MaybeUninit::uninit() }; MAX_HEADERS];
    let Some((req, _len, version, target)) = tokenize(buf, &mut slots)? else {
        return Ok(None);
    };
    let n = req.headers.len();
    for (dst, h) in headers.iter_mut().zip(req.headers.iter()) {
        *dst = view(h);
    }
    Ok(Some(Head {
        // `tokenize` proved both present and screened the target's form.
        method: req.method.ok_or(400u16)?,
        target,
        version,
        headers: &headers[..n],
    }))
}

#[cfg(test)]
thread_local! {
    /// Heads [`head_view`] tokenized on this thread because no index described them.
    pub(crate) static REPARSED: std::cell::Cell<usize> =
        const { std::cell::Cell::new(0) };
}

/// The [`Head`] view of `head`, rebuilt from `index` when it describes these bytes and tokenized by [`parse_head`] when
/// it does not. Same verdicts as [`parse_head`]. A head the index describes but cannot rebuild is a codec bug and comes
/// back `Ok(None)`, which the glue answers as one.
///
/// The tokenize is called from here and not from inside the view, so that path stays as shallow as a bare
/// [`parse_head`]. It runs on a loom coroutine, whose whole stack is 32 KiB.
pub(crate) fn head_view<'a, 'buf>(
    index: &HeadIndex,
    head: &'buf [u8],
    headers: &'a mut [HeaderView<'buf>; MAX_HEADERS],
) -> Result<Option<Head<'a>>, u16> {
    if index.described(head).is_some() {
        return Ok(index.view(head, headers));
    }
    #[cfg(test)]
    REPARSED.with(|n| n.set(n.get() + 1));
    parse_head(head, headers)
}

/// Whether raw head bytes name the `HEAD` method. It skips empty lines before the request line as `httparse` does (RFC
/// 9112 sec. 2.2), or `\r\nHEAD ...` would be judged a non-HEAD and its farewell would carry a body the client reads as
/// the next response's head. Usable on heads no facts were parsed from.
pub(crate) fn method_is_head(mut head: &[u8]) -> bool {
    while let [b'\r', b'\n', rest @ ..] | [b'\n', rest @ ..] = head {
        head = rest;
    }
    head.starts_with(b"HEAD ")
}

/// [`frame_facts_indexed`] for a caller with no dispatch to follow. Those are the framer's 431 recheck on a connection
/// that is already dying, the tests and the fuzz seam.
pub(crate) fn frame_facts(buf: &[u8]) -> Result<Option<FrameFacts<'_>>, u16> {
    frame_facts_indexed(buf, &mut HeadIndex::default())
}

/// Tokenize a (possibly incomplete) request head into the [`FrameFacts`] the framer consumes - same rules as
/// [`parse_head`] - and record where its parts sit in `index` for [`head_view`]. Any verdict but a complete head leaves
/// `index` describing nothing.
pub(crate) fn frame_facts_indexed<'b>(buf: &'b [u8], index: &mut HeadIndex) -> Result<Option<FrameFacts<'b>>, u16> {
    index.head = None;
    let mut slots = [const { MaybeUninit::uninit() }; MAX_HEADERS];
    // The target's form is screened here too: the framer runs first, so a shape this server does not serve must die
    // before its body is sized.
    let Some((req, len, version, target)) = tokenize(buf, &mut slots)? else {
        return Ok(None);
    };
    index.head = index.place(buf, len, &req, version, target);
    Ok(Some(FrameFacts {
        len,
        target,
        body: body_from(req.headers.iter().map(view), version),
        expects_continue: version == Version::Http11
            && has_token(req.headers.iter().map(view), "expect", b"100-continue"),
    }))
}

impl Head<'_> {
    fn views(&self) -> impl Iterator<Item = HeaderView<'_>> {
        self.headers.iter().copied()
    }

    /// First value of `name` (ASCII case-insensitive), if present. (Semantic rules read *all* field lines; a first-line
    /// view is only a test convenience.)
    #[cfg(test)]
    pub fn header(&self, name: &str) -> Option<&[u8]> {
        self.headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(name))
            .map(|h| h.value)
    }

    /// The declared body framing, applying RFC 9112 sec. 6.3's receiver rules plus the codec's own screens.
    ///
    /// - `Transfer-Encoding` with `chunked` as the sole coding is chunked, and a lone well-formed `Content-Length` sent
    ///   alongside is **ignored** (TE wins, the receiver rule). A malformed one is still 400.
    /// - Codings before a final `chunked` (`gzip, chunked`) are 501, since the framing is determinable and the coding
    ///   is not implemented.
    /// - `chunked` missing, repeated, or not final is 400, since the body length is unknowable (the smuggling class).
    /// - `Transfer-Encoding` on HTTP/1.0 is 400 (RFC 9112 sec. 6.1 says to treat the framing as faulty).
    /// - Multiple `Content-Length` values are 400 even when they agree, and even alongside TE, since agreement is what
    ///   a smuggling payload would fake.
    /// - A non-digit or overflowing `Content-Length` is 400.
    /// - Neither header is `Known(0)`, no body.
    ///
    /// The framer reads the same [`body_from`] over the same views through [`FrameFacts`], so this is only the tests'
    /// cross-check, and `frame_facts_agrees_with_parse_head` states each verdict outright.
    #[cfg(test)]
    pub fn body(&self) -> Result<BodyKind, u16> {
        body_from(self.views(), self.version)
    }

    /// Whether the client asked for a `100 Continue` interim response.
    ///
    /// True only for HTTP/1.1, since RFC 9110 sec. 10.1.1 says a server MUST ignore the expectation on an HTTP/1.0
    /// request. `Expect` is list-typed, so the token counts on any field line and at any list position. The framer
    /// reads the same check through [`FrameFacts`], so this is the tests' cross-check.
    #[cfg(test)]
    pub fn expects_continue(&self) -> bool {
        self.version == Version::Http11 && has_token(self.views(), "expect", b"100-continue")
    }

    /// Whether the connection persists after this exchange, per the version default and any `Connection` tokens on any
    /// field line (RFC 9110 sec. 5.3). The glue reads [`response_disposition`](Self::response_disposition), and this
    /// remains the tests' oracle.
    #[cfg(test)]
    pub fn keep_alive(&self) -> bool {
        // `close` decides on both versions: RFC 9112 sec. 9.6 makes it a receiver obligation regardless of the version
        // default, so a 1.0 request carrying both tokens closes rather than persisting.
        if has_token(self.views(), "connection", b"close") {
            return false;
        }
        match self.version {
            Version::Http11 => true,
            Version::Http10 => has_token(self.views(), "connection", b"keep-alive"),
        }
    }

    /// Whether this head carried both a `Content-Length` and a `Transfer-Encoding` field. The codec lets the transfer
    /// coding win (RFC 9112 sec. 6.3), and a front end preferring the length would frame the same bytes differently,
    /// which is the CL.TE smuggling primitive. So the response glue closes the connection on a conflict, and no later
    /// request shares it with a smuggled prefix. The glue reads [`response_disposition`](Self::response_disposition),
    /// and this remains the tests' oracle.
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

    /// The two facts the response glue needs, `(keep_alive, cl_te_conflict)`, resolved in one pass over the headers.
    /// Equal to [`keep_alive`](Self::keep_alive) and [`cl_te_conflict`](Self::cl_te_conflict), which stay as the
    /// oracle.
    ///
    /// The `Connection` read open-codes `has_token`'s list grammar (comma split, OWS trim, case-fold) to stay
    /// single-pass, so a grammar change in `has_token` must land here too.
    /// `response_disposition_agrees_with_the_oracle` catches drift between the two.
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
        // `close` wins on both versions. RFC 9112 sec. 9.6 makes it a receiver obligation and not the 1.1 default's
        // negation, so an HTTP/1.0 request carrying `keep-alive` *and* `close` must close.
        let keep_alive = !conn_close
            && match self.version {
                Version::Http11 => true,
                Version::Http10 => conn_keep,
            };
        (keep_alive, has_cl && has_te)
    }
}

/// Whether any comma-separated element of any `name` field line equals `token` (ASCII case-insensitive) - the RFC 9110
/// sec. 5.3 combined-list read of a repeatable list-typed field.
fn has_token<'h>(headers: impl Iterator<Item = HeaderView<'h>>, name: &str, token: &[u8]) -> bool {
    headers.filter(|h| h.name.eq_ignore_ascii_case(name)).any(|h| {
        h.value
            .split(|&b| b == b',')
            .any(|t| t.trim_ascii().eq_ignore_ascii_case(token))
    })
}

/// The body-framing rules (documented on [`Head::body`]), over any header view sequence - one pass, no allocation.
/// `Transfer-Encoding` is list-typed, so codings combine across repeated field lines exactly like `Connection` tokens
/// do.
fn body_from<'h>(headers: impl Iterator<Item = HeaderView<'h>>, version: Version) -> Result<BodyKind, u16> {
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
                    // Empty list elements are parsed and ignored (RFC 9110 sec. 5.6.1).
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
        // TE wins over a Content-Length sent alongside (the RFC 9112 sec. 6.3 receiver rule) - but the CL must at least
        // be well-formed; a malformed one is a broken client, not a framing choice.
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

/// RFC 9110 `token` bytes - the field-name grammar. `httparse` enforces it on request header names; the codec applies
/// the same set to trailer names off the wire and to handler-emitted response header names, so the two sides cannot
/// disagree about which names are valid.
pub(crate) fn is_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.' | b'^' | b'_' | b'`' | b'|' | b'~'
        )
}

/// Whether a field value carries a byte a field line may not. RFC 9110 sec. 5.5 admits only field-vchar (VCHAR
/// `0x21..=0x7E`, obs-text `0x80..=0xFF`), SP and HTAB, so the CR, LF and NUL that split a field line, the other C0
/// controls and DEL are all refused. Applied to handler-emitted response values and to trailer values off the wire,
/// mirroring httparse's request-side header-value map.
pub(crate) fn has_field_break(value: &[u8]) -> bool {
    value.iter().any(|&b| (b < 0x20 && b != b'\t') || b == 0x7f)
}

/// Strict `Content-Length`: ASCII digits only, no sign, no whitespace beyond what the tokenizer already trimmed,
/// checked arithmetic.
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

    /// A `Host` whose value is not a valid `uri-host` is a 400 on every request shape (RFC 9110 sec. 7.2), including
    /// origin-form, which runs no authority comparison.
    #[test]
    fn a_malformed_host_is_refused_on_origin_form() {
        let status = |buf: &[u8]| {
            let mut headers = [HeaderView::EMPTY; MAX_HEADERS];
            parse_head(buf, &mut headers).err()
        };

        for h in [
            "",
            "\t",
            "u:p@evil.example",
            "a b",
            "bucket/evil",
            "good:notaport",
            "good:8080x",
            "[not hex]",
            "[]",
        ] {
            let req = format!("GET /k HTTP/1.1\r\nHost: {h}\r\n\r\n");
            assert_eq!(status(req.as_bytes()), Some(400), "Host: {h:?}");
        }

        // And the shapes that must keep working.
        for h in [
            "good",
            "good.example",
            "good.example:8080",
            "good.example:",
            "under_score",
            "xn--bcher-kva.example",
            "192.0.2.1:443",
            "[::1]",
            "[::1]:8080",
            "[v7.deadbeef]",
            "pct%20encoded",
        ] {
            let req = format!("GET /k HTTP/1.1\r\nHost: {h}\r\n\r\n");
            assert_eq!(status(req.as_bytes()), None, "Host: {h:?} must serve");
        }
    }
    use super::*;

    /// Parse a complete head and run `f` against it. The header array must outlive the borrow, so the helper owns it
    /// and hands the head to a closure rather than returning it.
    fn complete<R>(buf: &[u8], f: impl FnOnce(&Head<'_>) -> R) -> R {
        let mut headers: [HeaderView<'_>; MAX_HEADERS] = [HeaderView::EMPTY; MAX_HEADERS];
        let head = parse_head(buf, &mut headers).expect("parse ok").expect("head complete");
        f(&head)
    }

    #[test]
    fn metadata_heavy_request_fits_the_slots() {
        // AWS's 2 KiB metadata budget spread across 130 short keys - the worst legitimate S3 shape - must parse, not
        // 431 on slot count.
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
        complete(b"GET /bucket/key?list-type=2 HTTP/1.1\r\nHost: s\r\n\r\n", |h| {
            assert_eq!(h.method, "GET");
            assert_eq!(h.target, "/bucket/key?list-type=2");
            assert_eq!(h.version, Version::Http11);
            assert_eq!(h.body(), Ok(BodyKind::Known(0)));
            assert!(h.keep_alive());
            assert_eq!(h.header("host"), Some(&b"s"[..]));
            assert_eq!(h.header("HOST"), Some(&b"s"[..]));
        });
    }

    #[test]
    fn partial_then_complete() {
        let full = b"PUT /k HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\n";
        let mut headers: [HeaderView<'_>; MAX_HEADERS] = [HeaderView::EMPTY; MAX_HEADERS];
        for cut in 0..full.len() {
            assert!(parse_head(&full[..cut], &mut headers).expect("partial ok").is_none());
        }
        let facts = frame_facts(full).expect("parse ok").expect("complete");
        assert_eq!(facts.len, full.len());
        complete(full, |h| assert_eq!(h.body(), Ok(BodyKind::Known(5))));
    }

    #[test]
    fn malformed_is_400() {
        let mut headers: [HeaderView<'_>; MAX_HEADERS] = [HeaderView::EMPTY; MAX_HEADERS];
        assert_eq!(parse_head(b"GET\x00/ HTTP/1.1\r\n\r\n", &mut headers), Err(400));
    }

    #[test]
    fn version_gate() {
        let mut headers: [HeaderView<'_>; MAX_HEADERS] = [HeaderView::EMPTY; MAX_HEADERS];
        assert_eq!(parse_head(b"GET / HTTP/2.0\r\n\r\n", &mut headers), Err(505));
        complete(b"GET / HTTP/1.0\r\n\r\n", |h10| {
            assert_eq!(h10.version, Version::Http10);
            assert!(!h10.keep_alive());
        });
    }

    /// Which request-target forms an origin server serves. An absolute-form target carries a second authority, which
    /// must agree with `Host`, and is reduced to its path.
    #[test]
    fn request_target_forms() {
        let status = |buf: &[u8]| {
            let mut headers = [HeaderView::EMPTY; MAX_HEADERS];
            parse_head(buf, &mut headers).err()
        };

        // Origin-form, in every shape a client sends it.
        for t in ["/", "/b/k", "/b/k?list-type=2", "//evil.example/other"] {
            let req = format!("GET {t} HTTP/1.1\r\nHost: good\r\n\r\n");
            complete(req.as_bytes(), |h| {
                assert_eq!(h.target, t, "origin-form is passed through");
            });
        }

        // Absolute-form is accepted (RFC 9112 sec. 3.2.2 requires it) when its authority agrees with Host - which is
        // how sec. 3.2.1's "use the host information of the request-target" is honoured without a second routing key -
        // and is reduced to its path, so a handler sees one target shape whatever the client sent.
        for (t, want) in [
            ("http://good/b/k", "/b/k"),
            ("https://GOOD/b/k?q=1", "/b/k?q=1"),
            ("http://good", "/"),
            ("http://good/", "/"),
        ] {
            let req = format!("GET {t} HTTP/1.1\r\nHost: good\r\n\r\n");
            complete(req.as_bytes(), |h| {
                assert_eq!(h.target, want, "{t} must reduce to its path");
            });
        }

        // The differential itself: two authorities in one request.
        assert_eq!(
            status(b"GET http://evil/other HTTP/1.1\r\nHost: good\r\n\r\n"),
            Some(400),
            "an absolute-form authority that disagrees with Host must die"
        );
        // `userinfo` is forbidden to a sender (RFC 9110 sec. 4.2.1) and falls out of the same comparison, as does an
        // empty authority.
        for t in ["http://u@good/k", "http:///k", "http://good:8080/k"] {
            let req = format!("GET {t} HTTP/1.1\r\nHost: good\r\n\r\n");
            assert_eq!(status(req.as_bytes()), Some(400), "{t}");
        }

        // The same shapes matched by a Host that is equally malformed. The comparison alone does not catch these - it
        // is `host_check` validating the field value that does, which is also what covers origin-form, where no
        // comparison happens at all.
        for h in ["u:p@evil.example", "", "bucket/evil", "good:notaport"] {
            let req = format!("GET http://{h}/k HTTP/1.1\r\nHost: {h}\r\n\r\n");
            assert_eq!(
                status(req.as_bytes()),
                Some(400),
                "absolute-form {h:?} matching an equally malformed Host"
            );
        }

        // Asterisk-form is a question about the server, and OPTIONS is the only method that asks one.
        complete(b"OPTIONS * HTTP/1.1\r\nHost: good\r\n\r\n", |h| {
            assert_eq!(h.target, "*");
        });
        assert_eq!(status(b"GET * HTTP/1.1\r\nHost: good\r\n\r\n"), Some(400));

        // Authority-form belongs to CONNECT and a proxy; this is neither.
        for line in ["CONNECT evil:443 HTTP/1.1", "GET good:80 HTTP/1.1"] {
            let req = format!("{line}\r\nHost: good\r\n\r\n");
            assert_eq!(status(req.as_bytes()), Some(400), "{line}");
        }

        // The framer screens the same way, so a bad shape dies before its body is sized rather than after.
        assert_eq!(
            frame_facts(b"GET http://evil/k HTTP/1.1\r\nHost: good\r\n\r\n").err(),
            Some(400)
        );
    }

    #[test]
    fn malformed_request_line_is_400_not_505() {
        let status = |buf: &[u8]| {
            let mut headers = [HeaderView::EMPTY; MAX_HEADERS];
            parse_head(buf, &mut headers).err()
        };
        // A non-version token or a lowercase name where the version belongs is a malformed request line, not an
        // unsupported version: 400, so the client is not told to retry at a version it never used.
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

    /// The version verdict is a property of the request, not of how the socket cut it. `httparse` refuses `HTTP/2.0` at
    /// `HTTP/2`, before the field is whole, so every prefix must answer need-more or 505 and never 400.
    #[test]
    fn the_version_verdict_does_not_depend_on_segmentation() {
        for v in [&b"HTTP/2.0"[..], b"HTTP/0.9", b"HTTP/9.9"] {
            let mut buf = b"GET / ".to_vec();
            buf.extend_from_slice(v);
            buf.extend_from_slice(b"\r\nHost: h\r\n\r\n");
            // Every prefix answers either "need more" or 505 - never 400.
            for end in 1..=buf.len() {
                match frame_facts(&buf[..end]) {
                    Ok(None) => {}
                    Err(505) => {}
                    other => panic!("{v:?} at {end} bytes: {:?}", other.map(|o| o.map(|f| f.len))),
                }
            }
            // And the whole request still dies 505, not "need more".
            assert_eq!(frame_facts(&buf).err(), Some(505), "{v:?}");
        }
        // The control: byte soup where a version belongs is still 400 at every prefix that decides at all.
        let soup = b"GET / XYZZY\r\nHost: h\r\n\r\n";
        for end in 1..=soup.len() {
            match frame_facts(&soup[..end]) {
                Ok(None) | Err(400) => {}
                other => panic!("soup at {end} bytes: {:?}", other.map(|o| o.map(|f| f.len))),
            }
        }
        assert_eq!(frame_facts(soup).err(), Some(400));
    }

    #[test]
    fn host_enforcement() {
        let mut headers: [HeaderView<'_>; MAX_HEADERS] = [HeaderView::EMPTY; MAX_HEADERS];
        // HTTP/1.1 without Host: 400 (RFC 9112 sec. 3.2).
        assert_eq!(parse_head(b"GET / HTTP/1.1\r\n\r\n", &mut headers), Err(400));
        // HTTP/1.0 predates Host; absence is fine.
        assert!(parse_head(b"GET / HTTP/1.0\r\n\r\n", &mut headers).is_ok());
        // Duplicate Host: 400 on any version.
        assert_eq!(
            parse_head(b"GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n", &mut headers),
            Err(400)
        );
        assert_eq!(
            parse_head(b"GET / HTTP/1.0\r\nHost: a\r\nHost: b\r\n\r\n", &mut headers),
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
        // TE and CL together, TE wins and CL is ignored.
        assert_eq!(
            body(b"PUT / HTTP/1.1\r\nHost: h\r\nContent-Length: 100\r\nTransfer-Encoding: chunked\r\n\r\n"),
            Ok(BodyKind::Chunked)
        );
        // ...but a malformed CL alongside TE is a broken client.
        assert_eq!(
            body(b"PUT / HTTP/1.1\r\nHost: h\r\nContent-Length: 1x\r\nTransfer-Encoding: chunked\r\n\r\n"),
            Err(400)
        );
        // Codings before a final chunked: framing valid, coding unimplemented.
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
            body(b"PUT / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: gzip\r\n\r\n"),
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
        assert_eq!(body(b"PUT / HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n"), Err(400));
        // List semantics: codings combine across field lines; empty elements are ignored.
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
        assert_eq!(parse_content_length(b"18446744073709551615"), Some(usize::MAX));
    }

    // Head-grammar edge cases. Several assert screens the tokenizer (httparse) enforces rather than this module, so
    // they also guard against a parser upgrade quietly loosening them.

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
        // Obsolete line folding (RFC 9112 sec. 5.2) is rejected; here the folded value would otherwise reconstruct to a
        // Transfer-Encoding of "chunked", a hidden-header vector.
        assert_eq!(
            head_err(b"GET /t HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chun\r\n ked\r\n\r\n"),
            Some(400)
        );
    }

    #[test]
    fn header_field_spacing_is_rejected() {
        // Whitespace before the colon (RFC 9112 sec. 5.1) or before the first header name is rejected; both are classic
        // proxy-differential smuggling shapes.
        assert_eq!(
            head_err(b"GET / HTTP/1.1\r\nHost: a\r\nContent-Length : 5\r\n\r\n"),
            Some(400)
        );
        assert_eq!(
            head_err(b"GET / HTTP/1.1\r\nHost: a\r\nContent-Length\t: 5\r\n\r\n"),
            Some(400)
        );
        assert_eq!(head_err(b"GET / HTTP/1.1\r\n Host: a\r\n\r\n"), Some(400));
    }

    #[test]
    fn control_bytes_in_a_header_value_are_rejected() {
        // A bare CR, NUL, or other C0 control byte in a value is rejected -- any of them could split or truncate the
        // field line - while obs-text (0x80..=0xFF) is allowed.
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
        assert_eq!(head_err(b"GET / HTTP/1.1\r\nHost: a\r\n: v\r\n\r\n"), Some(400));
    }

    #[test]
    fn comma_list_content_length_is_rejected() {
        // A comma-separated Content-Length is rejected outright, even when the values agree: it is the shape that
        // desyncs a first-element-wins parser from a last-element-wins one.
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
        // More header lines than the parser has slots for answers 431 rather than failing some other way.
        let mut buf = b"GET /b/k HTTP/1.1\r\nHost: h\r\n".to_vec();
        for i in 0..MAX_HEADERS {
            buf.extend_from_slice(format!("x-h-{i}: v\r\n").as_bytes());
        }
        buf.extend_from_slice(b"\r\n");
        assert_eq!(head_err(&buf), Some(431));
    }

    #[test]
    fn request_target_byte_classes() {
        // A NUL or otherwise invalid-UTF-8 request target is rejected; a valid UTF-8 target (such as an S3 key) is
        // accepted, since it is exposed as a &str.
        assert_eq!(head_err(b"GET /a\x00b HTTP/1.1\r\nHost: h\r\n\r\n"), Some(400));
        assert_eq!(head_err(b"GET /a\xffb HTTP/1.1\r\nHost: h\r\n\r\n"), Some(400));
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
        // The one-pass method must equal the two individual walks across the keep-alive and CL/TE shapes that decide
        // the response disposition.
        let cases: &[&[u8]] = &[
            b"GET / HTTP/1.1\r\nHost: h\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: h\r\nConnection: keep-alive, foo\r\n\r\n",
            b"GET / HTTP/1.0\r\n\r\n",
            b"GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n",
            b"GET / HTTP/1.0\r\nConnection: close\r\n\r\n",
            b"GET / HTTP/1.0\r\nConnection: keep-alive, close\r\n\r\n",
            b"GET / HTTP/1.0\r\nConnection: close, keep-alive\r\n\r\n",
            b"GET / HTTP/1.0\r\nConnection: keep-alive\r\nConnection: close\r\n\r\n",
            b"PUT / HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n",
            b"PUT / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n",
            b"PUT / HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\n",
            b"PUT / HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\nConnection: close\r\nTransfer-Encoding: chunked\r\n\r\n",
            // The axes the open-coded read owns. Field names and list tokens match case-insensitively (RFC 9110 sec.
            // 5.3, sec. 5.1), and `close` decides anywhere in the combined list, even beside `keep-alive` on 1.1.
            b"GET / HTTP/1.1\r\nHost: h\r\nConnection: CLOSE\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: h\r\nconnection: Close\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: h\r\nConnection: keep-alive, close\r\n\r\n",
            b"GET / HTTP/1.0\r\nConnection: KEEP-ALIVE\r\n\r\n",
            b"GET / HTTP/1.0\r\nCONNECTION: Keep-Alive\r\n\r\n",
            b"PUT / HTTP/1.1\r\nHost: h\r\ncontent-length: 5\r\ntransfer-encoding: chunked\r\n\r\n",
        ];
        for c in cases {
            complete(c, |h| {
                assert_eq!(h.response_disposition(), (h.keep_alive(), h.cl_te_conflict()), "{c:?}");
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

    /// `Connection: close` closes on **both** versions (RFC 9112 sec. 9.6), so a 1.0 request carrying `keep-alive`
    /// alongside it does not persist.
    #[test]
    fn close_beats_keep_alive_on_http10_too() {
        for raw in [
            &b"GET / HTTP/1.0\r\nConnection: keep-alive, close\r\n\r\n"[..],
            &b"GET / HTTP/1.0\r\nConnection: close, keep-alive\r\n\r\n"[..],
            &b"GET / HTTP/1.0\r\nConnection: keep-alive\r\nConnection: close\r\n\r\n"[..],
        ] {
            complete(raw, |h| {
                assert!(!h.keep_alive(), "{raw:?}");
                assert!(!h.response_disposition().0, "{raw:?}");
            });
        }
        // The 1.1 twin, as the control: it already closed on this input, and the two must not disagree.
        complete(
            b"GET / HTTP/1.1\r\nHost: h\r\nConnection: keep-alive, close\r\n\r\n",
            |h| assert!(!h.keep_alive()),
        );
        // And plain `keep-alive` on 1.0 still persists.
        complete(b"GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n", |h| {
            assert!(h.keep_alive())
        });
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
        // Each case states its verdict outright. `frame_facts` and `Head::body` both evaluate `body_from` over the same
        // views, so comparing them alone cannot fail, and the stated expectation is what gives this test a verdict.
        type Case = (&'static [u8], Result<BodyKind, u16>, bool);
        let reqs: &[Case] = &[
            (b"GET / HTTP/1.1\r\nHost: h\r\n\r\n", Ok(BodyKind::Known(0)), false),
            (
                b"PUT /k HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\n",
                Ok(BodyKind::Known(5)),
                false,
            ),
            (
                b"PUT /k HTTP/1.1\r\nHost: h\r\nExpect: 100-continue\r\nContent-Length: 3\r\n\r\n",
                Ok(BodyKind::Known(3)),
                true,
            ),
            (
                b"PUT /k HTTP/1.0\r\nExpect: 100-continue\r\nContent-Length: 3\r\n\r\n",
                Ok(BodyKind::Known(3)),
                false,
            ),
            (
                b"PUT / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n",
                Ok(BodyKind::Chunked),
                false,
            ),
            // The three verdicts the rules produce that no case above reaches: TE wins over a lone well-formed CL, a
            // repeated CL is the smuggling class, and a coding before `chunked` is framing this codec can place but not
            // decode.
            (
                b"PUT / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n",
                Ok(BodyKind::Chunked),
                false,
            ),
            (
                b"PUT /k HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\n",
                Err(400),
                false,
            ),
            (
                b"PUT / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: gzip, chunked\r\n\r\n",
                Err(501),
                false,
            ),
        ];
        for (req, body, expects) in reqs {
            complete(req, |head| {
                let facts = frame_facts(req).expect("parse ok").expect("complete");
                assert_eq!(facts.body, *body, "{req:?}");
                assert_eq!(facts.expects_continue, *expects, "{req:?}");
                assert_eq!(facts.body, head.body(), "{req:?}");
                assert_eq!(facts.expects_continue, head.expects_continue(), "{req:?}");
            });
        }
        // Error and partial verdicts agree too.
        assert_eq!(frame_facts(b"GET / HTTP/1.1\r\n\r\n").err(), Some(400));
        assert!(frame_facts(b"GET / HTT").expect("partial ok").is_none());
    }

    /// The view rebuilt from the index is the view a tokenize gives, over the shapes where an offset could go wrong.
    /// Those are a target reduced from absolute-form (a slice of the target, or a literal that is not in the head at
    /// all), an empty value, empty lines ahead of the request line, no headers, and body bytes behind the head.
    #[test]
    fn the_index_rebuilds_the_view_a_tokenize_gives() {
        let cases: &[&[u8]] = &[
            b"GET / HTTP/1.1\r\nHost: h\r\n\r\n",
            b"GET /k?a=b HTTP/1.1\r\nHost: h\r\nX-Empty:\r\nX-A: 1\r\n\r\n",
            b"GET http://h/k HTTP/1.1\r\nHost: h\r\n\r\n",
            b"GET http://h HTTP/1.1\r\nHost: h\r\n\r\n",
            b"OPTIONS * HTTP/1.1\r\nHost: h\r\n\r\n",
            b"\r\n\r\nHEAD /k HTTP/1.1\r\nhost:  h  \r\n\r\n",
            b"GET / HTTP/1.0\r\n\r\n",
            b"PUT /k HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\nhello",
        ];
        for buf in cases {
            let mut index = HeadIndex::default();
            let len = frame_facts_indexed(buf, &mut index)
                .expect("parse ok")
                .expect("complete")
                .len;
            let head = &buf[..len];
            let mut viewed = [HeaderView::EMPTY; MAX_HEADERS];
            let mut parsed = [HeaderView::EMPTY; MAX_HEADERS];
            let view = index.view(head, &mut viewed);
            assert!(view.is_some(), "no index for {buf:?}");
            assert_eq!(view, parse_head(head, &mut parsed).expect("parse ok"), "{buf:?}");
        }
    }

    /// An index serves only the head it was taken from. Bytes of another length are tokenized instead, and a tokenize
    /// that does not end in a complete head leaves nothing behind to view through.
    #[test]
    fn an_index_describes_only_the_head_it_was_taken_from() {
        let a = b"GET /a HTTP/1.1\r\nHost: h\r\n\r\n";
        let b = b"GET /other HTTP/1.1\r\nHost: h\r\n\r\n";
        let mut index = HeadIndex::default();
        frame_facts_indexed(a, &mut index).expect("parse ok");
        let mut headers = [HeaderView::EMPTY; MAX_HEADERS];
        assert!(index.view(a, &mut headers).is_some());
        assert!(index.view(b, &mut headers).is_none());

        // The fallback serves the bytes in hand, not the head indexed.
        let before = REPARSED.get();
        let head = head_view(&index, b, &mut headers).expect("parse ok").expect("complete");
        assert_eq!(head.target, "/other");
        assert_eq!(REPARSED.get(), before + 1);

        for undone in [&b"GET /a HTT"[..], &b"GET /a HTTP/1.1\r\n\r\n"[..]] {
            frame_facts_indexed(a, &mut index).expect("parse ok");
            let _ = frame_facts_indexed(undone, &mut index);
            assert!(index.view(a, &mut headers).is_none(), "{undone:?}");
        }
    }
}
