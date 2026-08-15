//! `http` — an HTTP/1.1 **codec** over the [`net::server`](crate::net::server)
//! protocol seam. A framer plus request/response vocabulary; not a server —
//! the io_uring reactor stays in charge of every socket.
//!
//! # Design
//!
//! The module plugs into [`Protocol`](crate::net::server::Protocol) exactly
//! like a length-prefixed protocol would: [`protocol`](protocol()) builds the
//! `accept`/`header`/`body` handler triple from an HTTP-shaped handler you
//! supply. The head tokenizer is `httparse` (sans-io, allocation-free, the
//! same parser hyper embeds); everything above tokens is implemented here:
//!
//! - **Framing** (`framer`): a per-connection state machine mapping HTTP
//!   message boundaries onto [`Framing`](crate::net::server::Framing)
//!   verdicts — scan (`More`) until the head completes, then declare the
//!   body from `Content-Length`, or walk a `Transfer-Encoding: chunked`
//!   stream (`chunked`) until its terminal chunk lands.
//! - **`Expect: 100-continue`** as a two-message dance: the head is delivered
//!   as a zero-body message, the glue replies with raw interim bytes
//!   (`Response::Reply` sends verbatim), and the framer then frames the body
//!   as a second message against the stashed head. No reactor extension
//!   needed.
//! - **Deferred completion** ([`protocol_deferrable`]): a handler may
//!   **park** a request ([`HttpRequest::defer`]) while a worker thread
//!   resolves what it needs; the retained request is redelivered on the
//!   server thread — re-running the handler once state is warm
//!   ([`HttpDeferred::redrive`]) or serializing a worker-built response
//!   ([`HttpDeferred::reply`]) — so the reactor never blocks and response
//!   policy never runs off-thread. Rides the reactor's
//!   [`Response::Defer`](crate::net::server::Response::Defer) machinery.
//! - **Keep-alive**: HTTP/1.1 persists unless `Connection: close`; HTTP/1.0
//!   closes unless `Connection: keep-alive`. Close maps onto
//!   [`Response::ReplyClose`](crate::net::server::Response::ReplyClose) —
//!   the flush-then-close farewell the reactor already implements.
//! - **Serialization** (`response`): status line, headers, IMF-fixdate
//!   `Date`, automatic `Content-Length`, HEAD body elision — with
//!   [`HttpResponse::head_content_length`] the one way a handler may
//!   declare a length itself, honored only on a HEAD, where the protocol
//!   sends no bytes for it to contradict. Header names, values, and bodies
//!   are `Cow<'static, _>` — responses built from literals allocate nothing
//!   until serialization.
//! - **Hardening**: request-smuggling screens (duplicate `Content-Length` →
//!   400; `Transfer-Encoding` where `chunked` is absent, repeated, or
//!   non-final → 400; codings before a final `chunked` → 501; TE on
//!   HTTP/1.0 → 400; a lone `Content-Length` alongside `TE: chunked` is
//!   ignored — TE wins, RFC 9112 §6.3's receiver rule, and the shape real
//!   botocore requests have), `Host` enforcement (missing on HTTP/1.1, or
//!   duplicated → 400), head-size cap (431), body cap (413), chunk-line and
//!   trailer caps (400/431), version check (505). On the write side, the
//!   response-splitting guards: non-token header names and values with a
//!   byte outside RFC 9110's field-value grammar are dropped, out-of-range
//!   statuses become 500, and bodyless
//!   statuses (1xx/204/304) never carry content.
//!
//! # Scope (v1)
//!
//! `Content-Length` and `Transfer-Encoding: chunked` bodies, buffered inline
//! up to [`HttpConfig::max_body`] (for chunked, the *decoded* size, enforced
//! mid-stream; the wire form gets a fixed extra framing allowance). The
//! defaults are sized so head + body + allowance together fit the reactor's
//! own default message cap (raise them in step; see
//! [`HttpConfig::min_request_bytes`]).
//!
//! Chunked is not optional for an S3 front: verified by wire capture
//! (boto3 1.37.9, 2026-08-07), the default modern SDK PUTs over TLS with
//! `Transfer-Encoding: chunked` + `Content-Encoding: aws-chunked` and an
//! unsigned-payload trailer — sometimes with a `Content-Length` alongside
//! carrying the *decoded* length. This codec de-frames only its own layer:
//! the aws-chunked entity (chunk metadata and checksum trailer *inside* the
//! body) passes through byte-for-byte for the S3 band to decode. Genuine
//! HTTP trailer fields are parsed and surfaced ([`HttpRequest::trailers`])
//! but not interpreted. Large streamed bodies (`Framing::SpliceBody`) and
//! streaming sends are planned follow-ups on the same seam.
//!
//! The raw head block is preserved and handed to the handler verbatim
//! ([`HttpRequest::raw_head`]) for diagnostics; SigV4 canonicalizes from the
//! parsed header views — borrows into that same buffer, values as sent — not
//! by re-parsing the raw block, so the codec never gets between the S3 layer
//! and the wire.

mod chunked;
mod date;
mod framer;
mod head;
mod protocol;
mod response;

pub use date::HttpDate;
pub use framer::{HttpConfig, HttpConn};
pub use head::{HeaderView, Version};
pub use protocol::{
    protocol, protocol_deferrable, HttpDeferPermit, HttpDeferred, HttpRequest,
    HttpVerdict,
};
pub use response::{HttpResponse, IntoBytes};

/// Pure codec entry points exposed to the fuzz crate (`fuzz/`) under `__fuzz`
/// only — the `http` analogue of the net stack's `frame_step` re-export.
/// Never part of the stable API.
///
/// The targets under `fuzz/fuzz_targets/`: `http_frame` driving
/// [`fuzz::drive_frame`], `http_head` driving [`fuzz::head_facts`], and
/// `http_chunked` driving [`fuzz::chunk_scan`] then [`fuzz::chunk_decode`],
/// each asserting the codec's delivery-safety and agreement invariants —
/// seeded under `fuzz/corpus/` with the golden botocore shapes.
#[cfg(feature = "__fuzz")]
pub mod fuzz {
    use std::borrow::Cow;

    use super::chunked::{self, ChunkScan};
    use super::framer::{frame, HttpConfig, HttpConn};
    use super::head::{frame_facts, HeaderView};
    use crate::net::Framing;

    /// Drive the framing state machine over `data`, feeding progressively
    /// longer prefixes so the resumable phases (chunk scan, head re-parse) run
    /// exactly as a drip-fed socket drives them. Returns the terminal verdict.
    pub fn drive_frame(data: &[u8]) -> Framing {
        let cfg = HttpConfig::default();
        let mut conn = HttpConn::new(());
        let mut verdict = Framing::More;
        for end in 0..=data.len() {
            verdict = frame(&data[..end], &mut conn, &cfg);
            if !matches!(verdict, Framing::More) {
                break;
            }
        }
        verdict
    }

    /// Run the head tokenizer and semantic rules over `data`, returning the
    /// head length, the expect-continue flag, and whether the body verdict was
    /// `Ok` (the body enum itself stays crate-private); `Err` is the
    /// die-with status.
    pub fn head_facts(data: &[u8]) -> Result<Option<(usize, bool, bool)>, u16> {
        Ok(frame_facts(data)?
            .map(|f| (f.len, f.expects_continue, f.body.is_ok())))
    }

    /// Resumable chunk scan over a body region: `Ok(Some(extent))` once the
    /// message completes, `Ok(None)` for need-more, `Err(status)` for
    /// malformed or oversized input.
    pub fn chunk_scan(body: &[u8]) -> Result<Option<usize>, u16> {
        chunked::scan(body, &mut ChunkScan::default())
    }

    /// One-shot decode of a fully framed chunked body into its entity bytes
    /// and trailer fields.
    #[allow(clippy::result_unit_err)]
    pub fn chunk_decode(
        body: &[u8],
    ) -> Result<(Cow<'_, [u8]>, Vec<HeaderView<'_>>), ()> {
        chunked::decode(body)
    }
}
