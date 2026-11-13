//! `http`, an HTTP/1.1 **codec** over the [`net::server`](crate::net::server) protocol seam. It is a framer plus
//! request and response vocabulary, not a server, and the io_uring reactor stays in charge of every socket.
//!
//! [`protocol`](protocol()) builds the `accept`/`header`/`body` handler triple from an HTTP handler, and `httparse`
//! tokenizes the head. The other builders add deferred completion ([`protocol_deferrable`]), the reactor's per-request
//! fs facade (`protocol_fs`, with `uring-fs`) and streamed bodies ([`protocol_streaming`]), none of them needing a
//! reactor extension. `Expect: 100-continue` is two messages, the head alone and then the body against the stashed
//! head.
//!
//! The request-smuggling screens answer before a handler runs. A duplicate `Content-Length`, a `Transfer-Encoding`
//! whose `chunked` is absent, repeated or not last, TE on HTTP/1.0, and a missing (HTTP/1.1) or repeated `Host` are
//! 400, and codings before a final `chunked` are 501. A `Content-Length` beside `TE: chunked` is ignored (RFC 9112 sec.
//! 6.3), and the reply closes the connection. On the write side the codec drops the headers it writes itself and any
//! name or value that could split a response.
//!
//! A buffered body is bounded by [`HttpConfig::max_body`] and a streamed one by its builder's cap. The codec de-frames
//! only its own chunked layer, so a coding inside the body, such as `aws-chunked`, passes through byte for byte, and
//! trailers are surfaced ([`HttpRequest::trailers`]) but not interpreted. Bodies are not spliced
//! (`Framing::SpliceBody`), because a body carrying its own framing cannot be de-framed on the way past, and over kTLS
//! a splice moves one TLS record per op.

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
    HttpDeferPermit, HttpDeferred, HttpRequest, HttpStreamDeferred, HttpVerdict, Stage, protocol, protocol_deferrable,
    protocol_streaming,
};
#[cfg(feature = "uring-fs")]
pub use protocol::{protocol_fs, protocol_streaming_fs};
pub use response::{HttpResponse, IntoBytes, ScreenedHeader, header_pair_ok};

/// Pure codec entry points for the fuzz crate (`fuzz/`), built under `__fuzz` only and never part of the stable API.
/// The `http_frame`, `http_head` and `http_chunked` targets under `fuzz/fuzz_targets/` drive them.
#[cfg(feature = "__fuzz")]
pub mod fuzz {
    use std::borrow::Cow;

    use super::chunked::{self, ChunkScan};
    use super::framer::{HttpConfig, HttpConn, frame};
    use super::head::{HeadIndex, HeaderView, MAX_HEADERS, frame_facts, frame_facts_indexed, parse_head};
    use crate::net::Framing;

    /// Drive the framing state machine over `data`, feeding progressively longer prefixes so the resumable phases
    /// (chunk scan, head re-parse) run exactly as a drip-fed socket drives them. Returns the terminal verdict.
    pub fn drive_frame(data: &[u8]) -> Framing {
        let cfg = HttpConfig::default();
        let mut conn = HttpConn::new(());
        let mut verdict = Framing::More;
        for end in 0..=data.len() {
            verdict = frame(&data[..end], &mut conn, &cfg);
            if !matches!(verdict, Framing::More | Framing::MoreInMessage) {
                break;
            }
        }
        verdict
    }

    /// Run the head tokenizer and semantic rules over `data`, returning the head length, the expect-continue flag,
    /// whether the body verdict was `Ok`, and the **screened request-target**, so a fuzz target can assert on the
    /// screen and not only exercise it. `Err` is the status the connection dies with.
    pub fn head_facts(data: &[u8]) -> Result<Option<(usize, bool, bool, &str)>, u16> {
        Ok(frame_facts(data)?.map(|f| (f.len, f.expects_continue, f.body.is_ok(), f.target)))
    }

    /// Whether the index the framer records for `data` describes the complete head at its front and rebuilds the same
    /// view a tokenize of that head gives, which is what dispatch relies on. `None` when `data` holds no complete head.
    pub fn index_agrees(data: &[u8]) -> Option<bool> {
        let mut index = HeadIndex::default();
        let len = frame_facts_indexed(data, &mut index).ok()??.len;
        let head = &data[..len];
        let mut viewed = [HeaderView::EMPTY; MAX_HEADERS];
        let mut parsed = [HeaderView::EMPTY; MAX_HEADERS];
        Some(index.view(head, &mut viewed) == parse_head(head, &mut parsed).ok().flatten())
    }

    /// Resumable chunk scan over a body region: `Ok(Some(extent))` once the message completes, `Ok(None)` for
    /// need-more, `Err(status)` for malformed or oversized input.
    pub fn chunk_scan(body: &[u8]) -> Result<Option<usize>, u16> {
        chunked::scan(body, &mut ChunkScan::default())
    }

    /// One-shot decode of a fully framed chunked body into its entity bytes and trailer fields.
    #[allow(clippy::result_unit_err)]
    pub fn chunk_decode(body: &[u8]) -> Result<(Cow<'_, [u8]>, Vec<HeaderView<'_>>), ()> {
        chunked::decode(body)
    }
}
