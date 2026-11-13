//! The HTTP framing state machine, a per-connection [`Phase`] plus the pure [`frame`] step mapping accumulated bytes
//! onto [`Framing`] verdicts. Every decision lives here, so the step stays a pure function of
//! `(buffer, phase, config)`, fuzzable like the reactor's own `frame_step`.
//!
//! - **Single message**, the normal path. The head completes, the body length is declared, and one
//!   `Complete { header_len, body_len }` delivers both.
//! - **The 100-continue dance.** A head with `Expect: 100-continue` and a non-empty body is delivered alone with its
//!   bytes stashed in the phase, the glue sends the raw interim and advances the phase, and the framer then declares
//!   the body as a second message paired with the stash.
//! - **Chunked.** The extent is discovered, not declared. The framer keeps a resumable [`ChunkScan`] in the phase and
//!   answers `MoreInMessage` until the terminal chunk lands, then declares the whole wire extent, which the glue
//!   de-chunks. It composes with the dance, since boto3 sends `Expect` and `TE: chunked` together.
//! - **Streamed**, on a connection with a stream cap. The head goes out alone, then each chunk or window is its own
//!   message, so the body never sits in the buffer whole.
//!
//! Malformed input moves to [`Phase::Fail`] and delivers whatever is buffered as a degenerate message, so the glue
//! sends a real error response and flush-closes ([`Response::ReplyClose`]) rather than slamming the connection.

use crate::net::Framing;
#[cfg(doc)]
use crate::net::server::{Response, ServerConfig};

use super::chunked::{self, CHUNK_LINE_MAX, ChunkScan, TRAILER_LINE_MAX};
use super::head::{BodyKind, HeadIndex, frame_facts, frame_facts_indexed, method_is_head};

/// Fixed wire-overhead allowance for chunk framing on top of [`HttpConfig::max_body`]. A chunked message whose **wire**
/// extent exceeds `max_body + CHUNK_WIRE_OVERHEAD` fails 400 even while its decoded size is in bounds. Only
/// pathological framing (one-byte chunks, jumbo extensions) gets there, so it reads as abuse rather than content size,
/// hence 400 and not 413.
pub(crate) const CHUNK_WIRE_OVERHEAD: usize = 16 * 1024;

/// Codec limits. Both caps close the connection with a real status (431 or 413) rather than truncating.
///
/// The reactor's own whole-message cap ([`ServerConfig::max_request_bytes`]) closes a message past it with **no HTTP
/// farewell** ([`CloseReason::TooLarge`](crate::net::server::CloseReason)). Keep it at
/// [`HttpConfig::min_request_bytes`] or above so every over-cap request receives its 413 or 431. The defaults on both
/// sides compose exactly.
#[derive(Debug, Clone, Copy)]
pub struct HttpConfig {
    /// Maximum request-head size in bytes (request line, headers and terminator). Exceeding it answers
    /// `431 Request Header Fields Too Large` and closes.
    ///
    /// It bounds each head re-parse, **not their total**. A head arriving in pieces is re-tokenized in full on every
    /// arrival, so the work is `segments * head_len` and only the second factor is capped here. Measured, the rescan is
    /// a fraction of the per-segment cost the connection pays regardless, so `max_head` alone keeps it bounded.
    pub max_head: usize,
    /// Maximum size of a buffered body, the declared `Content-Length` or for chunked the **decoded** size, enforced
    /// mid-stream as chunks arrive. Exceeding it answers `413 Content Too Large` and closes, and a chunked wire extent
    /// more than `CHUNK_WIRE_OVERHEAD` past it answers 400. On a streaming connection
    /// ([`protocol_streaming`](super::protocol_streaming())) it governs only the bodies that arrive as one delivery.
    /// Raising it past the reactor's message cap needs [`ServerConfig::max_request_bytes`] raised in step
    /// ([`HttpConfig::min_request_bytes`]), or the 413 path goes dead for the sizes in between.
    pub max_body: usize,
}

impl Default for HttpConfig {
    /// 16 KiB heads; bodies fill the rest of the reactor's default 1 MiB message cap
    /// ([`ServerConfig::max_request_bytes`]) after the head and chunk-framing allowances (16 KiB each) and the
    /// scanner's in-flight line, so the default codec on the default server has no dead band between the limits
    /// ([`HttpConfig::min_request_bytes`] is where the terms come from).
    fn default() -> Self {
        Self {
            max_head: 16 * 1024,
            max_body: 1024 * 1024 - 2 * 16 * 1024 - (TRAILER_LINE_MAX + 1),
        }
    }
}

impl HttpConfig {
    /// Reject a configuration that cannot admit any request, which is either cap at zero. The builders run this at
    /// construction. Keeping [`ServerConfig::max_request_bytes`] at or above
    /// [`min_request_bytes`](HttpConfig::min_request_bytes) stays the caller's job, since the codec never sees
    /// [`ServerConfig`].
    pub fn validate(&self) -> crate::Result<()> {
        if self.max_head == 0 {
            return Err(crate::Error::Validation("http max_head must be non-zero".into()));
        }
        if self.max_body == 0 {
            return Err(crate::Error::Validation("http max_body must be non-zero".into()));
        }
        Ok(())
    }

    /// The smallest [`ServerConfig::max_request_bytes`] under which every message this codec admits reaches the framer
    /// intact. A reactor cap below it leaves a dead band, where requests the codec would accept or answer 413 or 431
    /// are instead closed raw with no HTTP response. The reactor measures the **buffer**, so this is the larger of two
    /// sums.
    pub fn min_request_bytes(&self) -> usize {
        self.max_head
            .saturating_add(self.max_body)
            .saturating_add(CHUNK_WIRE_OVERHEAD)
            // The chunk scanner's in-flight line. It advances only over whole lines and the chunk caps are measured on
            // the scanned extent, so a peer pausing mid-line leaves up to a trailer line, the longer of the two,
            // buffered and uncounted.
            .saturating_add(TRAILER_LINE_MAX + 1)
            // One head and one streamed window, since `max_body` bounds only buffered bodies and a streaming endpoint
            // may set it far below a window. The pump's gate runs before the head is delivered, so both can sit in the
            // buffer at once.
            .max(
                self.max_head
                    .saturating_add(STREAM_WINDOW)
                    // The CRLF closing the previous payload, then the size line and its own CRLF - `chunked::step`'s
                    // `framing`.
                    .saturating_add(CHUNK_LINE_MAX + 4),
            )
    }

    /// The [`ServerConfig::recv_buffer_bytes`] this codec wants: a streamed window with its chunk framing, and a
    /// pipelined remainder.
    pub fn recv_buffer_bytes(&self) -> usize {
        STREAM_WINDOW.saturating_mul(RECV_BUFFER_WINDOWS)
    }

    /// The [`ServerConfig::receipt_window_bytes`] matching this codec's window, so a spliced body meets the same
    /// receipt floor as a streamed one.
    pub fn receipt_window_bytes(&self) -> usize {
        STREAM_WINDOW
    }
}

/// The most body a single streamed delivery carries, picked here so the peer's chunk size does not pick it.
///
/// 128 KiB clears one TLS record (`TLS_MAX_PAYLOAD_SIZE`, 16 KiB) by eight, which a kTLS recv needs before it decrypts
/// straight into the caller's pages. It matches ZFS's default `recordsize`, and it is the HTTP chunk size botocore
/// sends (urllib3 sends one chunk per `body.read(blocksize)`, and `httpsession.py` sets `BUFFER_SIZE` to 128 KiB), so
/// the common case is one window per chunk. The 1 MiB aws-chunked size frames the inner coding, which this layer never
/// sees.
///
/// Larger HTTP chunks arrive as mid-chunk windows, which carry no chunk header and so find the recv claim already
/// leased. `stream_step` sizes those from `chunk_left` alone and the reactor draws them from the ring rather than
/// placing them.
pub(crate) const STREAM_WINDOW: usize = 128 * 1024;

/// Windows per receive buffer ([`HttpConfig::recv_buffer_bytes`]).
const RECV_BUFFER_WINDOWS: usize = 2;

/// Where the connection stands between messages.
#[derive(Debug)]
pub(crate) enum Phase {
    /// Scanning for the next request head.
    Head,
    /// A head with `Expect: 100-continue` was just delivered as a zero-body message; the glue has not yet sent the
    /// interim response.
    ExpectHead {
        /// The head bytes, verbatim (consumed from the buffer on delivery).
        head: Vec<u8>,
        /// The body framing (`Known` > 0 or `Chunked`, or the dance wouldn't start).
        body: BodyKind,
    },
    /// The interim response is queued; the next message is the body alone.
    ExpectBody {
        /// The stashed head the body will be paired with.
        head: Vec<u8>,
        /// The body framing.
        body: BodyKind,
    },
    /// A chunked body is being scanned: the framer answers `More` and resumes `scan` as bytes accumulate, until the
    /// terminal chunk lands.
    ChunkedBody {
        /// The stashed head when the 100-continue dance consumed it already (the body arrives as its own message);
        /// `None` when the head is still at the front of the buffer.
        stash: Option<Vec<u8>>,
        /// Bytes the head occupies at the front of the buffer (0 when stashed).
        head_len: usize,
        /// Resumable scan progress over the body region.
        scan: ChunkScan,
    },
    /// A chunked message was just declared complete; the glue will de-chunk it on delivery.
    ChunkedDone {
        /// The stashed head from the dance, if that's how the head arrived.
        stash: Option<Vec<u8>>,
    },
    /// The stream is unsalvageable; `status` is the farewell the glue sends before flush-closing.
    Fail {
        /// Response status for the farewell (400/413/431/501/505).
        status: u16,
        /// Whether the dying request was a HEAD, recorded when the failure is declared - the last moment the head bytes
        /// are reliably at hand. By delivery time the dance may have consumed them, leaving only body bytes, and body
        /// bytes are client-chosen.
        head_only: bool,
    },
    /// A streamed body's head has been delivered on its own; the next call hands the consumer its opening view, before
    /// a body byte arrives.
    StreamOpen {
        /// The head bytes, verbatim.
        head: Vec<u8>,
        /// The client asked for `100-continue`, so the glue owes an interim line **if** the consumer accepts. Holding
        /// it until then is the point of streaming: a rejection goes out instead of the interim, rather than after
        /// inviting a body nobody wanted.
        expect: bool,
        /// Which body follows the open, so the glue restores the right mid-body phase: a chunked body scans its own
        /// framing, a known-length one counts down.
        body: StreamedBody,
    },
    /// A known-length streamed body in progress: raw payload, delivered a window at a time, with no framing of its own
    /// to scan.
    StreamKnown {
        /// The head every window is paired with.
        head: Vec<u8>,
        /// Payload bytes still owed by the declared length.
        remaining: u64,
    },
    /// A streamed body in progress: the body is declared a window at a time, so the reactor's buffer never holds more
    /// than one and the body's size stops bounding what the server can accept.
    StreamBody {
        /// The head every window is paired with.
        head: Vec<u8>,
        /// Payload still owed by the chunk being delivered, and zero between chunks. A chunk larger than
        /// [`STREAM_WINDOW`] is handed over in several windows rather than one - otherwise the peer's choice of chunk
        /// size would decide how much this server buffers, which is the client dictating a server bound.
        chunk_left: usize,
        /// A previous chunk's payload has been consumed, so the CRLF that closes it is the next step's framing.
        /// Advanced by the glue on delivery, never here: [`frame`] re-runs for the same chunk while its payload is
        /// still arriving, and must answer the same way each time.
        after_payload: bool,
        /// Decoded payload declared so far, for the mid-stream cap.
        decoded: usize,
    },
    /// The terminal chunk was declared; its trailer section is the delivered header and the next call finishes the
    /// request.
    StreamDone {
        /// The head this body belonged to.
        head: Vec<u8>,
        /// Where the terminal block starts inside the delivered header. `chunked::step` counts a chunked body's framing
        /// from the CRLF that closed the previous payload, and the trailer parser would read that leading empty line as
        /// a malformed size line, so the offset travels with the phase.
        block_at: usize,
    },
    /// A request is parked for deferred completion ([`HttpRequest::defer`](super::protocol::HttpRequest::defer)): the
    /// retained request rides here until the worker's outcome redelivers it. The framer holds later pipelined bytes
    /// unframed for the park's duration, so reply order stays request order even above the default in-flight cap of
    /// one.
    Parked {
        /// The retained request plus the answer cell a worker's [`reply`](super::protocol::HttpDeferred::reply) fills.
        req: Box<super::protocol::ParkedRequest>,
        /// What to put back when the park resolves, when the park was taken mid-body. Without it the connection would
        /// return to [`Phase::Head`] and the rest of the body would be framed as a new request - a desync, not an
        /// error.
        resume: Option<Box<StreamPark>>,
    },
}

/// What a streamed open's body is framed as, decided at the head and carried so the open's delivery can restore the
/// matching mid-body phase.
#[derive(Clone, Copy, Debug)]
pub(crate) enum StreamedBody {
    /// `Transfer-Encoding: chunked` — the body carries its own framing.
    Chunked,
    /// `Content-Length` — this many raw payload bytes and nothing else.
    Known(u64),
}

/// A park taken mid-body: the phase to restore once the park resolves. Which stage the retained delivery belongs to
/// lives on the park itself (`ParkedRequest::stage`), because an `End` park has no resume phase to read it off.
#[derive(Debug)]
pub(crate) struct StreamPark {
    /// The phase the connection returns to once the park resolves.
    pub(crate) next: Phase,
    /// A withheld `100 Continue` the resume owes before any body byte can arrive, released by `resume()` and by a
    /// redrive that returns `Continue`. Only an `Open` park can carry one. The client holds its body back for exactly
    /// this line, so a resume that answers with silence stalls every expecting upload until the client's own timeout
    /// (`a_deferred_stream_open_still_sends_the_interim`).
    pub(crate) expect_interim: bool,
}

/// Per-connection codec state wrapping the consumer's own state `U`.
///
/// Minted by the glue's accept wrapper; the `header`/`body` handlers thread it through the reactor as the connection's
/// protocol state.
pub struct HttpConn<U> {
    pub(crate) phase: Phase,
    /// Deliver bodies a chunk or window at a time rather than whole (chunked always, known-length above one window),
    /// and bound every body at this many bytes. The streaming builder sets it, and `None` keeps the single-delivery
    /// contract. The codec has no default for it, since a streamed body never sits in the buffer `max_body` protects.
    pub(crate) stream_cap: Option<std::num::NonZeroU64>,
    /// Where the parts of the last complete head sit, recorded by [`frame`] so that dispatch does not tokenize the head
    /// a second time.
    pub(crate) index: HeadIndex,
    /// The consumer's per-connection state, as returned by their accept handler.
    pub state: U,
}

impl<U> HttpConn<U> {
    /// A fresh connection's protocol state around the consumer's `state`, as the builders' accept wrapper mints it.
    /// Public for a kTLS listener's handshake worker, where the accept handler does not run and `AcceptDeferral::ready`
    /// takes the connection state directly. A streaming protocol adopts its own cap on such a connection at the first
    /// frame.
    pub fn new(state: U) -> Self {
        Self {
            phase: Phase::Head,
            stream_cap: None,
            index: HeadIndex::default(),
            state,
        }
    }

    /// A connection whose bodies stream (chunked a chunk at a time, known-length a window at a time above one window),
    /// bounded at `max_body_bytes`. A connection minted here keeps its own cap, since a streaming protocol adopts its
    /// cap only where none is set.
    ///
    /// The cap is the body limit on a streaming connection, so a zero would answer 413 to every body while a bodyless
    /// GET is served normally. `NonZeroU64` rules that out here, where no builder can screen it.
    pub fn new_streaming(state: U, max_body_bytes: std::num::NonZeroU64) -> Self {
        Self {
            phase: Phase::Head,
            stream_cap: Some(max_body_bytes),
            index: HeadIndex::default(),
            state,
        }
    }
}

impl<U> std::fmt::Debug for HttpConn<U> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpConn")
            .field("phase", &self.phase)
            .finish_non_exhaustive()
    }
}

/// Fail the connection: remember the farewell status (and whether the dying request was a HEAD) and deliver everything
/// buffered as a degenerate message so the glue runs exactly once more.
fn fail(phase: &mut Phase, buf_len: usize, status: u16, head_only: bool) -> Framing {
    *phase = Phase::Fail { status, head_only };
    Framing::Complete {
        header_len: buf_len,
        body_len: 0,
    }
}

/// One framing decision. The reactor calls this (via the glue's `header` handler) with the bytes accumulated since the
/// last complete message.
pub(crate) fn frame<U>(buf: &[u8], conn: &mut HttpConn<U>, cfg: &HttpConfig) -> Framing {
    match &conn.phase {
        // Already failed: deliver the remainder so the glue can farewell. (Normally unreachable - ReplyClose retires
        // the recv side - but total, so a scheduling surprise degrades to a repeat verdict.)
        Phase::Fail { .. } => Framing::Complete {
            header_len: buf.len(),
            body_len: 0,
        },
        // A parked request owns the connection until its outcome redelivers it, so pipelined bytes stay unframed. Above
        // an in-flight cap of one, this arm keeps a later request from being answered around the parked one.
        Phase::Parked { .. } => Framing::More,
        // A declared but undelivered chunked message, the same scheduling surprise as Fail above. Degrade to a
        // degenerate delivery, which the glue's decode fails as a codec bug (500) rather than mis-framing the stream.
        Phase::ChunkedDone { .. } => Framing::Complete {
            header_len: buf.len(),
            body_len: 0,
        },
        // The dance's second message with a declared length: the body alone, head already stashed. ExpectHead is
        // handled identically in defense: the glue advances ExpectHead -> ExpectBody before the framer can run again,
        // but if that invariant ever bends, the verdict is the same either way.
        Phase::ExpectHead {
            body: BodyKind::Known(n),
            ..
        }
        | Phase::ExpectBody {
            body: BodyKind::Known(n),
            ..
        } => Framing::Complete {
            header_len: 0,
            body_len: *n,
        },
        // The dance's second message, chunk-framed: swap the stash into a scan phase and start walking the chunk
        // stream.
        Phase::ExpectHead {
            body: BodyKind::Chunked,
            ..
        }
        | Phase::ExpectBody {
            body: BodyKind::Chunked,
            ..
        } => {
            let (Phase::ExpectHead { head, .. } | Phase::ExpectBody { head, .. }) =
                std::mem::replace(&mut conn.phase, Phase::Head)
            else {
                unreachable!("outer match admitted only Expect phases");
            };
            conn.phase = Phase::ChunkedBody {
                stash: Some(head),
                head_len: 0,
                scan: ChunkScan::default(),
            };
            scan_step(buf, conn, cfg)
        }
        Phase::ChunkedBody { .. } => scan_step(buf, conn, cfg),
        // The glue advances both of these at delivery, so the framer should not see them; degrade like the other
        // impossible phases rather than stall a connection on a scheduling surprise.
        Phase::StreamOpen { .. } | Phase::StreamDone { .. } => Framing::Complete {
            header_len: buf.len(),
            body_len: 0,
        },
        Phase::StreamBody { .. } => stream_step(buf, conn),
        Phase::StreamKnown { .. } => known_step(buf, conn),
        Phase::Head => {
            // In this phase the buffer front IS the head region, so the method prefix is sound to read here - unlike at
            // delivery, where the dance may have consumed the head already.
            let head_only = method_is_head(buf);
            match frame_facts_indexed(buf, &mut conn.index) {
                Err(status) => {
                    // The parse-time screens run before the head-size cap can, since the cap needs the head's extent.
                    // When the buffer is past the cap and no verdict was reachable within it, the promised 431 wins,
                    // and a screen that fires within the cap keeps its more specific status.
                    let status = if buf.len() > cfg.max_head && matches!(frame_facts(&buf[..cfg.max_head]), Ok(None)) {
                        431
                    } else {
                        status
                    };
                    fail(&mut conn.phase, buf.len(), status, head_only)
                }
                Ok(None) => {
                    if buf.len() > cfg.max_head {
                        fail(&mut conn.phase, buf.len(), 431, head_only)
                    } else {
                        Framing::More
                    }
                }
                Ok(Some(facts)) => {
                    if facts.len > cfg.max_head {
                        return fail(&mut conn.phase, buf.len(), 431, head_only);
                    }
                    let body = match facts.body {
                        Ok(b) => b,
                        Err(status) => {
                            return fail(&mut conn.phase, buf.len(), status, head_only);
                        }
                    };
                    match body {
                        BodyKind::Known(body_len) => {
                            // The streaming cap is what the endpoint accepts, so it bounds every body on the
                            // connection, not only the ones that stream. The chunked leg applies it per chunk
                            // regardless of size.
                            if conn.stream_cap.is_some_and(|cap| body_len as u64 > cap.get()) {
                                return fail(&mut conn.phase, buf.len(), 413, head_only);
                            }
                            // Above one window it streams; below it a whole delivery is already a single pool-buffered
                            // read, so there is nothing for a window to save. Streaming also lifts `max_body`, which
                            // bounds a buffer the body never sits in.
                            if conn.stream_cap.is_some() && body_len > STREAM_WINDOW {
                                let head_len = facts.len;
                                conn.phase = Phase::StreamOpen {
                                    head: buf[..head_len].to_vec(),
                                    expect: facts.expects_continue,
                                    body: StreamedBody::Known(body_len as u64),
                                };
                                return Framing::Complete {
                                    header_len: head_len,
                                    body_len: 0,
                                };
                            }
                            if body_len > cfg.max_body {
                                return fail(&mut conn.phase, buf.len(), 413, head_only);
                            }
                            if facts.expects_continue && body_len > 0 {
                                let head_len = facts.len;
                                conn.phase = Phase::ExpectHead {
                                    head: buf[..head_len].to_vec(),
                                    body: BodyKind::Known(body_len),
                                };
                                Framing::Complete {
                                    header_len: head_len,
                                    body_len: 0,
                                }
                            } else {
                                Framing::Complete {
                                    header_len: facts.len,
                                    body_len,
                                }
                            }
                        }
                        BodyKind::Chunked if conn.stream_cap.is_some() => {
                            // Streamed: the head goes out on its own so the consumer can refuse before a body byte
                            // arrives - and, when the client asked for it, so the interim line is withheld until the
                            // consumer has actually accepted.
                            let head_len = facts.len;
                            conn.phase = Phase::StreamOpen {
                                head: buf[..head_len].to_vec(),
                                expect: facts.expects_continue,
                                body: StreamedBody::Chunked,
                            };
                            Framing::Complete {
                                header_len: head_len,
                                body_len: 0,
                            }
                        }
                        BodyKind::Chunked => {
                            if facts.expects_continue {
                                // Chunked always dances when asked: the extent is unknown, so there is no "empty body"
                                // way out, and the client is waiting for the 100 before it sends even the terminal
                                // chunk.
                                let head_len = facts.len;
                                conn.phase = Phase::ExpectHead {
                                    head: buf[..head_len].to_vec(),
                                    body: BodyKind::Chunked,
                                };
                                Framing::Complete {
                                    header_len: head_len,
                                    body_len: 0,
                                }
                            } else {
                                conn.phase = Phase::ChunkedBody {
                                    stash: None,
                                    head_len: facts.len,
                                    scan: ChunkScan::default(),
                                };
                                // Scan immediately: the whole body may already be buffered, and `More` would stall
                                // waiting for bytes that will never come.
                                scan_step(buf, conn, cfg)
                            }
                        }
                    }
                }
            }
        }
    }
}

/// One step of a known-length streamed body, declaring its next window.
fn known_step<U>(buf: &[u8], conn: &mut HttpConn<U>) -> Framing {
    let Phase::StreamKnown { remaining, .. } = &conn.phase else {
        // Caller invariant. `buf.len()` and not 0, because the reactor will not deliver a zero-length `Complete`
        // (`frame_step` closes it raw as `Malformed`), and the 500 farewell would never go out.
        return fail(&mut conn.phase, buf.len(), 500, false);
    };
    let remaining = *remaining;
    if remaining == 0 {
        // The glue retires this phase on the delivery that exhausts the length (a zero-length message cannot be
        // framed), so a zero here is a codec bug, not a wire state.
        return fail(&mut conn.phase, buf.len(), 500, false);
    }
    if buf.is_empty() {
        // Between windows of a body already declared: nothing is buffered, and the request is still arriving.
        return Framing::MoreInMessage;
    }
    // A full window per delivery, however little is buffered. The read that completes it draws from the recv pool,
    // since the `MoreInMessage` above re-acquires a claim and the reactor will not place a frame one pool buffer can
    // serve, so the remainder arrives zero-copy. Windows sized to the buffered bytes would multiply deliveries, wakes
    // and leased writes for the same payload. The `remaining` bound keeps a pipelined next request out of the tail.
    Framing::Complete {
        header_len: 0,
        body_len: remaining.min(STREAM_WINDOW as u64) as usize,
    }
}

/// One chunk of a streamed body, declared as its own message so the body's size never bounds a buffer.
///
/// **Re-entrant on purpose.** `frame` runs again for the same chunk while its payload is still arriving, so nothing
/// here may advance `after_payload` or `decoded`, which the glue advances on delivery.
fn stream_step<U>(buf: &[u8], conn: &mut HttpConn<U>) -> Framing {
    let Phase::StreamBody {
        head,
        chunk_left,
        after_payload,
        decoded,
    } = &conn.phase
    else {
        // Caller invariant; nothing about the request is knowable here.
        return fail(&mut conn.phase, buf.len(), 500, false);
    };
    let head_only = method_is_head(head);
    let (chunk_left, after_payload, decoded) = (*chunk_left, *after_payload, *decoded);
    // Mid-chunk: the framing was consumed with the first window, so what is left is payload and nothing else.
    if chunk_left > 0 {
        return Framing::Complete {
            header_len: 0,
            body_len: chunk_left.min(STREAM_WINDOW),
        };
    }
    match chunked::step(buf, after_payload) {
        // At a chunk boundary the buffer is empty and the body is still coming; `More` would put this read on the idle
        // clock.
        chunked::Step::More => Framing::MoreInMessage,
        chunked::Step::Bad(status) => fail(&mut conn.phase, buf.len(), status, head_only),
        chunked::Step::Chunk { framing, payload } => {
            // The cap is on the decoded body and is checked as each chunk is declared, not after buffering one - a
            // streamed body is never buffered whole, so there is no "after" to check at.
            let total = (decoded as u64).saturating_add(payload as u64);
            let over = conn.stream_cap.is_some_and(|cap| total > cap.get());
            if over {
                return fail(&mut conn.phase, buf.len(), 413, head_only);
            }
            // `decoded` is advanced by the glue on delivery, for the same reason `after_payload` is: this runs again
            // for the same chunk while its payload arrives, and advancing here would count the chunk once per re-entry.
            Framing::Complete {
                header_len: framing,
                body_len: payload.min(STREAM_WINDOW),
            }
        }
        chunked::Step::Last { framing } => {
            let Phase::StreamBody { head, .. } = std::mem::replace(&mut conn.phase, Phase::Head) else {
                unreachable!("matched StreamBody above");
            };
            // `chunked::step` counted `framing` from the CRLF that closed the previous payload; the terminal block
            // itself starts after it.
            conn.phase = Phase::StreamDone {
                head,
                block_at: if after_payload { 2 } else { 0 },
            };
            // A terminal chunk is only locatable once its whole trailer section is buffered, so this delivers
            // immediately and the phase change cannot be re-entered.
            Framing::Complete {
                header_len: framing,
                body_len: 0,
            }
        }
    }
}

/// Advance the chunk scan against the accumulated buffer and map its verdict onto [`Framing`]. It answers
/// `MoreInMessage` while the body is mid-message, enforcing the decoded and wire caps as it goes, and `Complete` with
/// the full wire extent once the terminal chunk and trailers land.
fn scan_step<U>(buf: &[u8], conn: &mut HttpConn<U>, cfg: &HttpConfig) -> Framing {
    let Phase::ChunkedBody { stash, head_len, scan } = &mut conn.phase else {
        // Caller invariant; degrade like the other impossible phases. Nothing about the request is knowable here, so no
        // HEAD flag.
        return fail(&mut conn.phase, buf.len(), 500, false);
    };
    // The head bytes are still at hand, stashed by the dance or at the buffer front. Read the method now, since at
    // delivery the buffer may hold body bytes alone.
    let head_only = match stash {
        Some(h) => method_is_head(h),
        None => method_is_head(buf),
    };
    let header_len = *head_len;
    let body = buf.get(header_len..).unwrap_or(&[]);
    match chunked::scan(body, scan) {
        Err(status) => {
            // Check the caps first, with the same precedence as the arms below. `scan` keeps `decoded` and `consumed`
            // across arrivals, so an over-cap body reaches the same numbers whichever arrival meets the malformation,
            // and TCP segmentation must not choose the status.
            let decoded = scan.decoded;
            let consumed = scan.consumed;
            if decoded > cfg.max_body {
                fail(&mut conn.phase, buf.len(), 413, head_only)
            } else if consumed > cfg.max_body.saturating_add(CHUNK_WIRE_OVERHEAD) {
                fail(&mut conn.phase, buf.len(), 400, head_only)
            } else {
                fail(&mut conn.phase, buf.len(), status, head_only)
            }
        }
        Ok(None) => {
            let decoded = scan.decoded;
            let consumed = scan.consumed;
            if decoded > cfg.max_body {
                fail(&mut conn.phase, buf.len(), 413, head_only)
            } else if consumed > cfg.max_body.saturating_add(CHUNK_WIRE_OVERHEAD) {
                fail(&mut conn.phase, buf.len(), 400, head_only)
            } else {
                // A chunk scan runs only inside a body. With the head consumed by the 100-continue dance the buffer can
                // be empty here, which `More` would report as an idle park.
                Framing::MoreInMessage
            }
        }
        Ok(Some(extent)) => {
            let decoded = scan.decoded;
            if decoded > cfg.max_body {
                return fail(&mut conn.phase, buf.len(), 413, head_only);
            }
            // A single arrival can complete without ever taking the Ok(None) branch above, so the wire cap must hold
            // here too - or the same bytes pass or fail on TCP segmentation alone.
            if extent > cfg.max_body.saturating_add(CHUNK_WIRE_OVERHEAD) {
                return fail(&mut conn.phase, buf.len(), 400, head_only);
            }
            let stash = stash.take();
            conn.phase = Phase::ChunkedDone { stash };
            Framing::Complete {
                header_len,
                body_len: extent,
            }
        }
    }
}

#[cfg(test)]
mod tests;
