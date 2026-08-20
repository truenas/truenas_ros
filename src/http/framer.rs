//! The HTTP framing state machine: a per-connection [`Phase`] plus the pure
//! [`frame`] step mapping accumulated bytes onto [`Framing`] verdicts. All
//! decisions live here so the step stays a pure function of
//! `(buffer, phase, config)` - fuzzable exactly like the reactor's own
//! `frame_step`.
//!
//! Three shapes of exchange exist:
//!
//! - **Single message** (the normal path): the head completes, the body
//!   length is declared, and one `Complete { header_len, body_len }` delivers
//!   head + body together.
//! - **The 100-continue dance**: a head with `Expect: 100-continue` and a
//!   non-empty body is delivered *alone* (`Complete { header_len, 0 }`) with
//!   the head bytes stashed in the phase; the glue replies with the raw
//!   interim line and advances the phase; the framer then declares the body
//!   as a second message (`Complete { 0, body_len }`) paired with the stash.
//! - **Chunked** (`Transfer-Encoding: chunked` - what default S3 SDKs send
//!   over TLS): the body's extent isn't declared, it's discovered - the
//!   framer keeps a resumable [`ChunkScan`] in the phase and answers `More`
//!   until the terminal chunk lands, then declares the whole wire extent as
//!   the message body. The glue de-chunks on delivery. Composes with the
//!   dance (boto3 sends `Expect` *and* `TE: chunked` together): after the
//!   interim, the scan runs against the body-only messages with the head
//!   stashed.
//!
//! Malformed input transitions to [`Phase::Fail`] and delivers whatever is
//! buffered as a degenerate message, so the glue can send a real error
//! response and flush-close ([`Response::ReplyClose`]) rather than slamming
//! the connection - the "HTTP error before hanging up" case the reactor's
//! close semantics were designed for.

use crate::net::Framing;
#[cfg(doc)]
use crate::net::server::{Response, ServerConfig};

use super::chunked::{self, ChunkScan};
use super::head::{BodyKind, frame_facts, method_is_head};

/// Fixed wire-overhead allowance for chunk framing on top of
/// [`HttpConfig::max_body`]: a chunked message whose **wire** extent exceeds
/// `max_body + CHUNK_WIRE_OVERHEAD` fails 400 even while its decoded size is
/// still in bounds. The only way there is pathological framing (one-byte
/// chunks, jumbo extensions) - real clients chunk at 64 KiB or more, a few
/// hundred bytes of overhead per megabyte - so this reads as abuse, not
/// content size, hence 400 rather than 413.
pub(crate) const CHUNK_WIRE_OVERHEAD: usize = 16 * 1024;

/// Codec limits. Both caps close the connection with a real status (431 /
/// 413) rather than silently truncating.
///
/// The reactor imposes its own whole-message cap upstream of this codec
/// ([`ServerConfig::max_request_bytes`]), and a message that clears these
/// caps but exceeds the reactor's is closed abruptly with **no HTTP
/// farewell** ([`CloseReason::TooLarge`](crate::net::server::CloseReason)).
/// Keep `max_request_bytes` at [`HttpConfig::min_request_bytes`] or above so
/// every over-cap request receives its promised 413/431; the defaults on
/// both sides compose exactly.
#[derive(Debug, Clone, Copy)]
pub struct HttpConfig {
    /// Maximum request-head size in bytes (request line + headers +
    /// terminator). Exceeding it answers `431 Request Header Fields Too
    /// Large` and closes. Also bounds head re-parse cost on drip-fed input.
    pub max_head: usize,
    /// Maximum body size accepted for an inline-buffered body: the declared
    /// `Content-Length`, or for chunked requests the **decoded** entity size
    /// (enforced mid-stream as chunks arrive, not after buffering). Exceeding
    /// it answers `413 Content Too Large` and closes; a chunked wire extent
    /// more than `CHUNK_WIRE_OVERHEAD` past this cap answers 400. Bodies
    /// above the cap belong to the (planned) splice path, not the connection
    /// buffer. Raising it past the reactor's message cap requires raising
    /// [`ServerConfig::max_request_bytes`] in step (see
    /// [`HttpConfig::min_request_bytes`]), or the 413 path goes dead for
    /// the sizes in between.
    pub max_body: usize,
}

impl Default for HttpConfig {
    /// 16 KiB heads; bodies fill the rest of the reactor's default 1 MiB
    /// message cap ([`ServerConfig::max_request_bytes`]) after the head and
    /// chunk-framing allowances (16 KiB each), so the default codec on the
    /// default server has no dead band between the limits.
    fn default() -> Self {
        Self {
            max_head: 16 * 1024,
            max_body: 1024 * 1024 - 2 * 16 * 1024,
        }
    }
}

impl HttpConfig {
    /// Reject a configuration that cannot admit any request: both caps must
    /// be non-zero. [`protocol`](super::protocol()) and
    /// [`protocol_deferrable`](super::protocol_deferrable()) run this at
    /// construction. The reactor cross-check stays the consumer's: the codec
    /// never sees [`ServerConfig`], so whoever raises
    /// [`max_body`](HttpConfig::max_body) must keep
    /// [`ServerConfig::max_request_bytes`] at or above
    /// [`min_request_bytes`](HttpConfig::min_request_bytes) in step, or a
    /// request the codec would answer 413/431 is instead cut off with a raw
    /// close and no HTTP response.
    pub fn validate(&self) -> crate::Result<()> {
        if self.max_head == 0 {
            return Err(crate::Error::Validation(
                "http max_head must be non-zero".into(),
            ));
        }
        if self.max_body == 0 {
            return Err(crate::Error::Validation(
                "http max_body must be non-zero".into(),
            ));
        }
        Ok(())
    }

    /// The smallest [`ServerConfig::max_request_bytes`] under which every
    /// message this codec admits reaches the framer intact:
    /// `max_head + max_body + CHUNK_WIRE_OVERHEAD` (the last term because a
    /// chunked body's wire form may legitimately exceed its decoded size).
    /// A reactor cap below this leaves a dead band - requests the codec
    /// would accept (or answer 413/431) that the reactor instead kills with
    /// a raw close and no HTTP response.
    pub fn min_request_bytes(&self) -> usize {
        self.max_head
            .saturating_add(self.max_body)
            .saturating_add(CHUNK_WIRE_OVERHEAD)
    }
}

/// Where the connection stands between messages.
#[derive(Debug)]
pub(crate) enum Phase {
    /// Scanning for the next request head.
    Head,
    /// A head with `Expect: 100-continue` was just delivered as a zero-body
    /// message; the glue has not yet sent the interim response.
    ExpectHead {
        /// The head bytes, verbatim (consumed from the buffer on delivery).
        head: Vec<u8>,
        /// The body framing (`Known` > 0 or `Chunked`, or the dance
        /// wouldn't start).
        body: BodyKind,
    },
    /// The interim response is queued; the next message is the body alone.
    ExpectBody {
        /// The stashed head the body will be paired with.
        head: Vec<u8>,
        /// The body framing.
        body: BodyKind,
    },
    /// A chunked body is being scanned: the framer answers `More` and
    /// resumes `scan` as bytes accumulate, until the terminal chunk lands.
    ChunkedBody {
        /// The stashed head when the 100-continue dance consumed it already
        /// (the body arrives as its own message); `None` when the head is
        /// still at the front of the buffer.
        stash: Option<Vec<u8>>,
        /// Bytes the head occupies at the front of the buffer (0 when
        /// stashed).
        head_len: usize,
        /// Resumable scan progress over the body region.
        scan: ChunkScan,
    },
    /// A chunked message was just declared complete; the glue will de-chunk
    /// it on delivery.
    ChunkedDone {
        /// The stashed head from the dance, if that's how the head arrived.
        stash: Option<Vec<u8>>,
    },
    /// The stream is unsalvageable; `status` is the farewell the glue sends
    /// before flush-closing.
    Fail {
        /// Response status for the farewell (400/413/431/501/505).
        status: u16,
        /// Whether the dying request was a HEAD, recorded when the failure
        /// is declared - the last moment the head bytes are reliably at
        /// hand. By delivery time the dance may have consumed them, leaving
        /// only body bytes, and body bytes are client-chosen.
        head_only: bool,
    },
    /// A request is parked for deferred completion
    /// ([`HttpRequest::defer`](super::protocol::HttpRequest::defer)): the
    /// retained request rides here until the worker's outcome redelivers it.
    /// The framer holds later pipelined bytes unframed for the park's
    /// duration, so reply order stays request order even above the default
    /// in-flight cap of one.
    Parked {
        /// The retained request plus the answer cell a worker's
        /// [`reply`](super::protocol::HttpDeferred::reply) fills.
        req: Box<super::protocol::ParkedRequest>,
    },
}

/// Per-connection codec state wrapping the consumer's own state `U`.
///
/// Minted by the glue's accept wrapper; the `header`/`body` handlers thread
/// it through the reactor as the connection's protocol state.
pub struct HttpConn<U> {
    pub(crate) phase: Phase,
    /// The consumer's per-connection state, as returned by their accept
    /// handler.
    pub state: U,
}

impl<U> HttpConn<U> {
    /// A fresh connection's protocol state around the consumer's `state` --
    /// what the glue's accept wrapper mints for every plain connection.
    /// Public for the one admission that wrapper cannot cover: a kTLS
    /// listener's handshake worker, where the accept handler does not run
    /// and `AcceptDeferral::ready` takes the connection state directly.
    pub fn new(state: U) -> Self {
        Self {
            phase: Phase::Head,
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

/// Fail the connection: remember the farewell status (and whether the dying
/// request was a HEAD) and deliver everything buffered as a degenerate
/// message so the glue runs exactly once more.
fn fail(
    phase: &mut Phase,
    buf_len: usize,
    status: u16,
    head_only: bool,
) -> Framing {
    *phase = Phase::Fail { status, head_only };
    Framing::Complete {
        header_len: buf_len,
        body_len: 0,
    }
}

/// One framing decision. The reactor calls this (via the glue's `header`
/// handler) with the bytes accumulated since the last complete message.
pub(crate) fn frame<U>(
    buf: &[u8],
    conn: &mut HttpConn<U>,
    cfg: &HttpConfig,
) -> Framing {
    match &conn.phase {
        // Already failed: deliver the remainder so the glue can farewell.
        // (Normally unreachable - ReplyClose retires the recv side - but
        // total, so a scheduling surprise degrades to a repeat verdict.)
        Phase::Fail { .. } => Framing::Complete {
            header_len: buf.len(),
            body_len: 0,
        },
        // A parked request owns the connection until its worker outcome
        // redelivers it: hold pipelined bytes unframed. At the default
        // in-flight cap of one the reactor never asks (delivery and reads
        // are gated while a request is outstanding); above it, this arm is
        // what keeps a later request from being answered around a parked
        // earlier one.
        Phase::Parked { .. } => Framing::More,
        // A declared-but-undelivered chunked message: same class of
        // scheduling surprise as Fail above (the glue's step runs between
        // verdicts and resets the phase). Degrade to a degenerate delivery;
        // the glue's decode will fail it as a codec bug (500) rather than
        // mis-framing the stream.
        Phase::ChunkedDone { .. } => Framing::Complete {
            header_len: buf.len(),
            body_len: 0,
        },
        // The dance's second message with a declared length: the body
        // alone, head already stashed. ExpectHead is handled identically in
        // defense: the glue advances ExpectHead -> ExpectBody before the
        // framer can run again, but if that invariant ever bends, the
        // verdict is the same either way.
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
        // The dance's second message, chunk-framed: swap the stash into a
        // scan phase and start walking the chunk stream.
        Phase::ExpectHead {
            body: BodyKind::Chunked,
            ..
        }
        | Phase::ExpectBody {
            body: BodyKind::Chunked,
            ..
        } => {
            let (Phase::ExpectHead { head, .. }
            | Phase::ExpectBody { head, .. }) =
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
        Phase::Head => {
            // In this phase the buffer front IS the head region, so the
            // method prefix is sound to read here - unlike at delivery,
            // where the dance may have consumed the head already.
            let head_only = method_is_head(buf);
            match frame_facts(buf) {
                Err(status) => {
                    // The parse-time screens (malformed, Host, version) run
                    // before the head-size cap can, because the cap needs
                    // the head's extent and a failed parse has none. When
                    // the buffer already exceeds the cap and no verdict was
                    // reachable within it, the promised 431 wins over the
                    // screen that only fired on past-the-cap bytes; a
                    // screen that fires within the cap keeps its more
                    // specific status. (One bounded re-parse, only on a
                    // connection that is already dying.)
                    let status = if buf.len() > cfg.max_head
                        && matches!(frame_facts(&buf[..cfg.max_head]), Ok(None))
                    {
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
                        return fail(
                            &mut conn.phase,
                            buf.len(),
                            431,
                            head_only,
                        );
                    }
                    let body = match facts.body {
                        Ok(b) => b,
                        Err(status) => {
                            return fail(
                                &mut conn.phase,
                                buf.len(),
                                status,
                                head_only,
                            );
                        }
                    };
                    match body {
                        BodyKind::Known(body_len) => {
                            if body_len > cfg.max_body {
                                return fail(
                                    &mut conn.phase,
                                    buf.len(),
                                    413,
                                    head_only,
                                );
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
                        BodyKind::Chunked => {
                            if facts.expects_continue {
                                // Chunked always dances when asked: the
                                // extent is unknown, so there is no "empty
                                // body" way out, and the client is waiting
                                // for the 100 before it sends even the
                                // terminal chunk.
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
                                // Scan immediately: the whole body may
                                // already be buffered, and `More` would
                                // stall waiting for bytes that will never
                                // come.
                                scan_step(buf, conn, cfg)
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Advance the chunk scan against the accumulated buffer and map its verdict
/// onto [`Framing`]: `More` while the stream is mid-message (enforcing the
/// decoded and wire caps as it goes), `Complete` for the full wire extent
/// once the terminal chunk and trailers land.
fn scan_step<U>(
    buf: &[u8],
    conn: &mut HttpConn<U>,
    cfg: &HttpConfig,
) -> Framing {
    let Phase::ChunkedBody {
        stash,
        head_len,
        scan,
    } = &mut conn.phase
    else {
        // Caller invariant; degrade like the other impossible phases.
        // Nothing about the request is knowable here, so no HEAD flag.
        return fail(&mut conn.phase, buf.len(), 500, false);
    };
    // The head bytes are still at hand - stashed by the dance, or at the
    // buffer front when the head was never consumed. Read the method now;
    // at delivery the buffer may hold body bytes alone.
    let head_only = match stash {
        Some(h) => method_is_head(h),
        None => method_is_head(buf),
    };
    let header_len = *head_len;
    let body = buf.get(header_len..).unwrap_or(&[]);
    match chunked::scan(body, scan) {
        Err(status) => fail(&mut conn.phase, buf.len(), status, head_only),
        Ok(None) => {
            let decoded = scan.decoded;
            let consumed = scan.consumed;
            if decoded > cfg.max_body {
                fail(&mut conn.phase, buf.len(), 413, head_only)
            } else if consumed
                > cfg.max_body.saturating_add(CHUNK_WIRE_OVERHEAD)
            {
                fail(&mut conn.phase, buf.len(), 400, head_only)
            } else {
                Framing::More
            }
        }
        Ok(Some(extent)) => {
            let decoded = scan.decoded;
            if decoded > cfg.max_body {
                return fail(&mut conn.phase, buf.len(), 413, head_only);
            }
            // A single arrival can complete without ever taking the Ok(None)
            // branch above, so the wire cap must hold here too - or the same
            // bytes pass or fail on TCP segmentation alone.
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
mod tests {
    use super::*;

    fn conn() -> HttpConn<()> {
        HttpConn::new(())
    }

    fn cfg() -> HttpConfig {
        HttpConfig::default()
    }

    #[test]
    fn validate_rejects_zero_caps() {
        assert!(HttpConfig::default().validate().is_ok());
        assert!(
            HttpConfig {
                max_head: 0,
                max_body: 1024,
            }
            .validate()
            .is_err()
        );
        assert!(
            HttpConfig {
                max_head: 1024,
                max_body: 0,
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn default_caps_compose_with_the_reactor() {
        // The codec's default min request size equals the reactor's default
        // message cap, so the default codec on the default server has no dead
        // band. Pinned here because raising max_body without raising
        // max_request_bytes in step is what opens one.
        use crate::net::server::ServerConfig;
        assert_eq!(
            HttpConfig::default().min_request_bytes(),
            ServerConfig::default().max_request_bytes
        );
    }

    #[test]
    fn single_message_with_body() {
        let mut c = conn();
        let req =
            b"PUT /b/k HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\nhello";
        let head_len = req.len() - 5;
        // Drip-feed the head: every prefix is More.
        for cut in 0..head_len {
            assert_eq!(frame(&req[..cut], &mut c, &cfg()), Framing::More);
        }
        assert_eq!(
            frame(&req[..head_len], &mut c, &cfg()),
            Framing::Complete {
                header_len: head_len,
                body_len: 5
            }
        );
        assert!(matches!(c.phase, Phase::Head));
    }

    #[test]
    fn bodyless_get() {
        let mut c = conn();
        let req = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n";
        assert_eq!(
            frame(req, &mut c, &cfg()),
            Framing::Complete {
                header_len: req.len(),
                body_len: 0
            }
        );
    }

    #[test]
    fn expect_dance() {
        let mut c = conn();
        let head =
            b"PUT /k HTTP/1.1\r\nHost: h\r\nExpect: 100-continue\r\nContent-Length: 3\r\n\r\n";
        // Message 1: the head alone, stashed.
        assert_eq!(
            frame(head, &mut c, &cfg()),
            Framing::Complete {
                header_len: head.len(),
                body_len: 0
            }
        );
        let Phase::ExpectHead {
            head: stash,
            body: BodyKind::Known(body_len),
        } = &c.phase
        else {
            panic!("expected ExpectHead, got {:?}", c.phase);
        };
        assert_eq!(*body_len, 3);
        assert_eq!(stash.as_slice(), head.as_slice());
        // Glue advances the phase after queuing the interim response.
        let Phase::ExpectHead { head: stash, body } =
            std::mem::replace(&mut c.phase, Phase::Head)
        else {
            unreachable!()
        };
        c.phase = Phase::ExpectBody { head: stash, body };
        // Message 2: the body alone, empty header.
        assert_eq!(
            frame(b"abc", &mut c, &cfg()),
            Framing::Complete {
                header_len: 0,
                body_len: 3
            }
        );
    }

    #[test]
    fn expect_with_empty_body_is_normal() {
        let mut c = conn();
        let req =
            b"PUT /k HTTP/1.1\r\nHost: h\r\nExpect: 100-continue\r\nContent-Length: 0\r\n\r\n";
        assert_eq!(
            frame(req, &mut c, &cfg()),
            Framing::Complete {
                header_len: req.len(),
                body_len: 0
            }
        );
        assert!(matches!(c.phase, Phase::Head));
    }

    #[test]
    fn expect_on_http10_is_ignored() {
        // RFC 9110 sec. 10.1.1: no interim responses to a 1.0 client - the
        // request frames as one ordinary message, no dance.
        let mut c = conn();
        let req =
            b"PUT /k HTTP/1.0\r\nExpect: 100-continue\r\nContent-Length: 3\r\n\r\nabc";
        let head_len = req.len() - 3;
        assert_eq!(
            frame(req, &mut c, &cfg()),
            Framing::Complete {
                header_len: head_len,
                body_len: 3
            }
        );
        assert!(matches!(c.phase, Phase::Head));
    }

    #[test]
    fn missing_host_fails_400() {
        let mut c = conn();
        let req = b"GET / HTTP/1.1\r\n\r\n";
        assert_eq!(
            frame(req, &mut c, &cfg()),
            Framing::Complete {
                header_len: req.len(),
                body_len: 0
            }
        );
        assert!(matches!(c.phase, Phase::Fail { status: 400, .. }));
    }

    #[test]
    fn malformed_head_fails_400() {
        let mut c = conn();
        let junk = b"NOT HTTP\r\n\r\n";
        assert_eq!(
            frame(junk, &mut c, &cfg()),
            Framing::Complete {
                header_len: junk.len(),
                body_len: 0
            }
        );
        assert!(matches!(c.phase, Phase::Fail { status: 400, .. }));
    }

    #[test]
    fn oversized_head_fails_431() {
        let mut c = conn();
        let small = HttpConfig {
            max_head: 64,
            max_body: 1024,
        };
        // An incomplete head that already exceeds the cap.
        let mut buf = b"GET / HTTP/1.1\r\nX-Pad: ".to_vec();
        buf.extend(std::iter::repeat_n(b'a', 100));
        assert_eq!(
            frame(&buf, &mut c, &small),
            Framing::Complete {
                header_len: buf.len(),
                body_len: 0
            }
        );
        assert!(matches!(c.phase, Phase::Fail { status: 431, .. }));

        // A head that completes in one arrival but lands over the cap.
        let mut c = conn();
        let mut req = b"GET / HTTP/1.1\r\nHost: h\r\nX-Pad: ".to_vec();
        req.extend(std::iter::repeat_n(b'a', 60));
        req.extend_from_slice(b"\r\n\r\n");
        assert_eq!(
            frame(&req, &mut c, &small),
            Framing::Complete {
                header_len: req.len(),
                body_len: 0
            }
        );
        assert!(matches!(c.phase, Phase::Fail { status: 431, .. }));
    }

    #[test]
    fn over_cap_head_keeps_the_promised_431() {
        // A host-less head is a 400, but this one only completes past the
        // cap - no verdict was reachable within it, so the cap's promised
        // 431 wins over the screen that fired on past-the-cap bytes.
        let small = HttpConfig {
            max_head: 64,
            max_body: 1024,
        };
        let mut c = conn();
        let mut req = b"GET / HTTP/1.1\r\nX-Pad: ".to_vec();
        req.extend(std::iter::repeat_n(b'a', 60));
        req.extend_from_slice(b"\r\n\r\n");
        frame(&req, &mut c, &small);
        assert!(matches!(c.phase, Phase::Fail { status: 431, .. }));

        // The same screen within the cap keeps its specific status.
        let mut c = conn();
        frame(b"GET / HTTP/1.1\r\nX-P: a\r\n\r\n", &mut c, &small);
        assert!(matches!(c.phase, Phase::Fail { status: 400, .. }));
    }

    #[test]
    fn oversized_body_fails_413() {
        let mut c = conn();
        let small = HttpConfig {
            max_head: 1024,
            max_body: 10,
        };
        let req = b"PUT /k HTTP/1.1\r\nHost: h\r\nContent-Length: 11\r\n\r\n";
        assert_eq!(
            frame(req, &mut c, &small),
            Framing::Complete {
                header_len: req.len(),
                body_len: 0
            }
        );
        assert!(matches!(c.phase, Phase::Fail { status: 413, .. }));
    }

    #[test]
    fn chunked_single_arrival() {
        // Head + whole chunked body in one buffer: the framer must scan and
        // complete in the same call (`More` would stall - no bytes follow).
        let mut c = conn();
        let head =
            b"PUT /k HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n";
        let mut raw = head.to_vec();
        raw.extend_from_slice(b"5\r\nhello\r\n0\r\n\r\n");
        assert_eq!(
            frame(&raw, &mut c, &cfg()),
            Framing::Complete {
                header_len: head.len(),
                body_len: raw.len() - head.len(),
            }
        );
        assert!(matches!(c.phase, Phase::ChunkedDone { stash: None }));
    }

    #[test]
    fn chunked_drip_fed() {
        // Every prefix is More; the scan resumes rather than restarting.
        let mut c = conn();
        let head =
            b"PUT /k HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n";
        let mut raw = head.to_vec();
        raw.extend_from_slice(b"3\r\nfoo\r\n4\r\nbars\r\n0\r\n\r\n");
        for cut in 0..raw.len() {
            assert_eq!(
                frame(&raw[..cut], &mut c, &cfg()),
                Framing::More,
                "cut {cut}"
            );
        }
        assert_eq!(
            frame(&raw, &mut c, &cfg()),
            Framing::Complete {
                header_len: head.len(),
                body_len: raw.len() - head.len(),
            }
        );
    }

    #[test]
    fn chunked_expect_dance() {
        // The real boto3 shape: Expect and TE chunked together. Message 1
        // is the head alone; after the glue advances the phase, the chunk
        // scan runs against body-only bytes with the head stashed.
        let mut c = conn();
        let head = b"PUT /k HTTP/1.1\r\nHost: h\r\nExpect: 100-continue\r\nTransfer-Encoding: chunked\r\n\r\n";
        assert_eq!(
            frame(head, &mut c, &cfg()),
            Framing::Complete {
                header_len: head.len(),
                body_len: 0
            }
        );
        let Phase::ExpectHead {
            head: stash,
            body: BodyKind::Chunked,
        } = std::mem::replace(&mut c.phase, Phase::Head)
        else {
            panic!("expected chunked ExpectHead");
        };
        c.phase = Phase::ExpectBody {
            head: stash,
            body: BodyKind::Chunked,
        };
        let wire = b"5\r\nhello\r\n0\r\n\r\n";
        assert_eq!(
            frame(&wire[..4], &mut c, &cfg()),
            Framing::More,
            "partial body resumes the dance into a scan"
        );
        assert_eq!(
            frame(wire, &mut c, &cfg()),
            Framing::Complete {
                header_len: 0,
                body_len: wire.len()
            }
        );
        let Phase::ChunkedDone { stash: Some(stash) } = &c.phase else {
            panic!("expected stashed ChunkedDone, got {:?}", c.phase);
        };
        assert_eq!(stash.as_slice(), head.as_slice());
    }

    #[test]
    fn chunked_decoded_over_cap_fails_413() {
        // The decoded cap trips mid-stream, before the terminal chunk.
        let mut c = conn();
        let small = HttpConfig {
            max_head: 1024,
            max_body: 10,
        };
        let head =
            b"PUT /k HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n";
        let mut raw = head.to_vec();
        raw.extend_from_slice(b"b\r\n0123456789A");
        assert_eq!(
            frame(&raw, &mut c, &small),
            Framing::Complete {
                header_len: raw.len(),
                body_len: 0
            }
        );
        assert!(matches!(c.phase, Phase::Fail { status: 413, .. }));
    }

    #[test]
    fn chunked_wire_overhead_fails_400() {
        // Decoded size stays in bounds but one-byte chunks inflate the wire
        // extent past max_body + CHUNK_WIRE_OVERHEAD: framing abuse, 400.
        let mut c = conn();
        let small = HttpConfig {
            max_head: 1024,
            max_body: 4096,
        };
        let head =
            b"PUT /k HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n";
        let mut raw = head.to_vec();
        // 6 wire bytes per decoded byte; stop short of the decoded cap.
        for _ in 0..4000 {
            raw.extend_from_slice(b"1\r\nX\r\n");
        }
        frame(&raw, &mut c, &small);
        assert!(matches!(c.phase, Phase::Fail { status: 400, .. }));
    }

    #[test]
    fn chunked_wire_overhead_fails_400_on_completion() {
        // The same wire shape with its terminal chunk in the same call: the
        // scan completes rather than reporting progress, and the wire cap
        // must fire on the completion branch too - the verdict cannot
        // depend on how the bytes were segmented.
        let mut c = conn();
        let small = HttpConfig {
            max_head: 1024,
            max_body: 4096,
        };
        let head =
            b"PUT /k HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n";
        let mut raw = head.to_vec();
        for _ in 0..4000 {
            raw.extend_from_slice(b"1\r\nX\r\n");
        }
        raw.extend_from_slice(b"0\r\n\r\n");
        frame(&raw, &mut c, &small);
        assert!(matches!(c.phase, Phase::Fail { status: 400, .. }));
    }

    #[test]
    fn head_flag_survives_leading_empty_lines() {
        // httparse skips empty lines before the request line (RFC 9112
        // sec. 2.2), so `\r\nHEAD ...` parses as a HEAD; the failure flag must
        // agree, or this farewell carries a body the client reads as the
        // next response's head.
        let mut c = conn();
        let req = b"\r\nHEAD /x HTTP/1.1\r\nHost: h\r\nContent-Length: 99999999999\r\n\r\n";
        frame(req, &mut c, &cfg());
        assert!(matches!(
            c.phase,
            Phase::Fail {
                status: 413,
                head_only: true
            }
        ));

        // Bare LF, dying on a screen that parses no facts (missing Host):
        // the flag is judged from the method bytes alone.
        let mut c = conn();
        frame(b"\nHEAD / HTTP/1.1\r\n\r\n", &mut c, &cfg());
        assert!(matches!(
            c.phase,
            Phase::Fail {
                status: 400,
                head_only: true
            }
        ));

        // A non-HEAD behind the same empty line keeps its farewell body.
        let mut c = conn();
        frame(b"\r\nGET / HTTP/1.1\r\n\r\n", &mut c, &cfg());
        assert!(matches!(
            c.phase,
            Phase::Fail {
                status: 400,
                head_only: false
            }
        ));
    }

    #[test]
    fn chunked_malformed_fails_400() {
        let mut c = conn();
        let head =
            b"PUT /k HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n";
        let mut raw = head.to_vec();
        raw.extend_from_slice(b"FFFFFFFFFFFFFFFFF\r\n");
        frame(&raw, &mut c, &cfg());
        assert!(matches!(c.phase, Phase::Fail { status: 400, .. }));
    }

    #[test]
    fn te_with_unimplemented_coding_fails_501() {
        let mut c = conn();
        let req = b"PUT /k HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: gzip, chunked\r\n\r\n";
        frame(req, &mut c, &cfg());
        assert!(matches!(c.phase, Phase::Fail { status: 501, .. }));
    }

    #[test]
    fn pipelined_next_head_frames_cleanly() {
        let mut c = conn();
        // After a complete message is consumed, the framer starts over on
        // the remaining bytes - simulate the reactor's consume-and-recheck.
        let two = b"GET /a HTTP/1.1\r\nHost: h\r\n\r\nGET /b HTTP/1.1\r\nHost: h\r\n\r\n";
        let first = b"GET /a HTTP/1.1\r\nHost: h\r\n\r\n".len();
        assert_eq!(
            frame(two, &mut c, &cfg()),
            Framing::Complete {
                header_len: first,
                body_len: 0
            }
        );
        assert_eq!(
            frame(&two[first..], &mut c, &cfg()),
            Framing::Complete {
                header_len: two.len() - first,
                body_len: 0
            }
        );
    }

    #[test]
    fn empty_buffer_wants_more() {
        let mut c = conn();
        assert_eq!(frame(b"", &mut c, &cfg()), Framing::More);
    }
}
