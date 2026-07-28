//! [`FrameReader`]/[`write_frame`]: message framing over any tokio byte
//! stream, driven by the fuzz-verified [`frame_step`](crate::framing)
//! decision core — the same guard arithmetic the io_uring reactor enforced,
//! now on `AsyncRead`.
//!
//! Two read strategies, same framer contract:
//!
//! - **Buffered** ([`FrameReader::new`], the default): one `read` drains
//!   whatever the kernel has — often many pipelined frames — and subsequent
//!   [`next`](FrameReader::next) calls serve them from the buffer with no
//!   further syscall. This is the fast path for length-delimited protocols,
//!   competitive with `tokio_util::codec`. It does **not** support
//!   [`Frame::SpliceBody`] (a greedy read can pull past the header, which the
//!   splice hand-off forbids).
//! - **Exact** ([`FrameReader::exact`]): reads exactly what each framing step
//!   asks for, so when a splice framer returns `SpliceBody` the buffer holds
//!   the header and nothing past it — the discipline
//!   [`Bridge::recv_to_file`](super::Bridge::recv_to_file) needs to splice
//!   the body straight from the socket. Use this only for framers that emit
//!   `SpliceBody`; it is slower (a syscall per framing step).
//!
//! A framer is any `FnMut(&[u8]) -> Framing` (state lives in the closure);
//! [`crate::framing::length_prefix_header`] builds the common fixed-prefix
//! one.

use crate::errno::Errno;
use crate::framing::{frame_step, FrameFault, FrameStep, Framing, RECV_CHUNK};
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Greedy-read size for the buffered path — big enough to pull many
/// pipelined frames per syscall.
const READ_CHUNK: usize = 64 << 10;

/// One framed message from a [`FrameReader`].
#[derive(Debug)]
pub enum Frame {
    /// A fully-buffered message, split at the framer's header/body boundary.
    Message {
        /// The header bytes.
        header: Vec<u8>,
        /// The body bytes (possibly empty).
        body: Vec<u8>,
    },
    /// A message whose body the caller moves out-of-band (zero-copy): the
    /// header is delivered, the next `body_len` stream bytes are the body —
    /// drive them with a [`Bridge`](super::Bridge) on
    /// [`FrameReader::get_mut`] before calling
    /// [`next`](FrameReader::next) again. Only an [`exact`](FrameReader::exact)
    /// reader produces this.
    SpliceBody {
        /// The header bytes (the reader's buffer is now empty).
        header: Vec<u8>,
        /// Stream bytes belonging to the body phase.
        body_len: u64,
    },
}

/// A framed-message reader over any `AsyncRead`. See the module docs for the
/// buffered-vs-exact strategies.
///
/// `max_request_bytes` caps every buffered frame (header + buffered body);
/// splice bodies are deliberately exempt — streaming bodies larger than any
/// buffer cap is what [`Frame::SpliceBody`] is for.
#[derive(Debug)]
pub struct FrameReader<R> {
    io: R,
    buf: Vec<u8>,
    /// Cursor: `buf[pos..]` is the unparsed remainder. Delivered frames only
    /// advance `pos` (no shift); the buffer is compacted before the next
    /// read, so a full buffer of pipelined frames is served in O(n), not
    /// O(n²). Always 0 in exact mode.
    pos: usize,
    max_request_bytes: usize,
    body_placement_threshold: Option<usize>,
    /// `true` = buffered/greedy (default); `false` = exact (splice-safe).
    buffered: bool,
}

impl<R: AsyncRead + Unpin> FrameReader<R> {
    /// A buffered reader (fast path) with a 1 MiB frame cap.
    pub fn new(io: R) -> FrameReader<R> {
        FrameReader::with_limits(io, 1 << 20, Some(64 << 10))
    }

    /// A buffered reader with explicit limits.
    pub fn with_limits(
        io: R,
        max_request_bytes: usize,
        body_placement_threshold: Option<usize>,
    ) -> FrameReader<R> {
        FrameReader {
            io,
            buf: Vec::new(),
            pos: 0,
            max_request_bytes,
            body_placement_threshold,
            buffered: true,
        }
    }

    /// An **exact** reader (splice-safe) with a 1 MiB frame cap — for framers
    /// that emit [`Frame::SpliceBody`]. Slower than the buffered default; use
    /// only when you need the zero-copy body hand-off.
    pub fn exact(io: R) -> FrameReader<R> {
        FrameReader::exact_with_limits(io, 1 << 20, Some(64 << 10))
    }

    /// An exact reader with explicit limits.
    pub fn exact_with_limits(
        io: R,
        max_request_bytes: usize,
        body_placement_threshold: Option<usize>,
    ) -> FrameReader<R> {
        FrameReader {
            io,
            buf: Vec::new(),
            pos: 0,
            max_request_bytes,
            body_placement_threshold,
            buffered: false,
        }
    }

    /// The underlying stream — the seam for a zero-copy body phase (a
    /// [`Bridge`](super::Bridge) over the same socket between frames).
    /// Meaningful only on an [`exact`](FrameReader::exact) reader, whose
    /// buffer is empty at a `SpliceBody` hand-off.
    pub fn get_mut(&mut self) -> &mut R {
        &mut self.io
    }

    /// Read the next frame. `Ok(None)` is a clean end-of-stream **at a frame
    /// boundary** (nothing buffered); EOF mid-frame fails `ECONNRESET`, a
    /// framer refusal (malformed / over the cap) fails with a `Validation`
    /// error naming the fault.
    pub async fn next<F>(
        &mut self,
        framer: &mut F,
    ) -> crate::Result<Option<Frame>>
    where
        F: FnMut(&[u8]) -> Framing,
    {
        if self.buffered {
            self.next_buffered(framer).await
        } else {
            self.next_exact(framer).await
        }
    }

    /// The buffered fast path: parse from the in-memory buffer first, read
    /// greedily only when it holds no complete frame.
    async fn next_buffered<F>(
        &mut self,
        framer: &mut F,
    ) -> crate::Result<Option<Frame>>
    where
        F: FnMut(&[u8]) -> Framing,
    {
        loop {
            let buffered = self.buf.len() - self.pos;
            let verdict = framer(&self.buf[self.pos..]);
            match frame_step(
                verdict,
                buffered,
                self.max_request_bytes,
                self.body_placement_threshold,
            ) {
                FrameStep::Close(FrameFault::Malformed) => {
                    return Err(crate::Error::Validation(
                        "malformed frame".into(),
                    ));
                }
                FrameStep::Close(FrameFault::TooLarge) => {
                    return Err(self.too_large());
                }
                FrameStep::SpliceBody { .. } => {
                    return Err(crate::Error::Validation(
                        "SpliceBody frames require FrameReader::exact (the \
                         buffered reader may read past the header)"
                            .into(),
                    ));
                }
                FrameStep::Deliver {
                    header_len,
                    body_len,
                } => {
                    // Copy this frame out and advance the cursor — no shift.
                    let s = self.pos;
                    let header = self.buf[s..s + header_len].to_vec();
                    let body = self.buf
                        [s + header_len..s + header_len + body_len]
                        .to_vec();
                    self.pos += header_len + body_len;
                    return Ok(Some(Frame::Message { header, body }));
                }
                FrameStep::ReadHeader { exact, .. } => {
                    if self.greedy_read().await? == 0 {
                        return self.eof();
                    }
                    // frame_step caps exact (`Need`) reads; only a `More`
                    // delimiter scan (exact == false) is unbounded, and after
                    // the read `pos == 0` so `buf.len()` is that one frame's
                    // accumulation.
                    if !exact && self.buf.len() > self.max_request_bytes {
                        return Err(self.too_large());
                    }
                }
                FrameStep::ReadBody { .. } => {
                    if self.greedy_read().await? == 0 {
                        return self.eof(); // mid-body ⇒ ECONNRESET (buf nonempty)
                    }
                }
            }
        }
    }

    /// Compact consumed bytes, ensure spare capacity, and read greedily into
    /// the buffer's uninitialised tail (no zeroing). Returns bytes read.
    async fn greedy_read(&mut self) -> crate::Result<usize> {
        if self.pos > 0 {
            self.buf.drain(..self.pos);
            self.pos = 0;
        }
        if self.buf.capacity() - self.buf.len() < READ_CHUNK {
            self.buf.reserve(READ_CHUNK);
        }
        self.io
            .read_buf(&mut self.buf)
            .await
            .map_err(io_to_crate_err)
    }

    fn eof(&self) -> crate::Result<Option<Frame>> {
        if self.buf.len() == self.pos {
            Ok(None) // clean end between messages
        } else {
            Err(Errno::ECONNRESET.into()) // frame cut off mid-stream
        }
    }

    fn too_large(&self) -> crate::Error {
        crate::Error::Validation(format!(
            "frame exceeds max_request_bytes ({})",
            self.max_request_bytes
        ))
    }

    /// The exact path (splice-safe): read exactly what each framing step
    /// asks, so the buffer holds the header and nothing more at a
    /// `SpliceBody`.
    async fn next_exact<F>(
        &mut self,
        framer: &mut F,
    ) -> crate::Result<Option<Frame>>
    where
        F: FnMut(&[u8]) -> Framing,
    {
        loop {
            let verdict = framer(&self.buf);
            match frame_step(
                verdict,
                self.buf.len(),
                self.max_request_bytes,
                self.body_placement_threshold,
            ) {
                FrameStep::Close(FrameFault::Malformed) => {
                    return Err(crate::Error::Validation(
                        "malformed frame".into(),
                    ));
                }
                FrameStep::Close(FrameFault::TooLarge) => {
                    return Err(self.too_large());
                }
                FrameStep::ReadHeader { want, exact } => {
                    let got = self.fill(want, exact).await?;
                    if got == 0 {
                        if self.buf.is_empty() {
                            return Ok(None);
                        }
                        return Err(Errno::ECONNRESET.into());
                    }
                    if self.buf.len() > self.max_request_bytes {
                        return Err(self.too_large());
                    }
                }
                FrameStep::ReadBody { want, .. } => {
                    if self.fill(want, true).await? == 0 {
                        return Err(Errno::ECONNRESET.into());
                    }
                }
                FrameStep::Deliver {
                    header_len,
                    body_len,
                } => {
                    let total = header_len + body_len;
                    let mut header: Vec<u8> = self.buf.drain(..total).collect();
                    let body = header.split_off(header_len);
                    return Ok(Some(Frame::Message { header, body }));
                }
                FrameStep::SpliceBody {
                    header_len,
                    body_len,
                } => {
                    // frame_step guarantees buffered == header_len.
                    let header: Vec<u8> =
                        self.buf.drain(..header_len).collect();
                    return Ok(Some(Frame::SpliceBody {
                        header,
                        body_len: body_len as u64,
                    }));
                }
            }
        }
    }

    /// Exact-mode fill: read exactly `want` bytes (`exact`) or up to a chunk.
    /// 0 = EOF; for `exact`, partial-then-EOF also reports 0 with the partial
    /// bytes retained (the caller treats any short frame as `ECONNRESET`).
    async fn fill(&mut self, want: usize, exact: bool) -> crate::Result<usize> {
        let start = self.buf.len();
        let goal = if exact { want } else { want.min(RECV_CHUNK) };
        self.buf.resize(start + goal, 0);
        let mut got = 0usize;
        while got < goal {
            let n = self
                .io
                .read(&mut self.buf[start + got..])
                .await
                .map_err(io_to_crate_err)?;
            if n == 0 {
                break; // EOF
            }
            got += n;
            if !exact {
                break;
            }
        }
        self.buf.truncate(start + got);
        if exact && got != 0 && got < goal {
            return Ok(0);
        }
        Ok(got)
    }
}

/// Write a frame as gathered parts (header, body, …), fully.
pub async fn write_frame<W: AsyncWrite + Unpin>(
    io: &mut W,
    parts: &[&[u8]],
) -> crate::Result<()> {
    for part in parts {
        io.write_all(part).await.map_err(io_to_crate_err)?;
    }
    io.flush().await.map_err(io_to_crate_err)?;
    Ok(())
}

fn io_to_crate_err(e: io::Error) -> crate::Error {
    e.raw_os_error()
        .map(Errno::from_raw)
        .unwrap_or(Errno::EIO)
        .into()
}
