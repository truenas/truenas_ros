//! [`Bridge`]: zero-copy transfers between a tokio-owned socket and the
//! reactor's files — the data plane of the hybrid runtime.
//!
//! The socket stays tokio's; the ring is the transfer engine. Each transfer
//! splices through a blocking pipe from the [`PipePool`]
//! (socket→pipe→file for receive, file→pipe→socket for send) with both hops
//! sequenced manually on completions — never `IOSQE_IO_LINK`ed, because a
//! *short* splice fails the request kernel-side and would `-ECANCELED` the
//! linked hop. Readiness is **ring-driven**: `IORING_OP_SPLICE` never
//! poll-arms, so a nonblocking socket's `-EAGAIN` comes straight back in
//! the CQE and the bridge parks on a ring `POLL_ADD` — one readiness
//! authority (tokio's cached readiness would go stale, since the ring
//! consumes bytes behind tokio's io driver).
//!
//! **Serialization contract:** a `Bridge` mutably borrows the stream, so no
//! tokio read/write can interleave with a body phase — the borrow checker
//! enforces what the old reactor enforced by construction.
//!
//! **Cancel/timeout semantics:** dropping a bridge future (or hitting the
//! `timeout`) abandons the transfer, not the in-flight hop — the op runs to
//! completion against the op-entry-owned fd anchors, and the pipe lease is
//! tainted so it is discarded rather than repooled. Over kTLS a stalled
//! splice blocks an io-wq worker until the next TLS record or peer close
//! (`tls_sw_splice_read` honours only `SPLICE_F_NONBLOCK`, deliberately
//! unset here); an abandoned kTLS transfer can therefore pin that worker
//! until the connection dies. Bound kTLS bodies with `timeout` and close
//! the connection on expiry.

use super::fs::FsRt;
use super::pipe::{PipeLease, PipePool};
use super::FsRuntime;
use crate::async_fs::{FixedFile, SpliceEnd};
use crate::errno::Errno;
use std::future::Future;
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::Arc;
use std::time::Duration;

/// Below this, zero-copy send costs more (page pinning + notif CQE) than
/// the copy it saves; plain send is used instead. (~16 KiB, the same
/// break-even the kernel documentation suggests for `MSG_ZEROCOPY`.)
const ZC_THRESHOLD: usize = 16 << 10;

/// A zero-copy data-plane session over one socket. See the module docs.
pub struct Bridge<'a, S: AsRawFd + Unpin> {
    fs: FsRt,
    pipes: PipePool,
    /// Held mutably for the session: the serialization contract.
    sock: &'a mut S,
    /// A one-per-session dup of the socket fd. Every ring op anchors it (an
    /// `Arc` clone rides in the op entry), so the fd number the SQE names
    /// can never be closed or reused while an op is in flight — even if the
    /// caller drops everything.
    dup: Arc<OwnedFd>,
    /// Set when the socket rejected `MSG_ZEROCOPY`/`MSG_WAITALL`
    /// (`EOPNOTSUPP` — a kTLS socket): all further sends take the plain
    /// resubmit path, which is also the correct kTLS path (SW kTLS already
    /// zero-copies the plaintext *input* in-kernel).
    zc_denied: bool,
}

impl<'a, S: AsRawFd + Unpin> Bridge<'a, S> {
    /// Open a bridge session over `sock` (any `AsRawFd` stream — a
    /// `TcpStream`, a `KtlsStream`, a unix stream).
    pub fn new(
        rt: &FsRuntime,
        sock: &'a mut S,
    ) -> crate::Result<Bridge<'a, S>> {
        // SAFETY: F_DUPFD_CLOEXEC on a live fd; the result is a fresh fd.
        let raw = Errno::result(unsafe {
            libc::fcntl(sock.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0)
        })?;
        // SAFETY: fcntl(F_DUPFD_CLOEXEC) returned a fresh owned descriptor.
        let dup = Arc::new(unsafe { crate::fd::owned_from_raw(raw) });
        Ok(Bridge {
            fs: rt.rt(),
            pipes: rt.pipes().clone(),
            sock,
            dup,
            zc_denied: false,
        })
    }

    /// The bridged stream, for interleaving normal tokio I/O *between*
    /// transfers (never during one — each transfer holds `&mut self`).
    pub fn stream(&mut self) -> &mut S {
        self.sock
    }

    /// Splice exactly `len` bytes socket → `file` at offset `off`, fully
    /// in-kernel (socket→pipe→file; plaintext or kTLS receive — the tls
    /// socket's `splice_read` yields plaintext). Full-length-or-error: a
    /// peer close mid-body fails `ECONNRESET`, a `timeout` expiry
    /// `ETIMEDOUT`. Returns `len`.
    pub async fn recv_to_file(
        &mut self,
        file: &FixedFile,
        off: u64,
        len: u64,
        timeout: Option<Duration>,
    ) -> crate::Result<u64> {
        if len == 0 {
            return Ok(0);
        }
        let mut lease = self.pipes.lease().await?;
        let res = self.recv_inner(file, off, len, &mut lease, timeout).await;
        if res.is_err() {
            // Bytes may be stranded in the pipe; never repool it.
            lease.taint();
        }
        res.map(|()| len)
    }

    async fn recv_inner(
        &self,
        file: &FixedFile,
        mut off: u64,
        len: u64,
        lease: &mut PipeLease,
        timeout: Option<Duration>,
    ) -> crate::Result<()> {
        let mut remaining = len;
        while remaining > 0 {
            let chunk = remaining
                .min(lease.capacity() as u64)
                .min(i32::MAX as u64) as u32;
            // Hop 1: socket → pipe. `-EAGAIN` (empty nonblocking socket) →
            // park on POLLIN and retry; 0 → the peer closed mid-body.
            let moved = loop {
                let hop = self.fs.bridge_splice(
                    SpliceEnd::Raw(self.dup.as_raw_fd()),
                    u64::MAX,
                    SpliceEnd::Raw(lease.write_end().as_raw_fd()),
                    u64::MAX,
                    chunk,
                    vec![self.dup.clone(), lease.write_end().clone()],
                );
                match Self::clocked(hop, timeout).await {
                    Ok(0) => return Err(Errno::ECONNRESET.into()),
                    Ok(n) => break n,
                    Err(crate::Error::Errno(Errno::EAGAIN)) => {
                        let poll = self.fs.bridge_poll(
                            self.dup.as_raw_fd(),
                            libc::POLLIN as u32,
                            self.dup.clone(),
                        );
                        Self::clocked(poll, timeout).await?;
                    }
                    Err(e) => return Err(e),
                }
            };
            // Hop 2: drain the pipe → file. A blocking pipe with `moved`
            // bytes never EAGAINs; the file end may complete short — loop.
            let mut in_pipe = moved;
            while in_pipe > 0 {
                let hop = self.fs.bridge_splice(
                    SpliceEnd::Raw(lease.read_end().as_raw_fd()),
                    u64::MAX,
                    SpliceEnd::Fixed {
                        slot: file.slot,
                        gen: file.gen,
                    },
                    off,
                    in_pipe.min(i32::MAX as u64) as u32,
                    vec![lease.read_end().clone()],
                );
                let n = Self::clocked(hop, timeout).await?;
                if n == 0 {
                    return Err(Errno::EIO.into());
                }
                off += n;
                in_pipe -= n;
            }
            remaining -= moved;
        }
        Ok(())
    }

    /// Splice up to `len` bytes `file` (from offset `off`) → socket, fully
    /// in-kernel. Works over plaintext **and** kTLS (`splice_to_socket`
    /// feeds the tls layer via `MSG_SPLICE_PAGES`; the only data touch is
    /// the mandatory encrypt pass). Returns the bytes sent — short (like
    /// `sendfile`) if the file ends before `len`.
    pub async fn send_file(
        &mut self,
        file: &FixedFile,
        off: u64,
        len: u64,
        timeout: Option<Duration>,
    ) -> crate::Result<u64> {
        if len == 0 {
            return Ok(0);
        }
        let mut lease = self.pipes.lease().await?;
        let res = self.send_inner(file, off, len, &mut lease, timeout).await;
        match &res {
            Ok(_) => {}
            Err(_) => lease.taint(),
        }
        res
    }

    async fn send_inner(
        &self,
        file: &FixedFile,
        mut off: u64,
        len: u64,
        lease: &mut PipeLease,
        timeout: Option<Duration>,
    ) -> crate::Result<u64> {
        let mut sent = 0u64;
        while sent < len {
            let chunk = (len - sent)
                .min(lease.capacity() as u64)
                .min(i32::MAX as u64) as u32;
            // Hop 1: file → pipe. 0 = end of file — a short send, like
            // sendfile(2).
            let hop = self.fs.bridge_splice(
                SpliceEnd::Fixed {
                    slot: file.slot,
                    gen: file.gen,
                },
                off,
                SpliceEnd::Raw(lease.write_end().as_raw_fd()),
                u64::MAX,
                chunk,
                vec![lease.write_end().clone()],
            );
            let filled = Self::clocked(hop, timeout).await?;
            if filled == 0 {
                break;
            }
            off += filled;
            // Hop 2: drain the pipe → socket; `-EAGAIN` (full socket
            // buffer) → park on POLLOUT and resubmit the remainder.
            let mut in_pipe = filled;
            while in_pipe > 0 {
                let hop = self.fs.bridge_splice(
                    SpliceEnd::Raw(lease.read_end().as_raw_fd()),
                    u64::MAX,
                    SpliceEnd::Raw(self.dup.as_raw_fd()),
                    u64::MAX,
                    in_pipe.min(i32::MAX as u64) as u32,
                    vec![lease.read_end().clone(), self.dup.clone()],
                );
                match Self::clocked(hop, timeout).await {
                    Ok(0) => return Err(Errno::EPIPE.into()),
                    Ok(n) => {
                        in_pipe -= n;
                        sent += n;
                    }
                    Err(crate::Error::Errno(Errno::EAGAIN)) => {
                        let poll = self.fs.bridge_poll(
                            self.dup.as_raw_fd(),
                            libc::POLLOUT as u32,
                            self.dup.clone(),
                        );
                        Self::clocked(poll, timeout).await?;
                    }
                    Err(e) => return Err(e),
                }
            }
        }
        Ok(sent)
    }

    /// Send an in-memory payload, zero-copy where it pays: at or above the
    /// ~16 KiB break-even on a plaintext socket, `SEND_ZC` transmits
    /// straight from these pages (pinned until the kernel's release notif —
    /// handled entirely loop-side). Below it, or on a socket that rejects
    /// zero-copy (kTLS: `EOPNOTSUPP` — remembered, and harmless, since SW
    /// kTLS already zero-copies the plaintext input in-kernel), a plain
    /// send runs instead. Full-length-or-error; consumes the payload.
    pub async fn send_zc(
        &mut self,
        data: Vec<u8>,
        timeout: Option<Duration>,
    ) -> crate::Result<usize> {
        let len = data.len();
        if len == 0 {
            return Ok(0);
        }
        let nosig = libc::MSG_NOSIGNAL as u32;
        let waitall = nosig | libc::MSG_WAITALL as u32;
        let mut data = data;
        if !self.zc_denied && len >= ZC_THRESHOLD {
            let send = self.fs.bridge_send(
                self.dup.as_raw_fd(),
                data,
                0,
                waitall,
                true,
                self.dup.clone(),
            );
            let (res, back) = Self::clocked_send(send, timeout).await;
            match res {
                // `MSG_WAITALL` makes the kernel's `min_ret` the full length;
                // a *short* positive result is a partial-then-error
                // (`io_send` returns `done_io` with `req_set_fail`), not a
                // success — honour the full-length-or-error contract. The
                // payload stays pinned loop-side until the notif regardless.
                Ok(n) if n == len => return Ok(n),
                Ok(_) => return Err(Errno::EPIPE.into()),
                Err(crate::Error::Errno(Errno::EOPNOTSUPP)) => {
                    // kTLS (or a socket without SG): fall back for good.
                    self.zc_denied = true;
                    data = back;
                }
                Err(e) => return Err(e),
            }
        }
        if !self.zc_denied {
            // Plaintext plain send: MSG_WAITALL completes full-or-error
            // (io_uring re-arms internally on partials).
            let send = self.fs.bridge_send(
                self.dup.as_raw_fd(),
                data,
                0,
                waitall,
                false,
                self.dup.clone(),
            );
            let (res, back) = Self::clocked_send(send, timeout).await;
            match res {
                Ok(n) if n == len => return Ok(n),
                Ok(_) => return Err(Errno::EPIPE.into()),
                // A kTLS socket rejects `MSG_WAITALL` up front (before any
                // byte is sent → negative `EOPNOTSUPP`, not a short count).
                // This is the first *sub-threshold* send over kTLS, which
                // skipped the ZC attempt that would otherwise set the flag:
                // remember it and fall through to the no-WAITALL loop.
                Err(crate::Error::Errno(Errno::EOPNOTSUPP)) => {
                    self.zc_denied = true;
                    data = back;
                }
                Err(e) => return Err(e),
            }
        }
        // kTLS path: no WAITALL (tls sendmsg rejects it) — resubmit the
        // tail on partial sends; the payload round-trips each completion so
        // nothing is copied.
        let mut start = 0usize;
        while start < len {
            let send = self.fs.bridge_send(
                self.dup.as_raw_fd(),
                data,
                start,
                nosig,
                false,
                self.dup.clone(),
            );
            let (res, back) = Self::clocked_send(send, timeout).await;
            data = back;
            match res {
                Ok(0) => return Err(Errno::EPIPE.into()),
                Ok(n) => start += n,
                Err(e) => return Err(e),
            }
        }
        Ok(len)
    }

    async fn clocked<T>(
        fut: impl Future<Output = crate::Result<T>>,
        timeout: Option<Duration>,
    ) -> crate::Result<T> {
        match timeout {
            None => fut.await,
            Some(d) => match tokio::time::timeout(d, fut).await {
                Ok(r) => r,
                Err(_) => Err(Errno::ETIMEDOUT.into()),
            },
        }
    }

    async fn clocked_send(
        fut: impl Future<Output = (crate::Result<usize>, Vec<u8>)>,
        timeout: Option<Duration>,
    ) -> (crate::Result<usize>, Vec<u8>) {
        match timeout {
            None => fut.await,
            Some(d) => match tokio::time::timeout(d, fut).await {
                Ok(r) => r,
                // The abandoned op still owns (and will free) the payload.
                Err(_) => (Err(Errno::ETIMEDOUT.into()), Vec::new()),
            },
        }
    }
}

impl<S: AsRawFd + Unpin> std::fmt::Debug for Bridge<'_, S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Bridge")
            .field("zc_denied", &self.zc_denied)
            .finish_non_exhaustive()
    }
}
