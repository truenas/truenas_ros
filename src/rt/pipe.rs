//! [`PipePool`]: blocking pipes for the zero-copy bridges.
//!
//! Every bridge transfer moves bytes through one pipe (splice's mandatory
//! intermediary). The pipes are **blocking** on purpose, preserving the
//! contract the net reactor established: `do_splice` promotes an *output*
//! fd's `O_NONBLOCK` into `SPLICE_F_NONBLOCK`, which would make
//! "pipe momentarily full" indistinguishable from "socket empty" — with a
//! blocking pipe the (io-wq) splice simply parks, which is designed
//! backpressure. The bridges bound each hop to the pipe's capacity and
//! drain it fully every cycle, so parking never happens in steady state.
//!
//! A [`PipeLease`] must be **clean** (provably empty: bytes-in ==
//! bytes-out) to return to the pool; an abandoned transfer's pipe may hold
//! stranded bytes, so an unclean lease is discarded (its fds close) and the
//! capacity permit alone returns — the next lease simply creates a fresh
//! pair. The pool is a cache plus a concurrency bound, not a fixed set.

use crate::errno::Errno;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::{Arc, Mutex};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Sizing for a [`PipePool`].
#[derive(Clone, Copy, Debug)]
pub struct PipePoolConfig {
    /// Maximum concurrent bridge transfers (leases).
    pub capacity: usize,
    /// Requested pipe buffer size (`F_SETPIPE_SZ`), which also bounds one
    /// splice hop. Best-effort: clamped by `/proc/sys/fs/pipe-max-size` for
    /// unprivileged processes; the actual grant is what the lease reports.
    pub size: usize,
}

impl Default for PipePoolConfig {
    fn default() -> PipePoolConfig {
        PipePoolConfig {
            capacity: 8,
            size: 256 << 10,
        }
    }
}

struct Pair {
    r: Arc<OwnedFd>,
    w: Arc<OwnedFd>,
    cap: usize,
}

struct PoolInner {
    size: usize,
    sem: Arc<Semaphore>,
    idle: Mutex<Vec<Pair>>,
}

/// A pool of blocking pipes for bridge transfers. Cheap to clone.
#[derive(Clone)]
pub struct PipePool {
    inner: Arc<PoolInner>,
}

impl std::fmt::Debug for PipePool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PipePool")
            .field("size", &self.inner.size)
            .finish_non_exhaustive()
    }
}

impl PipePool {
    /// An empty pool (pipes are created lazily on lease, so construction is
    /// infallible and costs nothing).
    pub(crate) fn new(cfg: PipePoolConfig) -> PipePool {
        PipePool {
            inner: Arc::new(PoolInner {
                size: cfg.size,
                sem: Arc::new(Semaphore::new(cfg.capacity.max(1))),
                idle: Mutex::new(Vec::new()),
            }),
        }
    }

    /// Lease a pipe, waiting when `capacity` transfers are already running.
    pub async fn lease(&self) -> crate::Result<PipeLease> {
        let permit = self
            .inner
            .sem
            .clone()
            .acquire_owned()
            .await
            .expect("pipe semaphore never closed");
        let pair = {
            let mut idle = self
                .inner
                .idle
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            idle.pop()
        };
        let pair = match pair {
            Some(p) => p,
            None => new_pair(self.inner.size)?,
        };
        Ok(PipeLease {
            pair: Some(pair),
            pool: self.inner.clone(),
            clean: true,
            _permit: permit,
        })
    }
}

/// One leased blocking pipe. Starts **clean**; a bridge that may have left
/// bytes stranded (timeout, error mid-transfer) calls
/// `taint`, and a tainted lease is discarded rather than
/// pooled — a pooled pipe is always empty.
pub struct PipeLease {
    pair: Option<Pair>,
    pool: Arc<PoolInner>,
    clean: bool,
    _permit: OwnedSemaphorePermit,
}

impl PipeLease {
    /// The read end (kept alive by the `Arc` for any in-flight op).
    pub(crate) fn read_end(&self) -> &Arc<OwnedFd> {
        &self.pair.as_ref().expect("live lease").r
    }

    /// The write end.
    pub(crate) fn write_end(&self) -> &Arc<OwnedFd> {
        &self.pair.as_ref().expect("live lease").w
    }

    /// The pipe's actual buffer capacity — the bound on one splice hop.
    pub(crate) fn capacity(&self) -> usize {
        self.pair.as_ref().expect("live lease").cap
    }

    /// Mark the pipe possibly-nonempty; it will be discarded, not pooled.
    pub(crate) fn taint(&mut self) {
        self.clean = false;
    }
}

impl std::fmt::Debug for PipeLease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PipeLease")
            .field("clean", &self.clean)
            .finish_non_exhaustive()
    }
}

impl Drop for PipeLease {
    fn drop(&mut self) {
        let pair = self.pair.take().expect("dropped once");
        // Only a provably-empty pipe may be reused; and only if no op still
        // references its ends (an abandoned in-flight splice holds `Arc`
        // clones through the op entry — pooling the pipe then would hand a
        // future transfer a pipe the kernel is still writing into).
        let sole =
            Arc::strong_count(&pair.r) == 1 && Arc::strong_count(&pair.w) == 1;
        if self.clean && sole {
            let mut idle = self
                .pool
                .idle
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            idle.push(pair);
        }
        // Otherwise the ends drop (close) here — or once the last op-held
        // Arc drops — and the released permit lets the next lease build a
        // fresh pair.
    }
}

/// Create a blocking pipe pair and best-effort size it.
fn new_pair(size: usize) -> crate::Result<Pair> {
    let mut fds = [0 as RawFd; 2];
    // SAFETY: `fds` is a valid out-array; O_CLOEXEC only — the pipe must
    // stay BLOCKING (module docs).
    Errno::result(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) })?;
    // SAFETY: pipe2 returned two fresh owned descriptors.
    let (r, w) =
        unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    // Best-effort resize; the return value (or default) is the real bound.
    // SAFETY: plain fcntl on a live fd.
    let got =
        unsafe { libc::fcntl(w.as_raw_fd(), libc::F_SETPIPE_SZ, size as i32) };
    let cap = if got > 0 {
        got as usize
    } else {
        // The kernel default pipe buffer.
        64 << 10
    };
    Ok(Pair {
        r: Arc::new(r),
        w: Arc::new(w),
        cap,
    })
}
