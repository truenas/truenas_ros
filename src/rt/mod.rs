//! The tokio-hybrid runtime: the io_uring filesystem reactor as a
//! process-wide service for a multi-threaded tokio application.
//!
//! Sockets belong to tokio; files belong to the ring. This module packages
//! the existing [`async_fs`](crate::async_fs) reactor — same loop, same op
//! table, same personalities — behind an async handle, so a tokio task
//! awaits filesystem operations instead of blocking a thread on them:
//!
//! - One process-wide ring, owned by one dedicated loop thread (spawned by
//!   [`FsRuntimeBuilder::start`]). Submissions travel over the existing
//!   inject channel + wake eventfd from any thread; completions resolve the
//!   caller's future directly via a oneshot from the loop thread.
//! - [`FsRt`] is the async twin of [`FsHandle`]:
//!   `Clone + Send + Sync`, every operation an `async fn` with the same
//!   validation, personality discipline, and owned-buffer round-trips. The
//!   blocking `FsHandle` keeps working on the same loop — mixed callers are
//!   fine.
//! - Backpressure: an [`FsRt`] holds a semaphore sized to the op table, so
//!   async submitters queue (instead of eating `EBUSY`) when the table is
//!   full. Blocking `FsHandle` callers bypass it and can still observe
//!   `EBUSY` under contention.
//!
//! # Ordering rules (load-bearing)
//!
//! The credential broker must fork **after** the ring exists (it inherits
//! the ring fd — an io_uring fd cannot cross `SCM_RIGHTS`) and **before**
//! the process starts threads. The builder makes that sequence structural:
//!
//! ```no_run
//! use truenas_ros::async_fs::{CredBroker, FsConfig};
//! use truenas_ros::rt::{FsRuntime, FsRuntimeBuilder};
//!
//! // main(), before any thread (and before the tokio runtime) exists:
//! let builder = FsRuntimeBuilder::new(FsConfig::default())?; // ring exists
//! let broker = CredBroker::spawn(&[builder.reactor()])?;     // fork-inherit
//! let me = builder.register_self()?;                         // daemon creds
//! let fs_rt = builder.start()?;                              // loop thread
//! let fs_rt = FsRuntime::init_global(fs_rt)
//!     .unwrap_or_else(|_| panic!("global fs runtime initialized twice"));
//!
//! // ... now build the tokio runtime and serve. (Any runtime works — in a
//! // real daemon this is your multi-thread `#[tokio::main]`; the library's
//! // own tokio dependency carries only the primitive features.)
//! let rt = tokio::runtime::Builder::new_current_thread()
//!     .enable_all()
//!     .build()
//!     .expect("tokio runtime");
//! rt.block_on(async {
//!     let fs = fs_rt.rt();
//!     let anchor = truenas_ros::async_fs::Anchor::open("/tank/share")?;
//!     let how = truenas_ros::sync_fs::OpenHow::new()
//!         .flags(truenas_ros::sync_fs::OFlag::O_RDONLY);
//!     let f = fs.open(me, &anchor, "docs/readme.txt", how).await?;
//!     let (n, buf) = fs.pread(me, &f, vec![0u8; 4096], 0).await;
//!     let _ = (n?, buf);
//!     fs.close(f).await?;
//!     Ok::<(), truenas_ros::Error>(())
//! })?;
//! # let _ = broker;
//! # Ok::<(), truenas_ros::Error>(())
//! ```
//!
//! # Cancel-safety
//!
//! Dropping an [`FsRt`] future abandons the *result*, never the operation:
//! the op runs to completion on the reactor, and its buffers, anchors, and
//! backpressure permit stay owned loop-side until the CQE reaps — exactly
//! the discipline the blocking surface has. A [`FixedFile`] dropped from a
//! task injects its own close, as always.
//!
//! [`FixedFile`]: crate::async_fs::FixedFile

mod bridge;
mod buf;
mod framed;
mod fs;
#[cfg(feature = "rt-ktls")]
mod ktls;
mod pipe;
mod serve;

pub use bridge::Bridge;
pub use buf::{BufPool, BufPoolConfig, PooledBuf};
pub use framed::{write_frame, Frame, FrameReader};
pub use fs::{DirectFile, FsRt};
#[cfg(feature = "rt-ktls")]
pub use ktls::KtlsStream;
#[cfg(feature = "rt-tls-openssl")]
pub use ktls::{ktls_client_handshake, ktls_server_handshake};
pub use pipe::{PipeLease, PipePool, PipePoolConfig};
pub use serve::{serve, ServeOptions};

use crate::async_fs::{
    AsyncFs, FsConfig, FsHandle, Personality, ShutdownHandle,
};
use crate::errno::Errno;
use std::sync::{Arc, Mutex, OnceLock};
use std::thread::JoinHandle;
use tokio::sync::Semaphore;

/// Moves the `!Send` [`AsyncFs`] into the loop thread at
/// [`FsRuntimeBuilder::start`].
///
/// SAFETY: `AsyncFs` is `!Send` only transitively, through `Ring`'s raw
/// pointers into the ring's process-wide mmap — a single-driver discipline
/// marker, not a thread affinity: io_uring binds nothing to the creating
/// task unless `IORING_SETUP_SINGLE_ISSUER` is set, which this crate
/// deliberately never sets (pinned by
/// `single_issuer_gates_cross_thread_registration`), and off-thread
/// `io_uring_register` is an already-supported pattern (the credential
/// broker registers personalities from a forked process). This wrapper
/// transfers *ownership once, before the loop runs*: the builder thread
/// staged no SQEs (construction probes use `io_uring_register` or a
/// throwaway ring), the op and file tables are empty — so no `!Send`
/// payload (an embedded callback, which only an embedding host would park;
/// none ships in-tree) can exist inside — and after the move only the loop
/// thread touches the value. Exclusive handoff, never sharing.
struct LoopSeed(AsyncFs);
unsafe impl Send for LoopSeed {}

impl LoopSeed {
    /// By-value method (rather than field destructuring in the spawn
    /// closure) so edition-2021 precise capture moves the whole `LoopSeed` —
    /// the type carrying the `Send` assertion — and not the `!Send`
    /// `AsyncFs` field directly.
    fn into_inner(self) -> AsyncFs {
        self.0
    }
}

/// Builds the process-wide fs runtime in the order the credential broker
/// requires: ring first (construction), broker fork next (via
/// [`reactor`](FsRuntimeBuilder::reactor), while the process is still
/// single-threaded), loop thread last ([`start`](FsRuntimeBuilder::start)).
#[derive(Debug)]
pub struct FsRuntimeBuilder {
    afs: AsyncFs,
    ops: u32,
    bufs: Option<BufPool>,
    pipes: pipe::PipePoolConfig,
}

impl FsRuntimeBuilder {
    /// Build the ring, tables, and kernel probes — nothing runs yet. Same
    /// validation and errors as [`AsyncFs::new`].
    pub fn new(cfg: FsConfig) -> crate::Result<FsRuntimeBuilder> {
        Ok(FsRuntimeBuilder {
            afs: AsyncFs::new(cfg)?,
            ops: cfg.ops,
            bufs: None,
            pipes: pipe::PipePoolConfig::default(),
        })
    }

    /// Size the bridge pipe pool (defaults: 8 concurrent transfers × 256 KiB
    /// pipes). Pipes are created lazily, so this only sets bounds.
    pub fn with_pipes(mut self, cfg: PipePoolConfig) -> FsRuntimeBuilder {
        self.pipes = cfg;
        self
    }

    /// Register a [`BufPool`] on this ring — the zero-copy tier's registered
    /// buffers, leased via [`FsRuntime::bufs`] and consumed by
    /// [`FsRt::read_fixed`]/[`FsRt::write_fixed`]. Opt-in: filled slots pin
    /// pages against `RLIMIT_MEMLOCK`.
    pub fn with_buffers(
        mut self,
        cfg: BufPoolConfig,
    ) -> crate::Result<FsRuntimeBuilder> {
        // The pool owns a dup of the ring fd so growth keeps working for its
        // whole life, independent of the reactor's own descriptor.
        // SAFETY: F_DUPFD_CLOEXEC on a live fd; the result is a fresh fd.
        let raw = Errno::result(unsafe {
            libc::fcntl(self.afs.ring_fd(), libc::F_DUPFD_CLOEXEC, 0)
        })?;
        // SAFETY: fcntl(F_DUPFD_CLOEXEC) returned a fresh owned descriptor.
        let dup = unsafe { crate::fd::owned_from_raw(raw) };
        self.bufs = Some(BufPool::register(dup, cfg)?);
        Ok(self)
    }

    /// The not-yet-started reactor, for pre-start setup — above all
    /// `CredBroker::spawn(&[builder.reactor()])`, which must run after the
    /// ring exists (the forked child inherits the ring fd) and before any
    /// thread is spawned, [`start`](FsRuntimeBuilder::start) included.
    pub fn reactor(&self) -> &AsyncFs {
        &self.afs
    }

    /// Register the calling process's **current** credentials as a
    /// [`Personality`] — passthrough to [`AsyncFs::register_self`], usable
    /// before the loop starts.
    pub fn register_self(&self) -> crate::Result<Personality> {
        self.afs.register_self()
    }

    /// Spawn the dedicated loop thread and return the shareable runtime.
    /// The loop runs until [`FsRuntime::shutdown`] (or the last
    /// [`FsRuntime`] clone dropping) stops it.
    pub fn start(self) -> crate::Result<FsRuntime> {
        let handle = self.afs.handle();
        let stop = self.afs.shutdown_handle();
        let seed = LoopSeed(self.afs);
        let join = std::thread::Builder::new()
            .name("truenas-ros-fs".into())
            .spawn(move || {
                let mut afs = seed.into_inner();
                afs.run()
            })
            .map_err(|e| {
                crate::Error::from(
                    e.raw_os_error().map(Errno::from_raw).unwrap_or(
                        // Thread creation failed without an OS code.
                        Errno::EAGAIN,
                    ),
                )
            })?;
        Ok(FsRuntime {
            inner: Arc::new(RtInner {
                handle,
                stop,
                sem: Arc::new(Semaphore::new(self.ops as usize)),
                bufs: self.bufs,
                pipes: pipe::PipePool::new(self.pipes),
                join: Mutex::new(Some(join)),
            }),
        })
    }
}

struct RtInner {
    handle: FsHandle,
    stop: ShutdownHandle,
    /// Async-submitter backpressure, sized to the op table; permits ride
    /// inside each inject's reply endpoint and release at delivery.
    sem: Arc<Semaphore>,
    /// The registered-buffer pool, when the builder opted in.
    bufs: Option<BufPool>,
    /// Blocking pipes for the bridges (lazily created, bounded).
    pipes: PipePool,
    join: Mutex<Option<JoinHandle<crate::Result<()>>>>,
}

impl Drop for RtInner {
    fn drop(&mut self) {
        // Last runtime clone gone without an explicit shutdown(): stop the
        // loop so its thread exits (the armed wake keeps `inflight` nonzero,
        // so without this the loop would park forever). Deliberately no
        // join — drop may run inside an async context; the loop thread
        // finishes on its own promptly after the stop+poke.
        self.stop.shutdown();
    }
}

/// The process-wide fs runtime: a handle to the loop thread spawned by
/// [`FsRuntimeBuilder::start`]. Cheap to clone; mint per-task [`FsRt`]s
/// with [`rt`](FsRuntime::rt).
#[derive(Clone)]
pub struct FsRuntime {
    inner: Arc<RtInner>,
}

impl std::fmt::Debug for FsRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FsRuntime").finish_non_exhaustive()
    }
}

static GLOBAL: OnceLock<FsRuntime> = OnceLock::new();

impl FsRuntime {
    /// Install `rt` as the process-wide runtime reachable via
    /// [`FsRuntime::global`]. Returns the installed reference, or hands the
    /// runtime back if a global was already installed (the caller decides
    /// whether that is a bug or a benign race). Tests should prefer plain
    /// non-global runtimes.
    pub fn init_global(rt: FsRuntime) -> Result<&'static FsRuntime, FsRuntime> {
        match GLOBAL.set(rt) {
            Ok(()) => Ok(GLOBAL.get().expect("just set")),
            Err(rt) => Err(rt),
        }
    }

    /// The installed process-wide runtime, if [`init_global`]
    /// (FsRuntime::init_global) ran.
    ///
    /// [`init_global`]: FsRuntime::init_global
    pub fn global() -> Option<&'static FsRuntime> {
        GLOBAL.get()
    }

    /// An async operations handle (`Clone + Send + Sync`) for tokio tasks.
    pub fn rt(&self) -> FsRt {
        FsRt::new(self.inner.handle.clone(), self.inner.sem.clone())
    }

    /// The blocking [`FsHandle`], served by the same loop — for
    /// non-async threads living alongside the tokio runtime.
    pub fn handle(&self) -> FsHandle {
        self.inner.handle.clone()
    }

    /// The registered-buffer pool, when the builder opted in
    /// ([`FsRuntimeBuilder::with_buffers`]).
    pub fn bufs(&self) -> Option<&BufPool> {
        self.inner.bufs.as_ref()
    }

    /// The bridge pipe pool ([`Bridge`] leases from it; sized by
    /// [`FsRuntimeBuilder::with_pipes`]).
    pub fn pipes(&self) -> &PipePool {
        &self.inner.pipes
    }

    /// Stop the loop and join its thread, returning the loop's own result.
    /// **Blocking** (it joins a thread): call from a synchronous context —
    /// `main` after the tokio runtime is done, or `spawn_blocking`.
    /// Idempotent; a second call (or a call racing the last-clone drop)
    /// returns `Ok(())`.
    pub fn shutdown(&self) -> crate::Result<()> {
        self.inner.stop.shutdown();
        let join = self
            .inner
            .join
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        match join {
            Some(j) => j.join().map_err(|_| {
                crate::Error::Validation("fs loop thread panicked".into())
            })?,
            None => Ok(()),
        }
    }
}
