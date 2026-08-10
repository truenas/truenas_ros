//! [`query_directory`]: a **pull-based**, batched directory listing with
//! configurable per-entry enrichment, over the blocking [`FsHandle`].
//!
//! There is no io_uring `getdents`/`readdir` op, so the **name feed** is a
//! `readdir` pass over the directory fd on the caller's own thread (no worker,
//! no channel). [`QueryDir::next`] reads the next `clump` names, then enriches
//! them by **scattering non-blocking reactor ops** — `statx` (path-based) and
//! `fgetxattr` on an opened entry fd — through the [`FsHandle`] `start_*` twins:
//! all of a clump's ops are submitted before any is waited on, so they run
//! concurrently on the ring. The directory `DIR*` is held open across `next`
//! calls (incremental; nothing is buffered up front) and closed on `Drop`.
//!
//! The directory is opened **under the caller's [`Personality`]** — that open
//! is the DAC/list-permission check (`EACCES` if `who` cannot list), so
//! enumeration never runs under the reactor's ambient root.
//!
//! Entries come in raw `readdir` order (unsorted); a caller needing S3-style
//! lexicographic order sorts each page itself.

use super::{Anchor, File, FsHandle, FsPending, Leaf, Personality};
use crate::errno::{retry_on_eintr, Errno};
use crate::sync_fs::{AtFlags, OFlag, OpenHow, Statx, StatxMask};
use bitflags::bitflags;
use std::collections::VecDeque;
use std::ffi::{CStr, CString, OsStr, OsString};
use std::fmt;
use std::os::fd::RawFd;
use std::os::unix::ffi::OsStrExt;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

bitflags! {
    /// What to fetch for each directory entry. `STATX` is cheap (a path-based
    /// `statx`, no open); `XATTR`/`ACL` open the entry `O_RDONLY|O_NOFOLLOW` and
    /// `fgetxattr` it.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct EnrichSpec: u8 {
        /// size / mtime / type via a path-based `statx`.
        const STATX = 0b0001;
        /// the named extended attributes in [`QueryOptions::xattr_names`].
        const XATTR = 0b0010;
        /// the ACL extended attribute in [`QueryOptions::acl_name`]
        /// (`system.nfs4_acl_xdr` on ZFS, or `system.posix_acl_access`).
        const ACL = 0b0100;
    }
}

/// How to run a [`query_directory`] walk.
#[derive(Clone, Debug)]
pub struct QueryOptions {
    /// Which per-entry metadata to fetch.
    pub spec: EnrichSpec,
    /// Extended attributes to fetch when [`EnrichSpec::XATTR`] is set.
    pub xattr_names: Vec<CString>,
    /// The ACL xattr name to fetch when [`EnrichSpec::ACL`] is set.
    pub acl_name: CString,
    /// Entries per yielded batch (clamped to at least 1).
    pub clump: usize,
}

/// One enriched directory entry. Which fields are populated depends on the
/// [`EnrichSpec`]; a field is `None`/empty when not requested or unavailable.
#[derive(Clone, Debug)]
pub struct DirEntry {
    /// The entry name (a single path component).
    pub name: OsString,
    /// True if the entry is a directory (from `statx`, else the `readdir`
    /// `d_type` hint).
    pub is_dir: bool,
    /// `statx` metadata, when [`EnrichSpec::STATX`] was requested and succeeded.
    pub statx: Option<Statx>,
    /// Requested xattrs, in request order: `(name, value)`; `value` is `None`
    /// when the attribute is absent (or the entry could not be opened).
    pub xattrs: Vec<(CString, Option<Vec<u8>>)>,
    /// The ACL xattr value, when [`EnrichSpec::ACL`] was requested and present.
    pub acl: Option<Vec<u8>>,
}

/// A running directory query. Pull enriched batches with [`next`](QueryDir::next)
/// until it returns `None` (end of directory). Dropping it closes the directory.
///
/// Not `Send` (it owns a `DIR*`, whose `readdir` cursor is single-threaded);
/// use it on the thread that created it.
pub struct QueryDir {
    dp: *mut libc::DIR,
    h: FsHandle,
    who: Personality,
    dir: Anchor,
    opts: QueryOptions,
}

impl fmt::Debug for QueryDir {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QueryDir")
            .field("fd", &self.dir_fd())
            .field("spec", &self.opts.spec)
            .finish_non_exhaustive()
    }
}

impl QueryDir {
    /// The descriptor being read (the `fdopendir` dup); closed when this
    /// `QueryDir` drops. For diagnostics / tests.
    pub fn dir_fd(&self) -> RawFd {
        // SAFETY: `dp` is a live `DIR*` for this handle's lifetime.
        unsafe { libc::dirfd(self.dp) }
    }

    /// The next enriched batch of up to `clump` entries, or `None` at
    /// end-of-directory. A `readdir` error surfaces as `Some(Err)`.
    // Inherent `next`, not `Iterator`: `QueryDir` owns a `!Send` `DIR*` and
    // yields fallible batches the caller drives.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Option<crate::Result<Vec<DirEntry>>> {
        match self.read_clump() {
            Ok(names) if names.is_empty() => None,
            Ok(names) => Some(Ok(self.enrich(names))),
            Err(e) => Some(Err(e)),
        }
    }

    /// Read up to `clump` entry names (with their `d_type`), skipping `.`/`..`.
    /// Fewer than `clump` (or an empty `Vec`) marks end-of-directory.
    fn read_clump(&mut self) -> crate::Result<Vec<(OsString, u8)>> {
        let clump = self.opts.clump;
        let mut out = Vec::with_capacity(clump);
        while out.len() < clump {
            Errno::clear();
            // SAFETY: `dp` is a live `DIR*`; the returned pointer is valid until
            // the next `readdir`/`closedir` — copied out immediately below.
            let ent = unsafe { libc::readdir(self.dp) };
            if ent.is_null() {
                return match Errno::last_raw() {
                    0 => Ok(out), // end of directory
                    _ => Err(Errno::last().into()),
                };
            }
            // SAFETY: `ent` is a valid `dirent`; `d_name` is NUL-terminated.
            // `addr_of!` avoids forming a `&[c_char; 256]` over a record that
            // may be shorter than the full array.
            let (bytes, dtype) = unsafe {
                let name = CStr::from_ptr(
                    std::ptr::addr_of!((*ent).d_name).cast::<libc::c_char>(),
                );
                (name.to_bytes().to_vec(), (*ent).d_type)
            };
            if bytes == b"." || bytes == b".." {
                continue;
            }
            out.push((OsStr::from_bytes(&bytes).to_os_string(), dtype));
        }
        Ok(out)
    }

    /// Enrich a clump: scatter `statx`+`open` for every entry (phase 1),
    /// collect the results and opened fds, then scatter `fgetxattr` for every
    /// opened fd (phase 2), collect, and assemble. Every op runs under `who`;
    /// each phase submits all its ops before waiting on any, so they overlap on
    /// the ring.
    fn enrich(&self, names: Vec<(OsString, u8)>) -> Vec<DirEntry> {
        let who = self.who;
        let spec = self.opts.spec;

        // Phase 1: submit statx + open for every entry.
        let phase1: Vec<Scattered1> = names
            .into_iter()
            .map(|(name, dtype)| {
                let statx = if spec.contains(EnrichSpec::STATX) {
                    Leaf::new(name.as_bytes()).ok().and_then(|leaf| {
                        self.h
                            .start_statx(
                                who,
                                &self.dir,
                                leaf,
                                AtFlags::AT_SYMLINK_NOFOLLOW,
                                StatxMask::BASIC_STATS,
                            )
                            .ok()
                    })
                } else {
                    None
                };
                let open = if spec
                    .intersects(EnrichSpec::XATTR | EnrichSpec::ACL)
                {
                    let how = OpenHow::new()
                        .flags(OFlag::O_RDONLY | OFlag::O_NOFOLLOW);
                    self.h.start_open(who, &self.dir, name.as_bytes(), how).ok()
                } else {
                    None
                };
                Scattered1 {
                    name,
                    dtype,
                    statx,
                    open,
                }
            })
            .collect();

        // Phase 1 collect: statx result + opened File per entry.
        let opened: Vec<Opened> = phase1
            .into_iter()
            .map(|p| {
                let statx = p.statx.and_then(pending_statx);
                let is_dir = statx
                    .as_ref()
                    .map(Statx::is_dir)
                    .unwrap_or(p.dtype == libc::DT_DIR);
                let file = p.open.and_then(pending_file);
                Opened {
                    name: p.name,
                    is_dir,
                    statx,
                    file,
                }
            })
            .collect();

        // Phase 2: submit fgetxattr for every opened file.
        let phase2: Vec<Scattered2> = opened
            .into_iter()
            .map(|p| {
                let mut xattrs = Vec::new();
                let mut acl = None;
                match &p.file {
                    Some(f) => {
                        if spec.contains(EnrichSpec::XATTR) {
                            for xn in &self.opts.xattr_names {
                                let pend = self
                                    .h
                                    .start_fgetxattr(
                                        who,
                                        f,
                                        xn,
                                        vec![0u8; 4096],
                                    )
                                    .ok();
                                xattrs.push((xn.clone(), pend));
                            }
                        }
                        if spec.contains(EnrichSpec::ACL) {
                            acl = self
                                .h
                                .start_fgetxattr(
                                    who,
                                    f,
                                    &self.opts.acl_name,
                                    vec![0u8; 65536],
                                )
                                .ok();
                        }
                    }
                    None if spec.contains(EnrichSpec::XATTR) => {
                        for xn in &self.opts.xattr_names {
                            xattrs.push((xn.clone(), None));
                        }
                    }
                    None => {}
                }
                Scattered2 {
                    name: p.name,
                    is_dir: p.is_dir,
                    statx: p.statx,
                    _file: p.file,
                    xattrs,
                    acl,
                }
            })
            .collect();

        // Phase 2 collect + assemble. `_file` drops here — its fd closed once
        // its xattr ops completed (each parked its own `Arc` until its CQE).
        phase2
            .into_iter()
            .map(|p| {
                let xattrs = p
                    .xattrs
                    .into_iter()
                    .map(|(xn, pend)| (xn, pend.and_then(pending_bytes)))
                    .collect();
                let acl = p.acl.and_then(pending_bytes);
                DirEntry {
                    name: p.name,
                    is_dir: p.is_dir,
                    statx: p.statx,
                    xattrs,
                    acl,
                }
            })
            .collect()
    }
}

impl Drop for QueryDir {
    fn drop(&mut self) {
        // SAFETY: `dp` is a live `DIR*` from `fdopendir`, closed exactly once;
        // this also closes the underlying dup fd.
        unsafe { libc::closedir(self.dp) };
    }
}

// Per-entry state threaded between the two scatter phases.
struct Scattered1 {
    name: OsString,
    dtype: u8,
    statx: Option<FsPending>,
    open: Option<FsPending>,
}
struct Opened {
    name: OsString,
    is_dir: bool,
    statx: Option<Statx>,
    file: Option<File>,
}
struct Scattered2 {
    name: OsString,
    is_dir: bool,
    statx: Option<Statx>,
    // Held until its xattr ops were submitted; the ops park their own clones,
    // so the fd survives to completion regardless.
    _file: Option<File>,
    xattrs: Vec<(CString, Option<FsPending>)>,
    acl: Option<FsPending>,
}

/// Await a `statx` twin: `Some(Statx)` on success, else `None`.
fn pending_statx(p: FsPending) -> Option<Statx> {
    let out = p.into_outcome().ok()?;
    out.res.ok()?;
    out.stat.map(|raw| Statx::from_raw(*raw))
}

/// Await an `open` twin: the opened [`File`] on success, else `None`.
fn pending_file(p: FsPending) -> Option<File> {
    let out = p.into_outcome().ok()?;
    out.res.ok()?;
    out.file.map(File::new)
}

/// Await an `fgetxattr` twin: the attribute value (truncated to its size), else
/// `None` (absent / error / gone loop).
fn pending_bytes(p: FsPending) -> Option<Vec<u8>> {
    let out = p.into_outcome().ok()?;
    let n = out.res.ok()? as usize;
    let buf = out.bufs.into_iter().next()?;
    buf.get(..n).map(<[u8]>::to_vec)
}

/// Start listing `dir` as `who`, enriching each entry per `opts`. Opening the
/// directory `O_RDONLY|O_DIRECTORY` under `who` **is** the list-permission
/// check — returns `EACCES` when `who` cannot list `dir`. Pull enriched batches
/// with [`QueryDir::next`].
pub fn query_directory(
    h: &FsHandle,
    who: Personality,
    dir: &Anchor,
    opts: QueryOptions,
) -> crate::Result<QueryDir> {
    // The anchor is an `O_PATH` dirfd, which neither requires nor implies list
    // permission; open it readable under `who` so the kernel enforces DAC. `.`
    // resolves to the anchor itself, confined by the default `RESOLVE_BENEATH`.
    let list_how = OpenHow::new().flags(OFlag::O_RDONLY | OFlag::O_DIRECTORY);
    let dir_read = h.open(who, dir, ".", list_how)?;

    // `fdopendir`/`closedir` take ownership of the fd, so hand them a dup —
    // `dir_read` then drops here, closing its own fd; the `DIR*` owns the dup.
    // SAFETY: `dir_read` is a live fd for the dup call.
    let dup = retry_on_eintr(|| unsafe { libc::dup(dir_read.as_raw_fd()) })?;
    // SAFETY: `dup` is a fresh owned fd; `fdopendir` takes ownership of it.
    let dp = unsafe { libc::fdopendir(dup) };
    if dp.is_null() {
        let e = Errno::last();
        // SAFETY: `fdopendir` failed, so `dup` is still ours to close.
        unsafe { libc::close(dup) };
        return Err(e.into());
    }

    Ok(QueryDir {
        dp,
        h: h.clone(),
        who,
        dir: dir.clone(),
        opts: QueryOptions {
            clump: opts.clump.max(1),
            ..opts
        },
    })
}

// ---- QueryPool: a std worker pool over the pull-based `query_directory` -----

/// A boxed unit of work a pool worker runs. Every job is `Send` and
/// self-contained (it captures its own inputs and result channel), so the pool
/// is generic — the `!Send` [`QueryDir`] is built and driven *inside* the job,
/// on the worker's own thread, never sent.
type Job = Box<dyn FnOnce() + Send>;

/// Growth is rate-limited to at most one new worker per this interval, so a
/// burst of microsecond-fast jobs that momentarily saturates the pool does not
/// spawn a thread per job; sustained blocking work still grows to the ceiling.
const OFFLOAD_SPAWN_COOLDOWN: Duration = Duration::from_millis(1);
/// A burst worker idle this long retires, back down to the floor.
const OFFLOAD_IDLE_TIMEOUT: Duration = Duration::from_secs(10);

struct PoolInner {
    queue: VecDeque<Job>,
    /// Live worker threads: the floor plus any grown-in burst workers.
    total: usize,
    /// The pool is dropping; workers drain the queue, then exit.
    closed: bool,
}

struct PoolShared {
    inner: Mutex<PoolInner>,
    /// Signals a queued job, a shutdown, or a worker exit (`Drop` waits on it).
    cv: Condvar,
    /// Workers currently executing a job; `running == total` means saturated.
    running: AtomicUsize,
    floor: usize,
    ceiling: usize,
    epoch: Instant,
    /// Micros since `epoch` of the last spawn, throttling growth.
    last_spawn_us: AtomicU64,
    cooldown: Duration,
    idle_timeout: Duration,
}

/// An elastic pool of worker threads running `Box<dyn FnOnce() + Send>` jobs,
/// the shared machinery behind both the off-loop [`QueryPool`] helpers and the
/// on-loop `FsConn::offload` path. It keeps `floor` threads warm and grows to
/// `ceiling` when every worker is busy (blocked on a slow `readdir` or copy),
/// so one stalled walk does not head-of-line-block the rest; burst workers
/// retire after an idle period. It runs whatever job it is handed under the
/// reactor's ambient credentials; any per-`who` permission check belongs to the
/// job, not the pool.
///
/// Growth is hysteretic: a worker spawns only when the pool is saturated
/// (`running == total`) and at most once per cooldown, so a burst of fast
/// cached jobs clears without thread churn while genuinely blocking work grows.
/// Dropping the pool closes the queue and waits for every worker to exit, so no
/// detached worker outlives the state it borrows.
pub(crate) struct WorkerPool {
    shared: Arc<PoolShared>,
}

impl WorkerPool {
    /// A fixed pool of `workers` (at least 1) threads that never grows
    /// (`floor == ceiling`). Panics if a thread cannot be spawned, for off-loop
    /// callers that build the pool up front ([`QueryPool::new`]).
    pub(crate) fn new(workers: usize) -> WorkerPool {
        Self::try_elastic(workers, workers).expect("spawn fs worker")
    }

    /// An elastic pool: `floor` (at least 1) warm threads growing to `ceiling`
    /// under saturation, using the default cooldown and idle timeout. Returns
    /// the spawn error rather than panicking.
    pub(crate) fn try_elastic(
        floor: usize,
        ceiling: usize,
    ) -> std::io::Result<WorkerPool> {
        Self::try_elastic_tuned(
            floor,
            ceiling,
            OFFLOAD_SPAWN_COOLDOWN,
            OFFLOAD_IDLE_TIMEOUT,
        )
    }

    /// [`try_elastic`](Self::try_elastic) with explicit timings (for tests). On
    /// a partial spawn failure the workers already started are shut down and
    /// waited for before returning, so none is orphaned.
    pub(crate) fn try_elastic_tuned(
        floor: usize,
        ceiling: usize,
        cooldown: Duration,
        idle_timeout: Duration,
    ) -> std::io::Result<WorkerPool> {
        let floor = floor.max(1);
        let ceiling = ceiling.max(floor);
        let shared = Arc::new(PoolShared {
            inner: Mutex::new(PoolInner {
                queue: VecDeque::new(),
                total: 0,
                closed: false,
            }),
            cv: Condvar::new(),
            running: AtomicUsize::new(0),
            floor,
            ceiling,
            epoch: Instant::now(),
            last_spawn_us: AtomicU64::new(0),
            cooldown,
            idle_timeout,
        });
        let pool = WorkerPool {
            shared: Arc::clone(&shared),
        };
        for _ in 0..floor {
            {
                let mut g =
                    shared.inner.lock().unwrap_or_else(|e| e.into_inner());
                g.total += 1; // account the worker before it can exit
            }
            if let Err(e) = spawn_worker(&shared) {
                {
                    let mut g =
                        shared.inner.lock().unwrap_or_else(|e| e.into_inner());
                    g.total -= 1;
                }
                drop(pool); // closes and waits for the workers already started
                return Err(e);
            }
        }
        Ok(pool)
    }

    /// Enqueue `job`, growing the pool by one worker if it is saturated and the
    /// cooldown has elapsed (a no-op if the pool is already dropping).
    pub(crate) fn submit(&self, job: Job) {
        let grow = {
            let mut g =
                self.shared.inner.lock().unwrap_or_else(|e| e.into_inner());
            if g.closed {
                return;
            }
            g.queue.push_back(job);
            self.shared.cv.notify_one();
            let saturated =
                self.shared.running.load(Ordering::Relaxed) >= g.total;
            let grow = saturated
                && g.total < self.shared.ceiling
                && self.shared.claim_spawn_slot();
            if grow {
                g.total += 1; // reserve the slot before releasing the lock
            }
            grow
        };
        if grow && spawn_worker(&self.shared).is_err() {
            // Spawn failed: return the reserved slot. The job still runs when a
            // busy worker frees up.
            let mut g =
                self.shared.inner.lock().unwrap_or_else(|e| e.into_inner());
            g.total -= 1;
        }
    }
}

impl PoolShared {
    /// True at most once per [`cooldown`](Self::cooldown), claiming the slot so
    /// concurrent submits do not all spawn at once.
    fn claim_spawn_slot(&self) -> bool {
        let now = self.epoch.elapsed().as_micros() as u64;
        let cooldown = self.cooldown.as_micros() as u64;
        let last = self.last_spawn_us.load(Ordering::Relaxed);
        now.saturating_sub(last) >= cooldown
            && self
                .last_spawn_us
                .compare_exchange(
                    last,
                    now,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                )
                .is_ok()
    }
}

impl Drop for WorkerPool {
    fn drop(&mut self) {
        let mut g = self.shared.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.closed = true;
        self.shared.cv.notify_all();
        // Wait for every worker to drain and exit, so none touches the shared
        // state after this returns (join-on-drop without tracking handles).
        while g.total > 0 {
            g = self.shared.cv.wait(g).unwrap_or_else(|e| e.into_inner());
        }
    }
}

/// Spawn one worker thread bound to `shared`. The caller has already accounted
/// it in `total`; the worker decrements `total` when it exits.
fn spawn_worker(shared: &Arc<PoolShared>) -> std::io::Result<()> {
    let shared = Arc::clone(shared);
    thread::Builder::new()
        .name("truenas-fs-worker".into())
        .spawn(move || worker_loop(&shared))
        .map(|_| ())
}

/// A [`WorkerPool`] bound to an [`FsHandle`] for the off-loop directory-listing
/// ([`query`](QueryPool::query)) and byte-range copy
/// ([`copy_file_range`](QueryPool::copy_file_range)) helpers. Each method
/// enqueues a job and returns immediately with a handle; up to `workers` jobs
/// run concurrently, so one caller thread can fan out many and then collect
/// them.
///
/// A walk opens its directory under its own `who` (the list-permission check),
/// so `EACCES` surfaces as an error batch rather than a listing taken under the
/// reactor's ambient credentials.
pub struct QueryPool {
    pool: WorkerPool,
    h: FsHandle,
}

impl QueryPool {
    /// Build a pool of `workers` (at least 1) threads over `h` (cloned cheaply
    /// per job — the handle just shares the one loop).
    pub fn new(h: FsHandle, workers: usize) -> QueryPool {
        QueryPool {
            pool: WorkerPool::new(workers),
            h,
        }
    }

    /// Enqueue `job` (a no-op if the pool is already dropping).
    fn submit(&self, job: Job) {
        self.pool.submit(job);
    }

    /// Enqueue a listing of `dir` as `who` and return immediately. Pull its
    /// enriched batches from the [`QueryHandle`]. Non-blocking — just enqueues.
    pub fn query(
        &self,
        who: Personality,
        dir: Anchor,
        opts: QueryOptions,
    ) -> QueryHandle {
        let (out, rx) = mpsc::channel();
        let h = self.h.clone();
        self.submit(Box::new(move || {
            match query_directory(&h, who, &dir, opts) {
                Ok(mut q) => {
                    while let Some(batch) = q.next() {
                        if out.send(batch).is_err() {
                            break; // the caller dropped its QueryHandle
                        }
                    }
                }
                // A failed open (e.g. `EACCES` — the list-permission check)
                // surfaces as a single error batch.
                Err(e) => {
                    let _ = out.send(Err(e));
                }
            }
        }));
        QueryHandle { rx }
    }

    /// Copy `len` bytes from `src[off_src..]` to `dst[off_dst..]`. First tries an
    /// **inline block clone** (`FICLONERANGE`) on the caller's thread —
    /// metadata-only on a reflink-capable filesystem (ZFS
    /// `feature@block_cloning`: a block-pointer copy + BRT refcount, no data
    /// I/O), so it moves nothing and returns a resolved [`CopyHandle`]. If the
    /// clone is rejected (misaligned, unsupported, or cross-dataset), a real
    /// byte copy is **offloaded to the pool** and the handle is pending;
    /// `src`/`dst` clone into the job (`File` is `Send`) so their fds stay open.
    /// Either way, [`CopyHandle::wait`] yields the bytes copied.
    pub fn copy_file_range(
        &self,
        src: &File,
        dst: &File,
        off_src: u64,
        off_dst: u64,
        len: u64,
    ) -> CopyHandle {
        // 1. Inline `FICLONERANGE`: on ZFS this is metadata-only (no data I/O),
        //    so run it here, not on the pool — there is no io_uring op for it
        //    (a direct `ioctl`). Caveat: a freshly written, still-dirty source
        //    with `zfs_bclone_wait_dirty=1` can make this wait ~5s for a TXG
        //    sync (`zfs_vnops.c`); an existing/synced source won't.
        let fcr = FileCloneRange {
            src_fd: src.as_raw_fd() as i64,
            src_offset: off_src,
            src_length: len,
            dest_offset: off_dst,
        };
        // SAFETY: `dst`/`src` are live fds (held by the caller's `File`s); `&fcr`
        // is a valid `file_clone_range` for the ioctl's duration.
        let cloned =
            unsafe { libc::ioctl(dst.as_raw_fd(), FICLONERANGE, &fcr) };
        if cloned == 0 {
            // Clone succeeded — no bytes moved; `len` now shares blocks.
            return CopyHandle::Ready(Ok(len));
        }
        // 2. Clone rejected (misaligned `EINVAL`, `EOPNOTSUPP`, cross-dataset
        //    `EXDEV`, dirty-no-wait `EAGAIN`, …) → offload a real byte copy
        //    (clone-first `copy_file_range` with an `EXDEV` byte-copy fallback).
        let (out, rx) = mpsc::channel();
        let src = src.clone();
        let dst = dst.clone();
        self.submit(Box::new(move || {
            let res = copy_file_range_blocking(
                src.as_raw_fd(),
                dst.as_raw_fd(),
                off_src,
                off_dst,
                len,
            );
            let _ = out.send(res);
        }));
        CopyHandle::Pending(rx)
    }
}

impl fmt::Debug for QueryPool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let workers = self
            .pool
            .shared
            .inner
            .lock()
            .map(|g| g.total)
            .unwrap_or_else(|e| e.into_inner().total);
        f.debug_struct("QueryPool")
            .field("workers", &workers)
            .finish()
    }
}

/// A handle to one enqueued [`QueryPool::query`] listing. Pull enriched batches
/// with [`next`](QueryHandle::next) until `None` (end of directory, or the pool
/// was dropped). Also an [`Iterator`].
pub struct QueryHandle {
    rx: mpsc::Receiver<crate::Result<Vec<DirEntry>>>,
}

impl fmt::Debug for QueryHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QueryHandle").finish_non_exhaustive()
    }
}

impl QueryHandle {
    /// The next batch, blocking until a worker produces one; `None` at the end
    /// (or if the pool was dropped before finishing this walk).
    pub fn next(&self) -> Option<crate::Result<Vec<DirEntry>>> {
        self.rx.recv().ok()
    }

    /// The next batch if one is already available, without blocking. `None`
    /// means "nothing ready yet" *or* "finished" — [`next`](Self::next)
    /// distinguishes them by blocking.
    pub fn try_next(&self) -> Option<crate::Result<Vec<DirEntry>>> {
        self.rx.try_recv().ok()
    }
}

impl Iterator for QueryHandle {
    type Item = crate::Result<Vec<DirEntry>>;
    fn next(&mut self) -> Option<Self::Item> {
        self.rx.recv().ok()
    }
}

/// A worker: wait for a job, run it, repeat; `K` workers run `K` jobs
/// concurrently. A burst worker idle past the idle timeout retires (never below
/// the floor); on shutdown every worker drains the queue and exits, decrementing
/// `total` so [`WorkerPool`]'s `Drop` can wait them all out.
///
/// Each job runs under `catch_unwind`, so a panicking job retires only itself,
/// not the worker: the pool keeps draining, and a later `submit` is not
/// silently dropped onto a dead thread. Any handle the job owned (a `SendDir`)
/// still closes as its unwinding frame drops.
fn worker_loop(shared: &Arc<PoolShared>) {
    loop {
        let job = {
            let mut g = shared.inner.lock().unwrap_or_else(|e| e.into_inner());
            loop {
                if let Some(job) = g.queue.pop_front() {
                    break Some(job);
                }
                if g.closed {
                    break None;
                }
                let (guard, wait) = shared
                    .cv
                    .wait_timeout(g, shared.idle_timeout)
                    .unwrap_or_else(|e| e.into_inner());
                g = guard;
                if wait.timed_out()
                    && g.queue.is_empty()
                    && !g.closed
                    && g.total > shared.floor
                {
                    g.total -= 1; // idle burst worker retires
                    return;
                }
            }
        };
        let Some(job) = job else {
            // Pool closing: account the exit and wake `Drop`'s waiter.
            let mut g = shared.inner.lock().unwrap_or_else(|e| e.into_inner());
            g.total -= 1;
            shared.cv.notify_all();
            return;
        };
        shared.running.fetch_add(1, Ordering::Relaxed);
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(job));
        shared.running.fetch_sub(1, Ordering::Relaxed);
    }
}

/// The result of a [`QueryPool::copy_file_range`]: `Ready` when the inline
/// block clone succeeded (nothing offloaded), or `Pending` when a real byte
/// copy was handed to the pool. [`wait`](Self::wait) yields the bytes copied.
#[derive(Debug)]
pub enum CopyHandle {
    /// The inline `FICLONERANGE` clone already finished with this result.
    Ready(crate::Result<u64>),
    /// A byte copy is running on the pool; its result arrives on this channel.
    Pending(mpsc::Receiver<crate::Result<u64>>),
}

impl CopyHandle {
    /// The bytes copied — instant for an inline clone, else blocking until the
    /// offloaded copy finishes (`ECONNABORTED` if the pool was dropped first).
    pub fn wait(self) -> crate::Result<u64> {
        match self {
            CopyHandle::Ready(r) => r,
            CopyHandle::Pending(rx) => rx
                .recv()
                .unwrap_or_else(|_| Err(Errno::ECONNABORTED.into())),
        }
    }
}

/// `struct file_clone_range` (`linux/fs.h`) — the `FICLONERANGE` ioctl argument.
#[repr(C)]
struct FileCloneRange {
    src_fd: i64,
    src_offset: u64,
    src_length: u64,
    dest_offset: u64,
}

/// `FICLONERANGE` = `_IOW(0x94, 13, struct file_clone_range)` (a 32-byte arg):
/// `(1 << 30) | (32 << 16) | (0x94 << 8) | 13`.
const FICLONERANGE: libc::c_ulong = 0x4020_940D;

/// Largest single kernel transfer, page-aligned.
const MAX_CHUNK: usize = 0x7FFF_FFFF & !0xFFF;

/// Blocking ranged `copy_file_range`: block-clone `len` bytes from
/// `src[off_src..]` to `dst[off_dst..]` on a reflink-capable filesystem (ZFS
/// `feature@block_cloning` when recordsize-aligned), else the kernel copies
/// in-kernel; across filesystems/pools `copy_file_range` returns `EXDEV`, so
/// fall back to a positional read/write of the range. Returns bytes copied
/// (short only at source EOF). Standalone here because `sync_fs::shutil` is a
/// separate feature (unreachable under `uring-fs`) and its `clonefile` is
/// whole-file only.
fn copy_file_range_blocking(
    src: RawFd,
    dst: RawFd,
    off_src: u64,
    off_dst: u64,
    len: u64,
) -> crate::Result<u64> {
    let mut soff = off_src as i64;
    let mut doff = off_dst as i64;
    let mut remaining = len;
    let mut total = 0u64;
    while remaining > 0 {
        let want = remaining.min(MAX_CHUNK as u64) as usize;
        // SAFETY: `src`/`dst` are live raw fds (the job holds the owning `File`
        // clones); `soff`/`doff` are valid locals the kernel reads and advances.
        let n = retry_on_eintr(|| unsafe {
            libc::copy_file_range(src, &mut soff, dst, &mut doff, want, 0)
        });
        match n {
            Ok(0) => break, // source EOF
            Ok(n) => {
                total += n as u64;
                remaining -= n as u64;
            }
            // Cross-filesystem: byte-copy the whole requested range instead.
            Err(Errno::EXDEV) if total == 0 => {
                return copy_range_rw(src, dst, off_src, off_dst, len);
            }
            Err(e) => return Err(e.into()),
        }
    }
    Ok(total)
}

/// Positional read/write fallback for the cross-filesystem (`EXDEV`) case.
fn copy_range_rw(
    src: RawFd,
    dst: RawFd,
    off_src: u64,
    off_dst: u64,
    len: u64,
) -> crate::Result<u64> {
    let mut buf = vec![0u8; MAX_CHUNK.min(1 << 20)];
    let mut soff = off_src as i64;
    let mut doff = off_dst as i64;
    let mut remaining = len;
    let mut total = 0u64;
    while remaining > 0 {
        let want = remaining.min(buf.len() as u64) as usize;
        // SAFETY: reading `want` bytes into a live buffer at a valid offset.
        let r = retry_on_eintr(|| unsafe {
            libc::pread(src, buf.as_mut_ptr().cast(), want, soff)
        })?;
        if r == 0 {
            break; // source EOF
        }
        let r = r as usize;
        let mut written = 0usize;
        while written < r {
            // SAFETY: writing a sub-slice we just filled to a live fd.
            let w = retry_on_eintr(|| unsafe {
                libc::pwrite(
                    dst,
                    buf[written..r].as_ptr().cast(),
                    r - written,
                    doff + written as i64,
                )
            })?;
            if w == 0 {
                return Err(Errno::EIO.into());
            }
            written += w as usize;
        }
        soff += r as i64;
        doff += r as i64;
        total += r as u64;
        remaining -= r as u64;
    }
    Ok(total)
}

#[cfg(test)]
mod pool_tests {
    use super::*;

    /// The elastic pool grows past its floor when every worker is blocked, up to
    /// the ceiling, then retires the burst workers once they sit idle.
    #[test]
    fn offload_pool_grows_under_saturation_then_reclaims_when_idle() {
        // Floor 1, ceiling 4; no growth cooldown (deterministic under the
        // start-synchronised submits below) and a quick idle timeout.
        let pool = WorkerPool::try_elastic_tuned(
            1,
            4,
            Duration::ZERO,
            Duration::from_millis(50),
        )
        .expect("pool");

        let release = Arc::new((Mutex::new(false), Condvar::new()));
        let (started_tx, started_rx) = mpsc::channel::<()>();

        // Submit blocking jobs one at a time, waiting until each is actually
        // running before the next, so the growth decision sees an accurate
        // `running` count rather than racing ahead of the workers.
        for _ in 0..4 {
            let r = Arc::clone(&release);
            let s = started_tx.clone();
            pool.submit(Box::new(move || {
                s.send(()).unwrap();
                let (m, cv) = &*r;
                let mut held = m.lock().unwrap();
                while !*held {
                    held = cv.wait(held).unwrap();
                }
            }));
            started_rx.recv().unwrap();
        }

        let grown = pool.shared.inner.lock().unwrap().total;

        // Release the blocked jobs first, so a failing assertion cannot wedge
        // teardown (Drop waits for every worker to exit).
        {
            let (m, cv) = &*release;
            *m.lock().unwrap() = true;
            cv.notify_all();
        }
        assert_eq!(grown, 4, "grew from floor 1 to ceiling 4 under saturation");

        // Idle burst workers retire back to the floor.
        let mut total = grown;
        for _ in 0..200 {
            total = pool.shared.inner.lock().unwrap().total;
            if total == 1 {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(total, 1, "burst workers retired back to the floor");
    }

    /// A fixed pool (`floor == ceiling`) never grows, even when saturated.
    #[test]
    fn fixed_pool_does_not_grow() {
        let pool = WorkerPool::new(2);
        let release = Arc::new((Mutex::new(false), Condvar::new()));
        let (started_tx, started_rx) = mpsc::channel::<()>();
        for _ in 0..2 {
            let r = Arc::clone(&release);
            let s = started_tx.clone();
            pool.submit(Box::new(move || {
                s.send(()).unwrap();
                let (m, cv) = &*r;
                let mut held = m.lock().unwrap();
                while !*held {
                    held = cv.wait(held).unwrap();
                }
            }));
            started_rx.recv().unwrap();
        }
        // Two more jobs against a saturated fixed pool: they queue, no growth.
        for _ in 0..2 {
            pool.submit(Box::new(|| {}));
        }
        let total = pool.shared.inner.lock().unwrap().total;
        {
            let (m, cv) = &*release;
            *m.lock().unwrap() = true;
            cv.notify_all();
        }
        assert_eq!(total, 2, "fixed pool stayed at its worker count");
    }
}
