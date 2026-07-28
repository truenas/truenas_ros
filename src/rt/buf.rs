//! [`BufPool`]: a registered-buffer pool for the zero-copy tier.
//!
//! The pool registers a **sparse** buffer table on the ring once, at build
//! time (the table's size is immutable for the ring's lifetime — a second
//! register fails `-EBUSY` — but sparse slots pin nothing), then fills slots
//! lazily and in place via `IORING_REGISTER_BUFFERS_UPDATE`, which needs no
//! ring quiesce and is legal from any thread (this crate's rings never set
//! `SINGLE_ISSUER`). Each filled slot is one page-aligned anonymous mapping
//! of `chunk_len` bytes whose pages the kernel pins; `read_fixed` /
//! `write_fixed` then address the pre-pinned pages directly — no per-op
//! pin/unpin, and with `O_DIRECT` the device DMAs straight into them.
//!
//! A [`PooledBuf`] is an exclusive lease of one slot. While an op is in
//! flight the lease is owned by the loop's op entry (inside the reply
//! endpoint), so the mapping can never be reclaimed under the kernel; it
//! round-trips back to the caller with the outcome, or returns to the pool
//! when the outcome is undeliverable — both strictly after the CQE.

use crate::errno::Errno;
use crate::uring::sys::{register_buffers_sparse, register_buffers_update};
use std::os::fd::{AsRawFd, OwnedFd};
use std::ptr::NonNull;
use std::sync::{Arc, Mutex};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// The registered-buffer table's hard kernel ceiling
/// (`IORING_MAX_REG_BUFFERS`).
const MAX_SLOTS: u16 = 16_384;

/// Sizing for a [`BufPool`].
#[derive(Clone, Copy, Debug)]
pub struct BufPoolConfig {
    /// Sparse table slots registered up front — the pool's hard ceiling for
    /// its whole lifetime (kernel max 16 384). Sparse slots cost only table
    /// bookkeeping, so a generous ceiling is cheap.
    pub slots: u16,
    /// Bytes per buffer. Rounded-up-to-page by construction requirement:
    /// must be a nonzero multiple of the page size (mappings are
    /// page-granular, and page alignment is what makes `O_DIRECT` memory
    /// alignment hold by construction).
    pub chunk_len: usize,
    /// Slots filled (pages pinned) at build time.
    pub initial: u16,
    /// Growth ceiling: the pool fills further slots on demand up to this
    /// many. Pinned pages count against `RLIMIT_MEMLOCK` unless the process
    /// holds `CAP_IPC_LOCK` — size `max × chunk_len` against that limit.
    pub max: u16,
}

impl Default for BufPoolConfig {
    fn default() -> BufPoolConfig {
        BufPoolConfig {
            slots: 1024,
            chunk_len: 256 << 10,
            initial: 32,
            max: 64, // 16 MiB pinned ceiling — under common memlock defaults
        }
    }
}

/// One filled slot's mapping. Unmapped on drop — which happens only at pool
/// teardown, after every lease returned (leases hold the pool `Arc`), so no
/// in-flight op can still name these pages.
struct Chunk {
    ptr: NonNull<u8>,
    len: usize,
}

// SAFETY: a Chunk is an exclusively-owned anonymous mapping; the raw pointer
// is process-global, carries no thread affinity, and is only dereferenced by
// whoever holds the corresponding lease.
unsafe impl Send for Chunk {}
unsafe impl Sync for Chunk {}

impl Drop for Chunk {
    fn drop(&mut self) {
        // SAFETY: `ptr` is a live mapping of exactly `len` bytes that this
        // struct owns. (The kernel's own page pins from buffer registration
        // are independent of our mapping and are released with the ring.)
        unsafe { libc::munmap(self.ptr.as_ptr().cast(), self.len) };
    }
}

struct PoolInner {
    /// A dup of the ring fd, so growth (`BUFFERS_UPDATE`) works from any
    /// thread for the pool's whole life, independent of the reactor handles.
    ring_fd: OwnedFd,
    chunk_len: usize,
    max: u16,
    /// Capacity gate: `max` permits; a lease holds one until dropped.
    sem: Arc<Semaphore>,
    /// Filled-and-idle slots, plus how many slots have been filled so far
    /// (`filled` is the next slot index to fill on growth).
    state: Mutex<PoolState>,
}

struct PoolState {
    free: Vec<u16>,
    filled: u16,
    chunks: Vec<Chunk>,
}

/// A registered-buffer pool bound to one reactor ring. Cheap to clone.
#[derive(Clone)]
pub struct BufPool {
    inner: Arc<PoolInner>,
}

impl std::fmt::Debug for BufPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BufPool")
            .field("chunk_len", &self.inner.chunk_len)
            .field("max", &self.inner.max)
            .finish_non_exhaustive()
    }
}

impl BufPool {
    /// Register the sparse table on `ring_fd` (a dup owned by the pool) and
    /// fill the initial slots. Memlock exhaustion while pinning is reported
    /// as a `Validation` error naming `RLIMIT_MEMLOCK`, since the bare
    /// `ENOMEM`/`EPERM` is famously unhelpful.
    pub(crate) fn register(
        ring_fd: OwnedFd,
        cfg: BufPoolConfig,
    ) -> crate::Result<BufPool> {
        let page = page_size();
        if cfg.slots == 0 || cfg.slots > MAX_SLOTS {
            return Err(crate::Error::Validation(format!(
                "BufPoolConfig::slots must be in 1..={MAX_SLOTS}"
            )));
        }
        if cfg.chunk_len == 0 || cfg.chunk_len % page != 0 {
            return Err(crate::Error::Validation(format!(
                "BufPoolConfig::chunk_len must be a nonzero multiple of the \
                 page size ({page})"
            )));
        }
        if cfg.max == 0 || cfg.max > cfg.slots || cfg.initial > cfg.max {
            return Err(crate::Error::Validation(
                "BufPoolConfig: require 0 < initial <= max <= slots".into(),
            ));
        }
        register_buffers_sparse(ring_fd.as_raw_fd(), u32::from(cfg.slots))?;
        let pool = BufPool {
            inner: Arc::new(PoolInner {
                ring_fd,
                chunk_len: cfg.chunk_len,
                max: cfg.max,
                sem: Arc::new(Semaphore::new(usize::from(cfg.max))),
                state: Mutex::new(PoolState {
                    free: Vec::new(),
                    filled: 0,
                    chunks: Vec::new(),
                }),
            }),
        };
        {
            let mut st = pool.lock_state();
            for _ in 0..cfg.initial {
                let idx = pool.fill_next_slot(&mut st)?;
                st.free.push(idx);
            }
        }
        Ok(pool)
    }

    /// Lease a buffer, waiting (fairly) when all `max` are out. Grows the
    /// pool by one slot when no filled buffer is idle but headroom remains.
    pub async fn lease(&self) -> crate::Result<PooledBuf> {
        let permit = self
            .inner
            .sem
            .clone()
            .acquire_owned()
            .await
            .expect("pool semaphore never closed");
        self.take_filled(permit)
    }

    /// [`BufPool::lease`] without waiting: `None` when all buffers are out.
    /// Growth errors also yield `None` (the next `lease` will surface them).
    pub fn try_lease(&self) -> Option<PooledBuf> {
        let permit = self.inner.sem.clone().try_acquire_owned().ok()?;
        self.take_filled(permit).ok()
    }

    /// The fixed byte length of every leased buffer.
    pub fn chunk_len(&self) -> usize {
        self.inner.chunk_len
    }

    fn lock_state(&self) -> std::sync::MutexGuard<'_, PoolState> {
        self.inner
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// With a capacity permit in hand, pop an idle buffer or fill a fresh
    /// slot (permit ⇒ free.len() + headroom > 0, so one of the two holds).
    fn take_filled(
        &self,
        permit: OwnedSemaphorePermit,
    ) -> crate::Result<PooledBuf> {
        let mut st = self.lock_state();
        let idx = match st.free.pop() {
            Some(idx) => idx,
            None => self.fill_next_slot(&mut st)?,
        };
        let chunk = &st.chunks[usize::from(idx)];
        Ok(PooledBuf {
            idx,
            ptr: chunk.ptr,
            len: chunk.len,
            pool: self.inner.clone(),
            permit: Some(permit),
        })
    }

    /// Map one chunk and register it into the next sparse slot.
    fn fill_next_slot(&self, st: &mut PoolState) -> crate::Result<u16> {
        debug_assert!(st.filled < self.inner.max, "permit-gated growth");
        let len = self.inner.chunk_len;
        // SAFETY: plain anonymous mapping; length validated nonzero.
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(Errno::last().into());
        }
        let ptr = NonNull::new(ptr.cast::<u8>()).expect("mmap null");
        let idx = st.filled;
        // SAFETY: `[ptr, ptr+len)` is the live mapping just created; the
        // Chunk below keeps it alive until pool teardown, after all leases.
        let registered = unsafe {
            register_buffers_update(
                self.inner.ring_fd.as_raw_fd(),
                u32::from(idx),
                ptr.as_ptr(),
                len,
            )
        };
        if let Err(e) = registered {
            // SAFETY: unmapping the mapping we just created (never handed out).
            unsafe { libc::munmap(ptr.as_ptr().cast(), len) };
            return Err(match e {
                Errno::ENOMEM | Errno::EPERM => {
                    crate::Error::Validation(format!(
                        "registering a {len}-byte fixed buffer failed with \
                         {e}: pinned pages exceed RLIMIT_MEMLOCK (raise the \
                         limit, grant CAP_IPC_LOCK, or shrink \
                         BufPoolConfig::max × chunk_len)"
                    ))
                }
                e => e.into(),
            });
        }
        st.chunks.push(Chunk { ptr, len });
        st.filled = idx + 1;
        Ok(idx)
    }
}

/// An exclusive lease of one registered buffer: `Deref`s to its bytes,
/// returns to the pool on drop. `Send + Sync` (the mapping is process-global
/// and the lease is the unique accessor).
pub struct PooledBuf {
    idx: u16,
    ptr: NonNull<u8>,
    len: usize,
    pool: Arc<PoolInner>,
    /// The capacity permit; released with the lease.
    permit: Option<OwnedSemaphorePermit>,
}

// SAFETY: the lease exclusively owns access to `[ptr, ptr+len)`, a mapping
// kept alive by `pool` (chunks drop only at pool teardown, after all
// leases); the pointer itself is process-global with no thread affinity.
unsafe impl Send for PooledBuf {}
unsafe impl Sync for PooledBuf {}

impl PooledBuf {
    /// The registered-table slot this lease names (`sqe.buf_index`).
    pub fn index(&self) -> u16 {
        self.idx
    }

    /// The buffer's base address (stable for the lease's whole life).
    pub fn as_ptr(&self) -> *const u8 {
        self.ptr.as_ptr()
    }
}

impl std::ops::Deref for PooledBuf {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        // SAFETY: exclusive lease of a live `len`-byte mapping.
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }
}

impl std::ops::DerefMut for PooledBuf {
    fn deref_mut(&mut self) -> &mut [u8] {
        // SAFETY: as `deref`, with unique access through `&mut self`.
        unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
    }
}

impl std::fmt::Debug for PooledBuf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PooledBuf")
            .field("idx", &self.idx)
            .field("len", &self.len)
            .finish_non_exhaustive()
    }
}

impl Drop for PooledBuf {
    fn drop(&mut self) {
        let mut st = self
            .pool
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        st.free.push(self.idx);
        drop(st);
        // Capacity releases after the slot is back on the free list, so a
        // woken waiter always finds it.
        self.permit.take();
    }
}

fn page_size() -> usize {
    // SAFETY: sysconf(_SC_PAGESIZE) cannot fail on Linux.
    unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize }
}
