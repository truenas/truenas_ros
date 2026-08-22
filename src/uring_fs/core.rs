//! The fs core: the op table (owner of every kernel-visible payload from
//! submission to completion), plain reference-counted file descriptors
//! (`File = Arc<OwnedFd>`, close-last by ownership), the SQE builders, and
//! completion routing. A host owns the engine and drives this --
//! [`super::UringFs`] standalone, or a `net` server sharing its ring (which is
//! also what [`FsConn`] submits through).
//!
//! Invariants:
//!
//! - **The kernel must never touch freed memory.** Buffers, iovec arrays,
//!   paths, `open_how` pads, and anchor dirfds live in the op entry from
//!   submission until the CQE reaps - even when the caller lost interest.
//! - **Close-last by ownership.** An open returns an `Arc<OwnedFd>`; each op in
//!   flight against it parks its own clone in the op entry until that op's CQE,
//!   so the fd closes only when the last reference - the caller's handle and
//!   every in-flight op - drops. No explicit close op, no reusable slot index.
//! - **Op-slot generations make stale completions inert.** `user_data` packs
//!   `(tag, op-slot, generation)`; an op entry frees only at its own single
//!   terminal CQE, so a stale / duplicate / wrong-tag completion is rejected.

use super::offload_pool::{OffloadBounds, SharedPool};
use super::{
    Anchor, CONFINED_RESOLVE, File, FsOutcome, Leaf, Personality,
    PrivilegedXattrs, ReplyTo, RwFlags, statx_at_flags,
};
use crate::errno::{Errno, retry_on_eintr};
use crate::sync_fs::openat2::RawOpenHow;
use crate::sync_fs::{
    AtFlags, Mode, OFlag, OpenHow, RenameFlags, ResolveFlag, Statfs, Statx,
    StatxMask, StatxRaw, ZfsAttr,
};
use crate::uring::engine::Engine;
use crate::uring::slots::SlotEntry;
use crate::uring::sys::{
    IORING_FSYNC_DATASYNC, IORING_OP_ASYNC_CANCEL, IORING_OP_FADVISE,
    IORING_OP_FALLOCATE, IORING_OP_FGETXATTR, IORING_OP_FSETXATTR,
    IORING_OP_FSYNC, IORING_OP_FTRUNCATE, IORING_OP_LINKAT, IORING_OP_MKDIRAT,
    IORING_OP_OPENAT2, IORING_OP_READV, IORING_OP_RENAMEAT, IORING_OP_SPLICE,
    IORING_OP_STATX, IORING_OP_SYMLINKAT, IORING_OP_UNLINKAT, IORING_OP_WRITEV,
    IoUringCqe, SPLICE_F_MOVE,
};
use crate::uring::user_data::{pack_raw, unpack_raw};
use std::any::Any;
use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::ffi::{CStr, CString};
use std::mem::size_of;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::rc::Rc;
// The offload sink and the `DIR*` handoff are loom-modelled (see
// `loom_tests` at the bottom), so these come from `crate::sync` - std's
// outside `--cfg loom`.
use crate::sync::{Arc, Mutex};
use std::thread;

/// Default warm floor of worker threads backing [`FsConn::offload`]; the pool
/// is spawned on first use and grows to [`OFFLOAD_CEILING`] under saturation.
///
/// Four, so a small burst of concurrent listings is served without waiting on
/// a thread spawn: growth is rate-limited to one worker per millisecond, so a
/// pool starting at one takes three to reach four. This is the pool's only
/// resident cost, paid per ring once anything offloads.
pub(crate) const OFFLOAD_FLOOR: usize = 4;
/// Default ceiling the offload pool grows to under sustained blocking work
/// (opcode-less `readdir`/`fdopendir`/copy).
///
/// Generous on purpose: it caps how many *concurrently stalled* operations one
/// ring absorbs before they queue behind each other, which is the whole reason
/// the pool exists, and a stalled `readdir` against a cold NFS or FUSE backing
/// can take seconds. Only the floor is resident, growth is throttled to one
/// spawn per millisecond, and a burst worker retires once it has sat idle for
/// `OFFLOAD_IDLE_TIMEOUT` - the keep-alive policy of tokio's blocking pool
/// (`KEEP_ALIVE`, `runtime/blocking/pool.rs`). Retirement being idle-keyed
/// means bursts recurring inside that window hold the recent high-water mark
/// of workers, not the instantaneous blocked count; plan standing cost by the
/// burst peak, not the average.
///
/// Every bound here is per ring. A deployment running several multiplies
/// them, and sizes both through
/// [`OffloadBounds`](crate::uring_fs::OffloadBounds).
pub(crate) const OFFLOAD_CEILING: usize = 64;
/// Names per off-loop `readdir` batch in [`FsConn::next_batch`].
const DIR_BATCH: usize = 256;

// fs op tags (the 0x80 domain; fs-reactor design sec. 13).
pub(crate) const TAG_OPEN: u8 = 0x80;
pub(crate) const TAG_READV: u8 = 0x81;
pub(crate) const TAG_WRITEV: u8 = 0x82;
pub(crate) const TAG_FSYNC: u8 = 0x83;
pub(crate) const TAG_STATX: u8 = 0x84;
pub(crate) const TAG_FALLOCATE: u8 = 0x87;
pub(crate) const TAG_FTRUNCATE: u8 = 0x88;
pub(crate) const TAG_RENAMEAT: u8 = 0x89;
pub(crate) const TAG_UNLINKAT: u8 = 0x8A;
pub(crate) const TAG_MKDIRAT: u8 = 0x8B;
pub(crate) const TAG_SYMLINKAT: u8 = 0x8C;
pub(crate) const TAG_LINKAT: u8 = 0x8D;
pub(crate) const TAG_FGETXATTR: u8 = 0x8E;
pub(crate) const TAG_FSETXATTR: u8 = 0x8F;
pub(crate) const TAG_FADVISE: u8 = 0x90;
pub(crate) const TAG_SPLICE: u8 = 0x91;
/// The standalone host's wake tag (an embedded host reuses its own).
pub(crate) const TAG_WAKE: u8 = 0x9D;
/// Tags `ASYNC_CANCEL` ops (and the teardown drain); completions ignored.
pub(crate) const TAG_CANCEL: u8 = 0x9E;

/// A completed embedded op's callback, fired **inline on the loop thread** by
/// the embedding host (a `net` server) with the outcome and a fresh [`FsConn`]
/// for chaining. Dropping it without firing drops its captured continuation --
/// which closes the connection - so a submission failure needs no error path.
pub(crate) type EmbeddedCb = Box<dyn FnOnce(FsDone, &mut FsConn<'_>)>;

/// An opaque per-op **owner** tag: the embedding host's connection identity
/// `(slot, generation)`, threaded through so a chained callback runs under the
/// same connection. The core never interprets it (files close by `Arc`-drop
/// now, not by an owner sweep); `None` on the off-loop channel path.
pub(crate) type Owner = Option<(u32, u64)>;

/// Where a completed fs op's outcome goes: back over a channel to an off-loop
/// [`FsHandle`](super::FsHandle) caller, or into an in-loop callback the
/// embedding host (a `net` server) fires on the reactor thread.
pub(crate) enum FsWaiter {
    Channel(ReplyTo),
    #[cfg_attr(not(feature = "net-server"), allow(dead_code))]
    Embedded {
        owner: Owner,
        cb: EmbeddedCb,
    },
    /// A reactor-pump read (a `net` server streaming a file into a response
    /// body): no callback - [`FsCore::on_cqe`] hands the outcome back as
    /// [`ReapedFs::Pump`] and the host routes it to the owning connection
    /// itself, with the full loop state in hand. Cancelled by owner exactly
    /// like `Embedded`, so connection teardown reaches an in-flight body
    /// read through the same sweep.
    #[cfg_attr(not(feature = "net-server"), allow(dead_code))]
    Pump {
        owner: (u32, u64),
    },
}

/// A routed fs-domain CQE, from [`FsCore::on_cqe`]: nothing left to do (a
/// channel op delivered in place, or an inert stale completion), an embedded
/// callback + outcome for the host to fire once its borrow of the fs tables
/// has ended, or a pump read's outcome for the host to route to its owning
/// connection.
pub(crate) enum ReapedFs {
    None,
    Embedded(EmbeddedCb, FsDone, Owner),
    #[cfg_attr(not(feature = "net-server"), allow(dead_code))]
    Pump(FsDone, (u32, u64)),
}

/// Box a consumer callback as an owner-stamped embedded waiter - the one shape
/// every [`FsConn`] submit method hands the core.
#[cfg_attr(not(feature = "net-server"), allow(dead_code))]
fn embed<F>(owner: Owner, on_done: F) -> FsWaiter
where
    F: FnOnce(FsDone, &mut FsConn<'_>) + 'static,
{
    FsWaiter::Embedded {
        owner,
        cb: Box::new(on_done),
    }
}

/// Report an early submission failure - the SQE never staged (slot exhaustion,
/// an unusable file) - handing the caller's payloads back exactly as a
/// completion would (see [`deliver`]).
fn fail(waiter: FsWaiter, err: Errno, bufs: Vec<Vec<u8>>) {
    deliver(Some(waiter), Err(err), bufs, None, None);
}

/// `fremovexattr(2)` on `f`. Blocking, because io_uring has no opcode for it:
/// the kernel's xattr ops are get/set only, and an `IORING_OP_FSETXATTR` with
/// a zero-length value does **not** remove - `__vfs_setxattr` substitutes an
/// empty value for `size == 0` (`fs/xattr.c`, commented "empty EA, do not
/// remove"), leaving an attribute that still lists. Removal reaches a
/// filesystem as `handler->set(..., NULL, 0, XATTR_REPLACE)` only from the
/// `removexattr` syscalls, which io_uring cannot reach.
fn remove_xattr_blocking(f: &File, name: &CStr) -> crate::Result<()> {
    let raw = f.as_raw_fd();
    // SAFETY: `f` is borrowed for the call, so `raw` is live; `name` is a
    // NUL-terminated C string.
    retry_on_eintr(|| unsafe { libc::fremovexattr(raw, name.as_ptr()) })?;
    Ok(())
}

/// One in-flight (or free) fs operation. Owns everything the kernel can see.
struct FsOpEntry {
    state: FsOpState,
    waiter: Option<FsWaiter>,
    /// Owned data buffers: `READV` destinations / `WRITEV` sources, and the
    /// single value buffer of an `FGETXATTR`/`FSETXATTR`.
    bufs: Vec<Vec<u8>>,
    /// The iovec array the SQE points at. Element pointers target `bufs`'
    /// heap allocations, which never move while parked here.
    iov: Vec<libc::iovec>,
    /// Primary path payload: the `OPENAT2` path, a `STATX`/directory-op
    /// leaf, an xattr name, or a symlink target.
    path: Option<CString>,
    /// Secondary path payload (the destination leaf of rename/link, the
    /// link path of symlinkat).
    path2: Option<CString>,
    /// `OPENAT2` `open_how` pad - boxed for a stable address.
    how: Option<Box<RawOpenHow>>,
    /// `STATX` result pad - **the kernel writes it at completion**, so it
    /// must live until the CQE reaps.
    stat: Option<Box<StatxRaw>>,
    /// Keeps a path op's dirfd alive (and its fd number un-reused) while
    /// the op is in flight.
    anchor: Option<Anchor>,
    /// The second dirfd of a rename/link.
    anchor2: Option<Anchor>,
    /// The file an fd-op targets, parked here so its descriptor stays open
    /// (and un-reused) until the CQE reaps - the caller may drop its
    /// `File` mid-op. Dropping this on `clear` gives close-last ordering.
    file: Option<Arc<OwnedFd>>,
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum FsOpState {
    Free,
    InFlight { tag: u8 },
}

impl FsOpEntry {
    fn new() -> FsOpEntry {
        FsOpEntry {
            state: FsOpState::Free,
            waiter: None,
            bufs: Vec::new(),
            iov: Vec::new(),
            path: None,
            path2: None,
            how: None,
            stat: None,
            anchor: None,
            anchor2: None,
            file: None,
        }
    }

    /// Release every payload and mark the entry free (the caller bumps the
    /// generation and returns the slot to the free-list).
    fn clear(&mut self) {
        self.iov.clear();
        self.path = None;
        self.path2 = None;
        self.how = None;
        self.anchor = None;
        self.anchor2 = None;
        self.file = None;
        self.state = FsOpState::Free;
    }
}

/// What a reaped op entry yields once its payloads are taken back out.
struct Completed {
    waiter: Option<FsWaiter>,
    bufs: Vec<Vec<u8>>,
    stat: Option<Box<StatxRaw>>,
}

/// The fs domain's tables. The host owns the [`Engine`] and passes it in for
/// staging; completion routing happens in [`FsCore::on_cqe`].
/// A finished off-loop job awaiting on-loop delivery: `(token, boxed result)`.
type PoolCompletion = (u64, Box<dyn Any + Send>);
/// A type-erased on-loop continuation: it downcasts the boxed job result back to
/// the job's `R` and calls the caller's `on_done` with a fresh `FsConn`.
type OffloadDeliver = Box<dyn FnOnce(Box<dyn Any + Send>, &mut FsConn<'_>)>;
/// One drained offload ready to fire: its owner, its continuation, and the
/// boxed job result to hand it.
type PoolDelivery = (Owner, OffloadDeliver, Box<dyn Any + Send>);

/// The reactor-side half of an in-flight [`FsConn::offload`]: the owner to scope
/// the delivering [`FsConn`] to, and the type-erased continuation (it downcasts
/// the boxed result back to the job's `R` and calls the caller's `on_done`).
struct OffloadEntry {
    owner: Owner,
    deliver: OffloadDeliver,
}

pub(crate) struct FsCore {
    ops: Vec<SlotEntry<FsOpEntry>>,
    op_free: Vec<u32>,
    /// This reactor's one blocking-work pool (shared with off-loop
    /// [`QueryPool`](super::query_dir::QueryPool)s), spawned on first use.
    pool: Arc<SharedPool>,
    /// Where workers push finished jobs; drained on the loop's wake.
    completions: Arc<Mutex<VecDeque<PoolCompletion>>>,
    /// Reactor-side continuations for in-flight offloads, keyed by token.
    offload_reg: HashMap<u64, OffloadEntry>,
    next_offload: u64,
    /// Attribute names whose `FSETXATTR` runs under ambient credentials rather
    /// than the request identity. Empty by default - see [`PrivilegedXattrs`].
    priv_xattrs: PrivilegedXattrs,
}

impl FsCore {
    pub(crate) fn new(op_slots: u32, offload: OffloadBounds) -> FsCore {
        FsCore {
            ops: (0..op_slots)
                .map(|_| SlotEntry {
                    generation: 0,
                    state: FsOpEntry::new(),
                })
                .collect(),
            op_free: (0..op_slots).rev().collect(),
            pool: SharedPool::new(offload),
            completions: Arc::new(Mutex::new(VecDeque::new())),
            offload_reg: HashMap::new(),
            next_offload: 0,
            priv_xattrs: PrivilegedXattrs::default(),
        }
    }

    /// Install the ambient-credential xattr policy. Setup-time only: the hosts
    /// expose it through a `&mut self` setter, and their run loops also take
    /// `&mut self`, so it cannot change while operations are in flight.
    pub(crate) fn set_privileged_xattrs(&mut self, policy: PrivilegedXattrs) {
        self.priv_xattrs = policy;
    }

    // ---- off-loop offload: run a blocking job, deliver its result on-loop ----

    /// Register `deliver` (owner-scoped) for a new offload; returns its token.
    fn register_offload(
        &mut self,
        owner: Owner,
        deliver: OffloadDeliver,
    ) -> u64 {
        let token = self.next_offload;
        self.next_offload = self.next_offload.wrapping_add(1);
        self.offload_reg
            .insert(token, OffloadEntry { owner, deliver });
        token
    }

    /// A clone of the completion queue for a worker job to push its result onto.
    fn completion_sink(&self) -> Arc<Mutex<VecDeque<PoolCompletion>>> {
        Arc::clone(&self.completions)
    }

    /// A clone of this reactor's shared offload pool, for minting an
    /// [`FsHandle`](super::FsHandle) that submits blocking work to the same
    /// pool off-loop.
    pub(crate) fn pool_handle(&self) -> Arc<SharedPool> {
        Arc::clone(&self.pool)
    }

    /// Submit `job` to this reactor's shared offload pool (spawned on first
    /// use). If a worker thread cannot be spawned the job runs inline rather
    /// than take the reactor down; see [`SharedPool::submit`].
    fn submit_offload(&mut self, job: Box<dyn FnOnce() + Send>) {
        self.pool.submit(job);
    }

    /// Remove a **server-owned** extended attribute on the blocking pool,
    /// gated on the [`PrivilegedXattrs`](crate::uring_fs::PrivilegedXattrs)
    /// allowlist. Refuses anything unlisted with `EPERM`.
    ///
    /// This is the one fs mutation in the module that carries no
    /// [`Personality`], and the allowlist is what makes that defensible
    /// rather than a hole. There is no `IORING_OP_*REMOVEXATTR`, and a
    /// zero-length `FSETXATTR` sets an empty attribute instead of removing
    /// one (see [`remove_xattr_blocking`]) - so the call can only run on a
    /// pool thread, under the reactor's own credentials, with no way for the
    /// kernel to check it against a request identity. Restricting it to
    /// attributes the *server* owns keeps the promotion keyed on the name
    /// alone, exactly as the `FSETXATTR` promotion in
    /// [`FsCore::submit_fd_meta`] is: a caller can clear the metadata this
    /// reactor wrote, and nothing else.
    pub(crate) fn remove_priv_xattr(
        &mut self,
        file: Arc<OwnedFd>,
        name: CString,
        reply: ReplyTo,
    ) {
        if !self.priv_xattrs.permits(&name) {
            let _ = reply.send(FsOutcome::new(
                Err(Errno::EPERM),
                Vec::new(),
                None,
                None,
            ));
            return;
        }
        self.submit_offload(Box::new(move || {
            let raw = file.as_raw_fd();
            // SAFETY: the closure owns `file` for the syscall's duration, so
            // `raw` is live; `name` is NUL-terminated.
            let res = retry_on_eintr(|| unsafe {
                libc::fremovexattr(raw, name.as_ptr())
            })
            .map(|_| 0i32);
            let _ = reply.send(FsOutcome::new(res, Vec::new(), None, None));
        }));
    }

    /// Take every finished offload paired with its owner + continuation. The
    /// caller fires each with a fresh owner-scoped [`FsConn`] once its borrow of
    /// the fs tables has ended (mirrors [`FsCore::on_cqe`]'s hand-back). Called
    /// from the loop's `TAG_WAKE` handler.
    #[cfg_attr(not(feature = "net-server"), allow(dead_code))]
    pub(crate) fn take_pool_completions(&mut self) -> Vec<PoolDelivery> {
        let drained: Vec<PoolCompletion> = {
            let mut q =
                self.completions.lock().unwrap_or_else(|e| e.into_inner());
            q.drain(..).collect()
        };
        let mut out = Vec::with_capacity(drained.len());
        for (token, any) in drained {
            if let Some(e) = self.offload_reg.remove(&token) {
                out.push((e.owner, e.deliver, any));
            }
        }
        out
    }

    // ---- submission (from drained injects) -----------------------------

    /// Stage an `OPENAT2` into a freshly reserved file slot. All failures are
    /// reported through `reply` (the loop never dies for a per-op reason).
    pub(crate) fn submit_open(
        &mut self,
        eng: &mut Engine,
        pers: u16,
        anchor: Anchor,
        path: CString,
        how: RawOpenHow,
        waiter: FsWaiter,
    ) {
        // A name-resolving op with personality 0 would run under the ring
        // owner's ambient (root) credentials - the identity this surface must
        // never grant implicitly. `Personality` cannot be 0 by construction, so
        // this only catches an internal misuse; fail closed regardless.
        if pers == 0 {
            fail(waiter, Errno::EINVAL, Vec::new());
            return;
        }
        let Some(op_slot) = self.op_free.pop() else {
            fail(waiter, Errno::EBUSY, Vec::new());
            return;
        };

        let entry = &mut self.ops[op_slot as usize];
        let gen32 = entry.generation as u32;
        let e = &mut entry.state;
        e.state = FsOpState::InFlight { tag: TAG_OPEN };
        e.waiter = Some(waiter);
        e.path = Some(path);
        e.how = Some(Box::new(how));
        let dirfd = anchor.raw_fd();
        let path_ptr = e.path.as_ref().expect("just set").as_ptr() as u64;
        let how_ptr =
            &**e.how.as_ref().expect("just set") as *const RawOpenHow as u64;
        e.anchor = Some(anchor);

        // No `file_index`: OPENAT2 returns a real fd as its CQE result, which
        // `on_cqe` wraps in an `Arc<OwnedFd>` for the caller's `File`.
        let ud = pack_raw(TAG_OPEN, op_slot, gen32);
        let staged = eng.stage(ud, |sqe| {
            sqe.opcode = IORING_OP_OPENAT2;
            sqe.fd = dirfd;
            sqe.addr = path_ptr;
            sqe.off_addr2 = how_ptr;
            sqe.len = size_of::<RawOpenHow>() as u32;
            // `pers != 0` guaranteed at entry (fail-closed above).
            sqe.personality = pers;
        });
        if let Err(e) = staged {
            self.fail_op(op_slot, e);
        }
    }

    /// Stage a `READV`/`WRITEV` (per `tag`) against an open file.
    ///
    /// `rw_flags` is the `RWF_*` set - the same field `preadv2`/`pwritev2`
    /// take, which these opcodes read directly, so the flagged form is not a
    /// separate op. `0` is the plain `preadv`/`pwritev` behaviour. The kernel
    /// validates the set at prep and fails the whole operation with
    /// `EOPNOTSUPP` for anything this file's filesystem does not implement, so
    /// an unsupported flag is never silently dropped.
    #[allow(clippy::too_many_arguments)] // an inject unpacked, not an API
    pub(crate) fn submit_rw(
        &mut self,
        eng: &mut Engine,
        tag: u8,
        pers: u16,
        file: Arc<OwnedFd>,
        mut bufs: Vec<Vec<u8>>,
        off: u64,
        rw_flags: u32,
        waiter: FsWaiter,
    ) {
        let Some(op_slot) = self.op_free.pop() else {
            fail(waiter, Errno::EBUSY, bufs);
            return;
        };

        let iov: Vec<libc::iovec> = bufs
            .iter_mut()
            .map(|b| libc::iovec {
                iov_base: b.as_mut_ptr().cast(),
                iov_len: b.len(),
            })
            .collect();

        let raw_fd = file.as_raw_fd();
        let entry = &mut self.ops[op_slot as usize];
        let gen32 = entry.generation as u32;
        let e = &mut entry.state;
        e.state = FsOpState::InFlight { tag };
        e.waiter = Some(waiter);
        e.bufs = bufs;
        e.iov = iov;
        // Park the fd here so it stays open until the CQE even if the caller
        // drops its `File` mid-op (close-last by ownership).
        e.file = Some(file);
        let iov_ptr = e.iov.as_ptr() as u64;
        let iov_len = e.iov.len() as u32;

        let opcode = if tag == TAG_READV {
            IORING_OP_READV
        } else {
            IORING_OP_WRITEV
        };
        let ud = pack_raw(tag, op_slot, gen32);
        let staged = eng.stage(ud, |sqe| {
            sqe.opcode = opcode;
            sqe.fd = raw_fd;
            sqe.addr = iov_ptr;
            sqe.len = iov_len;
            sqe.off_addr2 = off;
            // The `preadv2`/`pwritev2` flag word. Zero for the plain forms.
            sqe.op_flags = rw_flags;
            sqe.personality = pers;
        });
        if let Err(err) = staged {
            self.fail_op(op_slot, err);
        }
    }

    /// Whether the op table has a slot left. The reply path consults this
    /// before committing a chunk buffer to a body read, so a full table parks
    /// the tail (a completing op frees a slot and re-drives it) instead of
    /// severing a transfer that has done nothing wrong.
    #[cfg_attr(not(feature = "net-server"), allow(dead_code))]
    pub(crate) fn has_free_op(&self) -> bool {
        !self.op_free.is_empty()
    }

    /// Stage a reactor-pump `READV`: one positional read of up to `want`
    /// bytes at `off` into `buf`'s spare capacity, completing back through
    /// [`ReapedFs::Pump`] rather than a callback - the submission path for
    /// reads the *reply* path issues itself (a file-sourced response body),
    /// outside any handler delivery.
    ///
    /// `buf` arrives empty with `capacity() >= want`; the kernel initializes
    /// the spare capacity and the host sets the length from the CQE count --
    /// the stream recv path's discipline, so no byte is zeroed only to be
    /// overwritten. No personality is stamped (the SQE is zeroed): the read
    /// runs as the ring's own credentials, because the access decision was
    /// made at the file's open and an fd read re-checks nothing.
    ///
    /// Unlike the waiter-carrying submissions, a failure is returned to the
    /// caller (`EBUSY` on a full op table, or the staging error): there is no
    /// callback whose drop could report it, and a silently dropped pump read
    /// would strand its connection mid-body with nothing left to re-drive it.
    #[cfg_attr(not(feature = "net-server"), allow(dead_code))]
    pub(crate) fn submit_pump_read(
        &mut self,
        eng: &mut Engine,
        file: &File,
        mut buf: Vec<u8>,
        want: usize,
        off: u64,
        owner: (u32, u64),
    ) -> Result<(), Errno> {
        debug_assert!(buf.is_empty() && buf.capacity() >= want);
        let Some(op_slot) = self.op_free.pop() else {
            return Err(Errno::EBUSY);
        };
        // The iovec targets the Vec's spare capacity; computed before the
        // move below, and the heap block's address survives the move.
        let iov = vec![libc::iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: want,
        }];
        let raw_fd = file.as_raw_fd();
        let entry = &mut self.ops[op_slot as usize];
        let gen32 = entry.generation as u32;
        let e = &mut entry.state;
        e.state = FsOpState::InFlight { tag: TAG_READV };
        e.waiter = Some(FsWaiter::Pump { owner });
        e.bufs = vec![buf];
        e.iov = iov;
        // Park the fd so it stays open until the CQE even if the connection
        // drops its `File` mid-op (close-last by ownership).
        e.file = Some(Arc::clone(&file.fd));
        let iov_ptr = e.iov.as_ptr() as u64;
        let ud = pack_raw(TAG_READV, op_slot, gen32);
        let staged = eng.stage(ud, |sqe| {
            sqe.opcode = IORING_OP_READV;
            sqe.fd = raw_fd;
            sqe.addr = iov_ptr;
            sqe.len = 1;
            sqe.off_addr2 = off;
        });
        if let Err(err) = staged {
            self.fail_op(op_slot, err);
            return Err(err);
        }
        Ok(())
    }

    /// Stage an `FSYNC` (`datasync` selects `fdatasync`). `offset`/`length`
    /// bound the sync to a byte range via the SQE's `off`/`len` fields (the
    /// kernel's `vfs_fsync_range`, deriving `end = off + len`); `offset == 0 &&
    /// length == 0` syncs the whole file.
    #[allow(clippy::too_many_arguments)] // an inject unpacked, not an API
    pub(crate) fn submit_fsync(
        &mut self,
        eng: &mut Engine,
        pers: u16,
        file: Arc<OwnedFd>,
        datasync: bool,
        offset: u64,
        length: u32,
        waiter: FsWaiter,
    ) {
        let Some(op_slot) = self.op_free.pop() else {
            fail(waiter, Errno::EBUSY, Vec::new());
            return;
        };

        let raw_fd = file.as_raw_fd();
        let entry = &mut self.ops[op_slot as usize];
        let gen32 = entry.generation as u32;
        let e = &mut entry.state;
        e.state = FsOpState::InFlight { tag: TAG_FSYNC };
        e.waiter = Some(waiter);
        e.file = Some(file);

        let ud = pack_raw(TAG_FSYNC, op_slot, gen32);
        let staged = eng.stage(ud, |sqe| {
            sqe.opcode = IORING_OP_FSYNC;
            sqe.fd = raw_fd;
            // Byte-range sync via the SQE's off/len (the kernel derives
            // `end = off + len`, treating 0/0 as through-EOF).
            sqe.off_addr2 = offset;
            sqe.len = length;
            if datasync {
                sqe.op_flags = IORING_FSYNC_DATASYNC;
            }
            sqe.personality = pers;
        });
        if let Err(err) = staged {
            self.fail_op(op_slot, err);
        }
    }

    /// Stage a metadata op that targets an **open file**: `FTRUNCATE`/
    /// `FALLOCATE` (no payload) and `FGETXATTR`/`FSETXATTR` (owned name +
    /// value). The file was permission-checked at open, and the fd is the
    /// capability; the op runs as `pers`.
    ///
    /// Scalars: `off` is the truncate length or the fallocate offset,
    /// `len64` the fallocate length, `aux32` the fallocate mode or the
    /// xattr flags. (The xattr *size* is the value buffer's own length.)
    ///
    /// Fail-closed on `pers == 0`: an fd-op under the ring owner's ambient
    /// (root) credentials is a privilege this surface must never grant
    /// implicitly. The sanctioned ambient-root paths are
    /// [`FsCore::submit_fgetxattr_as_root`] and, for writes, the
    /// [`PrivilegedXattrs`] allowlist consulted below.
    ///
    /// **The allowlist is the only place a write is promoted to ambient
    /// credentials, and the promotion is keyed on the attribute name alone.**
    /// It lives here rather than at the call sites so no public entry point
    /// can name a personality of 0 or pick its own privilege: callers pass the
    /// request identity, and an `FSETXATTR` of an allowlisted name - and
    /// nothing else - is rewritten to `0`.
    #[allow(clippy::too_many_arguments)] // an inject unpacked, not an API
    pub(crate) fn submit_fd_meta(
        &mut self,
        eng: &mut Engine,
        tag: u8,
        pers: u16,
        file: Arc<OwnedFd>,
        name: Option<CString>,
        value: Vec<u8>,
        off: u64,
        len64: u64,
        aux32: u32,
        waiter: FsWaiter,
    ) {
        if pers == 0 {
            fail(waiter, Errno::EINVAL, vec![value]);
            return;
        }
        // An allowlisted attribute is metadata the *server* owns, which the
        // request identity has no privilege to write (the `trusted.` namespace
        // is CAP_SYS_ADMIN-gated). Everything else keeps `pers`, including
        // every non-xattr fd-op and every unlisted name.
        let pers = match (tag, name.as_deref()) {
            (TAG_FSETXATTR, Some(n)) if self.priv_xattrs.permits(n) => 0,
            _ => pers,
        };
        self.stage_fd_meta(
            eng, tag, pers, file, name, value, off, len64, aux32, waiter,
        );
    }

    /// Read xattr `name` from `file` under the reactor's **ambient root**
    /// (`sqe.personality = 0`) - the sole sanctioned `pers = 0` fd-op. For a
    /// privileged `trusted.*`/`security.*` read a request's own identity cannot
    /// perform: `sqe.personality` (not the fd's open-time cred) governs
    /// `fgetxattr`'s `CAP_SYS_ADMIN` check, and `0` runs as the ring owner
    /// (root). Deliberate - every other fd-op path fails closed on `pers == 0`.
    pub(crate) fn submit_fgetxattr_as_root(
        &mut self,
        eng: &mut Engine,
        file: Arc<OwnedFd>,
        name: CString,
        value: Vec<u8>,
        waiter: FsWaiter,
    ) {
        self.stage_fd_meta(
            eng,
            TAG_FGETXATTR,
            0,
            file,
            Some(name),
            value,
            0,
            0,
            0,
            waiter,
        );
    }

    /// Stage an fd-meta op stamping `sqe.personality = personality_raw`
    /// **verbatim** (no `pers == 0` guard). Internal: the callers
    /// ([`FsCore::submit_fd_meta`], [`FsCore::submit_fgetxattr_as_root`]) own
    /// the personality policy.
    #[allow(clippy::too_many_arguments)]
    fn stage_fd_meta(
        &mut self,
        eng: &mut Engine,
        tag: u8,
        personality_raw: u16,
        file: Arc<OwnedFd>,
        name: Option<CString>,
        value: Vec<u8>,
        off: u64,
        len64: u64,
        aux32: u32,
        waiter: FsWaiter,
    ) {
        let Some(op_slot) = self.op_free.pop() else {
            fail(waiter, Errno::EBUSY, vec![value]);
            return;
        };

        let raw_fd = file.as_raw_fd();
        let entry = &mut self.ops[op_slot as usize];
        let gen32 = entry.generation as u32;
        let e = &mut entry.state;
        e.state = FsOpState::InFlight { tag };
        e.waiter = Some(waiter);
        e.file = Some(file);
        e.path = name;
        // The value rides in `bufs` so it round-trips like any data buffer
        // (an FGETXATTR's kernel writes land in it at issue time).
        e.bufs = vec![value];
        let name_ptr = e.path.as_ref().map_or(0, |n| n.as_ptr() as u64);
        let val = &mut e.bufs[0];
        let val_ptr = val.as_mut_ptr() as u64;
        let val_len = val.len() as u32;

        let ud = pack_raw(tag, op_slot, gen32);
        let staged = eng.stage(ud, |sqe| {
            sqe.fd = raw_fd;
            sqe.personality = personality_raw;
            match tag {
                TAG_FTRUNCATE => {
                    sqe.opcode = IORING_OP_FTRUNCATE;
                    sqe.off_addr2 = off; // the new length
                }
                TAG_FALLOCATE => {
                    sqe.opcode = IORING_OP_FALLOCATE;
                    sqe.off_addr2 = off; // offset
                    sqe.addr = len64; // length (kernel packing)
                    sqe.len = aux32; // mode
                }
                TAG_FADVISE => {
                    sqe.opcode = IORING_OP_FADVISE;
                    sqe.off_addr2 = off; // offset
                    // Length rides in `addr`; the kernel consults `len` only
                    // when `addr` is 0, and 0 already means "to end of file".
                    sqe.addr = len64;
                    sqe.op_flags = aux32; // POSIX_FADV_* advice
                }
                TAG_SPLICE => {
                    sqe.opcode = IORING_OP_SPLICE;
                    // `sqe.fd` (set above) is the *output* - the file being
                    // written. The input rides in `splice_fd_in`, which
                    // overlays `file_index`; it is a plain descriptor, so
                    // `SPLICE_F_FD_IN_FIXED` stays clear.
                    sqe.file_index = len64 as u32; // the pipe's read end
                    sqe.off_addr2 = off; // destination offset
                    sqe.len = aux32; // bytes to move
                    // A pipe has no position: `splice_off_in` must be -1, or
                    // `do_splice` refuses it `ESPIPE`. `fd_meta` leaves `addr`
                    // holding a name pointer, so overwrite it.
                    sqe.addr = u64::MAX;
                    sqe.op_flags = SPLICE_F_MOVE;
                }
                TAG_FGETXATTR | TAG_FSETXATTR => {
                    sqe.opcode = if tag == TAG_FGETXATTR {
                        IORING_OP_FGETXATTR
                    } else {
                        IORING_OP_FSETXATTR
                    };
                    sqe.addr = name_ptr;
                    sqe.off_addr2 = val_ptr;
                    sqe.len = val_len;
                    sqe.op_flags = aux32;
                }
                _ => debug_assert!(false, "not an fd-meta tag {tag:#x}"),
            }
        });
        if let Err(err) = staged {
            self.fail_op(op_slot, err);
        }
    }

    /// Stage a path op: `STATX`, or one of the directory-entry ops. Every
    /// dirfd is a real fd from an [`Anchor`] (the kernel rejects fixed-table
    /// dirfds on all of these), and every name has already been validated
    /// as a single component by `Leaf` - except a symlink's target, which is
    /// link content and never resolved, and `STATX`'s empty-path form.
    /// `flags` becomes `sqe.op_flags` (`AT_*`/`RENAME_*`); `len_arg` becomes
    /// `sqe.len` where the op wants a scalar there (statx mask, mkdir mode)
    /// -- for rename/link `sqe.len` is the *second dirfd* instead, per the
    /// kernel's packing, and `len_arg` is unused.
    #[allow(clippy::too_many_arguments)] // an inject unpacked, not an API
    pub(crate) fn submit_path_op(
        &mut self,
        eng: &mut Engine,
        tag: u8,
        pers: u16,
        a1: Anchor,
        n1: CString,
        a2: Option<Anchor>,
        n2: Option<CString>,
        flags: u32,
        len_arg: u32,
        waiter: FsWaiter,
    ) {
        // See `submit_open`: personality 0 = ambient root on a name-resolving
        // op. Fail closed.
        if pers == 0 {
            fail(waiter, Errno::EINVAL, Vec::new());
            return;
        }
        let Some(op_slot) = self.op_free.pop() else {
            fail(waiter, Errno::EBUSY, Vec::new());
            return;
        };

        let entry = &mut self.ops[op_slot as usize];
        let gen32 = entry.generation as u32;
        let e = &mut entry.state;
        e.state = FsOpState::InFlight { tag };
        e.waiter = Some(waiter);
        e.path = Some(n1);
        e.path2 = n2;
        if tag == TAG_STATX {
            // SAFETY: `StatxRaw` is all-integer plain data; the kernel
            // overwrites it wholesale at completion.
            e.stat = Some(Box::new(unsafe { std::mem::zeroed() }));
        }
        let dfd1 = a1.raw_fd();
        // Default the second dirfd to the first, never AT_FDCWD: a rename/link
        // with a missing destination anchor must not fall back to the process
        // CWD (a confinement escape). The public API always supplies both.
        let dfd2 = a2.as_ref().map_or(dfd1, |a| a.raw_fd());
        e.anchor = Some(a1);
        e.anchor2 = a2;
        let p1 = e.path.as_ref().expect("just set").as_ptr() as u64;
        let p2 = e.path2.as_ref().map_or(0, |p| p.as_ptr() as u64);
        let stat_ptr = e
            .stat
            .as_mut()
            .map_or(0, |s| std::ptr::addr_of_mut!(**s) as u64);

        let ud = pack_raw(tag, op_slot, gen32);
        let staged = eng.stage(ud, |sqe| {
            sqe.fd = dfd1;
            sqe.addr = p1;
            // `pers != 0` guaranteed at entry (fail-closed above).
            sqe.personality = pers;
            sqe.op_flags = flags;
            match tag {
                TAG_STATX => {
                    sqe.opcode = IORING_OP_STATX;
                    sqe.len = len_arg; // STATX_* mask
                    sqe.off_addr2 = stat_ptr; // kernel writes at completion
                }
                TAG_MKDIRAT => {
                    sqe.opcode = IORING_OP_MKDIRAT;
                    sqe.len = len_arg; // mode
                }
                TAG_UNLINKAT => {
                    sqe.opcode = IORING_OP_UNLINKAT; // flags = AT_REMOVEDIR
                }
                TAG_SYMLINKAT => {
                    sqe.opcode = IORING_OP_SYMLINKAT;
                    sqe.off_addr2 = p2; // link path (addr = target)
                }
                TAG_RENAMEAT | TAG_LINKAT => {
                    sqe.opcode = if tag == TAG_RENAMEAT {
                        IORING_OP_RENAMEAT
                    } else {
                        IORING_OP_LINKAT
                    };
                    sqe.off_addr2 = p2; // new path
                    sqe.len = dfd2 as u32; // new dirfd (kernel packing)
                }
                _ => debug_assert!(false, "not a path-op tag {tag:#x}"),
            }
        });
        if let Err(err) = staged {
            self.fail_op(op_slot, err);
        }
    }

    /// `LINKAT` with `AT_EMPTY_PATH`: give the already-open `file` a name at
    /// `a2 / n2`. This is the only linkat form that can name an **unnamed**
    /// inode, so it is how an `O_TMPFILE` is materialized - the publish step of
    /// a durable create.
    ///
    /// Two kernel rules govern whether it succeeds, and neither is discoverable
    /// from the error alone:
    ///
    /// - The file must have been opened `O_TMPFILE` **without `O_EXCL`**.
    ///   `O_EXCL` is precisely the "never link this" opt-out: only the
    ///   non-`O_EXCL` path sets `I_LINKABLE` (`fs/namei.c:4084`), and
    ///   `vfs_link` rejects a zero-`i_nlink` inode without it (`:4979`) --
    ///   surfacing as `ENOENT`.
    /// - `AT_EMPTY_PATH` requires `fd_file(f)->f_cred == current_cred()` or
    ///   `CAP_DAC_READ_SEARCH` (`fs/namei.c:2631`). io_uring captures the
    ///   personality's `struct cred *` as the file's `f_cred` at open time, so
    ///   **`pers` must carry the credentials that opened `file`**. The check is
    ///   a pointer comparison and `register_personality` stores
    ///   `get_current_cred()`, so ids registered from unchanged process
    ///   credentials alias and are interchangeable; brokered ids, each minted
    ///   after a `setresuid`, are distinct objects even for one uid. Mismatch
    ///   is `ENOENT`, not `EPERM`.
    ///
    /// `IOSQE_FIXED_FILE` is deliberately never set: `io_linkat_prep` rejects a
    /// fixed file outright with `-EBADF`. Plain-fd `File` satisfies that by
    /// construction.
    pub(crate) fn submit_linkat_file(
        &mut self,
        eng: &mut Engine,
        pers: u16,
        file: Arc<OwnedFd>,
        a2: Anchor,
        n2: CString,
        waiter: FsWaiter,
    ) {
        // Like every name-resolving op: personality 0 would resolve `n2` and
        // create the link as ambient root. Fail closed.
        if pers == 0 {
            fail(waiter, Errno::EINVAL, Vec::new());
            return;
        }
        let Some(op_slot) = self.op_free.pop() else {
            fail(waiter, Errno::EBUSY, Vec::new());
            return;
        };

        let entry = &mut self.ops[op_slot as usize];
        let gen32 = entry.generation as u32;
        let e = &mut entry.state;
        e.state = FsOpState::InFlight { tag: TAG_LINKAT };
        e.waiter = Some(waiter);
        // The empty source path AT_EMPTY_PATH resolves against `sqe.fd`. Owned
        // by the entry like any other path payload: the kernel reads it at
        // execution, which is after this call returns.
        e.path = Some(CString::default());
        e.path2 = Some(n2);
        let old_fd = file.as_raw_fd();
        let new_dfd = a2.raw_fd();
        e.file = Some(file);
        e.anchor2 = Some(a2);
        let p1 = e.path.as_ref().expect("just set").as_ptr() as u64;
        let p2 = e.path2.as_ref().expect("just set").as_ptr() as u64;

        let ud = pack_raw(TAG_LINKAT, op_slot, gen32);
        let staged = eng.stage(ud, |sqe| {
            sqe.opcode = IORING_OP_LINKAT;
            sqe.fd = old_fd; // the open file itself, not a dirfd
            sqe.addr = p1; // ""
            sqe.off_addr2 = p2; // destination leaf
            sqe.len = new_dfd as u32; // destination dirfd (kernel packing)
            sqe.op_flags = AtFlags::AT_EMPTY_PATH.bits() as u32;
            sqe.personality = pers;
        });
        if let Err(err) = staged {
            self.fail_op(op_slot, err);
        }
    }

    // ---- cancellation --------------------------------------------------

    /// Stage an `ASYNC_CANCEL` for the in-flight op named by `target_ud`. Its
    /// own completion is ignored ([`TAG_CANCEL`], which `on_cqe` drops); the
    /// cancelled op completes with `ECANCELED` and its CQE runs `take_op` like
    /// any other, dropping the parked `Arc` (close-last). Takes no op-table slot
    /// -- nothing routes its completion - but goes through `eng.stage` so the
    /// engine's in-flight accounting stays correct. Best-effort: a stage failure
    /// (ring full) is dropped; server teardown still reaps the op.
    #[cfg_attr(not(feature = "net-server"), allow(dead_code))]
    fn submit_cancel(&self, eng: &mut Engine, target_ud: u64) {
        let ud = pack_raw(TAG_CANCEL, 0, 0);
        let _ = eng.stage(ud, |sqe| {
            sqe.opcode = IORING_OP_ASYNC_CANCEL;
            sqe.addr = target_ud; // cancel the op whose user_data == target_ud
        });
    }

    /// Cancel every in-flight op owned by `owner` - the connection-teardown
    /// sweep. Replaces the removed `close_owned_by`: with plain-fd files a
    /// connection's fds close by `Arc`-drop, but an op still **in flight** parks
    /// its fd until the CQE, and a closed connection's op is otherwise never
    /// cancelled (a never-completing read would pin the fd until server
    /// teardown). Cancelling - not force-dropping the entry - is required: the
    /// kernel op may still touch the fd or a buffer, so the entry must live
    /// until its (now-`ECANCELED`) CQE reaps it.
    #[cfg_attr(not(feature = "net-server"), allow(dead_code))]
    pub(crate) fn cancel_owned_by(
        &mut self,
        eng: &mut Engine,
        owner: (u32, u64),
    ) {
        // Collect targets first (the scan borrows `self.ops`), then stage.
        let targets: Vec<u64> = self
            .ops
            .iter()
            .enumerate()
            .filter_map(|(i, entry)| {
                let FsOpState::InFlight { tag } = entry.state.state else {
                    return None;
                };
                match &entry.state.waiter {
                    Some(FsWaiter::Embedded { owner: Some(o), .. })
                        if *o == owner =>
                    {
                        Some(pack_raw(tag, i as u32, entry.generation as u32))
                    }
                    Some(FsWaiter::Pump { owner: o }) if *o == owner => {
                        Some(pack_raw(tag, i as u32, entry.generation as u32))
                    }
                    _ => None,
                }
            })
            .collect();
        for ud in targets {
            self.submit_cancel(eng, ud);
        }
    }

    // ---- completion routing --------------------------------------------

    /// Route one fs-domain CQE. `tag` is the unpacked op tag; a generation
    /// mismatch makes the completion inert (op entries free only at their own
    /// terminal CQE). An **off-loop** (channel) op is delivered here and returns
    /// [`ReapedFs::None`]; an **embedded** (on-loop) op hands back its
    /// callback and outcome for the host to fire once its borrow of the fs
    /// tables has ended; a **pump** read hands back its outcome and owner
    /// for the host to route itself.
    pub(crate) fn on_cqe(
        &mut self,
        _eng: &mut Engine,
        tag: u8,
        op_slot: u32,
        gen32: u32,
        res: i32,
    ) -> ReapedFs {
        if tag == TAG_CANCEL {
            // An ASYNC_CANCEL's own completion; nothing to route.
            return ReapedFs::None;
        }
        let Some(Completed { waiter, bufs, stat }) =
            self.take_op(tag, op_slot, gen32)
        else {
            return ReapedFs::None;
        };

        // A successful OPENAT2 returns a real fd as its result; wrap it in an
        // `Arc<OwnedFd>`. If nobody takes it (a gone channel receiver, or a
        // dropped embedded callback) the `Arc` drops and the fd closes - no
        // leak, no explicit close op. The op entry's parked `file` `Arc` (for
        // an fd op) was already dropped by `take_op`'s `clear`, giving
        // close-last ordering by ownership.
        let file = if tag == TAG_OPEN && res >= 0 {
            // SAFETY: `res` is a fresh fd OPENAT2 just returned; nothing else
            // owns it.
            Some(Arc::new(unsafe { crate::fd::owned_from_raw(res) }))
        } else {
            None
        };
        let result = map_res(res);

        match waiter {
            Some(FsWaiter::Channel(tx)) => {
                let _ = tx.send(FsOutcome::new(result, bufs, file, stat));
                ReapedFs::None
            }
            Some(FsWaiter::Embedded { owner, cb }) => ReapedFs::Embedded(
                cb,
                FsDone {
                    result,
                    bufs,
                    file: file.map(File::new),
                    stat,
                },
                owner,
            ),
            Some(FsWaiter::Pump { owner }) => ReapedFs::Pump(
                FsDone {
                    result,
                    bufs,
                    file: file.map(File::new),
                    stat,
                },
                owner,
            ),
            None => ReapedFs::None,
        }
    }

    /// Teardown-drain routing: reply and free, but never stage (the drain is
    /// cancelling everything; deferred closes are moot - the ring teardown
    /// closes the whole registered table).
    pub(crate) fn on_drain_cqe(&mut self, cqe: &IoUringCqe) {
        let (tag, op_slot, gen32) = unpack_raw(cqe.user_data);
        if tag & 0x80 == 0 || tag == TAG_CANCEL || tag == TAG_WAKE {
            return;
        }
        let Some(done) = self.take_op(tag, op_slot, gen32) else {
            return;
        };
        let Completed { waiter, bufs, stat } = done;
        // Teardown: the loop is dying - just report the outcome and hand any
        // buffers back. A file's fd is released when its op entry (and thus its
        // parked `Arc`) is dropped with the ring teardown.
        deliver(waiter, map_res(cqe.res), bufs, None, stat);
    }

    /// Leak the op table without dropping it - used ONLY when a teardown
    /// drain failed with ops possibly still in flight. The kernel may still
    /// write into a `READV`/`FGETXATTR` destination or the boxed `STATX`
    /// buffer until its CQE reaps, so freeing those here would be a
    /// use-after-free; forget them instead (mirrors the net stack's
    /// `ConnTable::leak`, and pairs with `Engine::leak_wake_buf`). Only the op
    /// table owns kernel-visible memory; the file table does not.
    pub(crate) fn leak(&mut self) {
        std::mem::forget(std::mem::take(&mut self.ops));
    }

    // ---- internals -----------------------------------------------------

    /// Take a completed op entry out: returns its waiter and payloads and
    /// frees the slot (generation bumped) - the freed-before-fire rule.
    fn take_op(
        &mut self,
        tag: u8,
        op_slot: u32,
        gen32: u32,
    ) -> Option<Completed> {
        let entry = self.ops.get_mut(op_slot as usize)?;
        if entry.generation as u32 != gen32 {
            return None;
        }
        match entry.state.state {
            FsOpState::InFlight { tag: t } if t == tag => {}
            _ => return None,
        }
        let e = &mut entry.state;
        let done = Completed {
            waiter: e.waiter.take(),
            bufs: std::mem::take(&mut e.bufs),
            stat: e.stat.take(),
        };
        e.clear();
        entry.generation += 1;
        self.op_free.push(op_slot);
        Some(done)
    }

    /// Fail a just-reserved op entry before its SQE ever reached the kernel:
    /// report and free (buffers go back to the caller, as on completion). A
    /// stage failure never fires an embedded callback - `let _ =` drops it,
    /// closing the connection via its captured `Deferred`.
    fn fail_op(&mut self, op_slot: u32, err: Errno) {
        let entry = &mut self.ops[op_slot as usize];
        let e = &mut entry.state;
        let waiter = e.waiter.take();
        let bufs = std::mem::take(&mut e.bufs);
        e.stat = None;
        e.clear();
        entry.generation += 1;
        self.op_free.push(op_slot);
        deliver(waiter, Err(err), bufs, None, None);
    }
}

/// The outcome handed to an embedded [`FsConn`] callback: the op's result plus
/// anything it produced (buffers, a new open [`File`], or `statx` metadata).
#[cfg_attr(not(feature = "net-server"), allow(dead_code))]
pub struct FsDone {
    result: Result<i32, Errno>,
    bufs: Vec<Vec<u8>>,
    file: Option<File>,
    stat: Option<Box<StatxRaw>>,
}

impl std::fmt::Debug for FsDone {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FsDone")
            .field("result", &self.result)
            .finish_non_exhaustive()
    }
}

#[cfg_attr(not(feature = "net-server"), allow(dead_code))]
impl FsDone {
    /// A completion no op produced - what a multi-step call answers
    /// with when it refuses between steps.
    pub(crate) fn failed(err: Errno) -> FsDone {
        FsDone {
            result: Err(err),
            bufs: Vec::new(),
            file: None,
            stat: None,
        }
    }

    /// The op's result: a byte count / `0`, or the errno it failed with.
    pub fn result(&self) -> crate::Result<i32> {
        self.result.map_err(Into::into)
    }

    /// The raw result, errno unwrapped - for the reply-path pump, which maps
    /// a failure to a [`CloseReason`](crate::net::server::CloseReason)
    /// carrying the errno itself.
    #[cfg(feature = "net-server")]
    pub(crate) fn raw_result(&self) -> Result<i32, Errno> {
        self.result
    }

    /// The freshly opened file - present only for a successful `open`.
    pub fn file(&self) -> Option<File> {
        self.file.clone()
    }

    /// Take the op's buffers back (read destinations / xattr value).
    pub fn into_bufs(self) -> Vec<Vec<u8>> {
        self.bufs
    }

    /// The `statx` metadata - present only for a successful `statx`.
    pub fn stat(&self) -> Option<Statx> {
        self.stat.as_deref().copied().map(Statx::from_raw)
    }
}

/// The request-bound fs submission facade a `net` server hands a protocol
/// handler and re-hands each completion callback for chaining. Every op runs on
/// the server's ring, checked as the [`Personality`] passed to it, and its
/// completion fires the `on_done` callback **inline on the loop thread**.
///
/// **Re-entrancy:** callbacks run inside dispatch - never block, and drive the
/// ring only through this facade. A submission or argument-validation failure
/// drops `on_done` (and the continuation it captured, closing the connection),
/// so these methods return `()`.
#[cfg_attr(not(feature = "net-server"), allow(dead_code))]
pub struct FsConn<'a> {
    fs: &'a mut FsCore,
    eng: &'a mut Engine,
    owner: Owner,
    root: bool,
}

impl std::fmt::Debug for FsConn<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FsConn").finish_non_exhaustive()
    }
}

#[cfg_attr(not(feature = "net-server"), allow(dead_code))]
impl<'a> FsConn<'a> {
    pub(crate) fn new(
        fs: &'a mut FsCore,
        eng: &'a mut Engine,
        owner: Owner,
        root: bool,
    ) -> FsConn<'a> {
        FsConn {
            fs,
            eng,
            owner,
            root,
        }
    }

    /// Open `path` relative to `anchor` as `who`; fire `on_done` with the new
    /// [`File`] ([`FsDone::file`]). `path` must be anchor-relative (a leading
    /// `/` is refused); resolution defaults to `RESOLVE_BENEATH |
    /// RESOLVE_NO_SYMLINKS` unless `how` chose its own. Only the request-handler
    /// facade may open (a continuation's `open` is refused). An invalid argument
    /// drops `on_done`, closing the connection.
    pub fn open<F>(
        &mut self,
        who: Personality,
        anchor: &Anchor,
        path: &CStr,
        how: OpenHow,
        on_done: F,
    ) where
        F: FnOnce(FsDone, &mut FsConn<'_>) + 'static,
    {
        if !self.root {
            return;
        }
        let bytes = path.to_bytes();
        if bytes.is_empty() || bytes[0] == b'/' {
            // Server facade: anchor-relative only (and `root`-gated above),
            // deliberately stricter than the general-client `FsHandle::open`
            // (`open_parts`), which allows an absolute path when the caller
            // drops `RESOLVE_BENEATH`. The two validations differ on purpose;
            // do not unify them.
            return;
        }
        let mut raw = how.to_raw();
        if raw.resolve == 0 {
            raw.resolve = ResolveFlag::RESOLVE_BENEATH
                .union(ResolveFlag::RESOLVE_NO_SYMLINKS)
                .bits();
        }
        self.fs.submit_open(
            self.eng,
            who.0,
            anchor.clone(),
            path.to_owned(),
            raw,
            embed(self.owner, on_done),
        );
    }

    /// Create every missing directory along `path` beneath `anchor` as
    /// `who`, then open the deepest one with `how` - `mkdir -p`,
    /// confined, on the ring. The reactor twin of
    /// [`FsHandle::mkdir_path`](crate::uring_fs::FsHandle::mkdir_path).
    ///
    /// `on_done` receives the final open, so `how` decides what the
    /// caller gets: an `O_PATH` handle to anchor against, or a directory
    /// it can `fsync`, which `O_PATH` cannot (`EBADF`).
    ///
    /// `EEXIST` is success at every component, so two callers building
    /// one tree both finish.
    ///
    /// # Why this is a primitive rather than caller code
    ///
    /// `mkdirat` honours **no** `RESOLVE_*` flags - that is what [`Leaf`]
    /// exists for - so handing it `"a/b/c"` would resolve the
    /// intermediate components unconfined. The only sound construction
    /// alternates confined `openat2` walks with single-component
    /// `mkdirat`s, and each of those opens depends on the completion
    /// before it. A consumer cannot write that loop: every step after
    /// the first is a continuation, where [`open`](Self::open) is
    /// refused. Keeping the walk here is what lets that refusal stand.
    ///
    /// `CONFINED_RESOLVE` is unioned in, not assigned: a caller may add
    /// restrictions and may drop none. Unlike a plain open, this one
    /// creates, and a create that escaped the anchor would leave a
    /// directory somewhere the caller never named.
    ///
    /// Entry is `root`-gated like [`open`](Self::open), and for its
    /// reason: the directory this hands back would outlive a connection
    /// that has already gone.
    pub fn mkdir_path<F>(
        &mut self,
        who: Personality,
        anchor: &Anchor,
        path: &CStr,
        mode: Mode,
        how: OpenHow,
        on_done: F,
    ) where
        F: FnOnce(FsDone, &mut FsConn<'_>) + 'static,
    {
        if !self.root {
            return;
        }
        let bytes = path.to_bytes();
        if bytes.is_empty() || bytes[0] == b'/' {
            return;
        }
        // Validated before anything is submitted, so a path carrying a
        // component `mkdirat` must not see fails whole rather than
        // leaving half a tree.
        let mut parts: VecDeque<CString> = VecDeque::new();
        for part in bytes.split(|&b| b == b'/').filter(|p| !p.is_empty()) {
            match Leaf::new(part) {
                Ok(leaf) => parts.push_back(leaf.to_cstring()),
                Err(_) => {
                    return fail(
                        embed(self.owner, on_done),
                        Errno::EINVAL,
                        Vec::new(),
                    );
                }
            }
        }
        let mut raw = how.to_raw();
        raw.resolve |= CONFINED_RESOLVE.bits();

        let (start, want) = (anchor.clone(), path.to_owned());
        let on_done: WalkDone = Box::new(on_done);
        self.open_component(who, start.clone(), want, raw, move |res, conn| {
            if res.file().is_some() {
                return on_done(res, conn);
            }
            walk(conn, who, start, parts, mode, raw, on_done);
        });
    }

    /// Submit an open that is not the request handler's own.
    ///
    /// [`open`](Self::open) refuses a continuation because the file it
    /// produces has nowhere to go once the owning connection is gone
    /// (`net/server/mod.rs`, the `root: false` facade). A walk's
    /// intermediates never leave the walk - each is owned by the closure
    /// that opened it and closes with the chain - so that leak cannot
    /// arise here. The final open does reach the consumer, which is what
    /// [`mkdir_path`](Self::mkdir_path) gates at entry instead.
    ///
    /// Stays private: every path this resolves is a single validated
    /// component of one the caller already named, confined, under the
    /// caller's own personality.
    fn open_component<F>(
        &mut self,
        who: Personality,
        anchor: Anchor,
        path: CString,
        how: RawOpenHow,
        on_done: F,
    ) where
        F: FnOnce(FsDone, &mut FsConn<'_>) + 'static,
    {
        self.fs.submit_open(
            self.eng,
            who.0,
            anchor,
            path,
            how,
            embed(self.owner, on_done),
        );
    }

    /// Scattered positional read with per-operation flags (`preadv2(2)`).
    /// See [`RwFlags`] - an unsupported flag fails the read with
    /// `EOPNOTSUPP` rather than being ignored.
    #[allow(clippy::too_many_arguments)]
    pub fn preadv2<F>(
        &mut self,
        who: Personality,
        f: File,
        bufs: Vec<Vec<u8>>,
        off: u64,
        flags: RwFlags,
        on_done: F,
    ) where
        F: FnOnce(FsDone, &mut FsConn<'_>) + 'static,
    {
        self.rw(TAG_READV, who, f, bufs, off, flags, on_done);
    }

    /// Gathered positional write with per-operation flags (`pwritev2(2)`).
    /// [`RwFlags::RWF_DSYNC`] makes the write itself durable, which can stand
    /// in for a following `fdatasync` - worth measuring on ZFS, where a
    /// synchronous write goes through the ZIL.
    #[allow(clippy::too_many_arguments)]
    pub fn pwritev2<F>(
        &mut self,
        who: Personality,
        f: File,
        bufs: Vec<Vec<u8>>,
        off: u64,
        flags: RwFlags,
        on_done: F,
    ) where
        F: FnOnce(FsDone, &mut FsConn<'_>) + 'static,
    {
        self.rw(TAG_WRITEV, who, f, bufs, off, flags, on_done);
    }

    /// Flush `f`'s data and metadata (`fsync`) as `who`.
    pub fn fsync<F>(&mut self, who: Personality, f: File, on_done: F)
    where
        F: FnOnce(FsDone, &mut FsConn<'_>) + 'static,
    {
        self.fs.submit_fsync(
            self.eng,
            who.0,
            f.fd,
            false,
            0,
            0,
            embed(self.owner, on_done),
        );
    }

    /// Flush `f`'s data and essential metadata (`fdatasync`) as `who`.
    pub fn fdatasync<F>(&mut self, who: Personality, f: File, on_done: F)
    where
        F: FnOnce(FsDone, &mut FsConn<'_>) + 'static,
    {
        self.fs.submit_fsync(
            self.eng,
            who.0,
            f.fd,
            true,
            0,
            0,
            embed(self.owner, on_done),
        );
    }

    /// Flush the byte range `[offset, offset + length)` of `f` as `who`
    /// (`datasync` selects `fdatasync` semantics); `offset == 0 && length == 0`
    /// syncs the whole file. `length` is the SQE's 32-bit field.
    pub fn fsync_range<F>(
        &mut self,
        who: Personality,
        f: File,
        datasync: bool,
        offset: u64,
        length: u32,
        on_done: F,
    ) where
        F: FnOnce(FsDone, &mut FsConn<'_>) + 'static,
    {
        self.fs.submit_fsync(
            self.eng,
            who.0,
            f.fd,
            datasync,
            offset,
            length,
            embed(self.owner, on_done),
        );
    }

    /// Stat the entry `leaf` inside `anchor` as `who` (no terminal-symlink
    /// follow by default; opt in with `AT_SYMLINK_FOLLOW`).
    pub fn statx<F>(
        &mut self,
        who: Personality,
        anchor: &Anchor,
        leaf: Leaf<'_>,
        flags: AtFlags,
        mask: StatxMask,
        on_done: F,
    ) where
        F: FnOnce(FsDone, &mut FsConn<'_>) + 'static,
    {
        self.fs.submit_path_op(
            self.eng,
            TAG_STATX,
            who.0,
            anchor.clone(),
            leaf.to_cstring(),
            None,
            None,
            statx_at_flags(flags),
            mask.bits(),
            embed(self.owner, on_done),
        );
    }

    /// Stat the anchor directory itself (`AT_EMPTY_PATH` on its dirfd).
    pub fn statx_anchor<F>(
        &mut self,
        who: Personality,
        anchor: &Anchor,
        flags: AtFlags,
        mask: StatxMask,
        on_done: F,
    ) where
        F: FnOnce(FsDone, &mut FsConn<'_>) + 'static,
    {
        self.fs.submit_path_op(
            self.eng,
            TAG_STATX,
            who.0,
            anchor.clone(),
            CString::default(),
            None,
            None,
            statx_at_flags(flags | AtFlags::AT_EMPTY_PATH),
            mask.bits(),
            embed(self.owner, on_done),
        );
    }

    /// Stat the open file `f` itself (`AT_EMPTY_PATH` on its fd) as `who`, the
    /// on-loop twin of [`FsHandle::fstatx`](super::FsHandle::fstatx).
    pub fn fstatx<F>(
        &mut self,
        who: Personality,
        f: &File,
        flags: AtFlags,
        mask: StatxMask,
        on_done: F,
    ) where
        F: FnOnce(FsDone, &mut FsConn<'_>) + 'static,
    {
        let anchor = Anchor::from_shared(f.fd.clone());
        self.statx_anchor(who, &anchor, flags, mask, on_done);
    }

    /// Read extended attribute `name` from `f` into `buf` as `who`. Needs
    /// Linux >= 6.13; fails closed (`EOPNOTSUPP`) otherwise.
    pub fn fgetxattr<F>(
        &mut self,
        who: Personality,
        f: File,
        name: &CStr,
        buf: Vec<u8>,
        on_done: F,
    ) where
        F: FnOnce(FsDone, &mut FsConn<'_>) + 'static,
    {
        self.fd_meta(
            TAG_FGETXATTR,
            who,
            f,
            Some(name.to_owned()),
            buf,
            0,
            0,
            0,
            on_done,
        );
    }

    /// Read extended attribute `name` from `f` under the reactor's **ambient
    /// root** - no `who`. The one sanctioned privileged read: for a
    /// `trusted.*`/`security.*` attribute a request's own identity cannot see
    /// (`sqe.personality`, not the fd's open-time cred, governs `fgetxattr`'s
    /// `CAP_SYS_ADMIN` check; `personality = 0` runs as the ring owner, root).
    /// Needs Linux >= 6.13; fails closed (`EOPNOTSUPP`) otherwise.
    pub fn fgetxattr_as_root<F>(
        &mut self,
        f: File,
        name: &CStr,
        buf: Vec<u8>,
        on_done: F,
    ) where
        F: FnOnce(FsDone, &mut FsConn<'_>) + 'static,
    {
        self.fs.submit_fgetxattr_as_root(
            self.eng,
            f.fd,
            name.to_owned(),
            buf,
            embed(self.owner, on_done),
        );
    }

    /// Write extended attribute `name` on `f` as `who`.
    pub fn fsetxattr<F>(
        &mut self,
        who: Personality,
        f: File,
        name: &CStr,
        value: Vec<u8>,
        flags: i32,
        on_done: F,
    ) where
        F: FnOnce(FsDone, &mut FsConn<'_>) + 'static,
    {
        self.fd_meta(
            TAG_FSETXATTR,
            who,
            f,
            Some(name.to_owned()),
            value,
            0,
            0,
            flags as u32,
            on_done,
        );
    }

    /// Set `f`'s length to `len` (`ftruncate`). Needs Linux >= 6.9.
    pub fn ftruncate<F>(
        &mut self,
        who: Personality,
        f: File,
        len: u64,
        on_done: F,
    ) where
        F: FnOnce(FsDone, &mut FsConn<'_>) + 'static,
    {
        self.fd_meta(
            TAG_FTRUNCATE,
            who,
            f,
            None,
            Vec::new(),
            len,
            0,
            0,
            on_done,
        );
    }

    /// Manipulate `f`'s allocated blocks (`fallocate`): `mode` is 0 or a
    /// `FALLOC_FL_*` combination.
    pub fn fallocate<F>(
        &mut self,
        who: Personality,
        f: File,
        mode: i32,
        off: u64,
        len: u64,
        on_done: F,
    ) where
        F: FnOnce(FsDone, &mut FsConn<'_>) + 'static,
    {
        self.fd_meta(
            TAG_FALLOCATE,
            who,
            f,
            None,
            Vec::new(),
            off,
            len,
            mode as u32,
            on_done,
        );
    }

    /// Advise the kernel how a range of `f` will be used (`posix_fadvise`);
    /// `len` of 0 means to the end of the file. See
    /// [`Advice`](crate::uring_fs::Advice) - on ZFS these reach the ARC, not
    /// just the page cache.
    pub fn fadvise<F>(
        &mut self,
        who: Personality,
        f: File,
        off: u64,
        len: u64,
        advice: crate::uring_fs::Advice,
        on_done: F,
    ) where
        F: FnOnce(FsDone, &mut FsConn<'_>) + 'static,
    {
        self.fd_meta(
            TAG_FADVISE,
            who,
            f,
            None,
            Vec::new(),
            off,
            len,
            advice as u32,
            on_done,
        );
    }

    /// Move up to `len` bytes from `pipe`'s read end into `f` at `off`,
    /// without a userspace buffer (`IORING_OP_SPLICE`).
    ///
    /// This is the ingest half of a zero-copy body path: whoever fills the
    /// pipe (a socket splice, a `vmsplice`) never materializes the bytes, and
    /// neither does this. `pipe` is a plain descriptor the caller keeps open
    /// until the completion fires - it is **not** taken into the fixed-file
    /// pool, so it does not consume a `FsConfig::ops` slot.
    ///
    /// # Short moves are normal
    ///
    /// A pipe delivers what it has, so a completion carrying fewer than `len`
    /// bytes is ordinary progress, not end of input: resubmit the remainder.
    /// [`FsDone::result`] is the byte count either way - the kernel's
    /// `req_set_fail` on a short move (`io_splice`, `io_uring/splice.c`)
    /// governs only whether an `IOSQE_IO_LINK` chain continues, which this
    /// does not use.
    ///
    /// Splice cannot hash what it moves - nothing passes through userspace.
    /// A body that needs an ETag has to be read conventionally, which is the
    /// tradeoff this exists to let a caller make per request.
    pub fn splice_from_pipe<F>(
        &mut self,
        who: Personality,
        f: File,
        pipe: RawFd,
        off: u64,
        len: u32,
        on_done: F,
    ) where
        F: FnOnce(FsDone, &mut FsConn<'_>) + 'static,
    {
        self.fd_meta(
            TAG_SPLICE,
            who,
            f,
            None,
            Vec::new(),
            off,
            // Carried to `splice_fd_in`; see the `TAG_SPLICE` staging arm.
            pipe as u32 as u64,
            len,
            on_done,
        );
    }

    /// Create directory `leaf` inside `anchor` as `who`.
    pub fn mkdirat<F>(
        &mut self,
        who: Personality,
        anchor: &Anchor,
        leaf: Leaf<'_>,
        mode: Mode,
        on_done: F,
    ) where
        F: FnOnce(FsDone, &mut FsConn<'_>) + 'static,
    {
        self.path_op(
            TAG_MKDIRAT,
            who,
            anchor,
            leaf.to_cstring(),
            None,
            None,
            0,
            mode.bits(),
            on_done,
        );
    }

    /// Remove file `leaf` from `anchor` as `who`.
    pub fn unlinkat<F>(
        &mut self,
        who: Personality,
        anchor: &Anchor,
        leaf: Leaf<'_>,
        on_done: F,
    ) where
        F: FnOnce(FsDone, &mut FsConn<'_>) + 'static,
    {
        self.path_op(
            TAG_UNLINKAT,
            who,
            anchor,
            leaf.to_cstring(),
            None,
            None,
            0,
            0,
            on_done,
        );
    }

    /// Remove empty directory `leaf` from `anchor` as `who` (`AT_REMOVEDIR`).
    pub fn rmdirat<F>(
        &mut self,
        who: Personality,
        anchor: &Anchor,
        leaf: Leaf<'_>,
        on_done: F,
    ) where
        F: FnOnce(FsDone, &mut FsConn<'_>) + 'static,
    {
        self.path_op(
            TAG_UNLINKAT,
            who,
            anchor,
            leaf.to_cstring(),
            None,
            None,
            libc::AT_REMOVEDIR as u32,
            0,
            on_done,
        );
    }

    /// Rename `old_leaf` in `old` to `new_leaf` in `new` as `who`.
    #[allow(clippy::too_many_arguments)]
    pub fn renameat<F>(
        &mut self,
        who: Personality,
        old: &Anchor,
        old_leaf: Leaf<'_>,
        new: &Anchor,
        new_leaf: Leaf<'_>,
        flags: RenameFlags,
        on_done: F,
    ) where
        F: FnOnce(FsDone, &mut FsConn<'_>) + 'static,
    {
        self.path_op(
            TAG_RENAMEAT,
            who,
            old,
            old_leaf.to_cstring(),
            Some(new),
            Some(new_leaf.to_cstring()),
            flags.bits(),
            0,
            on_done,
        );
    }

    /// Create a symlink `leaf` in `anchor` pointing at `target` as `who`
    /// (`target` is link content, stored verbatim). An empty target is refused.
    pub fn symlinkat<F>(
        &mut self,
        who: Personality,
        target: &CStr,
        anchor: &Anchor,
        leaf: Leaf<'_>,
        on_done: F,
    ) where
        F: FnOnce(FsDone, &mut FsConn<'_>) + 'static,
    {
        if target.to_bytes().is_empty() {
            return;
        }
        self.fs.submit_path_op(
            self.eng,
            TAG_SYMLINKAT,
            who.0,
            anchor.clone(),
            target.to_owned(),
            None,
            Some(leaf.to_cstring()),
            0,
            0,
            embed(self.owner, on_done),
        );
    }

    /// Create a hard link at `new_leaf` in `new` for `old_leaf` in `old`.
    #[allow(clippy::too_many_arguments)]
    pub fn linkat<F>(
        &mut self,
        who: Personality,
        old: &Anchor,
        old_leaf: Leaf<'_>,
        new: &Anchor,
        new_leaf: Leaf<'_>,
        flags: AtFlags,
        on_done: F,
    ) where
        F: FnOnce(FsDone, &mut FsConn<'_>) + 'static,
    {
        self.path_op(
            TAG_LINKAT,
            who,
            old,
            old_leaf.to_cstring(),
            Some(new),
            Some(new_leaf.to_cstring()),
            flags.bits() as u32,
            0,
            on_done,
        );
    }

    /// Give the already-open `f` a name at `new_leaf` in `new`
    /// (`linkat` with `AT_EMPTY_PATH`) - the publish step for an `O_TMPFILE`
    /// create. See [`FsHandle::linkat_file`](crate::uring_fs::FsHandle::linkat_file)
    /// for the two kernel requirements (`O_TMPFILE` without `O_EXCL`, and the
    /// *same* personality that opened `f`), both of which fail as `ENOENT`.
    pub fn linkat_file<F>(
        &mut self,
        who: Personality,
        f: File,
        new: &Anchor,
        new_leaf: Leaf<'_>,
        on_done: F,
    ) where
        F: FnOnce(FsDone, &mut FsConn<'_>) + 'static,
    {
        self.fs.submit_linkat_file(
            self.eng,
            who.0,
            f.fd,
            new.clone(),
            new_leaf.to_cstring(),
            embed(self.owner, on_done),
        );
    }

    /// Close `f`: drop the handle. Its fd closes once the last reference (this
    /// handle plus any op still parking a clone) drops - close-last by
    /// ownership. Fire-and-forget; there is no completion callback.
    pub fn close(&mut self, f: File) {
        drop(f);
    }

    // ---- private submit helpers ----------------------------------------

    #[allow(clippy::too_many_arguments)]
    fn rw<F>(
        &mut self,
        tag: u8,
        who: Personality,
        f: File,
        bufs: Vec<Vec<u8>>,
        off: u64,
        rw_flags: RwFlags,
        on_done: F,
    ) where
        F: FnOnce(FsDone, &mut FsConn<'_>) + 'static,
    {
        self.fs.submit_rw(
            self.eng,
            tag,
            who.0,
            f.fd,
            bufs,
            off,
            rw_flags.bits(),
            embed(self.owner, on_done),
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn fd_meta<F>(
        &mut self,
        tag: u8,
        who: Personality,
        f: File,
        name: Option<CString>,
        value: Vec<u8>,
        off: u64,
        len64: u64,
        aux32: u32,
        on_done: F,
    ) where
        F: FnOnce(FsDone, &mut FsConn<'_>) + 'static,
    {
        self.fs.submit_fd_meta(
            self.eng,
            tag,
            who.0,
            f.fd,
            name,
            value,
            off,
            len64,
            aux32,
            embed(self.owner, on_done),
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn path_op<F>(
        &mut self,
        tag: u8,
        who: Personality,
        a1: &Anchor,
        n1: CString,
        a2: Option<&Anchor>,
        n2: Option<CString>,
        flags: u32,
        len_arg: u32,
        on_done: F,
    ) where
        F: FnOnce(FsDone, &mut FsConn<'_>) + 'static,
    {
        self.fs.submit_path_op(
            self.eng,
            tag,
            who.0,
            a1.clone(),
            n1,
            a2.cloned(),
            n2,
            flags,
            len_arg,
            embed(self.owner, on_done),
        );
    }
}

/// The callback a [`FsConn::mkdir_path`] walk carries between steps.
///
/// Boxed: the walk is a loop written as recursion, so a generic parameter
/// would be a type that contains itself.
type WalkDone = Box<dyn FnOnce(FsDone, &mut FsConn<'_>)>;

/// One component: create it, open it, and recurse on what is left.
///
/// `cur` is the deepest directory reached so far, and the last component's
/// open is the answer.
fn walk(
    conn: &mut FsConn<'_>,
    who: Personality,
    cur: Anchor,
    mut parts: VecDeque<CString>,
    mode: Mode,
    how: RawOpenHow,
    on_done: WalkDone,
) {
    let Some(part) = parts.pop_front() else {
        // Entry validated a non-empty list. Answered rather than dropped:
        // a dropped callback closes the connection.
        return on_done(FsDone::failed(Errno::EINVAL), conn);
    };
    let bytes = part.clone().into_bytes();
    let Ok(leaf) = Leaf::new(&bytes) else {
        return on_done(FsDone::failed(Errno::EINVAL), conn);
    };
    let at = cur.clone();
    conn.mkdirat(who, &at, leaf, mode, move |res, conn| {
        match res.result() {
            // `mkdir -p`'s rule, and the outcome of losing a race with
            // another creator.
            Ok(_) | Err(crate::Error::Errno(Errno::EEXIST)) => {}
            Err(_) => return on_done(res, conn),
        }
        conn.open_component(who, cur, part, how, move |res, conn| {
            let Some(f) = res.file() else {
                return on_done(res, conn);
            };
            if parts.is_empty() {
                return on_done(res, conn);
            }
            match Anchor::from_file(&f) {
                Ok(next) => walk(conn, who, next, parts, mode, how, on_done),
                Err(_) => on_done(FsDone::failed(Errno::EBADF), conn),
            }
        });
    });
}

// ---- hybrid off-loop listing: threaded readdir + on-loop enrichment --------

/// A `*mut DIR` handed between the reactor and a worker thread. Sound only
/// because the walk gives it to exactly one thread at a time (reactor -> worker
/// for a batch, worker -> reactor on delivery) and never shares it concurrently.
///
/// Owns the `DIR*`: dropping it `closedir`s the handle, so a batch result that
/// is never delivered (the walk dropped mid-flight, or a worker job unwinds)
/// reclaims the fd instead of leaking it. Ownership is passed on, rather than
/// duplicated, with [`SendDir::into_raw`].
struct SendDir(*mut libc::DIR);
// SAFETY: single-owner-at-a-time hand-off, never aliased across threads.
unsafe impl Send for SendDir {}

impl SendDir {
    /// Take the `DIR*` out, leaving the wrapper null so its `Drop` is inert,
    /// for handing ownership to a [`DirWalkInner`].
    #[cfg_attr(not(feature = "net-server"), allow(dead_code))]
    fn into_raw(mut self) -> *mut libc::DIR {
        std::mem::replace(&mut self.0, std::ptr::null_mut())
    }
}

impl Drop for SendDir {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: a live DIR* from fdopendir, owned here, closed once.
            unsafe { libc::closedir(self.0) };
        }
    }
}

struct DirWalkInner {
    /// The open directory. `null` while a readdir batch runs on a worker.
    dp: *mut libc::DIR,
    /// A batch job currently holds `dp`.
    in_flight: bool,
    /// The `DirWalk` was dropped; the in-flight batch must close `dp`.
    dropped: bool,
}

/// A directory being walked by the hybrid lister ([`FsConn::open_dir`] /
/// [`FsConn::next_batch`]). The reactor holds it while the blocking `readdir`
/// runs off-loop on the pool; dropping it closes the `DIR*` (deferring to an
/// in-flight batch's delivery if one is running), so the fd never leaks.
///
/// DAC is preserved: the list-permission check ran on the ring under `who` in
/// `open_dir`; the pool only ever `readdir`s that already-authorized fd.
#[cfg_attr(not(feature = "net-server"), allow(dead_code))]
pub struct DirWalk {
    inner: Rc<RefCell<DirWalkInner>>,
}

impl std::fmt::Debug for DirWalk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DirWalk").finish_non_exhaustive()
    }
}

impl Drop for DirWalk {
    fn drop(&mut self) {
        let mut b = self.inner.borrow_mut();
        b.dropped = true;
        // If no batch job holds the DIR*, close it now; otherwise the batch's
        // delivery sees `dropped` and closes it when the worker hands it back.
        if !b.in_flight && !b.dp.is_null() {
            // SAFETY: a live DIR* from fdopendir, closed exactly once.
            unsafe { libc::closedir(b.dp) };
            b.dp = std::ptr::null_mut();
        }
    }
}

/// One batch of raw entry names from a [`DirWalk`].
#[cfg_attr(not(feature = "net-server"), allow(dead_code))]
#[derive(Debug)]
pub struct NameBatch {
    /// Entry names (one path component each); `.` and `..` are skipped.
    pub names: Vec<Vec<u8>>,
    /// True once the directory has been read to the end.
    pub eod: bool,
}

impl FsConn<'_> {
    /// Run `job` on a blocking worker thread, then deliver its result to
    /// `on_done` **on the reactor thread** with a fresh owner-scoped [`FsConn`].
    /// The generic escape hatch for work with no io_uring op (readdir,
    /// `fdopendir`, an ioctl): the reactor stays free while the job runs, and
    /// the continuation resumes on-loop like any completion callback.
    /// `on_done` receives a [`thread::Result`] because a panicking job must
    /// still deliver: the completion carries the panic, so the continuation
    /// runs, the registration is retired, and any reactor-side state the caller
    /// holds is released instead of stranded.
    ///
    /// The consumer shape this exists for: batch a request's whole blocking
    /// metadata tail into **one job** - several synchronous calls, one pool
    /// round trip, one delivery. [`statx`](crate::sync_fs::statx) plus
    /// [`fgetxattr`](crate::sync_fs::xattr::fgetxattr) reads before streaming
    /// a body, [`fsetxattr`](crate::sync_fs::xattr::fsetxattr) writes after
    /// one. A cached metadata syscall costs less than any round trip, so the
    /// win comes from paying one handoff per batch rather than one per call.
    ///
    /// The job contract - every derived facility above and
    /// [`offload_result`](Self::offload_result) share it:
    ///
    /// - **Jobs take open [`File`]s or descriptors, never names.** The
    ///   credential-checked step - the open, any path op - runs first on the
    ///   ring as a personality-stamped SQE; the job then runs at the
    ///   reactor's **ambient credentials** against the already-authorized fd,
    ///   and the kernel checks nothing in it against a request identity. See
    ///   [`fset_zfs_attrs`](Self::fset_zfs_attrs) and
    ///   `FsCore::remove_priv_xattr` for the same reasoning.
    /// - **Never mutate thread-wide state from a job** - credentials
    ///   (`setfsuid`), umask, signal dispositions. The workers are shared
    ///   with every consumer of the pool, the reactor's privileged offloads
    ///   included.
    /// - **An offload is never cancelled.** `cancel_owned_by` sweeps ring
    ///   ops only; the job always runs to completion and its delivery always
    ///   fires, possibly for an owner that is gone - a continuation must
    ///   already tolerate that (its facade cannot `open`, and a deferred
    ///   reply is generation-checked).
    /// - **The registry and pool queue are uncapped.** Bound in-flight jobs
    ///   upstream, at the request cap. A failed worker spawn runs the job
    ///   inline on the loop rather than lose it (`SharedPool`).
    /// - **A job runs on an ordinary thread stack** (std's default, moved by
    ///   `RUST_MIN_STACK` like any other). Bound a job's recursion or keep it
    ///   on the heap as the jobs here do: a panicking job is caught and
    ///   retires alone, but an *overflowing* one is a `SIGSEGV` that
    ///   `catch_unwind` cannot catch and that aborts the process, so it is the
    ///   one job-side mistake the pool cannot contain.
    pub fn offload<R, J, F>(&mut self, job: J, on_done: F)
    where
        J: FnOnce() -> R + Send + 'static,
        R: Send + 'static,
        F: FnOnce(thread::Result<R>, &mut FsConn<'_>) + 'static,
    {
        let deliver: OffloadDeliver = Box::new(move |any, conn| {
            // The token pairs this continuation with the job that produced
            // exactly this `thread::Result<R>`, so the downcast cannot mismatch.
            if let Ok(r) = any.downcast::<thread::Result<R>>() {
                on_done(*r, conn);
            }
        });
        let token = self.fs.register_offload(self.owner, deliver);
        let sink = self.fs.completion_sink();
        let wake = Arc::clone(&self.eng.shared);
        self.fs.submit_offload(Box::new(move || {
            // Push and poke unconditionally: an unwind past either one would
            // leave `offload_reg` holding a continuation that never fires.
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(job));
            sink.lock()
                .unwrap_or_else(|e| e.into_inner())
                .push_back((token, Box::new(r)));
            // Wake the loop to drain the completion (counting eventfd; the loop
            // re-arms the READ, so no poke is lost - the inject-path pattern).
            wake.wake.poke();
        }));
    }

    /// [`offload`](Self::offload) for a job that already yields a
    /// [`crate::Result`], mapping a panicked job to `EIO` so the continuation
    /// keeps its ordinary signature.
    ///
    /// This is the shape every derived facility here uses and the one a
    /// consumer batching its own blocking tail should reach for; the job
    /// contract is [`offload`](Self::offload)'s. Reach for `offload` itself
    /// only when the continuation must inspect the panic payload. Not a
    /// second spelling of one submission: the primitive delivers the raw
    /// [`thread::Result`], and this is the normalization everything built on
    /// it shares.
    pub fn offload_result<T, J, F>(&mut self, job: J, on_done: F)
    where
        J: FnOnce() -> crate::Result<T> + Send + 'static,
        T: Send + 'static,
        F: FnOnce(crate::Result<T>, &mut FsConn<'_>) + 'static,
    {
        self.offload(job, move |r: thread::Result<crate::Result<T>>, conn| {
            on_done(r.unwrap_or_else(|_| Err(Errno::EIO.into())), conn);
        });
    }

    /// Offload a `flistxattr` of `f` to the pool and deliver its attribute
    /// names (all namespaces, sorted) on the loop. The list runs at the
    /// reactor's privilege, so it proposes candidates only: a caller relaying to
    /// a `who` must read each value under `who` (via
    /// [`fgetxattr`](Self::fgetxattr)) and drop the denials, exactly as the
    /// directory enrichment does.
    pub fn flistxattr<F>(&mut self, f: File, on_done: F)
    where
        F: FnOnce(crate::Result<Vec<CString>>, &mut FsConn<'_>) + 'static,
    {
        self.offload_result(
            move || super::query_dir::list_xattr_names(&f),
            on_done,
        );
    }

    /// Filesystem statistics for the mount `f` lives on, delivered on the
    /// loop.
    ///
    /// io_uring has no `statfs` opcode, so this takes a pool thread and
    /// returns through the completion sink like any other offload.
    pub fn fstatfs<F>(&mut self, f: File, on_done: F)
    where
        F: FnOnce(crate::Result<Statfs>, &mut FsConn<'_>) + 'static,
    {
        self.offload_result(
            move || Ok(crate::sync_fs::fstatfs(&*f.fd)?),
            on_done,
        );
    }

    /// Filesystem statistics for the mount `anchor` lives on - a whole tree's
    /// capacity without opening anything inside it.
    ///
    /// Takes an `O_PATH` descriptor, which most fd-taking calls reject:
    /// `fd_statfs` resolves through `f_path` and never consults `f_op`
    /// (`fs/statfs.c`), unlike `fsync` or the ZFS attribute ioctls.
    pub fn fstatfs_anchor<F>(&mut self, anchor: &Anchor, on_done: F)
    where
        F: FnOnce(crate::Result<Statfs>, &mut FsConn<'_>) + 'static,
    {
        let anchor = anchor.clone();
        self.offload_result(
            move || Ok(crate::sync_fs::fstatfs(&anchor)?),
            on_done,
        );
    }

    /// Read `f`'s ZFS attributes, delivered on the loop.
    ///
    /// `f` must be opened for real I/O (an `O_PATH` descriptor has no
    /// `f_op->unlocked_ioctl`); `ENOTTY` off ZFS. For `IMMUTABLE`/
    /// `APPENDONLY` alone prefer [`fstatx`](Self::fstatx), which reports both
    /// via `statx` with no ioctl and no pool thread.
    pub fn fget_zfs_attrs<F>(&mut self, f: File, on_done: F)
    where
        F: FnOnce(crate::Result<ZfsAttr>, &mut FsConn<'_>) + 'static,
    {
        self.offload_result(
            move || Ok(crate::sync_fs::fget_zfs_attrs(&*f.fd)?),
            on_done,
        );
    }

    /// Replace `f`'s ZFS attributes with `attrs`. **The mask is absolute** --
    /// visible bits absent from `attrs` are cleared, so modify what
    /// [`fget_zfs_attrs`](Self::fget_zfs_attrs) returned.
    ///
    /// Takes no [`Personality`], as [`fremovexattr`](Self::fremovexattr) does
    /// not: an ioctl is checked against the *calling* thread's credentials,
    /// and that thread is the reactor's pool, not a request identity. So the
    /// kernel cannot decide whether this caller may lock this file, and
    /// something above must. `ZfsAttr::NOUNLINK` in particular needs only
    /// ownership to clear, where `IMMUTABLE` needs `CAP_LINUX_IMMUTABLE`.
    ///
    /// Setting `IMMUTABLE` also seals the file's extended attributes
    /// (`may_write_xattr`, `fs/xattr.c`) - write metadata that belongs with a
    /// locked object before locking it.
    pub fn fset_zfs_attrs<F>(&mut self, f: File, attrs: ZfsAttr, on_done: F)
    where
        F: FnOnce(crate::Result<()>, &mut FsConn<'_>) + 'static,
    {
        self.offload_result(
            move || Ok(crate::sync_fs::fset_zfs_attrs(&*f.fd, attrs)?),
            on_done,
        );
    }

    /// Copy `len` bytes from `src[off_src..]` to `dst[off_dst..]`, trying a
    /// metadata-only block clone first (`FICLONERANGE` - on a pool with ZFS
    /// block cloning this moves no data) and falling back to a real copy when
    /// the clone is refused. Delivers the bytes copied.
    ///
    /// This is how an embedded handler assembles a large object from parts
    /// without leaving the loop;
    /// [`QueryPool::copy_file_range`](super::query_dir::QueryPool::copy_file_range)
    /// is the off-loop twin.
    ///
    /// Takes no [`Personality`] because both endpoints are already-open
    /// [`File`]s and the kernel authorizes the copy from their open modes,
    /// which were established under the identity that opened them.
    pub fn copy_file_range<F>(
        &mut self,
        src: File,
        dst: File,
        off_src: u64,
        off_dst: u64,
        len: u64,
        on_done: F,
    ) where
        F: FnOnce(crate::Result<u64>, &mut FsConn<'_>) + 'static,
    {
        self.offload_result(
            move || {
                super::query_dir::clone_or_copy_range(
                    &src, &dst, off_src, off_dst, len,
                )
            },
            on_done,
        );
    }

    /// Remove a **server-owned** extended attribute from `f`
    /// (`fremovexattr`), or `EPERM` if `name` is not one the reactor's
    /// [`PrivilegedXattrs`](crate::uring_fs::PrivilegedXattrs) policy claims.
    ///
    /// Takes no [`Personality`] - see `FsCore::remove_priv_xattr` for why
    /// the allowlist has to stand in for one here.
    pub fn fremovexattr<F>(&mut self, f: File, name: CString, on_done: F)
    where
        F: FnOnce(crate::Result<()>, &mut FsConn<'_>) + 'static,
    {
        if !self.fs.priv_xattrs.permits(&name) {
            let job = move || {
                drop(f);
                Err(Errno::EPERM.into())
            };
            self.offload_result(job, on_done);
            return;
        }
        self.offload_result(move || remove_xattr_blocking(&f, &name), on_done);
    }

    /// Open `anchor` itself readable **under `who`** on the ring (the DAC /
    /// list-permission check), then `fdopendir` it off-loop; deliver the ready
    /// [`DirWalk`] to `on_ready` on the reactor thread. Only the request-handler
    /// facade may open (like [`FsConn::open`]).
    pub fn open_dir<F>(
        &mut self,
        who: Personality,
        anchor: &Anchor,
        on_ready: F,
    ) where
        F: FnOnce(crate::Result<DirWalk>, &mut FsConn<'_>) + 'static,
    {
        let how = OpenHow::new().flags(OFlag::O_RDONLY | OFlag::O_DIRECTORY);
        self.open(who, anchor, c".", how, move |done, conn| {
            match done.file() {
                Some(dir) => conn.offload(
                    move || -> crate::Result<SendDir> {
                        // Worker: dup the authorized fd and fdopendir the dup
                        // (which closedir/readdir then own; `dir` closes its own
                        // fd as it drops here). No permission re-check, opened
                        // under `who`. The errno is read here, on the worker's
                        // own thread, and the dup closed if fdopendir declines
                        // it (glibc leaves it open on failure).
                        // SAFETY: `dir` is a live fd for the dup; fdopendir takes
                        // ownership of the fresh dup.
                        let dup = retry_on_eintr(|| unsafe {
                            libc::dup(dir.as_raw_fd())
                        })?;
                        let dp = unsafe { libc::fdopendir(dup) };
                        if dp.is_null() {
                            let e = Errno::last();
                            // SAFETY: fdopendir failed, so `dup` is still ours.
                            unsafe { libc::close(dup) };
                            return Err(e.into());
                        }
                        Ok(SendDir(dp))
                    },
                    move |res: thread::Result<crate::Result<SendDir>>, conn| {
                        match res {
                            Ok(Ok(sdir)) => on_ready(
                                Ok(DirWalk {
                                    inner: Rc::new(RefCell::new(
                                        DirWalkInner {
                                            dp: sdir.into_raw(),
                                            in_flight: false,
                                            dropped: false,
                                        },
                                    )),
                                }),
                                conn,
                            ),
                            Ok(Err(e)) => on_ready(Err(e), conn),
                            Err(_) => on_ready(Err(Errno::EIO.into()), conn),
                        }
                    },
                ),
                None => {
                    let e = done
                        .result()
                        .err()
                        .unwrap_or_else(|| Errno::EIO.into());
                    on_ready(Err(e), conn);
                }
            }
        });
    }

    /// Read the next batch of entry names for `walk` off-loop - one job per walk
    /// (pull-style, natural backpressure) - delivering a [`NameBatch`] to
    /// `on_batch` on the reactor thread. The per-name enrichment the caller does
    /// (open + fgetxattr) stays on-loop.
    ///
    /// Calling again while a batch is still in flight yields `EBUSY`, delivered
    /// **synchronously** on the calling stack; every other outcome arrives
    /// later from the pool drain, so a caller must not assume `on_batch` always
    /// runs on a fresh turn. A batch that fails mid-`readdir` delivers the error
    /// and drops the names already read: `readdir` cannot rewind, so the walk is
    /// restart-recoverable, not resumable from the failed batch.
    pub fn next_batch<F>(&mut self, walk: &DirWalk, on_batch: F)
    where
        F: FnOnce(crate::Result<NameBatch>, &mut FsConn<'_>) + 'static,
    {
        // Take the DIR* out for the worker; mark it in flight so a concurrent
        // Drop defers the close to this batch's delivery.
        let dp = {
            let mut b = walk.inner.borrow_mut();
            if b.in_flight || b.dp.is_null() {
                drop(b);
                return on_batch(Err(Errno::EBUSY.into()), self);
            }
            b.in_flight = true;
            std::mem::replace(&mut b.dp, std::ptr::null_mut())
        };
        let sdir = SendDir(dp);
        let inner = Rc::clone(&walk.inner);
        self.offload(
            move || {
                // Force whole-capture of the `Send` wrapper: 2021 disjoint
                // captures would otherwise capture just its `*mut DIR` field and
                // make the job `!Send`. Re-binding the whole value pins it, and
                // the same `sdir` is handed back so its ownership is unbroken:
                // never a second wrapper over one `DIR*`.
                let sdir = sdir;
                let dp = sdir.0;
                let mut names = Vec::with_capacity(DIR_BATCH);
                let mut eod = false;
                let mut err = None;
                while names.len() < DIR_BATCH {
                    Errno::clear();
                    // SAFETY: `dp` is a live DIR*; the returned pointer is valid
                    // until the next readdir/closedir, copied out immediately.
                    let ent = unsafe { libc::readdir(dp) };
                    if ent.is_null() {
                        // NULL is end-of-directory only with errno untouched; a
                        // set errno is a failed getdents refill (EIO on a bad
                        // block, ESTALE on NFS, the directory removed underneath)
                        // and must surface, not read back as an empty directory.
                        match Errno::last_raw() {
                            0 => eod = true,
                            _ => err = Some(Errno::last()),
                        }
                        break;
                    }
                    // SAFETY: `ent` is a valid dirent, NUL-terminated d_name;
                    // `addr_of!` avoids forming a `&[c_char; 256]` over a record
                    // that may be shorter than the full array.
                    let name = unsafe {
                        CStr::from_ptr(
                            std::ptr::addr_of!((*ent).d_name)
                                .cast::<libc::c_char>(),
                        )
                        .to_bytes()
                        .to_vec()
                    };
                    if name == b"." || name == b".." {
                        continue;
                    }
                    names.push(name);
                }
                let batch = match err {
                    Some(e) => Err(e.into()),
                    None => Ok(NameBatch { names, eod }),
                };
                (batch, sdir)
            },
            move |res: thread::Result<(crate::Result<NameBatch>, SendDir)>,
                  conn| {
                // A panicking job unwound its frame, which dropped `SendDir`
                // and closed the DIR* with it: there is no handle to hand back,
                // so `dp` stays null and the walk reads as finished rather than
                // permanently busy.
                let (batch, sdir) = match res {
                    Ok((batch, sdir)) => (batch, Some(sdir)),
                    Err(_) => (Err(Errno::EIO.into()), None),
                };
                let mut b = inner.borrow_mut();
                if b.dropped {
                    // Walk dropped mid-batch: `sdir` drops here, closing the
                    // DIR*, and the batch is discarded (the caller is gone).
                    drop(b);
                    drop(sdir);
                    return;
                }
                b.dp = sdir.map_or(std::ptr::null_mut(), SendDir::into_raw);
                b.in_flight = false;
                drop(b);
                on_batch(batch, conn);
            },
        );
    }
}

#[cfg(all(test, not(loom)))]
mod hybrid_tests {
    use super::*;
    use crate::uring::sys::register_personality;
    use crate::uring::user_data::TAG_FS_DOMAIN;

    const OWNER0: Owner = Some((0, 0));
    const XVAL: &[u8] = b"val";

    fn xsum(n: usize) -> u64 {
        n as u64 * XVAL.iter().map(|&b| b as u64).sum::<u64>()
    }

    fn setup() -> (Engine, FsCore, Personality) {
        let eng = Engine::new(256, 128).expect("engine");
        let fs = FsCore::new(256, OffloadBounds::default());
        let me = Personality(
            register_personality(eng.ring.raw_fd()).expect("personality"),
        );
        (eng, fs, me)
    }

    /// Build a fresh owner-scoped `FsConn`, run `kickoff` on it, then drive the
    /// loop - firing embedded completions and pool deliveries, re-arming the
    /// wake - until `done`. Mirrors the standalone host's run_loop.
    fn drive(
        eng: &mut Engine,
        fs: &mut FsCore,
        kickoff: impl FnOnce(&mut FsConn<'_>),
        done: impl Fn() -> bool,
    ) {
        eng.arm_wake(pack_raw(TAG_WAKE, 0, 0)).expect("arm_wake");
        {
            let mut c = FsConn::new(fs, eng, OWNER0, true);
            kickoff(&mut c);
        }
        let mut guard = 0u32;
        while !done() {
            guard += 1;
            assert!(guard < 5_000_000, "reactor stalled");
            eng.ring.submit_and_wait(1).expect("submit_and_wait");
            let mut cqes = Vec::new();
            while let Some(cqe) = eng.ring.reap() {
                cqes.push(cqe);
            }
            for cqe in cqes {
                let (tag, slot, g) = unpack_raw(cqe.user_data);
                if tag == TAG_WAKE {
                    eng.arm_wake(pack_raw(TAG_WAKE, 0, 0)).expect("arm");
                    for (o, deliver, any) in fs.take_pool_completions() {
                        let mut c = FsConn::new(fs, eng, o, true);
                        deliver(any, &mut c);
                    }
                    continue;
                }
                if tag == TAG_CANCEL || tag & TAG_FS_DOMAIN == 0 {
                    continue;
                }
                if let ReapedFs::Embedded(cb, d, o) =
                    fs.on_cqe(eng, tag, slot, g, cqe.res)
                {
                    let mut c = FsConn::new(fs, eng, o, true);
                    cb(d, &mut c);
                }
            }
        }
    }

    fn fixture(n: usize) -> crate::TempDir {
        let dir = crate::tempdir().expect("tempdir");
        for i in 0..n {
            let p = dir.path().join(format!("f{i}"));
            std::fs::write(&p, b"x").unwrap();
            let cp = CString::new(p.as_os_str().as_encoded_bytes()).unwrap();
            // SAFETY: valid path / name / value + len.
            let r = unsafe {
                libc::setxattr(
                    cp.as_ptr(),
                    c"user.bench".as_ptr(),
                    XVAL.as_ptr().cast(),
                    XVAL.len(),
                    0,
                )
            };
            assert_eq!(r, 0, "setxattr");
        }
        dir
    }

    /// Run `f` with panic printing silenced, serialized against every other
    /// hook-swapping test: the hook is process-global and tests run as
    /// threads in one binary, so two unserialized swaps can interleave and
    /// strand the silent hook. Keep assertions outside `f` - a panic inside
    /// it leaves the hook silenced for the rest of the run.
    fn with_silent_panics<R>(f: impl FnOnce() -> R) -> R {
        static HOOK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _serialized = HOOK.lock().unwrap_or_else(|e| e.into_inner());
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let r = f();
        std::panic::set_hook(prev);
        r
    }

    #[test]
    fn offload_delivers_result_on_loop() {
        let (mut eng, mut fs, _me) = setup();
        let got: Rc<RefCell<Option<u64>>> = Rc::new(RefCell::new(None));
        let g2 = got.clone();
        drive(
            &mut eng,
            &mut fs,
            move |c| {
                c.offload(|| 6u64 * 7, move |r, _c| *g2.borrow_mut() = r.ok());
            },
            || got.borrow().is_some(),
        );
        assert_eq!(*got.borrow(), Some(42));
    }

    /// A panicking job must still deliver. Before, `push_back`/`poke` sat after
    /// `job()`, so an unwind skipped both: the continuation never ran, the
    /// `offload_reg` entry was never retired, and anything the continuation
    /// would have released (a walk's `in_flight`) stayed held forever.
    #[test]
    fn offload_delivers_even_when_the_job_panics() {
        let (mut eng, mut fs, _me) = setup();
        let got: Rc<RefCell<Option<bool>>> = Rc::new(RefCell::new(None));
        let g2 = got.clone();
        with_silent_panics(|| {
            drive(
                &mut eng,
                &mut fs,
                move |c| {
                    c.offload(
                        || -> u64 { panic!("job blew up") },
                        move |r, _c| *g2.borrow_mut() = Some(r.is_err()),
                    );
                },
                || got.borrow().is_some(),
            );
        });
        assert_eq!(
            *got.borrow(),
            Some(true),
            "the continuation must run, carrying the panic"
        );
        assert!(
            fs.offload_reg.is_empty(),
            "a panicked job must not strand its registry entry"
        );
    }

    /// `offload_result` maps a panicked job to exactly `EIO` - the documented
    /// contract - while an `Ok` job in the same drive passes its value
    /// through untouched, and neither strands its registry entry.
    #[test]
    fn offload_result_maps_a_panicked_job_to_eio() {
        let (mut eng, mut fs, _me) = setup();
        let ok: Rc<RefCell<Option<crate::Result<u64>>>> =
            Rc::new(RefCell::new(None));
        let bad: Rc<RefCell<Option<crate::Result<u64>>>> =
            Rc::new(RefCell::new(None));
        let (o2, b2) = (ok.clone(), bad.clone());
        with_silent_panics(|| {
            drive(
                &mut eng,
                &mut fs,
                move |c| {
                    c.offload_result(
                        || Ok(41u64),
                        move |r, _c| *o2.borrow_mut() = Some(r),
                    );
                    c.offload_result(
                        || -> crate::Result<u64> { panic!("job blew up") },
                        move |r, _c| *b2.borrow_mut() = Some(r),
                    );
                },
                || ok.borrow().is_some() && bad.borrow().is_some(),
            );
        });
        assert!(
            matches!(*ok.borrow(), Some(Ok(41))),
            "the Ok job's value passes through: {:?}",
            ok.borrow()
        );
        assert!(
            matches!(*bad.borrow(), Some(Err(crate::Error::Errno(Errno::EIO)))),
            "a panicked job is exactly EIO: {:?}",
            bad.borrow()
        );
        assert!(
            fs.offload_reg.is_empty(),
            "no continuation may be stranded in the registry"
        );
    }

    #[test]
    fn wake_drain_fires_every_completion() {
        let (mut eng, mut fs, _me) = setup();
        let count: Rc<RefCell<usize>> = Rc::new(RefCell::new(0));
        let c2 = count.clone();
        drive(
            &mut eng,
            &mut fs,
            move |c| {
                for _ in 0..8 {
                    let c3 = c2.clone();
                    c.offload(
                        || (),
                        move |r, _c| {
                            r.expect("a unit job never panics");
                            *c3.borrow_mut() += 1;
                        },
                    );
                }
            },
            || *count.borrow() == 8,
        );
        assert_eq!(*count.borrow(), 8);
    }

    #[test]
    fn a_failed_readdir_is_an_error_not_end_of_directory() {
        // Point the DIR*'s fd at a non-directory (`dup2` over it, keeping the fd
        // number valid so parallel tests and the walk's own `closedir` are
        // unaffected): the next `readdir` fails `ENOTDIR` and returns NULL with
        // errno set. That must be delivered as an error, not an empty
        // end-of-directory batch that reads as a complete listing of nothing.
        let (mut eng, mut fs, me) = setup();
        let dir = fixture(3);
        let anchor = Anchor::open(dir.path()).unwrap();
        struct S {
            walk: Option<DirWalk>,
            result: Option<crate::Result<NameBatch>>,
        }
        let st: Rc<RefCell<S>> = Rc::new(RefCell::new(S {
            walk: None,
            result: None,
        }));
        let st2 = st.clone();
        drive(
            &mut eng,
            &mut fs,
            move |c| {
                c.open_dir(me, &anchor, move |res, conn| {
                    let walk = res.expect("open_dir");
                    // SAFETY: `dp` is the live DIR* just handed back; redirect
                    // its fd to /dev/null so the next readdir sees a non-dir.
                    let dirfd = unsafe { libc::dirfd(walk.inner.borrow().dp) };
                    assert!(dirfd >= 0);
                    let null = unsafe { libc::open(c"/dev/null".as_ptr(), 0) };
                    assert!(null >= 0, "open /dev/null");
                    assert_eq!(
                        unsafe { libc::dup2(null, dirfd) },
                        dirfd,
                        "dup2 onto dirfd"
                    );
                    unsafe { libc::close(null) };
                    st2.borrow_mut().walk = Some(walk);
                    let st3 = st2.clone();
                    let b = st2.borrow();
                    conn.next_batch(
                        b.walk.as_ref().unwrap(),
                        move |res, _c| {
                            st3.borrow_mut().result = Some(res);
                        },
                    );
                });
            },
            || st.borrow().result.is_some(),
        );
        let s = st.borrow();
        assert!(
            matches!(
                s.result.as_ref().unwrap(),
                Err(crate::Error::Errno(Errno::ENOTDIR))
            ),
            "readdir failure delivered as Err(ENOTDIR), got {:?}",
            s.result.as_ref().unwrap()
        );
    }

    #[test]
    fn dirwalk_drop_closes_the_dir() {
        let (mut eng, mut fs, me) = setup();
        let dir = fixture(3);
        let anchor = Anchor::open(dir.path()).unwrap();
        let captured: Rc<RefCell<Option<Rc<RefCell<DirWalkInner>>>>> =
            Rc::new(RefCell::new(None));
        let cap2 = captured.clone();
        drive(
            &mut eng,
            &mut fs,
            move |c| {
                c.open_dir(me, &anchor, move |res, _c| {
                    let walk = res.expect("open_dir");
                    // Snapshot the inner, then drop `walk` at the end of this
                    // closure (no batch in flight -> Drop closes the DIR* now).
                    *cap2.borrow_mut() = Some(walk.inner.clone());
                });
            },
            || captured.borrow().is_some(),
        );
        let inner = captured.borrow().as_ref().unwrap().clone();
        assert!(inner.borrow().dropped, "walk Drop ran");
        assert!(
            inner.borrow().dp.is_null(),
            "DIR* closed on drop, not leaked"
        );
    }

    struct ListState {
        me: Personality,
        anchor: Anchor,
        walk: Option<DirWalk>,
        pending: VecDeque<Vec<u8>>,
        eod: bool,
        seen: usize,
        sum: u64,
        finished: bool,
    }
    type ListRef = Rc<RefCell<ListState>>;

    /// Pull the next batch of names for `st`'s walk (one job at a time).
    fn request_batch(st: &ListRef, conn: &mut FsConn<'_>) {
        let st2 = st.clone();
        let b = st.borrow();
        let walk = b.walk.as_ref().expect("walk");
        conn.next_batch(walk, move |res, conn| {
            let batch = res.expect("batch");
            {
                let mut s = st2.borrow_mut();
                s.pending.extend(batch.names);
                s.eod = batch.eod;
            }
            enrich_next(&st2, conn);
        });
    }

    /// Enrich the next pending name on-loop (open + fgetxattr), <= 1 op in
    /// flight; pull the next batch when the current one drains, finish at eod.
    fn enrich_next(st: &ListRef, conn: &mut FsConn<'_>) {
        let name = st.borrow_mut().pending.pop_front();
        let Some(name) = name else {
            let eod = st.borrow().eod;
            if eod {
                st.borrow_mut().finished = true;
            } else {
                request_batch(st, conn);
            }
            return;
        };
        let (me, anchor) = {
            let b = st.borrow();
            (b.me, b.anchor.clone())
        };
        let how = OpenHow::new().flags(OFlag::O_RDONLY | OFlag::O_NOFOLLOW);
        let cname = CString::new(name).unwrap();
        let st2 = st.clone();
        conn.open(me, &anchor, &cname, how, move |done, conn| {
            let Some(f) = done.file() else {
                return enrich_next(&st2, conn);
            };
            let me = st2.borrow().me;
            let st3 = st2.clone();
            conn.fgetxattr(
                me,
                f,
                c"user.bench",
                vec![0u8; 64],
                move |done, conn| {
                    if let Ok(nb) = done.result() {
                        let nb = nb as usize;
                        let bufs = done.into_bufs();
                        let mut s = st3.borrow_mut();
                        s.seen += 1;
                        if let Some(v) = bufs.first() {
                            for &x in &v[..nb.min(v.len())] {
                                s.sum += x as u64;
                            }
                        }
                    }
                    enrich_next(&st3, conn);
                },
            );
        });
    }

    #[test]
    fn hybrid_listing_enriches_every_entry() {
        let (mut eng, mut fs, me) = setup();
        let n = 40usize;
        let dir = fixture(n);
        let anchor = Anchor::open(dir.path()).unwrap();
        const CLIENTS: usize = 3;
        let states: Vec<ListRef> = (0..CLIENTS)
            .map(|_| {
                Rc::new(RefCell::new(ListState {
                    me,
                    anchor: anchor.clone(),
                    walk: None,
                    pending: VecDeque::new(),
                    eod: false,
                    seen: 0,
                    sum: 0,
                    finished: false,
                }))
            })
            .collect();
        let kick = states.clone();
        let check = states.clone();
        drive(
            &mut eng,
            &mut fs,
            move |c| {
                for st in &kick {
                    let st2 = st.clone();
                    let (me, anchor) = {
                        let b = st.borrow();
                        (b.me, b.anchor.clone())
                    };
                    c.open_dir(me, &anchor, move |res, c| {
                        st2.borrow_mut().walk = Some(res.expect("open_dir"));
                        request_batch(&st2, c);
                    });
                }
            },
            move || check.iter().all(|s| s.borrow().finished),
        );
        for s in &states {
            let b = s.borrow();
            assert_eq!(b.seen, n, "every entry enriched");
            assert_eq!(b.sum, xsum(n), "xattr values correct");
        }
    }
}

fn map_res(res: i32) -> Result<i32, Errno> {
    if res < 0 {
        Err(Errno::from_raw(-res))
    } else {
        Ok(res)
    }
}

/// Route a completed op's outcome to its channel waiter. A gone caller (a
/// dropped receiver - a `File`/future dropped before awaiting) simply
/// orphans the op; nothing to do. (A successful `open` does NOT route through
/// here - `on_cqe` wraps its fd in an `Arc<OwnedFd>`, and a gone receiver
/// drops that `Arc`, which closes the fd. No close op is staged, and there is
/// no slot to leak.)
fn deliver(
    waiter: Option<FsWaiter>,
    res: Result<i32, Errno>,
    bufs: Vec<Vec<u8>>,
    file: Option<Arc<OwnedFd>>,
    stat: Option<Box<StatxRaw>>,
) {
    match waiter {
        Some(FsWaiter::Channel(tx)) => {
            let _ = tx.send(FsOutcome::new(res, bufs, file, stat));
        }
        // Submission failure / teardown of an embedded op: drop the callback
        // unfired - dropping the continuation it captured closes the
        // connection (see [`EmbeddedCb`]). Nothing else routes it.
        Some(FsWaiter::Embedded { cb, .. }) => {
            drop(cb);
            drop((bufs, file, stat));
        }
        // A pump read has no callback to drop and nowhere to route from here:
        // on a teardown drain the owning connection is dying with the loop,
        // and on a staging failure (`fail_op`) `submit_pump_read` reports the
        // error to its caller synchronously. The payloads just drop.
        Some(FsWaiter::Pump { .. }) => drop((bufs, file, stat)),
        None => {}
    }
}

/// Deliver every finished offload's continuation on-loop, each with a fresh
/// owner-scoped [`FsConn`] (`root` per the host: the standalone reactor passes
/// `true`, a net-server continuation `false`). Shared by the host and the net
/// server so the wake-drain is written once.
pub(crate) fn deliver_pool_completions(
    fs: &mut FsCore,
    eng: &mut Engine,
    root: bool,
) {
    for (owner, deliver, any) in fs.take_pool_completions() {
        let mut conn = FsConn::new(fs, eng, owner, root);
        deliver(any, &mut conn);
    }
}

/// Fire an embedded on-loop completion reaped by [`FsCore::on_cqe`] with a
/// fresh owner-scoped [`FsConn`]; a no-op when `on_cqe` returned
/// [`ReapedFs::None`] (a channel op already delivered, or an inert stale
/// CQE). Shared by the host and the net server so the CQE hand-back is
/// written once. A [`ReapedFs::Pump`] never reaches here: only the net
/// server submits pump reads, and its dispatch routes them before this call.
pub(crate) fn deliver_embedded(
    fs: &mut FsCore,
    eng: &mut Engine,
    reaped: ReapedFs,
    root: bool,
) {
    match reaped {
        ReapedFs::Embedded(cb, done, owner) => {
            let mut conn = FsConn::new(fs, eng, owner, root);
            cb(done, &mut conn);
        }
        ReapedFs::Pump(..) => {
            unreachable!("pump reads are routed by the net server")
        }
        ReapedFs::None => {}
    }
}

/// Routing / close-last property fuzzer for the **plain-fd** core. There is no
/// file-slot pool any more; fds are `Arc<OwnedFd>` closed by last-reference. The
/// fuzzer drives fuzzed submit/complete schedules against a real (never-flushed)
/// `Engine`, feeds a mix of correct and anomalous CQEs, and asserts: op slots
/// free exactly once (`op_free` reconciles), every synthesized fd closes exactly
/// once (never early - a parked clone outlives a dropped caller - never leaked),
/// and stale/wrong-tag/recycled completions are inert. `ROUTING_FUZZ_SEEDS=N`
/// overrides the seed count.
#[cfg(all(test, not(loom)))]
mod routing_fuzz {
    use super::*;
    use crate::sync::mpsc;
    use std::os::fd::RawFd;
    use std::sync::Weak;

    const OP_SLOTS: u32 = 32;
    // The ring is sized far above any run's staged SQEs, so `push_sqe` never
    // flushes to the kernel - routing runs purely in userspace.
    const RING_ENTRIES: u32 = 1024;
    const POOL: u32 = 8;

    /// Deterministic xorshift RNG: a failing seed reproduces exactly.
    struct Rng(u64);
    impl Rng {
        fn new(seed: u64) -> Rng {
            Rng(seed ^ 0x9E37_79B9_7F4A_7C15 | 1)
        }
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }
        fn below(&mut self, n: u32) -> u32 {
            (self.next() % u64::from(n.max(1))) as u32
        }
    }

    /// Build a real `Engine` or signal an environment skip (mirrors the
    /// integration suites' io_uring guard).
    fn engine_or_skip() -> Option<Engine> {
        match Engine::new(RING_ENTRIES, POOL) {
            Ok(e) => Some(e),
            Err(crate::Error::Errno(
                Errno::EPERM | Errno::ENOSYS | Errno::EACCES,
            )) => None,
            Err(e) => panic!("Engine::new: {e}"),
        }
    }

    /// A fresh real fd (so close-last is observable); `/dev/null` always opens.
    fn synth_fd() -> RawFd {
        // SAFETY: a static NUL-terminated path; open cannot corrupt memory.
        let fd = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDWR) };
        assert!(fd >= 0, "open /dev/null");
        fd
    }

    fn chan(tx: &mpsc::Sender<FsOutcome>) -> FsWaiter {
        FsWaiter::Channel(ReplyTo::Sync(tx.clone()))
    }

    /// A compact snapshot to assert an anomalous completion is fully inert:
    /// sorted free-list + each op's `(generation, state-code)`.
    fn snapshot(c: &FsCore) -> (Vec<u32>, Vec<(u64, u8)>) {
        let mut free = c.op_free.clone();
        free.sort_unstable();
        let ops = c
            .ops
            .iter()
            .map(|e| {
                let code = match e.state.state {
                    FsOpState::Free => 0u8,
                    FsOpState::InFlight { tag } => tag,
                };
                (e.generation, code)
            })
            .collect();
        (free, ops)
    }

    /// In-flight ops as `(tag, slot, generation-low)` - the CQEs a real kernel
    /// could deliver.
    fn inflight(c: &FsCore) -> Vec<(u8, u32, u32)> {
        c.ops
            .iter()
            .enumerate()
            .filter_map(|(i, e)| match e.state.state {
                FsOpState::InFlight { tag } => {
                    Some((tag, i as u32, e.generation as u32))
                }
                _ => None,
            })
            .collect()
    }

    /// Complete `slot`/`gen`/`tag` correctly; a byte count for data ops, a fresh
    /// fd for an open (so the built `File` is a real closeable fd).
    fn complete(core: &mut FsCore, eng: &mut Engine, t: u8, s: u32, g: u32) {
        let res = if t == TAG_OPEN { synth_fd() } else { 16 };
        let _ = core.on_cqe(eng, t, s, g, res);
    }

    #[test]
    fn close_last_parked_vs_caller() {
        let Some(mut eng) = engine_or_skip() else {
            return;
        };
        let mut core = FsCore::new(8, OffloadBounds::default());

        // (A) caller drops BEFORE the CQE: the op's parked clone keeps the fd.
        let arc = Arc::new(unsafe { crate::fd::owned_from_raw(synth_fd()) });
        let weak = Arc::downgrade(&arc);
        let caller = File::new(arc.clone());
        let (tx, rx) = mpsc::channel::<FsOutcome>();
        core.submit_rw(
            &mut eng,
            TAG_READV,
            1,
            arc,
            vec![vec![0u8; 16]],
            0,
            0,
            chan(&tx),
        );
        drop(caller);
        assert!(
            weak.upgrade().is_some(),
            "parked clone must keep the fd alive after the caller drops"
        );
        let (t, s, g) = inflight(&core)[0];
        complete(&mut core, &mut eng, t, s, g);
        let _ = rx.recv();
        assert!(
            weak.upgrade().is_none(),
            "fd closes once both the parked clone and the caller are gone"
        );

        // (B) CQE BEFORE the caller drops: the caller's ref keeps the fd.
        let arc = Arc::new(unsafe { crate::fd::owned_from_raw(synth_fd()) });
        let weak = Arc::downgrade(&arc);
        let caller = File::new(arc.clone());
        let (tx, rx) = mpsc::channel::<FsOutcome>();
        core.submit_rw(
            &mut eng,
            TAG_WRITEV,
            1,
            arc,
            vec![vec![0u8; 16]],
            0,
            0,
            chan(&tx),
        );
        let (t, s, g) = inflight(&core)[0];
        complete(&mut core, &mut eng, t, s, g);
        let _ = rx.recv();
        assert!(
            weak.upgrade().is_some(),
            "the caller's ref keeps the fd alive after the CQE reaps"
        );
        drop(caller);
        assert!(
            weak.upgrade().is_none(),
            "fd closes when the caller finally drops its last ref"
        );
    }

    #[test]
    fn teardown_drain_releases_parked_fds() {
        let Some(mut eng) = engine_or_skip() else {
            return;
        };
        let mut core = FsCore::new(8, OffloadBounds::default());
        let (tx, _rx) = mpsc::channel::<FsOutcome>();
        let mut weaks = Vec::new();
        // Four in-flight rw ops, each parking a fd whose caller already dropped.
        for _ in 0..4 {
            let arc =
                Arc::new(unsafe { crate::fd::owned_from_raw(synth_fd()) });
            weaks.push(Arc::downgrade(&arc));
            core.submit_rw(
                &mut eng,
                TAG_READV,
                1,
                arc,
                vec![vec![0u8; 16]],
                0,
                0,
                chan(&tx),
            );
        }
        // Teardown reaps each in-flight op via the drain path -> parked Arcs drop.
        for (tag, slot, generation) in inflight(&core) {
            let cqe = IoUringCqe {
                user_data: pack_raw(tag, slot, generation),
                res: -libc::ECANCELED,
                flags: 0,
            };
            core.on_drain_cqe(&cqe);
        }
        assert!(
            weaks.iter().all(|w| w.upgrade().is_none()),
            "teardown released every parked fd"
        );
        let mut free = core.op_free.clone();
        free.sort_unstable();
        assert_eq!(
            free,
            (0..8).collect::<Vec<_>>(),
            "teardown freed every op slot exactly once"
        );
    }

    #[test]
    fn routing_survives_fuzzed_completion() {
        let Some(mut eng) = engine_or_skip() else {
            return;
        };
        let anchor = Anchor::open("/").expect("open / as anchor");
        let seeds: u64 = std::env::var("ROUTING_FUZZ_SEEDS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(64);
        for seed in 0..seeds {
            // Reuse one engine, rewinding its staging between seeds; the rewind
            // asserts nothing was ever submitted, so the "runs purely in
            // userspace, never enters the kernel" premise is checked, not assumed.
            eng.reset_staging();
            run_one(&mut eng, &anchor, seed);
        }
    }

    fn run_one(eng: &mut Engine, anchor: &Anchor, seed: u64) {
        let mut rng = Rng::new(seed);
        let mut core = FsCore::new(OP_SLOTS, OffloadBounds::default());
        let (tx, rx) = mpsc::channel::<FsOutcome>();
        // Weak refs to every synthesized fd - `upgrade() == None` means closed.
        let mut tracked: Vec<Weak<OwnedFd>> = Vec::new();
        // Caller-held files, dropped at fuzzed points (and all at the end).
        let mut held: Vec<File> = Vec::new();

        let steps = 24 + rng.below(72);
        for _ in 0..steps {
            // Drain delivered outcomes (opens' new fds): track, sometimes hold.
            while let Ok(out) = rx.try_recv() {
                if let Some(fd) = out.file {
                    tracked.push(Arc::downgrade(&fd));
                    if rng.below(2) == 0 {
                        held.push(File::new(fd));
                    }
                }
            }
            match rng.below(7) {
                0 if !core.op_free.is_empty() => core.submit_open(
                    eng,
                    1,
                    anchor.clone(),
                    CString::new("x").unwrap(),
                    OpenHow::new().to_raw(),
                    chan(&tx),
                ),
                1 | 2 if !core.op_free.is_empty() => {
                    let arc = Arc::new(unsafe {
                        crate::fd::owned_from_raw(synth_fd())
                    });
                    tracked.push(Arc::downgrade(&arc));
                    held.push(File::new(arc.clone()));
                    let tag = if rng.below(2) == 0 {
                        TAG_READV
                    } else {
                        TAG_WRITEV
                    };
                    core.submit_rw(
                        eng,
                        tag,
                        1,
                        arc,
                        vec![vec![0u8; 16]],
                        0,
                        0,
                        chan(&tx),
                    );
                }
                3 if !core.op_free.is_empty() => {
                    let arc = Arc::new(unsafe {
                        crate::fd::owned_from_raw(synth_fd())
                    });
                    tracked.push(Arc::downgrade(&arc));
                    held.push(File::new(arc.clone()));
                    core.submit_fd_meta(
                        eng,
                        TAG_FGETXATTR,
                        1,
                        arc,
                        Some(CString::new("user.x").unwrap()),
                        vec![0u8; 64],
                        0,
                        0,
                        0,
                        chan(&tx),
                    );
                }
                4 if !core.op_free.is_empty() => core.submit_path_op(
                    eng,
                    TAG_STATX,
                    1,
                    anchor.clone(),
                    CString::new("x").unwrap(),
                    None,
                    None,
                    0,
                    StatxMask::BASIC_STATS.bits(),
                    chan(&tx),
                ),
                5 => {
                    // A correct completion.
                    let fly = inflight(&core);
                    if !fly.is_empty() {
                        let (t, s, g) =
                            fly[rng.below(fly.len() as u32) as usize];
                        complete(&mut core, eng, t, s, g);
                    }
                }
                6 => {
                    // An anomalous completion - MUST mutate nothing.
                    let fly = inflight(&core);
                    let snap = snapshot(&core);
                    match rng.below(3) {
                        0 if !fly.is_empty() => {
                            let (t, s, g) =
                                fly[rng.below(fly.len() as u32) as usize];
                            let _ =
                                core.on_cqe(eng, t, s, g.wrapping_add(1), 16);
                        }
                        1 if !fly.is_empty() => {
                            let (t, s, g) =
                                fly[rng.below(fly.len() as u32) as usize];
                            let _ = core.on_cqe(eng, t ^ 0x0F, s, g, 16);
                        }
                        _ => {
                            if let Some(&fslot) = core.op_free.first() {
                                let _ =
                                    core.on_cqe(eng, TAG_READV, fslot, 0, 16);
                            }
                        }
                    }
                    assert_eq!(
                        snapshot(&core),
                        snap,
                        "anomalous CQE mutated state (seed {seed})"
                    );
                }
                _ => {}
            }
            // Occasionally drop a caller file mid-flight (parked clone must hold
            // the fd until its own CQE - the close-last guarantee).
            if !held.is_empty() && rng.below(3) == 0 {
                let i = rng.below(held.len() as u32) as usize;
                held.swap_remove(i);
            }
        }

        // Drain every remaining in-flight op with a correct completion.
        while let Some(&(t, s, g)) = inflight(&core).first() {
            complete(&mut core, eng, t, s, g);
        }
        // Track every delivered fd, then drop all caller-held files.
        while let Ok(out) = rx.try_recv() {
            if let Some(fd) = out.file {
                tracked.push(Arc::downgrade(&fd));
            }
        }
        held.clear();

        // (1) No fd leaked: every synthesized `Arc` has dropped (fd closed).
        let leaked = tracked.iter().filter(|w| w.upgrade().is_some()).count();
        assert_eq!(
            leaked, 0,
            "{leaked} fd(s) leaked after drain (seed {seed})"
        );
        // (2) Op slots reconcile: `op_free` is a permutation of `0..OP_SLOTS`.
        let mut free = core.op_free.clone();
        free.sort_unstable();
        assert_eq!(
            free,
            (0..OP_SLOTS).collect::<Vec<_>>(),
            "op slots leaked or double-freed (seed {seed})"
        );
    }

    // ---- reply-path pump reads (`FsWaiter::Pump`) ----

    #[test]
    fn a_pump_read_routes_back_with_its_owner_and_bytes() {
        let Some(mut eng) = engine_or_skip() else {
            return;
        };
        let mut core = FsCore::new(4, OffloadBounds::default());
        let dir = crate::tempdir().expect("tempdir");
        let p = dir.path().join("f");
        std::fs::write(&p, b"0123456789").unwrap();
        let fd: std::os::fd::OwnedFd = std::fs::File::open(&p).unwrap().into();
        let file = File::new(Arc::new(fd));

        core.submit_pump_read(
            &mut eng,
            &file,
            Vec::with_capacity(8),
            8,
            2,
            (3, 77),
        )
        .expect("submit");
        // The op parks its own fd clone (close-last): caller + op.
        assert_eq!(Arc::strong_count(&file.fd), 2);

        eng.ring.submit_and_wait(1).expect("submit_and_wait");
        let cqe = eng.ring.reap().expect("cqe");
        let (tag, slot, g) = unpack_raw(cqe.user_data);
        assert_eq!(tag, TAG_READV);
        let ReapedFs::Pump(done, owner) =
            core.on_cqe(&mut eng, tag, slot, g, cqe.res)
        else {
            panic!("a pump read must route as ReapedFs::Pump");
        };
        assert_eq!(owner, (3, 77), "the owner survives the round trip");
        assert!(matches!(done.result(), Ok(8)), "{:?}", done.result());
        // The parked clone dropped with the op entry (close-last).
        assert_eq!(Arc::strong_count(&file.fd), 1);
        let mut bufs = done.into_bufs();
        let mut b = bufs.pop().expect("the read's buffer comes back");
        assert!(bufs.is_empty());
        // SAFETY: the CQE count proves the kernel wrote 8 bytes into the
        // spare capacity the iovec targeted.
        unsafe { b.set_len(8) };
        assert_eq!(&b[..], b"23456789", "read from the requested offset");
    }

    #[test]
    fn a_full_op_table_refuses_a_pump_read_synchronously() {
        // The shed-one-connection discipline needs the error in hand at
        // submit time: there is no callback whose drop could report it, and
        // a silently dropped pump read would strand its connection mid-body
        // with nothing left to re-drive it.
        let Some(mut eng) = engine_or_skip() else {
            return;
        };
        let mut core = FsCore::new(1, OffloadBounds::default());
        let dir = crate::tempdir().expect("tempdir");
        let p = dir.path().join("f");
        std::fs::write(&p, b"abcd").unwrap();
        let fd: std::os::fd::OwnedFd = std::fs::File::open(&p).unwrap().into();
        let file = File::new(Arc::new(fd));
        let submit = |core: &mut FsCore, eng: &mut Engine| {
            core.submit_pump_read(
                eng,
                &file,
                Vec::with_capacity(4),
                4,
                0,
                (0, 1),
            )
        };

        submit(&mut core, &mut eng).expect("first read takes the only op slot");
        assert_eq!(
            submit(&mut core, &mut eng),
            Err(Errno::EBUSY),
            "a full table must refuse, not drop"
        );
        // Draining the first read frees the slot for the next.
        eng.ring.submit_and_wait(1).expect("submit_and_wait");
        let cqe = eng.ring.reap().expect("cqe");
        let (tag, slot, g) = unpack_raw(cqe.user_data);
        assert!(matches!(
            core.on_cqe(&mut eng, tag, slot, g, cqe.res),
            ReapedFs::Pump(..)
        ));
        submit(&mut core, &mut eng).expect("freed slot serves the next");
    }

    #[test]
    fn cancel_owned_by_reaches_a_pump_read() {
        // Connection teardown's sweep cancels fs ops by owner; a pump read
        // parked on an empty pipe (never completing on its own) must be
        // reaped by exactly that path, and its parked fd clone released.
        let Some(mut eng) = engine_or_skip() else {
            return;
        };
        let mut core = FsCore::new(4, OffloadBounds::default());
        let mut fds = [0i32; 2];
        // SAFETY: `pipe(2)` fills {read, write}.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe");
        // SAFETY: fds[0] is the fresh read end, owned here; fds[1] (the
        // write end, kept open so the read never EOFs) closes at the end.
        let file =
            File::new(Arc::new(unsafe { crate::fd::owned_from_raw(fds[0]) }));

        // `u64::MAX` offset = "the file position": a pipe rejects real
        // offsets with ESPIPE.
        core.submit_pump_read(
            &mut eng,
            &file,
            Vec::with_capacity(8),
            8,
            u64::MAX,
            (5, 9),
        )
        .expect("submit");
        assert_eq!(Arc::strong_count(&file.fd), 2, "op parks its clone");
        core.cancel_owned_by(&mut eng, (5, 9));

        // Reap until the read's own CQE routes (the cancel's is inert).
        //
        // Deadline rather than `submit_and_wait`: the read is parked on an
        // empty pipe and `cancel_owned_by`'s `FsWaiter::Pump` arm is the only
        // thing that can complete it, so a blocking wait turns the failure
        // this test exists to catch into a hang - in CI, indistinguishable
        // from a slow runner. Bounded, it names the arm instead.
        let deadline =
            std::time::Instant::now() + std::time::Duration::from_secs(10);
        let reaped = loop {
            assert!(
                std::time::Instant::now() < deadline,
                "the parked read was never reaped: `cancel_owned_by` no \
                 longer reaches a `FsWaiter::Pump` op, so a closed \
                 connection's body read stays in flight with its fd parked"
            );
            eng.ring.submit().expect("submit");
            let Some(cqe) = eng.ring.reap() else {
                std::thread::sleep(std::time::Duration::from_millis(1));
                continue;
            };
            let (tag, slot, g) = unpack_raw(cqe.user_data);
            match core.on_cqe(&mut eng, tag, slot, g, cqe.res) {
                ReapedFs::None => continue,
                other => break other,
            }
        };
        let ReapedFs::Pump(done, owner) = reaped else {
            panic!("the cancelled read must still route as Pump");
        };
        assert_eq!(owner, (5, 9));
        assert!(
            matches!(done.result(), Err(crate::Error::Errno(Errno::ECANCELED))),
            "an owner cancel reaps the parked read: {:?}",
            done.result()
        );
        assert_eq!(Arc::strong_count(&file.fd), 1, "clone released");
        // SAFETY: closing the test-owned write end.
        unsafe { libc::close(fds[1]) };
    }
}

#[cfg(all(test, not(loom)))]
mod pool_identity_tests {
    use super::*;

    /// A ring has exactly one offload pool: the handle minted for off-loop
    /// submitters is the core's own pool object, not a copy built from its
    /// bounds. Pins the construction-time invariant - any future path that
    /// replaces `FsCore::pool` after a handle was minted (a setter, a
    /// builder) splits the floor..ceiling thread budget across two live
    /// pools, and fails here.
    #[test]
    fn a_pool_handle_is_the_core_pool_itself() {
        let core = FsCore::new(4, OffloadBounds::default());
        let handle = core.pool_handle();
        assert!(
            Arc::ptr_eq(&handle, &core.pool),
            "pool_handle minted a different pool object"
        );
    }
}

// ---------------------------------------------------------------------------
// loom model of the offload completion handoff
// ---------------------------------------------------------------------------
//
// Run with:  RUSTFLAGS="--cfg loom" cargo test --lib --features uring-fs loom_
//
// A worker finishing an offload pushes its result under the `completions`
// mutex and then pokes the wake eventfd (`FsConn::offload`, above); the loop
// wakes, drains the queue with `take_pool_completions`, and re-arms the READ.
// The claim in that code - "counting eventfd; the loop re-arms the READ, so no
// poke is lost" - is a lost-wakeup argument, and until now nothing tested it.
//
// The order matters in one direction only: push *then* poke. Poke first and a
// loop can wake, find the queue empty, drain nothing, and park again while the
// result it was woken for is pushed behind it - the continuation in
// `offload_reg` then never fires, and the caller waits forever.
//
// The eventfd is the `cfg(loom)` counter in `crate::uring::wake`, so what this
// proves is conditional on a real eventfd accumulating pokes the same way.
#[cfg(loom)]
mod loom_tests {
    use super::*;
    use crate::uring::wake::WakeHandle;

    fn bounded_model(f: impl Fn() + Sync + Send + 'static) {
        let mut b = loom::model::Builder::new();
        b.preemption_bound = Some(3);
        b.check(f);
    }

    /// A completion pushed concurrently with a drain is never stranded: the
    /// loop either drains it on this pass, or is left with a pending poke that
    /// makes its next armed READ complete immediately.
    #[test]
    fn loom_offload_wakeup_loses_nothing() {
        bounded_model(|| {
            let mut fs = FsCore::new(4, OffloadBounds::default());
            let sink = fs.completion_sink();
            let wake = Arc::new(
                WakeHandle::new().expect("the model's wake never fails"),
            );

            // Two workers finishing at once, as `FsConn::offload` leaves them:
            // push under the lock, then poke.
            let mut workers = Vec::new();
            for token in 0..2u64 {
                let (s, w) = (Arc::clone(&sink), Arc::clone(&wake));
                workers.push(loom::thread::spawn(move || {
                    s.lock().unwrap_or_else(|e| e.into_inner()).push_back((
                        token,
                        Box::new(token) as Box<dyn Any + Send>,
                    ));
                    w.poke();
                }));
            }

            // The loop: wake, drain, re-arm - repeatedly, as the reactor does.
            // `take_pool_completions` discards tokens with no registered
            // continuation, so count what actually came off the queue instead.
            let mut seen = 0usize;
            while seen < 2 {
                wake.drain();
                seen += {
                    let mut q = sink.lock().unwrap_or_else(|e| e.into_inner());
                    q.drain(..).count()
                };
            }

            for w in workers {
                w.join().expect("worker");
            }

            // Nothing left behind, and the registry is untouched because no
            // continuation was registered for these tokens.
            assert!(
                sink.lock().unwrap_or_else(|e| e.into_inner()).is_empty(),
                "a completion was left on the queue"
            );
            assert!(
                fs.take_pool_completions().is_empty(),
                "an unregistered token produced a delivery"
            );
        });
    }

    /// A completion whose continuation *is* registered comes back out of
    /// `take_pool_completions` exactly once, and the registry entry is
    /// consumed with it - a second drain must not fire it again.
    #[test]
    fn loom_offload_delivers_each_completion_once() {
        bounded_model(|| {
            let mut fs = FsCore::new(4, OffloadBounds::default());
            // `Owner` is `Option<(slot, generation)>`; `None` scopes the
            // continuation to the reactor rather than to a connection.
            let token = fs.register_offload(
                None,
                Box::new(|_any, _conn| {
                    unreachable!("not invoked in the model")
                }),
            );
            let sink = fs.completion_sink();
            let wake = Arc::new(
                WakeHandle::new().expect("the model's wake never fails"),
            );

            let (s, w) = (Arc::clone(&sink), Arc::clone(&wake));
            let worker = loom::thread::spawn(move || {
                s.lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push_back((token, Box::new(()) as Box<dyn Any + Send>));
                w.poke();
            });

            let mut delivered = 0usize;
            while delivered == 0 {
                wake.drain();
                delivered += fs.take_pool_completions().len();
            }
            worker.join().expect("worker");

            assert_eq!(
                delivered, 1,
                "the completion was delivered {delivered} times"
            );
            assert!(
                fs.take_pool_completions().is_empty(),
                "the continuation fired twice for one completion"
            );
        });
    }
}
