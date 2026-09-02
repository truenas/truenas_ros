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
    AtFlags, Mode, OFlag, OpenHow, RenameFlags, Statfs, Statx, StatxMask,
    StatxRaw, ZfsAttr,
};
use crate::uring::engine::Engine;
use crate::uring::slots::SlotEntry;
use crate::uring::sys::KernelTimespec;
use crate::uring::sys::{
    IORING_FSYNC_DATASYNC, IORING_OP_ASYNC_CANCEL, IORING_OP_FADVISE,
    IORING_OP_FALLOCATE, IORING_OP_FGETXATTR, IORING_OP_FSETXATTR,
    IORING_OP_FSYNC, IORING_OP_FTRUNCATE, IORING_OP_LINKAT, IORING_OP_MKDIRAT,
    IORING_OP_OPENAT2, IORING_OP_READV, IORING_OP_RENAMEAT, IORING_OP_SPLICE,
    IORING_OP_STATX, IORING_OP_SYMLINKAT, IORING_OP_TIMEOUT,
    IORING_OP_UNLINKAT, IORING_OP_WRITEV, IOSQE_BUFFER_SELECT, IoUringCqe,
    SPLICE_F_MOVE,
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
pub(crate) const TAG_TIMEOUT: u8 = 0x92;
/// The standalone host's wake tag (an embedded host reuses its own).
pub(crate) const TAG_WAKE: u8 = 0x9D;
/// Tags `ASYNC_CANCEL` ops (and the teardown drain); completions ignored.
pub(crate) const TAG_CANCEL: u8 = 0x9E;

/// A completed embedded op's callback, fired **inline on the loop thread** by
/// the embedding host (a `net` server) with the outcome and a fresh [`FsConn`]
/// for chaining. Dropping it without firing drops its captured continuation --
/// which closes the connection - so a submission failure needs no error path.
pub(crate) type EmbeddedCb = Box<dyn FnOnce(FsDone, &mut FsConn<'_>)>;

/// Where an op that never reached the ring reports *why*, and hands
/// back what it was given.
///
/// A submission refusal and a teardown both drop the callback
/// unfired, which is the callback contract; firing one inline from a
/// submit path would deliver a completion during a submission, and
/// nothing here does that. A sink is not a callback: it runs no
/// consumer continuation and submits nothing, it only fills a slot, so
/// the distinction the callback form cannot make (`EBUSY` retry,
/// `EINVAL` caller bug, teardown stop) survives for the consumers that
/// can act on it.
///
/// **It carries the payload too.** `EBUSY` from a full op table is the
/// one refusal worth retrying, and a write whose buffers were dropped
/// on the way out cannot be retried by anyone - the caller would have
/// to keep a second copy of every payload against a failure the API
/// tells it is transient. [`FsDone::into_bufs`] hands them back on this
/// path exactly as it does on a completion.
///
/// **`Rc`, and cloned rather than taken.** A multi-step call ([`chain`],
/// [`walk`]) submits from a fresh facade at every step after the first,
/// so a sink one submission consumed would leave every later step
/// reporting teardown for a refusal the caller is told to retry. The
/// steps share one sink; the slot's "a real answer is final" precedence
/// is what makes more than one filler safe.
pub(crate) type FailSink = Rc<dyn Fn(Errno, Vec<Vec<u8>>)>;

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
        /// Set only by the futures layer; `None` for a plain callback,
        /// whose contract is that a drop closes the connection.
        on_fail: Option<FailSink>,
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

/// Report an early submission failure - the SQE never staged (slot exhaustion,
/// an unusable file) - handing the caller's payloads back exactly as a
/// completion would (see [`deliver`]).
fn fail(waiter: FsWaiter, err: Errno, bufs: Vec<Vec<u8>>) {
    deliver(Some(waiter), Err(err), bufs, None, None, true);
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
    /// This `OPENAT2` carries an `O_NONBLOCK` the special-file guard added,
    /// so the completion strips it back off the descriptor. False when the
    /// caller asked for the flag itself - theirs to keep.
    strip_nonblock: bool,
    /// `STATX` result pad - **the kernel writes it at completion**, so it
    /// must live until the CQE reaps.
    stat: Option<Box<StatxRaw>>,
    /// `TIMEOUT` timespec pad. The kernel copies it at prep
    /// (`__io_timeout_prep` -> `get_timespec64`), which happens inside the
    /// enter that submits the SQE - boxed and parked here so the address
    /// holds however many stages batch before that enter.
    ts: Option<Box<KernelTimespec>>,
    /// This timer's `ECANCELED` was asked for ([`FsConn::cancel_timeout`]),
    /// so the completion reports a marked retraction rather than the
    /// teardown verdict - `ECANCELED` with [`FsDone::was_refused`] false
    /// stays meaning teardown alone.
    retracted: bool,
    /// Keeps a path op's dirfd alive (and its fd number un-reused) while
    /// the op is in flight.
    anchor: Option<Anchor>,
    /// The second dirfd of a rename/link.
    anchor2: Option<Anchor>,
    /// The file an fd-op targets, parked here so its descriptor stays open
    /// (and un-reused) until the CQE reaps - the caller may drop its
    /// `File` mid-op. Dropping this on `clear` gives close-last ordering.
    file: Option<Arc<OwnedFd>>,
    /// This op's share of a leased recv-pool buffer (a leased write).
    /// Several writes in one delivery may read from the same buffer, so
    /// the id rides in an [`Arc`]: the buffer must outlive every DMA that
    /// reads it, and only the completion that drops the *last* share knows
    /// when that is - `Arc::into_inner` at reap surfaces the id exactly
    /// once, on [`FsDone`], for the net server to hand back to the pool.
    #[cfg(feature = "net-server")]
    recv_lease: Option<std::sync::Arc<LeaseHold>>,
    /// The byte count a leased write asked for, so a short completion can
    /// be told apart from a full one at reap time.
    #[cfg(feature = "net-server")]
    lease_want: u32,
}

/// One delivery's claim on a recv-pool buffer, shared by every leased
/// write reading from it. Plain `std::sync` deliberately: nothing
/// synchronizes *through* it - the refcount is the whole protocol - and
/// loom neither models this path nor supplies `Weak`.
#[cfg(feature = "net-server")]
#[derive(Debug)]
pub(crate) struct LeaseHold(pub(crate) u16);

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
            strip_nonblock: false,
            stat: None,
            ts: None,
            retracted: false,
            anchor: None,
            anchor2: None,
            file: None,
            #[cfg(feature = "net-server")]
            recv_lease: None,
            #[cfg(feature = "net-server")]
            lease_want: 0,
        }
    }

    /// Release every payload and mark the entry free (the caller bumps the
    /// generation and returns the slot to the free-list).
    fn clear(&mut self) {
        self.iov.clear();
        self.path = None;
        self.path2 = None;
        self.how = None;
        self.ts = None;
        self.retracted = false;
        self.anchor = None;
        self.anchor2 = None;
        self.file = None;
        #[cfg(feature = "net-server")]
        {
            self.recv_lease = None;
            self.lease_want = 0;
        }
        self.state = FsOpState::Free;
    }
}

/// Take the special-file guard's `O_NONBLOCK` back off a freshly opened
/// descriptor.
///
/// The flag exists to stop the *open* blocking on a planted FIFO or device;
/// on the descriptor it leaves behind it is not inert. `io_file_get_flags`
/// (`io_uring/io_uring.c:1793-1794`) reads it into `REQ_F_SUPPORT_NOWAIT` -
/// the same bit `FMODE_NOWAIT` sets - so `__io_read` (`io_uring/rw.c:950-958`)
/// takes the `IOCB_NOWAIT` branch instead of returning `-EAGAIN`, and the
/// transfer runs in the submitting task rather than on an io-wq worker. That
/// task is this reactor thread. The kernel strips the flag from the file it
/// returns whenever it was the one that added it
/// (`io_uring/openclose.c:161-162`); this is the same move for the same
/// reason.
///
/// One `fcntl` on the reactor, ~400 ns and about 5% of the open it follows,
/// spent to keep a whole read off this thread - a 32 MiB read of a warm ZFS
/// file measured 22.7 ms inline against being punted. Run here because this
/// is where the descriptor first becomes visible to anyone.
///
/// A failure is not worth failing the open over: the descriptor is valid
/// either way, and what is lost is scheduling, not correctness.
fn strip_guard_nonblock(fd: RawFd, flags: u64) {
    // SAFETY: `fd` is the descriptor OPENAT2 just returned. `F_SETFL` honours
    // only the settable subset (`O_APPEND`/`O_ASYNC`/`O_DIRECT`/`O_NOATIME`/
    // `O_NONBLOCK`), so passing back what was asked for minus `O_NONBLOCK`
    // keeps any of those the caller set and needs no `F_GETFL` first.
    unsafe {
        libc::fcntl(fd, libc::F_SETFL, flags as i32 & !libc::O_NONBLOCK);
    }
}

/// What a reaped op entry yields once its payloads are taken back out.
struct Completed {
    waiter: Option<FsWaiter>,
    bufs: Vec<Vec<u8>>,
    stat: Option<Box<StatxRaw>>,
    /// The op's `ECANCELED` was a retraction the caller asked for.
    retracted: bool,
    /// The open carried a guard `O_NONBLOCK`: the flags to restore without
    /// it, or `None` when there is nothing to strip.
    strip_nonblock: Option<u64>,
    #[cfg(feature = "net-server")]
    recv_lease: Option<std::sync::Arc<LeaseHold>>,
    #[cfg(feature = "net-server")]
    lease_want: u32,
}

/// The fs domain's tables. The host owns the [`Engine`] and passes it in for
/// staging; completion routing happens in [`FsCore::on_cqe`].
/// A finished off-loop job awaiting on-loop delivery: `(token, boxed result)`.
type PoolCompletion = (u64, Box<dyn Any + Send>);

/// The offload worker's epilogue: record the outcome, then wake the loop.
///
/// The order is what makes the wake reliable - the queue is written under
/// its lock *before* the poke, so a loop that wakes finds the completion
/// there. The eventfd counts, and the loop re-arms its `READ`, so no poke is
/// lost (the inject-path pattern).
///
/// A function so the loom models drive **this** epilogue rather than their
/// own copy of it. A model with its own copy checks the memory model rather
/// than the code: reorder the two lines in production and it stays green,
/// which is the case it is for (`bufring::publish_tail` states the rule).
pub(crate) fn finish_offload(
    sink: &Mutex<VecDeque<PoolCompletion>>,
    wake: &crate::uring::wake::WakeHandle,
    token: u64,
    outcome: Box<dyn Any + Send>,
) {
    sink.lock()
        .unwrap_or_else(|e| e.into_inner())
        .push_back((token, outcome));
    wake.poke();
}
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
    /// Spawned tasks and their run queue (the futures layer,
    /// [`super::task`]); woken tasks are polled by the delivery
    /// functions below.
    pub(crate) tasks: super::task::Tasks,
    /// This reactor's identity, minted at construction, so a [`Timer`]
    /// can be verified against the table that issued it - two reactors
    /// on one thread both start their tables at slot 0, generation 0,
    /// so slot + generation alone alias across them.
    core_id: u64,
    /// The highest connection generation [`FsCore::cancel_owned_by`]
    /// has swept, per connection slot - what
    /// [`FsCore::owner_is_gone`] reads. One entry per slot and slots
    /// are reused, so this is bounded by the host's connection table
    /// and never by how many connections have come and gone. Empty for
    /// a reactor with no owners (the standalone host).
    closed_owners: HashMap<u32, u64>,
    /// Armed timers per owner, and the per-owner ceiling the host set
    /// ([`FsCore::set_timer_cap`]). A timer is the one op that holds
    /// its slot for wall-clock time rather than until an I/O
    /// completes, so without a bound one connection could park the
    /// whole shared handler budget for its arms' full duration -
    /// measured at every slot of a consumer-sized table in 19 ms.
    /// The ceiling is the host's `max_in_flight_requests`: the real
    /// consumer's discipline is one timer per in-flight request (a
    /// retry tick per parked claimant), so one connection needs N
    /// concurrent timers exactly when N pipelined requests contend at
    /// once, and a smaller constant would couple this crate to the
    /// pipelining knob of another. `None` is uncapped - the standalone
    /// host has one caller and no tenants to protect from each other -
    /// and owner-less arms are never counted.
    armed_timers: HashMap<(u32, u64), u32>,
    timer_cap: Option<u32>,
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
            tasks: super::task::Tasks::new(),
            core_id: {
                // Plain std atomic: an id fetch is not a cross-thread
                // protocol, and loom need not model it.
                static NEXT: std::sync::atomic::AtomicU64 =
                    std::sync::atomic::AtomicU64::new(0);
                NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            },
            closed_owners: HashMap::new(),
            armed_timers: HashMap::new(),
            timer_cap: None,
        }
    }

    /// Bound armed timers per owner (see the field). Setup-time only,
    /// on [`FsCore::set_privileged_xattrs`]'s rule: the hosts expose
    /// it through a `&mut self` setter and their run loops also take
    /// `&mut self`, so it cannot change while operations are in
    /// flight.
    #[cfg_attr(not(feature = "net-server"), allow(dead_code))]
    pub(crate) fn set_timer_cap(&mut self, per_owner: u32) {
        self.timer_cap = Some(per_owner);
    }

    /// Whether `owner`'s connection has already been swept.
    ///
    /// Generations are per-slot and monotonic, so a sweep recorded at
    /// or above this one's means this one is over: an entry for a later
    /// tenant of the same slot answers `false` for the tenant that is
    /// live, and `true` for every tenant before it.
    #[cfg_attr(not(feature = "net-server"), allow(dead_code))]
    pub(crate) fn owner_is_gone(&self, owner: Owner) -> bool {
        let Some((slot, generation)) = owner else {
            return false;
        };
        self.closed_owners
            .get(&slot)
            .is_some_and(|&swept| swept >= generation)
    }

    /// A handle on this reactor's live-task count, for an embedding
    /// host whose graceful drain must wait for tasks as well as
    /// connections. Unused by the standalone host, which stops when
    /// nothing is in flight.
    #[cfg_attr(not(feature = "net-server"), allow(dead_code))]
    pub(crate) fn task_gauge(&self) -> std::rc::Rc<std::cell::Cell<usize>> {
        self.tasks.gauge()
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
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn submit_open(
        &mut self,
        eng: &mut Engine,
        pers: u16,
        anchor: Anchor,
        path: CString,
        how: RawOpenHow,
        guarded: bool,
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
        e.strip_nonblock = guarded;
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

    /// Stage a `WRITEV` whose single iovec points into a recv-pool buffer
    /// the caller holds leased - nothing is parked in `bufs`, and the buffer
    /// id rides the op entry out to [`FsDone`] so the net server hands it
    /// back to the pool at completion. `Err` returns the waiter untouched
    /// (a full op table or a refused SQE) for the caller to fall back with.
    ///
    /// # Safety-relevant contract (enforced by the caller)
    /// `[src, src + len)` must stay valid and un-recycled until this op's
    /// CQE: the connection surrenders its claim to the op rather than
    /// releasing it, and the pool reissues the id only after the server
    /// releases `FsDone`'s lease.
    #[cfg(feature = "net-server")]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn submit_pwritev2_leased(
        &mut self,
        eng: &mut Engine,
        pers: u16,
        file: Arc<OwnedFd>,
        src: *const u8,
        len: usize,
        off: u64,
        rw_flags: u32,
        hold: std::sync::Arc<LeaseHold>,
        waiter: FsWaiter,
    ) -> Result<(), FsWaiter> {
        let Some(op_slot) = self.op_free.pop() else {
            return Err(waiter);
        };
        let raw_fd = file.as_raw_fd();
        let entry = &mut self.ops[op_slot as usize];
        let gen32 = entry.generation as u32;
        entry.state.state = FsOpState::InFlight { tag: TAG_WRITEV };
        entry.state.iov = vec![libc::iovec {
            iov_base: src as *mut libc::c_void,
            iov_len: len,
        }];
        entry.state.file = Some(file);
        entry.state.recv_lease = Some(hold);
        entry.state.lease_want = len as u32;
        let iov_ptr = entry.state.iov.as_ptr() as u64;
        let ud = pack_raw(TAG_WRITEV, op_slot, gen32);
        let staged = eng.stage(ud, |sqe| {
            sqe.opcode = IORING_OP_WRITEV;
            sqe.fd = raw_fd;
            sqe.addr = iov_ptr;
            sqe.len = 1;
            sqe.off_addr2 = off;
            sqe.op_flags = rw_flags;
            sqe.personality = pers;
        });
        match staged {
            Ok(()) => {
                entry.state.waiter = Some(waiter);
                Ok(())
            }
            Err(_) => {
                // Never in flight: unwind the entry and hand the waiter
                // back, so the caller's fallback still owns its callback.
                entry.state.clear();
                entry.generation += 1;
                self.op_free.push(op_slot);
                Err(waiter)
            }
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

    #[cfg(all(test, not(loom)))]
    pub(crate) fn op_free_len_for_test(&self) -> usize {
        self.op_free.len()
    }

    #[cfg(all(test, not(loom)))]
    pub(crate) fn armed_timers_for_test(&self, owner: &(u32, u64)) -> u32 {
        self.armed_timers.get(owner).copied().unwrap_or(0)
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
    /// `dest` is either a buffer this side supplies, or a group id to let
    /// the kernel pick one from a registered ring at completion.
    ///
    /// A provided buffer works here for the same reason it works on a recv:
    /// `IORING_OP_READV` carries `buffer_select` (`io_uring/opdef.c`), and
    /// the one extra rule is a single iovec - `io_iov_buffer_select_prep`
    /// answers `-EINVAL` above one (`io_uring/rw.c`) - which this submit
    /// already satisfies. The kernel reads the iovec for its *length* and
    /// supplies the address itself, so `iov_base` is not dereferenced.
    pub(crate) fn submit_pump_read(
        &mut self,
        eng: &mut Engine,
        file: &File,
        dest: PumpDest,
        want: usize,
        off: u64,
        owner: (u32, u64),
    ) -> Result<(), Errno> {
        let (mut buf, bgid) = match dest {
            PumpDest::Owned(b) => (b, None),
            PumpDest::Group(g) => (Vec::new(), Some(g)),
        };
        debug_assert!(
            bgid.is_some() || (buf.is_empty() && buf.capacity() >= want)
        );
        let Some(op_slot) = self.op_free.pop() else {
            return Err(Errno::EBUSY);
        };
        // The iovec targets the Vec's spare capacity; computed before the
        // move below, and the heap block's address survives the move. Under
        // buffer select only its length is read.
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
        e.bufs = if bgid.is_some() {
            Vec::new()
        } else {
            vec![buf]
        };
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
            sqe.len = 1; // one iovec: buffer select refuses more
            sqe.off_addr2 = off;
            if let Some(g) = bgid {
                sqe.flags |= IOSQE_BUFFER_SELECT;
                sqe.buf_index = g;
            }
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

    /// Stage a standalone relative timer: one `IORING_OP_TIMEOUT` whose
    /// completion fires after `after`. Expiry is the op's success and is
    /// delivered as `Ok(0)` - the kernel answers a pure timer (count 0)
    /// with `-ETIME` (`io_timeout_fn`, `io_uring/timeout.c`), translated
    /// at [`FsCore::on_cqe`] because that firing is the completion the
    /// caller asked for. No fd, no personality: a timer touches nothing a
    /// credential guards.
    ///
    /// Answers the armed timer's slot and full-width generation, for
    /// [`FsConn::cancel_timeout`]'s [`Timer`]; `None` when the arm was
    /// refused, and then the waiter has already been answered.
    ///
    /// **A swept owner may not park time on the table.** Post-sweep
    /// submissions are deliberately allowed - a handler finishing an
    /// upload it accepted has work the disconnect does not undo - but a
    /// timer is a *wait*, not progress, and it is the one op that holds
    /// its slot for wall-clock duration: a re-arming retry tick whose
    /// connection died otherwise strands a slot per arm for the arm's
    /// full length, with the only holder of the [`Timer`] the dead
    /// handler itself. The refusal is the sweep's own verdict,
    /// `ECANCELED` with no refusal mark - exactly what the same timer
    /// would have answered had it been in flight when the sweep ran -
    /// so a continuation keyed on that vocabulary winds down the same
    /// way in both orderings.
    pub(crate) fn submit_timeout(
        &mut self,
        eng: &mut Engine,
        after: std::time::Duration,
        waiter: FsWaiter,
    ) -> Option<(u32, u64)> {
        if let FsWaiter::Embedded { owner: Some(o), .. } = &waiter {
            if self.owner_is_gone(Some(*o)) {
                deliver(
                    Some(waiter),
                    Err(Errno::ECANCELED),
                    Vec::new(),
                    None,
                    None,
                    false,
                );
                return None;
            }
            // The per-owner ceiling (see `armed_timers`). `EBUSY` with
            // the refusal mark, like a full table: the caller holds a
            // deadline already, and its completion is when arming again
            // makes sense.
            if let Some(cap) = self.timer_cap
                && self.armed_timers.get(o).copied().unwrap_or(0) >= cap
            {
                fail(waiter, Errno::EBUSY, Vec::new());
                return None;
            }
        }
        let Some(op_slot) = self.op_free.pop() else {
            fail(waiter, Errno::EBUSY, Vec::new());
            return None;
        };

        let ts = Box::new(KernelTimespec {
            tv_sec: i64::try_from(after.as_secs()).unwrap_or(i64::MAX),
            tv_nsec: i64::from(after.subsec_nanos()),
        });
        let addr = std::ptr::addr_of!(*ts) as u64;
        let entry = &mut self.ops[op_slot as usize];
        let gen32 = entry.generation as u32;
        let e = &mut entry.state;
        e.state = FsOpState::InFlight { tag: TAG_TIMEOUT };
        e.waiter = Some(waiter);
        e.ts = Some(ts);

        let ud = pack_raw(TAG_TIMEOUT, op_slot, gen32);
        let staged = eng.stage(ud, |sqe| {
            sqe.opcode = IORING_OP_TIMEOUT;
            sqe.addr = addr;
            sqe.len = 1; // exactly one timespec, per the kernel
        });
        if let Err(err) = staged {
            self.fail_op(op_slot, err);
            return None;
        }
        // Counted only once the arm is real - the refusals above never
        // increment, so nothing decrements for them either.
        if let Some(FsWaiter::Embedded { owner: Some(o), .. }) =
            &self.ops[op_slot as usize].state.waiter
        {
            *self.armed_timers.entry(*o).or_insert(0) += 1;
        }
        Some((op_slot, self.ops[op_slot as usize].generation))
    }

    /// Verify `Timer`'s three fields against this table and, when they
    /// still name a live timer, mark the entry retracted and stage the
    /// `ASYNC_CANCEL`. Anything else - a foreign reactor's token, a
    /// slot reissued since, an op that is not a timer - is inert.
    pub(crate) fn retract_timeout(
        &mut self,
        eng: &mut Engine,
        core: u64,
        slot: u32,
        generation: u64,
    ) {
        if core != self.core_id {
            return;
        }
        let Some(entry) = self.ops.get_mut(slot as usize) else {
            return;
        };
        if entry.generation != generation
            || entry.state.state != (FsOpState::InFlight { tag: TAG_TIMEOUT })
        {
            return;
        }
        entry.state.retracted = true;
        self.submit_cancel(eng, pack_raw(TAG_TIMEOUT, slot, generation as u32));
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

    /// The opcode an fd-meta tag stages, or `None` for a tag with no arm.
    ///
    /// Separate from the operand match so the refusal happens **before** an
    /// op slot is taken and an SQE is filled: `fill_sqe` zeroes the slot, so
    /// a fall-through would submit `IORING_OP_NOP` (opcode 0) under the op's
    /// own `user_data`, and a NOP completes `res = 0` - `Ok(0)` to the
    /// waiter, for a write that never happened.
    fn fd_meta_opcode(tag: u8) -> Option<u8> {
        Some(match tag {
            TAG_FTRUNCATE => IORING_OP_FTRUNCATE,
            TAG_FALLOCATE => IORING_OP_FALLOCATE,
            TAG_FADVISE => IORING_OP_FADVISE,
            TAG_SPLICE => IORING_OP_SPLICE,
            TAG_FGETXATTR => IORING_OP_FGETXATTR,
            TAG_FSETXATTR => IORING_OP_FSETXATTR,
            _ => return None,
        })
    }

    /// The opcode a path-op tag stages, or `None` for a tag with no arm. See
    /// [`fd_meta_opcode`](FsCore::fd_meta_opcode).
    fn path_op_opcode(tag: u8) -> Option<u8> {
        Some(match tag {
            TAG_STATX => IORING_OP_STATX,
            TAG_MKDIRAT => IORING_OP_MKDIRAT,
            TAG_UNLINKAT => IORING_OP_UNLINKAT,
            TAG_SYMLINKAT => IORING_OP_SYMLINKAT,
            TAG_RENAMEAT => IORING_OP_RENAMEAT,
            TAG_LINKAT => IORING_OP_LINKAT,
            _ => return None,
        })
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
        // Decide the opcode before a slot is taken. A tag with no arm in the
        // match below would otherwise reach `fill_sqe`, which zeroes the SQE
        // first (`uring/ring.rs`) - leaving `opcode` at 0, which is
        // `IORING_OP_NOP` (first in the kernel's `enum io_uring_op`). The NOP
        // is submitted carrying the op's real `user_data`, completes
        // `res = 0`, and `map_res` hands the waiter `Ok(0)`: a `trusted.*`
        // record write reported as done that never happened. The three
        // path-op siblings refuse instead, and so does this now.
        let Some(opcode) = Self::fd_meta_opcode(tag) else {
            debug_assert!(false, "not an fd-meta tag {tag:#x}");
            fail(waiter, Errno::EINVAL, vec![value]);
            return;
        };
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
            sqe.opcode = opcode;
            match tag {
                TAG_FTRUNCATE => {
                    sqe.off_addr2 = off; // the new length
                }
                TAG_FALLOCATE => {
                    sqe.off_addr2 = off; // offset
                    sqe.addr = len64; // length (kernel packing)
                    sqe.len = aux32; // mode
                }
                TAG_FADVISE => {
                    sqe.off_addr2 = off; // offset
                    // Length rides in `addr`; the kernel consults `len` only
                    // when `addr` is 0, and 0 already means "to end of file".
                    sqe.addr = len64;
                    sqe.op_flags = aux32; // POSIX_FADV_* advice
                }
                TAG_SPLICE => {
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
                    sqe.addr = name_ptr;
                    sqe.off_addr2 = val_ptr;
                    sqe.len = val_len;
                    sqe.op_flags = aux32;
                }
                // Unreachable: `fd_meta_opcode` refused any other tag before
                // a slot was taken. An arm added there and not here would
                // submit a real op with zeroed operands, which is what this
                // catches in a debug build.
                _ => debug_assert!(false, "no operands for tag {tag:#x}"),
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
        // See `stage_fd_meta`: an unhandled tag would leave the zeroed SQE's
        // opcode at 0 - `IORING_OP_NOP` - and report `Ok(0)` for an op that
        // never ran.
        let Some(opcode) = Self::path_op_opcode(tag) else {
            debug_assert!(false, "not a path-op tag {tag:#x}");
            fail(waiter, Errno::EINVAL, Vec::new());
            return;
        };
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
            sqe.opcode = opcode;
            match tag {
                TAG_STATX => {
                    sqe.len = len_arg; // STATX_* mask
                    sqe.off_addr2 = stat_ptr; // kernel writes at completion
                }
                TAG_MKDIRAT => {
                    sqe.len = len_arg; // mode
                }
                TAG_UNLINKAT => {} // flags = AT_REMOVEDIR; nothing else
                TAG_SYMLINKAT => {
                    sqe.off_addr2 = p2; // link path (addr = target)
                }
                TAG_RENAMEAT | TAG_LINKAT => {
                    sqe.off_addr2 = p2; // new path
                    sqe.len = dfd2 as u32; // new dirfd (kernel packing)
                }
                // Unreachable: `path_op_opcode` refused any other tag. See
                // the twin arm in `stage_fd_meta`.
                _ => debug_assert!(false, "no operands for tag {tag:#x}"),
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
    ///
    /// **This runs once per close, and it is not a liveness gate.** A
    /// continuation of a cancelled op runs after the sweep, with the same
    /// stamped owner, and whatever it submits then is not swept again -
    /// which is the same "an owner gone mid-chain" a continuation must
    /// already tolerate, and deliberately still allowed: a handler
    /// finishing an upload it already accepted has work to do that the
    /// peer's disconnect does not undo. A second sweep is not the
    /// answer either, and would be unbounded - a continuation that
    /// resubmits on `ECANCELED` keeps giving it something to find, and
    /// the sweep's own `ECANCELED` completions are what wake the
    /// continuations that resubmit.
    ///
    /// So the bound is the continuation's, not this function's, and
    /// [`FsCore::owner_is_gone`] - recorded here - is what makes it
    /// reachable. Two shapes need it, because for them a post-sweep op
    /// does *not* simply complete and stop:
    ///
    /// - An open with [`SpecialFiles::Allow`](super::SpecialFiles),
    ///   whose own rustdoc says it "hangs an io-wq worker and a caller
    ///   thread permanently, with no timeout anywhere to recover it".
    ///   Cancelling reaches it while in flight; a fresh one afterwards
    ///   has nothing left to reach it.
    /// - A task awaiting only offloads, which are never cancelled and
    ///   always deliver (see [`FsConn::offload`]) - so neither of the
    ///   two signals [`super::task`] tells a task to wind down on ever
    ///   arrives, and a re-arming one runs for a connection that is
    ///   gone, counted in `tasks.live` and holding a graceful drain
    ///   open with it.
    ///
    /// **Takes the whole batch of closes, because the scan is the
    /// cost.** A close is recorded unconditionally - the host cannot
    /// know whether a handler opened anything - so a connection that
    /// served one cached GET still arrives here, and one scan per
    /// owner walks the table `fs_ops + pool_size` entries deep, once
    /// each, on the reactor thread. Sorted so the membership test is a
    /// binary search: the batch is bounded by the connection table and
    /// a linear test would make a mass disconnect quadratic. The
    /// empty-table check ahead of it is what an idle server actually
    /// hits.
    #[cfg_attr(not(feature = "net-server"), allow(dead_code))]
    pub(crate) fn cancel_owned_by(
        &mut self,
        eng: &mut Engine,
        mut owners: Vec<(u32, u64)>,
    ) {
        // Recorded before the scan, so a continuation woken by one of
        // the cancellations below already reads its owner as gone -
        // and recorded whether or not there is anything to cancel,
        // since that is what a task with no ring op reads.
        for &(slot, generation) in &owners {
            let swept = self.closed_owners.entry(slot).or_insert(generation);
            *swept = (*swept).max(generation);
        }
        if self.op_free.len() == self.ops.len() {
            return; // nothing in flight for anyone
        }
        owners.sort_unstable();
        // Collect targets first (the scan borrows `self.ops`), then stage.
        let targets: Vec<u64> =
            self.ops
                .iter()
                .enumerate()
                .filter_map(|(i, entry)| {
                    let FsOpState::InFlight { tag } = entry.state.state else {
                        return None;
                    };
                    let owner = match &entry.state.waiter {
                        Some(FsWaiter::Embedded { owner: Some(o), .. }) => *o,
                        Some(FsWaiter::Pump { owner: o }) => *o,
                        _ => return None,
                    };
                    owners.binary_search(&owner).ok().map(|_| {
                        pack_raw(tag, i as u32, entry.generation as u32)
                    })
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
        #[cfg_attr(not(feature = "net-server"), allow(unused_mut))]
        let Some(mut completed) = self.take_op(tag, op_slot, gen32) else {
            return ReapedFs::None;
        };
        #[cfg(feature = "net-server")]
        let leased = completed.recv_lease.is_some();
        // The buffer goes back to the pool only when its LAST share drops:
        // sibling writes in the same delivery may still be reading it, so
        // the id surfaces from exactly one completion - `into_inner` on the
        // final `Arc` - and rides out `None` from every other.
        #[cfg(feature = "net-server")]
        let recv_lease = completed
            .recv_lease
            .take()
            .and_then(std::sync::Arc::into_inner)
            .map(|h| h.0);
        #[cfg(feature = "net-server")]
        let lease_want = completed.lease_want;
        let Completed {
            waiter,
            bufs,
            stat,
            strip_nonblock,
            retracted,
            ..
        } = completed;

        // A successful OPENAT2 returns a real fd as its result; wrap it in an
        // `Arc<OwnedFd>`. If nobody takes it (a gone channel receiver, or a
        // dropped embedded callback) the `Arc` drops and the fd closes - no
        // leak, no explicit close op. The op entry's parked `file` `Arc` (for
        // an fd op) was already dropped by `take_op`'s `clear`, giving
        // close-last ordering by ownership.
        let file = if tag == TAG_OPEN && res >= 0 {
            // Before anyone can see the descriptor, and so before any read of
            // it could be issued.
            if let Some(flags) = strip_nonblock {
                strip_guard_nonblock(res, flags);
            }
            // SAFETY: `res` is a fresh fd OPENAT2 just returned; nothing else
            // owns it.
            Some(Arc::new(unsafe { crate::fd::owned_from_raw(res) }))
        } else {
            None
        };
        let mut result = map_res(res);
        // A timer's expiry is its success: a pure `IORING_OP_TIMEOUT`
        // (count 0) completes `-ETIME` when it fires, and that firing is
        // the completion the caller asked for.
        if tag == TAG_TIMEOUT && result == Err(Errno::ETIME) {
            result = Ok(0);
        }
        // A retraction the caller staged is not the reactor going away:
        // `ECANCELED` with `was_refused` false stays meaning teardown
        // alone (the vocabulary a task winds down on), so the answer a
        // `cancel_timeout` asked for carries the mark. Gated on the
        // errno as well as the flag - if the timer expired before the
        // cancel reached it, the expiry is the answer and it is not a
        // retraction.
        let refused = retracted && result == Err(Errno::ECANCELED);
        // A short leased write is unrecoverable, so it must not look like
        // success: the source was the connection's receive buffer, and this
        // completion is what returns it to the pool - by the time a caller
        // saw `Ok(n)` the unwritten bytes could hold another connection's
        // request, so a retry from them writes someone else's data and a
        // shrug stores a truncated object. ZFS makes the case real: a
        // partial write returns its count with no error, by design
        // (`zfs_write`, `module/zfs/zfs_vnops.c:1085-1094` - "it's at least
        // a partial write, so it's successful"). The copy path stays
        // retryable (`FsDone::into_bufs` hands the source back), which is
        // the one honest asymmetry between the two.
        #[cfg(feature = "net-server")]
        if leased
            && let Ok(n) = result
            && (n as u32) < lease_want
        {
            result = Err(Errno::EIO);
        }

        match waiter {
            Some(FsWaiter::Channel(tx)) => {
                let _ = tx.send(FsOutcome::new(result, bufs, file, stat));
                ReapedFs::None
            }
            Some(FsWaiter::Embedded { owner, cb, .. }) => ReapedFs::Embedded(
                cb,
                FsDone {
                    result,
                    refused,
                    bufs,
                    file: file.map(File::new),
                    stat,
                    #[cfg(feature = "net-server")]
                    recv_lease,
                },
                owner,
            ),
            Some(FsWaiter::Pump { owner }) => ReapedFs::Pump(
                FsDone {
                    result,
                    refused,
                    bufs,
                    file: file.map(File::new),
                    stat,
                    #[cfg(feature = "net-server")]
                    recv_lease,
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
        #[cfg(feature = "net-server")]
        let mut done = done;
        #[cfg(feature = "net-server")]
        let leased = done.recv_lease.take().is_some();
        #[cfg(feature = "net-server")]
        let lease_want = done.lease_want;
        let Completed {
            waiter, bufs, stat, ..
        } = done;
        // A short leased write is unrecoverable on this path too, and the
        // reason does not soften at teardown: the source was the
        // connection's receive buffer, so a caller told `Ok(n)` cannot
        // retry from bytes it no longer owns, and a caller that shrugs
        // stores a truncated object. The live reap rewrites it; without the
        // same rewrite here a drain is the one way to observe the count.
        #[cfg(feature = "net-server")]
        let res = {
            let r = map_res(cqe.res);
            match r {
                Ok(n) if leased && (n as u32) < lease_want => Err(Errno::EIO),
                other => other,
            }
        };
        #[cfg(not(feature = "net-server"))]
        let res = map_res(cqe.res);
        // Teardown: the loop is dying - just report the outcome and hand any
        // buffers back. A file's fd is released when its op entry (and thus its
        // parked `Arc`) is dropped with the ring teardown - except an OPEN's,
        // which arrives in `cqe.res` with nothing parked owning it (the live
        // path is what builds the `Arc` from the result). Wrap it here too, so
        // the waiter takes an owned file or its drop closes the descriptor
        // instead of leaking it.
        // No `strip_guard_nonblock` here, unlike the live reap: the loop is
        // dying, so no further read can be submitted on this ring, and the
        // guard flag's only effect is on where a read of this descriptor
        // would run.
        let file = if tag == TAG_OPEN && cqe.res >= 0 {
            // SAFETY: `res` is a fresh fd OPENAT2 just returned; nothing else
            // owns it.
            Some(Arc::new(unsafe { crate::fd::owned_from_raw(cqe.res) }))
        } else {
            None
        };
        // Teardown, not a refusal: the loop is dying, so nothing here is
        // worth retrying and `ECANCELED` is the honest answer.
        deliver(waiter, res, bufs, file, stat, false);
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
        // A timer's completion - expiry, retraction, or the teardown
        // drain - returns its owner's headroom. Decremented here and
        // incremented only after a successful stage, so the two are
        // paired on the entry's own lifecycle whoever staged the
        // cancel.
        if tag == TAG_TIMEOUT
            && let Some(FsWaiter::Embedded { owner: Some(o), .. }) = &e.waiter
        {
            if let Some(n) = self.armed_timers.get_mut(o) {
                *n -= 1;
                if *n == 0 {
                    self.armed_timers.remove(o);
                }
            } else {
                debug_assert!(false, "a timer completed with no armed count");
            }
        }
        let done = Completed {
            waiter: e.waiter.take(),
            bufs: std::mem::take(&mut e.bufs),
            stat: e.stat.take(),
            retracted: e.retracted,
            strip_nonblock: e
                .strip_nonblock
                .then(|| e.how.as_ref().map(|h| h.flags))
                .flatten(),
            #[cfg(feature = "net-server")]
            recv_lease: e.recv_lease.take(),
            #[cfg(feature = "net-server")]
            lease_want: e.lease_want,
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
        deliver(waiter, Err(err), bufs, None, None, true);
    }
}

/// Where a pump read should land.
#[cfg_attr(not(feature = "net-server"), allow(dead_code))]
pub(crate) enum PumpDest {
    /// A buffer this side supplies and gets back on the completion.
    Owned(Vec<u8>),
    /// A registered buffer group; the kernel picks one at completion and
    /// names it in `IORING_CQE_F_BUFFER`.
    Group(u16),
}

/// The outcome handed to an embedded [`FsConn`] callback: the op's result plus
/// anything it produced (buffers, a new open [`File`], or `statx` metadata).
#[cfg_attr(not(feature = "net-server"), allow(dead_code))]
pub struct FsDone {
    result: Result<i32, Errno>,
    /// Whether this outcome is the facade's or the core's refusal to
    /// submit rather than something the kernel answered. See
    /// [`FsDone::was_refused`].
    refused: bool,
    bufs: Vec<Vec<u8>>,
    file: Option<File>,
    stat: Option<Box<StatxRaw>>,
    /// The recv-pool buffer id a leased write borrowed, owed back to the
    /// pool now that the op is over. Routed by the net server's dispatch;
    /// meaningless to any other consumer.
    #[cfg(feature = "net-server")]
    recv_lease: Option<u16>,
}

impl std::fmt::Debug for FsDone {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FsDone")
            .field("result", &self.result)
            .finish_non_exhaustive()
    }
}

/// A timer armed by [`FsConn::timeout`], for
/// [`FsConn::cancel_timeout`].
///
/// Names one arming, not the slot: it carries the reactor's identity
/// and the **full-width** op-table generation the arm was made under,
/// on the rule [`SlotEntry`](crate::uring::slots::SlotEntry) states -
/// a caller-retained handle must never alias a future incarnation of
/// its slot, and the truncated 32-bit routing token is only safe
/// because a completion cannot outlive its op, which a `Timer` held
/// past expiry does by design. The retraction verifies all three
/// fields against the table before staging anything, so a stale
/// token, or one minted by a different reactor on this thread, is
/// inert rather than a cancel of whoever holds the slot now. Copy, because
/// retracting is idempotent and a caller that holds two deadlines
/// should not have to track which one it has already spent; not
/// `Send`, because it names loop-thread state and crossing threads
/// with it could only ever reach the wrong ring.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timer {
    core: u64,
    slot: u32,
    generation: u64,
    _on_loop: std::marker::PhantomData<std::rc::Rc<()>>,
}

#[cfg_attr(not(feature = "net-server"), allow(dead_code))]
impl FsDone {
    /// A completion no op produced, with **no** claim about who
    /// produced the errno: the kernel's own verdict forwarded from
    /// somewhere else, or an outcome whose provenance is not this
    /// crate's to assert. [`FsDone::refused`] is the arm for a screen
    /// of this crate's own.
    pub(crate) fn failed(err: Errno) -> FsDone {
        FsDone {
            result: Err(err),
            refused: false,
            bufs: Vec::new(),
            file: None,
            stat: None,
            #[cfg(feature = "net-server")]
            recv_lease: None,
        }
    }

    /// A step this crate's own screen refused, carrying no payload -
    /// what a multi-step call answers with when it refuses *between*
    /// steps.
    ///
    /// Provenance has to be the same at both ends of a chain or it says
    /// nothing: the very screen that gives `EINVAL` with
    /// [`was_refused`](FsDone::was_refused) true at `open_chain`'s entry
    /// gives it again on a derived name three steps in, and answering
    /// the second with `failed` makes the same refusal read as
    /// `ECANCELED`-class teardown to the awaiting task.
    pub(crate) fn refused(err: Errno) -> FsDone {
        FsDone::refused_with(err, Vec::new())
    }

    /// A submission the facade or the core refused, with the payload it
    /// was handed back - see [`FailSink`] and [`FsDone::was_refused`].
    pub(crate) fn refused_with(err: Errno, bufs: Vec<Vec<u8>>) -> FsDone {
        FsDone {
            result: Err(err),
            refused: true,
            bufs,
            file: None,
            stat: None,
            #[cfg(feature = "net-server")]
            recv_lease: None,
        }
    }

    /// The recv-pool buffer a leased write borrowed, for the net server to
    /// hand back. Taken by the dispatch before the callback runs, so a
    /// consumer never sees it.
    #[cfg(feature = "net-server")]
    pub(crate) fn take_recv_lease(&mut self) -> Option<u16> {
        self.recv_lease.take()
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

    /// Whether this errno is **this crate's**, not the kernel's: the op
    /// never reached the ring, because the facade refused the arguments
    /// (`EINVAL`) or the op table was full (`EBUSY`).
    ///
    /// Read it before acting on an errno, because the two vocabularies
    /// overlap and the actions do not. `EBUSY` here is the documented
    /// fan-out failure, worth retrying with the payload
    /// [`FsDone::into_bufs`] hands back; `EBUSY` from the kernel is
    /// permanent for that path - `vfs_rmdir` answers it for a directory
    /// that is a mountpoint (`is_local_mountpoint`, `fs/namei.c`), and a
    /// nested dataset is exactly that under its parent, so a retry loop
    /// that cannot tell the two apart spins forever on the thread that
    /// serves every other connection. `ECANCELED` with this `false` is
    /// teardown.
    pub fn was_refused(&self) -> bool {
        self.refused
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
/// ring only through this facade. An argument a screen here refuses answers
/// `on_done` with a marked `EINVAL` **before the method returns**; a
/// submission failure past the screens (a full op table) drops `on_done`
/// (and the continuation it captured, closing the connection) unless a
/// reason sink is staged (the futures layer's [`FailSink`]). These methods
/// return `()` either way.
///
/// **No method here may return data borrowed from `'a`.** The task layer
/// parks a facade in a thread-local as `FsConn<'static>` and hands it back
/// as `&mut FsConn<'_>`; `&mut U` is invariant in `U`, so a closure taking
/// the facade can be instantiated at `&mut FsConn<'static>`.
///
/// What keeps that from leaking is **`task::with_conn`'s signature**:
/// `impl FnOnce(&mut FsConn<'_>) -> R` desugars higher-ranked, so `R`
/// cannot name the facade's lifetime whatever the cell holds. It is not
/// `task::reach_in`, which is generic over a `'static` `T` and quantifies
/// nothing - reached directly at `T = FsConn<'static>` it will hand out
/// `&'static` borrows of a facade that died with its poll. A second
/// wrapper beside `with_conn` has to reproduce that bound, or it is
/// unsound from safe code.
///
/// The rule here is the belt to that brace, and today it holds only
/// because every method returns owned values or borrows of `&self` - add
/// one `fn x(&self) -> &'a T` and a caller could extend a borrow of the
/// ring's tables past the poll that parked them.
#[cfg_attr(not(feature = "net-server"), allow(dead_code))]
pub struct FsConn<'a> {
    fs: &'a mut FsCore,
    eng: &'a mut Engine,
    owner: Owner,
    /// The delivering connection's recv-buffer claim, when the request's
    /// body still sits in one - what [`FsConn::pwritev2_from`] writes from
    /// without copying. `None` outside delivery (completion facades) and on
    /// unpooled connections.
    #[cfg(feature = "net-server")]
    lease: Option<RecvWriteLease<'a>>,
    /// The shared hold minted by this delivery's first leased write, kept
    /// as a `Weak` so the facade can hand later ranges a clone without
    /// itself delaying the buffer's release - the strong counts are the
    /// outstanding writes and nothing else.
    #[cfg(feature = "net-server")]
    lease_hold: Option<std::sync::Weak<LeaseHold>>,
    /// Staged by [`FsConn::fut`] for the submissions that follow it, and
    /// *cloned* by each one's `embed` rather than taken - see
    /// [`FailSink`]. `None` for every callback caller, which is what
    /// keeps their drop-on-refusal contract exactly as it was.
    fail_sink: Option<FailSink>,
    /// Whether a submission has taken a clone of `fail_sink` since it
    /// was staged. [`FsConn::fut`] reads it to tell "the op is in flight
    /// and reports for itself" from "`submit` returned without handing
    /// the op to the core at all".
    fail_armed: bool,
}

/// What [`FsConn::stage_fail_sink`] displaced, to be handed back to
/// [`FsConn::restore_fail_sink`]. A `fut` nested inside another's
/// `submit` closure must not swallow the outer's sink.
pub(crate) struct StagedSink(Option<FailSink>, bool);

/// A view of the delivering connection's recv-pool claim, offered to the
/// handler's fs facade for the duration of one delivery.
///
/// `taken` is a `Cell` because the handler holds the body as `&[u8]` -- a
/// shared borrow of the same connection - for its whole run, so the flag
/// that says "this claim now belongs to a write op" cannot go through
/// `&mut`. The connection reads it at consume time and surrenders the claim
/// to the op instead of recycling it.
#[cfg(feature = "net-server")]
pub(crate) struct RecvWriteLease<'a> {
    /// Start of the claimed buffer.
    pub(crate) ptr: *const u8,
    /// The leasable extent - the delivered message, never the whole
    /// buffer - bounding what may be written from.
    pub(crate) cap: usize,
    /// The pool buffer id, recorded on the op for the completion release.
    pub(crate) bid: u16,
    /// Set when a write takes the claim; read by the connection at consume.
    pub(crate) taken: &'a std::cell::Cell<bool>,
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
    ) -> FsConn<'a> {
        FsConn {
            fs,
            eng,
            owner,
            #[cfg(feature = "net-server")]
            lease: None,
            #[cfg(feature = "net-server")]
            lease_hold: None,
            fail_sink: None,
            fail_armed: false,
        }
    }

    /// Stage the reason-sink every submission inside one [`FsConn::fut`]
    /// takes a clone of, answering with what was staged before so the
    /// caller can put it back.
    pub(crate) fn stage_fail_sink(&mut self, sink: FailSink) -> StagedSink {
        StagedSink(
            self.fail_sink.replace(sink),
            std::mem::replace(&mut self.fail_armed, false),
        )
    }

    /// Put back what [`FsConn::stage_fail_sink`] displaced, answering
    /// whether any submission armed the sink being retired. `false`
    /// means the facade refused the arguments before the op reached the
    /// core, so nothing will ever report for it.
    pub(crate) fn restore_fail_sink(&mut self, prev: StagedSink) -> bool {
        self.fail_sink = prev.0;
        std::mem::replace(&mut self.fail_armed, prev.1)
    }

    /// Carry a multi-step call's sink onto the fresh facade a later step
    /// submits from (see [`FailSink`]). `chain` and `walk` are the only
    /// callers, because they are the only multi-step calls whose later
    /// steps reach the core themselves.
    fn carry_fail_sink(&mut self, sink: Option<FailSink>) {
        self.fail_sink = sink;
    }

    /// Box `on_done` as this connection's owner-stamped embedded waiter,
    /// taking a share of the staged reason sink on the way - **the one
    /// shape every submit method here hands the core.**
    ///
    /// Arming and boxing are one step because they were two, and the
    /// second was skippable. [`FsConn::fut`] tells "the op is in flight
    /// and will report for itself" from "the facade refused the
    /// arguments and nothing ever will" by whether any submission armed
    /// the sink, so a submit method that reaches the core without arming
    /// makes `fut` answer a perfectly good op with a spurious `EINVAL` -
    /// which is what the ring timer shipped with. There is no longer a
    /// waiter to build without passing through here, and nothing to pass
    /// in place of the share.
    #[cfg_attr(not(feature = "net-server"), allow(dead_code))]
    fn waiter<F>(&mut self, on_done: F) -> FsWaiter
    where
        F: FnOnce(FsDone, &mut FsConn<'_>) + 'static,
    {
        let on_fail = self.fail_sink.clone();
        self.fail_armed |= on_fail.is_some();
        FsWaiter::Embedded {
            owner: self.owner,
            cb: Box::new(on_done),
            on_fail,
        }
    }

    /// The facade's parts, reborrowed - what the task layer
    /// ([`super::task`]) needs so a poll can hold its task entry out of
    /// the table while the facade it hands the task borrows the tables.
    pub(crate) fn split(&mut self) -> (&mut FsCore, &mut Engine, Owner) {
        (&mut *self.fs, &mut *self.eng, self.owner)
    }

    /// Whether the connection this facade acts for has already been
    /// torn down.
    ///
    /// A continuation runs after its owner may be gone - the sweep is
    /// once per close and a completion it cancelled is what schedules
    /// the continuation - so "my ops are failing" is the signal a task
    /// is told to wind down on. Two shapes never see it: an offload is
    /// never cancelled and always delivers, and
    /// a timer armed *after* the sweep expires normally. A task built
    /// from either would otherwise run for a dead connection
    /// indefinitely, holding a graceful drain open with it.
    ///
    /// Submitting is still allowed here, and that is deliberate: a
    /// handler finishing work it already accepted - the last write of
    /// an upload, the rename that publishes it - is not undone by the
    /// peer hanging up. This says the peer is gone; what is worth
    /// finishing for it is the caller's judgement.
    ///
    /// Always `false` where the reactor has no owners (a standalone
    /// [`UringFs`](super::UringFs), whose whole loop is the lifetime).
    pub fn owner_is_gone(&self) -> bool {
        self.fs.owner_is_gone(self.owner)
    }

    /// Whether the loop this facade runs on has been asked to drain
    /// gracefully.
    ///
    /// The other half of [`owner_is_gone`](Self::owner_is_gone): that
    /// one says *your connection* closed, this one says *the server*
    /// is going away - a task whose connection is perfectly healthy
    /// can still be the last thing holding a drain open, and this is
    /// the signal it winds down on. Readable only between awaits, like
    /// its sibling, so it narrows the drain for looping work (a
    /// re-arming tick, a batch loop) and deliberately not for a single
    /// long await - an offload is never cancelled, and its delivery is
    /// the next chance to look.
    ///
    /// **Never `true` on a standalone [`UringFs`](super::UringFs)
    /// host today** - nothing there requests a graceful drain; its
    /// [`ShutdownHandle`](super::ShutdownHandle) stops the loop
    /// outright - so a consumer on that host must not wait for this.
    /// The contract is "a `true` means wind down", not "a drain will
    /// announce itself".
    pub fn draining(&self) -> bool {
        self.eng.shared.graceful_requested().is_some()
    }

    /// A second facade over the same delivery, for a step that dispatches
    /// twice (the window exhausting a known-length stream also carries the
    /// End stage). The recv-buffer claim moves into the reborrow - the
    /// first dispatch is the one with the body - so a leased write still
    /// happens at most once per delivery.
    #[cfg(feature = "http")]
    pub(crate) fn reborrow(&mut self) -> FsConn<'_> {
        FsConn {
            fs: &mut *self.fs,
            eng: &mut *self.eng,
            owner: self.owner,
            #[cfg(feature = "net-server")]
            lease: self.lease.take(),
            #[cfg(feature = "net-server")]
            lease_hold: self.lease_hold.take(),
            // Cloned, not taken: both halves of a two-step dispatch
            // submit, and both should report.
            fail_sink: self.fail_sink.clone(),
            fail_armed: false,
        }
    }

    /// Offer the delivering connection's recv-buffer claim for
    /// [`pwritev2_from`](FsConn::pwritev2_from) to write from without
    /// copying. Delivery-time only.
    #[cfg(feature = "net-server")]
    pub(crate) fn with_recv_lease(
        mut self,
        lease: Option<RecvWriteLease<'a>>,
    ) -> FsConn<'a> {
        self.lease = lease;
        self
    }

    /// Open `path` relative to `anchor` as `who`; fire `on_done` with the new
    /// [`File`] ([`FsDone::file`]). `path` must be anchor-relative (a leading
    /// `/` is refused); resolution defaults to the full [`CONFINED_RESOLVE`]
    /// set unless `how` states a confinement policy of its own, on the same
    /// rule the blocking [`FsHandle::open`](crate::uring_fs::FsHandle::open)
    /// applies - a `resolve` carrying only hardening flags composes with
    /// the default rather than replacing it. An invalid argument answers
    /// `on_done` **before this returns** with `EINVAL` and
    /// [`FsDone::was_refused`] true - the same verdict the mid-walk
    /// screens give, so provenance does not depend on where the screen
    /// fired. It is not silently dropped: a dropped continuation closes
    /// the connection, which turns a caller bug into a shed peer.
    ///
    /// Every facade may open, a continuation's included. What that costs
    /// is the file: a continuation runs for an owner that may already be
    /// gone, and nothing sweeps a descriptor opened after its
    /// connection closed until the reactor's tables go, so a chain that
    /// opens must reach a step that closes.
    pub fn open<F>(
        &mut self,
        who: Personality,
        anchor: &Anchor,
        path: &CStr,
        how: impl Into<super::FsOpenHow>,
        on_done: F,
    ) where
        F: FnOnce(FsDone, &mut FsConn<'_>) + 'static,
    {
        let bytes = path.to_bytes();
        if bytes.is_empty() || bytes[0] == b'/' {
            // Server facade: anchor-relative only, deliberately stricter
            // than the general-client `FsHandle::open`
            // (`open_parts`), which allows an absolute path when the caller
            // drops `RESOLVE_BENEATH`. The two validations differ on purpose;
            // do not unify them.
            return on_done(FsDone::refused(Errno::EINVAL), self);
        }
        let (how, special) = how.into().into_parts();
        let mut raw = how.to_raw();
        // BOTH of `open_parts`' rules, through the same functions: this is the
        // facade a request handler reaches with a path the peer chose, so it
        // cannot be the laxer of the two. Sharing only one of them is how it
        // becomes so - a creating open here parks on a planted FIFO that the
        // client facade survives.
        super::confine_resolve(&mut raw.resolve);
        let guarded = super::apply_special_file_guard(&mut raw, special);
        let w = self.waiter(on_done);
        self.fs.submit_open(
            self.eng,
            who.0,
            anchor.clone(),
            path.to_owned(),
            raw,
            guarded,
            w,
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
    /// That choice is the only one `how` has. `O_DIRECTORY` is forced -
    /// what this answers with is a directory or it is nothing - and a
    /// `how` carrying `O_CREAT` or `O_TMPFILE` is refused, because either
    /// would answer with a file where the caller asked for the tree.
    ///
    /// `EEXIST` is success at every component, so two callers building
    /// one tree both finish.
    ///
    /// An invalid argument answers `on_done` before this returns with a
    /// marked `EINVAL`, as [`open`](Self::open) does. `path` must name
    /// its components plainly
    /// -- relative, no `.`, no `..`, no empty component - which is
    /// [`path::relative_defect`](crate::path::relative_defect). `..` is
    /// refused rather than resolved even though `openat2` would resolve it
    /// safely under [`CONFINED_RESOLVE`]: what `a/..` names depends on what
    /// `a` turned out to be, so it is not a thing this walk can create, and
    /// a path that succeeded when the tree existed and failed when it did
    /// not would mean two different things.
    ///
    /// # Why this is a primitive rather than caller code
    ///
    /// `mkdirat` honours **no** `RESOLVE_*` flags - that is what [`Leaf`]
    /// exists for - so handing it `"a/b/c"` would resolve the
    /// intermediate components unconfined. The only sound construction
    /// alternates confined `openat2` walks with single-component
    /// `mkdirat`s, and each of those opens depends on the completion
    /// before it. Keeping the walk here is what makes each step's
    /// confinement the walk's own rather than a consumer's to get
    /// right, and what keeps a half-built tree from being reachable.
    ///
    /// `CONFINED_RESOLVE` is unioned in, not assigned: a caller may add
    /// restrictions and may drop none. Unlike a plain open, this one
    /// creates, and a create that escaped the anchor would leave a
    /// directory somewhere the caller never named.
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
        let bytes = path.to_bytes();
        // Judged on shape before anything is submitted, so the probe below
        // cannot admit what the walk would refuse. See the doc above.
        if crate::path::relative_defect(bytes).is_some() {
            return on_done(FsDone::refused(Errno::EINVAL), self);
        }
        // Owned, because each component outlives the completion that
        // consumes it. Every one is a `Leaf` by the check above.
        let parts: VecDeque<CString> = crate::path::components(bytes)
            .map(|p| CString::new(p).expect("no NUL: checked above"))
            .collect();
        let mut raw = how.to_raw();
        // Every open this makes - the probe, each intermediate, and the
        // answer - must name a directory, so `O_DIRECTORY` is forced the
        // way `CONFINED_RESOLVE` is. Two creation flags survive that and
        // are refused outright:
        //
        // `O_CREAT` would otherwise have the probe create a *regular file*
        // at the leaf and hand it back as though the tree had been built.
        // The kernel does refuse the pair - "Block bugs where O_DIRECTORY |
        // O_CREAT created regular files", `build_open_flags`,
        // `fs/open.c:1278-1284` - but only at the syscall, which is after
        // the walk has already created the tree beneath the leaf. Refusing
        // at entry is what keeps a bad argument from leaving a partial one.
        //
        // `O_TMPFILE` is `__O_TMPFILE | O_DIRECTORY`, so raising
        // `O_DIRECTORY` cannot exclude it and testing for it must mask the
        // `O_DIRECTORY` half off - otherwise every plain directory open
        // looks like one. It resolves the path as a directory and answers
        // with an unnamed inode *inside* it, which is not the directory the
        // caller asked for.
        const TMPFILE_ONLY: i32 = libc::O_TMPFILE & !libc::O_DIRECTORY;
        let refused = (libc::O_CREAT | TMPFILE_ONLY) as u64;
        if raw.flags & refused != 0 {
            return on_done(FsDone::refused(Errno::EINVAL), self);
        }
        // And `RESOLVE_IN_ROOT`, for the same class of reason as the two
        // above: the bundle unioned below carries `RESOLVE_BENEATH`, which
        // the kernel refuses to pair with it (`fs/open.c:1264`), so every
        // component of the walk would fail `EINVAL` - after the earlier ones
        // had already been created.
        if raw.resolve & crate::sync_fs::ResolveFlag::RESOLVE_IN_ROOT.bits()
            != 0
        {
            return on_done(FsDone::refused(Errno::EINVAL), self);
        }
        raw.flags |= libc::O_DIRECTORY as u64;
        raw.resolve |= CONFINED_RESOLVE.bits();

        let (start, want) = (anchor.clone(), path.to_owned());
        let on_done: WalkDone = Box::new(on_done);
        // Every step after the probe submits from a fresh facade, which
        // carries no sink of its own; see [`FailSink`].
        let sink = self.fail_sink.clone();
        // Every step this makes forces `O_DIRECTORY`, the answer
        // included, so no step can reach a FIFO's own `open`.
        self.open_component(
            who,
            start.clone(),
            want,
            raw,
            false,
            move |res, conn| {
                if res.file().is_some() {
                    return on_done(res, conn);
                }
                walk(conn, who, start, parts, mode, raw, on_done, sink);
            },
        );
    }

    /// Open each step relative to the file the step before it opened,
    /// and deliver the last.
    ///
    /// **Each step carries its own personality.** That is what this
    /// exists for: reaching a file inside a tree the caller may not
    /// traverse, while still having the kernel decide the caller's
    /// access to the file itself. A directory opened under the daemon's
    /// own personality grants nothing about what is inside it, so the
    /// last step names the caller and the answer is the kernel's.
    ///
    /// Kept here rather than written out by a consumer because the
    /// per-step personality and confinement are the point: a caller
    /// assembling the same walk by hand would have to get both right at
    /// every step, and an intermediate opened under the wrong one
    /// grants access the kernel was meant to decide.
    ///
    /// Every step is confined by [`CONFINED_RESOLVE`], unioned rather
    /// than assigned, and every step but the last is forced
    /// `O_DIRECTORY`. A step that creates, or that states
    /// `RESOLVE_IN_ROOT` - which the kernel refuses to pair with the
    /// `RESOLVE_BENEATH` unioned here - is refused at entry, before
    /// anything is submitted, so a bad argument cannot leave a
    /// half-walked chain behind. The refusal answers `on_done` with a
    /// marked `EINVAL` before this returns, exactly as the same screen
    /// answers mid-walk on a derived name - one verdict per defect,
    /// wherever it fires.
    pub fn open_chain<F>(
        &mut self,
        anchor: &Anchor,
        steps: Vec<OpenStep>,
        on_done: F,
    ) where
        F: FnOnce(FsDone, &mut FsConn<'_>) + 'static,
    {
        // Judged on shape before anything is submitted. A `Derived`
        // step cannot be judged here — it has no path yet — so the walk
        // judges it when it produces one, on the same rule.
        if steps.is_empty() {
            return on_done(FsDone::refused(Errno::EINVAL), self);
        }
        if matches!(steps[0].path, StepPath::Derived(_)) {
            // Nothing has been opened, so there is nothing to derive
            // from.
            return on_done(FsDone::refused(Errno::EINVAL), self);
        }
        for step in &steps {
            if let StepPath::Fixed(path) = &step.path
                && crate::path::relative_defect(path.to_bytes()).is_some()
            {
                return on_done(FsDone::refused(Errno::EINVAL), self);
            }
            if creation_refused(step.how.to_raw().flags) {
                return on_done(FsDone::refused(Errno::EINVAL), self);
            }
            // `chain` unions `CONFINED_RESOLVE` onto every step, and
            // `RESOLVE_BENEATH` is in it: "Scoping flags are mutually
            // exclusive" (`build_open_flags`, `fs/open.c:1263-1265`), so
            // a caller's `RESOLVE_IN_ROOT` makes every step `EINVAL` -
            // and with `was_refused` false, which tells the caller the
            // *kernel* objected to their path when this crate added the
            // bit that made it object. Screened here rather than fixed
            // up in `chain`, on `mkdir_path`'s rule: routing through
            // `confine_resolve` instead would union only
            // `CONFINED_HARDENING` once a policy bit is set, silently
            // dropping the `RESOLVE_NO_SYMLINKS` a multi-personality
            // chain needs more rather than less.
            if step.how.to_raw().resolve
                & crate::sync_fs::ResolveFlag::RESOLVE_IN_ROOT.bits()
                != 0
            {
                return on_done(FsDone::refused(Errno::EINVAL), self);
            }
        }
        let steps: VecDeque<OpenStep> = steps.into();
        let sink = self.fail_sink.clone();
        chain(self, anchor.clone(), steps, Box::new(on_done), sink);
    }

    /// One step of a walk, opened under its own personality.
    ///
    /// Stays private: every path this resolves is a single validated
    /// component of one the caller already named, confined, under the
    /// caller's own personality.
    /// `guarded` says whether the caller added the special-file guard to
    /// `how`, so the completion knows to strip `O_NONBLOCK` back off the
    /// descriptor. **The answer is not always a directory**: a step that
    /// forces `O_DIRECTORY` needs no guard, because the kernel answers
    /// `ENOTDIR` on a FIFO or device before reaching the file's own
    /// `open` method, but `chain`'s last step is opened as the caller
    /// asked and can name anything the anchor holds.
    fn open_component<F>(
        &mut self,
        who: Personality,
        anchor: Anchor,
        path: CString,
        how: RawOpenHow,
        guarded: bool,
        on_done: F,
    ) where
        F: FnOnce(FsDone, &mut FsConn<'_>) + 'static,
    {
        let w = self.waiter(on_done);
        self.fs
            .submit_open(self.eng, who.0, anchor, path, how, guarded, w);
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

    /// Write `src` - typically the request's own body - to `f` at `off`,
    /// without copying it when it still sits in the connection's receive
    /// buffer.
    ///
    /// When `src` lies inside the delivering connection's pooled claim,
    /// the op's iovec points straight at the buffer: the connection
    /// surrenders the claim to its writes instead of recycling it, and the
    /// pool gets the buffer back when the last of them completes - zero
    /// copies, zero allocations, for as many in-bounds ranges as one
    /// delivery submits. Anything else - an unpooled connection, a placed
    /// or owned body, a range outside the claim, a full op table, or a
    /// call from inside a task, whose facade carries no claim - falls
    /// back to `pwritev2` on a copy, so the call degrades instead of
    /// failing.
    ///
    /// The one behavioural asymmetry between the two paths is the **short
    /// write**, which ZFS returns as a success by design. On the copy path
    /// the source comes back through [`FsDone::into_bufs`] and the caller
    /// may retry the remainder; on the leased path the source is the
    /// receive buffer and this completion returns it to the pool, so no
    /// retry can ever be sound - a short leased write is therefore
    /// surfaced as `Err(EIO)` rather than as an `Ok(n)` inviting one.
    ///
    /// The `EIO` carries no cause because none is knowable at this
    /// completion: ZFS discards the breaking errno once
    /// any progress was made (`zfs_write`, `module/zfs/zfs_vnops.c:1085-1094`
    /// returns the partial count with no error), and io_uring folds a
    /// post-progress errno into the positive count the same way
    /// (`io_fixup_rw_res`, `io_uring/rw.c:563-574`) - so mapping the short
    /// write to `ENOSPC` or `EDQUOT` would be a guess. A consumer that must
    /// answer storage-full distinctly learns the cause from its next write
    /// against the same file, which has made no progress to hide the errno
    /// behind.
    ///
    /// Every leased write of a delivery shares the one claim: each holds a
    /// share, and the completion that drops the last share is the one that
    /// hands the buffer back. A short write fails its own op alone.
    ///
    /// # Pipelined ingest
    ///
    /// The lease outlives the delivery's verdict, so a streaming handler
    /// need not park per window: submit the write and return
    /// [`Continue`](crate::http::HttpVerdict::Continue), and the next
    /// window is read while this one's DMA runs - each write's completion
    /// releases its own buffer. The handler is the depth brake: track
    /// writes in flight and, at its cap, park with
    /// [`defer_stream`](crate::http::HttpRequest::defer_stream), resuming
    /// from a completion once below it - stopping the reads is the whole
    /// mechanism, since the socket buffer then fills and TCP slows the
    /// sender. Keep the cap at or under the reactor's per-connection ring
    /// headroom (`RECV_LEASE_DEPTH`, 4) or the excess degrades to copies,
    /// and size `fs_ops` to cover `pool_size` x depth. At `Stage::End`,
    /// wait for the outstanding completions with a plain
    /// [`defer`](crate::http::HttpRequest::defer) and answer from the last
    /// one; a failed window fails the request there.
    pub fn pwritev2_from<F>(
        &mut self,
        who: Personality,
        f: File,
        src: &[u8],
        off: u64,
        flags: RwFlags,
        on_done: F,
    ) where
        F: FnOnce(FsDone, &mut FsConn<'_>) + 'static,
    {
        #[cfg(feature = "net-server")]
        {
            let leased = match &self.lease {
                Some(l) => {
                    let base = l.ptr as usize;
                    let at = src.as_ptr() as usize;
                    let fits = at >= base
                        && at
                            .checked_add(src.len())
                            .is_some_and(|end| end <= base + l.cap);
                    fits.then_some((l.bid, l.taken))
                }
                _ => None,
            };
            // Every in-bounds range of one delivery shares the claim: the
            // hold is minted on the first leased write and cloned for the
            // rest, so the buffer goes back to the pool when the last of
            // them completes. The facade keeps only a `Weak` - a strong
            // clone here would withhold the release until the facade
            // dropped, for no one's benefit. An upgrade can only fail if
            // every holder already completed and released the buffer,
            // which cannot happen while this delivery is still running its
            // handler - but if it ever did, leasing again would write from
            // a buffer the pool may have re-issued, so it falls to the
            // copy path instead.
            let hold = leased.and_then(|(bid, _)| match &self.lease_hold {
                Some(w) => w.upgrade(),
                None => Some(std::sync::Arc::new(LeaseHold(bid))),
            });
            if let (Some((_, taken)), Some(hold)) = (leased, hold) {
                let w = self.waiter(on_done);
                let w = w;
                match self.fs.submit_pwritev2_leased(
                    self.eng,
                    who.0,
                    Arc::clone(&f.fd),
                    src.as_ptr(),
                    src.len(),
                    off,
                    flags.bits(),
                    std::sync::Arc::clone(&hold),
                    w,
                ) {
                    Ok(()) => {
                        taken.set(true);
                        self.lease_hold =
                            Some(std::sync::Arc::downgrade(&hold));
                        return;
                    }
                    Err(w) => {
                        // The op table refused; the copy path takes the
                        // same waiter so the callback survives the detour.
                        self.fs.submit_rw(
                            self.eng,
                            TAG_WRITEV,
                            who.0,
                            f.fd,
                            vec![src.to_vec()],
                            off,
                            flags.bits(),
                            w,
                        );
                        return;
                    }
                }
            }
        }
        self.pwritev2(who, f, vec![src.to_vec()], off, flags, on_done);
    }

    /// Flush `f`'s data and metadata (`fsync`) as `who`.
    pub fn fsync<F>(&mut self, who: Personality, f: File, on_done: F)
    where
        F: FnOnce(FsDone, &mut FsConn<'_>) + 'static,
    {
        let w = self.waiter(on_done);
        self.fs.submit_fsync(self.eng, who.0, f.fd, false, 0, 0, w);
    }

    /// Flush `f`'s data and essential metadata (`fdatasync`) as `who`.
    pub fn fdatasync<F>(&mut self, who: Personality, f: File, on_done: F)
    where
        F: FnOnce(FsDone, &mut FsConn<'_>) + 'static,
    {
        let w = self.waiter(on_done);
        self.fs.submit_fsync(self.eng, who.0, f.fd, true, 0, 0, w);
    }

    /// Fire `on_done` after `after`: one relative, one-shot
    /// `IORING_OP_TIMEOUT` on this ring, delivered as `Ok(0)` when it
    /// expires. No fd and no personality ride it - a timer touches
    /// nothing a credential guards - so this is the retry-tick and
    /// deadline primitive: a caller that must try again later re-arms
    /// here instead of sleeping an offload worker. An owner gone before
    /// expiry drops the callback, like any continuation's.
    ///
    /// **A timer holds its op slot for its whole wall-clock duration**,
    /// which no other op on this facade does - a read holds one until
    /// the I/O completes, and the table is sized on that. So a deadline
    /// armed for 30 s and reached in 3 ms costs the other 29.997 s of
    /// the handler budget unless it is retracted, which is what the
    /// returned [`Timer`] is for.
    ///
    /// `None` means the arm was refused - a full table, a staging
    /// failure, or a connection the teardown sweep has already passed,
    /// which may finish I/O but not park time on the table. The refusal
    /// reaches `on_done`'s frame the way every refused submission does:
    /// through the staged reason sink where one is armed (an awaited
    /// [`fut`](FsConn::fut) reads the errno and
    /// [`FsDone::was_refused`]), and otherwise by dropping the callback
    /// unfired, which for a request-handler continuation closes the
    /// connection. Nothing is delivered *to* a plain `on_done` on
    /// refusal - it never ran, and the `None` is the caller's copy of
    /// that fact.
    pub fn timeout<F>(
        &mut self,
        after: std::time::Duration,
        on_done: F,
    ) -> Option<Timer>
    where
        F: FnOnce(FsDone, &mut FsConn<'_>) + 'static,
    {
        let w = self.waiter(on_done);
        let core = self.fs.core_id;
        self.fs
            .submit_timeout(self.eng, after, w)
            .map(|(slot, generation)| Timer {
                core,
                slot,
                generation,
                _on_loop: std::marker::PhantomData,
            })
    }

    /// Retract a timer armed by [`timeout`](Self::timeout), freeing its
    /// op slot ahead of its expiry.
    ///
    /// The timer completes `ECANCELED` **with
    /// [`FsDone::was_refused`] true** and `on_done` fires with it, so a
    /// caller still gets exactly one answer per arm and the answer says
    /// what it was - `ECANCELED` unmarked stays meaning the reactor is
    /// going away, which is the verdict a task winds down on, and a
    /// healthy retraction must not read as that. Best-effort and
    /// idempotent: the token is verified against the table before
    /// anything is staged, so a [`Timer`] that already fired - or one
    /// minted by a different reactor - retracts nothing. Nothing is
    /// reported here either way; the answer arrives at `on_done`.
    pub fn cancel_timeout(&mut self, timer: Timer) {
        self.fs.retract_timeout(
            self.eng,
            timer.core,
            timer.slot,
            timer.generation,
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
        let w = self.waiter(on_done);
        self.fs
            .submit_fsync(self.eng, who.0, f.fd, datasync, offset, length, w);
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
        let w = self.waiter(on_done);
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
            w,
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
        let w = self.waiter(on_done);
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
            w,
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
        let w = self.waiter(on_done);
        self.fs.submit_fgetxattr_as_root(
            self.eng,
            f.fd,
            name.to_owned(),
            buf,
            w,
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
            return on_done(FsDone::refused(Errno::EINVAL), self);
        }
        let w = self.waiter(on_done);
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
            w,
        );
    }

    /// Create a hard link at `new_leaf` in `new` for `old_leaf` in `old`.
    ///
    /// **A [`Leaf`] bounds the name, not what the name resolves to.**
    /// `flags` reaches the kernel as given, and `AT_SYMLINK_FOLLOW`
    /// there makes `old_leaf` resolve wherever it points - a
    /// one-component symlink a peer planted inside `old` is a valid
    /// leaf, so the new name lands inside `new` as a second name for an
    /// inode outside it. The kernel offers no confinement for this:
    /// `may_linkat` (`fs/namei.c`) decides *which* inode may be linked
    /// and never where the link lands, so `fs.protected_hardlinks` does
    /// not help either. Pass `AtFlags::empty()` unless the source tree
    /// is one nothing else can write, or open the source under
    /// `RESOLVE_NO_SYMLINKS` and publish it with
    /// [`linkat_file`](Self::linkat_file).
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
        let w = self.waiter(on_done);
        self.fs.submit_linkat_file(
            self.eng,
            who.0,
            f.fd,
            new.clone(),
            new_leaf.to_cstring(),
            w,
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
        let w = self.waiter(on_done);
        self.fs.submit_rw(
            self.eng,
            tag,
            who.0,
            f.fd,
            bufs,
            off,
            rw_flags.bits(),
            w,
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
        let w = self.waiter(on_done);
        self.fs.submit_fd_meta(
            self.eng, tag, who.0, f.fd, name, value, off, len64, aux32, w,
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
        let w = self.waiter(on_done);
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
            w,
        );
    }
}

/// Names a step's path from the directory the step before it opened.
///
/// Boxed rather than a generic parameter: the steps travel as one list,
/// so they must all be the same type.
pub type DeriveName = Box<dyn FnOnce(&Anchor) -> crate::Result<CString>>;

/// What one step of an [`FsConn::open_chain`] resolves, and how it is
/// named.
///
/// A step's path may hold several components: `openat2` honours the
/// `RESOLVE_*` flags every step is confined by, so a whole subtree
/// descent is one open rather than one per component. That is the
/// difference from [`FsConn::mkdir_path`], whose `mkdirat` honours
/// none and must therefore walk a component at a time.
pub enum StepPath {
    /// Known before the chain starts.
    Fixed(CString),
    /// Named from the directory the previous step opened.
    ///
    /// The one thing a consumer can compute that this module cannot: a
    /// filehandle read back as the directory that stores state about
    /// it. Runs on the reactor thread between two submissions, so it
    /// must not block — a `name_to_handle_at` on a descriptor already
    /// open is the intended shape, and a read of anything is not.
    ///
    /// Never valid as the first step: there is no previous file.
    Derived(DeriveName),
}

impl std::fmt::Debug for StepPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Fixed(p) => f.debug_tuple("Fixed").field(p).finish(),
            Self::Derived(_) => f.write_str("Derived(..)"),
        }
    }
}

/// One step of an [`FsConn::open_chain`].
///
/// **The credential is per step, which is the point.** A tree only the
/// daemon may traverse is opened under its own personality, while a
/// file inside it is still resolved under the caller's — so the
/// kernel makes the access decision about the file the caller actually
/// named, in a directory the caller could never have walked.
#[derive(Debug)]
pub struct OpenStep {
    /// What this step names, relative to the file the previous step
    /// opened (or to the chain's anchor, for the first).
    pub path: StepPath,
    /// The credential this step resolves under.
    pub who: Personality,
    /// This step's flags. Every step but the last is forced
    /// `O_DIRECTORY`; the last is opened as asked.
    pub how: OpenHow,
}

/// The callback a [`FsConn::mkdir_path`] walk carries between steps.
///
/// Boxed: the walk is a loop written as recursion, so a generic parameter
/// would be a type that contains itself.
type WalkDone = Box<dyn FnOnce(FsDone, &mut FsConn<'_>)>;

/// The creation flags no step of a chain may carry.
///
/// `O_CREAT` and `O_TMPFILE` both make an inode, and a chain that made
/// one at an intermediate would leave it behind when a later step
/// failed. `O_TMPFILE` is `__O_TMPFILE | O_DIRECTORY`, so testing for
/// it has to mask the `O_DIRECTORY` half off — every directory open
/// carries that bit and would otherwise look like one.
fn creation_refused(flags: u64) -> bool {
    const TMPFILE_ONLY: i32 = libc::O_TMPFILE & !libc::O_DIRECTORY;
    flags & ((libc::O_CREAT | TMPFILE_ONLY) as u64) != 0
}

/// One step: name it, open it under its own personality, and recurse on
/// what is left.
///
/// `cur` is the deepest file reached so far, and the last step's open is
/// the answer.
fn chain(
    conn: &mut FsConn<'_>,
    cur: Anchor,
    mut steps: VecDeque<OpenStep>,
    on_done: WalkDone,
    sink: Option<FailSink>,
) {
    let Some(step) = steps.pop_front() else {
        // Entry validated a non-empty list. Answered rather than
        // dropped: a dropped callback closes the connection.
        return on_done(FsDone::refused(Errno::EINVAL), conn);
    };
    let last = steps.is_empty();
    let mut raw = step.how.to_raw();
    raw.resolve |= CONFINED_RESOLVE.bits();
    // Only the answer is opened as the caller asked; everything above it
    // is a directory this walks through.
    //
    // Which is why the answer is guarded and the rest are not. An
    // intermediate carries `O_DIRECTORY`, so the kernel answers `ENOTDIR`
    // on a special file before reaching its own `open`; the answer
    // carries whatever the caller asked for, and a FIFO named there with
    // a forcing flag (`O_TRUNC`, which `io_openat_force_async` punts to
    // io-wq where `io_openat2` never adds `O_NONBLOCK` -
    // `io_uring/openclose.c`) parks a worker in `wait_for_partner`
    // indefinitely and pins its op slot with it. There is no
    // `SpecialFiles` opt-out here: a step names a path relative to a
    // directory the caller may not own, which is the case the guard is
    // for. A caller who means to open a FIFO uses `FsConn::open` with
    // `SpecialFiles::Allow`.
    let guarded = if last {
        super::apply_special_file_guard(&mut raw, super::SpecialFiles::Guard)
    } else {
        raw.flags |= libc::O_DIRECTORY as u64;
        false
    };
    let who = step.who;
    // A derived name is produced here, from the file the previous step
    // opened, and screened on the same rule entry applied to the rest.
    let path = match step.path {
        StepPath::Fixed(path) => path,
        StepPath::Derived(name) => match name(&cur) {
            Ok(path)
                if crate::path::relative_defect(path.to_bytes()).is_none() =>
            {
                path
            }
            Ok(_) => return on_done(FsDone::refused(Errno::EINVAL), conn),
            // Forwarded, not refused: the errno is the caller's own
            // closure's, and marking it would have this crate claim a
            // verdict it did not reach.
            Err(crate::Error::Errno(e)) => {
                return on_done(FsDone::failed(e), conn);
            }
            Err(_) => return on_done(FsDone::refused(Errno::EINVAL), conn),
        },
    };
    // Carried onto every step's facade: the second and later steps
    // submit from the fresh `FsConn` a completion is handed, which has
    // no sink of its own, so without this a transient `EBUSY` mid-chain
    // reaches the caller as teardown.
    conn.carry_fail_sink(sink.clone());
    conn.open_component(who, cur, path, raw, guarded, move |res, conn| {
        let Some(f) = res.file() else {
            return on_done(res, conn);
        };
        if last {
            return on_done(res, conn);
        }
        match Anchor::from_file(&f) {
            Ok(next) => chain(conn, next, steps, on_done, sink),
            Err(_) => on_done(FsDone::refused(Errno::EBADF), conn),
        }
    });
}

/// One component: create it, open it, and recurse on what is left.
///
/// `cur` is the deepest directory reached so far, and the last component's
/// open is the answer.
#[allow(clippy::too_many_arguments)]
fn walk(
    conn: &mut FsConn<'_>,
    who: Personality,
    cur: Anchor,
    mut parts: VecDeque<CString>,
    mode: Mode,
    how: RawOpenHow,
    on_done: WalkDone,
    sink: Option<FailSink>,
) {
    let Some(part) = parts.pop_front() else {
        // Entry validated a non-empty list. Answered rather than dropped:
        // a dropped callback closes the connection.
        return on_done(FsDone::refused(Errno::EINVAL), conn);
    };
    let bytes = part.clone().into_bytes();
    let Ok(leaf) = Leaf::new(&bytes) else {
        return on_done(FsDone::refused(Errno::EINVAL), conn);
    };
    let at = cur.clone();
    // Carried onto every step's facade, for `chain`'s reason.
    conn.carry_fail_sink(sink.clone());
    conn.mkdirat(who, &at, leaf, mode, move |res, conn| {
        match res.result() {
            // `mkdir -p`'s rule, and the outcome of losing a race with
            // another creator.
            Ok(_) | Err(crate::Error::Errno(Errno::EEXIST)) => {}
            Err(_) => return on_done(res, conn),
        }
        conn.carry_fail_sink(sink.clone());
        // `mkdir_path` forces `O_DIRECTORY` on every step; see `chain`.
        conn.open_component(who, cur, part, how, false, move |res, conn| {
            let Some(f) = res.file() else {
                return on_done(res, conn);
            };
            if parts.is_empty() {
                return on_done(res, conn);
            }
            match Anchor::from_file(&f) {
                Ok(next) => {
                    walk(conn, who, next, parts, mode, how, on_done, sink)
                }
                Err(_) => on_done(FsDone::refused(Errno::EBADF), conn),
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
    ///   already tolerate that (a deferred reply is generation-checked,
    ///   and a file it opens is its own to close).
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
            finish_offload(&sink, &wake.wake, token, Box::new(r));
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

    /// Copy `len` bytes from `src[off_src..]` to `dst[off_dst..]`, delivering
    /// the bytes copied. On a pool with ZFS block cloning the kernel makes
    /// this metadata-only by itself — `copy_file_range(2)` is clone-first —
    /// and falls back to a byte copy where it cannot.
    ///
    /// **Offloaded, whole-range, one job.** A clone is not free of waiting
    /// even where it is free of data movement: with `zfs_bclone_wait_dirty`
    /// on, a source that was written moments ago costs a transaction group
    /// while it syncs. None of that may run on the loop, so all of it is
    /// offloaded.
    ///
    /// The whole remaining range goes in one call rather than in chunks. A
    /// chunk boundary is a second entry into `zfs_clone_range`, retaking
    /// both rangelocks and every property and alignment check, and it
    /// forfeits the clone besides — the destination's rangelock is promoted
    /// to whole-file only on its first write, which is what grows the
    /// blocksize to the source's. A short return is re-issued from where it
    /// stopped.
    ///
    /// This is how an embedded handler assembles a large object from parts
    /// without leaving the loop;
    /// [`QueryPool::copy_file_range`](super::query_dir::QueryPool::copy_file_range)
    /// is the twin for a caller that is not already on the loop.
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
                super::query_dir::copy_range(&src, &dst, off_src, off_dst, len)
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
    /// [`DirWalk`] to `on_ready` on the reactor thread.
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
            let mut c = FsConn::new(fs, eng, OWNER0);
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
                    // The real delivery functions, not a copy of their
                    // bodies: a copy silently misses whatever they
                    // grow - it missed task draining entirely, so a
                    // task spawned in a test here was polled once and
                    // then waited on a loop that would never poll it
                    // again, hanging instead of failing.
                    deliver_pool_completions(fs, eng);
                    continue;
                }
                if tag == TAG_CANCEL || tag & TAG_FS_DOMAIN == 0 {
                    continue;
                }
                let reaped = fs.on_cqe(eng, tag, slot, g, cqe.res);
                deliver_embedded(fs, eng, reaped);
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

    /// Run `f` with this thread's panic printing silenced. The guard
    /// carries its own serialization now (see
    /// `quiet_panics_on_this_thread`), so this is only the shorthand.
    fn with_silent_panics<R>(f: impl FnOnce() -> R) -> R {
        let _quiet = crate::uring_fs::quiet_panics_on_this_thread();
        f()
    }

    /// `a/b/leaf` under a fresh directory, for the chain tests.
    fn nested() -> crate::TempDir {
        let dir = crate::tempdir().expect("tempdir");
        std::fs::create_dir_all(dir.path().join("a/b")).expect("mkdir -p");
        std::fs::write(dir.path().join("a/b/leaf"), b"bytes").expect("write");
        dir
    }

    /// The whole point of the primitive: reach a file two directories
    /// down, in steps, from one facade entry.
    #[test]
    fn a_chain_reaches_a_file_two_directories_down() {
        let (mut eng, mut fs, me) = setup();
        let dir = nested();
        let at = Anchor::open(dir.path()).expect("anchor");
        let got: Rc<RefCell<Option<bool>>> = Rc::new(RefCell::new(None));
        let g2 = got.clone();
        drive(
            &mut eng,
            &mut fs,
            move |c| {
                c.open_chain(
                    &at,
                    vec![
                        OpenStep {
                            path: StepPath::Fixed(c"a/b".to_owned()),
                            who: me,
                            how: OpenHow::new()
                                .flags(OFlag::O_PATH | OFlag::O_DIRECTORY),
                        },
                        OpenStep {
                            path: StepPath::Fixed(c"leaf".to_owned()),
                            who: me,
                            how: OpenHow::new().flags(OFlag::O_RDONLY),
                        },
                    ],
                    move |res, _c| {
                        *g2.borrow_mut() = Some(res.file().is_some());
                    },
                );
            },
            || got.borrow().is_some(),
        );
        assert_eq!(*got.borrow(), Some(true), "the leaf must be delivered");
    }

    /// A chain's last step is opened as the caller asked, so unlike
    /// every step above it, it can name a special file.
    ///
    /// `O_TRUNC` forces the open async (`io_openat_force_async`,
    /// `io_uring/openclose.c`), and `io_openat2` adds `O_NONBLOCK` only
    /// on the inline attempt (`IO_URING_F_NONBLOCK`), which a forced
    /// io-wq worker does not have - the `WARN_ON_ONCE` beside it is the
    /// kernel asserting the two are exclusive. So an unguarded step here
    /// reaches `fifo_open`'s `wait_for_partner` (`fs/pipe.c`) and parks
    /// a worker and its op slot until the owner's teardown sweep. The
    /// guard is what makes it answer instead.
    #[test]
    fn a_chains_last_step_cannot_park_on_a_fifo() {
        let (mut eng, mut fs, me) = setup();
        let dir = crate::tempdir().expect("tempdir");
        std::fs::create_dir(dir.path().join("a")).expect("mkdir");
        let fifo = dir.path().join("a/pipe");
        let cpath =
            CString::new(fifo.as_os_str().as_encoded_bytes()).expect("no NUL");
        // SAFETY: a NUL-terminated path naming nothing yet, inside a
        // directory this test made.
        let made = unsafe { libc::mkfifo(cpath.as_ptr(), 0o600) };
        assert_eq!(made, 0, "mkfifo: {}", std::io::Error::last_os_error());

        let at = Anchor::open(dir.path()).expect("anchor");
        let got: Rc<RefCell<Option<Option<Errno>>>> =
            Rc::new(RefCell::new(None));
        let g2 = got.clone();
        drive(
            &mut eng,
            &mut fs,
            move |c| {
                c.open_chain(
                    &at,
                    vec![
                        OpenStep {
                            path: StepPath::Fixed(c"a".to_owned()),
                            who: me,
                            how: OpenHow::new()
                                .flags(OFlag::O_PATH | OFlag::O_DIRECTORY),
                        },
                        OpenStep {
                            path: StepPath::Fixed(c"pipe".to_owned()),
                            who: me,
                            how: OpenHow::new()
                                .flags(OFlag::O_WRONLY | OFlag::O_TRUNC),
                        },
                    ],
                    move |res, _c| {
                        *g2.borrow_mut() = Some(match res.result() {
                            Err(crate::Error::Errno(e)) => Some(e),
                            _ => None,
                        });
                    },
                );
            },
            || got.borrow().is_some(),
        );
        assert_eq!(
            *got.borrow(),
            Some(Some(Errno::ENXIO)),
            "a FIFO with no reader must answer, not park a worker"
        );
    }

    /// The step that cannot be written before the chain starts: a name
    /// computed from the directory the previous step opened.
    #[test]
    fn a_derived_step_names_the_next_directory() {
        let (mut eng, mut fs, me) = setup();
        let dir = nested();
        let at = Anchor::open(dir.path()).expect("anchor");
        let got: Rc<RefCell<Option<bool>>> = Rc::new(RefCell::new(None));
        let g2 = got.clone();
        drive(
            &mut eng,
            &mut fs,
            move |c| {
                c.open_chain(
                    &at,
                    vec![
                        OpenStep {
                            path: StepPath::Fixed(c"a".to_owned()),
                            who: me,
                            how: OpenHow::new()
                                .flags(OFlag::O_PATH | OFlag::O_DIRECTORY),
                        },
                        OpenStep {
                            // Derived from the open directory rather
                            // than from anything the caller knew.
                            path: StepPath::Derived(Box::new(|prev| {
                                let st = crate::sync_fs::statx(
                                    prev,
                                    "",
                                    AtFlags::AT_EMPTY_PATH,
                                    StatxMask::INO,
                                )?;
                                assert!(st.ino() != 0, "a real directory");
                                Ok(c"b/leaf".to_owned())
                            })),
                            who: me,
                            how: OpenHow::new().flags(OFlag::O_RDONLY),
                        },
                    ],
                    move |res, _c| {
                        *g2.borrow_mut() = Some(res.file().is_some());
                    },
                );
            },
            || got.borrow().is_some(),
        );
        assert_eq!(*got.borrow(), Some(true), "the derived name must resolve");
    }

    /// A chain from a continuation opens, like one from the request
    /// handler.
    ///
    /// It used to be refused, on the grounds that the file it produces
    /// "would outlive the connection it would go to". It cannot: the
    /// callback runs either way (`deliver_embedded` builds an `FsConn`
    /// and calls it unconditionally), and it is handed the fd wrapped
    /// in an `Arc<OwnedFd>` that closes on drop. Nothing was ever
    /// orphaned, and the refusal silently dropped `on_done` — which
    /// closes the connection — for consumers whose work legitimately
    /// spans completions.
    #[test]
    fn a_chain_from_a_continuation_opens() {
        let (mut eng, mut fs, me) = setup();
        let dir = nested();
        let at = Anchor::open(dir.path()).expect("anchor");
        let got = Rc::new(RefCell::new(None));
        let g2 = got.clone();
        drive(
            &mut eng,
            &mut fs,
            move |c| {
                // One completion, then a chain from inside it: the
                // shape the gate used to swallow.
                c.offload(
                    || 1u64,
                    move |_, c| {
                        c.open_chain(
                            &at,
                            vec![OpenStep {
                                path: StepPath::Fixed(c"a".to_owned()),
                                who: me,
                                how: OpenHow::new().flags(OFlag::O_RDONLY),
                            }],
                            move |res, _c| {
                                *g2.borrow_mut() = Some(res.file().is_some());
                            },
                        );
                    },
                );
            },
            || got.borrow().is_some(),
        );
        assert_eq!(*got.borrow(), Some(true), "the chain resolved");
    }

    /// A screen that fires mid-chain refuses the way the same screen
    /// refuses at entry.
    ///
    /// `..` in a component is refused at `open_chain`'s entry - where
    /// nothing is submitted, nothing arms the sink, and `FsConn::fut`
    /// synthesises the marked `EINVAL`
    /// (`a_refused_errno_is_marked_as_this_crates_own`) - and again on
    /// a name the caller's `DeriveName` produces after a step has
    /// opened. The second is a real completion answered by `chain`, so
    /// it has to carry the mark itself; without it the same defect
    /// reads as this crate's verdict at entry and as the kernel's three
    /// steps in, and an awaiting task takes the second for teardown.
    #[test]
    fn a_mid_chain_screen_refuses_the_way_the_entry_screen_does() {
        let (mut eng, mut fs, me) = setup();
        let dir = nested();
        let at = Anchor::open(dir.path()).expect("anchor");
        let mid: Rc<RefCell<Option<FsDone>>> = Rc::new(RefCell::new(None));
        let m2 = mid.clone();
        drive(
            &mut eng,
            &mut fs,
            move |c| {
                c.open_chain(
                    &at,
                    vec![
                        OpenStep {
                            path: StepPath::Fixed(c"a".to_owned()),
                            who: me,
                            how: OpenHow::new()
                                .flags(OFlag::O_PATH | OFlag::O_DIRECTORY),
                        },
                        OpenStep {
                            path: StepPath::Derived(Box::new(|_| {
                                Ok(c"../escape".to_owned())
                            })),
                            who: me,
                            how: OpenHow::new().flags(OFlag::O_RDONLY),
                        },
                    ],
                    move |res, _c| *m2.borrow_mut() = Some(res),
                );
            },
            || mid.borrow().is_some(),
        );
        let mid = mid.borrow_mut().take().expect("the chain answered");
        assert!(
            matches!(mid.result(), Err(crate::Error::Errno(Errno::EINVAL))),
            "the mid-chain screen refuses the same defect"
        );
        assert!(
            mid.was_refused(),
            "a mid-chain refusal must not read as the kernel's verdict"
        );
    }

    /// The other entry screens answer the same way `open_chain`'s do:
    /// inline, `EINVAL`, marked as this crate's. One test per method
    /// with a screen, so a new screen added to any of them without an
    /// answer shows up as an unfired callback here.
    #[test]
    fn every_entry_screen_answers_instead_of_dropping() {
        let (mut eng, mut fs, me) = setup();
        let dir = nested();
        let at = Anchor::open(dir.path()).expect("anchor");

        let refused = |what: &str, got: Rc<RefCell<Option<FsDone>>>| {
            let done = got
                .borrow_mut()
                .take()
                .unwrap_or_else(|| panic!("{what}: the refusal was dropped"));
            assert!(
                matches!(
                    done.result(),
                    Err(crate::Error::Errno(Errno::EINVAL))
                ) && done.was_refused(),
                "{what}: {:?} refused={}",
                done.result(),
                done.was_refused()
            );
        };

        let mut c = FsConn::new(&mut fs, &mut eng, OWNER0);
        for (what, path) in [
            ("an absolute open", c"/etc/hostname"),
            ("an empty open", c""),
        ] {
            let got: Rc<RefCell<Option<FsDone>>> = Rc::new(RefCell::new(None));
            let g2 = got.clone();
            c.open(
                me,
                &at,
                path,
                OpenHow::new().flags(OFlag::O_RDONLY),
                move |res, _c| *g2.borrow_mut() = Some(res),
            );
            refused(what, got);
        }

        for (what, path, how) in [
            (
                "a mkdir_path with ..",
                c"a/../b",
                OpenHow::new().flags(OFlag::O_RDONLY),
            ),
            (
                "a creating mkdir_path",
                c"a/b",
                OpenHow::new().flags(OFlag::O_RDONLY | OFlag::O_CREAT),
            ),
            (
                "a root-scoped mkdir_path",
                c"a/b",
                OpenHow::new()
                    .flags(OFlag::O_RDONLY)
                    .resolve(crate::sync_fs::ResolveFlag::RESOLVE_IN_ROOT),
            ),
        ] {
            let got: Rc<RefCell<Option<FsDone>>> = Rc::new(RefCell::new(None));
            let g2 = got.clone();
            c.mkdir_path(
                me,
                &at,
                path,
                Mode::from_bits_truncate(0o755),
                how,
                move |res, _c| *g2.borrow_mut() = Some(res),
            );
            refused(what, got);
        }

        let got: Rc<RefCell<Option<FsDone>>> = Rc::new(RefCell::new(None));
        let g2 = got.clone();
        c.symlinkat(
            me,
            c"",
            &at,
            Leaf::new("l").expect("leaf"),
            move |res, _c| *g2.borrow_mut() = Some(res),
        );
        refused("an empty symlink target", got);
        assert!(!dir.path().join("l").exists(), "nothing was created");
    }

    /// Every refusal is judged on shape at entry, before anything is
    /// submitted, so a bad argument cannot leave a half-walked chain -
    /// and each answers `on_done` with the marked `EINVAL` before
    /// `open_chain` returns, rather than dropping it. A dropped
    /// callback closes the connection, which turns a caller bug into a
    /// shed peer; and the awaited form aside, a plain-callback caller
    /// had no way to hear the refusal at all.
    #[test]
    fn a_chain_that_cannot_be_walked_is_refused_before_it_starts() {
        let (mut eng, mut fs, me) = setup();
        let dir = nested();
        let at = Anchor::open(dir.path()).expect("anchor");
        let dirstep = |how: OpenHow| OpenStep {
            path: StepPath::Fixed(c"a".to_owned()),
            who: me,
            how,
        };
        let plain = || OpenHow::new().flags(OFlag::O_RDONLY);
        let cases: Vec<(&str, Vec<OpenStep>)> = vec![
            ("no steps", Vec::new()),
            (
                // Nothing has been opened, so there is nothing to
                // derive a name from.
                "a first step that derives",
                vec![OpenStep {
                    path: StepPath::Derived(Box::new(|_| Ok(c"a".to_owned()))),
                    who: me,
                    how: plain(),
                }],
            ),
            (
                "an escaping component",
                vec![
                    dirstep(plain()),
                    OpenStep {
                        path: StepPath::Fixed(c"../escape".to_owned()),
                        who: me,
                        how: plain(),
                    },
                ],
            ),
            (
                // `chain` unions RESOLVE_BENEATH, and the kernel
                // refuses the pair ("Scoping flags are mutually
                // exclusive", `fs/open.c:1263-1265`) - so every step
                // would answer EINVAL, blaming the kernel for a bit
                // this crate added.
                "a step scoped to a root",
                vec![
                    dirstep(
                        plain().resolve(
                            crate::sync_fs::ResolveFlag::RESOLVE_IN_ROOT,
                        ),
                    ),
                    dirstep(plain()),
                ],
            ),
            (
                // A create at an intermediate would be left behind by a
                // later step's failure.
                "a creating step",
                vec![
                    dirstep(plain()),
                    OpenStep {
                        path: StepPath::Fixed(c"made".to_owned()),
                        who: me,
                        how: OpenHow::new()
                            .flags(OFlag::O_RDONLY | OFlag::O_CREAT),
                    },
                ],
            ),
        ];
        for (what, steps) in cases {
            let fired: Rc<RefCell<Option<FsDone>>> =
                Rc::new(RefCell::new(None));
            let f2 = fired.clone();
            {
                let mut c = FsConn::new(&mut fs, &mut eng, OWNER0);
                c.open_chain(&at, steps, move |res, _c| {
                    *f2.borrow_mut() = Some(res);
                });
            }
            // Inline: the refusal is answered before `open_chain`
            // returned, with nothing driven - which is also what pins
            // that nothing was submitted.
            let done = fired
                .borrow_mut()
                .take()
                .unwrap_or_else(|| panic!("{what}: the refusal was dropped"));
            assert!(
                matches!(
                    done.result(),
                    Err(crate::Error::Errno(Errno::EINVAL))
                ),
                "{what}: wrong errno {:?}",
                done.result()
            );
            assert!(done.was_refused(), "{what}: the crate's own verdict");
        }
        assert!(
            !dir.path().join("a/made").exists(),
            "a refused chain creates nothing"
        );
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
    // The kernel-internal restart codes, which io_uring folds to
    // `-EINTR` for reads and writes (`io_fixup_restart_res`,
    // `io_uring/rw.c` - "Just fail this IO with EINTR") but posts
    // verbatim for opens and splices, where the fixup is not applied.
    // A cancelled `SpecialFiles::Allow` open blocked in `fifo_open`
    // surfaces `-ERESTARTSYS` this way; unmapped it decodes as
    // `UnknownErrno`, and one teardown sweep then yields two different
    // errnos depending on where each op was parked. Folded here, once,
    // so every fs op behaves as the kernel's own rw path does. The
    // stream domain's splice does the same by hand
    // (`net/core/reactor/io.rs`).
    // Exactly the four the kernel names - 515 between them is
    // `ENOIOCTLCMD`, not a restart code.
    if matches!(res, -512 | -513 | -514 | -516) {
        return Err(Errno::EINTR);
    }
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
    refused: bool,
) {
    match waiter {
        // A refusal is *not* marked on the way out here, and the
        // asymmetry with the arm below is deliberate rather than
        // missed. The blocking path's public signatures return
        // `crate::Result`, so there is nowhere to put the bit without
        // redesigning them; `FsHandle::path_op` carries the rule a
        // caller needs instead, and names the facade path that does
        // report provenance. Surface it here the day a channel
        // consumer can act on it.
        Some(FsWaiter::Channel(tx)) => {
            let _ = tx.send(FsOutcome::new(res, bufs, file, stat));
        }
        // Submission failure / teardown of an embedded op: drop the callback
        // unfired - dropping the continuation it captured closes the
        // connection (see [`EmbeddedCb`]). Nothing else routes it.
        Some(FsWaiter::Embedded { cb, on_fail, .. }) => {
            // A refusal reports its reason and hands the payload back; a
            // teardown reports neither, which is what keeps `ECANCELED`
            // meaning teardown alone. The callback goes unfired either
            // way, as its contract says - the sink fills a slot and runs
            // no consumer code, so this is not an inline delivery.
            if let (true, Some(sink), Err(errno)) = (refused, &on_fail, res) {
                sink(errno, bufs);
            } else {
                drop(bufs);
            }
            drop((cb, on_fail, file, stat));
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
/// owner-scoped [`FsConn`]. Shared by the host and the net server so the
/// wake-drain is written once.
pub(crate) fn deliver_pool_completions(fs: &mut FsCore, eng: &mut Engine) {
    // Tasks woken by these deliveries - or poked from off-loop, which
    // lands on the same wake the pool uses - run in this dispatch, and
    // an on-loop wake inside it needs no poke to say so.
    super::task::in_pass(fs, eng, |fs, eng| {
        for (owner, deliver, any) in fs.take_pool_completions() {
            let mut conn = FsConn::new(fs, eng, owner);
            deliver(any, &mut conn);
        }
    });
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
) {
    // A completion that resolves an op future wakes its task from
    // inside the callback below; the drain that follows polls it, so
    // the wake needs no poke to reach the loop. See `task::in_pass`.
    super::task::in_pass(fs, eng, move |fs, eng| match reaped {
        ReapedFs::Embedded(cb, done, owner) => {
            let mut conn = FsConn::new(fs, eng, owner);
            cb(done, &mut conn);
        }
        ReapedFs::Pump(..) => {
            unreachable!("pump reads are routed by the net server")
        }
        ReapedFs::None => {}
    });
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
    /// integration suites' io_uring guard, gate included).
    fn engine_or_skip() -> Option<Engine> {
        match Engine::new(RING_ENTRIES, POOL) {
            Ok(e) => Some(e),
            Err(crate::Error::Errno(e))
                if crate::uring::setup_unavailable(e) =>
            {
                None
            }
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

    /// A tag with no arm must be refused before an SQE is filled.
    ///
    /// `fill_sqe` zeroes the slot, and opcode 0 is `IORING_OP_NOP` (first in
    /// the kernel's `enum io_uring_op`). A fall-through therefore submitted a
    /// NOP carrying the op's real `user_data`: it completes `res = 0`, and
    /// `map_res` turns that into `Ok(0)` - an `FSETXATTR` of a `trusted.*`
    /// record reported as done that never ran. The debug half is the
    /// `debug_assert!(false)`; this is the half that ships.
    #[cfg(not(debug_assertions))]
    #[test]
    fn an_unknown_tag_is_refused_rather_than_staged_as_a_nop() {
        let Some(mut eng) = engine_or_skip() else {
            return;
        };
        let mut core = FsCore::new(8, OffloadBounds::default());
        let before = snapshot(&core);

        let fd = synth_fd();
        // SAFETY: `synth_fd` just opened it; nothing else owns it.
        let file = Arc::new(unsafe { crate::fd::owned_from_raw(fd) });
        let (tx, rx) = mpsc::channel();
        core.submit_fd_meta(
            &mut eng,
            0x7F, // no arm in either match
            1,
            file,
            None,
            vec![1, 2, 3],
            0,
            0,
            0,
            chan(&tx),
        );
        let out = rx.try_recv().expect("refusal is delivered, not dropped");
        assert_eq!(out.res, Err(Errno::EINVAL));
        assert_eq!(out.bufs, vec![vec![1u8, 2, 3]], "the value comes back");

        let (tx2, rx2) = mpsc::channel();
        core.submit_path_op(
            &mut eng,
            0x7E,
            1,
            Anchor::open("/").expect("anchor /"),
            CString::new("x").unwrap(),
            None,
            None,
            0,
            0,
            chan(&tx2),
        );
        assert_eq!(rx2.try_recv().expect("delivered").res, Err(Errno::EINVAL));

        assert!(inflight(&core).is_empty(), "nothing was staged");
        assert_eq!(snapshot(&core), before, "no op slot was consumed");
    }

    /// The debug half of the guard above: the same call trips the
    /// `debug_assert!(false)` rather than reaching the refusal.
    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "not an fd-meta tag")]
    fn an_unknown_tag_asserts_in_debug() {
        let Some(mut eng) = engine_or_skip() else {
            // A `should_panic` test cannot skip; panic with the expected
            // message so an unavailable ring does not read as a regression.
            panic!("not an fd-meta tag (io_uring unavailable: skipped)");
        };
        let mut core = FsCore::new(8, OffloadBounds::default());
        let fd = synth_fd();
        // SAFETY: `synth_fd` just opened it; nothing else owns it.
        let file = Arc::new(unsafe { crate::fd::owned_from_raw(fd) });
        let (tx, _rx) = mpsc::channel();
        core.submit_fd_meta(
            &mut eng,
            0x7F,
            1,
            file,
            None,
            Vec::new(),
            0,
            0,
            0,
            chan(&tx),
        );
    }

    /// A short leased write must not look like success: its source is the
    /// connection's receive buffer, already on its way back to the pool by
    /// the time any caller could react, so `Ok(n)` would invite a retry
    /// from bytes that may hold another connection's request - and a
    /// caller that shrugged would store a truncated object. ZFS returns
    /// partial writes as successes by design (`zfs_write`,
    /// `module/zfs/zfs_vnops.c:1085-1094`), so the case is real, and the
    /// reap is the one place that still knows both the asked-for and the
    /// written count.
    #[cfg(feature = "net-server")]
    #[test]
    fn a_short_leased_write_is_an_error() {
        let Some(mut eng) = engine_or_skip() else {
            return;
        };
        let mut core = FsCore::new(8, OffloadBounds::default());
        let buf = vec![7u8; 8192];
        let fd = synth_fd();
        // SAFETY: `synth_fd` just opened it; nothing else owns it.
        let file = Arc::new(unsafe { crate::fd::owned_from_raw(fd) });

        // Short: the kernel wrote less than the lease asked for.
        let (tx, rx) = mpsc::channel();
        let staged = core.submit_pwritev2_leased(
            &mut eng,
            0,
            Arc::clone(&file),
            buf.as_ptr(),
            buf.len(),
            0,
            0,
            std::sync::Arc::new(LeaseHold(9)),
            chan(&tx),
        );
        assert!(staged.is_ok(), "staged");
        let [(t, s, g)] = inflight(&core)[..] else {
            panic!("one op in flight");
        };
        let _ = core.on_cqe(&mut eng, t, s, g, 4096);
        let out = rx.try_recv().expect("delivered");
        assert_eq!(
            out.res,
            Err(Errno::EIO),
            "a short leased write surfaced as success"
        );

        // Full: the same submit at the written size is an ordinary success.
        let (tx, rx) = mpsc::channel();
        let staged = core.submit_pwritev2_leased(
            &mut eng,
            0,
            file,
            buf.as_ptr(),
            buf.len(),
            0,
            0,
            std::sync::Arc::new(LeaseHold(9)),
            chan(&tx),
        );
        assert!(staged.is_ok(), "staged");
        let [(t, s, g)] = inflight(&core)[..] else {
            panic!("one op in flight");
        };
        let _ = core.on_cqe(&mut eng, t, s, g, 8192);
        let out = rx.try_recv().expect("delivered");
        assert_eq!(out.res, Ok(8192), "a full leased write is untouched");
    }

    /// N writes share one claim; the buffer surfaces from the last.
    ///
    /// Two leased writes read from one buffer, so releasing at the first
    /// completion re-posts it while the sibling's DMA still reads it. The
    /// id must ride out of exactly one completion - whichever drops the
    /// last share - and a short write still fails its own op alone,
    /// whether or not it is the one that releases.
    #[cfg(feature = "net-server")]
    #[test]
    fn the_last_shared_lease_releases_the_buffer() {
        let Some(mut eng) = engine_or_skip() else {
            return;
        };
        let mut core = FsCore::new(8, OffloadBounds::default());
        let buf = vec![7u8; 8192];
        let fd = synth_fd();
        // SAFETY: `synth_fd` just opened it; nothing else owns it.
        let file = Arc::new(unsafe { crate::fd::owned_from_raw(fd) });
        let hold = std::sync::Arc::new(LeaseHold(9));

        for off in [0u64, 4096] {
            let staged = core.submit_pwritev2_leased(
                &mut eng,
                0,
                Arc::clone(&file),
                // SAFETY: within `buf`, which outlives both submissions.
                unsafe { buf.as_ptr().add(off as usize) },
                4096,
                off,
                0,
                std::sync::Arc::clone(&hold),
                // No facade here, so no sink to arm from; every
                // shipping submission goes through `FsConn::waiter`.
                FsWaiter::Embedded {
                    owner: Some((0, 0)),
                    cb: Box::new(|_d, _fs| {}),
                    on_fail: None,
                },
            );
            assert!(staged.is_ok(), "staged");
        }
        drop(hold); // as the facade does: only the ops hold shares now

        let mut flight = inflight(&core);
        flight.sort();
        let [(ta, sa, ga), (tb, sb, gb)] = flight[..] else {
            panic!("two ops in flight");
        };
        // First completion: SHORT. Its op fails EIO; the buffer is
        // withheld because a sibling still reads it.
        let ReapedFs::Embedded(_, mut a, _) =
            core.on_cqe(&mut eng, ta, sa, ga, 100)
        else {
            panic!("an embedded waiter reaps embedded");
        };
        assert!(
            matches!(a.result(), Err(crate::Error::Errno(Errno::EIO))),
            "short fails its own op"
        );
        assert_eq!(
            a.take_recv_lease(),
            None,
            "the buffer must not come back while a sibling reads it"
        );
        // Last completion: full. Its op succeeds and carries the id out.
        let ReapedFs::Embedded(_, mut b, _) =
            core.on_cqe(&mut eng, tb, sb, gb, 4096)
        else {
            panic!("an embedded waiter reaps embedded");
        };
        assert_eq!(b.result().ok(), Some(4096), "the sibling is unaffected");
        assert_eq!(
            b.take_recv_lease(),
            Some(9),
            "the last share surfaces the id exactly once"
        );
    }

    /// The teardown drain answers a short leased write the same way the
    /// live reap does.
    ///
    /// The reason does not soften at shutdown: the write's source was the
    /// connection's receive buffer, so a caller handed `Ok(n)` cannot retry
    /// from bytes it no longer owns, and one that shrugs stores a truncated
    /// object. The drain is the only other path a leased completion can
    /// take.
    #[cfg(feature = "net-server")]
    #[test]
    fn a_drained_short_leased_write_is_an_error() {
        let Some(mut eng) = engine_or_skip() else {
            return;
        };
        let mut core = FsCore::new(8, OffloadBounds::default());
        let buf = vec![7u8; 8192];
        let fd = synth_fd();
        // SAFETY: `synth_fd` just opened it; nothing else owns it.
        let file = Arc::new(unsafe { crate::fd::owned_from_raw(fd) });
        let (tx, rx) = mpsc::channel();
        let staged = core.submit_pwritev2_leased(
            &mut eng,
            0,
            file,
            buf.as_ptr(),
            buf.len(),
            0,
            0,
            std::sync::Arc::new(LeaseHold(9)),
            chan(&tx),
        );
        assert!(staged.is_ok(), "staged");
        let [(t, s, g)] = inflight(&core)[..] else {
            panic!("one op in flight");
        };
        let cqe = IoUringCqe {
            user_data: pack_raw(t, s, g),
            res: 4096, // short of the 8192 the lease asked for
            flags: 0,
        };
        core.on_drain_cqe(&cqe);
        let out = rx.try_recv().expect("delivered");
        assert_eq!(
            out.res,
            Err(Errno::EIO),
            "a short leased write survived the drain as a success"
        );
    }

    /// Teardown's drain owns the fd a successful open completes with.
    ///
    /// The fd arrives in `cqe.res` and nothing parked owns it - the live
    /// path is what wraps the result - so a drain that delivers the raw
    /// count leaks the descriptor: the waiter is usually already gone at
    /// teardown, and a number nobody owns is closed by nobody.
    #[test]
    fn a_drained_open_owns_its_fd() {
        let Some(mut eng) = engine_or_skip() else {
            return;
        };
        let mut core = FsCore::new(8, OffloadBounds::default());
        let fd = synth_fd();
        // SAFETY: `synth_fd` just opened it; nothing else owns it.
        let file = Arc::new(unsafe { crate::fd::owned_from_raw(fd) });
        let (tx, rx) = mpsc::channel();
        core.submit_fsync(&mut eng, 0, file, false, 0, 0, chan(&tx));
        let [(_, s, g)] = inflight(&core)[..] else {
            panic!("one op in flight");
        };
        // Re-tag the staged op as the OPEN whose completion carries an fd;
        // the drain path reads only the tag and the result.
        core.ops[s as usize].state.state =
            FsOpState::InFlight { tag: TAG_OPEN };
        let opened = synth_fd();
        drop(rx); // as at teardown: nobody is left to take the outcome
        let cqe = IoUringCqe {
            user_data: pack_raw(TAG_OPEN, s, g),
            res: opened,
            flags: 0,
        };
        core.on_drain_cqe(&cqe);
        // With no receiver, the owned file had nowhere to land, so its drop
        // must have closed the descriptor rather than leaking it.
        // SAFETY: `fcntl(F_GETFD)` probes a descriptor number, reads nothing.
        let rc = unsafe { libc::fcntl(opened, libc::F_GETFD) };
        assert_eq!(rc, -1, "the drained open's fd was closed, not leaked");
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
                    false,
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
            PumpDest::Owned(Vec::with_capacity(8)),
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
                PumpDest::Owned(Vec::with_capacity(4)),
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

    /// The kernel-internal restart codes decode as `EINTR`, the way
    /// io_uring's own rw path folds them (`io_fixup_restart_res`,
    /// `io_uring/rw.c`), and the codes between and around them stay
    /// themselves.
    #[test]
    fn restart_codes_fold_to_eintr_like_the_kernels_rw_path() {
        for res in [-512, -513, -514, -516] {
            assert_eq!(map_res(res), Err(Errno::EINTR), "res {res}");
        }
        // 515 is ENOIOCTLCMD, not a restart code; a range would eat it.
        assert_eq!(map_res(-515), Err(Errno::from_raw(515)));
        assert_eq!(map_res(-libc::ECANCELED), Err(Errno::ECANCELED));
        assert_eq!(map_res(7), Ok(7));
    }

    /// The sweep leaves a signal behind, because it cannot leave a
    /// gate behind.
    ///
    /// It runs once per close and a continuation woken by one of its
    /// own cancellations submits after it, so nothing stops a task
    /// whose awaits cannot fail - an offload always delivers, a timer
    /// armed afterwards expires normally - from running for a
    /// connection that is gone. `owner_is_gone` is what such a task
    /// asks, and it must answer for the swept tenant of a slot without
    /// answering for the next one to take it.
    #[test]
    fn a_swept_owner_is_visible_to_what_runs_after_the_sweep() {
        let Some(mut eng) = engine_or_skip() else {
            return;
        };
        let mut core = FsCore::new(4, OffloadBounds::default());
        let gone = (7u32, 3u64);

        assert!(!core.owner_is_gone(Some(gone)), "nothing swept yet");
        core.cancel_owned_by(&mut eng, vec![gone]);
        assert!(core.owner_is_gone(Some(gone)), "the swept owner is gone");

        // A slot is reused, and its next tenant is not the one swept.
        assert!(
            !core.owner_is_gone(Some((gone.0, gone.1 + 1))),
            "a later tenant of the same slot is live"
        );
        // Every earlier tenant closed before this one did.
        assert!(
            core.owner_is_gone(Some((gone.0, gone.1 - 1))),
            "a tenant before the swept one is gone too"
        );
        assert!(!core.owner_is_gone(Some((8, 3))), "another slot is its own");
        assert!(
            !core.owner_is_gone(None),
            "a reactor with no owners has no connection to lose"
        );

        // And the facade a continuation is handed reads it.
        let conn = FsConn::new(&mut core, &mut eng, Some(gone));
        assert!(conn.owner_is_gone(), "the continuation facade answers");
    }

    /// One sweep reaches every closed owner's ops, and an idle table
    /// costs nothing to sweep.
    ///
    /// A close is recorded whether or not the handler opened anything,
    /// so on a busy server the batch is ordinary and the table is
    /// `fs_ops + pool_size` deep - 28k+ entries at a real consumer's
    /// configuration. Per-owner scanning walked all of it once per
    /// close, on the reactor thread.
    #[test]
    fn one_sweep_covers_the_batch_and_an_idle_table_is_free() {
        let Some(mut eng) = engine_or_skip() else {
            return;
        };
        let mut core = FsCore::new(8, OffloadBounds::default());
        let all_free = core.op_free_len_for_test();

        // Nothing in flight: the sweep records and returns.
        core.cancel_owned_by(&mut eng, vec![(1, 1), (2, 1), (3, 1)]);
        assert!(core.owner_is_gone(Some((2, 1))), "recorded regardless");
        assert_eq!(core.op_free_len_for_test(), all_free, "nothing taken");

        // Four owners with a parked pipe read each: only a cancel can
        // complete one, so what is left in flight names the batch.
        let mut fds = [0i32; 2];
        // SAFETY: `pipe(2)` fills {read, write}.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe");
        // SAFETY: the fresh read end, owned here; the write end stays
        // open so no read EOFs, and both close with the process.
        let file =
            File::new(Arc::new(unsafe { crate::fd::owned_from_raw(fds[0]) }));
        let owners = [(10u32, 1u64), (11, 1), (12, 1), (13, 1)];
        for o in owners {
            core.submit_pump_read(
                &mut eng,
                &file,
                PumpDest::Owned(Vec::with_capacity(8)),
                8,
                u64::MAX,
                o,
            )
            .expect("submit");
        }
        assert_eq!(inflight(&core).len(), 4, "four parked reads");

        // One call for three of them; the fourth is untouched.
        core.cancel_owned_by(&mut eng, vec![(10, 1), (11, 1), (12, 1)]);
        let deadline =
            std::time::Instant::now() + std::time::Duration::from_secs(10);
        let mut reaped = Vec::new();
        while reaped.len() < 3 {
            assert!(
                std::time::Instant::now() < deadline,
                "one sweep did not reach the whole batch: {reaped:?}"
            );
            eng.ring.submit().expect("submit");
            let Some(cqe) = eng.ring.reap() else {
                std::thread::sleep(std::time::Duration::from_millis(1));
                continue;
            };
            let (tag, slot, g) = unpack_raw(cqe.user_data);
            if let ReapedFs::Pump(_, owner) =
                core.on_cqe(&mut eng, tag, slot, g, cqe.res)
            {
                reaped.push(owner);
            }
        }
        reaped.sort_unstable();
        assert_eq!(
            reaped,
            vec![(10, 1), (11, 1), (12, 1)],
            "exactly the batch"
        );
        assert_eq!(inflight(&core).len(), 1, "the owner outside it stays");
        assert!(
            core.owner_is_gone(Some((11, 1)))
                && !core.owner_is_gone(Some((13, 1))),
            "and the record is exactly the batch too"
        );
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
            PumpDest::Owned(Vec::with_capacity(8)),
            8,
            u64::MAX,
            (5, 9),
        )
        .expect("submit");
        assert_eq!(Arc::strong_count(&file.fd), 2, "op parks its clone");
        core.cancel_owned_by(&mut eng, vec![(5, 9)]);

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
                    finish_offload(&s, &w, token, Box::new(token));
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
                finish_offload(&s, &w, token, Box::new(()));
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
