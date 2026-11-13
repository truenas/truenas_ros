//! The fs core: the op table (owner of every kernel-visible payload from submission to completion), plain
//! reference-counted file descriptors (`File = Arc<OwnedFd>`, close-last by ownership), the SQE builders, and
//! completion routing. A host owns the engine and drives this -- [`super::UringFs`] standalone, or a `net` server
//! sharing its ring (which is also what [`FsConn`] submits through).
//!
//! Invariants:
//!
//! - **The kernel must never touch freed memory.** Buffers, iovec arrays, paths, `open_how` pads, and anchor dirfds
//!   live in the op entry from submission until the CQE reaps - even when the caller lost interest.
//! - **Close-last by ownership.** An open returns an `Arc<OwnedFd>`; each op in flight against it parks its own clone
//!   in the op entry until that op's CQE, so the fd closes only when the last reference - the caller's handle and every
//!   in-flight op - drops. No explicit close op, no reusable slot index.
//! - **Op-slot generations make stale completions inert.** `user_data` packs `(tag, op-slot, generation)`; an op entry
//!   frees only at its own single terminal CQE, so a stale / duplicate / wrong-tag completion is rejected.

use super::file_lease::{FileLeaseId, FileLeases};
use super::offload_pool::{FILE_WORKER, Job, LOOKUP_WORKER, OffloadBounds, SharedPool};
use super::{
    Anchor, CONFINED_RESOLVE, File, FsOutcome, Leaf, Personality, PrivilegedXattrs, ReopenAccess, ReplyTo, RwFlags,
    statx_at_flags,
};
use crate::errno::{Errno, retry_on_eintr};
use crate::sync_fs::openat2::RawOpenHow;
use crate::sync_fs::{
    AtFlags, Mode, OFlag, OpenHow, RenameFlags, Statfs, Statx, StatxMask, StatxRaw, ZFS_SETATTR, ZfsAttr, ZfsSetattr,
};
use crate::uring::engine::Engine;
use crate::uring::force_async::ForceAsync;
use crate::uring::slots::SlotEntry;
use crate::uring::sys::KernelTimespec;
use crate::uring::sys::{
    IORING_FSYNC_DATASYNC, IORING_OP_ASYNC_CANCEL, IORING_OP_FADVISE, IORING_OP_FALLOCATE, IORING_OP_FGETXATTR,
    IORING_OP_FSETXATTR, IORING_OP_FSYNC, IORING_OP_FTRUNCATE, IORING_OP_GETXATTR, IORING_OP_LINKAT, IORING_OP_MKDIRAT,
    IORING_OP_OPENAT2, IORING_OP_READ, IORING_OP_READV, IORING_OP_RENAMEAT, IORING_OP_SPLICE, IORING_OP_STATX,
    IORING_OP_SYMLINKAT, IORING_OP_TIMEOUT, IORING_OP_UNLINKAT, IORING_OP_WRITE, IORING_OP_WRITEV, IOSQE_ASYNC,
    IOSQE_BUFFER_SELECT, IoUringCqe, SPLICE_F_MOVE,
};
use crate::uring::user_data::{pack_raw, unpack_raw};
use std::any::Any;
use std::borrow::Cow;
use std::cell::Cell;
use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::ffi::{CStr, CString};
use std::mem::size_of;
use std::ops::Range;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::rc::Rc;
// The offload sink and the `DIR*` handoff are loom-modelled (see `loom_tests` at the bottom), so these come from
// `crate::sync` - std's outside `--cfg loom`.
use super::CONFINEMENT_POLICY;
use super::FsOpenHow;
use super::SpecialFiles;
use super::apply_special_file_guard;
use super::confine_resolve;
use super::file_lease;
use super::query_dir;
use super::scoping_conflict;
use super::task;
use crate::sync::{Arc, Mutex};
use done::deliver;
pub(crate) use done::{deliver_embedded, deliver_pool_completions, drain_stop_window};
use std::thread;

/// Default warm floor of worker threads backing [`FsConn::offload`]. The pool is spawned on first use and grows to
/// [`OFFLOAD_CEILING`] under saturation.
///
/// Four, so a small burst of concurrent listings does not wait on a thread spawn, as growth is limited to one worker
/// per millisecond.
pub(crate) const OFFLOAD_FLOOR: usize = 4;
/// Default ceiling the offload pool grows to under sustained blocking work (opcode-less `readdir`/`fdopendir`/copy).
///
/// Generous on purpose, since it caps how many stalled operations one ring absorbs before they queue behind each other,
/// and a stalled `readdir` against a cold NFS or FUSE backing can take seconds. Only the floor is resident, and a burst
/// worker retires once it has sat idle for `OFFLOAD_IDLE_TIMEOUT`, so bursts that recur inside that window hold the
/// recent peak of workers.
///
/// Every bound here is per ring, and a deployment running several sizes them through
/// [`OffloadBounds`](crate::uring_fs::OffloadBounds).
pub(crate) const OFFLOAD_CEILING: usize = 64;
/// Default warm floor of the lookup lane ([`FsConn::offload_lookup`]). One, since a lookup answered from a cache or a
/// local file is quick, and the lane is there for the ones that wait.
pub(crate) const LOOKUP_FLOOR: usize = 1;
/// Default ceiling of the lookup lane, the same as [`OFFLOAD_CEILING`]. A job there may wait as long as a remote
/// service's timeouts allow, holding a socket all the while, so this bounds the sockets as well as the threads.
pub(crate) const LOOKUP_CEILING: usize = 64;
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
/// The guard timer riding an `Allow` open (`super::SpecialFiles`). An ordinary `IORING_OP_TIMEOUT` in its own op slot
/// whose expiry stages an `ASYNC_CANCEL` for the open, and which the open's own completion retracts.
///
/// Not a kernel `LINK_TIMEOUT`, which `io_queue_linked_timeout` arms only after `def->issue` returns
/// (`io_uring/io_uring.c:1850-1866`). A force-async open's one issue is the blocking one on io-wq
/// (`io_queue_sqe_fallback` -> `io_queue_iowq`), so a linked deadline would be armed only after the block ends.
/// `ASYNC_CANCEL` reaches the parked worker as a signal (`io_wq_worker_cancel` -> `__set_notify_signal`).
///
/// Routed by its own arm in [`FsCore::on_cqe`], with no consumer callback and no owner, since the open's waiter carries
/// both.
pub(crate) const TAG_OPEN_DEADLINE: u8 = 0x93;
/// `GETXATTR` of a held file through its path under `/proc/thread-self/fd`, which takes a file opened `O_PATH`.
pub(crate) const TAG_GETXATTR_PROC: u8 = 0x94;
/// `READ` into the room past the length of one buffer ([`FsConn::pread_spare`]). The buffer rides in the slot's
/// `value`, as an xattr op's does, and [`FsCore::on_cqe`] grows its length by what the kernel wrote.
pub(crate) const TAG_READ_SPARE: u8 = 0x95;
/// The poll of the signalfd the breaks of the ring's file leases arrive on ([`FileLeases`]). It holds no op slot, since
/// the ring has one at most.
pub(crate) const TAG_FILE_LEASE: u8 = 0x96;
/// `WRITE` of a range of one buffer ([`FsConn::pwritev2_owned`]). The buffer rides in the slot's `value`, as a read
/// into spare room's does, and comes back whole whatever the kernel answers.
pub(crate) const TAG_WRITE_OWNED: u8 = 0x97;
/// The standalone host's wake tag (an embedded host reuses its own).
pub(crate) const TAG_WAKE: u8 = 0x9D;
/// Tags `ASYNC_CANCEL` ops (and the teardown drain); completions ignored.
pub(crate) const TAG_CANCEL: u8 = 0x9E;

/// A completed embedded op's callback, fired on the loop thread by the embedding host (a `net` server) with the outcome
/// and a fresh [`FsConn`] for chaining. It fires inline at the completion's dispatch, or at the wake drain for a host
/// refusal ([`FsCore::refuse`]). Only the teardown drain drops it unfired, which drops the captured continuation and so
/// closes the connection.
pub(crate) type EmbeddedCb = Box<dyn FnOnce(FsDone, &mut FsConn<'_>)>;

/// Where an op that never reached the ring reports why, and hands back what it was given.
///
/// A sink runs no continuation and submits nothing, it only fills a slot, so it can fire from inside a `submit_*`
/// holding `&mut self` on the fs tables, where a callback cannot. That lets an awaited frame see the reason (`EBUSY`
/// retry, `EINVAL` caller bug, teardown stop) when the refusal is decided.
///
/// It carries the reason only. A marked refusal is queued whole ([`FsCore::refuse`]) and its delivery supersedes the
/// parked reason, so the sink gets an empty payload and [`FsDone::into_bufs`] hands the real one back.
///
/// An `Rc`, cloned rather than taken, since a multi-step call ([`chain`], [`walk`]) submits from a fresh facade at
/// every step after the first, and a sink the first step consumed would have every later step report teardown for a
/// refusal worth retrying. The slot's rule that a real answer is final makes more than one filler safe.
pub(crate) type FailSink = Rc<SinkInner>;

/// A staged reason sink and the frame flag that meters arms of it, in one allocation since both exist per
/// [`FsConn::fut`] frame.
pub(crate) struct SinkInner<F: ?Sized = dyn Fn(Errno, Vec<Vec<u8>>)> {
    /// Whether a submission in the watching frame has taken the share. Set by the first [`armed::arm`] under
    /// [`FsConn::fut`]'s frame and read back by [`FsConn::restore_fail_sink`]. Shared by every clone of the sink `Rc`,
    /// so an arm made through a [`FsConn::reborrow`] reaches the watching frame.
    armed: Cell<bool>,
    fill: F,
}

impl<F: Fn(Errno, Vec<Vec<u8>>)> SinkInner<F> {
    pub(crate) fn new(fill: F) -> SinkInner<F> {
        SinkInner {
            armed: Cell::new(false),
            fill,
        }
    }
}

/// An opaque per-op owner tag, the embedding host's connection identity `(slot, generation)`, threaded through so a
/// chained callback runs under the same connection. The core uses it only as a key, to sweep a closed connection's ops
/// and to meter its wall-clock holds. `None` on the off-loop channel path.
pub(crate) type Owner = Option<(u32, u64)>;

/// Where a completed fs op's outcome goes: back over a channel to an off-loop [`FsHandle`](super::FsHandle) caller, or
/// into an in-loop callback the embedding host (a `net` server) fires on the reactor thread.
pub(crate) enum FsWaiter {
    Channel(ReplyTo),
    #[cfg_attr(not(feature = "net-server"), allow(dead_code))]
    Embedded {
        owner: Owner,
        cb: EmbeddedCb,
        /// The reason-sink share [`armed::arm`] took, `None` for a plain callback, whose contract is that a drop closes
        /// the connection. The wrapper makes hand-building this variant a build failure (see [`armed`]).
        on_fail: armed::Armed,
    },
    /// A reactor-pump read (a `net` server streaming a file into a response body), with no callback. [`FsCore::on_cqe`]
    /// hands the outcome back as [`ReapedFs::Pump`] for the host to route to the owning connection. Cancelled by owner
    /// like `Embedded`, so connection teardown reaches an in-flight body read.
    #[cfg_attr(not(feature = "net-server"), allow(dead_code))]
    Pump {
        owner: (u32, u64),
    },
}

/// The one producer of an [`FsWaiter::Embedded`]'s reason-sink share.
///
/// [`FsConn::fut`] tells an op in flight from one the facade refused by whether any submission armed the staged sink,
/// so a waiter built without arming makes `fut` answer a good op with a spurious `EINVAL`. [`Armed`]'s field is private
/// to this module, so a submit method cannot hand-build the waiter, and [`arm`] does the whole clone, double-arm check
/// and frame accounting.
mod armed {
    use super::{FailSink, FsConn};

    /// One submission's share of the staged reason sink.
    pub(crate) struct Armed(Option<FailSink>);

    impl Armed {
        /// Surrender the share for delivery ([`super::deliver`]).
        pub(super) fn take(self) -> Option<FailSink> {
            self.0
        }
    }

    /// Clone the staged sink and record the arm on the watching frame.
    ///
    /// One frame, one submission. The first arm inside a frame takes the share, and a later arm in the same frame gets
    /// an empty one, so its refusal is dropped unfired as a plain callback's is. It must not panic, in either build
    /// profile, since it runs inside dispatch on consumer input. `chain`/`walk` steps run on a fresh facade that
    /// watches no frame, so their shares stay real and a mid-chain refusal keeps its errno.
    ///
    /// Which share answers the frame is the slot's rule (`SlotState::Refused`, `task.rs`). A share's refusal parks
    /// provisionally and the submission carrying the frame's callback owns the outcome, so no refusal discards a real
    /// completion still in flight.
    pub(super) fn arm(conn: &mut FsConn<'_>) -> Armed {
        if conn.frame_watching
            && let Some(sink) = &conn.fail_sink
            && sink.armed.replace(true)
        {
            return Armed(None);
        }
        Armed(conn.fail_sink.clone())
    }

    /// A share that never arms, for driving the core without a facade. Gated exactly as its one caller (the
    /// leased-write reap test) is, so no feature subset sees a producer with nothing producing.
    #[cfg(all(test, not(loom), feature = "net-server"))]
    pub(super) fn unarmed() -> Armed {
        Armed(None)
    }
}

/// A routed fs-domain CQE, from [`FsCore::on_cqe`], for the host to act on once its borrow of the fs tables has ended.
pub(crate) enum ReapedFs {
    None,
    Embedded(EmbeddedCb, FsDone, Owner),
    #[cfg_attr(not(feature = "net-server"), allow(dead_code))]
    Pump(FsDone, (u32, u64)),
    /// File leases of the ring a break reached, for its handler.
    FileLeaseBreaks(Vec<FileLeaseId>),
}

/// `fremovexattr(2)` on `f`. Blocking, because io_uring has no remove opcode, and an `IORING_OP_FSETXATTR` with a
/// zero-length value does not remove. `__vfs_setxattr` (`fs/xattr.c`) substitutes an empty value for `size == 0`,
/// leaving an attribute that still lists.
fn remove_xattr_blocking(f: &File, name: &CStr) -> crate::Result<()> {
    let raw = f.as_raw_fd();
    // SAFETY: `f` is borrowed for the call, so `raw` is live; `name` is a NUL-terminated C string.
    retry_on_eintr(|| unsafe { libc::fremovexattr(raw, name.as_ptr()) })?;
    Ok(())
}

/// Room in an op slot for the name the kernel reads at prep: one component and its NUL, which `NAME_MAX` (255) bounds,
/// and so the path of any descriptor under `/proc/thread-self/fd` too.
const NAME_ROOM: usize = 256;

/// One in-flight (or free) fs operation. Owns everything the kernel can see.
struct FsOpEntry {
    state: FsOpState,
    waiter: Option<FsWaiter>,
    /// Owned data buffers: `READV` destinations / `WRITEV` sources.
    bufs: Vec<Vec<u8>>,
    /// The one buffer of an `FGETXATTR`, an `FSETXATTR`, a `GETXATTR` through `/proc`, a read into spare room or an
    /// owned write, on its own so the op builds no outer `Vec` for it. An `FGETXATTR`'s kernel writes land in it at
    /// issue time.
    value: Option<Vec<u8>>,
    /// The iovec array the SQE points at. Element pointers target `bufs`' heap allocations, which never move while
    /// parked here.
    iov: Vec<libc::iovec>,
    /// Primary path payload, the `OPENAT2` path, a `STATX`/directory-op leaf, an xattr name, or a symlink target. The
    /// SQE carries its address, so it must not move until the CQE reaps. A name that fits `name` goes there instead
    /// ([`FsOpEntry::park_name`]).
    path: Option<Cow<'static, CStr>>,
    /// The bytes of the op's name when it fits with its NUL, or the path of a descriptor under `/proc/thread-self/fd`.
    /// The kernel copies it at prep, inside the enter that submits the SQE, and the op table never grows after
    /// [`FsCore::new`], so this address holds however many stages batch before that enter.
    name: [u8; NAME_ROOM],
    /// Secondary path payload (the destination leaf of rename/link, the link path of symlinkat).
    path2: Option<CString>,
    /// `OPENAT2` `open_how` pad, in the slot, whose address holds for the reason `name`'s does, so an open allocates
    /// nothing for it.
    how: Option<RawOpenHow>,
    /// This `OPENAT2` carries an `O_NONBLOCK` the special-file guard added, so the completion strips it back off the
    /// descriptor. False when the caller asked for the flag itself - theirs to keep.
    strip_nonblock: bool,
    /// `STATX` result pad - **the kernel writes it at completion**, so it must live until the CQE reaps.
    stat: Option<Box<StatxRaw>>,
    /// `TIMEOUT` timespec pad. The kernel copies it at prep (`__io_timeout_prep` -> `get_timespec64`), inside the enter
    /// that submits the SQE, so it is boxed here until then.
    ts: Option<Box<KernelTimespec>>,
    /// This op's `ECANCELED` was asked for, by [`FsConn::cancel_timeout`] or by an `Allow` open's own tripped deadline,
    /// so the completion reports a marked cancellation. An unmarked `ECANCELED` means teardown alone.
    retracted: bool,
    /// On a [`TAG_OPEN_DEADLINE`] entry: the slot and full generation of the `Allow` open this guard cancels if it
    /// fires - full-width like [`FsOpEntry::guard`], so a reissued slot is inert.
    cancels: Option<(u32, u64)>,
    /// On a [`TAG_OPEN`] entry: the guard timer's slot and full generation, retracted when the open answers first.
    guard: Option<(u32, u64)>,
    /// On a [`TAG_OPEN_DEADLINE`] entry whose open already answered, the owner whose [`WallClock::retiring`] count this
    /// slot holds open, since the pair's one count cannot go home while this slot is parked. Set by [`FsCore::take_op`]
    /// when it parks the count, never at the arm, as a guard that fires first frees this slot while the open still
    /// holds its `armed` charge.
    wall_clock: Option<(u32, u64)>,
    /// Keeps a path op's dirfd alive (and its fd number un-reused) while the op is in flight.
    anchor: Option<Anchor>,
    /// The second dirfd of a rename/link.
    anchor2: Option<Anchor>,
    /// The file an fd-op targets, parked here so its descriptor stays open (and un-reused) until the CQE reaps - the
    /// caller may drop its `File` mid-op. Dropping this on `clear` gives close-last ordering.
    file: Option<Arc<OwnedFd>>,
    /// This op's share of a leased recv-pool buffer. Several writes in one delivery may read the same buffer, which
    /// must outlive every DMA that reads it, so `Arc::into_inner` at reap surfaces the id once, on [`FsDone`], from the
    /// completion that drops the last share.
    #[cfg(feature = "net-server")]
    recv_lease: Option<std::sync::Arc<LeaseHold>>,
    /// The shares of a gathered leased write past its first window ([`FsConn::pwritev2_leased`]), each held to the CQE
    /// as `recv_lease` is.
    #[cfg(feature = "net-server")]
    recv_lease_more: Vec<std::sync::Arc<LeaseHold>>,
    /// The byte count a leased write asked for, so a short completion can be told apart from a full one at reap time.
    #[cfg(feature = "net-server")]
    lease_want: u32,
}

/// The most iovecs one `WRITEV` may carry (the kernel's `UIO_MAXIOV`).
#[cfg(feature = "net-server")]
const UIO_MAXIOV: usize = 1024;

/// The kernel's `MAX_RW_COUNT` (`include/linux/fs.h`): `__import_iovec` silently trims a longer write to it, which a
/// leased write would report as a short `EIO`.
#[cfg(feature = "net-server")]
fn max_rw_count() -> usize {
    i32::MAX as usize & !(crate::uring::page_size() - 1)
}

/// Whether `windows` windows of `total` bytes fit one gathered `WRITEV`.
#[cfg(feature = "net-server")]
fn gather_fits(windows: usize, total: usize) -> bool {
    windows > 0 && windows <= UIO_MAXIOV && total <= max_rw_count()
}

/// One delivery's claim on a recv-pool buffer, shared by every leased write, every leased job and every
/// [`LeasedWindow`] reading from it.
///
/// The buffer goes back to the pool when the last share goes. A reaped write and a taken job completion take the id out
/// on the reactor of the hold's own core ([`take_bid`](Self::take_bid), which disarms the drop), and a hold of another
/// core's pool goes home through its queue. A share dropped anywhere else returns it through the fs core's returns
/// queue and pokes the loop ([`publish`]). The share is a `std::sync::Arc` because the facade keeps a `Weak` to it and
/// the reactor paths race `Arc::into_inner` against a drop elsewhere, and loom supplies neither.
#[cfg(feature = "net-server")]
pub(crate) struct LeaseHold {
    bid: u16,
    /// `None` once the id was taken out explicitly, and on the test holds minted with no core behind them.
    returns: Option<LeaseReturns>,
}

/// Where a share dropped off the explicit release paths sends its buffer id, the core's queue and the loop's wake. The
/// wake is a strong `Arc`, since loom's `Arc` has no `Weak`, so a share a handler keeps alive keeps the loop's eventfd
/// open with it.
#[cfg(feature = "net-server")]
#[derive(Clone)]
pub(crate) struct LeaseReturns {
    queue: Arc<Mutex<VecDeque<u16>>>,
    wake: Arc<crate::uring::wake::LoopShared>,
}

#[cfg(feature = "net-server")]
impl std::fmt::Debug for LeaseHold {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LeaseHold").field("bid", &self.bid).finish()
    }
}

#[cfg(feature = "net-server")]
impl LeaseHold {
    fn new(bid: u16, returns: LeaseReturns) -> LeaseHold {
        LeaseHold {
            bid,
            returns: Some(returns),
        }
    }

    /// A hold with no core to return to: for the tests that drive the release paths by hand.
    #[cfg(test)]
    fn detached(bid: u16) -> LeaseHold {
        LeaseHold { bid, returns: None }
    }

    /// The buffer id, taken out by the last share's holder on the reactor: the caller returns it to the pool itself, so
    /// the drop does not.
    fn into_bid(mut self) -> u16 {
        self.returns = None;
        self.bid
    }

    /// The buffer id for the core whose returns queue is `home`, as [`into_bid`](Self::into_bid) takes it out, or
    /// `None` for a hold of another core's pool, which is dropped and so goes home through that core's queue. A
    /// `LeasedWindow` is `Send`, so a window written on another ring would otherwise put its buffer into the wrong
    /// pool, where the kernel could be handed a buffer still in use. A test's hold with no core is taken as `home`'s.
    fn take_bid(self, home: &Arc<Mutex<VecDeque<u16>>>) -> Option<u16> {
        let ours = self
            .returns
            .as_ref()
            .is_none_or(|returns| Arc::ptr_eq(&returns.queue, home));
        if ours { Some(self.into_bid()) } else { None }
    }
}

#[cfg(feature = "net-server")]
impl Drop for LeaseHold {
    fn drop(&mut self) {
        if let Some(returns) = self.returns.take() {
            publish(&returns.queue, &returns.wake.wake, self.bid);
        }
    }
}

/// A pool job's view of a leased recv buffer ([`FsConn::offload_from`]), the raw extent, because a `&[u8]` cannot cross
/// to a worker thread with the facade's lifetime on it.
///
/// Valid to read while a [`LeaseHold`] share for the buffer exists, and one does from before the job is submitted until
/// its completion is taken on the reactor. The pool re-issues a buffer only after its last share is gone, and nothing
/// writes a delivered buffer before then.
#[cfg(feature = "net-server")]
#[derive(Clone, Copy)]
struct LeasedBytes {
    ptr: *const u8,
    len: usize,
}

// SAFETY: the pointer addresses a buffer that stays mapped, unmoved and unwritten while the `LeaseHold` share taken
// beside this value lives, and the worker only reads through it.
#[cfg(feature = "net-server")]
unsafe impl Send for LeasedBytes {}

#[cfg(feature = "net-server")]
impl LeasedBytes {
    fn as_slice(&self) -> &[u8] {
        // SAFETY: `ptr` and `len` came from a live `&[u8]` into a leased buffer, and the share held beside this value
        // keeps that buffer alive and unwritten for longer than any borrow of the slice.
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }
}

/// A window of the delivering connection's receive buffer, held past the delivery ([`FsConn::lease_window`]). It holds
/// the bytes and a share of the buffer's claim, and reads as a slice through `Deref`. A handler spends it on
/// [`FsConn::offload_leased`] with no copy at either end. Dropping one unspent returns its share, and the buffer goes
/// back to the pool when the last share of its claim is gone.
///
/// Every buffer a handler holds a claim on counts against
/// [`recv_lease_depth`](crate::net::server::ServerConfig::recv_lease_depth). Past it the next read parks until a buffer
/// comes home, or with `recv_shortage_retry` off falls back to copies for good, so a handler holding windows until more
/// of its stream arrives must stay within its depth or wait on itself.
#[cfg(feature = "net-server")]
pub struct LeasedWindow {
    view: LeasedBytes,
    hold: std::sync::Arc<LeaseHold>,
}

#[cfg(feature = "net-server")]
impl LeasedWindow {
    /// The window's length in bytes.
    pub fn len(&self) -> usize {
        self.view.len
    }

    /// Whether the window holds no bytes.
    pub fn is_empty(&self) -> bool {
        self.view.len == 0
    }

    /// Split into `[0, mid)` and `[mid, len)`, each holding a share of the buffer, which goes back to the pool once
    /// both are spent or dropped.
    ///
    /// # Panics
    /// If `mid > len`, as [`slice::split_at`] does.
    pub fn split_at(self, mid: usize) -> (LeasedWindow, LeasedWindow) {
        assert!(mid <= self.view.len, "split past the window's end");
        let LeasedWindow { view, hold } = self;
        let tail = LeasedWindow {
            view: LeasedBytes {
                // In bounds: `mid <= len`, so at most one past the end.
                ptr: view.ptr.wrapping_add(mid),
                len: view.len - mid,
            },
            hold: std::sync::Arc::clone(&hold),
        };
        let head = LeasedWindow {
            view: LeasedBytes {
                ptr: view.ptr,
                len: mid,
            },
            hold,
        };
        (head, tail)
    }
}

/// The window's bytes, which nothing writes while it holds its share. A delivery that leases its buffer takes the
/// buffer from the connection and copies any pipelined remainder into storage of its own (`RecvBuf::drain_front`), so
/// no later receive lands in it, a release and a forfeit refuse a leased claim, and the kernel only reads a buffer it
/// writes to a file. The window is `Send` and not `Sync`, so the slice is read on the thread that holds the window.
#[cfg(feature = "net-server")]
impl std::ops::Deref for LeasedWindow {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.view.as_slice()
    }
}

#[cfg(feature = "net-server")]
impl std::fmt::Debug for LeasedWindow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LeasedWindow")
            .field("len", &self.view.len)
            .field("hold", &self.hold)
            .finish()
    }
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
            value: None,
            iov: Vec::new(),
            path: None,
            name: [0; NAME_ROOM],
            path2: None,
            how: None,
            strip_nonblock: false,
            stat: None,
            ts: None,
            retracted: false,
            cancels: None,
            guard: None,
            wall_clock: None,
            anchor: None,
            anchor2: None,
            file: None,
            #[cfg(feature = "net-server")]
            recv_lease: None,
            #[cfg(feature = "net-server")]
            recv_lease_more: Vec::new(),
            #[cfg(feature = "net-server")]
            lease_want: 0,
        }
    }

    /// Release every payload and mark the entry free (the caller bumps the generation and returns the slot to the
    /// free-list).
    fn clear(&mut self) {
        // Everything, including what a caller is expected to have taken first (`take_op` and `fail_op` do). A stale
        // field left here is read against the next tenant, as a stale `strip_nonblock` would be against its `how`.
        self.waiter = None;
        self.bufs = Vec::new();
        self.value = None;
        self.stat = None;
        self.strip_nonblock = false;
        self.iov.clear();
        self.path = None;
        self.path2 = None;
        self.how = None;
        self.ts = None;
        self.retracted = false;
        self.cancels = None;
        self.guard = None;
        self.wall_clock = None;
        self.anchor = None;
        self.anchor2 = None;
        self.file = None;
        #[cfg(feature = "net-server")]
        {
            self.recv_lease = None;
            self.recv_lease_more.clear();
            self.lease_want = 0;
        }
        self.state = FsOpState::Free;
    }

    /// Park `name`, which holds no NUL, for the kernel to read at prep, and give the address the SQE carries: the
    /// slot's own bytes when it fits with its NUL, which one component always does, or else a copy owned in `path`, as
    /// a symlink's target can be longer.
    fn park_name(&mut self, name: &[u8]) -> u64 {
        debug_assert!(!name.contains(&0), "a name holds no NUL");
        if let Some(room) = self.name.get_mut(..=name.len()) {
            let (bytes, nul) = room.split_at_mut(name.len());
            bytes.copy_from_slice(name);
            nul[0] = 0;
            return self.name.as_ptr() as u64;
        }
        let owned = CString::new(name).expect("a name holds no NUL");
        let ptr = owned.as_ptr() as u64;
        self.path = Some(Cow::Owned(owned));
        ptr
    }

    /// Write the path of `fd` under `/proc/thread-self/fd` into the slot's bytes, and give its address, for a reopen or
    /// a read of an xattr that resolves it on the io-wq worker that runs it. The worker shares the descriptors of the
    /// thread that submitted it (`create_io_thread` in `kernel/fork.c`), and a thread of the process reaches them
    /// whatever its personality, since `proc_fd_permission` in `fs/proc/fd.c` and `__ptrace_may_access` in
    /// `kernel/ptrace.c` let the same thread group through. The longest such path, of the largest descriptor number,
    /// takes 32 bytes with its NUL, and `write!` into a slice allocates nothing.
    fn park_proc_path(&mut self, fd: RawFd) -> u64 {
        use std::io::Write as _;
        let mut room = &mut self.name[..];
        write!(room, "/proc/thread-self/fd/{fd}\0").expect("the path of a descriptor fits the slot");
        self.name.as_ptr() as u64
    }
}

/// Take the special-file guard's `O_NONBLOCK` back off a freshly opened descriptor.
///
/// The flag stops the open blocking on a planted FIFO or device, but on the descriptor it is not inert.
/// `io_file_get_flags` (`io_uring/io_uring.c:1793-1794`) reads it into `REQ_F_SUPPORT_NOWAIT`, so `__io_read`
/// (`io_uring/rw.c:950-958`) takes the `IOCB_NOWAIT` branch and runs the transfer on this reactor thread rather than on
/// an io-wq worker. The kernel strips the flag the same way when it added it (`io_uring/openclose.c:161-162`).
///
/// `F_SETFL` honours only the settable flags, so passing back the flags asked for minus `O_NONBLOCK` needs no
/// `F_GETFL`. A failure does not fail the open, since the descriptor is valid either way and only scheduling is lost.
fn strip_guard_nonblock(fd: RawFd, flags: u64) {
    // SAFETY: `fd` is the descriptor OPENAT2 just returned, and `fcntl` with `F_SETFL` reads no memory.
    unsafe {
        libc::fcntl(fd, libc::F_SETFL, flags as i32 & !libc::O_NONBLOCK);
    }
}

/// What a reaped op entry yields once its payloads are taken back out.
struct Completed {
    waiter: Option<FsWaiter>,
    bufs: Vec<Vec<u8>>,
    value: Option<Vec<u8>>,
    stat: Option<Box<StatxRaw>>,
    /// The op's `ECANCELED` was a retraction the caller asked for.
    retracted: bool,
    /// An `Allow` open's guard timer, to retract now that the open has answered for itself.
    guard: Option<(u32, u64)>,
    /// The open carried a guard `O_NONBLOCK`: the flags to restore without it, or `None` when there is nothing to
    /// strip.
    strip_nonblock: Option<u64>,
    #[cfg(feature = "net-server")]
    recv_lease: Option<std::sync::Arc<LeaseHold>>,
    #[cfg(feature = "net-server")]
    recv_lease_more: Vec<std::sync::Arc<LeaseHold>>,
    #[cfg(feature = "net-server")]
    lease_want: u32,
}

/// A finished off-loop job awaiting on-loop delivery, `(token, boxed result)`.
type PoolCompletion = (u64, Box<dyn Any + Send>);

/// The offload worker's epilogue, which records the outcome and then wakes the loop through [`publish`].
///
/// A function so the loom models drive this epilogue rather than their own copy of it, which would stay green with the
/// two steps reordered (`bufring::publish_tail` states the rule).
pub(crate) fn finish_offload(
    sink: &Mutex<VecDeque<PoolCompletion>>,
    wake: &crate::uring::wake::WakeHandle,
    token: u64,
    outcome: Box<dyn Any + Send>,
) {
    publish(sink, wake, (token, outcome));
}

/// Hand `item` to the loop by pushing it under the queue's mutex and then poking. The one spelling of that order, for a
/// finished job's result ([`finish_offload`]) and a dropped share's buffer id ([`LeaseHold`]). A poke made first could
/// be drained ahead of the push and leave the item waiting for the next.
pub(crate) fn publish<T>(sink: &Mutex<VecDeque<T>>, wake: &crate::uring::wake::WakeHandle, item: T) {
    sink.lock().unwrap_or_else(|e| e.into_inner()).push_back(item);
    wake.poke();
}
/// Wake `pool` for the `pending` jobs queued on it since its last flush, and return its next deadline
/// ([`FsCore::flush_offloads`]).
fn flush_pool(pool: &SharedPool, pending: usize) -> Option<std::time::Duration> {
    if pending == 0 {
        let owed = pool.recheck_owed()?;
        if !owed.is_zero() {
            return Some(owed);
        }
    }
    pool.flush(pending)
}

/// A type-erased on-loop continuation: it downcasts the boxed job result back to the job's `R` and calls the caller's
/// `on_done` with a fresh `FsConn`.
type OffloadDeliver = Box<dyn FnOnce(Box<dyn Any + Send>, &mut FsConn<'_>)>;
/// One drained offload ready to fire: its owner, its continuation, and the boxed job result to hand it.
type PoolDelivery = (Owner, OffloadDeliver, Box<dyn Any + Send>);

/// The reactor-side half of an in-flight [`FsConn::offload`], the owner to scope the delivering [`FsConn`] to and its
/// continuation.
struct OffloadEntry {
    owner: Owner,
    deliver: OffloadDeliver,
    /// The job's share of the delivering connection's recv-buffer claim ([`FsConn::offload_from`]), held here and not
    /// by the job, and dropped in [`FsCore::take_pool_completions`] once the job has returned, so the bytes the job
    /// reads stay put for its whole run. `None` for every other offload.
    #[cfg(feature = "net-server")]
    lease: Option<std::sync::Arc<LeaseHold>>,
}

/// One owner's wall-clock tenancy. `armed` is what the cap meters, each count returned at its hold's ending or early at
/// a timer's retraction. `retiring` counts a hold whose count has gone back to the cap while a slot it charged for is
/// still parked awaiting its CQE, and there are two of those.
///
/// - A **retracted timer**, whose retraction hands the cap headroom back at once so retract-then-rearm holds inside one
///   delivery, while the slot rides to a CQE no delivery reaps.
/// - An **`Allow` pair whose open answered first**, which charged one count for two slots, so the guard slot outlives
///   the CQE that returns the charge.
///
/// So the arm screens also refuse once `armed + retiring` reaches twice the cap. **Both classes must reach
/// `retiring`**, or the sum bounds one of them and the other walks the table one unreaped slot at a time. A screen that
/// counts one reads as correct and is not. Without the clause the early headroom unmakes the cap, as a retract-rearm
/// loop parks the whole table with `armed` never leaving zero.
///
/// **Both screens are counts, and a count is not a slot.** A timer's count is one slot, an `Allow` pair's armed count
/// is two, and a `retiring` count is one, so the ceiling is `2 x cap` slots for an owner arming timers and up to `3 x
/// cap` for one arming pairs. Converting to slots would have to weigh each class on its own, since charging every count
/// the heavier weight over-refuses timers.
#[derive(Clone, Copy, Default)]
struct WallClock {
    armed: u32,
    retiring: u32,
}

/// Every move of the pair, in one place, so every caller fails the same way. Each step saturates, since a wrapped
/// `armed` reads as `armed >= cap` and refuses every later arm by that owner for good, and each decrement's
/// `debug_assert` catches a count already at zero.
impl WallClock {
    /// A hold armed.
    fn arm(&mut self) {
        self.armed = self.armed.saturating_add(1);
    }

    /// A hold's slot answered. `retired` picks the half its count sits on: a retraction moved it to `retiring` already.
    fn ended(&mut self, retired: bool) {
        let c = if retired { &mut self.retiring } else { &mut self.armed };
        debug_assert!(*c > 0, "a wall-clock hold ended with nothing counted");
        *c = c.saturating_sub(1);
    }

    /// A retraction: the cap headroom goes back now, the slot at the CQE.
    fn retract(&mut self) {
        debug_assert!(self.armed > 0, "a retraction with nothing armed");
        self.armed = self.armed.saturating_sub(1);
        self.retiring = self.retiring.saturating_add(1);
    }

    /// An `Allow` pair's one count parked on the slot that has not freed yet - it cannot go home with the first of the
    /// two.
    fn park(&mut self) {
        self.retiring = self.retiring.saturating_add(1);
    }

    /// A parked count going home, its slot now free.
    fn release_park(&mut self) {
        debug_assert!(self.retiring > 0, "a parked hold returned twice");
        self.retiring = self.retiring.saturating_sub(1);
    }

    /// Nothing left to account for this owner.
    fn is_empty(&self) -> bool {
        self.armed == 0 && self.retiring == 0
    }
}

/// The fs domain's tables. The host owns the [`Engine`] and passes it in for staging, and completion routing happens in
/// [`FsCore::on_cqe`].
pub(crate) struct FsCore {
    ops: Vec<SlotEntry<FsOpEntry>>,
    op_free: Vec<u32>,
    /// Reply-path pump reads in flight that select from a provided-buffer ring: what the body pool's `grow` subtracts
    /// from its free count.
    pump_selecting: u32,
    /// This reactor's one blocking-work pool (shared with off-loop [`QueryPool`](super::query_dir::QueryPool)s),
    /// spawned on first use.
    pool: Arc<SharedPool>,
    /// Jobs queued on the pool since the last [`Self::flush_offloads`].
    pending_offloads: usize,
    /// The lookup lane, a second pool for jobs that wait on another machine ([`FsConn::offload_lookup`]), so they never
    /// hold a thread of the pool above. Spawned on first use.
    lookup: Arc<SharedPool>,
    /// Jobs queued on the lookup lane since the last [`Self::flush_offloads`].
    pending_lookups: usize,
    /// Where workers push finished jobs; drained on the loop's wake.
    completions: Arc<Mutex<VecDeque<PoolCompletion>>>,
    /// Reactor-side continuations for in-flight offloads, keyed by token.
    offload_reg: HashMap<u64, OffloadEntry>,
    next_offload: u64,
    /// Recv-pool buffer ids whose last share a finished [`FsConn::offload_from`] job dropped, owed to the net server's
    /// pool ([`FsCore::take_pool_releases`]); the fs core cannot reach the pool itself.
    #[cfg(feature = "net-server")]
    pool_releases: Vec<u16>,
    /// Buffer ids returned by shares dropped off the explicit release paths ([`LeaseHold`]), from any thread; drained
    /// with `pool_releases`.
    #[cfg(feature = "net-server")]
    lease_returns: Arc<Mutex<VecDeque<u16>>>,
    /// Attribute names whose `FSETXATTR` runs under ambient credentials rather than the request identity. Empty by
    /// default - see [`PrivilegedXattrs`].
    priv_xattrs: PrivilegedXattrs,
    /// This reactor's identity, minted at construction, so a [`Timer`] can be verified against the table that issued
    /// it - two reactors on one thread both start their tables at slot 0, generation 0, so slot + generation alone
    /// alias across them.
    core_id: u64,
    /// The highest connection generation [`FsCore::cancel_owned_by`] has swept, per connection slot, which
    /// [`FsCore::owner_is_gone`] reads. One entry per slot, and slots are reused, so this is bounded by the host's
    /// connection table and never by how many connections have come and gone.
    closed_owners: HashMap<u32, u64>,
    /// Wall-clock holds per owner ([`WallClock`]) and the per-owner cap the host set ([`FsCore::set_timer_cap`]).
    armed_timers: HashMap<(u32, u64), WallClock>,
    timer_cap: Option<u32>,
    /// Which of this core's reads and writes carry `IOSQE_ASYNC`, as the host set it ([`FsCore::set_force_async`]).
    /// Only `READ` and `WRITE` are read here, as the socket classes belong to the net reactor.
    force_async: ForceAsync,
    /// Host refusals awaiting delivery ([`FsCore::refuse`]), each with its owner, callback and outcome.
    refusals: VecDeque<(Owner, EmbeddedCb, FsDone)>,
    /// The file leases this ring holds and the signalfd their breaks arrive on ([`FileLeases`]).
    pub(crate) file_leases: FileLeases,
    /// Spawned tasks and their run queue ([`super::task`]), polled by the delivery functions below. **Last field on
    /// purpose**, since fields drop in declaration order and `Tasks::drop`, which runs pending task destructors, relies
    /// on everything above being gone.
    pub(crate) tasks: super::task::Tasks,
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
            pump_selecting: 0,
            pool: SharedPool::new(FILE_WORKER, offload),
            pending_offloads: 0,
            lookup: SharedPool::new(
                LOOKUP_WORKER,
                OffloadBounds {
                    floor: LOOKUP_FLOOR,
                    ceiling: LOOKUP_CEILING,
                },
            ),
            pending_lookups: 0,
            completions: Arc::new(Mutex::new(VecDeque::new())),
            offload_reg: HashMap::new(),
            next_offload: 0,
            #[cfg(feature = "net-server")]
            pool_releases: Vec::new(),
            #[cfg(feature = "net-server")]
            lease_returns: Arc::new(Mutex::new(VecDeque::new())),
            priv_xattrs: PrivilegedXattrs::default(),
            tasks: super::task::Tasks::new(),
            core_id: {
                // Plain std atomic: an id fetch is not a cross-thread protocol, and loom need not model it.
                static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
                NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            },
            closed_owners: HashMap::new(),
            armed_timers: HashMap::new(),
            timer_cap: None,
            force_async: ForceAsync::empty(),
            refusals: VecDeque::new(),
            file_leases: FileLeases::default(),
        }
    }

    /// Bound wall-clock holds per owner. A timer holds its op slot for wall-clock time rather than until an I/O
    /// completes, and an `Allow` open holds two slots the same way, so without a bound one connection could park the
    /// whole shared handler budget for its arms' full duration. An `Allow` pair charges one count, taken when its guard
    /// stages and returned by whichever of its two slots frees last ([`WallClock`]).
    ///
    /// The host passes its `max_in_flight_requests`, since one connection needs N holds exactly when N pipelined
    /// requests carry deadlines at once, and a smaller constant would couple this crate to a consumer's pipelining.
    /// Unset is uncapped, for the standalone host, and owner-less arms are never counted. Setup-time only, on
    /// [`FsCore::set_privileged_xattrs`]'s rule.
    #[cfg_attr(not(feature = "net-server"), allow(dead_code))]
    pub(crate) fn set_timer_cap(&mut self, per_owner: u32) {
        self.timer_cap = Some(per_owner);
    }

    /// Stamp `IOSQE_ASYNC` on this core's `READV`/`WRITEV` submissions (see the field). Setup-time only, on
    /// [`FsCore::set_timer_cap`]'s rule.
    #[cfg_attr(not(feature = "net-server"), allow(dead_code))]
    pub(crate) fn set_force_async(&mut self, classes: ForceAsync) {
        self.force_async = classes;
    }

    /// Whether `owner`'s connection has already been swept.
    ///
    /// Generations are per-slot and monotonic, so a sweep recorded at or above this one's means this one is over: an
    /// entry for a later tenant of the same slot answers `false` for the tenant that is live, and `true` for every
    /// tenant before it.
    #[cfg_attr(not(feature = "net-server"), allow(dead_code))]
    pub(crate) fn owner_is_gone(&self, owner: Owner) -> bool {
        let Some((slot, generation)) = owner else {
            return false;
        };
        self.closed_owners.get(&slot).is_some_and(|&swept| swept >= generation)
    }

    /// Screen a wall-clock hold, a timer or an `Allow` open's pair, before any slot is popped for it. `Some` is the
    /// verdict to deliver, `(errno, marked)`. A swept owner gets the sweep's own unmarked `ECANCELED`, so a
    /// continuation keyed on it winds down the same way in both orderings. An owner at its cap, or with `armed +
    /// retiring` at twice it ([`WallClock`]), gets the marked `EBUSY` a full table answers.
    ///
    /// A hold that names no owner passes unscreened, an off-loop `FsWaiter::Channel` hold
    /// ([`FsHandle::open`](super::FsHandle::open) with a deadline) or an `Embedded` one with `owner: None`. Nothing
    /// meters those but the table, whose `op_free.len() < 2` check refuses them as `EBUSY` to whoever asks next,
    /// metered owners included. Metering them needs an owner axis off-loop callers do not have, so this is an exemption
    /// and not a bound.
    fn refuse_wall_clock_hold(&self, waiter: &FsWaiter) -> Option<(Errno, bool)> {
        let FsWaiter::Embedded { owner: Some(o), .. } = waiter else {
            return None;
        };
        if self.owner_is_gone(Some(*o)) {
            return Some((Errno::ECANCELED, false));
        }
        if let Some(cap) = self.timer_cap {
            let t = self.armed_timers.get(o).copied().unwrap_or_default();
            if t.armed >= cap || t.armed.saturating_add(t.retiring) >= cap.saturating_mul(2) {
                return Some((Errno::EBUSY, true));
            }
        }
        None
    }

    /// A handle on this reactor's live-task count, for an embedding host whose graceful drain must wait for tasks as
    /// well as connections. Unused by the standalone host, which stops when nothing is in flight.
    #[cfg_attr(not(feature = "net-server"), allow(dead_code))]
    pub(crate) fn task_gauge(&self) -> std::rc::Rc<std::cell::Cell<usize>> {
        self.tasks.gauge()
    }

    /// Install the ambient-credential xattr policy. Setup-time only: the hosts expose it through a `&mut self` setter,
    /// and their run loops also take `&mut self`, so it cannot change while operations are in flight.
    pub(crate) fn set_privileged_xattrs(&mut self, policy: PrivilegedXattrs) {
        self.priv_xattrs = policy;
    }
}

/// Whether a read of `count` bytes at `off` into `room` bytes past a buffer's length may be staged. A count past the
/// room would need the buffer grown, which allocates and moves it under the caller. A count past `u32::MAX` would
/// truncate in `sqe.len`, and an `off` of `u64::MAX` is -1, which io_uring reads as the file's position
/// (`io_kiocb_update_pos`, `io_uring/rw.c`), so the read would succeed from the wrong place.
pub(crate) fn spare_read_fits(room: usize, count: usize, off: u64) -> bool {
    count <= room && u32::try_from(count).is_ok() && off != u64::MAX
}

/// Whether a write of `range` of a buffer `len` bytes long at `off` may be staged. The range must be one `get` takes,
/// inside the buffer and not inverted, or the address the SQE names lies outside it. A count past `u32::MAX` would
/// truncate in `sqe.len`, and an `off` of `u64::MAX` is -1, which io_uring reads as the file's position
/// (`io_kiocb_update_pos`, `io_uring/rw.c`), so the write would land in the wrong place.
pub(crate) fn owned_write_fits(len: usize, range: &Range<usize>, off: u64) -> bool {
    range.start <= range.end && range.end <= len && u32::try_from(range.end - range.start).is_ok() && off != u64::MAX
}

#[cfg(test)]
mod spare_read_tests;

#[cfg(test)]
mod owned_write_tests;

/// Where a pump read should land.
#[cfg_attr(not(feature = "net-server"), allow(dead_code))]
pub(crate) enum PumpDest {
    /// A buffer this side supplies and gets back on the completion.
    Owned(Vec<u8>),
    /// A registered buffer group; the kernel picks one at completion and names it in `IORING_CQE_F_BUFFER`.
    Group(u16),
}

/// The outcome handed to an embedded [`FsConn`] callback: the op's result plus anything it produced (buffers, a new
/// open [`File`], or `statx` metadata).
#[cfg_attr(not(feature = "net-server"), allow(dead_code))]
pub struct FsDone {
    result: Result<i32, Errno>,
    /// Whether this outcome is the facade's or the core's refusal to submit rather than something the kernel answered.
    /// See [`FsDone::was_refused`].
    refused: bool,
    bufs: Vec<Vec<u8>>,
    /// An xattr op's value, which [`FsDone::into_value`] gives back alone.
    value: Option<Vec<u8>>,
    file: Option<File>,
    stat: Option<Box<StatxRaw>>,
    /// The recv-pool buffer id a leased write borrowed, owed back to the pool now that the op is over.
    #[cfg(feature = "net-server")]
    recv_lease: Option<u16>,
    /// Ids beyond `recv_lease` a gathered leased write owes back; empty for every other op.
    #[cfg(feature = "net-server")]
    recv_lease_more: Vec<u16>,
    /// The count a short leased write wrote before it was failed with `EIO` ([`FsDone::short_count`]). `None` for every
    /// other outcome.
    #[cfg(feature = "net-server")]
    short: Option<usize>,
}

impl std::fmt::Debug for FsDone {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FsDone")
            .field("result", &self.result)
            .finish_non_exhaustive()
    }
}

/// A timer armed by [`FsConn::timeout`], for [`FsConn::cancel_timeout`].
///
/// Names one arming, not the slot. It carries the reactor's identity and the full-width op-table generation of the arm
/// (`uring::slots`), since a `Timer` held past expiry must never alias a later tenant of its slot. The retraction
/// checks all three against the table before staging anything, so a stale token, or one from another reactor on this
/// thread, is inert. `Copy`, since retracting is idempotent, and not `Send`, since it names loop-thread state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timer {
    core: u64,
    slot: u32,
    generation: u64,
    _on_loop: std::marker::PhantomData<std::rc::Rc<()>>,
}

/// The request-bound fs submission facade a `net` server hands a protocol handler and re-hands each completion callback
/// for chaining. Every op runs on the server's ring, checked as the [`Personality`] passed to it, and its completion
/// fires the `on_done` callback **inline on the loop thread**.
///
/// **Re-entrancy.** Callbacks run inside dispatch, so they never block and drive the ring only through this facade. An
/// argument a screen here refuses answers `on_done` with a marked `EINVAL` before the method returns. When the core
/// declines to host an op (a full op table, an `Allow` open's two-slot charge with one slot left, the per-owner
/// wall-clock cap, a swept owner arming a hold, a staging failure), `on_done` is delivered at the next wake drain. A
/// capacity refusal is a marked errno ([`FsDone::was_refused`]) with [`FsDone::into_bufs`] handing the payload back for
/// a retry, and a swept owner's is the unmarked `ECANCELED` of teardown.
//
// No method here may return data borrowed from `'a`. The task layer parks a facade in a thread-local as
// `FsConn<'static>`. The higher-ranked signature of `task::with_conn` stops a caller naming the facade's lifetime, but
// `task::reach_in` reached at `T = FsConn<'static>` would hand out `&'static` borrows of the ring's tables from safe
// code. Keep methods returning owned values or borrows of `&self`, and give any wrapper beside `with_conn` its bound.
#[cfg_attr(not(feature = "net-server"), allow(dead_code))]
pub struct FsConn<'a> {
    fs: &'a mut FsCore,
    eng: &'a mut Engine,
    owner: Owner,
    /// The delivering connection's recv-buffer claim, when the request's body still sits in one - what
    /// [`FsConn::pwritev2_from`] writes from without copying. `None` outside delivery (completion facades) and on
    /// unpooled connections.
    #[cfg(feature = "net-server")]
    lease: Option<RecvWriteLease<'a>>,
    /// The shared hold minted by this delivery's first leased write, kept as a `Weak` so the facade can hand later
    /// ranges a clone without itself delaying the buffer's release - the strong counts are the outstanding writes and
    /// nothing else.
    #[cfg(feature = "net-server")]
    lease_hold: Option<std::sync::Weak<LeaseHold>>,
    /// Staged by [`FsConn::fut`] for the submissions that follow it, and cloned by each one's `embed` rather than taken
    /// (see [`FailSink`]). `None` for every callback caller, which keeps their drop-on-refusal contract.
    fail_sink: Option<FailSink>,
    /// Whether a [`FsConn::fut`] frame is watching this facade's submissions. The arm flag itself rides the staged
    /// sink's allocation ([`SinkInner`]), so an arm made through [`FsConn::reborrow`] reaches the watching frame. This
    /// bool stays per facade, since a `chain`/`walk` step's fresh facade carries the sink but watches no frame, and its
    /// arms take shares without spending the frame's one report.
    frame_watching: bool,
}

/// What [`FsConn::stage_fail_sink`] displaced, for [`FsConn::restore_fail_sink`], the sink staged before and whether a
/// frame was watching then. A `fut` nested inside another's `submit` closure must not swallow the outer's sink or its
/// frame.
pub(crate) struct StagedSink(Option<FailSink>, bool);

/// A view of the delivering connection's recv-pool claim, offered to the handler's fs facade for the duration of one
/// delivery.
///
/// `taken` is a `Cell` because the handler holds the body as `&[u8]` -- a shared borrow of the same connection - for
/// its whole run, so the flag that says "this claim now belongs to a write op" cannot go through `&mut`. The connection
/// reads it at consume time and surrenders the claim to the op instead of recycling it.
#[cfg(feature = "net-server")]
pub(crate) struct RecvWriteLease<'a> {
    /// Start of the claimed buffer.
    pub(crate) ptr: *const u8,
    /// The leasable extent - the delivered message, never the whole buffer - bounding what may be written from.
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
/// An opaque identity for the connection a facade serves, stable across every facade of one connection's deliveries and
/// continuations, and distinct across connections, reincarnations of a slot, and reactors. A key for consumers that
/// keep per-connection state. It carries no capability and names nothing retractable.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct ConnToken {
    core: u64,
    owner: Owner,
}

/// Names a step's path from the directory the step before it opened.
///
/// Boxed rather than a generic parameter: the steps travel as one list, so they must all be the same type.
pub type DeriveName = Box<dyn FnOnce(&Anchor) -> crate::Result<CString>>;

/// What one step of an [`FsConn::open_chain`] resolves, and how it is named.
///
/// A step's path may hold several components: `openat2` honours the `RESOLVE_*` flags every step is confined by, so a
/// whole subtree descent is one open rather than one per component. That is the difference from [`FsConn::mkdir_path`],
/// whose `mkdirat` honours none and must therefore walk a component at a time.
pub enum StepPath {
    /// Known before the chain starts.
    Fixed(CString),
    /// Named from the directory the previous step opened.
    ///
    /// The one thing a consumer can compute that this module cannot: a filehandle read back as the directory that
    /// stores state about it. Runs on the reactor thread between two submissions, so it must not block — a
    /// `name_to_handle_at` on a descriptor already open is the intended shape, and a read of anything is not.
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
#[derive(Debug)]
pub struct OpenStep {
    /// What this step names, relative to the file the previous step opened (or to the chain's anchor, for the first).
    pub path: StepPath,
    /// The credential this step resolves under.
    pub who: Personality,
    /// This step's flags. Every step but the last is forced `O_DIRECTORY`; the last is opened as asked.
    pub how: OpenHow,
}

/// The callback a [`FsConn::mkdir_path`] walk carries between steps.
///
/// Boxed: the walk is a loop written as recursion, so a generic parameter would be a type that contains itself.
type WalkDone = Box<dyn FnOnce(FsDone, &mut FsConn<'_>)>;

// ---- hybrid off-loop listing: threaded readdir + on-loop enrichment --------

/// A `*mut DIR` handed between the reactor and a worker thread. Sound only because the walk gives it to exactly one
/// thread at a time and never shares it.
///
/// Owns the `DIR*`, so dropping it `closedir`s the handle, and a batch result that is never delivered reclaims the fd.
/// [`SendDir::into_raw`] passes ownership on.
struct SendDir(*mut libc::DIR);
// SAFETY: single-owner-at-a-time hand-off, never aliased across threads.
unsafe impl Send for SendDir {}

impl SendDir {
    /// Take the `DIR*` out, leaving the wrapper null so its `Drop` is inert, for handing ownership to a
    /// [`DirWalkInner`].
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

/// A directory being walked by the hybrid lister ([`FsConn::open_dir`] / [`FsConn::next_batch`]). The reactor holds it
/// while the blocking `readdir` runs off-loop on the pool; dropping it closes the `DIR*` (deferring to an in-flight
/// batch's delivery if one is running), so the fd never leaks.
///
/// DAC is preserved: the list-permission check ran on the ring under `who` in `open_dir`; the pool only ever `readdir`s
/// that already-authorized fd.
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
        // If no batch job holds the DIR*, close it now; otherwise the batch's delivery sees `dropped` and closes it
        // when the worker hands it back.
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

#[cfg(all(test, not(loom)))]
mod hybrid_tests;

fn map_res(res: i32) -> Result<i32, Errno> {
    // The kernel's restart codes, which io_uring folds to `-EINTR` for reads and writes (`io_fixup_restart_res`,
    // `io_uring/rw.c`) but posts verbatim for opens and splices. A cancelled `SpecialFiles::Allow` open blocked in
    // `fifo_open` surfaces `-ERESTARTSYS` this way. Exactly the four the kernel names, as 515 is `ENOIOCTLCMD`.
    if matches!(res, -512 | -513 | -514 | -516) {
        return Err(Errno::EINTR);
    }
    if res < 0 { Err(Errno::from_raw(-res)) } else { Ok(res) }
}

/// The buffers of an op with its xattr value, if it has one, as the one buffer, for the outcomes that carry no value of
/// their own: the blocking path's, a refusal's and the teardown drain's.
fn with_value(bufs: Vec<Vec<u8>>, value: Option<Vec<u8>>) -> Vec<Vec<u8>> {
    match value {
        Some(value) => vec![value],
        None => bufs,
    }
}

#[cfg(all(test, not(loom)))]
mod op_entry_size;

#[cfg(all(test, not(loom)))]
mod fs_done_tests;

#[cfg(all(test, not(loom)))]
mod wall_clock_tests;

/// Routing and close-last property fuzzer. It drives fuzzed submit and complete schedules against a real, never-flushed
/// `Engine`, and asserts that op slots free exactly once, every fd closes exactly once and never early, and stale or
/// wrong-tag completions are inert. `ROUTING_FUZZ_SEEDS=N` overrides the seed count.
#[cfg(all(test, not(loom)))]
mod routing_fuzz;

#[cfg(all(test, not(loom)))]
mod pool_identity_tests;

// A loom model of the offload completion handoff. Run with
//   RUSTFLAGS="--cfg loom" cargo test --lib --features uring-fs loom_
//
// A worker pushes its result under the `completions` mutex and then pokes the wake eventfd, and the loop drains the
// queue and re-arms the READ. Poke first and the loop can wake, find the queue empty and park again while the result is
// pushed behind it. The eventfd is the `cfg(loom)` counter in `crate::uring::wake`, so the model holds if a real
// eventfd accumulates pokes the same way.
#[cfg(all(test, loom))]
mod loom_tests;

mod offload;

mod submit;

mod routing;

mod done;

mod fs_conn;

mod pool_ops;
