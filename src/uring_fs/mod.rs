//! The io_uring filesystem reactor: asynchronous filesystem operations with kernel-enforced per-operation identity.
//!
//! This is the asynchronous counterpart of [`crate::sync_fs`], built on the crate's shared io_uring engine (`uring`).
//! An open returns a **real process fd wrapped in an `Arc<OwnedFd>`** (closed by its last reference) and every data op
//! runs against that fd. Two rules shape the whole API:
//!
//! - **Personality is mandatory.** Every consumer-staged operation carries a [`Personality`] - a kernel-registered
//!   credential snapshot stamped into the SQE, under which the kernel itself performs its permission checks
//!   (`override_creds` around issue, io-wq included). The daemon's own identity is minted like any other via
//!   [`UringFs::register_self`], and `sqe.personality = 0` (the ring owner's ambient creds) is reachable only through
//!   the two reads [`FsHandle::fgetxattr_as_root`] and [`FsHandle::fgetxattr_proc_as_root`], for metadata a server
//!   checks itself and never hands to a request, the reopen [`FsHandle::reopen_proc_as_root`], for an access a server
//!   has already decided, and the write allowlist of [`PrivilegedXattrs`]. The few calls that are not ring ops, such as
//!   [`FsHandle::close`] and [`FsHandle::fremovexattr`], take none.
//! - **Resolution is anchored.** No call takes an absolute path. [`Anchor`] is a long-lived real directory fd; `open`
//!   resolves a **relative**, multi-component path against it (confine it in-kernel with
//!   [`ResolveFlag::RESOLVE_BENEATH`](crate::sync_fs::ResolveFlag)), and every subsequent operation is fd-based on the
//!   opened [`File`].
//!
//! # Consumer shape
//!
//! **Standalone** ([`UringFs`]) owns its own ring and loop. The core is host-agnostic: an embedding host can drive the
//! same core on its own ring via [`FsConn`] callbacks - under the `net-server` feature the io_uring net server does
//! this, interleaving fs and socket ops on one ring.
//!
//! The standalone loop is synchronous and single-threaded ([`UringFs::run`], `!Send`); concurrency comes from the ring.
//! Off-loop callers use the `Send + Sync` [`FsHandle`], whose blocking calls submit over an inject channel and park on
//! a per-call reply channel:
//!
//! ```no_run
//! use truenas_ros::uring_fs::{Anchor, UringFs, FsConfig, RwFlags};
//! use truenas_ros::sync_fs::{OFlag, OpenHow};
//!
//! let mut afs = UringFs::new(FsConfig::default())?;
//! let me = afs.register_self()?; // the daemon's own creds, as an explicit id
//! let handle = afs.handle();
//! let stop = afs.shutdown_handle();
//! let anchor = Anchor::open("/tank/share")?; // setup-time; the one absolute open
//!
//! let worker = std::thread::spawn(move || -> truenas_ros::Result<()> {
//!     let how = OpenHow::new().flags(OFlag::O_RDONLY);
//!     let f = handle.open(me, &anchor, "docs/readme.txt", how)?;
//!     let (n, bufs) =
//!         handle.preadv2(me, &f, vec![vec![0u8; 4096]], 0, RwFlags::empty());
//!     let _ = (n?, bufs);
//!     handle.close(f)?;
//!     stop.shutdown();
//!     Ok(())
//! });
//! afs.run()?; // runs until `stop.shutdown()`
//! worker.join().unwrap()?;
//! # Ok::<(), truenas_ros::Error>(())
//! ```
//!
//! Buffers are **owned round-trips**: a `Vec<u8>` moves in with the request and comes back with the result, because the
//! kernel may touch it until the completion reaps - even if the caller lost interest. Reads fill each buffer up to its
//! current `len()`; the returned count says how much is valid (short only at end-of-file).
//!
//! # Naming
//!
//! Method names follow their syscalls. Every data op is positional, carrying its own offset, so there is no offsetless
//! `read` or `write` and no `seek`. A single-buffer or unflagged read or write passes a one-element `bufs` and
//! [`RwFlags::empty()`] rather than taking a second spelling. The `at` suffix keeps its usual meaning, a name relative
//! to an anchor dirfd.
//!
//! # What operates on what
//!
//! The API is fd-first, so a file is named once, by its open, and later ops take the [`File`]. The directory entry ops
//! ([`mkdirat`](FsHandle::mkdirat), [`unlinkat`](FsHandle::unlinkat), [`renameat`](FsHandle::renameat) and the rest)
//! take an [`Anchor`] and a validated [`Leaf`], since no kernel has an fd-only form of them. [`statx`](FsHandle::statx)
//! resolves a name, and [`fstatx`](FsHandle::fstatx) stats an open file. A pool job ([`FsConn::offload_result`]) makes
//! blocking calls on a [`File`] through [`AsFd`]. [`File::from_fd`] takes a descriptor opened outside the reactor,
//! which carries the access of its opener and not that of a personality.
//!
//! # Building on top
//!
//! - **Durable create.** Open `O_TMPFILE` without `O_EXCL`, write, sync, then [`linkat_file`](FsHandle::linkat_file) to
//!   a private name and [`renameat`](FsHandle::renameat) onto the target. A reader sees the old file or the new one,
//!   and an abandoned create leaves nothing behind. Do not chain these with `IOSQE_IO_LINK`, since a failed filesystem
//!   op does not break a chain and the rename would run anyway.
//! - **Confinement.** [`open_confined`](FsHandle::open_confined) applies [`CONFINED_RESOLVE`] so the caller cannot
//!   weaken it, and [`mkdir_path`](FsHandle::mkdir_path) creates a nested path by alternating confined walks with
//!   single-[`Leaf`] `mkdirat`s, since `mkdirat` honours no resolve flags. [`FsConn::open_parent`] goes up one level as
//!   the caller and never across a mount, [`FsConn::open_parent_across_mount`] may cross the top of a mount, and
//!   [`FsConn::reopen_proc`] opens again only a file already held, through `/proc`.
//! - **Split-credential descent.** [`FsConn::open_chain`] opens a sequence of paths, each relative to the one before
//!   and each under **its own personality**, so the kernel decides access to the file the caller named under the
//!   caller's credential, even inside a tree only the daemon may traverse.
//! - **Server-owned metadata.** [`PrivilegedXattrs`] lets declared `trusted.*` attributes be written under the
//!   reactor's own credentials.
//! - **Batched blocking offload.** [`FsConn::offload_result`] runs the blocking part of a request as one pool job and
//!   delivers its result on the loop. The job contract lives at [`offload`](FsConn::offload).
//!
//! # Acting as other users
//!
//! [`UringFs::register_self`] mints the daemon's own identity. To act as an *authenticated peer*, use the
//! [`CredBroker`] - a tiny forked process that impersonates a user just long enough to snapshot their credentials, so
//! the reactor process never changes identity itself:
//!
//! ```no_run
//! use truenas_ros::uring_fs::{AsUser, UringFs, CredBroker, FsConfig};
//!
//! // Every ring first, then the broker (it inherits the ring fds), then
//! // threads. Both halves of that ordering are load-bearing - see
//! // `CredBroker::spawn`.
//! let afs = UringFs::new(FsConfig::default())?;
//! let broker = CredBroker::spawn(&[&afs])?; // main loses CAP_SETUID here
//! let creds = broker.handle(0)?;
//!
//! // ... a session authenticates as uid 1000 ...
//! let who = creds.register(&AsUser::new(1000, 1000).groups(vec![4, 27]))?;
//! // Every op stamped `who` is checked by the kernel as that user; when
//! // the session ends:
//! creds.unregister(who)?;
//! # Ok::<(), truenas_ros::Error>(())
//! ```
//!
//! Several reactors on several threads still need one broker, forked before any thread exists with every ring already
//! created. [`UringFs::setup_ring`] (and `net::server::setup_ring` in the net stack) create the ring without the
//! reactor: spawn the broker over the [`RingFd`]s, then build each reactor on its own thread with
//! [`UringFs::with_ring`].
//!
//! Registering is not free (an IPC round trip plus the impersonation window), and every live id pins a kernel
//! credential in a per-ring `u16` space, so wrap the broker in an [`IdentityCache`] to register once per *identity*
//! rather than once per connection.
//!
//! A brokered personality carries that user's authority and nothing more.
//! Where a service must resolve a path for a user entitled to the object but not to traverse every directory above it,
//! opt in with [`Caps`] - allowed by a ceiling fixed at [`CredBroker::spawn_with_caps`], before the privilege drop, so
//! nothing that happens to the reactor afterwards can widen it.
//!
//! Read the entry for whichever bit you are reaching for before reaching for it; none of them is narrow.
//!
//! # Awaiting instead of chaining
//!
//! Completion callbacks stay the primitive. [`FsConn::fut`] returns one submission's outcome as a future,
//! [`FsConn::result_fut`] does so for the offload-shaped methods, and [`FsConn::spawn`] runs a `'static` future as an
//! on-loop **task** that submits through the [`TaskFs`] it receives. The two styles mix freely within one request, and
//! the contract is at [`task`](self::TaskFs).

mod broker;
// The mint-once-per-key protocol behind `IdentityCache`, kept separate so it can be model-checked without a broker
// process to fork.
mod single_flight;
// The elastic blocking-work pool behind `FsConn::offload` and the off-loop helpers - generic machinery, kept apart from
// the fs-domain modules that submit to it.
pub(crate) mod offload_pool;
pub use offload_pool::OffloadBounds;
// `pub(crate)` so a `net` server can drive an `FsCore` on its own ring.
pub(crate) mod core;
// Read leases a ring holds on files, and the breaks of them that reach it.
pub mod file_lease;
// Exported without `net-server`, since a consumer driving a standalone [`UringFs`] needs the `FsConn` facade to run
// several operations back to back as much as an embedded server does.
pub use core::{ConnToken, DeriveName, DirWalk, FsConn, FsDone, NameBatch, OpenStep, StepPath, Timer};
// The one on-loop type that is the server's alone: a window of a pooled receive buffer, which only the net server has.
#[cfg(feature = "net-server")]
pub use core::LeasedWindow;
// The awaitable layer over the callback facade: op futures, offload futures, and on-loop tasks. A consumer, not a
// second submission path - every op it submits goes through `FsConn`'s methods above.
pub(crate) mod task;
pub use task::{FsFuture, JoinError, JoinHandle, OffloadFuture, OnDone, OnResult, TaskFs};

/// Silence the panic hook for **this thread only**, until the guard drops.
///
/// `set_hook` is process-wide and `cargo test` runs a binary's tests as threads in one process, so a hook that swallows
/// everything would hide a concurrent test's panic message.
///
/// **The filter is installed once and never taken back, because `set_hook` is a slot rather than a stack.** A guard
/// that restored the previous hook on drop would discard another thread's filter while it still runs. Quieting is
/// counted, so a guard inside a guard un-quiets nothing.
#[cfg(all(test, not(loom)))]
pub(crate) fn quiet_panics_on_this_thread() -> QuietPanics {
    static INSTALL: std::sync::Once = std::sync::Once::new();
    INSTALL.call_once(|| {
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if !quiet_threads()
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .contains_key(&std::thread::current().id())
            {
                prev(info);
            }
        }));
    });
    *quiet_threads()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .entry(std::thread::current().id())
        .or_insert(0) += 1;
    QuietPanics(std::marker::PhantomData)
}

/// Threads currently quieted, and how many guards deep each is.
#[cfg(all(test, not(loom)))]
fn quiet_threads() -> &'static std::sync::Mutex<std::collections::HashMap<std::thread::ThreadId, u32>> {
    static QUIET: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<std::thread::ThreadId, u32>>> =
        std::sync::OnceLock::new();
    QUIET.get_or_init(Default::default)
}

/// The guard [`quiet_panics_on_this_thread`] returns. Thread-affine (`!Send`), because its `Drop` decrements the
/// **dropping** thread's entry: carried across a spawn it would un-quiet the wrong thread - or no thread, leaving the
/// originating one quiet for the rest of the process.
#[cfg(all(test, not(loom)))]
pub(crate) struct QuietPanics(std::marker::PhantomData<std::rc::Rc<()>>);

#[cfg(all(test, not(loom)))]
impl Drop for QuietPanics {
    fn drop(&mut self) {
        let mut quiet = quiet_threads().lock().unwrap_or_else(|e| e.into_inner());
        if let std::collections::hash_map::Entry::Occupied(mut e) = quiet.entry(std::thread::current().id()) {
            *e.get_mut() -= 1;
            if *e.get() == 0 {
                e.remove();
            }
        }
    }
}

pub mod query_dir;
pub use query_dir::{
    CopyHandle, DirEntry, EnrichSpec, Order, QueryDir, QueryHandle, QueryOptions, QueryPool, XattrNamespaces,
    query_directory,
};

pub mod query_tree;
pub use query_tree::{QueryTree, TreeCursor, TreeEntry, TreeOptions, query_tree};
pub(crate) mod host;

pub use crate::uring::ring::RingFd;
pub use broker::{AsUser, BrokerReactor, Caps, CredBroker, CredHandle, IdentityCache, Lease, MAX_GROUPS, MAX_RINGS};
pub use host::{FsConfig, ShutdownHandle, UringFs};

/// The credential-broker request decoder, exposed to the fuzz crate (`fuzz/`) under `__fuzz` only - `broker` is a
/// private module. Never part of the stable API.
///
/// Driven by `fuzz/fuzz_targets/broker_request.rs`. This is the sharpest privilege boundary in the crate: the broker
/// child holds `CAP_SETUID` and mints personalities from whatever [`decode_request`](fuzz::decode_request) accepts, so
/// the target asserts that an accepted request is always within the ring count, the group cap, the exact declared
/// length, and the spawn-time capability ceiling.
#[cfg(feature = "__fuzz")]
pub mod fuzz {
    pub use super::broker::{Req, decode_groups, decode_request};

    /// [`Leaf::to_cstring`](super::Leaf) is crate-internal, but `fuzz/fuzz_targets/path_leaf.rs` needs it to prove its
    /// `expect("validated: no interior NUL")` unreachable for every name [`Leaf::new`](super::Leaf::new) accepts.
    pub fn leaf_to_cstring(leaf: super::Leaf<'_>) -> std::ffi::CString {
        leaf.to_cstring()
    }
}

use crate::errno::{Errno, retry_on_eintr};
use crate::fd::owned_from_raw;
use crate::path::TnPath;
use crate::sync_fs::openat2::RawOpenHow;
use crate::sync_fs::{
    AtFlags, Mode, OFlag, OpenHow, RenameFlags, ResolveFlag, Statfs, Statx, StatxMask, StatxRaw, ZFS_SETATTR, ZfsAttr,
    ZfsSetattr,
};
use crate::uring::wake::LoopShared;
use std::borrow::Cow;
use std::ffi::{CStr, CString};
use std::fmt;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd};
// The inject channel and the shared flags are loom-modelled (see `loom_tests` at the bottom), so these come from
// `crate::sync` - std's outside `--cfg loom`.
use crate::sync::Arc;
use crate::sync::mpsc;

/// The `AT_*` flags an async `statx` submits. `statx` follows a terminal symlink unless told not to; the confined
/// surface inverts that, forcing `AT_SYMLINK_NOFOLLOW` by default so a peer-planted leaf symlink can't redirect the
/// stat out of the anchor. Passing `AT_SYMLINK_FOLLOW` - which `statx` does not take natively - is the caller's opt-in
/// to follow (stat the target), mirroring `linkat`; it is stripped before the syscall.
pub(crate) fn statx_at_flags(flags: AtFlags) -> u32 {
    let follow = flags.contains(AtFlags::AT_SYMLINK_FOLLOW) && !flags.contains(AtFlags::AT_SYMLINK_NOFOLLOW);
    let base = flags.difference(AtFlags::AT_SYMLINK_FOLLOW);
    if follow {
        base.bits() as u32
    } else {
        (base | AtFlags::AT_SYMLINK_NOFOLLOW).bits() as u32
    }
}

/// Resolution rules that keep a path inside its [`Anchor`], as a set a caller can demand rather than merely receive by
/// default.
///
/// - `RESOLVE_BENEATH` - no component may resolve above the anchor, and an absolute path is refused rather than
///   resolved from `/`.
/// - `RESOLVE_NO_SYMLINKS` - no symlink is followed, anywhere in the path, so a link planted inside the tree cannot
///   redirect out of it.
/// - `RESOLVE_NO_XDEV` - resolution may not cross a mount point. On ZFS that means a nested dataset, or a
///   `.zfs/snapshot` automount, terminates the walk instead of silently serving files from another filesystem.
///
/// These are enforced by the kernel during resolution, not re-implemented here; see [`FsHandle::open_confined`].
pub const CONFINED_RESOLVE: ResolveFlag = ResolveFlag::RESOLVE_BENEATH
    .union(ResolveFlag::RESOLVE_NO_SYMLINKS)
    .union(ResolveFlag::RESOLVE_NO_XDEV);

/// The `resolve` flags that state *where* resolution may go, as against those that harden it where it already is.
///
/// The split is what keeps "I also want `RESOLVE_NO_MAGICLINKS`" from meaning "and no confinement". A caller naming one
/// of these has made the confinement decision and is left with exactly it; a caller naming only hardening flags
/// (`RESOLVE_NO_XDEV`, `RESOLVE_NO_SYMLINKS`, `RESOLVE_NO_MAGICLINKS`, `RESOLVE_CACHED`) has asked for *more*
/// restriction and must not be given less, so [`CONFINED_RESOLVE`] is unioned in underneath it.
const CONFINEMENT_POLICY: ResolveFlag = ResolveFlag::RESOLVE_BENEATH.union(ResolveFlag::RESOLVE_IN_ROOT);

/// The part of [`CONFINED_RESOLVE`] a stated [`CONFINEMENT_POLICY`] does **not** replace.
///
/// `RESOLVE_NO_XDEV` answers a different question from `BENEATH`/`IN_ROOT`. Those bound where resolution may go *within
/// a tree*; this bounds which *filesystem* it ends on, and the kernel keeps them just as separate --
/// `__traverse_mounts` (`fs/namei.c:1485-1522`) refuses a crossing only under `LOOKUP_NO_XDEV`, and `LOOKUP_BENEATH` is
/// consulted on the dotdot paths alone. Without this flag a caller naming `RESOLVE_BENEATH` to allow in-tree symlinks
/// would also let resolution walk onto a nested dataset or a `.zfs/snapshot` automount, with its own permissions,
/// quotas and snapshot policy.
const CONFINED_HARDENING: ResolveFlag = ResolveFlag::RESOLVE_NO_XDEV;

/// Apply the confinement rule to a caller's `resolve` word: the whole [`CONFINED_RESOLVE`] bundle where no policy was
/// stated, and [`CONFINED_HARDENING`] on top of one that was.
///
/// Hardening flags do not count as a policy, so adding one cannot subtract confinement, and no flag combination
/// resolves an absolute path from the filesystem root. One function, because the blocking [`open_parts`] and the
/// request handler's [`FsConn::open`](core::FsConn::open) must never differ in how lax they are.
pub(crate) fn confine_resolve(resolve: &mut u64) {
    if *resolve & CONFINEMENT_POLICY.bits() == 0 {
        *resolve |= CONFINED_RESOLVE.bits();
    } else {
        *resolve |= CONFINED_HARDENING.bits();
    }
}

/// Whether `resolve` states `RESOLVE_IN_ROOT`, which cannot compose with the `RESOLVE_BENEATH` a confined walk unions
/// in: "Scoping flags are mutually exclusive" (`build_open_flags`, `fs/open.c:1263-1265`), so every step of such a walk
/// would answer `EINVAL`, after the earlier steps had already run for a walk that creates. `open_confined`,
/// `FsConn::mkdir_path` and `FsConn::open_chain` screen it rather than route through [`confine_resolve`], which would
/// union only [`CONFINED_HARDENING`] once a policy bit is set and drop the `RESOLVE_NO_SYMLINKS` a confined walk needs
/// most.
pub(crate) fn scoping_conflict(resolve: u64) -> bool {
    resolve & crate::sync_fs::ResolveFlag::RESOLVE_IN_ROOT.bits() != 0
}

/// Whether an open may be left able to block on a special file.
///
/// A path a peer chose can resolve to a FIFO or a device node, and opening one *blocks inside `open(2)` itself* -
/// `fifo_open` sleeps in `wait_for_partner` (`fs/pipe.c`) until a writer appears, which for a FIFO nobody will write to
/// is forever. There is no descriptor at that point, so no `fstatx` can screen it out after the fact; the only defences
/// are to pass `O_NONBLOCK` or to never issue a read-open at all.
///
/// It is worse on the ring than off it. `io_openat_force_async` (`io_uring/openclose.c:42-50`) puts every
/// `O_CREAT`/`O_TRUNC`/`O_TMPFILE` open straight onto an io-wq worker, where the `op.open_flag |= O_NONBLOCK` the
/// inline path applies never runs, and `io_openat2`'s `LOOKUP_CACHED` sends a cold dentry or any symlink component down
/// the same road. The bounded pool is `min(sq_entries, 4 * nr_cpus)`, so a handful of planted names pins every blocking
/// fs op on the ring, and a blocking [`FsHandle`] call waits with no deadline, so each pins a caller thread too.
///
/// The flag is stripped from the descriptor once the open completes, as the kernel strips one it added itself
/// (`io_uring/openclose.c:161-162`), because it is not inert there. `io_file_get_flags`
/// (`io_uring/io_uring.c:1793-1794`) reads it to set `REQ_F_SUPPORT_NOWAIT`, and `__io_read` (`io_uring/rw.c:950-958`)
/// then runs the transfer inline on the reactor thread instead of on an io-wq worker, as one 32 MiB read of a warm file
/// shows.
///
/// ```text
/// ZFS    plain       enter= 7.8 ms   CQE not ready   (punted to io-wq)
/// ZFS    O_NONBLOCK  enter=22.7 ms   CQE ready       (ran inline)
/// tmpfs  plain       enter= 0.1 ms   CQE not ready   (punted)
/// tmpfs  O_NONBLOCK  enter=20.5 ms   CQE ready       (ran inline)
/// ```
///
/// ZFS references neither `IOCB_NOWAIT` nor `FMODE_NOWAIT`, so there it blocks inline on a cache miss.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SpecialFiles {
    /// Add `O_NONBLOCK` to the open so it cannot block, and strip it from the descriptor once the open completes. The
    /// default, and the right choice for any path a peer names or that another protocol can write.
    Guard,
    /// Leave the caller's flags exactly as given, bounded by `deadline`. A guard timer rides the open, an
    /// `ASYNC_CANCEL` staged at expiry rather than a kernel `LINK_TIMEOUT`, which arms only after the issue it would
    /// bound returns and so cannot cover a force-async open (`core::TAG_OPEN_DEADLINE`). An open that trips answers
    /// `ECANCELED`, or `EINTR` where the cancellation caught it mid-sleep.
    ///
    /// An `Allow` open charges **two op slots** until it answers, its own and its guard's, so one can be refused
    /// `EBUSY` with a slot still free. From an embedding host the pair is metered against the owner's timer cap and
    /// refused for a swept owner, as a timer arm is (`core::FsCore::armed_timers`). Over an [`FsHandle`] only the op
    /// table bounds it (`core::FsCore::refuse_wall_clock_hold`).
    ///
    /// For a tree the consumer owns outright, where nothing else can write a FIFO or device node. The deadline is
    /// mandatory because io-wq is one bounded pool, so a handful of planted names would pin every blocking fs op on the
    /// ring, not just this open.
    Allow {
        /// How long the open may block before the kernel cancels it.
        deadline: std::time::Duration,
    },
}

/// An [`OpenHow`] plus this crate's policy for it.
///
/// `OpenHow` is the kernel's `open_how` and nothing else; the policy is this crate's, applies only to opens issued on
/// the ring, and so lives here. Every open entry point takes `impl Into<FsOpenHow>`, so passing a bare `OpenHow` keeps
/// [`SpecialFiles::Guard`] - the safe default - and opting out is spelled at the call site that is taking the risk.
///
/// ```no_run
/// # use truenas_ros::uring_fs::FsOpenHow;
/// # use truenas_ros::sync_fs::{OpenHow, OFlag};
/// # let how = OpenHow::new().flags(OFlag::O_RDONLY);
/// // A tree nothing else can write to - bounded anyway:
/// let mine = FsOpenHow::from(how)
///     .allow_blocking_special_files(std::time::Duration::from_secs(5));
/// ```
#[derive(Clone, Copy, Debug)]
pub struct FsOpenHow {
    how: OpenHow,
    special: SpecialFiles,
}

impl From<OpenHow> for FsOpenHow {
    /// Takes [`SpecialFiles::Guard`].
    fn from(how: OpenHow) -> FsOpenHow {
        FsOpenHow {
            how,
            special: SpecialFiles::Guard,
        }
    }
}

impl FsOpenHow {
    /// Select [`SpecialFiles::Allow`] - read its warning first.
    pub fn allow_blocking_special_files(mut self, deadline: std::time::Duration) -> FsOpenHow {
        self.special = SpecialFiles::Allow { deadline };
        self
    }

    /// Select [`SpecialFiles::Guard`] explicitly (already the default).
    pub fn guard_special_files(mut self) -> FsOpenHow {
        self.special = SpecialFiles::Guard;
        self
    }

    /// The kernel payload and the policy, for the submission paths.
    pub(crate) fn into_parts(self) -> (OpenHow, SpecialFiles) {
        (self.how, self.special)
    }
}

/// Apply the special-file guard to `raw`, returning whether it was added here.
///
/// A caller that set `O_NONBLOCK` itself keeps it and gets `false`: the flag is theirs, and stripping it would be as
/// surprising as leaving ours. This mirrors the kernel's own `nonblock_set` test at `io_uring/openclose.c:161-162`.
///
/// The flag goes on every guarded open, not only `O_CREAT`/`O_TRUNC`. `io_openat2` applies `LOOKUP_CACHED` on the
/// inline attempt only, and `legitimize_links` (`fs/namei.c:808-812`) fails while that is set, so a cold dentry or any
/// symlink component also lands on a worker where the kernel's own fixup never runs.
pub(crate) fn apply_special_file_guard(raw: &mut RawOpenHow, special: SpecialFiles) -> bool {
    // `O_PATH` never runs the file's `open`, and `openat2` refuses `O_NONBLOCK` beside it (`fs/open.c:1298-1300`).
    // `O_DIRECTORY` fails `ENOTDIR` in `do_open` (`fs/namei.c:4003-4004`) before `vfs_open` can block, and
    // `O_DIRECTORY | O_CREAT` is refused (`fs/open.c:1283`). An `O_TMPFILE` open carries `O_DIRECTORY` and creates only
    // an `S_IFREG` inode (`do_tmpfile`). Each skip saves a blocking `fcntl` on the reactor thread.
    if matches!(special, SpecialFiles::Allow { .. })
        || raw.flags & libc::O_PATH as u64 != 0
        || raw.flags & libc::O_DIRECTORY as u64 != 0
        || raw.flags & libc::O_NONBLOCK as u64 != 0
    {
        return false;
    }
    raw.flags |= libc::O_NONBLOCK as u64;
    true
}

/// What a reopen of a held file through `/proc` asks for ([`FsConn::reopen_proc`](core::FsConn::reopen_proc)), and all
/// it may ask. A reopen never creates, truncates or opens `O_PATH`, since it takes a file that is already there and
/// gives a descriptor that reads or writes it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReopenAccess {
    /// `O_RDONLY`.
    Read,
    /// `O_WRONLY`.
    Write,
    /// `O_RDWR`.
    ReadWrite,
}

impl ReopenAccess {
    /// The `open_how` of the reopen, this access with `O_CLOEXEC` and `O_NOCTTY`, and whether the special-file guard
    /// added `O_NONBLOCK`, which it does for every access, so that a FIFO answers at once rather than hold a worker. No
    /// resolve flag is set, since `RESOLVE_NO_MAGICLINKS` refuses the link under `/proc` that the reopen follows, and
    /// the path is absolute, which `RESOLVE_BENEATH` and `RESOLVE_IN_ROOT` refuse.
    pub(crate) fn how(self) -> (RawOpenHow, bool) {
        let access = match self {
            ReopenAccess::Read => libc::O_RDONLY,
            ReopenAccess::Write => libc::O_WRONLY,
            ReopenAccess::ReadWrite => libc::O_RDWR,
        };
        let flags = access | libc::O_CLOEXEC | libc::O_NOCTTY;
        let mut raw = RawOpenHow {
            flags: flags as u64,
            mode: 0,
            resolve: 0,
        };
        let guarded = apply_special_file_guard(&mut raw, SpecialFiles::Guard);
        (raw, guarded)
    }
}

/// Split an open into the pieces a submission needs, applying both of this module's rules: resolve confinement and the
/// special-file guard.
///
/// Returns whether the guard added `O_NONBLOCK`, so the completion can strip it back off the descriptor.
/// [`FsConn::open`](core::FsConn::open) applies the same two rules through the same two functions, so neither facade
/// carries a copy of half the rule.
pub(crate) fn open_parts<P: ?Sized + TnPath>(
    path: &P,
    how: FsOpenHow,
) -> crate::Result<(CString, RawOpenHow, bool, Option<std::time::Duration>)> {
    let cpath: CString = path.with_tn_path(|c| c.to_owned())?;
    if cpath.as_bytes().is_empty() {
        return Err(crate::Error::Validation("uring_fs open: empty path".into()));
    }
    let deadline = match how.special {
        SpecialFiles::Allow { deadline } => {
            // A zero deadline races the open's own completion for no reason a caller can want; refuse it the way every
            // other shape defect is refused, before anything is submitted.
            if deadline.is_zero() {
                return Err(crate::Error::Validation(
                    "uring_fs open: a zero Allow deadline cancels the \
                     open it guards"
                        .into(),
                ));
            }
            Some(deadline)
        }
        SpecialFiles::Guard => None,
    };
    let mut raw = how.how.to_raw();
    // Union, keyed on whether the caller stated a policy at all - never on `resolve == 0`. Testing the whole word makes
    // a purely hardening flag an opt-out: `RESOLVE_NO_MAGICLINKS` alone would then drop `RESOLVE_BENEATH`, so a caller
    // asking for less traversal would get less confinement and `../../etc/shadow` would resolve.
    confine_resolve(&mut raw.resolve);
    let guarded = apply_special_file_guard(&mut raw, how.special);
    Ok((cpath, raw, guarded, deadline))
}

// Lives in the engine (`uring::personality`): registration is engine-level (`register_personality` takes a bare ring
// fd) and the net client stamps it on outbound connects, so the type cannot be fs-owned.
pub use crate::uring::personality::Personality;

tn_bitflags! {
    /// Per-operation flags for the `preadv2`/`pwritev2` forms ([`FsHandle::preadv2`], [`FsHandle::pwritev2`] and their
    /// [`FsConn`] twins) - the kernel's `RWF_*` set, carried in the SQE's read/write flags field.
    ///
    /// An **unsupported flag fails the operation** with `EOPNOTSUPP` rather than being ignored (`kiocb_set_rw_flags`),
    /// so support is detectable per call and a durability flag is never silently dropped. Support is per filesystem,
    /// and the table gives it for ZFS.
    ///
    /// | flag | ZFS | observed | why |
    /// |---|---|---|---|
    /// | [`RWF_DSYNC`](Self::RWF_DSYNC), [`RWF_SYNC`](Self::RWF_SYNC) | yes | `Ok` | the durability pair |
    /// | [`RWF_APPEND`](Self::RWF_APPEND), [`RWF_NOAPPEND`](Self::RWF_NOAPPEND) | yes | `Ok` | |
    /// | [`RWF_ATOMIC`](Self::RWF_ATOMIC) | **no** | `EOPNOTSUPP` | needs `FMODE_CAN_ATOMIC_WRITE`, which ZFS does not set |
    /// | [`RWF_DONTCACHE`](Self::RWF_DONTCACHE) | **no** | `EOPNOTSUPP` | needs `FOP_DONTCACHE` (Linux >= 6.14), which ZFS does not set |
    /// | [`RWF_NOWAIT`](Self::RWF_NOWAIT) | **no** | `EOPNOTSUPP` | needs `FMODE_NOWAIT` on the file; io_uring drives its own non-blocking attempt regardless |
    /// | [`RWF_HIPRI`](Self::RWF_HIPRI) | **no** | `EINVAL` | requires an `IOPOLL` ring, which this reactor does not create |
    pub struct RwFlags: u32 {
        /// High-priority read/write (`IOPOLL` rings only).
        RWF_HIPRI = 0x00000001;
        /// Complete as though the file were opened `O_DSYNC`.
        RWF_DSYNC = 0x00000002;
        /// Complete as though the file were opened `O_SYNC`.
        RWF_SYNC = 0x00000004;
        /// Return `EAGAIN` rather than blocking.
        RWF_NOWAIT = 0x00000008;
        /// Write at the end of the file, as though opened `O_APPEND`.
        RWF_APPEND = 0x00000010;
        /// Honour the supplied offset even on a file opened `O_APPEND`.
        RWF_NOAPPEND = 0x00000020;
        /// Torn-write protection: the write lands whole or not at all. Needs hardware and filesystem support, plus a
        /// size and alignment within the limits `statx` reports.
        RWF_ATOMIC = 0x00000040;
        /// Drop the page cache for this range once the I/O completes.
        RWF_DONTCACHE = 0x00000080;
    }
}

/// Namespace every [`PrivilegedXattrs`] prefix must sit under.
const TRUSTED_NS: &[u8] = b"trusted.";

/// Which extended attributes may be **written** under the reactor's ambient credentials instead of the request's
/// [`Personality`].
///
/// The reactor normally refuses `personality == 0`, which would run an op as the daemon rather than the requester. This
/// allowlist is the write-side counterpart of the privileged reads ([`FsHandle::fgetxattr_as_root`],
/// [`FsHandle::fgetxattr_proc_as_root`]) and reopen ([`FsHandle::reopen_proc_as_root`]), for metadata a server keeps
/// where the file's owner can neither read, change nor list it. On ZFS the `trusted.` namespace is gated on
/// `CAP_SYS_ADMIN` for get, set and list, so only `trusted.` prefixes are accepted. The policy is fixed before
/// [`UringFs::run`], which takes `&mut self`, and an empty policy (the default) permits nothing.
///
/// ```no_run
/// use truenas_ros::uring_fs::{FsConfig, PrivilegedXattrs, UringFs};
/// # fn main() -> truenas_ros::Result<()> {
/// let mut fs = UringFs::new(FsConfig::default())?;
/// fs.set_privileged_xattrs(
///     PrivilegedXattrs::new().allow_prefix(c"trusted.myserver_")?,
/// );
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug, Default)]
pub struct PrivilegedXattrs {
    prefixes: Vec<CString>,
}

impl PrivilegedXattrs {
    /// An empty policy: no attribute is written with elevated credentials.
    pub fn new() -> PrivilegedXattrs {
        PrivilegedXattrs::default()
    }

    /// Permit attributes whose name begins with `prefix`.
    ///
    /// Errors with `Validation` unless `prefix` is under `trusted.` and names at least one byte beyond it.
    pub fn allow_prefix(mut self, prefix: &CStr) -> crate::Result<Self> {
        let bytes = prefix.to_bytes();
        // `security.` would allow `security.capability`, which grants file capabilities, `system.` holds the ACLs, and
        // `user.` needs no privilege. A bare `trusted.` would cover the whole namespace.
        if !bytes.starts_with(TRUSTED_NS) || bytes.len() <= TRUSTED_NS.len() {
            return Err(crate::Error::Validation(
                "PrivilegedXattrs: prefix must be under `trusted.` and name \
                 more than the bare namespace"
                    .into(),
            ));
        }
        self.prefixes.push(prefix.to_owned());
        Ok(self)
    }

    /// Whether `name` is covered. Always false for an empty policy.
    pub(crate) fn permits(&self, name: &CStr) -> bool {
        let name = name.to_bytes();
        self.prefixes.iter().any(|p| name.starts_with(p.to_bytes()))
    }
}

/// Cache advice for [`FsHandle::fadvise`] - the `POSIX_FADV_*` values.
///
/// On ZFS these are not page-cache-only hints: [`WillNeed`](Self::WillNeed) prefetches into the ARC and
/// [`DontNeed`](Self::DontNeed) evicts from it, on top of the generic page-cache handling.
/// [`RwFlags::RWF_DONTCACHE`] cannot stand in for `DontNeed`, since ZFS answers it `EOPNOTSUPP`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum Advice {
    /// No advice; resets any previously set pattern for the range.
    Normal = 0,
    /// Expect random access - read-ahead is of little use.
    Random = 1,
    /// Expect sequential access, so read further ahead. Worth setting on the read side of a streamed object.
    Sequential = 2,
    /// Fetch the range into cache now. On ZFS an ARC prefetch.
    WillNeed = 3,
    /// Release the range's cached data. On ZFS an ARC eviction, worth calling after a large write has been synced.
    DontNeed = 4,
    /// Expect a single access in the near future.
    NoReuse = 5,
}

/// A validated **single path component** - the only name a directory-entry operation will accept.
///
/// This is a security boundary, not decoration. The `*at` opcodes honour no `RESOLVE_*` flags, so a name containing `/`
/// or `..` would walk wherever it pleased, out of the anchor and across the filesystem; confining them to one component
/// is what makes an [`Anchor`] an actual confinement.
///
/// **`AT_SYMLINK_FOLLOW` is the one exception, and it is not this type's to close.** A single-component symlink passes
/// `Leaf::new`, and an op whose `AtFlags` take that flag resolves it to wherever it points, outside the anchor. Those
/// are both `linkat`s, which nothing in the kernel bounds since `may_linkat` (`fs/namei.c:1271`) tests only the source
/// inode, and the `statx` forms. See [`FsConn::linkat`](crate::uring_fs::FsConn::linkat) for the worked case. An op
/// that takes a `Leaf` and no `AtFlags` uses the name literally.
///
/// Rejected: empty, `.`, `..`, anything containing `/` or an interior NUL.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Leaf<'a>(&'a [u8]);

impl<'a> Leaf<'a> {
    /// Validate `name` as a single component.
    pub fn new<S: AsRef<[u8]> + ?Sized>(name: &'a S) -> crate::Result<Leaf<'a>> {
        let b = name.as_ref();
        match crate::path::component_defect(b) {
            Some(defect) => Err(crate::Error::Validation(format!(
                "not a single path component ({defect})"
            ))),
            None => Ok(Leaf(b)),
        }
    }

    pub(crate) fn to_cstring(self) -> CString {
        CString::new(self.0).expect("validated: no interior NUL")
    }

    /// The component's bytes, with no NUL, for an op that copies them into its slot rather than allocating a `CString`.
    pub(crate) fn as_bytes(&self) -> &'a [u8] {
        self.0
    }
}

/// A long-lived **real** directory fd that anchors every path resolution.
///
/// The fs API exposes no absolute-path calls: `open` resolves relative to an `Anchor` (kernel constraint, not style -
/// io_uring's path ops reject fixed-table dirfds, so anchors must be real fds). Bootstrap one at setup time with
/// [`Anchor::open`] (the single absolute open, outside the async surface) or wrap an existing directory fd with
/// [`Anchor::from_fd`].
///
/// Cloning is cheap (`Arc`); an in-flight open holds a clone, so the dirfd can never close - or be reused by another
/// file - under a submitted op.
#[derive(Clone, Debug)]
pub struct Anchor(Arc<OwnedFd>);

impl Anchor {
    /// Open a directory as an anchor (`O_PATH | O_DIRECTORY | O_CLOEXEC`) -- a plain blocking syscall for setup time,
    /// and this module's one absolute-path entry point.
    pub fn open<P: ?Sized + TnPath>(path: &P) -> crate::Result<Anchor> {
        let fd = path.with_tn_path(|c| {
            retry_on_eintr(|| unsafe {
                // SAFETY: `c` is a valid NUL-terminated path for the call.
                libc::open(c.as_ptr(), libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC)
            })
        })??;
        // SAFETY: on success `open` returns a fresh owned descriptor.
        Ok(Anchor(Arc::new(unsafe { owned_from_raw(fd) })))
    }

    /// Wrap an already-open directory fd (any readable or `O_PATH` directory works as a dirfd). Fails `Validation` if
    /// `fd` is not a directory.
    pub fn from_fd(fd: OwnedFd) -> crate::Result<Anchor> {
        ensure_dir(fd.as_fd().as_raw_fd())?;
        Ok(Anchor(Arc::new(fd)))
    }

    /// Wrap an already-open fd (shared) as a resolution anchor **without** the directory check - used internally to
    /// statx a plain file fd (`AT_EMPTY_PATH`), where the anchor *is* the fd being stat'd, not a dirfd. Not for path
    /// resolution.
    pub(crate) fn from_shared(fd: Arc<OwnedFd>) -> Anchor {
        Anchor(fd)
    }

    /// Reuse an open directory [`File`] as an anchor, sharing its descriptor rather than duplicating it. Fails
    /// `Validation` if `f` is not a directory, like [`from_fd`](Self::from_fd).
    ///
    /// This is how a directory opened *through the reactor* - under a personality, with the kernel's confinement
    /// applied - becomes the anchor for the next step of a walk, without a second `open` from a path.
    pub fn from_file(f: &File) -> crate::Result<Anchor> {
        ensure_dir(f.as_raw_fd())?;
        Ok(Anchor(f.fd.clone()))
    }

    pub(crate) fn raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

/// Fail `Validation` unless `raw` names a directory. The anchor constructors share it so the "stat the fd, reject a
/// non-directory" check cannot drift between them.
fn ensure_dir(raw: RawFd) -> crate::Result<()> {
    let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `raw` is a live fd for the duration of this call; `st` is a valid out-pointer for fstat.
    Errno::result(unsafe { libc::fstat(raw, st.as_mut_ptr()) })?;
    // SAFETY: fstat succeeded, so `st` is initialized.
    let st = unsafe { st.assume_init() };
    if st.st_mode & libc::S_IFMT != libc::S_IFDIR {
        return Err(crate::Error::Validation("anchor fd is not a directory".into()));
    }
    Ok(())
}

/// Borrow the anchor's dirfd.
///
/// It is an `O_PATH` descriptor, so it names a directory without granting access to it: most fd-taking calls refuse one
/// (`fsync` gets `EINVAL` from `empty_fops`), while path-resolving and `f_path`-only calls accept it.
/// [`fstatfs`](crate::sync_fs::fstatfs) is in the second group.
impl AsFd for Anchor {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}

/// An open file: a real OS file descriptor, reference-counted so the reactor can keep it alive across an in-flight op
/// even after the caller drops this handle (each submitted op parks its own clone loop-side until the CQE). The fd
/// closes when the last clone - this handle plus any op still holding one -- drops, which gives close-last ordering by
/// construction, and [`FsHandle::close`] simply drops the handle. Cheap to [`Clone`].
#[derive(Clone)]
pub struct File {
    pub(crate) fd: Arc<OwnedFd>,
}

impl fmt::Debug for File {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("File").field("fd", &self.fd.as_raw_fd()).finish()
    }
}

impl File {
    /// Wrap a freshly-opened owned fd as a file handle.
    pub(crate) fn new(fd: Arc<OwnedFd>) -> File {
        File { fd }
    }

    /// Wrap a descriptor opened outside the reactor, so the reactor's fd-based ops can take it. It may name any kind of
    /// file, and unlike [`Anchor::from_fd`] it checks nothing.
    ///
    /// The descriptor carries the access it was opened with, not that of any [`Personality`]. A read or write checks
    /// only the open mode (`io_rw_init_file` in `io_uring/rw.c`), so one through a descriptor opened with more
    /// privilege than the requester holds is not refused. An op that checks access when it runs, such as
    /// [`fgetxattr`](FsHandle::fgetxattr), checks the personality it is submitted under. Deciding who may use the file
    /// is the caller's job.
    pub fn from_fd(fd: OwnedFd) -> File {
        File::new(Arc::new(fd))
    }

    /// Wrap a descriptor the caller shares, as one clone of the caller's `Arc`, so the reactor's fd-based ops take it
    /// with no `dup` and the caller keeps its own clone, as the crate makes an [`Anchor`] of a shared descriptor.
    ///
    /// The descriptor carries the access it was opened with, as [`File::from_fd`] says, and deciding who may use it is
    /// the caller's job. It closes with the last clone, which may be an op's, since an op in flight keeps its own until
    /// its completion reaps and its [`FsDone`] keeps that clone until it drops. A caller that has to close it somewhere
    /// else of its choosing takes it back from its own clone with `Arc::into_inner` once that `FsDone` is gone.
    pub fn from_shared(fd: Arc<OwnedFd>) -> File {
        File::new(fd)
    }

    /// Give back the `Arc` this handle holds, whatever else holds it, so a caller that keeps the descriptor in state of
    /// its own keeps the very `Arc` the reactor opened it into rather than a second one.
    pub fn into_shared(self) -> Arc<OwnedFd> {
        self.fd
    }

    /// The underlying raw descriptor. It stays valid for at least this handle's lifetime; the reactor independently
    /// keeps it open across any op it holds.
    pub fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    /// Take the descriptor out, so the caller owns it and closes it, when nothing else holds the file, or give the same
    /// `File` back.
    ///
    /// A clone holds it, and so does an op in flight, which parks its own clone until its completion reaps. An
    /// [`FsDone`] keeps the clone [`FsDone::file`] gives out until it drops, so drop the `FsDone` before taking the
    /// descriptor of the file it carried.
    pub fn into_fd(self) -> Result<OwnedFd, File> {
        Arc::try_unwrap(self.fd).map_err(File::new)
    }
}

/// Borrow the file's descriptor, so a pool job ([`FsConn::offload_result`]) can run blocking fd-based calls
/// ([`statx`](crate::sync_fs::statx), [`fgetxattr`](crate::sync_fs::xattr::fgetxattr)) on it. The `File` (or a clone)
/// keeps the fd open for at least the borrow.
///
/// Access was decided by whoever opened the descriptor. For a `File` the ring opened, that was the open under a
/// [`Personality`]. For one from [`File::from_fd`], it was the caller's own open. A pool job runs at the process's own
/// credentials, so a call that checks access when it runs checks those and not the requester's. Reading a ZFS NFSv4 ACL
/// is such a call (`__zpl_xattr_nfs41acl_get` checks `ACE_READ_ACL`).
impl AsFd for File {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

/// What crosses the reply channel for one completed operation.
pub(crate) struct FsOutcome {
    /// Mapped CQE result (`res` on success, `Errno` from `-res`).
    pub(crate) res: Result<i32, Errno>,
    /// The owned buffers, round-tripped back (empty for non-data ops).
    pub(crate) bufs: Vec<Vec<u8>>,
    /// For opens: the freshly-opened fd, reference-counted (the caller wraps it in a [`File`]).
    pub(crate) file: Option<Arc<OwnedFd>>,
    /// For `statx`: the kernel-filled buffer.
    pub(crate) stat: Option<Box<StatxRaw>>,
}

impl FsOutcome {
    /// The one constructor, shared by every [`FsOutcome`] construction site.
    pub(crate) fn new(
        res: Result<i32, Errno>,
        bufs: Vec<Vec<u8>>,
        file: Option<Arc<OwnedFd>>,
        stat: Option<Box<StatxRaw>>,
    ) -> FsOutcome {
        FsOutcome { res, bufs, file, stat }
    }
}

/// Where a completed op's [`FsOutcome`] goes: the blocking mpsc reply channel of the [`FsHandle`] path. The send is
/// non-blocking, and a gone receiver (an abandoned call) makes it a no-op - the outcome and its buffers are simply
/// dropped, which is safe because delivery happens only after the CQE reaped, when the kernel is done with them.
pub(crate) enum ReplyTo {
    Sync(mpsc::Sender<FsOutcome>),
}

impl ReplyTo {
    /// Deliver the outcome (consuming the endpoint; nothing blocks). Returns `Err(out)` when the receiver is already
    /// gone. Every site ignores that, since dropping the outcome frees its buffers and closes any fd it carries.
    pub(crate) fn send(self, out: FsOutcome) -> Result<(), FsOutcome> {
        match self {
            ReplyTo::Sync(tx) => tx.send(out).map_err(|e| e.0),
        }
    }
}

/// A cross-thread request to the loop. Every kernel-visible payload an op needs travels in the message and is then
/// owned by the loop's op table until the completion reaps (`Anchor` clones keep dirfds alive; buffers and paths move).
pub(crate) enum FsInject {
    Open {
        pers: u16,
        anchor: Anchor,
        path: CString,
        how: RawOpenHow,
        /// `open_parts` added `O_NONBLOCK` for the special-file guard, so the completion strips it back off the
        /// descriptor.
        guarded: bool,
        /// An [`SpecialFiles::Allow`] open's bound, a guard timer in its own op slot whose expiry cancels the open
        /// ([`core::TAG_OPEN_DEADLINE`]). `None` for a guarded open, which cannot block.
        deadline: Option<std::time::Duration>,
        reply: ReplyTo,
    },
    Rw {
        /// [`core::TAG_READV`] or [`core::TAG_WRITEV`].
        tag: u8,
        pers: u16,
        file: Arc<OwnedFd>,
        bufs: Vec<Vec<u8>>,
        off: u64,
        /// `RWF_*` for the `preadv2`/`pwritev2` forms; 0 = plain read/write.
        rw_flags: u32,
        reply: ReplyTo,
    },
    /// A read into the room past the length of one buffer ([`FsHandle::pread_spare`]).
    ReadSpare {
        pers: u16,
        file: Arc<OwnedFd>,
        buf: Vec<u8>,
        count: usize,
        off: u64,
        /// `RWF_*`, as for [`FsInject::Rw`].
        rw_flags: u32,
        reply: ReplyTo,
    },
    Fsync {
        pers: u16,
        file: Arc<OwnedFd>,
        datasync: bool,
        /// Byte range `[offset, offset + length)` synced via the SQE's `off`/`len`; `0`/`0` = whole file.
        offset: u64,
        length: u32,
        reply: ReplyTo,
    },
    /// A metadata op on an open file: ftruncate/fallocate (no payload) or fgetxattr/fsetxattr (name + value).
    FdMeta {
        tag: u8,
        pers: u16,
        file: Arc<OwnedFd>,
        name: Option<Cow<'static, CStr>>,
        value: Vec<u8>,
        off: u64,
        len64: u64,
        aux32: u32,
        reply: ReplyTo,
    },
    /// A privileged `fgetxattr` under the reactor's ambient (root) credentials (`personality = 0`), reading a
    /// `trusted.*`/`security.*` attribute a request identity cannot see (the off-loop twin of
    /// [`FsConn::fgetxattr_as_root`](core::FsConn::fgetxattr_as_root)), or `through_proc` the same read of a file held
    /// `O_PATH` by its path under `/proc/thread-self/fd` (the twin of
    /// [`FsConn::fgetxattr_proc_as_root`](core::FsConn::fgetxattr_proc_as_root)).
    FdMetaAsRoot {
        file: Arc<OwnedFd>,
        name: Cow<'static, CStr>,
        value: Vec<u8>,
        through_proc: bool,
        reply: ReplyTo,
    },
    /// A reopen of `file` through `/proc/thread-self/fd` as the personality `pers`, or as the ring owner when `None`
    /// (the twins of [`FsConn::reopen_proc`](core::FsConn::reopen_proc) and
    /// [`FsConn::reopen_proc_as_root`](core::FsConn::reopen_proc_as_root)).
    ReopenProc {
        pers: Option<u16>,
        file: Arc<OwnedFd>,
        access: ReopenAccess,
        reply: ReplyTo,
    },
    /// Remove a server-owned extended attribute. Off the ring - io_uring has no removal opcode - so the loop gates it
    /// on [`PrivilegedXattrs`] and hands it to the blocking pool (see `FsCore::remove_priv_xattr`).
    FRemoveXattr {
        file: Arc<OwnedFd>,
        name: Cow<'static, CStr>,
        reply: ReplyTo,
    },
    /// `statx` or a directory-entry op, resolved against real anchor dirfds.
    PathOp {
        tag: u8,
        pers: u16,
        a1: Anchor,
        n1: CString,
        a2: Option<Anchor>,
        n2: Option<CString>,
        flags: u32,
        len_arg: u32,
        reply: ReplyTo,
    },
    /// `LINKAT` with `AT_EMPTY_PATH`: name the already-open `file` at `a2 / n2`. Distinct from [`FsInject::PathOp`]
    /// because the source is a **file**, not an anchor dirfd plus leaf.
    LinkatFile {
        pers: u16,
        file: Arc<OwnedFd>,
        a2: Anchor,
        n2: CString,
        reply: ReplyTo,
    },
}

/// An operation submitted with [`FsHandle::start_preadv2`] (the non-blocking twin of the blocking forms): hold it, do
/// other work, then [`wait`](FsPending::wait) for the outcome.
// loom's channel types are `Debug` only when their payload is; std's are unconditionally. Derive normally, and
// hand-write the one-line impl for a model build rather than widen `FsOutcome`/`FsInject`'s bounds to suit it.
#[cfg_attr(not(loom), derive(Debug))]
pub struct FsPending {
    rx: mpsc::Receiver<FsOutcome>,
}

#[cfg(loom)]
impl fmt::Debug for FsPending {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FsPending").finish_non_exhaustive()
    }
}

impl FsPending {
    /// Block until the operation completes; returns the byte count and the round-tripped buffers. A loop shut down
    /// mid-flight yields `ECANCELED` or `ECONNABORTED`.
    pub fn wait(self) -> (crate::Result<usize>, Vec<Vec<u8>>) {
        match self.rx.recv() {
            Ok(out) => (out.res.map(|n| n as usize).map_err(Into::into), out.bufs),
            Err(_) => (Err(Errno::ECONNABORTED.into()), Vec::new()),
        }
    }

    /// Block until the op completes and hand back its **full** [`FsOutcome`] (result, buffers, opened file, `statx`
    /// buffer) - for callers that need more than [`wait`](Self::wait)'s byte count (an `open`'s `File`, a `statx`'s
    /// buffer, an `fgetxattr`'s value). A loop shut down mid-flight yields `ECONNABORTED`.
    pub(crate) fn into_outcome(self) -> crate::Result<FsOutcome> {
        self.rx.recv().map_err(|_| Errno::ECONNABORTED.into())
    }

    /// A pending already resolved to `outcome`, for tests that need to drive an awaiter's verdict without a ring behind
    /// it.
    #[cfg(all(test, not(loom)))]
    pub(crate) fn resolved(outcome: FsOutcome) -> FsPending {
        let (tx, rx) = mpsc::channel();
        tx.send(outcome).expect("the receiver is right here");
        FsPending { rx }
    }

    /// Block until a [`start_open`](FsHandle::start_open) completes and take its [`File`].
    ///
    /// [`wait`](Self::wait) reports only a byte count, which an open does not have - so without this the non-blocking
    /// open could be issued but never collected. Errors as any open does (`ENOENT`, `EACCES`, ...), or `ECONNABORTED`
    /// if the reactor stopped first.
    pub fn wait_file(self) -> crate::Result<File> {
        let out = self.into_outcome()?;
        match (out.res, out.file) {
            (Ok(_), Some(fd)) => Ok(File::new(fd)),
            (Err(e), _) => Err(e.into()),
            (Ok(_), None) => Err(Errno::EIO.into()),
        }
    }

    /// Block until a [`start_statx`](FsHandle::start_statx) completes and take the decoded [`Statx`].
    pub fn wait_statx(self) -> crate::Result<Statx> {
        let out = self.into_outcome()?;
        out.res.map_err(crate::Error::from)?;
        out.stat
            .map(|raw| Statx::from_raw(*raw))
            .ok_or_else(|| Errno::EIO.into())
    }

    /// Block until a single-buffer operation completes, returning the byte count and that buffer - the shape
    /// [`start_fgetxattr`](FsHandle::start_fgetxattr) needs, and the one-buffer convenience for
    /// [`start_preadv2`](FsHandle::start_preadv2).
    pub fn wait_buf(self) -> (crate::Result<usize>, Vec<u8>) {
        let (res, mut bufs) = self.wait();
        (res, bufs.pop().unwrap_or_default())
    }
}

/// The `Send + Sync` off-loop handle: blocking filesystem calls that submit to the loop and park on a per-call reply
/// channel. Clone freely; one loop serves any number of handle threads.
///
/// Every operation that runs on the ring takes the [`Personality`] it runs as.
/// Calls made while the loop is shutting down (or after it stopped) fail with `ECONNABORTED`.
#[cfg_attr(not(loom), derive(Debug))]
#[derive(Clone)]
pub struct FsHandle {
    pub(crate) tx: mpsc::Sender<FsInject>,
    pub(crate) shared: Arc<LoopShared>,
    /// This reactor's shared blocking-work pool, for the off-loop [`QueryPool`](query_dir::QueryPool) and generic
    /// offloaded work.
    pub(crate) pool: Arc<offload_pool::SharedPool>,
}

#[cfg(loom)]
impl fmt::Debug for FsHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FsHandle").finish_non_exhaustive()
    }
}

#[cfg(all(test, not(loom)))]
mod tests;

// ---------------------------------------------------------------------------
// loom model of the inject-vs-shutdown race
// ---------------------------------------------------------------------------
//
// Run with:  RUSTFLAGS="--cfg loom" cargo test --lib --features uring-fs loom_
//
// `FsHandle::send` checks a stop flag another thread sets and then sends, so a message can land after the loop decided
// to stop. An `Ok` from `send` must never leave its caller parked. Either the loop drains the message, or dropping the
// inject receiver drops it and its `ReplyTo`, so `call` sees a disconnect and answers `ECONNABORTED`. The model checks
// that `send`'s answer and the queue agree, and `shutdown_disconnects_a_queued_injects_reply` covers the disconnect.
#[cfg(all(test, loom))]
mod loom_tests;

mod fs_handle;
