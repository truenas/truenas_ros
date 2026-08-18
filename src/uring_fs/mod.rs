//! The io_uring filesystem reactor: asynchronous filesystem operations with
//! kernel-enforced per-operation identity.
//!
//! This is the asynchronous counterpart of [`crate::sync_fs`], built on the
//! crate's shared io_uring engine (`uring`). An open returns a **real process
//! fd wrapped in an `Arc<OwnedFd>`** (closed by its last reference) and every
//! data op runs against that fd. Two rules shape the whole API:
//!
//! - **Personality is mandatory.** Every consumer-staged operation carries a
//!   [`Personality`] — a kernel-registered credential snapshot stamped into
//!   the SQE, under which the kernel itself performs its permission checks
//!   (`override_creds` around issue, io-wq included). There is no
//!   ambient-identity variant: the daemon's own identity is minted like any
//!   other via [`UringFs::register_self`], and `sqe.personality = 0` (the
//!   ring owner's ambient creds) is unreachable from this API. Only
//!   [`FsHandle::close`] is exempt — teardown consults no credentials and
//!   must be stageable from [`File`]'s `Drop`.
//! - **Resolution is anchored.** No call takes an absolute path. [`Anchor`]
//!   is a long-lived real directory fd; `open` resolves a **relative**,
//!   multi-component path against it (confine it in-kernel with
//!   [`ResolveFlag::RESOLVE_BENEATH`](crate::sync_fs::ResolveFlag)), and
//!   every subsequent operation is fd-based on the opened [`File`].
//!
//! # Consumer shape
//!
//! **Standalone** ([`UringFs`]) owns its own ring and loop. The core is
//! host-agnostic: an embedding host can drive the same core on its own ring
//! via [`FsConn`] callbacks — under the `net-server` feature the io_uring net
//! server does this, interleaving fs and socket ops on one ring.
//!
//! The standalone loop is synchronous and single-threaded ([`UringFs::run`],
//! `!Send`); concurrency comes from the ring. Off-loop
//! callers use the `Send + Sync` [`FsHandle`], whose blocking calls submit over
//! an inject channel and park on a per-call reply channel:
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
//! Buffers are **owned round-trips**: a `Vec<u8>` moves in with the request
//! and comes back with the result, because the kernel may touch it until the
//! completion reaps — even if the caller lost interest. Reads fill each
//! buffer up to its current `len()`; the returned count says how much is
//! valid (short only at end-of-file).
//!
//! # Naming
//!
//! Method names follow their syscalls. The **`p`** prefix means *positional*
//! — [`preadv2`](FsHandle::preadv2)/[`pwritev2`](FsHandle::pwritev2) take an
//! explicit file offset, exactly as `preadv2(2)`/`pwritev2(2)` do. Every data
//! op here is positional: ops carry their own offset rather than advance a
//! shared file position, so there is no offsetless `read`/`write` and no
//! `seek`. Those two are also the *whole* data surface — a single-buffer or
//! unflagged variant would be a second spelling of one submission, so pass a
//! one-element `bufs` and [`RwFlags::empty()`]. The **`at`** suffix is
//! reserved for its usual meaning, the
//! dirfd-relative syscall family ([`renameat`](FsHandle::renameat),
//! [`unlinkat`](FsHandle::unlinkat), [`mkdirat`](FsHandle::mkdirat), …), where
//! the anchor dirfd is what the name refers to.
//!
//! # What operates on what
//!
//! The API is fd-first, so that `open → metadata → close` is the natural
//! shape and a file is named exactly once:
//!
//! - **On an open [`File`]:** [`preadv2`](FsHandle::preadv2) /
//!   [`pwritev2`](FsHandle::pwritev2) (vectored, carrying [`RwFlags`]),
//!   [`splice_from_pipe`](FsHandle::splice_from_pipe) for a body that never
//!   enters userspace, [`fsync`](FsHandle::fsync) /
//!   [`fdatasync`](FsHandle::fdatasync),
//!   [`fgetxattr`](FsHandle::fgetxattr) / [`fsetxattr`](FsHandle::fsetxattr) /
//!   [`fremovexattr`](FsHandle::fremovexattr),
//!   [`ftruncate`](FsHandle::ftruncate), [`fallocate`](FsHandle::fallocate),
//!   [`fadvise`](FsHandle::fadvise), and [`close`](FsHandle::close).
//! - **[`statx`](FsHandle::statx)** resolves a name against an anchor; for an
//!   already-open file, [`fstatx`](FsHandle::fstatx) stats it directly
//!   (`STATX` with `AT_EMPTY_PATH` on the plain fd — the `fstat` equivalent),
//!   as does [`statx_anchor`](FsHandle::statx_anchor) for an anchor's own
//!   dirfd.
//! - **Directory entries** — [`mkdirat`](FsHandle::mkdirat),
//!   [`unlinkat`](FsHandle::unlinkat), [`rmdirat`](FsHandle::rmdirat),
//!   [`renameat`](FsHandle::renameat), [`symlinkat`](FsHandle::symlinkat),
//!   [`linkat`](FsHandle::linkat) — take an [`Anchor`] plus a validated
//!   [`Leaf`]. These have no fd-only form in any kernel (you cannot unlink
//!   an fd); dirfd-plus-name *is* their fd-based shape.
//! - **[`linkat_file`](FsHandle::linkat_file)** is the exception that gives an
//!   *already-open* file a name (`AT_EMPTY_PATH`) — the only way to name an
//!   `O_TMPFILE`, and so the commit step of a durable create.
//! - **Blocking tails** ([`FsConn::offload_result`]) operate on the open
//!   [`File`] too: it is [`AsFd`], so a pool job makes blocking fd-based
//!   calls on it — descriptors, never names.
//!
//! # Building on top: durable create, confinement, server-owned metadata
//!
//! Four facilities exist because a service storing data on behalf of remote
//! users needs them and cannot assemble them safely from the raw ops:
//!
//! - **Durable create.** Open `O_TMPFILE` (no `O_EXCL`), write, sync, then
//!   [`linkat_file`](FsHandle::linkat_file) to a private name and
//!   [`renameat`](FsHandle::renameat) onto the target. Nothing is visible
//!   until the rename, which replaces atomically, so a reader sees the old
//!   file or the new one and never a partial write — and an abandoned or
//!   crashed create leaves *nothing* to clean up, because an unnamed inode
//!   simply disappears. (Do not fuse these into an
//!   [`IOSQE_IO_LINK`](crate::uring_fs) chain: filesystem opcodes do not break
//!   chains on failure, so a failed link would let the rename run anyway.)
//! - **Confinement.** [`open_confined`](FsHandle::open_confined) applies
//!   [`CONFINED_RESOLVE`] in a way the caller cannot weaken, and
//!   [`mkdir_path`](FsHandle::mkdir_path) creates a nested path the only sound
//!   way — alternating confined walks with single-[`Leaf`] `mkdirat`s, because
//!   `mkdirat` itself honours no resolve flags.
//! - **Server-owned metadata.** [`PrivilegedXattrs`] lets declared
//!   `trusted.*` attributes be written under the reactor's own credentials, so
//!   a service can keep metadata that the user who owns the file can neither
//!   read, change, nor see.
//! - **Batched blocking offload.** [`FsConn::offload_result`] runs the
//!   blocking, opcode-less part of a request as one pool job — one job per
//!   request tail, not one per call — and delivers its `crate::Result` back
//!   on the loop. The job contract lives at [`offload`](FsConn::offload).
//!
//! # Acting as other users
//!
//! [`UringFs::register_self`] mints the daemon's own identity. To act as an
//! *authenticated peer*, use the [`CredBroker`] — a tiny forked process
//! that impersonates a user just long enough to snapshot their credentials,
//! so the reactor process never changes identity itself:
//!
//! ```no_run
//! use truenas_ros::uring_fs::{AsUser, UringFs, CredBroker, FsConfig};
//!
//! // Every ring first, then the broker (it inherits the ring fds), then
//! // threads. Both halves of that ordering are load-bearing — see
//! // `CredBroker::spawn`.
//! let afs = UringFs::new(FsConfig::default())?;
//! let broker = CredBroker::spawn(&[&afs])?; // main loses CAP_SETUID here
//! let creds = broker.handle(0)?;
//!
//! // … a session authenticates as uid 1000 …
//! let who = creds.register(&AsUser::new(1000, 1000).groups(vec![4, 27]))?;
//! // Every op stamped `who` is checked by the kernel as that user; when
//! // the session ends:
//! creds.unregister(who)?;
//! # Ok::<(), truenas_ros::Error>(())
//! ```
//!
//! Registering is not free (an IPC round trip plus the impersonation window),
//! and every live id pins a kernel credential in a per-ring `u16` space, so
//! wrap the broker in an [`IdentityCache`] to register once per *identity*
//! rather than once per connection.
//!
//! A brokered personality carries that user's authority and nothing more.
//! Where a service must resolve a path for a user entitled to the object but
//! not to traverse every directory above it, opt in with [`Caps`] — allowed
//! by a ceiling fixed at [`CredBroker::spawn_with_caps`], before the
//! privilege drop, so nothing that happens to the reactor afterwards can
//! widen it. Read [`Caps::DAC_READ_SEARCH`] first: it is a whole-filesystem
//! read grant, not a traverse-only one, and Linux offers nothing narrower.
//!
//! # Embedding in another host
//!
//! The reactor core ([`FsConn`]/[`FsDone`]) is deliberately host-agnostic: a
//! single-threaded event loop that owns its own `Engine` can drive fs ops
//! inline and receive completions as in-loop callbacks, interleaving fs and
//! its own SQEs on one ring. Under the `net-server` feature the io_uring net
//! server drives the core this way.

mod broker;
// The mint-once-per-key protocol behind `IdentityCache`, kept separate so it
// can be model-checked without a broker process to fork.
mod single_flight;
// The elastic blocking-work pool behind `FsConn::offload` and the off-loop
// helpers — generic machinery, kept apart from the fs-domain modules that
// submit to it.
pub(crate) mod offload_pool;
// `pub(crate)` so an embedding host (a server driving `FsCore` on its own
// can drive an `FsCore` on the server's own ring; the standalone host is
// `uring_fs`'s own `UringFs`.
pub(crate) mod core;
// Exported unconditionally, not just with `net-server`. `FsConn` is the
// callback submission facade — the only way to run several operations back to
// back without parking a thread between them — and an out-of-tree consumer
// driving a standalone [`UringFs`] needs it exactly as much as an embedded
// server does. Gating it on the server role made the whole on-loop surface
// unreachable for anyone else.
pub use core::{DirWalk, FsConn, FsDone, NameBatch};

pub mod query_dir;
pub use query_dir::{
    query_directory, CopyHandle, DirEntry, EnrichSpec, Order, QueryDir,
    QueryHandle, QueryOptions, QueryPool, XattrNamespaces,
};

pub mod query_tree;
pub use query_tree::{
    query_tree, QueryTree, TreeCursor, TreeEntry, TreeOptions,
};
// `pub(crate)` so a `net` server can reuse the fixed-file-xattr capability
// probe (the 6.13 floor is not visible to `REGISTER_PROBE`); the standalone
// reactor is `UringFs`.
pub(crate) mod host;

pub use broker::{
    AsUser, BrokerReactor, Caps, CredBroker, CredHandle, IdentityCache, Lease,
    MAX_GROUPS, MAX_RINGS,
};
pub use host::{FsConfig, ShutdownHandle, UringFs};

/// The credential-broker request decoder, exposed to the fuzz crate (`fuzz/`)
/// under `__fuzz` only — `broker` is a private module. Never part of the stable
/// API.
///
/// Driven by `fuzz/fuzz_targets/broker_request.rs`. This is the sharpest
/// privilege boundary in the crate: the broker child holds `CAP_SETUID` and
/// mints personalities from whatever [`decode_request`](fuzz::decode_request)
/// accepts, so the target asserts that an accepted request is always within the
/// ring count, the group cap, the exact declared length, and the spawn-time
/// capability ceiling.
#[cfg(feature = "__fuzz")]
pub mod fuzz {
    pub use super::broker::{decode_groups, decode_request, Req};

    /// [`Leaf::to_cstring`](super::Leaf) is crate-internal, but
    /// `fuzz/fuzz_targets/path_leaf.rs` needs it to prove its
    /// `expect("validated: no interior NUL")` unreachable for every name
    /// [`Leaf::new`](super::Leaf::new) accepts.
    pub fn leaf_to_cstring(leaf: super::Leaf<'_>) -> std::ffi::CString {
        leaf.to_cstring()
    }
}

use crate::errno::{retry_on_eintr, Errno};
use crate::fd::owned_from_raw;
use crate::path::TnPath;
use crate::sync_fs::openat2::RawOpenHow;
use crate::sync_fs::{
    AtFlags, Mode, OFlag, OpenHow, RenameFlags, ResolveFlag, Statfs, Statx,
    StatxMask, StatxRaw, ZfsAttr,
};
use crate::uring::wake::LoopShared;
use std::ffi::{CStr, CString};
use std::fmt;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd};
// The inject channel and the shared flags are loom-modelled (see
// `loom_tests` at the bottom), so these come from `crate::sync` — std's
// outside `--cfg loom`.
use crate::sync::mpsc;
use crate::sync::Arc;

/// The `AT_*` flags an async `statx` submits. `statx` follows a terminal
/// symlink unless told not to; the confined surface inverts that, forcing
/// `AT_SYMLINK_NOFOLLOW` by default so a peer-planted leaf symlink can't
/// redirect the stat out of the anchor. Passing `AT_SYMLINK_FOLLOW` — which
/// `statx` does not take natively — is the caller's opt-in to follow (stat the
/// target), mirroring `linkat`; it is stripped before the syscall.
pub(crate) fn statx_at_flags(flags: AtFlags) -> u32 {
    let follow = flags.contains(AtFlags::AT_SYMLINK_FOLLOW)
        && !flags.contains(AtFlags::AT_SYMLINK_NOFOLLOW);
    let base = flags.difference(AtFlags::AT_SYMLINK_FOLLOW);
    if follow {
        base.bits() as u32
    } else {
        (base | AtFlags::AT_SYMLINK_NOFOLLOW).bits() as u32
    }
}

/// Resolution rules that keep a path inside its [`Anchor`], as a set a caller
/// can demand rather than merely receive by default.
///
/// - `RESOLVE_BENEATH` — no component may resolve above the anchor, and an
///   absolute path is refused rather than resolved from `/`.
/// - `RESOLVE_NO_SYMLINKS` — no symlink is followed, anywhere in the path, so
///   a link planted inside the tree cannot redirect out of it.
/// - `RESOLVE_NO_XDEV` — resolution may not cross a mount point. On ZFS that
///   means a nested dataset, or a `.zfs/snapshot` automount, terminates the
///   walk instead of silently serving files from another filesystem.
///
/// These are enforced by the kernel during resolution, not re-implemented
/// here; see [`FsHandle::open_confined`].
pub const CONFINED_RESOLVE: ResolveFlag = ResolveFlag::RESOLVE_BENEATH
    .union(ResolveFlag::RESOLVE_NO_SYMLINKS)
    .union(ResolveFlag::RESOLVE_NO_XDEV);

/// Validate an open's `(path, how)` pair and produce the payloads an
/// `OPENAT2` inject carries — shared by the blocking [`FsHandle::open`] and the
/// async `rt` handle so both surfaces enforce identical rules.
///
/// The path may be **multi-component** and is resolved by the kernel against
/// the anchor dirfd. It is **confined to the anchor by default**
/// (`RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS`, applied when the caller set no
/// `resolve` policy of its own). A caller that sets its own `resolve` — e.g.
/// dropping `RESOLVE_BENEATH` — opts out of confinement and may then pass an
/// **absolute** path, which the kernel resolves from the filesystem root
/// (ignoring the dirfd), per `openat2(2)`. Opens return a real fd, so
/// `O_CLOEXEC` is accepted.
pub(crate) fn open_parts<P: ?Sized + TnPath>(
    path: &P,
    how: OpenHow,
) -> crate::Result<(CString, RawOpenHow)> {
    let cpath: CString = path.with_tn_path(|c| c.to_owned())?;
    if cpath.as_bytes().is_empty() {
        return Err(crate::Error::Validation(
            "uring_fs open: empty path".into(),
        ));
    }
    let mut raw = how.to_raw();
    // Confine to the anchor by default: an unset `resolve` would let `..` or a
    // symlink escape. A caller that sets its own `resolve` (e.g. to drop
    // `RESOLVE_BENEATH` for an absolute path) opts out deliberately.
    if raw.resolve == 0 {
        raw.resolve = ResolveFlag::RESOLVE_BENEATH
            .union(ResolveFlag::RESOLVE_NO_SYMLINKS)
            .bits();
    }
    Ok((cpath, raw))
}

/// A registered io_uring personality: a kernel-held snapshot of one
/// identity's credentials (fsuid/fsgid, supplementary groups, capabilities,
/// LSM label), stamped into every SQE this module submits. The kernel — not
/// the library — performs each operation's permission checks under it.
///
/// Mint one for the calling process with [`UringFs::register_self`]. Ids are
/// ring-local and never 0 (the kernel's allocator starts at 1), so a
/// `Personality` always names a real registration; a stale id (unregistered,
/// or from another ring) fails the operation with `EINVAL` at submission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Personality(pub(crate) u16);

impl Personality {
    /// The raw kernel id.
    pub fn id(self) -> u16 {
        self.0
    }

    /// Name an id registered elsewhere on **this** ring — the form a
    /// credential broker's reply takes once it has registered an identity
    /// on the reactor's behalf. Returns `None` for `0`, which is not a valid
    /// personality: **`sqe.personality == 0` means "no credential override",
    /// so an op stamped with it runs under the reactor thread's ambient
    /// credentials (the root daemon), bypassing the kernel's per-op identity
    /// check entirely.** The kernel never allocates id 0 (`XA_FLAGS_ALLOC1`),
    /// so a broker reply of 0 is malformed; refusing it keeps the
    /// "personality-0 is unreachable from this API" invariant true by
    /// construction.
    ///
    /// Forging a *nonzero* id is not a privilege hole: one this ring never
    /// registered fails its operation with `EINVAL` at submission (the kernel
    /// resolves the id and refuses rather than falling back to ambient
    /// credentials). An id from a *different* ring is equally meaningless
    /// here — personalities are ring-local.
    pub fn from_raw(id: u16) -> Option<Personality> {
        (id != 0).then_some(Personality(id))
    }
}

tn_bitflags! {
    /// Per-operation flags for the `preadv2`/`pwritev2` forms
    /// ([`FsHandle::preadv2`], [`FsHandle::pwritev2`] and their [`FsConn`]
    /// twins) — the kernel's `RWF_*` set, carried in the SQE's read/write
    /// flags field.
    ///
    /// These are not a separate opcode: `READV`/`WRITEV` already read this
    /// field, so the flagged forms cost nothing extra. An **unsupported flag
    /// fails the operation** with `EOPNOTSUPP` at submission rather than being
    /// ignored (`kiocb_set_rw_flags`), which makes support detectable per call
    /// — there is nothing to probe up front, and a silently-dropped durability
    /// flag is impossible.
    ///
    /// Support is per-filesystem and narrower than the flag list suggests.
    /// Measured against ZFS (identical results on tmpfs):
    ///
    /// | flag | ZFS | observed | why |
    /// |---|---|---|---|
    /// | [`RWF_DSYNC`](Self::RWF_DSYNC), [`RWF_SYNC`](Self::RWF_SYNC) | yes | `Ok` | the durability pair |
    /// | [`RWF_APPEND`](Self::RWF_APPEND), [`RWF_NOAPPEND`](Self::RWF_NOAPPEND) | yes | `Ok` | |
    /// | [`RWF_ATOMIC`](Self::RWF_ATOMIC) | **no** | `EOPNOTSUPP` | needs `FMODE_CAN_ATOMIC_WRITE`, which ZFS does not set |
    /// | [`RWF_DONTCACHE`](Self::RWF_DONTCACHE) | **no** | `EOPNOTSUPP` | needs `FOP_DONTCACHE` (Linux ≥ 6.14), which ZFS does not set |
    /// | [`RWF_NOWAIT`](Self::RWF_NOWAIT) | **no** | `EOPNOTSUPP` | needs `FMODE_NOWAIT` on the file; io_uring drives its own non-blocking attempt regardless |
    /// | [`RWF_HIPRI`](Self::RWF_HIPRI) | **no** | `EINVAL` | requires an `IOPOLL` ring, which this reactor does not create |
    ///
    /// A durability note worth measuring rather than assuming: pairing
    /// [`RWF_DSYNC`](Self::RWF_DSYNC) with a write can replace a following
    /// `fdatasync`, but on ZFS a synchronous write goes through the ZIL, which
    /// for large writes can cost more than one trailing sync of the whole
    /// range. Benchmark before choosing it as a default.
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
        /// Torn-write protection: the write lands whole or not at all.
        /// Needs hardware and filesystem support, plus a size and alignment
        /// within the limits `statx` reports.
        RWF_ATOMIC = 0x00000040;
        /// Drop the page cache for this range once the I/O completes.
        RWF_DONTCACHE = 0x00000080;
    }
}

/// Namespace every [`PrivilegedXattrs`] prefix must sit under.
const TRUSTED_NS: &[u8] = b"trusted.";

/// Which extended attributes may be **written** under the reactor's ambient
/// credentials instead of the request's [`Personality`].
///
/// The reactor normally refuses `personality == 0` on every fd operation,
/// because that is "no credential override" — the op would run as the daemon
/// (root) rather than the requesting identity. Reads have one sanctioned
/// exception already ([`FsHandle::fgetxattr_as_root`]); this is its write-side
/// counterpart, and it is an allowlist rather than a blanket permit because a
/// privileged *write* is a far sharper tool than a privileged read.
///
/// # Why it exists
///
/// A server that stores its own metadata about a file — and needs that
/// metadata to survive users who can write the file itself — has to put it
/// somewhere unprivileged code cannot reach. On ZFS the `trusted.` namespace
/// is exactly that: get, set, **and list** are all gated on `CAP_SYS_ADMIN`,
/// so an unprivileged local, SMB, or NFS user cannot read it, change it, or
/// even discover that it is there. Writing it therefore cannot go through the
/// requesting identity, which by design has no such privilege.
///
/// # Why only `trusted.`
///
/// [`allow_prefix`](Self::allow_prefix) refuses every other namespace, and the
/// refusals are the point:
///
/// - `security.` would permit writing `security.capability`, which grants file
///   capabilities — a direct privilege-escalation primitive.
/// - `system.` holds the ACLs (`system.posix_acl_access`,
///   `system.nfs4_acl_xdr`); writing those as root would let a caller grant
///   itself access it was just denied.
/// - `user.` needs no privilege at all, so allowing it would silently promote
///   ordinary writes to root for no benefit.
///
/// # Scope
///
/// The policy is set on the reactor before it runs and cannot change while it
/// does — [`UringFs::run`] takes `&mut self`, so the borrow checker, not a
/// convention, prevents a later call. An empty policy (the default) permits
/// nothing.
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
    /// Errors unless `prefix` is under `trusted.` and names at least one byte
    /// beyond it — see the type docs for why the other namespaces are refused,
    /// and why a bare `trusted.` (which would cover the whole namespace) is
    /// too broad to accept.
    pub fn allow_prefix(mut self, prefix: &CStr) -> crate::Result<Self> {
        let bytes = prefix.to_bytes();
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

/// Cache advice for [`FsHandle::fadvise`] — the `POSIX_FADV_*` values.
///
/// On ZFS these are not page-cache-only hints: `zpl_fadvise`
/// (`module/os/linux/zfs/zpl_file.c`) maps [`WillNeed`](Self::WillNeed) to a
/// `dmu_prefetch` into the ARC and [`DontNeed`](Self::DontNeed) to a
/// `dmu_evict_range` out of it, on top of the generic page-cache handling. So
/// this is the API that reaches the cache that actually matters here.
///
/// It has no `preadv2`/`pwritev2` equivalent. [`RwFlags::RWF_DONTCACHE`] would
/// cover the drop half more cheaply — no second syscall, no window where the
/// pages linger — but ZFS does not set `FOP_DONTCACHE`, so it fails
/// `EOPNOTSUPP` (see the [`RwFlags`] support table). There is no read-ahead
/// flag at all, so [`WillNeed`](Self::WillNeed) has no equivalent even in
/// principle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum Advice {
    /// No advice; resets any previously set pattern for the range.
    Normal = 0,
    /// Expect random access — read-ahead is of little use.
    Random = 1,
    /// Expect sequential access, so read further ahead. Worth setting on the
    /// read side of a streamed object.
    Sequential = 2,
    /// Fetch the range into cache now. On ZFS an ARC prefetch.
    WillNeed = 3,
    /// Release the range's cached data. On ZFS an ARC eviction, which is the
    /// point of calling it after a large write has been synced: the bytes are
    /// durable and will not be read back soon, so they should not be holding
    /// ARC that a working set needs.
    DontNeed = 4,
    /// Expect a single access in the near future.
    NoReuse = 5,
}

/// A validated **single path component** — the only name a directory-entry
/// operation will accept.
///
/// This is a security boundary, not decoration. The `*at` opcodes honour no
/// `RESOLVE_*` flags, so a name containing `/` or `..` would walk wherever
/// it pleased, out of the anchor and across the filesystem; confining them
/// to one component is what makes an [`Anchor`] an actual confinement.
/// (Multi-component resolution exists in exactly one place —
/// [`FsHandle::open`] — where `RESOLVE_BENEATH` lets the *kernel* enforce
/// containment.)
///
/// Rejected: empty, `.`, `..`, anything containing `/` or an interior NUL.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Leaf<'a>(&'a [u8]);

impl<'a> Leaf<'a> {
    /// Validate `name` as a single component.
    pub fn new<S: AsRef<[u8]> + ?Sized>(
        name: &'a S,
    ) -> crate::Result<Leaf<'a>> {
        let b = name.as_ref();
        let bad = |why: &str| {
            Err(crate::Error::Validation(format!(
                "not a single path component ({why})"
            )))
        };
        match b {
            [] => return bad("empty"),
            b"." => return bad("`.`"),
            b".." => return bad("`..`"),
            _ => {}
        }
        if b.contains(&b'/') {
            return bad("contains `/`");
        }
        if b.contains(&0) {
            return bad("contains NUL");
        }
        Ok(Leaf(b))
    }

    pub(crate) fn to_cstring(self) -> CString {
        CString::new(self.0).expect("validated: no interior NUL")
    }
}

/// A long-lived **real** directory fd that anchors every path resolution.
///
/// The fs API exposes no absolute-path calls: `open` resolves relative to an
/// `Anchor` (kernel constraint, not style — io_uring's path ops reject
/// fixed-table dirfds, so anchors must be real fds). Bootstrap one at setup
/// time with [`Anchor::open`] (the single absolute open, outside the async
/// surface) or wrap an existing directory fd with [`Anchor::from_fd`].
///
/// Cloning is cheap (`Arc`); an in-flight open holds a clone, so the dirfd
/// can never close — or be reused by another file — under a submitted op.
#[derive(Clone, Debug)]
pub struct Anchor(Arc<OwnedFd>);

impl Anchor {
    /// Open a directory as an anchor (`O_PATH | O_DIRECTORY | O_CLOEXEC`) —
    /// a plain blocking syscall for setup time, and this module's one
    /// absolute-path entry point.
    pub fn open<P: ?Sized + TnPath>(path: &P) -> crate::Result<Anchor> {
        let fd = path.with_tn_path(|c| {
            retry_on_eintr(|| unsafe {
                // SAFETY: `c` is a valid NUL-terminated path for the call.
                libc::open(
                    c.as_ptr(),
                    libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
                )
            })
        })??;
        // SAFETY: on success `open` returns a fresh owned descriptor.
        Ok(Anchor(Arc::new(unsafe { owned_from_raw(fd) })))
    }

    /// Wrap an already-open directory fd (any readable or `O_PATH` directory
    /// works as a dirfd). Fails `Validation` if `fd` is not a directory.
    pub fn from_fd(fd: OwnedFd) -> crate::Result<Anchor> {
        ensure_dir(fd.as_fd().as_raw_fd())?;
        Ok(Anchor(Arc::new(fd)))
    }

    /// Wrap an already-open fd (shared) as a resolution anchor **without** the
    /// directory check — used internally to statx a plain file fd
    /// (`AT_EMPTY_PATH`), where the anchor *is* the fd being stat'd, not a
    /// dirfd. Not for path resolution.
    pub(crate) fn from_shared(fd: Arc<OwnedFd>) -> Anchor {
        Anchor(fd)
    }

    /// Reuse an open directory [`File`] as an anchor, sharing its descriptor
    /// rather than duplicating it. Fails `Validation` if `f` is not a
    /// directory, like [`from_fd`](Self::from_fd).
    ///
    /// This is how a directory opened *through the reactor* — under a
    /// personality, with the kernel's confinement applied — becomes the anchor
    /// for the next step of a walk, without a second `open` from a path.
    pub fn from_file(f: &File) -> crate::Result<Anchor> {
        ensure_dir(f.as_raw_fd())?;
        Ok(Anchor(f.fd.clone()))
    }

    pub(crate) fn raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

/// Fail `Validation` unless `raw` names a directory. The anchor constructors
/// share it so the "stat the fd, reject a non-directory" check cannot drift
/// between them.
fn ensure_dir(raw: RawFd) -> crate::Result<()> {
    let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `raw` is a live fd for the duration of this call; `st` is a
    // valid out-pointer for fstat.
    Errno::result(unsafe { libc::fstat(raw, st.as_mut_ptr()) })?;
    // SAFETY: fstat succeeded, so `st` is initialized.
    let st = unsafe { st.assume_init() };
    if st.st_mode & libc::S_IFMT != libc::S_IFDIR {
        return Err(crate::Error::Validation(
            "anchor fd is not a directory".into(),
        ));
    }
    Ok(())
}

/// Borrow the anchor's dirfd.
///
/// It is an `O_PATH` descriptor, so it names a directory without granting
/// access to it: most fd-taking calls refuse one (`fsync` gets `EINVAL` from
/// `empty_fops`), while path-resolving and `f_path`-only calls accept it.
/// [`fstatfs`](crate::sync_fs::fstatfs) is in the second group.
impl AsFd for Anchor {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}

/// An open file: a real OS file descriptor, reference-counted so the reactor
/// can keep it alive across an in-flight op even after the caller drops this
/// handle (each submitted op parks its own clone loop-side until the CQE). The
/// fd closes when the last clone — this handle plus any op still holding one —
/// drops, which gives close-last ordering by construction; [`FsHandle::close`]
/// simply drops the handle. Cheap to [`Clone`].
#[derive(Clone)]
pub struct File {
    pub(crate) fd: Arc<OwnedFd>,
}

impl fmt::Debug for File {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("File")
            .field("fd", &self.fd.as_raw_fd())
            .finish()
    }
}

impl File {
    /// Wrap a freshly-opened owned fd as a file handle.
    pub(crate) fn new(fd: Arc<OwnedFd>) -> File {
        File { fd }
    }

    /// The underlying raw descriptor. It stays valid for at least this handle's
    /// lifetime; the reactor independently keeps it open across any op it holds.
    pub fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

/// Borrow the file's descriptor — what lets a pool job
/// ([`FsConn::offload_result`]) run blocking fd-based calls
/// ([`statx`](crate::sync_fs::statx),
/// [`fgetxattr`](crate::sync_fs::xattr::fgetxattr)) against a descriptor the
/// ring opened under a [`Personality`]: the access decision was made at that
/// open, so an fd-based call needs no identity re-attached. The `File` (or a
/// clone) keeps the fd open for at least the borrow.
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
    /// For opens: the freshly-opened fd, reference-counted (the caller wraps it
    /// in a [`File`]).
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
        FsOutcome {
            res,
            bufs,
            file,
            stat,
        }
    }
}

/// Where a completed op's [`FsOutcome`] goes: the blocking mpsc reply channel
/// of the [`FsHandle`] path. The send is non-blocking, and a gone receiver (an
/// abandoned call) makes it a no-op — the outcome and its buffers are simply
/// dropped, which is safe because delivery happens only after the CQE reaped,
/// when the kernel is done with them.
pub(crate) enum ReplyTo {
    Sync(mpsc::Sender<FsOutcome>),
}

impl ReplyTo {
    /// Deliver the outcome (consuming the endpoint; nothing blocks).
    /// Returns `Err(out)` when the receiver is already gone (an abandoned
    /// call, a dropped future) — most sites ignore it, but a successful
    /// `open` uses it to detect that no [`File`] will be built to
    /// orphan-close the slot, and stages the close itself.
    pub(crate) fn send(self, out: FsOutcome) -> Result<(), FsOutcome> {
        match self {
            ReplyTo::Sync(tx) => tx.send(out).map_err(|e| e.0),
        }
    }
}

/// A cross-thread request to the loop. Every kernel-visible payload an op
/// needs travels in the message and is then owned by the loop's op table
/// until the completion reaps (`Anchor` clones keep dirfds alive; buffers
/// and paths move).
pub(crate) enum FsInject {
    Open {
        pers: u16,
        anchor: Anchor,
        path: CString,
        how: RawOpenHow,
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
    Fsync {
        pers: u16,
        file: Arc<OwnedFd>,
        datasync: bool,
        /// Byte range `[offset, offset + length)` synced via the SQE's
        /// `off`/`len`; `0`/`0` = whole file.
        offset: u64,
        length: u32,
        reply: ReplyTo,
    },
    /// A metadata op on an open file: ftruncate/fallocate (no payload) or
    /// fgetxattr/fsetxattr (owned name + value).
    FdMeta {
        tag: u8,
        pers: u16,
        file: Arc<OwnedFd>,
        name: Option<CString>,
        value: Vec<u8>,
        off: u64,
        len64: u64,
        aux32: u32,
        reply: ReplyTo,
    },
    /// A privileged `fgetxattr` under the reactor's ambient (root) credentials
    /// (`personality = 0`), reading a `trusted.*`/`security.*` attribute a
    /// request identity cannot see (the off-loop twin of
    /// [`FsConn::fgetxattr_as_root`](core::FsConn::fgetxattr_as_root)).
    FdMetaAsRoot {
        file: Arc<OwnedFd>,
        name: CString,
        value: Vec<u8>,
        reply: ReplyTo,
    },
    /// Remove a server-owned extended attribute. Off the ring — io_uring has
    /// no removal opcode — so the loop gates it on [`PrivilegedXattrs`] and
    /// hands it to the blocking pool
    /// (see `FsCore::remove_priv_xattr`).
    FRemoveXattr {
        file: Arc<OwnedFd>,
        name: CString,
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
    /// `LINKAT` with `AT_EMPTY_PATH`: name the already-open `file` at
    /// `a2 / n2`. Distinct from [`FsInject::PathOp`] because the source is a
    /// **file**, not an anchor dirfd plus leaf.
    LinkatFile {
        pers: u16,
        file: Arc<OwnedFd>,
        a2: Anchor,
        n2: CString,
        reply: ReplyTo,
    },
}

/// An operation submitted with [`FsHandle::start_preadv2`] (the
/// non-blocking twin of the blocking forms): hold it, do other work,
/// then [`wait`](FsPending::wait) for the outcome.
// loom's channel types are `Debug` only when their payload is; std's are
// unconditionally. Derive normally, and hand-write the one-line impl for a
// model build rather than widen `FsOutcome`/`FsInject`'s bounds to suit it.
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
    /// Block until the operation completes; returns the byte count and the
    /// round-tripped buffers. A loop shut down mid-flight yields
    /// `ECONNABORTED`; an operation cancelled by a dropped [`File`]
    /// yields `ECANCELED`.
    pub fn wait(self) -> (crate::Result<usize>, Vec<Vec<u8>>) {
        match self.rx.recv() {
            Ok(out) => {
                (out.res.map(|n| n as usize).map_err(Into::into), out.bufs)
            }
            Err(_) => (Err(Errno::ECONNABORTED.into()), Vec::new()),
        }
    }

    /// Block until the op completes and hand back its **full** [`FsOutcome`]
    /// (result, buffers, opened file, `statx` buffer) — for callers that need
    /// more than [`wait`](Self::wait)'s byte count (an `open`'s `File`, a
    /// `statx`'s buffer, an `fgetxattr`'s value). A loop shut down mid-flight
    /// yields `ECONNABORTED`.
    pub(crate) fn into_outcome(self) -> crate::Result<FsOutcome> {
        self.rx.recv().map_err(|_| Errno::ECONNABORTED.into())
    }

    /// Block until a [`start_open`](FsHandle::start_open) completes and take
    /// its [`File`].
    ///
    /// [`wait`](Self::wait) reports only a byte count, which an open does not
    /// have — so without this the non-blocking open could be issued but never
    /// collected. Errors as any open does (`ENOENT`, `EACCES`, …), or
    /// `ECONNABORTED` if the reactor stopped first.
    pub fn wait_file(self) -> crate::Result<File> {
        let out = self.into_outcome()?;
        match (out.res, out.file) {
            (Ok(_), Some(fd)) => Ok(File::new(fd)),
            (Err(e), _) => Err(e.into()),
            (Ok(_), None) => Err(Errno::EIO.into()),
        }
    }

    /// Block until a [`start_statx`](FsHandle::start_statx) completes and take
    /// the decoded [`Statx`].
    pub fn wait_statx(self) -> crate::Result<Statx> {
        let out = self.into_outcome()?;
        out.res.map_err(crate::Error::from)?;
        out.stat
            .map(|raw| Statx::from_raw(*raw))
            .ok_or_else(|| Errno::EIO.into())
    }

    /// Block until a single-buffer operation completes, returning the byte
    /// count and that buffer — the shape
    /// [`start_fgetxattr`](FsHandle::start_fgetxattr) needs, and the
    /// one-buffer convenience for [`start_preadv2`](FsHandle::start_preadv2).
    pub fn wait_buf(self) -> (crate::Result<usize>, Vec<u8>) {
        let (res, mut bufs) = self.wait();
        (res, bufs.pop().unwrap_or_default())
    }
}

/// The `Send + Sync` off-loop handle: blocking filesystem calls that submit
/// to the loop and park on a per-call reply channel. Clone freely; one loop
/// serves any number of handle threads.
///
/// Every operation (except [`close`](FsHandle::close) — see the module docs)
/// takes the [`Personality`] it runs as. Calls made while the loop is
/// shutting down (or after it stopped) fail with `ECONNABORTED`.
#[cfg_attr(not(loom), derive(Debug))]
#[derive(Clone)]
pub struct FsHandle {
    pub(crate) tx: mpsc::Sender<FsInject>,
    pub(crate) shared: Arc<LoopShared>,
    /// This reactor's shared blocking-work pool, for the off-loop
    /// [`QueryPool`](query_dir::QueryPool) and generic offloaded work.
    pub(crate) pool: Arc<offload_pool::SharedPool>,
}

#[cfg(loom)]
impl fmt::Debug for FsHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FsHandle").finish_non_exhaustive()
    }
}

impl FsHandle {
    /// Open `path` — **relative**, resolved against `anchor` under the
    /// kernel's checks as `who` — returning a real fd as a [`File`].
    ///
    /// `how` is the same [`OpenHow`] the blocking
    /// [`openat2`](crate::sync_fs::openat2) takes; `O_CLOEXEC` is accepted.
    /// Open failures (`ENOENT`, `EACCES` — the personality *working*) come
    /// back as `Errno` errors.
    ///
    /// **Confined to `anchor` by default.** When `how` carries no `resolve`
    /// policy, this applies `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS`: a `..`
    /// component or a symlink that would leave `anchor` is rejected
    /// (`"../../etc/shadow"` cannot walk out of the share) and no symlink is
    /// followed. A caller that sets its own `resolve` is trusted and left
    /// untouched — pass e.g. just [`RESOLVE_BENEATH`] to allow in-tree
    /// symlinks. The personality's DAC binds every access regardless; the
    /// metadata ops are separately single-component-confined by [`Leaf`].
    ///
    /// [`RESOLVE_BENEATH`]: crate::sync_fs::ResolveFlag::RESOLVE_BENEATH
    pub fn open<P: ?Sized + TnPath>(
        &self,
        who: Personality,
        anchor: &Anchor,
        path: &P,
        how: OpenHow,
    ) -> crate::Result<File> {
        let (cpath, raw) = open_parts(path, how)?;
        self.open_raw(who, anchor, cpath, raw)
    }

    /// Submit a prepared `OPENAT2`. Shared by [`open`](Self::open) and
    /// [`open_confined`](Self::open_confined) so both reach the ring by one
    /// path and cannot drift.
    fn open_raw(
        &self,
        who: Personality,
        anchor: &Anchor,
        cpath: CString,
        raw: RawOpenHow,
    ) -> crate::Result<File> {
        let (tx, rx) = mpsc::channel();
        let out = self.call(
            FsInject::Open {
                pers: who.0,
                anchor: anchor.clone(),
                path: cpath,
                how: raw,
                reply: ReplyTo::Sync(tx),
            },
            &rx,
        )?;
        let fd = match (out.res, out.file) {
            (Ok(_), Some(fd)) => fd,
            (Err(e), _) => return Err(e.into()),
            (Ok(_), None) => return Err(Errno::EIO.into()),
        };
        Ok(File::new(fd))
    }

    /// Open `path` under [`CONFINED_RESOLVE`], which the caller **cannot
    /// weaken**.
    ///
    /// [`open`](Self::open) confines by default but yields to a caller that
    /// supplies its own `resolve` — reasonable for a general-purpose opener,
    /// and wrong when confinement is a security property of the surrounding
    /// system rather than a convenience. This form unions the confinement
    /// flags into whatever `how` asks for, so extra restrictions compose but
    /// none of the three can be dropped.
    ///
    /// Use it wherever the path component comes from a remote peer. The three
    /// escapes it forecloses are `..` walking above `anchor`, a symlink
    /// redirecting out of the tree, and resolution crossing into a different
    /// filesystem — the last being how a nested dataset or a `.zfs/snapshot`
    /// automount would otherwise be served as though it were part of the tree.
    pub fn open_confined<P: ?Sized + TnPath>(
        &self,
        who: Personality,
        anchor: &Anchor,
        path: &P,
        how: OpenHow,
    ) -> crate::Result<File> {
        let (cpath, mut raw) = open_parts(path, how)?;
        // Union, never assign: a caller may add restrictions (RESOLVE_NO_
        // MAGICLINKS, say) but cannot subtract any of these three.
        raw.resolve |= CONFINED_RESOLVE.bits();
        self.open_raw(who, anchor, cpath, raw)
    }

    /// Create every missing directory along `path` beneath `anchor`, returning
    /// an [`Anchor`] for the deepest one — `mkdir -p`, confined.
    ///
    /// Existing components are left alone (`EEXIST` is success, as `mkdir -p`
    /// treats it), so this is idempotent and safe to race: two callers
    /// creating the same tree both succeed.
    ///
    /// # Why this is a primitive rather than caller code
    ///
    /// It cannot be written as one operation, and the obvious shortcut is
    /// unsafe. `mkdirat` honours **no** `RESOLVE_*` flags — that is precisely
    /// why [`Leaf`] exists — so handing it `"a/b/c"` would resolve the
    /// intermediate components with no confinement at all. The only sound
    /// construction alternates confined `openat2` walks with single-component
    /// `mkdirat`s, one round trip per component, which every consumer would
    /// otherwise have to rediscover.
    ///
    /// The fast path is one operation: an existing tree resolves in a single
    /// confined open. Only missing components cost a `mkdir` plus an open
    /// each.
    ///
    /// `mode` applies to directories this call creates, and is subject to the
    /// process umask exactly as `mkdir(2)` is.
    pub fn mkdir_path<P: ?Sized + TnPath>(
        &self,
        who: Personality,
        anchor: &Anchor,
        path: &P,
        mode: Mode,
    ) -> crate::Result<Anchor> {
        let cpath: CString = path.with_tn_path(|c| c.to_owned())?;
        let bytes = cpath.as_bytes();
        if bytes.is_empty() {
            return Err(crate::Error::Validation(
                "uring_fs mkdir_path: empty path".into(),
            ));
        }
        if bytes.first() == Some(&b'/') {
            return Err(crate::Error::Validation(
                "uring_fs mkdir_path: path must be relative to the anchor"
                    .into(),
            ));
        }

        // Fast path: the whole tree already exists, so one confined open
        // settles it. `O_PATH|O_DIRECTORY` is exactly what an `Anchor` is.
        let dir_how = OpenHow::new()
            .flags(OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC)
            .resolve(CONFINED_RESOLVE);
        if let Ok(f) = self.open(who, anchor, cpath.as_c_str(), dir_how) {
            return Anchor::from_file(&f);
        }

        // Slow path: walk, creating what is missing. Each component is a
        // validated `Leaf`, so `mkdirat`'s lack of resolve flags cannot be
        // exploited; each open is confined, so the walk cannot leave `anchor`.
        let mut cur = anchor.clone();
        for part in bytes.split(|&b| b == b'/') {
            if part.is_empty() {
                // A doubled or trailing slash names the same directory.
                continue;
            }
            let leaf = Leaf::new(part)?;
            match self.mkdirat(who, &cur, leaf, mode) {
                Ok(()) => {}
                // Already there: `mkdir -p` semantics, and also the benign
                // outcome of losing a race with another creator.
                Err(crate::Error::Errno(Errno::EEXIST)) => {}
                Err(e) => return Err(e),
            }
            let f =
                self.open(who, &cur, leaf.to_cstring().as_c_str(), dir_how)?;
            cur = Anchor::from_file(&f)?;
        }
        Ok(cur)
    }

    /// Vectored positional read as `who` — `preadv2(2)` semantics: fill each
    /// buffer up to its current `len()`, in order, starting at file offset
    /// `off`. Returns the byte count (short only at end-of-file) and the
    /// buffers.
    ///
    /// See [`RwFlags`] for what the flags mean and which ones a given
    /// filesystem actually implements; an unsupported flag fails the read
    /// with `EOPNOTSUPP` rather than being quietly ignored, so support is
    /// discoverable per call. Pass [`RwFlags::empty()`] for plain `preadv(2)`
    /// behaviour, and a one-element `bufs` for a single-buffer read — this is
    /// the whole read surface, so there is one shape to learn and one to
    /// audit.
    pub fn preadv2(
        &self,
        who: Personality,
        f: &File,
        bufs: Vec<Vec<u8>>,
        off: u64,
        flags: RwFlags,
    ) -> (crate::Result<usize>, Vec<Vec<u8>>) {
        self.rw(core::TAG_READV, who, f, bufs, off, flags)
    }

    /// Vectored positional write as `who` — `pwritev2(2)` semantics: write
    /// each buffer's `len()` bytes, in order, starting at `off`. Returns
    /// bytes written and the buffers.
    ///
    /// [`RwFlags::RWF_DSYNC`] makes the write itself durable and can therefore
    /// replace a following [`fdatasync`](Self::fdatasync) — one operation
    /// instead of two. Whether that is *faster* is a filesystem question worth
    /// measuring: on ZFS a synchronous write goes through the ZIL, which for
    /// large writes can cost more than a single trailing sync. Pass
    /// [`RwFlags::empty()`] for plain `pwritev(2)` behaviour.
    pub fn pwritev2(
        &self,
        who: Personality,
        f: &File,
        bufs: Vec<Vec<u8>>,
        off: u64,
        flags: RwFlags,
    ) -> (crate::Result<usize>, Vec<Vec<u8>>) {
        self.rw(core::TAG_WRITEV, who, f, bufs, off, flags)
    }

    /// Start a vectored read without blocking; the returned [`FsPending`]
    /// collects the outcome. (The seam the dropped-mid-op lifecycle needs:
    /// the token can be dropped while this op is in flight — the orphan
    /// close cancels it and the pending wait observes `ECANCELED`.)
    pub fn start_preadv2(
        &self,
        who: Personality,
        f: &File,
        bufs: Vec<Vec<u8>>,
        off: u64,
        flags: RwFlags,
    ) -> crate::Result<FsPending> {
        self.start_rw(core::TAG_READV, who, f, bufs, off, flags)
    }

    /// Start a vectored write without blocking — the write-side twin of
    /// [`start_preadv2`](Self::start_preadv2).
    ///
    /// Without this, an off-loop caller writing a large object must use the
    /// blocking [`pwritev2`](Self::pwritev2) and park a thread for every write
    /// in flight. Issuing several of these and then collecting them lets one
    /// thread keep many writes on the ring at once, which is the whole reason
    /// the reactor exists.
    pub fn start_pwritev2(
        &self,
        who: Personality,
        f: &File,
        bufs: Vec<Vec<u8>>,
        off: u64,
        flags: RwFlags,
    ) -> crate::Result<FsPending> {
        self.start_rw(core::TAG_WRITEV, who, f, bufs, off, flags)
    }

    /// Shared body of the non-blocking read/write starts.
    fn start_rw(
        &self,
        tag: u8,
        who: Personality,
        f: &File,
        bufs: Vec<Vec<u8>>,
        off: u64,
        flags: RwFlags,
    ) -> crate::Result<FsPending> {
        let (tx, rx) = mpsc::channel();
        // Non-blocking: the buffers ride in the pending op and come back
        // through `FsPending::wait`; on a send failure they are dropped with
        // the message (this API returns no buffer to hand them back through).
        self.send(FsInject::Rw {
            tag,
            pers: who.0,
            file: f.fd.clone(),
            bufs,
            off,
            rw_flags: flags.bits(),
            reply: ReplyTo::Sync(tx),
        })
        .map_err(|_| crate::Error::from(Errno::ECONNABORTED))?;
        Ok(FsPending { rx })
    }

    /// Start a `statx` of `leaf` inside `anchor` as `who` without blocking;
    /// collect the metadata with
    /// [`FsPending::wait_statx`](FsPending::wait_statx). The non-blocking twin of
    /// [`statx`](Self::statx), for scattering per-entry metadata (see
    /// [`query_directory`]).
    pub fn start_statx(
        &self,
        who: Personality,
        anchor: &Anchor,
        leaf: Leaf<'_>,
        flags: AtFlags,
        mask: StatxMask,
    ) -> crate::Result<FsPending> {
        let (tx, rx) = mpsc::channel();
        self.send(FsInject::PathOp {
            tag: core::TAG_STATX,
            pers: who.0,
            a1: anchor.clone(),
            n1: leaf.to_cstring(),
            a2: None,
            n2: None,
            flags: statx_at_flags(flags),
            len_arg: mask.bits(),
            reply: ReplyTo::Sync(tx),
        })
        .map_err(|_| crate::Error::from(Errno::ECONNABORTED))?;
        Ok(FsPending { rx })
    }

    /// Start an `open` of `path` under `anchor` as `who` without blocking;
    /// collect the [`File`] with
    /// [`FsPending::wait_file`](FsPending::wait_file). The non-blocking twin of
    /// [`open`](Self::open).
    pub fn start_open<P: ?Sized + TnPath>(
        &self,
        who: Personality,
        anchor: &Anchor,
        path: &P,
        how: OpenHow,
    ) -> crate::Result<FsPending> {
        let (cpath, raw) = open_parts(path, how)?;
        let (tx, rx) = mpsc::channel();
        self.send(FsInject::Open {
            pers: who.0,
            anchor: anchor.clone(),
            path: cpath,
            how: raw,
            reply: ReplyTo::Sync(tx),
        })
        .map_err(|_| crate::Error::from(Errno::ECONNABORTED))?;
        Ok(FsPending { rx })
    }

    /// Start an `fgetxattr` of `name` on the open file `f` into `buf` as `who`
    /// without blocking; collect the size and filled buffer with
    /// [`FsPending::wait_buf`](FsPending::wait_buf). The non-blocking
    /// twin of [`fgetxattr`](Self::fgetxattr).
    pub fn start_fgetxattr(
        &self,
        who: Personality,
        f: &File,
        name: &CStr,
        buf: Vec<u8>,
    ) -> crate::Result<FsPending> {
        let (tx, rx) = mpsc::channel();
        self.send(FsInject::FdMeta {
            tag: core::TAG_FGETXATTR,
            pers: who.0,
            file: f.fd.clone(),
            name: Some(name.to_owned()),
            value: buf,
            off: 0,
            len64: 0,
            aux32: 0,
            reply: ReplyTo::Sync(tx),
        })
        .map_err(|_| crate::Error::from(Errno::ECONNABORTED))?;
        Ok(FsPending { rx })
    }

    /// Flush `f`'s data and metadata to stable storage (`fsync`).
    pub fn fsync(&self, who: Personality, f: &File) -> crate::Result<()> {
        self.sync(who, f, false, 0, 0)
    }

    /// Flush `f`'s data (and only essential metadata) — `fdatasync`.
    pub fn fdatasync(&self, who: Personality, f: &File) -> crate::Result<()> {
        self.sync(who, f, true, 0, 0)
    }

    /// Flush the byte range `[offset, offset + length)` of `f` (`datasync`
    /// selects `fdatasync` semantics), mirroring `truenas_pyos`'s ranged
    /// `prep_fsync`. The kernel syncs `[offset, offset + length]` via
    /// `vfs_fsync_range`; `offset == 0 && length == 0` syncs the whole file.
    /// `length` is the SQE's 32-bit field (≤ ~4 GiB per call); a nonzero
    /// `offset` with `length == 0` is a single-byte range at `offset`, **not**
    /// through end-of-file.
    pub fn fsync_range(
        &self,
        who: Personality,
        f: &File,
        datasync: bool,
        offset: u64,
        length: u32,
    ) -> crate::Result<()> {
        self.sync(who, f, datasync, offset, length)
    }

    // ---- metadata on an open file (the encouraged shape) ---------------

    /// Read extended attribute `name` from the open file into `buf`.
    ///
    /// Returns the attribute's size and the buffer. A `buf` shorter than the
    /// value fails `ERANGE`; passing an empty `buf` queries the size without
    /// reading (the kernel's `size == 0` convention). Note this is a **real
    /// per-operation credential check**, not just attribution: `user.*`
    /// requires read permission on the inode at call time, and an
    /// unprivileged `trusted.*` read reports `ENODATA` rather than `EPERM`.
    pub fn fgetxattr(
        &self,
        who: Personality,
        f: &File,
        name: &CStr,
        buf: Vec<u8>,
    ) -> (crate::Result<usize>, Vec<u8>) {
        self.fd_meta_buf(
            core::TAG_FGETXATTR,
            who,
            f,
            Some(name.to_owned()),
            buf,
            0,
            0,
            0,
        )
    }

    /// Read extended attribute `name` from `f` under the reactor's ambient
    /// (root) credentials, not any `who`'s: the off-loop twin of
    /// [`FsConn::fgetxattr_as_root`](crate::uring_fs::FsConn::fgetxattr_as_root).
    ///
    /// A privileged, unattributed read for a `trusted.*`/`security.*` attribute
    /// a request identity cannot see. Use it only for server-internal metadata,
    /// never to relay a value past a `who` that could not read it. Needs Linux
    /// >= 6.13; fails closed (`EOPNOTSUPP`) otherwise.
    pub fn fgetxattr_as_root(
        &self,
        f: &File,
        name: &CStr,
        buf: Vec<u8>,
    ) -> (crate::Result<usize>, Vec<u8>) {
        let (tx, rx) = mpsc::channel();
        let sent = self.send(FsInject::FdMetaAsRoot {
            file: f.fd.clone(),
            name: name.to_owned(),
            value: buf,
            reply: ReplyTo::Sync(tx),
        });
        if let Err(msg) = sent {
            let value = match msg {
                FsInject::FdMetaAsRoot { value, .. } => value,
                _ => Vec::new(),
            };
            return (Err(Errno::ECONNABORTED.into()), value);
        }
        match rx.recv() {
            Ok(mut out) => (
                out.res.map(|n| n as usize).map_err(Into::into),
                out.bufs.pop().unwrap_or_default(),
            ),
            Err(_) => (Err(Errno::ECONNABORTED.into()), Vec::new()),
        }
    }

    /// Write extended attribute `name` on the open file.
    ///
    /// `flags` takes `libc::XATTR_CREATE` (fail if it exists) or
    /// `libc::XATTR_REPLACE` (fail if it does not); 0 means create-or-
    /// replace. The value is returned alongside the result, like every
    /// owned buffer here.
    ///
    /// Needs Linux ≥ 6.13, like [`fgetxattr`](Self::fgetxattr).
    pub fn fsetxattr(
        &self,
        who: Personality,
        f: &File,
        name: &CStr,
        value: Vec<u8>,
        flags: i32,
    ) -> (crate::Result<()>, Vec<u8>) {
        let (res, buf) = self.fd_meta_buf(
            core::TAG_FSETXATTR,
            who,
            f,
            Some(name.to_owned()),
            value,
            0,
            0,
            flags as u32,
        );
        (res.map(|_| ()), buf)
    }

    /// List the extended-attribute names on the open file `f` (all namespaces).
    ///
    /// Runs a blocking `flistxattr` on the calling thread at its own privilege,
    /// so call it off the reactor (a worker or client thread). Names the caller
    /// is not privileged to see (`trusted.*` without `CAP_SYS_ADMIN`) are
    /// omitted by the kernel. Unlike the fd-xattr read/write ops this needs no
    /// special kernel version.
    pub fn flistxattr(&self, f: &File) -> crate::Result<Vec<CString>> {
        query_dir::list_xattr_names(f)
    }

    /// Filesystem statistics for the mount `f` lives on.
    ///
    /// Runs inline on the calling thread — this handle is already off the
    /// reactor, so there is nothing to offload it *from*, exactly as
    /// [`flistxattr`](Self::flistxattr) does. io_uring has no `statfs`
    /// opcode, so the on-loop [`FsConn`] twin has to
    /// take a pool thread; here the caller supplies one by being one.
    pub fn fstatfs(&self, f: &File) -> crate::Result<Statfs> {
        Ok(crate::sync_fs::fstatfs(&*f.fd)?)
    }

    /// Filesystem statistics for the mount `anchor` lives on — capacity for a
    /// whole tree without opening anything in it.
    ///
    /// An [`Anchor`] is an `O_PATH` descriptor, which most fd-taking calls
    /// reject; this one does not, because the kernel resolves through
    /// `f_path` and never consults `f_op` (`fd_statfs`, `fs/statfs.c`). So a
    /// bucket's free space costs no open.
    pub fn fstatfs_anchor(&self, anchor: &Anchor) -> crate::Result<Statfs> {
        Ok(crate::sync_fs::fstatfs(anchor)?)
    }

    /// Read `f`'s ZFS attributes.
    ///
    /// `f` must have been opened for real I/O — the ioctl needs an
    /// `f_op->unlocked_ioctl`, which an `O_PATH` descriptor lacks. `ENOTTY`
    /// off ZFS.
    ///
    /// For `IMMUTABLE`/`APPENDONLY` alone, prefer
    /// [`fstatx`](Self::fstatx): `statx` reports both through
    /// [`StatxAttr`](crate::sync_fs::StatxAttr) with no ioctl, and a listing
    /// already pays for that stat.
    pub fn fget_zfs_attrs(&self, f: &File) -> crate::Result<ZfsAttr> {
        Ok(crate::sync_fs::fget_zfs_attrs(&*f.fd)?)
    }

    /// Replace `f`'s ZFS attributes with `attrs`. **The mask is absolute**:
    /// visible bits absent from `attrs` are cleared, so read with
    /// [`fget_zfs_attrs`](Self::fget_zfs_attrs) and modify that rather than
    /// writing a constant.
    ///
    /// Note the missing [`Personality`], for the same reason
    /// [`fremovexattr`](Self::fremovexattr) has none: the kernel checks the
    /// *calling thread's* credentials for an ioctl, and this thread carries
    /// the reactor's, not a request identity's. Whether a given caller may
    /// lock a given file is therefore a policy question this API cannot
    /// answer — and it matters, because `ZfsAttr::NOUNLINK` needs only
    /// ownership to clear while `IMMUTABLE` needs `CAP_LINUX_IMMUTABLE`.
    /// Do not expose this to a request identity without a gate above it.
    ///
    /// Setting `IMMUTABLE` also makes the file's extended attributes
    /// read-only (`may_write_xattr`, `fs/xattr.c`), so write any metadata
    /// that belongs with a locked object *before* locking it.
    pub fn fset_zfs_attrs(
        &self,
        f: &File,
        attrs: ZfsAttr,
    ) -> crate::Result<()> {
        Ok(crate::sync_fs::fset_zfs_attrs(&*f.fd, attrs)?)
    }

    /// Remove a **server-owned** extended attribute from `f`, or `EPERM` if
    /// `name` is not covered by the reactor's [`PrivilegedXattrs`] policy.
    ///
    /// Note the missing [`Personality`]: alone among the mutations here, this
    /// one cannot be credential-checked by the kernel. io_uring has no
    /// removal opcode, and a zero-length `FSETXATTR` sets an *empty*
    /// attribute rather than removing one, so the call has to run on a pool
    /// thread under the reactor's own credentials. The allowlist stands in
    /// for the identity check: a caller may clear metadata this reactor
    /// wrote, and nothing else. To let a *user* remove their own attribute,
    /// do it on a thread that holds their credentials — this API cannot.
    pub fn fremovexattr(&self, f: &File, name: &CStr) -> crate::Result<()> {
        let (tx, rx) = mpsc::channel();
        let out = self.call(
            FsInject::FRemoveXattr {
                file: f.fd.clone(),
                name: name.to_owned(),
                reply: ReplyTo::Sync(tx),
            },
            &rx,
        )?;
        out.res.map(|_| ()).map_err(Into::into)
    }

    /// Enumerate the extended attributes of `f` in the namespaces `ns`, read
    /// their values under `who`, and return `(name, value)` for only those
    /// `who` can read (see [`XattrNamespaces`]).
    ///
    /// The candidate `flistxattr` runs at this thread's privilege; the per-value
    /// read under `who` is the authoritative gate, so an attribute `who` cannot
    /// read (`trusted.*` for an unprivileged identity) is dropped, never
    /// returned. Off-loop: it scatters ring reads and blocks on them, so call it
    /// off the reactor. The caller owns any policy above `who`-readability.
    pub fn query_xattrs(
        &self,
        who: Personality,
        f: &File,
        ns: query_dir::XattrNamespaces,
    ) -> crate::Result<Vec<(CString, Vec<u8>)>> {
        query_dir::scan_xattrs(self, who, f, ns)
    }

    /// Set the open file's length (`ftruncate`).
    ///
    /// Requires `IORING_OP_FTRUNCATE` (Linux ≥ 6.9) — the one op above this
    /// crate's other io_uring floors. Where the kernel lacks it,
    /// [`UringFs::new`] leaves it disabled and this returns `EOPNOTSUPP`
    /// without touching the ring.
    pub fn ftruncate(
        &self,
        who: Personality,
        f: &File,
        len: u64,
    ) -> crate::Result<()> {
        self.fd_meta_unit(core::TAG_FTRUNCATE, who, f, len, 0, 0)
    }

    /// Manipulate the open file's allocated blocks (`fallocate`): `mode` is
    /// 0 to preallocate, or a `libc::FALLOC_FL_*` combination (punch hole,
    /// zero range, collapse, …).
    pub fn fallocate(
        &self,
        who: Personality,
        f: &File,
        mode: i32,
        off: u64,
        len: u64,
    ) -> crate::Result<()> {
        self.fd_meta_unit(core::TAG_FALLOCATE, who, f, off, len, mode as u32)
    }

    /// Advise the kernel how `len` bytes of `f` from `off` will be used
    /// (`posix_fadvise`). `len` of 0 means "to the end of the file".
    ///
    /// Advisory by definition: it is never an error for the kernel to ignore
    /// it, and it changes no file contents. See [`Advice`] for what each
    /// value does on ZFS, where these reach the ARC rather than only the page
    /// cache.
    pub fn fadvise(
        &self,
        who: Personality,
        f: &File,
        off: u64,
        len: u64,
        advice: Advice,
    ) -> crate::Result<()> {
        self.fd_meta_unit(core::TAG_FADVISE, who, f, off, len, advice as u32)
    }

    /// Move up to `len` bytes from `pipe`'s read end into `f` at `off`,
    /// without a userspace buffer (`IORING_OP_SPLICE`). Returns the number of
    /// bytes moved.
    ///
    /// The ingest half of a zero-copy body path: whoever fills the pipe never
    /// materializes the bytes, and neither does this. `pipe` is a plain
    /// descriptor the caller keeps open across the call — it is **not** taken
    /// into the fixed-file pool and costs no [`FsConfig`] slot.
    ///
    /// # A short move is ordinary progress
    ///
    /// A pipe delivers what it has, so **a returned count below `len` means
    /// resubmit the remainder** — it does not mean end of input, and it is
    /// not an error. (The kernel's `req_set_fail` on a short move —
    /// `io_splice`, `io_uring/splice.c` — decides only whether an
    /// `IOSQE_IO_LINK` chain continues, and this issues no chain.)
    ///
    /// Nothing passes through userspace, so nothing can hash the bytes in
    /// transit. A body that needs an ETag computed on ingest has to be read
    /// conventionally instead.
    pub fn splice_from_pipe(
        &self,
        who: Personality,
        f: &File,
        pipe: RawFd,
        off: u64,
        len: u32,
    ) -> crate::Result<u64> {
        self.fd_meta_count(
            core::TAG_SPLICE,
            who,
            f,
            off,
            // Carried to `splice_fd_in`; see the `TAG_SPLICE` staging arm.
            pipe as u32 as u64,
            len,
        )
    }

    // ---- statx: the one path-resolving metadata op ---------------------

    /// Stat the entry `leaf` inside `anchor`. Does **not** follow a terminal
    /// symlink by default (the link itself is stat'd); pass
    /// `AtFlags::AT_SYMLINK_FOLLOW` to stat the target.
    ///
    /// **A metadata op that resolves a name** rather than taking an open file.
    /// For an already-open [`File`], [`fstatx`](Self::fstatx) stats it directly
    /// (`STATX` with `AT_EMPTY_PATH` on its plain fd); prefer that, or
    /// [`statx_anchor`](Self::statx_anchor) when you already hold the target,
    /// and be aware that a statx-then-open pair names the file twice: the two
    /// can disagree if it is replaced in between.
    pub fn statx(
        &self,
        who: Personality,
        anchor: &Anchor,
        leaf: Leaf<'_>,
        flags: AtFlags,
        mask: StatxMask,
    ) -> crate::Result<Statx> {
        self.statx_inner(who, anchor, leaf.to_cstring(), flags, mask)
    }

    /// Stat the anchor directory itself (`AT_EMPTY_PATH` on its dirfd) —
    /// the closest thing to an fd-based statx this interface can offer.
    pub fn statx_anchor(
        &self,
        who: Personality,
        anchor: &Anchor,
        flags: AtFlags,
        mask: StatxMask,
    ) -> crate::Result<Statx> {
        self.statx_inner(
            who,
            anchor,
            CString::default(),
            flags | AtFlags::AT_EMPTY_PATH,
            mask,
        )
    }

    /// Statx an **open file** by its descriptor
    /// (`statx(fd, "", AT_EMPTY_PATH)`) — the `fstat` equivalent. No path is
    /// resolved (no name TOCTOU); the metadata is exactly this fd's.
    pub fn fstatx(
        &self,
        who: Personality,
        f: &File,
        flags: AtFlags,
        mask: StatxMask,
    ) -> crate::Result<Statx> {
        let anchor = Anchor::from_shared(f.fd.clone());
        self.statx_anchor(who, &anchor, flags, mask)
    }

    // ---- directory entries ---------------------------------------------

    /// Create a directory `leaf` inside `anchor`.
    pub fn mkdirat(
        &self,
        who: Personality,
        anchor: &Anchor,
        leaf: Leaf<'_>,
        mode: Mode,
    ) -> crate::Result<()> {
        self.path_op(
            core::TAG_MKDIRAT,
            who,
            anchor,
            leaf,
            None,
            None,
            0,
            mode.bits(),
        )
    }

    /// Remove the file `leaf` from `anchor`.
    pub fn unlinkat(
        &self,
        who: Personality,
        anchor: &Anchor,
        leaf: Leaf<'_>,
    ) -> crate::Result<()> {
        self.path_op(core::TAG_UNLINKAT, who, anchor, leaf, None, None, 0, 0)
    }

    /// Remove the (empty) directory `leaf` from `anchor` — `unlinkat` with
    /// `AT_REMOVEDIR`, the only flag the kernel accepts here.
    pub fn rmdirat(
        &self,
        who: Personality,
        anchor: &Anchor,
        leaf: Leaf<'_>,
    ) -> crate::Result<()> {
        self.path_op(
            core::TAG_UNLINKAT,
            who,
            anchor,
            leaf,
            None,
            None,
            libc::AT_REMOVEDIR as u32,
            0,
        )
    }

    /// Rename `old_leaf` in `old` to `new_leaf` in `new` (the anchors may be
    /// the same, and must be on one filesystem). `flags` takes
    /// [`RenameFlags`] — `RENAME_NOREPLACE`, `RENAME_EXCHANGE`, ….
    pub fn renameat(
        &self,
        who: Personality,
        old: &Anchor,
        old_leaf: Leaf<'_>,
        new: &Anchor,
        new_leaf: Leaf<'_>,
        flags: RenameFlags,
    ) -> crate::Result<()> {
        self.path_op(
            core::TAG_RENAMEAT,
            who,
            old,
            old_leaf,
            Some(new),
            Some(new_leaf),
            flags.bits(),
            0,
        )
    }

    /// Create a symlink `leaf` in `anchor` pointing at `target`.
    ///
    /// `target` is link *content*: it is stored verbatim and never resolved
    /// at creation, so it is deliberately not a [`Leaf`] and may be any
    /// path. What it resolves to later is decided by whoever follows it —
    /// with the follower's credentials, not the creator's.
    pub fn symlinkat<P: ?Sized + TnPath>(
        &self,
        who: Personality,
        target: &P,
        anchor: &Anchor,
        leaf: Leaf<'_>,
    ) -> crate::Result<()> {
        let target = target.with_tn_path(|c| c.to_owned())?;
        if target.as_bytes().is_empty() {
            return Err(crate::Error::Validation(
                "symlinkat: empty target".into(),
            ));
        }
        // Here the *first* name is the link content and the second is the
        // entry to create, so this cannot go through `path_op`'s leaf-first
        // shape.
        let (tx, rx) = mpsc::channel();
        let out = self.call(
            FsInject::PathOp {
                tag: core::TAG_SYMLINKAT,
                pers: who.0,
                a1: anchor.clone(),
                n1: target,
                a2: None,
                n2: Some(leaf.to_cstring()),
                flags: 0,
                len_arg: 0,
                reply: ReplyTo::Sync(tx),
            },
            &rx,
        )?;
        out.res.map(|_| ()).map_err(Into::into)
    }

    /// Create a hard link at `new_leaf` in `new` for the existing entry
    /// `old_leaf` in `old`. `flags` may carry `AT_SYMLINK_FOLLOW` to follow a
    /// symlink named by `old_leaf` (default: no-follow); a followed link can
    /// name a target outside `anchor`, bounded by the personality's DAC.
    pub fn linkat(
        &self,
        who: Personality,
        old: &Anchor,
        old_leaf: Leaf<'_>,
        new: &Anchor,
        new_leaf: Leaf<'_>,
        flags: AtFlags,
    ) -> crate::Result<()> {
        self.path_op(
            core::TAG_LINKAT,
            who,
            old,
            old_leaf,
            Some(new),
            Some(new_leaf),
            flags.bits() as u32,
            0,
        )
    }

    /// Give the already-open `f` a name at `new_leaf` in `new`
    /// (`linkat` with `AT_EMPTY_PATH`).
    ///
    /// This is how an `O_TMPFILE` file is materialized: it is the only link
    /// form that can name an inode which has no name yet, and it is therefore
    /// the publish step of a durable create — write and sync an invisible file,
    /// then make it appear, already complete, in one atomic operation. A
    /// failure before this point leaves nothing behind at all: dropping the
    /// [`File`] releases the last reference to an unnamed inode, so there is no
    /// temporary file to clean up, on error or after a crash.
    ///
    /// Note that `linkat` cannot replace an existing name (`EEXIST`); to
    /// overwrite, link to a temporary name and then
    /// [`renameat`](Self::renameat) over the target.
    ///
    /// # Requirements
    ///
    /// - `f` must have been opened `O_TMPFILE` **without `O_EXCL`**. `O_EXCL`
    ///   is the "this file can never be linked" opt-out, and violating it fails
    ///   with `ENOENT` rather than anything more descriptive.
    /// - `who` must carry **the same credentials that opened `f`**. The kernel
    ///   compares the file's open-time `f_cred` against the caller's by
    ///   *pointer*, and io_uring records the personality's credentials on the
    ///   file at open time. Two ids from [`UringFs::register_self`] alias the
    ///   same credentials and are interchangeable here; two *brokered*
    ///   registrations are not, even for the same user, because each mints
    ///   fresh credentials. A mismatch fails with `ENOENT`, not `EPERM`. In
    ///   practice: hold one [`Lease`] for the whole create rather than
    ///   re-acquiring between the open and the link.
    ///
    ///   The kernel accepts [`Caps::DAC_READ_SEARCH`] as the alternative to
    ///   that pointer match, so a personality carrying it can publish a file
    ///   opened under a *different* one — useful when a create genuinely
    ///   cannot be held inside a single lease. It is a broad capability for a
    ///   narrow problem, though; prefer the one-[`Lease`] rule.
    pub fn linkat_file(
        &self,
        who: Personality,
        f: &File,
        new: &Anchor,
        new_leaf: Leaf<'_>,
    ) -> crate::Result<()> {
        let (tx, rx) = mpsc::channel();
        let out = self.call(
            FsInject::LinkatFile {
                pers: who.0,
                file: f.fd.clone(),
                a2: new.clone(),
                n2: new_leaf.to_cstring(),
                reply: ReplyTo::Sync(tx),
            },
            &rx,
        )?;
        out.res.map(|_| ()).map_err(Into::into)
    }

    /// Close the file. This drops the handle's reference-counted fd; the
    /// descriptor is closed once the last clone — this handle plus any op still
    /// in flight on it — is dropped, so an in-flight op never races the close
    /// and no explicit ring op is needed. Returns `Result` to sit alongside
    /// the fallible ops, but never fails.
    pub fn close(&self, f: File) -> crate::Result<()> {
        drop(f);
        Ok(())
    }

    fn sync(
        &self,
        who: Personality,
        f: &File,
        datasync: bool,
        offset: u64,
        length: u32,
    ) -> crate::Result<()> {
        let (tx, rx) = mpsc::channel();
        let out = self.call(
            FsInject::Fsync {
                pers: who.0,
                file: f.fd.clone(),
                datasync,
                offset,
                length,
                reply: ReplyTo::Sync(tx),
            },
            &rx,
        )?;
        out.res.map(|_| ()).map_err(Into::into)
    }

    fn rw(
        &self,
        tag: u8,
        who: Personality,
        f: &File,
        bufs: Vec<Vec<u8>>,
        off: u64,
        rw_flags: RwFlags,
    ) -> (crate::Result<usize>, Vec<Vec<u8>>) {
        let (tx, rx) = mpsc::channel();
        let sent = self.send(FsInject::Rw {
            tag,
            pers: who.0,
            file: f.fd.clone(),
            bufs,
            off,
            rw_flags: rw_flags.bits(),
            reply: ReplyTo::Sync(tx),
        });
        if let Err(msg) = sent {
            // Loop gone: hand the caller's buffers back, as the completion
            // path does — the owned-round-trip contract holds on failure too.
            let bufs = match msg {
                FsInject::Rw { bufs, .. } => bufs,
                _ => Vec::new(),
            };
            return (Err(Errno::ECONNABORTED.into()), bufs);
        }
        match rx.recv() {
            Ok(out) => {
                (out.res.map(|n| n as usize).map_err(Into::into), out.bufs)
            }
            Err(_) => (Err(Errno::ECONNABORTED.into()), Vec::new()),
        }
    }

    /// An fd metadata op whose payload buffer round-trips (xattr).
    #[allow(clippy::too_many_arguments)]
    fn fd_meta_buf(
        &self,
        tag: u8,
        who: Personality,
        f: &File,
        name: Option<CString>,
        value: Vec<u8>,
        off: u64,
        len64: u64,
        aux32: u32,
    ) -> (crate::Result<usize>, Vec<u8>) {
        let (tx, rx) = mpsc::channel();
        let sent = self.send(FsInject::FdMeta {
            tag,
            pers: who.0,
            file: f.fd.clone(),
            name,
            value,
            off,
            len64,
            aux32,
            reply: ReplyTo::Sync(tx),
        });
        if let Err(msg) = sent {
            // Loop gone: hand the caller's value buffer back.
            let value = match msg {
                FsInject::FdMeta { value, .. } => value,
                _ => Vec::new(),
            };
            return (Err(Errno::ECONNABORTED.into()), value);
        }
        match rx.recv() {
            Ok(mut out) => (
                out.res.map(|n| n as usize).map_err(Into::into),
                out.bufs.pop().unwrap_or_default(),
            ),
            Err(_) => (Err(Errno::ECONNABORTED.into()), Vec::new()),
        }
    }

    /// An fd metadata op with no payload buffer (truncate/fallocate).
    fn fd_meta_unit(
        &self,
        tag: u8,
        who: Personality,
        f: &File,
        off: u64,
        len64: u64,
        aux32: u32,
    ) -> crate::Result<()> {
        self.fd_meta_count(tag, who, f, off, len64, aux32)
            .map(|_| ())
    }

    /// [`fd_meta_unit`](Self::fd_meta_unit) for the ops whose result is a
    /// byte count rather than a bare success.
    fn fd_meta_count(
        &self,
        tag: u8,
        who: Personality,
        f: &File,
        off: u64,
        len64: u64,
        aux32: u32,
    ) -> crate::Result<u64> {
        let (tx, rx) = mpsc::channel();
        let out = self.call(
            FsInject::FdMeta {
                tag,
                pers: who.0,
                file: f.fd.clone(),
                name: None,
                value: Vec::new(),
                off,
                len64,
                aux32,
                reply: ReplyTo::Sync(tx),
            },
            &rx,
        )?;
        // `map_res` turns every negative result into `Err`, so the `Ok` arm is
        // a non-negative count.
        out.res.map(|n| n as u64).map_err(Into::into)
    }

    fn statx_inner(
        &self,
        who: Personality,
        anchor: &Anchor,
        path: CString,
        flags: AtFlags,
        mask: StatxMask,
    ) -> crate::Result<Statx> {
        let (tx, rx) = mpsc::channel();
        let out = self.call(
            FsInject::PathOp {
                tag: core::TAG_STATX,
                pers: who.0,
                a1: anchor.clone(),
                n1: path,
                a2: None,
                n2: None,
                // Default to not following a terminal symlink (see
                // `FsConn::statx`); AT_SYMLINK_FOLLOW opts into the target.
                flags: statx_at_flags(flags),
                len_arg: mask.bits(),
                reply: ReplyTo::Sync(tx),
            },
            &rx,
        )?;
        out.res?;
        out.stat
            .map(|raw| Statx::from_raw(*raw))
            .ok_or_else(|| Errno::EIO.into())
    }

    /// A directory-entry op in the common `(anchor, leaf)` [+ destination]
    /// shape.
    #[allow(clippy::too_many_arguments)]
    fn path_op(
        &self,
        tag: u8,
        who: Personality,
        a1: &Anchor,
        n1: Leaf<'_>,
        a2: Option<&Anchor>,
        n2: Option<Leaf<'_>>,
        flags: u32,
        len_arg: u32,
    ) -> crate::Result<()> {
        let (tx, rx) = mpsc::channel();
        let out = self.call(
            FsInject::PathOp {
                tag,
                pers: who.0,
                a1: a1.clone(),
                n1: n1.to_cstring(),
                a2: a2.cloned(),
                n2: n2.map(Leaf::to_cstring),
                flags,
                len_arg,
                reply: ReplyTo::Sync(tx),
            },
            &rx,
        )?;
        out.res.map(|_| ()).map_err(Into::into)
    }

    /// Queue an inject and wake the loop. On failure (loop stopping or gone)
    /// the un-sent message is handed back as `Err(msg)` so a caller can recover
    /// the owned buffers it moved in; the error is always `ECONNABORTED`.
    /// (`pub(crate)`: the async `rt` handle submits through the same path.)
    // The Err IS the un-sent message, by design — its size is the payload the
    // caller gets back (buffers, lease), not an error-path allocation to shrink.
    #[allow(clippy::result_large_err)]
    pub(crate) fn send(&self, msg: FsInject) -> Result<(), FsInject> {
        use crate::sync::atomic::Ordering;
        if self.shared.stop.load(Ordering::Acquire) {
            return Err(msg);
        }
        if let Err(e) = self.tx.send(msg) {
            return Err(e.0); // SendError(msg) — the loop is gone
        }
        self.shared.wake.poke();
        Ok(())
    }

    fn call(
        &self,
        msg: FsInject,
        rx: &mpsc::Receiver<FsOutcome>,
    ) -> crate::Result<FsOutcome> {
        self.send(msg)
            .map_err(|_| crate::Error::from(Errno::ECONNABORTED))?;
        rx.recv().map_err(|_| Errno::ECONNABORTED.into())
    }
}

#[cfg(all(test, not(loom)))]
mod tests {
    use super::*;

    /// The liveness half of the inject-vs-shutdown race: a caller that got an
    /// `Ok` from [`FsHandle::send`] and is parked in [`FsHandle::call`] on its
    /// reply channel must be woken when the loop goes away, not left there.
    ///
    /// What wakes it is ownership, not a notification — dropping the inject
    /// receiver drops whatever was still queued, and each queued `FsInject`
    /// carries the `ReplyTo::Sync` sender for its own reply. So the reply
    /// channel disconnects and `recv` returns an error `call` maps to
    /// `ECONNABORTED`.
    ///
    /// This is deliberately a real-threads test rather than a loom model:
    /// loom's `mpsc` has no sender count, so a disconnected `recv` blocks in
    /// its scheduler instead of returning `Err` (see the `loom_tests` note).
    #[test]
    fn shutdown_disconnects_a_queued_injects_reply() {
        let (tx, rx) = mpsc::channel();
        let shared = Arc::new(crate::uring::wake::LoopShared {
            stop: std::sync::atomic::AtomicBool::new(false),
            graceful: std::sync::atomic::AtomicBool::new(false),
            grace_ms: std::sync::atomic::AtomicU64::new(0),
            wake: crate::uring::wake::WakeHandle::new().expect("eventfd"),
        });
        let h = FsHandle {
            tx,
            shared,
            pool: offload_pool::SharedPool::new(1, 1),
        };

        // SAFETY: dup(2) returns a fresh owned descriptor or -1; stderr is
        // always open in a test process.
        let raw = unsafe { libc::dup(2) };
        assert!(raw >= 0, "dup(2) failed");
        // SAFETY: fresh owned fd from dup().
        let file = Arc::new(unsafe { crate::fd::owned_from_raw(raw) });

        let (reply_tx, reply_rx) = mpsc::channel();
        h.send(FsInject::Fsync {
            pers: 0,
            file,
            datasync: false,
            offset: 0,
            length: 0,
            reply: ReplyTo::Sync(reply_tx),
        })
        // `send`'s error *is* the un-sent message, which has no `Debug`, so
        // check the discriminant rather than unwrapping.
        .map_err(|_| ())
        .expect("the loop has not stopped yet, so this is accepted");

        // The loop goes away with the inject still queued.
        drop(rx);

        assert!(
            reply_rx.recv().is_err(),
            "a queued inject's caller was left parked after the loop went away"
        );
    }

    /// The elevation decision is a pure prefix match, so it is testable on any
    /// kernel — unlike the privileged write itself, which needs 6.13 plus root
    /// and therefore only runs in the QEMU job.
    #[test]
    fn privileged_xattrs_matches_only_listed_prefixes() {
        let empty = PrivilegedXattrs::new();
        assert!(
            !empty.permits(c"trusted.example_etag"),
            "an empty policy grants nothing"
        );

        let p = PrivilegedXattrs::new()
            .allow_prefix(c"trusted.example_")
            .expect("valid prefix");
        assert!(p.permits(c"trusted.example_etag"));
        assert!(p.permits(c"trusted.example_"), "the prefix itself");
        // Neighbouring names that merely look similar are not covered.
        assert!(!p.permits(c"trusted.example"), "one byte short");
        assert!(!p.permits(c"trusted.other"));
        assert!(!p.permits(c"security.capability"));
        assert!(!p.permits(c"user.trusted.example_etag"));
        // A prefix match is anchored at the start, never a substring search.
        assert!(!p.permits(c"x.trusted.example_etag"));
    }

    #[test]
    fn privileged_xattrs_accumulates_prefixes() {
        let p = PrivilegedXattrs::new()
            .allow_prefix(c"trusted.a_")
            .and_then(|p| p.allow_prefix(c"trusted.b_"))
            .expect("valid prefixes");
        assert!(p.permits(c"trusted.a_one"));
        assert!(p.permits(c"trusted.b_two"));
        assert!(!p.permits(c"trusted.c_three"));
    }
}

// ---------------------------------------------------------------------------
// loom model of the inject-vs-shutdown race
// ---------------------------------------------------------------------------
//
// Run with:  RUSTFLAGS="--cfg loom" cargo test --lib --features uring-fs loom_
//
// `FsHandle::send` is a check-then-act against a flag another thread sets:
//
//   caller (FsHandle::send)                loop (host.rs / ShutdownHandle)
//   if stop.load(Acquire) { return Err }   stop.store(true, Release)
//   tx.send(msg)?                          wake.poke()
//   wake.poke()                            ...final drain of the receiver...
//
// The window between the load and the send is real: a caller can pass the
// check, the loop can decide to stop, and the message can land afterwards. The
// contract that makes that safe is not "the race cannot happen" but **an `Ok`
// from `send` never leaves its caller parked** — either the loop drains the
// message, or the inject receiver is dropped, which drops the queued message
// and with it the `ReplyTo` sender, so the caller's `rx.recv()` in `call`
// returns a disconnect it maps to `ECONNABORTED`.
//
// Note what this does *not* prove. The Acquire on the stop load has no payload
// behind it — the shutdown side publishes only the flag — so weakening it to
// Relaxed changes nothing this model can observe. What is verified here is the
// liveness contract, not a memory-ordering one; loom reports a violation as a
// deadlock on the reply channel.
//
// This model drives the real `send`. What it cannot drive is the reactor's
// teardown, which lives in `host.rs` around real io_uring work — so the loop
// side is a stand-in that performs the same two steps in the same order.
#[cfg(loom)]
mod loom_tests {
    use super::*;
    use crate::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use crate::uring::wake::{LoopShared, WakeHandle};

    fn bounded_model(f: impl Fn() + Sync + Send + 'static) {
        let mut b = loom::model::Builder::new();
        b.preemption_bound = Some(3);
        b.check(f);
    }

    /// A throwaway fd for the inject payload. Every `FsInject` variant carries
    /// one; which fd it is does not matter, only that it is owned and closes
    /// with the message.
    fn scratch_fd() -> Arc<OwnedFd> {
        // SAFETY: dup(2) returns a fresh owned descriptor or -1; stderr is
        // always open in a test process.
        let raw = unsafe { libc::dup(2) };
        assert!(raw >= 0, "dup(2) failed in the model");
        // SAFETY: fresh owned fd from dup().
        Arc::new(unsafe { crate::fd::owned_from_raw(raw) })
    }

    fn handle() -> (FsHandle, mpsc::Receiver<FsInject>, Arc<LoopShared>) {
        let (tx, rx) = mpsc::channel();
        let shared = Arc::new(LoopShared {
            stop: AtomicBool::new(false),
            graceful: AtomicBool::new(false),
            grace_ms: AtomicU64::new(0),
            wake: WakeHandle::new().expect("the model's wake never fails"),
        });
        let h = FsHandle {
            tx,
            shared: Arc::clone(&shared),
            pool: offload_pool::SharedPool::new(1, 1),
        };
        (h, rx, shared)
    }

    /// An `Ok` from `send` is honoured: the message is on the queue, so the
    /// loop's final drain finds it. An `Err` hands the message back intact so
    /// the caller can recover the buffers it moved in. Neither outcome may
    /// leave a message accepted-but-undrainable.
    // The liveness property this file's shutdown race really turns on — an
    // accepted inject whose receiver is dropped disconnects the caller's reply
    // channel, so `call` returns `ECONNABORTED` instead of parking — is **not
    // modelled here**. loom's `mpsc` tracks a message count and no sender
    // count (`loom-0.7.2/src/sync/mpsc.rs`), so `recv()` on a disconnected
    // channel blocks in its scheduler and is reported as a deadlock rather
    // than returning `Err`. Disconnect is unrepresentable, so the property is
    // covered by a real-threads test instead:
    // `shutdown_disconnects_a_queued_injects_reply`.

    /// Once `stop` is visible to the caller, `send` refuses and gives the
    /// message back rather than queueing onto a loop that will never drain.
    #[test]
    fn loom_inject_after_stop_is_refused() {
        bounded_model(|| {
            let (h, rx, shared) = handle();
            let (reply_tx, _reply_rx) = mpsc::channel();

            shared.stop.store(true, Ordering::Release);
            let refused = h
                .send(FsInject::Fsync {
                    pers: 0,
                    file: scratch_fd(),
                    datasync: false,
                    offset: 0,
                    length: 0,
                    reply: ReplyTo::Sync(reply_tx),
                })
                .is_err();

            assert!(refused, "send accepted an inject after stop was set");
            assert!(
                rx.try_recv().is_err(),
                "a refused inject was queued anyway"
            );
        });
    }
}
