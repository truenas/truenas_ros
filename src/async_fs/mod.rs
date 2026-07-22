//! The io_uring filesystem reactor: asynchronous filesystem operations with
//! kernel-enforced per-operation identity.
//!
//! This is the asynchronous counterpart of [`crate::sync_fs`], built on the
//! same shared engine (`uring`) the `net` roles drive. Files open **directly
//! into a fixed-descriptor pool** (no process fd is ever materialized) and
//! every data op runs against that pool slot. Two rules shape the whole API:
//!
//! - **Personality is mandatory.** Every consumer-staged operation carries a
//!   [`Personality`] — a kernel-registered credential snapshot stamped into
//!   the SQE, under which the kernel itself performs its permission checks
//!   (`override_creds` around issue, io-wq included). There is no
//!   ambient-identity variant: the daemon's own identity is minted like any
//!   other via [`AsyncFs::register_self`], and `sqe.personality = 0` (the
//!   ring owner's ambient creds) is unreachable from this API. Only
//!   [`FsHandle::close`] is exempt — teardown consults no credentials and
//!   must be stageable from [`FixedFile`]'s `Drop`.
//! - **Resolution is anchored.** No call takes an absolute path. [`Anchor`]
//!   is a long-lived real directory fd; `open` resolves a **relative**,
//!   multi-component path against it (confine it in-kernel with
//!   [`ResolveFlag::RESOLVE_BENEATH`](crate::sync_fs::ResolveFlag)), and
//!   every subsequent operation is fd-based on the opened [`FixedFile`].
//!
//! # Consumer shape
//!
//! There are two ways in, sharing one core. **Standalone** ([`AsyncFs`]) owns
//! its own ring and loop; **embedded** puts the same reactor on a `net`
//! server's ring, so a protocol handler does its filesystem work inline —
//! that is [`FsConn`], reached through `Request::fs`, and it is described
//! under [Embedding in a server](#embedding-in-a-server) below.
//!
//! The standalone loop is synchronous and single-threaded ([`AsyncFs::run`],
//! `!Send` like the net roles); concurrency comes from the ring. Off-loop
//! callers use the `Send + Sync` [`FsHandle`], whose blocking calls submit over
//! an inject channel and park on a per-call reply channel:
//!
//! ```no_run
//! use truenas_ros::async_fs::{Anchor, AsyncFs, FsConfig};
//! use truenas_ros::sync_fs::{OFlag, OpenHow};
//!
//! let mut afs = AsyncFs::new(FsConfig::default())?;
//! let me = afs.register_self()?; // the daemon's own creds, as an explicit id
//! let handle = afs.handle();
//! let stop = afs.shutdown_handle();
//! let anchor = Anchor::open("/tank/share")?; // setup-time; the one absolute open
//!
//! let worker = std::thread::spawn(move || -> truenas_ros::Result<()> {
//!     let how = OpenHow::new().flags(OFlag::O_RDONLY);
//!     let f = handle.open(me, &anchor, "docs/readme.txt", how)?;
//!     let (n, buf) = handle.pread(me, &f, vec![0u8; 4096], 0);
//!     let _ = (n?, buf);
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
//! — [`pread`](FsHandle::pread)/[`pwrite`](FsHandle::pwrite) and their
//! vectored [`preadv`](FsHandle::preadv)/[`pwritev`](FsHandle::pwritev)
//! forms take an explicit file offset, exactly as `pread(2)`/`pwritev(2)` do.
//! Every data op here is positional: a fixed-table file has no user-visible
//! file position to advance, so there is no offsetless `read`/`write` and no
//! `seek`. The **`at`** suffix is reserved for its usual meaning, the
//! dirfd-relative syscall family ([`renameat`](FsHandle::renameat),
//! [`unlinkat`](FsHandle::unlinkat), [`mkdirat`](FsHandle::mkdirat), …), where
//! the anchor dirfd is what the name refers to.
//!
//! # What operates on what
//!
//! The API is fd-first, so that `open → metadata → close` is the natural
//! shape and a file is named exactly once:
//!
//! - **On an open [`FixedFile`]:** [`preadv`](FsHandle::preadv) /
//!   [`pwritev`](FsHandle::pwritev) (+ the `pread`/`pwrite` k=1 forms),
//!   [`fsync`](FsHandle::fsync) / [`fdatasync`](FsHandle::fdatasync),
//!   [`fgetxattr`](FsHandle::fgetxattr) / [`fsetxattr`](FsHandle::fsetxattr),
//!   [`ftruncate`](FsHandle::ftruncate), [`fallocate`](FsHandle::fallocate),
//!   and [`close`](FsHandle::close).
//! - **The one exception, [`statx`](FsHandle::statx):** it resolves a name
//!   against an anchor, because *no* kernel offers statx on a
//!   registered-table file — io_uring's `STATX` rejects fixed files
//!   outright. [`statx_anchor`](FsHandle::statx_anchor) is the closest
//!   fd-based form (`AT_EMPTY_PATH` on the anchor's own dirfd).
//! - **Directory entries** — [`mkdirat`](FsHandle::mkdirat),
//!   [`unlinkat`](FsHandle::unlinkat), [`rmdirat`](FsHandle::rmdirat),
//!   [`renameat`](FsHandle::renameat), [`symlinkat`](FsHandle::symlinkat),
//!   [`linkat`](FsHandle::linkat) — take an [`Anchor`] plus a validated
//!   [`Leaf`]. These have no fd-only form in any kernel (you cannot unlink
//!   an fd); dirfd-plus-name *is* their fd-based shape.
//!
//! Two operations depend on the kernel version and are probed at
//! construction rather than assumed: fd-based xattr needs Linux ≥ 6.13
//! ([`AsyncFs::supports_fd_xattr`]) and `ftruncate` needs ≥ 6.9
//! ([`AsyncFs::supports_ftruncate`]); both return `EOPNOTSUPP` where
//! unavailable instead of failing construction.
//!
//! # Acting as other users
//!
//! [`AsyncFs::register_self`] mints the daemon's own identity. To act as an
//! *authenticated peer*, use the [`CredBroker`] — a tiny forked process
//! that impersonates a user just long enough to snapshot their credentials,
//! so the reactor process never changes identity itself:
//!
//! ```no_run
//! use truenas_ros::async_fs::{AsUser, AsyncFs, CredBroker, FsConfig};
//!
//! // Every ring first, then the broker (it inherits the ring fds), then
//! // threads. Both halves of that ordering are load-bearing — see
//! // `CredBroker::spawn`.
//! let afs = AsyncFs::new(FsConfig::default())?;
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
//! # Embedding in a server
//!
//! The same core also runs on a `net` server's own ring, which is how a
//! protocol handler does filesystem work without leaving the loop: build the
//! server with `ServerConfig::fs_files` set, and each request arrives with an
//! [`FsConn`] in `Request::fs`. Take it, park the request with
//! `Responder::defer`, and submit — the completion fires **in the loop**, and
//! the callback either chains the next op on the [`FsConn`] it is handed or
//! resolves the request through the `Deferred` it captured. fs and net SQEs
//! interleave on the one ring; there is no thread hop and no second reactor.
//!
//! Three differences from the off-loop [`FsHandle`] are worth knowing:
//!
//! - An open yields an [`FsFile`], not a [`FixedFile`]: `Copy`, no `Drop`, and
//!   it **remembers the personality it was opened under**, so every later
//!   fd-op on it runs as that identity without a per-op argument
//!   ([`FsFile::as_root`] is the one deliberate exception). Close it in the
//!   chain; a connection that dies mid-chain has its files reclaimed by the
//!   close sweep.
//! - Only the request-handler facade may [`open`](FsConn::open). A completion
//!   callback's facade refuses it — see [`FsConn::open`].
//! - Nothing returns an error to the caller: a submission or argument failure
//!   drops the callback, and dropping the `Deferred` it captured closes the
//!   connection. Operation failures (`ENOENT`, `EACCES`) arrive normally, in
//!   the callback's [`FsDone`].

mod broker;
// `pub(crate)` so the embedded host (`net::server`, when both features are on)
// can drive an `FsCore` on the server's own ring; the standalone host is
// `async_fs`'s own `AsyncFs`.
pub(crate) mod core;
// `pub(crate)` so a `net` server can reuse the fixed-file-xattr capability
// probe (the 6.13 floor is not visible to `REGISTER_PROBE`); the standalone
// reactor is `AsyncFs`.
pub(crate) mod host;

pub use broker::{
    AsUser, BrokerReactor, CredBroker, CredHandle, IdentityCache, Lease,
    MAX_GROUPS, MAX_RINGS,
};
// The embedded (in-loop) completion payload and chaining facade a `net` server
// hands protocol handlers; only meaningful with an fs pool, but the types are
// always exported so signatures don't shift with the `net-server` feature.
pub use core::{FsConn, FsDone};
pub use host::{AsyncFs, FsConfig, ShutdownHandle};

use crate::errno::{retry_on_eintr, Errno};
use crate::fd::owned_from_raw;
use crate::path::TnPath;
use crate::sync_fs::openat2::RawOpenHow;
use crate::sync_fs::{
    AtFlags, Mode, OpenHow, RenameFlags, ResolveFlag, Statx, StatxMask,
    StatxRaw,
};
use crate::uring::wake::LoopShared;
use std::ffi::{CStr, CString};
use std::fmt;
use std::os::fd::{AsFd, AsRawFd, OwnedFd, RawFd};
use std::sync::mpsc;
use std::sync::Arc;

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

/// A registered io_uring personality: a kernel-held snapshot of one
/// identity's credentials (fsuid/fsgid, supplementary groups, capabilities,
/// LSM label), stamped into every SQE this module submits. The kernel — not
/// the library — performs each operation's permission checks under it.
///
/// Mint one for the calling process with [`AsyncFs::register_self`]. Ids are
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

    fn to_cstring(self) -> CString {
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
        let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: `fd` is live; `st` is a valid out-pointer for fstat.
        Errno::result(unsafe {
            libc::fstat(fd.as_fd().as_raw_fd(), st.as_mut_ptr())
        })?;
        // SAFETY: fstat succeeded, so `st` is initialized.
        let st = unsafe { st.assume_init() };
        if st.st_mode & libc::S_IFMT != libc::S_IFDIR {
            return Err(crate::Error::Validation(
                "Anchor::from_fd: not a directory".into(),
            ));
        }
        Ok(Anchor(Arc::new(fd)))
    }

    pub(crate) fn raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

/// An open file in the reactor's fixed-descriptor table.
///
/// This is a token — `{slot, generation}` plus a channel back to the loop —
/// not an fd: the file exists only in the ring's registered table. Close it
/// explicitly with [`FsHandle::close`]; a dropped token injects a close by
/// itself (cancelling any ops still in flight on it first), so a lost holder
/// cannot leak a pool slot. A token whose slot has since been recycled is
/// inert: operations through it fail `EBADF` and touch nothing.
pub struct FixedFile {
    pub(crate) slot: u32,
    pub(crate) gen: u64,
    pub(crate) tx: mpsc::Sender<FsInject>,
    pub(crate) shared: Arc<LoopShared>,
    pub(crate) defused: bool,
}

impl fmt::Debug for FixedFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FixedFile")
            .field("slot", &self.slot)
            .field("gen", &self.gen)
            .finish_non_exhaustive()
    }
}

impl Drop for FixedFile {
    fn drop(&mut self) {
        if !self.defused {
            // Orphan close: best-effort — a dead loop means the ring (and the
            // file table with it) is already being torn down.
            let _ = self.tx.send(FsInject::Close {
                slot: self.slot,
                gen: self.gen,
                reply: None,
            });
            self.shared.wake.poke();
        }
    }
}

/// A bare open-file identity — `{slot, generation}` with no channel — for the
/// **embedded** (in-loop) path, where follow-up ops are chained inline through
/// an `FsConn` (a `net` server's request-bound fs facade) rather than injected
/// over a channel.
///
/// Unlike [`FixedFile`], this is `Copy` and has no `Drop`: an embedded file is
/// closed explicitly in the callback chain (or swept when its connection
/// closes), never by a token going out of scope. A token whose slot has since
/// been recycled is inert — operations through it fail `EBADF`.
///
/// The token also carries the [`Personality`] the file was **opened under**:
/// every fd-op on it ([`FsConn::preadv`](crate::async_fs::FsConn) etc.) runs as
/// that identity, so a file's whole lifecycle stays under one identity by
/// construction — there is no per-op personality argument to mismatch. The one
/// exception is [`as_root`](FsFile::as_root).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FsFile {
    pub(crate) slot: u32,
    pub(crate) gen: u64,
    /// The personality id the file was opened under (always nonzero — an
    /// `open` carries a real [`Personality`]). fd-ops stamp it unless
    /// [`as_root`](FsFile::as_root) flips them to the ambient path.
    pub(crate) pers: u16,
    /// This flavor's fd-ops run as the daemon's own root credentials
    /// (`sqe.personality = 0`) instead of the opened-under identity.
    pub(crate) as_root: bool,
}

impl FsFile {
    /// The fixed-table slot this file occupies.
    pub fn slot(self) -> u32 {
        self.slot
    }

    /// The slot's generation at open time (stale-token detection).
    pub fn generation(self) -> u64 {
        self.gen
    }

    /// The [`Personality`] this file was opened under — the identity its fd-ops
    /// run as (unless taken through [`as_root`](FsFile::as_root)).
    pub fn personality(self) -> Personality {
        Personality(self.pers)
    }

    /// A flavor of this token whose fd-ops run as the daemon's **own root
    /// credentials** rather than the opened-under identity — the io_uring
    /// equivalent of Samba's `become_root()` (`sqe.personality = 0`: no
    /// `override_creds`, so the ring owner's ambient — root — creds apply,
    /// verified against the kernel's `io_init_req`/`__io_issue_sqe`).
    ///
    /// The file's *data* was already access-checked at `open` under
    /// [`personality`](FsFile::personality); this only changes the identity
    /// subsequent ops are attributed to and re-checked under — its use is
    /// privileged metadata the peer itself cannot touch (a `security.*` /
    /// `trusted.*` xattr, quota-exempt writes). It does **not** re-open or
    /// widen data access. Deliberately the only way to reach `personality = 0`
    /// from this API; [`personality`](FsFile::personality) still reports the
    /// original opened-under id.
    pub fn as_root(self) -> FsFile {
        FsFile {
            as_root: true,
            ..self
        }
    }

    /// The personality id an fd-op on this token stamps: `0` (ambient root) for
    /// an [`as_root`](FsFile::as_root) flavor, else the opened-under id.
    pub(crate) fn op_pers(self) -> u16 {
        if self.as_root {
            0
        } else {
            self.pers
        }
    }
}

/// What crosses the reply channel for one completed operation.
pub(crate) struct FsOutcome {
    /// Mapped CQE result (`res` on success, `Errno` from `-res`).
    pub(crate) res: Result<i32, Errno>,
    /// The owned buffers, round-tripped back (empty for non-data ops).
    pub(crate) bufs: Vec<Vec<u8>>,
    /// For opens: the now-open `(slot, generation)`.
    pub(crate) file: Option<(u32, u64)>,
    /// For `statx`: the kernel-filled buffer.
    pub(crate) stat: Option<Box<StatxRaw>>,
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
        reply: mpsc::Sender<FsOutcome>,
    },
    Rw {
        /// [`core::TAG_READV`] or [`core::TAG_WRITEV`].
        tag: u8,
        pers: u16,
        slot: u32,
        gen: u64,
        bufs: Vec<Vec<u8>>,
        off: u64,
        reply: mpsc::Sender<FsOutcome>,
    },
    Fsync {
        pers: u16,
        slot: u32,
        gen: u64,
        datasync: bool,
        reply: mpsc::Sender<FsOutcome>,
    },
    Close {
        slot: u32,
        gen: u64,
        /// `None` = orphan close (a dropped [`FixedFile`]); nobody waits.
        reply: Option<mpsc::Sender<FsOutcome>>,
    },
    /// A metadata op on an open file: ftruncate/fallocate (no payload) or
    /// fgetxattr/fsetxattr (owned name + value).
    FdMeta {
        tag: u8,
        pers: u16,
        slot: u32,
        gen: u64,
        name: Option<CString>,
        value: Vec<u8>,
        off: u64,
        len64: u64,
        aux32: u32,
        reply: mpsc::Sender<FsOutcome>,
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
        reply: mpsc::Sender<FsOutcome>,
    },
}

/// An operation submitted with [`FsHandle::start_preadv`] (the
/// non-blocking twin of the blocking conveniences): hold it, do other work,
/// then [`wait`](FsPending::wait) for the outcome.
#[derive(Debug)]
pub struct FsPending {
    rx: mpsc::Receiver<FsOutcome>,
}

impl FsPending {
    /// Block until the operation completes; returns the byte count and the
    /// round-tripped buffers. A loop shut down mid-flight yields
    /// `ECONNABORTED`; an operation cancelled by a dropped [`FixedFile`]
    /// yields `ECANCELED`.
    pub fn wait(self) -> (crate::Result<usize>, Vec<Vec<u8>>) {
        match self.rx.recv() {
            Ok(out) => {
                (out.res.map(|n| n as usize).map_err(Into::into), out.bufs)
            }
            Err(_) => (Err(Errno::ECONNABORTED.into()), Vec::new()),
        }
    }
}

/// The `Send + Sync` off-loop handle: blocking filesystem calls that submit
/// to the loop and park on a per-call reply channel. Clone freely; one loop
/// serves any number of handle threads.
///
/// Every operation (except [`close`](FsHandle::close) — see the module docs)
/// takes the [`Personality`] it runs as. Calls made while the loop is
/// shutting down (or after it stopped) fail with `ECONNABORTED`.
#[derive(Clone, Debug)]
pub struct FsHandle {
    pub(crate) tx: mpsc::Sender<FsInject>,
    pub(crate) shared: Arc<LoopShared>,
    /// Whether this kernel has `IORING_OP_FTRUNCATE` (probed at
    /// construction); see [`FsHandle::ftruncate`].
    pub(crate) ftruncate_ok: bool,
    /// Whether the fd-based xattr ops accept a registered-table file
    /// (probed at construction); see [`FsHandle::fgetxattr`].
    pub(crate) fd_xattr_ok: bool,
}

impl FsHandle {
    /// Open `path` — **relative**, resolved against `anchor` under the
    /// kernel's checks as `who` — into a fixed-table slot.
    ///
    /// `how` is the same [`OpenHow`] the blocking
    /// [`openat2`](crate::sync_fs::openat2) takes. `O_CLOEXEC` is rejected
    /// (meaningless for a file that never enters the process fd table, and
    /// refused by the kernel when installing into one). Open failures
    /// (`ENOENT`, `EACCES` — the personality *working*) come back as `Errno`
    /// errors.
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
    ) -> crate::Result<FixedFile> {
        let cpath: CString = path.with_tn_path(|c| c.to_owned())?;
        let bytes = cpath.as_bytes();
        if bytes.is_empty() {
            return Err(crate::Error::Validation(
                "async_fs open: empty path".into(),
            ));
        }
        if bytes[0] == b'/' {
            return Err(crate::Error::Validation(
                "async_fs paths are anchor-relative; absolute paths are not \
                 accepted"
                    .into(),
            ));
        }
        let mut raw = how.to_raw();
        if raw.flags & libc::O_CLOEXEC as u64 != 0 {
            return Err(crate::Error::Validation(
                "async_fs open: O_CLOEXEC is meaningless for fixed-table \
                 opens (and rejected by the kernel); drop it"
                    .into(),
            ));
        }
        // Confine to `anchor` by default (see the doc): an unset `resolve`
        // would let `..`/symlinks escape the share.
        if raw.resolve == 0 {
            raw.resolve = ResolveFlag::RESOLVE_BENEATH
                .union(ResolveFlag::RESOLVE_NO_SYMLINKS)
                .bits();
        }
        let (tx, rx) = mpsc::channel();
        let out = self.call(
            FsInject::Open {
                pers: who.0,
                anchor: anchor.clone(),
                path: cpath,
                how: raw,
                reply: tx,
            },
            &rx,
        )?;
        let (slot, gen) = match (out.res, out.file) {
            (Ok(_), Some(sg)) => sg,
            (Err(e), _) => return Err(e.into()),
            (Ok(_), None) => return Err(Errno::EIO.into()),
        };
        Ok(FixedFile {
            slot,
            gen,
            tx: self.tx.clone(),
            shared: self.shared.clone(),
            defused: false,
        })
    }

    /// Vectored positional read as `who` — `preadv(2)` semantics: fill each
    /// buffer up to its current `len()`, in order, starting at file offset
    /// `off`. Returns the byte count (short only at end-of-file) and the
    /// buffers.
    pub fn preadv(
        &self,
        who: Personality,
        f: &FixedFile,
        bufs: Vec<Vec<u8>>,
        off: u64,
    ) -> (crate::Result<usize>, Vec<Vec<u8>>) {
        self.rw(core::TAG_READV, who, f, bufs, off)
    }

    /// Single-buffer positional read — `pread(2)`; the one-vector
    /// [`preadv`](Self::preadv).
    pub fn pread(
        &self,
        who: Personality,
        f: &FixedFile,
        buf: Vec<u8>,
        off: u64,
    ) -> (crate::Result<usize>, Vec<u8>) {
        let (res, mut bufs) = self.rw(core::TAG_READV, who, f, vec![buf], off);
        (res, bufs.pop().unwrap_or_default())
    }

    /// Vectored positional write as `who` — `pwritev(2)` semantics: write
    /// each buffer's `len()` bytes, in order, starting at `off`. Returns
    /// bytes written and the buffers.
    pub fn pwritev(
        &self,
        who: Personality,
        f: &FixedFile,
        bufs: Vec<Vec<u8>>,
        off: u64,
    ) -> (crate::Result<usize>, Vec<Vec<u8>>) {
        self.rw(core::TAG_WRITEV, who, f, bufs, off)
    }

    /// Single-buffer positional write — `pwrite(2)`; the one-vector
    /// [`pwritev`](Self::pwritev).
    pub fn pwrite(
        &self,
        who: Personality,
        f: &FixedFile,
        buf: Vec<u8>,
        off: u64,
    ) -> (crate::Result<usize>, Vec<u8>) {
        let (res, mut bufs) = self.rw(core::TAG_WRITEV, who, f, vec![buf], off);
        (res, bufs.pop().unwrap_or_default())
    }

    /// Start a vectored read without blocking; the returned [`FsPending`]
    /// collects the outcome. (The seam the dropped-mid-op lifecycle needs:
    /// the token can be dropped while this op is in flight — the orphan
    /// close cancels it and the pending wait observes `ECANCELED`.)
    pub fn start_preadv(
        &self,
        who: Personality,
        f: &FixedFile,
        bufs: Vec<Vec<u8>>,
        off: u64,
    ) -> crate::Result<FsPending> {
        let (tx, rx) = mpsc::channel();
        // Non-blocking: the buffers ride in the pending op and come back
        // through `FsPending::wait`; on a send failure they are dropped with
        // the message (this API returns no buffer to hand them back through).
        self.send(FsInject::Rw {
            tag: core::TAG_READV,
            pers: who.0,
            slot: f.slot,
            gen: f.gen,
            bufs,
            off,
            reply: tx,
        })
        .map_err(|_| crate::Error::from(Errno::ECONNABORTED))?;
        Ok(FsPending { rx })
    }

    /// Flush `f`'s data and metadata to stable storage (`fsync`).
    pub fn fsync(&self, who: Personality, f: &FixedFile) -> crate::Result<()> {
        self.sync(who, f, false)
    }

    /// Flush `f`'s data (and only essential metadata) — `fdatasync`.
    pub fn fdatasync(
        &self,
        who: Personality,
        f: &FixedFile,
    ) -> crate::Result<()> {
        self.sync(who, f, true)
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
    ///
    /// Needs Linux ≥ 6.13 (before that io_uring refused a registered-table
    /// file here); on an older kernel this returns `EOPNOTSUPP` without
    /// touching the ring — check
    /// [`AsyncFs::supports_fd_xattr`](crate::async_fs::AsyncFs::supports_fd_xattr).
    pub fn fgetxattr(
        &self,
        who: Personality,
        f: &FixedFile,
        name: &CStr,
        buf: Vec<u8>,
    ) -> (crate::Result<usize>, Vec<u8>) {
        if !self.fd_xattr_ok {
            return (Err(Errno::EOPNOTSUPP.into()), buf);
        }
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
        f: &FixedFile,
        name: &CStr,
        value: Vec<u8>,
        flags: i32,
    ) -> (crate::Result<()>, Vec<u8>) {
        if !self.fd_xattr_ok {
            return (Err(Errno::EOPNOTSUPP.into()), value);
        }
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

    /// Set the open file's length (`ftruncate`).
    ///
    /// Requires `IORING_OP_FTRUNCATE` (Linux ≥ 6.9) — the one op above this
    /// crate's other io_uring floors. Where the kernel lacks it,
    /// [`AsyncFs::new`] leaves it disabled and this returns `EOPNOTSUPP`
    /// without touching the ring.
    pub fn ftruncate(
        &self,
        who: Personality,
        f: &FixedFile,
        len: u64,
    ) -> crate::Result<()> {
        if !self.ftruncate_ok {
            return Err(Errno::EOPNOTSUPP.into());
        }
        self.fd_meta_unit(core::TAG_FTRUNCATE, who, f, len, 0, 0)
    }

    /// Manipulate the open file's allocated blocks (`fallocate`): `mode` is
    /// 0 to preallocate, or a `libc::FALLOC_FL_*` combination (punch hole,
    /// zero range, collapse, …).
    pub fn fallocate(
        &self,
        who: Personality,
        f: &FixedFile,
        mode: i32,
        off: u64,
        len: u64,
    ) -> crate::Result<()> {
        self.fd_meta_unit(core::TAG_FALLOCATE, who, f, off, len, mode as u32)
    }

    // ---- statx: the one path-resolving metadata op ---------------------

    /// Stat the entry `leaf` inside `anchor`. Does **not** follow a terminal
    /// symlink by default (the link itself is stat'd); pass
    /// `AtFlags::AT_SYMLINK_FOLLOW` to stat the target.
    ///
    /// **The one metadata op that resolves a name rather than taking an open
    /// file** — no kernel exposes statx on a registered-table file
    /// (io_uring's `STATX` rejects fixed files outright), so an open
    /// [`FixedFile`] cannot be stat'ed. Prefer
    /// [`statx_anchor`](Self::statx_anchor) where the target is a directory
    /// you already hold, and be aware that a statx-then-open pair names the
    /// file twice: the two can disagree if it is replaced in between.
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
                reply: tx,
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

    /// Close the file and free its pool slot, waiting for the kernel's
    /// close. Ops still in flight on it are cancelled first; the
    /// index-freeing close is always the file's last op.
    ///
    /// Deliberately personality-free: teardown consults no credentials, and
    /// the same close must be stageable from [`FixedFile`]'s parameterless
    /// `Drop`.
    pub fn close(&self, mut f: FixedFile) -> crate::Result<()> {
        let (slot, gen) = (f.slot, f.gen);
        f.defused = true;
        drop(f);
        let (tx, rx) = mpsc::channel();
        let out = self.call(
            FsInject::Close {
                slot,
                gen,
                reply: Some(tx),
            },
            &rx,
        )?;
        out.res.map(|_| ()).map_err(Into::into)
    }

    fn sync(
        &self,
        who: Personality,
        f: &FixedFile,
        datasync: bool,
    ) -> crate::Result<()> {
        let (tx, rx) = mpsc::channel();
        let out = self.call(
            FsInject::Fsync {
                pers: who.0,
                slot: f.slot,
                gen: f.gen,
                datasync,
                reply: tx,
            },
            &rx,
        )?;
        out.res.map(|_| ()).map_err(Into::into)
    }

    fn rw(
        &self,
        tag: u8,
        who: Personality,
        f: &FixedFile,
        bufs: Vec<Vec<u8>>,
        off: u64,
    ) -> (crate::Result<usize>, Vec<Vec<u8>>) {
        let (tx, rx) = mpsc::channel();
        let sent = self.send(FsInject::Rw {
            tag,
            pers: who.0,
            slot: f.slot,
            gen: f.gen,
            bufs,
            off,
            reply: tx,
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
        f: &FixedFile,
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
            slot: f.slot,
            gen: f.gen,
            name,
            value,
            off,
            len64,
            aux32,
            reply: tx,
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
        f: &FixedFile,
        off: u64,
        len64: u64,
        aux32: u32,
    ) -> crate::Result<()> {
        let (tx, rx) = mpsc::channel();
        let out = self.call(
            FsInject::FdMeta {
                tag,
                pers: who.0,
                slot: f.slot,
                gen: f.gen,
                name: None,
                value: Vec::new(),
                off,
                len64,
                aux32,
                reply: tx,
            },
            &rx,
        )?;
        out.res.map(|_| ()).map_err(Into::into)
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
                reply: tx,
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
                reply: tx,
            },
            &rx,
        )?;
        out.res.map(|_| ()).map_err(Into::into)
    }

    /// Queue an inject and wake the loop. On failure (loop stopping or gone)
    /// the un-sent message is handed back as `Err(msg)` so a caller can recover
    /// the owned buffers it moved in; the error is always `ECONNABORTED`.
    fn send(&self, msg: FsInject) -> Result<(), FsInject> {
        use std::sync::atomic::Ordering;
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
