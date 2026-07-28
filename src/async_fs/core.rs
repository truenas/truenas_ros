//! The fs core: the op table (owner of every kernel-visible payload from
//! submission to completion), the fixed-file table with its close-last
//! discipline, the SQE builders, and completion routing. A host owns the
//! engine and drives this — [`super::AsyncFs`] standalone, or a `net` server
//! sharing its ring (which is also what [`FsConn`] submits through).
//!
//! Invariants inherited from the net stack, transposed from connections to
//! ops and files:
//!
//! - **The kernel must never touch freed memory.** Buffers, iovec arrays,
//!   paths, `open_how` pads, and anchor dirfds live in the op entry from
//!   submission until the CQE reaps — even when the caller lost interest.
//! - **The index-freeing `CLOSE` is a file's last op.** A close requested
//!   while ops are in flight cancels them and defers; the last reaping op
//!   stages the actual close. A surviving op would otherwise pin the old
//!   file under a reusable index.
//! - **Generations make stale things inert.** File tokens carry the full
//!   `u64` generation (channel-side); op `user_data` packs the low 32 bits,
//!   exact because an op entry frees only at its own single terminal CQE.

use super::{Anchor, FsFile, FsOutcome, Leaf, Personality, ReplyTo};
use crate::errno::Errno;
use crate::sync_fs::openat2::RawOpenHow;
use crate::sync_fs::{
    AtFlags, Mode, OpenHow, RenameFlags, ResolveFlag, Statx, StatxMask,
    StatxRaw,
};
use crate::uring::engine::Engine;
use crate::uring::slots::SlotEntry;
use crate::uring::sys::{
    IoUringCqe, IORING_ASYNC_CANCEL_ALL, IORING_FSYNC_DATASYNC,
    IORING_OP_ASYNC_CANCEL, IORING_OP_CLOSE, IORING_OP_FALLOCATE,
    IORING_OP_FGETXATTR, IORING_OP_FSETXATTR, IORING_OP_FSYNC,
    IORING_OP_FTRUNCATE, IORING_OP_LINKAT, IORING_OP_MKDIRAT,
    IORING_OP_OPENAT2, IORING_OP_READV, IORING_OP_RENAMEAT, IORING_OP_STATX,
    IORING_OP_SYMLINKAT, IORING_OP_UNLINKAT, IORING_OP_WRITEV,
    IOSQE_FIXED_FILE,
};
#[cfg(feature = "rt-tokio")]
use crate::uring::sys::{
    IORING_OP_POLL_ADD, IORING_OP_READ_FIXED, IORING_OP_SEND,
    IORING_OP_SEND_ZC, IORING_OP_SPLICE, IORING_OP_WRITE_FIXED,
    SPLICE_F_FD_IN_FIXED,
};
use crate::uring::user_data::{pack_raw, unpack_raw};
use std::ffi::{CStr, CString};
use std::mem::size_of;

// fs op tags (the 0x80 domain; fs-reactor design §13).
pub(crate) const TAG_OPEN: u8 = 0x80;
pub(crate) const TAG_READV: u8 = 0x81;
pub(crate) const TAG_WRITEV: u8 = 0x82;
pub(crate) const TAG_FSYNC: u8 = 0x83;
pub(crate) const TAG_STATX: u8 = 0x84;
pub(crate) const TAG_CLOSE: u8 = 0x85;
pub(crate) const TAG_FALLOCATE: u8 = 0x87;
pub(crate) const TAG_FTRUNCATE: u8 = 0x88;
pub(crate) const TAG_RENAMEAT: u8 = 0x89;
pub(crate) const TAG_UNLINKAT: u8 = 0x8A;
pub(crate) const TAG_MKDIRAT: u8 = 0x8B;
pub(crate) const TAG_SYMLINKAT: u8 = 0x8C;
pub(crate) const TAG_LINKAT: u8 = 0x8D;
pub(crate) const TAG_FGETXATTR: u8 = 0x8E;
pub(crate) const TAG_FSETXATTR: u8 = 0x8F;
/// Registered-buffer read (`IORING_OP_READ_FIXED`) — the zero-copy tier's
/// data ops. Unconditional consts (they gate `targets_file`, compiled in
/// every build); the submit paths are `rt-tokio`-only.
pub(crate) const TAG_READ_FIXED: u8 = 0x90;
/// Registered-buffer write (`IORING_OP_WRITE_FIXED`).
pub(crate) const TAG_WRITE_FIXED: u8 = 0x91;
/// A bridge splice hop between raw fds (socket↔pipe); holds no file.
pub(crate) const TAG_SPLICE_RAW: u8 = 0x92;
/// A bridge splice hop with a fixed-table file end (pipe↔file) — counted
/// against the file for close-last, like every fd-targeting op.
pub(crate) const TAG_SPLICE_FILE: u8 = 0x93;
/// A bridge readiness poll (one-shot `POLL_ADD` on a raw fd).
pub(crate) const TAG_POLL: u8 = 0x94;
/// A bridge send on a raw socket fd (single CQE).
pub(crate) const TAG_SEND: u8 = 0x95;
/// A bridge zero-copy send (`SEND_ZC`): two CQEs — the result (delivered,
/// `F_MORE`) and the buffer-release notif (`F_NOTIF`, frees the slot).
pub(crate) const TAG_SEND_ZC: u8 = 0x96;
/// The standalone host's wake tag (an embedded host reuses its own).
pub(crate) const TAG_WAKE: u8 = 0x9D;
/// Tags `ASYNC_CANCEL` ops (and the teardown drain); completions ignored.
pub(crate) const TAG_CANCEL: u8 = 0x9E;

/// Does this tag operate on a fixed-table file (and so hold a `FileEntry`
/// op reference for the close-last rule)?
fn targets_file(tag: u8) -> bool {
    matches!(
        tag,
        TAG_READV
            | TAG_WRITEV
            | TAG_READ_FIXED
            | TAG_WRITE_FIXED
            | TAG_SPLICE_FILE
            | TAG_FSYNC
            | TAG_FALLOCATE
            | TAG_FTRUNCATE
            | TAG_FGETXATTR
            | TAG_FSETXATTR
    )
}

/// What a completed embedded (in-loop) fs op hands its callback.
///
/// Plain owned data — it names neither the server nor its per-connection state.
/// Read the outcome with [`result`](FsDone::result); recover the round-tripped
/// buffers a read filled or a write sent with [`into_bufs`](FsDone::into_bufs);
/// after an `open`, take the new file's token with [`file`](FsDone::file) to
/// chain the next op; after a `statx`, take the metadata with
/// [`stat`](FsDone::stat).
pub struct FsDone {
    /// Mapped CQE result: a byte count / `0`, or the errno the op failed with.
    pub(crate) result: Result<i32, Errno>,
    /// The op's owned buffers, back (read/write data, an xattr value).
    pub(crate) bufs: Vec<Vec<u8>>,
    /// For opens: the now-open file's `(registered slot, generation,
    /// opened-under personality id)`, for follow-up ops in a chain.
    pub(crate) file: Option<(u32, u64, u16)>,
    /// For `statx`: the kernel-filled buffer.
    pub(crate) stat: Option<Box<StatxRaw>>,
}

impl std::fmt::Debug for FsDone {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FsDone")
            .field("result", &self.result)
            .field("bufs", &self.bufs.len())
            .field("file", &self.file)
            .field("stat", &self.stat.is_some())
            .finish()
    }
}

impl FsDone {
    /// The operation's result: the byte count for a read/write (`0` for ops
    /// that report none), or the error it failed with (`ENOENT`/`EACCES` from
    /// a working personality, `ECANCELED` if the op was cancelled).
    pub fn result(&self) -> crate::Result<i32> {
        self.result.map_err(Into::into)
    }

    /// The just-opened file's token — `Some` only in an `open`'s callback —
    /// to chain the next op on it, carrying the personality it was opened
    /// under. `None` for every other op, and for a failed open.
    pub fn file(&self) -> Option<FsFile> {
        self.file.map(|(slot, gen, pers)| FsFile {
            slot,
            gen,
            pers,
            as_root: false,
        })
    }

    /// Move the op's owned buffers back out: a read's filled destinations, a
    /// write's sources, an xattr value. Empty for ops that carry none. The
    /// [`result`](FsDone::result) byte count says how much of a read is valid.
    pub fn into_bufs(self) -> Vec<Vec<u8>> {
        self.bufs
    }

    /// The metadata a `statx` returned (`None` for any other op, or a failed
    /// `statx`).
    pub fn stat(&self) -> Option<Statx> {
        // The STATX box is pre-allocated (zeroed) and only the kernel fills it
        // on success; a failed statx leaves it all-zero, so a `None` result
        // means "no metadata", not an existing mode-000 file.
        if self.result.is_err() {
            return None;
        }
        self.stat.as_ref().map(|raw| Statx::from_raw(**raw))
    }
}

/// A callback fired **in the server loop** when an embedded fs op completes.
/// It resolves the owning request (via a captured `Deferred`) or submits the
/// next op in a chain (via the handed-in [`FsConn`]). Same-thread only, so no
/// `Send` bound; it names neither the server nor the connection state
/// (type-erased). Dropping it without firing drops its captured `Deferred`,
/// which closes the connection — so a submission failure needs no separate
/// error path.
pub(crate) type EmbeddedCb = Box<dyn FnOnce(FsDone, &mut FsConn<'_>)>;

/// An opaque per-op/per-file **owner** tag: the embedding host's connection
/// identity `(slot, generation)`, stored so a connection's still-open files can
/// be swept when it closes ([`FsCore::close_owned_by`]). The core never
/// interprets it — it only compares tags for equality; the `net` server reads
/// it back as the connection it minted. `None` on the off-loop channel path
/// (no connection owns those ops).
pub(crate) type Owner = Option<(u32, u64)>;

/// Where a completed fs op's outcome goes: back over a channel to an off-loop
/// [`FsHandle`](super::FsHandle) caller, or into an in-loop callback the
/// embedding host (a `net` server) fires. The embedded arm carries the owning
/// connection's [`Owner`] tag, stamped onto the op (and its file, for an open)
/// so the connection-close sweep can find them.
pub(crate) enum FsWaiter {
    Channel(ReplyTo),
    Embedded { owner: Owner, cb: EmbeddedCb },
}

impl FsWaiter {
    /// The owner tag to stamp onto the op entry (`None` for the channel path).
    fn owner(&self) -> Owner {
        match self {
            FsWaiter::Channel(_) => None,
            FsWaiter::Embedded { owner, .. } => *owner,
        }
    }
}

/// Box a consumer callback as an owner-stamped embedded waiter — the one shape
/// every [`FsConn`] submit method hands the core.
fn embed<F>(owner: Owner, on_done: F) -> FsWaiter
where
    F: FnOnce(FsDone, &mut FsConn<'_>) + 'static,
{
    FsWaiter::Embedded {
        owner,
        cb: Box::new(on_done),
    }
}

/// Report an early submission failure — the SQE never staged (slot exhaustion,
/// an unusable file) — handing the caller's payloads back exactly as a
/// completion would (see [`deliver`]).
fn fail(waiter: FsWaiter, err: Errno, bufs: Vec<Vec<u8>>) {
    let _ = deliver(Some(waiter), Err(err), bufs, None, None);
}

/// The request-bound fs submission facade a `net` server hands a protocol
/// handler (`Request::fs`) and re-hands each completion callback for chaining.
///
/// Every op runs on the server's own ring, stamped with the [`Personality`]
/// passed to it (the kernel checks permissions as that identity), and its
/// completion fires the `on_done` callback **inline on the loop thread**. The
/// callback resolves the request through a `Deferred` it captured — the first
/// op parks the request (the handler returns `Response::Defer`), a chained op
/// continues toward the same parked request, and the terminal callback replies.
///
/// **Re-entrancy:** callbacks run inside dispatch — never block, and drive the
/// ring only through this facade. A submission or argument-validation failure
/// needs no error return: it drops the `on_done` closure, and dropping the
/// `Deferred` the closure captured closes the connection. So these methods
/// return `()` — the outcome (including "couldn't submit") always reaches the
/// connection.
pub struct FsConn<'a> {
    fs: &'a mut FsCore,
    eng: &'a mut Engine,
    /// The owning connection, stamped onto every op this facade submits so the
    /// connection-close sweep can reclaim files it opened but never closed.
    /// Propagated to each chained callback's facade (an open→read chain stays
    /// owned by the one connection).
    owner: Owner,
    /// Kernel-capability flags (from the server), so an unsupported fd op
    /// fails closed with `EOPNOTSUPP` at the facade instead of surfacing a
    /// bare kernel `EBADF` in the callback — matching the blocking
    /// [`FsHandle`](super::FsHandle) surface.
    fd_xattr_ok: bool,
    ftruncate_ok: bool,
    /// `true` only for the request-handler facade, where [`open`](FsConn::open)
    /// may mint a new file. A continuation (a completion callback's facade) is
    /// `false`: it can fire after its connection was swept, so a file opened
    /// under that dead owner would never be reclaimed — `open` is refused
    /// there. A chain works the file it already holds and closes it.
    root: bool,
}

impl std::fmt::Debug for FsConn<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FsConn").finish_non_exhaustive()
    }
}

impl<'a> FsConn<'a> {
    // Minted by the embedding `net` server (in dispatch and `Request::fs`); dead
    // in an async-fs-only build, which has no server to hand it out.
    #[allow(dead_code)] // minted only by an embedding host (none in-tree today)
    pub(crate) fn new(
        fs: &'a mut FsCore,
        eng: &'a mut Engine,
        owner: Owner,
        fd_xattr_ok: bool,
        ftruncate_ok: bool,
        root: bool,
    ) -> FsConn<'a> {
        FsConn {
            fs,
            eng,
            owner,
            fd_xattr_ok,
            ftruncate_ok,
            root,
        }
    }

    /// Fire `on_done` **now** with a synthesized error and no ring op — used
    /// when a fd op is unsupported on this kernel, so the callback resolves
    /// its request with `EOPNOTSUPP` (round-tripping `bufs`) rather than get a
    /// bare `EBADF` from the kernel later.
    fn fail_now<F>(&mut self, err: Errno, bufs: Vec<Vec<u8>>, on_done: F)
    where
        F: FnOnce(FsDone, &mut FsConn<'_>) + 'static,
    {
        let done = FsDone {
            result: Err(err),
            bufs,
            file: None,
            stat: None,
        };
        on_done(done, self);
    }

    /// Open `path` — **relative**, resolved against `anchor` under the
    /// kernel's checks as `who` — into a fixed-table slot, then fire `on_done`
    /// with the new [`FsFile`](super::FsFile) (via [`FsDone::file`]).
    ///
    /// `path` must be anchor-relative (a leading `/` is refused) and must not
    /// carry `O_CLOEXEC` (meaningless for a fixed-table file). Resolution
    /// defaults to `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS` — the walk stays
    /// under `anchor` and follows no symlink — unless `how` already carries a
    /// `resolve` policy, which is then honored as-is. An invalid argument drops
    /// `on_done` and closes the connection.
    ///
    /// **Only the request-handler facade may open.** A completion callback gets
    /// a facade whose `open` is refused: it works the file it was handed and
    /// closes it. Opening a *new* file from a callback is unsupported — the
    /// callback can run after its connection was already swept, so that file
    /// would hold its pool slot until server teardown, and a peer that aborts
    /// mid-chain could exhaust `fs_files` for everyone. Refused the same way as
    /// any bad argument: `on_done` is dropped, which closes the connection.
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
        // `open` is available only on the request-handler facade — never in a
        // continuation, where the owning connection may already be gone and a
        // file opened here would never be swept. Deliberately a plain
        // fail-closed return and NOT a `debug_assert!`: this is the whole
        // structural guarantee behind the owned-file sweep, so it has to behave
        // (and be testable) identically in debug and release — and panicking
        // here would unwind the reactor loop, taking every other connection
        // down for one handler's misuse.
        if !self.root {
            return;
        }
        let bytes = path.to_bytes();
        if bytes.is_empty() || bytes[0] == b'/' {
            return; // anchor-relative only; drop `on_done` → close conn
        }
        let mut raw = how.to_raw();
        if raw.flags & libc::O_CLOEXEC as u64 != 0 {
            return; // O_CLOEXEC is rejected for fixed-table opens
        }
        // Confine to `anchor` by default: an unset `resolve` would let `..` or
        // a symlink climb out of the share. `RESOLVE_BENEATH` rejects any
        // escape and `RESOLVE_NO_SYMLINKS` refuses symlink following outright;
        // a caller that chose its own `resolve` policy is left untouched.
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

    /// Vectored positional read (`preadv(2)`): fill each buffer up to its
    /// `len()`, in order, from offset `off`; `on_done`'s [`FsDone`] carries the
    /// byte count and the buffers back ([`FsDone::into_bufs`]). Runs as the
    /// personality `f` was opened under (or root via [`FsFile::as_root`]).
    pub fn preadv<F>(
        &mut self,
        f: FsFile,
        bufs: Vec<Vec<u8>>,
        off: u64,
        on_done: F,
    ) where
        F: FnOnce(FsDone, &mut FsConn<'_>) + 'static,
    {
        self.rw(TAG_READV, f, bufs, off, on_done);
    }

    /// Single-buffer positional read (`pread(2)`) — the one-vector
    /// [`preadv`](FsConn::preadv).
    pub fn pread<F>(&mut self, f: FsFile, buf: Vec<u8>, off: u64, on_done: F)
    where
        F: FnOnce(FsDone, &mut FsConn<'_>) + 'static,
    {
        self.rw(TAG_READV, f, vec![buf], off, on_done);
    }

    /// Vectored positional write (`pwritev(2)`): write each buffer's `len()`
    /// bytes, in order, from offset `off`. Runs as `f`'s personality.
    pub fn pwritev<F>(
        &mut self,
        f: FsFile,
        bufs: Vec<Vec<u8>>,
        off: u64,
        on_done: F,
    ) where
        F: FnOnce(FsDone, &mut FsConn<'_>) + 'static,
    {
        self.rw(TAG_WRITEV, f, bufs, off, on_done);
    }

    /// Single-buffer positional write (`pwrite(2)`) — the one-vector
    /// [`pwritev`](FsConn::pwritev).
    pub fn pwrite<F>(&mut self, f: FsFile, buf: Vec<u8>, off: u64, on_done: F)
    where
        F: FnOnce(FsDone, &mut FsConn<'_>) + 'static,
    {
        self.rw(TAG_WRITEV, f, vec![buf], off, on_done);
    }

    /// Flush `f`'s data and metadata (`fsync`), then fire `on_done`.
    pub fn fsync<F>(&mut self, f: FsFile, on_done: F)
    where
        F: FnOnce(FsDone, &mut FsConn<'_>) + 'static,
    {
        self.fs.submit_fsync(
            self.eng,
            f.op_pers(),
            f.slot,
            f.gen,
            false,
            embed(self.owner, on_done),
        );
    }

    /// Flush `f`'s data and only essential metadata (`fdatasync`).
    pub fn fdatasync<F>(&mut self, f: FsFile, on_done: F)
    where
        F: FnOnce(FsDone, &mut FsConn<'_>) + 'static,
    {
        self.fs.submit_fsync(
            self.eng,
            f.op_pers(),
            f.slot,
            f.gen,
            true,
            embed(self.owner, on_done),
        );
    }

    /// Stat the entry `leaf` inside `anchor` as `who` — the one metadata op
    /// that resolves a name (no kernel offers statx on a fixed-table file).
    /// Does **not** follow a terminal symlink by default (a leaf symlink is
    /// stat'd as the link itself); pass `AtFlags::AT_SYMLINK_FOLLOW` to stat
    /// the target instead. `on_done`'s [`FsDone`] carries the metadata
    /// ([`FsDone::stat`]).
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
            // Default to not following a terminal symlink (a peer-planted leaf
            // symlink can't redirect the stat out of the anchor); the caller
            // opts into following with AT_SYMLINK_FOLLOW.
            super::statx_at_flags(flags),
            mask.bits(),
            embed(self.owner, on_done),
        );
    }

    /// Stat the anchor directory itself (`AT_EMPTY_PATH` on its dirfd) — the
    /// closest fd-based statx this interface offers. `flags` are normalized as
    /// for [`statx`](FsConn::statx); the follow/no-follow choice is moot here,
    /// since an anchor's own dirfd names no symlink to resolve.
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
            // Through the same normalizer as every other statx here, so one
            // rule (safe default, explicit AT_SYMLINK_FOLLOW opt-in) covers all
            // four entry points and no `AT_*` bit reaches the kernel unfiltered.
            super::statx_at_flags(flags | AtFlags::AT_EMPTY_PATH),
            mask.bits(),
            embed(self.owner, on_done),
        );
    }

    // ---- metadata on an open file ------------------------------------

    /// Read extended attribute `name` from `f` into `buf`; `on_done`'s
    /// [`FsDone`] carries the attribute size ([`FsDone::result`]) and the
    /// filled buffer ([`FsDone::into_bufs`]). An empty `buf` queries the size.
    /// Runs as `f`'s personality — take `f.`[`as_root()`](super::FsFile::as_root)
    /// for a `trusted.*`/`security.*` read the peer itself can't do.
    ///
    /// Needs Linux ≥ 6.13 for a fixed-table file; on an older kernel this
    /// fails closed — `on_done` fires at once with `EOPNOTSUPP` (the buffer
    /// round-tripped), matching the blocking
    /// [`FsHandle::fgetxattr`](super::FsHandle::fgetxattr).
    pub fn fgetxattr<F>(
        &mut self,
        f: FsFile,
        name: &CStr,
        buf: Vec<u8>,
        on_done: F,
    ) where
        F: FnOnce(FsDone, &mut FsConn<'_>) + 'static,
    {
        if !self.fd_xattr_ok {
            return self.fail_now(Errno::EOPNOTSUPP, vec![buf], on_done);
        }
        self.fd_meta(
            TAG_FGETXATTR,
            f,
            Some(name.to_owned()),
            buf,
            0,
            0,
            0,
            on_done,
        );
    }

    /// Write extended attribute `name` on `f`. `flags` takes
    /// `libc::XATTR_CREATE`/`XATTR_REPLACE` (or 0 for create-or-replace); the
    /// value round-trips in `on_done`'s [`FsDone::into_bufs`]. Runs as `f`'s
    /// personality (or root via [`as_root()`](super::FsFile::as_root)). Needs
    /// Linux ≥ 6.13, like [`fgetxattr`](FsConn::fgetxattr) — and fails closed
    /// the same way on an older kernel.
    pub fn fsetxattr<F>(
        &mut self,
        f: FsFile,
        name: &CStr,
        value: Vec<u8>,
        flags: i32,
        on_done: F,
    ) where
        F: FnOnce(FsDone, &mut FsConn<'_>) + 'static,
    {
        if !self.fd_xattr_ok {
            return self.fail_now(Errno::EOPNOTSUPP, vec![value], on_done);
        }
        self.fd_meta(
            TAG_FSETXATTR,
            f,
            Some(name.to_owned()),
            value,
            0,
            0,
            flags as u32,
            on_done,
        );
    }

    /// Set `f`'s length to `len` (`ftruncate`). Needs `IORING_OP_FTRUNCATE`
    /// (Linux ≥ 6.9); on an older kernel this fails closed, firing `on_done`
    /// with `EOPNOTSUPP`.
    pub fn ftruncate<F>(&mut self, f: FsFile, len: u64, on_done: F)
    where
        F: FnOnce(FsDone, &mut FsConn<'_>) + 'static,
    {
        if !self.ftruncate_ok {
            return self.fail_now(Errno::EOPNOTSUPP, Vec::new(), on_done);
        }
        self.fd_meta(TAG_FTRUNCATE, f, None, Vec::new(), len, 0, 0, on_done);
    }

    /// Manipulate `f`'s allocated blocks (`fallocate`): `mode` is 0 to
    /// preallocate, or a `libc::FALLOC_FL_*` combination (punch hole, zero
    /// range, …).
    pub fn fallocate<F>(
        &mut self,
        f: FsFile,
        mode: i32,
        off: u64,
        len: u64,
        on_done: F,
    ) where
        F: FnOnce(FsDone, &mut FsConn<'_>) + 'static,
    {
        self.fd_meta(
            TAG_FALLOCATE,
            f,
            None,
            Vec::new(),
            off,
            len,
            mode as u32,
            on_done,
        );
    }

    // ---- directory entries (anchor + validated leaf) -----------------

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

    /// Rename `old_leaf` in `old` to `new_leaf` in `new` as `who`. `flags`
    /// takes [`RenameFlags`] (`RENAME_NOREPLACE`, `RENAME_EXCHANGE`, …). The
    /// anchors may be the same and must be on one filesystem.
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

    /// Create a symlink `leaf` in `anchor` pointing at `target` as `who`.
    /// `target` is link *content* — stored verbatim, never resolved here, so
    /// deliberately not a [`Leaf`] and may be any path. An empty `target` is
    /// rejected (dropping `on_done` closes the connection), as everywhere else
    /// on this facade.
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
            return; // no such thing as an empty link target
        }
        // The link content is the *first* name and the entry to create is the
        // second — the reverse of the leaf-first `path_op` shape.
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

    /// Create a hard link at `new_leaf` in `new` for the existing `old_leaf`
    /// in `old` as `who`. `flags` may carry `AT_SYMLINK_FOLLOW`.
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

    /// Close `f` and free its pool slot. Fire-and-forget: any ops still in
    /// flight on it are cancelled first and the index-freeing close is the
    /// file's last op (as for [`FsHandle::close`](super::FsHandle::close)), but
    /// there is no completion callback — a chain closes its file after its last
    /// read/write. Personality-free by design (a fixed-slot close consults no
    /// credentials).
    pub fn close(&mut self, f: FsFile) {
        self.fs.submit_close(self.eng, f.slot, f.gen, None);
    }

    fn rw<F>(
        &mut self,
        tag: u8,
        f: FsFile,
        bufs: Vec<Vec<u8>>,
        off: u64,
        on_done: F,
    ) where
        F: FnOnce(FsDone, &mut FsConn<'_>) + 'static,
    {
        self.fs.submit_rw(
            self.eng,
            tag,
            f.op_pers(),
            f.slot,
            f.gen,
            bufs,
            off,
            embed(self.owner, on_done),
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn fd_meta<F>(
        &mut self,
        tag: u8,
        f: FsFile,
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
            f.op_pers(),
            f.slot,
            f.gen,
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
    /// `OPENAT2` `open_how` pad — boxed for a stable address.
    how: Option<Box<RawOpenHow>>,
    /// `STATX` result pad — **the kernel writes it at completion**, so it
    /// must live until the CQE reaps.
    stat: Option<Box<StatxRaw>>,
    /// Keeps a path op's dirfd alive (and its fd number un-reused) while
    /// the op is in flight.
    anchor: Option<Anchor>,
    /// The second dirfd of a rename/link.
    anchor2: Option<Anchor>,
    /// Raw descriptors a bridge op names (socket dups, pipe halves), kept
    /// open — and their fd numbers un-reused — until the CQE reaps.
    #[cfg(feature = "rt-tokio")]
    raw_fds: Vec<std::sync::Arc<std::os::fd::OwnedFd>>,
    /// The fixed-file slot this op targets.
    file_slot: Option<u32>,
    /// The owning connection (embedded path), propagated to a chained op's
    /// facade so an open→read chain stays owned by the one connection. `None`
    /// on the off-loop channel path.
    owner: Owner,
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum FsOpState {
    Free,
    InFlight {
        tag: u8,
    },
    /// A `SEND_ZC` past its *result* CQE (`F_MORE`), still pinning its
    /// payload until the `F_NOTIF` CQE frees the slot. The generation is
    /// deliberately unbumped — the notif carries the same `user_data` and
    /// must still match. `failed_res` is `None` when the send succeeded (the
    /// waiter was already resolved at the result; the notif just frees), or
    /// `Some(negative res)` when it failed — in which case the waiter and
    /// payload are held here and delivered at the notif, once the kernel has
    /// definitively released every page (a mid-send error can leave partial
    /// skbs referencing them until then, so handing the buffer back at the
    /// result would be a use-after-free).
    #[cfg(feature = "rt-tokio")]
    ZcAwaitNotif {
        failed_res: Option<i32>,
    },
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
            #[cfg(feature = "rt-tokio")]
            raw_fds: Vec::new(),
            file_slot: None,
            owner: None,
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
        #[cfg(feature = "rt-tokio")]
        self.raw_fds.clear();
        self.file_slot = None;
        self.owner = None;
        self.state = FsOpState::Free;
    }
}

/// What a reaped op entry yields once its payloads are taken back out.
struct Completed {
    waiter: Option<FsWaiter>,
    bufs: Vec<Vec<u8>>,
    stat: Option<Box<StatxRaw>>,
    file_slot: Option<u32>,
    /// The op's owning connection, so `on_cqe` can re-stamp a chained op the
    /// fired callback submits (propagation) — see [`Owner`].
    owner: Owner,
}

/// One fixed-table file slot's lifecycle state.
struct FileEntry {
    state: FileState,
    /// In-flight data ops on this file (gates the close-last rule).
    ops: u16,
    /// A close arrived while `ops > 0`; the last reaping op stages it.
    close_deferred: bool,
    /// The deferred close's waiter, parked until the close is staged.
    close_waiter: Option<ReplyTo>,
    /// The connection that opened this file (embedded path), for the
    /// connection-close sweep ([`FsCore::close_owned_by`]). `None` off-loop.
    owner: Owner,
    /// The owner closed while this file was still `Opening`: its open's
    /// completion closes it at once instead of leaving an orphaned open file.
    orphaned: bool,
    /// The personality id the file was opened under, handed to the embedded
    /// caller in the [`FsFile`] token so its fd-ops run as that identity.
    pers: u16,
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum FileState {
    Free,
    Opening,
    Open,
    Closing,
}

impl FileEntry {
    fn new() -> FileEntry {
        FileEntry {
            state: FileState::Free,
            ops: 0,
            close_deferred: false,
            close_waiter: None,
            owner: None,
            orphaned: false,
            pers: 0,
        }
    }
}

/// The fs domain's tables. The host owns the [`Engine`] and passes it in for
/// staging; completion routing happens in [`FsCore::on_cqe`].
pub(crate) struct FsCore {
    ops: Vec<SlotEntry<FsOpEntry>>,
    op_free: Vec<u32>,
    files: Vec<SlotEntry<FileEntry>>,
    file_free: Vec<u32>,
    /// The registered index the fs file range starts at: the `[0, file_base)`
    /// prefix belongs to the embedding host's connection pool and is never used
    /// here, so table scans start at `file_base`.
    file_base: u32,
    /// Open-or-opening files right now: lets the connection-close sweep skip the
    /// table scan entirely when nothing is open.
    live_files: u32,
    /// A close wanted staging but the op table was exhausted; retry on the
    /// next completion (which just freed an op slot).
    close_retry: bool,
}

impl FsCore {
    /// `file_base` is the registered-table index the fs file range starts at:
    /// `0` for the standalone reactor, or `pool_size` when embedded in a
    /// server (the low `[0, pool)` indices belong to the connection pool, so
    /// the fs table occupies `[pool, pool + file_slots)`). The `files` Vec is
    /// indexed by the registered slot, so its low `file_base` entries stay
    /// unused — a few hundred bytes, versus threading a base offset through
    /// every slot computation.
    pub(crate) fn new(
        op_slots: u32,
        file_base: u32,
        file_slots: u32,
    ) -> FsCore {
        FsCore {
            ops: (0..op_slots)
                .map(|_| SlotEntry {
                    generation: 0,
                    state: FsOpEntry::new(),
                })
                .collect(),
            op_free: (0..op_slots).rev().collect(),
            files: (0..file_base + file_slots)
                .map(|_| SlotEntry {
                    generation: 0,
                    state: FileEntry::new(),
                })
                .collect(),
            file_free: (file_base..file_base + file_slots).rev().collect(),
            file_base,
            live_files: 0,
            close_retry: false,
        }
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
        // owner's ambient (root) credentials — the identity this surface must
        // never grant implicitly. `Personality` cannot be 0 by construction, so
        // this only catches an internal misuse; fail closed regardless.
        if pers == 0 {
            fail(waiter, Errno::EINVAL, Vec::new());
            return;
        }
        let Some(file_slot) = self.file_free.pop() else {
            fail(waiter, Errno::ENFILE, Vec::new());
            return;
        };
        let Some(op_slot) = self.op_free.pop() else {
            self.file_free.push(file_slot);
            fail(waiter, Errno::EBUSY, Vec::new());
            return;
        };

        let owner = waiter.owner();
        let fe = &mut self.files[file_slot as usize].state;
        fe.state = FileState::Opening;
        // The file carries the owner too (not just the op): the open completes
        // and frees the op, but the file lives on until closed — the sweep
        // finds it by this tag. It also records the personality it was opened
        // under, to hand back in the `FsFile` token (fd-ops run as that id).
        fe.owner = owner;
        fe.pers = pers;
        self.live_files += 1;

        let entry = &mut self.ops[op_slot as usize];
        let gen32 = entry.generation as u32;
        let e = &mut entry.state;
        e.state = FsOpState::InFlight { tag: TAG_OPEN };
        e.owner = owner;
        e.waiter = Some(waiter);
        e.path = Some(path);
        e.how = Some(Box::new(how));
        e.file_slot = Some(file_slot);
        let dirfd = anchor.raw_fd();
        let path_ptr = e.path.as_ref().expect("just set").as_ptr() as u64;
        let how_ptr =
            &**e.how.as_ref().expect("just set") as *const RawOpenHow as u64;
        e.anchor = Some(anchor);

        let ud = pack_raw(TAG_OPEN, op_slot, gen32);
        let staged = eng.stage(ud, |sqe| {
            sqe.opcode = IORING_OP_OPENAT2;
            sqe.fd = dirfd;
            sqe.addr = path_ptr;
            sqe.off_addr2 = how_ptr;
            sqe.len = size_of::<RawOpenHow>() as u32;
            sqe.file_index = file_slot + 1;
            // `pers != 0` guaranteed at entry (fail-closed above).
            sqe.personality = pers;
        });
        if let Err(e) = staged {
            self.free_file_slot(file_slot);
            self.fail_op(op_slot, e);
        }
    }

    /// Stage a `READV`/`WRITEV` (per `tag`) against an open file.
    #[allow(clippy::too_many_arguments)] // an inject unpacked, not an API
    pub(crate) fn submit_rw(
        &mut self,
        eng: &mut Engine,
        tag: u8,
        pers: u16,
        file_slot: u32,
        file_gen: u64,
        mut bufs: Vec<Vec<u8>>,
        off: u64,
        waiter: FsWaiter,
    ) {
        if !self.file_usable(file_slot, file_gen) {
            fail(waiter, Errno::EBADF, bufs);
            return;
        }
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

        let entry = &mut self.ops[op_slot as usize];
        let gen32 = entry.generation as u32;
        let e = &mut entry.state;
        e.state = FsOpState::InFlight { tag };
        e.owner = waiter.owner();
        e.waiter = Some(waiter);
        e.bufs = bufs;
        e.iov = iov;
        e.file_slot = Some(file_slot);
        let iov_ptr = e.iov.as_ptr() as u64;
        let iov_len = e.iov.len() as u32;

        self.files[file_slot as usize].state.ops += 1;

        let opcode = if tag == TAG_READV {
            IORING_OP_READV
        } else {
            IORING_OP_WRITEV
        };
        let ud = pack_raw(tag, op_slot, gen32);
        let staged = eng.stage(ud, |sqe| {
            sqe.opcode = opcode;
            sqe.flags = IOSQE_FIXED_FILE;
            sqe.fd = file_slot as i32;
            sqe.addr = iov_ptr;
            sqe.len = iov_len;
            sqe.off_addr2 = off;
            // `pers` may be 0: the intentional BECOME_ROOT path
            // ([`FsFile::as_root`]). fd-ops on an already-open file permit the
            // ambient-root identity; only the name-resolving ops (open /
            // path_op) assert a nonzero personality.
            sqe.personality = pers;
        });
        if let Err(err) = staged {
            self.files[file_slot as usize].state.ops -= 1;
            self.fail_op(op_slot, err);
        }
    }

    /// Stage a `READ_FIXED`/`WRITE_FIXED` (per `tag`) against an open file.
    /// The SQE names a range inside a registered buffer
    /// (`addr`/`len`/`buf_index`); the **owning** lease rides in the
    /// waiter's reply endpoint, held by this op entry until the CQE reaps —
    /// so the address cannot dangle while the kernel may touch it (see
    /// [`FsInject::RwFixed`](super::FsInject)).
    #[cfg(feature = "rt-tokio")]
    #[allow(clippy::too_many_arguments)] // an inject unpacked, not an API
    pub(crate) fn submit_rw_fixed(
        &mut self,
        eng: &mut Engine,
        tag: u8,
        pers: u16,
        file_slot: u32,
        file_gen: u64,
        addr: u64,
        len: u32,
        buf_index: u16,
        off: u64,
        waiter: FsWaiter,
    ) {
        if !self.file_usable(file_slot, file_gen) {
            fail(waiter, Errno::EBADF, Vec::new());
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
        e.owner = waiter.owner();
        e.waiter = Some(waiter);
        e.file_slot = Some(file_slot);

        self.files[file_slot as usize].state.ops += 1;

        let opcode = if tag == TAG_READ_FIXED {
            IORING_OP_READ_FIXED
        } else {
            IORING_OP_WRITE_FIXED
        };
        let ud = pack_raw(tag, op_slot, gen32);
        let staged = eng.stage(ud, |sqe| {
            sqe.opcode = opcode;
            sqe.flags = IOSQE_FIXED_FILE;
            sqe.fd = file_slot as i32;
            sqe.addr = addr;
            sqe.len = len;
            sqe.off_addr2 = off;
            sqe.buf_index = buf_index;
            // `pers` may be 0: the BECOME_ROOT path ([`FsFile::as_root`]);
            // see `submit_rw`.
            sqe.personality = pers;
        });
        if let Err(err) = staged {
            self.files[file_slot as usize].state.ops -= 1;
            self.fail_op(op_slot, err);
        }
    }

    /// Stage one bridge splice hop. At most one end is a fixed-table file
    /// (the bridges splice socket↔pipe↔file): that end is generation-checked
    /// and takes an op reference (close-last); raw ends are kept alive by
    /// the `keep` anchors until the CQE. Personality 0 by design — splice
    /// resolves no names, and the file end was permission-checked at open.
    #[cfg(feature = "rt-tokio")]
    #[allow(clippy::too_many_arguments)] // an inject unpacked, not an API
    pub(crate) fn submit_splice(
        &mut self,
        eng: &mut Engine,
        in_end: super::SpliceEnd,
        off_in: u64,
        out_end: super::SpliceEnd,
        off_out: u64,
        len: u32,
        flags: u32,
        keep: Vec<std::sync::Arc<std::os::fd::OwnedFd>>,
        cancel: super::CancelToken,
        waiter: FsWaiter,
    ) {
        use super::SpliceEnd;
        let file_slot = match (in_end, out_end) {
            (SpliceEnd::Fixed { slot, gen }, _)
            | (_, SpliceEnd::Fixed { slot, gen }) => {
                if !self.file_usable(slot, gen) {
                    fail(waiter, Errno::EBADF, Vec::new());
                    return;
                }
                Some(slot)
            }
            _ => None,
        };
        let tag = if file_slot.is_some() {
            TAG_SPLICE_FILE
        } else {
            TAG_SPLICE_RAW
        };
        let Some(op_slot) = self.op_free.pop() else {
            fail(waiter, Errno::EBUSY, Vec::new());
            return;
        };
        let gen32 = self.ops[op_slot as usize].generation as u32;
        let ud = pack_raw(tag, op_slot, gen32);
        if !publish_cancel(&cancel, ud) {
            // The bridge future was dropped before we staged: abort cleanly.
            self.op_free.push(op_slot);
            fail(waiter, Errno::ECANCELED, Vec::new());
            return;
        }

        let e = &mut self.ops[op_slot as usize].state;
        e.state = FsOpState::InFlight { tag };
        e.owner = waiter.owner();
        e.waiter = Some(waiter);
        e.raw_fds = keep;
        e.file_slot = file_slot;
        if let Some(fs) = file_slot {
            self.files[fs as usize].state.ops += 1;
        }

        let staged = eng.stage(ud, |sqe| {
            sqe.opcode = IORING_OP_SPLICE;
            // Output end: `sqe.fd` — the 0-based fixed slot under
            // `IOSQE_FIXED_FILE`, or the raw fd.
            match out_end {
                SpliceEnd::Raw(fd) => sqe.fd = fd,
                SpliceEnd::Fixed { slot, .. } => {
                    sqe.flags = IOSQE_FIXED_FILE;
                    sqe.fd = slot as i32;
                }
            }
            // Input end: `splice_fd_in` overlays `file_index` — the raw fd
            // value, or the 0-based fixed slot flagged FD_IN_FIXED.
            match in_end {
                SpliceEnd::Raw(fd) => sqe.file_index = fd as u32,
                SpliceEnd::Fixed { slot, .. } => {
                    sqe.file_index = slot;
                    sqe.op_flags = SPLICE_F_FD_IN_FIXED;
                }
            }
            sqe.op_flags |= flags;
            sqe.addr = off_in; // splice_off_in
            sqe.off_addr2 = off_out; // off_out
            sqe.len = len;
        });
        if let Err(err) = staged {
            if let Some(fs) = file_slot {
                self.files[fs as usize].state.ops -= 1;
            }
            self.fail_op(op_slot, err);
        }
    }

    /// Stage a one-shot readiness poll on a raw fd — the bridges' retry
    /// signal after a splice returned `-EAGAIN` (io_uring never poll-arms
    /// splice itself; `opdef` declares no pollin/pollout for it).
    #[cfg(feature = "rt-tokio")]
    pub(crate) fn submit_poll(
        &mut self,
        eng: &mut Engine,
        fd: std::os::fd::RawFd,
        events: u32,
        keep: std::sync::Arc<std::os::fd::OwnedFd>,
        cancel: super::CancelToken,
        waiter: FsWaiter,
    ) {
        let Some(op_slot) = self.op_free.pop() else {
            fail(waiter, Errno::EBUSY, Vec::new());
            return;
        };
        let gen32 = self.ops[op_slot as usize].generation as u32;
        let ud = pack_raw(TAG_POLL, op_slot, gen32);
        if !publish_cancel(&cancel, ud) {
            self.op_free.push(op_slot);
            fail(waiter, Errno::ECANCELED, Vec::new());
            return;
        }
        let e = &mut self.ops[op_slot as usize].state;
        e.state = FsOpState::InFlight { tag: TAG_POLL };
        e.owner = waiter.owner();
        e.waiter = Some(waiter);
        e.raw_fds = vec![keep];

        let staged = eng.stage(ud, |sqe| {
            sqe.opcode = IORING_OP_POLL_ADD;
            sqe.fd = fd;
            sqe.op_flags = events; // poll32_events; ERR/HUP are implicit
        });
        if let Err(err) = staged {
            self.fail_op(op_slot, err);
        }
    }

    /// Stage a bridge send on a raw socket fd: `data[start..]`, plain
    /// (`SEND`, one CQE, payload round-trips at completion) or zero-copy
    /// (`SEND_ZC`, two CQEs — see [`FsCore::on_send_zc_cqe`]; the payload
    /// stays op-owned until the notif, and round-trips only on a flagless
    /// early failure, which is what lets the `EOPNOTSUPP`-on-kTLS attempt
    /// hand the bytes back for the plain-send fallback).
    #[cfg(feature = "rt-tokio")]
    #[allow(clippy::too_many_arguments)] // an inject unpacked, not an API
    pub(crate) fn submit_send(
        &mut self,
        eng: &mut Engine,
        fd: std::os::fd::RawFd,
        data: Vec<u8>,
        start: usize,
        msg_flags: u32,
        zc: bool,
        keep: std::sync::Arc<std::os::fd::OwnedFd>,
        cancel: super::CancelToken,
        waiter: FsWaiter,
    ) {
        if start >= data.len() {
            fail(waiter, Errno::EINVAL, vec![data]);
            return;
        }
        // `sqe.len` is a u32: a payload tail >= 4 GiB would truncate (or wrap
        // to 0 at exactly 4 GiB) and silently under-send while reporting the
        // truncated count as success. Reject it up front, as `rw_fixed` does
        // — the caller chunks. (A single 4 GiB+ send is pathological; a bare
        // truncating cast is a data-corruption hazard, not a convenience.)
        let Ok(len) = u32::try_from(data.len() - start) else {
            fail(waiter, Errno::EINVAL, vec![data]);
            return;
        };
        let Some(op_slot) = self.op_free.pop() else {
            fail(waiter, Errno::EBUSY, vec![data]);
            return;
        };
        let tag = if zc { TAG_SEND_ZC } else { TAG_SEND };
        let gen32 = self.ops[op_slot as usize].generation as u32;
        let ud = pack_raw(tag, op_slot, gen32);
        if !publish_cancel(&cancel, ud) {
            self.op_free.push(op_slot);
            fail(waiter, Errno::ECANCELED, vec![data]);
            return;
        }
        let e = &mut self.ops[op_slot as usize].state;
        e.state = FsOpState::InFlight { tag };
        e.owner = waiter.owner();
        e.waiter = Some(waiter);
        e.bufs = vec![data];
        e.raw_fds = vec![keep];
        let addr = e.bufs[0].as_ptr() as u64 + start as u64;

        let staged = eng.stage(ud, |sqe| {
            sqe.opcode = if zc {
                IORING_OP_SEND_ZC
            } else {
                IORING_OP_SEND
            };
            sqe.fd = fd;
            sqe.addr = addr;
            sqe.len = len;
            sqe.op_flags = msg_flags;
        });
        if let Err(err) = staged {
            self.fail_op(op_slot, err);
        }
    }

    /// Stage an `FSYNC` (whole-file; `datasync` selects `fdatasync`).
    pub(crate) fn submit_fsync(
        &mut self,
        eng: &mut Engine,
        pers: u16,
        file_slot: u32,
        file_gen: u64,
        datasync: bool,
        waiter: FsWaiter,
    ) {
        if !self.file_usable(file_slot, file_gen) {
            fail(waiter, Errno::EBADF, Vec::new());
            return;
        }
        let Some(op_slot) = self.op_free.pop() else {
            fail(waiter, Errno::EBUSY, Vec::new());
            return;
        };

        let entry = &mut self.ops[op_slot as usize];
        let gen32 = entry.generation as u32;
        let e = &mut entry.state;
        e.state = FsOpState::InFlight { tag: TAG_FSYNC };
        e.owner = waiter.owner();
        e.waiter = Some(waiter);
        e.file_slot = Some(file_slot);

        self.files[file_slot as usize].state.ops += 1;

        let ud = pack_raw(TAG_FSYNC, op_slot, gen32);
        let staged = eng.stage(ud, |sqe| {
            sqe.opcode = IORING_OP_FSYNC;
            sqe.flags = IOSQE_FIXED_FILE;
            sqe.fd = file_slot as i32;
            if datasync {
                sqe.op_flags = IORING_FSYNC_DATASYNC;
            }
            // `pers` may be 0: the BECOME_ROOT path ([`FsFile::as_root`]); see
            // `submit_rw`.
            sqe.personality = pers;
        });
        if let Err(err) = staged {
            self.files[file_slot as usize].state.ops -= 1;
            self.fail_op(op_slot, err);
        }
    }

    /// Stage a metadata op that targets an **open file** by its pool slot:
    /// `FTRUNCATE`/`FALLOCATE` (no payload) and `FGETXATTR`/`FSETXATTR`
    /// (owned name + value). This is the encouraged shape — the file was
    /// permission-checked at open, and the fd is the capability.
    ///
    /// Scalars: `off` is the truncate length or the fallocate offset,
    /// `len64` the fallocate length, `aux32` the fallocate mode or the
    /// xattr flags. (The xattr *size* is the value buffer's own length.)
    #[allow(clippy::too_many_arguments)] // an inject unpacked, not an API
    pub(crate) fn submit_fd_meta(
        &mut self,
        eng: &mut Engine,
        tag: u8,
        pers: u16,
        file_slot: u32,
        file_gen: u64,
        name: Option<CString>,
        value: Vec<u8>,
        off: u64,
        len64: u64,
        aux32: u32,
        waiter: FsWaiter,
    ) {
        if !self.file_usable(file_slot, file_gen) {
            fail(waiter, Errno::EBADF, vec![value]);
            return;
        }
        let Some(op_slot) = self.op_free.pop() else {
            fail(waiter, Errno::EBUSY, vec![value]);
            return;
        };

        let entry = &mut self.ops[op_slot as usize];
        let gen32 = entry.generation as u32;
        let e = &mut entry.state;
        e.state = FsOpState::InFlight { tag };
        e.owner = waiter.owner();
        e.waiter = Some(waiter);
        e.file_slot = Some(file_slot);
        e.path = name;
        // The value rides in `bufs` so it round-trips like any data buffer
        // (an FGETXATTR's kernel writes land in it at issue time).
        e.bufs = vec![value];
        let name_ptr = e.path.as_ref().map_or(0, |n| n.as_ptr() as u64);
        let val = &mut e.bufs[0];
        let val_ptr = val.as_mut_ptr() as u64;
        let val_len = val.len() as u32;

        self.files[file_slot as usize].state.ops += 1;

        let ud = pack_raw(tag, op_slot, gen32);
        let staged = eng.stage(ud, |sqe| {
            sqe.flags = IOSQE_FIXED_FILE;
            sqe.fd = file_slot as i32;
            // `pers` may be 0: the BECOME_ROOT path ([`FsFile::as_root`]); see
            // `submit_rw`.
            sqe.personality = pers;
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
            self.files[file_slot as usize].state.ops -= 1;
            self.fail_op(op_slot, err);
        }
    }

    /// Stage a path op: `STATX`, or one of the directory-entry ops. Every
    /// dirfd is a real fd from an [`Anchor`] (the kernel rejects fixed-table
    /// dirfds on all of these), and every name has already been validated
    /// as a single component by `Leaf` — except a symlink's target, which is
    /// link content and never resolved, and `STATX`'s empty-path form.
    /// `flags` becomes `sqe.op_flags` (`AT_*`/`RENAME_*`); `len_arg` becomes
    /// `sqe.len` where the op wants a scalar there (statx mask, mkdir mode)
    /// — for rename/link `sqe.len` is the *second dirfd* instead, per the
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
        e.owner = waiter.owner();
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

    /// Request a close. With ops in flight: cancel them and defer — the last
    /// reaping op stages the actual `CLOSE` (the close-last rule). `reply`
    /// `None` is the orphan path (dropped token).
    pub(crate) fn submit_close(
        &mut self,
        eng: &mut Engine,
        file_slot: u32,
        file_gen: u64,
        reply: Option<ReplyTo>,
    ) {
        let usable = self.files.get(file_slot as usize).is_some_and(|f| {
            f.generation == file_gen && f.state.state == FileState::Open
        });
        if !usable {
            if let Some(reply) = reply {
                reply_err(reply, Errno::EBADF);
            }
            return;
        }
        let fe = &mut self.files[file_slot as usize].state;
        if fe.close_deferred {
            if let Some(reply) = reply {
                reply_err(reply, Errno::EBADF);
            }
            return;
        }
        if fe.ops > 0 {
            fe.close_deferred = true;
            fe.close_waiter = reply;
            self.cancel_file_ops(eng, file_slot);
            return;
        }
        self.stage_close(eng, file_slot, reply);
    }

    // ---- completion routing --------------------------------------------

    /// Route one fs-domain CQE. `tag` is the unpacked op tag; a generation
    /// mismatch makes the completion inert (defensive — op entries free only
    /// at their own terminal CQE). `cqe_flags` disambiguates the one op with
    /// **two** CQEs, `SEND_ZC` (`F_MORE` result / `F_NOTIF` release); every
    /// other completion ignores it.
    pub(crate) fn on_cqe(
        &mut self,
        eng: &mut Engine,
        tag: u8,
        op_slot: u32,
        gen32: u32,
        res: i32,
        cqe_flags: u32,
    ) -> Option<(EmbeddedCb, FsDone, Owner)> {
        if tag == TAG_CANCEL {
            return None; // an ASYNC_CANCEL's own completion; nothing to route
        }
        #[cfg(feature = "rt-tokio")]
        {
            use crate::uring::sys::{IORING_CQE_F_MORE, IORING_CQE_F_NOTIF};
            if tag == TAG_SEND_ZC
                && cqe_flags & (IORING_CQE_F_MORE | IORING_CQE_F_NOTIF) != 0
            {
                self.on_send_zc_cqe(eng, op_slot, gen32, res, cqe_flags);
                return None;
            }
            // A flagless SEND_ZC CQE (early failure, no notif coming) takes
            // the normal single-CQE path below — payload handed back.
        }
        #[cfg(not(feature = "rt-tokio"))]
        let _ = cqe_flags;
        let done = self.take_op(tag, op_slot, gen32)?;
        let Completed {
            waiter,
            bufs,
            stat,
            file_slot,
            owner,
        } = done;

        // Each arm finishes ALL bookkeeping first, then produces the fired
        // embedded callback (if any) for the host to run — the "core
        // bookkeeping, role tail" rule: the op slot is already freed and the
        // file's op-count already settled, so a chained op the callback
        // submits sees consistent state.
        let fired = match tag {
            TAG_OPEN => {
                let file_slot = file_slot.expect("open records its slot");
                if res < 0 {
                    // Read `orphaned` before `free_file_slot` resets the entry.
                    // If the owning connection closed while this open was in
                    // flight, drop the waiter (its `Deferred` targets the dead
                    // connection) instead of firing the callback — a callback
                    // that retries the open would install a new file under the
                    // already-swept owner, leaking its slot.
                    let orphaned =
                        self.files[file_slot as usize].state.orphaned;
                    self.free_file_slot(file_slot);
                    if orphaned {
                        drop(waiter);
                        None
                    } else {
                        deliver(
                            waiter,
                            Err(Errno::from_raw(-res)),
                            bufs,
                            None,
                            None,
                        )
                    }
                } else {
                    // Explicit-index install convention: res == 0.
                    debug_assert_eq!(res, 0, "explicit-index install res");
                    let (gen, pers, orphaned) = {
                        let fe = &mut self.files[file_slot as usize];
                        fe.state.state = FileState::Open;
                        (fe.generation, fe.state.pers, fe.state.orphaned)
                    };
                    if orphaned {
                        // The owning connection closed while this file was
                        // opening: close it at once and drop the waiter (its
                        // `Deferred` targets the now-dead connection) rather
                        // than hand a callback a file it can't use.
                        self.stage_close(eng, file_slot, None);
                        drop(waiter);
                        None
                    } else {
                        // Deliver the freshly-opened file. If the caller's
                        // receiver is gone — an async `open` future dropped or
                        // timed out before it could await, a blocking caller
                        // that panicked — then no `FixedFile` token will ever
                        // be built to orphan-close this slot, so stage the
                        // close here rather than leak the pool slot. Only the
                        // channel path can fail this way; the embedded path
                        // yields a callback the host fires.
                        match waiter {
                            Some(FsWaiter::Embedded { cb, .. }) => Some((
                                cb,
                                FsDone {
                                    result: Ok(res),
                                    bufs,
                                    file: Some((file_slot, gen, pers)),
                                    stat: None,
                                },
                            )),
                            Some(FsWaiter::Channel(reply)) => {
                                let out = FsOutcome::new(
                                    Ok(res),
                                    bufs,
                                    Some((file_slot, gen)),
                                    None,
                                );
                                if reply.send(out).is_err() {
                                    self.stage_close(eng, file_slot, None);
                                }
                                None
                            }
                            None => None,
                        }
                    }
                }
            }
            TAG_CLOSE => {
                let file_slot = file_slot.expect("close records its slot");
                self.free_file_slot(file_slot);
                deliver(waiter, map_res(res), bufs, None, None)
            }
            // Every fd-targeting op (data + metadata): release the file's op
            // reference and honour any deferred close, THEN deliver.
            _ if targets_file(tag) => {
                let file_slot = file_slot.expect("fd ops record their slot");
                let fe = &mut self.files[file_slot as usize].state;
                fe.ops -= 1;
                if fe.ops == 0 && fe.close_deferred {
                    fe.close_deferred = false;
                    let parked = fe.close_waiter.take();
                    self.stage_close(eng, file_slot, parked);
                }
                deliver(waiter, map_res(res), bufs, None, stat)
            }
            // Path ops (statx + the directory-entry family) hold no file.
            _ => deliver(waiter, map_res(res), bufs, None, stat),
        };

        // This completion freed an op slot; stage any close that was parked
        // on op-table exhaustion.
        if self.close_retry {
            self.retry_parked_closes(eng);
        }
        // The op's owner rides out with the fired callback so the host builds
        // that callback's [`FsConn`] with the same owner — a chained op stays
        // owned by the one connection.
        fired.map(|(cb, done)| (cb, done, owner))
    }

    /// The `SEND_ZC` two-CQE lifecycle. The **result** CQE (`F_MORE`)
    /// delivers the outcome and parks the entry as
    /// [`FsOpState::ZcAwaitNotif`] — payload still pinned by the kernel,
    /// generation deliberately unbumped so the notif (same `user_data`)
    /// still matches. The **notif** CQE (`F_NOTIF`) releases the payload and
    /// frees the slot; nothing is delivered (the waiter already was).
    #[cfg(feature = "rt-tokio")]
    fn on_send_zc_cqe(
        &mut self,
        eng: &mut Engine,
        op_slot: u32,
        gen32: u32,
        res: i32,
        cqe_flags: u32,
    ) {
        use crate::uring::sys::IORING_CQE_F_NOTIF;
        let Some(entry) = self.ops.get_mut(op_slot as usize) else {
            return;
        };
        if entry.generation as u32 != gen32 {
            return; // stale — inert, like every guarded completion
        }
        if cqe_flags & IORING_CQE_F_NOTIF != 0 {
            let FsOpState::ZcAwaitNotif { failed_res } = entry.state.state
            else {
                return; // a notif without a parked result — inert
            };
            let e = &mut entry.state;
            // The kernel has now released every page (this is the notif's
            // whole meaning), so the payload is finally safe to move.
            let bufs = std::mem::take(&mut e.bufs);
            let waiter = e.waiter.take();
            e.clear();
            entry.generation += 1;
            self.op_free.push(op_slot);
            match failed_res {
                // Success was already delivered at the result; just free.
                None => drop((bufs, waiter)),
                // Failure was deferred to here: deliver the error together
                // with the round-tripped payload, which the bridge needs to
                // retry via a plain send (the kTLS `EOPNOTSUPP` fallback).
                Some(res) => {
                    let _ = deliver(waiter, map_res(res), bufs, None, None);
                }
            }
            // This freed an op slot; stage any close parked on exhaustion.
            if self.close_retry {
                self.retry_parked_closes(eng);
            }
            return;
        }
        // The send *result* (F_MORE set): a notif will follow (that is what
        // F_MORE promises), and `io_send_zc` sets it only after `sock_sendmsg`
        // ran with the pages installed as the skb's `msg_ubuf` (io_uring/
        // net.c), so the payload must live until that notif regardless of the
        // result's sign.
        let e = &mut entry.state;
        if e.state != (FsOpState::InFlight { tag: TAG_SEND_ZC }) {
            return;
        }
        if res < 0 {
            // Defer BOTH the error and the payload to the notif: a mid-send
            // failure can leave partial skbs referencing the pages until
            // then, so handing the `Vec` back now would be a use-after-free.
            // (kTLS rejecting `MSG_ZEROCOPY` fails *before* any skb, so its
            // notif is immediate — the fallback proceeds with no real delay.)
            e.state = FsOpState::ZcAwaitNotif {
                failed_res: Some(res),
            };
        } else {
            // Success: deliver now, withhold the payload until the notif.
            // Bridge sends are channel-only; no embedded callback can exist.
            let waiter = e.waiter.take();
            e.state = FsOpState::ZcAwaitNotif { failed_res: None };
            let _ = deliver(waiter, Ok(res), Vec::new(), None, None);
        }
    }

    /// Teardown-drain routing: reply and free, but never stage (the drain is
    /// cancelling everything; deferred closes are moot — the ring teardown
    /// closes the whole registered table).
    pub(crate) fn on_drain_cqe(&mut self, cqe: &IoUringCqe) {
        let (tag, op_slot, gen32) = unpack_raw(cqe.user_data);
        if tag & 0x80 == 0 || tag == TAG_CANCEL || tag == TAG_WAKE {
            return;
        }
        #[cfg(feature = "rt-tokio")]
        if tag == TAG_SEND_ZC {
            use crate::uring::sys::{IORING_CQE_F_MORE, IORING_CQE_F_NOTIF};
            if cqe.flags & IORING_CQE_F_NOTIF != 0 {
                if let Some(entry) = self.ops.get_mut(op_slot as usize) {
                    if entry.generation as u32 == gen32 {
                        if let FsOpState::ZcAwaitNotif { failed_res } =
                            entry.state.state
                        {
                            let e = &mut entry.state;
                            let bufs = std::mem::take(&mut e.bufs);
                            let waiter = e.waiter.take();
                            e.clear();
                            entry.generation += 1;
                            self.op_free.push(op_slot);
                            // Same split as `on_send_zc_cqe`: a deferred
                            // failure delivers its error + payload now.
                            match failed_res {
                                None => drop((bufs, waiter)),
                                Some(res) => {
                                    let _ = deliver(
                                        waiter,
                                        map_res(res),
                                        bufs,
                                        None,
                                        None,
                                    );
                                }
                            }
                        }
                    }
                }
                return;
            }
            if cqe.flags & IORING_CQE_F_MORE != 0 {
                // A result completing during teardown: park it — the drain
                // keeps reaping until the notif lands (the engine's inflight
                // count only drops on terminal CQEs). Payload and (on
                // failure) the error are withheld until that notif, exactly
                // as `on_send_zc_cqe` documents (F_MORE ⇒ a notif follows ⇒
                // pages may still be kernel-pinned).
                if let Some(entry) = self.ops.get_mut(op_slot as usize) {
                    if entry.generation as u32 == gen32
                        && entry.state.state
                            == (FsOpState::InFlight { tag: TAG_SEND_ZC })
                    {
                        let e = &mut entry.state;
                        if cqe.res < 0 {
                            e.state = FsOpState::ZcAwaitNotif {
                                failed_res: Some(cqe.res),
                            };
                        } else {
                            let waiter = e.waiter.take();
                            e.state =
                                FsOpState::ZcAwaitNotif { failed_res: None };
                            let _ = deliver(
                                waiter,
                                Ok(cqe.res),
                                Vec::new(),
                                None,
                                None,
                            );
                        }
                    }
                }
                return;
            }
            // Flagless early failure: the normal drain path below hands the
            // payload back.
        }
        let Some(done) = self.take_op(tag, op_slot, gen32) else {
            return;
        };
        let Completed {
            waiter,
            bufs,
            stat,
            file_slot,
            owner: _,
        } = done;
        // Teardown: never fire an embedded callback (the loop is dying);
        // `let _ =` drops any returned callback, whose captured `Deferred`
        // then closes the connection — correct, it is being torn down anyway.
        match tag {
            TAG_OPEN | TAG_CLOSE => {
                let file_slot = file_slot.expect("op records its slot");
                // Success or not, the loop is going away: free the slot and
                // report. A file installed by a drain-completed open is
                // released by the ring teardown itself.
                self.free_file_slot(file_slot);
                let _ = deliver(waiter, map_res(cqe.res), bufs, None, None);
            }
            _ if targets_file(tag) => {
                let file_slot = file_slot.expect("fd ops record their slot");
                self.files[file_slot as usize].state.ops -= 1;
                let _ = deliver(waiter, map_res(cqe.res), bufs, None, stat);
            }
            _ => {
                let _ = deliver(waiter, map_res(cqe.res), bufs, None, stat);
            }
        }
    }

    /// Leak the op table without dropping it — used ONLY when a teardown
    /// drain failed with ops possibly still in flight. The kernel may still
    /// write into a `READV`/`FGETXATTR` destination or the boxed `STATX`
    /// buffer until its CQE reaps, so freeing those here would be a
    /// use-after-free; forget them instead (mirrors the net stack's
    /// `ConnTable::leak`, and pairs with `Engine::leak_wake_buf`). Only the op
    /// table owns kernel-visible memory; the file table does not.
    pub(crate) fn leak(&mut self) {
        std::mem::forget(std::mem::take(&mut self.ops));
    }

    /// Post-drain sweep: unblock any close waiter still parked behind a
    /// deferred close that never got staged. (Their file is released by the
    /// ring teardown.)
    pub(crate) fn fail_parked(&mut self) {
        for f in &mut self.files {
            if let Some(w) = f.state.close_waiter.take() {
                reply_err(w, Errno::ECONNABORTED);
            }
        }
    }

    /// Reclaim the fs resources a closing connection still owns: close every
    /// file it opened but never closed, so a handler that opens without closing
    /// (or a connection that dies mid-chain) cannot leak a fixed-file slot until
    /// server teardown. The embedding host calls this once per closing
    /// connection with that connection's [`Owner`] tag.
    ///
    /// In-flight ops on an owned file are cancelled by [`FsCore::submit_close`]'s
    /// close-last handling. Standalone path ops (statx / the directory-entry
    /// family) the connection owned hold no file and free their own op slot on
    /// completion, so they need no sweep. A file still *opening* has no fd to
    /// close yet, so it is flagged instead: its open's completion closes it
    /// (see [`FsCore::on_cqe`]).
    // Called only by the embedding server's connection-close sweep; dead in an
    // async-fs-only build.
    #[allow(dead_code)] // minted only by an embedding host (none in-tree today)
    pub(crate) fn close_owned_by(
        &mut self,
        eng: &mut Engine,
        owner: (u32, u64),
    ) {
        // Nothing open anywhere → nothing this connection could own; skip the
        // table scan (the common case for a connection that touched no files).
        if self.live_files == 0 {
            return;
        }
        let base = self.file_base as usize;
        // Collect first — `submit_close` mutates `self.files`, so we cannot
        // hold an iterator over it while submitting. Skip the `[0, file_base)`
        // connection-pool prefix, which never holds an fs file.
        let open: Vec<(u32, u64)> = self.files[base..]
            .iter()
            .enumerate()
            .filter_map(|(i, f)| {
                (f.state.state == FileState::Open
                    && f.state.owner == Some(owner))
                .then_some(((base + i) as u32, f.generation))
            })
            .collect();
        for (slot, gen) in open {
            self.submit_close(eng, slot, gen, None);
        }
        for f in &mut self.files[base..] {
            if f.state.state == FileState::Opening
                && f.state.owner == Some(owner)
            {
                f.state.orphaned = true;
            }
        }
    }

    // ---- internals -----------------------------------------------------

    fn file_usable(&self, slot: u32, gen: u64) -> bool {
        self.files.get(slot as usize).is_some_and(|f| {
            f.generation == gen
                && f.state.state == FileState::Open
                && !f.state.close_deferred
        })
    }

    /// Take a completed op entry out: returns its waiter and payloads and
    /// frees the slot (generation bumped) — the freed-before-fire rule.
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
            file_slot: e.file_slot,
            owner: e.owner,
        };
        e.clear();
        entry.generation += 1;
        self.op_free.push(op_slot);
        Some(done)
    }

    /// Fail a just-reserved op entry before its SQE ever reached the kernel:
    /// report and free (buffers go back to the caller, as on completion). A
    /// stage failure never fires an embedded callback — `let _ =` drops it,
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
        let _ = deliver(waiter, Err(err), bufs, None, None);
    }

    fn free_file_slot(&mut self, slot: u32) {
        let f = &mut self.files[slot as usize];
        debug_assert_eq!(f.state.ops, 0, "file freed with ops in flight");
        f.state = FileEntry::new();
        f.generation += 1;
        self.file_free.push(slot);
        self.live_files -= 1;
    }

    /// Stage the index-freeing `CLOSE` (`file_index = slot + 1`). No
    /// personality: a fixed-slot close consults no credentials.
    fn stage_close(
        &mut self,
        eng: &mut Engine,
        file_slot: u32,
        reply: Option<ReplyTo>,
    ) {
        let Some(op_slot) = self.op_free.pop() else {
            // No op slot for the close: park it as deferred; the next
            // completion (which frees an op slot by definition) retries it
            // via `close_retry`. New ops on the file are already refused
            // (`file_usable` checks `close_deferred`).
            let fe = &mut self.files[file_slot as usize].state;
            fe.close_deferred = true;
            fe.close_waiter = reply;
            self.close_retry = true;
            return;
        };
        self.files[file_slot as usize].state.state = FileState::Closing;

        let entry = &mut self.ops[op_slot as usize];
        let gen32 = entry.generation as u32;
        let e = &mut entry.state;
        e.state = FsOpState::InFlight { tag: TAG_CLOSE };
        // Close is channel-only (never embedded): the server closes owned
        // files via the sweep with `reply == None`.
        e.waiter = reply.map(FsWaiter::Channel);
        e.file_slot = Some(file_slot);

        let ud = pack_raw(TAG_CLOSE, op_slot, gen32);
        let staged = eng.stage(ud, |sqe| {
            sqe.opcode = IORING_OP_CLOSE;
            sqe.file_index = file_slot + 1;
        });
        if let Err(err) = staged {
            // The close SQE could not be staged; the slot stays Closing and
            // unreachable rather than risking the close-last invariant. The
            // teardown drain releases it. Report the failure if anyone waits.
            self.fail_op(op_slot, err);
        }
    }

    /// Stage every close parked on op-table exhaustion (deferred with
    /// `ops == 0`). Runs right after a completion freed an op slot.
    fn retry_parked_closes(&mut self, eng: &mut Engine) {
        self.close_retry = false;
        let base = self.file_base as usize;
        let parked: Vec<u32> = self.files[base..]
            .iter()
            .enumerate()
            .filter(|(_, f)| {
                f.state.state == FileState::Open
                    && f.state.close_deferred
                    && f.state.ops == 0
            })
            .map(|(i, _)| (base + i) as u32)
            .collect();
        for slot in parked {
            let fe = &mut self.files[slot as usize].state;
            fe.close_deferred = false;
            let waiter = fe.close_waiter.take();
            self.stage_close(eng, slot, waiter);
        }
    }

    /// Cancel every in-flight data op targeting `file_slot` (by exact
    /// `user_data`). Best-effort: a failed cancel just means the op finishes
    /// on its own and the deferred close triggers then.
    fn cancel_file_ops(&mut self, eng: &mut Engine, file_slot: u32) {
        let mut targets = Vec::new();
        for (i, entry) in self.ops.iter().enumerate() {
            if entry.state.file_slot == Some(file_slot) {
                if let FsOpState::InFlight { tag } = entry.state.state {
                    if tag != TAG_CLOSE {
                        targets.push(pack_raw(
                            tag,
                            i as u32,
                            entry.generation as u32,
                        ));
                    }
                }
            }
        }
        for target in targets {
            let _ = eng.stage(pack_raw(TAG_CANCEL, 0, 0), |sqe| {
                sqe.opcode = IORING_OP_ASYNC_CANCEL;
                sqe.fd = -1;
                sqe.addr = target;
                sqe.op_flags = IORING_ASYNC_CANCEL_ALL;
            });
        }
    }

    /// Cancel a single in-flight op by its exact `user_data` — the bridges'
    /// cancel-on-drop path ([`FsInject::CancelUd`](super::FsInject)). A
    /// dropped/timed-out bridge future's guard injects this so a stalled op
    /// (a `POLL_ADD` a silent peer never satisfies, an io-wq-blocked kTLS
    /// splice) is torn down — freeing its slot and backpressure permit —
    /// instead of leaking until the connection dies. Best-effort and inert
    /// when stale: if the op already reaped and its slot recycled, the
    /// generation baked into `target` matches nothing.
    #[cfg(feature = "rt-tokio")]
    pub(crate) fn submit_cancel_ud(&mut self, eng: &mut Engine, target: u64) {
        let _ = eng.stage(pack_raw(TAG_CANCEL, 0, 0), |sqe| {
            sqe.opcode = IORING_OP_ASYNC_CANCEL;
            sqe.fd = -1;
            sqe.addr = target;
            sqe.op_flags = IORING_ASYNC_CANCEL_ALL;
        });
    }
}

/// The cancel-on-drop handshake, loop side: publish this op's `user_data`
/// into the future's [`CancelToken`](super::CancelToken) so a later drop
/// can target it. Returns `false` if the guard already wrote
/// [`CANCEL_REQUESTED`](super::CANCEL_REQUESTED) — the future was dropped
/// before we staged, so the caller must abort the op rather than stage a
/// leak. The single `compare_exchange` is the whole race resolution: exactly
/// one of {loop stages, guard cancels} wins the transition out of `0`.
#[cfg(feature = "rt-tokio")]
fn publish_cancel(cancel: &super::CancelToken, ud: u64) -> bool {
    use std::sync::atomic::Ordering;
    cancel
        .compare_exchange(0, ud, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
}

fn map_res(res: i32) -> Result<i32, Errno> {
    if res < 0 {
        Err(Errno::from_raw(-res))
    } else {
        Ok(res)
    }
}

/// Route a completed op's outcome to its waiter.
///
/// A `Channel` waiter is delivered inline (returns `None`). An `Embedded`
/// waiter returns its callback + the [`FsDone`] for the host to fire in the
/// loop — EXCEPT the host runs completions; failure/teardown sites just
/// `let _ = deliver(...)`, which drops the returned callback, and dropping a
/// callback drops its captured `Deferred`, closing the connection (so a
/// submission failure needs no separate error path).
#[must_use = "an embedded callback must be fired by the host, or dropped to close the conn"]
fn deliver(
    waiter: Option<FsWaiter>,
    res: Result<i32, Errno>,
    bufs: Vec<Vec<u8>>,
    file: Option<(u32, u64, u16)>,
    stat: Option<Box<StatxRaw>>,
) -> Option<(EmbeddedCb, FsDone)> {
    match waiter {
        // A gone caller (dropped receiver) orphans the op; nothing to do. The
        // off-loop `FixedFile` carries no personality, so drop it here.
        // (A successful `open` does NOT route through here — its arm in
        // `on_cqe` handles the gone-receiver case by staging a close, so the
        // freshly-opened slot isn't leaked when no `FixedFile` gets built.)
        Some(FsWaiter::Channel(tx)) => {
            let _ = tx.send(FsOutcome::new(
                res,
                bufs,
                file.map(|(slot, gen, _pers)| (slot, gen)),
                stat,
            ));
            None
        }
        Some(FsWaiter::Embedded { cb, .. }) => Some((
            cb,
            FsDone {
                result: res,
                bufs,
                file,
                stat,
            },
        )),
        None => None,
    }
}

fn reply_err(reply: ReplyTo, err: Errno) {
    let _ = reply.send(FsOutcome::new(Err(err), Vec::new(), None, None));
}

/// Cancellation-injection fuzzer for the completion-routing state machine.
///
/// Drives the *real* `FsCore` (op table, file table, close-last discipline,
/// generation guard) with fuzzed schedules of open/read/write/close submissions
/// interleaved with completions delivered out of order and at fuzzed results,
/// plus deliberately stale / wrong-tag / recycled completions. It runs entirely
/// in userspace: a real `Engine` is built (so `submit_*`/`on_cqe` have their
/// `&mut Engine`) but never submitted — staging only writes SQ memory, and the
/// ring is sized so a single run never fills it, so the kernel never touches a
/// buffer. A fresh `Engine` per seed resets the staged SQEs.
///
/// It exercises the exact hazard SPDK's raw-pointer `user_data` guards against by
/// synchronous drain (§ reactor-design comparison): a completion arriving for a
/// since-recycled slot. Here the generation guard must make it inert.
///
/// Invariants asserted (each maps to a line that trips if the logic breaks — see
/// the mutation-verification recipe in the PR/commit):
///   * a stale-generation / wrong-tag / recycled completion mutates nothing;
///   * `ops` never underflows and a file's index-freeing CLOSE is its last op
///     (both are `debug_assert`/`u16`-underflow panics, i.e. crash oracles);
///   * at quiescence every op slot and file slot is free exactly once (no leak,
///     no double-free) and `live_files == 0`;
///   * every submission yields exactly one outcome and every r/w buffer returns
///     exactly once (no lost/duplicated delivery).
///
/// Run: `TRUENAS_ROS_REQUIRE_IO_URING=1 cargo test --features async-fs \
///       --lib routing_survives_fuzzed_cancellation`
/// (skips automatically where io_uring is unavailable, like the integration
/// suites). `CANCEL_FUZZ_SEEDS=N` overrides the seed count.
#[cfg(test)]
mod cancel_fuzz {
    use super::*;
    use std::collections::HashSet;
    use std::sync::mpsc;

    const OP_SLOTS: u32 = 64;
    const FILE_SLOTS: u32 = 16;
    const POOL: u32 = FILE_SLOTS + 1;
    // >> SQEs any single run stages; the ring never fills, so push_sqe never
    // flushes to the kernel (the routing runs purely in userspace).
    const RING_ENTRIES: u32 = 1024;

    /// A tiny deterministic xorshift RNG so a failing run reproduces from its seed.
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
            )) => {
                assert!(
                    std::env::var_os("TRUENAS_ROS_REQUIRE_IO_URING").is_none(),
                    "TRUENAS_ROS_REQUIRE_IO_URING set but io_uring unavailable"
                );
                None
            }
            Err(e) => panic!("Engine::new: {e}"),
        }
    }

    /// A compact snapshot used to assert an injected stale/anomalous completion
    /// is fully inert: free-list, per-op `(generation, state)`, and live count.
    fn snapshot(c: &FsCore) -> (Vec<u32>, Vec<(u64, u8)>, u32) {
        let mut free = c.op_free.clone();
        free.sort_unstable();
        let ops = c
            .ops
            .iter()
            .map(|e| {
                let code = match e.state.state {
                    FsOpState::Free => 0u8,
                    FsOpState::InFlight { tag } => tag,
                    #[cfg(feature = "rt-tokio")]
                    FsOpState::ZcAwaitNotif { failed_res: None } => 0xFE,
                    #[cfg(feature = "rt-tokio")]
                    FsOpState::ZcAwaitNotif {
                        failed_res: Some(_),
                    } => 0xFF,
                };
                (e.generation, code)
            })
            .collect();
        (free, ops, c.live_files)
    }

    /// Currently in-flight ops as `(tag, slot, generation-low)` — the CQEs a real
    /// kernel could deliver.
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

    /// Files that accept a new fd-op or a close: `Open && !close_deferred`.
    fn usable_files(c: &FsCore) -> Vec<(u32, u64)> {
        c.files
            .iter()
            .enumerate()
            .filter_map(|(i, f)| {
                (f.state.state == FileState::Open && !f.state.close_deferred)
                    .then_some((i as u32, f.generation))
            })
            .collect()
    }

    #[test]
    fn routing_survives_fuzzed_cancellation() {
        if engine_or_skip().is_none() {
            return;
        }
        let anchor = Anchor::open("/").expect("open / as anchor");
        let seeds: u64 = std::env::var("CANCEL_FUZZ_SEEDS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(300);
        for seed in 0..seeds {
            // Fresh Engine per run: resets staged SQEs so the ring never fills.
            let mut eng = Engine::new(RING_ENTRIES, POOL).expect("engine");
            run_one(&mut eng, &anchor, seed);
        }
    }

    fn run_one(eng: &mut Engine, anchor: &Anchor, seed: u64) {
        let mut rng = Rng::new(seed);
        let mut core = FsCore::new(OP_SLOTS, 0, FILE_SLOTS);
        let (tx, rx) = mpsc::channel::<FsOutcome>();

        let mut submitted: u64 = 0; // opens + rws + closes (each yields 1 outcome)
        let mut next_buf_id: u64 = 1;
        let mut issued_bufs: HashSet<u64> = HashSet::new();
        let mut completed: Vec<(u8, u32, u32)> = Vec::new();

        let steps = 24 + rng.below(72);
        for _ in 0..steps {
            match rng.below(6) {
                // open a new file
                0 | 1
                    if !core.file_free.is_empty()
                        && !core.op_free.is_empty() =>
                {
                    let how = OpenHow::new().to_raw();
                    core.submit_open(
                        eng,
                        1,
                        anchor.clone(),
                        CString::new("x").unwrap(),
                        how,
                        FsWaiter::Channel(ReplyTo::Sync(tx.clone())),
                    );
                    submitted += 1;
                }
                // read or write on a usable file
                2 | 3 => {
                    let files = usable_files(&core);
                    if !files.is_empty() && !core.op_free.is_empty() {
                        let (slot, gen) =
                            files[rng.below(files.len() as u32) as usize];
                        let tag = if rng.below(2) == 0 {
                            TAG_READV
                        } else {
                            TAG_WRITEV
                        };
                        let id = next_buf_id;
                        next_buf_id += 1;
                        issued_bufs.insert(id);
                        let mut b = vec![0u8; 16];
                        b[..8].copy_from_slice(&id.to_le_bytes());
                        core.submit_rw(
                            eng,
                            tag,
                            1,
                            slot,
                            gen,
                            vec![b],
                            0,
                            FsWaiter::Channel(ReplyTo::Sync(tx.clone())),
                        );
                        submitted += 1;
                    }
                }
                // close a usable file (defers + cancels if it has in-flight ops)
                4 => {
                    let files = usable_files(&core);
                    if !files.is_empty() && !core.op_free.is_empty() {
                        let (slot, gen) =
                            files[rng.below(files.len() as u32) as usize];
                        core.submit_close(
                            eng,
                            slot,
                            gen,
                            Some(ReplyTo::Sync(tx.clone())),
                        );
                        submitted += 1;
                    }
                }
                // deliver a completion, or inject an anomaly the guard must reject
                _ => {
                    let inf = inflight(&core);
                    if inf.is_empty() {
                        continue;
                    }
                    let (tag, slot, gen) =
                        inf[rng.below(inf.len() as u32) as usize];
                    match rng.below(12) {
                        // stale generation -> inert
                        0 => {
                            let before = snapshot(&core);
                            let _ = core.on_cqe(
                                eng,
                                tag,
                                slot,
                                gen.wrapping_sub(1),
                                0,
                                0,
                            );
                            assert_eq!(
                                snapshot(&core),
                                before,
                                "stale-gen CQE mutated state (seed {seed})"
                            );
                        }
                        // wrong tag -> inert
                        1 => {
                            let bad = tag ^ 0x01;
                            let before = snapshot(&core);
                            let _ = core.on_cqe(eng, bad, slot, gen, 0, 0);
                            assert_eq!(
                                snapshot(&core),
                                before,
                                "wrong-tag CQE mutated state (seed {seed})"
                            );
                        }
                        // replay a since-recycled completion -> inert (the SPDK
                        // raw-pointer hazard; here the generation makes it a no-op)
                        2 if !completed.is_empty() => {
                            let (t, s, g) = completed
                                [rng.below(completed.len() as u32) as usize];
                            let before = snapshot(&core);
                            let _ = core.on_cqe(eng, t, s, g, 0, 0);
                            assert_eq!(
                                snapshot(&core),
                                before,
                                "recycled CQE mutated state (seed {seed})"
                            );
                        }
                        // genuine delivery, fuzzed result
                        _ => {
                            let res = match rng.below(8) {
                                0 => -libc::ECANCELED,
                                1 => -libc::EIO,
                                _ => 0,
                            };
                            let _ = core.on_cqe(eng, tag, slot, gen, res, 0);
                            completed.push((tag, slot, gen));
                        }
                    }
                }
            }
        }

        // Drain to quiescence: deliver every in-flight op, then close every
        // remaining open file, until nothing is in flight and nothing is live.
        let mut guard = 0u32;
        loop {
            guard += 1;
            assert!(guard < 100_000, "drain did not converge (seed {seed})");
            if let Some(&(tag, slot, gen)) = inflight(&core).first() {
                let _ = core.on_cqe(eng, tag, slot, gen, 0, 0);
                continue;
            }
            if let Some(&(slot, gen)) = usable_files(&core).first() {
                core.submit_close(
                    eng,
                    slot,
                    gen,
                    Some(ReplyTo::Sync(tx.clone())),
                );
                submitted += 1;
                continue;
            }
            break;
        }

        // ---- structural quiescence invariants (private state) ----
        assert!(
            inflight(&core).is_empty(),
            "ops still in flight (seed {seed})"
        );
        assert_eq!(core.live_files, 0, "live_files != 0 (seed {seed})");

        let mut op_free = core.op_free.clone();
        op_free.sort_unstable();
        assert_eq!(
            op_free.len(),
            OP_SLOTS as usize,
            "op slot leaked or double-freed (seed {seed})"
        );
        op_free.dedup();
        assert_eq!(
            op_free.len(),
            OP_SLOTS as usize,
            "op_free has a duplicate slot (seed {seed})"
        );
        assert!(
            core.ops.iter().all(|e| e.state.state == FsOpState::Free),
            "an op entry is not Free (seed {seed})"
        );

        let mut file_free = core.file_free.clone();
        file_free.sort_unstable();
        assert_eq!(
            file_free.len(),
            FILE_SLOTS as usize,
            "file slot leaked or double-freed (seed {seed})"
        );
        file_free.dedup();
        assert_eq!(
            file_free.len(),
            FILE_SLOTS as usize,
            "file_free has a duplicate slot (seed {seed})"
        );
        assert!(
            core.files.iter().all(|f| f.state.state == FileState::Free),
            "a file entry is not Free (seed {seed})"
        );

        // ---- delivery-once + buffer-return-once ----
        // Every stored sender was consumed as its op completed; dropping the
        // local one closes the channel so the drain below terminates.
        drop(tx);
        let mut outcomes: u64 = 0;
        let mut returned: HashSet<u64> = HashSet::new();
        while let Ok(out) = rx.recv() {
            outcomes += 1;
            for b in &out.bufs {
                if b.len() >= 8 {
                    let id = u64::from_le_bytes(b[..8].try_into().unwrap());
                    if issued_bufs.contains(&id) {
                        assert!(
                            returned.insert(id),
                            "buffer {id} returned twice (seed {seed})"
                        );
                    }
                }
            }
        }
        assert_eq!(
            outcomes, submitted,
            "each submission must yield exactly one outcome (seed {seed})"
        );
        assert_eq!(
            returned, issued_bufs,
            "every r/w buffer must return exactly once (seed {seed})"
        );
    }
}

/// Randomized lifecycle model for the `SEND_ZC` two-CQE state machine —
/// the `cancel_fuzz` discipline applied to the one op whose slot outlives
/// its delivered result. Same in-userspace trick: a real `Engine`, sized so
/// staging never reaches the kernel.
///
/// Invariants asserted:
///   * the result CQE (`F_MORE`) delivers exactly one outcome with the
///     payload **withheld**, parks the entry (`ZcAwaitNotif`) and bumps no
///     generation — the slot is unreusable between result and notif;
///   * the notif CQE (`F_NOTIF`) frees the slot (generation bumped, slot on
///     the free list) and delivers nothing;
///   * a notif before any result, a second result, a stale-generation CQE
///     of either kind — all inert;
///   * a flagless CQE (early failure, no notif coming) is terminal in one
///     step and hands the payload back;
///   * at quiescence every slot is free and every submission produced
///     exactly one outcome.
#[cfg(all(test, feature = "rt-tokio"))]
mod zc_lifecycle {
    use super::*;
    use crate::uring::sys::{IORING_CQE_F_MORE, IORING_CQE_F_NOTIF};
    use std::os::fd::OwnedFd;
    use std::sync::mpsc;
    use std::sync::Arc;

    const RING_ENTRIES: u32 = 1024;
    const OP_SLOTS: u32 = 6;

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

    fn engine_or_skip() -> Option<Engine> {
        match Engine::new(RING_ENTRIES, 4) {
            Ok(e) => Some(e),
            Err(crate::Error::Errno(
                Errno::EPERM | Errno::ENOSYS | Errno::EACCES,
            )) => {
                assert!(
                    std::env::var_os("TRUENAS_ROS_REQUIRE_IO_URING").is_none(),
                    "TRUENAS_ROS_REQUIRE_IO_URING set but io_uring unavailable"
                );
                None
            }
            Err(e) => panic!("Engine::new: {e}"),
        }
    }

    #[derive(Clone, Copy, PartialEq)]
    enum Mirror {
        InFlight,
        /// Past the result CQE, awaiting the notif. `failed` records whether
        /// the result was an error (its outcome + payload are deferred to
        /// the notif) or a success (already delivered at the result).
        AwaitNotif {
            failed: bool,
        },
    }

    #[test]
    fn zc_two_cqe_lifecycle_invariants() {
        if engine_or_skip().is_none() {
            return; // io_uring unavailable in this sandbox
        }
        let keep = Arc::new(OwnedFd::from(
            std::fs::File::open("/dev/null").expect("open /dev/null"),
        ));
        let seeds: u64 = std::env::var("CANCEL_FUZZ_SEEDS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(48);

        for seed in 0..seeds {
            let mut eng = engine_or_skip().expect("probed above");
            let mut core = FsCore::new(OP_SLOTS, 0, 4);
            let (tx, rx) = mpsc::channel::<FsOutcome>();
            let mut rng = Rng::new(seed);

            // (op_slot, gen32, mirror)
            let mut live: Vec<(u32, u32, Mirror)> = Vec::new();
            let mut submitted = 0usize;
            let mut outcomes_ok = 0usize;
            let mut outcomes_err_with_payload = 0usize;

            for _ in 0..160 {
                match rng.below(8) {
                    // Submit a zc send.
                    0 | 1 => {
                        if core.op_free.is_empty() {
                            continue;
                        }
                        let slot = *core.op_free.last().expect("nonempty");
                        let gen32 = core.ops[slot as usize].generation as u32;
                        core.submit_send(
                            &mut eng,
                            1, // fd value is never dereferenced (SQ never submitted)
                            vec![0xA5; 16],
                            0,
                            0,
                            true,
                            keep.clone(),
                            std::sync::Arc::new(
                                std::sync::atomic::AtomicU64::new(0),
                            ),
                            FsWaiter::Channel(ReplyTo::Sync(tx.clone())),
                        );
                        assert_eq!(
                            core.ops[slot as usize].state.state,
                            FsOpState::InFlight { tag: TAG_SEND_ZC },
                            "submit stages into the predicted slot"
                        );
                        live.push((slot, gen32, Mirror::InFlight));
                        submitted += 1;
                    }
                    // Deliver the result (F_MORE). A result CQE carrying
                    // F_MORE — the kernel's promise that a notif follows —
                    // always withholds the payload until that notif (reaching
                    // this arm means `sock_sendmsg` ran with the pages
                    // installed, so an error can still leave partial skbs
                    // pinning them). On SUCCESS the outcome is delivered now
                    // (payload withheld); on FAILURE both the error and the
                    // payload are deferred to the notif.
                    2 | 3 => {
                        let Some(i) =
                            pick(&mut rng, &live, |m| m == Mirror::InFlight)
                        else {
                            continue;
                        };
                        let (slot, gen32, _) = live[i];
                        let failed = rng.below(3) == 0;
                        let res = if failed { -libc::EPIPE } else { 16 };
                        let _ = core.on_cqe(
                            &mut eng,
                            TAG_SEND_ZC,
                            slot,
                            gen32,
                            res,
                            IORING_CQE_F_MORE,
                        );
                        if failed {
                            assert!(
                                rx.try_recv().is_err(),
                                "a failed result defers its outcome to the \
                                 notif (nothing delivered yet)"
                            );
                        } else {
                            let out = rx.try_recv().expect("success delivered");
                            assert_eq!(out.res, Ok(16));
                            assert!(
                                out.bufs.is_empty(),
                                "a success withholds the payload until notif"
                            );
                            outcomes_ok += 1;
                        }
                        assert!(
                            matches!(
                                core.ops[slot as usize].state.state,
                                FsOpState::ZcAwaitNotif { .. }
                            ),
                            "entry parks awaiting the notif"
                        );
                        assert_eq!(
                            core.ops[slot as usize].generation as u32, gen32,
                            "generation unbumped between result and notif"
                        );
                        assert!(
                            !core.op_free.contains(&slot),
                            "slot unreusable between result and notif"
                        );
                        live[i].2 = Mirror::AwaitNotif { failed };
                    }
                    // Deliver the notif (F_NOTIF): frees the slot, and for a
                    // deferred failure delivers its error + payload now.
                    4 => {
                        let Some(i) = pick(&mut rng, &live, |m| {
                            matches!(m, Mirror::AwaitNotif { .. })
                        }) else {
                            continue;
                        };
                        let (slot, gen32, m) = live.swap_remove(i);
                        let failed =
                            matches!(m, Mirror::AwaitNotif { failed: true });
                        let _ = core.on_cqe(
                            &mut eng,
                            TAG_SEND_ZC,
                            slot,
                            gen32,
                            0,
                            IORING_CQE_F_NOTIF,
                        );
                        if failed {
                            let out = rx.try_recv().expect("deferred failure");
                            assert_eq!(out.res, Err(Errno::EPIPE));
                            assert_eq!(
                                out.bufs.len(),
                                1,
                                "a deferred failure hands the payload back \
                                 at the notif"
                            );
                            outcomes_err_with_payload += 1;
                        } else {
                            assert!(
                                rx.try_recv().is_err(),
                                "a success notif delivers nothing"
                            );
                        }
                        assert!(
                            core.op_free.contains(&slot),
                            "notif frees the slot"
                        );
                        assert_ne!(
                            core.ops[slot as usize].generation as u32, gen32,
                            "notif bumps the generation"
                        );
                    }
                    // Flagless early failure (e.g. ENOTSOCK, or a socket
                    // without SOCK_SUPPORT_ZC): no notif follows, so it is
                    // terminal in one CQE and the payload comes straight
                    // back via the normal single-CQE path.
                    5 => {
                        let Some(i) =
                            pick(&mut rng, &live, |m| m == Mirror::InFlight)
                        else {
                            continue;
                        };
                        let (slot, gen32, _) = live.swap_remove(i);
                        let _ = core.on_cqe(
                            &mut eng,
                            TAG_SEND_ZC,
                            slot,
                            gen32,
                            -libc::EOPNOTSUPP,
                            0,
                        );
                        let out = rx.try_recv().expect("failure delivered");
                        assert_eq!(out.res, Err(Errno::EOPNOTSUPP));
                        assert_eq!(
                            out.bufs.len(),
                            1,
                            "early failure hands the payload back"
                        );
                        outcomes_err_with_payload += 1;
                        assert!(core.op_free.contains(&slot));
                    }
                    // Anomalies — every one must be inert.
                    _ => {
                        if live.is_empty() {
                            continue;
                        }
                        let i = rng.below(live.len() as u32) as usize;
                        let (slot, gen32, m) = live[i];
                        let snap_gen = core.ops[slot as usize].generation;
                        let snap_free = core.op_free.len();
                        match rng.below(3) {
                            // Stale generation, either flag.
                            0 => {
                                let _ = core.on_cqe(
                                    &mut eng,
                                    TAG_SEND_ZC,
                                    slot,
                                    gen32.wrapping_add(9),
                                    16,
                                    if rng.below(2) == 0 {
                                        IORING_CQE_F_MORE
                                    } else {
                                        IORING_CQE_F_NOTIF
                                    },
                                );
                            }
                            // A notif before any result.
                            1 if m == Mirror::InFlight => {
                                let _ = core.on_cqe(
                                    &mut eng,
                                    TAG_SEND_ZC,
                                    slot,
                                    gen32,
                                    0,
                                    IORING_CQE_F_NOTIF,
                                );
                            }
                            // A second result after the first.
                            _ if matches!(m, Mirror::AwaitNotif { .. }) => {
                                let _ = core.on_cqe(
                                    &mut eng,
                                    TAG_SEND_ZC,
                                    slot,
                                    gen32,
                                    16,
                                    IORING_CQE_F_MORE,
                                );
                            }
                            _ => continue,
                        }
                        assert_eq!(
                            core.ops[slot as usize].generation, snap_gen,
                            "anomalous CQE mutated a generation"
                        );
                        assert_eq!(
                            core.op_free.len(),
                            snap_free,
                            "anomalous CQE freed a slot"
                        );
                        assert!(
                            rx.try_recv().is_err(),
                            "anomalous CQE delivered an outcome"
                        );
                    }
                }
            }

            // Drain to quiescence: finish every op's remaining CQEs.
            for (slot, gen32, m) in std::mem::take(&mut live) {
                if m == Mirror::InFlight {
                    // A success result, then its notif.
                    let _ = core.on_cqe(
                        &mut eng,
                        TAG_SEND_ZC,
                        slot,
                        gen32,
                        16,
                        IORING_CQE_F_MORE,
                    );
                    let out = rx.try_recv().expect("drain result");
                    assert_eq!(out.res, Ok(16));
                    outcomes_ok += 1;
                }
                let _ = core.on_cqe(
                    &mut eng,
                    TAG_SEND_ZC,
                    slot,
                    gen32,
                    0,
                    IORING_CQE_F_NOTIF,
                );
                // A notif for a deferred failure delivers its error + payload.
                if matches!(m, Mirror::AwaitNotif { failed: true }) {
                    let out = rx.try_recv().expect("drain deferred failure");
                    assert_eq!(out.res, Err(Errno::EPIPE));
                    assert_eq!(out.bufs.len(), 1);
                    outcomes_err_with_payload += 1;
                }
            }

            assert_eq!(
                core.op_free.len(),
                OP_SLOTS as usize,
                "seed {seed}: every op slot free exactly once at quiescence"
            );
            let mut dedup = core.op_free.clone();
            dedup.sort_unstable();
            dedup.dedup();
            assert_eq!(dedup.len(), OP_SLOTS as usize, "seed {seed}: no dup");
            assert_eq!(
                outcomes_ok + outcomes_err_with_payload,
                submitted,
                "seed {seed}: exactly one outcome per submission"
            );
            assert!(rx.try_recv().is_err(), "seed {seed}: no stray outcome");
        }
    }

    fn pick(
        rng: &mut Rng,
        live: &[(u32, u32, Mirror)],
        want: impl Fn(Mirror) -> bool,
    ) -> Option<usize> {
        let candidates: Vec<usize> = live
            .iter()
            .enumerate()
            .filter(|(_, (_, _, m))| want(*m))
            .map(|(i, _)| i)
            .collect();
        if candidates.is_empty() {
            return None;
        }
        Some(candidates[rng.below(candidates.len() as u32) as usize])
    }
}
