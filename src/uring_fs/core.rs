//! The fs core: the op table (owner of every kernel-visible payload from
//! submission to completion), plain reference-counted file descriptors
//! (`File = Arc<OwnedFd>`, close-last by ownership), the SQE builders, and
//! completion routing. A host owns the engine and drives this —
//! [`super::UringFs`] standalone, or a `net` server sharing its ring (which is
//! also what [`FsConn`] submits through).
//!
//! Invariants:
//!
//! - **The kernel must never touch freed memory.** Buffers, iovec arrays,
//!   paths, `open_how` pads, and anchor dirfds live in the op entry from
//!   submission until the CQE reaps — even when the caller lost interest.
//! - **Close-last by ownership.** An open returns an `Arc<OwnedFd>`; each op in
//!   flight against it parks its own clone in the op entry until that op's CQE,
//!   so the fd closes only when the last reference — the caller's handle and
//!   every in-flight op — drops. No explicit close op, no reusable slot index.
//! - **Op-slot generations make stale completions inert.** `user_data` packs
//!   `(tag, op-slot, generation)`; an op entry frees only at its own single
//!   terminal CQE, so a stale / duplicate / wrong-tag completion is rejected.

use super::{
    statx_at_flags, Anchor, File, FsOutcome, Leaf, Personality, ReplyTo,
};
use crate::errno::Errno;
use crate::sync_fs::openat2::RawOpenHow;
use crate::sync_fs::{
    AtFlags, Mode, OpenHow, RenameFlags, ResolveFlag, Statx, StatxMask,
    StatxRaw,
};
use crate::uring::engine::Engine;
use crate::uring::slots::SlotEntry;
use crate::uring::sys::{
    IoUringCqe, IORING_FSYNC_DATASYNC, IORING_OP_ASYNC_CANCEL,
    IORING_OP_FALLOCATE, IORING_OP_FGETXATTR, IORING_OP_FSETXATTR,
    IORING_OP_FSYNC, IORING_OP_FTRUNCATE, IORING_OP_LINKAT, IORING_OP_MKDIRAT,
    IORING_OP_OPENAT2, IORING_OP_READV, IORING_OP_RENAMEAT, IORING_OP_STATX,
    IORING_OP_SYMLINKAT, IORING_OP_UNLINKAT, IORING_OP_WRITEV,
};
use crate::uring::user_data::{pack_raw, unpack_raw};
use std::ffi::{CStr, CString};
use std::mem::size_of;
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::Arc;

// fs op tags (the 0x80 domain; fs-reactor design §13).
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
/// The standalone host's wake tag (an embedded host reuses its own).
pub(crate) const TAG_WAKE: u8 = 0x9D;
/// Tags `ASYNC_CANCEL` ops (and the teardown drain); completions ignored.
pub(crate) const TAG_CANCEL: u8 = 0x9E;

/// A completed embedded op's callback, fired **inline on the loop thread** by
/// the embedding host (a `net` server) with the outcome and a fresh [`FsConn`]
/// for chaining. Dropping it without firing drops its captured continuation —
/// which closes the connection — so a submission failure needs no error path.
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
}

/// Box a consumer callback as an owner-stamped embedded waiter — the one shape
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

/// Report an early submission failure — the SQE never staged (slot exhaustion,
/// an unusable file) — handing the caller's payloads back exactly as a
/// completion would (see [`deliver`]).
fn fail(waiter: FsWaiter, err: Errno, bufs: Vec<Vec<u8>>) {
    deliver(Some(waiter), Err(err), bufs, None, None);
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
    /// The file an fd-op targets, parked here so its descriptor stays open
    /// (and un-reused) until the CQE reaps — the caller may drop its
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
pub(crate) struct FsCore {
    ops: Vec<SlotEntry<FsOpEntry>>,
    op_free: Vec<u32>,
}

impl FsCore {
    pub(crate) fn new(op_slots: u32) -> FsCore {
        FsCore {
            ops: (0..op_slots)
                .map(|_| SlotEntry {
                    generation: 0,
                    state: FsOpEntry::new(),
                })
                .collect(),
            op_free: (0..op_slots).rev().collect(),
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
    #[allow(clippy::too_many_arguments)] // an inject unpacked, not an API
    pub(crate) fn submit_rw(
        &mut self,
        eng: &mut Engine,
        tag: u8,
        pers: u16,
        file: Arc<OwnedFd>,
        mut bufs: Vec<Vec<u8>>,
        off: u64,
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
            sqe.personality = pers;
        });
        if let Err(err) = staged {
            self.fail_op(op_slot, err);
        }
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
    /// implicitly. The one sanctioned ambient-root path is
    /// [`FsCore::submit_fgetxattr_as_root`].
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
        self.stage_fd_meta(
            eng, tag, pers, file, name, value, off, len64, aux32, waiter,
        );
    }

    /// Read xattr `name` from `file` under the reactor's **ambient root**
    /// (`sqe.personality = 0`) — the sole sanctioned `pers = 0` fd-op. For a
    /// privileged `trusted.*`/`security.*` read a request's own identity cannot
    /// perform: `sqe.personality` (not the fd's open-time cred) governs
    /// `fgetxattr`'s `CAP_SYS_ADMIN` check, and `0` runs as the ring owner
    /// (root). Deliberate — every other fd-op path fails closed on `pers == 0`.
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

    // ---- cancellation --------------------------------------------------

    /// Stage an `ASYNC_CANCEL` for the in-flight op named by `target_ud`. Its
    /// own completion is ignored ([`TAG_CANCEL`], which `on_cqe` drops); the
    /// cancelled op completes with `ECANCELED` and its CQE runs `take_op` like
    /// any other, dropping the parked `Arc` (close-last). Takes no op-table slot
    /// — nothing routes its completion — but goes through `eng.stage` so the
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

    /// Cancel every in-flight op owned by `owner` — the connection-teardown
    /// sweep. Replaces the removed `close_owned_by`: with plain-fd files a
    /// connection's fds close by `Arc`-drop, but an op still **in flight** parks
    /// its fd until the CQE, and a closed connection's op is otherwise never
    /// cancelled (a never-completing read would pin the fd until server
    /// teardown). Cancelling — not force-dropping the entry — is required: the
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
    /// `None`; an **embedded** (on-loop) op hands back its callback + outcome
    /// for the host to fire once its borrow of the fs tables has ended.
    pub(crate) fn on_cqe(
        &mut self,
        _eng: &mut Engine,
        tag: u8,
        op_slot: u32,
        gen32: u32,
        res: i32,
    ) -> Option<(EmbeddedCb, FsDone, Owner)> {
        if tag == TAG_CANCEL {
            return None; // an ASYNC_CANCEL's own completion; nothing to route
        }
        let Completed { waiter, bufs, stat } =
            self.take_op(tag, op_slot, gen32)?;

        // A successful OPENAT2 returns a real fd as its result; wrap it in an
        // `Arc<OwnedFd>`. If nobody takes it (a gone channel receiver, or a
        // dropped embedded callback) the `Arc` drops and the fd closes — no
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
                None
            }
            Some(FsWaiter::Embedded { owner, cb }) => Some((
                cb,
                FsDone {
                    result,
                    bufs,
                    file: file.map(File::new),
                    stat,
                },
                owner,
            )),
            None => None,
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
        let Some(done) = self.take_op(tag, op_slot, gen32) else {
            return;
        };
        let Completed { waiter, bufs, stat } = done;
        // Teardown: the loop is dying — just report the outcome and hand any
        // buffers back. A file's fd is released when its op entry (and thus its
        // parked `Arc`) is dropped with the ring teardown.
        deliver(waiter, map_res(cqe.res), bufs, None, stat);
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

    // ---- internals -----------------------------------------------------

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
    /// The op's result: a byte count / `0`, or the errno it failed with.
    pub fn result(&self) -> crate::Result<i32> {
        self.result.map_err(Into::into)
    }

    /// The freshly opened file — present only for a successful `open`.
    pub fn file(&self) -> Option<File> {
        self.file.clone()
    }

    /// Take the op's buffers back (read destinations / xattr value).
    pub fn into_bufs(self) -> Vec<Vec<u8>> {
        self.bufs
    }

    /// The `statx` metadata — present only for a successful `statx`.
    pub fn stat(&self) -> Option<Statx> {
        self.stat.as_deref().copied().map(Statx::from_raw)
    }
}

/// The request-bound fs submission facade a `net` server hands a protocol
/// handler and re-hands each completion callback for chaining. Every op runs on
/// the server's ring, checked as the [`Personality`] passed to it, and its
/// completion fires the `on_done` callback **inline on the loop thread**.
///
/// **Re-entrancy:** callbacks run inside dispatch — never block, and drive the
/// ring only through this facade. A submission or argument-validation failure
/// drops `on_done` (and the continuation it captured, closing the connection),
/// so these methods return `()`.
#[cfg_attr(not(feature = "net-server"), allow(dead_code))]
pub struct FsConn<'a> {
    fs: &'a mut FsCore,
    eng: &'a mut Engine,
    owner: Owner,
    fd_xattr_ok: bool,
    ftruncate_ok: bool,
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

    /// Fire `on_done` now with a synthesized error and no ring op — used when a
    /// fd op is unsupported on this kernel.
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
            return; // anchor-relative only
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

    /// Vectored positional read (`preadv(2)`) as `who`.
    pub fn preadv<F>(
        &mut self,
        who: Personality,
        f: File,
        bufs: Vec<Vec<u8>>,
        off: u64,
        on_done: F,
    ) where
        F: FnOnce(FsDone, &mut FsConn<'_>) + 'static,
    {
        self.rw(TAG_READV, who, f, bufs, off, on_done);
    }

    /// Single-buffer positional read (`pread(2)`).
    pub fn pread<F>(
        &mut self,
        who: Personality,
        f: File,
        buf: Vec<u8>,
        off: u64,
        on_done: F,
    ) where
        F: FnOnce(FsDone, &mut FsConn<'_>) + 'static,
    {
        self.rw(TAG_READV, who, f, vec![buf], off, on_done);
    }

    /// Vectored positional write (`pwritev(2)`) as `who`.
    pub fn pwritev<F>(
        &mut self,
        who: Personality,
        f: File,
        bufs: Vec<Vec<u8>>,
        off: u64,
        on_done: F,
    ) where
        F: FnOnce(FsDone, &mut FsConn<'_>) + 'static,
    {
        self.rw(TAG_WRITEV, who, f, bufs, off, on_done);
    }

    /// Single-buffer positional write (`pwrite(2)`).
    pub fn pwrite<F>(
        &mut self,
        who: Personality,
        f: File,
        buf: Vec<u8>,
        off: u64,
        on_done: F,
    ) where
        F: FnOnce(FsDone, &mut FsConn<'_>) + 'static,
    {
        self.rw(TAG_WRITEV, who, f, vec![buf], off, on_done);
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

    /// Read extended attribute `name` from `f` into `buf` as `who`. Needs
    /// Linux ≥ 6.13; fails closed (`EOPNOTSUPP`) otherwise.
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
        if !self.fd_xattr_ok {
            return self.fail_now(Errno::EOPNOTSUPP, vec![buf], on_done);
        }
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
    /// root** — no `who`. The one sanctioned privileged read: for a
    /// `trusted.*`/`security.*` attribute a request's own identity cannot see
    /// (`sqe.personality`, not the fd's open-time cred, governs `fgetxattr`'s
    /// `CAP_SYS_ADMIN` check; `personality = 0` runs as the ring owner, root).
    /// Needs Linux ≥ 6.13; fails closed (`EOPNOTSUPP`) otherwise.
    pub fn fgetxattr_as_root<F>(
        &mut self,
        f: File,
        name: &CStr,
        buf: Vec<u8>,
        on_done: F,
    ) where
        F: FnOnce(FsDone, &mut FsConn<'_>) + 'static,
    {
        if !self.fd_xattr_ok {
            return self.fail_now(Errno::EOPNOTSUPP, vec![buf], on_done);
        }
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
        if !self.fd_xattr_ok {
            return self.fail_now(Errno::EOPNOTSUPP, vec![value], on_done);
        }
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

    /// Set `f`'s length to `len` (`ftruncate`). Needs Linux ≥ 6.9.
    pub fn ftruncate<F>(
        &mut self,
        who: Personality,
        f: File,
        len: u64,
        on_done: F,
    ) where
        F: FnOnce(FsDone, &mut FsConn<'_>) + 'static,
    {
        if !self.ftruncate_ok {
            return self.fail_now(Errno::EOPNOTSUPP, Vec::new(), on_done);
        }
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

    /// Close `f`: drop the handle. Its fd closes once the last reference (this
    /// handle plus any op still parking a clone) drops — close-last by
    /// ownership. Fire-and-forget; there is no completion callback.
    pub fn close(&mut self, f: File) {
        drop(f);
    }

    // ---- private submit helpers ----------------------------------------

    fn rw<F>(
        &mut self,
        tag: u8,
        who: Personality,
        f: File,
        bufs: Vec<Vec<u8>>,
        off: u64,
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

fn map_res(res: i32) -> Result<i32, Errno> {
    if res < 0 {
        Err(Errno::from_raw(-res))
    } else {
        Ok(res)
    }
}

/// Route a completed op's outcome to its channel waiter. A gone caller (a
/// dropped receiver — a `File`/future dropped before awaiting) simply
/// orphans the op; nothing to do. (A successful `open` does NOT route through
/// here — its arm in `on_cqe` handles the gone-receiver case by staging a
/// close, so the freshly-opened slot isn't leaked when no `File` gets
/// built.)
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
        // unfired — dropping the continuation it captured closes the
        // connection (see [`EmbeddedCb`]). Nothing else routes it.
        Some(FsWaiter::Embedded { cb, .. }) => {
            drop(cb);
            drop((bufs, file, stat));
        }
        None => {}
    }
}

/// Routing / close-last property fuzzer for the **plain-fd** core. There is no
/// file-slot pool any more; fds are `Arc<OwnedFd>` closed by last-reference. The
/// fuzzer drives fuzzed submit/complete schedules against a real (never-flushed)
/// `Engine`, feeds a mix of correct and anomalous CQEs, and asserts: op slots
/// free exactly once (`op_free` reconciles), every synthesized fd closes exactly
/// once (never early — a parked clone outlives a dropped caller — never leaked),
/// and stale/wrong-tag/recycled completions are inert. `ROUTING_FUZZ_SEEDS=N`
/// overrides the seed count.
#[cfg(test)]
mod routing_fuzz {
    use super::*;
    use std::os::fd::RawFd;
    use std::sync::{mpsc, Weak};

    const OP_SLOTS: u32 = 32;
    // The ring is sized far above any run's staged SQEs, so `push_sqe` never
    // flushes to the kernel — routing runs purely in userspace.
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

    /// In-flight ops as `(tag, slot, generation-low)` — the CQEs a real kernel
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
        let mut core = FsCore::new(8);

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
        let mut core = FsCore::new(8);
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
                chan(&tx),
            );
        }
        // Teardown reaps each in-flight op via the drain path → parked Arcs drop.
        for (tag, slot, gen) in inflight(&core) {
            let cqe = IoUringCqe {
                user_data: pack_raw(tag, slot, gen),
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
        let mut core = FsCore::new(OP_SLOTS);
        let (tx, rx) = mpsc::channel::<FsOutcome>();
        // Weak refs to every synthesized fd — `upgrade() == None` means closed.
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
                    // An anomalous completion — MUST mutate nothing.
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
            // the fd until its own CQE — the close-last guarantee).
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
}
