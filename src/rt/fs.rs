//! [`FsRt`]: the async twin of [`FsHandle`] — same loop, same validation,
//! same owned-buffer round-trips, awaited instead of blocked on.

use super::buf::PooledBuf;
use crate::async_fs::core::{
    TAG_FALLOCATE, TAG_FGETXATTR, TAG_FSETXATTR, TAG_FTRUNCATE, TAG_LINKAT,
    TAG_MKDIRAT, TAG_READV, TAG_READ_FIXED, TAG_RENAMEAT, TAG_STATX,
    TAG_SYMLINKAT, TAG_UNLINKAT, TAG_WRITEV, TAG_WRITE_FIXED,
};
use crate::async_fs::{
    open_parts, statx_at_flags, Anchor, CancelToken, FixedFile, FsHandle,
    FsInject, FsOutcome, Leaf, Personality, ReplyTo, CANCEL_REQUESTED,
};
use crate::errno::Errno;
use crate::path::TnPath;
use crate::sync_fs::openat2::RawOpenHow;
use crate::sync_fs::{AtFlags, Mode, OpenHow, RenameFlags, Statx, StatxMask};
use std::ffi::{CStr, CString};
use std::ops::Range;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::sync::oneshot;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// The bridge-op cancel-on-drop guard. Lives on a `bridge_call` future's
/// stack from just after submission until the op completes; a normal
/// completion [`disarm`](CancelGuard::disarm)s it, but a dropped future
/// (timeout, `select!`, abort) runs its `Drop`, which reclaims the abandoned
/// op. The single `swap` on the shared [`CancelToken`] resolves the race
/// with the loop's staging:
/// - the loop had already published the op's `user_data` → ask it to cancel
///   that op by `user_data` ([`FsInject::CancelUd`]);
/// - the loop had not staged yet (`0`) → we leave [`CANCEL_REQUESTED`], and
///   the loop's `publish_cancel` sees it and aborts the op cleanly.
struct CancelGuard {
    h: FsHandle,
    cancel: CancelToken,
    armed: bool,
}

impl CancelGuard {
    /// The op completed normally; nothing to cancel.
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for CancelGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        match self.cancel.swap(CANCEL_REQUESTED, Ordering::AcqRel) {
            // Not staged yet: the loop will see CANCEL_REQUESTED when it goes
            // to publish and abort the op cleanly. Nothing to send.
            0 => {}
            // Op in flight under this user_data: ask the loop to cancel it.
            // `FsHandle::send` pokes the wake; a stopping loop drops it (the
            // op is being torn down anyway).
            ud => {
                let _ = self.h.send(FsInject::CancelUd { ud });
            }
        }
    }
}

/// The `Clone + Send + Sync` async operations handle: every method is the
/// `async fn` twin of the same-named blocking [`FsHandle`] call — identical
/// argument validation, personality discipline, buffer round-trips, and
/// error mapping (see each blocking method's documentation for semantics).
///
/// Two async-specific properties:
///
/// - **Cancel-safety**: dropping a returned future abandons the *result*,
///   never the operation — the op runs to completion on the loop; its
///   buffers and anchors stay owned by the op table until the CQE reaps,
///   then are dropped with the undeliverable outcome. A future dropped
///   before its inject was sent has no effect at all.
/// - **Backpressure**: submissions first acquire a semaphore permit sized
///   to the op table, so async callers queue rather than fail `EBUSY` when
///   the table is full. The permit travels loop-side in the reply endpoint
///   and releases when the outcome is delivered (right after the op slot
///   frees) — a cancelled future cannot release it early. Blocking
///   [`FsHandle`] callers on the same loop bypass this gate and may still
///   observe `EBUSY` under contention.
///
/// A loop that is shutting down (or gone) fails calls with `ECONNABORTED`,
/// exactly like the blocking surface.
#[derive(Clone, Debug)]
pub struct FsRt {
    h: FsHandle,
    sem: Arc<Semaphore>,
}

impl FsRt {
    pub(crate) fn new(h: FsHandle, sem: Arc<Semaphore>) -> FsRt {
        FsRt { h, sem }
    }

    /// Queue-don't-fail backpressure: waits for an op-table permit. The
    /// semaphore is never closed, so an `Err` (impossible today) simply
    /// degrades to "no permit" rather than failing the op.
    async fn permit(&self) -> Option<OwnedSemaphorePermit> {
        self.sem.clone().acquire_owned().await.ok()
    }

    /// Submit an inject whose only payload is the reply, and await the
    /// outcome. (Ops with recoverable buffers — reads/writes/xattr — have
    /// their own paths that hand buffers back on a send failure.)
    async fn unit_call(
        &self,
        build: impl FnOnce(ReplyTo) -> FsInject,
    ) -> crate::Result<FsOutcome> {
        let permit = self.permit().await;
        let (tx, rx) = oneshot::channel();
        self.h
            .send(build(ReplyTo::once(tx, permit)))
            .map_err(|_| crate::Error::from(Errno::ECONNABORTED))?;
        rx.await.map_err(|_| Errno::ECONNABORTED.into())
    }

    /// Async twin of [`FsHandle::open`]: open `path` (anchor-relative,
    /// confined by default) into a fixed-table slot as `who`.
    pub async fn open<P: ?Sized + TnPath>(
        &self,
        who: Personality,
        anchor: &Anchor,
        path: &P,
        how: OpenHow,
    ) -> crate::Result<FixedFile> {
        let (cpath, raw) = open_parts(path, how)?;
        self.open_raw(who, anchor, cpath, raw).await
    }

    /// Like [`open`](FsRt::open), but forces `O_DIRECT` and captures the
    /// file's direct-I/O alignment (`STATX_DIOALIGN`) into the returned
    /// [`DirectFile`], whose [`read_direct`](FsRt::read_direct) /
    /// [`write_direct`](FsRt::write_direct) pre-validate offsets and lengths
    /// against it (a precise `Validation` error instead of the kernel's bare
    /// `EINVAL`). Registered pool buffers are page-aligned by construction,
    /// so the *memory* alignment requirement holds automatically.
    ///
    /// Filesystems without direct I/O reject the open itself (`EINVAL`);
    /// ones that don't report alignment leave it 0, which disables the
    /// pre-validation (the kernel still enforces its own rules). Note the
    /// alignment statx names the path a second time after the open — the
    /// same statx-then-open caveat the module docs describe.
    pub async fn open_direct<P: ?Sized + TnPath>(
        &self,
        who: Personality,
        anchor: &Anchor,
        path: &P,
        how: OpenHow,
    ) -> crate::Result<DirectFile> {
        let (cpath, mut raw) = open_parts(path, how)?;
        raw.flags |= libc::O_DIRECT as u64;
        let statx_path = cpath.clone();
        let file = self.open_raw(who, anchor, cpath, raw).await?;
        let a1 = anchor.clone();
        let stat = self
            .unit_call(move |reply| FsInject::PathOp {
                tag: TAG_STATX,
                pers: who.0,
                a1,
                n1: statx_path,
                a2: None,
                n2: None,
                flags: statx_at_flags(AtFlags::empty()),
                len_arg: (StatxMask::BASIC_STATS | StatxMask::DIOALIGN).bits(),
                reply,
            })
            .await;
        let aligns = match stat {
            Ok(out) if out.res.is_ok() => out
                .stat
                .map(|s| (s.stx_dio_mem_align, s.stx_dio_offset_align))
                .unwrap_or((0, 0)),
            Ok(out) => {
                let e = out.res.expect_err("checked");
                let _ = self.close(file).await; // don't leak the slot
                return Err(e.into());
            }
            Err(e) => {
                let _ = self.close(file).await;
                return Err(e);
            }
        };
        Ok(DirectFile {
            file,
            mem_align: aligns.0,
            offset_align: aligns.1,
        })
    }

    async fn open_raw(
        &self,
        who: Personality,
        anchor: &Anchor,
        cpath: CString,
        raw: RawOpenHow,
    ) -> crate::Result<FixedFile> {
        let anchor = anchor.clone();
        let out = self
            .unit_call(move |reply| FsInject::Open {
                pers: who.0,
                anchor,
                path: cpath,
                how: raw,
                reply,
            })
            .await?;
        let (slot, gen) = match (out.res, out.file) {
            (Ok(_), Some(sg)) => sg,
            (Err(e), _) => return Err(e.into()),
            (Ok(_), None) => return Err(Errno::EIO.into()),
        };
        Ok(FixedFile {
            slot,
            gen,
            tx: self.h.tx.clone(),
            shared: self.h.shared.clone(),
            defused: false,
        })
    }

    /// Async twin of [`FsHandle::preadv`] — vectored positional read.
    pub async fn preadv(
        &self,
        who: Personality,
        f: &FixedFile,
        bufs: Vec<Vec<u8>>,
        off: u64,
    ) -> (crate::Result<usize>, Vec<Vec<u8>>) {
        self.rw(TAG_READV, who, f, bufs, off).await
    }

    /// Async twin of [`FsHandle::pread`] — single-buffer positional read.
    pub async fn pread(
        &self,
        who: Personality,
        f: &FixedFile,
        buf: Vec<u8>,
        off: u64,
    ) -> (crate::Result<usize>, Vec<u8>) {
        let (res, mut bufs) = self.rw(TAG_READV, who, f, vec![buf], off).await;
        (res, bufs.pop().unwrap_or_default())
    }

    /// Async twin of [`FsHandle::pwritev`] — vectored positional write.
    pub async fn pwritev(
        &self,
        who: Personality,
        f: &FixedFile,
        bufs: Vec<Vec<u8>>,
        off: u64,
    ) -> (crate::Result<usize>, Vec<Vec<u8>>) {
        self.rw(TAG_WRITEV, who, f, bufs, off).await
    }

    /// Async twin of [`FsHandle::pwrite`] — single-buffer positional write.
    pub async fn pwrite(
        &self,
        who: Personality,
        f: &FixedFile,
        buf: Vec<u8>,
        off: u64,
    ) -> (crate::Result<usize>, Vec<u8>) {
        let (res, mut bufs) = self.rw(TAG_WRITEV, who, f, vec![buf], off).await;
        (res, bufs.pop().unwrap_or_default())
    }

    /// Positional read into a **registered buffer** (`READ_FIXED`): the
    /// kernel resolves the pool's pre-pinned pages directly — no per-op page
    /// pin, and on an `O_DIRECT` file the device DMAs straight into them.
    /// Fills up to `buf.len()` bytes from offset `off`.
    ///
    /// The lease is owned by the op until its CQE and round-trips back with
    /// the result; **on error the lease returns to the pool** (re-lease to
    /// retry). Needs a pool ([`FsRuntimeBuilder::with_buffers`]) — this
    /// method's `PooledBuf` argument is the capability.
    ///
    /// [`FsRuntimeBuilder::with_buffers`]: super::FsRuntimeBuilder::with_buffers
    pub async fn read_fixed(
        &self,
        who: Personality,
        f: &FixedFile,
        buf: PooledBuf,
        off: u64,
    ) -> crate::Result<(usize, PooledBuf)> {
        let whole = 0..buf.len();
        self.rw_fixed(TAG_READ_FIXED, who, f, buf, whole, off).await
    }

    /// Positional write of `buf[range]` from a registered buffer
    /// (`WRITE_FIXED`); the lease round-trips like
    /// [`read_fixed`](FsRt::read_fixed).
    pub async fn write_fixed(
        &self,
        who: Personality,
        f: &FixedFile,
        buf: PooledBuf,
        range: Range<usize>,
        off: u64,
    ) -> crate::Result<(usize, PooledBuf)> {
        self.rw_fixed(TAG_WRITE_FIXED, who, f, buf, range, off)
            .await
    }

    /// [`read_fixed`](FsRt::read_fixed) with the [`DirectFile`]'s alignment
    /// pre-validated.
    pub async fn read_direct(
        &self,
        who: Personality,
        f: &DirectFile,
        buf: PooledBuf,
        off: u64,
    ) -> crate::Result<(usize, PooledBuf)> {
        f.check(off, buf.len())?;
        self.read_fixed(who, f.file(), buf, off).await
    }

    /// [`write_fixed`](FsRt::write_fixed) with the [`DirectFile`]'s
    /// alignment pre-validated.
    pub async fn write_direct(
        &self,
        who: Personality,
        f: &DirectFile,
        buf: PooledBuf,
        range: Range<usize>,
        off: u64,
    ) -> crate::Result<(usize, PooledBuf)> {
        f.check(off, range.len())?;
        self.write_fixed(who, f.file(), buf, range, off).await
    }

    async fn rw_fixed(
        &self,
        tag: u8,
        who: Personality,
        f: &FixedFile,
        buf: PooledBuf,
        range: Range<usize>,
        off: u64,
    ) -> crate::Result<(usize, PooledBuf)> {
        if range.start > range.end || range.end > buf.len() {
            return Err(crate::Error::Validation(format!(
                "fixed rw range {}..{} outside the {}-byte buffer",
                range.start,
                range.end,
                buf.len()
            )));
        }
        let addr = buf.as_ptr() as u64 + range.start as u64;
        let len = u32::try_from(range.len()).map_err(|_| {
            crate::Error::Validation("fixed rw longer than u32::MAX".into())
        })?;
        let buf_index = buf.index();
        let permit = self.permit().await;
        let (tx, rx) = oneshot::channel();
        self.h
            .send(FsInject::RwFixed {
                tag,
                pers: who.0,
                slot: f.slot,
                gen: f.gen,
                addr,
                len,
                buf_index,
                off,
                // The lease rides in the reply endpoint: owned by the op
                // entry until the CQE, then either round-tripped back with
                // the outcome or returned to the pool. `addr` can never
                // dangle while the kernel may touch it.
                reply: ReplyTo::Once {
                    tx,
                    permit,
                    fixed: Some(buf),
                },
            })
            .map_err(|_| crate::Error::from(Errno::ECONNABORTED))?;
        match rx.await {
            Ok(out) => {
                let n = out.res.map_err(crate::Error::from)? as usize;
                let buf = out.fixed.ok_or(Errno::EIO)?;
                Ok((n, buf))
            }
            Err(_) => Err(Errno::ECONNABORTED.into()),
        }
    }

    /// Async twin of [`FsHandle::fsync`].
    pub async fn fsync(
        &self,
        who: Personality,
        f: &FixedFile,
    ) -> crate::Result<()> {
        self.sync(who, f, false).await
    }

    /// Async twin of [`FsHandle::fdatasync`].
    pub async fn fdatasync(
        &self,
        who: Personality,
        f: &FixedFile,
    ) -> crate::Result<()> {
        self.sync(who, f, true).await
    }

    /// Async twin of [`FsHandle::fgetxattr`] (Linux ≥ 6.13; `EOPNOTSUPP`
    /// where the fixed-file xattr probe failed).
    pub async fn fgetxattr(
        &self,
        who: Personality,
        f: &FixedFile,
        name: &CStr,
        buf: Vec<u8>,
    ) -> (crate::Result<usize>, Vec<u8>) {
        if !self.h.fd_xattr_ok {
            return (Err(Errno::EOPNOTSUPP.into()), buf);
        }
        self.fd_meta_buf(
            TAG_FGETXATTR,
            who,
            f,
            Some(name.to_owned()),
            buf,
            0,
            0,
            0,
        )
        .await
    }

    /// Async twin of [`FsHandle::fsetxattr`] (Linux ≥ 6.13).
    pub async fn fsetxattr(
        &self,
        who: Personality,
        f: &FixedFile,
        name: &CStr,
        value: Vec<u8>,
        flags: i32,
    ) -> (crate::Result<()>, Vec<u8>) {
        if !self.h.fd_xattr_ok {
            return (Err(Errno::EOPNOTSUPP.into()), value);
        }
        let (res, buf) = self
            .fd_meta_buf(
                TAG_FSETXATTR,
                who,
                f,
                Some(name.to_owned()),
                value,
                0,
                0,
                flags as u32,
            )
            .await;
        (res.map(|_| ()), buf)
    }

    /// Async twin of [`FsHandle::ftruncate`] (Linux ≥ 6.9; `EOPNOTSUPP`
    /// where `IORING_OP_FTRUNCATE` is unsupported).
    pub async fn ftruncate(
        &self,
        who: Personality,
        f: &FixedFile,
        len: u64,
    ) -> crate::Result<()> {
        if !self.h.ftruncate_ok {
            return Err(Errno::EOPNOTSUPP.into());
        }
        self.fd_meta_unit(TAG_FTRUNCATE, who, f, len, 0, 0).await
    }

    /// Async twin of [`FsHandle::fallocate`].
    pub async fn fallocate(
        &self,
        who: Personality,
        f: &FixedFile,
        mode: i32,
        off: u64,
        len: u64,
    ) -> crate::Result<()> {
        self.fd_meta_unit(TAG_FALLOCATE, who, f, off, len, mode as u32)
            .await
    }

    /// Async twin of [`FsHandle::statx`] — stat `leaf` inside `anchor`
    /// (terminal symlinks not followed unless `AT_SYMLINK_FOLLOW`).
    pub async fn statx(
        &self,
        who: Personality,
        anchor: &Anchor,
        leaf: Leaf<'_>,
        flags: AtFlags,
        mask: StatxMask,
    ) -> crate::Result<Statx> {
        self.statx_inner(who, anchor, leaf.to_cstring(), flags, mask)
            .await
    }

    /// Async twin of [`FsHandle::statx_anchor`] — stat the anchor directory
    /// itself.
    pub async fn statx_anchor(
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
        .await
    }

    /// Async twin of [`FsHandle::mkdirat`].
    pub async fn mkdirat(
        &self,
        who: Personality,
        anchor: &Anchor,
        leaf: Leaf<'_>,
        mode: Mode,
    ) -> crate::Result<()> {
        self.path_op(TAG_MKDIRAT, who, anchor, leaf, None, None, 0, mode.bits())
            .await
    }

    /// Async twin of [`FsHandle::unlinkat`].
    pub async fn unlinkat(
        &self,
        who: Personality,
        anchor: &Anchor,
        leaf: Leaf<'_>,
    ) -> crate::Result<()> {
        self.path_op(TAG_UNLINKAT, who, anchor, leaf, None, None, 0, 0)
            .await
    }

    /// Async twin of [`FsHandle::rmdirat`].
    pub async fn rmdirat(
        &self,
        who: Personality,
        anchor: &Anchor,
        leaf: Leaf<'_>,
    ) -> crate::Result<()> {
        self.path_op(
            TAG_UNLINKAT,
            who,
            anchor,
            leaf,
            None,
            None,
            libc::AT_REMOVEDIR as u32,
            0,
        )
        .await
    }

    /// Async twin of [`FsHandle::renameat`].
    #[allow(clippy::too_many_arguments)]
    pub async fn renameat(
        &self,
        who: Personality,
        old: &Anchor,
        old_leaf: Leaf<'_>,
        new: &Anchor,
        new_leaf: Leaf<'_>,
        flags: RenameFlags,
    ) -> crate::Result<()> {
        self.path_op(
            TAG_RENAMEAT,
            who,
            old,
            old_leaf,
            Some(new),
            Some(new_leaf),
            flags.bits(),
            0,
        )
        .await
    }

    /// Async twin of [`FsHandle::symlinkat`] — create a symlink `leaf` in
    /// `anchor` whose stored content is `target` (never resolved here).
    pub async fn symlinkat<P: ?Sized + TnPath>(
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
        let a1 = anchor.clone();
        let link = leaf.to_cstring();
        let out = self
            .unit_call(move |reply| FsInject::PathOp {
                tag: TAG_SYMLINKAT,
                pers: who.0,
                a1,
                n1: target,
                a2: None,
                n2: Some(link),
                flags: 0,
                len_arg: 0,
                reply,
            })
            .await?;
        out.res.map(|_| ()).map_err(Into::into)
    }

    /// Async twin of [`FsHandle::linkat`].
    #[allow(clippy::too_many_arguments)]
    pub async fn linkat(
        &self,
        who: Personality,
        old: &Anchor,
        old_leaf: Leaf<'_>,
        new: &Anchor,
        new_leaf: Leaf<'_>,
        flags: AtFlags,
    ) -> crate::Result<()> {
        self.path_op(
            TAG_LINKAT,
            who,
            old,
            old_leaf,
            Some(new),
            Some(new_leaf),
            flags.bits() as u32,
            0,
        )
        .await
    }

    /// Async twin of [`FsHandle::close`]: close the file and free its pool
    /// slot, awaiting the kernel's close (in-flight ops on it are cancelled
    /// first; close-last holds). Personality-free like its blocking twin.
    pub async fn close(&self, f: FixedFile) -> crate::Result<()> {
        // Keep `f` armed until the inject is actually queued: a future
        // dropped before the send still orphan-closes via `FixedFile::drop`.
        let permit = self.permit().await;
        let (tx, rx) = oneshot::channel();
        let mut f = f;
        f.defused = true;
        let (slot, gen) = (f.slot, f.gen);
        drop(f);
        self.h
            .send(FsInject::Close {
                slot,
                gen,
                reply: Some(ReplyTo::once(tx, permit)),
            })
            .map_err(|_| crate::Error::from(Errno::ECONNABORTED))?;
        match rx.await {
            Ok(out) => out.res.map(|_| ()).map_err(Into::into),
            Err(_) => Err(Errno::ECONNABORTED.into()),
        }
    }

    async fn sync(
        &self,
        who: Personality,
        f: &FixedFile,
        datasync: bool,
    ) -> crate::Result<()> {
        let (slot, gen) = (f.slot, f.gen);
        let out = self
            .unit_call(move |reply| FsInject::Fsync {
                pers: who.0,
                slot,
                gen,
                datasync,
                reply,
            })
            .await?;
        out.res.map(|_| ()).map_err(Into::into)
    }

    async fn rw(
        &self,
        tag: u8,
        who: Personality,
        f: &FixedFile,
        bufs: Vec<Vec<u8>>,
        off: u64,
    ) -> (crate::Result<usize>, Vec<Vec<u8>>) {
        let permit = self.permit().await;
        let (tx, rx) = oneshot::channel();
        let sent = self.h.send(FsInject::Rw {
            tag,
            pers: who.0,
            slot: f.slot,
            gen: f.gen,
            bufs,
            off,
            reply: ReplyTo::once(tx, permit),
        });
        if let Err(msg) = sent {
            // Loop gone: hand the caller's buffers back (the owned-round-trip
            // contract holds on failure too, as on the blocking surface).
            let bufs = match msg {
                FsInject::Rw { bufs, .. } => bufs,
                _ => Vec::new(),
            };
            return (Err(Errno::ECONNABORTED.into()), bufs);
        }
        match rx.await {
            Ok(out) => {
                (out.res.map(|n| n as usize).map_err(Into::into), out.bufs)
            }
            Err(_) => (Err(Errno::ECONNABORTED.into()), Vec::new()),
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn fd_meta_buf(
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
        let permit = self.permit().await;
        let (tx, rx) = oneshot::channel();
        let sent = self.h.send(FsInject::FdMeta {
            tag,
            pers: who.0,
            slot: f.slot,
            gen: f.gen,
            name,
            value,
            off,
            len64,
            aux32,
            reply: ReplyTo::once(tx, permit),
        });
        if let Err(msg) = sent {
            let value = match msg {
                FsInject::FdMeta { value, .. } => value,
                _ => Vec::new(),
            };
            return (Err(Errno::ECONNABORTED.into()), value);
        }
        match rx.await {
            Ok(mut out) => (
                out.res.map(|n| n as usize).map_err(Into::into),
                out.bufs.pop().unwrap_or_default(),
            ),
            Err(_) => (Err(Errno::ECONNABORTED.into()), Vec::new()),
        }
    }

    async fn fd_meta_unit(
        &self,
        tag: u8,
        who: Personality,
        f: &FixedFile,
        off: u64,
        len64: u64,
        aux32: u32,
    ) -> crate::Result<()> {
        let (slot, gen) = (f.slot, f.gen);
        let out = self
            .unit_call(move |reply| FsInject::FdMeta {
                tag,
                pers: who.0,
                slot,
                gen,
                name: None,
                value: Vec::new(),
                off,
                len64,
                aux32,
                reply,
            })
            .await?;
        out.res.map(|_| ()).map_err(Into::into)
    }

    async fn statx_inner(
        &self,
        who: Personality,
        anchor: &Anchor,
        path: CString,
        flags: AtFlags,
        mask: StatxMask,
    ) -> crate::Result<Statx> {
        let a1 = anchor.clone();
        let out = self
            .unit_call(move |reply| FsInject::PathOp {
                tag: TAG_STATX,
                pers: who.0,
                a1,
                n1: path,
                a2: None,
                n2: None,
                flags: statx_at_flags(flags),
                len_arg: mask.bits(),
                reply,
            })
            .await?;
        out.res?;
        out.stat
            .map(|raw| Statx::from_raw(*raw))
            .ok_or_else(|| Errno::EIO.into())
    }

    /// Close a [`DirectFile`] (unwraps to the plain close).
    pub async fn close_direct(&self, f: DirectFile) -> crate::Result<()> {
        self.close(f.file).await
    }

    // ---- bridge primitives (crate-internal; the public face is
    // `rt::Bridge`) ------------------------------------------------------

    /// A bridge-op submission that **cancels the in-flight op if the future
    /// is dropped** (a timeout, a `select!`, a task abort). Without this a
    /// dropped transfer would leak the op's slot and backpressure permit
    /// until a CQE that a silent peer never produces — a `POLL_ADD` awaiting
    /// readiness, an io-wq-blocked kTLS splice — starving the whole fs
    /// runtime. A [`super::CancelToken`] shared with the loop carries the
    /// op's `user_data`; the guard's `Drop` asks the loop to cancel it (or,
    /// if the loop hasn't staged yet, poisons the token so the loop aborts
    /// the op cleanly). A normal completion disarms the guard.
    async fn bridge_call(
        &self,
        build: impl FnOnce(ReplyTo, CancelToken) -> FsInject,
    ) -> crate::Result<FsOutcome> {
        use std::sync::atomic::AtomicU64;
        let permit = self.permit().await;
        let (tx, rx) = oneshot::channel();
        let cancel: CancelToken = Arc::new(AtomicU64::new(0));
        self.h
            .send(build(ReplyTo::once(tx, permit), cancel.clone()))
            .map_err(|_| crate::Error::from(Errno::ECONNABORTED))?;
        let mut guard = CancelGuard {
            h: self.h.clone(),
            cancel,
            armed: true,
        };
        let out = rx.await;
        guard.disarm(); // completed normally — nothing to cancel
        out.map_err(|_| Errno::ECONNABORTED.into())
    }

    /// One splice hop. Returns the CQE result as bytes moved; `-EAGAIN`
    /// surfaces as `Err(EAGAIN)` for the caller's readiness retry (io_uring
    /// never poll-arms splice). Cancel-on-drop (see [`bridge_call`]).
    pub(crate) async fn bridge_splice(
        &self,
        in_end: crate::async_fs::SpliceEnd,
        off_in: u64,
        out_end: crate::async_fs::SpliceEnd,
        off_out: u64,
        len: u32,
        keep: Vec<Arc<std::os::fd::OwnedFd>>,
    ) -> crate::Result<u64> {
        let out = self
            .bridge_call(move |reply, cancel| FsInject::Splice {
                in_end,
                off_in,
                out_end,
                off_out,
                len,
                flags: crate::uring::sys::SPLICE_F_MOVE,
                keep,
                cancel,
                reply,
            })
            .await?;
        out.res.map(|n| n as u64).map_err(Into::into)
    }

    /// One-shot readiness wait on a raw fd (`POLL_ADD`). Cancel-on-drop.
    pub(crate) async fn bridge_poll(
        &self,
        fd: std::os::fd::RawFd,
        events: u32,
        keep: Arc<std::os::fd::OwnedFd>,
    ) -> crate::Result<()> {
        let out = self
            .bridge_call(move |reply, cancel| FsInject::Poll {
                fd,
                events,
                keep,
                cancel,
                reply,
            })
            .await?;
        out.res.map(|_| ()).map_err(Into::into)
    }

    /// One bridge send (`data[start..]`), plain or zero-copy. The payload
    /// comes back alongside the result whenever the op still owns it at
    /// delivery — a plain send's completion, or a zero-copy attempt's failure
    /// once its notif lands (the `EOPNOTSUPP`-on-kTLS case the fallback
    /// needs); a *successful* zero-copy send keeps it pinned until the notif
    /// and returns an empty `Vec`. Cancel-on-drop.
    pub(crate) async fn bridge_send(
        &self,
        fd: std::os::fd::RawFd,
        data: Vec<u8>,
        start: usize,
        msg_flags: u32,
        zc: bool,
        keep: Arc<std::os::fd::OwnedFd>,
    ) -> (crate::Result<usize>, Vec<u8>) {
        match self
            .bridge_call(move |reply, cancel| FsInject::Send {
                fd,
                data,
                start,
                msg_flags,
                zc,
                keep,
                cancel,
                reply,
            })
            .await
        {
            Ok(mut out) => (
                out.res.map(|n| n as usize).map_err(Into::into),
                out.bufs.pop().unwrap_or_default(),
            ),
            // Loop gone (ECONNABORTED): the payload is lost with the failed
            // inject, but every `send_zc` caller returns on this error
            // without reusing it.
            Err(e) => (Err(e), Vec::new()),
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn path_op(
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
        let a1 = a1.clone();
        let a2 = a2.cloned();
        let n1 = n1.to_cstring();
        let n2 = n2.map(Leaf::to_cstring);
        let out = self
            .unit_call(move |reply| FsInject::PathOp {
                tag,
                pers: who.0,
                a1,
                n1,
                a2,
                n2,
                flags,
                len_arg,
                reply,
            })
            .await?;
        out.res.map(|_| ()).map_err(Into::into)
    }
}

/// An `O_DIRECT`-opened file plus its direct-I/O alignment, captured at
/// [`FsRt::open_direct`] via `STATX_DIOALIGN`. Ops through
/// [`FsRt::read_direct`]/[`FsRt::write_direct`] pre-validate offset and
/// length against `offset_align`; memory alignment holds by construction
/// (pool chunks are page-aligned mappings). An alignment of 0 means the
/// filesystem reported none — validation is skipped and the kernel's own
/// checks apply.
#[derive(Debug)]
pub struct DirectFile {
    file: FixedFile,
    mem_align: u32,
    offset_align: u32,
}

impl DirectFile {
    /// The underlying pool file (usable with every [`FsRt`] fd-op; the
    /// alignment-validated paths are `read_direct`/`write_direct`).
    pub fn file(&self) -> &FixedFile {
        &self.file
    }

    /// Required memory alignment for direct I/O buffers (0 = unreported).
    /// Pool buffers are page-aligned, which satisfies any value ≤ page size.
    pub fn mem_align(&self) -> u32 {
        self.mem_align
    }

    /// Required file-offset/length alignment for direct I/O (0 = unreported).
    pub fn offset_align(&self) -> u32 {
        self.offset_align
    }

    fn check(&self, off: u64, len: usize) -> crate::Result<()> {
        let a = u64::from(self.offset_align);
        if a == 0 {
            return Ok(());
        }
        if off % a != 0 || (len as u64) % a != 0 {
            return Err(crate::Error::Validation(format!(
                "direct I/O requires offset and length aligned to {a} \
                 (offset {off}, length {len})"
            )));
        }
        Ok(())
    }
}
