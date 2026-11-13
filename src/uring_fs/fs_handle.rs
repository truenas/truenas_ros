use super::*;

impl FsHandle {
    /// Open `path` - **relative**, resolved against `anchor` under the kernel's checks as `who` - returning a real fd
    /// as a [`File`].
    ///
    /// `how` is the same [`OpenHow`] the blocking [`openat2`](crate::sync_fs::openat2) takes; `O_CLOEXEC` is accepted.
    /// Open failures (`ENOENT`, `EACCES` - the personality *working*) come back as `Errno` errors.
    ///
    /// **Confined to `anchor` by default,** with the full [`CONFINED_RESOLVE`] set: a `..` component or a symlink that
    /// would leave `anchor` is rejected (`"../../etc/shadow"` cannot walk out of the share), no symlink is followed,
    /// and resolution stops at a mount point rather than crossing into a nested dataset or a `.zfs/snapshot` automount.
    ///
    /// A caller that names [`RESOLVE_BENEATH`] or [`RESOLVE_IN_ROOT`] replaces that policy, `RESOLVE_BENEATH` alone to
    /// allow in-tree symlinks for one, but `RESOLVE_NO_XDEV` stays with every policy, so anchor on a nested mount to
    /// serve it. Hardening flags alone add to the default rather than replace it. Use
    /// [`open_confined`](Self::open_confined) where confinement must not be replaceable at all.
    ///
    /// [`RESOLVE_BENEATH`]: crate::sync_fs::ResolveFlag::RESOLVE_BENEATH
    /// [`RESOLVE_IN_ROOT`]: crate::sync_fs::ResolveFlag::RESOLVE_IN_ROOT
    pub fn open<P: ?Sized + TnPath>(
        &self,
        who: Personality,
        anchor: &Anchor,
        path: &P,
        how: impl Into<FsOpenHow>,
    ) -> crate::Result<File> {
        let (cpath, raw, guarded, deadline) = open_parts(path, how.into())?;
        self.open_raw(who, anchor, cpath, raw, guarded, deadline)
    }

    /// Submit a prepared `OPENAT2`. Shared by [`open`](Self::open) and [`open_confined`](Self::open_confined) so both
    /// reach the ring by one path and cannot drift.
    fn open_raw(
        &self,
        who: Personality,
        anchor: &Anchor,
        cpath: CString,
        raw: RawOpenHow,
        guarded: bool,
        deadline: Option<std::time::Duration>,
    ) -> crate::Result<File> {
        let (tx, rx) = mpsc::channel();
        let out = self.call(
            FsInject::Open {
                pers: who.0,
                anchor: anchor.clone(),
                path: cpath,
                how: raw,
                guarded,
                deadline,
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

    /// Open `path` under [`CONFINED_RESOLVE`], which the caller **cannot weaken**.
    ///
    /// The confinement flags are unioned into whatever `how` asks for, so extra restrictions compose but none of the
    /// three can be dropped, as [`open`](Self::open) allows. Use it wherever the path comes from a remote peer. A
    /// `RESOLVE_IN_ROOT` in `how` is refused with `Validation`, since `openat2` refuses it beside `RESOLVE_BENEATH`.
    pub fn open_confined<P: ?Sized + TnPath>(
        &self,
        who: Personality,
        anchor: &Anchor,
        path: &P,
        how: impl Into<FsOpenHow>,
    ) -> crate::Result<File> {
        let (cpath, mut raw, guarded, deadline) = open_parts(path, how.into())?;
        // Refused here, where the message can say what to do instead, rather than as a bare `EINVAL` from the syscall
        // (see `scoping_conflict`).
        if scoping_conflict(raw.resolve) {
            return Err(crate::Error::Validation(
                "uring_fs open_confined: RESOLVE_IN_ROOT cannot compose \
                 with the confinement bundle (openat2 refuses \
                 BENEATH|IN_ROOT). Anchor on the root you mean, or use \
                 `open` if you want IN_ROOT's clamping resolution."
                    .into(),
            ));
        }
        // Union, never assign: a caller may add restrictions (RESOLVE_NO_ MAGICLINKS, say) but cannot subtract any of
        // these three.
        raw.resolve |= CONFINED_RESOLVE.bits();
        self.open_raw(who, anchor, cpath, raw, guarded, deadline)
    }

    /// Create every missing directory along `path` beneath `anchor`, returning an [`Anchor`] for the deepest one -
    /// `mkdir -p`, confined.
    ///
    /// Existing components are left alone (`EEXIST` is success, as `mkdir -p` treats it), so this is idempotent and
    /// safe to race: two callers creating the same tree both succeed.
    ///
    /// `mode` applies to directories this call creates, and is subject to the process umask exactly as `mkdir(2)` is.
    /// A path with any component that is not a plain name is refused with `Validation` before anything is opened.
    pub fn mkdir_path<P: ?Sized + TnPath>(
        &self,
        who: Personality,
        anchor: &Anchor,
        path: &P,
        mode: Mode,
    ) -> crate::Result<Anchor> {
        let cpath: CString = path.with_tn_path(|c| c.to_owned())?;
        let bytes = cpath.as_bytes();
        // Judged before anything is opened, so the fast path cannot answer for a shape the walk would refuse: `a/../b`
        // resolves under `RESOLVE_BENEATH` and would come back as a directory when the tree happens to exist, then fail
        // when it does not. See [`path::Defect`](crate::path::Defect) for why `..` is refused rather than folded away.
        if let Some(defect) = crate::path::relative_defect(bytes) {
            return Err(crate::Error::Validation(format!("uring_fs mkdir_path: {defect}")));
        }

        // Fast path: the whole tree already exists, so one confined open settles it. `O_PATH|O_DIRECTORY` is exactly
        // what an `Anchor` is.
        let dir_how = OpenHow::new()
            .flags(OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC)
            .resolve(CONFINED_RESOLVE);
        if let Ok(f) = self.open(who, anchor, cpath.as_c_str(), dir_how) {
            return Anchor::from_file(&f);
        }

        // Slow path: walk, creating what is missing. Each component is a validated `Leaf`, so `mkdirat`'s lack of
        // resolve flags cannot be exploited; each open is confined, so the walk cannot leave `anchor`.
        let mut cur = anchor.clone();
        for part in bytes.split(|&b| b == b'/') {
            if part.is_empty() {
                // Unreachable, since `relative_defect` refused an empty component above.
                continue;
            }
            let leaf = Leaf::new(part)?;
            match self.mkdirat(who, &cur, leaf, mode) {
                Ok(()) => {}
                // Already there: `mkdir -p` semantics, and also the benign outcome of losing a race with another
                // creator.
                Err(crate::Error::Errno(Errno::EEXIST)) => {}
                Err(e) => return Err(e),
            }
            let f = self.open(who, &cur, leaf.to_cstring().as_c_str(), dir_how)?;
            cur = Anchor::from_file(&f)?;
        }
        Ok(cur)
    }

    /// Vectored positional read as `who` - `preadv2(2)` semantics: fill each buffer up to its current `len()`, in
    /// order, starting at file offset `off`. Returns the byte count (short only at end-of-file) and the buffers.
    ///
    /// An unsupported flag fails the read with `EOPNOTSUPP`, as [`RwFlags`] says. Pass [`RwFlags::empty()`] for plain
    /// `preadv(2)` behaviour. [`pread_spare`](Self::pread_spare) reads into the spare capacity of one buffer instead,
    /// so nothing is zeroed first.
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

    /// Positional read as `who` of up to `count` bytes at `off` into the room past the length of `buf`, with the flags
    /// of [`preadv2`](Self::preadv2), so nothing is zeroed first. Returns the byte count, short only at end-of-file,
    /// and the same `buf`, its length grown by that count, or unchanged on a failure.
    ///
    /// A `count` past `buf`'s spare capacity or past `u32::MAX`, and an `off` of `u64::MAX`, are refused with `EINVAL`
    /// before anything is submitted: the buffer is never grown, which would allocate and move it, and io_uring reads
    /// `u64::MAX` as the file's position (`io_kiocb_update_pos`, `io_uring/rw.c`).
    pub fn pread_spare(
        &self,
        who: Personality,
        f: &File,
        buf: Vec<u8>,
        count: usize,
        off: u64,
        flags: RwFlags,
    ) -> (crate::Result<usize>, Vec<u8>) {
        let (tx, rx) = mpsc::channel();
        let sent = self.send(FsInject::ReadSpare {
            pers: who.0,
            file: f.fd.clone(),
            buf,
            count,
            off,
            rw_flags: flags.bits(),
            reply: ReplyTo::Sync(tx),
        });
        if let Err(msg) = sent {
            // Loop gone: the buffer comes back, as from `rw`.
            let buf = match msg {
                FsInject::ReadSpare { buf, .. } => buf,
                _ => Vec::new(),
            };
            return (Err(Errno::ECONNABORTED.into()), buf);
        }
        match rx.recv() {
            Ok(mut out) => (
                out.res.map(|n| n as usize).map_err(Into::into),
                out.bufs.pop().unwrap_or_default(),
            ),
            Err(_) => (Err(Errno::ECONNABORTED.into()), Vec::new()),
        }
    }

    /// Vectored positional write as `who` - `pwritev2(2)` semantics: write each buffer's `len()` bytes, in order,
    /// starting at `off`. Returns bytes written and the buffers.
    ///
    /// [`RwFlags::RWF_DSYNC`] makes the write itself durable and can replace a following
    /// [`fdatasync`](Self::fdatasync), but on ZFS a synchronous write goes through the ZIL, which for large writes can
    /// cost more than one trailing sync. Pass [`RwFlags::empty()`] for plain `pwritev(2)` behaviour.
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

    /// Start a vectored read without blocking. The returned [`FsPending`] collects the outcome.
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

    /// Start a vectored write without blocking - the write-side twin of [`start_preadv2`](Self::start_preadv2).
    ///
    /// Issuing several of these and then collecting them keeps many writes on the ring from one thread.
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
        // Non-blocking: the buffers ride in the pending op and come back through `FsPending::wait`; on a send failure
        // they are dropped with the message (this API returns no buffer to hand them back through).
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
    /// collect the metadata with [`FsPending::wait_statx`](FsPending::wait_statx). The non-blocking twin of
    /// [`statx`](Self::statx), for scattering per-entry metadata (see [`query_directory`]).
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

    /// Start a `statx` of an **already-open** [`File`] without blocking (`statx(fd, "", AT_EMPTY_PATH)`); collect it
    /// with [`FsPending::wait_statx`]. The non-blocking twin of [`fstatx`](Self::fstatx), and the fd-keyed counterpart
    /// of [`start_statx`](Self::start_statx).
    ///
    /// Prefer this wherever a descriptor is already in hand: no path is resolved, so the metadata is that descriptor's
    /// and cannot belong to whatever the name resolved to a moment later.
    pub fn start_fstatx(
        &self,
        who: Personality,
        f: &File,
        flags: AtFlags,
        mask: StatxMask,
    ) -> crate::Result<FsPending> {
        let (tx, rx) = mpsc::channel();
        self.send(FsInject::PathOp {
            tag: core::TAG_STATX,
            pers: who.0,
            a1: Anchor::from_shared(f.fd.clone()),
            n1: CString::default(),
            a2: None,
            n2: None,
            flags: statx_at_flags(flags | AtFlags::AT_EMPTY_PATH),
            len_arg: mask.bits(),
            reply: ReplyTo::Sync(tx),
        })
        .map_err(|_| crate::Error::from(Errno::ECONNABORTED))?;
        Ok(FsPending { rx })
    }

    /// Start an `open` of `path` under `anchor` as `who` without blocking;
    /// collect the [`File`] with [`FsPending::wait_file`](FsPending::wait_file). The non-blocking twin of
    /// [`open`](Self::open).
    pub fn start_open<P: ?Sized + TnPath>(
        &self,
        who: Personality,
        anchor: &Anchor,
        path: &P,
        how: impl Into<FsOpenHow>,
    ) -> crate::Result<FsPending> {
        let (cpath, raw, guarded, deadline) = open_parts(path, how.into())?;
        let (tx, rx) = mpsc::channel();
        self.send(FsInject::Open {
            pers: who.0,
            anchor: anchor.clone(),
            path: cpath,
            how: raw,
            guarded,
            deadline,
            reply: ReplyTo::Sync(tx),
        })
        .map_err(|_| crate::Error::from(Errno::ECONNABORTED))?;
        Ok(FsPending { rx })
    }

    /// Start an `fgetxattr` of `name` on the open file `f` into `buf` as `who` without blocking; collect the size and
    /// filled buffer with [`FsPending::wait_buf`](FsPending::wait_buf). The non-blocking twin of
    /// [`fgetxattr`](Self::fgetxattr).
    pub fn start_fgetxattr(
        &self,
        who: Personality,
        f: &File,
        name: impl Into<Cow<'static, CStr>>,
        buf: Vec<u8>,
    ) -> crate::Result<FsPending> {
        let (tx, rx) = mpsc::channel();
        self.send(FsInject::FdMeta {
            tag: core::TAG_FGETXATTR,
            pers: who.0,
            file: f.fd.clone(),
            name: Some(name.into()),
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

    /// Flush `f`'s data (and only essential metadata) - `fdatasync`.
    pub fn fdatasync(&self, who: Personality, f: &File) -> crate::Result<()> {
        self.sync(who, f, true, 0, 0)
    }

    /// Flush the byte range `[offset, offset + length)` of `f`, with `fdatasync` semantics when `datasync` is set. The
    /// kernel syncs `[offset, offset + length]` through `vfs_fsync_range`, and `offset == 0 && length == 0` syncs the
    /// whole file. `length` is the SQE's 32-bit field, so one call covers at most 4 GiB, and a nonzero `offset` with
    /// `length == 0` is a single-byte range at `offset`, **not** through end-of-file.
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
    /// Returns the attribute's size and the buffer. Passing an empty `buf` queries the size without reading (the
    /// kernel's `size == 0` convention). Note this is a **real per-operation credential check**, not just attribution:
    /// `user.*` requires read permission on the inode at call time, and an unprivileged `trusted.*` read reports
    /// `ENODATA` rather than `EPERM`.
    ///
    /// # A short buffer is reported two ways
    ///
    /// A `buf` shorter than the value fails **`ERANGE` or `E2BIG`**, and which one arrives is decided by the buffer
    /// rather than by the value. `do_getxattr` (`fs/xattr.c`) rewrites `-ERANGE` to `-E2BIG` whenever the buffer is at
    /// or above `XATTR_SIZE_MAX` (65536), with no `IS_LARGE_XATTR` guard, and a value on ZFS may reach 2 MiB. So a
    /// grow-and-retry loop must retry on **both**, or it gives up on any value whose retry buffer reaches 65536.
    pub fn fgetxattr(
        &self,
        who: Personality,
        f: &File,
        name: impl Into<Cow<'static, CStr>>,
        buf: Vec<u8>,
    ) -> (crate::Result<usize>, Vec<u8>) {
        self.fd_meta_buf(core::TAG_FGETXATTR, who, f, Some(name.into()), buf, 0, 0, 0)
    }

    /// Read extended attribute `name` of `f` into `buf` as `who`, through the path of `f` under `/proc/thread-self/fd`,
    /// so `f` may be opened `O_PATH`. The blocking twin of
    /// [`FsConn::fgetxattr_proc`](crate::uring_fs::FsConn::fgetxattr_proc), which says what it reads.
    pub fn fgetxattr_proc(
        &self,
        who: Personality,
        f: &File,
        name: impl Into<Cow<'static, CStr>>,
        buf: Vec<u8>,
    ) -> (crate::Result<usize>, Vec<u8>) {
        self.fd_meta_buf(core::TAG_GETXATTR_PROC, who, f, Some(name.into()), buf, 0, 0, 0)
    }

    /// Read extended attribute `name` from `f` under the reactor's ambient (root) credentials, not any `who`'s: the
    /// off-loop twin of [`FsConn::fgetxattr_as_root`](crate::uring_fs::FsConn::fgetxattr_as_root).
    ///
    /// A privileged, unattributed read for a `trusted.*`/`security.*` attribute a request identity cannot see. Use it
    /// only for server-internal metadata, never to relay a value past a `who` that could not read it. Needs Linux >=
    /// 6.13; fails closed (`EOPNOTSUPP`) otherwise.
    pub fn fgetxattr_as_root(
        &self,
        f: &File,
        name: impl Into<Cow<'static, CStr>>,
        buf: Vec<u8>,
    ) -> (crate::Result<usize>, Vec<u8>) {
        self.read_as_root(f, name.into(), buf, false)
    }

    /// Read extended attribute `name` of `f` under the reactor's ambient (root) credentials through the path of `f`
    /// under `/proc/thread-self/fd`, so `f` may be opened `O_PATH`, which
    /// [`fgetxattr_as_root`](Self::fgetxattr_as_root) refuses with `EBADF`.
    /// The blocking twin of [`FsConn::fgetxattr_proc_as_root`](crate::uring_fs::FsConn::fgetxattr_proc_as_root), which
    /// says what it reads and what it is for.
    pub fn fgetxattr_proc_as_root(
        &self,
        f: &File,
        name: impl Into<Cow<'static, CStr>>,
        buf: Vec<u8>,
    ) -> (crate::Result<usize>, Vec<u8>) {
        self.read_as_root(f, name.into(), buf, true)
    }

    /// The two reads under the reactor's ambient credentials, on the descriptor or `through_proc`.
    fn read_as_root(
        &self,
        f: &File,
        name: Cow<'static, CStr>,
        buf: Vec<u8>,
        through_proc: bool,
    ) -> (crate::Result<usize>, Vec<u8>) {
        let (tx, rx) = mpsc::channel();
        let sent = self.send(FsInject::FdMetaAsRoot {
            file: f.fd.clone(),
            name,
            value: buf,
            through_proc,
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

    /// Open `f` again with `access` as `who`, through its path under `/proc/thread-self/fd`. The blocking twin of
    /// [`FsConn::reopen_proc`](crate::uring_fs::FsConn::reopen_proc), which says what it checks.
    pub fn reopen_proc(&self, who: Personality, f: &File, access: ReopenAccess) -> crate::Result<File> {
        self.reopen(Some(who.0), f, access)
    }

    /// Open `f` again with `access` under the reactor's ambient (root) credentials, through its path under
    /// `/proc/thread-self/fd`. The blocking twin of
    /// [`FsConn::reopen_proc_as_root`](crate::uring_fs::FsConn::reopen_proc_as_root), which says what it is for.
    pub fn reopen_proc_as_root(&self, f: &File, access: ReopenAccess) -> crate::Result<File> {
        self.reopen(None, f, access)
    }

    /// The two reopens, as the personality `pers` or as the ring owner.
    fn reopen(&self, pers: Option<u16>, f: &File, access: ReopenAccess) -> crate::Result<File> {
        let (tx, rx) = mpsc::channel();
        let out = self.call(
            FsInject::ReopenProc {
                pers,
                file: f.fd.clone(),
                access,
                reply: ReplyTo::Sync(tx),
            },
            &rx,
        )?;
        match (out.res, out.file) {
            (Ok(_), Some(fd)) => Ok(File::new(fd)),
            (Err(e), _) => Err(e.into()),
            (Ok(_), None) => Err(Errno::EIO.into()),
        }
    }

    /// Write extended attribute `name` on the open file.
    ///
    /// `flags` takes `libc::XATTR_CREATE` (fail if it exists) or `libc::XATTR_REPLACE` (fail if it does not); 0 means
    /// create-or- replace. The value is returned alongside the result, like every owned buffer here.
    pub fn fsetxattr(
        &self,
        who: Personality,
        f: &File,
        name: impl Into<Cow<'static, CStr>>,
        value: Vec<u8>,
        flags: i32,
    ) -> (crate::Result<()>, Vec<u8>) {
        let (res, buf) = self.fd_meta_buf(
            core::TAG_FSETXATTR,
            who,
            f,
            Some(name.into()),
            value,
            0,
            0,
            flags as u32,
        );
        (res.map(|_| ()), buf)
    }

    /// Set what `set` names on `f` as `who`, in one `FSETXATTR` of [`ZFS_SETATTR`], so the kernel's checks run as
    /// `who`.
    ///
    /// [`ZfsSetattr`] says which checks apply, and a ZFS without the handler answers `EOPNOTSUPP`.
    pub fn fset_attrs(&self, who: Personality, f: &File, set: &ZfsSetattr) -> crate::Result<()> {
        self.fsetxattr(who, f, ZFS_SETATTR, set.to_bytes(), 0).0
    }

    /// List the extended-attribute names on the open file `f` (all namespaces).
    ///
    /// Runs a blocking `flistxattr` on the calling thread at its own privilege, so call it off the reactor (a worker or
    /// client thread). Names the caller is not privileged to see (`trusted.*` without `CAP_SYS_ADMIN`) are omitted by
    /// the kernel.
    pub fn flistxattr(&self, f: &File) -> crate::Result<Vec<CString>> {
        query_dir::list_xattr_names(f)
    }

    /// Filesystem statistics for the mount `f` lives on.
    ///
    /// Runs inline on the calling thread, which is already off the reactor.
    pub fn fstatfs(&self, f: &File) -> crate::Result<Statfs> {
        Ok(crate::sync_fs::fstatfs(&*f.fd)?)
    }

    /// Filesystem statistics for the mount `anchor` lives on - capacity for a whole tree without opening anything in
    /// it.
    ///
    /// An [`Anchor`] is an `O_PATH` descriptor, which most fd-taking calls reject; this one does not, because the
    /// kernel resolves through `f_path` and never consults `f_op` (`fd_statfs`, `fs/statfs.c`).
    pub fn fstatfs_anchor(&self, anchor: &Anchor) -> crate::Result<Statfs> {
        Ok(crate::sync_fs::fstatfs(anchor)?)
    }

    /// Read `f`'s ZFS attributes.
    ///
    /// `f` must have been opened for real I/O - the ioctl needs an `f_op->unlocked_ioctl`, which an `O_PATH` descriptor
    /// lacks. `ENOTTY` off ZFS.
    ///
    /// For `IMMUTABLE`/`APPENDONLY` alone, prefer [`fstatx`](Self::fstatx): `statx` reports both through
    /// [`StatxAttr`](crate::sync_fs::StatxAttr) with no ioctl, and a listing already pays for that stat.
    pub fn fget_zfs_attrs(&self, f: &File) -> crate::Result<ZfsAttr> {
        Ok(crate::sync_fs::fget_zfs_attrs(&*f.fd)?)
    }

    /// Replace `f`'s ZFS attributes with `attrs`. **The mask is absolute**: visible bits absent from `attrs` are
    /// cleared, so read with [`fget_zfs_attrs`](Self::fget_zfs_attrs) and modify that rather than writing a constant.
    ///
    /// It takes no [`Personality`], since the kernel checks an ioctl against the calling thread's credentials, the
    /// process's own. Clearing `ZfsAttr::NOUNLINK` needs only ownership while `IMMUTABLE` needs `CAP_LINUX_IMMUTABLE`,
    /// so do not expose this to a request identity without a gate above it.
    ///
    /// Setting `IMMUTABLE` also makes the file's extended attributes read-only (`may_write_xattr`, `fs/xattr.c`), so
    /// write any metadata that belongs with a locked object *before* locking it.
    pub fn fset_zfs_attrs(&self, f: &File, attrs: ZfsAttr) -> crate::Result<()> {
        Ok(crate::sync_fs::fset_zfs_attrs(&*f.fd, attrs)?)
    }

    /// Remove a **server-owned** extended attribute from `f`, or `EPERM` if `name` is not covered by the reactor's
    /// [`PrivilegedXattrs`] policy.
    ///
    /// It takes no [`Personality`]. io_uring has no removal opcode, and a zero-length `FSETXATTR` sets an *empty*
    /// attribute rather than removing one, so the call runs on a pool thread under the reactor's own credentials. The
    /// allowlist stands in for the identity check, so a user's own attribute cannot be removed through this.
    pub fn fremovexattr(&self, f: &File, name: impl Into<Cow<'static, CStr>>) -> crate::Result<()> {
        let (tx, rx) = mpsc::channel();
        let out = self.call(
            FsInject::FRemoveXattr {
                file: f.fd.clone(),
                name: name.into(),
                reply: ReplyTo::Sync(tx),
            },
            &rx,
        )?;
        out.res.map(|_| ()).map_err(Into::into)
    }

    /// Enumerate the extended attributes of `f` in the namespaces `ns`, read their values under `who`, and return
    /// `(name, value)` for only those `who` can read (see [`XattrNamespaces`]).
    ///
    /// The candidate `flistxattr` runs at this thread's privilege; the per-value read under `who` is the authoritative
    /// gate, so an attribute `who` cannot read (`trusted.*` for an unprivileged identity) is dropped, never returned.
    /// Off-loop: it scatters ring reads and blocks on them, so call it off the reactor. The caller owns any policy
    /// above `who`-readability.
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
    /// Uses `IORING_OP_FTRUNCATE`, from Linux 6.9, below the crate's 6.18 floor, so nothing probes for it.
    pub fn ftruncate(&self, who: Personality, f: &File, len: u64) -> crate::Result<()> {
        self.fd_meta_unit(core::TAG_FTRUNCATE, who, f, len, 0, 0)
    }

    /// Manipulate the open file's allocated blocks (`fallocate`): `mode` is 0 to preallocate, or a `libc::FALLOC_FL_*`
    /// combination (punch hole, zero range, collapse, ...).
    pub fn fallocate(&self, who: Personality, f: &File, mode: i32, off: u64, len: u64) -> crate::Result<()> {
        self.fd_meta_unit(core::TAG_FALLOCATE, who, f, off, len, mode as u32)
    }

    /// Advise the kernel how `len` bytes of `f` from `off` will be used (`posix_fadvise`). `len` of 0 means "to the end
    /// of the file".
    ///
    /// Advisory by definition: it is never an error for the kernel to ignore it, and it changes no file contents. See
    /// [`Advice`] for what each value does on ZFS, where these reach the ARC rather than only the page cache.
    pub fn fadvise(&self, who: Personality, f: &File, off: u64, len: u64, advice: Advice) -> crate::Result<()> {
        self.fd_meta_unit(core::TAG_FADVISE, who, f, off, len, advice as u32)
    }

    /// Move up to `len` bytes from `pipe`'s read end into `f` at `off`, without a userspace buffer
    /// (`IORING_OP_SPLICE`). Returns the number of bytes moved.
    ///
    /// `pipe` is a plain descriptor the caller keeps open across the call. A pipe delivers what it has, so **a returned
    /// count below `len` means resubmit the remainder**, not end of input and not an error. Nothing passes through
    /// userspace, so nothing can hash the bytes in transit.
    pub fn splice_from_pipe(&self, who: Personality, f: &File, pipe: RawFd, off: u64, len: u32) -> crate::Result<u64> {
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

    /// Stat the entry `leaf` inside `anchor`. Does **not** follow a terminal symlink by default (the link itself is
    /// stat'd); pass `AtFlags::AT_SYMLINK_FOLLOW` to stat the target.
    ///
    /// Prefer [`fstatx`](Self::fstatx) on a file already open, since a stat and then an open by name can find two
    /// different files if the name is replaced in between.
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

    /// Stat the anchor directory itself (`AT_EMPTY_PATH` on its dirfd) -- the closest thing to an fd-based statx this
    /// interface can offer.
    pub fn statx_anchor(
        &self,
        who: Personality,
        anchor: &Anchor,
        flags: AtFlags,
        mask: StatxMask,
    ) -> crate::Result<Statx> {
        self.statx_inner(who, anchor, CString::default(), flags | AtFlags::AT_EMPTY_PATH, mask)
    }

    /// Statx an **open file** by its descriptor (`statx(fd, "", AT_EMPTY_PATH)`) - the `fstat` equivalent. No path is
    /// resolved (no name TOCTOU); the metadata is exactly this fd's.
    pub fn fstatx(&self, who: Personality, f: &File, flags: AtFlags, mask: StatxMask) -> crate::Result<Statx> {
        let anchor = Anchor::from_shared(f.fd.clone());
        self.statx_anchor(who, &anchor, flags, mask)
    }

    // ---- directory entries ---------------------------------------------

    /// Create a directory `leaf` inside `anchor`.
    pub fn mkdirat(&self, who: Personality, anchor: &Anchor, leaf: Leaf<'_>, mode: Mode) -> crate::Result<()> {
        self.path_op(core::TAG_MKDIRAT, who, anchor, leaf, None, None, 0, mode.bits())
    }

    /// Remove the file `leaf` from `anchor`.
    pub fn unlinkat(&self, who: Personality, anchor: &Anchor, leaf: Leaf<'_>) -> crate::Result<()> {
        self.path_op(core::TAG_UNLINKAT, who, anchor, leaf, None, None, 0, 0)
    }

    /// Remove the (empty) directory `leaf` from `anchor` - `unlinkat` with `AT_REMOVEDIR`, the only flag the kernel
    /// accepts here.
    pub fn rmdirat(&self, who: Personality, anchor: &Anchor, leaf: Leaf<'_>) -> crate::Result<()> {
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

    /// Rename `old_leaf` in `old` to `new_leaf` in `new` (the anchors may be the same, and must be on one filesystem).
    /// `flags` takes [`RenameFlags`] - `RENAME_NOREPLACE`, `RENAME_EXCHANGE`, ....
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
    /// `target` is link *content*: it is stored verbatim and never resolved at creation, so it is deliberately not a
    /// [`Leaf`] and may be any path. What it resolves to later is decided by whoever follows it -- with the follower's
    /// credentials, not the creator's.
    pub fn symlinkat<P: ?Sized + TnPath>(
        &self,
        who: Personality,
        target: &P,
        anchor: &Anchor,
        leaf: Leaf<'_>,
    ) -> crate::Result<()> {
        let target = target.with_tn_path(|c| c.to_owned())?;
        if target.as_bytes().is_empty() {
            return Err(crate::Error::Validation("symlinkat: empty target".into()));
        }
        // Here the *first* name is the link content and the second is the entry to create, so this cannot go through
        // `path_op`'s leaf-first shape.
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

    /// Create a hard link at `new_leaf` in `new` for the existing entry `old_leaf` in `old`. `flags` may carry
    /// `AT_SYMLINK_FOLLOW` to follow a symlink named by `old_leaf` (default: no-follow); a followed link can name a
    /// target outside `anchor`, bounded by the personality's DAC.
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

    /// Give the already-open `f` a name at `new_leaf` in `new` (`linkat` with `AT_EMPTY_PATH`).
    ///
    /// This is how an `O_TMPFILE` file is published, the commit step of a durable create. Until then a failure leaves
    /// nothing behind, since dropping the [`File`] releases an unnamed inode. `linkat` cannot replace an existing name
    /// (`EEXIST`), so to overwrite, link to a temporary name and then [`renameat`](Self::renameat) over the target.
    ///
    /// # Requirements
    ///
    /// - `f` must have been opened `O_TMPFILE` **without `O_EXCL`**. `O_EXCL` is the "this file can never be linked"
    ///   opt-out, and violating it fails with `ENOENT` rather than anything more descriptive.
    /// - `who` must carry **the same credentials that opened `f`**. The kernel compares the file's open-time `f_cred`
    ///   against the caller's by *pointer*, and io_uring records the personality's credentials on the file at open
    ///   time. Two ids from [`UringFs::register_self`] alias the same credentials and are interchangeable here; two
    ///   *brokered* registrations are not, even for the same user, because each mints fresh credentials. A mismatch
    ///   fails with `ENOENT`, not `EPERM`. In practice: hold one [`Lease`] for the whole create rather than
    ///   re-acquiring between the open and the link.
    ///
    ///   The kernel also accepts [`Caps::DAC_READ_SEARCH`] in place of that match, a broad capability for a narrow
    ///   problem, so prefer the one-[`Lease`] rule.
    pub fn linkat_file(&self, who: Personality, f: &File, new: &Anchor, new_leaf: Leaf<'_>) -> crate::Result<()> {
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

    /// Close the file. This drops the handle's reference-counted fd; the descriptor is closed once the last clone -
    /// this handle plus any op still in flight on it - is dropped, so an in-flight op never races the close and no
    /// explicit ring op is needed. Returns `Result` to sit alongside the fallible ops, but never fails.
    pub fn close(&self, f: File) -> crate::Result<()> {
        drop(f);
        Ok(())
    }

    fn sync(&self, who: Personality, f: &File, datasync: bool, offset: u64, length: u32) -> crate::Result<()> {
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
            // Loop gone: hand the caller's buffers back, as the completion path does - the owned-round-trip contract
            // holds on failure too.
            let bufs = match msg {
                FsInject::Rw { bufs, .. } => bufs,
                _ => Vec::new(),
            };
            return (Err(Errno::ECONNABORTED.into()), bufs);
        }
        match rx.recv() {
            Ok(out) => (out.res.map(|n| n as usize).map_err(Into::into), out.bufs),
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
        name: Option<Cow<'static, CStr>>,
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
    fn fd_meta_unit(&self, tag: u8, who: Personality, f: &File, off: u64, len64: u64, aux32: u32) -> crate::Result<()> {
        self.fd_meta_count(tag, who, f, off, len64, aux32).map(|_| ())
    }

    /// [`fd_meta_unit`](Self::fd_meta_unit) for the ops whose result is a byte count rather than a bare success.
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
        // `map_res` turns every negative result into `Err`, so the `Ok` arm is a non-negative count.
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
                // Default to not following a terminal symlink (see `FsConn::statx`); AT_SYMLINK_FOLLOW opts into the
                // target.
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

    /// A directory-entry op in the common `(anchor, leaf)` [+ destination] shape.
    ///
    /// **`EBUSY` from here has two producers and this path cannot tell them apart.** The reactor answers it when the op
    /// table is full, which is transient, and the kernel answers it from `is_local_mountpoint` in `vfs_rmdir`
    /// (`fs/namei.c:4588`), `vfs_unlink` (`:4715`) and `vfs_rename` (`:5243`), which is permanent for that path. A
    /// nested dataset is a local mountpoint under its parent, so bound the retries, or use the [`FsConn`] facade, where
    /// [`FsDone::was_refused`](core::FsDone::was_refused) tells them apart.
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

    /// Queue an inject and wake the loop. On failure (loop stopping or gone) the un-sent message is handed back as
    /// `Err(msg)` so a caller can recover the owned buffers it moved in; the error is always `ECONNABORTED`.
    // The `Err` is the un-sent message, so its size is the buffers the caller gets back, not an error-path allocation
    // to shrink.
    #[allow(clippy::result_large_err)]
    pub(crate) fn send(&self, msg: FsInject) -> Result<(), FsInject> {
        if self.shared.stop_requested() {
            return Err(msg);
        }
        if let Err(e) = self.tx.send(msg) {
            return Err(e.0); // SendError(msg) - the loop is gone
        }
        self.shared.wake.poke();
        Ok(())
    }

    fn call(&self, msg: FsInject, rx: &mpsc::Receiver<FsOutcome>) -> crate::Result<FsOutcome> {
        self.send(msg).map_err(|_| crate::Error::from(Errno::ECONNABORTED))?;
        rx.recv().map_err(|_| Errno::ECONNABORTED.into())
    }
}
