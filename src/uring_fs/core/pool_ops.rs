use super::*;

impl FsConn<'_> {
    /// Run `job` on a blocking worker thread, then deliver its result to `on_done` **on the reactor thread** with a
    /// fresh owner-scoped [`FsConn`]. The escape hatch for work with no io_uring op (readdir, `fdopendir`, an ioctl).
    /// `on_done` receives a [`thread::Result`], so a panicking job still delivers and the caller's reactor-side state
    /// is released.
    ///
    /// Batch a request's whole blocking metadata tail into one job, such as [`statx`](crate::sync_fs::statx) plus
    /// [`fgetxattr`](crate::sync_fs::xattr::fgetxattr) reads before streaming a body, since a cached metadata syscall
    /// costs less than any round trip.
    ///
    /// The job contract, shared by every derived facility here and [`offload_result`](Self::offload_result), follows.
    ///
    /// - **Jobs take open [`File`]s or descriptors, never names.** The credential-checked step runs first on the ring
    ///   under a personality, and the job then runs at the reactor's **ambient credentials** against the authorized fd
    ///   (see `FsCore::remove_priv_xattr`).
    /// - **Never mutate thread-wide state from a job** (credentials, umask, signal dispositions), as the workers are
    ///   shared with every consumer of the pool.
    /// - **An offload is never cancelled.** `cancel_owned_by` sweeps ring ops only, so the job runs to completion and
    ///   its delivery always fires, possibly for an owner that is gone.
    /// - **The registry and pool queue are uncapped.** Bound in-flight jobs upstream, at the request cap. A failed
    ///   worker spawn runs the job inline on the loop rather than lose it (`SharedPool`).
    /// - **A job runs on an ordinary thread stack.** A panicking job is caught, but an overflowing one is a `SIGSEGV`
    ///   that aborts the process, so bound a job's recursion or keep it on the heap.
    pub fn offload<R, J, F>(&mut self, job: J, on_done: F)
    where
        J: FnOnce() -> R + Send + 'static,
        R: Send + 'static,
        F: FnOnce(thread::Result<R>, &mut FsConn<'_>) + 'static,
    {
        let deliver: OffloadDeliver = Box::new(move |any, conn| {
            // The token pairs this continuation with the job that produced exactly this `thread::Result<R>`, so the
            // downcast cannot mismatch.
            if let Ok(r) = any.downcast::<thread::Result<R>>() {
                on_done(*r, conn);
            }
        });
        let token = self.fs.register_offload(self.owner, deliver);
        let sink = self.fs.completion_sink();
        let wake = Arc::clone(&self.eng.shared);
        self.fs.submit_offload(Box::new(move || {
            // Push and poke unconditionally: an unwind past either one would leave `offload_reg` holding a continuation
            // that never fires.
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(job));
            finish_offload(&sink, &wake.wake, token, Box::new(r));
        }));
    }

    /// Run `job` over `src` on the pool, [`pwritev2_from`]'s twin for CPU work. Where `src` lies inside the delivering
    /// connection's recv-buffer claim the job reads that buffer in place, and anywhere else the bytes are copied.
    /// `on_done` gets the job's [`crate::Result`] on the loop, a panicked job mapped to `EIO` as
    /// [`offload_result`](Self::offload_result) maps it.
    ///
    /// The job holds a share of the same claim a leased write holds, so a window can be written with [`pwritev2_from`]
    /// and digested here from one buffer, which returns to the pool when the last of its writes and jobs is over. The
    /// reactor keeps the share and drops it once the job has returned, so a streaming handler submits both and returns
    /// `Continue`, braking on the count in flight as [`pwritev2_from`] describes.
    ///
    /// The job contract is [`offload`](Self::offload)'s, and the job must treat `src` as immutable.
    ///
    /// [`pwritev2_from`]: Self::pwritev2_from
    pub fn offload_from<T, J, F>(&mut self, src: &[u8], job: J, on_done: F)
    where
        J: FnOnce(&[u8]) -> crate::Result<T> + Send + 'static,
        T: Send + 'static,
        F: FnOnce(crate::Result<T>, &mut FsConn<'_>) + 'static,
    {
        #[cfg(feature = "net-server")]
        if let Some(window) = self.lease_window(src) {
            self.offload_leased(window, job, on_done);
            return;
        }
        let owned = src.to_vec();
        self.offload_result(move || job(&owned), on_done);
    }

    /// Hold `src`'s receive buffer past this delivery, as a share of the buffer's claim spent later on
    /// [`offload_leased`](Self::offload_leased) from any facade, or returned by the drop. `None` where `src` is not in
    /// a pooled receive buffer this delivery claimed, and the caller copies. The bytes stay valid and immutable while
    /// the window lives.
    #[cfg(feature = "net-server")]
    pub fn lease_window(&mut self, src: &[u8]) -> Option<LeasedWindow> {
        let (taken, hold) = self.claim_share(src)?;
        taken.set(true);
        self.lease_hold = Some(std::sync::Arc::downgrade(&hold));
        Some(LeasedWindow {
            view: LeasedBytes {
                ptr: src.as_ptr(),
                len: src.len(),
            },
            hold,
        })
    }

    /// Run `job` over a leased window on the pool, from any facade; the window's share is dropped when the finished
    /// job's completion is taken on the loop, so the pool re-issues the buffer only after the job has returned.
    /// `on_done` fires on the loop with the job's result, as [`offload_result`](Self::offload_result)'s does.
    #[cfg(feature = "net-server")]
    pub fn offload_leased<T, J, F>(&mut self, window: LeasedWindow, job: J, on_done: F)
    where
        J: FnOnce(&[u8]) -> crate::Result<T> + Send + 'static,
        T: Send + 'static,
        F: FnOnce(crate::Result<T>, &mut FsConn<'_>) + 'static,
    {
        let LeasedWindow { view, hold } = window;
        // `view` stays valid and immutable for the job's whole run, as the share registered below is dropped only after
        // the job returns (`take_pool_completions`). The raw parts cross to the worker, since a `&[u8]` borrows the
        // facade's lifetime.
        let deliver: OffloadDeliver = Box::new(move |any, conn| {
            if let Ok(r) = any.downcast::<thread::Result<crate::Result<T>>>() {
                on_done((*r).unwrap_or_else(|_| Err(Errno::EIO.into())), conn);
            }
        });
        let token = self.fs.register_leased_offload(self.owner, deliver, hold);
        let sink = self.fs.completion_sink();
        let wake = Arc::clone(&self.eng.shared);
        self.fs.submit_offload(Box::new(move || {
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| job(view.as_slice())));
            finish_offload(&sink, &wake.wake, token, Box::new(r));
        }));
    }

    /// [`offload`](Self::offload) for a job that already yields a [`crate::Result`], mapping a panicked job to `EIO` so
    /// the continuation keeps its ordinary signature. The shape every derived facility here uses, with
    /// [`offload`](Self::offload)'s job contract. Use `offload` itself only when the continuation must inspect the
    /// panic payload.
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

    /// [`offload_result`](Self::offload_result) on the lookup lane, a second pool of this ring for jobs that wait on
    /// another machine, such as a lookup through the name service switch. The lane has its own bounds
    /// (`ServerConfig::lookup_offload_floor` and `lookup_offload_ceiling`), so a stalled service never takes a thread
    /// from [`offload`](Self::offload).
    ///
    /// The job contract is [`offload`](Self::offload)'s, but a job here never runs on the loop, since it may wait as
    /// long as the service's timeouts allow. When the lane cannot spawn its first thread, and for a second after that
    /// failure, the job is dropped unrun and `on_done` gets `EAGAIN` on the loop. A job that can fail in a way that may
    /// pass should carry its own error inside `T`, since its own `EAGAIN` looks the same.
    pub fn offload_lookup<T, J, F>(&mut self, job: J, on_done: F)
    where
        J: FnOnce() -> crate::Result<T> + Send + 'static,
        T: Send + 'static,
        F: FnOnce(crate::Result<T>, &mut FsConn<'_>) + 'static,
    {
        let deliver: OffloadDeliver = Box::new(move |any, conn| {
            if let Ok(r) = any.downcast::<thread::Result<crate::Result<T>>>() {
                on_done((*r).unwrap_or_else(|_| Err(Errno::EIO.into())), conn);
            }
        });
        let token = self.fs.register_offload(self.owner, deliver);
        let sink = self.fs.completion_sink();
        let wake = Arc::clone(&self.eng.shared);
        let refused = self.fs.submit_lookup(Box::new(move || {
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(job));
            finish_offload(&sink, &wake.wake, token, Box::new(r));
        }));
        if refused.is_err() {
            let r: thread::Result<crate::Result<T>> = Ok(Err(Errno::EAGAIN.into()));
            let wake = &self.eng.shared.wake;
            finish_offload(&self.fs.completions, wake, token, Box::new(r));
        }
    }

    /// Offload a `flistxattr` of `f` to the pool and deliver its attribute names (all namespaces, sorted) on the loop.
    /// The list runs at the reactor's privilege, so it proposes candidates only: a caller relaying to a `who` must read
    /// each value under `who` (via [`fgetxattr`](Self::fgetxattr)) and drop the denials, exactly as the directory
    /// enrichment does.
    pub fn flistxattr<F>(&mut self, f: File, on_done: F)
    where
        F: FnOnce(crate::Result<Vec<CString>>, &mut FsConn<'_>) + 'static,
    {
        self.offload_result(move || super::query_dir::list_xattr_names(&f), on_done);
    }

    /// Filesystem statistics for the mount `f` lives on, delivered on the loop.
    ///
    /// io_uring has no `statfs` opcode, so this takes a pool thread and returns through the completion sink like any
    /// other offload.
    pub fn fstatfs<F>(&mut self, f: File, on_done: F)
    where
        F: FnOnce(crate::Result<Statfs>, &mut FsConn<'_>) + 'static,
    {
        self.offload_result(move || Ok(crate::sync_fs::fstatfs(&*f.fd)?), on_done);
    }

    /// Filesystem statistics for the mount `anchor` lives on - a whole tree's capacity without opening anything inside
    /// it.
    ///
    /// Takes an `O_PATH` descriptor, which most fd-taking calls reject: `fd_statfs` resolves through `f_path` and never
    /// consults `f_op` (`fs/statfs.c`), unlike `fsync` or the ZFS attribute ioctls.
    pub fn fstatfs_anchor<F>(&mut self, anchor: &Anchor, on_done: F)
    where
        F: FnOnce(crate::Result<Statfs>, &mut FsConn<'_>) + 'static,
    {
        let anchor = anchor.clone();
        self.offload_result(move || Ok(crate::sync_fs::fstatfs(&anchor)?), on_done);
    }

    /// Read `f`'s ZFS attributes, delivered on the loop.
    ///
    /// `f` must be opened for real I/O (an `O_PATH` descriptor has no `f_op->unlocked_ioctl`); `ENOTTY` off ZFS. For
    /// `IMMUTABLE`/ `APPENDONLY` alone prefer [`fstatx`](Self::fstatx), which reports both via `statx` with no ioctl
    /// and no pool thread.
    pub fn fget_zfs_attrs<F>(&mut self, f: File, on_done: F)
    where
        F: FnOnce(crate::Result<ZfsAttr>, &mut FsConn<'_>) + 'static,
    {
        self.offload_result(move || Ok(crate::sync_fs::fget_zfs_attrs(&*f.fd)?), on_done);
    }

    /// Replace `f`'s ZFS attributes with `attrs`. **The mask is absolute**, so visible bits absent from `attrs` are
    /// cleared, and a caller modifies what [`fget_zfs_attrs`](Self::fget_zfs_attrs) returned.
    ///
    /// Takes no [`Personality`], since an ioctl is checked against the calling thread's credentials, the reactor's
    /// pool. So the kernel cannot decide whether this caller may lock this file, and something above must.
    /// `ZfsAttr::NOUNLINK` needs only ownership to clear, where `IMMUTABLE` needs `CAP_LINUX_IMMUTABLE`. Setting
    /// `IMMUTABLE` also seals the file's extended attributes (`may_write_xattr`, `fs/xattr.c`), so write them first.
    pub fn fset_zfs_attrs<F>(&mut self, f: File, attrs: ZfsAttr, on_done: F)
    where
        F: FnOnce(crate::Result<()>, &mut FsConn<'_>) + 'static,
    {
        self.offload_result(move || Ok(crate::sync_fs::fset_zfs_attrs(&*f.fd, attrs)?), on_done);
    }

    /// Copy `len` bytes from `src[off_src..]` to `dst[off_dst..]`, delivering the bytes copied. On a pool with ZFS
    /// block cloning the kernel clones where it can (`copy_file_range(2)` is clone-first) and falls back to a byte
    /// copy.
    ///
    /// Offloaded as one job, since with `zfs_bclone_wait_dirty` on, cloning a freshly written source waits a
    /// transaction group. The whole range goes in one call, as a chunk boundary re-enters `zfs_clone_range`, retaking
    /// both rangelocks, and forfeits the clone, since the destination's rangelock is promoted to whole-file only on its
    /// first write, which grows the blocksize to the source's. A short return is re-issued from where it stopped.
    /// [`QueryPool::copy_file_range`](super::query_dir::QueryPool::copy_file_range) is the twin off the loop.
    ///
    /// Takes no [`Personality`], since the kernel authorizes the copy from the two files' open modes.
    pub fn copy_file_range<F>(&mut self, src: File, dst: File, off_src: u64, off_dst: u64, len: u64, on_done: F)
    where
        F: FnOnce(crate::Result<u64>, &mut FsConn<'_>) + 'static,
    {
        self.offload_result(
            move || super::query_dir::copy_range(&src, &dst, off_src, off_dst, len),
            on_done,
        );
    }

    /// Remove a **server-owned** extended attribute from `f` (`fremovexattr`), or `EPERM` if `name` is not one the
    /// reactor's [`PrivilegedXattrs`](crate::uring_fs::PrivilegedXattrs) policy claims. Takes no [`Personality`], so
    /// the allowlist stands in for one (`FsCore::remove_priv_xattr`).
    pub fn fremovexattr<F>(&mut self, f: File, name: impl Into<Cow<'static, CStr>>, on_done: F)
    where
        F: FnOnce(crate::Result<()>, &mut FsConn<'_>) + 'static,
    {
        let name = name.into();
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

    /// Open `anchor` itself readable **under `who`** on the ring (the DAC / list-permission check), then `fdopendir` it
    /// off-loop; deliver the ready [`DirWalk`] to `on_ready` on the reactor thread.
    pub fn open_dir<F>(&mut self, who: Personality, anchor: &Anchor, on_ready: F)
    where
        F: FnOnce(crate::Result<DirWalk>, &mut FsConn<'_>) + 'static,
    {
        let how = OpenHow::new().flags(OFlag::O_RDONLY | OFlag::O_DIRECTORY);
        self.open(who, anchor, c".", how, move |done, conn| {
            match done.file() {
                Some(dir) => conn.offload(
                    move || -> crate::Result<SendDir> {
                        // Worker. Dup the authorized fd and fdopendir the dup, which closedir then owns, as `dir`
                        // closes its own fd as it drops here. The errno is read on this thread, and the dup closed if
                        // fdopendir declines it, as glibc leaves it open.
                        // SAFETY: `dir` is a live fd for the dup; fdopendir takes ownership of the fresh dup.
                        let dup = retry_on_eintr(|| unsafe { libc::dup(dir.as_raw_fd()) })?;
                        let dp = unsafe { libc::fdopendir(dup) };
                        if dp.is_null() {
                            let e = Errno::last();
                            // SAFETY: fdopendir failed, so `dup` is still ours.
                            unsafe { libc::close(dup) };
                            return Err(e.into());
                        }
                        Ok(SendDir(dp))
                    },
                    move |res: thread::Result<crate::Result<SendDir>>, conn| match res {
                        Ok(Ok(sdir)) => on_ready(
                            Ok(DirWalk {
                                inner: Rc::new(RefCell::new(DirWalkInner {
                                    dp: sdir.into_raw(),
                                    in_flight: false,
                                    dropped: false,
                                })),
                            }),
                            conn,
                        ),
                        Ok(Err(e)) => on_ready(Err(e), conn),
                        Err(_) => on_ready(Err(Errno::EIO.into()), conn),
                    },
                ),
                None => {
                    let e = done.result().err().unwrap_or_else(|| Errno::EIO.into());
                    on_ready(Err(e), conn);
                }
            }
        });
    }

    /// Read the next batch of entry names for `walk` off-loop, one job per walk, delivering a [`NameBatch`] to
    /// `on_batch` on the reactor thread.
    ///
    /// Calling again while a batch is still in flight yields `EBUSY` **synchronously** on the calling stack, and every
    /// other outcome arrives later from the pool drain. A batch that fails mid-`readdir` delivers the error and drops
    /// the names already read, since `readdir` cannot rewind, so the walk is restart-recoverable and not resumable.
    pub fn next_batch<F>(&mut self, walk: &DirWalk, on_batch: F)
    where
        F: FnOnce(crate::Result<NameBatch>, &mut FsConn<'_>) + 'static,
    {
        // Take the DIR* out for the worker; mark it in flight so a concurrent Drop defers the close to this batch's
        // delivery.
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
                // Rebind the whole `Send` wrapper, since 2021 disjoint captures would take just its `*mut DIR` field
                // and make the job `!Send`. The same `sdir` goes back, so one `DIR*` never has two wrappers.
                let sdir = sdir;
                let dp = sdir.0;
                let mut names = Vec::with_capacity(DIR_BATCH);
                let mut eod = false;
                let mut err = None;
                while names.len() < DIR_BATCH {
                    Errno::clear();
                    // SAFETY: `dp` is a live DIR*; the returned pointer is valid until the next readdir/closedir,
                    // copied out immediately.
                    let ent = unsafe { libc::readdir(dp) };
                    if ent.is_null() {
                        // NULL is end-of-directory only with errno untouched; a set errno is a failed getdents refill
                        // (EIO on a bad block, ESTALE on NFS, the directory removed underneath) and must surface, not
                        // read back as an empty directory.
                        match Errno::last_raw() {
                            0 => eod = true,
                            _ => err = Some(Errno::last()),
                        }
                        break;
                    }
                    // SAFETY: `ent` is a valid dirent, NUL-terminated d_name;
                    // `addr_of!` avoids forming a `&[c_char; 256]` over a record that may be shorter than the full
                    // array.
                    let name = unsafe {
                        CStr::from_ptr(std::ptr::addr_of!((*ent).d_name).cast::<libc::c_char>())
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
            move |res: thread::Result<(crate::Result<NameBatch>, SendDir)>, conn| {
                // A panicking job unwound its frame, which dropped `SendDir` and closed the DIR* with it: there is no
                // handle to hand back, so `dp` stays null and the walk reads as finished rather than permanently busy.
                let (batch, sdir) = match res {
                    Ok((batch, sdir)) => (batch, Some(sdir)),
                    Err(_) => (Err(Errno::EIO.into()), None),
                };
                let mut b = inner.borrow_mut();
                if b.dropped {
                    // Walk dropped mid-batch: `sdir` drops here, closing the DIR*, and the batch is discarded (the
                    // caller is gone).
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
