use super::*;

impl<'a> FsConn<'a> {
    /// The identity of the connection this facade acts for.
    pub fn conn_token(&self) -> ConnToken {
        ConnToken {
            core: self.fs.core_id,
            owner: self.owner,
        }
    }

    pub(crate) fn new(fs: &'a mut FsCore, eng: &'a mut Engine, owner: Owner) -> FsConn<'a> {
        FsConn {
            fs,
            eng,
            owner,
            #[cfg(feature = "net-server")]
            lease: None,
            #[cfg(feature = "net-server")]
            lease_hold: None,
            fail_sink: None,
            frame_watching: false,
        }
    }

    /// Stage the reason sink whose share the frame's one submission takes ([`armed::arm`]) and mark the frame watching,
    /// answering with what was staged before so the caller can put it back.
    pub(crate) fn stage_fail_sink(&mut self, sink: FailSink) -> StagedSink {
        StagedSink(
            self.fail_sink.replace(sink),
            std::mem::replace(&mut self.frame_watching, true),
        )
    }

    /// Put back what [`FsConn::stage_fail_sink`] displaced, answering whether any submission armed the sink being
    /// retired. `false` means the facade refused the arguments before the op reached the core, so nothing will ever
    /// report for it. Read off the retiring sink's own shared flag, so an arm made through a [`FsConn::reborrow`]
    /// counts.
    pub(crate) fn restore_fail_sink(&mut self, prev: StagedSink) -> bool {
        let armed = std::mem::replace(&mut self.fail_sink, prev.0).is_some_and(|s| s.armed.get());
        self.frame_watching = prev.1;
        armed
    }

    /// Carry a multi-step call's sink onto the fresh facade a later step submits from (see [`FailSink`]). `chain` and
    /// `walk` are the only callers, because they are the only multi-step calls whose later steps reach the core
    /// themselves.
    fn carry_fail_sink(&mut self, sink: Option<FailSink>) {
        self.fail_sink = sink;
    }

    /// Box `on_done` as this connection's owner-stamped embedded waiter, taking a share of the staged reason sink on
    /// the way. **The one shape every submit method here hands the core**, and the only way to build the share
    /// ([`armed`]).
    #[cfg_attr(not(feature = "net-server"), allow(dead_code))]
    fn waiter<F>(&mut self, on_done: F) -> FsWaiter
    where
        F: FnOnce(FsDone, &mut FsConn<'_>) + 'static,
    {
        let on_fail = armed::arm(self);
        FsWaiter::Embedded {
            owner: self.owner,
            cb: Box::new(on_done),
            on_fail,
        }
    }

    /// The facade's parts, reborrowed - what the task layer ([`super::task`]) needs so a poll can hold its task entry
    /// out of the table while the facade it hands the task borrows the tables.
    pub(crate) fn split(&mut self) -> (&mut FsCore, &mut Engine, Owner) {
        (&mut *self.fs, &mut *self.eng, self.owner)
    }

    /// Whether the connection this facade acts for has already been torn down.
    ///
    /// A continuation may run after its owner is gone, and failing ops are the signal a task winds down on. An offload
    /// is never cancelled and a timer armed after the sweep expires normally, so a task built from either would run for
    /// a dead connection, holding a graceful drain open, unless it reads this. Submitting is still allowed, since a
    /// handler finishing work it already accepted is not undone by the peer hanging up.
    ///
    /// Always `false` where the reactor has no owners (a standalone [`UringFs`](super::super::UringFs)).
    pub fn owner_is_gone(&self) -> bool {
        self.fs.owner_is_gone(self.owner)
    }

    /// Whether the loop this facade runs on has been asked to drain gracefully.
    ///
    /// The other half of [`owner_is_gone`](Self::owner_is_gone), which says the connection closed, where this says the
    /// server is going away. Readable only between awaits, so it narrows the drain for looping work (a re-arming tick,
    /// a batch loop) and not for one long await.
    ///
    /// **Never `true` on a standalone [`UringFs`](super::super::UringFs) host**, whose
    /// [`ShutdownHandle`](super::super::ShutdownHandle) stops the loop outright, so a consumer there must not wait for
    /// it. A `true` means wind down, and a drain need not announce itself.
    pub fn draining(&self) -> bool {
        self.eng.shared.graceful_requested().is_some()
    }

    /// A second facade over the same delivery, for a step that dispatches twice (the window exhausting a known-length
    /// stream also carries the End stage). The recv-buffer claim moves into the reborrow - the first dispatch is the
    /// one with the body - so a leased write still happens at most once per delivery.
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
            // Cloned, not taken, since both halves of a two-step dispatch submit and both should report. The arm flag
            // rides the shared sink `Rc`, so an arm made here reaches the outer facade's frame.
            fail_sink: self.fail_sink.clone(),
            frame_watching: self.frame_watching,
        }
    }

    /// Offer the delivering connection's recv-buffer claim for [`pwritev2_from`](FsConn::pwritev2_from) to write from
    /// without copying. Delivery-time only.
    #[cfg(feature = "net-server")]
    pub(crate) fn with_recv_lease(mut self, lease: Option<RecvWriteLease<'a>>) -> FsConn<'a> {
        self.lease = lease;
        self
    }

    /// The delivering connection's claim on the buffer `src` lies in, as a share to hand an op or a job. The hold is
    /// minted on the first taker and cloned for the rest, so the buffer goes back to the pool when the last of them
    /// completes. The facade keeps only a `Weak`, so it never withholds the release. An upgrade cannot fail while this
    /// delivery runs its handler, but if it did the buffer may have been re-issued, so `None` sends the caller to its
    /// copy path.
    #[cfg(feature = "net-server")]
    pub(super) fn claim_share(&self, src: &[u8]) -> Option<(&'a Cell<bool>, std::sync::Arc<LeaseHold>)> {
        let l = self.lease.as_ref()?;
        let base = l.ptr as usize;
        let at = src.as_ptr() as usize;
        let fits = at >= base && at.checked_add(src.len()).is_some_and(|end| end <= base + l.cap);
        if !fits {
            return None;
        }
        let hold = match &self.lease_hold {
            Some(w) => w.upgrade()?,
            None => std::sync::Arc::new(LeaseHold::new(l.bid, self.fs.lease_returns(&self.eng.shared))),
        };
        Some((l.taken, hold))
    }

    /// Open `path` relative to `anchor` as `who`, and fire `on_done` with the new [`File`] ([`FsDone::file`]). `path`
    /// must be anchor-relative, as a leading `/` is refused. Resolution defaults to the full [`CONFINED_RESOLVE`] set
    /// unless `how` states a confinement policy of its own, as [`FsHandle::open`](crate::uring_fs::FsHandle::open)
    /// does, and a `resolve` carrying only hardening flags composes with the default. An invalid argument answers
    /// `on_done` before this returns with `EINVAL` and [`FsDone::was_refused`] true, the same verdict the mid-walk
    /// screens give.
    ///
    /// Every facade may open, a continuation's included, but nothing sweeps a descriptor opened after its connection
    /// closed until the reactor's tables go, so a chain that opens must reach a step that closes.
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
            // Anchor-relative only, deliberately stricter than `FsHandle::open` (`open_parts`), which allows an
            // absolute path when the caller drops `RESOLVE_BENEATH`. Do not unify them.
            return on_done(FsDone::refused(Errno::EINVAL), self);
        }
        let (how, special) = how.into().into_parts();
        // An `Allow` open's mandatory bound; a zero deadline cancels the open it guards, so it is refused on the
        // entry-screen contract like every other shape defect.
        let deadline = match special {
            super::SpecialFiles::Allow { deadline } => {
                if deadline.is_zero() {
                    return on_done(FsDone::refused(Errno::EINVAL), self);
                }
                Some(deadline)
            }
            super::SpecialFiles::Guard => None,
        };
        let mut raw = how.to_raw();
        // Both of `open_parts`' rules, through the same functions, since a request handler reaches this with a path the
        // peer chose. Sharing only one would let a creating open here park on a planted FIFO.
        super::confine_resolve(&mut raw.resolve);
        let guarded = super::apply_special_file_guard(&mut raw, special);
        let w = self.waiter(on_done);
        self.fs.submit_open(
            self.eng,
            who.0,
            anchor.clone(),
            path.to_bytes(),
            raw,
            guarded,
            deadline,
            w,
        );
    }

    /// Open the parent of the directory `anchor` names, as `who`, and fire `on_done` with it ([`FsDone::file`]). It
    /// goes up one level and no further, since it takes no path and opens only `..`.
    ///
    /// [`open`](Self::open) cannot reach a parent, as `RESOLVE_BENEATH` answers `..` at the anchor with `EXDEV`,
    /// `RESOLVE_IN_ROOT` keeps it at the anchor (`follow_dotdot` in `fs/namei.c`), and [`Leaf`] refuses `..`. So this
    /// drops the scope and keeps `RESOLVE_NO_SYMLINKS` and `RESOLVE_NO_XDEV`.
    ///
    /// - The kernel checks only that `who` may search the directory (`may_lookup` in `link_path_walk`), and the parent
    ///   is opened as `how` asks.
    /// - At the top of a mount the open answers `EXDEV` rather than cross (`follow_dotdot`), and with no scope there is
    ///   no rename-race check (`handle_dots`), so `EXDEV` always means the top of a mount.
    /// - The parent comes from the dentry cache (`dget_parent`), so a directory that moved answers its new parent.
    ///
    /// A `how` that creates (`O_CREAT` or `O_TMPFILE`) or states a scope (`RESOLVE_BENEATH` or `RESOLVE_IN_ROOT`) is
    /// refused before this returns, with the marked `EINVAL` that [`open`](Self::open) gives.
    pub fn open_parent<F>(&mut self, who: Personality, anchor: &Anchor, how: OpenHow, on_done: F)
    where
        F: FnOnce(FsDone, &mut FsConn<'_>) + 'static,
    {
        self.open_dotdot(who, anchor, how, false, on_done);
    }

    /// Open the parent of the directory `anchor` names, as `who`, as [`open_parent`](Self::open_parent) does, but at
    /// the top of a mount go on to the parent of the directory the mount covers (`follow_dotdot` and
    /// `choose_mountpoint` in `fs/namei.c`).
    ///
    /// It drops `RESOLVE_NO_XDEV`, so its answer may be on another file system than its anchor. `..` never goes down
    /// into a mount, and a directory moved above the mount answers where it is now. A `how` is refused as for
    /// `open_parent`.
    pub fn open_parent_across_mount<F>(&mut self, who: Personality, anchor: &Anchor, how: OpenHow, on_done: F)
    where
        F: FnOnce(FsDone, &mut FsConn<'_>) + 'static,
    {
        self.open_dotdot(who, anchor, how, true, on_done);
    }

    /// Open `..` of `anchor` as `who` for [`open_parent`](Self::open_parent), and across the top of a mount when
    /// `across`.
    fn open_dotdot<F>(&mut self, who: Personality, anchor: &Anchor, how: OpenHow, across: bool, on_done: F)
    where
        F: FnOnce(FsDone, &mut FsConn<'_>) + 'static,
    {
        use crate::sync_fs::ResolveFlag;
        // `O_TMPFILE` carries `O_DIRECTORY`, so only its other half marks a create, as in `mkdir_path`.
        const TMPFILE_ONLY: i32 = libc::O_TMPFILE & !libc::O_DIRECTORY;
        let mut raw = how.to_raw();
        let creates = raw.flags & (libc::O_CREAT | TMPFILE_ONLY) as u64 != 0;
        if creates || raw.resolve & super::CONFINEMENT_POLICY.bits() != 0 {
            return on_done(FsDone::refused(Errno::EINVAL), self);
        }
        let mut kept = CONFINED_RESOLVE.difference(ResolveFlag::RESOLVE_BENEATH);
        if across {
            kept = kept.difference(ResolveFlag::RESOLVE_NO_XDEV);
        }
        raw.resolve |= kept.bits();
        // `..` is always a directory, so no special file can make the open block, and no guard rides it
        // (`apply_special_file_guard`).
        let w = self.waiter(on_done);
        self.fs
            .submit_open(self.eng, who.0, anchor.clone(), b"..", raw, false, None, w);
    }

    /// Create every missing directory along `path` beneath `anchor` as `who`, then open the deepest one with `how`, a
    /// confined `mkdir -p` on the ring. The reactor twin of
    /// [`FsHandle::mkdir_path`](crate::uring_fs::FsHandle::mkdir_path).
    ///
    /// `how` decides what `on_done` gets, an `O_PATH` handle to anchor against or a directory it can `fsync`.
    /// `O_DIRECTORY` is forced, [`CONFINED_RESOLVE`] is unioned in, and a `how` carrying `O_CREAT` or `O_TMPFILE` is
    /// refused, as either would answer with a file. `EEXIST` is success at every component, so two callers building one
    /// tree both finish.
    ///
    /// An invalid argument answers `on_done` before this returns with a marked `EINVAL`. `path` must name its
    /// components plainly, relative with no `.`, `..` or empty component
    /// ([`path::relative_defect`](crate::path::relative_defect)). `..` is refused even though `openat2` would resolve
    /// it safely, since what `a/..` names depends on what `a` turned out to be.
    ///
    /// `mkdirat` honours no `RESOLVE_*` flags, so it is handed one [`Leaf`] at a time between confined `openat2` opens,
    /// and a consumer never has to get each step's confinement right.
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
        // Judged on shape before anything is submitted, so the probe below cannot admit what the walk would refuse.
        if crate::path::relative_defect(bytes).is_some() {
            return on_done(FsDone::refused(Errno::EINVAL), self);
        }
        // Owned, because each component outlives the completion that consumes it. Every one is a `Leaf` by the check
        // above.
        let parts: VecDeque<CString> = crate::path::components(bytes)
            .map(|p| CString::new(p).expect("no NUL: checked above"))
            .collect();
        let mut raw = how.to_raw();
        // Every open this makes must name a directory, so `O_DIRECTORY` is forced. `O_CREAT` would have the probe
        // create a regular file at the leaf, which the kernel refuses beside `O_DIRECTORY` only at the syscall
        // (`build_open_flags`, `fs/open.c:1278-1284`), after the walk built the tree beneath it. `O_TMPFILE` is
        // `__O_TMPFILE | O_DIRECTORY`, so its test masks the `O_DIRECTORY` half off, and it would answer with an
        // unnamed inode inside the directory.
        const TMPFILE_ONLY: i32 = libc::O_TMPFILE & !libc::O_DIRECTORY;
        let refused = (libc::O_CREAT | TMPFILE_ONLY) as u64;
        if raw.flags & refused != 0 {
            return on_done(FsDone::refused(Errno::EINVAL), self);
        }
        // A scoping conflict would fail `EINVAL` at every component after the earlier ones were created (see
        // `scoping_conflict`).
        if super::scoping_conflict(raw.resolve) {
            return on_done(FsDone::refused(Errno::EINVAL), self);
        }
        raw.flags |= libc::O_DIRECTORY as u64;
        raw.resolve |= CONFINED_RESOLVE.bits();

        let (start, want) = (anchor.clone(), path.to_owned());
        let on_done: WalkDone = Box::new(on_done);
        // Every step after the probe submits from a fresh facade, which carries no sink of its own; see [`FailSink`].
        let sink = self.fail_sink.clone();
        // Every step this makes forces `O_DIRECTORY`, the answer included, so no step can reach a FIFO's own `open`.
        self.open_component(who, start.clone(), want, raw, false, move |res, conn| {
            if res.file().is_some() {
                return on_done(res, conn);
            }
            walk(conn, who, start, parts, mode, raw, on_done, sink);
        });
    }

    /// Open each step relative to the file the step before it opened, and deliver the last.
    ///
    /// **Each step carries its own personality.** That reaches a file inside a tree the caller may not traverse while
    /// the kernel still decides the caller's access to the file itself, since the last step names the caller.
    ///
    /// Every step is confined by [`CONFINED_RESOLVE`], unioned rather than assigned, and every step but the last is
    /// forced `O_DIRECTORY`. A step that creates, or states `RESOLVE_IN_ROOT`, which the kernel refuses to pair with
    /// `RESOLVE_BENEATH`, is refused at entry before anything is submitted. The refusal answers `on_done` with a marked
    /// `EINVAL` before this returns, the same verdict a derived name gets mid-walk.
    pub fn open_chain<F>(&mut self, anchor: &Anchor, steps: Vec<OpenStep>, on_done: F)
    where
        F: FnOnce(FsDone, &mut FsConn<'_>) + 'static,
    {
        // Judged on shape before anything is submitted. A `Derived` step has no path yet, so the walk judges it on the
        // same rule.
        if steps.is_empty() {
            return on_done(FsDone::refused(Errno::EINVAL), self);
        }
        if matches!(steps[0].path, StepPath::Derived(_)) {
            // Nothing has been opened, so there is nothing to derive from.
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
            // A scoping conflict would otherwise make every step `EINVAL`, blaming the kernel for a bit this crate
            // added (see `scoping_conflict`).
            if super::scoping_conflict(step.how.to_raw().resolve) {
                return on_done(FsDone::refused(Errno::EINVAL), self);
            }
        }
        let steps: VecDeque<OpenStep> = steps.into();
        let sink = self.fail_sink.clone();
        chain(self, anchor.clone(), steps, Box::new(on_done), sink);
    }

    /// One step of a walk, opened under its own personality. `guarded` says whether the caller added the special-file
    /// guard to `how`, so the completion strips `O_NONBLOCK` back off. A step that forces `O_DIRECTORY` needs no guard,
    /// since the kernel answers `ENOTDIR` on a FIFO or device before the file's own `open`, but `chain`'s last step can
    /// name anything the anchor holds.
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
        let path = path.to_bytes();
        self.fs
            .submit_open(self.eng, who.0, anchor, path, how, guarded, None, w);
    }

    /// Scattered positional read with per-operation flags (`preadv2(2)`). See [`RwFlags`] - an unsupported flag fails
    /// the read with `EOPNOTSUPP` rather than being ignored.
    #[allow(clippy::too_many_arguments)]
    pub fn preadv2<F>(&mut self, who: Personality, f: File, bufs: Vec<Vec<u8>>, off: u64, flags: RwFlags, on_done: F)
    where
        F: FnOnce(FsDone, &mut FsConn<'_>) + 'static,
    {
        self.rw(TAG_READV, who, f, bufs, off, flags, on_done);
    }

    /// Positional read of up to `count` bytes of `f` at `off` into the room past the length of `buf`, with the flags of
    /// [`preadv2`](Self::preadv2), so nothing is zeroed first. For a caller that reads a file's bytes straight after a
    /// reply's head in one buffer.
    ///
    /// The same `buf` comes back through [`FsDone::into_value`], its length grown by the count read, which is short
    /// only at the end of the file, and unchanged on a failure. A `count` past `buf`'s spare capacity or past
    /// `u32::MAX`, and an `off` of `u64::MAX`, are refused with a marked `EINVAL` ([`FsDone::was_refused`]).
    #[allow(clippy::too_many_arguments)]
    pub fn pread_spare<F>(
        &mut self,
        who: Personality,
        f: File,
        buf: Vec<u8>,
        count: usize,
        off: u64,
        flags: RwFlags,
        on_done: F,
    ) where
        F: FnOnce(FsDone, &mut FsConn<'_>) + 'static,
    {
        let w = self.waiter(on_done);
        self.fs
            .submit_read_spare(self.eng, who.0, f.fd, buf, count, off, flags.bits(), w);
    }

    /// Gathered positional write with per-operation flags (`pwritev2(2)`). [`RwFlags::RWF_DSYNC`] makes the write
    /// itself durable, which can stand in for a following `fdatasync` - worth measuring on ZFS, where a synchronous
    /// write goes through the ZIL.
    #[allow(clippy::too_many_arguments)]
    pub fn pwritev2<F>(&mut self, who: Personality, f: File, bufs: Vec<Vec<u8>>, off: u64, flags: RwFlags, on_done: F)
    where
        F: FnOnce(FsDone, &mut FsConn<'_>) + 'static,
    {
        self.rw(TAG_WRITEV, who, f, bufs, off, flags, on_done);
    }

    /// Write `src`, typically the request's own body, to `f` at `off`, without copying it when it still sits in the
    /// connection's receive buffer.
    ///
    /// When `src` lies inside the delivering connection's pooled claim, the op's iovec points straight at the buffer,
    /// and the pool gets the buffer back when the last write of the delivery completes. Anything else (an unpooled
    /// connection, a placed or owned body, a range outside the claim, or a call from inside a task) falls back to
    /// `pwritev2` on a copy. A body placed in storage of its own is written with no copy by
    /// [`pwritev2_owned`](Self::pwritev2_owned). A full op table refuses the write with a marked `EBUSY`
    /// ([`FsDone::was_refused`]) and hands nothing back, as the bytes were the delivery's.
    ///
    /// **A short leased write answers `Err(EIO)`, never `Ok(n)`.** ZFS returns a partial write as a success
    /// (`zfs_write`), and by then this completion has returned the source buffer to the pool, so a retry would write
    /// another connection's bytes. The count comes beside the `EIO` through [`FsDone::short_count`], for a caller that
    /// answers it rather than retrying. The copy path stays retryable, since [`FsDone::into_bufs`] hands the source
    /// back. The `EIO` carries no cause, since ZFS and io_uring (`io_fixup_rw_res`, `io_uring/rw.c:563-574`) both fold
    /// a post-progress errno into the count, and the next write to the file shows it.
    ///
    /// # Pipelined ingest
    ///
    /// The lease outlives the delivery's verdict, so a streaming handler submits the write and returns
    /// [`Continue`](crate::http::HttpVerdict::Continue), and the next window is read while this one's DMA runs. The
    /// handler is the depth brake. It tracks writes in flight and at its cap parks with
    /// [`defer_stream`](crate::http::HttpRequest::defer_stream), resuming from a completion, as stopping the reads is
    /// the whole mechanism. Keep the cap within `ServerConfig::recv_lease_depth` and size `fs_ops` to cover `pool_size`
    /// x depth. At `Stage::End`, wait for the outstanding completions with a plain
    /// [`defer`](crate::http::HttpRequest::defer) and answer from the last one.
    pub fn pwritev2_from<F>(&mut self, who: Personality, f: File, src: &[u8], off: u64, flags: RwFlags, on_done: F)
    where
        F: FnOnce(FsDone, &mut FsConn<'_>) + 'static,
    {
        #[cfg(feature = "net-server")]
        {
            let leased = match &self.lease {
                Some(l) => {
                    let base = l.ptr as usize;
                    let at = src.as_ptr() as usize;
                    let fits = at >= base && at.checked_add(src.len()).is_some_and(|end| end <= base + l.cap);
                    fits.then_some((l.bid, l.taken))
                }
                _ => None,
            };
            // Shares the claim as `claim_share` does, and a failed upgrade falls to the copy path.
            let minted = self.lease_hold.is_none();
            let hold = leased.and_then(|(bid, _)| match &self.lease_hold {
                Some(w) => w.upgrade(),
                None => Some(std::sync::Arc::new(LeaseHold::new(
                    bid,
                    self.fs.lease_returns(&self.eng.shared),
                ))),
            });
            if let (Some((_, taken)), Some(hold)) = (leased, hold) {
                let window = LeasedWindow {
                    view: LeasedBytes {
                        ptr: src.as_ptr(),
                        len: src.len(),
                    },
                    hold: std::sync::Arc::clone(&hold),
                };
                let w = self.waiter(on_done);
                // An array of one, so the write takes no outer `Vec`.
                match self.fs.submit_pwritev2_gathered(
                    self.eng,
                    who.0,
                    Arc::clone(&f.fd),
                    [window],
                    off,
                    flags.bits(),
                    w,
                ) {
                    Ok(()) => {
                        taken.set(true);
                        self.lease_hold = Some(std::sync::Arc::downgrade(&hold));
                    }
                    Err((window, w)) => {
                        drop(window);
                        // A hold this call minted is the only share of a claim the connection still releases at
                        // consume: disarm it, or its drop returns the buffer twice. An upgraded hold's claim was
                        // already taken, so dropping it is its release.
                        if minted && let Some(hold) = std::sync::Arc::into_inner(hold) {
                            let _ = hold.into_bid();
                        }
                        self.fs.refuse(self.eng, w, Errno::EBUSY, true, Vec::new(), Some(f.fd));
                    }
                }
                return;
            }
        }
        self.pwritev2(who, f, vec![src.to_vec()], off, flags, on_done);
    }

    /// Write `buf[range]` to `f` at `off` with the flags of [`pwritev2`](Self::pwritev2), from `buf` itself, so a body
    /// the reactor placed in storage of its own ([`Body::take_owned`](crate::net::core::Body::take_owned)) is written
    /// with no copy, iovec or outer `Vec`.
    ///
    /// The same `buf` comes back through [`FsDone::into_value`] whatever the outcome, for the caller to keep or give
    /// back to the ring's body pool ([`BodyRecycler::recycle`](crate::net::core::BodyRecycler::recycle)). So a short
    /// write, which ZFS returns as a success (`zfs_write`), answers `Ok(n)`, and the caller may write the rest from the
    /// same bytes. A `range` that `buf.get` does not take, a count past `u32::MAX`, and an `off` of `u64::MAX` are
    /// refused with a marked `EINVAL`, and a full op table refuses with a marked `EBUSY` ([`FsDone::was_refused`]).
    #[allow(clippy::too_many_arguments)]
    pub fn pwritev2_owned<F>(
        &mut self,
        who: Personality,
        f: File,
        buf: Vec<u8>,
        range: Range<usize>,
        off: u64,
        flags: RwFlags,
        on_done: F,
    ) where
        F: FnOnce(FsDone, &mut FsConn<'_>) + 'static,
    {
        let w = self.waiter(on_done);
        self.fs
            .submit_write_owned(self.eng, who.0, f.fd, buf, range, off, flags.bits(), w);
    }

    /// Write windows held with [`lease_window`](Self::lease_window) to `f` at `off` as one gathered write, in order,
    /// none copied. Windows cut at a record boundary ([`LeasedWindow::split_at`]) fill a ZFS record whole, skipping the
    /// zero-fill of a partial record and the regrowth copy of a one-block file (`zfs_grow_blocksize`).
    ///
    /// Each buffer returns to the pool when its last share goes. A short write fails the op with `EIO` and gives its
    /// count through [`FsDone::short_count`], as [`pwritev2_from`](Self::pwritev2_from)'s does.
    ///
    /// A full op table refuses the write with a marked `EBUSY` ([`FsDone::was_refused`]), its buffers going back as the
    /// windows drop. A gather one `WRITEV` cannot carry is written from a copy ([`pwritev2`](Self::pwritev2)), which
    /// reports a short write as `Ok(n)` with the copy in [`FsDone::into_bufs`], so check the count.
    #[cfg(feature = "net-server")]
    pub fn pwritev2_leased<F>(
        &mut self,
        who: Personality,
        f: File,
        windows: Vec<LeasedWindow>,
        off: u64,
        flags: RwFlags,
        on_done: F,
    ) where
        F: FnOnce(FsDone, &mut FsConn<'_>) + 'static,
    {
        self.write_windows(who, f, windows, off, flags, on_done);
    }

    /// Write one window held with [`lease_window`](Self::lease_window) to `f` at `off`, as
    /// [`pwritev2_leased`](Self::pwritev2_leased) writes a gather, from any facade on the ring that leased it, a later
    /// callback's included, with no outer `Vec` and no iovec. So a consumer that keeps a request across a pause writes
    /// a range of it with no copy, cut out with [`LeasedWindow::split_at`].
    ///
    /// The buffer returns to the pool when the window's last share goes. A short write fails the op with `EIO` and
    /// gives its count through [`FsDone::short_count`], and a full op table refuses the write with a marked `EBUSY`
    /// ([`FsDone::was_refused`]), the buffer going back as the window drops.
    #[cfg(feature = "net-server")]
    pub fn pwritev2_window<F>(
        &mut self,
        who: Personality,
        f: File,
        window: LeasedWindow,
        off: u64,
        flags: RwFlags,
        on_done: F,
    ) where
        F: FnOnce(FsDone, &mut FsConn<'_>) + 'static,
    {
        self.write_windows(who, f, [window], off, flags, on_done);
    }

    /// The write of [`pwritev2_leased`](Self::pwritev2_leased) and [`pwritev2_window`](Self::pwritev2_window), for a
    /// `Vec` of windows or an array of one.
    #[cfg(feature = "net-server")]
    fn write_windows<W, F>(&mut self, who: Personality, f: File, windows: W, off: u64, flags: RwFlags, on_done: F)
    where
        W: AsRef<[LeasedWindow]> + IntoIterator<Item = LeasedWindow>,
        F: FnOnce(FsDone, &mut FsConn<'_>) + 'static,
    {
        let held = windows.as_ref();
        let total = held.iter().map(LeasedWindow::len).sum();
        if gather_fits(held.len(), total) {
            let w = self.waiter(on_done);
            self.fs
                .submit_leased_or_refuse(self.eng, who.0, Arc::clone(&f.fd), windows, off, flags.bits(), w);
            return;
        }
        // Too many windows or bytes for one `WRITEV`: one copy instead, and the shares go back as the windows drop.
        let mut copy = Vec::with_capacity(total);
        for window in windows.as_ref() {
            copy.extend_from_slice(window);
        }
        drop(windows);
        self.pwritev2(who, f, vec![copy], off, flags, on_done);
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

    /// Fire `on_done` after `after`, one relative, one-shot `IORING_OP_TIMEOUT` on this ring, delivered as `Ok(0)` when
    /// it expires. No fd or personality rides it, so this is the retry-tick and deadline primitive, re-armed rather
    /// than sleeping an offload worker. An owner gone before expiry drops the callback, like any continuation's.
    ///
    /// **A timer holds its op slot for its whole wall-clock duration**, where a read holds one only until its I/O
    /// completes, so retract a deadline reached early with the returned [`Timer`].
    ///
    /// `None` means the arm was refused (a full table, the per-owner cap, a staging failure, or an owner the teardown
    /// sweep has passed) and no timer exists to retract. The refusal still reaches `on_done` at the next wake drain, as
    /// the marked `EBUSY` a full table answers ([`FsDone::was_refused`]), worth retrying once a hold ends, or for a
    /// swept owner as the unmarked `ECANCELED` of the sweep.
    #[must_use = "None means no timer exists to retract - the arm was \
                  refused and `on_done` will deliver the verdict at \
                  the next drain; a discarded Some forfeits the \
                  retraction and rides the full wall-clock hold"]
    pub fn timeout<F>(&mut self, after: std::time::Duration, on_done: F) -> Option<Timer>
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

    /// Retract a timer armed by [`timeout`](Self::timeout), ending its wall-clock hold ahead of its expiry.
    ///
    /// The owner's cap headroom returns here, so retracting one deadline and arming its replacement in the same
    /// delivery holds at any cap. The op slot follows at the retracted timer's CQE, so an owner mid-swap holds up to
    /// twice its cap in slots, and the arm screen refuses past that.
    ///
    /// The timer completes `ECANCELED` with [`FsDone::was_refused`] true and `on_done` fires with it, one answer per
    /// arm, since an unmarked `ECANCELED` means the reactor is going away. That holds even when the timer fired first,
    /// as a retracted timer's `-ETIME` is delivered as the marked cancellation and never as `Ok(0)`.
    ///
    /// Idempotent. The token is checked against the table first, so a [`Timer`] whose op already answered, one from a
    /// different reactor, or one already retracted retracts nothing.
    pub fn cancel_timeout(&mut self, timer: Timer) {
        self.fs
            .retract_timeout(self.eng, timer.core, timer.slot, timer.generation);
    }

    /// Flush the byte range `[offset, offset + length)` of `f` as `who` (`datasync` selects `fdatasync` semantics);
    /// `offset == 0 && length == 0` syncs the whole file. `length` is the SQE's 32-bit field.
    pub fn fsync_range<F>(&mut self, who: Personality, f: File, datasync: bool, offset: u64, length: u32, on_done: F)
    where
        F: FnOnce(FsDone, &mut FsConn<'_>) + 'static,
    {
        let w = self.waiter(on_done);
        self.fs.submit_fsync(self.eng, who.0, f.fd, datasync, offset, length, w);
    }

    /// Stat the entry `leaf` inside `anchor` as `who` (no terminal-symlink follow by default; opt in with
    /// `AT_SYMLINK_FOLLOW`).
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
            leaf.as_bytes(),
            None,
            None,
            statx_at_flags(flags),
            mask.bits(),
            w,
        );
    }

    /// Stat the anchor directory itself (`AT_EMPTY_PATH` on its dirfd).
    pub fn statx_anchor<F>(&mut self, who: Personality, anchor: &Anchor, flags: AtFlags, mask: StatxMask, on_done: F)
    where
        F: FnOnce(FsDone, &mut FsConn<'_>) + 'static,
    {
        let w = self.waiter(on_done);
        self.fs.submit_path_op(
            self.eng,
            TAG_STATX,
            who.0,
            anchor.clone(),
            b"",
            None,
            None,
            statx_at_flags(flags | AtFlags::AT_EMPTY_PATH),
            mask.bits(),
            w,
        );
    }

    /// Stat the open file `f` itself (`AT_EMPTY_PATH` on its fd) as `who`, the on-loop twin of
    /// [`FsHandle::fstatx`](super::super::FsHandle::fstatx).
    pub fn fstatx<F>(&mut self, who: Personality, f: &File, flags: AtFlags, mask: StatxMask, on_done: F)
    where
        F: FnOnce(FsDone, &mut FsConn<'_>) + 'static,
    {
        let anchor = Anchor::from_shared(f.fd.clone());
        self.statx_anchor(who, &anchor, flags, mask, on_done);
    }

    /// Read extended attribute `name` from `f` into `buf` as `who`. Needs Linux >= 6.13; fails closed (`EOPNOTSUPP`)
    /// otherwise.
    pub fn fgetxattr<F>(
        &mut self,
        who: Personality,
        f: File,
        name: impl Into<Cow<'static, CStr>>,
        buf: Vec<u8>,
        on_done: F,
    ) where
        F: FnOnce(FsDone, &mut FsConn<'_>) + 'static,
    {
        self.fd_meta(TAG_FGETXATTR, who, f, Some(name.into()), buf, 0, 0, 0, on_done);
    }

    /// Read extended attribute `name` of `f` into `buf` as `who`, through the path of `f` under `/proc/thread-self/fd`,
    /// so `f` may be opened `O_PATH`, which [`fgetxattr`](Self::fgetxattr) refuses with `EBADF`.
    ///
    /// The kernel resolves the path as `who`, and the file system checks `who` as it does for `fgetxattr`. The last
    /// step jumps to `f` itself (`proc_pid_get_link` in `fs/proc/base.c`), so a link opened `O_PATH` with `O_NOFOLLOW`
    /// is read rather than its target, and a FIFO is read without an open. It needs `/proc` mounted in the process's
    /// root. A read brings the whole value back and leaves the check to the file system, so nothing is dropped, which
    /// is why it may go through `/proc` where no write does.
    pub fn fgetxattr_proc<F>(
        &mut self,
        who: Personality,
        f: File,
        name: impl Into<Cow<'static, CStr>>,
        buf: Vec<u8>,
        on_done: F,
    ) where
        F: FnOnce(FsDone, &mut FsConn<'_>) + 'static,
    {
        self.fd_meta(TAG_GETXATTR_PROC, who, f, Some(name.into()), buf, 0, 0, 0, on_done);
    }

    /// Read extended attribute `name` from `f` under the reactor's **ambient root**, with no `who`, for a `trusted.*`
    /// or `security.*` attribute a request's own identity cannot see. `sqe.personality`, not the fd's open-time cred,
    /// governs the `CAP_SYS_ADMIN` check, and `personality = 0` runs as the ring owner. Needs Linux >= 6.13, and fails
    /// closed (`EOPNOTSUPP`) otherwise.
    pub fn fgetxattr_as_root<F>(&mut self, f: File, name: impl Into<Cow<'static, CStr>>, buf: Vec<u8>, on_done: F)
    where
        F: FnOnce(FsDone, &mut FsConn<'_>) + 'static,
    {
        let w = self.waiter(on_done);
        self.fs
            .submit_fgetxattr_as_root(self.eng, f.fd, name.into(), buf, false, w);
    }

    /// Read extended attribute `name` of `f` under the reactor's **ambient root**, through the path of `f` under
    /// `/proc/thread-self/fd`, so `f` may be opened `O_PATH`, which [`fgetxattr_as_root`](Self::fgetxattr_as_root)
    /// refuses with `EBADF`. The path resolves as the ring owner and the file system checks the ring owner, as
    /// [`fgetxattr_proc`](Self::fgetxattr_proc) says of `who`, so a value the file's own entries hide from a request
    /// identity comes back. For metadata a server checks itself and never hands to a request, such as an ACL it answers
    /// an access check from on behalf of a caller the ACL refuses READ_ACL. It needs `/proc` mounted in the process's
    /// root.
    pub fn fgetxattr_proc_as_root<F>(&mut self, f: File, name: impl Into<Cow<'static, CStr>>, buf: Vec<u8>, on_done: F)
    where
        F: FnOnce(FsDone, &mut FsConn<'_>) + 'static,
    {
        let w = self.waiter(on_done);
        self.fs
            .submit_fgetxattr_as_root(self.eng, f.fd, name.into(), buf, true, w);
    }

    /// Open `f` again with `access` as `who`, through the path of `f` under `/proc/thread-self/fd`, and fire `on_done`
    /// with the new [`File`] ([`FsDone::file`]). `f` may be opened `O_PATH`.
    ///
    /// The link jumps to `f` itself (`proc_pid_get_link` in `fs/proc/base.c`), and the open checks `who` against the
    /// file as an open by name does (`may_open` in `fs/namei.c`), its ACL included, and carries nothing around the
    /// check, so nothing is dropped. It skips the walk, so a folder above `f` that `who` may not search does not refuse
    /// it. A link held `O_PATH` with `O_NOFOLLOW` answers `ELOOP`, and a FIFO answers at once rather than wait for a
    /// peer. It runs on an io-wq worker and needs `/proc` mounted in the process's root.
    pub fn reopen_proc<F>(&mut self, who: Personality, f: File, access: ReopenAccess, on_done: F)
    where
        F: FnOnce(FsDone, &mut FsConn<'_>) + 'static,
    {
        let w = self.waiter(on_done);
        self.fs.submit_reopen_proc(self.eng, who.0, f.fd, access, w);
    }

    /// Open `f` again with `access` under the reactor's **ambient root**, as [`reopen_proc`](Self::reopen_proc) opens
    /// it as `who`. The ring owner's capabilities pass the check of the file, so this is for an access a server has
    /// already decided a request may have, such as the access left after it lowers what an open may do, never for
    /// deciding it.
    pub fn reopen_proc_as_root<F>(&mut self, f: File, access: ReopenAccess, on_done: F)
    where
        F: FnOnce(FsDone, &mut FsConn<'_>) + 'static,
    {
        let w = self.waiter(on_done);
        self.fs.submit_reopen_proc_as_root(self.eng, f.fd, access, w);
    }

    /// Take a read lease on `file`, a descriptor open for reading, and give back what names it. A break of it reaches
    /// the handler the host was given, once, as [`file_lease`](super::file_lease) says, and the lease lasts until
    /// [`FsConn::release_file_lease`] gives it back. The ring keeps a clone of `file` until then.
    ///
    /// A plain `fcntl(2)` on the ring's thread, which never blocks. It is `EAGAIN` while anyone holds the file open for
    /// writing, `EACCES` for a file the ring does not own without `CAP_LEASE` (`vfs_setlease` in `fs/locks.c`), `EBUSY`
    /// for a descriptor that already holds one of the ring's leases, and `EINVAL` where no handler was given or the
    /// ring's thread has not blocked the signals a break comes as
    /// ([`file_lease::block_signals`](super::file_lease::block_signals)), since a break would then go unheard or end
    /// the process.
    pub fn file_lease(&mut self, file: &File) -> crate::Result<super::file_lease::FileLeaseId> {
        self.fs.file_leases.take(self.eng, &file.fd)
    }

    /// Give back the lease `id`, which lets anyone waiting on its break go on at once, and drop the ring's clone of its
    /// descriptor. A lease the kernel dropped since its break is given back all the same. `ENOENT` for one the ring
    /// does not hold.
    pub fn release_file_lease(&mut self, id: super::file_lease::FileLeaseId) -> crate::Result<()> {
        self.fs.file_leases.release(id)
    }

    /// Write extended attribute `name` on `f` as `who`.
    pub fn fsetxattr<F>(
        &mut self,
        who: Personality,
        f: File,
        name: impl Into<Cow<'static, CStr>>,
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
            Some(name.into()),
            value,
            0,
            0,
            flags as u32,
            on_done,
        );
    }

    /// Set what `set` names on `f` as `who`, in one `FSETXATTR` of [`ZFS_SETATTR`], so the kernel's checks run as
    /// `who`.
    ///
    /// [`ZfsSetattr`] says which checks apply, and a ZFS without the handler answers `EOPNOTSUPP`.
    pub fn fset_attrs<F>(&mut self, who: Personality, f: File, set: &ZfsSetattr, on_done: F)
    where
        F: FnOnce(FsDone, &mut FsConn<'_>) + 'static,
    {
        self.fsetxattr(who, f, ZFS_SETATTR, set.to_bytes(), 0, on_done);
    }

    /// Set `f`'s length to `len` (`ftruncate`). Needs Linux >= 6.9.
    pub fn ftruncate<F>(&mut self, who: Personality, f: File, len: u64, on_done: F)
    where
        F: FnOnce(FsDone, &mut FsConn<'_>) + 'static,
    {
        self.fd_meta(TAG_FTRUNCATE, who, f, None, Vec::new(), len, 0, 0, on_done);
    }

    /// Manipulate `f`'s allocated blocks (`fallocate`): `mode` is 0 or a `FALLOC_FL_*` combination.
    pub fn fallocate<F>(&mut self, who: Personality, f: File, mode: i32, off: u64, len: u64, on_done: F)
    where
        F: FnOnce(FsDone, &mut FsConn<'_>) + 'static,
    {
        self.fd_meta(TAG_FALLOCATE, who, f, None, Vec::new(), off, len, mode as u32, on_done);
    }

    /// Advise the kernel how a range of `f` will be used (`posix_fadvise`);
    /// `len` of 0 means to the end of the file. See [`Advice`](crate::uring_fs::Advice) - on ZFS these reach the ARC,
    /// not just the page cache.
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
        self.fd_meta(TAG_FADVISE, who, f, None, Vec::new(), off, len, advice as u32, on_done);
    }

    /// Move up to `len` bytes from `pipe`'s read end into `f` at `off`, without a userspace buffer
    /// (`IORING_OP_SPLICE`).
    ///
    /// The ingest half of a zero-copy body path. `pipe` is a plain descriptor the caller keeps open until the
    /// completion fires. Splice cannot hash what it moves, so a body that needs an ETag has to be read conventionally.
    ///
    /// # Short moves are normal
    ///
    /// A pipe delivers what it has, so a completion carrying fewer than `len` bytes is progress, not end of input, and
    /// the caller resubmits the remainder. [`FsDone::result`] is the byte count either way, since the kernel's
    /// `req_set_fail` on a short move (`io_splice`, `io_uring/splice.c`) governs only an `IOSQE_IO_LINK` chain, which
    /// this does not use.
    pub fn splice_from_pipe<F>(&mut self, who: Personality, f: File, pipe: RawFd, off: u64, len: u32, on_done: F)
    where
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
    pub fn mkdirat<F>(&mut self, who: Personality, anchor: &Anchor, leaf: Leaf<'_>, mode: Mode, on_done: F)
    where
        F: FnOnce(FsDone, &mut FsConn<'_>) + 'static,
    {
        self.path_op(
            TAG_MKDIRAT,
            who,
            anchor,
            leaf.as_bytes(),
            None,
            None,
            0,
            mode.bits(),
            on_done,
        );
    }

    /// Remove file `leaf` from `anchor` as `who`.
    pub fn unlinkat<F>(&mut self, who: Personality, anchor: &Anchor, leaf: Leaf<'_>, on_done: F)
    where
        F: FnOnce(FsDone, &mut FsConn<'_>) + 'static,
    {
        self.path_op(TAG_UNLINKAT, who, anchor, leaf.as_bytes(), None, None, 0, 0, on_done);
    }

    /// Remove empty directory `leaf` from `anchor` as `who` (`AT_REMOVEDIR`).
    pub fn rmdirat<F>(&mut self, who: Personality, anchor: &Anchor, leaf: Leaf<'_>, on_done: F)
    where
        F: FnOnce(FsDone, &mut FsConn<'_>) + 'static,
    {
        self.path_op(
            TAG_UNLINKAT,
            who,
            anchor,
            leaf.as_bytes(),
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
            old_leaf.as_bytes(),
            Some(new),
            Some(new_leaf.to_cstring()),
            flags.bits(),
            0,
            on_done,
        );
    }

    /// Create a symlink `leaf` in `anchor` pointing at `target` as `who` (`target` is link content, stored verbatim).
    /// An empty target is refused.
    pub fn symlinkat<F>(&mut self, who: Personality, target: &CStr, anchor: &Anchor, leaf: Leaf<'_>, on_done: F)
    where
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
            target.to_bytes(),
            None,
            Some(leaf.to_cstring()),
            0,
            0,
            w,
        );
    }

    /// Create a hard link at `new_leaf` in `new` for `old_leaf` in `old`.
    ///
    /// **A [`Leaf`] bounds the name, not what the name resolves to.** With `AT_SYMLINK_FOLLOW` in `flags`, a
    /// one-component symlink a peer planted inside `old` makes the new name a second name for an inode outside it. The
    /// kernel offers no confinement for this, as `may_linkat` (`fs/namei.c`) decides which inode may be linked and
    /// never where the link lands. Pass `AtFlags::empty()` unless nothing else can write the source tree, or open the
    /// source under `RESOLVE_NO_SYMLINKS` and publish it with [`linkat_file`](Self::linkat_file).
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
            old_leaf.as_bytes(),
            Some(new),
            Some(new_leaf.to_cstring()),
            flags.bits() as u32,
            0,
            on_done,
        );
    }

    /// Give the already-open `f` a name at `new_leaf` in `new` (`linkat` with `AT_EMPTY_PATH`) - the publish step for
    /// an `O_TMPFILE` create. See [`FsHandle::linkat_file`](crate::uring_fs::FsHandle::linkat_file) for the two kernel
    /// requirements (`O_TMPFILE` without `O_EXCL`, and the *same* personality that opened `f`), both of which fail as
    /// `ENOENT`.
    pub fn linkat_file<F>(&mut self, who: Personality, f: File, new: &Anchor, new_leaf: Leaf<'_>, on_done: F)
    where
        F: FnOnce(FsDone, &mut FsConn<'_>) + 'static,
    {
        let w = self.waiter(on_done);
        self.fs
            .submit_linkat_file(self.eng, who.0, f.fd, new.clone(), new_leaf.to_cstring(), w);
    }

    /// Close `f`: drop the handle. Its fd closes once the last reference (this handle plus any op still parking a
    /// clone) drops - close-last by ownership. Fire-and-forget; there is no completion callback.
    pub fn close(&mut self, f: File) {
        drop(f);
    }

    // ---- private submit helpers ----------------------------------------

    #[allow(clippy::too_many_arguments)]
    fn rw<F>(&mut self, tag: u8, who: Personality, f: File, bufs: Vec<Vec<u8>>, off: u64, rw_flags: RwFlags, on_done: F)
    where
        F: FnOnce(FsDone, &mut FsConn<'_>) + 'static,
    {
        let w = self.waiter(on_done);
        self.fs
            .submit_rw(self.eng, tag, who.0, f.fd, bufs, off, rw_flags.bits(), w);
    }

    #[allow(clippy::too_many_arguments)]
    fn fd_meta<F>(
        &mut self,
        tag: u8,
        who: Personality,
        f: File,
        name: Option<Cow<'static, CStr>>,
        value: Vec<u8>,
        off: u64,
        len64: u64,
        aux32: u32,
        on_done: F,
    ) where
        F: FnOnce(FsDone, &mut FsConn<'_>) + 'static,
    {
        let w = self.waiter(on_done);
        self.fs
            .submit_fd_meta(self.eng, tag, who.0, f.fd, name, value, off, len64, aux32, w);
    }

    #[allow(clippy::too_many_arguments)]
    fn path_op<F>(
        &mut self,
        tag: u8,
        who: Personality,
        a1: &Anchor,
        n1: &[u8],
        a2: Option<&Anchor>,
        n2: Option<CString>,
        flags: u32,
        len_arg: u32,
        on_done: F,
    ) where
        F: FnOnce(FsDone, &mut FsConn<'_>) + 'static,
    {
        let w = self.waiter(on_done);
        self.fs
            .submit_path_op(self.eng, tag, who.0, a1.clone(), n1, a2.cloned(), n2, flags, len_arg, w);
    }
}

/// The creation flags no step of a chain may carry. `O_CREAT` and `O_TMPFILE` both make an inode, which a later failing
/// step would leave behind. `O_TMPFILE` is `__O_TMPFILE | O_DIRECTORY`, so its test masks the `O_DIRECTORY` half off.
fn creation_refused(flags: u64) -> bool {
    const TMPFILE_ONLY: i32 = libc::O_TMPFILE & !libc::O_DIRECTORY;
    flags & ((libc::O_CREAT | TMPFILE_ONLY) as u64) != 0
}

/// One step: name it, open it under its own personality, and recurse on what is left.
///
/// `cur` is the deepest file reached so far, and the last step's open is the answer.
fn chain(conn: &mut FsConn<'_>, cur: Anchor, mut steps: VecDeque<OpenStep>, on_done: WalkDone, sink: Option<FailSink>) {
    let Some(step) = steps.pop_front() else {
        // Entry validated a non-empty list. Answered rather than dropped: a dropped callback closes the connection.
        return on_done(FsDone::refused(Errno::EINVAL), conn);
    };
    let last = steps.is_empty();
    let mut raw = step.how.to_raw();
    raw.resolve |= CONFINED_RESOLVE.bits();
    // Only the answer is opened as the caller asked, and everything above it is a directory, so only the answer is
    // guarded. An intermediate carries `O_DIRECTORY`, so the kernel answers `ENOTDIR` on a special file before its own
    // `open`. A FIFO named as the answer with a forcing flag (`O_TRUNC`, which `io_openat_force_async` punts to io-wq,
    // `io_uring/openclose.c`) would park a worker in `wait_for_partner` indefinitely. There is no `SpecialFiles`
    // opt-out here, since a step names a path in a directory the caller may not own. To open a FIFO, use `FsConn::open`
    // with `SpecialFiles::Allow`.
    let guarded = if last {
        super::apply_special_file_guard(&mut raw, super::SpecialFiles::Guard)
    } else {
        raw.flags |= libc::O_DIRECTORY as u64;
        false
    };
    let who = step.who;
    // A derived name is produced here, from the file the previous step opened, and screened on the same rule entry
    // applied to the rest.
    let path = match step.path {
        StepPath::Fixed(path) => path,
        StepPath::Derived(name) => match name(&cur) {
            Ok(path) if crate::path::relative_defect(path.to_bytes()).is_none() => path,
            Ok(_) => return on_done(FsDone::refused(Errno::EINVAL), conn),
            // Forwarded, not refused: the errno is the caller's own closure's, and marking it would have this crate
            // claim a verdict it did not reach.
            Err(crate::Error::Errno(e)) => {
                return on_done(FsDone::failed(e), conn);
            }
            Err(_) => return on_done(FsDone::refused(Errno::EINVAL), conn),
        },
    };
    // Carried onto every step's facade, since a later step submits from the fresh `FsConn` a completion is handed,
    // which has no sink, and a transient `EBUSY` mid-chain would reach the caller as teardown.
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
/// `cur` is the deepest directory reached so far, and the last component's open is the answer.
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
        // Entry validated a non-empty list. Answered rather than dropped: a dropped callback closes the connection.
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
            // `mkdir -p`'s rule, and the outcome of losing a race with another creator.
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
                Ok(next) => walk(conn, who, next, parts, mode, how, on_done, sink),
                Err(_) => on_done(FsDone::refused(Errno::EBADF), conn),
            }
        });
    });
}
