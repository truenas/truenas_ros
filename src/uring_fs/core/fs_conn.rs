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

    /// Stage the reason-sink whose share the frame's one submission takes ([`armed::arm`]) and mark the frame watching,
    /// answering with what was staged before so the caller can put it back. The frame's arm flag rides the sink's own
    /// allocation, so a frame costs no second `Rc`.
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
    /// the way - **the one shape every submit method here hands the core.**
    ///
    /// Arming and boxing are one step because they were two, and the second was skippable; the share itself is only
    /// constructible in [`armed`], so a hand-built waiter that skips arming is a build failure rather than a spurious
    /// `EINVAL` - the defect the ring timer shipped with.
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
    /// A continuation runs after its owner may be gone - the sweep is once per close and a completion it cancelled is
    /// what schedules the continuation - so "my ops are failing" is the signal a task is told to wind down on. Two
    /// shapes never see it: an offload is never cancelled and always delivers, and a timer armed *after* the sweep
    /// expires normally. A task built from either would otherwise run for a dead connection indefinitely, holding a
    /// graceful drain open with it.
    ///
    /// Submitting is still allowed here, and that is deliberate: a handler finishing work it already accepted - the
    /// last write of an upload, the rename that publishes it - is not undone by the peer hanging up. This says the peer
    /// is gone; what is worth finishing for it is the caller's judgement.
    ///
    /// Always `false` where the reactor has no owners (a standalone [`UringFs`](super::super::UringFs), whose whole
    /// loop is the lifetime).
    pub fn owner_is_gone(&self) -> bool {
        self.fs.owner_is_gone(self.owner)
    }

    /// Whether the loop this facade runs on has been asked to drain gracefully.
    ///
    /// The other half of [`owner_is_gone`](Self::owner_is_gone): that one says *your connection* closed, this one says
    /// *the server* is going away - a task whose connection is perfectly healthy can still be the last thing holding a
    /// drain open, and this is the signal it winds down on. Readable only between awaits, like its sibling, so it
    /// narrows the drain for looping work (a re-arming tick, a batch loop) and deliberately not for a single long
    /// await - an offload is never cancelled, and its delivery is the next chance to look.
    ///
    /// **Never `true` on a standalone [`UringFs`](super::super::UringFs) host today** - nothing there requests a
    /// graceful drain; its [`ShutdownHandle`](super::super::ShutdownHandle) stops the loop outright - so a consumer on
    /// that host must not wait for this. The contract is "a `true` means wind down", not "a drain will announce
    /// itself".
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
            // Cloned, not taken: both halves of a two-step dispatch submit, and both should report. The frame's arm
            // flag rides the shared sink `Rc`, not a copied field - an arm made through the reborrow belongs to
            // whatever frame is watching the outer facade.
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

    /// The delivering connection's claim on the buffer `src` lies in, as a share to hand an op or a job: the hold is
    /// minted on the first taker and cloned for the rest, so the buffer goes back to the pool when the last of them
    /// completes. The facade keeps only a `Weak` - a strong clone here would withhold the release until the facade
    /// dropped, for no one's benefit. An upgrade can only fail if every holder already completed and released the
    /// buffer, which cannot happen while this delivery is still running its handler - but if it ever did, leasing again
    /// would read a buffer the pool may have re-issued, so `None` sends the caller to its copy path instead.
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

    /// Open `path` relative to `anchor` as `who`; fire `on_done` with the new [`File`] ([`FsDone::file`]). `path` must
    /// be anchor-relative (a leading `/` is refused); resolution defaults to the full [`CONFINED_RESOLVE`] set unless
    /// `how` states a confinement policy of its own, on the same rule the blocking
    /// [`FsHandle::open`](crate::uring_fs::FsHandle::open) applies - a `resolve` carrying only hardening flags composes
    /// with the default rather than replacing it. An invalid argument answers `on_done` **before this returns** with
    /// `EINVAL` and [`FsDone::was_refused`] true - the same verdict the mid-walk screens give, so provenance does not
    /// depend on where the screen fired. It is not silently dropped: a dropped continuation closes the connection,
    /// which turns a caller bug into a shed peer.
    ///
    /// Every facade may open, a continuation's included. What that costs is the file: a continuation runs for an owner
    /// that may already be gone, and nothing sweeps a descriptor opened after its connection closed until the reactor's
    /// tables go, so a chain that opens must reach a step that closes.
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
            // Server facade: anchor-relative only, deliberately stricter than the general-client `FsHandle::open`
            // (`open_parts`), which allows an absolute path when the caller
            // drops `RESOLVE_BENEATH`. The two validations differ on purpose;
            // do not unify them.
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
        // BOTH of `open_parts`' rules, through the same functions: this is the facade a request handler reaches with a
        // path the peer chose, so it cannot be the laxer of the two. Sharing only one of them is how it becomes so - a
        // creating open here parks on a planted FIFO that the client facade survives.
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

    /// Open the parent of the directory `anchor` names, as `who`, and fire `on_done` with it ([`FsDone::file`]). It is
    /// the one open that leaves its anchor, and it goes up one level and no further, since it takes no path and opens
    /// only `..`.
    ///
    /// [`open`](Self::open) cannot reach a parent. `RESOLVE_BENEATH` answers `..` at the anchor with `EXDEV`,
    /// `RESOLVE_IN_ROOT` keeps it at the anchor (`follow_dotdot` in `fs/namei.c`), and [`Leaf`] refuses `..`. So this
    /// open drops the scope and keeps the rest of [`CONFINED_RESOLVE`], which is `RESOLVE_NO_SYMLINKS` and
    /// `RESOLVE_NO_XDEV`.
    ///
    /// - The kernel checks that `who` may search the directory before it looks up `..` (`may_lookup` in
    ///   `link_path_walk`), as it does for any name in it. The parent is then opened as `how` asks, so an `O_PATH` open
    ///   needs nothing of the parent itself.
    /// - At the top of a mount the parent is on another file system, and the open answers `EXDEV` rather than cross to
    ///   it (`follow_dotdot`). The parent of the process's root is that root, as for any `..`.
    /// - The parent comes from the dentry cache (`dget_parent` in `follow_dotdot`), so a directory that moved answers
    ///   its new parent. With no scope there is no check for a rename racing the walk (`handle_dots`), so `EXDEV` here
    ///   always means the top of a mount.
    ///
    /// A `how` that creates (`O_CREAT` or `O_TMPFILE`) or states a scope (`RESOLVE_BENEATH` or `RESOLVE_IN_ROOT`) is
    /// refused before this returns, with the marked `EINVAL` that [`open`](Self::open) gives. A create would make a
    /// file in the parent, `RESOLVE_BENEATH` would always answer `EXDEV`, and `RESOLVE_IN_ROOT` would answer the
    /// directory itself.
    pub fn open_parent<F>(&mut self, who: Personality, anchor: &Anchor, how: OpenHow, on_done: F)
    where
        F: FnOnce(FsDone, &mut FsConn<'_>) + 'static,
    {
        self.open_dotdot(who, anchor, how, false, on_done);
    }

    /// Open the parent of the directory `anchor` names, as `who`, as [`open_parent`](Self::open_parent) does, but at
    /// the top of a mount go on to the parent of the directory the mount covers, as `..` does for any process
    /// (`follow_dotdot` and `choose_mountpoint` in `fs/namei.c`).
    ///
    /// It keeps `RESOLVE_NO_SYMLINKS` and drops `RESOLVE_NO_XDEV`, so it is the one open whose answer may be on another
    /// file system than its anchor. `..` only goes up, so it never goes down into a mount, and the parent comes from
    /// the live tree of mounts, so a directory moved above the mount answers where it is now. The kernel checks only
    /// that `who` may search the directory, and a `how` is refused as for `open_parent`.
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

    /// Create every missing directory along `path` beneath `anchor` as `who`, then open the deepest one with `how` -
    /// `mkdir -p`, confined, on the ring. The reactor twin of
    /// [`FsHandle::mkdir_path`](crate::uring_fs::FsHandle::mkdir_path).
    ///
    /// `on_done` receives the final open, so `how` decides what the caller gets: an `O_PATH` handle to anchor against,
    /// or a directory it can `fsync`, which `O_PATH` cannot (`EBADF`).
    ///
    /// That choice is the only one `how` has. `O_DIRECTORY` is forced - what this answers with is a directory or it is
    /// nothing - and a `how` carrying `O_CREAT` or `O_TMPFILE` is refused, because either would answer with a file
    /// where the caller asked for the tree.
    ///
    /// `EEXIST` is success at every component, so two callers building one tree both finish.
    ///
    /// An invalid argument answers `on_done` before this returns with a marked `EINVAL`, as [`open`](Self::open) does.
    /// `path` must name its components plainly -- relative, no `.`, no `..`, no empty component - which is
    /// [`path::relative_defect`](crate::path::relative_defect). `..` is refused rather than resolved even though
    /// `openat2` would resolve it safely under [`CONFINED_RESOLVE`]: what `a/..` names depends on what `a` turned out
    /// to be, so it is not a thing this walk can create, and a path that succeeded when the tree existed and failed
    /// when it did not would mean two different things.
    ///
    /// # Why this is a primitive rather than caller code
    ///
    /// `mkdirat` honours **no** `RESOLVE_*` flags - that is what [`Leaf`] exists for - so handing it `"a/b/c"` would
    /// resolve the intermediate components unconfined. The only sound construction alternates confined `openat2` walks
    /// with single-component `mkdirat`s, and each of those opens depends on the completion before it. Keeping the walk
    /// here is what makes each step's confinement the walk's own rather than a consumer's to get right, and what keeps
    /// a half-built tree from being reachable.
    ///
    /// `CONFINED_RESOLVE` is unioned in, not assigned: a caller may add restrictions and may drop none. Unlike a plain
    /// open, this one creates, and a create that escaped the anchor would leave a directory somewhere the caller never
    /// named.
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
        // Judged on shape before anything is submitted, so the probe below cannot admit what the walk would refuse. See
        // the doc above.
        if crate::path::relative_defect(bytes).is_some() {
            return on_done(FsDone::refused(Errno::EINVAL), self);
        }
        // Owned, because each component outlives the completion that consumes it. Every one is a `Leaf` by the check
        // above.
        let parts: VecDeque<CString> = crate::path::components(bytes)
            .map(|p| CString::new(p).expect("no NUL: checked above"))
            .collect();
        let mut raw = how.to_raw();
        // Every open this makes - the probe, each intermediate, and the answer - must name a directory, so
        // `O_DIRECTORY` is forced the way `CONFINED_RESOLVE` is. Two creation flags survive that and are refused
        // outright:
        //
        // `O_CREAT` would otherwise have the probe create a *regular file* at the leaf and hand it back as though the
        // tree had been built. The kernel does refuse the pair - "Block bugs where O_DIRECTORY | O_CREAT created
        // regular files", `build_open_flags`, `fs/open.c:1278-1284` - but only at the syscall, which is after the walk
        // has already created the tree beneath the leaf. Refusing at entry is what keeps a bad argument from leaving a
        // partial one.
        //
        // `O_TMPFILE` is `__O_TMPFILE | O_DIRECTORY`, so raising `O_DIRECTORY` cannot exclude it and testing for it
        // must mask the `O_DIRECTORY` half off - otherwise every plain directory open looks like one. It resolves the
        // path as a directory and answers with an unnamed inode *inside* it, which is not the directory the caller
        // asked for.
        const TMPFILE_ONLY: i32 = libc::O_TMPFILE & !libc::O_DIRECTORY;
        let refused = (libc::O_CREAT | TMPFILE_ONLY) as u64;
        if raw.flags & refused != 0 {
            return on_done(FsDone::refused(Errno::EINVAL), self);
        }
        // And a scoping conflict, for the same class of reason as the two above: the walk would fail `EINVAL` at every
        // component - after the earlier ones had already been created. The rule and its citation live on
        // `scoping_conflict`.
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
    /// **Each step carries its own personality.** That is what this exists for: reaching a file inside a tree the
    /// caller may not traverse, while still having the kernel decide the caller's access to the file itself. A
    /// directory opened under the daemon's own personality grants nothing about what is inside it, so the last step
    /// names the caller and the answer is the kernel's.
    ///
    /// Kept here rather than written out by a consumer because the per-step personality and confinement are the point:
    /// a caller assembling the same walk by hand would have to get both right at every step, and an intermediate opened
    /// under the wrong one grants access the kernel was meant to decide.
    ///
    /// Every step is confined by [`CONFINED_RESOLVE`], unioned rather than assigned, and every step but the last is
    /// forced `O_DIRECTORY`. A step that creates, or that states `RESOLVE_IN_ROOT` - which the kernel refuses to pair
    /// with the `RESOLVE_BENEATH` unioned here - is refused at entry, before anything is submitted, so a bad argument
    /// cannot leave a half-walked chain behind. The refusal answers `on_done` with a marked `EINVAL` before this
    /// returns, exactly as the same screen answers mid-walk on a derived name - one verdict per defect, wherever it
    /// fires.
    pub fn open_chain<F>(&mut self, anchor: &Anchor, steps: Vec<OpenStep>, on_done: F)
    where
        F: FnOnce(FsDone, &mut FsConn<'_>) + 'static,
    {
        // Judged on shape before anything is submitted. A `Derived` step cannot be judged here — it has no path yet —
        // so the walk judges it when it produces one, on the same rule.
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
            // A scoping conflict would otherwise make every step `EINVAL` with the kernel blamed for a bit this crate
            // added; the rule and its citation live on `scoping_conflict`.
            if super::scoping_conflict(step.how.to_raw().resolve) {
                return on_done(FsDone::refused(Errno::EINVAL), self);
            }
        }
        let steps: VecDeque<OpenStep> = steps.into();
        let sink = self.fail_sink.clone();
        chain(self, anchor.clone(), steps, Box::new(on_done), sink);
    }

    /// One step of a walk, opened under its own personality.
    ///
    /// Stays private: every path this resolves is a single validated component of one the caller already named,
    /// confined, under the caller's own personality.
    /// `guarded` says whether the caller added the special-file guard to `how`, so the completion knows to strip
    /// `O_NONBLOCK` back off the descriptor. **The answer is not always a directory**: a step that forces `O_DIRECTORY`
    /// needs no guard, because the kernel answers `ENOTDIR` on a FIFO or device before reaching the file's own `open`
    /// method, but `chain`'s last step is opened as the caller asked and can name anything the anchor holds.
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
    /// [`preadv2`](Self::preadv2), so nothing is zeroed first. For a caller that builds a reply in one buffer and reads
    /// a file's bytes straight after its head, where `preadv2` fills each buffer up to the length it already has.
    ///
    /// The same `buf` comes back through [`FsDone::into_value`], its length grown by the count read, which is short
    /// only at the end of the file, and unchanged on a failure. A `count` past `buf`'s spare capacity or past
    /// `u32::MAX`, and an `off` of `u64::MAX`, are refused with a marked `EINVAL` ([`FsDone::was_refused`]): the buffer
    /// is never grown, which would allocate and move it, and io_uring reads `u64::MAX` as the file's position
    /// (`io_kiocb_update_pos`, `io_uring/rw.c`).
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

    /// Write `src` - typically the request's own body - to `f` at `off`, without copying it when it still sits in the
    /// connection's receive buffer.
    ///
    /// When `src` lies inside the delivering connection's pooled claim, the op's iovec points straight at the buffer:
    /// the connection surrenders the claim to its writes instead of recycling it, and the pool gets the buffer back
    /// when the last of them completes - zero copies, zero allocations, for as many in-bounds ranges as one delivery
    /// submits. Anything else - an unpooled connection, a placed or owned body, a range outside the claim, or a call
    /// from inside a task, whose facade carries no claim - falls back to `pwritev2` on a copy, so the call degrades
    /// instead of failing. A body placed in storage of its own is written with no copy by
    /// [`pwritev2_owned`](Self::pwritev2_owned) instead. A full op table refuses the write with a marked `EBUSY`
    /// ([`FsDone::was_refused`]), as it refuses a copy, and hands nothing back: the bytes were the delivery's.
    ///
    /// The one behavioural asymmetry between the two paths is the **short write**, which ZFS returns as a success by
    /// design. On the copy path the source comes back through [`FsDone::into_bufs`] and the caller may retry the
    /// remainder; on the leased path the source is the receive buffer and this completion returns it to the pool, so no
    /// retry can ever be sound - a short leased write is therefore surfaced as `Err(EIO)` rather than as an `Ok(n)`
    /// inviting one. The count it wrote still comes with it through [`FsDone::short_count`], for a caller that must
    /// answer the count rather than retry.
    ///
    /// The `EIO` carries no cause because none is knowable at this completion: ZFS discards the breaking errno once any
    /// progress was made, returning the partial count with no error, and io_uring folds a post-progress errno into the
    /// positive count the same way (`io_fixup_rw_res`, `io_uring/rw.c:563-574`) - so mapping the short write to
    /// `ENOSPC` or `EDQUOT` would be a guess. A consumer that must answer storage-full distinctly learns the cause from
    /// its next write against the same file, which has made no progress to hide the errno behind.
    ///
    /// Every leased write of a delivery shares the one claim: each holds a share, and the completion that drops the
    /// last share is the one that hands the buffer back. A short write fails its own op alone.
    ///
    /// # Pipelined ingest
    ///
    /// The lease outlives the delivery's verdict, so a streaming handler need not park per window: submit the write and
    /// return [`Continue`](crate::http::HttpVerdict::Continue), and the next window is read while this one's DMA runs -
    /// each write's completion releases its own buffer. The handler is the depth brake: track writes in flight and, at
    /// its cap, park with [`defer_stream`](crate::http::HttpRequest::defer_stream), resuming from a completion once
    /// below it - stopping the reads is the whole mechanism, since the socket buffer then fills and TCP slows the
    /// sender. Keep the cap within `ServerConfig::recv_lease_depth` (past it reads park, or fall back to copies with
    /// `recv_shortage_retry` off), and size `fs_ops` to cover `pool_size` x depth. At `Stage::End`, wait for the
    /// outstanding completions with a plain [`defer`](crate::http::HttpRequest::defer) and answer from the last one; a
    /// failed window fails the request there.
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
            // Every in-bounds range of one delivery shares the claim: the hold is minted on the first leased write and
            // cloned for the rest, so the buffer goes back to the pool when the last of them completes. The facade
            // keeps only a `Weak` - a strong clone here would withhold the release until the facade dropped, for no
            // one's benefit. An upgrade can only fail if every holder already completed and released the buffer, which
            // cannot happen while this delivery is still running its handler - but if it ever did, leasing again would
            // write from a buffer the pool may have re-issued, so it falls to the copy path instead.
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
    /// with no copy, and no iovec or outer `Vec` is made for it.
    ///
    /// The same `buf` comes back through [`FsDone::into_value`] whatever the outcome, for the caller to keep or to give
    /// back to the ring's body pool ([`BodyRecycler::recycle`](crate::net::core::BodyRecycler::recycle)). So a short
    /// write, which ZFS returns as a success (`zfs_write`), answers `Ok(n)`, and the caller may write the rest from the
    /// same bytes, as on the copy path. A `range` that `buf.get` does not take, a count past `u32::MAX`, and an `off`
    /// of `u64::MAX` are refused with a marked `EINVAL`, since io_uring reads `u64::MAX` as the file's position
    /// (`io_kiocb_update_pos`, `io_uring/rw.c`). A full op table refuses the write with a marked `EBUSY`
    /// ([`FsDone::was_refused`]).
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

    /// Fire `on_done` after `after`: one relative, one-shot `IORING_OP_TIMEOUT` on this ring, delivered as `Ok(0)` when
    /// it expires. No fd and no personality ride it - a timer touches nothing a credential guards - so this is the
    /// retry-tick and deadline primitive: a caller that must try again later re-arms here instead of sleeping an
    /// offload worker. An owner gone before expiry drops the callback, like any continuation's.
    ///
    /// **A timer holds its op slot for its whole wall-clock duration**, which no other op on this facade does - a read
    /// holds one until the I/O completes, and the table is sized on that. So a deadline armed for 30 s and reached in 3
    /// ms costs the other 29.997 s of the handler budget unless it is retracted, which is what the returned [`Timer`]
    /// is for.
    ///
    /// `None` means the arm was refused - a full table, the per-owner cap, a staging failure, or a connection the
    /// teardown sweep has already passed, which may finish I/O but not park time on the table - and no timer exists to
    /// retract. The refusal still reaches `on_done`, delivered at the next wake drain (`FsCore::refuse`) with the
    /// verdict on its face: the capacity refusals as the marked `EBUSY` a full table answers ([`FsDone::was_refused`]
    /// true - the arm is worth retrying once a hold ends), the swept owner's as *unmarked* `ECANCELED` - the sweep's
    /// own vocabulary, on purpose, so a continuation keyed on it winds down the same way in both orderings. An awaited
    /// [`fut`](FsConn::fut) additionally reads a marked reason synchronously through its armed sink share, before the
    /// delivered callback settles the frame with the same verdict.
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
    /// What comes back when: the owner's **cap headroom returns here**, synchronously, so retracting one deadline and
    /// arming its replacement inside the same delivery holds at any cap; the **op slot follows at the retracted timer's
    /// CQE**, which the staged cancel hastens but this call cannot wait for. An owner mid-swap therefore holds up to
    /// twice its cap in slots - and no further: the arm screen refuses at that bound, so a retract-rearm loop inside
    /// one delivery is refused once its retiring slots reach the cap again, instead of walking the whole table with the
    /// armed count never leaving zero.
    ///
    /// The timer completes `ECANCELED` **with [`FsDone::was_refused`] true** and `on_done` fires with it, so a caller
    /// still gets exactly one answer per arm and the answer says what it was - `ECANCELED` unmarked stays meaning the
    /// reactor is going away, which is the verdict a task winds down on, and a healthy retraction must not read as
    /// that. **That verdict does not depend on the cancel winning.** The kernel delists a timeout before posting
    /// `-ETIME` (`io_timeout_fn`, `io_uring/timeout.c:254-276`), so a retraction that arrives after the fire cancels
    /// nothing and the expiry stands - and the cancel is best-effort besides. The mark is the caller's ask, and
    /// `on_cqe` reads the mark: a retracted timer's `-ETIME` is delivered as the marked cancellation, never as `Ok(0)`,
    /// which is this crate's "the deadline arrived" and would run a timeout handler for work the caller had already
    /// finished.
    ///
    /// Idempotent: the token is verified against the table before anything is staged, so a [`Timer`] whose op has
    /// already *answered* - its slot freed, or reissued since - or one minted by a different reactor, or retracted once
    /// already, retracts nothing. Nothing is reported here either way; the answer arrives at `on_done`.
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
    /// root. It is a read alone, and nothing here writes through `/proc`, as the settled decision on `O_PATH` in the
    /// crate's notes says.
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

    /// Read extended attribute `name` from `f` under the reactor's **ambient root** - no `who`. The one sanctioned
    /// privileged read: for a `trusted.*`/`security.*` attribute a request's own identity cannot see
    /// (`sqe.personality`, not the fd's open-time cred, governs `fgetxattr`'s `CAP_SYS_ADMIN` check; `personality = 0`
    /// runs as the ring owner, root). Needs Linux >= 6.13; fails closed (`EOPNOTSUPP`) otherwise.
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
    /// The link jumps to `f` itself (`proc_pid_get_link` in `fs/proc/base.c`), and the open then checks `who` against
    /// the file as an open by name does (`may_open` in `fs/namei.c`), so the file system decides the access, its ACL
    /// included. It skips the walk to the file, so a folder above it that `who` may not search does not refuse it. A
    /// link held `O_PATH` with `O_NOFOLLOW` answers `ELOOP`, since the jump reaches the link itself, and a FIFO answers
    /// at once rather than wait for a peer. It runs on an io-wq worker and needs `/proc` mounted in the process's root.
    /// An open is the one thing besides a read that goes through `/proc`, as the settled decision on `O_PATH` in the
    /// crate's notes says, since the file system checks it in full and nothing is carried around the check.
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
    /// This is the ingest half of a zero-copy body path: whoever fills the pipe (a socket splice, a `vmsplice`) never
    /// materializes the bytes, and neither does this. `pipe` is a plain descriptor the caller keeps open until the
    /// completion fires - it is **not** taken into the fixed-file pool, so it does not consume a `FsConfig::ops` slot.
    ///
    /// # Short moves are normal
    ///
    /// A pipe delivers what it has, so a completion carrying fewer than `len` bytes is ordinary progress, not end of
    /// input: resubmit the remainder. [`FsDone::result`] is the byte count either way - the kernel's `req_set_fail` on
    /// a short move (`io_splice`, `io_uring/splice.c`) governs only whether an `IOSQE_IO_LINK` chain continues, which
    /// this does not use.
    ///
    /// Splice cannot hash what it moves - nothing passes through userspace.
    /// A body that needs an ETag has to be read conventionally, which is the tradeoff this exists to let a caller make
    /// per request.
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
    /// **A [`Leaf`] bounds the name, not what the name resolves to.** `flags` reaches the kernel as given, and
    /// `AT_SYMLINK_FOLLOW` there makes `old_leaf` resolve wherever it points - a one-component symlink a peer planted
    /// inside `old` is a valid leaf, so the new name lands inside `new` as a second name for an inode outside it. The
    /// kernel offers no confinement for this: `may_linkat` (`fs/namei.c`) decides *which* inode may be linked and never
    /// where the link lands, so `fs.protected_hardlinks` does not help either. Pass `AtFlags::empty()` unless the
    /// source tree is one nothing else can write, or open the source under `RESOLVE_NO_SYMLINKS` and publish it with
    /// [`linkat_file`](Self::linkat_file).
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

/// The creation flags no step of a chain may carry.
///
/// `O_CREAT` and `O_TMPFILE` both make an inode, and a chain that made one at an intermediate would leave it behind
/// when a later step failed. `O_TMPFILE` is `__O_TMPFILE | O_DIRECTORY`, so testing for it has to mask the
/// `O_DIRECTORY` half off — every directory open carries that bit and would otherwise look like one.
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
    // Only the answer is opened as the caller asked; everything above it is a directory this walks through.
    //
    // Which is why the answer is guarded and the rest are not. An intermediate carries `O_DIRECTORY`, so the kernel
    // answers `ENOTDIR` on a special file before reaching its own `open`; the answer carries whatever the caller asked
    // for, and a FIFO named there with a forcing flag (`O_TRUNC`, which `io_openat_force_async` punts to io-wq where
    // `io_openat2` never adds `O_NONBLOCK` - `io_uring/openclose.c`) parks a worker in `wait_for_partner` indefinitely
    // and pins its op slot with it. There is no `SpecialFiles` opt-out here: a step names a path relative to a
    // directory the caller may not own, which is the case the guard is for. A caller who means to open a FIFO uses
    // `FsConn::open` with `SpecialFiles::Allow`.
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
    // Carried onto every step's facade: the second and later steps submit from the fresh `FsConn` a completion is
    // handed, which has no sink of its own, so without this a transient `EBUSY` mid-chain reaches the caller as
    // teardown.
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
