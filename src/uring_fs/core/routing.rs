use super::*;

impl FsCore {
    // ---- cancellation --------------------------------------------------

    /// Stage an `ASYNC_CANCEL` for the in-flight op named by `target_ud`. Its own completion is dropped
    /// ([`TAG_CANCEL`]), and the cancelled op completes with `ECANCELED` and runs `take_op` like any other. Takes no
    /// op-table slot, but goes through `eng.stage` so the engine's in-flight count stays right.
    ///
    /// **Best-effort, and nothing may hang off it having reached the kernel.** `push_sqe` answers `EBUSY` when a full
    /// SQ meets a `submit` that accepted nothing, which a healthy ring under load reaches. A cancel that never staged
    /// leaves the op running to its own ending, so callers build their verdicts on [`FsCore::retract_op`]'s mark, which
    /// records the ask whether or not the cancel arrived.
    pub(super) fn submit_cancel(&self, eng: &mut Engine, target_ud: u64) {
        let ud = pack_raw(TAG_CANCEL, 0, 0);
        let _ = eng.stage(ud, |sqe| {
            sqe.opcode = IORING_OP_ASYNC_CANCEL;
            sqe.addr = target_ud; // cancel the op whose user_data == target_ud
        });
    }

    /// Cancel every in-flight op owned by any of `owners`, the connection-teardown sweep. An op in flight parks its fd
    /// and buffers until its CQE, so it is cancelled rather than dropped, and its entry lives until the `ECANCELED` CQE
    /// reaps it.
    ///
    /// **This runs once per close, and it is not a liveness gate.** A continuation of a cancelled op runs after the
    /// sweep with the same owner, and what it submits then is not swept again, on purpose, since a handler finishing an
    /// upload it accepted still has work to do. A second sweep would be unbounded, as a continuation that resubmits on
    /// `ECANCELED` keeps giving it something to find. The bound is the continuation's, through
    /// [`FsCore::owner_is_gone`], recorded here, which two shapes need.
    ///
    /// - An open with [`SpecialFiles::Allow`](super::SpecialFiles), which can hang an io-wq worker for good. Cancelling
    ///   reaches it in flight, but a fresh one afterwards has nothing left to reach it.
    /// - A task awaiting only offloads, which are never cancelled and always deliver ([`FsConn::offload`]), so neither
    ///   signal [`super::task`] winds a task down on arrives, and a re-arming one holds a graceful drain open.
    ///
    /// **Takes the whole batch of closes, because the scan is the cost.** Every close arrives here, and one scan per
    /// owner would walk the table once each on the reactor thread. Sorted so the membership test is a binary search,
    /// since a linear one makes a mass disconnect quadratic.
    #[cfg_attr(not(feature = "net-server"), allow(dead_code))]
    pub(crate) fn cancel_owned_by(&mut self, eng: &mut Engine, mut owners: Vec<(u32, u64)>) {
        // Recorded before the scan, so a continuation woken by a cancellation below reads its owner as gone, and
        // recorded with nothing to cancel too, since a task with no ring op reads it.
        for &(slot, generation) in &owners {
            let swept = self.closed_owners.entry(slot).or_insert(generation);
            *swept = (*swept).max(generation);
        }
        // Bounded by the in-flight count. A slot is in `op_free` iff free, so the difference is how many in-flight
        // entries the scan can meet, and it stops once it has seen them all.
        let mut in_flight = self.ops.len() - self.op_free.len();
        // Checked only in the direction that hurts. A count too low, from a slot pushed to `op_free` twice, breaks the
        // walk early and leaves live ops uncancelled. `>=`, since a slot popped for an op whose state is not set yet
        // counts here and not in the census, which is also why the walk ends with no assertion on what is left.
        debug_assert!(
            in_flight
                >= self
                    .ops
                    .iter()
                    .filter(|e| matches!(e.state.state, FsOpState::InFlight { .. }))
                    .count(),
            "the free list holds a slot the op table still has in flight"
        );
        if in_flight == 0 {
            return; // nothing in flight for anyone
        }
        owners.sort_unstable();
        // Collect targets first (the scan borrows `self.ops`), then stage.
        let mut targets: Vec<u64> = Vec::new();
        for (i, entry) in self.ops.iter().enumerate() {
            if in_flight == 0 {
                break;
            }
            let FsOpState::InFlight { tag } = entry.state.state else {
                continue;
            };
            in_flight -= 1;
            let owner = match &entry.state.waiter {
                Some(FsWaiter::Embedded { owner: Some(o), .. }) => *o,
                Some(FsWaiter::Pump { owner: o }) => *o,
                _ => continue,
            };
            if owners.binary_search(&owner).is_ok() {
                targets.push(pack_raw(tag, i as u32, entry.generation as u32));
            }
        }
        for ud in targets {
            self.submit_cancel(eng, ud);
        }
    }

    // ---- completion routing --------------------------------------------

    /// Route one fs-domain CQE. `tag` is the unpacked op tag; a generation mismatch makes the completion inert (op
    /// entries free only at their own terminal CQE). An **off-loop** (channel) op is delivered here and returns
    /// [`ReapedFs::None`]; an **embedded** (on-loop) op hands back its callback and outcome for the host to fire once
    /// its borrow of the fs tables has ended; a **pump** read hands back its outcome and owner for the host to route
    /// itself.
    pub(crate) fn on_cqe(&mut self, eng: &mut Engine, tag: u8, op_slot: u32, gen32: u32, res: i32) -> ReapedFs {
        // A poll of the file leases' signalfd that could not be staged is staged again on the ring's next completion.
        self.file_leases.arm(eng);
        if tag == TAG_CANCEL {
            // An ASYNC_CANCEL's own completion; nothing to route.
            return ReapedFs::None;
        }
        if tag == TAG_FILE_LEASE {
            let broken = self.file_leases.on_readable(eng);
            if broken.is_empty() {
                return ReapedFs::None;
            }
            return ReapedFs::FileLeaseBreaks(broken);
        }
        if tag == TAG_OPEN_DEADLINE {
            // An `Allow` open's guard, fired (`-ETIME`), retracted by the open completing first (`-ECANCELED`), or
            // swept. Its slot frees here, and only a genuine firing stages the cancel.
            let Some(entry) = self.ops.get_mut(op_slot as usize) else {
                return ReapedFs::None;
            };
            if entry.generation as u32 != gen32 || entry.state.state != (FsOpState::InFlight { tag: TAG_OPEN_DEADLINE })
            {
                return ReapedFs::None;
            }
            let cancels = entry.state.cancels.take();
            let retracted = entry.state.retracted;
            let parked = entry.state.wall_clock.take();
            entry.state.clear();
            entry.generation += 1;
            self.op_free.push(op_slot);
            // The pair's charge, parked here by `take_op` when the open answered first: the slot is free now, so it
            // goes home.
            if let Some(o) = parked {
                self.release_retiring(o);
            }
            if !retracted
                && res != -libc::ECANCELED
                && let Some((oslot, ogen)) = cancels
            {
                // Mark, then cancel (`retract_op`). The mark makes the open's `ECANCELED` carry the deadline's verdict,
                // marked like a retracted timer's, instead of teardown's unmarked form. An open that already answered
                // is left alone by the generation check.
                //
                // The screen is on the cancellation, not the firing. `__io_timeout_prep` runs inside `io_uring_enter`
                // after `push_sqe` took the charge, and can still answer `-ENOMEM` (`io_uring/timeout.c:554-556`) with
                // `io_submit_fail_init` posting a CQE under the guard's tag. Left uncancelled, the open could park in
                // `fifo_open`'s `wait_for_partner` for as long as the peer likes. An unmarked `ECANCELED` alone must
                // not cancel here, since it is a sweep or teardown, which stages the open's own cancel.
                self.retract_op(eng, TAG_OPEN, oslot, ogen);
            }
            return ReapedFs::None;
        }
        #[cfg_attr(not(feature = "net-server"), allow(unused_mut))]
        let Some(mut completed) = self.take_op(tag, op_slot, gen32) else {
            return ReapedFs::None;
        };
        #[cfg(feature = "net-server")]
        let leased = completed.recv_lease.is_some();
        // The buffer goes back to the pool only when its LAST share drops: sibling writes in the same delivery may
        // still be reading it, so the id surfaces from exactly one completion - `into_inner` on the final `Arc` - and
        // rides out `None` from every other.
        #[cfg(feature = "net-server")]
        let home = &self.lease_returns;
        #[cfg(feature = "net-server")]
        let recv_lease = completed
            .recv_lease
            .take()
            .and_then(std::sync::Arc::into_inner)
            .and_then(|hold| hold.take_bid(home));
        // In order, so a buffer two windows share surfaces once, from the later.
        #[cfg(feature = "net-server")]
        let recv_lease_more: Vec<u16> = std::mem::take(&mut completed.recv_lease_more)
            .into_iter()
            .filter_map(std::sync::Arc::into_inner)
            .filter_map(|hold| hold.take_bid(home))
            .collect();
        #[cfg(feature = "net-server")]
        let lease_want = completed.lease_want;
        let Completed {
            waiter,
            bufs,
            mut value,
            stat,
            strip_nonblock,
            retracted,
            guard,
            ..
        } = completed;
        // The open answered, so retract its guard timer (`retract_op`). The mark keeps the guard's `ECANCELED` from
        // cancelling a slot the open no longer holds, and the generation check makes a stale pair inert.
        if let Some((gslot, ggen)) = guard {
            self.retract_op(eng, TAG_OPEN_DEADLINE, gslot, ggen);
        }

        // A successful OPENAT2 returns a real fd. Wrapped in an `Arc<OwnedFd>`, it closes when nobody takes it, and an
        // fd op's parked `file` was already dropped by `take_op`'s `clear`, for close-last ordering.
        let file = if tag == TAG_OPEN && res >= 0 {
            // Before anyone can see the descriptor, and so before any read of it could be issued.
            if let Some(flags) = strip_nonblock {
                strip_guard_nonblock(res, flags);
            }
            // SAFETY: `res` is a fresh fd OPENAT2 just returned; nothing else owns it.
            Some(Arc::new(unsafe { crate::fd::owned_from_raw(res) }))
        } else {
            None
        };
        let mut result = map_res(res);
        // A pure `IORING_OP_TIMEOUT` completes `-ETIME` when it fires, which is the success the caller asked for,
        // unless the caller retracted it. A retraction cannot make the cancel win, since `io_timeout_fn` delists the
        // timeout before posting `-ETIME` (`io_uring/timeout.c:254-276`) and `submit_cancel` is best-effort. So the
        // mark decides, and a retracted timer reads as the marked cancellation a winning cancel would have delivered.
        if tag == TAG_TIMEOUT && result == Err(Errno::ETIME) {
            result = if retracted { Err(Errno::ECANCELED) } else { Ok(0) };
        }
        // An asked-for cancellation carries the mark, as an unmarked `ECANCELED` means teardown alone. Gated on the
        // errno too, since an op that answered before the cancel reached it keeps its answer. A deadline that catches
        // the open's worker mid-sleep can surface as `EINTR`, a kernel verdict left unmarked.
        let refused = retracted && result == Err(Errno::ECANCELED);
        // A short leased write answers `EIO` with its count beside it, never `Ok(n)` (see `FsConn::pwritev2_from`).
        #[cfg(feature = "net-server")]
        let mut short = None;
        #[cfg(feature = "net-server")]
        if leased
            && let Ok(n) = result
            && (n as u32) < lease_want
        {
            result = Err(Errno::EIO);
            short = Some(n as usize);
        }

        if tag == TAG_READ_SPARE
            && let (Ok(n), Some(buf)) = (result, value.as_mut())
        {
            // SAFETY: the kernel wrote `n` bytes into the room past the length, and `n` is at most the count
            // `submit_read_spare` held to that room, so the first `len + n` bytes are initialized.
            unsafe { buf.set_len(buf.len() + n as usize) };
        }

        // A selecting pump read (no owned buffer) is done with the ring, whatever it answered - `-ENOBUFS` and
        // `-ECANCELED` included.
        if matches!(waiter, Some(FsWaiter::Pump { .. })) && bufs.is_empty() {
            self.pump_selecting = self.pump_selecting.saturating_sub(1);
        }
        match waiter {
            Some(FsWaiter::Channel(tx)) => {
                let bufs = with_value(bufs, value);
                let _ = tx.send(FsOutcome::new(result, bufs, file, stat));
                ReapedFs::None
            }
            Some(FsWaiter::Embedded { owner, cb, .. }) => ReapedFs::Embedded(
                cb,
                FsDone {
                    result,
                    refused,
                    bufs,
                    value,
                    file: file.map(File::new),
                    stat,
                    #[cfg(feature = "net-server")]
                    recv_lease,
                    #[cfg(feature = "net-server")]
                    recv_lease_more,
                    #[cfg(feature = "net-server")]
                    short,
                },
                owner,
            ),
            Some(FsWaiter::Pump { owner }) => ReapedFs::Pump(
                FsDone {
                    result,
                    refused,
                    bufs,
                    value,
                    file: file.map(File::new),
                    stat,
                    #[cfg(feature = "net-server")]
                    recv_lease,
                    #[cfg(feature = "net-server")]
                    recv_lease_more,
                    #[cfg(feature = "net-server")]
                    short,
                },
                owner,
            ),
            None => ReapedFs::None,
        }
    }

    /// Teardown-drain routing, which replies and frees but never stages, since the drain is cancelling everything.
    pub(crate) fn on_drain_cqe(&mut self, cqe: &IoUringCqe) {
        let (tag, op_slot, gen32) = unpack_raw(cqe.user_data);
        if tag & 0x80 == 0 || tag == TAG_CANCEL || tag == TAG_WAKE || tag == TAG_FILE_LEASE {
            return;
        }
        let Some(done) = self.take_op(tag, op_slot, gen32) else {
            return;
        };
        #[cfg(feature = "net-server")]
        let mut done = done;
        #[cfg(feature = "net-server")]
        let leased = done.recv_lease.take().is_some();
        #[cfg(feature = "net-server")]
        let lease_want = done.lease_want;
        let Completed {
            waiter,
            bufs,
            value,
            stat,
            ..
        } = done;
        // A short leased write answers `EIO` here too, as the live reap does.
        #[cfg(feature = "net-server")]
        let res = {
            let r = map_res(cqe.res);
            match r {
                Ok(n) if leased && (n as u32) < lease_want => Err(Errno::EIO),
                other => other,
            }
        };
        #[cfg(not(feature = "net-server"))]
        let res = map_res(cqe.res);
        // The loop is dying, so report the outcome and hand any buffers back. An OPEN's fd arrives in `cqe.res` with
        // nothing parked owning it, so wrap it here too, or it leaks. No `strip_guard_nonblock`, since no further read
        // can be submitted on this ring.
        let file = if tag == TAG_OPEN && cqe.res >= 0 {
            // SAFETY: `res` is a fresh fd OPENAT2 just returned; nothing else owns it.
            Some(Arc::new(unsafe { crate::fd::owned_from_raw(cqe.res) }))
        } else {
            None
        };
        // Teardown, not a refusal, so the outcome goes unmarked.
        deliver(waiter, res, with_value(bufs, value), file, stat);
    }

    /// Leak the op table without dropping it, used only when a teardown drain failed with ops possibly still in flight.
    /// The kernel may still write into a buffer an op entry owns until its CQE reaps, so freeing it would be a
    /// use-after-free. Pairs with `ConnTable::leak` and `Engine::leak_wake_buf`.
    pub(crate) fn leak(&mut self) {
        std::mem::forget(std::mem::take(&mut self.ops));
    }

    // ---- internals -----------------------------------------------------

    /// Return a wall-clock count parked on `retiring` - an `Allow` pair's, once the guard slot it was parked on has
    /// freed. The timer half is inline in [`FsCore::take_op`], where the same CQE decides which of the two buckets it
    /// came out of.
    fn release_retiring(&mut self, owner: (u32, u64)) {
        let Some(t) = self.armed_timers.get_mut(&owner) else {
            debug_assert!(false, "a parked wall-clock hold with no count");
            return;
        };
        t.release_park();
        if t.is_empty() {
            self.armed_timers.remove(&owner);
        }
    }

    /// Take a completed op entry out: returns its waiter and payloads and frees the slot (generation bumped) - the
    /// freed-before-fire rule.
    fn take_op(&mut self, tag: u8, op_slot: u32, gen32: u32) -> Option<Completed> {
        let entry = self.ops.get(op_slot as usize)?;
        if entry.generation as u32 != gen32 {
            return None;
        }
        match entry.state.state {
            FsOpState::InFlight { tag: t } if t == tag => {}
            _ => return None,
        }
        // An `Allow` open whose guard slot is still in flight parks its pair's charge rather than sending it home (see
        // `park` below). Checked against the guard entry itself, since `guard` stays set on an open whose guard fired
        // first, when that slot is already free and there is nothing left to meter.
        let live_guard = if tag == TAG_OPEN {
            entry.state.guard.filter(|&(gslot, ggen)| {
                self.ops.get(gslot as usize).is_some_and(|g| {
                    g.generation == ggen && g.state.state == (FsOpState::InFlight { tag: TAG_OPEN_DEADLINE })
                })
            })
        } else {
            None
        };
        let entry = &mut self.ops[op_slot as usize];
        let e = &mut entry.state;
        // A wall-clock hold's completion returns its owner's tenancy, a timer's or an `Allow` open's (`guard` still set
        // is the receipt, as a stage-failed guard never charged). Decremented here and incremented only after a
        // successful stage, so the two pair on the entry's own lifecycle.
        let charged = match (tag, &e.waiter) {
            // A retracted timer returned its cap headroom at the retraction itself (`retract_timeout`), which parked
            // the count on `retiring` until this CQE frees the slot; the unretracted endings - expiry, the teardown
            // drain, the sweep's cancel - return the armed half here instead.
            (TAG_TIMEOUT, Some(FsWaiter::Embedded { owner: Some(o), .. })) => Some((*o, e.retracted)),
            (TAG_OPEN, Some(FsWaiter::Embedded { owner: Some(o), .. })) if e.guard.is_some() => Some((*o, false)),
            _ => None,
        };
        // An `Allow` open that answers first leaves its guard slot parked until that slot's own CQE, so the count moves
        // to `retiring` rather than home, or the screen would wave through a fresh pair per unreaped guard.
        let park_on_guard = match charged {
            Some((o, _)) => live_guard.map(|g| (o, g)),
            None => None,
        };
        // The other direction: a guard slot reaped without passing `on_cqe`'s `TAG_OPEN_DEADLINE` arm - the teardown
        // drain routes every tag through here - still owes whatever its own open parked on it. Read under the tag, so
        // an ordinary completion does not touch the field at all.
        let owed_here = if tag == TAG_OPEN_DEADLINE {
            e.wall_clock.take()
        } else {
            None
        };
        // Set only where the count moved, so the receipt on the guard slot and the count on `retiring` are written by
        // the same branch.
        let mut parked = false;
        if let Some((o, retired)) = charged {
            if let Some(t) = self.armed_timers.get_mut(&o) {
                t.ended(retired);
                if park_on_guard.is_some() {
                    t.park();
                    parked = true;
                }
                if t.is_empty() {
                    self.armed_timers.remove(&o);
                }
            } else {
                debug_assert!(false, "a wall-clock hold completed with no armed count");
            }
        }
        let done = Completed {
            waiter: e.waiter.take(),
            bufs: std::mem::take(&mut e.bufs),
            value: e.value.take(),
            stat: e.stat.take(),
            retracted: e.retracted,
            guard: e.guard.take(),
            strip_nonblock: e.strip_nonblock.then(|| e.how.as_ref().map(|h| h.flags)).flatten(),
            #[cfg(feature = "net-server")]
            recv_lease: e.recv_lease.take(),
            #[cfg(feature = "net-server")]
            recv_lease_more: std::mem::take(&mut e.recv_lease_more),
            #[cfg(feature = "net-server")]
            lease_want: e.lease_want,
        };
        e.clear();
        entry.generation += 1;
        self.op_free.push(op_slot);
        // Hand the guard the owner whose count now sits on `retiring`, for its own CQE to return. Written after this
        // entry's borrow ends.
        if parked && let Some((o, (gslot, _))) = park_on_guard {
            self.ops[gslot as usize].state.wall_clock = Some(o);
        }
        if let Some(o) = owed_here {
            self.release_retiring(o);
        }
        Some(done)
    }

    /// Refuse to host an op, resolving `waiter` with the verdict now and delivering it at the next wake drain. A
    /// channel waiter is answered in place, since a send runs no consumer code. An embedded callback is queued with its
    /// `FsDone`, payload included, because the refusal is decided inside a `submit_*` holding `&mut self` on the fs
    /// tables, where consumer code cannot run. The push pokes the loop's wake, so the queue drains on the `TAG_WAKE`
    /// pass that delivers finished offloads ([`deliver_pool_completions`]), as an offload that resolved at submit time.
    /// A screen that dropped the callback instead would hand a plain-callback caller nothing but a closed connection.
    ///
    /// A marked refusal also fills the staged reason-sink share at once, with the reason only (`armed::arm`,
    /// `SlotState::Refused`). An unmarked one, the swept owner's, fills no sink, since an unmarked `ECANCELED` is the
    /// teardown vocabulary a task winds down on. A pump waiter has no callback, and its submit site reports
    /// synchronously.
    ///
    /// The queue is uncapped, as the task run queue is, since the request cap bounds in-flight work upstream. It is
    /// loop-thread state, as `FsCore` is `!Send`, and the poke that guarantees a drain rests on pokes accumulating in
    /// the eventfd counter (`eventfd_write`, `fs/eventfd.c`), which `loom_wake_pokes_accumulate` models.
    pub(super) fn refuse(
        &mut self,
        eng: &mut Engine,
        waiter: FsWaiter,
        err: Errno,
        marked: bool,
        bufs: Vec<Vec<u8>>,
        file: Option<Arc<OwnedFd>>,
    ) {
        match waiter {
            FsWaiter::Embedded { owner, cb, on_fail } => {
                let on_fail = on_fail.take();
                if marked && let Some(sink) = &on_fail {
                    (sink.fill)(err, Vec::new());
                }
                if self.refusals.is_empty() {
                    eng.shared.wake.poke();
                }
                self.refusals.push_back((
                    owner,
                    cb,
                    FsDone {
                        result: Err(err),
                        refused: marked,
                        bufs,
                        value: None,
                        file: file.map(File::new),
                        stat: None,
                        #[cfg(feature = "net-server")]
                        recv_lease: None,
                        #[cfg(feature = "net-server")]
                        recv_lease_more: Vec::new(),
                        #[cfg(feature = "net-server")]
                        short: None,
                    },
                ));
            }
            other => deliver(Some(other), Err(err), bufs, file, None),
        }
    }

    /// One queued refusal, taken for delivery; the drain owns the bound (what was queued when its pass began).
    pub(crate) fn take_refusal(&mut self) -> Option<(Owner, EmbeddedCb, FsDone)> {
        self.refusals.pop_front()
    }

    /// How many refusals the current drain pass should deliver.
    pub(crate) fn refusals_queued(&self) -> usize {
        self.refusals.len()
    }

    /// Poke the wake when a pass leaves refusals behind, since a callback that resubmits and is refused again queues
    /// mid-drain, and the poke that started the pass is already consumed.
    pub(crate) fn repoke_if_refusals_left(&self, eng: &Engine) {
        if !self.refusals.is_empty() {
            eng.shared.wake.poke();
        }
    }

    /// Fail a just-reserved op entry before its SQE reached the kernel, freeing it and answering through
    /// [`FsCore::refuse`] with the buffers handed back. An entry with no waiter, an `Allow` guard, frees silently.
    pub(super) fn fail_op(&mut self, eng: &mut Engine, op_slot: u32, err: Errno) {
        let entry = &mut self.ops[op_slot as usize];
        let e = &mut entry.state;
        let waiter = e.waiter.take();
        let bufs = with_value(std::mem::take(&mut e.bufs), e.value.take());
        // Taken out before `clear`, as the buffers are, since the caller surrendered its `File` to this submission and
        // a marked errno advises a retry that needs it.
        let file = e.file.take();
        e.clear();
        entry.generation += 1;
        self.op_free.push(op_slot);
        match waiter {
            Some(w) => self.refuse(eng, w, err, true, bufs, file),
            None => drop((bufs, file)),
        }
    }
}
