use super::*;

impl FsCore {
    // ---- cancellation --------------------------------------------------

    /// Stage an `ASYNC_CANCEL` for the in-flight op named by `target_ud`. Its own completion is ignored
    /// ([`TAG_CANCEL`], which `on_cqe` drops); the cancelled op completes with `ECANCELED` and its CQE runs `take_op`
    /// like any other, dropping the parked `Arc` (close-last). Takes no op-table slot -- nothing routes its
    /// completion - but goes through `eng.stage` so the engine's in-flight accounting stays correct.
    ///
    /// **Best-effort, and nothing may hang off it having reached the kernel.** `push_sqe` answers `EBUSY` when a full
    /// SQ meets a `submit` that accepted nothing - a CQ-overflow backpressure return is `Ok` with the SQEs still staged
    /// (`Ring::submit`) - so a healthy ring under load reaches this, not only a failing `io_uring_enter`. A cancel that
    /// never staged leaves the op running to its own ending, which the teardown drain reaps. [`FsCore::retract_op`]'s
    /// mark is what the callers' verdicts are built on for exactly that reason: the mark records the ask, and the ask
    /// is answerable whether or not the hastening arrived.
    pub(super) fn submit_cancel(&self, eng: &mut Engine, target_ud: u64) {
        let ud = pack_raw(TAG_CANCEL, 0, 0);
        let _ = eng.stage(ud, |sqe| {
            sqe.opcode = IORING_OP_ASYNC_CANCEL;
            sqe.addr = target_ud; // cancel the op whose user_data == target_ud
        });
    }

    /// Cancel every in-flight op owned by `owner` - the connection-teardown sweep. Replaces the removed
    /// `close_owned_by`: with plain-fd files a connection's fds close by `Arc`-drop, but an op still **in flight**
    /// parks its fd until the CQE, and a closed connection's op is otherwise never cancelled (a never-completing read
    /// would pin the fd until server teardown). Cancelling - not force-dropping the entry - is required: the kernel op
    /// may still touch the fd or a buffer, so the entry must live until its (now-`ECANCELED`) CQE reaps it.
    ///
    /// **This runs once per close, and it is not a liveness gate.** A continuation of a cancelled op runs after the
    /// sweep, with the same stamped owner, and whatever it submits then is not swept again - which is the same "an
    /// owner gone mid-chain" a continuation must already tolerate, and deliberately still allowed: a handler finishing
    /// an upload it already accepted has work to do that the peer's disconnect does not undo. A second sweep is not the
    /// answer either, and would be unbounded - a continuation that resubmits on `ECANCELED` keeps giving it something
    /// to find, and the sweep's own `ECANCELED` completions are what wake the continuations that resubmit.
    ///
    /// So the bound is the continuation's, not this function's, and [`FsCore::owner_is_gone`] - recorded here - is what
    /// makes it reachable. Two shapes need it, because for them a post-sweep op does *not* simply complete and stop:
    ///
    /// - An open with [`SpecialFiles::Allow`](super::SpecialFiles), whose own rustdoc says it "hangs an io-wq worker
    ///   and a caller thread permanently, with no timeout anywhere to recover it".
    ///   Cancelling reaches it while in flight; a fresh one afterwards has nothing left to reach it.
    /// - A task awaiting only offloads, which are never cancelled and always deliver (see [`FsConn::offload`]) - so
    ///   neither of the two signals [`super::task`] tells a task to wind down on ever arrives, and a re-arming one runs
    ///   for a connection that is gone, counted in `tasks.live` and holding a graceful drain open with it.
    ///
    /// **Takes the whole batch of closes, because the scan is the cost.** A close is recorded unconditionally - the
    /// host cannot know whether a handler opened anything - so a connection that served one cached GET still arrives
    /// here, and one scan per owner walks the table `fs_ops + pool_size` entries deep, once each, on the reactor
    /// thread. Sorted so the membership test is a binary search: the batch is bounded by the connection table and a
    /// linear test would make a mass disconnect quadratic. The empty-table check ahead of it is what an idle server
    /// actually hits.
    #[cfg_attr(not(feature = "net-server"), allow(dead_code))]
    pub(crate) fn cancel_owned_by(&mut self, eng: &mut Engine, mut owners: Vec<(u32, u64)>) {
        // Recorded before the scan, so a continuation woken by one of the cancellations below already reads its owner
        // as gone - and recorded whether or not there is anything to cancel, since that is what a task with no ring op
        // reads.
        for &(slot, generation) in &owners {
            let swept = self.closed_owners.entry(slot).or_insert(generation);
            *swept = (*swept).max(generation);
        }
        // Bounded by the in-flight count: a slot is in `op_free` iff free (all four push sites clear the entry and bump
        // the generation first), so the difference is exactly how many in-flight entries the scan can meet, and it
        // stops once it has seen them all. That break already lands at one past the highest in-flight index, so the
        // count is a position bound too - a further position term cannot improve on it (a `scan_high` water mark was
        // measured within one entry of this bound in every reachable state, and 1,950 entries looser after a drained
        // burst, because LIFO reuse keeps re-raising it). What would escape the highest-index term is *membership* -
        // iterating an occupied-slot list or bitmap instead of scanning toward a count - at a cost on every
        // submit/complete for a saving on the close path; the sweep stays a scan until that trade is worth it. The
        // empty-table early-out above is what an idle server hits.
        let mut in_flight = self.ops.len() - self.op_free.len();
        // The premise, checked in the direction that hurts, and only that one: a count too *low* (a slot pushed to
        // `op_free` twice) breaks the walk early and silently leaves live ops uncancelled, in both profiles, and only
        // the derived figure against the table's own census sees that.
        //
        // `>=`, not equality: a slot popped for an op whose state is not set yet counts as in flight here and not in
        // the census, and that window is legitimate - unobservable from this function's one production caller, which
        // runs from the reactor's top-level loop, but not something to assert away. Which is also why the walk below
        // ends with no assertion on what is left of the count: a remainder is exactly that window, every in-flight
        // entry having been visited, and a detector that fires on a state its own premise documents as legitimate
        // reports the wrong thing twice - once by firing, and once by reading as though it were watching something.
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
            // An `Allow` open's guard: fired (`-ETIME`), retracted by the open completing first (`-ECANCELED`), or
            // swept. Its slot frees here; only a genuine firing stages the cancel
            // - a retracted or stale guard must not cancel whoever
            // holds the open's slot now, which the token's generation already prevents.
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
                // Mark, then cancel (`retract_op`). The mark is what makes the open's `ECANCELED` carry the deadline's
                // verdict (`was_refused` true, like a retracted timer's) instead of the unmarked form reserved for
                // teardown - which a task winds a live connection down on (`task.rs`). An open that already answered
                // - its slot freed or reissued - is left alone, and
                // the cancel is skipped with it.
                //
                // The screen is the *cancellation*, not the firing. A guard that ends any other way has stopped
                // bounding an open that is still running, and the reachable one is not `-ETIME`: the SQE is accepted by
                // `push_sqe` - charge taken, cancel target recorded - while `__io_timeout_prep` runs later inside
                // `io_uring_enter` and can still answer `-ENOMEM` (`io_uring/timeout.c:554-556`), with
                // `io_submit_fail_init` posting a CQE under the guard's own tag. Left uncancelled, an `Allow` open
                // parks in `fifo_open`'s `wait_for_partner` on a peer-planted FIFO for as long as the peer likes,
                // holding an io-wq worker, its op slot and its owner's wall-clock charge. An unmarked `ECANCELED` is
                // the one ending that must NOT cancel here: it is a sweep (`cancel_owned_by`) or teardown, which stages
                // the open's own cancel and needs its `ECANCELED` to stay in teardown's vocabulary.
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
        // The open answered, so its guard timer's hour is over: mark and cancel it (`retract_op`) - the mark keeps its
        // `ECANCELED` from staging a cancel of a slot the open no longer holds, and the generation check makes a stale
        // pair inert.
        if let Some((gslot, ggen)) = guard {
            self.retract_op(eng, TAG_OPEN_DEADLINE, gslot, ggen);
        }

        // A successful OPENAT2 returns a real fd as its result; wrap it in an `Arc<OwnedFd>`. If nobody takes it (a
        // gone channel receiver, or a dropped embedded callback) the `Arc` drops and the fd closes - no leak, no
        // explicit close op. The op entry's parked `file` `Arc` (for an fd op) was already dropped by `take_op`'s
        // `clear`, giving close-last ordering by ownership.
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
        // A timer's expiry is its success: a pure `IORING_OP_TIMEOUT` (count 0) completes `-ETIME` when it fires, and
        // that firing is the completion the caller asked for.
        //
        // Unless the caller retracted it, in which case the deadline is gone whatever the kernel did with the cancel,
        // and `Ok(0)` - this crate's spelling for "the deadline arrived" - would run a timeout handler for work the
        // caller already finished. The retraction cannot make the cancel win: `io_timeout_fn` delists the timeout
        // before posting `-ETIME` (`io_uring/timeout.c:254-276`), so an `ASYNC_CANCEL` that arrives after the fire
        // finds nothing (`io_timeout_extract`, `:278-303`) and the `-ETIME` stands - and `submit_cancel` is best-effort
        // besides, so the cancel may never have been staged at all. The mark is the caller's ask, and it is what
        // decides the verdict; the errno then reads as the marked cancellation `refused` computes below, exactly as a
        // cancel that won would have delivered.
        if tag == TAG_TIMEOUT && result == Err(Errno::ETIME) {
            result = if retracted { Err(Errno::ECANCELED) } else { Ok(0) };
        }
        // A cancellation that was asked for is not the reactor going away: `ECANCELED` with `was_refused` false stays
        // meaning teardown alone (the vocabulary a task winds down on), so the answer a `cancel_timeout` staged - or an
        // `Allow` open's own tripped deadline - carries the mark. Gated on the errno as well as the flag: if the op
        // answered before the cancel reached it, that answer stands and is not a cancellation. A deadline that catches
        // the open's worker mid-sleep can also surface as `EINTR` (the cancel arrives as a signal, and `map_res` folds
        // `-ERESTARTSYS` the way the kernel's rw path does) - a kernel verdict, left unmarked; only the `ECANCELED`
        // spelling ever collided with teardown's.
        let refused = retracted && result == Err(Errno::ECANCELED);
        // A short leased write is unrecoverable, so it must not look like success: the source was the connection's
        // receive buffer, and this completion is what returns it to the pool - by the time a caller saw `Ok(n)` the
        // unwritten bytes could hold another connection's request, so a retry from them writes someone else's data and
        // a shrug stores a truncated object. ZFS makes the case real: a partial write returns its count with no error,
        // by design. The copy path stays retryable (`FsDone::into_bufs` hands the source back), which is the one honest
        // asymmetry between the two.
        // The count still goes out beside the `EIO`, for a caller that answers it rather than retrying.
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

    /// Teardown-drain routing: reply and free, but never stage (the drain is cancelling everything; deferred closes are
    /// moot - the ring teardown closes the whole registered table).
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
        // A short leased write is unrecoverable on this path too, and the reason does not soften at teardown: the
        // source was the connection's receive buffer, so a caller told `Ok(n)` cannot retry from bytes it no longer
        // owns, and a caller that shrugs stores a truncated object. The live reap rewrites it; without the same rewrite
        // here a drain is the one way to observe the count.
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
        // Teardown: the loop is dying - just report the outcome and hand any buffers back. A file's fd is released when
        // its op entry (and thus its parked `Arc`) is dropped with the ring teardown - except an OPEN's, which arrives
        // in `cqe.res` with nothing parked owning it (the live path is what builds the `Arc` from the result). Wrap it
        // here too, so the waiter takes an owned file or its drop closes the descriptor instead of leaking it.
        // No `strip_guard_nonblock` here, unlike the live reap: the loop is dying, so no further read can be submitted
        // on this ring, and the guard flag's only effect is on where a read of this descriptor would run.
        let file = if tag == TAG_OPEN && cqe.res >= 0 {
            // SAFETY: `res` is a fresh fd OPENAT2 just returned; nothing else owns it.
            Some(Arc::new(unsafe { crate::fd::owned_from_raw(cqe.res) }))
        } else {
            None
        };
        // Teardown, not a refusal: the loop is dying, so nothing here is worth retrying and `ECANCELED` is the honest
        // answer.
        deliver(waiter, res, with_value(bufs, value), file, stat);
    }

    /// Leak the op table without dropping it - used ONLY when a teardown drain failed with ops possibly still in
    /// flight. The kernel may still write into a `READV`/`FGETXATTR` destination or the boxed `STATX` buffer until its
    /// CQE reaps, so freeing those here would be a use-after-free; forget them instead (mirrors the net stack's
    /// `ConnTable::leak`, and pairs with `Engine::leak_wake_buf`). Only the op table owns kernel-visible memory; the
    /// file table does not.
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
        // An `Allow` open whose guard slot is still in flight: the pair charged one count for two slots, so the charge
        // outlives this CQE and has to park rather than go home (see `park` below). Checked against the guard entry
        // itself, because `guard` stays set on an open whose guard fired *first* - in that ordering the guard's slot is
        // already free (and possibly reissued) and there is nothing left to meter.
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
        // A wall-clock hold's completion returns its owner's tenancy: a timer's - expiry, retraction, or the teardown
        // drain - and an `Allow` open's, whose pair charged one count when its guard staged (`guard` still set is the
        // receipt; a stage-failed guard never charged). Decremented here and incremented only after a successful stage,
        // so the two are paired on the entry's own lifecycle whoever staged the cancel.
        let charged = match (tag, &e.waiter) {
            // A retracted timer returned its cap headroom at the retraction itself (`retract_timeout`), which parked
            // the count on `retiring` until this CQE frees the slot; the unretracted endings - expiry, the teardown
            // drain, the sweep's cancel - return the armed half here instead.
            (TAG_TIMEOUT, Some(FsWaiter::Embedded { owner: Some(o), .. })) => Some((*o, e.retracted)),
            (TAG_OPEN, Some(FsWaiter::Embedded { owner: Some(o), .. })) if e.guard.is_some() => Some((*o, false)),
            _ => None,
        };
        // An `Allow` open that answers first leaves its guard slot parked until that slot's own CQE, so returning the
        // whole charge here would leave a held slot metered by nothing and let the arm screen wave through a fresh pair
        // per unreaped guard - the cap counting arms while the table pays in slots. The count moves to `retiring`, the
        // same bucket a retracted timer parks on for the same window, and the guard carries the owner that owes it.
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
        // Set only where the count actually moved, so the receipt on the guard slot and the count on `retiring` are
        // written by the same branch: a park recorded against a charge that was not there would have the guard's CQE
        // return a count nobody took.
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
        // Hand the guard the owner whose count now sits on `retiring`, for its own CQE to return (`on_cqe`'s
        // [`TAG_OPEN_DEADLINE`] arm). Written after this entry's borrow ends, so the two slots are touched one at a
        // time.
        if parked && let Some((o, (gslot, _))) = park_on_guard {
            self.ops[gslot as usize].state.wall_clock = Some(o);
        }
        if let Some(o) = owed_here {
            self.release_retiring(o);
        }
        Some(done)
    }

    /// Refuse to host an op: resolve `waiter` with the verdict now and deliver it at the next wake drain. A channel
    /// waiter is answered in place (a send runs no consumer code, so there is no re-entrancy to defer around); an
    /// embedded callback is **queued with its `FsDone`** - payload included, so a refused write hands its buffers back
    /// through the same callback a completion would - because the refusal is decided inside a `submit_*` holding `&mut
    /// self` on the fs tables, where consumer code cannot run. The push pokes the loop's wake, so the queue drains on
    /// the same `TAG_WAKE` pass that delivers finished offloads ([`deliver_pool_completions`]); a refusal is
    /// structurally an offload that resolved at submit time.
    ///
    /// A *marked* refusal also fires the staged reason-sink share synchronously (reason only - the payload rides the
    /// queue), which is what an awaited frame reads before its callback route settles (`armed::arm`,
    /// `SlotState::Refused`). An unmarked one (the swept owner's) fires no sink on purpose: the delivered `ECANCELED`
    /// with [`FsDone::was_refused`] false is the teardown vocabulary a task winds down on, in both orderings. A pump
    /// waiter has no callback and its submit site reports synchronously; it drops here as before.
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

    /// How many refusals the current drain pass should deliver, and a re-poke when a pass leaves any behind - a
    /// callback that resubmits and is refused again queues mid-drain, and the poke that started the pass is already
    /// consumed.
    pub(crate) fn refusals_queued(&self) -> usize {
        self.refusals.len()
    }

    pub(crate) fn repoke_if_refusals_left(&self, eng: &Engine) {
        if !self.refusals.is_empty() {
            eng.shared.wake.poke();
        }
    }

    /// Fail a just-reserved op entry before its SQE ever reached the kernel: report and free (buffers go back to the
    /// caller, as on completion), on [`FsCore::refuse`]'s delivery - the one shape every host refusal takes. An entry
    /// with no waiter (an `Allow` guard) frees silently; there is nobody to answer.
    pub(super) fn fail_op(&mut self, eng: &mut Engine, op_slot: u32, err: Errno) {
        let entry = &mut self.ops[op_slot as usize];
        let e = &mut entry.state;
        let waiter = e.waiter.take();
        let bufs = with_value(std::mem::take(&mut e.bufs), e.value.take());
        // Taken out before `clear`, for the same reason the buffers are:
        // the caller surrendered its `File` to this submission, so dropping the parked `Arc` here closes the descriptor
        // of a caller being told a *marked* errno - the one `FsDone::was_refused` documents as worth retrying. A retry
        // needs the file.
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
