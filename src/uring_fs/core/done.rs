use super::*;

#[cfg_attr(not(feature = "net-server"), allow(dead_code))]
impl FsDone {
    /// A completion no op produced, with **no** claim about who produced the errno: the kernel's own verdict forwarded
    /// from somewhere else, or an outcome whose provenance is not this crate's to assert. [`FsDone::refused`] is the
    /// arm for a screen of this crate's own.
    pub(crate) fn failed(err: Errno) -> FsDone {
        FsDone {
            result: Err(err),
            refused: false,
            bufs: Vec::new(),
            value: None,
            file: None,
            stat: None,
            #[cfg(feature = "net-server")]
            recv_lease: None,
            #[cfg(feature = "net-server")]
            recv_lease_more: Vec::new(),
            #[cfg(feature = "net-server")]
            short: None,
        }
    }

    /// A step this crate's own screen refused, carrying no payload - what a multi-step call answers with when it
    /// refuses *between* steps.
    ///
    /// Provenance has to be the same at both ends of a chain or it says nothing: the very screen that gives `EINVAL`
    /// with [`was_refused`](FsDone::was_refused) true at `open_chain`'s entry gives it again on a derived name three
    /// steps in, and answering the second with `failed` makes the same refusal read as `ECANCELED`-class teardown to
    /// the awaiting task.
    pub(crate) fn refused(err: Errno) -> FsDone {
        FsDone::refused_with(err, Vec::new())
    }

    /// A submission the facade or the core refused, with the payload it was handed back - see [`FailSink`] and
    /// [`FsDone::was_refused`].
    pub(crate) fn refused_with(err: Errno, bufs: Vec<Vec<u8>>) -> FsDone {
        FsDone {
            result: Err(err),
            refused: true,
            bufs,
            value: None,
            file: None,
            stat: None,
            #[cfg(feature = "net-server")]
            recv_lease: None,
            #[cfg(feature = "net-server")]
            recv_lease_more: Vec::new(),
            #[cfg(feature = "net-server")]
            short: None,
        }
    }

    /// The recv-pool buffer a leased write borrowed, for the net server to hand back. Taken by the dispatch before the
    /// callback runs, so a consumer never sees it.
    #[cfg(feature = "net-server")]
    pub(crate) fn take_recv_lease(&mut self) -> Option<u16> {
        self.recv_lease.take()
    }

    /// The further buffers a gathered leased write borrowed ([`FsConn::pwritev2_leased`]), taken beside
    /// [`take_recv_lease`](Self::take_recv_lease) and for the same reason.
    #[cfg(feature = "net-server")]
    pub(crate) fn take_recv_lease_more(&mut self) -> Vec<u16> {
        std::mem::take(&mut self.recv_lease_more)
    }

    /// The count a short leased write wrote before it answered `EIO` ([`FsConn::pwritev2_from`],
    /// [`FsConn::pwritev2_leased`]), for a caller that never retries one but must still answer how much was written.
    /// `None` for every other outcome, a full leased write and a short copied or owned one among them, which answer
    /// their count as `Ok(n)`.
    #[cfg(feature = "net-server")]
    pub fn short_count(&self) -> Option<usize> {
        self.short
    }

    /// The op's result: a byte count / `0`, or the errno it failed with.
    pub fn result(&self) -> crate::Result<i32> {
        self.result.map_err(Into::into)
    }

    /// The raw result, errno unwrapped - for the reply-path pump, which maps a failure to a
    /// [`CloseReason`](crate::net::server::CloseReason) carrying the errno itself.
    #[cfg(feature = "net-server")]
    pub(crate) fn raw_result(&self) -> Result<i32, Errno> {
        self.result
    }

    /// The file this outcome carries: a successful `open`'s new one, or - on a refusal
    /// ([`was_refused`](FsDone::was_refused)) of an op that targets an open file - the very handle the refused
    /// submission was given back, so the retry the mark advises can actually be made.
    ///
    /// The facade's fd-ops take `File` **by value**, so a caller that hands in its last handle has surrendered it.
    /// Dropping it on a capacity refusal closed the descriptor under a caller told `EBUSY` with
    /// [`into_bufs`](FsDone::into_bufs) handing the payload back for a retry that had nothing left to write to. Nothing
    /// here reports an *opened* file for a refusal: a refusal never reached the ring.
    pub fn file(&self) -> Option<File> {
        self.file.clone()
    }

    /// Take the op's buffers back (read destinations / xattr value). An xattr op's value comes back as the one buffer,
    /// in an outer `Vec` built here for it, which [`into_value`](FsDone::into_value) spares.
    pub fn into_bufs(self) -> Vec<Vec<u8>> {
        with_value(self.bufs, self.value)
    }

    /// Take back the one buffer of an op that was handed one, the value an `fsetxattr` set or an `fgetxattr` read into,
    /// the buffer of [`FsConn::pread_spare`] or that of [`FsConn::pwritev2_owned`]. It comes with no outer `Vec` around
    /// it, so a caller that keeps its buffers allocates nothing to have one back. A refused op gives its buffer back
    /// here too.
    pub fn into_value(self) -> Vec<u8> {
        let FsDone { value, mut bufs, .. } = self;
        value.or_else(|| bufs.pop()).unwrap_or_default()
    }

    /// Whether this errno is **this crate's**, not the kernel's: the op never reached the ring, because the facade
    /// refused the arguments (`EINVAL`) or the op table was full (`EBUSY`).
    ///
    /// Read it before acting on an errno, because the two vocabularies overlap and the actions do not. `EBUSY` here is
    /// the documented fan-out failure, worth retrying with the payload [`FsDone::into_bufs`] hands back; `EBUSY` from
    /// the kernel is permanent for that path - `vfs_rmdir` answers it for a directory that is a mountpoint
    /// (`is_local_mountpoint`, `fs/namei.c`), and a nested dataset is exactly that under its parent, so a retry loop
    /// that cannot tell the two apart spins forever on the thread that serves every other connection. `ECANCELED` with
    /// this `false` is teardown.
    pub fn was_refused(&self) -> bool {
        self.refused
    }

    /// The `statx` metadata - present only for a successful `statx`.
    ///
    /// The pad is allocated before submission and zeroed, and the kernel returns from `do_statx` before it writes any
    /// of it, so a failed op leaves a pad that would read as size 0, mode 0 and a 1970 mtime. Gated on the result for
    /// the same reason [`FsDone::file`] is.
    pub fn stat(&self) -> Option<Statx> {
        self.result.ok()?;
        self.stat.as_deref().copied().map(Statx::from_raw)
    }
}

pub(super) fn deliver(
    waiter: Option<FsWaiter>,
    res: Result<i32, Errno>,
    bufs: Vec<Vec<u8>>,
    file: Option<Arc<OwnedFd>>,
    stat: Option<Box<StatxRaw>>,
) {
    match waiter {
        // A refusal is *not* marked on the way out here, and the asymmetry with the embedded path is deliberate rather
        // than missed. The blocking path's public signatures return `crate::Result`, so there is nowhere to put the bit
        // without redesigning them; `FsHandle::path_op` carries the rule a caller needs instead, and names the facade
        // path that does report provenance. Surface it here the day a channel consumer can act on it.
        Some(FsWaiter::Channel(tx)) => {
            let _ = tx.send(FsOutcome::new(res, bufs, file, stat));
        }
        // The teardown drain only, now that a live host refusal queues for delivery (`FsCore::refuse`): the loop is
        // dying, nothing will drain a queue, and dropping the callback unfired is the one shape left - which resolves
        // an awaited frame as its `Fire` drops, `ECANCELED` unmarked, teardown's own vocabulary.
        Some(FsWaiter::Embedded { cb, on_fail, .. }) => {
            drop((cb, on_fail, bufs, file, stat));
        }
        // A pump read has no callback to drop and nowhere to route from here: on a teardown drain the owning connection
        // is dying with the loop, and on a refusal (`FsCore::refuse`) `submit_pump_read` reports the error to its
        // caller synchronously. The payloads just drop.
        Some(FsWaiter::Pump { .. }) => drop((bufs, file, stat)),
        None => {}
    }
}

/// Deliver every finished offload's continuation on-loop, each with a fresh owner-scoped [`FsConn`]. Shared by the host
/// and the net server so the wake-drain is written once.
pub(crate) fn deliver_pool_completions(fs: &mut FsCore, eng: &mut Engine) {
    // Tasks woken by these deliveries - or poked from off-loop, which lands on the same wake the pool uses - run in
    // this dispatch, and an on-loop wake inside it needs no poke to say so.
    //
    // A recv buffer a finished `offload_from` job released is *not* handed back here: the pool is the net server's, so
    // the wake handler that called this takes `FsCore::take_pool_releases` afterwards.
    super::task::in_pass(fs, eng, |fs, eng| {
        for (owner, deliver, any) in fs.take_pool_completions() {
            let mut conn = FsConn::new(fs, eng, owner);
            deliver(any, &mut conn);
        }
        // Host refusals resolved at submit time deliver on the same pass, with the same fresh owner-scoped facade a
        // completion gets. Bounded to what was queued when the pass began: a callback that resubmits and is refused
        // again queues behind the re-poke below and delivers next pass, so a retry loop pays a wake round-trip per
        // attempt instead of starving the ring from inside one drain.
        for _ in 0..fs.refusals_queued() {
            let Some((owner, cb, done)) = fs.take_refusal() else {
                break;
            };
            let mut conn = FsConn::new(fs, eng, owner);
            cb(done, &mut conn);
        }
        fs.repoke_if_refusals_left(eng);
    });
}

/// Deliver what the stop window left queued, once the loop has stopped.
///
/// `run_loop` exits on `stopping()` and the teardown reap reaches ring ops only, so a refusal queued in the window
/// before the stop - and an offload whose worker finished after it - is delivered by nothing: the callback dies unfired
/// with the payload it was handing back, which for a refused write is its buffers. An offload is not a ring op at all,
/// so `cancel_and_reap_all` cannot reach it however long it runs, and [`FsConn::offload`]'s promise that "the job
/// always runs to completion and its delivery always fires" is the thing being kept here.
///
/// **Called before the teardown reap, not after**: a callback firing here may submit, and the ring is still whole, so
/// whatever it stages is cancelled and reaped like any other in-flight op instead of being staged into a ring already
/// torn down.
///
/// **One pass, which is the whole guarantee.** The pass is already bounded to what was queued when it began
/// ([`deliver_pool_completions`]), so a callback that resubmits, is refused again and queues behind it is *not*
/// covered - deliberately. Running to quiescence instead would let a consumer's retry loop hold teardown open for as
/// long as it liked, and what a callback asks for during teardown is going nowhere anyway: its op would be cancelled
/// with the rest, and a plain callback dropped unfired already means the connection closes.
pub(crate) fn drain_stop_window(fs: &mut FsCore, eng: &mut Engine) {
    // The teardown below blocks without parking, so flush what the last iteration queued.
    fs.flush_offloads();
    deliver_pool_completions(fs, eng);
}

/// Fire an embedded on-loop completion reaped by [`FsCore::on_cqe`] with a fresh owner-scoped [`FsConn`]; a no-op when
/// `on_cqe` returned [`ReapedFs::None`] (a channel op already delivered, or an inert stale CQE). Shared by the host and
/// the net server so the CQE hand-back is written once. A [`ReapedFs::Pump`] never reaches here: only the net server
/// submits pump reads, and its dispatch routes them before this call.
pub(crate) fn deliver_embedded(fs: &mut FsCore, eng: &mut Engine, reaped: ReapedFs) {
    // A completion that resolves an op future wakes its task from inside the callback below; the drain that follows
    // polls it, so the wake needs no poke to reach the loop. See `task::in_pass`.
    super::task::in_pass(fs, eng, move |fs, eng| match reaped {
        ReapedFs::Embedded(cb, done, owner) => {
            let mut conn = FsConn::new(fs, eng, owner);
            cb(done, &mut conn);
        }
        ReapedFs::Pump(..) => {
            unreachable!("pump reads are routed by the net server")
        }
        ReapedFs::FileLeaseBreaks(broken) => {
            FileLeases::deliver(fs, eng, broken);
        }
        ReapedFs::None => {}
    });
}
