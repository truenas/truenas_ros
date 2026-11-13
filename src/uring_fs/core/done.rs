use super::*;

#[cfg_attr(not(feature = "net-server"), allow(dead_code))]
impl FsDone {
    /// A completion no op produced, making no claim about who produced the errno. [`FsDone::refused`] is the arm for a
    /// screen of this crate's own.
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

    /// A step this crate's own screen refused, carrying no payload, for a multi-step call that refuses between steps.
    /// The same screen gives a marked `EINVAL` at `open_chain`'s entry, so answering here with `failed` would make the
    /// same refusal read as teardown.
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

    /// The file this outcome carries, a successful `open`'s new one, or on a refusal
    /// ([`was_refused`](FsDone::was_refused)) of an op that targets an open file, the handle the refused submission was
    /// given, so the retry the mark advises can be made. The facade's fd ops take `File` by value, so a caller that
    /// handed in its last handle gets it back only here. A refusal never reports an opened file.
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

    /// Whether this errno is this crate's, not the kernel's, because the op never reached the ring. The facade refused
    /// the arguments (`EINVAL`), or the op table was full (`EBUSY`).
    ///
    /// Read it before acting on an errno, because the two vocabularies overlap and the actions do not. A marked `EBUSY`
    /// is worth retrying with the payload [`FsDone::into_bufs`] hands back, while the kernel's `EBUSY` is permanent for
    /// that path, as `vfs_rmdir` answers it for a mountpoint (`is_local_mountpoint`, `fs/namei.c`), so a retry loop
    /// that cannot tell them apart spins forever. `ECANCELED` with this `false` is teardown.
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
        // A refusal is not marked here, on purpose. The blocking path's public signatures return `crate::Result`, so
        // there is nowhere to put the bit, and `FsHandle::path_op` states the rule a caller needs instead.
        Some(FsWaiter::Channel(tx)) => {
            let _ = tx.send(FsOutcome::new(res, bufs, file, stat));
        }
        // The teardown drain only, as a live host refusal queues for delivery (`FsCore::refuse`). Dropping the callback
        // unfired resolves an awaited frame as its `Fire` drops, with `ECANCELED` unmarked.
        Some(FsWaiter::Embedded { cb, on_fail, .. }) => {
            drop((cb, on_fail, bufs, file, stat));
        }
        // A pump read has no callback. On a teardown drain its connection dies with the loop, and on a refusal
        // `submit_pump_read` reports to its caller synchronously.
        Some(FsWaiter::Pump { .. }) => drop((bufs, file, stat)),
        None => {}
    }
}

/// Deliver every finished offload's continuation on-loop, each with a fresh owner-scoped [`FsConn`]. Shared by the host
/// and the net server so the wake-drain is written once.
pub(crate) fn deliver_pool_completions(fs: &mut FsCore, eng: &mut Engine) {
    // Tasks woken by these deliveries run in this dispatch, so an on-loop wake inside it needs no poke. A recv buffer a
    // finished `offload_from` job released is not handed back here, since the pool is the net server's
    // (`FsCore::take_pool_releases`).
    super::task::in_pass(fs, eng, |fs, eng| {
        for (owner, deliver, any) in fs.take_pool_completions() {
            let mut conn = FsConn::new(fs, eng, owner);
            deliver(any, &mut conn);
        }
        // Host refusals deliver on the same pass, with the same fresh facade. Bounded to what was queued when the pass
        // began, so a callback refused again delivers next pass and a retry loop cannot starve the ring in one drain.
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
/// The teardown reap reaches ring ops only, so a refusal queued just before the stop, or an offload whose worker
/// finished after it, would otherwise die unfired with the payload it was handing back. This keeps
/// [`FsConn::offload`]'s promise that its delivery always fires.
///
/// **Called before the teardown reap**, so whatever a callback here stages is cancelled and reaped with the rest. **One
/// pass only**, bounded as [`deliver_pool_completions`] is, so a consumer's retry loop cannot hold teardown open.
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
