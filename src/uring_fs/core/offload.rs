use super::*;

impl FsCore {
    // ---- off-loop offload: run a blocking job, deliver its result on-loop ----

    /// Register `deliver` (owner-scoped) for a new offload; returns its token.
    pub(super) fn register_offload(&mut self, owner: Owner, deliver: OffloadDeliver) -> u64 {
        let token = self.next_offload;
        self.next_offload = self.next_offload.wrapping_add(1);
        self.offload_reg.insert(
            token,
            OffloadEntry {
                owner,
                deliver,
                #[cfg(feature = "net-server")]
                lease: None,
            },
        );
        token
    }

    /// [`register_offload`](Self::register_offload) for a job that reads a leased recv buffer: `hold` is the job's
    /// share of the claim, kept with the continuation and dropped when the completion is taken.
    #[cfg(feature = "net-server")]
    pub(super) fn register_leased_offload(
        &mut self,
        owner: Owner,
        deliver: OffloadDeliver,
        hold: std::sync::Arc<LeaseHold>,
    ) -> u64 {
        let token = self.register_offload(owner, deliver);
        if let Some(e) = self.offload_reg.get_mut(&token) {
            e.lease = Some(hold);
        }
        token
    }

    /// A clone of the completion queue for a worker job to push its result onto.
    pub(super) fn completion_sink(&self) -> Arc<Mutex<VecDeque<PoolCompletion>>> {
        Arc::clone(&self.completions)
    }

    /// A clone of this reactor's shared offload pool, for minting an [`FsHandle`](super::FsHandle) that submits
    /// blocking work to the same pool off-loop.
    pub(crate) fn pool_handle(&self) -> Arc<SharedPool> {
        Arc::clone(&self.pool)
    }

    /// Queue `job` on this reactor's shared offload pool (spawned on first use) without waking a worker; the loop wakes
    /// the pool once per iteration ([`Self::flush_offloads`]). If a worker thread cannot be spawned the job runs inline
    /// rather than take the reactor down; see [`SharedPool::enqueue`].
    pub(super) fn submit_offload(&mut self, job: Box<dyn FnOnce() + Send>) {
        self.pool.enqueue(job);
        self.pending_offloads += 1;
    }

    /// Size the lookup lane. The host calls it before its loop runs, so the lane it replaces has spawned nothing.
    #[cfg(any(test, feature = "net-server"))]
    pub(crate) fn set_lookup_bounds(&mut self, bounds: OffloadBounds) {
        self.lookup = SharedPool::new(LOOKUP_WORKER, bounds);
    }

    /// Queue `job` on the lookup lane as [`Self::submit_offload`] queues on the file pool, or hand it back when the
    /// lane has no thread to run it ([`SharedPool::try_enqueue`]).
    pub(super) fn submit_lookup(&mut self, job: Job) -> Result<(), Job> {
        self.lookup.try_enqueue(job)?;
        self.pending_lookups += 1;
        Ok(())
    }

    /// Wake the pool for everything queued since the last flush, and return how long the loop may sleep before it must
    /// flush again ([`WorkerPool::flush`]).
    ///
    /// The loop calls this every iteration right before it can block, and before its teardown drain. It bounds its
    /// sleep by the return (`Ring::submit_and_wait_for`), which also covers deadlines published by off-loop submitters
    /// ([`SharedPool::submit`]).
    ///
    /// An iteration that queued nothing skips the pool's lock until the deadline is due. The deadline moves earlier
    /// only when the last claimed worker starts its job, so the check can run up to `OFFLOAD_WAKE_ALLOWANCE` late.
    ///
    /// Both pools are flushed, the file pool and the lookup lane, and the sooner of their deadlines is returned.
    ///
    /// [`WorkerPool::flush`]: super::offload_pool::WorkerPool::flush
    pub(crate) fn flush_offloads(&mut self) -> Option<std::time::Duration> {
        let file = std::mem::take(&mut self.pending_offloads);
        let lookups = std::mem::take(&mut self.pending_lookups);
        let file = flush_pool(&self.pool, file);
        let lookups = flush_pool(&self.lookup, lookups);
        file.into_iter().chain(lookups).min()
    }

    /// Remove a **server-owned** extended attribute on the blocking pool, gated on the
    /// [`PrivilegedXattrs`](crate::uring_fs::PrivilegedXattrs) allowlist. Refuses anything unlisted with `EPERM`.
    ///
    /// This is the one fs mutation in the module that carries no [`Personality`], and the allowlist is what makes that
    /// defensible rather than a hole. There is no `IORING_OP_*REMOVEXATTR`, and a zero-length `FSETXATTR` sets an empty
    /// attribute instead of removing one (see [`remove_xattr_blocking`]) - so the call can only run on a pool thread,
    /// under the reactor's own credentials, with no way for the kernel to check it against a request identity.
    /// Restricting it to attributes the *server* owns keeps the promotion keyed on the name alone, exactly as the
    /// `FSETXATTR` promotion in [`FsCore::submit_fd_meta`] is: a caller can clear the metadata this reactor wrote, and
    /// nothing else.
    pub(crate) fn remove_priv_xattr(&mut self, file: Arc<OwnedFd>, name: Cow<'static, CStr>, reply: ReplyTo) {
        if !self.priv_xattrs.permits(&name) {
            let _ = reply.send(FsOutcome::new(Err(Errno::EPERM), Vec::new(), None, None));
            return;
        }
        self.submit_offload(Box::new(move || {
            let raw = file.as_raw_fd();
            // SAFETY: the closure owns `file` for the syscall's duration, so `raw` is live; `name` is NUL-terminated.
            let res = retry_on_eintr(|| unsafe { libc::fremovexattr(raw, name.as_ptr()) }).map(|_| 0i32);
            let _ = reply.send(FsOutcome::new(res, Vec::new(), None, None));
        }));
    }

    /// Take every finished offload paired with its owner + continuation. The caller fires each with a fresh
    /// owner-scoped [`FsConn`] once its borrow of the fs tables has ended (mirrors [`FsCore::on_cqe`]'s hand-back).
    /// Called from the loop's `TAG_WAKE` handler.
    #[cfg_attr(not(feature = "net-server"), allow(dead_code))]
    pub(crate) fn take_pool_completions(&mut self) -> Vec<PoolDelivery> {
        let drained: Vec<PoolCompletion> = {
            let mut q = self.completions.lock().unwrap_or_else(|e| e.into_inner());
            q.drain(..).collect()
        };
        let mut out = Vec::with_capacity(drained.len());
        for (token, any) in drained {
            if let Some(e) = self.offload_reg.remove(&token) {
                // The job is over - its result is in hand - so its share of the recv claim ends here, on the reactor.
                // The buffer surfaces only from the last share, as a leased write's completion surfaces it (`on_cqe`);
                // sibling writes of the same delivery may still be reading it.
                #[cfg(feature = "net-server")]
                if let Some(bid) = e
                    .lease
                    .and_then(std::sync::Arc::into_inner)
                    .and_then(|hold| hold.take_bid(&self.lease_returns))
                {
                    self.pool_releases.push(bid);
                }
                out.push((e.owner, e.deliver, any));
            }
        }
        out
    }

    /// The recv-pool buffers finished offload jobs, and shares dropped elsewhere, have released since the last call,
    /// for the net server to hand back to its pool. Empty on a host with no pool.
    #[cfg(feature = "net-server")]
    pub(crate) fn take_pool_releases(&mut self) -> Vec<u16> {
        let mut out = std::mem::take(&mut self.pool_releases);
        out.extend(self.lease_returns.lock().unwrap_or_else(|e| e.into_inner()).drain(..));
        out
    }

    /// The return road for a share minted against this core: the queue [`take_pool_releases`](Self::take_pool_releases)
    /// drains, and the loop's wake.
    #[cfg(feature = "net-server")]
    pub(super) fn lease_returns(&self, wake: &Arc<crate::uring::wake::LoopShared>) -> LeaseReturns {
        LeaseReturns {
            queue: Arc::clone(&self.lease_returns),
            wake: Arc::clone(wake),
        }
    }
}
