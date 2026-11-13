//! The standalone host: [`UringFs`] owns the engine and the fs core, runs the completion loop on its thread, and mints
//! the cross-thread handles. (The core is host-agnostic - a `net` server is the other host, driving the same [`FsCore`]
//! on its own ring.)

use super::core::{FsCore, FsWaiter, TAG_CANCEL, TAG_WAKE, deliver_embedded, deliver_pool_completions};
use super::offload_pool::MAX_OFFLOAD_THREADS;
use super::{FsHandle, FsInject, FsOutcome, OffloadBounds, Personality, PrivilegedXattrs};
use crate::errno::{self, Errno};
use crate::sync::{Arc, mpsc};
use crate::uring::engine::Engine;
use crate::uring::probe::probe_op_supported;
use crate::uring::ring::RingFd;
use crate::uring::sys::{IORING_CQE_F_MORE, IORING_OP_OPENAT2, IoUringCqe, register_personality};
use crate::uring::user_data::{SLOT_MASK, TAG_FS_DOMAIN, pack_raw, unpack_raw};
use crate::uring::wake::LoopShared;
use std::fmt;

/// Sizing for an [`UringFs`], defaulted for a **server**: a request handler fans out many independent operations and
/// collects their completions. Both fields are public; a consumer with a different shape sets its own.
///
/// There is no open-file count. Files are plain descriptors and the reactor registers no fixed-file pool, so the limit
/// is the process's `RLIMIT_NOFILE`.
///
/// `entries` is the submission queue, and staging past a full queue flushes and continues, so it is a batching knob and
/// not a ceiling. `ops` is the table an in-flight operation holds a slot in until its completion reaps, so **`ops` is
/// the real concurrency ceiling**, and exhausting it fails a fan-out with `EBUSY`. It should exceed `entries`.
///
/// Only `entries` costs locked memory. A ring's queues are charged against `RLIMIT_MEMLOCK` with no capability bypass,
/// so root is not exempt (`__io_account_mem`, `io_uring/rsrc.c:39-47`). The cost is about `entries x 96` bytes, roughly
/// 400 KiB for the default, and against a common 8 MiB limit the 22nd concurrent default-sized ring fails `ENOMEM`.
/// Several reactors, or a consumer that also registers buffers, must raise it (`LimitMEMLOCK=` in the unit, or
/// `setrlimit` before the first [`UringFs::new`]). `ops` is plain heap at 584 bytes a slot, 616 under `net-server`
/// (pinned by `core::op_entry_size`), so the default costs about 18.25 MiB and raising concurrency is cheap.
///
/// `#[non_exhaustive]`, so build one by mutating [`FsConfig::default`].
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct FsConfig {
    /// Submission-queue depth (rounded up to a power of two by the kernel) -- how much work rides on one
    /// `io_uring_enter`. The field that costs `RLIMIT_MEMLOCK`; see the type docs.
    pub entries: u32,
    /// Op-table slots - the maximum number of concurrently in-flight operations, and the ceiling a fan-out actually
    /// hits. Submitting past it fails `EBUSY` however deep the ring is.
    pub ops: u32,
    /// Sizing for the blocking-offload pool that backs `FsConn::offload` and the hybrid lister. Per ring; see
    /// [`OffloadBounds`].
    pub offload: OffloadBounds,
}

impl Default for FsConfig {
    fn default() -> FsConfig {
        FsConfig {
            entries: 4096,
            ops: 32768,
            offload: OffloadBounds::default(),
        }
    }
}

/// Stops a running [`UringFs::run`] loop from any thread.
#[derive(Clone, Debug)]
pub struct ShutdownHandle {
    shared: Arc<LoopShared>,
}

impl ShutdownHandle {
    /// Stop the loop: in-flight operations are cancelled (parked callers observe `ECANCELED`/`ECONNABORTED`) and
    /// [`UringFs::run`] returns. Safe to call from any thread and more than once. Infallible: a flag store plus an
    /// eventfd poke.
    pub fn shutdown(&self) {
        // Through `request_stop`, not a hand-spelled store: one spelling of the ordering is what lets a model drive
        // *this* code rather than its own copy of the pairing.
        self.shared.request_stop();
        self.shared.wake.poke();
    }
}

/// The standalone fs reactor: one ring, one loop thread, open files as plain reference-counted fds (`Arc<OwnedFd>`,
/// closed by last reference), every operation stamped with a [`Personality`].
///
/// Like the `net` roles it is deliberately `!Send` (the ring is single-thread-owned): build it, mint
/// [`FsHandle`]s/[`ShutdownHandle`]s for other threads, then park the owning thread in [`UringFs::run`].
pub struct UringFs {
    // Field order is load-bearing (as in the net roles): `fs` owns every kernel-visible buffer and is declared before
    // `eng`, so those buffers drop before the engine unmaps the ring - the kernel must never touch a freed buffer.
    fs: FsCore,
    inject_tx: mpsc::Sender<FsInject>,
    inject_rx: mpsc::Receiver<FsInject>,
    eng: Engine,
}

impl fmt::Debug for UringFs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UringFs").finish_non_exhaustive()
    }
}

impl Drop for UringFs {
    fn drop(&mut self) {
        // A no-op after `run`, which already drained. On an early drop, or a panic unwinding out of `run`, drain here,
        // and if that fails leak the op buffers rather than free them under a still-live kernel op.
        let _ = self.drain_or_leak();
    }
}

impl UringFs {
    /// Build the ring and probe the kernel (`OPENAT2` as the canary for the op set). Fails with `Validation` on an
    /// unsupported kernel and with the underlying errno where io_uring itself is unavailable.
    ///
    /// No fixed-file pool is registered: fs ops name files by raw descriptor.
    pub fn new(cfg: FsConfig) -> crate::Result<UringFs> {
        Self::check(&cfg)?;
        let ring = RingFd::setup(cfg.entries)?;
        Self::build(cfg, ring)
    }

    /// Create the ring a reactor under `cfg` will run on, without building the reactor.
    ///
    /// For a process that runs several reactors on several threads behind one credential broker. The broker must
    /// inherit every ring fd at fork and the fork must precede every thread, while a [`UringFs`] can only be built on
    /// the thread that runs it. So create each ring here, on the main thread, spawn the broker over the [`RingFd`]s,
    /// then build each reactor on its own thread with [`UringFs::with_ring`].
    pub fn setup_ring(cfg: &FsConfig) -> crate::Result<RingFd> {
        Self::check(cfg)?;
        Ok(RingFd::setup(cfg.entries)?)
    }

    /// As [`UringFs::new`], on a ring from [`UringFs::setup_ring`]. A ring shallower than `cfg.entries` asks for is
    /// refused with `Validation`.
    pub fn with_ring(cfg: FsConfig, ring: RingFd) -> crate::Result<UringFs> {
        Self::check(&cfg)?;
        if ring.sq_entries() < cfg.entries {
            return Err(crate::Error::Validation(format!(
                "ring has {} submission entries, FsConfig::entries asks for {}",
                ring.sq_entries(),
                cfg.entries
            )));
        }
        Self::build(cfg, ring)
    }

    fn check(cfg: &FsConfig) -> crate::Result<()> {
        if cfg.ops < 2 || u64::from(cfg.ops) > SLOT_MASK {
            return Err(crate::Error::Validation(
                "FsConfig::ops must be in 2..=SLOT_MASK".into(),
            ));
        }
        if cfg.entries < 4 {
            return Err(crate::Error::Validation("FsConfig::entries must be at least 4".into()));
        }
        // Both offload bounds are OS threads and `floor` spawns eagerly on the reactor thread at first use, so an
        // absurd value is a thread storm inside one `offload` call. The pool normalises an inverted pair.
        let widest = cfg.offload.floor.max(cfg.offload.ceiling);
        if widest > MAX_OFFLOAD_THREADS {
            return Err(crate::Error::Validation(format!(
                "FsConfig::offload asks for {widest} worker threads; the \
                 pool is bounded at {MAX_OFFLOAD_THREADS}"
            )));
        }
        Ok(())
    }

    fn build(cfg: FsConfig, ring: RingFd) -> crate::Result<UringFs> {
        let eng = Engine::without_pool_on(ring)?;
        if !probe_op_supported(&eng.ring, IORING_OP_OPENAT2) {
            return Err(crate::Error::Validation(
                "uring_fs requires io_uring OPENAT2 (Linux >= 5.6); this \
                 kernel's io_uring does not support it"
                    .into(),
            ));
        }
        let (inject_tx, inject_rx) = mpsc::channel();
        Ok(UringFs {
            fs: FsCore::new(cfg.ops, cfg.offload),
            inject_tx,
            inject_rx,
            eng,
        })
    }

    /// This reactor's ring descriptor - handed to the credential broker so it can register personalities on this ring
    /// (and to nothing else: a ring fd plus its personality table is a credential capability).
    pub(crate) fn ring_fd(&self) -> std::os::fd::RawFd {
        self.eng.ring.raw_fd()
    }

    /// Register the calling process's **current** credentials as a [`Personality`] - the identity every subsequent
    /// operation must name.
    ///
    /// Unprivileged: registering your own credentials needs no capability. The snapshot is frozen at this call (a later
    /// `setgroups`/capability drop does not update it - register again for a fresh one). Ids are kernel-allocated from
    /// 1 upward, cyclically, without immediate reuse.
    pub fn register_self(&self) -> crate::Result<Personality> {
        let id = register_personality(self.eng.ring.raw_fd())?;
        Ok(Personality(id))
    }

    /// Declare which extended attributes are written under this reactor's ambient credentials rather than the
    /// requesting [`Personality`] - see [`PrivilegedXattrs`] for the rules and the reasoning.
    ///
    /// Setup-time only, and enforced as such: [`UringFs::run`] borrows `&mut self` for the lifetime of the loop, so
    /// this cannot be called while operations are in flight. Replaces any previous policy; the default permits nothing.
    pub fn set_privileged_xattrs(&mut self, policy: PrivilegedXattrs) {
        self.fs.set_privileged_xattrs(policy);
    }

    /// A `Send + Sync` handle for submitting operations from other threads.
    pub fn handle(&self) -> FsHandle {
        FsHandle {
            tx: self.inject_tx.clone(),
            shared: self.eng.shared.clone(),
            pool: self.fs.pool_handle(),
        }
    }

    /// A handle that stops [`UringFs::run`] from any thread.
    pub fn shutdown_handle(&self) -> ShutdownHandle {
        ShutdownHandle {
            shared: self.eng.shared.clone(),
        }
    }

    /// Run the completion loop until a [`ShutdownHandle`] stops it or a fatal ring error occurs. In-flight operations
    /// are cancelled and drained before returning; parked handle callers are unblocked with errors. Terminal: build a
    /// fresh `UringFs` rather than re-running.
    pub fn run(&mut self) -> crate::Result<()> {
        self.eng.arm_wake(pack_raw(TAG_WAKE, 0, 0))?;
        self.eng.shared.wake.activate();
        let run = self.run_loop();
        let drained = self.drain_teardown();
        run?;
        drained?;
        Ok(())
    }

    fn run_loop(&mut self) -> errno::Result<()> {
        while !self.eng.stopping() {
            if self.eng.inflight == 0 {
                break; // nothing outstanding; avoid blocking forever
            }
            // Wake the pool for what this iteration queued and bound the sleep by the pool's next deadline
            // (`FsCore::flush_offloads`). Then park: a poke that landed while the loop was awake wrote no eventfd and
            // is drained here (`WakeHandle::park`).
            let recheck = self.fs.flush_offloads();
            match self.eng.shared.wake.park() {
                crate::uring::wake::Park::Block => {
                    let waited = self.eng.ring.submit_and_wait_for(1, recheck);
                    self.eng.shared.wake.unpark();
                    waited?;
                }
                crate::uring::wake::Park::Drain => {
                    self.drain_wake_sources();
                    self.eng.submit_and_flush_overflow()?;
                }
            }
            while let Some(cqe) = self.eng.ring.reap() {
                self.dispatch(cqe)?;
            }
        }
        Ok(())
    }

    /// Drain every wake source without re-arming the wake `READ`: `TAG_WAKE` re-arms after consuming the read, and
    /// `Park::Drain` runs this with the read still armed.
    fn drain_wake_sources(&mut self) {
        self.drain_injects();
        // Fire on-loop deliveries from finished pool jobs (`FsConn::offload` and the hybrid lister).
        deliver_pool_completions(&mut self.fs, &mut self.eng);
    }

    fn dispatch(&mut self, cqe: IoUringCqe) -> errno::Result<()> {
        // Count the reaped CQE off `inflight` before its handler runs, so an error return can't leave the count
        // permanently high (which would hang the teardown drain).
        if cqe.flags & IORING_CQE_F_MORE == 0 {
            self.eng.inflight = self.eng.inflight.saturating_sub(1);
        }
        let (tag, slot, gen32) = unpack_raw(cqe.user_data);
        if tag & TAG_FS_DOMAIN == 0 {
            return Ok(()); // not ours (nothing stages such tags today)
        }
        match tag {
            TAG_WAKE => {
                if !self.eng.stopping() {
                    self.eng.arm_wake(pack_raw(TAG_WAKE, 0, 0))?;
                }
                self.drain_wake_sources();
            }
            TAG_CANCEL => {}
            // An `FsHandle` op's channel waiter is answered inside `on_cqe`, and an `FsConn` op's callback comes back
            // to fire here. Only a `net` server submits pump reads, so `deliver_embedded` treats one as unreachable.
            _ => {
                let reaped = self.fs.on_cqe(&mut self.eng, tag, slot, gen32, cqe.res);
                deliver_embedded(&mut self.fs, &mut self.eng, reaped);
            }
        }
        Ok(())
    }

    fn drain_injects(&mut self) {
        while let Ok(msg) = self.inject_rx.try_recv() {
            match msg {
                FsInject::Open {
                    pers,
                    anchor,
                    path,
                    how,
                    guarded,
                    deadline,
                    reply,
                } => self.fs.submit_open(
                    &mut self.eng,
                    pers,
                    anchor,
                    path.to_bytes(),
                    how,
                    guarded,
                    deadline,
                    FsWaiter::Channel(reply),
                ),
                FsInject::Rw {
                    tag,
                    pers,
                    file,
                    bufs,
                    off,
                    rw_flags,
                    reply,
                } => self.fs.submit_rw(
                    &mut self.eng,
                    tag,
                    pers,
                    file,
                    bufs,
                    off,
                    rw_flags,
                    FsWaiter::Channel(reply),
                ),
                FsInject::ReadSpare {
                    pers,
                    file,
                    buf,
                    count,
                    off,
                    rw_flags,
                    reply,
                } => self.fs.submit_read_spare(
                    &mut self.eng,
                    pers,
                    file,
                    buf,
                    count,
                    off,
                    rw_flags,
                    FsWaiter::Channel(reply),
                ),
                FsInject::Fsync {
                    pers,
                    file,
                    datasync,
                    offset,
                    length,
                    reply,
                } => self.fs.submit_fsync(
                    &mut self.eng,
                    pers,
                    file,
                    datasync,
                    offset,
                    length,
                    FsWaiter::Channel(reply),
                ),
                FsInject::FdMeta {
                    tag,
                    pers,
                    file,
                    name,
                    value,
                    off,
                    len64,
                    aux32,
                    reply,
                } => self.fs.submit_fd_meta(
                    &mut self.eng,
                    tag,
                    pers,
                    file,
                    name,
                    value,
                    off,
                    len64,
                    aux32,
                    FsWaiter::Channel(reply),
                ),
                FsInject::FdMetaAsRoot {
                    file,
                    name,
                    value,
                    through_proc,
                    reply,
                } => self.fs.submit_fgetxattr_as_root(
                    &mut self.eng,
                    file,
                    name,
                    value,
                    through_proc,
                    FsWaiter::Channel(reply),
                ),
                FsInject::ReopenProc {
                    pers,
                    file,
                    access,
                    reply,
                } => {
                    let waiter = FsWaiter::Channel(reply);
                    let eng = &mut self.eng;
                    match pers {
                        Some(pers) => self.fs.submit_reopen_proc(eng, pers, file, access, waiter),
                        None => self.fs.submit_reopen_proc_as_root(eng, file, access, waiter),
                    }
                }
                FsInject::FRemoveXattr { file, name, reply } => self.fs.remove_priv_xattr(file, name, reply),
                FsInject::PathOp {
                    tag,
                    pers,
                    a1,
                    n1,
                    a2,
                    n2,
                    flags,
                    len_arg,
                    reply,
                } => self.fs.submit_path_op(
                    &mut self.eng,
                    tag,
                    pers,
                    a1,
                    n1.to_bytes(),
                    a2,
                    n2,
                    flags,
                    len_arg,
                    FsWaiter::Channel(reply),
                ),
                FsInject::LinkatFile {
                    pers,
                    file,
                    a2,
                    n2,
                    reply,
                } => self
                    .fs
                    .submit_linkat_file(&mut self.eng, pers, file, a2, n2, FsWaiter::Channel(reply)),
            }
        }
    }

    /// Cancel and reap everything, routing each fs completion so waiters unblock and buffers free. If that drain fails
    /// with ops possibly still in flight, leak the op buffers and the wake pad rather than free memory the kernel may
    /// still be writing into.
    fn drain_or_leak(&mut self) -> errno::Result<()> {
        let fs = &mut self.fs;
        let drained = self
            .eng
            .cancel_and_reap_all(pack_raw(TAG_CANCEL, 0, 0), |cqe| fs.on_drain_cqe(cqe));
        if drained.is_err() {
            self.fs.leak();
            self.eng.leak_wake_buf();
        }
        drained
    }

    /// Drain the ring, then answer every inject still queued with `ECONNABORTED`.
    fn drain_teardown(&mut self) -> crate::Result<()> {
        // Before the reap, while the ring is still whole: see `drain_stop_window`.
        crate::uring_fs::core::drain_stop_window(&mut self.fs, &mut self.eng);
        let drained = self.drain_or_leak();
        while let Ok(msg) = self.inject_rx.try_recv() {
            let (reply, bufs) = match msg {
                FsInject::Open { reply, .. } => (Some(reply), Vec::new()),
                FsInject::Rw { reply, bufs, .. } => (Some(reply), bufs),
                FsInject::ReadSpare { reply, buf, .. } => (Some(reply), vec![buf]),
                FsInject::Fsync { reply, .. } => (Some(reply), Vec::new()),
                FsInject::FdMeta { reply, value, .. } => (Some(reply), vec![value]),
                FsInject::FdMetaAsRoot { reply, value, .. } => (Some(reply), vec![value]),
                FsInject::ReopenProc { reply, .. } => (Some(reply), Vec::new()),
                FsInject::FRemoveXattr { reply, .. } => (Some(reply), Vec::new()),
                FsInject::PathOp { reply, .. } => (Some(reply), Vec::new()),
                FsInject::LinkatFile { reply, .. } => (Some(reply), Vec::new()),
            };
            if let Some(reply) = reply {
                let _ = reply.send(FsOutcome::new(Err(Errno::ECONNABORTED), bufs, None, None));
            }
        }
        drained?;
        Ok(())
    }
}

/// The host's screens and teardown, and kernel-convention pins that need raw rings. Environmental skips follow the
/// integration suites' discipline (`TRUENAS_ROS_REQUIRE_IO_URING`).
#[cfg(all(test, not(loom)))]
mod tests {
    use super::*;
    use crate::sync_fs::openat2::RawOpenHow;
    use crate::sync_fs::{OFlag, OpenHow};
    use crate::uring::ring::Ring;
    use crate::uring::sys::{
        IORING_OP_FGETXATTR, IORING_OP_FSETXATTR, IORING_SETUP_SINGLE_ISSUER, IoUringParams, io_uring_setup,
        unregister_personality,
    };
    use crate::uring_fs::{Anchor, FsConfig, Personality, RwFlags};
    use std::ffi::CString;
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;

    use crate::uring::setup_unavailable as skip_unavailable;

    /// `FsConfig` is checked before a ring is created. An op table wider than `user_data`'s 24-bit slot field
    /// (`user_data::SLOT_MASK`) would alias indices and route a completion to the wrong op, and nothing downstream
    /// re-checks it.
    #[test]
    fn a_config_the_slot_field_cannot_index_is_refused() {
        use crate::uring::user_data::SLOT_MASK;
        let over = FsConfig {
            ops: (SLOT_MASK + 1) as u32,
            ..FsConfig::default()
        };
        assert!(
            matches!(UringFs::new(over), Err(crate::Error::Validation(_))),
            "an op table wider than the slot field must be refused"
        );
        assert!(
            matches!(
                UringFs::new(FsConfig {
                    ops: 1,
                    ..FsConfig::default()
                }),
                Err(crate::Error::Validation(_))
            ),
            "an op table with no room to make progress is refused"
        );
        assert!(
            matches!(
                UringFs::new(FsConfig {
                    entries: 3,
                    ..FsConfig::default()
                }),
                Err(crate::Error::Validation(_))
            ),
            "a submission ring below the floor is refused"
        );
    }

    /// The offload bounds are OS threads spawned on the reactor thread at first use, so they are screened at
    /// construction like every other sizing knob.
    #[test]
    fn offload_bounds_past_the_thread_cap_are_refused() {
        for (floor, ceiling) in [
            (MAX_OFFLOAD_THREADS + 1, MAX_OFFLOAD_THREADS + 1),
            // The floor is the eager half, so it is screened on its own.
            (usize::MAX, 1),
            (1, usize::MAX),
        ] {
            let storm = FsConfig {
                offload: crate::uring_fs::OffloadBounds {
                    floor,
                    ceiling,
                    ..crate::uring_fs::OffloadBounds::default()
                },
                entries: 8,
                ops: 8,
                ..FsConfig::default()
            };
            match UringFs::new(storm) {
                Err(crate::Error::Validation(_)) => {}
                Err(crate::Error::Errno(e)) if skip_unavailable(e) => {}
                Err(e) => panic!("UringFs::new({floor}..={ceiling}): {e}"),
                Ok(_fs) => panic!(
                    "accepted {floor}..={ceiling} worker threads; the first \
                     offload spawns them on the reactor thread"
                ),
            }
        }
    }

    /// A refusal queued in the stop window is delivered by the teardown, not dropped with its callback.
    ///
    /// Once `run_loop` sees `stopping()` the wake `READ` is never re-armed, and the teardown reap touches ring ops
    /// only, never `fs.refusals`. The pass delivers only what was already queued, so what a callback asks for during
    /// teardown is not delivered.
    #[test]
    fn teardown_delivers_a_refusal_queued_in_the_stop_window() {
        use crate::uring_fs::core::FsConn;
        use std::cell::RefCell;
        use std::rc::Rc;

        let mut host = match UringFs::new(FsConfig::default()) {
            Ok(h) => h,
            Err(crate::Error::Errno(e)) if skip_unavailable(e) => return,
            Err(e) => panic!("UringFs::new: {e}"),
        };
        host.fs.set_timer_cap(1);
        let hour = std::time::Duration::from_secs(3600);
        {
            let mut conn = FsConn::new(&mut host.fs, &mut host.eng, Some((1, 1)));
            assert!(conn.timeout(hour, |_d, _c| {}).is_some(), "cap spender");
        }
        let log: Rc<RefCell<Vec<&'static str>>> = Rc::new(RefCell::new(Vec::new()));
        {
            let l = Rc::clone(&log);
            let requeued = Rc::clone(&log);
            let mut conn = FsConn::new(&mut host.fs, &mut host.eng, Some((1, 1)));
            assert!(
                conn.timeout(hour, move |_d, c| {
                    l.borrow_mut().push("a");
                    // Still at cap: this re-arm queues mid-drain.
                    let _ = c.timeout(hour, move |_d, _c| {
                        requeued.borrow_mut().push("a2");
                    });
                })
                .is_none(),
                "refused at the cap"
            );
        }
        host.drain_teardown().expect("teardown");
        assert_eq!(
            *log.borrow(),
            vec!["a"],
            "a refusal queued before the stop died with its callback"
        );
    }

    /// A burst of off-loop submits (one thread fanning out jobs, as `QueryPool`'s callers do) gets a worker per job, on
    /// a loop with nothing else to wake it. The burst outruns growth, so the jobs past the floor get workers only when
    /// the loop comes back at the published deadline. Each job holds its worker until all of them run.
    #[test]
    fn an_off_loop_burst_gets_a_worker_per_job() {
        use std::sync::{Arc, Condvar, Mutex};
        use std::time::{Duration, Instant};
        const JOBS: usize = 2 * crate::uring_fs::core::OFFLOAD_FLOOR;

        let mut host = match UringFs::new(FsConfig::default()) {
            Ok(h) => h,
            Err(crate::Error::Errno(e)) if skip_unavailable(e) => return,
            Err(e) => panic!("UringFs::new: {e}"),
        };
        let h = host.handle();
        let stop = host.shutdown_handle();
        // Jobs running, and whether they may finish.
        let gate = Arc::new((Mutex::new((0usize, false)), Condvar::new()));
        std::thread::scope(|s| {
            s.spawn(|| {
                for _ in 0..JOBS {
                    let g = Arc::clone(&gate);
                    let job = Box::new(move || {
                        let (m, cv) = &*g;
                        let mut st = m.lock().unwrap();
                        st.0 += 1;
                        cv.notify_all();
                        while !st.1 {
                            st = cv.wait(st).unwrap();
                        }
                    });
                    h.pool.submit(job, &h.shared.wake);
                }
                let (m, cv) = &*gate;
                let give_up = Instant::now() + Duration::from_secs(10);
                let mut st = m.lock().unwrap();
                while st.0 < JOBS && Instant::now() < give_up {
                    st = cv.wait_timeout(st, Duration::from_millis(10)).unwrap().0;
                }
                let running = st.0;
                st.1 = true;
                cv.notify_all();
                drop(st);
                stop.shutdown();
                assert_eq!(
                    running, JOBS,
                    "{running} of {JOBS} jobs got a worker; the rest waited \
                     on the ones ahead of them"
                );
            });
            host.run().expect("run");
        });
    }

    fn ring_or_skip(entries: u32) -> Option<Ring> {
        match Ring::new(entries) {
            Ok(r) => Some(r),
            Err(e) if skip_unavailable(e) => None,
            Err(e) => panic!("Ring::new: {e}"),
        }
    }

    /// The ALLOC1 contract this design leans on: ids start at 1 (0 stays the "ambient creds" SQE sentinel), allocate
    /// cyclically, and an unregistered id is not immediately reused.
    #[test]
    fn personality_ids_start_at_one_and_do_not_reuse() {
        let Some(ring) = ring_or_skip(4) else { return };
        let fd = ring.raw_fd();
        assert_eq!(register_personality(fd), Ok(1));
        assert_eq!(register_personality(fd), Ok(2));
        assert_eq!(register_personality(fd), Ok(3));
        unregister_personality(fd, 1).expect("unregister");
        assert_eq!(register_personality(fd), Ok(4), "cyclic, no reuse");
    }

    /// A `SINGLE_ISSUER` ring refuses registration from any task but its creator with `-EEXIST`, so our rings never set
    /// the flag, since the credential broker registers from outside. Pin both directions.
    #[test]
    fn single_issuer_gates_cross_thread_registration() {
        let mut p = IoUringParams {
            flags: IORING_SETUP_SINGLE_ISSUER,
            ..Default::default()
        };
        let fd = match io_uring_setup(4, &mut p) {
            Ok(fd) => fd,
            // EINVAL: kernel predates the flag (< 6.0) - nothing to pin.
            Err(Errno::EINVAL) => return,
            Err(e) if skip_unavailable(e) => return,
            Err(e) => panic!("io_uring_setup: {e}"),
        };
        let raw = fd.as_raw_fd();
        std::thread::scope(|s| {
            s.spawn(move || {
                assert_eq!(
                    register_personality(raw),
                    Err(Errno::EEXIST),
                    "cross-task register must hit the SINGLE_ISSUER gate"
                );
            });
        });
        // The creating task itself may register.
        assert!(register_personality(raw).is_ok());
    }

    /// The explicit-index install convention: `OPENAT2` with `file_index = slot + 1` completes with `res == 0` (not an
    /// fd number). Raw-ring test on purpose - it pins the kernel, not our plumbing.
    #[test]
    fn explicit_index_install_res_is_zero() {
        let Some(mut ring) = ring_or_skip(8) else {
            return;
        };
        ring.register_pool(4).expect("register pool");
        let dir = crate::tempdir().unwrap();
        let path = CString::new(dir.path().join("f").as_os_str().as_bytes()).unwrap();
        let how = RawOpenHow {
            flags: (libc::O_CREAT | libc::O_WRONLY) as u64,
            mode: 0o600,
            resolve: 0,
        };
        ring.push_sqe(|sqe| {
            sqe.opcode = IORING_OP_OPENAT2;
            sqe.fd = libc::AT_FDCWD;
            sqe.addr = path.as_ptr() as u64;
            sqe.off_addr2 = &how as *const RawOpenHow as u64;
            sqe.len = std::mem::size_of::<RawOpenHow>() as u32;
            sqe.file_index = 1; // slot 0
            sqe.user_data = 7;
        })
        .expect("stage");
        ring.submit_and_wait(1).expect("submit");
        let cqe = ring.reap().expect("cqe");
        assert_eq!(cqe.user_data, 7);
        assert_eq!(cqe.res, 0, "explicit-index install must complete with res == 0");
    }

    /// Pin the xattr SQE field packing on a raw ring (`addr` the name, `addr2` the value, `len` the size), apart from
    /// the reactor's xattr ops.
    #[test]
    fn xattr_sqe_packing_round_trips() {
        let Some(mut ring) = ring_or_skip(8) else {
            return;
        };
        let dir = crate::tempdir().unwrap();
        let path = dir.path().join("x");
        std::fs::write(&path, b"body").unwrap();
        let file = std::fs::File::open(&path).unwrap();
        let fd = file.as_raw_fd();
        let name = c"user.packing";
        let value = b"VALUE".to_vec();

        ring.push_sqe(|sqe| {
            sqe.opcode = IORING_OP_FSETXATTR;
            sqe.fd = fd;
            sqe.addr = name.as_ptr() as u64;
            sqe.off_addr2 = value.as_ptr() as u64;
            sqe.len = value.len() as u32;
            sqe.user_data = 1;
        })
        .unwrap();
        ring.submit_and_wait(1).unwrap();
        let res = ring.reap().expect("set cqe").res;
        if res == -libc::EOPNOTSUPP || res == -libc::ENOTSUP {
            return; // filesystem without user xattrs (unusual /tmp)
        }
        assert_eq!(res, 0, "fsetxattr with our packing");

        let mut out = vec![0u8; 32];
        ring.push_sqe(|sqe| {
            sqe.opcode = IORING_OP_FGETXATTR;
            sqe.fd = fd;
            sqe.addr = name.as_ptr() as u64;
            sqe.off_addr2 = out.as_mut_ptr() as u64;
            sqe.len = out.len() as u32;
            sqe.user_data = 2;
        })
        .unwrap();
        ring.submit_and_wait(1).unwrap();
        let got = ring.reap().expect("get cqe").res;
        assert_eq!(got, value.len() as i32, "res is the attribute size");
        assert_eq!(&out[..got as usize], &value[..], "value round-trips");
    }

    /// A personality id nothing registered fails `EINVAL` at submission, the kernel refusing the stamp, surfaced as the
    /// op's error.
    #[test]
    fn a_personality_nothing_registered_fails_einval() {
        let dir = crate::tempdir().unwrap();
        std::fs::write(dir.path().join("f"), b"data").unwrap();
        // Not `FsConfig::default()`: that is server-sized and costs ~400 KiB of RLIMIT_MEMLOCK per ring, and `cargo
        // test` runs this alongside every other test in one process.
        let cfg = FsConfig {
            entries: 128,
            ops: 128,
            ..FsConfig::default()
        };
        let mut afs = match UringFs::new(cfg) {
            Ok(a) => a,
            Err(crate::Error::Errno(e)) if skip_unavailable(e) => return,
            Err(e) => panic!("UringFs::new: {e}"),
        };
        let me = afs.register_self().unwrap();
        let h = afs.handle();
        let stop = afs.shutdown_handle();
        let dir_path = dir.path().to_path_buf();
        std::thread::scope(|s| {
            let stop_c = stop.clone();
            s.spawn(move || {
                let anchor = Anchor::open(dir_path.as_path()).unwrap();
                let how = OpenHow::new().flags(OFlag::O_RDONLY);
                let f = h.open(me, &anchor, "f", how).unwrap();

                // A plain read works.
                let (res, bufs) = h.preadv2(me, &f, vec![vec![0u8; 4]], 0, RwFlags::empty());
                assert_eq!(res.unwrap(), 4);
                assert_eq!(&bufs[0], b"data");

                // A personality nothing registered: the kernel refuses the SQE at init; the caller sees EINVAL.
                let bogus = Personality(4242);
                let (res, _b) = h.preadv2(bogus, &f, vec![vec![0u8; 4]], 0, RwFlags::empty());
                assert!(matches!(res, Err(crate::Error::Errno(Errno::EINVAL))));

                h.close(f).unwrap();
                stop_c.shutdown();
            });
            afs.run().unwrap();
        });
    }
}
