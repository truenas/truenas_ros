use super::*;

/// The teardown drain answers a short leased write the same way the live reap does.
///
/// The reason does not soften at shutdown: the write's source was the connection's receive buffer, so a caller
/// handed `Ok(n)` cannot retry from bytes it no longer owns, and one that shrugs stores a truncated object. The
/// drain is the only other path a leased completion can take.
#[cfg(feature = "net-server")]
#[test]
fn a_drained_short_leased_write_is_an_error() {
    let Some(mut eng) = engine_or_skip() else {
        return;
    };
    let mut core = FsCore::new(8, OffloadBounds::default());
    let buf = vec![7u8; 8192];
    let fd = synth_fd();
    // SAFETY: `synth_fd` just opened it; nothing else owns it.
    let file = Arc::new(unsafe { crate::fd::owned_from_raw(fd) });
    let (tx, rx) = mpsc::channel();
    let staged = core.submit_pwritev2_gathered(
        &mut eng,
        0,
        file,
        vec![LeasedWindow {
            view: LeasedBytes {
                ptr: buf.as_ptr(),
                len: buf.len(),
            },
            hold: std::sync::Arc::new(LeaseHold::detached(9)),
        }],
        0,
        0,
        chan(&tx),
    );
    assert!(staged.is_ok(), "staged");
    let [(t, s, g)] = inflight(&core)[..] else {
        panic!("one op in flight");
    };
    let cqe = IoUringCqe {
        user_data: pack_raw(t, s, g),
        res: 4096, // short of the 8192 the lease asked for
        flags: 0,
    };
    core.on_drain_cqe(&cqe);
    let out = rx.try_recv().expect("delivered");
    assert_eq!(
        out.res,
        Err(Errno::EIO),
        "a short leased write survived the drain as a success"
    );
}

/// Teardown's drain owns the fd a successful open completes with.
///
/// The fd arrives in `cqe.res` and nothing parked owns it - the live path is what wraps the result - so a drain
/// that delivers the raw count leaks the descriptor: the waiter is usually already gone at teardown, and a number
/// nobody owns is closed by nobody.
#[test]
fn a_drained_open_owns_its_fd() {
    let Some(mut eng) = engine_or_skip() else {
        return;
    };
    let mut core = FsCore::new(8, OffloadBounds::default());
    let fd = synth_fd();
    // SAFETY: `synth_fd` just opened it; nothing else owns it.
    let file = Arc::new(unsafe { crate::fd::owned_from_raw(fd) });
    let (tx, rx) = mpsc::channel();
    core.submit_fsync(&mut eng, 0, file, false, 0, 0, chan(&tx));
    let [(_, s, g)] = inflight(&core)[..] else {
        panic!("one op in flight");
    };
    // Re-tag the staged op as the OPEN whose completion carries an fd;
    // the drain path reads only the tag and the result.
    core.ops[s as usize].state.state = FsOpState::InFlight { tag: TAG_OPEN };
    let opened = synth_fd();
    drop(rx); // as at teardown: nobody is left to take the outcome
    let cqe = IoUringCqe {
        user_data: pack_raw(TAG_OPEN, s, g),
        res: opened,
        flags: 0,
    };
    core.on_drain_cqe(&cqe);
    // With no receiver, the owned file had nowhere to land, so its drop must have closed the descriptor rather than
    // leaking it.
    // SAFETY: `fcntl(F_GETFD)` probes a descriptor number, reads nothing.
    let rc = unsafe { libc::fcntl(opened, libc::F_GETFD) };
    assert_eq!(rc, -1, "the drained open's fd was closed, not leaked");
}

/// A refused fd-op hands the caller's `File` back with the payload.
///
/// The facade's fd-ops take `File` by value, so a caller that submits its last handle has surrendered it. The
/// refusal used to drop the parked `Arc`, which **closed the descriptor** under a caller told a *marked* `EBUSY` -
/// the errno `FsDone::was_refused` documents as "worth retrying with the payload `into_bufs` hands back". The
/// payload came back and the file it was to be written to did not.
///
/// Control first: with a slot free the same submission parks the fd and it stays open, so the weak-ref instrument
/// is shown reading "alive" before it is trusted to read "closed".
///
/// This drives the *submit-time* refusals - the `pop_op` arms and the screens above them, which is where the
/// documented `EBUSY` fan-out failure lives. `fail_op`'s arm (a slot already taken and the SQE then refused)
/// carries the same one-line return and no test: `push_sqe` flushes and retries on a full SQ, so a staging failure
/// needs a kernel-side refusal this suite cannot provoke.
#[test]
fn a_refused_fd_op_hands_the_callers_file_back() {
    let Some(mut eng) = engine_or_skip() else {
        return;
    };

    // --- live control: a slot IS free, so the fd survives ---------
    let mut core = FsCore::new(2, OffloadBounds::default());
    let arc = Arc::new(unsafe { crate::fd::owned_from_raw(synth_fd()) });
    let weak_ok = Arc::downgrade(&arc);
    let (tx, _rx) = mpsc::channel::<FsOutcome>();
    core.submit_fd_meta(
        &mut eng,
        TAG_FTRUNCATE,
        1,
        arc, // the caller's LAST reference moves in
        None,
        Vec::new(),
        0,
        0,
        0,
        chan(&tx),
    );
    assert!(
        weak_ok.upgrade().is_some(),
        "CONTROL: an accepted fd-op parks the fd; it must stay open"
    );

    // --- the case: the table is full, so the op is refused --------
    let mut core = FsCore::new(1, OffloadBounds::default());
    // Take the one slot.
    let hog = Arc::new(unsafe { crate::fd::owned_from_raw(synth_fd()) });
    core.submit_fd_meta(&mut eng, TAG_FTRUNCATE, 1, hog, None, Vec::new(), 0, 0, 0, chan(&tx));
    assert!(!core.has_free_op(), "the table is full");

    let arc = Arc::new(unsafe { crate::fd::owned_from_raw(synth_fd()) });
    let raw_before = arc.as_raw_fd();
    let weak = Arc::downgrade(&arc);
    let payload = vec![1u8, 2, 3];
    let (tx2, rx2) = mpsc::channel::<FsOutcome>();
    core.submit_fd_meta(
        &mut eng,
        TAG_FSETXATTR,
        1,
        arc, // the caller's LAST reference moves in
        Some(Cow::Borrowed(c"user.x")),
        payload,
        0,
        0,
        0,
        chan(&tx2),
    );
    let out = rx2.try_recv().expect("the refusal is delivered in place");
    assert_eq!(out.res, Err(Errno::EBUSY), "the marked fan-out refusal");
    assert_eq!(
        out.bufs,
        vec![vec![1u8, 2, 3]],
        "the PAYLOAD is handed back for the advised retry"
    );
    assert!(
        weak.upgrade().is_some(),
        "the refusal dropped the caller's last File reference"
    );
    assert_eq!(
        out.file.as_ref().map(|f| f.as_raw_fd()),
        Some(raw_before),
        "the refusal must hand the caller's own file back"
    );
    // And the descriptor is still open, so the advised retry can run.
    // SAFETY: `fcntl(F_GETFD)` probes a descriptor number, reads nothing.
    let rc = unsafe { libc::fcntl(raw_before, libc::F_GETFD) };
    assert_ne!(
        rc, -1,
        "the refused op closed the caller's descriptor: retry impossible"
    );
    drop(out);
    assert!(
        weak.upgrade().is_none(),
        "and it closes normally once the outcome is dropped"
    );
}

#[test]
fn close_last_parked_vs_caller() {
    let Some(mut eng) = engine_or_skip() else {
        return;
    };
    let mut core = FsCore::new(8, OffloadBounds::default());

    // (A) caller drops BEFORE the CQE: the op's parked clone keeps the fd.
    let arc = Arc::new(unsafe { crate::fd::owned_from_raw(synth_fd()) });
    let weak = Arc::downgrade(&arc);
    let caller = File::new(arc.clone());
    let (tx, rx) = mpsc::channel::<FsOutcome>();
    core.submit_rw(&mut eng, TAG_READV, 1, arc, vec![vec![0u8; 16]], 0, 0, chan(&tx));
    drop(caller);
    assert!(
        weak.upgrade().is_some(),
        "parked clone must keep the fd alive after the caller drops"
    );
    let (t, s, g) = inflight(&core)[0];
    complete(&mut core, &mut eng, t, s, g);
    let _ = rx.recv();
    assert!(
        weak.upgrade().is_none(),
        "fd closes once both the parked clone and the caller are gone"
    );

    // (B) CQE BEFORE the caller drops: the caller's ref keeps the fd.
    let arc = Arc::new(unsafe { crate::fd::owned_from_raw(synth_fd()) });
    let weak = Arc::downgrade(&arc);
    let caller = File::new(arc.clone());
    let (tx, rx) = mpsc::channel::<FsOutcome>();
    core.submit_rw(&mut eng, TAG_WRITEV, 1, arc, vec![vec![0u8; 16]], 0, 0, chan(&tx));
    let (t, s, g) = inflight(&core)[0];
    complete(&mut core, &mut eng, t, s, g);
    let _ = rx.recv();
    assert!(
        weak.upgrade().is_some(),
        "the caller's ref keeps the fd alive after the CQE reaps"
    );
    drop(caller);
    assert!(
        weak.upgrade().is_none(),
        "fd closes when the caller finally drops its last ref"
    );
}

#[test]
fn teardown_drain_releases_parked_fds() {
    let Some(mut eng) = engine_or_skip() else {
        return;
    };
    let mut core = FsCore::new(8, OffloadBounds::default());
    let (tx, _rx) = mpsc::channel::<FsOutcome>();
    let mut weaks = Vec::new();
    // Four in-flight rw ops, each parking a fd whose caller already dropped.
    for _ in 0..4 {
        let arc = Arc::new(unsafe { crate::fd::owned_from_raw(synth_fd()) });
        weaks.push(Arc::downgrade(&arc));
        core.submit_rw(&mut eng, TAG_READV, 1, arc, vec![vec![0u8; 16]], 0, 0, chan(&tx));
    }
    // Teardown reaps each in-flight op via the drain path -> parked Arcs drop.
    for (tag, slot, generation) in inflight(&core) {
        let cqe = IoUringCqe {
            user_data: pack_raw(tag, slot, generation),
            res: -libc::ECANCELED,
            flags: 0,
        };
        core.on_drain_cqe(&cqe);
    }
    assert!(
        weaks.iter().all(|w| w.upgrade().is_none()),
        "teardown released every parked fd"
    );
    let mut free = core.op_free.clone();
    free.sort_unstable();
    assert_eq!(
        free,
        (0..8).collect::<Vec<_>>(),
        "teardown freed every op slot exactly once"
    );
}

#[test]
fn routing_survives_fuzzed_completion() {
    let Some(mut eng) = engine_or_skip() else {
        return;
    };
    let anchor = Anchor::open("/").expect("open / as anchor");
    let seeds: u64 = std::env::var("ROUTING_FUZZ_SEEDS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(64);
    for seed in 0..seeds {
        // Reuse one engine, rewinding its staging between seeds; the rewind asserts nothing was ever submitted, so
        // the "runs purely in userspace, never enters the kernel" premise is checked, not assumed.
        eng.reset_staging();
        run_one(&mut eng, &anchor, seed);
    }
}

fn run_one(eng: &mut Engine, anchor: &Anchor, seed: u64) {
    let mut rng = Rng::new(seed);
    let mut core = FsCore::new(OP_SLOTS, OffloadBounds::default());
    let (tx, rx) = mpsc::channel::<FsOutcome>();
    // Weak refs to every synthesized fd - `upgrade() == None` means closed.
    let mut tracked: Vec<Weak<OwnedFd>> = Vec::new();
    // Caller-held files, dropped at fuzzed points (and all at the end).
    let mut held: Vec<File> = Vec::new();

    let steps = 24 + rng.below(72);
    for _ in 0..steps {
        // Drain delivered outcomes (opens' new fds): track, sometimes hold.
        while let Ok(out) = rx.try_recv() {
            if let Some(fd) = out.file {
                tracked.push(Arc::downgrade(&fd));
                if rng.below(2) == 0 {
                    held.push(File::new(fd));
                }
            }
        }
        match rng.below(7) {
            0 if !core.op_free.is_empty() => core.submit_open(
                eng,
                1,
                anchor.clone(),
                b"x",
                OpenHow::new().to_raw(),
                false,
                None,
                chan(&tx),
            ),
            1 | 2 if !core.op_free.is_empty() => {
                let arc = Arc::new(unsafe { crate::fd::owned_from_raw(synth_fd()) });
                tracked.push(Arc::downgrade(&arc));
                held.push(File::new(arc.clone()));
                let tag = if rng.below(2) == 0 { TAG_READV } else { TAG_WRITEV };
                core.submit_rw(eng, tag, 1, arc, vec![vec![0u8; 16]], 0, 0, chan(&tx));
            }
            3 if !core.op_free.is_empty() => {
                let arc = Arc::new(unsafe { crate::fd::owned_from_raw(synth_fd()) });
                tracked.push(Arc::downgrade(&arc));
                held.push(File::new(arc.clone()));
                // The read through /proc parks a path besides the file.
                let tag = if rng.below(2) == 0 {
                    TAG_FGETXATTR
                } else {
                    TAG_GETXATTR_PROC
                };
                core.submit_fd_meta(
                    eng,
                    tag,
                    1,
                    arc,
                    Some(Cow::Borrowed(c"user.x")),
                    vec![0u8; 64],
                    0,
                    0,
                    0,
                    chan(&tx),
                );
            }
            4 if !core.op_free.is_empty() => core.submit_path_op(
                eng,
                TAG_STATX,
                1,
                anchor.clone(),
                b"x",
                None,
                None,
                0,
                StatxMask::BASIC_STATS.bits(),
                chan(&tx),
            ),
            5 => {
                // A correct completion.
                let fly = inflight(&core);
                if !fly.is_empty() {
                    let (t, s, g) = fly[rng.below(fly.len() as u32) as usize];
                    complete(&mut core, eng, t, s, g);
                }
            }
            6 => {
                // An anomalous completion - MUST mutate nothing.
                let fly = inflight(&core);
                let snap = snapshot(&core);
                match rng.below(3) {
                    0 if !fly.is_empty() => {
                        let (t, s, g) = fly[rng.below(fly.len() as u32) as usize];
                        let _ = core.on_cqe(eng, t, s, g.wrapping_add(1), 16);
                    }
                    1 if !fly.is_empty() => {
                        let (t, s, g) = fly[rng.below(fly.len() as u32) as usize];
                        let _ = core.on_cqe(eng, t ^ 0x0F, s, g, 16);
                    }
                    _ => {
                        if let Some(&fslot) = core.op_free.first() {
                            let _ = core.on_cqe(eng, TAG_READV, fslot, 0, 16);
                        }
                    }
                }
                assert_eq!(snapshot(&core), snap, "anomalous CQE mutated state (seed {seed})");
            }
            _ => {}
        }
        // Occasionally drop a caller file mid-flight (parked clone must hold the fd until its own CQE - the
        // close-last guarantee).
        if !held.is_empty() && rng.below(3) == 0 {
            let i = rng.below(held.len() as u32) as usize;
            held.swap_remove(i);
        }
    }

    // Drain every remaining in-flight op with a correct completion.
    while let Some(&(t, s, g)) = inflight(&core).first() {
        complete(&mut core, eng, t, s, g);
    }
    // Track every delivered fd, then drop all caller-held files.
    while let Ok(out) = rx.try_recv() {
        if let Some(fd) = out.file {
            tracked.push(Arc::downgrade(&fd));
        }
    }
    held.clear();

    // (1) No fd leaked: every synthesized `Arc` has dropped (fd closed).
    let leaked = tracked.iter().filter(|w| w.upgrade().is_some()).count();
    assert_eq!(leaked, 0, "{leaked} fd(s) leaked after drain (seed {seed})");
    // (2) Op slots reconcile: `op_free` is a permutation of `0..OP_SLOTS`.
    let mut free = core.op_free.clone();
    free.sort_unstable();
    assert_eq!(
        free,
        (0..OP_SLOTS).collect::<Vec<_>>(),
        "op slots leaked or double-freed (seed {seed})"
    );
}
