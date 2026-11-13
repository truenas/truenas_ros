use super::*;

/// A tag with no arm must be refused before an SQE is filled, since `fill_sqe` zeroes the slot and opcode 0 is
/// `IORING_OP_NOP`, which completes `res = 0` and reads as `Ok(0)` for an op that never ran. This is the release half
/// of the guard.
#[cfg(not(debug_assertions))]
#[test]
fn an_unknown_tag_is_refused_rather_than_staged_as_a_nop() {
    let Some(mut eng) = engine_or_skip() else {
        return;
    };
    let mut core = FsCore::new(8, OffloadBounds::default());
    let before = snapshot(&core);

    let fd = synth_fd();
    // SAFETY: `synth_fd` just opened it; nothing else owns it.
    let file = Arc::new(unsafe { crate::fd::owned_from_raw(fd) });
    let (tx, rx) = mpsc::channel();
    core.submit_fd_meta(
        &mut eng,
        0x7F, // no arm in either match
        1,
        file,
        None,
        vec![1, 2, 3],
        0,
        0,
        0,
        chan(&tx),
    );
    let out = rx.try_recv().expect("refusal is delivered, not dropped");
    assert_eq!(out.res, Err(Errno::EINVAL));
    assert_eq!(out.bufs, vec![vec![1u8, 2, 3]], "the value comes back");

    let (tx2, rx2) = mpsc::channel();
    core.submit_path_op(
        &mut eng,
        0x7E,
        1,
        Anchor::open("/").expect("anchor /"),
        b"x",
        None,
        None,
        0,
        0,
        chan(&tx2),
    );
    assert_eq!(rx2.try_recv().expect("delivered").res, Err(Errno::EINVAL));

    assert!(inflight(&core).is_empty(), "nothing was staged");
    assert_eq!(snapshot(&core), before, "no op slot was consumed");
}

/// The debug half of the guard above: the same call trips the `debug_assert!(false)` rather than reaching the
/// refusal.
#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "not an fd-meta tag")]
fn an_unknown_tag_asserts_in_debug() {
    let Some(mut eng) = engine_or_skip() else {
        // A `should_panic` test cannot skip; panic with the expected message so an unavailable ring does not read
        // as a regression.
        panic!("not an fd-meta tag (io_uring unavailable: skipped)");
    };
    let mut core = FsCore::new(8, OffloadBounds::default());
    let fd = synth_fd();
    // SAFETY: `synth_fd` just opened it; nothing else owns it.
    let file = Arc::new(unsafe { crate::fd::owned_from_raw(fd) });
    let (tx, _rx) = mpsc::channel();
    core.submit_fd_meta(&mut eng, 0x7F, 1, file, None, Vec::new(), 0, 0, 0, chan(&tx));
}

/// A short leased write must not look like success, since its source buffer is already on its way back to the pool, and
/// ZFS returns partial writes as successes (`zfs_write`). The reap is the one place that knows both the asked-for and
/// the written count.
#[cfg(feature = "net-server")]
#[test]
fn a_short_leased_write_is_an_error() {
    let Some(mut eng) = engine_or_skip() else {
        return;
    };
    let mut core = FsCore::new(8, OffloadBounds::default());
    let buf = vec![7u8; 8192];
    let fd = synth_fd();
    // SAFETY: `synth_fd` just opened it; nothing else owns it.
    let file = Arc::new(unsafe { crate::fd::owned_from_raw(fd) });

    // Short: the kernel wrote less than the lease asked for.
    let (tx, rx) = mpsc::channel();
    let staged = core.submit_pwritev2_gathered(
        &mut eng,
        0,
        Arc::clone(&file),
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
    let _ = core.on_cqe(&mut eng, t, s, g, 4096);
    let out = rx.try_recv().expect("delivered");
    assert_eq!(out.res, Err(Errno::EIO), "a short leased write surfaced as success");

    // Full: the same submit at the written size is an ordinary success.
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
    let _ = core.on_cqe(&mut eng, t, s, g, 8192);
    let out = rx.try_recv().expect("delivered");
    assert_eq!(out.res, Ok(8192), "a full leased write is untouched");
}

/// A short owned write is an ordinary success with its count, as a copied one is, since the buffer comes back whole
/// with the completion and the caller can write the rest from it. ZFS writes short only at a quota or a full pool,
/// so the count is handed in.
#[test]
fn a_short_owned_write_answers_its_count_with_its_buffer() {
    let Some(mut eng) = engine_or_skip() else {
        return;
    };
    let mut core = FsCore::new(8, OffloadBounds::default());
    let buf = vec![7u8; 8192];
    let storage = buf.as_ptr();
    let fd = synth_fd();
    // SAFETY: `synth_fd` just opened it; nothing else owns it.
    let file = Arc::new(unsafe { crate::fd::owned_from_raw(fd) });
    let (tx, rx) = mpsc::channel();
    let w = chan(&tx);
    core.submit_write_owned(&mut eng, 0, file, buf, 0..8192, 0, 0, w);
    let [(t, s, g)] = inflight(&core)[..] else {
        panic!("one op in flight");
    };
    let _ = core.on_cqe(&mut eng, t, s, g, 4096);
    let out = rx.try_recv().expect("delivered");
    assert_eq!(out.res, Ok(4096), "a short owned write is its count");
    let [back] = &out.bufs[..] else {
        panic!("one buffer back, not {}", out.bufs.len());
    };
    assert_eq!((back.as_ptr(), back.len()), (storage, 8192));
}

/// A short leased write still fails with `EIO`, and the count it wrote comes beside the failure, for a caller that
/// answers the count rather than retrying. A full one has no count beside its `Ok`.
#[cfg(feature = "net-server")]
#[test]
fn a_short_leased_write_gives_its_count_beside_its_eio() {
    let Some(mut eng) = engine_or_skip() else {
        return;
    };
    let mut core = FsCore::new(8, OffloadBounds::default());
    let buf = vec![7u8; 8192];
    let fd = synth_fd();
    // SAFETY: `synth_fd` just opened it; nothing else owns it.
    let file = Arc::new(unsafe { crate::fd::owned_from_raw(fd) });
    let short = (4096, Err(Errno::EIO), Some(4096));
    for (written, res, count) in [short, (8192, Ok(8192), None)] {
        let hold = std::sync::Arc::new(LeaseHold::detached(9));
        let staged = core.submit_pwritev2_gathered(
            &mut eng,
            0,
            Arc::clone(&file),
            vec![window_over(&buf, &hold)],
            0,
            0,
            embedded_noop(),
        );
        assert!(staged.is_ok(), "staged");
        drop(hold);
        let [(t, s, g)] = inflight(&core)[..] else {
            panic!("one op in flight");
        };
        let ReapedFs::Embedded(_, done, _) = core.on_cqe(&mut eng, t, s, g, written) else {
            panic!("an embedded waiter reaps embedded");
        };
        assert_eq!((done.raw_result(), done.short_count()), (res, count));
    }
}

/// One window is staged as one `WRITE` of its bytes, with no iovec, and its short write fails with `EIO` and gives
/// its count as a gather's does, while the buffer still comes back from its last share.
#[cfg(feature = "net-server")]
#[test]
fn a_short_window_write_gives_its_count_beside_its_eio() {
    let Some(mut eng) = engine_or_skip() else {
        return;
    };
    let mut core = FsCore::new(8, OffloadBounds::default());
    let buf = vec![7u8; 8192];
    let fd = synth_fd();
    // SAFETY: `synth_fd` just opened it; nothing else owns it.
    let file = Arc::new(unsafe { crate::fd::owned_from_raw(fd) });
    let hold = std::sync::Arc::new(LeaseHold::detached(9));
    let staged = core.submit_pwritev2_gathered(&mut eng, 0, file, [window_over(&buf, &hold)], 0, 0, embedded_noop());
    assert!(staged.is_ok(), "staged");
    drop(hold);
    let sqe = eng.staged_sqe(0);
    assert_eq!(
        (sqe.opcode, sqe.addr, sqe.len),
        (IORING_OP_WRITE, buf.as_ptr() as u64, 8192),
        "one window is one WRITE of its bytes"
    );
    let [(t, s, g)] = inflight(&core)[..] else {
        panic!("one op in flight");
    };
    let ReapedFs::Embedded(_, mut done, _) = core.on_cqe(&mut eng, t, s, g, 4096) else {
        panic!("an embedded waiter reaps embedded");
    };
    assert_eq!((done.raw_result(), done.short_count()), (Err(Errno::EIO), Some(4096)));
    assert_eq!(done.take_recv_lease(), Some(9), "the buffer comes back");
}

/// A hold of another core's pool, reaped here as a write's last share or taken here as a job's, gives this core no
/// id, and its id reaches its own core's queue, so no ring puts another ring's buffer in its pool. A hold of this
/// core's pool gives its id here and nowhere else.
#[cfg(feature = "net-server")]
#[test]
fn a_hold_of_another_core_goes_home() {
    let Some(mut eng) = engine_or_skip() else {
        return;
    };
    let mut fs = FsCore::new(8, OffloadBounds::default());
    let mut other = FsCore::new(4, OffloadBounds::default());
    let theirs = other.lease_returns(&eng.shared);
    let buf = vec![7u8; 64];
    let fd = synth_fd();
    // SAFETY: `synth_fd` just opened it; nothing else owns it.
    let file = Arc::new(unsafe { crate::fd::owned_from_raw(fd) });
    // A gather of two of their buffers, then one window of ours.
    let ours = fs.lease_returns(&eng.shared);
    for bids in [&[5, 7][..], &[6][..]] {
        let returns = if bids == [6] { &ours } else { &theirs };
        let holds: Vec<_> = bids
            .iter()
            .map(|&bid| std::sync::Arc::new(LeaseHold::new(bid, returns.clone())))
            .collect();
        let windows: Vec<LeasedWindow> = holds.iter().map(|hold| window_over(&buf, hold)).collect();
        let staged = fs.submit_pwritev2_gathered(&mut eng, 0, Arc::clone(&file), windows, 0, 0, embedded_noop());
        assert!(staged.is_ok(), "staged");
        drop(holds);
        let [(t, s, g)] = inflight(&fs)[..] else {
            panic!("one op in flight");
        };
        let written = (buf.len() * bids.len()) as i32;
        let ReapedFs::Embedded(_, mut done, _) = fs.on_cqe(&mut eng, t, s, g, written) else {
            panic!("an embedded waiter reaps embedded");
        };
        let mut given: Vec<u16> = done.take_recv_lease().into_iter().collect();
        given.extend(done.take_recv_lease_more());
        let want: &[u16] = if bids == [6] { &[6] } else { &[] };
        assert_eq!(given, want, "{bids:?}");
    }
    let mut home = other.take_pool_releases();
    home.sort_unstable();
    assert_eq!(home, [5, 7], "the write's go home");
    assert!(fs.take_pool_releases().is_empty(), "none came back twice");

    let wake = crate::uring::wake::WakeHandle::new().expect("wake");
    let (sink, hold) = (fs.completion_sink(), std::sync::Arc::new(LeaseHold::new(8, theirs)));
    let token = fs.register_leased_offload(None, Box::new(|_any, _conn| {}), hold);
    finish_offload(&sink, &wake, token, Box::new(()));
    assert_eq!(fs.take_pool_completions().len(), 1, "the job is taken");
    assert!(fs.take_pool_releases().is_empty(), "no id of theirs here");
    assert_eq!(other.take_pool_releases(), [8], "the job's goes home");
}

/// N writes share one claim, and the buffer surfaces from the last. Releasing at the first completion would re-post the
/// buffer while the sibling's DMA still reads it, and a short write fails its own op alone, whether or not it releases.
#[cfg(feature = "net-server")]
#[test]
fn the_last_shared_lease_releases_the_buffer() {
    let Some(mut eng) = engine_or_skip() else {
        return;
    };
    let mut core = FsCore::new(8, OffloadBounds::default());
    let buf = vec![7u8; 8192];
    let fd = synth_fd();
    // SAFETY: `synth_fd` just opened it; nothing else owns it.
    let file = Arc::new(unsafe { crate::fd::owned_from_raw(fd) });
    let hold = std::sync::Arc::new(LeaseHold::detached(9));

    for off in [0u64, 4096] {
        let staged = core.submit_pwritev2_gathered(
            &mut eng,
            0,
            Arc::clone(&file),
            vec![LeasedWindow {
                view: LeasedBytes {
                    // SAFETY: within `buf`, which outlives both submissions.
                    ptr: unsafe { buf.as_ptr().add(off as usize) },
                    len: 4096,
                },
                hold: std::sync::Arc::clone(&hold),
            }],
            off,
            0,
            // No facade here, so no sink to arm from; every shipping submission goes through `FsConn::waiter`.
            FsWaiter::Embedded {
                owner: Some((0, 0)),
                cb: Box::new(|_d, _fs| {}),
                on_fail: armed::unarmed(),
            },
        );
        assert!(staged.is_ok(), "staged");
    }
    drop(hold); // as the facade does: only the ops hold shares now

    let mut flight = inflight(&core);
    flight.sort();
    let [(ta, sa, ga), (tb, sb, gb)] = flight[..] else {
        panic!("two ops in flight");
    };
    // First completion: SHORT. Its op fails EIO; the buffer is withheld because a sibling still reads it.
    let ReapedFs::Embedded(_, mut a, _) = core.on_cqe(&mut eng, ta, sa, ga, 100) else {
        panic!("an embedded waiter reaps embedded");
    };
    assert!(
        matches!(a.result(), Err(crate::Error::Errno(Errno::EIO))),
        "short fails its own op"
    );
    assert_eq!(
        a.take_recv_lease(),
        None,
        "the buffer must not come back while a sibling reads it"
    );
    // Last completion: full. Its op succeeds and carries the id out.
    let ReapedFs::Embedded(_, mut b, _) = core.on_cqe(&mut eng, tb, sb, gb, 4096) else {
        panic!("an embedded waiter reaps embedded");
    };
    assert_eq!(b.result().ok(), Some(4096), "the sibling is unaffected");
    assert_eq!(
        b.take_recv_lease(),
        Some(9),
        "the last share surfaces the id exactly once"
    );
}

/// An embedded waiter for the gathered-write tests, which have no facade to arm one from.
#[cfg(feature = "net-server")]
fn embedded_noop() -> FsWaiter {
    FsWaiter::Embedded {
        owner: Some((0, 0)),
        cb: Box::new(|_d, _fs| {}),
        on_fail: armed::unarmed(),
    }
}

/// A window over `buf` holding its own share of `hold`.
#[cfg(feature = "net-server")]
fn window_over(buf: &[u8], hold: &std::sync::Arc<LeaseHold>) -> LeasedWindow {
    LeasedWindow {
        view: LeasedBytes {
            ptr: buf.as_ptr(),
            len: buf.len(),
        },
        hold: std::sync::Arc::clone(hold),
    }
}

/// Leased writes against a table with room for three, driven at random: a write is refused only while the table is
/// full, and across completions (some failed), refusals, owner sweeps and dropped windows every write is answered
/// once and every buffer returned once, whichever share goes last.
#[cfg(feature = "net-server")]
#[test]
fn refused_leased_writes_answer_and_return_every_buffer_once() {
    use std::cell::RefCell;
    use std::collections::HashSet;
    use std::rc::Rc;
    const SLOTS: u32 = 3;
    const STEPS: usize = 3000;
    const OWNERS: u32 = 4;
    // Above every SQE the run stages, so nothing reaches the kernel.
    const ENTRIES: u32 = 8192;
    const WINDOW: usize = 4096;
    let mut eng = match Engine::new(ENTRIES, POOL) {
        Ok(e) => e,
        Err(crate::Error::Errno(e)) if crate::uring::setup_unavailable(e) => {
            return;
        }
        Err(e) => panic!("engine: {e}"),
    };
    let mut core = FsCore::new(SLOTS, OffloadBounds::default());
    let fd = synth_fd();
    // SAFETY: `synth_fd` just opened it; nothing else owns it.
    let file = Arc::new(unsafe { crate::fd::owned_from_raw(fd) });
    let buf = vec![0u8; WINDOW];
    let answered = Rc::new(RefCell::new(Vec::new()));
    let mut returned = HashSet::new();
    let mut minted = Vec::new();
    let mut generations = [0u64; OWNERS as usize];
    let mut carry: Option<std::sync::Arc<LeaseHold>> = None;
    let mut submitted = 0usize;
    let mut refused = 0usize;
    let mut rng = Rng::new(0x9A2C);

    let mut surface = |bid: u16| {
        assert!(returned.insert(bid), "buffer {bid} returned twice");
    };
    let complete = |core: &mut FsCore, eng: &mut Engine, surface: &mut dyn FnMut(u16), op: (u8, u32, u32), res: i32| {
        let (tag, slot, generation) = op;
        let reaped = core.on_cqe(eng, tag, slot, generation, res);
        if let ReapedFs::Embedded(cb, mut done, owner) = reaped {
            done.take_recv_lease().into_iter().for_each(&mut *surface);
            done.take_recv_lease_more().into_iter().for_each(&mut *surface);
            cb(done, &mut FsConn::new(core, eng, owner));
        }
    };

    for _ in 0..STEPS {
        match rng.below(10) {
            0..=4 => {
                let at = rng.below(OWNERS);
                let owner = Some((at, generations[at as usize]));
                let n = 1 + rng.below(3);
                let mut windows = Vec::new();
                for w in 0..n {
                    let hold = match (w, carry.take()) {
                        (0, Some(h)) => h,
                        (_, back) => {
                            carry = back;
                            let bid = minted.len() as u16;
                            minted.push(bid);
                            std::sync::Arc::new(LeaseHold::new(bid, core.lease_returns(&eng.shared)))
                        }
                    };
                    windows.push(window_over(&buf, &hold));
                    if w + 1 == n && rng.below(3) == 0 {
                        carry = Some(hold);
                    }
                }
                let id = submitted;
                submitted += 1;
                let answered = Rc::clone(&answered);
                let waiter = FsWaiter::Embedded {
                    owner,
                    cb: Box::new(move |_d, _fs| answered.borrow_mut().push(id)),
                    on_fail: armed::unarmed(),
                };
                let full = !core.has_free_op();
                core.submit_leased_or_refuse(&mut eng, 0, Arc::clone(&file), windows, 0, 0, waiter);
                while let Some((owner, cb, done)) = core.take_refusal() {
                    assert!(full, "a write refused while a slot was free");
                    assert_eq!(done.raw_result(), Err(Errno::EBUSY));
                    assert!(done.was_refused(), "capacity: marked");
                    refused += 1;
                    cb(done, &mut FsConn::new(&mut core, &mut eng, owner));
                }
            }
            5..=7 => {
                let flight = inflight(&core);
                if flight.is_empty() {
                    continue;
                }
                let op = flight[rng.below(flight.len() as u32) as usize];
                let want = core.ops[op.1 as usize].state.lease_want as i32;
                let res = if rng.below(8) == 0 { -libc::ECANCELED } else { want };
                complete(&mut core, &mut eng, &mut surface, op, res);
            }
            8 => {
                let at = rng.below(OWNERS);
                let swept = (at, generations[at as usize]);
                core.cancel_owned_by(&mut eng, vec![swept]);
                generations[at as usize] += 1;
            }
            _ => carry = None,
        }
        core.take_pool_releases().into_iter().for_each(&mut surface);
    }

    carry = None;
    loop {
        let flight = inflight(&core);
        if flight.is_empty() {
            break;
        }
        for op in flight {
            let want = core.ops[op.1 as usize].state.lease_want as i32;
            complete(&mut core, &mut eng, &mut surface, op, want);
        }
    }
    drop(carry);
    core.take_pool_releases().into_iter().for_each(&mut surface);
    let mut answered = answered.borrow().clone();
    answered.sort_unstable();
    assert_eq!(answered, (0..submitted).collect::<Vec<_>>(), "each write answered once");
    let mut returned: Vec<u16> = returned.into_iter().collect();
    returned.sort_unstable();
    assert_eq!(returned, minted, "each buffer returned once");
    assert!(refused > 0, "the run never filled the table");
}

/// Past `UIO_MAXIOV` iovecs the kernel refuses a write, and past `MAX_RW_COUNT` bytes it trims one, so either takes
/// the copy path.
#[cfg(feature = "net-server")]
#[test]
fn a_gather_fits_one_writev_or_takes_the_copy_path() {
    let cap = max_rw_count();
    assert!(cap < i32::MAX as usize, "the cap is page-aligned below");
    assert!(gather_fits(1, cap));
    assert!(!gather_fits(1, cap + 1), "trimmed by the kernel");
    assert!(gather_fits(UIO_MAXIOV, 0));
    assert!(!gather_fits(UIO_MAXIOV + 1, 0), "refused by the kernel");
    assert!(!gather_fits(0, 0), "nothing to gather");
}

/// A gathered write returns each buffer once, from its last share - including one two split windows share - and a
/// short count fails it `EIO`.
#[cfg(feature = "net-server")]
#[test]
fn a_gathered_write_returns_each_buffer_once() {
    let Some(mut eng) = engine_or_skip() else {
        return;
    };
    let mut core = FsCore::new(8, OffloadBounds::default());
    let (a, b) = (vec![1u8; 8192], vec![2u8; 4096]);
    let fd = synth_fd();
    // SAFETY: `synth_fd` just opened it; nothing else owns it.
    let file = Arc::new(unsafe { crate::fd::owned_from_raw(fd) });
    for (res, want) in [(12288, Ok(12288)), (100, Err(Errno::EIO))] {
        let (hold_a, hold_b) = (
            std::sync::Arc::new(LeaseHold::detached(9)),
            std::sync::Arc::new(LeaseHold::detached(10)),
        );
        let (head, tail) = window_over(&a, &hold_a).split_at(4096);
        let windows = vec![head, window_over(&b, &hold_b), tail];
        drop((hold_a, hold_b)); // only the windows hold shares now
        let staged = core.submit_pwritev2_gathered(&mut eng, 0, Arc::clone(&file), windows, 0, 0, embedded_noop());
        assert!(staged.is_ok(), "staged");
        let [(t, sl, g)] = inflight(&core)[..] else {
            panic!("one op in flight");
        };
        assert_eq!(core.ops[sl as usize].state.iov.len(), 3, "one iovec per window");
        let ReapedFs::Embedded(_, mut done, _) = core.on_cqe(&mut eng, t, sl, g, res) else {
            panic!("an embedded waiter reaps embedded");
        };
        assert_eq!(done.raw_result(), want, "the whole op's verdict");
        let mut bids: Vec<u16> = done
            .take_recv_lease()
            .into_iter()
            .chain(done.take_recv_lease_more())
            .collect();
        bids.sort_unstable();
        assert_eq!(bids, [9, 10], "each buffer once, from its last share");
    }
}

/// A gathered write the core cannot take hands every window back, with nothing in flight: none at all, or more than
/// one `WRITEV` carries.
#[cfg(feature = "net-server")]
#[test]
fn a_refused_gathered_write_hands_its_windows_back() {
    let Some(mut eng) = engine_or_skip() else {
        return;
    };
    let mut core = FsCore::new(8, OffloadBounds::default());
    let buf = vec![3u8; 64];
    let fd = synth_fd();
    // SAFETY: `synth_fd` just opened it; nothing else owns it.
    let file = Arc::new(unsafe { crate::fd::owned_from_raw(fd) });
    let hold = std::sync::Arc::new(LeaseHold::detached(9));
    for n in [0, UIO_MAXIOV + 1] {
        let windows: Vec<LeasedWindow> = (0..n).map(|_| window_over(&buf, &hold)).collect();
        let Err((Some(back), _)) =
            core.submit_pwritev2_gathered(&mut eng, 0, Arc::clone(&file), windows, 0, 0, embedded_noop())
        else {
            panic!("{n} windows must be refused and handed back");
        };
        assert_eq!(back.len(), n, "every window comes back");
        assert!(inflight(&core).is_empty(), "nothing went in flight");
    }
}

/// A window reads as the bytes it was leased over, and so do both halves of a split, each where it begins.
#[cfg(feature = "net-server")]
#[test]
fn a_window_reads_as_the_bytes_it_was_leased_over() {
    let buf = b"<head|tail>".to_vec();
    let hold = std::sync::Arc::new(LeaseHold::detached(9));
    let window = window_over(&buf[1..10], &hold);
    assert_eq!(&*window, b"head|tail");
    let (head, tail) = window.split_at(5);
    assert_eq!((&*head, &*tail), (&b"head|"[..], &b"tail"[..]));
    assert_eq!((head.len(), tail.len()), (5, 4), "its own lengths stay");
}

/// Both halves of a split window read the buffer, so both hold it.
#[cfg(feature = "net-server")]
#[test]
fn a_split_window_shares_its_buffer() {
    let buf = vec![5u8; 100];
    let hold = std::sync::Arc::new(LeaseHold::detached(9));
    let (head, tail) = window_over(&buf, &hold).split_at(30);
    assert_eq!((head.len(), tail.len()), (30, 70));
    assert_eq!(tail.view.ptr, buf.as_ptr().wrapping_add(30));
    assert_eq!(std::sync::Arc::strong_count(&hold), 3, "two halves");
    drop((head, tail));
    assert_eq!(std::sync::Arc::strong_count(&hold), 1, "both let go");
}

#[cfg(feature = "net-server")]
#[test]
#[should_panic(expected = "split past the window's end")]
fn a_split_past_the_end_panics() {
    let buf = vec![5u8; 100];
    let hold = std::sync::Arc::new(LeaseHold::detached(9));
    let _ = window_over(&buf, &hold).split_at(101);
}
