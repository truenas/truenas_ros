use super::*;

/// The timer composes with the future layer like any submission: a task awaits its tick and resumes on the loop
/// that armed it.
#[test]
fn a_task_awaits_a_timer() {
    let Some((mut eng, mut fs, _who)) = rig() else {
        return;
    };
    let done = Rc::new(StdCell::new(false));
    let started = Instant::now();
    {
        let done = Rc::clone(&done);
        let mut conn = FsConn::new(&mut fs, &mut eng, None);
        conn.spawn(move |t| async move {
            let fired = t
                .fut(|c, cb| {
                    // The frame's sink carries any refusal.
                    let _ = c.timeout(Duration::from_millis(30), cb);
                })
                .await;
            assert!(fired.result().is_ok(), "{:?}", fired.result().err());
            done.set(true);
        });
    }
    drive(&mut fs, &mut eng, &done, "task timer");
    assert!(
        started.elapsed() >= Duration::from_millis(25),
        "fired early: {:?}",
        started.elapsed()
    );
}

/// The core claim: a whole write chain - open, write, fsync, stat, read back - as one straight-line task, every hop
/// on the ring.
#[test]
fn a_task_awaits_a_whole_chain_on_the_ring() {
    let Some((mut eng, mut fs, who)) = rig() else {
        return;
    };
    let dir = crate::tempdir::tempdir().expect("tempdir");
    let anchor = Anchor::open(dir.path()).expect("anchor");
    let payload: Vec<u8> = (0..4096u32).map(|i| i as u8).collect();
    let done = Rc::new(StdCell::new(false));

    {
        let (done, payload) = (Rc::clone(&done), payload.clone());
        let mut conn = FsConn::new(&mut fs, &mut eng, None);
        conn.spawn(move |t| async move {
            let opened = t.fut(|c, cb| c.open(who, &anchor, c"demo.bin", creating(), cb)).await;
            let file = opened.file().expect("open");

            let wrote = t
                .fut(|c, cb| c.pwritev2(who, file.clone(), vec![payload.clone()], 0, RwFlags::empty(), cb))
                .await;
            assert_eq!(wrote.result().expect("write") as usize, payload.len());

            t.fut(|c, cb| c.fsync(who, file.clone(), cb))
                .await
                .result()
                .expect("fsync");

            let stat = t
                .fut(|c, cb| c.fstatx(who, &file, AtFlags::empty(), StatxMask::BASIC_STATS, cb))
                .await;
            assert_eq!(stat.stat().expect("statx").size(), payload.len() as u64);

            let read = t
                .fut(|c, cb| {
                    c.preadv2(
                        who,
                        file.clone(),
                        vec![vec![0u8; payload.len()]],
                        0,
                        RwFlags::empty(),
                        cb,
                    )
                })
                .await;
            assert_eq!(read.result().expect("read") as usize, payload.len());
            assert_eq!(read.into_bufs()[0], payload);
            done.set(true);
        });
    }
    drive(&mut fs, &mut eng, &done, "write chain");
}

/// Two futures made back to back are both in flight before either is awaited - eager submission is what overlaps
/// them.
#[test]
fn futures_submit_eagerly_and_overlap() {
    let Some((mut eng, mut fs, who)) = rig() else {
        return;
    };
    let dir = crate::tempdir::tempdir().expect("tempdir");
    let anchor = Anchor::open(dir.path()).expect("anchor");
    std::fs::write(dir.path().join("a"), b"a").expect("seed a");
    std::fs::write(dir.path().join("b"), b"bb").expect("seed b");
    let done = Rc::new(StdCell::new(false));

    {
        let done = Rc::clone(&done);
        let mut conn = FsConn::new(&mut fs, &mut eng, None);
        conn.spawn(move |t| async move {
            let ro = || OpenHow::new().flags(OFlag::O_RDONLY);
            let a = t.fut(|c, cb| c.open(who, &anchor, c"a", ro(), cb));
            let b = t.fut(|c, cb| c.open(who, &anchor, c"b", ro(), cb));
            // Both submitted above; awaiting in either order works.
            let (a, b) = (a.await, b.await);
            assert!(a.file().is_some(), "a: {:?}", a.result());
            assert!(b.file().is_some(), "b: {:?}", b.result());
            done.set(true);
        });
    }
    drive(&mut fs, &mut eng, &done, "overlapping opens");
}

/// A refused submission resolves with the reason, not a blanket `ECANCELED`: an argument the facade will never
/// accept answers `EINVAL`, and a full op table answers `EBUSY` - which a task can retry. Both arrive with no CQE
/// ever produced.
#[test]
fn a_refusal_resolves_with_the_errno_it_was_refused_for() {
    let Some((mut eng, mut fs, who)) = rig() else {
        return;
    };
    let dir = crate::tempdir::tempdir().expect("tempdir");
    let anchor = Anchor::open(dir.path()).expect("anchor");

    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);

    // An absolute path: refused by the facade, never submitted.
    let mut conn = FsConn::new(&mut fs, &mut eng, None);
    let bad = conn.fut(|c, cb| c.open(who, &anchor, c"/etc/hostname", creating(), cb));
    let mut bad = std::pin::pin!(bad);
    let Poll::Ready(done) = bad.as_mut().poll(&mut cx) else {
        panic!("a refused submission left its future pending");
    };
    assert!(
        matches!(done.result(), Err(crate::Error::Errno(Errno::EINVAL))),
        "want EINVAL, got {:?}",
        done.result()
    );

    // Fill the op table (8 slots), then more: each surplus is EBUSY, delivered at the wake drain its queued
    // callback rides.
    let mut held = Vec::new();
    for _ in 0..16 {
        held.push(conn.fut(|c, cb| c.open(who, &anchor, c".", spec_dir(), cb)));
    }
    let mut busy = false;
    let deadline = Instant::now() + Duration::from_secs(10);
    while !busy {
        assert!(
            Instant::now() < deadline,
            "a full op table must answer EBUSY, not ECANCELED"
        );
        held.retain_mut(|f| match Pin::new(&mut *f).poll(&mut cx) {
            Poll::Ready(d) => {
                if matches!(d.result(), Err(crate::Error::Errno(Errno::EBUSY))) {
                    busy = true;
                }
                false
            }
            Poll::Pending => true,
        });
        if !busy && turn(&mut fs, &mut eng) == 0 {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}

/// ZFS's `f_type` magic - `statfs(2)`, and `Statfs::fs_type`'s own doc.
const ZFS_SUPER_MAGIC: i64 = 0x2fc1_2fc1;

/// The offload-shaped half of the facade, awaited from one task: the capacity tail, the xattr list, the ZFS
/// attribute ioctl, server-side copy, and the `open_dir`/`next_batch` walk whose first step is itself a ring op.
///
/// The attribute ioctl must answer `Ok` on ZFS and `ENOTTY` anywhere else, judged by the `f_type` this test reads, so
/// both arms assert and neither degrades into a skip. Outcomes are asserted after the drive, since an `assert!` in a
/// task body is contained into its `JoinHandle` and its message lost.
#[test]
fn a_task_awaits_the_offload_shaped_ops_and_sees_the_filesystem() {
    let Some((mut eng, mut fs, who)) = rig() else {
        return;
    };
    eng.arm_wake(pack_raw(TAG_WAKE, 0, 0)).expect("arm wake");
    let dir = crate::tempdir::tempdir().expect("tempdir");
    let anchor = Anchor::open(dir.path()).expect("anchor");
    let done = Rc::new(StdCell::new(false));

    type Seen = (
        Option<i64>,                    // fstatfs f_type
        Option<usize>,                  // flistxattr count
        Option<crate::Result<ZfsAttr>>, // the ioctl, either way
        Option<crate::Result<u64>>,     // copy_file_range
        Option<usize>,                  // next_batch names
    );
    let seen: Rc<StdRefCell<Seen>> = Rc::new(StdRefCell::new(Default::default()));

    {
        let (done, seen) = (Rc::clone(&done), Rc::clone(&seen));
        let anchor2 = anchor.clone();
        let mut conn = FsConn::new(&mut fs, &mut eng, None);
        conn.spawn(move |t| async move {
            let src = t
                .fut(|c, cb| c.open(who, &anchor2, c"src.bin", creating(), cb))
                .await
                .file()
                .expect("open src");
            let wrote = t
                .fut(|c, cb| c.pwritev2(who, src.clone(), vec![b"payload".to_vec()], 0, RwFlags::empty(), cb))
                .await;
            assert_eq!(wrote.result().expect("write"), 7);

            let st = t.result_fut(|c, cb| c.fstatfs(src.clone(), cb)).await.expect("fstatfs");
            seen.borrow_mut().0 = Some(st.fs_type());

            let names = t
                .result_fut(|c, cb| c.flistxattr(src.clone(), cb))
                .await
                .expect("flistxattr");
            seen.borrow_mut().1 = Some(names.len());

            seen.borrow_mut().2 = Some(t.result_fut(|c, cb| c.fget_zfs_attrs(src.clone(), cb)).await);

            let dst = t
                .fut(|c, cb| c.open(who, &anchor2, c"dst.bin", creating(), cb))
                .await
                .file()
                .expect("open dst");
            seen.borrow_mut().3 = Some(
                t.result_fut(|c, cb| c.copy_file_range(src.clone(), dst, 0, 0, 7, cb))
                    .await,
            );

            let walk = t
                .result_fut(|c, cb| c.open_dir(who, &anchor2, cb))
                .await
                .expect("open_dir");
            let batch = t.result_fut(|c, cb| c.next_batch(&walk, cb)).await.expect("next_batch");
            seen.borrow_mut().4 = Some(batch.names.len());

            done.set(true);
        });
    }
    drive(&mut fs, &mut eng, &done, "offload-shaped ops");

    let (f_type, xattrs, zfs, copied, entries) = std::mem::take(&mut *seen.borrow_mut());
    let f_type = f_type.expect("fstatfs answered");
    assert_eq!(xattrs, Some(0), "a fresh file carries no xattrs");
    assert_eq!(copied.expect("copy answered").expect("copy"), 7);
    assert_eq!(entries, Some(2), "src.bin and dst.bin");

    let zfs = zfs.expect("the ioctl answered");
    if f_type == ZFS_SUPER_MAGIC {
        zfs.expect("a ZFS dataset must answer the attribute ioctl");
    } else {
        match zfs {
            Err(crate::Error::Errno(Errno::ENOTTY)) => {}
            other => panic!(
                "f_type {f_type:#x} is not ZFS, so the attribute ioctl \
                     must answer ENOTTY, not {other:?}"
            ),
        }
    }
}

/// A refusal hands the payload back, because the retry it advises is impossible without it: the buffers a write was
/// given are dropped on the way out of `deliver`, and nothing tells a caller to keep a second copy.
#[test]
fn a_refusal_hands_back_the_payload_it_advises_retrying() {
    let Some((mut eng, mut fs, who)) = rig() else {
        return;
    };
    let dir = crate::tempdir::tempdir().expect("tempdir");
    let anchor = Anchor::open(dir.path()).expect("anchor");
    let done = Rc::new(StdCell::new(false));
    /// Whether the refusal was marked as this crate's, and the payload it handed back.
    type Refused = Option<(bool, Vec<Vec<u8>>)>;
    let seen: Rc<StdRefCell<Refused>> = Rc::new(StdRefCell::new(None));

    {
        let (done, seen) = (Rc::clone(&done), Rc::clone(&seen));
        let anchor2 = anchor.clone();
        let mut conn = FsConn::new(&mut fs, &mut eng, None);
        conn.spawn(move |t| async move {
            let file = t
                .fut(|c, cb| c.open(who, &anchor2, c"payload.bin", creating(), cb))
                .await
                .file()
                .expect("open");
            // Fill the op table, then write through it.
            let mut held = Vec::new();
            for _ in 0..POOL {
                held.push(t.fut(|c, cb| c.open(who, &anchor2, c".", spec_dir(), cb)));
            }
            let refused = t
                .fut(|c, cb| {
                    c.pwritev2(
                        who,
                        file,
                        vec![b"the body a retry needs".to_vec()],
                        0,
                        RwFlags::empty(),
                        cb,
                    )
                })
                .await;
            assert!(
                matches!(refused.result(), Err(crate::Error::Errno(Errno::EBUSY))),
                "a full op table must answer EBUSY"
            );
            *seen.borrow_mut() = Some((refused.was_refused(), refused.into_bufs()));
            drop(held);
            done.set(true);
        });
    }
    drive(&mut fs, &mut eng, &done, "refused payload");

    let (refused, bufs) = std::mem::take(&mut *seen.borrow_mut()).expect("the write answered");
    assert!(refused, "a full op table is this crate's refusal");
    assert_eq!(
        bufs,
        vec![b"the body a retry needs".to_vec()],
        "a refusal that keeps the payload cannot be retried"
    );
}

/// The errno alone cannot say who answered. `EBUSY` from a full op table is worth retrying; `EBUSY` from the
/// kernel - a directory that is a mountpoint, which every nested dataset is - is permanent, so a task that cannot
/// tell them apart spins forever.
#[test]
fn a_refused_errno_is_marked_as_this_crates_own() {
    let Some((mut eng, mut fs, who)) = rig() else {
        return;
    };
    let dir = crate::tempdir::tempdir().expect("tempdir");
    let anchor = Anchor::open(dir.path()).expect("anchor");
    let done = Rc::new(StdCell::new(false));
    let seen: Rc<StdRefCell<Vec<(Errno, bool)>>> = Rc::new(StdRefCell::new(Vec::new()));

    {
        let (done, seen) = (Rc::clone(&done), Rc::clone(&seen));
        let anchor2 = anchor.clone();
        let mut conn = FsConn::new(&mut fs, &mut eng, None);
        conn.spawn(move |t| async move {
            // The kernel's: nothing of that name.
            let miss = t
                .fut(|c, cb| {
                    c.statx(
                        who,
                        &anchor2,
                        Leaf::new(b"absent").expect("leaf"),
                        AtFlags::empty(),
                        StatxMask::INO,
                        cb,
                    )
                })
                .await;
            let Err(crate::Error::Errno(e)) = miss.result() else {
                panic!("a missing name must fail");
            };
            seen.borrow_mut().push((e, miss.was_refused()));

            // This crate's: an absolute path the facade will not take.
            let bad = t
                .fut(|c, cb| c.open(who, &anchor2, c"/etc/hostname", creating(), cb))
                .await;
            let Err(crate::Error::Errno(e)) = bad.result() else {
                panic!("an absolute path must be refused");
            };
            seen.borrow_mut().push((e, bad.was_refused()));
            done.set(true);
        });
    }
    drive(&mut fs, &mut eng, &done, "refusal provenance");

    let seen = std::mem::take(&mut *seen.borrow_mut());
    assert_eq!(
        seen,
        vec![(Errno::ENOENT, false), (Errno::EINVAL, true)],
        "the kernel's errno must not read as a refusal, nor the reverse"
    );
}

/// A chain submits every step after the first from the fresh facade its predecessor's completion was handed. A sink
/// that one submission consumed would leave every later step reporting teardown for a refusal the caller is told to
/// retry.
#[test]
fn a_chain_step_past_the_first_still_names_its_refusal() {
    let Some((mut eng, mut fs, who)) = rig() else {
        return;
    };
    let dir = crate::tempdir::tempdir().expect("tempdir");
    std::fs::create_dir(dir.path().join("sub")).expect("mkdir sub");
    std::fs::write(dir.path().join("sub/leaf"), b"x").expect("leaf");
    let anchor = Anchor::open(dir.path()).expect("anchor");
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);

    let chained = {
        let mut conn = FsConn::new(&mut fs, &mut eng, None);
        conn.fut(|c, cb| {
            c.open_chain(
                &anchor,
                vec![
                    OpenStep {
                        path: StepPath::Fixed(c"sub".to_owned()),
                        who,
                        how: spec_dir(),
                    },
                    OpenStep {
                        path: StepPath::Fixed(c"leaf".to_owned()),
                        who,
                        how: OpenHow::new().flags(OFlag::O_RDONLY),
                    },
                ],
                cb,
            )
        })
    };
    let mut chained = std::pin::pin!(chained);

    // Take every free slot in the window `on_cqe` opens and `deliver_embedded` closes - which is exactly where the
    // net server's `redrive_parked_tail` takes one - so step two meets a full table.
    let mut stolen = false;
    let deadline = Instant::now() + Duration::from_secs(10);
    let done = loop {
        assert!(Instant::now() < deadline, "the chain never answered");
        if let Poll::Ready(d) = chained.as_mut().poll(&mut cx) {
            break d;
        }
        eng.ring.submit().expect("submit");
        let Some(cqe) = eng.ring.reap() else {
            std::thread::sleep(Duration::from_millis(1));
            continue;
        };
        if cqe.flags & IORING_CQE_F_MORE == 0 {
            eng.inflight = eng.inflight.saturating_sub(1);
        }
        let (tag, slot, gen32) = unpack_raw(cqe.user_data);
        if tag & TAG_FS_DOMAIN == 0 || tag == TAG_CANCEL {
            continue;
        }
        if tag == TAG_WAKE {
            // Step two's refusal rides the wake drain now.
            eng.arm_wake(pack_raw(TAG_WAKE, 0, 0)).expect("re-arm");
            deliver_pool_completions(&mut fs, &mut eng);
            continue;
        }
        let reaped = fs.on_cqe(&mut eng, tag, slot, gen32, cqe.res);
        if !stolen {
            stolen = true;
            let mut thief = FsConn::new(&mut fs, &mut eng, None);
            for _ in 0..POOL {
                thief.open(who, &anchor, c".", spec_dir(), |_, _| {});
            }
        }
        deliver_embedded(&mut fs, &mut eng, reaped);
    };

    assert!(
        matches!(done.result(), Err(crate::Error::Errno(Errno::EBUSY))),
        "step two's refusal must keep its errno, got {:?}",
        done.result()
    );
    assert!(done.was_refused(), "and must read as this crate's own");
}

/// A `fut` inside another `fut`'s submit closure stages a sink of its own. Assigning over the outer's would leave
/// the outer op reporting teardown for its own refusal.
#[test]
fn a_nested_fut_does_not_swallow_the_outer_ones_reason() {
    let Some((mut eng, mut fs, who)) = rig() else {
        return;
    };
    let dir = crate::tempdir::tempdir().expect("tempdir");
    let anchor = Anchor::open(dir.path()).expect("anchor");
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    let mut conn = FsConn::new(&mut fs, &mut eng, None);

    // Leave exactly one free slot: the nested `fut` takes it, so the outer's own submission is the one refused.
    let mut held = Vec::new();
    for _ in 0..POOL - 1 {
        held.push(conn.fut(|c, cb| c.open(who, &anchor, c".", spec_dir(), cb)));
    }
    let mut inner = None;
    let outer = conn.fut(|c, cb| {
        inner = Some(c.fut(|c2, cb2| c2.open(who, &anchor, c".", spec_dir(), cb2)));
        c.open(who, &anchor, c".", spec_dir(), cb);
    });
    let mut outer = std::pin::pin!(outer);
    let deadline = Instant::now() + Duration::from_secs(10);
    let done = loop {
        if let Poll::Ready(d) = outer.as_mut().poll(&mut cx) {
            break d;
        }
        assert!(Instant::now() < deadline, "the outer's refusal never delivered");
        if turn(&mut fs, &mut eng) == 0 {
            std::thread::sleep(Duration::from_millis(1));
        }
    };
    assert!(
        matches!(done.result(), Err(crate::Error::Errno(Errno::EBUSY))),
        "want the outer's own EBUSY, got {:?}",
        done.result()
    );
    assert!(done.was_refused());
    drop((inner, held));
}
