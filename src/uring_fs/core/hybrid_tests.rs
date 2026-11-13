use super::*;
use crate::uring::sys::register_personality;
use crate::uring::user_data::TAG_FS_DOMAIN;

const OWNER0: Owner = Some((0, 0));
const XVAL: &[u8] = b"val";

fn xsum(n: usize) -> u64 {
    n as u64 * XVAL.iter().map(|&b| b as u64).sum::<u64>()
}

fn setup() -> (Engine, FsCore, Personality) {
    let eng = Engine::new(256, 128).expect("engine");
    let fs = FsCore::new(256, OffloadBounds::default());
    let me = Personality(register_personality(eng.ring.raw_fd()).expect("personality"));
    (eng, fs, me)
}

/// Build a fresh owner-scoped `FsConn`, run `kickoff` on it, then drive the loop - firing embedded completions and
/// pool deliveries, re-arming the wake - until `done`. Mirrors the standalone host's run_loop.
fn drive(eng: &mut Engine, fs: &mut FsCore, kickoff: impl FnOnce(&mut FsConn<'_>), done: impl Fn() -> bool) {
    eng.arm_wake(pack_raw(TAG_WAKE, 0, 0)).expect("arm_wake");
    {
        let mut c = FsConn::new(fs, eng, OWNER0);
        kickoff(&mut c);
    }
    // A timer bounds every block, so a missed wake fails at the deadline below instead of hanging the harness.
    //
    // The tag is unused in the fs domain, which this harness dispatches. Tags under 0x80 belong to the net stack.
    //
    // Re-armed only when its completion returns, so one is in flight per call. `drive` can return with one armed;
    // every caller builds a fresh `Engine`, so a stale completion is never reaped.
    const TAG_DRIVE_TIMER: u8 = 0xFF;
    let ts = libc::timespec { tv_sec: 1, tv_nsec: 0 };
    let mut timer_armed = false;
    let mut passes = 0u64;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    while !done() {
        // The pass count is reported because it tells a stall (about one pass per timer expiry) from a busy loop.
        passes += 1;
        assert!(
            std::time::Instant::now() < deadline,
            "reactor stalled: 60s without `done()` over {passes} \
                 passes. ~60 is one per timer expiry, so the loop was \
                 blocking with nothing to reap; far more means it was \
                 reaping and `done()` never came true"
        );
        // As the real loops do before they block (`FsCore::flush_offloads`).
        let recheck = fs.flush_offloads();
        if !timer_armed {
            // The kernel copies the timespec when it preps the SQE;
            // `ts` outlives the submit.
            eng.ring
                .push_sqe(|sqe| {
                    sqe.opcode = IORING_OP_TIMEOUT;
                    sqe.addr = std::ptr::addr_of!(ts) as u64;
                    sqe.len = 1; // exactly one timespec, per the kernel
                    sqe.user_data = pack_raw(TAG_DRIVE_TIMER, 0, 0);
                })
                .expect("stage the drive timer");
            timer_armed = true;
        }
        eng.ring.submit_and_wait_for(1, recheck).expect("submit_and_wait");
        let mut cqes = Vec::new();
        while let Some(cqe) = eng.ring.reap() {
            cqes.push(cqe);
        }
        for cqe in cqes {
            let (tag, slot, g) = unpack_raw(cqe.user_data);
            if tag == TAG_DRIVE_TIMER {
                // `-ETIME` is the timer expiring. Anything else means it never armed and the block is unbounded
                // again.
                assert!(
                    cqe.res == -libc::ETIME || cqe.res == -libc::ECANCELED,
                    "the drive timer was refused: {}",
                    cqe.res
                );
                timer_armed = false;
                continue;
            }
            if tag == TAG_WAKE {
                eng.arm_wake(pack_raw(TAG_WAKE, 0, 0)).expect("arm");
                // The real delivery functions, not a copy of their bodies: a copy silently misses whatever they
                // grow - it missed task draining entirely, so a task spawned in a test here was polled once and
                // then waited on a loop that would never poll it again, hanging instead of failing.
                deliver_pool_completions(fs, eng);
                continue;
            }
            if tag == TAG_CANCEL || tag & TAG_FS_DOMAIN == 0 {
                continue;
            }
            let reaped = fs.on_cqe(eng, tag, slot, g, cqe.res);
            deliver_embedded(fs, eng, reaped);
        }
    }
}

fn fixture(n: usize) -> crate::TempDir {
    let dir = crate::tempdir().expect("tempdir");
    for i in 0..n {
        let p = dir.path().join(format!("f{i}"));
        std::fs::write(&p, b"x").unwrap();
        let cp = CString::new(p.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: valid path / name / value + len.
        let r = unsafe { libc::setxattr(cp.as_ptr(), c"user.bench".as_ptr(), XVAL.as_ptr().cast(), XVAL.len(), 0) };
        assert_eq!(r, 0, "setxattr");
    }
    dir
}

/// Run `f` with this thread's panic printing silenced. The guard carries its own serialization now (see
/// `quiet_panics_on_this_thread`), so this is only the shorthand.
fn with_silent_panics<R>(f: impl FnOnce() -> R) -> R {
    let _quiet = crate::uring_fs::quiet_panics_on_this_thread();
    f()
}

/// `a/b/leaf` under a fresh directory, for the chain tests.
fn nested() -> crate::TempDir {
    let dir = crate::tempdir().expect("tempdir");
    std::fs::create_dir_all(dir.path().join("a/b")).expect("mkdir -p");
    std::fs::write(dir.path().join("a/b/leaf"), b"bytes").expect("write");
    dir
}

/// The whole point of the primitive: reach a file two directories down, in steps, from one facade entry.
#[test]
fn a_chain_reaches_a_file_two_directories_down() {
    let (mut eng, mut fs, me) = setup();
    let dir = nested();
    let at = Anchor::open(dir.path()).expect("anchor");
    let got: Rc<RefCell<Option<bool>>> = Rc::new(RefCell::new(None));
    let g2 = got.clone();
    drive(
        &mut eng,
        &mut fs,
        move |c| {
            c.open_chain(
                &at,
                vec![
                    OpenStep {
                        path: StepPath::Fixed(c"a/b".to_owned()),
                        who: me,
                        how: OpenHow::new().flags(OFlag::O_PATH | OFlag::O_DIRECTORY),
                    },
                    OpenStep {
                        path: StepPath::Fixed(c"leaf".to_owned()),
                        who: me,
                        how: OpenHow::new().flags(OFlag::O_RDONLY),
                    },
                ],
                move |res, _c| {
                    *g2.borrow_mut() = Some(res.file().is_some());
                },
            );
        },
        || got.borrow().is_some(),
    );
    assert_eq!(*got.borrow(), Some(true), "the leaf must be delivered");
}

/// A chain's last step is opened as the caller asked, so unlike every step above it, it can name a special file.
///
/// `O_TRUNC` forces the open async (`io_openat_force_async`, `io_uring/openclose.c`), and `io_openat2` adds
/// `O_NONBLOCK` only on the inline attempt (`IO_URING_F_NONBLOCK`), which a forced io-wq worker does not have - the
/// `WARN_ON_ONCE` beside it is the kernel asserting the two are exclusive. So an unguarded step here reaches
/// `fifo_open`'s `wait_for_partner` (`fs/pipe.c`) and parks a worker and its op slot until the owner's teardown
/// sweep. The guard is what makes it answer instead.
#[test]
fn a_chains_last_step_cannot_park_on_a_fifo() {
    let (mut eng, mut fs, me) = setup();
    let dir = crate::tempdir().expect("tempdir");
    std::fs::create_dir(dir.path().join("a")).expect("mkdir");
    let fifo = dir.path().join("a/pipe");
    let cpath = CString::new(fifo.as_os_str().as_encoded_bytes()).expect("no NUL");
    // SAFETY: a NUL-terminated path naming nothing yet, inside a directory this test made.
    let made = unsafe { libc::mkfifo(cpath.as_ptr(), 0o600) };
    assert_eq!(made, 0, "mkfifo: {}", std::io::Error::last_os_error());

    let at = Anchor::open(dir.path()).expect("anchor");
    let got: Rc<RefCell<Option<Option<Errno>>>> = Rc::new(RefCell::new(None));
    let g2 = got.clone();
    drive(
        &mut eng,
        &mut fs,
        move |c| {
            c.open_chain(
                &at,
                vec![
                    OpenStep {
                        path: StepPath::Fixed(c"a".to_owned()),
                        who: me,
                        how: OpenHow::new().flags(OFlag::O_PATH | OFlag::O_DIRECTORY),
                    },
                    OpenStep {
                        path: StepPath::Fixed(c"pipe".to_owned()),
                        who: me,
                        how: OpenHow::new().flags(OFlag::O_WRONLY | OFlag::O_TRUNC),
                    },
                ],
                move |res, _c| {
                    *g2.borrow_mut() = Some(match res.result() {
                        Err(crate::Error::Errno(e)) => Some(e),
                        _ => None,
                    });
                },
            );
        },
        || got.borrow().is_some(),
    );
    assert_eq!(
        *got.borrow(),
        Some(Some(Errno::ENXIO)),
        "a FIFO with no reader must answer, not park a worker"
    );
}

/// Open the parent of `at` as `me` with `how`, across the top of a mount when `across`, and give back what the open
/// answered.
fn parent_of(at: Anchor, how: OpenHow, across: bool) -> FsDone {
    let (mut eng, mut fs, me) = setup();
    let got: Rc<RefCell<Option<FsDone>>> = Rc::new(RefCell::new(None));
    let g2 = got.clone();
    drive(
        &mut eng,
        &mut fs,
        move |c| {
            let then = move |res, _c: &mut FsConn<'_>| {
                *g2.borrow_mut() = Some(res);
            };
            if across {
                c.open_parent_across_mount(me, &at, how, then);
            } else {
                c.open_parent(me, &at, how, then);
            }
        },
        || got.borrow().is_some(),
    );
    got.borrow_mut().take().expect("answered")
}

/// The object number and the unique mount ID of what `done` opened.
fn opened(done: &FsDone) -> (u64, u64) {
    let file = done.file().expect("the parent opens");
    let mask = StatxMask::INO | StatxMask::MNT_ID_UNIQUE;
    let st = crate::sync_fs::statx(&file, "", AtFlags::AT_EMPTY_PATH, mask).expect("statx");
    (st.ino(), st.mnt_id())
}

/// The parent is the one the directory has now, so a directory that moved answers the directory it moved into, with
/// either open.
#[test]
fn the_parent_of_a_moved_directory_is_where_it_went() {
    use std::os::unix::fs::MetadataExt;
    for across in [false, true] {
        let dir = nested();
        std::fs::create_dir(dir.path().join("c")).expect("mkdir");
        let at = Anchor::open(&dir.path().join("a/b")).expect("anchor");
        std::fs::rename(dir.path().join("a/b"), dir.path().join("c/b")).expect("rename");
        let how = OpenHow::new().flags(OFlag::O_PATH);
        let (ino, _) = opened(&parent_of(at, how, across));
        let went = std::fs::metadata(dir.path().join("c")).expect("stat");
        assert_eq!(ino, went.ino(), "the parent is c, not a ({across})");
    }
}

/// The parent of the top of a mount is on another file system, so the open answers `EXDEV` and never opens the
/// directory under the mount.
#[test]
fn a_parent_open_stops_at_the_top_of_a_mount() {
    let at = Anchor::open("/proc").expect("anchor");
    let how = OpenHow::new().flags(OFlag::O_PATH);
    let done = parent_of(at, how, false);
    assert!(
        matches!(done.result(), Err(crate::Error::Errno(Errno::EXDEV))),
        "{:?}",
        done.result()
    );
}

/// Across the top of a mount, the parent is that of the directory the mount covers, on the file system the mount
/// sits in. `/proc` is mounted on the root, so its parent is `/`.
#[test]
fn a_parent_open_across_a_mount_lands_beside_it() {
    let at = Anchor::open("/proc").expect("anchor");
    let how = OpenHow::new().flags(OFlag::O_PATH);
    let got = opened(&parent_of(at, how, true));
    let mask = StatxMask::INO | StatxMask::MNT_ID_UNIQUE;
    let root = crate::sync_fs::statx(crate::AT_FDCWD, "/", AtFlags::empty(), mask).expect("statx of /");
    assert_eq!(got, (root.ino(), root.mnt_id()), "the parent is /");
}

/// The step that cannot be written before the chain starts: a name computed from the directory the previous step
/// opened.
#[test]
fn a_derived_step_names_the_next_directory() {
    let (mut eng, mut fs, me) = setup();
    let dir = nested();
    let at = Anchor::open(dir.path()).expect("anchor");
    let got: Rc<RefCell<Option<bool>>> = Rc::new(RefCell::new(None));
    let g2 = got.clone();
    drive(
        &mut eng,
        &mut fs,
        move |c| {
            c.open_chain(
                &at,
                vec![
                    OpenStep {
                        path: StepPath::Fixed(c"a".to_owned()),
                        who: me,
                        how: OpenHow::new().flags(OFlag::O_PATH | OFlag::O_DIRECTORY),
                    },
                    OpenStep {
                        // Derived from the open directory rather than from anything the caller knew.
                        path: StepPath::Derived(Box::new(|prev| {
                            let st = crate::sync_fs::statx(prev, "", AtFlags::AT_EMPTY_PATH, StatxMask::INO)?;
                            assert!(st.ino() != 0, "a real directory");
                            Ok(c"b/leaf".to_owned())
                        })),
                        who: me,
                        how: OpenHow::new().flags(OFlag::O_RDONLY),
                    },
                ],
                move |res, _c| {
                    *g2.borrow_mut() = Some(res.file().is_some());
                },
            );
        },
        || got.borrow().is_some(),
    );
    assert_eq!(*got.borrow(), Some(true), "the derived name must resolve");
}

/// A chain from a continuation opens, like one from the request handler.
///
/// It used to be refused, on the grounds that the file it produces "would outlive the connection it would go to".
/// It cannot: the callback runs either way (`deliver_embedded` builds an `FsConn` and calls it unconditionally),
/// and it is handed the fd wrapped in an `Arc<OwnedFd>` that closes on drop. Nothing was ever orphaned, and the
/// refusal silently dropped `on_done` — which closes the connection — for consumers whose work legitimately spans
/// completions.
#[test]
fn a_chain_from_a_continuation_opens() {
    let (mut eng, mut fs, me) = setup();
    let dir = nested();
    let at = Anchor::open(dir.path()).expect("anchor");
    let got = Rc::new(RefCell::new(None));
    let g2 = got.clone();
    drive(
        &mut eng,
        &mut fs,
        move |c| {
            // One completion, then a chain from inside it: the shape the gate used to swallow.
            c.offload(
                || 1u64,
                move |_, c| {
                    c.open_chain(
                        &at,
                        vec![OpenStep {
                            path: StepPath::Fixed(c"a".to_owned()),
                            who: me,
                            how: OpenHow::new().flags(OFlag::O_RDONLY),
                        }],
                        move |res, _c| {
                            *g2.borrow_mut() = Some(res.file().is_some());
                        },
                    );
                },
            );
        },
        || got.borrow().is_some(),
    );
    assert_eq!(*got.borrow(), Some(true), "the chain resolved");
}

/// A screen that fires mid-chain refuses the way the same screen refuses at entry.
///
/// `..` in a component is refused at `open_chain`'s entry - where nothing is submitted, nothing arms the sink, and
/// `FsConn::fut` synthesises the marked `EINVAL` (`a_refused_errno_is_marked_as_this_crates_own`) - and again on a
/// name the caller's `DeriveName` produces after a step has opened. The second is a real completion answered by
/// `chain`, so it has to carry the mark itself; without it the same defect reads as this crate's verdict at entry
/// and as the kernel's three steps in, and an awaiting task takes the second for teardown.
#[test]
fn a_mid_chain_screen_refuses_the_way_the_entry_screen_does() {
    let (mut eng, mut fs, me) = setup();
    let dir = nested();
    let at = Anchor::open(dir.path()).expect("anchor");
    let mid: Rc<RefCell<Option<FsDone>>> = Rc::new(RefCell::new(None));
    let m2 = mid.clone();
    drive(
        &mut eng,
        &mut fs,
        move |c| {
            c.open_chain(
                &at,
                vec![
                    OpenStep {
                        path: StepPath::Fixed(c"a".to_owned()),
                        who: me,
                        how: OpenHow::new().flags(OFlag::O_PATH | OFlag::O_DIRECTORY),
                    },
                    OpenStep {
                        path: StepPath::Derived(Box::new(|_| Ok(c"../escape".to_owned()))),
                        who: me,
                        how: OpenHow::new().flags(OFlag::O_RDONLY),
                    },
                ],
                move |res, _c| *m2.borrow_mut() = Some(res),
            );
        },
        || mid.borrow().is_some(),
    );
    let mid = mid.borrow_mut().take().expect("the chain answered");
    assert!(
        matches!(mid.result(), Err(crate::Error::Errno(Errno::EINVAL))),
        "the mid-chain screen refuses the same defect"
    );
    assert!(
        mid.was_refused(),
        "a mid-chain refusal must not read as the kernel's verdict"
    );
}

/// An op submitted through a reborrowed facade still reports to the frame that is watching.
///
/// `reborrow` clones the sink - both halves of a two-step dispatch submit, and both should report - and used to
/// reset the arm counter to a fresh copy, so a `fut` whose closure reborrowed saw nothing armed, synthesised a
/// spurious `EINVAL` for an op in flight, and the real completion landed in the settled slot: for a creating open,
/// a file made on disk whose descriptor was dropped under the caller. The counter is shared now.
#[cfg(feature = "http")]
#[test]
fn a_reborrowed_submission_arms_the_outer_frame() {
    let (mut eng, mut fs, me) = setup();
    let dir = crate::tempdir().expect("tempdir");
    let at = Anchor::open(dir.path()).expect("anchor");
    let got: Rc<RefCell<Option<FsDone>>> = Rc::new(RefCell::new(None));
    let g2 = got.clone();
    drive(
        &mut eng,
        &mut fs,
        move |c| {
            drop(c.spawn(move |t| async move {
                let done = t
                    .fut(|c, cb| {
                        let mut r = c.reborrow();
                        r.open(
                            me,
                            &at,
                            c"made",
                            OpenHow::new()
                                .flags(OFlag::O_RDWR | OFlag::O_CREAT)
                                .mode(Mode::from_bits_truncate(0o600)),
                            cb,
                        );
                    })
                    .await;
                *g2.borrow_mut() = Some(done);
            }));
        },
        || got.borrow().is_some(),
    );
    let done = got.borrow_mut().take().expect("resolved");
    assert!(
        done.file().is_some(),
        "the open through the reborrow must reach this future: {:?} \
             (was_refused={})",
        done.result(),
        done.was_refused()
    );
    assert!(dir.path().join("made").exists(), "and it really ran");
}

/// The one-frame-one-submission rule, enforced by attribution rather than by a panic: the first submission in a
/// frame owns the frame's slot, and a second one's refusal cannot fill it. The one-slot table makes the second
/// open's refusal *real* - the case where both arms sharing the slot discarded the first op's completion, `File`
/// and all, and reported the loser's `EBUSY` for an op still in flight. Both profiles now answer the same way, so
/// this test carries no `debug_assertions` gate.
#[test]
fn a_second_submissions_refusal_cannot_answer_for_the_first() {
    let mut eng = Engine::new(256, 128).expect("engine");
    let mut fs = FsCore::new(1, OffloadBounds::default());
    let me = Personality(register_personality(eng.ring.raw_fd()).expect("personality"));
    let dir = nested();
    let at = Anchor::open(dir.path()).expect("anchor");
    let got: Rc<RefCell<Option<FsDone>>> = Rc::new(RefCell::new(None));
    let g2 = got.clone();
    drive(
        &mut eng,
        &mut fs,
        move |c| {
            drop(c.spawn(move |t| async move {
                let done = t
                    .fut(|c, cb| {
                        let how = OpenHow::new().flags(OFlag::O_RDONLY);
                        // Takes the one op slot and arms the frame.
                        c.open(me, &at, c"a", how, cb);
                        // Refused `EBUSY` on the empty table; its share is empty, so the refusal follows the
                        // callback contract instead of filling the frame's slot.
                        c.open(me, &at, c"a", how, |_d, _c| {});
                    })
                    .await;
                *g2.borrow_mut() = Some(done);
            }));
        },
        || got.borrow().is_some(),
    );
    let done = got.borrow_mut().take().expect("resolved");
    assert!(
        done.file().is_some(),
        "the armed op must answer with its own completion: {:?} \
             refused={}",
        done.result(),
        done.was_refused()
    );
}

/// The third ordering of the same violation, and the one the other two cannot see: the *first* submission takes the
/// frame's arm and is refused **without consuming a slot** (the per-owner cap - reachable at the consumer's stated
/// cap-1 configuration), while the second, carrying the frame's own `on_done`, submits fine and completes with a
/// real fd. The refusal's share must not answer for the op the caller actually awaited: parked provisionally
/// (`SlotState::Refused`), it is superseded by the real completion - where settling the slot outright reported a
/// marked `EBUSY` for a create that ran and dropped the real `FsDone` into the settled slot, closing the fresh
/// descriptor under the caller (a retry of that "retryable" `EBUSY` then answers `EEXIST` for a create it was told
/// never happened).
#[test]
fn a_refused_first_arm_cannot_answer_for_the_callbacks_own_op() {
    let mut eng = Engine::new(256, 128).expect("engine");
    let mut fs = FsCore::new(2, OffloadBounds::default());
    let me = Personality(register_personality(eng.ring.raw_fd()).expect("personality"));
    fs.set_timer_cap(1);
    let dir = crate::tempdir().expect("tempdir");
    let at = Anchor::open(dir.path()).expect("anchor");
    // Spend the owner's one wall-clock count outside the frame.
    {
        let mut c = FsConn::new(&mut fs, &mut eng, OWNER0);
        let held = c.timeout(std::time::Duration::from_secs(3600), |_d, _c| {});
        assert!(held.is_some(), "the budget-spending arm itself");
    }
    let got: Rc<RefCell<Option<FsDone>>> = Rc::new(RefCell::new(None));
    let g2 = got.clone();
    drive(
        &mut eng,
        &mut fs,
        move |c| {
            drop(c.spawn(move |t| async move {
                let done = t
                    .fut(|c, cb| {
                        // Takes the frame's arm; refused at the cap, consuming no slot.
                        let _ = c.timeout(std::time::Duration::from_secs(3600), |_d, _c| {});
                        // Carries the frame's callback; succeeds.
                        c.open(
                            me,
                            &at,
                            c"made",
                            OpenHow::new()
                                .flags(OFlag::O_RDWR | OFlag::O_CREAT)
                                .mode(Mode::from_bits_truncate(0o600)),
                            cb,
                        );
                    })
                    .await;
                *g2.borrow_mut() = Some(done);
            }));
        },
        || got.borrow().is_some(),
    );
    let done = got.borrow_mut().take().expect("resolved");
    assert!(
        done.file().is_some(),
        "the awaited op must answer its own frame: {:?} refused={}",
        done.result(),
        done.was_refused()
    );
    let f = done.file().expect("checked above");
    // SAFETY: querying flags on an fd this test still owns.
    let live = unsafe { libc::fcntl(f.as_raw_fd(), libc::F_GETFD) } >= 0;
    assert!(live, "and its descriptor must still be open");
    assert!(dir.path().join("made").exists(), "the create really ran");
}

/// The other ordering of the same violation: when the frame's own `on_done` rides the *second* submission and that
/// one is refused, the future resolves with that submission's own marked verdict - the queued refusal fires the
/// callback with its `EBUSY` ([`FsCore::refuse`]) - rather than hanging, stealing the first op's answer, or reading
/// back as the unmarked `ECANCELED` a task winds a live connection down on. `fut`'s rustdoc states both halves.
#[test]
fn a_refused_second_submission_answers_for_itself() {
    let mut eng = Engine::new(256, 128).expect("engine");
    let mut fs = FsCore::new(1, OffloadBounds::default());
    let me = Personality(register_personality(eng.ring.raw_fd()).expect("personality"));
    let dir = nested();
    let at = Anchor::open(dir.path()).expect("anchor");
    let got: Rc<RefCell<Option<FsDone>>> = Rc::new(RefCell::new(None));
    let opened: Rc<RefCell<Option<bool>>> = Rc::new(RefCell::new(None));
    let g2 = got.clone();
    let o2 = opened.clone();
    drive(
        &mut eng,
        &mut fs,
        move |c| {
            drop(c.spawn(move |t| async move {
                let done = t
                    .fut(|c, cb| {
                        let how = OpenHow::new().flags(OFlag::O_RDONLY);
                        // Takes the slot and the frame's share.
                        c.open(me, &at, c"a", how, move |d, _c| {
                            *o2.borrow_mut() = Some(d.file().is_some());
                        });
                        // Refused; the queued callback resolves the future with the refusal's own marked verdict at
                        // the wake drain.
                        c.open(me, &at, c"a", how, cb);
                    })
                    .await;
                *g2.borrow_mut() = Some(done);
            }));
        },
        || got.borrow().is_some() && opened.borrow().is_some(),
    );
    let done = got.borrow_mut().take().expect("resolved");
    assert!(
        matches!(done.result(), Err(crate::Error::Errno(Errno::EBUSY))) && done.was_refused(),
        "the refused submission's own verdict: {:?} refused={}",
        done.result(),
        done.was_refused()
    );
    assert_eq!(
        opened.borrow_mut().take(),
        Some(true),
        "and the first submission still answers its own callback"
    );
}

/// The other entry screens answer the same way `open_chain`'s do: inline, `EINVAL`, marked as this crate's. One
/// test per method with a screen, so a new screen added to any of them without an answer shows up as an unfired
/// callback here.
#[test]
fn every_entry_screen_answers_instead_of_dropping() {
    let (mut eng, mut fs, me) = setup();
    let dir = nested();
    let at = Anchor::open(dir.path()).expect("anchor");

    let refused = |what: &str, got: Rc<RefCell<Option<FsDone>>>| {
        let done = got
            .borrow_mut()
            .take()
            .unwrap_or_else(|| panic!("{what}: the refusal was dropped"));
        assert!(
            matches!(done.result(), Err(crate::Error::Errno(Errno::EINVAL))) && done.was_refused(),
            "{what}: {:?} refused={}",
            done.result(),
            done.was_refused()
        );
    };

    let mut c = FsConn::new(&mut fs, &mut eng, OWNER0);
    for (what, path) in [("an absolute open", c"/etc/hostname"), ("an empty open", c"")] {
        let got: Rc<RefCell<Option<FsDone>>> = Rc::new(RefCell::new(None));
        let g2 = got.clone();
        c.open(me, &at, path, OpenHow::new().flags(OFlag::O_RDONLY), move |res, _c| {
            *g2.borrow_mut() = Some(res)
        });
        refused(what, got);
    }

    // `open`'s second screen, on a path the first admits: a zero-length `Allow` deadline would cancel the open it
    // guards. The screens are driven separately because the first returns before the second can run - which is how
    // this one shipped uncovered.
    let got: Rc<RefCell<Option<FsDone>>> = Rc::new(RefCell::new(None));
    let g2 = got.clone();
    c.open(
        me,
        &at,
        c"a",
        crate::uring_fs::FsOpenHow::from(OpenHow::new().flags(OFlag::O_RDONLY))
            .allow_blocking_special_files(std::time::Duration::ZERO),
        move |res, _c| *g2.borrow_mut() = Some(res),
    );
    refused("a zero Allow deadline", got);

    for (what, path, how) in [
        ("a mkdir_path with ..", c"a/../b", OpenHow::new().flags(OFlag::O_RDONLY)),
        (
            "a creating mkdir_path",
            c"a/b",
            OpenHow::new().flags(OFlag::O_RDONLY | OFlag::O_CREAT),
        ),
        (
            "a root-scoped mkdir_path",
            c"a/b",
            OpenHow::new()
                .flags(OFlag::O_RDONLY)
                .resolve(crate::sync_fs::ResolveFlag::RESOLVE_IN_ROOT),
        ),
    ] {
        let got: Rc<RefCell<Option<FsDone>>> = Rc::new(RefCell::new(None));
        let g2 = got.clone();
        c.mkdir_path(me, &at, path, Mode::from_bits_truncate(0o755), how, move |res, _c| {
            *g2.borrow_mut() = Some(res)
        });
        refused(what, got);
    }

    for (what, how) in [
        (
            "a creating open_parent",
            OpenHow::new().flags(OFlag::O_RDONLY | OFlag::O_CREAT),
        ),
        (
            "an open_parent of a new unnamed file",
            OpenHow::new().flags(OFlag::O_RDWR | OFlag::O_TMPFILE),
        ),
        (
            "an open_parent scoped beneath its anchor",
            OpenHow::new()
                .flags(OFlag::O_PATH)
                .resolve(crate::sync_fs::ResolveFlag::RESOLVE_BENEATH),
        ),
        (
            "an open_parent scoped to a root",
            OpenHow::new()
                .flags(OFlag::O_PATH)
                .resolve(crate::sync_fs::ResolveFlag::RESOLVE_IN_ROOT),
        ),
    ] {
        for across in [false, true] {
            let got: Rc<RefCell<Option<FsDone>>> = Rc::new(RefCell::new(None));
            let g2 = got.clone();
            let then = move |res, _c: &mut FsConn<'_>| {
                *g2.borrow_mut() = Some(res);
            };
            if across {
                c.open_parent_across_mount(me, &at, how, then);
            } else {
                c.open_parent(me, &at, how, then);
            }
            refused(what, got);
        }
    }

    let got: Rc<RefCell<Option<FsDone>>> = Rc::new(RefCell::new(None));
    let g2 = got.clone();
    c.symlinkat(me, c"", &at, Leaf::new("l").expect("leaf"), move |res, _c| {
        *g2.borrow_mut() = Some(res)
    });
    refused("an empty symlink target", got);
    assert!(!dir.path().join("l").exists(), "nothing was created");
}

/// Every refusal is judged on shape at entry, before anything is submitted, so a bad argument cannot leave a
/// half-walked chain - and each answers `on_done` with the marked `EINVAL` before `open_chain` returns, rather than
/// dropping it. A dropped callback closes the connection, which turns a caller bug into a shed peer; and the
/// awaited form aside, a plain-callback caller had no way to hear the refusal at all.
#[test]
fn a_chain_that_cannot_be_walked_is_refused_before_it_starts() {
    let (mut eng, mut fs, me) = setup();
    let dir = nested();
    let at = Anchor::open(dir.path()).expect("anchor");
    let dirstep = |how: OpenHow| OpenStep {
        path: StepPath::Fixed(c"a".to_owned()),
        who: me,
        how,
    };
    let plain = || OpenHow::new().flags(OFlag::O_RDONLY);
    let cases: Vec<(&str, Vec<OpenStep>)> = vec![
        ("no steps", Vec::new()),
        (
            // Nothing has been opened, so there is nothing to derive a name from.
            "a first step that derives",
            vec![OpenStep {
                path: StepPath::Derived(Box::new(|_| Ok(c"a".to_owned()))),
                who: me,
                how: plain(),
            }],
        ),
        (
            "an escaping component",
            vec![
                dirstep(plain()),
                OpenStep {
                    path: StepPath::Fixed(c"../escape".to_owned()),
                    who: me,
                    how: plain(),
                },
            ],
        ),
        (
            // `chain` unions RESOLVE_BENEATH, and the kernel refuses the pair ("Scoping flags are mutually
            // exclusive", `fs/open.c:1263-1265`) - so every step would answer EINVAL, blaming the kernel for a bit
            // this crate added.
            "a step scoped to a root",
            vec![
                dirstep(plain().resolve(crate::sync_fs::ResolveFlag::RESOLVE_IN_ROOT)),
                dirstep(plain()),
            ],
        ),
        (
            // A create at an intermediate would be left behind by a later step's failure.
            "a creating step",
            vec![
                dirstep(plain()),
                OpenStep {
                    path: StepPath::Fixed(c"made".to_owned()),
                    who: me,
                    how: OpenHow::new().flags(OFlag::O_RDONLY | OFlag::O_CREAT),
                },
            ],
        ),
    ];
    for (what, steps) in cases {
        let fired: Rc<RefCell<Option<FsDone>>> = Rc::new(RefCell::new(None));
        let f2 = fired.clone();
        {
            let mut c = FsConn::new(&mut fs, &mut eng, OWNER0);
            c.open_chain(&at, steps, move |res, _c| {
                *f2.borrow_mut() = Some(res);
            });
        }
        // Inline: the refusal is answered before `open_chain` returned, with nothing driven - which is also what
        // pins that nothing was submitted.
        let done = fired
            .borrow_mut()
            .take()
            .unwrap_or_else(|| panic!("{what}: the refusal was dropped"));
        assert!(
            matches!(done.result(), Err(crate::Error::Errno(Errno::EINVAL))),
            "{what}: wrong errno {:?}",
            done.result()
        );
        assert!(done.was_refused(), "{what}: the crate's own verdict");
    }
    assert!(!dir.path().join("a/made").exists(), "a refused chain creates nothing");
}

#[test]
fn offload_delivers_result_on_loop() {
    let (mut eng, mut fs, _me) = setup();
    let got: Rc<RefCell<Option<u64>>> = Rc::new(RefCell::new(None));
    let g2 = got.clone();
    drive(
        &mut eng,
        &mut fs,
        move |c| {
            c.offload(|| 6u64 * 7, move |r, _c| *g2.borrow_mut() = r.ok());
        },
        || got.borrow().is_some(),
    );
    assert_eq!(*got.borrow(), Some(42));
}

/// Blocking offloads queued in one iteration run side by side, though the loop sleeps right after queueing them:
/// the flush wakes one worker, and the rest get workers when the loop wakes at the returned deadline. The jobs meet
/// at a barrier, so they finish only if all four run at once.
///
/// The floor is parked first: workers still starting would take the jobs whatever the wake rules were.
#[test]
fn a_turns_blocking_offloads_run_side_by_side() {
    const JOBS: usize = 4;
    let (mut eng, mut fs, _me) = setup();
    let floor = OffloadBounds::default().floor;
    assert!(JOBS <= floor, "the fixture must not need growth");
    let pool = fs.pool_handle();
    pool.submit(Box::new(|| {}), &eng.shared.wake);
    let parking = std::time::Instant::now();
    // At least the floor: the warm-up's flush can grow the pool by one.
    while pool.parked().is_none_or(|parked| parked < floor) {
        assert!(
            parking.elapsed() < std::time::Duration::from_secs(5),
            "the pool's floor never parked"
        );
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(JOBS));
    let done = Rc::new(Cell::new(0usize));
    let d2 = done.clone();
    let began = std::time::Instant::now();
    drive(
        &mut eng,
        &mut fs,
        move |c| {
            for _ in 0..JOBS {
                let b = std::sync::Arc::clone(&barrier);
                let d = d2.clone();
                c.offload(
                    move || {
                        b.wait();
                    },
                    move |_r, _c| d.set(d.get() + 1),
                );
            }
        },
        || done.get() == JOBS,
    );
    let took = began.elapsed();
    assert!(
        took < std::time::Duration::from_millis(500),
        "the blocked jobs got their workers only after {took:?}: the \
             loop slept through the pool's deadline"
    );
}

/// A panicking job must still deliver. Before, `push_back`/`poke` sat after `job()`, so an unwind skipped both: the
/// continuation never ran, the `offload_reg` entry was never retired, and anything the continuation would have
/// released (a walk's `in_flight`) stayed held forever.
#[test]
fn offload_delivers_even_when_the_job_panics() {
    let (mut eng, mut fs, _me) = setup();
    let got: Rc<RefCell<Option<bool>>> = Rc::new(RefCell::new(None));
    let g2 = got.clone();
    with_silent_panics(|| {
        drive(
            &mut eng,
            &mut fs,
            move |c| {
                c.offload(
                    || -> u64 { panic!("job blew up") },
                    move |r, _c| *g2.borrow_mut() = Some(r.is_err()),
                );
            },
            || got.borrow().is_some(),
        );
    });
    assert_eq!(
        *got.borrow(),
        Some(true),
        "the continuation must run, carrying the panic"
    );
    assert!(
        fs.offload_reg.is_empty(),
        "a panicked job must not strand its registry entry"
    );
}

/// A share dropped off the explicit release paths returns its buffer through the core's queue and pokes the loop;
/// one taken out by `into_bid` - a reaped write's, a taken completion's - does not return it a second time.
#[cfg(feature = "net-server")]
#[test]
fn a_dropped_share_returns_its_buffer_once() {
    let (eng, mut fs, _me) = setup();
    let returns = fs.lease_returns(&eng.shared);
    let dropped = std::sync::Arc::new(LeaseHold::new(3, returns.clone()));
    let taken = std::sync::Arc::new(LeaseHold::new(4, returns));
    let sibling = std::sync::Arc::clone(&dropped);
    drop(dropped);
    assert!(
        fs.take_pool_releases().is_empty(),
        "a share returned while a sibling still held the buffer"
    );
    drop(sibling);
    assert_eq!(fs.take_pool_releases(), [3], "the last share returns");
    assert_eq!(std::sync::Arc::into_inner(taken).map(LeaseHold::into_bid), Some(4));
    assert!(
        fs.take_pool_releases().is_empty(),
        "a share taken out explicitly returned again from its drop"
    );
}

/// Windows one `WRITEV` cannot carry are written from one in-order copy that holds no share.
#[cfg(feature = "net-server")]
#[test]
fn a_gather_past_uio_maxiov_is_written_from_a_copy() {
    let mut eng = Engine::new(256, 128).expect("engine");
    let mut fs = FsCore::new(1, OffloadBounds::default());
    let sink: OwnedFd = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/null")
        .expect("/dev/null")
        .into();
    let file = crate::uring_fs::File { fd: Arc::new(sink) };
    let bytes: Vec<u8> = (0..=UIO_MAXIOV).map(|i| i as u8).collect();
    let hold = std::sync::Arc::new(LeaseHold::detached(3));
    let windows = bytes
        .iter()
        .map(|b| LeasedWindow {
            view: LeasedBytes {
                ptr: std::ptr::from_ref(b),
                len: 1,
            },
            hold: std::sync::Arc::clone(&hold),
        })
        .collect();
    {
        let mut c = FsConn::new(&mut fs, &mut eng, OWNER0);
        c.pwritev2_leased(Personality(0), file.clone(), windows, 0, RwFlags::empty(), |_d, _c| {});
    }
    assert_eq!(std::sync::Arc::strong_count(&hold), 1, "the copy path kept a share");
    let staged: Vec<_> = fs
        .ops
        .iter()
        .filter(|e| matches!(e.state.state, FsOpState::InFlight { .. }))
        .collect();
    let [op] = staged[..] else {
        panic!("{} ops staged, want one write", staged.len());
    };
    assert_eq!(op.state.bufs, vec![bytes], "one copy, in window order");
    assert!(
        op.state.recv_lease.is_none() && op.state.recv_lease_more.is_empty(),
        "no share rides the copy"
    );
}

/// A writable descriptor nothing reads back: the refusal tests stage their writes and synthesize every completion.
#[cfg(feature = "net-server")]
fn dev_null() -> crate::uring_fs::File {
    let sink: OwnedFd = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/null")
        .expect("/dev/null")
        .into();
    crate::uring_fs::File { fd: Arc::new(sink) }
}

/// Every staged op, as `(tag, slot, generation)`.
#[cfg(feature = "net-server")]
fn staged_ops(fs: &FsCore) -> Vec<(u8, u32, u32)> {
    fs.ops
        .iter()
        .enumerate()
        .filter_map(|(i, e)| match e.state.state {
            FsOpState::InFlight { tag } => Some((tag, i as u32, e.generation as u32)),
            _ => None,
        })
        .collect()
}

/// Stage a copied write that fills the table's one slot, then a leased write of `buf` as buffer `bid`; returns
/// whether the leased write took its delivery's claim.
#[cfg(feature = "net-server")]
fn lease_behind(fs: &mut FsCore, eng: &mut Engine, file: &crate::uring_fs::File, buf: &[u8], bid: u16) -> bool {
    let taken = std::cell::Cell::new(false);
    let mut c = FsConn::new(fs, eng, OWNER0).with_recv_lease(Some(RecvWriteLease {
        ptr: buf.as_ptr(),
        cap: buf.len(),
        bid,
        taken: &taken,
    }));
    c.pwritev2(
        Personality(0),
        file.clone(),
        vec![vec![0u8; 16]],
        0,
        RwFlags::empty(),
        |_d, _c| {},
    );
    c.pwritev2_from(Personality(0), file.clone(), buf, 0, RwFlags::empty(), |_d, _c| {});
    taken.get()
}

/// A delivery's first leased write the op table cannot take is refused with a marked `EBUSY` and takes nothing: the
/// connection keeps the claim to release at consume, so the refusal returns no buffer.
#[cfg(feature = "net-server")]
#[test]
fn a_refused_leased_write_leaves_the_claim_with_the_connection() {
    let mut eng = Engine::new(256, 128).expect("engine");
    let mut fs = FsCore::new(1, OffloadBounds::default());
    let file = dev_null();
    let buf = vec![7u8; 1024];
    assert!(
        !lease_behind(&mut fs, &mut eng, &file, &buf, 5),
        "a refused write took the claim"
    );
    let Some((_, _, done)) = fs.take_refusal() else {
        panic!("the refused write is answered");
    };
    assert_eq!(done.raw_result(), Err(Errno::EBUSY));
    assert!(done.was_refused(), "a capacity refusal is marked");
    assert_eq!(staged_ops(&fs).len(), 1, "only the blocker in flight");
    assert!(
        fs.take_pool_releases().is_empty(),
        "the refusal returned a buffer the connection still releases"
    );
}

/// A leased write refused behind an earlier one of the same delivery drops only its own share: the buffer comes
/// back once, when the sibling completes.
#[cfg(feature = "net-server")]
#[test]
fn a_write_refused_behind_its_sibling_returns_the_buffer_once() {
    let mut eng = Engine::new(256, 128).expect("engine");
    let mut fs = FsCore::new(1, OffloadBounds::default());
    let file = dev_null();
    let buf = vec![7u8; 1024];
    let taken = std::cell::Cell::new(false);
    {
        let mut c = FsConn::new(&mut fs, &mut eng, OWNER0).with_recv_lease(Some(RecvWriteLease {
            ptr: buf.as_ptr(),
            cap: buf.len(),
            bid: 5,
            taken: &taken,
        }));
        for half in buf.chunks(buf.len() / 2) {
            c.pwritev2_from(Personality(0), file.clone(), half, 0, RwFlags::empty(), |_d, _c| {});
        }
    }
    assert!(taken.get(), "the first write took the claim");
    let Some((_, _, done)) = fs.take_refusal() else {
        panic!("the second write is answered");
    };
    assert!(done.was_refused(), "refused for the full table");
    assert!(
        fs.take_pool_releases().is_empty(),
        "returned while the sibling still reads it"
    );
    let [(tag, slot, generation)] = staged_ops(&fs)[..] else {
        panic!("the first write in flight");
    };
    let half = (buf.len() / 2) as i32;
    let ReapedFs::Embedded(_, mut done, _) = fs.on_cqe(&mut eng, tag, slot, generation, half) else {
        panic!("an embedded completion");
    };
    assert_eq!(done.take_recv_lease(), Some(5), "back at the sibling's CQE");
    assert!(fs.take_pool_releases().is_empty(), "and nowhere else");
}

/// A gathered write the op table cannot take is refused with a marked `EBUSY`, and each window's buffer comes back
/// once as it drops.
#[cfg(feature = "net-server")]
#[test]
fn a_refused_gathered_write_returns_each_buffer_once() {
    let mut eng = Engine::new(256, 128).expect("engine");
    let mut fs = FsCore::new(1, OffloadBounds::default());
    let file = dev_null();
    let bufs = [vec![1u8; 1024], vec![2u8; 1024]];
    let windows = bufs
        .iter()
        .zip([5u16, 6])
        .map(|(buf, bid)| LeasedWindow {
            view: LeasedBytes {
                ptr: buf.as_ptr(),
                len: buf.len(),
            },
            hold: std::sync::Arc::new(LeaseHold::new(bid, fs.lease_returns(&eng.shared))),
        })
        .collect();
    {
        let mut c = FsConn::new(&mut fs, &mut eng, OWNER0);
        c.pwritev2(
            Personality(0),
            file.clone(),
            vec![vec![0u8; 16]],
            0,
            RwFlags::empty(),
            |_d, _c| {},
        );
        c.pwritev2_leased(Personality(0), file.clone(), windows, 0, RwFlags::empty(), |_d, _c| {});
    }
    let Some((_, _, done)) = fs.take_refusal() else {
        panic!("the gathered write is answered");
    };
    assert_eq!(done.raw_result(), Err(Errno::EBUSY));
    assert!(done.was_refused(), "a capacity refusal is marked");
    let mut back = fs.take_pool_releases();
    back.sort_unstable();
    assert_eq!(back, vec![5, 6], "each buffer, once");
}

/// A facade with no recv claim - every completion facade, every unpooled connection - sends `offload_from` down its
/// copy path: the job sees the caller's bytes, verbatim, and the result comes back through the ordinary `Result`
/// seam with a panic mapped to `EIO`. The leased path is the net server's to prove (`test/recv_alloc.rs`), since
/// only a delivery can hold a claim.
#[test]
fn offload_from_copies_where_nothing_is_leased() {
    type Seen = Rc<RefCell<Option<crate::Result<(usize, u64)>>>>;
    let (mut eng, mut fs, _me) = setup();
    let seen: Seen = Rc::new(RefCell::new(None));
    let bad: Rc<RefCell<Option<crate::Result<u64>>>> = Rc::new(RefCell::new(None));
    let (s2, b2) = (seen.clone(), bad.clone());
    let bytes: Vec<u8> = (0..=255u8).cycle().take(3 * 1024 + 7).collect();
    let want: u64 = bytes.iter().map(|&b| u64::from(b)).sum();
    with_silent_panics(|| {
        drive(
            &mut eng,
            &mut fs,
            move |c| {
                c.offload_from(
                    &bytes,
                    |view| Ok((view.len(), view.iter().map(|&b| u64::from(b)).sum())),
                    move |r, _c| *s2.borrow_mut() = Some(r),
                );
                c.offload_from(
                    &[1u8, 2, 3],
                    |_view| -> crate::Result<u64> { panic!("job blew up") },
                    move |r, _c| *b2.borrow_mut() = Some(r),
                );
            },
            || seen.borrow().is_some() && bad.borrow().is_some(),
        );
    });
    assert!(
        matches!(*seen.borrow(), Some(Ok((n, sum))) if n == 3 * 1024 + 7 && sum == want),
        "the job reads the caller's bytes: {:?}",
        seen.borrow()
    );
    assert!(
        matches!(*bad.borrow(), Some(Err(crate::Error::Errno(Errno::EIO)))),
        "a panicked job is exactly EIO: {:?}",
        bad.borrow()
    );
    assert!(
        fs.offload_reg.is_empty(),
        "no continuation may be stranded in the registry"
    );
}

/// `offload_result` maps a panicked job to exactly `EIO` - the documented contract - while an `Ok` job in the same
/// drive passes its value through untouched, and neither strands its registry entry.
#[test]
fn offload_result_maps_a_panicked_job_to_eio() {
    let (mut eng, mut fs, _me) = setup();
    let ok: Rc<RefCell<Option<crate::Result<u64>>>> = Rc::new(RefCell::new(None));
    let bad: Rc<RefCell<Option<crate::Result<u64>>>> = Rc::new(RefCell::new(None));
    let (o2, b2) = (ok.clone(), bad.clone());
    with_silent_panics(|| {
        drive(
            &mut eng,
            &mut fs,
            move |c| {
                c.offload_result(|| Ok(41u64), move |r, _c| *o2.borrow_mut() = Some(r));
                c.offload_result(
                    || -> crate::Result<u64> { panic!("job blew up") },
                    move |r, _c| *b2.borrow_mut() = Some(r),
                );
            },
            || ok.borrow().is_some() && bad.borrow().is_some(),
        );
    });
    assert!(
        matches!(*ok.borrow(), Some(Ok(41))),
        "the Ok job's value passes through: {:?}",
        ok.borrow()
    );
    assert!(
        matches!(*bad.borrow(), Some(Err(crate::Error::Errno(Errno::EIO)))),
        "a panicked job is exactly EIO: {:?}",
        bad.borrow()
    );
    assert!(
        fs.offload_reg.is_empty(),
        "no continuation may be stranded in the registry"
    );
}

/// The lookup lane delivers on the loop as `offload_result` does, a panicked job as exactly `EIO`, and strands no
/// registry entry. The second lookup is queued once the lane's thread has parked, so it runs only if the loop's
/// flush wakes the lane.
#[test]
fn a_lookup_delivers_on_the_loop_and_a_panic_as_eio() {
    let (mut eng, mut fs, _me) = setup();
    let ok: Rc<RefCell<Option<crate::Result<u64>>>> = Rc::default();
    let bad: Rc<RefCell<Option<crate::Result<u64>>>> = Rc::default();
    let (o2, b2) = (ok.clone(), bad.clone());
    // One thread at most, so the lane cannot grow, and its one thread parked is the whole lane at rest.
    fs.set_lookup_bounds(OffloadBounds { floor: 1, ceiling: 1 });
    let lane = Arc::clone(&fs.lookup);
    with_silent_panics(|| {
        drive(
            &mut eng,
            &mut fs,
            move |c| {
                c.offload_lookup(
                    || Ok(41u64),
                    move |r, c| {
                        *o2.borrow_mut() = Some(r);
                        let parking = std::time::Instant::now();
                        while lane.parked() != Some(1) {
                            assert!(parking.elapsed().as_secs() < 5, "the lane's thread never parked");
                            std::thread::yield_now();
                        }
                        c.offload_lookup(
                            || -> crate::Result<u64> { panic!("lookup blew up") },
                            move |r, _c| *b2.borrow_mut() = Some(r),
                        );
                    },
                );
            },
            || ok.borrow().is_some() && bad.borrow().is_some(),
        );
    });
    assert!(
        matches!(*ok.borrow(), Some(Ok(41))),
        "the Ok lookup's value passes through: {:?}",
        ok.borrow()
    );
    assert!(
        matches!(*bad.borrow(), Some(Err(crate::Error::Errno(Errno::EIO)))),
        "a panicked lookup is exactly EIO: {:?}",
        bad.borrow()
    );
    assert!(
        fs.offload_reg.is_empty(),
        "no continuation may be stranded in the registry"
    );
}

/// A lookup that waits never holds a thread of the file pool, and the lane's ceiling holds a second lookup back.
/// Both pools are cut to one thread, so the file job runs only if the waiting lookup is on a pool of its own, and
/// the second lookup runs only once the first ends.
#[test]
fn a_waiting_lookup_holds_no_file_thread_and_its_lane_stays_bounded() {
    use std::time::{Duration, Instant};
    let mut eng = Engine::new(256, 128).expect("engine");
    let one = OffloadBounds { floor: 1, ceiling: 1 };
    let mut fs = FsCore::new(256, one);
    fs.set_lookup_bounds(one);
    let (release, held) = std::sync::mpsc::channel::<()>();
    let release = RefCell::new(Some(release));
    let order: Rc<RefCell<Vec<&str>>> = Rc::default();
    let seen: RefCell<Vec<&str>> = RefCell::default();
    let (o1, o2, o3) = (order.clone(), order.clone(), order.clone());
    let began = Instant::now();
    drive(
        &mut eng,
        &mut fs,
        move |c| {
            c.offload_lookup(
                move || {
                    // Bounded, so a lane that shares the file pool fails the order below rather than hanging the
                    // test.
                    let _ = held.recv_timeout(Duration::from_secs(10));
                    Ok(())
                },
                move |_r, _c| o1.borrow_mut().push("waiting"),
            );
            c.offload_lookup(|| Ok(()), move |_r, _c| o2.borrow_mut().push("queued"));
            c.offload(|| (), move |_r, _c| o3.borrow_mut().push("file"));
        },
        || {
            // Long past the file job, a second lane thread would have run the queued lookup, were the ceiling not
            // one.
            let late = began.elapsed() > Duration::from_millis(200);
            if late
                && order.borrow().contains(&"file")
                && let Some(release) = release.borrow_mut().take()
            {
                seen.borrow_mut().clone_from(&order.borrow());
                release.send(()).ok();
            }
            order.borrow().len() == 3
        },
    );
    assert_eq!(
        *seen.borrow(),
        ["file"],
        "the file job ran while the lookup waited, and nothing else"
    );
    assert_eq!(*order.borrow(), ["file", "waiting", "queued"]);
}

/// A lane with no thread answers `EAGAIN` on the loop, on a later pass and not inside the call, and never runs the
/// job, which may wait seconds where the loop must not.
#[test]
fn a_lane_with_no_thread_answers_eagain_without_running_the_job() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let (mut eng, mut fs, _me) = setup();
    fs.lookup.back_off();
    let ran = Arc::new(AtomicBool::new(false));
    let got: Rc<RefCell<Option<crate::Result<()>>>> = Rc::default();
    let (r2, g2, g3) = (ran.clone(), got.clone(), got.clone());
    drive(
        &mut eng,
        &mut fs,
        move |c| {
            c.offload_lookup(
                move || {
                    r2.store(true, Ordering::Relaxed);
                    Ok(())
                },
                move |r, _c| *g2.borrow_mut() = Some(r),
            );
            assert!(g3.borrow().is_none(), "answered inside the call");
        },
        || got.borrow().is_some(),
    );
    assert!(
        matches!(*got.borrow(), Some(Err(crate::Error::Errno(Errno::EAGAIN)))),
        "a lane with no thread is EAGAIN: {:?}",
        got.borrow()
    );
    assert!(!ran.load(Ordering::Relaxed), "the job ran on the loop");
    assert!(
        fs.offload_reg.is_empty(),
        "no continuation may be stranded in the registry"
    );
}

/// Lookups that wait together each get a thread of the lane, though the loop sleeps right after queueing them. The
/// lane grows past its floor only at the deadline its flush returns, so the jobs meet at the barrier in time only
/// if the loop wakes for the lane's deadline as well as the file pool's.
#[test]
fn lookups_that_wait_together_each_get_a_thread() {
    const JOBS: usize = 3;
    const { assert!(LOOKUP_FLOOR < JOBS, "the fixture must need growth") };
    let (mut eng, mut fs, _me) = setup();
    let barrier = Arc::new(std::sync::Barrier::new(JOBS));
    let done = Rc::new(Cell::new(0usize));
    let d2 = done.clone();
    let began = std::time::Instant::now();
    drive(
        &mut eng,
        &mut fs,
        move |c| {
            for _ in 0..JOBS {
                let b = Arc::clone(&barrier);
                let d = d2.clone();
                c.offload_lookup(
                    move || {
                        b.wait();
                        Ok(())
                    },
                    move |_r, _c| d.set(d.get() + 1),
                );
            }
        },
        || done.get() == JOBS,
    );
    let took = began.elapsed();
    assert!(
        took < std::time::Duration::from_millis(500),
        "the waiting lookups got their threads only after {took:?}, so \
             the loop slept through the lane's deadline"
    );
}

#[test]
fn wake_drain_fires_every_completion() {
    let (mut eng, mut fs, _me) = setup();
    let count: Rc<RefCell<usize>> = Rc::new(RefCell::new(0));
    let c2 = count.clone();
    drive(
        &mut eng,
        &mut fs,
        move |c| {
            for _ in 0..8 {
                let c3 = c2.clone();
                c.offload(
                    || (),
                    move |r, _c| {
                        r.expect("a unit job never panics");
                        *c3.borrow_mut() += 1;
                    },
                );
            }
        },
        || *count.borrow() == 8,
    );
    assert_eq!(*count.borrow(), 8);
}

#[test]
fn a_failed_readdir_is_an_error_not_end_of_directory() {
    // Point the DIR*'s fd at a non-directory (`dup2` over it, keeping the fd number valid so parallel tests and the
    // walk's own `closedir` are unaffected): the next `readdir` fails `ENOTDIR` and returns NULL with errno set.
    // That must be delivered as an error, not an empty end-of-directory batch that reads as a complete listing of
    // nothing.
    let (mut eng, mut fs, me) = setup();
    let dir = fixture(3);
    let anchor = Anchor::open(dir.path()).unwrap();
    struct S {
        walk: Option<DirWalk>,
        result: Option<crate::Result<NameBatch>>,
    }
    let st: Rc<RefCell<S>> = Rc::new(RefCell::new(S {
        walk: None,
        result: None,
    }));
    let st2 = st.clone();
    drive(
        &mut eng,
        &mut fs,
        move |c| {
            c.open_dir(me, &anchor, move |res, conn| {
                let walk = res.expect("open_dir");
                // SAFETY: `dp` is the live DIR* just handed back; redirect its fd to /dev/null so the next readdir
                // sees a non-dir.
                let dirfd = unsafe { libc::dirfd(walk.inner.borrow().dp) };
                assert!(dirfd >= 0);
                let null = unsafe { libc::open(c"/dev/null".as_ptr(), 0) };
                assert!(null >= 0, "open /dev/null");
                assert_eq!(unsafe { libc::dup2(null, dirfd) }, dirfd, "dup2 onto dirfd");
                unsafe { libc::close(null) };
                st2.borrow_mut().walk = Some(walk);
                let st3 = st2.clone();
                let b = st2.borrow();
                conn.next_batch(b.walk.as_ref().unwrap(), move |res, _c| {
                    st3.borrow_mut().result = Some(res);
                });
            });
        },
        || st.borrow().result.is_some(),
    );
    let s = st.borrow();
    assert!(
        matches!(s.result.as_ref().unwrap(), Err(crate::Error::Errno(Errno::ENOTDIR))),
        "readdir failure delivered as Err(ENOTDIR), got {:?}",
        s.result.as_ref().unwrap()
    );
}

#[test]
fn dirwalk_drop_closes_the_dir() {
    let (mut eng, mut fs, me) = setup();
    let dir = fixture(3);
    let anchor = Anchor::open(dir.path()).unwrap();
    let captured: Rc<RefCell<Option<Rc<RefCell<DirWalkInner>>>>> = Rc::new(RefCell::new(None));
    let cap2 = captured.clone();
    drive(
        &mut eng,
        &mut fs,
        move |c| {
            c.open_dir(me, &anchor, move |res, _c| {
                let walk = res.expect("open_dir");
                // Snapshot the inner, then drop `walk` at the end of this closure (no batch in flight -> Drop
                // closes the DIR* now).
                *cap2.borrow_mut() = Some(walk.inner.clone());
            });
        },
        || captured.borrow().is_some(),
    );
    let inner = captured.borrow().as_ref().unwrap().clone();
    assert!(inner.borrow().dropped, "walk Drop ran");
    assert!(inner.borrow().dp.is_null(), "DIR* closed on drop, not leaked");
}

struct ListState {
    me: Personality,
    anchor: Anchor,
    walk: Option<DirWalk>,
    pending: VecDeque<Vec<u8>>,
    eod: bool,
    seen: usize,
    sum: u64,
    finished: bool,
}
type ListRef = Rc<RefCell<ListState>>;

/// Pull the next batch of names for `st`'s walk (one job at a time).
fn request_batch(st: &ListRef, conn: &mut FsConn<'_>) {
    let st2 = st.clone();
    let b = st.borrow();
    let walk = b.walk.as_ref().expect("walk");
    conn.next_batch(walk, move |res, conn| {
        let batch = res.expect("batch");
        {
            let mut s = st2.borrow_mut();
            s.pending.extend(batch.names);
            s.eod = batch.eod;
        }
        enrich_next(&st2, conn);
    });
}

/// Enrich the next pending name on-loop (open + fgetxattr), <= 1 op in flight; pull the next batch when the current
/// one drains, finish at eod.
fn enrich_next(st: &ListRef, conn: &mut FsConn<'_>) {
    let name = st.borrow_mut().pending.pop_front();
    let Some(name) = name else {
        let eod = st.borrow().eod;
        if eod {
            st.borrow_mut().finished = true;
        } else {
            request_batch(st, conn);
        }
        return;
    };
    let (me, anchor) = {
        let b = st.borrow();
        (b.me, b.anchor.clone())
    };
    let how = OpenHow::new().flags(OFlag::O_RDONLY | OFlag::O_NOFOLLOW);
    let cname = CString::new(name).unwrap();
    let st2 = st.clone();
    conn.open(me, &anchor, &cname, how, move |done, conn| {
        let Some(f) = done.file() else {
            return enrich_next(&st2, conn);
        };
        let me = st2.borrow().me;
        let st3 = st2.clone();
        conn.fgetxattr(me, f, c"user.bench", vec![0u8; 64], move |done, conn| {
            if let Ok(nb) = done.result() {
                let nb = nb as usize;
                let bufs = done.into_bufs();
                let mut s = st3.borrow_mut();
                s.seen += 1;
                if let Some(v) = bufs.first() {
                    for &x in &v[..nb.min(v.len())] {
                        s.sum += x as u64;
                    }
                }
            }
            enrich_next(&st3, conn);
        });
    });
}

#[test]
fn hybrid_listing_enriches_every_entry() {
    let (mut eng, mut fs, me) = setup();
    let n = 40usize;
    let dir = fixture(n);
    let anchor = Anchor::open(dir.path()).unwrap();
    const CLIENTS: usize = 3;
    let states: Vec<ListRef> = (0..CLIENTS)
        .map(|_| {
            Rc::new(RefCell::new(ListState {
                me,
                anchor: anchor.clone(),
                walk: None,
                pending: VecDeque::new(),
                eod: false,
                seen: 0,
                sum: 0,
                finished: false,
            }))
        })
        .collect();
    let kick = states.clone();
    let check = states.clone();
    drive(
        &mut eng,
        &mut fs,
        move |c| {
            for st in &kick {
                let st2 = st.clone();
                let (me, anchor) = {
                    let b = st.borrow();
                    (b.me, b.anchor.clone())
                };
                c.open_dir(me, &anchor, move |res, c| {
                    st2.borrow_mut().walk = Some(res.expect("open_dir"));
                    request_batch(&st2, c);
                });
            }
        },
        move || check.iter().all(|s| s.borrow().finished),
    );
    for s in &states {
        let b = s.borrow();
        assert_eq!(b.seen, n, "every entry enriched");
        assert_eq!(b.sum, xsum(n), "xattr values correct");
    }
}

/// Route the ring's completions, the poll of the file leases' signalfd and reopens among them, until `until` holds,
/// failing after 30 seconds, well short of the 45 a broken lease holds its breaker.
fn pump_until(eng: &mut Engine, fs: &mut FsCore, until: impl Fn(&FsCore) -> bool) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while !until(fs) {
        assert!(
            std::time::Instant::now() < deadline,
            "nothing came of the break within 30 seconds"
        );
        let wait = Some(std::time::Duration::from_millis(200));
        match eng.ring.submit_and_wait_for(1, wait) {
            Ok(()) | Err(Errno::ETIME) | Err(Errno::EINTR) => {}
            Err(e) => panic!("submit and wait: {e}"),
        }
        while let Some(cqe) = eng.ring.reap() {
            eng.retire(&cqe);
            let (tag, slot, g) = unpack_raw(cqe.user_data);
            if tag & TAG_FS_DOMAIN == 0 || tag == TAG_CANCEL {
                continue;
            }
            let reaped = fs.on_cqe(eng, tag, slot, g, cqe.res);
            deliver_embedded(fs, eng, reaped);
        }
    }
}

/// A file of a fresh folder, and a descriptor of it open for reading.
fn a_file() -> (crate::TempDir, std::path::PathBuf, File) {
    let dir = crate::tempdir().expect("tempdir");
    let path = dir.path().join("f");
    std::fs::write(&path, b"x").unwrap();
    let read = std::fs::File::open(&path).unwrap();
    (dir, path, File::from_fd(read.into()))
}

/// A handler that records each break it hears in `heard`, and gives the lease back when `gives_back`.
fn hearing(
    heard: &Rc<RefCell<Vec<super::super::file_lease::FileLeaseId>>>,
    gives_back: bool,
) -> super::super::file_lease::BreakHandler {
    let heard = Rc::clone(heard);
    Box::new(move |id, fs| {
        heard.borrow_mut().push(id);
        if gives_back {
            fs.release_file_lease(id).expect("give the lease back");
        }
    })
}

/// An open of `path` for writing with `O_NONBLOCK`, which a lease answers `EWOULDBLOCK` once it has begun its
/// break.
fn open_nonblocking(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
}

/// An open for writing breaks a lease, its break reaches the handler on the ring that took it, and the handler's
/// release lets the opener go at once rather than after `lease-break-time`.
#[test]
fn a_write_open_breaks_a_file_lease_and_its_release_lets_the_opener_go() {
    super::super::file_lease::block_signals().unwrap();
    let (mut eng, mut fs, _) = setup();
    let heard = Rc::new(RefCell::new(Vec::new()));
    fs.file_leases.set_handler(hearing(&heard, true));
    let (_dir, path, file) = a_file();
    let id = FsConn::new(&mut fs, &mut eng, None).file_lease(&file).expect("a lease");
    let opener = std::thread::spawn(move || {
        let at = std::time::Instant::now();
        std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        at.elapsed()
    });
    pump_until(&mut eng, &mut fs, |_| !heard.borrow().is_empty());
    assert_eq!(*heard.borrow(), [id]);
    let waited = opener.join().unwrap();
    assert!(waited < std::time::Duration::from_secs(10), "{waited:?}");
    assert!(fs.file_leases.held_none(), "the lease was given back");
    // The realtime signal named the descriptor, so no lease was asked.
    assert_eq!(fs.file_leases.sigio, 0, "the break came as F_SETSIG's");
}

/// A break is reported once, though a `SIGIO` after it asks every lease again and finds it still broken, and the
/// ring polls its signals again after each read.
#[test]
fn a_break_is_reported_once() {
    super::super::file_lease::block_signals().unwrap();
    let (mut eng, mut fs, _) = setup();
    let heard = Rc::new(RefCell::new(Vec::new()));
    fs.file_leases.set_handler(hearing(&heard, false));
    let (_dir, path, file) = a_file();
    let id = FsConn::new(&mut fs, &mut eng, None).file_lease(&file).expect("a lease");
    let refused = open_nonblocking(&path).unwrap_err();
    assert_eq!(refused.raw_os_error(), Some(libc::EWOULDBLOCK));
    pump_until(&mut eng, &mut fs, |_| !heard.borrow().is_empty());
    let read = fs.file_leases.read;
    // SAFETY: a signal to this thread, which has it blocked.
    let sent = unsafe { libc::syscall(libc::SYS_tgkill, libc::getpid(), libc::gettid(), libc::SIGIO) };
    assert_eq!(sent, 0);
    pump_until(&mut eng, &mut fs, |fs| fs.file_leases.read > read);
    assert_eq!(*heard.borrow(), [id]);
    FsConn::new(&mut fs, &mut eng, None).release_file_lease(id).unwrap();
}

/// A truncate breaks a lease as an open for writing does (`vfs_truncate` in `fs/open.c`).
#[test]
fn a_truncate_breaks_a_file_lease() {
    super::super::file_lease::block_signals().unwrap();
    let (mut eng, mut fs, _) = setup();
    let heard = Rc::new(RefCell::new(Vec::new()));
    fs.file_leases.set_handler(hearing(&heard, true));
    let (_dir, path, file) = a_file();
    let id = FsConn::new(&mut fs, &mut eng, None).file_lease(&file).expect("a lease");
    let truncater = std::thread::spawn(move || {
        let path = CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: a NUL-terminated path.
        unsafe { libc::truncate(path.as_ptr(), 0) }
    });
    pump_until(&mut eng, &mut fs, |_| !heard.borrow().is_empty());
    assert_eq!(*heard.borrow(), [id]);
    assert_eq!(truncater.join().unwrap(), 0);
}

/// A signal names only a descriptor's number. One left from a lease given back, read once a new lease holds the
/// same descriptor and is not broken, reports nothing.
#[test]
fn a_signal_left_from_a_lease_given_back_reports_no_break() {
    super::super::file_lease::block_signals().unwrap();
    let (mut eng, mut fs, _) = setup();
    let heard = Rc::new(RefCell::new(Vec::new()));
    fs.file_leases.set_handler(hearing(&heard, false));
    let (_dir, path, file) = a_file();
    let mut c = FsConn::new(&mut fs, &mut eng, None);
    let id = c.file_lease(&file).expect("a lease");
    // The break begins and its signal waits on this thread, unread.
    let refused = open_nonblocking(&path).unwrap_err();
    assert_eq!(refused.raw_os_error(), Some(libc::EWOULDBLOCK));
    c.release_file_lease(id).unwrap();
    let again = c.file_lease(&file).expect("a second lease");
    assert_ne!(again, id, "a new lease on the same descriptor");
    drop(c);
    pump_until(&mut eng, &mut fs, |fs| fs.file_leases.read > 0);
    assert!(heard.borrow().is_empty(), "{:?}", heard.borrow());
}

/// An open on the ring meets a lease with the special-file guard's `O_NONBLOCK`, so the reopen for writing answers
/// `EWOULDBLOCK` at once, and the break it began reaches the handler.
#[test]
fn a_reopen_for_writing_answers_ewouldblock_and_starts_the_break() {
    super::super::file_lease::block_signals().unwrap();
    let (mut eng, mut fs, _) = setup();
    let heard = Rc::new(RefCell::new(Vec::new()));
    fs.file_leases.set_handler(hearing(&heard, true));
    let (_dir, _path, file) = a_file();
    let refused = Rc::new(Cell::new(None));
    let r = Rc::clone(&refused);
    let mut c = FsConn::new(&mut fs, &mut eng, None);
    let id = c.file_lease(&file).expect("a lease");
    c.reopen_proc_as_root(file.clone(), ReopenAccess::Write, move |d, _| {
        r.set(Some(matches!(d.result(), Err(crate::Error::Errno(Errno::EAGAIN)))));
    });
    drop(c);
    pump_until(&mut eng, &mut fs, |_| {
        refused.get().is_some() && !heard.borrow().is_empty()
    });
    assert_eq!(refused.get(), Some(true), "EWOULDBLOCK at once");
    assert_eq!(*heard.borrow(), [id]);
}

/// The kernel refuses a read lease while anyone holds the file open for writing, and a ring refuses one with no
/// handler to hear its break or on a thread that has not blocked the signals a break comes as.
#[test]
fn a_file_lease_is_refused_where_its_break_could_not_be_heard() {
    // A thread that never blocked the signals, spawned before this one blocks them, since a thread inherits the
    // mask.
    let unblocked = std::thread::spawn(|| {
        let (mut eng, mut fs, _) = setup();
        fs.file_leases.set_handler(Box::new(|_, _| {}));
        let (_dir, _path, file) = a_file();
        let mut c = FsConn::new(&mut fs, &mut eng, None);
        c.file_lease(&file).err()
    })
    .join()
    .unwrap();
    assert!(
        matches!(unblocked, Some(crate::Error::Errno(Errno::EINVAL))),
        "{unblocked:?}"
    );
    super::super::file_lease::block_signals().unwrap();
    let (mut eng, mut fs, _) = setup();
    let (_dir, path, file) = a_file();
    let unheard = FsConn::new(&mut fs, &mut eng, None).file_lease(&file);
    assert!(
        matches!(unheard, Err(crate::Error::Errno(Errno::EINVAL))),
        "{unheard:?}"
    );
    fs.file_leases.set_handler(Box::new(|_, _| {}));
    let writer = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
    let mut c = FsConn::new(&mut fs, &mut eng, None);
    let held = c.file_lease(&file);
    assert!(matches!(held, Err(crate::Error::Errno(Errno::EAGAIN))), "{held:?}");
    drop(writer);
    let id = c.file_lease(&file).expect("a lease once the writer went");
    c.release_file_lease(id).unwrap();
}

/// A break whose realtime signal cannot be queued comes as `SIGIO` with no descriptor (`send_sigio_to_task` in
/// `fs/fcntl.c`), and still reaches the handler, through `F_GETLEASE` asked of every lease. It runs in a child
/// process whose `RLIMIT_SIGPENDING` is 0, since the limit is the process's, and a realtime signal never passes it
/// (`__send_signal_locked` in `kernel/signal.c`).
#[test]
fn a_break_whose_signal_cannot_be_queued_arrives_through_sigio() {
    const CHILD: &str = "TRUENAS_ROS_FILE_LEASE_SIGIO_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let me = "uring_fs::core::hybrid_tests::\
                      a_break_whose_signal_cannot_be_queued_arrives_through_sigio";
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", me, "--test-threads=1", "--nocapture"])
            .env(CHILD, "1")
            .status()
            .unwrap();
        assert!(status.success(), "the child failed: {status}");
        return;
    }
    let none = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: a valid limit, in this child process alone.
    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_SIGPENDING, &none) }, 0);
    super::super::file_lease::block_signals().unwrap();
    let (mut eng, mut fs, _) = setup();
    let heard = Rc::new(RefCell::new(Vec::new()));
    fs.file_leases.set_handler(hearing(&heard, true));
    let (_dir, path, file) = a_file();
    let id = FsConn::new(&mut fs, &mut eng, None).file_lease(&file).expect("a lease");
    let refused = open_nonblocking(&path).unwrap_err();
    assert_eq!(refused.raw_os_error(), Some(libc::EWOULDBLOCK));
    pump_until(&mut eng, &mut fs, |_| !heard.borrow().is_empty());
    assert_eq!(*heard.borrow(), [id]);
    assert!(fs.file_leases.sigio > 0, "the break came as SIGIO");
}
