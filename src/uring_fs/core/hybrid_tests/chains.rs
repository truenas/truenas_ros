use super::*;

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
/// `O_NONBLOCK` only on the inline attempt (`IO_URING_F_NONBLOCK`), so an unguarded step here reaches `fifo_open`'s
/// `wait_for_partner` (`fs/pipe.c`) and parks a worker and its op slot until the owner's teardown sweep. The guard
/// makes it answer instead.
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

/// A chain from a continuation opens, like one from the request handler. The callback runs either way
/// (`deliver_embedded`) and is handed the fd in an `Arc<OwnedFd>` that closes on drop, so nothing is orphaned.
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
            // One completion, then a chain from inside it.
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
/// `..` in a component is refused at `open_chain`'s entry, and again on a name the caller's `DeriveName` produces after
/// a step has opened. The second is a real completion answered by `chain`, so it carries the mark itself, or an
/// awaiting task would take it for teardown.
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

/// An op submitted through a reborrowed facade still reports to the frame that is watching, since the arm flag rides
/// the shared sink. A copied flag would have `fut` synthesise a spurious `EINVAL` for an op in flight and drop a
/// created file's descriptor under the caller.
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

/// The one-frame-one-submission rule, enforced by attribution rather than by a panic. The first submission in a frame
/// owns the frame's slot, and a second one's refusal cannot fill it. The one-slot table makes the second open's refusal
/// real, and it must not discard the first op's completion.
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

/// The first submission takes the frame's arm and is refused without consuming a slot (the per-owner cap), while the
/// second, carrying the frame's own `on_done`, completes with a real fd. The refusal parks provisionally
/// (`SlotState::Refused`) and the real completion supersedes it, or a marked `EBUSY` would be reported for a create
/// that ran, with its fresh descriptor closed under the caller.
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

/// When the frame's own `on_done` rides the second submission and that one is refused, the future resolves with that
/// submission's own marked verdict ([`FsCore::refuse`]), rather than hanging, stealing the first op's answer, or
/// reading back as the unmarked `ECANCELED` of teardown.
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

    // `open`'s second screen, on a path the first admits. A zero-length `Allow` deadline would cancel the open it
    // guards. Driven apart from the first, which returns before it can run.
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
/// half-walked chain, and each answers `on_done` with the marked `EINVAL` before `open_chain` returns rather than
/// dropping it, which would close the connection.
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
