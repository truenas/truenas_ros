use super::*;
use crate::uring::ring::RingFd;
use crate::uring::sys::{IOSQE_IO_LINK, register_personality};
use crate::uring::user_data::TAG_FS_DOMAIN;
use std::path::Path;
use std::time::{Duration, Instant};

/// The connections a test ring's table holds, and its op slots, each with a slot of the table past them.
const POOL: u32 = 4;
const OPS: u32 = 8;
const OWNER: Owner = Some((0, 0));
/// A value the setter refuses, `EINVAL` on ZFS and `EOPNOTSUPP` elsewhere, as no file system takes it.
const BAD_SET: &[u8] = b"bad";
/// The tag of a probe of a slot of the table, outside the fs domain.
const TAG_PROBE: u8 = 0x70;

struct Rig {
    eng: Engine,
    fs: FsCore,
    me: Personality,
    dir: crate::TempDir,
}

/// A ring with chain slots, its core and a personality of this thread's credentials.
fn rig() -> Rig {
    let eng = Engine::on_ring(RingFd::setup(64).expect("ring"), POOL, OPS).expect("engine");
    let mut fs = FsCore::new(OPS, OffloadBounds::default());
    fs.enable_chains(POOL);
    let me = Personality(register_personality(eng.ring.raw_fd()).expect("personality"));
    Rig {
        eng,
        fs,
        me,
        dir: crate::tempdir().expect("tempdir"),
    }
}

/// A file of `bytes` under the rig's folder, held `O_PATH` as a server holds what it names.
fn held(r: &Rig, name: &str, bytes: &[u8]) -> (File, std::path::PathBuf) {
    let p = r.dir.path().join(name);
    std::fs::write(&p, bytes).expect("write");
    (open(&p, libc::O_PATH), p)
}

fn open(p: &Path, flags: i32) -> File {
    let path = CString::new(p.as_os_str().as_encoded_bytes()).expect("a path with no NUL");
    // SAFETY: a NUL-terminated path, and `open` reads nothing else.
    let fd = unsafe { libc::open(path.as_ptr(), flags | libc::O_CLOEXEC) };
    assert!(fd >= 0, "open {p:?}: {}", Errno::last());
    // SAFETY: `fd` was just opened, and nothing else owns it.
    File::new(Arc::new(unsafe { crate::fd::owned_from_raw(fd) }))
}

/// A chain of `file` with nothing in it yet.
fn on(file: &File) -> Chain {
    Chain {
        file: file.clone(),
        reopen: None,
        truncate: None,
        set: None,
        statx: None,
        sync: false,
    }
}

/// A completion of a step of a chain, and the ring's count in flight once it was routed.
#[derive(Debug, PartialEq)]
struct Posted {
    tag: u8,
    res: i32,
    inflight: u64,
}

/// Route every completion as the net server's dispatch does, retiring it first and delivering at once, with the
/// refusals the wake drain delivers, until `done` holds. Gives the completions of the chain's steps in order.
fn pump(r: &mut Rig, done: impl Fn() -> bool) -> Vec<Posted> {
    let mut posted = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        deliver_pool_completions(&mut r.fs, &mut r.eng);
        if done() {
            return posted;
        }
        assert!(Instant::now() < deadline, "the chain did not end within 30 seconds");
        r.eng
            .ring
            .submit_and_wait_for(1, Some(Duration::from_millis(100)))
            .expect("submit and wait");
        while let Some(cqe) = r.eng.ring.reap() {
            r.eng.retire(&cqe);
            let (tag, slot, g) = unpack_raw(cqe.user_data);
            if tag & TAG_FS_DOMAIN == 0 || tag == TAG_CANCEL {
                continue;
            }
            let reaped = r.fs.on_cqe(&mut r.eng, tag, slot, g, cqe.res);
            if is_chain_tag(tag) {
                posted.push(Posted {
                    tag,
                    res: cqe.res,
                    inflight: r.eng.inflight,
                });
            }
            deliver_embedded(&mut r.fs, &mut r.eng, reaped);
        }
    }
}

/// Run `chain` as the rig's personality to its end.
fn run(r: &mut Rig, chain: Chain) -> (ChainDone, Vec<Posted>) {
    let out: Rc<RefCell<Option<ChainDone>>> = Rc::default();
    let o = Rc::clone(&out);
    FsConn::new(&mut r.fs, &mut r.eng, OWNER).chain(r.me, chain, move |d, _| *o.borrow_mut() = Some(d));
    let posted = pump(r, || out.borrow().is_some());
    let done = out.borrow_mut().take().expect("pumped until it ended");
    (done, posted)
}

/// The op slot the next op takes.
fn next_op_slot(r: &Rig) -> u32 {
    *r.fs.op_free.last().expect("a free op slot")
}

/// Whether op slot `op`'s slot of the table holds a file, by an `fsync` that names it and finds none (`EBADF`).
fn slot_holds_a_file(r: &mut Rig, op: u32) -> bool {
    r.eng
        .ring
        .push_sqe(|sqe| {
            sqe.opcode = IORING_OP_FSYNC;
            sqe.fd = (POOL + op) as RawFd;
            sqe.flags = IOSQE_FIXED_FILE;
            sqe.user_data = pack_raw(TAG_PROBE, 0, 0);
        })
        .expect("stage the probe");
    loop {
        r.eng.ring.submit_and_wait(1).expect("submit the probe");
        while let Some(cqe) = r.eng.ring.reap() {
            if cqe.user_data as u8 == TAG_PROBE {
                return cqe.res != -libc::EBADF;
            }
        }
    }
}

/// The errno a step answered, or `None` for one that worked or posted nothing.
fn err(step: Option<crate::Result<i32>>) -> Option<Errno> {
    match step? {
        Err(crate::Error::Errno(e)) => Some(e),
        _ => None,
    }
}

fn tags(posted: &[Posted]) -> Vec<u8> {
    posted.iter().map(|p| p.tag).collect()
}

fn len_of(p: &Path) -> u64 {
    std::fs::metadata(p).expect("metadata").len()
}

/// A set that fails lets the fsync and the close after it run, and the chain posts one completion for each of the set,
/// the fsync and the close, as the reopen and the statx skip theirs. Only the last is counted in flight, so the ring
/// holds the chain as one op until it ends, and its slot is empty after.
#[test]
fn a_failed_set_lets_the_fsync_and_the_close_run() {
    let mut r = rig();
    let (f, _) = held(&r, "f", b"bytes");
    let op = next_op_slot(&r);
    let (done, posted) = run(
        &mut r,
        Chain {
            reopen: Some(Reopen::AsRing(ReopenAccess::Write)),
            set: Some(BAD_SET.to_vec()),
            statx: Some(StatxMask::SIZE),
            sync: true,
            ..on(&f)
        },
    );
    assert!(done.step(ChainStep::Set).expect("the set posts").is_err(), "{done:?}");
    assert_eq!(done.step(ChainStep::Sync).map(|r| r.ok()), Some(Some(0)), "{done:?}");
    assert_eq!(done.step(ChainStep::Close).map(|r| r.ok()), Some(Some(0)), "{done:?}");
    assert!(
        done.step(ChainStep::Reopen).is_none(),
        "a reopen that worked posts nothing"
    );
    assert_eq!(done.stat().expect("the statx ran").size(), 5);
    assert!(!done.was_refused());
    assert_eq!(done.into_value(), BAD_SET, "the value comes back");
    assert_eq!(tags(&posted), [TAG_CHAIN_SET, TAG_CHAIN_SYNC, TAG_CHAIN_END]);
    let held: Vec<u64> = posted.iter().map(|p| p.inflight).collect();
    assert_eq!(held, [1, 1, 0], "only the last completion ends the op in flight");
    assert!(!slot_holds_a_file(&mut r, op), "the close emptied the slot");
}

/// A statx that fails posts nothing, since its completion is skipped and its failure ends nothing, so its error is
/// lost and only its cleared mask tells.
#[test]
fn a_statx_that_fails_posts_nothing_and_shows_no_stat() {
    let mut r = rig();
    let (f, _) = held(&r, "f", b"bytes");
    // `STATX__RESERVED`, which `do_statx` in `fs/stat.c` refuses with `EINVAL`.
    let reserved = StatxMask::from_bits_retain(0x8000_0000);
    let (done, posted) = run(
        &mut r,
        Chain {
            reopen: Some(Reopen::AsRing(ReopenAccess::Read)),
            statx: Some(reserved),
            sync: true,
            ..on(&f)
        },
    );
    assert!(done.stat().is_none(), "{done:?}");
    assert_eq!(tags(&posted), [TAG_CHAIN_SYNC, TAG_CHAIN_END]);
    assert_eq!(done.step(ChainStep::Sync).map(|r| r.ok()), Some(Some(0)));
}

/// The reopen opens the held file again into the op's own slot, and the steps after it name that slot, so an
/// `ftruncate` the held `O_PATH` descriptor could never take truncates the file. The rest of the chain is staged from
/// the `ftruncate`'s completion, and the slot is empty once it ends.
#[test]
fn a_reopen_fills_the_op_slot_that_the_steps_then_name() {
    let mut r = rig();
    let (f, p) = held(&r, "f", b"bytes");
    let op = next_op_slot(&r);
    let (done, posted) = run(
        &mut r,
        Chain {
            reopen: Some(Reopen::AsCaller(ReopenAccess::Write)),
            truncate: Some(3),
            statx: Some(StatxMask::SIZE),
            sync: true,
            ..on(&f)
        },
    );
    assert_eq!(
        done.step(ChainStep::Truncate).map(|r| r.ok()),
        Some(Some(0)),
        "{done:?}"
    );
    assert_eq!(done.step(ChainStep::Sync).map(|r| r.ok()), Some(Some(0)), "{done:?}");
    assert_eq!(done.step(ChainStep::Close).map(|r| r.ok()), Some(Some(0)), "{done:?}");
    assert_eq!(len_of(&p), 3);
    assert_eq!(
        done.stat().expect("the statx ran").size(),
        3,
        "the statx reads after the size"
    );
    // The size's link ends at the `ftruncate`, whose completion stages the rest as one op again, the statx first in
    // it and so posting.
    assert_eq!(
        tags(&posted),
        [TAG_CHAIN_END, TAG_CHAIN_STATX, TAG_CHAIN_SYNC, TAG_CHAIN_END]
    );
    let held: Vec<u64> = posted.iter().map(|p| p.inflight).collect();
    assert_eq!(held, [1, 1, 1, 0]);
    assert!(!slot_holds_a_file(&mut r, op));
}

/// A failed `ftruncate` stages nothing after it, so a refused size sets nothing and syncs nothing, and the core empties
/// the slot the reopen filled, since no close of the chain's ran.
#[test]
fn a_failed_ftruncate_stages_nothing_after_it_and_its_slot_is_emptied() {
    let mut r = rig();
    let (f, p) = held(&r, "f", b"bytes");
    let op = next_op_slot(&r);
    let (done, posted) = run(
        &mut r,
        Chain {
            reopen: Some(Reopen::AsRing(ReopenAccess::Write)),
            // A negative length, which `do_truncate` in `fs/open.c` refuses.
            truncate: Some(u64::MAX),
            set: Some(BAD_SET.to_vec()),
            sync: true,
            ..on(&f)
        },
    );
    assert!(
        done.step(ChainStep::Truncate).expect("the ftruncate posts").is_err(),
        "{done:?}"
    );
    for step in [ChainStep::Set, ChainStep::Sync, ChainStep::Close] {
        assert!(done.step(step).is_none(), "{step:?} ran after a failed size: {done:?}");
    }
    assert_eq!(tags(&posted), [TAG_CHAIN_END]);
    assert_eq!(len_of(&p), 5);
    assert!(!slot_holds_a_file(&mut r, op), "the core emptied the slot");
}

/// A step that fails at prep fails every step of its link. With the reopen first, whose completion is skipped, only the
/// reopen posts, `ECANCELED`, and the slot stays empty. The value of a set past the largest the kernel takes fails at
/// prep (`setxattr_copy` in `fs/xattr.c`).
#[test]
fn a_step_that_fails_at_prep_after_the_reopen_posts_the_reopen_alone() {
    let mut r = rig();
    let (f, _) = held(&r, "f", b"bytes");
    let op = next_op_slot(&r);
    let (done, posted) = run(
        &mut r,
        Chain {
            reopen: Some(Reopen::AsRing(ReopenAccess::Write)),
            set: Some(vec![0; too_large()]),
            statx: Some(StatxMask::SIZE),
            sync: true,
            ..on(&f)
        },
    );
    assert_eq!(err(done.step(ChainStep::Reopen)), Some(Errno::ECANCELED), "{done:?}");
    for step in [ChainStep::Set, ChainStep::Sync, ChainStep::Close] {
        assert!(done.step(step).is_none(), "{step:?}: {done:?}");
    }
    assert!(done.stat().is_none());
    assert_eq!(tags(&posted), [TAG_CHAIN_REOPEN]);
    assert_eq!(posted[0].inflight, 0);
    assert!(!slot_holds_a_file(&mut r, op));
}

/// The rest of a size fails at prep with the file the reopen opened in its slot. Its set comes first and posts, so
/// every step posts, the close's `ECANCELED` among them, and the core empties the slot. A chain with no reopen that
/// fails at prep posts every step too, the statx among them, and counts as one op still.
#[test]
fn a_step_that_fails_at_prep_after_the_size_leaves_no_file_in_the_slot() {
    let mut r = rig();
    let (f, p) = held(&r, "f", b"bytes");
    let op = next_op_slot(&r);
    let (done, posted) = run(
        &mut r,
        Chain {
            reopen: Some(Reopen::AsRing(ReopenAccess::Write)),
            truncate: Some(2),
            set: Some(vec![0; too_large()]),
            sync: true,
            ..on(&f)
        },
    );
    assert_eq!(
        done.step(ChainStep::Truncate).map(|r| r.ok()),
        Some(Some(0)),
        "{done:?}"
    );
    let cancelled = Some(Errno::ECANCELED);
    assert_eq!(err(done.step(ChainStep::Sync)), cancelled, "{done:?}");
    assert_eq!(err(done.step(ChainStep::Close)), cancelled, "{done:?}");
    assert_eq!(len_of(&p), 2);
    assert_eq!(
        tags(&posted),
        [TAG_CHAIN_END, TAG_CHAIN_SET, TAG_CHAIN_SYNC, TAG_CHAIN_END]
    );
    assert!(!slot_holds_a_file(&mut r, op), "the core emptied the slot");

    let rw = open(&p, libc::O_RDWR);
    let (done, posted) = run(
        &mut r,
        Chain {
            set: Some(vec![0; too_large()]),
            statx: Some(StatxMask::SIZE),
            sync: true,
            ..on(&rw)
        },
    );
    assert!(done.step(ChainStep::Set).expect("the set posts").is_err());
    assert_eq!(tags(&posted), [TAG_CHAIN_SET, TAG_CHAIN_STATX, TAG_CHAIN_END]);
    let held: Vec<u64> = posted.iter().map(|p| p.inflight).collect();
    assert_eq!(held, [1, 1, 0]);
}

/// The largest value of an xattr the kernel takes, by one byte past it, `XATTR_LARGE_SIZE_MAX` on TrueNAS and
/// `XATTR_SIZE_MAX` past that elsewhere (`include/uapi/linux/limits.h`).
fn too_large() -> usize {
    2_097_152 + 1
}

/// A failed reopen ends the chain with its completion alone and leaves the slot empty, and the next chain on the same
/// op slot reopens into it and works. So do chains that end each other way, more of them than the op table holds.
#[test]
fn a_slot_is_taken_again_after_each_way_a_chain_ends() {
    let mut r = rig();
    let (f, p) = held(&r, "f", b"bytes");
    let dir = open(r.dir.path(), libc::O_PATH | libc::O_DIRECTORY);
    let op = next_op_slot(&r);
    // A folder opened again for writing, which `do_open` refuses with `EISDIR`.
    let (done, posted) = run(
        &mut r,
        Chain {
            reopen: Some(Reopen::AsRing(ReopenAccess::Write)),
            sync: true,
            ..on(&dir)
        },
    );
    assert!(done.step(ChainStep::Reopen).expect("a failed reopen posts").is_err());
    assert_eq!(tags(&posted), [TAG_CHAIN_REOPEN]);
    assert!(!slot_holds_a_file(&mut r, op));
    for n in 0..OPS * 2 {
        let failing = match n % 3 {
            0 => Chain {
                reopen: Some(Reopen::AsRing(ReopenAccess::Write)),
                set: Some(BAD_SET.to_vec()),
                ..on(&f)
            },
            1 => Chain {
                reopen: Some(Reopen::AsRing(ReopenAccess::Write)),
                truncate: Some(u64::MAX),
                ..on(&f)
            },
            _ => Chain {
                reopen: Some(Reopen::AsRing(ReopenAccess::Write)),
                set: Some(vec![0; too_large()]),
                ..on(&f)
            },
        };
        assert_eq!(next_op_slot(&r), op);
        run(&mut r, failing);
        assert!(!slot_holds_a_file(&mut r, op), "chain {n} left a file in its slot");
    }
    let (done, _) = run(
        &mut r,
        Chain {
            reopen: Some(Reopen::AsRing(ReopenAccess::Write)),
            truncate: Some(1),
            ..on(&f)
        },
    );
    assert_eq!(done.step(ChainStep::Close).map(|r| r.ok()), Some(Some(0)), "{done:?}");
    assert_eq!(len_of(&p), 1);
    assert_eq!(r.eng.inflight, 0);
}

/// The core refuses to stage the rest after a size, as a full submission queue whose flush moves nothing answers. The
/// chain then answers the refusal for each step of the rest, marked, and the core empties the slot.
#[test]
fn a_refused_stage_of_the_rest_empties_the_slot() {
    let mut r = rig();
    let (f, p) = held(&r, "f", b"bytes");
    let op = next_op_slot(&r);
    let out: Rc<RefCell<Option<ChainDone>>> = Rc::default();
    let o = Rc::clone(&out);
    let chain = Chain {
        reopen: Some(Reopen::AsRing(ReopenAccess::Write)),
        truncate: Some(2),
        set: Some(BAD_SET.to_vec()),
        sync: true,
        ..on(&f)
    };
    FsConn::new(&mut r.fs, &mut r.eng, OWNER).chain(r.me, chain, move |d, _| *o.borrow_mut() = Some(d));
    // Staged and in the kernel's hands before the seam is set, so only the rest meets it.
    r.eng.ring.submit().expect("submit");
    r.eng.stage_seam.refuse_next = true;
    pump(&mut r, || out.borrow().is_some());
    let done = out.borrow_mut().take().expect("ended");
    assert!(done.was_refused(), "{done:?}");
    let busy = Some(Errno::EBUSY);
    for step in [ChainStep::Set, ChainStep::Sync, ChainStep::Close] {
        assert_eq!(err(done.step(step)), busy, "{step:?}: {done:?}");
    }
    assert_eq!(len_of(&p), 2, "the size worked before the refusal");
    assert!(!slot_holds_a_file(&mut r, op), "the core emptied the slot");
    assert_eq!(r.eng.inflight, 0);
}

/// A chain with no reopen names the file the caller gives in every step, and closes nothing.
#[test]
fn a_chain_with_no_reopen_names_the_callers_file() {
    let mut r = rig();
    let (_, p) = held(&r, "f", b"bytes");
    let rw = open(&p, libc::O_RDWR);
    let (done, posted) = run(
        &mut r,
        Chain {
            truncate: Some(2),
            set: Some(BAD_SET.to_vec()),
            statx: Some(StatxMask::SIZE),
            sync: true,
            ..on(&rw)
        },
    );
    assert_eq!(len_of(&p), 2);
    assert_eq!(done.stat().expect("the statx ran").size(), 2);
    assert!(done.step(ChainStep::Set).expect("the set posts").is_err());
    assert_eq!(done.step(ChainStep::Sync).map(|r| r.ok()), Some(Some(0)));
    assert!(done.step(ChainStep::Reopen).is_none() && done.step(ChainStep::Close).is_none());
    assert_eq!(tags(&posted), [TAG_CHAIN_END, TAG_CHAIN_SET, TAG_CHAIN_END]);
}

/// A full op table refuses a chain with a marked `EBUSY`, as it refuses any op, answered for each step the chain had
/// and with its value back, however many come, and a chain after the table frees works.
#[test]
fn chains_past_a_full_op_table_are_refused_and_one_after_works() {
    let mut r = rig();
    let (f, p) = held(&r, "f", b"bytes");
    let out: Rc<RefCell<Vec<ChainDone>>> = Rc::default();
    let reopening = || Chain {
        reopen: Some(Reopen::AsRing(ReopenAccess::Write)),
        set: Some(BAD_SET.to_vec()),
        ..on(&f)
    };
    // Staged and not yet submitted, so each holds its op slot.
    let ended = Rc::new(Cell::new(0));
    for _ in 0..OPS {
        let e = Rc::clone(&ended);
        FsConn::new(&mut r.fs, &mut r.eng, OWNER).chain(r.me, reopening(), move |_, _| e.set(e.get() + 1));
    }
    for _ in 0..OPS + 2 {
        let o = Rc::clone(&out);
        FsConn::new(&mut r.fs, &mut r.eng, OWNER).chain(r.me, reopening(), move |d, _| o.borrow_mut().push(d));
    }
    deliver_pool_completions(&mut r.fs, &mut r.eng);
    let refused = out.take();
    assert_eq!(refused.len(), OPS as usize + 2);
    for done in refused {
        assert!(done.was_refused());
        let busy = Some(Errno::EBUSY);
        for step in [ChainStep::Reopen, ChainStep::Set, ChainStep::Close] {
            assert_eq!(err(done.step(step)), busy, "{step:?}");
        }
        assert!(done.step(ChainStep::Truncate).is_none() && done.step(ChainStep::Sync).is_none());
        assert_eq!(done.into_value(), BAD_SET);
    }
    pump(&mut r, || ended.get() == OPS);
    assert_eq!(r_free(&r), OPS);
    let (done, _) = run(
        &mut r,
        Chain {
            reopen: Some(Reopen::AsRing(ReopenAccess::Write)),
            truncate: Some(4),
            ..on(&f)
        },
    );
    assert_eq!(done.step(ChainStep::Close).map(|r| r.ok()), Some(Some(0)), "{done:?}");
    assert_eq!(len_of(&p), 4);
}

fn r_free(r: &Rig) -> u32 {
    r.fs.op_free.len() as u32
}

/// A ring without the chain slots refuses a chain with a marked `EINVAL`, its value back, and keeps no state for one.
#[test]
fn a_ring_without_the_slots_refuses_a_chain_and_keeps_nothing_for_one() {
    let eng = Engine::new(64, POOL).expect("engine");
    let mut r = Rig {
        me: Personality(register_personality(eng.ring.raw_fd()).expect("personality")),
        eng,
        fs: FsCore::new(OPS, OffloadBounds::default()),
        dir: crate::tempdir().expect("tempdir"),
    };
    assert!(r.fs.chains.is_none());
    let (f, _) = held(&r, "f", b"bytes");
    let (done, posted) = run(
        &mut r,
        Chain {
            reopen: Some(Reopen::AsRing(ReopenAccess::Write)),
            set: Some(BAD_SET.to_vec()),
            ..on(&f)
        },
    );
    assert!(done.was_refused());
    assert_eq!(err(done.step(ChainStep::Set)), Some(Errno::EINVAL));
    assert!(posted.is_empty());
    assert_eq!(done.into_value(), BAD_SET);
}

/// The teardown drain cancels chains in flight and ends once the last completion of each is reaped, counting each as
/// one op. Their callbacks are dropped unfired, and every op slot is free after.
#[test]
fn the_teardown_drain_ends_with_chains_in_flight() {
    let mut r = rig();
    let (f, _) = held(&r, "f", b"bytes");
    let fired = Rc::new(Cell::new(0));
    for n in 0..OPS {
        let fired = Rc::clone(&fired);
        let chain = Chain {
            reopen: Some(Reopen::AsRing(ReopenAccess::Write)),
            truncate: (n % 2 == 0).then_some(5),
            set: Some(BAD_SET.to_vec()),
            statx: Some(StatxMask::SIZE),
            sync: true,
            ..on(&f)
        };
        FsConn::new(&mut r.fs, &mut r.eng, OWNER).chain(r.me, chain, move |_, _| fired.set(fired.get() + 1));
    }
    assert_eq!(r.eng.inflight, u64::from(OPS));
    let fs = &mut r.fs;
    r.eng
        .cancel_and_reap_all(pack_raw(TAG_CANCEL, 0, 0), |cqe| fs.on_drain_cqe(cqe))
        .expect("drain");
    assert_eq!(r.eng.inflight, 0);
    assert_eq!(r_free(&r), OPS, "an op of a chain was left in flight");
    assert_eq!(fired.get(), 0);
}

/// Every step but the reopen and the last carries `IOSQE_IO_HARDLINK`, so a step that fails or is cancelled stops
/// nothing after it. The reopen skips its completion and links plainly, so its failure ends the link. The statx skips
/// its completion but where it comes first in its link, since a failure at prep posts only the first step's then.
#[test]
fn every_step_but_the_reopen_and_the_last_is_hard_linked() {
    let mut r = rig();
    let (f, _) = held(&r, "f", b"bytes");
    let full = Chain {
        reopen: Some(Reopen::AsCaller(ReopenAccess::Write)),
        set: Some(BAD_SET.to_vec()),
        statx: Some(StatxMask::SIZE),
        sync: true,
        ..on(&f)
    };
    FsConn::new(&mut r.fs, &mut r.eng, OWNER).chain(r.me, full, |_, _| {});
    let flags: Vec<u8> = (0..5).map(|i| r.eng.staged_sqe(i).flags).collect();
    let skip = IOSQE_CQE_SKIP_SUCCESS;
    let hard = IOSQE_IO_HARDLINK | IOSQE_IO_LINK;
    let fixed = IOSQE_FIXED_FILE;
    assert_eq!(
        flags,
        [
            IOSQE_IO_LINK | IOSQE_ASYNC | skip,
            hard | fixed,
            hard | skip,
            hard | fixed,
            0
        ],
        "reopen, set, statx, fsync, close"
    );
    r.eng.reset_staging();

    // The rest of a size, staged once its `ftruncate` answers, which a completion handed in by hand stands for here.
    let op = next_op_slot(&r);
    let sized = Chain {
        reopen: Some(Reopen::AsCaller(ReopenAccess::Write)),
        truncate: Some(1),
        statx: Some(StatxMask::SIZE),
        sync: true,
        ..on(&f)
    };
    FsConn::new(&mut r.fs, &mut r.eng, OWNER).chain(r.me, sized, |_, _| {});
    let first: Vec<u8> = (0..2).map(|i| r.eng.staged_sqe(i).flags).collect();
    assert_eq!(first, [IOSQE_IO_LINK | IOSQE_ASYNC | skip, fixed], "reopen, ftruncate");
    let generation = r.fs.ops[op as usize].generation as u32;
    let reaped = r.fs.on_cqe(&mut r.eng, TAG_CHAIN_END, op, generation, 0);
    assert!(
        matches!(reaped, ReapedFs::None),
        "the rest is staged, so nothing is delivered"
    );
    let rest: Vec<u8> = (2..5).map(|i| r.eng.staged_sqe(i).flags).collect();
    assert_eq!(rest, [hard, hard | fixed, 0], "a statx first in its link posts");
    r.eng.reset_staging();
}

/// A statx or a set that posts with the chain still running, as a cancelled one does under its hard link, ends neither
/// the op in flight nor the chain, which ends at its last step. A completion handed in by hand stands for each, since a
/// cancel cannot be timed to land on a step of a link.
#[test]
fn a_cancelled_statx_or_set_still_ends_the_chain_at_its_last_step() {
    for reopen in [Some(Reopen::AsRing(ReopenAccess::Write)), None] {
        let mut r = rig();
        let (f, p) = held(&r, "f", b"bytes");
        let file = if reopen.is_some() { f } else { open(&p, libc::O_RDWR) };
        let op = next_op_slot(&r);
        let out: Rc<RefCell<Option<ChainDone>>> = Rc::default();
        let o = Rc::clone(&out);
        let chain = Chain {
            reopen,
            set: Some(BAD_SET.to_vec()),
            statx: Some(StatxMask::SIZE),
            sync: true,
            ..on(&file)
        };
        FsConn::new(&mut r.fs, &mut r.eng, OWNER).chain(r.me, chain, move |d, _| *o.borrow_mut() = Some(d));
        let generation = r.fs.ops[op as usize].generation as u32;
        let mut hand = |tag: u8, res: i32| {
            let cqe = IoUringCqe {
                user_data: pack_raw(tag, op, generation),
                res,
                flags: 0,
            };
            r.eng.retire(&cqe);
            let reaped = r.fs.on_cqe(&mut r.eng, tag, op, generation, res);
            deliver_embedded(&mut r.fs, &mut r.eng, reaped);
            r.eng.inflight
        };
        assert_eq!(hand(TAG_CHAIN_SET, -libc::ECANCELED), 1);
        assert_eq!(hand(TAG_CHAIN_STATX, -libc::ECANCELED), 1);
        assert!(out.borrow().is_none(), "the chain ended before its last step");
        if reopen.is_some() {
            assert_eq!(hand(TAG_CHAIN_SYNC, 0), 1);
        }
        assert_eq!(hand(TAG_CHAIN_END, 0), 0);
        let done = out.borrow_mut().take().expect("ended at its last step");
        assert_eq!(err(done.step(ChainStep::Set)), Some(Errno::ECANCELED));
        assert!(done.stat().is_none());
        r.eng.reset_staging();
    }
}

/// A step that fails through the path a cancelled one takes, `io_req_task_queue_fail` from `io_wq_submit_work`, lets
/// the steps after it run under their hard links. A step whose file is gone fails that way, a slot of the table left
/// empty or a descriptor closed, so the statx after the set still reads the file, and the fsync runs and fails for
/// itself, rather than both being cancelled.
#[test]
fn a_step_failed_as_a_cancel_is_still_followed_by_the_rest() {
    for slot in [true, false] {
        let mut r = rig();
        let (f, _) = held(&r, "f", b"bytes");
        // A descriptor number past any the process can hold, which `fget` in `fs/file.c` never finds. One just closed
        // could be taken again by a test on another thread before the steps run.
        let gone = (!slot).then_some(RawFd::MAX);
        let mut stat: Box<StatxRaw> = Box::new(zeroed_statx());
        let value = BAD_SET.to_vec();
        let fill = Fill {
            fixed: slot.then_some(POOL + OPS - 1),
            raw_fd: gone.unwrap_or_else(|| f.fd.as_raw_fd()),
            pers: r.me.0,
            value: (value.as_ptr() as u64, value.len() as u32),
            stat: std::ptr::addr_of_mut!(*stat) as u64,
            mask: StatxMask::SIZE.bits(),
            len: 0,
            reopen: None,
        };
        stage_link(&mut r.eng, 0, 0, &[Step::Set, Step::Statx, Step::Sync], &fill).expect("stage");
        let mut got = Vec::new();
        while got.len() < 2 {
            r.eng.ring.submit_and_wait(1).expect("submit");
            while let Some(cqe) = r.eng.ring.reap() {
                got.push((cqe.user_data as u8, cqe.res));
            }
        }
        assert_eq!(
            got,
            [(TAG_CHAIN_SET, -libc::EBADF), (TAG_CHAIN_END, -libc::EBADF)],
            "slot {slot}"
        );
        if slot {
            assert_ne!(stat.stx_mask, 0, "the statx ran after the set");
        }
        drop((value, f));
    }
}
