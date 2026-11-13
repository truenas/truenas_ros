use super::*;
use crate::sync::mpsc;
use std::os::fd::RawFd;
use std::sync::Weak;

const OP_SLOTS: u32 = 32;
// The ring is sized far above any run's staged SQEs, so `push_sqe` never flushes to the kernel - routing runs
// purely in userspace.
const RING_ENTRIES: u32 = 1024;
const POOL: u32 = 8;

/// Deterministic xorshift RNG: a failing seed reproduces exactly.
struct Rng(u64);
impl Rng {
    fn new(seed: u64) -> Rng {
        Rng(seed ^ 0x9E37_79B9_7F4A_7C15 | 1)
    }
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, n: u32) -> u32 {
        (self.next() % u64::from(n.max(1))) as u32
    }
}

/// Build a real `Engine` or signal an environment skip (mirrors the integration suites' io_uring guard, gate
/// included).
fn engine_or_skip() -> Option<Engine> {
    // Under Miri there is no ring to set up - `io_uring_setup` is an unsupported foreign call that aborts the
    // interpreter, not an errno the arm below could catch - so the skip decision has to come first. The
    // ring-dependent tests then skip themselves exactly as they do on a ring-less host, and the Miri lane (ci.yml
    // `miri`) runs what is left: the pure-executor paths.
    if cfg!(miri) {
        return None;
    }
    match Engine::new(RING_ENTRIES, POOL) {
        Ok(e) => Some(e),
        Err(crate::Error::Errno(e)) if crate::uring::setup_unavailable(e) => None,
        Err(e) => panic!("Engine::new: {e}"),
    }
}

/// A fresh real fd (so close-last is observable); `/dev/null` always opens.
fn synth_fd() -> RawFd {
    // SAFETY: a static NUL-terminated path; open cannot corrupt memory.
    let fd = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDWR) };
    assert!(fd >= 0, "open /dev/null");
    fd
}

fn chan(tx: &mpsc::Sender<FsOutcome>) -> FsWaiter {
    FsWaiter::Channel(ReplyTo::Sync(tx.clone()))
}

/// A compact snapshot to assert an anomalous completion is fully inert: sorted free-list + each op's `(generation,
/// state-code)`.
fn snapshot(c: &FsCore) -> (Vec<u32>, Vec<(u64, u8)>) {
    let mut free = c.op_free.clone();
    free.sort_unstable();
    let ops = c
        .ops
        .iter()
        .map(|e| {
            let code = match e.state.state {
                FsOpState::Free => 0u8,
                FsOpState::InFlight { tag } => tag,
            };
            (e.generation, code)
        })
        .collect();
    (free, ops)
}

/// In-flight ops as `(tag, slot, generation-low)` - the CQEs a real kernel could deliver.
fn inflight(c: &FsCore) -> Vec<(u8, u32, u32)> {
    c.ops
        .iter()
        .enumerate()
        .filter_map(|(i, e)| match e.state.state {
            FsOpState::InFlight { tag } => Some((tag, i as u32, e.generation as u32)),
            _ => None,
        })
        .collect()
}

/// Complete `slot`/`gen`/`tag` correctly; a byte count for data ops, a fresh fd for an open (so the built `File` is
/// a real closeable fd).
fn complete(core: &mut FsCore, eng: &mut Engine, t: u8, s: u32, g: u32) {
    let res = if t == TAG_OPEN { synth_fd() } else { 16 };
    let _ = core.on_cqe(eng, t, s, g, res);
}

/// A tag with no arm must be refused before an SQE is filled.
///
/// `fill_sqe` zeroes the slot, and opcode 0 is `IORING_OP_NOP` (first in the kernel's `enum io_uring_op`). A
/// fall-through therefore submitted a NOP carrying the op's real `user_data`: it completes `res = 0`, and `map_res`
/// turns that into `Ok(0)` - an `FSETXATTR` of a `trusted.*` record reported as done that never ran. The debug half
/// is the `debug_assert!(false)`; this is the half that ships.
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

/// A short leased write must not look like success: its source is the connection's receive buffer, already on its
/// way back to the pool by the time any caller could react, so `Ok(n)` would invite a retry from bytes that may
/// hold another connection's request - and a caller that shrugged would store a truncated object. ZFS returns
/// partial writes as successes by design, so the case is real, and the reap is the one place that still knows both
/// the asked-for and the written count.
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

/// N writes share one claim; the buffer surfaces from the last.
///
/// Two leased writes read from one buffer, so releasing at the first completion re-posts it while the sibling's DMA
/// still reads it. The id must ride out of exactly one completion - whichever drops the last share - and a short
/// write still fails its own op alone, whether or not it is the one that releases.
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

// ---- `IOSQE_ASYNC` (`FsCore::set_force_async`) ----

/// The file classes stamp `IOSQE_ASYNC` on a read, and only their own class does. The `WRITE`-only arm is the
/// control: it configures the core, submits the same read, and must leave the SQE unflagged, so an assertion that
/// merely found the bit set could not pass it.
#[test]
fn a_pump_read_carries_iosqe_async_only_for_its_own_class() {
    let staged_flags = |classes: ForceAsync| -> Option<u8> {
        let mut eng = engine_or_skip()?;
        let mut core = FsCore::new(4, OffloadBounds::default());
        core.set_force_async(classes);
        let dir = crate::tempdir().expect("tempdir");
        let p = dir.path().join("f");
        std::fs::write(&p, b"0123456789").unwrap();
        let fd: std::os::fd::OwnedFd = std::fs::File::open(&p).unwrap().into();
        let file = File::new(Arc::new(fd));
        core.submit_pump_read(&mut eng, &file, PumpDest::Owned(Vec::with_capacity(8)), 8, 0, (1, 1))
            .expect("submit");
        let flags = eng.staged_sqe(0).flags;
        // Reap rather than drop mid-flight: the op parks an fd clone and the entry is only released by its
        // completion.
        eng.ring.submit_and_wait(1).expect("submit_and_wait");
        let cqe = eng.ring.reap().expect("cqe");
        let (tag, slot, g) = unpack_raw(cqe.user_data);
        core.on_cqe(&mut eng, tag, slot, g, cqe.res);
        Some(flags)
    };
    let Some(armed) = staged_flags(ForceAsync::READ) else {
        return;
    };
    assert_eq!(
        armed & crate::uring::sys::IOSQE_ASYNC,
        crate::uring::sys::IOSQE_ASYNC,
        "ForceAsync::READ must reach the pump read's SQE"
    );
    for wrong in [ForceAsync::empty(), ForceAsync::WRITE] {
        let flags = staged_flags(wrong).expect("ring was available");
        assert_eq!(
            flags & crate::uring::sys::IOSQE_ASYNC,
            0,
            "a read must stay unflagged under {wrong:?}"
        );
    }
}

// ---- reply-path pump reads (`FsWaiter::Pump`) ----

#[test]
fn a_pump_read_routes_back_with_its_owner_and_bytes() {
    let Some(mut eng) = engine_or_skip() else {
        return;
    };
    let mut core = FsCore::new(4, OffloadBounds::default());
    let dir = crate::tempdir().expect("tempdir");
    let p = dir.path().join("f");
    std::fs::write(&p, b"0123456789").unwrap();
    let fd: std::os::fd::OwnedFd = std::fs::File::open(&p).unwrap().into();
    let file = File::new(Arc::new(fd));

    core.submit_pump_read(&mut eng, &file, PumpDest::Owned(Vec::with_capacity(8)), 8, 2, (3, 77))
        .expect("submit");
    // The op parks its own fd clone (close-last): caller + op.
    assert_eq!(Arc::strong_count(&file.fd), 2);

    eng.ring.submit_and_wait(1).expect("submit_and_wait");
    let cqe = eng.ring.reap().expect("cqe");
    let (tag, slot, g) = unpack_raw(cqe.user_data);
    assert_eq!(tag, TAG_READV);
    let ReapedFs::Pump(done, owner) = core.on_cqe(&mut eng, tag, slot, g, cqe.res) else {
        panic!("a pump read must route as ReapedFs::Pump");
    };
    assert_eq!(owner, (3, 77), "the owner survives the round trip");
    assert!(matches!(done.result(), Ok(8)), "{:?}", done.result());
    // The parked clone dropped with the op entry (close-last).
    assert_eq!(Arc::strong_count(&file.fd), 1);
    let mut bufs = done.into_bufs();
    let mut b = bufs.pop().expect("the read's buffer comes back");
    assert!(bufs.is_empty());
    // SAFETY: the CQE count proves the kernel wrote 8 bytes into the spare capacity the iovec targeted.
    unsafe { b.set_len(8) };
    assert_eq!(&b[..], b"23456789", "read from the requested offset");
}

#[test]
fn a_full_op_table_refuses_a_pump_read_synchronously() {
    // The shed-one-connection discipline needs the error in hand at submit time: there is no callback whose drop
    // could report it, and a silently dropped pump read would strand its connection mid-body with nothing left to
    // re-drive it.
    let Some(mut eng) = engine_or_skip() else {
        return;
    };
    let mut core = FsCore::new(1, OffloadBounds::default());
    let dir = crate::tempdir().expect("tempdir");
    let p = dir.path().join("f");
    std::fs::write(&p, b"abcd").unwrap();
    let fd: std::os::fd::OwnedFd = std::fs::File::open(&p).unwrap().into();
    let file = File::new(Arc::new(fd));
    let submit = |core: &mut FsCore, eng: &mut Engine| {
        core.submit_pump_read(eng, &file, PumpDest::Owned(Vec::with_capacity(4)), 4, 0, (0, 1))
    };

    submit(&mut core, &mut eng).expect("first read takes the only op slot");
    assert_eq!(
        submit(&mut core, &mut eng),
        Err(Errno::EBUSY),
        "a full table must refuse, not drop"
    );
    // Draining the first read frees the slot for the next.
    eng.ring.submit_and_wait(1).expect("submit_and_wait");
    let cqe = eng.ring.reap().expect("cqe");
    let (tag, slot, g) = unpack_raw(cqe.user_data);
    assert!(matches!(
        core.on_cqe(&mut eng, tag, slot, g, cqe.res),
        ReapedFs::Pump(..)
    ));
    submit(&mut core, &mut eng).expect("freed slot serves the next");
}

/// A pump read whose buffer cannot hold `want` is refused, not staged.
///
/// The iovec points at the `Vec`'s spare capacity and carries `want` as its length, so an oversized `want` is an
/// out-of-bounds heap write performed by the kernel on an io-wq worker - the corruption surfaces
/// nowhere near the call. The debug half is the `debug_assert!(false)`;
/// this is the half that ships, on `an_unknown_tag_is_refused_rather_than_staged_as_a_nop`'s pattern.
#[cfg(not(debug_assertions))]
#[test]
fn a_pump_read_past_its_buffer_is_refused_not_staged() {
    let Some(mut eng) = engine_or_skip() else {
        return;
    };
    let mut core = FsCore::new(4, OffloadBounds::default());
    let dir = crate::tempdir().expect("tempdir");
    let p = dir.path().join("f");
    std::fs::write(&p, b"abcd").unwrap();
    let fd: std::os::fd::OwnedFd = std::fs::File::open(&p).unwrap().into();
    let file = File::new(Arc::new(fd));

    // The control: `want == capacity` is exactly what the reply path submits, and it must still be accepted - and
    // take a slot.
    let free = core.op_free_len_for_test();
    core.submit_pump_read(&mut eng, &file, PumpDest::Owned(Vec::with_capacity(8)), 8, 0, (0, 1))
        .expect("want == capacity is the ordinary case");
    assert_eq!(core.op_free_len_for_test(), free - 1, "it took a slot");

    // One byte past the allocation.
    let free = core.op_free_len_for_test();
    assert_eq!(
        core.submit_pump_read(&mut eng, &file, PumpDest::Owned(Vec::with_capacity(8)), 9, 0, (0, 1),),
        Err(Errno::EINVAL),
        "a read past the buffer must be refused"
    );
    assert_eq!(
        core.op_free_len_for_test(),
        free,
        "the refusal must not consume an op slot"
    );

    // The other half of the precondition: the host sets the length from the CQE count, so a buffer that already has
    // one would be written past its own contents.
    let mut used = Vec::with_capacity(64);
    used.push(1u8);
    assert_eq!(
        core.submit_pump_read(&mut eng, &file, PumpDest::Owned(used), 8, 0, (0, 1),),
        Err(Errno::EINVAL),
        "a non-empty destination must be refused"
    );
}

/// The debug half of the guard above: the same call trips the `debug_assert!(false)` rather than reaching the
/// refusal.
#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "a pump read of 9 bytes")]
fn a_pump_read_past_its_buffer_asserts_in_debug() {
    let Some(mut eng) = engine_or_skip() else {
        // A `should_panic` test cannot skip; panic with the expected message so an unavailable ring does not read
        // as a regression.
        panic!("a pump read of 9 bytes (io_uring unavailable: skipped)");
    };
    let mut core = FsCore::new(4, OffloadBounds::default());
    let dir = crate::tempdir().expect("tempdir");
    let p = dir.path().join("f");
    std::fs::write(&p, b"abcd").unwrap();
    let fd: std::os::fd::OwnedFd = std::fs::File::open(&p).unwrap().into();
    let file = File::new(Arc::new(fd));
    let _ = core.submit_pump_read(&mut eng, &file, PumpDest::Owned(Vec::with_capacity(8)), 9, 0, (0, 1));
}

/// The kernel-internal restart codes decode as `EINTR`, the way io_uring's own rw path folds them
/// (`io_fixup_restart_res`, `io_uring/rw.c`), and the codes between and around them stay themselves.
#[test]
fn restart_codes_fold_to_eintr_like_the_kernels_rw_path() {
    for res in [-512, -513, -514, -516] {
        assert_eq!(map_res(res), Err(Errno::EINTR), "res {res}");
    }
    // 515 is ENOIOCTLCMD, not a restart code; a range would eat it.
    assert_eq!(map_res(-515), Err(Errno::from_raw(515)));
    assert_eq!(map_res(-libc::ECANCELED), Err(Errno::ECANCELED));
    assert_eq!(map_res(7), Ok(7));
}

/// The sweep leaves a signal behind, because it cannot leave a gate behind.
///
/// It runs once per close and a continuation woken by one of its own cancellations submits after it, so nothing
/// stops a task whose awaits cannot fail - an offload always delivers, a timer armed afterwards expires normally -
/// from running for a connection that is gone. `owner_is_gone` is what such a task asks, and it must answer for the
/// swept tenant of a slot without answering for the next one to take it.
#[test]
fn a_swept_owner_is_visible_to_what_runs_after_the_sweep() {
    let Some(mut eng) = engine_or_skip() else {
        return;
    };
    let mut core = FsCore::new(4, OffloadBounds::default());
    let gone = (7u32, 3u64);

    assert!(!core.owner_is_gone(Some(gone)), "nothing swept yet");
    core.cancel_owned_by(&mut eng, vec![gone]);
    assert!(core.owner_is_gone(Some(gone)), "the swept owner is gone");

    // A slot is reused, and its next tenant is not the one swept.
    assert!(
        !core.owner_is_gone(Some((gone.0, gone.1 + 1))),
        "a later tenant of the same slot is live"
    );
    // Every earlier tenant closed before this one did.
    assert!(
        core.owner_is_gone(Some((gone.0, gone.1 - 1))),
        "a tenant before the swept one is gone too"
    );
    assert!(!core.owner_is_gone(Some((8, 3))), "another slot is its own");
    assert!(
        !core.owner_is_gone(None),
        "a reactor with no owners has no connection to lose"
    );

    // And the facade a continuation is handed reads it.
    let conn = FsConn::new(&mut core, &mut eng, Some(gone));
    assert!(conn.owner_is_gone(), "the continuation facade answers");
}

/// One sweep reaches every closed owner's ops, and an idle table costs nothing to sweep.
///
/// A close is recorded whether or not the handler opened anything, so on a busy server the batch is ordinary and
/// the table is `fs_ops + pool_size` deep - 28k+ entries at a real consumer's configuration. Per-owner scanning
/// walked all of it once per close, on the reactor thread.
#[test]
fn one_sweep_covers_the_batch_and_an_idle_table_is_free() {
    let Some(mut eng) = engine_or_skip() else {
        return;
    };
    let mut core = FsCore::new(8, OffloadBounds::default());
    let all_free = core.op_free_len_for_test();

    // Nothing in flight: the sweep records and returns.
    core.cancel_owned_by(&mut eng, vec![(1, 1), (2, 1), (3, 1)]);
    assert!(core.owner_is_gone(Some((2, 1))), "recorded regardless");
    assert_eq!(core.op_free_len_for_test(), all_free, "nothing taken");

    // Four owners with a parked pipe read each: only a cancel can complete one, so what is left in flight names the
    // batch.
    let mut fds = [0i32; 2];
    // SAFETY: `pipe(2)` fills {read, write}.
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe");
    // SAFETY: the fresh read end, owned here; the write end stays open so no read EOFs, and both close with the
    // process.
    let file = File::new(Arc::new(unsafe { crate::fd::owned_from_raw(fds[0]) }));
    let owners = [(10u32, 1u64), (11, 1), (12, 1), (13, 1)];
    for o in owners {
        core.submit_pump_read(&mut eng, &file, PumpDest::Owned(Vec::with_capacity(8)), 8, u64::MAX, o)
            .expect("submit");
    }
    assert_eq!(inflight(&core).len(), 4, "four parked reads");

    // One call for three of them; the fourth is untouched. The batch arrives DESCENDING, because production
    // `fs_closed` is pushed in close order and is not sorted: the membership test is a binary search, so an
    // already-sorted batch here would pass with the sort deleted while production silently missed owners - their
    // ops never cancelled, their fds parked until teardown.
    core.cancel_owned_by(&mut eng, vec![(12, 1), (11, 1), (10, 1)]);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let mut reaped = Vec::new();
    while reaped.len() < 3 {
        assert!(
            std::time::Instant::now() < deadline,
            "one sweep did not reach the whole batch: {reaped:?}"
        );
        eng.ring.submit().expect("submit");
        let Some(cqe) = eng.ring.reap() else {
            std::thread::sleep(std::time::Duration::from_millis(1));
            continue;
        };
        let (tag, slot, g) = unpack_raw(cqe.user_data);
        if let ReapedFs::Pump(_, owner) = core.on_cqe(&mut eng, tag, slot, g, cqe.res) {
            reaped.push(owner);
        }
    }
    reaped.sort_unstable();
    assert_eq!(reaped, vec![(10, 1), (11, 1), (12, 1)], "exactly the batch");
    assert_eq!(inflight(&core).len(), 1, "the owner outside it stays");
    assert!(
        core.owner_is_gone(Some((11, 1))) && !core.owner_is_gone(Some((13, 1))),
        "and the record is exactly the batch too"
    );
}

/// The teardown sweep reaching an `Allow` open retracts its guard with it: the open completes through the sweep's
/// cancel, its completion marks and cancels the guard, and both slots return - no hour-long residue for a
/// connection that is gone.
#[test]
fn the_sweep_reaches_an_allow_open_and_its_guard_follows() {
    let Some(mut eng) = engine_or_skip() else {
        return;
    };
    let mut core = FsCore::new(2, OffloadBounds::default());
    let dir = crate::tempdir::tempdir().expect("tempdir");
    let fifo = dir.path().join("pipe");
    let cpath = CString::new(fifo.as_os_str().as_encoded_bytes()).expect("no NUL");
    // SAFETY: a NUL-terminated path this test owns.
    assert_eq!(unsafe { libc::mkfifo(cpath.as_ptr(), 0o600) }, 0, "mkfifo");
    let at = Anchor::open(dir.path()).expect("anchor");
    let me = crate::uring::sys::register_personality(eng.ring.raw_fd()).expect("personality");

    // The forced-async blocking shape, behind an hour's guard.
    let mut raw = OpenHow::new()
        .flags(OFlag::O_WRONLY | OFlag::O_CREAT)
        .mode(crate::sync_fs::Mode::from_bits_truncate(0o600))
        .to_raw();
    crate::uring_fs::confine_resolve(&mut raw.resolve);
    core.submit_open(
        &mut eng,
        me,
        at.clone(),
        b"pipe",
        raw,
        false,
        Some(std::time::Duration::from_secs(3600)),
        FsWaiter::Pump { owner: (5, 9) },
    );
    assert!(!core.has_free_op(), "the open and its guard hold both slots");

    core.cancel_owned_by(&mut eng, vec![(5, 9)]);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let mut open_done = false;
    while !(open_done && core.op_free_len_for_test() == 2) {
        assert!(
            std::time::Instant::now() < deadline,
            "open_done={open_done} free={}: the sweep stranded the \
                 pair for its hour",
            core.op_free_len_for_test()
        );
        eng.ring.submit().expect("submit");
        let Some(cqe) = eng.ring.reap() else {
            std::thread::sleep(std::time::Duration::from_millis(1));
            continue;
        };
        let (tag, slot, g) = unpack_raw(cqe.user_data);
        if let ReapedFs::Pump(done, owner) = core.on_cqe(&mut eng, tag, slot, g, cqe.res) {
            assert_eq!(owner, (5, 9));
            assert!(
                matches!(done.result(), Err(crate::Error::Errno(Errno::ECANCELED | Errno::EINTR))),
                "the sweep's verdict: {:?}",
                done.result()
            );
            open_done = true;
        }
    }
}

/// A deadline-tripped `Allow` open answers in its own vocabulary, never teardown's: the guard's expiry marks the
/// open before staging its cancel, so the `ECANCELED` arrives with `was_refused` true - unmarked `ECANCELED` is
/// what a task winds a whole live connection down on, and one bad filename must not read as the reactor going away.
/// Driven with synthesized CQEs (the routing idiom above) because the live trip has two honest spellings - which
/// one the kernel answers depends on where the cancel's signal catches the parked worker - and only this arm's
/// ordering is the property under test.
#[test]
fn a_tripped_allow_deadline_answers_marked_not_as_teardown() {
    let Some(mut eng) = engine_or_skip() else {
        return;
    };
    let mut core = FsCore::new(2, OffloadBounds::default());
    let dir = crate::tempdir::tempdir().expect("tempdir");
    let at = Anchor::open(dir.path()).expect("anchor");
    let raw = OpenHow::new().flags(OFlag::O_WRONLY).to_raw();
    // A fresh table's LIFO free list hands out slot 0 (the open) then slot 1 (the guard), both at generation 0. The
    // SQEs stage into a ring far larger than two entries and are never submitted; the CQEs below are synthesized.
    core.submit_open(
        &mut eng,
        77,
        at.clone(),
        b"planted",
        raw,
        false,
        Some(std::time::Duration::from_secs(3600)),
        FsWaiter::Pump { owner: (5, 9) },
    );
    assert!(!core.has_free_op(), "the open and its guard hold both slots");

    // The guard fires: its arm must mark the open it cancels.
    let reaped = core.on_cqe(&mut eng, TAG_OPEN_DEADLINE, 1, 0, -libc::ETIME);
    assert!(matches!(reaped, ReapedFs::None), "the guard routes nowhere");
    // The cancel lands: the open completes `ECANCELED`, marked.
    match core.on_cqe(&mut eng, TAG_OPEN, 0, 0, -libc::ECANCELED) {
        ReapedFs::Pump(done, owner) => {
            assert_eq!(owner, (5, 9));
            assert!(
                matches!(done.result(), Err(crate::Error::Errno(Errno::ECANCELED))) && done.was_refused(),
                "a tripped deadline answered teardown's verdict: \
                     {:?} refused={}",
                done.result(),
                done.was_refused()
            );
        }
        _ => panic!("the open's completion was not routed"),
    }
    assert_eq!(core.op_free_len_for_test(), 2, "both slots returned");
}

/// A guard that ends without firing has still stopped bounding its open, and the reachable ending is a prep
/// failure: `push_sqe` accepts the SQE - charge taken, cancel target recorded - while `__io_timeout_prep` runs
/// later inside `io_uring_enter` and can answer `-ENOMEM` (`io_uring/timeout.c:554-556`), with
/// `io_submit_fail_init` posting a CQE under the guard's own tag. Screened on `-ETIME` the token was discarded and
/// nothing ever cancelled the open, so an `Allow` open parked in `fifo_open` held an io-wq worker, its op slot and
/// its owner's charge for as long as the peer liked.
#[test]
fn a_guard_that_never_armed_still_cancels_its_open() {
    let Some(mut eng) = engine_or_skip() else {
        return;
    };
    let mut core = FsCore::new(2, OffloadBounds::default());
    let dir = crate::tempdir::tempdir().expect("tempdir");
    let at = Anchor::open(dir.path()).expect("anchor");
    let raw = OpenHow::new().flags(OFlag::O_WRONLY).to_raw();
    core.submit_open(
        &mut eng,
        77,
        at.clone(),
        b"planted",
        raw,
        false,
        Some(std::time::Duration::from_secs(3600)),
        FsWaiter::Pump { owner: (5, 9) },
    );
    assert!(!core.has_free_op(), "the open and its guard hold both");

    // The guard's prep failed: it never armed, so nothing else will ever end the open.
    let reaped = core.on_cqe(&mut eng, TAG_OPEN_DEADLINE, 1, 0, -libc::ENOMEM);
    assert!(matches!(reaped, ReapedFs::None), "the guard routes nowhere");
    match core.on_cqe(&mut eng, TAG_OPEN, 0, 0, -libc::ECANCELED) {
        ReapedFs::Pump(done, owner) => {
            assert_eq!(owner, (5, 9));
            assert!(
                done.was_refused(),
                "an open whose bound never armed ran on unmarked: \
                     {:?} refused={}",
                done.result(),
                done.was_refused()
            );
        }
        _ => panic!("the open was never cancelled"),
    }
    assert_eq!(core.op_free_len_for_test(), 2, "both slots returned");
}

/// The other half of the same screen: an *unmarked* `ECANCELED` on the guard is a sweep or teardown, which stages
/// the open's own cancel and needs its `ECANCELED` to stay in teardown's vocabulary. Marking there would tell a
/// task that its connection had one op refused, where what happened is that the connection went away.
#[test]
fn a_swept_guard_leaves_its_open_in_teardown_s_vocabulary() {
    let Some(mut eng) = engine_or_skip() else {
        return;
    };
    let mut core = FsCore::new(2, OffloadBounds::default());
    let dir = crate::tempdir::tempdir().expect("tempdir");
    let at = Anchor::open(dir.path()).expect("anchor");
    let raw = OpenHow::new().flags(OFlag::O_WRONLY).to_raw();
    core.submit_open(
        &mut eng,
        77,
        at.clone(),
        b"planted",
        raw,
        false,
        Some(std::time::Duration::from_secs(3600)),
        FsWaiter::Pump { owner: (5, 9) },
    );
    // The sweep stages a cancel for both, marking neither.
    core.cancel_owned_by(&mut eng, vec![(5, 9)]);
    let reaped = core.on_cqe(&mut eng, TAG_OPEN_DEADLINE, 1, 0, -libc::ECANCELED);
    assert!(matches!(reaped, ReapedFs::None), "the guard routes nowhere");
    match core.on_cqe(&mut eng, TAG_OPEN, 0, 0, -libc::ECANCELED) {
        ReapedFs::Pump(done, owner) => {
            assert_eq!(owner, (5, 9));
            assert!(
                !done.was_refused(),
                "a swept open answered as a refusal: {:?}",
                done.result()
            );
        }
        _ => panic!("the open's completion was not routed"),
    }
    assert_eq!(core.op_free_len_for_test(), 2, "both slots returned");
}

/// The live half of the trip: a planted FIFO with no writer parks the open on an io-wq worker, and the deadline is
/// the only way it ends. Which spelling comes back depends on where the cancel's signal catches the worker -
/// `ECANCELED` marked, or `EINTR` - so what this pins is that both slots recover and that the teardown spelling
/// (`ECANCELED` unmarked) never appears; the deterministic ordering above owns the mark itself.
#[test]
fn a_tripped_allow_deadline_recovers_both_slots() {
    let Some(mut eng) = engine_or_skip() else {
        return;
    };
    let mut core = FsCore::new(2, OffloadBounds::default());
    let dir = crate::tempdir::tempdir().expect("tempdir");
    let fifo = dir.path().join("pipe");
    let cpath = CString::new(fifo.as_os_str().as_encoded_bytes()).expect("no NUL");
    // SAFETY: a NUL-terminated path this test owns.
    assert_eq!(unsafe { libc::mkfifo(cpath.as_ptr(), 0o600) }, 0, "mkfifo");
    let at = Anchor::open(dir.path()).expect("anchor");
    let me = crate::uring::sys::register_personality(eng.ring.raw_fd()).expect("personality");

    let mut raw = OpenHow::new()
        .flags(OFlag::O_WRONLY | OFlag::O_CREAT)
        .mode(crate::sync_fs::Mode::from_bits_truncate(0o600))
        .to_raw();
    crate::uring_fs::confine_resolve(&mut raw.resolve);
    core.submit_open(
        &mut eng,
        me,
        at.clone(),
        b"pipe",
        raw,
        false,
        Some(std::time::Duration::from_millis(50)),
        FsWaiter::Pump { owner: (5, 9) },
    );

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let mut open_done = false;
    while !(open_done && core.op_free_len_for_test() == 2) {
        assert!(
            std::time::Instant::now() < deadline,
            "open_done={open_done} free={}: the deadline never \
                 recovered the pair",
            core.op_free_len_for_test()
        );
        eng.ring.submit().expect("submit");
        let Some(cqe) = eng.ring.reap() else {
            std::thread::sleep(std::time::Duration::from_millis(1));
            continue;
        };
        let (tag, slot, g) = unpack_raw(cqe.user_data);
        if let ReapedFs::Pump(done, owner) = core.on_cqe(&mut eng, tag, slot, g, cqe.res) {
            assert_eq!(owner, (5, 9));
            match done.result() {
                Err(crate::Error::Errno(Errno::ECANCELED)) => {
                    assert!(
                        done.was_refused(),
                        "a tripped deadline answered the unmarked \
                             `ECANCELED` reserved for teardown"
                    );
                }
                Err(crate::Error::Errno(Errno::EINTR)) => {}
                other => panic!("the open ended some other way: {other:?}"),
            }
            open_done = true;
        }
    }
}

#[test]
fn cancel_owned_by_reaches_a_pump_read() {
    // Connection teardown's sweep cancels fs ops by owner; a pump read parked on an empty pipe (never completing on
    // its own) must be reaped by exactly that path, and its parked fd clone released.
    let Some(mut eng) = engine_or_skip() else {
        return;
    };
    let mut core = FsCore::new(4, OffloadBounds::default());
    let mut fds = [0i32; 2];
    // SAFETY: `pipe(2)` fills {read, write}.
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe");
    // SAFETY: fds[0] is the fresh read end, owned here; fds[1] (the write end, kept open so the read never EOFs)
    // closes at the end.
    let file = File::new(Arc::new(unsafe { crate::fd::owned_from_raw(fds[0]) }));

    // `u64::MAX` offset = "the file position": a pipe rejects real offsets with ESPIPE.
    core.submit_pump_read(
        &mut eng,
        &file,
        PumpDest::Owned(Vec::with_capacity(8)),
        8,
        u64::MAX,
        (5, 9),
    )
    .expect("submit");
    assert_eq!(Arc::strong_count(&file.fd), 2, "op parks its clone");
    core.cancel_owned_by(&mut eng, vec![(5, 9)]);

    // Reap until the read's own CQE routes (the cancel's is inert).
    //
    // Deadline rather than `submit_and_wait`: the read is parked on an empty pipe and `cancel_owned_by`'s
    // `FsWaiter::Pump` arm is the only thing that can complete it, so a blocking wait turns the failure this test
    // exists to catch into a hang - in CI, indistinguishable from a slow runner. Bounded, it names the arm instead.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let reaped = loop {
        assert!(
            std::time::Instant::now() < deadline,
            "the parked read was never reaped: `cancel_owned_by` no \
                 longer reaches a `FsWaiter::Pump` op, so a closed \
                 connection's body read stays in flight with its fd parked"
        );
        eng.ring.submit().expect("submit");
        let Some(cqe) = eng.ring.reap() else {
            std::thread::sleep(std::time::Duration::from_millis(1));
            continue;
        };
        let (tag, slot, g) = unpack_raw(cqe.user_data);
        match core.on_cqe(&mut eng, tag, slot, g, cqe.res) {
            ReapedFs::None => continue,
            other => break other,
        }
    };
    let ReapedFs::Pump(done, owner) = reaped else {
        panic!("the cancelled read must still route as Pump");
    };
    assert_eq!(owner, (5, 9));
    assert!(
        matches!(done.result(), Err(crate::Error::Errno(Errno::ECANCELED))),
        "an owner cancel reaps the parked read: {:?}",
        done.result()
    );
    assert_eq!(Arc::strong_count(&file.fd), 1, "clone released");
    // SAFETY: closing the test-owned write end.
    unsafe { libc::close(fds[1]) };
}
