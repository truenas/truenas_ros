//! A chain of steps on one file, staged as one link of io_uring ([`FsConn::chain`]): a reopen into a slot of the
//! ring's registered table, an `ftruncate`, a set of [`ZFS_SETATTR`], a statx, an fsync and a close, each present or
//! not, in that order.
//!
//! **How a link ends decides how the chain is counted.** Of these steps only a failed reopen or close ends a link
//! (`req_set_fail` in `io_uring/openclose.c`), but a step cancelled on its worker ends one too (`io_wq_submit_work` in
//! `io_uring/io_uring.c`). So every step but the reopen and the last carries `IOSQE_IO_HARDLINK`, and once the reopen
//! worked nothing ends the chain before its last step (`io_disarm_next` in `io_uring/timeout.c`). The reopen skips its
//! completion, which then posts only when it ends the chain, and the statx skips its own, reading into a buffer whose
//! mask shows whether it ran, since a failed statx posts nothing under the skip (`io_uring/statx.c`). A step that fails
//! at prep fails them all (`io_submit_fail_init`), and only the first step posts when it skips its completion, so a
//! statx first in its link posts its completion. Each link then posts exactly one completion that is counted in
//! flight, its last step's or the reopen's, and the rest are [`chain_mid`].
//!
//! **A size runs first, alone.** The reopen and the `ftruncate` go as one link, and the rest is staged from the
//! `ftruncate`'s completion once it worked, since a failed `ftruncate` stops nothing after it, and a refused size must
//! set nothing.
//!
//! **No slot is left to the caller.** Op slot `i` reopens into slot `base + i` of the registered table, so a chain that
//! has an op has a slot. A chain that ends before its close once its reopen worked, by a failed `ftruncate`, a close
//! cancelled before it ran or a refused stage of the rest, leaves a file there, which the core empties at once
//! ([`Ring::clear_file`](crate::uring::ring::Ring::clear_file)) before the op slot goes back. A failed reopen, and a
//! failure at prep of a link the reopen heads, leave it empty.

use super::*;
use crate::uring::sys::{IORING_OP_CLOSE, IOSQE_CQE_SKIP_SUCCESS, IOSQE_FIXED_FILE, IOSQE_IO_HARDLINK, IoUringSqe};
use std::cell::UnsafeCell;

/// The steps of one chain ([`FsConn::chain`]), each present or not, run in the order of the fields.
#[derive(Debug)]
pub struct Chain {
    /// The file the reopen opens again and the statx reads, which may be held `O_PATH`, or with no reopen the file every
    /// step names.
    pub file: File,
    /// Open `file` again into the op's own slot of the ring's registered table, which every later step names and the
    /// chain closes last.
    pub reopen: Option<Reopen>,
    /// The length to `ftruncate` the file to.
    pub truncate: Option<u64>,
    /// The value of [`ZFS_SETATTR`] to set, given back by [`ChainDone::into_value`].
    pub set: Option<Vec<u8>>,
    /// The fields to statx of `file`, read after the set, which [`ChainDone::stat`] gives.
    pub statx: Option<StatxMask>,
    /// Whether to `fsync` the file.
    pub sync: bool,
}

/// Who a chain's reopen opens the file as.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reopen {
    /// As the personality the chain runs as, which the open checks against the file as an open by name does, as
    /// [`FsConn::reopen_proc`] checks it.
    AsCaller(ReopenAccess),
    /// Under the ring owner's credentials, for an access a server has already decided, as
    /// [`FsConn::reopen_proc_as_root`] opens it.
    AsRing(ReopenAccess),
}

impl Reopen {
    fn access(self) -> ReopenAccess {
        match self {
            Reopen::AsCaller(a) | Reopen::AsRing(a) => a,
        }
    }
}

/// A step of a chain whose result [`ChainDone::step`] gives. The statx has none, since its buffer shows whether it ran
/// ([`ChainDone::stat`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChainStep {
    /// The reopen into the op's slot.
    Reopen = 0,
    /// The `ftruncate`.
    Truncate = 1,
    /// The set of [`ZFS_SETATTR`].
    Set = 2,
    /// The `fsync`.
    Sync = 3,
    /// The close of the op's slot, which every chain with a reopen ends with.
    Close = 4,
}

/// The result of a step that posted nothing.
const NOT_RAN: i32 = i32::MIN;

/// What a chain answered, handed to its callback once its last completion arrives.
#[derive(Debug)]
pub struct ChainDone {
    res: [i32; 5],
    stat: StatxRaw,
    refused: bool,
    value: Vec<u8>,
}

impl ChainDone {
    /// What `step` answered, or `None` for a step that posted nothing: the chain did not have it, it is the reopen that
    /// worked, whose completion is skipped, or it never ran, since a failed reopen ended the chain or a failed
    /// `ftruncate` kept the rest from being staged. Every step the core refused to run answers its refusal.
    pub fn step(&self, step: ChainStep) -> Option<crate::Result<i32>> {
        let res = self.res[step as usize];
        (res != NOT_RAN).then(|| map_res(res).map_err(Into::into))
    }

    /// The statx, or `None` when the chain had none or it did not run or failed, since its mask was cleared before.
    pub fn stat(&self) -> Option<Statx> {
        (self.stat.stx_mask != 0).then(|| Statx::from_raw(self.stat))
    }

    /// Whether this crate refused to run the chain, or the rest of it after its size, rather than the kernel answering:
    /// a marked `EBUSY` for a full op table or submission queue, worth a retry, or a marked `EINVAL` for a chain with no
    /// step, no personality, or on a ring without the slots.
    pub fn was_refused(&self) -> bool {
        self.refused
    }

    /// The value the set was given, back for its next use.
    pub fn into_value(self) -> Vec<u8> {
        self.value
    }
}

/// The steps a link of a chain stages.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Step {
    Reopen,
    Truncate,
    Set,
    Statx,
    Sync,
    Close,
}

impl Step {
    /// Where its result goes in [`ChainDone`], or `None` for the statx.
    fn index(self) -> Option<usize> {
        Some(match self {
            Step::Reopen => ChainStep::Reopen as usize,
            Step::Truncate => ChainStep::Truncate as usize,
            Step::Set => ChainStep::Set as usize,
            Step::Sync => ChainStep::Sync as usize,
            Step::Close => ChainStep::Close as usize,
            Step::Statx => return None,
        })
    }
}

/// The steps of one link, at most five.
#[derive(Clone, Copy)]
struct Steps {
    list: [Step; 5],
    len: usize,
}

impl Steps {
    fn new() -> Steps {
        Steps {
            list: [Step::Close; 5],
            len: 0,
        }
    }

    fn push_if(&mut self, present: bool, step: Step) {
        if present {
            self.list[self.len] = step;
            self.len += 1;
        }
    }

    fn as_slice(&self) -> &[Step] {
        &self.list[..self.len]
    }
}

/// What a chain keeps beside its op slot while it runs, one for each slot of the op table, made only on a ring with the
/// chain slots ([`FsCore::enable_chains`]), so no other ring pays for the buffer of the statx.
///
/// Both outlive the op's reap until the callback copies them out, which [`deliver_embedded`] runs straight after the
/// reap, before anything can stage another chain on the slot.
pub(crate) struct Chains {
    /// The first slot of the registered table past the pool, so op slot `i` reopens into `base + i`.
    base: u32,
    entries: Box<[ChainEntry]>,
    /// The buffer of each slot's statx, which the kernel writes whole as the statx runs, its mask cleared before. Apart
    /// from `entries` and reached by pointer alone, since a step's completion is routed while the statx after it may
    /// be writing.
    stats: Box<[UnsafeCell<StatxRaw>]>,
}

/// A chain's state beside its op slot.
struct ChainEntry {
    /// What each step answered, by [`ChainStep`], or [`NOT_RAN`].
    res: [i32; 5],
    /// The personality the steps on the file run as.
    pers: u16,
    /// The mask of the statx.
    mask: u32,
    set: bool,
    statx: bool,
    sync: bool,
    /// The chain reopened into its slot, so it closes it last.
    reopens: bool,
    /// The rest is staged once the `ftruncate` worked.
    rest: bool,
    /// The last step of the link in flight, whose completion is the one tagged [`TAG_CHAIN_END`].
    end: Step,
    /// The core refused to stage the rest after the size.
    refused: bool,
}

impl ChainEntry {
    fn new() -> ChainEntry {
        ChainEntry {
            res: [NOT_RAN; 5],
            pers: 0,
            mask: 0,
            set: false,
            statx: false,
            sync: false,
            reopens: false,
            rest: false,
            end: Step::Close,
            refused: false,
        }
    }

    /// The steps after the reopen and the size.
    fn rest_steps(&self) -> Steps {
        let mut s = Steps::new();
        s.push_if(self.set, Step::Set);
        s.push_if(self.statx, Step::Statx);
        s.push_if(self.sync, Step::Sync);
        s.push_if(self.reopens, Step::Close);
        s
    }
}

/// A statx buffer that reads as not run.
fn zeroed_statx() -> StatxRaw {
    // SAFETY: `StatxRaw` is plain integers, for which all zeros is a value.
    unsafe { std::mem::zeroed() }
}

/// What the SQEs of a link point at.
struct Fill {
    /// The slot of the registered table the steps name, with a reopen.
    fixed: Option<u32>,
    /// The file the caller gave, which the statx reads and, with no reopen, every step names.
    raw_fd: RawFd,
    pers: u16,
    value: (u64, u32),
    stat: u64,
    mask: u32,
    len: u64,
    /// The folder of descriptors, the name of the file in it, the `open_how` and the personality of the reopen.
    reopen: Option<(RawFd, u64, u64, u16)>,
}

/// Stage `steps` as one link for op `op_slot`, as [`chain`](self) lays out.
fn stage_link(eng: &mut Engine, op_slot: u32, gen32: u32, steps: &[Step], f: &Fill) -> Result<(), Errno> {
    let n = steps.len();
    eng.stage_fs_chain(n, |i, sqe| {
        let step = steps[i];
        let last = i + 1 == n;
        let tag = match step {
            _ if last => TAG_CHAIN_END,
            Step::Reopen => TAG_CHAIN_REOPEN,
            Step::Set => TAG_CHAIN_SET,
            Step::Statx => TAG_CHAIN_STATX,
            Step::Sync => TAG_CHAIN_SYNC,
            Step::Truncate | Step::Close => {
                debug_assert!(false, "{step:?} ends its link");
                TAG_CHAIN_END
            }
        };
        sqe.user_data = pack_raw(tag, op_slot, gen32);
        if !last && step != Step::Reopen {
            sqe.flags |= IOSQE_IO_HARDLINK;
        }
        let on_file = |sqe: &mut IoUringSqe| match f.fixed {
            Some(s) => {
                sqe.fd = s as RawFd;
                sqe.flags |= IOSQE_FIXED_FILE;
            }
            None => sqe.fd = f.raw_fd,
        };
        match step {
            Step::Reopen => {
                let (dir, name, how, pers) = f.reopen.expect("a reopen has its operands");
                sqe.opcode = IORING_OP_OPENAT2;
                sqe.fd = dir;
                sqe.addr = name;
                sqe.off_addr2 = how;
                sqe.len = size_of::<RawOpenHow>() as u32;
                sqe.file_index = f.fixed.map_or(0, |s| s + 1);
                // The inline try always fails, as `stage_reopen_proc` says.
                sqe.flags |= IOSQE_ASYNC | IOSQE_CQE_SKIP_SUCCESS;
                sqe.personality = pers;
            }
            Step::Truncate => {
                sqe.opcode = IORING_OP_FTRUNCATE;
                on_file(sqe);
                sqe.off_addr2 = f.len;
                sqe.personality = f.pers;
            }
            Step::Set => {
                sqe.opcode = IORING_OP_FSETXATTR;
                on_file(sqe);
                sqe.addr = ZFS_SETATTR.as_ptr() as u64;
                (sqe.off_addr2, sqe.len) = f.value;
                sqe.personality = f.pers;
            }
            Step::Statx => {
                // STATX names no registered slot (`io_uring/opdef.c`), so it reads the caller's file.
                static EMPTY: &CStr = c"";
                sqe.opcode = IORING_OP_STATX;
                sqe.fd = f.raw_fd;
                sqe.addr = EMPTY.as_ptr() as u64;
                sqe.op_flags = statx_at_flags(AtFlags::AT_EMPTY_PATH);
                sqe.len = f.mask;
                sqe.off_addr2 = f.stat;
                if !last && i > 0 {
                    sqe.flags |= IOSQE_CQE_SKIP_SUCCESS;
                }
            }
            Step::Sync => {
                sqe.opcode = IORING_OP_FSYNC;
                on_file(sqe);
                sqe.personality = f.pers;
            }
            Step::Close => {
                sqe.opcode = IORING_OP_CLOSE;
                sqe.fd = 0;
                sqe.file_index = f.fixed.map_or(0, |s| s + 1);
            }
        }
    })
}

impl FsCore {
    /// Keep the state of a chain beside each op slot, reopening into the slots of the registered table from `base`,
    /// which the host registered past its pool, one for each op slot.
    #[cfg_attr(not(feature = "net-server"), allow(dead_code))]
    pub(crate) fn enable_chains(&mut self, base: u32) {
        self.chains = Some(Chains {
            base,
            entries: (0..self.ops.len()).map(|_| ChainEntry::new()).collect(),
            stats: (0..self.ops.len()).map(|_| UnsafeCell::new(zeroed_statx())).collect(),
        });
    }

    /// Stage `chain` as `pers` ([`FsConn::chain`]).
    pub(crate) fn submit_chain(&mut self, eng: &mut Engine, pers: u16, chain: Chain, waiter: FsWaiter) {
        let Chain {
            file,
            reopen,
            truncate,
            set,
            statx,
            sync,
        } = chain;
        let file = file.fd;
        let has_set = set.is_some();
        let empty = reopen.is_none() && truncate.is_none() && set.is_none() && statx.is_none() && !sync;
        if self.chains.is_none() || pers == 0 || empty {
            self.refuse(eng, waiter, Errno::EINVAL, true, set.into_iter().collect(), Some(file));
            return;
        }
        let dir = match reopen.map(|_| self.proc_fd_dir()).transpose() {
            Ok(dir) => dir,
            Err(err) => {
                self.refuse(eng, waiter, err, false, set.into_iter().collect(), Some(file));
                return;
            }
        };
        let Some(op_slot) = self.pop_op() else {
            self.refuse(eng, waiter, Errno::EBUSY, true, set.into_iter().collect(), Some(file));
            return;
        };
        let waiter = self.park(op_slot, waiter);
        let raw_fd = file.as_raw_fd();
        let entry = &mut self.ops[op_slot as usize];
        let gen32 = entry.generation as u32;
        let e = &mut entry.state;
        e.state = FsOpState::InFlight { tag: TAG_CHAIN_END };
        e.waiter = Some(waiter);
        e.file = Some(file);
        let reopen = reopen.zip(dir).map(|(r, dir)| {
            let (mut how, _) = r.access().how();
            // A slot of the registered table takes no close-on-exec flag (`__io_openat_prep` in
            // `io_uring/openclose.c`). The guard's `O_NONBLOCK` stays, since the chain closes the file itself.
            how.flags &= !(libc::O_CLOEXEC as u64);
            let how = e.how.insert(how) as *const RawOpenHow as u64;
            let open_pers = match r {
                Reopen::AsCaller(_) => pers,
                Reopen::AsRing(_) => 0,
            };
            (dir, e.park_fd_name(raw_fd), how, open_pers)
        });
        let value = match set {
            Some(v) => {
                let v = e.value.insert(v);
                (v.as_ptr() as u64, v.len() as u32)
            }
            None => (0, 0),
        };
        let chains = self.chains.as_mut().expect("screened above");
        let fixed = reopen.map(|_| chains.base + op_slot);
        let stat = chains.stats[op_slot as usize].get();
        // SAFETY: the slot's last chain has ended, so no statx writes its buffer.
        unsafe { (*stat).stx_mask = 0 };
        let c = &mut chains.entries[op_slot as usize];
        c.res = [NOT_RAN; 5];
        c.pers = pers;
        c.mask = statx.map_or(0, |m| m.bits());
        c.set = has_set;
        c.statx = statx.is_some();
        c.sync = sync;
        c.reopens = reopen.is_some();
        c.rest = truncate.is_some();
        c.refused = false;
        let mut steps = Steps::new();
        steps.push_if(reopen.is_some(), Step::Reopen);
        if truncate.is_some() {
            steps.push_if(true, Step::Truncate);
        } else {
            for &s in c.rest_steps().as_slice() {
                steps.push_if(true, s);
            }
        }
        c.end = steps.as_slice()[steps.len - 1];
        let fill = Fill {
            fixed,
            raw_fd,
            pers,
            value,
            stat: stat as u64,
            mask: c.mask,
            len: truncate.unwrap_or(0),
            reopen,
        };
        if let Err(err) = stage_link(eng, op_slot, gen32, steps.as_slice(), &fill) {
            self.fail_op(eng, op_slot, err);
        }
    }

    /// One completion of a chain. A step with more to come records its result, and the one that ends a link, its last
    /// or a failed reopen, stages the rest after a size or ends the chain, emptying the slot a file was left in.
    pub(super) fn on_chain_cqe(&mut self, eng: &mut Engine, tag: u8, op_slot: u32, gen32: u32, res: i32) -> ReapedFs {
        let live = self.ops.get(op_slot as usize).is_some_and(|entry| {
            entry.generation as u32 == gen32 && entry.state.state == (FsOpState::InFlight { tag: TAG_CHAIN_END })
        });
        let Some(chains) = self.chains.as_mut().filter(|_| live) else {
            return ReapedFs::None;
        };
        let slot = chains.base + op_slot;
        let stat = chains.stats[op_slot as usize].get() as u64;
        let c = &mut chains.entries[op_slot as usize];
        match tag {
            TAG_CHAIN_SET => {
                c.res[ChainStep::Set as usize] = res;
                return ReapedFs::None;
            }
            TAG_CHAIN_SYNC => {
                c.res[ChainStep::Sync as usize] = res;
                return ReapedFs::None;
            }
            // A statx first in its link, or cancelled, or cancelled behind a cancelled step, posts with more to come.
            // Its buffer says whether it ran.
            TAG_CHAIN_STATX => return ReapedFs::None,
            // The reopen posts only when it failed, which ended the link and left the slot empty.
            TAG_CHAIN_REOPEN => c.res[ChainStep::Reopen as usize] = res,
            _ => {
                if let Some(i) = c.end.index() {
                    c.res[i] = res;
                }
                let mut left = c.reopens && c.end == Step::Close && res != 0;
                if c.end == Step::Truncate && std::mem::take(&mut c.rest) {
                    left = c.reopens;
                    let steps = c.rest_steps();
                    if res == 0 && steps.len > 0 {
                        c.end = steps.as_slice()[steps.len - 1];
                        let e = &self.ops[op_slot as usize].state;
                        let fill = Fill {
                            fixed: c.reopens.then_some(slot),
                            raw_fd: e.file.as_ref().map_or(-1, |f| f.as_raw_fd()),
                            pers: c.pers,
                            value: e.value.as_ref().map_or((0, 0), |v| (v.as_ptr() as u64, v.len() as u32)),
                            stat,
                            mask: c.mask,
                            len: 0,
                            reopen: None,
                        };
                        match stage_link(eng, op_slot, gen32, steps.as_slice(), &fill) {
                            Ok(()) => return ReapedFs::None,
                            Err(err) => {
                                c.refused = true;
                                for i in steps.as_slice().iter().filter_map(|s| s.index()) {
                                    c.res[i] = -(err as i32);
                                }
                            }
                        }
                    }
                }
                if left {
                    // Nothing can be done with a slot that will not empty but leave it, and the next reopen into it
                    // drops what it holds (`io_install_fixed_file` in `io_uring/filetable.c`).
                    let _ = eng.ring.clear_file(slot);
                }
            }
        }
        let Some(completed) = self.take_op(TAG_CHAIN_END, op_slot, gen32) else {
            return ReapedFs::None;
        };
        let Completed { waiter, value, .. } = completed;
        // The callback reads the rest out of the chain's entry by the slot ([`FsCore::chain_done`]).
        let mut done = FsDone::failed(Errno::EIO);
        done.result = Ok(op_slot as i32);
        done.value = value;
        match waiter {
            Some(FsWaiter::Embedded { owner, cb, .. }) => ReapedFs::Embedded(
                match cb {
                    Callback::Boxed(cb) => ReapedCb::Boxed(cb),
                    Callback::Parked => ReapedCb::Parked { slot: op_slot },
                    Callback::Staged => match self.cbs.unstage() {
                        Some(cb) => ReapedCb::Boxed(cb),
                        None => return ReapedFs::None,
                    },
                },
                done,
                owner,
            ),
            _ => ReapedFs::None,
        }
    }

    /// What a chain answered, from the [`FsDone`] its reap or its refusal gave and, for a reap, the entry beside its op
    /// slot. `present` has a bit for each [`ChainStep`] the chain had, which a refusal answers for.
    fn chain_done(&self, done: FsDone, present: u8) -> ChainDone {
        let mut out = ChainDone {
            res: [NOT_RAN; 5],
            stat: zeroed_statx(),
            refused: done.was_refused(),
            value: Vec::new(),
        };
        match (done.result, &self.chains) {
            (Ok(op_slot), Some(chains)) if !out.refused => {
                let c = &chains.entries[op_slot as usize];
                out.res = c.res;
                // SAFETY: every link of the chain has posted its last completion, so no statx writes the buffer.
                out.stat = unsafe { *chains.stats[op_slot as usize].get() };
                out.refused = c.refused;
            }
            (result, _) => {
                let err = result.err().unwrap_or(Errno::EIO);
                for (i, res) in out.res.iter_mut().enumerate() {
                    if present & (1 << i) != 0 {
                        *res = -(err as i32);
                    }
                }
            }
        }
        out.value = done.into_value();
        out
    }
}

impl<'a> FsConn<'a> {
    /// Run the steps of `chain` as `who`, as one link of io_uring, and fire `on_done` once its last completion arrives,
    /// with what each step answered ([`ChainDone::step`]) and the statx ([`ChainDone::stat`]).
    ///
    /// A failed step lets every later one run, the fsync and the close among them, but for a failed reopen, which ends
    /// the chain, and a failed `ftruncate`, which keeps the rest from running, so a refused size sets nothing. A reopen
    /// checks as [`FsConn::reopen_proc`] says. A failed statx is seen only as a missing [`ChainDone::stat`].
    ///
    /// It runs only on a ring of a server with
    /// [`fs_chain_slots`](crate::net::server::ServerConfig::fs_chain_slots), and is refused with a marked `EINVAL`
    /// elsewhere, as it is with no step. A full op table refuses it with a marked `EBUSY`, as it refuses any op.
    pub fn chain<F>(&mut self, who: Personality, chain: Chain, on_done: F)
    where
        F: FnOnce(ChainDone, &mut FsConn<'_>) + 'static,
    {
        let present = u8::from(chain.reopen.is_some()) << ChainStep::Reopen as u8
            | u8::from(chain.truncate.is_some()) << ChainStep::Truncate as u8
            | u8::from(chain.set.is_some()) << ChainStep::Set as u8
            | u8::from(chain.sync) << ChainStep::Sync as u8
            | u8::from(chain.reopen.is_some()) << ChainStep::Close as u8;
        let w = self.waiter(move |done: FsDone, conn: &mut FsConn<'_>| {
            let done = conn.fs.chain_done(done, present);
            on_done(done, conn)
        });
        self.fs.submit_chain(self.eng, who.0, chain, w);
    }
}

#[cfg(all(test, not(loom)))]
mod tests;
