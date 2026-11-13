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

mod writes;

mod drains;

mod pump_reads;

mod sweeps;
