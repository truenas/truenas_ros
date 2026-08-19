//! Layer 0 callback substrate - a self-contained, compiling design probe.
//!
//! A completion-callback model for the FS reactor on the io_uring net-server
//! base, distilled to the part that actually stresses the borrow checker:
//! `submit(op, ReqKey, Callback)`, a drain loop firing each callback with
//! `(&Completion, &mut ReqState, &mut Staging)`, and a `Staging` buffer with
//! `linked_run` (IOSQE_IO_LINK) for the atomic-PUT tail.
//!
//! NOT wired to the real reactor. The "ring" here is a synchronous mock that
//! runs each op with one real syscall against a temp dir, so the
//! ownership/borrow structure is exactly what the real reactor would have,
//! while the demo genuinely creates files (and shows link fail-fast leaving no
//! half-written object behind). No futures anywhere - a request's terminal
//! action is a plain boxed closure; the callback layer needs no async runtime.
//!
//! Run: `cargo run --example fs_callback_layer0`

use std::collections::VecDeque;
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::RawFd;

// ---- identity: OpToken rides *in* the SQE/CQE `user_data` field -------------

/// Our op identity: packs (generation, slot). This is the value we put in the
/// ABI `user_data` field; naming it `OpToken` keeps the logical identity
/// distinct from that field.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
struct OpToken(u64);
impl OpToken {
    fn pack(generation: u32, slot: u32) -> Self {
        OpToken(((generation as u64) << 32) | slot as u64)
    }
    fn slot(self) -> u32 {
        self.0 as u32
    }
    fn generation(self) -> u32 {
        (self.0 >> 32) as u32
    }
}

/// The request-state key (pyos's `private_data`, as a slab index).
type ReqKey = usize;

// ---- what a callback receives ----------------------------------------------

#[derive(Debug)]
struct Completion {
    token: OpToken,
    res: i32,
    out: OpOutput,
}

#[allow(dead_code)] // Bytes payload is illustrative; not read in these demos
#[derive(Debug)]
enum OpOutput {
    Fd(RawFd),
    Bytes(u32),
    IsDir(bool),
    None,
}

// ---- ops (each becomes one real syscall in the mock) -----------------------

enum OpSpec {
    OpenAt {
        dir: RawFd,
        path: CString,
        flags: i32,
        mode: u32,
    },
    StatIsDir {
        dir: RawFd,
        path: CString,
    },
    Write {
        fd: RawFd,
        data: Vec<u8>,
    },
    Fsync {
        fd: RawFd,
    },
    Rename {
        olddir: RawFd,
        old: CString,
        newdir: RawFd,
        new: CString,
    },
    Close {
        fd: RawFd,
    },
    Unlink {
        dir: RawFd,
        path: CString,
    },
}

// ---- staging: the callback stages follow-ups; the reactor flushes them ------

type Callback = Box<dyn FnOnce(&Completion, &mut ReqState, &mut Staging)>;

/// A request's terminal side effect: its result, delivered to the caller.
type Done = Box<dyn FnOnce(Result<String, i32>)>;

struct Staged {
    op: OpSpec,
    key: ReqKey,
    cb: Callback,
    link_next: bool,
}

#[derive(Default)]
struct Staging {
    runs: Vec<Staged>,
}

impl Staging {
    /// One standalone op.
    fn one(&mut self, op: OpSpec, key: ReqKey, cb: Callback) {
        self.runs.push(Staged {
            op,
            key,
            cb,
            link_next: false,
        });
    }

    /// A kernel-linked run (IOSQE_IO_LINK across all but the last): ordered and
    /// fail-fast - the tail is cancelled if any op fails. This is the atomic
    /// write -> fsync -> rename -> dirfsync tail.
    fn linked_run(&mut self, items: Vec<(OpSpec, Callback)>, key: ReqKey) {
        let n = items.len();
        for (i, (op, cb)) in items.into_iter().enumerate() {
            self.runs.push(Staged {
                op,
                key,
                cb,
                link_next: i + 1 < n,
            });
        }
    }
}

// ---- per-request state, owned by the reactor, reached by ReqKey ------------

struct ReqState {
    key: ReqKey,
    dir: RawFd,
    tmp_fd: RawFd,
    tmp_path: CString,
    final_path: CString,
    body: Vec<u8>,
    failed: bool,
    /// Terminal side effect - a plain closure, NOT a future.
    done: Option<Done>,
}
impl ReqState {
    fn finish(&mut self, r: Result<String, i32>) {
        if let Some(f) = self.done.take() {
            f(r);
        }
    }
    fn fail(&mut self, res: i32) {
        self.failed = true;
        self.finish(Err(res));
    }
}

// ---- the op-slot table: OpToken identity + generation guard ----------------

struct OpSlot {
    generation: u32,
    used: bool,
    cb: Option<Callback>,
    key: ReqKey,
}

#[derive(Default)]
struct Core {
    slots: Vec<OpSlot>,
    free: Vec<u32>,
    cq: VecDeque<Completion>, // the mock completion queue
}
impl Core {
    fn alloc(&mut self, key: ReqKey, cb: Callback) -> OpToken {
        let slot = if let Some(s) = self.free.pop() {
            s
        } else {
            self.slots.push(OpSlot {
                generation: 0,
                used: false,
                cb: None,
                key: 0,
            });
            (self.slots.len() - 1) as u32
        };
        let e = &mut self.slots[slot as usize];
        e.generation = e.generation.wrapping_add(1); // consecutive uses never share a token
        e.used = true;
        e.cb = Some(cb);
        e.key = key;
        OpToken::pack(e.generation, slot)
    }

    /// Retrieve + recycle the slot for a completion. A stale/foreign token
    /// (wrong generation, or already reaped) returns None and is inert - the
    /// property the routing/close-last fuzzer checks.
    fn take_op(&mut self, tok: OpToken) -> Option<(Callback, ReqKey)> {
        let e = self.slots.get_mut(tok.slot() as usize)?;
        if !e.used || e.generation != tok.generation() {
            return None;
        }
        e.used = false;
        let cb = e.cb.take()?;
        let key = e.key;
        self.free.push(tok.slot());
        Some((cb, key))
    }
}

// ---- the reactor: core + request slab + staging ----------------------------

#[derive(Default)]
struct Reactor {
    core: Core,
    reqs: Vec<ReqState>, // a real one uses a slab with generation-guarded keys
    staging: Staging,
}
impl Reactor {
    fn begin(&mut self, mut st: ReqState) -> ReqKey {
        let key = self.reqs.len();
        st.key = key;
        self.reqs.push(st);
        key
    }

    /// Execute staged ops into completions. A linked run runs in order and
    /// severs its tail (-ECANCELED) on the first failure - the mock's stand-in
    /// for IOSQE_IO_LINK.
    fn flush(&mut self) {
        let runs = std::mem::take(&mut self.staging.runs);
        let mut severed = false;
        for Staged {
            op,
            key,
            cb,
            link_next,
        } in runs
        {
            let token = self.core.alloc(key, cb);
            let (res, out) = if severed {
                (-libc::ECANCELED, OpOutput::None)
            } else {
                execute(&op)
            };
            if res < 0 {
                severed = true; // sever the rest of this run
            }
            self.core.cq.push_back(Completion { token, res, out });
            if !link_next {
                severed = false; // run boundary resets fail-fast
            }
        }
    }

    /// Fire each completion's callback with ONLY its own request state + the
    /// stage buffer. `reqs` and `staging` are disjoint fields, so the reactor
    /// hands out &mut to each at once - the borrow split that makes this legal.
    fn drain(&mut self) {
        while let Some(comp) = self.core.cq.pop_front() {
            let Some((cb, key)) = self.core.take_op(comp.token) else {
                continue;
            };
            let state = &mut self.reqs[key];
            let staging = &mut self.staging;
            // A panicking callback must not abort the drain (pyos reports it
            // unraisable); catch_unwind is the equivalent.
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(
                move || cb(&comp, state, staging),
            ));
        }
    }

    fn run_until_idle(&mut self) {
        loop {
            self.flush();
            if self.core.cq.is_empty() {
                break;
            }
            self.drain();
        }
    }
}

// ---- the op executor: one real syscall per op ------------------------------

fn execute(op: &OpSpec) -> (i32, OpOutput) {
    // SAFETY: every fd/path handed to these calls is live for the call's
    // duration (owned by the ReqState / OpSpec the caller still holds).
    unsafe {
        match op {
            OpSpec::OpenAt {
                dir,
                path,
                flags,
                mode,
            } => {
                let fd = libc::openat(
                    *dir,
                    path.as_ptr(),
                    *flags,
                    *mode as libc::c_uint,
                );
                if fd < 0 {
                    errno_out()
                } else {
                    (fd, OpOutput::Fd(fd))
                }
            }
            OpSpec::StatIsDir { dir, path } => {
                let mut stx: libc::stat = std::mem::zeroed();
                if libc::fstatat(*dir, path.as_ptr(), &mut stx, 0) < 0 {
                    errno_out()
                } else {
                    let is_dir = (stx.st_mode & libc::S_IFMT) == libc::S_IFDIR;
                    (0, OpOutput::IsDir(is_dir))
                }
            }
            OpSpec::Write { fd, data } => {
                let n = libc::write(
                    *fd,
                    data.as_ptr() as *const libc::c_void,
                    data.len(),
                );
                if n < 0 {
                    errno_out()
                } else {
                    (n as i32, OpOutput::Bytes(n as u32))
                }
            }
            OpSpec::Fsync { fd } => io_result(libc::fsync(*fd)),
            OpSpec::Rename {
                olddir,
                old,
                newdir,
                new,
            } => io_result(libc::renameat(
                *olddir,
                old.as_ptr(),
                *newdir,
                new.as_ptr(),
            )),
            OpSpec::Close { fd } => io_result(libc::close(*fd)),
            OpSpec::Unlink { dir, path } => {
                io_result(libc::unlinkat(*dir, path.as_ptr(), 0))
            }
        }
    }
}
fn io_result(r: i32) -> (i32, OpOutput) {
    if r < 0 {
        errno_out()
    } else {
        (0, OpOutput::None)
    }
}
fn errno_out() -> (i32, OpOutput) {
    let e = std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(libc::EIO);
    (-e, OpOutput::None)
}

// ---- handlers, written as callback chains (no futures) ---------------------

/// Atomic durable PUT: open tmp (a round-trip for the fd), then the ordered
/// write -> fsync -> rename -> dirfsync tail as one linked run.
fn put(
    rt: &mut Reactor,
    dir: RawFd,
    tmp: &str,
    fin: &str,
    body: Vec<u8>,
    done: Done,
) {
    let key = rt.begin(ReqState {
        key: 0,
        dir,
        tmp_fd: -1,
        tmp_path: cstr(tmp),
        final_path: cstr(fin),
        body,
        failed: false,
        done: Some(done),
    });
    rt.staging.one(
        OpSpec::OpenAt {
            dir,
            path: cstr(tmp),
            flags: libc::O_CREAT | libc::O_WRONLY | libc::O_TRUNC,
            mode: 0o600,
        },
        key,
        Box::new(on_tmp_open),
    );
}

fn on_tmp_open(c: &Completion, st: &mut ReqState, stage: &mut Staging) {
    match c.out {
        OpOutput::Fd(fd) if c.res >= 0 => {
            st.tmp_fd = fd;
            // Every input is known now: this fd, and the static tmp/final paths
            // + parent dirfd. No data forwarding across a link -> plain fds
            // suffice, no fixed-file table needed.
            let items: Vec<(OpSpec, Callback)> = vec![
                (
                    OpSpec::Write {
                        fd,
                        data: std::mem::take(&mut st.body),
                    },
                    Box::new(on_step),
                ),
                (OpSpec::Fsync { fd }, Box::new(on_step)),
                (
                    OpSpec::Rename {
                        olddir: st.dir,
                        old: st.tmp_path.clone(),
                        newdir: st.dir,
                        new: st.final_path.clone(),
                    },
                    Box::new(on_step),
                ),
                (OpSpec::Fsync { fd: st.dir }, Box::new(on_committed)),
            ];
            stage.linked_run(items, st.key);
        }
        _ => st.fail(c.res),
    }
}

fn on_step(c: &Completion, st: &mut ReqState, stage: &mut Staging) {
    // The first failure finalizes + cleans up; the linked tail's -ECANCELED
    // completions land here too but are ignored (st.failed already set).
    if c.res < 0 && !st.failed {
        st.failed = true;
        st.finish(Err(c.res));
        stage.one(
            OpSpec::Unlink {
                dir: st.dir,
                path: st.tmp_path.clone(),
            },
            st.key,
            Box::new(ignore),
        );
        if st.tmp_fd >= 0 {
            stage.one(
                OpSpec::Close { fd: st.tmp_fd },
                st.key,
                Box::new(ignore),
            );
        }
    }
}

fn on_committed(c: &Completion, st: &mut ReqState, stage: &mut Staging) {
    if !st.failed {
        let r = if c.res >= 0 {
            Ok("committed".to_string())
        } else {
            Err(c.res)
        };
        st.failed = r.is_err();
        st.finish(r);
        if st.tmp_fd >= 0 {
            stage.one(
                OpSpec::Close { fd: st.tmp_fd },
                st.key,
                Box::new(ignore),
            );
        }
    }
}

/// stat -> (if a regular file) open. A directory finishes without opening.
fn stat_then_open(rt: &mut Reactor, dir: RawFd, name: &str, done: Done) {
    let key = rt.begin(ReqState {
        key: 0,
        dir,
        tmp_fd: -1,
        tmp_path: cstr(""),
        final_path: cstr(name),
        body: Vec::new(),
        failed: false,
        done: Some(done),
    });
    rt.staging.one(
        OpSpec::StatIsDir {
            dir,
            path: cstr(name),
        },
        key,
        Box::new(on_stat),
    );
}

fn on_stat(c: &Completion, st: &mut ReqState, stage: &mut Staging) {
    match c.out {
        OpOutput::IsDir(true) => {
            st.finish(Ok("is a directory (not opened)".to_string()))
        }
        OpOutput::IsDir(false) => stage.one(
            OpSpec::OpenAt {
                dir: st.dir,
                path: st.final_path.clone(),
                flags: libc::O_RDONLY,
                mode: 0,
            },
            st.key,
            Box::new(on_open),
        ),
        _ => st.fail(c.res),
    }
}

fn on_open(c: &Completion, st: &mut ReqState, stage: &mut Staging) {
    match c.out {
        OpOutput::Fd(fd) if c.res >= 0 => {
            st.finish(Ok(format!("opened fd {}", fd)));
            stage.one(OpSpec::Close { fd }, st.key, Box::new(ignore));
        }
        _ => st.fail(c.res),
    }
}

fn ignore(_c: &Completion, _st: &mut ReqState, _stage: &mut Staging) {}

// ---- driver ----------------------------------------------------------------

fn cstr(s: &str) -> CString {
    CString::new(s).unwrap()
}

fn main() {
    let base =
        std::env::temp_dir().join(format!("fs_cb_demo_{}", std::process::id()));
    std::fs::create_dir_all(&base).unwrap();
    let dir = open_dir(&base);

    let mut rt = Reactor::default();

    println!("== Demo 1: atomic PUT (success) ==");
    put(
        &mut rt,
        dir,
        "obj1.tmp",
        "obj1",
        b"hello atomic world\n".to_vec(),
        Box::new(|r| println!("  [PUT obj1]      -> {:?}", r)),
    );
    rt.run_until_idle();
    report_file(&base, "obj1");
    report_absent(&base, "obj1.tmp");

    println!(
        "== Demo 2: atomic PUT (rename fails -> fail-fast, no half-write) =="
    );
    put(
        &mut rt,
        dir,
        "obj2.tmp",
        "nope/obj2",
        b"should never be published\n".to_vec(),
        Box::new(|r| println!("  [PUT nope/obj2] -> {:?}", r)),
    );
    rt.run_until_idle();
    report_absent(&base, "obj2.tmp"); // cleaned up
    report_absent(&base, "nope"); // never created

    println!("== Demo 3: stat -> open chain ==");
    stat_then_open(
        &mut rt,
        dir,
        "obj1",
        Box::new(|r| println!("  [open obj1]     -> {:?}", r)),
    );
    stat_then_open(
        &mut rt,
        dir,
        ".",
        Box::new(|r| println!("  [open .]        -> {:?}", r)),
    );
    stat_then_open(
        &mut rt,
        dir,
        "missing",
        Box::new(|r| println!("  [open missing]  -> {:?}", r)),
    );
    rt.run_until_idle();

    // SAFETY: `dir` is a live fd we opened above and no longer use.
    unsafe {
        libc::close(dir);
    }
    let _ = std::fs::remove_dir_all(&base);
}

fn open_dir(p: &std::path::Path) -> RawFd {
    let c = CString::new(p.as_os_str().as_bytes()).unwrap();
    // SAFETY: `c` is a valid NUL-terminated path live for the call.
    let fd =
        unsafe { libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY) };
    assert!(
        fd >= 0,
        "open dir {:?}: {}",
        p,
        std::io::Error::last_os_error()
    );
    fd
}

fn report_file(base: &std::path::Path, name: &str) {
    match std::fs::read(base.join(name)) {
        Ok(b) => println!(
            "  file {:?} present, {} bytes: {:?}",
            name,
            b.len(),
            String::from_utf8_lossy(&b)
        ),
        Err(e) => println!("  file {:?} MISSING ({})", name, e),
    }
}
fn report_absent(base: &std::path::Path, name: &str) {
    println!(
        "  {:?} present? {}  (expected: false)",
        name,
        base.join(name).exists()
    );
}
