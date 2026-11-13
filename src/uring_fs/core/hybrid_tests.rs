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
    // A timer bounds every block, so a missed wake fails at the deadline below instead of hanging. Its tag is unused in
    // the fs domain. Re-armed only when its completion returns, and every caller builds a fresh `Engine`, so a stale
    // completion is never reaped.
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
                // The real delivery functions, not a copy of their bodies, which would miss whatever they grow.
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

/// Run `f` with this thread's panic printing silenced, a shorthand for `quiet_panics_on_this_thread`.
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
///
/// The file is made with no writer. The kernel refuses a read lease while any process holds the file open for
/// writing, and a test that forks lends its child a copy of whatever writer is open at that moment.
fn a_file() -> (crate::TempDir, std::path::PathBuf, File) {
    use std::os::unix::fs::OpenOptionsExt;
    let dir = crate::tempdir().expect("tempdir");
    let path = dir.path().join("f");
    let read = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CREAT)
        .mode(0o644)
        .open(&path)
        .unwrap();
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
    // A fork elsewhere in the process may hold a copy of the writer for a moment longer, so the lease is asked again
    // while the answer is EAGAIN, up to a deadline.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let id = loop {
        match c.file_lease(&file) {
            Err(crate::Error::Errno(Errno::EAGAIN)) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            other => break other.expect("a lease once the writer went"),
        }
    };
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

mod chains;

mod offload;

mod listing;
