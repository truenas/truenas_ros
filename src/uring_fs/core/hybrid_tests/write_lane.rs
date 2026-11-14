use super::*;
use crate::uring_fs::core::offload::WriteSeam;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

/// A fresh file holding `bytes`, and a descriptor of it open for writing.
fn a_written_file(bytes: &[u8]) -> (crate::TempDir, std::path::PathBuf, File) {
    let dir = crate::tempdir().expect("tempdir");
    let path = dir.path().join("f");
    std::fs::write(&path, bytes).unwrap();
    let write = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
    (dir, path, File::from_fd(write.into()))
}

/// A window over `bytes` holding its own share of `hold`.
#[cfg(feature = "net-server")]
fn window_over(bytes: &[u8], hold: &std::sync::Arc<LeaseHold>) -> LeasedWindow {
    LeasedWindow {
        view: LeasedBytes {
            ptr: bytes.as_ptr(),
            len: bytes.len(),
        },
        hold: std::sync::Arc::clone(hold),
    }
}

/// The writes in flight on the lane, the most there ever were, whether any ran on a thread of another pool, and whether
/// the test has let them go.
#[derive(Default)]
struct Counts {
    now: AtomicUsize,
    most: AtomicUsize,
    elsewhere: AtomicBool,
    go: AtomicBool,
}

/// A seam that counts each write in flight on its thread and holds it there until `go` says it may go on or `patience`
/// has passed, so a lane that cannot hold the writes together fails its count rather than hanging.
fn holding(
    counts: &std::sync::Arc<Counts>,
    patience: Duration,
    go: impl Fn(&Counts) -> bool + Send + Sync + 'static,
) -> WriteSeam {
    let c = std::sync::Arc::clone(counts);
    WriteSeam {
        before: Some(std::sync::Arc::new(move || {
            if std::thread::current().name() != Some(WRITE_WORKER) {
                c.elsewhere.store(true, Ordering::SeqCst);
            }
            let now = c.now.fetch_add(1, Ordering::SeqCst) + 1;
            c.most.fetch_max(now, Ordering::SeqCst);
            let began = Instant::now();
            while !go(&c) && began.elapsed() < patience {
                std::thread::sleep(Duration::from_millis(1));
            }
            c.now.fetch_sub(1, Ordering::SeqCst);
        })),
        ..WriteSeam::default()
    }
}

/// What a write answered, its count or its errno, and whether it was marked.
type Verdict = (Option<i32>, Option<Errno>, bool);

/// The [`Verdict`] of `done`.
fn verdict(done: &FsDone) -> Verdict {
    let errno = match done.result() {
        Err(crate::Error::Errno(e)) => Some(e),
        _ => None,
    };
    (done.result().ok(), errno, done.was_refused())
}

/// Two writes to one file are on the lane at once, where io-wq would run them in turn, each on a thread of the lane, so
/// no thread another pool runs jobs on drops `CAP_FSETID`. Each waits on its thread until the other is in flight too,
/// or two seconds pass.
#[test]
fn two_writes_to_one_file_are_in_flight_at_once() {
    let (mut eng, mut fs, _me) = setup();
    let counts = std::sync::Arc::new(Counts::default());
    fs.write_seam = holding(&counts, Duration::from_secs(2), |c| c.most.load(Ordering::SeqCst) >= 2);
    let (_dir, path, file) = a_written_file(b"........");
    let answers: Rc<RefCell<Vec<Option<i32>>>> = Rc::default();
    let a = answers.clone();
    drive(
        &mut eng,
        &mut fs,
        move |c| {
            for (at, bytes) in [(0u64, b"ab"), (4, b"cd")] {
                let a = a.clone();
                c.offload_write_owned(file.clone(), bytes.to_vec(), 0..2, at, RwFlags::empty(), move |d, _| {
                    a.borrow_mut().push(d.result().ok());
                });
            }
        },
        || answers.borrow().len() == 2,
    );
    assert_eq!(*answers.borrow(), [Some(2), Some(2)]);
    assert_eq!(counts.most.load(Ordering::SeqCst), 2, "the writes ran one at a time");
    assert!(!counts.elsewhere.load(Ordering::SeqCst), "a write ran off the lane");
    assert_eq!(std::fs::read(&path).unwrap(), b"ab..cd..");
}

/// The lane grows past its floor to its ceiling while its writes wait, and no further. Three writes wait until the
/// test lets them go, on a lane of one thread that may grow to two, and the lane grows only at the deadline its flush
/// gives the loop.
#[test]
fn the_lane_grows_to_its_ceiling_and_no_further() {
    let (mut eng, mut fs, _me) = setup();
    fs.set_write_bounds(OffloadBounds { floor: 1, ceiling: 2 });
    let counts = std::sync::Arc::new(Counts::default());
    fs.write_seam = holding(&counts, Duration::from_secs(10), |c| c.go.load(Ordering::SeqCst));
    let (_dir, _path, file) = a_written_file(b"");
    let done = Rc::new(Cell::new(0usize));
    let d = done.clone();
    let seen = Cell::new(None);
    let began = Instant::now();
    drive(
        &mut eng,
        &mut fs,
        move |c| {
            for at in 0..3u64 {
                let d = d.clone();
                c.offload_write_owned(file.clone(), vec![b'x'], 0..1, at, RwFlags::empty(), move |_, _| {
                    d.set(d.get() + 1);
                });
            }
        },
        || {
            if seen.get().is_none() && began.elapsed() > Duration::from_millis(300) {
                seen.set(Some(counts.most.load(Ordering::SeqCst)));
                counts.go.store(true, Ordering::SeqCst);
            }
            done.get() == 3
        },
    );
    assert_eq!(
        seen.get(),
        Some(2),
        "the writes in flight at once, on a lane of one to two threads"
    );
}

/// A lane with no thread refuses a write of storage and one of a window with a marked `EAGAIN` on a later pass, not
/// inside the call, writes nothing, gives the storage back and lets the window's share go, since a write never runs on
/// the loop.
#[test]
fn a_lane_with_no_thread_refuses_a_write_with_a_marked_eagain() {
    let (mut eng, mut fs, _me) = setup();
    fs.write.back_off();
    let (_dir, path, file) = a_written_file(b"bytes");
    let buf = b"owned".to_vec();
    let storage = buf.as_ptr();
    #[cfg(feature = "net-server")]
    let (bytes, hold) = (b"window".to_vec(), std::sync::Arc::new(LeaseHold::detached(9)));
    #[cfg(feature = "net-server")]
    let window = window_over(&bytes, &hold);
    let answers: Rc<RefCell<Vec<Verdict>>> = Rc::default();
    let back = Rc::new(Cell::new(std::ptr::null()));
    let (a, a2, b) = (answers.clone(), answers.clone(), back.clone());
    #[cfg(feature = "net-server")]
    let a3 = answers.clone();
    #[cfg(feature = "net-server")]
    let want = 2;
    #[cfg(not(feature = "net-server"))]
    let want = 1;
    drive(
        &mut eng,
        &mut fs,
        move |c| {
            c.offload_write_owned(file.clone(), buf, 0..5, 0, RwFlags::empty(), move |d, _| {
                a.borrow_mut().push(verdict(&d));
                b.set(d.into_value().as_ptr());
            });
            #[cfg(feature = "net-server")]
            c.offload_write_window(file, window, 0, RwFlags::empty(), move |d, _| {
                a3.borrow_mut().push(verdict(&d));
            });
            assert!(a2.borrow().is_empty(), "answered inside the call");
        },
        || answers.borrow().len() == want,
    );
    let eagain = (None, Some(Errno::EAGAIN), true);
    assert!(answers.borrow().iter().all(|a| *a == eagain), "{:?}", answers.borrow());
    assert_eq!(back.get(), storage, "the storage came back");
    assert_eq!(std::fs::read(&path).unwrap(), b"bytes", "nothing written");
    #[cfg(feature = "net-server")]
    assert_eq!(std::sync::Arc::strong_count(&hold), 1, "the window's share went");
}

/// A lane thread that cannot drop `CAP_FSETID` answers the errno `capset` gave, unmarked, and writes nothing, so it
/// never writes with the capability. The failure is forced, since a real one needs a seccomp filter or an LSM.
#[test]
fn a_thread_that_cannot_drop_fsetid_writes_nothing() {
    let (mut eng, mut fs, _me) = setup();
    fs.write_seam.drop_fails = true;
    let (_dir, path, file) = a_written_file(b"bytes");
    let buf = b"owned".to_vec();
    let storage = buf.as_ptr();
    let answer: Rc<RefCell<Option<Verdict>>> = Rc::default();
    let back = Rc::new(Cell::new(std::ptr::null()));
    let (a, b) = (answer.clone(), back.clone());
    drive(
        &mut eng,
        &mut fs,
        move |c| {
            c.offload_write_owned(file, buf, 0..5, 0, RwFlags::empty(), move |d, _| {
                *a.borrow_mut() = Some(verdict(&d));
                b.set(d.into_value().as_ptr());
            });
        },
        || answer.borrow().is_some(),
    );
    assert_eq!(*answer.borrow(), Some((None, Some(Errno::EPERM), false)));
    assert_eq!(back.get(), storage, "the storage came back");
    assert_eq!(std::fs::read(&path).unwrap(), b"bytes", "nothing written");
}

/// A short write of storage answers its count with the storage back, and one of a window fails with `EIO` and gives its
/// count beside it, as the ring's writes answer them. The counts are made up, since a thread cannot be made to write
/// short without a limit on the whole process.
#[test]
fn a_short_write_answers_as_the_rings_does() {
    let buf = vec![7u8; 8192];
    let storage = buf.as_ptr();
    let done = FsDone::owned_written(Ok(4096), buf);
    assert_eq!(done.result().ok(), Some(4096), "a short write of storage is its count");
    let back = done.into_value();
    assert_eq!((back.as_ptr(), back.len()), (storage, 8192));
    #[cfg(feature = "net-server")]
    for (written, res, count) in [
        (Ok(4096), Err(Errno::EIO), Some(4096)),
        (Ok(8192), Ok(8192), None),
        (Err(Errno::ENOSPC), Err(Errno::ENOSPC), None),
    ] {
        let done = FsDone::window_written(written, 8192);
        assert_eq!((done.raw_result(), done.short_count()), (res, count));
    }
}

/// A window is written where it asks, and its share goes once the write has returned and its completion is taken, so
/// the pool gets the buffer back then.
#[cfg(feature = "net-server")]
#[test]
fn a_window_is_written_and_its_buffer_goes_home_after() {
    let (mut eng, mut fs, _me) = setup();
    let (_dir, path, file) = a_written_file(b"..........");
    let bytes = b"window".to_vec();
    let hold = std::sync::Arc::new(LeaseHold::new(9, fs.lease_returns(&eng.shared)));
    let window = window_over(&bytes, &hold);
    drop(hold);
    let answer: Rc<RefCell<Option<Verdict>>> = Rc::default();
    let a = answer.clone();
    drive(
        &mut eng,
        &mut fs,
        move |c| {
            c.offload_write_window(file, window, 2, RwFlags::empty(), move |d, _| {
                *a.borrow_mut() = Some(verdict(&d));
            });
        },
        || answer.borrow().is_some(),
    );
    assert_eq!(*answer.borrow(), Some((Some(6), None, false)));
    assert_eq!(std::fs::read(&path).unwrap(), b"..window..");
    assert_eq!(fs.take_pool_releases(), [9], "the buffer went home");
}
