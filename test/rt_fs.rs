//! Integration tests for the tokio-hybrid runtime (`rt::FsRuntime` /
//! `rt::FsRt`): async filesystem ops from multi-threaded tokio tasks against
//! the one process-wide loop, mixed with blocking [`FsHandle`] callers on
//! the same loop.
//!
//! Like `test/async_fs.rs`, these **skip** (return early) when io_uring is
//! unavailable, and `TRUENAS_ROS_REQUIRE_IO_URING=1` turns that skip into a
//! hard failure.

#![cfg(all(target_os = "linux", feature = "rt-tokio"))]

use std::ffi::CString;
use std::future::Future;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use truenas_ros::async_fs::{
    Anchor, AsUser, CredBroker, FsConfig, Leaf, Personality,
};
use truenas_ros::rt::{FsRt, FsRuntime, FsRuntimeBuilder};
use truenas_ros::sync_fs::{AtFlags, Mode, OFlag, OpenHow, StatxMask};
use truenas_ros::{Errno, Error};

fn leaf(name: &str) -> Leaf<'_> {
    Leaf::new(name).expect("valid leaf")
}

/// Errors that mean "io_uring is unavailable here" — an environmental skip.
fn should_skip(e: &Error) -> bool {
    let unavailable = matches!(
        e,
        Error::Errno(Errno::EPERM | Errno::ENOSYS | Errno::EACCES)
    );
    if unavailable {
        assert!(
            std::env::var_os("TRUENAS_ROS_REQUIRE_IO_URING").is_none(),
            "TRUENAS_ROS_REQUIRE_IO_URING set but io_uring unavailable: {e}"
        );
    }
    unavailable
}

fn rdonly() -> OpenHow {
    OpenHow::new().flags(OFlag::O_RDONLY)
}

fn creat_rw() -> OpenHow {
    OpenHow::new()
        .flags(OFlag::O_CREAT | OFlag::O_RDWR)
        .mode(Mode::from_bits_truncate(0o600))
}

fn mkfifo(dir: &Path, name: &str) {
    let p = dir.join(name);
    let c = CString::new(p.as_os_str().as_bytes()).unwrap();
    // SAFETY: valid NUL-terminated path.
    let rc = unsafe { libc::mkfifo(c.as_ptr(), 0o600) };
    assert_eq!(rc, 0, "mkfifo failed: {}", std::io::Error::last_os_error());
}

fn tokio_rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("tokio runtime")
}

/// Build an `FsRuntime` over a fresh tempdir, register a self personality,
/// run `client` on a multi-thread tokio runtime, then shut the loop down and
/// assert it exits cleanly.
fn with_rt<Fut>(
    cfg: FsConfig,
    client: impl FnOnce(FsRuntime, Personality, PathBuf) -> Fut,
) where
    Fut: Future<Output = ()>,
{
    let dir = tempfile::tempdir().expect("tempdir");
    let builder = match FsRuntimeBuilder::new(cfg) {
        Ok(b) => b,
        Err(e) => {
            if should_skip(&e) {
                return;
            }
            panic!("FsRuntimeBuilder::new: {e}");
        }
    };
    let me = builder.register_self().expect("register_self");
    let rt = builder.start().expect("start loop thread");
    let trt = tokio_rt();
    trt.block_on(client(rt.clone(), me, dir.path().to_path_buf()));
    drop(trt); // no task still holds a handle when the loop is joined
    rt.shutdown().expect("loop exits cleanly");
}

/// Retry an async open while the loop finishes an asynchronous reclaim
/// (orphan close), mirroring the blocking suite's `eventually`.
async fn reopen_eventually(
    fs: &FsRt,
    me: Personality,
    anchor: &Anchor,
    name: &str,
) -> truenas_ros::async_fs::FixedFile {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match fs.open(me, anchor, name, rdonly()).await {
            Ok(f) => return f,
            Err(Error::Errno(Errno::ENFILE)) => {
                assert!(
                    Instant::now() < deadline,
                    "slot still not reclaimed after 2s"
                );
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            Err(e) => panic!("unexpected error: {e}"),
        }
    }
}

// ---------------------------------------------------------------------------

#[test]
fn async_round_trip_write_fsync_read_statx() {
    with_rt(FsConfig::default(), |rt, me, dir| async move {
        let fs = rt.rt();
        let anchor = Anchor::open(dir.as_path()).unwrap();

        let payload: Vec<u8> = (0..16384u32).map(|i| i as u8).collect();
        let f = fs.open(me, &anchor, "data.bin", creat_rw()).await.unwrap();
        let (n, _bufs) = fs.pwritev(me, &f, vec![payload.clone()], 0).await;
        assert_eq!(n.unwrap(), payload.len());
        fs.fsync(me, &f).await.unwrap();
        fs.close(f).await.unwrap();

        // Fresh open + scattered read: bytes round-trip through the ring.
        let f = fs.open(me, &anchor, "data.bin", rdonly()).await.unwrap();
        let half = payload.len() / 2;
        let (n, bufs) = fs
            .preadv(
                me,
                &f,
                vec![vec![0u8; half], vec![0u8; payload.len() - half]],
                0,
            )
            .await;
        assert_eq!(n.unwrap(), payload.len());
        assert_eq!(&bufs[0], &payload[..half]);
        assert_eq!(&bufs[1], &payload[half..]);
        fs.close(f).await.unwrap();

        // Path metadata through the same async surface.
        let st = fs
            .statx(
                me,
                &anchor,
                leaf("data.bin"),
                AtFlags::empty(),
                StatxMask::BASIC_STATS,
            )
            .await
            .expect("statx");
        assert_eq!(st.size(), payload.len() as u64);
        let st = fs
            .statx_anchor(me, &anchor, AtFlags::empty(), StatxMask::BASIC_STATS)
            .await
            .expect("statx anchor");
        assert!(st.is_dir());

        // Directory-entry ops: mkdir → verify → rmdir; rename a file.
        fs.mkdirat(me, &anchor, leaf("sub"), Mode::from_bits_truncate(0o755))
            .await
            .unwrap();
        assert!(dir.join("sub").is_dir());
        fs.rmdirat(me, &anchor, leaf("sub")).await.unwrap();
        assert!(!dir.join("sub").exists());
        fs.renameat(
            me,
            &anchor,
            leaf("data.bin"),
            &anchor,
            leaf("renamed.bin"),
            truenas_ros::sync_fs::RenameFlags::empty(),
        )
        .await
        .unwrap();
        assert!(dir.join("renamed.bin").exists());
        fs.unlinkat(me, &anchor, leaf("renamed.bin")).await.unwrap();
        assert!(!dir.join("renamed.bin").exists());
    });
}

#[test]
fn mt_storm_async_tasks_mixed_with_blocking_handles() {
    let cfg = FsConfig {
        files: 32,
        ops: 64,
        ..FsConfig::default()
    };
    with_rt(cfg, |rt, me, dir| async move {
        let anchor = Anchor::open(dir.as_path()).unwrap();
        let mut joins = Vec::new();

        // 8 async tasks, each cycling open→pwritev→fsync→close→reopen→preadv
        // on its own file — every worker thread submits to the one loop.
        for i in 0..8usize {
            let fs = rt.rt();
            let anchor = anchor.clone();
            joins.push(tokio::spawn(async move {
                for round in 0..4usize {
                    let name = format!("t{i}.bin");
                    let payload = vec![(i * 8 + round) as u8 + 1; 4096];
                    let f = fs
                        .open(me, &anchor, name.as_str(), creat_rw())
                        .await
                        .unwrap();
                    let (n, _b) =
                        fs.pwritev(me, &f, vec![payload.clone()], 0).await;
                    assert_eq!(n.unwrap(), payload.len());
                    fs.fsync(me, &f).await.unwrap();
                    fs.close(f).await.unwrap();

                    let f = fs
                        .open(me, &anchor, name.as_str(), rdonly())
                        .await
                        .unwrap();
                    let (n, bufs) =
                        fs.preadv(me, &f, vec![vec![0u8; 4096]], 0).await;
                    assert_eq!(n.unwrap(), payload.len());
                    assert_eq!(bufs[0], payload);
                    fs.close(f).await.unwrap();
                }
            }));
        }

        // 2 blocking FsHandle legs on the same loop, via spawn_blocking —
        // the mixed-caller contract.
        for i in 0..2usize {
            let h = rt.handle();
            let anchor = anchor.clone();
            joins.push(tokio::spawn(async move {
                tokio::task::spawn_blocking(move || {
                    for round in 0..4usize {
                        let name = format!("b{i}.bin");
                        let payload = vec![(100 + i * 4 + round) as u8; 2048];
                        let f = h
                            .open(me, &anchor, name.as_str(), creat_rw())
                            .unwrap();
                        let (n, _b) =
                            h.pwritev(me, &f, vec![payload.clone()], 0);
                        assert_eq!(n.unwrap(), payload.len());
                        let (n, bufs) =
                            h.preadv(me, &f, vec![vec![0u8; 2048]], 0);
                        assert_eq!(n.unwrap(), payload.len());
                        assert_eq!(bufs[0], payload);
                        h.close(f).unwrap();
                    }
                })
                .await
                .unwrap();
            }));
        }

        for j in joins {
            j.await.expect("storm task");
        }
    });
}

#[test]
fn future_drop_mid_op_cancels_and_reclaims() {
    let cfg = FsConfig {
        files: 1,
        ..FsConfig::default()
    };
    with_rt(cfg, |rt, me, dir| async move {
        let fs = rt.rt();
        mkfifo(&dir, "fifo");
        std::fs::write(dir.join("a"), b"a").unwrap();
        let anchor = Anchor::open(dir.as_path()).unwrap();

        // O_RDWR on a FIFO keeps a writer attached, so a read with no data
        // parks in the kernel — an op genuinely in flight.
        let how = OpenHow::new().flags(OFlag::O_RDWR);
        let f = fs.open(me, &anchor, "fifo", how).await.expect("open fifo");

        // Start the read, let it park, then DROP the future: the op is
        // abandoned, not aborted — its buffers stay owned by the op table
        // until the (cancelled) CQE reaps.
        {
            let read = fs.preadv(me, &f, vec![vec![0u8; 8]], 0);
            tokio::pin!(read);
            let raced =
                tokio::time::timeout(Duration::from_millis(50), &mut read)
                    .await;
            assert!(raced.is_err(), "parked read must still be pending");
            // `read` drops here.
        }

        // Close cancels the in-flight read first (close-last), and the
        // pool's single slot becomes reusable — observably.
        fs.close(f).await.expect("close cancels the parked read");
        let f = reopen_eventually(&fs, me, &anchor, "a").await;
        fs.close(f).await.unwrap();
    });
}

#[test]
fn fixedfile_drop_from_task_reclaims_slot() {
    let cfg = FsConfig {
        files: 1,
        ..FsConfig::default()
    };
    with_rt(cfg, |rt, me, dir| async move {
        let fs = rt.rt();
        std::fs::write(dir.join("a"), b"a").unwrap();
        let anchor = Anchor::open(dir.as_path()).unwrap();

        let fs2 = fs.clone();
        let anchor2 = anchor.clone();
        tokio::spawn(async move {
            let f = fs2.open(me, &anchor2, "a", rdonly()).await.unwrap();
            drop(f); // orphan close injected from a worker thread
        })
        .await
        .unwrap();

        let f = reopen_eventually(&fs, me, &anchor, "a").await;
        fs.close(f).await.unwrap();
    });
}

#[test]
fn backpressure_queues_async_submitters_instead_of_ebusy() {
    // ops=2 is the minimum table; without the semaphore a burst of
    // concurrent async writes would race the tiny table and some would fail
    // EBUSY. With it, submitters queue and every op succeeds.
    let cfg = FsConfig {
        files: 4,
        ops: 2,
        ..FsConfig::default()
    };
    with_rt(cfg, |rt, me, dir| async move {
        let fs = rt.rt();
        let anchor = Anchor::open(dir.as_path()).unwrap();
        let f = std::sync::Arc::new(
            fs.open(me, &anchor, "f", creat_rw()).await.unwrap(),
        );

        let mut joins = Vec::new();
        for i in 0..8usize {
            let fs = fs.clone();
            let f = f.clone();
            let payload = vec![i as u8 + 1; 512];
            joins.push(tokio::spawn(async move {
                let (n, _b) =
                    fs.pwritev(me, &f, vec![payload], (i * 512) as u64).await;
                assert_eq!(n.unwrap(), 512, "no EBUSY under the semaphore");
            }));
        }
        for j in joins {
            j.await.unwrap();
        }
        let f = std::sync::Arc::try_unwrap(f)
            .expect("all writers joined; sole owner");
        fs.close(f).await.unwrap();
    });
}

#[test]
// The first block_on deliberately returns the parked task's JoinHandle so it
// can be awaited AFTER the runtime shutdown between the two block_on calls.
#[allow(clippy::async_yields_async)]
fn shutdown_unblocks_awaiting_future_and_fails_later_calls() {
    let dir = tempfile::tempdir().expect("tempdir");
    let builder = match FsRuntimeBuilder::new(FsConfig::default()) {
        Ok(b) => b,
        Err(e) => {
            if should_skip(&e) {
                return;
            }
            panic!("FsRuntimeBuilder::new: {e}");
        }
    };
    let me = builder.register_self().expect("register_self");
    let rt = builder.start().expect("start");
    let fs = rt.rt();
    mkfifo(dir.path(), "fifo");
    let anchor = Anchor::open(dir.path()).unwrap();

    let trt = tokio_rt();
    let parked = trt.block_on(async {
        let how = OpenHow::new().flags(OFlag::O_RDWR);
        let f = fs.open(me, &anchor, "fifo", how).await.expect("open fifo");
        let fs2 = fs.clone();
        let jh = tokio::spawn(async move {
            let (res, _bufs) = fs2.preadv(me, &f, vec![vec![0u8; 8]], 0).await;
            res
        });
        tokio::time::sleep(Duration::from_millis(50)).await; // let it park
        jh
    });

    // Shut down with the read parked: the drain cancels it, the awaiting
    // future resolves with an error, and the loop exits cleanly.
    rt.shutdown().expect("clean teardown with a parked op");
    let res = trt.block_on(parked).expect("task join");
    assert!(res.is_err(), "parked read must fail at teardown");

    // Later submissions observe the dead loop as ECONNABORTED.
    let res = trt.block_on(fs.statx_anchor(
        me,
        &anchor,
        AtFlags::empty(),
        StatxMask::BASIC_STATS,
    ));
    assert!(matches!(res, Err(Error::Errno(Errno::ECONNABORTED))));
}

#[test]
fn brokered_identity_drives_async_ops() {
    // The broker forks, so everything before `start()` must run while the
    // process is single-threaded — the exact ordering the builder encodes.
    let dir = tempfile::tempdir().expect("tempdir");
    let builder = match FsRuntimeBuilder::new(FsConfig::default()) {
        Ok(b) => b,
        Err(e) => {
            if should_skip(&e) {
                return;
            }
            panic!("FsRuntimeBuilder::new: {e}");
        }
    };
    let broker = match CredBroker::spawn(&[builder.reactor()]) {
        Ok(b) => b,
        Err(e) => {
            if should_skip(&e) {
                return;
            }
            panic!("CredBroker::spawn: {e}");
        }
    };
    let creds = broker.handle(0).expect("broker handle");
    let rt = builder.start().expect("start");
    let fs = rt.rt();

    // SAFETY: geteuid cannot fail.
    let euid = unsafe { libc::geteuid() };
    if euid == 0 {
        // Root's own identity is refused by broker policy; the impersonation
        // legs live in test/async_fs.rs. This test is about the async path.
        rt.shutdown().expect("clean shutdown");
        return;
    }

    // Register the runner's own identity (needs no privilege) and drive a
    // real async op under it.
    // SAFETY: these cannot fail.
    let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
    // SAFETY: a zero count asks for the length instead of writing.
    let n = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    assert!(n >= 0);
    let mut groups = vec![0 as libc::gid_t; n as usize];
    // SAFETY: the destination holds the `n` entries just counted.
    let n = unsafe { libc::getgroups(n, groups.as_mut_ptr()) };
    assert!(n >= 0);
    groups.truncate(n as usize);
    let who = creds
        .register(&AsUser::new(uid, gid).groups(groups))
        .expect("brokered self-registration");

    std::fs::write(dir.path().join("f"), b"brokered").unwrap();
    let anchor = Anchor::open(dir.path()).unwrap();
    let trt = tokio_rt();
    trt.block_on(async {
        let f = fs.open(who, &anchor, "f", rdonly()).await.expect("open");
        let (n, buf) = fs.pread(who, &f, vec![0u8; 16], 0).await;
        assert_eq!(&buf[..n.unwrap()], b"brokered");
        fs.close(f).await.unwrap();
    });
    creds.unregister(who).expect("unregister");
    drop(trt);
    rt.shutdown().expect("clean shutdown");
}

// --- Phase B: registered buffers + O_DIRECT --------------------------------

/// [`with_rt`] plus a registered buffer pool.
fn with_rt_bufs<Fut>(
    cfg: FsConfig,
    bufs: truenas_ros::rt::BufPoolConfig,
    client: impl FnOnce(FsRuntime, Personality, PathBuf) -> Fut,
) where
    Fut: Future<Output = ()>,
{
    let dir = tempfile::tempdir().expect("tempdir");
    let builder = match FsRuntimeBuilder::new(cfg) {
        Ok(b) => b,
        Err(e) => {
            if should_skip(&e) {
                return;
            }
            panic!("FsRuntimeBuilder::new: {e}");
        }
    };
    let builder = builder.with_buffers(bufs).expect("register buffer pool");
    let me = builder.register_self().expect("register_self");
    let rt = builder.start().expect("start loop thread");
    let trt = tokio_rt();
    trt.block_on(client(rt.clone(), me, dir.path().to_path_buf()));
    drop(trt);
    rt.shutdown().expect("loop exits cleanly");
}

fn small_pool() -> truenas_ros::rt::BufPoolConfig {
    truenas_ros::rt::BufPoolConfig {
        slots: 8,
        chunk_len: 64 << 10,
        initial: 2,
        max: 4,
    }
}

#[test]
fn fixed_rw_parity_and_lease_cycling() {
    with_rt_bufs(
        FsConfig::default(),
        small_pool(),
        |rt, me, dir| async move {
            let fs = rt.rt();
            let pool = rt.bufs().expect("pool registered").clone();
            let anchor = Anchor::open(dir.as_path()).unwrap();
            let f = fs.open(me, &anchor, "data", creat_rw()).await.unwrap();

            // write_fixed a patterned payload, then read it back both ways.
            let payload: Vec<u8> =
                (0..pool.chunk_len()).map(|i| i as u8).collect();
            let mut buf = pool.lease().await.unwrap();
            buf.copy_from_slice(&payload);
            let (n, buf) = fs
                .write_fixed(me, &f, buf, 0..payload.len(), 0)
                .await
                .expect("write_fixed");
            assert_eq!(n, payload.len());

            // Registered-buffer read sees what the registered-buffer write wrote…
            let (n, rbuf) =
                fs.read_fixed(me, &f, buf, 0).await.expect("read_fixed");
            assert_eq!(n, payload.len());
            assert_eq!(&rbuf[..n], &payload[..]);
            drop(rbuf);

            // …and so does the plain vectored path (same file, same bytes).
            let (n, bufs) =
                fs.preadv(me, &f, vec![vec![0u8; payload.len()]], 0).await;
            assert_eq!(n.unwrap(), payload.len());
            assert_eq!(bufs[0], payload);

            // Lease cycling: many sequential leases across a small pool.
            for round in 0..8u8 {
                let mut b = pool.lease().await.unwrap();
                b[0] = round;
                let (_n, b) = fs
                    .write_fixed(me, &f, b, 0..1, u64::from(round))
                    .await
                    .expect("cycled write");
                drop(b);
            }
            fs.close(f).await.unwrap();
        },
    );
}

#[test]
fn pool_exhaustion_queues_then_releases() {
    let mut cfg = small_pool();
    cfg.initial = 1;
    cfg.max = 1;
    with_rt_bufs(FsConfig::default(), cfg, |rt, _me, _dir| async move {
        let pool = rt.bufs().unwrap().clone();
        let held = pool.lease().await.unwrap();
        assert!(pool.try_lease().is_none(), "single buffer is out");

        // A waiter parks on the semaphore until the lease returns.
        let pool2 = pool.clone();
        let waiter = tokio::spawn(async move {
            let b = pool2.lease().await.unwrap();
            b.len()
        });
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(!waiter.is_finished(), "waiter must be queued, not failed");
        drop(held);
        let len = tokio::time::timeout(Duration::from_secs(2), waiter)
            .await
            .expect("waiter unblocked")
            .unwrap();
        assert_eq!(len, 64 << 10);
    });
}

#[test]
fn pool_grows_past_initial_up_to_max() {
    let mut cfg = small_pool();
    cfg.initial = 1;
    cfg.max = 2;
    with_rt_bufs(FsConfig::default(), cfg, |rt, _me, _dir| async move {
        let pool = rt.bufs().unwrap();
        let a = pool.lease().await.unwrap();
        let b = pool.lease().await.unwrap(); // second slot filled on demand
        assert_ne!(a.index(), b.index(), "distinct registered slots");
        assert!(pool.try_lease().is_none(), "max reached");
    });
}

#[test]
fn lease_survives_future_drop_and_returns_after_cqe() {
    let mut pcfg = small_pool();
    pcfg.initial = 1;
    pcfg.max = 1;
    let cfg = FsConfig {
        files: 1,
        ..FsConfig::default()
    };
    with_rt_bufs(cfg, pcfg, |rt, me, dir| async move {
        let fs = rt.rt();
        let pool = rt.bufs().unwrap().clone();
        mkfifo(&dir, "fifo");
        let anchor = Anchor::open(dir.as_path()).unwrap();
        let how = OpenHow::new().flags(OFlag::O_RDWR);
        let f = fs.open(me, &anchor, "fifo", how).await.expect("open fifo");

        // Park a registered-buffer read on the FIFO, then drop the future:
        // the lease is owned loop-side (in the reply endpoint) and must NOT
        // return to the pool while the op is still in flight.
        let buf = pool.lease().await.unwrap();
        {
            let read = fs.read_fixed(me, &f, buf, 0);
            tokio::pin!(read);
            let raced =
                tokio::time::timeout(Duration::from_millis(50), &mut read)
                    .await;
            assert!(raced.is_err(), "parked read must still be pending");
        }
        assert!(
            pool.try_lease().is_none(),
            "lease must stay op-owned while the read is parked"
        );

        // Closing cancels the read; once its CQE reaps, the undeliverable
        // outcome drops and the lease returns to the pool.
        fs.close(f).await.expect("close cancels the parked read");
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if let Some(b) = pool.try_lease() {
                drop(b);
                break;
            }
            assert!(
                Instant::now() < deadline,
                "lease did not return to the pool after the CQE"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    });
}

#[test]
fn o_direct_roundtrip_or_skip() {
    with_rt_bufs(
        FsConfig::default(),
        small_pool(),
        |rt, me, dir| async move {
            let fs = rt.rt();
            let pool = rt.bufs().unwrap().clone();
            let anchor = Anchor::open(dir.as_path()).unwrap();

            // Seed the file with buffered I/O so the direct read has content.
            std::fs::write(dir.join("d"), vec![7u8; 64 << 10]).unwrap();

            let d = match fs.open_direct(me, &anchor, "d", rdonly()).await {
                Ok(d) => d,
                // tmpfs (and other no-direct-I/O filesystems) reject O_DIRECT at
                // open; the qemu ZFS job exercises the real path.
                Err(Error::Errno(Errno::EINVAL | Errno::EOPNOTSUPP)) => return,
                Err(e) => panic!("open_direct: {e}"),
            };
            let buf = pool.lease().await.unwrap();
            let (n, buf) = fs
                .read_direct(me, &d, buf, 0)
                .await
                .expect("aligned direct read");
            assert_eq!(n, 64 << 10);
            assert!(buf[..n].iter().all(|&b| b == 7));

            // A misaligned offset is refused up front with a Validation error —
            // only checkable when the filesystem reported its alignment.
            if d.offset_align() > 1 {
                match fs.read_direct(me, &d, buf, 1).await {
                    Err(Error::Validation(msg)) => {
                        assert!(msg.contains("aligned"), "got: {msg}")
                    }
                    other => panic!("expected Validation, got {other:?}"),
                }
            }
            fs.close_direct(d).await.unwrap();
        },
    );
}

// --- Phase C: socket↔file bridges + SEND_ZC --------------------------------

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use truenas_ros::rt::Bridge;

#[test]
fn bridge_recv_to_file_loopback() {
    with_rt(FsConfig::default(), |rt, me, dir| async move {
        let fs = rt.rt();
        let anchor = Anchor::open(dir.as_path()).unwrap();
        let listener =
            tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Bigger than one pipe, dribbled with pauses: exercises multi-chunk
        // hops AND the -EAGAIN → POLL_ADD readiness path.
        let total: usize = 700 << 10;
        let payload: Vec<u8> = (0..total).map(|i| (i * 7) as u8).collect();
        let p2 = payload.clone();
        let client = tokio::spawn(async move {
            let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
            for chunk in p2.chunks(97 << 10) {
                s.write_all(chunk).await.unwrap();
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        });

        let (mut sock, _) = listener.accept().await.unwrap();
        let f = fs.open(me, &anchor, "body.bin", creat_rw()).await.unwrap();
        let mut br = Bridge::new(&rt, &mut sock).unwrap();
        let n = br
            .recv_to_file(&f, 0, total as u64, Some(Duration::from_secs(10)))
            .await
            .expect("spliced body");
        assert_eq!(n, total as u64);
        fs.fsync(me, &f).await.unwrap();
        fs.close(f).await.unwrap();
        client.await.unwrap();

        let got = std::fs::read(dir.join("body.bin")).unwrap();
        assert_eq!(got, payload, "spliced bytes must round-trip exactly");
    });
}

#[test]
fn bridge_send_file_loopback_and_short_at_eof() {
    with_rt(FsConfig::default(), |rt, me, dir| async move {
        let fs = rt.rt();
        let anchor = Anchor::open(dir.as_path()).unwrap();
        let total: usize = 300 << 10;
        let payload: Vec<u8> = (0..total).map(|i| (i * 13) as u8).collect();
        std::fs::write(dir.join("serve.bin"), &payload).unwrap();

        let listener =
            tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let reader = tokio::spawn(async move {
            let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
            let mut got = Vec::new();
            s.read_to_end(&mut got).await.unwrap();
            got
        });

        let (mut sock, _) = listener.accept().await.unwrap();
        let f = fs.open(me, &anchor, "serve.bin", rdonly()).await.unwrap();
        let mut br = Bridge::new(&rt, &mut sock).unwrap();
        // Ask for more than the file holds: sendfile semantics, short at EOF.
        let n = br
            .send_file(
                &f,
                0,
                (total + 4096) as u64,
                Some(Duration::from_secs(10)),
            )
            .await
            .expect("spliced file out");
        assert_eq!(n, total as u64, "short send at end-of-file");
        fs.close(f).await.unwrap();
        drop(br);
        drop(sock); // FIN so the reader's read_to_end completes

        let got = reader.await.unwrap();
        assert_eq!(got, payload, "served bytes must round-trip exactly");
    });
}

#[test]
fn bridge_send_zc_loopback_and_small_plain_path() {
    with_rt(FsConfig::default(), |rt, _me, _dir| async move {
        let listener =
            tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let big: usize = 128 << 10; // ≥ threshold → SEND_ZC path
        let small: usize = 512; // < threshold → plain SEND path
        let expect = big * 2 + small;
        let reader = tokio::spawn(async move {
            let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
            let mut got = vec![0u8; expect];
            s.read_exact(&mut got).await.unwrap();
            got
        });

        let (mut sock, _) = listener.accept().await.unwrap();
        let mut br = Bridge::new(&rt, &mut sock).unwrap();
        // Two zc sends back-to-back: the second proves the slot lifecycle
        // (result → notif → free) sustains reuse.
        let a: Vec<u8> = vec![0xAA; big];
        let b: Vec<u8> = vec![0xBB; big];
        let c: Vec<u8> = vec![0xCC; small];
        assert_eq!(
            br.send_zc(a, Some(Duration::from_secs(10))).await.unwrap(),
            big
        );
        assert_eq!(
            br.send_zc(b, Some(Duration::from_secs(10))).await.unwrap(),
            big
        );
        assert_eq!(
            br.send_zc(c, Some(Duration::from_secs(10))).await.unwrap(),
            small
        );

        let got = reader.await.unwrap();
        assert!(got[..big].iter().all(|&x| x == 0xAA));
        assert!(got[big..2 * big].iter().all(|&x| x == 0xBB));
        assert!(got[2 * big..].iter().all(|&x| x == 0xCC));
    });
}

#[test]
fn bridge_recv_peer_close_mid_body_is_econnreset() {
    with_rt(FsConfig::default(), |rt, me, dir| async move {
        let fs = rt.rt();
        let anchor = Anchor::open(dir.as_path()).unwrap();
        let listener =
            tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = tokio::spawn(async move {
            let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
            s.write_all(&vec![9u8; 8 << 10]).await.unwrap();
            // Drop (FIN) with the body only half-delivered.
        });

        let (mut sock, _) = listener.accept().await.unwrap();
        let f = fs.open(me, &anchor, "trunc.bin", creat_rw()).await.unwrap();
        let mut br = Bridge::new(&rt, &mut sock).unwrap();
        let res = br
            .recv_to_file(&f, 0, 64 << 10, Some(Duration::from_secs(10)))
            .await;
        assert!(
            matches!(res, Err(Error::Errno(Errno::ECONNRESET))),
            "peer close mid-body must fail ECONNRESET, got {res:?}"
        );
        fs.close(f).await.unwrap();
        client.await.unwrap();
    });
}

#[test]
fn bridge_timeout_abandons_and_pool_recovers() {
    with_rt(FsConfig::default(), |rt, me, dir| async move {
        let fs = rt.rt();
        let anchor = Anchor::open(dir.as_path()).unwrap();
        let listener =
            tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // A client that connects and then says nothing: the bridge parks on
        // readiness and the timeout fires.
        let silent = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (mut sock, _) = listener.accept().await.unwrap();
        let f = fs.open(me, &anchor, "t.bin", creat_rw()).await.unwrap();
        let mut br = Bridge::new(&rt, &mut sock).unwrap();
        let res = br
            .recv_to_file(&f, 0, 4096, Some(Duration::from_millis(100)))
            .await;
        assert!(
            matches!(res, Err(Error::Errno(Errno::ETIMEDOUT))),
            "got {res:?}"
        );
        drop(br);
        fs.close(f).await.unwrap();
        drop(silent);

        // The abandoned transfer tainted its pipe; a fresh transfer on a new
        // connection must work (the pool replaces discarded pipes).
        let payload = vec![3u8; 32 << 10];
        let p2 = payload.clone();
        let client = tokio::spawn(async move {
            let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
            s.write_all(&p2).await.unwrap();
        });
        let (mut sock2, _) = listener.accept().await.unwrap();
        let f = fs.open(me, &anchor, "ok.bin", creat_rw()).await.unwrap();
        let mut br = Bridge::new(&rt, &mut sock2).unwrap();
        let n = br
            .recv_to_file(
                &f,
                0,
                payload.len() as u64,
                Some(Duration::from_secs(10)),
            )
            .await
            .expect("fresh transfer after an abandoned one");
        assert_eq!(n, payload.len() as u64);
        fs.close(f).await.unwrap();
        client.await.unwrap();
        assert_eq!(std::fs::read(dir.join("ok.bin")).unwrap(), payload);
    });
}

// --- Phase D: framing, serve, kTLS -----------------------------------------

use truenas_ros::framing::{
    length_prefix_header, Endian, Framing, PrefixWidth,
};
use truenas_ros::rt::{
    ktls_client_handshake, ktls_server_handshake, serve, write_frame, Frame,
    FrameReader, ServeOptions,
};

#[test]
fn frame_reader_roundtrip_and_eof_semantics() {
    let trt = tokio_rt();
    trt.block_on(async {
        let (client, server) = tokio::io::duplex(4096);
        let writer = tokio::spawn(async move {
            let mut client = client;
            for msg in [&b"hello"[..], &b""[..], &b"a longer message"[..]] {
                let len = (msg.len() as u32).to_be_bytes();
                write_frame(&mut client, &[&len, msg]).await.unwrap();
            }
            // Dropping at a frame boundary = clean end-of-stream.
        });

        let mut fr = FrameReader::new(server);
        let mut framer =
            length_prefix_header(PrefixWidth::U32, Endian::Big, false);
        let mut got = Vec::new();
        while let Some(frame) = fr.next(&mut framer).await.unwrap() {
            match frame {
                Frame::Message { header, body } => {
                    assert_eq!(header.len(), 4);
                    got.push(body);
                }
                other => panic!("unexpected {other:?}"),
            }
        }
        assert_eq!(
            got,
            vec![b"hello".to_vec(), Vec::new(), b"a longer message".to_vec()]
        );
        writer.await.unwrap();

        // EOF mid-frame is a hard error, not a clean end.
        let (client, server) = tokio::io::duplex(4096);
        let mut fr = FrameReader::new(server);
        let mut framer =
            length_prefix_header(PrefixWidth::U32, Endian::Big, false);
        let half = tokio::spawn(async move {
            let mut client = client;
            // Announce 100 bytes, deliver 3, vanish.
            write_frame(&mut client, &[&100u32.to_be_bytes(), b"abc"])
                .await
                .unwrap();
        });
        let res = fr.next(&mut framer).await;
        assert!(
            matches!(res, Err(Error::Errno(Errno::ECONNRESET))),
            "got {res:?}"
        );
        half.await.unwrap();
    });
}

/// A "PUT"-style framer: an 8-byte header — u32 magic + u32 body length —
/// whose body is diverted to the zero-copy path. Exact-`Need` discipline.
fn splice_framer() -> impl FnMut(&[u8]) -> Framing {
    |buf: &[u8]| {
        if buf.len() < 8 {
            return Framing::Need(8 - buf.len());
        }
        let body = u32::from_be_bytes(buf[4..8].try_into().unwrap());
        Framing::SpliceBody {
            header_len: 8,
            body_len: body as usize,
        }
    }
}

#[test]
fn frame_reader_splice_body_drives_bridge() {
    with_rt(FsConfig::default(), |rt, me, dir| async move {
        let fs = rt.rt();
        let anchor = Anchor::open(dir.as_path()).unwrap();
        let listener =
            tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let body: Vec<u8> = (0..192 << 10).map(|i| (i * 3) as u8).collect();
        let blen = body.len();
        let b2 = body.clone();
        let client = tokio::spawn(async move {
            let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
            let mut header = Vec::new();
            header.extend_from_slice(&0xCAFE_F00Du32.to_be_bytes());
            header.extend_from_slice(&(blen as u32).to_be_bytes());
            s.write_all(&header).await.unwrap();
            s.write_all(&b2).await.unwrap();
        });

        let (sock, _) = listener.accept().await.unwrap();
        // Splice bodies require the exact reader (buffered mode may read past
        // the header, which the splice hand-off forbids).
        let mut fr = FrameReader::exact(sock);
        let mut framer = splice_framer();
        let Some(Frame::SpliceBody { header, body_len }) =
            fr.next(&mut framer).await.unwrap()
        else {
            panic!("expected a splice frame");
        };
        assert_eq!(&header[..4], &0xCAFE_F00Du32.to_be_bytes());
        assert_eq!(body_len, blen as u64);

        // The body phase: a bridge over the reader's own stream.
        let f = fs.open(me, &anchor, "put.bin", creat_rw()).await.unwrap();
        let mut br = Bridge::new(&rt, fr.get_mut()).unwrap();
        let n = br
            .recv_to_file(&f, 0, body_len, Some(Duration::from_secs(10)))
            .await
            .unwrap();
        assert_eq!(n, body_len);
        fs.close(f).await.unwrap();
        client.await.unwrap();
        assert_eq!(std::fs::read(dir.join("put.bin")).unwrap(), body);

        // Back to framing: the peer is done → clean end-of-stream.
        assert!(fr.next(&mut framer).await.unwrap().is_none());
    });
}

#[test]
fn serve_caps_connections_and_drains_on_shutdown() {
    let trt = tokio_rt();
    trt.block_on(async {
        let listener =
            tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        let served =
            std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let served2 = served.clone();

        let server = tokio::spawn(serve(
            listener,
            ServeOptions {
                max_connections: 2,
                drain: Duration::from_secs(2),
            },
            stop_rx,
            move |mut stream, _peer| {
                let served = served2.clone();
                async move {
                    let mut b = [0u8; 1];
                    if stream.read_exact(&mut b).await.is_ok() {
                        let _ = stream.write_all(&b).await;
                        served
                            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    }
                }
            },
        ));

        let mut clients = Vec::new();
        for i in 0..6u8 {
            clients.push(tokio::spawn(async move {
                let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
                s.write_all(&[i]).await.unwrap();
                let mut b = [0u8; 1];
                s.read_exact(&mut b).await.unwrap();
                assert_eq!(b[0], i);
            }));
        }
        for c in clients {
            c.await.unwrap();
        }
        assert_eq!(served.load(std::sync::atomic::Ordering::SeqCst), 6);

        stop_tx.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .expect("serve drains promptly")
            .unwrap()
            .unwrap();
    });
}

// ---- kTLS: the Phase E parity coverage ------------------------------------

fn self_signed() -> (Vec<u8>, Vec<u8>) {
    use openssl::asn1::Asn1Time;
    use openssl::hash::MessageDigest;
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
    use openssl::x509::{X509NameBuilder, X509};
    let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "localhost").unwrap();
    let name = name.build();
    let mut b = X509::builder().unwrap();
    b.set_version(2).unwrap();
    b.set_subject_name(&name).unwrap();
    b.set_issuer_name(&name).unwrap();
    b.set_pubkey(&key).unwrap();
    b.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    b.set_not_after(&Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    b.sign(&key, MessageDigest::sha256()).unwrap();
    (
        b.build().to_pem().unwrap(),
        key.private_key_to_pem_pkcs8().unwrap(),
    )
}

const SSL_OP_ENABLE_KTLS: u64 = 1 << 3; // SSL_OP_BIT(3); no named crate const

fn ktls_acceptor() -> std::sync::Arc<openssl::ssl::SslAcceptor> {
    use openssl::pkey::PKey;
    use openssl::ssl::{SslAcceptor, SslMethod, SslOptions};
    use openssl::x509::X509;
    let (cert, key) = self_signed();
    let mut b = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
    b.set_private_key(&PKey::private_key_from_pem(&key).unwrap())
        .unwrap();
    b.set_certificate(&X509::from_pem(&cert).unwrap()).unwrap();
    b.check_private_key().unwrap();
    b.set_options(SslOptions::from_bits_retain(SSL_OP_ENABLE_KTLS));
    b.set_num_tickets(0).unwrap();
    std::sync::Arc::new(b.build())
}

fn ktls_connector() -> std::sync::Arc<openssl::ssl::SslConnector> {
    use openssl::ssl::{SslConnector, SslMethod, SslOptions, SslVerifyMode};
    let mut b = SslConnector::builder(SslMethod::tls()).unwrap();
    b.set_verify(SslVerifyMode::NONE);
    b.set_options(SslOptions::from_bits_retain(SSL_OP_ENABLE_KTLS));
    std::sync::Arc::new(b.build())
}

/// kTLS engagement is best-effort in OpenSSL: treat a handshake-helper
/// failure as an environmental skip unless `TRUENAS_ROS_REQUIRE_KTLS`
/// insists (the qemu TrueNAS-kernel job sets it).
fn ktls_skip(e: &Error) -> bool {
    let env = matches!(e, Error::Validation(_));
    if env {
        assert!(
            std::env::var_os("TRUENAS_ROS_REQUIRE_KTLS").is_none(),
            "TRUENAS_ROS_REQUIRE_KTLS set but kTLS did not engage: {e}"
        );
    }
    env
}

#[test]
fn ktls_stream_echo_bridge_and_zc_fallback() {
    with_rt(FsConfig::default(), |rt, me, dir| async move {
        let fs = rt.rt();
        let anchor = Anchor::open(dir.as_path()).unwrap();
        let listener =
            tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let acceptor = ktls_acceptor();
        let connector = ktls_connector();

        let server_task = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            ktls_server_handshake(sock.into_std().unwrap(), acceptor).await
        });
        let client_sock = tokio::net::TcpStream::connect(addr).await.unwrap();
        let client_res = ktls_client_handshake(
            client_sock.into_std().unwrap(),
            connector,
            "localhost",
        )
        .await;
        let server_res = server_task.await.unwrap();
        let (mut server, mut client) = match (server_res, client_res) {
            (Ok(s), Ok(c)) => (s, c),
            (Err(e), _) | (_, Err(e)) => {
                if ktls_skip(&e) {
                    return; // this host's OpenSSL cannot engage kTLS
                }
                panic!("kTLS handshake: {e}");
            }
        };

        // 1) Plain byte echo through both KtlsStreams (kernel encrypts and
        //    decrypts; the streams speak plaintext).
        client.write_all(b"over-ktls").await.unwrap();
        let mut b = [0u8; 9];
        server.read_exact(&mut b).await.unwrap();
        assert_eq!(&b, b"over-ktls");
        server.write_all(b"eck").await.unwrap();
        let mut b3 = [0u8; 3];
        client.read_exact(&mut b3).await.unwrap();
        assert_eq!(&b3, b"eck");

        // 2) recv_to_file over kTLS: the splice path decrypts in-kernel
        //    (tls_sw_splice_read) — plaintext lands in the file.
        let body: Vec<u8> = (0..96 << 10).map(|i| (i * 11) as u8).collect();
        let blen = body.len();
        let b2 = body.clone();
        let up = tokio::spawn(async move {
            client.write_all(&b2).await.unwrap();
            client // keep the stream alive; hand it back
        });
        let f = fs.open(me, &anchor, "tls.bin", creat_rw()).await.unwrap();
        let mut br = Bridge::new(&rt, &mut server).unwrap();
        let n = br
            .recv_to_file(&f, 0, blen as u64, Some(Duration::from_secs(10)))
            .await
            .expect("kTLS body splice");
        assert_eq!(n, blen as u64);
        fs.close(f).await.unwrap();
        let mut client = up.await.unwrap();
        assert_eq!(std::fs::read(dir.join("tls.bin")).unwrap(), body);

        // 3) send_file over kTLS: file pages feed the kernel's encrypt path
        //    (MSG_SPLICE_PAGES); the client reads plaintext.
        std::fs::write(dir.join("serve-tls.bin"), &body).unwrap();
        let f = fs
            .open(me, &anchor, "serve-tls.bin", rdonly())
            .await
            .unwrap();
        let down = tokio::spawn(async move {
            let mut got = vec![0u8; blen];
            client.read_exact(&mut got).await.unwrap();
            (client, got)
        });
        let mut br = Bridge::new(&rt, &mut server).unwrap();
        let n = br
            .send_file(&f, 0, blen as u64, Some(Duration::from_secs(10)))
            .await
            .expect("kTLS sendfile splice");
        assert_eq!(n, blen as u64);
        fs.close(f).await.unwrap();
        let (mut client, got) = down.await.unwrap();
        assert_eq!(got, body);

        // 4) send_zc over kTLS: the kernel rejects MSG_ZEROCOPY, the bridge
        //    detects EOPNOTSUPP and falls back to plain sends — bytes still
        //    arrive intact (and SW kTLS zero-copies the input in-kernel).
        let payload = vec![0x5Au8; 64 << 10];
        let plen = payload.len();
        let down = tokio::spawn(async move {
            let mut got = vec![0u8; plen];
            client.read_exact(&mut got).await.unwrap();
            got
        });
        let mut br = Bridge::new(&rt, &mut server).unwrap();
        let n = br
            .send_zc(payload, Some(Duration::from_secs(10)))
            .await
            .expect("zc falls back on kTLS");
        assert_eq!(n, plen);
        let got = down.await.unwrap();
        assert!(got.iter().all(|&x| x == 0x5A));
    });
}

// --- Code-review regressions ------------------------------------------------

/// #1: a dropped/timed-out bridge transfer must cancel its in-flight op so
/// the op-table slot and its backpressure permit are reclaimed. Without the
/// cancel-on-drop guard, each abandoned transfer against a silent peer parks
/// a POLL_ADD that never completes, and after `ops` of them every FsRt
/// operation hangs forever. This drives 3× the op table through abandoned
/// transfers, then proves the runtime still works.
#[test]
fn bridge_cancel_on_drop_reclaims_op_slots() {
    let cfg = FsConfig {
        ops: 4,
        ..FsConfig::default()
    };
    with_rt(cfg, |rt, me, dir| async move {
        let fs = rt.rt();
        let anchor = Anchor::open(dir.as_path()).unwrap();
        let listener =
            tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Keep silent peers alive for the whole loop (dropping them early
        // would let the splice see EOF instead of parking on readiness).
        let mut silent = Vec::new();
        for _ in 0..12 {
            let c = tokio::net::TcpStream::connect(addr).await.unwrap();
            let (mut server, _) = listener.accept().await.unwrap();
            let f = fs.open(me, &anchor, "sink", creat_rw()).await.unwrap();
            // The peer sends nothing: hop-1 splice EAGAINs, the bridge parks
            // on POLL_ADD, and the timeout drops the future mid-park.
            let mut br = Bridge::new(&rt, &mut server).unwrap();
            let res = br
                .recv_to_file(&f, 0, 4096, Some(Duration::from_millis(60)))
                .await;
            assert!(
                matches!(res, Err(Error::Errno(Errno::ETIMEDOUT))),
                "expected timeout, got {res:?}"
            );
            drop(br);
            fs.close(f).await.unwrap();
            silent.push(c);
        }

        // If any abandoned poll leaked its permit, the op table (4 slots)
        // would be exhausted and this would hang. A short timeout turns a
        // hang into a visible failure.
        let ok = tokio::time::timeout(Duration::from_secs(5), async {
            for _ in 0..8 {
                fs.statx_anchor(
                    me,
                    &anchor,
                    AtFlags::empty(),
                    StatxMask::BASIC_STATS,
                )
                .await
                .expect("runtime still serves after abandoned transfers");
            }
        })
        .await;
        assert!(ok.is_ok(), "fs runtime starved — a cancelled op leaked");
        drop(silent);
    });
}

/// #3: dropping an `open` future after its inject is sent must not leak the
/// freshly-opened pool slot — the loop stages a close when the outcome can't
/// be delivered. `timeout(0)` polls the future once (sending the inject),
/// then drops it; the open still completes loop-side. Without the fix the
/// slot is gone forever and the pool exhausts.
#[test]
fn open_future_drop_does_not_leak_slot() {
    let cfg = FsConfig {
        files: 4,
        ..FsConfig::default()
    };
    with_rt(cfg, |rt, me, dir| async move {
        let fs = rt.rt();
        std::fs::write(dir.join("a"), b"a").unwrap();
        let anchor = Anchor::open(dir.as_path()).unwrap();

        for _ in 0..64 {
            let fut = fs.open(me, &anchor, "a", rdonly());
            match tokio::time::timeout(Duration::from_millis(0), fut).await {
                Ok(Ok(f)) => fs.close(f).await.unwrap(),
                Ok(Err(e)) => panic!("open: {e}"),
                Err(_) => { /* dropped mid-flight — must not leak */ }
            }
        }
        // Every leaked slot is unrecoverable; with the fix the loop-staged
        // closes drain and the pool stays usable (retry briefly to let the
        // async closes land).
        let f = reopen_eventually(&fs, me, &anchor, "a").await;
        fs.close(f).await.unwrap();
    });
}

/// #2: a `Framing::More` (delimiter-scanning) framer whose delimiter never
/// arrives must be bounded by `max_request_bytes`, not grown without limit.
#[test]
fn frame_reader_caps_unbounded_more() {
    let trt = tokio_rt();
    trt.block_on(async {
        let (client, server) = tokio::io::duplex(1 << 16);
        let flood = tokio::spawn(async move {
            let mut client = client;
            // 40 KiB with no newline — the framer keeps saying `More`.
            let _ = client.write_all(&vec![b'x'; 40 << 10]).await;
            // Hold the connection open so EOF can't end the read first.
            std::future::pending::<()>().await;
        });

        let mut fr = FrameReader::with_limits(server, 8 << 10, None);
        let mut framer = |buf: &[u8]| match buf.iter().position(|&b| b == b'\n')
        {
            Some(i) => Framing::Complete {
                header_len: i + 1,
                body_len: 0,
            },
            None => Framing::More,
        };
        let res =
            tokio::time::timeout(Duration::from_secs(5), fr.next(&mut framer))
                .await
                .expect("must not grow unbounded / hang");
        match res {
            Err(Error::Validation(m)) => {
                assert!(m.contains("max_request_bytes"), "got: {m}")
            }
            other => panic!("expected TooLarge validation, got {other:?}"),
        }
        flood.abort();
    });
}

/// #7: a partial header followed by EOF is a truncated frame (`ECONNRESET`),
/// not a clean end-of-stream (`Ok(None)`).
#[test]
fn frame_reader_partial_header_then_eof_is_reset() {
    let trt = tokio_rt();
    trt.block_on(async {
        let (client, server) = tokio::io::duplex(4096);
        let half = tokio::spawn(async move {
            let mut client = client;
            // 2 of the 4 length-prefix bytes, then close.
            client.write_all(&[0u8, 0u8]).await.unwrap();
        });
        let mut fr = FrameReader::new(server);
        let mut framer =
            length_prefix_header(PrefixWidth::U32, Endian::Big, false);
        let res = fr.next(&mut framer).await;
        assert!(
            matches!(res, Err(Error::Errno(Errno::ECONNRESET))),
            "truncated header must be ECONNRESET, got {res:?}"
        );
        half.await.unwrap();

        // Sanity: a clean close *between* frames is still Ok(None).
        let (client, server) = tokio::io::duplex(4096);
        drop(client);
        let mut fr = FrameReader::new(server);
        let mut framer =
            length_prefix_header(PrefixWidth::U32, Endian::Big, false);
        assert!(fr.next(&mut framer).await.unwrap().is_none());
    });
}

/// #8: at `max_connections`, a shutdown signal must still be observed
/// promptly — the accept loop must not be parked on the connection permit.
#[test]
fn serve_shutdown_responsive_at_capacity() {
    let trt = tokio_rt();
    trt.block_on(async {
        let listener =
            tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        let (release_tx, release_rx) = tokio::sync::watch::channel(false);
        let release_rx = std::sync::Arc::new(release_rx);

        let server = tokio::spawn(serve(
            listener,
            ServeOptions {
                max_connections: 1,
                drain: Duration::from_secs(5),
            },
            stop_rx,
            move |_stream, _peer| {
                let mut r = (*release_rx).clone();
                async move {
                    // Occupy the one slot until released (or shutdown drains).
                    while !*r.borrow() {
                        if r.changed().await.is_err() {
                            break;
                        }
                    }
                }
            },
        ));

        // Fill the single slot, then queue a second connection.
        let _c1 = tokio::net::TcpStream::connect(addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        let _c2 = tokio::net::TcpStream::connect(addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Signal shutdown while at capacity with a pending accept, and
        // release the handler so the drain phase completes at once. The loop
        // must have *observed* the shutdown promptly — if it were parked on
        // the connection permit (the bug), it would never see the watch and
        // serve() would hang past this 2s bound even though a slot is free.
        stop_tx.send(true).unwrap();
        let _ = release_tx.send(true);
        let drained =
            tokio::time::timeout(Duration::from_secs(2), server).await;
        assert!(
            drained.is_ok(),
            "serve() did not observe shutdown at capacity"
        );
        drained.unwrap().unwrap().unwrap();
    });
}
