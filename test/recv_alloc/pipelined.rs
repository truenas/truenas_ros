use super::*;

// ---- pipelined ingest: K windows in flight per connection ------------------

/// Room for the depth-2 runs, stated rather than inherited.
#[cfg(feature = "uring-fs")]
const PIPE_LEASE_DEPTH: u32 = 4;

/// Per-connection pipeline control shared with the write continuations.
#[cfg(feature = "uring-fs")]
struct PipeCtl {
    inflight: AtomicUsize,
    peak: AtomicUsize,
    failed: std::sync::atomic::AtomicBool,
    /// The window parked at the depth cap, resumed by the next completion.
    parked: std::sync::Mutex<Option<truenas_ros::http::HttpStreamDeferred>>,
    /// The End delivery, answered once every write has completed.
    end: std::sync::Mutex<Option<truenas_ros::http::HttpDeferred>>,
}

/// Upload `mib` MiB on `conns` connections at write depth `k`, every window written to its connection's file with
/// `pwritev2_from` and `Continue` -- parking only at the cap. Answers (large allocations, all files matched, peak
/// writes in flight observed).
#[cfg(feature = "uring-fs")]
#[allow(clippy::too_many_lines)]
fn pipelined_put_cost(mib: usize, conns: usize, k: usize) -> Option<(usize, bool, usize)> {
    use std::sync::OnceLock;
    use truenas_ros::http::HttpDeferred;
    use truenas_ros::uring_fs::{File, Personality, RwFlags};

    // `truenas_ros::tempdir()` rather than a parameter-named directory, since two `recv_alloc` binaries may run at once
    // and `MEASURING` serializes only within a process. The drop guard rather than a trailing `remove_dir_all`, since
    // it cleans up on the unwind of a failed assert too.
    let tmp = truenas_ros::tempdir().expect("tempdir");
    let dir = tmp.path().to_owned();
    for i in 0..conns {
        std::fs::write(dir.join(format!("obj{i}")), b"").expect("create");
    }

    let files: Vec<File> = {
        use truenas_ros::sync_fs::{OFlag, OpenHow};
        use truenas_ros::uring_fs::{Anchor, FsConfig, UringFs};
        let mut afs = match UringFs::new(FsConfig::default()) {
            Ok(f) => f,
            Err(e) if should_skip(&e) => return None,
            Err(e) => panic!("UringFs::new: {e}"),
        };
        let who = afs.register_self().expect("register_self");
        let handle = afs.handle();
        let stop_fs = afs.shutdown_handle();
        let anchor = Anchor::open(&dir).expect("anchor");
        let (ftx, frx) = std::sync::mpsc::channel();
        thread::scope(|sc| {
            sc.spawn(move || {
                for i in 0..conns {
                    let name = std::ffi::CString::new(format!("obj{i}")).unwrap();
                    let r = handle.open(who, &anchor, name.as_c_str(), OpenHow::new().flags(OFlag::O_WRONLY));
                    let _ = ftx.send(r);
                }
                stop_fs.shutdown();
            });
            afs.run().expect("fs host run");
        });
        (0..conns)
            .map(|_| frx.recv().expect("open outcome").expect("open"))
            .collect()
    };

    let pers: std::sync::Arc<OnceLock<Personality>> = std::sync::Arc::new(OnceLock::new());
    let pc = std::sync::Arc::clone(&pers);
    let peak_seen = std::sync::Arc::new(AtomicUsize::new(0));
    let peak_out = std::sync::Arc::clone(&peak_seen);
    let assigned = std::sync::Arc::new(AtomicUsize::new(0));

    type St = (u64, std::sync::Arc<PipeCtl>, File);
    let files_for_accept = files.clone();
    let proto = truenas_ros::http::protocol_streaming_fs(
        HttpConfig::default(),
        1 << 30,
        move |_i: Incoming<'_>| -> Option<St> {
            let n = assigned.fetch_add(1, Ordering::Relaxed);
            Some((
                0,
                std::sync::Arc::new(PipeCtl {
                    inflight: AtomicUsize::new(0),
                    peak: AtomicUsize::new(0),
                    failed: std::sync::atomic::AtomicBool::new(false),
                    parked: std::sync::Mutex::new(None),
                    end: std::sync::Mutex::new(None),
                }),
                files_for_accept[n % files_for_accept.len()].clone(),
            ))
        },
        move |req: HttpRequest<'_>, st: &mut St, fs| {
            let (off, ctl, file) = st;
            match req.stage {
                Stage::Open => {
                    *off = 0;
                    HttpVerdict::Continue
                }
                Stage::Window => {
                    let Some(mut fs) = fs else {
                        return HttpVerdict::Respond(HttpResponse::new(500));
                    };
                    let who = *pc.get().expect("personality set");
                    let at = *off;
                    *off += req.body.len() as u64;
                    let now = ctl.inflight.fetch_add(1, Ordering::Relaxed) + 1;
                    ctl.peak.fetch_max(now, Ordering::Relaxed);
                    peak_out.fetch_max(now, Ordering::Relaxed);
                    // The completion: release the depth slot, wake whoever the cap parked, and settle End once
                    // everything landed.
                    let done_ctl = std::sync::Arc::clone(ctl);
                    let cont = move |done: truenas_ros::uring_fs::FsDone,
                                     _fs: &mut truenas_ros::uring_fs::FsConn<'_>| {
                        if done.result().is_err() {
                            done_ctl.failed.store(true, Ordering::Relaxed);
                        }
                        let left = done_ctl.inflight.fetch_sub(1, Ordering::Relaxed) - 1;
                        if let Some(d) = done_ctl.parked.lock().unwrap().take() {
                            d.resume();
                        }
                        let end: Option<HttpDeferred> = if left == 0 {
                            done_ctl.end.lock().unwrap().take()
                        } else {
                            None
                        };
                        if let Some(d) = end {
                            if done_ctl.failed.load(Ordering::Relaxed) {
                                d.reply(HttpResponse::new(500));
                            } else {
                                d.reply(HttpResponse::new(200));
                            }
                        }
                    };
                    if now < k {
                        // Below depth: float the write, keep reading.
                        fs.pwritev2_from(who, file.clone(), &req.body, at, RwFlags::empty(), cont);
                        HttpVerdict::Continue
                    } else {
                        // At depth: same write, but brake the stream until a completion frees a slot.
                        let (d, permit, body) = req.defer_stream();
                        *ctl.parked.lock().unwrap() = Some(d);
                        fs.pwritev2_from(who, file.clone(), &body, at, RwFlags::empty(), cont);
                        HttpVerdict::Defer(permit)
                    }
                }
                Stage::End => {
                    if ctl.inflight.load(Ordering::Relaxed) == 0 {
                        let code = if ctl.failed.load(Ordering::Relaxed) { 500 } else { 200 };
                        return HttpVerdict::Respond(HttpResponse::new(code));
                    }
                    let (deferred, permit) = req.defer();
                    *ctl.end.lock().unwrap() = Some(deferred);
                    HttpVerdict::Defer(permit)
                }
                Stage::Whole => HttpVerdict::Respond(HttpResponse::new(500)),
            }
        },
    )
    .expect("codec config");

    let cfg = ServerConfig {
        pool_size: conns as u32,
        fs_ops: 64,
        max_request_bytes: 512 * 1024,
        // `None`, so an undersized ring shows as allocations; parking would hide it.
        recv_lease_depth: PIPE_LEASE_DEPTH,
        recv_shortage_retry: None,
        ..ServerConfig::default()
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let mut server = match Server::with_config([addr], cfg, proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return None,
        Err(e) => panic!("bind: {e}"),
    };
    pers.set(server.register_self().expect("register_self"))
        .expect("set once");
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stats = server.stats_handle();
    let stop = server.shutdown_handle();

    let payload = vec![0xc3u8; mib * 1024 * 1024];
    let wire = std::sync::Arc::new(chunked_put(&payload, 128 * 1024));
    drop(payload);

    let client = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone());
        let before = BIG_ALLOCS.load(Ordering::Relaxed);
        let uploads: Vec<_> = (0..conns)
            .map(|_| {
                let wire = std::sync::Arc::clone(&wire);
                thread::spawn(move || {
                    let mut s = TcpStream::connect(v4).expect("connect");
                    s.set_read_timeout(Some(Duration::from_secs(60))).unwrap();
                    s.write_all(&wire).expect("write");
                    let status = read_status(&mut s).expect("status");
                    assert_eq!(status, 200, "upload refused");
                })
            })
            .collect();
        for u in uploads {
            u.join().expect("upload thread");
        }
        let cost = BIG_ALLOCS.load(Ordering::Relaxed) - before;
        stop.shutdown();
        cost
    });

    server.serve_forever().expect("serve_forever");
    let cost = client.join().expect("client thread");
    let s = stats.snapshot();
    assert!(s.recv_bufs_total > 0, "no ring: {s:?}");
    assert_eq!(s.recv_bufs_lent, 0, "leases not returned: {s:?}");
    let want = vec![0xc3u8; mib * 1024 * 1024];
    let ok = (0..conns).all(|i| std::fs::read(dir.join(format!("obj{i}"))).expect("read back") == want);
    let peak = peak_seen.load(Ordering::Relaxed);
    Some((cost, ok, peak))
}

/// A depth-2 pipelined PUT overlaps a window's write with the next window's arrival, copies nothing, allocates nothing
/// per window, and the files come back byte-identical.
///
/// The peak-in-flight watermark is what proves the overlap is real: at depth 1 it cannot exceed one, at depth 2 the
/// loopback client outruns the io-wq write punt and the watermark reaches two. The allocation scaling run is what
/// proves the ring covered the depth - past the registration wall connections degrade to owned buffers and every window
/// costs a copy, which is exactly what the depth-sized registration exists to prevent.
#[cfg(feature = "uring-fs")]
#[test]
fn a_pipelined_put_overlaps_writes_with_arrivals() {
    let _turn = MEASURING.lock().unwrap_or_else(|e| e.into_inner());
    let Some((small, ok_small, peak2)) = pipelined_put_cost(4, 2, 2) else {
        return; // io_uring unavailable
    };
    let Some((large, ok_large, _)) = pipelined_put_cost(16, 2, 2) else {
        return;
    };
    let Some((_, ok_serial, peak1)) = pipelined_put_cost(4, 2, 1) else {
        return;
    };
    assert!(ok_small && ok_large && ok_serial, "file bytes differ");
    assert!(peak2 >= 2, "depth 2 never overlapped: peak {peak2}");
    assert_eq!(peak1, 1, "depth 1 must not overlap: peak {peak1}");
    assert!(
        large <= small + 8,
        "pipelined PUT cost scales with payload: 4 MiB cost {small}, \
         16 MiB cost {large}. A ring registered below the write depth \
         degrades connections to owned buffers and looks exactly like this."
    );
}

/// Per-connection state of a gathering handler, shared with its writes.
#[cfg(feature = "uring-fs")]
struct GatherCtl {
    /// Windows held by gathered writes still in flight.
    flying: AtomicUsize,
    failed: std::sync::atomic::AtomicBool,
    /// The window parked at the claim cap, resumed by the next completion.
    parked: std::sync::Mutex<Option<truenas_ros::http::HttpStreamDeferred>>,
    /// The End delivery, answered once every write has completed.
    end: std::sync::Mutex<Option<truenas_ros::http::HttpDeferred>>,
}

/// Upload `mib` MiB on `conns` connections, every window held with `lease_window` and written `g` at a time with one
/// `pwritev2_leased`, braking the stream once held and in-flight windows reach `cap`. Answers (large allocations, all
/// files matched, gathered writes, windows that could not be leased).
#[cfg(feature = "uring-fs")]
#[allow(clippy::too_many_lines)]
fn gathered_put_cost(mib: usize, conns: usize, g: usize, cap: usize) -> Option<(usize, bool, usize, usize)> {
    use std::sync::OnceLock;
    use truenas_ros::http::HttpDeferred;
    use truenas_ros::uring_fs::{File, LeasedWindow, Personality, RwFlags};

    let tmp = truenas_ros::tempdir().expect("tempdir");
    let dir = tmp.path().to_owned();
    for i in 0..conns {
        std::fs::write(dir.join(format!("obj{i}")), b"").expect("create");
    }
    let files: Vec<File> = {
        use truenas_ros::sync_fs::{OFlag, OpenHow};
        use truenas_ros::uring_fs::{Anchor, FsConfig, UringFs};
        let mut afs = match UringFs::new(FsConfig::default()) {
            Ok(f) => f,
            Err(e) if should_skip(&e) => return None,
            Err(e) => panic!("UringFs::new: {e}"),
        };
        let who = afs.register_self().expect("register_self");
        let handle = afs.handle();
        let stop_fs = afs.shutdown_handle();
        let anchor = Anchor::open(&dir).expect("anchor");
        let (ftx, frx) = std::sync::mpsc::channel();
        thread::scope(|sc| {
            sc.spawn(move || {
                for i in 0..conns {
                    let name = std::ffi::CString::new(format!("obj{i}")).unwrap();
                    let r = handle.open(who, &anchor, name.as_c_str(), OpenHow::new().flags(OFlag::O_WRONLY));
                    let _ = ftx.send(r);
                }
                stop_fs.shutdown();
            });
            afs.run().expect("fs host run");
        });
        (0..conns)
            .map(|_| frx.recv().expect("open outcome").expect("open"))
            .collect()
    };

    let pers: std::sync::Arc<OnceLock<Personality>> = std::sync::Arc::new(OnceLock::new());
    let pc = std::sync::Arc::clone(&pers);
    let gathers = std::sync::Arc::new(AtomicUsize::new(0));
    let gathers_out = std::sync::Arc::clone(&gathers);
    let copied = std::sync::Arc::new(AtomicUsize::new(0));
    let copied_out = std::sync::Arc::clone(&copied);
    let assigned = std::sync::Arc::new(AtomicUsize::new(0));

    // (next window's offset, first held window's offset, held, ctl, file)
    type St = (u64, u64, Vec<LeasedWindow>, std::sync::Arc<GatherCtl>, File);
    // One completion per gathered write of `n` windows: give their claims back, wake the brake, and settle End once the
    // last write landed.
    fn landed(
        ctl: std::sync::Arc<GatherCtl>,
        n: usize,
    ) -> impl FnOnce(truenas_ros::uring_fs::FsDone, &mut truenas_ros::uring_fs::FsConn<'_>) + 'static {
        move |done, _fs| {
            if done.result().is_err() {
                ctl.failed.store(true, Ordering::Relaxed);
            }
            let left = ctl.flying.fetch_sub(n, Ordering::Relaxed) - n;
            if let Some(d) = ctl.parked.lock().unwrap().take() {
                d.resume();
            }
            let end: Option<HttpDeferred> = if left == 0 {
                ctl.end.lock().unwrap().take()
            } else {
                None
            };
            if let Some(d) = end {
                let code = if ctl.failed.load(Ordering::Relaxed) { 500 } else { 200 };
                d.reply(HttpResponse::new(code));
            }
        }
    }
    let files_for_accept = files.clone();
    let proto = truenas_ros::http::protocol_streaming_fs(
        HttpConfig::default(),
        1 << 30,
        move |_i: Incoming<'_>| -> Option<St> {
            let n = assigned.fetch_add(1, Ordering::Relaxed);
            Some((
                0,
                0,
                Vec::new(),
                std::sync::Arc::new(GatherCtl {
                    flying: AtomicUsize::new(0),
                    failed: std::sync::atomic::AtomicBool::new(false),
                    parked: std::sync::Mutex::new(None),
                    end: std::sync::Mutex::new(None),
                }),
                files_for_accept[n % files_for_accept.len()].clone(),
            ))
        },
        move |req: HttpRequest<'_>, st: &mut St, fs| {
            let (off, held_at, held, ctl, file) = st;
            match req.stage {
                Stage::Open => {
                    (*off, *held_at) = (0, 0);
                    held.clear();
                    HttpVerdict::Continue
                }
                Stage::Window => {
                    let Some(mut fs) = fs else {
                        return HttpVerdict::Respond(HttpResponse::new(500));
                    };
                    let who = *pc.get().expect("personality set");
                    // Decide the brake before `defer_stream` takes `req`.
                    let full = held.len() + 1 == g;
                    let held_next = if full { 0 } else { held.len() + 1 };
                    let flying_next = ctl.flying.load(Ordering::Relaxed) + if full { g } else { 0 };
                    let (body, verdict) = if held_next + flying_next >= cap {
                        let (d, permit, body) = req.defer_stream();
                        *ctl.parked.lock().unwrap() = Some(d);
                        (body, HttpVerdict::Defer(permit))
                    } else {
                        (req.body, HttpVerdict::Continue)
                    };
                    let at = *off;
                    *off += body.len() as u64;
                    let Some(window) = fs.lease_window(&body) else {
                        // Not leasable: write the held run and this window on copies, so the file still comes out
                        // whole.
                        copied.fetch_add(1, Ordering::Relaxed);
                        if !held.is_empty() {
                            let n = held.len();
                            ctl.flying.fetch_add(n, Ordering::Relaxed);
                            fs.pwritev2_leased(
                                who,
                                file.clone(),
                                std::mem::take(held),
                                *held_at,
                                RwFlags::empty(),
                                landed(std::sync::Arc::clone(ctl), n),
                            );
                        }
                        ctl.flying.fetch_add(1, Ordering::Relaxed);
                        fs.pwritev2_from(
                            who,
                            file.clone(),
                            &body,
                            at,
                            RwFlags::empty(),
                            landed(std::sync::Arc::clone(ctl), 1),
                        );
                        return verdict;
                    };
                    if held.is_empty() {
                        *held_at = at;
                    }
                    held.push(window);
                    if full {
                        gathers.fetch_add(1, Ordering::Relaxed);
                        ctl.flying.fetch_add(g, Ordering::Relaxed);
                        fs.pwritev2_leased(
                            who,
                            file.clone(),
                            std::mem::take(held),
                            *held_at,
                            RwFlags::empty(),
                            landed(std::sync::Arc::clone(ctl), g),
                        );
                    }
                    verdict
                }
                Stage::End => {
                    if !held.is_empty() {
                        let Some(mut fs) = fs else {
                            return HttpVerdict::Respond(HttpResponse::new(500));
                        };
                        let who = *pc.get().expect("personality set");
                        let n = held.len();
                        gathers.fetch_add(1, Ordering::Relaxed);
                        ctl.flying.fetch_add(n, Ordering::Relaxed);
                        fs.pwritev2_leased(
                            who,
                            file.clone(),
                            std::mem::take(held),
                            *held_at,
                            RwFlags::empty(),
                            landed(std::sync::Arc::clone(ctl), n),
                        );
                    }
                    if ctl.flying.load(Ordering::Relaxed) == 0 {
                        let code = if ctl.failed.load(Ordering::Relaxed) { 500 } else { 200 };
                        return HttpVerdict::Respond(HttpResponse::new(code));
                    }
                    let (deferred, permit) = req.defer();
                    *ctl.end.lock().unwrap() = Some(deferred);
                    HttpVerdict::Defer(permit)
                }
                Stage::Whole => HttpVerdict::Respond(HttpResponse::new(500)),
            }
        },
    )
    .expect("codec config");

    let cfg = ServerConfig {
        pool_size: conns as u32,
        fs_ops: 64,
        max_request_bytes: 512 * 1024,
        // As above: sized to the cap, a shortfall shows as allocations.
        recv_lease_depth: cap as u32,
        recv_shortage_retry: None,
        ..ServerConfig::default()
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let mut server = match Server::with_config([addr], cfg, proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return None,
        Err(e) => panic!("bind: {e}"),
    };
    pers.set(server.register_self().expect("register_self"))
        .expect("set once");
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stats = server.stats_handle();
    let stop = server.shutdown_handle();

    let payload = vec![0x5au8; mib * 1024 * 1024];
    let wire = std::sync::Arc::new(chunked_put(&payload, 128 * 1024));
    drop(payload);

    let client = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone());
        let before = BIG_ALLOCS.load(Ordering::Relaxed);
        let uploads: Vec<_> = (0..conns)
            .map(|_| {
                let wire = std::sync::Arc::clone(&wire);
                thread::spawn(move || {
                    let mut s = TcpStream::connect(v4).expect("connect");
                    s.set_read_timeout(Some(Duration::from_secs(60))).unwrap();
                    s.write_all(&wire).expect("write");
                    let status = read_status(&mut s).expect("status");
                    assert_eq!(status, 200, "upload refused");
                })
            })
            .collect();
        for u in uploads {
            u.join().expect("upload thread");
        }
        let cost = BIG_ALLOCS.load(Ordering::Relaxed) - before;
        stop.shutdown();
        cost
    });

    server.serve_forever().expect("serve_forever");
    let cost = client.join().expect("client thread");
    let s = stats.snapshot();
    assert!(s.recv_bufs_total > 0, "no ring: {s:?}");
    assert_eq!(s.recv_bufs_lent, 0, "leases not returned: {s:?}");
    let want = vec![0x5au8; mib * 1024 * 1024];
    let ok = (0..conns).all(|i| std::fs::read(dir.join(format!("obj{i}"))).expect("read back") == want);
    Some((
        cost,
        ok,
        gathers_out.load(Ordering::Relaxed),
        copied_out.load(Ordering::Relaxed),
    ))
}

/// Windows held across deliveries and written `g` at a time copy nothing, allocate nothing per window, and return every
/// buffer. That each gather is one `WRITEV` is the unit test's (`a_gathered_write_returns_each_buffer_once`).
#[cfg(feature = "uring-fs")]
#[test]
fn a_gathered_put_writes_held_windows_without_copying_them() {
    let _turn = MEASURING.lock().unwrap_or_else(|e| e.into_inner());
    let (conns, g, cap) = (2, 2, 4);
    let Some((small, ok_small, _, copied_small)) = gathered_put_cost(4, conns, g, cap) else {
        return; // io_uring unavailable
    };
    let Some((large, ok_large, gathers, copied_large)) = gathered_put_cost(16, conns, g, cap) else {
        return;
    };
    assert!(ok_small && ok_large, "file bytes differ");
    assert_eq!(copied_small + copied_large, 0, "every window leased");
    let windows = conns * 16 * 1024 * 1024 / (128 * 1024);
    assert!(
        gathers >= windows / g,
        "{gathers} gathered writes for {windows} windows at {g} a write"
    );
    assert!(
        large <= small + 8,
        "gathered PUT cost scales with payload: 4 MiB cost {small}, 16 MiB \
         cost {large}"
    );
}

/// The exhaustion runs' lease depth, stated so their wall does not move with the default.
#[cfg(feature = "uring-fs")]
const EXHAUSTION_LEASE_DEPTH: u32 = 4;

/// Handler op slots for the exhaustion runs that must not fill the table.
#[cfg(feature = "uring-fs")]
const ROOMY_FS_OPS: u32 = 64;

/// What an exhaustion run waits to see before it drains the FIFO.
#[cfg(feature = "uring-fs")]
#[derive(Clone, Copy, Debug, PartialEq)]
enum Gate {
    /// The recv ring at its bound: reads parked on the retry backoff, or, with the knob off, every buffer the ring can
    /// hold lent.
    RingBound,
    /// A leased write refused for the full op table.
    Refusal,
}

/// What an exhaustion run measured.
#[cfg(feature = "uring-fs")]
struct Exhaustion {
    /// Reads parked on the retry backoff.
    parks: u64,
    /// Leased writes refused for the full op table.
    writes_refused: u64,
    /// Large allocations over the run.
    cost: usize,
    /// Bytes the FIFO drained.
    got: u64,
    /// Every upload answered - 200, unless the run refuses writes - and every written byte drained.
    ok: bool,
}

/// Upload on `conns` connections into ONE FIFO, floating every window's write with `Continue` and never braking - so
/// leases pile until the pipe blocks the writes and the recv ring hits its registered bound. What happens next is
/// `recv_shortage_retry`'s to decide, and this measures it: returns (shortage parks, large allocations, bytes drained,
/// all 200s).
///
/// The test thread holds the FIFO's read end and does NOT drain until the run reaches its gate (parks observed, or
/// every client byte written), so exhaustion is a phase the run provably enters, not a race it may dodge.
#[cfg(feature = "uring-fs")]
#[allow(clippy::too_many_lines)]
fn exhaustion_run(retry: Option<Duration>, per_conn: usize, fs_ops: u32, gate: Gate) -> Option<Exhaustion> {
    use std::os::fd::{FromRawFd, OwnedFd};
    use std::sync::OnceLock;
    use std::sync::atomic::AtomicBool;
    use truenas_ros::http::HttpDeferred;
    use truenas_ros::uring_fs::{File, Personality, RwFlags};

    let tmp = truenas_ros::tempdir().expect("tempdir");
    let dir = tmp.path().to_owned();
    let fifo = dir.join("sink");
    let cpath = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
    // SAFETY: a plain mkfifo(3) on a path this test owns.
    assert_eq!(unsafe { libc::mkfifo(cpath.as_ptr(), 0o600) }, 0, "mkfifo");
    // Hold the read end (nonblocking, so this open never waits and the drain loop can poll a stop flag) BEFORE the
    // server opens the write end - a FIFO O_WRONLY open blocks until a reader exists.
    // SAFETY: open(3) of the fifo just created; the fd is owned below.
    let rfd = unsafe { libc::open(cpath.as_ptr(), libc::O_RDONLY | libc::O_NONBLOCK) };
    assert!(rfd >= 0, "open fifo read end");
    // SAFETY: `rfd` was just returned by open and is owned by nothing else.
    let read_end = unsafe { OwnedFd::from_raw_fd(rfd) };
    // One page of capacity: the first probe write fills it and every write after that BLOCKS in io-wq, holding its
    // window's lease, until the drain makes room - which is the pinning this whole fixture exists for. SAFETY: fcntl(2)
    // on the fd owned just above.
    assert!(
        unsafe { libc::fcntl(rfd, libc::F_SETPIPE_SZ, 4096) } >= 4096,
        "shrink fifo"
    );

    let conns = 2usize;
    // Pre-open the FIFO's write end through a standalone host, exactly as a handler's destination file would be.
    let sink: File = {
        use truenas_ros::sync_fs::{OFlag, OpenHow};
        use truenas_ros::uring_fs::{Anchor, FsConfig, UringFs};
        let mut afs = match UringFs::new(FsConfig::default()) {
            Ok(f) => f,
            Err(e) if should_skip(&e) => return None,
            Err(e) => panic!("UringFs::new: {e}"),
        };
        let who = afs.register_self().expect("register_self");
        let handle = afs.handle();
        let stop_fs = afs.shutdown_handle();
        let anchor = Anchor::open(&dir).expect("anchor");
        let (ftx, frx) = std::sync::mpsc::channel();
        thread::scope(|sc| {
            sc.spawn(move || {
                let name = std::ffi::CString::new("sink").unwrap();
                let r = handle.open(who, &anchor, name.as_c_str(), OpenHow::new().flags(OFlag::O_WRONLY));
                let _ = ftx.send(r);
                stop_fs.shutdown();
            });
            afs.run().expect("fs host run");
        });
        frx.recv().expect("open outcome").expect("open fifo")
    };

    let pers: std::sync::Arc<OnceLock<Personality>> = std::sync::Arc::new(OnceLock::new());
    let pc = std::sync::Arc::clone(&pers);

    type St = (std::sync::Arc<PipeCtl>, File);
    let written = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let written_in = std::sync::Arc::clone(&written);
    let refused = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let refused_in = std::sync::Arc::clone(&refused);
    let sink_for_accept = sink.clone();
    let proto = truenas_ros::http::protocol_streaming_fs(
        HttpConfig::default(),
        1 << 30,
        move |_i: Incoming<'_>| -> Option<St> {
            Some((
                std::sync::Arc::new(PipeCtl {
                    inflight: AtomicUsize::new(0),
                    peak: AtomicUsize::new(0),
                    failed: std::sync::atomic::AtomicBool::new(false),
                    parked: std::sync::Mutex::new(None),
                    end: std::sync::Mutex::new(None),
                }),
                sink_for_accept.clone(),
            ))
        },
        move |req: HttpRequest<'_>, st: &mut St, fs| {
            let (ctl, file) = st;
            match req.stage {
                Stage::Open => HttpVerdict::Continue,
                Stage::Window => {
                    let Some(mut fs) = fs else {
                        return HttpVerdict::Respond(HttpResponse::new(500));
                    };
                    let who = *pc.get().expect("personality set");
                    ctl.inflight.fetch_add(1, Ordering::Relaxed);
                    let done_ctl = std::sync::Arc::clone(ctl);
                    let done_written = std::sync::Arc::clone(&written_in);
                    let done_refused = std::sync::Arc::clone(&refused_in);
                    let cont = move |done: truenas_ros::uring_fs::FsDone,
                                     _fs: &mut truenas_ros::uring_fs::FsConn<'_>| {
                        if done.was_refused() {
                            done_refused.fetch_add(1, Ordering::Relaxed);
                        }
                        match done.result() {
                            Err(_) => done_ctl.failed.store(true, Ordering::Relaxed),
                            Ok(n) => {
                                done_written.fetch_add(n as u64, Ordering::Relaxed);
                            }
                        }
                        let left = done_ctl.inflight.fetch_sub(1, Ordering::Relaxed) - 1;
                        let end: Option<HttpDeferred> = if left == 0 {
                            done_ctl.end.lock().unwrap().take()
                        } else {
                            None
                        };
                        if let Some(d) = end {
                            if done_ctl.failed.load(Ordering::Relaxed) {
                                d.reply(HttpResponse::new(500));
                            } else {
                                d.reply(HttpResponse::new(200));
                            }
                        }
                    };
                    // Float every window with no depth cap, and write only its first page. A pipe write of at most
                    // PIPE_BUF is atomic (pipe(7)), so it never completes short and trips the leased-write EIO rule,
                    // while the subrange still holds the whole window's lease until the pipe makes room. A stream write
                    // has no position, and `u64::MAX` is the no-offset sentinel the kernel maps to f_pos
                    // (`io_kiocb_update_pos`, io_uring/rw.c).
                    let probe = 4096.min(req.body.len());
                    fs.pwritev2_from(who, file.clone(), &req.body[..probe], u64::MAX, RwFlags::empty(), cont);
                    HttpVerdict::Continue
                }
                Stage::End => {
                    if ctl.inflight.load(Ordering::Relaxed) == 0 {
                        let code = if ctl.failed.load(Ordering::Relaxed) { 500 } else { 200 };
                        return HttpVerdict::Respond(HttpResponse::new(code));
                    }
                    let (deferred, permit) = req.defer();
                    *ctl.end.lock().unwrap() = Some(deferred);
                    HttpVerdict::Defer(permit)
                }
                Stage::Whole => HttpVerdict::Respond(HttpResponse::new(500)),
            }
        },
    )
    .expect("codec config");

    let cfg = ServerConfig {
        pool_size: conns as u32,
        fs_ops,
        max_request_bytes: 512 * 1024,
        recv_lease_depth: EXHAUSTION_LEASE_DEPTH,
        recv_shortage_retry: retry,
        ..ServerConfig::default()
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let mut server = match Server::with_config([addr], cfg, proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return None,
        Err(e) => panic!("bind: {e}"),
    };
    pers.set(server.register_self().expect("register_self"))
        .expect("set once");
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stats = server.stats_handle();
    let stats_gate = stats.clone();
    let stop = server.shutdown_handle();

    let payload = vec![0xc3u8; per_conn];
    let wire = std::sync::Arc::new(chunked_put(&payload, 128 * 1024));
    drop(payload);

    let drained = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let stop_drain = std::sync::Arc::new(AtomicBool::new(false));

    // The drain waits until the run provably exhausts the ring (parks observed when the knob is on, the lent gauge
    // pinned at the ring's registered bound when it is off, a write refused for the full table in a refusal run), then
    // empties the FIFO so the writes and their leases come home. Without the gate a fast drain lets the leases cycle
    // and the assertions hold vacuously. The bound is the pool's demand, the lease depth plus the arriving message, per
    // connection.
    let ring_bound = conns as u32 * (EXHAUSTION_LEASE_DEPTH + 1);
    let gate_on_parks = retry.is_some();
    let d_count = std::sync::Arc::clone(&drained);
    let d_stop = std::sync::Arc::clone(&stop_drain);
    let d_refused = std::sync::Arc::clone(&refused);
    let drain = thread::spawn(move || {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        let gated = loop {
            let s = stats_gate.snapshot();
            let gated = match gate {
                Gate::Refusal => d_refused.load(Ordering::Relaxed) > 0,
                Gate::RingBound if gate_on_parks => s.recv_shortage_parks > 0,
                Gate::RingBound => s.recv_bufs_lent >= ring_bound,
            };
            if gated || std::time::Instant::now() > deadline {
                break gated;
            }
            thread::sleep(Duration::from_millis(5));
        };
        let mut buf = vec![0u8; 64 * 1024];
        while !d_stop.load(Ordering::Relaxed) {
            // SAFETY: reading the owned nonblocking fd into a live buffer.
            let n = unsafe { libc::read(rfd, buf.as_mut_ptr().cast(), buf.len()) };
            if n > 0 {
                d_count.fetch_add(n as u64, Ordering::Relaxed);
            } else {
                thread::sleep(Duration::from_millis(2));
            }
        }
        drop(read_end);
        gated
    });

    let client = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone());
        let before = BIG_ALLOCS.load(Ordering::Relaxed);
        let upload = move |wire: &[u8]| {
            let mut s = TcpStream::connect(v4).expect("connect");
            s.set_read_timeout(Some(Duration::from_secs(60))).unwrap();
            s.write_all(wire).expect("write");
            read_status(&mut s).expect("status")
        };
        let uploads: Vec<_> = (0..conns)
            .map(|_| {
                let wire = std::sync::Arc::clone(&wire);
                thread::spawn(move || upload(&wire))
            })
            .collect();
        // A refused window fails its upload, answered from its last completion.
        let ok = uploads.into_iter().all(|u| {
            let status = u.join().expect("upload thread");
            status == 200 || (gate == Gate::Refusal && status == 500)
        });
        let cost = BIG_ALLOCS.load(Ordering::Relaxed) - before;
        stop.shutdown();
        (cost, ok)
    });

    server.serve_forever().expect("serve_forever");
    let (cost, ok) = client.join().expect("client thread");
    // Every page the handler's writes reported must come out of the FIFO before the drain stops (the responses settled,
    // so the writes did).
    let total = written.load(Ordering::Relaxed);
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while drained.load(Ordering::Relaxed) < total && std::time::Instant::now() < deadline {
        thread::sleep(Duration::from_millis(5));
    }
    stop_drain.store(true, Ordering::Relaxed);
    let gated = drain.join().expect("drain thread");
    // A gate that timed out measured an ordinary upload.
    assert!(
        gated,
        "the run never reached its gate ({gate:?}, ring bound {ring_bound})"
    );
    let s = stats.snapshot();
    assert_eq!(s.recv_bufs_lent, 0, "leases not returned: {s:?}");
    let got = drained.load(Ordering::Relaxed);
    Some(Exhaustion {
        parks: s.recv_shortage_parks,
        writes_refused: refused.load(Ordering::Relaxed),
        cost,
        got,
        ok: ok && total > 0 && got == total,
    })
}

/// Genuine pool exhaustion with `recv_shortage_retry` set parks the reads instead of falling back to owned buffers. The
/// uploads stall against TCP until the FIFO drains, then complete intact, and the cost stays flat when the upload
/// doubles, because a parked read allocates nothing while it waits. The run's baseline (the pool growing to its
/// registered bound, the fixture's own buffers) is a constant, so the claim is no per-window cost on top of it. The
/// parks counter proves each run entered exhaustion rather than dodging it.
#[cfg(feature = "uring-fs")]
#[test]
fn exhaustion_parks_reads_instead_of_allocating() {
    let _turn = MEASURING.lock().unwrap_or_else(|e| e.into_inner());
    let retry = Some(Duration::from_millis(2));
    // 12 and 24 windows a connection, both past the wall of 10 two connections hold between them.
    let Some(one) = exhaustion_run(retry, 1536 * 1024, ROOMY_FS_OPS, Gate::RingBound) else {
        return; // io_uring unavailable here
    };
    let two = exhaustion_run(retry, 3072 * 1024, ROOMY_FS_OPS, Gate::RingBound).expect("second run");
    assert!(
        one.ok && two.ok,
        "uploads failed or bytes lost ({}, {})",
        one.got,
        two.got
    );
    assert!(
        one.parks > 0 && two.parks > 0,
        "the pool never exhausted: nothing was proven ({}, {})",
        one.parks,
        two.parks
    );
    assert!(
        two.cost <= one.cost + 2,
        "parked backpressure allocated per window: {} large allocations \
         for 12 windows/conn, {} for 24",
        one.cost,
        two.cost
    );
}

/// The control. `None` falls back to owned buffers and keeps every connection moving, so the same uploads complete
/// without a single park.
#[cfg(feature = "uring-fs")]
#[test]
fn exhaustion_without_the_knob_completes_without_parking() {
    let _turn = MEASURING.lock().unwrap_or_else(|e| e.into_inner());
    let Some(run) = exhaustion_run(None, 1536 * 1024, ROOMY_FS_OPS, Gate::RingBound) else {
        return; // io_uring unavailable here
    };
    assert!(run.ok, "uploads failed or bytes lost (drained {})", run.got);
    assert_eq!(run.parks, 0, "None must never park");
}

/// With room in the op table for one handler op, a pipelined upload's leased writes are refused once the table fills:
/// every upload is still answered, every byte a write reported lands, and every buffer comes home once.
#[cfg(feature = "uring-fs")]
#[test]
fn a_full_op_table_refuses_leased_writes_and_returns_their_buffers() {
    let _turn = MEASURING.lock().unwrap_or_else(|e| e.into_inner());
    let retry = Some(Duration::from_millis(2));
    let Some(run) = exhaustion_run(retry, 1536 * 1024, 1, Gate::Refusal) else {
        return; // io_uring unavailable here
    };
    assert!(run.writes_refused > 0, "the table never filled");
    assert!(
        run.ok,
        "an upload went unanswered or bytes were lost (drained {})",
        run.got
    );
}
