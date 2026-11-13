use super::*;

#[cfg(feature = "uring-fs")]
#[test]
fn server_builds_with_fs_pool() {
    // A server with `fs_ops` set drives an fs reactor on the same ring, its op table sized `fs_ops + pool_size`. Open
    // files are plain raw fds, not registered-table slots, so the connection pool stays `pool_size`. Constructing it
    // exercises that path on a real ring; a plain echo still serves over the same ring.
    let cfg = ServerConfig {
        pool_size: 16,
        fs_ops: 16,
        ..ServerConfig::default()
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let mut server = match Server::with_config([addr], cfg, length_prefixed(PrefixWidth::U32, Endian::Big, false, echo))
    {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind with fs pool: {e}"),
    };
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();
    let client = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone()); // fail fast on panic
        let r = one_shot(v4, 0);
        stop.shutdown();
        r
    });
    server.serve_forever().expect("serve_forever with fs pool");
    assert_eq!(client.join().unwrap().expect("client io"), b"req-0");
}

/// A graceful drain waits for a task, and stops as soon as it retires.
///
/// The wait is deliberate - a task outlives the connection that spawned it - but the quiescence test has to be re-read
/// somewhere the gauge falling can reach, or the drain sits out its whole grace period and leaves through the
/// `Deadline` hard stop instead. The grace here is long and the task is short, so the two outcomes are seconds apart.
///
/// **Bounded on both sides, because both failures are silent.** The upper bound catches a drain that hangs to its
/// deadline. The lower one catches the opposite and worse mutation - a drain that stops ignoring tasks altogether,
/// dropping their work on the floor - which on a `SIGTERM` with a long grace looks exactly like a clean shutdown.
/// Without it, discarding the task gauge entirely leaves this test green.
#[cfg(feature = "uring-fs")]
#[test]
fn a_graceful_drain_ends_when_its_last_task_retires() {
    let cfg = ServerConfig {
        pool_size: 4,
        fs_ops: 8,
        ..ServerConfig::default()
    };
    let body = move |mut req: Request<'_, ()>| -> Response {
        let Some(mut fs) = req.fs.take() else {
            return Response::Close;
        };
        // Pending with no connection and no ring op: the shape a connection count cannot see. It outlives the reply
        // below and the close that follows it.
        drop(fs.spawn(|t| async move {
            let _ = t
                .offload_fut(|| {
                    thread::sleep(Duration::from_millis(300));
                    Ok(())
                })
                .await;
        }));
        Response::Reply(echo_frame(b"spawned"))
    };
    let protocol = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(PrefixWidth::U32, Endian::Big, false),
        body,
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let mut server = match Server::with_config([addr], cfg, protocol) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind with fs pool: {e}"),
    };
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();
    const GRACE: Duration = Duration::from_secs(5);
    let client = thread::spawn(move || -> io::Result<()> {
        let mut c = connect_tcp(v4)?;
        send_framed(&mut c, b"go")?;
        assert_eq!(recv_framed(&mut c)?, b"spawned");
        // The task is still pending; the table empties behind it.
        drop(c);
        stop.shutdown_graceful(GRACE);
        Ok(())
    });
    let began = Instant::now();
    server.serve_forever().expect("serve_forever");
    let took = began.elapsed();
    client.join().expect("client thread").expect("client io");
    assert!(
        took < GRACE / 2,
        "the drain ran to its grace deadline ({took:?}) rather than \
         stopping when the task retired"
    );
    assert!(
        took >= Duration::from_millis(250),
        "the drain stopped in {took:?}, inside the task's own 300 ms - so \
         it did not wait for the task at all and dropped its work"
    );
}

/// The M4 headline: a static-file server. Each request names a file; the body handler opens it on the server's own ring
/// under a per-connection [`Personality`], reads it, and replies with its contents - all inline on the loop thread via
/// `Request::fs` and the `Deferred` reuse (open -> read -> reply, no worker thread, no blocking the ring). Two requests
/// on one keep-alive connection prove the fixed-file slot is opened and freed per request rather than leaked.
#[cfg(feature = "uring-fs")]
#[test]
fn fs_static_file_server_open_read_reply() {
    use std::ffi::CString;
    use std::sync::OnceLock;
    use truenas_ros::sync_fs::{OFlag, OpenHow};
    use truenas_ros::uring_fs::{Anchor, Personality, RwFlags};

    let dir = truenas_ros::tempdir().unwrap();
    std::fs::write(dir.path().join("hello.txt"), b"contents of hello").unwrap();
    std::fs::write(dir.path().join("second.txt"), b"the second file").unwrap();

    // The reactor's own creds, minted after construction; the handler reads it through a shared cell (the closure is
    // moved into the server first).
    let pers: Arc<OnceLock<Personality>> = Arc::new(OnceLock::new());
    let anchor = match Anchor::open(dir.path()) {
        Ok(a) => a,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("anchor open: {e}"),
    };

    let pc = Arc::clone(&pers);
    let body = move |mut req: Request<'_, ()>| -> Response {
        let name = req.body.take(); // the requested filename
        let (deferred, permit) = req.responder.defer();
        let Some(mut fs) = req.fs.take() else {
            return Response::Close; // built without an fs pool
        };
        let who = *pc.get().expect("personality set before serving");
        let anchor = anchor.clone();
        let Ok(path) = CString::new(name) else {
            deferred.close();
            return Response::Defer(permit);
        };
        let how = OpenHow::new().flags(OFlag::O_RDONLY);
        fs.open(who, &anchor, &path, how, move |done, fs| {
            let Some(file) = done.file() else {
                deferred.close(); // open failed (ENOENT/EACCES - the personality working)
                return;
            };
            fs.preadv2(
                who,
                file.clone(),
                vec![vec![0u8; 4096]],
                0,
                RwFlags::empty(),
                move |done, fs| {
                    fs.close(file); // fire-and-forget: free the slot
                    match done.result() {
                        Ok(n) => {
                            let mut buf = done.into_bufs().pop().unwrap_or_default();
                            buf.truncate(n as usize);
                            deferred.reply(echo_frame(&buf));
                        }
                        Err(_) => deferred.close(),
                    }
                },
            );
        });
        Response::Defer(permit)
    };
    let protocol = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(PrefixWidth::U32, Endian::Big, false),
        body,
    };
    let cfg = ServerConfig {
        pool_size: 16,
        fs_ops: 16,
        ..ServerConfig::default()
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let mut server = match Server::with_config([addr], cfg, protocol) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind with fs pool: {e}"),
    };
    pers.set(server.register_self().expect("register_self")).unwrap();
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();
    let client = thread::spawn(move || -> io::Result<(Vec<u8>, Vec<u8>)> {
        let _stop = ShutdownOnDrop(stop.clone()); // fail fast on panic
        let mut s = connect_tcp(v4)?;
        // Two files on ONE keep-alive connection: proves per-request open/close.
        send_framed(&mut s, b"hello.txt")?;
        let first = recv_framed(&mut s)?;
        send_framed(&mut s, b"second.txt")?;
        let second = recv_framed(&mut s)?;
        drop(s);
        stop.shutdown();
        Ok((first, second))
    });
    server.serve_forever().expect("serve_forever static-file");
    let (first, second) = client.join().unwrap().expect("client io");
    assert_eq!(first, b"contents of hello");
    assert_eq!(second, b"the second file");
}

/// A directory listing replies through the wake drain. The handler lists on the ring via `open_dir`/`next_batch`, both
/// delivered by off-loop worker jobs that poke the wake, and answers with the entry count via its `Deferred`.
/// The reply only arrives if `on_wake` drains the fs offload pool; without that drain the completion is stranded, the
/// request never answers, and the client read times out. The socket read timeout makes that regression a failure rather
/// than a hang.
#[cfg(feature = "uring-fs")]
#[test]
fn fs_dir_listing_replies_through_the_wake_drain() {
    use std::rc::Rc;
    use std::sync::OnceLock;
    use std::time::Duration;
    use truenas_ros::uring_fs::{Anchor, Personality};

    let dir = truenas_ros::tempdir().unwrap();
    for i in 0..3 {
        std::fs::write(dir.path().join(format!("f{i}")), b"x").unwrap();
    }

    let pers: Arc<OnceLock<Personality>> = Arc::new(OnceLock::new());
    let anchor = match Anchor::open(dir.path()) {
        Ok(a) => a,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("anchor open: {e}"),
    };

    let pc = Arc::clone(&pers);
    let body = move |mut req: Request<'_, ()>| -> Response {
        let (deferred, permit) = req.responder.defer();
        let Some(mut fs) = req.fs.take() else {
            return Response::Close; // built without an fs pool
        };
        let who = *pc.get().expect("personality set before serving");
        let anchor = anchor.clone();
        fs.open_dir(who, &anchor, move |res, fs| {
            let walk = match res {
                Ok(w) => Rc::new(w),
                Err(_) => return deferred.close(),
            };
            // Hold the walk alive through the batch delivery: the `keep` clone rides in the continuation, so the `DIR*`
            // is not dropped mid-flight.
            let keep = Rc::clone(&walk);
            fs.next_batch(&walk, move |res, _fs| {
                let _keep = keep;
                match res {
                    Ok(batch) => {
                        deferred.reply(echo_frame(batch.names.len().to_string().as_bytes()));
                    }
                    Err(_) => deferred.close(),
                }
            });
        });
        Response::Defer(permit)
    };
    let protocol = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(PrefixWidth::U32, Endian::Big, false),
        body,
    };
    let cfg = ServerConfig {
        pool_size: 16,
        fs_ops: 16,
        ..ServerConfig::default()
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let mut server = match Server::with_config([addr], cfg, protocol) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind with fs pool: {e}"),
    };
    pers.set(server.register_self().expect("register_self")).unwrap();
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();
    let client = thread::spawn(move || -> io::Result<Vec<u8>> {
        let _stop = ShutdownOnDrop(stop.clone()); // fail fast on panic
        let mut s = connect_tcp(v4)?;
        s.set_read_timeout(Some(Duration::from_secs(5)))?;
        send_framed(&mut s, b"list")?;
        let reply = recv_framed(&mut s); // times out if the drain is missing
        drop(s);
        stop.shutdown(); // unconditional: unblock serve_forever even on timeout
        reply
    });
    server.serve_forever().expect("serve_forever dir-listing");
    let reply = client.join().unwrap().expect("client io");
    assert_eq!(reply, b"3", "listing counted the three entries and replied");
}

/// A server's lookup lane takes its bounds from `ServerConfig`, and its results reach the handler's `Deferred` through
/// the wake drain. The first lookup waits for the second, which runs alongside it only if the lane has a second thread.
/// At a ceiling of one it cannot, so the first gives up and the reply says they ran one at a time.
#[cfg(feature = "uring-fs")]
#[test]
fn a_servers_lookup_lane_takes_its_bounds_from_the_config() {
    use std::sync::mpsc;
    use std::time::Duration;

    let body = |mut req: Request<'_, ()>| -> Response {
        let (deferred, permit) = req.responder.defer();
        let Some(mut fs) = req.fs.take() else {
            return Response::Close; // built without an fs pool
        };
        let (tx, rx) = mpsc::channel::<()>();
        fs.offload_lookup(
            move || Ok(rx.recv_timeout(Duration::from_secs(2)).is_ok()),
            move |res, _fs| match res {
                Ok(true) => deferred.reply(echo_frame(b"together")),
                Ok(false) => deferred.reply(echo_frame(b"one at a time")),
                Err(_) => deferred.close(),
            },
        );
        fs.offload_lookup(
            move || {
                tx.send(()).ok();
                Ok(())
            },
            |_res, _fs| {},
        );
        Response::Defer(permit)
    };
    let protocol = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(PrefixWidth::U32, Endian::Big, false),
        body,
    };
    let cfg = ServerConfig {
        pool_size: 16,
        fs_ops: 16,
        lookup_offload_floor: 1,
        lookup_offload_ceiling: 1,
        ..ServerConfig::default()
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let mut server = match Server::with_config([addr], cfg, protocol) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind with fs pool: {e}"),
    };
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();
    let client = thread::spawn(move || -> io::Result<Vec<u8>> {
        let _stop = ShutdownOnDrop(stop.clone()); // fail fast on panic
        let mut s = connect_tcp(v4)?;
        s.set_read_timeout(Some(Duration::from_secs(10)))?;
        send_framed(&mut s, b"look")?;
        let reply = recv_framed(&mut s);
        drop(s);
        // Unconditional, so serve_forever ends even on a timeout.
        stop.shutdown();
        reply
    });
    server.serve_forever().expect("serve_forever lookups");
    let reply = client.join().unwrap().expect("client io");
    assert_eq!(reply, b"one at a time", "the lane kept to one thread");
}

/// `FsConn::flistxattr` enumerates a file's xattr names on-loop: it opens the file on the ring, offloads the
/// `flistxattr` to the pool, and delivers the names on the loop, answered via `Deferred` (same drain path as the
/// listing).
#[cfg(feature = "uring-fs")]
#[test]
fn fs_conn_flistxattr_lists_file_xattrs() {
    use std::sync::OnceLock;
    use std::time::Duration;
    use truenas_ros::sync_fs::{OFlag, OpenHow};
    use truenas_ros::uring_fs::{Anchor, Personality};

    let dir = truenas_ros::tempdir().unwrap();
    let fp = dir.path().join("f.txt");
    std::fs::write(&fp, b"x").unwrap();
    // Seed two user xattrs with a plain syscall (independent of fd-xattr support, which only gates the ring read/write
    // ops). Through `set_user_xattr`, which holds the refusal to `TRUENAS_ROS_REQUIRE_XATTRS`: every assertion below is
    // behind this probe, so a hand-rolled `libc::setxattr` with a silent `return` reports ok having tested nothing on a
    // filesystem without xattrs.
    if !set_user_xattr(&fp, b"user.a", b"1") || !set_user_xattr(&fp, b"user.b", b"22") {
        return; // this fs refuses user xattrs
    }

    let pers: Arc<OnceLock<Personality>> = Arc::new(OnceLock::new());
    let anchor = match Anchor::open(dir.path()) {
        Ok(a) => a,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("anchor open: {e}"),
    };

    let pc = Arc::clone(&pers);
    let body = move |mut req: Request<'_, ()>| -> Response {
        let (deferred, permit) = req.responder.defer();
        let Some(mut fs) = req.fs.take() else {
            return Response::Close;
        };
        let who = *pc.get().expect("personality set before serving");
        let anchor = anchor.clone();
        let how = OpenHow::new().flags(OFlag::O_RDONLY);
        fs.open(who, &anchor, c"f.txt", how, move |done, fs| {
            let Some(file) = done.file() else {
                return deferred.close();
            };
            fs.flistxattr(file, move |res, _fs| match res {
                Ok(names) => {
                    let joined = names
                        .iter()
                        .map(|c| c.to_string_lossy().into_owned())
                        .collect::<Vec<_>>()
                        .join("\n");
                    deferred.reply(echo_frame(joined.as_bytes()));
                }
                Err(_) => deferred.close(),
            });
        });
        Response::Defer(permit)
    };
    let protocol = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(PrefixWidth::U32, Endian::Big, false),
        body,
    };
    let cfg = ServerConfig {
        pool_size: 16,
        fs_ops: 16,
        ..ServerConfig::default()
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let mut server = match Server::with_config([addr], cfg, protocol) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind with fs pool: {e}"),
    };
    pers.set(server.register_self().expect("register_self")).unwrap();
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();
    let client = thread::spawn(move || -> io::Result<Vec<u8>> {
        let _stop = ShutdownOnDrop(stop.clone()); // fail fast on panic
        let mut s = connect_tcp(v4)?;
        s.set_read_timeout(Some(Duration::from_secs(5)))?;
        send_framed(&mut s, b"list")?;
        let reply = recv_framed(&mut s);
        drop(s);
        stop.shutdown();
        reply
    });
    server.serve_forever().expect("serve_forever flistxattr");
    let reply = client.join().unwrap().expect("client io");
    let text = String::from_utf8_lossy(&reply);
    assert!(text.contains("user.a"), "flistxattr listed user.a: {text:?}");
    assert!(text.contains("user.b"), "flistxattr listed user.b: {text:?}");
}

/// `FsConn::fstatfs`/`fstatfs_anchor` answer on-loop: each offloads to the pool (io_uring has no statfs opcode) and
/// delivers through the completion sink. Both name the same filesystem, so their answers must agree - and the anchor
/// form proves an `O_PATH` descriptor is accepted, which is what lets a caller ask a whole tree's capacity without
/// opening anything inside it.
#[cfg(feature = "uring-fs")]
#[test]
fn fs_conn_fstatfs_agrees_from_file_and_anchor() {
    use std::sync::OnceLock;
    use std::time::Duration;
    use truenas_ros::sync_fs::{OFlag, OpenHow};
    use truenas_ros::uring_fs::{Anchor, Personality};

    let dir = truenas_ros::tempdir().unwrap();
    std::fs::write(dir.path().join("f.txt"), b"x").unwrap();

    let pers: Arc<OnceLock<Personality>> = Arc::new(OnceLock::new());
    let anchor = match Anchor::open(dir.path()) {
        Ok(a) => a,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("anchor open: {e}"),
    };

    let pc = Arc::clone(&pers);
    let body = move |mut req: Request<'_, ()>| -> Response {
        let (deferred, permit) = req.responder.defer();
        let Some(mut fs) = req.fs.take() else {
            return Response::Close;
        };
        let who = *pc.get().expect("personality set before serving");
        let anchor = anchor.clone();
        let how = OpenHow::new().flags(OFlag::O_RDONLY);
        // `open` first, then the offloads chain behind it - the chain is what this test is about. (Every facade can
        // open, an offload-delivery continuation's included; the gate that once said otherwise is gone.)
        fs.open(who, &anchor.clone(), c"f.txt", how, move |done, fs| {
            let Some(file) = done.file() else {
                return deferred.reply(echo_frame(format!("OPEN {:?}", done.result()).as_bytes()));
            };
            fs.fstatfs(file, move |by_file, fs| {
                let by_file = match by_file {
                    Ok(v) => v,
                    Err(e) => {
                        return deferred.reply(echo_frame(format!("FILE {e}").as_bytes()));
                    }
                };
                // offload -> offload: the second continuation still reaches the pool, and an O_PATH anchor is a valid
                // target.
                fs.fstatfs_anchor(&anchor, move |by_anchor, _fs| {
                    let msg = match by_anchor {
                        Ok(a) => {
                            let ok = a.block_size() > 0
                                && a.total_blocks() > 0
                                && a.block_size() == by_file.block_size()
                                && a.total_blocks() == by_file.total_blocks()
                                && a.available_blocks() <= a.free_blocks()
                                && a.total_bytes() == a.total_blocks() * a.block_size();
                            format!(
                                "{} bs={} total={}",
                                if ok { "agree" } else { "DISAGREE" },
                                a.block_size(),
                                a.total_blocks()
                            )
                        }
                        Err(e) => format!("ANCHOR {e}"),
                    };
                    deferred.reply(echo_frame(msg.as_bytes()));
                });
            });
        });
        Response::Defer(permit)
    };
    let protocol = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(PrefixWidth::U32, Endian::Big, false),
        body,
    };
    let cfg = ServerConfig {
        pool_size: 16,
        fs_ops: 16,
        ..ServerConfig::default()
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let mut server = match Server::with_config([addr], cfg, protocol) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind with fs pool: {e}"),
    };
    pers.set(server.register_self().expect("register_self")).unwrap();
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();
    let client = thread::spawn(move || -> io::Result<Vec<u8>> {
        let _stop = ShutdownOnDrop(stop.clone()); // fail fast on panic
        let mut s = connect_tcp(v4)?;
        s.set_read_timeout(Some(Duration::from_secs(5)))?;
        send_framed(&mut s, b"statfs")?;
        let reply = recv_framed(&mut s);
        drop(s);
        stop.shutdown();
        reply
    });
    server.serve_forever().expect("serve_forever fstatfs");
    let reply = client.join().unwrap().expect("client io");
    let text = String::from_utf8_lossy(&reply);
    assert!(
        text.starts_with("agree "),
        "file and anchor must report one filesystem: {text:?}"
    );
}

/// `FsConn::fget_zfs_attrs`/`fset_zfs_attrs` on-loop: read the mask, set `IMMUTABLE`, read it back, and restore - each
/// hop an offload delivered through the completion sink.
///
/// Needs a real ZFS dataset; on tmpfs the ioctl is `ENOTTY`. Resolved the way `test/zfs.rs` does, and skipped loudly
/// under `TRUENAS_ROS_REQUIRE_ZFS` so a runner that stopped provisioning one goes red rather than reporting a green
/// suite that exercised nothing.
#[cfg(feature = "uring-fs")]
#[test]
fn fs_conn_zfs_attrs_round_trip_through_the_pool() {
    use std::path::PathBuf;
    use std::sync::OnceLock;
    use std::time::Duration;
    use truenas_ros::sync_fs::{OFlag, OpenHow, ZfsAttr};
    use truenas_ros::uring_fs::{Anchor, Personality};

    let ds = ["TRUENAS_ROS_NFS4_DATASET", "TRUENAS_ROS_POSIX_DATASET"]
        .iter()
        .filter_map(|v| std::env::var_os(v).map(PathBuf::from))
        .chain(["/NFSV4ACL", "/POSIXACL"].iter().map(PathBuf::from))
        .find(|d| d.is_dir());
    let Some(ds) = ds else {
        assert!(
            std::env::var_os("TRUENAS_ROS_REQUIRE_ZFS").is_none(),
            "TRUENAS_ROS_REQUIRE_ZFS is set but no ZFS dataset is present"
        );
        return;
    };
    let fp = ds.join("ros-fsconn-zfsattr.bin");
    let _ = std::fs::remove_file(&fp);
    std::fs::write(&fp, b"x").unwrap();

    let pers: Arc<OnceLock<Personality>> = Arc::new(OnceLock::new());
    let anchor = match Anchor::open(ds.as_path()) {
        Ok(a) => a,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("anchor open: {e}"),
    };

    let pc = Arc::clone(&pers);
    let body = move |mut req: Request<'_, ()>| -> Response {
        let (deferred, permit) = req.responder.defer();
        let Some(mut fs) = req.fs.take() else {
            return Response::Close;
        };
        let who = *pc.get().expect("personality set before serving");
        let anchor = anchor.clone();
        let how = OpenHow::new().flags(OFlag::O_RDWR);
        fs.open(who, &anchor, c"ros-fsconn-zfsattr.bin", how, move |done, fs| {
            let Some(file) = done.file() else {
                return deferred.reply(echo_frame(format!("OPEN {:?}", done.result()).as_bytes()));
            };
            let f2 = file.clone();
            let f3 = file.clone();
            fs.fget_zfs_attrs(file, move |before, fs| {
                let before = match before {
                    Ok(v) => v,
                    Err(e) => {
                        return deferred.reply(echo_frame(format!("GET {e}").as_bytes()));
                    }
                };
                fs.fset_zfs_attrs(f2, before | ZfsAttr::IMMUTABLE, move |set, fs| {
                    if let Err(e) = set {
                        return deferred.reply(echo_frame(format!("SET {e}").as_bytes()));
                    }
                    fs.fget_zfs_attrs(f3.clone(), move |after, fs| {
                        let locked = matches!(&after, Ok(a)
                                    if a.contains(ZfsAttr::IMMUTABLE));
                        // Restore before answering, or the dataset is left with an undeletable file.
                        fs.fset_zfs_attrs(f3, before, move |r, _fs| {
                            let msg = if !locked {
                                format!("NOTLOCKED {after:?}")
                            } else if r.is_err() {
                                "UNLOCK-FAILED".to_string()
                            } else {
                                "locked-then-restored".to_string()
                            };
                            deferred.reply(echo_frame(msg.as_bytes()));
                        });
                    });
                });
            });
        });
        Response::Defer(permit)
    };
    let protocol = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(PrefixWidth::U32, Endian::Big, false),
        body,
    };
    let cfg = ServerConfig {
        pool_size: 16,
        fs_ops: 16,
        ..ServerConfig::default()
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let mut server = match Server::with_config([addr], cfg, protocol) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind with fs pool: {e}"),
    };
    pers.set(server.register_self().expect("register_self")).unwrap();
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();
    let client = thread::spawn(move || -> io::Result<Vec<u8>> {
        let _stop = ShutdownOnDrop(stop.clone()); // fail fast on panic
        let mut s = connect_tcp(v4)?;
        s.set_read_timeout(Some(Duration::from_secs(5)))?;
        send_framed(&mut s, b"attrs")?;
        let reply = recv_framed(&mut s);
        drop(s);
        stop.shutdown();
        reply
    });
    server.serve_forever().expect("serve_forever zfs attrs");
    let reply = client.join().unwrap().expect("client io");
    let text = String::from_utf8_lossy(&reply).into_owned();
    let _ = std::fs::remove_file(&fp);
    // Unprivileged, setting IMMUTABLE is refused - which is the property under test, so assert that rather than
    // treating it as a skip.
    if text.starts_with("SET ") {
        assert!(
            text.contains("EPERM") && !is_root(),
            "only an unprivileged caller may be refused: {text:?}"
        );
        return;
    }
    assert_eq!(text, "locked-then-restored", "round trip through the pool");
}

/// The batched-blocking-offload consumer shape, end to end: the credential-checked open runs on the ring as a
/// personality-stamped SQE, then ONE `FsConn::offload_result` job runs the whole blocking metadata tail - `statx` plus
/// two xattr reads on the already-authorized fd (`File` is `AsFd`) - and the delivery arrives through the wake path's
/// `drain_fs_offloads` on an owner-scoped continuation facade.
#[cfg(feature = "uring-fs")]
#[test]
fn fs_conn_offload_result_batches_statx_and_xattrs_in_one_job() {
    use std::sync::OnceLock;
    use std::time::Duration;
    use truenas_ros::sync_fs::xattr::fgetxattr;
    use truenas_ros::sync_fs::{AtFlags, OFlag, OpenHow, StatxMask, statx};
    use truenas_ros::uring_fs::{Anchor, Personality};

    let dir = truenas_ros::tempdir().unwrap();
    let fp = dir.path().join("f.txt");
    std::fs::write(&fp, b"hello object").unwrap();
    if !set_user_xattr(&fp, b"user.a", b"1") || !set_user_xattr(&fp, b"user.b", b"22") {
        return; // this fs refuses user xattrs
    }

    let pers: Arc<OnceLock<Personality>> = Arc::new(OnceLock::new());
    let anchor = match Anchor::open(dir.path()) {
        Ok(a) => a,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("anchor open: {e}"),
    };

    let pc = Arc::clone(&pers);
    let body = move |mut req: Request<'_, ()>| -> Response {
        let (deferred, permit) = req.responder.defer();
        let Some(mut fs) = req.fs.take() else {
            return Response::Close;
        };
        let who = *pc.get().expect("personality set before serving");
        let anchor = anchor.clone();
        let how = OpenHow::new().flags(OFlag::O_RDONLY);
        fs.open(who, &anchor, c"f.txt", how, move |done, fs| {
            let Some(file) = done.file() else {
                return deferred.close();
            };
            fs.offload_result(
                move || {
                    let st = statx(&file, c"", AtFlags::AT_EMPTY_PATH, StatxMask::BASIC_STATS)?;
                    let a = fgetxattr(&file, "user.a")?;
                    let b = fgetxattr(&file, "user.b")?;
                    Ok((st.size(), a, b))
                },
                move |res, _fs| match res {
                    Ok((size, a, b)) => {
                        let msg = format!("{size}:{}:{}", String::from_utf8_lossy(&a), String::from_utf8_lossy(&b),);
                        deferred.reply(echo_frame(msg.as_bytes()));
                    }
                    Err(_) => deferred.close(),
                },
            );
        });
        Response::Defer(permit)
    };
    let protocol = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(PrefixWidth::U32, Endian::Big, false),
        body,
    };
    let cfg = ServerConfig {
        pool_size: 16,
        fs_ops: 16,
        ..ServerConfig::default()
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let mut server = match Server::with_config([addr], cfg, protocol) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind with fs pool: {e}"),
    };
    pers.set(server.register_self().expect("register_self")).unwrap();
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();
    let client = thread::spawn(move || -> io::Result<Vec<u8>> {
        let _stop = ShutdownOnDrop(stop.clone()); // fail fast on panic
        let mut s = connect_tcp(v4)?;
        s.set_read_timeout(Some(Duration::from_secs(5)))?;
        send_framed(&mut s, b"head")?;
        let reply = recv_framed(&mut s);
        drop(s);
        stop.shutdown();
        reply
    });
    server.serve_forever().expect("serve_forever offload_result");
    let reply = client.join().unwrap().expect("client io");
    assert_eq!(
        String::from_utf8_lossy(&reply),
        "12:1:22",
        "one job returned size and both xattr values"
    );
}

/// Read `name` off `path` with `libc::getxattr`, `None` on any failure - the out-of-band witness for the
/// privileged-xattr policy test below.
#[cfg(feature = "uring-fs")]
fn get_xattr_raw(path: &Path, name: &std::ffi::CStr) -> Option<Vec<u8>> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let cpath = CString::new(path.as_os_str().as_bytes()).unwrap();
    let mut buf = vec![0u8; 256];
    // SAFETY: valid NUL-terminated path/name and an owned out-buffer.
    let n = unsafe { libc::getxattr(cpath.as_ptr(), name.as_ptr(), buf.as_mut_ptr().cast(), buf.len()) };
    if n < 0 {
        return None;
    }
    buf.truncate(n as usize);
    Some(buf)
}

/// `Server::set_privileged_xattrs` reaches the embedded reactor. With a policy allowing `trusted.test_`: a covered
/// `fsetxattr` through the request facade lands (promoted to the reactor's own credentials), an **uncovered**
/// `fremovexattr` stays `EPERM`, and a **covered** `fremovexattr` succeeds - the leg that bites, since that path is
/// gated on the allowlist alone and fails `EPERM` under the default empty policy whether or not the caller is
/// privileged. The `trusted.` namespace needs `CAP_SYS_ADMIN`: unprivileged, the covered write's refusal is itself the
/// asserted property (the promotion escalates to the daemon's own identity, which has nothing to escalate to). The qemu
/// lane runs as root and takes the full path.
#[cfg(feature = "uring-fs")]
#[test]
fn server_privileged_xattr_policy_reaches_the_embedded_reactor() {
    use std::sync::OnceLock;
    use std::time::Duration;
    use truenas_ros::sync_fs::{OFlag, OpenHow};
    use truenas_ros::uring_fs::{Anchor, Personality, PrivilegedXattrs};

    let dir = truenas_ros::tempdir().unwrap();
    let fp = dir.path().join("f.txt");
    std::fs::write(&fp, b"x").unwrap();
    if is_root() && !set_user_xattr(&fp, b"trusted.probe", b"1") {
        return; // this fs refuses trusted xattrs even to root
    }

    let pers: Arc<OnceLock<Personality>> = Arc::new(OnceLock::new());
    let anchor = match Anchor::open(dir.path()) {
        Ok(a) => a,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("anchor open: {e}"),
    };

    let pc = Arc::clone(&pers);
    let body = move |mut req: Request<'_, ()>| -> Response {
        let (deferred, permit) = req.responder.defer();
        let Some(mut fs) = req.fs.take() else {
            return Response::Close;
        };
        let who = *pc.get().expect("personality set before serving");
        let anchor = anchor.clone();
        let how = OpenHow::new().flags(OFlag::O_RDONLY);
        fs.open(who, &anchor, c"f.txt", how, move |done, fs| {
            let Some(file) = done.file() else {
                return deferred.reply(echo_frame(format!("OPEN {:?}", done.result()).as_bytes()));
            };
            let f2 = file.clone();
            let f3 = file.clone();
            fs.fsetxattr(who, file, c"trusted.test_x", b"v1".to_vec(), 0, move |set, fs| {
                if let Err(e) = set.result() {
                    return deferred.reply(echo_frame(format!("SET {e}").as_bytes()));
                }
                fs.fremovexattr(f2, c"trusted.other", move |out, fs| {
                    if out.is_ok() {
                        return deferred.reply(echo_frame(b"UNCOVERED-REMOVED"));
                    }
                    fs.fremovexattr(f3, c"trusted.test_x", move |cov, _fs| match cov {
                        Ok(()) => deferred.reply(echo_frame(b"policy-enforced")),
                        Err(e) => deferred.reply(echo_frame(format!("RM-COVERED {e}").as_bytes())),
                    });
                });
            });
        });
        Response::Defer(permit)
    };
    let protocol = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(PrefixWidth::U32, Endian::Big, false),
        body,
    };
    let cfg = ServerConfig {
        pool_size: 16,
        fs_ops: 16,
        ..ServerConfig::default()
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let mut server = match Server::with_config([addr], cfg, protocol) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind with fs pool: {e}"),
    };
    server.set_privileged_xattrs(
        PrivilegedXattrs::new()
            .allow_prefix(c"trusted.test_")
            .expect("a trusted.-rooted prefix is accepted"),
    );
    pers.set(server.register_self().expect("register_self")).unwrap();
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();
    let client = thread::spawn(move || -> io::Result<Vec<u8>> {
        let _stop = ShutdownOnDrop(stop.clone()); // fail fast on panic
        let mut s = connect_tcp(v4)?;
        s.set_read_timeout(Some(Duration::from_secs(5)))?;
        send_framed(&mut s, b"go")?;
        let reply = recv_framed(&mut s);
        drop(s);
        stop.shutdown();
        reply
    });
    server.serve_forever().expect("serve_forever priv xattrs");
    let reply = client.join().unwrap().expect("client io");
    let text = String::from_utf8_lossy(&reply).into_owned();
    if text.starts_with("SET ") {
        assert!(
            text.contains("EPERM") && !is_root(),
            "only an unprivileged daemon may be refused: {text:?}"
        );
        return;
    }
    assert_eq!(text, "policy-enforced", "unexpected chain result");
    // Out of band: the covered remove really removed - `trusted.test_x` is gone while the probe attribute survives (so
    // absence is not ENOTSUP).
    assert!(get_xattr_raw(&fp, c"trusted.probe").is_some());
    assert!(get_xattr_raw(&fp, c"trusted.test_x").is_none());
}
