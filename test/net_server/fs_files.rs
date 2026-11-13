use super::*;

/// `FsConn::fset_attrs` sets a mode and a ZFS attribute in one call through the embedded reactor, as
/// `FsHandle::fset_attrs` does off it. Runs as root on ZFS, and `TRUENAS_ROS_REQUIRE_ZFS_SETATTR` fails a ZFS whose
/// answer is `EOPNOTSUPP` for want of the handler of `system.truenas_setattr`.
#[cfg(feature = "uring-fs")]
#[test]
fn the_embedded_reactor_sets_attributes_in_one_call() {
    use std::os::fd::AsFd;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::OnceLock;
    use truenas_ros::sync_fs::{Mode, OFlag, OpenHow, ZfsAttr, ZfsSetattr, fget_zfs_attrs};
    use truenas_ros::uring_fs::{Anchor, Personality};

    if !root_or_skip("the_embedded_reactor_sets_attributes_in_one_call") {
        return;
    }
    let Some(ds) = zfs_dir::zfs_dir_or_skip() else {
        return;
    };
    let dir = ds.join(format!("rostest_setattr_conn_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir(&dir).unwrap();
    let fp = dir.join("f");
    std::fs::write(&fp, b"x").unwrap();
    std::fs::set_permissions(&fp, std::fs::Permissions::from_mode(0o644)).unwrap();
    let anchor = Anchor::open(&dir).expect("anchor open");

    let pers: Arc<OnceLock<Personality>> = Arc::new(OnceLock::new());
    let pc = Arc::clone(&pers);
    let body = move |mut req: Request<'_, ()>| -> Response {
        let (deferred, permit) = req.responder.defer();
        let Some(mut fs) = req.fs.take() else {
            return Response::Close;
        };
        let who = *pc.get().expect("personality set before serving");
        let anchor = anchor.clone();
        let how = OpenHow::new().flags(OFlag::O_RDONLY);
        fs.open(who, &anchor, c"f", how, move |done, fs| {
            let Some(file) = done.file() else {
                return deferred.reply(echo_frame(format!("OPEN {:?}", done.result()).as_bytes()));
            };
            let set = ZfsSetattr::new()
                .mode(Mode::from_bits_truncate(0o600))
                .dos(ZfsAttr::HIDDEN, ZfsAttr::empty());
            fs.fset_attrs(who, file, &set, move |out, _fs| {
                let text = match out.result() {
                    Ok(_) => "set".to_owned(),
                    Err(e) => format!("SET {e:?}"),
                };
                deferred.reply(echo_frame(text.as_bytes()));
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
        send_framed(&mut s, b"go")?;
        let reply = recv_framed(&mut s);
        drop(s);
        stop.shutdown();
        reply
    });
    server.serve_forever().expect("serve_forever fset_attrs");
    let reply = client.join().unwrap().expect("client io");
    let text = String::from_utf8_lossy(&reply).into_owned();
    if text.contains("EOPNOTSUPP") {
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(
            std::env::var_os("TRUENAS_ROS_REQUIRE_ZFS_SETATTR").is_none(),
            "TRUENAS_ROS_REQUIRE_ZFS_SETATTR is set but this ZFS has no \
             handler for system.truenas_setattr"
        );
        return;
    }
    assert_eq!(text, "set", "the set through the reactor");
    let mode = std::fs::metadata(&fp).unwrap().permissions().mode();
    let file = std::fs::File::open(&fp).unwrap();
    let hidden = fget_zfs_attrs(file.as_fd()).unwrap().contains(ZfsAttr::HIDDEN);
    std::fs::remove_dir_all(&dir).unwrap();
    assert_eq!((mode & 0o7777, hidden), (0o600, true));
}

/// Serve the framed `request` on a ring with an fs table through `body`, which is handed the ring's own personality,
/// and give the reply and the server's counters once it stopped. `None` on a box with no io_uring.
// Under `--cfg loom` the crate's `Arc` is loom's, which `File::from_shared` takes and a std `Arc` is not, and the loom
// lane runs no ring.
#[cfg(all(feature = "uring-fs", not(loom)))]
fn one_fs_reply<B>(
    cfg: ServerConfig,
    request: &'static [u8],
    body: B,
) -> Option<(Vec<u8>, truenas_ros::net::server::ServerStats)>
where
    B: Fn(Request<'_, ()>, truenas_ros::uring_fs::Personality) -> Response + 'static,
{
    use std::sync::OnceLock;
    let pers = Arc::new(OnceLock::new());
    let pc = Arc::clone(&pers);
    let protocol = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(PrefixWidth::U32, Endian::Big, false),
        body: move |req: Request<'_, ()>| body(req, *pc.get().expect("personality set before serving")),
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let mut server = match Server::with_config([addr], cfg, protocol) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return None,
        Err(e) => panic!("bind with fs pool: {e}"),
    };
    pers.set(server.register_self().expect("register_self")).unwrap();
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let (stop, stats) = (server.shutdown_handle(), server.stats_handle());
    let client = thread::spawn(move || -> io::Result<Vec<u8>> {
        let _stop = ShutdownOnDrop(stop.clone()); // fail fast on panic
        let mut s = connect_tcp(v4)?;
        s.set_read_timeout(Some(Duration::from_secs(5)))?;
        send_framed(&mut s, request)?;
        let reply = recv_framed(&mut s);
        drop(s);
        stop.shutdown();
        reply
    });
    server.serve_forever().expect("serve_forever");
    let reply = client.join().unwrap().expect("client io");
    Some((reply, stats.snapshot()))
}

/// What an owned write answered, and whether it gave back the very buffer it was handed with the bytes it held.
#[cfg(all(feature = "uring-fs", not(loom)))]
fn owned_write_verdict(d: truenas_ros::uring_fs::FsDone, storage: *const u8, held: &[u8]) -> String {
    let marked = d.was_refused();
    let res = match d.result() {
        Ok(n) => format!("ok {n}"),
        Err(Error::Errno(e)) => format!("{e:?}"),
        Err(e) => format!("{e}"),
    };
    let back = d.into_value();
    let same = back.as_ptr() == storage && back == held;
    format!("{res} marked={marked} same={same}")
}

/// `FsConn::pwritev2_owned` writes just its range of a buffer at its offset on ZFS and gives the very buffer back
/// through `FsDone::into_value`. A range past the buffer, an inverted one and an offset of `u64::MAX`, which io_uring
/// reads as the file's position, are refused with a marked `EINVAL`, each with its buffer back and nothing written.
#[cfg(all(feature = "uring-fs", not(loom)))]
#[test]
fn an_owned_write_writes_its_range_and_gives_its_buffer_back() {
    use std::cell::RefCell;
    use std::rc::Rc;
    use truenas_ros::uring_fs::{File, RwFlags};

    let Some(ds) = zfs_dir::zfs_dir_or_skip() else {
        return;
    };
    let dir = ds.join(format!("rostest_owned_write_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir(&dir).unwrap();
    let fp = dir.join("f");
    std::fs::write(&fp, b"0123456789abcdef").unwrap();
    let held: Arc<std::os::fd::OwnedFd> = Arc::new(std::fs::OpenOptions::new().write(true).open(&fp).unwrap().into());
    #[allow(clippy::reversed_empty_ranges)]
    let writes = [(2..6, 4), (6..9, 0), (5..3, 0), (0..2, u64::MAX)];
    let cfg = ServerConfig {
        pool_size: 4,
        fs_ops: 16,
        ..ServerConfig::default()
    };
    let reply = one_fs_reply(cfg, b"go", move |mut req, who| {
        let (deferred, permit) = req.responder.defer();
        let Some(mut fs) = req.fs.take() else {
            return Response::Close;
        };
        let answers = Rc::new(RefCell::new(vec![String::new(); writes.len()]));
        let deferred = Rc::new(RefCell::new(Some(deferred)));
        for (i, (range, off)) in writes.iter().cloned().enumerate() {
            let buf = b"..WXYZ..".to_vec();
            let storage = buf.as_ptr();
            let (answers, deferred) = (Rc::clone(&answers), Rc::clone(&deferred));
            let file = File::from_shared(Arc::clone(&held));
            let flags = RwFlags::empty();
            fs.pwritev2_owned(who, file, buf, range, off, flags, move |d, _| {
                answers.borrow_mut()[i] = owned_write_verdict(d, storage, b"..WXYZ..");
                if answers.borrow().iter().all(|a| !a.is_empty())
                    && let Some(deferred) = deferred.borrow_mut().take()
                {
                    let text = answers.borrow().join("\n");
                    deferred.reply(echo_frame(text.as_bytes()));
                }
            });
        }
        Response::Defer(permit)
    });
    let Some((reply, _)) = reply else {
        std::fs::remove_dir_all(&dir).unwrap();
        return;
    };
    let file = std::fs::read(&fp).unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
    let refused = "EINVAL marked=true same=true";
    assert_eq!(
        String::from_utf8_lossy(&reply),
        ["ok 4 marked=false same=true", refused, refused, refused].join("\n")
    );
    assert_eq!(file, b"0123WXYZ89abcdef", "just the range, at its offset");
}

/// With both slots of a two-slot table held by reads parked on a FIFO, `FsConn::pwritev2_owned` is refused with a
/// marked `EBUSY` and gives its buffer back as it came.
#[cfg(all(feature = "uring-fs", not(loom)))]
#[test]
fn an_owned_write_on_a_full_table_gives_its_buffer_back() {
    use std::os::unix::ffi::OsStrExt;
    use truenas_ros::uring_fs::{File, RwFlags};

    let Some(ds) = zfs_dir::zfs_dir_or_skip() else {
        return;
    };
    let dir = ds.join(format!("rostest_owned_full_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir(&dir).unwrap();
    let fp = dir.join("f");
    std::fs::write(&fp, b"bytes").unwrap();
    let fifo = dir.join("fifo");
    let c = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
    // SAFETY: a valid NUL-terminated path.
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
    let open = |p: &Path| -> Arc<std::os::fd::OwnedFd> {
        // O_RDWR on a FIFO opens at once with a writer attached, so a read with no data parks and holds its slot.
        let f = std::fs::OpenOptions::new().read(true).write(true).open(p);
        Arc::new(f.unwrap().into())
    };
    let (held, pipe) = (open(&fp), open(&fifo));
    let cfg = ServerConfig {
        pool_size: 1,
        fs_ops: 1,
        ..ServerConfig::default()
    };
    let reply = one_fs_reply(cfg, b"go", move |mut req, who| {
        let (deferred, permit) = req.responder.defer();
        let Some(mut fs) = req.fs.take() else {
            return Response::Close;
        };
        let flags = RwFlags::empty();
        for _ in 0..2 {
            let parked = File::from_shared(Arc::clone(&pipe));
            fs.preadv2(who, parked, vec![vec![0u8; 4]], 0, flags, |_, _| {});
        }
        let buf = b"owned".to_vec();
        let storage = buf.as_ptr();
        let file = File::from_shared(Arc::clone(&held));
        fs.pwritev2_owned(who, file, buf, 0..5, 0, flags, move |d, _| {
            let text = owned_write_verdict(d, storage, b"owned");
            deferred.reply(echo_frame(text.as_bytes()));
        });
        Response::Defer(permit)
    });
    let file = std::fs::read(&fp).unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
    let Some((reply, _)) = reply else {
        return;
    };
    assert_eq!(String::from_utf8_lossy(&reply), "EBUSY marked=true same=true");
    assert_eq!(file, b"bytes", "nothing written");
}

/// `FsConn::pwritev2_window` writes windows of the request on ZFS, the first from the delivery's own facade and the
/// second from that write's callback, after the delivery is over, while the second window alone keeps the receive
/// buffer. The buffer goes back to the pool once the last window's share is gone.
#[cfg(all(feature = "uring-fs", not(loom)))]
#[test]
fn a_window_is_written_from_its_delivery_and_after_it() {
    use truenas_ros::uring_fs::{File, RwFlags};

    let Some(ds) = zfs_dir::zfs_dir_or_skip() else {
        return;
    };
    let dir = ds.join(format!("rostest_window_write_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir(&dir).unwrap();
    let fp = dir.join("f");
    std::fs::write(&fp, b"").unwrap();
    let held: Arc<std::os::fd::OwnedFd> = Arc::new(std::fs::OpenOptions::new().write(true).open(&fp).unwrap().into());
    let cfg = ServerConfig {
        pool_size: 4,
        fs_ops: 16,
        ..ServerConfig::default()
    };
    let reply = one_fs_reply(cfg, b"0123456789", move |mut req, who| {
        let (deferred, permit) = req.responder.defer();
        let Some(mut fs) = req.fs.take() else {
            return Response::Close;
        };
        let Some(window) = fs.lease_window(&req.body[..]) else {
            deferred.reply(echo_frame(b"not leased"));
            return Response::Defer(permit);
        };
        let (head, tail) = window.split_at(4);
        let (first, later) = (
            File::from_shared(Arc::clone(&held)),
            File::from_shared(Arc::clone(&held)),
        );
        let flags = RwFlags::empty();
        fs.pwritev2_window(who, first, head, 0, flags, move |done, fs| {
            let first = done.result().ok();
            fs.pwritev2_window(who, later, tail, 4, flags, move |done, _| {
                let text = format!("{first:?} {:?}", done.result().ok());
                deferred.reply(echo_frame(text.as_bytes()));
            });
        });
        Response::Defer(permit)
    });
    let file = std::fs::read(&fp).unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
    let Some((reply, stats)) = reply else {
        return;
    };
    assert_eq!(String::from_utf8_lossy(&reply), "Some(4) Some(6)");
    assert_eq!(file, b"0123456789", "each window at its offset");
    assert!(stats.recv_bufs_total > 0, "no receive pool: {stats:?}");
    assert_eq!(stats.recv_bufs_lent, 0, "the buffer came home: {stats:?}");
}

/// With both slots of a two-slot table held by reads parked on a FIFO, `FsConn::pwritev2_window` is refused with a
/// marked `EBUSY`, writes nothing, and its receive buffer goes back to the pool as the window drops.
#[cfg(all(feature = "uring-fs", not(loom)))]
#[test]
fn a_window_write_on_a_full_table_gives_its_buffer_back() {
    use std::os::unix::ffi::OsStrExt;
    use truenas_ros::uring_fs::{File, RwFlags};

    let Some(ds) = zfs_dir::zfs_dir_or_skip() else {
        return;
    };
    let dir = ds.join(format!("rostest_window_full_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir(&dir).unwrap();
    let fp = dir.join("f");
    std::fs::write(&fp, b"bytes").unwrap();
    let fifo = dir.join("fifo");
    let c = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
    // SAFETY: a valid NUL-terminated path.
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
    let open = |p: &Path| -> Arc<std::os::fd::OwnedFd> {
        // O_RDWR on a FIFO opens at once with a writer attached, so a read with no data parks and holds its slot.
        let f = std::fs::OpenOptions::new().read(true).write(true).open(p);
        Arc::new(f.unwrap().into())
    };
    let (held, pipe) = (open(&fp), open(&fifo));
    let cfg = ServerConfig {
        pool_size: 1,
        fs_ops: 1,
        ..ServerConfig::default()
    };
    let reply = one_fs_reply(cfg, b"window", move |mut req, who| {
        let (deferred, permit) = req.responder.defer();
        let Some(mut fs) = req.fs.take() else {
            return Response::Close;
        };
        let Some(window) = fs.lease_window(&req.body[..]) else {
            deferred.reply(echo_frame(b"not leased"));
            return Response::Defer(permit);
        };
        let flags = RwFlags::empty();
        for _ in 0..2 {
            let parked = File::from_shared(Arc::clone(&pipe));
            fs.preadv2(who, parked, vec![vec![0u8; 4]], 0, flags, |_, _| {});
        }
        let file = File::from_shared(Arc::clone(&held));
        fs.pwritev2_window(who, file, window, 0, flags, move |d, _| {
            let text = match d.result() {
                Err(Error::Errno(e)) => format!("{e:?} {}", d.was_refused()),
                other => format!("{other:?}"),
            };
            deferred.reply(echo_frame(text.as_bytes()));
        });
        Response::Defer(permit)
    });
    let file = std::fs::read(&fp).unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
    let Some((reply, stats)) = reply else {
        return;
    };
    assert_eq!(String::from_utf8_lossy(&reply), "EBUSY true");
    assert_eq!(file, b"bytes", "nothing written");
    assert_eq!(stats.recv_bufs_lent, 0, "the buffer came home: {stats:?}");
}

/// `FsConn::fgetxattr_as_root` reads an xattr under the reactor's ambient (root) credentials (`sqe.personality = 0`) -
/// the sanctioned privileged-read path for a `trusted.*`/`security.*` attribute a request's own identity can't see.
/// Here it reads a seeded `user.*` value end to end; the full privilege boundary (a non-root peer vs. a root-only
/// xattr) isn't reproduced, since on this root dev host the peer identity is itself root - the point is exercising the
/// `personality = 0` SQE path end to end.
#[cfg(feature = "uring-fs")]
#[test]
fn fs_file_carries_personality_and_as_root() {
    use std::ffi::CString;
    use std::sync::OnceLock;
    use truenas_ros::sync_fs::{OFlag, OpenHow};
    use truenas_ros::uring_fs::{Anchor, Personality};

    let dir = truenas_ros::tempdir().unwrap();
    let fpath = dir.path().join("f.txt");
    std::fs::write(&fpath, b"payload").unwrap();
    // Seed an xattr to read back through the ambient-root path; skip if the filesystem refuses user xattrs (some `/tmp`
    // configs).
    if !set_user_xattr(&fpath, b"user.tr_test", b"secret") {
        return;
    }

    let pers: Arc<OnceLock<Personality>> = Arc::new(OnceLock::new());
    let anchor = match Anchor::open(dir.path()) {
        Ok(a) => a,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("anchor open: {e}"),
    };

    let pc = Arc::clone(&pers);
    let body = move |mut req: Request<'_, ()>| -> Response {
        let _ = req.body.take();
        let (deferred, permit) = req.responder.defer();
        let Some(mut fs) = req.fs.take() else {
            return Response::Close;
        };
        let who = *pc.get().expect("personality set before serving");
        let anchor = anchor.clone();
        let path = CString::new("f.txt").unwrap();
        let how = OpenHow::new().flags(OFlag::O_RDONLY);
        fs.open(who, &anchor, &path, how, move |done, fs| {
            let Some(file) = done.file() else {
                deferred.close();
                return;
            };
            // Read the seeded xattr under ambient root (personality 0) - no `who`. On this root host the peer is itself
            // root, so this exercises the `personality = 0` SQE path end to end rather than a privilege boundary.
            let name = CString::new("user.tr_test").unwrap();
            fs.fgetxattr_as_root(file.clone(), name.clone(), vec![0u8; 64], move |d, fs| {
                fs.close(file);
                match d.result() {
                    Ok(n) => {
                        let mut v = d.into_bufs().pop().unwrap_or_default();
                        v.truncate(n as usize);
                        deferred.reply(echo_frame(&v));
                    }
                    Err(_) => deferred.reply(echo_frame(b"xattr-err")),
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
        pool_size: 8,
        fs_ops: 8,
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
        send_framed(&mut s, b"go")?;
        let r = recv_framed(&mut s)?;
        drop(s);
        stop.shutdown();
        Ok(r)
    });
    server.serve_forever().expect("serve_forever as_root xattr");
    let reply = client.join().unwrap().expect("client io");
    // The ambient-root fgetxattr read the seeded value end to end.
    assert_eq!(reply, b"secret");
}

/// `FsConn::fgetxattr_proc_as_root` reads an xattr of a file held `O_PATH` under the reactor's ambient (root)
/// credentials, through the file's path under `/proc/thread-self/fd`, where `fgetxattr_as_root` refuses the descriptor
/// itself with `EBADF`. As above, the peer on this root host is itself root, so the privilege boundary is pinned in
/// `test/uring_fs.rs`, and this exercises the `personality = 0` `GETXATTR` path end to end.
#[cfg(feature = "uring-fs")]
#[test]
fn fs_file_held_o_path_reads_as_root_through_proc() {
    use std::ffi::CString;
    use std::sync::OnceLock;
    use truenas_ros::sync_fs::{OFlag, OpenHow};
    use truenas_ros::uring_fs::{Anchor, Personality};

    let dir = truenas_ros::tempdir().unwrap();
    let fpath = dir.path().join("f.txt");
    std::fs::write(&fpath, b"payload").unwrap();
    if !set_user_xattr(&fpath, b"user.tr_test", b"secret") {
        return;
    }

    let pers: Arc<OnceLock<Personality>> = Arc::new(OnceLock::new());
    let anchor = match Anchor::open(dir.path()) {
        Ok(a) => a,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("anchor open: {e}"),
    };

    let pc = Arc::clone(&pers);
    let body = move |mut req: Request<'_, ()>| -> Response {
        let _ = req.body.take();
        let (deferred, permit) = req.responder.defer();
        let Some(mut fs) = req.fs.take() else {
            return Response::Close;
        };
        let who = *pc.get().expect("personality set before serving");
        let anchor = anchor.clone();
        let path = CString::new("f.txt").unwrap();
        let how = OpenHow::new().flags(OFlag::O_PATH);
        fs.open(who, &anchor, &path, how, move |done, fs| {
            let Some(file) = done.file() else {
                deferred.close();
                return;
            };
            let name = CString::new("user.tr_test").unwrap();
            let again = name.clone();
            let held = file.clone();
            fs.fgetxattr_as_root(file, name, vec![0u8; 64], move |d, fs| {
                let refused = matches!(d.result(), Err(Error::Errno(Errno::EBADF)));
                let file = held.clone();
                fs.fgetxattr_proc_as_root(held, again, vec![0u8; 64], move |d, fs| {
                    fs.close(file);
                    let mut out = vec![if refused { b'1' } else { b'0' }];
                    out.push(b':');
                    match d.result() {
                        Ok(n) => {
                            let mut v = d.into_bufs().pop().unwrap_or_default();
                            v.truncate(n as usize);
                            out.extend_from_slice(&v);
                        }
                        Err(_) => out.extend_from_slice(b"xattr-err"),
                    }
                    deferred.reply(echo_frame(&out));
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
        pool_size: 8,
        fs_ops: 8,
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
        send_framed(&mut s, b"go")?;
        let r = recv_framed(&mut s)?;
        drop(s);
        stop.shutdown();
        Ok(r)
    });
    server.serve_forever().expect("serve_forever proc as_root xattr");
    let reply = client.join().unwrap().expect("client io");
    // The descriptor was refused and the proc path read the value.
    assert_eq!(reply, b"1:secret");
}

/// The rest of the embedded op sweep over the ring: `renameat` (the `submit_path_op` two-anchor route), `ftruncate`
/// (the `submit_fd_meta` route), and an `fgetxattr` read - each stamped with the per-connection personality, driven
/// from the body handler and resolved through a `Deferred`. The two version-gated ops (`ftruncate` >= 6.9, fixed-file
/// xattr >= 6.13) run only where the server reports support; `renameat` always does.
#[cfg(feature = "uring-fs")]
#[test]
fn fs_metadata_ops_rename_truncate_xattr() {
    use std::ffi::CString;
    use std::sync::OnceLock;
    use truenas_ros::sync_fs::{OFlag, OpenHow, RenameFlags};
    use truenas_ros::uring_fs::{Anchor, Leaf, Personality};

    let dir = truenas_ros::tempdir().unwrap();
    let orig = dir.path().join("orig.txt");
    std::fs::write(&orig, b"payload-7").unwrap(); // 9 bytes
    let xattr_set = set_user_xattr(&orig, b"user.color", b"blue");

    let pers: Arc<OnceLock<Personality>> = Arc::new(OnceLock::new());
    let anchor = match Anchor::open(dir.path()) {
        Ok(a) => a,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("anchor open: {e}"),
    };

    let pc = Arc::clone(&pers);
    let body = move |mut req: Request<'_, ()>| -> Response {
        let cmd = req.body.take();
        let (deferred, permit) = req.responder.defer();
        let Some(mut fs) = req.fs.take() else {
            return Response::Close;
        };
        let who = *pc.get().expect("personality set before serving");
        let anchor = anchor.clone();
        match cmd.as_slice() {
            b"getxattr" => {
                let path = CString::new("orig.txt").unwrap();
                let how = OpenHow::new().flags(OFlag::O_RDONLY);
                fs.open(who, &anchor, &path, how, move |done, fs| {
                    let Some(file) = done.file() else {
                        deferred.close();
                        return;
                    };
                    let name = CString::new("user.color").unwrap();
                    fs.fgetxattr(who, file.clone(), name.clone(), vec![0u8; 64], move |d, fs| {
                        fs.close(file);
                        match d.result() {
                            Ok(n) => {
                                let mut v = d.into_bufs().pop().unwrap_or_default();
                                v.truncate(n as usize);
                                deferred.reply(echo_frame(&v));
                            }
                            Err(_) => deferred.reply(echo_frame(b"xattr-err")),
                        }
                    });
                });
            }
            b"truncate" => {
                let path = CString::new("orig.txt").unwrap();
                let how = OpenHow::new().flags(OFlag::O_WRONLY);
                fs.open(who, &anchor, &path, how, move |done, fs| {
                    let Some(file) = done.file() else {
                        deferred.close();
                        return;
                    };
                    fs.ftruncate(who, file.clone(), 3, move |d, fs| {
                        fs.close(file);
                        match d.result() {
                            Ok(_) => deferred.reply(echo_frame(b"ok")),
                            Err(_) => deferred.reply(echo_frame(b"trunc-err")),
                        }
                    });
                });
            }
            b"rename" => {
                let old = Leaf::new("orig.txt").unwrap();
                let new = Leaf::new("renamed.txt").unwrap();
                fs.renameat(
                    who,
                    &anchor,
                    old,
                    &anchor,
                    new,
                    RenameFlags::empty(),
                    move |d, _fs| match d.result() {
                        Ok(_) => deferred.reply(echo_frame(b"renamed-ok")),
                        Err(_) => deferred.reply(echo_frame(b"renamed-err")),
                    },
                );
            }
            _ => deferred.close(),
        }
        Response::Defer(permit)
    };
    let protocol = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(PrefixWidth::U32, Endian::Big, false),
        body,
    };
    let cfg = ServerConfig {
        pool_size: 8,
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
    let do_xattr = xattr_set;
    let do_truncate = true;
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();
    // (optional getxattr reply, optional truncate reply, rename reply).
    type MetaReplies = io::Result<(Option<Vec<u8>>, Option<Vec<u8>>, Vec<u8>)>;
    let client = thread::spawn(move || -> MetaReplies {
        let _stop = ShutdownOnDrop(stop.clone()); // fail fast on panic
        let mut s = connect_tcp(v4)?;
        // getxattr and truncate read/modify orig.txt; rename moves it last.
        let xattr = if do_xattr {
            send_framed(&mut s, b"getxattr")?;
            Some(recv_framed(&mut s)?)
        } else {
            None
        };
        let trunc = if do_truncate {
            send_framed(&mut s, b"truncate")?;
            Some(recv_framed(&mut s)?)
        } else {
            None
        };
        send_framed(&mut s, b"rename")?;
        let renamed = recv_framed(&mut s)?;
        drop(s);
        stop.shutdown();
        Ok((xattr, trunc, renamed))
    });
    server.serve_forever().expect("serve_forever metadata");
    let (xattr, trunc, renamed) = client.join().unwrap().expect("client io");

    assert_eq!(renamed, b"renamed-ok");
    assert!(dir.path().join("renamed.txt").exists(), "rename took effect");
    assert!(!orig.exists(), "orig.txt is gone after rename");
    if let Some(v) = xattr {
        assert_eq!(v, b"blue", "fgetxattr read the value back");
    }
    if let Some(t) = trunc {
        assert_eq!(t, b"ok");
        // ftruncate shrank orig.txt to 3 bytes before it was renamed.
        let len = std::fs::metadata(dir.path().join("renamed.txt")).unwrap().len();
        assert_eq!(len, 3, "ftruncate shrank the file to 3 bytes");
    }
}

/// The connection-close owned-file sweep. A handler opens a file on every request and **never closes it** - a
/// deliberate leak. Across many sequential connections (each opening one file, then dropping), the process would run
/// out of descriptors if the files were not reclaimed; the sweep closes each connection's still-open files as it
/// closes, so every open succeeds. (Mirrors `tcp_sequential_slot_reuse`: a small pool with slack absorbs the
/// asynchronous close, so one-at-a-time connections never outrun the sweep.)
#[cfg(feature = "uring-fs")]
#[test]
fn fs_owned_files_swept_on_connection_close() {
    use std::ffi::CString;
    use std::sync::OnceLock;
    use truenas_ros::sync_fs::{OFlag, OpenHow};
    use truenas_ros::uring_fs::{Anchor, Personality};

    const N: usize = 16;
    let dir = truenas_ros::tempdir().unwrap();
    std::fs::write(dir.path().join("f.txt"), b"data").unwrap();

    let pers: Arc<OnceLock<Personality>> = Arc::new(OnceLock::new());
    let anchor = match Anchor::open(dir.path()) {
        Ok(a) => a,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("anchor open: {e}"),
    };

    let pc = Arc::clone(&pers);
    let body = move |mut req: Request<'_, ()>| -> Response {
        let _ = req.body.take();
        let (deferred, permit) = req.responder.defer();
        let Some(mut fs) = req.fs.take() else {
            return Response::Close;
        };
        let who = *pc.get().expect("personality set before serving");
        let anchor = anchor.clone();
        let path = CString::new("f.txt").unwrap();
        let how = OpenHow::new().flags(OFlag::O_RDONLY);
        fs.open(who, &anchor, &path, how, move |done, _fs| {
            // Deliberately DO NOT close the file: the connection-close sweep is the only thing that can reclaim its
            // pool slot.
            if done.file().is_some() {
                deferred.reply(echo_frame(b"opened"));
            } else {
                deferred.reply(echo_frame(b"open-err")); // pool exhausted / open failed
            }
        });
        Response::Defer(permit)
    };
    let protocol = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(PrefixWidth::U32, Endian::Big, false),
        body,
    };
    let cfg = ServerConfig {
        pool_size: 8,
        fs_ops: 8, // far fewer than N: reuse across closes is mandatory
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
    let client = thread::spawn(move || -> io::Result<Vec<Vec<u8>>> {
        let _stop = ShutdownOnDrop(stop.clone()); // fail fast on panic
        // Sequential connections, each opening one (never-closed) file, then closing - the sweep must reclaim its slot
        // before the pool exhausts.
        let mut replies = Vec::with_capacity(N);
        for _ in 0..N {
            let mut s = connect_tcp(v4)?;
            send_framed(&mut s, b"open")?;
            replies.push(recv_framed(&mut s)?);
            drop(s); // close -> triggers the owned-file sweep
        }
        stop.shutdown();
        Ok(replies)
    });
    server.serve_forever().expect("serve_forever sweep");
    let replies = client.join().unwrap().expect("client io");
    assert_eq!(replies.len(), N);
    for (i, r) in replies.iter().enumerate() {
        assert_eq!(
            r, b"opened",
            "connection {i} opened a file - the sweep must have freed the \
             earlier connections' descriptors (else the process runs out)"
        );
    }
}

/// A continuation may open, and doing so reclaims its slot like any other op.
///
/// This used to assert the opposite - that the facade refused - on the grounds that a file minted after `close_conn`
/// had already swept the connection would hold its slot until server teardown. It does not. `close_owned_by` is gone;
/// `cancel_owned_by` cancels in-flight *ops* so their parked fds are released, and the fds themselves close by
/// `Arc`-drop whether or not anyone takes them. An `openat2` completes, so its entry is reaped either way.
///
/// The pool is deliberately smaller than the connection count, and each connection leaves its *first* file open while
/// chaining a second from the completion. If a chained open leaked a slot, the later connections would find none and
/// answer `open-err` - which is what makes this a measurement rather than a restatement.
#[cfg(feature = "uring-fs")]
#[test]
fn fs_continuation_may_open_and_its_slot_comes_back() {
    use std::ffi::CString;
    use std::sync::OnceLock;
    use truenas_ros::sync_fs::{OFlag, OpenHow};
    use truenas_ros::uring_fs::{Anchor, Personality};

    const N: usize = 6;
    let dir = truenas_ros::tempdir().unwrap();
    std::fs::write(dir.path().join("a.txt"), b"first").unwrap();
    std::fs::write(dir.path().join("b.txt"), b"second").unwrap();

    let pers: Arc<OnceLock<Personality>> = Arc::new(OnceLock::new());
    let anchor = match Anchor::open(dir.path()) {
        Ok(a) => a,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("anchor open: {e}"),
    };

    let pc = Arc::clone(&pers);
    let body = move |mut req: Request<'_, ()>| -> Response {
        let _ = req.body.take();
        let (deferred, permit) = req.responder.defer();
        let Some(mut fs) = req.fs.take() else {
            return Response::Close;
        };
        let who = *pc.get().expect("personality set before serving");
        let (a1, a2) = (anchor.clone(), anchor.clone());
        let first = CString::new("a.txt").unwrap();
        let second = CString::new("b.txt").unwrap();
        let how = OpenHow::new().flags(OFlag::O_RDONLY);
        fs.open(who, &a1, &first, how, move |done, fs| {
            if done.file().is_none() {
                deferred.reply(echo_frame(b"open-err"));
                return;
            }
            // The first file stays open on purpose: this connection is holding a slot while it asks for another.
            fs.open(who, &a2, &second, how, move |d, _fs| match d.file() {
                Some(_) => deferred.reply(echo_frame(b"chained")),
                None => deferred.reply(echo_frame(b"open-err")),
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
        pool_size: 8,
        fs_ops: 4, // < N: the sweep must recycle between connections
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
    let client = thread::spawn(move || -> Vec<io::Result<Vec<u8>>> {
        let _stop = ShutdownOnDrop(stop.clone()); // fail fast on panic
        let mut out = Vec::with_capacity(N);
        for _ in 0..N {
            let mut s = connect_tcp(v4).expect("connect");
            send_framed(&mut s, b"go").expect("send");
            out.push(recv_framed(&mut s));
        }
        stop.shutdown();
        out
    });
    server.serve_forever().expect("serve_forever");
    let replies = client.join().unwrap();
    assert_eq!(replies.len(), N);
    for (i, r) in replies.iter().enumerate() {
        let b = r
            .as_ref()
            .unwrap_or_else(|e| panic!("connection {i}: the chained open must answer, got {e:?}"));
        assert_eq!(
            b, b"chained",
            "connection {i}: every connection past the pool must still find \
             a slot, so nothing the chain opened was left holding one"
        );
    }
}
