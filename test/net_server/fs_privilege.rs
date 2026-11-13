use super::*;

/// The end-to-end proof that a server acts as *authenticated peers*: the personality genuinely gates namespace access,
/// it is not a stamp. The credential broker (spawned on the **server's** ring) registers an unprivileged uid; the
/// handler then opens a root-owned `0600` file two ways -- under the daemon's own personality it opens and reads back,
/// under the peer's it is refused (`EACCES`, so `done.file()` is `None`). Pure `open` + `pread`, so it runs live
/// wherever io_uring + root are available (no xattr / 6.13 gate). The divergence is at **open** by design: DAC is
/// checked there, not on each read of an already-open fd.
///
/// Root-only (the broker needs `CAP_SETUID` to become the peer); skipped otherwise.
#[cfg(feature = "uring-fs")]
#[test]
fn fs_broker_personality_gates_open() {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::sync::OnceLock;
    use truenas_ros::sync_fs::{OFlag, OpenHow};
    use truenas_ros::uring_fs::{Anchor, AsUser, CredBroker, Personality, RwFlags};

    if !root_or_skip("fs_broker_personality_gates_open") {
        return; // the broker cannot become another uid without CAP_SETUID
    }
    // A uid/gid that owns nothing here - its personality has only what "other" grants, and "other" is nothing on a 0600
    // file.
    const NOBODY_UID: u32 = 65_534;
    const NOBODY_GID: u32 = 65_534;

    let dir = truenas_ros::tempdir().unwrap();
    // A root-owned, owner-only file: openable by the daemon, not by the peer.
    let secret = dir.path().join("secret.txt");
    std::fs::write(&secret, b"topsecret").unwrap();
    let cpath = CString::new(secret.as_os_str().as_bytes()).unwrap();
    // SAFETY: valid path; chmod cannot corrupt memory.
    assert_eq!(unsafe { libc::chmod(cpath.as_ptr(), 0o600) }, 0);

    // (root-daemon personality, unprivileged-peer personality), minted after construction and read by the handler.
    let cell: Arc<OnceLock<(Personality, Personality)>> = Arc::new(OnceLock::new());
    let anchor = match Anchor::open(dir.path()) {
        Ok(a) => a,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("anchor open: {e}"),
    };

    let pc = Arc::clone(&cell);
    let body = move |mut req: Request<'_, ()>| -> Response {
        let cmd = req.body.take();
        let (deferred, permit) = req.responder.defer();
        let Some(mut fs) = req.fs.take() else {
            return Response::Close;
        };
        let (root_pers, peer_pers) = *pc.get().expect("personalities set before serving");
        let anchor = anchor.clone();
        let ro = OpenHow::new().flags(OFlag::O_RDONLY);
        // Open the 0600 file as the daemon (`as-root`) or the peer, then, if it opened, read it back - proving the
        // daemon both opens AND reads while the peer is refused at open.
        let who = if cmd == b"as-root" { root_pers } else { peer_pers };
        let path = CString::new("secret.txt").unwrap();
        fs.open(who, &anchor, &path, ro, move |done, fs| {
            let Some(file) = done.file() else {
                // EACCES - the personality gated the open.
                deferred.reply(echo_frame(b"denied"));
                return;
            };
            fs.preadv2(
                who,
                file.clone(),
                vec![vec![0u8; 64]],
                0,
                RwFlags::empty(),
                move |d, fs| {
                    fs.close(file);
                    match d.result() {
                        Ok(n) => {
                            let mut out = b"read:".to_vec();
                            let mut v = d.into_bufs().pop().unwrap_or_default();
                            v.truncate(n as usize);
                            out.extend_from_slice(&v);
                            deferred.reply(echo_frame(&out));
                        }
                        Err(_) => deferred.reply(echo_frame(b"read-err")),
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
        pool_size: 8,
        fs_ops: 16,
        ..ServerConfig::default()
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    // The ring must exist before the broker forks (it inherits the fd), and the broker must fork before any threads -
    // so build, register, spawn, all before the client thread below.
    let mut server = match Server::with_config([addr], cfg, protocol) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind with fs pool: {e}"),
    };
    let root_pers = server.register_self().expect("register_self");
    let broker = match CredBroker::spawn(&[&server]) {
        Ok(b) => b,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("CredBroker::spawn: {e}"),
    };
    let creds = broker.handle(0).expect("broker handle");
    let peer_pers = creds
        .register(&AsUser::new(NOBODY_UID, NOBODY_GID))
        .expect("register peer");
    cell.set((root_pers, peer_pers)).unwrap();

    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();
    let client = thread::spawn(move || -> io::Result<(Vec<u8>, Vec<u8>)> {
        let _stop = ShutdownOnDrop(stop.clone()); // fail fast on panic
        let mut s = connect_tcp(v4)?;
        send_framed(&mut s, b"as-peer")?;
        let peer = recv_framed(&mut s)?;
        send_framed(&mut s, b"as-root")?;
        let root = recv_framed(&mut s)?;
        drop(s);
        stop.shutdown();
        Ok((peer, root))
    });
    server.serve_forever().expect("serve_forever broker");
    let (peer, root) = client.join().unwrap().expect("client io");

    assert_eq!(
        root, b"read:topsecret",
        "the daemon's own identity opens and reads its 0600 file"
    );
    assert_eq!(
        peer, b"denied",
        "the unprivileged peer is refused at open - the personality gates DAC"
    );
}

/// A parent open checks that the caller may search the directory it starts from, as any lookup in it does, and asks
/// nothing of the parent itself when it opens `O_PATH`. In a root-owned `0700` tree a peer is refused the parent of a
/// `0700` directory and given the parent of a `0755` one, and the daemon is given both. The open across a mount is
/// refused the same.
///
/// Root-only, since the broker needs `CAP_SETUID` to become the peer. Skipped otherwise.
#[cfg(feature = "uring-fs")]
#[test]
fn fs_parent_open_needs_search_on_the_directory() {
    use std::os::unix::fs::PermissionsExt;
    use std::sync::OnceLock;
    use truenas_ros::errno::Errno;
    use truenas_ros::sync_fs::{OFlag, OpenHow};
    use truenas_ros::uring_fs::{Anchor, AsUser, CredBroker, FsConn, FsDone, Personality};

    if !root_or_skip("fs_parent_open_needs_search_on_the_directory") {
        return;
    }
    const NOBODY_UID: u32 = 65_534;
    const NOBODY_GID: u32 = 65_534;

    let dir = truenas_ros::tempdir().unwrap();
    for (name, mode) in [("locked", 0o700), ("open", 0o755)] {
        let path = dir.path().join(name);
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
    }
    let anchors = (
        Anchor::open(&dir.path().join("locked")).expect("anchor"),
        Anchor::open(&dir.path().join("open")).expect("anchor"),
    );

    let cell: Arc<OnceLock<(Personality, Personality)>> = Arc::new(OnceLock::new());
    let pc = Arc::clone(&cell);
    let body = move |mut req: Request<'_, ()>| -> Response {
        let cmd = req.body.take();
        let (deferred, permit) = req.responder.defer();
        let Some(mut fs) = req.fs.take() else {
            return Response::Close;
        };
        let (root_pers, peer_pers) = *pc.get().expect("personalities set before serving");
        let who = if cmd.ends_with(b"as root") {
            root_pers
        } else {
            peer_pers
        };
        let anchor = if cmd.starts_with(b"locked") || cmd.starts_with(b"across") {
            &anchors.0
        } else {
            &anchors.1
        };
        let how = OpenHow::new().flags(OFlag::O_PATH);
        let then = move |done: FsDone, _fs: &mut FsConn<'_>| {
            let answer = match done.result() {
                Ok(_) => "opened".to_owned(),
                Err(truenas_ros::Error::Errno(Errno::EACCES)) => "denied".to_owned(),
                Err(e) => format!("{e}"),
            };
            deferred.reply(echo_frame(answer.as_bytes()));
        };
        if cmd.starts_with(b"across") {
            fs.open_parent_across_mount(who, anchor, how, then);
        } else {
            fs.open_parent(who, anchor, how, then);
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
    // The ring must exist before the broker forks, since the broker inherits its fd, and the broker must fork before
    // any thread starts.
    let mut server = match Server::with_config([addr], cfg, protocol) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind with fs pool: {e}"),
    };
    let root_pers = server.register_self().expect("register_self");
    let broker = match CredBroker::spawn(&[&server]) {
        Ok(b) => b,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("CredBroker::spawn: {e}"),
    };
    let creds = broker.handle(0).expect("broker handle");
    let peer_pers = creds
        .register(&AsUser::new(NOBODY_UID, NOBODY_GID))
        .expect("register peer");
    cell.set((root_pers, peer_pers)).unwrap();

    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();
    let client = thread::spawn(move || -> io::Result<Vec<Vec<u8>>> {
        let _stop = ShutdownOnDrop(stop.clone());
        let mut s = connect_tcp(v4)?;
        let mut answers = Vec::new();
        let cmds = [&b"locked"[..], b"open", b"locked as root", b"across locked"];
        for cmd in cmds {
            send_framed(&mut s, cmd)?;
            answers.push(recv_framed(&mut s)?);
        }
        drop(s);
        stop.shutdown();
        Ok(answers)
    });
    server.serve_forever().expect("serve_forever broker");
    let answers = client.join().unwrap().expect("client io");

    let text: Vec<String> = answers
        .iter()
        .map(|a| String::from_utf8_lossy(a).into_owned())
        .collect();
    assert_eq!(
        text,
        ["denied", "opened", "opened", "denied"],
        "the peer may not search locked, may search open and needs nothing \
         of their 0700 parent, the daemon opens what the peer may not, and \
         the open across a mount checks the peer the same"
    );
}

/// `FsConn::reopen_proc` opens a file the ring holds `O_PATH` again as the peer, which a file of mode 0600 refuses, and
/// `FsConn::reopen_proc_as_root` opens it as the ring owner, whose capabilities pass the check. Root-only, since the
/// broker needs `CAP_SETUID` to become the peer. Skipped otherwise.
#[cfg(feature = "uring-fs")]
#[test]
fn fs_reopen_through_proc_checks_the_peer_and_not_the_ring_owner() {
    use std::os::unix::fs::PermissionsExt;
    use std::sync::OnceLock;
    use truenas_ros::errno::Errno;
    use truenas_ros::sync_fs::{OFlag, OpenHow};
    use truenas_ros::uring_fs::{Anchor, AsUser, CredBroker, FsConn, FsDone, Personality, ReopenAccess};

    if !root_or_skip("fs_reopen_through_proc_checks_the_peer_and_not_the_ring_owner") {
        return;
    }
    const NOBODY_UID: u32 = 65_534;
    const NOBODY_GID: u32 = 65_534;

    let dir = truenas_ros::tempdir().unwrap();
    std::fs::write(dir.path().join("f"), b"held").unwrap();
    std::fs::set_permissions(dir.path().join("f"), std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    let anchor = Anchor::open(dir.path()).expect("anchor");

    let cell: Arc<OnceLock<(Personality, Personality)>> = Arc::new(OnceLock::new());
    let pc = Arc::clone(&cell);
    let body = move |mut req: Request<'_, ()>| -> Response {
        let cmd = req.body.take();
        let (deferred, permit) = req.responder.defer();
        let Some(mut fs) = req.fs.take() else {
            return Response::Close;
        };
        let (root_pers, peer_pers) = *pc.get().expect("personalities set before serving");
        let as_root = cmd == b"root";
        let how = OpenHow::new().flags(OFlag::O_PATH);
        let held = move |done: FsDone, fs: &mut FsConn<'_>| {
            let file = done.file().expect("the ring holds the file");
            let then = move |done: FsDone, _fs: &mut FsConn<'_>| {
                let answer = match done.result() {
                    Ok(_) => "opened".to_owned(),
                    Err(truenas_ros::Error::Errno(Errno::EACCES)) => "denied".to_owned(),
                    Err(e) => format!("{e}"),
                };
                deferred.reply(echo_frame(answer.as_bytes()));
            };
            let read = ReopenAccess::Read;
            if as_root {
                fs.reopen_proc_as_root(file, read, then);
            } else {
                fs.reopen_proc(peer_pers, file, read, then);
            }
        };
        fs.open(root_pers, &anchor, c"f", how, held);
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
    // The ring must exist before the broker forks, since the broker inherits its fd, and the broker must fork before
    // any thread starts.
    let mut server = match Server::with_config([addr], cfg, protocol) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind with fs pool: {e}"),
    };
    let root_pers = server.register_self().expect("register_self");
    let broker = match CredBroker::spawn(&[&server]) {
        Ok(b) => b,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("CredBroker::spawn: {e}"),
    };
    let creds = broker.handle(0).expect("broker handle");
    let peer_pers = creds
        .register(&AsUser::new(NOBODY_UID, NOBODY_GID))
        .expect("register peer");
    cell.set((root_pers, peer_pers)).unwrap();

    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();
    let client = thread::spawn(move || -> io::Result<Vec<Vec<u8>>> {
        let _stop = ShutdownOnDrop(stop.clone());
        let mut s = connect_tcp(v4)?;
        let mut answers = Vec::new();
        for cmd in [&b"peer"[..], b"root"] {
            send_framed(&mut s, cmd)?;
            answers.push(recv_framed(&mut s)?);
        }
        drop(s);
        stop.shutdown();
        Ok(answers)
    });
    server.serve_forever().expect("serve_forever broker");
    let answers = client.join().unwrap().expect("client io");

    let text: Vec<String> = answers
        .iter()
        .map(|a| String::from_utf8_lossy(a).into_owned())
        .collect();
    assert_eq!(
        text,
        ["denied", "opened"],
        "the peer may not read a file of mode 0600, and the ring owner may"
    );
}

/// `open_chain`'s whole point: a directory the caller could never traverse, opened as the daemon, with the file inside
/// it still gated on the caller.
///
/// This is the property the split credential exists for. A `0700` daemon-owned tree grants nothing, so opening
/// something under it as the daemon proves nothing about the caller — the last step has to name the caller for the
/// kernel to decide their access to the file they actually asked for.
///
/// Three chains over the same tree say it three ways: the daemon reaches the file; the peer is refused at the file even
/// though the directory above it opened; and the peer is refused at the directory when it is the one traversing. The
/// second is the one that matters — a chain that leaked the daemon's credential into the last step would hand the peer
/// a file it may not read.
///
/// Root-only (the broker needs `CAP_SETUID` to become the peer);
/// skipped otherwise.
#[cfg(feature = "uring-fs")]
#[test]
fn fs_open_chain_gates_the_last_step_on_its_own_personality() {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::sync::OnceLock;
    use truenas_ros::sync_fs::{OFlag, OpenHow};
    use truenas_ros::uring_fs::{Anchor, AsUser, CredBroker, OpenStep, Personality, StepPath};

    if !root_or_skip("fs_open_chain_gates_the_last_step") {
        return; // the broker cannot become another uid without CAP_SETUID
    }
    const NOBODY_UID: u32 = 65_534;
    const NOBODY_GID: u32 = 65_534;

    let dir = truenas_ros::tempdir().unwrap();
    // `private/` is the daemon-owned tree: 0700, so the peer cannot even traverse it. `obj` inside it is 0600, so the
    // peer cannot read it either — two separate refusals, one per step.
    let private = dir.path().join("private");
    std::fs::create_dir(&private).unwrap();
    let obj = private.join("obj");
    std::fs::write(&obj, b"topsecret").unwrap();
    for (path, mode) in [(&private, 0o700), (&obj, 0o600)] {
        let c = CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: valid path; chmod cannot corrupt memory.
        assert_eq!(unsafe { libc::chmod(c.as_ptr(), mode) }, 0);
    }

    let cell: Arc<OnceLock<(Personality, Personality)>> = Arc::new(OnceLock::new());
    let anchor = match Anchor::open(dir.path()) {
        Ok(a) => a,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("anchor open: {e}"),
    };

    let pc = Arc::clone(&cell);
    let body = move |mut req: Request<'_, ()>| -> Response {
        let cmd = req.body.take();
        let (deferred, permit) = req.responder.defer();
        let Some(mut fs) = req.fs.take() else {
            return Response::Close;
        };
        let (root_pers, peer_pers) = *pc.get().expect("personalities set before serving");
        let anchor = anchor.clone();
        // Who walks the directory, and who opens the file under it.
        let (dir_who, leaf_who) = match cmd.as_slice() {
            b"root-root" => (root_pers, root_pers),
            b"root-peer" => (root_pers, peer_pers),
            _ => (peer_pers, peer_pers),
        };
        fs.open_chain(
            &anchor,
            vec![
                OpenStep {
                    path: StepPath::Fixed(c"private".to_owned()),
                    who: dir_who,
                    how: OpenHow::new().flags(OFlag::O_PATH | OFlag::O_DIRECTORY),
                },
                OpenStep {
                    path: StepPath::Fixed(c"obj".to_owned()),
                    who: leaf_who,
                    how: OpenHow::new().flags(OFlag::O_RDONLY),
                },
            ],
            move |done, fs| match done.file() {
                Some(file) => {
                    fs.close(file);
                    deferred.reply(echo_frame(b"opened"));
                }
                None => deferred.reply(echo_frame(b"denied")),
            },
        );
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
    let root_pers = server.register_self().expect("register_self");
    let broker = match CredBroker::spawn(&[&server]) {
        Ok(b) => b,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("CredBroker::spawn: {e}"),
    };
    let creds = broker.handle(0).expect("broker handle");
    let peer_pers = creds
        .register(&AsUser::new(NOBODY_UID, NOBODY_GID))
        .expect("register peer");
    cell.set((root_pers, peer_pers)).unwrap();

    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();
    let client = thread::spawn(move || -> io::Result<Vec<Vec<u8>>> {
        let _stop = ShutdownOnDrop(stop.clone()); // fail fast on panic
        let mut s = connect_tcp(v4)?;
        let mut out = Vec::new();
        for cmd in [b"root-root".as_slice(), b"root-peer", b"peer-peer"] {
            send_framed(&mut s, cmd)?;
            out.push(recv_framed(&mut s)?);
        }
        drop(s);
        stop.shutdown();
        Ok(out)
    });
    server.serve_forever().expect("serve_forever broker");
    let got = client.join().unwrap().expect("client io");

    assert_eq!(
        got[0], b"opened",
        "the daemon's own identity walks its 0700 tree and opens the file"
    );
    assert_eq!(
        got[1], b"denied",
        "the peer is refused at the file even though the daemon opened \
         the directory above it - the last step's personality is what \
         decides, and a chain that leaked the daemon's would hand over a \
         file the peer may not read"
    );
    assert_eq!(got[2], b"denied", "the peer cannot traverse the 0700 directory either");
}

/// The multi-reactor shape: rings created on the main thread before the broker forks, servers built on worker threads
/// after it, and the peer's personality minted on each ring before the thread that owns it has even mapped it. The
/// broker's personalities then gate opens on every ring exactly as they do on a server that built its own ring, which
/// is the proof that `setup_ring` + `with_ring` is the same server, constructed in two halves on two threads.
///
/// A ring created **before** the thread that will serve on it, mapped and driven by that thread, serves real requests.
///
/// This is the unprivileged half of the multi-reactor recipe: `setup_ring` builds each ring on this thread with no
/// other thread alive, then each worker takes one and calls `Server::with_ring`, which does the mapping on the thread
/// that will drive it. Nothing here needs a credential broker, so it runs on `ci.yml`'s unprivileged runner - the job
/// that gates merges, where `fs_broker_serves_rings_mapped_on_worker_threads` can only skip.
///
/// Two rings, so the per-ring construction is exercised more than once and the servers are proven independent rather
/// than aliased.
#[test]
fn rings_created_before_the_threads_that_serve_them() {
    use std::sync::mpsc;

    const RINGS: usize = 2;
    let cfg = ServerConfig {
        pool_size: 4,
        ..ServerConfig::default()
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());

    // Every ring first, on this thread, with no other thread alive yet.
    let mut rings = Vec::new();
    for _ in 0..RINGS {
        match setup_ring([addr.clone()], &cfg) {
            Ok(r) => rings.push(r),
            Err(e) if should_skip(&e) => return,
            Err(e) => panic!("setup_ring: {e}"),
        }
    }

    let (tx, rx) = mpsc::channel::<(usize, SocketAddrV4, ShutdownHandle)>();
    let mut workers = Vec::new();
    for (i, ring) in rings.into_iter().enumerate() {
        let (addr, tx) = (addr.clone(), tx.clone());
        workers.push(thread::spawn(move || {
            // Answer with this ring's index, so a reply proves which server served it and two rings cannot be one.
            let body = move |mut req: Request<'_, ()>| -> Response {
                let got = req.body.take();
                let mut out = got;
                out.extend_from_slice(format!("@{i}").as_bytes());
                Response::Reply(echo_frame(&out))
            };
            let protocol = Protocol {
                accept: |_: Incoming<'_>| Some(()),
                header: length_prefix_header::<()>(PrefixWidth::U32, Endian::Big, false),
                body,
            };
            let mut server =
                Server::with_ring([addr], cfg, protocol, ring).expect("with_ring on a ring created by another thread");
            let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
                panic!("expected Tcp");
            };
            tx.send((i, v4, server.shutdown_handle())).unwrap();
            server.serve_forever().expect("serve_forever");
        }));
    }
    drop(tx);

    let mut served = 0usize;
    for (i, v4, stop) in rx.iter() {
        let mut s = connect_tcp(v4).expect("connect");
        send_framed(&mut s, b"ping").expect("send");
        let got = recv_framed(&mut s).expect("recv");
        drop(s);
        stop.shutdown();
        assert_eq!(
            got,
            format!("ping@{i}").into_bytes(),
            "ring {i} served its own request on the thread that mapped it"
        );
        served += 1;
    }
    assert_eq!(served, RINGS, "every ring served");
    for w in workers {
        w.join().expect("worker");
    }
}

/// Root-only, because the **broker** half needs `CAP_SETUID` to become another uid. The skip is loud:
/// `TRUENAS_ROS_REQUIRE_CRED_BROKER=1` (armed in the QEMU job, which runs as root) turns a mis-provisioned runner red
/// instead of green. The unprivileged half of the same feature - a ring created on one thread and mapped, built and
/// driven on another - is covered without privilege by `rings_created_before_the_threads_that_serve_them`.
#[cfg(feature = "uring-fs")]
#[test]
fn fs_broker_serves_rings_mapped_on_worker_threads() {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::sync::OnceLock;
    use std::sync::mpsc;
    use truenas_ros::sync_fs::{OFlag, OpenHow};
    use truenas_ros::uring_fs::{Anchor, AsUser, CredBroker, Personality, RwFlags};

    if !is_root() {
        assert!(
            std::env::var_os("TRUENAS_ROS_REQUIRE_CRED_BROKER").is_none(),
            "TRUENAS_ROS_REQUIRE_CRED_BROKER is set but this process is not \
             root: the broker cannot become another uid without CAP_SETUID"
        );
        return;
    }
    const NOBODY_UID: u32 = 65_534;
    const NOBODY_GID: u32 = 65_534;
    const RINGS: u8 = 2;

    let dir = truenas_ros::tempdir().unwrap();
    let secret = dir.path().join("secret.txt");
    std::fs::write(&secret, b"topsecret").unwrap();
    let cpath = CString::new(secret.as_os_str().as_bytes()).unwrap();
    // SAFETY: valid path; chmod cannot corrupt memory.
    assert_eq!(unsafe { libc::chmod(cpath.as_ptr(), 0o600) }, 0);
    let anchor = match Anchor::open(dir.path()) {
        Ok(a) => a,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("anchor open: {e}"),
    };

    let cfg = ServerConfig {
        pool_size: 8,
        fs_ops: 16,
        ..ServerConfig::default()
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());

    // Every ring first, on this thread, with no other thread alive yet; then the broker over all of them.
    let mut rings = Vec::new();
    for _ in 0..RINGS {
        match setup_ring([addr.clone()], &cfg) {
            Ok(r) => rings.push(r),
            Err(e) if should_skip(&e) => return,
            Err(e) => panic!("setup_ring: {e}"),
        }
    }
    // One more ring, deliberately *not* handed to the broker: the pairing check has to refuse a reactor this broker
    // does not serve, or it is not a pairing check.
    let outsider = match setup_ring([addr.clone()], &cfg) {
        Ok(r) => r,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("setup_ring: {e}"),
    };
    let broker = match CredBroker::spawn(&rings.iter().collect::<Vec<_>>()) {
        Ok(b) => b,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("CredBroker::spawn: {e}"),
    };
    assert!(
        broker.handle_for(&outsider).is_err(),
        "a ring this broker does not serve must not get a handle"
    );
    drop(outsider);

    // Each worker mints the peer on its still-unmapped ring, maps it, builds the server around it, and reports its
    // address and stop handle before serving.
    let (tx, rx) = mpsc::channel::<(usize, SocketAddrV4, ShutdownHandle)>();
    let mut workers = Vec::new();
    for (i, ring) in rings.into_iter().enumerate() {
        // By ring, not by position: a personality is meaningful only on the ring that minted it, and `i` here is a
        // second list beside the first. The positional form must agree with it.
        let creds = broker.handle_for(&ring).expect("broker handle");
        assert_eq!(
            creds.ring(),
            broker.handle(i as u8).expect("broker handle").ring(),
            "handle_for and handle must name the same ring"
        );
        let anchor = anchor.clone();
        let addr = addr.clone();
        let tx = tx.clone();
        workers.push(thread::spawn(move || {
            let cell: Arc<OnceLock<(Personality, Personality)>> = Arc::new(OnceLock::new());
            let pc = Arc::clone(&cell);
            let body = move |mut req: Request<'_, ()>| -> Response {
                let cmd = req.body.take();
                let (deferred, permit) = req.responder.defer();
                let Some(mut fs) = req.fs.take() else {
                    return Response::Close;
                };
                let (root_pers, peer_pers) = *pc.get().expect("personalities set before serving");
                let anchor = anchor.clone();
                let ro = OpenHow::new().flags(OFlag::O_RDONLY);
                let who = if cmd == b"as-root" { root_pers } else { peer_pers };
                let path = CString::new("secret.txt").unwrap();
                fs.open(who, &anchor, &path, ro, move |done, fs| {
                    let Some(file) = done.file() else {
                        deferred.reply(echo_frame(b"denied"));
                        return;
                    };
                    fs.preadv2(
                        who,
                        file.clone(),
                        vec![vec![0u8; 64]],
                        0,
                        RwFlags::empty(),
                        move |d, fs| {
                            fs.close(file);
                            match d.result() {
                                Ok(n) => {
                                    let mut out = b"read:".to_vec();
                                    let mut v = d.into_bufs().pop().unwrap_or_default();
                                    v.truncate(n as usize);
                                    out.extend_from_slice(&v);
                                    deferred.reply(echo_frame(&out));
                                }
                                Err(_) => deferred.reply(echo_frame(b"read-err")),
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
            // The broker needs only the fd: the peer is minted on this ring before this thread maps it.
            let peer_pers = creds
                .register(&AsUser::new(NOBODY_UID, NOBODY_GID))
                .expect("register peer on a ring not yet mapped");
            let mut server =
                Server::with_ring([addr], cfg, protocol, ring).expect("with_ring on a ring created by another thread");
            let root_pers = server.register_self().expect("register_self");
            cell.set((root_pers, peer_pers)).unwrap();
            let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
                panic!("expected Tcp");
            };
            tx.send((i, v4, server.shutdown_handle())).unwrap();
            server.serve_forever().expect("serve_forever");
        }));
    }
    drop(tx);

    // Drive each ring in turn: both identities, both verdicts, then stop it.
    let mut served = 0u8;
    for (i, v4, stop) in rx.iter() {
        let mut s = connect_tcp(v4).expect("connect");
        send_framed(&mut s, b"as-peer").expect("send");
        let peer = recv_framed(&mut s).expect("recv");
        send_framed(&mut s, b"as-root").expect("send");
        let root = recv_framed(&mut s).expect("recv");
        drop(s);
        stop.shutdown();
        assert_eq!(
            root, b"read:topsecret",
            "ring {i}: the daemon's own identity reads its 0600 file"
        );
        assert_eq!(
            peer, b"denied",
            "ring {i}: the peer is refused at open by a personality minted \
             before the ring was mapped"
        );
        served += 1;
    }
    assert_eq!(served, RINGS, "every worker served");
    for w in workers {
        w.join().expect("worker");
    }
}

/// Real privilege boundary for `fgetxattr_as_root`: a `trusted.*` attribute is invisible to an unprivileged reader (the
/// kernel hides it without `CAP_SYS_ADMIN`, returning `ENODATA`), while the ambient-root path (`personality = 0`) holds
/// the capability and returns the value. The peer opens a world-readable file, then reads the attribute both ways.
///
/// Root-only (the broker needs `CAP_SETUID`); skipped otherwise, and skipped if the fs refuses `trusted.*` or the
/// kernel lacks fd-xattr (< 6.13).
#[cfg(feature = "uring-fs")]
#[test]
fn fs_as_root_reads_trusted_xattr_across_privilege() {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::OnceLock;
    use truenas_ros::sync_fs::{OFlag, OpenHow};
    use truenas_ros::uring_fs::{Anchor, AsUser, CredBroker, Personality};

    if !root_or_skip("fs_as_root_reads_trusted_xattr_across_privilege") {
        return;
    }
    const NOBODY_UID: u32 = 65_534;
    const NOBODY_GID: u32 = 65_534;

    let dir = truenas_ros::tempdir().unwrap();
    // `tempdir` creates the scratch directory 0700; the unprivileged peer must traverse it to reach the file, and DAC
    // on the path is not the boundary under test.
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    let f = dir.path().join("t.txt");
    std::fs::write(&f, b"body").unwrap();
    let cpath = CString::new(f.as_os_str().as_bytes()).unwrap();
    // World-readable so the unprivileged peer can OPEN it - the boundary under test is the xattr `CAP_SYS_ADMIN` check,
    // not DAC on open.
    // SAFETY: valid path; chmod cannot corrupt memory.
    assert_eq!(unsafe { libc::chmod(cpath.as_ptr(), 0o644) }, 0);
    // Seed a `trusted.*` attribute (root/CAP_SYS_ADMIN only); skip if the fs refuses it. Through `set_user_xattr`, as
    // the privileged-xattr fixture above already is: the one assertion this test makes sits at its end, so a
    // hand-rolled `libc::setxattr` with a silent `return` reports ok having tested nothing - with
    // `TRUENAS_ROS_REQUIRE_XATTRS` armed, which `qemu-4-test.sh` arms naming this very probe.
    if !set_user_xattr(&f, b"trusted.tr_test", b"cap") {
        return; // filesystem refuses trusted.* here
    }

    let cell: Arc<OnceLock<Personality>> = Arc::new(OnceLock::new());
    let anchor = match Anchor::open(dir.path()) {
        Ok(a) => a,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("anchor open: {e}"),
    };

    let pc = Arc::clone(&cell);
    let body = move |mut req: Request<'_, ()>| -> Response {
        let _ = req.body.take();
        let (deferred, permit) = req.responder.defer();
        let Some(mut fs) = req.fs.take() else {
            return Response::Close;
        };
        let peer = *pc.get().expect("peer personality set before serving");
        let anchor = anchor.clone();
        let ro = OpenHow::new().flags(OFlag::O_RDONLY);
        let path = CString::new("t.txt").unwrap();
        fs.open(peer, &anchor, &path, ro, move |done, fs| {
            let Some(file) = done.file() else {
                deferred.reply(echo_frame(b"open-denied"));
                return;
            };
            let name = CString::new("trusted.tr_test").unwrap();
            // (1) As the unprivileged peer: trusted.* is hidden -> ENODATA.
            fs.fgetxattr(peer, file.clone(), name.clone(), vec![0u8; 32], move |d1, fs| {
                let peer_failed = d1.result().is_err();
                let name2 = CString::new("trusted.tr_test").unwrap();
                // (2) As ambient root: CAP_SYS_ADMIN -> the value.
                fs.fgetxattr_as_root(file, name2.clone(), vec![0u8; 32], move |d2, _fs| {
                    let mut out = Vec::new();
                    out.push(if peer_failed { b'1' } else { b'0' });
                    out.push(b':');
                    match d2.result() {
                        Ok(n) => {
                            let mut v = d2.into_bufs().pop().unwrap_or_default();
                            v.truncate(n as usize);
                            out.extend_from_slice(&v);
                        }
                        Err(_) => out.extend_from_slice(b"root-err"),
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
        fs_ops: 16,
        ..ServerConfig::default()
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let mut server = match Server::with_config([addr], cfg, protocol) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind with fs pool: {e}"),
    };
    let _root = server.register_self().expect("register_self");
    let broker = match CredBroker::spawn(&[&server]) {
        Ok(b) => b,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("CredBroker::spawn: {e}"),
    };
    let creds = broker.handle(0).expect("broker handle");
    let peer = creds
        .register(&AsUser::new(NOBODY_UID, NOBODY_GID))
        .expect("register peer");
    cell.set(peer).unwrap();

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
    server.serve_forever().expect("serve_forever trusted-xattr");
    let reply = client.join().unwrap().expect("client io");
    // "1" = the peer's read failed (trusted.* hidden without CAP_SYS_ADMIN);
    // ":cap" = the ambient-root read returned the value.
    assert_eq!(
        reply, b"1:cap",
        "as-root read the trusted.* the unprivileged peer cannot see"
    );
}

/// An fd opened for a connection torn down **mid-chain** is reclaimed when the connection closes. A handler opens a
/// FIFO and submits a read that blocks forever (no writer sends data), then the peer disconnects before the read
/// completes. Plain-fd files close by `Arc`-drop, but an in-flight op parks the fd until its CQE - so the
/// connection-teardown sweep (`cancel_owned_by`) cancels the op; it completes `ECANCELED`, the parked `Arc` drops, and
/// the fd closes without waiting for whole-server teardown. Validates the Arc-model replacement for the old
/// `close_owned_by`.
#[cfg(feature = "uring-fs")]
#[test]
fn fs_fd_reclaimed_on_connection_close_midchain() {
    use std::ffi::CString;
    use std::os::fd::RawFd;
    use std::os::unix::ffi::OsStrExt;
    use std::sync::OnceLock;
    use std::time::Duration;
    use truenas_ros::sync_fs::{OFlag, OpenHow};
    use truenas_ros::uring_fs::{Anchor, Personality, RwFlags};

    let dir = truenas_ros::tempdir().unwrap();
    let fifo = dir.path().join("f.fifo");
    let cfifo = CString::new(fifo.as_os_str().as_bytes()).unwrap();
    // SAFETY: valid NUL-terminated path.
    if unsafe { libc::mkfifo(cfifo.as_ptr(), 0o600) } != 0 {
        return;
    }
    // Hold the FIFO open O_RDWR so the handler's O_RDONLY open succeeds without blocking and its reads block (no data
    // is ever written).
    // SAFETY: valid path; O_RDWR|O_NONBLOCK on a FIFO does not block.
    let keep = unsafe { libc::open(cfifo.as_ptr(), libc::O_RDWR | libc::O_NONBLOCK) };
    assert!(keep >= 0, "open fifo O_RDWR");

    let opened: Arc<OnceLock<RawFd>> = Arc::new(OnceLock::new());
    let pers: Arc<OnceLock<Personality>> = Arc::new(OnceLock::new());
    let anchor = match Anchor::open(dir.path()) {
        Ok(a) => a,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("anchor open: {e}"),
    };

    let oc = Arc::clone(&opened);
    let pc = Arc::clone(&pers);
    let body = move |mut req: Request<'_, ()>| -> Response {
        let _ = req.body.take();
        let (deferred, permit) = req.responder.defer();
        let Some(mut fs) = req.fs.take() else {
            return Response::Close;
        };
        let who = *pc.get().expect("personality set before serving");
        let anchor = anchor.clone();
        let oc = Arc::clone(&oc);
        let path = CString::new("f.fifo").unwrap();
        let how = OpenHow::new().flags(OFlag::O_RDONLY);
        fs.open(who, &anchor, &path, how, move |done, fs| {
            let Some(file) = done.file() else {
                deferred.close();
                return;
            };
            let _ = oc.set(file.as_raw_fd());
            // Reply now, then submit a read that never completes (FIFO, no data): it parks the file's `Arc` in the op
            // entry. The peer will disconnect with this read still in flight.
            deferred.reply(echo_frame(b"opened"));
            fs.preadv2(
                who,
                file.clone(),
                vec![vec![0u8; 16]],
                0,
                RwFlags::empty(),
                move |_d, fs| {
                    fs.close(file); // never reached - the read blocks forever
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
    let oc2 = Arc::clone(&opened);
    let client = thread::spawn(move || -> io::Result<bool> {
        let _stop = ShutdownOnDrop(stop.clone()); // fail fast on panic
        let mut s = connect_tcp(v4)?;
        send_framed(&mut s, b"go")?;
        let _ = recv_framed(&mut s)?; // "opened": fd recorded, read in flight
        drop(s); // disconnect mid-chain, read still in flight
        let fd = *oc2.get().expect("handler recorded the fd");
        let link = format!("/proc/self/fd/{fd}");
        // Poll for reclamation: the fd is reclaimed iff /proc/self/fd/N stops resolving to the FIFO (closed, or reused
        // for a different file).
        let mut leaked = true;
        for _ in 0..80 {
            thread::sleep(Duration::from_millis(10));
            match std::fs::read_link(&link) {
                Ok(t) if t == fifo => {}
                _ => {
                    leaked = false;
                    break;
                }
            }
        }
        stop.shutdown();
        Ok(leaked)
    });
    server.serve_forever().expect("serve_forever fd-leak");
    let leaked = client.join().unwrap().expect("client io");
    // SAFETY: closing our own kept fd.
    unsafe { libc::close(keep) };
    assert!(
        !leaked,
        "the fd opened for a connection torn down mid-chain was not reclaimed \
         after the connection closed (leaked until server teardown)"
    );
}

/// `FsConn::mkdir_path` builds a missing tree on-loop and hands back the deepest directory as a real descriptor.
///
/// Two requests, because the two paths through it differ: the first walks a tree that does not exist, the second takes
/// the fast path over the tree the first made. The reply is the `fsync` of the returned handle, which an `O_PATH`
/// directory would answer `EBADF`.
#[cfg(feature = "uring-fs")]
#[test]
fn fs_conn_mkdir_path_builds_a_tree_and_answers_a_real_directory() {
    use std::sync::OnceLock;
    use std::time::Duration;
    use truenas_ros::sync_fs::{Mode, OFlag, OpenHow};
    use truenas_ros::uring_fs::{Anchor, Personality};

    let dir = truenas_ros::tempdir().unwrap();
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
        let how = OpenHow::new().flags(OFlag::O_RDONLY | OFlag::O_DIRECTORY);
        let mode = Mode::from_bits_truncate(0o755);
        fs.mkdir_path(who, &anchor, c"a/b/c", mode, how, move |done, fs| {
            let Some(deepest) = done.file() else {
                return deferred.close();
            };
            fs.fsync(who, deepest, move |res, _fs| match res.result() {
                Ok(_) => deferred.reply(echo_frame(b"ok")),
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
    let client = thread::spawn(move || -> io::Result<(Vec<u8>, Vec<u8>)> {
        let _stop = ShutdownOnDrop(stop.clone()); // fail fast on panic
        // Shut down on every exit: one that skipped it would strand `serve_forever` and hang rather than fail.
        let out = (|| {
            let mut s = connect_tcp(v4)?;
            s.set_read_timeout(Some(Duration::from_secs(5)))?;
            // The walk: nothing of `a/b/c` exists yet.
            send_framed(&mut s, b"walk")?;
            let walked = recv_framed(&mut s)?;
            // The fast path: the tree is whole, so one open settles it.
            send_framed(&mut s, b"again")?;
            let again = recv_framed(&mut s)?;
            Ok((walked, again))
        })();
        stop.shutdown();
        out
    });
    server.serve_forever().expect("serve_forever mkdir_path");
    let (walked, again) = client.join().unwrap().expect("client io");
    assert_eq!(walked, b"ok", "the walk answered a flushable directory");
    assert_eq!(again, b"ok", "an existing tree is not an error");
    assert!(dir.path().join("a/b/c").is_dir(), "the tree was created");
}

/// `FsConn::mkdir_path` refuses a path whose components it cannot rebuild, and refuses it on **shape** rather than on
/// whether the kernel resolves it.
///
/// `a/../b` is the case worth pinning: `openat2` under `CONFINED_RESOLVE` resolves it, so a probe-first order would
/// answer it with a directory wherever the tree happened to exist and refuse it everywhere else - one path meaning two
/// things. A walk that has to create `b` cannot know what `a/..` names, so the answer is the same either way: refused,
/// before anything is submitted.
///
/// An invalid argument answers `on_done` before `mkdir_path` returns, with `EINVAL` and the refusal mark - so the
/// handler replies to the peer instead of the connection being shed over a caller bug, and the callback runs inline
/// while the handler is still on its way to `Response::Defer`. That ordering is the other thing this pins: a
/// `Deferred::reply` made before the `Defer(permit)` verdict is processed rides the injection queue and lands once the
/// park exists.
#[cfg(feature = "uring-fs")]
#[test]
fn fs_conn_mkdir_path_refuses_a_path_it_cannot_rebuild() {
    use std::sync::OnceLock;
    use std::time::Duration;
    use truenas_ros::sync_fs::{Mode, OFlag, OpenHow};
    use truenas_ros::uring_fs::{Anchor, Personality};

    let dir = truenas_ros::tempdir().unwrap();
    // `a` exists, so `a/../b` is a path the kernel WOULD resolve if the walk ever let it near `openat2`.
    std::fs::create_dir(dir.path().join("a")).unwrap();
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
        let how = OpenHow::new().flags(OFlag::O_RDONLY | OFlag::O_DIRECTORY);
        let mode = Mode::from_bits_truncate(0o755);
        fs.mkdir_path(who, &anchor, c"a/../b", mode, how, move |d, _fs| {
            // Fired inline, before `mkdir_path` returned: the screen answers rather than dropping, and the reply below
            // is injected ahead of the `Defer` verdict being processed.
            let verdict = match d.result() {
                Err(truenas_ros::Error::Errno(e)) if d.was_refused() => {
                    format!("refused:{e:?}")
                }
                other => format!("wrong:{other:?}"),
            };
            deferred.reply(echo_frame(verdict.as_bytes()));
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
    let client = thread::spawn(move || -> io::Result<io::Result<Vec<u8>>> {
        let _stop = ShutdownOnDrop(stop.clone()); // fail fast on panic
        let out = (|| {
            let mut s = connect_tcp(v4)?;
            s.set_read_timeout(Some(Duration::from_secs(5)))?;
            send_framed(&mut s, b"go")?;
            Ok(recv_framed(&mut s))
        })();
        stop.shutdown();
        out
    });
    server.serve_forever().expect("serve_forever mkdir_path refusal");
    let got = client.join().unwrap().expect("client io");
    assert_eq!(
        got.expect("the handler answered instead of shedding the peer"),
        b"refused:EINVAL".to_vec(),
        "the callback saw the marked refusal"
    );
    assert!(
        !dir.path().join("b").exists() && !dir.path().join("a/b").exists(),
        "a refused path creates nothing"
    );
}
/// `FsConn::mkdir_path` answers with a directory or with nothing: a `how` that would make the final open produce a
/// *file* is refused.
///
/// `O_CREAT` is the case that bites. The probe opens the whole path, so with `a/b` present and `c` missing it would
/// create a regular file `c` and hand it back as though the tree had been built - success, wrong object, nothing on the
/// wire to say so. The kernel does refuse `O_DIRECTORY | O_CREAT` (`build_open_flags`, `fs/open.c:1278-1284`),
/// but only at the syscall, by which point the walk has created the tree;
/// the refusal here happens before anything is submitted.
///
/// `O_TMPFILE` is the case that hides: it is `__O_TMPFILE | O_DIRECTORY`, so forcing `O_DIRECTORY` does not exclude it
/// and a naive `flags & O_TMPFILE` test matches every plain directory open.
///
/// Both refusals answer the callback inline with a marked `EINVAL`;
/// the handler replies, and the peer keeps its connection.
#[cfg(feature = "uring-fs")]
#[test]
fn fs_conn_mkdir_path_refuses_a_how_that_would_answer_with_a_file() {
    use std::sync::OnceLock;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    use truenas_ros::sync_fs::{Mode, OFlag, OpenHow};
    use truenas_ros::uring_fs::{Anchor, Personality};

    let dir = truenas_ros::tempdir().unwrap();
    // The parents exist and the leaf does not - exactly the shape where an `O_CREAT` probe would succeed by creating a
    // regular file.
    std::fs::create_dir_all(dir.path().join("a/b")).unwrap();
    let pers: Arc<OnceLock<Personality>> = Arc::new(OnceLock::new());
    let anchor = match Anchor::open(dir.path()) {
        Ok(a) => a,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("anchor open: {e}"),
    };

    // Which request is being served: 0 => O_CREAT, 1 => O_TMPFILE.
    let nth = Arc::new(AtomicUsize::new(0));
    let pc = Arc::clone(&pers);
    let nc = Arc::clone(&nth);
    let body = move |mut req: Request<'_, ()>| -> Response {
        let (deferred, permit) = req.responder.defer();
        let Some(mut fs) = req.fs.take() else {
            return Response::Close;
        };
        let who = *pc.get().expect("personality set before serving");
        let anchor = anchor.clone();
        let flags = match nc.fetch_add(1, Ordering::Relaxed) {
            0 => OFlag::O_RDONLY | OFlag::O_CREAT,
            _ => OFlag::O_RDWR | OFlag::O_TMPFILE,
        };
        let how = OpenHow::new().flags(flags).mode(Mode::from_bits_truncate(0o644));
        let mode = Mode::from_bits_truncate(0o755);
        fs.mkdir_path(who, &anchor, c"a/b/c", mode, how, move |d, _fs| {
            // Fired inline with the marked refusal; see the sibling test for the ordering this rides on.
            let ok = matches!(
                d.result(),
                Err(truenas_ros::Error::Errno(truenas_ros::errno::Errno::EINVAL))
            ) && d.was_refused();
            deferred.reply(echo_frame(if ok { b"refused" } else { b"wrong" }));
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
    let client = thread::spawn(move || -> io::Result<[bool; 2]> {
        let _stop = ShutdownOnDrop(stop.clone()); // fail fast on panic
        let out = (|| {
            let mut got = [false; 2];
            for slot in got.iter_mut() {
                let mut s = connect_tcp(v4)?;
                s.set_read_timeout(Some(Duration::from_secs(5)))?;
                send_framed(&mut s, b"go")?;
                *slot = recv_framed(&mut s)? == b"refused";
            }
            Ok(got)
        })();
        stop.shutdown();
        out
    });
    server.serve_forever().expect("serve_forever mkdir_path how");
    let answered = client.join().unwrap().expect("client io");
    assert_eq!(
        answered,
        [true, true],
        "both O_CREAT and O_TMPFILE must be refused, with the refusal \
         answered to the handler rather than the connection shed"
    );
    let leaf = dir.path().join("a/b/c");
    assert!(
        !leaf.exists(),
        "a refused `how` must not leave anything at the leaf, least of all \
         a regular file standing in for the directory"
    );
}
