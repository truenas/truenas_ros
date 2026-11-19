use super::*;
use std::path::PathBuf;
use std::sync::OnceLock;
use truenas_ros::sync_fs::{Mode, OFlag, OpenHow, StatxMask, ZfsSetattr};
use truenas_ros::uring_fs::{Anchor, Chain, ChainStep, Personality, Reopen, ReopenAccess};

/// A ZFS dataset to set on, or `None` to skip where `TRUENAS_ROS_REQUIRE_ZFS` allows it.
fn dataset() -> Option<PathBuf> {
    let ds = ["TRUENAS_ROS_POSIX_DATASET", "TRUENAS_ROS_NFS4_DATASET"]
        .iter()
        .filter_map(|v| std::env::var_os(v).map(PathBuf::from))
        .chain(["/POSIXACL", "/NFSV4ACL"].iter().map(PathBuf::from))
        .find(|d| d.is_dir());
    if ds.is_none() {
        assert!(
            std::env::var_os("TRUENAS_ROS_REQUIRE_ZFS").is_none(),
            "TRUENAS_ROS_REQUIRE_ZFS is set but no ZFS dataset is present"
        );
    }
    ds
}

/// Serve one request on a ring with or without the chain slots, whose handler opens `name` under `ds` `O_PATH` and
/// sets its mode to 0600 through a chain that reopens it, then answers what the chain gave.
fn serve_a_chain(ds: &Path, name: &'static std::ffi::CStr, fs_chain_slots: bool) -> Option<String> {
    let pers: Arc<OnceLock<Personality>> = Arc::new(OnceLock::new());
    let anchor = match Anchor::open(ds) {
        Ok(a) => a,
        Err(e) if should_skip(&e) => return None,
        Err(e) => panic!("anchor open: {e}"),
    };
    let pc = Arc::clone(&pers);
    let body = move |mut req: Request<'_, ()>| -> Response {
        let (deferred, permit) = req.responder.defer();
        let Some(mut fs) = req.fs.take() else {
            return Response::Close;
        };
        let who = *pc.get().expect("personality set before serving");
        fs.open(
            who,
            &anchor,
            name,
            OpenHow::new().flags(OFlag::O_PATH),
            move |done, fs| {
                let Some(file) = done.file() else {
                    return deferred.reply(echo_frame(format!("OPEN {:?}", done.result()).as_bytes()));
                };
                let set = ZfsSetattr::new().mode(Mode::S_IRUSR | Mode::S_IWUSR).to_bytes();
                let chain = Chain {
                    file,
                    reopen: Some(Reopen::AsCaller(ReopenAccess::Read)),
                    truncate: None,
                    set: Some(set),
                    statx: Some(StatxMask::MODE),
                    sync: true,
                };
                fs.chain(who, chain, move |done, _fs| {
                    let msg = format!(
                        "refused {} mode {:?} set {:?} sync {:?} close {:?}",
                        done.was_refused(),
                        done.stat().map(|s| format!("{:o}", s.mode() & 0o7777)),
                        done.step(ChainStep::Set),
                        done.step(ChainStep::Sync),
                        done.step(ChainStep::Close),
                    );
                    deferred.reply(echo_frame(msg.as_bytes()));
                });
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
        pool_size: 16,
        fs_ops: 16,
        fs_chain_slots,
        ..ServerConfig::default()
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
    let stop = server.shutdown_handle();
    let client = thread::spawn(move || -> io::Result<Vec<u8>> {
        let _stop = ShutdownOnDrop(stop.clone()); // fail fast on panic
        let mut s = connect_tcp(v4)?;
        s.set_read_timeout(Some(Duration::from_secs(5)))?;
        send_framed(&mut s, b"chain")?;
        let reply = recv_framed(&mut s);
        drop(s);
        stop.shutdown();
        reply
    });
    server.serve_forever().expect("serve_forever");
    let reply = client.join().unwrap().expect("client io");
    Some(String::from_utf8_lossy(&reply).into_owned())
}

/// On a server with the chain slots, a chain reopens a file held `O_PATH` into its op's slot and sets, reads, syncs
/// and closes it there, and the mode it set is on the file. Without the slots the same chain is refused with a marked
/// `EINVAL` and the file keeps its mode.
#[test]
fn a_chain_sets_through_its_reopen_only_on_a_server_with_the_slots() {
    use std::os::unix::fs::PermissionsExt;
    let Some(ds) = dataset() else {
        return;
    };
    let fp = ds.join("ros-fs-chain.bin");
    let _ = std::fs::remove_file(&fp);
    std::fs::write(&fp, b"x").unwrap();
    std::fs::set_permissions(&fp, std::fs::Permissions::from_mode(0o644)).unwrap();
    let mode = || std::fs::metadata(&fp).unwrap().permissions().mode() & 0o7777;

    let Some(without) = serve_a_chain(&ds, c"ros-fs-chain.bin", false) else {
        return;
    };
    assert_eq!(
        without,
        "refused true mode None set Some(Err(Errno(EINVAL))) sync Some(Err(Errno(EINVAL))) close \
         Some(Err(Errno(EINVAL)))"
    );
    assert_eq!(mode(), 0o644);

    let Some(with) = serve_a_chain(&ds, c"ros-fs-chain.bin", true) else {
        return;
    };
    let _ = std::fs::remove_file(&fp);
    assert_eq!(
        with,
        "refused false mode Some(\"600\") set Some(Ok(0)) sync Some(Ok(0)) close Some(Ok(0))"
    );
}
