use super::*;

// ---- the download side ----------------------------------------------------

/// Serve one file body per connection and answer how many large allocations `conns` connections cost.
///
/// Connections, not requests, is the axis that matters: chunk buffers used to be minted per connection and held until
/// it closed, so the cost scaled with the connection table rather than with how many bodies were actually moving.
#[cfg(feature = "uring-fs")]
fn download_cost(warmup: usize, measured: usize) -> Option<usize> {
    use std::io::Read as _;
    use truenas_ros::net::server::{Endian, PrefixWidth, Protocol, Request, Response, length_prefix_header};

    const CHUNK: usize = 64 * 1024;
    const SIZE: usize = 4 * CHUNK; // four chunk reads per body

    let tmp = truenas_ros::tempdir().expect("tempdir");
    let dir = tmp.path().to_owned();
    let path = dir.join("obj");
    std::fs::write(&path, vec![0x41u8; SIZE]).expect("write fixture");

    let cfg = ServerConfig {
        pool_size: 32,
        fs_ops: 16,
        fs_body_chunk: CHUNK,
        ..ServerConfig::default()
    };
    // One open through a standalone fs host, cloned per request: only an fs reactor can mint a `File`, but the fd is
    // host-independent once open and `File` is an `Arc<OwnedFd>`.
    let file = {
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
                let r = handle.open(who, &anchor, c"obj", OpenHow::new().flags(OFlag::O_RDONLY));
                let _ = ftx.send(r);
                stop_fs.shutdown();
            });
            afs.run().expect("fs host run");
        });
        frx.recv().expect("open outcome").expect("open")
    };
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(PrefixWidth::U32, Endian::Big, false),
        body: move |_req: Request<'_, ()>| Response::ReplyFile {
            head: Vec::new(),
            file: file.clone(),
            offset: 0,
            len: SIZE as u64,
            close: true,
        },
    };

    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let mut server = match Server::with_config([addr], cfg, proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return None,
        Err(e) => panic!("bind: {e}"),
    };
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stats = server.stats_handle();
    let stop = server.shutdown_handle();

    let client = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone());
        // Sized once, outside the measurement: a growing client buffer reallocates past the counting threshold several
        // times per body and would be indistinguishable from the server allocating per read.
        let mut got = vec![0u8; SIZE];
        let one = |got: &mut [u8]| {
            let mut s = TcpStream::connect(v4).expect("connect");
            s.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
            s.write_all(&1u32.to_be_bytes()).expect("len");
            s.write_all(b"g").expect("req");
            s.read_exact(got).expect("body");
            assert!(got.iter().all(|&b| b == 0x41), "intact");
        };
        for _ in 0..warmup {
            one(&mut got);
        }
        let before = BIG_ALLOCS.load(Ordering::Relaxed);
        for _ in 0..measured {
            one(&mut got);
        }
        let cost = BIG_ALLOCS.load(Ordering::Relaxed) - before;
        stop.shutdown();
        cost
    });

    server.serve_forever().expect("serve_forever");
    let cost = client.join().expect("client thread");
    let _ = stats.snapshot();
    Some(cost)
}

/// Serving file bodies must not allocate per connection.
///
/// Chunk buffers came off a per-connection pool minted on the first file reply and held until close, so N connections
/// cost N x FILE_TAIL_BUFS buffers of `fs_body_chunk` - `pool_size` x 2 x a megabyte in a real deployment, held whether
/// or not anything was streaming. Drawn from the reactor's ring instead, the cost is flat in the connection count.
#[cfg(feature = "uring-fs")]
#[test]
fn serving_file_bodies_does_not_allocate_per_connection() {
    let _turn = MEASURING.lock().unwrap_or_else(|e| e.into_inner());
    // Warm the pool first, then measure: growing the ring allocates, once, and that is not what this is about.
    let Some(few) = download_cost(8, 4) else {
        return; // io_uring unavailable
    };
    let Some(many) = download_cost(8, 32) else {
        return;
    };
    assert!(
        many <= few + 8,
        "download cost scales with connections: 4 more cost {few} large \
         allocations, 32 more cost {many}. Chunk buffers tied to connection \
         lifetime look exactly like this."
    );
}
