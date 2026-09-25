//! Does a streamed upload allocate per window?
//!
//! Its own test binary, and it has to be: the measurement is a process-wide
//! allocation count, so anything else running in the same process is noise.
//! One test, one server, one client.
//!
//! The property is the reason the recv buffer pool exists. A pool that only
//! covered request heads would leave the upload path minting a buffer per
//! window - at a 128 KiB window that is one allocation per 128 KiB of
//! payload, tens of thousands of them on a multi-gigabyte PUT - and would be
//! decorative. Measured rather than reasoned about, because the code path
//! that decides it (`body_placement_threshold` vs the pool buffer's size)
//! is three modules away from the allocation.
#![cfg(all(target_os = "linux", feature = "http", feature = "net-server"))]

use std::alloc::{GlobalAlloc, Layout, System};
use std::io::{self, Read, Write};
use std::net::{SocketAddrV4, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;
use truenas_ros::http::{
    HttpConfig, HttpRequest, HttpResponse, HttpVerdict, Stage,
    protocol_streaming,
};
use truenas_ros::net::server::{
    Incoming, Server, ServerAddr, ServerConfig, ShutdownHandle,
};
use truenas_ros::{Errno, Error};

/// Allocations of at least this size are counted.
///
/// Body buffers are the only thing on this path that reaches it: the window
/// is 128 KiB and the placement threshold is 64 KiB, so a placed window
/// lands here and nothing else does. Counting every allocation instead would
/// drown the signal in the reply-building and framing traffic that is not
/// what this measures.
const BIG: usize = 64 * 1024;

static BIG_ALLOCS: AtomicUsize = AtomicUsize::new(0);

/// The second threshold, for costs whose unit is smaller than [`BIG`].
///
/// A copy or fallback need not move a full window at a time to matter -
/// anything from a chunk read up scales with the payload all the same.
/// Counting from half a `RECV_CHUNK` keeps such costs visible while
/// staying above the framing and reply-building traffic, which is what a
/// lower bar would drown the signal in.
const MED: usize = 2 * 1024;

static MED_ALLOCS: AtomicUsize = AtomicUsize::new(0);

/// The counter is process-global, so two measurements running at once
/// report each other's allocations. Cargo runs a binary's tests as threads,
/// so they have to take turns.
static MEASURING: std::sync::Mutex<()> = std::sync::Mutex::new(());

struct Counting;

// SAFETY: every method delegates to `System` unchanged; the counter is the
// only addition and it touches no allocator state.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        if l.size() >= BIG {
            BIG_ALLOCS.fetch_add(1, Ordering::Relaxed);
        }
        if l.size() >= MED {
            MED_ALLOCS.fetch_add(1, Ordering::Relaxed);
        }
        unsafe { System.alloc(l) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        unsafe { System.dealloc(p, l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, new: usize) -> *mut u8 {
        if new >= BIG {
            BIG_ALLOCS.fetch_add(1, Ordering::Relaxed);
        }
        if new >= MED {
            MED_ALLOCS.fetch_add(1, Ordering::Relaxed);
        }
        unsafe { System.realloc(p, l, new) }
    }
}

#[global_allocator]
static A: Counting = Counting;

fn is_unavailable(e: &Error) -> bool {
    matches!(
        e,
        // ENOMEM: rings pin pages against RLIMIT_MEMLOCK, so a loaded
        // box exhausts it and ring creation fails - environmental, and
        // the REQUIRE variable turns the skip red where it must not
        // happen.
        Error::Errno(
            Errno::EPERM | Errno::ENOSYS | Errno::EACCES | Errno::ENOMEM
        )
    )
}

fn should_skip(e: &Error) -> bool {
    if is_unavailable(e) {
        assert!(
            std::env::var_os("TRUENAS_ROS_REQUIRE_IO_URING").is_none(),
            "TRUENAS_ROS_REQUIRE_IO_URING set but io_uring unavailable: {e}"
        );
        return true;
    }
    false
}

struct ShutdownOnDrop(ShutdownHandle);
impl Drop for ShutdownOnDrop {
    fn drop(&mut self) {
        self.0.shutdown();
    }
}

/// One HTTP chunk of `n` bytes, framed for a chunked PUT.
fn chunked_put(payload: &[u8], chunk: usize) -> Vec<u8> {
    let mut wire = b"PUT /up HTTP/1.1\r\nHost: t\r\n\
                     Transfer-Encoding: chunked\r\n\r\n"
        .to_vec();
    for part in payload.chunks(chunk) {
        wire.extend_from_slice(format!("{:x}\r\n", part.len()).as_bytes());
        wire.extend_from_slice(part);
        wire.extend_from_slice(b"\r\n");
    }
    wire.extend_from_slice(b"0\r\n\r\n");
    wire
}

/// A `Content-Length` PUT: the head, then the raw payload.
#[cfg(feature = "uring-fs")] // both call sites are gated on it
fn cl_put(payload: &[u8]) -> Vec<u8> {
    let mut req = format!(
        "PUT /o HTTP/1.1\r\nHost: t\r\nContent-Length: {}\r\n\r\n",
        payload.len()
    )
    .into_bytes();
    req.extend_from_slice(payload);
    req
}

fn read_status(s: &mut TcpStream) -> io::Result<u16> {
    let mut buf = Vec::new();
    let mut b = [0u8; 1];
    while !buf.ends_with(b"\r\n\r\n") {
        if s.read(&mut b)? == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "eof"));
        }
        buf.push(b[0]);
    }
    let head = String::from_utf8_lossy(&buf).to_string();
    head.split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .ok_or_else(|| io::Error::other(format!("no status in {head:?}")))
}

/// Upload `mib` MiB in 128 KiB chunks and answer how many large
/// allocations the whole exchange cost.
fn upload_cost(mib: usize) -> Option<usize> {
    let cfg = ServerConfig {
        pool_size: 8,
        // A head cap, which is the configuration streaming creates: no
        // single message is a whole body.
        max_request_bytes: 512 * 1024,
        ..ServerConfig::default()
    };
    let proto = protocol_streaming(
        HttpConfig::default(),
        1 << 30,
        |_i: Incoming<'_>| Some(0usize),
        |req: HttpRequest<'_>, seen: &mut usize| match req.stage {
            Stage::Open => {
                *seen = 0;
                HttpVerdict::Continue
            }
            // Consume the window without keeping it - what a handler
            // writing to a file does, and what makes the buffer reusable.
            Stage::Window => {
                *seen += req.body.len();
                HttpVerdict::Continue
            }
            Stage::End => HttpVerdict::Respond(
                HttpResponse::new(200).header("x-bytes", seen.to_string()),
            ),
            Stage::Whole => HttpVerdict::Respond(HttpResponse::new(500)),
        },
    )
    .expect("codec config is valid");

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

    let payload = vec![0x7eu8; mib * 1024 * 1024];
    let wire = chunked_put(&payload, 128 * 1024);
    drop(payload);

    let client = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone());
        let mut s = TcpStream::connect(v4).expect("connect");
        s.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
        // Count only the exchange: everything before this is setup, and
        // the wire buffer above is one allocation either way.
        let before = BIG_ALLOCS.load(Ordering::Relaxed);
        s.write_all(&wire).expect("write");
        let status = read_status(&mut s).expect("status");
        assert_eq!(status, 200, "upload refused");
        let cost = BIG_ALLOCS.load(Ordering::Relaxed) - before;
        drop(s);
        stop.shutdown();
        cost
    });

    server.serve_forever().expect("serve_forever");
    let cost = client.join().expect("client thread");
    let s = stats.snapshot();
    assert!(
        s.recv_bufs_total > 0,
        "no recv buffer ring registered - this measured the owned-buffer \
         fallback, not the pool: {s:?}"
    );
    Some(cost)
}

/// The cost of an upload must not scale with its size.
///
/// Doubling the payload doubles the windows, so a per-window allocation
/// shows up as a doubled count. Comparing two runs rather than asserting an
/// absolute number keeps the test honest about the fixed setup cost, which
/// is neither zero nor interesting.
#[test]
fn a_streamed_upload_does_not_allocate_per_window() {
    let _turn = MEASURING.lock().unwrap_or_else(|e| e.into_inner());
    let Some(small) = upload_cost(4) else {
        return; // io_uring unavailable
    };
    let Some(large) = upload_cost(16) else {
        return;
    };
    // 4 MiB is 32 windows, 16 MiB is 128 - so a per-window allocation would
    // put 96 between them.
    assert!(
        large <= small + 8,
        "upload cost scales with payload: 4 MiB cost {small} large \
         allocations, 16 MiB cost {large}. A pool that covered request heads \
         but not body windows would look exactly like this."
    );
}

// ---- the download side ----------------------------------------------------

/// Serve one file body per connection and answer how many large allocations
/// `conns` connections cost.
///
/// Connections, not requests, is the axis that matters: chunk buffers used
/// to be minted per connection and held until it closed, so the cost scaled
/// with the connection table rather than with how many bodies were actually
/// moving.
#[cfg(feature = "uring-fs")]
fn download_cost(warmup: usize, measured: usize) -> Option<usize> {
    use std::io::Read as _;
    use truenas_ros::net::server::{
        Endian, PrefixWidth, Protocol, Request, Response, length_prefix_header,
    };

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
    // One open through a standalone fs host, cloned per request: only an
    // fs reactor can mint a `File`, but the fd is host-independent once
    // open and `File` is an `Arc<OwnedFd>`.
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
                let r = handle.open(
                    who,
                    &anchor,
                    c"obj",
                    OpenHow::new().flags(OFlag::O_RDONLY),
                );
                let _ = ftx.send(r);
                stop_fs.shutdown();
            });
            afs.run().expect("fs host run");
        });
        frx.recv().expect("open outcome").expect("open")
    };
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(
            PrefixWidth::U32,
            Endian::Big,
            false,
        ),
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
        // Sized once, outside the measurement: a growing client buffer
        // reallocates past the counting threshold several times per body and
        // would be indistinguishable from the server allocating per read.
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
/// Chunk buffers came off a per-connection pool minted on the first file
/// reply and held until close, so N connections cost N x FILE_TAIL_BUFS
/// buffers of `fs_body_chunk` - `pool_size` x 2 x a megabyte in a real
/// deployment, held whether or not anything was streaming. Drawn from the
/// reactor's ring instead, the cost is flat in the connection count.
#[cfg(feature = "uring-fs")]
#[test]
fn serving_file_bodies_does_not_allocate_per_connection() {
    let _turn = MEASURING.lock().unwrap_or_else(|e| e.into_inner());
    // Warm the pool first, then measure: growing the ring allocates, once,
    // and that is not what this is about.
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

// ---- the write side: PUT windows straight to a file ------------------------

/// Upload `mib` MiB as a streamed PUT whose handler writes every window to a
/// real file with `pwritev2_from` + `defer_stream`, and answer (large
/// allocations, file bytes matched).
///
/// This is the whole ingest path at once: kernel picks the recv buffer, the
/// framer scans it in place, the handler's write borrows it, the claim is
/// surrendered to the op, and the pool gets it back at the write's CQE. Any
/// copy or allocation snuck back into that chain shows up in the count.
#[cfg(feature = "uring-fs")]
fn put_to_file_cost(
    mib: usize,
    wire_of: fn(&[u8]) -> Vec<u8>,
) -> Option<(usize, usize, bool)> {
    put_to_file_cost_ranged(mib, wire_of, false)
}

/// [`put_to_file_cost`], optionally writing every window as **two** leased
/// ranges - the shape a verifier that emits payload extents produces. Both
/// ranges borrow the same claim, so the second must share the first's
/// hold rather than fall to the copy path.
#[cfg(feature = "uring-fs")]
fn put_to_file_cost_ranged(
    mib: usize,
    wire_of: fn(&[u8]) -> Vec<u8>,
    split: bool,
) -> Option<(usize, usize, bool)> {
    use truenas_ros::http::HttpStreamDeferred;
    use truenas_ros::uring_fs::RwFlags;

    let landed = streamed_put(mib, wire_of, |file, pc| {
        truenas_ros::http::protocol_streaming_fs(
            HttpConfig::default(),
            1 << 30,
            |_i: Incoming<'_>| Some(0u64),
            move |req: HttpRequest<'_>, off: &mut u64, fs| match req.stage {
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
                    let (d, permit, body) = req.defer_stream();
                    let d: HttpStreamDeferred = d;
                    let half = if split && body.len() >= 2 {
                        body.len() / 2
                    } else {
                        body.len()
                    };
                    let ranges: Vec<(usize, usize)> = if half == body.len() {
                        vec![(0, body.len())]
                    } else {
                        vec![(0, half), (half, body.len())]
                    };
                    let d = std::rc::Rc::new(std::cell::RefCell::new(Some(d)));
                    let left =
                        std::rc::Rc::new(std::cell::Cell::new(ranges.len()));
                    let failed = std::rc::Rc::new(std::cell::Cell::new(false));
                    for (start, end) in ranges {
                        let (d, left, failed) = (
                            std::rc::Rc::clone(&d),
                            std::rc::Rc::clone(&left),
                            std::rc::Rc::clone(&failed),
                        );
                        fs.pwritev2_from(
                            who,
                            file.clone(),
                            &body[start..end],
                            at + start as u64,
                            RwFlags::empty(),
                            move |done, _fs| {
                                if done.result().is_err() {
                                    failed.set(true);
                                }
                                left.set(left.get() - 1);
                                if left.get() == 0 {
                                    let d = d
                                        .borrow_mut()
                                        .take()
                                        .expect("one taker");
                                    if failed.get() {
                                        d.fail(HttpResponse::new(500));
                                    } else {
                                        d.resume();
                                    }
                                }
                            },
                        );
                    }
                    HttpVerdict::Defer(permit)
                }
                Stage::End => HttpVerdict::Respond(
                    HttpResponse::new(200).header("x-bytes", off.to_string()),
                ),
                Stage::Whole => HttpVerdict::Respond(HttpResponse::new(500)),
            },
        )
        .expect("codec config")
    })?;
    Some((landed.cost, landed.cost_med, landed.matches))
}

/// What one streamed PUT through [`streamed_put`] cost and delivered.
#[cfg(feature = "uring-fs")]
struct Landed {
    /// Allocations at or above [`BIG`] during the upload.
    cost: usize,
    /// Allocations at or above [`MED`] during the upload.
    cost_med: usize,
    /// The destination holds exactly the payload.
    matches: bool,
    /// The bytes that were uploaded, for a digest to be checked against.
    payload: Vec<u8>,
    /// The response head, for whatever the handler put on it.
    head: String,
}

#[cfg(feature = "uring-fs")]
impl Landed {
    /// A response header's value, where the handler set it.
    fn header(&self, name: &str) -> Option<&str> {
        self.head.lines().find_map(|l| {
            l.strip_prefix(name)
                .and_then(|rest| rest.strip_prefix(": "))
                .map(str::trim)
        })
    }
}

/// One streamed PUT of `mib` MiB of varied bytes, framed by `wire_of`,
/// into a server running the protocol `proto_of` builds over a
/// pre-opened destination and the reactor's own personality (set once the
/// server exists, before the first connection). The upload's large
/// allocations are counted, every receive buffer is checked back home,
/// and the destination is read back. `None` where this box has no
/// io_uring.
///
/// The destination is opened through a throwaway [`UringFs`] host, not
/// the server's own reactor: the open path is not what any caller
/// measures, and the file is cloned into every request from here.
#[cfg(feature = "uring-fs")]
fn streamed_put<U, A, H, B>(
    mib: usize,
    wire_of: impl FnOnce(&[u8]) -> Vec<u8>,
    proto_of: impl FnOnce(
        truenas_ros::uring_fs::File,
        std::sync::Arc<std::sync::OnceLock<truenas_ros::uring_fs::Personality>>,
    ) -> truenas_ros::net::server::Protocol<A, H, B>,
) -> Option<Landed>
where
    A: FnMut(Incoming<'_>) -> Option<U>,
    H: FnMut(&[u8], &mut U) -> truenas_ros::net::Framing,
    B: FnMut(
        truenas_ros::net::server::Request<'_, U>,
    ) -> truenas_ros::net::server::Response,
{
    use std::sync::OnceLock;
    use truenas_ros::sync_fs::{OFlag, OpenHow};
    use truenas_ros::uring_fs::{Anchor, FsConfig, Personality, UringFs};

    let tmp = truenas_ros::tempdir().expect("tempdir");
    let dir = tmp.path().to_owned();
    let path = dir.join("obj");
    std::fs::write(&path, b"").expect("create");

    let file = {
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
                let r = handle.open(
                    who,
                    &anchor,
                    c"obj",
                    OpenHow::new().flags(OFlag::O_WRONLY),
                );
                let _ = ftx.send(r);
                stop_fs.shutdown();
            });
            afs.run().expect("fs host run");
        });
        frx.recv().expect("open outcome").expect("open")
    };

    let pers: std::sync::Arc<OnceLock<Personality>> =
        std::sync::Arc::new(OnceLock::new());
    let proto = proto_of(file, std::sync::Arc::clone(&pers));

    let cfg = ServerConfig {
        pool_size: 8,
        fs_ops: 16,
        max_request_bytes: 512 * 1024,
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

    // Varied bytes, so a window digested out of order or over a recycled
    // buffer shows up; a constant fill would hash the same either way.
    let payload: Vec<u8> =
        (0..mib * 1024 * 1024).map(|i| (i % 251) as u8).collect();
    let wire = wire_of(&payload);

    let client = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone());
        let mut s = TcpStream::connect(v4).expect("connect");
        s.set_read_timeout(Some(Duration::from_secs(60))).unwrap();
        let before = BIG_ALLOCS.load(Ordering::Relaxed);
        let before_med = MED_ALLOCS.load(Ordering::Relaxed);
        s.write_all(&wire).expect("write");
        let (status, head) = read_response_head(&mut s).expect("head");
        assert_eq!(status, 200, "upload refused: {head}");
        let cost = BIG_ALLOCS.load(Ordering::Relaxed) - before;
        let cost_med = MED_ALLOCS.load(Ordering::Relaxed) - before_med;
        drop(s);
        stop.shutdown();
        (cost, cost_med, head)
    });

    server.serve_forever().expect("serve_forever");
    let (cost, cost_med, head) = client.join().expect("client thread");
    let s = stats.snapshot();
    assert!(
        s.recv_bufs_total > 0,
        "no recv ring registered - the lease path was never exercised: {s:?}"
    );
    assert_eq!(
        s.recv_bufs_lent, 0,
        "a leased buffer was never returned: {s:?}"
    );
    let written = std::fs::read(&path).expect("read back");
    Some(Landed {
        cost,
        cost_med,
        matches: written == payload,
        payload,
        head,
    })
}

/// The digest the two digesting handlers compute: order-sensitive, so a
/// window hashed over the wrong bytes or a recycled buffer shows up.
#[cfg(feature = "uring-fs")]
fn fold(acc: u64, bytes: &[u8]) -> u64 {
    bytes.iter().fold(acc, |h, &b| {
        h.wrapping_mul(0x0000_0100_0000_01b3) ^ u64::from(b)
    })
}

#[cfg(feature = "uring-fs")]
const FOLD_SEED: u64 = 0xcbf2_9ce4_8422_2325;

/// [`put_to_file_cost`] with every window also *digested* on the pool from
/// the same leased buffer (`offload_from`): the write and the job share
/// the window's claim, the stream resumes when both have landed, and
/// `End` answers the running digest. Returns the allocation costs, whether
/// the file matched, and whether the digest the handler accumulated is
/// the payload's.
#[cfg(feature = "uring-fs")]
fn put_digest_cost(mib: usize) -> Option<(usize, usize, bool, bool)> {
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;
    use truenas_ros::http::HttpStreamDeferred;
    use truenas_ros::uring_fs::RwFlags;

    /// One connection's upload: the payload offset and the digest so
    /// far. Each window parks until its job is back, so the next window
    /// starts from the digest its predecessor's completion stored.
    struct Digesting {
        off: u64,
        acc: u64,
    }

    let landed = streamed_put(
        mib,
        |p| chunked_put(p, 128 * 1024),
        |file, pc| {
            truenas_ros::http::protocol_streaming_fs(
                HttpConfig::default(),
                1 << 30,
                |_i: Incoming<'_>| {
                    Some(Rc::new(RefCell::new(Digesting {
                        off: 0,
                        acc: FOLD_SEED,
                    })))
                },
                move |req: HttpRequest<'_>,
                      st: &mut Rc<RefCell<Digesting>>,
                      fs| {
                    match req.stage {
                        Stage::Open => HttpVerdict::Continue,
                        Stage::Window => {
                            let Some(mut fs) = fs else {
                                return HttpVerdict::Respond(
                                    HttpResponse::new(500),
                                );
                            };
                            let who = *pc.get().expect("personality set");
                            let (at, acc) = {
                                let mut p = st.borrow_mut();
                                let at = p.off;
                                p.off += req.body.len() as u64;
                                (at, p.acc)
                            };
                            let (d, permit, body) = req.defer_stream();
                            let d: HttpStreamDeferred = d;
                            let d = Rc::new(RefCell::new(Some(d)));
                            // Two landings per window: the write's CQE and
                            // the job's delivery. The last one resumes the
                            // stream.
                            let left = Rc::new(Cell::new(2u8));
                            let failed = Rc::new(Cell::new(false));
                            let finish = {
                                let (d, left, failed) = (
                                    Rc::clone(&d),
                                    Rc::clone(&left),
                                    Rc::clone(&failed),
                                );
                                move |ok: bool| {
                                    if !ok {
                                        failed.set(true);
                                    }
                                    left.set(left.get() - 1);
                                    if left.get() == 0 {
                                        let d = d
                                            .borrow_mut()
                                            .take()
                                            .expect("one taker");
                                        if failed.get() {
                                            d.fail(HttpResponse::new(500));
                                        } else {
                                            d.resume();
                                        }
                                    }
                                }
                            };
                            let f1 = finish.clone();
                            fs.pwritev2_from(
                                who,
                                file.clone(),
                                &body,
                                at,
                                RwFlags::empty(),
                                move |done, _fs| f1(done.result().is_ok()),
                            );
                            let st = Rc::clone(st);
                            fs.offload_from(
                                &body,
                                move |view| Ok(fold(acc, view)),
                                move |r, _fs| match r {
                                    Ok(h) => {
                                        // Stored before the resume, so the
                                        // next window and `End` both read it.
                                        st.borrow_mut().acc = h;
                                        finish(true);
                                    }
                                    Err(_) => finish(false),
                                },
                            );
                            HttpVerdict::Defer(permit)
                        }
                        Stage::End => {
                            let p = st.borrow();
                            HttpVerdict::Respond(
                                HttpResponse::new(200)
                                    .header("x-bytes", p.off.to_string())
                                    .header(
                                        "x-digest",
                                        format!("{:016x}", p.acc),
                                    ),
                            )
                        }
                        Stage::Whole => {
                            HttpVerdict::Respond(HttpResponse::new(500))
                        }
                    }
                },
            )
            .expect("codec config")
        },
    )?;
    let want = format!("{:016x}", fold(FOLD_SEED, &landed.payload));
    let digested = landed.header("x-digest") == Some(want.as_str());
    Some((landed.cost, landed.cost_med, landed.matches, digested))
}

/// [`put_digest_cost`] with the digest *pipelined*: a window is never
/// parked on its own job. Each window is written and leased
/// (`lease_window`); the lease is spent on the pool at once when no job is
/// running, else it waits in a backlog and the running job's completion
/// spends it - `offload_leased` from a completion facade. The stream
/// brakes only past two waiting windows, and `End` answers from the
/// completion that drains the last of them. Returns what
/// [`put_digest_cost`] does.
#[cfg(feature = "uring-fs")]
fn put_pipelined_digest_cost(mib: usize) -> Option<(usize, usize, bool, bool)> {
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::rc::Rc;
    use truenas_ros::http::{HttpDeferred, HttpStreamDeferred};
    use truenas_ros::uring_fs::{FsConn, LeasedWindow, RwFlags};

    /// A window waiting for the digest: leased where the delivery could
    /// lease it, copied where it could not (never, on this path - the
    /// flat allocation count is what proves it).
    enum Window {
        Leased(LeasedWindow),
        Owned(Vec<u8>),
    }

    /// One connection's upload.
    struct Pipe {
        off: u64,
        acc: u64,
        /// A digest job is out.
        busy: bool,
        backlog: VecDeque<Window>,
        writes: u32,
        write_failed: bool,
        parked: Option<HttpStreamDeferred>,
        end: Option<HttpDeferred>,
    }

    const BACKLOG: usize = 2;

    impl Pipe {
        fn settled(&self) -> bool {
            !self.busy && self.backlog.is_empty() && self.writes == 0
        }
        fn answer(&mut self) {
            if self.settled()
                && let Some(end) = self.end.take()
            {
                end.reply(if self.write_failed {
                    HttpResponse::new(500)
                } else {
                    HttpResponse::new(200)
                        .header("x-bytes", self.off.to_string())
                        .header("x-digest", format!("{:016x}", self.acc))
                });
            }
        }
        fn unbrake(&mut self) {
            if self.backlog.len() < BACKLOG
                && let Some(p) = self.parked.take()
            {
                p.resume();
            }
        }
    }

    /// Spend one window on the pool; its completion spends the next.
    fn submit(conn: &mut FsConn<'_>, st: Rc<RefCell<Pipe>>, w: Window) {
        let acc = st.borrow().acc;
        let done = {
            let st = Rc::clone(&st);
            move |r: truenas_ros::Result<u64>, conn: &mut FsConn<'_>| {
                let next = {
                    let mut p = st.borrow_mut();
                    match r {
                        Ok(h) => p.acc = h,
                        Err(_) => p.write_failed = true,
                    }
                    let next = p.backlog.pop_front();
                    if next.is_none() {
                        p.busy = false;
                    }
                    p.unbrake();
                    next
                };
                match next {
                    Some(w) => submit(conn, st, w),
                    None => st.borrow_mut().answer(),
                }
            }
        };
        match w {
            Window::Leased(w) => {
                conn.offload_leased(w, move |view| Ok(fold(acc, view)), done)
            }
            Window::Owned(bytes) => {
                conn.offload_result(move || Ok(fold(acc, &bytes)), done)
            }
        }
    }

    let landed = streamed_put(
        mib,
        |p| chunked_put(p, 128 * 1024),
        |file, pc| {
            truenas_ros::http::protocol_streaming_fs(
                HttpConfig::default(),
                1 << 30,
                |_i: Incoming<'_>| {
                    Some(Rc::new(RefCell::new(Pipe {
                        off: 0,
                        acc: FOLD_SEED,
                        busy: false,
                        backlog: VecDeque::new(),
                        writes: 0,
                        write_failed: false,
                        parked: None,
                        end: None,
                    })))
                },
                move |req: HttpRequest<'_>, st: &mut Rc<RefCell<Pipe>>, fs| {
                    match req.stage {
                        Stage::Open => HttpVerdict::Continue,
                        Stage::Window => {
                            let Some(mut fs) = fs else {
                                return HttpVerdict::Respond(
                                    HttpResponse::new(500),
                                );
                            };
                            let who = *pc.get().expect("personality set");
                            let at = {
                                let mut p = st.borrow_mut();
                                let at = p.off;
                                p.off += req.body.len() as u64;
                                p.writes += 1;
                                at
                            };
                            let wst = Rc::clone(st);
                            fs.pwritev2_from(
                                who,
                                file.clone(),
                                &req.body,
                                at,
                                RwFlags::empty(),
                                move |done, _fs| {
                                    let mut p = wst.borrow_mut();
                                    if done.result().is_err() {
                                        p.write_failed = true;
                                    }
                                    p.writes -= 1;
                                    p.answer();
                                },
                            );
                            let window = match fs.lease_window(&req.body) {
                                Some(w) => Window::Leased(w),
                                None => Window::Owned(req.body.to_vec()),
                            };
                            let busy = std::mem::replace(
                                &mut st.borrow_mut().busy,
                                true,
                            );
                            if busy {
                                st.borrow_mut().backlog.push_back(window);
                            } else {
                                submit(&mut fs, Rc::clone(st), window);
                            }
                            if st.borrow().backlog.len() >= BACKLOG {
                                let (d, permit, _body) = req.defer_stream();
                                st.borrow_mut().parked = Some(d);
                                HttpVerdict::Defer(permit)
                            } else {
                                HttpVerdict::Continue
                            }
                        }
                        Stage::End => {
                            let (d, permit) = req.defer();
                            let mut p = st.borrow_mut();
                            p.end = Some(d);
                            p.answer();
                            HttpVerdict::Defer(permit)
                        }
                        Stage::Whole => {
                            HttpVerdict::Respond(HttpResponse::new(500))
                        }
                    }
                },
            )
            .expect("codec config")
        },
    )?;
    let want = format!("{:016x}", fold(FOLD_SEED, &landed.payload));
    let digested = landed.header("x-digest") == Some(want.as_str());
    Some((landed.cost, landed.cost_med, landed.matches, digested))
}

/// A window held past its delivery and spent from an earlier job's
/// completion costs no copy and returns its lease.
///
/// The pipelined shape: the stream flows while the digest runs behind
/// it, windows waiting their turn as leases rather than copies, every
/// one spent by `offload_leased` from a completion facade that holds no
/// lease of its own. Flat allocation count, every buffer back, and the
/// digest is the payload's - so the windows were read in order and none
/// was recycled under a waiting job.
#[cfg(feature = "uring-fs")]
#[test]
fn a_held_window_is_digested_from_the_previous_jobs_completion() {
    let _turn = MEASURING.lock().unwrap_or_else(|e| e.into_inner());
    let Some((small, _, ok_small, digest_small)) = put_pipelined_digest_cost(4)
    else {
        return; // io_uring unavailable
    };
    let Some((large, _, ok_large, digest_large)) =
        put_pipelined_digest_cost(16)
    else {
        return;
    };
    assert!(ok_small && ok_large, "file bytes differ from the upload");
    assert!(
        digest_small && digest_large,
        "the pipelined jobs digested other bytes than the payload's"
    );
    assert!(
        large <= small + 8,
        "pipelined digesting cost scales with payload: 4 MiB cost {small} \
         large allocations, 16 MiB cost {large}. A held window that fell \
         to a copy looks exactly like this."
    );
}

/// Read one response head; the status and the raw header block.
#[cfg(feature = "uring-fs")]
fn read_response_head(s: &mut TcpStream) -> io::Result<(u16, String)> {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    while !buf.ends_with(b"\r\n\r\n") {
        if s.read(&mut byte)? == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "head"));
        }
        buf.push(byte[0]);
    }
    let text = String::from_utf8_lossy(&buf).into_owned();
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    Ok((status, text))
}

/// A window digested on the pool from the receive buffer it arrived in
/// costs no copy and returns its lease.
///
/// `offload_from` shares the write's claim: the write and the job read
/// the same buffer, the buffer returns when the last of them is over, and
/// neither falls to the copy path - so the allocation count is flat in
/// the payload, every lease comes back, and the digest is the payload's.
#[cfg(feature = "uring-fs")]
#[test]
fn a_leased_window_is_digested_in_place() {
    let _turn = MEASURING.lock().unwrap_or_else(|e| e.into_inner());
    let Some((small, _, ok_small, digest_small)) = put_digest_cost(4) else {
        return; // io_uring unavailable
    };
    let Some((large, _, ok_large, digest_large)) = put_digest_cost(16) else {
        return;
    };
    assert!(ok_small && ok_large, "file bytes differ from the upload");
    assert!(
        digest_small && digest_large,
        "the pool job digested other bytes than the payload's"
    );
    // 4 MiB is 32 windows, 16 MiB is 128: a per-window copy shows up as
    // ~96 between them.
    assert!(
        large <= small + 8,
        "digesting cost scales with payload: 4 MiB cost {small} large \
         allocations, 16 MiB cost {large}. A copy fallback looks exactly \
         like this."
    );
}

/// Writing a streamed PUT to a file must neither corrupt it nor allocate
/// per window.
///
/// The windows are written from the receive buffer itself - the claim is
/// surrendered to the write op and comes back to the pool at its CQE - and
/// the stream park retains no copy. Byte-identical content proves the
/// buffer was never recycled under the DMA; a flat allocation count proves
/// neither the write nor the park fell back to copying.
#[cfg(feature = "uring-fs")]
#[test]
fn a_streamed_put_writes_windows_without_copying_them() {
    let _turn = MEASURING.lock().unwrap_or_else(|e| e.into_inner());
    let wire = |p: &[u8]| chunked_put(p, 128 * 1024);
    let Some((small, _, ok_small)) = put_to_file_cost(4, wire) else {
        return; // io_uring unavailable
    };
    let Some((large, _, ok_large)) = put_to_file_cost(16, wire) else {
        return;
    };
    assert!(ok_small && ok_large, "file bytes differ from the upload");
    // 4 MiB is 32 windows, 16 MiB is 128: a per-window copy or park shows
    // up as ~96 between them.
    assert!(
        large <= small + 8,
        "PUT-to-file cost scales with payload: 4 MiB cost {small} large \
         allocations, 16 MiB cost {large}. A copy fallback or a park that \
         retains the window looks exactly like this."
    );
}

/// Two ranges of one window both write from the claim.
///
/// A verifier that emits payload extents hands the handler several ranges
/// of the same window; each borrows the same claim, so all of them must
/// share its hold - the buffer goes back when the last completes. A
/// single-shot lease sends every range after the first to the copy path,
/// which at two ranges per window is one ~64 KiB allocation-and-copy per
/// window, scaling with the payload.
#[cfg(feature = "uring-fs")]
#[test]
fn a_multi_range_window_writes_every_range_from_the_claim() {
    let _turn = MEASURING.lock().unwrap_or_else(|e| e.into_inner());
    fn wire(p: &[u8]) -> Vec<u8> {
        chunked_put(p, 1024 * 1024)
    }
    let Some((small, _, ok_small)) = put_to_file_cost_ranged(4, wire, true)
    else {
        return; // io_uring unavailable
    };
    let Some((large, _, ok_large)) = put_to_file_cost_ranged(16, wire, true)
    else {
        return;
    };
    assert!(ok_small && ok_large, "file bytes differ from the upload");
    assert!(
        large <= small + 8,
        "two-range PUT-to-file cost scales with payload: 4 MiB cost \
         {small} large allocations, 16 MiB cost {large}. A range after the \
         first is falling to the copy path instead of sharing the claim."
    );
}

/// The same guarantee when a peer's HTTP chunks are larger than a window.
///
/// A chunk of exactly one window is the single size at which every window
/// carries its chunk header, so the connection always holds a recv claim
/// and the cost of the no-claim arm is invisible. Fixtures framed at that
/// size therefore prove nothing about it - which is how a copy of seven
/// windows in eight went unnoticed.
///
/// 1 MiB here is not botocore: botocore's HTTP chunks are 128 KiB (see
/// `STREAM_WINDOW`), and its 1 MiB `_DEFAULT_CHUNK_SIZE` frames an inner
/// aws-chunked payload this layer never frames. 1 MiB is chosen as a peer
/// that chunks eight windows at a time, so seven in eight are mid-chunk
/// with the claim already leased to the previous window's write. Those must
/// draw a fresh buffer from the ring, not be placed into an allocation
/// `pwritev2_from` then copies.
#[cfg(feature = "uring-fs")]
#[test]
fn a_streamed_put_at_oversized_http_chunks_still_does_not_copy() {
    let _turn = MEASURING.lock().unwrap_or_else(|e| e.into_inner());
    fn wire(p: &[u8]) -> Vec<u8> {
        chunked_put(p, 1024 * 1024)
    }
    let Some((small, _, ok_small)) = put_to_file_cost(4, wire) else {
        return; // io_uring unavailable
    };
    let Some((large, _, ok_large)) = put_to_file_cost(16, wire) else {
        return;
    };
    assert!(ok_small && ok_large, "file bytes differ from the upload");
    // Placed-and-copied mid-chunk windows cost exactly 14 large
    // allocations per MiB (measured: 56 and 224 here before the no-claim
    // suppression); flat means every window drew from the ring.
    assert!(
        large <= small + 8,
        "PUT-to-file cost scales with payload at 1 MiB chunks: 4 MiB cost \
         {small} large allocations, 16 MiB cost {large}. Mid-chunk windows \
         are being placed and copied instead of drawing from the ring."
    );
}

/// A `Content-Length` body above one window streams exactly as a chunked
/// one: windows from the receive ring, leased writes, no copy and no
/// per-window allocation. The harness's `Whole` arm answers 500, so a
/// body this size that fails to stream fails the test outright — the
/// regression this exists to catch is precisely a silent fall back to
/// buffering.
///
/// Counted from [`MED`], the tighter of the allocator's two thresholds,
/// so a fallback whose unit is smaller than a full window still registers
/// rather than sliding under a 64 KiB bar.
#[cfg(feature = "uring-fs")]
#[test]
fn a_known_length_put_streams_without_copying() {
    let _turn = MEASURING.lock().unwrap_or_else(|e| e.into_inner());
    let Some((_, small, ok_small)) = put_to_file_cost(4, cl_put) else {
        return; // io_uring unavailable
    };
    let Some((_, large, ok_large)) = put_to_file_cost(16, cl_put) else {
        return;
    };
    assert!(ok_small && ok_large, "file bytes differ from the upload");
    assert!(
        large <= small + 8,
        "CL PUT-to-file cost scales with payload: 4 MiB cost {small}, \
         16 MiB cost {large} allocations at or above MED. A copy fallback \
         or a park that retains the window looks exactly like this."
    );
}

/// Two known-length streamed PUTs pipelined on one connection.
///
/// The End handoff consumes zero bytes, so the second request's head —
/// already buffered behind the first body — must frame cleanly rather
/// than be eaten as a trailer section. Answered wrong, the connection
/// desyncs and the second status never arrives.
#[cfg(feature = "uring-fs")]
#[test]
fn pipelined_known_length_streams_do_not_desync() {
    use std::sync::atomic::AtomicUsize;

    // Allocates ~20 buffers over `BIG` through a live server. The counter
    // is process-global and this binary's tests run as parallel threads,
    // so without the turn those land inside another test's measurement
    // window - reddening a correct suite, or raising a differential's
    // baseline arm enough to admit the regression it exists to catch.
    let _turn = MEASURING.lock().unwrap_or_else(|e| e.into_inner());

    let opens = std::sync::Arc::new(AtomicUsize::new(0));
    let ends = std::sync::Arc::new(AtomicUsize::new(0));
    let (o, e) = (std::sync::Arc::clone(&opens), std::sync::Arc::clone(&ends));
    let proto = truenas_ros::http::protocol_streaming_fs(
        HttpConfig::default(),
        1 << 30,
        |_i: Incoming<'_>| Some(0u64),
        move |req: HttpRequest<'_>, got: &mut u64, _fs| match req.stage {
            Stage::Open => {
                o.fetch_add(1, Ordering::Relaxed);
                *got = 0;
                HttpVerdict::Continue
            }
            Stage::Window => {
                *got += req.body.len() as u64;
                HttpVerdict::Continue
            }
            Stage::End => {
                e.fetch_add(1, Ordering::Relaxed);
                HttpVerdict::Respond(
                    HttpResponse::new(200).header("x-bytes", got.to_string()),
                )
            }
            Stage::Whole => HttpVerdict::Respond(HttpResponse::new(500)),
        },
    )
    .expect("codec config");

    let cfg = ServerConfig {
        pool_size: 4,
        max_request_bytes: 512 * 1024,
        ..ServerConfig::default()
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let mut server = match Server::with_config([addr], cfg, proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind: {e}"),
    };
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();

    let client = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone());
        let mut s = TcpStream::connect(v4).expect("connect");
        s.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
        // Both requests in one write: the second head sits in the buffer
        // behind the first body when the End handoff runs.
        let first = cl_put(&vec![0x51u8; 300 * 1024]);
        let second = cl_put(&vec![0x52u8; 200 * 1024]);
        let mut wire = first;
        wire.extend_from_slice(&second);
        s.write_all(&wire).expect("write");
        let one = read_status(&mut s).expect("first status");
        let two = read_status(&mut s).expect("second status");
        stop.shutdown();
        (one, two)
    });

    server.serve_forever().expect("serve_forever");
    let (one, two) = client.join().expect("client thread");
    assert_eq!((one, two), (200, 200));
    assert_eq!(opens.load(Ordering::Relaxed), 2, "both requests opened");
    assert_eq!(ends.load(Ordering::Relaxed), 2, "both requests ended");
}

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

/// Upload `mib` MiB on `conns` connections at write depth `k`, every window
/// written to its connection's file with `pwritev2_from` and `Continue` --
/// parking only at the cap. Answers (large allocations, all files matched,
/// peak writes in flight observed).
#[cfg(feature = "uring-fs")]
#[allow(clippy::too_many_lines)]
fn pipelined_put_cost(
    mib: usize,
    conns: usize,
    k: usize,
) -> Option<(usize, bool, usize)> {
    use std::sync::OnceLock;
    use truenas_ros::http::HttpDeferred;
    use truenas_ros::uring_fs::{File, Personality, RwFlags};

    // `truenas_ros::tempdir()` (mkdtemp) rather than a parameter-named
    // directory, and the drop guard rather than a trailing
    // `remove_dir_all`, for two measured reasons: parameter-named
    // fixtures were shared by two `recv_alloc` binaries running at
    // once - `MEASURING` serializes only within a process - and the
    // pre-clean deleted the other's objects mid-upload, reading as a
    // lost write at the verify; and a hand-rolled teardown sits behind
    // every assert, so one failing run left its RAM-backed fixtures on
    // tmpfs. The guard cleans up on the unwind too.
    let tmp = truenas_ros::tempdir().expect("tempdir");
    let dir = tmp.path().to_owned();
    for i in 0..conns {
        std::fs::write(dir.join(format!("obj{i}")), b"").expect("create");
    }

    // Pre-open one destination per connection through a standalone host.
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
                    let name =
                        std::ffi::CString::new(format!("obj{i}")).unwrap();
                    let r = handle.open(
                        who,
                        &anchor,
                        name.as_c_str(),
                        OpenHow::new().flags(OFlag::O_WRONLY),
                    );
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

    let pers: std::sync::Arc<OnceLock<Personality>> =
        std::sync::Arc::new(OnceLock::new());
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
                    // The completion: release the depth slot, wake whoever
                    // the cap parked, and settle End once everything landed.
                    let done_ctl = std::sync::Arc::clone(ctl);
                    let cont =
                        move |done: truenas_ros::uring_fs::FsDone,
                              _fs: &mut truenas_ros::uring_fs::FsConn<'_>| {
                            if done.result().is_err() {
                                done_ctl
                                    .failed
                                    .store(true, Ordering::Relaxed);
                            }
                            let left = done_ctl
                                .inflight
                                .fetch_sub(1, Ordering::Relaxed)
                                - 1;
                            if let Some(d) =
                                done_ctl.parked.lock().unwrap().take()
                            {
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
                        fs.pwritev2_from(
                            who,
                            file.clone(),
                            &req.body,
                            at,
                            RwFlags::empty(),
                            cont,
                        );
                        HttpVerdict::Continue
                    } else {
                        // At depth: same write, but brake the stream until
                        // a completion frees a slot.
                        let (d, permit, body) = req.defer_stream();
                        *ctl.parked.lock().unwrap() = Some(d);
                        fs.pwritev2_from(
                            who,
                            file.clone(),
                            &body,
                            at,
                            RwFlags::empty(),
                            cont,
                        );
                        HttpVerdict::Defer(permit)
                    }
                }
                Stage::End => {
                    if ctl.inflight.load(Ordering::Relaxed) == 0 {
                        let code = if ctl.failed.load(Ordering::Relaxed) {
                            500
                        } else {
                            200
                        };
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
        // `None`, so an undersized ring shows as allocations; parking
        // would hide it.
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
    let ok = (0..conns).all(|i| {
        std::fs::read(dir.join(format!("obj{i}"))).expect("read back") == want
    });
    let peak = peak_seen.load(Ordering::Relaxed);
    Some((cost, ok, peak))
}

/// A depth-2 pipelined PUT overlaps a window's write with the next window's
/// arrival, copies nothing, allocates nothing per window, and the files
/// come back byte-identical.
///
/// The peak-in-flight watermark is what proves the overlap is real: at
/// depth 1 it cannot exceed one, at depth 2 the loopback client outruns the
/// io-wq write punt and the watermark reaches two. The allocation scaling
/// run is what proves the ring covered the depth - past the registration
/// wall connections degrade to owned buffers and every window costs a
/// copy, which is exactly what the depth-sized registration exists to
/// prevent.
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

/// Upload `mib` MiB on `conns` connections, every window held with
/// `lease_window` and written `g` at a time with one `pwritev2_leased`,
/// braking the stream once held and in-flight windows reach `cap`.
/// Answers (large allocations, all files matched, gathered writes,
/// windows that could not be leased).
#[cfg(feature = "uring-fs")]
#[allow(clippy::too_many_lines)]
fn gathered_put_cost(
    mib: usize,
    conns: usize,
    g: usize,
    cap: usize,
) -> Option<(usize, bool, usize, usize)> {
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
                    let name =
                        std::ffi::CString::new(format!("obj{i}")).unwrap();
                    let r = handle.open(
                        who,
                        &anchor,
                        name.as_c_str(),
                        OpenHow::new().flags(OFlag::O_WRONLY),
                    );
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

    let pers: std::sync::Arc<OnceLock<Personality>> =
        std::sync::Arc::new(OnceLock::new());
    let pc = std::sync::Arc::clone(&pers);
    let gathers = std::sync::Arc::new(AtomicUsize::new(0));
    let gathers_out = std::sync::Arc::clone(&gathers);
    let copied = std::sync::Arc::new(AtomicUsize::new(0));
    let copied_out = std::sync::Arc::clone(&copied);
    let assigned = std::sync::Arc::new(AtomicUsize::new(0));

    // (next window's offset, first held window's offset, held, ctl, file)
    type St = (u64, u64, Vec<LeasedWindow>, std::sync::Arc<GatherCtl>, File);
    // One completion per gathered write of `n` windows: give their claims
    // back, wake the brake, and settle End once the last write landed.
    fn landed(
        ctl: std::sync::Arc<GatherCtl>,
        n: usize,
    ) -> impl FnOnce(
        truenas_ros::uring_fs::FsDone,
        &mut truenas_ros::uring_fs::FsConn<'_>,
    ) + 'static {
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
                let code = if ctl.failed.load(Ordering::Relaxed) {
                    500
                } else {
                    200
                };
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
                    let flying_next = ctl.flying.load(Ordering::Relaxed)
                        + if full { g } else { 0 };
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
                        // Not leasable: write the held run and this window
                        // on copies, so the file still comes out whole.
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
                            return HttpVerdict::Respond(HttpResponse::new(
                                500,
                            ));
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
                        let code = if ctl.failed.load(Ordering::Relaxed) {
                            500
                        } else {
                            200
                        };
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
    let ok = (0..conns).all(|i| {
        std::fs::read(dir.join(format!("obj{i}"))).expect("read back") == want
    });
    Some((
        cost,
        ok,
        gathers_out.load(Ordering::Relaxed),
        copied_out.load(Ordering::Relaxed),
    ))
}

/// Windows held across deliveries and written `g` at a time copy nothing,
/// allocate nothing per window, and return every buffer. That each gather
/// is one `WRITEV` is the unit test's
/// (`a_gathered_write_returns_each_buffer_once`).
#[cfg(feature = "uring-fs")]
#[test]
fn a_gathered_put_writes_held_windows_without_copying_them() {
    let _turn = MEASURING.lock().unwrap_or_else(|e| e.into_inner());
    let (conns, g, cap) = (2, 2, 4);
    let Some((small, ok_small, _, copied_small)) =
        gathered_put_cost(4, conns, g, cap)
    else {
        return; // io_uring unavailable
    };
    let Some((large, ok_large, gathers, copied_large)) =
        gathered_put_cost(16, conns, g, cap)
    else {
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

/// The exhaustion runs' lease depth, stated so their wall does not move
/// with the default.
#[cfg(feature = "uring-fs")]
const EXHAUSTION_LEASE_DEPTH: u32 = 4;

/// Handler op slots for the exhaustion runs that must not fill the table.
#[cfg(feature = "uring-fs")]
const ROOMY_FS_OPS: u32 = 64;

/// What an exhaustion run waits to see before it drains the FIFO.
#[cfg(feature = "uring-fs")]
#[derive(Clone, Copy, Debug, PartialEq)]
enum Gate {
    /// The recv ring at its bound: reads parked on the retry backoff, or,
    /// with the knob off, every buffer the ring can hold lent.
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
    /// Every upload answered - 200, unless the run refuses writes - and
    /// every written byte drained.
    ok: bool,
}

/// Upload on `conns` connections into ONE FIFO, floating every window's
/// write with `Continue` and never braking - so leases pile until the pipe
/// blocks the writes and the recv ring hits its registered bound. What
/// happens next is `recv_shortage_retry`'s to decide, and this measures it:
/// returns (shortage parks, large allocations, bytes drained, all 200s).
///
/// The test thread holds the FIFO's read end and does NOT drain until the
/// run reaches its gate (parks observed, or every client byte written), so
/// exhaustion is a phase the run provably enters, not a race it may dodge.
#[cfg(feature = "uring-fs")]
#[allow(clippy::too_many_lines)]
fn exhaustion_run(
    retry: Option<Duration>,
    per_conn: usize,
    fs_ops: u32,
    gate: Gate,
) -> Option<Exhaustion> {
    use std::os::fd::{FromRawFd, OwnedFd};
    use std::sync::OnceLock;
    use std::sync::atomic::AtomicBool;
    use truenas_ros::http::HttpDeferred;
    use truenas_ros::uring_fs::{File, Personality, RwFlags};

    let tmp = truenas_ros::tempdir().expect("tempdir");
    let dir = tmp.path().to_owned();
    let fifo = dir.join("sink");
    let cpath =
        std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
    // SAFETY: a plain mkfifo(3) on a path this test owns.
    assert_eq!(unsafe { libc::mkfifo(cpath.as_ptr(), 0o600) }, 0, "mkfifo");
    // Hold the read end (nonblocking, so this open never waits and the
    // drain loop can poll a stop flag) BEFORE the server opens the write
    // end - a FIFO O_WRONLY open blocks until a reader exists.
    // SAFETY: open(3) of the fifo just created; the fd is owned below.
    let rfd = unsafe {
        libc::open(cpath.as_ptr(), libc::O_RDONLY | libc::O_NONBLOCK)
    };
    assert!(rfd >= 0, "open fifo read end");
    // SAFETY: `rfd` was just returned by open and is owned by nothing else.
    let read_end = unsafe { OwnedFd::from_raw_fd(rfd) };
    // One page of capacity: the first probe write fills it and every write
    // after that BLOCKS in io-wq, holding its window's lease, until the
    // drain makes room - which is the pinning this whole fixture exists
    // for. SAFETY: fcntl(2) on the fd owned just above.
    assert!(
        unsafe { libc::fcntl(rfd, libc::F_SETPIPE_SZ, 4096) } >= 4096,
        "shrink fifo"
    );

    let conns = 2usize;
    // Pre-open the FIFO's write end through a standalone host, exactly as
    // a handler's destination file would be.
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
                let r = handle.open(
                    who,
                    &anchor,
                    name.as_c_str(),
                    OpenHow::new().flags(OFlag::O_WRONLY),
                );
                let _ = ftx.send(r);
                stop_fs.shutdown();
            });
            afs.run().expect("fs host run");
        });
        frx.recv().expect("open outcome").expect("open fifo")
    };

    let pers: std::sync::Arc<OnceLock<Personality>> =
        std::sync::Arc::new(OnceLock::new());
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
                    let cont =
                        move |done: truenas_ros::uring_fs::FsDone,
                              _fs: &mut truenas_ros::uring_fs::FsConn<
                                  '_,
                              >| {
                            if done.was_refused() {
                                done_refused.fetch_add(1, Ordering::Relaxed);
                            }
                            match done.result() {
                                Err(_) => done_ctl
                                    .failed
                                    .store(true, Ordering::Relaxed),
                                Ok(n) => {
                                    done_written.fetch_add(
                                        n as u64,
                                        Ordering::Relaxed,
                                    );
                                }
                            }
                            let left = done_ctl
                                .inflight
                                .fetch_sub(1, Ordering::Relaxed)
                                - 1;
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
                    // Float EVERY window - no depth cap - and write only
                    // its first page: a pipe write of at most PIPE_BUF is
                    // atomic (all-or-block, pipe(7)), so it can never
                    // complete short and trip the leased-write EIO rule,
                    // while an in-bounds subrange still holds the WHOLE
                    // window's lease until the pipe makes room. The FIFO
                    // blocks the writes, the leases pile up: exactly the
                    // pipelined-ingest shape that can reach the ring's
                    // registered bound. A stream write has no position;
                    // `u64::MAX` is the no-offset sentinel the kernel
                    // maps to f_pos (`io_kiocb_update_pos`, io_uring/rw.c).
                    let probe = 4096.min(req.body.len());
                    fs.pwritev2_from(
                        who,
                        file.clone(),
                        &req.body[..probe],
                        u64::MAX,
                        RwFlags::empty(),
                        cont,
                    );
                    HttpVerdict::Continue
                }
                Stage::End => {
                    if ctl.inflight.load(Ordering::Relaxed) == 0 {
                        let code = if ctl.failed.load(Ordering::Relaxed) {
                            500
                        } else {
                            200
                        };
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

    // The drain: parked until the run PROVABLY exhausts the ring - parks
    // observed when the knob is on, the lent gauge pinned at the ring's
    // registered bound when it is off, a write refused for the full table
    // in a refusal run - then empties the FIFO so the
    // writes, and with them the leases, come home. Without the gate a fast
    // drain lets the leases cycle and the run never enters the phase under
    // test, so its assertions would hold vacuously. The bound is the pool's
    // demand: the lease depth plus the arriving message, per connection.
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
            let n =
                unsafe { libc::read(rfd, buf.as_mut_ptr().cast(), buf.len()) };
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
        // A refused window fails its upload, answered from its last
        // completion.
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
    // Every page the handler's writes reported must come out of the FIFO
    // before the drain stops (the responses settled, so the writes did).
    let total = written.load(Ordering::Relaxed);
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while drained.load(Ordering::Relaxed) < total
        && std::time::Instant::now() < deadline
    {
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

/// Genuine pool exhaustion with `recv_shortage_retry` set parks the reads
/// instead of falling back to owned buffers: the uploads stall against TCP
/// until the FIFO drains, then complete intact - and the cost stays FLAT
/// when the upload doubles, because a parked read allocates nothing while
/// it waits and resumes against pool buffers when they come home. (An
/// absolute zero is not the law here: the run's baseline - the pool
/// growing to its registered bound, the fixture's own buffers - is a
/// constant, and the feature's claim is the absence of per-window cost on
/// top of it.) The parks counter is the proof each run actually entered
/// exhaustion rather than dodging it.
#[cfg(feature = "uring-fs")]
#[test]
fn exhaustion_parks_reads_instead_of_allocating() {
    let _turn = MEASURING.lock().unwrap_or_else(|e| e.into_inner());
    let retry = Some(Duration::from_millis(2));
    // 12 and 24 windows a connection, both past the wall of 10 two
    // connections hold between them.
    let Some(one) =
        exhaustion_run(retry, 1536 * 1024, ROOMY_FS_OPS, Gate::RingBound)
    else {
        return; // io_uring unavailable here
    };
    let two = exhaustion_run(retry, 3072 * 1024, ROOMY_FS_OPS, Gate::RingBound)
        .expect("second run");
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

/// The configurable control: `None` keeps the old answer - fall back to
/// owned buffers and keep every connection moving - so the same uploads
/// complete without a single park.
#[cfg(feature = "uring-fs")]
#[test]
fn exhaustion_without_the_knob_completes_without_parking() {
    let _turn = MEASURING.lock().unwrap_or_else(|e| e.into_inner());
    let Some(run) =
        exhaustion_run(None, 1536 * 1024, ROOMY_FS_OPS, Gate::RingBound)
    else {
        return; // io_uring unavailable here
    };
    assert!(run.ok, "uploads failed or bytes lost (drained {})", run.got);
    assert_eq!(run.parks, 0, "None must never park");
}

/// With room in the op table for one handler op, a pipelined upload's
/// leased writes are refused once the table fills: every upload is still
/// answered, every byte a write reported lands, and every buffer comes
/// home once.
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

// ---- the buffered side: placed bodies cycle through the recycler ----------

/// N large buffered bodies on one connection, the handler recycling each
/// delivered `Vec`; the count of large allocations is the return value.
fn buffered_cost(messages: usize) -> Option<usize> {
    use std::cell::RefCell;
    use std::rc::Rc;
    use truenas_ros::http::protocol_deferrable;
    use truenas_ros::net::server::BodyRecycler;

    let http = HttpConfig {
        max_body: 4 * 1024 * 1024,
        ..HttpConfig::default()
    };
    let cfg = ServerConfig {
        pool_size: 8,
        // The reactor must admit what the codec admits, or an over-cap
        // body dies on a raw close with no HTTP response.
        max_request_bytes: http.min_request_bytes(),
        ..ServerConfig::default()
    };
    // Filled after the server exists; the handler runs on this same
    // thread, so the cell is never read before serve_forever fills it.
    let seam: Rc<RefCell<Option<BodyRecycler>>> = Rc::new(RefCell::new(None));
    let handler_seam = Rc::clone(&seam);
    let proto = protocol_deferrable(
        http,
        |_i: Incoming<'_>| Some(0usize),
        move |mut req: HttpRequest<'_>, _: &mut usize| {
            // What a consumer does: own the body for its parse, then hand
            // the storage home.
            let body = req.body.take();
            let n = body.len();
            if let Some(r) = handler_seam.borrow().as_ref() {
                r.recycle(body);
            }
            HttpVerdict::Respond(
                HttpResponse::new(200).header("x-bytes", n.to_string()),
            )
        },
    )
    .expect("codec config is valid");

    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let mut server = match Server::with_config([addr], cfg, proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return None,
        Err(e) => panic!("bind: {e}"),
    };
    *seam.borrow_mut() = server.body_recycler();
    assert!(
        seam.borrow().is_some(),
        "a server always carries a body pool"
    );
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();

    // Over one pool buffer, so every body takes the placement path the
    // pool serves; under max_body, so none is refused.
    let payload = vec![0x5au8; 1024 * 1024];
    let mut one = format!(
        "PUT /o HTTP/1.1\r\nHost: t\r\nContent-Length: {}\r\n\r\n",
        payload.len()
    )
    .into_bytes();
    one.extend_from_slice(&payload);
    drop(payload);

    let client = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone());
        let mut s = TcpStream::connect(v4).expect("connect");
        s.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
        let before = BIG_ALLOCS.load(Ordering::Relaxed);
        for _ in 0..messages {
            s.write_all(&one).expect("write");
            let status = read_status(&mut s).expect("status");
            assert_eq!(status, 200, "buffered put refused");
        }
        let cost = BIG_ALLOCS.load(Ordering::Relaxed) - before;
        drop(s);
        stop.shutdown();
        cost
    });

    server.serve_forever().expect("serve_forever");
    Some(client.join().expect("client thread"))
}

/// The first recycle already licenses reuse: the licence is potted
/// before the handler runs, so message 2 serves from message 1's
/// recycled storage. Potted after the handler instead, message 1's
/// recycle found an empty pot and freed, and message 2 allocated
/// afresh - the pool bootstrapped one message late in the fast case,
/// and never at all for bodies spaced past a maintenance window,
/// where the zeroed pot ate the licence between messages every time.
#[test]
fn the_first_recycle_licenses_the_second_message() {
    let _turn = MEASURING.lock().unwrap_or_else(|e| e.into_inner());
    let Some(one) = buffered_cost(1) else {
        return; // io_uring unavailable
    };
    let Some(two) = buffered_cost(2) else {
        return;
    };
    assert_eq!(
        two, one,
        "the second message must reuse the first one's storage and cost \
         nothing extra: 1 message cost {one} large allocations, 2 cost \
         {two}. Above, the recycle's licence is reaching the pot one step \
         behind the give it exists to cover; below, run 1's own setup has \
         started costing more than run 2's and the comparison no longer \
         measures the pool."
    );
}

/// A recycled buffered body must not cost an allocation per message.
///
/// The first body is a miss and allocates; every later one on the
/// connection reuses that storage through the ring's body pool. Comparing
/// two run lengths rather than asserting an absolute keeps the fixed setup
/// cost out of the verdict, as the streaming twin above does. Before the
/// pool, each message minted its `Vec` afresh and the difference read as
/// the message count.
#[test]
fn a_recycled_buffered_body_does_not_allocate_per_message() {
    let _turn = MEASURING.lock().unwrap_or_else(|e| e.into_inner());
    let Some(small) = buffered_cost(4) else {
        return; // io_uring unavailable
    };
    let Some(large) = buffered_cost(16) else {
        return;
    };
    // Twelve more messages: a per-message allocation puts ~12 between the
    // runs; reuse leaves the two within slack of each other.
    assert!(
        large <= small + 4,
        "buffered-body cost scales with the message count: 4 messages cost \
         {small} large allocations, 16 cost {large}. A pool that is never \
         consulted on the placement path would look exactly like this."
    );
}
