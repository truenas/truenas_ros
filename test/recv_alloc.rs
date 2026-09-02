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
    use std::sync::OnceLock;
    use truenas_ros::http::HttpStreamDeferred;
    use truenas_ros::uring_fs::{Personality, RwFlags};

    let tmp = truenas_ros::tempdir().expect("tempdir");
    let dir = tmp.path().to_owned();
    let path = dir.join("obj");
    std::fs::write(&path, b"").expect("create");

    // One pre-opened destination, cloned per request (the open path is not
    // what this measures).
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
    let pc = std::sync::Arc::clone(&pers);
    let proto = truenas_ros::http::protocol_streaming_fs(
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
                let left = std::rc::Rc::new(std::cell::Cell::new(ranges.len()));
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
                                let d =
                                    d.borrow_mut().take().expect("one taker");
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
    .expect("codec config");

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

    let payload = vec![0x9du8; mib * 1024 * 1024];
    let wire = wire_of(&payload);

    let client = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone());
        let mut s = TcpStream::connect(v4).expect("connect");
        s.set_read_timeout(Some(Duration::from_secs(60))).unwrap();
        let before = BIG_ALLOCS.load(Ordering::Relaxed);
        let before_med = MED_ALLOCS.load(Ordering::Relaxed);
        s.write_all(&wire).expect("write");
        let status = read_status(&mut s).expect("status");
        assert_eq!(status, 200, "upload refused");
        let cost = BIG_ALLOCS.load(Ordering::Relaxed) - before;
        let cost_med = MED_ALLOCS.load(Ordering::Relaxed) - before_med;
        drop(s);
        stop.shutdown();
        (cost, cost_med)
    });

    server.serve_forever().expect("serve_forever");
    let (cost, cost_med) = client.join().expect("client thread");
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
    let matches = written == payload;
    Some((cost, cost_med, matches))
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
fn exhaustion_put_cost(
    retry: Option<Duration>,
    per_conn: usize,
) -> Option<(u64, usize, u64, bool)> {
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
                    let cont =
                        move |done: truenas_ros::uring_fs::FsDone,
                              _fs: &mut truenas_ros::uring_fs::FsConn<
                                  '_,
                              >| {
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
        fs_ops: 64,
        max_request_bytes: 512 * 1024,
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
    // registered bound (`pool_size` recvs + `RECV_LEASE_DEPTH` leases per
    // connection) when it is off - then empties the FIFO so the writes,
    // and with them the leases, come home. Without the gate a fast drain
    // lets the leases cycle and the run never enters the phase under
    // test, so its assertions would hold vacuously.
    let ring_bound = (conns * 5) as u32;
    let gate_on_parks = retry.is_some();
    let d_count = std::sync::Arc::clone(&drained);
    let d_stop = std::sync::Arc::clone(&stop_drain);
    let drain = thread::spawn(move || {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            let s = stats_gate.snapshot();
            let gated = if gate_on_parks {
                s.recv_shortage_parks > 0
            } else {
                s.recv_bufs_lent >= ring_bound
            };
            if gated || std::time::Instant::now() > deadline {
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }
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
    });

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
                    status == 200
                })
            })
            .collect();
        let ok = uploads
            .into_iter()
            .all(|u| u.join().expect("upload thread"));
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
    drain.join().expect("drain thread");
    let s = stats.snapshot();
    assert_eq!(s.recv_bufs_lent, 0, "leases not returned: {s:?}");
    let got = drained.load(Ordering::Relaxed);
    Some((
        s.recv_shortage_parks,
        cost,
        got,
        ok && total > 0 && got == total,
    ))
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
    let Some((parks1, cost1, got1, ok1)) =
        exhaustion_put_cost(retry, 1536 * 1024)
    else {
        return; // io_uring unavailable here
    };
    let (parks2, cost2, got2, ok2) =
        exhaustion_put_cost(retry, 3072 * 1024).expect("second run");
    assert!(ok1 && ok2, "uploads failed or bytes lost ({got1}, {got2})");
    assert!(
        parks1 > 0 && parks2 > 0,
        "the pool never exhausted: nothing was proven ({parks1}, {parks2})"
    );
    assert!(
        cost2 <= cost1 + 2,
        "parked backpressure allocated per window: {cost1} large \
         allocations for 12 windows/conn, {cost2} for 24"
    );
}

/// The configurable control: `None` keeps the old answer - fall back to
/// owned buffers and keep every connection moving - so the same uploads
/// complete without a single park.
#[cfg(feature = "uring-fs")]
#[test]
fn exhaustion_without_the_knob_completes_without_parking() {
    let _turn = MEASURING.lock().unwrap_or_else(|e| e.into_inner());
    let Some((parks, _cost, got, ok)) = exhaustion_put_cost(None, 1536 * 1024)
    else {
        return; // io_uring unavailable here
    };
    assert!(ok, "uploads failed or bytes lost (drained {got})");
    assert_eq!(parks, 0, "None must never park");
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
