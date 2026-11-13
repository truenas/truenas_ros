//! Does a streamed upload allocate per window?
//!
//! Its own test binary, and it has to be: the measurement is a process-wide allocation count, so anything else running
//! in the same process is noise. One test, one server, one client.
//!
//! A pool that covered only request heads would leave the upload path minting a buffer per window. Measured rather than
//! reasoned about, because the code path that decides it (`body_placement_threshold` against the pool buffer's size) is
//! three modules away from the allocation.
#![cfg(all(target_os = "linux", feature = "http", feature = "net-server"))]

use std::alloc::{GlobalAlloc, Layout, System};
use std::io::{self, Read, Write};
use std::net::{SocketAddrV4, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;
use truenas_ros::http::{HttpConfig, HttpRequest, HttpResponse, HttpVerdict, Stage, protocol_streaming};
use truenas_ros::net::server::{Incoming, Server, ServerAddr, ServerConfig, ShutdownHandle};
use truenas_ros::{Errno, Error};

/// Allocations of at least this size are counted.
///
/// Body buffers are the only thing on this path that reaches it: the window is 128 KiB and the placement threshold is
/// 64 KiB, so a placed window lands here and nothing else does. Counting every allocation instead would drown the
/// signal in the reply-building and framing traffic that is not what this measures.
const BIG: usize = 64 * 1024;

static BIG_ALLOCS: AtomicUsize = AtomicUsize::new(0);

/// The second threshold, for costs whose unit is smaller than [`BIG`].
///
/// A copy or fallback need not move a full window at a time to matter - anything from a chunk read up scales with the
/// payload all the same. Counting from half a `RECV_CHUNK` keeps such costs visible while staying above the framing and
/// reply-building traffic, which is what a lower bar would drown the signal in.
const MED: usize = 2 * 1024;

static MED_ALLOCS: AtomicUsize = AtomicUsize::new(0);

/// The counter is process-global, so two measurements running at once report each other's allocations. Cargo runs a
/// binary's tests as threads, so they have to take turns.
static MEASURING: std::sync::Mutex<()> = std::sync::Mutex::new(());

struct Counting;

// SAFETY: every method delegates to `System` unchanged; the counter is the only addition and it touches no allocator
// state.
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
        // ENOMEM: rings pin pages against RLIMIT_MEMLOCK, so a loaded box exhausts it and ring creation fails -
        // environmental, and the REQUIRE variable turns the skip red where it must not happen.
        Error::Errno(Errno::EPERM | Errno::ENOSYS | Errno::EACCES | Errno::ENOMEM)
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

/// Upload `mib` MiB in 128 KiB chunks and answer how many large allocations the whole exchange cost.
fn upload_cost(mib: usize) -> Option<usize> {
    let cfg = ServerConfig {
        pool_size: 8,
        // A head cap, which is the configuration streaming creates: no single message is a whole body.
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
            // Consume the window without keeping it - what a handler writing to a file does, and what makes the buffer
            // reusable.
            Stage::Window => {
                *seen += req.body.len();
                HttpVerdict::Continue
            }
            Stage::End => HttpVerdict::Respond(HttpResponse::new(200).header("x-bytes", seen.to_string())),
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
        // Count only the exchange: everything before this is setup, and the wire buffer above is one allocation either
        // way.
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
/// Doubling the payload doubles the windows, so a per-window allocation shows up as a doubled count. Comparing two runs
/// rather than asserting an absolute number keeps the test honest about the fixed setup cost, which is neither zero nor
/// interesting.
#[test]
fn a_streamed_upload_does_not_allocate_per_window() {
    let _turn = MEASURING.lock().unwrap_or_else(|e| e.into_inner());
    let Some(small) = upload_cost(4) else {
        return; // io_uring unavailable
    };
    let Some(large) = upload_cost(16) else {
        return;
    };
    // 4 MiB is 32 windows, 16 MiB is 128 - so a per-window allocation would put 96 between them.
    assert!(
        large <= small + 8,
        "upload cost scales with payload: 4 MiB cost {small} large \
         allocations, 16 MiB cost {large}. A pool that covered request heads \
         but not body windows would look exactly like this."
    );
}

#[cfg(feature = "uring-fs")]
#[path = "recv_alloc/download.rs"]
mod download;

#[cfg(feature = "uring-fs")]
#[path = "recv_alloc/writes.rs"]
mod writes;

#[cfg(feature = "uring-fs")]
#[path = "recv_alloc/pipelined.rs"]
mod pipelined;

#[path = "recv_alloc/buffered.rs"]
mod buffered;

#[path = "recv_alloc/replies.rs"]
mod replies;
