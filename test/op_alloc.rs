//! Does an op a handler sends on a warm ring allocate more than its
//! callback?
//!
//! Its own test binary, since it counts through a global allocator. It
//! counts on the ring's thread alone, around each submit, which is where an
//! op's name, its path under `/proc`, its `open_how` and the outer `Vec` of
//! an xattr value were allocated. So nothing else the process does reaches
//! the count, and what the completion makes (the `Arc` of a new descriptor)
//! is the op's answer, not its cost. The one allocation left is the box of
//! the callback itself, and a statx's box for its result.
//!
//! The ops run twice on one connection, the first pass to warm the ring,
//! and the second pass is counted.
// Under `--cfg loom` the crate's `Arc` is loom's, which a std `Arc` is not,
// and the loom lane runs no ring.
#![cfg(all(
    target_os = "linux",
    feature = "net-server",
    feature = "uring-fs",
    not(loom)
))]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::{Cell, OnceCell, RefCell};
use std::ffi::CStr;
use std::io::{self, Read, Write};
use std::net::{SocketAddrV4, TcpStream};
use std::os::fd::OwnedFd;
use std::rc::Rc;
use std::sync::{Arc, OnceLock};
use std::thread;
use std::time::Duration;
use truenas_ros::net::server::{
    BodyRecycler, Deferred, Endian, Incoming, PrefixWidth, Protocol, Request,
    Response, Server, ServerAddr, ServerConfig, ShutdownHandle,
    length_prefix_header,
};
use truenas_ros::sync_fs::{AtFlags, OFlag, OpenHow, StatxMask};
use truenas_ros::uring_fs::{
    Anchor, File, FsDone, Leaf, Personality, ReopenAccess, RwFlags,
};
use truenas_ros::{Errno, Error};

#[path = "support/xattr.rs"]
mod xattr_probe;

thread_local! {
    /// Allocations made on this thread. A `const` initializer and no
    /// destructor, so reading it from inside the allocator allocates
    /// nothing and never fails.
    static ALLOCS: Cell<usize> = const { Cell::new(0) };
}

struct Counting;

// SAFETY: every method delegates to `System` unchanged; the per-thread
// counter is the only addition and it touches no allocator state.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        ALLOCS.with(|n| n.set(n.get() + 1));
        unsafe { System.alloc(l) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        unsafe { System.dealloc(p, l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, new: usize) -> *mut u8 {
        ALLOCS.with(|n| n.set(n.get() + 1));
        unsafe { System.realloc(p, l, new) }
    }
}

#[global_allocator]
static A: Counting = Counting;

/// How many allocations `submit` makes on this thread.
fn counted(submit: impl FnOnce()) -> usize {
    let before = ALLOCS.with(Cell::get);
    submit();
    ALLOCS.with(Cell::get) - before
}

fn should_skip(e: &Error) -> bool {
    let unavailable = matches!(
        e,
        Error::Errno(
            Errno::EPERM | Errno::ENOSYS | Errno::EACCES | Errno::ENOMEM
        )
    );
    if unavailable {
        assert!(
            std::env::var_os("TRUENAS_ROS_REQUIRE_IO_URING").is_none(),
            "TRUENAS_ROS_REQUIRE_IO_URING set but io_uring unavailable: {e}"
        );
    }
    unavailable
}

struct ShutdownOnDrop(ShutdownHandle);
impl Drop for ShutdownOnDrop {
    fn drop(&mut self) {
        self.0.shutdown();
    }
}

fn send_framed(s: &mut TcpStream, payload: &[u8]) -> io::Result<()> {
    s.write_all(&(payload.len() as u32).to_be_bytes())?;
    s.write_all(payload)
}

fn recv_framed(s: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut len = [0u8; 4];
    s.read_exact(&mut len)?;
    let mut buf = vec![0u8; u32::from_be_bytes(len) as usize];
    s.read_exact(&mut buf)?;
    Ok(buf)
}

/// The ops counted, in the order a pass reports them, with the
/// allocations each may make: its callback's box, and a statx's box for
/// its result besides.
const OPS: [(&str, usize); 9] = [
    ("a reopen through /proc", 1),
    ("an open of a name", 1),
    ("an open of ..", 1),
    ("a statx of a name", 2),
    ("an fstatx", 2),
    ("a read of an xattr through /proc", 1),
    ("an fsetxattr", 1),
    ("a read into spare room", 1),
    ("an owned write", 1),
];

/// What one pass gathers until its last op answers.
struct Pass {
    counts: RefCell<Vec<usize>>,
    /// Whether each xattr op, the read into spare room and the owned write
    /// gave back the very buffer it was handed, through
    /// `FsDone::into_value`.
    same_value: RefCell<Vec<bool>>,
    /// Whether the body pool's storage the owned write wrote from is the
    /// storage the pass before gave back to the pool.
    cycled: Cell<bool>,
    left: Cell<usize>,
    deferred: RefCell<Option<Deferred>>,
}

impl Pass {
    /// One op answered. The last one replies with the counts, then a byte
    /// for each op that gave its buffer back.
    fn answered(&self) {
        self.left.set(self.left.get() - 1);
        if self.left.get() > 0 {
            return;
        }
        let mut reply = Vec::new();
        for n in self.counts.borrow().iter() {
            reply.extend_from_slice(&(*n as u32).to_be_bytes());
        }
        reply.extend(self.same_value.borrow().iter().map(|&s| u8::from(s)));
        reply.push(u8::from(self.cycled.get()));
        let mut framed = (reply.len() as u32).to_be_bytes().to_vec();
        framed.extend_from_slice(&reply);
        if let Some(deferred) = self.deferred.borrow_mut().take() {
            deferred.reply(framed);
        }
    }
}

const XATTR: &CStr = c"user.alloc";

/// A reopen, an open of a name, an open of `..`, a statx of a name, an
/// `fstatx`, a read of an xattr through `/proc`, an `fsetxattr`, a read
/// into spare room with a buffer the handler keeps and an owned write from
/// storage of the ring's body pool allocate nothing on a warm ring but the
/// box of their callback, and each statx the box of its result. An xattr
/// op, the read and the write give their buffer back through
/// `FsDone::into_value` with no outer `Vec`, and the write's storage goes
/// back to the pool and is the storage the next pass claims.
#[test]
fn a_warm_rings_ops_allocate_only_their_callback() {
    let dir = truenas_ros::tempdir().unwrap();
    std::fs::write(dir.path().join("f"), b"bytes").unwrap();
    std::fs::create_dir(dir.path().join("d")).unwrap();
    xattr_probe::set_user_xattr(
        &dir.path().join("f"),
        XATTR.to_bytes(),
        b"value",
    );
    let anchor = match Anchor::open(dir.path()) {
        Ok(a) => a,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("anchor open: {e}"),
    };
    let inner = Anchor::open(&dir.path().join("d")).expect("open d");
    let held: Arc<OwnedFd> = Arc::new(
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(dir.path().join("f"))
            .expect("open f")
            .into(),
    );
    let pers: Arc<OnceLock<Personality>> = Arc::new(OnceLock::new());
    let pool: Rc<OnceCell<BodyRecycler>> = Rc::new(OnceCell::new());
    let claimed = Rc::new(Cell::new(std::ptr::null::<u8>()));

    let pc = Arc::clone(&pers);
    let rc = Rc::clone(&pool);
    let body = move |mut req: Request<'_, ()>| -> Response {
        let _ = req.body.take();
        let (deferred, permit) = req.responder.defer();
        let Some(mut fs) = req.fs.take() else {
            return Response::Close;
        };
        let who = *pc.get().expect("personality set before serving");
        let pass = Rc::new(Pass {
            counts: RefCell::new(Vec::with_capacity(OPS.len())),
            same_value: RefCell::new(Vec::with_capacity(4)),
            cycled: Cell::new(false),
            left: Cell::new(OPS.len()),
            deferred: RefCell::new(Some(deferred)),
        });
        let file = File::from_shared(Arc::clone(&held));
        let read = OpenHow::new().flags(OFlag::O_RDONLY);
        let leaf = Leaf::new("f").expect("a valid leaf");

        let done = |pass: &Rc<Pass>| {
            let pass = Rc::clone(pass);
            move |_: FsDone, _: &mut truenas_ros::uring_fs::FsConn<'_>| {
                pass.answered()
            }
        };
        let gave_back = |pass: &Rc<Pass>, storage: *const u8| {
            let pass = Rc::clone(pass);
            move |d: FsDone, _: &mut truenas_ros::uring_fs::FsConn<'_>| {
                let back = d.into_value();
                let same = back.as_ptr() == storage;
                pass.same_value.borrow_mut().push(same);
                pass.answered();
            }
        };

        let (f, cb) = (file.clone(), done(&pass));
        let n = counted(|| fs.reopen_proc(who, f, ReopenAccess::Read, cb));
        pass.counts.borrow_mut().push(n);
        let cb = done(&pass);
        let n = counted(|| fs.open(who, &anchor, c"f", read, cb));
        pass.counts.borrow_mut().push(n);
        let cb = done(&pass);
        let n = counted(|| fs.open_parent(who, &inner, read, cb));
        pass.counts.borrow_mut().push(n);
        let (mask, cb) = (StatxMask::BASIC_STATS, done(&pass));
        let empty = AtFlags::empty();
        let n = counted(|| fs.statx(who, &anchor, leaf, empty, mask, cb));
        pass.counts.borrow_mut().push(n);
        let cb = done(&pass);
        let n = counted(|| fs.fstatx(who, &file, empty, mask, cb));
        pass.counts.borrow_mut().push(n);
        let buf = vec![0u8; 64];
        let (f, cb) = (file.clone(), gave_back(&pass, buf.as_ptr()));
        let n = counted(|| fs.fgetxattr_proc(who, f, XATTR, buf, cb));
        pass.counts.borrow_mut().push(n);
        let value = b"other".to_vec();
        let (f, cb) = (file.clone(), gave_back(&pass, value.as_ptr()));
        let n = counted(|| fs.fsetxattr(who, f, XATTR, value, 0, cb));
        pass.counts.borrow_mut().push(n);
        let room = Vec::with_capacity(64);
        let (f, cb) = (file.clone(), gave_back(&pass, room.as_ptr()));
        let empty = RwFlags::empty();
        let n = counted(|| fs.pread_spare(who, f, room, 5, 0, empty, cb));
        pass.counts.borrow_mut().push(n);
        let recycler = rc.get().expect("the pool set before serving").clone();
        let mut owned = recycler.claim(4096);
        owned.resize(4096, b'w');
        pass.cycled
            .set(owned.as_ptr() == claimed.replace(owned.as_ptr()));
        let (storage, pass_back) = (owned.as_ptr(), Rc::clone(&pass));
        let cb = move |d: FsDone, _: &mut truenas_ros::uring_fs::FsConn<'_>| {
            let back = d.into_value();
            pass_back
                .same_value
                .borrow_mut()
                .push(back.as_ptr() == storage);
            recycler.recycle(back);
            pass_back.answered();
        };
        let n = counted(|| {
            fs.pwritev2_owned(who, file, owned, 0..4096, 4096, empty, cb)
        });
        pass.counts.borrow_mut().push(n);
        Response::Defer(permit)
    };
    let protocol = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(
            PrefixWidth::U32,
            Endian::Big,
            false,
        ),
        body,
    };
    let cfg = ServerConfig {
        pool_size: 4,
        fs_ops: 16,
        ..ServerConfig::default()
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let mut server = match Server::with_config([addr], cfg, protocol) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind with an fs table: {e}"),
    };
    pers.set(server.register_self().expect("register_self"))
        .unwrap();
    let recycler = server.body_recycler().expect("a server keeps a body pool");
    assert!(pool.set(recycler).is_ok(), "the pool is set once");
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();
    let client = thread::spawn(move || -> io::Result<Vec<u8>> {
        let _stop = ShutdownOnDrop(stop.clone());
        let mut s = TcpStream::connect(v4)?;
        s.set_read_timeout(Some(Duration::from_secs(10)))?;
        send_framed(&mut s, b"warm")?;
        recv_framed(&mut s)?;
        send_framed(&mut s, b"count")?;
        let counted = recv_framed(&mut s)?;
        stop.shutdown();
        Ok(counted)
    });
    server.serve_forever().expect("serve_forever");
    let reply = client.join().unwrap().expect("client io");
    assert_eq!(reply.len(), OPS.len() * 4 + 5, "{reply:?}");
    for (i, (what, most)) in OPS.iter().enumerate() {
        let at = i * 4;
        let n = u32::from_be_bytes(reply[at..at + 4].try_into().unwrap());
        assert_eq!(n as usize, *most, "{what} allocated {n} times");
    }
    let gave = &reply[OPS.len() * 4..OPS.len() * 4 + 4];
    assert_eq!(gave, [1, 1, 1, 1], "each gives back its own buffer");
    assert_eq!(
        reply[OPS.len() * 4 + 4],
        1,
        "the pass wrote from the storage the warm pass gave back"
    );
}
