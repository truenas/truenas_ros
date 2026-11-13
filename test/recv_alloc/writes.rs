use super::*;

// ---- the write side: PUT windows straight to a file ------------------------

/// Upload `mib` MiB as a streamed PUT whose handler writes every window to a real file with `pwritev2_from` +
/// `defer_stream`, and answer (large allocations, file bytes matched).
#[cfg(feature = "uring-fs")]
fn put_to_file_cost(mib: usize, wire_of: fn(&[u8]) -> Vec<u8>) -> Option<(usize, usize, bool)> {
    put_to_file_cost_ranged(mib, wire_of, false)
}

/// [`put_to_file_cost`], optionally writing every window as **two** leased ranges - the shape a verifier that emits
/// payload extents produces. Both ranges borrow the same claim, so the second must share the first's hold rather than
/// fall to the copy path.
#[cfg(feature = "uring-fs")]
fn put_to_file_cost_ranged(mib: usize, wire_of: fn(&[u8]) -> Vec<u8>, split: bool) -> Option<(usize, usize, bool)> {
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
                                    let d = d.borrow_mut().take().expect("one taker");
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
                Stage::End => HttpVerdict::Respond(HttpResponse::new(200).header("x-bytes", off.to_string())),
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

/// One streamed PUT of `mib` MiB of varied bytes, framed by `wire_of`, into a server running the protocol `proto_of`
/// builds over a pre-opened destination and the reactor's own personality. The upload's large allocations are counted,
/// every receive buffer is checked back home, and the destination is read back. `None` where this box has no io_uring.
/// The destination is opened through a throwaway [`UringFs`] host, since the open path is not what any caller measures.
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
    B: FnMut(truenas_ros::net::server::Request<'_, U>) -> truenas_ros::net::server::Response,
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
                let r = handle.open(who, &anchor, c"obj", OpenHow::new().flags(OFlag::O_WRONLY));
                let _ = ftx.send(r);
                stop_fs.shutdown();
            });
            afs.run().expect("fs host run");
        });
        frx.recv().expect("open outcome").expect("open")
    };

    let pers: std::sync::Arc<OnceLock<Personality>> = std::sync::Arc::new(OnceLock::new());
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

    // Varied bytes, so a window digested out of order or over a recycled buffer shows up; a constant fill would hash
    // the same either way.
    let payload: Vec<u8> = (0..mib * 1024 * 1024).map(|i| (i % 251) as u8).collect();
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
    assert_eq!(s.recv_bufs_lent, 0, "a leased buffer was never returned: {s:?}");
    let written = std::fs::read(&path).expect("read back");
    Some(Landed {
        cost,
        cost_med,
        matches: written == payload,
        payload,
        head,
    })
}

/// The digest the two digesting handlers compute: order-sensitive, so a window hashed over the wrong bytes or a
/// recycled buffer shows up.
#[cfg(feature = "uring-fs")]
fn fold(acc: u64, bytes: &[u8]) -> u64 {
    bytes
        .iter()
        .fold(acc, |h, &b| h.wrapping_mul(0x0000_0100_0000_01b3) ^ u64::from(b))
}

#[cfg(feature = "uring-fs")]
const FOLD_SEED: u64 = 0xcbf2_9ce4_8422_2325;

/// [`put_to_file_cost`] with every window also *digested* on the pool from the same leased buffer (`offload_from`): the
/// write and the job share the window's claim, the stream resumes when both have landed, and `End` answers the running
/// digest. Returns the allocation costs, whether the file matched, and whether the digest the handler accumulated is
/// the payload's.
#[cfg(feature = "uring-fs")]
fn put_digest_cost(mib: usize) -> Option<(usize, usize, bool, bool)> {
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;
    use truenas_ros::http::HttpStreamDeferred;
    use truenas_ros::uring_fs::RwFlags;

    /// One connection's upload: the payload offset and the digest so far. Each window parks until its job is back, so
    /// the next window starts from the digest its predecessor's completion stored.
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
                |_i: Incoming<'_>| Some(Rc::new(RefCell::new(Digesting { off: 0, acc: FOLD_SEED }))),
                move |req: HttpRequest<'_>, st: &mut Rc<RefCell<Digesting>>, fs| {
                    match req.stage {
                        Stage::Open => HttpVerdict::Continue,
                        Stage::Window => {
                            let Some(mut fs) = fs else {
                                return HttpVerdict::Respond(HttpResponse::new(500));
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
                            // Two landings per window: the write's CQE and the job's delivery. The last one resumes the
                            // stream.
                            let left = Rc::new(Cell::new(2u8));
                            let failed = Rc::new(Cell::new(false));
                            let finish = {
                                let (d, left, failed) = (Rc::clone(&d), Rc::clone(&left), Rc::clone(&failed));
                                move |ok: bool| {
                                    if !ok {
                                        failed.set(true);
                                    }
                                    left.set(left.get() - 1);
                                    if left.get() == 0 {
                                        let d = d.borrow_mut().take().expect("one taker");
                                        if failed.get() {
                                            d.fail(HttpResponse::new(500));
                                        } else {
                                            d.resume();
                                        }
                                    }
                                }
                            };
                            let f1 = finish.clone();
                            fs.pwritev2_from(who, file.clone(), &body, at, RwFlags::empty(), move |done, _fs| {
                                f1(done.result().is_ok())
                            });
                            let st = Rc::clone(st);
                            fs.offload_from(
                                &body,
                                move |view| Ok(fold(acc, view)),
                                move |r, _fs| match r {
                                    Ok(h) => {
                                        // Stored before the resume, so the next window and `End` both read it.
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
                                    .header("x-digest", format!("{:016x}", p.acc)),
                            )
                        }
                        Stage::Whole => HttpVerdict::Respond(HttpResponse::new(500)),
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

/// [`put_digest_cost`] with the digest *pipelined*: a window is never parked on its own job. Each window is written and
/// leased (`lease_window`); the lease is spent on the pool at once when no job is running, else it waits in a backlog
/// and the running job's completion spends it - `offload_leased` from a completion facade. The stream brakes only past
/// two waiting windows, and `End` answers from the completion that drains the last of them. Returns what
/// [`put_digest_cost`] does.
#[cfg(feature = "uring-fs")]
fn put_pipelined_digest_cost(mib: usize) -> Option<(usize, usize, bool, bool)> {
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::rc::Rc;
    use truenas_ros::http::{HttpDeferred, HttpStreamDeferred};
    use truenas_ros::uring_fs::{FsConn, LeasedWindow, RwFlags};

    /// A window waiting for the digest: leased where the delivery could lease it, copied where it could not (never, on
    /// this path - the flat allocation count is what proves it).
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
            Window::Leased(w) => conn.offload_leased(w, move |view| Ok(fold(acc, view)), done),
            Window::Owned(bytes) => conn.offload_result(move || Ok(fold(acc, &bytes)), done),
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
                move |req: HttpRequest<'_>, st: &mut Rc<RefCell<Pipe>>, fs| match req.stage {
                    Stage::Open => HttpVerdict::Continue,
                    Stage::Window => {
                        let Some(mut fs) = fs else {
                            return HttpVerdict::Respond(HttpResponse::new(500));
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
                        fs.pwritev2_from(who, file.clone(), &req.body, at, RwFlags::empty(), move |done, _fs| {
                            let mut p = wst.borrow_mut();
                            if done.result().is_err() {
                                p.write_failed = true;
                            }
                            p.writes -= 1;
                            p.answer();
                        });
                        let window = match fs.lease_window(&req.body) {
                            Some(w) => Window::Leased(w),
                            None => Window::Owned(req.body.to_vec()),
                        };
                        let busy = std::mem::replace(&mut st.borrow_mut().busy, true);
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
                    Stage::Whole => HttpVerdict::Respond(HttpResponse::new(500)),
                },
            )
            .expect("codec config")
        },
    )?;
    let want = format!("{:016x}", fold(FOLD_SEED, &landed.payload));
    let digested = landed.header("x-digest") == Some(want.as_str());
    Some((landed.cost, landed.cost_med, landed.matches, digested))
}

/// A window held past its delivery and spent from an earlier job's completion costs no copy and returns its lease.
/// Windows wait their turn as leases rather than copies, each spent by `offload_leased` from a completion facade that
/// holds no lease of its own. The payload's digest proves the windows were read in order and none was recycled under a
/// waiting job.
#[cfg(feature = "uring-fs")]
#[test]
fn a_held_window_is_digested_from_the_previous_jobs_completion() {
    let _turn = MEASURING.lock().unwrap_or_else(|e| e.into_inner());
    let Some((small, _, ok_small, digest_small)) = put_pipelined_digest_cost(4) else {
        return; // io_uring unavailable
    };
    let Some((large, _, ok_large, digest_large)) = put_pipelined_digest_cost(16) else {
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
    let status = text.split_whitespace().nth(1).and_then(|c| c.parse().ok()).unwrap_or(0);
    Ok((status, text))
}

/// A window digested on the pool from the receive buffer it arrived in costs no copy and returns its lease.
/// `offload_from` shares the write's claim, so the write and the job read the same buffer and it returns when the last
/// of them is over.
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
    // 4 MiB is 32 windows, 16 MiB is 128: a per-window copy shows up as ~96 between them.
    assert!(
        large <= small + 8,
        "digesting cost scales with payload: 4 MiB cost {small} large \
         allocations, 16 MiB cost {large}. A copy fallback looks exactly \
         like this."
    );
}

/// Writing a streamed PUT to a file must neither corrupt it nor allocate per window.
/// Byte-identical content proves the buffer was never recycled under the write, and a flat allocation count proves
/// neither the write nor the stream park fell back to copying.
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
    // 4 MiB is 32 windows, 16 MiB is 128: a per-window copy or park shows up as ~96 between them.
    assert!(
        large <= small + 8,
        "PUT-to-file cost scales with payload: 4 MiB cost {small} large \
         allocations, 16 MiB cost {large}. A copy fallback or a park that \
         retains the window looks exactly like this."
    );
}

/// Two ranges of one window both write from the claim.
/// A verifier that emits payload extents hands the handler several ranges of the same window, and each must share the
/// claim's hold, since a single-shot lease would send every range after the first to the copy path.
#[cfg(feature = "uring-fs")]
#[test]
fn a_multi_range_window_writes_every_range_from_the_claim() {
    let _turn = MEASURING.lock().unwrap_or_else(|e| e.into_inner());
    fn wire(p: &[u8]) -> Vec<u8> {
        chunked_put(p, 1024 * 1024)
    }
    let Some((small, _, ok_small)) = put_to_file_cost_ranged(4, wire, true) else {
        return; // io_uring unavailable
    };
    let Some((large, _, ok_large)) = put_to_file_cost_ranged(16, wire, true) else {
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
/// A chunk of exactly one window is the single size at which every window carries its chunk header, so the connection
/// always holds a recv claim and the cost of the no-claim arm is invisible. Fixtures framed at that size prove nothing
/// about it.
///
/// 1 MiB is a peer that chunks eight windows at a time. botocore's HTTP chunks are 128 KiB (see `STREAM_WINDOW`), and
/// its 1 MiB `_DEFAULT_CHUNK_SIZE` frames an inner aws-chunked payload this layer never frames. Seven windows in eight
/// are mid-chunk with the claim already leased to the previous window's write, and those must draw a fresh buffer from
/// the ring, not be placed into an allocation `pwritev2_from` then copies.
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
    // Placed-and-copied mid-chunk windows cost 14 large allocations per MiB, and flat means every window drew from the
    // ring.
    assert!(
        large <= small + 8,
        "PUT-to-file cost scales with payload at 1 MiB chunks: 4 MiB cost \
         {small} large allocations, 16 MiB cost {large}. Mid-chunk windows \
         are being placed and copied instead of drawing from the ring."
    );
}

/// A `Content-Length` body above one window streams exactly as a chunked one, with windows from the receive ring,
/// leased writes, no copy and no per-window allocation. The harness's `Whole` arm answers 500, so a body this size that
/// falls back to buffering fails the test outright.
///
/// Counted from [`MED`], the tighter of the allocator's two thresholds, so a fallback whose unit is smaller than a full
/// window still registers rather than sliding under a 64 KiB bar.
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
/// The End handoff consumes zero bytes, so the second request's head — already buffered behind the first body — must
/// frame cleanly rather than be eaten as a trailer section. Answered wrong, the connection desyncs and the second
/// status never arrives.
#[cfg(feature = "uring-fs")]
#[test]
fn pipelined_known_length_streams_do_not_desync() {
    use std::sync::atomic::AtomicUsize;

    // This allocates about 20 buffers over `BIG`, and the counter is process-global, so without the turn they would
    // land inside another test's measurement window.
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
                HttpVerdict::Respond(HttpResponse::new(200).header("x-bytes", got.to_string()))
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
        // Both requests in one write: the second head sits in the buffer behind the first body when the End handoff
        // runs.
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
