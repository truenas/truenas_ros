use super::*;

// ---------------------------------------------------------------------------
// `HttpResponse::file_body`: fd-sourced response bodies, streamed by the reactor's reply path in bounded chunks.

/// A deterministic pattern any hole, reorder, or overrun shows up in.
#[cfg(feature = "uring-fs")]
fn patterned(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

/// The property the whole seam exists for: a body spanning many chunks (default `fs_body_chunk` 256 KiB, plus an odd
/// remainder for the final short chunk) served byte-exact through the codec - with a HEAD of the same resource
/// declaring the length and sending nothing, keep-alive surviving the stream, and a `Connection: close` GET flushing
/// the WHOLE body before the farewell (the tail-guarded flush-close).
#[cfg(feature = "uring-fs")]
#[test]
fn http_file_body_streams_a_multi_chunk_file() {
    use std::sync::{Arc, OnceLock};
    use truenas_ros::http::HttpVerdict;
    use truenas_ros::sync_fs::{OFlag, OpenHow};
    use truenas_ros::uring_fs::{Anchor, Personality};

    const SIZE: usize = 3 * 256 * 1024 + 12_345;
    let dir = truenas_ros::tempdir().unwrap();
    let content = patterned(SIZE);
    std::fs::write(dir.path().join("obj"), &content).unwrap();
    let anchor = match Anchor::open(dir.path()) {
        Ok(a) => a,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("anchor open: {e}"),
    };
    let pers: Arc<OnceLock<Personality>> = Arc::new(OnceLock::new());

    let pc = Arc::clone(&pers);
    let handler: FsHandler<()> = Box::new(move |req, _state, fs| {
        if req.target == "/small" {
            return HttpVerdict::Respond(HttpResponse::new(200).body("after"));
        }
        let Some(mut fs) = fs else {
            return HttpVerdict::Respond(HttpResponse::new(500));
        };
        let (deferred, permit) = req.defer();
        let who = *pc.get().expect("personality set before serving");
        let anchor = anchor.clone();
        let how = OpenHow::new().flags(OFlag::O_RDONLY);
        fs.open(who, &anchor, c"obj", how, move |done, _fs| match done.file() {
            Some(file) => deferred.reply(HttpResponse::new(200).file_body(file, 0, SIZE as u64)),
            None => deferred.close(),
        });
        HttpVerdict::Defer(permit)
    });

    let Some(()) = with_http_fs_server(
        || (),
        handler,
        pers,
        move |v4| {
            let mut s = connect_tcp(v4)?;
            s.set_read_timeout(Some(Duration::from_secs(10)))?;
            // HEAD: the length is declared, no body byte follows - the next request on this same connection parses only
            // if that held.
            s.write_all(b"HEAD /obj HTTP/1.1\r\nHost: t\r\n\r\n")?;
            let (status, head) = read_head(&mut s)?;
            assert_eq!(status, 200);
            assert!(head.contains(&format!("Content-Length: {SIZE}\r\n")), "{head}");
            // GET: the streamed body, byte-exact.
            s.write_all(b"GET /obj HTTP/1.1\r\nHost: t\r\n\r\n")?;
            let (status, _head, body) = read_response(&mut s)?;
            assert_eq!(status, 200);
            assert_eq!(body.len(), SIZE);
            assert_eq!(body, content, "streamed bytes match the file");
            // Keep-alive survived the stream.
            s.write_all(b"GET /small HTTP/1.1\r\nHost: t\r\n\r\n")?;
            let (status, _head, body) = read_response(&mut s)?;
            assert_eq!(status, 200);
            assert_eq!(body, b"after");
            // A farewell GET: the whole body must flush before the close.
            s.write_all(b"GET /obj HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n")?;
            let (status, head, body) = read_response(&mut s)?;
            assert_eq!(status, 200);
            assert!(head.contains("Connection: close\r\n"), "{head}");
            assert_eq!(body, content, "farewell body complete before close");
            assert_eof(&mut s)?;
            Ok(())
        },
    ) else {
        return; // io_uring unavailable
    };
}

/// A range is an offset and a length - and a `File` handle stashed across requests serves one **inline** (no park): the
/// first request opens and stashes, the second replies `file_body` straight from the handler.
#[cfg(feature = "uring-fs")]
#[test]
fn http_file_body_serves_a_range_from_a_stashed_handle() {
    use std::sync::{Arc, Mutex, OnceLock};
    use truenas_ros::http::HttpVerdict;
    use truenas_ros::sync_fs::{OFlag, OpenHow};
    use truenas_ros::uring_fs::{Anchor, File, Personality};

    const SIZE: usize = 4096;
    let dir = truenas_ros::tempdir().unwrap();
    let content = patterned(SIZE);
    std::fs::write(dir.path().join("obj"), &content).unwrap();
    let anchor = match Anchor::open(dir.path()) {
        Ok(a) => a,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("anchor open: {e}"),
    };
    let pers: Arc<OnceLock<Personality>> = Arc::new(OnceLock::new());
    let stash: Arc<Mutex<Option<File>>> = Arc::new(Mutex::new(None));

    let pc = Arc::clone(&pers);
    let st = Arc::clone(&stash);
    let handler: FsHandler<()> = Box::new(move |req, _state, fs| {
        if req.target == "/range" {
            // Inline: the handle held from the previous request answers without a park - the handler-side shape of a
            // preamble that already opened the object.
            let file = st.lock().unwrap().take().expect("stashed by /open");
            return HttpVerdict::Respond(HttpResponse::new(200).file_body(file, 100, 1000));
        }
        let Some(mut fs) = fs else {
            return HttpVerdict::Respond(HttpResponse::new(500));
        };
        let (deferred, permit) = req.defer();
        let who = *pc.get().expect("personality set before serving");
        let anchor = anchor.clone();
        let how = OpenHow::new().flags(OFlag::O_RDONLY);
        let st = Arc::clone(&st);
        fs.open(who, &anchor, c"obj", how, move |done, _fs| match done.file() {
            Some(file) => {
                *st.lock().unwrap() = Some(file);
                deferred.reply(HttpResponse::new(200).body("opened"));
            }
            None => deferred.close(),
        });
        HttpVerdict::Defer(permit)
    });

    let Some(()) = with_http_fs_server(
        || (),
        handler,
        pers,
        move |v4| {
            let mut s = connect_tcp(v4)?;
            s.set_read_timeout(Some(Duration::from_secs(5)))?;
            s.write_all(b"GET /open HTTP/1.1\r\nHost: t\r\n\r\n")?;
            let (status, _head, body) = read_response(&mut s)?;
            assert_eq!((status, &body[..]), (200, &b"opened"[..]));
            s.write_all(b"GET /range HTTP/1.1\r\nHost: t\r\n\r\n")?;
            let (status, head, body) = read_response(&mut s)?;
            assert_eq!(status, 200);
            assert!(head.contains("Content-Length: 1000\r\n"), "{head}");
            assert_eq!(body, content[100..1100], "the requested range");
            Ok(())
        },
    ) else {
        return; // io_uring unavailable
    };
}

/// A range whose start the caller's arithmetic wrapped is refused before it reaches the ring, and refusing sheds that
/// one connection rather than the server.
///
/// `u64::MAX` is `-1`, io_uring's "use the file's own position" sentinel: for a regular file `io_kiocb_update_pos`
/// (linux `io_uring/rw.c:484-490`) would read `f_pos` in place of the offset asked for and `rw.c:670-671` would write
/// the new position back, so the read would SUCCEED from the wrong place and move a position shared with every other
/// holder of the descriptor - behind a `Content-Length` already on the wire. A start past `i64::MAX` that is not the
/// sentinel fails much later, in `rw_verify_area`, which is also after the head has committed. `bytes=-N` past the
/// object size is how either arrives: computing the start as `size - N` wraps in `u64` rather than clamping.
///
/// The last assertion is the one that matters: a *later* connection is served. A closed connection alone cannot tell a
/// clean shed from the reactor thread dying on the overflow, which is what an unguarded advance does in debug.
#[cfg(feature = "uring-fs")]
#[test]
fn http_file_body_refuses_a_wrapped_range() {
    use std::io::Read as _;
    use std::sync::{Arc, Mutex, OnceLock};
    use truenas_ros::http::HttpVerdict;
    use truenas_ros::sync_fs::{OFlag, OpenHow};
    use truenas_ros::uring_fs::{Anchor, File, Personality};

    const SIZE: usize = 4096;
    let dir = truenas_ros::tempdir().unwrap();
    let content = patterned(SIZE);
    std::fs::write(dir.path().join("obj"), &content).unwrap();
    let anchor = match Anchor::open(dir.path()) {
        Ok(a) => a,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("anchor open: {e}"),
    };
    let pers: Arc<OnceLock<Personality>> = Arc::new(OnceLock::new());
    let stash: Arc<Mutex<Vec<File>>> = Arc::new(Mutex::new(Vec::new()));

    let pc = Arc::clone(&pers);
    let st = Arc::clone(&stash);
    let handler: FsHandler<()> = Box::new(move |req, _state, fs| {
        // Each target answers inline from a handle the previous `/open` stashed, so the range reaches
        // `begin_file_reply` with nothing else in flight.
        let range = match req.target {
            // `size - N` for a suffix range one byte past the object.
            "/sentinel" => Some((u64::MAX, 8)),
            // Not the sentinel, but the sum still walks past `i64::MAX`.
            "/sum" => Some((i64::MAX as u64, 8)),
            "/ok" => Some((0, SIZE as u64)),
            _ => None,
        };
        if let Some((offset, len)) = range {
            let file = st.lock().unwrap().pop().expect("stashed by /open");
            return HttpVerdict::Respond(HttpResponse::new(200).file_body(file, offset, len));
        }
        let Some(mut fs) = fs else {
            return HttpVerdict::Respond(HttpResponse::new(500));
        };
        let (deferred, permit) = req.defer();
        let who = *pc.get().expect("personality set before serving");
        let anchor = anchor.clone();
        let how = OpenHow::new().flags(OFlag::O_RDONLY);
        let st = Arc::clone(&st);
        fs.open(who, &anchor, c"obj", how, move |done, _fs| match done.file() {
            Some(file) => {
                st.lock().unwrap().push(file);
                deferred.reply(HttpResponse::new(200).body("opened"));
            }
            None => deferred.close(),
        });
        HttpVerdict::Defer(permit)
    });

    let Some(()) = with_http_fs_server(
        || (),
        handler,
        pers,
        move |v4| {
            // Each refusal gets its own connection: the shed is the point.
            for target in ["/sentinel", "/sum"] {
                let mut s = connect_tcp(v4)?;
                s.set_read_timeout(Some(Duration::from_secs(10)))?;
                s.write_all(b"GET /open HTTP/1.1\r\nHost: t\r\n\r\n")?;
                let (status, _head, body) = read_response(&mut s)?;
                assert_eq!((status, &body[..]), (200, &b"opened"[..]));

                let req = format!("GET {target} HTTP/1.1\r\nHost: t\r\n\r\n");
                s.write_all(req.as_bytes())?;
                let mut got = Vec::new();
                s.read_to_end(&mut got)?;
                assert!(
                    got.is_empty(),
                    "{target} must be refused before the head commits, \
                     got {} bytes",
                    got.len()
                );
            }

            // The server is still there, and the reply path still streams.
            let mut s = connect_tcp(v4)?;
            s.set_read_timeout(Some(Duration::from_secs(10)))?;
            s.write_all(b"GET /open HTTP/1.1\r\nHost: t\r\n\r\n")?;
            let (status, _head, body) = read_response(&mut s)?;
            assert_eq!((status, &body[..]), (200, &b"opened"[..]));
            s.write_all(b"GET /ok HTTP/1.1\r\nHost: t\r\n\r\n")?;
            let (status, head, body) = read_response(&mut s)?;
            assert_eq!(status, 200);
            assert!(head.contains(&format!("Content-Length: {SIZE}\r\n")), "{head}");
            assert_eq!(body, content, "a sound range still serves");
            Ok(())
        },
    ) else {
        return; // io_uring unavailable
    };
}

/// A body read that finds the op table full WAITS for a slot instead of severing the transfer.
///
/// The table is `fs_ops + pool_size`, one free list shared by handler ops and the reply path's body reads, and nothing
/// reserves either side's share. A missing chunk buffer waits for a flush to recycle one, so a missing op slot waits
/// too: the same class of transient shortage must not get opposite verdicts, one of them fatal to a multi-GB download
/// mid-stream.
///
/// Both slots are pinned here by reads on a FIFO that cannot complete until the client writes to it, which is what a
/// handler fan-out looks like from the reply path. The object must still arrive whole.
#[cfg(feature = "uring-fs")]
#[test]
fn http_file_body_waits_for_an_op_slot() {
    use std::io::Write as _;
    use std::sync::mpsc;
    use std::sync::{Arc, OnceLock};
    use truenas_ros::http::HttpVerdict;
    use truenas_ros::net::server::ServerConfig;
    use truenas_ros::sync_fs::{OFlag, OpenHow};
    use truenas_ros::uring_fs::{Anchor, Personality, RwFlags};

    const SIZE: usize = 300_000; // more than one 256 KiB chunk
    let dir = truenas_ros::tempdir().unwrap();
    let content = patterned(SIZE);
    std::fs::write(dir.path().join("obj"), &content).unwrap();
    let fifo = dir.path().join("fifo");
    let cpath = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).expect("path has no NUL");
    // SAFETY: a fresh path in a private tempdir; 0o600 is the mode.
    assert_eq!(unsafe { libc::mkfifo(cpath.as_ptr(), 0o600) }, 0, "mkfifo");

    let anchor = match Anchor::open(dir.path()) {
        Ok(a) => a,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("anchor open: {e}"),
    };
    let pers: Arc<OnceLock<Personality>> = Arc::new(OnceLock::new());
    // The handler says when the reply has been handed over, so the client releases the pinned reads only after the body
    // has had its chance to park - not before, which would leave the wait unexercised.
    let (armed_tx, armed_rx) = mpsc::channel::<()>();

    let pc = Arc::clone(&pers);
    let handler: FsHandler<()> = Box::new(move |req, _state, fs| {
        use std::cell::RefCell;
        use std::rc::Rc;

        let Some(mut fs) = fs else {
            return HttpVerdict::Respond(HttpResponse::new(500));
        };
        let (deferred, permit) = req.defer();
        let who = *pc.get().expect("personality set before serving");
        let armed = armed_tx.clone();
        // Both opens are issued HERE so they overlap on the ring, which is what this test is about: whichever completes
        // second does the work. (Not a restriction - a continuation's facade opens like any other; see
        // `fs_continuation_may_open_and_its_slot_comes_back`.)
        type Held = (
            Option<truenas_ros::uring_fs::File>,
            Option<truenas_ros::uring_fs::File>,
            Option<truenas_ros::http::HttpDeferred>,
        );
        let held: Rc<RefCell<Held>> = Rc::new(RefCell::new((None, None, Some(deferred))));
        // O_RDWR so the open does not wait for a writer and the reads below never see EOF.
        let fifo_how = OpenHow::new().flags(OFlag::O_RDWR);
        let obj_how = OpenHow::new().flags(OFlag::O_RDONLY);

        // A free `fn`, not a closure: it is called from two `'static` continuations and captures nothing.
        fn finish(
            fs: &mut truenas_ros::uring_fs::FsConn<'_>,
            who: Personality,
            held: &Rc<RefCell<Held>>,
            armed: &mpsc::Sender<()>,
        ) {
            let mut h = held.borrow_mut();
            let (pipe, obj, deferred) = &mut *h;
            let (Some(pipe), Some(obj)) = (pipe.as_ref(), obj.take()) else {
                return; // the other open has not landed yet
            };
            // Take every op slot the table has (`fs_ops + pool_size` = 2). `u64::MAX` because a pipe refuses a real
            // offset (ESPIPE) and takes the file-position sentinel instead.
            //
            // The buffer needs a LENGTH, not just capacity: `submit_rw` sets `iov_len` from `buf.len()`, so a
            // `Vec::with_capacity(8)` asks the kernel for zero bytes, completes immediately, and pins no slot at all -
            // which leaves the wait below unexercised.
            for _ in 0..2 {
                fs.preadv2(
                    who,
                    pipe.clone(),
                    vec![vec![0u8; 8]],
                    u64::MAX,
                    RwFlags::empty(),
                    |_done, _fs| {},
                );
            }
            deferred
                .take()
                .expect("one finisher")
                .reply(HttpResponse::new(200).file_body(obj, 0, SIZE as u64));
            let _ = armed.send(());
        }

        let (h1, a1) = (Rc::clone(&held), armed.clone());
        fs.open(who, &anchor, c"fifo", fifo_how, move |done, fs| {
            h1.borrow_mut().0 = Some(done.file().expect("fifo opens"));
            finish(fs, who, &h1, &a1);
        });
        let (h2, a2) = (Rc::clone(&held), armed);
        fs.open(who, &anchor, c"obj", obj_how, move |done, fs| {
            h2.borrow_mut().1 = Some(done.file().expect("obj opens"));
            finish(fs, who, &h2, &a2);
        });
        HttpVerdict::Defer(permit)
    });

    let Some(()) = with_http_fs_server_cfg(
        ServerConfig {
            pool_size: 1,
            fs_ops: 1,
            ..ServerConfig::default()
        },
        || (),
        handler,
        pers,
        move |v4| {
            let mut s = connect_tcp(v4)?;
            s.set_read_timeout(Some(Duration::from_secs(20)))?;
            s.write_all(b"GET /obj HTTP/1.1\r\nHost: t\r\n\r\n")?;
            // Wait for the reply to be handed over, then release the pinned reads: their completions are what re-drive
            // the parked body.
            armed_rx.recv().expect("handler armed the table");
            let mut w = std::fs::OpenOptions::new().write(true).open(&fifo)?;
            w.write_all(b"go")?;
            drop(w);

            let (status, head, body) = read_response(&mut s)?;
            assert_eq!(status, 200);
            assert!(head.contains(&format!("Content-Length: {SIZE}\r\n")), "{head}");
            assert_eq!(body, content, "the whole object, after waiting");
            Ok(())
        },
    ) else {
        return; // io_uring unavailable
    };
}

/// A freed op slot reaches the **parked body** before the completion's own continuation can take it back.
///
/// `Server::on_cqe` calls `redrive_parked_tail()` between `fs.on_cqe(...)` (which returns the slot) and `match reaped`
/// (which fires the handler continuation). That statement order is the whole anti-starvation property, and it reads
/// like post-dispatch bookkeeping, so a refactor moving it below the dispatch is entirely plausible.
/// `http_file_body_waits_for_an_op_slot` does not catch that: its pinned reads complete into `|_done, _fs| {}`, so
/// nothing competes for the slot they free and the test passes with the two statements in either order.
///
/// Here the pinned reads' continuations re-submit, so the freed slot is contended by exactly the party the ordering
/// exists to beat. Swap the two statements in `on_cqe` and the re-submitted read wins the slot, the body never gets
/// one, and this fails on the client's read timeout.
///
/// The continuations capture no `HttpDeferred`, so the one that loses the race (which, with the ordering correct, is
/// the re-submit) is dropped harmlessly rather than closing the connection.
#[cfg(feature = "uring-fs")]
#[test]
fn http_a_freed_op_slot_reaches_the_parked_body_first() {
    use std::io::Write as _;
    use std::sync::mpsc;
    use std::sync::{Arc, OnceLock};
    use truenas_ros::http::HttpVerdict;
    use truenas_ros::net::server::ServerConfig;
    use truenas_ros::sync_fs::{OFlag, OpenHow};
    use truenas_ros::uring_fs::{Anchor, File, Personality, RwFlags};

    const SIZE: usize = 300_000; // more than one 256 KiB chunk
    let dir = truenas_ros::tempdir().unwrap();
    let content = patterned(SIZE);
    std::fs::write(dir.path().join("obj"), &content).unwrap();
    let fifo = dir.path().join("fifo");
    let cpath = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).expect("path has no NUL");
    // SAFETY: a fresh path in a private tempdir; 0o600 is the mode.
    assert_eq!(unsafe { libc::mkfifo(cpath.as_ptr(), 0o600) }, 0, "mkfifo");

    let anchor = match Anchor::open(dir.path()) {
        Ok(a) => a,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("anchor open: {e}"),
    };
    let pers: Arc<OnceLock<Personality>> = Arc::new(OnceLock::new());
    let (armed_tx, armed_rx) = mpsc::channel::<()>();

    let pc = Arc::clone(&pers);
    let handler: FsHandler<()> = Box::new(move |req, _state, fs| {
        use std::cell::RefCell;
        use std::rc::Rc;

        let Some(mut fs) = fs else {
            return HttpVerdict::Respond(HttpResponse::new(500));
        };
        let (deferred, permit) = req.defer();
        let who = *pc.get().expect("personality set before serving");
        let armed = armed_tx.clone();
        type Held = (Option<File>, Option<File>, Option<truenas_ros::http::HttpDeferred>);
        let held: Rc<RefCell<Held>> = Rc::new(RefCell::new((None, None, Some(deferred))));
        let fifo_how = OpenHow::new().flags(OFlag::O_RDWR);
        let obj_how = OpenHow::new().flags(OFlag::O_RDONLY);

        /// Pin one op slot with a fifo read whose completion immediately asks for the slot back. `again` bounds the
        /// chain so a lost race does not spin; one re-submit is all the contention the ordering has to survive.
        fn pin(fs: &mut truenas_ros::uring_fs::FsConn<'_>, who: Personality, pipe: File, again: bool) {
            let p = pipe.clone();
            fs.preadv2(
                who,
                pipe,
                // Length, not capacity: `submit_rw` sets `iov_len` from `buf.len()`, so a `Vec::with_capacity(8)` asks
                // for ZERO bytes and the read completes at once, pinning nothing.
                vec![vec![0u8; 8]],
                u64::MAX, // a pipe refuses a real offset (ESPIPE)
                RwFlags::empty(),
                move |_done, fs| {
                    if again {
                        // Contend for the slot this completion just freed. Losing is fine: nothing here captures the
                        // reply, so a dropped callback closes nothing.
                        pin(fs, who, p, false);
                    }
                },
            );
        }

        fn finish(
            fs: &mut truenas_ros::uring_fs::FsConn<'_>,
            who: Personality,
            held: &Rc<RefCell<Held>>,
            armed: &mpsc::Sender<()>,
        ) {
            let mut h = held.borrow_mut();
            let (pipe, obj, deferred) = &mut *h;
            let (Some(pipe), Some(obj)) = (pipe.as_ref(), obj.take()) else {
                return; // the other open has not landed yet
            };
            // Take every op slot the table has (`fs_ops + pool_size` = 2).
            for _ in 0..2 {
                pin(fs, who, pipe.clone(), true);
            }
            deferred
                .take()
                .expect("one finisher")
                .reply(HttpResponse::new(200).file_body(obj, 0, SIZE as u64));
            let _ = armed.send(());
        }

        let (h1, a1) = (Rc::clone(&held), armed.clone());
        fs.open(who, &anchor, c"fifo", fifo_how, move |done, fs| {
            h1.borrow_mut().0 = Some(done.file().expect("fifo opens"));
            finish(fs, who, &h1, &a1);
        });
        let (h2, a2) = (Rc::clone(&held), armed);
        fs.open(who, &anchor, c"obj", obj_how, move |done, fs| {
            h2.borrow_mut().1 = Some(done.file().expect("obj opens"));
            finish(fs, who, &h2, &a2);
        });
        HttpVerdict::Defer(permit)
    });

    let Some(()) = with_http_fs_server_cfg(
        ServerConfig {
            pool_size: 1,
            fs_ops: 1,
            ..ServerConfig::default()
        },
        || (),
        handler,
        pers,
        move |v4| {
            let mut s = connect_tcp(v4)?;
            s.set_read_timeout(Some(Duration::from_secs(20)))?;
            s.write_all(b"GET /obj HTTP/1.1\r\nHost: t\r\n\r\n")?;
            armed_rx.recv().expect("handler armed the table");
            // Release exactly one pinned read. Its completion frees one slot and its continuation asks for that slot
            // back; the body must get it first.
            let mut w = std::fs::OpenOptions::new().write(true).open(&fifo)?;
            w.write_all(b"go")?;
            drop(w);

            let (status, head, body) = read_response(&mut s)?;
            assert_eq!(status, 200);
            assert!(head.contains(&format!("Content-Length: {SIZE}\r\n")), "{head}");
            assert_eq!(body, content, "the parked body won the freed slot and streamed whole");
            Ok(())
        },
    ) else {
        return; // io_uring unavailable
    };
}

/// Pipelined file bodies are served, in order, all of them.
///
/// One tail at a time is structural - two bodies' chunks would interleave on the wire - but shedding the connection to
/// enforce that destroys the FIRST response, which is already committed: the client gets nothing, not even body one.
/// Every other PDU in this position queues behind the tail, and so does a file body.
///
/// Answered INLINE from handles a preamble stashed, not through `defer`: pipelining lets replies complete out of
/// request order (`net::server`, the Pipelining section), which HTTP/1.1 forbids, so a deferred reply at
/// `max_in_flight_requests > 1` is a consumer-protocol mismatch rather than anything to do with the tail.
#[cfg(feature = "uring-fs")]
#[test]
fn http_pipelined_file_bodies_queue_instead_of_killing_the_connection() {
    use std::sync::{Arc, Mutex, OnceLock};
    use truenas_ros::http::HttpVerdict;
    use truenas_ros::net::server::ServerConfig;
    use truenas_ros::sync_fs::{OFlag, OpenHow};
    use truenas_ros::uring_fs::{Anchor, File, Personality};

    const SIZE: usize = 300_000; // more than one 256 KiB chunk
    const REQUESTS: usize = 3;
    let dir = truenas_ros::tempdir().unwrap();
    let content = patterned(SIZE);
    std::fs::write(dir.path().join("obj"), &content).unwrap();
    let anchor = match Anchor::open(dir.path()) {
        Ok(a) => a,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("anchor open: {e}"),
    };
    let pers: Arc<OnceLock<Personality>> = Arc::new(OnceLock::new());
    let stash: Arc<Mutex<Vec<File>>> = Arc::new(Mutex::new(Vec::new()));

    let pc = Arc::clone(&pers);
    let st = Arc::clone(&stash);
    let handler: FsHandler<()> = Box::new(move |req, _state, fs| {
        if req.target == "/obj" {
            let file = st.lock().unwrap().pop().expect("stashed by /open");
            return HttpVerdict::Respond(HttpResponse::new(200).file_body(file, 0, SIZE as u64));
        }
        let Some(mut fs) = fs else {
            return HttpVerdict::Respond(HttpResponse::new(500));
        };
        let (deferred, permit) = req.defer();
        let who = *pc.get().expect("personality set before serving");
        let anchor = anchor.clone();
        let how = OpenHow::new().flags(OFlag::O_RDONLY);
        let st = Arc::clone(&st);
        fs.open(who, &anchor, c"obj", how, move |done, _fs| match done.file() {
            Some(file) => {
                st.lock().unwrap().push(file);
                deferred.reply(HttpResponse::new(200).body("opened"));
            }
            None => deferred.close(),
        });
        HttpVerdict::Defer(permit)
    });

    let Some(()) = with_http_fs_server_cfg(
        ServerConfig {
            pool_size: 16,
            fs_ops: 16,
            // The whole point: read-ahead deep enough that request two is delivered while request one's body is still
            // streaming.
            max_in_flight_requests: 2,
            ..ServerConfig::default()
        },
        || (),
        handler,
        pers,
        move |v4| {
            let mut s = connect_tcp(v4)?;
            s.set_read_timeout(Some(Duration::from_secs(20)))?;
            // One handle per pipelined GET, stashed one request at a time.
            for _ in 0..REQUESTS {
                s.write_all(b"GET /open HTTP/1.1\r\nHost: t\r\n\r\n")?;
                let (status, _head, body) = read_response(&mut s)?;
                assert_eq!((status, &body[..]), (200, &b"opened"[..]));
            }
            // All of them in one write, so they are genuinely pipelined.
            let mut reqs = Vec::new();
            for _ in 0..REQUESTS {
                reqs.extend_from_slice(b"GET /obj HTTP/1.1\r\nHost: t\r\n\r\n");
            }
            s.write_all(&reqs)?;
            for i in 0..REQUESTS {
                let (status, head, body) = read_response(&mut s)?;
                assert_eq!(status, 200, "response {i}");
                assert!(
                    head.contains(&format!("Content-Length: {SIZE}\r\n")),
                    "response {i}: {head}"
                );
                assert_eq!(body, content, "response {i} body");
            }
            Ok(())
        },
    ) else {
        return; // io_uring unavailable
    };
}

/// A file grown after the length was declared: reads clamp to the declared length, so exactly `len` bytes arrive and
/// the NEXT request on the same connection still parses - unclamped, the surplus would arrive as the start of the next
/// response (a framing desync).
#[cfg(feature = "uring-fs")]
#[test]
fn http_file_body_clamps_a_file_grown_mid_reply() {
    use std::io::Write as _;
    use std::sync::{Arc, OnceLock};
    use truenas_ros::http::HttpVerdict;
    use truenas_ros::sync_fs::{OFlag, OpenHow};
    use truenas_ros::uring_fs::{Anchor, Personality};

    const SIZE: usize = 256 * 1024 + 10;
    let dir = truenas_ros::tempdir().unwrap();
    let content = patterned(SIZE);
    let fp = dir.path().join("obj");
    std::fs::write(&fp, &content).unwrap();
    let anchor = match Anchor::open(dir.path()) {
        Ok(a) => a,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("anchor open: {e}"),
    };
    let pers: Arc<OnceLock<Personality>> = Arc::new(OnceLock::new());

    let pc = Arc::clone(&pers);
    let handler: FsHandler<()> = Box::new(move |req, _state, fs| {
        if req.target == "/small" {
            return HttpVerdict::Respond(HttpResponse::new(200).body("after"));
        }
        let Some(mut fs) = fs else {
            return HttpVerdict::Respond(HttpResponse::new(500));
        };
        let (deferred, permit) = req.defer();
        let who = *pc.get().expect("personality set before serving");
        let anchor = anchor.clone();
        let how = OpenHow::new().flags(OFlag::O_RDONLY);
        let fp = fp.clone();
        fs.open(who, &anchor, c"obj", how, move |done, _fs| {
            match done.file() {
                Some(file) => {
                    // Grow the file between the open and the reply: the declared length is a snapshot; the surplus must
                    // never reach the wire.
                    std::fs::OpenOptions::new()
                        .append(true)
                        .open(&fp)
                        .and_then(|mut f| f.write_all(b"SURPLUS-NEVER-SENT"))
                        .expect("append");
                    deferred.reply(HttpResponse::new(200).file_body(file, 0, SIZE as u64));
                }
                None => deferred.close(),
            }
        });
        HttpVerdict::Defer(permit)
    });

    let Some(()) = with_http_fs_server(
        || (),
        handler,
        pers,
        move |v4| {
            let mut s = connect_tcp(v4)?;
            s.set_read_timeout(Some(Duration::from_secs(10)))?;
            s.write_all(b"GET /obj HTTP/1.1\r\nHost: t\r\n\r\n")?;
            let (status, _head, body) = read_response(&mut s)?;
            assert_eq!(status, 200);
            assert_eq!(body, content, "exactly the declared length");
            // Nothing leaked past the declared length: the next request on this connection frames cleanly.
            s.write_all(b"GET /small HTTP/1.1\r\nHost: t\r\n\r\n")?;
            let (status, _head, body) = read_response(&mut s)?;
            assert_eq!((status, &body[..]), (200, &b"after"[..]));
            Ok(())
        },
    ) else {
        return; // io_uring unavailable
    };
}

/// A file truncated after the length was declared: the read hits EOF short of the contract, and the only honest answer
/// is a mid-body close - the client sees a truncated transfer, never a short body framed as complete. (The first read
/// also comes back short - the file shrank below one chunk -- so this pins short-read continuation and EOF
/// classification at once.)
#[cfg(feature = "uring-fs")]
#[test]
fn http_file_body_truncation_closes_mid_body() {
    use std::io::Read as _;
    use std::sync::{Arc, OnceLock};
    use truenas_ros::http::HttpVerdict;
    use truenas_ros::sync_fs::{OFlag, OpenHow};
    use truenas_ros::uring_fs::{Anchor, Personality};

    const SIZE: usize = 300_000;
    const SHRUNK: usize = 100_000;
    let dir = truenas_ros::tempdir().unwrap();
    let content = patterned(SIZE);
    let fp = dir.path().join("obj");
    std::fs::write(&fp, &content).unwrap();
    let anchor = match Anchor::open(dir.path()) {
        Ok(a) => a,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("anchor open: {e}"),
    };
    let pers: Arc<OnceLock<Personality>> = Arc::new(OnceLock::new());

    let pc = Arc::clone(&pers);
    let handler: FsHandler<()> = Box::new(move |req, _state, fs| {
        let Some(mut fs) = fs else {
            return HttpVerdict::Respond(HttpResponse::new(500));
        };
        let (deferred, permit) = req.defer();
        let who = *pc.get().expect("personality set before serving");
        let anchor = anchor.clone();
        let how = OpenHow::new().flags(OFlag::O_RDONLY);
        let fp = fp.clone();
        fs.open(who, &anchor, c"obj", how, move |done, _fs| {
            match done.file() {
                Some(file) => {
                    // Shrink after the open: the declared length becomes a promise the file can no longer keep.
                    std::fs::OpenOptions::new()
                        .write(true)
                        .open(&fp)
                        .and_then(|f| f.set_len(SHRUNK as u64))
                        .expect("truncate");
                    deferred.reply(HttpResponse::new(200).file_body(file, 0, SIZE as u64));
                }
                None => deferred.close(),
            }
        });
        HttpVerdict::Defer(permit)
    });

    let Some(()) = with_http_fs_server(
        || (),
        handler,
        pers,
        move |v4| {
            let mut s = connect_tcp(v4)?;
            s.set_read_timeout(Some(Duration::from_secs(10)))?;
            s.write_all(b"GET /obj HTTP/1.1\r\nHost: t\r\n\r\n")?;
            let (status, head) = read_head(&mut s)?;
            assert_eq!(status, 200);
            assert!(head.contains(&format!("Content-Length: {SIZE}\r\n")), "{head}");
            let mut got = Vec::new();
            s.read_to_end(&mut got)?;
            assert!(
                got.len() < SIZE,
                "the transfer must be visibly truncated, got all {SIZE}"
            );
            assert_eq!(got, content[..got.len()], "what did arrive is the true prefix");
            Ok(())
        },
    ) else {
        return; // io_uring unavailable
    };
}

/// A file-sourced body over kernel TLS is nothing special - chunks are plaintext buffers on the ordinary send path,
/// encrypted in the kernel -- so the same multi-chunk stream arrives byte-exact and the connection serves the next
/// request. Worth proving once, which is what this is.
#[cfg(feature = "uring-fs")]
#[test]
fn ktls_file_body_streams_intact() {
    use std::sync::OnceLock;
    use truenas_ros::http::{HttpVerdict, protocol_fs};
    use truenas_ros::sync_fs::{OFlag, OpenHow};
    use truenas_ros::uring_fs::{Anchor, Personality};

    if ktls_openssl_unsupported() {
        return;
    }
    const SIZE: usize = 2 * 256 * 1024 + 4_321;
    let dir = truenas_ros::tempdir().unwrap();
    let content = patterned(SIZE);
    std::fs::write(dir.path().join("obj"), &content).unwrap();
    let anchor = match Anchor::open(dir.path()) {
        Ok(a) => a,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("anchor open: {e}"),
    };
    let pers: Arc<OnceLock<Personality>> = Arc::new(OnceLock::new());

    let pc = Arc::clone(&pers);
    let proto = protocol_fs(
        HttpConfig::default(),
        |_inc: Incoming<'_>| Some(()),
        move |req: HttpRequest<'_>, _state: &mut (), fs| {
            if req.target == "/small" {
                return HttpVerdict::Respond(HttpResponse::new(200).body("after"));
            }
            let Some(mut fs) = fs else {
                return HttpVerdict::Respond(HttpResponse::new(500));
            };
            let (deferred, permit) = req.defer();
            let who = *pc.get().expect("personality set before serving");
            let anchor = anchor.clone();
            let how = OpenHow::new().flags(OFlag::O_RDONLY);
            fs.open(who, &anchor, c"obj", how, move |done, _fs| match done.file() {
                Some(file) => deferred.reply(HttpResponse::new(200).file_body(file, 0, SIZE as u64)),
                None => deferred.close(),
            });
            HttpVerdict::Defer(permit)
        },
    )
    .expect("codec config is valid");

    let (cert, key) = self_signed();
    let acceptor = Arc::new(ktls_acceptor(&cert, &key));
    let cfg = ServerConfig {
        pool_size: 16,
        fs_ops: 16,
        ..ServerConfig::default()
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let mut server = match Server::with_config([Listen::tls(addr)], cfg, proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) || ktls_unsupported(&e) => return,
        Err(e) => panic!("bind: {e}"),
    };
    pers.set(server.register_self().expect("register_self")).unwrap();
    server.set_tls_handshake(move |fd, _inc, deferral| {
        let acceptor = Arc::clone(&acceptor);
        thread::spawn(move || match ktls_server_handshake(fd, &acceptor) {
            Ok(()) => deferral.ready(HttpConn::new(())),
            Err(_) => deferral.reject(),
        });
    });
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();
    let join = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone()); // fail fast on panic
        let r = (|| -> io::Result<()> {
            let mut s = tls_connect(v4)?;
            s.write_all(b"GET /obj HTTP/1.1\r\nHost: t\r\n\r\n")?;
            let (status, _head, body) = read_response(&mut s)?;
            assert_eq!(status, 200);
            assert_eq!(body, content, "kTLS-streamed bytes match the file");
            s.write_all(b"GET /small HTTP/1.1\r\nHost: t\r\n\r\n")?;
            let (status, _head, body) = read_response(&mut s)?;
            assert_eq!((status, &body[..]), (200, &b"after"[..]));
            Ok(())
        })();
        stop.shutdown();
        r
    });
    server.serve_forever().expect("serve_forever");
    join.join().expect("client thread").expect("client io");
}

/// A request pipelined behind a streaming body is answered after it, in order: both requests ride one write, and the
/// second reply follows the full first body on the wire.
#[cfg(feature = "uring-fs")]
#[test]
fn http_file_body_holds_a_pipelined_request_until_the_body_completes() {
    use std::sync::{Arc, OnceLock};
    use truenas_ros::http::HttpVerdict;
    use truenas_ros::sync_fs::{OFlag, OpenHow};
    use truenas_ros::uring_fs::{Anchor, Personality};

    const SIZE: usize = 2 * 256 * 1024 + 777;
    let dir = truenas_ros::tempdir().unwrap();
    let content = patterned(SIZE);
    std::fs::write(dir.path().join("obj"), &content).unwrap();
    let anchor = match Anchor::open(dir.path()) {
        Ok(a) => a,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("anchor open: {e}"),
    };
    let pers: Arc<OnceLock<Personality>> = Arc::new(OnceLock::new());

    let pc = Arc::clone(&pers);
    let handler: FsHandler<()> = Box::new(move |req, _state, fs| {
        if req.target == "/small" {
            return HttpVerdict::Respond(HttpResponse::new(200).body("after"));
        }
        let Some(mut fs) = fs else {
            return HttpVerdict::Respond(HttpResponse::new(500));
        };
        let (deferred, permit) = req.defer();
        let who = *pc.get().expect("personality set before serving");
        let anchor = anchor.clone();
        let how = OpenHow::new().flags(OFlag::O_RDONLY);
        fs.open(who, &anchor, c"obj", how, move |done, _fs| match done.file() {
            Some(file) => deferred.reply(HttpResponse::new(200).file_body(file, 0, SIZE as u64)),
            None => deferred.close(),
        });
        HttpVerdict::Defer(permit)
    });

    let Some(()) = with_http_fs_server(
        || (),
        handler,
        pers,
        move |v4| {
            let mut s = connect_tcp(v4)?;
            s.set_read_timeout(Some(Duration::from_secs(10)))?;
            // Both requests in one write: the second is buffered behind the streaming reply and answered after it.
            s.write_all(
                b"GET /obj HTTP/1.1\r\nHost: t\r\n\r\n\
                  GET /small HTTP/1.1\r\nHost: t\r\n\r\n",
            )?;
            let (status, _head, body) = read_response(&mut s)?;
            assert_eq!(status, 200);
            assert_eq!(body, content, "first: the full streamed body");
            let (status, _head, body) = read_response(&mut s)?;
            assert_eq!((status, &body[..]), (200, &b"after"[..]));
            Ok(())
        },
    ) else {
        return; // io_uring unavailable
    };
}
