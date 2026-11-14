use super::*;

// ---- the bytes a ring holds out of its body pool ---------------------------

/// The ring's count of held bytes follows a placed body from its claim into the handler, which sees it counted until it
/// takes the body or drops it untaken, and a reply marked recycled until it is sent, so a request after both finds the
/// count back at 0.
#[test]
fn held_bytes_follow_a_placed_body_and_a_recycled_reply() {
    use std::cell::{OnceCell, RefCell};
    use std::rc::Rc;
    use truenas_ros::net::server::{BodyRecycler, SendBuf};

    // Past a receive buffer of the default size, so it is placed.
    const BODY: usize = 512 * 1024;
    let seam: Rc<OnceCell<BodyRecycler>> = Rc::new(OnceCell::new());
    // What the handler saw, `(held at delivery, held after the body)`.
    let seen: Rc<RefCell<Vec<(usize, usize)>>> = Rc::default();
    let (handler_seam, handler_seen) = (Rc::clone(&seam), Rc::clone(&seen));
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(PrefixWidth::U32, Endian::Big, false),
        body: move |mut req: Request<'_, ()>| {
            let r = handler_seam.get().expect("filled before serving");
            let at_delivery = r.held();
            let mut reply = r.claim(64 * 1024);
            match req.body.first() {
                // Taken, so off the count as the handler has it.
                Some(b'T') => drop(req.body.take()),
                Some(b'O') => drop(req.body.take_owned()),
                // Dropped untaken, so off the count as it goes home.
                Some(b'U') => drop(req.body),
                _ => {}
            }
            handler_seen.borrow_mut().push((at_delivery, r.held()));
            reply.extend_from_slice(&echo_frame(&(at_delivery as u64).to_be_bytes()));
            Response::ReplyVectored {
                segments: vec![SendBuf::recycled(reply)],
                close: false,
            }
        },
    };
    let cfg = ServerConfig {
        body_placement_threshold: Some(1024),
        ..ServerConfig::default()
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let mut server = match Server::with_config([addr], cfg, proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind: {e}"),
    };
    let recycler = server.body_recycler().expect("a server keeps a body pool");
    seam.set(recycler.clone()).expect("set once");
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();
    let client = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone()); // fail fast on panic
        (|| -> io::Result<()> {
            let mut s = connect_tcp(v4)?;
            for tag in *b"TOU" {
                let mut body = vec![tag; BODY];
                body[1] = 0;
                send_framed(&mut s, &body)?;
                recv_framed(&mut s)?;
                // A small request after the reply was read, whose handler sees whatever the ring still counts.
                send_framed(&mut s, b"p")?;
                let held = recv_framed(&mut s)?;
                assert_eq!(held, 0u64.to_be_bytes(), "after {}", tag as char);
            }
            Ok(())
        })()
        .expect("client io");
        stop.shutdown();
    });
    server.serve_forever().expect("serve_forever");
    client.join().expect("thread join");
    let seen = seen.borrow();
    assert_eq!(seen.len(), 6, "three bodies and three probes");
    for (i, &(at, after)) in seen.iter().enumerate() {
        if i % 2 == 0 {
            assert!(at >= BODY, "a placed body is counted from its claim: {at}");
            assert_eq!(after, 0, "and comes off as it leaves the reactor");
        } else {
            assert_eq!((at, after), (0, 0), "nothing held between requests");
        }
    }
    assert_eq!(recycler.held(), 0, "and nothing once the ring is idle");
}

/// A framer of records in fragments, each behind a mark of four bytes whose top bit says it is the last, as RFC 5531
/// frames ONC RPC over TCP. It reads only the marks, and only as far as it must, so every fragment but the last is the
/// header, and the data of the last is the body, placed when it is large enough.
fn fragments_header(buf: &[u8], _state: &mut ()) -> Framing {
    if buf.is_empty() {
        return Framing::Need(4);
    }
    let mut at = 0;
    loop {
        let data = at + 4;
        let Some(mark) = buf.get(at..data) else {
            return Framing::NeedInMessage(data - buf.len());
        };
        let mark = u32::from_be_bytes(mark.try_into().expect("a mark is four bytes"));
        let len = (mark & 0x7fff_ffff) as usize;
        if mark & 0x8000_0000 != 0 {
            return Framing::Complete {
                header_len: data,
                body_len: len,
            };
        }
        at = data + len;
        if buf.len() < at + 4 {
            return Framing::NeedInMessage(at + 4 - buf.len());
        }
    }
}

/// Send a record of `fragments`, each behind its mark.
fn send_record<W: Write>(s: &mut W, fragments: &[&[u8]]) -> io::Result<()> {
    for (i, fragment) in fragments.iter().enumerate() {
        let last = if i + 1 == fragments.len() { 0x8000_0000 } else { 0 };
        s.write_all(&(fragment.len() as u32 | last).to_be_bytes())?;
        s.write_all(fragment)?;
    }
    Ok(())
}

/// Storage promoted off a receive buffer counts what it grows by as later fragments of its record arrive, and gives
/// exactly that back. The handler of a record of two fragments whose last is not placed, and of one of three, sees at
/// least the record's bytes held, and a request after each finds the count back at 0.
#[test]
fn promoted_storage_counts_what_it_grows_by() {
    use std::cell::OnceCell;
    use std::rc::Rc;
    use truenas_ros::net::server::BodyRecycler;

    // Past a receive buffer of the default size, so the record is promoted as it outgrows one.
    const FIRST: usize = 300 * 1024;
    // Under the placement threshold, so the last fragment is read into the promoted storage.
    const LAST: usize = 32 * 1024;
    let seam: Rc<OnceCell<BodyRecycler>> = Rc::new(OnceCell::new());
    let h_seam = Rc::clone(&seam);
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: fragments_header,
        body: move |req: Request<'_, ()>| {
            let held = h_seam.get().expect("filled before serving").held() as u64;
            let record = (req.header.len() + req.body.len()) as u64;
            let mut reply = held.to_be_bytes().to_vec();
            reply.extend_from_slice(&record.to_be_bytes());
            Response::Reply(echo_frame(&reply))
        },
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let mut server = match Server::with_config([addr], ServerConfig::default(), proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind: {e}"),
    };
    let recycler = server.body_recycler().expect("a server keeps a body pool");
    seam.set(recycler.clone()).expect("set once");
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();
    let client = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone()); // fail fast on panic
        (|| -> io::Result<()> {
            let ask = |s: &mut TcpStream, fragments: &[&[u8]]| -> io::Result<(u64, u64)> {
                send_record(s, fragments)?;
                let reply = recv_framed(s)?;
                let (held, record) = reply.split_at(8);
                Ok((
                    u64::from_be_bytes(held.try_into().expect("eight bytes")),
                    u64::from_be_bytes(record.try_into().expect("eight bytes")),
                ))
            };
            let mut s = connect_tcp(v4)?;
            let (first, middle, last) = (vec![1u8; FIRST], vec![2u8; 400 * 1024], vec![3u8; LAST]);
            for record in [&[&first[..], &last[..]][..], &[&first[..], &middle[..], &last[..]][..]] {
                let (held, bytes) = ask(&mut s, record)?;
                assert!(
                    held >= bytes,
                    "a record of {} fragments counts {held} of its {bytes} bytes",
                    record.len()
                );
                let (held, _) = ask(&mut s, &[b"p"])?;
                assert_eq!(held, 0, "after a record of {} fragments", record.len());
            }
            Ok(())
        })()
        .expect("client io");
        stop.shutdown();
    });
    server.serve_forever().expect("serve_forever");
    client.join().expect("thread join");
    assert_eq!(recycler.held(), 0, "and nothing once the ring is idle");
}

/// A reply given to `Deferred::reply_recycled` counts from that call, before the loop has it, and stays counted once
/// the loop queues it until it is sent, with no turn where neither side counts it. One that reaches no request leaves
/// the count as it goes home, and an empty one goes as `Done` and adds nothing.
#[test]
fn a_deferred_recycled_reply_counts_from_its_hand_off() {
    use std::cell::{OnceCell, RefCell};
    use std::rc::Rc;
    use truenas_ros::net::server::BodyRecycler;

    const ROOM: usize = 64 * 1024;
    let seam: Rc<OnceCell<(BodyRecycler, ControlHandle)>> = Rc::new(OnceCell::new());
    // `(held, room)` as the handler saw them after each hand-off, and as the control hook saw them once the loop queued
    // the reply.
    let handed: Rc<RefCell<Vec<(usize, usize)>>> = Rc::default();
    let queued: Rc<RefCell<Vec<(usize, usize)>>> = Rc::default();
    let (h_seam, h_handed) = (Rc::clone(&seam), Rc::clone(&handed));
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: length_prefix_header::<()>(PrefixWidth::U32, Endian::Big, false),
        body: move |req: Request<'_, ()>| {
            let (r, control) = h_seam.get().expect("filled before serving");
            let framed = || {
                let mut v = r.claim(ROOM);
                v.extend_from_slice(&echo_frame(b"sent"));
                v
            };
            let (reply, spill) = match &*req.body {
                b"reply" => (framed(), false),
                b"spill" => (framed(), true),
                b"empty" => (r.claim(ROOM), false),
                _ => {
                    let held = (r.held() as u64).to_be_bytes();
                    return Response::Reply(echo_frame(&held));
                }
            };
            if spill {
                // Closed in the loop's drain ahead of the reply, so the reply reaches no request.
                req.responder.push_handle().close();
            }
            let room = if reply.is_empty() { 0 } else { reply.capacity() };
            let (deferred, permit) = req.responder.defer();
            deferred.reply_recycled(reply);
            h_handed.borrow_mut().push((r.held(), room));
            if room > 0 && !spill {
                // Reached in the same drain right after the reply, so the hook sees it queued and not yet sent.
                control.send(Box::new(room));
            }
            Response::Defer(permit)
        },
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let mut server = match Server::with_config([addr], ServerConfig::default(), proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind: {e}"),
    };
    let recycler = server.body_recycler().expect("a server keeps a body pool");
    let (hook_recycler, hook_queued) = (recycler.clone(), Rc::clone(&queued));
    server.set_control_hook(move |m| {
        let room = *m.downcast::<usize>().expect("a room");
        hook_queued.borrow_mut().push((hook_recycler.held(), room));
    });
    seam.set((recycler.clone(), server.control_handle()))
        .unwrap_or_else(|_| panic!("set once"));
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();
    let client = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone()); // fail fast on panic
        (|| -> io::Result<()> {
            let held = |s: &mut TcpStream| -> io::Result<u64> {
                send_framed(s, b"held")?;
                let v = recv_framed(s)?;
                Ok(u64::from_be_bytes(v.try_into().expect("eight bytes")))
            };
            let mut s = connect_tcp(v4)?;
            send_framed(&mut s, b"reply")?;
            assert_eq!(recv_framed(&mut s)?, b"sent");
            // The loop may learn the reply was sent after the peer has it.
            let until = Instant::now() + Duration::from_secs(10);
            while held(&mut s)? != 0 {
                assert!(Instant::now() < until, "a sent reply stayed counted");
                thread::sleep(Duration::from_millis(1));
            }
            // An empty reply sends nothing, so the next reply is the probe's.
            send_framed(&mut s, b"empty")?;
            assert_eq!(held(&mut s)?, 0, "an empty reply adds nothing");
            send_framed(&mut s, b"spill")?;
            let mut rest = Vec::new();
            s.read_to_end(&mut rest)?;
            assert!(rest.is_empty(), "the reply reached no request");
            let mut s = connect_tcp(v4)?;
            assert_eq!(held(&mut s)?, 0, "a spilled reply leaves the count");
            Ok(())
        })()
        .expect("client io");
        stop.shutdown();
    });
    server.serve_forever().expect("serve_forever");
    client.join().expect("thread join");
    let handed = handed.borrow();
    assert_eq!(handed.len(), 3, "a reply, an empty one and a spilled one");
    for &(held, room) in handed.iter() {
        assert_eq!(held, room, "counted from the hand-off, before the drain");
    }
    let queued = queued.borrow();
    assert_eq!(queued.len(), 1, "the reply was queued once");
    let (held, room) = queued[0];
    assert!(room > 0);
    assert_eq!(held, room, "counted once queued, and once only");
    assert_eq!(recycler.held(), 0, "and nothing once the ring is idle");
}

/// Placed bodies past `held_cap` wait and go on in the order they arrived, one at a time as the consumer gives bytes
/// back, so the ring passes the cap by one body at most, and every body arrives whole. A body larger than the cap goes
/// on once the count is under it. A read that waits longer than `max_receipt_time` is not closed for it, since only the
/// peer's own time counts.
#[test]
fn placed_bodies_past_the_held_cap_wait_their_turn() {
    use std::cell::{OnceCell, RefCell};
    use std::collections::VecDeque;
    use std::rc::Rc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use truenas_ros::net::server::BodyRecycler;

    // Past a receive buffer of the default size, so each is placed.
    const BODY: usize = 512 * 1024;
    const CAP: usize = 768 * 1024;
    // Larger than the cap alone, the last to arrive.
    const LARGE: usize = 1536 * 1024;
    const PEERS: u8 = 6;
    let size = |tag: u8| if tag + 1 == PEERS { LARGE } else { BODY };
    let receipt = Duration::from_millis(300);

    let seam: Rc<OnceCell<BodyRecycler>> = Rc::new(OnceCell::new());
    // The bodies the consumer holds, each with the reply it owes.
    type Held = VecDeque<(Deferred, Vec<u8>)>;
    let stash: Rc<RefCell<Held>> = Rc::default();
    // What each delivery saw, `(tag, held at delivery)`.
    let seen: Rc<RefCell<Vec<(u8, usize)>>> = Rc::default();
    let delivered = Arc::new(AtomicUsize::new(0));
    let (h_seam, h_stash, h_seen, h_delivered) = (
        Rc::clone(&seam),
        Rc::clone(&stash),
        Rc::clone(&seen),
        Arc::clone(&delivered),
    );
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: lsp_header,
        body: move |mut req: Request<'_, ()>| {
            let r = h_seam.get().expect("filled before serving");
            let at = r.held();
            // The consumer holds the body, and counts it, until released.
            let body = req.body.take();
            r.take_out(body.capacity());
            h_seen.borrow_mut().push((body[0], at));
            h_delivered.fetch_add(1, Ordering::SeqCst);
            let (deferred, permit) = req.responder.defer();
            h_stash.borrow_mut().push_back((deferred, body));
            Response::Defer(permit)
        },
    };
    let cfg = ServerConfig {
        pool_size: 16,
        max_request_bytes: 4 * 1024 * 1024,
        body_placement_threshold: Some(1024),
        held_cap: Some(CAP),
        max_receipt_time: Some(receipt),
        ..ServerConfig::default()
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let mut server = match Server::with_config([addr], cfg, proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind: {e}"),
    };
    let recycler = server.body_recycler().expect("a server keeps a body pool");
    seam.set(recycler.clone()).expect("set once");
    // Each control message releases the body held longest, giving its bytes back and answering whether it arrived
    // whole.
    let (c_stash, c_recycler) = (Rc::clone(&stash), recycler.clone());
    server.set_control_hook(move |_| {
        if let Some((deferred, body)) = c_stash.borrow_mut().pop_front() {
            c_recycler.give_back(body.capacity());
            let tag = body[0];
            let whole = body.len() == size(tag) && body[1..].iter().all(|&b| b == tag);
            deferred.reply(echo_frame(&[tag, u8::from(whole)]));
        }
    });
    let closes = close_reason_channel(&mut server);
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();
    let control = server.control_handle();
    let gate = Arc::clone(&delivered);
    let client = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone()); // fail fast on panic
        let peers: Vec<_> = (0..PEERS)
            .map(|tag| {
                thread::spawn(move || -> io::Result<Vec<u8>> {
                    // In order, each a beat after the one before.
                    thread::sleep(Duration::from_millis(80) * u32::from(tag));
                    let mut s = connect_tcp(v4)?;
                    let n = size(tag);
                    // The header in two parts, so its second read is part of the message and arms the receipt budget.
                    s.write_all(format!("Content-Length: {n}\r\n").as_bytes())?;
                    thread::sleep(Duration::from_millis(20));
                    s.write_all(b"\r\n")?;
                    s.write_all(&vec![tag; n])?;
                    recv_framed(&mut s)
                })
            })
            .collect();
        let wait_for = |n: usize| {
            let until = Instant::now() + Duration::from_secs(20);
            while gate.load(Ordering::SeqCst) < n {
                assert!(Instant::now() < until, "only {n} bodies went on");
                thread::sleep(Duration::from_millis(5));
            }
        };
        // Two bodies take the count past the cap, and the rest wait well past their receipt budget.
        wait_for(2);
        thread::sleep(Duration::from_millis(80) * u32::from(PEERS) + receipt * 2);
        assert_eq!(gate.load(Ordering::SeqCst), 2, "the rest wait");
        // Each release once the body the last one let go on has arrived, so no two held bodies go on together and
        // finish in either order.
        for released in 0..usize::from(PEERS) {
            wait_for((released + 2).min(usize::from(PEERS)));
            control.send(Box::new(()));
        }
        for (tag, peer) in peers.into_iter().enumerate() {
            let reply = peer.join().expect("peer").expect("peer io");
            assert_eq!(reply, [tag as u8, 1], "body {tag} arrived whole");
        }
        stop.shutdown();
    });
    server.serve_forever().expect("serve_forever");
    client.join().expect("thread join");
    let seen = seen.borrow();
    let order: Vec<u8> = seen.iter().map(|&(tag, _)| tag).collect();
    assert_eq!(order, (0..PEERS).collect::<Vec<_>>(), "in arrival order");
    // The body that crosses the cap may be any of them, the large one too.
    for &(tag, at) in seen.iter() {
        assert!(
            at <= CAP + LARGE,
            "body {tag} found {at} held, past the cap by more than one body"
        );
    }
    assert!(
        !closes.try_iter().any(|r| r == CloseReason::ReceiptTimeout),
        "a held read was closed on its receipt budget"
    );
}

/// Turns the consumer queues and placed bodies held back at the cap go on in one queue, in the order they came, one at
/// a time while each takes the count to the cap, so a stream of turns keeps no body back and a stream of bodies keeps
/// no turn back. The hook runs once for each turn, from the loop and never inside the call that queued it, and only
/// under the cap.
#[test]
fn turns_and_placed_bodies_go_on_in_the_order_they_came() {
    use std::cell::{Cell, OnceCell, RefCell};
    use std::rc::Rc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use truenas_ros::net::server::BodyRecycler;

    // Past a receive buffer of the default size, so each is placed, and past the cap, so each takes the count to it
    // alone.
    const BODY: usize = 512 * 1024;
    const CAP: usize = 256 * 1024;
    let seam: Rc<OnceCell<BodyRecycler>> = Rc::new(OnceCell::new());
    // What went on, in the order it went.
    let went: Rc<RefCell<Vec<String>>> = Rc::default();
    let runs = Rc::new(Cell::new(0usize));
    // What the client waits on, the bodies framed and the hook's runs.
    let framed = Arc::new(AtomicUsize::new(0));
    let ran = Arc::new(AtomicUsize::new(0));
    let (h_seam, h_went, h_runs) = (Rc::clone(&seam), Rc::clone(&went), Rc::clone(&runs));
    let h_framed = Arc::clone(&framed);
    let mut framing = length_prefix_header::<()>(PrefixWidth::U32, Endian::Big, false);
    let proto = Protocol {
        accept: |_: Incoming<'_>| Some(()),
        header: move |bytes: &[u8], state: &mut ()| {
            let framed = framing(bytes, state);
            if let Framing::Complete { body_len, .. } = framed
                && body_len >= BODY
            {
                h_framed.fetch_add(1, Ordering::SeqCst);
            }
            framed
        },
        body: move |mut req: Request<'_, ()>| {
            let r = h_seam.get().expect("filled before serving");
            if req.body.len() >= BODY {
                // Taken, so off the count, which lets the next go on.
                let tag = req.body[0] as char;
                h_went.borrow_mut().push(format!("body {tag}"));
                drop(req.body.take());
            } else {
                match &*req.body {
                    b"hold" => r.take_out(CAP),
                    b"release" => r.give_back(CAP),
                    b"turn" => {
                        assert!(!r.may_go(), "at the cap a call waits");
                        let before = h_runs.get();
                        r.queue_turn();
                        assert_eq!(h_runs.get(), before, "not inside the call");
                    }
                    _ => {}
                }
            }
            Response::Reply(echo_frame(b"ok"))
        },
    };
    let cfg = ServerConfig {
        max_request_bytes: 1 << 20,
        body_placement_threshold: Some(1024),
        held_cap: Some(CAP),
        ..ServerConfig::default()
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let mut server = match Server::with_config([addr], cfg, proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind: {e}"),
    };
    let recycler = server.body_recycler().expect("a server keeps a body pool");
    seam.set(recycler.clone()).unwrap_or_else(|_| panic!("set once"));
    let (k_went, k_runs, k_ran) = (Rc::clone(&went), Rc::clone(&runs), Arc::clone(&ran));
    server.set_held_hook(move || {
        assert!(recycler.held() < CAP, "a turn goes on only under the cap");
        k_runs.set(k_runs.get() + 1);
        k_went.borrow_mut().push(format!("turn {}", k_runs.get()));
        // The turn's call holds the count at the cap until released.
        recycler.take_out(CAP);
        k_ran.fetch_add(1, Ordering::SeqCst);
    });
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();
    let client = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone()); // fail fast on panic
        let wait = |count: &AtomicUsize, n: usize| {
            let until = Instant::now() + Duration::from_secs(10);
            while count.load(Ordering::SeqCst) < n {
                assert!(Instant::now() < until, "only {n} - 1 came");
                thread::sleep(Duration::from_millis(1));
            }
        };
        let body = |tag: u8| {
            thread::spawn(move || -> io::Result<Vec<u8>> {
                let mut s = connect_tcp(v4)?;
                send_framed(&mut s, &vec![tag; BODY])?;
                recv_framed(&mut s)
            })
        };
        let mut s = connect_tcp(v4).expect("connect");
        let mut ask = |what: &[u8]| {
            send_framed(&mut s, what).expect("send");
            assert_eq!(recv_framed(&mut s).expect("reply"), b"ok");
        };
        ask(b"hold");
        let a = body(b'A');
        wait(&framed, 1);
        ask(b"turn");
        ask(b"turn");
        let b = body(b'B');
        wait(&framed, 2);
        ask(b"turn");
        // One at a time from here, each holding the count at the cap.
        ask(b"release");
        assert_eq!(a.join().unwrap().expect("body A"), b"ok");
        wait(&ran, 1);
        ask(b"release");
        wait(&ran, 2);
        ask(b"release");
        assert_eq!(b.join().unwrap().expect("body B"), b"ok");
        wait(&ran, 3);
        ask(b"release");
        stop.shutdown();
    });
    server.serve_forever().expect("serve_forever");
    client.join().expect("thread join");
    assert_eq!(
        *went.borrow(),
        ["body A", "turn 1", "turn 2", "body B", "turn 3"],
        "in the order they came"
    );
}
