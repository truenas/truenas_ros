use super::*;

#[test]
fn send_gather_and_advance() {
    let mut c = Connection::new(ClientAddr::Unix { cred: None }, (), 2);
    c.enqueue(vec![1; 10], SendKind::ReplyLast);
    c.enqueue(vec![2; 20], SendKind::Push);
    c.enqueue(vec![3; 30], SendKind::ReplyLast);
    assert_eq!(c.queued_bytes(), 60);

    // Gather caps at max_send_coalesce (2): PDUs 1+2 armed, PDU 3 waits.
    assert_eq!(c.arm_send(), 30);
    // Partial completion mid-PDU-2: PDU 1 (a reply) finishes, cursor lands inside PDU 2.
    let p = c.advance_sent(15);
    assert_eq!((p.replies, p.pushes, p.armed_remaining), (1, 0, 15));
    assert_eq!(c.queued_bytes(), 50);
    // Error-recovery re-arm from the cursor: PDU 2's tail + PDU 3.
    assert_eq!(c.arm_send(), 15 + 30);
    let p = c.advance_sent(45);
    assert_eq!((p.replies, p.pushes, p.armed_remaining), (1, 1, 0));
    assert_eq!(c.queued_bytes(), 0);
    assert!(!c.has_pending_send());

    // A completion never advances past what was armed.
    c.enqueue(vec![4; 8], SendKind::ReplyLast);
    assert_eq!(c.arm_send(), 8);
    let p = c.advance_sent(usize::MAX);
    assert_eq!((p.replies, p.armed_remaining), (1, 0));
}

#[test]
fn vectored_reply_head_counts_as_one_reply_no_push() {
    let mut c = Connection::new(ClientAddr::Unix { cred: None }, (), 2);
    // A vectored reply: head + body as separate segments. The head is a non-final segment; it must not be tallied
    // as a push.
    assert!(c.enqueue_reply_segments(vec![vec![b'H'; 12].into(), vec![b'B'; 40].into(),]));
    assert_eq!(c.arm_send(), 12 + 40);
    let p = c.advance_sent(12 + 40);
    assert_eq!((p.replies, p.pushes, p.armed_remaining), (1, 0, 0));
}

#[test]
fn a_static_segment_is_armed_at_its_own_address() {
    // A `'static` segment is sent from where it lives: the armed iovec must point at the static bytes themselves,
    // proving no copy sits anywhere between enqueue and the gather.
    static BODY: &[u8] = b"the canned body, sent by reference";
    let mut c = Connection::new(ClientAddr::Unix { cred: None }, (), 2);
    assert!(c.enqueue_reply_segments(vec![vec![b'H'; 8].into(), BODY.into()]));
    assert_eq!(c.arm_send(), 8 + BODY.len());
    assert_eq!(c.send_iovs[1].iov_base as *const u8, BODY.as_ptr());
    assert_eq!(c.send_iovs[1].iov_len, BODY.len());
    let p = c.advance_sent(8 + BODY.len());
    assert_eq!((p.replies, p.pushes), (1, 0));
    assert_eq!(c.queued_bytes(), 0);
}

/// A connection on a pool, and storage for a reply claimed from it as a consumer claims one, so the pool's law
/// keeps what comes back.
#[cfg(feature = "net-server")]
fn pooled_conn(claims: &[usize]) -> (Box<Connection<()>>, super::super::bodypool::PoolHandle, Vec<Vec<u8>>) {
    let pool = std::rc::Rc::new(std::cell::RefCell::new(super::super::bodypool::BodyPool::new(
        1 << 20,
        None,
    )));
    let mut c = Connection::new(ClientAddr::Unix { cred: None }, (), 4);
    c.body_pool = Some(std::rc::Rc::clone(&pool));
    let bufs = claims.iter().map(|&n| pool.borrow_mut().claim(n)).collect();
    (c, pool, bufs)
}

/// A segment marked as the pool's sends its own storage home once all of it is sent, and no sooner. A plain owned
/// segment sends nothing, so storage no one claimed never reaches the pool.
#[cfg(feature = "net-server")]
#[test]
fn a_recycled_segment_gives_its_storage_back_once_sent() {
    let (mut c, pool, mut bufs) = pooled_conn(&[64, 16]);
    let mut tail = bufs.pop().expect("claimed");
    let mut head = bufs.pop().expect("claimed");
    head.extend_from_slice(&[b'H'; 12]);
    tail.extend_from_slice(&[b'R'; 10]);
    let at = head.as_ptr();
    assert!(c.enqueue_reply_segments(vec![SendBuf::recycled(head), vec![b'B'; 8].into(),]));
    assert!(c.enqueue_reply_segments(vec![SendBuf::recycled(tail)]));
    assert_eq!(pool.borrow().held(), 64 + 16, "counted once queued");
    assert_eq!(c.arm_send(), 12 + 8 + 10);

    let _ = c.advance_sent(4);
    assert_eq!(pool.borrow().retained(), 0, "a partly sent segment keeps its storage");
    assert_eq!(pool.borrow().held(), 64 + 16, "and stays counted");

    // The rest of the head, all of the plain segment and half the last.
    let p = c.advance_sent(8 + 8 + 5);
    assert_eq!(p.replies, 1);
    assert_eq!(pool.borrow().retained(), 64, "only the marked segment goes home");
    assert_eq!(pool.borrow().held(), 16, "and leaves the count");

    let p = c.advance_sent(5);
    assert_eq!((p.replies, p.armed_remaining), (1, 0));
    assert_eq!(pool.borrow().retained(), 64 + 16);
    assert_eq!(pool.borrow().held(), 0);
    let again = pool.borrow_mut().claim(64);
    assert_eq!(again.as_ptr(), at, "its own storage, not a copy");
}

/// A segment marked as the pool's that its connection drops unsent, as a teardown does, goes home all the same.
#[cfg(feature = "net-server")]
#[test]
fn a_recycled_segment_queued_at_a_teardown_goes_home() {
    let (mut c, pool, mut bufs) = pooled_conn(&[64]);
    let mut reply = bufs.pop().expect("claimed");
    reply.extend_from_slice(&[b'R'; 12]);
    let at = reply.as_ptr();
    assert!(c.enqueue_reply_segments(vec![SendBuf::recycled(reply)]));
    assert_eq!(c.arm_send(), 12);
    drop(c);
    assert_eq!(pool.borrow().retained(), 64, "the unsent reply came home");
    assert_eq!(pool.borrow().held(), 0, "and left the count");
    let again = pool.borrow_mut().claim(64);
    assert_eq!(again.as_ptr(), at, "its own storage, not a copy");
}

#[test]
fn body_placement_bookkeeping() {
    let mut c = Connection::new(ClientAddr::Unix { cred: None }, (), 8);
    // Frame a 4-byte header + 30 already-buffered body bytes (a More-style over-read), then place the 100-byte
    // body.
    c.arm_recv(34, true);
    {
        // Play the kernel: recvs land in reserved spare capacity, and only the completion (recv_result) extends the
        // length over the initialized bytes.
        let ptr = c.recv_ptr() as *mut u8;
        // SAFETY: recv_ptr points at the 34 reserved-but-uninit bytes.
        unsafe { std::ptr::write_bytes(ptr, 0, 34) };
    }
    assert_eq!(c.recv_result(34), RecvOutcome::Complete);
    c.set_frame(4, 100);
    let want = c.arm_body_recv(None);
    assert_eq!(want, 70, "prefix of 30 already copied in");
    assert_eq!(c.buffered(), 4, "buf truncated back to the header");
    // Play the kernel: fill the armed spare capacity, then complete.
    let ptr = c.recv_ptr() as *mut u8;
    // SAFETY: recv_ptr points at `want` reserved-but-uninit bytes.
    unsafe { std::ptr::write_bytes(ptr, 0xCD, want) };
    assert_eq!(c.recv_result(want as i32), RecvOutcome::Complete);
    {
        let (header, mut body, _addr, _state, _lic) = c.deliver_parts(None);
        assert_eq!(header.len(), 4);
        assert_eq!(body.len(), 100);
        assert!(body[..30].iter().all(|&b| b == 0), "copied prefix");
        assert!(body[30..].iter().all(|&b| b == 0xCD), "kernel-read tail");
        let owned = body.take();
        assert_eq!(owned.len(), 100);
        assert_eq!(body.len(), 0, "take leaves the body empty");
        assert_eq!(body.take(), Vec::<u8>::new(), "second take is empty");
    }
    c.consume();
    assert_eq!(c.buffered(), 0, "placed body never re-enters buf");
}

/// The kTLS continuation's guard bounds the placed-body cursor by the *body*, not its buffer. A pooled buffer carries
/// whatever capacity its largest tenant left, and the bytes past `body_len` are a previous message's, so a cursor past
/// the body must be refused even inside the allocation.
#[test]
fn a_placed_cursor_is_bounded_by_the_body_not_its_buffer() {
    let mut c = Connection::new(ClientAddr::Unix { cred: None }, (), 8);
    c.set_frame(0, 100);
    // Reused pool storage, sized by a larger tenant.
    let want = c.arm_body_recv(Some((Vec::with_capacity(1024), Ticket::default())));
    assert_eq!(want, 100);
    assert!(c.recv_armed_within(), "the armed read is in bounds");
    // Partial progress up to the body's edge stays in bounds.
    c.advance_exact_partial(60);
    assert!(c.recv_armed_within(), "a mid-body continuation is fine");
    // A cursor past the body but not the buffer is exactly the range whose bytes belong to someone else's message.
    c.recv_want = 100;
    assert!(!c.recv_armed_within(), "the guard must bound by body_len, not capacity");
}

/// A ticket as a claim of 100 bytes the pool could not serve records.
#[cfg(feature = "net-server")]
const MISSED_100: Ticket = Ticket {
    licence: 100,
    bytes: 100,
};

/// A delivered placed body's ticket leaves custody *with* it, its licence for potting before the handler runs and
/// its bytes for the body to give back, rather than dying on the connection or leaking onto the next message's
/// claim.
#[cfg(feature = "net-server")]
#[test]
fn a_delivered_bodys_ticket_rides_out_with_the_body() {
    let mut c = Connection::new(ClientAddr::Unix { cred: None }, (), 8);
    c.set_frame(0, 100);
    let want = c.arm_body_recv(Some((Vec::with_capacity(100), MISSED_100)));
    let ptr = c.recv_ptr() as *mut u8;
    // SAFETY: recv_ptr points at `want` reserved-but-uninit bytes.
    unsafe { std::ptr::write_bytes(ptr, 0xCD, want) };
    assert_eq!(c.recv_result(want as i32), RecvOutcome::Complete);
    {
        let (_h, body, _addr, _state, ticket) = c.deliver_parts(None);
        assert_eq!(body.len(), 100, "the placed body delivered");
        assert_eq!(ticket, MISSED_100, "the ticket rode out with it");
    }
    c.set_frame(0, 0);
    let (_h, body, _addr, _state, ticket) = c.deliver_parts(None);
    assert_eq!(body.len(), 0, "the body was taken once");
    assert_eq!(ticket, Ticket::default(), "and the ticket with it");
}

/// Teardown hands a dying connection's body storage home with the held licences its claims recorded - an abandoned
/// mid-receive upload must not take a warm buffer out of the pool's loop.
#[cfg(feature = "net-server")]
#[test]
fn teardown_forfeits_body_storage_with_its_ticket() {
    let mut c = Connection::new(ClientAddr::Unix { cred: None }, (), 8);
    c.set_frame(0, 100);
    // Armed and mid-receive: the peer disconnects here.
    let _want = c.arm_body_recv(Some((Vec::with_capacity(100), MISSED_100)));
    let (placed, owned) = c.forfeit_body_storage();
    let (v, ticket) = placed.expect("the placed storage comes home");
    assert!(v.capacity() >= 100);
    assert_eq!(ticket, MISSED_100, "with the ticket its claim recorded");
    assert!(owned.is_none(), "nothing was promoted");
    let (placed, _) = c.forfeit_body_storage();
    assert!(placed.is_none(), "forfeit is take-once");
}

/// A redelivery must not be handed the buffer an in-flight `RECV` is writing into.
///
/// The pump can arm the next message's body while a handler is parked on `Response::Defer`, and a `Vec` taken from
/// under that recv is freed as its `Request` drops, with the kernel still writing into it.
#[test]
fn a_redelivery_does_not_steal_the_armed_body_buffer() {
    let mut c = Connection::new(ClientAddr::Unix { cred: None }, (), 8);
    let want = arm_a_body_recv(&mut c);
    let armed = c.recv_ptr();

    // The redelivery, as `deliver_one` stages it.
    c.set_frame(0, 0);
    {
        let (header, body, _addr, _state, _lic) = c.deliver_parts(None);
        assert!(header.is_empty(), "a redelivery carries no header");
        assert_eq!(body.len(), 0, "nor the next message's body");
    }
    assert_eq!(c.recv_ptr(), armed, "the armed recv still owns its destination");
    assert_eq!(c.recv_want, want, "and still targets the same count");
}

/// The leased twin of [`a_redelivery_does_not_steal_the_armed_body_buffer`]. Both delivery forms open the same way,
/// so a guard on one is a guard on neither.
#[cfg(all(feature = "net-server", feature = "uring-fs"))]
#[test]
fn a_leased_redelivery_does_not_steal_the_armed_body_buffer() {
    let mut c = Connection::new(ClientAddr::Unix { cred: None }, (), 8);
    arm_a_body_recv(&mut c);
    let armed = c.recv_ptr();

    c.set_frame(0, 0);
    {
        let (header, body, _addr, _state, _lease, _lic) = c.deliver_parts_leased(Some(0));
        assert!(header.is_empty(), "a redelivery carries no header");
        assert_eq!(body.len(), 0, "nor the next message's body");
    }
    assert_eq!(c.recv_ptr(), armed, "the armed recv still owns its destination");
}

/// Frame a 4-byte header plus 30 buffered body bytes and arm the rest of a 100-byte body into `body_buf`, as the
/// pump does for a pipelined message. Returns the count the recv targets.
#[cfg(test)]
fn arm_a_body_recv(c: &mut Connection<()>) -> usize {
    c.arm_recv(34, true);
    {
        // Play the kernel: the recv lands in reserved spare capacity.
        let ptr = c.recv_ptr() as *mut u8;
        // SAFETY: recv_ptr points at the 34 reserved-but-uninit bytes.
        unsafe { std::ptr::write_bytes(ptr, 0, 34) };
    }
    assert_eq!(c.recv_result(34), RecvOutcome::Complete);
    c.set_frame(4, 100);
    let want = c.arm_body_recv(None);
    assert_eq!(want, 70, "prefix of 30 already copied in");
    want
}

#[test]
fn body_only_delivery_hands_over_the_buffer() {
    // The http dance shape: the head was consumed with a previous delivery, the framer declared `Complete { 0,
    // body_len }`, and the whole extent is buffered. At or over the handoff threshold the accumulate buffer itself
    // moves out - ownership, not bytes.
    let mut c = Connection::new(ClientAddr::Unix { cred: None }, (), 8);
    c.arm_recv(100, true);
    let ptr = c.recv_ptr() as *mut u8;
    // SAFETY: recv_ptr points at the 100 reserved-but-uninit bytes.
    unsafe { std::ptr::write_bytes(ptr, 0xEE, 100) };
    assert_eq!(c.recv_result(100), RecvOutcome::Complete);
    c.set_frame(0, 100);
    let p0 = c.recv_buf.as_ptr() as usize;
    {
        let (header, mut body, _addr, _state, _lic) = c.deliver_parts(Some(64));
        assert!(header.is_empty());
        assert_eq!(body.len(), 100);
        let owned = body.take();
        assert_eq!(owned.as_ptr() as usize, p0, "the buffer itself moved");
        assert!(owned.iter().all(|&b| b == 0xEE));
    }
    c.consume();
    assert_eq!(c.buffered(), 0, "handoff composes with consume");

    // Below the threshold the delivery stays inline (borrowed).
    c.arm_recv(10, true);
    let ptr = c.recv_ptr() as *mut u8;
    // SAFETY: as above - 10 reserved bytes.
    unsafe { std::ptr::write_bytes(ptr, 0xAA, 10) };
    assert_eq!(c.recv_result(10), RecvOutcome::Complete);
    c.set_frame(0, 10);
    let p_small = c.recv_buf.as_ptr() as usize;
    {
        let (_h, mut body, _addr, _state, _lic) = c.deliver_parts(Some(64));
        assert_eq!(body.len(), 10);
        let copied = body.take();
        assert_ne!(
            copied.as_ptr() as usize,
            p_small,
            "small body copies out of the retained buffer"
        );
    }
    c.consume();
    assert_eq!(c.buffered(), 0);

    // A pipelined remainder blocks the handoff - the tail belongs to the next message.
    c.arm_recv(120, true);
    let ptr = c.recv_ptr() as *mut u8;
    // SAFETY: as above - 120 reserved bytes.
    unsafe { std::ptr::write_bytes(ptr, 0xBB, 120) };
    assert_eq!(c.recv_result(120), RecvOutcome::Complete);
    c.set_frame(0, 100);
    {
        let (_h, body, _addr, _state, _lic) = c.deliver_parts(Some(64));
        assert_eq!(body.len(), 100);
    }
    c.consume();
    assert_eq!(c.buffered(), 20, "remainder kept for the next message");
}

#[test]
fn deferred_request_gating() {
    let mut c = Connection::new(ClientAddr::Unix { cred: None }, (), 8);
    let a = c.begin_request();
    let b = c.begin_request();
    assert_ne!(a, b);
    c.open_deferred(a);
    c.open_deferred(b);
    assert!(c.take_deferred(b)); // out-of-order claim is fine
    assert!(!c.take_deferred(b)); // exactly once
    assert!(c.take_deferred(a));
    assert!(!c.take_deferred(a));
    // A request that was never opened (answered inline) can't be claimed.
    let inline = c.begin_request();
    assert!(!c.take_deferred(inline));
}

#[test]
fn user_data_round_trip() {
    // The match stops compiling when a variant is added, and the count below then proves `from_u8` decodes it.
    // `SpliceRecv`'s token is an `ASYNC_CANCEL` match key, so a gap in `from_u8` breaks mid-splice teardown.
    const OP_COUNT: usize = {
        match Op::Accept {
            Op::Accept
            | Op::RecvHeader
            | Op::RecvBody
            | Op::Send
            | Op::Close
            | Op::Wake
            | Op::Cancel
            | Op::LinkTimeout
            | Op::Deadline
            | Op::Cred
            | Op::Shutdown
            | Op::Peername
            | Op::FdInstall
            | Op::AcceptRetry
            | Op::HandshakeTimeout
            | Op::DetachInstall
            | Op::SpliceRecv
            | Op::SplicePoll
            | Op::RecvClock
            | Op::SpliceDeadline
            | Op::Connect
            | Op::RecvRetry
            | Op::ReceiptDeadline
            | Op::Maintain
            | Op::Handoff
            | Op::Handed => {}
        }
        26
    };
    // Every decodable op value: `from_u8` must invert the discriminant (a renumbered enum with a stale table shows
    // up here), and the decoded set must cover every variant.
    let ops: Vec<Op> = (0..=u8::MAX).filter_map(Op::from_u8).collect();
    assert_eq!(ops.len(), OP_COUNT, "Op::from_u8 table out of sync");
    for op in &ops {
        assert_eq!(Op::from_u8(*op as u8), Some(*op), "discriminant vs from_u8 drift");
    }
    for op in ops {
        for &(slot, generation) in &[(0u32, 0u32), (1, 7), (0x00ff_ffff, u32::MAX), (128, 3)] {
            let (o, s, g) = unpack(pack(op, slot, generation));
            assert_eq!(o, Some(op));
            assert_eq!(s, slot);
            assert_eq!(g, generation);
        }
    }
}

#[test]
fn accept_and_wake_sentinels_distinct() {
    let acc = pack(Op::Accept, 0, 0);
    let wake = pack(Op::Wake, 0, 0);
    assert_ne!(acc, wake);
    assert_eq!(unpack(acc).0, Some(Op::Accept));
    assert_eq!(unpack(wake).0, Some(Op::Wake));
}

#[test]
fn unknown_op_tag() {
    assert_eq!(unpack(0xff).0, None);
}

#[cfg(all(feature = "net-server", feature = "uring-fs"))]
#[test]
fn file_tail_diverts_reclaims_and_releases_in_order() {
    let mut c = Connection::new(ClientAddr::Unix { cred: None }, (), 8);
    let fd: std::os::fd::OwnedFd = std::fs::File::open("/dev/null").expect("open").into();
    let file = crate::uring_fs::File::new(crate::sync::Arc::new(fd));

    // Head first (the diversion is not yet on), then the tail.
    c.enqueue_reply_head(b"HEAD".to_vec());
    c.install_file_tail(file, 0, 20);
    assert!(c.tail_active());

    // A body holds at most two chunks at once; a third read waits for a flush. The buffers themselves come from the
    // reactor's ring, so what is capped here is this connection's share of it.
    assert!(c.tail_claim_chunk(), "first chunk");
    assert!(c.tail_claim_chunk(), "second chunk");
    assert!(!c.tail_claim_chunk(), "capped at two");
    c.tail_release_chunk(); // the second read never happened

    // Mid-tail enqueues divert - their bytes may not land between two chunks on the wire - but stay in the backlog
    // accounting.
    c.enqueue_push(b"PU".to_vec());
    c.enqueue_reply(b"RRR".to_vec());
    assert_eq!(c.queued_bytes(), 4 + 2 + 3);

    // The tail's own chunks go straight through.
    c.enqueue_file_chunk(SendBuf::from(vec![b'a'; 8]), false);
    assert_eq!(c.arm_send(), 4 + 8, "head + chunk, no diverted bytes");
    let p = c.advance_sent(12);
    assert_eq!((p.replies, p.pushes), (0, 0), "nothing retires before the last chunk");
    // The flush freed this connection's share, so a read can be armed again.
    assert!(c.tail_claim_chunk(), "the flush freed a chunk");

    // The final chunk retires the tail; the diverted PDUs follow in arrival order behind it.
    c.enqueue_file_chunk(SendBuf::from(vec![b'z'; 12]), true);
    c.finish_file_tail();
    assert!(!c.tail_active());
    assert_eq!(c.arm_send(), 12 + 2 + 3);
    assert_eq!(c.send_iovs[0].iov_len, 12);
    assert_eq!(c.send_iovs[1].iov_len, 2, "push held until the tail");
    assert_eq!(c.send_iovs[2].iov_len, 3, "deferred reply after it");
    let p = c.advance_sent(12 + 2 + 3);
    assert_eq!(
        (p.replies, p.pushes),
        (2, 1),
        "the tail's reply, the diverted reply, and the push"
    );
    assert_eq!(c.queued_bytes(), 0);
    assert!(!c.has_pending_send());
}

/// Dropping a stranded body returns the followers' bytes as well as their `outstanding` charges.
///
/// `enqueue` counts a diverted PDU into `queued_bytes` before the diversion holds it back, and nothing flushes to
/// credit it once the flush-close discards it.
#[cfg(all(feature = "net-server", feature = "uring-fs"))]
#[test]
fn dropping_a_stranded_body_returns_the_followers_bytes() {
    let dev_null = || {
        let fd: std::os::fd::OwnedFd = std::fs::File::open("/dev/null").expect("open").into();
        crate::uring_fs::File::new(crate::sync::Arc::new(fd))
    };
    let mut c = Connection::new(ClientAddr::Unix { cred: None }, (), 8);
    c.install_file_tail(dev_null(), 0, 20);
    // A push arrives mid-tail (released when the tail retires), then a second `ReplyFile`, then another push behind
    // *that* - which is what stays held once the tail hands on.
    c.enqueue_push(vec![b'p'; 7]);
    c.defer_file_reply(PendingFile {
        head: Vec::new(),
        file: dev_null(),
        offset: 0,
        len: 40,
        close: false,
    });
    c.enqueue_push(vec![b'q'; 5]);
    assert_eq!(c.queued_bytes(), 12, "diverted, and still counted");

    c.finish_file_tail();
    assert_eq!(c.queued_bytes(), 12, "the first push is on the queue");

    // Flush-closing: the deferred body and everything behind it go.
    c.drop_queued_file_reply();
    assert_eq!(c.queued_bytes(), 7, "the dropped follower's bytes were never returned");
}

/// A short read continues from the offset it REACHED. The declared length is a promise about the body's size, not
/// about how many bytes any one read returns, so the tail's cursor tracks the count actually delivered. Advance by
/// the length asked for instead and the unread bytes are skipped, with the next read's bytes framed in their place.
#[cfg(all(feature = "net-server", feature = "uring-fs"))]
#[test]
fn a_short_read_continues_from_the_offset_it_reached() {
    let mut c = Connection::new(ClientAddr::Unix { cred: None }, (), 8);
    let fd: std::os::fd::OwnedFd = std::fs::File::open("/dev/null").expect("open").into();
    let file = crate::uring_fs::File::new(crate::sync::Arc::new(fd));
    // A range of 300 bytes starting 1000 in.
    c.install_file_tail(file, 1000, 300);

    // 200 bytes came back where a whole chunk was asked for.
    assert!(!c.advance_file_tail(SendBuf::from(vec![b'a'; 200])), "100 still owed");
    {
        let t = c.file_tail.as_ref().expect("still streaming");
        assert_eq!(t.next_offset, 1200, "advanced by the count read");
        assert_eq!(t.unread, 100, "the rest is still owed");
    }

    // The remainder retires the tail exactly once.
    assert!(
        c.advance_file_tail(SendBuf::from(vec![b'b'; 100])),
        "the declared length"
    );
    assert!(!c.tail_active(), "the last chunk retires the tail");
    assert_eq!(c.queued_bytes(), 300, "both chunks queued, nothing else");
}

/// A body's share of the ring comes back as it flushes, so each body on a connection starts from the same share however
/// many ran before it.
#[cfg(all(feature = "net-server", feature = "uring-fs"))]
#[test]
fn chunk_buffers_outlive_the_body_that_minted_them() {
    let mut c = Connection::new(ClientAddr::Unix { cred: None }, (), 8);
    let file = || {
        let fd: std::os::fd::OwnedFd = std::fs::File::open("/dev/null").expect("open").into();
        crate::uring_fs::File::new(crate::sync::Arc::new(fd))
    };
    let serve = |c: &mut Connection<()>, buf: SendBuf| {
        c.enqueue_file_chunk(buf, true);
        c.finish_file_tail();
        assert_eq!(c.arm_send(), 4);
        let _ = c.advance_sent(4);
    };

    // A body claims a share, and the flush gives it back - so the next body starts from the same place however many
    // ran before it.
    for round in 0..3 {
        c.install_file_tail(file(), 0, 4);
        assert!(c.tail_claim_chunk(), "round {round}: claimed");
        assert!(c.tail_claim_chunk(), "round {round}: and again");
        assert!(!c.tail_claim_chunk(), "round {round}: capped at two");
        c.tail_release_chunk();
        serve(&mut c, SendBuf::from(b"aaaa".to_vec()));
        assert_eq!(c.chunk_out, 0, "round {round}: the flush released the share");
    }
}

/// While a leased write holds the claim, every other way the buffer could reach the pool must refuse: release,
/// forfeit and promote are the three, and any one of them re-posting the id puts the kernel free to select it for
/// another connection's recv while the write's DMA still reads it.
#[cfg(all(feature = "net-server", feature = "uring-fs"))]
#[test]
fn a_leased_claim_is_refused_to_every_path_but_the_write() {
    let mut rb = RecvBuf::default();
    rb.set_pooled();
    let buf = Box::leak(vec![0u8; 64].into_boxed_slice());
    rb.install(RecvClaim {
        bid: 3,
        ptr: buf.as_mut_ptr(),
        cap: 64,
    });
    rb.write_lease(64).expect("a claim leases").taken.set(true);
    assert!(rb.release().0.is_none(), "release while leased");
    assert!(rb.forfeit().is_none(), "forfeit while leased");
    // Forfeit dropped the claim without surrendering the bid: the op's completion is the one release left, which is
    // the point.
}

/// The lease is bounded to the delivered message, never the buffer.
///
/// A recycled pool buffer is not zeroed, so bytes past the message are a previous holder's, and `pwritev2_from` reads
/// this cap as the line between writing straight from the ring and falling to the copy path.
#[cfg(all(feature = "net-server", feature = "uring-fs"))]
#[test]
fn a_lease_never_reaches_past_the_delivered_message() {
    let mut rb = RecvBuf::default();
    rb.set_pooled();
    let buf = Box::leak(vec![0u8; 256].into_boxed_slice());
    rb.install(RecvClaim {
        bid: 4,
        ptr: buf.as_mut_ptr(),
        cap: 256,
    });
    let lease = rb.write_lease(96).expect("a claim leases");
    assert_eq!(lease.cap, 96, "the lease stops at the delivered message");
    let whole = rb.write_lease(4096).expect("a claim leases");
    assert_eq!(whole.cap, 256, "and never reaches past the buffer either");
}

/// Promote under a lease is declared unreachable - no recv is armed between the write's submit and the delivery's
/// consume - so its guard fails closed loudly rather than moving bytes out from under the DMA.
///
/// Debug builds only: the `debug_assert` is what panics, and in a release build `should_panic` has nothing to
/// catch. `promote_under_a_lease_fails_closed_without_asserts` covers the `return None` that ships beside it.
#[cfg(all(debug_assertions, feature = "net-server", feature = "uring-fs"))]
#[test]
#[should_panic(expected = "promote under a leased write")]
fn promote_under_a_lease_fails_closed() {
    let mut rb = RecvBuf::default();
    rb.set_pooled();
    let buf = Box::leak(vec![0u8; 64].into_boxed_slice());
    rb.install(RecvClaim {
        bid: 4,
        ptr: buf.as_mut_ptr(),
        cap: 64,
    });
    rb.write_lease(64).expect("a claim leases").taken.set(true);
    let _ = rb.promote_for(0, 1 << 20, || None);
}

/// The shipping half of the same guard: `None`, and the claim left where it was.
///
/// Returning the claim here would hand the pool a bid whose buffer the write's DMA is still reading, and clearing
/// `claim` would strand it - `release` is the only place a buffer is reissued or freed.
#[cfg(all(not(debug_assertions), feature = "net-server", feature = "uring-fs"))]
#[test]
fn promote_under_a_lease_fails_closed_without_asserts() {
    let mut rb = RecvBuf::default();
    rb.set_pooled();
    let buf = Box::leak(vec![0u8; 64].into_boxed_slice());
    rb.install(RecvClaim {
        bid: 4,
        ptr: buf.as_mut_ptr(),
        cap: 64,
    });
    rb.write_lease(64).expect("a claim leases").taken.set(true);
    assert!(
        rb.promote_for(0, 1 << 20, || None).is_none(),
        "promote under a lease must not surrender the claim"
    );
    assert_eq!(
        rb.claim.map(|c| c.bid),
        Some(4),
        "and must leave it installed for the op's completion to release"
    );
}

/// A consume that finds the lease flag set but the claim gone must not dereference it. The flag and the claim are
/// set and cleared together, so this is declared unreachable - and the arm that ships is the one no debug test can
/// reach, because the assert fires first.
///
/// `draining_a_lease_with_no_claim_fails_closed_without_asserts` covers the release half.
#[cfg(all(debug_assertions, feature = "net-server", feature = "uring-fs"))]
#[test]
#[should_panic(expected = "leased with no claim")]
fn draining_a_lease_with_no_claim_fails_closed() {
    let mut rb = RecvBuf::default();
    rb.set_pooled();
    rb.write_leased.set(true);
    rb.set_filled(8);
    rb.drain_front(4);
}

/// The shipping half: clear the flag and drain nothing.
///
/// Falling through would take the `unsafe` copy below it with no claim to bound it. Leaving the flag set is nearly
/// as bad - every later consume on the connection would re-enter this arm and never drain, so the buffer would fill
/// and the connection stall. Asserted on state, which is what the release build actually has.
#[cfg(all(not(debug_assertions), feature = "net-server", feature = "uring-fs"))]
#[test]
fn draining_a_lease_with_no_claim_fails_closed_without_asserts() {
    let mut rb = RecvBuf::default();
    rb.set_pooled();
    rb.write_leased.set(true);
    rb.set_filled(8);
    rb.drain_front(4);
    assert!(!rb.write_leased.get(), "the lease flag must be cleared");
    assert_eq!(rb.len(), 8, "and nothing drained from a buffer it lacks");
}

/// A delivery must not hand a lent pool buffer back while a recv is still writing into it.
///
/// A redelivery reaches `release_recv_buffer` from `drain_injections`, past the `!recving` test the wire path relies
/// on, and its zeroed frame drains nothing. `filled == 0` under an armed read is ordinary after a spliced body's
/// consume or a partial read, and released there the descriptor is reposted for another connection with this one's DMA
/// still aimed at it.
#[cfg(feature = "net-server")]
#[test]
fn a_delivery_does_not_release_a_buffer_under_an_armed_recv() {
    let mut c = Connection::new(ClientAddr::Unix { cred: None }, (), 8);
    c.set_recv_pooled();
    let buf = Box::leak(vec![0u8; 64].into_boxed_slice());
    c.install_recv_buf(RecvClaim {
        bid: 7,
        ptr: buf.as_mut_ptr(),
        cap: 64,
    });
    // The state a spliced body's consume leaves: claim held, nothing in it. The pump then arms the next read into
    // that same buffer.
    assert_eq!(c.buffered(), 0);
    assert_eq!(c.arm_recv(32, false), 32);
    c.recving = true;
    let ptr_armed = c.recv_ptr();
    assert_eq!(
        ptr_armed,
        buf.as_mut_ptr() as u64,
        "the kernel was handed the claim's own storage"
    );

    let (claim, surplus) = c.release_recv_buf();
    assert!(
        claim.is_none() && surplus.is_none(),
        "the buffer went back to the pool under a live recv"
    );

    // The control: once the recv completes it is released as before, so the guard is a `recving` rule and not a
    // blanket refusal.
    c.recving = false;
    let (claim, _) = c.release_recv_buf();
    assert_eq!(
        claim.map(|c| c.bid),
        Some(7),
        "a quiet connection still gives its buffer up"
    );
}

/// A promote that copies nothing still has to leave the connection reading into the storage it just installed.
///
/// `submit_recv` decides the buffer select before the promote hands the claim back, so the SQE carries no
/// `IOSQE_BUFFER_SELECT`. If `needs_buffer` then answered `true`, `write_ptr` would hand the kernel address 0 and the
/// connection would die `RecvError(EFAULT)`. Reachable after a spliced body's consume, which keeps the claim.
#[cfg(feature = "net-server")]
#[test]
fn a_promote_that_copies_nothing_still_has_a_destination() {
    let mut rb = RecvBuf::default();
    rb.set_pooled();
    let buf = Box::leak(vec![0u8; 64].into_boxed_slice());
    rb.install(RecvClaim {
        bid: 5,
        ptr: buf.as_mut_ptr(),
        cap: 64,
    });
    // A spliced body's consume: the claim stays, nothing is in it.
    assert_eq!(rb.len(), 0, "the header was consumed");
    assert!(
        !rb.needs_buffer(),
        "a held claim needs no buffer - the select decision the \
             submit takes before it promotes"
    );

    let want = 4096;
    let claim = rb.promote_for(0, want, || None).expect("the read outgrows the claim");
    assert_eq!(claim.bid, 5, "the buffer goes back to the pool");
    assert!(
        !rb.needs_buffer(),
        "the promoted storage is this read's destination, and the \
             SQE has already been decided to carry no buffer select"
    );
    assert_eq!(rb.reserve_at(0, want), want, "the whole read is granted");
    assert!(!rb.write_ptr(0).is_null(), "and it has somewhere to land");
    assert!(rb.armed_within(0, want), "inside what the promote sized");
}

/// A ticket outlives the `pooled` flag that let it be taken, so the three sites that move `owned` out all carry it.
///
/// `promote_for` writes `owned_ticket` but does not clear `pooled`, and `set_owned` clears it one-way, so `take_owned`
/// can hand promoted storage to the handler. A dropped licence is demand the pool met and never counted, and dropped
/// bytes stay on the count of held storage for good.
#[cfg(feature = "net-server")]
#[test]
fn every_path_that_moves_owned_out_carries_its_ticket() {
    const MISSED_4096: Ticket = Ticket {
        licence: 4096,
        bytes: 4096,
    };
    // Promote off a pool buffer: the seed's licence lands on the connection and rides `owned` from here on.
    let seed = |rb: &mut RecvBuf| {
        rb.set_pooled();
        let buf = Box::leak(vec![b'x'; 64].into_boxed_slice());
        rb.install(RecvClaim {
            bid: 1,
            ptr: buf.as_mut_ptr(),
            cap: 64,
        });
        rb.set_filled(8);
        rb.promote_for(8, 1 << 20, || Some((Vec::new(), MISSED_4096)))
            .expect("a promote past the claim's cap");
        assert_eq!(rb.owned_ticket, MISSED_4096, "the seed's is held");
    };

    // The delivery handoff, once the pool has given up on this connection (`set_owned`) - the composition the
    // promote alone cannot reach.
    let mut handed = RecvBuf::default();
    seed(&mut handed);
    handed.set_owned();
    let (v, ticket) = handed.take_owned().expect("owned and unpooled");
    assert_eq!(ticket, MISSED_4096, "the handoff dropped the ticket");
    assert_eq!(handed.owned_ticket, Ticket::default(), "none behind");
    assert_eq!(v.len(), 8, "with the accumulated bytes");

    // Teardown, with the storage already handed off: a licence with no capacity under it must still be surrendered,
    // because `give_held` pots it before it looks at the capacity and this is the last chance to.
    let mut bare = RecvBuf::default();
    seed(&mut bare);
    bare.owned = Vec::new();
    let (_, ticket) = bare.forfeit_owned().expect("a ticket with no Vec");
    assert_eq!(ticket, MISSED_4096, "teardown dropped the ticket");

    // And the ordinary release, for the denominator - which the delivery reaches once the message it accumulated is
    // consumed.
    let mut released = RecvBuf::default();
    seed(&mut released);
    released.truncate(0);
    let (_, surplus) = released.release();
    assert_eq!(
        surplus.expect("promoted storage comes home").1,
        MISSED_4096,
        "release dropped the ticket"
    );
}

/// `armed_within` is the predicate both continuation guards key on, and what is on the other side of it is the
/// kernel writing past the allocation.
///
/// The claim arm bounds on the buffer's `cap`, the owned arm on the length `reserve_at` grew, and the sum is
/// computed with `checked_add` because a wrapped end compares as though it were in range.
#[test]
fn an_arm_reaching_past_its_buffer_is_outside_it() {
    let mut owned = RecvBuf::default();
    owned.reserve_at(0, 64);
    assert!(owned.armed_within(0, 64), "the whole buffer is inside");
    assert!(owned.armed_within(32, 32), "and so is an offset arm");
    assert!(!owned.armed_within(32, 33), "one past the end is outside");
    assert!(
        !owned.armed_within(usize::MAX, 1),
        "and a wrapping sum is outside, not back at the start"
    );

    let mut pooled = RecvBuf::default();
    pooled.set_pooled();
    let buf = Box::leak(vec![0u8; 64].into_boxed_slice());
    pooled.install(RecvClaim {
        bid: 7,
        ptr: buf.as_mut_ptr(),
        cap: 64,
    });
    assert!(pooled.armed_within(0, 64), "a claim bounds on its cap");
    assert!(!pooled.armed_within(1, 64), "not on the storage behind it");
}

/// Why `resubmit_exact_recv`'s guard has no reachable arm: this is what moves the cursor between the arm and the
/// re-arm, and it moves `recv_at` up by exactly what it takes off `recv_want`, so the end of the armed range never
/// moves. An arm that was inside its buffer is still inside it, and losing that pairing is what would make the
/// guard bite.
#[test]
fn advancing_an_exact_partial_leaves_the_armed_end_where_it_was() {
    let mut c = Connection::new(ClientAddr::Unix { cred: None }, (), 8);
    c.recv_at = 100;
    c.recv_want = 400;
    let end = c.recv_at + c.recv_want;
    for n in [0, 1, 137, 262] {
        c.advance_exact_partial(n);
        assert_eq!(c.recv_at + c.recv_want, end, "the armed end moved");
    }
    assert_eq!(c.recv_want, 0, "and the range is exhausted, not negative");
}

/// Progress past the armed want is a miscount, and in a release build the clamp is the whole guard: without it
/// `recv_want` wraps and the re-arm asks the kernel for an address-space-sized range.
#[cfg(not(debug_assertions))]
#[test]
fn advancing_past_the_armed_want_clamps_without_asserts() {
    let mut c = Connection::new(ClientAddr::Unix { cred: None }, (), 8);
    c.recv_at = 100;
    c.recv_want = 400;
    c.advance_exact_partial(4096);
    assert_eq!(c.recv_want, 0, "a wrap would read as ~usize::MAX");
    assert_eq!(c.recv_at, 500, "and the cursor stops at the armed end");
}

/// The debug half of the same guard, which is what surfaces the bug.
#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "progress past the armed want")]
fn advancing_past_the_armed_want_panics() {
    let mut c = Connection::new(ClientAddr::Unix { cred: None }, (), 8);
    c.recv_at = 100;
    c.recv_want = 400;
    c.advance_exact_partial(4096);
}

/// A chunk can still be flushing when its tail retires. Its ring buffer has to come back anyway: conditioning the
/// release on a tail being installed strands the buffer in the pool forever, where it can be neither reissued nor
/// freed.
#[cfg(all(feature = "net-server", feature = "uring-fs"))]
#[test]
fn a_chunk_outliving_its_tail_still_frees_its_buffer() {
    let mut c = Connection::new(ClientAddr::Unix { cred: None }, (), 8);
    let fd: std::os::fd::OwnedFd = std::fs::File::open("/dev/null").expect("open").into();
    let file = crate::uring_fs::File::new(crate::sync::Arc::new(fd));
    c.install_file_tail(file, 0, 4);
    assert!(c.tail_claim_chunk());
    // SAFETY: a test buffer that outlives the segment.
    let buf = Box::leak(Box::new([b'a'; 4]));
    let seg = unsafe { SendBuf::pooled(buf.as_mut_ptr(), 4, 7) };
    c.enqueue_file_chunk(seg, true);
    // The tail retires with its chunk still queued, and nothing follows it - so at the flush there is no tail to
    // hand anything to.
    c.finish_file_tail();
    assert!(!c.tail_active(), "no successor");
    assert_eq!(c.arm_send(), 4);
    let p = c.advance_sent(4);
    assert_eq!(c.chunk_out, 0, "the share came back");
    assert_eq!(p.freed, 1, "and the buffer id rode out to the pool");
    assert_eq!(p.freed_bids[0], 7, "the one the segment held");
}

/// A redelivery owns no bytes, so it must not be handed a write lease.
///
/// Its frame is zeroed, and its empty `Body` sits at the claim base, which `pwritev2_from`'s bounds test admits. A
/// zero-length write would then take the claim and release it to the pool from its completion while the read-ahead recv
/// is still armed into that buffer. `take_body_handoff` excludes the same case with its `body_len > 0`.
#[cfg(all(feature = "net-server", feature = "uring-fs"))]
#[test]
fn a_redelivery_is_not_handed_a_write_lease() {
    let mut c = Connection::new(ClientAddr::Unix { cred: None }, (), 8);
    c.set_recv_pooled();
    let buf = Box::leak(vec![0u8; 64].into_boxed_slice());
    let base = buf.as_mut_ptr();
    c.install_recv_buf(RecvClaim {
        bid: 7,
        ptr: base,
        cap: 64,
    });

    // A claim held, nothing in it, the next read armed into it.
    assert_eq!(c.arm_recv(32, false), 32);
    c.recving = true;
    assert_eq!(c.recv_ptr(), base as u64, "the kernel has the claim");

    // `deliver_one(Redelivery)` zeroes the frame before delivering.
    c.set_frame(0, 0);
    {
        let (header, body, _peer, _state, lease, _lic) = c.deliver_parts_leased(Some(0));
        assert!(header.is_empty() && body.is_empty());
        assert!(lease.is_none(), "a zeroed frame has no bytes to lease the claim for");
    }
    c.consume();
    assert!(
        c.recv_buf.claim.is_some(),
        "the claim stays where the armed recv is writing"
    );

    // The control: a real wire frame over the same buffer still leases.
    c.recv_buf.set_filled(8);
    c.set_frame(4, 4);
    let (_h, _b, _p, _s, lease, _l) = c.deliver_parts_leased(Some(0));
    let lease = lease.expect("a wire delivery still gets its lease");
    assert_eq!((lease.bid, lease.cap), (7, 8), "bounded to the message");
}

/// The mark that a message was let in at the cap ends as the message is consumed. A redelivery consumes an empty frame
/// while the next message may be under way already, and leaves the mark alone.
#[cfg(feature = "net-server")]
#[test]
fn a_mark_ends_with_its_message_and_not_at_a_redelivery() {
    let mut c = Connection::new(ClientAddr::Unix { cred: None }, (), 2);
    c.let_in = true;
    c.set_frame(0, 0);
    c.consume();
    assert!(c.let_in, "a redelivery ended the next message's mark");
    c.set_frame(4, 8);
    c.consume();
    assert!(!c.let_in, "the mark outlived its message");
}
