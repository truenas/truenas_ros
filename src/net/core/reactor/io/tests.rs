use super::*;
#[cfg(feature = "net-server")]
use crate::net::ClientAddr;
#[cfg(feature = "net-server")]
use crate::net::core::bodypool::HeldBack;
#[cfg(feature = "net-server")]
use crate::net::core::config::CoreConfig;
#[cfg(feature = "net-server")]
use crate::net::core::conn::Connection;
#[cfg(feature = "net-server")]
use crate::net::core::reactor::KernelPads;
#[cfg(feature = "net-server")]
use crate::uring::sys::KernelTimespec;
#[cfg(feature = "net-server")]
use std::time::Duration;

/// A reactor over a small real ring, with one connection installed at slot 0 generation 0. `None` where io_uring is
/// unavailable.
///
/// Nothing is ever submitted: the SQEs the timer arms stage into a ring far larger than the handful used, and the
/// completions below are synthesized - which is the only way to fix the interleaving the property is about.
#[cfg(feature = "net-server")]
fn reactor_with_one_conn(max_receipt_time: Option<Duration>, request_timeout: Option<Duration>) -> Option<Reactor<()>> {
    reactor_with_force_async(max_receipt_time, request_timeout, ForceAsync::empty())
}

/// [`reactor_with_one_conn`] with the `IOSQE_ASYNC` classes named.
#[cfg(feature = "net-server")]
fn reactor_with_force_async(
    max_receipt_time: Option<Duration>,
    request_timeout: Option<Duration>,
    force_async: ForceAsync,
) -> Option<Reactor<()>> {
    let tcp = ClientAddr::Inet("127.0.0.1:1".parse::<std::net::SocketAddr>().unwrap());
    reactor_with_peer(max_receipt_time, request_timeout, force_async, tcp, 1)
}

/// [`reactor_with_force_async`] with the connection's peer and gather width named.
#[cfg(feature = "net-server")]
fn reactor_with_peer(
    max_receipt_time: Option<Duration>,
    request_timeout: Option<Duration>,
    force_async: ForceAsync,
    peer: ClientAddr,
    max_send_coalesce: usize,
) -> Option<Reactor<()>> {
    let engine = match crate::uring::engine::Engine::new(64, 8) {
        Ok(e) => e,
        Err(crate::Error::Errno(e)) if crate::uring::setup_unavailable(e) => {
            return None;
        }
        Err(e) => panic!("engine: {e}"),
    };
    let cfg = CoreConfig {
        max_request_bytes: MAX,
        body_placement_threshold: None,
        max_send_coalesce: 1,
        max_send_backlog: 8,
        max_in_flight_requests: 4,
        idle_timeout: None,
        request_timeout,
        max_receipt_time,
        receipt_window_bytes: crate::net::server::ServerConfig::default().receipt_window_bytes,
        send_timeout: None,
        tls_handshake_timeout: None,
        recv_shortage_retry: None,
        force_async,
        zc_threshold: usize::MAX,
        zc_max_pinned: 0,
        zc_linger: std::time::Duration::ZERO,
    };
    let pads = Box::new(KernelPads {
        deadline: KernelTimespec::default(),
        accept_retry: KernelTimespec::default(),
        idle_timeout: KernelTimespec::default(),
        send_timeout: KernelTimespec::default(),
        request_timeout: KernelTimespec::default(),
        max_receipt_time: KernelTimespec::default(),
        tls_handshake: KernelTimespec::default(),
        recv_retry: KernelTimespec::default(),
        maintain: KernelTimespec::default(),
    });
    let mut r: Reactor<()> = Reactor::from_parts(engine, 4, cfg, pads);
    r.table.install(0, Connection::new(peer, (), max_send_coalesce));
    Some(r)
}

/// A recv that finds the pool dry below its limit grows it and reads again, counting the shortage, rather than
/// parking or falling back to an owned buffer.
#[cfg(feature = "net-server")]
#[test]
fn a_recv_that_finds_the_pool_dry_grows_it_and_reads_again() {
    let Some(mut r) = reactor_with_one_conn(None, None) else {
        return;
    };
    const BUF: usize = 64;
    const ENTRIES: u16 = 64;
    let mut pool = crate::uring::bufring::BufPool::new(
        r.engine.ring.raw_fd(),
        crate::uring::bufring::BGID_RECV,
        BUF,
        ENTRIES,
        crate::uring::bufring::PoolSizing::UNSIZED,
    )
    .expect("registers");
    let dry = pool.allocated();
    for bid in 0..dry {
        assert!(pool.lend_as_the_kernel(bid), "lend {bid}");
    }
    r.recv_bufs = Some(pool);
    r.table.conn_mut(0).set_recv_pooled();

    assert!(r.recv_buffer_shortage(0, 0).expect("shortage"), "reads again");
    let grown = r.recv_bufs.as_ref().expect("pool").allocated();
    assert!(grown > dry, "the pool grew: {grown} from {dry}");
    assert!(
        r.table.conn(0).recv_needs_buffer(),
        "the connection still draws on the pool"
    );
    assert_eq!(r.stats.buf_shortages.load(std::sync::atomic::Ordering::Relaxed), 1);
}

/// A placed body read waits behind any read or turn already held back, even with the ring under its cap, so that
/// both go on in the order they came. A second look keeps the one place it has, and the read whose turn it is goes
/// on.
#[cfg(feature = "net-server")]
#[test]
fn a_new_body_read_waits_behind_held_ones() {
    let Some(mut r) = reactor_with_one_conn(None, None) else {
        return; // io_uring unavailable
    };
    let peer = ClientAddr::Inet("127.0.0.1:2".parse::<std::net::SocketAddr>().unwrap());
    r.table.install(1, Connection::new(peer, (), 1));
    let pool = std::rc::Rc::new(std::cell::RefCell::new(crate::net::core::bodypool::BodyPool::new(
        1 << 20,
        Some(100),
    )));
    r.body_pool = Some(std::rc::Rc::clone(&pool));
    let (g0, g1) = (r.table.generation(0), r.table.generation(1));

    pool.borrow_mut().hold(100);
    assert!(r.hold_back(0, g0 as u32).unwrap(), "at the cap it waits");
    pool.borrow_mut().unhold(100);
    pool.borrow_mut().hold_back(HeldBack::Turn);
    assert!(
        r.hold_back(1, g1 as u32).unwrap(),
        "under the cap, a newcomer still waits behind them"
    );
    assert!(r.hold_back(0, g0 as u32).unwrap(), "still waiting");
    let read = |slot, generation| HeldBack::Read { slot, generation };
    assert_eq!(
        pool.borrow().held_back(),
        [read(0, g0), HeldBack::Turn, read(1, g1)],
        "once each, in the order they came"
    );
    r.held_turn = Some(0);
    assert!(!r.hold_back(0, g0 as u32).unwrap(), "its turn goes on");
    assert_eq!(r.held_turn, None, "and only the once");
}

/// A budget retired and replaced inside one dispatch: the predecessor's expiry must not be charged to the
/// successor.
///
/// The retire only stages its cancel, and the re-arm runs before the reap loop reaches the old timer's `-ETIME`, which
/// carries the same `user_data`, so the flag alone cannot tell the two expiries apart.
#[cfg(feature = "net-server")]
#[test]
fn a_retired_receipt_budget_is_not_charged_to_its_successor() {
    let Some(mut r) = reactor_with_one_conn(Some(Duration::from_secs(30)), None) else {
        return;
    };
    r.arm_receipt_deadline(0, 0).expect("arm");
    r.cancel_receipt_deadline(0, 0).expect("retire");
    r.arm_receipt_deadline(0, 0).expect("the successor's budget");
    assert!(r.table.conn(0).receipt_deadline_armed, "armed again");

    // The retired timer's expiry, reaped after the re-arm.
    r.on_receipt_deadline(0, 0, -libc::ETIME).expect("stale expiry");
    assert!(
        r.table.slot_matches_cqe(0, 0),
        "a peer that finished inside its budget was closed"
    );
    assert!(
        r.table.conn(0).receipt_deadline_armed,
        "the successor's budget was spent by its predecessor"
    );

    // And the successor's own expiry still bites: the flag it armed is spent, and the connection is winding down.
    r.on_receipt_deadline(0, 0, -libc::ETIME).expect("live expiry");
    assert!(
        !r.table.conn(0).receipt_deadline_armed && r.table.conn(0).closing,
        "the live budget stopped reclaiming a stalled peer"
    );
}

/// The same interleaving on the kTLS splice watchdog, where it is worse: `splice_watermark` equals
/// `splice_remaining` at every arm, so a stale expiry reaching the live path takes `Next::Cancel` and cancels the
/// *successor's* splice - a healthy multi-GB transfer killed at its first record, and the watchdog disarmed behind
/// it.
#[cfg(feature = "net-server")]
#[test]
fn a_retired_splice_watchdog_does_not_cancel_the_next_body() {
    let Some(mut r) = reactor_with_one_conn(None, Some(Duration::from_secs(30))) else {
        return;
    };
    {
        let conn = r.table.conn_mut(0);
        conn.splicing = true;
        conn.splice_remaining = 1 << 20;
    }
    r.arm_splice_deadline(0, 0).expect("arm");
    r.cancel_splice_deadline(0, 0).expect("body done");
    // The next body on the same connection.
    r.table.conn_mut(0).splice_remaining = 1 << 20;
    r.arm_splice_deadline(0, 0).expect("the successor's watchdog");
    assert!(r.table.conn(0).splice_deadline_armed, "armed again");

    r.on_splice_deadline(0, 0, -libc::ETIME).expect("stale expiry");
    assert!(
        r.table.conn(0).splice_deadline_armed,
        "the successor's watchdog was disarmed by its predecessor"
    );
}

const MAX: usize = 1024 * 1024;

#[test]
fn frame_step_needs_and_caps() {
    // A zero-byte need is malformed.
    assert_eq!(
        frame_step(Framing::Need(0), 0, MAX, None),
        FrameStep::Close(CloseReason::Malformed)
    );
    // A normal need reads exactly that many header bytes.
    assert_eq!(
        frame_step(Framing::Need(4), 0, MAX, None),
        FrameStep::ReadHeader {
            want: 4,
            exact: true,
            in_message: false
        }
    );
    // A need whose post-read total exceeds the cap closes TooLarge...
    assert_eq!(
        frame_step(Framing::Need(MAX), 1, MAX, None),
        FrameStep::Close(CloseReason::TooLarge)
    );
    // ...including one that would overflow usize.
    assert_eq!(
        frame_step(Framing::Need(usize::MAX), 1, MAX, None),
        FrameStep::Close(CloseReason::TooLarge)
    );
    // More is always a chunk read.
    assert_eq!(
        frame_step(Framing::More, 7, MAX, None),
        FrameStep::ReadHeader {
            want: RECV_CHUNK,
            exact: false,
            in_message: false
        }
    );
    // The same read, flagged as an active transfer. That flag is the whole of the difference, and `submit_recv`
    // reads it to pick the clock and arm the receipt budget.
    assert_eq!(
        frame_step(Framing::MoreInMessage, 0, MAX, None),
        FrameStep::ReadHeader {
            want: RECV_CHUNK,
            exact: false,
            in_message: true
        }
    );
    // An exact read from an empty buffer is ambiguous on its own, the next message's first read for a length-prefix
    // framer or a continuation for one that consumed its head. Only the framer knows, and a `Need` that should have
    // been `NeedInMessage` arms no receipt budget and takes the idle clock.
    assert_eq!(
        frame_step(Framing::Need(64), 0, MAX, None),
        FrameStep::ReadHeader {
            want: 64,
            exact: true,
            in_message: false
        }
    );
    assert_eq!(
        frame_step(Framing::NeedInMessage(64), 0, MAX, None),
        FrameStep::ReadHeader {
            want: 64,
            exact: true,
            in_message: true
        }
    );
    // The twin inherits every guard, not just the flag.
    assert_eq!(
        frame_step(Framing::NeedInMessage(0), 0, MAX, None),
        FrameStep::Close(CloseReason::Malformed)
    );
    assert_eq!(
        frame_step(Framing::NeedInMessage(usize::MAX), 8, MAX, None),
        FrameStep::Close(CloseReason::TooLarge)
    );
    assert_eq!(
        frame_step(Framing::NeedInMessage(MAX), 1, MAX, None),
        FrameStep::Close(CloseReason::TooLarge)
    );
    // Invalid closes.
    assert_eq!(
        frame_step(Framing::Invalid, 0, MAX, None),
        FrameStep::Close(CloseReason::Malformed)
    );
}

#[test]
fn frame_step_complete_paths() {
    // Overflowing header+body is rejected before any slice.
    assert_eq!(
        frame_step(
            Framing::Complete {
                header_len: 8,
                body_len: usize::MAX
            },
            0,
            MAX,
            None
        ),
        FrameStep::Close(CloseReason::TooLarge)
    );
    // A zero-length message is malformed.
    assert_eq!(
        frame_step(
            Framing::Complete {
                header_len: 0,
                body_len: 0
            },
            0,
            MAX,
            None
        ),
        FrameStep::Close(CloseReason::Malformed)
    );
    // Over the cap closes.
    assert_eq!(
        frame_step(
            Framing::Complete {
                header_len: 4,
                body_len: MAX
            },
            0,
            MAX,
            None
        ),
        FrameStep::Close(CloseReason::TooLarge)
    );
    // Fully buffered -> deliver with the split.
    assert_eq!(
        frame_step(
            Framing::Complete {
                header_len: 4,
                body_len: 16
            },
            20,
            MAX,
            None
        ),
        FrameStep::Deliver {
            header_len: 4,
            body_len: 16
        }
    );
    // Body not yet buffered -> read the remainder; no placement (small).
    assert_eq!(
        frame_step(
            Framing::Complete {
                header_len: 4,
                body_len: 16
            },
            4,
            MAX,
            Some(64 * 1024)
        ),
        FrameStep::ReadBody {
            want: 16,
            header_len: 4,
            body_len: 16,
            place: false
        }
    );
    // A large body at/over the threshold is placed (header fully buffered).
    assert_eq!(
        frame_step(
            Framing::Complete {
                header_len: 4,
                body_len: 128 * 1024
            },
            4,
            MAX,
            Some(64 * 1024)
        ),
        FrameStep::ReadBody {
            want: 128 * 1024,
            header_len: 4,
            body_len: 128 * 1024,
            place: true
        }
    );
}

/// `ForceAsync` stamps `IOSQE_ASYNC` on the class it names and on no other. The wrong-class arm is the control: a
/// reactor configured for `RECV` submits the same send, so an assertion that only checked for the bit's presence
/// would pass there too and prove nothing about which knob reached the SQE.
#[cfg(feature = "net-server")]
#[test]
fn a_send_carries_iosqe_async_only_for_its_own_class() {
    let staged_send_flags = |classes: ForceAsync| -> Option<u8> {
        let mut r = reactor_with_force_async(None, None, classes)?;
        r.table.conn_mut(0).enqueue_reply(b"reply".to_vec());
        r.submit_send(0, 0).expect("stage the send");
        Some(r.engine.staged_sqe(0).flags)
    };
    let Some(armed) = staged_send_flags(ForceAsync::SEND) else {
        return;
    };
    assert_eq!(
        armed & IOSQE_ASYNC,
        IOSQE_ASYNC,
        "ForceAsync::SEND must reach the send SQE"
    );
    assert_eq!(
        armed & IOSQE_FIXED_FILE,
        IOSQE_FIXED_FILE,
        "the flag is added to the fixed-file bit, not instead of it"
    );
    for wrong in [ForceAsync::empty(), ForceAsync::RECV] {
        let flags = staged_send_flags(wrong).expect("ring was available");
        assert_eq!(flags & IOSQE_ASYNC, 0, "a send must stay unflagged under {wrong:?}");
    }
}

/// A reactor that sends gathers of 64 bytes and up zero-copy, with one connection at slot 0 whose peer is `peer`.
#[cfg(feature = "net-server")]
fn zero_copy_reactor(peer: ClientAddr, max_send_coalesce: usize) -> Option<Reactor<()>> {
    let mut r = reactor_with_peer(None, None, ForceAsync::empty(), peer, max_send_coalesce)?;
    r.cfg.zc_threshold = 64;
    r.cfg.zc_max_pinned = 1 << 20;
    r.cfg.zc_linger = Duration::from_secs(1);
    Some(r)
}

#[cfg(feature = "net-server")]
fn tcp_peer() -> ClientAddr {
    ClientAddr::Inet("127.0.0.1:1".parse::<std::net::SocketAddr>().unwrap())
}

/// The send SQE a zero-copy reactor stages once `prepare` has set its connection up, `None` without io_uring.
#[cfg(feature = "net-server")]
fn first_send(peer: ClientAddr, coalesce: usize, prepare: impl FnOnce(&mut Reactor<()>)) -> Option<IoUringSqe> {
    let mut r = zero_copy_reactor(peer, coalesce)?;
    prepare(&mut r);
    r.submit_send(0, 0).expect("stage the send");
    Some(r.engine.staged_sqe(0))
}

/// A zero-copy reactor whose connection has one 100-byte zero-copy send waiting for its notification.
#[cfg(feature = "net-server")]
fn one_zero_copy_send_owed() -> Option<Reactor<()>> {
    let mut r = zero_copy_reactor(tcp_peer(), 1)?;
    r.table.conn_mut(0).enqueue_reply(vec![7; 100]);
    r.submit_send(0, 0).expect("stage the send");
    r.on_send_zc_complete(0, 0, 100, IORING_CQE_F_MORE).expect("the result");
    assert_eq!((r.zc_pinned, r.zc_owed), (100, 1));
    Some(r)
}

#[cfg(feature = "net-server")]
#[test]
fn zero_copy_is_staged_only_above_the_threshold_on_plain_tcp() {
    let Some(sqe) = first_send(tcp_peer(), 1, |r| r.table.conn_mut(0).enqueue_reply(vec![7; 100])) else {
        return;
    };
    assert_eq!(sqe.opcode, IORING_OP_SEND_ZC);
    assert_eq!(sqe.ioprio, IORING_SEND_ZC_REPORT_USAGE);
    assert_eq!(
        sqe.user_data,
        pack(Op::SendZc, 0, 0),
        "the sequence rides in the generation field"
    );
    assert_eq!((sqe.addr3, sqe.pad2), (0, 0), "io_send_zc_prep refuses either");
    assert_eq!(sqe.op_flags, (libc::MSG_WAITALL | libc::MSG_NOSIGNAL) as u32);
    let gather = first_send(tcp_peer(), 8, |r| {
        r.table.conn_mut(0).enqueue_reply(vec![7; 50]);
        r.table.conn_mut(0).enqueue_reply(vec![8; 50]);
    })
    .expect("ring was available");
    assert_eq!(gather.opcode, IORING_OP_SENDMSG_ZC, "a gather of 100 bytes");

    // Each of these keeps the SQE a server without zero-copy stages.
    let copies = |sqe: IoUringSqe, why: &str| {
        assert_eq!(sqe.opcode, IORING_OP_SEND, "{why}");
        assert_eq!(sqe.ioprio, 0, "{why}");
        assert_eq!(sqe.user_data, pack(Op::Send, 0, 0), "{why}");
    };
    let reply = |r: &mut Reactor<()>| r.table.conn_mut(0).enqueue_reply(vec![7; 100]);
    copies(
        first_send(tcp_peer(), 1, |r| r.table.conn_mut(0).enqueue_reply(vec![7; 63])).unwrap(),
        "below the threshold",
    );
    copies(
        first_send(ClientAddr::Unix { cred: None }, 1, reply).unwrap(),
        "an AF_UNIX peer",
    );
    copies(
        first_send(tcp_peer(), 1, |r| {
            r.table.conn_mut(0).install_ktls();
            reply(r);
        })
        .unwrap(),
        "kTLS",
    );
    copies(
        first_send(tcp_peer(), 1, |r| {
            let mut zc = Box::new(crate::net::core::conn::ZcLedger::new(1000));
            zc.off = true;
            r.table.conn_mut(0).zc = Some(zc);
            reply(r);
        })
        .unwrap(),
        "a connection turned back to copying",
    );
    copies(
        first_send(tcp_peer(), 1, |r| {
            r.cfg.zc_max_pinned = 99;
            reply(r);
        })
        .unwrap(),
        "past max_pinned",
    );
    // The reply is queued before the tail, since a PDU enqueued behind an active one is diverted into it and would
    // leave nothing armed - which would read as a copy for the threshold's reason rather than the tail's.
    #[cfg(feature = "uring-fs")]
    copies(
        first_send(tcp_peer(), 1, |r| {
            reply(r);
            let fd: std::os::fd::OwnedFd = std::fs::File::open("/dev/null").expect("open").into();
            let file = crate::uring_fs::File::new(crate::sync::Arc::new(fd));
            r.table.conn_mut(0).install_file_tail(file, 0, 20);
        })
        .unwrap(),
        "a file body in flight",
    );
    let mut off = reactor_with_one_conn(None, None).unwrap();
    reply(&mut off);
    off.submit_send(0, 0).unwrap();
    copies(off.engine.staged_sqe(0), "zero-copy off");
}

#[cfg(feature = "net-server")]
#[test]
fn a_refused_zero_copy_send_is_resent_with_a_copy() {
    for (res, flags) in [
        (-libc::EOPNOTSUPP, IORING_CQE_F_MORE),
        (-libc::ENOMEM, IORING_CQE_F_MORE),
        (-libc::EINVAL, 0),
    ] {
        let Some(mut r) = zero_copy_reactor(tcp_peer(), 1) else {
            return;
        };
        r.table.conn_mut(0).enqueue_reply(vec![7; 100]);
        r.submit_send(0, 0).unwrap();
        r.on_send_zc_complete(0, 0, res, flags).unwrap();
        let again = r.engine.staged_sqe(1);
        assert_eq!(again.opcode, IORING_OP_SEND, "res {res}: not sent again with a copy");
        assert_eq!(again.user_data, pack(Op::Send, 0, 0), "res {res}");
        assert!(!r.table.conn(0).closing, "res {res}: a refusal closed the connection");
        assert!(r.table.conn(0).zc.as_deref().unwrap().off, "res {res}");
        let fallbacks = r.stats.zero_copy_fallbacks.load(std::sync::atomic::Ordering::Relaxed);
        assert_eq!(fallbacks, 1, "res {res}");
        assert_eq!(
            r.zc_owed,
            u64::from(flags != 0),
            "res {res}: only F_MORE owes a notification"
        );
    }
    // Any other failure closes, as a plain send's does.
    let Some(mut r) = zero_copy_reactor(tcp_peer(), 1) else {
        return;
    };
    r.table.conn_mut(0).enqueue_reply(vec![7; 100]);
    r.submit_send(0, 0).unwrap();
    r.on_send_zc_complete(0, 0, -libc::EPIPE, IORING_CQE_F_MORE).unwrap();
    assert!(r.table.conn(0).closing);
}

#[cfg(feature = "net-server")]
#[test]
fn a_copy_report_turns_zero_copy_off_for_the_connection() {
    let Some(mut r) = one_zero_copy_send_owed() else {
        return;
    };
    r.on_send_zc_notif(0, 0, IORING_NOTIF_USAGE_ZC_COPIED as i32).unwrap();
    assert_eq!((r.zc_pinned, r.zc_owed), (0, 0));
    assert!(r.table.conn(0).zc.as_deref().unwrap().off);
    assert_eq!(r.stats.zero_copy_copied.load(std::sync::atomic::Ordering::Relaxed), 1);
    r.table.conn_mut(0).enqueue_reply(vec![7; 100]);
    r.submit_send(0, 0).unwrap();
    let next = r.engine.staged_sqes().pop().unwrap();
    assert_eq!(
        next.opcode, IORING_OP_SEND,
        "a connection the kernel copies for keeps copying"
    );
}

#[cfg(feature = "net-server")]
#[test]
fn a_closing_connection_holds_its_close_until_notified() {
    let Some(mut r) = one_zero_copy_send_owed() else {
        return;
    };
    let before = r.engine.staged_sqes().len();
    r.close_conn(0, 0, CloseReason::PeerClosed).unwrap();
    let staged = r.engine.staged_sqes().split_off(before);
    assert!(
        staged.iter().all(|s| s.opcode != IORING_OP_CLOSE),
        "a CLOSE went out while the kernel may still read the pages"
    );
    let linger = staged
        .iter()
        .find(|s| s.user_data == pack(Op::ZcLinger, 0, 0))
        .expect("the socket gets TCP_USER_TIMEOUT");
    assert_eq!(linger.opcode, IORING_OP_URING_CMD);
    assert_eq!(linger.off_addr2, u64::from(SOCKET_URING_OP_SETSOCKOPT));
    let level_and_name = (libc::IPPROTO_TCP as u32 as u64) | ((libc::TCP_USER_TIMEOUT as u32 as u64) << 32);
    assert_eq!(linger.addr, level_and_name);
    // SAFETY: `addr3` points at the ledger's linger value, which lives while the connection does.
    assert_eq!(
        unsafe { *(linger.addr3 as *const u32) },
        1000,
        "the linger in milliseconds"
    );

    // The setsockopt reaps first: the notification is still owed, so still no CLOSE.
    let before = r.engine.staged_sqes().len();
    r.on_zc_linger(0, 0).unwrap();
    assert_eq!(r.engine.staged_sqes().len(), before);
    // The notification lets it go.
    r.on_send_zc_notif(0, 0, 0).unwrap();
    let close = r.engine.staged_sqes().pop().unwrap();
    assert_eq!(close.opcode, IORING_OP_CLOSE);
    assert_eq!(close.file_index, 1);
}

/// The reset count reports resets that went out, not resets the ring refused.
#[cfg(feature = "net-server")]
#[test]
fn a_reset_the_ring_refuses_is_not_counted() {
    use std::sync::atomic::Ordering::Relaxed;
    let Some(mut r) = one_zero_copy_send_owed() else {
        return;
    };
    assert_eq!(r.stats.zero_copy_resets.load(Relaxed), 0);
    r.engine.stage_seam.refuse_next = true;
    let refused = r.reset_owing();
    assert!(matches!(refused, Err(crate::errno::Errno::EBUSY)), "{refused:?}");
    assert_eq!(
        r.stats.zero_copy_resets.load(Relaxed),
        0,
        "a reset the kernel never saw was counted"
    );
    r.reset_owing().expect("the reset stages");
    assert_eq!(r.stats.zero_copy_resets.load(Relaxed), 1);
    assert_eq!(
        r.engine.staged_sqes().pop().expect("an SQE").user_data,
        pack(Op::ZcReset, 0, 0)
    );
}

/// A zero-copy reactor whose connection has two 100-byte zero-copy sends waiting for notifications, and the
/// `user_data` of the second.
#[cfg(feature = "net-server")]
fn two_zero_copy_sends_waiting_for_notifications() -> Option<(Reactor<()>, u64)> {
    let mut r = one_zero_copy_send_owed()?;
    r.table.conn_mut(0).enqueue_reply(vec![8; 100]);
    r.submit_send(0, 0).expect("stage the second send");
    let second = r.engine.staged_sqes().pop().expect("the second send's SQE").user_data;
    r.on_send_zc_complete(0, 1, 100, IORING_CQE_F_MORE)
        .expect("the second result");
    assert_eq!((r.zc_pinned, r.zc_owed), (200, 2));
    Some((r, second))
}

/// A held `CLOSE` waits for the last notification and for the `TCP_USER_TIMEOUT` setsockopt, in either order.
#[cfg(feature = "net-server")]
#[test]
fn a_held_close_waits_for_every_notification_and_for_the_linger() {
    let Some((mut r, second)) = two_zero_copy_sends_waiting_for_notifications() else {
        return;
    };
    // Each send carries its own sequence, or the ledger credits one notification against another send's bytes.
    assert_eq!(
        second,
        pack(Op::SendZc, 0, 1),
        "the second zero-copy send did not carry the next sequence"
    );

    // The setsockopt reaps first, then one of the two notifications: still one send owed, so still no CLOSE.
    r.close_conn(0, 0, CloseReason::PeerClosed).expect("close");
    r.on_zc_linger(0, 0).expect("the setsockopt");
    let before = r.engine.staged_sqes().len();
    r.on_send_zc_notif(0, 0, 0).expect("the first notification");
    let staged = r.engine.staged_sqes().split_off(before);
    assert!(
        staged.iter().all(|s| s.opcode != IORING_OP_CLOSE),
        "a CLOSE went out while a second send was still owed"
    );
    r.on_send_zc_notif(0, 1, 0).expect("the second notification");
    assert_eq!(r.engine.staged_sqes().pop().expect("the CLOSE").opcode, IORING_OP_CLOSE);

    // The other order: both notifications arrive while the setsockopt is still in flight. Nothing is owed, but the
    // held CLOSE must come after the command that is reading the ledger's linger value.
    let Some((mut r, _)) = two_zero_copy_sends_waiting_for_notifications() else {
        return;
    };
    r.close_conn(0, 0, CloseReason::PeerClosed).expect("close");
    let before = r.engine.staged_sqes().len();
    r.on_send_zc_notif(0, 0, 0).expect("the first notification");
    r.on_send_zc_notif(0, 1, 0).expect("the second notification");
    let staged = r.engine.staged_sqes().split_off(before);
    assert!(
        staged.iter().all(|s| s.opcode != IORING_OP_CLOSE),
        "a CLOSE went out with the TCP_USER_TIMEOUT setsockopt still in flight"
    );
    r.on_zc_linger(0, 0).expect("the setsockopt");
    assert_eq!(r.engine.staged_sqes().pop().expect("the CLOSE").opcode, IORING_OP_CLOSE);
}

#[cfg(feature = "net-server")]
#[test]
fn a_stop_resets_only_the_sockets_that_still_owe() {
    let Some(mut r) = one_zero_copy_send_owed() else {
        return;
    };
    r.reset_owing().unwrap();
    let reset = r.engine.staged_sqes().pop().unwrap();
    assert_eq!(reset.opcode, IORING_OP_CONNECT);
    assert_eq!(reset.user_data, pack(Op::ZcReset, 0, 0));
    assert_eq!((reset.fd, reset.flags), (0, IOSQE_FIXED_FILE));
    // SAFETY: `addr` is the static `AF_UNSPEC` sockaddr.
    let family = unsafe { (*(reset.addr as *const libc::sockaddr)).sa_family };
    assert_eq!(family, libc::AF_UNSPEC as libc::sa_family_t);

    r.on_send_zc_notif(0, 0, 0).unwrap();
    let before = r.engine.staged_sqes().len();
    r.reset_owing().unwrap();
    assert_eq!(
        r.engine.staged_sqes().len(),
        before,
        "a socket that owes nothing was reset"
    );
}

/// A `TCP_USER_TIMEOUT` completion for an incarnation the slot has left reaches nothing, and the completion of the
/// current one releases the held `CLOSE`.
#[cfg(feature = "net-server")]
#[test]
fn a_zero_copy_linger_for_a_past_incarnation_reaches_nothing() {
    let Some(mut r) = one_zero_copy_send_owed() else {
        return;
    };
    // The teardown holds the CLOSE and sets TCP_USER_TIMEOUT, so a linger is in flight on this incarnation.
    r.close_conn(0, 0, CloseReason::PeerClosed).expect("hold the close");
    assert!(r.table.conn(0).zc.as_deref().expect("the ledger").linger_inflight);
    let stale = r.table.generation_low(0);

    // The slot recycles into the state a stale linger would walk into a CLOSE: a held CLOSE, its own linger in
    // flight, and nothing owed.
    r.table.free(0);
    r.table.install(0, Connection::new(tcp_peer(), (), 1));
    let generation = r.table.generation_low(0);
    assert_ne!(generation, stale, "the recycle must bump the generation");
    {
        let mut zc = Box::new(crate::net::core::conn::ZcLedger::new(1000));
        zc.close_held = true;
        zc.linger_inflight = true;
        r.table.conn_mut(0).zc = Some(zc);
    }

    let before = r.engine.staged_sqes().len();
    r.on_zc_linger(0, stale).expect("the stale linger");
    assert_eq!(
        r.engine.staged_sqes().len(),
        before,
        "a stale linger released the new connection's held CLOSE"
    );
    {
        let zc = r.table.conn(0).zc.as_deref().expect("the ledger");
        assert!(
            zc.linger_inflight,
            "a stale linger cleared a setsockopt still in flight"
        );
        assert!(zc.close_held, "a stale linger took the hold off the CLOSE");
    }

    // The control: this incarnation's own completion means the kernel has read the value, so the CLOSE may go.
    r.on_zc_linger(0, generation).expect("this incarnation's linger");
    {
        let zc = r.table.conn(0).zc.as_deref().expect("the ledger");
        assert!(!zc.linger_inflight);
        assert!(!zc.close_held, "the hold is released as the CLOSE is staged");
    }
    let close = r.engine.staged_sqes().pop().expect("the CLOSE");
    assert_eq!(close.opcode, IORING_OP_CLOSE);
    assert_eq!(close.file_index, 1);
}

/// A zero-copy send the ring refuses owes nothing, since no completion will ever name it.
#[cfg(feature = "net-server")]
#[test]
fn a_zero_copy_send_the_ring_refuses_owes_nothing() {
    let Some(mut r) = zero_copy_reactor(tcp_peer(), 1) else {
        return;
    };
    r.table.conn_mut(0).enqueue_reply(vec![7; 100]);
    r.engine.stage_seam.refuse_next = true;
    assert_eq!(r.submit_send(0, 0), Err(crate::errno::Errno::EBUSY));
    assert_eq!((r.zc_owed, r.zc_pinned, r.engine.inflight), (0, 0, 0));
    let zc = r.table.conn(0).zc.as_deref().expect("admission made the ledger");
    assert!(!zc.owes());
    assert_eq!(zc.admit(), Some(0), "the refused sequence is free again");
}

/// The cap counts a send's armed bytes once the ring takes it, so the next admission in the same loop sees them.
#[cfg(feature = "net-server")]
#[test]
fn the_cap_counts_a_staged_zero_copy_send_before_its_result() {
    let Some(mut r) = zero_copy_reactor(tcp_peer(), 1) else {
        return;
    };
    r.cfg.zc_max_pinned = 150;
    r.table.install(1, Connection::new(tcp_peer(), (), 1));
    for slot in 0..2 {
        r.table.conn_mut(slot).enqueue_reply(vec![7; 100]);
        r.submit_send(slot, 0).expect("stage the send");
    }
    let ops: Vec<u8> = r.engine.staged_sqes().iter().map(|s| s.opcode).collect();
    assert_eq!(
        ops,
        [IORING_OP_SEND_ZC, IORING_OP_SEND],
        "the second send passed the cap"
    );
    assert_eq!((r.zc_pinned, r.zc_owed), (100, 1));
}

/// The stop drain starts the linger once only notifications are left, and also when the owed count is too high, so
/// that a count gone wrong ends in the reset rather than in a wait with no deadline.
#[cfg(feature = "net-server")]
#[test]
fn the_stop_drain_lingers_when_the_owed_count_is_too_high() {
    use crate::net::core::reactor::zero_copy::only_notifications_left;
    assert!(only_notifications_left(1, 1));
    assert!(only_notifications_left(1, 2));
    assert!(!only_notifications_left(2, 1));
}
