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
    let peer = ClientAddr::Inet("127.0.0.1:1".parse::<std::net::SocketAddr>().unwrap());
    r.table.install(0, Connection::new(peer, (), 1));
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
/// `deliver_one` retires (clearing the flag and *staging* a cancel that `run_loop` submits only at the top of the
/// next iteration) and `pump -> submit_recv -> arm_receipt_deadline` re-arms, all before the reap loop reaches the
/// old timer's `-ETIME` - which is posted at exactly the deadline the retire sat on, i.e. whenever a peer finishes
/// just inside its budget. `user_data` carries the slot's generation, not the timer's, so the two expiries are
/// bit-identical and the flag alone cannot tell them apart.
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
    // An exact read from an empty buffer is ambiguous on its own: for a length-prefix framer it is the next
    // message's first read, and for one that parsed a body length out of a head it has already consumed it is a
    // continuation. Only the framer knows, so only the framer can say - and a `Need` that should have been
    // `NeedInMessage` arms no receipt budget and takes the idle clock, which where `idle_timeout` is unset is no
    // clock at all.
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
    // Overflowing header+body is rejected before any slice (the U64-prefix remote-panic class the fuzzer
    // rediscovered).
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
