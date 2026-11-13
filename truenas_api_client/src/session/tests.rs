use super::*;
use truenas_ros::ws::FrameHead;

fn session() -> Session {
    let mut s = Session::new("test-key".into(), false, 65_536, 1024, 256, 16 * 1024 * 1024);
    // on_frame does not gate on phase, but a realistic session is Open.
    s.phase = Phase::Open;
    s
}

/// A server->style FrameHead (unmasked) for feeding on_frame directly.
fn head(fin: bool, opcode: u8, payload_len: usize) -> FrameHead {
    FrameHead {
        fin,
        opcode,
        header_len: if payload_len < 126 { 2 } else { 4 },
        payload_len,
    }
}

/// Unmask a client frame the session emitted, returning (opcode, payload) - the session always masks what it sends.
fn unmask(f: &[u8]) -> (u8, Vec<u8>) {
    assert!(f[0] & 0x80 != 0, "FIN set");
    assert!(f[1] & 0x80 != 0, "client frame is masked");
    let (hdr, len) = match f[1] & 0x7f {
        126 => (4, usize::from(u16::from_be_bytes([f[2], f[3]]))),
        127 => (10, u64::from_be_bytes(f[2..10].try_into().unwrap()) as usize),
        n => (2, usize::from(n)),
    };
    let mask = &f[hdr..hdr + 4];
    let payload = f[hdr + 4..hdr + 4 + len]
        .iter()
        .enumerate()
        .map(|(i, b)| b ^ mask[i % 4])
        .collect();
    (f[0] & 0x0f, payload)
}

/// A continuation with no message in progress fails the connection.
#[test]
fn a_continuation_with_no_message_open_faults() {
    let mut s = session();
    let acts = s.on_frame(head(true, OP_CONT, 3), b"abc".to_vec());
    assert!(
        matches!(acts.as_slice(), [Act::Fault(_)]),
        "orphan continuation is a protocol fault: {acts:?}"
    );
}

/// A fresh data frame while a fragmented message is owed a FIN fails the connection.
#[test]
fn a_new_data_frame_mid_fragment_faults() {
    let mut s = session();
    // Open a fragmented text message (FIN=0), then send a *new* text frame instead of a continuation.
    assert!(s.on_frame(head(false, OP_TEXT, 1), b"{".to_vec()).is_empty());
    let acts = s.on_frame(head(false, OP_TEXT, 1), b"[".to_vec());
    assert!(
        matches!(acts.as_slice(), [Act::Fault(_)]),
        "a data frame owing a FIN is a fault: {acts:?}"
    );
}

/// A binary frame: middlewared is text-only, so it is a fault (mirrors the session's OP_BINARY arm; the codec
/// accepts the opcode, the session rejects the type).
#[test]
fn a_binary_frame_faults() {
    let mut s = session();
    let acts = s.on_frame(head(true, OP_BINARY, 2), b"hi".to_vec());
    assert!(matches!(acts.as_slice(), [Act::Fault(_)]), "{acts:?}");
}

/// A valid fragmented message reassembles across a continuation and is dispatched once whole - here a notification,
/// so it surfaces as an Update.
#[test]
fn a_fragmented_message_reassembles() {
    let mut s = session();
    let whole = br#"{"jsonrpc":"2.0","method":"collection_update","params":{"msg":"added","collection":"c"}}"#;
    let (a, b) = whole.split_at(40);
    assert!(s.on_frame(head(false, OP_TEXT, a.len()), a.to_vec()).is_empty());
    let acts = s.on_frame(head(true, OP_CONT, b.len()), b.to_vec());
    assert!(
        acts.iter().any(|act| matches!(act, Act::Update(_))),
        "the reassembled notification dispatched: {acts:?}"
    );
}

/// A control frame may interleave a fragmented message without disturbing reassembly (RFC §5.4; lws control opcodes
/// never touch the continuation state): a ping between fragments is answered with a pong echoing its payload, and
/// the message still completes.
#[test]
fn a_ping_interleaves_a_fragment_and_is_ponged() {
    let mut s = session();
    let whole = br#"{"jsonrpc":"2.0","method":"collection_update","params":{"msg":"added","collection":"c"}}"#;
    let (a, b) = whole.split_at(40);
    assert!(s.on_frame(head(false, OP_TEXT, a.len()), a.to_vec()).is_empty());
    // Ping mid-fragment -> a single masked pong with the same payload.
    let acts = s.on_frame(head(true, OP_PING, 4), b"body".to_vec());
    match acts.as_slice() {
        [Act::Send(frame)] => {
            assert_eq!(unmask(frame), (OP_PONG, b"body".to_vec()));
        }
        other => panic!("expected one pong, got {other:?}"),
    }
    // The fragment still completes afterward.
    let acts = s.on_frame(head(true, OP_CONT, b.len()), b.to_vec());
    assert!(acts.iter().any(|act| matches!(act, Act::Update(_))), "{acts:?}");
}

/// A reassembled message may not exceed the inbound cap - the sum over fragments is bounded, not just each frame
/// (the reactor bounds a single frame; this bounds the whole message).
#[test]
fn an_oversized_reassembly_faults() {
    let mut s = Session::new("k".into(), false, 65_536, 8, 256, 16 * 1024 * 1024);
    s.phase = Phase::Open;
    assert!(s.on_frame(head(false, OP_TEXT, 6), vec![b'x'; 6]).is_empty());
    let acts = s.on_frame(head(false, OP_CONT, 6), vec![b'x'; 6]);
    assert!(
        matches!(acts.as_slice(), [Act::Fault(_)]),
        "12 bytes over an 8-byte cap faults: {acts:?}"
    );
}

/// A ping outside any fragment is answered with a pong of the same payload (RFC §5.5.2).
#[test]
fn a_ping_is_answered_with_a_matching_pong() {
    let mut s = session();
    let acts = s.on_frame(head(true, OP_PING, 5), b"hello".to_vec());
    match acts.as_slice() {
        [Act::Send(frame)] => {
            assert_eq!(unmask(frame), (OP_PONG, b"hello".to_vec()));
        }
        other => panic!("expected a pong, got {other:?}"),
    }
}

/// A peer close echoes a close frame and hands the driver PeerClosing;
/// the status code is captured for the session-closed report.
#[test]
fn a_peer_close_echoes_and_reports() {
    let mut s = session();
    // 1001 "going away", big-endian.
    let acts = s.on_frame(head(true, OP_CLOSE, 2), vec![0x03, 0xe9]);
    assert!(
        acts.iter().any(|a| matches!(a, Act::PeerClosing)),
        "the driver is told to close: {acts:?}"
    );
    match acts.first() {
        Some(Act::Send(frame)) => {
            let (op, payload) = unmask(frame);
            assert_eq!(op, OP_CLOSE);
            assert_eq!(payload, vec![0x03, 0xe9], "the code is echoed");
        }
        other => panic!("expected a close echo first, got {other:?}"),
    }
    assert!(
        s.close_reason.as_deref().is_some_and(|r| r.contains("1001")),
        "the close code is captured: {:?}",
        s.close_reason
    );
}

/// middlewared grants the extended cap per *method*, after parsing - `parse_message` returns early for a
/// whitelisted one and applies the ordinary cap to everything else - so a single per-session number cannot mirror
/// it. An upload gets the extended cap without the session's other calls getting it too.
#[test]
fn the_extended_cap_applies_to_the_upload_methods_only() {
    use serde_json::value::RawValue;
    let mut s = Session::new("k".into(), false, 65_536, 1024, 256, 16 * 1024 * 1024);
    s.phase = Phase::Open;
    // A params array comfortably over the ordinary 64 KiB cap and under the extended 2 MiB one.
    let big = format!("[\"{}\"]", "x".repeat(100_000));
    let args = RawValue::from_string(big).unwrap();
    let mut n = 0;
    let mut go = |s: &mut Session, method: &str| {
        n += 1;
        s.submit(crate::CallId(n), Kind::User, method, &args, None)
    };
    for method in crate::MSG_SIZE_EXTENDED_METHODS {
        assert!(
            matches!(go(&mut s, method).as_deref(), Ok([Act::Send(_)])),
            "{method} must be allowed the extended cap"
        );
    }
    match go(&mut s, "pool.dataset.create") {
        Err(ApiError::TooLarge { cap, .. }) => {
            assert_eq!(cap, crate::MIDDLEWARE_MSG_CAP)
        }
        other => panic!("an ordinary method must be refused: {other:?}"),
    }
    // The exemption is a larger cap, not the absence of one: `parse_message` refuses above it before it reads the
    // method at all.
    let huge = format!("[\"{}\"]", "x".repeat(crate::MIDDLEWARE_MSG_CAP_EXTENDED));
    let huge = RawValue::from_string(huge).unwrap();
    match s.submit(crate::CallId(99), Kind::User, "filesystem.file_receive", &huge, None) {
        Err(ApiError::TooLarge { cap, .. }) => {
            assert_eq!(cap, crate::MIDDLEWARE_MSG_CAP_EXTENDED)
        }
        other => panic!("the extended cap still bounds: {other:?}"),
    }
}

/// The backlog has two caps and refuses on whichever trips first.
#[test]
fn a_full_backlog_is_refused_by_bytes_as_well_as_by_count() {
    use serde_json::value::RawValue;
    // Room for many frames, but only a little memory.
    let mut s = Session::new("k".into(), false, 2_097_152, 1024, 1024, 200_000);
    s.phase = Phase::Open;
    let big = format!("[\"{}\"]", "x".repeat(60_000));
    let args = RawValue::from_string(big).unwrap();
    let mut n = 0;
    let mut put = |s: &mut Session| {
        n += 1;
        s.submit(crate::CallId(n), Kind::User, "core.ping", &args, None)
    };
    // Spend the budget on the wire, then fill the queue by bytes.
    for _ in 0..CALL_BUDGET {
        put(&mut s).expect("under budget");
    }
    let mut queued = 0;
    loop {
        match put(&mut s) {
            Ok(_) => queued += 1,
            Err(ApiError::QueueFull { cap, .. }) => {
                assert_eq!(cap, 200_000, "the byte cap is what refused");
                break;
            }
            other => panic!("unexpected: {other:?}"),
        }
        assert!(queued < 50, "the byte cap must bite long before 1024");
    }
    assert!(
        s.queued_bytes <= 200_000,
        "the queue stays inside its byte bound: {}",
        s.queued_bytes
    );
    // Draining gives the bytes back.
    s.budget = CALL_BUDGET;
    let _ = s.drain_backlog();
    assert_eq!(s.queued_bytes, 0, "a drained queue charges nothing");
}

/// An `id: null` error is reported and the session keeps serving, since middlewared sends one and carries on (JSON-RPC
/// 2.0 §5).
#[test]
fn a_null_id_error_reports_without_killing_the_session() {
    let mut s = session();
    let body = r#"{"jsonrpc":"2.0","error":{"code":-32700,
                       "message":"Parse error"},"id":null}"#;
    let acts = s.on_frame(head(true, OP_TEXT, body.len()), body.as_bytes().to_vec());
    match acts.as_slice() {
        [Act::ServerError(e)] => {
            assert!(
                format!("{e}").contains("Parse error"),
                "the server's report reaches the caller: {e}"
            );
        }
        other => panic!("expected a report, not a teardown: {other:?}"),
    }
    assert!(!matches!(s.phase, Phase::Closing), "the session stays open");
}

/// An `id: null` Response fails every call in flight, since the one that provoked it will never be answered. Their
/// tombstones and slots stay until the server's answers land, or each answer would fault the session.
#[test]
fn a_null_id_error_fails_the_calls_in_flight_but_keeps_their_tombstones() {
    use serde_json::value::RawValue;
    let mut s = session();
    let args = RawValue::from_string("[]".to_owned()).unwrap();
    let mut ids = Vec::new();
    for i in 0..3u64 {
        let acts = s
            .submit(crate::CallId(i), Kind::User, "core.ping", &args, None)
            .expect("submits");
        let [Act::Send(frame)] = acts.as_slice() else {
            panic!("call {i} should have gone out: {acts:?}")
        };
        let (_op, payload) = unmask(frame);
        let v: serde_json::Value = serde_json::from_slice(&payload).expect("a JSON request");
        ids.push(v.get("id").cloned().expect("a request carries an id"));
    }
    assert_eq!(s.budget, CALL_BUDGET - 3);

    let body = r#"{"jsonrpc":"2.0","error":{"code":-32700,
                       "message":"Parse error"},"id":null}"#;
    let acts = s.on_frame(head(true, OP_TEXT, body.len()), body.as_bytes().to_vec());
    let done = acts.iter().filter(|a| matches!(a, Act::CallDone { .. })).count();
    assert!(
        matches!(acts.first(), Some(Act::ServerError(_))),
        "the server's report still surfaces: {acts:?}"
    );
    assert_eq!(done, 3, "every call in flight is answered: {acts:?}");
    assert_eq!(
        s.pending.len(),
        3,
        "the server still owes three answers; the tombstones wait"
    );
    assert_eq!(s.budget, CALL_BUDGET - 3, "and still holds their slots");
    assert!(!matches!(s.phase, Phase::Closing), "the session keeps serving");

    // The answers land. Each is recognised and dropped, and each returns its slot. A fault here is the defect.
    for (n, id) in ids.iter().enumerate() {
        let body = serde_json::json!({"jsonrpc":"2.0","id":id,"result":null}).to_string();
        let len = body.len();
        let acts = s.on_frame(head(true, OP_TEXT, len), body.into_bytes());
        assert!(
            acts.is_empty(),
            "late answer {n} must be dropped, not faulted: {acts:?}"
        );
        assert_eq!(s.budget, CALL_BUDGET - 2 + n);
    }
    assert!(s.pending.is_empty(), "every tombstone retired");
    assert!(!matches!(s.phase, Phase::Closing), "and the session is still serving");
}

/// A session still in setup keeps its `core.set_options` tombstone through the same report. Dropping it would leave
/// the setup answer matching no entry, and the session would then fault itself with "response to no outstanding
/// call" - a diagnosis of the wrong thing. Its budget slot stays spent with it.
#[test]
fn a_null_id_error_does_not_strand_a_session_still_in_setup() {
    let mut s = Session::new("k".into(), false, 65_536, 65_536, 256, 1 << 20);
    // The setup call, exactly as `on_head` issues it once the 101 validates: `core.set_options` under
    // `Kind::SetOptions`.
    let params = serde_json::value::RawValue::from_string(r#"[{"legacy_jobs":false}]"#.to_owned()).unwrap();
    s.phase = Phase::Open;
    s.submit(crate::CallId(0), Kind::SetOptions, "core.set_options", &params, None)
        .expect("the setup call goes out");
    assert_eq!(s.pending.len(), 1, "the setup call is outstanding");

    let body = r#"{"jsonrpc":"2.0","error":{"code":-32700,
                       "message":"Parse error"},"id":null}"#;
    let _ = s.on_frame(head(true, OP_TEXT, body.len()), body.as_bytes().to_vec());
    assert_eq!(
        s.pending.len(),
        1,
        "the setup tombstone survives, or its answer faults the session"
    );
    assert_eq!(
        s.budget,
        CALL_BUDGET - 1,
        "and the slot it holds is not handed back twice"
    );
}

/// The inbound cap covers an unfragmented message, not only a reassembled one.
#[test]
fn the_inbound_cap_covers_an_unfragmented_message() {
    let mut s = Session::new("k".into(), false, 65_536, 64, 256, 16 * 1024 * 1024);
    s.phase = Phase::Open;
    match s.on_frame(head(true, OP_TEXT, 256), vec![b'a'; 256]).as_slice() {
        [Act::Fault(why)] => {
            assert_eq!(*why, "message exceeds the inbound cap")
        }
        other => panic!("an over-cap message must fault: {other:?}"),
    }
}

/// No data frame goes out after our Close (§5.5.1), even when an answer frees a slot for a queued call.
#[test]
fn no_data_frame_goes_out_after_our_close() {
    use serde_json::value::RawValue;
    let mut s = session();
    let args = RawValue::from_string("[]".to_owned()).unwrap();
    for i in 0..CALL_BUDGET {
        let _ = s
            .submit(crate::CallId(100 + i as u64), Kind::User, "core.ping", &args, None)
            .expect("under budget");
    }
    let _ = s
        .submit(crate::CallId(999), Kind::User, "core.ping", &args, None)
        .expect("queues");
    assert_eq!(s.backlog.len(), 1, "one call is queued");

    // The peer closes; we echo and go to Closing.
    let close = s.on_frame(head(true, OP_CLOSE, 2), vec![0x03, 0xE8]);
    assert!(matches!(close.as_slice(), [Act::Send(_), Act::PeerClosing]));
    assert!(matches!(s.phase, Phase::Closing));

    // Now one of the outstanding answers lands.
    let answered = s
        .pending
        .iter()
        .find(|(_, p)| p.sent)
        .map(|(k, _)| k.clone())
        .expect("a sent call");
    let body = serde_json::json!({
        "jsonrpc": "2.0", "id": answered, "result": "pong",
    })
    .to_string();
    let len = body.len();
    let acts = s.on_frame(head(true, OP_TEXT, len), body.into_bytes());
    let sent: Vec<u8> = acts
        .iter()
        .filter_map(|a| match a {
            Act::Send(b) => Some(b[0] & 0x0F),
            _ => None,
        })
        .collect();
    assert!(sent.is_empty(), "no frame may follow our Close; sent opcodes {sent:?}");
    // The answer itself is still delivered - only the sending stops.
    assert!(
        acts.iter().any(|a| matches!(a, Act::CallDone { .. })),
        "the answer that already arrived is still surfaced: {acts:?}"
    );
    assert_eq!(s.backlog.len(), 1, "the queued call stays queued");
}

/// `expire` drains the backlog too, and `pump` runs it before it reaps a single completion, so it must not send after
/// our Close either.
#[test]
fn expire_does_not_drain_the_backlog_after_our_close() {
    use serde_json::value::RawValue;
    use std::time::Duration;
    let mut s = session();
    let args = RawValue::from_string("[]".to_owned()).unwrap();
    let t0 = Instant::now();
    // Budget spent, every one of them due to time out...
    for i in 0..CALL_BUDGET {
        let _ = s
            .submit(crate::CallId(100 + i as u64), Kind::User, "core.ping", &args, Some(t0))
            .expect("under budget");
    }
    // ...and one queued call that is not due, so expiry does not drop it.
    let _ = s
        .submit(crate::CallId(999), Kind::User, "core.ping", &args, None)
        .expect("queues");
    assert_eq!(s.backlog.len(), 1);

    let close = s.on_frame(head(true, OP_CLOSE, 2), vec![0x03, 0xE8]);
    assert!(matches!(close.as_slice(), [Act::Send(_), Act::PeerClosing]));

    let acts = s.expire(t0 + Duration::from_secs(1));
    let sent: Vec<u8> = acts
        .iter()
        .filter_map(|a| match a {
            Act::Send(b) => Some(b[0] & 0x0F),
            _ => None,
        })
        .collect();
    assert!(
        sent.is_empty(),
        "expire must not put a frame on a closing connection; sent \
             opcodes {sent:?}"
    );
    assert_eq!(s.backlog.len(), 1, "the queued call stays queued");
}

/// A first fragment is held until a continuation arrives, so it is bounded where it is stored, not only where the
/// pieces are joined - otherwise a peer opens a fragmented message, sends nothing more, and holds whatever it
/// declared for the connection's life. Closing releases it: no continuation can arrive after that.
#[test]
fn an_open_reassembly_is_bounded_and_released_at_close() {
    let mut s = Session::new("k".into(), false, 65_536, 64, 256, 16 * 1024 * 1024);
    s.phase = Phase::Open;
    // Over the cap in the very first fragment.
    match s.on_frame(head(false, OP_TEXT, 256), vec![b'a'; 256]).as_slice() {
        [Act::Fault(why)] => {
            assert_eq!(*why, "fragmented message exceeds the inbound cap")
        }
        other => {
            panic!("an over-cap first fragment must fault: {other:?}")
        }
    }
    assert!(s.frag.is_none(), "a refused fragment is not stored");

    // Under the cap: held, then released when the peer closes.
    let mut s = Session::new("k".into(), false, 65_536, 64, 256, 16 * 1024 * 1024);
    s.phase = Phase::Open;
    assert!(s.on_frame(head(false, OP_TEXT, 32), vec![b'a'; 32]).is_empty());
    assert!(s.frag.is_some(), "the control: it really is held");
    let _ = s.on_frame(head(true, OP_CLOSE, 2), 1000u16.to_be_bytes().to_vec());
    assert!(s.frag.is_none(), "closing releases the reassembly");
}

/// Past the concurrency budget calls queue, and past the queue's own bound they are refused and leave nothing behind.
#[test]
fn a_full_backlog_refuses_rather_than_growing() {
    use serde_json::value::RawValue;
    const QUEUED: usize = 4;
    let mut s = Session::new("k".into(), false, 65_536, 1024, QUEUED, usize::MAX);
    s.phase = Phase::Open;
    let args = RawValue::from_string("[]".to_owned()).unwrap();
    let put = |s: &mut Session, i: usize| s.submit(crate::CallId(i as u64), Kind::User, "core.ping", &args, None);
    // The budget's worth go to the wire.
    for i in 0..CALL_BUDGET {
        let acts = put(&mut s, i).expect("under budget");
        assert!(
            matches!(acts.as_slice(), [Act::Send(_)]),
            "call {i} should have gone out"
        );
    }
    // The queue's worth are accepted and held.
    for i in 0..QUEUED {
        let acts = put(&mut s, CALL_BUDGET + i).expect("queues");
        assert!(acts.is_empty(), "a queued call sends nothing");
    }
    assert_eq!(s.backlog.len(), QUEUED);
    // One more is refused, and leaves nothing behind: no tombstone for an answer to find, and no growth.
    let pending_before = s.pending.len();
    match put(&mut s, 999) {
        Err(ApiError::QueueFull { cap, .. }) => {
            assert_eq!(cap, QUEUED)
        }
        other => panic!("expected QueueFull, got {other:?}"),
    }
    assert_eq!(s.backlog.len(), QUEUED, "a refusal does not queue");
    assert_eq!(s.pending.len(), pending_before, "a refusal leaves no tombstone");
}

/// A locally timed-out call keeps its concurrency slot and its tombstone until the server answers, and that late answer
/// frees the slot once, releasing the next queued call.
#[test]
fn a_timed_out_call_keeps_its_slot_until_a_late_answer_frees_it_once() {
    use serde_json::value::RawValue;
    let mut s = session();
    let args = RawValue::from_string("[]".to_owned()).unwrap();
    let past = Instant::now();

    // Fill the budget, every call already past its deadline. Keep the ids so one can be answered late.
    let mut ids = Vec::new();
    for i in 0..CALL_BUDGET {
        let acts = s
            .submit(
                crate::CallId(100 + i as u64),
                Kind::User,
                "core.ping",
                &args,
                Some(past),
            )
            .expect("submits under budget");
        let [Act::Send(frame)] = acts.as_slice() else {
            panic!("call {i} should have gone to the wire: {acts:?}")
        };
        let (_op, payload) = unmask(frame);
        let v: serde_json::Value = serde_json::from_slice(&payload).expect("a JSON request");
        ids.push(v.get("id").cloned().expect("a request carries an id"));
    }
    assert_eq!(s.budget, 0, "every slot is spent while the calls live");

    // The clock crosses every deadline.
    let later = past + std::time::Duration::from_secs(1);
    let acts = s.expire(later);
    assert_eq!(acts.len(), CALL_BUDGET, "every abandoned call surfaces its Timeout");
    assert_eq!(
        s.pending.len(),
        CALL_BUDGET,
        "tombstones stay, so a late answer is still recognised"
    );
    assert_eq!(
        s.budget, 0,
        "the caller gave up; the server did not, so it still holds \
             every slot"
    );

    // So a further call is queued, not sent: the peer's concurrency limit is counted by the peer, and it has not
    // answered anything.
    let acts = s
        .submit(crate::CallId(999), Kind::User, "core.ping", &args, None)
        .expect("submits");
    assert!(acts.is_empty(), "queued behind the server's own work");
    assert_eq!(s.backlog.len(), 1);

    // The answer is what frees the server, so it is what frees the slot - and it releases the queued call.
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": ids[0],
        "result": null,
    })
    .to_string();
    let len = body.len();
    let acts = s.on_frame(head(true, OP_TEXT, len), body.into_bytes());
    assert!(
        matches!(acts.as_slice(), [Act::Send(_)]),
        "the late answer's slot goes to the queued call: {acts:?}"
    );
    assert_eq!(s.budget, 0, "which spends it again immediately");
    assert!(s.backlog.is_empty(), "the backlog drained");
    assert_eq!(
        s.pending.len(),
        CALL_BUDGET,
        "one tombstone retired, one live call added"
    );
}

/// Read a request frame's `id` out of a `Send`.
fn sent_id(acts: &[Act]) -> serde_json::Value {
    let [Act::Send(frame)] = acts else {
        panic!("expected exactly one Send: {acts:?}")
    };
    let (_op, payload) = unmask(frame);
    let v: serde_json::Value = serde_json::from_slice(&payload).expect("a JSON request");
    v.get("id").cloned().expect("a request carries an id")
}

/// Build a `-32000` answer for `id`.
fn refusal(id: &serde_json::Value) -> String {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": crate::error::TOO_MANY_CONCURRENT_CALLS,
            "message": "Maximum number of concurrent calls (20) has \
                            exceeded",
        },
    })
    .to_string()
}

/// A `-32000` comes before the method runs (`SoftHardSemaphore.__aenter__`), so the call is reissued after a pause
/// rather than reported. Nothing else goes out during the pause, neither the queued calls nor one submitted on the slot
/// the refusal returned.
#[test]
fn a_concurrency_refusal_is_reissued_after_a_pause() {
    use serde_json::value::RawValue;
    let mut s = session();
    let args = RawValue::from_string("[]".to_owned()).unwrap();

    let mut ids = Vec::new();
    for i in 0..CALL_BUDGET {
        let acts = s
            .submit(crate::CallId(100 + i as u64), Kind::User, "core.ping", &args, None)
            .expect("submits under budget");
        ids.push(sent_id(&acts));
    }
    s.submit(crate::CallId(999), Kind::User, "core.ping", &args, None)
        .expect("submits");
    assert_eq!(s.backlog.len(), 1, "queued behind the budget");

    // The refusal lands.
    let body = refusal(&ids[0]);
    let len = body.len();
    let acts = s.on_frame(head(true, OP_TEXT, len), body.into_bytes());
    assert!(acts.is_empty(), "nothing is reported and nothing goes out: {acts:?}");
    assert_eq!(s.backlog.len(), 2, "the refused call is requeued");
    let front: serde_json::Value =
        serde_json::from_slice(&s.backlog.front().expect("a queued frame").1).expect("a JSON request");
    assert_eq!(
        front.get("id"),
        Some(&ids[0]),
        "and requeued at the front, ahead of what was already waiting"
    );

    // A call submitted during the pause queues too: the refusal returned a slot, so `submit` would otherwise find
    // budget and go straight out around the drain's gate.
    let acts = s
        .submit(crate::CallId(1000), Kind::User, "core.ping", &args, None)
        .expect("submits");
    assert!(acts.is_empty(), "a fresh call queues too: {acts:?}");
    assert_eq!(s.backlog.len(), 3);

    // `expire` gives the pause a clock and publishes it.
    let t0 = Instant::now();
    assert!(s.expire(t0).is_empty(), "still paused");
    let until = s.next_deadline().expect("the pause is a pump deadline");
    assert!(until > t0 && until <= t0 + BACKOFF_CAP, "bounded");
    assert!(s.expire(until - Duration::from_millis(1)).is_empty(), "the pause holds");
    assert_eq!(s.backlog.len(), 3, "all three still held");

    // One answer came back, so one slot did: the reissue goes, and the rest wait for further answers.
    let acts = s.expire(until);
    assert_eq!(sent_id(&acts), ids[0], "the reissued call is the one that goes");
    assert_eq!(s.backlog.len(), 2, "held by the budget, not the pause");
    assert_eq!(s.next_deadline(), None, "and the pause is no longer a deadline");
}

/// A call refused past [`MAX_CALL_RETRIES`] reaches its caller. The reissue is a courtesy against a busy peer, not
/// an unbounded loop - a session with no `call_timeout` has nothing else to end it.
#[test]
fn a_call_refused_past_its_retry_bound_reaches_its_caller() {
    use serde_json::value::RawValue;
    let mut s = session();
    let args = RawValue::from_string("[]".to_owned()).unwrap();

    let acts = s
        .submit(crate::CallId(1), Kind::User, "core.ping", &args, None)
        .expect("submits");
    let mut id = sent_id(&acts);

    for attempt in 0..MAX_CALL_RETRIES {
        let body = refusal(&id);
        let len = body.len();
        let acts = s.on_frame(head(true, OP_TEXT, len), body.into_bytes());
        assert!(acts.is_empty(), "reissue {attempt} must not report: {acts:?}");
        // Clear the pause; the reissue goes out with the same id.
        let t0 = Instant::now();
        s.expire(t0);
        let until = s.next_deadline().expect("a pause");
        let acts = s.expire(until);
        assert_eq!(sent_id(&acts), id, "reissued under its own id");
        id = sent_id(&acts);
    }

    // One more refusal, and the caller hears about it.
    let body = refusal(&id);
    let len = body.len();
    let acts = s.on_frame(head(true, OP_TEXT, len), body.into_bytes());
    assert!(
        matches!(
            acts.as_slice(),
            [Act::CallDone {
                result: Err(ApiError::TooManyConcurrentCalls { .. }),
                ..
            }]
        ),
        "the bound is reached and the refusal surfaces: {acts:?}"
    );
    assert!(s.backlog.is_empty(), "and it is not requeued again");
}

/// Consecutive refusals lengthen the pause, and an answer that is not a refusal resets it. Each pause is jittered, so
/// the check is on the window `[full/2, full]` for that step.
#[test]
fn the_backoff_grows_and_an_ordinary_answer_resets_it() {
    use serde_json::value::RawValue;
    let mut s = session();
    let args = RawValue::from_string("[]".to_owned()).unwrap();

    // Answer one call and return the pause that answer produced.
    let answer = |s: &mut Session, n: u64, refused: bool| -> Duration {
        let acts = s
            .submit(crate::CallId(n), Kind::User, "core.ping", &args, None)
            .expect("submits");
        let id = sent_id(&acts);
        let body = if refused {
            refusal(&id)
        } else {
            serde_json::json!({"jsonrpc":"2.0","id":id,"result":null}).to_string()
        };
        let len = body.len();
        s.on_frame(head(true, OP_TEXT, len), body.into_bytes());
        let t0 = Instant::now();
        s.expire(t0);
        let d = s.next_deadline().map_or(Duration::ZERO, |t| t - t0);
        // Clear whatever pause was set, so the next measurement is not taken through this one.
        s.expire(t0 + d);
        d
    };
    // The window `full` for the nth consecutive refusal.
    let window = |n: u32| -> Duration { BACKOFF_BASE.saturating_mul(1 << n).min(BACKOFF_CAP) };
    let in_window = |d: Duration, n: u32| {
        let full = window(n);
        assert!(
            d >= full / 2 && d <= full,
            "refusal {} paused {d:?}, outside [{:?}, {full:?}]",
            n + 1,
            full / 2
        );
    };

    in_window(answer(&mut s, 1, true), 0);
    in_window(answer(&mut s, 2, true), 1);
    in_window(answer(&mut s, 3, true), 2);

    // A good answer resets the exponent.
    assert_eq!(answer(&mut s, 4, false), Duration::ZERO, "no pause");
    in_window(answer(&mut s, 5, true), 0);

    // And the pause is really jittered, not merely inside a window a fixed delay would also satisfy. A fresh session
    // per sample, since an unanswered reissue would hold its slot.
    let first_pause = |n: u64| -> Duration {
        let mut s = session();
        let args = RawValue::from_string("[]".to_owned()).unwrap();
        let acts = s
            .submit(crate::CallId(n), Kind::User, "core.ping", &args, None)
            .expect("submits");
        let body = refusal(&sent_id(&acts));
        let len = body.len();
        s.on_frame(head(true, OP_TEXT, len), body.into_bytes());
        let t0 = Instant::now();
        s.expire(t0);
        s.next_deadline().map_or(Duration::ZERO, |t| t - t0)
    };
    let seen: Vec<Duration> = (0..8u64).map(first_pause).collect();
    assert!(
        seen.iter().any(|d| *d != seen[0]),
        "eight first-step pauses were all {:?}: no jitter",
        seen[0]
    );
}

/// A peer that answers an id it was never sent is refused, not believed. Crediting it would hand the caller a
/// fabricated result and send the call with no `pending` entry.
#[test]
fn an_answer_for_a_never_sent_call_is_refused() {
    use serde_json::value::RawValue;
    let mut s = session();
    let args = RawValue::from_string("[]".to_owned()).unwrap();

    // Fill the budget, then one more so it is queued rather than sent.
    for i in 0..CALL_BUDGET {
        let acts = s
            .submit(crate::CallId(100 + i as u64), Kind::User, "core.ping", &args, None)
            .expect("submits under budget");
        assert!(matches!(acts.as_slice(), [Act::Send(_)]), "call {i}");
    }
    let acts = s
        .submit(crate::CallId(999), Kind::User, "core.ping", &args, None)
        .expect("submits");
    assert!(acts.is_empty(), "the ninth call is queued, not sent");
    assert_eq!(s.backlog.len(), 1);
    let queued_id = s.backlog.front().expect("a queued frame").0.clone();
    let budget_before = s.budget;

    // The peer answers the id it has not been sent.
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": queued_id,
        "result": "early",
    })
    .to_string();
    let len = body.len();
    let acts = s.on_frame(head(true, OP_TEXT, len), body.into_bytes());

    assert!(
        matches!(acts.as_slice(), [Act::Fault(_)]),
        "an answer for a call never sent is a protocol fault: {acts:?}"
    );
    assert_eq!(
        s.budget, budget_before,
        "no slot is credited for a call that never spent one"
    );
}

/// §7.4.1: 1005 is a reserved value an endpoint MUST NOT set as a status code, so the echo answers 1002 while the
/// report still names what the peer actually sent. Same for a malformed one-byte body and a reason that is not
/// UTF-8 (§5.5.1, §8.1).
#[test]
fn a_close_code_no_endpoint_may_send_is_not_echoed_back() {
    for code in [1004u16, 1005, 1006, 1015, 0, 2999] {
        let mut s = session();
        let acts = s.on_frame(head(true, OP_CLOSE, 2), code.to_be_bytes().to_vec());
        match acts.first() {
            Some(Act::Send(frame)) => {
                let (op, payload) = unmask(frame);
                assert_eq!(op, OP_CLOSE);
                assert_eq!(
                    payload,
                    1002u16.to_be_bytes().to_vec(),
                    "peer sent {code}; the echo must be 1002"
                );
            }
            other => panic!("expected a close echo, got {other:?}"),
        }
        assert!(
            s.close_reason.as_deref().is_some_and(|r| r.contains(&code.to_string())),
            "the report still names {code}: {:?}",
            s.close_reason
        );
    }
    // A one-byte body is not a code (§5.5.1).
    let mut s = session();
    let acts = s.on_frame(head(true, OP_CLOSE, 1), vec![0x03]);
    match acts.first() {
        Some(Act::Send(frame)) => {
            assert_eq!(unmask(frame).1, 1002u16.to_be_bytes().to_vec());
        }
        other => panic!("expected a close echo, got {other:?}"),
    }
    assert!(
        s.close_reason.as_deref().is_some_and(|r| r.contains("malformed")),
        "a one-byte body is reported as malformed: {:?}",
        s.close_reason
    );
    // A non-UTF-8 reason is answered 1007, not echoed as 1000.
    let mut s = session();
    let mut body = 1000u16.to_be_bytes().to_vec();
    body.extend_from_slice(&[0xFF, 0xFE, 0x80]);
    let acts = s.on_frame(head(true, OP_CLOSE, body.len()), body);
    match acts.first() {
        Some(Act::Send(frame)) => {
            assert_eq!(unmask(frame).1, 1007u16.to_be_bytes().to_vec());
        }
        other => panic!("expected a close echo, got {other:?}"),
    }
}
