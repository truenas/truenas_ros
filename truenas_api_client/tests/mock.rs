//! Integration tests against a scripted mock middlewared (see `support/mod.rs`): a real `ApiClient` on a real io_uring
//! ring dialing a real unix socket, with the server side canned. Every scenario's mock asserts the two standing
//! invariants on every frame it reads - client frames are masked, call params are Arrays - so any test that elicits a
//! violation fails at its join.
//!
//! Skips (loudly under `TRUENAS_ROS_REQUIRE_IO_URING`) when io_uring is unavailable, exactly like the parent crate's
//! net tests.

mod support;

use serde_json::{Value, json};
use std::time::Duration;
use support::{Mock, Wire, serve, serve_one};
use truenas_api_client::{
    ApiClient, ApiConfig, ApiError, ApiEvent, CALL_BUDGET, HandshakeError, MAX_CALL_RETRIES, MIN_API_VERSION,
    SessionOpts, params, validate_endpoint,
};

/// The scenario-default config against `mock`'s socket.
fn config(mock: &Mock) -> ApiConfig {
    ApiConfig {
        socket_path: mock.path.clone(),
        connect_timeout: Some(Duration::from_secs(10)),
        ..ApiConfig::default()
    }
}

/// The environment-skip discipline: io_uring absent is a skip, unless CI armed the REQUIRE variable; anything else is a
/// real failure.
fn client_or_skip_cfg(cfg: ApiConfig) -> Option<ApiClient> {
    match ApiClient::new(cfg) {
        Ok(c) => Some(c),
        Err(ApiError::Io(e)) => {
            assert!(
                matches!(
                    e.raw_os_error(),
                    Some(libc::EPERM | libc::ENOSYS | libc::EACCES | libc::ENOMEM)
                ),
                "ring setup failed for a non-environmental reason: {e}"
            );
            assert!(
                std::env::var_os("TRUENAS_ROS_REQUIRE_IO_URING").is_none(),
                "TRUENAS_ROS_REQUIRE_IO_URING set but io_uring unavailable: {e}"
            );
            None
        }
        Err(e) => panic!("ApiClient::new: {e}"),
    }
}

fn client_or_skip(mock: &Mock) -> Option<ApiClient> {
    client_or_skip_cfg(config(mock))
}

/// Close a session and pump the client until the teardown completes. `close` only *queues* the WebSocket close frame;
/// the pump is what flushes it (so a mock blocked on `expect_close` unblocks) and reaps the transport close.
fn shutdown(api: &mut ApiClient, sid: truenas_api_client::SessionId) {
    api.close(sid);
    while api.is_open(sid) {
        match api.pump(Some(Duration::from_secs(10))).expect("pump to close") {
            Some(_) => {}
            None => break,
        }
    }
}

/// The whole happy path: dial, upgrade, session setup observed first on the wire, one call, one typed answer.
#[test]
fn handshake_and_ping() {
    let mock = serve_one(|mut w: Wire| {
        w.accept_session("/api/current");
        let (id, params) = w.expect_call("core.ping");
        assert_eq!(params, json!([]));
        w.respond_ok(&id, json!("pong"));
    });
    let Some(mut api) = client_or_skip(&mock) else {
        return;
    };
    let sid = api.connect(SessionOpts::default()).expect("connect");
    let pong: String = api.call(sid, "core.ping", &params!()).expect("ping");
    assert_eq!(pong, "pong");
    shutdown(&mut api, sid);
    mock.join();
}

/// A non-101 answer surfaces as the status it was, not a bare close.
#[test]
fn non_101_fails_connect() {
    let mock = serve_one(|mut w: Wire| {
        w.refuse_upgrade("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n");
    });
    let Some(mut api) = client_or_skip(&mock) else {
        return;
    };
    match api.connect(SessionOpts::default()) {
        Err(ApiError::Handshake(HandshakeError::NotSwitching { status, reason })) => {
            assert_eq!(status, 404);
            assert_eq!(reason, "Not Found");
        }
        other => panic!("expected NotSwitching, got {other:?}"),
    }
    mock.join();
}

/// A 101 whose accept digest is wrong is a refused session - the peer did not parse our key.
#[test]
fn bad_accept_fails_connect() {
    let mock = serve_one(|mut w: Wire| {
        w.accept_with_bad_digest();
    });
    let Some(mut api) = client_or_skip(&mock) else {
        return;
    };
    match api.connect(SessionOpts::default()) {
        Err(ApiError::Handshake(HandshakeError::BadAccept)) => {}
        other => panic!("expected BadAccept, got {other:?}"),
    }
    mock.join();
}

/// middlewared's -32001 payload decodes into the typed CallError, and a -32000 is its own retryable variant.
///
/// A `-32000` is reissued rather than reported, so the caller only hears about it once the reissues are spent - which
/// is what the repeated refusals below are: the same call arriving again, under its own id, after each backoff.
#[test]
fn call_error_envelope() {
    let mock = serve_one(|mut w: Wire| {
        w.accept_session("/api/current");
        let (id, _) = w.expect_call("pool.create");
        w.respond_err(
            &id,
            -32001,
            "Method call error",
            Some(json!({
                "error": 1,
                "errname": "EPERM",
                "reason": "not allowed",
                "trace": {
                    "class": "CallError",
                    "formatted": "Traceback ...",
                    "repr": "CallError()",
                    "frames": []
                },
                "extra": [["pool_create.name", "Invalid name", 22]]
            })),
        );
        // Refuse every reissue, then one more: the last is the one the caller is told about.
        for _ in 0..=MAX_CALL_RETRIES {
            let (id, _) = w.expect_call("pool.create");
            w.respond_err(&id, -32000, "Too many concurrent calls", None);
        }
    });
    let Some(mut api) = client_or_skip(&mock) else {
        return;
    };
    let sid = api.connect(SessionOpts::default()).expect("connect");

    match api.call::<_, Value>(sid, "pool.create", &params!()) {
        Err(ApiError::Call(e)) => {
            assert_eq!(e.message, "Method call error");
            assert_eq!(e.errno, Some(1));
            assert_eq!(e.errname.as_deref(), Some("EPERM"));
            assert_eq!(e.reason.as_deref(), Some("not allowed"));
            let trace = e.trace.expect("trace");
            assert_eq!(trace.class.as_deref(), Some("CallError"));
            let extra = e.extra.expect("extra");
            assert_eq!(extra[0].0, "pool_create.name");
            assert_eq!(extra[0].2, 22);
        }
        other => panic!("expected Call, got {other:?}"),
    }
    match api.call::<_, Value>(sid, "pool.create", &params!()) {
        Err(ApiError::TooManyConcurrentCalls { .. }) => {}
        other => panic!("expected TooManyConcurrentCalls, got {other:?}"),
    }
    shutdown(&mut api, sid);
    mock.join();
}

/// collection_update and notify_unsubscribed decode and dispatch - both carry *named* params (middlewared notifies
/// by-name even though it rejects by-name inbound).
#[test]
fn notification_dispatch() {
    let mock = serve_one(|mut w: Wire| {
        w.accept_session("/api/current");
        w.send_notification(
            "collection_update",
            json!({
                "msg": "changed",
                "collection": "core.get_jobs",
                "id": 17,
                "fields": { "state": "RUNNING", "progress": 40 }
            }),
        );
        w.send_notification(
            "notify_unsubscribed",
            json!({ "collection": "core.get_jobs", "error": null }),
        );
        // A notification this client does not model: surfaced, not fatal.
        w.send_notification("something_new", json!({ "x": 1 }));
        // Prove the session survived all three.
        let (id, _) = w.expect_call("core.ping");
        w.respond_ok(&id, json!("pong"));
    });
    let Some(mut api) = client_or_skip(&mock) else {
        return;
    };
    let sid = api.connect(SessionOpts::default()).expect("connect");

    match api.pump(Some(Duration::from_secs(10))).expect("pump") {
        Some(ApiEvent::CollectionUpdate { session, update }) => {
            assert_eq!(session, sid);
            assert_eq!(update.msg, "changed");
            assert_eq!(update.collection, "core.get_jobs");
            assert_eq!(update.id, Some(json!(17)));
            assert_eq!(update.fields.as_ref().and_then(|f| f.get("progress")), Some(&json!(40)));
        }
        other => panic!("expected CollectionUpdate, got {other:?}"),
    }
    match api.pump(Some(Duration::from_secs(10))).expect("pump") {
        Some(ApiEvent::SubscriptionEnded {
            session,
            collection,
            error,
        }) => {
            assert_eq!(session, sid);
            assert_eq!(collection, "core.get_jobs");
            assert_eq!(error, None);
        }
        other => panic!("expected SubscriptionEnded, got {other:?}"),
    }
    match api.pump(Some(Duration::from_secs(10))).expect("pump") {
        Some(ApiEvent::Notification { method, params, .. }) => {
            assert_eq!(method, "something_new");
            assert_eq!(params, Some(json!({ "x": 1 })));
        }
        other => panic!("expected Notification, got {other:?}"),
    }
    let pong: String = api.call(sid, "core.ping", &params!()).expect("ping");
    assert_eq!(pong, "pong");
    shutdown(&mut api, sid);
    mock.join();
}

/// Unprompted pushes flow with zero calls in flight - the API-level twin of the parent crate's read-gate liveness pin.
#[test]
fn notifications_flow_without_calls() {
    const PUSHES: usize = 5;
    let mock = serve_one(|mut w: Wire| {
        w.accept_session("/api/current");
        for i in 0..PUSHES {
            w.send_notification(
                "collection_update",
                json!({ "msg": "added", "collection": "test.seq", "id": i }),
            );
        }
    });
    let Some(mut api) = client_or_skip(&mock) else {
        return;
    };
    let sid = api.connect(SessionOpts::default()).expect("connect");
    for i in 0..PUSHES {
        match api.pump(Some(Duration::from_secs(10))).expect("pump") {
            Some(ApiEvent::CollectionUpdate { update, .. }) => {
                assert_eq!(update.id, Some(json!(i)), "push order");
            }
            other => panic!("expected update {i}, got {other:?}"),
        }
    }
    shutdown(&mut api, sid);
    mock.join();
}

/// A multi-megabyte single-frame result (64-bit length form) arrives intact through the placement path.
#[test]
fn big_inbound_frame() {
    const BIG: usize = 8 * 1024 * 1024;
    let mock = serve_one(move |mut w: Wire| {
        w.accept_session("/api/current");
        let (id, _) = w.expect_call("config.download");
        let blob = "x".repeat(BIG);
        w.respond_ok(&id, Value::String(blob));
    });
    let Some(mut api) = client_or_skip(&mock) else {
        return;
    };
    let sid = api.connect(SessionOpts::default()).expect("connect");
    let got: String = api.call(sid, "config.download", &params!()).expect("call");
    assert_eq!(got.len(), BIG);
    assert!(got.bytes().all(|b| b == b'x'));
    shutdown(&mut api, sid);
    mock.join();
}

/// A response fragmented across three continuations, with a ping injected between fragments: the pong goes out
/// mid-reassembly and the reassembled message completes the call.
#[test]
fn fragmented_message_with_interleaved_ping() {
    let mock = serve_one(|mut w: Wire| {
        w.accept_session("/api/current");
        let (id, _) = w.expect_call("core.ping");
        let msg = json!({ "jsonrpc": "2.0", "result": "pong", "id": id }).to_string();
        let bytes = msg.as_bytes();
        let (a, rest) = bytes.split_at(bytes.len() / 3);
        let (b, c) = rest.split_at(rest.len() / 2);
        w.send_frame(0x1, false, a);
        w.send_ping(b"mid-frag");
        w.send_frame(0x0, false, b);
        w.send_frame(0x0, true, c);
        // The pong must arrive (read_text_json would also skip it; read the frame explicitly to assert its payload
        // echoes).
        let (opcode, _fin, payload) = w.read_frame();
        assert_eq!(opcode, 0xA, "a pong answers the ping");
        assert_eq!(payload, b"mid-frag");
    });
    let Some(mut api) = client_or_skip(&mock) else {
        return;
    };
    let sid = api.connect(SessionOpts::default()).expect("connect");
    let pong: String = api.call(sid, "core.ping", &params!()).expect("call");
    assert_eq!(pong, "pong");
    shutdown(&mut api, sid);
    mock.join();
}

/// A hundred pings answered without wedging anything - the `awaiting`-FIFO analysis pinned at the API level - and a
/// call still round-trips afterwards.
#[test]
fn ping_flood_never_wedges() {
    const FLOOD: usize = 100;
    let mock = serve_one(|mut w: Wire| {
        w.accept_session("/api/current");
        for i in 0..FLOOD {
            w.send_ping(format!("{i}").as_bytes());
        }
        let (id, _) = w.drain_pongs_and_one_call(FLOOD, "core.ping");
        w.respond_ok(&id, json!("pong"));
    });
    let Some(mut api) = client_or_skip(&mock) else {
        return;
    };
    let sid = api.connect(SessionOpts::default()).expect("connect");
    let pong: String = api.call(sid, "core.ping", &params!()).expect("call");
    assert_eq!(pong, "pong");
    shutdown(&mut api, sid);
    mock.join();
}

/// An oversized outbound message is refused before the wire - middlewared would close the whole connection - and the
/// session keeps serving.
///
/// The method has to be one middlewared does *not* exempt: it grants the extended cap per method, after parsing, so 70
/// KiB under `filesystem.file_receive` is a message the server accepts and this client must not refuse.
#[test]
fn oversize_outbound_refused() {
    let mock = serve_one(|mut w: Wire| {
        w.accept_session("/api/current");
        // Nothing else arrives before the survival probe.
        let (id, _) = w.expect_call("core.ping");
        w.respond_ok(&id, json!("pong"));
    });
    let Some(mut api) = client_or_skip(&mock) else {
        return;
    };
    let sid = api.connect(SessionOpts::default()).expect("connect");
    let big = "y".repeat(70 * 1024);
    match api.call_start(sid, "pool.dataset.create", &params!(big)) {
        Err(ApiError::TooLarge { len, cap }) => {
            assert!(len > cap);
            assert_eq!(cap, truenas_api_client::MIDDLEWARE_MSG_CAP);
        }
        other => panic!("expected TooLarge, got {other:?}"),
    }
    let pong: String = api.call(sid, "core.ping", &params!()).expect("call");
    assert_eq!(pong, "pong");
    shutdown(&mut api, sid);
    mock.join();
}

/// The server killing the connection mid-call (the close 1009 shape) fails the call with the close reason and surfaces
/// the session's end.
#[test]
fn server_close_mid_call() {
    let mock = serve_one(|mut w: Wire| {
        w.accept_session("/api/current");
        let (_id, _) = w.expect_call("some.method");
        w.send_close(1009, "Max message length is 64 kB");
        // The client echoes the close before its FIN.
        w.expect_close();
    });
    let Some(mut api) = client_or_skip(&mock) else {
        return;
    };
    let sid = api.connect(SessionOpts::default()).expect("connect");
    match api.call::<_, Value>(sid, "some.method", &params!()) {
        Err(ApiError::Closed { reason }) => {
            assert!(reason.contains("1009"), "reason names the code: {reason}");
        }
        other => panic!("expected Closed, got {other:?}"),
    }
    match api.pump(Some(Duration::from_secs(10))).expect("pump") {
        Some(ApiEvent::SessionClosed { session, reason }) => {
            assert_eq!(session, sid);
            assert!(reason.contains("1009"));
        }
        other => panic!("expected SessionClosed, got {other:?}"),
    }
    assert!(!api.is_open(sid));
    mock.join();
}

/// A timed-out call surfaces `Timeout`, its late answer is dropped silently, and the session keeps working.
///
/// The mock never *withholds* the fresh call's answer - a mock is sequential, so sleeping before reading the fresh call
/// would time the fresh call out too, which is a test artifact, not the behavior under test. Instead it reads the slow
/// call, waits for the fresh call (the client sends it only after the slow one times out), answers the fresh one at
/// once, and answers the slow one *late* - the abandoned answer the session must swallow.
#[test]
fn call_timeout_abandons() {
    let mock = serve_one(|mut w: Wire| {
        w.accept_session("/api/current");
        let (slow_id, _) = w.expect_call("slow.method");
        // Blocks until the client, having abandoned the slow call, sends this one - so answering it now is well inside
        // its own deadline.
        let (fresh_id, _) = w.expect_call("fast.method");
        w.respond_ok(&fresh_id, json!("fresh"));
        // The abandoned call's answer, arriving after the client gave up.
        w.respond_ok(&slow_id, json!("late"));
        // Stay up until the client closes, so a mock-initiated EOF does not race the "late answer is swallowed" check
        // with a SessionClosed.
        w.expect_close();
    });
    let cfg = ApiConfig {
        call_timeout: Some(Duration::from_millis(200)),
        ..config(&mock)
    };
    let Some(mut api) = client_or_skip_cfg(cfg) else {
        return;
    };
    let sid = api.connect(SessionOpts::default()).expect("connect");

    match api.call::<_, Value>(sid, "slow.method", &params!()) {
        Err(ApiError::Timeout) => {}
        other => panic!("expected Timeout, got {other:?}"),
    }
    let fresh: String = api.call(sid, "fast.method", &params!()).expect("fresh call");
    assert_eq!(fresh, "fresh");
    // The late answer to the abandoned call is swallowed: pumping now surfaces no CallDone (the session stays open -
    // the mock holds it until we close).
    match api.pump(Some(Duration::from_millis(200))).expect("pump") {
        None => {}
        Some(ApiEvent::CallDone { .. }) => {
            panic!("the abandoned call's late answer leaked a CallDone")
        }
        Some(other) => panic!("unexpected event: {other:?}"),
    }
    shutdown(&mut api, sid);
    mock.join();
}

/// The per-session legacy opt-out: no core.set_options on the wire, and a job method's result is the bare integer job
/// id.
#[test]
fn job_id_when_legacy() {
    let mock = serve_one(|mut w: Wire| {
        w.accept_upgrade("/api/current");
        // The FIRST call must be the job itself - an expect_call of it fails if a set_options snuck in ahead.
        let (id, _) = w.expect_call("update.run");
        w.respond_ok(&id, json!(42));
    });
    let Some(mut api) = client_or_skip(&mock) else {
        return;
    };
    let sid = api.connect(SessionOpts::default().legacy_jobs()).expect("connect");
    let job: i64 = api.call(sid, "update.run", &params!()).expect("job call");
    assert_eq!(job, 42);
    shutdown(&mut api, sid);
    mock.join();
}

/// Two sessions on one client: answers and events route by session, and a slow call on one never blocks the other.
#[test]
fn multi_session_isolation() {
    let (unblock_tx, unblock_rx) = std::sync::mpsc::channel::<()>();
    let scripts: Vec<Box<dyn FnOnce(Wire) + Send>> = vec![
        Box::new(move |mut w: Wire| {
            w.accept_session("/api/current");
            let (id, _) = w.expect_call("slow.method");
            // Hold the answer until the fast session finished.
            unblock_rx
                .recv_timeout(Duration::from_secs(10))
                .expect("fast session finished first");
            w.respond_ok(&id, json!("slow-done"));
            // Stay up until the client closes, so the reply is not raced by a mock-initiated EOF (which would surface
            // as a SessionClosed ahead of the CallDone).
            w.expect_close();
        }),
        Box::new(move |mut w: Wire| {
            w.accept_session("/api/current");
            let (id, _) = w.expect_call("fast.method");
            w.respond_ok(&id, json!("fast-done"));
            let _ = unblock_tx.send(());
            w.expect_close();
        }),
    ];
    let mock = serve(scripts);
    let Some(mut api) = client_or_skip(&mock) else {
        return;
    };
    let s1 = api.connect(SessionOpts::default()).expect("s1");
    let s2 = api.connect(SessionOpts::default()).expect("s2");

    let slow = api.call_start(s1, "slow.method", &params!()).expect("start");
    let fast: String = api.call(s2, "fast.method", &params!()).expect("fast call");
    assert_eq!(fast, "fast-done");

    match api.pump(Some(Duration::from_secs(10))).expect("pump") {
        Some(ApiEvent::CallDone { call, result }) => {
            assert_eq!(call, slow);
            let got: String = result.expect("slow ok").decode().expect("str");
            assert_eq!(got, "slow-done");
        }
        other => panic!("expected the slow CallDone, got {other:?}"),
    }
    shutdown(&mut api, s1);
    shutdown(&mut api, s2);
    mock.join();
}

/// subscribe/unsubscribe round-trip: the server ident is held internally, events dispatch while subscribed, and the
/// unsubscribe carries the same ident back.
#[test]
fn subscribe_unsubscribe_round_trip() {
    let mock = serve_one(|mut w: Wire| {
        w.accept_session("/api/current");
        let (id, params) = w.expect_call("core.subscribe");
        assert_eq!(params, json!(["core.get_jobs"]));
        w.respond_ok(&id, json!("11111111-2222-3333-4444-555555555555"));
        w.send_notification(
            "collection_update",
            json!({ "msg": "added", "collection": "core.get_jobs", "id": 1 }),
        );
        let (id, params) = w.expect_call("core.unsubscribe");
        assert_eq!(
            params,
            json!(["11111111-2222-3333-4444-555555555555"]),
            "the unsubscribe names the server's ident"
        );
        w.respond_ok(&id, json!(null));
    });
    let Some(mut api) = client_or_skip(&mock) else {
        return;
    };
    let sid = api.connect(SessionOpts::default()).expect("connect");

    let call = api.subscribe_start(sid, "core.get_jobs").expect("subscribe");
    let sub = match api.pump(Some(Duration::from_secs(10))).expect("pump") {
        Some(ApiEvent::SubscriptionReady { call: c, sub }) => {
            assert_eq!(c, call);
            sub
        }
        other => panic!("expected SubscriptionReady, got {other:?}"),
    };
    match api.pump(Some(Duration::from_secs(10))).expect("pump") {
        Some(ApiEvent::CollectionUpdate { update, .. }) => {
            assert_eq!(update.msg, "added");
        }
        other => panic!("expected CollectionUpdate, got {other:?}"),
    }
    let call = api.unsubscribe_start(sid, sub).expect("unsubscribe");
    match api.pump(Some(Duration::from_secs(10))).expect("pump") {
        Some(ApiEvent::Unsubscribed { call: c, sub: s }) => {
            assert_eq!(c, call);
            assert_eq!(s, sub);
        }
        other => panic!("expected Unsubscribed, got {other:?}"),
    }
    shutdown(&mut api, sid);
    mock.join();
}

/// call_start returns before any answer exists, and completions arrive through the pump - the non-blocking contract,
/// pinned.
#[test]
fn call_start_is_non_blocking() {
    let (got_call_tx, got_call_rx) = std::sync::mpsc::channel::<()>();
    let (answer_tx, answer_rx) = std::sync::mpsc::channel::<()>();
    let mock = serve_one(move |mut w: Wire| {
        w.accept_session("/api/current");
        let (id, _) = w.expect_call("core.ping");
        let _ = got_call_tx.send(());
        answer_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("test signals the answer");
        w.respond_ok(&id, json!("pong"));
    });
    let Some(mut api) = client_or_skip(&mock) else {
        return;
    };
    let sid = api.connect(SessionOpts::default()).expect("connect");

    let call = api.call_start(sid, "core.ping", &params!()).expect("start");
    // Not yet answered: the mock is holding the reply hostage. Pump long enough for the send to flush so the mock can
    // even see the call.
    while got_call_rx.try_recv().is_err() {
        assert!(
            api.pump(Some(Duration::from_millis(50))).expect("pump").is_none(),
            "no event can exist before the mock answers"
        );
    }
    answer_tx.send(()).expect("mock alive");
    match api.pump(Some(Duration::from_secs(10))).expect("pump") {
        Some(ApiEvent::CallDone { call: c, result }) => {
            assert_eq!(c, call);
            let pong: String = result.expect("ok").decode().expect("str");
            assert_eq!(pong, "pong");
        }
        other => panic!("expected CallDone, got {other:?}"),
    }
    shutdown(&mut api, sid);
    mock.join();
}

/// A timed-out call returns its concurrency slot. `CALL_BUDGET` calls the server never answers, all timed out locally,
/// must not leave the session unable to send anything further: the caller has just been handed `Timeout` for each and
/// is entitled to issue more.
///
/// Under the defect this covers, the call after the timeouts is accepted (`call_start` answers `Ok`) but never reaches
/// the wire, so the mock's `expect_call("after.timeouts")` reads the close frame instead and panics - a failure, not a
/// hang.
#[test]
fn a_timed_out_call_returns_its_budget_slot() {
    let mock = serve_one(|mut w: Wire| {
        w.accept_session("/api/current");
        // Fill the budget and answer none of it.
        let ids: Vec<_> = (0..CALL_BUDGET).map(|_| w.expect_call("core.ping").0).collect();
        // A call issued after every one of those timed out must NOT reach the wire: this server is still holding all
        // eight, and being told nothing by the client giving up.
        // Long enough to cover the client's submission (which follows the 250 ms timeouts) and short enough that the
        // answer below still beats that submission's own deadline.
        let quiet = w.count_client_text_frames_until_quiet(Duration::from_millis(350));
        assert_eq!(quiet, 0, "the client sent more while the server held every slot");
        // Answering one is what frees a slot - and the tombstone for that long-abandoned call must still correlate, or
        // this answer faults the session instead of releasing the queue.
        w.respond_ok(&ids[0], json!(null));
        let (id, _) = w.expect_call("after.timeouts");
        w.respond_ok(&id, json!("sent-after-a-slot-came-back"));
        w.expect_close();
    });
    let cfg = ApiConfig {
        call_timeout: Some(Duration::from_millis(250)),
        ..config(&mock)
    };
    let Some(mut api) = client_or_skip_cfg(cfg) else {
        return;
    };
    let sid = api.connect(SessionOpts::default()).expect("connect");

    for _ in 0..CALL_BUDGET {
        api.call_start(sid, "core.ping", &params!()).expect("start");
    }
    let mut timeouts = 0;
    while timeouts < CALL_BUDGET {
        match api.pump(Some(Duration::from_secs(10))).expect("pump") {
            Some(ApiEvent::CallDone {
                result: Err(ApiError::Timeout),
                ..
            }) => {
                timeouts += 1;
            }
            Some(_) => {}
            None => break,
        }
    }
    assert_eq!(timeouts, CALL_BUDGET, "every filled call timed out");

    let after = api
        .call_start(sid, "after.timeouts", &params!())
        .expect("a call after the timeouts");
    loop {
        match api.pump(Some(Duration::from_secs(10))).expect("pump") {
            Some(ApiEvent::CallDone { call, result }) if call == after => {
                let got: String = result.expect("answered").decode().expect("a string");
                assert_eq!(got, "sent-after-a-slot-came-back");
                break;
            }
            Some(_) => {}
            None => {
                panic!("the call after the timeouts never reached the wire")
            }
        }
    }
    shutdown(&mut api, sid);
    mock.join();
}

/// `core.set_options`' answer is the authority on what is in force, not the request. A server that answers
/// `legacy_jobs: true` after this session asked for modern answering must fail setup, because every job call's result
/// would then be the job's integer id where the caller expects the job's result — a silently wrong value, not an error.
///
/// The reference Python client reads the same echo (`truenas/api_client`, the `_set_options_call` arm) rather than
/// trusting its own request.
#[test]
fn a_set_options_echo_contradicting_the_request_fails_setup() {
    let mock = serve_one(|mut w: Wire| {
        w.accept_upgrade("/api/current");
        let (id, params) = w.expect_call("core.set_options");
        assert_eq!(params, json!([{ "legacy_jobs": false }]));
        // The server did not honour it.
        w.respond_ok(&id, json!({ "legacy_jobs": true }));
    });
    let Some(mut api) = client_or_skip(&mock) else {
        return;
    };
    match api.connect(SessionOpts::default()) {
        Err(ApiError::Protocol(what)) => {
            assert!(what.contains("legacy_jobs"), "the refusal names the option: {what}");
        }
        other => panic!("expected a Protocol refusal, got {other:?}"),
    }
}

/// A silent echo is a refusal too, and for a sharper reason than a contradicting one: every API version that honours
/// `legacy_jobs` answers with a required object, so the only versions that answer nothing are the ones that dropped the
/// option and left `App.legacy_jobs` at `true`. Proceeding there decodes every job's integer id as the caller's result.
#[test]
fn a_set_options_echo_without_the_member_fails_setup() {
    for echo in [json!(null), json!({ "py_exceptions": false })] {
        let mock = serve_one(move |mut w: Wire| {
            w.accept_upgrade("/api/current");
            let (id, _) = w.expect_call("core.set_options");
            w.respond_ok(&id, echo.clone());
        });
        let Some(mut api) = client_or_skip(&mock) else {
            return;
        };
        match api.connect(SessionOpts::default()) {
            Err(ApiError::Protocol(what)) => {
                assert!(what.contains("legacy_jobs"), "the refusal names the option: {what}")
            }
            other => panic!("expected a Protocol refusal, got {other:?}"),
        }
    }
}

/// The positive control for both refusals above: the echo middlewared actually sends opens the session and serves a
/// call.
#[test]
fn the_echo_middlewared_sends_opens_the_session() {
    let mock = serve_one(|mut w: Wire| {
        w.accept_session("/api/current");
        let (id, _) = w.expect_call("core.ping");
        w.respond_ok(&id, json!("pong"));
        w.expect_close();
    });
    let Some(mut api) = client_or_skip(&mock) else {
        return;
    };
    let sid = api.connect(SessionOpts::default()).expect("the real echo");
    let pong: String = api.call(sid, "core.ping", &params!()).expect("ping");
    assert_eq!(pong, "pong");
    shutdown(&mut api, sid);
    mock.join();
}

/// A `{:?}` on an event is how a consumer's log gets written, and a method's result is whatever it asked middlewared
/// for. Report the size, not the content - the line middlewared itself draws between the caller and the audit record
/// (`api/base/handler/remove_secrets.py`).
#[test]
fn debug_on_an_event_does_not_print_the_server_result() {
    const SECRET: &str = "s3cr3t-token-do-not-log";
    let mock = serve_one(|mut w: Wire| {
        w.accept_session("/api/current");
        let (id, _) = w.expect_call("auth.generate_token");
        w.respond_ok(&id, json!({ "token": SECRET }));
        w.send_notification(
            "collection_update",
            json!({
                "msg": "changed",
                "collection": "core.get_jobs",
                "id": 1,
                "fields": { "result": SECRET },
            }),
        );
        w.expect_close();
    });
    let Some(mut api) = client_or_skip(&mock) else {
        return;
    };
    let sid = api.connect(SessionOpts::default()).expect("connect");
    let call = api.call_start(sid, "auth.generate_token", &params!()).expect("send");
    let mut seen_call = false;
    let mut seen_update = false;
    while !(seen_call && seen_update) {
        let Some(ev) = api.pump(Some(Duration::from_secs(10))).expect("pump") else {
            panic!("timed out waiting for both events")
        };
        let printed = format!("{ev:?}");
        assert!(!printed.contains(SECRET), "Debug leaked the payload: {printed}");
        match &ev {
            ApiEvent::CallDone { call: c, result } => {
                assert_eq!(*c, call);
                // The caller's own side still gets the whole thing.
                assert!(
                    result.as_ref().expect("ok").get().contains(SECRET),
                    "the value itself must survive"
                );
                seen_call = true;
            }
            ApiEvent::CollectionUpdate { update, .. } => {
                assert!(
                    update.fields.as_ref().expect("fields").to_string().contains(SECRET),
                    "the value itself must survive"
                );
                seen_update = true;
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }
    shutdown(&mut api, sid);
    mock.join();
}

/// `Instant + Duration` panics on overflow and the durations here are the caller's: `Duration::MAX` is an ordinary way
/// to spell "wait as long as it takes", and a library must not abort the process over it. An unrepresentable deadline
/// is no deadline, which is what `None` already means on every one of these paths.
#[test]
fn an_unrepresentable_timeout_is_no_timeout() {
    let mock = serve_one(|mut w: Wire| {
        w.accept_session("/api/current");
        let (id, _) = w.expect_call("core.ping");
        w.respond_ok(&id, json!("pong"));
        w.expect_close();
    });
    let cfg = ApiConfig {
        connect_timeout: Some(Duration::MAX),
        call_timeout: Some(Duration::MAX),
        ..config(&mock)
    };
    let Some(mut api) = client_or_skip_cfg(cfg) else {
        return;
    };
    let sid = api.connect(SessionOpts::default()).expect("connect");
    // And on `pump`'s own argument: an answer is on its way, so an unrepresentable bound waits for it instead of
    // aborting.
    let call = api.call_start(sid, "core.ping", &params!()).expect("send");
    match api.pump(Some(Duration::MAX)).expect("pump") {
        Some(ApiEvent::CallDone { call: c, result }) => {
            assert_eq!(c, call);
            assert_eq!(result.expect("ok").get(), "\"pong\"");
        }
        other => panic!("expected the ping's answer, got {other:?}"),
    }
    shutdown(&mut api, sid);
    mock.join();
}

/// Every route that removes a session drains `pending` first, so a call the session accepted is answered rather than
/// stranded.
///
/// This is the surviving half of what `Phase::Setup` made unconstructible. `call_start` now refuses until the setup
/// echo lands, so no caller call can be in flight when `Act::SetupFailed` or `Act::Failed` fires - but the property
/// those two routes were given `fail_session` for is about *every* removal route, and `Act::Fault` reaches a session
/// that is fully open with real work outstanding.
///
/// Strand it and `ApiClient::call` waits on a `CallDone` that can never come, for as long as `call_timeout` allows -
/// which is for ever by default. `SessionClosed` does not substitute: `wait_for`'s predicate is per-event, so a
/// session-level report is stashed as a skipped event rather than delivered as the call's answer.
#[test]
fn a_faulted_session_answers_the_call_it_accepted() {
    let mock = serve_one(|mut w: Wire| {
        w.accept_session("/api/current");
        let (_id, _) = w.expect_call("slow.method");
        // An answer naming a call that was never made: JSON-RPC has no reading of it, so the session faults with the
        // real call still outstanding.
        w.respond_ok(&json!(999_999), json!(null));
        let _ = w.read_frame_or_eof();
    });
    let Some(mut api) = client_or_skip(&mock) else {
        return;
    };
    let sid = api.connect(SessionOpts::default()).expect("connect");
    let call = api
        .call_start(sid, "slow.method", &params!())
        .expect("an open session takes the call");

    let mut answered = None;
    let mut closed = false;
    for _ in 0..50 {
        match api.pump(Some(Duration::from_millis(200))) {
            Ok(Some(ApiEvent::CallDone { call: c, result })) if c == call => answered = Some(result),
            Ok(Some(ApiEvent::SessionClosed { session, reason })) => {
                assert_eq!(session, sid);
                assert!(
                    reason.contains("protocol violation"),
                    "the fault names itself: {reason}"
                );
                closed = true;
            }
            Ok(_) => {}
            Err(_) => break,
        }
        if answered.is_some() && closed {
            break;
        }
    }
    assert!(closed, "the session's own failure still surfaces");
    match answered {
        Some(Err(ApiError::Closed { .. })) => {}
        other => panic!("the accepted call must be failed, got {other:?}"),
    }
    assert!(!api.is_open(sid));
    // Dropped before the join: the fault's `close_now` is what gives the script its EOF, and the script is blocked in
    // `read_frame_or_eof` waiting for it.
    drop(api);
    mock.join();
}

/// No caller's call joins a session whose setup has not answered, and a setup that then fails still reports itself.
///
/// `connect_start` promises calls before ready are refused, and the window this closes is the one where they were not:
/// `Phase::Open` used to be set at the `101`, with `core.set_options` still outstanding. In that window the peer's
/// `App.legacy_jobs` is at its default of `true` (`api/base/server/app.py`), so a job method answers with the job's
/// integer id rather than the job's result (`api/base/server/method.py`) - the silent substitution
/// `legacy_jobs_in_force` fails the whole session over when the echo says it.
#[test]
fn no_call_is_accepted_before_setup_answers() {
    let mock = serve_one(|mut w: Wire| {
        w.accept_upgrade("/api/current");
        let (id, _) = w.expect_call("core.set_options");
        // Nothing else may reach the wire before this answer; the client-side assertion below is what proves it, and
        // the params-Array/mask invariants would catch a stray frame here.
        std::thread::sleep(Duration::from_millis(150));
        w.respond_err(&id, -32000, "no options for you", None);
    });
    let Some(mut api) = client_or_skip(&mock) else {
        return;
    };
    let sid = api.connect_start(SessionOpts::default()).expect("dial");

    // Every attempt across the whole setup phase is refused, and the refusal is the one `connect_start` documents.
    let mut failed = false;
    let mut attempts = 0;
    for _ in 0..50 {
        match api.call_start(sid, "core.ping", &params!()) {
            Ok(c) => panic!("a call was accepted before ready: {c:?}"),
            Err(ApiError::Closed { .. }) => attempts += 1,
            // Once the setup failure lands the session is gone, which is the other legitimate refusal.
            Err(ApiError::UnknownSession) => {}
            Err(e) => panic!("unexpected refusal: {e}"),
        }
        match api.pump(Some(Duration::from_millis(20))) {
            Ok(Some(ApiEvent::SessionFailed { session, .. })) => {
                assert_eq!(session, sid);
                failed = true;
                break;
            }
            Ok(Some(ApiEvent::SessionReady(_))) => {
                panic!("the setup was refused; it cannot be ready")
            }
            Ok(_) => {}
            Err(_) => break,
        }
    }
    assert!(failed, "the session's own failure surfaces");
    assert!(attempts > 0, "the refusal path was actually exercised");
    mock.join();
}

/// The deferred queue is bounded in bytes as well as in items. The count is a pipelining depth; each item carries its
/// own encoded params and nothing bounds those at enqueue, so a count alone leaves the queue's memory at the item cap
/// times whatever the caller queues.
#[test]
fn the_deferred_queue_is_bounded_in_bytes_too() {
    let mock = serve_one(|mut w: Wire| {
        w.accept_session("/api/current");
        w.expect_close();
    });
    let cfg = ApiConfig {
        // Room for many items, but only a little memory.
        max_queued_bulk_items: 10_000,
        max_queued_bulk_bytes: 64 * 1024,
        ..config(&mock)
    };
    let Some(mut api) = client_or_skip_cfg(cfg) else {
        return;
    };
    let sid = api.connect(SessionOpts::default()).expect("connect");
    let big = "x".repeat(8 * 1024);
    let mut queued = 0;
    loop {
        match api.queue_bulk(sid, "pool.snapshot", &params!(big.clone())) {
            Ok(_) => queued += 1,
            Err(ApiError::QueueFull { queue, cap }) => {
                assert_eq!(cap, 64 * 1024, "the byte cap is what refused");
                assert!(queue.contains("bytes"), "and it says so: {queue}");
                break;
            }
            other => panic!("unexpected: {other:?}"),
        }
        assert!(
            queued < 100,
            "the byte cap must bite long before the item cap of 10,000"
        );
    }
    api.close(sid);
    while api.is_open(sid) {
        let _ = api.pump(Some(Duration::from_millis(50)));
    }
    mock.join();
}

/// A blocking wait sets aside every event that is not the one it wants, and a subscribed session lets the *peer* decide
/// how many of those there are. Bound it: past the cap the wait fails rather than buffering, and the events set aside
/// are still there for `pump`.
#[test]
fn a_blocking_wait_will_not_buffer_without_bound() {
    const FLOOD: usize = 64;
    let mock = serve_one(|mut w: Wire| {
        w.accept_session("/api/current");
        let (id, _) = w.expect_call("core.ping");
        // Answer only after burying it under notifications.
        for i in 0..FLOOD {
            w.send_notification(
                "collection_update",
                json!({ "msg": "changed", "collection": "c", "id": i }),
            );
        }
        w.respond_ok(&id, json!("pong"));
        w.expect_close();
    });
    let cfg = ApiConfig {
        max_waiting_events: 8,
        ..config(&mock)
    };
    let Some(mut api) = client_or_skip_cfg(cfg) else {
        return;
    };
    let sid = api.connect(SessionOpts::default()).expect("connect");
    match api.call::<_, String>(sid, "core.ping", &params!()) {
        Err(ApiError::QueueFull { queue, cap }) => {
            assert_eq!(cap, 8);
            assert!(
                queue.contains("blocking wait"),
                "the message names the queue that filled: {queue}"
            );
        }
        other => panic!("expected the wait to be bounded, got {other:?}"),
    }
    // What was set aside is still deliverable - the bound refuses the wait, it does not drop the peer's events.
    let mut seen = 0;
    while let Ok(Some(ev)) = api.pump(Some(Duration::from_millis(50))) {
        if matches!(ev, ApiEvent::CollectionUpdate { .. }) {
            seen += 1;
        }
    }
    assert!(seen > 0, "the buffered events survive the refusal");
    api.close(sid);
    while api.is_open(sid) {
        let _ = api.pump(Some(Duration::from_millis(50)));
    }
    mock.join();
}

/// A wait refused by `max_waiting_events` must not be refused again on the events the refusal itself put back.
///
/// `wait_for` restores its set-aside to the front of `self.out`, and `pump` drains `self.out` before it touches the
/// transport. Counting a restored event made the refusal self-sustaining: every later `call` tripped the cap on the
/// previous one's stash without doing any I/O, so a healthy server answering every request could not get an answer
/// through, and the frames those calls had just handed the transport were never flushed.
#[test]
fn a_refused_wait_does_not_refuse_the_calls_that_follow_it() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    const FLOOD: usize = 64;
    const ISSUED: usize = 20;
    let seen = Arc::new(AtomicUsize::new(0));
    let seen_w = seen.clone();
    let mock = serve_one(move |mut w: Wire| {
        w.accept_session("/api/current");
        // The first call reaches the wire before the flood.
        let (_id, _) = w.expect_call("core.ping");
        for i in 0..FLOOD {
            w.send_notification(
                "collection_update",
                json!({ "msg": "changed", "collection": "c", "id": i }),
            );
        }
        // Answer nothing; count every further call that arrives.
        let n = w.count_client_text_frames_until_quiet(Duration::from_millis(900));
        seen_w.store(n + 1, Ordering::SeqCst);
    });
    let cfg = ApiConfig {
        max_waiting_events: 4,
        call_timeout: Some(Duration::from_millis(80)),
        ..config(&mock)
    };
    let Some(mut api) = client_or_skip_cfg(cfg) else {
        return;
    };
    let sid = api.connect(SessionOpts::default()).expect("connect");
    for _ in 0..ISSUED {
        let _ = api.call::<_, String>(sid, "core.ping", &params!());
    }
    // Let the concurrency budget recycle so the backlog drains: the point is that the calls reach the wire at all, not
    // how fast.
    for _ in 0..60 {
        let _ = api.pump(Some(Duration::from_millis(20)));
    }
    mock.join();
    let n = seen.load(Ordering::SeqCst);
    // With the refusal counting its own restored stash, exactly ONE of the twenty ever reached the wire - the wait
    // short-circuited before any I/O, so even the frames already handed to the transport were never flushed.
    //
    // The number that should reach it is the concurrency budget, and no more: this mock answers nothing, and a call the
    // server has not answered is one it is still running, so its slot does not come back when the client times out.
    // What the wedge did is bound this by the *wait* rather than by the budget.
    assert_eq!(
        n, CALL_BUDGET,
        "the concurrency budget is what bounds how many of the {ISSUED} \
         reach the wire, not a refused wait"
    );
}

/// The same, from the caller's side: a healthy server that buries one answer under a flood must still be able to answer
/// the calls that come after, without the caller dropping to `pump`.
#[test]
fn a_flood_does_not_make_call_permanently_unusable() {
    const FLOOD: usize = 64;
    let mock = serve_one(|mut w: Wire| {
        w.accept_session("/api/current");
        let (id, _) = w.expect_call("core.ping");
        for i in 0..FLOOD {
            w.send_notification(
                "collection_update",
                json!({ "msg": "changed", "collection": "c", "id": i }),
            );
        }
        w.respond_ok(&id, json!("pong"));
        for _ in 0..11 {
            let (id, _) = w.expect_call("core.ping");
            w.respond_ok(&id, json!("pong"));
        }
        w.expect_close();
    });
    let cfg = ApiConfig {
        max_waiting_events: 8,
        ..config(&mock)
    };
    let Some(mut api) = client_or_skip_cfg(cfg) else {
        return;
    };
    let sid = api.connect(SessionOpts::default()).expect("connect");
    let mut oks = 0;
    for _ in 0..12 {
        if api.call::<_, String>(sid, "core.ping", &params!()).is_ok() {
            oks += 1;
        }
    }
    assert!(
        oks >= 2,
        "a healthy server answering every ping must not leave call() \
         permanently refused: {oks} of 12 succeeded"
    );
    shutdown(&mut api, sid);
    mock.join();
}

/// The endpoint reaches the wire inside the request line and decides which API version answers, so both refusals happen
/// before the dial - no half-open session, no socket.
#[test]
fn a_refused_endpoint_never_dials() {
    // Nothing is ever accepted here: a refusal that dialled would show up as the script blocking on accept, which
    // `join` would surface.
    let mock = serve(Vec::new());
    let Some(_probe) = client_or_skip(&mock) else {
        return;
    };
    let with = |ep: &str| ApiConfig {
        endpoint: ep.to_owned(),
        ..config(&mock)
    };
    for ep in [
        "/api/current\r\nX-Injected: 1",
        "/api/current HTTP/1.1\r\n\r\nGET /admin",
        "/api/cur rent",
        "api/current",
        "",
    ] {
        let mut api = ApiClient::new(with(ep)).expect("client");
        match api.connect_start(SessionOpts::default()) {
            Err(ApiError::Handshake(HandshakeError::BadTarget { .. })) => {}
            other => panic!("{ep:?} must be refused, got {other:?}"),
        }
    }
    for (ep, want) in [("/api/v25.04.1", (25u32, 4u32, 1u32)), ("/api/v24.10", (24, 10, 0))] {
        let mut api = ApiClient::new(with(ep)).expect("client");
        match api.connect_start(SessionOpts::default()) {
            Err(ApiError::UnsupportedApiVersion { pinned, minimum }) => {
                assert_eq!(pinned, want);
                assert_eq!(minimum, MIN_API_VERSION);
            }
            other => panic!("{ep:?} must be refused, got {other:?}"),
        }
    }
    // What must still pass: `current`, the floor, and a later pin.
    for ep in ["/api/current", "/api/v26.0.0", "/api/v27.0.0", "/ws"] {
        assert!(validate_endpoint(ep).is_ok(), "{ep} must be accepted");
    }
    mock.join();
}

#[path = "mock/bulk.rs"]
mod bulk;
