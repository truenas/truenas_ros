//! Integration tests against a scripted mock middlewared (see
//! `support/mod.rs`): a real `ApiClient` on a real io_uring ring dialing a
//! real unix socket, with the server side canned. Every scenario's mock
//! asserts the two standing invariants on every frame it reads - client
//! frames are masked, call params are Arrays - so any test that elicits a
//! violation fails at its join.
//!
//! Skips (loudly under `TRUENAS_ROS_REQUIRE_IO_URING`) when io_uring is
//! unavailable, exactly like the parent crate's net tests.

mod support;

use serde_json::{Value, json};
use std::time::Duration;
use support::{Mock, Wire, serve, serve_one};
use truenas_api_client::{
    ApiClient, ApiConfig, ApiError, ApiEvent, HandshakeError, SessionOpts,
    params,
};

/// The scenario-default config against `mock`'s socket.
fn config(mock: &Mock) -> ApiConfig {
    ApiConfig {
        socket_path: mock.path.clone(),
        connect_timeout: Some(Duration::from_secs(10)),
        ..ApiConfig::default()
    }
}

/// The environment-skip discipline: io_uring absent is a skip, unless CI
/// armed the REQUIRE variable; anything else is a real failure.
fn client_or_skip_cfg(cfg: ApiConfig) -> Option<ApiClient> {
    match ApiClient::new(cfg) {
        Ok(c) => Some(c),
        Err(ApiError::Io(e)) => {
            assert!(
                matches!(
                    e.raw_os_error(),
                    Some(
                        libc::EPERM
                            | libc::ENOSYS
                            | libc::EACCES
                            | libc::ENOMEM
                    )
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

/// Close a session and pump the client until the teardown completes.
/// `close` only *queues* the WebSocket close frame; the pump is what
/// flushes it (so a mock blocked on `expect_close` unblocks) and reaps the
/// transport close.
fn shutdown(api: &mut ApiClient, sid: truenas_api_client::SessionId) {
    api.close(sid);
    while api.is_open(sid) {
        match api
            .pump(Some(Duration::from_secs(10)))
            .expect("pump to close")
        {
            Some(_) => {}
            None => break,
        }
    }
}

/// The whole happy path: dial, upgrade, session setup observed first on
/// the wire, one call, one typed answer.
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
        Err(ApiError::Handshake(HandshakeError::NotSwitching {
            status,
            reason,
        })) => {
            assert_eq!(status, 404);
            assert_eq!(reason, "Not Found");
        }
        other => panic!("expected NotSwitching, got {other:?}"),
    }
    mock.join();
}

/// A 101 whose accept digest is wrong is a refused session - the peer did
/// not parse our key.
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

/// middlewared's -32001 payload decodes into the typed CallError, and a
/// -32000 is its own retryable variant.
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
        let (id, _) = w.expect_call("pool.create");
        w.respond_err(&id, -32000, "Too many concurrent calls", None);
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

/// collection_update and notify_unsubscribed decode and dispatch - both
/// carry *named* params (middlewared notifies by-name even though it
/// rejects by-name inbound).
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
            assert_eq!(
                update.fields.as_ref().and_then(|f| f.get("progress")),
                Some(&json!(40))
            );
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

/// Unprompted pushes flow with zero calls in flight - the API-level twin
/// of the parent crate's read-gate liveness pin.
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

/// A multi-megabyte single-frame result (64-bit length form) arrives
/// intact through the placement path.
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
    let got: String =
        api.call(sid, "config.download", &params!()).expect("call");
    assert_eq!(got.len(), BIG);
    assert!(got.bytes().all(|b| b == b'x'));
    shutdown(&mut api, sid);
    mock.join();
}

/// A response fragmented across three continuations, with a ping injected
/// between fragments: the pong goes out mid-reassembly and the reassembled
/// message completes the call.
#[test]
fn fragmented_message_with_interleaved_ping() {
    let mock = serve_one(|mut w: Wire| {
        w.accept_session("/api/current");
        let (id, _) = w.expect_call("core.ping");
        let msg =
            json!({ "jsonrpc": "2.0", "result": "pong", "id": id }).to_string();
        let bytes = msg.as_bytes();
        let (a, rest) = bytes.split_at(bytes.len() / 3);
        let (b, c) = rest.split_at(rest.len() / 2);
        w.send_frame(0x1, false, a);
        w.send_ping(b"mid-frag");
        w.send_frame(0x0, false, b);
        w.send_frame(0x0, true, c);
        // The pong must arrive (read_text_json would also skip it; read
        // the frame explicitly to assert its payload echoes).
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

/// A hundred pings answered without wedging anything - the
/// `awaiting`-FIFO analysis pinned at the API level - and a call still
/// round-trips afterwards.
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

/// An oversized outbound message is refused before the wire - middlewared
/// would close the whole connection - and the session keeps serving.
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
    match api.call_start(sid, "filesystem.file_receive", &params!(big)) {
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

/// The server killing the connection mid-call (the close 1009 shape) fails
/// the call with the close reason and surfaces the session's end.
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

/// A timed-out call surfaces `Timeout`, its late answer is dropped
/// silently, and the session keeps working.
///
/// The mock never *withholds* the fresh call's answer - a mock is
/// sequential, so sleeping before reading the fresh call would time the
/// fresh call out too, which is a test artifact, not the behavior under
/// test. Instead it reads the slow call, waits for the fresh call (the
/// client sends it only after the slow one times out), answers the fresh
/// one at once, and answers the slow one *late* - the abandoned answer
/// the session must swallow.
#[test]
fn call_timeout_abandons() {
    let mock = serve_one(|mut w: Wire| {
        w.accept_session("/api/current");
        let (slow_id, _) = w.expect_call("slow.method");
        // Blocks until the client, having abandoned the slow call, sends
        // this one - so answering it now is well inside its own deadline.
        let (fresh_id, _) = w.expect_call("fast.method");
        w.respond_ok(&fresh_id, json!("fresh"));
        // The abandoned call's answer, arriving after the client gave up.
        w.respond_ok(&slow_id, json!("late"));
        // Stay up until the client closes, so a mock-initiated EOF does
        // not race the "late answer is swallowed" check with a
        // SessionClosed.
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
    let fresh: String = api
        .call(sid, "fast.method", &params!())
        .expect("fresh call");
    assert_eq!(fresh, "fresh");
    // The late answer to the abandoned call is swallowed: pumping now
    // surfaces no CallDone (the session stays open - the mock holds it
    // until we close).
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

/// The per-session legacy opt-out: no core.set_options on the wire, and a
/// job method's result is the bare integer job id.
#[test]
fn job_id_when_legacy() {
    let mock = serve_one(|mut w: Wire| {
        w.accept_upgrade("/api/current");
        // The FIRST call must be the job itself - an expect_call of it
        // fails if a set_options snuck in ahead.
        let (id, _) = w.expect_call("update.run");
        w.respond_ok(&id, json!(42));
    });
    let Some(mut api) = client_or_skip(&mock) else {
        return;
    };
    let sid = api
        .connect(SessionOpts::default().legacy_jobs())
        .expect("connect");
    let job: i64 = api.call(sid, "update.run", &params!()).expect("job call");
    assert_eq!(job, 42);
    shutdown(&mut api, sid);
    mock.join();
}

/// Two sessions on one client: answers and events route by session, and a
/// slow call on one never blocks the other.
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
            // Stay up until the client closes, so the reply is not raced
            // by a mock-initiated EOF (which would surface as a
            // SessionClosed ahead of the CallDone).
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

    let slow = api
        .call_start(s1, "slow.method", &params!())
        .expect("start");
    let fast: String =
        api.call(s2, "fast.method", &params!()).expect("fast call");
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

/// subscribe/unsubscribe round-trip: the server ident is held internally,
/// events dispatch while subscribed, and the unsubscribe carries the same
/// ident back.
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

    let call = api
        .subscribe_start(sid, "core.get_jobs")
        .expect("subscribe");
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

/// call_start returns before any answer exists, and completions arrive
/// through the pump - the non-blocking contract, pinned.
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
    // Not yet answered: the mock is holding the reply hostage. Pump long
    // enough for the send to flush so the mock can even see the call.
    while got_call_rx.try_recv().is_err() {
        assert!(
            api.pump(Some(Duration::from_millis(50)))
                .expect("pump")
                .is_none(),
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

// --- The deferred core.bulk queue --------------------------------------

/// A flush sends one core.bulk per method carrying every queued item's
/// args in order, and each item's result fans back to its ticket. The
/// mock asserts the core.bulk parameter shape it received.
#[test]
fn bulk_flush_groups_by_method() {
    let mock = serve_one(|mut w: Wire| {
        w.accept_session("/api/current");
        // Two methods queued; BTreeMap flush order is alphabetical, so
        // "a.method" before "z.method".
        let (id, params) = w.expect_call("core.bulk");
        assert_eq!(
            params,
            json!(["a.method", [[1], [2]]]),
            "one core.bulk for a.method with both items in order"
        );
        w.respond_ok(
            &id,
            json!([{ "result": 10, "error": null },
                                  { "result": 20, "error": null }]),
        );
        let (id, params) = w.expect_call("core.bulk");
        assert_eq!(params, json!(["z.method", [["x"]]]));
        w.respond_ok(&id, json!([{ "result": true, "error": null }]));
    });
    let Some(mut api) = client_or_skip(&mock) else {
        return;
    };
    let sid = api.connect(SessionOpts::default()).expect("connect");

    let t1 = api.queue_bulk(sid, "a.method", &params!(1)).expect("q1");
    let t2 = api.queue_bulk(sid, "a.method", &params!(2)).expect("q2");
    let t3 = api.queue_bulk(sid, "z.method", &params!("x")).expect("q3");
    api.flush_bulk();

    // Collect events until all three tickets have answered.
    let mut done: std::collections::HashMap<_, i64> =
        std::collections::HashMap::new();
    let mut flushed = 0;
    while done.len() < 3 {
        match api.pump(Some(Duration::from_secs(10))).expect("pump") {
            Some(ApiEvent::BulkFlushed { items, .. }) => flushed += items,
            Some(ApiEvent::BulkItemDone { ticket, result }) => {
                let v: Value = result.expect("item ok").decode().expect("json");
                done.insert(ticket, v.as_i64().unwrap_or(-1));
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }
    assert_eq!(flushed, 3, "BulkFlushed accounted for every item");
    assert_eq!(done[&t1], 10);
    assert_eq!(done[&t2], 20);
    assert_eq!(done[&t3], -1); // "true" is not an i64
    shutdown(&mut api, sid);
    mock.join();
}

/// A per-item error in the core.bulk result maps to that ticket's
/// failure, while its siblings succeed.
#[test]
fn bulk_per_item_error_maps_to_ticket() {
    let mock = serve_one(|mut w: Wire| {
        w.accept_session("/api/current");
        let (id, _) = w.expect_call("core.bulk");
        w.respond_ok(
            &id,
            json!([
                { "result": null, "error": "boom" },
                { "result": "ok", "error": null }
            ]),
        );
    });
    let Some(mut api) = client_or_skip(&mock) else {
        return;
    };
    let sid = api.connect(SessionOpts::default()).expect("connect");
    let bad = api.queue_bulk(sid, "m", &params!(1)).expect("q1");
    let good = api.queue_bulk(sid, "m", &params!(2)).expect("q2");
    api.flush_bulk();

    let mut results: std::collections::HashMap<_, Result<String, String>> =
        std::collections::HashMap::new();
    while results.len() < 2 {
        match api.pump(Some(Duration::from_secs(10))).expect("pump") {
            Some(ApiEvent::BulkFlushed { .. }) => {}
            Some(ApiEvent::BulkItemDone { ticket, result }) => {
                let r = match result {
                    Ok(v) => Ok(v.decode::<String>().expect("str")),
                    Err(ApiError::Call(e)) => {
                        Err(e.reason.clone().unwrap_or_default())
                    }
                    Err(other) => panic!("unexpected item error: {other:?}"),
                };
                results.insert(ticket, r);
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }
    assert_eq!(results[&bad], Err("boom".to_owned()));
    assert_eq!(results[&good], Ok("ok".to_owned()));
    shutdown(&mut api, sid);
    mock.join();
}

/// Items too numerous for one frame split into more than one core.bulk
/// call for the same method; every ticket still answers.
#[test]
fn bulk_chunks_under_the_outbound_cap() {
    // A small outbound cap forces chunking: each item is a ~1 KiB string.
    let mock = serve_one(|mut w: Wire| {
        w.accept_session("/api/current");
        let mut seen = 0;
        // Two chunks expected; answer each core.bulk it reads until both
        // items are covered.
        while seen < 3 {
            let (id, params) = w.expect_call("core.bulk");
            let count = params[1].as_array().unwrap().len();
            seen += count;
            let items: Vec<Value> = (0..count)
                .map(|_| json!({ "result": "ok", "error": null }))
                .collect();
            w.respond_ok(&id, Value::Array(items));
        }
        assert_eq!(seen, 3, "all three items arrived across chunks");
    });
    let cfg = ApiConfig { ..config(&mock) };
    let Some(mut api) = client_or_skip_cfg(cfg) else {
        return;
    };
    // A session whose outbound cap is small enough that ~two 1 KiB items
    // exceed one frame.
    let sid = api
        .connect(SessionOpts {
            max_outbound_bytes: 2500,
            ..SessionOpts::default()
        })
        .expect("connect");
    let big = "z".repeat(1000);
    let mut tickets = Vec::new();
    for _ in 0..3 {
        tickets.push(api.queue_bulk(sid, "m", &params!(big)).expect("q"));
    }
    api.flush_bulk();

    let mut answered = 0;
    let mut batches = 0;
    while answered < 3 {
        match api.pump(Some(Duration::from_secs(10))).expect("pump") {
            Some(ApiEvent::BulkFlushed { .. }) => batches += 1,
            Some(ApiEvent::BulkItemDone { result, .. }) => {
                result.expect("item ok");
                answered += 1;
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }
    assert!(
        batches >= 2,
        "the cap forced more than one batch: {batches}"
    );
    shutdown(&mut api, sid);
    mock.join();
}

/// A single queued item too large for any frame fails its own ticket with
/// TooLarge and does not block the rest.
#[test]
fn bulk_single_item_too_large() {
    let mock = serve_one(|mut w: Wire| {
        w.accept_session("/api/current");
        // Only the small item should reach the wire.
        let (id, params) = w.expect_call("core.bulk");
        assert_eq!(
            params[1].as_array().unwrap().len(),
            1,
            "just the small one"
        );
        w.respond_ok(&id, json!([{ "result": "ok", "error": null }]));
    });
    let Some(mut api) = client_or_skip(&mock) else {
        return;
    };
    let sid = api
        .connect(SessionOpts {
            max_outbound_bytes: 2000,
            ..SessionOpts::default()
        })
        .expect("connect");
    let huge = "q".repeat(4000);
    let big_ticket = api.queue_bulk(sid, "m", &params!(huge)).expect("q-big");
    let small_ticket = api.queue_bulk(sid, "m", &params!(1)).expect("q-small");
    api.flush_bulk();

    let mut outcomes: std::collections::HashMap<_, bool> =
        std::collections::HashMap::new();
    while outcomes.len() < 2 {
        match api.pump(Some(Duration::from_secs(10))).expect("pump") {
            Some(ApiEvent::BulkFlushed { .. }) => {}
            Some(ApiEvent::BulkItemDone { ticket, result }) => {
                outcomes.insert(ticket, result.is_ok());
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }
    assert!(!outcomes[&big_ticket], "the oversized item failed");
    assert!(outcomes[&small_ticket], "the small item still went");
    shutdown(&mut api, sid);
    mock.join();
}

/// The queue refuses past its item cap rather than growing without bound.
#[test]
fn bulk_queue_full_refuses() {
    let mock = serve_one(|mut w: Wire| {
        w.accept_session("/api/current");
        // The one item that fit is flushed at teardown-time pumping; be
        // ready to answer it so join does not block.
        let (id, _) = w.expect_call("core.bulk");
        w.respond_ok(&id, json!([{ "result": 1, "error": null }]));
    });
    let cfg = ApiConfig {
        max_queued_bulk_items: 1,
        ..config(&mock)
    };
    let Some(mut api) = client_or_skip_cfg(cfg) else {
        return;
    };
    let sid = api.connect(SessionOpts::default()).expect("connect");
    api.queue_bulk(sid, "m", &params!(1)).expect("first fits");
    match api.queue_bulk(sid, "m", &params!(2)) {
        Err(ApiError::QueueFull { cap }) => assert_eq!(cap, 1),
        other => panic!("expected QueueFull, got {other:?}"),
    }
    api.flush_bulk();
    // Drain the one flushed item so the mock's core.bulk is consumed.
    loop {
        match api.pump(Some(Duration::from_secs(10))).expect("pump") {
            Some(ApiEvent::BulkItemDone { .. }) => break,
            Some(ApiEvent::BulkFlushed { .. }) => {}
            other => panic!("unexpected event: {other:?}"),
        }
    }
    shutdown(&mut api, sid);
    mock.join();
}

/// The tick timer flushes on its own, with no explicit flush_bulk call.
#[test]
fn bulk_tick_flushes_automatically() {
    let mock = serve_one(|mut w: Wire| {
        w.accept_session("/api/current");
        let (id, _) = w.expect_call("core.bulk");
        w.respond_ok(&id, json!([{ "result": 7, "error": null }]));
    });
    let cfg = ApiConfig {
        bulk_tick: Duration::from_millis(50),
        ..config(&mock)
    };
    let Some(mut api) = client_or_skip_cfg(cfg) else {
        return;
    };
    let sid = api.connect(SessionOpts::default()).expect("connect");
    let ticket = api.queue_bulk(sid, "m", &params!(1)).expect("queue");
    // No flush_bulk(): the pump's own tick clock sends it.
    let mut got = None;
    while got.is_none() {
        match api.pump(Some(Duration::from_secs(10))).expect("pump") {
            Some(ApiEvent::BulkFlushed { .. }) => {}
            Some(ApiEvent::BulkItemDone { ticket: t, result }) => {
                assert_eq!(t, ticket);
                got = Some(result.expect("ok").decode::<i64>().expect("i64"));
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }
    assert_eq!(got, Some(7));
    shutdown(&mut api, sid);
    mock.join();
}
