use super::*;

// --- The deferred core.bulk queue --------------------------------------

/// A flush sends one core.bulk per method carrying every queued item's args in order, and each item's result fans back
/// to its ticket. The mock asserts the core.bulk parameter shape it received.
#[test]
fn bulk_flush_groups_by_method() {
    let mock = serve_one(|mut w: Wire| {
        w.accept_session("/api/current");
        // Two methods queued; BTreeMap flush order is alphabetical, so "a.method" before "z.method".
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
    let mut done: std::collections::HashMap<_, i64> = std::collections::HashMap::new();
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

/// A session still dialing is not a dead one. The tick starts due, so the first `pump` after `connect_start` reaches
/// the flush while the session is in `AwaitingHead`, and its items must wait for it rather than fail `Closed`. The mock
/// holds the upgrade back so the window is wide enough to pump through.
#[test]
fn bulk_items_survive_a_dialing_session() {
    let mock = serve_one(|mut w: Wire| {
        // Wide enough for the client to pump several times while the session sits in `AwaitingHead`.
        std::thread::sleep(Duration::from_millis(200));
        w.accept_session("/api/current");
        let (id, params) = w.expect_call("core.bulk");
        assert_eq!(params, json!(["m.method", [[1]]]));
        w.respond_ok(&id, json!([{ "result": 7, "error": null }]));
    });
    let Some(mut api) = client_or_skip(&mock) else {
        return;
    };
    let sid = api.connect_start(SessionOpts::default()).expect("dial");
    let ticket = api.queue_bulk(sid, "m.method", &params!(1)).expect("queue");

    // Pump the whole dialing window. Nothing may answer the ticket here.
    let mut ready = false;
    for _ in 0..100 {
        match api.pump(Some(Duration::from_millis(20))).expect("pump") {
            Some(ApiEvent::BulkItemDone { ticket: t, result }) => {
                panic!("ticket {t:?} answered while dialing: {result:?}")
            }
            Some(ApiEvent::SessionReady(s)) => {
                assert_eq!(s, sid);
                ready = true;
                break;
            }
            Some(other) => panic!("unexpected event: {other:?}"),
            None => {}
        }
    }
    assert!(ready, "the session never came up");

    // And the item the queue held is still there to send. (The default `bulk_tick` is 10s, so force the flush rather
    // than wait it out.)
    api.flush_bulk();
    let mut got = None;
    while got.is_none() {
        match api.pump(Some(Duration::from_secs(10))).expect("pump") {
            Some(ApiEvent::BulkItemDone { ticket: t, result }) => {
                assert_eq!(t, ticket);
                got = Some(result.expect("the held item flushed and ran"));
            }
            Some(ApiEvent::BulkFlushed { items, .. }) => {
                assert_eq!(items, 1, "the item was still queued")
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }
    let v: Value = got.expect("answered").decode().expect("json");
    assert_eq!(v.as_i64(), Some(7));
    shutdown(&mut api, sid);
    mock.join();
}

/// Each queued item flushes on the session it was queued against. core.bulk runs its items under the calling session's
/// credentials, so a second `queue_bulk` naming a different session must not re-aim the items already queued for the
/// first.
#[test]
fn bulk_flushes_each_item_on_its_own_session() {
    let scripts: Vec<Box<dyn FnOnce(Wire) + Send>> = vec![
        Box::new(|mut w: Wire| {
            w.accept_session("/api/current");
            let (id, params) = w.expect_call("core.bulk");
            assert_eq!(params, json!(["s1.method", [["one"]]]));
            w.respond_ok(&id, json!([{ "result": 1, "error": null }]));
            w.expect_close();
        }),
        Box::new(|mut w: Wire| {
            w.accept_session("/api/current");
            let (id, params) = w.expect_call("core.bulk");
            assert_eq!(params, json!(["s2.method", [["two"]]]));
            w.respond_ok(&id, json!([{ "result": 2, "error": null }]));
            w.expect_close();
        }),
    ];
    let mock = serve(scripts);
    let Some(mut api) = client_or_skip(&mock) else {
        return;
    };
    let s1 = api.connect(SessionOpts::default()).expect("s1");
    let s2 = api.connect(SessionOpts::default()).expect("s2");
    let t1 = api.queue_bulk(s1, "s1.method", &params!("one")).expect("q1");
    let t2 = api.queue_bulk(s2, "s2.method", &params!("two")).expect("q2");
    api.flush_bulk();

    let mut done: std::collections::HashMap<_, i64> = std::collections::HashMap::new();
    while done.len() < 2 {
        match api.pump(Some(Duration::from_secs(10))).expect("pump") {
            Some(ApiEvent::BulkFlushed { .. }) => {}
            Some(ApiEvent::BulkItemDone { ticket, result }) => {
                let v: Value = result.expect("item ok").decode().expect("i64");
                done.insert(ticket, v.as_i64().expect("i64"));
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }
    assert_eq!(done[&t1], 1);
    assert_eq!(done[&t2], 2);
    shutdown(&mut api, s1);
    shutdown(&mut api, s2);
    mock.join();
}

/// A per-item error in the core.bulk result maps to that ticket's failure, while its siblings succeed.
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

    let mut results: std::collections::HashMap<_, Result<String, String>> = std::collections::HashMap::new();
    while results.len() < 2 {
        match api.pump(Some(Duration::from_secs(10))).expect("pump") {
            Some(ApiEvent::BulkFlushed { .. }) => {}
            Some(ApiEvent::BulkItemDone { ticket, result }) => {
                let r = match result {
                    Ok(v) => Ok(v.decode::<String>().expect("str")),
                    Err(ApiError::Call(e)) => Err(e.reason.clone().unwrap_or_default()),
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

/// Items too numerous for one frame split into more than one core.bulk call for the same method; every ticket still
/// answers.
#[test]
fn bulk_chunks_under_the_outbound_cap() {
    // A small outbound cap forces chunking: each item is a ~1 KiB string.
    let mock = serve_one(|mut w: Wire| {
        w.accept_session("/api/current");
        let mut seen = 0;
        // Two chunks expected; answer each core.bulk it reads until both items are covered.
        while seen < 3 {
            let (id, params) = w.expect_call("core.bulk");
            let count = params[1].as_array().unwrap().len();
            seen += count;
            let items: Vec<Value> = (0..count).map(|_| json!({ "result": "ok", "error": null })).collect();
            w.respond_ok(&id, Value::Array(items));
        }
        assert_eq!(seen, 3, "all three items arrived across chunks");
    });
    let cfg = ApiConfig { ..config(&mock) };
    let Some(mut api) = client_or_skip_cfg(cfg) else {
        return;
    };
    // A session whose outbound cap is small enough that ~two 1 KiB items exceed one frame.
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
    assert!(batches >= 2, "the cap forced more than one batch: {batches}");
    shutdown(&mut api, sid);
    mock.join();
}

/// A single queued item too large for any frame fails its own ticket with TooLarge and does not block the rest.
#[test]
fn bulk_single_item_too_large() {
    let mock = serve_one(|mut w: Wire| {
        w.accept_session("/api/current");
        // Only the small item should reach the wire.
        let (id, params) = w.expect_call("core.bulk");
        assert_eq!(params[1].as_array().unwrap().len(), 1, "just the small one");
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

    let mut outcomes: std::collections::HashMap<_, bool> = std::collections::HashMap::new();
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
        // The one item that fit is flushed at teardown-time pumping; be ready to answer it so join does not block.
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
        Err(ApiError::QueueFull { queue, cap }) => {
            assert_eq!(cap, 1);
            assert!(queue.contains("bulk"), "names the bulk queue: {queue}");
        }
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

/// Nothing with a data opcode follows this client's own Close on the wire (RFC 6455 §5.5.1), including an
/// `unsubscribe_start`, which reaches `Act::Send` through `submit` past the backlog's phase gate.
#[test]
fn no_data_frame_follows_our_own_close() {
    let mock = serve_one(|mut w: Wire| {
        w.accept_session("/api/current");
        let (id, _) = w.expect_call("core.subscribe");
        w.respond_ok(&id, json!("ident-1"));
        let mut after_close = Vec::new();
        let mut closed = false;
        while let Some((opcode, _fin, _payload)) = w.read_frame_or_eof() {
            if closed {
                after_close.push(opcode);
            }
            if opcode == 0x8 {
                closed = true;
            }
        }
        assert!(closed, "the client sent a close frame");
        assert!(
            !after_close.contains(&0x1) && !after_close.contains(&0x2),
            "a data frame followed our own Close: {after_close:?}"
        );
    });
    let Some(mut api) = client_or_skip_cfg(config(&mock)) else {
        return;
    };
    let sid = api.connect(SessionOpts::default()).expect("connect");
    let _call = api.subscribe_start(sid, "reporting.realtime").expect("sub");
    let sub = loop {
        match api.pump(Some(Duration::from_secs(10))).expect("pump") {
            Some(ApiEvent::SubscriptionReady { sub, .. }) => break sub,
            Some(_) => {}
            None => panic!("no subscription"),
        }
    };
    api.close(sid);
    assert!(
        matches!(api.unsubscribe_start(sid, sub), Err(ApiError::Closed { .. })),
        "unsubscribing a closing session must be refused, not sent"
    );
    let mut guard = 0;
    while api.is_open(sid) && guard < 200 {
        guard += 1;
        if api.pump(Some(Duration::from_millis(50))).expect("pump").is_none() {
            break;
        }
    }
    mock.join();
}
