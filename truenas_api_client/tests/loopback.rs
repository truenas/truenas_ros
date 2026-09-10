//! Our ws/JSON-RPC client against our ws/JSON-RPC server, in one process:
//! the real io_uring `ApiClient` dials a std-thread server built on
//! `JsonRpcServer` + the `truenas_ros::ws` server codec. This is the
//! loopback that runs in an unprivileged GH runner - no middlewared, no
//! QEMU - exercising both halves of the crate over a real socket.
//!
//! It is *not* a replacement for `tests/mock.rs`: that mock is a
//! hand-rolled, independent server, the adversarial oracle that catches a
//! bug we'd make symmetrically on both sides. This proves the two real
//! halves interoperate and that the server session is usable.
//!
//! The client half is io_uring, so the test skips (loudly under
//! `TRUENAS_ROS_REQUIRE_IO_URING`) where a ring can't be created.

#![cfg(target_os = "linux")]

use serde_json::{Value, json};
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::thread::JoinHandle;
use std::time::Duration;
use truenas_api_client::{
    ApiClient, ApiConfig, ApiError, ApiEvent, JsonRpcServer, ServerAct,
    ServerStep, SessionOpts, params,
};
use truenas_jsonrpc::ErrorObject;
use truenas_ros::ws::{self, HeadVerdict};

// --- the std-thread ws/JSON-RPC server -------------------------------

/// One accepted connection: an incremental frame reader over the server
/// codec, plus the `JsonRpcServer` session driving it.
struct Conn {
    stream: UnixStream,
    server: JsonRpcServer,
}

impl Conn {
    /// Read the client's HTTP upgrade request head, byte by byte through
    /// its blank line (the client waits for the `101` before sending
    /// frames, so this never over-reads into frame bytes).
    fn read_head(&mut self) -> Option<Vec<u8>> {
        let mut head = Vec::new();
        let mut b = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            self.stream.read_exact(&mut b).ok()?;
            head.push(b[0]);
            assert!(head.len() < 64 * 1024, "runaway request head");
        }
        Some(head)
    }

    /// Read one whole client frame, reading exactly the bytes
    /// `server_frame_head` asks for, then unmask its payload.
    fn read_frame(&mut self) -> Option<(ws::FrameHead, Vec<u8>)> {
        let mut hdr = vec![0u8; 2];
        self.stream.read_exact(&mut hdr).ok()?;
        let h = loop {
            match ws::server_frame_head(&hdr) {
                HeadVerdict::Incomplete { need } => {
                    let mut more = vec![0u8; need];
                    self.stream.read_exact(&mut more).ok()?;
                    hdr.extend_from_slice(&more);
                }
                HeadVerdict::Done(h) => break h,
                HeadVerdict::Invalid(_) => return None,
            }
        };
        // The declared length is the peer's, so it is checked against
        // the session's bound before it sizes an allocation. That bound
        // is what `JsonRpcServer::max_message_bytes` exists to hand a
        // driver: the payload is read before `on_frame` ever sees it, so
        // a driver that trusts `payload_len` aborts on a header alone -
        // 64 bits of declared length and nothing between it and
        // `vec![0u8; n]`.
        if h.payload_len > self.server.max_message_bytes() {
            return None;
        }
        let mut payload = vec![0u8; h.payload_len];
        self.stream.read_exact(&mut payload).ok()?;
        ws::unmask(&hdr, &mut payload);
        Some((h, payload))
    }

    fn write(&mut self, bytes: &[u8]) {
        self.stream.write_all(bytes).expect("server write");
    }
}

/// What a handler answers with: a result-or-error, and any events to push
/// right after the reply.
struct Answer {
    result: Result<Value, ErrorObject>,
    then_notify: Vec<(String, Value)>,
}

fn ok(v: Value) -> Answer {
    Answer {
        result: Ok(v),
        then_notify: Vec::new(),
    }
}

/// Serve one connection with `handler` on a fresh unix socket. Returns the
/// socket path, its tempdir (keep it alive), and the server's join handle.
fn serve<H>(
    handler: H,
) -> (std::path::PathBuf, truenas_ros::TempDir, JoinHandle<()>)
where
    H: FnMut(&str, Option<Value>) -> Answer + Send + 'static,
{
    let dir = truenas_ros::tempdir().expect("tempdir");
    let path = dir.path().join("loopback.sock");
    let listener = UnixListener::bind(&path).expect("bind");
    let handle = std::thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept");
        run_conn(stream, handler);
    });
    (path, dir, handle)
}

fn run_conn<H>(stream: UnixStream, mut handler: H)
where
    H: FnMut(&str, Option<Value>) -> Answer,
{
    let mut conn = Conn {
        stream,
        server: JsonRpcServer::new(64 * 1024 * 1024),
    };
    let head = conn.read_head().expect("request head");
    match conn.server.on_head(&head) {
        ServerStep::Accept(resp) => conn.write(&resp),
        ServerStep::Reject(e) => panic!("rejected a valid upgrade: {e}"),
    }
    while let Some((head, payload)) = conn.read_frame() {
        let acts = conn.server.on_frame(head, payload);
        let mut stop = false;
        for act in acts {
            match act {
                ServerAct::Send(bytes) => conn.write(&bytes),
                ServerAct::PeerClosing => stop = true,
                ServerAct::Fault(what) => panic!("client fault: {what}"),
                ServerAct::Notification { .. } => {}
                ServerAct::Request { id, method, params } => {
                    let pv = params
                        .as_ref()
                        .map(|p| serde_json::from_str(p.get()).unwrap());
                    let ans = handler(&method, pv);
                    let frame = match ans.result {
                        Ok(v) => conn.server.reply(id, &v).expect("encode"),
                        Err(e) => conn.server.reply_error(id, e),
                    };
                    conn.write(&frame);
                    for (m, p) in ans.then_notify {
                        let f =
                            conn.server.notify(&m, Some(&p)).expect("notify");
                        conn.write(&f);
                    }
                }
            }
        }
        if stop {
            break;
        }
    }
}

// --- the test --------------------------------------------------------

fn client_or_skip(path: &std::path::Path) -> Option<ApiClient> {
    let cfg = ApiConfig {
        socket_path: path.to_path_buf(),
        connect_timeout: Some(Duration::from_secs(10)),
        ..ApiConfig::default()
    };
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
                "non-environmental ring failure: {e}"
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

/// The whole stack, both halves ours: connect (handshake + set_options),
/// a call, a subscribe that pushes an event, and a bulk flush.
#[test]
fn client_and_server_round_trip() {
    let uuid = "11111111-2222-3333-4444-555555555555";
    let (path, _dir, handle) = serve(move |method, params| match method {
        "core.set_options" => ok(json!({
            "legacy_jobs": false,
            "private_methods": false,
            "py_exceptions": false,
        })),
        "core.ping" => ok(json!("pong")),
        "core.subscribe" => Answer {
            result: Ok(json!(uuid)),
            // Push an event right after acknowledging the subscription.
            then_notify: vec![(
                "collection_update".into(),
                json!({
                    "msg": "added",
                    "collection": "core.get_jobs",
                    "id": 1,
                }),
            )],
        },
        "core.bulk" => {
            // params = [method, [[args]...]]; answer one item per entry.
            let items = params
                .as_ref()
                .and_then(|p| p.get(1))
                .and_then(Value::as_array)
                .map(Vec::len)
                .unwrap_or(0);
            let statuses: Vec<Value> = (0..items)
                .map(|_| json!({ "result": true, "error": null }))
                .collect();
            ok(Value::Array(statuses))
        }
        _ => Answer {
            result: Err(ErrorObject::method_not_found()),
            then_notify: Vec::new(),
        },
    });

    let Some(mut api) = client_or_skip(&path) else {
        return;
    };
    let session = api.connect(SessionOpts::default()).expect("connect");

    // A direct call round-trips through both real codecs.
    let pong: String =
        api.call(session, "core.ping", &params!()).expect("ping");
    assert_eq!(pong, "pong");

    // A subscription is acknowledged, then the pushed event arrives.
    let call = api.subscribe_start(session, "core.get_jobs").expect("sub");
    let mut ready = false;
    let mut got_event = false;
    while !(ready && got_event) {
        match api.pump(Some(Duration::from_secs(10))).expect("pump") {
            Some(ApiEvent::SubscriptionReady { call: c, .. }) => {
                assert_eq!(c, call);
                ready = true;
            }
            Some(ApiEvent::CollectionUpdate { update, .. }) => {
                assert_eq!(update.collection, "core.get_jobs");
                assert_eq!(update.msg, "added");
                got_event = true;
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }

    // The deferred bulk path: two items flush as one core.bulk, and each
    // ticket gets its per-item result back.
    let t1 = api
        .queue_bulk(session, "pool.snapshot", &params!("a"))
        .expect("q1");
    let t2 = api
        .queue_bulk(session, "pool.snapshot", &params!("b"))
        .expect("q2");
    api.flush_bulk();
    let mut done = std::collections::HashSet::new();
    while done.len() < 2 {
        match api.pump(Some(Duration::from_secs(10))).expect("pump") {
            Some(ApiEvent::BulkFlushed { .. }) => {}
            Some(ApiEvent::BulkItemDone { ticket, result }) => {
                result.expect("bulk item ok");
                done.insert(ticket);
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }
    assert!(done.contains(&t1) && done.contains(&t2));

    api.close(session);
    while api.is_open(session) {
        if api
            .pump(Some(Duration::from_secs(5)))
            .expect("pump")
            .is_none()
        {
            break;
        }
    }
    handle.join().expect("server thread");
}
