//! A scripted mock middlewared: a `UnixListener` thread speaking the real
//! wire shapes (HTTP 101 upgrade, RFC 6455 frames, JSON-RPC text), driven
//! by a per-connection script closure.
//!
//! Two invariants are woven through every read rather than asserted in
//! one test: **every client frame must be masked** (RFC 6455 §5.1 - a
//! real middlewared's aiohttp closes on an unmasked client frame) and
//! **every call's `params` must be a JSON Array** (middlewared rejects
//! named params). Any scenario that elicits a violation fails its join.

use serde_json::{Value, json};
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::thread::JoinHandle;
use truenas_api_client::accept_for;

/// One accepted connection, with frame/JSON helpers for scripts.
pub struct Wire {
    stream: UnixStream,
}

impl Wire {
    /// Read the HTTP request head (through CRLFCRLF), assert the upgrade
    /// shape middlewared would see, and answer `101` with the computed
    /// accept. Returns nothing a script needs; the key never leaves.
    pub fn accept_upgrade(&mut self, expect_endpoint: &str) {
        let head = self.read_head();
        let text = String::from_utf8(head).expect("request head is ASCII");
        let request_line = text.lines().next().expect("a request line");
        assert_eq!(
            request_line,
            format!("GET {expect_endpoint} HTTP/1.1"),
            "the upgrade request line"
        );
        assert!(
            text.lines()
                .any(|l| l.eq_ignore_ascii_case("host: localhost")),
            "Host: localhost, the value every deployment accepts: {text}"
        );
        let key = text
            .lines()
            .find_map(|l| {
                l.split_once(':').and_then(|(name, v)| {
                    name.eq_ignore_ascii_case("sec-websocket-key")
                        .then(|| v.trim().to_owned())
                })
            })
            .expect("a Sec-WebSocket-Key header");
        let resp = format!(
            "HTTP/1.1 101 Switching Protocols\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Accept: {}\r\n\r\n",
            accept_for(&key)
        );
        self.stream.write_all(resp.as_bytes()).expect("write 101");
    }

    /// Accept the upgrade *and* the session-setup `core.set_options`
    /// call (the default, non-legacy session shape), asserting it is the
    /// first thing on the wire.
    pub fn accept_session(&mut self, expect_endpoint: &str) {
        self.accept_upgrade(expect_endpoint);
        let (id, params) = self.expect_call("core.set_options");
        assert_eq!(
            params,
            json!([{ "legacy_jobs": false }]),
            "session setup asks for modern job answering"
        );
        self.respond_ok(&id, json!(null));
    }

    /// Answer the upgrade request with an arbitrary non-101 head.
    pub fn refuse_upgrade(&mut self, head: &str) {
        let _ = self.read_head();
        self.stream
            .write_all(head.as_bytes())
            .expect("write refusal");
    }

    /// Answer with a 101 whose accept digest is wrong.
    pub fn accept_with_bad_digest(&mut self) {
        let _ = self.read_head();
        let resp = "HTTP/1.1 101 Switching Protocols\r\n\
                    Upgrade: websocket\r\n\
                    Connection: Upgrade\r\n\
                    Sec-WebSocket-Accept: c3VyZWx5LW5vdC10aGUtZGlnZXN0\r\n\r\n";
        self.stream
            .write_all(resp.as_bytes())
            .expect("write bad 101");
    }

    fn read_head(&mut self) -> Vec<u8> {
        let mut head = Vec::new();
        let mut b = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            let n = self.stream.read(&mut b).expect("read head byte");
            assert!(n == 1, "peer closed inside the request head");
            head.push(b[0]);
            assert!(head.len() < 64 * 1024, "runaway request head");
        }
        head
    }

    fn read_exact(&mut self, n: usize) -> Vec<u8> {
        let mut buf = vec![0u8; n];
        self.stream.read_exact(&mut buf).expect("read frame bytes");
        buf
    }

    /// Read one client frame, enforcing the mask invariant, and hand back
    /// `(opcode, fin, unmasked payload)`.
    pub fn read_frame(&mut self) -> (u8, bool, Vec<u8>) {
        let h = self.read_exact(2);
        let fin = h[0] & 0x80 != 0;
        let opcode = h[0] & 0x0F;
        assert!(
            h[1] & 0x80 != 0,
            "INVARIANT: client frames must be masked (opcode {opcode:#x})"
        );
        let len = match h[1] & 0x7F {
            126 => {
                let ext = self.read_exact(2);
                usize::from(u16::from_be_bytes([ext[0], ext[1]]))
            }
            127 => {
                let ext = self.read_exact(8);
                u64::from_be_bytes(ext.try_into().unwrap()) as usize
            }
            n => usize::from(n),
        };
        let mask = self.read_exact(4);
        let mut payload = self.read_exact(len);
        for (i, byte) in payload.iter_mut().enumerate() {
            *byte ^= mask[i % 4];
        }
        (opcode, fin, payload)
    }

    /// Read frames until a text message arrives (answering pings along
    /// the way is the *client's* job - any ping the script sent earlier
    /// comes back as a pong here and is counted, not answered). Enforces
    /// the params-Array invariant on every call seen.
    pub fn read_text_json(&mut self) -> Value {
        loop {
            let (opcode, fin, payload) = self.read_frame();
            assert!(fin, "the client never fragments (outbound cap)");
            match opcode {
                0x1 => {
                    let v: Value = serde_json::from_slice(&payload)
                        .expect("client text frames are JSON");
                    if let Some(params) = v.get("params") {
                        assert!(
                            params.is_array(),
                            "INVARIANT: params must be a JSON Array, got \
                             {params}"
                        );
                    }
                    return v;
                }
                0xA => continue, // a pong for a ping this script sent
                0x8 => panic!("unexpected close frame from the client"),
                other => panic!("unexpected client frame {other:#x}"),
            }
        }
    }

    /// Read the next text message and require it to be a call of
    /// `method`; hand back `(id, params)`.
    pub fn expect_call(&mut self, method: &str) -> (Value, Value) {
        let v = self.read_text_json();
        assert_eq!(
            v.get("method").and_then(Value::as_str),
            Some(method),
            "expected a {method} call, got {v}"
        );
        let id = v.get("id").expect("calls carry ids").clone();
        let params = v.get("params").cloned().unwrap_or(json!([]));
        (id, params)
    }

    /// Count pongs until `n` have arrived, allowing one text message to
    /// arrive meanwhile (returned). For the ping-flood scenario.
    pub fn drain_pongs_and_one_call(
        &mut self,
        n: usize,
        method: &str,
    ) -> (Value, Value) {
        let mut pongs = 0;
        let mut call = None;
        while pongs < n || call.is_none() {
            let (opcode, _fin, payload) = self.read_frame();
            match opcode {
                0xA => pongs += 1,
                0x1 => {
                    let v: Value = serde_json::from_slice(&payload)
                        .expect("client text is JSON");
                    if let Some(params) = v.get("params") {
                        assert!(params.is_array(), "INVARIANT: params Array");
                    }
                    assert_eq!(
                        v.get("method").and_then(Value::as_str),
                        Some(method)
                    );
                    assert!(call.is_none(), "one call expected");
                    call = Some((
                        v.get("id").expect("id").clone(),
                        v.get("params").cloned().unwrap_or(json!([])),
                    ));
                }
                other => panic!("unexpected frame {other:#x} in flood"),
            }
        }
        call.expect("the call arrived")
    }

    /// One unmasked server frame.
    pub fn send_frame(&mut self, opcode: u8, fin: bool, payload: &[u8]) {
        let mut out = Vec::with_capacity(10 + payload.len());
        out.push(if fin { 0x80 } else { 0 } | opcode);
        match payload.len() {
            n if n < 126 => out.push(n as u8),
            n if n <= 0xFFFF => {
                out.push(126);
                out.extend_from_slice(&(n as u16).to_be_bytes());
            }
            n => {
                out.push(127);
                out.extend_from_slice(&(n as u64).to_be_bytes());
            }
        }
        out.extend_from_slice(payload);
        self.stream.write_all(&out).expect("write server frame");
    }

    /// One whole text message.
    pub fn send_text(&mut self, text: &str) {
        self.send_frame(0x1, true, text.as_bytes());
    }

    /// A JSON-RPC success for `id`.
    pub fn respond_ok(&mut self, id: &Value, result: Value) {
        self.send_text(
            &json!({ "jsonrpc": "2.0", "result": result, "id": id })
                .to_string(),
        );
    }

    /// A JSON-RPC error for `id`, middlewared-shaped.
    pub fn respond_err(
        &mut self,
        id: &Value,
        code: i64,
        message: &str,
        data: Option<Value>,
    ) {
        let mut error = json!({ "code": code, "message": message });
        if let Some(d) = data {
            error["data"] = d;
        }
        self.send_text(
            &json!({ "jsonrpc": "2.0", "error": error, "id": id }).to_string(),
        );
    }

    /// A server notification (no id member - never answered).
    pub fn send_notification(&mut self, method: &str, params: Value) {
        self.send_text(
            &json!({ "jsonrpc": "2.0", "method": method, "params": params })
                .to_string(),
        );
    }

    /// A ping the client must answer.
    pub fn send_ping(&mut self, payload: &[u8]) {
        self.send_frame(0x9, true, payload);
    }

    /// A close frame with `code` and `reason`, aiohttp-style.
    pub fn send_close(&mut self, code: u16, reason: &str) {
        let mut payload = code.to_be_bytes().to_vec();
        payload.extend_from_slice(reason.as_bytes());
        self.send_frame(0x8, true, &payload);
    }

    /// Read the client's close echo (or its initiated close).
    pub fn expect_close(&mut self) {
        let (opcode, _fin, _payload) = self.read_frame();
        assert_eq!(opcode, 0x8, "expected a close frame");
    }
}

/// A listening mock serving `scripts.len()` connections, in accept order,
/// each script on its own thread. Join it at the end of the test: a
/// script's assertion failure surfaces there.
pub struct Mock {
    pub path: PathBuf,
    // Kept alive so the socket's tempdir survives the test body.
    _dir: truenas_ros::TempDir,
    accept: Option<JoinHandle<Vec<JoinHandle<()>>>>,
}

/// Serve `scripts.len()` connections at a fresh socket path.
pub fn serve(scripts: Vec<Box<dyn FnOnce(Wire) + Send>>) -> Mock {
    let dir = truenas_ros::tempdir().expect("tempdir");
    let path = dir.path().join("mockd.sock");
    let listener = UnixListener::bind(&path).expect("bind mock socket");
    let accept = std::thread::spawn(move || {
        let mut workers = Vec::new();
        for script in scripts {
            let (stream, _) = listener.accept().expect("accept");
            workers.push(std::thread::spawn(move || {
                script(Wire { stream });
            }));
        }
        workers
    });
    Mock {
        path,
        _dir: dir,
        accept: Some(accept),
    }
}

/// The single-connection form.
pub fn serve_one(script: impl FnOnce(Wire) + Send + 'static) -> Mock {
    serve(vec![Box::new(script)])
}

impl Mock {
    /// Wait for every script to finish, propagating its panics into the
    /// test.
    pub fn join(mut self) {
        let workers = self
            .accept
            .take()
            .expect("join once")
            .join()
            .expect("accept thread");
        for w in workers {
            w.join().expect("mock script");
        }
    }
}
