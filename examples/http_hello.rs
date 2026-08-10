//! The `http` codec on the io_uring reactor: a minimal HTTP/1.1 endpoint.
//!
//! Wires `http::protocol` — accept, per-connection state, and a request
//! handler — onto a loopback `net::server`. Everything HTTP (framing,
//! keep-alive, 100-continue, error farewells) is the codec's job; this file
//! is only routing.
//!
//! Run (loopback only):
//!   cargo run --example http_hello --features http
//!
//! Then:
//!   curl -v http://127.0.0.1:8080/
//!   curl -v -X PUT --data-binary @somefile http://127.0.0.1:8080/echo
//!   curl -v -H 'Expect: 100-continue' -T somefile http://127.0.0.1:8080/echo
//!
//! The default caps compose: `HttpConfig::default()` accepts bodies up to
//! ~1 MiB (a larger upload is answered with a clean 413). To accept more,
//! raise `HttpConfig::max_body` and give `Server::with_config` a
//! `ServerConfig::max_request_bytes` of at least
//! `HttpConfig::min_request_bytes()`.

use truenas_ros::http::{protocol, HttpConfig, HttpRequest, HttpResponse};
use truenas_ros::net::server::{Incoming, Server, ServerAddr};
use truenas_ros::net::ClientAddr;

/// Per-connection state: just a request counter, to show keep-alive reuse.
struct Session {
    requests: u64,
}

fn admit(inc: Incoming<'_>) -> Option<Session> {
    match inc.peer {
        ClientAddr::Inet(sa) if sa.ip().is_loopback() => {
            Some(Session { requests: 0 })
        }
        _ => None,
    }
}

fn handle(req: HttpRequest<'_>, session: &mut Session) -> HttpResponse {
    session.requests += 1;
    match (req.method, req.target) {
        ("GET", "/") => HttpResponse::new(200)
            .header("content-type", "text/plain")
            .body(format!(
                "hello from the io_uring reactor (request #{} on this connection)\n",
                session.requests
            )),
        ("PUT", "/echo") => HttpResponse::new(200)
            .header("content-type", "text/plain")
            .body(format!("received {} bytes\n", req.body.len())),
        _ => HttpResponse::new(404).body("not found\n"),
    }
}

fn main() -> truenas_ros::Result<()> {
    let proto = protocol(HttpConfig::default(), admit, handle);
    let addr = [ServerAddr::Tcp("127.0.0.1:8080".parse().unwrap())];
    let mut server = Server::bind(addr, proto)?;
    println!("listening on {:?}", server.local_addrs());
    server.serve_forever()
}
