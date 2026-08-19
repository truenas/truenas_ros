//! Parking an HTTP request with `protocol_deferrable` - the cold-miss
//! pattern.
//!
//! A handler that needs state only another thread can produce (an identity
//! lookup against a directory service, a database row) must not block the
//! io_uring thread and must not fail the request. Instead it **parks**:
//!
//!  1. the handler calls [`HttpRequest::defer`], which retains the request
//!     (head verbatim, body owned) and detaches a `Send` [`HttpDeferred`],
//!  2. it returns `HttpVerdict::Defer(permit)` - the server thread goes
//!     straight back to polling,
//!  3. the worker resolves what it needed, then either
//!     [`HttpDeferred::redrive`]s - the handler runs again on the server
//!     thread over the identical request, now hitting its warm state - or,
//!     past its own deadline, builds an error and [`HttpDeferred::reply`]s
//!     it (serialized on the server thread, so response policy never runs
//!     off-thread).
//!
//! The client sees one round trip either way; nothing blocks the ring.
//!
//!   cargo run --example http_offload --features http
//!
//! Then: `curl -i http://127.0.0.1:8080/user/alice` - the first request for
//! a name parks ~50 ms while the "directory" resolves, repeats answer from
//! the warm cache; `/user/slow` always misses its deadline and answers 503.
//!
//! [`HttpRequest::defer`]: truenas_ros::http::HttpRequest::defer
//! [`HttpDeferred`]: truenas_ros::http::HttpDeferred
//! [`HttpDeferred::redrive`]: truenas_ros::http::HttpDeferred::redrive
//! [`HttpDeferred::reply`]: truenas_ros::http::HttpDeferred::reply

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use truenas_ros::http::{
    protocol_deferrable, HttpConfig, HttpRequest, HttpResponse, HttpVerdict,
};
use truenas_ros::net::server::{Incoming, Server, ServerAddr};

/// The shared "identity cache" the handler reads on the server thread and a
/// worker fills off it. A real service would hold TTLs and verdicts; the
/// shape that matters here is lock-for-a-lookup, never lock-across-work.
type Cache = Arc<Mutex<HashMap<String, u32>>>;

/// The slow lookup a worker runs - stands in for NSS/LDAP/a database.
fn resolve(name: &str) -> Option<u32> {
    thread::sleep(Duration::from_millis(50));
    if name == "slow" {
        // Never resolves in time; the worker answers 503 itself.
        return None;
    }
    Some(1000 + name.len() as u32)
}

fn main() -> truenas_ros::Result<()> {
    let cache: Cache = Arc::new(Mutex::new(HashMap::new()));
    let addr = ServerAddr::Tcp("127.0.0.1:8080".parse().unwrap());

    let handler = move |req: HttpRequest<'_>, _: &mut ()| {
        let Some(name) = req.target.strip_prefix("/user/") else {
            return HttpVerdict::Respond(
                HttpResponse::new(404).body("try /user/<name>\n"),
            );
        };
        // Fast path: a warm cache answers inline - including the second
        // invocation of a redriven request.
        if let Some(uid) = cache.lock().unwrap().get(name) {
            return HttpVerdict::Respond(
                HttpResponse::new(200).body(format!("{name} = uid {uid}\n")),
            );
        }
        // Cold miss: park the request, resolve off-thread, redrive.
        let name = name.to_string();
        let (deferred, permit) = req.defer();
        let cache = Arc::clone(&cache);
        thread::spawn(move || match resolve(&name) {
            Some(uid) => {
                cache.lock().unwrap().insert(name, uid);
                deferred.redrive();
            }
            None => deferred.reply(
                HttpResponse::new(503)
                    .header("retry-after", "1")
                    .body("resolver deadline exceeded\n"),
            ),
        });
        HttpVerdict::Defer(permit)
    };

    let proto = protocol_deferrable(
        HttpConfig::default(),
        |_: Incoming<'_>| Some(()),
        handler,
    )?;
    let mut server = Server::bind([addr], proto)?;
    println!("listening on {:?}", server.local_addrs());
    server.serve_forever()
}
