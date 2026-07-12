//! Wiring the `net::server` handlers as standalone functions rather than
//! inline closures — in particular the `accept` handler.
//!
//! The `accept` handler's contract is `fn(Incoming<'_>) -> Option<U>`, where
//! `U` is your per-connection state type: `Some(state)` admits the connection
//! and attaches `state`; `None` rejects it (accepted then closed before any
//! read). A plain `fn` satisfies the `FnMut` bound, so it can be used directly
//! — and so can the `header` and `body` handlers.
//!
//! Run (loopback only):
//!   cargo run --example tcp_accept_fn --features net-server
//!   cargo run --example tcp_accept_fn --features net-server -- --allowlist
//!
//! Then, from another shell, send a 4-byte big-endian length prefix followed by
//! that many payload bytes; the server replies with a length-prefixed line.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;
use truenas_ros::net::server::{
    length_prefix_header, ClientAddr, Endian, Incoming, PrefixWidth, Protocol,
    Request, Response, Server, ServerAddr, ServerConfig,
};

/// Prepend a 4-byte BE length so the client can length-delimit the reply.
fn frame(payload: &[u8]) -> Vec<u8> {
    let mut pdu = (payload.len() as u32).to_be_bytes().to_vec();
    pdu.extend_from_slice(payload);
    pdu
}

/// Per-connection state, created by the accept handler and dropped when the
/// connection closes. The header/body handlers borrow it `&mut`.
struct Session {
    peer: String,
    requests: u64,
}

/// The accept handler as a standalone function.
///
/// Its signature *is* the `accept` contract:
/// `fn(Incoming<'_>) -> Option<U>` (here `U = Session`) — the [`Incoming`]
/// carries the peer's identity plus the listener it arrived on. `None`
/// rejects the connection (accepted then closed before any read);
/// `Some(state)` admits it with per-connection state. The peer address is
/// fetched per connection (race-free), so admitting by IP is sound.
fn admit(inc: Incoming<'_>) -> Option<Session> {
    match (inc.peer, inc.listener_addr) {
        // Local-trust split: anything on a unix listener is admitted...
        (ClientAddr::Unix { .. }, ServerAddr::Unix(_)) => Some(Session {
            peer: "unix".into(),
            requests: 0,
        }),
        // ...TCP listeners take loopback peers only.
        (ClientAddr::Inet(sa), _) if sa.ip().is_loopback() => Some(Session {
            peer: sa.to_string(),
            requests: 0,
        }),
        (ClientAddr::Inet(sa), _) => {
            eprintln!("rejecting non-loopback peer {sa}");
            None
        }
        _ => None,
    }
}

/// The body handler can be a plain function too:
/// `fn(Request<'_, U>) -> Response`. This one replies synchronously; see
/// `examples/tcp_offload.rs` for the `Response::Defer` path.
fn handle(req: Request<'_, Session>) -> Response {
    let Request { body, state, .. } = req;
    state.requests += 1;
    Response::Reply(frame(
        format!(
            "{}: request #{}, {} bytes\n",
            state.peer,
            state.requests,
            body.len()
        )
        .as_bytes(),
    ))
}

/// Self-contained accept logic: use the `fn` directly as the `accept` field.
fn serve_bare() -> truenas_ros::Result<()> {
    let proto = Protocol {
        accept: admit, // <- separate function, used directly
        header: length_prefix_header::<Session>(
            PrefixWidth::U32,
            Endian::Big,
            false,
        ),
        body: handle, // <- so can the body handler
    };
    // One server, two listeners: a trusted unix socket plus loopback TCP.
    let addrs = [
        ServerAddr::Tcp("127.0.0.1:9000".parse().unwrap()),
        ServerAddr::Unix("/tmp/tcp_accept_fn.sock".into()),
    ];
    let mut server = Server::bind(addrs, proto)?;
    println!("listening on {:?}", server.local_addrs());
    server.serve_forever()
}

/// Same logic, now parameterized by a runtime allowlist. A `fn` can't capture,
/// so the state is threaded in as a parameter.
fn admit_with(peer: &ClientAddr, allow: &HashSet<IpAddr>) -> Option<Session> {
    match peer {
        ClientAddr::Inet(sa) if allow.contains(&sa.ip()) => Some(Session {
            peer: sa.to_string(),
            requests: 0,
        }),
        _ => None,
    }
}

/// When accept needs runtime state, keep the function and bind that state with a
/// one-line capturing closure that delegates to it.
fn serve_with_allowlist(allow: HashSet<IpAddr>) -> truenas_ros::Result<()> {
    let proto = Protocol {
        accept: move |inc: Incoming<'_>| admit_with(inc.peer, &allow),
        header: length_prefix_header::<Session>(
            PrefixWidth::U32,
            Endian::Big,
            false,
        ),
        body: handle,
    };
    let cfg = ServerConfig {
        idle_timeout: Some(Duration::from_secs(30)),
        ..ServerConfig::default()
    };
    let addr = ServerAddr::Tcp("127.0.0.1:9001".parse().unwrap());
    let mut server = Server::with_config([addr], cfg, proto)?;
    println!("listening on {:?}", server.local_addrs());
    server.serve_forever()
}

fn main() -> truenas_ros::Result<()> {
    // Two ways to wire the same accept function; pick one with an arg.
    if std::env::args().any(|a| a == "--allowlist") {
        let allow: HashSet<IpAddr> =
            [IpAddr::V4(Ipv4Addr::LOCALHOST)].into_iter().collect();
        serve_with_allowlist(allow)
    } else {
        serve_bare()
    }
}
