//! `net` — io_uring stream networking: a shared reactor core with server and
//! client roles.
//!
//! Three modules share the design: [`core`] holds the role-agnostic reactor
//! engine and the shared vocabulary (re-exported at the `net::` root), while
//! `server` (inbound) and `client` (outbound) are thin roles that embed it.

pub mod core;

#[cfg(feature = "net-server")]
pub mod server;

#[cfg(feature = "net-client")]
pub mod client;

// Shared public vocabulary, surfaced at the `net::` root (independent of role).
pub use core::{
    length_prefix_header, Body, ClientAddr, CloseReason, Endian, Framing,
    PeerCred, PrefixWidth, ServerAddr,
};

// The client role's public surface, surfaced at the `net::` root.
#[cfg(feature = "net-client")]
pub use client::{
    Client, ClientConfig, ConnId, ConnectDeferral, ConnectOpts, Event,
    RequestId, TlsConnectContext,
};
