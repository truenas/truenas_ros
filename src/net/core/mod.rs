//! `net::core` — the role-agnostic io_uring engine and primitives shared by the
//! server and client roles.
//!
//! The engine is a superset of both roles' needs — the server exercises accept,
//! peer-identity, kTLS-handshake and detach machinery a client never touches,
//! and vice versa. A single-role build therefore leaves some shared primitives
//! unused. The `not(net-server)` allow below relaxes dead-code exactly for the
//! server-support surface when the server role is absent; `net-server` and
//! `full` builds stay strict, so genuinely dead core code is still caught.
pub(crate) mod config;
#[cfg_attr(not(feature = "net-server"), allow(dead_code))]
pub(crate) mod conn;
#[cfg_attr(not(feature = "net-server"), allow(dead_code))]
pub(crate) mod handles;
#[cfg_attr(not(feature = "net-server"), allow(dead_code))]
pub(crate) mod probe;
pub(crate) mod protocol;
#[cfg_attr(not(feature = "net-server"), allow(dead_code))]
pub(crate) mod reactor;
#[cfg_attr(not(feature = "net-server"), allow(dead_code))]
pub(crate) mod sock;
#[cfg_attr(not(feature = "net-server"), allow(dead_code))]
pub(crate) mod table;

pub use protocol::{
    length_prefix_header, Body, ClientAddr, CloseReason, Endian, Framing,
    PeerCred, PrefixWidth, ServerAddr,
};
