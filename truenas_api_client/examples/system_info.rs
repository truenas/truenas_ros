//! Manual end-to-end check against a *real* middlewared. Not a CI test -
//! the QEMU VM has no middlewared, so this is the by-hand proof on a real
//! TrueNAS box (25.10 or 27.0).
//!
//! ```text
//! # As root (the daemon's own full-admin session):
//! cargo run --example system_info
//!
//! # As a minted uid, to prove the personality path end to end (needs
//! # root to spawn the broker; the uid must map to a TrueNAS user with
//! # privileges for an authenticated session, else auth.me fails
//! # ENOTAUTHENTICATED - which is itself the documented behaviour):
//! cargo run --example system_info -- --as-uid 3000 --as-gid 3000
//! ```
//!
//! It calls `core.ping` (expect `"pong"`), `system.info`, and `auth.me`
//! (who the session authenticated as), printing each. A demo bulk-style
//! call is out of scope for a read-only probe; the point here is the
//! transport, the handshake, and the identity.

use std::time::Duration;
use truenas_api_client::{
    ApiClient, ApiConfig, AsUser, CredBroker, SessionOpts,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let uid = flag(&args, "--as-uid").map(|s| s.parse::<u32>().unwrap());
    let gid = flag(&args, "--as-gid").map(|s| s.parse::<u32>().unwrap());

    let cfg = ApiConfig {
        connect_timeout: Some(Duration::from_secs(10)),
        ..ApiConfig::default()
    };

    // Root path: the client owns its ring, sessions dial ambient.
    // Personality path: the ring predates the broker fork, the broker
    // mints the uid on it, and the session dials under it.
    let (mut api, opts) = match uid {
        None => (ApiClient::new(cfg)?, SessionOpts::default()),
        Some(uid) => {
            let ring = ApiClient::setup_ring(&cfg)?;
            let broker = CredBroker::spawn(&[&ring])?;
            let who = broker
                .handle(0)?
                .register(&AsUser::new(uid, gid.unwrap_or(uid)))?;
            (
                ApiClient::with_ring(cfg, ring)?,
                SessionOpts::default().personality(who),
            )
        }
    };

    let session = api.connect(opts)?;
    println!("session up");

    let pong: String = api.call(session, "core.ping", &empty())?;
    println!("core.ping -> {pong:?}");

    let info: serde_json::Value = api.call(session, "system.info", &empty())?;
    println!(
        "system.info -> version={:?} hostname={:?}",
        info.get("version"),
        info.get("hostname")
    );

    match api.call::<_, serde_json::Value>(session, "auth.me", &empty()) {
        Ok(me) => println!(
            "auth.me -> user={:?} privilege={:?}",
            me.get("pw_name"),
            me.get("privilege").and_then(|p| p.get("roles"))
        ),
        Err(e) => {
            println!("auth.me -> {e} (an unprivileged uid is unauthenticated)")
        }
    }

    api.close(session);
    while api.is_open(session) {
        if api.pump(Some(Duration::from_secs(5)))?.is_none() {
            break;
        }
    }
    Ok(())
}

/// An empty positional-params array.
fn empty() -> Vec<serde_json::Value> {
    Vec::new()
}

fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
}
