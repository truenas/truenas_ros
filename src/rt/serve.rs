//! [`serve`]: the one opinionated net helper — an accept loop with a
//! connection cap and a graceful drain. Everything else about serving
//! (protocols, TLS policy, routing) belongs to the consumer's ordinary
//! tokio code; this exists because cap + drain logic is subtle enough to
//! write once, not per daemon.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, Semaphore};
use tokio::task::JoinSet;

/// Limits for [`serve`].
#[derive(Clone, Copy, Debug)]
pub struct ServeOptions {
    /// Maximum concurrent connections; accepts queue (in the kernel
    /// backlog) beyond it.
    pub max_connections: usize,
    /// How long a graceful shutdown waits for in-flight connections before
    /// aborting the stragglers.
    pub drain: Duration,
}

impl Default for ServeOptions {
    fn default() -> ServeOptions {
        ServeOptions {
            max_connections: 1024,
            drain: Duration::from_secs(5),
        }
    }
}

/// Accept connections until `shutdown` flips to `true`, spawning
/// `per_conn(stream, peer)` as one task per connection, at most
/// `max_connections` at once. On shutdown: stop accepting, wait up to
/// `drain` for the in-flight tasks, then abort the rest. Returns when
/// drained.
///
/// The handler owns its stream outright — wrap it (kTLS, tungstenite),
/// bridge it, or drop it; when the handler returns, its connection slot
/// frees.
pub async fn serve<F, Fut>(
    listener: TcpListener,
    opts: ServeOptions,
    mut shutdown: watch::Receiver<bool>,
    per_conn: F,
) -> crate::Result<()>
where
    F: Fn(TcpStream, SocketAddr) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let per_conn = Arc::new(per_conn);
    let cap = Arc::new(Semaphore::new(opts.max_connections.max(1)));
    let mut tasks: JoinSet<()> = JoinSet::new();

    loop {
        // Phase 1: reserve a connection slot. Awaiting the permit *inside*
        // the accept arm (the naive shape) would park the whole loop at
        // max_connections, so a shutdown signal would go unpolled until a
        // handler happened to finish — graceful shutdown could hang past its
        // deadline. Acquiring it as its own shutdown-aware select keeps the
        // watch responsive even while every slot is taken.
        let permit = tokio::select! {
            biased;
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
                continue;
            }
            // Reap finished handlers so the set never grows unbounded.
            Some(_) = tasks.join_next(), if !tasks.is_empty() => continue,
            permit = cap.clone().acquire_owned() => {
                permit.expect("cap semaphore never closed")
            }
        };

        // Phase 2: accept a connection, still watching shutdown (and
        // dropping the reserved permit on either exit).
        let (stream, peer) = tokio::select! {
            biased;
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
                continue; // spurious wake — release the permit, retry
            }
            accepted = listener.accept() => match accepted {
                Ok(a) => a,
                // Transient accept errors (EMFILE bursts, aborted
                // handshakes) shouldn't kill the loop.
                Err(_) => continue,
            },
        };

        let per_conn = per_conn.clone();
        tasks.spawn(async move {
            let _slot = permit; // held for the handler's lifetime
            per_conn(stream, peer).await;
        });
    }

    // Graceful drain: no new accepts (listener drops with this frame's
    // borrow), bounded wait for the in-flight handlers.
    drop(listener);
    let deadline = tokio::time::Instant::now() + opts.drain;
    while !tasks.is_empty() {
        match tokio::time::timeout_at(deadline, tasks.join_next()).await {
            Ok(Some(_)) => {}
            Ok(None) => break,
            Err(_) => {
                tasks.abort_all();
                while tasks.join_next().await.is_some() {}
                break;
            }
        }
    }
    Ok(())
}
