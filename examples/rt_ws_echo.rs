//! The layering proof for the tokio-hybrid runtime: a WebSocket echo server
//! whose messages are journaled to disk through the io_uring fs reactor.
//!
//! Nothing here is bespoke protocol code — that is the point:
//!
//! - **WebSocket** comes from `tokio_tungstenite::accept_async` over the
//!   plain accepted `TcpStream` (a [`KtlsStream`] slots in identically —
//!   anything `AsyncRead + AsyncWrite` does).
//! - **Accept/cap/drain** come from [`rt::serve`].
//! - **File I/O** goes through [`rt::FsRt`] — kernel-checked under the
//!   daemon's registered personality, awaited from ordinary tokio tasks.
//!
//! Run: `cargo run --example rt_ws_echo --features __ws-example` then point
//! any WS client at `ws://127.0.0.1:9002` — every message echoes back and
//! appends to `<tempdir>/ws.log` via the ring.
//!
//! [`KtlsStream`]: truenas_ros::rt::KtlsStream
//! [`rt::serve`]: truenas_ros::rt::serve
//! [`rt::FsRt`]: truenas_ros::rt::FsRt

use futures_util::{SinkExt, StreamExt};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use truenas_ros::async_fs::{Anchor, FsConfig};
use truenas_ros::rt::{serve, FsRuntimeBuilder, ServeOptions};
use truenas_ros::sync_fs::{Mode, OFlag, OpenHow};

fn main() -> truenas_ros::Result<()> {
    // Ring first, then (optionally) the credential broker, THEN threads —
    // the builder encodes the ordering; this example skips the broker and
    // acts as itself.
    let builder = FsRuntimeBuilder::new(FsConfig::default())?;
    let me = builder.register_self()?;
    let fs_rt = builder.start()?;

    let dir = tempfile::tempdir().expect("tempdir");
    println!("journal: {}", dir.path().join("ws.log").display());
    let anchor = Anchor::open(dir.path())?;

    let trt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    trt.block_on(async {
        let fs = fs_rt.rt();
        let how = OpenHow::new()
            .flags(OFlag::O_CREAT | OFlag::O_WRONLY)
            .mode(Mode::from_bits_truncate(0o600));
        let log = Arc::new(fs.open(me, &anchor, "ws.log", how).await?);
        let cursor = Arc::new(AtomicU64::new(0));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:9002")
            .await
            .expect("bind");
        println!("listening on ws://127.0.0.1:9002 (ctrl-c to stop)");
        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        tokio::spawn(async move {
            let _ = tokio::signal::ctrl_c().await;
            let _ = stop_tx.send(true);
        });

        let conn_fs = fs.clone();
        let conn_log = log.clone();
        let conn_cursor = cursor.clone();
        serve(
            listener,
            ServeOptions {
                max_connections: 256,
                drain: Duration::from_secs(2),
            },
            stop_rx,
            move |stream, peer| {
                let fs = conn_fs.clone();
                let log = conn_log.clone();
                let cursor = conn_cursor.clone();
                async move {
                    // The whole WebSocket protocol, from the ecosystem:
                    let Ok(mut ws) =
                        tokio_tungstenite::accept_async(stream).await
                    else {
                        return;
                    };
                    while let Some(Ok(msg)) = ws.next().await {
                        if msg.is_close() {
                            break;
                        }
                        if !(msg.is_text() || msg.is_binary()) {
                            continue; // ping/pong: tungstenite's business
                        }
                        // Journal through the ring, as the registered
                        // personality, from this ordinary tokio task.
                        let mut line = format!("{peer}: ").into_bytes();
                        line.extend_from_slice(&msg.clone().into_data());
                        line.push(b'\n');
                        let at = cursor
                            .fetch_add(line.len() as u64, Ordering::SeqCst);
                        let (res, _buf) = fs.pwrite(me, &log, line, at).await;
                        if res.is_err() {
                            break;
                        }
                        if ws.send(msg).await.is_err() {
                            break;
                        }
                    }
                }
            },
        )
        .await?;
        let log = Arc::try_unwrap(log).expect("all handlers drained");
        fs.fsync(me, &log).await?;
        fs.close(log).await?;
        Ok::<(), truenas_ros::Error>(())
    })?;

    fs_rt.shutdown()
}
