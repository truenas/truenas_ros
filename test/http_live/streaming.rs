use super::*;

/// Bind a **streaming** http server that reassembles what it is given and echoes it back, so the assertion is that a
/// body delivered in pieces is the body that was sent. `None` means io_uring is unavailable (a skip).
fn with_streaming_server<T: Send + 'static>(
    max_body: u64,
    client: impl FnOnce(SocketAddrV4) -> io::Result<T> + Send + 'static,
) -> Option<T> {
    use truenas_ros::http::{HttpVerdict, Stage, protocol_streaming};

    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    // Per-connection state: what the windows have added up to, and how many of them there were - the count is what
    // proves it streamed rather than arrived whole.
    let proto = protocol_streaming(
        HttpConfig::default(),
        max_body,
        |_inc: Incoming<'_>| Some((Vec::<u8>::new(), 0usize)),
        |req: HttpRequest<'_>, state: &mut (Vec<u8>, usize)| match req.stage {
            Stage::Open => {
                state.0.clear();
                state.1 = 0;
                HttpVerdict::Continue
            }
            Stage::Window => {
                state.0.extend_from_slice(&req.body[..]);
                state.1 += 1;
                HttpVerdict::Continue
            }
            Stage::End => {
                let windows = state.1;
                HttpVerdict::Respond(
                    HttpResponse::new(200)
                        .header("x-windows", windows.to_string())
                        .body(std::mem::take(&mut state.0)),
                )
            }
            Stage::Whole => HttpVerdict::Respond(HttpResponse::new(500)),
        },
    )
    .expect("codec config is valid");
    let mut server = match Server::bind([addr], proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return None,
        Err(e) => panic!("bind: {e}"),
    };
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();
    let join = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone());
        let r = client(v4);
        stop.shutdown();
        r
    });
    server.serve_forever().expect("serve_forever");
    Some(join.join().expect("client thread").expect("client io"))
}

/// A known-length streamed PUT whose exhausting window is resolved with `HttpDeferred::redrive` must not eat the next
/// pipelined request.
///
/// `Phase::StreamDone` is the marker for "the length is spent; the End stage is owed and there is no wire left to frame
/// it from". The resume route dispatches End off the park for exactly that reason. A redrive that restores the phase
/// instead leaves the connection in `StreamDone` with bytes buffered, and the framer's degrade arm then declares those
/// bytes - the next request's head - as this message's header, which the End dispatch parses as a trailer section. The
/// PUT is answered while the request behind it is consumed: a desync, and the reply the peer gets next belongs to a
/// request it never had answered.
#[test]
fn a_redriven_known_length_stream_does_not_eat_the_next_request() {
    use truenas_ros::http::{HttpDeferred, HttpVerdict, Stage, protocol_streaming};

    const PUT_LEN: usize = 200 * 1024;

    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    // One deferral, on the window that exhausts the declared length.
    let proto = protocol_streaming(
        HttpConfig::default(),
        1 << 20,
        |_inc: Incoming<'_>| Some((0usize, false)),
        |req: HttpRequest<'_>, st: &mut (usize, bool)| match req.stage {
            Stage::Open => {
                *st = (0, false);
                HttpVerdict::Continue
            }
            // Defer on the window that *exhausts* the declared length - the only one whose park carries the
            // `StreamDone` marker, because after it there is no wire left to frame End from.
            Stage::Window => {
                st.0 += req.body.len();
                if st.0 == PUT_LEN && !st.1 {
                    st.1 = true;
                    let (d, permit) = req.defer();
                    let d: HttpDeferred = d;
                    thread::spawn(move || {
                        thread::sleep(Duration::from_millis(20));
                        d.redrive();
                    });
                    return HttpVerdict::Defer(permit);
                }
                HttpVerdict::Continue
            }
            Stage::End => HttpVerdict::Respond(HttpResponse::new(200)),
            Stage::Whole => HttpVerdict::Respond(HttpResponse::new(204)),
        },
    )
    .expect("codec config is valid");
    let mut server = match Server::bind([addr], proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind: {e}"),
    };
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();
    let join = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone());
        let r = (|| -> io::Result<(u16, u16)> {
            let mut s = connect_tcp(v4)?;
            s.set_read_timeout(Some(Duration::from_secs(5)))?;
            // The PUT and a plain GET behind it, in one write, so the head read over-reads into the second request.
            let body = vec![b'x'; PUT_LEN];
            let mut wire =
                format!("PUT /up HTTP/1.1\r\nHost: t\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
            wire.extend_from_slice(&body);
            wire.extend_from_slice(b"GET /after HTTP/1.1\r\nHost: t\r\n\r\n");
            s.write_all(&wire)?;
            let (first, _h1, _b1) = read_response(&mut s)?;
            let (second, _h2, _b2) = read_response(&mut s)?;
            Ok((first, second))
        })();
        stop.shutdown();
        r
    });
    server.serve_forever().expect("serve_forever");
    let (first, second) = join.join().expect("client thread").expect("client io");
    assert_eq!(first, 200, "the PUT is answered");
    assert_eq!(
        second, 204,
        "the GET behind it must be framed as its own request, not eaten as \
         the PUT's trailer section"
    );
}

/// A streamed terminal chunk carries its trailers to `Stage::End`.
///
/// The trailer section is the whole point of the streaming path for an S3 front: `X-Amz-Trailer` promises a checksum
/// that only arrives after the last byte of payload, and a handler that never sees it cannot verify what it just wrote.
/// The buffered path is pinned by `chunked_put_and_trailers`; this is the streamed twin, and it asserts on the trailer
/// *reaching the handler* rather than on any framing detail.
#[test]
fn a_streamed_terminal_chunk_carries_its_trailers() {
    use truenas_ros::http::{HttpVerdict, Stage, protocol_streaming};

    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let proto = protocol_streaming(
        HttpConfig::default(),
        1 << 20,
        |_inc: Incoming<'_>| Some(()),
        |req: HttpRequest<'_>, _s: &mut ()| match req.stage {
            Stage::Open | Stage::Window => HttpVerdict::Continue,
            Stage::End => {
                // Name and value both, so a trailer that arrives empty is distinguishable from one that never arrived.
                let seen: Vec<String> = req
                    .trailers
                    .iter()
                    .map(|t| format!("{}={}", t.name, String::from_utf8_lossy(t.value)))
                    .collect();
                HttpVerdict::Respond(HttpResponse::new(200).header("x-trailers", seen.join(",")))
            }
            Stage::Whole => HttpVerdict::Respond(HttpResponse::new(500)),
        },
    )
    .expect("codec config is valid");
    let mut server = match Server::bind([addr], proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind: {e}"),
    };
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();
    let join = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone());
        let r = (|| -> io::Result<String> {
            let mut s = connect_tcp(v4)?;
            s.set_read_timeout(Some(Duration::from_secs(5)))?;
            s.write_all(
                b"PUT /up HTTP/1.1\r\nHost: t\r\n\
                  Transfer-Encoding: chunked\r\n\
                  X-Amz-Trailer: x-amz-checksum-crc32\r\n\r\n\
                  4\r\nAAAA\r\n0\r\nx-amz-checksum-crc32: sQlaLQ==\r\n\r\n",
            )?;
            let (status, head, _body) = read_response(&mut s)?;
            assert_eq!(status, 200);
            Ok(head)
        })();
        stop.shutdown();
        r
    });
    server.serve_forever().expect("serve_forever");
    let head = join.join().expect("client thread").expect("client io");
    assert!(
        head.contains("x-trailers: x-amz-checksum-crc32=sQlaLQ=="),
        "the streamed terminal chunk's trailer never reached the handler: \
         {head}"
    );
}

/// A multi-chunk PUT, streamed. The body is larger than any single window and arrives in pieces the handler never sees
/// together; what comes back has to be exactly what went out, and the window count has to show it was never assembled
/// by the codec.
#[test]
fn a_streamed_body_arrives_in_windows_and_survives_them() {
    let Some(()) = with_streaming_server(1 << 20, |v4| {
        let mut s = connect_tcp(v4)?;
        let mut payload = Vec::new();
        for i in 0..5u32 {
            payload.extend_from_slice(&[b'a' + (i as u8); 4096]);
        }
        let mut wire = b"PUT /echo HTTP/1.1\r\nHost: t\r\n\
                         Transfer-Encoding: chunked\r\n\r\n"
            .to_vec();
        for part in payload.chunks(4096) {
            wire.extend_from_slice(format!("{:x}\r\n", part.len()).as_bytes());
            wire.extend_from_slice(part);
            wire.extend_from_slice(b"\r\n");
        }
        wire.extend_from_slice(b"0\r\n\r\n");
        s.write_all(&wire)?;
        let (status, head, body) = read_response(&mut s)?;
        assert_eq!(status, 200);
        assert_eq!(body, payload, "every window's bytes, in order");
        assert!(
            head.to_ascii_lowercase().contains("x-windows: 5"),
            "one delivery per chunk, not one for the body: {head}"
        );
        Ok(())
    }) else {
        return; // io_uring unavailable
    };
}

/// A chunk larger than the window arrives in several windows. The bound on what this server buffers has to be one it
/// picked: otherwise a peer that sends a single large chunk decides it, and `max_request_bytes` is the only thing
/// standing between that and a megabyte per connection.
#[test]
fn one_oversized_chunk_is_delivered_in_several_windows() {
    let Some(()) = with_streaming_server(4 << 20, |v4| {
        let mut s = connect_tcp(v4)?;
        // One chunk, three windows' worth.
        let payload = vec![b'z'; 3 * 128 * 1024];
        let mut wire = b"PUT /echo HTTP/1.1\r\nHost: t\r\n\
                         Transfer-Encoding: chunked\r\n\r\n"
            .to_vec();
        wire.extend_from_slice(format!("{:x}\r\n", payload.len()).as_bytes());
        wire.extend_from_slice(&payload);
        wire.extend_from_slice(b"\r\n0\r\n\r\n");
        s.write_all(&wire)?;
        let (status, head, body) = read_response(&mut s)?;
        assert_eq!(status, 200);
        assert_eq!(body, payload, "split and rejoined without loss");
        assert!(
            head.to_ascii_lowercase().contains("x-windows: 3"),
            "one chunk, but three deliveries: {head}"
        );
        Ok(())
    }) else {
        return; // io_uring unavailable
    };
}

/// The decoded cap is measured as chunks are declared, so a body that exceeds it is refused partway through rather than
/// after being buffered -- which is the point, since it is never buffered.
#[test]
fn a_streamed_body_over_the_cap_is_refused_mid_stream() {
    let Some(()) = with_streaming_server(8192, |v4| {
        let mut s = connect_tcp(v4)?;
        let mut wire = b"PUT /echo HTTP/1.1\r\nHost: t\r\n\
                         Transfer-Encoding: chunked\r\n\r\n"
            .to_vec();
        for _ in 0..4 {
            wire.extend_from_slice(b"1000\r\n");
            wire.extend_from_slice(&[b'x'; 0x1000]);
            wire.extend_from_slice(b"\r\n");
        }
        wire.extend_from_slice(b"0\r\n\r\n");
        // The peer may be cut off mid-write once the server answers 413 and closes; that is the refusal working, not a
        // test failure.
        let _ = s.write_all(&wire);
        let (status, _) = read_head(&mut s)?;
        assert_eq!(status, 413, "refused as the cap was crossed");
        Ok(())
    }) else {
        return; // io_uring unavailable
    };
}

/// A handler that refuses partway through a body. The peer is still sending, and nothing will read the rest, so the
/// reply has to be final:
/// a keep-alive answer would leave the remaining chunks to be framed as the next request. The client must see the
/// status and then EOF.
#[test]
fn a_handler_refusing_mid_body_ends_the_connection() {
    use truenas_ros::http::{HttpVerdict, Stage, protocol_streaming};

    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let proto = protocol_streaming(
        HttpConfig::default(),
        1 << 20,
        |_inc: Incoming<'_>| Some(0usize),
        |req: HttpRequest<'_>, seen: &mut usize| match req.stage {
            Stage::Open => HttpVerdict::Continue,
            // Accept one window, then refuse - the shape a quota or a checksum failure has.
            Stage::Window if *seen == 0 => {
                *seen += 1;
                HttpVerdict::Continue
            }
            Stage::Window => HttpVerdict::Respond(HttpResponse::new(413).body("too much")),
            _ => HttpVerdict::Respond(HttpResponse::new(200)),
        },
    )
    .expect("codec config is valid");
    let mut server = match Server::bind([addr], proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind: {e}"),
    };
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();
    let join = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone());
        let r = (|| -> io::Result<()> {
            let mut s = connect_tcp(v4)?;
            let mut wire = b"PUT /o HTTP/1.1\r\nHost: t\r\n\
                             Transfer-Encoding: chunked\r\n\r\n"
                .to_vec();
            for _ in 0..4 {
                wire.extend_from_slice(b"1000\r\n");
                wire.extend_from_slice(&[b'x'; 0x1000]);
                wire.extend_from_slice(b"\r\n");
            }
            wire.extend_from_slice(b"0\r\n\r\n");
            // The refusal closes under us; a partial write is the mechanism working, not a failure.
            let _ = s.write_all(&wire);
            let (status, head1) = read_head(&mut s)?;
            assert_eq!(status, 413, "the handler's refusal reached the peer");
            assert!(
                head1.to_ascii_lowercase().contains("connection: close"),
                "a refusal has to announce the close, not just perform it - \
                 a peer told keep-alive and then given EOF cannot tell \
                 whether it was answered or cut off: {head1}"
            );
            // And then nothing: the connection is finished, so a read past the body sees EOF rather than another
            // response.
            let mut rest = Vec::new();
            s.read_to_end(&mut rest)?;
            assert!(
                !rest.windows(4).any(|w| w == b"HTTP"),
                "no second response was framed from the abandoned body"
            );
            Ok(())
        })();
        stop.shutdown();
        r
    });
    server.serve_forever().expect("serve_forever");
    join.join().expect("client thread").expect("client io");
}

/// The redrive twin of the resume test above: a deferred `Open` resolved by `HttpDeferred::redrive` - the handler
/// re-runs and answers `Continue` - owes the withheld interim exactly as a `resume()` does.
/// The two routes emit independently, so each carries its own pin;
/// without this one an expecting client holds its body back for its own timeout.
#[test]
fn a_redriven_stream_open_still_sends_the_interim() {
    use truenas_ros::http::{HttpVerdict, Stage, protocol_streaming};

    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let proto = protocol_streaming(
        HttpConfig::default(),
        1 << 20,
        |_inc: Incoming<'_>| Some(0usize),
        |req: HttpRequest<'_>, opened: &mut usize| match req.stage {
            Stage::Open if *opened == 0 => {
                *opened = 1;
                let (d, permit) = req.defer();
                thread::spawn(move || {
                    // The off-thread decision, resolved by re-running the handler rather than by resuming the stream.
                    thread::sleep(Duration::from_millis(20));
                    d.redrive();
                });
                HttpVerdict::Defer(permit)
            }
            Stage::Open => HttpVerdict::Continue,
            Stage::Window => HttpVerdict::Continue,
            Stage::End => HttpVerdict::Respond(HttpResponse::new(200)),
            Stage::Whole => HttpVerdict::Respond(HttpResponse::new(500)),
        },
    )
    .expect("codec config is valid");
    let mut server = match Server::bind([addr], proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind: {e}"),
    };
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();
    let join = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone());
        let r = (|| -> io::Result<()> {
            let mut s = connect_tcp(v4)?;
            s.set_read_timeout(Some(Duration::from_secs(5)))?;
            s.write_all(
                b"PUT /up HTTP/1.1\r\nHost: t\r\nExpect: 100-continue\r\n\
                  Transfer-Encoding: chunked\r\n\r\n",
            )?;
            // The client's half of the dance: no body until the interim.
            let mut interim = [0u8; 25];
            s.read_exact(&mut interim)?;
            assert_eq!(
                &interim[..],
                b"HTTP/1.1 100 Continue\r\n\r\n",
                "the redriven open swallowed the interim"
            );
            s.write_all(b"5\r\nhello\r\n0\r\n\r\n")?;
            let (status, _head, _body) = read_response(&mut s)?;
            assert_eq!(status, 200);
            Ok(())
        })();
        stop.shutdown();
        r
    });
    server.serve_forever().expect("serve_forever");
    join.join().expect("client thread").expect("client io");
}

/// A deferred stream open must still release the withheld `100 Continue`.
///
/// The interim is withheld pending the open decision, and an expecting client sends no body byte until it arrives - so
/// a handler that defers that decision (an authorization check is the canonical case) and then resumes must emit it
/// from the resume path, or every expecting PUT stalls for the client's own timeout against a server that thinks it is
/// waiting for a body.
#[test]
fn a_deferred_stream_open_still_sends_the_interim() {
    use truenas_ros::http::HttpStreamDeferred;

    let Some(()) = with_streaming_deferring_server(|v4| {
        let mut s = connect_tcp(v4)?;
        s.set_read_timeout(Some(Duration::from_secs(5)))?;
        s.write_all(
            b"PUT /up HTTP/1.1\r\nHost: t\r\nExpect: 100-continue\r\n\
              Transfer-Encoding: chunked\r\n\r\n",
        )?;
        // The client's half of the dance: no body until the interim.
        let mut interim = [0u8; 25];
        s.read_exact(&mut interim)?;
        assert_eq!(
            &interim[..],
            b"HTTP/1.1 100 Continue\r\n\r\n",
            "the deferred open swallowed the interim"
        );
        s.write_all(b"5\r\nhello\r\n0\r\n\r\n")?;
        let (status, _head, _body) = read_response(&mut s)?;
        assert_eq!(status, 200);
        Ok(())
    }) else {
        return; // io_uring unavailable
    };

    /// A streaming server whose `Open` handler defers off-thread and resumes a moment later - the review's reproducer
    /// shape.
    fn with_streaming_deferring_server<T: Send + 'static>(
        client: impl FnOnce(SocketAddrV4) -> io::Result<T> + Send + 'static,
    ) -> Option<T> {
        use truenas_ros::http::{HttpVerdict, Stage, protocol_streaming};

        let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
        let proto = protocol_streaming(
            HttpConfig::default(),
            1 << 20,
            |_inc: Incoming<'_>| Some(0usize),
            |req: HttpRequest<'_>, seen: &mut usize| match req.stage {
                Stage::Open => {
                    let (d, permit, _body) = req.defer_stream();
                    let d: HttpStreamDeferred = d;
                    thread::spawn(move || {
                        // The off-thread decision the park exists for.
                        thread::sleep(Duration::from_millis(20));
                        d.resume();
                    });
                    HttpVerdict::Defer(permit)
                }
                Stage::Window => {
                    *seen += req.body.len();
                    HttpVerdict::Continue
                }
                Stage::End => HttpVerdict::Respond(HttpResponse::new(200).header("x-bytes", seen.to_string())),
                Stage::Whole => HttpVerdict::Respond(HttpResponse::new(500)),
            },
        )
        .expect("codec config is valid");
        let mut server = match Server::bind([addr], proto) {
            Ok(s) => s,
            Err(e) if should_skip(&e) => return None,
            Err(e) => panic!("bind: {e}"),
        };
        let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
            panic!("expected Tcp");
        };
        let stop = server.shutdown_handle();
        let join = thread::spawn(move || {
            let _stop = ShutdownOnDrop(stop.clone());
            let r = client(v4);
            stop.shutdown();
            r
        });
        server.serve_forever().expect("serve_forever");
        Some(join.join().expect("client thread").expect("client io"))
    }
}

/// A peer pacing an exact read below `want / request_timeout` used to die mid-transfer: the linked request clock
/// cancelled the `MSG_WAITALL` recv with partial progress and the short-positive completion always closed. The
/// clock-cancelled continuation (`resubmit_exact_recv`) resumes the read instead, so the clock bounds
/// progress-per-period rather than imposing a throughput floor on the whole window.
///
/// 128 KiB `Content-Length` body written 16 KiB per ~150 ms against a 500 ms request clock: the transfer spans ~2 clock
/// periods, every period sees progress, and the upload must complete and echo back intact.
#[test]
fn a_put_pacing_a_window_below_the_clock_floor_completes() {
    use truenas_ros::net::server::ServerConfig;

    let cfg = ServerConfig {
        request_timeout: Some(Duration::from_millis(500)),
        ..ServerConfig::default()
    };
    let Some(()) = with_http_server_cfg(cfg, |v4| {
        let body: Vec<u8> = (0..128 * 1024).map(|i| (i % 249) as u8).collect();
        // A loaded runner can stall the pacing loop past a whole clock period, which is a legitimate zero-progress
        // close - retry those. The regression this pins is deterministic (the first mid-window expiry kills the
        // upload), so every attempt fails under it.
        let mut last = None;
        for _ in 0..3 {
            let r = (|| -> io::Result<Vec<u8>> {
                let mut s = connect_tcp(v4)?;
                write!(
                    s,
                    "PUT /echo HTTP/1.1\r\nHost: t\r\nContent-Length: {}\r\n\r\n",
                    body.len()
                )?;
                for chunk in body.chunks(16 * 1024) {
                    s.write_all(chunk)?;
                    thread::sleep(Duration::from_millis(150));
                }
                let (status, _, echoed) = read_response(&mut s)?;
                assert_eq!(status, 200);
                Ok(echoed)
            })();
            match r {
                Ok(echoed) => {
                    assert_eq!(echoed, body, "echoed body differs from what was sent");
                    return Ok(());
                }
                Err(e) => last = Some(e),
            }
        }
        Err(last.unwrap())
    }) else {
        return; // io_uring unavailable here
    };
}

/// The same pace through a STREAMED chunked upload - the default-client shape (botocore frames 128 KiB HTTP chunks, and
/// a streaming handler consumes them as stream windows). A plain accumulating handler dodges the floor by accident
/// (chunked bodies arrive through non-exact `More` scans, each arrival re-arming a fresh clock); a streamed window is
/// one exact `MSG_WAITALL` read under one clock, so this is where the chunked framing hit it.
#[test]
fn a_streamed_chunked_put_pacing_below_the_clock_floor_completes() {
    use std::sync::{Arc, Mutex};
    use truenas_ros::http::{HttpVerdict, Stage, protocol_streaming};
    use truenas_ros::net::server::ServerConfig;

    let body: Vec<u8> = (0..256 * 1024).map(|i| (i % 247) as u8).collect();
    let got = Arc::new(Mutex::new(Vec::new()));
    let sink = got.clone();

    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let proto = protocol_streaming(
        HttpConfig::default(),
        1 << 20,
        move |_inc: Incoming<'_>| Some(sink.clone()),
        |mut req: HttpRequest<'_>, sink: &mut Arc<Mutex<Vec<u8>>>| match req.stage {
            Stage::Open => HttpVerdict::Continue,
            Stage::Window => {
                sink.lock().unwrap().extend_from_slice(&req.body.take());
                HttpVerdict::Continue
            }
            Stage::End => HttpVerdict::Respond(HttpResponse::new(200)),
            Stage::Whole => HttpVerdict::Respond(HttpResponse::new(500)),
        },
    )
    .expect("codec config is valid");
    let cfg = ServerConfig {
        request_timeout: Some(Duration::from_millis(500)),
        ..ServerConfig::default()
    };
    let mut server = match Server::with_config([addr], cfg, proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind: {e}"),
    };
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();
    let sent = body.clone();
    let join = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone());
        // Same retry policy as the Content-Length twin above: a loaded runner stalling a full period is a legitimate
        // close, while the pinned regression fails every attempt.
        let mut last = None;
        for _ in 0..3 {
            got.lock().unwrap().clear();
            let r = (|| -> io::Result<()> {
                let mut s = connect_tcp(v4)?;
                write!(
                    s,
                    "PUT /up HTTP/1.1\r\nHost: t\r\n\
                     Transfer-Encoding: chunked\r\n\r\n{:x}\r\n",
                    sent.len()
                )?;
                for chunk in sent.chunks(16 * 1024) {
                    s.write_all(chunk)?;
                    thread::sleep(Duration::from_millis(80));
                }
                s.write_all(b"\r\n0\r\n\r\n")?;
                let (status, _, _) = read_response(&mut s)?;
                assert_eq!(status, 200);
                Ok(())
            })();
            match r {
                Ok(()) => {
                    let delivered = got.lock().unwrap();
                    assert_eq!(*delivered, sent, "windows delivered differ from what was sent");
                    stop.shutdown();
                    return Ok(());
                }
                Err(e) => last = Some(e),
            }
        }
        stop.shutdown();
        Err(last.unwrap())
    });
    server.serve_forever().expect("serve_forever");
    join.join().expect("client thread").expect("client io");
}

/// The continuation must not have unseated the slow-loris guard: a transfer that makes NO progress for a full
/// request-clock period still closes. The peer sends a quarter of the declared body and then stalls; the server must
/// FIN within a few periods, never answer 200.
#[test]
fn a_stalled_transfer_still_dies_by_the_request_clock() {
    use truenas_ros::net::server::ServerConfig;

    let cfg = ServerConfig {
        request_timeout: Some(Duration::from_millis(250)),
        ..ServerConfig::default()
    };
    let Some(()) = with_http_server_cfg(cfg, |v4| {
        let mut s = connect_tcp(v4)?;
        write!(s, "PUT /echo HTTP/1.1\r\nHost: t\r\nContent-Length: 131072\r\n\r\n")?;
        s.write_all(&[7u8; 32 * 1024])?;
        // Stall. The read outlasts several clock periods, so anything but the server closing the connection is a
        // failure; a 200 here means a quarter of a body was delivered as whole.
        s.set_read_timeout(Some(Duration::from_secs(5)))?;
        let mut b = [0u8; 512];
        match s.read(&mut b) {
            Ok(0) => Ok(()), // FIN: the clock reclaimed the slot
            Ok(n) => panic!(
                "server answered {} bytes to a stalled quarter-body: {:?}",
                n,
                String::from_utf8_lossy(&b[..n.min(64)])
            ),
            // ECONNRESET is a close with unread bytes on some paths.
            Err(e) if e.kind() == io::ErrorKind::ConnectionReset => Ok(()),
            Err(e) => panic!("expected the server to close, got {e}"),
        }
    }) else {
        return; // io_uring unavailable here
    };
}

/// A streamed body between windows is a message in progress, not an idle connection - so it carries `request_timeout`
/// and arms `max_receipt_time`.
///
/// The reactor cannot tell the two apart on its own: a streaming codec consumes each window as its own message, so at a
/// chunk boundary (and after the head has gone out as `Stage::Open`) the accumulate buffer is empty, which is exactly
/// what "parked for the next request" looks like. `Framing::MoreInMessage` is the framer saying otherwise.
///
/// The negative control is the configuration: `idle_timeout` is deliberately unset here, so if the read is
/// misclassified as idle it carries **no clock at all** and the peer holds its pool slot - taken at accept, before any
/// authentication - forever. Reverting `known_step`/`stream_step`/ `scan_step` to plain `More` hangs this test rather
/// than failing it fast, which is the shape of the denial it guards.
#[test]
fn a_stalled_streamed_upload_is_reaped_mid_body() {
    use std::sync::{Arc, Mutex};
    use truenas_ros::http::{HttpConn, HttpVerdict, Stage, protocol_streaming};
    use truenas_ros::net::CloseReason;
    use truenas_ros::net::server::ServerConfig;

    for (what, trailer) in [
        // Stall the moment the head has been delivered: the framer is in `StreamOpen` -> `StreamBody` with nothing
        // buffered.
        ("after the head", None),
        // Stall at a chunk boundary, the CRLF after the payload withheld so the buffer is empty there too.
        ("after one full window", Some(128 * 1024usize)),
    ] {
        let reasons = Arc::new(Mutex::new(Vec::new()));
        let cfg = ServerConfig {
            request_timeout: Some(Duration::from_millis(300)),
            max_receipt_time: Some(Duration::from_millis(900)),
            idle_timeout: None, // the control: nothing else can reap this
            ..ServerConfig::default()
        };
        let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
        let proto = protocol_streaming(
            HttpConfig::default(),
            1 << 30,
            |_inc: Incoming<'_>| Some(()),
            |req: HttpRequest<'_>, _s: &mut ()| match req.stage {
                Stage::End => HttpVerdict::Respond(HttpResponse::new(200)),
                Stage::Whole => HttpVerdict::Respond(HttpResponse::new(500)),
                _ => HttpVerdict::Continue,
            },
        )
        .expect("codec config is valid");
        let mut server = match Server::with_config([addr], cfg, proto) {
            Ok(s) => s,
            Err(e) if should_skip(&e) => return,
            Err(e) => panic!("bind: {e}"),
        };
        {
            let reasons = Arc::clone(&reasons);
            server.set_close_hook(move |_a, reason, _s: &mut HttpConn<()>| {
                reasons.lock().unwrap().push(reason);
            });
        }
        let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
            panic!("expected Tcp");
        };
        let stop = server.shutdown_handle();
        let join = thread::spawn(move || {
            let _stop = ShutdownOnDrop(stop.clone());
            let r = (|| -> io::Result<()> {
                let mut s = connect_tcp(v4)?;
                s.write_all(
                    b"PUT /o HTTP/1.1\r\nHost: t\r\n\
                      Transfer-Encoding: chunked\r\n\r\n",
                )?;
                s.flush()?;
                if let Some(n) = trailer {
                    s.write_all(format!("{n:x}\r\n").as_bytes())?;
                    s.write_all(&vec![b'A'; n])?;
                    s.flush()?; // no closing CRLF: the buffer drains empty
                }
                // Now stall. Only the server closing ends this read.
                s.set_read_timeout(Some(Duration::from_secs(8)))?;
                let mut b = [0u8; 64];
                match s.read(&mut b) {
                    Ok(0) => Ok(()),
                    Ok(n) => panic!(
                        "answered {n} bytes to a stalled upload: {:?}",
                        String::from_utf8_lossy(&b[..n.min(64)])
                    ),
                    Err(e) if e.kind() == io::ErrorKind::ConnectionReset => Ok(()),
                    Err(e) => panic!("{what}: the server never reclaimed the slot: {e}"),
                }
            })();
            stop.shutdown();
            r
        });
        server.serve_forever().expect("serve_forever");
        join.join().expect("client thread").expect("client io");
        let got = reasons.lock().unwrap().clone();
        assert_eq!(
            got.as_slice(),
            &[CloseReason::RequestTimeout],
            "{what}: a stalled streamed body must read as RequestTimeout - \
             IdleTimeout would mean the read took the wrong clock, and \
             nothing at all means it took none"
        );
    }
}

/// The receipt budget reaches a streamed window: a peer pacing one window slower than `max_receipt_time` is reclaimed
/// even though it satisfies `request_timeout` throughout.
///
/// This is the property that separates the two clocks (`ServerConfig::max_receipt_time`), on the framing where the
/// floor the config documents - one window over the budget - actually has to hold.
///
/// Not a control for `Framing::MoreInMessage`: the chunk-size line leaves bytes buffered, so this arm would find the
/// budget armed either way. The stall above is the case that needs the framer's verdict.
#[test]
fn a_streamed_window_paced_under_the_floor_is_reclaimed() {
    use std::sync::{Arc, Mutex};
    use truenas_ros::http::{HttpConn, HttpVerdict, Stage, protocol_streaming};
    use truenas_ros::net::CloseReason;
    use truenas_ros::net::server::ServerConfig;

    let reasons = Arc::new(Mutex::new(Vec::new()));
    let cfg = ServerConfig {
        request_timeout: Some(Duration::from_millis(300)),
        max_receipt_time: Some(Duration::from_millis(800)),
        idle_timeout: None,
        ..ServerConfig::default()
    };
    let addr = ServerAddr::Tcp("127.0.0.1:0".parse::<SocketAddrV4>().unwrap());
    let proto = protocol_streaming(
        HttpConfig::default(),
        1 << 30,
        |_inc: Incoming<'_>| Some(()),
        |req: HttpRequest<'_>, _s: &mut ()| match req.stage {
            Stage::End => HttpVerdict::Respond(HttpResponse::new(200)),
            Stage::Whole => HttpVerdict::Respond(HttpResponse::new(500)),
            _ => HttpVerdict::Continue,
        },
    )
    .expect("codec config is valid");
    let mut server = match Server::with_config([addr], cfg, proto) {
        Ok(s) => s,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("bind: {e}"),
    };
    {
        let reasons = Arc::clone(&reasons);
        server.set_close_hook(move |_a, reason, _s: &mut HttpConn<()>| {
            reasons.lock().unwrap().push(reason);
        });
    }
    let ServerAddr::Tcp(v4) = server.local_addrs().remove(0) else {
        panic!("expected Tcp");
    };
    let stop = server.shutdown_handle();
    let join = thread::spawn(move || {
        let _stop = ShutdownOnDrop(stop.clone());
        let r = (|| -> io::Result<()> {
            let mut s = connect_tcp(v4)?;
            s.write_all(
                b"PUT /o HTTP/1.1\r\nHost: t\r\n\
                  Transfer-Encoding: chunked\r\n\r\n",
            )?;
            // A chunk far larger than one window, then one byte per 150 ms -- half `request_timeout`, so that clock is
            // satisfied throughout while the window needs hours.
            s.write_all(b"40000\r\n")?;
            s.flush()?;
            for _ in 0..40 {
                if s.write_all(b"A").is_err() || s.flush().is_err() {
                    break; // the server closed under us, which is the point
                }
                thread::sleep(Duration::from_millis(150));
            }
            s.set_read_timeout(Some(Duration::from_secs(5)))?;
            let mut b = [0u8; 64];
            match s.read(&mut b) {
                Ok(0) => Ok(()),
                Ok(n) => panic!("answered {n} bytes to a trickling window"),
                Err(e) if e.kind() == io::ErrorKind::ConnectionReset => Ok(()),
                Err(e) => panic!("the server never reclaimed the slot: {e}"),
            }
        })();
        stop.shutdown();
        r
    });
    server.serve_forever().expect("serve_forever");
    join.join().expect("client thread").expect("client io");
    assert_eq!(
        reasons.lock().unwrap().as_slice(),
        &[CloseReason::ReceiptTimeout],
        "a window paced under the floor must read as ReceiptTimeout - \
         RequestTimeout would mean the inactivity guard caught it and the \
         budget never armed"
    );
}
