use super::*;

/// The S3 GET preamble through the HTTP codec: the handler takes the facade, parks the request, opens under the
/// server's personality on the ring, and ONE `offload_result` job runs the whole blocking metadata tail (`statx` plus
/// two xattr reads) - the reply is served from its delivery. Mirrors
/// `fs_conn_offload_result_batches_statx_and_xattrs_in_one_job` (`test/net_server.rs`) with the codec in the loop.
#[cfg(feature = "uring-fs")]
#[test]
fn http_handler_reads_a_file_through_one_batched_job() {
    use std::sync::{Arc, OnceLock};
    use truenas_ros::http::HttpVerdict;
    use truenas_ros::sync_fs::xattr::fgetxattr;
    use truenas_ros::sync_fs::{AtFlags, OFlag, OpenHow, StatxMask, statx};
    use truenas_ros::uring_fs::{Anchor, Personality};

    let dir = truenas_ros::tempdir().unwrap();
    let fp = dir.path().join("f.txt");
    std::fs::write(&fp, b"hello object").unwrap();
    if !set_user_xattr(&fp, b"user.a", b"1") || !set_user_xattr(&fp, b"user.b", b"22") {
        return; // this fs refuses user xattrs
    }
    let anchor = match Anchor::open(dir.path()) {
        Ok(a) => a,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("anchor open: {e}"),
    };
    let pers: Arc<OnceLock<Personality>> = Arc::new(OnceLock::new());

    let pc = Arc::clone(&pers);
    let handler: FsHandler<()> = Box::new(move |req, _state, fs| {
        let Some(mut fs) = fs else {
            return HttpVerdict::Respond(HttpResponse::new(500).body("no fs pool\n"));
        };
        let (deferred, permit) = req.defer();
        let who = *pc.get().expect("personality set before serving");
        let anchor = anchor.clone();
        let how = OpenHow::new().flags(OFlag::O_RDONLY);
        fs.open(who, &anchor, c"f.txt", how, move |done, fs| {
            let Some(file) = done.file() else {
                return deferred.close();
            };
            fs.offload_result(
                move || {
                    let st = statx(&file, c"", AtFlags::AT_EMPTY_PATH, StatxMask::BASIC_STATS)?;
                    let a = fgetxattr(&file, "user.a")?;
                    let b = fgetxattr(&file, "user.b")?;
                    Ok((st.size(), a, b))
                },
                move |res, _fs| match res {
                    Ok((size, a, b)) => deferred.reply(HttpResponse::new(200).body(format!(
                        "{size}:{}:{}",
                        String::from_utf8_lossy(&a),
                        String::from_utf8_lossy(&b),
                    ))),
                    Err(_) => deferred.close(),
                },
            );
        });
        HttpVerdict::Defer(permit)
    });

    let Some(()) = with_http_fs_server(
        || (),
        handler,
        pers,
        |v4| {
            let mut s = connect_tcp(v4)?;
            s.set_read_timeout(Some(Duration::from_secs(5)))?;
            s.write_all(b"GET /f.txt HTTP/1.1\r\nHost: t\r\n\r\n")?;
            let (status, _head, body) = read_response(&mut s)?;
            assert_eq!(status, 200);
            assert_eq!(body, b"12:1:22", "one job returned size and both xattrs");
            Ok(())
        },
    ) else {
        return; // io_uring unavailable
    };
}

/// `HttpDeferred::redrive` hands a handler a fresh request-handler facade, with the request state it parked in `U`.
///
/// Every facade can `open` - the gate that once stopped a continuation from opening is gone, and
/// `fs_continuation_may_open_and_its_slot_comes_back` pins that directly. What survives is the redelivery contract: a
/// handler whose next step depends on an earlier result parks its progress, redrives from wherever the earlier result
/// landed, and must get a facade back at all - a redelivery that dropped its continuation would close the connection
/// instead of answering.
#[cfg(feature = "uring-fs")]
#[test]
fn http_redrive_returns_a_facade_with_the_parked_state() {
    use std::sync::{Arc, OnceLock};
    use truenas_ros::http::HttpVerdict;
    use truenas_ros::sync_fs::{OFlag, OpenHow};
    use truenas_ros::uring_fs::{Anchor, Personality};

    let dir = truenas_ros::tempdir().unwrap();
    std::fs::write(dir.path().join("f.txt"), b"x").unwrap();
    let anchor = match Anchor::open(dir.path()) {
        Ok(a) => a,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("anchor open: {e}"),
    };
    let pers: Arc<OnceLock<Personality>> = Arc::new(OnceLock::new());

    let pc = Arc::clone(&pers);
    let handler: FsHandler<bool> = Box::new(move |req, redriven, fs| {
        let Some(mut fs) = fs else {
            return HttpVerdict::Respond(HttpResponse::new(500).body("no fs pool\n"));
        };
        if !*redriven {
            // First pass: park, and redrive from an offload delivery - the seam furthest from the request handler.
            *redriven = true;
            let (deferred, permit) = req.defer();
            fs.offload_result(|| Ok(()), move |_res, _fs| deferred.redrive());
            HttpVerdict::Defer(permit)
        } else {
            // Second pass (the redelivery): this facade must open.
            let (deferred, permit) = req.defer();
            let who = *pc.get().expect("personality set before serving");
            let how = OpenHow::new().flags(OFlag::O_RDONLY);
            fs.open(who, &anchor, c"f.txt", how, move |done, _fs| match done.file() {
                Some(_) => deferred.reply(HttpResponse::new(200).body("opened")),
                None => deferred.close(),
            });
            HttpVerdict::Defer(permit)
        }
    });

    let Some(()) = with_http_fs_server(
        || false,
        handler,
        pers,
        |v4| {
            let mut s = connect_tcp(v4)?;
            s.set_read_timeout(Some(Duration::from_secs(5)))?;
            s.write_all(b"GET /again HTTP/1.1\r\nHost: t\r\n\r\n")?;
            let (status, _head, body) = read_response(&mut s)?;
            assert_eq!(status, 200);
            assert_eq!(body, b"opened", "the redelivered facade opened a file");
            Ok(())
        },
    ) else {
        return; // io_uring unavailable
    };
}
