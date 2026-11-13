use super::*;
use crate::net::ClientAddr;
use crate::net::server::Body;
use crate::sync::thread;

fn unreached(_: HttpRequest<'_>, _: &mut (), _: FsSlot<'_>) -> HttpVerdict {
    panic!("worker reply surfaced as a redrive")
}

#[test]
fn loom_worker_reply_is_never_a_redrive() {
    loom::model(|| {
        let (responder, probe) = Responder::test_responder_with_probe();
        let peer = ClientAddr::Inet("127.0.0.1:9000".parse().unwrap());
        let req = HttpRequest {
            method: "GET",
            target: "/",
            version: Version::Http11,
            headers: &[],
            body: Body::inline(b""),
            raw_head: b"GET / HTTP/1.1\r\nHost: h\r\n\r\n",
            trailers: &[],
            peer: &peer,
            stage: Stage::Whole,
            responder,
        };
        let (deferred, permit) = req.defer();
        let HttpDeferPermit {
            permit: _permit,
            req: parked,
        } = permit;
        let mut conn: HttpConn<()> = HttpConn::new(());
        conn.phase = Phase::Parked {
            req: parked,
            resume: None,
        };

        let worker = thread::spawn(move || {
            deferred.reply(HttpResponse::new(204));
        });

        probe.recv_redeliver();
        let resp = step(
            b"",
            Body::inline(b""),
            &peer,
            Responder::test_responder(),
            FsSlot::default(),
            &mut conn,
            &mut DateCache::default(),
            &mut unreached,
        );
        let Response::Reply(bytes) = resp else {
            panic!("expected the worker's reply, got {resp:?}");
        };
        assert!(bytes.starts_with(b"HTTP/1.1 204"));
        worker.join().unwrap();
    });
}
