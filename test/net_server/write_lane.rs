use super::fs_files::{one_fs_reply, owned_write_verdict};
use super::*;
use std::cell::RefCell;
use std::rc::Rc;
use truenas_ros::uring_fs::{File, FsDone, RwFlags};

/// What a write of a window answered, and whether it was marked.
fn window_verdict(d: &FsDone) -> String {
    let res = match d.result() {
        Ok(n) => format!("ok {n}"),
        Err(Error::Errno(e)) => format!("{e:?}"),
        Err(e) => format!("{e}"),
    };
    format!("{res} marked={}", d.was_refused())
}

/// The write lane writes storage and windows of the request where they ask on ZFS, with the flags given, which reach
/// the call, since ZFS answers `RWF_NOWAIT` with `EOPNOTSUPP` and writes nothing. Storage comes back whole, a window at
/// an `off` of `u64::MAX` is refused with a marked `EINVAL`, and the receive buffer goes home once its windows are
/// written.
#[test]
fn the_write_lane_writes_where_it_is_asked_with_the_flags_given() {
    let Some(ds) = zfs_dir::zfs_dir_or_skip() else {
        return;
    };
    let dir = ds.join(format!("rostest_write_lane_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir(&dir).unwrap();
    let fp = dir.join("f");
    std::fs::write(&fp, b"............").unwrap();
    let held: Arc<std::os::fd::OwnedFd> = Arc::new(std::fs::OpenOptions::new().write(true).open(&fp).unwrap().into());
    let cfg = ServerConfig {
        pool_size: 4,
        fs_ops: 16,
        ..ServerConfig::default()
    };
    let reply = one_fs_reply(cfg, b"0123456789", move |mut req, _who| {
        let (deferred, permit) = req.responder.defer();
        let Some(mut fs) = req.fs.take() else {
            return Response::Close;
        };
        let Some(window) = fs.lease_window(&req.body[..]) else {
            deferred.reply(echo_frame(b"not leased"));
            return Response::Defer(permit);
        };
        let answers = Rc::new(RefCell::new(vec![String::new(); 6]));
        let deferred = Rc::new(RefCell::new(Some(deferred)));
        let answer = move |answers: &Rc<RefCell<Vec<String>>>, i: usize, text: String| {
            answers.borrow_mut()[i] = text;
            if answers.borrow().iter().all(|a| !a.is_empty())
                && let Some(deferred) = deferred.borrow_mut().take()
            {
                deferred.reply(echo_frame(answers.borrow().join("\n").as_bytes()));
            }
        };
        let answer = Rc::new(answer);
        let owned = [(0, RwFlags::empty()), (4, RwFlags::RWF_DSYNC), (8, RwFlags::RWF_NOWAIT)];
        for (i, (off, flags)) in owned.into_iter().enumerate() {
            let buf = b"WXYZ".to_vec();
            let storage = buf.as_ptr();
            let (answers, answer) = (Rc::clone(&answers), Rc::clone(&answer));
            let file = File::from_shared(Arc::clone(&held));
            fs.offload_write_owned(file, buf, 0..4, off, flags, move |d, _| {
                answer(&answers, i, owned_write_verdict(d, storage, b"WXYZ"));
            });
        }
        let (head, tail) = window.split_at(4);
        let (tail, rest) = tail.split_at(6);
        let windows = [
            (head, 12, RwFlags::RWF_SYNC),
            (tail, 16, RwFlags::empty()),
            (rest, u64::MAX, RwFlags::empty()),
        ];
        for (i, (window, off, flags)) in windows.into_iter().enumerate() {
            let (answers, answer) = (Rc::clone(&answers), Rc::clone(&answer));
            let file = File::from_shared(Arc::clone(&held));
            fs.offload_write_window(file, window, off, flags, move |d, _| {
                answer(&answers, 3 + i, window_verdict(&d));
            });
        }
        Response::Defer(permit)
    });
    let file = std::fs::read(&fp).unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
    let Some((reply, stats)) = reply else {
        return;
    };
    let expected = [
        "ok 4 marked=false same=true",
        "ok 4 marked=false same=true",
        "EOPNOTSUPP marked=false same=true",
        "ok 4 marked=false",
        "ok 6 marked=false",
        "EINVAL marked=true",
    ];
    assert_eq!(String::from_utf8_lossy(&reply), expected.join("\n"));
    assert_eq!(
        file, b"WXYZWXYZ....0123456789",
        "each write at its offset, and none for RWF_NOWAIT"
    );
    assert!(stats.recv_bufs_total > 0, "no receive pool: {stats:?}");
    assert_eq!(stats.recv_bufs_lent, 0, "the buffer came home: {stats:?}");
}

/// On ZFS a write by the lane as root clears the set-user-ID bit of a file with an execute bit, as an unprivileged
/// caller's write does, while a write on the ring under the root daemon's own personality keeps it, so the lane's
/// threads write without `CAP_FSETID`. `zfs_write` clears the bit in a check of its own
/// (`zfs_clear_setid_bits_if_necessary`), which a file of tmpfs never reaches.
#[test]
fn a_lane_write_as_root_clears_the_set_user_id_bit() {
    use std::os::unix::fs::PermissionsExt;
    if !root_or_skip("a_lane_write_as_root_clears_the_set_user_id_bit") {
        return;
    }
    let Some(ds) = zfs_dir::zfs_dir_or_skip() else {
        return;
    };
    let dir = ds.join(format!("rostest_write_lane_setid_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir(&dir).unwrap();
    let open = |name: &str| -> Arc<std::os::fd::OwnedFd> {
        let fp = dir.join(name);
        std::fs::write(&fp, b"bytes").unwrap();
        std::fs::set_permissions(&fp, std::fs::Permissions::from_mode(0o4755)).unwrap();
        Arc::new(std::fs::OpenOptions::new().write(true).open(&fp).unwrap().into())
    };
    let (ring, lane) = (open("ring"), open("lane"));
    let cfg = ServerConfig {
        pool_size: 4,
        fs_ops: 16,
        ..ServerConfig::default()
    };
    let reply = one_fs_reply(cfg, b"go", move |mut req, who| {
        let (deferred, permit) = req.responder.defer();
        let Some(mut fs) = req.fs.take() else {
            return Response::Close;
        };
        let (ring, lane) = (
            File::from_shared(Arc::clone(&ring)),
            File::from_shared(Arc::clone(&lane)),
        );
        let flags = RwFlags::empty();
        fs.pwritev2_owned(who, ring, b"x".to_vec(), 0..1, 0, flags, move |first, fs| {
            let first = first.result().ok();
            fs.offload_write_owned(lane, b"x".to_vec(), 0..1, 0, flags, move |second, _| {
                let text = format!("{first:?} {:?}", second.result().ok());
                deferred.reply(echo_frame(text.as_bytes()));
            });
        });
        Response::Defer(permit)
    });
    let mode = |name: &str| std::fs::metadata(dir.join(name)).unwrap().permissions().mode() & 0o7777;
    let modes = (mode("ring"), mode("lane"));
    std::fs::remove_dir_all(&dir).unwrap();
    let Some((reply, _)) = reply else {
        return;
    };
    assert_eq!(String::from_utf8_lossy(&reply), "Some(1) Some(1)");
    assert_eq!(
        modes,
        (0o4755, 0o755),
        "the ring's write as root keeps the bit and the lane's clears it"
    );
}
