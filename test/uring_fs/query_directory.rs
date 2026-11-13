use super::*;

// --- query_directory -------------------------------------------------------

/// The special-file guard leaves nothing behind on the descriptor.
///
/// `O_NONBLOCK` stops the *open* parking on a planted FIFO, but on the file it returns it is not inert.
/// `io_file_get_flags` reads it into `REQ_F_SUPPORT_NOWAIT`, so `__io_read` takes the `IOCB_NOWAIT` branch and the
/// transfer runs on the reactor thread instead of an io-wq worker. The kernel strips the flag from files it added it to
/// (`io_uring/openclose.c:161-162`), and so does this.
#[test]
fn an_open_leaves_no_guard_nonblock_on_the_descriptor() {
    use truenas_ros::sync_fs::{OFlag, OpenHow};
    use truenas_ros::uring_fs::FsOpenHow;

    with_fs(test_cfg(), |h, me, dir, _stop| {
        std::fs::write(dir.join("f"), b"data").unwrap();
        let anchor = Anchor::open(dir.as_path()).unwrap();
        let flags = |f: &truenas_ros::uring_fs::File| {
            // SAFETY: a live descriptor; F_GETFL reads no memory through it.
            unsafe { libc::fcntl(f.as_raw_fd(), libc::F_GETFL) }
        };

        // Guarded (the default): the open cannot block, and the descriptor does not carry the flag that made it so.
        let plain = OpenHow::new().flags(OFlag::O_RDONLY);
        let f = h.open(me, &anchor, "f", plain).unwrap();
        assert_eq!(
            flags(&f) & libc::O_NONBLOCK,
            0,
            "the guard's O_NONBLOCK rode out on the descriptor"
        );

        // A caller asking for it keeps it - the flag is theirs, and the kernel makes the same distinction with
        // `nonblock_set`.
        let mine = OpenHow::new().flags(OFlag::O_RDONLY | OFlag::O_NONBLOCK);
        let f = h.open(me, &anchor, "f", mine).unwrap();
        assert_ne!(
            flags(&f) & libc::O_NONBLOCK,
            0,
            "a caller's own O_NONBLOCK must not be stripped"
        );

        let allow = FsOpenHow::from(plain).allow_blocking_special_files(std::time::Duration::from_secs(5));
        let f = h.open(me, &anchor, "f", allow).unwrap();
        assert_eq!(
            flags(&f) & libc::O_NONBLOCK,
            0,
            "Allow adds nothing, so there is nothing to strip"
        );
    });
}

/// A creating open does not park on a planted writer-less FIFO.
///
/// `io_openat_force_async` (`io_uring/openclose.c:42-50`) puts every `O_CREAT`/`O_TRUNC`/`O_TMPFILE` open straight onto
/// an io-wq worker, where the `op.open_flag |= O_NONBLOCK` the inline path applies never runs and `fifo_open` sleeps in
/// `wait_for_partner` (`fs/pipe.c`) until a writer appears - forever, for a FIFO nobody will write to. The io-wq pool
/// is `min(sq_entries, 4 * nr_cpus)`, so a handful of planted names pins every blocking fs op on the ring, and
/// `into_outcome` waits with no deadline, so each pins a caller thread too.
///
/// Runs with a deadline on a worker thread: without the guard this does not fail, it hangs, and a hung test is a worse
/// signal than a red one.
#[test]
fn a_creating_open_does_not_park_on_a_planted_fifo() {
    use std::sync::mpsc;
    use std::time::Duration;
    use truenas_ros::sync_fs::{Mode, OFlag, OpenHow};

    with_fs(test_cfg(), |h, me, dir, _stop| {
        let fifo = dir.join("planted");
        let c = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: a NUL-terminated path we own.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o644) }, 0, "mkfifo");

        let anchor = Anchor::open(dir.as_path()).unwrap();
        let (tx, rx) = mpsc::channel();
        std::thread::scope(|s| {
            s.spawn(|| {
                // Exactly what an object create issues.
                let how = OpenHow::new()
                    .flags(OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_TRUNC)
                    .mode(Mode::from_bits_truncate(0o644));
                let _ = tx.send(h.open(me, &anchor, "planted", how));
            });
            if rx.recv_timeout(Duration::from_secs(5)).is_err() {
                panic!(
                    "a creating open parked on a writer-less FIFO: the \
                     special-file guard is not reaching this path"
                );
            }
        });
    });
}

/// An `Allow` open that blocks is bounded by its own deadline, and the worker it parked comes back.
///
/// `O_WRONLY|O_CREAT` on a planted writer-less FIFO is forced onto an io-wq worker (`io_openat_force_async`) where
/// `fifo_open` sleeps in `wait_for_partner`, forever with `Allow` and no deadline. The deadline is a guard timer in its
/// own op slot whose expiry stages an `ASYNC_CANCEL` for the open (`core::TAG_OPEN_DEADLINE`), **not** a kernel
/// `LINK_TIMEOUT`, which arms only after the blocking issue returns and so cannot bound this shape. The cancel reaches
/// the sleep as a signal, so the errno is `ECANCELED`, or `EINTR` where the parked open returns `-ERESTARTSYS` and
/// `map_res` folds it as the kernel's own rw path does. The guarded open afterwards proves the worker was freed, since
/// it needs one of its own.
#[test]
fn an_allow_open_is_bounded_by_its_deadline() {
    use std::time::{Duration, Instant};
    use truenas_ros::errno::Errno;
    use truenas_ros::sync_fs::{Mode, OFlag, OpenHow};
    use truenas_ros::uring_fs::FsOpenHow;

    with_fs(test_cfg(), |h, me, dir, _stop| {
        let fifo = dir.join("planted");
        let c = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: a NUL-terminated path we own.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o644) }, 0, "mkfifo");
        let anchor = Anchor::open(dir.as_path()).unwrap();

        let how = OpenHow::new()
            .flags(OFlag::O_WRONLY | OFlag::O_CREAT)
            .mode(Mode::from_bits_truncate(0o644));
        let allow = FsOpenHow::from(how).allow_blocking_special_files(Duration::from_millis(300));
        let began = Instant::now();
        let got = h.open(me, &anchor, "planted", allow);
        let took = began.elapsed();
        let errno = match got {
            Err(truenas_ros::Error::Errno(e)) => e,
            other => panic!("a blocked Allow open must fail: {other:?}"),
        };
        assert!(
            matches!(errno, Errno::ECANCELED | Errno::EINTR),
            "the deadline's cancellation, not some other failure: {errno}"
        );
        assert!(
            took >= Duration::from_millis(250),
            "failed in {took:?}: something other than the deadline ended it"
        );
        assert!(
            took < Duration::from_secs(5),
            "took {took:?}: the deadline did not bound the park"
        );

        // The worker came back: a guarded creating open needs one too.
        let plain = OpenHow::new()
            .flags(OFlag::O_WRONLY | OFlag::O_CREAT)
            .mode(Mode::from_bits_truncate(0o644));
        h.open(me, &anchor, "after", plain)
            .expect("the parked worker was never freed");
    });
}

/// An `Allow` open that completes retracts its guard, giving both slots back long before the hour-long deadline.
///
/// On a two-slot table, so the leak is the difference: an `Allow` open charges its own slot and its guard's, and a
/// guard left armed after the open answered holds one of the two for the deadline's full length - the next `Allow`
/// open, which needs both, then never fits. The retraction's slot returns with its own CQE, so the second open is
/// retried briefly rather than demanded instantly.
#[test]
fn an_allow_open_that_completes_disarms_its_deadline() {
    use std::time::{Duration, Instant};
    use truenas_ros::sync_fs::{Mode, OFlag, OpenHow};
    use truenas_ros::uring_fs::FsOpenHow;

    let mut cfg = test_cfg();
    cfg.ops = 2;
    with_fs(cfg, |h, me, dir, _stop| {
        let anchor = Anchor::open(dir.as_path()).unwrap();
        let how = OpenHow::new()
            .flags(OFlag::O_RDWR | OFlag::O_CREAT)
            .mode(Mode::from_bits_truncate(0o600));
        let allow = FsOpenHow::from(how).allow_blocking_special_files(Duration::from_secs(3600));
        let f = h
            .open(me, &anchor, "quick", allow)
            .expect("a regular file answers long before its deadline");
        drop(f);

        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match h.open(me, &anchor, "again", allow) {
                Ok(_) => break,
                Err(truenas_ros::Error::Errno(truenas_ros::errno::Errno::EBUSY)) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(e) => panic!(
                    "the guard's slot never came back after the open \
                     answered: {e}"
                ),
            }
        }
    });
}

/// A zero `Allow` deadline is refused at entry: it would cancel the open it exists to guard, so it is a shape defect
/// like any other.
#[test]
fn a_zero_allow_deadline_is_refused() {
    use std::time::Duration;
    use truenas_ros::sync_fs::{OFlag, OpenHow};
    use truenas_ros::uring_fs::FsOpenHow;

    with_fs(test_cfg(), |h, me, dir, _stop| {
        let anchor = Anchor::open(dir.as_path()).unwrap();
        let allow = FsOpenHow::from(OpenHow::new().flags(OFlag::O_RDONLY)).allow_blocking_special_files(Duration::ZERO);
        assert!(
            matches!(h.open(me, &anchor, "x", allow), Err(truenas_ros::Error::Validation(_))),
            "a zero deadline must be refused before anything submits"
        );
    });
}

/// An entry whose descriptor could not be opened still reports metadata.
///
/// `enrich` takes an entry's `statx` from the descriptor it opened, so that the metadata cannot describe a different
/// inode than the content. Where the open fails there is no descriptor to stat - and equally nothing for a by-name
/// answer to be mispaired against - so the by-name lookup is both safe there and the only answer available. A symlink
/// under `O_NOFOLLOW` is the deterministic way to reach that arm as root.
#[test]
fn an_unopenable_entry_still_reports_statx() {
    use std::collections::BTreeMap;
    use std::ffi::CString;
    use truenas_ros::uring_fs::{DirEntry, EnrichSpec, QueryOptions, query_directory};

    with_fs(test_cfg(), |h, me, dir, _stop| {
        std::fs::write(dir.join("real"), b"xx").unwrap();
        std::os::unix::fs::symlink("real", dir.join("link")).unwrap();

        let anchor = Anchor::open(dir.as_path()).unwrap();
        let opts = QueryOptions {
            // Both, so a descriptor is opened and the fd-keyed statx is the one that normally answers.
            spec: EnrichSpec::STATX | EnrichSpec::XATTR,
            xattr_names: vec![CString::new("user.etag").unwrap()],
            acl_name: CString::new("system.nfs4_acl_xdr").unwrap(),
            xattr_ns: truenas_ros::uring_fs::XattrNamespaces::empty(),
            clump: 8,
            same_device_only: false,
            ..Default::default()
        };
        let mut q = query_directory(&h, me, &anchor, opts).unwrap();
        let mut all: BTreeMap<String, DirEntry> = BTreeMap::new();
        while let Some(batch) = q.next() {
            for e in batch.unwrap() {
                all.insert(e.name.to_string_lossy().into_owned(), e);
            }
        }

        assert_eq!(all.len(), 2, "the file and the symlink");
        let link = all["link"].statx.as_ref().expect(
            "a symlink cannot be opened O_NOFOLLOW, so its metadata has to \
             come from the by-name fallback",
        );
        assert!(link.is_symlink(), "and it describes the symlink itself");
        let real = all["real"].statx.as_ref().expect("opened, so fd-keyed");
        assert_eq!(real.size(), 2);
    });
}

#[test]
fn query_directory_lists_and_enriches() {
    use std::collections::BTreeMap;
    use std::ffi::CString;
    use truenas_ros::uring_fs::{DirEntry, EnrichSpec, QueryOptions, query_directory};

    with_fs(test_cfg(), |h, me, dir, _stop| {
        std::fs::write(dir.join("a.txt"), b"aa").unwrap();
        std::fs::write(dir.join("b.txt"), vec![0u8; 100]).unwrap();
        std::fs::write(dir.join("c.txt"), vec![0u8; 4096]).unwrap();
        std::fs::create_dir(dir.join("sub")).unwrap();

        let anchor = Anchor::open(dir.as_path()).unwrap();
        let etag = CString::new("user.etag").unwrap();
        let xattr_ok = {
            let how = OpenHow::new().flags(OFlag::O_RDWR);
            let f = h.open(me, &anchor, "a.txt", how).unwrap();
            let (res, _) = h.fsetxattr(me, &f, etag.clone(), b"deadbeef".to_vec(), 0);
            h.close(f).unwrap();
            fd_xattr_ok("fsetxattr(user.etag)", &res)
        };

        let opts = QueryOptions {
            spec: EnrichSpec::STATX | EnrichSpec::XATTR,
            xattr_names: vec![etag.clone()],
            acl_name: CString::new("system.nfs4_acl_xdr").unwrap(),
            xattr_ns: truenas_ros::uring_fs::XattrNamespaces::empty(),
            clump: 2, // force more than one batch
            same_device_only: false,
            ..Default::default()
        };
        let mut q = query_directory(&h, me, &anchor, opts).unwrap();
        let mut all: BTreeMap<String, DirEntry> = BTreeMap::new();
        while let Some(batch) = q.next() {
            for e in batch.unwrap() {
                all.insert(e.name.to_string_lossy().into_owned(), e);
            }
        }

        assert_eq!(all.len(), 4, "3 files + 1 subdir");
        assert_eq!(all["a.txt"].statx.as_ref().unwrap().size(), 2);
        assert_eq!(all["b.txt"].statx.as_ref().unwrap().size(), 100);
        assert_eq!(all["c.txt"].statx.as_ref().unwrap().size(), 4096);
        assert!(all["sub"].is_dir);
        assert!(!all["a.txt"].is_dir);
        if xattr_ok {
            assert_eq!(
                all["a.txt"].xattrs[0].1.as_deref(),
                Some(&b"deadbeef"[..]),
                "a.txt carries the etag",
            );
            assert_eq!(all["b.txt"].xattrs[0].1, None, "b.txt has no etag");
        }
    });
}

/// `XATTR_LIST` discovers the attributes present in the requested namespace and returns their values; a namespace the
/// attributes are not in discovers none of them.
#[test]
fn query_directory_discovers_user_xattrs() {
    use std::collections::BTreeMap;
    use truenas_ros::uring_fs::{EnrichSpec, QueryOptions, XattrNamespaces, query_directory};

    with_fs(test_cfg(), |h, me, dir, _stop| {
        std::fs::write(dir.join("a.txt"), b"aa").unwrap();
        let anchor = Anchor::open(dir.as_path()).unwrap();

        // Tag a.txt with two user attrs; the first set probes fd-xattr support.
        let set = |name: &str, val: &[u8]| -> bool {
            let how = OpenHow::new().flags(OFlag::O_RDWR);
            let f = h.open(me, &anchor, "a.txt", how).unwrap();
            let (res, _) = h.fsetxattr(me, &f, xattr_name(name), val.to_vec(), 0);
            h.close(f).unwrap();
            fd_xattr_ok(&format!("fsetxattr({name})"), &res)
        };
        if !set("user.alpha", b"one") {
            return; // this kernel/fs refuses fd xattrs; nothing to discover
        }
        assert!(set("user.beta", b"two"));

        let discover = |ns: XattrNamespaces| {
            let opts = QueryOptions {
                spec: EnrichSpec::XATTR_LIST,
                xattr_ns: ns,
                ..Default::default()
            };
            let mut q = query_directory(&h, me, &anchor, opts).unwrap();
            let mut got: BTreeMap<String, Option<Vec<u8>>> = BTreeMap::new();
            while let Some(batch) = q.next() {
                for e in batch.unwrap() {
                    if e.name.as_bytes() == b"a.txt" {
                        for (n, v) in e.xattrs {
                            got.insert(n.to_string_lossy().into_owned(), v);
                        }
                    }
                }
            }
            got
        };

        let user = discover(XattrNamespaces::USER);
        assert_eq!(user.get("user.alpha").and_then(|v| v.as_deref()), Some(&b"one"[..]),);
        assert_eq!(user.get("user.beta").and_then(|v| v.as_deref()), Some(&b"two"[..]),);

        let trusted = discover(XattrNamespaces::TRUSTED);
        assert!(
            !trusted.contains_key("user.alpha"),
            "user.* must not surface under a TRUSTED-only query"
        );
    });
}

/// A discovered attribute whose name is not UTF-8 is enriched under `who`: its bytes reach `fgetxattr` verbatim, so the
/// value comes back rather than the attribute being dropped over a lossy name.
#[test]
fn query_directory_discovers_non_utf8_name() {
    use std::ffi::CString;
    use truenas_ros::uring_fs::{EnrichSpec, QueryOptions, XattrNamespaces, query_directory};

    with_fs(test_cfg(), |h, me, dir, _stop| {
        std::fs::write(dir.join("a.txt"), b"aa").unwrap();
        let anchor = Anchor::open(dir.as_path()).unwrap();
        let name = CString::new(&b"user.\xff\xfe"[..]).unwrap();

        let set_ok = {
            let how = OpenHow::new().flags(OFlag::O_RDWR);
            let f = h.open(me, &anchor, "a.txt", how).unwrap();
            let (res, _) = h.fsetxattr(me, &f, name.clone(), b"present".to_vec(), 0);
            h.close(f).unwrap();
            fd_xattr_ok("fsetxattr(user.<non-utf8>)", &res)
        };
        if !set_ok {
            return; // fd xattrs unsupported, or the fs rejects the name
        }

        let opts = QueryOptions {
            spec: EnrichSpec::XATTR_LIST,
            xattr_ns: XattrNamespaces::USER,
            ..Default::default()
        };
        let mut q = query_directory(&h, me, &anchor, opts).unwrap();
        let mut found = None;
        while let Some(batch) = q.next() {
            for e in batch.unwrap() {
                if e.name.as_bytes() == b"a.txt" {
                    for (n, v) in e.xattrs {
                        if n.as_bytes() == b"user.\xff\xfe" {
                            found = v;
                        }
                    }
                }
            }
        }
        assert_eq!(
            found.as_deref(),
            Some(&b"present"[..]),
            "non-UTF-8 name enriched with its value, not dropped"
        );
    });
}

/// A discovered value larger than the initial buffer is refetched at its true size, not silently truncated or dropped.
#[test]
fn query_directory_discovers_large_value() {
    use truenas_ros::uring_fs::{EnrichSpec, QueryOptions, XattrNamespaces, query_directory};

    with_fs(test_cfg(), |h, me, dir, _stop| {
        std::fs::write(dir.join("big.bin"), b"x").unwrap();
        let anchor = Anchor::open(dir.as_path()).unwrap();
        let big = vec![0xabu8; 5000]; // larger than the 4096-byte buffer

        let set_ok = {
            let how = OpenHow::new().flags(OFlag::O_RDWR);
            let f = h.open(me, &anchor, "big.bin", how).unwrap();
            let (res, _) = h.fsetxattr(me, &f, xattr_name("user.blob"), big.clone(), 0);
            h.close(f).unwrap();
            fd_xattr_ok("fsetxattr(user.blob)", &res)
        };
        if !set_ok {
            return; // fd xattrs unsupported, or the fs rejects the value size
        }

        let opts = QueryOptions {
            spec: EnrichSpec::XATTR_LIST,
            xattr_ns: XattrNamespaces::USER,
            ..Default::default()
        };
        let mut q = query_directory(&h, me, &anchor, opts).unwrap();
        let mut found = None;
        while let Some(batch) = q.next() {
            for e in batch.unwrap() {
                if e.name.as_bytes() == b"big.bin" {
                    for (n, v) in e.xattrs {
                        if n.to_bytes() == b"user.blob" {
                            found = v;
                        }
                    }
                }
            }
        }
        assert_eq!(found.as_deref(), Some(big.as_slice()), "the whole value is refetched");
    });
}

/// An explicitly requested value larger than the initial buffer is returned at its true size, not reported absent: the
/// ERANGE the fixed buffer yields must not read as "no such attribute".
#[test]
fn query_directory_explicit_large_value() {
    use truenas_ros::uring_fs::{EnrichSpec, QueryOptions, XattrNamespaces, query_directory};

    with_fs(test_cfg(), |h, me, dir, _stop| {
        std::fs::write(dir.join("big.bin"), b"x").unwrap();
        let anchor = Anchor::open(dir.as_path()).unwrap();
        let name = xattr_name("user.blob");
        let big = vec![0xcdu8; 8192]; // twice the 4096-byte explicit buffer

        let set_ok = {
            let how = OpenHow::new().flags(OFlag::O_RDWR);
            let f = h.open(me, &anchor, "big.bin", how).unwrap();
            let (res, _) = h.fsetxattr(me, &f, name.clone(), big.clone(), 0);
            h.close(f).unwrap();
            fd_xattr_ok("fsetxattr(user.blob)", &res)
        };
        if !set_ok {
            return; // fd xattrs unsupported, or the fs rejects the value size
        }

        let opts = QueryOptions {
            spec: EnrichSpec::XATTR,
            xattr_names: vec![name.clone()],
            xattr_ns: XattrNamespaces::empty(),
            ..Default::default()
        };
        let mut q = query_directory(&h, me, &anchor, opts).unwrap();
        let mut found = None;
        while let Some(batch) = q.next() {
            for e in batch.unwrap() {
                if e.name.as_bytes() == b"big.bin" {
                    // The explicit name keeps its slot, in request order.
                    assert_eq!(e.xattrs[0].0, name);
                    found = e.xattrs[0].1.clone();
                }
            }
        }
        assert_eq!(
            found.as_deref(),
            Some(big.as_slice()),
            "the whole explicit value is returned, not reported absent"
        );
    });
}

/// A listing that lost nothing must not report itself short - and one that did must.
///
/// The listing opens each entry `O_RDONLY|O_NOFOLLOW|O_NONBLOCK`, which a symbolic link answers `ELOOP` and a socket
/// `ENXIO`. What the object can hold decides the verdict, not the errno. A symlink can hold neither an access ACL
/// (`vfs_get_acl` refuses one outright) nor a `user.*` attribute (`xattr(7)`), so "absent" is true of it, and flagging
/// it would make `xattrs_incomplete` permanent for an ordinary directory. A socket holds both, as a regular file does,
/// so its `ENXIO` leaves values the caller asked for unread, and reporting them absent with the flag clear is the
/// trivial-versus-unread confusion the ACL arm in `next_batch` exists to refuse.
///
/// The regular file is the live control, opened, read and reported complete, so a blanket "everything is flagged" would
/// not pass either.
#[test]
fn query_directory_does_not_flag_an_entry_it_cannot_open() {
    use truenas_ros::uring_fs::{EnrichSpec, QueryOptions, XattrNamespaces, query_directory};

    with_fs(test_cfg(), |h, me, dir, _stop| {
        std::fs::write(dir.join("plain.bin"), b"x").unwrap();
        std::os::unix::fs::symlink("plain.bin", dir.join("link")).unwrap();
        let sock = std::os::unix::net::UnixListener::bind(dir.join("sock")).expect("bind a unix socket in the listing");
        std::fs::create_dir(dir.join("sub")).unwrap();
        let anchor = Anchor::open(dir.as_path()).unwrap();
        let name = xattr_name("user.probe");

        let set_ok = {
            let how = OpenHow::new().flags(OFlag::O_RDWR);
            let f = h.open(me, &anchor, "plain.bin", how).unwrap();
            let (res, _) = h.fsetxattr(me, &f, name.clone(), b"v".to_vec(), 0);
            h.close(f).unwrap();
            fd_xattr_ok("fsetxattr(user.probe)", &res)
        };

        let opts = QueryOptions {
            spec: EnrichSpec::XATTR,
            xattr_names: vec![name.clone()],
            xattr_ns: XattrNamespaces::empty(),
            ..Default::default()
        };
        let mut q = query_directory(&h, me, &anchor, opts).unwrap();
        let mut seen: Vec<(String, bool, Option<Vec<u8>>)> = Vec::new();
        while let Some(batch) = q.next() {
            for e in batch.unwrap() {
                seen.push((
                    e.name.to_string_lossy().into_owned(),
                    e.xattrs_incomplete,
                    e.xattrs.first().and_then(|(_, v)| v.clone()),
                ));
            }
        }
        seen.sort();
        let names: Vec<&str> = seen.iter().map(|(n, ..)| n.as_str()).collect();
        assert_eq!(
            names,
            ["link", "plain.bin", "sock", "sub"],
            "the listing must yield every entry it was given"
        );
        for (n, incomplete, _) in &seen {
            // Nothing here lost a value. `user.*` lives only on regular files and directories (`xattr_permission`,
            // `fs/xattr.c`), so for the symlink and the socket "absent" is the true answer rather than an unread one.
            assert!(
                !incomplete,
                "{n}: flagged incomplete for a `user.*` name it cannot hold"
            );
        }
        if set_ok {
            let plain = seen.iter().find(|(n, ..)| n == "plain.bin").unwrap();
            assert_eq!(
                plain.2.as_deref(),
                Some(b"v".as_slice()),
                "the control entry's value was not read"
            );
        }
        drop(sock);
    });
}

/// The narrowing is two-sided. An entry that could not be opened is flagged when the request named something its type
/// *does* hold.
///
/// The companion above pins that a socket asked only for `user.*` is not flagged. Here the same socket is asked for its
/// access ACL, which it holds and which this listing did not read. Without both halves, suppressing the flag for every
/// socket would pass the first test and lose a real value silently.
///
/// The ACL is put on the socket through the raw syscall because the listing itself cannot open one, and `fsetxattr`
/// needs a descriptor.
#[test]
fn query_directory_flags_a_socket_whose_acl_it_could_not_read() {
    use truenas_ros::uring_fs::{EnrichSpec, QueryOptions, XattrNamespaces, query_directory};

    with_fs(test_cfg(), |h, me, dir, _stop| {
        std::fs::write(dir.join("plain.bin"), b"x").unwrap();
        let sock = std::os::unix::net::UnixListener::bind(dir.join("sock")).expect("bind a unix socket in the listing");

        // A named user makes it a real ACL rather than one equivalent to the mode, so the value genuinely exists on the
        // socket. Written out rather than built through `sync_fs::acl`, which is a different feature - this test
        // compiles under `uring-fs` alone.
        // version 2, then USER_OBJ / USER:1000 / GROUP_OBJ / MASK / OTHER.
        let mut blob = 2u32.to_le_bytes().to_vec();
        for (tag, perm, id) in [
            (0x01u16, 0o7u16, !0u32),
            (0x02, 0o4, 1000),
            (0x04, 0o7, !0),
            (0x10, 0o7, !0),
            (0x20, 0o5, !0),
        ] {
            blob.extend_from_slice(&tag.to_le_bytes());
            blob.extend_from_slice(&perm.to_le_bytes());
            blob.extend_from_slice(&id.to_le_bytes());
        }
        use std::os::unix::ffi::OsStrExt as _;
        let sock_path = dir.join("sock");
        let cp = std::ffi::CString::new(sock_path.as_os_str().as_bytes()).unwrap();
        // SAFETY: a valid NUL-terminated path and a sized buffer.
        let rc = unsafe {
            libc::setxattr(
                cp.as_ptr(),
                c"system.posix_acl_access".as_ptr(),
                blob.as_ptr().cast(),
                blob.len(),
                0,
            )
        };
        if rc != 0 {
            let e = std::io::Error::last_os_error();
            assert!(
                std::env::var_os("TRUENAS_ROS_REQUIRE_POSIX_ACL").is_none(),
                "TRUENAS_ROS_REQUIRE_POSIX_ACL is set but a socket here \
                 will not hold a POSIX ACL: {e}"
            );
            return;
        }

        let opts = QueryOptions {
            spec: EnrichSpec::ACL,
            acl_name: c"system.posix_acl_access".to_owned(),
            xattr_ns: XattrNamespaces::empty(),
            ..Default::default()
        };
        let anchor = Anchor::open(dir.as_path()).unwrap();
        let mut q = query_directory(&h, me, &anchor, opts).unwrap();
        let mut seen: Vec<(String, bool, bool)> = Vec::new();
        while let Some(batch) = q.next() {
            for e in batch.unwrap() {
                seen.push((
                    e.name.to_string_lossy().into_owned(),
                    e.xattrs_incomplete,
                    e.acl.is_some(),
                ));
            }
        }
        seen.sort();
        let sock_row = seen.iter().find(|(n, ..)| n == "sock").expect("sock");
        assert!(
            sock_row.1 && !sock_row.2,
            "a socket holding an ACL this listing could not open must be \
             reported as unread, not as having none: {sock_row:?}"
        );
        let plain = seen.iter().find(|(n, ..)| n == "plain.bin").expect("f");
        assert!(!plain.1, "the control opened fine and lost nothing: {plain:?}");
        drop(sock);
    });
}

/// An ACL the filesystem does not implement is **absent**, not a listing that could not be completed.
///
/// [`QueryOptions::acl_name`] is the caller's to choose, and asking for `system.nfs4_acl_xdr` on tmpfs or an
/// `acltype=posixacl` dataset gets `EOPNOTSUPP` for every entry. Classed as a failed read, it would raise
/// `xattrs_incomplete` on every entry of a complete listing, and a consumer reading the flag would re-query or refuse
/// for ever.
///
/// The first half is the live control. A `None` ACL proves nothing alone, since the slot reads `None` when
/// `EnrichSpec::ACL` was never requested, when the entry could not be opened and when the read was refused, so the same
/// machinery is first shown fetching an `acl_name` that *is* readable.
#[test]
fn query_directory_reports_an_unimplemented_acl_as_absent() {
    use truenas_ros::uring_fs::{EnrichSpec, QueryOptions, XattrNamespaces, query_directory};

    with_fs(test_cfg(), |h, me, dir, _stop| {
        std::fs::write(dir.join("obj.bin"), b"x").unwrap();
        let anchor = Anchor::open(dir.as_path()).unwrap();
        let readable = xattr_name("user.pretend_acl");
        let value = b"an acl blob".to_vec();

        let set_ok = {
            let how = OpenHow::new().flags(OFlag::O_RDWR);
            let f = h.open(me, &anchor, "obj.bin", how).unwrap();
            let (res, _) = h.fsetxattr(me, &f, readable.clone(), value.clone(), 0);
            h.close(f).unwrap();
            fd_xattr_ok("fsetxattr(user.pretend_acl)", &res)
        };

        let list = |acl_name: CString| {
            let opts = QueryOptions {
                spec: EnrichSpec::ACL,
                acl_name,
                xattr_ns: XattrNamespaces::empty(),
                ..Default::default()
            };
            let mut q = query_directory(&h, me, &anchor, opts).unwrap();
            let mut seen = None;
            while let Some(batch) = q.next() {
                for e in batch.unwrap() {
                    if e.name.as_bytes() == b"obj.bin" {
                        seen = Some((e.acl.clone(), e.xattrs_incomplete));
                    }
                }
            }
            seen.expect("the listing never yielded the file it was given")
        };

        // The control: the ACL slot really does fetch.
        if set_ok {
            let (acl, incomplete) = list(readable);
            assert_eq!(
                acl.as_deref(),
                Some(value.as_slice()),
                "the ACL slot did not fetch a readable attribute"
            );
            assert!(!incomplete, "a value that was read is not incomplete");
        }

        // The case: a name this filesystem has no handler for.
        let (acl, incomplete) = list(xattr_name("system.nfs4_acl_xdr"));
        assert!(acl.is_none(), "there is no NFSv4 ACL here to report");
        assert!(
            !incomplete,
            "an attribute the filesystem does not implement is absent, \
             not a listing that could not be completed"
        );
    });
}

/// Discovery runs each value read under the caller: an unprivileged identity sees the world-readable `user.*` attribute
/// but never the `trusted.*` one, while a privileged identity does. The candidate-listing `flistxattr` runs at the
/// reactor's privilege, so the per-value `who` read is what gates it.
#[test]
fn query_directory_discovery_drops_unreadable_trusted() {
    use std::collections::BTreeMap;
    use truenas_ros::uring_fs::{EnrichSpec, QueryOptions, XattrNamespaces, query_directory};

    if !root_or_skip("query_directory_discovery_drops_unreadable_trusted") {
        return; // broker impersonation and trusted.* both need privilege
    }
    const NOBODY_UID: u32 = 65_534;
    const NOBODY_GID: u32 = 65_534;

    with_broker(|h, creds, me, dir| {
        std::fs::write(dir.join("f.txt"), b"hi").unwrap();
        std::fs::set_permissions(dir.join("f.txt"), std::fs::Permissions::from_mode(0o644)).unwrap();
        let anchor = Anchor::open(dir).unwrap();

        let set = |who: Personality, name: &str, val: &[u8]| {
            let how = OpenHow::new().flags(OFlag::O_RDWR);
            let f = h.open(who, &anchor, "f.txt", how).unwrap();
            let (res, _) = h.fsetxattr(who, &f, xattr_name(name), val.to_vec(), 0);
            h.close(f).unwrap();
            res
        };
        if !fd_xattr_ok("fsetxattr(user.pub)", &set(me, "user.pub", b"public")) {
            return; // fd xattrs unsupported
        }
        set(me, "trusted.secret", b"classified").unwrap();

        let peer = creds.register(&AsUser::new(NOBODY_UID, NOBODY_GID)).unwrap();

        let discover = |who: Personality| {
            let opts = QueryOptions {
                spec: EnrichSpec::XATTR_LIST,
                xattr_ns: XattrNamespaces::USER | XattrNamespaces::TRUSTED,
                ..Default::default()
            };
            let mut q = query_directory(h, who, &anchor, opts).unwrap();
            let mut got: BTreeMap<String, Option<Vec<u8>>> = BTreeMap::new();
            while let Some(batch) = q.next() {
                for e in batch.unwrap() {
                    if e.name.as_bytes() == b"f.txt" {
                        for (n, v) in e.xattrs {
                            got.insert(n.to_string_lossy().into_owned(), v);
                        }
                    }
                }
            }
            got
        };

        let peer_view = discover(peer);
        assert!(
            peer_view.contains_key("user.pub"),
            "peer should read the world-readable user attr"
        );
        assert!(
            !peer_view.contains_key("trusted.secret"),
            "trusted.* must not leak to an unprivileged identity"
        );

        let root_view = discover(me);
        assert_eq!(
            root_view.get("trusted.secret").and_then(|v| v.as_deref()),
            Some(&b"classified"[..]),
            "a privileged identity does read trusted.*"
        );
    });
}

/// Discovery works through the pooled lister as well as the direct one.
#[test]
fn query_pool_discovers_xattrs() {
    use truenas_ros::uring_fs::{EnrichSpec, QueryOptions, QueryPool, XattrNamespaces};

    with_fs(test_cfg(), |h, me, dir, _stop| {
        std::fs::write(dir.join("p.txt"), b"hi").unwrap();
        let anchor = Anchor::open(dir.as_path()).unwrap();
        let set_ok = {
            let how = OpenHow::new().flags(OFlag::O_RDWR);
            let f = h.open(me, &anchor, "p.txt", how).unwrap();
            let (res, _) = h.fsetxattr(me, &f, xattr_name("user.tag"), b"v".to_vec(), 0);
            h.close(f).unwrap();
            fd_xattr_ok("fsetxattr(user.tag)", &res)
        };
        if !set_ok {
            return;
        }

        let pool = QueryPool::new(h);
        let opts = QueryOptions {
            spec: EnrichSpec::XATTR_LIST,
            xattr_ns: XattrNamespaces::USER,
            ..Default::default()
        };
        let handle = pool.query(me, anchor, opts);
        let mut found = false;
        while let Some(batch) = handle.next() {
            for e in batch.unwrap() {
                if e.name.as_bytes() == b"p.txt" {
                    found = e
                        .xattrs
                        .iter()
                        .any(|(n, v)| n.to_bytes() == b"user.tag" && v.as_deref() == Some(&b"v"[..]));
                }
            }
        }
        assert!(found, "pool discovery surfaces the user attr");
    });
}

/// Enumeration is gated by the caller's list permission: opening the directory readable under `who` is the DAC check,
/// so a non-root peer that cannot list a `0700` directory it does not own gets `EACCES` (never the reactor's root).
#[test]
fn query_directory_enumeration_obeys_dac() {
    use std::ffi::CString;
    use truenas_ros::errno::Errno;
    use truenas_ros::uring_fs::{EnrichSpec, QueryOptions, query_directory};

    if !root_or_skip("query_directory_enumeration_obeys_dac") {
        return; // the broker cannot become another uid without CAP_SETUID
    }
    const NOBODY_UID: u32 = 65_534;
    const NOBODY_GID: u32 = 65_534;

    with_broker(|h, creds, _me, dir| {
        let secret = dir.join("secret");
        std::fs::create_dir(&secret).unwrap();
        std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(secret.join("hidden.txt"), b"x").unwrap();

        let peer = creds.register(&AsUser::new(NOBODY_UID, NOBODY_GID)).unwrap();
        let anchor = Anchor::open(&secret).unwrap();
        let opts = QueryOptions {
            spec: EnrichSpec::STATX,
            xattr_names: vec![],
            acl_name: CString::new("system.nfs4_acl_xdr").unwrap(),
            xattr_ns: truenas_ros::uring_fs::XattrNamespaces::empty(),
            clump: 8,
            same_device_only: false,
            ..Default::default()
        };
        let err = query_directory(h, peer, &anchor, opts).unwrap_err();
        assert!(
            matches!(err, Error::Errno(Errno::EACCES)),
            "peer cannot list a 0700 dir it does not own: {err:?}"
        );
    });
}

/// Dropping a `QueryDir` mid-walk closes its directory fd (RAII), not at some later teardown - verified against
/// `/proc/self/fd`.
#[test]
fn query_directory_drop_closes_dir_fd() {
    use std::ffi::CString;
    use truenas_ros::uring_fs::{EnrichSpec, QueryOptions, query_directory};

    with_fs(test_cfg(), |h, me, dir, _stop| {
        for i in 0..6 {
            std::fs::write(dir.join(format!("f{i}")), b"x").unwrap();
        }
        let anchor = Anchor::open(dir.as_path()).unwrap();
        let opts = QueryOptions {
            spec: EnrichSpec::STATX,
            xattr_names: vec![],
            acl_name: CString::new("system.nfs4_acl_xdr").unwrap(),
            xattr_ns: truenas_ros::uring_fs::XattrNamespaces::empty(),
            clump: 2,
            same_device_only: false,
            ..Default::default()
        };
        let mut q = query_directory(&h, me, &anchor, opts).unwrap();
        let fd = q.dir_fd();
        let link = format!("/proc/self/fd/{fd}");
        let first = q.next().expect("a batch").unwrap();
        assert!(!first.is_empty());
        let target = std::fs::read_link(&link).expect("dir fd open during walk");
        drop(q);
        // `Drop` closes the `DIR*` (and its dup fd) synchronously via `closedir`. The freed fd *number* can be reused
        // by the reactor thread running concurrently, so assert the fd no longer names our directory - closed (`Err`)
        // or reused for something else (a different target) - rather than that the number is merely absent, which fd
        // reuse would race.
        match std::fs::read_link(&link) {
            Err(_) => {}
            Ok(reused) => assert_ne!(
                reused, target,
                "dir fd still open and still the directory after drop \
                 (deferred to teardown?)"
            ),
        }
    });
}
