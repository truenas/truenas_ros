use super::*;

// ---------------------------------------------------------------------------

/// A close-on-exec pipe, returned `(read end, write end)`. Both are plain descriptors the caller closes;
/// `splice_from_pipe` never adopts either.
fn pipe_pair() -> (libc::c_int, libc::c_int) {
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: `pipe2` writes exactly two descriptors into `fds`.
    let rc = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
    assert_eq!(rc, 0, "pipe2: {}", std::io::Error::last_os_error());
    (fds[0], fds[1])
}

/// `splice_from_pipe` moves pipe bytes into a file with no userspace buffer, honouring the destination offset - and
/// reports a short move as a count rather than an error, which is what the resubmit contract rests on.
///
/// Bites three ways: drop the destination offset and the seeded bytes are overwritten at 0; leave `splice_off_in` at 0
/// instead of -1 and the kernel refuses a pipe source with `ESPIPE`; put the pipe in `sqe.fd` instead of `splice_fd_in`
/// and it moves nothing.
#[test]
fn splice_from_a_pipe_lands_at_the_offset_and_reports_short_moves() {
    with_fs(test_cfg(), |h, me, dir, _stop| {
        let anchor = Anchor::open(dir.as_path()).expect("anchor");
        let f = h.open(me, &anchor, "spliced.bin", creat_rw()).expect("open");

        // Seed 16 bytes so a splice at offset 4 has to land *inside* existing content: an ignored offset shows up as
        // clobbered leading bytes.
        let (n, _) = h.pwritev2(me, &f, vec![vec![b'.'; 16]], 0, RwFlags::empty());
        assert_eq!(n.expect("seed"), 16);

        let (rd, wr) = pipe_pair();
        let body = b"SPLICED";
        // SAFETY: writing our own buffer to our own pipe's write end.
        let w = unsafe { libc::write(wr, body.as_ptr().cast(), body.len()) };
        assert_eq!(w, body.len() as isize, "seed the pipe");
        // Close the write end so the pipe is at EOF once drained, making both the short move and the follow-up zero
        // deterministic.
        // SAFETY: our own descriptor, not used again.
        unsafe { libc::close(wr) };

        // Ask for far more than the pipe holds.
        let moved = h.splice_from_pipe(me, &f, rd, 4, 4096).expect("splice");
        assert_eq!(
            moved,
            body.len() as u64,
            "a pipe delivers what it has; short is progress, not failure"
        );

        // Drained: the next move is a clean zero, not an error.
        let eof = h.splice_from_pipe(me, &f, rd, 11, 4096).expect("splice eof");
        assert_eq!(eof, 0, "drained pipe with the write end closed");
        // SAFETY: our own descriptor, not used again.
        unsafe { libc::close(rd) };

        h.fsync(me, &f).expect("fsync");
        h.close(f).expect("close");

        let disk = std::fs::read(dir.join("spliced.bin")).expect("std read");
        assert_eq!(disk.len(), 16, "a splice inside the file cannot extend it");
        assert_eq!(&disk[..4], b"....", "bytes before the offset are intact");
        assert_eq!(&disk[4..11], body, "the body landed at the offset");
        assert_eq!(&disk[11..], b".....", "bytes after are intact");
    });
}

#[test]
fn round_trip_write_fsync_read() {
    with_fs(test_cfg(), |h, me, dir, _stop| {
        let anchor = Anchor::open(dir.as_path()).expect("anchor");

        let f = h.open(me, &anchor, "out.bin", creat_rw()).expect("open");
        let (n, bufs) = h.pwritev2(me, &f, vec![b"hello ".to_vec(), b"world".to_vec()], 0, RwFlags::empty());
        assert_eq!(n.expect("writev"), 11);
        assert_eq!(bufs.len(), 2, "buffers round-trip");
        h.fsync(me, &f).expect("fsync");
        h.fdatasync(me, &f).expect("fdatasync");
        h.close(f).expect("close");

        // Oracle: the bytes are on disk, owned by us (O_CREAT under a self personality creates as the calling
        // identity).
        let disk = std::fs::read(dir.join("out.bin")).expect("std read");
        assert_eq!(disk, b"hello world");
        let meta = std::fs::metadata(dir.join("out.bin")).unwrap();
        // SAFETY: geteuid is always safe.
        assert_eq!(meta.uid(), unsafe { libc::geteuid() });

        let f = h.open(me, &anchor, "out.bin", rdonly()).expect("reopen");
        let (n, bufs) = h.preadv2(
            me,
            &f,
            vec![vec![0u8; 4], vec![0u8; 4], vec![0u8; 8]],
            0,
            RwFlags::empty(),
        );
        assert_eq!(n.expect("readv"), 11, "short only at EOF");
        assert_eq!(&bufs[0], b"hell");
        assert_eq!(&bufs[1], b"o wo");
        assert_eq!(&bufs[2][..3], b"rld");

        let (n, buf) = pread1(&h, me, &f, vec![0u8; 5], 6);
        assert_eq!(n.expect("pread"), 5);
        assert_eq!(&buf, b"world");
        h.close(f).expect("close 2");
    });
}

/// A read into spare room lands straight after what the buffer holds, in the same storage, and comes back short at the
/// end of the file. A count past the room, the offset io_uring reads as the file's position, and a read the kernel
/// refuses each hand the buffer back as it came.
#[test]
fn a_read_into_spare_room_keeps_what_the_buffer_holds() {
    with_fs(test_cfg(), |h, me, dir, _stop| {
        std::fs::write(dir.join("f"), b"hello world").unwrap();
        let anchor = Anchor::open(dir.as_path()).expect("anchor");
        let f = h.open(me, &anchor, "f", rdonly()).expect("open");
        let mut buf = Vec::with_capacity(32);
        buf.extend_from_slice(b"head");
        let storage = buf.as_ptr();
        let flags = RwFlags::empty();
        let (n, buf) = h.pread_spare(me, &f, buf, 11, 0, flags);
        assert_eq!(n.expect("read"), 11);
        assert_eq!(buf, b"headhello world");
        assert_eq!(buf.as_ptr(), storage, "the same storage, never grown");

        let (n, buf) = h.pread_spare(me, &f, buf, 10, 6, flags);
        assert_eq!(n.expect("a short read at the end"), 5);
        assert_eq!(buf, b"headhello worldworld");

        // Two bytes are left at 9, fewer than the room, so only the screen stops this.
        let room = buf.capacity() - buf.len();
        let (n, buf) = h.pread_spare(me, &f, buf, room + 1, 9, flags);
        assert!(matches!(n, Err(Error::Errno(Errno::EINVAL))), "{n:?}");
        assert_eq!(buf, b"headhello worldworld");

        let (n, buf) = h.pread_spare(me, &f, buf, 4, u64::MAX, flags);
        assert!(matches!(n, Err(Error::Errno(Errno::EINVAL))), "{n:?}");
        assert_eq!(buf, b"headhello worldworld");
        h.close(f).expect("close");

        let how = OpenHow::new().flags(OFlag::O_WRONLY);
        let w = h.open(me, &anchor, "f", how).expect("open for writing");
        let (n, buf) = h.pread_spare(me, &w, buf, 4, 0, flags);
        assert!(matches!(n, Err(Error::Errno(Errno::EBADF))), "{n:?}");
        assert_eq!(buf, b"headhello worldworld");
        assert_eq!(buf.as_ptr(), storage);
        h.close(w).expect("close");
    });
}

/// With both slots of a two-slot table held by parked reads, a read into spare room is refused with `EBUSY` and hands
/// its buffer back as it came.
#[test]
fn a_read_into_spare_room_on_a_full_table_hands_its_buffer_back() {
    let mut cfg = test_cfg();
    cfg.ops = 2;
    with_fs(cfg, |h, me, dir, _stop| {
        mkfifo(&dir, "fifo");
        std::fs::write(dir.join("f"), b"bytes").unwrap();
        let anchor = Anchor::open(dir.as_path()).unwrap();
        let f = h.open(me, &anchor, "f", rdonly()).expect("open f");
        // O_RDWR on a FIFO opens at once with a writer attached, so a read with no data parks and holds its slot.
        let how = OpenHow::new().flags(OFlag::O_RDWR);
        let fifo = h.open(me, &anchor, "fifo", how).expect("open fifo");
        let park = || {
            h.start_preadv2(me, &fifo, vec![vec![0u8; 4]], 0, RwFlags::empty())
                .expect("start readv")
        };
        let (first, second) = (park(), park());
        let mut buf = Vec::with_capacity(8);
        buf.push(b'h');
        let (n, buf) = h.pread_spare(me, &f, buf, 5, 0, RwFlags::empty());
        assert!(matches!(n, Err(Error::Errno(Errno::EBUSY))), "{n:?}");
        assert_eq!(buf, b"h");
        assert_eq!(buf.capacity(), 8);

        let path = dir.join("fifo");
        let writer = thread::spawn(move || {
            use std::io::Write;
            let mut w = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
            w.write_all(b"one two ").unwrap();
        });
        for pending in [first, second] {
            let (res, _) = pending.wait();
            assert_eq!(res.expect("a parked read completes"), 4);
        }
        writer.join().unwrap();
    });
}

/// `fstatfs` answers for the mount, from a file and from an anchor alike, and the two agree because they name the same
/// filesystem. The anchor form is the one that matters: an `Anchor` is `O_PATH`, which `fsync` refuses, so this pins
/// that `fstatfs` accepts it and a caller need not open anything to ask a whole tree's capacity.
#[test]
fn fstatfs_answers_from_a_file_and_from_an_anchor() {
    with_fs(test_cfg(), |h, me, dir, _stop| {
        let anchor = Anchor::open(dir.as_path()).expect("anchor");
        let f = h.open(me, &anchor, "sf.bin", creat_rw()).expect("open");

        let by_anchor = h.fstatfs_anchor(&anchor).expect("statfs by anchor");
        let by_file = h.fstatfs(&f).expect("statfs by file");

        assert!(by_anchor.block_size() > 0, "a unit is always reported");
        assert_eq!(
            by_anchor.block_size(),
            by_file.block_size(),
            "same filesystem, same unit"
        );
        assert_eq!(
            by_anchor.total_blocks(),
            by_file.total_blocks(),
            "same filesystem, same size"
        );
        assert!(by_anchor.total_blocks() > 0);
        assert!(by_anchor.available_blocks() <= by_anchor.free_blocks());
        assert_eq!(
            by_anchor.total_bytes(),
            by_anchor.total_blocks() * by_anchor.block_size()
        );
        h.close(f).expect("close");
    });
}

/// The immutability claim, exercised rather than asserted: set `IMMUTABLE` through the reactor and the file becomes
/// undeletable *and* its xattrs unwritable - enforcement the VFS applies, so no protocol routes around it.
///
/// Needs a real ZFS dataset - a tmpfs tempdir answers the ioctl `ENOTTY` - so it resolves one and skips loudly under
/// `TRUENAS_ROS_REQUIRE_ZFS`, which the QEMU job arms. Unprivileged, the `EPERM` on setting the flag is itself the
/// property under test and is asserted rather than skipped.
#[test]
fn an_immutable_file_cannot_be_unlinked_or_relabelled() {
    let Some(ds) = zfs_dir_or_skip() else {
        return;
    };
    with_fs(test_cfg(), |h, me, _dir, _stop| {
        let anchor = Anchor::open(ds.as_path()).expect("anchor");
        let f = h.open(me, &anchor, "locked.bin", creat_rw()).expect("open");
        let (n, _) = pwrite1(&h, me, &f, b"retained".to_vec(), 0);
        assert_eq!(n.expect("write"), 8);

        let before = h
            .fget_zfs_attrs(&f)
            .expect("a ZFS dataset must answer the attribute ioctl");
        assert_eq!(
            before & ZfsAttr::IMMUTABLE,
            ZfsAttr::empty(),
            "a fresh file is not locked"
        );

        // Metadata has to land before the lock: an immutable inode refuses xattr writes (`may_write_xattr`,
        // fs/xattr.c).
        let name = xattr_name("user.retain-until");
        let (res, _) = h.fsetxattr(me, &f, name.clone(), b"2099-01-01".to_vec(), 0);
        res.expect("xattr before locking");

        match h.fset_zfs_attrs(&f, before | ZfsAttr::IMMUTABLE) {
            Ok(()) => {}
            // CAP_LINUX_IMMUTABLE is required, and its absence is the very property under test - so an unprivileged
            // refusal is a pass for the half this can reach, not a skip of the whole test.
            Err(Error::Errno(Errno::EPERM)) => {
                assert!(!is_root(), "root was refused CAP_LINUX_IMMUTABLE");
                h.close(f).expect("close");
                return;
            }
            Err(e) => panic!("fset_zfs_attrs: {e}"),
        }

        // statx sees it without an ioctl - the free read path.
        let st = h
            .fstatx(me, &f, AtFlags::empty(), StatxMask::BASIC_STATS)
            .expect("fstatx");
        assert!(
            st.attributes().contains(StatxAttr::IMMUTABLE),
            "statx must report the lock"
        );

        let unlinked = h.unlinkat(me, &anchor, leaf("locked.bin"));
        assert!(
            matches!(unlinked, Err(Error::Errno(Errno::EPERM))),
            "an immutable file must not unlink: {unlinked:?}"
        );
        let (res, _) = h.fsetxattr(me, &f, name.clone(), b"2000-01-01".to_vec(), 0);
        assert!(
            matches!(res, Err(Error::Errno(Errno::EPERM))),
            "an immutable file's xattrs must be sealed: {res:?}"
        );

        // Clear it so the tempdir can be torn down.
        h.fset_zfs_attrs(&f, before).expect("unlock");
        h.unlinkat(me, &anchor, leaf("locked.bin")).expect("unlink");
        h.close(f).expect("close");
    });
}

#[test]
fn ranged_fsync_syncs_a_byte_range_and_whole_file() {
    with_fs(test_cfg(), |h, me, dir, _stop| {
        let anchor = Anchor::open(dir.as_path()).expect("anchor");
        let f = h.open(me, &anchor, "ranged.bin", creat_rw()).expect("open");

        // Write 8 KiB so a sub-range fsync has a range to bound.
        let data = vec![0xABu8; 8192];
        let (n, _) = pwrite1(&h, me, &f, data.clone(), 0);
        assert_eq!(n.expect("pwrite"), 8192);

        h.fsync_range(me, &f, false, 0, 4096).expect("fsync_range head");
        h.fsync_range(me, &f, true, 4096, 4096).expect("fdatasync_range tail");
        h.fsync_range(me, &f, false, 0, 0).expect("fsync_range whole");
        h.fsync(me, &f).expect("fsync");
        h.fdatasync(me, &f).expect("fdatasync");
        h.close(f).expect("close");

        let disk = std::fs::read(dir.join("ranged.bin")).expect("read");
        assert_eq!(disk, data);
    });
}

#[test]
fn multi_component_and_beneath() {
    with_fs(test_cfg(), |h, me, dir, _stop| {
        std::fs::create_dir(dir.join("sub")).unwrap();
        std::fs::write(dir.join("sub/inner.txt"), b"beneath").unwrap();
        let anchor = Anchor::open(dir.as_path()).unwrap();

        // Multi-component relative paths are the open's job (only op that walks); RESOLVE_BENEATH confines them
        // in-kernel.
        let how = rdonly().resolve(ResolveFlag::RESOLVE_BENEATH);
        let f = h.open(me, &anchor, "sub/inner.txt", how).expect("open");
        let (n, buf) = pread1(&h, me, &f, vec![0u8; 16], 0);
        assert_eq!(&buf[..n.unwrap()], b"beneath");
        h.close(f).unwrap();

        // Escaping the anchor under RESOLVE_BENEATH is the kernel's EXDEV.
        let how = rdonly().resolve(ResolveFlag::RESOLVE_BENEATH);
        match h.open(me, &anchor, "../escape", how) {
            Err(Error::Errno(Errno::EXDEV)) => {}
            other => panic!("expected EXDEV, got {other:?}"),
        }

        // The DEFAULT (no explicit resolve) confines too: `open` applies the whole `CONFINED_RESOLVE` set - BENEATH |
        // NO_SYMLINKS | NO_XDEV -- when `how` states no policy, so a bare `rdonly()` rejects a `..` escape without the
        // caller opting in.
        match h.open(me, &anchor, "../escape", rdonly()) {
            Err(Error::Errno(Errno::EXDEV)) => {}
            other => panic!("default open must confine `..`, got {other:?}"),
        }
        // ...and does not follow a symlink (NO_SYMLINKS -> ELOOP), so a peer-planted link can't redirect the open out
        // of the share.
        std::os::unix::fs::symlink("/etc/hostname", dir.join("out")).unwrap();
        match h.open(me, &anchor, "out", rdonly()) {
            Err(Error::Errno(Errno::ELOOP)) => {}
            other => {
                panic!("default open must not follow a symlink, {other:?}")
            }
        }
        // A legit in-anchor nested path still opens under the default policy: BENEATH permits descending real subdirs;
        // NO_SYMLINKS blocks only symlink components.
        let f = h.open(me, &anchor, "sub/inner.txt", rdonly()).expect("nested");
        h.close(f).unwrap();
    });
}

#[test]
fn fstatx_reports_open_file_metadata() {
    with_fs(test_cfg(), |h, me, dir, _stop| {
        std::fs::write(dir.join("m.bin"), vec![0u8; 4096]).unwrap();
        let anchor = Anchor::open(dir.as_path()).unwrap();
        let f = h.open(me, &anchor, "m.bin", rdonly()).expect("open");
        // fstat-by-fd: no path resolved - the metadata is exactly this fd's.
        let st = h
            .fstatx(me, &f, AtFlags::empty(), StatxMask::BASIC_STATS)
            .expect("fstatx");
        assert_eq!(st.size(), 4096);
        h.close(f).unwrap();
    });
}

/// A descriptor opened outside the reactor serves its fd-based ops once wrapped. The ring's statx sees the inode a
/// blocking stat sees, and a ring read gives back the bytes.
#[test]
fn a_descriptor_opened_outside_the_ring_serves_its_ops_once_wrapped() {
    with_fs(test_cfg(), |h, me, dir, _stop| {
        let path = dir.join("outside.bin");
        std::fs::write(&path, b"from outside").unwrap();
        let ino = std::fs::metadata(&path).unwrap().ino();
        let fd = std::fs::File::open(&path).unwrap().into();
        let f = File::from_fd(fd);
        let st = h.fstatx(me, &f, AtFlags::empty(), StatxMask::INO).expect("fstatx");
        assert_eq!(st.ino(), ino);
        let (n, buf) = pread1(&h, me, &f, vec![0u8; 12], 0);
        assert_eq!(n.expect("read"), 12);
        assert_eq!(&buf[..12], b"from outside");
        h.close(f).expect("close");
    });
}

/// A `resolve` that only *hardens* must not also un-confine. `open` applies the full `CONFINED_RESOLVE` and lets a
/// caller replace it, but only by naming a policy (`RESOLVE_BENEATH`, `RESOLVE_IN_ROOT`); a request for
/// `RESOLVE_NO_MAGICLINKS` asks for *more* restriction and keeps the default underneath it. Keying that union on
/// `resolve == 0` instead turns the hardening request into an escape hatch, which is what this pins.
#[test]
fn a_hardening_flag_does_not_opt_out_of_confinement() {
    with_fs(test_cfg(), |h, me, dir, _stop| {
        std::fs::write(dir.join("abs.txt"), b"abs").unwrap();
        std::os::unix::fs::symlink("abs.txt", dir.join("link")).unwrap();
        let anchor = Anchor::open(dir.as_path()).unwrap();
        let abs = dir.join("abs.txt"); // an absolute path

        let hardened = rdonly().resolve(ResolveFlag::RESOLVE_NO_MAGICLINKS);
        for (what, how) in [("default", rdonly()), ("hardened", hardened)] {
            match h.open(me, &anchor, &abs, how) {
                Err(Error::Errno(Errno::EXDEV)) => {}
                other => panic!("{what}: absolute path opened: {other:?}"),
            }
            match h.open(me, &anchor, "link", how) {
                Err(Error::Errno(Errno::ELOOP)) => {}
                other => panic!("{what}: symlink followed: {other:?}"),
            }
        }

        // A *stated* policy still stands alone: `RESOLVE_BENEATH` without `RESOLVE_NO_SYMLINKS` is how a caller asks to
        // follow in-tree symlinks, and it must keep meaning that.
        let stated = rdonly().resolve(ResolveFlag::RESOLVE_BENEATH);
        let f = h.open(me, &anchor, "link", stated).expect("in-tree symlink");
        h.close(f).unwrap();
    });
}

#[test]
fn validation_and_errno_mapping() {
    with_fs(test_cfg(), |h, me, dir, _stop| {
        let anchor = Anchor::open(dir.as_path()).unwrap();

        // An empty path is a library-validation error; an absolute path is refused by the *kernel* under the default
        // RESOLVE_BENEATH confinement (it cannot resolve outside the anchor).
        assert!(matches!(h.open(me, &anchor, "", rdonly()), Err(Error::Validation(_))));
        assert!(matches!(
            h.open(me, &anchor, "/etc/hostname", rdonly()),
            Err(Error::Errno(Errno::EXDEV))
        ));
        // O_CLOEXEC is accepted and reaches the kernel, which opens the file.
        std::fs::write(dir.join("cx"), b"cx").unwrap();
        let cloexec = OpenHow::new().flags(OFlag::O_RDONLY | OFlag::O_CLOEXEC);
        let fc = h.open(me, &anchor, "cx", cloexec).expect("O_CLOEXEC open");
        h.close(fc).unwrap();

        assert!(matches!(
            h.open(me, &anchor, "missing.txt", rdonly()),
            Err(Error::Errno(Errno::ENOENT))
        ));
        std::fs::write(dir.join("ro.txt"), b"ro").unwrap();
        let f = h.open(me, &anchor, "ro.txt", rdonly()).unwrap();
        let (res, _buf) = pwrite1(&h, me, &f, b"nope".to_vec(), 0);
        assert!(matches!(res, Err(Error::Errno(Errno::EBADF))));
        h.close(f).unwrap();
    });
}

#[test]
fn stale_personality_from_other_ring_is_einval() {
    // Two reactors: an id registered on ring A names nothing on ring B.
    let dir = truenas_ros::tempdir().unwrap();
    let afs_a = match UringFs::new(test_cfg()) {
        Ok(a) => a,
        Err(e) => {
            if should_skip(&e) {
                return;
            }
            panic!("{e}");
        }
    };
    let id_a = afs_a.register_self().unwrap();
    let mut afs_b = UringFs::new(test_cfg()).unwrap();
    // Deliberately: nothing registered on B.
    let h = afs_b.handle();
    let stop = afs_b.shutdown_handle();
    std::fs::write(dir.path().join("f"), b"x").unwrap();
    let dir_path = dir.path().to_path_buf();
    thread::scope(|s| {
        let stop_c = stop.clone();
        s.spawn(move || {
            let _guard = StopGuard(stop_c);
            let anchor = Anchor::open(dir_path.as_path()).unwrap();
            match h.open(id_a, &anchor, "f", rdonly()) {
                Err(Error::Errno(Errno::EINVAL)) => {}
                other => panic!("expected EINVAL, got {other:?}"),
            }
        });
        afs_b.run().unwrap();
    });
    drop(afs_a); // ring A (and its registration) outlived the use on B
}

// Dropping a token does not cancel in-flight ops. The reactor keeps the fd alive through the op entry's parked
// `Arc<OwnedFd>` until the op completes, so a parked read whose only caller token is dropped mid-flight still completes
// correctly when data arrives.
#[test]
fn dropped_file_mid_op_completes_without_use_after_close() {
    with_fs(test_cfg(), |h, me, dir, _stop| {
        mkfifo(&dir, "fifo");
        let anchor = Anchor::open(dir.as_path()).unwrap();

        // O_RDWR on a FIFO opens immediately and keeps a writer attached, so a read with no data parks - an op
        // genuinely in flight.
        let how = OpenHow::new().flags(OFlag::O_RDWR);
        let f = h.open(me, &anchor, "fifo", how).expect("open fifo");
        let pending = h
            .start_preadv2(me, &f, vec![vec![0u8; 4]], 0, RwFlags::empty())
            .expect("start readv");
        thread::sleep(Duration::from_millis(50)); // let it park in the kernel

        // Drop the caller's only token while the read is parked. The reactor still owns the fd (op-entry `Arc`), so the
        // read stays valid.
        drop(f);

        // Feed the fifo from a fresh writer; the parked read must complete with the real bytes, proving the fd was not
        // closed out from under it.
        let path = dir.join("fifo");
        let writer = thread::spawn(move || {
            use std::io::Write;
            let mut w = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
            w.write_all(b"okay").unwrap();
        });

        let (res, bufs) = pending.wait();
        assert_eq!(res.expect("parked read completes after data arrives"), 4);
        assert_eq!(&bufs[0], b"okay");
        writer.join().unwrap();
    });
}

/// A creating open must not block on a name someone else planted.
///
/// `io_openat_force_async` puts every `O_CREAT`/`O_TRUNC` open on an io-wq worker, where the kernel does *not* add the
/// `O_NONBLOCK` its inline path adds, so an `O_CREAT` that lands on a pre-existing FIFO sleeps in `wait_for_partner`
/// until a writer appears. That pins a bounded io-wq worker and the calling thread - `into_outcome` waits with no
/// deadline -- so a handful of names in a shared multiprotocol tree stall every blocking fs op on the ring.
///
/// Both flags are driven: `O_CREAT|O_RDONLY` blocks for a writer, `O_TRUNC|O_WRONLY` for a reader. Non-blocking, the
/// first opens and the second answers `ENXIO`; what is asserted is that each *returns*.
#[test]
fn a_creating_open_of_a_planted_fifo_does_not_block() {
    use std::sync::mpsc;
    with_fs(test_cfg(), |h, me, dir, _stop| {
        mkfifo(&dir, "planted");
        let anchor = Anchor::open(dir.as_path()).unwrap();
        for (what, flags) in [
            ("O_CREAT|O_RDONLY", OFlag::O_CREAT | OFlag::O_RDONLY),
            ("O_TRUNC|O_WRONLY", OFlag::O_TRUNC | OFlag::O_WRONLY),
        ] {
            let (tx, rx) = mpsc::channel();
            let h2 = h.clone();
            let a2 = anchor.clone();
            // Off-thread, because the failure mode is an indefinite block: a regression must fail this test rather than
            // hang it.
            thread::spawn(move || {
                let how = OpenHow::new().flags(flags).mode(Mode::from_bits_truncate(0o600));
                let _ = tx.send(h2.open(me, &a2, "planted", how).is_ok());
            });
            rx.recv_timeout(Duration::from_secs(3)).unwrap_or_else(|_| {
                panic!(
                    "{what} on a pre-existing FIFO never returned: the open \
                     is blocked in fifo_open on an io-wq worker, and the \
                     calling thread with it"
                )
            });
        }
    });
}

#[test]
fn teardown_with_inflight_op() {
    with_fs(test_cfg(), |h, me, dir, stop| {
        mkfifo(&dir, "fifo");
        let anchor = Anchor::open(dir.as_path()).unwrap();
        let how = OpenHow::new().flags(OFlag::O_RDWR);
        let f = h.open(me, &anchor, "fifo", how).expect("open fifo");
        let pending = h
            .start_preadv2(me, &f, vec![vec![0u8; 8]], 0, RwFlags::empty())
            .expect("start readv");
        thread::sleep(Duration::from_millis(50));

        // Shut down with the read parked: run()'s drain cancels it, the waiter unblocks with an error, and run()
        // returns cleanly (the harness asserts that).
        stop.shutdown();
        let (res, _bufs) = pending.wait();
        assert!(res.is_err(), "parked read must fail at teardown");
        // The token is now pointed at a dead loop; ops fail, drop is inert.
        let (res, _buf) = pread1(&h, me, &f, vec![0u8; 4], 0);
        assert!(matches!(res, Err(Error::Errno(Errno::ECONNABORTED))));
        drop(f);
    });
}

#[test]
fn concurrent_ops_across_threads() {
    with_fs(test_cfg(), |h, me, dir, _stop| {
        let anchor = Anchor::open(dir.as_path()).unwrap();
        thread::scope(|s| {
            for i in 0..4usize {
                let h = h.clone();
                let anchor = anchor.clone();
                s.spawn(move || {
                    let name = format!("t{i}.bin");
                    let name = name.as_str();
                    let payload = vec![i as u8 + 1; 4096 * (i + 1)];
                    let f = h.open(me, &anchor, name, creat_rw()).unwrap();
                    let (n, _bufs) = h.pwritev2(me, &f, vec![payload.clone()], 0, RwFlags::empty());
                    assert_eq!(n.unwrap(), payload.len());
                    h.fsync(me, &f).unwrap();
                    h.close(f).unwrap();
                    let f = h.open(me, &anchor, name, rdonly()).unwrap();
                    let half = payload.len() / 2;
                    let (n, bufs) = h.preadv2(
                        me,
                        &f,
                        vec![vec![0u8; half], vec![0u8; payload.len() - half]],
                        0,
                        RwFlags::empty(),
                    );
                    assert_eq!(n.unwrap(), payload.len());
                    assert_eq!(&bufs[0], &payload[..half]);
                    assert_eq!(&bufs[1], &payload[half..]);
                    h.close(f).unwrap();
                });
            }
        });
    });
}

#[test]
fn write_pread_offsets() {
    with_fs(test_cfg(), |h, me, dir, _stop| {
        let anchor = Anchor::open(dir.as_path()).unwrap();
        let f = h.open(me, &anchor, "sparse", creat_rw()).unwrap();
        let (n, _b) = pwrite1(&h, me, &f, b"tail".to_vec(), 100);
        assert_eq!(n.unwrap(), 4);
        let (n, buf) = pread1(&h, me, &f, vec![0u8; 8], 98);
        assert_eq!(n.unwrap(), 6, "2 hole bytes + 4 tail bytes to EOF");
        assert_eq!(&buf[..6], b"\0\0tail");
        h.close(f).unwrap();
        assert_eq!(std::fs::metadata(dir.join("sparse")).unwrap().len(), 104);
    });
}
