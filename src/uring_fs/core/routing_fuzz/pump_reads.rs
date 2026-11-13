use super::*;

// ---- `IOSQE_ASYNC` (`FsCore::set_force_async`) ----

/// The file classes stamp `IOSQE_ASYNC` on a read, and only their own class does. The `WRITE`-only arm is the
/// control: it configures the core, submits the same read, and must leave the SQE unflagged, so an assertion that
/// merely found the bit set could not pass it.
#[test]
fn a_pump_read_carries_iosqe_async_only_for_its_own_class() {
    let staged_flags = |classes: ForceAsync| -> Option<u8> {
        let mut eng = engine_or_skip()?;
        let mut core = FsCore::new(4, OffloadBounds::default());
        core.set_force_async(classes);
        let dir = crate::tempdir().expect("tempdir");
        let p = dir.path().join("f");
        std::fs::write(&p, b"0123456789").unwrap();
        let fd: std::os::fd::OwnedFd = std::fs::File::open(&p).unwrap().into();
        let file = File::new(Arc::new(fd));
        core.submit_pump_read(&mut eng, &file, PumpDest::Owned(Vec::with_capacity(8)), 8, 0, (1, 1))
            .expect("submit");
        let flags = eng.staged_sqe(0).flags;
        // Reap rather than drop mid-flight: the op parks an fd clone and the entry is only released by its
        // completion.
        eng.ring.submit_and_wait(1).expect("submit_and_wait");
        let cqe = eng.ring.reap().expect("cqe");
        let (tag, slot, g) = unpack_raw(cqe.user_data);
        core.on_cqe(&mut eng, tag, slot, g, cqe.res);
        Some(flags)
    };
    let Some(armed) = staged_flags(ForceAsync::READ) else {
        return;
    };
    assert_eq!(
        armed & crate::uring::sys::IOSQE_ASYNC,
        crate::uring::sys::IOSQE_ASYNC,
        "ForceAsync::READ must reach the pump read's SQE"
    );
    for wrong in [ForceAsync::empty(), ForceAsync::WRITE] {
        let flags = staged_flags(wrong).expect("ring was available");
        assert_eq!(
            flags & crate::uring::sys::IOSQE_ASYNC,
            0,
            "a read must stay unflagged under {wrong:?}"
        );
    }
}

// ---- reply-path pump reads (`FsWaiter::Pump`) ----

#[test]
fn a_pump_read_routes_back_with_its_owner_and_bytes() {
    let Some(mut eng) = engine_or_skip() else {
        return;
    };
    let mut core = FsCore::new(4, OffloadBounds::default());
    let dir = crate::tempdir().expect("tempdir");
    let p = dir.path().join("f");
    std::fs::write(&p, b"0123456789").unwrap();
    let fd: std::os::fd::OwnedFd = std::fs::File::open(&p).unwrap().into();
    let file = File::new(Arc::new(fd));

    core.submit_pump_read(&mut eng, &file, PumpDest::Owned(Vec::with_capacity(8)), 8, 2, (3, 77))
        .expect("submit");
    // The op parks its own fd clone (close-last): caller + op.
    assert_eq!(Arc::strong_count(&file.fd), 2);

    eng.ring.submit_and_wait(1).expect("submit_and_wait");
    let cqe = eng.ring.reap().expect("cqe");
    let (tag, slot, g) = unpack_raw(cqe.user_data);
    assert_eq!(tag, TAG_READV);
    let ReapedFs::Pump(done, owner) = core.on_cqe(&mut eng, tag, slot, g, cqe.res) else {
        panic!("a pump read must route as ReapedFs::Pump");
    };
    assert_eq!(owner, (3, 77), "the owner survives the round trip");
    assert!(matches!(done.result(), Ok(8)), "{:?}", done.result());
    // The parked clone dropped with the op entry (close-last).
    assert_eq!(Arc::strong_count(&file.fd), 1);
    let mut bufs = done.into_bufs();
    let mut b = bufs.pop().expect("the read's buffer comes back");
    assert!(bufs.is_empty());
    // SAFETY: the CQE count proves the kernel wrote 8 bytes into the spare capacity the iovec targeted.
    unsafe { b.set_len(8) };
    assert_eq!(&b[..], b"23456789", "read from the requested offset");
}

#[test]
fn a_full_op_table_refuses_a_pump_read_synchronously() {
    // The error comes back at submit time, since there is no callback to report it and a dropped pump read would strand
    // its connection mid-body.
    let Some(mut eng) = engine_or_skip() else {
        return;
    };
    let mut core = FsCore::new(1, OffloadBounds::default());
    let dir = crate::tempdir().expect("tempdir");
    let p = dir.path().join("f");
    std::fs::write(&p, b"abcd").unwrap();
    let fd: std::os::fd::OwnedFd = std::fs::File::open(&p).unwrap().into();
    let file = File::new(Arc::new(fd));
    let submit = |core: &mut FsCore, eng: &mut Engine| {
        core.submit_pump_read(eng, &file, PumpDest::Owned(Vec::with_capacity(4)), 4, 0, (0, 1))
    };

    submit(&mut core, &mut eng).expect("first read takes the only op slot");
    assert_eq!(
        submit(&mut core, &mut eng),
        Err(Errno::EBUSY),
        "a full table must refuse, not drop"
    );
    // Draining the first read frees the slot for the next.
    eng.ring.submit_and_wait(1).expect("submit_and_wait");
    let cqe = eng.ring.reap().expect("cqe");
    let (tag, slot, g) = unpack_raw(cqe.user_data);
    assert!(matches!(
        core.on_cqe(&mut eng, tag, slot, g, cqe.res),
        ReapedFs::Pump(..)
    ));
    submit(&mut core, &mut eng).expect("freed slot serves the next");
}

/// A pump read whose buffer cannot hold `want` is refused, not staged, since an oversized `want` is a heap write by the
/// kernel on an io-wq worker, far from the call. This is the release half of the guard, on
/// `an_unknown_tag_is_refused_rather_than_staged_as_a_nop`'s pattern.
#[cfg(not(debug_assertions))]
#[test]
fn a_pump_read_past_its_buffer_is_refused_not_staged() {
    let Some(mut eng) = engine_or_skip() else {
        return;
    };
    let mut core = FsCore::new(4, OffloadBounds::default());
    let dir = crate::tempdir().expect("tempdir");
    let p = dir.path().join("f");
    std::fs::write(&p, b"abcd").unwrap();
    let fd: std::os::fd::OwnedFd = std::fs::File::open(&p).unwrap().into();
    let file = File::new(Arc::new(fd));

    // The control: `want == capacity` is exactly what the reply path submits, and it must still be accepted - and
    // take a slot.
    let free = core.op_free_len_for_test();
    core.submit_pump_read(&mut eng, &file, PumpDest::Owned(Vec::with_capacity(8)), 8, 0, (0, 1))
        .expect("want == capacity is the ordinary case");
    assert_eq!(core.op_free_len_for_test(), free - 1, "it took a slot");

    // One byte past the allocation.
    let free = core.op_free_len_for_test();
    assert_eq!(
        core.submit_pump_read(&mut eng, &file, PumpDest::Owned(Vec::with_capacity(8)), 9, 0, (0, 1),),
        Err(Errno::EINVAL),
        "a read past the buffer must be refused"
    );
    assert_eq!(
        core.op_free_len_for_test(),
        free,
        "the refusal must not consume an op slot"
    );

    // The other half of the precondition: the host sets the length from the CQE count, so a buffer that already has
    // one would be written past its own contents.
    let mut used = Vec::with_capacity(64);
    used.push(1u8);
    assert_eq!(
        core.submit_pump_read(&mut eng, &file, PumpDest::Owned(used), 8, 0, (0, 1),),
        Err(Errno::EINVAL),
        "a non-empty destination must be refused"
    );
}

/// The debug half of the guard above: the same call trips the `debug_assert!(false)` rather than reaching the
/// refusal.
#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "a pump read of 9 bytes")]
fn a_pump_read_past_its_buffer_asserts_in_debug() {
    let Some(mut eng) = engine_or_skip() else {
        // A `should_panic` test cannot skip; panic with the expected message so an unavailable ring does not read
        // as a regression.
        panic!("a pump read of 9 bytes (io_uring unavailable: skipped)");
    };
    let mut core = FsCore::new(4, OffloadBounds::default());
    let dir = crate::tempdir().expect("tempdir");
    let p = dir.path().join("f");
    std::fs::write(&p, b"abcd").unwrap();
    let fd: std::os::fd::OwnedFd = std::fs::File::open(&p).unwrap().into();
    let file = File::new(Arc::new(fd));
    let _ = core.submit_pump_read(&mut eng, &file, PumpDest::Owned(Vec::with_capacity(8)), 9, 0, (0, 1));
}
