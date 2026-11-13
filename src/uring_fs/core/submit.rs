use super::*;

impl FsCore {
    // ---- submission (from drained injects) -----------------------------

    /// Stage an `OPENAT2` in a freshly reserved op slot. Every failure is answered through `waiter`, as the loop never
    /// dies for a per-op reason.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn submit_open(
        &mut self,
        eng: &mut Engine,
        pers: u16,
        anchor: Anchor,
        path: &[u8],
        how: RawOpenHow,
        guarded: bool,
        deadline: Option<std::time::Duration>,
        waiter: FsWaiter,
    ) {
        // Personality 0 would resolve the name under the ring owner's ambient root credentials. `Personality` cannot be
        // 0 by construction, so this catches an internal misuse, and fails closed.
        if pers == 0 {
            self.refuse(eng, waiter, Errno::EINVAL, true, Vec::new(), None);
            return;
        }
        // An `Allow` open is a wall-clock hold like a timer, two slots parked until the deadline or the open ends the
        // pair, so it answers to the timer's screen. A guarded open cannot block and passes unscreened.
        if deadline.is_some()
            && let Some((err, marked)) = self.refuse_wall_clock_hold(&waiter)
        {
            self.refuse(eng, waiter, err, marked, Vec::new(), None);
            return;
        }
        // An `Allow` open charges two slots - its own and its guard timer's, both held until it answers - so the
        // refusal happens here, before either pop, and the guard's pop below cannot fail.
        if deadline.is_some() && self.op_free.len() < 2 {
            self.refuse(eng, waiter, Errno::EBUSY, true, Vec::new(), None);
            return;
        }
        let Some(op_slot) = self.pop_op() else {
            self.refuse(eng, waiter, Errno::EBUSY, true, Vec::new(), None);
            return;
        };

        // The owner an `Allow` pair's wall-clock charge is metered to, read before the waiter parks on the entry.
        let timer_owner = match &waiter {
            FsWaiter::Embedded { owner: Some(o), .. } => Some(*o),
            _ => None,
        };
        let entry = &mut self.ops[op_slot as usize];
        let open_gen = entry.generation;
        let gen32 = entry.generation as u32;
        let e = &mut entry.state;
        e.state = FsOpState::InFlight { tag: TAG_OPEN };
        e.waiter = Some(waiter);
        let path_ptr = e.park_name(path);
        e.how = Some(how);
        e.strip_nonblock = guarded;
        let dirfd = anchor.raw_fd();
        let how_ptr = e.how.as_ref().expect("just set") as *const RawOpenHow as u64;
        e.anchor = Some(anchor);

        // OPENAT2 returns a real fd as its CQE result, which `on_cqe` wraps in an `Arc<OwnedFd>`.
        let ud = pack_raw(TAG_OPEN, op_slot, gen32);
        let staged = eng.stage(ud, |sqe| {
            sqe.opcode = IORING_OP_OPENAT2;
            sqe.fd = dirfd;
            sqe.addr = path_ptr;
            sqe.off_addr2 = how_ptr;
            sqe.len = size_of::<RawOpenHow>() as u32;
            // `pers != 0` guaranteed at entry (fail-closed above).
            sqe.personality = pers;
        });
        if let Err(e) = staged {
            self.fail_op(eng, op_slot, e);
            return;
        }
        // An `Allow` open's bound, an ordinary timer in its own slot whose expiry stages the `ASYNC_CANCEL` that frees
        // a worker parked in `fifo_open`, and which the open's completion retracts ([`TAG_OPEN_DEADLINE`] says why it
        // is not a `LINK_TIMEOUT`). The two-slot charge was checked before the open's pop, so this pop cannot fail.
        if let Some(after) = deadline {
            let guard_slot = self.pop_op().expect("reserved before the open's pop");
            let ts = Box::new(KernelTimespec {
                tv_sec: i64::try_from(after.as_secs()).unwrap_or(i64::MAX),
                tv_nsec: i64::from(after.subsec_nanos()),
            });
            let ts_ptr = std::ptr::addr_of!(*ts) as u64;
            let gentry = &mut self.ops[guard_slot as usize];
            let ggen32 = gentry.generation as u32;
            let ge = &mut gentry.state;
            ge.state = FsOpState::InFlight { tag: TAG_OPEN_DEADLINE };
            ge.ts = Some(ts);
            ge.cancels = Some((op_slot, open_gen));
            let gud = pack_raw(TAG_OPEN_DEADLINE, guard_slot, ggen32);
            let staged = eng.stage(gud, |sqe| {
                sqe.opcode = IORING_OP_TIMEOUT;
                sqe.addr = ts_ptr;
                sqe.len = 1; // exactly one timespec, per the kernel
            });
            match staged {
                Ok(()) => {
                    self.ops[op_slot as usize].state.guard =
                        Some((guard_slot, self.ops[guard_slot as usize].generation));
                    // The pair's wall-clock charge, taken only once the guard is real and returned by whichever of the
                    // two slots frees last (`take_op` parks it on `retiring` meanwhile).
                    if let Some(o) = timer_owner {
                        self.armed_timers.entry(o).or_default().arm();
                    }
                }
                Err(_) => {
                    // The open is in flight and its bound cannot be, so ask for the open to be cancelled, marked
                    // (`retract_op`) so its `ECANCELED` reads as the deadline's verdict rather than teardown's. The
                    // guard's slot frees, delivering to nobody.
                    //
                    // The ask is all this can promise. The cancel goes to the same ring that just refused a stage
                    // ([`FsCore::submit_cancel`] is best-effort), so the open may run to its own ending with an io-wq
                    // worker parked in it, and teardown is the recovery for that.
                    self.fail_op(eng, guard_slot, Errno::ECANCELED);
                    self.retract_op(eng, TAG_OPEN, op_slot, open_gen);
                }
            }
        }
    }

    /// Stage a `READV`/`WRITEV` (per `tag`) against an open file. `rw_flags` is the `RWF_*` set `preadv2`/`pwritev2`
    /// take, which the kernel validates at prep, failing the op with `EOPNOTSUPP` for anything the file system does not
    /// implement, so an unsupported flag is never silently dropped.
    #[allow(clippy::too_many_arguments)] // an inject unpacked, not an API
    pub(crate) fn submit_rw(
        &mut self,
        eng: &mut Engine,
        tag: u8,
        pers: u16,
        file: Arc<OwnedFd>,
        mut bufs: Vec<Vec<u8>>,
        off: u64,
        rw_flags: u32,
        waiter: FsWaiter,
    ) {
        let Some(op_slot) = self.pop_op() else {
            self.refuse(eng, waiter, Errno::EBUSY, true, bufs, Some(file));
            return;
        };

        let raw_fd = file.as_raw_fd();
        let entry = &mut self.ops[op_slot as usize];
        let gen32 = entry.generation as u32;
        let e = &mut entry.state;
        e.state = FsOpState::InFlight { tag };
        e.waiter = Some(waiter);
        // Into the slot's own storage, since `FsOpEntry::clear` empties this vector without releasing it, and a fresh
        // `Vec` here would allocate once per op. The heap block each iovec names does not move with `bufs`.
        e.iov.clear();
        e.iov.extend(bufs.iter_mut().map(|b| libc::iovec {
            iov_base: b.as_mut_ptr().cast(),
            iov_len: b.len(),
        }));
        e.bufs = bufs;
        // Park the fd here so it stays open until the CQE even if the caller drops its `File` mid-op (close-last by
        // ownership).
        e.file = Some(file);
        let iov_ptr = e.iov.as_ptr() as u64;
        let iov_len = e.iov.len() as u32;

        let (opcode, class) = if tag == TAG_READV {
            (IORING_OP_READV, ForceAsync::READ)
        } else {
            (IORING_OP_WRITEV, ForceAsync::WRITE)
        };
        let force = self.force_async.sqe_bit(class);
        let ud = pack_raw(tag, op_slot, gen32);
        let staged = eng.stage(ud, |sqe| {
            sqe.opcode = opcode;
            sqe.fd = raw_fd;
            sqe.flags = force;
            sqe.addr = iov_ptr;
            sqe.len = iov_len;
            sqe.off_addr2 = off;
            // The `preadv2`/`pwritev2` flag word. Zero for the plain forms.
            sqe.op_flags = rw_flags;
            sqe.personality = pers;
        });
        if let Err(err) = staged {
            self.fail_op(eng, op_slot, err);
        }
    }

    /// Stage one `READ` of up to `count` bytes of `file` at `off` into the room past the length of `buf`, which the
    /// slot keeps in its `value` until the CQE, where [`FsCore::on_cqe`] grows the length by what the kernel wrote.
    /// `IORING_OP_READ` takes the address and the count itself (`io_prep_read`, `io_uring/rw.c`), so the slot builds no
    /// iovec.
    ///
    /// Refused with a marked `EINVAL` before a slot is taken whenever [`spare_read_fits`] says no, with `buf` handed
    /// back as it came.
    #[allow(clippy::too_many_arguments)] // an inject unpacked, not an API
    pub(crate) fn submit_read_spare(
        &mut self,
        eng: &mut Engine,
        pers: u16,
        file: Arc<OwnedFd>,
        buf: Vec<u8>,
        count: usize,
        off: u64,
        rw_flags: u32,
        waiter: FsWaiter,
    ) {
        if !spare_read_fits(buf.capacity() - buf.len(), count, off) {
            let (bufs, file) = (vec![buf], Some(file));
            self.refuse(eng, waiter, Errno::EINVAL, true, bufs, file);
            return;
        }
        let Some(op_slot) = self.pop_op() else {
            let (bufs, file) = (vec![buf], Some(file));
            self.refuse(eng, waiter, Errno::EBUSY, true, bufs, file);
            return;
        };

        let raw_fd = file.as_raw_fd();
        let entry = &mut self.ops[op_slot as usize];
        let gen32 = entry.generation as u32;
        let e = &mut entry.state;
        e.state = FsOpState::InFlight { tag: TAG_READ_SPARE };
        e.waiter = Some(waiter);
        // Parked so the descriptor stays open to the CQE, as `submit_rw` parks it.
        e.file = Some(file);
        // The heap block does not move with the vector parked here, so the room the SQE names stays where it is until
        // the CQE.
        let val = e.value.insert(buf);
        let room = val.spare_capacity_mut().as_mut_ptr() as u64;
        let force = self.force_async.sqe_bit(ForceAsync::READ);
        let ud = pack_raw(TAG_READ_SPARE, op_slot, gen32);
        let staged = eng.stage(ud, |sqe| {
            sqe.opcode = IORING_OP_READ;
            sqe.fd = raw_fd;
            sqe.flags = force;
            sqe.addr = room;
            // `spare_read_fits` held the count to a `u32`.
            sqe.len = count as u32;
            sqe.off_addr2 = off;
            sqe.op_flags = rw_flags;
            sqe.personality = pers;
        });
        if let Err(err) = staged {
            self.fail_op(eng, op_slot, err);
        }
    }

    /// Stage one `WRITE` of `buf[range]` to `file` at `off`, with `buf` kept in the slot's `value` until the CQE, as
    /// [`submit_read_spare`](Self::submit_read_spare) keeps its own. `IORING_OP_WRITE` takes the address and the count
    /// itself (`io_prep_write`, `io_uring/rw.c`), so the slot builds no iovec.
    ///
    /// Refused with a marked `EINVAL` before a slot is taken whenever [`owned_write_fits`] says no, and with a marked
    /// `EBUSY` on a full table, with `buf` handed back as it came either way.
    #[allow(clippy::too_many_arguments)] // an inject unpacked, not an API
    pub(crate) fn submit_write_owned(
        &mut self,
        eng: &mut Engine,
        pers: u16,
        file: Arc<OwnedFd>,
        buf: Vec<u8>,
        range: Range<usize>,
        off: u64,
        rw_flags: u32,
        waiter: FsWaiter,
    ) {
        if !owned_write_fits(buf.len(), &range, off) {
            let (bufs, file) = (vec![buf], Some(file));
            self.refuse(eng, waiter, Errno::EINVAL, true, bufs, file);
            return;
        }
        let Some(op_slot) = self.pop_op() else {
            let (bufs, file) = (vec![buf], Some(file));
            self.refuse(eng, waiter, Errno::EBUSY, true, bufs, file);
            return;
        };

        let raw_fd = file.as_raw_fd();
        let entry = &mut self.ops[op_slot as usize];
        let gen32 = entry.generation as u32;
        let e = &mut entry.state;
        e.state = FsOpState::InFlight { tag: TAG_WRITE_OWNED };
        e.waiter = Some(waiter);
        // Parked so the descriptor stays open to the CQE, as `submit_rw` parks it.
        e.file = Some(file);
        // The heap block does not move with the vector parked here, so the bytes the SQE names stay where they are
        // until the CQE.
        let val = e.value.insert(buf);
        let at = val[range.clone()].as_ptr() as u64;
        let force = self.force_async.sqe_bit(ForceAsync::WRITE);
        let ud = pack_raw(TAG_WRITE_OWNED, op_slot, gen32);
        let staged = eng.stage(ud, |sqe| {
            sqe.opcode = IORING_OP_WRITE;
            sqe.fd = raw_fd;
            sqe.flags = force;
            sqe.addr = at;
            // `owned_write_fits` held the count to a `u32`.
            sqe.len = range.len() as u32;
            sqe.off_addr2 = off;
            sqe.op_flags = rw_flags;
            sqe.personality = pers;
        });
        if let Err(err) = staged {
            self.fail_op(eng, op_slot, err);
        }
    }

    /// Stage one write of held windows' bytes, in order from `off`, every share held to the CQE and each buffer's id
    /// surfaced at the reap for the net server to hand back. One window is a `WRITE`, which takes the address and count
    /// itself (`io_prep_write`, `io_uring/rw.c`), so it needs no iovec and never grows the slot's array. More are a
    /// `WRITEV`.
    ///
    /// `Err` hands the waiter back, never in flight. A full op table and a gather that does not fit one `WRITEV`
    /// (`gather_fits`) hand the windows back as they came. A refused SQE drops them in the slot, which returns each
    /// share. A window's bytes stay valid while its share lives, and the entry keeps every share to the reap.
    #[cfg(feature = "net-server")]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn submit_pwritev2_gathered<W>(
        &mut self,
        eng: &mut Engine,
        pers: u16,
        file: Arc<OwnedFd>,
        windows: W,
        off: u64,
        rw_flags: u32,
        waiter: FsWaiter,
    ) -> Result<(), (Option<W>, FsWaiter)>
    where
        W: AsRef<[LeasedWindow]> + IntoIterator<Item = LeasedWindow>,
    {
        let held = windows.as_ref();
        let count = held.len();
        let total: usize = held.iter().map(LeasedWindow::len).sum();
        if !gather_fits(count, total) {
            return Err((Some(windows), waiter));
        }
        let Some(op_slot) = self.pop_op() else {
            return Err((Some(windows), waiter));
        };
        let raw_fd = file.as_raw_fd();
        let entry = &mut self.ops[op_slot as usize];
        let gen32 = entry.generation as u32;
        entry.state.state = FsOpState::InFlight { tag: TAG_WRITEV };
        entry.state.iov.clear();
        entry.state.recv_lease_more.clear();
        let mut single = None;
        for LeasedWindow { view, hold } in windows {
            if count == 1 {
                single = Some(view);
            } else {
                entry.state.iov.push(libc::iovec {
                    iov_base: view.ptr as *mut libc::c_void,
                    iov_len: view.len,
                });
            }
            if entry.state.recv_lease.is_none() {
                entry.state.recv_lease = Some(hold);
            } else {
                entry.state.recv_lease_more.push(hold);
            }
        }
        entry.state.file = Some(file);
        entry.state.lease_want = total as u32;
        // `gather_fits` held the count to `UIO_MAXIOV` and the bytes to `max_rw_count`, so both fit a `u32`.
        let (opcode, addr, len) = match single {
            Some(view) => (IORING_OP_WRITE, view.ptr as u64, view.len as u32),
            None => {
                let iov = entry.state.iov.as_ptr() as u64;
                (IORING_OP_WRITEV, iov, count as u32)
            }
        };
        let force = self.force_async.sqe_bit(ForceAsync::WRITE);
        let ud = pack_raw(TAG_WRITEV, op_slot, gen32);
        let staged = eng.stage(ud, |sqe| {
            sqe.opcode = opcode;
            sqe.fd = raw_fd;
            sqe.flags = force;
            sqe.addr = addr;
            sqe.len = len;
            sqe.off_addr2 = off;
            sqe.op_flags = rw_flags;
            sqe.personality = pers;
        });
        match staged {
            Ok(()) => {
                entry.state.waiter = Some(waiter);
                Ok(())
            }
            Err(_) => {
                // Never in flight, so the clear drops every share the slot took, which returns each buffer as its last
                // share goes.
                entry.state.clear();
                entry.generation += 1;
                self.op_free.push(op_slot);
                Err((None, waiter))
            }
        }
    }

    /// Submit `windows` as one gathered leased write or, when the table or the SQ is full, refuse it with a marked
    /// `EBUSY` like any other op. The windows drop with the refusal, so each buffer goes back as its last share goes.
    /// The caller has checked `gather_fits`.
    ///
    /// Do not park a refused write for a later slot. Waiting writes take each slot as it frees, so a full table stays
    /// full and the handler's other ops - the open before a body, the fsync and rename after it - are refused in their
    /// place, after the body was written.
    #[cfg(feature = "net-server")]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn submit_leased_or_refuse<W>(
        &mut self,
        eng: &mut Engine,
        pers: u16,
        file: Arc<OwnedFd>,
        windows: W,
        off: u64,
        rw_flags: u32,
        waiter: FsWaiter,
    ) where
        W: AsRef<[LeasedWindow]> + IntoIterator<Item = LeasedWindow>,
    {
        debug_assert!(gather_fits(
            windows.as_ref().len(),
            windows.as_ref().iter().map(LeasedWindow::len).sum()
        ));
        if let Err((windows, waiter)) =
            self.submit_pwritev2_gathered(eng, pers, Arc::clone(&file), windows, off, rw_flags, waiter)
        {
            drop(windows);
            self.refuse(eng, waiter, Errno::EBUSY, true, Vec::new(), Some(file));
        }
    }

    /// Pop a free op slot - the one way any submit path takes one.
    fn pop_op(&mut self) -> Option<u32> {
        self.op_free.pop()
    }

    /// Whether the op table has a slot left. The reply path consults this before committing a chunk buffer to a body
    /// read, so a full table parks the tail (a completing op frees a slot and re-drives it) instead of severing a
    /// transfer that has done nothing wrong.
    #[cfg_attr(not(feature = "net-server"), allow(dead_code))]
    pub(crate) fn has_free_op(&self) -> bool {
        !self.op_free.is_empty()
    }

    /// Selecting pump reads in flight, for the body pool's `grow`.
    #[cfg_attr(not(feature = "net-server"), allow(dead_code))]
    pub(crate) fn pump_selecting(&self) -> u32 {
        self.pump_selecting
    }

    #[cfg(all(test, not(loom)))]
    pub(crate) fn op_free_len_for_test(&self) -> usize {
        self.op_free.len()
    }

    #[cfg(all(test, not(loom)))]
    pub(crate) fn armed_timers_for_test(&self, owner: &(u32, u64)) -> u32 {
        self.armed_timers.get(owner).copied().unwrap_or_default().armed
    }

    #[cfg(all(test, not(loom)))]
    pub(crate) fn retiring_timers_for_test(&self, owner: &(u32, u64)) -> u32 {
        self.armed_timers.get(owner).copied().unwrap_or_default().retiring
    }

    /// Stage a reactor-pump `READV`, one positional read of up to `want` bytes at `off`, completing through
    /// [`ReapedFs::Pump`] rather than a callback, for reads the reply path issues itself (a file-sourced response
    /// body).
    ///
    /// `dest` is a buffer this side supplies, arriving empty with `capacity() >= want`, or a group id to let the kernel
    /// pick one from a registered ring at completion. No personality is stamped, so the read runs as the ring's own
    /// credentials, since the access was decided at the file's open. A failure is returned (`EBUSY` on a full op table,
    /// or the staging error), as there is no callback to report it, and a dropped pump read would strand its connection
    /// mid-body.
    ///
    /// `IORING_OP_READV` carries `buffer_select` (`io_uring/opdef.c`) with a single iovec, since
    /// `io_iov_buffer_select_prep` answers `-EINVAL` above one (`io_uring/rw.c`). The kernel reads that iovec for its
    /// length and supplies the address itself.
    #[cfg_attr(not(feature = "net-server"), allow(dead_code))]
    pub(crate) fn submit_pump_read(
        &mut self,
        eng: &mut Engine,
        file: &File,
        dest: PumpDest,
        want: usize,
        off: u64,
        owner: (u32, u64),
    ) -> Result<(), Errno> {
        let (mut buf, bgid) = match dest {
            PumpDest::Owned(b) => (b, None),
            PumpDest::Group(g) => (Vec::new(), Some(g)),
        };
        // The kernel writes `want` bytes into `buf`'s spare capacity, so a buffer that cannot hold them is a heap
        // overflow later on an io-wq worker. Screened in both profiles, since this length is the caller's to get right,
        // and refused rather than only asserted. Buffer select is exempt, as the kernel supplies the address there.
        if bgid.is_none() && (!buf.is_empty() || buf.capacity() < want) {
            debug_assert!(
                false,
                "a pump read of {want} bytes into a buffer holding {} with \
                 capacity {}",
                buf.len(),
                buf.capacity()
            );
            return Err(Errno::EINVAL);
        }
        let Some(op_slot) = self.pop_op() else {
            return Err(Errno::EBUSY);
        };
        let raw_fd = file.as_raw_fd();
        let entry = &mut self.ops[op_slot as usize];
        let gen32 = entry.generation as u32;
        let e = &mut entry.state;
        e.state = FsOpState::InFlight { tag: TAG_READV };
        e.waiter = Some(FsWaiter::Pump { owner });
        // The iovec targets the Vec's spare capacity, whose heap block survives the move below. Under buffer select
        // only its length is read.
        e.iov.clear();
        e.iov.push(libc::iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: want,
        });
        e.bufs = if bgid.is_some() { Vec::new() } else { vec![buf] };
        // Park the fd so it stays open until the CQE even if the connection drops its `File` mid-op (close-last by
        // ownership).
        e.file = Some(Arc::clone(&file.fd));
        let iov_ptr = e.iov.as_ptr() as u64;
        let force = self.force_async.sqe_bit(ForceAsync::READ);
        let ud = pack_raw(TAG_READV, op_slot, gen32);
        let staged = eng.stage(ud, |sqe| {
            sqe.opcode = IORING_OP_READV;
            sqe.fd = raw_fd;
            sqe.flags = force;
            sqe.addr = iov_ptr;
            sqe.len = 1; // one iovec: buffer select refuses more
            sqe.off_addr2 = off;
            if let Some(g) = bgid {
                sqe.flags |= IOSQE_BUFFER_SELECT;
                sqe.buf_index = g;
            }
        });
        if let Err(err) = staged {
            self.fail_op(eng, op_slot, err);
            return Err(err);
        }
        if bgid.is_some() {
            self.pump_selecting += 1;
        }
        Ok(())
    }

    /// Stage an `FSYNC` (`datasync` selects `fdatasync`). `offset`/`length` bound the sync to a byte range via the
    /// SQE's `off`/`len` fields (the kernel's `vfs_fsync_range`, deriving `end = off + len`); `offset == 0 && length ==
    /// 0` syncs the whole file.
    #[allow(clippy::too_many_arguments)] // an inject unpacked, not an API
    pub(crate) fn submit_fsync(
        &mut self,
        eng: &mut Engine,
        pers: u16,
        file: Arc<OwnedFd>,
        datasync: bool,
        offset: u64,
        length: u32,
        waiter: FsWaiter,
    ) {
        let Some(op_slot) = self.pop_op() else {
            self.refuse(eng, waiter, Errno::EBUSY, true, Vec::new(), Some(file));
            return;
        };

        let raw_fd = file.as_raw_fd();
        let entry = &mut self.ops[op_slot as usize];
        let gen32 = entry.generation as u32;
        let e = &mut entry.state;
        e.state = FsOpState::InFlight { tag: TAG_FSYNC };
        e.waiter = Some(waiter);
        e.file = Some(file);

        let ud = pack_raw(TAG_FSYNC, op_slot, gen32);
        let staged = eng.stage(ud, |sqe| {
            sqe.opcode = IORING_OP_FSYNC;
            sqe.fd = raw_fd;
            // Byte-range sync via the SQE's off/len (the kernel derives `end = off + len`, treating 0/0 as
            // through-EOF).
            sqe.off_addr2 = offset;
            sqe.len = length;
            if datasync {
                sqe.op_flags = IORING_FSYNC_DATASYNC;
            }
            sqe.personality = pers;
        });
        if let Err(err) = staged {
            self.fail_op(eng, op_slot, err);
        }
    }

    /// Stage a standalone relative timer, one `IORING_OP_TIMEOUT` that completes after `after`. Expiry is the op's
    /// success, so the kernel's `-ETIME` for a pure timer (`io_timeout_fn`, `io_uring/timeout.c`) is delivered as
    /// `Ok(0)` ([`FsCore::on_cqe`]). No fd and no personality, as a timer touches nothing a credential guards.
    ///
    /// Answers the armed timer's slot and full-width generation, for [`FsConn::cancel_timeout`]'s [`Timer`], or `None`
    /// when the arm was refused and the waiter has been answered.
    ///
    /// **A swept owner may not park time on the table.** Other post-sweep submissions are allowed, but a timer is a
    /// wait, not progress, and a re-arming tick whose connection died would strand a slot per arm. The refusal is the
    /// sweep's own unmarked `ECANCELED`, so a continuation winds down the same way in both orderings, and it arrives
    /// through the callback, since [`FsCore::refuse`] fills a sink only for a marked refusal.
    pub(crate) fn submit_timeout(
        &mut self,
        eng: &mut Engine,
        after: std::time::Duration,
        waiter: FsWaiter,
    ) -> Option<(u32, u64)> {
        if let Some((err, marked)) = self.refuse_wall_clock_hold(&waiter) {
            self.refuse(eng, waiter, err, marked, Vec::new(), None);
            return None;
        }
        let Some(op_slot) = self.pop_op() else {
            self.refuse(eng, waiter, Errno::EBUSY, true, Vec::new(), None);
            return None;
        };

        // Saturating, as every Duration-to-timespec conversion in the crate is. `timespec64_valid` only refuses a bad
        // `tv_nsec` (`__io_timeout_prep`, `io_uring/timeout.c`), so a clamped `i64::MAX` is effectively forever.
        let ts = Box::new(KernelTimespec {
            tv_sec: i64::try_from(after.as_secs()).unwrap_or(i64::MAX),
            tv_nsec: i64::from(after.subsec_nanos()),
        });
        let addr = std::ptr::addr_of!(*ts) as u64;
        let entry = &mut self.ops[op_slot as usize];
        let gen32 = entry.generation as u32;
        let e = &mut entry.state;
        e.state = FsOpState::InFlight { tag: TAG_TIMEOUT };
        e.waiter = Some(waiter);
        e.ts = Some(ts);

        let ud = pack_raw(TAG_TIMEOUT, op_slot, gen32);
        let staged = eng.stage(ud, |sqe| {
            sqe.opcode = IORING_OP_TIMEOUT;
            sqe.addr = addr;
            sqe.len = 1; // exactly one timespec, per the kernel
        });
        if let Err(err) = staged {
            self.fail_op(eng, op_slot, err);
            return None;
        }
        // Counted only once the arm is real, so the refusals above have nothing to return.
        if let Some(FsWaiter::Embedded { owner: Some(o), .. }) = &self.ops[op_slot as usize].state.waiter {
            self.armed_timers.entry(*o).or_default().arm();
        }
        Some((op_slot, self.ops[op_slot as usize].generation))
    }

    /// Verify `(tag, slot, generation)` still names the in-flight op it was minted against and, if so, mark it
    /// retracted and stage its `ASYNC_CANCEL`. The one spelling of asked-for cancellation, shared by a timer's
    /// retraction, an `Allow` guard's firing, an answered open retiring its guard, and a failed guard stage cancelling
    /// its open. The mark routes the coming `ECANCELED` away from teardown's vocabulary ([`FsDone::was_refused`]), and
    /// is checked before it is set, so a second ask neither re-marks nor re-stages. `false` for a stale generation, a
    /// reissued slot, a tag mismatch, or an entry already marked.
    ///
    /// **`true` reports the mark, not the staging.** The cancel is best-effort ([`FsCore::submit_cancel`]) and can lose
    /// its race, so `on_cqe` reads the mark, not the errno, to decide whether a completion answers an ask. Nothing may
    /// take `true` to mean an `ASYNC_CANCEL` reached the kernel.
    pub(super) fn retract_op(&mut self, eng: &mut Engine, tag: u8, op_slot: u32, generation: u64) -> bool {
        let Some(entry) = self.ops.get_mut(op_slot as usize) else {
            return false;
        };
        if entry.generation != generation || entry.state.state != (FsOpState::InFlight { tag }) {
            return false;
        }
        if entry.state.retracted {
            return false;
        }
        entry.state.retracted = true;
        self.submit_cancel(eng, pack_raw(tag, op_slot, generation as u32));
        true
    }

    /// Verify `Timer`'s three fields against this table and, when they still name a live timer, mark the entry
    /// retracted and stage the `ASYNC_CANCEL` ([`FsCore::retract_op`]). Anything else - a foreign reactor's token, a
    /// slot reissued since, an op that is not a timer, a timer retracted once already (the headroom went back the first
    /// time; `Timer` is `Copy`) - is inert.
    pub(crate) fn retract_timeout(&mut self, eng: &mut Engine, core: u64, slot: u32, generation: u64) {
        if core != self.core_id {
            return;
        }
        if !self.retract_op(eng, TAG_TIMEOUT, slot, generation) {
            return;
        }
        // The owner's cap headroom returns at the retraction, not at the CQE, so retracting one deadline and arming its
        // replacement in the same delivery is not refused at the cap. The slot still frees at the timer's CQE, so the
        // count moves from `armed` to `retiring` ([`WallClock`]).
        let o = match &self.ops[slot as usize].state.waiter {
            Some(FsWaiter::Embedded { owner: Some(o), .. }) => Some(*o),
            _ => None,
        };
        if let Some(o) = o {
            if let Some(t) = self.armed_timers.get_mut(&o) {
                t.retract();
            } else {
                debug_assert!(false, "a retraction with no armed count");
            }
        }
    }

    /// Stage a metadata op that targets an open file, as `pers`. The file was permission-checked at open, and the fd is
    /// the capability. `off` is the truncate length or the fallocate offset, `len64` the fallocate length, and `aux32`
    /// the fallocate mode or the xattr flags.
    ///
    /// Fail-closed on `pers == 0`, as an fd op under the ring owner's ambient root credentials is a privilege this
    /// surface never grants implicitly. The sanctioned ambient-root paths are [`FsCore::submit_fgetxattr_as_root`],
    /// [`FsCore::submit_reopen_proc_as_root`], and for writes the [`PrivilegedXattrs`] allowlist below. **The allowlist
    /// is the only place a write is promoted, keyed on the attribute name alone**, so no public entry point can name a
    /// personality of 0 or pick its own privilege.
    #[allow(clippy::too_many_arguments)] // an inject unpacked, not an API
    pub(crate) fn submit_fd_meta(
        &mut self,
        eng: &mut Engine,
        tag: u8,
        pers: u16,
        file: Arc<OwnedFd>,
        name: Option<Cow<'static, CStr>>,
        value: Vec<u8>,
        off: u64,
        len64: u64,
        aux32: u32,
        waiter: FsWaiter,
    ) {
        if pers == 0 {
            self.refuse(eng, waiter, Errno::EINVAL, true, vec![value], Some(file));
            return;
        }
        // An allowlisted attribute is metadata the *server* owns, which the request identity has no privilege to write
        // (the `trusted.` namespace is CAP_SYS_ADMIN-gated). Everything else keeps `pers`, including every non-xattr
        // fd-op and every unlisted name.
        let pers = match (tag, name.as_deref()) {
            (TAG_FSETXATTR, Some(n)) if self.priv_xattrs.permits(n) => 0,
            _ => pers,
        };
        self.stage_fd_meta(eng, tag, pers, file, name, value, off, len64, aux32, waiter);
    }

    /// Read xattr `name` from `file` under the reactor's **ambient root** (`sqe.personality = 0`), the sanctioned `pers
    /// = 0` read, for a `trusted.*`/`security.*` attribute a request's own identity cannot read. `FGETXATTR` on the
    /// descriptor, or when `through_proc` `GETXATTR` of its path under `/proc/thread-self/fd`, which takes a file held
    /// `O_PATH`. The file system checks the ring owner either way.
    pub(crate) fn submit_fgetxattr_as_root(
        &mut self,
        eng: &mut Engine,
        file: Arc<OwnedFd>,
        name: Cow<'static, CStr>,
        value: Vec<u8>,
        through_proc: bool,
        waiter: FsWaiter,
    ) {
        let tag = if through_proc { TAG_GETXATTR_PROC } else { TAG_FGETXATTR };
        self.stage_fd_meta(eng, tag, 0, file, Some(name), value, 0, 0, 0, waiter);
    }

    /// Stage an `OPENAT2` of the path of `file` under `/proc/thread-self/fd` as `pers`, which opens the file again with
    /// `access` ([`FsConn::reopen_proc`]). Fail-closed on `pers == 0`, as every other op on a file is. The one way to
    /// run it as the ring owner is [`FsCore::submit_reopen_proc_as_root`].
    pub(crate) fn submit_reopen_proc(
        &mut self,
        eng: &mut Engine,
        pers: u16,
        file: Arc<OwnedFd>,
        access: ReopenAccess,
        waiter: FsWaiter,
    ) {
        if pers == 0 {
            self.refuse(eng, waiter, Errno::EINVAL, true, Vec::new(), Some(file));
            return;
        }
        self.stage_reopen_proc(eng, pers, file, access, waiter);
    }

    /// Stage the reopen of [`FsCore::submit_reopen_proc`] under the ring owner's ambient (root) credentials,
    /// `personality = 0` ([`FsConn::reopen_proc_as_root`]).
    pub(crate) fn submit_reopen_proc_as_root(
        &mut self,
        eng: &mut Engine,
        file: Arc<OwnedFd>,
        access: ReopenAccess,
        waiter: FsWaiter,
    ) {
        self.stage_reopen_proc(eng, 0, file, access, waiter);
    }

    /// Stage a reopen stamping `sqe.personality = personality_raw` verbatim, as the two callers own the personality
    /// policy.
    ///
    /// An open like any other ([`TAG_OPEN`]), so its completion wraps the new descriptor and strips the guard's
    /// `O_NONBLOCK`. The path is absolute, so the dirfd is `AT_FDCWD`, and `file` is parked with the op so its number
    /// is not reused before the io-wq worker follows the link ([`park_proc_path`](FsOpEntry::park_proc_path)). The open
    /// takes `IOSQE_ASYNC`, since the inline try always fails, as `proc_pid_get_link` (`fs/proc/base.c`) answers
    /// `ECHILD` with no dentry and `io_openat2` (`io_uring/openclose.c`) sets `LOOKUP_CACHED`.
    fn stage_reopen_proc(
        &mut self,
        eng: &mut Engine,
        personality_raw: u16,
        file: Arc<OwnedFd>,
        access: ReopenAccess,
        waiter: FsWaiter,
    ) {
        let Some(op_slot) = self.pop_op() else {
            self.refuse(eng, waiter, Errno::EBUSY, true, Vec::new(), Some(file));
            return;
        };
        let (how, guarded) = access.how();
        let raw_fd = file.as_raw_fd();
        let entry = &mut self.ops[op_slot as usize];
        let gen32 = entry.generation as u32;
        let e = &mut entry.state;
        e.state = FsOpState::InFlight { tag: TAG_OPEN };
        e.waiter = Some(waiter);
        e.file = Some(file);
        let path_ptr = e.park_proc_path(raw_fd);
        e.how = Some(how);
        e.strip_nonblock = guarded;
        let how_ptr = e.how.as_ref().expect("just set") as *const RawOpenHow as u64;
        let ud = pack_raw(TAG_OPEN, op_slot, gen32);
        let staged = eng.stage(ud, |sqe| {
            sqe.opcode = IORING_OP_OPENAT2;
            sqe.fd = libc::AT_FDCWD;
            sqe.addr = path_ptr;
            sqe.off_addr2 = how_ptr;
            sqe.len = size_of::<RawOpenHow>() as u32;
            sqe.flags |= IOSQE_ASYNC;
            sqe.personality = personality_raw;
        });
        if let Err(e) = staged {
            self.fail_op(eng, op_slot, e);
        }
    }

    /// The opcode an fd-meta tag stages, or `None` for a tag with no arm.
    ///
    /// Separate from the operand match so the refusal happens **before** an op slot is taken and an SQE is filled:
    /// `fill_sqe` zeroes the slot, so a fall-through would submit `IORING_OP_NOP` (opcode 0) under the op's own
    /// `user_data`, and a NOP completes `res = 0` - `Ok(0)` to the waiter, for a write that never happened.
    fn fd_meta_opcode(tag: u8) -> Option<u8> {
        Some(match tag {
            TAG_FTRUNCATE => IORING_OP_FTRUNCATE,
            TAG_FALLOCATE => IORING_OP_FALLOCATE,
            TAG_FADVISE => IORING_OP_FADVISE,
            TAG_SPLICE => IORING_OP_SPLICE,
            TAG_FGETXATTR => IORING_OP_FGETXATTR,
            TAG_FSETXATTR => IORING_OP_FSETXATTR,
            TAG_GETXATTR_PROC => IORING_OP_GETXATTR,
            _ => return None,
        })
    }

    /// The opcode a path-op tag stages, or `None` for a tag with no arm. See
    /// [`fd_meta_opcode`](FsCore::fd_meta_opcode).
    fn path_op_opcode(tag: u8) -> Option<u8> {
        Some(match tag {
            TAG_STATX => IORING_OP_STATX,
            TAG_MKDIRAT => IORING_OP_MKDIRAT,
            TAG_UNLINKAT => IORING_OP_UNLINKAT,
            TAG_SYMLINKAT => IORING_OP_SYMLINKAT,
            TAG_RENAMEAT => IORING_OP_RENAMEAT,
            TAG_LINKAT => IORING_OP_LINKAT,
            _ => return None,
        })
    }

    /// Stage an fd-meta op stamping `sqe.personality = personality_raw` **verbatim** (no `pers == 0` guard). Internal:
    /// the callers ([`FsCore::submit_fd_meta`], [`FsCore::submit_fgetxattr_as_root`]) own the personality policy.
    #[allow(clippy::too_many_arguments)]
    fn stage_fd_meta(
        &mut self,
        eng: &mut Engine,
        tag: u8,
        personality_raw: u16,
        file: Arc<OwnedFd>,
        name: Option<Cow<'static, CStr>>,
        value: Vec<u8>,
        off: u64,
        len64: u64,
        aux32: u32,
        waiter: FsWaiter,
    ) {
        // Decide the opcode before a slot is taken (see `fd_meta_opcode`).
        let Some(opcode) = Self::fd_meta_opcode(tag) else {
            debug_assert!(false, "not an fd-meta tag {tag:#x}");
            self.refuse(eng, waiter, Errno::EINVAL, true, vec![value], Some(file));
            return;
        };
        // The length reaches the SQE as a `u32`, so an oversized one truncates rather than failing, and at 1 << 32
        // becomes zero. Each xattr tag needs its own bound.
        //
        // For FSETXATTR `value` is the attribute, bounded at `XATTR_SIZE_MAX` as `sync_fs::xattr::fsetxattr` is, so one
        // operation has one contract. A truncated length would store an empty attribute and answer `Ok`.
        //
        // For FGETXATTR `value` is the caller's output buffer, and a generous one is legal (`FsHandle::fgetxattr`), so
        // the only bound is `u32::MAX`. Past it the length truncates to zero, the kernel's size-only form, and the
        // waiter would be told it read a value it did not.
        let unrepresentable = match tag {
            TAG_FSETXATTR => value.len() > crate::sync_fs::xattr::XATTR_SIZE_MAX,
            TAG_FGETXATTR | TAG_GETXATTR_PROC => value.len() > u32::MAX as usize,
            _ => false,
        };
        if unrepresentable {
            self.refuse(eng, waiter, Errno::E2BIG, true, vec![value], Some(file));
            return;
        }
        let Some(op_slot) = self.pop_op() else {
            self.refuse(eng, waiter, Errno::EBUSY, true, vec![value], Some(file));
            return;
        };

        let raw_fd = file.as_raw_fd();
        let entry = &mut self.ops[op_slot as usize];
        let gen32 = entry.generation as u32;
        let e = &mut entry.state;
        e.state = FsOpState::InFlight { tag };
        e.waiter = Some(waiter);
        e.file = Some(file);
        e.path = name;
        // The kernel copies the path at prep, which is inside the enter that submits the SQE, so it is parked here as
        // the name is. The file parked above keeps its number from being reused meanwhile.
        let path_ptr = if tag == TAG_GETXATTR_PROC {
            e.park_proc_path(raw_fd)
        } else {
            0
        };
        // The value rides alone, with no outer `Vec`, and comes back through `FsDone::into_value` (an FGETXATTR's
        // kernel writes land in it at issue time).
        let name_ptr = e.path.as_ref().map_or(0, |n| n.as_ptr() as u64);
        let val = e.value.insert(value);
        let val_ptr = val.as_mut_ptr() as u64;
        let val_len = val.len() as u32;

        let ud = pack_raw(tag, op_slot, gen32);
        let staged = eng.stage(ud, |sqe| {
            sqe.fd = raw_fd;
            sqe.personality = personality_raw;
            sqe.opcode = opcode;
            match tag {
                TAG_FTRUNCATE => {
                    sqe.off_addr2 = off; // the new length
                }
                TAG_FALLOCATE => {
                    sqe.off_addr2 = off; // offset
                    sqe.addr = len64; // length (kernel packing)
                    sqe.len = aux32; // mode
                }
                TAG_FADVISE => {
                    sqe.off_addr2 = off; // offset
                    // Length rides in `addr`; the kernel consults `len` only when `addr` is 0, and 0 already means "to
                    // end of file".
                    sqe.addr = len64;
                    sqe.op_flags = aux32; // POSIX_FADV_* advice
                }
                TAG_SPLICE => {
                    // `sqe.fd` (set above) is the *output* - the file being written. The input rides in `splice_fd_in`,
                    // which overlays `file_index`; it is a plain descriptor, so `SPLICE_F_FD_IN_FIXED` stays clear.
                    sqe.file_index = len64 as u32; // the pipe's read end
                    sqe.off_addr2 = off; // destination offset
                    sqe.len = aux32; // bytes to move
                    // A pipe has no position: `splice_off_in` must be -1, or `do_splice` refuses it `ESPIPE`. `fd_meta`
                    // leaves `addr` holding a name pointer, so overwrite it.
                    sqe.addr = u64::MAX;
                    sqe.op_flags = SPLICE_F_MOVE;
                }
                TAG_FGETXATTR | TAG_FSETXATTR => {
                    sqe.addr = name_ptr;
                    sqe.off_addr2 = val_ptr;
                    sqe.len = val_len;
                    sqe.op_flags = aux32;
                }
                TAG_GETXATTR_PROC => {
                    sqe.addr = name_ptr;
                    sqe.off_addr2 = val_ptr;
                    sqe.addr3 = path_ptr;
                    sqe.len = val_len;
                }
                // Unreachable: `fd_meta_opcode` refused any other tag before a slot was taken. An arm added there and
                // not here would submit a real op with zeroed operands, which is what this catches in a debug build.
                _ => debug_assert!(false, "no operands for tag {tag:#x}"),
            }
        });
        if let Err(err) = staged {
            self.fail_op(eng, op_slot, err);
        }
    }

    /// Stage a path op: `STATX`, or one of the directory-entry ops. Every dirfd is a real fd from an [`Anchor`] (the
    /// kernel rejects fixed-table dirfds on all of these), and every name has already been validated as a single
    /// component by `Leaf` - except a symlink's target, which is link content and never resolved, and `STATX`'s
    /// empty-path form. `flags` becomes `sqe.op_flags` (`AT_*`/`RENAME_*`); `len_arg` becomes `sqe.len` where the op
    /// wants a scalar there (statx mask, mkdir mode) -- for rename/link `sqe.len` is the *second dirfd* instead, per
    /// the kernel's packing, and `len_arg` is unused.
    #[allow(clippy::too_many_arguments)] // an inject unpacked, not an API
    pub(crate) fn submit_path_op(
        &mut self,
        eng: &mut Engine,
        tag: u8,
        pers: u16,
        a1: Anchor,
        n1: &[u8],
        a2: Option<Anchor>,
        n2: Option<CString>,
        flags: u32,
        len_arg: u32,
        waiter: FsWaiter,
    ) {
        // See `submit_open`: personality 0 = ambient root on a name-resolving op. Fail closed.
        if pers == 0 {
            self.refuse(eng, waiter, Errno::EINVAL, true, Vec::new(), None);
            return;
        }
        // See `stage_fd_meta`: an unhandled tag would leave the zeroed SQE's opcode at 0 - `IORING_OP_NOP` - and report
        // `Ok(0)` for an op that never ran.
        let Some(opcode) = Self::path_op_opcode(tag) else {
            debug_assert!(false, "not a path-op tag {tag:#x}");
            self.refuse(eng, waiter, Errno::EINVAL, true, Vec::new(), None);
            return;
        };
        let Some(op_slot) = self.pop_op() else {
            self.refuse(eng, waiter, Errno::EBUSY, true, Vec::new(), None);
            return;
        };

        let entry = &mut self.ops[op_slot as usize];
        let gen32 = entry.generation as u32;
        let e = &mut entry.state;
        e.state = FsOpState::InFlight { tag };
        e.waiter = Some(waiter);
        let p1 = e.park_name(n1);
        e.path2 = n2;
        if tag == TAG_STATX {
            // SAFETY: `StatxRaw` is all-integer plain data; the kernel overwrites it wholesale at completion.
            e.stat = Some(Box::new(unsafe { std::mem::zeroed() }));
        }
        let dfd1 = a1.raw_fd();
        // Default the second dirfd to the first, never AT_FDCWD: a rename/link with a missing destination anchor must
        // not fall back to the process CWD (a confinement escape). The public API always supplies both.
        let dfd2 = a2.as_ref().map_or(dfd1, |a| a.raw_fd());
        e.anchor = Some(a1);
        e.anchor2 = a2;
        let p2 = e.path2.as_ref().map_or(0, |p| p.as_ptr() as u64);
        let stat_ptr = e.stat.as_mut().map_or(0, |s| std::ptr::addr_of_mut!(**s) as u64);

        let ud = pack_raw(tag, op_slot, gen32);
        let staged = eng.stage(ud, |sqe| {
            sqe.fd = dfd1;
            sqe.addr = p1;
            // `pers != 0` guaranteed at entry (fail-closed above).
            sqe.personality = pers;
            sqe.op_flags = flags;
            sqe.opcode = opcode;
            match tag {
                TAG_STATX => {
                    sqe.len = len_arg; // STATX_* mask
                    sqe.off_addr2 = stat_ptr; // kernel writes at completion
                }
                TAG_MKDIRAT => {
                    sqe.len = len_arg; // mode
                }
                TAG_UNLINKAT => {} // flags = AT_REMOVEDIR; nothing else
                TAG_SYMLINKAT => {
                    sqe.off_addr2 = p2; // link path (addr = target)
                }
                TAG_RENAMEAT | TAG_LINKAT => {
                    sqe.off_addr2 = p2; // new path
                    sqe.len = dfd2 as u32; // new dirfd (kernel packing)
                }
                // Unreachable: `path_op_opcode` refused any other tag. See the twin arm in `stage_fd_meta`.
                _ => debug_assert!(false, "no operands for tag {tag:#x}"),
            }
        });
        if let Err(err) = staged {
            self.fail_op(eng, op_slot, err);
        }
    }

    /// `LINKAT` with `AT_EMPTY_PATH`, giving the already-open `file` a name at `a2 / n2`. The only linkat form that can
    /// name an unnamed inode, so it publishes an `O_TMPFILE` create. Two kernel rules decide whether it succeeds, and
    /// both fail as `ENOENT`.
    ///
    /// - The file must have been opened `O_TMPFILE` **without `O_EXCL`**. Only the non-`O_EXCL` path sets `I_LINKABLE`
    ///   (`fs/namei.c:4084`), and `vfs_link` rejects a zero-`i_nlink` inode without it (`:4979`).
    /// - `AT_EMPTY_PATH` requires `fd_file(f)->f_cred == current_cred()` or `CAP_DAC_READ_SEARCH` (`fs/namei.c:2631`),
    ///   and io_uring takes the personality's cred as the file's `f_cred` at open, so **`pers` must carry the
    ///   credentials that opened `file`**. The check compares pointers, so ids registered from unchanged process
    ///   credentials are interchangeable, while brokered ids, each minted after a `setresuid`, are distinct even for
    ///   one uid.
    ///
    /// `IOSQE_FIXED_FILE` is never set, as `io_linkat_prep` rejects a fixed file with `-EBADF`.
    pub(crate) fn submit_linkat_file(
        &mut self,
        eng: &mut Engine,
        pers: u16,
        file: Arc<OwnedFd>,
        a2: Anchor,
        n2: CString,
        waiter: FsWaiter,
    ) {
        // Personality 0 would create the link as ambient root. Fail closed.
        if pers == 0 {
            self.refuse(eng, waiter, Errno::EINVAL, true, Vec::new(), Some(file));
            return;
        }
        let Some(op_slot) = self.pop_op() else {
            self.refuse(eng, waiter, Errno::EBUSY, true, Vec::new(), Some(file));
            return;
        };

        let entry = &mut self.ops[op_slot as usize];
        let gen32 = entry.generation as u32;
        let e = &mut entry.state;
        e.state = FsOpState::InFlight { tag: TAG_LINKAT };
        e.waiter = Some(waiter);
        // The empty source path AT_EMPTY_PATH resolves against `sqe.fd`. A literal, so the entry borrows it: nothing to
        // allocate or free.
        e.path = Some(Cow::Borrowed(c""));
        e.path2 = Some(n2);
        let old_fd = file.as_raw_fd();
        let new_dfd = a2.raw_fd();
        e.file = Some(file);
        e.anchor2 = Some(a2);
        let p1 = e.path.as_ref().expect("just set").as_ptr() as u64;
        let p2 = e.path2.as_ref().expect("just set").as_ptr() as u64;

        let ud = pack_raw(TAG_LINKAT, op_slot, gen32);
        let staged = eng.stage(ud, |sqe| {
            sqe.opcode = IORING_OP_LINKAT;
            sqe.fd = old_fd; // the open file itself, not a dirfd
            sqe.addr = p1; // ""
            sqe.off_addr2 = p2; // destination leaf
            sqe.len = new_dfd as u32; // destination dirfd (kernel packing)
            sqe.op_flags = AtFlags::AT_EMPTY_PATH.bits() as u32;
            sqe.personality = pers;
        });
        if let Err(err) = staged {
            self.fail_op(eng, op_slot, err);
        }
    }
}
