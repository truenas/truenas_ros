use super::*;

/// A budget that buys nothing: the pool starts at [`POOL_INITIAL`] and doubles to its demand.
const NO_BUDGET: PoolSizing = PoolSizing::UNSIZED;

/// `rounds` quiet observations, each a full idle round after the last.
fn quiet(p: &mut BufPool, t: &mut Instant, rounds: u8) {
    for _ in 0..rounds {
        *t += IDLE_ROUND;
        p.rebalance_at(*t);
    }
}

fn kernel_picks(p: &mut BufPool, bid: u16) -> bool {
    p.lend_as_the_kernel(bid)
}

/// The ids the ring currently holds posted.
fn posted_ids(p: &BufPool) -> Vec<u16> {
    (0..p.ring.entries())
        .filter(|&b| p.ring.slots[usize::from(b)] == Slot::Posted)
        .collect()
}
use crate::uring::ring::RingFd;

/// A ring the kernel accepted, or `None` where io_uring is unavailable (a container without it). Skipping is loud
/// in the caller.
fn ring() -> Option<RingFd> {
    match RingFd::setup(8) {
        Ok(r) => Some(r),
        Err(e) if crate::uring::setup_unavailable(e) => None,
        Err(e) => panic!("io_uring_setup: {e}"),
    }
}

/// A ring the kernel accepts and then releases proves the mapping page aligned, the entry count a power of two, and
/// the descriptor layout what the kernel reads.
#[test]
fn a_ring_registers_and_unregisters() {
    let Some(r) = ring() else {
        return;
    };
    let br = BufRing::new(r.raw_fd(), 0, 4, 64, 4).expect("registers");
    assert_eq!(br.entries(), 4);
    assert_eq!(br.buf_len(), 64);
    assert_eq!(br.lent(), 0, "nothing lent before an op runs");
    assert_eq!(br.free(), 4, "every buffer posted");
    drop(br); // unregisters; a leak would fail the next registration
    let again = BufRing::new(r.raw_fd(), 0, 4, 64, 4);
    assert!(again.is_ok(), "the id was freed: {again:?}");
}

/// The shortage the free count cannot see, where every free buffer is spoken for by a selecting read still in flight.
/// Answering it with no growth would re-arm the read against the same empty ring and spin.
#[test]
fn a_shortage_masked_by_armed_reads_still_grows() {
    let Some(r) = ring() else {
        return;
    };
    let mut p = BufPool::new(r.raw_fd(), 1, 64, 64, NO_BUDGET).expect("registers");
    assert_eq!(p.allocated(), POOL_INITIAL);
    assert!(p.grow(0), "nothing armed: the free buffers answer it");
    assert_eq!(p.allocated(), POOL_INITIAL, "and nothing is added");
    assert!(p.grow(u32::from(POOL_INITIAL)), "every free buffer is armed");
    assert_eq!(p.allocated(), POOL_INITIAL * 2, "so it is real, and doubles");
}

/// A buffer length the descriptor cannot carry is refused at registration.
///
/// `io_uring_buf::len` is a `u32`, and a truncated zero length would make every selecting read look like the peer
/// hanging up.
#[test]
fn a_buffer_longer_than_the_descriptor_field_is_refused() {
    let Some(r) = ring() else {
        return;
    };
    for len in [0, u32::MAX as usize + 1, 1usize << 33] {
        assert!(
            matches!(BufRing::new(r.raw_fd(), 0, 4, len, 0), Err(Errno::EINVAL)),
            "registered a {len}-byte buffer the descriptor cannot name"
        );
    }
}

/// The descriptor ring does not reach a forked child.
///
/// This mapping is `MAP_PRIVATE`, so without `MADV_DONTFORK` a fork copies in descriptors naming this process's recv
/// buffers.
#[test]
fn the_descriptor_ring_is_not_inherited() {
    let Some(r) = ring() else {
        return;
    };
    let br = BufRing::new(r.raw_fd(), 0, 4, 64, 4).expect("registers");
    let (addr, len) = (br.ring.cast::<libc::c_void>(), br.mapped);

    let mut fds = [0i32; 2];
    // SAFETY: `fds` is a valid 2-element array for `pipe` to fill.
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
    // SAFETY: the child issues three syscalls and `_exit`s - no allocation and no Rust destructor, so nothing can
    // deadlock on a lock some other thread held at the moment of the fork.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork failed");
    if pid == 0 {
        // `msync` answers `ENOMEM` for a range that is not mapped.
        let mapped = u8::from(unsafe { libc::msync(addr, len, libc::MS_ASYNC) } == 0);
        unsafe {
            libc::close(fds[0]);
            libc::write(fds[1], std::ptr::addr_of!(mapped).cast(), 1);
            libc::_exit(0)
        };
    }
    let mut got = 1u8;
    let mut st = 0;
    let n = unsafe {
        libc::close(fds[1]);
        let n = libc::read(fds[0], std::ptr::addr_of_mut!(got).cast(), 1);
        libc::close(fds[0]);
        libc::waitpid(pid, &mut st, 0);
        n
    };
    // Status first: a child that faulted never reported, and its silence would otherwise read as the assertion
    // passing.
    assert!(
        libc::WIFEXITED(st) && libc::WEXITSTATUS(st) == 0,
        "the child faulted: status {st}"
    );
    assert_eq!(n, 1, "the child reported nothing");
    assert_eq!(got, 0, "the descriptor ring reached the forked child");
}

/// An entry count no `u16` power of two can describe is refused, in **both** profiles.
///
/// `u16::next_power_of_two` panics in debug above 32768 and wraps to zero in release, the profile that ships. The
/// refusal precedes the mmap, so it needs no ring.
#[test]
fn an_entry_count_no_power_of_two_can_describe_is_refused() {
    for n in [32769u16, 65535] {
        assert!(
            matches!(BufRing::new(-1, 0, n, 64, 0), Err(Errno::EINVAL)),
            "{n} entries was not refused"
        );
    }
    // And the last count that does fit is still accepted, so the bound is the field's and not a taste one.
    let Some(r) = ring() else {
        return;
    };
    assert_eq!(
        BufRing::new(r.raw_fd(), 0, 32768, 64, 0)
            .expect("32768 entries fit a u16")
            .entries(),
        32768
    );
}

/// The kernel demands a power of two and rejects anything else, so the rounding happens here rather than surfacing
/// as `-EINVAL` from a number the caller thought was fine.
#[test]
fn an_entry_count_is_rounded_to_a_power_of_two() {
    let Some(r) = ring() else {
        return;
    };
    let br = BufRing::new(r.raw_fd(), 1, 5, 32, 1).expect("registers");
    assert_eq!(br.entries(), 8, "5 rounded up, not refused");
}

/// Entries are descriptors and buffers are allocated behind them, so a ring registered for many can start holding
/// few. This is what makes the entry count a free ceiling rather than a commitment.
#[test]
fn a_ring_holds_fewer_buffers_than_it_has_entries() {
    let Some(r) = ring() else {
        return;
    };
    let mut br = BufRing::new(r.raw_fd(), 0, 64, 128, 2).expect("registers");
    assert_eq!(br.entries(), 64, "room for 64");
    assert_eq!(br.allocated(), 2, "but only 2 allocated");
    assert!(br.addr_of(0).is_some(), "id 0 is backed");
    assert!(br.addr_of(2).is_none(), "id 2 is not");
}

/// Raising the target allocates and posts; every id stays distinct, so no two ops can be handed the same storage.
#[test]
fn growing_posts_distinct_buffers() {
    let Some(r) = ring() else {
        return;
    };
    let mut br = BufRing::new(r.raw_fd(), 0, 8, 64, 2).expect("registers");
    br.set_target(6);
    assert_eq!(br.allocated(), 6);
    let mut seen: Vec<*mut u8> = (0..6).map(|b| br.addr_of(b).expect("backed")).collect();
    seen.sort_unstable();
    seen.dedup();
    assert_eq!(seen.len(), 6, "six ids, six distinct allocations");
}

/// A lend/release round trip returns the buffer to the ring rather than consuming it, so a steady workload cycles
/// the same storage.
#[test]
fn a_released_buffer_returns_to_the_ring() {
    let Some(r) = ring() else {
        return;
    };
    let mut br = BufRing::new(r.raw_fd(), 0, 4, 64, 4).expect("registers");
    let before = br.addr_of(1).expect("backed");
    br.lend(1);
    assert_eq!(br.lent(), 1);
    assert_eq!(br.free(), 3, "one fewer available");
    br.release(1);
    assert_eq!(br.lent(), 0);
    assert_eq!(br.free(), 4, "back in the ring");
    assert_eq!(br.addr_of(1), Some(before), "same storage, not a new one");
}

/// A post never stores to the published tail. Entry zero's `resv` is the tail, so this posts into descriptor slot
/// zero and reads the tail back before committing, where a whole-struct descriptor write shows as a rewound tail.
#[test]
fn a_post_never_touches_the_published_tail() {
    let Some(r) = ring() else {
        return;
    };
    let mut br = BufRing::new(r.raw_fd(), 0, 4, 64, 3).expect("registers");
    let tail_cell =
        |br: &BufRing| unsafe { (*(&raw const (*br.ring).resv).cast::<AtomicU16>()).load(Ordering::Acquire) };
    assert_eq!(tail_cell(&br), 3, "three posts published at setup");
    // Take two ids out of the ring (target below allocated).
    br.set_target(1);
    br.lend(0);
    br.release(0); // kept out of the ring, since allocated >= target
    br.lend(1);
    br.release(1);
    assert_eq!(br.allocated(), 1);
    // Advance the tail to the wrap: this post lands in slot 3.
    assert!(br.post(0), "repost id 0 into slot 3");
    br.commit();
    assert_eq!(tail_cell(&br), 4);
    // The post under test: tail 4 & mask 3 = descriptor slot zero, where the descriptor overlays the tail cell.
    assert!(br.post(1), "repost id 1 into slot 0");
    assert_eq!(
        tail_cell(&br),
        4,
        "a post into slot zero stored over the published tail"
    );
    br.commit();
    assert_eq!(tail_cell(&br), 5, "commit alone advances it");
}

/// A second release of the same id is refused before it can re-post a buffer another op still owns, or wrap the
/// loan count.
///
/// Only a debug build reaches this, through the `debug_assert`. `releasing_one_id_twice_is_refused_without_asserts`
/// covers the `if` that ships.
#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "releasing a buffer nobody took")]
fn releasing_one_id_twice_is_refused() {
    let Some(r) = ring() else {
        panic!("releasing a buffer nobody took: skipped, no io_uring");
    };
    let mut br = BufRing::new(r.raw_fd(), 0, 4, 64, 4).expect("registers");
    br.lend(1);
    br.release(1);
    assert_eq!(br.free(), 4, "the first release landed");
    br.release(1); // the second owner
}

/// A bid the table never posted is refused, and nothing moves. It is a descriptor desync reachable without a bug on
/// this side, so it must not abort the reactor in any build.
#[test]
fn a_bid_never_posted_is_refused_without_an_abort() {
    let Some(r) = ring() else {
        return;
    };
    let mut br = BufRing::new(r.raw_fd(), 0, 8, 64, 4).expect("registers");
    let before = (br.free(), br.lent(), br.allocated());
    assert_eq!(br.take_lent(7), None, "an absent id is refused");
    assert_eq!(br.take_lent(200), None, "an out-of-range id is refused");
    assert_eq!(
        (br.free(), br.lent(), br.allocated()),
        before,
        "and the refusals moved nothing"
    );
}

/// A bid that is already lent is the same desync with a worse consequence: the storage belongs to another op, so a
/// second loan would hand two consumers one buffer. Refused, with the first loan left standing.
#[test]
fn a_bid_already_lent_is_refused_not_reserved() {
    let Some(r) = ring() else {
        return;
    };
    let mut br = BufRing::new(r.raw_fd(), 0, 4, 64, 4).expect("registers");
    assert!(br.take_lent(1).is_some(), "a posted id lends");
    let before = (br.free(), br.lent(), br.allocated());
    assert_eq!(br.take_lent(1), None, "a second pick of it is refused");
    assert_eq!(
        (br.free(), br.lent(), br.allocated()),
        before,
        "and the first loan stands"
    );
}

/// The shipping half of the same refusal: with `debug_assertions` off the `if` is the whole guard, and what it must
/// do is nothing.
///
/// A fall-through would post one buffer twice, handing it to two ops at once, and wrap `lent` from zero.
#[cfg(not(debug_assertions))]
#[test]
fn releasing_one_id_twice_is_refused_without_asserts() {
    let Some(r) = ring() else {
        return;
    };
    let mut br = BufRing::new(r.raw_fd(), 0, 4, 64, 4).expect("registers");
    br.lend(1);
    br.release(1);
    assert_eq!(br.free(), 4, "the first release landed");
    let (free, lent, allocated) = (br.free(), br.lent(), br.allocated());
    br.release(1); // the second owner
    assert_eq!(br.free(), free, "a refused release posted nothing");
    assert_eq!(br.lent(), lent, "and retired no loan");
    assert_eq!(br.allocated(), allocated, "and allocated nothing");
}

/// A release naming an id the ring has no slot for: a userspace/kernel descriptor desync, refused before it can
/// index out of the table.
///
/// The `debug_assert` fires first, so this reaches only the debug half and only in a debug build.
/// `releasing_an_id_outside_the_ring_is_refused_without_asserts` covers the `return` that ships beside it.
#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "buffer id outside the ring")]
fn releasing_an_id_outside_the_ring_is_refused() {
    let Some(r) = ring() else {
        panic!("buffer id outside the ring: skipped, no io_uring");
    };
    let mut br = BufRing::new(r.raw_fd(), 0, 4, 64, 4).expect("registers");
    br.release(200);
}

/// The shipping half. With `debug_assertions` off the `let else` is the whole guard and must retire no loan, since a
/// wrapped `lent` reads as a nearly empty pool.
#[cfg(not(debug_assertions))]
#[test]
fn releasing_an_id_outside_the_ring_is_refused_without_asserts() {
    let Some(r) = ring() else {
        return;
    };
    let mut br = BufRing::new(r.raw_fd(), 0, 4, 64, 4).expect("registers");
    br.lend(1);
    let before = (br.free(), br.lent(), br.allocated());
    br.release(200);
    assert_eq!(
        (br.free(), br.lent(), br.allocated()),
        before,
        "an out-of-range release moved nothing"
    );
}

/// The steady-state path allocates nothing.
///
/// A buffer cycling lend -> release -> re-post keeps its storage. Counted rather than compared, since an allocator
/// handed back a block of the same size usually returns the one it just took.
#[test]
fn cycling_a_buffer_allocates_nothing() {
    let Some(r) = ring() else {
        return;
    };
    let mut br = BufRing::new(r.raw_fd(), 0, 4, 64, 4).expect("registers");
    assert_eq!(br.allocs, 4, "one per buffer at registration");
    for _ in 0..32 {
        br.lend(1);
        br.release(1);
    }
    assert_eq!(br.allocs, 4, "32 cycles reached the allocator not once");
    assert_eq!(br.allocated(), 4, "and the pool is unchanged");
}

/// The mirror: over target, the release leaves the ring and keeps its storage, so a later growth reaches for it
/// before the allocator. Together with the test above this pins exactly when the allocator is reached.
#[test]
fn a_release_over_target_keeps_the_storage_unposted() {
    let Some(r) = ring() else {
        return;
    };
    let mut br = BufRing::new(r.raw_fd(), 0, 4, 64, 4).expect("registers");
    br.lend(2);
    assert!(br.bufs[2].is_some());
    br.set_target(1);
    br.release(2);
    assert!(br.bufs[2].is_some(), "surplus storage kept");
    assert_eq!(br.slots[2], Slot::Absent, "and out of the ring");
    assert_eq!(br.allocated(), 3, "not counted as held");
    let allocs = br.allocs;
    br.set_target(4);
    assert_eq!(br.slots[2], Slot::Posted, "growth posts it again");
    assert_eq!(br.allocs, allocs, "without reaching the allocator");
    br.set_target(1);
    br.trim();
    assert!(br.bufs[2].is_some(), "a posted id is never trimmed");
}

/// Shrinking cannot take a buffer away from an op that holds it. The target falls, but the storage survives the
/// release and goes only when trimmed.
#[test]
fn a_lent_buffer_survives_a_shrink() {
    let Some(r) = ring() else {
        return;
    };
    let mut br = BufRing::new(r.raw_fd(), 0, 8, 64, 8).expect("registers");
    br.lend(3);
    let held = br.addr_of(3).expect("backed");
    br.set_target(1);
    assert_eq!(
        br.addr_of(3),
        Some(held),
        "a lent buffer is still there to be written into"
    );
    assert_eq!(br.lent(), 1);
    // Only on release does it leave, because only then is the kernel done - and it leaves the ring, not the
    // allocator.
    br.release(3);
    assert_eq!(br.lent(), 0);
    assert_eq!(br.slots[3], Slot::Absent, "out of the ring once back");
    assert_eq!(br.addr_of(3), Some(held), "storage kept for a regrowth");
    br.trim();
    assert!(br.addr_of(3).is_none(), "and gone only when trimmed");
}

/// Over-target buffers are given up as they come back, one release at a time, and the ring settles at the target
/// rather than below it.
#[test]
fn releases_drain_down_to_the_target() {
    let Some(r) = ring() else {
        return;
    };
    let mut br = BufRing::new(r.raw_fd(), 0, 8, 64, 6).expect("registers");
    for bid in 0..6 {
        br.lend(bid);
    }
    assert_eq!(br.allocated(), 6);
    br.set_target(2);
    for bid in 0..6 {
        br.release(bid);
    }
    assert_eq!(br.allocated(), 2, "settled at the target");
    assert_eq!(br.free(), 2, "and both are posted");
    assert_eq!(br.lent(), 0);
}

/// Covering demand survives the power-of-two rounding: the round-up only adds slots, and the kernel cap is itself a
/// power of two.
#[test]
fn ring_entries_covers_demand_up_to_the_kernel_cap() {
    assert_eq!(ring_entries(0), 1);
    assert_eq!(ring_entries(512), 512);
    assert_eq!(ring_entries(513).next_power_of_two(), 1024);
    assert_eq!(ring_entries(100_000), MAX_RING_ENTRIES);
    assert_eq!(MAX_RING_ENTRIES.next_power_of_two(), MAX_RING_ENTRIES);
}

/// The pool doubles on shortage rather than stepping, because the shortage says it is under its working set and a
/// per-buffer step would need one `-ENOBUFS` round trip each to get there.
#[test]
fn a_pool_doubles_when_it_runs_dry() {
    let Some(r) = ring() else {
        return;
    };
    let mut p = BufPool::new(r.raw_fd(), 0, 64, 64, NO_BUDGET).expect("registers");
    let start = p.allocated();
    // Dry means dry: every buffer lent. A shortage with buffers free is stale - already answered by an earlier
    // doubling - and grows nothing.
    for b in 0..start {
        assert!(kernel_picks(&mut p, b), "lend {b}");
    }
    assert!(p.grow(0), "room to grow");
    assert_eq!(p.allocated(), start * 2, "doubled");
}

/// The ceiling is not exhaustion while anything is free.
///
/// A `false` from `grow()` demotes the connection to owned buffers for its life, so at the ceiling it is reserved for
/// a pool with every buffer lent.
#[test]
fn the_ceiling_is_not_exhaustion_while_anything_is_free() {
    let Some(r) = ring() else {
        return;
    };
    let mut p = BufPool::new(r.raw_fd(), 0, 64, 4, NO_BUDGET).expect("registers");
    assert_eq!(p.allocated(), 4, "born at the ceiling");
    assert!(p.grow(0), "free buffers at the ceiling answer a shortage");
    assert_eq!(p.allocated(), 4, "without growing past it");
    for b in 0..4 {
        assert!(p.take_lent(b).is_some(), "lend {b}");
    }
    assert!(!p.grow(0), "everything lent and nowhere to grow is exhaustion");
    p.release(0);
    assert!(p.grow(0), "one freed buffer answers the next shortage");
}

/// One burst grows the pool once, not once per queued completion.
///
/// A burst queues several `-ENOBUFS` completions into one CQE batch and each lands in `grow()`. Without the free check
/// the rest would double a pool that already grew, 2^N for one batch.
#[test]
fn a_batch_of_shortages_doubles_once() {
    let Some(r) = ring() else {
        return;
    };
    let mut p = BufPool::new(r.raw_fd(), 0, 64, 4096, NO_BUDGET).expect("registers");
    let start = p.allocated();
    for b in 0..start {
        assert!(kernel_picks(&mut p, b), "lend {b}");
    }
    assert!(p.grow(0), "a genuine shortage grows");
    let after = p.allocated();
    assert_eq!(after, start * 2, "one doubling");
    for i in 0..16 {
        assert!(p.grow(0), "queued completion {i} finds the answer");
    }
    assert_eq!(p.allocated(), after, "the rest of the batch rode the first doubling");
}

/// Shrinking waits for several consecutive idle rounds. A pool that lowered its sights the moment it went quiet
/// would spend a bursty workload allocating and freeing.
#[test]
fn a_pool_shrinks_only_after_staying_idle() {
    let Some(r) = ring() else {
        return;
    };
    let mut p = BufPool::new(r.raw_fd(), 0, 64, 64, NO_BUDGET).expect("registers");
    p.grow(0);
    p.grow(0);
    let grown = p.target();
    assert!(grown > 1);
    let mut t = Instant::now();
    for round in 0..SHRINK_AFTER - 1 {
        quiet(&mut p, &mut t, 1);
        assert_eq!(p.target(), grown, "still aiming high at round {round}");
    }
    quiet(&mut p, &mut t, 1);
    assert!(p.target() < grown, "lowered after the quiet spell");
}

/// Observations that arrive within one round count as one: a batch of completions re-arms several connections back
/// to back, and four such arms are not four quiet spells.
#[test]
fn a_burst_of_observations_within_a_round_counts_once() {
    let Some(r) = ring() else {
        return;
    };
    let mut p = BufPool::new(r.raw_fd(), 0, 64, 64, NO_BUDGET).expect("registers");
    p.grow(0);
    p.grow(0);
    let grown = p.target();
    let mut t = Instant::now() + IDLE_ROUND;
    for _ in 0..SHRINK_AFTER * 4 {
        p.rebalance_at(t);
    }
    assert_eq!(p.target(), grown, "one round, however often it asked");
    quiet(&mut p, &mut t, SHRINK_AFTER);
    assert!(p.target() < grown, "paced rounds still shrink it");
}

/// Lowering the target does not free anything by itself - a posted descriptor cannot be retracted from the kernel -
/// so the surplus goes back as each buffer completes a cycle. This is what makes a pool that quietens down return
/// its memory, and why one that goes silent outright keeps it.
#[test]
fn surplus_is_given_up_as_buffers_cycle() {
    let Some(r) = ring() else {
        return;
    };
    let mut p = BufPool::new(r.raw_fd(), 0, 64, 64, NO_BUDGET).expect("registers");
    p.grow(0);
    p.grow(0);
    let grown = p.allocated();
    quiet(&mut p, &mut Instant::now(), SHRINK_AFTER);
    assert!(p.target() < grown, "aiming lower");
    assert_eq!(p.allocated(), grown, "but still holding it all");
    // One cycle per buffer is what hands the surplus back.
    for bid in 0..grown {
        assert!(p.take_lent(bid).is_some(), "a posted id lends");
        p.release(bid);
    }
    assert_eq!(p.allocated(), p.target(), "settled where it was aiming");
    assert!(p.allocated() < grown, "and that is fewer than before");
}

/// A pool that shrinks and then grows again posts what it kept: the allocator is reached once per buffer for the
/// pool's whole life unless a second quiet spell trims the surplus first.
#[test]
fn a_shrink_and_a_regrowth_reach_the_allocator_not_once() {
    let Some(r) = ring() else {
        return;
    };
    let mut p = BufPool::new(r.raw_fd(), 0, 64, 64, NO_BUDGET).expect("registers");
    p.grow(0);
    p.grow(0);
    let grown = p.allocated();
    let allocs = p.ring.allocs;
    quiet(&mut p, &mut Instant::now(), SHRINK_AFTER);
    for bid in 0..grown {
        assert!(p.take_lent(bid).is_some(), "a posted id lends");
        p.release(bid);
    }
    assert!(p.allocated() < grown, "the surplus left the ring");
    let kept = p.ring.bufs.iter().filter(|b| b.is_some()).count();
    assert_eq!(kept, usize::from(grown), "and kept its storage");
    // Every one of them lent: the shortage that grows the pool back.
    for bid in posted_ids(&p) {
        assert!(kernel_picks(&mut p, bid), "a posted id lends");
    }
    assert!(p.grow(0), "a dry ring grows");
    assert_eq!(p.allocated(), grown, "back to where it was");
    assert_eq!(p.ring.allocs, allocs, "with nothing newly allocated");
}

/// Storage a shrink left behind goes at the next shrink, not before: two quiet spells in a row are what say the
/// surplus is not wanted.
#[test]
fn a_second_quiet_spell_trims_what_the_first_kept() {
    let Some(r) = ring() else {
        return;
    };
    let mut p = BufPool::new(r.raw_fd(), 0, 64, 64, NO_BUDGET).expect("registers");
    p.grow(0);
    p.grow(0);
    let grown = p.allocated();
    let mut t = Instant::now();
    quiet(&mut p, &mut t, SHRINK_AFTER);
    for bid in 0..grown {
        assert!(p.take_lent(bid).is_some(), "a posted id lends");
        p.release(bid);
    }
    let held = |p: &BufPool| p.ring.bufs.iter().filter(|b| b.is_some()).count();
    assert_eq!(held(&p), usize::from(grown), "kept through the first");
    // The cycle's loans are activity, seen by the next observation.
    quiet(&mut p, &mut t, 1);
    quiet(&mut p, &mut t, SHRINK_AFTER - 1);
    assert_eq!(held(&p), usize::from(grown), "and until the second lands");
    quiet(&mut p, &mut t, 1);
    assert_eq!(
        held(&p),
        usize::from(p.allocated()),
        "then only what the ring holds is backed"
    );
}

/// The observation is the peak since the last one: a loan taken and returned between two observations still counts
/// as activity, which is what the arm sites see on every request.
#[test]
fn a_loan_returned_before_the_observation_still_counts() {
    let Some(r) = ring() else {
        return;
    };
    let mut p = BufPool::new(r.raw_fd(), 0, 64, 64, NO_BUDGET).expect("registers");
    p.grow(0);
    let grown = p.target();
    let mut t = Instant::now();
    for _ in 0..SHRINK_AFTER * 3 {
        assert!(p.take_lent(0).is_some(), "a posted id lends");
        p.release(0);
        t += IDLE_ROUND;
        p.rebalance_at(t);
    }
    assert_eq!(p.target(), grown, "never lowered between requests");
}

/// Activity resets the count, so a pool that is busy every so often never reaches the shrink threshold.
#[test]
fn activity_resets_the_idle_count() {
    let Some(r) = ring() else {
        return;
    };
    let mut p = BufPool::new(r.raw_fd(), 0, 64, 64, NO_BUDGET).expect("registers");
    p.grow(0);
    let grown = p.target();
    let mut t = Instant::now();
    for _ in 0..SHRINK_AFTER * 3 {
        quiet(&mut p, &mut t, SHRINK_AFTER - 1);
        // One buffer in use is enough to count as busy.
        assert!(p.take_lent(0).is_some(), "a posted id lends");
        t += IDLE_ROUND;
        p.rebalance_at(t);
        p.release(0);
    }
    assert_eq!(p.target(), grown, "never lowered while it was working");
}

/// A shortage while the target sits *below* what is allocated still grows.
///
/// A pool that goes quiet and then busy can hold more than its target with every buffer lent. Doubling from the target
/// would add nothing and report failure, which demotes the connection to owned buffers for good.
#[test]
fn a_shortage_below_a_shrunk_target_still_grows() {
    let Some(r) = ring() else {
        return;
    };
    let Ok(mut p) = BufPool::new(r.raw_fd(), 5, 64, 64, NO_BUDGET) else {
        return;
    };
    // Idle it down first: the target falls, and the surplus is given up only in `release`, so nothing posted cycles
    // and the pool goes on holding what it had.
    quiet(&mut p, &mut Instant::now(), SHRINK_AFTER);
    let allocated = p.allocated();
    assert!(
        p.target() < allocated,
        "the fixture needs a target under what is held: {} vs {allocated}",
        p.target()
    );

    // Then hand every one of them out, which is what a shortage means.
    let held: Vec<u16> = (0..allocated).filter(|&b| kernel_picks(&mut p, b)).collect();
    assert_eq!(held.len(), allocated as usize, "the fixture has to lend them all");

    assert!(p.grow(0), "a dry ring holding {allocated} buffers reported no growth");
    assert!(
        p.allocated() > allocated,
        "and added none: {} vs {allocated}",
        p.allocated()
    );
}

/// A pool starts with what its budget buys, between the floor and the ring - a budget past what a `u16` counts
/// clamped, not wrapped.
#[test]
fn a_pool_starts_with_its_byte_budget() {
    const BUF: usize = 64;
    const ROOMY: u16 = 1024;
    const TIGHT: u16 = 32;
    const BOUGHT: u16 = 100;
    const UNDER_FLOOR: usize = POOL_INITIAL as usize - 1;
    // One more buffer than a `u16` counts, which a cast wraps to zero.
    const PAST_U16: usize = u16::MAX as usize + 1;
    let Some(r) = ring() else {
        return;
    };
    for (entries, budget, want) in [
        (ROOMY, usize::from(BOUGHT) * BUF, BOUGHT),
        (ROOMY, UNDER_FLOOR * BUF, POOL_INITIAL),
        (ROOMY, NO_BUDGET.initial_bytes, POOL_INITIAL),
        (TIGHT, usize::from(BOUGHT) * BUF, TIGHT),
        (TIGHT, PAST_U16 * BUF, TIGHT),
    ] {
        let sizing = PoolSizing {
            initial_bytes: budget,
            ..NO_BUDGET
        };
        let p = BufPool::new(r.raw_fd(), 0, BUF, entries, sizing).expect("registers");
        assert_eq!(
            (p.allocated(), p.free()),
            (want, want),
            "{budget} bytes into {entries} entries"
        );
    }
}

/// A loan that leaves a quarter free doubles the pool, so past its starting budget it holds at most 8/3 of its peak
/// loans, and loans taken one at a time never find it dry below its limit.
#[test]
fn a_pool_grows_before_it_runs_dry() {
    let Some(r) = ring() else {
        return;
    };
    let mut p = BufPool::new(r.raw_fd(), 0, 64, 1024, NO_BUDGET).expect("registers");
    let start = p.allocated();
    // The loan that leaves a quarter free, counted from zero.
    let last = start - start / 4 - 1;
    for b in 0..last {
        assert!(p.take_lent(b).is_some(), "lend {b}");
    }
    assert_eq!(p.allocated(), start, "over a quarter free: nothing added");
    assert!(p.take_lent(last).is_some(), "the next loan");
    assert_eq!(p.allocated(), start * 2, "a quarter free: doubled");

    while p.allocated() < p.limit {
        let bid = posted_ids(&p)[0];
        assert!(p.take_lent(bid).is_some(), "lend {bid}");
        let (lent, held) = (u32::from(p.lent()), u32::from(p.allocated()));
        assert!(p.free() > 0, "{lent} lent ran the ring dry at {held}");
        assert!(3 * held <= 8 * lent, "{held} held for {lent} lent");
    }
}

/// Growth stops at the demand, not at the ring's power-of-two size.
#[test]
fn a_pool_grows_to_its_demand_and_no_further() {
    const DEMAND: u16 = 40;
    let Some(r) = ring() else {
        return;
    };
    let mut p = BufPool::new(r.raw_fd(), 0, 64, DEMAND, NO_BUDGET).expect("registers");
    assert!(p.ring.entries() > DEMAND, "the ring rounds {DEMAND} up");
    while p.free() > 0 {
        let bid = posted_ids(&p)[0];
        assert!(p.take_lent(bid).is_some(), "lend {bid}");
        assert!(
            p.allocated() <= DEMAND,
            "grew to {} past a demand of {DEMAND}",
            p.allocated()
        );
    }
    assert_eq!(p.allocated(), DEMAND, "every buffer lent, at the demand");
    assert!(!p.grow(0), "a shortage at the demand is not growth's to fix");
    assert_eq!(p.allocated(), DEMAND);
}

/// A step doubles the pool, adding at most `max_step_bytes`.
#[test]
fn a_growth_step_is_capped() {
    const BUF: usize = 64;
    const STEP: u16 = 16;
    const UNTIL: u16 = 64;
    let Some(r) = ring() else {
        return;
    };
    let sizing = PoolSizing {
        max_step_bytes: usize::from(STEP) * BUF,
        ..NO_BUDGET
    };
    let mut p = BufPool::new(r.raw_fd(), 0, BUF, 1024, sizing).expect("registers");
    let mut held = p.allocated();
    assert!(held < STEP, "the first step must double");
    while p.allocated() < UNTIL {
        let bid = posted_ids(&p)[0];
        assert!(p.take_lent(bid).is_some(), "lend {bid}");
        let now = p.allocated();
        if now != held {
            assert_eq!(now, held + held.min(STEP), "a step from {held}");
            held = now;
        }
    }
}

/// A byte cap below the demand is the pool's limit.
#[test]
fn a_pool_stays_under_its_byte_cap() {
    const BUF: usize = 64;
    const CAP: u16 = 20;
    let Some(r) = ring() else {
        return;
    };
    let sizing = PoolSizing {
        max_bytes: Some(usize::from(CAP) * BUF),
        ..NO_BUDGET
    };
    let mut p = BufPool::new(r.raw_fd(), 0, BUF, 1024, sizing).expect("registers");
    while p.free() > 0 {
        let bid = posted_ids(&p)[0];
        assert!(p.take_lent(bid).is_some(), "lend {bid}");
        assert!(p.allocated() <= CAP, "grew to {}", p.allocated());
    }
    assert_eq!(p.allocated(), CAP, "every buffer lent, at the cap");
    assert!(!p.grow(0), "a shortage at the cap is not growth's to fix");
}

/// The pool always keeps at least one buffer: dropping to zero would mean every recv came back `-ENOBUFS` with
/// nothing to grow from.
#[test]
fn a_pool_keeps_a_last_buffer() {
    let Some(r) = ring() else {
        return;
    };
    let mut p = BufPool::new(r.raw_fd(), 0, 64, 64, NO_BUDGET).expect("registers");
    quiet(&mut p, &mut Instant::now(), SHRINK_AFTER * 8);
    assert!(p.target() >= 1, "never aims at nothing");
    assert!(p.free() >= 1, "and what it keeps is available");
}
