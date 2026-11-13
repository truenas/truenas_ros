/// Whether a root-only test may proceed. `false` means the caller returns without asserting;
/// `TRUENAS_ROS_REQUIRE_ROOT` turns that skip into a failure where CI arms it (the QEMU job, the only place this
/// module's impersonation paths run at all).
fn root_or_skip(what: &str) -> bool {
    if super::raw_geteuid() == 0 {
        return true;
    }
    assert!(
        std::env::var_os("TRUENAS_ROS_REQUIRE_ROOT").is_none(),
        "TRUENAS_ROS_REQUIRE_ROOT is set but this process is not root: \
             {what}"
    );
    false
}

/// The pre-fork headroom check must be exactly the range `tidy_child_fds` renumbers through, and must scale with
/// the ring count - otherwise raising `MAX_RINGS` moves a `dup3` `EBADF` into the window after `CAP_SETUID` is
/// shed, where no caller can act on it.
#[test]
fn the_child_fd_high_water_scales_with_the_ring_count() {
    // Low `max_src`: the target range itself is the floor.
    assert_eq!(child_fd_high_water(3, 1), RING_FD_BASE + 1 + 1 + 1);
    // High `max_src`: scratch sits above it, one slot per ring plus the socket's own copy.
    assert_eq!(child_fd_high_water(900, 8), 900 + 1 + 8);
    assert_eq!(child_fd_high_water(900, 16), 900 + 1 + 16);
    // Doubling MAX_RINGS costs exactly MAX_RINGS more descriptors.
    assert_eq!(
        child_fd_high_water(900, MAX_RINGS) - child_fd_high_water(900, MAX_RINGS / 2),
        (MAX_RINGS / 2) as RawFd
    );
}

/// `spawn` refuses before the fork when the layout cannot fit under `RLIMIT_NOFILE`, rather than forking a child
/// that `_exit`s inside `tidy_child_fds`. Driven through the arithmetic rather than by lowering the process limit,
/// which every other test in this binary shares.
#[test]
fn a_layout_that_cannot_fit_is_refused_not_forked() {
    let soft: u64 = 64;
    // A daemon holding descriptors just under its soft limit.
    let top = child_fd_high_water(60, MAX_RINGS);
    assert!(
        u64::from(top.unsigned_abs()) >= soft,
        "{MAX_RINGS} rings over fd 60 must not fit under a soft limit of {soft}"
    );
    // The same daemon with one ring does fit, so the refusal is about the slice and a caller can retry.
    let one = child_fd_high_water(60, 1);
    assert!(
        u64::from(one.unsigned_abs()) < soft,
        "one ring over fd 60 must fit under {soft}"
    );
}

/// Both halves of the ready handshake `spawn` consults before it hands back a handle.
///
/// A child that dies renumbering never sends its ready datagram, so the parent's read is short, which is the
/// `ECONNRESET` of broker death. A live child's eight bytes read back as a reply.
#[test]
fn a_child_that_dies_before_its_ready_datagram_reads_as_broker_death() {
    use std::os::fd::AsRawFd;

    fn pair() -> (std::os::fd::OwnedFd, std::os::fd::OwnedFd) {
        let mut sv = [0 as libc::c_int; 2];
        // SAFETY: `sv` is a valid 2-element array for socketpair.
        let rc = unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                0,
                sv.as_mut_ptr(),
            )
        };
        assert_eq!(rc, 0, "socketpair: {}", super::Errno::last());
        // SAFETY: fresh owned fds from socketpair.
        unsafe { (crate::fd::owned_from_raw(sv[0]), crate::fd::owned_from_raw(sv[1])) }
    }

    let (parent, child) = pair();
    super::reply(child.as_raw_fd(), 0).expect("the child says it is up");
    assert_eq!(
        super::recv_reply(parent.as_raw_fd()),
        Ok(0),
        "a ready child hands the parent its datagram"
    );

    let (parent, child) = pair();
    drop(child); // the child exited in `tidy_child_fds`
    assert_eq!(
        super::recv_reply(parent.as_raw_fd()),
        Err(super::Errno::ECONNRESET),
        "a dead child must reach `spawn` as broker death, not as a \
             handle whose mint capabilities are already gone"
    );
}

/// A repeated gid must not buy the no-impersonation fast path.
///
/// That path registers the broker's *own* credentials, so taking it for a request whose group list only looks like the
/// current one hands the caller whatever the broker holds. Equal length plus one-way containment satisfies `[1, 1]`
/// against a current `[1, 2]` (same count, every requested gid present) while the sets differ by group 2.
#[test]
fn a_repeated_gid_does_not_take_the_no_impersonation_path() {
    assert!(
        super::group_set_differs(&[1, 2], &[1, 1]),
        "a repeat forged equality out of containment"
    );
    assert!(super::group_set_differs(&[1, 1], &[1, 2]));
    // Order is not identity.
    assert!(!super::group_set_differs(&[1, 2, 3], &[3, 1, 2]));
    assert!(!super::group_set_differs(&[], &[]));
    // Neither containment direction alone is enough.
    assert!(super::group_set_differs(&[1, 2], &[1, 3]));
    assert!(super::group_set_differs(&[1], &[1, 2]));
}

/// The fast path is taken only on genuine set equality - swept, rather than argued from the three clauses that
/// implement it. Every sequence pair over a 3-symbol alphabet up to length 3, checked against a sorted-vector
/// oracle that is deliberately not the shipped algorithm.
#[test]
fn the_group_fast_path_is_exactly_set_equality() {
    fn seqs() -> Vec<Vec<u32>> {
        let mut out = vec![vec![]];
        for _ in 0..3 {
            let mut next = Vec::new();
            for s in &out {
                for g in 1..=3u32 {
                    let mut t = s.clone();
                    t.push(g);
                    next.push(t);
                }
            }
            out.extend(next);
        }
        out
    }
    let all = seqs();
    let mut fast = 0usize;
    for cur in &all {
        for want in &all {
            // The oracle: multiset equality, which for the fast path to be sound must coincide with set equality -
            // a repeat is exactly where the two part company.
            let (mut a, mut b) = (cur.clone(), want.clone());
            a.sort_unstable();
            b.sort_unstable();
            let same_multiset = a == b;
            let differs = super::group_set_differs(cur, want);
            if !differs {
                fast += 1;
                assert!(same_multiset, "fast path on unequal sets: {cur:?} vs {want:?}");
            }
            // A repeat on either side must never be served fast, even when the multisets do match: `setgroups` is
            // what installs the list the caller asked for.
            let repeats = |l: &[u32]| l.iter().enumerate().any(|(i, g)| l[..i].contains(g));
            if repeats(cur) || repeats(want) {
                assert!(differs, "repeat took the fast path: {cur:?}");
            }
        }
    }
    assert!(fast > 0, "the sweep never reached the fast path");
}

use super::*;
use crate::uring::ring::Ring;
use std::mem::size_of;

/// The server-side fail-closed check in `register_as`: even if a caller bypassed the input guards, a `(uid_t)-1`
/// request must NOT mint a personality - the kernel no-ops the setres*id drop, so the euid post-condition rejects
/// it - and the broker must be left back at root. (Root-only: impersonation needs `CAP_SETUID`.)
#[test]
fn register_as_rejects_the_no_change_sentinel() {
    if !root_or_skip("register_as_rejects_the_no_change_sentinel") {
        return;
    }
    let ring = match Ring::new(4) {
        Ok(r) => r,
        Err(e) if crate::uring::setup_unavailable(e) => return,
        Err(e) => panic!("Ring::new: {e}"),
    };
    let mut scratch = [0 as libc::gid_t; 8];
    let out = register_as(ring.raw_fd(), u32::MAX, u32::MAX, Caps::empty(), &[], &mut scratch);
    assert!(out < 0, "sentinel uid/gid must be refused, got id {out}");
    // The window was reverted: we are root again, able to impersonate a real (non-sentinel) uid on the same ring.
    assert_eq!(raw_geteuid(), 0, "euid restored after refusal");
    let ok = register_as(ring.raw_fd(), 65534, 65534, Caps::empty(), &[], &mut scratch);
    assert!(ok > 0, "a real uid still registers after the refusal: {ok}");

    // The sentinel is refused *before* any capability is raised, so a capability request cannot smuggle one past
    // the euid post-condition.
    let out = register_as(
        ring.raw_fd(),
        u32::MAX,
        u32::MAX,
        Caps::DAC_READ_SEARCH,
        &[],
        &mut scratch,
    );
    assert!(out < 0, "sentinel plus caps must still be refused: {out}");
    assert_eq!(raw_geteuid(), 0, "euid restored after the caps refusal");
}

/// `drop_setid_caps` must clear `CAP_SETUID` and `CAP_SETGID` from the **bounding set**, or a uid-0 `execve` restores
/// them. Root-only, and in a forked child, since the drop is irreversible.
#[test]
fn drop_setid_caps_clears_the_bounding_set() {
    const CAP_SETGID: libc::c_long = 6;
    const CAP_SETUID: libc::c_long = 7;
    const PR_CAPBSET_READ: libc::c_long = 23;
    if !root_or_skip("drop_setid_caps_clears_the_bounding_set") {
        return;
    }
    // SAFETY: fork; the child only makes async-signal-safe syscalls and `_exit`s, so it is sound from a threaded
    // test harness.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork");
    if pid == 0 {
        let ok = drop_setid_caps().is_ok();
        // SAFETY: prctl with scalar arguments.
        let u = unsafe { libc::syscall(libc::SYS_prctl, PR_CAPBSET_READ, CAP_SETUID) };
        // SAFETY: prctl with scalar arguments.
        let g = unsafe { libc::syscall(libc::SYS_prctl, PR_CAPBSET_READ, CAP_SETGID) };
        // SAFETY: `_exit` in a forked child; runs no destructors.
        unsafe { libc::_exit(i32::from(!(ok && u == 0 && g == 0))) }
    }
    let mut status = 0;
    // SAFETY: valid pid and status pointer.
    unsafe { libc::waitpid(pid, &mut status, 0) };
    assert_eq!(
        libc::WEXITSTATUS(status),
        0,
        "CAP_SETUID/CAP_SETGID must be gone from the bounding set after \
             drop_setid_caps, else a uid-0 execve restores them"
    );
}

/// A root window writes the effective set itself, so it must write both words exactly. Root holds capabilities in
/// the high word too, such as `CAP_BPF` and `CAP_PERFMON`, and a high word left as read would ride into every root
/// personality. `restore_effective_caps` then gives the whole of permitted back, both words. Root-only, and in a
/// forked child, since it changes the process's capabilities. The high word of permitted must hold something, or
/// the test would prove nothing.
#[test]
fn set_effective_caps_writes_both_words_and_restore_gives_them_back() {
    if !root_or_skip("set_effective_caps_writes_both_words_and_restore_gives_them_back") {
        return;
    }
    fn read() -> Option<[CapData; 2]> {
        let mut hdr = CapHeader {
            version: VERSION_3,
            pid: 0,
        };
        let mut data = [CapData::default(); 2];
        // SAFETY: capget fills two CapData words for VERSION_3.
        let rc = unsafe { libc::syscall(libc::SYS_capget, std::ptr::addr_of_mut!(hdr), data.as_mut_ptr()) };
        (rc == 0).then_some(data)
    }
    // SAFETY: fork; the child only makes async-signal-safe syscalls and `_exit`s, so it is sound from a threaded
    // test harness.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork");
    if pid == 0 {
        let asked = Caps::CHOWN | Caps::MKNOD;
        let set = set_effective_caps(asked).is_ok();
        let narrowed =
            read().is_some_and(|d| d[0].effective == asked.bits() && d[1].effective == 0 && d[1].permitted != 0);
        let restored = restore_effective_caps().is_ok();
        let back = read().is_some_and(|d| d.iter().all(|word| word.effective == word.permitted));
        let ok = set && narrowed && restored && back;
        // SAFETY: `_exit` in a forked child; runs no destructors.
        unsafe { libc::_exit(i32::from(!ok)) }
    }
    let mut status = 0;
    // SAFETY: valid pid and status pointer.
    unsafe { libc::waitpid(pid, &mut status, 0) };
    assert_eq!(
        libc::WEXITSTATUS(status),
        0,
        "the effective set must be exactly what was asked, both words, \
             and come back whole"
    );
}

/// A root window narrows the broker's effective set without leaving uid 0, so `revert` must give it back before it
/// clears the groups, since `setgroups` needs `CAP_SETGID`. The gid would come back anyway, through saved gid 0,
/// and nothing would fail, but the broker would keep the groups of the root personality it had just minted. So the
/// broker's own credentials are read after the window, which must leave them as every window does, uid and gid 0,
/// no groups and the whole effective set. Root-only, and in a forked child, since a window changes them.
#[test]
fn a_root_window_closes_as_every_window_does() {
    if !root_or_skip("a_root_window_closes_as_every_window_does") {
        return;
    }
    let ring = match Ring::new(4) {
        Ok(r) => r,
        Err(e) if crate::uring::setup_unavailable(e) => return,
        Err(e) => panic!("Ring::new: {e}"),
    };
    fn groups(out: &mut [libc::gid_t]) -> i64 {
        // SAFETY: raw `getgroups` into `out`, its length bounding the write.
        unsafe { libc::syscall(libc::SYS_getgroups, out.len() as libc::c_long, out.as_mut_ptr()) }
    }
    // SAFETY: fork; the child only makes async-signal-safe syscalls and `_exit`s, so it is sound from a threaded
    // test harness.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork");
    if pid == 0 {
        let mut after = [0; 8];
        let mut scratch = [0 as libc::gid_t; 8];
        let caps = Caps::DAC_OVERRIDE;
        let id = register_as(ring.raw_fd(), 0, 4400, caps, &[4401], &mut scratch);
        let has = groups(&mut after);
        let mut hdr = CapHeader {
            version: VERSION_3,
            pid: 0,
        };
        let mut data = [CapData::default(); 2];
        // SAFETY: capget fills two CapData words for VERSION_3.
        let rc = unsafe { libc::syscall(libc::SYS_capget, std::ptr::addr_of_mut!(hdr), data.as_mut_ptr()) };
        let whole = rc == 0 && data.iter().all(|w| w.effective == w.permitted);
        let ok = id > 0 && raw_geteuid() == 0 && raw_getegid() == 0 && has == 0 && whole;
        // SAFETY: `_exit` in a forked child; runs no destructors.
        unsafe { libc::_exit(i32::from(!ok)) }
    }
    let mut status = 0;
    // SAFETY: valid pid and status pointer.
    unsafe { libc::waitpid(pid, &mut status, 0) };
    assert_eq!(
        libc::WEXITSTATUS(status),
        0,
        "after a root window the broker must have its own gid, groups and \
             capabilities back"
    );
}

/// A registration of uid 0 is held to the root limit alone, and refused when the broker has none, while every other
/// request is held to the limit for other identities. The id of an unregistration rides in the uid field, so an id
/// of 0 there is no root.
#[test]
fn a_registration_of_uid_0_is_held_to_the_root_limit() {
    let request = |op: u8, uid: u32, caps: Caps| {
        let mut req = [0u8; HDR_LEN];
        req[0] = op;
        req[4..8].copy_from_slice(&uid.to_le_bytes());
        req[12..16].copy_from_slice(&caps.bits().to_le_bytes());
        req
    };
    let allowed = Caps::DAC_READ_SEARCH;
    let decoded = |op, uid, caps, root| decode_request(&request(op, uid, caps), 1, allowed, root).map(|req| req.caps);
    let eperm = Err(-(libc::EPERM as i64));
    assert_eq!(decoded(OP_REGISTER, 0, Caps::empty(), None), eperm);
    let root = Some(Caps::DAC_OVERRIDE | Caps::CHOWN);
    assert_eq!(decoded(OP_REGISTER, 0, Caps::CHOWN, root), Ok(Caps::CHOWN));
    assert_eq!(decoded(OP_REGISTER, 0, allowed, root), eperm);
    assert_eq!(decoded(OP_REGISTER, 1000, Caps::CHOWN, root), eperm);
    assert_eq!(decoded(OP_REGISTER, 1000, allowed, root), Ok(allowed));
    let unregister = decoded(OP_UNREGISTER, 0, Caps::empty(), None);
    assert_eq!(unregister, Ok(Caps::empty()));
}

/// The other half of the bounding-set drop: an unprivileged caller must still get `Ok`.
///
/// `PR_CAPBSET_DROP` fails `EPERM` without `CAP_SETPCAP`, and a failure is fatal to `spawn`, so the tolerance is keyed
/// on the uid. Root-only, because it has to shed privilege to test the shed.
#[test]
fn drop_setid_caps_tolerates_an_unprivileged_caller() {
    if !root_or_skip("drop_setid_caps_tolerates_an_unprivileged_caller") {
        return;
    }
    // SAFETY: fork; the child only makes async-signal-safe syscalls and `_exit`s, so it is sound from a threaded
    // test harness.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork");
    if pid == 0 {
        // Become nobody: no CAP_SETPCAP, but a still-full bounding set.
        // SAFETY: scalar arguments; the child exits either way.
        let dropped = unsafe { libc::syscall(libc::SYS_setresuid, 65534, 65534, 65534) };
        let ok = dropped == 0 && drop_setid_caps().is_ok();
        // SAFETY: `_exit` in a forked child; runs no destructors.
        unsafe { libc::_exit(i32::from(!ok)) }
    }
    let mut status = 0;
    // SAFETY: valid pid and status pointer.
    unsafe { libc::waitpid(pid, &mut status, 0) };
    assert_eq!(
        libc::WEXITSTATUS(status),
        0,
        "an unprivileged drop_setid_caps must succeed: spawn treats a \
             failure as fatal, and a non-root reactor has nothing to regain"
    );
}

/// **SECURITY.** A recv that gives up leaves the broker's reply on the socket, and the wire carries nothing naming
/// the request it answers, so without the mark the *next* caller receives it. The control clears the mark by hand and
/// gets the previous caller's id.
#[test]
fn a_timed_out_request_refuses_the_next_caller_not_its_reply() {
    let mut sv = [0 as RawFd; 2];
    // SAFETY: valid 2-element array.
    Errno::result(unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
            sv.as_mut_ptr(),
        )
    })
    .expect("socketpair");
    // SAFETY: fresh fds from socketpair.
    let (parent, child) = unsafe { (crate::fd::owned_from_raw(sv[0]), crate::fd::owned_from_raw(sv[1])) };
    set_timeout(parent.as_raw_fd(), libc::SO_RCVTIMEO, Duration::from_millis(50)).expect("SO_RCVTIMEO");
    let mut sock = BrokerSock {
        fd: parent,
        desynced: false,
    };

    // A broker that does not answer in time - a cgroup freeze, say, which `RECV_TIMEOUT` names.
    let req = [0u8; HDR_LEN];
    let e = round_trip(&mut sock, &req).expect_err("the recv must give up");
    assert_eq!(e, Errno::EAGAIN, "SO_RCVTIMEO expiry");
    assert!(sock.desynced, "a reply is owed on this socket");

    // It thaws and replies. The request was delivered, so this is a real reply - for a caller that has gone.
    reply(child.as_raw_fd(), 7).expect("the broker answers late");

    let e = round_trip(&mut sock, &req).expect_err("desynced must refuse");
    assert_eq!(e, Errno::EPROTO, "a reply that cannot be attributed is not an answer");

    // The control: what the refusal is standing in front of.
    sock.desynced = false;
    assert_eq!(
        round_trip(&mut sock, &req).expect("the queued reply"),
        7,
        "the socket really does hand the previous caller's id over"
    );

    // The one recv failure that consumed the queue is not a desync and keeps its own errno. Driven with a reply the
    // broker could never send - a short datagram - because that reaches `recv_reply`'s length check with the peer
    // still open, where a closed peer would fail at the send instead.
    let short = [0u8; 4];
    // SAFETY: a valid 4-byte source on the child end.
    Errno::result(unsafe {
        libc::send(
            child.as_raw_fd(),
            short.as_ptr().cast::<c_void>(),
            short.len(),
            libc::MSG_NOSIGNAL,
        )
    })
    .expect("short reply");
    assert_eq!(
        round_trip(&mut sock, &req).expect_err("not eight bytes"),
        Errno::ECONNRESET,
        "broker death must keep its own vocabulary"
    );
    assert!(!sock.desynced, "a recv that consumed the queue leaves nothing stale");
}

/// Pin the kernel behaviour that shapes this whole module: an io_uring descriptor **cannot** be passed over a unix
/// socket (`scm_fp_copy` answers `EINVAL`). If this ever starts succeeding, a broker could receive rings after the
/// fork.
#[test]
fn io_uring_fd_cannot_cross_scm_rights() {
    let ring = match Ring::new(4) {
        Ok(r) => r,
        Err(e) if crate::uring::setup_unavailable(e) => return,
        Err(e) => panic!("Ring::new: {e}"),
    };
    let mut sv = [0 as RawFd; 2];
    // SAFETY: valid 2-element array.
    Errno::result(unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
            sv.as_mut_ptr(),
        )
    })
    .unwrap();
    // SAFETY: fresh fds from socketpair.
    let (a, b) = unsafe { (crate::fd::owned_from_raw(sv[0]), crate::fd::owned_from_raw(sv[1])) };

    let payload = [0u8; 4];
    let mut cmsg_buf = [0u8; 64];
    let mut iov = libc::iovec {
        iov_base: payload.as_ptr() as *mut c_void,
        iov_len: payload.len(),
    };
    // SAFETY: a zeroed msghdr is valid; every field used is set below.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr().cast::<c_void>();
    // SAFETY: CMSG_SPACE is pure arithmetic.
    msg.msg_controllen = unsafe { libc::CMSG_SPACE(size_of::<RawFd>() as u32) } as libc::size_t;
    let fd = ring.raw_fd();
    // SAFETY: the control buffer holds one SCM_RIGHTS cmsg for one fd.
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(size_of::<RawFd>() as u32) as libc::size_t;
        std::ptr::copy_nonoverlapping(
            std::ptr::addr_of!(fd).cast::<u8>(),
            libc::CMSG_DATA(cmsg),
            size_of::<RawFd>(),
        );
    }
    // SAFETY: `msg` is fully initialized and outlives the call.
    let rc = unsafe { libc::sendmsg(a.as_raw_fd(), &msg, 0) };
    assert_eq!(rc, -1, "the kernel must refuse an io_uring fd here");
    assert_eq!(Errno::last(), Errno::EINVAL, "refusal is EINVAL from scm_fp_copy");
    drop(b);
}
