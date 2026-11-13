use super::*;

/// Set the calling process's **effective** set to exactly `caps`, inside the impersonation window, leaving permitted
/// and inheritable untouched.
///
/// Both words are written, so the high word (capabilities 32 and up, such as `CAP_BPF`) is cleared, since a root window
/// finds it full. Permitted **must not** be narrowed here, since `capset` can never restore it and the broker would
/// lose its own `CAP_SETUID` for good. It stays inert, since authorization reads effective (`cap_capable_helper`) and
/// nothing in an io_uring operation raises effective from it. The window's `setresuid(uid, uid, 0)` keeps saved-uid 0,
/// so permitted survives the drop (`cap_emulate_setxuid`) and gives this its headroom.
pub(super) fn set_effective_caps(caps: Caps) -> errno::Result<()> {
    let mut hdr = CapHeader {
        version: VERSION_3,
        pid: 0,
    };
    let mut data = [CapData::default(); 2];
    // SAFETY: capget fills two CapData words for VERSION_3.
    Errno::result(unsafe { libc::syscall(libc::SYS_capget, std::ptr::addr_of_mut!(hdr), data.as_mut_ptr()) })?;
    // `Caps` bits are kernel capability numbers, all below 32, so the mask is the low word verbatim, and the high word
    // holds none of them.
    data[0].effective = caps.bits();
    data[1].effective = 0;
    // SAFETY: capset reads the same two-word layout back.
    Errno::result(unsafe { libc::syscall(libc::SYS_capset, std::ptr::addr_of_mut!(hdr), data.as_ptr()) })?;
    Ok(())
}

// -------------------------------------------------------------------------
// The broker process
// -------------------------------------------------------------------------

/// The forked child's whole life. Never returns.
///
/// Deliberately allocation-free and panic-free in the request loop: the scratch buffers are allocated by the parent and
/// moved in, every other buffer is a fixed-size stack array, and every failure becomes an errno in the reply. Errors
/// are never logged - writing a log line inside an impersonation window would perform file I/O as the impersonated
/// user.
pub(super) fn broker_main(
    sock: RawFd,
    ring_fds: &[RawFd],
    allowed: Caps,
    root: Option<Caps>,
    req: Vec<u8>,
    groups: Vec<u32>,
    scratch: Vec<libc::gid_t>,
) -> ! {
    let nrings = tidy_child_fds(sock, ring_fds);
    // Say the layout took, before anything can be asked of it, since `dup2_or_die` exits where the parent cannot see.
    // `spawn` takes this reply before it hands back a handle.
    if reply(SOCK_FD, 0).is_err() {
        // SAFETY: `_exit` in the forked child; no destructors, no flush.
        unsafe { libc::_exit(4) }
    }
    // A panic inside request handling must not unwind past `_exit` and run the parent's `Drop` handlers / flush its
    // buffers on the shared copy-on-write image. Contain it here and exit non-zero; under `panic = "abort"` the child
    // aborts instead, which is equally safe.
    let ok = std::panic::catch_unwind(move || broker_loop(nrings, allowed, root, req, groups, scratch)).is_ok();
    // SAFETY: `_exit` never runs atexit handlers or destructors - exactly what a forked child sharing the parent's heap
    // image must do.
    unsafe { libc::_exit(if ok { 0 } else { 1 }) }
}

/// The broker's request loop, split out so a panic in it is catchable at the `_exit` boundary (see [`broker_main`]).
///
/// The three scratch buffers are allocated by the **parent** before the fork and moved in here, so the loop allocates
/// nothing, and leaving it frees nothing (see the end of the body).
fn broker_loop(
    nrings: usize,
    allowed: Caps,
    root: Option<Caps>,
    mut req: Vec<u8>,
    mut groups: Vec<u32>,
    mut scratch: Vec<libc::gid_t>,
) {
    loop {
        let n = match recv_request(SOCK_FD, &mut req) {
            Ok(0) | Err(_) => break, // parent closed, or a fatal IPC error
            Ok(n) => n,
        };
        let Req {
            op,
            ring,
            ngroups,
            uid,
            gid,
            caps,
        } = match decode_request(&req[..n], nrings, allowed, root) {
            Ok(r) => r,
            Err(errno) => {
                let _ = reply(SOCK_FD, errno);
                continue;
            }
        };
        let ring_fd = RING_FD_BASE + ring as RawFd;

        let res: i64 = match op {
            // `decode_request` already refused uid 0 without a root limit, and this says so again where the window
            // opens.
            OP_REGISTER if uid != 0 || root.is_some() => {
                decode_groups(&req[..n], ngroups, &mut groups);
                register_as(ring_fd, uid, gid, caps, &groups[..ngroups], &mut scratch)
            }
            OP_UNREGISTER => match u16::try_from(uid) {
                // The id rides in the uid field; freeing needs no creds.
                Ok(id) => match crate::uring::sys::unregister_personality(ring_fd, id) {
                    Ok(()) => 0,
                    Err(e) => -(e as i32 as i64),
                },
                Err(_) => -(libc::EINVAL as i64),
            },
            _ => -(libc::EINVAL as i64),
        };
        if reply(SOCK_FD, res).is_err() {
            break;
        }
    }
    // Dropped here, these three would be three `free()` calls on the same arena lock the raw `clone3` may have caught
    // held. Leaking them costs nothing, since `broker_main` `_exit`s next and the kernel reclaims the child's address
    // space.
    std::mem::forget(req);
    std::mem::forget(groups);
    std::mem::forget(scratch);
}

/// Renumber the child's descriptors to a fixed layout - the IPC socket at [`SOCK_FD`], ring `i` at `RING_FD_BASE + i` -
/// then close everything else it inherited. Returns the ring count.
///
/// The moves go through a scratch range first, because a source descriptor may already sit in a destination slot, and a
/// direct `dup2` would clobber a descriptor not yet copied.
fn tidy_child_fds(sock: RawFd, ring_fds: &[RawFd]) -> usize {
    let n = ring_fds.len();
    // The scratch range must sit above BOTH the highest inherited source fd AND the final target range [SOCK_FD,
    // RING_FD_BASE + n): copying down into the target must never clobber a source or a not-yet-copied ring. A fixed
    // base would collide once the daemon had opened enough fds (TLS certs, many listeners) before creating the rings.
    let max_src = ring_fds.iter().copied().fold(sock, |a, b| a.max(b));
    let scratch_base = max_src.max(RING_FD_BASE + n as RawFd) + 1;
    // SAFETY: dup2/close_range on descriptors this forked child owns. A failed dup2 would leave a wrong layout (serving
    // requests off a stray fd, or a missing ring), so `dup2_or_die` aborts the child instead.
    unsafe {
        dup2_or_die(sock, scratch_base);
        for (i, &fd) in ring_fds.iter().enumerate() {
            dup2_or_die(fd, scratch_base + 1 + i as RawFd);
        }
        // The target range now holds nothing we still need; copy down.
        dup2_or_die(scratch_base, SOCK_FD);
        for i in 0..n {
            dup2_or_die(scratch_base + 1 + i as RawFd, RING_FD_BASE + i as RawFd);
        }
        // Keep only the socket and the rings, closing fds 0 to 2 as well, where a daemon that closed stdio could have
        // let a ring (a credential capability) or the parent's end (which keeps the socket from reaching EOF) land.
        libc::syscall(libc::SYS_close_range, 0u32, (SOCK_FD - 1) as libc::c_uint, 0);
        libc::syscall(
            libc::SYS_close_range,
            (RING_FD_BASE + n as RawFd) as libc::c_uint,
            libc::c_uint::MAX,
            0,
        );
    }
    n
}

/// `dup2(from, to)` retrying `EINTR`, aborting the (forked) child on any other failure - a wrong descriptor layout must
/// never go on to serve requests.
///
/// # Safety
///
/// Runs in the forked child; `from` and `to` are descriptors it owns.
unsafe fn dup2_or_die(from: RawFd, to: RawFd) {
    loop {
        // SAFETY: dup2 on owned descriptors.
        let r = unsafe { libc::dup2(from, to) };
        if r >= 0 {
            return;
        }
        // SAFETY: errno is valid after a failed syscall.
        if unsafe { *libc::__errno_location() } == libc::EINTR {
            continue;
        }
        // SAFETY: _exit in the forked child.
        unsafe { libc::_exit(3) };
    }
}

/// **The impersonation window.** Become `uid`/`gid`/`groups`, snapshot those credentials into a personality, and
/// revert.
///
/// Every credential call is a *raw* syscall (see the module docs). Groups and gids are set while still privileged, and
/// the uid drop comes last and keeps **saved-uid 0** so the window can close again. As euid leaves 0 the kernel clears
/// the effective set, so the snapshot carries the user's authority plus only the `caps` the spawn-time policy allowed.
/// uid 0 never leaves root, so for it the window always writes the effective set to exactly `caps` and never registers
/// the broker's own credentials. Nothing else runs inside the window, no allocation, no logging, nothing that could
/// unwind.
pub(super) fn register_as(
    ring_fd: RawFd,
    uid: u32,
    gid: u32,
    caps: Caps,
    groups: &[u32],
    scratch: &mut [libc::gid_t],
) -> i64 {
    // The broker's own credentials need no transition, which is the path an unprivileged process takes, since
    // `setgroups` fails without `CAP_SETGID` even for an unchanged list. Never for uid 0, whose effective set the
    // window must write.
    // it.
    if uid != 0 && !needs_impersonation(uid, gid, groups, scratch) {
        // No transition means no setuid fixup, so the broker's own effective set would go into the snapshot untouched.
        // Granting capabilities here would hand out the daemon's own authority under another name.
        if !caps.is_empty() {
            return -(libc::EPERM as i64);
        }
        return match crate::uring::sys::register_personality(ring_fd) {
            Ok(id) => i64::from(id),
            Err(e) => -(e as i32 as i64),
        };
    }

    // The window's reasoning holds from euid 0 alone (`cap_emulate_setxuid`, `security/commoncap.c:1132-1136`). A
    // broker at another euid with `CAP_SETUID` raised would stamp its whole effective set into every personality, and
    // `revert` would escalate it into root through saved-uid 0.
    if raw_geteuid() != 0 {
        return -(libc::EPERM as i64);
    }

    // --- window opens ---
    // SAFETY: raw setgroups/setresgid/setresuid on a single-threaded process; each is checked, and every exit path
    // closes the window via `revert`.
    let rc = unsafe { libc::syscall(libc::SYS_setgroups, groups.len() as libc::size_t, groups.as_ptr()) };
    if rc < 0 {
        let e = Errno::last_raw();
        revert();
        return -(e as i64);
    }
    // Keep saved-gid unchanged (-1) so the revert can restore it.
    // SAFETY: as above.
    let rc = unsafe { libc::syscall(libc::SYS_setresgid, gid, gid, u32::MAX) };
    if rc < 0 {
        let e = Errno::last_raw();
        revert();
        return -(e as i64);
    }
    // Saved-uid stays 0: the only way back.
    // SAFETY: as above.
    let rc = unsafe { libc::syscall(libc::SYS_setresuid, uid, uid, 0) };
    if rc < 0 {
        let e = Errno::last_raw();
        revert();
        return -(e as i64);
    }

    // Fail closed. setres*id treats `(uid_t)-1` as "leave unchanged" and succeeds, so a sentinel request would leave
    // the broker fully root. Re-reading the effective ids (raw, see `raw_geteuid`) refuses that and any other no-op.
    if raw_geteuid() != uid || raw_getegid() != gid {
        revert();
        return -(libc::EINVAL as i64);
    }

    // Ordered after the euid check, so the credentials being elevated are proven to be the requested identity's. uid 0
    // always goes through here, even asking for nothing, since its effective set is still the broker's own.
    if (uid == 0 || !caps.is_empty())
        && let Err(e) = set_effective_caps(caps)
    {
        revert();
        return -(e as i32 as i64);
    }

    let out = match crate::uring::sys::register_personality(ring_fd) {
        Ok(id) => i64::from(id),
        Err(e) => -(e as i32 as i64),
    };
    // --- window closes ---
    revert();
    out
}

/// Is `groups` a different *set* from the broker's current `cur`?
///
/// `true` sends the request through the impersonation window, which is always sound, and a wrong `false` serves it
/// under the *broker's* credentials. Pure, so tests can drive it on any host.
pub(super) fn group_set_differs(cur: &[u32], groups: &[u32]) -> bool {
    if cur.len() != groups.len() {
        return true;
    }
    // Equal length plus containment is not set equality once a gid repeats (`[1, 1]` against `[1, 2]`), and the fast
    // path would register the broker's *own* credentials under the caller's name. A repeat goes through the window
    // instead.
    let repeats = |l: &[u32]| l.iter().enumerate().any(|(i, g)| l[..i].contains(g));
    if repeats(groups) || repeats(cur) {
        return true;
    }
    groups.iter().any(|g| !cur.contains(g))
}
