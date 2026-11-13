use super::*;

// --- M3: the credential broker ---------------------------------------------

/// The broker forks, so it must be created before the harness starts threads. These tests each build their own reactor
/// rather than using `with_fs`, and run the loop on a scoped thread while the test thread drives registration (the
/// reverse of the other tests, because `UringFs` is `!Send` but `CredBroker`/`CredHandle` are `Send`).
/// Dropping the broker must leave no zombie behind.
///
/// `clone3_fork(0, 0, ..)` gives the child `exit_signal == 0`, which makes it a "clone child": `eligible_child`
/// (`kernel/exit.c:1163`) tests `(p->exit_signal != SIGCHLD) ^ !!(wo->wo_flags & __WCLONE)`, so a plain `waitpid`
/// answers `-1 ECHILD` at once and the task stays `Z` for the host process's life. Nothing else reaps it either - no
/// `SIGCHLD` is delivered to hang a handler off - so this leaks one task per broker.
#[test]
fn dropping_the_broker_leaves_no_zombie() {
    let afs = match UringFs::new(test_cfg()) {
        Ok(a) => a,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("UringFs::new: {e}"),
    };
    let broker = match CredBroker::spawn(&[&afs]) {
        Ok(b) => b,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("CredBroker::spawn: {e}"),
    };
    let pid = broker.pid();
    assert!(broker.is_alive(), "the broker should be running");
    drop(broker); // SIGKILL via the pidfd, then the reap

    // A successful reap releases the task, so `/proc/<pid>` is gone the moment `Drop` returns. The poll is for the
    // failing shape: a `waitpid` that answered ECHILD returns just as fast, and the child needs a moment to finish
    // dying before it reads `Z`.
    let deadline = std::time::Instant::now() + Duration::from_millis(500);
    // Loops while `/proc/<pid>` still exists; a read error is the reap.
    while let Ok(last) = std::fs::read_to_string(format!("/proc/{pid}/status")) {
        assert!(
            std::time::Instant::now() < deadline,
            "broker pid {pid} outlived its drop ({}): the reap needs \
             __WALL, since exit_signal == 0 makes plain waitpid answer \
             ECHILD and nothing else collects the task",
            last.lines()
                .find(|l| l.starts_with("State:"))
                .unwrap_or("no State line")
        );
        thread::sleep(Duration::from_millis(10));
    }
}

/// [`with_broker_caps`] with a root limit too, through `CredBroker::spawn_with_root`.
fn with_broker_root<F>(allowed: Caps, root: Caps, client: F)
where
    F: FnOnce(&FsHandle, &CredHandle, Personality, &Path) + Send,
{
    with_broker_policy(allowed, Some(root), client)
}

/// The identity a test can actually register: root impersonates anyone, an unprivileged runner can only ask for what it
/// already holds - *including* its supplementary groups. Naming uid/gid alone would request an empty group list, and
/// dropping a group is itself a privileged change, so the broker's `setgroups` would fail with `EPERM`.
fn registerable_user() -> AsUser {
    if is_root() {
        // Carry two supplementary groups: the callers that exercise set normalization need something to shuffle, and an
        // empty list would leave that check dead whenever the suite runs privileged.
        return AsUser::new(NOBODY_UID, NOBODY_GID).groups(vec![NOBODY_GID, 65_533]);
    }
    // SAFETY: these cannot fail.
    let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
    // SAFETY: a zero count asks for the length instead of writing.
    let n = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    assert!(n >= 0, "getgroups count");
    let mut groups = vec![0 as libc::gid_t; n as usize];
    // SAFETY: the destination holds the `n` entries just counted.
    let n = unsafe { libc::getgroups(n, groups.as_mut_ptr()) };
    assert!(n >= 0, "getgroups");
    groups.truncate(n as usize);
    AsUser::new(uid, gid).groups(groups)
}

#[test]
fn broker_registers_own_identity_unprivileged() {
    // Registering credentials identical to the broker's needs no privilege at all, so this leg runs everywhere and
    // covers the IPC round trip: socketpair framing, the inherited ring fd, and a real op under the resulting id.
    with_broker(|h, creds, _me, dir| {
        if is_root() {
            // Root's own identity is refused by policy; covered below.
            return;
        }
        let who = registerable_user();
        let id = creds.register(&who).expect("brokered self-registration");

        std::fs::write(dir.join("f"), b"brokered").unwrap();
        let anchor = Anchor::open(dir).unwrap();
        let f = h.open(id, &anchor, "f", rdonly()).expect("open as self");
        let (n, buf) = pread1(h, id, &f, vec![0u8; 16], 0);
        assert_eq!(&buf[..n.unwrap()], b"brokered");
        h.close(f).unwrap();
        creds.unregister(id).expect("unregister");
    });
}

#[test]
fn broker_refuses_uid_zero() {
    with_broker(|_h, creds, _me, _dir| {
        // With no root limit fixed at spawn, uid 0 is refused outright. A root personality carrying the daemon's
        // capabilities is the exact thing the broker exists to prevent.
        assert!(matches!(creds.register(&AsUser::new(0, 0)), Err(Error::Validation(_))));
    });
}

#[test]
fn group_list_beyond_the_cap_is_rejected_not_truncated() {
    with_broker(|_h, creds, _me, _dir| {
        // Distinct ids: repeating one gid would collapse under the set normalization and no longer exceed the cap.
        let over: Vec<u32> = (0..=truenas_ros::uring_fs::MAX_GROUPS)
            .map(|i| 400_000 + i as u32)
            .collect();
        let who = AsUser::new(NOBODY_UID, NOBODY_GID).groups(over);
        // Truncating would silently change what the identity may do, so an over-long list must fail loudly instead.
        assert!(matches!(creds.register(&who), Err(Error::Validation(_))));
    });
}

#[test]
fn impersonated_open_obeys_dac() {
    if !root_or_skip("impersonated_open_obeys_dac") {
        return; // cross-uid impersonation needs CAP_SETUID
    }
    with_broker(|h, creds, me, dir| {
        // A root-owned 0600 file, and a world-readable one beside it.
        std::fs::write(dir.join("secret"), b"root only").unwrap();
        std::fs::set_permissions(dir.join("secret"), std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(dir.join("public"), b"everyone").unwrap();
        std::fs::set_permissions(dir.join("public"), std::fs::Permissions::from_mode(0o644)).unwrap();
        let anchor = Anchor::open(dir).unwrap();

        let user = creds
            .register(&AsUser::new(NOBODY_UID, NOBODY_GID))
            .expect("register nobody");

        // The daemon (root) can read the secret...
        let f = h.open(me, &anchor, "secret", rdonly()).expect("root open");
        h.close(f).unwrap();

        // ...the impersonated user cannot. This is the whole design in one assertion: the kernel refused, under
        // credentials the daemon itself does not have.
        assert!(
            matches!(
                h.open(user, &anchor, "secret", rdonly()),
                Err(Error::Errno(Errno::EACCES))
            ),
            "impersonated open of a 0600 root file must be denied"
        );

        // A world-readable file is fine as that user.
        let f = h.open(user, &anchor, "public", rdonly()).expect("open");
        let (n, buf) = pread1(h, user, &f, vec![0u8; 16], 0);
        assert_eq!(&buf[..n.unwrap()], b"everyone");
        h.close(f).unwrap();

        creds.unregister(user).unwrap();
    });
}

#[test]
fn impersonated_personality_holds_no_dac_override() {
    if !root_or_skip("impersonated_personality_holds_no_dac_override") {
        return;
    }
    with_broker(|h, creds, _me, dir| {
        // A directory the user cannot even traverse.
        std::fs::create_dir(dir.join("vault")).unwrap();
        std::fs::write(dir.join("vault/inner"), b"x").unwrap();
        std::fs::set_permissions(dir.join("vault"), std::fs::Permissions::from_mode(0o700)).unwrap();
        let anchor = Anchor::open(dir).unwrap();
        let user = creds.register(&AsUser::new(NOBODY_UID, NOBODY_GID)).unwrap();

        // CAP_DAC_OVERRIDE would sail through both of these. The snapshot must not carry it: dropping euid to a
        // non-root uid clears the effective capability set, which is the property being pinned.
        assert!(matches!(
            h.open(user, &anchor, "vault/inner", rdonly()),
            Err(Error::Errno(Errno::EACCES))
        ));
        assert!(matches!(
            h.statx(user, &anchor, leaf("vault"), AtFlags::empty(), StatxMask::BASIC_STATS)
                .map(|st| st.is_dir()),
            Ok(true)
        ));
        let sub = Anchor::open(dir.join("vault").as_path()).unwrap();
        assert!(matches!(
            h.statx(user, &sub, leaf("inner"), AtFlags::empty(), StatxMask::BASIC_STATS),
            Err(Error::Errno(Errno::EACCES))
        ));
        creds.unregister(user).unwrap();
    });
}

#[test]
fn impersonated_create_is_owned_by_the_user() {
    if !root_or_skip("impersonated_create_is_owned_by_the_user") {
        return;
    }
    with_broker(|h, creds, _me, dir| {
        let anchor = Anchor::open(dir).unwrap();
        let user = creds.register(&AsUser::new(NOBODY_UID, NOBODY_GID)).unwrap();

        // O_CREAT under the personality: the file belongs to the user, not to the (root) daemon that actually issued
        // the syscall.
        let f = h.open(user, &anchor, "theirs", creat_rw()).expect("create");
        let (n, _b) = h.pwritev2(user, &f, vec![b"mine".to_vec()], 0, RwFlags::empty());
        assert_eq!(n.unwrap(), 4);
        h.close(f).unwrap();
        let md = std::fs::metadata(dir.join("theirs")).unwrap();
        assert_eq!(md.uid(), NOBODY_UID, "created as the impersonated user");
        assert_eq!(md.gid(), NOBODY_GID);

        // Directory entries too: mkdir and unlink run as the user.
        h.mkdirat(user, &anchor, leaf("theirdir"), Mode::from_bits_truncate(0o755))
            .expect("mkdirat");
        assert_eq!(std::fs::metadata(dir.join("theirdir")).unwrap().uid(), NOBODY_UID);
        h.unlinkat(user, &anchor, leaf("theirs")).expect("unlinkat");
        assert!(!dir.join("theirs").exists());
        creds.unregister(user).unwrap();
    });
}

#[test]
fn impersonated_trusted_xattr_is_denied() {
    if !root_or_skip("impersonated_trusted_xattr_is_denied") {
        return;
    }
    with_broker(|h, creds, me, dir| {
        let anchor = Anchor::open(dir).unwrap();
        let f = h.open(me, &anchor, "attr", creat_rw()).unwrap();
        let user = creds.register(&AsUser::new(NOBODY_UID, NOBODY_GID)).unwrap();

        let trusted = xattr_name("trusted.probe");
        let (res, _v) = h.fsetxattr(me, &f, trusted.clone(), b"v".to_vec(), 0);
        if matches!(res, Err(Error::Errno(Errno::EOPNOTSUPP))) {
            creds.unregister(user).unwrap();
            h.close(f).unwrap();
            return; // kernel < 6.13 (or no trusted.* support here)
        }
        res.expect("root may write trusted.*");

        // trusted.* needs CAP_SYS_ADMIN, which the personality lacks. Note the kernel's masquerade: an unprivileged
        // *read* reports ENODATA ("no such attribute"), not EPERM - it hides the attribute's existence rather than its
        // contents.
        let (res, _v) = h.fgetxattr(user, &f, trusted.clone(), vec![0u8; 16]);
        assert!(
            matches!(res, Err(Error::Errno(Errno::ENODATA))),
            "unprivileged trusted.* read must report ENODATA, got {res:?}"
        );
        let (res, _v) = h.fsetxattr(user, &f, trusted.clone(), b"z".to_vec(), 0);
        assert!(matches!(res, Err(Error::Errno(Errno::EPERM))));

        // user.* on a file the personality does not own is also refused.
        let user_attr = xattr_name("user.mine");
        let (res, _v) = h.fsetxattr(user, &f, user_attr.clone(), b"z".to_vec(), 0);
        assert!(matches!(res, Err(Error::Errno(Errno::EACCES))));

        creds.unregister(user).unwrap();
        h.close(f).unwrap();
    });
}

#[test]
fn broker_reverts_credentials_between_registrations() {
    if !root_or_skip("broker_reverts_credentials_between_registrations") {
        return;
    }
    with_broker(|h, creds, _me, dir| {
        let anchor = Anchor::open(dir).unwrap();

        // Register a low-privilege identity, then another with a different uid. If the broker failed to revert, the
        // second snapshot would inherit the first's (unprivileged) credentials and could not impersonate a different
        // user at all.
        let a = creds.register(&AsUser::new(NOBODY_UID, NOBODY_GID)).unwrap();
        let b = creds
            .register(&AsUser::new(NOBODY_UID - 1, NOBODY_GID - 1))
            .expect("second registration needs privilege back");

        let f = h.open(a, &anchor, "a", creat_rw()).unwrap();
        h.close(f).unwrap();
        let f = h.open(b, &anchor, "b", creat_rw()).unwrap();
        h.close(f).unwrap();
        assert_eq!(std::fs::metadata(dir.join("a")).unwrap().uid(), NOBODY_UID);
        assert_eq!(std::fs::metadata(dir.join("b")).unwrap().uid(), NOBODY_UID - 1);
        creds.unregister(a).unwrap();
        creds.unregister(b).unwrap();
    });
}

#[test]
fn unregistered_personality_stops_working() {
    with_broker(|h, creds, _me, dir| {
        let who = registerable_user();
        std::fs::write(dir.join("f"), b"x").unwrap();
        std::fs::set_permissions(dir.join("f"), std::fs::Permissions::from_mode(0o644)).unwrap();
        let anchor = Anchor::open(dir).unwrap();

        let id = creds.register(&who).expect("register");
        let f = h.open(id, &anchor, "f", rdonly()).expect("works while live");
        h.close(f).unwrap();

        creds.unregister(id).expect("unregister");
        // The id is gone: the kernel refuses the SQE outright rather than falling back to the submitter's (root)
        // credentials.
        assert!(matches!(
            h.open(id, &anchor, "f", rdonly()),
            Err(Error::Errno(Errno::EINVAL))
        ));
    });
}

// --- M3: the identity cache (register once per *identity*, not per connection)

#[test]
fn identity_cache_registers_once_per_identity() {
    with_broker(|h, creds, _me, dir| {
        let cache = IdentityCache::new(creds.clone());
        let who = registerable_user();

        // Many "connections" for one identity -> one registration.
        let leases: Vec<_> = (0..8).map(|_| cache.acquire(&who).expect("acquire")).collect();
        assert_eq!(cache.len(), 1, "one cached identity");
        let id = leases[0].personality();
        assert!(
            leases.iter().all(|l| l.personality() == id),
            "every lease shares the personality"
        );

        // Group order and duplicates are not semantically meaningful, so an equivalent list must hit the same entry
        // rather than mint another.
        if !who.group_list().is_empty() {
            let mut shuffled = who.group_list().to_vec();
            shuffled.reverse();
            shuffled.push(shuffled[0]);
            let same = AsUser::new(who.uid, who.gid).groups(shuffled);
            let l = cache.acquire(&same).expect("acquire equivalent");
            assert_eq!(l.personality(), id, "set-equal identity is the same");
            assert_eq!(cache.len(), 1);
        }

        // The id works while leased.
        let anchor = Anchor::open(dir).unwrap();
        let f = h.open(id, &anchor, "c", creat_rw()).expect("open");
        h.close(f).unwrap();

        // Every lease is gone, but the cache map holds the last reference -- so the id survives and the next acquire
        // reuses it rather than paying for a fresh registration.
        drop(leases);
        let held = cache.acquire(&who).expect("re-acquire");
        assert_eq!(held.personality(), id, "still the same registration");
        let f = h.open(id, &anchor, "d", creat_rw()).expect("still live");
        h.close(f).unwrap();

        // The last lease *and* the cache entry must both go before the kernel id is retired.
        cache.invalidate(&who);
        drop(held);
        assert!(matches!(
            h.open(id, &anchor, "e", creat_rw()),
            Err(Error::Errno(Errno::EINVAL))
        ));
    });
}

#[test]
fn identity_cache_invalidation_reregisters_without_disturbing_leases() {
    with_broker(|h, creds, _me, dir| {
        let cache = IdentityCache::new(creds.clone());
        let who = registerable_user();
        let anchor = Anchor::open(dir).unwrap();

        let old = cache.acquire(&who).expect("acquire");
        let old_id = old.personality();

        // A directory-services change: forget the snapshot. Work already under way must not be disturbed - this is the
        // property that lets re-registration happen while requests are in flight.
        cache.invalidate(&who);
        assert_eq!(cache.len(), 0);
        let f = h.open(old_id, &anchor, "old", creat_rw()).expect("old lives");
        h.close(f).unwrap();

        // The next acquire mints a *fresh* personality.
        let new = cache.acquire(&who).expect("re-acquire");
        assert_ne!(new.personality(), old_id, "re-registered under a new id");
        let f = h
            .open(new.personality(), &anchor, "new", creat_rw())
            .expect("new works");
        h.close(f).unwrap();

        // Retiring the old lease does not disturb the new registration.
        drop(old);
        assert!(matches!(
            h.open(old_id, &anchor, "gone", creat_rw()),
            Err(Error::Errno(Errno::EINVAL))
        ));
        let f = h
            .open(new.personality(), &anchor, "still", creat_rw())
            .expect("new still works");
        h.close(f).unwrap();
    });
}

#[test]
fn identity_cache_is_concurrency_safe() {
    with_broker(|_h, creds, _me, _dir| {
        let cache = IdentityCache::new(creds.clone());
        let who = registerable_user();
        // A connection burst for one identity collapses to one registration rather than stampeding the broker.
        let ids: Vec<Personality> = thread::scope(|s| {
            let handles: Vec<_> = (0..8)
                .map(|_| {
                    let cache = cache.clone();
                    let who = who.clone();
                    s.spawn(move || {
                        let l = cache.acquire(&who).expect("acquire");
                        l.personality()
                    })
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });
        assert!(
            ids.windows(2).all(|w| w[0] == w[1]),
            "all threads saw one personality: {ids:?}"
        );
        assert_eq!(cache.len(), 1);
    });
}

#[test]
fn large_ad_group_list_round_trips() {
    // winbindd imposes no small ceiling (Samba grows its buffer and retries), and an AD Kerberos PAC carries on the
    // order of 1000 group SIDs, so the wire format and the impersonation window must handle a list of that size - not
    // just the handful a POSIX user has.
    if !root_or_skip("large_ad_group_list_round_trips") {
        return; // setgroups with a foreign list needs CAP_SETGID
    }
    with_broker(|h, creds, _me, dir| {
        for n in [256usize, 1024, truenas_ros::uring_fs::MAX_GROUPS] {
            let groups: Vec<u32> = (0..n as u32).map(|i| 200_000 + i).collect();
            // One of them is the group that will own the file, proving the supplementary list actually reached the
            // kernel intact rather than being truncated somewhere in the middle.
            let marker = 200_000 + (n as u32 - 1);
            let who = AsUser::new(NOBODY_UID, NOBODY_GID).groups(groups.clone());
            assert_eq!(who.group_list().len(), n, "list preserved");

            let id = creds
                .register(&who)
                .unwrap_or_else(|e| panic!("register with {n} groups: {e}"));

            // A directory only that last group may enter: reaching the file proves the tail of the list survived.
            let dirname = format!("g{n}");
            std::fs::create_dir(dir.join(&dirname)).unwrap();
            std::fs::write(dir.join(&dirname).join("f"), b"deep").unwrap();
            // SAFETY: valid path; chown to root:marker, mode 0710 - only a member of `marker` can traverse it.
            let cpath = CString::new(dir.join(&dirname).as_os_str().as_bytes()).unwrap();
            assert_eq!(unsafe { libc::chown(cpath.as_ptr(), 0, marker) }, 0, "chown");
            std::fs::set_permissions(dir.join(&dirname), std::fs::Permissions::from_mode(0o710)).unwrap();

            let sub = Anchor::open(dir.join(&dirname).as_path()).unwrap();
            let f = h
                .open(id, &sub, "f", rdonly())
                .unwrap_or_else(|e| panic!("group {marker} (entry {} of {n}) lost: {e}", n - 1));
            let (got, buf) = pread1(h, id, &f, vec![0u8; 8], 0);
            assert_eq!(&buf[..got.unwrap()], b"deep");
            h.close(f).unwrap();
            creds.unregister(id).unwrap();
        }
    });
}

// --- Security regressions -------------------------------------------------

#[test]
fn personality_zero_is_not_constructible() {
    // `sqe.personality == 0` means "no credential override" - an op stamped with it runs as the reactor thread (the
    // root daemon), bypassing the whole per-op identity model. The public constructor must refuse 0 so that path is
    // unreachable, as the module docs claim.
    assert!(Personality::from_raw(0).is_none());
    assert_eq!(Personality::from_raw(1).map(|p| p.id()), Some(1));
    assert_eq!(Personality::from_raw(4242).map(|p| p.id()), Some(4242));
}

#[test]
fn sentinel_uid_gid_are_refused_by_the_api() {
    // `(uid_t)-1`/`(gid_t)-1` are the kernel's "leave unchanged" sentinel for setres*id: a broker that passed them
    // straight through would no-op the privilege drop and snapshot its own root creds. The API must reject them before
    // they reach the impersonation window.
    with_broker(|_h, creds, _me, _dir| {
        assert!(matches!(
            creds.register(&AsUser::new(u32::MAX, 1000)),
            Err(Error::Validation(_))
        ));
        assert!(matches!(
            creds.register(&AsUser::new(1000, u32::MAX)),
            Err(Error::Validation(_))
        ));
    });
}

// ---- capability-carrying personalities -------------------------------------

const CAP_NOBODY_UID: u32 = 65_534;
const CAP_NOBODY_GID: u32 = 65_534;

/// The traversal problem this capability exists for: an object the identity is entitled to, under a directory it cannot
/// search. Without the capability the walk stops at `vault/`; with it the kernel resolves through and the read
/// succeeds.
///
/// The second assertion is the uncomfortable half, and it is here on purpose: `CAP_DAC_READ_SEARCH` is not
/// traverse-only. It reads the file too, and no narrower capability exists (`CAP_DAC_OVERRIDE` and
/// `CAP_DAC_READ_SEARCH` are the only two DAC bypasses Linux defines). Anyone loosening this should have to change a
/// test that says so.
#[test]
fn dac_read_search_traverses_a_directory_the_identity_cannot_search() {
    if !root_or_skip("dac_read_search_traverses_a_directory_the_identity_cannot_search") {
        return;
    }
    with_broker_caps(Caps::DAC_READ_SEARCH, |h, creds, _me, dir| {
        std::fs::create_dir(dir.join("vault")).unwrap();
        std::fs::write(dir.join("vault/inner"), b"secret").unwrap();
        std::fs::set_permissions(dir.join("vault"), std::fs::Permissions::from_mode(0o700)).unwrap();
        // Unreadable to the identity in its own right, so the successful read below is the capability's doing and not
        // the mode's.
        std::fs::set_permissions(dir.join("vault/inner"), std::fs::Permissions::from_mode(0o600)).unwrap();
        let anchor = Anchor::open(dir).unwrap();
        let plain = AsUser::new(CAP_NOBODY_UID, CAP_NOBODY_GID);
        let privileged = plain.clone().caps(Caps::DAC_READ_SEARCH);

        let bare = creds.register(&plain).unwrap();
        assert!(
            matches!(
                h.open(bare, &anchor, "vault/inner", rdonly()),
                Err(Error::Errno(Errno::EACCES))
            ),
            "without the capability the 0700 directory still blocks the walk"
        );

        let elevated = creds.register(&privileged).unwrap();
        let f = h
            .open(elevated, &anchor, "vault/inner", rdonly())
            .expect("DAC_READ_SEARCH should traverse the 0700 directory");
        let (n, buf) = pread1(h, elevated, &f, vec![0u8; 6], 0);
        assert_eq!(n.expect("read"), 6);
        assert_eq!(&buf[..6], b"secret", "and it reads the file, too");
        h.close(f).unwrap();

        creds.unregister(bare).unwrap();
        creds.unregister(elevated).unwrap();
    });
}

/// `CAP_DAC_READ_SEARCH` grants a *pure* read and nothing wider: `fs/namei.c` tests `mask == MAY_READ` with exact
/// equality, so adding a write bit drops out of the grant entirely. `O_RDONLY` succeeds on a file `O_RDWR` cannot even
/// open - asymmetric enough to be worth pinning.
#[test]
fn dac_read_search_grants_o_rdonly_but_not_o_rdwr() {
    if !root_or_skip("dac_read_search_grants_o_rdonly_but_not_o_rdwr") {
        return;
    }
    with_broker_caps(Caps::DAC_READ_SEARCH, |h, creds, _me, dir| {
        std::fs::write(dir.join("locked"), b"x").unwrap();
        std::fs::set_permissions(dir.join("locked"), std::fs::Permissions::from_mode(0o000)).unwrap();
        let anchor = Anchor::open(dir).unwrap();
        let who = creds
            .register(&AsUser::new(CAP_NOBODY_UID, CAP_NOBODY_GID).caps(Caps::DAC_READ_SEARCH))
            .unwrap();

        let f = h
            .open(who, &anchor, "locked", rdonly())
            .expect("a pure read is granted");
        h.close(f).unwrap();

        assert!(
            matches!(
                h.open(who, &anchor, "locked", OpenHow::new().flags(OFlag::O_RDWR)),
                Err(Error::Errno(Errno::EACCES))
            ),
            "read|write is not `mask == MAY_READ`, so the grant does not apply"
        );

        creds.unregister(who).unwrap();
    });
}

/// The spawn-time mask is a ceiling the broker enforces, not a hint the caller may exceed. This is the property that
/// keeps a compromised main - which can already mint any non-root identity - from minting itself read access to every
/// file on the system.
#[test]
fn spawn_time_mask_is_a_ceiling_on_requested_caps() {
    if !root_or_skip("spawn_time_mask_is_a_ceiling_on_requested_caps") {
        return;
    }
    with_broker(|_h, creds, _me, _dir| {
        // `with_broker` spawns with `Caps::empty()`.
        let err = creds
            .register(&AsUser::new(CAP_NOBODY_UID, CAP_NOBODY_GID).caps(Caps::DAC_READ_SEARCH))
            .expect_err("a capability outside the ceiling must be refused");
        assert!(matches!(err, Error::Errno(Errno::EPERM)), "expected EPERM, got {err:?}");
        // The same identity without capabilities still registers.
        let ok = creds
            .register(&AsUser::new(CAP_NOBODY_UID, CAP_NOBODY_GID))
            .expect("the plain identity is unaffected");
        creds.unregister(ok).unwrap();
    });
}

/// `caps` participates in `AsUser`'s identity, so the cache mints a separate personality rather than handing back one
/// registered without them. Getting this wrong would silently serve whichever variant was requested first -- either
/// leaking a capability or withholding one, depending on the order.
#[test]
fn identity_cache_keys_on_the_capability_set() {
    if !root_or_skip("identity_cache_keys_on_the_capability_set") {
        return;
    }
    with_broker_caps(Caps::DAC_READ_SEARCH, |_h, creds, _me, _dir| {
        let cache = IdentityCache::new(creds.clone());
        let plain = AsUser::new(CAP_NOBODY_UID, CAP_NOBODY_GID);
        let privileged = plain.clone().caps(Caps::DAC_READ_SEARCH);
        assert_ne!(plain, privileged, "the capability set is part of identity");

        let a = cache.acquire(&plain).unwrap();
        let b = cache.acquire(&privileged).unwrap();
        assert_ne!(
            a.personality().id(),
            b.personality().id(),
            "distinct capability sets must not share a personality"
        );
        // And each is stable on re-acquire.
        assert_eq!(cache.acquire(&plain).unwrap().personality().id(), a.personality().id());
    });
}

/// The six capabilities a file service grants its superuser, the ones its file calls check.
const ROOT_SET: Caps = Caps::CHOWN
    .union(Caps::DAC_OVERRIDE)
    .union(Caps::DAC_READ_SEARCH)
    .union(Caps::FOWNER)
    .union(Caps::FSETID)
    .union(Caps::MKNOD);

/// A root personality carries exactly what it asked for within the root limit, and nothing of the broker's own
/// authority. Asking for nothing, uid 0 cannot open its own mode-0000 file for writing. Asking for the set, it can,
/// through `CAP_DAC_OVERRIDE`. What it creates is owned by uid 0 and the gid it asked for. It still cannot set a
/// `trusted.` xattr, which needs `CAP_SYS_ADMIN` (`xattr_permission`, `fs/xattr.c`), though the daemon's own
/// personality can.
#[test]
fn a_root_personality_carries_exactly_what_it_asked_for() {
    if !root_or_skip("a_root_personality_carries_exactly_what_it_asked_for") {
        return;
    }
    with_broker_root(Caps::empty(), ROOT_SET, |h, creds, me, dir| {
        std::fs::write(dir.join("locked"), b"x").unwrap();
        std::fs::set_permissions(dir.join("locked"), std::fs::Permissions::from_mode(0o000)).unwrap();
        let anchor = Anchor::open(dir).unwrap();
        let rdwr = || OpenHow::new().flags(OFlag::O_RDWR);

        let bare = creds.register(&AsUser::new(0, 4400)).unwrap();
        assert!(
            matches!(
                h.open(bare, &anchor, "locked", rdwr()),
                Err(Error::Errno(Errno::EACCES))
            ),
            "uid 0 with no capability is held to the mode like its owner"
        );

        let full = AsUser::new(0, 4400).groups(vec![4401]).caps(ROOT_SET);
        let full = creds.register(&full).unwrap();
        let f = h
            .open(full, &anchor, "locked", rdwr())
            .expect("CAP_DAC_OVERRIDE opens a mode-0000 file for writing");
        h.close(f).unwrap();

        let create = OpenHow::new()
            .flags(OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_RDWR)
            .mode(Mode::from_bits_truncate(0o644));
        let f = h.open(full, &anchor, "made", create).expect("create");
        let seen = h.fstatx(full, &f, AtFlags::empty(), StatxMask::BASIC_STATS).unwrap();
        assert_eq!((seen.uid(), seen.gid()), (0, 4400));

        let name = xattr_name("trusted.truenas_ros_root_test");
        let (res, _) = h.fsetxattr(me, &f, name.clone(), b"v".to_vec(), 0);
        if fd_xattr_ok("a trusted xattr set as the daemon", &res) {
            let (res, _) = h.fsetxattr(full, &f, name, b"v".to_vec(), 0);
            assert!(
                matches!(res, Err(Error::Errno(Errno::EPERM))),
                "a root personality holds no CAP_SYS_ADMIN, got {res:?}"
            );
        }
        h.close(f).unwrap();
        creds.unregister(bare).unwrap();
        creds.unregister(full).unwrap();
    });
}

/// The root limit is a ceiling for uid 0, as the other limit is for every other identity, and neither stands in for the
/// other. A root request for a capability outside the root limit is refused `EPERM`, and so is a request of another
/// identity for a capability that only the root limit holds.
#[test]
fn the_root_limit_binds_uid_0_alone() {
    if !root_or_skip("the_root_limit_binds_uid_0_alone") {
        return;
    }
    let (allowed, root) = (Caps::DAC_READ_SEARCH, Caps::DAC_OVERRIDE);
    with_broker_root(allowed, root, |_h, creds, _me, _dir| {
        let eperm = |who: &AsUser| matches!(creds.register(who), Err(Error::Errno(Errno::EPERM)));
        assert!(eperm(&AsUser::new(0, 0).caps(Caps::DAC_READ_SEARCH)));
        let nobody = AsUser::new(CAP_NOBODY_UID, CAP_NOBODY_GID);
        assert!(eperm(&nobody.clone().caps(Caps::DAC_OVERRIDE)));
        let inside = creds.register(&AsUser::new(0, 0).caps(root)).unwrap();
        let other = creds.register(&nobody.caps(allowed)).unwrap();
        creds.unregister(inside).unwrap();
        creds.unregister(other).unwrap();
    });
}

/// `Caps::ROOT_ONLY` belongs to the root limit alone. In the limit for other identities it is refused before the broker
/// forks, so the caller keeps the power to impersonate and may spawn again.
#[test]
fn root_only_capabilities_are_refused_in_the_other_limit() {
    let afs = match UringFs::new(test_cfg()) {
        Ok(a) => a,
        Err(e) if should_skip(&e) => return,
        Err(e) => panic!("UringFs::new: {e}"),
    };
    for only in [Caps::CHOWN, Caps::FSETID, Caps::MKNOD] {
        assert!(matches!(
            CredBroker::spawn_with_caps(&[&afs], only),
            Err(Error::Validation(_))
        ));
        assert!(matches!(
            CredBroker::spawn_with_root(&[&afs], only, ROOT_SET),
            Err(Error::Validation(_))
        ));
    }
}

/// Minting root narrows the broker's own effective set without leaving uid 0, so the window's revert must give it back
/// before it restores the gid and the groups, which need `CAP_SETGID`. Done in the wrong order, the broker would keep
/// the root personality's gid, groups and capabilities, and refuse the next identity. Here it impersonates nobody after
/// root, and that personality still holds nothing beyond nobody's own authority.
#[test]
fn the_broker_impersonates_again_after_minting_root() {
    if !root_or_skip("the_broker_impersonates_again_after_minting_root") {
        return;
    }
    with_broker_root(Caps::empty(), ROOT_SET, |h, creds, _me, dir| {
        std::fs::write(dir.join("secret"), b"root only").unwrap();
        std::fs::set_permissions(dir.join("secret"), std::fs::Permissions::from_mode(0o600)).unwrap();
        let anchor = Anchor::open(dir).unwrap();
        let root = AsUser::new(0, 4400).groups(vec![4401]).caps(ROOT_SET);
        let root = creds.register(&root).unwrap();
        let nobody = creds
            .register(&AsUser::new(NOBODY_UID, NOBODY_GID))
            .expect("the broker still impersonates after minting root");
        assert!(
            matches!(
                h.open(nobody, &anchor, "secret", rdonly()),
                Err(Error::Errno(Errno::EACCES))
            ),
            "nobody holds nothing of the root personality before it"
        );
        let f = h.open(root, &anchor, "secret", rdonly()).expect("root");
        h.close(f).unwrap();
        let again = creds
            .register(&AsUser::new(0, 0).caps(Caps::DAC_OVERRIDE))
            .expect("and mints root again");
        for id in [root, nobody, again] {
            creds.unregister(id).unwrap();
        }
    });
}
