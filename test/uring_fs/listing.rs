use super::*;

// ---- ordered / filtered / resumable listing --------------------------------

/// Every name a query yields, in the order it yields them.
fn list_names(h: &FsHandle, me: Personality, anchor: &Anchor, opts: QueryOptions) -> Vec<String> {
    let mut q = query_directory(h, me, anchor, opts).expect("list");
    let mut out = Vec::new();
    while let Some(batch) = q.next() {
        for e in batch.expect("batch") {
            out.push(e.name.to_string_lossy().into_owned());
        }
    }
    out
}

/// A directory sorts where its trailing separator puts it, not where its bare name does. `/` is `0x2F`, above `-`
/// (`0x2D`) and `.` (`0x2E`), so `a` belongs *between* `a.txt` and `aa.txt`. A walk that recursed in bare-name order
/// would emit everything under `a/` before `a-1.txt`, disagreeing with the order the full paths actually compare in.
#[test]
fn path_order_places_a_directory_after_its_dotted_siblings() {
    with_fs(test_cfg(), |h, me, dir, _stop| {
        std::fs::create_dir(dir.join("a")).expect("mkdir a");
        for f in ["a-1.txt", "a.txt", "aa.txt"] {
            std::fs::write(dir.join(f), b"x").expect("write");
        }
        let anchor = Anchor::open(dir.as_path()).expect("anchor");
        // `clump` below the entry count, so the sorted buffer is drained across several batches rather than served in
        // one.
        let opts = |order| QueryOptions {
            clump: 2,
            order,
            ..Default::default()
        };

        assert_eq!(
            list_names(&h, me, &anchor, opts(Order::ByPathBytes)),
            ["a-1.txt", "a.txt", "a", "aa.txt"],
        );
        // The ordering a walk must not use, asserted so the difference stays visible if either mode is ever touched.
        assert_eq!(
            list_names(&h, me, &anchor, opts(Order::ByName)),
            ["a", "a-1.txt", "a.txt", "aa.txt"],
        );
        let mut raw = list_names(&h, me, &anchor, opts(Order::Readdir));
        raw.sort();
        assert_eq!(raw, ["a", "a-1.txt", "a.txt", "aa.txt"]);
    });
}

/// `name_prefix` drops entries during the `readdir` pass, and a batch is still filled to `clump` *kept* entries - so a
/// short batch keeps meaning end-of-directory rather than "the filter ate this one".
#[test]
fn name_prefix_filters_without_shortening_batches() {
    with_fs(test_cfg(), |h, me, dir, _stop| {
        for i in 0..5 {
            std::fs::write(dir.join(format!("keep-{i}")), b"x").expect("write");
            std::fs::write(dir.join(format!("drop-{i}")), b"x").expect("write");
        }
        let anchor = Anchor::open(dir.as_path()).expect("anchor");
        let opts = QueryOptions {
            clump: 2,
            order: Order::ByName,
            name_prefix: Some(b"keep-".to_vec()),
            ..Default::default()
        };

        let mut q = query_directory(&h, me, &anchor, opts).expect("list");
        let mut sizes = Vec::new();
        let mut names = Vec::new();
        while let Some(batch) = q.next() {
            let batch = batch.expect("batch");
            sizes.push(batch.len());
            names.extend(batch.iter().map(|e| e.name.to_string_lossy().into_owned()));
        }

        assert_eq!(
            names,
            ["keep-0", "keep-1", "keep-2", "keep-3", "keep-4"],
            "only the prefixed names, in order"
        );
        // 5 kept entries at clump 2: full, full, remainder. The interleaved `drop-*` names must not have shortened
        // either full batch.
        assert_eq!(sizes, [2, 2, 1], "batches fill to clump on kept entries");
    });
}

/// `start_after` resumes an ordered listing exactly at the cut, with no key repeated and none skipped. The cursor is a
/// **literal key**, so resuming past the directory `a` means passing `a/` - where `a/` sorts - rather than `a`, where a
/// file of that name would sort.
#[test]
fn start_after_resumes_a_path_ordered_listing_without_gaps() {
    with_fs(test_cfg(), |h, me, dir, _stop| {
        std::fs::create_dir(dir.join("a")).expect("mkdir a");
        for f in ["a-1.txt", "a.txt", "aa.txt"] {
            std::fs::write(dir.join(f), b"x").expect("write");
        }
        let anchor = Anchor::open(dir.as_path()).expect("anchor");
        let page = |start_after: Option<Vec<u8>>| {
            list_names(
                &h,
                me,
                &anchor,
                QueryOptions {
                    clump: 64,
                    order: Order::ByPathBytes,
                    start_after,
                    ..Default::default()
                },
            )
        };

        let all = page(None);
        assert_eq!(all, ["a-1.txt", "a.txt", "a", "aa.txt"]);

        // Cutting after each key in turn yields exactly the remainder. The directory's key carries its separator; the
        // files' do not.
        let keys = ["a-1.txt", "a.txt", "a/", "aa.txt"];
        for (i, key) in keys.iter().enumerate() {
            assert_eq!(
                page(Some(key.as_bytes().to_vec())),
                all[i + 1..],
                "resuming after {key:?}"
            );
        }

        // The bare name `a` is *not* the directory's key: it sorts where a file `a` would, before `a-1.txt`, so nothing
        // is consumed.
        assert_eq!(page(Some(b"a".to_vec())), all);
    });
}

/// The change cookie is the exact validator for anything cached per file, so two properties have to hold: it moves when
/// the file is modified, and it does **not** move when the file is merely read. A cookie that advanced on reads would
/// invalidate every cache entry on every access.
///
/// Skips where the kernel does not hand the cookie to userspace, which is a property of the *kernel*, not the
/// filesystem. Upstream strips the bit in `cp_statx` and clears it from the request mask ("kernel-only for now",
/// fs/stat.c), while the TrueNAS fork exposes it under `CONFIG_TRUENAS`. Runs on a **ZFS dataset**, not the default
/// `tempdir`, since tmpfs carries `i_version` too (`SB_I_VERSION`, `mm/shmem.c:5375`) and a tempdir fixture would pin
/// tmpfs's cookie rather than ZFS's.
///
/// Two gates, both armed in the QEMU job: `TRUENAS_ROS_REQUIRE_ZFS` for the dataset, and
/// `TRUENAS_ROS_REQUIRE_CHANGE_COOKIE` for the kernel.
#[test]
fn change_cookie_moves_on_writes_and_not_on_reads() {
    let Some(ds) = zfs_dir_or_skip() else {
        return;
    };
    with_fs(test_cfg(), |h, me, _dir, _stop| {
        let anchor = Anchor::open(ds.as_path()).expect("anchor");
        let how = OpenHow::new()
            .flags(OFlag::O_RDWR | OFlag::O_CREAT)
            .mode(Mode::from_bits_truncate(0o600));
        let f = h.open(me, &anchor, "cookie.bin", how).expect("open");
        let mask = StatxMask::BASIC_STATS | StatxMask::CHANGE_COOKIE;
        let cookie = |f: &_| h.fstatx(me, f, AtFlags::empty(), mask).expect("fstatx").change_cookie();

        let Some(first) = cookie(&f) else {
            assert!(
                std::env::var_os("TRUENAS_ROS_REQUIRE_CHANGE_COOKIE").is_none(),
                "TRUENAS_ROS_REQUIRE_CHANGE_COOKIE is set but the dataset \
                 at {} reports none: this kernel is not exposing \
                 STATX_CHANGE_COOKIE",
                ds.display()
            );
            return;
        };

        let (n, _) = pwrite1(&h, me, &f, b"hello".to_vec(), 0);
        assert_eq!(n.expect("write"), 5);
        let after_write = cookie(&f).expect("cookie still reported");
        assert_ne!(after_write, first, "a write must move the change cookie");

        let (n, _) = pread1(&h, me, &f, vec![0u8; 5], 0);
        assert_eq!(n.expect("read"), 5);
        assert_eq!(
            cookie(&f).expect("cookie still reported"),
            after_write,
            "a read must not move the change cookie (note: a `noatime` or \
             `relatime` mount can hide a violation here)"
        );

        h.close(f).expect("close");
    });
}

/// The ring's statx gives the ZFS flags the ioctl gives, since `IORING_OP_STATX` ends in the same `cp_statx` as the
/// blocking call.
///
/// Runs on a **ZFS dataset**, and as root, since it sets a flag. Two gates are armed in the QEMU job,
/// `TRUENAS_ROS_REQUIRE_ZFS` for the dataset and `TRUENAS_ROS_REQUIRE_STATX_ZFSFLAGS` for the field.
#[test]
fn the_rings_statx_gives_the_zfs_flags() {
    use std::os::fd::{AsFd, OwnedFd};
    use truenas_ros::sync_fs::{ZfsAttr, fget_zfs_attrs, fset_zfs_attrs};

    let Some(ds) = zfs_dir_or_skip() else {
        return;
    };
    with_fs(test_cfg(), |h, me, _dir, _stop| {
        let path = ds.join(format!("rostest_zfsflags_{}", std::process::id()));
        std::fs::write(&path, b"").unwrap();
        let file = std::fs::OpenOptions::new().read(true).write(true).open(&path).unwrap();
        // The setter takes the whole mask, so the bits ZFS set at create stay.
        let attrs = fget_zfs_attrs(file.as_fd()).unwrap() | ZfsAttr::HIDDEN;
        fset_zfs_attrs(file.as_fd(), attrs).unwrap();
        let f = File::from_fd(OwnedFd::from(file));
        let st = h.fstatx(me, &f, AtFlags::empty(), StatxMask::ZFSFLAGS);
        h.close(f).expect("close");
        std::fs::remove_file(&path).unwrap();
        let st = st.expect("fstatx");
        let Some(seen) = st.zfs_attrs() else {
            assert!(
                std::env::var_os("TRUENAS_ROS_REQUIRE_STATX_ZFSFLAGS").is_none(),
                "TRUENAS_ROS_REQUIRE_STATX_ZFSFLAGS is set but the dataset at \
                 {} reports none through the ring",
                ds.display()
            );
            return;
        };
        assert_eq!(seen, attrs);
    });
}

/// The ring's statx says whether a file has a POSIX access ACL and a folder a default one, as the blocking call does,
/// since `IORING_OP_STATX` ends in the same `vfs_getattr_nosec` (`statx_posix_acls` in fs/stat.c).
///
/// Runs in the tempdir, whose POSIX ACLs `TRUENAS_ROS_REQUIRE_POSIX_ACL` demands, and
/// `TRUENAS_ROS_REQUIRE_STATX_POSIX_ACLS` turns a kernel that does not answer into a failure. Both are armed in the
/// QEMU job.
#[cfg(feature = "acl")]
#[test]
fn the_rings_statx_says_whether_a_file_has_a_posix_acl() {
    use truenas_ros::sync_fs::acl::{Acl, PosixAce, PosixAcl, PosixPerm, PosixTag, fsetacl};

    with_fs(test_cfg(), |h, me, dir, _stop| {
        std::fs::write(dir.join("plain"), b"").unwrap();
        std::fs::write(dir.join("named"), b"").unwrap();
        std::fs::create_dir(dir.join("both")).unwrap();
        let aces = |default| {
            [
                (PosixTag::UserObj, -1),
                (PosixTag::User, 4_200),
                (PosixTag::GroupObj, -1),
                (PosixTag::Mask, -1),
                (PosixTag::Other, -1),
            ]
            .map(|(tag, id)| PosixAce {
                tag,
                perms: PosixPerm::READ,
                id,
                default,
            })
        };
        let set = |name: &str, aces: Vec<PosixAce>| {
            let f = std::fs::File::open(dir.join(name)).unwrap();
            let acl = Acl::Posix(PosixAcl::from_aces(aces));
            fsetacl(&f, Some(&acl))
        };
        let both = [aces(false), aces(true)].concat();
        if let Err(e) = set("named", aces(false).to_vec()).and_then(|()| set("both", both)) {
            return xattr_probe::posix_acl_refusal_is_allowed("a POSIX ACL on the tempdir", e);
        }
        let anchor = Anchor::open(dir.as_path()).unwrap();
        let acls = |name: &str| {
            let flags = AtFlags::AT_SYMLINK_NOFOLLOW;
            let st = h.statx(me, &anchor, leaf(name), flags, StatxMask::ACL);
            let st = st.expect("statx");
            (st.posix_access_acl(), st.posix_default_acl())
        };
        if acls("plain").0.is_none() {
            assert!(
                std::env::var_os("TRUENAS_ROS_REQUIRE_STATX_POSIX_ACLS").is_none(),
                "TRUENAS_ROS_REQUIRE_STATX_POSIX_ACLS is set but the kernel \
                 does not answer STATX_ACL through the ring at {}",
                dir.display()
            );
            return;
        }
        assert_eq!(acls("plain"), (Some(false), Some(false)));
        assert_eq!(acls("named"), (Some(true), Some(false)));
        assert_eq!(acls("both"), (Some(true), Some(true)));
    });
}

/// A file opened by handle outside the ring and wrapped answers the ring's statx with the object number and generation
/// its handle carries, and a ring read gives back its bytes.
///
/// Runs on a **ZFS dataset**, since the fid layout checked is the one `zfs_fid` writes. `open_by_handle_at` needs
/// `CAP_DAC_READ_SEARCH` (`may_decode_fh`, fs/fhandle.c), so it runs only as root. Three gates are armed in the QEMU
/// job, `TRUENAS_ROS_REQUIRE_ZFS` for the dataset, `TRUENAS_ROS_REQUIRE_FHANDLE` for the open and
/// `TRUENAS_ROS_REQUIRE_STATX_GEN` for the generation.
#[cfg(feature = "fhandle")]
#[test]
fn a_file_opened_by_handle_serves_ring_ops_once_wrapped() {
    use std::os::fd::AsFd;
    use truenas_ros::sync_fs::fhandle::{FhFlags, name_to_handle_at};

    let Some(ds) = zfs_dir_or_skip() else {
        return;
    };
    with_fs(test_cfg(), |h, me, _dir, _stop| {
        let path = ds.join(format!("rostest_from_fd_{}", std::process::id()));
        std::fs::write(&path, b"by handle").unwrap();
        let handle = name_to_handle_at(truenas_ros::AT_FDCWD, &path, FhFlags::AT_HANDLE_MNT_ID_UNIQUE)
            .expect("name_to_handle_at");
        let mount = std::fs::File::open(&ds).unwrap();
        let fd = match handle.open(mount.as_fd(), OFlag::O_RDONLY) {
            Ok(fd) => fd,
            Err(Error::Errno(e @ (Errno::EPERM | Errno::EACCES | Errno::ENOSYS))) => {
                std::fs::remove_file(&path).unwrap();
                assert!(
                    std::env::var_os("TRUENAS_ROS_REQUIRE_FHANDLE").is_none(),
                    "TRUENAS_ROS_REQUIRE_FHANDLE is set but \
                     open_by_handle_at failed with {e}"
                );
                return;
            }
            Err(e) => panic!("open_by_handle_at failed with {e}"),
        };
        let f = File::from_fd(fd);
        let st = h.fstatx(me, &f, AtFlags::empty(), StatxMask::INO | StatxMask::GEN);
        let (n, buf) = pread1(&h, me, &f, vec![0u8; 9], 0);
        h.close(f).expect("close");
        std::fs::remove_file(&path).unwrap();
        let st = st.expect("fstatx");
        assert_eq!(n.expect("read"), 9);
        assert_eq!(&buf[..9], b"by handle");

        // `zfs_fid`'s short form, after the eight byte `struct file_handle` head. It is a `u16` length of ten, the
        // object number in six little endian bytes, then the generation in four with a zero remapped to one.
        let raw = handle.to_bytes();
        let fid = &raw[8..];
        assert_eq!(fid.len(), 12, "{raw:02x?}");
        let mut object = [0u8; 8];
        object[..6].copy_from_slice(&fid[2..8]);
        assert_eq!(u64::from_le_bytes(object), st.ino());
        let Some(generation) = st.generation() else {
            assert!(
                std::env::var_os("TRUENAS_ROS_REQUIRE_STATX_GEN").is_none(),
                "TRUENAS_ROS_REQUIRE_STATX_GEN is set but the dataset at {} \
                 reports none through the ring",
                ds.display()
            );
            return;
        };
        let in_handle = u32::from_le_bytes([fid[8], fid[9], fid[10], fid[11]]);
        assert_eq!(
            match generation as u32 {
                0 => 1,
                low => low,
            },
            in_handle
        );
    });
}

// ---- recursive, resumable subtree walk -------------------------------------

/// A tree whose root level exercises the `/`-vs-`.`-vs-`-` ordering trap at more than one depth, so a walk that got the
/// comparator right at one level and wrong at another still fails.
fn make_tree(dir: &Path) {
    std::fs::create_dir(dir.join("a")).unwrap();
    std::fs::create_dir(dir.join("a/c")).unwrap();
    std::fs::create_dir(dir.join("z")).unwrap();
    for f in ["a-1.txt", "a.txt", "aa.txt", "a/b.txt", "a/c/d.txt", "z/y.txt"] {
        std::fs::write(dir.join(f), b"x").unwrap();
    }
}

/// Every key the walk yields, in order, as strings.
fn walk_keys(h: &FsHandle, me: Personality, anchor: &Anchor, opts: TreeOptions) -> Vec<String> {
    let mut t = query_tree(h, me, anchor, opts).expect("query_tree");
    let mut out = Vec::new();
    while let Some(e) = t.next() {
        let e = e.expect("entry");
        out.push(String::from_utf8(e.key()).unwrap());
    }
    out
}

/// Per-directory sorting composes into global path order. Note where `a/` lands: after `a.txt` because `/` outranks
/// `.`, and its whole subtree follows immediately - `a/c/d.txt` still precedes `aa.txt`, which is the property a naive
/// bare-name sort breaks.
#[test]
fn tree_walk_emits_the_subtree_in_global_path_order() {
    with_fs(test_cfg(), |h, me, dir, _stop| {
        make_tree(&dir);
        let anchor = Anchor::open(dir.as_path()).expect("anchor");
        let keys = walk_keys(
            &h,
            me,
            &anchor,
            TreeOptions {
                entries: QueryOptions {
                    clump: 2,
                    ..Default::default()
                },
                ..Default::default()
            },
        );
        assert_eq!(
            keys,
            [
                "a-1.txt",
                "a.txt",
                "a/",
                "a/b.txt",
                "a/c/",
                "a/c/d.txt",
                "aa.txt",
                "z/",
                "z/y.txt",
            ]
        );

        // The same set, sorted independently as flat byte strings, must agree -- that is what "global path order"
        // means, and it is checked here rather than trusted from the literal above.
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted);
    });
}

/// `max_depth: 1` and `skip_descent` are the two ways to get the non-recursive listing a delimiter asks for, and they
/// must agree.
#[test]
fn depth_one_and_skip_descent_both_stop_at_the_top_level() {
    with_fs(test_cfg(), |h, me, dir, _stop| {
        make_tree(&dir);
        let anchor = Anchor::open(dir.as_path()).expect("anchor");
        let expected = ["a-1.txt", "a.txt", "a/", "aa.txt", "z/"];

        let capped = walk_keys(
            &h,
            me,
            &anchor,
            TreeOptions {
                max_depth: 1,
                ..Default::default()
            },
        );
        assert_eq!(capped, expected, "max_depth 1");

        // Pruning every directory as it is yielded reaches the same place, and is how a caller folds one into a common
        // prefix.
        let mut t = query_tree(&h, me, &anchor, TreeOptions::default()).expect("query_tree");
        let mut pruned = Vec::new();
        while let Some(e) = t.next() {
            let e = e.expect("entry");
            let is_dir = e.is_dir();
            pruned.push(String::from_utf8(e.key()).unwrap());
            if is_dir {
                t.skip_descent();
            }
        }
        assert_eq!(pruned, expected, "skip_descent on every directory");
    });
}

/// The pagination property, and the reason the cursor is key-based rather than a directory offset: paging through the
/// tree must reproduce the whole walk **exactly** - no key repeated, none skipped - including when a page boundary
/// falls on a directory, which is the case a position-based cursor gets wrong.
#[test]
fn paging_with_a_cursor_reproduces_the_walk_exactly() {
    with_fs(test_cfg(), |h, me, dir, _stop| {
        make_tree(&dir);
        let anchor = Anchor::open(dir.as_path()).expect("anchor");
        let full = walk_keys(&h, me, &anchor, TreeOptions::default());

        // Every page size from 1 up, so the boundary lands on each entry in turn - files, directories, and the last
        // entry of a level alike.
        for page in 1..=full.len() {
            let mut paged: Vec<String> = Vec::new();
            let mut resume: Option<TreeCursor> = None;
            loop {
                let mut t = query_tree(
                    &h,
                    me,
                    &anchor,
                    TreeOptions {
                        resume: resume.clone(),
                        ..Default::default()
                    },
                )
                .expect("query_tree");
                let mut n = 0;
                while n < page {
                    match t.next() {
                        Some(e) => {
                            let e = e.expect("entry");
                            paged.push(String::from_utf8(e.key()).unwrap());
                            n += 1;
                        }
                        None => break,
                    }
                }
                if n == 0 {
                    break;
                }
                resume = Some(t.cursor());
            }
            assert_eq!(paged, full, "paging {page} at a time");
        }
    });
}

/// Resuming a listing must tolerate a subtree that vanished between pages, the same way the forward walk tolerates one
/// removed mid-walk: the walk emits a directory before its contents, so a page can end on `a/c/` with the resume about
/// to re-open it. If `a/c` is gone by then, the rebuild must skip its subtree and advance to the next sibling, not fail
/// the whole listing.
#[test]
fn a_subtree_removed_between_pages_is_skipped_not_fatal() {
    with_fs(test_cfg(), |h, me, dir, _stop| {
        make_tree(&dir);
        let anchor = Anchor::open(dir.as_path()).expect("anchor");
        let full = walk_keys(&h, me, &anchor, TreeOptions::default());
        // `a/c/` is emitted before its contents, so removing it once yielded drops only `a/c/d.txt`.
        let expected: Vec<String> = full.iter().filter(|k| *k != "a/c/d.txt").cloned().collect();

        let mut paged: Vec<String> = Vec::new();
        let mut resume: Option<TreeCursor> = None;
        let mut removed = false;
        loop {
            let mut t = query_tree(
                &h,
                me,
                &anchor,
                TreeOptions {
                    resume: resume.clone(),
                    ..Default::default()
                },
            )
            .expect("query_tree resumes across the removed subtree");
            let Some(e) = t.next() else { break };
            let key = String::from_utf8(e.expect("entry").key()).unwrap();
            if key == "a/c/" && !removed {
                // The next page re-opens `a/c`; remove it first so the rebuild hits ENOENT on that level (the walk has
                // not descended into it yet - a directory is emitted before its contents).
                std::fs::remove_dir_all(dir.join("a/c")).unwrap();
                removed = true;
            }
            paged.push(key);
            resume = Some(t.cursor());
        }
        assert!(removed, "a/c/ was never yielded");
        assert_eq!(paged, expected);
    });
}

/// The other half of the restore guard: a level that fails for a reason that is *not* a subtree skip aborts the resume.
///
/// `a_subtree_removed_between_pages_is_skipped_not_fatal` pins the skip half, since EACCES, EPERM and ENOENT are levels
/// the forward walk would have skipped too. For anything else the cursor names a place the rebuild could not reach, so
/// continuing from a shallower level would hand back a short listing with no error in it.
///
/// Provoked by replacing the directory with a regular file between pages, so the rebuild's `O_DIRECTORY` open answers
/// ENOTDIR, which `is_subtree_skip` deliberately does not cover.
#[test]
fn a_level_that_became_a_file_between_pages_aborts_the_resume() {
    with_fs(test_cfg(), |h, me, dir, _stop| {
        make_tree(&dir);
        let anchor = Anchor::open(dir.as_path()).expect("anchor");

        let mut resume: Option<TreeCursor> = None;
        let mut swapped = false;
        loop {
            let opened = query_tree(
                &h,
                me,
                &anchor,
                TreeOptions {
                    resume: resume.clone(),
                    ..Default::default()
                },
            );
            if swapped {
                // The page after the swap must refuse rather than resume somewhere shallower.
                let err = match opened {
                    Ok(_) => panic!(
                        "a level the rebuild could not re-enter was resumed \
                         past, not reported"
                    ),
                    Err(e) => e,
                };
                let truenas_ros::Error::IteratorRestore { path, .. } = &err else {
                    panic!("expected IteratorRestore, got {err:?}");
                };
                assert!(
                    path.ends_with("c"),
                    "the refusal names the level it could not rebuild: \
                     {path:?}"
                );
                return;
            }
            let mut t = opened.expect("query_tree resumes");
            let Some(e) = t.next() else {
                panic!("a/c/ was never yielded");
            };
            let key = String::from_utf8(e.expect("entry").key()).unwrap();
            if key == "a/c/" {
                // The next page re-opens `a/c`. Replace it with a regular file so the rebuild's O_DIRECTORY open
                // answers ENOTDIR.
                std::fs::remove_dir_all(dir.join("a/c")).unwrap();
                std::fs::write(dir.join("a/c"), b"").unwrap();
                swapped = true;
            }
            resume = Some(t.cursor());
        }
    });
}

/// `skip_descent` and `cursor` are both documented delimiter primitives, so the obvious composition of them - fold a
/// directory into a common prefix, then page - has to work. It is the page boundary that makes it hard: the walk emits
/// a directory *before* its contents, so a cursor sitting on a folded directory is positioned at the start of the
/// subtree the caller just said to skip. Resuming there must not re-enter it, and must not re-emit the directory
/// either.
#[test]
fn a_folded_subtree_stays_folded_across_a_page_boundary() {
    with_fs(test_cfg(), |h, me, dir, _stop| {
        make_tree(&dir);
        let anchor = Anchor::open(dir.as_path()).expect("anchor");
        // What one uninterrupted walk yields when every directory is pruned.
        let expected = ["a-1.txt", "a.txt", "a/", "aa.txt", "z/"];

        for page in 1..=expected.len() {
            let mut paged: Vec<String> = Vec::new();
            let mut resume: Option<TreeCursor> = None;
            loop {
                let mut t = query_tree(
                    &h,
                    me,
                    &anchor,
                    TreeOptions {
                        resume: resume.clone(),
                        ..Default::default()
                    },
                )
                .expect("query_tree");
                let mut n = 0;
                while n < page {
                    match t.next() {
                        Some(e) => {
                            let e = e.expect("entry");
                            let is_dir = e.is_dir();
                            paged.push(String::from_utf8(e.key()).unwrap());
                            if is_dir {
                                t.skip_descent();
                            }
                            n += 1;
                        }
                        None => break,
                    }
                }
                if n == 0 {
                    break;
                }
                // Round-trip the token, since a real pager persists it.
                let blob = t.cursor().to_bytes();
                resume = Some(TreeCursor::from_bytes(&blob).expect("cursor decodes"));
            }
            assert_eq!(paged, expected, "folding every directory, {page} entries at a time");
        }
    });
}

/// A cursor survives serialization, so a listing can be resumed by a later request - or a later process - and not just
/// within one walk.
#[test]
fn a_serialized_cursor_resumes_the_walk() {
    with_fs(test_cfg(), |h, me, dir, _stop| {
        make_tree(&dir);
        let anchor = Anchor::open(dir.as_path()).expect("anchor");
        let full = walk_keys(&h, me, &anchor, TreeOptions::default());

        let mut t = query_tree(&h, me, &anchor, TreeOptions::default()).expect("query_tree");
        for _ in 0..4 {
            t.next().expect("entry").expect("ok");
        }
        let blob = t.cursor().to_bytes();
        drop(t);

        let restored = TreeCursor::from_bytes(&blob).expect("cursor decodes");
        let rest = walk_keys(
            &h,
            me,
            &anchor,
            TreeOptions {
                resume: Some(restored),
                ..Default::default()
            },
        );
        assert_eq!(rest, full[4..], "the tail of the walk, exactly once");
    });
}

/// Descent resolves one component against the descriptor the walk already holds, under `CONFINED_RESOLVE` - so a
/// symlink planted in the tree is not a way out of it, whether it points outside or back inside.
#[test]
fn the_walk_does_not_follow_symlinks_out_of_the_tree() {
    with_fs(test_cfg(), |h, me, dir, _stop| {
        std::fs::create_dir(dir.join("real")).unwrap();
        std::fs::write(dir.join("real/inside.txt"), b"x").unwrap();
        std::os::unix::fs::symlink("/etc", dir.join("escape")).unwrap();
        std::os::unix::fs::symlink("real", dir.join("loop")).unwrap();

        let anchor = Anchor::open(dir.as_path()).expect("anchor");
        let keys = walk_keys(&h, me, &anchor, TreeOptions::default());

        // The links are yielded as entries - they exist - but neither is descended into, so nothing from /etc and no
        // second copy of `real/`'s contents appears.
        assert!(keys.contains(&"real/".to_string()));
        assert!(keys.contains(&"real/inside.txt".to_string()));
        assert!(
            !keys.iter().any(|k| k.starts_with("escape/")),
            "symlink to /etc must not be descended: {keys:?}"
        );
        assert!(
            !keys.iter().any(|k| k.starts_with("loop/")),
            "symlink to a sibling must not be descended: {keys:?}"
        );
    });
}
