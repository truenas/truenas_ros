use truenas_ros::errno::Errno;
use truenas_ros::sync_fs::iter::{Cookie, DirStackEntry, EntryType, FsIterBuilder};
use truenas_ros::sync_fs::{AtFlags, OFlag, StatxMask, statx};
use truenas_ros::{AT_FDCWD, Error};

/// The mount source of `p`, so the fsiter source-check matches on kernels that report `sb_source`. Where it is not
/// reported (e.g. the TrueNAS 6.12 kernel) this returns a placeholder and the check is skipped anyway.
fn fs_source(p: &std::path::Path) -> String {
    truenas_ros::mount::statmount_path(p)
        .ok()
        .and_then(|sm| sm.sb_source)
        .unwrap_or_else(|| "x".to_string())
}

#[test]
fn relative_path_scopes_iteration() {
    let dir = truenas_ros::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("sub")).unwrap();
    std::fs::write(dir.path().join("sub/inner"), b"x").unwrap();
    std::fs::write(dir.path().join("outside"), b"y").unwrap();
    let it = FsIterBuilder::new(dir.path(), fs_source(dir.path()))
        .relative_path("sub")
        .build()
        .unwrap();
    let names: Vec<_> = it.map(|e| e.unwrap().name().to_string_lossy().into_owned()).collect();
    assert!(names.contains(&"inner".to_string()));
    assert!(!names.contains(&"outside".to_string()));
}

/// The screen `relative_path` documents: a shape that would walk out of the mountpoint is refused at build, not
/// resolved. The mount-source check cannot stand in for this - it catches crossing to a different filesystem, and
/// `../outside` here stays on the same one.
#[test]
fn a_relative_path_cannot_escape_the_mountpoint() {
    let dir = truenas_ros::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("tree/anchor/sub")).unwrap();
    std::fs::create_dir_all(dir.path().join("tree/outside")).unwrap();
    std::fs::write(dir.path().join("tree/outside/secret"), b"s").unwrap();
    let anchor = dir.path().join("tree/anchor");
    for rel in ["../outside", "sub/../../outside", "/etc", "a//b", ""] {
        let err = FsIterBuilder::new(&anchor, fs_source(&anchor))
            .relative_path(rel)
            .build()
            .map(|_| ())
            .unwrap_err();
        assert!(matches!(err, Error::Errno(Errno::EINVAL)), "{rel:?} built: {err:?}");
    }
    // The screen does not over-reach: an honest subdirectory builds.
    assert!(
        FsIterBuilder::new(&anchor, fs_source(&anchor))
            .relative_path("sub")
            .build()
            .is_ok(),
        "a plain subdirectory still builds"
    );
}

#[test]
fn build_on_a_file_is_enotdir() {
    let dir = truenas_ros::tempdir().unwrap();
    let p = dir.path().join("f");
    std::fs::write(&p, b"x").unwrap();
    assert!(matches!(
        FsIterBuilder::new(&p, "x").build().unwrap_err(),
        Error::Errno(Errno::ENOTDIR)
    ));
}

#[test]
fn file_open_flags_dir_stack_and_entry_helpers() {
    let dir = truenas_ros::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("d")).unwrap();
    std::fs::write(dir.path().join("d/f"), b"hello").unwrap();
    let mut it = FsIterBuilder::new(dir.path(), fs_source(dir.path()))
        .file_open_flags(OFlag::O_RDONLY | OFlag::O_NOFOLLOW)
        .build()
        .unwrap();
    let mut saw = false;
    let mut max_depth = 0;
    while let Some(res) = it.next() {
        let e = res.unwrap();
        max_depth = max_depth.max(it.dir_stack().len());
        if e.name() == "f" {
            saw = true;
            assert!(e.is_regular());
            assert_eq!(e.file_type(), EntryType::File);
            assert_eq!(e.path(), dir.path().join("d").join("f"));
            assert_eq!(e.parent(), dir.path().join("d"));
            let fd = e.into_fd();
            use std::os::fd::AsFd;
            let st = statx(fd.as_fd(), "", AtFlags::AT_EMPTY_PATH, StatxMask::SIZE).unwrap();
            assert_eq!(st.size(), 5);
        }
    }
    assert!(saw);
    assert!(max_depth >= 1);
}

#[test]
fn btime_cutoff_skips_newer_files() {
    let dir = truenas_ros::tempdir().unwrap();
    let p = dir.path().join("f");
    std::fs::write(&p, b"x").unwrap();
    let st = statx(AT_FDCWD, &p, AtFlags::empty(), StatxMask::BTIME).unwrap();
    // A filesystem with no birth time is a real case the builder handles
    // (`a_cutoff_refuses_a_filesystem_with_no_birth_time` pins the refusal), so the skip is legitimate - but it
    // takes the whole cutoff assertion with it, so a runner whose scratch filesystem reports no btime must say so
    // rather than pass green.
    if !st.mask().contains(StatxMask::BTIME) || st.btime().sec <= 0 {
        assert!(
            std::env::var_os("TRUENAS_ROS_REQUIRE_BTIME").is_none(),
            "TRUENAS_ROS_REQUIRE_BTIME is set but {} reports no \
                 birth time",
            p.display()
        );
        return;
    }
    let it = FsIterBuilder::new(dir.path(), fs_source(dir.path()))
        .btime_cutoff(st.btime().sec - 1)
        .build()
        .unwrap();
    let names: Vec<_> = it.map(|e| e.unwrap().name().to_string_lossy().into_owned()).collect();
    assert!(!names.contains(&"f".to_string()));
}

#[test]
fn empty_directory_yields_nothing() {
    let dir = truenas_ros::tempdir().unwrap();
    let mut it = FsIterBuilder::new(dir.path(), fs_source(dir.path())).build().unwrap();
    assert!(it.next().is_none());
    assert_eq!(it.stats().count, 0);
}

#[test]
fn deep_nesting_is_fully_walked() {
    let dir = truenas_ros::tempdir().unwrap();
    let mut p = dir.path().to_path_buf();
    for i in 0..12 {
        p = p.join(format!("d{i}"));
    }
    std::fs::create_dir_all(&p).unwrap();
    std::fs::write(p.join("leaf"), b"z").unwrap();
    let count = FsIterBuilder::new(dir.path(), fs_source(dir.path()))
        .build()
        .unwrap()
        .map(Result::unwrap)
        .count();
    assert_eq!(count, 13); // 12 dirs + 1 leaf
}

#[test]
fn unreadable_regular_file_fails_the_walk() {
    use std::os::unix::fs::PermissionsExt;
    // Root bypasses mode bits, so this only holds unprivileged.
    if unsafe { libc::getuid() } == 0 {
        return;
    }
    let dir = truenas_ros::tempdir().unwrap();
    std::fs::write(dir.path().join("ok"), b"x").unwrap();
    let bad = dir.path().join("bad");
    std::fs::write(&bad, b"y").unwrap();
    std::fs::set_permissions(&bad, std::fs::Permissions::from_mode(0o000)).unwrap();
    // "bad" hits the EACCES branch (retry O_RDONLY, still denied).
    let mut it = FsIterBuilder::new(dir.path(), fs_source(dir.path())).build().unwrap();
    let mut names = Vec::new();
    let mut err = None;
    for res in it.by_ref() {
        match res {
            Ok(e) => names.push(e.name().to_string_lossy().into_owned()),
            Err(e) => {
                err = Some(e);
                break;
            }
        }
    }
    assert!(
        matches!(err, Some(Error::Errno(Errno::EACCES))),
        "unexpected outcome: {err:?}"
    );
    assert!(!names.contains(&"bad".to_string()));
    // The error is fatal to the walk.
    assert!(it.next().is_none());
}

#[test]
fn cookie_bytes_round_trip_including_non_utf8_path() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    let ck = Cookie::from(vec![
        DirStackEntry {
            path: "/mnt/tank".into(),
            ino: 2,
        },
        DirStackEntry {
            path: std::path::PathBuf::from(OsStr::from_bytes(b"/mnt/tank/we\xffird")),
            ino: 42,
        },
    ]);
    let back = Cookie::from_bytes(&ck.to_bytes()).unwrap();
    assert_eq!(back, ck);
    assert_eq!(back.len(), 2);
    assert_eq!(back.entries()[1].ino, 42);
}

#[test]
fn cookie_from_bytes_rejects_malformed() {
    // Empty / too short for even the header.
    assert!(matches!(Cookie::from_bytes(&[]), Err(Error::Validation(_))));
    // Ten bytes but a bad magic.
    assert!(matches!(
        Cookie::from_bytes(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]),
        Err(Error::Validation(_))
    ));
    let good = Cookie::from(vec![DirStackEntry {
        path: "/a".into(),
        ino: 5,
    }])
    .to_bytes();
    assert!(Cookie::from_bytes(&good).is_ok());
    // A byte lopped off => truncated; a byte added => trailing garbage.
    let mut truncated = good.clone();
    truncated.pop();
    assert!(matches!(Cookie::from_bytes(&truncated), Err(Error::Validation(_))));
    let mut trailing = good.clone();
    trailing.push(0);
    assert!(matches!(Cookie::from_bytes(&trailing), Err(Error::Validation(_))));
}

#[test]
fn empty_and_single_level_cookies_walk_the_whole_tree() {
    use std::collections::BTreeSet;
    use std::os::unix::fs::MetadataExt;
    let dir = truenas_ros::tempdir().unwrap();
    let root = dir.path();
    std::fs::create_dir_all(root.join("sub")).unwrap();
    std::fs::write(root.join("sub/f"), b"x").unwrap();
    std::fs::write(root.join("g"), b"y").unwrap();
    let walk = |b: FsIterBuilder| -> BTreeSet<String> {
        b.build()
            .unwrap()
            .map(|r| r.unwrap().name().to_string_lossy().into_owned())
            .collect()
    };
    let full = walk(FsIterBuilder::new(root, fs_source(root)));

    // Empty cookie => no resume => full walk.
    let empty = walk(FsIterBuilder::new(root, fs_source(root)).resume_from(Cookie::default()));
    assert_eq!(empty, full);

    // A single-level (root-only) cookie re-reads root from the start =>
    // also a full walk (the root inode must match).
    let ck = Cookie::from(vec![DirStackEntry {
        path: root.to_path_buf(),
        ino: std::fs::metadata(root).unwrap().ino(),
    }]);
    let one = walk(FsIterBuilder::new(root, fs_source(root)).resume_from(ck));
    assert_eq!(one, full);
}

#[test]
fn resume_from_wrong_root_inode_is_restore_depth_0() {
    let dir = truenas_ros::tempdir().unwrap();
    let root = dir.path();
    let ck = Cookie::from(vec![DirStackEntry {
        path: root.to_path_buf(),
        ino: u64::MAX, // definitely not the real root inode
    }]);
    let err = FsIterBuilder::new(root, fs_source(root))
        .resume_from(ck)
        .build()
        .unwrap_err();
    assert!(matches!(err, Error::IteratorRestore { depth: 0, .. }));
}

#[test]
fn cookie_deeper_than_max_depth_is_rejected() {
    let dir = truenas_ros::tempdir().unwrap();
    let root = dir.path();
    // MAX_DEPTH is 2048; a longer cookie is rejected before any descent.
    let entries: Vec<DirStackEntry> = (0..2049)
        .map(|i| DirStackEntry {
            path: format!("/x/{i}").into(),
            ino: i as u64,
        })
        .collect();
    let err = FsIterBuilder::new(root, fs_source(root))
        .resume_from(Cookie::from(entries))
        .build()
        .unwrap_err();
    assert!(matches!(err, Error::Validation(_)));
}

#[test]
fn seed_stats_continues_running_totals() {
    let dir = truenas_ros::tempdir().unwrap();
    let root = dir.path();
    std::fs::write(root.join("f"), b"xyz").unwrap();
    let mut it = FsIterBuilder::new(root, fs_source(root))
        .seed_stats(100, 1000)
        .build()
        .unwrap();
    // The seed is in effect before anything is yielded.
    assert_eq!(it.stats().count, 100);
    assert_eq!(it.stats().bytes, 1000);
    for r in it.by_ref() {
        r.unwrap();
    }
    // One 3-byte file added on top of the seed.
    assert_eq!(it.stats().count, 101);
    assert_eq!(it.stats().bytes, 1003);
}
