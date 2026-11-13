use std::collections::BTreeSet;
use truenas_ros::Error;
use truenas_ros::errno::Errno;
use truenas_ros::sync_fs::iter::FsIterBuilder;
use truenas_ros::sync_fs::{AtFlags, OFlag, StatxMask, statx};

/// The mount source of `p`, so the fsiter source-check matches on kernels that report `sb_source`. Where it is not
/// reported (e.g. the TrueNAS 6.12 kernel) this returns a placeholder and the check is skipped anyway.
fn fs_source(p: &std::path::Path) -> String {
    truenas_ros::mount::statmount_path(p)
        .ok()
        .and_then(|sm| sm.sb_source)
        .unwrap_or_else(|| "x".to_string())
}

/// A walk that cannot open an entry surfaces the error and then stops.
///
/// The iterator prunes exactly what has nothing left to list - the same line `query_tree`'s `is_subtree_skip`
/// draws - and everything else has to reach the caller. `copytree` is built directly on this (`let entry = res?`),
/// so an error swallowed here is a partial tree copied as if it were whole: data loss that reads as success.
///
/// The `fatal` latch is the second half. Once a walk has failed its directory stack describes a position it never
/// reached, so continuing to yield from it would produce a listing that is short *and* has no error in it.
///
/// Provoked with `ENOTDIR` (a regular file where a directory open is demanded) rather than a permission denial,
/// which running as root cannot stage.
#[test]
fn a_walk_that_cannot_open_an_entry_reports_it_and_stops() {
    let dir = truenas_ros::tempdir().unwrap();
    std::fs::write(dir.path().join("f"), b"x").unwrap();
    std::fs::write(dir.path().join("g"), b"y").unwrap();

    // Directories still open (the walk uses its own flags for those);
    // a regular file opened `O_DIRECTORY` is ENOTDIR.
    let mut it = FsIterBuilder::new(dir.path(), fs_source(dir.path()))
        .file_open_flags(OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_DIRECTORY)
        .build()
        .unwrap();

    let first = it.next().expect("the walk yields something");
    assert!(
        matches!(first, Err(Error::Errno(Errno::ENOTDIR))),
        "an unopenable entry must surface, not be pruned: {first:?}"
    );
    assert!(
        it.next().is_none(),
        "a failed walk must stop rather than yield a short listing \
             with no error in it"
    );
    assert!(it.next().is_none(), "and stay stopped");
}

/// A directory `Entry::fd()` shares the walk's cursor, and the reopen the docs prescribe is what gives a caller its
/// own.
///
/// The walk descends by duplicating the entry's descriptor, so the two are one open file description. The fd is
/// offered for `statx`, `read_link` and file data, not for reading a directory stream, and this test keeps the
/// warning that says so honest. Reading it directly must shorten the walk; reopening, as `shutil::reopen_dir` does,
/// must not.
/// If the descent ever stops sharing, delete the warning and this half with it.
#[test]
fn an_entry_fd_shares_the_walk_cursor_and_a_reopen_does_not() {
    use std::os::fd::AsRawFd;

    let dir = truenas_ros::tempdir().unwrap();
    let sub = dir.path().join("sub");
    std::fs::create_dir(&sub).unwrap();
    for i in 0..50 {
        std::fs::write(sub.join(format!("f{i}")), b"x").unwrap();
    }

    // `drain` reads the directory stream from the handed-out fd; `reopen` reads it from a fresh open file
    // description over the same inode.
    let count = |drain: bool, reopen: bool| {
        let mut it = FsIterBuilder::new(dir.path(), fs_source(dir.path())).build().unwrap();
        let mut n = 0;
        for res in it.by_ref() {
            let e = res.unwrap();
            n += 1;
            if !drain || !e.is_dir() {
                continue;
            }
            // SAFETY: a live directory fd; `.` names it.
            let fd = if reopen {
                let r = unsafe { libc::openat(e.fd().as_raw_fd(), c".".as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY) };
                assert!(r >= 0, "reopen failed");
                r
            } else {
                e.fd().as_raw_fd()
            };
            let mut buf = [0u8; 4096];
            // SAFETY: a live directory fd and a buffer of `len`.
            let got = unsafe { libc::syscall(libc::SYS_getdents64, fd, buf.as_mut_ptr(), buf.len()) };
            assert!(got > 0, "the directory reads: {got}");
            if reopen {
                // SAFETY: our own fd, closed once.
                unsafe { libc::close(fd) };
            }
        }
        n
    };

    let control = count(false, false);
    assert_eq!(control, 51, "the subdirectory plus its fifty files");
    assert!(
        count(true, false) < control,
        "reading the handed-out fd shares the walk's cursor, as documented"
    );
    assert_eq!(
        count(true, true),
        control,
        "the documented reopen leaves the walk intact"
    );
}

fn names(dir: &std::path::Path) -> (BTreeSet<String>, u64, u64) {
    let mut it = FsIterBuilder::new(dir, fs_source(dir)).build().unwrap();
    let mut set = BTreeSet::new();
    for res in it.by_ref() {
        let e = res.unwrap();
        set.insert(e.name().to_string_lossy().into_owned());
    }
    let s = it.stats();
    (set, s.count, s.bytes)
}

#[test]
fn walks_whole_tree_depth_first() {
    let dir = truenas_ros::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("a/b")).unwrap();
    std::fs::write(dir.path().join("a/f1"), b"1").unwrap();
    std::fs::write(dir.path().join("a/b/f2"), b"22").unwrap();
    std::fs::write(dir.path().join("c"), b"333").unwrap();

    let (set, count, bytes) = names(dir.path());
    for n in ["a", "b", "c", "f1", "f2"] {
        assert!(set.contains(n), "missing {n}");
    }
    assert_eq!(count, 5); // a, b, c, f1, f2
    assert_eq!(bytes, 6); // 1 + 2 + 3 (files only; dirs add no bytes)
}

// A writer-less FIFO in the tree would hang the walk forever on a blocking O_RDONLY open; it must classify as
// `Special` so the walk finishes without opening it.
#[test]
fn special_files_classify_without_hanging() {
    use std::os::unix::ffi::OsStrExt;
    use truenas_ros::sync_fs::iter::EntryType;
    let dir = truenas_ros::tempdir().unwrap();
    std::fs::write(dir.path().join("regular"), b"hi").unwrap();
    let fifo = dir.path().join("pipe");
    let c = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o644) }, 0);

    let mut it = FsIterBuilder::new(dir.path(), fs_source(dir.path())).build().unwrap();
    let mut kinds = std::collections::BTreeMap::new();
    for res in it.by_ref() {
        let e = res.unwrap();
        kinds.insert(e.name().to_string_lossy().into_owned(), e.file_type());
    }
    assert_eq!(kinds.get("regular"), Some(&EntryType::File));
    assert_eq!(kinds.get("pipe"), Some(&EntryType::Special));
}

#[test]
fn skip_descent_prunes_subtree() {
    let dir = truenas_ros::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("keep")).unwrap();
    std::fs::create_dir_all(dir.path().join("prune/hidden")).unwrap();
    std::fs::write(dir.path().join("keep/f"), b"x").unwrap();
    std::fs::write(dir.path().join("prune/secret"), b"y").unwrap();

    let mut it = FsIterBuilder::new(dir.path(), fs_source(dir.path())).build().unwrap();
    let mut seen = BTreeSet::new();
    while let Some(res) = it.next() {
        let e = res.unwrap();
        let name = e.name().to_string_lossy().into_owned();
        if name == "prune" {
            assert!(e.is_dir());
            it.skip_descent();
        }
        seen.insert(name);
    }
    assert!(seen.contains("keep") && seen.contains("f"));
    assert!(seen.contains("prune")); // the dir itself is yielded...
    assert!(!seen.contains("secret")); // ...but not descended into
    assert!(!seen.contains("hidden"));
}

#[test]
fn yielded_fd_is_usable_and_self_closing() {
    let dir = truenas_ros::tempdir().unwrap();
    std::fs::write(dir.path().join("data"), b"hello world").unwrap();

    let it = FsIterBuilder::new(dir.path(), fs_source(dir.path())).build().unwrap();
    let file = it
        .map(Result::unwrap)
        .find(|e| e.name() == "data")
        .expect("entry not found");
    // The entry carries statx metadata directly.
    assert!(file.is_regular());
    assert_eq!(file.statx().size(), 11);
    // Its fd is a live, usable descriptor (statx via AT_EMPTY_PATH).
    let st = statx(file.fd(), "", AtFlags::AT_EMPTY_PATH, StatxMask::SIZE).unwrap();
    assert_eq!(st.size(), 11);
    // Dropping `file` closes the fd automatically (no manual close).
}

#[test]
fn symlinks_skipped_by_default_included_on_request() {
    let dir = truenas_ros::tempdir().unwrap();
    std::fs::write(dir.path().join("target"), b"t").unwrap();
    std::os::unix::fs::symlink("target", dir.path().join("link")).unwrap();

    let (default, _, _) = names(dir.path());
    assert!(!default.contains("link"), "symlink should be skipped");

    let mut it = FsIterBuilder::new(dir.path(), fs_source(dir.path()))
        .include_symlinks(true)
        .build()
        .unwrap();
    let link = it
        .by_ref()
        .map(Result::unwrap)
        .find(|e| e.name() == "link")
        .expect("symlink not yielded");
    assert!(link.is_symlink());
    let target = link.read_link().unwrap();
    assert_eq!(target.as_os_str(), "target");
    // A short target must not carry the PATH_MAX probe buffer out with it.
    assert_eq!(
        target.as_os_str().len(),
        target.into_os_string().into_encoded_bytes().capacity(),
        "the readlink probe buffer was retained behind the target"
    );
}

/// A small tree with globally-unique names (so a basename identifies an entry regardless of where it sits or of
/// readdir order).
fn sample_tree(root: &std::path::Path) {
    use std::fs::{create_dir_all, write};
    create_dir_all(root.join("d_a/d_ab")).unwrap();
    create_dir_all(root.join("d_b")).unwrap();
    write(root.join("f_c"), b"c").unwrap();
    write(root.join("d_a/f_a1"), b"a1").unwrap();
    write(root.join("d_a/f_a2"), b"a2").unwrap();
    write(root.join("d_a/d_ab/f_ab1"), b"ab1").unwrap();
    write(root.join("d_a/d_ab/f_ab2"), b"ab2").unwrap();
    write(root.join("d_b/f_b1"), b"b1").unwrap();
}

fn walk_names(root: &std::path::Path) -> BTreeSet<String> {
    FsIterBuilder::new(root, fs_source(root))
        .build()
        .unwrap()
        .map(|r| r.unwrap().name().to_string_lossy().into_owned())
        .collect()
}

// Iterate until `f_ab1` (a file deep in d_a/d_ab) is yielded, returning the names seen so far and the cookie
// captured at that point (stack is then [root, d_a, d_ab]).
fn walk_to_f_ab1(root: &std::path::Path) -> (BTreeSet<String>, truenas_ros::sync_fs::iter::Cookie) {
    let mut it = FsIterBuilder::new(root, fs_source(root)).build().unwrap();
    let mut prefix = BTreeSet::new();
    let mut cookie = None;
    while let Some(res) = it.next() {
        let name = res.unwrap().name().to_string_lossy().into_owned();
        prefix.insert(name.clone());
        if name == "f_ab1" {
            cookie = Some(it.cookie());
            break;
        }
    }
    drop(it);
    (prefix, cookie.expect("f_ab1 never yielded"))
}

#[test]
fn cookie_resume_is_complete_and_skips_descended_dirs() {
    let dir = truenas_ros::tempdir().unwrap();
    let root = dir.path();
    sample_tree(root);
    let full = walk_names(root);
    let (prefix, cookie) = walk_to_f_ab1(root);

    // Resume: the union of what we saw and what resume yields must be the whole tree (nothing skipped), and the
    // silently-descended directories must not be re-yielded.
    let resumed: BTreeSet<String> = FsIterBuilder::new(root, fs_source(root))
        .resume_from(cookie)
        .build()
        .unwrap()
        .map(|r| r.unwrap().name().to_string_lossy().into_owned())
        .collect();

    let union: BTreeSet<_> = prefix.union(&resumed).cloned().collect();
    assert_eq!(union, full, "resume must not skip any entry");
    assert!(!resumed.contains("d_a"), "descended dir re-yielded");
    assert!(!resumed.contains("d_ab"), "descended dir re-yielded");
}

#[test]
fn cookie_resume_recovers_after_deleted_directory() {
    let dir = truenas_ros::tempdir().unwrap();
    let root = dir.path();
    sample_tree(root);
    let (_prefix, cookie) = walk_to_f_ab1(root);

    // Delete the deepest saved directory, then try to resume from it.
    std::fs::remove_dir_all(root.join("d_a/d_ab")).unwrap();
    let err = FsIterBuilder::new(root, fs_source(root))
        .resume_from(cookie.clone())
        .build()
        .unwrap_err();
    let depth = match err {
        Error::IteratorRestore { depth, .. } => depth,
        other => panic!("expected IteratorRestore, got {other:?}"),
    };
    assert_eq!(depth, 2, "d_ab is at stack depth 2");

    // Recover by trimming to the surviving ancestor and rebuilding.
    let mut recovered = cookie;
    recovered.truncate(depth);
    let seen: BTreeSet<String> = FsIterBuilder::new(root, fs_source(root))
        .resume_from(recovered)
        .build()
        .unwrap()
        .map(|r| r.unwrap().name().to_string_lossy().into_owned())
        .collect();
    assert!(seen.contains("f_a1") && seen.contains("f_a2"));
    assert!(!seen.contains("f_ab1"), "deleted subtree must be gone");
}
