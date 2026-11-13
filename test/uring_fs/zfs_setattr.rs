use super::*;
use std::os::fd::AsFd;
use truenas_ros::sync_fs::{
    SetTime, Statx, StatxTimestamp, ZFS_SETATTR, ZfsSetattr, fget_zfs_attrs, fset_zfs_attrs, statx,
};

const OWNER: u32 = 61_001;
const OTHER: u32 = 61_002;
const GROUP: u32 = 61_100;

const T0: StatxTimestamp = StatxTimestamp { sec: 500, nsec: 3 };
const T1: StatxTimestamp = StatxTimestamp { sec: 1_000, nsec: 5 };
const T2: StatxTimestamp = StatxTimestamp { sec: 2_000, nsec: 7 };

/// Whether the ZFS here answered. A `system.` name no handler takes is `EOPNOTSUPP` (`xattr_resolve_name`,
/// `fs/xattr.c`), which `TRUENAS_ROS_REQUIRE_ZFS_SETATTR` turns into a failure.
fn handled(res: &Result<(), Error>) -> bool {
    if !matches!(res, Err(Error::Errno(Errno::EOPNOTSUPP))) {
        return true;
    }
    assert!(
        std::env::var_os("TRUENAS_ROS_REQUIRE_ZFS_SETATTR").is_none(),
        "TRUENAS_ROS_REQUIRE_ZFS_SETATTR is set but this ZFS has no \
             handler for system.truenas_setattr"
    );
    false
}

/// The datasets the runner provides, NFSv4 then POSIX.
fn datasets() -> Vec<PathBuf> {
    let found: Vec<PathBuf> = ["TRUENAS_ROS_NFS4_DATASET", "TRUENAS_ROS_POSIX_DATASET"]
        .iter()
        .filter_map(|v| std::env::var_os(v).map(PathBuf::from))
        .filter(|d| zfs_dir::is_zfs(d) == Some(true))
        .collect();
    assert!(
        !found.is_empty() || std::env::var_os("TRUENAS_ROS_REQUIRE_ZFS").is_none(),
        "TRUENAS_ROS_REQUIRE_ZFS is set but neither ACL dataset is ZFS"
    );
    found
}

/// A fresh folder anyone may enter under `ds`.
fn fresh(ds: &Path, tag: &str) -> PathBuf {
    let d = ds.join(format!("rostest_setattr_{tag}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir(&d).unwrap();
    std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o777)).unwrap();
    d
}

/// A file under `dir` that `uid` owns, with `mode`.
fn owned(dir: &Path, name: &str, uid: u32, mode: u32) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, b"setattr").unwrap();
    std::os::unix::fs::chown(&p, Some(uid), Some(uid)).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
    p
}

/// `name` under `dir`, opened by root on the ring. `fsetxattr` asks nothing of how a file was opened
/// (`file_setxattr`, `fs/xattr.c`), so the setter's checks are those of the identity it runs as.
fn ring_file(h: &FsHandle, me: Personality, dir: &Path, name: &str) -> File {
    let anchor = Anchor::open(dir).unwrap();
    h.open(me, &anchor, name, rdonly()).expect("open")
}

fn stat(p: &Path) -> Statx {
    let f = std::fs::File::open(p).unwrap();
    let mask = StatxMask::BASIC_STATS | StatxMask::BTIME;
    statx(f.as_fd(), "", AtFlags::AT_EMPTY_PATH, mask).unwrap()
}

fn dos(p: &Path) -> ZfsAttr {
    fget_zfs_attrs(std::fs::File::open(p).unwrap().as_fd()).unwrap()
}

fn utimens(p: &Path, atime: StatxTimestamp, mtime: StatxTimestamp) {
    let c = CString::new(p.as_os_str().as_bytes()).unwrap();
    let ts = |t: StatxTimestamp| libc::timespec {
        tv_sec: t.sec,
        tv_nsec: t.nsec.into(),
    };
    let times = [ts(atime), ts(mtime)];
    // SAFETY: a valid NUL-terminated path and two timespecs.
    let rc = unsafe { libc::utimensat(libc::AT_FDCWD, c.as_ptr(), times.as_ptr(), 0) };
    assert_eq!(rc, 0, "utimensat {}", p.display());
}

fn eperm(res: &Result<(), Error>) -> bool {
    matches!(res, Err(Error::Errno(Errno::EPERM)))
}

/// What the owner sets in one call is what chmod, utimensat and the ioctl set on a twin, and the birth time is the
/// one given.
#[test]
fn the_owner_sets_what_chmod_utimensat_and_the_ioctl_set() {
    if !root_or_skip("the_owner_sets_what_chmod_utimensat_and_the_ioctl_set") {
        return;
    }
    with_broker(|h, creds, me, _tmp| {
        let owner = creds.register(&AsUser::new(OWNER, OWNER)).unwrap();
        for ds in datasets() {
            let dir = fresh(&ds, "owner");
            let a = owned(&dir, "native", OWNER, 0o644);
            let b = owned(&dir, "setter", OWNER, 0o644);
            let set = ZfsSetattr::new()
                .mode(Mode::from_bits_truncate(0o640))
                .atime(SetTime::At(T1))
                .mtime(SetTime::At(T2))
                .btime(SetTime::At(T0))
                .dos(ZfsAttr::HIDDEN | ZfsAttr::SYSTEM, ZfsAttr::ARCHIVE);
            let f = ring_file(h, me, &dir, "setter");
            let res = h.fset_attrs(owner, &f, &set);
            h.close(f).unwrap();
            if !handled(&res) {
                std::fs::remove_dir_all(&dir).unwrap();
                break;
            }
            res.expect("the owner's set");

            // The twin, through the calls the setter stands for.
            std::fs::set_permissions(&a, std::fs::Permissions::from_mode(0o640)).unwrap();
            utimens(&a, T1, T2);
            let file = std::fs::File::open(&a).unwrap();
            let want = (fget_zfs_attrs(file.as_fd()).unwrap() | ZfsAttr::HIDDEN | ZfsAttr::SYSTEM) - ZfsAttr::ARCHIVE;
            fset_zfs_attrs(file.as_fd(), want).unwrap();

            let (sa, sb) = (stat(&a), stat(&b));
            assert_eq!(sb.mode() & 0o7777, 0o640, "{}", ds.display());
            assert_eq!(
                (sb.mode(), sb.atime(), sb.mtime()),
                (sa.mode(), sa.atime(), sa.mtime()),
                "{}",
                ds.display()
            );
            assert_eq!(sb.btime(), T0, "{}", ds.display());
            assert_eq!(dos(&b), dos(&a), "{}", ds.display());
            assert!(dos(&b).contains(ZfsAttr::HIDDEN | ZfsAttr::SYSTEM));
            assert!(!dos(&b).contains(ZfsAttr::ARCHIVE));
            std::fs::remove_dir_all(&dir).unwrap();
        }
        creds.unregister(owner).unwrap();
    });
}

/// Root sets the owner and group as chown does, which takes set-user-ID from a file. With a mode in the same call
/// set-user-ID goes too, as `nfsd_sanitize_attrs` (`fs/nfsd/vfs.c`) clears it, since `notify_change` cannot take a
/// mode beside `ATTR_KILL_SUID`.
#[test]
fn root_sets_the_owner_as_chown_does() {
    if !root_or_skip("root_sets_the_owner_as_chown_does") {
        return;
    }
    with_fs(test_cfg(), |h, me, _tmp, _stop| {
        for ds in datasets() {
            let dir = fresh(&ds, "chown");
            let a = owned(&dir, "native", OWNER, 0o4755);
            let b = owned(&dir, "setter", OWNER, 0o4755);
            let c = owned(&dir, "with_mode", OWNER, 0o644);
            let f = ring_file(&h, me, &dir, "setter");
            let res = h.fset_attrs(me, &f, &ZfsSetattr::new().uid(OTHER).gid(GROUP));
            h.close(f).unwrap();
            if !handled(&res) {
                std::fs::remove_dir_all(&dir).unwrap();
                break;
            }
            res.expect("root's set of the owner");
            std::os::unix::fs::chown(&a, Some(OTHER), Some(GROUP)).unwrap();
            let (sa, sb) = (stat(&a), stat(&b));
            assert_eq!(
                (sb.uid(), sb.gid(), sb.mode()),
                (sa.uid(), sa.gid(), sa.mode()),
                "{}",
                ds.display()
            );
            assert_eq!(sb.mode() & 0o7777, 0o755, "{}", ds.display());

            let f = ring_file(&h, me, &dir, "with_mode");
            let set = ZfsSetattr::new().uid(OTHER).mode(Mode::from_bits_truncate(0o4755));
            h.fset_attrs(me, &f, &set).expect("owner and mode");
            h.close(f).unwrap();
            let sc = stat(&c);
            assert_eq!((sc.uid(), sc.mode() & 0o7777), (OTHER, 0o755));
            std::fs::remove_dir_all(&dir).unwrap();
        }
    });
}

/// Another user is refused what chmod, chown and utimensat refuse it, and the ZFS attributes too, write permission
/// or not, and a refused call changes nothing. A touch, which write permission allows, goes through.
#[test]
fn another_user_is_refused_what_the_owner_may_set() {
    if !root_or_skip("another_user_is_refused_what_the_owner_may_set") {
        return;
    }
    with_broker(|h, creds, me, _tmp| {
        let other = creds.register(&AsUser::new(OTHER, OTHER)).unwrap();
        for ds in datasets() {
            let dir = fresh(&ds, "other");
            let p = owned(&dir, "f", OWNER, 0o666);
            let f = ring_file(h, me, &dir, "f");
            let before = stat(&p);
            let now = SetTime::Now;
            let hidden = |s: ZfsSetattr| s.dos(ZfsAttr::HIDDEN, ZfsAttr::empty());
            let refused = [
                ("mode", ZfsSetattr::new().mode(Mode::S_IRUSR)),
                ("uid", ZfsSetattr::new().uid(OTHER)),
                ("times", ZfsSetattr::new().atime(SetTime::At(T1)).mtime(SetTime::At(T2))),
                ("btime", ZfsSetattr::new().btime(SetTime::At(T0))),
                ("hidden", hidden(ZfsSetattr::new())),
                ("touch and hidden", hidden(ZfsSetattr::new().atime(now).mtime(now))),
            ];
            for (what, set) in refused {
                let res = h.fset_attrs(other, &f, &set);
                if !handled(&res) {
                    h.close(f).unwrap();
                    std::fs::remove_dir_all(&dir).unwrap();
                    return;
                }
                assert!(eperm(&res), "{what} on {}: {res:?}", ds.display());
            }
            let after = stat(&p);
            let seen = |s: &Statx| (s.mode(), s.uid(), s.atime(), s.mtime(), s.btime(), s.ctime());
            assert_eq!(seen(&after), seen(&before), "{}", ds.display());
            assert!(!dos(&p).contains(ZfsAttr::HIDDEN), "{}", ds.display());

            h.fset_attrs(other, &f, &ZfsSetattr::new().atime(now).mtime(now))
                .expect("a touch with write permission");
            h.close(f).unwrap();
            std::fs::remove_dir_all(&dir).unwrap();
        }
        creds.unregister(other).unwrap();
    });
}

/// An NFSv4 ACL that grants another user write attributes lets it set readonly, hidden and system, but not nodump,
/// which needs the owner, nor the birth time, which needs the owner as any explicit time does.
#[cfg(feature = "acl")]
#[test]
fn write_attributes_from_an_nfsv4_acl_lets_another_user_set_dos_bits() {
    use truenas_ros::sync_fs::acl::{
        Acl, Nfs4Ace, Nfs4AceType, Nfs4Acl, Nfs4AclFlag, Nfs4Flag, Nfs4Perm, Nfs4Who, fgetacl, fsetacl,
    };
    if !root_or_skip("write_attributes_from_an_nfsv4_acl") {
        return;
    }
    let nfs4 = std::env::var_os("TRUENAS_ROS_NFS4_DATASET")
        .map(PathBuf::from)
        .filter(|d| zfs_dir::is_zfs(d) == Some(true));
    let Some(ds) = nfs4 else {
        assert!(
            std::env::var_os("TRUENAS_ROS_REQUIRE_ZFS").is_none(),
            "TRUENAS_ROS_REQUIRE_ZFS is set but there is no NFSv4 dataset"
        );
        return;
    };
    with_broker(|h, creds, me, _tmp| {
        let other = creds.register(&AsUser::new(OTHER, OTHER)).unwrap();
        let dir = fresh(&ds, "wattr");
        let p = owned(&dir, "f", OWNER, 0o644);
        let file = std::fs::File::open(&p).unwrap();
        let Ok(Acl::Nfs4(acl)) = fgetacl(file.as_fd()) else {
            panic!("expected an NFSv4 ACL on {}", ds.display());
        };
        let mut aces = acl.aces.clone();
        aces.insert(
            0,
            Nfs4Ace::new(
                Nfs4AceType::Allow,
                Nfs4Flag::empty(),
                Nfs4Perm::WRITE_ATTRIBUTES,
                Nfs4Who::Named,
                OTHER.into(),
            ),
        );
        let granted = Acl::Nfs4(Nfs4Acl::from_aces(aces, Nfs4AclFlag::empty()));
        fsetacl(file.as_fd(), Some(&granted)).expect("fsetacl");

        let f = ring_file(h, me, &dir, "f");
        let bits = ZfsAttr::READONLY | ZfsAttr::HIDDEN | ZfsAttr::SYSTEM;
        let res = h.fset_attrs(other, &f, &ZfsSetattr::new().dos(bits, ZfsAttr::empty()));
        if handled(&res) {
            res.expect("write attributes from the ACL");
            assert!(dos(&p).contains(bits));
            let nodump = ZfsSetattr::new().dos(ZfsAttr::NODUMP, ZfsAttr::empty());
            assert!(eperm(&h.fset_attrs(other, &f, &nodump)));
            let btime = ZfsSetattr::new().btime(SetTime::At(T0));
            assert!(eperm(&h.fset_attrs(other, &f, &btime)));
        }
        h.close(f).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        creds.unregister(other).unwrap();
    });
}

/// IMMUTABLE needs `CAP_LINUX_IMMUTABLE` beside the owner. Once it is set the VFS refuses the setter itself
/// (`may_write_xattr`, `fs/xattr.c`), so only the ioctl clears it.
#[test]
fn immutable_needs_cap_linux_immutable_and_only_the_ioctl_clears_it() {
    if !root_or_skip("immutable_needs_cap_linux_immutable") {
        return;
    }
    with_broker(|h, creds, me, _tmp| {
        let owner = creds.register(&AsUser::new(OWNER, OWNER)).unwrap();
        let lock = ZfsSetattr::new().dos(ZfsAttr::IMMUTABLE, ZfsAttr::empty());
        let unlock = ZfsSetattr::new().dos(ZfsAttr::empty(), ZfsAttr::IMMUTABLE);
        for ds in datasets() {
            let dir = fresh(&ds, "immutable");
            let p = owned(&dir, "f", OWNER, 0o644);
            let f = ring_file(h, me, &dir, "f");
            let res = h.fset_attrs(owner, &f, &lock);
            if !handled(&res) {
                h.close(f).unwrap();
                std::fs::remove_dir_all(&dir).unwrap();
                break;
            }
            assert!(eperm(&res), "the owner alone: {res:?}");
            h.fset_attrs(me, &f, &lock).expect("root sets IMMUTABLE");
            assert!(dos(&p).contains(ZfsAttr::IMMUTABLE));
            assert!(eperm(&h.fset_attrs(me, &f, &unlock)));
            h.close(f).unwrap();
            let file = std::fs::File::open(&p).unwrap();
            let attrs = fget_zfs_attrs(file.as_fd()).unwrap();
            fset_zfs_attrs(file.as_fd(), attrs - ZfsAttr::IMMUTABLE).unwrap();
            std::fs::remove_dir_all(&dir).unwrap();
        }
        creds.unregister(owner).unwrap();
    });
}

/// The handler refuses with `EINVAL` a value it cannot apply, and one of a version it does not know.
#[test]
fn the_handler_refuses_a_value_it_cannot_apply() {
    if !root_or_skip("the_handler_refuses_a_value_it_cannot_apply") {
        return;
    }
    with_fs(test_cfg(), |h, me, _tmp, _stop| {
        for ds in datasets() {
            let dir = fresh(&ds, "einval");
            owned(&dir, "f", OWNER, 0o644);
            let f = ring_file(&h, me, &dir, "f");
            let empty = h.fset_attrs(me, &f, &ZfsSetattr::new());
            if !handled(&empty) {
                h.close(f).unwrap();
                std::fs::remove_dir_all(&dir).unwrap();
                break;
            }
            let second = StatxTimestamp {
                sec: 1,
                nsec: 1_000_000_000,
            };
            let refused = [
                ("nothing to set", empty),
                (
                    "a mask of no bits",
                    h.fset_attrs(me, &f, &ZfsSetattr::new().mode_masked(Mode::S_IRUSR, Mode::empty())),
                ),
                ("uid u32::MAX", h.fset_attrs(me, &f, &ZfsSetattr::new().uid(u32::MAX))),
                (
                    "a bit to set and to clear",
                    h.fset_attrs(me, &f, &ZfsSetattr::new().dos(ZfsAttr::HIDDEN, ZfsAttr::HIDDEN)),
                ),
                (
                    "a second of nanoseconds",
                    h.fset_attrs(me, &f, &ZfsSetattr::new().atime(SetTime::At(second))),
                ),
            ];
            for (what, res) in refused {
                assert!(matches!(res, Err(Error::Errno(Errno::EINVAL))), "{what}: {res:?}");
            }
            let mut later = ZfsSetattr::new().uid(OWNER).to_bytes();
            later[0] = 2;
            let (res, _) = h.fsetxattr(me, &f, ZFS_SETATTR, later, 0);
            assert!(matches!(res, Err(Error::Errno(Errno::EINVAL))), "{res:?}");
            h.close(f).unwrap();
            std::fs::remove_dir_all(&dir).unwrap();
        }
    });
}
