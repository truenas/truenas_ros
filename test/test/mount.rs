use std::os::fd::AsFd;
use truenas_ros::AT_FDCWD;
use truenas_ros::errno::Errno;
use truenas_ros::mount::{
    FsConfig, FsmountFlags, FsopenFlags, LSMT_ROOT, MountAttr, StatmountMask, fsconfig, fsmount, fsopen, iter_mount,
    listmount, statmount,
};
use truenas_ros::sync_fs::{AtFlags, StatxMask, statx};

fn root_mnt_id() -> u64 {
    statx(AT_FDCWD, "/", AtFlags::empty(), StatxMask::MNT_ID_UNIQUE)
        .unwrap()
        .mnt_id()
}

#[test]
fn listmount_namespace_is_nonempty() {
    let ids = listmount(LSMT_ROOT, false).unwrap();
    assert!(!ids.is_empty());
}

#[test]
fn statmount_root_reports_mountpoint_and_opts() {
    let id = root_mnt_id();
    let sm = statmount(
        id,
        StatmountMask::MNT_BASIC
            | StatmountMask::SB_BASIC
            | StatmountMask::MNT_POINT
            | StatmountMask::FS_TYPE
            | StatmountMask::MNT_OPTS,
    )
    .unwrap();
    assert_eq!(sm.mnt_id, Some(id));
    assert_eq!(sm.mnt_point.as_deref(), Some(std::path::Path::new("/")));
    assert!(sm.fs_type.is_some());
    // With SB_BASIC co-requested, options carry the synthetic ro/rw prefix.
    let opts = sm.mount_opts().unwrap();
    assert!(
        opts.starts_with("rw") || opts.starts_with("ro"),
        "unexpected mount_opts: {opts:?}"
    );
}

#[test]
fn iter_mount_yields_records() {
    let mounts: Vec<_> = iter_mount(LSMT_ROOT, false, StatmountMask::MNT_POINT)
        .unwrap()
        .filter_map(Result::ok)
        .collect();
    assert!(!mounts.is_empty());
    assert!(mounts.iter().any(|sm| sm.mnt_point.is_some()));
}

/// A recursive unmount orders children before parents by **depth**, not by mount id.
///
/// `listmount`'s reverse flag walks an rbtree keyed on `mnt_id_unique` (`fs/namespace.c`), which is `++mnt_id_ctr`
/// at mount *allocation* - so it is descending creation order, and equals children-before-parents only when every
/// child was created after its parent. `fsmount` then `move_mount`, both exported from this module, make the
/// opposite ordinary.
///
/// This builds the inversion on purpose: three tmpfs mounts allocated deepest-first, so their ids descend as depth
/// increases, then attached parent-first. Trusting the listing order unmounts the middle mount while its child is
/// still on it - `umount2` answers `EBUSY`, the caller is told the unmount failed, and the whole tree is left
/// mounted.
///
/// Needs privilege to mount, so it skips unless `TRUENAS_ROS_REQUIRE_ROOT` says a root run must reach it.
#[test]
fn recursive_umount_orders_by_depth_not_mount_id() {
    use truenas_ros::mount::{MoveMountFlags, UmountOptions, move_mount, umount};
    let mk = || -> Option<_> {
        let fs = match fsopen("tmpfs", FsopenFlags::empty()) {
            Ok(fd) => fd,
            Err(e @ (Errno::EPERM | Errno::ENOSYS | Errno::EACCES)) => {
                assert!(
                    std::env::var_os("TRUENAS_ROS_REQUIRE_ROOT").is_none(),
                    "TRUENAS_ROS_REQUIRE_ROOT is set but fsopen: {e}"
                );
                return None;
            }
            Err(e) => panic!("fsopen(tmpfs): {e}"),
        };
        fsconfig(fs.as_fd(), FsConfig::Create).expect("fsconfig");
        Some(fsmount(fs.as_fd(), FsmountFlags::empty(), MountAttr::empty()).expect("fsmount"))
    };
    // Deepest first, so the ids descend as depth increases.
    let (Some(gc), Some(ch), Some(pa)) = (mk(), mk(), mk()) else {
        return;
    };

    let tmp = truenas_ros::tempdir().unwrap();
    let mp = tmp.path().join("mp");
    std::fs::create_dir(&mp).unwrap();

    // Mounts are process-wide and outlive a failed assertion: without this, every failing run leaks three into the
    // namespace every other test in the binary shares, and `TempDir`'s own Drop cannot reach them. Lazy so it
    // cannot itself block, deepest-first so a parent is never asked while a child is on it, and best-effort because
    // the test's own unmount normally got there first.
    struct UnmountOnDrop(std::path::PathBuf);
    impl Drop for UnmountOnDrop {
        fn drop(&mut self) {
            let Ok(info) = std::fs::read_to_string("/proc/self/mountinfo") else {
                return;
            };
            let mut points: Vec<&str> = info
                .lines()
                .filter_map(|l| l.split_whitespace().nth(4))
                .filter(|p| p.starts_with(self.0.to_str().unwrap_or("\0")))
                .collect();
            points.sort_unstable_by_key(|p| std::cmp::Reverse(p.len()));
            for p in points {
                let Ok(c) = std::ffi::CString::new(p) else {
                    continue;
                };
                // SAFETY: a valid NUL-terminated path.
                unsafe { libc::umount2(c.as_ptr(), libc::MNT_DETACH) };
            }
        }
    }
    let _cleanup = UnmountOnDrop(mp.clone());
    // The `fsmount` descriptor pins the mount: it must be dropped once attached, or every unmount below answers
    // EBUSY.
    let attach = |m: std::os::fd::OwnedFd, at: &std::path::Path| {
        move_mount(
            m.as_fd(),
            "",
            truenas_ros::AT_FDCWD,
            at,
            MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH,
        )
        .expect("move_mount")
    };
    attach(pa, &mp);
    let a = mp.join("a");
    std::fs::create_dir(&a).unwrap();
    attach(ch, &a);
    let b = a.join("b");
    std::fs::create_dir(&b).unwrap();
    attach(gc, &b);

    // Retried, and the retry cannot mask what this guards. Getting the order wrong is deterministic - `umount2` of
    // the middle mount answers EBUSY because its child is still on it, on every attempt alike, so the reverted fix
    // fails all five (measured). What the retry absorbs is ambient: this suite runs its binaries concurrently in
    // one mount namespace, and a freshly created leaf has been observed EBUSY for reasons outside this test -
    // roughly one full release run in three, which is worse than no test.
    let mut r = Err(truenas_ros::Error::from(Errno::EBUSY));
    for _ in 0..5 {
        r = umount(
            &mp,
            UmountOptions {
                recursive: true,
                ..Default::default()
            },
        );
        if r.is_ok() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let left = std::fs::read_to_string("/proc/self/mountinfo")
        .unwrap()
        .lines()
        .filter(|l| {
            l.split_whitespace()
                .nth(4)
                .is_some_and(|p| p.starts_with(mp.to_str().unwrap()))
        })
        .count();
    assert!(r.is_ok() && left == 0, "recursive umount left {left} mounts: {r:?}");
}

#[test]
fn fsopen_fsconfig_fsmount_detached_tmpfs() {
    // Build a tmpfs mount object but never `move_mount` it into the tree, so this is safe even in the initial mount
    // namespace: the detached mount is discarded when its fd drops. Skips when unprivileged.
    let fs = match fsopen("tmpfs", FsopenFlags::empty()) {
        Ok(fd) => fd,
        Err(e @ (Errno::EPERM | Errno::ENOSYS | Errno::EACCES)) => {
            // The only end-to-end drive of fsopen/fsconfig/fsmount in the tree; `coverage.rs` calls fsconfig but
            // discards every result. A root run must not reach this arm.
            assert!(
                std::env::var_os("TRUENAS_ROS_REQUIRE_ROOT").is_none(),
                "TRUENAS_ROS_REQUIRE_ROOT is set but fsopen(tmpfs): {e}"
            );
            return;
        }
        Err(e) => panic!("fsopen(tmpfs): {e}"),
    };
    fsconfig(fs.as_fd(), FsConfig::Create).expect("fsconfig create");
    let mnt = fsmount(fs.as_fd(), FsmountFlags::empty(), MountAttr::empty()).expect("fsmount");
    // The mount fd points at the (detached) tmpfs root directory.
    let st = statx(mnt.as_fd(), "", AtFlags::AT_EMPTY_PATH, StatxMask::BASIC_STATS).expect("statx of mount fd");
    assert!(st.is_dir());
}
