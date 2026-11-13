use std::os::fd::AsFd;
use std::path::Path;
use truenas_ros::mount::{
    Atime, FsConfig, LSMT_ROOT, MntFlags, MntPropagation, MountAttr, MountSetattr, MoveMountFlags, OpenTreeFlags,
    StatmountMask, UmountOptions, fsconfig, is_zfs_snapshot, listmount, mount_setattr, move_mount, open_mount_by_id,
    open_tree, statmount, statmount_path, umount, umount2,
};
use truenas_ros::sync_fs::{AtFlags, OFlag, StatxMask, statx};
use truenas_ros::{AT_FDCWD, Error};

fn root_id() -> u64 {
    statx(AT_FDCWD, "/", AtFlags::empty(), StatxMask::MNT_ID_UNIQUE)
        .unwrap()
        .mnt_id()
}

#[test]
fn open_mount_by_id_opens_root() {
    let fd = open_mount_by_id(root_id(), OFlag::O_DIRECTORY | OFlag::O_RDONLY).unwrap();
    let st = statx(fd.as_fd(), "", AtFlags::AT_EMPTY_PATH, StatxMask::TYPE).unwrap();
    assert!(st.is_dir());
}

#[test]
fn statmount_mask_filtering_and_invalid_id() {
    let sm = statmount(root_id(), StatmountMask::MNT_BASIC).unwrap();
    assert!(sm.mnt_id.is_some());
    assert!(sm.mnt_point.is_none());
    assert!(sm.fs_type.is_none());
    assert!(statmount(u64::MAX - 1, StatmountMask::MNT_BASIC).is_err());
}

#[test]
fn listmount_forward_and_reverse() {
    let fwd = listmount(LSMT_ROOT, false).unwrap();
    let rev = listmount(LSMT_ROOT, true).unwrap();
    assert!(!fwd.is_empty());
    assert_eq!(fwd.len(), rev.len());
}

#[test]
fn is_zfs_snapshot_false_for_root() {
    assert!(!is_zfs_snapshot(&statmount_path(Path::new("/")).unwrap()));
}

#[test]
fn statmount_path_rejects_symlink() {
    let dir = truenas_ros::tempdir().unwrap();
    std::os::unix::fs::symlink("/", dir.path().join("l")).unwrap();
    assert!(matches!(
        statmount_path(&dir.path().join("l")).unwrap_err(),
        Error::SymlinkInPath { .. }
    ));
}

#[test]
fn umount_error_paths() {
    assert!(umount2("/no/such/mount/xyz", MntFlags::empty()).is_err());
    let dir = truenas_ros::tempdir().unwrap();
    // Recursive umount of a non-mountpoint -> validation error.
    assert!(matches!(
        umount(
            dir.path(),
            UmountOptions {
                recursive: true,
                ..Default::default()
            }
        )
        .unwrap_err(),
        Error::Validation(_)
    ));
    // Non-recursive umount of a non-mountpoint -> syscall error.
    assert!(umount(dir.path(), UmountOptions::default()).is_err());
}

/// The mountpoint of a mount with no children of its own, so a recursive umount of it has nothing to tear down.
/// `None` if the namespace has no such mount or its mountpoint is unreadable.
fn leaf_mountpoint() -> Option<std::path::PathBuf> {
    listmount(LSMT_ROOT, false).unwrap().into_iter().find_map(|id| {
        listmount(id, false).ok().filter(|kids| kids.is_empty())?;
        statmount(id, StatmountMask::MNT_POINT).ok()?.mnt_point
    })
}

#[test]
fn recursive_umount_rejects_a_symlinked_mountpoint() {
    let Some(point) = leaf_mountpoint() else {
        panic!("no childless mount in this namespace");
    };
    let dir = truenas_ros::tempdir().unwrap();
    let link = dir.path().join("l");
    std::os::unix::fs::symlink(&point, &link).unwrap();
    // The symlink is not itself a mountpoint, so validation fails before any umount2 - a syscall error here would
    // mean it got that far.
    assert!(matches!(
        umount(
            &link,
            UmountOptions {
                recursive: true,
                ..Default::default()
            }
        )
        .unwrap_err(),
        Error::Validation(_)
    ));
}

#[test]
fn privileged_wrappers_are_callable() {
    // Each wrapper builds its argument struct and issues its syscall, and that path is under test, not the kernel's
    // answer.
    //
    // **Every target is a name that cannot exist.** This test runs as root in the QEMU lane, so a real target such as
    // `/` could be remounted read-only by an edit that dropped the idmap. Against an absent path the syscall can only
    // fail, so the outcome is assertable too.
    let dir = truenas_ros::tempdir().unwrap();
    let gone = dir.path().join("no-such-mount");
    assert!(open_tree(AT_FDCWD, &gone, OpenTreeFlags::OPEN_TREE_CLONE).is_err());
    assert!(move_mount(AT_FDCWD, &gone, AT_FDCWD, &gone, MoveMountFlags::empty()).is_err());
    let anchor = std::fs::File::open("/").unwrap();
    let attr = MountSetattr::new()
        .set(MountAttr::RDONLY)
        .clear(MountAttr::NODEV)
        .atime(Atime::Noatime)
        .propagation(MntPropagation::MS_SLAVE)
        .idmap(anchor.as_fd());
    assert!(mount_setattr(AT_FDCWD, &gone, AtFlags::empty(), &attr).is_err());
}

#[test]
fn fsconfig_variants_reach_the_syscall() {
    use truenas_ros::errno::Errno;
    // `fsopen` needs `CAP_SYS_ADMIN`, so drive `fsconfig` against a plain fd instead. Each match arm must reach the
    // syscall, which refuses a descriptor that is not a filesystem context with `EINVAL`.
    //
    // The errno is the assertion. Only `Create` is driven anywhere else, by a root-only test, so a short-circuit that
    // answers `Ok` without the syscall would pass every target but this one.
    let f = std::fs::File::open("/").unwrap();
    let fd = f.as_fd();
    for (what, got) in [
        ("Flag", fsconfig(fd, FsConfig::Flag { key: "ro" })),
        ("String", fsconfig(fd, FsConfig::String { key: "src", value: "x" })),
        ("Binary", fsconfig(fd, FsConfig::Binary { key: "k", value: b"v" })),
        ("Fd", fsconfig(fd, FsConfig::Fd { key: "fd", fd })),
        ("Create", fsconfig(fd, FsConfig::Create)),
        ("Reconfigure", fsconfig(fd, FsConfig::Reconfigure)),
        ("CreateExcl", fsconfig(fd, FsConfig::CreateExcl)),
    ] {
        assert_eq!(
            got,
            Err(Errno::EINVAL),
            "fsconfig({what}) on a non-context fd must be refused by \
                 the kernel, not answered locally"
        );
    }
}
