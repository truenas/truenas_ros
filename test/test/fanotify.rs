use std::os::fd::{AsFd, AsRawFd};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use truenas_ros::AT_FDCWD;
use truenas_ros::errno::Errno;
use truenas_ros::mount::{
    FsConfig, FsmountFlags, FsopenFlags, MntFlags, MountAttr, MoveMountFlags, fsconfig, fsmount, fsopen, move_mount,
    umount2,
};
use truenas_ros::sync_fs::fanotify::{EventMask, Fanotify, Info, InitFlags, MarkFlags};
use truenas_ros::sync_fs::{AtFlags, OFlag, StatxMask, statx};

/// Detaches the mount on `.0` when dropped, so a failed assertion does not leave it in the namespace every test of
/// the binary shares.
struct Detach(PathBuf);
impl Drop for Detach {
    fn drop(&mut self) {
        let _ = umount2(&self.0, MntFlags::MNT_DETACH);
    }
}

/// Wait up to five seconds for an event that holds `mask` and names mount `id`. Other tests of this binary mount
/// and unmount in the same namespace, so events of other mounts are passed over.
fn wait_for(group: &Fanotify, mask: EventMask, id: u64) {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut buf = vec![0u8; 4096];
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        assert!(!left.is_zero(), "no {mask:?} event for mount {id:#x}");
        let mut pfd = libc::pollfd {
            fd: group.as_fd().as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one valid pollfd that outlives the call.
        unsafe { libc::poll(&mut pfd, 1, left.as_millis() as i32) };
        let events = match group.read(&mut buf) {
            Ok(events) => events,
            Err(Errno::EAGAIN) => continue,
            Err(e) => panic!("read of the group failed with {e}"),
        };
        for event in events {
            let event = event.expect("a well formed event").event;
            assert!(event.raw_fd() < 0, "a mount event carries no fd");
            let named = event.infos().any(|info| matches!(info, Ok(Info::Mount(m)) if m == id));
            if named && event.mask().contains(mask) {
                return;
            }
        }
    }
}

/// Hold a refusal for want of privilege to `TRUENAS_ROS_REQUIRE_ROOT`, so a root run that is refused fails where an
/// unprivileged one skips.
#[track_caller]
fn refusal_is_allowed(what: &str, e: Errno) {
    assert!(
        std::env::var_os("TRUENAS_ROS_REQUIRE_ROOT").is_none(),
        "TRUENAS_ROS_REQUIRE_ROOT is set but {what} failed with {e}"
    );
}

/// A group that marks the mount namespace sees a mount attached and then detached, each naming the unique mount ID
/// statx gives.
///
/// An unprivileged process may make a group that reports mounts, but the group is marked `FANOTIFY_UNPRIV` and
/// refused any mark but an inode's without `CAP_SYS_ADMIN` (`fanotify_init` and `do_fanotify_mark` in
/// `fs/notify/fanotify/fanotify_user.c`). So the refusal comes at the mark, and the test skips there unless
/// `TRUENAS_ROS_REQUIRE_ROOT` says a root run must reach it.
#[test]
fn a_mount_namespace_mark_sees_attach_and_detach() {
    let group = match Fanotify::init(InitFlags::REPORT_MNT | InitFlags::NONBLOCK, OFlag::O_RDONLY) {
        Ok(group) => group,
        Err(e @ (Errno::EPERM | Errno::EINVAL)) => {
            return refusal_is_allowed("fanotify_init", e);
        }
        Err(e) => panic!("fanotify_init failed with {e}"),
    };
    let ns = std::fs::File::open("/proc/self/ns/mnt").unwrap();
    match group.mark(
        MarkFlags::ADD | MarkFlags::MNTNS,
        EventMask::MNT_ATTACH | EventMask::MNT_DETACH,
        &ns,
    ) {
        Ok(()) => {}
        Err(e @ Errno::EPERM) => {
            return refusal_is_allowed("the mark of the namespace", e);
        }
        Err(e) => panic!("the mark of the namespace failed with {e}"),
    }

    let fs = fsopen("tmpfs", FsopenFlags::empty()).expect("fsopen");
    fsconfig(fs.as_fd(), FsConfig::Create).expect("fsconfig");
    let mnt = fsmount(fs.as_fd(), FsmountFlags::empty(), MountAttr::empty()).expect("fsmount");
    let tmp = truenas_ros::tempdir().unwrap();
    let mp = tmp.path().join("mp");
    std::fs::create_dir(&mp).unwrap();
    move_mount(mnt.as_fd(), "", AT_FDCWD, &mp, MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH).expect("move_mount");
    // The fsmount descriptor pins the mount, so it goes before the unmount.
    drop(mnt);
    let _detach = Detach(mp.clone());
    let id = mount_id(&mp);

    wait_for(&group, EventMask::MNT_ATTACH, id);
    umount2(&mp, MntFlags::MNT_DETACH).expect("umount2");
    wait_for(&group, EventMask::MNT_DETACH, id);
}

/// A group that reports neither FIDs nor mounts hands each event's object over as a descriptor the reader owns,
/// here the file this test opened, as the inode a statx of it gives shows.
///
/// Such a group needs `CAP_SYS_ADMIN`, so it skips unless `TRUENAS_ROS_REQUIRE_ROOT` says a root run must reach it.
#[test]
fn a_group_without_fids_hands_over_the_object_fd() {
    let group = match Fanotify::init(InitFlags::NONBLOCK, OFlag::O_RDONLY) {
        Ok(group) => group,
        Err(e @ Errno::EPERM) => {
            return refusal_is_allowed("fanotify_init", e);
        }
        Err(e) => panic!("fanotify_init failed with {e}"),
    };
    let tmp = truenas_ros::tempdir().unwrap();
    let file = tmp.path().join("watched");
    std::fs::write(&file, b"x").unwrap();
    group
        .mark_path(MarkFlags::ADD, EventMask::OPEN, AT_FDCWD, &file)
        .expect("mark of the file");
    drop(std::fs::File::open(&file).unwrap());
    let ino = statx(AT_FDCWD, &file, AtFlags::empty(), StatxMask::INO).unwrap().ino();

    let mut buf = vec![0u8; 4096];
    let mut events = group.read(&mut buf).expect("an event is queued");
    let read = events.next().expect("one event").expect("well formed");
    assert!(read.event.mask().contains(EventMask::OPEN));
    let fd = read.fd.expect("the event carries the file");
    let st = statx(fd.as_fd(), "", AtFlags::AT_EMPTY_PATH, StatxMask::INO).expect("statx of the event's fd");
    assert_eq!(st.ino(), ino);
}

fn mount_id(path: &Path) -> u64 {
    statx(AT_FDCWD, path, AtFlags::empty(), StatxMask::MNT_ID_UNIQUE)
        .expect("statx of the mount point")
        .mnt_id()
}
