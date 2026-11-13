use std::os::fd::AsRawFd;
use truenas_ros::Error;
use truenas_ros::errno::Errno;
use truenas_ros::mount::idmap::{IdmapCache, IdmapEntry, create_idmap_userns};

fn nsfs_link(fd: std::os::fd::RawFd) -> String {
    std::fs::read_link(format!("/proc/self/fd/{fd}"))
        .unwrap()
        .to_string_lossy()
        .into_owned()
}

fn skip(e: &Error) -> bool {
    matches!(
        e,
        Error::Errno(Errno::EPERM | Errno::ENOSYS | Errno::EACCES | Errno::EINVAL)
    )
}

#[test]
fn idmap_entry_validation_and_accessors() {
    assert!(IdmapEntry::new(0, 0, 0).is_err()); // zero length
    assert!(IdmapEntry::new(u32::MAX, 0, 2).is_err()); // inside overflow
    assert!(IdmapEntry::new(0, u32::MAX, 2).is_err()); // outside overflow
    assert!(IdmapEntry::new(u32::MAX, 0, 1).is_ok()); // MAX+1 == 2^32, ok

    let e = IdmapEntry::new(0, 100_000, 1000).unwrap();
    assert_eq!((e.inside(), e.outside(), e.length()), (0, 100_000, 1000));
}

#[test]
fn create_produces_a_user_namespace_fd() {
    let map = vec![IdmapEntry::new(0, 100_000, 65536).unwrap()];
    let fd = match create_idmap_userns(&map, &map) {
        Ok(fd) => fd,
        Err(e) if skip(&e) => return,
        Err(e) => panic!("create_idmap_userns: {e}"),
    };
    // A pinned user namespace shows up as a `user:[...]` nsfs link.
    assert!(
        nsfs_link(fd.as_raw_fd()).starts_with("user:"),
        "expected a user-namespace fd"
    );
}

#[test]
fn cache_dedups_and_clear_forces_recreation() {
    // A distinct map from the other test to avoid cross-test coupling.
    let map = vec![IdmapEntry::new(0, 300_000, 1000).unwrap()];
    let cache = IdmapCache::new();
    let fd1 = match cache.get_or_create(&map, &map) {
        Ok(fd) => fd,
        Err(e) if skip(&e) => return,
        Err(e) => panic!("get_or_create: {e}"),
    };
    let fd2 = cache.get_or_create(&map, &map).expect("cached lookup");
    // Same underlying namespace...
    assert_eq!(nsfs_link(fd1.as_raw_fd()), nsfs_link(fd2.as_raw_fd()));
    // ...but independent duplicated descriptors.
    assert_ne!(fd1.as_raw_fd(), fd2.as_raw_fd());

    // Clearing drops the cached original; the earlier dup stays valid.
    cache.clear();
    assert!(nsfs_link(fd1.as_raw_fd()).starts_with("user:"));
    let fd3 = cache.get_or_create(&map, &map).expect("recreate after clear");
    assert!(nsfs_link(fd3.as_raw_fd()).starts_with("user:"));
}
