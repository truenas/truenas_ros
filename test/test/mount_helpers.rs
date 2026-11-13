use std::path::Path;
use truenas_ros::mount::{LSMT_ROOT, iter_mountinfo, statmount_path};

#[test]
fn statmount_path_of_root() {
    let sm = statmount_path(Path::new("/")).unwrap();
    assert_eq!(sm.mnt_point.as_deref(), Some(std::path::Path::new("/")));
    assert!(sm.fs_type.is_some());
}

#[test]
fn iter_mountinfo_is_nonempty() {
    let mounts = iter_mountinfo(LSMT_ROOT, false, true).unwrap();
    assert!(!mounts.is_empty());
    assert!(mounts.iter().any(|m| m.mnt_point.is_some()));
}
