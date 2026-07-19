//! Privileged, ZFS-backed integration tests: real NFSv4 and POSIX ACLs on ZFS
//! datasets, plus ZFS snapshot detection — the paths that a plain tmpfs cannot
//! exercise.
//!
//! Each test resolves its dataset directory from, in order: the
//! `TRUENAS_ROS_{NFS4,POSIX}_DATASET` environment variables, then the
//! `/NFSV4ACL` / `/POSIXACL` convention (matching the Python `truenas_pyos`
//! fixtures). When no such dataset is present the test **skips**, so the suite
//! stays green in an unprivileged sandbox and only does real work in CI (see
//! `.github/workflows/scripts/setup-test-zfs.sh`).
#![cfg(all(target_os = "linux", feature = "acl"))]

use std::os::fd::AsFd;
use std::path::{Path, PathBuf};
use truenas_ros::sync_fs::acl::{
    fgetacl, fsetacl, Acl, Nfs4Ace, Nfs4AceType, Nfs4Acl, Nfs4AclFlag,
    Nfs4Flag, Nfs4Perm, Nfs4Who, PosixAce, PosixAcl, PosixPerm, PosixTag,
};
use truenas_ros::sync_fs::xattr::fgetxattr;

/// Resolve an ACL-typed dataset directory, or `None` to skip the test.
fn dataset(env_var: &str, fallback: &str) -> Option<PathBuf> {
    let dir = std::env::var_os(env_var)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(fallback));
    dir.is_dir().then_some(dir)
}

fn nfs4_dir() -> Option<PathBuf> {
    dataset("TRUENAS_ROS_NFS4_DATASET", "/NFSV4ACL")
}

fn posix_dir() -> Option<PathBuf> {
    dataset("TRUENAS_ROS_POSIX_DATASET", "/POSIXACL")
}

/// A fresh, unique R/W test file under `dir`.
fn scratch_file(dir: &Path, tag: &str) -> (PathBuf, std::fs::File) {
    let p = dir.join(format!("rostest_{tag}_{}", std::process::id()));
    let _ = std::fs::remove_file(&p);
    std::fs::write(&p, b"acl test").unwrap();
    let f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&p)
        .unwrap();
    (p, f)
}

#[test]
fn nfs4_codec_and_named_user_roundtrip() {
    let Some(dir) = nfs4_dir() else {
        return;
    };
    let (path, f) = scratch_file(&dir, "nfs4");

    let acl = match fgetacl(f.as_fd()) {
        Ok(Acl::Nfs4(a)) => a,
        // The path exists but isn't an NFS4-ACL filesystem here — skip rather
        // than fail (e.g. a placeholder `/NFSV4ACL` dir on a non-ZFS host).
        _ => {
            let _ = std::fs::remove_file(&path);
            return;
        }
    };
    // Whatever the fresh file carries (it may inherit entries from the parent),
    // our codec reproduces the kernel's exact bytes.
    let raw0 = fgetxattr(f.as_fd(), "system.nfs4_acl_xdr").unwrap();
    assert_eq!(acl.to_xattr(), raw0, "codec must round-trip live ZFS bytes");

    // Append a named-user ALLOW to ZFS's own (valid) entries and write it back.
    let uid = 8_675_309;
    let mut aces = acl.aces.clone();
    aces.push(Nfs4Ace::new(
        Nfs4AceType::Allow,
        Nfs4Flag::empty(),
        Nfs4Perm::READ_DATA
            | Nfs4Perm::READ_ATTRIBUTES
            | Nfs4Perm::READ_ACL
            | Nfs4Perm::SYNCHRONIZE,
        Nfs4Who::Named,
        uid,
    ));
    let updated = Acl::Nfs4(Nfs4Acl::from_aces(aces, Nfs4AclFlag::empty()));
    fsetacl(f.as_fd(), Some(&updated)).expect("fsetacl nfs4");

    // Read back: no longer trivial, the named user is present, and our encoder
    // byte-exactly reproduces what the kernel now stores.
    let back = match fgetacl(f.as_fd()) {
        Ok(Acl::Nfs4(a)) => a,
        other => panic!("expected nfs4, got {other:?}"),
    };
    assert!(!back.trivial());
    assert!(back
        .aces
        .iter()
        .any(|a| a.who_type == Nfs4Who::Named && a.who_id == uid));
    let raw = fgetxattr(f.as_fd(), "system.nfs4_acl_xdr").unwrap();
    assert_eq!(back.to_xattr(), raw, "encoder must match kernel bytes");

    // Removing the ACL restores triviality.
    fsetacl(f.as_fd(), None).expect("fsetacl None");
    match fgetacl(f.as_fd()) {
        Ok(Acl::Nfs4(a)) => assert!(a.trivial()),
        other => panic!("expected trivial nfs4, got {other:?}"),
    }
    let _ = std::fs::remove_file(&path);
}

#[test]
fn posix_named_user_roundtrip_on_zfs() {
    let Some(dir) = posix_dir() else {
        return;
    };
    let (path, f) = scratch_file(&dir, "posix");

    // Fresh file: a trivial ACL synthesised from the mode bits.
    let acl = match fgetacl(f.as_fd()) {
        Ok(Acl::Posix(a)) => a,
        // Not a POSIX-ACL filesystem here — skip.
        _ => {
            let _ = std::fs::remove_file(&path);
            return;
        }
    };
    assert!(acl.trivial());

    // Add a named user (which requires a MASK) and write it back.
    let uid = 4_200;
    let mut aces = acl.access.clone();
    aces.push(PosixAce {
        tag: PosixTag::User,
        perms: PosixPerm::READ | PosixPerm::WRITE,
        id: uid,
        default: false,
    });
    aces.push(PosixAce {
        tag: PosixTag::Mask,
        perms: PosixPerm::READ | PosixPerm::WRITE,
        id: -1,
        default: false,
    });
    let updated = Acl::Posix(PosixAcl::from_aces(aces));
    fsetacl(f.as_fd(), Some(&updated)).expect("fsetacl posix");

    let back = match fgetacl(f.as_fd()) {
        Ok(Acl::Posix(a)) => a,
        other => panic!("expected posix, got {other:?}"),
    };
    assert!(back
        .access
        .iter()
        .any(|a| a.tag == PosixTag::User && a.id == uid));
    let raw = fgetxattr(f.as_fd(), "system.posix_acl_access").unwrap();
    assert_eq!(back.access_bytes(), raw, "encoder must match kernel bytes");

    let _ = fsetacl(f.as_fd(), None);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn posix_default_acl_on_directory() {
    let Some(dir) = posix_dir() else {
        return;
    };
    let sub = dir.join(format!("rostest_dir_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&sub);
    std::fs::create_dir(&sub).unwrap();
    let d = std::fs::File::open(&sub).unwrap();

    let base = match fgetacl(d.as_fd()) {
        Ok(Acl::Posix(a)) => a,
        _ => {
            let _ = std::fs::remove_dir_all(&sub);
            return;
        }
    };
    // Access entries plus a default (inheritable) copy of them.
    let mut aces = base.access.clone();
    for a in base.access.clone() {
        aces.push(PosixAce { default: true, ..a });
    }
    fsetacl(d.as_fd(), Some(&Acl::Posix(PosixAcl::from_aces(aces))))
        .expect("fsetacl default");
    match fgetacl(d.as_fd()) {
        Ok(Acl::Posix(a)) => assert!(a.default.is_some(), "default ACL lost"),
        other => panic!("expected posix, got {other:?}"),
    }
    let _ = fsetacl(d.as_fd(), None);
    let _ = std::fs::remove_dir_all(&sub);
}

/// Snapshot the NFS4 dataset via the `zfs` CLI and confirm the auto-mounted
/// snapshot under `.zfs/snapshot/` is recognised. Needs `TRUENAS_ROS_NFS4_DS`
/// (the dataset name, set by the provisioning script) and the `mount` feature.
#[cfg(feature = "mount")]
#[test]
fn zfs_snapshot_is_detected() {
    use truenas_ros::mount::{is_zfs_snapshot, statmount_path};
    let (Some(dir), Ok(ds)) =
        (nfs4_dir(), std::env::var("TRUENAS_ROS_NFS4_DS"))
    else {
        return;
    };
    let snap = format!("{ds}@rostest_{}", std::process::id());
    let zfs =
        |args: &[&str]| std::process::Command::new("zfs").args(args).status();
    let _ = zfs(&["destroy", "-r", &snap]);
    if !matches!(zfs(&["snapshot", &snap]), Ok(s) if s.success()) {
        return; // couldn't snapshot (not root / not our dataset)
    }
    let snap_dir = format!("rostest_{}", std::process::id());
    let snap_path = dir.join(".zfs/snapshot").join(&snap_dir);
    // Access the path first to trigger the ctldir automount; statmount_path's
    // O_PATH open does not trigger it on its own.
    let _ = std::fs::read_dir(&snap_path).map(|d| d.count());
    let sm = statmount_path(&snap_path);
    let _ = zfs(&["destroy", "-r", &snap]);
    if let Ok(sm) = sm {
        // Snapshot detection needs `sb_source`, which requires a new-enough
        // kernel *and* ZFS wiring it up for the snapshot mount. Where it is
        // unavailable, detection is gracefully disabled (exactly as
        // `truenas_pyos` documents), so only assert when it was reported.
        if sm.sb_source.is_some() {
            assert!(
                is_zfs_snapshot(&sm),
                "snapshot not detected: sb_source={:?} mnt_point={:?}",
                sm.sb_source,
                sm.mnt_point
            );
        }
    }
}
