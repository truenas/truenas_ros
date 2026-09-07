//! Privileged, ZFS-backed integration tests: real NFSv4 and POSIX ACLs on ZFS
//! datasets, plus ZFS snapshot detection - the paths that a plain tmpfs cannot
//! exercise.
//!
//! Each test resolves its dataset directory from, in order: the
//! `TRUENAS_ROS_{NFS4,POSIX}_DATASET` environment variables, then the
//! `/NFSV4ACL` / `/POSIXACL` convention (matching the Python `truenas_pyos`
//! fixtures). When no such dataset is present the test **skips**, so the suite
//! stays green in an unprivileged sandbox and only does real work in CI (see
//! `.github/workflows/scripts/setup-test-zfs.sh`).
#![cfg(all(
    target_os = "linux",
    feature = "acl",
    feature = "xattr",
    feature = "sync-fs"
))]

use std::os::fd::AsFd;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use truenas_ros::sync_fs::acl::{
    Acl, Nfs4Ace, Nfs4AceType, Nfs4Acl, Nfs4AclFlag, Nfs4Flag, Nfs4Perm,
    Nfs4Who, PosixAce, PosixAcl, PosixPerm, PosixTag, fgetacl, fsetacl,
};
use truenas_ros::sync_fs::xattr::fgetxattr;
use truenas_ros::sync_fs::{
    AtFlags, Mode, OFlag, OpenHow, RenameFlags, ZfsAttr, fget_zfs_attrs,
    fset_zfs_attrs, linkat, openat2, renameat2,
};

/// Skip the calling test. `TRUENAS_ROS_REQUIRE_ZFS` turns the skip into a
/// failure, so a fixture that stopped being provisioned cannot report a green
/// suite that tested nothing.
#[track_caller]
fn skip(why: &str) {
    assert!(
        std::env::var_os("TRUENAS_ROS_REQUIRE_ZFS").is_none(),
        "TRUENAS_ROS_REQUIRE_ZFS is set but {why}"
    );
}

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
        return skip("no NFSv4-ACL dataset");
    };
    let (path, f) = scratch_file(&dir, "nfs4");

    let acl = match fgetacl(f.as_fd()) {
        Ok(Acl::Nfs4(a)) => a,
        // The path exists but isn't an NFS4-ACL filesystem here - skip rather
        // than fail (e.g. a placeholder `/NFSV4ACL` dir on a non-ZFS host).
        _ => {
            let _ = std::fs::remove_file(&path);
            return skip(
                "the NFSv4 dataset path is not an NFSv4-ACL filesystem",
            );
        }
    };
    // Whatever the fresh file carries (it may inherit entries from the parent),
    // our codec reproduces the kernel's exact bytes.
    let raw0 = fgetxattr(f.as_fd(), "system.nfs4_acl_xdr").unwrap();
    assert_eq!(
        acl.to_xattr().unwrap(),
        raw0,
        "codec must round-trip live ZFS bytes"
    );

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
    assert!(
        back.aces
            .iter()
            .any(|a| a.who_type == Nfs4Who::Named && a.who_id == uid)
    );
    let raw = fgetxattr(f.as_fd(), "system.nfs4_acl_xdr").unwrap();
    assert_eq!(
        back.to_xattr().unwrap(),
        raw,
        "encoder must match kernel bytes"
    );

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
        return skip("no POSIX-ACL dataset");
    };
    let (path, f) = scratch_file(&dir, "posix");

    // Fresh file: a trivial ACL synthesised from the mode bits.
    let acl = match fgetacl(f.as_fd()) {
        Ok(Acl::Posix(a)) => a,
        // Not a POSIX-ACL filesystem here - skip.
        _ => {
            let _ = std::fs::remove_file(&path);
            return skip(
                "the POSIX dataset path is not a POSIX-ACL filesystem",
            );
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
    assert!(
        back.access
            .iter()
            .any(|a| a.tag == PosixTag::User && a.id == uid)
    );
    let raw = fgetxattr(f.as_fd(), "system.posix_acl_access").unwrap();
    assert_eq!(
        back.access_bytes().unwrap(),
        raw,
        "encoder must match kernel bytes"
    );

    let _ = fsetacl(f.as_fd(), None);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn posix_default_acl_on_directory() {
    let Some(dir) = posix_dir() else {
        return skip("no POSIX-ACL dataset");
    };
    let sub = dir.join(format!("rostest_dir_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&sub);
    std::fs::create_dir(&sub).unwrap();
    let d = std::fs::File::open(&sub).unwrap();

    let base = match fgetacl(d.as_fd()) {
        Ok(Acl::Posix(a)) => a,
        _ => {
            let _ = std::fs::remove_dir_all(&sub);
            return skip(
                "the POSIX dataset path is not a POSIX-ACL filesystem",
            );
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
        return skip("no NFSv4 dataset or TRUENAS_ROS_NFS4_DS unset");
    };
    let snap = format!("{ds}@rostest_{}", std::process::id());
    let zfs =
        |args: &[&str]| std::process::Command::new("zfs").args(args).status();
    let _ = zfs(&["destroy", "-r", &snap]);
    if !matches!(zfs(&["snapshot", &snap]), Ok(s) if s.success()) {
        return skip("could not snapshot (not root, or not our dataset)");
    }
    let snap_dir = format!("rostest_{}", std::process::id());
    let snap_path = dir.join(".zfs/snapshot").join(&snap_dir);
    // Access the path first to trigger the ctldir automount; statmount_path's
    // O_PATH open does not trigger it on its own.
    let _ = std::fs::read_dir(&snap_path).map(|d| d.count());
    let sm = statmount_path(&snap_path);
    let _ = zfs(&["destroy", "-r", &snap]);
    // Both degradations are announced. Held inside two silent `if`s, this
    // test returned green whether it had asserted anything or not, so
    // `REQUIRE_ZFS` could not see the fixture go missing under it - which
    // is the whole job of the gate.
    let Ok(sm) = sm else {
        return skip("statmount of the snapshot mount failed");
    };
    // Snapshot detection needs `sb_source`, which requires a new-enough
    // kernel *and* ZFS wiring it up for the snapshot mount. Where it is
    // unavailable, detection is gracefully disabled (exactly as
    // `truenas_pyos` documents), so only assert when it was reported.
    if sm.sb_source.is_none() {
        return skip("the snapshot mount reported no sb_source");
    }
    assert!(
        is_zfs_snapshot(&sm),
        "snapshot not detected: sb_source={:?} mnt_point={:?}",
        sm.sb_source,
        sm.mnt_point
    );
}

// ---------------------------------------------------------------------------
// ZFS_READONLY / ZFS_IMMUTABLE - the file-attribute semantics the S3 front's
// read-only objects lean on. Each of these is a **pin on fork behaviour**,
// probed rather than assumed (the `unix_peercred` discipline): the design
// sets `ZfsAttr::READONLY` on a staged object before it first gains a name
// and `READONLY | IMMUTABLE` on superseded versions, and every step of that
// choreography rests on a semantic the shipped ZFS could change under a
// train bump. A red here is the platform moving, and names the doc or the
// landing order that has to move with it.
// ---------------------------------------------------------------------------

/// Fork, become `nobody`, and try to open `path` for writing.
///
/// `Ok(())` for a successful open; `Err(errno)` with the child's errno
/// otherwise. The children exist because this suite runs as root and DAC
/// never denies root anything on the fallback path - the writers the
/// read-only flag is aimed at (NFS clients, local processes) arrive as
/// unprivileged uids, so the probe must too. Raw syscalls in the child, no
/// allocation after the fork (the path is a `CString` made before it), and
/// `_exit` so no parent state is dropped twice - the `CredBroker` child's
/// own rules.
fn open_for_write_as_nobody(path: &Path) -> Result<(), i32> {
    let c = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    // SAFETY: fork; the child makes only async-signal-safe syscalls
    // (setgroups/setresgid/setresuid/open/_exit) and allocates nothing.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork");
    if pid == 0 {
        // SAFETY: raw credential syscalls in the single-threaded child.
        // setresuid to a non-zero uid clears the effective capability set,
        // so the child cannot ride CAP_DAC_OVERRIDE through the check.
        unsafe {
            libc::syscall(libc::SYS_setgroups, 0usize, std::ptr::null::<u32>());
            libc::syscall(libc::SYS_setresgid, 65534, 65534, 65534);
            libc::syscall(libc::SYS_setresuid, 65534, 65534, 65534);
            let fd = libc::open(c.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC);
            libc::_exit(if fd >= 0 {
                0
            } else {
                *libc::__errno_location()
            });
        }
    }
    let mut status = 0;
    // SAFETY: valid pid and status pointer.
    assert!(
        unsafe { libc::waitpid(pid, &mut status, 0) } == pid,
        "waitpid"
    );
    assert!(libc::WIFEXITED(status), "probe child did not exit");
    match libc::WEXITSTATUS(status) {
        0 => Ok(()),
        e => Err(e),
    }
}

/// Read-modify-write a flag onto a file's ZFS attributes.
///
/// `ZFS_IOC_SETDOSFLAGS` takes the whole visible mask, not a delta
/// (`FLAG_CHANGE` in `__zpl_ioctl_setdosflags` diffs every bit against the
/// argument), so a bare `fset_zfs_attrs(fd, READONLY)` would also *clear*
/// the `ARCHIVE` bit ZFS set at create. This is the idiom a consumer must
/// use, so it is the idiom the pins use.
fn add_zfs_attrs(f: &std::fs::File, add: ZfsAttr) -> ZfsAttr {
    let cur = fget_zfs_attrs(f.as_fd()).expect("fget_zfs_attrs");
    fset_zfs_attrs(f.as_fd(), cur | add).expect("fset_zfs_attrs");
    let now = fget_zfs_attrs(f.as_fd()).expect("fget_zfs_attrs readback");
    assert_eq!(now, cur | add, "the setter is absolute and lost a bit");
    now
}

/// The descriptor that holds a file open keeps writing after `READONLY`
/// lands - the fchmod(0444) shape `zfs_zaccess_common` documents and
/// `zfs_write` implements by exempting the flag ("Intentionally allow
/// ZFS_READONLY through here", `zfs_vnops.c`). The S3 front's PUT flags the
/// staged object while its own descriptor still owes writes, so a platform
/// that starts checking the flag per-write breaks every upload: this pin is
/// what turns that into a red lane instead of a fleet incident.
///
/// The second half is the one write channel that never consults
/// `zfs_write`: dirtying pages through a shared writable mapping. `zfs_map`
/// refuses to create one over a flagged file - unconditionally, root
/// included, on every acltype - while a private mapping stays allowed
/// (copy-on-write publishes nothing). Both directions are asserted so the
/// refusal is pinned to the sharing, not to mapping in general.
#[test]
fn a_readonly_flag_is_fchmod_shaped_for_the_descriptor_holding_it() {
    let Some(dir) = nfs4_dir() else {
        return skip("no NFSv4-ACL dataset");
    };
    let (path, f) = scratch_file(&dir, "ro_fd");
    if fget_zfs_attrs(f.as_fd()).is_err() {
        let _ = std::fs::remove_file(&path);
        return skip("the NFSv4 dataset path does not answer ZFS ioctls");
    }

    use std::os::unix::fs::FileExt;
    f.write_at(b"before", 0).expect("control write");

    add_zfs_attrs(&f, ZfsAttr::READONLY);

    f.write_at(b"after ", 0)
        .expect("a held descriptor must keep writing once READONLY lands");
    f.sync_all().expect("fsync through the held descriptor");

    // A fresh *read* open is untouched; reads were never in question.
    let _ro = std::fs::File::open(&path).expect("fresh O_RDONLY open");

    // A shared writable mapping is refused at creation - `zfs_map` checks
    // the flag at the vnop with no privilege fallback and no acltype gate,
    // so this holds even though the suite runs as root - and it is asked
    // through `f`, the descriptor the flag grandfathered for write(2):
    // the grandfathering covers writes, not new mappings. (Through a
    // read-only descriptor the VFS answers EACCES before ZFS is ever
    // consulted - a writable shared mapping needs a writable fd - so
    // only this fd reaches the vnop verdict at all.)
    // SAFETY: mmap with a length inside the file; the result is checked
    // before use and never dereferenced on failure.
    let shared = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            4,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            f.as_fd().as_raw_fd(),
            0,
        )
    };
    assert_eq!(
        shared,
        libc::MAP_FAILED,
        "a shared writable mapping of a READONLY file must be refused"
    );
    // SAFETY: errno read directly after the failed call on this thread.
    let e = unsafe { *libc::__errno_location() };
    assert_eq!(e, libc::EPERM, "zfs_map answers EPERM, got errno {e}");

    // SAFETY: as above; a private writable mapping is the control - its
    // dirty pages never publish, and `zfs_map` allows it.
    let private = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            4,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE,
            f.as_fd().as_raw_fd(),
            0,
        )
    };
    assert_ne!(
        private,
        libc::MAP_FAILED,
        "the refusal must be about sharing, not about mapping"
    );
    // SAFETY: unmapping the mapping created above.
    unsafe { libc::munmap(private, 4) };

    // A trusted.* xattr still lands: `xattr_permission`'s trusted branch
    // is `CAP_SYS_ADMIN` alone, with no inode write check (`fs/xattr.c`),
    // and the flag's own deny is `WRITE_MASK_DATA` through `zfs_zaccess`,
    // which a trusted write never consults. The S3 front re-stamps a
    // superseded predecessor's index record while that predecessor is
    // READONLY, so this is load-bearing, not a curiosity.
    {
        use truenas_ros::sync_fs::xattr::{XattrFlags, fsetxattr};
        fsetxattr(f.as_fd(), "trusted.rostest_ro", b"v", XattrFlags::empty())
            .expect(
                "trusted.* must survive READONLY - the restamp depends \
                     on it",
            );
    }

    // Deletion needs no clearing: READONLY guards data, not names. This is
    // why DeleteObject carries no unlatch step.
    std::fs::remove_file(&path)
        .expect("unlink of a READONLY file needs no clear step");
}

/// A `READONLY` inode gains and loses names freely: first name by
/// `linkat(AT_EMPTY_PATH)`, more names by plain link, moves by rename, and
/// rename *over* a flagged victim - the supersede shape, where the current
/// object is READONLY and a new PUT replaces its name.
///
/// The first-name half is the load-bearing one and is **fork behaviour, not
/// doctrine**: this tree's Linux `zfs_link` carries no pflag check, while
/// FreeBSD's refuses APPENDONLY|IMMUTABLE|READONLY sources outright
/// (`module/os/freebsd/zfs/zfs_vnops_os.c`). A unification that imports the
/// FreeBSD check turns this red - and the fix is to move the flag *after*
/// the first link, not to delete this test.
#[test]
fn a_readonly_inode_gains_and_loses_names_freely() {
    let Some(dir) = nfs4_dir() else {
        return skip("no NFSv4-ACL dataset");
    };
    let dirf = std::fs::File::open(&dir).expect("open dataset dir");
    if fget_zfs_attrs(dirf.as_fd()).is_err() {
        return skip("the NFSv4 dataset path does not answer ZFS ioctls");
    }

    // The staged shape: an unnamed inode born in the directory the name
    // will land in.
    let staged: std::fs::File = openat2(
        dirf.as_fd(),
        ".",
        OpenHow::new()
            .flags(OFlag::O_TMPFILE | OFlag::O_RDWR)
            .mode(Mode::from_bits_truncate(0o600)),
    )
    .expect("stage an unnamed inode")
    .into();
    use std::os::unix::fs::FileExt;
    staged.write_at(b"body", 0).expect("write the body");
    add_zfs_attrs(&staged, ZfsAttr::READONLY);

    let pid = std::process::id();
    let (n1, n2, n3) = (
        format!("rostest_names_a_{pid}"),
        format!("rostest_names_b_{pid}"),
        format!("rostest_names_c_{pid}"),
    );
    for n in [&n1, &n2, &n3] {
        let _ = std::fs::remove_file(dir.join(n));
    }

    // Born read-only, then named: the zero-window landing order.
    linkat(&staged, "", &dirf, n1.as_str(), AtFlags::AT_EMPTY_PATH).expect(
        "first name for a READONLY inode (Linux zfs_link has no \
                 pflag check; see the FreeBSD divergence above)",
    );
    // More names, and a move - a flagged *source* everywhere.
    linkat(&dirf, n1.as_str(), &dirf, n2.as_str(), AtFlags::empty())
        .expect("second name for a READONLY file");
    renameat2(&dirf, n2.as_str(), &dirf, n3.as_str(), RenameFlags::empty())
        .expect("rename of a READONLY source");

    // Supersede: an unflagged newcomer replaces the name of a READONLY
    // incumbent. The victim's flag must not defend the *name* - a current
    // object is only ever READONLY (never IMMUTABLE) precisely so this
    // rename can happen.
    std::fs::write(dir.join(format!("rostest_names_new_{pid}")), b"v2")
        .expect("newcomer");
    renameat2(
        &dirf,
        format!("rostest_names_new_{pid}").as_str(),
        &dirf,
        n1.as_str(),
        RenameFlags::empty(),
    )
    .expect("rename over a READONLY victim (the supersede shape)");

    // The flag rode along: it is inode state, not name state.
    let via_n3 = std::fs::File::open(dir.join(&n3)).expect("open via n3");
    assert!(
        fget_zfs_attrs(via_n3.as_fd())
            .expect("fget via the moved name")
            .contains(ZfsAttr::READONLY),
        "READONLY must survive link and rename"
    );

    for n in [&n1, &n3] {
        std::fs::remove_file(dir.join(n)).expect("cleanup unlink");
    }
}

/// Where the flag actually denies, and where it documentedly does not.
///
/// An ordinary open-for-write is asked of ZFS at all only on an
/// `acltype=nfsv4` dataset whose file carries a **non-trivial** ACL;
/// everything else is answered from the mode alone. That scope is the
/// platform contract the S3 front documents ("NFSv4 required"), and this
/// test is the contract in executable form: the nfsv4 half proves the deny
/// where it is promised, and the posix half proves the gap where it is
/// documented.
///
/// **A red on either half is the platform moving, not this test rotting.**
/// If the posix half's open starts failing, or the root open below starts
/// failing, the fork has grown enforcement - update `ZfsAttr::READONLY`'s
/// rustdoc and the S3 front's requirement documentation to match, then the
/// assertions.
#[test]
fn readonly_denies_a_fresh_writer_exactly_where_documented() {
    // --- the enforced half: acltype=nfsv4, non-trivial ACL ---------------
    let Some(dir) = nfs4_dir() else {
        return skip("no NFSv4-ACL dataset");
    };
    let (path, f) = scratch_file(&dir, "ro_deny");
    let acl = match fgetacl(f.as_fd()) {
        Ok(Acl::Nfs4(a)) => a,
        _ => {
            let _ = std::fs::remove_file(&path);
            return skip(
                "the NFSv4 dataset path is not an NFSv4-ACL filesystem",
            );
        }
    };

    // Grant `nobody` write through the ACL - a named-user ACE, which also
    // forces the ACL non-trivial, which is what gets the next open asked of
    // ZFS at all. Asserted, not hoped: `trivial()` is the same verdict the
    // kernel short-circuits on.
    let mut aces = acl.aces.clone();
    aces.push(Nfs4Ace::new(
        Nfs4AceType::Allow,
        Nfs4Flag::empty(),
        Nfs4Perm::READ_DATA
            | Nfs4Perm::WRITE_DATA
            | Nfs4Perm::APPEND_DATA
            | Nfs4Perm::READ_ATTRIBUTES
            | Nfs4Perm::SYNCHRONIZE,
        Nfs4Who::Named,
        65534,
    ));
    let updated = Acl::Nfs4(Nfs4Acl::from_aces(aces, Nfs4AclFlag::empty()));
    fsetacl(f.as_fd(), Some(&updated)).expect("fsetacl");
    match fgetacl(f.as_fd()) {
        Ok(Acl::Nfs4(a)) => assert!(
            !a.trivial(),
            "the fixture ACL must be non-trivial or the flag is bypassed"
        ),
        other => panic!("expected nfs4 back, got {other:?}"),
    }

    // Control first: the grant works, so the later denial is the flag's.
    open_for_write_as_nobody(&path)
        .expect("the ACE grants nobody write before the flag");

    add_zfs_attrs(&f, ZfsAttr::READONLY);

    // EACCES, not EPERM: the flag's own refusal is internal, and the
    // privilege fallback that runs after it re-decides the errno - denying
    // an unprivileged caller as EACCES. `IMMUTABLE` is the one that answers
    // EPERM, because the VFS refuses it before ZFS is consulted at all.
    assert_eq!(
        open_for_write_as_nobody(&path),
        Err(libc::EACCES),
        "READONLY must deny a fresh unprivileged writer on the enforced \
         path"
    );

    // Root passes on that same fallback. Pinned so a fork hardening
    // announces itself here rather than in a fleet's backup scripts.
    std::fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .expect("root rides the privilege fallback past READONLY");

    std::fs::remove_file(&path).expect("cleanup");

    // --- the documented gap: acltype=posixacl ----------------------------
    let Some(pdir) = posix_dir() else {
        return skip("no POSIX-ACL dataset for the scope half");
    };
    let (ppath, pf) = scratch_file(&pdir, "ro_scope");
    if fget_zfs_attrs(pf.as_fd()).is_err() {
        let _ = std::fs::remove_file(&ppath);
        return skip("the POSIX dataset path does not answer ZFS ioctls");
    }
    // World-writable by mode, then flagged. On a posixacl dataset a plain
    // write check never reaches ZFS, so the flag holds no one - the gap
    // "NFSv4 required" exists to document.
    let mut perms = std::fs::metadata(&ppath).expect("stat").permissions();
    use std::os::unix::fs::PermissionsExt;
    perms.set_mode(0o666);
    std::fs::set_permissions(&ppath, perms).expect("chmod 0666");
    add_zfs_attrs(&pf, ZfsAttr::READONLY);
    open_for_write_as_nobody(&ppath).expect(
        "documented scope: READONLY does not deny on a posixacl dataset - \
         if this starts failing the platform grew enforcement; update the \
         ZfsAttr::READONLY rustdoc and the S3 front's requirement docs",
    );
    std::fs::remove_file(&ppath).expect("cleanup");
}

/// `IMMUTABLE` stacked on `READONLY` is the version-row lock, and it locks
/// the *daemon* too: the flag reaches the VFS as `S_IMMUTABLE`
/// (`zfs_znode_os.c`), so writes through descriptors opened before it
/// (`zfs_write` checks IMMUTABLE per write, unlike READONLY), renames,
/// unlinks (`may_delete`, `fs/namei.c`) and every xattr write - trusted.*
/// included (`fs/xattr.c`, before the capability branch) - answer EPERM for
/// every caller, capabilities notwithstanding, until the flag is cleared.
///
/// That is why every delete of a sealed version is a two-step: clear (needs
/// `CAP_LINUX_IMMUTABLE`, ambient), then unlink - and why the *current*
/// object must never carry it, or the supersede rename dies. The clear
/// deliberately leaves READONLY in place: deletion needs no unlatch, so the
/// window between clear and unlink is a read-only file, not a writable one.
#[test]
fn immutable_locks_the_version_row_until_cleared() {
    let Some(dir) = nfs4_dir() else {
        return skip("no NFSv4-ACL dataset");
    };
    let (path, f) = scratch_file(&dir, "immutable");
    if fget_zfs_attrs(f.as_fd()).is_err() {
        let _ = std::fs::remove_file(&path);
        return skip("the NFSv4 dataset path does not answer ZFS ioctls");
    }
    use std::os::unix::fs::FileExt;
    use truenas_ros::sync_fs::xattr::{XattrFlags, fsetxattr};

    // Controls before the lock: the held descriptor writes, and the
    // trusted xattr lands (root holds CAP_SYS_ADMIN, so a later refusal is
    // the inode's, not a permission miss).
    f.write_at(b"sealed", 0).expect("control write");
    fsetxattr(f.as_fd(), "trusted.rostest", b"v", XattrFlags::empty())
        .expect("control trusted.* write");

    add_zfs_attrs(&f, ZfsAttr::READONLY | ZfsAttr::IMMUTABLE);

    assert_eq!(
        f.write_at(b"late", 0).unwrap_err().raw_os_error(),
        Some(libc::EPERM),
        "IMMUTABLE denies even the descriptor that was open before it - \
         the opposite of READONLY, so nothing may still owe this file \
         writes when the version seals"
    );
    assert_eq!(
        fsetxattr(f.as_fd(), "trusted.rostest", b"w", XattrFlags::empty())
            .unwrap_err(),
        truenas_ros::Errno::EPERM,
        "IMMUTABLE denies trusted.* xattr writes at the VFS - any record \
         the version row will ever need must land before the seal"
    );
    let moved = format!("rostest_immutable_moved_{}", std::process::id());
    assert!(
        renameat2(
            std::fs::File::open(&dir).expect("dir").as_fd(),
            path.file_name().unwrap().to_str().unwrap(),
            std::fs::File::open(&dir).expect("dir").as_fd(),
            moved.as_str(),
            RenameFlags::empty(),
        )
        .is_err(),
        "IMMUTABLE must pin the name: a sealed version cannot be renamed"
    );
    assert!(
        std::fs::remove_file(&path).is_err(),
        "IMMUTABLE must refuse unlink until cleared"
    );

    // The two-step delete: clear IMMUTABLE alone - READONLY stays, so the
    // condemned row is never writable on its way out - then unlink.
    let cur = fget_zfs_attrs(f.as_fd()).expect("fget");
    fset_zfs_attrs(f.as_fd(), cur & !ZfsAttr::IMMUTABLE).expect("clear");
    std::fs::remove_file(&path)
        .expect("unlink after the clear, with READONLY still set");
}
