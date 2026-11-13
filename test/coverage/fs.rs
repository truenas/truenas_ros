use truenas_ros::AT_FDCWD;
use truenas_ros::errno::Errno;
use truenas_ros::sync_fs::{
    AtFlags, Mode, OFlag, OpenHow, RenameFlags, ResolveFlag, StatxMask, makedev, openat2, renameat2, statx,
};

#[test]
fn statx_accessors_match_std_metadata() {
    use std::os::unix::fs::MetadataExt;
    let dir = truenas_ros::tempdir().unwrap();
    let path = dir.path().join("f");
    std::fs::write(&path, b"1234567").unwrap();
    // Give atime, mtime and ctime three distinct values first, since a fresh file carries all three at one instant and
    // a swap between the accessors would be invisible. `utimensat` sets the first two, and ctime becomes now because
    // changing them is itself a status change.
    {
        use std::os::unix::ffi::OsStrExt as _;
        let c = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        let times = [
            libc::timespec {
                tv_sec: 1_000_000,
                tv_nsec: 111,
            },
            libc::timespec {
                tv_sec: 2_000_000,
                tv_nsec: 222,
            },
        ];
        // SAFETY: a valid NUL-terminated path and a two-element array.
        let rc = unsafe { libc::utimensat(libc::AT_FDCWD, c.as_ptr(), times.as_ptr(), 0) };
        assert_eq!(rc, 0, "utimensat: {}", std::io::Error::last_os_error());
    }
    let md = std::fs::metadata(&path).unwrap();

    let st = statx(
        AT_FDCWD,
        &path,
        AtFlags::empty(),
        StatxMask::BASIC_STATS | StatxMask::BTIME,
    )
    .unwrap();
    assert!(st.is_regular() && !st.is_dir() && !st.is_symlink());
    assert_eq!(st.size(), 7);
    assert_eq!(st.uid(), md.uid());
    assert_eq!(st.gid(), md.gid());
    assert_eq!(st.ino(), md.ino());
    assert_eq!(u64::from(st.nlink()), md.nlink());
    assert_eq!(u32::from(st.mode()) & 0o777, md.mode() & 0o777);
    assert!(st.blksize() > 0);
    assert_eq!(st.mtime().sec, md.mtime());
    assert_eq!(makedev(st.dev_major(), st.dev_minor()), st.dev());
    // The remaining field accessors, checked against an oracle. Each is one raw read off the buffer the kernel filled,
    // so the fault to catch is a wrongly named field, which reading them under `let _ =` cannot see. `blocks`, `subvol`
    // and `attributes_mask` are read here and nowhere else in the tree.
    //
    // `st_blocks` is the same 512-byte count `stx_blocks` carries.
    {
        use std::os::linux::fs::MetadataExt as _;
        assert_eq!(st.blocks(), md.st_blocks(), "stx_blocks");
    }
    // The fields this test read values out of must be reported filled. Not `BASIC_STATS`: `ATIME` is in that set
    // and ZFS does not return it here (measured), so demanding the whole set reddens for a filesystem answering
    // correctly.
    assert!(
        st.mask().contains(StatxMask::INO | StatxMask::SIZE | StatxMask::BLOCKS),
        "the kernel did not report the fields this test read: {:?}",
        st.mask()
    );
    // `attributes_mask` is what the filesystem supports, a different word from `attributes`. The VFS sets the automount
    // and mount-root bits in it for every stat, while `attributes` on an ordinary file is zero, so an `attributes_mask`
    // that read the attributes word would be empty here.
    let attrs = st.attributes();
    let supported = st.attributes_mask();
    assert!(
        !supported.is_empty(),
        "attributes_mask is empty: the attributes word was read instead"
    );
    assert_eq!(
        attrs & supported,
        attrs,
        "attributes carries bits the filesystem does not support"
    );
    // `SUBVOL` was not requested, so the kernel leaves it zero; the file has bytes, so its block count does not.
    // That asymmetry is what distinguishes the two fields without pinning a value.
    assert!(st.blocks() > 0, "a 7-byte file occupies blocks");
    assert_eq!(st.subvol(), 0, "SUBVOL was not requested");
    // `raw` is the buffer the accessors read, not a copy of it.
    assert_eq!(st.raw().stx_ino, st.ino(), "raw() is not the read buffer");
    assert_eq!(st.btime().sec, st.raw().stx_btime.tv_sec, "btime() is not stx_btime");
    // Each timestamp against std's own `stat`, and against the value set above - the cross-check alone would pass a
    // swap that moved both readers together.
    assert_eq!(st.atime().sec, md.atime(), "stx_atime vs std");
    assert_eq!(st.ctime().sec, md.ctime(), "stx_ctime vs std");
    assert_eq!(st.atime().sec, 1_000_000, "atime() is not stx_atime");
    assert_eq!(st.atime().nsec, 111, "atime() lost its nanoseconds");
    assert_eq!(st.mtime().sec, 2_000_000, "mtime() is not stx_mtime");
    assert_eq!(st.mtime().nsec, 222, "mtime() lost its nanoseconds");
    assert!(
        st.ctime().sec > 2_000_000,
        "ctime() is not stx_ctime: the status change is `now`, later \
             than either time set above, but it reads {}",
        st.ctime().sec
    );
    // Conversions, still driven for their arithmetic.
    let _ = (st.atime().as_secs_f64(), st.ctime().as_nanos());
    assert!(st.mtime().to_system_time().is_some());
}

#[test]
fn statx_symlink_nofollow() {
    let dir = truenas_ros::tempdir().unwrap();
    std::fs::write(dir.path().join("t"), b"x").unwrap();
    std::os::unix::fs::symlink("t", dir.path().join("l")).unwrap();
    let link = dir.path().join("l");
    assert!(
        statx(AT_FDCWD, &link, AtFlags::empty(), StatxMask::TYPE)
            .unwrap()
            .is_regular()
    );
    assert!(
        statx(AT_FDCWD, &link, AtFlags::AT_SYMLINK_NOFOLLOW, StatxMask::TYPE)
            .unwrap()
            .is_symlink()
    );
}

#[test]
fn statx_device_file_rdev() {
    let st = match statx(AT_FDCWD, "/dev/null", AtFlags::empty(), StatxMask::BASIC_STATS) {
        Ok(s) => s,
        Err(_) => return,
    };
    assert_eq!(u32::from(st.mode()) & libc::S_IFMT, libc::S_IFCHR);
    assert_eq!(st.rdev(), makedev(1, 3));
}

#[test]
fn makedev_encoding() {
    assert_eq!(makedev(0, 0), 0);
    assert_eq!(makedev(1, 3), 0x103);
    let (ma, mi) = (0x1234u64, 0x5678u64);
    assert_eq!(
        makedev(ma as u32, mi as u32),
        ((ma & 0xffff_f000) << 32) | ((ma & 0x0000_0fff) << 8) | ((mi & 0xffff_ff00) << 12) | (mi & 0x0000_00ff)
    );
}

#[test]
fn openat2_creates_with_mode() {
    use std::os::unix::fs::PermissionsExt;
    let dir = truenas_ros::tempdir().unwrap();
    let path = dir.path().join("new");
    let how = OpenHow::new()
        .flags(OFlag::O_CREAT | OFlag::O_WRONLY | OFlag::O_EXCL)
        .mode(Mode::S_IRUSR | Mode::S_IWUSR)
        .resolve(ResolveFlag::empty());
    let _fd = openat2(AT_FDCWD, &path, how).unwrap();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode();
    assert_eq!(mode & 0o600, 0o600);
}

#[test]
fn renameat2_plain_and_error_flags() {
    use std::os::fd::AsFd;
    let dir = truenas_ros::tempdir().unwrap();
    let a = dir.path().join("a");
    let b = dir.path().join("b");
    std::fs::write(&a, b"data").unwrap();
    // Single components against a dirfd: the component screen.
    let at = openat2(
        AT_FDCWD,
        dir.path(),
        OpenHow::new().flags(OFlag::O_DIRECTORY | OFlag::O_CLOEXEC),
    )
    .expect("open the directory");
    let at = at.as_fd();

    renameat2(at, "a", at, "b", RenameFlags::empty()).unwrap();
    assert!(!a.exists());
    assert_eq!(std::fs::read(&b).unwrap(), b"data");

    // EXCHANGE with a missing partner -> ENOENT.
    assert_eq!(
        renameat2(at, "b", at, "c", RenameFlags::RENAME_EXCHANGE).unwrap_err(),
        Errno::ENOENT
    );
    // NOREPLACE | EXCHANGE is contradictory -> EINVAL.
    assert_eq!(
        renameat2(
            at,
            "b",
            at,
            "c",
            RenameFlags::RENAME_NOREPLACE | RenameFlags::RENAME_EXCHANGE,
        )
        .unwrap_err(),
        Errno::EINVAL
    );
}
