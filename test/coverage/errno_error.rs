use std::io;
use truenas_ros::Error;
use truenas_ros::errno::{Errno, ErrnoSentinel};

#[test]
fn from_raw_known_and_unknown() {
    assert_eq!(Errno::from_raw(libc::EPERM), Errno::EPERM);
    assert_eq!(Errno::from_raw(libc::ENOENT), Errno::ENOENT);
    assert_eq!(Errno::from_raw(libc::EOPNOTSUPP), Errno::EOPNOTSUPP);
    assert_eq!(Errno::from_raw(0), Errno::UnknownErrno);
    assert_eq!(Errno::from_raw(999_999), Errno::UnknownErrno);
}

#[test]
fn aliases() {
    assert_eq!(Errno::EWOULDBLOCK, Errno::EAGAIN);
    assert_eq!(Errno::EDEADLOCK, Errno::EDEADLK);
    assert_eq!(Errno::ENOTSUP, Errno::EOPNOTSUPP);
}

#[test]
fn thread_local_get_set_clear() {
    Errno::EINVAL.set();
    assert_eq!(Errno::last(), Errno::EINVAL);
    assert_eq!(Errno::last_raw(), libc::EINVAL);
    Errno::clear();
    assert_eq!(Errno::last_raw(), 0);
    Errno::set_raw(libc::EIO);
    assert_eq!(Errno::last(), Errno::EIO);
    Errno::clear();
}

#[test]
fn result_and_sentinel() {
    assert_eq!(<isize as ErrnoSentinel>::sentinel(), -1isize);
    Errno::EACCES.set();
    assert_eq!(Errno::result(-1isize), Err(Errno::EACCES));
    assert_eq!(Errno::result(7isize), Ok(7isize));
    Errno::clear();
}

#[test]
fn display_and_io_roundtrip() {
    assert!(format!("{}", Errno::EIO).contains("EIO"));
    let io_err: io::Error = Errno::EIO.into();
    assert_eq!(io_err.raw_os_error(), Some(libc::EIO));
    assert_eq!(
        Errno::try_from(io::Error::from_raw_os_error(libc::EACCES)).ok(),
        Some(Errno::EACCES)
    );
    // An io::Error without an os error cannot convert.
    assert!(Errno::try_from(io::Error::other("x")).is_err());
}

#[test]
fn from_raw_covers_every_known_value() {
    // Drive every arm of the `from_raw` match, plus Display, across the whole Linux errno range.
    for e in 1..=133 {
        let errno = Errno::from_raw(e);
        let _ = format!("{errno}");
        if errno != Errno::UnknownErrno {
            assert_eq!(errno as i32, e);
        }
    }
}

#[test]
fn error_display_all_variants() {
    use std::path::PathBuf;
    assert_eq!(format!("{}", Error::Errno(Errno::EIO)), format!("{}", Errno::EIO));
    assert!(format!("{}", Error::Validation("bad".into())).contains("bad"));
    assert!(format!("{}", Error::Parse("boom".into())).contains("boom"));
    assert!(
        format!(
            "{}",
            Error::IteratorRestore {
                depth: 3,
                path: PathBuf::from("/x")
            }
        )
        .contains("depth 3")
    );
    assert!(
        format!(
            "{}",
            Error::MountSourceMismatch {
                expected: "a".into(),
                found: "b".into(),
                path: PathBuf::from("/m"),
            }
        )
        .contains("mismatch")
    );
    assert!(
        format!(
            "{}",
            Error::SymlinkInPath {
                path: PathBuf::from("/l")
            }
        )
        .contains("symlink")
    );
}

#[test]
fn error_source_and_into_io() {
    use std::error::Error as _;
    assert!(Error::Errno(Errno::EIO).source().is_some());
    assert!(Error::Validation("x".into()).source().is_none());
    let e: Error = Errno::ENOENT.into();
    assert!(matches!(e, Error::Errno(Errno::ENOENT)));

    let io1: io::Error = Error::Errno(Errno::EACCES).into();
    assert_eq!(io1.raw_os_error(), Some(libc::EACCES));
    let io2: io::Error = Error::SymlinkInPath { path: "/l".into() }.into();
    assert_eq!(io2.raw_os_error(), Some(libc::ELOOP));
    let io3: io::Error = Error::Validation("x".into()).into();
    assert_eq!(io3.kind(), io::ErrorKind::InvalidInput);
}
