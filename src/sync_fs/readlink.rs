//! `readlinkat(2)` with an empty path - read the target of the symbolic
//! link a descriptor holds.

use crate::errno::{self, retry_on_eintr};
use std::ffi::OsString;
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;

/// The first buffer a read takes, which holds a typical target.
const FIRST: usize = 256;

/// Read the target of the symbolic link `fd` holds, a descriptor opened
/// `O_PATH | O_NOFOLLOW` on the link itself.
///
/// Nothing is resolved, since the path is empty and the descriptor is the
/// link, so no link planted along a path can move the read. A descriptor
/// of anything that is not a link answers `ENOENT`, which `do_readlinkat`
/// in `fs/stat.c` gives an empty path where a named one gets `EINVAL`.
///
/// The target comes back whole, its bytes as the file system keeps them,
/// which need not be UTF-8. `readlinkat` truncates to the buffer without
/// saying so, so a read that fills the buffer is taken again with twice
/// the room, as `std::fs::read_link` reads.
///
/// See [`readlinkat(2)`](https://man7.org/linux/man-pages/man2/readlinkat.2.html).
pub fn freadlink<Fd: AsFd>(fd: Fd) -> errno::Result<PathBuf> {
    let raw = fd.as_fd().as_raw_fd();
    let mut buf = vec![0u8; FIRST];
    loop {
        let n = retry_on_eintr(|| unsafe {
            libc::readlinkat(
                raw,
                c"".as_ptr(),
                buf.as_mut_ptr().cast(),
                buf.len(),
            )
        })? as usize;
        if n < buf.len() {
            buf.truncate(n);
            buf.shrink_to_fit();
            return Ok(PathBuf::from(OsString::from_vec(buf)));
        }
        buf.resize(buf.len() * 2, 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tempdir;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{OpenOptionsExt, symlink};
    use std::path::Path;

    /// The link at `path` itself, as a server holds what a lookup found.
    fn held(path: &Path) -> std::fs::File {
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_NOFOLLOW)
            .open(path)
            .expect("opens")
    }

    #[test]
    fn reads_the_target_of_the_link_it_holds() {
        let tmp = tempdir().unwrap();
        std::fs::write(tmp.path().join("f"), b"x").unwrap();
        symlink("f", tmp.path().join("l")).unwrap();
        let link = held(&tmp.path().join("l"));
        assert_eq!(freadlink(&link).unwrap(), Path::new("f"));
    }

    /// A target that fills the first buffer, or that is as long as Linux
    /// lets one be, is read again with more room and comes back whole.
    #[test]
    fn a_target_longer_than_the_first_buffer_comes_back_whole() {
        let tmp = tempdir().unwrap();
        for len in [FIRST - 1, FIRST, FIRST + 1, libc::PATH_MAX as usize - 1] {
            let target = "t".repeat(len);
            let at = tmp.path().join(format!("l{len}"));
            symlink(&target, &at).unwrap();
            let read = freadlink(held(&at)).unwrap();
            assert_eq!(read, Path::new(&target), "a target of {len} bytes");
        }
    }

    /// The bytes come back as they are kept, since a target need not be
    /// UTF-8.
    #[test]
    fn a_target_that_is_not_utf8_comes_back_as_its_bytes() {
        let tmp = tempdir().unwrap();
        let target = std::ffi::OsStr::from_bytes(b"\xff\xfe/x");
        symlink(target, tmp.path().join("l")).unwrap();
        let read = freadlink(held(&tmp.path().join("l"))).unwrap();
        assert_eq!(read.as_os_str().as_bytes(), b"\xff\xfe/x");
    }

    /// A file, a folder, or a link opened through to what it names is not
    /// a link, and the empty path makes that `ENOENT`.
    #[test]
    fn what_is_not_a_link_is_enoent() {
        let tmp = tempdir().unwrap();
        std::fs::write(tmp.path().join("f"), b"x").unwrap();
        symlink("f", tmp.path().join("l")).unwrap();
        let through = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH)
            .open(tmp.path().join("l"))
            .unwrap();
        for fd in [held(&tmp.path().join("f")), held(tmp.path()), through] {
            assert_eq!(freadlink(&fd), Err(errno::Errno::ENOENT));
        }
    }
}
