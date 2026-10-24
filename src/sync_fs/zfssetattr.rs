//! One call that sets the mode, owner, group, times and ZFS attributes of a
//! file, through the xattr `system.truenas_setattr` of the TrueNAS ZFS fork.
//!
//! io_uring has no chmod, chown, utimensat or ioctl, but it has
//! `IORING_OP_FSETXATTR`, so this lets a ring set what those calls set under
//! a request's personality. ZFS writes everything one value asks for in one
//! `zfs_setattr` transaction, so all of it applies or none of it does.
//!
//! The handler (`zpl_xattr_setattr_set`, `module/os/linux/zfs/zpl_xattr.c`)
//! builds the iattr as `chmod_common`, `chown_common` and `vfs_utimes` build
//! it and calls `notify_change`, so the checks are those of chmod, chown and
//! utimensat, run as the caller. A birth time needs the owner, as any time
//! other than now does. `READONLY`, `HIDDEN`, `SYSTEM`, `ARCHIVE`, `OFFLINE`
//! and `SPARSE` need the owner or write attributes granted by an NFSv4 ACL
//! that is not trivial. The other [`ZfsAttr`] bits need the owner, and
//! `IMMUTABLE` and `APPENDONLY` need `CAP_LINUX_IMMUTABLE` as well, whether
//! or not they would change. A new owner or group of what is not a directory
//! clears set-user-ID, and set-group-ID when group execute is set, as
//! `nfsd_sanitize_attrs` (`fs/nfsd/vfs.c`) does.
//!
//! The VFS refuses every xattr write to an immutable or append only file
//! (`may_write_xattr`, `fs/xattr.c`), so clearing those two takes
//! [`fset_zfs_attrs`](super::fset_zfs_attrs). A ZFS without the handler
//! answers `EOPNOTSUPP`.

use super::{Mode, StatxTimestamp, ZfsAttr};
use std::ffi::CStr;

/// The name the handler answers to, `TRUENAS_XATTR_SETATTR` in
/// `include/sys/fs/zfs.h`.
pub const ZFS_SETATTR: &CStr = c"system.truenas_setattr";

/// `TRUENAS_XATTR_SETATTR_VERSION`.
const VERSION: u32 = 1;
/// `sizeof (truenas_xattr_setattr_t)`, which the handler checks.
const SIZE: usize = 144;
/// `UTIME_NOW` of `include/linux/stat.h`, as an `int64_t` nanosecond field.
const UTIME_NOW: i64 = (1 << 30) - 1;

// The bits of `zsa_valid`, each naming the fields it gives.
const VALID_MODE: u64 = 1 << 0;
const VALID_UID: u64 = 1 << 1;
const VALID_GID: u64 = 1 << 2;
const VALID_ATIME: u64 = 1 << 3;
const VALID_MTIME: u64 = 1 << 4;
const VALID_BTIME: u64 = 1 << 5;
const VALID_DOS: u64 = 1 << 6;

/// A time to set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SetTime {
    /// The time of the call, as `UTIME_NOW` gives it.
    Now,
    /// This time. A nanosecond count of a second or more is refused with
    /// `EINVAL`.
    At(StatxTimestamp),
}

impl SetTime {
    fn pair(self) -> (i64, i64) {
        match self {
            SetTime::Now => (0, UTIME_NOW),
            SetTime::At(t) => (t.sec, t.nsec.into()),
        }
    }
}

/// What one call of the setter sets. Whatever is left out stays as it is.
///
/// The kernel refuses with `EINVAL` a value that sets nothing, a mask of no
/// bits, a uid or gid of `u32::MAX`, and a [`ZfsAttr`] bit both to set and
/// to clear.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ZfsSetattr {
    valid: u64,
    mode: u32,
    mode_mask: u32,
    uid: u32,
    gid: u32,
    atime: (i64, i64),
    mtime: (i64, i64),
    btime: (i64, i64),
    dos_set: u64,
    dos_clear: u64,
}

impl ZfsSetattr {
    /// A value that sets nothing yet.
    pub fn new() -> ZfsSetattr {
        ZfsSetattr::default()
    }

    /// Set every permission bit, set-ID bit and the sticky bit to `mode`.
    pub fn mode(self, mode: Mode) -> ZfsSetattr {
        self.mode_masked(mode, Mode::all())
    }

    /// Set the bits of `mask` to what `mode` holds and leave the others, as
    /// NFS's `mode_set_masked` does. Bits of `mode` outside `mask` are
    /// ignored.
    pub fn mode_masked(mut self, mode: Mode, mask: Mode) -> ZfsSetattr {
        self.valid |= VALID_MODE;
        self.mode = mode.bits();
        self.mode_mask = mask.bits();
        self
    }

    /// Set the owner.
    pub fn uid(mut self, uid: u32) -> ZfsSetattr {
        self.valid |= VALID_UID;
        self.uid = uid;
        self
    }

    /// Set the group.
    pub fn gid(mut self, gid: u32) -> ZfsSetattr {
        self.valid |= VALID_GID;
        self.gid = gid;
        self
    }

    /// Set the access time. With [`mtime`](Self::mtime) both
    /// [`SetTime::Now`] and no birth time, it is a touch, which write
    /// permission allows.
    pub fn atime(mut self, t: SetTime) -> ZfsSetattr {
        self.valid |= VALID_ATIME;
        self.atime = t.pair();
        self
    }

    /// Set the modification time. One older than the birth time lowers the
    /// birth time too, unless this value sets the birth time.
    pub fn mtime(mut self, t: SetTime) -> ZfsSetattr {
        self.valid |= VALID_MTIME;
        self.mtime = t.pair();
        self
    }

    /// Set the birth time, which needs the owner.
    pub fn btime(mut self, t: SetTime) -> ZfsSetattr {
        self.valid |= VALID_BTIME;
        self.btime = t.pair();
        self
    }

    /// Set the bits of `set` and clear those of `clear`, leaving every other
    /// [`ZfsAttr`] bit as it is, so none is read and written back.
    pub fn dos(mut self, set: ZfsAttr, clear: ZfsAttr) -> ZfsSetattr {
        self.valid |= VALID_DOS;
        self.dos_set = set.bits();
        self.dos_clear = clear.bits();
        self
    }

    /// The value the handler reads, `truenas_xattr_setattr_t` in the byte
    /// order of this machine, with no ACL after it.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(SIZE);
        v.extend_from_slice(&VERSION.to_ne_bytes());
        v.extend_from_slice(&(SIZE as u32).to_ne_bytes());
        v.extend_from_slice(&self.valid.to_ne_bytes());
        for word in [self.mode, self.mode_mask, self.uid, self.gid] {
            v.extend_from_slice(&word.to_ne_bytes());
        }
        for (sec, nsec) in [self.atime, self.mtime, self.btime] {
            v.extend_from_slice(&sec.to_ne_bytes());
            v.extend_from_slice(&nsec.to_ne_bytes());
        }
        v.extend_from_slice(&self.dos_set.to_ne_bytes());
        v.extend_from_slice(&self.dos_clear.to_ne_bytes());
        // zsa_acl_len, zsa_flags and the five reserved words stay 0.
        v.resize(SIZE, 0);
        v
    }
}

#[cfg(all(test, not(loom), target_endian = "little"))]
mod tests {
    use super::*;

    /// Every field lands at the offset `truenas_xattr_setattr_t` gives it,
    /// checked against bytes written out by hand.
    #[test]
    fn the_value_is_laid_out_as_the_handler_reads_it() {
        let set = ZfsSetattr::new()
            .mode_masked(Mode::S_ISGID | Mode::S_IRWXU, Mode::S_ISGID)
            .uid(1000)
            .gid(0x0102_0304)
            .atime(SetTime::Now)
            .mtime(SetTime::At(StatxTimestamp { sec: -2, nsec: 7 }))
            .btime(SetTime::At(StatxTimestamp {
                sec: 0x1234,
                nsec: 0,
            }))
            .dos(ZfsAttr::HIDDEN, ZfsAttr::ARCHIVE);
        #[rustfmt::skip]
        let want: [u8; 144] = [
            // 0x00 zsa_version 1, zsa_hdrsize 144
            0x01, 0, 0, 0,  0x90, 0, 0, 0,
            // 0x08 zsa_valid, every bit but the ACL's
            0x7f, 0, 0, 0, 0, 0, 0, 0,
            // 0x10 zsa_mode 02700, zsa_mode_mask 02000
            0xc0, 0x05, 0, 0,  0x00, 0x04, 0, 0,
            // 0x18 zsa_uid 1000, zsa_gid 0x01020304
            0xe8, 0x03, 0, 0,  0x04, 0x03, 0x02, 0x01,
            // 0x20 zsa_atime 0 and UTIME_NOW, (1 << 30) - 1
            0, 0, 0, 0, 0, 0, 0, 0,
            0xff, 0xff, 0xff, 0x3f, 0, 0, 0, 0,
            // 0x30 zsa_mtime -2 and 7
            0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0x07, 0, 0, 0, 0, 0, 0, 0,
            // 0x40 zsa_btime 0x1234 and 0
            0x34, 0x12, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            // 0x50 zsa_dos_set HIDDEN, 1 << 33
            0, 0, 0, 0, 0x02, 0, 0, 0,
            // 0x58 zsa_dos_clear ARCHIVE, 1 << 35
            0, 0, 0, 0, 0x08, 0, 0, 0,
            // 0x60 zsa_acl_len 0, zsa_flags 0
            0, 0, 0, 0,  0, 0, 0, 0,
            // 0x68 zsa_reserved, five words of 0
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
        ];
        assert_eq!(set.to_bytes(), want);
    }

    /// A field left out sends no bit of `zsa_valid` and no value, and
    /// [`ZfsSetattr::mode`] replaces every bit `Mode` has.
    #[test]
    fn a_field_left_out_sends_nothing() {
        let bytes = ZfsSetattr::new().to_bytes();
        assert_eq!(bytes.len(), 144);
        assert_eq!(bytes[4], 0x90);
        assert!(bytes[8..].iter().all(|&b| b == 0), "{bytes:02x?}");

        let bytes = ZfsSetattr::new().mode(Mode::S_IRUSR).to_bytes();
        assert_eq!(&bytes[0x08..0x10], &[0x01, 0, 0, 0, 0, 0, 0, 0]);
        // 0400, then the mask 07777.
        assert_eq!(&bytes[0x10..0x18], &[0x00, 0x01, 0, 0, 0xff, 0x0f, 0, 0]);
        assert!(bytes[0x18..].iter().all(|&b| b == 0), "{bytes:02x?}");
    }
}
