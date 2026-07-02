//! `statmount(2)` — detailed information about a single mount.

use super::{
    MntIdReq, MntPropagation, MountAttr, MNT_ID_REQ_SIZE_VER1, SYS_STATMOUNT,
};
use crate::errno::{self, retry_on_eintr, Errno};

tn_bitflags! {
    /// `STATMOUNT_*` — fields requested from / returned by `statmount`
    /// (the full 6.18 set, through the uid/gid maps).
    pub struct StatmountMask: u64 {
        /// Superblock basics (`sb_dev_*`, `sb_magic`, `sb_flags`).
        SB_BASIC = 0x0000_0001;
        /// Mount basics (`mnt_id`, parent, attrs, propagation, peers).
        MNT_BASIC = 0x0000_0002;
        /// `propagate_from`.
        PROPAGATE_FROM = 0x0000_0004;
        /// `mnt_root` string.
        MNT_ROOT = 0x0000_0008;
        /// `mnt_point` string.
        MNT_POINT = 0x0000_0010;
        /// `fs_type` string.
        FS_TYPE = 0x0000_0020;
        /// `mnt_ns_id`.
        MNT_NS_ID = 0x0000_0040;
        /// `mnt_opts` string.
        MNT_OPTS = 0x0000_0080;
        /// `fs_subtype` string.
        FS_SUBTYPE = 0x0000_0100;
        /// `sb_source` string (mount source device / ZFS dataset).
        SB_SOURCE = 0x0000_0200;
        /// Filesystem options array.
        OPT_ARRAY = 0x0000_0400;
        /// Security-module options array.
        OPT_SEC_ARRAY = 0x0000_0800;
        /// Mask of `STATMOUNT_*` bits this kernel supports.
        SUPPORTED_MASK = 0x0000_1000;
        /// uid-mapping array.
        MNT_UIDMAP = 0x0000_2000;
        /// gid-mapping array.
        MNT_GIDMAP = 0x0000_4000;
    }
}

tn_bitflags! {
    /// Superblock flags reported in [`Statmount::sb_flags`].
    pub struct SbFlags: u32 {
        /// Mounted read-only.
        RDONLY = 0x0000_0001;
        /// Writes are synchronised immediately.
        SYNCHRONOUS = 0x0000_0010;
        /// Directory modifications are synchronous.
        DIRSYNC = 0x0000_0080;
        /// Timestamps are updated lazily.
        LAZYTIME = 0x0200_0000;
    }
}

/// Fixed header of the kernel `struct statmount` (6.18). Strings live in the
/// flexible `str[]` array immediately after this header (offset 512); the u32
/// string fields hold byte offsets into it. The string base stays at 512
/// across kernel versions (`__spare2` shrinks as fields are added), so this is
/// forward/backward compatible.
#[repr(C)]
#[derive(Clone, Copy)]
struct RawStatmount {
    size: u32,
    mnt_opts: u32,
    mask: u64,
    sb_dev_major: u32,
    sb_dev_minor: u32,
    sb_magic: u64,
    sb_flags: u32,
    fs_type: u32,
    mnt_id: u64,
    mnt_parent_id: u64,
    mnt_id_old: u32,
    mnt_parent_id_old: u32,
    mnt_attr: u64,
    mnt_propagation: u64,
    mnt_peer_group: u64,
    mnt_master: u64,
    propagate_from: u64,
    mnt_root: u32,
    mnt_point: u32,
    mnt_ns_id: u64,
    fs_subtype: u32,
    sb_source: u32,
    opt_num: u32,
    opt_array: u32,
    opt_sec_num: u32,
    opt_sec_array: u32,
    supported_mask: u64,
    mnt_uidmap_num: u32,
    mnt_uidmap: u32,
    mnt_gidmap_num: u32,
    mnt_gidmap: u32,
    __spare2: [u64; 43],
}

/// Byte offset of the string area (`offsetof(struct statmount, str)`).
const STR_BASE: usize = 512;
const _: () = assert!(core::mem::size_of::<RawStatmount>() == STR_BASE);

/// Detailed information about a single mount, from [`statmount`].
///
/// Every field group is `Some` only when its corresponding [`StatmountMask`]
/// bit was requested and returned.
#[derive(Clone, Debug)]
pub struct Statmount {
    /// The set of fields the kernel actually populated.
    pub mask: StatmountMask,
    /// Unique mount id.
    pub mnt_id: Option<u64>,
    /// Unique mount id of the parent.
    pub mnt_parent_id: Option<u64>,
    /// Legacy (reused) mount id, as in `/proc/.../mountinfo`.
    pub mnt_id_old: Option<u32>,
    /// Legacy (reused) parent mount id.
    pub mnt_parent_id_old: Option<u32>,
    /// Per-mount attributes.
    pub mnt_attr: Option<MountAttr>,
    /// Propagation type.
    pub mnt_propagation: Option<MntPropagation>,
    /// Shared peer group id.
    pub mnt_peer_group: Option<u64>,
    /// Id this mount receives propagation from.
    pub mnt_master: Option<u64>,
    /// Propagation source in the current namespace.
    pub propagate_from: Option<u64>,
    /// Root of the mount relative to the root of its filesystem.
    pub mnt_root: Option<String>,
    /// Mount point relative to the current root.
    pub mnt_point: Option<String>,
    /// Filesystem type name.
    pub fs_type: Option<String>,
    /// Mount-namespace id.
    pub mnt_ns_id: Option<u64>,
    /// Superblock device major.
    pub sb_dev_major: Option<u32>,
    /// Superblock device minor.
    pub sb_dev_minor: Option<u32>,
    /// Superblock magic (`*_SUPER_MAGIC`).
    pub sb_magic: Option<u64>,
    /// Superblock flags.
    pub sb_flags: Option<SbFlags>,
    /// Subtype of `fs_type`, if any (e.g. the FUSE subtype).
    pub fs_subtype: Option<String>,
    /// Mount source (device / ZFS dataset). Requires a 6.14+ kernel; `None`
    /// when unsupported by the running kernel.
    pub sb_source: Option<String>,
    /// Filesystem options, one per element.
    pub opt_array: Option<Vec<String>>,
    /// Security-module options, one per element.
    pub opt_sec_array: Option<Vec<String>>,
    /// The `STATMOUNT_*` mask this kernel supports.
    pub supported_mask: Option<StatmountMask>,
    /// uid mappings, as seen from the caller's namespace.
    pub mnt_uidmap: Option<Vec<String>>,
    /// gid mappings, as seen from the caller's namespace.
    pub mnt_gidmap: Option<Vec<String>>,
    // Raw mount options, without the synthetic `ro,`/`rw,` prefix.
    mnt_opts_raw: Option<String>,
}

impl Statmount {
    /// The mount options string, matching `/proc/self/mountinfo`.
    ///
    /// When both [`StatmountMask::MNT_OPTS`] and [`StatmountMask::SB_BASIC`]
    /// were requested, a `ro,`/`rw,` prefix (derived from
    /// [`SbFlags::RDONLY`]) is prepended, since `statmount` otherwise omits it.
    pub fn mount_opts(&self) -> Option<String> {
        if !self.mask.contains(StatmountMask::MNT_OPTS) {
            return None;
        }
        let opts = self.mnt_opts_raw.as_deref().unwrap_or("");
        if self.mask.contains(StatmountMask::SB_BASIC) {
            let ro = self
                .sb_flags
                .unwrap_or_else(SbFlags::empty)
                .contains(SbFlags::RDONLY);
            let prefix = if ro { "ro" } else { "rw" };
            Some(if opts.is_empty() {
                prefix.to_string()
            } else {
                format!("{prefix},{opts}")
            })
        } else if opts.is_empty() {
            None
        } else {
            Some(opts.to_string())
        }
    }
}

/// Retrieve detailed information about the mount identified by `mnt_id`,
/// requesting the field groups named in `mask`.
///
/// See [`statmount(2)`](https://man7.org/linux/man-pages/man2/statmount.2.html).
pub fn statmount(mnt_id: u64, mask: StatmountMask) -> errno::Result<Statmount> {
    // 8-byte-aligned buffer (kernel writes u64 fields). Start at 1 KiB, grow
    // by 4 KiB on EOVERFLOW, matching the `truenas_os` C extension.
    let mut words = vec![0u64; 1024 / 8];
    loop {
        let byte_len = words.len() * 8;
        let mut req = MntIdReq {
            size: MNT_ID_REQ_SIZE_VER1,
            mnt_ns_fd: 0,
            mnt_id,
            param: mask.bits(),
            mnt_ns_id: 0,
        };
        let res = retry_on_eintr(|| unsafe {
            libc::syscall(
                SYS_STATMOUNT,
                &mut req as *mut MntIdReq,
                words.as_mut_ptr(),
                byte_len,
                0u32,
            )
        });
        match res {
            Ok(_) => return Ok(parse(&words)),
            Err(Errno::EOVERFLOW) => {
                let new_len = words.len() + 4096 / 8;
                words.resize(new_len, 0);
            }
            Err(e) => return Err(e),
        }
    }
}

fn parse(words: &[u64]) -> Statmount {
    // SAFETY: `words` is 8-byte aligned and at least 1 KiB (>= STR_BASE), so
    // reading the fixed `RawStatmount` header is in-bounds and aligned.
    let hdr = unsafe { &*words.as_ptr().cast::<RawStatmount>() };
    // SAFETY: same allocation, reinterpreted as bytes for string extraction.
    let bytes = unsafe {
        std::slice::from_raw_parts(words.as_ptr().cast::<u8>(), words.len() * 8)
    };
    let mask = StatmountMask::from_bits_retain(hdr.mask);

    let get_str = |offset: u32| -> String {
        let start = STR_BASE + offset as usize;
        if start >= bytes.len() {
            return String::new();
        }
        let tail = &bytes[start..];
        let end = tail.iter().position(|&b| b == 0).unwrap_or(tail.len());
        String::from_utf8_lossy(&tail[..end]).into_owned()
    };

    // A run of `count` NUL-terminated strings starting at `offset` into `str`.
    let get_str_array = |offset: u32, count: u32| -> Vec<String> {
        let mut out = Vec::with_capacity(count as usize);
        let mut pos = STR_BASE + offset as usize;
        for _ in 0..count {
            if pos >= bytes.len() {
                break;
            }
            let tail = &bytes[pos..];
            let end = tail.iter().position(|&b| b == 0).unwrap_or(tail.len());
            out.push(String::from_utf8_lossy(&tail[..end]).into_owned());
            pos += end + 1;
        }
        out
    };

    let has = |bit: StatmountMask| mask.contains(bit);
    let mnt_basic = has(StatmountMask::MNT_BASIC);
    let sb_basic = has(StatmountMask::SB_BASIC);

    Statmount {
        mask,
        mnt_id: mnt_basic.then_some(hdr.mnt_id),
        mnt_parent_id: mnt_basic.then_some(hdr.mnt_parent_id),
        mnt_id_old: mnt_basic.then_some(hdr.mnt_id_old),
        mnt_parent_id_old: mnt_basic.then_some(hdr.mnt_parent_id_old),
        mnt_attr: mnt_basic.then(|| MountAttr::from_bits_retain(hdr.mnt_attr)),
        mnt_propagation: mnt_basic
            .then(|| MntPropagation::from_bits_retain(hdr.mnt_propagation)),
        mnt_peer_group: mnt_basic.then_some(hdr.mnt_peer_group),
        mnt_master: mnt_basic.then_some(hdr.mnt_master),
        propagate_from: has(StatmountMask::PROPAGATE_FROM)
            .then_some(hdr.propagate_from),
        mnt_root: has(StatmountMask::MNT_ROOT).then(|| get_str(hdr.mnt_root)),
        mnt_point: has(StatmountMask::MNT_POINT)
            .then(|| get_str(hdr.mnt_point)),
        fs_type: has(StatmountMask::FS_TYPE).then(|| get_str(hdr.fs_type)),
        mnt_ns_id: has(StatmountMask::MNT_NS_ID).then_some(hdr.mnt_ns_id),
        sb_dev_major: sb_basic.then_some(hdr.sb_dev_major),
        sb_dev_minor: sb_basic.then_some(hdr.sb_dev_minor),
        sb_magic: sb_basic.then_some(hdr.sb_magic),
        sb_flags: sb_basic.then(|| SbFlags::from_bits_retain(hdr.sb_flags)),
        fs_subtype: has(StatmountMask::FS_SUBTYPE)
            .then(|| get_str(hdr.fs_subtype)),
        sb_source: has(StatmountMask::SB_SOURCE)
            .then(|| get_str(hdr.sb_source)),
        opt_array: has(StatmountMask::OPT_ARRAY)
            .then(|| get_str_array(hdr.opt_array, hdr.opt_num)),
        opt_sec_array: has(StatmountMask::OPT_SEC_ARRAY)
            .then(|| get_str_array(hdr.opt_sec_array, hdr.opt_sec_num)),
        supported_mask: has(StatmountMask::SUPPORTED_MASK)
            .then(|| StatmountMask::from_bits_retain(hdr.supported_mask)),
        mnt_uidmap: has(StatmountMask::MNT_UIDMAP)
            .then(|| get_str_array(hdr.mnt_uidmap, hdr.mnt_uidmap_num)),
        mnt_gidmap: has(StatmountMask::MNT_GIDMAP)
            .then(|| get_str_array(hdr.mnt_gidmap, hdr.mnt_gidmap_num)),
        mnt_opts_raw: has(StatmountMask::MNT_OPTS)
            .then(|| get_str(hdr.mnt_opts)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mount::is_zfs_snapshot;

    /// A `Statmount` with every field cleared except `mask`. Constructible here
    /// because this test module is a child of the module that owns the private
    /// `mnt_opts_raw` field.
    fn base(mask: StatmountMask) -> Statmount {
        Statmount {
            mask,
            mnt_id: None,
            mnt_parent_id: None,
            mnt_id_old: None,
            mnt_parent_id_old: None,
            mnt_attr: None,
            mnt_propagation: None,
            mnt_peer_group: None,
            mnt_master: None,
            propagate_from: None,
            mnt_root: None,
            mnt_point: None,
            fs_type: None,
            mnt_ns_id: None,
            sb_dev_major: None,
            sb_dev_minor: None,
            sb_magic: None,
            sb_flags: None,
            fs_subtype: None,
            sb_source: None,
            opt_array: None,
            opt_sec_array: None,
            supported_mask: None,
            mnt_uidmap: None,
            mnt_gidmap: None,
            mnt_opts_raw: None,
        }
    }

    #[test]
    fn is_zfs_snapshot_needs_zfs_and_an_at_sign() {
        let mut sm = base(StatmountMask::FS_TYPE | StatmountMask::SB_SOURCE);
        sm.fs_type = Some("zfs".into());
        sm.sb_source = Some("tank/ds@snap".into());
        assert!(is_zfs_snapshot(&sm));

        sm.sb_source = Some("tank/ds".into()); // no '@'
        assert!(!is_zfs_snapshot(&sm));

        sm.fs_type = Some("ext4".into()); // not zfs
        sm.sb_source = Some("dev@x".into());
        assert!(!is_zfs_snapshot(&sm));

        // Missing sb_source (older kernel) is never a snapshot.
        assert!(!is_zfs_snapshot(&base(StatmountMask::FS_TYPE)));
    }

    #[test]
    fn mount_opts_prefixes_ro_rw_only_with_sb_basic() {
        // MNT_OPTS + SB_BASIC → synthetic ro/rw prefix.
        let mut sm = base(StatmountMask::MNT_OPTS | StatmountMask::SB_BASIC);
        sm.sb_flags = Some(SbFlags::empty());
        sm.mnt_opts_raw = Some("noatime".into());
        assert_eq!(sm.mount_opts().as_deref(), Some("rw,noatime"));

        sm.sb_flags = Some(SbFlags::RDONLY);
        assert_eq!(sm.mount_opts().as_deref(), Some("ro,noatime"));

        // Empty raw opts → just the prefix.
        sm.mnt_opts_raw = Some(String::new());
        assert_eq!(sm.mount_opts().as_deref(), Some("ro"));

        // MNT_OPTS without SB_BASIC → raw opts, no prefix...
        let mut sm2 = base(StatmountMask::MNT_OPTS);
        sm2.mnt_opts_raw = Some("noatime".into());
        assert_eq!(sm2.mount_opts().as_deref(), Some("noatime"));
        // ...and empty raw opts → None.
        sm2.mnt_opts_raw = Some(String::new());
        assert_eq!(sm2.mount_opts(), None);

        // No MNT_OPTS bit at all → None.
        assert_eq!(base(StatmountMask::MNT_BASIC).mount_opts(), None);
    }
}
