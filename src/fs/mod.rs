//! Modern filesystem syscalls and safe I/O helpers.
//!
//! Currently: [`statx`], [`openat2`], [`renameat2`], and the shared flag types
//! ([`AtFlags`], [`OFlag`], [`Mode`]).

mod atomic;
mod openat2;
mod renameat2;
mod safe_open;
mod statx;

pub use atomic::{atomic_replace, atomic_write, AtomicWriteOptions};
pub use openat2::{openat2, OpenHow, ResolveFlag};
pub use renameat2::{renameat2, RenameFlags};
pub use safe_open::safe_open;
pub use statx::{
    makedev, statx, Statx, StatxAttr, StatxMask, StatxRaw, StatxTimestamp,
    StatxTimestampRaw,
};

tn_bitflags! {
    /// Flags for the `*at` family of syscalls (`AT_*`).
    pub struct AtFlags: libc::c_int {
        /// Do not dereference a terminal symbolic link.
        AT_SYMLINK_NOFOLLOW;
        /// Dereference a terminal symbolic link.
        AT_SYMLINK_FOLLOW;
        /// Do not trigger automounts.
        AT_NO_AUTOMOUNT;
        /// Operate on the fd itself when the path is empty.
        AT_EMPTY_PATH;
        /// `statx`: force synchronisation with the server/device.
        AT_STATX_FORCE_SYNC = 0x2000;
        /// `statx`: do not synchronise; return cached attributes.
        AT_STATX_DONT_SYNC = 0x4000;
        /// Apply to an entire mount subtree (e.g. `mount_setattr`).
        AT_RECURSIVE = 0x8000;
    }
}

tn_bitflags! {
    /// File status/creation flags (`O_*`) for [`openat2`] and friends.
    pub struct OFlag: libc::c_int {
        /// Open for reading only.
        O_RDONLY;
        /// Open for writing only.
        O_WRONLY;
        /// Open for reading and writing.
        O_RDWR;
        /// Append to the file on every write.
        O_APPEND;
        /// Enable signal-driven I/O.
        O_ASYNC;
        /// Close the descriptor automatically on `exec`.
        O_CLOEXEC;
        /// Create the file if it does not exist.
        O_CREAT;
        /// Bypass the page cache (direct I/O).
        O_DIRECT;
        /// Fail unless the path names a directory.
        O_DIRECTORY;
        /// With `O_CREAT`, fail if the file already exists.
        O_EXCL;
        /// Allow opening files larger than 2 GiB (a no-op on 64-bit).
        O_LARGEFILE;
        /// Do not update the file's last-access time.
        O_NOATIME;
        /// Do not make a terminal the controlling terminal.
        O_NOCTTY;
        /// Fail if the trailing path component is a symbolic link.
        O_NOFOLLOW;
        /// Open in non-blocking mode.
        O_NONBLOCK;
        /// Obtain a path-reference descriptor (no read/write).
        O_PATH;
        /// Write synchronously (data and metadata).
        O_SYNC;
        /// Write synchronously (data only).
        O_DSYNC;
        /// Create an unnamed temporary file in the named directory.
        O_TMPFILE;
        /// Truncate the file to zero length on open.
        O_TRUNC;
    }
}

tn_bitflags! {
    /// File mode / permission bits (`S_*`).
    pub struct Mode: libc::mode_t {
        /// Read, write, and execute for the owner.
        S_IRWXU as libc::mode_t;
        /// Read for the owner.
        S_IRUSR as libc::mode_t;
        /// Write for the owner.
        S_IWUSR as libc::mode_t;
        /// Execute for the owner.
        S_IXUSR as libc::mode_t;
        /// Read, write, and execute for the group.
        S_IRWXG as libc::mode_t;
        /// Read for the group.
        S_IRGRP as libc::mode_t;
        /// Write for the group.
        S_IWGRP as libc::mode_t;
        /// Execute for the group.
        S_IXGRP as libc::mode_t;
        /// Read, write, and execute for others.
        S_IRWXO as libc::mode_t;
        /// Read for others.
        S_IROTH as libc::mode_t;
        /// Write for others.
        S_IWOTH as libc::mode_t;
        /// Execute for others.
        S_IXOTH as libc::mode_t;
        /// Set-user-ID on execution.
        S_ISUID as libc::mode_t;
        /// Set-group-ID on execution.
        S_ISGID as libc::mode_t;
        /// Sticky bit.
        S_ISVTX as libc::mode_t;
    }
}
