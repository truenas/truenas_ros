//! `fanotify(7)`, events about files and mounts read from a notification
//! group.
//!
//! [`Fanotify::init`] creates a group and [`Fanotify::mark`] or
//! [`Fanotify::mark_path`] says what it watches. The group is a pollable file
//! descriptor, so a caller reads it on a thread with [`Fanotify::read`], or
//! polls it and reads it on a ring. [`parse`] decodes the bytes of a read
//! with no I/O, so a caller that reads the descriptor itself decodes them the
//! same way.
//!
//! Only notification groups are offered. A group of `FAN_CLASS_CONTENT` or
//! `FAN_CLASS_PRE_CONTENT` holds every access it marks until the reader
//! answers, and a process whose access goes unanswered hangs, so those
//! classes and their replies are left out until a caller needs them.
//!
//! A group that reports mount events, [`InitFlags::REPORT_MNT`], reports
//! nothing else and can mark only a mount namespace (`fanotify_init` and
//! `do_fanotify_mark` in `fs/notify/fanotify/fanotify_user.c`), so watching
//! mounts and files at once takes two groups.

use crate::errno::{self, Errno, retry_on_eintr};
use crate::error::{Error, Result};
use crate::fd::owned_from_raw;
use crate::path::TnPath;
use crate::sync_fs::OFlag;
use std::ffi::OsStr;
use std::mem::{offset_of, size_of};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;

tn_bitflags! {
    /// Flags for [`Fanotify::init`], the flags of `fanotify_init` that a
    /// notification group may take. `FAN_CLOEXEC` is always set.
    pub struct InitFlags: libc::c_uint {
        /// A read with nothing queued fails with `EAGAIN` and does not block.
        NONBLOCK = 0x0000_0002;
        /// No limit on queued events. Needs `CAP_SYS_ADMIN`.
        UNLIMITED_QUEUE = 0x0000_0010;
        /// No limit on marks. Needs `CAP_SYS_ADMIN`.
        UNLIMITED_MARKS = 0x0000_0020;
        /// Each event carries a pidfd for the process behind it.
        REPORT_PIDFD = 0x0000_0080;
        /// The pid of an event is the thread rather than the process.
        REPORT_TID = 0x0000_0100;
        /// An event names its object by fsid and file handle, not by fd.
        REPORT_FID = 0x0000_0200;
        /// An event names the directory it happened in by fsid and handle.
        REPORT_DIR_FID = 0x0000_0400;
        /// With `REPORT_DIR_FID`, an event also carries the entry's name.
        REPORT_NAME = 0x0000_0800;
        /// With the other FID flags, an event also names the entry itself.
        REPORT_TARGET_FID = 0x0000_1000;
        /// An fd the kernel could not open is reported as a negative errno.
        REPORT_FD_ERROR = 0x0000_2000;
        /// The group reports mount events of a mount namespace and nothing
        /// else.
        REPORT_MNT = 0x0000_4000;
    }
}

tn_bitflags! {
    /// Flags for [`Fanotify::mark`]. The type of a mark is `MOUNT`,
    /// `FILESYSTEM` or `MNTNS`, or none of them for an inode. `MNTNS` holds
    /// the bits of both others, as the uapi defines it, so test for it with
    /// `contains(MNTNS)` before the other two.
    pub struct MarkFlags: libc::c_uint {
        /// Add the events of the mask to the mark.
        ADD = 0x0000_0001;
        /// Remove the events of the mask from the mark.
        REMOVE = 0x0000_0002;
        /// Mark a symbolic link itself rather than its target.
        DONT_FOLLOW = 0x0000_0004;
        /// Fail with `ENOTDIR` unless the object is a directory.
        ONLYDIR = 0x0000_0008;
        /// Mark the mount the object is on.
        MOUNT = 0x0000_0010;
        /// The mask is of events to ignore, in the older form.
        IGNORED_MASK = 0x0000_0020;
        /// The ignore mask survives a modification of the object.
        IGNORED_SURV_MODIFY = 0x0000_0040;
        /// Remove every mark of the type given.
        FLUSH = 0x0000_0080;
        /// Mark the file system the object is on.
        FILESYSTEM = 0x0000_0100;
        /// The kernel may evict an inode mark with the inode.
        EVICTABLE = 0x0000_0200;
        /// The mask is of events to ignore.
        IGNORE = 0x0000_0400;
        /// Mark the mount namespace whose nsfs file the object is.
        MNTNS = 0x0000_0110;
    }
}

tn_bitflags! {
    /// The events of a mark and of an event read from a group. The events
    /// that need a reply are left out with their classes, and a decoded
    /// event keeps any bit this type does not name.
    pub struct EventMask: u64 {
        /// A file was read.
        ACCESS = 0x0000_0001;
        /// A file was written.
        MODIFY = 0x0000_0002;
        /// Metadata changed.
        ATTRIB = 0x0000_0004;
        /// A file opened for writing was closed.
        CLOSE_WRITE = 0x0000_0008;
        /// A file not opened for writing was closed.
        CLOSE_NOWRITE = 0x0000_0010;
        /// A file was opened.
        OPEN = 0x0000_0020;
        /// An entry was moved out of a watched directory.
        MOVED_FROM = 0x0000_0040;
        /// An entry was moved into a watched directory.
        MOVED_TO = 0x0000_0080;
        /// An entry was created in a watched directory.
        CREATE = 0x0000_0100;
        /// An entry was deleted from a watched directory.
        DELETE = 0x0000_0200;
        /// The watched object was deleted.
        DELETE_SELF = 0x0000_0400;
        /// The watched object was moved.
        MOVE_SELF = 0x0000_0800;
        /// A file was opened to be executed.
        OPEN_EXEC = 0x0000_1000;
        /// The queue overflowed and events were lost.
        Q_OVERFLOW = 0x0000_4000;
        /// A file system reported an error.
        FS_ERROR = 0x0000_8000;
        /// A mount was attached to the marked namespace. A mount moved
        /// within it comes with both this and `MNT_DETACH` (`FS_MNT_MOVE` in
        /// `include/linux/fsnotify_backend.h`), so only an event with
        /// `MNT_DETACH` alone means the mount left.
        MNT_ATTACH = 0x0100_0000;
        /// A mount was detached from the marked namespace, or moved within
        /// it when `MNT_ATTACH` comes too.
        MNT_DETACH = 0x0200_0000;
        /// Events of the children of a marked directory are wanted too.
        EVENT_ON_CHILD = 0x0800_0000;
        /// An entry was renamed.
        RENAME = 0x1000_0000;
        /// The event happened to a directory.
        ONDIR = 0x4000_0000;
    }
}

const FAN_CLOEXEC: libc::c_uint = 0x0000_0001;
const METADATA_VERSION: u8 = 3;

// The mirrors below give the uapi layout to `offset_of` and `size_of`.
// They are never built, since the parser reads fields from the bytes.
/// `struct fanotify_event_metadata`.
#[allow(dead_code)]
#[repr(C)]
struct RawMetadata {
    event_len: u32,
    vers: u8,
    reserved: u8,
    metadata_len: u16,
    mask: u64,
    fd: i32,
    pid: i32,
}

/// `struct fanotify_event_info_header`.
#[allow(dead_code)]
#[repr(C)]
struct RawHeader {
    info_type: u8,
    pad: u8,
    len: u16,
}

/// `struct fanotify_event_info_fid`, which a `struct file_handle` follows.
#[allow(dead_code)]
#[repr(C)]
struct RawFid {
    hdr: RawHeader,
    fsid: [u32; 2],
}

/// `struct fanotify_event_info_pidfd`.
#[allow(dead_code)]
#[repr(C)]
struct RawPidfd {
    hdr: RawHeader,
    pidfd: i32,
}

/// `struct fanotify_event_info_error`.
#[allow(dead_code)]
#[repr(C)]
struct RawError {
    hdr: RawHeader,
    error: i32,
    error_count: u32,
}

/// `struct fanotify_event_info_range`.
#[allow(dead_code)]
#[repr(C)]
struct RawRange {
    hdr: RawHeader,
    pad: u32,
    offset: u64,
    count: u64,
}

/// `struct fanotify_event_info_mnt`.
#[allow(dead_code)]
#[repr(C)]
struct RawMnt {
    hdr: RawHeader,
    mnt_id: u64,
}

/// The fixed part of every event, `FAN_EVENT_METADATA_LEN`.
pub const EVENT_METADATA_LEN: usize = size_of::<RawMetadata>();

/// The header of a `struct file_handle`, `handle_bytes` and `handle_type`.
const HANDLE_HEADER_LEN: usize = 8;

const INFO_FID: u8 = 1;
const INFO_DFID_NAME: u8 = 2;
const INFO_DFID: u8 = 3;
const INFO_PIDFD: u8 = 4;
const INFO_ERROR: u8 = 5;
const INFO_RANGE: u8 = 6;
const INFO_MNT: u8 = 7;
const INFO_OLD_DFID_NAME: u8 = 10;
const INFO_NEW_DFID_NAME: u8 = 12;

/// A notification group. Closing it removes its marks.
#[derive(Debug)]
pub struct Fanotify(OwnedFd);

impl Fanotify {
    /// Create a notification group (`fanotify_init(2)`).
    ///
    /// `event_flags` are the open flags of the descriptor an event carries
    /// when the group reports neither FIDs nor mounts, and `O_CLOEXEC` is
    /// added to them. Most groups need `CAP_SYS_ADMIN`.
    pub fn init(
        flags: InitFlags,
        event_flags: OFlag,
    ) -> errno::Result<Fanotify> {
        let event_flags =
            (event_flags | OFlag::O_CLOEXEC).bits() as libc::c_uint;
        // SAFETY: plain integer arguments, and no memory is read.
        let fd = Errno::result(unsafe {
            libc::fanotify_init(flags.bits() | FAN_CLOEXEC, event_flags)
        })?;
        // SAFETY: on success `fanotify_init` returns a new descriptor that
        // nothing else owns.
        Ok(Fanotify(unsafe { owned_from_raw(fd) }))
    }

    /// Change the mark on the object `fd` names itself, as the nsfs file of
    /// a mount namespace for [`MarkFlags::MNTNS`] (`fanotify_mark(2)` with
    /// no path).
    pub fn mark<Fd: AsFd>(
        &self,
        flags: MarkFlags,
        mask: EventMask,
        fd: Fd,
    ) -> errno::Result<()> {
        let fd = fd.as_fd().as_raw_fd();
        // SAFETY: a null path makes the kernel take `fd` itself as the
        // object, and no other memory is read.
        retry_on_eintr(|| unsafe {
            libc::fanotify_mark(
                self.0.as_raw_fd(),
                flags.bits(),
                mask.bits(),
                fd,
                std::ptr::null(),
            )
        })?;
        Ok(())
    }

    /// Change the mark on `path` relative to `dirfd` (`fanotify_mark(2)`).
    pub fn mark_path<P, Fd>(
        &self,
        flags: MarkFlags,
        mask: EventMask,
        dirfd: Fd,
        path: &P,
    ) -> errno::Result<()>
    where
        P: ?Sized + TnPath,
        Fd: AsFd,
    {
        let dirfd = dirfd.as_fd().as_raw_fd();
        path.with_tn_path(|c| {
            // SAFETY: `c` is a NUL terminated path that outlives the call.
            retry_on_eintr(|| unsafe {
                libc::fanotify_mark(
                    self.0.as_raw_fd(),
                    flags.bits(),
                    mask.bits(),
                    dirfd,
                    c.as_ptr(),
                )
            })
        })??;
        Ok(())
    }

    /// Read the queued events into `buf` and decode them.
    ///
    /// The kernel copies only whole events and fails with `EINVAL` when
    /// `buf` cannot hold the first, so 4 KiB is a safe size for any event
    /// with a name. A group made with [`InitFlags::NONBLOCK`] fails with
    /// `EAGAIN` when nothing is queued.
    pub fn read<'b>(&self, buf: &'b mut [u8]) -> errno::Result<Events<'b>> {
        // SAFETY: the kernel writes at most `buf.len()` bytes into `buf`.
        let n = retry_on_eintr(|| unsafe {
            libc::read(self.0.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len())
        })?;
        Ok(Events {
            events: parse(&buf[..n as usize]),
        })
    }
}

impl AsFd for Fanotify {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}

/// The events of one [`Fanotify::read`].
///
/// The kernel installs a descriptor for the reader in every event fd and
/// pidfd that is not negative (`copy_event_to_user` in
/// `fs/notify/fanotify/fanotify_user.c`). Each [`ReadEvent`] owns its two,
/// and dropping the batch closes those of the events not taken, so none
/// leaks.
#[derive(Debug)]
pub struct Events<'b> {
    events: EventIter<'b>,
}

/// An event of a [`Fanotify::read`] with the descriptors it carried.
#[derive(Debug)]
pub struct ReadEvent<'b> {
    /// The decoded event.
    pub event: Event<'b>,
    /// The object of the event, for a group that reports neither FIDs nor
    /// mounts.
    pub fd: Option<OwnedFd>,
    /// The process behind the event, for a group made with
    /// [`InitFlags::REPORT_PIDFD`].
    pub pidfd: Option<OwnedFd>,
}

impl<'b> Iterator for Events<'b> {
    type Item = Result<ReadEvent<'b>>;

    fn next(&mut self) -> Option<Self::Item> {
        let event = match self.events.next()? {
            Ok(event) => event,
            Err(e) => return Some(Err(e)),
        };
        let adopt = |fd: RawFd| {
            // SAFETY: these bytes came from a read of the group, which
            // installs each descriptor that is not negative for the reader
            // alone, and the iterator yields each event once.
            (fd >= 0).then(|| unsafe { owned_from_raw(fd) })
        };
        let pidfd = event.infos().find_map(|info| match info {
            Ok(Info::Pidfd(fd)) => Some(fd),
            _ => None,
        });
        Some(Ok(ReadEvent {
            fd: adopt(event.raw_fd()),
            pidfd: pidfd.and_then(adopt),
            event,
        }))
    }
}

impl Drop for Events<'_> {
    fn drop(&mut self) {
        for _ in self.by_ref() {}
    }
}

/// Decode the events in the bytes of a read of a group. No descriptor is
/// taken, so a caller that reads the group itself owns and must close the
/// fds and pidfds the events name.
pub fn parse(bytes: &[u8]) -> EventIter<'_> {
    EventIter { rest: bytes }
}

/// The events of [`parse`]. A malformed event ends the iteration with an
/// error.
#[derive(Clone, Debug)]
pub struct EventIter<'a> {
    rest: &'a [u8],
}

impl<'a> Iterator for EventIter<'a> {
    type Item = Result<Event<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.rest.is_empty() {
            return None;
        }
        match split_event(self.rest) {
            Ok((event, rest)) => {
                self.rest = rest;
                Some(Ok(event))
            }
            Err(e) => {
                self.rest = &[];
                Some(Err(e))
            }
        }
    }
}

fn split_event(bytes: &[u8]) -> Result<(Event<'_>, &[u8])> {
    if bytes.len() < EVENT_METADATA_LEN {
        return Err(invalid("an event shorter than its fixed part"));
    }
    let event_len = u32_at(bytes, offset_of!(RawMetadata, event_len)) as usize;
    let metadata_len =
        u16_at(bytes, offset_of!(RawMetadata, metadata_len)) as usize;
    if bytes[offset_of!(RawMetadata, vers)] != METADATA_VERSION {
        return Err(invalid("an event of an unknown metadata version"));
    }
    if metadata_len < EVENT_METADATA_LEN
        || metadata_len > event_len
        || event_len > bytes.len()
    {
        return Err(invalid("an event whose lengths do not fit the buffer"));
    }
    let event = Event {
        mask: EventMask::from_bits_retain(u64_at(
            bytes,
            offset_of!(RawMetadata, mask),
        )),
        fd: i32_at(bytes, offset_of!(RawMetadata, fd)),
        pid: i32_at(bytes, offset_of!(RawMetadata, pid)),
        info: &bytes[metadata_len..event_len],
    };
    Ok((event, &bytes[event_len..]))
}

/// One event, borrowing the bytes it was decoded from.
#[derive(Clone, Copy, Debug)]
pub struct Event<'a> {
    mask: EventMask,
    fd: i32,
    pid: i32,
    info: &'a [u8],
}

impl<'a> Event<'a> {
    /// What happened.
    pub fn mask(&self) -> EventMask {
        self.mask
    }

    /// The descriptor of the object as the kernel wrote it. It is -1 when
    /// the group reports FIDs or mounts or the queue overflowed, and a
    /// negative errno under [`InitFlags::REPORT_FD_ERROR`] when it could not
    /// be opened.
    pub fn raw_fd(&self) -> i32 {
        self.fd
    }

    /// The process or, under [`InitFlags::REPORT_TID`], the thread behind
    /// the event, or 0 when the kernel withholds it.
    pub fn pid(&self) -> i32 {
        self.pid
    }

    /// The info records that follow the fixed part.
    pub fn infos(&self) -> InfoIter<'a> {
        InfoIter { rest: self.info }
    }
}

/// The info records of an [`Event`]. A malformed record ends the iteration
/// with an error.
#[derive(Clone, Debug)]
pub struct InfoIter<'a> {
    rest: &'a [u8],
}

impl<'a> Iterator for InfoIter<'a> {
    type Item = Result<Info<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.rest.is_empty() {
            return None;
        }
        match split_info(self.rest) {
            Ok((info, rest)) => {
                self.rest = rest;
                Some(Ok(info))
            }
            Err(e) => {
                self.rest = &[];
                Some(Err(e))
            }
        }
    }
}

/// An info record of an event.
#[derive(Clone, Copy, Debug)]
pub enum Info<'a> {
    /// An object named by fsid and file handle, with the name of an entry
    /// for the kinds that carry one.
    Fid(Fid<'a>),
    /// The pidfd of the process behind the event as the kernel wrote it. It
    /// is -1 when the process had gone, and -2 or a negative errno when no
    /// pidfd could be made.
    Pidfd(i32),
    /// A file system error, `FAN_FS_ERROR`, and how many were merged into
    /// the event.
    Error {
        /// The errno the file system reported.
        error: i32,
        /// How many errors the event stands for.
        count: u32,
    },
    /// The byte range of an access.
    Range {
        /// The first byte.
        offset: u64,
        /// How many bytes.
        count: u64,
    },
    /// The unique mount ID of a mount event, as `STATX_MNT_ID_UNIQUE` and
    /// `statmount` give it.
    Mount(u64),
    /// A record of a type this module does not name.
    Other {
        /// The record's `info_type`.
        info_type: u8,
        /// The record after its header.
        body: &'a [u8],
    },
}

/// Which object a [`Fid`] record names.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FidKind {
    /// The object of the event.
    Object,
    /// The directory the event happened in.
    Dir,
    /// The directory the event happened in, with the entry's name.
    DirName,
    /// The directory a renamed entry left, with its old name.
    OldDirName,
    /// The directory a renamed entry went to, with its new name.
    NewDirName,
}

/// An object named by fsid and file handle.
#[derive(Clone, Copy, Debug)]
pub struct Fid<'a> {
    /// Which object the record names.
    pub kind: FidKind,
    /// The fsid of its file system, as `statfs` gives it.
    pub fsid: [u32; 2],
    /// The `struct file_handle`, its header and `handle_bytes` of opaque
    /// data, in the form `FileHandle::from_bytes` of the `fhandle` feature
    /// takes.
    pub handle: &'a [u8],
    /// The entry's name, for the kinds that carry one.
    pub name: Option<&'a OsStr>,
}

fn split_info(bytes: &[u8]) -> Result<(Info<'_>, &[u8])> {
    let header_len = size_of::<RawHeader>();
    if bytes.len() < header_len {
        return Err(invalid("an info record shorter than its header"));
    }
    let info_type = bytes[offset_of!(RawHeader, info_type)];
    let len = u16_at(bytes, offset_of!(RawHeader, len)) as usize;
    // A length below the header's would never advance.
    if len < header_len || len > bytes.len() {
        return Err(invalid("an info record whose length does not fit"));
    }
    let record = &bytes[..len];
    let rest = &bytes[len..];
    let need = |n: usize| {
        if len < n {
            Err(invalid("an info record too short for its type"))
        } else {
            Ok(())
        }
    };
    let info = match info_type {
        INFO_FID | INFO_DFID | INFO_DFID_NAME | INFO_OLD_DFID_NAME
        | INFO_NEW_DFID_NAME => Info::Fid(fid(info_type, record)?),
        INFO_PIDFD => {
            need(size_of::<RawPidfd>())?;
            Info::Pidfd(i32_at(record, offset_of!(RawPidfd, pidfd)))
        }
        INFO_ERROR => {
            need(size_of::<RawError>())?;
            Info::Error {
                error: i32_at(record, offset_of!(RawError, error)),
                count: u32_at(record, offset_of!(RawError, error_count)),
            }
        }
        INFO_RANGE => {
            need(size_of::<RawRange>())?;
            Info::Range {
                offset: u64_at(record, offset_of!(RawRange, offset)),
                count: u64_at(record, offset_of!(RawRange, count)),
            }
        }
        INFO_MNT => {
            need(size_of::<RawMnt>())?;
            Info::Mount(u64_at(record, offset_of!(RawMnt, mnt_id)))
        }
        _ => Info::Other {
            info_type,
            body: &record[header_len..],
        },
    };
    Ok((info, rest))
}

fn fid(info_type: u8, record: &[u8]) -> Result<Fid<'_>> {
    let kind = match info_type {
        INFO_FID => FidKind::Object,
        INFO_DFID => FidKind::Dir,
        INFO_DFID_NAME => FidKind::DirName,
        INFO_OLD_DFID_NAME => FidKind::OldDirName,
        _ => FidKind::NewDirName,
    };
    let start = size_of::<RawFid>();
    if record.len() < start + HANDLE_HEADER_LEN {
        return Err(invalid("a FID record too short for its handle"));
    }
    let handle_bytes = u32_at(record, start) as usize;
    if handle_bytes > record.len() - start - HANDLE_HEADER_LEN {
        return Err(invalid("a FID record whose handle does not fit"));
    }
    let end = start + HANDLE_HEADER_LEN + handle_bytes;
    // The name follows the handle with its NUL, and zeros pad the record to
    // four bytes (`copy_fid_info_to_user`).
    let name = match kind {
        FidKind::Object | FidKind::Dir => None,
        _ => {
            let tail = &record[end..];
            let Some(nul) = tail.iter().position(|&b| b == 0) else {
                return Err(invalid("a FID record whose name has no NUL"));
            };
            Some(OsStr::from_bytes(&tail[..nul]))
        }
    };
    Ok(Fid {
        kind,
        fsid: [
            u32_at(record, offset_of!(RawFid, fsid)),
            u32_at(record, offset_of!(RawFid, fsid) + 4),
        ],
        handle: &record[start..end],
        name,
    })
}

fn invalid(what: &str) -> Error {
    Error::Validation(format!("fanotify read held {what}"))
}

// Each caller has checked that `at` plus the width lies inside `b`.
fn u16_at(b: &[u8], at: usize) -> u16 {
    u16::from_ne_bytes(b[at..at + 2].try_into().unwrap())
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_ne_bytes(b[at..at + 4].try_into().unwrap())
}

fn i32_at(b: &[u8], at: usize) -> i32 {
    i32::from_ne_bytes(b[at..at + 4].try_into().unwrap())
}

fn u64_at(b: &[u8], at: usize) -> u64 {
    u64::from_ne_bytes(b[at..at + 8].try_into().unwrap())
}

#[cfg(all(test, not(loom)))]
mod tests {
    use super::*;

    /// Builds the bytes of a read the way `copy_event_to_user` lays them
    /// out, host order and all.
    fn event(mask: u64, fd: i32, pid: i32, infos: &[Vec<u8>]) -> Vec<u8> {
        let info_len: usize = infos.iter().map(Vec::len).sum();
        let mut out = Vec::new();
        out.extend_from_slice(
            &((EVENT_METADATA_LEN + info_len) as u32).to_ne_bytes(),
        );
        out.push(METADATA_VERSION);
        out.push(0);
        out.extend_from_slice(&(EVENT_METADATA_LEN as u16).to_ne_bytes());
        out.extend_from_slice(&mask.to_ne_bytes());
        out.extend_from_slice(&fd.to_ne_bytes());
        out.extend_from_slice(&pid.to_ne_bytes());
        for info in infos {
            out.extend_from_slice(info);
        }
        out
    }

    fn header(info_type: u8, len: usize) -> Vec<u8> {
        let mut out = vec![info_type, 0];
        out.extend_from_slice(&(len as u16).to_ne_bytes());
        out
    }

    fn mnt(id: u64) -> Vec<u8> {
        let mut out = header(INFO_MNT, size_of::<RawMnt>());
        out.resize(offset_of!(RawMnt, mnt_id), 0);
        out.extend_from_slice(&id.to_ne_bytes());
        out
    }

    fn fid_record(
        info_type: u8,
        fsid: [u32; 2],
        handle: &[u8],
        name: Option<&str>,
    ) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&fsid[0].to_ne_bytes());
        body.extend_from_slice(&fsid[1].to_ne_bytes());
        body.extend_from_slice(&(handle.len() as u32).to_ne_bytes());
        body.extend_from_slice(&1i32.to_ne_bytes());
        body.extend_from_slice(handle);
        if let Some(name) = name {
            body.extend_from_slice(name.as_bytes());
            body.push(0);
        }
        while (body.len() + 4) % 4 != 0 {
            body.push(0);
        }
        let mut out = header(info_type, body.len() + 4);
        out.extend_from_slice(&body);
        out
    }

    fn only_info(bytes: &[u8]) -> Info<'_> {
        let mut events = parse(bytes);
        let event = events.next().unwrap().unwrap();
        assert!(events.next().is_none());
        let mut infos = event.infos();
        let info = infos.next().unwrap().unwrap();
        assert!(infos.next().is_none());
        info
    }

    #[test]
    fn the_layout_is_the_uapi_one() {
        assert_eq!(EVENT_METADATA_LEN, 24);
        assert_eq!(offset_of!(RawMetadata, mask), 8);
        assert_eq!(size_of::<RawFid>(), 12);
        assert_eq!(size_of::<RawPidfd>(), 8);
        assert_eq!(size_of::<RawError>(), 12);
        assert_eq!(size_of::<RawRange>(), 24);
        assert_eq!(size_of::<RawMnt>(), 16);
        assert_eq!(offset_of!(RawMnt, mnt_id), 8);
    }

    #[test]
    fn a_mount_event_gives_its_mount_id() {
        let bytes =
            event(EventMask::MNT_ATTACH.bits(), -1, 0, &[mnt(0x1_0000_002a)]);
        let event = parse(&bytes).next().unwrap().unwrap();
        assert_eq!(event.mask(), EventMask::MNT_ATTACH);
        assert_eq!(event.raw_fd(), -1);
        assert!(matches!(only_info(&bytes), Info::Mount(0x1_0000_002a)));
    }

    #[test]
    fn events_follow_one_another_by_their_length() {
        let mut bytes = event(EventMask::MNT_ATTACH.bits(), -1, 0, &[mnt(7)]);
        bytes.extend(event(EventMask::MNT_DETACH.bits(), -1, 0, &[mnt(8)]));
        let got: Vec<_> = parse(&bytes)
            .map(|e| {
                let e = e.unwrap();
                let Some(Ok(Info::Mount(id))) = e.infos().next() else {
                    panic!("no mount record");
                };
                (e.mask(), id)
            })
            .collect();
        assert_eq!(
            got,
            [(EventMask::MNT_ATTACH, 7), (EventMask::MNT_DETACH, 8)]
        );
    }

    #[test]
    fn a_dir_name_record_gives_fsid_handle_and_name() {
        let record =
            fid_record(INFO_DFID_NAME, [5, 6], &[1, 2, 3, 4, 5], Some("a.txt"));
        let bytes = event(EventMask::CREATE.bits(), -1, 42, &[record]);
        let Info::Fid(fid) = only_info(&bytes) else {
            panic!("not a FID record");
        };
        assert_eq!(fid.kind, FidKind::DirName);
        assert_eq!(fid.fsid, [5, 6]);
        assert_eq!(fid.handle.len(), HANDLE_HEADER_LEN + 5);
        assert_eq!(&fid.handle[HANDLE_HEADER_LEN..], &[1, 2, 3, 4, 5]);
        assert_eq!(fid.name, Some(OsStr::new("a.txt")));
    }

    #[test]
    fn a_rename_carries_the_old_and_the_new_name() {
        let old =
            fid_record(INFO_OLD_DFID_NAME, [1, 1], &[9; 8], Some("before"));
        let new =
            fid_record(INFO_NEW_DFID_NAME, [1, 1], &[9; 8], Some("after"));
        let bytes = event(EventMask::RENAME.bits(), -1, 1, &[old, new]);
        let event = parse(&bytes).next().unwrap().unwrap();
        let names: Vec<_> = event
            .infos()
            .map(|i| match i.unwrap() {
                Info::Fid(f) => (f.kind, f.name.unwrap().to_owned()),
                other => panic!("{other:?}"),
            })
            .collect();
        assert_eq!(
            names,
            [
                (FidKind::OldDirName, "before".into()),
                (FidKind::NewDirName, "after".into())
            ]
        );
    }

    #[test]
    fn an_object_record_has_no_name() {
        let bytes =
            event(0, -1, 0, &[fid_record(INFO_FID, [0, 0], &[7; 12], None)]);
        let Info::Fid(fid) = only_info(&bytes) else {
            panic!("not a FID record");
        };
        assert_eq!(fid.kind, FidKind::Object);
        assert!(fid.name.is_none());
    }

    #[test]
    fn pidfd_error_and_range_records_decode() {
        let mut pidfd = header(INFO_PIDFD, size_of::<RawPidfd>());
        pidfd.extend_from_slice(&(-2i32).to_ne_bytes());
        let mut error = header(INFO_ERROR, size_of::<RawError>());
        error.extend_from_slice(&5i32.to_ne_bytes());
        error.extend_from_slice(&3u32.to_ne_bytes());
        let mut range = header(INFO_RANGE, size_of::<RawRange>());
        range.extend_from_slice(&0u32.to_ne_bytes());
        range.extend_from_slice(&100u64.to_ne_bytes());
        range.extend_from_slice(&50u64.to_ne_bytes());
        let bytes = event(0, -1, 0, &[pidfd, error, range]);
        let event = parse(&bytes).next().unwrap().unwrap();
        let infos: Vec<_> = event.infos().map(Result::unwrap).collect();
        assert!(matches!(infos[0], Info::Pidfd(-2)));
        assert!(matches!(infos[1], Info::Error { error: 5, count: 3 }));
        assert!(matches!(
            infos[2],
            Info::Range {
                offset: 100,
                count: 50
            }
        ));
    }

    #[test]
    fn an_unknown_record_is_passed_over() {
        let mut other = header(99, 8);
        other.extend_from_slice(&[1, 2, 3, 4]);
        let bytes = event(0, -1, 0, &[other, mnt(3)]);
        let event = parse(&bytes).next().unwrap().unwrap();
        let infos: Vec<_> = event.infos().map(Result::unwrap).collect();
        assert!(matches!(
            infos[0],
            Info::Other {
                info_type: 99,
                body: [1, 2, 3, 4]
            }
        ));
        assert!(matches!(infos[1], Info::Mount(3)));
    }

    #[test]
    fn a_bit_this_module_does_not_name_is_kept() {
        let bytes = event(1 << 62, -1, 0, &[]);
        let event = parse(&bytes).next().unwrap().unwrap();
        assert_eq!(event.mask().bits(), 1 << 62);
    }

    /// Each refusal ends the iteration, so a caller is never handed bytes
    /// past a length that did not fit.
    #[test]
    fn malformed_events_are_refused() {
        let good = event(0, -1, 0, &[mnt(1)]);
        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("short", good[..EVENT_METADATA_LEN - 1].to_vec()),
            ("cut off", good[..good.len() - 1].to_vec()),
            ("version", {
                let mut b = good.clone();
                b[offset_of!(RawMetadata, vers)] = 2;
                b
            }),
            ("metadata past event", {
                let mut b = good.clone();
                b[6..8].copy_from_slice(&(good.len() as u16 + 1).to_ne_bytes());
                b
            }),
            ("metadata too short", {
                let mut b = good.clone();
                b[6..8].copy_from_slice(&8u16.to_ne_bytes());
                b
            }),
        ];
        for (what, bytes) in cases {
            let mut events = parse(&bytes);
            assert!(events.next().unwrap().is_err(), "{what}");
            assert!(events.next().is_none(), "{what}");
        }
    }

    #[test]
    fn malformed_records_are_refused() {
        let zero_len = header(INFO_MNT, 0);
        // A type with no size of its own leans on the header's check alone.
        let unknown_zero_len = header(99, 0);
        let unknown_short = {
            let mut b = header(99, 2);
            b.extend_from_slice(&[0; 4]);
            b
        };
        let past_end = header(INFO_MNT, 64);
        let short_mnt = {
            let mut b = header(INFO_MNT, 8);
            b.extend_from_slice(&[0; 4]);
            b
        };
        // One byte more than the record holds after the handle's header.
        let handle_past_end = {
            let mut b = fid_record(INFO_FID, [0, 0], &[1; 4], None);
            let room = b.len() - size_of::<RawFid>() - HANDLE_HEADER_LEN;
            b[12..16].copy_from_slice(&(room as u32 + 1).to_ne_bytes());
            b
        };
        let no_nul = {
            let mut b =
                fid_record(INFO_DFID_NAME, [0, 0], &[1; 4], Some("abc"));
            for byte in &mut b[24..] {
                *byte = b'x';
            }
            b
        };
        for (what, record) in [
            ("zero length", zero_len),
            ("unknown type of zero length", unknown_zero_len),
            ("unknown type shorter than a header", unknown_short),
            ("past the end", past_end),
            ("short mount record", short_mnt),
            ("handle past the end", handle_past_end),
            ("name with no NUL", no_nul),
        ] {
            let bytes = event(0, -1, 0, &[record]);
            let event = parse(&bytes).next().unwrap().unwrap();
            let mut infos = event.infos();
            assert!(infos.next().unwrap().is_err(), "{what}");
            assert!(infos.next().is_none(), "{what}");
        }
    }
}
