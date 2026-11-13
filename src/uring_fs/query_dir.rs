//! [`query_directory`]: a **pull-based**, batched directory listing with
//! configurable per-entry enrichment, over the blocking [`FsHandle`].
//!
//! The **name feed** is a `readdir` pass on the caller's own thread, since io_uring has no `getdents` op.
//! [`QueryDir::next`] reads the next `clump` names, then submits every `statx` and `fgetxattr` for them through the
//! [`FsHandle`] `start_*` twins before waiting on any, so they run concurrently on the ring. The directory is opened
//! **under the caller's [`Personality`]**, so that open is the list-permission check. See [`Order`] for what the
//! ordered modes cost, and [`query_tree`](super::query_tree::query_tree) to walk a subtree in path order.
//!
//! **A listing is not a snapshot.** `readdir` may miss an entry renamed during the sweep or report it twice, sorting
//! cannot restore what the sweep never saw, and each [`QueryOptions::start_after`] continuation is a fresh sweep. On
//! ZFS it is a rename that changes the name that moves an entry across the cursor. A caller that needs a point-in-time
//! view needs a snapshot underneath it (`.zfs/snapshot`).

use super::offload_pool::{Job, SharedPool};
use super::{Anchor, File, FsHandle, FsPending, Leaf, Personality};
use crate::errno::{Errno, retry_on_eintr};
use crate::sync::{Arc, mpsc};
use crate::sync_fs::xattr::{XATTR_SIZE_MAX, XATTR_SIZE_RETRIES, flistxattr, is_short_buffer, xattr_retry_cap};
use crate::sync_fs::{AtFlags, OFlag, OpenHow, Statx, StatxMask};
use bitflags::bitflags;
use std::collections::VecDeque;
use std::ffi::{CStr, CString, OsString};
use std::fmt;
use std::os::fd::{AsFd, RawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};

bitflags! {
    /// What to fetch for each directory entry. `STATX` is cheap (a path-based `statx`, no open); `XATTR`/`ACL` open the
    /// entry `O_RDONLY|O_NOFOLLOW` and `fgetxattr` it.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct EnrichSpec: u8 {
        /// size / mtime / type via a path-based `statx`.
        const STATX = 0b0001;
        /// the named extended attributes in [`QueryOptions::xattr_names`].
        const XATTR = 0b0010;
        /// the ACL extended attribute in [`QueryOptions::acl_name`] (`system.nfs4_acl_xdr` on ZFS, or
        /// `system.posix_acl_access`).
        const ACL = 0b0100;
        /// discover attribute names via `flistxattr`, filtered to the namespaces in [`QueryOptions::xattr_ns`], and
        /// fetch their values (see [`XattrNamespaces`] for the credential contract).
        const XATTR_LIST = 0b1000;
    }
}

bitflags! {
    /// Extended-attribute namespaces to enumerate for [`EnrichSpec::XATTR_LIST`].
    ///
    /// Discovery runs `flistxattr` to propose names in the selected namespaces and reads each value under `who`, so
    /// only attributes `who` can read are returned. The kernel lists `user.`, `security.` and `system.` names to any
    /// caller and gates `trusted.` on `CAP_SYS_ADMIN`, and what is safe to expose to the consumer's own callers remains
    /// the consumer's call.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct XattrNamespaces: u8 {
        /// The `user.` namespace (unprivileged application metadata; e.g. the `user.DosStream.*` attributes an SMB
        /// server maps to NTFS streams).
        const USER = 0b0001;
        /// The `trusted.` namespace (reading a value requires `CAP_SYS_ADMIN`).
        const TRUSTED = 0b0010;
        /// The `security.` namespace (LSM labels, file capabilities).
        const SECURITY = 0b0100;
        /// The `system.` namespace (ACLs; e.g. `system.posix_acl_access`, `system.nfs4_acl_xdr`).
        ///
        /// On an `acltype=nfsv4` dataset ZFS lists `system.nfs4_acl_xdr` only when the ACL is **not** trivial, and
        /// almost every object carries a trivial one - so discovery alone is not a reliable way to pick ACLs up. Ask
        /// for [`EnrichSpec::ACL`] instead, which fetches [`QueryOptions::acl_name`] directly.
        const SYSTEM = 0b1000;
    }
}

/// How to run a [`query_directory`] walk.
#[derive(Clone, Debug)]
pub struct QueryOptions {
    /// Which per-entry metadata to fetch.
    pub spec: EnrichSpec,
    /// Extended attributes to fetch when [`EnrichSpec::XATTR`] is set.
    pub xattr_names: Vec<CString>,
    /// Namespaces to enumerate when [`EnrichSpec::XATTR_LIST`] is set; the library returns only the attributes readable
    /// under `who`. Defaults to [`XattrNamespaces::USER`]. See [`XattrNamespaces`] for the contract.
    pub xattr_ns: XattrNamespaces,
    /// The ACL xattr name to fetch when [`EnrichSpec::ACL`] is set.
    pub acl_name: CString,
    /// Entries per yielded batch (clamped to at least 1).
    pub clump: usize,
    /// Drop entries that live on a **different filesystem** from the directory being listed - a mount point, which on
    /// ZFS means a child dataset or a `.zfs/snapshot` automount.
    ///
    /// `readdir` honours no `RESOLVE_*` flags, so this is the listing side of
    /// [`CONFINED_RESOLVE`](crate::uring_fs::CONFINED_RESOLVE)'s `RESOLVE_NO_XDEV`. It requires [`EnrichSpec::STATX`]
    /// and is ignored without it. An entry this identity may not stat, or one that has gone, is dropped, and any other
    /// `statx` failure fails the batch rather than letting the entry through. With no device for the directory itself
    /// nothing is filtered. [`TreeOptions`](super::query_tree::TreeOptions) applies this at every level.
    pub same_device_only: bool,
    /// The `statx` mask requested for each entry when [`EnrichSpec::STATX`] is set. Defaults to
    /// [`StatxMask::BASIC_STATS`]. Widening it to [`StatxMask::CHANGE_COOKIE`] costs nothing extra and gives an exact
    /// validator for anything cached per entry ([`Statx::change_cookie`]).
    pub statx_mask: StatxMask,
    /// The order entries are yielded in. Defaults to [`Order::Readdir`] - see [`Order`] for what the ordered modes
    /// cost.
    pub order: Order,
    /// Yield only entries whose name starts with these bytes.
    ///
    /// Applied during the `readdir` pass, **before** any enrichment, so a filtered-out entry costs neither a `statx`
    /// nor an open. A batch is still filled to `clump` kept entries, so a short batch still means end-of-directory.
    pub name_prefix: Option<Vec<u8>>,
    /// Skip entries up to and including this key, in the active [`Order`]. Ignored under [`Order::Readdir`].
    ///
    /// The bytes are a **literal key**, so to resume past directory `a` under [`Order::ByPathBytes`] pass `a/`, not
    /// `a`, which is where a *file* named `a` sorts. The directory is still read and sorted in full first.
    pub start_after: Option<Vec<u8>>,
}

impl Default for QueryOptions {
    fn default() -> Self {
        QueryOptions {
            spec: EnrichSpec::empty(),
            xattr_names: Vec::new(),
            xattr_ns: XattrNamespaces::USER,
            acl_name: c"".to_owned(),
            clump: 1,
            same_device_only: false,
            statx_mask: StatxMask::BASIC_STATS,
            order: Order::Readdir,
            name_prefix: None,
            start_after: None,
        }
    }
}

/// The order [`QueryDir::next`] yields entries in.
///
/// [`Order::Readdir`] streams, a batch costing one `readdir` of `clump` names. **Both ordered modes read the whole
/// directory before the first batch**, a full sweep and an O(n log n) sort, and hold every name for the life of the
/// [`QueryDir`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Order {
    /// Whatever the filesystem returns. On ZFS that is hash order, not alphabetical. Cheapest, and the only streaming
    /// mode.
    #[default]
    Readdir,
    /// Byte order of the entry names.
    ByName,
    /// Byte order of the entry names **with a `/` appended to directories**, which is the order the *full paths*
    /// beneath this directory compare in.
    ///
    /// Sorting keys, not names, since `/` is `0x2F`. A bare-name sort puts the directory `a` before `a-1.txt` and
    /// `a.txt`, while their full paths order `a-1.txt` < `a.txt` < `a/b.txt`, and only the appended separator lets
    /// per-directory sorting compose into a subtree in global path order. A `DT_UNKNOWN` entry is resolved with a
    /// `statx` before sorting, since guessing would silently reorder it.
    ByPathBytes,
}

/// One enriched directory entry. Which fields are populated depends on the [`EnrichSpec`]; a field is `None`/empty when
/// not requested or unavailable.
#[derive(Clone, Debug)]
pub struct DirEntry {
    /// The entry name (a single path component).
    pub name: OsString,
    /// True if the entry is a directory (from `statx`, else the `readdir` `d_type` hint).
    pub is_dir: bool,
    /// `statx` metadata, when [`EnrichSpec::STATX`] was requested and succeeded.
    pub statx: Option<Statx>,
    /// Requested and discovered xattrs. Explicit [`QueryOptions::xattr_names`] come first, in request order, with
    /// `value` `None` when the attribute is absent (or the entry could not be opened); names discovered via
    /// [`EnrichSpec::XATTR_LIST`] follow, sorted, each readable under `who` (unreadable ones are dropped rather than
    /// listed).
    pub xattrs: Vec<(CString, Option<Vec<u8>>)>,
    /// The ACL xattr value, when [`EnrichSpec::ACL`] was requested and present.
    pub acl: Option<Vec<u8>>,
    /// Discovery could not report every attribute (a failed `flistxattr`, no op slot, or a value known to be readable
    /// that could not be refetched), as against an entry that has none. Never set for an attribute `who` simply cannot
    /// read, which is a deliberate drop.
    pub xattrs_incomplete: bool,
}

/// A running directory query. Pull enriched batches with [`next`](QueryDir::next) until it returns `None` (end of
/// directory). Dropping it closes the directory.
///
/// Not `Send` (it owns a `DIR*`, whose `readdir` cursor is single-threaded);
/// use it on the thread that created it.
pub struct QueryDir {
    dp: *mut libc::DIR,
    h: FsHandle,
    who: Personality,
    dir: Anchor,
    /// The listed directory's device, for [`QueryOptions::same_device_only`]. `None` if it could not be determined, in
    /// which case nothing is filtered.
    dir_dev: Option<u64>,
    opts: QueryOptions,
    /// Ordered modes only: every kept name in the directory, sorted, read on the first [`QueryDir::next`] and drained a
    /// `clump` at a time after. `None` until that first call; `Some(empty)` once exhausted.
    sorted: Option<VecDeque<(OsString, u8)>>,
    /// A batch answered `Err`, so the listing is over.
    ///
    /// **Continuing past one would be the data loss the error exists to report.** The failed clump's names are already
    /// off a `readdir` stream with no rewind, so the rest of the directory would read as a complete listing.
    fatal: bool,
}

impl fmt::Debug for QueryDir {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QueryDir")
            .field("fd", &self.dir_fd())
            .field("spec", &self.opts.spec)
            .finish_non_exhaustive()
    }
}

impl QueryDir {
    /// The descriptor being read (the `fdopendir` dup); closed when this `QueryDir` drops. For diagnostics / tests.
    pub fn dir_fd(&self) -> RawFd {
        // SAFETY: `dp` is a live `DIR*` for this handle's lifetime.
        unsafe { libc::dirfd(self.dp) }
    }

    /// The next enriched batch of up to `clump` entries, or `None` at end-of-directory. A `readdir` error surfaces as
    /// `Some(Err)`.
    // Inherent `next`, not `Iterator`: `QueryDir` owns a `!Send` `DIR*` and yields fallible batches the caller drives.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Option<crate::Result<Vec<DirEntry>>> {
        if self.fatal {
            return None;
        }
        let out = match self.next_names() {
            Ok(names) if names.is_empty() => return None,
            Ok(names) => self.enrich(names),
            Err(e) => Err(e),
        };
        if out.is_err() {
            self.fatal = true;
        }
        Some(out)
    }

    /// The next `clump` names to enrich. Streams straight off `readdir` under [`Order::Readdir`]; under an ordered mode
    /// the whole directory is read and sorted on the first call and drained from there after.
    fn next_names(&mut self) -> crate::Result<Vec<(OsString, u8)>> {
        if self.opts.order == Order::Readdir {
            return self.read_clump(self.opts.clump);
        }
        if self.sorted.is_none() {
            self.sorted = Some(self.read_all_sorted()?);
        }
        // Filled directly above if it was empty, so the queue is present.
        let q = self.sorted.as_mut().expect("sorted buffer filled");
        let take = self.opts.clump.min(q.len());
        Ok(q.drain(..take).collect())
    }

    /// Read the entire directory, resolve any `DT_UNKNOWN` needed for the sort, sort, and drop everything up to
    /// `start_after`.
    fn read_all_sorted(&mut self) -> crate::Result<VecDeque<(OsString, u8)>> {
        let mut all = self.read_clump(usize::MAX)?;
        match self.opts.order {
            // `next_names` only reaches here for an ordered mode.
            Order::Readdir => {}
            Order::ByName => all.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes())),
            Order::ByPathBytes => {
                self.resolve_unknown_dtypes(&mut all)?;
                all.sort_by(|a, b| {
                    cmp_path_bytes(a.0.as_bytes(), a.1 == libc::DT_DIR, b.0.as_bytes(), b.1 == libc::DT_DIR)
                });
            }
        }
        if let Some(after) = &self.opts.start_after {
            // `after` is a literal key, never a bare name needing a separator synthesized for it: a caller resuming
            // past the directory `a` passes `a/`, which is exactly where `a/` sorts. Hence `false`.
            let cut = match self.opts.order {
                Order::ByPathBytes => {
                    all.partition_point(|(n, d)| cmp_path_bytes(n.as_bytes(), *d == libc::DT_DIR, after, false).is_le())
                }
                _ => all.partition_point(|(n, _)| n.as_bytes() <= &after[..]),
            };
            all.drain(..cut);
        }
        Ok(all.into())
    }

    /// Give every `DT_UNKNOWN` entry a real `d_type` with a scatter-gathered `statx`, so [`Order::ByPathBytes`] never
    /// has to guess whether a name carries a trailing separator.
    ///
    /// An entry left `DT_UNKNOWN` here is emitted with a file's key and never descended into ([`entry_is_dir`]), so
    /// only the answers [`unresolved_statx_verdict`] swallows may leave one. Every other refusal fails the batch, since
    /// sorting on a guess produces a page that reads as complete and is not.
    fn resolve_unknown_dtypes(&self, all: &mut [(OsString, u8)]) -> crate::Result<()> {
        let mut pending: Vec<(usize, FsPending)> = Vec::new();
        for (i, (name, d)) in all.iter().enumerate() {
            if *d != libc::DT_UNKNOWN {
                continue;
            }
            // A name that cannot be a leaf cannot be statted or descended into either, so it stays what `readdir`
            // called it.
            let Ok(leaf) = Leaf::new(name.as_bytes()) else {
                continue;
            };
            pending.push((
                i,
                self.h
                    .start_statx(self.who, &self.dir, leaf, AtFlags::AT_SYMLINK_NOFOLLOW, StatxMask::TYPE)?,
            ));
        }
        for (i, p) in pending {
            let (st, err) = split_statx(Some(p));
            if let Some(st) = st {
                all[i].1 = if st.is_dir() { libc::DT_DIR } else { libc::DT_REG };
            } else if let Some(e) = unresolved_statx_verdict(err) {
                return Err(e.into());
            }
        }
        Ok(())
    }

    /// Read up to `limit` kept entry names (with their `d_type`), skipping `.`/`..` and anything
    /// [`QueryOptions::name_prefix`] excludes. Fewer than `limit` (or an empty `Vec`) marks end-of-directory.
    fn read_clump(&mut self, limit: usize) -> crate::Result<Vec<(OsString, u8)>> {
        let mut out = Vec::with_capacity(limit.min(self.opts.clump));
        while out.len() < limit {
            Errno::clear();
            // SAFETY: `dp` is a live `DIR*`; the returned pointer is valid until the next `readdir`/`closedir` - copied
            // out immediately below.
            let ent = unsafe { libc::readdir(self.dp) };
            if ent.is_null() {
                return match Errno::last_raw() {
                    0 => Ok(out), // end of directory
                    _ => Err(Errno::last().into()),
                };
            }
            // SAFETY: `ent` is a valid `dirent`; `d_name` is NUL-terminated. `addr_of!` avoids forming a `&[c_char;
            // 256]` over a record that may be shorter than the full array.
            let (bytes, dtype) = unsafe {
                let name = CStr::from_ptr(std::ptr::addr_of!((*ent).d_name).cast::<libc::c_char>());
                (name.to_bytes().to_vec(), (*ent).d_type)
            };
            if bytes == b"." || bytes == b".." {
                continue;
            }
            // Pushed down into the readdir pass: an unwanted name costs no statx, no open and no xattr read.
            if self.opts.name_prefix.as_ref().is_some_and(|p| !bytes.starts_with(p)) {
                continue;
            }
            out.push((OsString::from_vec(bytes), dtype));
        }
        Ok(out)
    }

    /// Enrich a clump of entries. Every ring op of the clump is submitted before any result is awaited, and each runs
    /// under `who`.
    fn enrich(&self, names: Vec<(OsString, u8)>) -> crate::Result<Vec<DirEntry>> {
        let who = self.who;
        let spec = self.opts.spec;
        // With the confinement asked for, an entry whose device cannot be determined is answered for rather than
        // yielded ([`unresolved_statx_verdict`]). The refusal is collected here because the judgement sits inside an
        // iterator pipeline.
        let confined = self.opts.same_device_only;
        let mut refused: Option<Errno> = None;

        // Where a descriptor is opened, the entry's metadata comes from it, since two by-name lookups can land on two
        // inodes under rename churn and pair one file's size and change cookie with another's name.
        let wants_fd = spec.intersects(EnrichSpec::XATTR | EnrichSpec::ACL | EnrichSpec::XATTR_LIST);

        let requested: Vec<Requested> = names
            .into_iter()
            .map(|(name, dtype)| {
                let statx = if spec.contains(EnrichSpec::STATX) && !wants_fd {
                    Leaf::new(name.as_bytes()).ok().and_then(|leaf| {
                        self.h
                            .start_statx(who, &self.dir, leaf, AtFlags::AT_SYMLINK_NOFOLLOW, self.opts.statx_mask)
                            .ok()
                    })
                } else {
                    None
                };
                let open = if wants_fd {
                    let how = OpenHow::new().flags(OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK);
                    self.h.start_open(who, &self.dir, name.as_bytes(), how).ok()
                } else {
                    None
                };
                Requested {
                    name,
                    dtype,
                    statx,
                    open,
                }
            })
            .collect();

        // Drop what crossed a mount point. Only entries with by-name metadata can be judged here and the rest wait for
        // the assembly, so a crossed entry may pay for xattr reads rather than every entry paying a second `statx`.
        let cross_dev = |st: Option<&Statx>| match (self.dir_dev, st) {
            (Some(dev), Some(st)) => st.dev() != dev,
            // No device for the directory, or no statx for the entry: nothing to compare, so nothing is dropped.
            _ => false,
        };
        let opened: Vec<Opened> = requested
            .into_iter()
            .filter_map(|p| {
                // Only the early drop here; the verdict on an entry with no device is the assembly's, which is the one
                // place that has seen every attempt to get one.
                let (statx, statx_err) = split_statx(p.statx);
                if statx.is_some() && confined && cross_dev(statx.as_ref()) {
                    return None;
                }
                let (file, open_err) = match p.open.map(pending_file) {
                    Some((f, e)) => (f, e),
                    None => (None, None),
                };
                Some(Opened {
                    name: p.name,
                    dtype: p.dtype,
                    statx,
                    statx_err,
                    file,
                    open_err,
                })
            })
            .collect();

        let reading: Vec<Reading> = opened
            .into_iter()
            .map(|p| {
                let mut xattrs = Vec::new();
                let mut acl = None;
                let mut discovered = Vec::new();
                let mut incomplete = false;
                let mut statx_pending = None;
                match &p.file {
                    Some(f) => {
                        if spec.contains(EnrichSpec::STATX) {
                            // This entry's own descriptor, so the metadata cannot describe a different inode. Issued
                            // here so it pipelines with the xattr reads below.
                            statx_pending = self.h.start_fstatx(who, f, AtFlags::empty(), self.opts.statx_mask).ok();
                        }
                        if spec.contains(EnrichSpec::XATTR) {
                            for xn in &self.opts.xattr_names {
                                let pend = self.h.start_fgetxattr(who, f, xn.clone(), vec![0u8; 4096]).ok();
                                xattrs.push((xn.clone(), pend));
                            }
                        }
                        if spec.contains(EnrichSpec::ACL) {
                            acl = self
                                .h
                                .start_fgetxattr(who, f, self.opts.acl_name.clone(), vec![0u8; 65536])
                                .ok();
                        }
                        if spec.contains(EnrichSpec::XATTR_LIST) {
                            // Exclude only names actually fetched above, so `XATTR_LIST` without `XATTR` still surfaces
                            // every name in the namespace.
                            let explicit: &[CString] = if spec.contains(EnrichSpec::XATTR) {
                                self.opts.xattr_names.as_slice()
                            } else {
                                &[]
                            };
                            // The ACL was fetched above into `acl`; discovering it again would spend a second op and a
                            // second 64 KiB buffer on the same bytes.
                            let fetched_acl = spec.contains(EnrichSpec::ACL).then_some(self.opts.acl_name.as_c_str());
                            let (names, listed) = discover_names(f, self.opts.xattr_ns, explicit, fetched_acl);
                            incomplete |= !listed;
                            for dn in names {
                                let pend = self.h.start_fgetxattr(who, f, dn.clone(), vec![0u8; DISCOVER_BUF]).ok();
                                // No op slot: the attribute exists but was never read, which is not "absent".
                                incomplete |= pend.is_none();
                                discovered.push((dn, pend));
                            }
                        }
                    }
                    None if spec.contains(EnrichSpec::XATTR) => {
                        for xn in &self.opts.xattr_names {
                            xattrs.push((xn.clone(), None));
                        }
                    }
                    None => {}
                }
                // No descriptor where one was wanted, so every value asked for is unread, and a full op table answers
                // the open with a marked `EBUSY`. That is not "no extended attributes"
                // ([`DirEntry::xattrs_incomplete`]).
                incomplete |= wants_fd
                    && p.file.is_none()
                    && open_failure_is_incompleteness(p.open_err)
                    && asked_for_what_this_type_can_hold(spec, &self.opts, p.dtype);
                // An entry whose open failed has no descriptor to stat, and so nothing for a by-name answer to be
                // mispaired against: there it is both safe and the only answer available.
                if statx_pending.is_none() && p.statx.is_none() && spec.contains(EnrichSpec::STATX) {
                    statx_pending = Leaf::new(p.name.as_bytes()).ok().and_then(|leaf| {
                        self.h
                            .start_statx(who, &self.dir, leaf, AtFlags::AT_SYMLINK_NOFOLLOW, self.opts.statx_mask)
                            .ok()
                    });
                }
                Reading {
                    name: p.name,
                    dtype: p.dtype,
                    statx: p.statx,
                    statx_err: p.statx_err,
                    statx_pending,
                    file: p.file,
                    xattrs,
                    acl,
                    discovered,
                    incomplete,
                }
            })
            .collect();

        // Assemble each entry. A value larger than its probe buffer is refetched at its true size under `who`, and the
        // fd is held until any refetch finishes.
        let entries: Vec<DirEntry> = reading
            .into_iter()
            .filter_map(|p| {
                // The descriptor's own answer where there is one; the by-name answer only where no descriptor was
                // opened.
                let (fd_statx, fd_err) = split_statx(p.statx_pending);
                let statx = fd_statx.or(p.statx);
                let statx_err = fd_err.or(p.statx_err);
                // **The one place an entry's device is judged**, since only here has every attempt to get it been seen.
                // Judging earlier reads "no metadata yet" as a failure for every entry whose device comes from a
                // descriptor.
                if confined && spec.contains(EnrichSpec::STATX) {
                    if statx.is_none() {
                        if let Some(e) = unresolved_statx_verdict(statx_err) {
                            refused = refused.or(Some(e));
                        }
                        return None;
                    }
                    if cross_dev(statx.as_ref()) {
                        return None;
                    }
                }
                let is_dir = entry_is_dir(self.opts.order, p.dtype, statx.as_ref().map(Statx::is_dir));
                // Declared before the reads that report into it: every value this entry was asked for now says whether
                // it was lost, and the ACL is one of them.
                let mut incomplete = p.incomplete;
                // A missing pending means "no op slot was free" only where a descriptor existed. Without one the
                // verdict was taken above (`open_failure_is_incompleteness`), and taking it again would flag every
                // symlink and socket.
                let had_fd = p.file.is_some();
                let mut xattrs: Vec<(CString, Option<Vec<u8>>)> = p
                    .xattrs
                    .into_iter()
                    .map(|(xn, pend)| {
                        let val = match pend.map(pending_discovered) {
                            Some(DiscRead::Got(v)) => Some(v),
                            Some(DiscRead::Grow) => {
                                // `ERANGE` proved the value readable and oversized, so losing it now is a failed read,
                                // not a denial - the discovered twin below says the same.
                                let v = p.file.as_ref().and_then(|f| refetch_grow(&self.h, who, f, &xn));
                                incomplete |= v.is_none();
                                v
                            }
                            // No op slot, so the read never happened: the slot keeps its name with a `None` value, and
                            // the entry says the listing is short.
                            Some(DiscRead::Lost) => {
                                incomplete = true;
                                None
                            }
                            // ... but only where a descriptor existed to read through; see `had_fd`.
                            None => {
                                incomplete |= had_fd;
                                None
                            }
                            Some(DiscRead::Drop) => None,
                        };
                        (xn, val)
                    })
                    .collect();
                // The ACL reads like every other value, since mapping every error to `None` would report a full op
                // table as an absent ACL. The growth arm serves a caller-supplied `acl_name`, since ZFS caps
                // `system.nfs4_acl_xdr` at 20488 bytes (`zpl_xattr.c`).
                let acl = match p.acl.map(pending_discovered) {
                    Some(DiscRead::Got(v)) => Some(v),
                    Some(DiscRead::Grow) => {
                        let v = p
                            .file
                            .as_ref()
                            .and_then(|f| refetch_grow(&self.h, who, f, &self.opts.acl_name));
                        incomplete |= v.is_none();
                        v
                    }
                    Some(DiscRead::Lost) => {
                        incomplete = true;
                        None
                    }
                    // Absent - on an `acltype=nfsv4` dataset the ordinary case, since ZFS keeps no
                    // `system.nfs4_acl_xdr` for a trivial ACL - or one this identity may not read.
                    Some(DiscRead::Drop) => None,
                    // Not submitted (a full op table) where an ACL was asked for and a descriptor existed, which is the
                    // same unread value `DiscRead::Lost` reports.
                    None => {
                        incomplete |= had_fd && spec.contains(EnrichSpec::ACL);
                        None
                    }
                };
                for (dn, pend) in p.discovered {
                    let val = match pend.map(pending_discovered) {
                        Some(DiscRead::Got(v)) => Some(v),
                        Some(DiscRead::Grow) => {
                            // `ERANGE` proved the value readable and oversized, so losing it now is a failed read, not
                            // a denial.
                            let v = p.file.as_ref().and_then(|f| refetch_grow(&self.h, who, f, &dn));
                            incomplete |= v.is_none();
                            v
                        }
                        // As above: nothing was read, so the name is not reportable as absent.
                        Some(DiscRead::Lost) | None => {
                            incomplete = true;
                            None
                        }
                        Some(DiscRead::Drop) => None,
                    };
                    if let Some(v) = val {
                        xattrs.push((dn, Some(v)));
                    }
                }
                Some(DirEntry {
                    name: p.name,
                    is_dir,
                    statx,
                    xattrs,
                    acl,
                    xattrs_incomplete: incomplete,
                })
            })
            .collect();
        // After the pipelines, not inside them: the ops of a clump are all in flight, and abandoning the collection
        // early would leave their completions - and the descriptors they carry - to be reaped by nobody. Every entry is
        // awaited either way; only the verdict changes.
        match refused {
            Some(e) => Err(e.into()),
            None => Ok(entries),
        }
    }
}

impl Drop for QueryDir {
    fn drop(&mut self) {
        // SAFETY: `dp` is a live `DIR*` from `fdopendir`, closed exactly once;
        // this also closes the underlying dup fd.
        unsafe { libc::closedir(self.dp) };
    }
}

// Per-entry intermediate state.
struct Requested {
    name: OsString,
    dtype: u8,
    statx: Option<FsPending>,
    open: Option<FsPending>,
}
struct Opened {
    name: OsString,
    dtype: u8,
    /// The by-name answer, present only where no descriptor was opened.
    statx: Option<Statx>,
    /// Why that answer is absent, where one was attempted. `None` both when it succeeded and when none was issued - the
    /// assembly tells those apart by whether it ends up with metadata.
    statx_err: Option<Errno>,
    file: Option<File>,
    /// Why there is no descriptor, where one was attempted. `None` both when the open succeeded and when none was
    /// issued.
    open_err: Option<Errno>,
}
struct Reading {
    name: OsString,
    dtype: u8,
    /// The by-name answer, present only where no descriptor was opened.
    statx: Option<Statx>,
    /// Why that answer is absent, where one was attempted.
    statx_err: Option<Errno>,
    /// A `statx` of the descriptor this entry actually holds, issued with the xattr reads. Supersedes the by-name
    /// answer, which cannot be trusted to describe the same inode the open resolved to.
    statx_pending: Option<FsPending>,
    // Kept alive until any oversized discovered value has been refetched; each in-flight op holds its own reference
    // regardless.
    file: Option<File>,
    xattrs: Vec<(CString, Option<FsPending>)>,
    acl: Option<FsPending>,
    discovered: Vec<(CString, Option<FsPending>)>,
    /// Discovery already lost something for this entry (see [`DirEntry::xattrs_incomplete`]).
    incomplete: bool,
}

/// Await an entry's `statx`, keeping the errno apart from the metadata.
///
/// `(None, None)` means no `statx` was issued for this entry at all - which is ordinary: the by-name one is skipped
/// whenever a descriptor is opened, because the descriptor's own answer supersedes it.
fn split_statx(p: Option<FsPending>) -> (Option<Statx>, Option<Errno>) {
    let Some(p) = p else {
        return (None, None);
    };
    let out = match p.into_outcome() {
        Ok(out) => out,
        Err(_) => return (None, Some(Errno::ECONNABORTED)),
    };
    match out.res {
        Ok(_) => (out.stat.map(|raw| Statx::from_raw(*raw)), None),
        Err(e) => (None, Some(e)),
    }
}

/// One entry's directory-ness, which is one answer and not two.
///
/// Under [`Order::ByPathBytes`] it is the `d_type` the **sort** committed to, not the later enrichment `statx`, since
/// [`DirEntry::is_dir`] is what a caller builds its resume key from, and an entry reported against its sort key makes
/// the next page step over siblings never emitted. A directory replaced in between surfaces as `ENOTDIR` on descent,
/// which `query_tree::is_subtree_skip` does not swallow. The unordered modes synthesize no key, so the metadata wins.
fn entry_is_dir(order: Order, dtype: u8, statx_says_dir: Option<bool>) -> bool {
    match order {
        Order::ByPathBytes => dtype == libc::DT_DIR,
        _ => statx_says_dir.unwrap_or(dtype == libc::DT_DIR),
    }
}

/// What a listing does with an entry whose `statx` did not answer: swallow this one, or fail the batch. `None` is
/// "nothing there to list".
///
/// [`QueryDir::resolve_unknown_dtypes`] asks it before the sort, and the `same_device_only` filter after it. The split
/// is `query_tree`'s `is_subtree_skip`, since a partial listing that reads as complete is data loss.
///
/// * `EACCES`/`EPERM` - this identity may not see it, which is the per-identity behaviour the rest of this module
///   already has (an xattr `who` cannot read is dropped, not reported).
/// * `ENOENT` - the entry went away between `readdir` and the `statx`. A walk over a live tree hits this routinely.
/// * Anything else, the marked `EBUSY` of a full op table above all, is the listing failing, and the caller is told.
/// * No errno at all: nothing was issued where something should have been. Not "nothing to list", so it surfaces too.
fn unresolved_statx_verdict(err: Option<Errno>) -> Option<Errno> {
    match err {
        Some(Errno::EACCES | Errno::EPERM | Errno::ENOENT) => None,
        Some(e) => Some(e),
        None => Some(Errno::ECONNABORTED),
    }
}

/// Await an `open` twin: the opened [`File`] on success, else the errno that says why there is none - the open's twin
/// of `statx_err`, and the input to [`open_failure_is_incompleteness`].
fn pending_file(p: FsPending) -> (Option<File>, Option<Errno>) {
    let Ok(out) = p.into_outcome() else {
        return (None, Some(Errno::ECONNABORTED));
    };
    match out.res {
        Ok(_) => match out.file.map(File::new) {
            Some(f) => (Some(f), None),
            None => (None, Some(Errno::EIO)),
        },
        Err(e) => (None, Some(e)),
    }
}

/// Whether this request asked for anything an entry of this `d_type` could actually hold.
///
/// [`open_failure_is_incompleteness`] says whether the values were left *unread*, not whether there were any, and a
/// socket answers `ENXIO` to the listing's open every time, so a flag raised from the errno alone would be permanent.
/// `user.*` lives only on regular files and directories (`xattr_permission`, `fs/xattr.c`), an access ACL on everything
/// but a symlink (`vfs_get_acl`, `fs/posix_acl.c`), and `trusted.*` and `security.*` on any type. This only ever
/// *narrows* the flag, and `DT_UNKNOWN` answers `true`, since over-reporting is the safe direction.
fn asked_for_what_this_type_can_hold(spec: EnrichSpec, opts: &QueryOptions, dtype: u8) -> bool {
    // Regular files and directories hold every namespace, so nothing a request can name is ruled out for them.
    if matches!(dtype, libc::DT_REG | libc::DT_DIR | libc::DT_UNKNOWN) {
        return true;
    }
    // Only a symlink cannot hold an access ACL.
    if spec.contains(EnrichSpec::ACL) && dtype != libc::DT_LNK {
        return true;
    }
    // A named read is ruled out only where every name is `user.*`.
    if spec.contains(EnrichSpec::XATTR) && opts.xattr_names.iter().any(|n| !n.to_bytes().starts_with(b"user.")) {
        return true;
    }
    // Discovery is ruled out only where `user.` is the whole request.
    if spec.contains(EnrichSpec::XATTR_LIST) && !(opts.xattr_ns - XattrNamespaces::USER).is_empty() {
        return true;
    }
    false
}

/// Whether a failed entry `open` leaves this entry's values genuinely *unread* - which is what
/// [`DirEntry::xattrs_incomplete`] reports - rather than definitely answered.
///
/// `EACCES`/`EPERM` (a deliberate drop) and `ENOENT` (no values) are definite answers. **`ELOOP` joins them only
/// because a symlink cannot hold the values**, since the `O_NOFOLLOW` open answers it for every symlink and the kernel
/// refuses an access ACL and `user.*` on one. **`ENXIO` must not sit beside it.** A socket answers it, and a socket
/// carries xattrs and POSIX ACLs like a regular file, so classed definite it would report a real ACL as absent.
/// Everything else, the marked `EBUSY` of a full op table and a missing op slot included, is reported.
fn open_failure_is_incompleteness(err: Option<Errno>) -> bool {
    !matches!(err, Some(Errno::EACCES | Errno::EPERM | Errno::ENOENT | Errno::ELOOP))
}

/// Initial buffer for a discovered attribute's value read; larger values are refetched at their true size (see
/// [`refetch_grow`]).
const DISCOVER_BUF: usize = 4096;

/// The namespace an attribute name belongs to (by prefix), or `None` for a name outside the four standard namespaces.
fn namespace_of(name: &[u8]) -> Option<XattrNamespaces> {
    if name.starts_with(b"user.") {
        Some(XattrNamespaces::USER)
    } else if name.starts_with(b"trusted.") {
        Some(XattrNamespaces::TRUSTED)
    } else if name.starts_with(b"security.") {
        Some(XattrNamespaces::SECURITY)
    } else if name.starts_with(b"system.") {
        Some(XattrNamespaces::SYSTEM)
    } else {
        None
    }
}

/// `flistxattr` the entry, keep names in the requested namespaces, drop any already fetched (the `explicit` names and
/// `fetched_acl`), and return them sorted along with whether the listing itself succeeded. It runs at the calling
/// thread's privilege and only proposes candidates, since the per-value `who` read is the gate.
fn discover_names(
    f: &File,
    want: XattrNamespaces,
    explicit: &[CString],
    fetched_acl: Option<&CStr>,
) -> (Vec<CString>, bool) {
    let (mut names, listed): (Vec<CString>, bool) = match flistxattr(f.fd.as_fd()) {
        Ok(list) => (
            list.into_iter()
                .filter(|n| namespace_of(n.as_bytes()).is_some_and(|ns| want.intersects(ns)))
                .filter(|c| !explicit.iter().any(|e| e == c))
                .filter(|c| fetched_acl != Some(c.as_c_str()))
                .collect(),
            true,
        ),
        Err(_) => (Vec::new(), false),
    };
    names.sort();
    names.dedup();
    (names, listed)
}

/// A discovered attribute's value read outcome.
enum DiscRead {
    /// Read succeeded.
    Got(Vec<u8>),
    /// Value outgrew the initial buffer (`ERANGE`); refetch at its true size.
    Grow,
    /// Absent (`ENODATA`), or `who` lacks the privilege to read it (`EACCES`/`EPERM`). A deliberate drop, never an
    /// incompleteness -- see [`DirEntry::xattrs_incomplete`].
    Drop,
    /// The read itself failed: the marked `EBUSY` of a full op table, a torn-down loop, or a count the buffer cannot
    /// account for. The attribute may well be there and readable, so this is the case [`DirEntry::xattrs_incomplete`]
    /// exists to report - it is not "absent".
    Lost,
}

/// Narrow an owned buffer to the `n` bytes the kernel filled, keeping the allocation. For [`refetch_grow`] only, whose
/// buffer was sized from the value's probed size, and a fixed-probe read wants [`right_size`], since `truncate` never
/// shrinks capacity. `None` if `n` is past what the buffer holds, where `truncate` alone would silently do nothing.
fn narrow(mut buf: Vec<u8>, n: usize) -> Option<Vec<u8>> {
    if n > buf.len() {
        return None;
    }
    buf.truncate(n);
    Some(buf)
}

/// Narrow a fixed-size probe buffer to the `n` bytes the kernel filled, giving surplus capacity back when the value is
/// small.
///
/// The probe buffers (4 KiB discovery, 64 KiB ACL) land in [`DirEntry`] fields the caller holds, and a typical ACL is
/// tens of bytes. The shrink's copy is skipped when the value fills more than half the buffer. Bounds as [`narrow`]
/// does.
fn right_size(mut buf: Vec<u8>, n: usize) -> Option<Vec<u8>> {
    if n > buf.len() {
        return None;
    }
    buf.truncate(n);
    if buf.capacity() / 2 >= buf.len() {
        buf.shrink_to_fit();
    }
    Some(buf)
}

/// Classify a discovered attribute's `fgetxattr` outcome (see [`DiscRead`]).
fn pending_discovered(p: FsPending) -> DiscRead {
    let Some(out) = p.into_outcome().ok() else {
        return DiscRead::Lost;
    };
    match out.res {
        Ok(n) => match out
            .bufs
            .into_iter()
            .next()
            .and_then(|b| right_size(b, usize::try_from(n).ok()?))
        {
            Some(v) => DiscRead::Got(v),
            None => DiscRead::Lost,
        },
        // Both spellings of "your buffer was too small" ([`is_short_buffer`]), since `do_getxattr` rewrites `-ERANGE`
        // to `-E2BIG` when the caller's buffer is at or above `XATTR_SIZE_MAX`, which the 64 KiB ACL probe is.
        Err(e) if is_short_buffer(e) => DiscRead::Grow,
        // A definite "no value here" (not set, not readable by this identity, or not implemented), never an
        // incompleteness. **`EOPNOTSUPP` is the easy one to miss.** An `acltype=posixacl` dataset answers it for
        // `system.nfs4_acl_xdr` (`module/os/linux/zfs/zpl_xattr.c`), and classed as a failed read it would flag every
        // entry of a complete listing.
        Err(Errno::ENODATA | Errno::EACCES | Errno::EPERM | Errno::EOPNOTSUPP) => DiscRead::Drop,
        Err(_) => DiscRead::Lost,
    }
}

/// Refetch an attribute whose value outgrew its initial buffer: probe the size and read at that size under `who`,
/// bounded to [`XATTR_SIZE_MAX`]. A value growing between probe and read reports a short buffer, in either of the two
/// spellings [`is_short_buffer`] names, so retry a bounded number of times, over-allocating on retry so a steadily
/// growing value converges. `None` if it became unreadable or exceeds the cap. Mirrors the sync `fgetxattr` retry.
fn refetch_grow(h: &FsHandle, who: Personality, f: &File, name: &CStr) -> Option<Vec<u8>> {
    let mut tries = 0u32;
    loop {
        let (size, _) = h.fgetxattr(who, f, name.to_owned(), Vec::new());
        let size = size.ok()?;
        if size > XATTR_SIZE_MAX {
            return None;
        }
        let cap = xattr_retry_cap(size, tries);
        let (n, buf) = h.fgetxattr(who, f, name.to_owned(), vec![0u8; cap]);
        match n {
            Ok(n) => return narrow(buf, n),
            Err(crate::Error::Errno(e)) if is_short_buffer(e) => {
                tries += 1;
                if tries >= XATTR_SIZE_RETRIES {
                    return None;
                }
            }
            Err(_) => return None,
        }
    }
}

/// List the extended-attribute names on `f` (all namespaces), sorted. Runs a blocking `flistxattr` on the calling
/// thread at its own privilege; names the caller is not privileged to see (`trusted.*` without `CAP_SYS_ADMIN`) are
/// omitted by the kernel.
pub(crate) fn list_xattr_names(f: &File) -> crate::Result<Vec<CString>> {
    let mut names: Vec<CString> = flistxattr(f.fd.as_fd())?;
    names.sort();
    names.dedup();
    Ok(names)
}

/// Enumerate the extended attributes of `f` in the namespaces `want`, read each value under `who`, and return only
/// those `who` can read. `flistxattr` runs on the calling thread proposing candidates; the per-value read under `who`
/// is the authoritative gate, so an attribute `who` cannot read is dropped. Off-loop only: it blocks on the ring, so
/// never run it on the reactor.
pub(crate) fn scan_xattrs(
    h: &FsHandle,
    who: Personality,
    f: &File,
    want: XattrNamespaces,
) -> crate::Result<Vec<(CString, Vec<u8>)>> {
    let mut names: Vec<CString> = flistxattr(f.fd.as_fd())?
        .into_iter()
        .filter(|n| namespace_of(n.as_bytes()).is_some_and(|ns| want.intersects(ns)))
        .collect();
    names.sort();
    names.dedup();
    // Submit a read for every name before awaiting any, then gather.
    let pending: Vec<(CString, Option<FsPending>)> = names
        .into_iter()
        .map(|n| {
            let p = h.start_fgetxattr(who, f, n.clone(), vec![0u8; DISCOVER_BUF]).ok();
            (n, p)
        })
        .collect();
    let mut out = Vec::with_capacity(pending.len());
    for (n, p) in pending {
        let val = match p.map(pending_discovered) {
            Some(DiscRead::Got(v)) => Some(v),
            Some(DiscRead::Grow) => refetch_grow(h, who, f, &n),
            // This signature has nowhere to carry "and one was lost" the way [`DirEntry::xattrs_incomplete`] does, so a
            // refused read is dropped here.
            Some(DiscRead::Drop | DiscRead::Lost) | None => None,
        };
        if let Some(v) = val {
            out.push((n, v));
        }
    }
    Ok(out)
}

/// Compare two entries the way their **full paths** compare: a directory is ordered as though its name already carried
/// the `/` that will separate it from its children. See [`Order::ByPathBytes`] for why that is the only ordering under
/// which per-directory sorting composes into a correctly ordered walk.
///
/// The trailing separator is synthesized during the comparison rather than by building a key, so sorting a directory
/// allocates nothing per entry.
fn cmp_path_bytes(a: &[u8], a_dir: bool, b: &[u8], b_dir: bool) -> std::cmp::Ordering {
    let (la, lb) = (a.len() + usize::from(a_dir), b.len() + usize::from(b_dir));
    // Past its name, an entry's only remaining key byte is its trailing `/`, which is reachable only when the entry is
    // a directory.
    let byte = |s: &[u8], i: usize| if i < s.len() { s[i] } else { b'/' };
    for i in 0..la.min(lb) {
        match byte(a, i).cmp(&byte(b, i)) {
            std::cmp::Ordering::Equal => continue,
            other => return other,
        }
    }
    la.cmp(&lb)
}

/// The listing comparator exposed to the fuzz crate (`fuzz/`) under `__fuzz` only. Never part of the stable API.
///
/// Driven by `fuzz/fuzz_targets/path_order.rs`. `cmp_path_bytes` orders attacker-named directory entries and its result
/// feeds `sort_by` and `partition_point`, so it must be a **total order** - since Rust 1.81 an inconsistent comparator
/// is a `sort_by` panic, and here it would also cut a resume boundary in the wrong place.
#[cfg(feature = "__fuzz")]
pub mod fuzz {
    /// Compare two directory entries by their full-path ordering.
    pub fn cmp_path_bytes(a: &[u8], a_dir: bool, b: &[u8], b_dir: bool) -> std::cmp::Ordering {
        super::cmp_path_bytes(a, a_dir, b, b_dir)
    }
}

/// Start listing `dir` as `who`, enriching each entry per `opts`. Opening the directory `O_RDONLY|O_DIRECTORY` under
/// `who` **is** the list-permission check - returns `EACCES` when `who` cannot list `dir`. Pull enriched batches with
/// [`QueryDir::next`].
pub fn query_directory(h: &FsHandle, who: Personality, dir: &Anchor, opts: QueryOptions) -> crate::Result<QueryDir> {
    // The anchor is an `O_PATH` dirfd, which neither requires nor implies list permission; open it readable under `who`
    // so the kernel enforces DAC. `.` resolves to the anchor itself, confined by the default `RESOLVE_BENEATH`.
    let list_how = OpenHow::new().flags(OFlag::O_RDONLY | OFlag::O_DIRECTORY);
    let dir_read = h.open(who, dir, ".", list_how)?;

    // `fdopendir`/`closedir` take ownership of the fd, so hand them a dup -- `dir_read` then drops here, closing its
    // own fd; the `DIR*` owns the dup.
    // SAFETY: `dir_read` is a live fd for the dup call.
    let dup = retry_on_eintr(|| unsafe { libc::dup(dir_read.as_raw_fd()) })?;
    // SAFETY: `dup` is a fresh owned fd; `fdopendir` takes ownership of it.
    let dp = unsafe { libc::fdopendir(dup) };
    if dp.is_null() {
        let e = Errno::last();
        // SAFETY: `fdopendir` failed, so `dup` is still ours to close.
        unsafe { libc::close(dup) };
        return Err(e.into());
    }

    // The directory's own device, so an entry on a different one is recognisable as a mount point. Taken from the
    // readable fd we just opened, before it drops.
    let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `dir_read` is live here; `st` is a valid out-pointer.
    let dir_dev = if unsafe { libc::fstat(dir_read.as_raw_fd(), st.as_mut_ptr()) } == 0 {
        // SAFETY: fstat succeeded, so `st` is initialized.
        Some(unsafe { st.assume_init() }.st_dev)
    } else {
        None
    };

    Ok(QueryDir {
        dp,
        h: h.clone(),
        who,
        dir: dir.clone(),
        dir_dev,
        opts: QueryOptions {
            clump: opts.clump.max(1),
            ..opts
        },
        sorted: None,
        fatal: false,
    })
}

// ---- QueryPool: off-loop fan-out over the reactor's blocking-work pool ----

/// An [`FsHandle`] bound to the reactor's shared blocking-work pool for the off-loop directory-listing
/// ([`query`](QueryPool::query)) and byte-range copy ([`copy_file_range`](QueryPool::copy_file_range)) helpers. Each
/// method enqueues a job and returns a handle at once, so one caller thread can fan out many jobs and then collect
/// them. A walk opens its directory under its own `who`, so `EACCES` surfaces as an error batch.
pub struct QueryPool {
    pool: Arc<SharedPool>,
    h: FsHandle,
}

impl QueryPool {
    /// Build a listing pool over `h`, sharing the reactor's one elastic blocking-work pool. `h` is cloned cheaply per
    /// job (the handle just shares the one loop).
    pub fn new(h: FsHandle) -> QueryPool {
        QueryPool {
            pool: h.pool.clone(),
            h,
        }
    }

    /// Enqueue `job` (a no-op if the pool is already dropping), poking the reactor if the pool needs it to come back
    /// ([`SharedPool::submit`]).
    fn submit(&self, job: Job) {
        self.pool.submit(job, &self.h.shared.wake);
    }

    /// Enqueue a listing of `dir` as `who` and return immediately. Pull its enriched batches from the [`QueryHandle`].
    /// Non-blocking - just enqueues.
    pub fn query(&self, who: Personality, dir: Anchor, opts: QueryOptions) -> QueryHandle {
        let (out, rx) = mpsc::channel();
        let h = self.h.clone();
        self.submit(Box::new(move || {
            match query_directory(&h, who, &dir, opts) {
                Ok(mut q) => {
                    while let Some(batch) = q.next() {
                        if out.send(batch).is_err() {
                            break; // the caller dropped its QueryHandle
                        }
                    }
                }
                // A failed open (e.g. `EACCES` - the list-permission check) surfaces as a single error batch.
                Err(e) => {
                    let _ = out.send(Err(e));
                }
            }
        }));
        QueryHandle { rx }
    }

    /// Copy `len` bytes from `src[off_src..]` to `dst[off_dst..]`, **always on the pool**; `src`/`dst` clone into the
    /// job (`File` is `Send`) so their fds stay open. [`CopyHandle::wait`] yields the bytes copied.
    ///
    /// **Nothing runs on the caller's thread**, including the clone, since a ZFS block clone takes filesystem locks and
    /// can wait a transaction group for a source that was just written (`zfs_bclone_wait_dirty`).
    pub fn copy_file_range(&self, src: &File, dst: &File, off_src: u64, off_dst: u64, len: u64) -> CopyHandle {
        // Nothing to move, and nothing to wait for.
        if len == 0 {
            return CopyHandle::Ready(Ok(0));
        }
        let (out, rx) = mpsc::channel();
        let src = src.clone();
        let dst = dst.clone();
        self.submit(Box::new(move || {
            let res = copy_file_range_blocking(src.as_raw_fd(), dst.as_raw_fd(), off_src, off_dst, len);
            let _ = out.send(res);
        }));
        CopyHandle::Pending(rx)
    }
}

impl fmt::Debug for QueryPool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QueryPool").field("pool", &self.pool).finish()
    }
}

/// A handle to one enqueued [`QueryPool::query`] listing. Pull enriched batches with [`next`](QueryHandle::next) until
/// `None` (end of directory, or the pool was dropped). Also an [`Iterator`].
pub struct QueryHandle {
    rx: mpsc::Receiver<crate::Result<Vec<DirEntry>>>,
}

impl fmt::Debug for QueryHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QueryHandle").finish_non_exhaustive()
    }
}

impl QueryHandle {
    /// The next batch, blocking until a worker produces one; `None` at the end (or if the pool was dropped before
    /// finishing this walk).
    pub fn next(&self) -> Option<crate::Result<Vec<DirEntry>>> {
        self.rx.recv().ok()
    }

    /// The next batch if one is already available, without blocking. `None` means "nothing ready yet" *or* "finished" -
    /// [`next`](Self::next) distinguishes them by blocking.
    pub fn try_next(&self) -> Option<crate::Result<Vec<DirEntry>>> {
        self.rx.try_recv().ok()
    }
}

impl Iterator for QueryHandle {
    type Item = crate::Result<Vec<DirEntry>>;
    fn next(&mut self) -> Option<Self::Item> {
        self.rx.recv().ok()
    }
}

/// The result of a [`QueryPool::copy_file_range`]: `Ready` only when the request asked for nothing, else `Pending` on
/// the job the pool is running. [`wait`](Self::wait) yields the bytes copied.
#[derive(Debug)]
pub enum CopyHandle {
    /// Answered without a job — a zero-length copy, which moves nothing and waits for nothing.
    Ready(crate::Result<u64>),
    /// A copy is running on the pool; its result arrives on this channel.
    Pending(mpsc::Receiver<crate::Result<u64>>),
}

impl CopyHandle {
    /// The bytes copied, blocking until the offloaded copy finishes (`ECONNABORTED` if the pool was dropped first).
    pub fn wait(self) -> crate::Result<u64> {
        match self {
            CopyHandle::Ready(r) => r,
            CopyHandle::Pending(rx) => rx.recv().unwrap_or_else(|_| Err(Errno::ECONNABORTED.into())),
        }
    }
}

/// Largest single kernel transfer, page-aligned.
///
/// A ceiling the kernel imposes on one `copy_file_range(2)`, not a chunk size, so the whole remaining range is offered
/// on every call. Splitting a copy smaller costs the clone on ZFS, which can take the whole-file lock a clone needs
/// only while the destination is still empty.
const MAX_CHUNK: usize = 0x7FFF_FFFF & !0xFFF;

/// Copy `len` bytes from `src[off_src..]` to `dst[off_dst..]`, letting the kernel clone them where it can. Returns
/// bytes copied (short only at source EOF); across filesystems `copy_file_range` answers `EXDEV` and a positional
/// read/write of the range stands in.
///
/// **Blocking - for a pool thread, never the reactor.** Even a clone that moves no data takes filesystem locks and can
/// wait on dirty data, so there is no fast path that may run on the loop.
///
/// **The clone is the kernel's, not an ioctl's.** On ZFS `copy_file_range(2)` already tries a clone and falls back to a
/// byte copy, while `FICLONERANGE` refuses a range it can only partly clone, after waiting a transaction group for the
/// source.
///
/// Needs no [`Personality`], since the kernel authorizes the copy from the open modes of the two [`File`]s.
pub(crate) fn copy_range(src: &File, dst: &File, off_src: u64, off_dst: u64, len: u64) -> crate::Result<u64> {
    copy_file_range_blocking(src.as_raw_fd(), dst.as_raw_fd(), off_src, off_dst, len)
}

fn copy_file_range_blocking(src: RawFd, dst: RawFd, off_src: u64, off_dst: u64, len: u64) -> crate::Result<u64> {
    let mut soff = off_src as i64;
    let mut doff = off_dst as i64;
    let mut remaining = len;
    let mut total = 0u64;
    while remaining > 0 {
        let want = remaining.min(MAX_CHUNK as u64) as usize;
        // SAFETY: `src`/`dst` are live raw fds (the job holds the owning `File` clones); `soff`/`doff` are valid locals
        // the kernel reads and advances.
        let n = retry_on_eintr(|| unsafe { libc::copy_file_range(src, &mut soff, dst, &mut doff, want, 0) });
        match n {
            Ok(0) => break, // source EOF
            Ok(n) => {
                total += n as u64;
                remaining -= n as u64;
            }
            // Cross-filesystem: byte-copy the whole requested range instead.
            Err(Errno::EXDEV) if total == 0 => {
                return copy_range_rw(src, dst, off_src, off_dst, len);
            }
            Err(e) => return Err(e.into()),
        }
    }
    Ok(total)
}

/// Positional read/write fallback for the cross-filesystem (`EXDEV`) case.
fn copy_range_rw(src: RawFd, dst: RawFd, off_src: u64, off_dst: u64, len: u64) -> crate::Result<u64> {
    let mut buf = vec![0u8; MAX_CHUNK.min(1 << 20)];
    let mut soff = off_src as i64;
    let mut doff = off_dst as i64;
    let mut remaining = len;
    let mut total = 0u64;
    while remaining > 0 {
        let want = remaining.min(buf.len() as u64) as usize;
        // SAFETY: reading `want` bytes into a live buffer at a valid offset.
        let r = retry_on_eintr(|| unsafe { libc::pread(src, buf.as_mut_ptr().cast(), want, soff) })?;
        if r == 0 {
            break; // source EOF
        }
        let r = r as usize;
        let mut written = 0usize;
        while written < r {
            // SAFETY: writing a sub-slice we just filled to a live fd.
            let w = retry_on_eintr(|| unsafe {
                libc::pwrite(dst, buf[written..r].as_ptr().cast(), r - written, doff + written as i64)
            })?;
            if w == 0 {
                return Err(Errno::EIO.into());
            }
            written += w as usize;
        }
        soff += r as i64;
        doff += r as i64;
        total += r as u64;
        remaining -= r as u64;
    }
    Ok(total)
}

#[cfg(all(test, not(loom)))]
mod confinement_tests;

#[cfg(all(test, not(loom)))]
mod order_tests;

#[cfg(all(test, not(loom)))]
mod narrow_tests;

#[cfg(all(test, not(loom)))]
mod copy_range_tests;
