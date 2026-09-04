//! [`query_directory`]: a **pull-based**, batched directory listing with
//! configurable per-entry enrichment, over the blocking [`FsHandle`].
//!
//! There is no io_uring `getdents`/`readdir` op, so the **name feed** is a
//! `readdir` pass over the directory fd on the caller's own thread (no worker,
//! no channel). [`QueryDir::next`] reads the next `clump` names, then enriches
//! them by **scattering non-blocking reactor ops** - `statx` (path-based) and
//! `fgetxattr` on an opened entry fd - through the [`FsHandle`] `start_*` twins:
//! all of a clump's ops are submitted before any is waited on, so they run
//! concurrently on the ring. The directory `DIR*` is held open across `next`
//! calls (incremental; nothing is buffered up front) and closed on `Drop`.
//!
//! The directory is opened **under the caller's [`Personality`]** - that open
//! is the DAC/list-permission check (`EACCES` if `who` cannot list), so
//! enumeration never runs under the reactor's ambient root.
//!
//! Entries come in raw `readdir` order unless [`QueryOptions::order`] asks
//! for otherwise; see [`Order`] for what the ordered modes cost, and
//! [`query_tree`](super::query_tree::query_tree) to walk a whole subtree in
//! path order.
//!
//! # A listing is not a snapshot
//!
//! The name feed is `readdir`, and its contract admits an entry renamed
//! during the sweep being missed or reported twice. Sorting afterwards
//! cannot restore what the sweep never saw, so an ordered listing is as
//! non-atomic as an unordered one - it is merely sorted.
//!
//! Paging with [`QueryOptions::start_after`] widens that window rather than
//! closing it. Each continuation is its own sweep of a directory that has
//! moved on since the last, so an entry renamed between pages can be absent
//! from both or present in both under two names.
//!
//! Measured on ZFS under rename churn: a 4,000-entry directory lost an entry
//! in 10 of 16 listings, and a 20,000-entry one yielded between 19,998 and
//! 20,001 distinct names across 12 rounds. Create/unlink churn and
//! `RENAME_EXCHANGE` were exact - it is specifically a rename that *changes
//! the name* that can move an entry across the cursor.
//!
//! A caller that needs a point-in-time view needs a snapshot underneath it
//! (`.zfs/snapshot`); no listing option can supply one.

use super::offload_pool::{Job, SharedPool};
use super::{Anchor, File, FsHandle, FsPending, Leaf, Personality};
use crate::errno::{Errno, retry_on_eintr};
use crate::sync_fs::xattr::{
    XATTR_SIZE_MAX, XATTR_SIZE_RETRIES, flistxattr, xattr_retry_cap,
};
use crate::sync_fs::{AtFlags, OFlag, OpenHow, Statx, StatxMask};
use bitflags::bitflags;
use std::collections::VecDeque;
use std::ffi::{CStr, CString, OsString};
use std::fmt;
use std::os::fd::{AsFd, RawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
// `Arc` and the reply channels come from `crate::sync` - std's outside
// `--cfg loom` - so this file compiles in the pool's loom model build.
use crate::sync::{Arc, mpsc};

bitflags! {
    /// What to fetch for each directory entry. `STATX` is cheap (a path-based
    /// `statx`, no open); `XATTR`/`ACL` open the entry `O_RDONLY|O_NOFOLLOW` and
    /// `fgetxattr` it.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct EnrichSpec: u8 {
        /// size / mtime / type via a path-based `statx`.
        const STATX = 0b0001;
        /// the named extended attributes in [`QueryOptions::xattr_names`].
        const XATTR = 0b0010;
        /// the ACL extended attribute in [`QueryOptions::acl_name`]
        /// (`system.nfs4_acl_xdr` on ZFS, or `system.posix_acl_access`).
        const ACL = 0b0100;
        /// discover attribute names via `flistxattr`, filtered to the
        /// namespaces in [`QueryOptions::xattr_ns`], and fetch their values
        /// (see [`XattrNamespaces`] for the credential contract).
        const XATTR_LIST = 0b1000;
    }
}

bitflags! {
    /// Extended-attribute namespaces to enumerate for
    /// [`EnrichSpec::XATTR_LIST`].
    ///
    /// The caller declares which namespaces it wants. Discovery runs
    /// `flistxattr` to propose candidate names, keeps those in the selected
    /// namespaces, and reads each value under the request identity `who`; only
    /// attributes `who` can actually read are returned (an attribute `who`
    /// lacks the privilege to read, such as `trusted.*` for a non-privileged
    /// identity, is dropped). The kernel lists `user.`/`security.`/`system.`
    /// names to any caller and gates `trusted.` on `CAP_SYS_ADMIN`; this crate
    /// does not re-implement that policy, it enforces the per-value `who`
    /// check. The consumer remains responsible for understanding and filtering
    /// what is actually safe to expose to its own callers.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct XattrNamespaces: u8 {
        /// The `user.` namespace (unprivileged application metadata; e.g. the
        /// `user.DosStream.*` attributes an SMB server maps to NTFS streams).
        const USER = 0b0001;
        /// The `trusted.` namespace (reading a value requires `CAP_SYS_ADMIN`).
        const TRUSTED = 0b0010;
        /// The `security.` namespace (LSM labels, file capabilities).
        const SECURITY = 0b0100;
        /// The `system.` namespace (ACLs; e.g. `system.posix_acl_access`,
        /// `system.nfs4_acl_xdr`).
        ///
        /// On an `acltype=nfsv4` dataset ZFS lists `system.nfs4_acl_xdr` only
        /// when the ACL is **not** trivial (`zpl_xattr_list`), and almost every
        /// object carries a trivial one - so discovery alone is not a reliable
        /// way to pick ACLs up. Ask for [`EnrichSpec::ACL`] instead, which
        /// fetches [`QueryOptions::acl_name`] directly.
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
    /// Namespaces to enumerate when [`EnrichSpec::XATTR_LIST`] is set; the
    /// library returns only the attributes readable under `who`. Defaults to
    /// [`XattrNamespaces::USER`]. See [`XattrNamespaces`] for the contract.
    pub xattr_ns: XattrNamespaces,
    /// The ACL xattr name to fetch when [`EnrichSpec::ACL`] is set.
    pub acl_name: CString,
    /// Entries per yielded batch (clamped to at least 1).
    pub clump: usize,
    /// Drop entries that live on a **different filesystem** from the directory
    /// being listed - a mount point, which on ZFS means a child dataset or a
    /// `.zfs/snapshot` automount.
    ///
    /// `readdir` honours no `RESOLVE_*` flags, so a walk has no equivalent of
    /// [`CONFINED_RESOLVE`](crate::uring_fs::CONFINED_RESOLVE)'s
    /// `RESOLVE_NO_XDEV`: a nested mount simply appears as an ordinary entry.
    /// Setting this restores the same rule on the listing side, so a tree that
    /// is meant to be one filesystem lists as one filesystem.
    ///
    /// Requires [`EnrichSpec::STATX`] (the device number comes from `statx`);
    /// without it the option cannot be honoured and is ignored.
    ///
    /// **It fails open, and one of the three ways it can is not a
    /// configuration choice.** The filter compares two device numbers and
    /// keeps the entry whenever either is missing: with `STATX` unset (the
    /// line above), with no device for the directory itself, and - the one
    /// a caller does not opt into - when a *per-entry* `statx` fails while
    /// `STATX` was requested. Each entry's `statx` is a ring op, and a full
    /// op table answers a marked `EBUSY`, so under exactly the pressure
    /// that makes a listing large a child dataset or a `.zfs/snapshot`
    /// automount can appear as an ordinary entry in a listing whose caller
    /// asked for one filesystem. [`DirEntry`] has no equivalent of
    /// [`DirEntry::xattrs_incomplete`] here, so a caller cannot re-check
    /// or refuse either. [`TreeOptions`](super::query_tree::TreeOptions)
    /// surfaces this verbatim, so a subtree walk inherits it at every
    /// level.
    pub same_device_only: bool,
    /// The `statx` mask requested for each entry when [`EnrichSpec::STATX`] is
    /// set. Defaults to [`StatxMask::BASIC_STATS`]; widen it to ask for fields
    /// the basic set omits - notably [`StatxMask::CHANGE_COOKIE`], which costs
    /// nothing extra here because the `statx` runs either way and gives a
    /// caller an exact validator for anything it caches per entry (see
    /// [`Statx::change_cookie`]).
    pub statx_mask: StatxMask,
    /// The order entries are yielded in. Defaults to [`Order::Readdir`] - see
    /// [`Order`] for what the ordered modes cost.
    pub order: Order,
    /// Yield only entries whose name starts with these bytes.
    ///
    /// Applied during the `readdir` pass, **before** any enrichment, so a
    /// filtered-out entry costs neither a `statx` nor an open. A batch is
    /// still filled to `clump` kept entries, so a short batch still means
    /// end-of-directory.
    pub name_prefix: Option<Vec<u8>>,
    /// Skip entries up to and including this key, in the active [`Order`].
    ///
    /// These bytes are compared as a **literal key**, not as a bare name: to
    /// resume past the directory `a` under [`Order::ByPathBytes`], pass `a/`
    /// -- exactly where `a/` sorts - rather than `a`, which is where a *file*
    /// named `a` sorts.
    ///
    /// Ignored under [`Order::Readdir`], which has no order to be "after".
    /// Note this prunes *after* the directory has been read and sorted - it
    /// resumes a listing, it does not make resuming cheap.
    ///
    /// Resuming is also not a snapshot: each continuation re-reads a
    /// directory that has moved on, so an entry renamed between pages can be
    /// missed by both or reported by both under two names. See the module
    /// docs - this is `readdir`'s contract, not something paging closes.
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
/// [`Order::Readdir`] streams: a batch costs one `readdir` of `clump` names.
/// **Both ordered modes read the whole directory before the first batch**, so
/// they cost one full `getdents` sweep plus an O(n log n) sort up front, and
/// hold every name in memory for the life of the [`QueryDir`]. That is
/// inherent - the smallest name cannot be known without seeing them all.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Order {
    /// Whatever the filesystem returns. On ZFS that is hash order, not
    /// alphabetical. Cheapest, and the only streaming mode.
    #[default]
    Readdir,
    /// Byte order of the entry names.
    ByName,
    /// Byte order of the entry names **with a `/` appended to directories**,
    /// which is the order the *full paths* beneath this directory compare in.
    ///
    /// This is the difference between sorting names and sorting keys, and it
    /// is not cosmetic. `/` is `0x2F`, so a bare-name sort puts the directory
    /// `a` before `a-1.txt` and `a.txt`, and a depth-first walk would then
    /// emit `a/b.txt` before both - while their full paths order
    /// `a-1.txt` < `a.txt` < `a/b.txt`. Appending the separator that will
    /// actually follow the directory name restores agreement, so sorting each
    /// directory this way and recursing in that order yields a subtree in
    /// global path order with no global sort.
    ///
    /// Directory-ness comes from the `readdir` `d_type`; entries reported as
    /// `DT_UNKNOWN` are resolved with a `statx` before sorting, since guessing
    /// would silently reorder them.
    ByPathBytes,
}

/// One enriched directory entry. Which fields are populated depends on the
/// [`EnrichSpec`]; a field is `None`/empty when not requested or unavailable.
#[derive(Clone, Debug)]
pub struct DirEntry {
    /// The entry name (a single path component).
    pub name: OsString,
    /// True if the entry is a directory (from `statx`, else the `readdir`
    /// `d_type` hint).
    pub is_dir: bool,
    /// `statx` metadata, when [`EnrichSpec::STATX`] was requested and succeeded.
    pub statx: Option<Statx>,
    /// Requested and discovered xattrs. Explicit [`QueryOptions::xattr_names`]
    /// come first, in request order, with `value` `None` when the attribute is
    /// absent (or the entry could not be opened); names discovered via
    /// [`EnrichSpec::XATTR_LIST`] follow, sorted, each readable under `who`
    /// (unreadable ones are dropped rather than listed).
    pub xattrs: Vec<(CString, Option<Vec<u8>>)>,
    /// The ACL xattr value, when [`EnrichSpec::ACL`] was requested and present.
    pub acl: Option<Vec<u8>>,
    /// Discovery could not report every attribute: the `flistxattr` itself
    /// failed (a name list past `XATTR_LIST_MAX` yields `E2BIG`), an op slot
    /// was unavailable, or a value known to be readable could not be refetched.
    /// It separates "this entry has no extended attributes" from "the listing
    /// could not be completed", which are otherwise both an empty
    /// [`xattrs`](Self::xattrs). Never set for an attribute `who` simply cannot
    /// read - that is a deliberate drop, not a failure.
    pub xattrs_incomplete: bool,
}

/// A running directory query. Pull enriched batches with [`next`](QueryDir::next)
/// until it returns `None` (end of directory). Dropping it closes the directory.
///
/// Not `Send` (it owns a `DIR*`, whose `readdir` cursor is single-threaded);
/// use it on the thread that created it.
pub struct QueryDir {
    dp: *mut libc::DIR,
    h: FsHandle,
    who: Personality,
    dir: Anchor,
    /// The listed directory's device, for
    /// [`QueryOptions::same_device_only`]. `None` if it could not be
    /// determined, in which case nothing is filtered.
    dir_dev: Option<u64>,
    opts: QueryOptions,
    /// Ordered modes only: every kept name in the directory, sorted, read on
    /// the first [`QueryDir::next`] and drained a `clump` at a time after.
    /// `None` until that first call; `Some(empty)` once exhausted.
    sorted: Option<VecDeque<(OsString, u8)>>,
    /// A batch answered `Err`, so the listing is over.
    ///
    /// **Continuing past one would be the data loss the error exists to
    /// report.** A clump's names are already off the `readdir` stream by the
    /// time it can fail, and that stream has no rewind: calling
    /// [`next`](QueryDir::next) again would resume at the *following* clump
    /// and hand the caller the rest of the directory with a hole in it,
    /// which reads as a complete listing. `FsIter` carries the same flag for
    /// the same reason.
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
    /// The descriptor being read (the `fdopendir` dup); closed when this
    /// `QueryDir` drops. For diagnostics / tests.
    pub fn dir_fd(&self) -> RawFd {
        // SAFETY: `dp` is a live `DIR*` for this handle's lifetime.
        unsafe { libc::dirfd(self.dp) }
    }

    /// The next enriched batch of up to `clump` entries, or `None` at
    /// end-of-directory. A `readdir` error surfaces as `Some(Err)`.
    // Inherent `next`, not `Iterator`: `QueryDir` owns a `!Send` `DIR*` and
    // yields fallible batches the caller drives.
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

    /// The next `clump` names to enrich. Streams straight off `readdir` under
    /// [`Order::Readdir`]; under an ordered mode the whole directory is read
    /// and sorted on the first call and drained from there after.
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

    /// Read the entire directory, resolve any `DT_UNKNOWN` needed for the
    /// sort, sort, and drop everything up to `start_after`.
    fn read_all_sorted(&mut self) -> crate::Result<VecDeque<(OsString, u8)>> {
        let mut all = self.read_clump(usize::MAX)?;
        match self.opts.order {
            // `next_names` only reaches here for an ordered mode.
            Order::Readdir => {}
            Order::ByName => {
                all.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()))
            }
            Order::ByPathBytes => {
                self.resolve_unknown_dtypes(&mut all);
                all.sort_by(|a, b| {
                    cmp_path_bytes(
                        a.0.as_bytes(),
                        a.1 == libc::DT_DIR,
                        b.0.as_bytes(),
                        b.1 == libc::DT_DIR,
                    )
                });
            }
        }
        if let Some(after) = &self.opts.start_after {
            // `after` is a literal key, never a bare name needing a separator
            // synthesized for it: a caller resuming past the directory `a`
            // passes `a/`, which is exactly where `a/` sorts. Hence `false`.
            let cut = match self.opts.order {
                Order::ByPathBytes => all.partition_point(|(n, d)| {
                    cmp_path_bytes(
                        n.as_bytes(),
                        *d == libc::DT_DIR,
                        after,
                        false,
                    )
                    .is_le()
                }),
                _ => all.partition_point(|(n, _)| n.as_bytes() <= &after[..]),
            };
            all.drain(..cut);
        }
        Ok(all.into())
    }

    /// Give every `DT_UNKNOWN` entry a real `d_type` with a scatter-gathered
    /// `statx`, so [`Order::ByPathBytes`] never has to guess whether a name
    /// carries a trailing separator. An entry whose `statx` fails keeps
    /// `DT_UNKNOWN` and sorts as a non-directory - the same answer guessing
    /// would have given, but only where the kernel could tell us nothing.
    fn resolve_unknown_dtypes(&self, all: &mut [(OsString, u8)]) {
        let pending: Vec<(usize, FsPending)> = all
            .iter()
            .enumerate()
            .filter(|(_, (_, d))| *d == libc::DT_UNKNOWN)
            .filter_map(|(i, (name, _))| {
                let leaf = Leaf::new(name.as_bytes()).ok()?;
                let p = self
                    .h
                    .start_statx(
                        self.who,
                        &self.dir,
                        leaf,
                        AtFlags::AT_SYMLINK_NOFOLLOW,
                        StatxMask::TYPE,
                    )
                    .ok()?;
                Some((i, p))
            })
            .collect();
        for (i, p) in pending {
            if let Some(st) = pending_statx(p) {
                all[i].1 = if st.is_dir() {
                    libc::DT_DIR
                } else {
                    libc::DT_REG
                };
            }
        }
    }

    /// Read up to `limit` kept entry names (with their `d_type`), skipping
    /// `.`/`..` and anything [`QueryOptions::name_prefix`] excludes. Fewer
    /// than `limit` (or an empty `Vec`) marks end-of-directory.
    fn read_clump(
        &mut self,
        limit: usize,
    ) -> crate::Result<Vec<(OsString, u8)>> {
        let mut out = Vec::with_capacity(limit.min(self.opts.clump));
        while out.len() < limit {
            Errno::clear();
            // SAFETY: `dp` is a live `DIR*`; the returned pointer is valid until
            // the next `readdir`/`closedir` - copied out immediately below.
            let ent = unsafe { libc::readdir(self.dp) };
            if ent.is_null() {
                return match Errno::last_raw() {
                    0 => Ok(out), // end of directory
                    _ => Err(Errno::last().into()),
                };
            }
            // SAFETY: `ent` is a valid `dirent`; `d_name` is NUL-terminated.
            // `addr_of!` avoids forming a `&[c_char; 256]` over a record that
            // may be shorter than the full array.
            let (bytes, dtype) = unsafe {
                let name = CStr::from_ptr(
                    std::ptr::addr_of!((*ent).d_name).cast::<libc::c_char>(),
                );
                (name.to_bytes().to_vec(), (*ent).d_type)
            };
            if bytes == b"." || bytes == b".." {
                continue;
            }
            // Pushed down into the readdir pass: an unwanted name costs no
            // statx, no open and no xattr read.
            if self
                .opts
                .name_prefix
                .as_ref()
                .is_some_and(|p| !bytes.starts_with(p))
            {
                continue;
            }
            out.push((OsString::from_vec(bytes), dtype));
        }
        Ok(out)
    }

    /// Enrich a clump of entries. For each entry, request its `statx` and open
    /// its fd, then `fgetxattr` the requested and discovered attributes on that
    /// fd. A clump's ring ops are all submitted before any result is awaited, so
    /// they overlap on the ring, and each runs under `who`. `XATTR_LIST`
    /// discovery lists candidate names with `flistxattr` on the caller's own
    /// thread, then reads their values under `who` and keeps only the readable
    /// ones.
    fn enrich(
        &self,
        names: Vec<(OsString, u8)>,
    ) -> crate::Result<Vec<DirEntry>> {
        let who = self.who;
        let spec = self.opts.spec;
        // With the confinement asked for, an entry whose device cannot be
        // determined is answered for rather than yielded
        // ([`unknown_device_verdict`]). The refusal is collected here
        // because the judgement sits inside an iterator pipeline.
        let confined = self.opts.same_device_only;
        let mut refused: Option<Errno> = None;

        // A descriptor is opened whenever anything below needs one. Where it
        // is, the entry's metadata is taken from that descriptor rather than
        // from a second resolution of the same name: two independent by-name
        // lookups can land on two different inodes under rename churn, and
        // pairing them reports one file's size, mtime and change cookie
        // against another file's name. The fd-keyed `statx` is issued in the
        // read phase below, where it overlaps the xattr reads, so this costs
        // no op that the by-name form did not already cost.
        let wants_fd = spec.intersects(
            EnrichSpec::XATTR | EnrichSpec::ACL | EnrichSpec::XATTR_LIST,
        );

        // Request statx and an fd for each entry, opened as `who`.
        let requested: Vec<Requested> = names
            .into_iter()
            .map(|(name, dtype)| {
                let statx = if spec.contains(EnrichSpec::STATX) && !wants_fd {
                    Leaf::new(name.as_bytes()).ok().and_then(|leaf| {
                        self.h
                            .start_statx(
                                who,
                                &self.dir,
                                leaf,
                                AtFlags::AT_SYMLINK_NOFOLLOW,
                                self.opts.statx_mask,
                            )
                            .ok()
                    })
                } else {
                    None
                };
                let open = if wants_fd {
                    let how = OpenHow::new().flags(
                        OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK,
                    );
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

        // Collect each entry's opened fd and, where one was issued, its
        // by-name statx, dropping anything that crossed a mount point when
        // the caller asked for one filesystem.
        //
        // That drop needs metadata, so it runs here only for the entries that
        // have some - the no-descriptor case - and is deferred to the assembly
        // below for the rest. The trade is deliberate: a crossed entry pays
        // for xattr reads it did not need, and every ordinary entry is spared
        // a second `statx`. Crossing is the rare case; being listed is not.
        let cross_dev = |st: Option<&Statx>| match (self.dir_dev, st) {
            (Some(dev), Some(st)) => st.dev() != dev,
            // No device for the directory, or no statx for the entry: nothing
            // to compare, so nothing is dropped.
            _ => false,
        };
        let opened: Vec<Opened> = requested
            .into_iter()
            .filter_map(|p| {
                // Only the early drop here; the verdict on an entry with no
                // device is the assembly's, which is the one place that has
                // seen every attempt to get one.
                let (statx, statx_err) = split_statx(p.statx);
                if statx.is_some() && confined && cross_dev(statx.as_ref()) {
                    return None;
                }
                let file = p.open.and_then(pending_file);
                Some(Opened {
                    name: p.name,
                    dtype: p.dtype,
                    statx,
                    statx_err,
                    file,
                })
            })
            .collect();

        // For each opened fd, read the explicit names and ACL, and read each
        // discovered name into the initial buffer.
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
                            // This entry's own descriptor, so no name is
                            // resolved and the metadata cannot describe a
                            // different inode. Issued here rather than with
                            // the open so it pipelines with the xattr reads
                            // below instead of costing a round trip.
                            statx_pending = self
                                .h
                                .start_fstatx(
                                    who,
                                    f,
                                    AtFlags::empty(),
                                    self.opts.statx_mask,
                                )
                                .ok();
                        }
                        if spec.contains(EnrichSpec::XATTR) {
                            for xn in &self.opts.xattr_names {
                                let pend = self
                                    .h
                                    .start_fgetxattr(
                                        who,
                                        f,
                                        xn,
                                        vec![0u8; 4096],
                                    )
                                    .ok();
                                xattrs.push((xn.clone(), pend));
                            }
                        }
                        if spec.contains(EnrichSpec::ACL) {
                            acl = self
                                .h
                                .start_fgetxattr(
                                    who,
                                    f,
                                    &self.opts.acl_name,
                                    vec![0u8; 65536],
                                )
                                .ok();
                        }
                        if spec.contains(EnrichSpec::XATTR_LIST) {
                            // Exclude only names actually fetched above, so
                            // `XATTR_LIST` without `XATTR` still surfaces every
                            // name in the namespace.
                            let explicit: &[CString] =
                                if spec.contains(EnrichSpec::XATTR) {
                                    self.opts.xattr_names.as_slice()
                                } else {
                                    &[]
                                };
                            // The ACL was fetched above into `acl`; discovering
                            // it again would spend a second op and a second
                            // 64 KiB buffer on the same bytes.
                            let fetched_acl = spec
                                .contains(EnrichSpec::ACL)
                                .then_some(self.opts.acl_name.as_c_str());
                            let (names, listed) = discover_names(
                                f,
                                self.opts.xattr_ns,
                                explicit,
                                fetched_acl,
                            );
                            incomplete |= !listed;
                            for dn in names {
                                let pend = self
                                    .h
                                    .start_fgetxattr(
                                        who,
                                        f,
                                        &dn,
                                        vec![0u8; DISCOVER_BUF],
                                    )
                                    .ok();
                                // No op slot: the attribute exists but was
                                // never read, which is not "absent".
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
                // An entry whose open failed has no descriptor to stat, and
                // so nothing for a by-name answer to be mispaired against:
                // there it is both safe and the only answer available.
                if statx_pending.is_none()
                    && p.statx.is_none()
                    && spec.contains(EnrichSpec::STATX)
                {
                    statx_pending =
                        Leaf::new(p.name.as_bytes()).ok().and_then(|leaf| {
                            self.h
                                .start_statx(
                                    who,
                                    &self.dir,
                                    leaf,
                                    AtFlags::AT_SYMLINK_NOFOLLOW,
                                    self.opts.statx_mask,
                                )
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

        // Assemble each entry. Explicit xattrs keep their slot, with a `None`
        // value when absent; any value larger than the initial buffer, explicit
        // or discovered, is refetched at its true size under `who`, and a
        // discovered attribute `who` cannot read is dropped. The fd is held
        // until any refetch finishes, then dropped (each in-flight op keeps its
        // own reference).
        let entries: Vec<DirEntry> = reading
            .into_iter()
            .filter_map(|p| {
                // The descriptor's own answer where there is one; the by-name
                // answer only where no descriptor was opened.
                let (fd_statx, fd_err) = split_statx(p.statx_pending);
                let statx = fd_statx.or(p.statx);
                let statx_err = fd_err.or(p.statx_err);
                // **The one place an entry's device is judged**, because it
                // is the only one that has seen every attempt to get it: the
                // by-name `statx`, the descriptor's own, and the by-name
                // retry when no descriptor opened. Judging at the collection
                // phase instead reads "no metadata yet" as a failure for
                // every entry whose device was always going to come from a
                // descriptor - which is every entry, whenever the caller
                // asked for xattrs, an ACL or a name list.
                if confined && spec.contains(EnrichSpec::STATX) {
                    if statx.is_none() {
                        if let Some(e) = unknown_device_verdict(statx_err) {
                            refused = refused.or(Some(e));
                        }
                        return None;
                    }
                    if cross_dev(statx.as_ref()) {
                        return None;
                    }
                }
                // A verdict from the metadata where there is any, and only
                // then the readdir hint.
                let is_dir = statx
                    .as_ref()
                    .map(Statx::is_dir)
                    .unwrap_or(p.dtype == libc::DT_DIR);
                let mut xattrs: Vec<(CString, Option<Vec<u8>>)> = p
                    .xattrs
                    .into_iter()
                    .map(|(xn, pend)| {
                        let val = match pend.map(pending_discovered) {
                            Some(DiscRead::Got(v)) => Some(v),
                            Some(DiscRead::Grow) => {
                                p.file.as_ref().and_then(|f| {
                                    refetch_grow(&self.h, who, f, &xn)
                                })
                            }
                            Some(DiscRead::Drop) | None => None,
                        };
                        (xn, val)
                    })
                    .collect();
                let acl = p.acl.and_then(pending_bytes);
                let mut incomplete = p.incomplete;
                for (dn, pend) in p.discovered {
                    let val = match pend.map(pending_discovered) {
                        Some(DiscRead::Got(v)) => Some(v),
                        Some(DiscRead::Grow) => {
                            // `ERANGE` proved the value readable and oversized,
                            // so losing it now is a failed read, not a denial.
                            let v = p.file.as_ref().and_then(|f| {
                                refetch_grow(&self.h, who, f, &dn)
                            });
                            incomplete |= v.is_none();
                            v
                        }
                        Some(DiscRead::Drop) | None => None,
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
        // After the pipelines, not inside them: the ops of a clump are all
        // in flight, and abandoning the collection early would leave their
        // completions - and the descriptors they carry - to be reaped by
        // nobody. Every entry is awaited either way; only the verdict
        // changes.
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
    /// Why that answer is absent, where one was attempted. `None` both when
    /// it succeeded and when none was issued - the assembly tells those
    /// apart by whether it ends up with metadata.
    statx_err: Option<Errno>,
    file: Option<File>,
}
struct Reading {
    name: OsString,
    dtype: u8,
    /// The by-name answer, present only where no descriptor was opened.
    statx: Option<Statx>,
    /// Why that answer is absent, where one was attempted.
    statx_err: Option<Errno>,
    /// A `statx` of the descriptor this entry actually holds, issued with the
    /// xattr reads. Supersedes the by-name answer, which cannot be trusted to
    /// describe the same inode the open resolved to.
    statx_pending: Option<FsPending>,
    // Kept alive until any oversized discovered value has been refetched; each
    // in-flight op holds its own reference regardless.
    file: Option<File>,
    xattrs: Vec<(CString, Option<FsPending>)>,
    acl: Option<FsPending>,
    discovered: Vec<(CString, Option<FsPending>)>,
    /// Discovery already lost something for this entry (see
    /// [`DirEntry::xattrs_incomplete`]).
    incomplete: bool,
}

/// Await a `statx` twin: `Some(Statx)` on success, else `None`.
fn pending_statx(p: FsPending) -> Option<Statx> {
    let out = p.into_outcome().ok()?;
    out.res.ok()?;
    out.stat.map(|raw| Statx::from_raw(*raw))
}

/// Await an entry's `statx`, keeping the errno apart from the metadata.
///
/// `(None, None)` means no `statx` was issued for this entry at all - which
/// is ordinary: the by-name one is skipped whenever a descriptor is opened,
/// because the descriptor's own answer supersedes it.
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

/// What a confined listing does with an entry whose device it could not
/// read: drop this one, or fail the batch.
///
/// **`same_device_only` is a confinement, and the filter behind it keeps an
/// entry whose device is unknown.** It exists to drop what lives on another
/// filesystem - on ZFS a child dataset or a `.zfs/snapshot` automount - so a
/// listing that silently includes one it could not check is exactly what the
/// caller asked not to get. With the option set, an unresolved `statx` is
/// therefore answered for.
///
/// The split is `query_tree`'s `is_subtree_skip`, deliberately: skip only
/// what has nothing left to list, surface everything else, because a partial
/// listing that reads as complete is data loss for whatever is built on it.
///
/// * `EACCES`/`EPERM` - this identity may not see it, which is the
///   per-identity behaviour the rest of this module already has (an xattr
///   `who` cannot read is dropped, not reported).
/// * `ENOENT` - the entry went away between `readdir` and the `statx`. A
///   walk over a live tree hits this routinely.
/// * Anything else - the marked `EBUSY` of a full op table above all, which
///   is reached under exactly the pressure that makes a listing large - is
///   the filter failing, and the caller is told. `EBUSY` there is the
///   documented retryable refusal.
/// * No errno at all: nothing was issued where something should have been.
///   Not "nothing to list", so it surfaces too.
fn unknown_device_verdict(err: Option<Errno>) -> Option<Errno> {
    match err {
        Some(Errno::EACCES | Errno::EPERM | Errno::ENOENT) => None,
        Some(e) => Some(e),
        None => Some(Errno::ECONNABORTED),
    }
}

/// Await an `open` twin: the opened [`File`] on success, else `None`.
fn pending_file(p: FsPending) -> Option<File> {
    let out = p.into_outcome().ok()?;
    out.res.ok()?;
    out.file.map(File::new)
}

/// Await an `fgetxattr` twin: the attribute value (truncated to its size), else
/// `None` (absent / error / gone loop).
fn pending_bytes(p: FsPending) -> Option<Vec<u8>> {
    let out = p.into_outcome().ok()?;
    let n = usize::try_from(out.res.ok()?).ok()?;
    let buf = out.bufs.into_iter().next()?;
    right_size(buf, n)
}

/// Initial buffer for a discovered attribute's value read; larger values are
/// refetched at their true size (see [`refetch_grow`]).
const DISCOVER_BUF: usize = 4096;

/// The namespace an attribute name belongs to (by prefix), or `None` for a name
/// outside the four standard namespaces.
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

/// `flistxattr` the entry, keep names in the requested namespaces, drop any
/// already fetched (the `explicit` names and `fetched_acl`), and return them
/// sorted (stable output) along with whether the listing itself succeeded. Runs
/// on the caller's own thread (the same thread that reads the directory), at
/// that thread's privilege: it only proposes candidates, the per-value `who`
/// read is the authoritative gate.
///
/// A failed `flistxattr` returns no names and `false`, so the caller can tell
/// it apart from an entry that genuinely has none.
fn discover_names(
    f: &File,
    want: XattrNamespaces,
    explicit: &[CString],
    fetched_acl: Option<&CStr>,
) -> (Vec<CString>, bool) {
    let (mut names, listed): (Vec<CString>, bool) =
        match flistxattr(f.fd.as_fd()) {
            Ok(list) => (
                list.into_iter()
                    .filter(|n| {
                        namespace_of(n.as_bytes())
                            .is_some_and(|ns| want.intersects(ns))
                    })
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
    /// Absent, or `who` lacks the privilege to read it, or the loop is gone.
    Drop,
}

/// Narrow an owned buffer to the `n` bytes the kernel filled, keeping the
/// allocation. For [`refetch_grow`] only, whose buffer was sized from the
/// value's probed size ([`xattr_retry_cap`]: exact on the first fetch, 1.5x
/// on a growth retry) - there the allocation IS the value's size, so
/// truncating hands back what went to the kernel with nothing retained and
/// nothing copied.
///
/// Do not reach for this from a fixed-probe read ([`DISCOVER_BUF`], the ACL
/// buffer): `truncate` never shrinks capacity, so a small value would carry
/// the whole probe buffer for as long as the caller holds it - that is what
/// [`right_size`] is for.
///
/// `None` if `n` is past what the buffer holds - `truncate` alone is silently a
/// no-op there, and a count the buffer cannot account for is not a value.
fn narrow(mut buf: Vec<u8>, n: usize) -> Option<Vec<u8>> {
    if n > buf.len() {
        return None;
    }
    buf.truncate(n);
    Some(buf)
}

/// Narrow a fixed-size probe buffer to the `n` bytes the kernel filled,
/// giving surplus capacity back when the value is small.
///
/// The probe buffers are sized for the values they might hold (4 KiB
/// discovery, 64 KiB ACL), not the values they do: a typical ACL is tens of
/// bytes, and these `Vec`s land in [`DirEntry`] fields the caller holds for
/// as long as it holds the listing - measured at 315x the value bytes for
/// xattrs and 5041x for ACLs on a real dataset. Shrinking costs one
/// value-sized `memcpy`; it is skipped when the value fills more than half
/// the buffer, so the copy is only ever paid to reclaim at least its own
/// size again.
///
/// Bounds exactly as [`narrow`]: a count past the buffer is refused.
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
        return DiscRead::Drop;
    };
    match out.res {
        Ok(n) => match out
            .bufs
            .into_iter()
            .next()
            .and_then(|b| right_size(b, usize::try_from(n).ok()?))
        {
            Some(v) => DiscRead::Got(v),
            None => DiscRead::Drop,
        },
        Err(Errno::ERANGE) => DiscRead::Grow,
        Err(_) => DiscRead::Drop,
    }
}

/// Refetch an attribute whose value outgrew its initial buffer: probe the size
/// and read at that size under `who`, bounded to [`XATTR_SIZE_MAX`]. A value
/// growing between probe and read yields `ERANGE` (rewritten to `E2BIG` once the
/// buffer reaches the cap, `fs/xattr.c`), so retry a bounded number of times,
/// over-allocating on retry so a steadily growing value converges. `None` if it
/// became unreadable or exceeds the cap. Mirrors the sync `fgetxattr` retry.
fn refetch_grow(
    h: &FsHandle,
    who: Personality,
    f: &File,
    name: &CStr,
) -> Option<Vec<u8>> {
    let mut tries = 0u32;
    loop {
        let (size, _) = h.fgetxattr(who, f, name, Vec::new());
        let size = size.ok()?;
        if size > XATTR_SIZE_MAX {
            return None;
        }
        let cap = xattr_retry_cap(size, tries);
        let (n, buf) = h.fgetxattr(who, f, name, vec![0u8; cap]);
        match n {
            Ok(n) => return narrow(buf, n),
            Err(crate::Error::Errno(Errno::ERANGE | Errno::E2BIG)) => {
                tries += 1;
                if tries >= XATTR_SIZE_RETRIES {
                    return None;
                }
            }
            Err(_) => return None,
        }
    }
}

/// List the extended-attribute names on `f` (all namespaces), sorted. Runs a
/// blocking `flistxattr` on the calling thread at its own privilege; names the
/// caller is not privileged to see (`trusted.*` without `CAP_SYS_ADMIN`) are
/// omitted by the kernel.
pub(crate) fn list_xattr_names(f: &File) -> crate::Result<Vec<CString>> {
    let mut names: Vec<CString> = flistxattr(f.fd.as_fd())?;
    names.sort();
    names.dedup();
    Ok(names)
}

/// Enumerate the extended attributes of `f` in the namespaces `want`, read each
/// value under `who`, and return only those `who` can read. `flistxattr` runs
/// on the calling thread proposing candidates; the per-value read under `who`
/// is the authoritative gate, so an attribute `who` cannot read is dropped.
/// Off-loop only: it blocks on the ring, so never run it on the reactor.
pub(crate) fn scan_xattrs(
    h: &FsHandle,
    who: Personality,
    f: &File,
    want: XattrNamespaces,
) -> crate::Result<Vec<(CString, Vec<u8>)>> {
    let mut names: Vec<CString> = flistxattr(f.fd.as_fd())?
        .into_iter()
        .filter(|n| {
            namespace_of(n.as_bytes()).is_some_and(|ns| want.intersects(ns))
        })
        .collect();
    names.sort();
    names.dedup();
    // Submit a read for every name before awaiting any, then gather.
    let pending: Vec<(CString, Option<FsPending>)> = names
        .into_iter()
        .map(|n| {
            let p = h.start_fgetxattr(who, f, &n, vec![0u8; DISCOVER_BUF]).ok();
            (n, p)
        })
        .collect();
    let mut out = Vec::with_capacity(pending.len());
    for (n, p) in pending {
        let val = match p.map(pending_discovered) {
            Some(DiscRead::Got(v)) => Some(v),
            Some(DiscRead::Grow) => refetch_grow(h, who, f, &n),
            Some(DiscRead::Drop) | None => None,
        };
        if let Some(v) = val {
            out.push((n, v));
        }
    }
    Ok(out)
}

/// Compare two entries the way their **full paths** compare: a directory is
/// ordered as though its name already carried the `/` that will separate it
/// from its children. See [`Order::ByPathBytes`] for why that is the only
/// ordering under which per-directory sorting composes into a correctly
/// ordered walk.
///
/// The trailing separator is synthesized during the comparison rather than by
/// building a key, so sorting a directory allocates nothing per entry.
fn cmp_path_bytes(
    a: &[u8],
    a_dir: bool,
    b: &[u8],
    b_dir: bool,
) -> std::cmp::Ordering {
    let (la, lb) = (a.len() + usize::from(a_dir), b.len() + usize::from(b_dir));
    // Past its name, an entry's only remaining key byte is its trailing `/`,
    // which is reachable only when the entry is a directory.
    let byte = |s: &[u8], i: usize| if i < s.len() { s[i] } else { b'/' };
    for i in 0..la.min(lb) {
        match byte(a, i).cmp(&byte(b, i)) {
            std::cmp::Ordering::Equal => continue,
            other => return other,
        }
    }
    la.cmp(&lb)
}

/// The listing comparator exposed to the fuzz crate (`fuzz/`) under `__fuzz`
/// only. Never part of the stable API.
///
/// Driven by `fuzz/fuzz_targets/path_order.rs`. `cmp_path_bytes` orders
/// attacker-named directory entries and its result feeds `sort_by` and
/// `partition_point`, so it must be a **total order** - since Rust 1.81 an
/// inconsistent comparator is a `sort_by` panic, and here it would also cut a
/// resume boundary in the wrong place.
#[cfg(feature = "__fuzz")]
pub mod fuzz {
    /// Compare two directory entries by their full-path ordering.
    pub fn cmp_path_bytes(
        a: &[u8],
        a_dir: bool,
        b: &[u8],
        b_dir: bool,
    ) -> std::cmp::Ordering {
        super::cmp_path_bytes(a, a_dir, b, b_dir)
    }
}

/// Start listing `dir` as `who`, enriching each entry per `opts`. Opening the
/// directory `O_RDONLY|O_DIRECTORY` under `who` **is** the list-permission
/// check - returns `EACCES` when `who` cannot list `dir`. Pull enriched batches
/// with [`QueryDir::next`].
pub fn query_directory(
    h: &FsHandle,
    who: Personality,
    dir: &Anchor,
    opts: QueryOptions,
) -> crate::Result<QueryDir> {
    // The anchor is an `O_PATH` dirfd, which neither requires nor implies list
    // permission; open it readable under `who` so the kernel enforces DAC. `.`
    // resolves to the anchor itself, confined by the default `RESOLVE_BENEATH`.
    let list_how = OpenHow::new().flags(OFlag::O_RDONLY | OFlag::O_DIRECTORY);
    let dir_read = h.open(who, dir, ".", list_how)?;

    // `fdopendir`/`closedir` take ownership of the fd, so hand them a dup --
    // `dir_read` then drops here, closing its own fd; the `DIR*` owns the dup.
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

    // The directory's own device, so an entry on a different one is
    // recognisable as a mount point. Taken from the readable fd we just
    // opened, before it drops.
    let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `dir_read` is live here; `st` is a valid out-pointer.
    let dir_dev =
        if unsafe { libc::fstat(dir_read.as_raw_fd(), st.as_mut_ptr()) } == 0 {
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

/// An [`FsHandle`] bound to the reactor's shared blocking-work pool for the
/// off-loop directory-listing ([`query`](QueryPool::query)) and byte-range copy
/// ([`copy_file_range`](QueryPool::copy_file_range)) helpers. Each method
/// enqueues a job and returns immediately with a handle; the pool is elastic
/// (sized at reactor construction), so one caller thread can fan out many jobs
/// and then collect them.
///
/// A walk opens its directory under its own `who` (the list-permission check),
/// so `EACCES` surfaces as an error batch rather than a listing taken under the
/// reactor's ambient credentials.
pub struct QueryPool {
    pool: Arc<SharedPool>,
    h: FsHandle,
}

impl QueryPool {
    /// Build a listing pool over `h`, sharing the reactor's one elastic
    /// blocking-work pool. `h` is cloned cheaply per job (the handle just
    /// shares the one loop).
    pub fn new(h: FsHandle) -> QueryPool {
        QueryPool {
            pool: h.pool.clone(),
            h,
        }
    }

    /// Enqueue `job` (a no-op if the pool is already dropping).
    fn submit(&self, job: Job) {
        self.pool.submit(job);
    }

    /// Enqueue a listing of `dir` as `who` and return immediately. Pull its
    /// enriched batches from the [`QueryHandle`]. Non-blocking - just enqueues.
    pub fn query(
        &self,
        who: Personality,
        dir: Anchor,
        opts: QueryOptions,
    ) -> QueryHandle {
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
                // A failed open (e.g. `EACCES` - the list-permission check)
                // surfaces as a single error batch.
                Err(e) => {
                    let _ = out.send(Err(e));
                }
            }
        }));
        QueryHandle { rx }
    }

    /// Copy `len` bytes from `src[off_src..]` to `dst[off_dst..]`, **always on
    /// the pool**; `src`/`dst` clone into the job (`File` is `Send`) so their
    /// fds stay open. [`CopyHandle::wait`] yields the bytes copied.
    ///
    /// **Nothing runs on the caller's thread**, including the clone. On ZFS a
    /// block clone moves no data, which once argued for doing it inline, but
    /// it still takes filesystem locks and - with `zfs_bclone_wait_dirty`,
    /// which this fork defaults on - waits a transaction group for a source
    /// that was just written. That is precisely the caller who clones what it
    /// has only now finished writing, so the wait is the expected path and
    /// not a corner: seconds of it, on the reactor, per copy. The whole range
    /// goes in one job and the job re-issues on a short return, so the cost
    /// of a large copy is one worker, not one worker per chunk.
    pub fn copy_file_range(
        &self,
        src: &File,
        dst: &File,
        off_src: u64,
        off_dst: u64,
        len: u64,
    ) -> CopyHandle {
        // Nothing to move, and nothing to wait for.
        if len == 0 {
            return CopyHandle::Ready(Ok(0));
        }
        let (out, rx) = mpsc::channel();
        let src = src.clone();
        let dst = dst.clone();
        self.submit(Box::new(move || {
            let res = copy_file_range_blocking(
                src.as_raw_fd(),
                dst.as_raw_fd(),
                off_src,
                off_dst,
                len,
            );
            let _ = out.send(res);
        }));
        CopyHandle::Pending(rx)
    }
}

impl fmt::Debug for QueryPool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QueryPool")
            .field("pool", &self.pool)
            .finish()
    }
}

/// A handle to one enqueued [`QueryPool::query`] listing. Pull enriched batches
/// with [`next`](QueryHandle::next) until `None` (end of directory, or the pool
/// was dropped). Also an [`Iterator`].
pub struct QueryHandle {
    rx: mpsc::Receiver<crate::Result<Vec<DirEntry>>>,
}

impl fmt::Debug for QueryHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QueryHandle").finish_non_exhaustive()
    }
}

impl QueryHandle {
    /// The next batch, blocking until a worker produces one; `None` at the end
    /// (or if the pool was dropped before finishing this walk).
    pub fn next(&self) -> Option<crate::Result<Vec<DirEntry>>> {
        self.rx.recv().ok()
    }

    /// The next batch if one is already available, without blocking. `None`
    /// means "nothing ready yet" *or* "finished" - [`next`](Self::next)
    /// distinguishes them by blocking.
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

/// The result of a [`QueryPool::copy_file_range`]: `Ready` only when the
/// request asked for nothing, else `Pending` on the job the pool is running.
/// [`wait`](Self::wait) yields the bytes copied.
#[derive(Debug)]
pub enum CopyHandle {
    /// Answered without a job — a zero-length copy, which moves nothing and
    /// waits for nothing.
    Ready(crate::Result<u64>),
    /// A copy is running on the pool; its result arrives on this channel.
    Pending(mpsc::Receiver<crate::Result<u64>>),
}

impl CopyHandle {
    /// The bytes copied, blocking until the offloaded copy finishes
    /// (`ECONNABORTED` if the pool was dropped first).
    pub fn wait(self) -> crate::Result<u64> {
        match self {
            CopyHandle::Ready(r) => r,
            CopyHandle::Pending(rx) => rx
                .recv()
                .unwrap_or_else(|_| Err(Errno::ECONNABORTED.into())),
        }
    }
}

/// Largest single kernel transfer, page-aligned.
///
/// A ceiling the kernel imposes on one `copy_file_range(2)`, not a chunk
/// size this crate chose: the whole remaining range is offered on every
/// call, and the loop below exists to re-issue what a short return left
/// behind. Splitting a copy smaller than this would re-enter
/// `zfs_clone_range` per piece — retaking both rangelocks and every
/// property and alignment check — and would cost the clone outright, since
/// the destination's rangelock is promoted to whole-file only while
/// `z_size <= z_blksz` (`/CODE/zfs`, `module/os/linux/zfs/zfs_znode_os.c`),
/// which is its first write and the one that grows the blocksize to the
/// source's.
const MAX_CHUNK: usize = 0x7FFF_FFFF & !0xFFF;

/// Copy `len` bytes from `src[off_src..]` to `dst[off_dst..]`, letting the
/// kernel clone them where it can. Returns bytes copied (short only at
/// source EOF); across filesystems `copy_file_range` answers `EXDEV` and a
/// positional read/write of the range stands in.
///
/// **Blocking - for a pool thread, never the reactor.** Even a clone that
/// moves no data takes filesystem locks and can wait on dirty data, so
/// there is no fast path that may run on the loop.
///
/// **The clone is the kernel's, not an ioctl's.** `zpl_copy_file_range`
/// tries `zfs_clone_range` first and falls back to a byte copy itself
/// (`/CODE/zfs`, `module/os/linux/zfs/zpl_file.c`), so `copy_file_range(2)`
/// is already clone-first and an explicit `FICLONERANGE` buys nothing. It
/// costs: the ioctl refuses a range it can only partly clone rather than
/// returning it short, and it refuses *after* `zfs_bclone_wait_dirty` has
/// waited a transaction group for the source to sync - which this fork does
/// by default (`zfs_vnops.c`, `int zfs_bclone_wait_dirty = 1`, and required
/// by deployments that clone what they have just written). Trying the ioctl
/// first therefore pays that wait, throws the answer away, and pays it again
/// in the fallback.
///
/// Needs no [`Personality`]: both endpoints are already-open [`File`]s, and
/// the kernel authorizes the copy from *their* open modes - which were
/// established under the identity that opened them - rather than from the
/// calling thread's credentials.
pub(crate) fn copy_range(
    src: &File,
    dst: &File,
    off_src: u64,
    off_dst: u64,
    len: u64,
) -> crate::Result<u64> {
    copy_file_range_blocking(
        src.as_raw_fd(),
        dst.as_raw_fd(),
        off_src,
        off_dst,
        len,
    )
}

fn copy_file_range_blocking(
    src: RawFd,
    dst: RawFd,
    off_src: u64,
    off_dst: u64,
    len: u64,
) -> crate::Result<u64> {
    let mut soff = off_src as i64;
    let mut doff = off_dst as i64;
    let mut remaining = len;
    let mut total = 0u64;
    while remaining > 0 {
        let want = remaining.min(MAX_CHUNK as u64) as usize;
        // SAFETY: `src`/`dst` are live raw fds (the job holds the owning `File`
        // clones); `soff`/`doff` are valid locals the kernel reads and advances.
        let n = retry_on_eintr(|| unsafe {
            libc::copy_file_range(src, &mut soff, dst, &mut doff, want, 0)
        });
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
fn copy_range_rw(
    src: RawFd,
    dst: RawFd,
    off_src: u64,
    off_dst: u64,
    len: u64,
) -> crate::Result<u64> {
    let mut buf = vec![0u8; MAX_CHUNK.min(1 << 20)];
    let mut soff = off_src as i64;
    let mut doff = off_dst as i64;
    let mut remaining = len;
    let mut total = 0u64;
    while remaining > 0 {
        let want = remaining.min(buf.len() as u64) as usize;
        // SAFETY: reading `want` bytes into a live buffer at a valid offset.
        let r = retry_on_eintr(|| unsafe {
            libc::pread(src, buf.as_mut_ptr().cast(), want, soff)
        })?;
        if r == 0 {
            break; // source EOF
        }
        let r = r as usize;
        let mut written = 0usize;
        while written < r {
            // SAFETY: writing a sub-slice we just filled to a live fd.
            let w = retry_on_eintr(|| unsafe {
                libc::pwrite(
                    dst,
                    buf[written..r].as_ptr().cast(),
                    r - written,
                    doff + written as i64,
                )
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
mod confinement_tests {
    use super::{split_statx, unknown_device_verdict};
    use crate::errno::Errno;
    use crate::uring_fs::{FsOutcome, FsPending};

    fn split(res: Result<i32, Errno>) -> Option<Errno> {
        split_statx(Some(FsPending::resolved(FsOutcome::new(
            res,
            Vec::new(),
            None,
            None,
        ))))
        .1
    }

    /// `same_device_only` is a confinement, and the filter behind it keeps
    /// an entry whose device it could not read. So with the option set, an
    /// unresolved `statx` has to be answered for.
    ///
    /// The split is `query_tree`'s `is_subtree_skip`, deliberately: skip
    /// only what has nothing left to list, surface everything else, because
    /// a partial listing that reads as complete is data loss for whatever
    /// is built on it.
    #[test]
    fn an_unreadable_device_is_answered_for_the_way_query_tree_would() {
        // Nothing left to list: the entry alone goes, which is the
        // per-identity behaviour the rest of this module already has.
        for e in [Errno::EACCES, Errno::EPERM, Errno::ENOENT] {
            assert_eq!(
                unknown_device_verdict(Some(e)),
                None,
                "{e} should drop the entry, not fail the listing"
            );
        }

        // The filter failing: surfaced, with its own errno. `EBUSY` is the
        // marked refusal of a full op table - reached under exactly the
        // pressure that makes a listing large - and is the documented
        // retryable one.
        for e in [Errno::EBUSY, Errno::EIO, Errno::ENOTDIR] {
            assert_eq!(
                unknown_device_verdict(Some(e)),
                Some(e),
                "{e} should fail the listing rather than admit an entry \
                 whose filesystem is unknown"
            );
        }

        // No errno at all where a device was owed: not "nothing to list".
        assert_eq!(
            unknown_device_verdict(None),
            Some(Errno::ECONNABORTED),
            "an entry that produced no answer and no reason must surface"
        );
    }

    /// The errno has to survive the await, or every verdict above is taken
    /// on `None` and the listing fails for reasons it should have skipped.
    #[test]
    fn splitting_a_statx_keeps_the_errno_apart_from_the_metadata() {
        for e in [Errno::EACCES, Errno::EBUSY, Errno::ENOENT] {
            assert_eq!(split(Err(e)), Some(e));
        }
        // A success carries no errno - and no pad on this outcome, which is
        // what makes the "no metadata, no reason" arm above reachable at
        // all.
        assert_eq!(split(Ok(0)), None);
        // And an entry for which none was issued reports neither.
        let (st, err) = split_statx(None);
        assert!(st.is_none() && err.is_none());
    }
}

#[cfg(all(test, not(loom)))]
mod order_tests {
    use super::*;

    /// Sort `(name, is_dir)` pairs the way [`Order::ByPathBytes`] does and
    /// return the resulting keys, so a case reads as the paths it stands for.
    fn keys(entries: &[(&str, bool)]) -> Vec<String> {
        let mut v = entries.to_vec();
        v.sort_by(|a, b| {
            cmp_path_bytes(a.0.as_bytes(), a.1, b.0.as_bytes(), b.1)
        });
        v.into_iter()
            .map(|(n, d)| if d { format!("{n}/") } else { n.to_string() })
            .collect()
    }

    /// The inversion the whole comparator exists for. `/` is `0x2F`, above
    /// both `-` (`0x2D`) and `.` (`0x2E`), so the directory `a` belongs
    /// *between* `a.txt` and `aa.txt` - not first, where its bare name sorts.
    /// Getting this wrong reorders a walk against true path order, which is
    /// how keys go missing at a page boundary.
    #[test]
    fn a_directory_sorts_where_its_trailing_separator_puts_it() {
        assert_eq!(
            keys(&[
                ("a", true),
                ("a-1.txt", false),
                ("a.txt", false),
                ("aa.txt", false)
            ]),
            ["a-1.txt", "a.txt", "a/", "aa.txt"],
        );

        // What a bare-name sort would have produced, for contrast: the
        // directory leads, so a depth-first walk would emit everything under
        // `a/` before `a-1.txt`.
        let mut bare = ["a", "a-1.txt", "a.txt", "aa.txt"];
        bare.sort_unstable();
        assert_eq!(bare, ["a", "a-1.txt", "a.txt", "aa.txt"]);
    }

    /// Several entries sharing a prefix, each differing only in what follows
    /// it - `.` vs `/` vs end-of-name - so every branch of the synthesized
    /// trailing byte is exercised against a real neighbour.
    #[test]
    fn separator_ranks_against_dot_at_every_position() {
        assert_eq!(
            keys(&[("b", true), ("b..", false), ("b.", true)]),
            ["b..", "b./", "b/"],
        );
    }

    /// A file and a directory of the same name cannot coexist in one
    /// directory, but the comparator is still asked to order them (a walk
    /// merging sources, a caller sorting a synthetic list). The file sorts
    /// first: its key is a strict prefix of the directory's.
    #[test]
    fn same_name_file_precedes_directory() {
        assert_eq!(keys(&[("a", true), ("a", false)]), ["a", "a/"]);
    }

    /// A name that is a prefix of another orders by length once the shared
    /// bytes run out, with the separator counted as part of the key.
    #[test]
    fn prefix_names_order_by_the_synthesized_key_length() {
        assert_eq!(
            keys(&[("ab", false), ("a", false), ("a", true)]),
            ["a", "a/", "ab"],
        );
        // `a/` vs `ab`: `/` (0x2F) < `b` (0x62), so the directory leads.
        assert_eq!(
            cmp_path_bytes(b"a", true, b"ab", false),
            std::cmp::Ordering::Less,
        );
    }

    /// Identical inputs compare equal, so the sort is well-formed (a
    /// comparator that never reports `Equal` can violate sort invariants).
    #[test]
    fn identical_entries_compare_equal() {
        assert_eq!(
            cmp_path_bytes(b"x", false, b"x", false),
            std::cmp::Ordering::Equal,
        );
        assert_eq!(
            cmp_path_bytes(b"x", true, b"x", true),
            std::cmp::Ordering::Equal,
        );
    }

    /// The ordering agrees with comparing fully-built keys, on a spread of
    /// names chosen around the separator's neighbourhood in byte space.
    #[test]
    fn matches_comparing_materialized_keys() {
        let names = [
            "a", "a-", "a.", "a/", "a0", "aa", "", "-", ".", "z", "a.b", "a-b",
        ];
        let key = |n: &str, d: bool| {
            let mut k = n.to_string();
            if d {
                k.push('/');
            }
            k
        };
        for a in names {
            for b in names {
                for ad in [false, true] {
                    for bd in [false, true] {
                        assert_eq!(
                            cmp_path_bytes(a.as_bytes(), ad, b.as_bytes(), bd),
                            key(a, ad).cmp(&key(b, bd)),
                            "({a:?},{ad}) vs ({b:?},{bd})",
                        );
                    }
                }
            }
        }
    }
}

#[cfg(all(test, not(loom)))]
mod narrow_tests {
    use super::{narrow, right_size};

    /// `narrow`'s property on the buffer shape it is kept for - a refetch
    /// buffer sized to the value, so nearly full: it comes back in the
    /// allocation that went to the kernel. Pointer identity is the
    /// assertion, because length and contents look the same either way.
    #[test]
    fn narrowing_reuses_the_buffer_instead_of_copying_it() {
        let buf = vec![7u8; 4096];
        let before = buf.as_ptr();
        let got = narrow(buf, 4000).expect("4000 fits in 4096");
        assert_eq!(got.as_ptr(), before, "the value was copied elsewhere");
        assert_eq!(got.len(), 4000);
        assert_eq!(got.capacity(), 4096, "capacity shrank, so it reallocated");
        assert!(got.iter().all(|&b| b == 7));
    }

    /// `right_size`'s two regimes. A small value gives the probe buffer's
    /// surplus back - the capacity assertion is the defect guard: `truncate`
    /// alone leaves a 13-byte ACL carrying its whole 64 KiB probe buffer for
    /// as long as the listing holds it. A value past half the buffer keeps
    /// the allocation, pointer-identical, because the shrink's copy would
    /// reclaim less than it moves.
    #[test]
    fn right_sizing_returns_a_probe_buffers_surplus() {
        let got = right_size(vec![7u8; 65536], 13).expect("13 fits");
        assert_eq!(got.len(), 13);
        assert_eq!(got.capacity(), 13, "the probe buffer was retained");
        assert!(got.iter().all(|&b| b == 7));

        let buf = vec![9u8; 4096];
        let before = buf.as_ptr();
        let got = right_size(buf, 3000).expect("3000 fits");
        assert_eq!(got.as_ptr(), before, "a near-full buffer was copied");
        assert_eq!(got.capacity(), 4096);
        assert_eq!(got.len(), 3000);
    }

    /// A count past the end must be refused, not ignored: `truncate` does
    /// nothing there and would hand back the whole buffer as if the kernel had
    /// filled it. Both narrowers hold the same line.
    #[test]
    fn a_count_past_the_end_is_refused_rather_than_ignored() {
        assert!(narrow(vec![0u8; 16], 17).is_none());
        assert!(narrow(vec![0u8; 16], usize::MAX).is_none());
        assert_eq!(narrow(vec![0u8; 16], 16).map(|v| v.len()), Some(16));
        assert_eq!(narrow(Vec::new(), 0).map(|v| v.len()), Some(0));
        assert!(right_size(vec![0u8; 16], 17).is_none());
        assert!(right_size(vec![0u8; 16], usize::MAX).is_none());
        assert_eq!(right_size(Vec::new(), 0).map(|v| v.len()), Some(0));
    }
}

#[cfg(all(test, not(loom)))]
mod copy_range_tests {
    use super::copy_range;
    use crate::uring_fs::File;
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::fd::OwnedFd;
    use std::sync::Arc;

    fn handle(f: std::fs::File) -> File {
        File::new(Arc::new(OwnedFd::from(f)))
    }

    /// The whole range in one call, and the count is the kernel's.
    ///
    /// **A request past the end must answer what moved, not what was
    /// asked for.** The caller sizes its destination from a `statx` it
    /// took earlier, so a source that has since shrunk is exactly the
    /// case where a copy that reported success on trust would publish a
    /// short object nothing re-checks. The clone ioctl this path used to
    /// try first could not express that — it either moved the whole
    /// range or refused — so the count it returned was the request, not
    /// the transfer.
    #[test]
    fn a_copy_reports_what_moved_not_what_was_asked_for() {
        let dir = crate::tempdir().expect("tempdir");
        let body: Vec<u8> =
            (0..40_000u32).flat_map(|i| i.to_le_bytes()).collect();

        let src_path = dir.path().join("src.bin");
        let mut src = std::fs::File::options()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(&src_path)
            .expect("source");
        src.write_all(&body).expect("fill the source");
        src.sync_all().expect("sync");

        let dst_path = dir.path().join("dst.bin");
        let dst = std::fs::File::options()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(&dst_path)
            .expect("destination");

        // Offer far more than the source holds: one call, whole range.
        let src_h = handle(src);
        let dst_h = handle(dst);
        let moved = copy_range(&src_h, &dst_h, 0, 0, body.len() as u64 * 4)
            .expect("copy");
        assert_eq!(
            moved,
            body.len() as u64,
            "the count is what the source had, not what was requested"
        );

        let mut back = Vec::new();
        let mut f = std::fs::File::open(&dst_path).expect("reopen");
        f.seek(SeekFrom::Start(0)).expect("rewind");
        f.read_to_end(&mut back).expect("read back");
        assert_eq!(back, body, "byte for byte");
    }

    /// An offset pair the caller chose, so the range really is ranged.
    #[test]
    fn a_copy_honours_both_offsets() {
        let dir = crate::tempdir().expect("tempdir");
        let src_path = dir.path().join("src.bin");
        let mut src = std::fs::File::options()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(&src_path)
            .expect("source");
        src.write_all(b"0123456789").expect("fill");
        src.sync_all().expect("sync");

        let dst_path = dir.path().join("dst.bin");
        let mut dst = std::fs::File::options()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(&dst_path)
            .expect("destination");
        dst.write_all(b"..........").expect("prefill");
        dst.sync_all().expect("sync");

        let moved =
            copy_range(&handle(src), &handle(dst), 2, 5, 3).expect("copy");
        assert_eq!(moved, 3);

        let back = std::fs::read(&dst_path).expect("read back");
        assert_eq!(
            &back, b".....234..",
            "the window landed where it was aimed"
        );
    }
}
