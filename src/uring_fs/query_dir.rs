//! [`query_directory`]: a **pull-based**, batched directory listing with
//! configurable per-entry enrichment, over the blocking [`FsHandle`].
//!
//! There is no io_uring `getdents`/`readdir` op, so the **name feed** is a
//! `readdir` pass over the directory fd on the caller's own thread (no worker,
//! no channel). [`QueryDir::next`] reads the next `clump` names, then enriches
//! them by **scattering non-blocking reactor ops** — `statx` (path-based) and
//! `fgetxattr` on an opened entry fd — through the [`FsHandle`] `start_*` twins:
//! all of a clump's ops are submitted before any is waited on, so they run
//! concurrently on the ring. The directory `DIR*` is held open across `next`
//! calls (incremental; nothing is buffered up front) and closed on `Drop`.
//!
//! The directory is opened **under the caller's [`Personality`]** — that open
//! is the DAC/list-permission check (`EACCES` if `who` cannot list), so
//! enumeration never runs under the reactor's ambient root.
//!
//! Entries come in raw `readdir` order unless [`QueryOptions::order`] asks
//! for otherwise; see [`Order`] for what the ordered modes cost, and
//! [`query_tree`](super::query_tree::query_tree) to walk a whole subtree in
//! path order.

use super::{Anchor, File, FsHandle, FsPending, Leaf, Personality};
use crate::errno::{retry_on_eintr, Errno};
use crate::sync_fs::xattr::{flistxattr, XATTR_SIZE_MAX};
use crate::sync_fs::{AtFlags, OFlag, OpenHow, Statx, StatxMask};
use bitflags::bitflags;
use std::cell::Cell;
use std::collections::VecDeque;
use std::ffi::{CStr, CString, OsStr, OsString};
use std::fmt;
use std::os::fd::{AsFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Condvar, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

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
        /// object carries a trivial one — so discovery alone is not a reliable
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
    /// being listed — a mount point, which on ZFS means a child dataset or a
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
    pub same_device_only: bool,
    /// The `statx` mask requested for each entry when [`EnrichSpec::STATX`] is
    /// set. Defaults to [`StatxMask::BASIC_STATS`]; widen it to ask for fields
    /// the basic set omits — notably [`StatxMask::CHANGE_COOKIE`], which costs
    /// nothing extra here because the `statx` runs either way and gives a
    /// caller an exact validator for anything it caches per entry (see
    /// [`Statx::change_cookie`]).
    pub statx_mask: StatxMask,
    /// The order entries are yielded in. Defaults to [`Order::Readdir`] — see
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
    /// — exactly where `a/` sorts — rather than `a`, which is where a *file*
    /// named `a` sorts.
    ///
    /// Ignored under [`Order::Readdir`], which has no order to be "after".
    /// Note this prunes *after* the directory has been read and sorted — it
    /// resumes a listing, it does not make resuming cheap.
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
/// inherent — the smallest name cannot be known without seeing them all.
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
    /// emit `a/b.txt` before both — while their full paths order
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
    /// read — that is a deliberate drop, not a failure.
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
        match self.next_names() {
            Ok(names) if names.is_empty() => None,
            Ok(names) => Some(Ok(self.enrich(names))),
            Err(e) => Some(Err(e)),
        }
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
    /// `DT_UNKNOWN` and sorts as a non-directory — the same answer guessing
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
            // the next `readdir`/`closedir` — copied out immediately below.
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
            out.push((OsStr::from_bytes(&bytes).to_os_string(), dtype));
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
    fn enrich(&self, names: Vec<(OsString, u8)>) -> Vec<DirEntry> {
        let who = self.who;
        let spec = self.opts.spec;

        // Request statx and an fd for each entry, opened as `who`.
        let requested: Vec<Requested> = names
            .into_iter()
            .map(|(name, dtype)| {
                let statx = if spec.contains(EnrichSpec::STATX) {
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
                let open = if spec.intersects(
                    EnrichSpec::XATTR
                        | EnrichSpec::ACL
                        | EnrichSpec::XATTR_LIST,
                ) {
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

        // Collect each entry's statx and opened fd, dropping anything that
        // crossed a mount point when the caller asked for one filesystem.
        // Filtering here — before the xattr reads below — also means a nested
        // dataset costs no further work.
        let cross_dev = |st: Option<&Statx>| match (self.dir_dev, st) {
            (Some(dev), Some(st)) => st.dev() != dev,
            // No device for the directory, or no statx for the entry: nothing
            // to compare, so nothing is dropped.
            _ => false,
        };
        let opened: Vec<Opened> = requested
            .into_iter()
            .filter_map(|p| {
                let statx = p.statx.and_then(pending_statx);
                if self.opts.same_device_only && cross_dev(statx.as_ref()) {
                    return None;
                }
                let is_dir = statx
                    .as_ref()
                    .map(Statx::is_dir)
                    .unwrap_or(p.dtype == libc::DT_DIR);
                let file = p.open.and_then(pending_file);
                Some(Opened {
                    name: p.name,
                    is_dir,
                    statx,
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
                match &p.file {
                    Some(f) => {
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
                Reading {
                    name: p.name,
                    is_dir: p.is_dir,
                    statx: p.statx,
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
        reading
            .into_iter()
            .map(|p| {
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
                DirEntry {
                    name: p.name,
                    is_dir: p.is_dir,
                    statx: p.statx,
                    xattrs,
                    acl,
                    xattrs_incomplete: incomplete,
                }
            })
            .collect()
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
    is_dir: bool,
    statx: Option<Statx>,
    file: Option<File>,
}
struct Reading {
    name: OsString,
    is_dir: bool,
    statx: Option<Statx>,
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
    let n = out.res.ok()? as usize;
    let buf = out.bufs.into_iter().next()?;
    buf.get(..n).map(<[u8]>::to_vec)
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
            .and_then(|b| b.get(..n as usize).map(<[u8]>::to_vec))
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
    const SIZE_RETRIES: u32 = 4;
    let mut tries = 0u32;
    loop {
        let (size, _) = h.fgetxattr(who, f, name, Vec::new());
        let size = size.ok()?;
        if size > XATTR_SIZE_MAX {
            return None;
        }
        // Read at the probed size; on retry add half again so a value that
        // grew since the probe still fits without another round trip.
        let cap = if tries == 0 {
            size.max(1)
        } else {
            (size + size / 2).clamp(1, XATTR_SIZE_MAX)
        };
        let (n, buf) = h.fgetxattr(who, f, name, vec![0u8; cap]);
        match n {
            Ok(n) => return buf.get(..n).map(<[u8]>::to_vec),
            Err(crate::Error::Errno(Errno::ERANGE | Errno::E2BIG)) => {
                tries += 1;
                if tries >= SIZE_RETRIES {
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

/// Start listing `dir` as `who`, enriching each entry per `opts`. Opening the
/// directory `O_RDONLY|O_DIRECTORY` under `who` **is** the list-permission
/// check — returns `EACCES` when `who` cannot list `dir`. Pull enriched batches
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

    // `fdopendir`/`closedir` take ownership of the fd, so hand them a dup —
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
    })
}

// ---- QueryPool: a std worker pool over the pull-based `query_directory` -----

/// A boxed unit of work a pool worker runs. Every job is `Send` and
/// self-contained (it captures its own inputs and result channel), so the pool
/// is generic — the `!Send` [`QueryDir`] is built and driven *inside* the job,
/// on the worker's own thread, never sent.
type Job = Box<dyn FnOnce() + Send>;

/// Growth is rate-limited to at most one new worker per this interval, so a
/// burst of microsecond-fast jobs that momentarily saturates the pool does not
/// spawn a thread per job; sustained blocking work still grows to the ceiling.
const OFFLOAD_SPAWN_COOLDOWN: Duration = Duration::from_millis(1);
/// A burst worker idle this long retires, back down to the floor.
const OFFLOAD_IDLE_TIMEOUT: Duration = Duration::from_secs(10);

struct PoolInner {
    queue: VecDeque<Job>,
    /// Live worker threads: the floor plus any grown-in burst workers.
    total: usize,
    /// The pool is dropping; workers drain the queue, then exit.
    closed: bool,
}

struct PoolShared {
    inner: Mutex<PoolInner>,
    /// Signals a queued job, a shutdown, or a worker exit (`Drop` waits on it).
    cv: Condvar,
    /// Workers currently executing a job; `running == total` means saturated.
    running: AtomicUsize,
    floor: usize,
    ceiling: usize,
    epoch: Instant,
    /// Micros since `epoch` of the last spawn, throttling growth.
    last_spawn_us: AtomicU64,
    cooldown: Duration,
    idle_timeout: Duration,
}

/// An elastic pool of worker threads running `Box<dyn FnOnce() + Send>` jobs,
/// the shared machinery behind both the off-loop [`QueryPool`] helpers and the
/// on-loop `FsConn::offload` path. It keeps `floor` threads warm and grows to
/// `ceiling` when every worker is busy (blocked on a slow `readdir` or copy),
/// so one stalled walk does not head-of-line-block the rest; burst workers
/// retire after an idle period. It runs whatever job it is handed under the
/// reactor's ambient credentials; any per-`who` permission check belongs to the
/// job, not the pool.
///
/// Growth is hysteretic: a worker spawns only when the pool is saturated
/// (`running == total`) and at most once per cooldown, so a burst of fast
/// cached jobs clears without thread churn while genuinely blocking work grows.
/// Dropping the pool closes the queue and waits for every worker to exit, so no
/// detached worker outlives the state it borrows.
pub(crate) struct WorkerPool {
    shared: Arc<PoolShared>,
}

impl WorkerPool {
    /// An elastic pool: `floor` (at least 1) warm threads growing to `ceiling`
    /// under saturation, using the default cooldown and idle timeout. Returns
    /// the spawn error rather than panicking.
    pub(crate) fn try_elastic(
        floor: usize,
        ceiling: usize,
    ) -> std::io::Result<WorkerPool> {
        Self::try_elastic_tuned(
            floor,
            ceiling,
            OFFLOAD_SPAWN_COOLDOWN,
            OFFLOAD_IDLE_TIMEOUT,
        )
    }

    /// [`try_elastic`](Self::try_elastic) with explicit timings (for tests). On
    /// a partial spawn failure the workers already started are shut down and
    /// waited for before returning, so none is orphaned.
    pub(crate) fn try_elastic_tuned(
        floor: usize,
        ceiling: usize,
        cooldown: Duration,
        idle_timeout: Duration,
    ) -> std::io::Result<WorkerPool> {
        let floor = floor.max(1);
        let ceiling = ceiling.max(floor);
        let shared = Arc::new(PoolShared {
            inner: Mutex::new(PoolInner {
                queue: VecDeque::new(),
                total: 0,
                closed: false,
            }),
            cv: Condvar::new(),
            running: AtomicUsize::new(0),
            floor,
            ceiling,
            epoch: Instant::now(),
            last_spawn_us: AtomicU64::new(0),
            cooldown,
            idle_timeout,
        });
        let pool = WorkerPool {
            shared: Arc::clone(&shared),
        };
        for _ in 0..floor {
            {
                let mut g =
                    shared.inner.lock().unwrap_or_else(|e| e.into_inner());
                g.total += 1; // account the worker before it can exit
            }
            if let Err(e) = spawn_worker(&shared) {
                {
                    let mut g =
                        shared.inner.lock().unwrap_or_else(|e| e.into_inner());
                    g.total -= 1;
                }
                drop(pool); // closes and waits for the workers already started
                return Err(e);
            }
        }
        Ok(pool)
    }

    /// Enqueue `job`, growing the pool by one worker if it is saturated and the
    /// cooldown has elapsed (a no-op if the pool is already dropping).
    pub(crate) fn submit(&self, job: Job) {
        let grow = {
            let mut g =
                self.shared.inner.lock().unwrap_or_else(|e| e.into_inner());
            if g.closed {
                return;
            }
            g.queue.push_back(job);
            self.shared.cv.notify_one();
            let saturated =
                self.shared.running.load(Ordering::Relaxed) >= g.total;
            let grow = saturated
                && g.total < self.shared.ceiling
                && self.shared.claim_spawn_slot();
            if grow {
                g.total += 1; // reserve the slot before releasing the lock
            }
            grow
        };
        if grow && spawn_worker(&self.shared).is_err() {
            // Spawn failed: return the reserved slot. The job still runs when a
            // busy worker frees up.
            let mut g =
                self.shared.inner.lock().unwrap_or_else(|e| e.into_inner());
            g.total -= 1;
        }
    }
}

impl PoolShared {
    /// True at most once per [`cooldown`](Self::cooldown), claiming the slot so
    /// concurrent submits do not all spawn at once.
    fn claim_spawn_slot(&self) -> bool {
        let now = self.epoch.elapsed().as_micros() as u64;
        let cooldown = self.cooldown.as_micros() as u64;
        let last = self.last_spawn_us.load(Ordering::Relaxed);
        now.saturating_sub(last) >= cooldown
            && self
                .last_spawn_us
                .compare_exchange(
                    last,
                    now,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                )
                .is_ok()
    }
}

thread_local! {
    /// Set for the lifetime of a pool worker thread. [`WorkerPool::drop`] can
    /// run on a worker when a job drops the pool's last `Arc`; the flag tells
    /// that `Drop` not to join the workers — this thread is one of them, so the
    /// join would wait on itself.
    static ON_POOL_WORKER: Cell<bool> = const { Cell::new(false) };
}

impl Drop for WorkerPool {
    fn drop(&mut self) {
        let mut g = self.shared.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.closed = true;
        self.shared.cv.notify_all();
        // Running on a pool worker (a job dropped the pool's last `Arc`): this
        // thread is itself counted in `total`, so waiting the workers out here
        // would wait on this very thread forever. Each worker owns an
        // `Arc<PoolShared>`, so they exit and reclaim the shared state on their
        // own once `closed` is set, with no join needed.
        if ON_POOL_WORKER.with(Cell::get) {
            return;
        }
        // Wait for every worker to drain and exit, so none touches the shared
        // state after this returns (join-on-drop without tracking handles).
        while g.total > 0 {
            g = self.shared.cv.wait(g).unwrap_or_else(|e| e.into_inner());
        }
    }
}

/// Spawn one worker thread bound to `shared`. The caller has already accounted
/// it in `total`; the worker decrements `total` when it exits.
fn spawn_worker(shared: &Arc<PoolShared>) -> std::io::Result<()> {
    let shared = Arc::clone(shared);
    thread::Builder::new()
        .name("truenas-fs-worker".into())
        .spawn(move || worker_loop(&shared))
        .map(|_| ())
}

/// One lazily-spawned [`WorkerPool`] shared by a reactor's on-loop offloads
/// (`FsConn::offload`) and its off-loop [`QueryPool`], so the reactor has a
/// single blocking-work thread budget. Cheap to clone (`Arc`); the floor
/// threads spawn on the first submit, and if a worker cannot be spawned the job
/// runs inline (a degraded loop, not a dead one).
pub(crate) struct SharedPool {
    pool: OnceLock<WorkerPool>,
    floor: usize,
    ceiling: usize,
    /// Set once the lazy spawn has failed. Whatever stopped a thread from
    /// starting (`EAGAIN`, an RLIMIT, a cgroup pids cap) will still be true on
    /// the next job, so remember it and run inline instead of re-attempting a
    /// full floor spawn per submit.
    spawn_failed: AtomicBool,
}

impl fmt::Debug for SharedPool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SharedPool")
            .field("spawned", &self.pool.get().is_some())
            .field("spawn_failed", &self.spawn_failed.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl SharedPool {
    /// A shared pool with warm floor `floor` and growth ceiling `ceiling` (each
    /// at least 1); no threads spawn until the first [`submit`](Self::submit).
    pub(crate) fn new(floor: usize, ceiling: usize) -> Arc<SharedPool> {
        let floor = floor.max(1);
        Arc::new(SharedPool {
            pool: OnceLock::new(),
            floor,
            ceiling: ceiling.max(floor),
            spawn_failed: AtomicBool::new(false),
        })
    }

    /// Submit a job, spawning the pool on first use. A lost init race just
    /// drops the surplus pool (its `Drop` joins the idle workers); a spawn
    /// failure runs the job inline rather than take the reactor down.
    pub(crate) fn submit(&self, job: Job) {
        if let Some(pool) = self.pool.get() {
            return pool.submit(job);
        }
        if self.spawn_failed.load(Ordering::Relaxed) {
            return job(); // already known unspawnable; don't retry per job
        }
        match WorkerPool::try_elastic(self.floor, self.ceiling) {
            Ok(pool) => {
                let _ = self.pool.set(pool);
                if let Some(pool) = self.pool.get() {
                    pool.submit(job);
                }
            }
            Err(_) => {
                self.spawn_failed.store(true, Ordering::Relaxed);
                job();
            }
        }
    }
}

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
    /// enriched batches from the [`QueryHandle`]. Non-blocking — just enqueues.
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
                // A failed open (e.g. `EACCES` — the list-permission check)
                // surfaces as a single error batch.
                Err(e) => {
                    let _ = out.send(Err(e));
                }
            }
        }));
        QueryHandle { rx }
    }

    /// Copy `len` bytes from `src[off_src..]` to `dst[off_dst..]`. First tries an
    /// **inline block clone** (`FICLONERANGE`) on the caller's thread —
    /// metadata-only on a reflink-capable filesystem (ZFS
    /// `feature@block_cloning`: a block-pointer copy + BRT refcount, no data
    /// I/O), so it moves nothing and returns a resolved [`CopyHandle`]. If the
    /// clone is rejected (misaligned, unsupported, or cross-dataset), a real
    /// byte copy is **offloaded to the pool** and the handle is pending;
    /// `src`/`dst` clone into the job (`File` is `Send`) so their fds stay open.
    /// Either way, [`CopyHandle::wait`] yields the bytes copied.
    pub fn copy_file_range(
        &self,
        src: &File,
        dst: &File,
        off_src: u64,
        off_dst: u64,
        len: u64,
    ) -> CopyHandle {
        // 1. Inline `FICLONERANGE`: on ZFS this is metadata-only (no data I/O),
        //    so run it here, not on the pool — there is no io_uring op for it
        //    (a direct `ioctl`). Caveat: a freshly written, still-dirty source
        //    with `zfs_bclone_wait_dirty=1` can make this wait ~5s for a TXG
        //    sync (`zfs_vnops.c`); an existing/synced source won't.
        let fcr = FileCloneRange {
            src_fd: src.as_raw_fd() as i64,
            src_offset: off_src,
            src_length: len,
            dest_offset: off_dst,
        };
        // SAFETY: `dst`/`src` are live fds (held by the caller's `File`s); `&fcr`
        // is a valid `file_clone_range` for the ioctl's duration.
        let cloned =
            unsafe { libc::ioctl(dst.as_raw_fd(), FICLONERANGE, &fcr) };
        if cloned == 0 {
            // Clone succeeded — no bytes moved; `len` now shares blocks.
            return CopyHandle::Ready(Ok(len));
        }
        // 2. Clone rejected (misaligned `EINVAL`, `EOPNOTSUPP`, cross-dataset
        //    `EXDEV`, dirty-no-wait `EAGAIN`, …) → offload a real byte copy
        //    (clone-first `copy_file_range` with an `EXDEV` byte-copy fallback).
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
    /// means "nothing ready yet" *or* "finished" — [`next`](Self::next)
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

/// A worker: wait for a job, run it, repeat; `K` workers run `K` jobs
/// concurrently. A burst worker idle past the idle timeout retires (never below
/// the floor); on shutdown every worker drains the queue and exits, decrementing
/// `total` so [`WorkerPool`]'s `Drop` can wait them all out.
///
/// Each job runs under `catch_unwind`, so a panicking job retires only itself,
/// not the worker: the pool keeps draining, and a later `submit` is not
/// silently dropped onto a dead thread. Any handle the job owned (a `SendDir`)
/// still closes as its unwinding frame drops.
fn worker_loop(shared: &Arc<PoolShared>) {
    // Mark this thread so a `WorkerPool::drop` triggered here (a job dropping
    // the pool's last `Arc`) does not try to join the pool it belongs to.
    ON_POOL_WORKER.with(|w| w.set(true));
    loop {
        let job = {
            let mut g = shared.inner.lock().unwrap_or_else(|e| e.into_inner());
            loop {
                if let Some(job) = g.queue.pop_front() {
                    break Some(job);
                }
                if g.closed {
                    break None;
                }
                let (guard, wait) = shared
                    .cv
                    .wait_timeout(g, shared.idle_timeout)
                    .unwrap_or_else(|e| e.into_inner());
                g = guard;
                if wait.timed_out()
                    && g.queue.is_empty()
                    && !g.closed
                    && g.total > shared.floor
                {
                    g.total -= 1; // idle burst worker retires
                    return;
                }
            }
        };
        let Some(job) = job else {
            // Pool closing: account the exit and wake `Drop`'s waiter.
            let mut g = shared.inner.lock().unwrap_or_else(|e| e.into_inner());
            g.total -= 1;
            shared.cv.notify_all();
            return;
        };
        shared.running.fetch_add(1, Ordering::Relaxed);
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(job));
        shared.running.fetch_sub(1, Ordering::Relaxed);
    }
}

/// The result of a [`QueryPool::copy_file_range`]: `Ready` when the inline
/// block clone succeeded (nothing offloaded), or `Pending` when a real byte
/// copy was handed to the pool. [`wait`](Self::wait) yields the bytes copied.
#[derive(Debug)]
pub enum CopyHandle {
    /// The inline `FICLONERANGE` clone already finished with this result.
    Ready(crate::Result<u64>),
    /// A byte copy is running on the pool; its result arrives on this channel.
    Pending(mpsc::Receiver<crate::Result<u64>>),
}

impl CopyHandle {
    /// The bytes copied — instant for an inline clone, else blocking until the
    /// offloaded copy finishes (`ECONNABORTED` if the pool was dropped first).
    pub fn wait(self) -> crate::Result<u64> {
        match self {
            CopyHandle::Ready(r) => r,
            CopyHandle::Pending(rx) => rx
                .recv()
                .unwrap_or_else(|_| Err(Errno::ECONNABORTED.into())),
        }
    }
}

/// `struct file_clone_range` (`linux/fs.h`) — the `FICLONERANGE` ioctl argument.
#[repr(C)]
struct FileCloneRange {
    src_fd: i64,
    src_offset: u64,
    src_length: u64,
    dest_offset: u64,
}

/// `FICLONERANGE` = `_IOW(0x94, 13, struct file_clone_range)` (a 32-byte arg):
/// `(1 << 30) | (32 << 16) | (0x94 << 8) | 13`.
const FICLONERANGE: libc::c_ulong = 0x4020_940D;

/// Largest single kernel transfer, page-aligned.
const MAX_CHUNK: usize = 0x7FFF_FFFF & !0xFFF;

/// Blocking ranged `copy_file_range`: block-clone `len` bytes from
/// `src[off_src..]` to `dst[off_dst..]` on a reflink-capable filesystem (ZFS
/// `feature@block_cloning` when recordsize-aligned), else the kernel copies
/// in-kernel; across filesystems/pools `copy_file_range` returns `EXDEV`, so
/// fall back to a positional read/write of the range. Returns bytes copied
/// (short only at source EOF). Standalone here because `sync_fs::shutil` is a
/// separate feature (unreachable under `uring-fs`) and its `clonefile` is
/// whole-file only.
/// Clone `len` bytes from `src[off_src..]` to `dst[off_dst..]`, preferring a
/// metadata-only block clone and falling back to a real copy.
///
/// **Blocking — for a pool thread, never the reactor.** `FICLONERANGE` is
/// metadata-only on a reflink-capable filesystem, but it still takes
/// filesystem locks and can wait on dirty data, so even the fast path must
/// not run on the loop.
///
/// Needs no [`Personality`]: both endpoints are already-open [`File`]s, and
/// the kernel authorizes the copy from *their* open modes — which were
/// established under the identity that opened them — rather than from the
/// calling thread's credentials.
pub(crate) fn clone_or_copy_range(
    src: &File,
    dst: &File,
    off_src: u64,
    off_dst: u64,
    len: u64,
) -> crate::Result<u64> {
    let fcr = FileCloneRange {
        src_fd: src.as_raw_fd() as i64,
        src_offset: off_src,
        src_length: len,
        dest_offset: off_dst,
    };
    // SAFETY: both fds are live for the call; `&fcr` is a valid
    // `file_clone_range` for the ioctl's duration.
    if unsafe { libc::ioctl(dst.as_raw_fd(), FICLONERANGE, &fcr) } == 0 {
        return Ok(len);
    }
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

#[cfg(test)]
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
    /// *between* `a.txt` and `aa.txt` — not first, where its bare name sorts.
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
    /// it — `.` vs `/` vs end-of-name — so every branch of the synthesized
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

#[cfg(test)]
mod pool_tests {
    use super::*;

    /// The elastic pool grows past its floor when every worker is blocked, up to
    /// the ceiling, then retires the burst workers once they sit idle.
    #[test]
    fn offload_pool_grows_under_saturation_then_reclaims_when_idle() {
        // Floor 1, ceiling 4; no growth cooldown (deterministic under the
        // start-synchronised submits below) and a quick idle timeout.
        let pool = WorkerPool::try_elastic_tuned(
            1,
            4,
            Duration::ZERO,
            Duration::from_millis(50),
        )
        .expect("pool");

        let release = Arc::new((Mutex::new(false), Condvar::new()));
        let (started_tx, started_rx) = mpsc::channel::<()>();

        // Submit blocking jobs one at a time, waiting until each is actually
        // running before the next, so the growth decision sees an accurate
        // `running` count rather than racing ahead of the workers.
        for _ in 0..4 {
            let r = Arc::clone(&release);
            let s = started_tx.clone();
            pool.submit(Box::new(move || {
                s.send(()).unwrap();
                let (m, cv) = &*r;
                let mut held = m.lock().unwrap();
                while !*held {
                    held = cv.wait(held).unwrap();
                }
            }));
            started_rx.recv().unwrap();
        }

        let grown = pool.shared.inner.lock().unwrap().total;

        // Release the blocked jobs first, so a failing assertion cannot wedge
        // teardown (Drop waits for every worker to exit).
        {
            let (m, cv) = &*release;
            *m.lock().unwrap() = true;
            cv.notify_all();
        }
        assert_eq!(grown, 4, "grew from floor 1 to ceiling 4 under saturation");

        // Idle burst workers retire back to the floor.
        let mut total = grown;
        for _ in 0..200 {
            total = pool.shared.inner.lock().unwrap().total;
            if total == 1 {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(total, 1, "burst workers retired back to the floor");
    }

    /// A fixed pool (`floor == ceiling`) never grows, even when saturated.
    #[test]
    fn fixed_pool_does_not_grow() {
        let pool = WorkerPool::try_elastic(2, 2).unwrap();
        let release = Arc::new((Mutex::new(false), Condvar::new()));
        let (started_tx, started_rx) = mpsc::channel::<()>();
        for _ in 0..2 {
            let r = Arc::clone(&release);
            let s = started_tx.clone();
            pool.submit(Box::new(move || {
                s.send(()).unwrap();
                let (m, cv) = &*r;
                let mut held = m.lock().unwrap();
                while !*held {
                    held = cv.wait(held).unwrap();
                }
            }));
            started_rx.recv().unwrap();
        }
        // Two more jobs against a saturated fixed pool: they queue, no growth.
        for _ in 0..2 {
            pool.submit(Box::new(|| {}));
        }
        let total = pool.shared.inner.lock().unwrap().total;
        {
            let (m, cv) = &*release;
            *m.lock().unwrap() = true;
            cv.notify_all();
        }
        assert_eq!(total, 2, "fixed pool stayed at its worker count");
    }

    /// A job that ends up holding the pool's last `Arc` drops it on the worker
    /// it runs on, landing `WorkerPool::drop` there; that drop must not join the
    /// pool (it would wait on the running worker itself). Mirrors a
    /// `QueryPool::query` job outliving the reactor and every handle.
    #[test]
    fn dpool_query_job_holding_the_last_pool_arc_wedges_a_worker() {
        let pool = SharedPool::new(1, 1);
        // The job's own clone; once the outer `pool` drops it becomes the last.
        let held = Arc::clone(&pool);
        let (proceed_tx, proceed_rx) = mpsc::channel::<()>();
        let (done_tx, done_rx) = mpsc::channel::<()>();
        pool.submit(Box::new(move || {
            proceed_rx.recv().ok();
            // Last `Arc` -> `SharedPool::drop` -> `WorkerPool::drop`, here on
            // the worker running this job.
            drop(held);
            // Reached only if that drop returned rather than self-joining.
            done_tx.send(()).ok();
        }));
        drop(pool); // only the job's clone keeps the pool alive now
        proceed_tx.send(()).ok();
        assert!(
            done_rx.recv_timeout(Duration::from_secs(5)).is_ok(),
            "a job dropping the pool's last Arc wedged its worker",
        );
    }
}
