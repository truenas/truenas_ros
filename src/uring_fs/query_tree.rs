//! [`query_tree`]: a **resumable, path-ordered, recursive** walk over a
//! directory subtree, built from the single-directory [`QueryDir`] machinery.
//!
//! Each level is an ordinary [`query_directory`] listing — same enrichment,
//! same scatter-gathered `statx`/`fgetxattr` on the ring, same
//! [`Personality`] — so this module adds only three things: descent, order
//! that composes across levels, and a cursor.
//!
//! # Ordering
//!
//! Every level is read with [`Order::ByPathBytes`], which is not optional and
//! is forced regardless of what the caller put in [`QueryOptions`]. Sorting
//! each directory by the bytes its *full path* will compare by — a directory
//! ordered as though it already carried its trailing `/` — is exactly the
//! condition under which per-directory sorting composes into a subtree
//! emitted in global path order. There is no global sort, and the tree is
//! never materialized: the walk holds one sorted name list per level on the
//! current stack, so peak memory is bounded by depth times directory width,
//! not by the size of the subtree.
//!
//! # Relationship to [`crate::sync_fs::iter`]
//!
//! [`FsIter`](crate::sync_fs::iter::FsIter) is the blocking sibling of this
//! walk and the model for most of it: the descent discipline (`openat` from
//! the parent's own descriptor, never a re-resolution from the root), the
//! caller-driven [`skip_descent`](QueryTree::skip_descent), the depth bound,
//! and a serializable resume token that carries a `depth` back on failure so
//! the caller can retry from a surviving ancestor.
//!
//! It deliberately diverges on **one** point, and it is the important one.
//! `FsIter`'s [`Cookie`](crate::sync_fs::iter::Cookie) records a *position* —
//! `(path, inode)` per level — and its resume is documented as best-effort:
//! the deepest saved directory is re-read from the start, so entries can be
//! yielded twice. That is the right trade for a scanner that de-duplicates
//! downstream. It is the wrong one for a paginated listing, where a repeated
//! key is a protocol violation.
//!
//! [`TreeCursor`] records a *key* instead — the last path emitted — and
//! resume is an exact seek: each level is opened with
//! [`QueryOptions::start_after`] set to the component the walk descended
//! through, so nothing before the cut is read, enriched, or emitted, and
//! nothing is emitted twice. This costs nothing extra precisely because the
//! walk already sorts each level; a position-based cursor is only forced on
//! `FsIter` because it does not.
//!
//! The key carries one bit alongside it, because a key alone cannot say
//! everything the walk needs. A directory is emitted before its contents, so
//! the key `"D/"` is the position *before* `D`'s subtree — right after
//! yielding `D`, wrong after [`skip_descent`](QueryTree::skip_descent) folded
//! `D` away, and unfixable by rewriting the key (`"D"` sorts ahead of the
//! directory's own key and re-emits it). [`TreeCursor::skips_subtree`]
//! distinguishes the two, which is what lets a delimiter listing page.
//!
//! Resume is still *best-effort about the tree*, not about the cursor: if a
//! directory the cursor descended through has been renamed or removed,
//! [`query_tree`] returns [`Error::IteratorRestore`](crate::Error) carrying
//! the depth at which the chain broke.

use super::{
    query_dir::{query_directory, DirEntry, Order, QueryDir, QueryOptions},
    Anchor, File, FsHandle, Personality, CONFINED_RESOLVE,
};
use crate::errno::Errno;
use crate::sync_fs::{OFlag, OpenHow};
use std::collections::VecDeque;
use std::os::unix::ffi::OsStrExt;

/// Upper bound on how deep a walk will descend, mirroring
/// [`sync_fs::iter`](crate::sync_fs::iter)'s limit. Each level holds an open
/// directory descriptor, so this bounds the walk's fd usage.
pub const MAX_DEPTH: usize = 2048;

/// Magic prefixing a [`TreeCursor::to_bytes`] blob (`"TnTc"`, host-endian).
const CURSOR_MAGIC: u32 = u32::from_ne_bytes(*b"TnTc");
/// On-disk [`TreeCursor`] format version. A blob declaring anything else is
/// refused rather than guessed at: the token is persisted by whoever holds it
/// and handed back later, so a format that changed under it must fail loudly.
const CURSOR_VERSION: u16 = 1;
/// Flag: the key names a directory the caller pruned, so a resume must step
/// over its subtree instead of entering it.
const CURSOR_FLAG_SKIP: u16 = 1 << 0;

/// One entry from a [`QueryTree`], with where it sits in the subtree.
///
/// The [`DirEntry`] is exactly what a single-directory listing would have
/// produced; the walk adds the parent path so the entry can be named
/// relative to the root.
#[derive(Clone, Debug)]
pub struct TreeEntry {
    /// Path of the containing directory, relative to the walk root. Empty
    /// for entries directly in the root.
    parent: Vec<u8>,
    /// The enriched entry itself.
    pub entry: DirEntry,
}

impl TreeEntry {
    /// The containing directory's path relative to the walk root, empty at
    /// the top level. Never has a trailing `/`.
    pub fn parent(&self) -> &[u8] {
        &self.parent
    }

    /// This entry's path relative to the walk root — `parent/name`, or just
    /// `name` at the top level. No trailing `/`, even for a directory; see
    /// [`key`](Self::key) for the form that sorts and resumes correctly.
    pub fn path(&self) -> Vec<u8> {
        let name = self.entry.name.as_bytes();
        if self.parent.is_empty() {
            return name.to_vec();
        }
        let mut p = Vec::with_capacity(self.parent.len() + 1 + name.len());
        p.extend_from_slice(&self.parent);
        p.push(b'/');
        p.extend_from_slice(name);
        p
    }

    /// The entry's **sort key**: [`path`](Self::path) with a trailing `/` for
    /// a directory.
    ///
    /// This is the form the walk orders by and the form a [`TreeCursor`]
    /// carries, so a caller resuming after this entry should hand this value
    /// — not [`path`](Self::path) — to [`TreeCursor::from_key`].
    pub fn key(&self) -> Vec<u8> {
        let mut k = self.path();
        if self.entry.is_dir {
            k.push(b'/');
        }
        k
    }

    /// How far below the root this entry sits; 0 for the top level.
    pub fn depth(&self) -> usize {
        if self.parent.is_empty() {
            0
        } else {
            self.parent.iter().filter(|&&b| b == b'/').count() + 1
        }
    }

    /// Whether this entry is a directory (and so a candidate for descent).
    pub fn is_dir(&self) -> bool {
        self.entry.is_dir
    }
}

/// A serializable resume token: the last key a [`QueryTree`] emitted, plus
/// whether the caller pruned it.
///
/// Round-trip it with [`to_bytes`](Self::to_bytes) /
/// [`from_bytes`](Self::from_bytes) to carry a paginated listing across
/// requests or process restarts. Unlike a directory offset, it stays
/// meaningful when the tree changes underneath: it names a position in the
/// key space, not in any directory's read order.
///
/// The key alone cannot express every position the walk can be in. A directory
/// is emitted *before* its contents, so the key `"D/"` means "just before
/// `D`'s subtree" — which is what a resume needs after yielding `D`, and the
/// opposite of what it needs after [`skip_descent`](QueryTree::skip_descent)
/// folded `D` into a common prefix. Nor can the key be rewritten to say so:
/// `"D"` sorts *before* the directory's own key and would re-emit `D` itself.
/// [`skips_subtree`](Self::skips_subtree) is that missing bit.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TreeCursor {
    key: Vec<u8>,
    skip_subtree: bool,
}

impl TreeCursor {
    /// A cursor positioned just after `key`, which must be an entry's
    /// [`TreeEntry::key`] — trailing `/` included when it named a directory,
    /// since that is what decides where the resume point sorts.
    ///
    /// Resuming from this descends into a directory key; pair it with
    /// [`skipping_subtree`](Self::skipping_subtree) to step over one instead.
    pub fn from_key(key: impl Into<Vec<u8>>) -> TreeCursor {
        TreeCursor {
            key: key.into(),
            skip_subtree: false,
        }
    }

    /// This cursor, but resuming *past* the directory its key names rather
    /// than inside it — the persisted form of
    /// [`skip_descent`](QueryTree::skip_descent). A no-op on a key that does
    /// not name a directory.
    pub fn skipping_subtree(mut self) -> TreeCursor {
        self.skip_subtree = self.key.ends_with(b"/");
        self
    }

    /// Whether resuming from this cursor steps over the directory its key
    /// names instead of descending into it.
    pub fn skips_subtree(&self) -> bool {
        self.skip_subtree
    }

    /// The raw key this cursor sits after.
    pub fn key(&self) -> &[u8] {
        &self.key
    }

    /// True if this cursor is positioned at the start (resuming from it walks
    /// the whole tree).
    pub fn is_empty(&self) -> bool {
        self.key.is_empty()
    }

    /// Serialize to a self-describing blob suitable for persisting: magic,
    /// version, flags, then the length-prefixed key. Paths are stored as
    /// bytes, so non-UTF-8 names round-trip exactly.
    ///
    /// Exactly one blob encodes a given cursor, so two tokens naming the same
    /// position compare equal as bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let flags = if self.skip_subtree {
            CURSOR_FLAG_SKIP
        } else {
            0
        };
        let mut out = Vec::with_capacity(12 + self.key.len());
        out.extend_from_slice(&CURSOR_MAGIC.to_ne_bytes());
        out.extend_from_slice(&CURSOR_VERSION.to_ne_bytes());
        out.extend_from_slice(&flags.to_ne_bytes());
        out.extend_from_slice(&(self.key.len() as u32).to_ne_bytes());
        out.extend_from_slice(&self.key);
        out
    }

    /// Reconstruct from [`to_bytes`](Self::to_bytes) output. Malformed input
    /// (bad magic or version, an unknown flag, truncated, or trailing bytes)
    /// is [`Error::Validation`](crate::Error).
    pub fn from_bytes(data: &[u8]) -> crate::Result<TreeCursor> {
        let bad = |why: &str| {
            Err(crate::Error::Validation(format!("tree cursor: {why}")))
        };
        if data.len() < 12 {
            return bad("truncated header");
        }
        let magic = u32::from_ne_bytes(data[0..4].try_into().unwrap());
        if magic != CURSOR_MAGIC {
            return bad(&format!("not a cursor blob (magic {magic:#010x})"));
        }
        let version = u16::from_ne_bytes(data[4..6].try_into().unwrap());
        if version != CURSOR_VERSION {
            return bad(&format!("unsupported version {version}"));
        }
        let flags = u16::from_ne_bytes(data[6..8].try_into().unwrap());
        // Refuse a bit this build does not understand rather than silently
        // resuming with a meaning the writer did not intend.
        if flags & !CURSOR_FLAG_SKIP != 0 {
            return bad(&format!("unknown flags {flags:#06x}"));
        }
        let len = u32::from_ne_bytes(data[8..12].try_into().unwrap()) as usize;
        if data.len() != 12 + len {
            return bad("length does not match the blob");
        }
        Ok(TreeCursor {
            key: data[12..].to_vec(),
            skip_subtree: flags & CURSOR_FLAG_SKIP != 0,
        })
    }

    /// The `/`-separated components of the key, with the trailing empty
    /// component a directory key produces already dropped.
    fn components(&self) -> Vec<&[u8]> {
        self.key
            .split(|&b| b == b'/')
            .filter(|c| !c.is_empty())
            .collect()
    }
}

/// How to walk a subtree. [`QueryOptions`] governs each level's listing; the
/// rest governs the walk.
#[derive(Clone, Debug)]
pub struct TreeOptions {
    /// Per-level listing options — enrichment, `clump`, `statx_mask`,
    /// `same_device_only`.
    ///
    /// Two fields are overridden by the walk and ignored here:
    /// [`order`](QueryOptions::order), which is forced to
    /// [`Order::ByPathBytes`] because nothing else composes across levels,
    /// and [`start_after`](QueryOptions::start_after), which belongs to
    /// [`resume`](Self::resume).
    ///
    /// [`name_prefix`](QueryOptions::name_prefix) applies **only to the root
    /// level**. A subtree walk is normally rooted at the parent of the prefix
    /// being served, with the prefix's last partial component filtering that
    /// first level — applying it further down would filter names that the
    /// caller's prefix has nothing to say about.
    pub entries: QueryOptions,
    /// How many levels to descend. `1` lists the root directory only, which
    /// is the non-recursive case; `MAX_DEPTH` is the ceiling.
    pub max_depth: usize,
    /// Resume after this cursor instead of starting at the beginning.
    pub resume: Option<TreeCursor>,
}

impl Default for TreeOptions {
    fn default() -> Self {
        TreeOptions {
            entries: QueryOptions::default(),
            max_depth: MAX_DEPTH,
            resume: None,
        }
    }
}

/// One open directory level on the walk stack.
struct Frame {
    /// This directory's path relative to the walk root; empty for the root.
    path: Vec<u8>,
    /// Keeps the directory descriptor alive for the frame's lifetime, and is
    /// what the next descent resolves against.
    anchor: Anchor,
    /// The level's listing, already ordered and (on resume) already cut.
    dir: QueryDir,
    /// The current batch, drained one entry at a time.
    buf: VecDeque<DirEntry>,
}

/// A running subtree walk. Pull entries with [`next`](QueryTree::next) until
/// it returns `None`. Dropping it closes every level still open.
///
/// Not `Send`: each level owns a directory stream whose cursor is
/// single-threaded.
pub struct QueryTree {
    h: FsHandle,
    who: Personality,
    opts: TreeOptions,
    stack: Vec<Frame>,
    /// The directory just yielded, waiting to be descended into on the next
    /// call — deferred so [`skip_descent`](Self::skip_descent) can cancel it
    /// before the descent costs an `open`. Holds its relative path.
    pending: Option<Vec<u8>>,
    /// The key most recently emitted, for [`cursor`](Self::cursor).
    last_key: Vec<u8>,
    /// [`skip_descent`](Self::skip_descent) cancelled the descent into
    /// `last_key`, so a [`cursor`](Self::cursor) taken here must resume past
    /// that subtree rather than inside it.
    skip_subtree: bool,
    /// A level failed irrecoverably; stop rather than loop.
    fatal: bool,
}

impl std::fmt::Debug for QueryTree {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QueryTree")
            .field("depth", &self.stack.len())
            .field("pending_descent", &self.pending.is_some())
            .finish_non_exhaustive()
    }
}

impl QueryTree {
    /// Do not descend into the directory just yielded.
    ///
    /// This is the pruning primitive a delimiter is built from: fold the
    /// entry into a common prefix and skip it, and the walk never opens it,
    /// never reads it, and never enriches anything beneath it. A no-op unless
    /// the last entry was a directory the walk was about to enter.
    ///
    /// The pruning survives a [`cursor`](Self::cursor) round-trip: the token
    /// records it, so a page boundary landing on a folded directory does not
    /// re-open the subtree on the next page.
    pub fn skip_descent(&mut self) {
        // Only a cancelled descent counts. Called after a file — where there
        // was nothing to descend into — this must not mark the cursor, or the
        // resume would step past a key it should merely resume after.
        self.skip_subtree |= self.pending.take().is_some();
    }

    /// A cursor positioned after the last entry yielded — persist it to
    /// resume a later walk exactly here. Empty before the first entry.
    ///
    /// Carries the effect of a [`skip_descent`](Self::skip_descent) made since
    /// that entry, so folding and paging compose.
    pub fn cursor(&self) -> TreeCursor {
        TreeCursor {
            key: self.last_key.clone(),
            skip_subtree: self.skip_subtree,
        }
    }

    /// The next entry in path order, or `None` at the end of the subtree.
    ///
    /// A subtree with nothing left to list is **skipped**: one this identity
    /// may not enter (`EACCES`/`EPERM`), matching the per-entry permission
    /// behavior elsewhere in this module, or one removed out from under the
    /// walk (`ENOENT`). Any failure that leaves the walk *unable to see* what
    /// is there — fd exhaustion, I/O, a mount not crossed, a directory
    /// replaced by something else — is surfaced as `Some(Err)`, so an
    /// incomplete walk is never mistaken for a fully listed one. See
    /// `is_subtree_skip` for which is which and why.
    ///
    /// A surfaced descent failure is per-subtree, not terminal: the walk
    /// resumes in the parent on the next call.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Option<crate::Result<TreeEntry>> {
        if self.fatal {
            return None;
        }
        loop {
            // Enter the directory yielded last time, unless the caller said
            // not to. Done here rather than at yield time so a pruned
            // directory costs no `open` at all.
            if let Some(path) = self.pending.take() {
                if let Err(e) = self.descend(&path) {
                    return Some(Err(e));
                }
            }

            let frame = self.stack.last_mut()?;
            if frame.buf.is_empty() {
                match frame.dir.next() {
                    None => {
                        // Level exhausted: ascend and continue in the parent.
                        self.stack.pop();
                        continue;
                    }
                    Some(Ok(batch)) => frame.buf.extend(batch),
                    Some(Err(e)) => {
                        // A readdir that failed mid-level cannot be resumed
                        // (the stream has no rewind), so drop the level
                        // rather than silently repeating part of it.
                        self.stack.pop();
                        return Some(Err(e));
                    }
                }
                continue;
            }

            let entry = frame.buf.pop_front().expect("buf is non-empty");
            let out = TreeEntry {
                parent: frame.path.clone(),
                entry,
            };
            self.last_key = out.key();
            // A fresh entry: whatever the caller pruned belonged to the last
            // one, and the cursor now sits here instead.
            self.skip_subtree = false;
            if out.is_dir() && self.stack.len() < self.opts.max_depth {
                self.pending = Some(out.path());
            }
            return Some(Ok(out));
        }
    }

    /// Open `path`'s directory relative to the current top frame and push it.
    /// A directory that is forbidden or already gone ([`is_subtree_skip`]) is
    /// skipped silently; any other open failure is returned so the walk does
    /// not continue as though the subtree were empty.
    fn descend(&mut self, path: &[u8]) -> crate::Result<()> {
        let Some(top) = self.stack.last() else {
            return Ok(());
        };
        // The leaf name, which is all that is resolved: descent never
        // re-walks from the root, so a component swapped underneath the walk
        // cannot redirect it above the level we already hold open.
        let name = match path.rsplit(|&b| b == b'/').next() {
            Some(n) if !n.is_empty() => n.to_vec(),
            _ => return Ok(()),
        };
        let anchor = top.anchor.clone();
        let mut opts = self.opts.entries.clone();
        // The prefix filter belongs to the root level only (see
        // `TreeOptions::entries`).
        opts.name_prefix = None;
        match open_frame(
            &self.h,
            self.who,
            &anchor,
            &name,
            path.to_vec(),
            opts,
            None,
        ) {
            Ok(frame) => {
                self.stack.push(frame);
                Ok(())
            }
            // A subtree with nothing to list drops out quietly; a failing walk
            // (fd exhaustion, I/O, a mount point not crossed) must not.
            Err(e) if is_subtree_skip(&e) => Ok(()),
            Err(e) => Err(e),
        }
    }
}

/// Whether failing to open a level means **there is nothing there to list**,
/// so the subtree drops out quietly, rather than **the walk cannot see what is
/// there**, which has to surface.
///
/// * `EACCES`/`EPERM` — this identity may not enter. The documented
///   per-identity behaviour: a permission-filtered listing, matching how a
///   denial surfaces per-entry elsewhere in this module.
/// * `ENOENT` — the directory was removed between the parent's `readdir` and
///   the deferred descent. There is no subtree left to list, and a walk over a
///   live tree hits this routinely, so failing the whole listing over one
///   ordinary race would make the walk unusable on anything being written to.
///
/// `ENOTDIR` is deliberately **not** here even though it is also a race. The
/// name still exists, but as something other than a directory — and the walk
/// has already emitted it with a directory key, so the listing now contains a
/// claim the filesystem contradicts. That is worth telling the caller about;
/// a vanished entry is not.
fn is_subtree_skip(e: &crate::Error) -> bool {
    matches!(
        e,
        crate::Error::Errno(Errno::EACCES | Errno::EPERM | Errno::ENOENT)
    )
}

/// Open one directory level and build its frame.
///
/// The open is `O_DIRECTORY | O_NOFOLLOW` under [`CONFINED_RESOLVE`], so the
/// kernel — not this code — refuses a symlink, a `..`, or a crossing into
/// another filesystem, and it resolves a single component against a
/// descriptor the walk already holds.
fn open_frame(
    h: &FsHandle,
    who: Personality,
    parent: &Anchor,
    name: &[u8],
    path: Vec<u8>,
    mut opts: QueryOptions,
    start_after: Option<Vec<u8>>,
) -> crate::Result<Frame> {
    let how = OpenHow::new()
        .flags(OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW)
        .resolve(CONFINED_RESOLVE);
    let dir: File = h.open(who, parent, name, how)?;
    let anchor = Anchor::from_file(&dir)?;
    opts.order = Order::ByPathBytes;
    opts.start_after = start_after;
    let listing = query_directory(h, who, &anchor, opts)?;
    Ok(Frame {
        path,
        anchor,
        dir: listing,
        buf: VecDeque::new(),
    })
}

/// Walk the subtree under `root` as `who`, in path order.
///
/// The root itself is never yielded; its entries are, then their subtrees,
/// depth-first. See the module docs for what the ordering guarantees and
/// [`TreeOptions::resume`] for restarting a paginated walk.
pub fn query_tree(
    h: &FsHandle,
    who: Personality,
    root: &Anchor,
    opts: TreeOptions,
) -> crate::Result<QueryTree> {
    if opts.max_depth == 0 || opts.max_depth > MAX_DEPTH {
        return Err(crate::Error::Validation(format!(
            "query_tree: max_depth must be 1..={MAX_DEPTH}, got {}",
            opts.max_depth
        )));
    }
    let cursor = opts.resume.clone().unwrap_or_default();
    let comps = cursor.components();

    // A cursor ending in `/` named a **directory**, which the walk emits
    // *before* its contents — so what it owes is that directory's subtree,
    // and the resume descends through every component and starts the deepest
    // level at its beginning. A cursor naming a file owes only what follows
    // the file, so the deepest level is its parent, cut at the file itself.
    // Confusing the two silently drops a whole subtree whenever a page
    // boundary lands on a directory.
    //
    // A pruned directory is the third case, and it is why the bit exists: the
    // caller folded it into a common prefix, so the walk owes what follows the
    // whole subtree. That resumes like a file cursor — the deepest level is
    // the parent — but cut past `D/` rather than at `D`, since the directory
    // sorts at its slashed key and cutting at the bare name would re-emit it.
    let skip = cursor.skips_subtree();
    let into_dir = cursor.key().ends_with(b"/") && !skip;
    let descend = if into_dir {
        comps.len()
    } else {
        comps.len().saturating_sub(1)
    }
    // Never rebuild a deeper stack than the caller allows.
    .min(opts.max_depth - 1);

    // What the level at `depth` should skip past.
    let cut_for = |depth: usize| -> Option<Vec<u8>> {
        if depth < descend {
            // This level descends through `comps[depth]`, so cut past that
            // directory: the walk resumes after it on the way back up.
            let mut k = comps[depth].to_vec();
            k.push(b'/');
            return Some(k);
        }
        if depth >= comps.len() || (into_dir && depth == comps.len()) {
            // The deepest level of a directory cursor: nothing inside it has
            // been emitted, so start from its first entry.
            return None;
        }
        // The deepest level of a file cursor — cut at the file. (Or a level
        // `max_depth` stopped the descent at, where the component is a
        // directory we cannot enter, so cut past it.) A pruned directory is
        // cut past too: `skip` is only ever set for a key ending in `/`, so
        // the slash restores the sort key the entry actually carries.
        let mut k = comps[depth].to_vec();
        if into_dir || skip || depth + 1 < comps.len() {
            k.push(b'/');
        }
        Some(k)
    };

    let mut root_opts = opts.entries.clone();
    root_opts.order = Order::ByPathBytes;
    root_opts.start_after = cut_for(0);
    let mut stack = vec![Frame {
        path: Vec::new(),
        anchor: root.clone(),
        dir: query_directory(h, who, root, root_opts)?,
        buf: VecDeque::new(),
    }];

    // Rebuild the directory chain the cursor descended through, cutting each
    // level at the component below it. Nothing before a cut is read, so a
    // resumed walk costs one `open` per level rather than a re-scan.
    for (depth, comp) in comps.iter().copied().enumerate().take(descend) {
        let mut path = stack.last().expect("stack is non-empty").path.clone();
        if !path.is_empty() {
            path.push(b'/');
        }
        path.extend_from_slice(comp);

        let mut level_opts = opts.entries.clone();
        level_opts.name_prefix = None;
        let anchor = stack.last().expect("stack is non-empty").anchor.clone();
        let frame = open_frame(
            h,
            who,
            &anchor,
            comp,
            path.clone(),
            level_opts,
            cut_for(depth + 1),
        )
        .map_err(|_| crate::Error::IteratorRestore {
            depth,
            path: std::path::PathBuf::from(
                String::from_utf8_lossy(&path).into_owned(),
            ),
        })?;
        stack.push(frame);
    }

    Ok(QueryTree {
        h: h.clone(),
        who,
        opts,
        stack,
        pending: None,
        last_key: cursor.key().to_vec(),
        // Carry the incoming bit so `cursor()` before the first `next()`
        // returns the token we were resumed from, not a weaker one.
        skip_subtree: skip,
        fatal: false,
    })
}

#[cfg(all(test, not(loom)))]
mod tests {
    use super::*;

    /// Both halves of the descent contract. A subtree with nothing left to
    /// list drops out quietly; anything that leaves the walk unable to see
    /// what is there must surface, or a partial listing reads as a complete
    /// one. Pinned here as a predicate because the interesting errnos are
    /// awkward to provoke for real — fd exhaustion is process-wide, `EACCES`
    /// needs a non-root runner — while the integration side in
    /// `test/uring_fs.rs` drives the two races end to end.
    #[test]
    fn a_subtree_is_skipped_only_when_nothing_is_left_to_list() {
        for e in [Errno::EACCES, Errno::EPERM, Errno::ENOENT] {
            assert!(
                is_subtree_skip(&crate::Error::Errno(e)),
                "{e:?} leaves no subtree to list, so it drops out quietly"
            );
        }
        for e in [
            Errno::EMFILE,
            Errno::ENFILE,
            Errno::EXDEV,
            Errno::EIO,
            Errno::ENOMEM,
            Errno::ELOOP,
            // The name is still there, but no longer a directory — and the
            // walk already emitted it with a directory key, so the caller is
            // holding a claim the filesystem now contradicts.
            Errno::ENOTDIR,
        ] {
            assert!(
                !is_subtree_skip(&crate::Error::Errno(e)),
                "{e:?} means the walk cannot see the subtree, not that it is \
                 empty"
            );
        }
        assert!(
            !is_subtree_skip(&crate::Error::Validation("x".into())),
            "a non-errno failure is never a quiet skip"
        );
    }

    #[test]
    fn cursor_round_trips_through_bytes() {
        let c = TreeCursor::from_key(b"a/b/c.txt".to_vec());
        let back = TreeCursor::from_bytes(&c.to_bytes()).expect("round trip");
        assert_eq!(back, c);

        // Non-UTF-8 names survive: the blob is length-prefixed bytes.
        let raw = TreeCursor::from_key(vec![0xff, b'/', 0xfe]);
        assert_eq!(
            TreeCursor::from_bytes(&raw.to_bytes()).expect("round trip"),
            raw
        );
    }

    #[test]
    fn malformed_cursor_blobs_are_rejected() {
        assert!(TreeCursor::from_bytes(b"short").is_err());
        let mut bad_magic = TreeCursor::from_key("x").to_bytes();
        bad_magic[0] ^= 0xff;
        assert!(TreeCursor::from_bytes(&bad_magic).is_err());
        let mut bad_version = TreeCursor::from_key("x").to_bytes();
        bad_version[4] = 0xff;
        assert!(TreeCursor::from_bytes(&bad_version).is_err());
        let mut trailing = TreeCursor::from_key("x").to_bytes();
        trailing.push(0);
        assert!(TreeCursor::from_bytes(&trailing).is_err());

        // Cut off inside the flags word.
        let short = TreeCursor::from_key("x/").skipping_subtree().to_bytes();
        assert!(TreeCursor::from_bytes(&short[..9]).is_err());
        // A flag this build does not know is refused, not ignored: resuming
        // with a meaning the writer did not intend would mis-list silently.
        let mut unknown =
            TreeCursor::from_key("x/").skipping_subtree().to_bytes();
        unknown[6] = 0xff;
        assert!(TreeCursor::from_bytes(&unknown).is_err());
    }

    /// The skip bit is what makes folding and paging compose, so it has to
    /// survive the round-trip and it has to be part of the cursor's identity
    /// — two cursors on the same key that resume differently are not the same
    /// cursor, and must not encode to the same bytes.
    #[test]
    fn the_skip_bit_survives_a_round_trip_and_distinguishes_two_cursors() {
        let plain = TreeCursor::from_key("a/");
        let folded = TreeCursor::from_key("a/").skipping_subtree();
        assert!(!plain.skips_subtree());
        assert!(folded.skips_subtree());
        assert_ne!(folded, plain);
        assert_ne!(folded.to_bytes(), plain.to_bytes());

        for c in [&plain, &folded] {
            let back = TreeCursor::from_bytes(&c.to_bytes()).expect("decode");
            assert_eq!(&back, c, "cursor does not round-trip");
            assert_eq!(back.key(), b"a/");
        }

        // Nothing to skip past on a file key, so the bit does not attach.
        assert!(!TreeCursor::from_key("a.txt")
            .skipping_subtree()
            .skips_subtree());
    }

    /// A directory key's trailing `/` must not become an empty component, or
    /// the restore would try to open a level named "".
    #[test]
    fn components_drop_the_directory_separator() {
        assert_eq!(
            TreeCursor::from_key("a/b/").components(),
            [b"a".as_slice(), b"b".as_slice()]
        );
        assert_eq!(
            TreeCursor::from_key("a/b").components(),
            [b"a".as_slice(), b"b".as_slice()]
        );
        assert!(TreeCursor::default().components().is_empty());
    }
}
