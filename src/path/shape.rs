//! Path *shape*: whether a byte string may name something the `*at`
//! syscalls can create beneath an anchor. Validation only - nothing here
//! joins, normalises or resolves.
//!
//! # Why there is no `normpath`
//!
//! Normalising would be the obvious alternative: fold `a/./b` to `a/b`,
//! `a/../b` to `b`, and hand the kernel the result. CPython implements
//! exactly that and warns about it in the same breath
//! (`Lib/posixpath.py:339-341`):
//!
//! > Normalize a path, e.g. A//B, A/./B and A/foo/../B all become A/B.
//! > It should be understood that this may change the meaning of the path
//! > if it contains symbolic links!
//!
//! That is the whole problem. `a/../b` is `b` only when `a` is not a
//! symlink; when it is, `a/..` is the *target's* parent and the two name
//! different directories. Folding the path lexically therefore launders a
//! traversal into something that looks confined - the exact substitution
//! `RESOLVE_NO_SYMLINKS` exists to refuse. A create that resolved through
//! a component the caller never named would leave a directory somewhere it
//! never asked for, and no error would say so.
//!
//! So a path either names its components plainly or it is refused, and the
//! refusal carries which component was wrong.
//!
//! # What is deliberately not checked
//!
//! **Lengths.** `NAME_MAX` is a filesystem property, not a constant: ZFS
//! raises it to 1023 with the `longname` feature, so a hard 255 here would
//! refuse names the filesystem would have taken. The kernel answers
//! `ENAMETOOLONG` and it is the authority.
//!
//! **Encoding.** A POSIX name is an arbitrary non-NUL byte string. A
//! UTF-8 rule belongs to whatever models the *keys* a service accepts, not
//! to the syscall layer.
//!
//! # Nothing here copies
//!
//! Every function borrows the caller's bytes and answers with a `Copy`
//! enum: [`components`] hands back subslices of its argument
//! (`slice::split` is lazy), and the two `*_defect` functions only scan.
//! There is no allocation on either the accepting or the refusing path, so
//! a caller may validate a path it is about to hand to a syscall without
//! paying for a second copy of it.
//!
//! **The screen is applied per call site, not by the path conversion.** No
//! `TnPath::with_tn_path` implementation calls either function - that trait
//! converts a path to a `CStr` and screens nothing - so going through it
//! says nothing about whether a path was judged. The callers that do judge
//! name it explicitly: `FsIterBuilder::build`, `FsConn::mkdir_path`,
//! `FsHandle::mkdir_path` and `mkdirat`. Anything else - `renameat2`,
//! `statx`, `name_to_handle_at` among them - takes the caller's bytes as
//! given, and its confinement is whatever `RESOLVE_*` flags and anchor it
//! was handed, not this module.
//!
//! The owned components a directory *walk* carries are a different matter:
//! those outlive the completion that consumes them and have to be owned.

use std::fmt;

/// Why a byte string cannot name an entry beneath an anchor.
///
/// Each variant names one component's defect rather than reporting a bare
/// "invalid path", so a caller can say which part of what it was handed
/// was wrong.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Defect {
    /// The whole path is empty, where a name is required.
    Empty,
    /// A leading `/`. An absolute path ignores the anchor descriptor
    /// entirely, so it can never be confined by one.
    Absolute,
    /// An empty component - `a//b`, or a trailing `/`. It names what the
    /// path without it names, so it is a caller assembling a path wrongly
    /// rather than a path meaning something unintended. Refused rather
    /// than skipped, because a rule that quietly accepts one malformed
    /// shape is a worse rule to reason about than one that accepts none.
    EmptyComponent,
    /// A `.` component, which names the directory it sits in rather than
    /// an entry within it.
    Dot,
    /// A `..` component. It resolves against whatever the preceding
    /// component turned out to be, which is not knowable from the path.
    DotDot,
    /// A NUL byte, which terminates the string the kernel receives and so
    /// cannot appear inside a name.
    Nul,
    /// A `/` where a single component is required.
    Separator,
}

impl fmt::Display for Defect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Defect::Empty => "the path is empty",
            Defect::Absolute => "the path is absolute",
            Defect::EmptyComponent => "a component is empty",
            Defect::Dot => "a component is `.`",
            Defect::DotDot => "a component is `..`",
            Defect::Nul => "a component carries NUL",
            Defect::Separator => "a single component may not contain `/`",
        })
    }
}

/// The components of `path`, split on `/`. An empty path yields one empty
/// component, as `split` does.
pub fn components(path: &[u8]) -> impl Iterator<Item = &[u8]> {
    path.split(|&byte| byte == b'/')
}

/// Why `name` cannot be a **single** directory entry's name, or `None`.
///
/// This is the rule the `*at` opcodes need: none of `mkdirat`, `linkat`,
/// `renameat` or `unlinkat` honours a `RESOLVE_*` flag, so a name they are
/// handed must not resolve anywhere but the directory it is given.
pub fn component_defect(name: &[u8]) -> Option<Defect> {
    match name {
        b"" => Some(Defect::Empty),
        b"." => Some(Defect::Dot),
        b".." => Some(Defect::DotDot),
        n if n.contains(&b'/') => Some(Defect::Separator),
        n if n.contains(&0) => Some(Defect::Nul),
        _ => None,
    }
}

/// Why `path` cannot be a relative multi-component path beneath an anchor,
/// or `None`.
///
/// Every component must be a plain name: `a/b/c` passes, and `a/../b`,
/// `./a`, `a//b` and `a/b/` do not. A caller that wants a path resolved
/// *with* `..` has `openat2` and its `RESOLVE_*` flags, where the kernel
/// enforces the confinement; this rule is for the paths a walk has to take
/// apart and create one component at a time, where it cannot.
///
/// The path admitted here is exactly the path a walk will rebuild, one
/// `mkdirat` per component - no component is skipped, folded or reordered
/// on the way. That equality is the point: anything the kernel would
/// resolve differently from that walk is refused instead of quietly
/// resolving one way here and another way there.
pub fn relative_defect(path: &[u8]) -> Option<Defect> {
    if path.is_empty() {
        return Some(Defect::Empty);
    }
    if path[0] == b'/' {
        return Some(Defect::Absolute);
    }
    components(path).find_map(|c| match component_defect(c) {
        // Inside a multi-component path an empty split is a doubled or
        // trailing separator, not a path that is empty outright.
        Some(Defect::Empty) => Some(Defect::EmptyComponent),
        other => other,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_plain_name_is_a_component() {
        for name in [
            &b"made"[..],
            b"...",      // three dots is an ordinary name
            b".hidden",  // so is a leading dot
            b"..hidden", // and a leading double dot
            b"a b",      // spaces are ordinary
            b"caf\xe9",  // a POSIX name need not be UTF-8
            b"\xff\xfe", // including one no encoding claims
        ] {
            assert_eq!(component_defect(name), None, "{name:?}");
        }
        // Length is the kernel's ENAMETOOLONG to give, not this module's:
        // NAME_MAX moves with the filesystem (ZFS `longname` raises it to
        // 1023), so a constant here would refuse names ZFS would take.
        let overlong = vec![b'x'; 4096];
        assert_eq!(component_defect(&overlong), None);
    }

    #[test]
    fn a_component_names_its_defect() {
        for (name, defect) in [
            (&b""[..], Defect::Empty),
            (&b"."[..], Defect::Dot),
            (&b".."[..], Defect::DotDot),
            (&b"a/b"[..], Defect::Separator),
            (&b"a/"[..], Defect::Separator),
            (&b"/"[..], Defect::Separator),
            (&b"a\0b"[..], Defect::Nul),
        ] {
            assert_eq!(component_defect(name), Some(defect), "{name:?}");
        }
    }

    #[test]
    fn a_relative_path_admits_what_a_walk_can_create() {
        for path in [
            &b"a"[..],
            b"a/b/c",
            b"photos/2026/holiday snaps",
            b"...",
            b".hidden/child",
        ] {
            assert_eq!(relative_defect(path), None, "{path:?}");
        }
    }

    /// The shapes this module exists to refuse, each by name. `a/../b` is
    /// the one worth stating twice: it is a legal path the kernel would
    /// resolve, and it is refused anyway, because a walk that has to
    /// create `b` cannot know what `a/..` will turn out to be.
    #[test]
    fn a_relative_path_names_its_defect() {
        for (path, defect) in [
            (&b""[..], Defect::Empty),
            (&b"/etc"[..], Defect::Absolute),
            (&b"/"[..], Defect::Absolute),
            (&b"."[..], Defect::Dot),
            (&b".."[..], Defect::DotDot),
            (&b"./a"[..], Defect::Dot),
            (&b"a/."[..], Defect::Dot),
            (&b"../a"[..], Defect::DotDot),
            (&b"a/../b"[..], Defect::DotDot),
            (&b"a/.."[..], Defect::DotDot),
            (&b"a//b"[..], Defect::EmptyComponent),
            (&b"a/b/"[..], Defect::EmptyComponent),
            (&b"a/\0/b"[..], Defect::Nul),
        ] {
            assert_eq!(relative_defect(path), Some(defect), "{path:?}");
        }
    }

    /// Every component handed back points **into** the caller's buffer, so
    /// splitting a path costs nothing and a caller may validate the same
    /// bytes it is about to give the kernel. Change `components` to return
    /// owned data and this fails.
    #[test]
    fn components_borrow_rather_than_copy() {
        let path = b"alpha/beta/gamma";
        let range = path.as_ptr_range();
        let mut seen = 0;
        for c in components(path) {
            assert!(
                range.contains(&c.as_ptr()),
                "component {c:?} is not a subslice of the input"
            );
            seen += 1;
        }
        assert_eq!(seen, 3, "every component was visited");
    }

    /// The defect reported is the FIRST one, so the message names the
    /// component a reader will find by counting from the left.
    #[test]
    fn the_leftmost_defect_is_the_one_reported() {
        assert_eq!(relative_defect(b"./a/../b"), Some(Defect::Dot));
        assert_eq!(relative_defect(b"a/../b//c"), Some(Defect::DotDot));
        // The empty component comes first here, so it is what is named -
        // there is no ranking of defects, only position.
        assert_eq!(relative_defect(b"a//../b"), Some(Defect::EmptyComponent));
    }
}
