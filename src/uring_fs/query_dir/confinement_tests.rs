use std::ffi::CString;

use super::{
    DiscRead, EnrichSpec, Order, QueryOptions, XattrNamespaces, asked_for_what_this_type_can_hold, entry_is_dir,
    open_failure_is_incompleteness, pending_discovered, split_statx, unresolved_statx_verdict,
};
use crate::errno::Errno;
use crate::uring_fs::{FsOutcome, FsPending};

/// An entry that cannot be opened at all is answered, not lost - but only where the entry could not have held the
/// values either.
///
/// The listing opens each entry `O_RDONLY|O_NOFOLLOW|O_NONBLOCK` to read its values through, and two ordinary entry
/// types can never satisfy that: a symbolic link answers `ELOOP` because of `O_NOFOLLOW`, and a socket answers
/// `ENXIO`. Measured with the listing's own flags on this tree: sym -> ELOOP, sock -> ENXIO, while fifo, regular
/// and directory all open.
///
/// The two do **not** get the same verdict, and the errno is not what separates them - what the object can hold is.
/// Treated as an incompleteness, `ELOOP` flags [`DirEntry::xattrs_incomplete`] on a listing that lost nothing and a
/// consumer that re-queries on the flag re-queries for ever; that is affordable because a symlink can hold neither
/// an access ACL nor a `user.*` attribute, so "absent" is true of it. A socket holds both, so its `ENXIO` leaves
/// values genuinely unread and belongs on the reported side beside `EBUSY`, or the listing answers "this object has
/// no ACL" for one that has one.
///
/// The reported side is what the flag is for, and `None` is in it:
/// no op slot was free to issue the open with, so the entry's values really are unread.
/// The type half of the same verdict: the errno says the values were not read, this says whether there were any to
/// read.
///
/// Both must hold, so this can only ever *narrow* the flag. The matrix is the point - a socket asked for `user.*`
/// lost nothing and a socket asked for its ACL lost a real value, and a fix that answers only one of those reads as
/// correct.
#[test]
fn only_a_request_the_type_could_answer_is_an_incompleteness() {
    let opts = |spec, names: &[&str], ns| QueryOptions {
        spec,
        xattr_names: names.iter().map(|n| CString::new(*n).unwrap()).collect(),
        xattr_ns: ns,
        ..Default::default()
    };
    let user = opts(EnrichSpec::XATTR, &["user.probe"], XattrNamespaces::empty());
    let trusted = opts(EnrichSpec::XATTR, &["trusted.probe"], XattrNamespaces::empty());
    let acl = opts(EnrichSpec::ACL, &[], XattrNamespaces::empty());
    let disc_user = opts(EnrichSpec::XATTR_LIST, &[], XattrNamespaces::USER);
    let disc_both = opts(
        EnrichSpec::XATTR_LIST,
        &[],
        XattrNamespaces::USER | XattrNamespaces::TRUSTED,
    );

    // A socket holds an ACL and `trusted.*`, and cannot hold `user.*` (`xattr_permission`, `fs/xattr.c`).
    for (o, want, why) in [
        (&user, false, "user.* cannot live on a socket"),
        (&trusted, true, "trusted.* has no type rule"),
        (&acl, true, "a socket's ACL reads back at full length"),
        (&disc_user, false, "user.-only discovery finds nothing"),
        (&disc_both, true, "trusted.* is in the requested set"),
    ] {
        assert_eq!(
            asked_for_what_this_type_can_hold(o.spec, o, libc::DT_SOCK),
            want,
            "DT_SOCK: {why}"
        );
    }
    // A symlink holds neither, but `ELOOP` is what actually decides it.
    assert!(!asked_for_what_this_type_can_hold(acl.spec, &acl, libc::DT_LNK));
    // A regular file, a directory and an unknown type rule out nothing.
    for dt in [libc::DT_REG, libc::DT_DIR, libc::DT_UNKNOWN] {
        assert!(
            asked_for_what_this_type_can_hold(user.spec, &user, dt),
            "dtype {dt} must rule nothing out"
        );
    }
    // Nothing asked for is never an incompleteness.
    let nothing = opts(EnrichSpec::STATX, &["user.probe"], XattrNamespaces::USER);
    assert!(!asked_for_what_this_type_can_hold(
        nothing.spec,
        &nothing,
        libc::DT_SOCK
    ));
}

#[test]
fn an_unopenable_entry_is_answered_not_lost() {
    for e in [Errno::EACCES, Errno::EPERM, Errno::ENOENT, Errno::ELOOP] {
        assert!(
            !open_failure_is_incompleteness(Some(e)),
            "{e} is a definite answer about this entry"
        );
    }
    for e in [
        Errno::ENXIO,
        Errno::ENOTDIR,
        Errno::EBUSY,
        Errno::ECANCELED,
        Errno::ECONNABORTED,
        Errno::EIO,
        Errno::EMFILE,
        Errno::ENOMEM,
    ] {
        assert!(
            open_failure_is_incompleteness(Some(e)),
            "{e} left this entry's values unread"
        );
    }
    assert!(
        open_failure_is_incompleteness(None),
        "no op slot to issue the open with is a failed read"
    );
}

/// An attribute read that did not happen is not an attribute that is not there.
///
/// [`DirEntry::xattrs_incomplete`] exists to separate the two, and its own doc names the causes: "the `flistxattr`
/// itself failed ..., an op slot was unavailable, or a value known to be readable could not be refetched".
/// Everything downstream of this classification keys off it -- the explicit names, the discovered names, and the
/// ACL - so the split lives here, once, and is pinned here.
///
/// The two deliberate drops are `unresolved_statx_verdict`'s, minus `ENOENT` (which names a *path*, and these reads
/// take a descriptor) plus `ENODATA` (the attribute genuinely is not there). Getting the membership wrong in either
/// direction is a real defect: a marked `EBUSY` classed as `Drop` reports a full op table as "this file has no
/// ACL", and an `EACCES` classed as `Lost` flags every listing under an identity that cannot read `trusted.*`.
#[test]
fn a_refused_value_read_is_not_an_absent_attribute() {
    fn classify(res: Result<i32, Errno>, buf: Vec<u8>) -> DiscRead {
        pending_discovered(FsPending::resolved(FsOutcome::new(res, vec![buf], None, None)))
    }

    assert!(
        matches!(classify(Ok(3), vec![1, 2, 3, 0, 0]), DiscRead::Got(v) if v == [1, 2, 3]),
        "a short value in a probe buffer is the value"
    );
    assert!(
        matches!(classify(Err(Errno::ERANGE), vec![0; 4]), DiscRead::Grow),
        "ERANGE is the refetch signal, not a loss"
    );
    // `E2BIG` is the same signal for a large caller buffer: `do_getxattr` (`fs/xattr.c:852-857`) rewrites the
    // filesystem's `-ERANGE` to it once the buffer reaches the kernel's `XATTR_SIZE_MAX`. Unreachable from here
    // today - both probe buffers are 64 KiB or under - and pinned anyway, because the fixed sizes are the only
    // reason it is, and `refetch_grow`, whose buffers do pass 64 KiB, needs the same answer.
    assert!(
        matches!(classify(Err(Errno::E2BIG), vec![0; 4]), DiscRead::Grow),
        "E2BIG is ERANGE for a buffer at or above XATTR_SIZE_MAX"
    );

    // Deliberate drops: a definite "no value here". Never an incompleteness.
    //
    // `EOPNOTSUPP` is the one that costs if it is missed. An `acltype=posixacl` dataset answers it for
    // `system.nfs4_acl_xdr`, and `acl_name` is the caller's to choose, so classing it as a failed read flags every
    // entry of a complete listing whenever a permissions layer asks for the NFSv4 ACL on a POSIX dataset.
    for e in [Errno::ENODATA, Errno::EACCES, Errno::EPERM, Errno::EOPNOTSUPP] {
        assert!(
            matches!(classify(Err(e), vec![0; 4]), DiscRead::Drop),
            "{e} is a definite answer, not a failed read"
        );
    }

    // The read failing. `EBUSY` is the marked refusal of a full op table - reached under exactly the pressure that
    // makes a listing large - and `ECONNABORTED` is a loop torn down mid-flight.
    for e in [Errno::EBUSY, Errno::EIO, Errno::ECANCELED, Errno::ECONNABORTED] {
        assert!(
            matches!(classify(Err(e), vec![0; 4]), DiscRead::Lost),
            "{e} left the value unread, which is not 'absent'"
        );
    }

    // A count the buffer cannot account for is not a value either.
    assert!(
        matches!(classify(Ok(9), vec![0; 4]), DiscRead::Lost),
        "a count past the buffer is a failed read"
    );
}

/// An ordered listing emits the directory-ness it sorted by.
///
/// `cmp_path_bytes` gives a directory the trailing separator its children will carry, and a caller resumes from the
/// key built out of `DirEntry::is_dir` - so an entry ordered as one thing and reported as the other resumes at a
/// key that steps over siblings never emitted. A disagreement is ordinary: the two observations are a `readdir`
/// sweep and a later per-entry `statx`, with the entry free to be replaced in between.
#[test]
fn an_ordered_listing_reports_the_directory_ness_it_sorted_by() {
    // Sorted as a file, `statx` says directory: the key is already spent, so the listing keeps its word.
    assert!(
        !entry_is_dir(Order::ByPathBytes, libc::DT_REG, Some(true)),
        "an entry sorted at `a` reported as `a/`: the resume key skips \
             every sibling between them"
    );
    // And the other way, which the descent answers for with ENOTDIR.
    assert!(entry_is_dir(Order::ByPathBytes, libc::DT_DIR, Some(false)));
    // No metadata at all: the hint, in every mode.
    for order in [Order::ByPathBytes, Order::ByName, Order::Readdir] {
        assert!(entry_is_dir(order, libc::DT_DIR, None));
        assert!(!entry_is_dir(order, libc::DT_REG, None));
    }
    // The unordered modes synthesize no key, so the metadata wins.
    for order in [Order::ByName, Order::Readdir] {
        assert!(entry_is_dir(order, libc::DT_REG, Some(true)));
        assert!(!entry_is_dir(order, libc::DT_DIR, Some(false)));
    }
}

fn split(res: Result<i32, Errno>) -> Option<Errno> {
    split_statx(Some(FsPending::resolved(FsOutcome::new(res, Vec::new(), None, None)))).1
}

/// `same_device_only` is a confinement, and the filter behind it keeps an entry whose device it could not read. So
/// with the option set, an unresolved `statx` has to be answered for.
///
/// The split is `query_tree`'s `is_subtree_skip`, deliberately: skip only what has nothing left to list, surface
/// everything else, because a partial listing that reads as complete is data loss for whatever is built on it.
#[test]
fn an_unreadable_device_is_answered_for_the_way_query_tree_would() {
    // Nothing left to list: the entry alone goes, which is the per-identity behaviour the rest of this module
    // already has.
    for e in [Errno::EACCES, Errno::EPERM, Errno::ENOENT] {
        assert_eq!(
            unresolved_statx_verdict(Some(e)),
            None,
            "{e} should drop the entry, not fail the listing"
        );
    }

    // The filter failing: surfaced, with its own errno. `EBUSY` is the marked refusal of a full op table - reached
    // under exactly the pressure that makes a listing large - and is the documented retryable one.
    for e in [Errno::EBUSY, Errno::EIO, Errno::ENOTDIR] {
        assert_eq!(
            unresolved_statx_verdict(Some(e)),
            Some(e),
            "{e} should fail the listing rather than admit an entry \
                 whose filesystem is unknown"
        );
    }

    // No errno at all where a device was owed: not "nothing to list".
    assert_eq!(
        unresolved_statx_verdict(None),
        Some(Errno::ECONNABORTED),
        "an entry that produced no answer and no reason must surface"
    );
}

/// The errno has to survive the await, or every verdict above is taken on `None` and the listing fails for reasons
/// it should have skipped.
#[test]
fn splitting_a_statx_keeps_the_errno_apart_from_the_metadata() {
    for e in [Errno::EACCES, Errno::EBUSY, Errno::ENOENT] {
        assert_eq!(split(Err(e)), Some(e));
    }
    // A success carries no errno - and no pad on this outcome, which is what makes the "no metadata, no reason" arm
    // above reachable at all.
    assert_eq!(split(Ok(0)), None);
    // And an entry for which none was issued reports neither.
    let (st, err) = split_statx(None);
    assert!(st.is_none() && err.is_none());
}
