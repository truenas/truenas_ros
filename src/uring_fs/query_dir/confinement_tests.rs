use std::ffi::CString;

use super::{
    DiscRead, EnrichSpec, Order, QueryOptions, XattrNamespaces, asked_for_what_this_type_can_hold, entry_is_dir,
    open_failure_is_incompleteness, pending_discovered, split_statx, unresolved_statx_verdict,
};
use crate::errno::Errno;
use crate::uring_fs::{FsOutcome, FsPending};

/// The type half of the open-failure verdict. The errno says the values were not read, and this says whether there
/// were any to read.
///
/// The matrix is the point, since a socket asked for `user.*` lost nothing and a socket asked for its ACL lost a real
/// value.
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

/// An open that fails with a definite answer about the entry (`EACCES`, `EPERM`, `ENOENT`, and a symlink's `ELOOP`)
/// leaves nothing unread, while a socket's `ENXIO`, every other refusal and a missing op slot do.
/// `open_failure_is_incompleteness` says why `ELOOP` and `ENXIO` part company.
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
/// The deliberate drops are `unresolved_statx_verdict`'s minus `ENOENT`, plus `ENODATA`. A marked `EBUSY` classed as
/// `Drop` reports a full op table as "this file has no ACL", and an `EACCES` classed as `Lost` flags every listing
/// under an identity that cannot read `trusted.*`.
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
    // `E2BIG` is the same signal for a buffer at or above `XATTR_SIZE_MAX` (`do_getxattr`, `fs/xattr.c:852-857`).
    assert!(
        matches!(classify(Err(Errno::E2BIG), vec![0; 4]), DiscRead::Grow),
        "E2BIG is ERANGE for a buffer at or above XATTR_SIZE_MAX"
    );

    // Deliberate drops, `EOPNOTSUPP` included, which a POSIX dataset answers for `system.nfs4_acl_xdr`.
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
/// The two observations are a `readdir` sweep and a later `statx`, so they can disagree, and the resume key comes from
/// `DirEntry::is_dir`.
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

/// With `same_device_only` set, an unresolved `statx` is answered for, skipping only what has nothing left to list and
/// surfacing everything else, as `query_tree`'s `is_subtree_skip` does.
#[test]
fn an_unreadable_device_is_answered_for_the_way_query_tree_would() {
    // Nothing left to list, so the entry alone goes.
    for e in [Errno::EACCES, Errno::EPERM, Errno::ENOENT] {
        assert_eq!(
            unresolved_statx_verdict(Some(e)),
            None,
            "{e} should drop the entry, not fail the listing"
        );
    }

    // The filter failing surfaces with its own errno.
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
