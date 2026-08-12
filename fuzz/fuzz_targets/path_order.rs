#![no_main]

//! Fuzz the ordered-listing comparator for **total-order violations**.
//!
//! `cmp_path_bytes` orders directory entries the way their full paths compare,
//! synthesizing a directory's trailing `/` during the comparison instead of
//! building a key. Its output feeds `sort_by` and `partition_point` over names
//! an unprivileged user chose. Since Rust 1.81 `sort_by` **panics** on a
//! comparator that contradicts itself, and `partition_point` on a non-monotone
//! predicate silently cuts the resume boundary in the wrong place — so a
//! listing would skip or repeat entries across a page.
//!
//! The three laws are checked over a triple: reflexivity, antisymmetry (also
//! called duality — `cmp(a,b)` is the reverse of `cmp(b,a)`), and transitivity
//! in each of its forms. An entry's key is `(name, is_dir)`, so both halves
//! vary.

use libfuzzer_sys::fuzz_target;
use std::cmp::Ordering;
use truenas_ros::uring_fs::query_dir::fuzz::cmp_path_bytes;

type Entry = (Vec<u8>, bool);

fn cmp(a: &Entry, b: &Entry) -> Ordering {
    cmp_path_bytes(&a.0, a.1, &b.0, b.1)
}

fuzz_target!(|data: &[u8]| {
    // Three entries out of one input: a `\xff`-separated list of names, with
    // the leading byte supplying each name's is-a-directory bit. Keeping this
    // byte-driven means a corpus entry reads as the names it compares — the
    // interesting cases are prefix pairs like `a` / `a/` / `ab`, which a
    // structured generator would rarely line up on its own.
    let Some((&flags, rest)) = data.split_first() else {
        return;
    };
    let mut names = rest.split(|&b| b == 0xff);
    let mut next = |bit: u8| -> Entry {
        (names.next().unwrap_or_default().to_vec(), flags & bit != 0)
    };
    let (a, b, c) = (next(1), next(2), next(4));

    // Reflexivity: an entry equals itself.
    for e in [&a, &b, &c] {
        assert_eq!(cmp(e, e), Ordering::Equal, "not reflexive: {e:?}");
    }

    // Duality: reversing the arguments reverses the answer.
    for (x, y) in [(&a, &b), (&b, &c), (&a, &c)] {
        assert_eq!(
            cmp(x, y),
            cmp(y, x).reverse(),
            "not antisymmetric: {x:?} vs {y:?}"
        );
    }

    // Equality must be an equivalence: equal entries compare identically
    // against any third entry, or `sort_by` can place them inconsistently.
    if cmp(&a, &b) == Ordering::Equal {
        assert_eq!(
            cmp(&a, &c),
            cmp(&b, &c),
            "equal entries {a:?} and {b:?} disagree about {c:?}"
        );
    }

    // Transitivity, in the two forms `sort_by` relies on.
    let (ab, bc, ac) = (cmp(&a, &b), cmp(&b, &c), cmp(&a, &c));
    if ab == bc && ab != Ordering::Equal {
        assert_eq!(
            ac, ab,
            "not transitive: {a:?} {ab:?} {b:?} {bc:?} {c:?} but a..c is {ac:?}"
        );
    }
    if ab == Ordering::Equal && bc == Ordering::Equal {
        assert_eq!(
            ac,
            Ordering::Equal,
            "equality is not transitive across {a:?} {b:?} {c:?}"
        );
    }

    // Sorting must therefore be safe and must actually produce a sorted run.
    let mut all = vec![a, b, c];
    all.sort_by(cmp);
    assert!(
        all.windows(2)
            .all(|w| cmp(&w[0], &w[1]) != Ordering::Greater),
        "sort_by left the entries out of order: {all:?}"
    );
});
