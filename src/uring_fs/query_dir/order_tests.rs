use super::*;

/// Sort `(name, is_dir)` pairs the way [`Order::ByPathBytes`] does and return the resulting keys, so a case reads
/// as the paths it stands for.
fn keys(entries: &[(&str, bool)]) -> Vec<String> {
    let mut v = entries.to_vec();
    v.sort_by(|a, b| cmp_path_bytes(a.0.as_bytes(), a.1, b.0.as_bytes(), b.1));
    v.into_iter()
        .map(|(n, d)| if d { format!("{n}/") } else { n.to_string() })
        .collect()
}

/// The inversion the whole comparator exists for. `/` is `0x2F`, above both `-` (`0x2D`) and `.` (`0x2E`), so the
/// directory `a` belongs *between* `a.txt` and `aa.txt` - not first, where its bare name sorts. Getting this wrong
/// reorders a walk against true path order, which is how keys go missing at a page boundary.
#[test]
fn a_directory_sorts_where_its_trailing_separator_puts_it() {
    assert_eq!(
        keys(&[("a", true), ("a-1.txt", false), ("a.txt", false), ("aa.txt", false)]),
        ["a-1.txt", "a.txt", "a/", "aa.txt"],
    );

    // What a bare-name sort would have produced, for contrast: the directory leads, so a depth-first walk would
    // emit everything under `a/` before `a-1.txt`.
    let mut bare = ["a", "a-1.txt", "a.txt", "aa.txt"];
    bare.sort_unstable();
    assert_eq!(bare, ["a", "a-1.txt", "a.txt", "aa.txt"]);
}

/// Several entries sharing a prefix, each differing only in what follows it - `.` vs `/` vs end-of-name - so every
/// branch of the synthesized trailing byte is exercised against a real neighbour.
#[test]
fn separator_ranks_against_dot_at_every_position() {
    assert_eq!(keys(&[("b", true), ("b..", false), ("b.", true)]), ["b..", "b./", "b/"],);
}

/// A file and a directory of the same name cannot coexist in one directory, but the comparator is still asked to
/// order them (a walk merging sources, a caller sorting a synthetic list). The file sorts first: its key is a
/// strict prefix of the directory's.
#[test]
fn same_name_file_precedes_directory() {
    assert_eq!(keys(&[("a", true), ("a", false)]), ["a", "a/"]);
}

/// A name that is a prefix of another orders by length once the shared bytes run out, with the separator counted as
/// part of the key.
#[test]
fn prefix_names_order_by_the_synthesized_key_length() {
    assert_eq!(keys(&[("ab", false), ("a", false), ("a", true)]), ["a", "a/", "ab"],);
    // `a/` vs `ab`: `/` (0x2F) < `b` (0x62), so the directory leads.
    assert_eq!(cmp_path_bytes(b"a", true, b"ab", false), std::cmp::Ordering::Less,);
}

/// Identical inputs compare equal, so the sort is well-formed (a comparator that never reports `Equal` can violate
/// sort invariants).
#[test]
fn identical_entries_compare_equal() {
    assert_eq!(cmp_path_bytes(b"x", false, b"x", false), std::cmp::Ordering::Equal,);
    assert_eq!(cmp_path_bytes(b"x", true, b"x", true), std::cmp::Ordering::Equal,);
}

/// The ordering agrees with comparing fully-built keys, on a spread of names chosen around the separator's
/// neighbourhood in byte space.
#[test]
fn matches_comparing_materialized_keys() {
    let names = ["a", "a-", "a.", "a/", "a0", "aa", "", "-", ".", "z", "a.b", "a-b"];
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
