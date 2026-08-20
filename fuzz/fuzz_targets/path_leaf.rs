#![no_main]

//! Fuzz `Leaf::new` — the single-path-component check.
//!
//! This is a documented security boundary, and it carries no unit tests. The
//! `*at` opcodes the fs reactor issues honour no `RESOLVE_*` flags, so a name
//! that slips a `/` or a `..` past this check escapes its anchor directory
//! entirely — the containment the whole API rests on is this one function.
//!
//! Two properties. First, nothing traversal-shaped is ever accepted. Second,
//! `to_cstring`'s `expect("validated: no interior NUL")` is genuinely
//! unreachable: `Leaf::new` is what discharges that precondition, so any name
//! it accepts must convert without panicking.

use libfuzzer_sys::fuzz_target;
use truenas_ros::uring_fs::{Leaf, fuzz::leaf_to_cstring};

fuzz_target!(|data: &[u8]| {
    let Ok(leaf) = Leaf::new(data) else {
        return;
    };

    assert!(!data.is_empty(), "accepted an empty component");
    assert_ne!(data, b".", "accepted `.`");
    assert_ne!(data, b"..", "accepted `..`");
    assert!(
        !data.contains(&b'/'),
        "accepted a name containing a separator: {data:?}"
    );
    assert!(
        !data.contains(&0),
        "accepted a name containing NUL: {data:?}"
    );

    // The `expect` inside `to_cstring` is discharged by the check above; if
    // this panics, the two disagree about what "validated" means.
    let c = leaf_to_cstring(leaf);
    assert_eq!(
        c.as_bytes(),
        data,
        "the C string does not carry the validated name"
    );

    // Validation is idempotent — a name that passed once still passes when it
    // comes back around as bytes.
    assert!(
        Leaf::new(c.as_bytes()).is_ok(),
        "a validated name failed revalidation"
    );
});
