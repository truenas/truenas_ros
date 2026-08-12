#![no_main]

//! Fuzz the configparser-compatible INI codec: parse, serialize, reparse.
//!
//! The grammar is already differentially tested against real CPython
//! `configparser` (`test/configparser_compat.rs`, including a random-document
//! generator), so this target is not chasing grammar coverage. It chases the
//! two things that oracle cannot reach:
//!
//! 1. **Serialization is a fixed point.** Whatever `read_str` accepts,
//!    `write_string` must render as a document that reparses to the same
//!    configuration and renders identically the second time. A value or key
//!    that survives parsing but re-parses differently — one carrying a newline,
//!    a delimiter, or a comment marker — is a config-rewriting bug: read a
//!    file, write it back, and it now means something else.
//! 2. **Interpolation terminates.** `get`/`items` run the recursive `%(name)s`
//!    expansion, which is bounded by a depth cap and a 1 MiB output cap. Both
//!    caps must hold for adversarially self-referential documents.
//!
//! Both delimiter modes are exercised, since `to_string_with(false)` emits
//! `key=value` and is the shape most likely to reparse ambiguously.

use libfuzzer_sys::fuzz_target;
use truenas_ros::configfile::ConfigFile;

/// Parse, serialize, reparse, re-serialize; assert the two renderings agree
/// and the structure survived. Returns early if the document is rejected.
fn fixed_point(text: &str, spaced: bool) {
    let mut first = ConfigFile::new();
    if first.read_str(text).is_err() {
        return; // not a document; nothing to say about it
    }
    let once = first.to_string_with(spaced);

    let mut second = ConfigFile::new();
    second
        .read_str(&once)
        .expect("a serialized configuration must reparse");
    let twice = second.to_string_with(spaced);
    assert_eq!(once, twice, "serialization is not a fixed point");

    // Structure, not just bytes: the same sections, each with the same
    // options, in the same order.
    assert_eq!(
        first.sections(),
        second.sections(),
        "sections changed across a round trip"
    );
    for section in first.sections() {
        assert_eq!(
            first.options(section),
            second.options(section),
            "options of [{section}] changed across a round trip"
        );
        for option in first.options(section).unwrap_or_default() {
            assert_eq!(
                first.get_raw(section, &option),
                second.get_raw(section, &option),
                "raw value of {section}.{option} changed across a round trip"
            );
            // Drive interpolation. A cycle or a blow-up is an `Err`, which is
            // the guard working; a hang or a panic is not.
            let expanded = first.get(section, &option);
            if let Ok(Some(v)) = expanded {
                assert!(
                    v.len() <= 1 << 20,
                    "interpolation exceeded its output cap: {} bytes",
                    v.len()
                );
            }
        }
        // `items` expands every value in the section in one pass.
        let _ = first.items(section);
    }
}

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return; // `read_str` takes &str; non-UTF-8 is the file reader's problem
    };
    fixed_point(text, true);
    fixed_point(text, false);
});
