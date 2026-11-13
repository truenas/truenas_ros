#![no_main]

//! Fuzz the configparser-compatible INI codec: parse, serialize, reparse.
//!
//! The grammar is already tested against CPython `configparser` in `test/configparser_compat.rs`, so this target chases
//! the two things that oracle cannot reach.
//!
//! 1. **Serialization is a fixed point.** Whatever `read_str` accepts must render as a document that reparses to the
//!    same configuration and renders identically the second time. A key or value that reparses differently, such as one
//!    carrying a newline, a delimiter or a comment marker, makes a file read and written back mean something else.
//! 2. **Interpolation terminates.** `get` and `items` expand `%(name)s` recursively under a depth cap and a 1 MiB
//!    output cap, and both caps must hold for self-referential documents.
//!
//! Both delimiter modes run, since `to_string_with(false)` emits `key=value`, the shape most likely to reparse
//! ambiguously.

use libfuzzer_sys::fuzz_target;
use truenas_ros::configfile::ConfigFile;

fn fixed_point(text: &str, spaced: bool) {
    let mut first = ConfigFile::new();
    if first.read_str(text).is_err() {
        return;
    }
    let once = first.to_string_with(spaced);

    let mut second = ConfigFile::new();
    second.read_str(&once).expect("a serialized configuration must reparse");
    let twice = second.to_string_with(spaced);
    assert_eq!(once, twice, "serialization is not a fixed point");

    // Structure, not just bytes: the same sections, each with the same options, in the same order.
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
            // Drive interpolation. A cycle or a blow-up is an `Err`, which is the guard working; a hang or a panic is
            // not.
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
