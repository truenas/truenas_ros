//! `configparser`-compatible serialization.
//!
//! A faithful port of CPython `configparser.write` / `_write_section`
//! (`Lib/configparser.py:936-973`): the `DEFAULT` section is emitted first (only
//! if non-empty), each section is `[name]` followed by its options in insertion
//! order and a trailing blank line, embedded newlines in a value are re-indented
//! with a tab, and (with `allow_no_value`) a valueless key is written bare.

use super::{ConfigFile, Ordered, DEFAULT_SECTION};

/// Serialize `cfg` exactly as `configparser.write` would. `space_around`
/// controls whether the `=` delimiter is padded (`key = value` vs `key=value`).
pub(super) fn to_string(cfg: &ConfigFile, space_around: bool) -> String {
    let delim = if space_around { " = " } else { "=" };
    let mut out = String::new();
    if !cfg.defaults.is_empty() {
        write_section(
            &mut out,
            DEFAULT_SECTION,
            &cfg.defaults,
            delim,
            cfg.allow_no_value,
        );
    }
    for (name, opts) in cfg.sections.iter() {
        write_section(&mut out, name, opts, delim, cfg.allow_no_value);
    }
    out
}

fn write_section(
    out: &mut String,
    name: &str,
    opts: &Ordered<Option<String>>,
    delim: &str,
    allow_no_value: bool,
) {
    out.push('[');
    out.push_str(name);
    out.push_str("]\n");
    for (key, value) in opts.iter() {
        // Matches `if value is not None or not self._allow_no_value`: a `None`
        // value is written bare only when `allow_no_value` is set, otherwise it
        // serializes via `str(None)` (`"None"`), exactly as CPython does.
        if value.is_some() || !allow_no_value {
            let rendered = match value {
                Some(v) => v.replace('\n', "\n\t"),
                None => String::from("None"),
            };
            out.push_str(key);
            out.push_str(delim);
            out.push_str(&rendered);
        } else {
            out.push_str(key);
        }
        out.push('\n');
    }
    out.push('\n');
}
