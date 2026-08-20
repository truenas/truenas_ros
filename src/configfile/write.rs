//! `configparser`-compatible serialization.
//!
//! A faithful port of CPython `configparser.write` / `_write_section`
//! (`Lib/configparser.py:936-973`): the `DEFAULT` section is emitted first (only
//! if non-empty), each section is `[name]` followed by its options in insertion
//! order and a trailing blank line, embedded newlines in a value are re-indented
//! with a tab, and (with `allow_no_value`) a valueless key is written bare.

use super::{ConfigFile, DEFAULT_SECTION, Ordered};

/// The serialization buffer. For a scrubbed configuration each growth
/// reallocates through a burn of the old allocation, so no plaintext
/// prefix of the output is left behind in freed heap; otherwise it grows
/// as a plain `String`.
struct Out {
    s: String,
    scrub: bool,
}

impl Out {
    fn push_str(&mut self, part: &str) {
        if self.scrub {
            let need = self.s.len() + part.len();
            if need > self.s.capacity() {
                // Amortized doubling, like `String`'s own growth.
                let mut grown =
                    String::with_capacity(need.max(self.s.capacity() * 2));
                grown.push_str(&self.s);
                super::scrub_string(&mut self.s);
                self.s = grown;
            }
        }
        self.s.push_str(part);
    }
}

/// Serialize `cfg` exactly as `configparser.write` would. `space_around`
/// controls whether the `=` delimiter is padded (`key = value` vs `key=value`).
pub(super) fn to_string(cfg: &ConfigFile, space_around: bool) -> String {
    let delim = if space_around { " = " } else { "=" };
    let mut out = Out {
        s: String::new(),
        scrub: cfg.scrub,
    };
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
    out.s
}

fn write_section(
    out: &mut Out,
    name: &str,
    opts: &Ordered<Option<String>>,
    delim: &str,
    allow_no_value: bool,
) {
    out.push_str("[");
    out.push_str(name);
    out.push_str("]\n");
    for (key, value) in opts.iter() {
        // Matches `if value is not None or not self._allow_no_value`: a `None`
        // value is written bare only when `allow_no_value` is set, otherwise it
        // serializes via `str(None)` (`"None"`), exactly as CPython does.
        if value.is_some() || !allow_no_value {
            out.push_str(key);
            out.push_str(delim);
            match value {
                // The re-indent temporary is a full copy of the value, so
                // it is only made when a newline calls for one, and a
                // scrubbed configuration burns it.
                Some(v) if v.contains('\n') => {
                    let mut rendered = v.replace('\n', "\n\t");
                    out.push_str(&rendered);
                    if out.scrub {
                        super::scrub_string(&mut rendered);
                    }
                }
                Some(v) => out.push_str(v),
                None => out.push_str("None"),
            }
        } else {
            out.push_str(key);
        }
        out.push_str("\n");
    }
    out.push_str("\n");
}
