//! The `configparser`-compatible read loop.
//!
//! A faithful port of CPython `configparser._read`
//! (`Lib/configparser.py:1056-1168`): the same handling of full-line comments,
//! multi-line continuation values (indentation measured on the *raw* line while
//! section/option matching runs on the stripped line), DEFAULT-section merging,
//! and strict duplicate detection. The result is accumulated into working
//! structures and only merged into `cfg` once the whole document parses, so a
//! parse error leaves the target untouched.

use super::{optionxform, ConfigFile, Ordered, DEFAULT_SECTION};
use crate::error::{Error, Result};
use std::collections::HashSet;

/// A value accumulator during parsing: `None` for a valueless key, otherwise the
/// list of (stripped) lines that are joined at the end.
type Acc = Option<Vec<String>>;

/// Whitespace as CPython counts it, which is not what Rust counts.
///
/// `str.strip()`, `str.isspace()` and `re`'s `\s` all go through
/// `Py_UNICODE_ISSPACE`, which includes U+001C..U+001F — the file, group,
/// record and unit separators. Unicode's `White_Space` property, which
/// `char::is_whitespace` implements, does not. Compared across every code
/// point those four are the *only* disagreement in either direction, so
/// widening by exactly them makes the two definitions identical.
///
/// It matters because every strip in the read loop is a strip `configparser`
/// also performs: a key or value fenced by one of these bytes otherwise parses
/// to a different string here than there, and `get` and `write_string` both
/// inherit the difference.
fn is_py_space(c: char) -> bool {
    c.is_whitespace() || matches!(c, '\u{1c}'..='\u{1f}')
}

/// `str.strip()`.
fn py_strip(s: &str) -> &str {
    s.trim_matches(is_py_space)
}

/// `str.rstrip()`.
fn py_rstrip(s: &str) -> &str {
    s.trim_end_matches(is_py_space)
}

/// Why this loop would not read `key` back as the name it was given, or
/// `None` if it round-trips. Each arm names its own reason.
///
/// Keys are written verbatim — by [`super::write`], and by CPython's
/// `_write_section` (`Lib/configparser.py:961`), which re-indents a newline
/// in the *value* and does nothing to the key — so a name carrying this
/// loop's syntax parses back as something else.
///
/// Screened at [`super::ConfigFile::set`] rather than at write time, since
/// that is the only way in: keys from [`read`] are safe by construction,
/// because this loop splits on lines, splits at the first delimiter, and
/// strips.
///
/// The `[` rule is blunter than [`section_header`], which also wants a
/// closing `]` past the first column, so `[]x` is refused though it would
/// survive. A second copy of the header rule would be free to drift from the
/// one that decides.
pub(super) fn key_fault(key: &str) -> Option<&'static str> {
    if key.is_empty() {
        Some("is empty")
    } else if key.contains(['\n', '\r']) {
        Some("contains a line break")
    } else if key.contains(['=', ':']) {
        Some("contains a key/value delimiter")
    } else if key.starts_with(is_py_space) || key.ends_with(is_py_space) {
        Some("is surrounded by whitespace")
    } else if key.starts_with('[') {
        Some("would be read back as a section header")
    } else if key.starts_with('#') || key.starts_with(';') {
        Some("would be read back as a comment")
    } else {
        None
    }
}

/// Why `[name]` would not be read back as this section, or `None` if it
/// round-trips. Companion to [`key_fault`].
///
/// Less is forbidden than for a key: a header is delimited on both sides and
/// [`section_header`] takes the *last* `]`, so a name containing, ending in,
/// or padded around one survives. Only a line break, which closes the header
/// early and leaves the rest to be read as its own section, and the empty
/// name, which writes `[]` and is not a header at all.
pub(super) fn section_fault(name: &str) -> Option<&'static str> {
    if name.is_empty() {
        Some("is empty")
    } else if name.contains(['\n', '\r']) {
        Some("contains a line break")
    } else {
        None
    }
}

/// The current section as a duplicate-detection key.
///
/// Stands in for the section's name, which is what `configparser` keys
/// `elements_added` by. The substitution is sound because the mapping is
/// injective within one read: section indices are only ever appended, a
/// repeated header is rejected before it gets here, and a section literally
/// named DEFAULT is routed to [`Cur::Default`] rather than given an index.
/// Being `Copy`, it costs no allocation per option line.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum SectionId {
    Default,
    At(usize),
}

impl SectionId {
    fn of(cur: &Cur) -> SectionId {
        match cur {
            // Unreachable: an option with no open section is rejected above.
            Cur::None | Cur::Default => SectionId::Default,
            Cur::Section(i) => SectionId::At(*i),
        }
    }
}

/// Which section subsequent option/continuation lines belong to.
enum Cur {
    None,
    Default,
    Section(usize),
}

/// Parse `text` and merge it into `cfg`. `source` names the input for error
/// messages.
pub(super) fn read(
    cfg: &mut ConfigFile,
    source: &str,
    text: &str,
) -> Result<()> {
    let allow_no_value = cfg.allow_no_value;
    // The working state lives in a guard: on every exit — the error returns
    // included — a scrubbed configuration's accumulated keys and values are
    // burned rather than dropped.
    let mut work = Work {
        default: Ordered::new(),
        sections: Ordered::new(),
        dups: HashSet::new(),
        added_sections: HashSet::new(),
        scrub: cfg.scrub,
    };

    let mut cur = Cur::None;
    let mut optname: Option<String> = None;
    let mut indent_level: usize = 0;
    // Non-fatal option-syntax errors are collected and reported together at the
    // end (like `configparser`'s accumulated `ParsingError`).
    let mut parse_errors: Vec<String> = Vec::new();

    // `split_inclusive('\n')` matches Python's line iteration exactly: one line
    // per '\n', with no spurious trailing empty line when the text ends in '\n'.
    for (idx, line) in text.split_inclusive('\n').enumerate() {
        let lineno = idx + 1;
        let trimmed = py_strip(line);
        let is_full_comment =
            trimmed.starts_with('#') || trimmed.starts_with(';');
        let clean = if is_full_comment { "" } else { trimmed };

        if clean.is_empty() {
            // A truly blank line (not a comment) extends an open multi-line
            // value with an empty line; the join at the end rstrips trailing
            // blanks away.
            if !is_full_comment {
                if let (Some(opts), Some(name)) = (
                    cur_opts(&mut work.default, &mut work.sections, &cur),
                    optname.as_deref(),
                ) {
                    if let Some(Some(lines)) = opts.get_mut(name) {
                        lines.push(String::new());
                    }
                }
            }
            continue;
        }

        // Continuation depth is measured on the raw (un-stripped) line.
        let cur_indent = line.chars().take_while(|c| is_py_space(*c)).count();

        let is_continuation = !matches!(cur, Cur::None)
            && optname.is_some()
            && cur_indent > indent_level;
        if is_continuation {
            let name = optname.as_deref().unwrap();
            let opts =
                cur_opts(&mut work.default, &mut work.sections, &cur).unwrap();
            match opts.get_mut(name) {
                Some(Some(lines)) => lines.push(clean.to_string()),
                _ => {
                    return Err(Error::Parse(format!(
                        "{source}:{lineno}: continuation line for a key with \
                         no value"
                    )))
                }
            }
            continue;
        }

        if let Some(header) = section_header(clean) {
            if header == DEFAULT_SECTION {
                cur = Cur::Default;
            } else if work.added_sections.contains(header) {
                // The name is withheld from a scrubbed configuration's
                // error like the duplicate-option key below: in a
                // credentials file it is an identifier that must not
                // reach a log.
                return Err(Error::Parse(if cfg.scrub {
                    format!("{source}:{lineno}: duplicate section")
                } else {
                    format!("{source}:{lineno}: duplicate section {header:?}")
                }));
            } else {
                work.added_sections.insert(header.to_string());
                work.sections.insert(header, Ordered::new());
                cur = Cur::Section(work.sections.position(header).unwrap());
            }
            optname = None;
            continue;
        }

        // An option (or garbage) with no open section is a hard error.
        if matches!(cur, Cur::None) {
            return Err(Error::Parse(format!(
                "{source}:{lineno}: missing section header"
            )));
        }

        indent_level = cur_indent;
        let (raw_key, value) = match parse_option(clean, allow_no_value) {
            Some(kv) => kv,
            None => {
                parse_errors.push(format!("{source}:{lineno}"));
                continue;
            }
        };
        let key = optionxform(raw_key);
        if key.is_empty() {
            parse_errors.push(format!("{source}:{lineno}"));
            continue;
        }

        let mut dup_key = (SectionId::of(&cur), key.clone());
        if work.dups.contains(&dup_key) {
            // The key is withheld from a scrubbed configuration's error: in
            // a credentials file it is an identifier that must not reach a
            // log. Both copies of it — the line's and the lookup tuple's —
            // are burned.
            let msg = if cfg.scrub {
                format!("{source}:{lineno}: duplicate option")
            } else {
                format!("{source}:{lineno}: duplicate option {key:?}")
            };
            let mut key = key;
            if cfg.scrub {
                super::scrub_string(&mut key);
                super::scrub_string(&mut dup_key.1);
            }
            return Err(Error::Parse(msg));
        }
        work.dups.insert(dup_key);

        let acc: Acc = value.map(|v| vec![v.to_string()]);
        let opts =
            cur_opts(&mut work.default, &mut work.sections, &cur).unwrap();
        opts.insert(&key, acc);
        optname = Some(key);
    }

    if !parse_errors.is_empty() {
        return Err(Error::Parse(format!(
            "source contains parsing errors at {}",
            parse_errors.join(", ")
        )));
    }

    merge(cfg, &mut work);
    Ok(())
}

/// The working-section map for the current section, if any.
fn cur_opts<'a>(
    work_default: &'a mut Ordered<Acc>,
    work_sections: &'a mut Ordered<Ordered<Acc>>,
    cur: &Cur,
) -> Option<&'a mut Ordered<Acc>> {
    match cur {
        Cur::None => None,
        Cur::Default => Some(work_default),
        Cur::Section(i) => Some(&mut work_sections.entries[*i].1),
    }
}

/// Match a section header `[name]` against a stripped line, returning `name`.
///
/// Mirrors `configparser`'s `SECTCRE = \[(?P<header>.+)\]` matched with
/// `.match()`: the line must start with `[`, the greedy `.+` runs to the *last*
/// `]`, and there must be at least one character between the brackets. Anything
/// after that last `]` is ignored (the match is not anchored at end).
fn section_header(clean: &str) -> Option<&str> {
    if !clean.starts_with('[') {
        return None;
    }
    let close = clean.rfind(']')?;
    if close <= 1 {
        return None; // empty header (`[]`) is not a section
    }
    Some(&clean[1..close])
}

/// Split a stripped option line into `(key, value)`.
///
/// Mirrors `configparser`'s `OPTCRE`/`OPTCRE_NV`: the first `=` or `:` splits
/// key from value, whitespace around the delimiter is dropped, and the value is
/// stripped. With `allow_no_value`, a line with no delimiter is a valueless key;
/// otherwise it is a syntax error (returned as `None`).
fn parse_option(
    clean: &str,
    allow_no_value: bool,
) -> Option<(&str, Option<&str>)> {
    match clean.find(['=', ':']) {
        Some(p) => {
            let key = py_rstrip(&clean[..p]);
            let value = py_strip(&clean[p + 1..]);
            Some((key, Some(value)))
        }
        None => {
            if allow_no_value {
                Some((py_rstrip(clean), None))
            } else {
                None
            }
        }
    }
}

/// The parse's working state. A guard: when a scrubbed configuration's
/// read exits — the error paths included — whatever accumulated here is
/// burned rather than dropped. [`merge`] empties it on success, so the
/// burn then covers only what merging left behind.
struct Work {
    default: Ordered<Acc>,
    sections: Ordered<Ordered<Acc>>,
    /// Per-read duplicate detection (`configparser`'s `elements_added`,
    /// fresh each read so a conflict is within one document); holds a
    /// clone of every option key.
    dups: HashSet<(SectionId, String)>,
    /// Its section-name half: a clone of every section name, held here so
    /// a scrubbed read burns them on drop.
    added_sections: HashSet<String>,
    scrub: bool,
}

impl Drop for Work {
    fn drop(&mut self) {
        if !self.scrub {
            return;
        }
        scrub_acc(&mut self.default);
        self.sections.scrub_with(scrub_acc);
        for (_, mut key) in self.dups.drain() {
            super::scrub_string(&mut key);
        }
        for mut name in self.added_sections.drain() {
            super::scrub_string(&mut name);
        }
    }
}

/// Burn one working section: keys (the index's copies included) and every
/// accumulated value line.
fn scrub_acc(opts: &mut Ordered<Acc>) {
    opts.scrub_with(|acc| {
        if let Some(lines) = acc {
            for line in lines {
                super::scrub_string(line);
            }
        }
    });
}

/// Join accumulated value lines with `\n` and rstrip, matching
/// `configparser`'s `'\n'.join(val).rstrip()`. Under scrub the consumed
/// lines are burned after the join.
fn join(acc: Acc, scrub: bool) -> Option<String> {
    acc.map(|mut lines| {
        let mut s = lines.join("\n");
        s.truncate(py_rstrip(&s).len());
        if scrub {
            for line in &mut lines {
                super::scrub_string(line);
            }
        }
        s
    })
}

/// Merge the working structures into `cfg`, joining multi-line values.
///
/// Existing `cfg` sections/keys keep their position and are overridden in
/// place; new ones are appended in first-appearance order. Under scrub,
/// every working copy consumed here — accumulator lines, key copies, a
/// displaced earlier value — is burned as it is released.
fn merge(cfg: &mut ConfigFile, work: &mut Work) {
    let scrub = work.scrub;
    let mut default = std::mem::take(&mut work.default);
    for (mut key, _) in default.index.drain() {
        if scrub {
            super::scrub_string(&mut key);
        }
    }
    for (mut key, acc) in default.entries {
        super::scrub_displaced(
            scrub,
            cfg.defaults.insert(&key, join(acc, scrub)),
        );
        if scrub {
            super::scrub_string(&mut key);
        }
    }
    let mut sections = std::mem::take(&mut work.sections);
    for (mut key, _) in sections.index.drain() {
        if scrub {
            super::scrub_string(&mut key);
        }
    }
    for (mut name, mut opts) in sections.entries {
        if !cfg.sections.contains(&name) {
            cfg.sections.insert(&name, Ordered::new());
        }
        let target = cfg.sections.get_mut(&name).unwrap();
        for (mut key, _) in opts.index.drain() {
            if scrub {
                super::scrub_string(&mut key);
            }
        }
        for (mut key, acc) in opts.entries {
            super::scrub_displaced(
                scrub,
                target.insert(&key, join(acc, scrub)),
            );
            if scrub {
                super::scrub_string(&mut key);
            }
        }
        if scrub {
            super::scrub_string(&mut name);
        }
    }
}
