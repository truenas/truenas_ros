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
    let mut work_default: Ordered<Acc> = Ordered::new();
    let mut work_sections: Ordered<Ordered<Acc>> = Ordered::new();

    let mut cur = Cur::None;
    let mut optname: Option<String> = None;
    let mut indent_level: usize = 0;
    // Fresh per read, so a section/option only conflicts within this document —
    // matching `configparser`'s per-`_read` `elements_added`.
    let mut added_sections: HashSet<String> = HashSet::new();
    let mut added_options: HashSet<(String, String)> = HashSet::new();
    // Non-fatal option-syntax errors are collected and reported together at the
    // end (like `configparser`'s accumulated `ParsingError`).
    let mut parse_errors: Vec<String> = Vec::new();

    // `split_inclusive('\n')` matches Python's line iteration exactly: one line
    // per '\n', with no spurious trailing empty line when the text ends in '\n'.
    for (idx, line) in text.split_inclusive('\n').enumerate() {
        let lineno = idx + 1;
        let trimmed = line.trim();
        let is_full_comment =
            trimmed.starts_with('#') || trimmed.starts_with(';');
        let clean = if is_full_comment { "" } else { trimmed };

        if clean.is_empty() {
            // A truly blank line (not a comment) extends an open multi-line
            // value with an empty line; the join at the end rstrips trailing
            // blanks away.
            if !is_full_comment {
                if let (Some(opts), Some(name)) = (
                    cur_opts(&mut work_default, &mut work_sections, &cur),
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
        let cur_indent = line.chars().take_while(|c| c.is_whitespace()).count();

        let is_continuation = !matches!(cur, Cur::None)
            && optname.is_some()
            && cur_indent > indent_level;
        if is_continuation {
            let name = optname.clone().unwrap();
            let opts =
                cur_opts(&mut work_default, &mut work_sections, &cur).unwrap();
            match opts.get_mut(&name) {
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
            } else if added_sections.contains(header) {
                return Err(Error::Parse(format!(
                    "{source}:{lineno}: duplicate section {header:?}"
                )));
            } else {
                added_sections.insert(header.to_string());
                work_sections.insert(header, Ordered::new());
                cur = Cur::Section(work_sections.position(header).unwrap());
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

        let sect_name = current_section_name(&cur, &work_sections);
        let dup_key = (sect_name, key.clone());
        if added_options.contains(&dup_key) {
            return Err(Error::Parse(format!(
                "{source}:{lineno}: duplicate option {key:?}"
            )));
        }
        added_options.insert(dup_key);

        let acc: Acc = value.map(|v| vec![v.to_string()]);
        let opts =
            cur_opts(&mut work_default, &mut work_sections, &cur).unwrap();
        opts.insert(&key, acc);
        optname = Some(key);
    }

    if !parse_errors.is_empty() {
        return Err(Error::Parse(format!(
            "source contains parsing errors at {}",
            parse_errors.join(", ")
        )));
    }

    merge(cfg, work_default, work_sections);
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

/// The name of the current section (used to key duplicate-option detection).
fn current_section_name(
    cur: &Cur,
    work_sections: &Ordered<Ordered<Acc>>,
) -> String {
    match cur {
        Cur::None => String::new(),
        Cur::Default => DEFAULT_SECTION.to_string(),
        Cur::Section(i) => work_sections.entries[*i].0.clone(),
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
            let key = clean[..p].trim_end();
            let value = clean[p + 1..].trim();
            Some((key, Some(value)))
        }
        None => {
            if allow_no_value {
                Some((clean.trim_end(), None))
            } else {
                None
            }
        }
    }
}

/// Join accumulated value lines with `\n` and rstrip, matching
/// `configparser`'s `'\n'.join(val).rstrip()`.
fn join(acc: Acc) -> Option<String> {
    acc.map(|lines| {
        let mut s = lines.join("\n");
        s.truncate(s.trim_end().len());
        s
    })
}

/// Merge the working structures into `cfg`, joining multi-line values.
///
/// Existing `cfg` sections/keys keep their position and are overridden in place;
/// new ones are appended in first-appearance order.
fn merge(
    cfg: &mut ConfigFile,
    work_default: Ordered<Acc>,
    work_sections: Ordered<Ordered<Acc>>,
) {
    for (key, acc) in work_default.entries {
        cfg.defaults.insert(&key, join(acc));
    }
    for (name, opts) in work_sections.entries {
        if !cfg.sections.contains(&name) {
            cfg.sections.insert(&name, Ordered::new());
        }
        let target = cfg.sections.get_mut(&name).unwrap();
        for (key, acc) in opts.entries {
            target.insert(&key, join(acc));
        }
    }
}
