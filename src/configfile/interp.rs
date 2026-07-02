//! `configparser`-compatible basic (`%(name)s`) interpolation.
//!
//! A port of `BasicInterpolation` (`Lib/configparser.py:396-465`): `%%` is a
//! literal `%`, `%(name)s` expands to another option's value (looked up in the
//! merged DEFAULT+section map and interpolated recursively up to
//! [`MAX_INTERPOLATION_DEPTH`](super::MAX_INTERPOLATION_DEPTH)), and any other
//! `%` sequence is a syntax error.

use super::{optionxform, Ordered, MAX_INTERPOLATION_DEPTH};
use crate::error::{Error, Result};

/// Interpolate `value` for `option`, resolving `%(name)s` against `map` (the
/// merged section-over-DEFAULT raw values). Mirrors `before_get`.
pub(super) fn before_get(
    option: &str,
    value: &str,
    map: &Ordered<Option<String>>,
) -> Result<String> {
    let mut out = String::new();
    interpolate(option, value, map, 1, &mut out)?;
    Ok(out)
}

fn interpolate(
    option: &str,
    rest: &str,
    map: &Ordered<Option<String>>,
    depth: u32,
    out: &mut String,
) -> Result<()> {
    if depth > MAX_INTERPOLATION_DEPTH {
        return Err(Error::Parse(format!(
            "interpolation too deeply recursive for {option:?}"
        )));
    }
    let mut rest = rest;
    while !rest.is_empty() {
        let p = match rest.find('%') {
            None => {
                out.push_str(rest);
                return Ok(());
            }
            Some(p) => p,
        };
        out.push_str(&rest[..p]);
        rest = &rest[p..]; // now starts with '%'
        match rest.as_bytes().get(1).copied() {
            Some(b'%') => {
                out.push('%');
                rest = &rest[2..];
            }
            Some(b'(') => {
                let (name, end) = key_ref(rest).ok_or_else(|| {
                    Error::Parse(format!(
                        "bad interpolation variable reference: {rest:?}"
                    ))
                })?;
                let var = optionxform(name);
                rest = &rest[end..];
                let value = match map.get(&var) {
                    Some(Some(s)) => s.clone(),
                    _ => {
                        return Err(Error::Parse(format!(
                            "interpolation references missing option {var:?}"
                        )))
                    }
                };
                if value.contains('%') {
                    interpolate(option, &value, map, depth + 1, out)?;
                } else {
                    out.push_str(&value);
                }
            }
            _ => {
                return Err(Error::Parse(format!(
                    "'%' must be followed by '%' or '(' in {rest:?}"
                )))
            }
        }
    }
    Ok(())
}

/// Validate that `value` is safe to store under basic interpolation, matching
/// `BasicInterpolation.before_set`: after removing escaped `%%` and every valid
/// `%(name)s`, no stray `%` may remain.
pub(super) fn validate_set(value: &str) -> Result<()> {
    let stripped = value.replace("%%", "");
    let mut rest = stripped.as_str();
    while let Some(p) = rest.find('%') {
        let at = &rest[p..];
        if at.as_bytes().get(1) == Some(&b'(') {
            if let Some((_, end)) = key_ref(at) {
                rest = &at[end..];
                continue;
            }
        }
        return Err(Error::Validation(format!(
            "invalid interpolation syntax in {value:?}"
        )));
    }
    Ok(())
}

/// Parse a `%(name)s` reference at the start of `s` (which begins with `%(`),
/// returning `(name, end_byte_index)`, or `None` if malformed. Mirrors
/// `_KEYCRE = %\(([^)]+)\)s`.
fn key_ref(s: &str) -> Option<(&str, usize)> {
    let bytes = s.as_bytes();
    let close = s[2..].find(')')? + 2;
    if close == 2 {
        return None; // empty name (`[^)]+` requires at least one char)
    }
    if bytes.get(close) != Some(&b')') || bytes.get(close + 1) != Some(&b's') {
        return None;
    }
    Some((&s[2..close], close + 2))
}
