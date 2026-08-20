//! `configparser`-compatible basic (`%(name)s`) interpolation.
//!
//! A port of `BasicInterpolation` (`Lib/configparser.py:396-465`): `%%` is a
//! literal `%`, `%(name)s` expands to another option's value (looked up in the
//! merged DEFAULT+section map and interpolated recursively up to
//! [`MAX_INTERPOLATION_DEPTH`](super::MAX_INTERPOLATION_DEPTH)), and any other
//! `%` sequence is a syntax error.

use super::{MAX_INTERPOLATION_DEPTH, MergedView, optionxform};
use crate::error::{Error, Result};

/// Cap on the total interpolated output for one value. [`MAX_INTERPOLATION_DEPTH`]
/// bounds nesting depth but not the branching factor: B references per level
/// over D levels expand to B^D bytes (ten options each referencing the prior
/// ten blow ~800 bytes up to 10^1^0), so the depth limit alone does not stop an
/// untrusted config from exhausting memory. Bounding the accumulated output
/// does - 1 MiB is far beyond any real interpolated value.
///
/// CPython caps only the recursion depth, so a document `configparser`
/// resolves can be rejected here.
const MAX_INTERPOLATION_OUTPUT: usize = 1 << 20;

/// Interpolate `value` for `option`, resolving `%(name)s` against `map` (the
/// merged section-over-DEFAULT raw values). Mirrors `before_get`.
///
/// Under `scrub`, error messages withhold the value fragment and the option
/// names they would otherwise quote: an interpolation error from a secrets
/// configuration may reach a log, and the fragment is the secret.
pub(super) fn before_get(
    option: &str,
    value: &str,
    map: &MergedView<'_>,
    scrub: bool,
) -> Result<String> {
    let mut out = String::new();
    interpolate(option, value, map, 1, &mut out, scrub)?;
    Ok(out)
}

fn interpolate(
    option: &str,
    rest: &str,
    map: &MergedView<'_>,
    depth: u32,
    out: &mut String,
    scrub: bool,
) -> Result<()> {
    if depth > MAX_INTERPOLATION_DEPTH {
        return Err(Error::Parse(if scrub {
            "interpolation too deeply recursive".into()
        } else {
            format!("interpolation too deeply recursive for {option:?}")
        }));
    }
    let mut rest = rest;
    while !rest.is_empty() {
        // `out` is shared across the whole recursion and grows monotonically, so
        // checking here bounds the total expansion regardless of which nested
        // reference is currently being resolved.
        if out.len() > MAX_INTERPOLATION_OUTPUT {
            return Err(Error::Parse(if scrub {
                format!(
                    "interpolation expanded past \
                     {MAX_INTERPOLATION_OUTPUT} bytes"
                )
            } else {
                format!(
                    "interpolation for {option:?} expanded past \
                     {MAX_INTERPOLATION_OUTPUT} bytes"
                )
            }));
        }
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
                    Error::Parse(if scrub {
                        "bad interpolation variable reference".into()
                    } else {
                        format!(
                            "bad interpolation variable reference: {rest:?}"
                        )
                    })
                })?;
                let var = optionxform(name);
                rest = &rest[end..];
                let value = match map.get(&var) {
                    Some(Some(s)) => s,
                    _ => {
                        return Err(Error::Parse(if scrub {
                            "interpolation references a missing option".into()
                        } else {
                            format!(
                                "interpolation references missing option \
                                 {var:?}"
                            )
                        }));
                    }
                };
                if value.contains('%') {
                    interpolate(option, value, map, depth + 1, out, scrub)?;
                } else {
                    out.push_str(value);
                }
            }
            _ => {
                return Err(Error::Parse(if scrub {
                    "'%' must be followed by '%' or '('".into()
                } else {
                    format!("'%' must be followed by '%' or '(' in {rest:?}")
                }));
            }
        }
    }
    Ok(())
}

/// Validate that `value` is safe to store under basic interpolation, matching
/// `BasicInterpolation.before_set`: with escaped `%%` and every valid
/// `%(name)s` removed, no stray `%` may remain. Under `scrub` the rejected
/// value is withheld from the error, as in [`before_get`].
///
/// The `%%` removal is global before the scan (a `%%` inside a reference name
/// is stripped too), so it is done with `replace`, not scanned in place - the
/// left-to-right equivalent disagrees with `configparser` on inputs like
/// `%(%%)s`. `replace` copies `value`; under `scrub` that copy holds the
/// secret, so it is burned before returning rather than freed in the clear.
pub(super) fn validate_set(value: &str, scrub: bool) -> Result<()> {
    let mut stripped = value.replace("%%", "");
    let outcome = {
        let mut rest = stripped.as_str();
        loop {
            let Some(p) = rest.find('%') else {
                break Ok(());
            };
            let at = &rest[p..];
            if at.as_bytes().get(1) == Some(&b'(')
                && let Some((_, end)) = key_ref(at)
            {
                rest = &at[end..];
                continue;
            }
            break Err(Error::Validation(if scrub {
                "invalid interpolation syntax".into()
            } else {
                format!("invalid interpolation syntax in {value:?}")
            }));
        }
    };
    if scrub {
        super::scrub_string(&mut stripped);
    }
    outcome
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

#[cfg(test)]
mod tests {
    use super::*;

    // The stored value must, after escaped `%%` and every `%(name)s`, hold no
    // stray `%`. Each `Some` accepts (returns Ok), each None-shaped input
    // rejects; `%%` neighbouring a reference must not change the verdict.
    #[test]
    fn validate_set_accepts_and_rejects() {
        for ok in [
            "",
            "no percents",
            "%%",
            "100%% sure",
            "%(name)s",
            "%(a)s and %(b)s",
            "%%%(name)s", // an escaped `%` then a reference
            "%(a%%b)s",   // `%%` inside a name strips to a valid `%(ab)s`
            "%(name)%%s", // `%%` strips to bridge the `)s` terminator
            "trailing %%",
        ] {
            assert!(validate_set(ok, false).is_ok(), "{ok:?} should pass");
        }
        for bad in [
            "50% off",    // a stray `%`
            "%",          // a lone `%`
            "%(unclosed", // no `)s`
            "%(a)b",      // `)` not followed by `s`
            "%()s",       // empty name
            "%(%%)s",     // `%%` strips to an empty name
            "%%%",        // escaped pair then a stray `%`
            "%(a)s%",     // stray `%` after a valid reference
        ] {
            assert!(validate_set(bad, false).is_err(), "{bad:?} should fail");
        }
    }

    // Under scrub the rejected value never reaches the error text.
    #[test]
    fn validate_set_withholds_the_value_when_scrubbed() {
        let err = validate_set("secret 50% value", true).unwrap_err();
        assert!(!format!("{err}").contains("secret"), "{err}");
        let err = validate_set("secret 50% value", false).unwrap_err();
        assert!(format!("{err}").contains("secret"), "{err}");
    }
}
