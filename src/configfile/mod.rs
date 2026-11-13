//! An INI-file parser and serializer, byte-for-byte compatible with Python's standard-library `configparser`.
//!
//! [`ConfigFile`] mirrors `configparser.ConfigParser`, and via [`ConfigFile::raw`] `RawConfigParser`. File I/O goes
//! through the crate's symlink-safe [`safe_open`] and atomic [`atomic_replace`], so [`ConfigFile::read_path`] never
//! follows a symlink and [`ConfigFile::write_path`] replaces the target atomically with an explicit owner and mode.
//!
//! # Compatibility scope
//!
//! The "core" of `configparser` is implemented: sections, `key = value` / `key : value`, `#`/`;` full-line comments,
//! multi-line continuation values, case-insensitive keys with case-sensitive section names, DEFAULT inheritance, strict
//! duplicate detection, typed getters, and `%(name)s` basic interpolation. Not implemented (rarely used, and
//! deliberately out of scope): `${...}` extended interpolation, custom delimiters or comment prefixes, converters,
//! unnamed sections, and inline comments (which `configparser` also disables by default).
//!
//! # Secret-bearing files
//!
//! A configuration built with [`ConfigFile::scrubbed`] burns every buffer this module allocates for it with a volatile
//! zeroing pass as each is released, so dropping the configuration leaves no heap copies behind. With the `secrets`
//! feature, [`ConfigFile::read_secret_path`] also stages the raw file image in `memfd_secret`-backed memory.
//!
//! Stored values are ordinary heap memory while the configuration lives, swappable and visible in a core dump, so a
//! long-lived secret belongs in [`Secret`](crate::secrets::Secret), moved there promptly from
//! [`get_raw`](ConfigFile::get_raw). Whatever an accessor returns ([`get`](ConfigFile::get),
//! [`items`](ConfigFile::items), [`write_string`](ConfigFile::write_string)) is the caller's copy to burn, as is a
//! [`read_str`](ConfigFile::read_str) input buffer. Interpolation intermediates are not chased, so
//! [`raw`][ConfigFile::raw] is the secrets configuration. Transient key copies in parse control state and the kernel's
//! page cache are not chased either.
//!
//! ```
//! use truenas_ros::configfile::ConfigFile;
//!
//! let mut cfg = ConfigFile::new();
//! cfg.read_str("[server]\nHost = localhost\nPort = 8080\n").unwrap();
//! assert_eq!(cfg.get("server", "host").unwrap().as_deref(), Some("localhost"));
//! assert_eq!(cfg.get_int("server", "port").unwrap(), Some(8080));
//! ```

mod interp;
mod parse;
mod write;

use crate::AT_FDCWD;
use crate::errno::Errno;
use crate::error::{Error, Result};
#[cfg(feature = "secrets")]
use crate::sync_fs::{AtFlags, StatxMask, statx};
use crate::sync_fs::{AtomicWriteOptions, Mode, OFlag, atomic_replace, safe_open};
use std::io::Read;
use std::path::{Path, PathBuf};

/// Maximum recursive-interpolation depth, matching `configparser`'s `MAX_INTERPOLATION_DEPTH`.
const MAX_INTERPOLATION_DEPTH: u32 = 10;

/// The DEFAULT pseudo-section name (`configparser`'s `DEFAULTSECT`).
const DEFAULT_SECTION: &str = "DEFAULT";

/// Which interpolation dialect a [`ConfigFile`] applies when reading a value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Interp {
    /// No interpolation (`RawConfigParser`): values are returned verbatim.
    None,
    /// `%(name)s` basic interpolation (`ConfigParser`).
    Basic,
}

/// A minimal insertion-ordered, string-keyed map.
///
/// `entries` keeps insertion order, as `configparser` relies on, and `index` makes lookups and the upsert
/// [`insert`](Ordered::insert) O(1). Without the index, parsing an untrusted config with very many keys in one section
/// would be quadratic.
#[derive(Clone, Debug, Default)]
struct Ordered<V> {
    entries: Vec<(String, V)>,
    index: std::collections::HashMap<String, usize>,
}

impl<V> Ordered<V> {
    fn new() -> Self {
        Ordered {
            entries: Vec::new(),
            index: std::collections::HashMap::new(),
        }
    }

    fn position(&self, key: &str) -> Option<usize> {
        self.index.get(key).copied()
    }

    fn contains(&self, key: &str) -> bool {
        self.index.contains_key(key)
    }

    fn get(&self, key: &str) -> Option<&V> {
        self.position(key).map(|i| &self.entries[i].1)
    }

    fn get_mut(&mut self, key: &str) -> Option<&mut V> {
        match self.index.get(key).copied() {
            Some(i) => Some(&mut self.entries[i].1),
            None => None,
        }
    }

    /// Upsert; a displaced value is returned, never silently dropped, so a scrubbing caller can burn it.
    fn insert(&mut self, key: &str, value: V) -> Option<V> {
        if let Some(&i) = self.index.get(key) {
            Some(std::mem::replace(&mut self.entries[i].1, value))
        } else {
            self.index.insert(key.to_string(), self.entries.len());
            self.entries.push((key.to_string(), value));
            None
        }
    }

    /// Remove, handing back both stored copies of the key (the index's and the entry's) along with the value, so a
    /// scrubbing caller can burn them.
    fn remove(&mut self, key: &str) -> Option<(String, String, V)> {
        let (index_key, i) = self.index.remove_entry(key)?;
        let (entry_key, v) = self.entries.remove(i);
        // Entries after `i` shifted down by one; fix their recorded positions in place (no key is cloned or displaced
        // doing it).
        for pos in i..self.entries.len() {
            if let Some(slot) = self.index.get_mut(self.entries[pos].0.as_str()) {
                *slot = pos;
            }
        }
        Some((index_key, entry_key, v))
    }

    fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn iter(&self) -> impl Iterator<Item = (&str, &V)> {
        self.entries.iter().map(|(k, v)| (k.as_str(), v))
    }

    fn keys(&self) -> impl Iterator<Item = &str> {
        self.entries.iter().map(|(k, _)| k.as_str())
    }

    /// Burn every key, the entries' and the index's copies, and each value through `burn`. Every scrubbing release goes
    /// through this one walk so no path misses a copy. The index is drained, so only dropping the map should follow.
    fn scrub_with(&mut self, mut burn: impl FnMut(&mut V)) {
        for (key, value) in &mut self.entries {
            scrub_string(key);
            burn(value);
        }
        for (mut key, _) in self.index.drain() {
            scrub_string(&mut key);
        }
    }
}

/// An INI configuration, compatible with Python's `configparser`.
#[derive(Clone)]
pub struct ConfigFile {
    defaults: Ordered<Option<String>>,
    sections: Ordered<Ordered<Option<String>>>,
    interp: Interp,
    allow_no_value: bool,
    scrub: bool,
}

/// Prints the full structure for an ordinary configuration; a scrubbed one prints shape only - a secrets-bearing
/// configuration reaching a log must not carry its values.
impl std::fmt::Debug for ConfigFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.scrub {
            return f
                .debug_struct("ConfigFile")
                .field("sections", &self.sections.entries.len())
                .field("scrub", &true)
                .finish_non_exhaustive();
        }
        f.debug_struct("ConfigFile")
            .field("defaults", &self.defaults)
            .field("sections", &self.sections)
            .field("interp", &self.interp)
            .field("allow_no_value", &self.allow_no_value)
            .field("scrub", &self.scrub)
            .finish()
    }
}

/// Burning happens on release: whatever the configuration still holds when it drops is scrubbed here.
impl Drop for ConfigFile {
    fn drop(&mut self) {
        if !self.scrub {
            return;
        }
        scrub_opts(&mut self.defaults);
        self.sections.scrub_with(scrub_opts);
    }
}

/// Burn a string's whole allocation, spare capacity included - a truncated value keeps its old tail bytes past `len`.
///
/// Zero bytes are valid UTF-8, so the string stays sound until it drops.
fn scrub_string(s: &mut String) {
    // SAFETY: the vec's buffer is `capacity` writable bytes, and an all-zero prefix keeps the content valid UTF-8.
    unsafe {
        let v = s.as_mut_vec();
        crate::scrub::scrub(v.as_mut_ptr(), v.capacity());
    }
}

/// Burn one section's storage: every key (the index's copies included) and every value.
fn scrub_opts(opts: &mut Ordered<Option<String>>) {
    opts.scrub_with(|value| {
        if let Some(value) = value {
            scrub_string(value);
        }
    });
}

/// Burn a value displaced by an upsert.
fn scrub_displaced(scrub: bool, displaced: Option<Option<String>>) {
    if !scrub {
        return;
    }
    if let Some(Some(mut old)) = displaced {
        scrub_string(&mut old);
    }
}

impl Default for ConfigFile {
    fn default() -> Self {
        Self::new()
    }
}

impl ConfigFile {
    /// Create an empty configuration with `%(name)s` basic interpolation, matching `configparser.ConfigParser()`.
    pub fn new() -> Self {
        ConfigFile {
            defaults: Ordered::new(),
            sections: Ordered::new(),
            interp: Interp::Basic,
            allow_no_value: false,
            scrub: false,
        }
    }

    /// Create an empty configuration with interpolation disabled, matching `configparser.RawConfigParser()`. Values
    /// round-trip verbatim.
    pub fn raw() -> Self {
        let mut cfg = Self::new();
        cfg.interp = Interp::None;
        cfg
    }

    /// Allow keys with no value (a bare `key` with no `=`/`:`), matching `configparser`'s `allow_no_value=True`. Off by
    /// default.
    pub fn allow_no_value(mut self, yes: bool) -> Self {
        self.allow_no_value = yes;
        self
    }

    /// Burn every buffer this configuration allocates - the file image, parse accumulators, and stored keys and
    /// values - with a volatile zeroing pass as each is released, the whole store included when the configuration
    /// drops. It is for files that carry secrets, and the module docs say where the guarantee ends. Off by default.
    ///
    /// Parsing and every accessor behave identically either way, with two exceptions. Error messages withhold every
    /// value and name that came out of the file, so none of it reaches a log. And a scrubbed read refuses a non-regular
    /// file, whose stat size cannot pre-size the single burned buffer.
    pub fn scrubbed(mut self, yes: bool) -> Self {
        self.scrub = yes;
        self
    }

    // --- reading ---------------------------------------------------------

    /// Parse the INI document in `s` and merge it in (like `configparser.read_string`). Later values override earlier
    /// ones, and duplicate sections or options *within* `s` are rejected.
    pub fn read_str(&mut self, s: &str) -> Result<()> {
        parse::read(self, "<string>", s)
    }

    /// Read and parse a single file, opened symlink-safely.
    ///
    /// A missing file is an error here (use [`read_paths`](Self::read_paths) for `configparser.read()`'s skip-missing
    /// behavior). A symlink anywhere in `path` yields [`Error::SymlinkInPath`]; non-UTF-8 content yields
    /// [`Error::Parse`]. Line endings are decoded with universal newlines, as `configparser.read()` gets from
    /// `open(filename)`.
    pub fn read_path(&mut self, path: &Path) -> Result<()> {
        if self.scrub {
            return self.read_path_scrubbed(path);
        }
        let text = read_file_to_string(path)?;
        parse::read(self, &path.display().to_string(), &text)
    }

    /// [`read_path`](Self::read_path) for a scrubbed configuration: one fixed buffer sized from the file's length
    /// (never reallocated, so no freed copy escapes the burn), newlines normalized in place instead of by copy, and the
    /// buffer burned to its full capacity on every exit - the UTF-8 and parse failures included. Only a regular file is
    /// accepted; see [`regular_file_len`].
    fn read_path_scrubbed(&mut self, path: &Path) -> Result<()> {
        let mut file = safe_open(AT_FDCWD, path, OFlag::O_RDONLY | OFlag::O_CLOEXEC, Mode::empty())?;
        let len = regular_file_len(&file, path)?;
        let mut buf = ScrubVec(vec![0u8; len + 1]);
        let filled = read_filled(&mut file, &mut buf.0)?;
        buf.0.truncate(filled);
        normalize_newlines(&mut buf.0);
        let text = std::str::from_utf8(&buf.0).map_err(|_| Error::Parse("config file is not valid UTF-8".into()))?;
        parse::read(self, &path.display().to_string(), text)
    }

    /// Read and parse `path` with the raw file image staged in `memfd_secret`-backed memory
    /// ([`SecretMem`](crate::secrets::SecretMem)) and burned when the read ends. The image never touches the ordinary
    /// heap.
    ///
    /// Once the image is staged, the configuration is [`scrubbed`](Self::scrubbed) and [`raw`](Self::raw) for good.
    /// Only a regular file is accepted. Fails where `memfd_secret` is unavailable rather than degrading to an ordinary
    /// read.
    ///
    /// Returns which file image was read, so a caller can skip rebuilding what it derived when the next read finds the
    /// same one ([`StagedIdentity::same`]).
    #[cfg(feature = "secrets")]
    pub fn read_secret_path(&mut self, path: &Path) -> Result<StagedIdentity> {
        let source = path.display().to_string();
        // Stage first. Both settings below are one-way, so setting them ahead of a fallible read would downgrade an
        // interpolating configuration to raw over a secret this call never read.
        let (id, staged) = stage_secret_image(path)?;
        self.scrub = true;
        // Read secrets verbatim. The growing accumulator in `before_get` would leave partial plaintext copies in freed
        // heap that no scrub reaches.
        self.interp = Interp::None;
        match staged {
            None => parse::read(self, &source, "")?,
            Some((mut mem, content)) => {
                let slice = mem.as_mut_slice();
                let text = std::str::from_utf8(&slice[..content])
                    .map_err(|_| Error::Parse("config file is not valid UTF-8".into()))?;
                parse::read(self, &source, text)?
            }
        }
        Ok(id)
    }

    /// Read each path in turn, **skipping** any that cannot be used - missing, unreadable, a symlink component, or not
    /// a regular file - and return the paths actually read, the behavior of `configparser.read([...])`. A file that
    /// opens but fails to parse (or is not UTF-8) still returns an error, and so does one that grows mid-read. Line
    /// endings are decoded as in [`read_path`](Self::read_path).
    pub fn read_paths<I>(&mut self, paths: I) -> Result<Vec<PathBuf>>
    where
        I: IntoIterator<Item = PathBuf>,
    {
        let mut read = Vec::new();
        for path in paths {
            match self.read_path(&path) {
                Ok(()) => read.push(path),
                // Skipped as `configparser` skips any `OSError` from `open`, so one bad entry cannot deny the whole
                // load. A file that opens but fails to parse, or grows mid-read, still aborts.
                Err(Error::Errno(_)) | Err(Error::SymlinkInPath { .. }) | Err(Error::NotRegularFile { .. }) => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(read)
    }

    // --- writing ---------------------------------------------------------

    /// Serialize to a `String` exactly as `configparser.write()` would, with spaces around the `=` delimiter.
    pub fn write_string(&self) -> String {
        write::to_string(self, true)
    }

    /// Serialize like [`write_string`](Self::write_string), choosing whether the delimiter is padded with spaces (`key
    /// = value` vs `key=value`) - matching `configparser.write(space_around_delimiters=...)`.
    pub fn to_string_with(&self, space_around_delimiters: bool) -> String {
        write::to_string(self, space_around_delimiters)
    }

    /// Atomically write the serialized configuration to `path`.
    ///
    /// Uses [`atomic_replace`]: the content is written to a temporary file in the same directory, `fsync`ed, and
    /// `rename`d into place with the ownership and mode from `opts`, and every path component is resolved with
    /// `RESOLVE_NO_SYMLINKS`.
    pub fn write_path(&self, path: &Path, opts: AtomicWriteOptions) -> Result<()> {
        let mut text = self.write_string();
        let result = atomic_replace(path, text.as_bytes(), opts);
        // The serialization buffer carried every value, so a scrubbed configuration burns it on both outcomes.
        if self.scrub {
            scrub_string(&mut text);
        }
        result
    }

    // --- access ----------------------------------------------------------

    /// The section names, in insertion order (excluding `DEFAULT`).
    pub fn sections(&self) -> Vec<&str> {
        self.sections.keys().collect()
    }

    /// Whether a section with this exact (case-sensitive) name exists.
    pub fn has_section(&self, section: &str) -> bool {
        self.sections.contains(section)
    }

    /// The option keys visible in `section` (its own keys plus inherited `DEFAULT` keys), or `None` if the section does
    /// not exist. Keys are lowercased.
    ///
    /// The section's own keys come first, in file order, then the `DEFAULT` keys it did not override, as
    /// `configparser.options` does. [`items`](Self::items) builds up from the defaults instead, and the two disagree in
    /// CPython as they do here.
    pub fn options(&self, section: &str) -> Option<Vec<String>> {
        let opts = self.sections.get(section)?;
        let mut merged: Vec<String> = opts.keys().map(str::to_string).collect();
        merged.extend(self.defaults.keys().filter(|k| !opts.contains(k)).map(str::to_string));
        Some(merged)
    }

    /// Whether `option` is set in `section` or inherited from `DEFAULT`.
    pub fn has_option(&self, section: &str, option: &str) -> bool {
        let key = optionxform(option);
        match self.sections.get(section) {
            Some(opts) => opts.contains(&key) || self.defaults.contains(&key),
            None => section == DEFAULT_SECTION && self.defaults.contains(&key),
        }
    }

    /// The raw (un-interpolated) value of `option` in `section`, falling back to `DEFAULT`. Returns `None` if the
    /// option is absent or valueless, or if the section does not exist.
    pub fn get_raw(&self, section: &str, option: &str) -> Option<&str> {
        let key = optionxform(option);
        self.raw_lookup(section, &key).and_then(|v| v.as_deref())
    }

    /// The value of `option` in `section`, with `%(name)s` interpolation applied (unless this is a [`raw`](Self::raw)
    /// config), falling back to `DEFAULT`.
    ///
    /// Returns `Ok(None)` if the option is absent or valueless, and `Err` if the section does not exist (`configparser`
    /// raises `NoSectionError`) or if interpolation fails.
    pub fn get(&self, section: &str, option: &str) -> Result<Option<String>> {
        self.require_section(section)?;
        let key = optionxform(option);
        let raw = match self.raw_lookup(section, &key) {
            Some(Some(s)) => s,
            _ => return Ok(None),
        };
        match self.interp {
            Interp::None => Ok(Some(raw.clone())),
            Interp::Basic => {
                let view = self.merged_view(section);
                Ok(Some(interp::before_get(&key, raw, &view, self.scrub)?))
            }
        }
    }

    /// [`get`](Self::get), parsed as an integer (`configparser.getint`). `Ok(None)` if absent; `Err` if the value is
    /// not a valid integer.
    ///
    /// # Where this and `int()` part company
    ///
    /// `configparser` hands the string to `int()`, which also accepts underscores between digits (`1_000`), any Unicode
    /// decimal digit (`١٢٣`), and a magnitude no machine integer holds. [`get_float`](Self::get_float) inherits the
    /// first two from `float()`. All three are errors here. Python only ever accepts more, so a value that converts
    /// here converts there to the same number.
    pub fn get_int(&self, section: &str, option: &str) -> Result<Option<i64>> {
        match self.get(section, option)? {
            None => Ok(None),
            // The value is withheld from a scrubbed configuration's error -- on such a configuration it is the secret -
            // and the module-made copy is burned whichever way the parse goes.
            Some(mut v) => {
                let res = v.trim().parse::<i64>().map(Some).map_err(|_| {
                    Error::Parse(if self.scrub {
                        "not an integer".into()
                    } else {
                        format!("not an integer: {v:?}")
                    })
                });
                if self.scrub {
                    scrub_string(&mut v);
                }
                res
            }
        }
    }

    /// [`get`](Self::get), parsed as a float (`configparser.getfloat`).
    pub fn get_float(&self, section: &str, option: &str) -> Result<Option<f64>> {
        match self.get(section, option)? {
            None => Ok(None),
            Some(mut v) => {
                let res = v.trim().parse::<f64>().map(Some).map_err(|_| {
                    Error::Parse(if self.scrub {
                        "not a float".into()
                    } else {
                        format!("not a float: {v:?}")
                    })
                });
                if self.scrub {
                    scrub_string(&mut v);
                }
                res
            }
        }
    }

    /// [`get`](Self::get), parsed as a boolean (`configparser.getboolean`): one of `1`/`yes`/`true`/`on` or
    /// `0`/`no`/`false`/`off`, case-insensitively.
    pub fn get_bool(&self, section: &str, option: &str) -> Result<Option<bool>> {
        match self.get(section, option)? {
            None => Ok(None),
            // `to_lowercase` is a second module-made copy of the value, and under scrub both are burned.
            Some(mut v) => {
                let mut lower = v.to_lowercase();
                let res = match lower.as_str() {
                    "1" | "yes" | "true" | "on" => Ok(Some(true)),
                    "0" | "no" | "false" | "off" => Ok(Some(false)),
                    _ => Err(Error::Parse(if self.scrub {
                        "not a boolean".into()
                    } else {
                        format!("not a boolean: {v:?}")
                    })),
                };
                if self.scrub {
                    scrub_string(&mut lower);
                    scrub_string(&mut v);
                }
                res
            }
        }
    }

    /// All `(key, value)` pairs visible in `section` (its own plus inherited `DEFAULT`), interpolated, or `None` if the
    /// section does not exist.
    pub fn items(&self, section: &str) -> Result<Option<Vec<(String, String)>>> {
        // `DEFAULT` is not in `sections`, but `configparser.items` raises `NoSectionError` only `if section !=
        // self.default_section`, so it answers the defaults. `options` keeps CPython's refusal.
        if !self.sections.contains(section) && section != DEFAULT_SECTION {
            return Ok(None);
        }
        let view = self.merged_view(section);
        let mut out = Vec::new();
        for (k, v) in view.iter() {
            let value = match v {
                None => String::new(),
                Some(s) => match self.interp {
                    Interp::None => s.to_string(),
                    Interp::Basic => interp::before_get(k, s, &view, self.scrub)?,
                },
            };
            out.push((k.to_string(), value));
        }
        Ok(Some(out))
    }

    // --- mutation --------------------------------------------------------

    /// Add an empty section. Errors if it already exists, is named `DEFAULT`, or could not be read back as itself (see
    /// [`set`](Self::set)).
    pub fn add_section(&mut self, name: &str) -> Result<()> {
        if let Some(why) = parse::section_fault(name) {
            return Err(Error::Validation(format!("section name {name:?} {why}")));
        }
        if name == DEFAULT_SECTION {
            return Err(Error::Validation(format!("invalid section name: {name:?}")));
        }
        if self.sections.contains(name) {
            return Err(Error::Validation(format!("section already exists: {name:?}")));
        }
        self.sections.insert(name, Ordered::new());
        Ok(())
    }

    /// Set `option` in `section` to `value` (`None` is only meaningful with [`allow_no_value`](Self::allow_no_value)).
    ///
    /// The section must already exist, or be `DEFAULT`. For an interpolating config, a value with invalid `%` syntax is
    /// rejected (matching `ConfigParser.set`).
    ///
    /// # Option names are screened
    ///
    /// A name [`write_string`](Self::write_string) could not emit and read back as itself is rejected: one containing a
    /// line break or a `=`/`:` delimiter, surrounded by whitespace, or opening with `[`, `#` or `;`. `parse::key_fault`
    /// has the rules.
    ///
    /// `configparser` screens the value and never the name (`RawConfigParser.set`, `Lib/configparser.py:922`), so there
    /// a name such as `[global]` injects a section into the written file. Values keep `configparser`'s behaviour
    /// exactly.
    pub fn set(&mut self, section: &str, option: &str, value: Option<&str>) -> Result<()> {
        let key = optionxform(option);
        if let Some(why) = parse::key_fault(&key) {
            return Err(Error::Validation(format!("option name {option:?} {why}")));
        }
        if self.interp == Interp::Basic
            && let Some(v) = value
        {
            interp::validate_set(v, self.scrub)?;
        }
        let scrub = self.scrub;
        let slot = if section == DEFAULT_SECTION {
            &mut self.defaults
        } else {
            self.sections
                .get_mut(section)
                .ok_or_else(|| Error::Validation(format!("no such section: {section:?}")))?
        };
        scrub_displaced(scrub, slot.insert(&key, value.map(str::to_string)));
        Ok(())
    }

    /// Set `option` to an integer, serialized as a plain decimal.
    pub fn set_int(&mut self, section: &str, option: &str, value: i64) -> Result<()> {
        self.set(section, option, Some(&value.to_string()))
    }

    /// Set `option` to a boolean, serialized as Python's `str(bool)` (`True` / `False`), which `configparser`'s boolean
    /// parsing reads back.
    pub fn set_bool(&mut self, section: &str, option: &str, value: bool) -> Result<()> {
        self.set(section, option, Some(if value { "True" } else { "False" }))
    }

    /// Remove a section and all its options; returns whether it existed.
    pub fn remove_section(&mut self, name: &str) -> bool {
        match self.sections.remove(name) {
            Some((mut index_key, mut entry_key, mut opts)) => {
                if self.scrub {
                    scrub_string(&mut index_key);
                    scrub_string(&mut entry_key);
                    scrub_opts(&mut opts);
                }
                true
            }
            None => false,
        }
    }

    /// Remove an option from `section` (or `DEFAULT`); returns whether it existed. Errors if the section does not
    /// exist.
    pub fn remove_option(&mut self, section: &str, option: &str) -> Result<bool> {
        let key = optionxform(option);
        let scrub = self.scrub;
        let slot = if section == DEFAULT_SECTION {
            &mut self.defaults
        } else {
            self.sections
                .get_mut(section)
                .ok_or_else(|| Error::Validation(format!("no such section: {section:?}")))?
        };
        match slot.remove(&key) {
            Some((mut index_key, mut entry_key, mut value)) => {
                if scrub {
                    scrub_string(&mut index_key);
                    scrub_string(&mut entry_key);
                    if let Some(value) = value.as_mut() {
                        scrub_string(value);
                    }
                }
                Ok(true)
            }
            None => Ok(false),
        }
    }

    // --- internals -------------------------------------------------------

    /// Whether `section` can be addressed at all: `DEFAULT` always can, even with no `sections` entry of its own. Any
    /// other name that was never defined is an error, as `configparser` raises `NoSectionError`.
    fn require_section(&self, section: &str) -> Result<()> {
        if section == DEFAULT_SECTION || self.sections.contains(section) {
            Ok(())
        } else {
            Err(Error::Validation(format!("no such section: {section:?}")))
        }
    }

    /// Section-over-DEFAULT raw lookup (the `configparser` `ChainMap` order).
    /// A section that does not exist inherits nothing: DEFAULT is only reachable through a section that does, or under
    /// its own name.
    fn raw_lookup(&self, section: &str, key: &str) -> Option<&Option<String>> {
        match self.sections.get(section) {
            Some(opts) => opts.get(key).or_else(|| self.defaults.get(key)),
            None if section == DEFAULT_SECTION => self.defaults.get(key),
            None => None,
        }
    }

    /// The merged (DEFAULT, then section-override) raw values used both for interpolation variable lookups and for
    /// [`items`](Self::items).
    ///
    /// The view borrows rather than clones, since a clone per `get` would cost on the read path and, under scrub, leave
    /// a plaintext copy of every value to burn.
    fn merged_view(&self, section: &str) -> MergedView<'_> {
        let mut view = MergedView::default();
        for (k, v) in self.defaults.iter() {
            view.upsert(k, v.as_deref());
        }
        if let Some(opts) = self.sections.get(section) {
            for (k, v) in opts.iter() {
                view.upsert(k, v.as_deref());
            }
        }
        view
    }
}

/// A read-only merged view of a section over `DEFAULT` ([`merged_view`]), borrowing key and value from the
/// configuration. Section entries shadow `DEFAULT`; insertion order is preserved (DEFAULT keys first, then section-only
/// additions) so [`items`](ConfigFile::items) serializes as `configparser` does.
///
/// [`merged_view`]: ConfigFile::merged_view
#[derive(Default)]
pub(super) struct MergedView<'a> {
    entries: Vec<(&'a str, Option<&'a str>)>,
    index: std::collections::HashMap<&'a str, usize>,
}

impl<'a> MergedView<'a> {
    fn upsert(&mut self, key: &'a str, value: Option<&'a str>) {
        if let Some(&i) = self.index.get(key) {
            self.entries[i].1 = value;
        } else {
            self.index.insert(key, self.entries.len());
            self.entries.push((key, value));
        }
    }

    /// The value for `key`: outer `Some` means the key is present, inner `Some` that it carries a value (a valueless
    /// option reads as `Some(None)`).
    pub(super) fn get(&self, key: &str) -> Option<Option<&'a str>> {
        self.index.get(key).map(|&i| self.entries[i].1)
    }

    /// Merged `(key, value)` pairs in insertion order.
    pub(super) fn iter(&self) -> impl Iterator<Item = (&'a str, Option<&'a str>)> + '_ {
        self.entries.iter().copied()
    }
}

/// The `optionxform` transform: `configparser` stores and looks up option keys case-insensitively by lowercasing them
/// (section names are left as-is).
fn optionxform(option: &str) -> String {
    option.to_lowercase()
}

/// A read buffer burned to its full capacity when it drops, whichever way the read ends.
struct ScrubVec(Vec<u8>);

impl Drop for ScrubVec {
    fn drop(&mut self) {
        // SAFETY: the allocation is live and `capacity` bytes of it are writable.
        unsafe {
            crate::scrub::scrub(self.0.as_mut_ptr(), self.0.capacity());
        }
    }
}

/// Translate `\r\n` and a lone `\r` to `\n` in place, the universal-newline decoding `configparser.read()` gets from
/// `open(filename)`, with no reallocation. Bytes past the new length keep their old content, which is why a scrubbed
/// buffer is burned to capacity, not length.
///
/// Only the file entry points translate: `read_string`, which [`ConfigFile::read_str`] mirrors, wraps the text in a
/// `StringIO` with `newline='\n'`, which passes `\r` through verbatim.
fn normalize_newlines(buf: &mut Vec<u8>) {
    let len = normalize_newlines_slice(buf);
    buf.truncate(len);
}

/// [`normalize_newlines`] over a slice, returning the content's new length. `\r` and `\n` are ASCII, so the rewrite
/// cannot fall inside a multi-byte UTF-8 sequence.
fn normalize_newlines_slice(buf: &mut [u8]) -> usize {
    if !buf.contains(&b'\r') {
        return buf.len();
    }
    let mut w = 0;
    let mut r = 0;
    while r < buf.len() {
        if buf[r] == b'\r' {
            buf[w] = b'\n';
            r += if buf.get(r + 1) == Some(&b'\n') { 2 } else { 1 };
        } else {
            buf[w] = buf[r];
            r += 1;
        }
        w += 1;
    }
    w
}

/// The length a scrubbed read sizes its one buffer from. Only a regular file has one: for anything else - a FIFO, a
/// device, a proc file - the stat size does not describe the content, and a wrong pre-size either refuses a whole read
/// as a grow or silently reads as empty.
fn regular_file_len(file: &std::fs::File, path: &Path) -> Result<usize> {
    let meta = file.metadata().map_err(|e| Errno::try_from(e).unwrap_or(Errno::EIO))?;
    if !meta.file_type().is_file() {
        return Err(Error::NotRegularFile {
            path: path.to_path_buf(),
        });
    }
    Ok(meta.len() as usize)
}

/// Read to end-of-file into a fixed region sized for it, returning the bytes filled. The region is never grown: content
/// past its end - the file grew after it was sized - is refused rather than read torn or reallocated over, which would
/// leave the original buffer freed unburned. `Interrupted` is retried, as `read_to_end` retries it.
fn read_filled(file: &mut std::fs::File, buf: &mut [u8]) -> Result<usize> {
    let mut filled = 0;
    loop {
        let n = match file.read(&mut buf[filled..]) {
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => {
                return Err(Errno::try_from(e).unwrap_or(Errno::EIO).into());
            }
        };
        if n == 0 {
            return Ok(filled);
        }
        filled += n;
        if filled == buf.len() {
            return Err(Error::Validation("config file grew while being read".into()));
        }
    }
}

/// Which file image a secret read staged: the inode and its change cookie, taken from `statx` on the opened descriptor
/// before the read, so a rewrite during the read shows up as a different cookie next time.
#[cfg(feature = "secrets")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StagedIdentity {
    /// `stx_ino`.
    pub ino: u64,
    /// `stx_change_cookie`, or `None` where the filesystem supplies none.
    pub change_cookie: Option<u64>,
}

#[cfg(feature = "secrets")]
impl StagedIdentity {
    /// Whether `other` is the same unmodified file. Never true without a cookie on both sides: no cookie means no way
    /// to know.
    pub fn same(&self, other: &StagedIdentity) -> bool {
        self.ino == other.ino && self.change_cookie.is_some() && self.change_cookie == other.change_cookie
    }

    /// The identity of `path` now, without reading it: what a caller compares against the last
    /// [`read_secret_path`](ConfigFile::read_secret_path) before deciding whether to read again. Opens the file the way
    /// the read does and stages nothing.
    pub fn of_path(path: &Path) -> Result<StagedIdentity> {
        let file = safe_open(AT_FDCWD, path, OFlag::O_RDONLY | OFlag::O_CLOEXEC, Mode::empty())?;
        regular_file_len(&file, path)?;
        Self::of_file(&file)
    }

    fn of_file(file: &std::fs::File) -> Result<StagedIdentity> {
        let st = statx(
            file,
            "",
            AtFlags::AT_EMPTY_PATH,
            StatxMask::INO | StatxMask::CHANGE_COOKIE,
        )?;
        Ok(StagedIdentity {
            ino: st.ino(),
            change_cookie: st.change_cookie(),
        })
    }
}

/// Open `path` symlink-safely and stage its image - newline-normalized in place - in `memfd_secret` memory, returning
/// its identity with the region and the content's length, or `None` for an empty file. Split from
/// [`ConfigFile::read_secret_path`] so a test can hold the staged region and check what backs it.
#[cfg(feature = "secrets")]
fn stage_secret_image(path: &Path) -> Result<(StagedIdentity, Option<(crate::secrets::SecretMem, usize)>)> {
    let mut file = safe_open(AT_FDCWD, path, OFlag::O_RDONLY | OFlag::O_CLOEXEC, Mode::empty())?;
    let len = regular_file_len(&file, path)?;
    let id = StagedIdentity::of_file(&file)?;
    if len == 0 {
        return Ok((id, None));
    }
    let mut mem = crate::secrets::SecretMem::with_capacity(len + 1).map_err(|e| match e {
        Errno::EFAULT => Error::SecretMemRefused,
        e => Error::Errno(e),
    })?;
    let slice = mem.as_mut_slice();
    let filled = read_filled(&mut file, slice)?;
    let content = normalize_newlines_slice(&mut slice[..filled]);
    Ok((id, Some((mem, content))))
}

/// Read a whole file to a UTF-8 `String`, opened symlink-safely, with line endings translated by
/// [`normalize_newlines`].
fn read_file_to_string(path: &Path) -> Result<String> {
    let mut file = safe_open(AT_FDCWD, path, OFlag::O_RDONLY | OFlag::O_CLOEXEC, Mode::empty())?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)
        .map_err(|e| Errno::try_from(e).unwrap_or(Errno::EIO))?;
    // `\r` and `\n` cannot fall inside a multi-byte UTF-8 sequence, so translating before the validity check changes
    // nothing it decides.
    normalize_newlines(&mut buf);
    String::from_utf8(buf).map_err(|_| Error::Parse("config file is not valid UTF-8".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The same document, default vs scrubbed: parsing, reading back, and serialization must be indistinguishable -
    /// scrubbing changes when buffers are burned, never what the configuration means.
    #[test]
    fn scrubbed_parses_identically() {
        let doc = "[DEFAULT]\nshared = base\n\n[db]\npassword = hunter2\n\
                   multi = one\n  two\n\n  three\n# comment\n[empty]\n";
        let over = "[db]\npassword = swordfish\n";
        let dir = crate::tempdir().unwrap();
        let path = dir.path().join("cfg.ini");
        // CRLF endings exercise the in-place translation against the copying one over a real read.
        std::fs::write(&path, doc.replace('\n', "\r\n")).unwrap();

        let mut plain = ConfigFile::raw();
        plain.read_path(&path).unwrap();
        plain.read_str(over).unwrap();
        let mut scrubbed = ConfigFile::raw().scrubbed(true);
        scrubbed.read_path(&path).unwrap();
        scrubbed.read_str(over).unwrap();

        assert_eq!(plain.sections(), scrubbed.sections());
        assert_eq!(plain.items("db").unwrap(), scrubbed.items("db").unwrap());
        assert_eq!(scrubbed.get_raw("db", "password"), Some("swordfish"));
        assert_eq!(scrubbed.get_raw("db", "multi"), Some("one\ntwo\n\nthree"));
        assert_eq!(plain.write_string(), scrubbed.write_string());
    }

    /// The burn covers the allocation's spare capacity: a truncated value keeps its old tail bytes past `len`, and they
    /// must go too.
    #[test]
    fn scrub_string_burns_the_whole_allocation() {
        let mut s = String::with_capacity(32);
        s.push_str("supersecretvalue");
        s.truncate(5);
        scrub_string(&mut s);
        // SAFETY: `scrub_string` wrote every capacity byte, so extending `len` over them reads initialized memory, and
        // all-zero content is valid UTF-8.
        unsafe {
            let v = s.as_mut_vec();
            let cap = v.capacity();
            v.set_len(cap);
            assert!(v.iter().all(|&b| b == 0), "unburned bytes remain");
        }
    }

    /// The in-place newline translation must match Python's two-pass `str.replace` decoding byte for byte - `\r\r\n`
    /// and a trailing `\r` included.
    #[test]
    fn normalize_newlines_matches_the_copying_translation() {
        for case in [
            "plain\n",
            "a\r\nb",
            "a\rb",
            "\r\r\n",
            "a\r",
            "\r\n\r\n",
            "mixed\r\nlone\rend",
            "",
        ] {
            let want = case.replace("\r\n", "\n").replace('\r', "\n");
            let mut buf = case.as_bytes().to_vec();
            normalize_newlines(&mut buf);
            assert_eq!(buf, want.as_bytes(), "case {case:?}");
        }
    }

    /// A duplicate-option error from a scrubbed configuration must not name the key.
    #[test]
    fn a_duplicate_option_error_withholds_the_key_when_scrubbed() {
        let doc = "[s]\nakid = 1\nakid = 2\n";
        let mut plain = ConfigFile::raw();
        let loud = plain.read_str(doc).unwrap_err().to_string();
        assert!(loud.contains("akid"), "{loud}");
        let mut scrubbed = ConfigFile::raw().scrubbed(true);
        let quiet = scrubbed.read_str(doc).unwrap_err().to_string();
        assert!(!quiet.contains("akid"), "{quiet}");
        assert!(quiet.contains("duplicate option"), "{quiet}");
    }

    /// Debug output of a scrubbed configuration carries structure only.
    #[test]
    fn debug_redacts_a_scrubbed_configuration() {
        let mut cfg = ConfigFile::raw().scrubbed(true);
        cfg.read_str("[s]\nkey = hunter2\n").unwrap();
        let redacted = format!("{cfg:?}");
        assert!(!redacted.contains("hunter2"), "{redacted}");
        let mut plain = ConfigFile::raw();
        plain.read_str("[s]\nkey = hunter2\n").unwrap();
        assert!(format!("{plain:?}").contains("hunter2"));
    }

    /// Removing a non-last entry has to correct the recorded position of everything after it, or a lookup through
    /// `index` quietly returns a neighbour's value.
    #[test]
    fn removing_a_middle_entry_keeps_the_rest_reachable() {
        let mut cfg = ConfigFile::raw();
        cfg.read_str("[s]\na = 1\nb = 2\nc = 3\n").expect("parses");
        assert!(cfg.remove_option("s", "a").expect("section exists"));
        assert_eq!(
            cfg.options("s").expect("section exists"),
            vec!["b".to_string(), "c".to_string()],
            "order survives the removal"
        );
        assert_eq!(cfg.get_raw("s", "b").expect("present"), "2");
        assert_eq!(cfg.get_raw("s", "c").expect("present"), "3");
        // A write through the index must land on the key it names.
        cfg.set("s", "c", Some("9")).expect("set");
        assert_eq!(cfg.get_raw("s", "c").expect("present"), "9");
        assert_eq!(
            cfg.get_raw("s", "b").expect("present"),
            "2",
            "writing c must not land on b"
        );

        // The same for sections, whose index is the same structure.
        let mut cfg = ConfigFile::raw();
        cfg.read_str("[a]\nk = 1\n\n[b]\nk = 2\n\n[c]\nk = 3\n")
            .expect("parses");
        assert!(cfg.remove_section("a"));
        assert_eq!(cfg.get_raw("b", "k").expect("present"), "2");
        assert_eq!(cfg.get_raw("c", "k").expect("present"), "3");
    }

    /// Overwrite, removal, and re-serialization behave identically in scrub mode: the burn happens on release, never in
    /// semantics.
    #[test]
    fn scrubbed_mutation_keeps_behavior() {
        let doc = "[a]\nx = 1\ny = 2\n\n[b]\nz = 3\n";
        let mut plain = ConfigFile::raw();
        let mut scrubbed = ConfigFile::raw().scrubbed(true);
        for cfg in [&mut plain, &mut scrubbed] {
            cfg.read_str(doc).unwrap();
            cfg.set("a", "x", Some("overwritten")).unwrap();
            assert!(cfg.remove_option("a", "y").unwrap());
            assert!(cfg.remove_section("b"));
        }
        assert_eq!(plain.write_string(), scrubbed.write_string());
        assert_eq!(scrubbed.get_raw("a", "x"), Some("overwritten"));
    }

    /// `read_secret_path` stages the image off-heap and yields the same configuration, marked scrubbed.
    #[cfg(feature = "secrets")]
    #[test]
    fn read_secret_path_parses_and_marks_scrubbed() {
        if !crate::secrets::SecretMem::available() {
            assert!(
                std::env::var_os("TRUENAS_ROS_REQUIRE_SECRETMEM").is_none(),
                "memfd_secret unavailable but REQUIRE_SECRETMEM is set"
            );
            return;
        }
        let dir = crate::tempdir().unwrap();
        let path = dir.path().join("cred.ini");
        std::fs::write(&path, "[user]\r\nsecret_access_key = sw0rdf1sh\r\n").unwrap();
        let mut cfg = ConfigFile::raw();
        cfg.read_secret_path(&path).unwrap();
        assert_eq!(cfg.get_raw("user", "secret_access_key"), Some("sw0rdf1sh"));
        assert!(
            !format!("{cfg:?}").contains("sw0rdf1sh"),
            "reading through secret memory must mark the store scrubbed"
        );

        // An empty file parses to an empty configuration without staging.
        let empty_path = dir.path().join("empty.ini");
        std::fs::write(&empty_path, "").unwrap();
        let mut empty = ConfigFile::raw();
        empty.read_secret_path(&empty_path).unwrap();
        assert!(empty.sections().is_empty());
    }

    /// `read_secret_path` reads verbatim even from a default (interpolating) configuration.
    #[cfg(feature = "secrets")]
    #[test]
    fn read_secret_path_reads_verbatim_from_a_default_config() {
        if !crate::secrets::SecretMem::available() {
            assert!(
                std::env::var_os("TRUENAS_ROS_REQUIRE_SECRETMEM").is_none(),
                "memfd_secret unavailable but REQUIRE_SECRETMEM is set"
            );
            return;
        }
        let dir = crate::tempdir().unwrap();
        let path = dir.path().join("cred.ini");
        // `%(user)s` reads back differently verbatim vs interpolated, so the value tells the two modes apart.
        std::fs::write(&path, "[db]\r\nurl = postgres://%(user)s@h\r\nuser = svc\r\n").unwrap();
        let mut cfg = ConfigFile::new();
        cfg.read_secret_path(&path).unwrap();
        assert_eq!(
            cfg.get("db", "url").unwrap().as_deref(),
            Some("postgres://%(user)s@h"),
            "a secret value must be read verbatim, not interpolated"
        );
    }

    /// `items("DEFAULT")` answers the defaults, as `configparser` does, while `options("DEFAULT")` keeps CPython's
    /// refusal.
    #[test]
    fn items_answers_the_default_section() {
        let mut cfg = ConfigFile::raw();
        cfg.read_str("[DEFAULT]\na = 1\nb = 2\n[s]\nb = 3\nc = 4\n").unwrap();
        assert_eq!(
            cfg.items("DEFAULT").unwrap(),
            Some(vec![
                ("a".to_string(), "1".to_string()),
                ("b".to_string(), "2".to_string()),
            ])
        );
        // A section that really is absent still answers `None`, and `options` keeps CPython's answer for `DEFAULT`.
        assert_eq!(cfg.items("nope").unwrap(), None);
        assert_eq!(cfg.options("DEFAULT"), None);
        // And the ordinary section is unchanged: defaults first, then the section's own additions, with its overrides
        // in place.
        assert_eq!(
            cfg.items("s").unwrap(),
            Some(vec![
                ("a".to_string(), "1".to_string()),
                ("b".to_string(), "3".to_string()),
                ("c".to_string(), "4".to_string()),
            ])
        );
    }

    /// A secret read that fails leaves the configuration as it found it, interpolating and unscrubbed. Driven with an
    /// absent path, the same failure a permission denial or a non-regular file takes.
    #[cfg(feature = "secrets")]
    #[test]
    fn a_refused_secret_read_does_not_downgrade_the_configuration() {
        let mut cfg = ConfigFile::new();
        cfg.read_str("[DEFAULT]\nbase = /srv\n[p]\ndir = %(base)s/data\n")
            .unwrap();
        assert_eq!(
            cfg.get("p", "dir").unwrap().as_deref(),
            Some("/srv/data"),
            "interpolating before the refused read"
        );

        let dir = crate::tempdir().unwrap();
        cfg.read_secret_path(&dir.path().join("nope.ini"))
            .expect_err("an absent secret must fail");

        assert_eq!(
            cfg.get("p", "dir").unwrap().as_deref(),
            Some("/srv/data"),
            "a refused secret read downgraded the configuration to raw"
        );
        assert!(!cfg.scrub, "and marked it scrubbed");
    }

    /// The identity names the file image: equal across two reads of an unchanged file, different once it is rewritten,
    /// and never `same` without a change cookie. Runs on the ZFS dataset the QEMU job names, where
    /// `TRUENAS_ROS_REQUIRE_CHANGE_COOKIE` turns a missing cookie from a skip into a failure.
    #[cfg(feature = "secrets")]
    #[test]
    fn read_secret_path_identifies_the_image() {
        if !crate::secrets::SecretMem::available() {
            assert!(
                std::env::var_os("TRUENAS_ROS_REQUIRE_SECRETMEM").is_none(),
                "memfd_secret unavailable but REQUIRE_SECRETMEM is set"
            );
            return;
        }
        /// Removes the file on the way out, on the dataset as in the tempdir.
        struct Cleanup(PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(&self.0);
            }
        }
        let dir = crate::tempdir().unwrap();
        let base = ["TRUENAS_ROS_POSIX_DATASET", "TRUENAS_ROS_NFS4_DATASET"]
            .into_iter()
            .find_map(|v| std::env::var_os(v).map(PathBuf::from))
            .unwrap_or_else(|| dir.path().to_path_buf());
        let path = base.join(format!("cred-{}.ini", std::process::id()));
        let _cleanup = Cleanup(path.clone());
        std::fs::write(&path, "[user]\nkey = a\n").unwrap();
        let first = ConfigFile::raw().read_secret_path(&path).unwrap();
        let again = ConfigFile::raw().read_secret_path(&path).unwrap();
        assert_eq!(first, again);
        std::fs::write(&path, "[user]\nkey = b\n").unwrap();
        let changed = ConfigFile::raw().read_secret_path(&path).unwrap();
        assert_eq!(first.ino, changed.ino, "rewritten in place");
        if first.change_cookie.is_some() {
            assert!(first.same(&again));
            assert!(!first.same(&changed), "a rewrite kept the cookie");
        } else {
            assert!(
                std::env::var_os("TRUENAS_ROS_REQUIRE_CHANGE_COOKIE").is_none(),
                "TRUENAS_ROS_REQUIRE_CHANGE_COOKIE is set but {} reports no \
                 change cookie",
                path.display()
            );
            assert!(!first.same(&again), "no cookie read as unchanged");
        }
    }

    /// The probe answers what the read would, without staging anything, and moves with the file the same way.
    #[cfg(feature = "secrets")]
    #[test]
    fn identity_of_path_matches_the_read() {
        if !crate::secrets::SecretMem::available() {
            assert!(
                std::env::var_os("TRUENAS_ROS_REQUIRE_SECRETMEM").is_none(),
                "memfd_secret unavailable but REQUIRE_SECRETMEM is set"
            );
            return;
        }
        let dir = crate::tempdir().unwrap();
        let path = dir.path().join("cred.ini");
        std::fs::write(&path, "[user]\nkey = a\n").unwrap();
        let probed = StagedIdentity::of_path(&path).unwrap();
        let read = ConfigFile::raw().read_secret_path(&path).unwrap();
        assert_eq!(probed, read);
        std::fs::write(&path, "[user]\nkey = b\n").unwrap();
        let after = StagedIdentity::of_path(&path).unwrap();
        assert_eq!(after.ino, probed.ino);
        if probed.change_cookie.is_some() {
            assert!(probed.same(&read));
            assert!(!after.same(&probed), "a rewrite kept the cookie");
        }
        StagedIdentity::of_path(&dir.path().join("nope.ini")).expect_err("a missing file has no identity");
        StagedIdentity::of_path(dir.path()).expect_err("a directory is not a secret file");
    }

    /// The staged image really is `memfd_secret` memory: its VMA is the `/secretmem` pseudo-file and carries
    /// secretmem's undumpable and no-fork flags, which an ordinary heap buffer's does not. Catches the staging being
    /// swapped for a plain allocation, which parse results alone cannot see.
    #[cfg(feature = "secrets")]
    #[test]
    fn read_secret_path_stages_off_heap() {
        if !crate::secrets::SecretMem::available() {
            assert!(
                std::env::var_os("TRUENAS_ROS_REQUIRE_SECRETMEM").is_none(),
                "memfd_secret unavailable but REQUIRE_SECRETMEM is set"
            );
            return;
        }
        let dir = crate::tempdir().unwrap();
        let path = dir.path().join("cred.ini");
        std::fs::write(&path, "[user]\r\nkey = sw0rdf1sh\r\n").unwrap();
        let (mem, content) = stage_secret_image(&path).unwrap().1.unwrap();
        // Normalized in place, in the region.
        assert_eq!(&mem.as_slice()[..content], b"[user]\nkey = sw0rdf1sh\n");
        let vma =
            crate::secrets::vma_of(mem.as_slice().as_ptr() as usize).expect("no smaps entry for the staged image");
        assert!(
            vma.name.starts_with("/secretmem"),
            "staging is not secretmem-backed: {:?}",
            vma.name
        );
        for want in ["dd", "dc"] {
            assert!(
                vma.flags.split_whitespace().any(|f| f == want),
                "staging is missing {want:?} in {:?}",
                vma.flags
            );
        }
    }

    /// A typed getter's parse error must not quote the value out of a scrubbed configuration - the value is the secret.
    #[test]
    fn typed_getter_errors_withhold_the_value_when_scrubbed() {
        let doc = "[s]\nn = sw0rdf1sh\n";
        let mut plain = ConfigFile::raw();
        plain.read_str(doc).unwrap();
        let mut scrubbed = ConfigFile::raw().scrubbed(true);
        scrubbed.read_str(doc).unwrap();
        let loud = plain.get_int("s", "n").unwrap_err().to_string();
        assert!(loud.contains("sw0rdf1sh"), "{loud}");
        for quiet in [
            scrubbed.get_int("s", "n").unwrap_err().to_string(),
            scrubbed.get_float("s", "n").unwrap_err().to_string(),
            scrubbed.get_bool("s", "n").unwrap_err().to_string(),
        ] {
            assert!(!quiet.contains("sw0rdf1sh"), "{quiet}");
        }
    }

    /// A duplicate-section error withholds the name like the duplicate-option error withholds its key.
    #[test]
    fn a_duplicate_section_error_withholds_the_name_when_scrubbed() {
        let doc = "[acct]\na = 1\n[acct]\nb = 2\n";
        let mut plain = ConfigFile::raw();
        let loud = plain.read_str(doc).unwrap_err().to_string();
        assert!(loud.contains("acct"), "{loud}");
        let mut scrubbed = ConfigFile::raw().scrubbed(true);
        let quiet = scrubbed.read_str(doc).unwrap_err().to_string();
        assert!(!quiet.contains("acct"), "{quiet}");
        assert!(quiet.contains("duplicate section"), "{quiet}");
    }

    /// An interpolation error must not carry the value fragment or a referenced option name out of a scrubbed
    /// configuration.
    #[test]
    fn interpolation_errors_withhold_the_value_when_scrubbed() {
        let doc = "[s]\nbad = AKIA%zzz\nmissing = %(gone)s\n";
        let mut plain = ConfigFile::new();
        plain.read_str(doc).unwrap();
        let mut scrubbed = ConfigFile::new().scrubbed(true);
        scrubbed.read_str(doc).unwrap();
        for (option, marker) in [("bad", "zzz"), ("missing", "gone")] {
            let loud = plain.get("s", option).unwrap_err().to_string();
            assert!(loud.contains(marker), "{loud}");
            let quiet = scrubbed.get("s", option).unwrap_err().to_string();
            assert!(!quiet.contains(marker), "{quiet}");
        }
        let loud = plain.set("s", "x", Some("50% off")).unwrap_err();
        assert!(loud.to_string().contains("50%"), "{loud}");
        let quiet = scrubbed.set("s", "x", Some("50% off")).unwrap_err();
        assert!(!quiet.to_string().contains("50%"), "{quiet}");
    }

    #[test]
    fn interpolation_resolves_across_the_merged_view() {
        // The merged view a `get` interpolates against: `%(host)s` falls back to DEFAULT while `%(base)s` takes the
        // section's override, and `%(url)s` resolves recursively through a value that itself interpolates. Values
        // verified against CPython `configparser`.
        let doc = "[DEFAULT]\n\
                   host = example.com\n\
                   base = /srv\n\
                   [site]\n\
                   base = /var/www\n\
                   url = http://%(host)s%(base)s\n\
                   nested = %(url)s/index\n";
        let mut cfg = ConfigFile::new();
        cfg.read_str(doc).unwrap();
        assert_eq!(
            cfg.get("site", "url").unwrap().as_deref(),
            Some("http://example.com/var/www")
        );
        assert_eq!(
            cfg.get("site", "nested").unwrap().as_deref(),
            Some("http://example.com/var/www/index")
        );
        // A DEFAULT-only key is inherited by the section.
        assert_eq!(cfg.get("site", "host").unwrap().as_deref(), Some("example.com"));
    }

    /// A scrubbed read refuses a non-regular file: its stat size cannot pre-size the staging buffer, so it would stage
    /// a torn image or read as silently empty. The plain read keeps `configparser`'s take-what-`open`-gives behavior.
    #[test]
    fn a_scrubbed_read_refuses_a_non_regular_file() {
        let dev_null = Path::new("/dev/null");
        let mut plain = ConfigFile::raw();
        plain.read_path(dev_null).unwrap();
        let mut scrubbed = ConfigFile::raw().scrubbed(true);
        let err = scrubbed.read_path(dev_null).unwrap_err().to_string();
        assert!(err.contains("not a regular file"), "{err}");
        #[cfg(feature = "secrets")]
        {
            // Refused before any staging, so no secretmem is needed.
            let mut secret = ConfigFile::raw();
            let err = secret.read_secret_path(dev_null).unwrap_err().to_string();
            assert!(err.contains("not a regular file"), "{err}");
        }
    }

    #[test]
    fn read_paths_skips_a_non_regular_file() {
        // A non-regular candidate is skipped like a missing one, so one planted FIFO cannot deny a whole multi-file
        // load. Exercised on a scrubbed config, which refuses a non-regular file.
        let dir = crate::tempdir().unwrap();
        let good = dir.path().join("creds.ini");
        std::fs::write(&good, "[user]\r\nkey = sw0rdf1sh\r\n").unwrap();

        let mut cfg = ConfigFile::raw().scrubbed(true);
        let read = cfg
            .read_paths([good.clone(), PathBuf::from("/dev/null")])
            .expect("a non-regular path is skipped, not fatal");
        assert_eq!(read, vec![good]);
        assert_eq!(cfg.get_raw("user", "key"), Some("sw0rdf1sh"));
    }
}
