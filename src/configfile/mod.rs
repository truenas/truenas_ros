//! An INI-file parser and serializer, byte-for-byte compatible with Python's
//! standard-library `configparser`.
//!
//! [`ConfigFile`] mirrors `configparser.ConfigParser` (and, via
//! [`ConfigFile::raw`], `RawConfigParser`): the same INI grammar, the same
//! `optionxform` key-lowercasing, DEFAULT-section inheritance, `%(name)s`
//! interpolation, and the same serialization (delimiter, blank-line, and
//! multi-line-`\t` rules). Where `configparser` leaves durability and safety to
//! the caller, this module wires file I/O through the crate's symlink-safe
//! [`safe_open`] and atomic [`atomic_replace`], so [`ConfigFile::read_path`]
//! never follows a symlink and [`ConfigFile::write_path`] replaces the target
//! atomically (temp file, `fsync`, `rename`) with an explicit owner and mode.
//!
//! # Compatibility scope
//!
//! The "core" of `configparser` is implemented: sections, `key = value` /
//! `key : value`, `#`/`;` full-line comments, multi-line continuation values,
//! case-insensitive keys with case-sensitive section names, DEFAULT
//! inheritance, strict duplicate detection, typed getters, and `%(name)s` basic
//! interpolation. Not implemented (rarely used, and deliberately out of scope):
//! `${...}` extended interpolation, custom delimiters or comment prefixes,
//! converters, unnamed sections, and inline comments (which `configparser` also
//! disables by default).
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

use crate::errno::Errno;
use crate::error::{Error, Result};
use crate::sync_fs::{
    atomic_replace, safe_open, AtomicWriteOptions, Mode, OFlag,
};
use crate::AT_FDCWD;
use std::io::Read;
use std::path::{Path, PathBuf};

/// Maximum recursive-interpolation depth, matching `configparser`'s
/// `MAX_INTERPOLATION_DEPTH`.
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
/// `entries` preserves insertion order — the Python `dict`-assignment semantics
/// `configparser`'s ordering relies on — and `index` maps each key to its
/// position so lookups and the upsert [`insert`](Ordered::insert) are O(1)
/// rather than a scan. Without the index, parsing an untrusted config with very
/// many keys in one section would be quadratic.
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

    fn insert(&mut self, key: &str, value: V) {
        if let Some(&i) = self.index.get(key) {
            self.entries[i].1 = value;
        } else {
            self.index.insert(key.to_string(), self.entries.len());
            self.entries.push((key.to_string(), value));
        }
    }

    fn remove(&mut self, key: &str) -> Option<V> {
        let i = self.index.remove(key)?;
        let (_, v) = self.entries.remove(i);
        // Entries after `i` shifted down by one; fix their recorded positions.
        for pos in i..self.entries.len() {
            let k = self.entries[pos].0.clone();
            self.index.insert(k, pos);
        }
        Some(v)
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
}

/// An INI configuration, compatible with Python's `configparser`.
///
/// Build one with [`new`](Self::new) (interpolating, like `ConfigParser`) or
/// [`raw`](Self::raw) (like `RawConfigParser`), populate it by reading a string
/// or file, query it with the typed getters, and serialize it back with
/// [`write_string`](Self::write_string) or [`write_path`](Self::write_path).
#[derive(Clone, Debug)]
pub struct ConfigFile {
    defaults: Ordered<Option<String>>,
    sections: Ordered<Ordered<Option<String>>>,
    interp: Interp,
    allow_no_value: bool,
}

impl Default for ConfigFile {
    fn default() -> Self {
        Self::new()
    }
}

impl ConfigFile {
    /// Create an empty configuration with `%(name)s` basic interpolation,
    /// matching `configparser.ConfigParser()`.
    pub fn new() -> Self {
        ConfigFile {
            defaults: Ordered::new(),
            sections: Ordered::new(),
            interp: Interp::Basic,
            allow_no_value: false,
        }
    }

    /// Create an empty configuration with interpolation disabled, matching
    /// `configparser.RawConfigParser()`. Values round-trip verbatim.
    pub fn raw() -> Self {
        ConfigFile {
            interp: Interp::None,
            ..Self::new()
        }
    }

    /// Allow keys with no value (a bare `key` with no `=`/`:`), matching
    /// `configparser`'s `allow_no_value=True`. Off by default.
    pub fn allow_no_value(mut self, yes: bool) -> Self {
        self.allow_no_value = yes;
        self
    }

    // --- reading ---------------------------------------------------------

    /// Parse the INI document in `s` and merge it in (like
    /// `configparser.read_string`). Later values override earlier ones;
    /// duplicate sections or options *within* `s` are rejected.
    pub fn read_str(&mut self, s: &str) -> Result<()> {
        parse::read(self, "<string>", s)
    }

    /// Read and parse a single file, opened symlink-safely.
    ///
    /// A missing file is an error here (use [`read_paths`](Self::read_paths) for
    /// `configparser.read()`'s skip-missing behavior). A symlink anywhere in
    /// `path` yields [`Error::SymlinkInPath`]; non-UTF-8 content yields
    /// [`Error::Parse`].
    pub fn read_path(&mut self, path: &Path) -> Result<()> {
        let text = read_file_to_string(path)?;
        parse::read(self, &path.display().to_string(), &text)
    }

    /// Read each path in turn, **skipping** any that cannot be opened (missing,
    /// unreadable, or containing a symlink component), and return the paths
    /// actually read — the behavior of `configparser.read([...])`. A file that
    /// opens but fails to parse (or is not UTF-8) still returns an error.
    pub fn read_paths<I>(&mut self, paths: I) -> Result<Vec<PathBuf>>
    where
        I: IntoIterator<Item = PathBuf>,
    {
        let mut read = Vec::new();
        for path in paths {
            let text = match read_file_to_string(&path) {
                Ok(text) => text,
                // Could not open/read (missing, permissions, symlink): skip, as
                // `configparser` skips any `OSError` from `open`.
                Err(Error::Errno(_)) | Err(Error::SymlinkInPath { .. }) => {
                    continue
                }
                Err(e) => return Err(e),
            };
            parse::read(self, &path.display().to_string(), &text)?;
            read.push(path);
        }
        Ok(read)
    }

    // --- writing ---------------------------------------------------------

    /// Serialize to a `String` exactly as `configparser.write()` would, with
    /// spaces around the `=` delimiter.
    pub fn write_string(&self) -> String {
        write::to_string(self, true)
    }

    /// Serialize like [`write_string`](Self::write_string), choosing whether the
    /// delimiter is padded with spaces (`key = value` vs `key=value`) — matching
    /// `configparser.write(space_around_delimiters=...)`.
    pub fn to_string_with(&self, space_around_delimiters: bool) -> String {
        write::to_string(self, space_around_delimiters)
    }

    /// Atomically write the serialized configuration to `path`.
    ///
    /// Uses [`atomic_replace`]: the content is written to a temporary file in
    /// the same directory, `fsync`ed, and `rename`d into
    /// place with the ownership and mode from `opts`, and every path component is
    /// resolved with `RESOLVE_NO_SYMLINKS`. `configparser` itself does none of
    /// this.
    pub fn write_path(
        &self,
        path: &Path,
        opts: AtomicWriteOptions,
    ) -> Result<()> {
        atomic_replace(path, self.write_string().as_bytes(), opts)
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

    /// The option keys visible in `section` (its own keys plus inherited
    /// `DEFAULT` keys), or `None` if the section does not exist. Keys are
    /// lowercased.
    pub fn options(&self, section: &str) -> Option<Vec<String>> {
        let opts = self.sections.get(section)?;
        let mut merged = self.defaults.clone();
        for (k, v) in opts.iter() {
            merged.insert(k, v.clone());
        }
        Some(merged.keys().map(str::to_string).collect())
    }

    /// Whether `option` is set in `section` or inherited from `DEFAULT`.
    pub fn has_option(&self, section: &str, option: &str) -> bool {
        let key = optionxform(option);
        match self.sections.get(section) {
            Some(opts) => opts.contains(&key) || self.defaults.contains(&key),
            None => section == DEFAULT_SECTION && self.defaults.contains(&key),
        }
    }

    /// The raw (un-interpolated) value of `option` in `section`, falling back to
    /// `DEFAULT`. Returns `None` if the option is absent or valueless.
    pub fn get_raw(&self, section: &str, option: &str) -> Option<&str> {
        let key = optionxform(option);
        self.raw_lookup(section, &key).and_then(|v| v.as_deref())
    }

    /// The value of `option` in `section`, with `%(name)s` interpolation applied
    /// (unless this is a [`raw`](Self::raw) config), falling back to `DEFAULT`.
    ///
    /// Returns `Ok(None)` if the option is absent or valueless, or `Err` if
    /// interpolation fails.
    pub fn get(&self, section: &str, option: &str) -> Result<Option<String>> {
        let key = optionxform(option);
        let raw = match self.raw_lookup(section, &key) {
            Some(Some(s)) => s,
            _ => return Ok(None),
        };
        match self.interp {
            Interp::None => Ok(Some(raw.clone())),
            Interp::Basic => {
                let map = self.merged_map(section);
                Ok(Some(interp::before_get(&key, raw, &map)?))
            }
        }
    }

    /// [`get`](Self::get), parsed as an integer (`configparser.getint`).
    /// `Ok(None)` if absent; `Err` if the value is not a valid integer.
    pub fn get_int(&self, section: &str, option: &str) -> Result<Option<i64>> {
        match self.get(section, option)? {
            None => Ok(None),
            Some(v) => v
                .trim()
                .parse::<i64>()
                .map(Some)
                .map_err(|_| Error::Parse(format!("not an integer: {v:?}"))),
        }
    }

    /// [`get`](Self::get), parsed as a float (`configparser.getfloat`).
    pub fn get_float(
        &self,
        section: &str,
        option: &str,
    ) -> Result<Option<f64>> {
        match self.get(section, option)? {
            None => Ok(None),
            Some(v) => v
                .trim()
                .parse::<f64>()
                .map(Some)
                .map_err(|_| Error::Parse(format!("not a float: {v:?}"))),
        }
    }

    /// [`get`](Self::get), parsed as a boolean (`configparser.getboolean`): one
    /// of `1`/`yes`/`true`/`on` or `0`/`no`/`false`/`off`, case-insensitively.
    pub fn get_bool(
        &self,
        section: &str,
        option: &str,
    ) -> Result<Option<bool>> {
        match self.get(section, option)? {
            None => Ok(None),
            Some(v) => match v.to_lowercase().as_str() {
                "1" | "yes" | "true" | "on" => Ok(Some(true)),
                "0" | "no" | "false" | "off" => Ok(Some(false)),
                _ => Err(Error::Parse(format!("not a boolean: {v:?}"))),
            },
        }
    }

    /// All `(key, value)` pairs visible in `section` (its own plus inherited
    /// `DEFAULT`), interpolated, or `None` if the section does not exist.
    pub fn items(
        &self,
        section: &str,
    ) -> Result<Option<Vec<(String, String)>>> {
        if !self.sections.contains(section) {
            return Ok(None);
        }
        let map = self.merged_map(section);
        let mut out = Vec::new();
        for (k, v) in map.iter() {
            let value = match v {
                None => String::new(),
                Some(s) => match self.interp {
                    Interp::None => s.clone(),
                    Interp::Basic => interp::before_get(k, s, &map)?,
                },
            };
            out.push((k.to_string(), value));
        }
        Ok(Some(out))
    }

    // --- mutation --------------------------------------------------------

    /// Add an empty section. Errors if it already exists or is named `DEFAULT`.
    pub fn add_section(&mut self, name: &str) -> Result<()> {
        if name == DEFAULT_SECTION {
            return Err(Error::Validation(format!(
                "invalid section name: {name:?}"
            )));
        }
        if self.sections.contains(name) {
            return Err(Error::Validation(format!(
                "section already exists: {name:?}"
            )));
        }
        self.sections.insert(name, Ordered::new());
        Ok(())
    }

    /// Set `option` in `section` to `value` (`None` is only meaningful with
    /// [`allow_no_value`](Self::allow_no_value)).
    ///
    /// The section must already exist, or be `DEFAULT`. For an interpolating
    /// config, a value with invalid `%` syntax is rejected (matching
    /// `ConfigParser.set`).
    pub fn set(
        &mut self,
        section: &str,
        option: &str,
        value: Option<&str>,
    ) -> Result<()> {
        if self.interp == Interp::Basic {
            if let Some(v) = value {
                interp::validate_set(v)?;
            }
        }
        let key = optionxform(option);
        let slot = if section == DEFAULT_SECTION {
            &mut self.defaults
        } else {
            self.sections.get_mut(section).ok_or_else(|| {
                Error::Validation(format!("no such section: {section:?}"))
            })?
        };
        slot.insert(&key, value.map(str::to_string));
        Ok(())
    }

    /// Set `option` to an integer, serialized as a plain decimal.
    pub fn set_int(
        &mut self,
        section: &str,
        option: &str,
        value: i64,
    ) -> Result<()> {
        self.set(section, option, Some(&value.to_string()))
    }

    /// Set `option` to a boolean, serialized as Python's `str(bool)` (`True` /
    /// `False`), which `configparser`'s boolean parsing reads back.
    pub fn set_bool(
        &mut self,
        section: &str,
        option: &str,
        value: bool,
    ) -> Result<()> {
        self.set(section, option, Some(if value { "True" } else { "False" }))
    }

    /// Remove a section and all its options; returns whether it existed.
    pub fn remove_section(&mut self, name: &str) -> bool {
        self.sections.remove(name).is_some()
    }

    /// Remove an option from `section` (or `DEFAULT`); returns whether it
    /// existed. Errors if the section does not exist.
    pub fn remove_option(
        &mut self,
        section: &str,
        option: &str,
    ) -> Result<bool> {
        let key = optionxform(option);
        let slot = if section == DEFAULT_SECTION {
            &mut self.defaults
        } else {
            self.sections.get_mut(section).ok_or_else(|| {
                Error::Validation(format!("no such section: {section:?}"))
            })?
        };
        Ok(slot.remove(&key).is_some())
    }

    // --- internals -------------------------------------------------------

    /// Section-over-DEFAULT raw lookup (the `configparser` `ChainMap` order).
    fn raw_lookup(&self, section: &str, key: &str) -> Option<&Option<String>> {
        if let Some(opts) = self.sections.get(section) {
            if let Some(v) = opts.get(key) {
                return Some(v);
            }
        }
        self.defaults.get(key)
    }

    /// The merged (DEFAULT, then section-override) raw values used both for
    /// interpolation variable lookups and for [`items`](Self::items).
    fn merged_map(&self, section: &str) -> Ordered<Option<String>> {
        let mut map = self.defaults.clone();
        if let Some(opts) = self.sections.get(section) {
            for (k, v) in opts.iter() {
                map.insert(k, v.clone());
            }
        }
        map
    }
}

/// The `optionxform` transform: `configparser` stores and looks up option keys
/// case-insensitively by lowercasing them (section names are left as-is).
fn optionxform(option: &str) -> String {
    option.to_lowercase()
}

/// Read a whole file to a UTF-8 `String`, opened symlink-safely.
fn read_file_to_string(path: &Path) -> Result<String> {
    let mut file = safe_open(
        AT_FDCWD,
        path,
        OFlag::O_RDONLY | OFlag::O_CLOEXEC,
        Mode::empty(),
    )?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)
        .map_err(|e| Errno::try_from(e).unwrap_or(Errno::EIO))?;
    String::from_utf8(buf)
        .map_err(|_| Error::Parse("config file is not valid UTF-8".into()))
}
