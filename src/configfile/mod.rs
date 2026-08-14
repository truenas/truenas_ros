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
//! # Secret-bearing files
//!
//! A configuration built with [`ConfigFile::scrubbed`] burns every buffer
//! this module allocates for it — the file image, the parse accumulators,
//! and the stored keys and values — with a volatile zeroing pass as each is
//! released, so dropping the configuration leaves no heap copies behind.
//! With the `secrets` feature, [`ConfigFile::read_secret_path`] additionally
//! stages the raw file image in `memfd_secret`-backed memory, off the
//! ordinary heap entirely.
//!
//! The guarantee's edges are stated rather than implied. Stored values are
//! ordinary heap memory while the configuration lives — swappable, and
//! visible in a core dump — so a long-lived secret belongs in
//! [`Secret`](crate::secrets::Secret), moved there promptly from
//! [`get_raw`](ConfigFile::get_raw). Whatever an accessor returns
//! ([`get`](ConfigFile::get), [`items`](ConfigFile::items),
//! [`write_string`](ConfigFile::write_string)) is the caller's copy and the
//! caller's to burn, as is a [`read_str`](ConfigFile::read_str) input
//! buffer. Interpolation intermediates are not chased — [`raw`][ConfigFile::raw]
//! is the secrets configuration — nor are transient key copies in parse
//! control state, and the kernel's page cache retains what was read from
//! disk regardless of anything a process does.
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

    /// Upsert; a displaced value is returned, never silently dropped, so a
    /// scrubbing caller can burn it.
    fn insert(&mut self, key: &str, value: V) -> Option<V> {
        if let Some(&i) = self.index.get(key) {
            Some(std::mem::replace(&mut self.entries[i].1, value))
        } else {
            self.index.insert(key.to_string(), self.entries.len());
            self.entries.push((key.to_string(), value));
            None
        }
    }

    /// Remove, handing back both stored copies of the key (the index's and
    /// the entry's) along with the value, so a scrubbing caller can burn
    /// them.
    fn remove(&mut self, key: &str) -> Option<(String, String, V)> {
        let (index_key, i) = self.index.remove_entry(key)?;
        let (entry_key, v) = self.entries.remove(i);
        // Entries after `i` shifted down by one; fix their recorded positions
        // in place (no key is cloned or displaced doing it).
        for pos in i..self.entries.len() {
            if let Some(slot) = self.index.get_mut(self.entries[pos].0.as_str())
            {
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
}

/// An INI configuration, compatible with Python's `configparser`.
///
/// Build one with [`new`](Self::new) (interpolating, like `ConfigParser`) or
/// [`raw`](Self::raw) (like `RawConfigParser`), populate it by reading a string
/// or file, query it with the typed getters, and serialize it back with
/// [`write_string`](Self::write_string) or [`write_path`](Self::write_path).
#[derive(Clone)]
pub struct ConfigFile {
    defaults: Ordered<Option<String>>,
    sections: Ordered<Ordered<Option<String>>>,
    interp: Interp,
    allow_no_value: bool,
    scrub: bool,
}

/// Prints the full structure for an ordinary configuration; a scrubbed one
/// prints shape only — a secrets-bearing configuration reaching a log must
/// not carry its values.
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

/// Burning happens on release: whatever the configuration still holds when
/// it drops is scrubbed here.
impl Drop for ConfigFile {
    fn drop(&mut self) {
        if !self.scrub {
            return;
        }
        scrub_opts(&mut self.defaults);
        for (name, opts) in &mut self.sections.entries {
            scrub_string(name);
            scrub_opts(opts);
        }
        for (mut key, _) in self.sections.index.drain() {
            scrub_string(&mut key);
        }
    }
}

/// Burn a string's whole allocation, spare capacity included — a truncated
/// value keeps its old tail bytes past `len`.
///
/// Zero bytes are valid UTF-8, so the string stays sound until it drops.
fn scrub_string(s: &mut String) {
    // SAFETY: the vec's buffer is `capacity` writable bytes, and an
    // all-zero prefix keeps the content valid UTF-8.
    unsafe {
        let v = s.as_mut_vec();
        crate::scrub::scrub(v.as_mut_ptr(), v.capacity());
    }
}

/// Burn one section's storage: every key (the index's copies included) and
/// every value.
fn scrub_opts(opts: &mut Ordered<Option<String>>) {
    for (key, value) in &mut opts.entries {
        scrub_string(key);
        if let Some(value) = value {
            scrub_string(value);
        }
    }
    for (mut key, _) in opts.index.drain() {
        scrub_string(&mut key);
    }
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
            scrub: false,
        }
    }

    /// Create an empty configuration with interpolation disabled, matching
    /// `configparser.RawConfigParser()`. Values round-trip verbatim.
    pub fn raw() -> Self {
        let mut cfg = Self::new();
        cfg.interp = Interp::None;
        cfg
    }

    /// Allow keys with no value (a bare `key` with no `=`/`:`), matching
    /// `configparser`'s `allow_no_value=True`. Off by default.
    pub fn allow_no_value(mut self, yes: bool) -> Self {
        self.allow_no_value = yes;
        self
    }

    /// Burn every buffer this configuration allocates — the file image,
    /// parse accumulators, and stored keys and values — with a volatile
    /// zeroing pass as each is released, the whole store included when the
    /// configuration drops. For files that carry secrets; see the module
    /// docs for exactly where the guarantee ends. Off by default.
    ///
    /// Parsing and every accessor behave identically either way, with one
    /// exception: an error for a duplicate option names its position but
    /// not the key, which in a credentials file is an identifier that must
    /// not reach a log.
    pub fn scrubbed(mut self, yes: bool) -> Self {
        self.scrub = yes;
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
    /// [`Error::Parse`]. Line endings are decoded with universal newlines, as
    /// `configparser.read()` gets from `open(filename)`.
    pub fn read_path(&mut self, path: &Path) -> Result<()> {
        if self.scrub {
            return self.read_path_scrubbed(path);
        }
        let text = read_file_to_string(path)?;
        parse::read(self, &path.display().to_string(), &text)
    }

    /// [`read_path`](Self::read_path) for a scrubbed configuration: one
    /// buffer pre-sized from the file's length (no reallocation trail),
    /// newlines normalized in place instead of by copy, and the buffer
    /// burned to its full capacity on every exit — the UTF-8 and parse
    /// failures included.
    fn read_path_scrubbed(&mut self, path: &Path) -> Result<()> {
        let mut file = safe_open(
            AT_FDCWD,
            path,
            OFlag::O_RDONLY | OFlag::O_CLOEXEC,
            Mode::empty(),
        )?;
        let len = file
            .metadata()
            .map_err(|e| Errno::try_from(e).unwrap_or(Errno::EIO))?
            .len() as usize;
        let mut buf = ScrubVec(Vec::with_capacity(len + 1));
        file.read_to_end(&mut buf.0)
            .map_err(|e| Errno::try_from(e).unwrap_or(Errno::EIO))?;
        normalize_newlines(&mut buf.0);
        let text = std::str::from_utf8(&buf.0).map_err(|_| {
            Error::Parse("config file is not valid UTF-8".into())
        })?;
        parse::read(self, &path.display().to_string(), text)
    }

    /// Read and parse `path` with the raw file image staged in
    /// `memfd_secret`-backed memory
    /// ([`SecretMem`](crate::secrets::SecretMem)) — off the kernel's direct
    /// map, off swap, absent from core dumps — and burned when the read
    /// ends. The image never touches the ordinary heap.
    ///
    /// Reading this way marks the configuration
    /// [`scrubbed`](Self::scrubbed): the parse output it produces will be
    /// burned on release like the image was.
    ///
    /// Fails where `memfd_secret` is unavailable rather than degrading to
    /// an ordinary read.
    #[cfg(feature = "secrets")]
    pub fn read_secret_path(&mut self, path: &Path) -> Result<()> {
        self.scrub = true;
        let mut file = safe_open(
            AT_FDCWD,
            path,
            OFlag::O_RDONLY | OFlag::O_CLOEXEC,
            Mode::empty(),
        )?;
        let len = file
            .metadata()
            .map_err(|e| Errno::try_from(e).unwrap_or(Errno::EIO))?
            .len() as usize;
        let source = path.display().to_string();
        if len == 0 {
            return parse::read(self, &source, "");
        }
        let mut mem = crate::secrets::SecretMem::with_capacity(len + 1)?;
        let slice = mem.as_mut_slice();
        let mut filled = 0;
        loop {
            let n = file
                .read(&mut slice[filled..])
                .map_err(|e| Errno::try_from(e).unwrap_or(Errno::EIO))?;
            if n == 0 {
                break;
            }
            filled += n;
            if filled == slice.len() {
                // More content than the size the open saw: the image no
                // longer fits the staging region, so start over rather
                // than parse a torn read.
                return Err(Error::Validation(
                    "config file grew while being read".into(),
                ));
            }
        }
        let content = normalize_newlines_slice(&mut slice[..filled]);
        let text = std::str::from_utf8(&slice[..content]).map_err(|_| {
            Error::Parse("config file is not valid UTF-8".into())
        })?;
        parse::read(self, &source, text)
    }

    /// Read each path in turn, **skipping** any that cannot be opened (missing,
    /// unreadable, or containing a symlink component), and return the paths
    /// actually read — the behavior of `configparser.read([...])`. A file that
    /// opens but fails to parse (or is not UTF-8) still returns an error. Line
    /// endings are decoded as in [`read_path`](Self::read_path).
    pub fn read_paths<I>(&mut self, paths: I) -> Result<Vec<PathBuf>>
    where
        I: IntoIterator<Item = PathBuf>,
    {
        let mut read = Vec::new();
        for path in paths {
            if self.scrub {
                match self.read_path_scrubbed(&path) {
                    Ok(()) => read.push(path),
                    // The same skip classes as below; a parse failure
                    // still fails.
                    Err(Error::Errno(_)) | Err(Error::SymlinkInPath { .. }) => {
                        continue
                    }
                    Err(e) => return Err(e),
                }
                continue;
            }
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
        let mut text = self.write_string();
        let result = atomic_replace(path, text.as_bytes(), opts);
        // The serialization buffer carried every value; for a scrubbed
        // configuration it is burned on both outcomes. (The page-cache copy
        // the write itself creates is the file's, not this process's.)
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

    /// The option keys visible in `section` (its own keys plus inherited
    /// `DEFAULT` keys), or `None` if the section does not exist. Keys are
    /// lowercased.
    ///
    /// The section's own keys come first, in file order, then the `DEFAULT`
    /// keys it did not override. That is `configparser.options`, which copies
    /// the section and `update`s it with the defaults — the opposite order
    /// from [`items`](Self::items), which builds up from the defaults instead.
    /// The two disagree in CPython and so they disagree here.
    pub fn options(&self, section: &str) -> Option<Vec<String>> {
        let opts = self.sections.get(section)?;
        let mut merged: Vec<String> = opts.keys().map(str::to_string).collect();
        merged.extend(
            self.defaults
                .keys()
                .filter(|k| !opts.contains(k))
                .map(str::to_string),
        );
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

    /// The raw (un-interpolated) value of `option` in `section`, falling back to
    /// `DEFAULT`. Returns `None` if the option is absent or valueless, or if the
    /// section does not exist.
    pub fn get_raw(&self, section: &str, option: &str) -> Option<&str> {
        let key = optionxform(option);
        self.raw_lookup(section, &key).and_then(|v| v.as_deref())
    }

    /// The value of `option` in `section`, with `%(name)s` interpolation applied
    /// (unless this is a [`raw`](Self::raw) config), falling back to `DEFAULT`.
    ///
    /// Returns `Ok(None)` if the option is absent or valueless, and `Err` if the
    /// section does not exist (`configparser` raises `NoSectionError`) or if
    /// interpolation fails.
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
                let mut map = self.merged_map(section);
                let got = interp::before_get(&key, raw, &map);
                if self.scrub {
                    scrub_opts(&mut map);
                }
                Ok(Some(got?))
            }
        }
    }

    /// [`get`](Self::get), parsed as an integer (`configparser.getint`).
    /// `Ok(None)` if absent; `Err` if the value is not a valid integer.
    ///
    /// # Where this and `int()` part company
    ///
    /// The conversion is Rust's. `configparser` hands the string to `int()`,
    /// which additionally accepts underscores between digits (`1_000`), any
    /// Unicode decimal digit (`١٢٣`), and a magnitude no machine integer
    /// holds; [`get_float`](Self::get_float) inherits the first two from
    /// `float()`. All three are errors here, and matching them would mean an
    /// arbitrary-precision integer and a port of Python's numeric-literal
    /// grammar for values a config file does not plausibly contain.
    ///
    /// Every difference runs the same way — Python accepts something this
    /// rejects. Neither getter returns a *different* number from the one
    /// `configparser` would, so a value that converts here converts there to
    /// the same thing.
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
        let mut map = self.merged_map(section);
        let walk = || -> Result<Vec<(String, String)>> {
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
            Ok(out)
        };
        let out = walk();
        if self.scrub {
            scrub_opts(&mut map);
        }
        Ok(Some(out?))
    }

    // --- mutation --------------------------------------------------------

    /// Add an empty section. Errors if it already exists, is named `DEFAULT`,
    /// or could not be read back as itself (see [`set`](Self::set)).
    pub fn add_section(&mut self, name: &str) -> Result<()> {
        if let Some(why) = parse::section_fault(name) {
            return Err(Error::Validation(format!(
                "section name {name:?} {why}"
            )));
        }
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
    ///
    /// # Option names are screened
    ///
    /// A name [`write_string`](Self::write_string) could not emit and read
    /// back as itself is rejected: one containing a line break or a `=`/`:`
    /// delimiter, surrounded by whitespace, or opening with `[`, `#` or `;`.
    /// `parse::key_fault` has the rules.
    ///
    /// `configparser` screens the value and the argument types, never the
    /// name (`RawConfigParser.set`, `Lib/configparser.py:922`), so INI syntax
    /// in a name reaches its output intact: on CPython 3.13
    /// `set(s, "[global]", v)` writes a file that reads back carrying a
    /// section the caller never asked for. Storing externally-supplied names
    /// as options there is an injection primitive. Values keep
    /// `configparser`'s behaviour exactly.
    pub fn set(
        &mut self,
        section: &str,
        option: &str,
        value: Option<&str>,
    ) -> Result<()> {
        let key = optionxform(option);
        if let Some(why) = parse::key_fault(&key) {
            return Err(Error::Validation(format!(
                "option name {option:?} {why}"
            )));
        }
        if self.interp == Interp::Basic {
            if let Some(v) = value {
                interp::validate_set(v)?;
            }
        }
        let scrub = self.scrub;
        let slot = if section == DEFAULT_SECTION {
            &mut self.defaults
        } else {
            self.sections.get_mut(section).ok_or_else(|| {
                Error::Validation(format!("no such section: {section:?}"))
            })?
        };
        if let Some(mut old) = slot.insert(&key, value.map(str::to_string)) {
            if scrub {
                if let Some(old) = old.as_mut() {
                    scrub_string(old);
                }
            }
        }
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

    /// Remove an option from `section` (or `DEFAULT`); returns whether it
    /// existed. Errors if the section does not exist.
    pub fn remove_option(
        &mut self,
        section: &str,
        option: &str,
    ) -> Result<bool> {
        let key = optionxform(option);
        let scrub = self.scrub;
        let slot = if section == DEFAULT_SECTION {
            &mut self.defaults
        } else {
            self.sections.get_mut(section).ok_or_else(|| {
                Error::Validation(format!("no such section: {section:?}"))
            })?
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

    /// Whether `section` can be addressed at all: `DEFAULT` always can, even
    /// with no `sections` entry of its own. Any other name that was never
    /// defined is an error, as `configparser` raises `NoSectionError`.
    fn require_section(&self, section: &str) -> Result<()> {
        if section == DEFAULT_SECTION || self.sections.contains(section) {
            Ok(())
        } else {
            Err(Error::Validation(format!("no such section: {section:?}")))
        }
    }

    /// Section-over-DEFAULT raw lookup (the `configparser` `ChainMap` order).
    /// A section that does not exist inherits nothing: DEFAULT is only reachable
    /// through a section that does, or under its own name.
    fn raw_lookup(&self, section: &str, key: &str) -> Option<&Option<String>> {
        match self.sections.get(section) {
            Some(opts) => opts.get(key).or_else(|| self.defaults.get(key)),
            None if section == DEFAULT_SECTION => self.defaults.get(key),
            None => None,
        }
    }

    /// The merged (DEFAULT, then section-override) raw values used both for
    /// interpolation variable lookups and for [`items`](Self::items).
    /// The temporary holds value clones; a scrubbed configuration's callers
    /// burn it with [`scrub_opts`] after use, and a default clone displaced
    /// by a section override is burned here rather than dropped.
    fn merged_map(&self, section: &str) -> Ordered<Option<String>> {
        let mut map = self.defaults.clone();
        if let Some(opts) = self.sections.get(section) {
            for (k, v) in opts.iter() {
                if let Some(mut old) = map.insert(k, v.clone()) {
                    if self.scrub {
                        if let Some(old) = old.as_mut() {
                            scrub_string(old);
                        }
                    }
                }
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

/// A read buffer burned to its full capacity when it drops, whichever way
/// the read ends.
struct ScrubVec(Vec<u8>);

impl Drop for ScrubVec {
    fn drop(&mut self) {
        // SAFETY: the allocation is live and `capacity` bytes of it are
        // writable.
        unsafe {
            crate::scrub::scrub(self.0.as_mut_ptr(), self.0.capacity());
        }
    }
}

/// [`universal_newlines`] in place over a `Vec`: `\r\n` and a lone `\r`
/// become `\n` with no reallocation, so no unscrubbed copy of the content
/// is left behind. Bytes past the new length keep their old content, which
/// is why the buffer is burned to capacity, not length.
fn normalize_newlines(buf: &mut Vec<u8>) {
    let len = normalize_newlines_slice(buf);
    buf.truncate(len);
}

/// [`normalize_newlines`] over a slice, returning the content's new length.
/// `\r` and `\n` are ASCII, so the rewrite cannot fall inside a multi-byte
/// UTF-8 sequence.
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

/// Read a whole file to a UTF-8 `String`, opened symlink-safely, with line
/// endings translated by [`universal_newlines`].
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
    let text = String::from_utf8(buf)
        .map_err(|_| Error::Parse("config file is not valid UTF-8".into()))?;
    Ok(universal_newlines(text))
}

/// Translate `\r\n` and a lone `\r` to `\n`, the universal-newline decoding
/// Python's `open(filename)` — and so `configparser.read()` — applies.
///
/// Only the file entry points need this: `read_string`, which
/// [`ConfigFile::read_str`] mirrors, wraps the text in a `StringIO` with
/// `newline='\n'`, which passes `\r` through verbatim.
fn universal_newlines(text: String) -> String {
    if text.contains('\r') {
        text.replace("\r\n", "\n").replace('\r', "\n")
    } else {
        text
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The same document, default vs scrubbed: parsing, reading back, and
    /// serialization must be indistinguishable — scrubbing changes when
    /// buffers are burned, never what the configuration means.
    #[test]
    fn scrubbed_parses_identically() {
        let doc = "[DEFAULT]\nshared = base\n\n[db]\npassword = hunter2\n\
                   multi = one\n  two\n\n  three\n# comment\n[empty]\n";
        let over = "[db]\npassword = swordfish\n";
        let dir = crate::tempdir().unwrap();
        let path = dir.path().join("cfg.ini");
        // CRLF endings exercise the in-place translation against the
        // copying one over a real read.
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

    /// The burn covers the allocation's spare capacity: a truncated value
    /// keeps its old tail bytes past `len`, and they must go too.
    #[test]
    fn scrub_string_burns_the_whole_allocation() {
        let mut s = String::with_capacity(32);
        s.push_str("supersecretvalue");
        s.truncate(5);
        scrub_string(&mut s);
        // SAFETY: `scrub_string` wrote every capacity byte, so extending
        // `len` over them reads initialized memory, and all-zero content
        // is valid UTF-8.
        unsafe {
            let v = s.as_mut_vec();
            let cap = v.capacity();
            v.set_len(cap);
            assert!(v.iter().all(|&b| b == 0), "unburned bytes remain");
        }
    }

    /// The in-place newline translation must match the copying one byte
    /// for byte — `\r\r\n` and a trailing `\r` included.
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

    /// A duplicate-option error from a scrubbed configuration must not
    /// name the key: in a credentials file it is an identifier that must
    /// not reach a log.
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

    /// Debug output of a scrubbed configuration carries structure only; a
    /// configuration holding secrets that reaches a log must not print
    /// them.
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

    /// Overwrite, removal, and re-serialization behave identically in
    /// scrub mode: the burn happens on release, never in semantics.
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

    /// `read_secret_path` stages the image off-heap and yields the same
    /// configuration, marked scrubbed.
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
        std::fs::write(&path, "[user]\r\nsecret_access_key = sw0rdf1sh\r\n")
            .unwrap();
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
}
