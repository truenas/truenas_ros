//! Differential tests that prove the `configfile` module behaves byte-for-byte
//! and semantically like Python's standard-library `configparser`.
//!
//! Each corpus document is fed to the real `configparser` (via
//! `test/support/configparser_oracle.py`) and to [`ConfigFile`]; the results are
//! required to agree on serialization (both `space_around` modes), raw and
//! interpolated `get`, the typed getters, and — crucially — whether the document
//! is accepted or rejected at all. The corpus is a curated table of every parsing
//! subtlety plus a large batch of seeded-random documents.
//!
//! Like `test/zfs.rs`, this suite **skips** (returns early) when `python3` is not
//! available, so `cargo test` stays green in a bare sandbox. CI sets
//! `TRUENAS_ROS_REQUIRE_PYTHON` so a missing interpreter is a hard failure there
//! rather than a silent skip, guaranteeing the parity checks actually run. Point
//! it at a specific interpreter with `TRUENAS_ROS_PYTHON`, and/or a specific
//! `configparser` with `TRUENAS_ROS_CPYTHON_LIB` (added to `PYTHONPATH`).
#![cfg(all(target_os = "linux", feature = "configfile"))]

use std::io::Write;
use std::process::{Command, Stdio};
use truenas_ros::configfile::ConfigFile;

// ---- oracle plumbing ------------------------------------------------------

/// One result field from the oracle: a value, or the exception marker.
#[derive(Debug)]
enum OResult {
    Ok(String),
    Err,
}

/// The oracle's view of one `(section, option)` pair.
#[derive(Debug)]
struct Probe {
    section: String,
    option: String,
    get: OResult,
    int: OResult,
    float: OResult,
    boolean: OResult,
}

/// The oracle's full view of one document.
#[derive(Debug)]
enum Oracle {
    /// `configparser` rejected the document.
    ParseErr,
    /// `configparser` accepted it; here is everything it reported.
    Ok {
        spaced: Vec<u8>,
        tight: Vec<u8>,
        probes: Vec<Probe>,
    },
}

/// Resolve the interpreter, returning `None` (→ skip) if it cannot run.
fn python() -> Option<String> {
    let py = std::env::var("TRUENAS_ROS_PYTHON")
        .unwrap_or_else(|_| "python3".to_string());
    let ok = Command::new(&py)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if ok {
        return Some(py);
    }
    // In CI, TRUENAS_ROS_REQUIRE_PYTHON is set so a missing interpreter is a hard
    // failure (the differential coverage must actually run); locally, absent that
    // variable, we skip gracefully.
    assert!(
        std::env::var_os("TRUENAS_ROS_REQUIRE_PYTHON").is_none(),
        "TRUENAS_ROS_REQUIRE_PYTHON is set but python3 ({py:?}) is not runnable"
    );
    None
}

fn oracle_script() -> String {
    format!(
        "{}/test/support/configparser_oracle.py",
        env!("CARGO_MANIFEST_DIR")
    )
}

/// A cursor over the oracle's length-prefixed record stream.
struct Reader<'a> {
    data: &'a [u8],
}

impl Reader<'_> {
    fn field(&mut self) -> Vec<u8> {
        let nl = self
            .data
            .iter()
            .position(|&b| b == b'\n')
            .expect("field length line");
        let len: usize = std::str::from_utf8(&self.data[..nl])
            .unwrap()
            .parse()
            .unwrap();
        let start = nl + 1;
        let field = self.data[start..start + len].to_vec();
        self.data = &self.data[start + len..];
        field
    }

    fn field_str(&mut self) -> String {
        String::from_utf8(self.field()).unwrap()
    }

    fn result(&mut self) -> OResult {
        let status = self.field();
        let value = self.field_str();
        if status == b"ok" {
            OResult::Ok(value)
        } else {
            OResult::Err
        }
    }
}

fn parse_stream(data: &[u8]) -> Oracle {
    let mut r = Reader { data };
    if r.field() == b"err" {
        return Oracle::ParseErr;
    }
    let spaced = r.field();
    let tight = r.field();
    let nprobes: usize = r.field_str().parse().unwrap();
    let mut probes = Vec::with_capacity(nprobes);
    for _ in 0..nprobes {
        probes.push(Probe {
            section: r.field_str(),
            option: r.field_str(),
            get: r.result(),
            int: r.result(),
            float: r.result(),
            boolean: r.result(),
        });
    }
    Oracle::Ok {
        spaced,
        tight,
        probes,
    }
}

fn run_oracle(py: &str, doc: &str) -> Oracle {
    let mut cmd = Command::new(py);
    cmd.arg(oracle_script());
    if let Some(lib) = std::env::var_os("TRUENAS_ROS_CPYTHON_LIB") {
        cmd.env("PYTHONPATH", lib);
    }
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = cmd.spawn().expect("spawn python oracle");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(doc.as_bytes())
        .expect("write document to oracle");
    let out = child.wait_with_output().expect("wait for oracle");
    assert!(out.status.success(), "oracle process failed for {doc:?}");
    parse_stream(&out.stdout)
}

// ---- the differential assertions ------------------------------------------

fn assert_doc(py: &str, doc: &str, check_typed: bool) {
    let oracle = run_oracle(py, doc);

    let mut rraw = ConfigFile::raw();
    let raw_res = rraw.read_str(doc);
    let mut rnew = ConfigFile::new();
    let new_res = rnew.read_str(doc);

    let (spaced, tight, probes) = match oracle {
        Oracle::ParseErr => {
            assert!(
                raw_res.is_err(),
                "python rejected but rust(raw) accepted: {doc:?}"
            );
            assert!(
                new_res.is_err(),
                "python rejected but rust(new) accepted: {doc:?}"
            );
            return;
        }
        Oracle::Ok {
            spaced,
            tight,
            probes,
        } => (spaced, tight, probes),
    };

    raw_res.unwrap_or_else(|e| {
        panic!("python accepted but rust(raw) rejected {doc:?}: {e:?}")
    });
    new_res.unwrap_or_else(|e| {
        panic!("python accepted but rust(new) rejected {doc:?}: {e:?}")
    });

    // Serialization parity (both delimiter-padding modes). `write` does not
    // interpolate, so the interpolating parser must serialize identically.
    assert_serialization(&rraw.write_string(), &spaced, doc, "spaced");
    assert_serialization(&rraw.to_string_with(false), &tight, doc, "tight");
    assert_serialization(&rnew.write_string(), &spaced, doc, "interp-spaced");

    for p in &probes {
        // Interpolated get() through the interpolating parser.
        match &p.get {
            OResult::Err => assert!(
                rnew.get(&p.section, &p.option).is_err(),
                "expected get() error at [{}] {} in {doc:?}",
                p.section,
                p.option
            ),
            OResult::Ok(v) => assert_eq!(
                rnew.get(&p.section, &p.option).unwrap().as_deref(),
                Some(v.as_str()),
                "get() mismatch at [{}] {} in {doc:?}",
                p.section,
                p.option
            ),
        }
        if check_typed {
            assert_int(&rnew, p, doc);
            assert_float(&rnew, p, doc);
            assert_bool(&rnew, p, doc);
        }
    }

    // Rust's serialization must itself reparse to the same bytes (write/parse
    // symmetry); combined with the parity above this pins full round-tripping.
    let s1 = rraw.write_string();
    let mut reparsed = ConfigFile::raw();
    reparsed.read_str(&s1).unwrap_or_else(|e| {
        panic!("reparse of own output failed {doc:?}: {e:?}")
    });
    assert_eq!(
        reparsed.write_string(),
        s1,
        "serialization is not idempotent for {doc:?}"
    );
}

fn assert_serialization(got: &str, want: &[u8], doc: &str, which: &str) {
    assert_eq!(
        got.as_bytes(),
        want,
        "{which} serialization mismatch for {doc:?}\n  rust: {got:?}\n  py:   {:?}",
        String::from_utf8_lossy(want)
    );
}

fn assert_int(cfg: &ConfigFile, p: &Probe, doc: &str) {
    let got = cfg.get_int(&p.section, &p.option);
    match &p.int {
        OResult::Err => assert!(
            got.is_err(),
            "expected getint error at [{}] {} in {doc:?}, got {got:?}",
            p.section,
            p.option
        ),
        OResult::Ok(v) => {
            let want: i64 = v.parse().expect("oracle integer");
            assert_eq!(
                got.unwrap(),
                Some(want),
                "getint mismatch at [{}] {} in {doc:?}",
                p.section,
                p.option
            );
        }
    }
}

fn assert_float(cfg: &ConfigFile, p: &Probe, doc: &str) {
    let got = cfg.get_float(&p.section, &p.option);
    match &p.float {
        OResult::Err => assert!(
            got.is_err(),
            "expected getfloat error at [{}] {} in {doc:?}, got {got:?}",
            p.section,
            p.option
        ),
        OResult::Ok(v) => {
            let want: f64 = v.parse().expect("oracle float");
            assert_eq!(
                got.unwrap(),
                Some(want),
                "getfloat mismatch at [{}] {} in {doc:?}",
                p.section,
                p.option
            );
        }
    }
}

fn assert_bool(cfg: &ConfigFile, p: &Probe, doc: &str) {
    let got = cfg.get_bool(&p.section, &p.option);
    match &p.boolean {
        OResult::Err => assert!(
            got.is_err(),
            "expected getboolean error at [{}] {} in {doc:?}, got {got:?}",
            p.section,
            p.option
        ),
        OResult::Ok(v) => {
            let want = v == "true";
            assert_eq!(
                got.unwrap(),
                Some(want),
                "getboolean mismatch at [{}] {} in {doc:?}",
                p.section,
                p.option
            );
        }
    }
}

// ---- corpus 1: curated edge cases -----------------------------------------

/// Every parsing/serialization subtlety, hand-picked. Typed getters are checked
/// for all of these (the values are controlled).
const CURATED: &[&str] = &[
    "",
    "[s]\n",
    "[s]\nk = v\n",
    "[s]\nk=v\n",
    "[s]\nk : v\n",
    "[s]\nKey = Value\n", // keys are lowercased
    "[Section]\na=1\n[section]\nb=2\n", // section names are case-sensitive
    "[s]\n  k = v\n",     // an indented option
    "[s]\nk = a ; b\n",   // inline ';' is NOT a comment
    "[s]\nk = a # b\n",   // inline '#' is NOT a comment either
    "# lead comment\n[s]\nk = v\n", // full-line comment
    "[s]\n  ; indented comment\n  k=v\n", // indented full-line comment
    "[s]\nk =\n",         // empty value
    "[s]\nk = line1\n  line2\n  line3\n", // multi-line value
    "[s]\nk = line1\n\n  line3\n", // blank line inside a value
    "[s]\nk = a=b=c\n",   // first delimiter splits
    "[a]b]\nk = v\n",     // header greedy to last ']'
    "[DEFAULT]\nd = base\n[s]\nk = v\n", // DEFAULT inheritance
    "[DEFAULT]\nk = def\n[s]\nk = over\n", // section overrides DEFAULT
    "[s]\nn = 42\nneg = -7\nz = 0\n", // integers
    "[s]\nf = 3.14\ng = 1e3\nh = -0.5\n", // floats
    "[s]\nb1 = yes\nb2 = Off\nb3 = TRUE\nb4 = 0\n", // booleans, mixed case
    "[s]\npct = 100%%\n", // '%%' escapes to '%'
    "[DEFAULT]\nbase = /srv\n[s]\np = %(base)s/data\n", // interpolation
    "[s]\na = 1\nb = %(a)s%(a)s\nc = %(b)s\n", // chained interpolation
    "[s]\nbad = 50%\n",   // invalid interpolation → get() errs
    // Documents `configparser` rejects (Rust must reject them too):
    "k = v\n",                      // no section header
    "[s]\n[s]\n",                   // duplicate section
    "[s]\nk = 1\nk = 2\n",          // duplicate option
    "[s]\n = novalue\n",            // empty option name
    "[s]\n  orphan continuation\n", // continuation with no prior option
];

#[test]
fn curated_corpus_matches_configparser() {
    let Some(py) = python() else {
        eprintln!("skipping: python3 not available");
        return;
    };
    for doc in CURATED {
        assert_doc(&py, doc, true);
    }
}

// ---- corpus 2: seeded-random documents ------------------------------------

/// A tiny reproducible xorshift64 PRNG (no `rand` dependency, fixed seed so the
/// corpus is identical on every run).
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    fn pick<'s>(&mut self, xs: &[&'s str]) -> &'s str {
        xs[self.below(xs.len())]
    }
}

/// Build a random-but-plausible INI document, biased toward interesting shapes
/// (sections, delimiters, comments, indentation, `%` sequences, empties).
fn random_doc(rng: &mut Rng) -> String {
    let sections = ["s1", "s2", "DEFAULT", "Sec", "a]b", "x y"];
    let keys = ["k", "Key", "a", "b c", "n", "flag"];
    let values = [
        "v", "1", "true", "%(k)s", "50%", "%%", "x = y", "", "a ; b", "-3",
    ];
    let junk = ["[", "]", "=", ":", "%", "key", "(a)s", " ", "\t", "#", ";"];

    let mut s = String::new();
    // Often open with a section so more documents reach the serialization path.
    if rng.below(2) == 0 {
        s.push_str("[s1]\n");
    }
    let nlines = 1 + rng.below(10);
    for _ in 0..nlines {
        match rng.below(7) {
            0 => {
                s.push('[');
                s.push_str(rng.pick(&sections));
                s.push(']');
            }
            1 | 2 => {
                if rng.below(3) == 0 {
                    s.push_str("  "); // indent (maybe a continuation)
                }
                s.push_str(rng.pick(&keys));
                s.push_str(if rng.below(2) == 0 { " = " } else { ":" });
                s.push_str(rng.pick(&values));
            }
            3 => s.push_str(rng.pick(&["# comment", "; comment", "   "])),
            4 => {
                let n = rng.below(5);
                for _ in 0..n {
                    s.push_str(rng.pick(&junk));
                }
            }
            _ => s.push_str(rng.pick(&keys)),
        }
        s.push('\n');
    }
    s
}

#[test]
fn random_corpus_matches_configparser() {
    let Some(py) = python() else {
        eprintln!("skipping: python3 not available");
        return;
    };
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    for _ in 0..500 {
        let doc = random_doc(&mut rng);
        // Values are arbitrary here, so only exercise structure/serialization
        // and interpolated get(), not the numeric/boolean converters.
        assert_doc(&py, &doc, false);
    }
}
