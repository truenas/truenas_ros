use truenas_ros::Error;
use truenas_ros::configfile::ConfigFile;

#[test]
fn writes_global_section_byte_exact() {
    // The exact bytes the TrueNAS `configfile.py` wrapper emits via `configparser` for its `[GLOBAL]` section: keys
    // lowercased, `" = "` delimiter, `str(bool)` booleans, a trailing blank line.
    let mut cfg = ConfigFile::new();
    cfg.add_section("GLOBAL").unwrap();
    cfg.set_bool("GLOBAL", "Enabled", false).unwrap();
    cfg.set_int("GLOBAL", "MaxConcurrentJobs", 4).unwrap();
    cfg.set_int("GLOBAL", "ReportingStatsWriteInterval", 120).unwrap();
    cfg.set_int("GLOBAL", "RewriteChunkSize", 2048).unwrap();
    cfg.set_int("GLOBAL", "ReportingCallbackInterval", 200).unwrap();
    cfg.set_int("GLOBAL", "MaxUsedPercent", 85).unwrap();
    cfg.set_int("GLOBAL", "StatsFlushInterval", 1).unwrap();
    let expected = "[GLOBAL]\n\
             enabled = False\n\
             maxconcurrentjobs = 4\n\
             reportingstatswriteinterval = 120\n\
             rewritechunksize = 2048\n\
             reportingcallbackinterval = 200\n\
             maxusedpercent = 85\n\
             statsflushinterval = 1\n\n";
    assert_eq!(cfg.write_string(), expected);
}

#[test]
fn serialization_modes_and_multiline() {
    let mut cfg = ConfigFile::raw();
    cfg.read_str("[s]\nk = one\n  two\n").unwrap();
    // A newline in a value is re-indented with a tab.
    assert_eq!(cfg.write_string(), "[s]\nk = one\n\ttwo\n\n");
    // `space_around=false` drops the padding.
    assert_eq!(cfg.to_string_with(false), "[s]\nk=one\n\ttwo\n\n");
}

#[test]
fn default_section_written_first() {
    let mut cfg = ConfigFile::raw();
    cfg.read_str("[s]\nk = v\n[DEFAULT]\nd = 1\n").unwrap();
    assert_eq!(cfg.write_string(), "[DEFAULT]\nd = 1\n\n[s]\nk = v\n\n");
}

#[test]
fn keys_lowercased_sections_case_sensitive() {
    let mut cfg = ConfigFile::new();
    cfg.read_str("[Sec]\nKey = V\n[sec]\nKey = W\n").unwrap();
    assert_eq!(cfg.sections(), vec!["Sec", "sec"]);
    assert_eq!(cfg.get_raw("Sec", "KEY"), Some("V"));
    assert_eq!(cfg.get_raw("sec", "key"), Some("W"));
    assert!(cfg.has_section("Sec") && !cfg.has_section("SEC"));
}

#[test]
fn inline_comment_chars_are_not_comments() {
    let mut cfg = ConfigFile::new();
    cfg.read_str("# top\n[s]\n  ; indented\nk = a ; b\nj = c # d\n")
        .unwrap();
    assert_eq!(cfg.get_raw("s", "k"), Some("a ; b"));
    assert_eq!(cfg.get_raw("s", "j"), Some("c # d"));
}

#[test]
fn multiline_values_join_and_rstrip() {
    let mut cfg = ConfigFile::raw();
    cfg.read_str("[s]\nk = one\n  two\n\n  three\n  \n").unwrap();
    assert_eq!(cfg.get_raw("s", "k"), Some("one\ntwo\n\nthree"));
}

#[test]
fn default_inheritance_and_override() {
    let mut cfg = ConfigFile::new();
    cfg.read_str("[DEFAULT]\nd = base\nk = def\n[s]\nk = over\n").unwrap();
    assert_eq!(cfg.get("s", "d").unwrap().as_deref(), Some("base"));
    assert_eq!(cfg.get("s", "k").unwrap().as_deref(), Some("over"));
    assert!(cfg.has_option("s", "d"));
    let opts = cfg.options("s").unwrap();
    assert!(opts.iter().any(|o| o == "d"));
    assert!(opts.iter().any(|o| o == "k"));
}

#[test]
fn rejects_malformed_documents() {
    for doc in [
        "k = v\n",         // no section header
        "[s]\n[s]\n",      // duplicate section
        "[s]\nk=1\nk=2\n", // duplicate option
        "[s]\n = v\n",     // empty option name
        "[s]\n  orphan\n", // continuation with no prior option
    ] {
        assert!(
            matches!(ConfigFile::new().read_str(doc), Err(Error::Parse(_))),
            "should reject {doc:?}"
        );
    }
}

#[test]
fn typed_getters_and_bad_values() {
    let mut cfg = ConfigFile::new();
    cfg.read_str("[s]\nn = 42\nneg = -7\nf = 3.5\nb = ON\nbad = xx\n")
        .unwrap();
    assert_eq!(cfg.get_int("s", "n").unwrap(), Some(42));
    assert_eq!(cfg.get_int("s", "neg").unwrap(), Some(-7));
    assert_eq!(cfg.get_float("s", "f").unwrap(), Some(3.5));
    assert_eq!(cfg.get_bool("s", "b").unwrap(), Some(true));
    assert!(matches!(cfg.get_int("s", "bad"), Err(Error::Parse(_))));
    assert!(matches!(cfg.get_bool("s", "bad"), Err(Error::Parse(_))));
    assert_eq!(cfg.get_int("s", "absent").unwrap(), None);
}

#[test]
fn boolean_states() {
    let mut cfg = ConfigFile::new();
    cfg.read_str("[s]\na=1\nb=yes\nc=true\nd=on\ne=0\nf=no\ng=false\nh=off\n")
        .unwrap();
    for k in ["a", "b", "c", "d"] {
        assert_eq!(cfg.get_bool("s", k).unwrap(), Some(true));
    }
    for k in ["e", "f", "g", "h"] {
        assert_eq!(cfg.get_bool("s", k).unwrap(), Some(false));
    }
}

#[test]
fn interpolation_basic_and_escapes() {
    let mut cfg = ConfigFile::new();
    cfg.read_str("[DEFAULT]\nbase = /srv\n[s]\np = %(base)s/x\nlit = 100%%\n")
        .unwrap();
    assert_eq!(cfg.get("s", "p").unwrap().as_deref(), Some("/srv/x"));
    assert_eq!(cfg.get("s", "lit").unwrap().as_deref(), Some("100%"));
    // `get_raw` bypasses interpolation.
    assert_eq!(cfg.get_raw("s", "p"), Some("%(base)s/x"));
}

#[test]
fn interpolation_errors_and_depth_limit() {
    let mut cfg = ConfigFile::new();
    cfg.read_str("[s]\nbad = 50%\nmissing = %(nope)s\na = %(b)s\nb = %(a)s\n")
        .unwrap();
    assert!(matches!(cfg.get("s", "bad"), Err(Error::Parse(_))));
    assert!(matches!(cfg.get("s", "missing"), Err(Error::Parse(_))));
    assert!(matches!(cfg.get("s", "a"), Err(Error::Parse(_))));
}

#[test]
fn raw_mode_does_not_interpolate() {
    let mut cfg = ConfigFile::raw();
    cfg.read_str("[s]\np = %(x)s\nlit = 50%\n").unwrap();
    assert_eq!(cfg.get("s", "p").unwrap().as_deref(), Some("%(x)s"));
    assert_eq!(cfg.get("s", "lit").unwrap().as_deref(), Some("50%"));
}

#[test]
fn set_rejects_invalid_interpolation_but_raw_allows() {
    let mut cfg = ConfigFile::new();
    cfg.add_section("s").unwrap();
    assert!(matches!(cfg.set("s", "k", Some("50%")), Err(Error::Validation(_))));
    cfg.set("s", "k", Some("100%%")).unwrap();
    cfg.set("s", "k", Some("%(other)s")).unwrap();

    let mut raw = ConfigFile::raw();
    raw.add_section("s").unwrap();
    raw.set("s", "k", Some("50%")).unwrap();
}

#[test]
fn mutation_add_set_remove() {
    let mut cfg = ConfigFile::new();
    cfg.add_section("s").unwrap();
    assert!(matches!(cfg.add_section("s"), Err(Error::Validation(_))));
    assert!(matches!(cfg.add_section("DEFAULT"), Err(Error::Validation(_))));
    assert!(matches!(cfg.set("missing", "k", Some("v")), Err(Error::Validation(_))));
    cfg.set("s", "k", Some("v")).unwrap();
    assert!(cfg.has_option("s", "k"));
    assert!(cfg.remove_option("s", "k").unwrap());
    assert!(!cfg.remove_option("s", "k").unwrap());
    assert!(cfg.remove_section("s"));
    assert!(!cfg.remove_section("s"));
    assert!(matches!(cfg.remove_option("gone", "k"), Err(Error::Validation(_))));
}

#[test]
fn allow_no_value_parses_and_writes_bare_keys() {
    let mut cfg = ConfigFile::new().allow_no_value(true);
    cfg.read_str("[s]\nflag\nk = v\n").unwrap();
    assert!(cfg.has_option("s", "flag"));
    assert_eq!(cfg.get_raw("s", "flag"), None);
    assert_eq!(cfg.write_string(), "[s]\nflag\nk = v\n\n");
    // Without the flag, a bare key is a parse error.
    assert!(matches!(
        ConfigFile::new().read_str("[s]\nflag\n"),
        Err(Error::Parse(_))
    ));
}

#[test]
fn multiple_reads_merge_and_override() {
    let mut cfg = ConfigFile::raw();
    cfg.read_str("[s]\na = 1\nb = 2\n").unwrap();
    cfg.read_str("[s]\nb = 20\nc = 3\n").unwrap();
    assert_eq!(cfg.get_raw("s", "a"), Some("1"));
    assert_eq!(cfg.get_raw("s", "b"), Some("20"));
    assert_eq!(cfg.get_raw("s", "c"), Some("3"));
}
