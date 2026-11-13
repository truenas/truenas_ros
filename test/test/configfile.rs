use std::os::unix::fs::PermissionsExt;
use truenas_ros::Error;
use truenas_ros::configfile::ConfigFile;
use truenas_ros::sync_fs::AtomicWriteOptions;

// Two halves: a name `set` accepts must survive `write_string` + `read_str` unchanged, and one it cannot must be
// refused rather than written. Rejecting everything would satisfy the first half alone.
#[test]
fn an_option_name_that_cannot_round_trip_is_refused() {
    let hostile = [
        "x\n[global]\nadmin", // splits the record; injects a section
        "[global]",           // read back as a header on its own
        "a=b",                // re-split at the delimiter
        "a:b",                // ... and at the other one
        "  indented",         // folded into the previous option's value
        "trailing ",          // stripped back off
        "# nope",             // read back as a comment
        ";nope",
        "",
        "has\rcr", // a line break once read_path applies universal newlines
    ];
    for name in hostile {
        let mut cfg = ConfigFile::new();
        cfg.add_section("app").unwrap();
        cfg.set("app", "first", Some("1")).unwrap();
        assert!(
            cfg.set("app", name, Some("v")).is_err(),
            "set accepted an option name it cannot read back: {name:?}"
        );
    }

    // The screen is not simply refusing everything: ordinary names, and the awkward-but-safe ones, still go through
    // and still round-trip.
    let benign = ["plain", "with space", "dot.sep", "pct%%", "0", "x[y]"];
    for name in benign {
        let mut cfg = ConfigFile::raw();
        cfg.add_section("app").unwrap();
        cfg.set("app", name, Some("v")).unwrap();
        let mut back = ConfigFile::raw();
        back.read_str(&cfg.write_string())
            .unwrap_or_else(|e| panic!("{name:?} wrote a document that will not reparse: {e:?}"));
        assert_eq!(back.sections(), vec!["app"], "for {name:?}");
        assert_eq!(
            back.get_raw("app", name),
            Some("v"),
            "{name:?} did not survive the round trip"
        );
    }
}

// A section name carrying a line break closes its header early, and the remainder becomes a section of its own.
#[test]
fn a_section_name_that_cannot_round_trip_is_refused() {
    for name in ["x]\n[global", "", "a\rb"] {
        let mut cfg = ConfigFile::new();
        assert!(cfg.add_section(name).is_err(), "add_section accepted {name:?}");
    }
    // A `]` inside or at the end is fine: a header runs to the *last* one.
    for name in ["a]b", "a]", " padded "] {
        let mut cfg = ConfigFile::raw();
        cfg.add_section(name).unwrap();
        cfg.set(name, "k", Some("v")).unwrap();
        let mut back = ConfigFile::raw();
        back.read_str(&cfg.write_string()).unwrap();
        assert_eq!(back.sections(), vec![name], "for {name:?}");
    }
}

// A shallow-but-wide interpolation (one value referencing another ~2000 times, each ~1 KiB) expands past the output
// budget; the getter must error rather than build a multi-megabyte string. The input stays shallow so this
// exercises the output cap, not the depth cap.
#[test]
fn interpolation_output_is_bounded() {
    let big = "x".repeat(1024);
    let refs = "%(a)s".repeat(2048); // 2048 * ~1 KiB > 1 MiB budget
    let src = format!("[s]\na = {big}\nb = {refs}\n");
    let mut cfg = ConfigFile::new();
    cfg.read_str(&src).unwrap();
    assert!(cfg.get("s", "b").is_err(), "expected interpolation to be bounded");
    // A modest interpolation still resolves.
    assert_eq!(cfg.get("s", "a").unwrap().as_deref(), Some(big.as_str()));
}

#[test]
fn write_path_is_atomic_with_mode_and_round_trips() {
    let dir = truenas_ros::tempdir().unwrap();
    let path = dir.path().join("app.conf");
    let mut cfg = ConfigFile::new();
    cfg.add_section("main").unwrap();
    cfg.set("main", "name", Some("value")).unwrap();
    cfg.set_int("main", "count", 7).unwrap();

    let opts = AtomicWriteOptions {
        mode: 0o600,
        ..Default::default()
    };
    cfg.write_path(&path, opts).unwrap();

    // The requested mode is applied (configparser would not do this).
    assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    // No temporary file is left behind by the atomic write.
    let leftovers: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .filter(|n| n != "app.conf")
        .collect();
    assert!(leftovers.is_empty(), "temp files left: {leftovers:?}");

    // It round-trips through read_path.
    let mut back = ConfigFile::new();
    back.read_path(&path).unwrap();
    assert_eq!(back.get("main", "name").unwrap().as_deref(), Some("value"));
    assert_eq!(back.get_int("main", "count").unwrap(), Some(7));
}

#[test]
fn read_path_errors_on_missing_read_paths_skips() {
    let dir = truenas_ros::tempdir().unwrap();
    let present = dir.path().join("a.conf");
    std::fs::write(&present, b"[s]\nk = v\n").unwrap();
    let missing = dir.path().join("nope.conf");

    // A single read of a missing file is an error.
    assert!(ConfigFile::new().read_path(&missing).is_err());

    // read_paths skips the missing file and returns those actually read.
    let mut cfg = ConfigFile::new();
    let read = cfg.read_paths([missing, present.clone()]).unwrap();
    assert_eq!(read, vec![present]);
    assert_eq!(cfg.get_raw("s", "k"), Some("v"));
}

#[test]
fn read_path_rejects_symlinked_component() {
    let dir = truenas_ros::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("real")).unwrap();
    std::fs::write(dir.path().join("real/c.conf"), b"[s]\nk=v\n").unwrap();
    std::os::unix::fs::symlink("real", dir.path().join("link")).unwrap();
    let via_link = dir.path().join("link/c.conf");
    assert!(matches!(
        ConfigFile::new().read_path(&via_link),
        Err(Error::SymlinkInPath { .. })
    ));
}

#[test]
fn on_disk_bytes_are_stable_across_reparse() {
    let dir = truenas_ros::tempdir().unwrap();
    let path = dir.path().join("s.conf");
    let mut cfg = ConfigFile::raw();
    cfg.read_str("[a]\nx = 1\n[b]\ny = two words\n").unwrap();
    cfg.write_path(&path, AtomicWriteOptions::default()).unwrap();

    let on_disk = std::fs::read_to_string(&path).unwrap();
    assert_eq!(on_disk, cfg.write_string());

    let mut back = ConfigFile::raw();
    back.read_path(&path).unwrap();
    assert_eq!(back.write_string(), on_disk);
}
