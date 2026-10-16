//! The journal transport against the real journald.
//!
//! Records go to the journal's own socket and are read back with
//! `journalctl -o export`, found by a field that names the run, so the test
//! checks what journald kept and not only what was sent. One case runs this
//! binary again as a systemd service of its own, where systemd sets
//! `JOURNAL_STREAM`, to check that `Journal::open` chooses the socket there.
//!
//! A machine with no journald, or one whose journal this user cannot read,
//! skips. `TRUENAS_ROS_REQUIRE_JOURNAL` turns either skip into a failure, as
//! the QEMU job sets it, where systemd runs and the job is root.
#![cfg(all(target_os = "linux", feature = "log"))]

#[path = "support/privilege.rs"]
mod privilege;

use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use truenas_ros::log::journal::{CUT, Journal, MAX_VALUE, SOCKET, STREAM_VAR};
use truenas_ros::log::{Level, Logger};

/// The `SYSLOG_IDENTIFIER=` of every record here.
const IDENTIFIER: &str = "truenas_ros_test";

/// The variable that tells this binary it runs as the child service.
const CHILD: &str = "TRUENAS_ROS_JOURNAL_CHILD";

/// Whether a skip should fail instead.
fn required() -> bool {
    std::env::var_os("TRUENAS_ROS_REQUIRE_JOURNAL").is_some()
}

/// Skip, or fail when the journal is required, saying why.
fn skip(why: &str) {
    assert!(!required(), "TRUENAS_ROS_REQUIRE_JOURNAL is set but {why}");
    eprintln!("SKIP the journal test, since {why}");
}

/// Whether journald listens and `journalctl` runs here.
fn journal_or_skip() -> bool {
    if !Path::new(SOCKET).exists() {
        skip("journald's socket is not there");
        return false;
    }
    let ran = Command::new("journalctl").arg("--version").output();
    if !ran.is_ok_and(|out| out.status.success()) {
        skip("journalctl does not run");
        return false;
    }
    true
}

/// A value no other run gives, for the field the records are found by.
fn run_id(what: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{what}-{}-{nanos}", std::process::id())
}

/// A logger that sends to journald's socket whatever the environment says.
fn native() -> (Arc<Journal>, Logger) {
    let journal =
        Arc::new(Journal::native(IDENTIFIER, Level::Debug, SOCKET).unwrap());
    (Arc::clone(&journal), Logger::new(journal))
}

/// One entry of `journalctl -o export`, its fields in order.
type Entry = Vec<(String, Vec<u8>)>;

/// The entries of the export format. A field is `NAME=value` and a newline,
/// or for a value that is not plain text, `NAME`, a newline, its length in
/// 64 bits little endian, the value and a newline. An empty line ends an
/// entry.
fn parse_export(mut bytes: &[u8]) -> Vec<Entry> {
    let mut entries = Vec::new();
    let mut entry = Entry::new();
    while !bytes.is_empty() {
        if bytes[0] == b'\n' {
            entries.push(std::mem::take(&mut entry));
            bytes = &bytes[1..];
            continue;
        }
        let end = bytes
            .iter()
            .position(|&b| b == b'=' || b == b'\n')
            .expect("a field name ends");
        let name = String::from_utf8(bytes[..end].to_vec()).unwrap();
        if bytes[end] == b'=' {
            let rest = &bytes[end + 1..];
            let len = rest.iter().position(|&b| b == b'\n').unwrap();
            entry.push((name, rest[..len].to_vec()));
            bytes = &rest[len + 1..];
        } else {
            let rest = &bytes[end + 1..];
            let len = u64::from_le_bytes(rest[..8].try_into().unwrap());
            let len = usize::try_from(len).unwrap();
            entry.push((name, rest[8..8 + len].to_vec()));
            bytes = &rest[8 + len + 1..];
        }
    }
    if !entry.is_empty() {
        entries.push(entry);
    }
    entries
}

/// The first value of `name` in `entry`, as text.
fn field<'a>(entry: &'a Entry, name: &str) -> Option<&'a str> {
    entry
        .iter()
        .find(|(n, _)| n == name)
        .map(|(_, v)| std::str::from_utf8(v).expect("UTF-8"))
}

/// The entries whose `TRUENAS_ROS_TEST` is `id`, once there are `want` of
/// them. journald may take a moment to write, so this asks for up to ten
/// seconds. None means they never came, which skips unless the journal is
/// required, since a user outside the journal's group reads none of it.
fn read_back(id: &str, want: usize) -> Option<Vec<Entry>> {
    let until = Instant::now() + Duration::from_secs(10);
    loop {
        let out = Command::new("journalctl")
            .args(["--no-pager", "-o", "export"])
            .arg(format!("TRUENAS_ROS_TEST={id}"))
            .output()
            .expect("journalctl runs");
        let entries = parse_export(&out.stdout);
        if entries.len() >= want {
            return Some(entries);
        }
        if Instant::now() > until {
            skip(&format!("journalctl found {} of {want}", entries.len()));
            return None;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[test]
fn a_record_lands_with_its_level_name_source_and_fields() {
    if !journal_or_skip() {
        return;
    }
    let (journal, logger) = native();
    let id = run_id("fields");
    let peer = "192.0.2.7";
    truenas_ros::log!(
        logger,
        Level::Warning,
        [TRUENAS_ROS_TEST = id, PEER = peer],
        "landed {id}"
    );
    assert_eq!(journal.lost(), 0);
    let Some(entries) = read_back(&id, 1) else {
        return;
    };
    assert_eq!(entries.len(), 1);
    let entry = &entries[0];
    assert_eq!(field(entry, "PRIORITY"), Some("4"));
    assert_eq!(field(entry, "SYSLOG_IDENTIFIER"), Some(IDENTIFIER));
    let message = format!("landed {id}");
    assert_eq!(field(entry, "MESSAGE"), Some(message.as_str()));
    assert_eq!(field(entry, "PEER"), Some(peer));
    let file = field(entry, "CODE_FILE").expect("the source file");
    assert!(file.ends_with("journal.rs"), "{file}");
    let line: u32 = field(entry, "CODE_LINE").unwrap().parse().unwrap();
    assert!(line > 0);
    // journald's own field says the record came by its protocol and not as
    // a line of stderr.
    assert_eq!(field(entry, "_TRANSPORT"), Some("journal"));
}

#[test]
fn each_level_lands_as_its_priority() {
    if !journal_or_skip() {
        return;
    }
    let (_journal, logger) = native();
    let id = run_id("levels");
    for level in Level::ALL {
        let name = level.as_str();
        truenas_ros::log!(
            logger,
            level,
            [TRUENAS_ROS_TEST = id, LEVEL = name],
            "at {name}"
        );
    }
    let Some(entries) = read_back(&id, Level::ALL.len()) else {
        return;
    };
    for level in Level::ALL {
        let entry = entries
            .iter()
            .find(|e| field(e, "LEVEL") == Some(level.as_str()))
            .expect("the record of each level");
        let priority = level.priority().to_string();
        assert_eq!(field(entry, "PRIORITY"), Some(priority.as_str()));
    }
}

/// A value with a newline is sent with its length, and journald keeps it
/// whole, as it keeps a message with a newline.
#[test]
fn a_value_with_a_newline_lands_whole() {
    if !journal_or_skip() {
        return;
    }
    let (_journal, logger) = native();
    let id = run_id("newline");
    let note = "first line\nsecond line";
    truenas_ros::log!(
        logger,
        Level::Notice,
        [TRUENAS_ROS_TEST = id, NOTE = note],
        "two\nlines"
    );
    let Some(entries) = read_back(&id, 1) else {
        return;
    };
    assert_eq!(field(&entries[0], "NOTE"), Some(note));
    assert_eq!(field(&entries[0], "MESSAGE"), Some("two\nlines"));
}

/// A value past the limit lands cut after the last whole character that
/// fits, with the mark of a cut after it.
#[test]
fn a_long_value_lands_cut_at_the_limit() {
    if !journal_or_skip() {
        return;
    }
    let (_journal, logger) = native();
    let id = run_id("long");
    let long = "é".repeat(MAX_VALUE);
    truenas_ros::log!(
        logger,
        Level::Notice,
        [TRUENAS_ROS_TEST = id, LONG = long],
        "long"
    );
    let Some(entries) = read_back(&id, 1) else {
        return;
    };
    let kept = field(&entries[0], "LONG").expect("the long field");
    let want = format!("{}{CUT}", "é".repeat(MAX_VALUE / 2));
    assert_eq!(kept, want);
}

/// `open` chooses the socket exactly when systemd said stderr is the
/// journal. The socket is addressed at each send and never connected, so
/// it is chosen even when journald is not there yet.
#[test]
fn open_follows_the_stream_variable() {
    let journal = Journal::open(IDENTIFIER, Level::Notice);
    let stream = std::env::var_os(STREAM_VAR).is_some();
    assert_eq!(journal.is_native(), stream);
}

/// This binary runs again as a service of its own, which runs only
/// `child_under_a_unit`. systemd sets `JOURNAL_STREAM` there, so `open`
/// must choose the socket, and the record must arrive by the journal's
/// protocol rather than as a line of the service's stderr.
#[test]
fn open_chooses_the_socket_under_a_unit() {
    if !journal_or_skip() || !privilege::root_or_skip("systemd-run") {
        return;
    }
    let ran = Command::new("systemd-run").arg("--version").output();
    if !ran.is_ok_and(|out| out.status.success()) {
        skip("systemd-run does not run");
        return;
    }
    let id = run_id("unit");
    let exe = std::env::current_exe().unwrap();
    let status = Command::new("systemd-run")
        .args(["--wait", "--quiet", "--collect"])
        .arg(format!("--setenv={CHILD}={id}"))
        .arg(&exe)
        .args(["--exact", "child_under_a_unit", "--ignored"])
        .status()
        .expect("systemd-run runs");
    assert!(status.success(), "the child service failed ({status})");
    let Some(entries) = read_back(&id, 1) else {
        return;
    };
    assert_eq!(entries.len(), 1);
    assert_eq!(field(&entries[0], "MESSAGE"), Some("from a unit"));
    assert_eq!(field(&entries[0], "_TRANSPORT"), Some("journal"));
}

/// The child of `open_chooses_the_socket_under_a_unit`, run as a service.
/// Run any other way it does nothing.
#[test]
#[ignore = "run only as a service by open_chooses_the_socket_under_a_unit"]
fn child_under_a_unit() {
    let Some(id) = std::env::var_os(CHILD) else {
        return;
    };
    let id = id.to_string_lossy().into_owned();
    let journal = Journal::open(IDENTIFIER, Level::Notice);
    assert!(journal.is_native(), "JOURNAL_STREAM chose the socket");
    let logger = Logger::new(Arc::new(journal));
    truenas_ros::log!(
        logger,
        Level::Notice,
        [TRUENAS_ROS_TEST = id],
        "from a unit"
    );
}
