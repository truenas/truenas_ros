//! The journal transport. A record goes as one datagram in the journal's
//! own form, sent without blocking, and is counted when it cannot be.
//!
//! Under systemd a daemon's stderr is a stream to journald, and a write to
//! it blocks for as long as the journal is behind. The journal's own socket
//! takes datagrams instead, and a send lands whole or fails at once, so the
//! thread that logs never waits. A record that fails is not queued, since a
//! queue is a thread and a lock, and a daemon may fork after it starts
//! logging, as one with a credential broker does. It is counted, and the
//! count is said in the next record that lands, so the gap shows where it
//! was.
//!
//! systemd says whether stderr is the journal with `JOURNAL_STREAM`. When it
//! is not, records go to stderr as lines, for a terminal or for a harness
//! that runs the daemon, and a failed write is ignored, since a closed or
//! broken stderr is no reason to stop serving.

use std::ffi::OsStr;
use std::fmt::{self, Write as _};
use std::io::{self, Write as _};
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};

use super::{Event, Field, Level, Sink};

/// Where journald listens for its own protocol.
pub const SOCKET: &str = "/run/systemd/journal/socket";

/// The variable systemd sets when stderr is the journal.
pub const STREAM_VAR: &str = "JOURNAL_STREAM";

/// The most of one value that is kept. A record is one datagram, sized
/// against the send buffer of the socket, so a longer value is cut at a
/// character boundary and ends in [`CUT`].
pub const MAX_VALUE: usize = 4096;

/// What a cut value ends in.
pub const CUT: &str = "…";

#[derive(Debug)]
enum Transport {
    Native { socket: UnixDatagram, path: PathBuf },
    Stderr,
}

/// The sink a daemon reports through.
#[derive(Debug)]
pub struct Journal {
    identifier: &'static str,
    level: AtomicU8,
    lost: AtomicU64,
    transport: Transport,
}

impl Journal {
    /// The journal's own socket when stderr is the journal, and stderr
    /// otherwise. `identifier` is the `SYSLOG_IDENTIFIER=` of each record
    /// and the start of each stderr line.
    pub fn open(identifier: &'static str, level: Level) -> Self {
        let stream = std::env::var_os(STREAM_VAR);
        let transport = match choose(stream.as_deref()) {
            Some(path) => native(path).unwrap_or(Transport::Stderr),
            None => Transport::Stderr,
        };
        Self::with(identifier, level, transport)
    }

    /// The journal's protocol to a socket at `path`, for a test's own
    /// listener.
    pub fn native(
        identifier: &'static str,
        level: Level,
        path: impl Into<PathBuf>,
    ) -> io::Result<Self> {
        Ok(Self::with(identifier, level, native(&path.into())?))
    }

    /// Lines on stderr.
    pub fn stderr(identifier: &'static str, level: Level) -> Self {
        Self::with(identifier, level, Transport::Stderr)
    }

    fn with(
        identifier: &'static str,
        level: Level,
        transport: Transport,
    ) -> Self {
        Self {
            identifier,
            level: AtomicU8::new(level.priority()),
            lost: AtomicU64::new(0),
            transport,
        }
    }

    /// Whether records go to the journal's socket rather than stderr.
    pub fn is_native(&self) -> bool {
        matches!(self.transport, Transport::Native { .. })
    }

    /// The threshold, which is the least serious level kept.
    pub fn level(&self) -> Level {
        Level::from_priority(self.level.load(Ordering::Relaxed))
    }

    /// Move the threshold, from any thread, as a reload does.
    pub fn set_level(&self, level: Level) {
        self.level.store(level.priority(), Ordering::Relaxed);
    }

    /// The records that could not be sent and are not yet counted in one
    /// that was.
    pub fn lost(&self) -> u64 {
        self.lost.load(Ordering::Relaxed)
    }

    fn send(&self, socket: &UnixDatagram, path: &Path, event: &Event<'_>) {
        // The gap is said before the record after it, so the count sits
        // where the records are missing. If that notice fails too, the
        // count goes back and the next record that lands says it.
        let lost = self.lost.swap(0, Ordering::Relaxed);
        if lost > 0 {
            let mut notice = Vec::with_capacity(128);
            encode(
                &mut notice,
                self.identifier,
                &Event {
                    level: Level::Warning,
                    source: None,
                    message: format_args!("{lost} log records lost"),
                    fields: &[Field::new("LOST", &lost)],
                },
            );
            if socket.send_to(&notice, path).is_err() {
                self.lost.fetch_add(lost, Ordering::Relaxed);
            }
        }
        let mut record = Vec::with_capacity(256);
        encode(&mut record, self.identifier, event);
        if socket.send_to(&record, path).is_err() {
            self.lost.fetch_add(1, Ordering::Relaxed);
        }
    }
}

impl Sink for Journal {
    fn enabled(&self, level: Level) -> bool {
        level.priority() <= self.level.load(Ordering::Relaxed)
    }

    fn emit(&self, event: &Event<'_>) {
        match &self.transport {
            Transport::Native { socket, path } => {
                self.send(socket, path, event);
            }
            Transport::Stderr => {
                let mut line = String::with_capacity(128);
                render_line(&mut line, self.identifier, event);
                let _ = io::stderr().lock().write_all(line.as_bytes());
            }
        }
    }
}

/// The socket to use given `JOURNAL_STREAM`, or none for stderr.
fn choose(stream: Option<&OsStr>) -> Option<&'static Path> {
    stream.map(|_| Path::new(SOCKET))
}

/// An unbound datagram socket that does not block, aimed at `path`. It is
/// addressed at each send rather than connected, so a journal that restarts
/// and binds again is reached with nothing here noticing.
fn native(path: &Path) -> io::Result<Transport> {
    let socket = UnixDatagram::unbound()?;
    socket.set_nonblocking(true)?;
    Ok(Transport::Native {
        socket,
        path: path.to_path_buf(),
    })
}

/// One record in the journal's own form. A value with no newline is
/// `NAME=value` and a newline. One with a newline is `NAME`, a newline, its
/// length in 64 bits little endian, the value and a newline.
pub(crate) fn encode(buf: &mut Vec<u8>, identifier: &str, event: &Event<'_>) {
    push(buf, "PRIORITY", &event.level.priority());
    push(buf, "SYSLOG_IDENTIFIER", &identifier);
    push(buf, "MESSAGE", &event.message);
    if let Some(source) = event.source {
        push(buf, "CODE_FILE", &source.file);
        push(buf, "CODE_LINE", &source.line);
    }
    for field in event.fields {
        push(buf, field.name(), field.value());
    }
}

fn push(buf: &mut Vec<u8>, name: &str, value: &dyn fmt::Display) {
    buf.extend_from_slice(name.as_bytes());
    buf.push(b'=');
    let at = buf.len();
    write_bounded(buf, value);
    if buf[at..].contains(&b'\n') {
        let len = (buf.len() - at) as u64;
        buf[at - 1] = b'\n';
        buf.splice(at..at, len.to_le_bytes());
    }
    buf.push(b'\n');
}

/// A `fmt::Write` over the end of a buffer that stops at a limit, keeping
/// whole every character it keeps.
struct Bounded<'a> {
    buf: &'a mut Vec<u8>,
    end: usize,
    cut: bool,
}

impl fmt::Write for Bounded<'_> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        if self.cut {
            return Ok(());
        }
        let room = self.end - self.buf.len();
        if s.len() <= room {
            self.buf.extend_from_slice(s.as_bytes());
            return Ok(());
        }
        let mut keep = room;
        while !s.is_char_boundary(keep) {
            keep -= 1;
        }
        self.buf.extend_from_slice(&s.as_bytes()[..keep]);
        self.cut = true;
        Ok(())
    }
}

fn write_bounded(buf: &mut Vec<u8>, value: &dyn fmt::Display) {
    let end = buf.len() + MAX_VALUE;
    let mut bounded = Bounded {
        buf,
        end,
        cut: false,
    };
    let _ = write!(bounded, "{value}");
    if bounded.cut {
        bounded.buf.extend_from_slice(CUT.as_bytes());
    }
}

/// One record as a stderr line. It is the identifier, the level when it is
/// not notice or info, the message, and then the fields as `NAME=value`,
/// with a value quoted when it would not read as one word.
pub(crate) fn render_line(
    line: &mut String,
    identifier: &str,
    event: &Event<'_>,
) {
    let _ = write!(line, "{identifier}: ");
    match event.level {
        Level::Notice | Level::Info => {}
        level => {
            let _ = write!(line, "{level}: ");
        }
    }
    let _ = write!(line, "{}", event.message);
    for field in event.fields {
        let value = field.value().to_string();
        let one_word = !value.is_empty()
            && value.chars().all(|c| !c.is_whitespace() && !c.is_control());
        if one_word {
            let _ = write!(line, " {}={value}", field.name());
        } else {
            let _ = write!(line, " {}={value:?}", field.name());
        }
    }
    line.push('\n');
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::log::{Logger, Source};
    use crate::{TempDir, tempdir};

    fn event<'a>(
        level: Level,
        message: fmt::Arguments<'a>,
        fields: &'a [Field<'a>],
    ) -> Event<'a> {
        Event {
            level,
            source: None,
            message,
            fields,
        }
    }

    fn encoded(event: &Event<'_>) -> Vec<u8> {
        let mut buf = Vec::new();
        encode(&mut buf, "d", event);
        buf
    }

    #[test]
    fn a_plain_value_is_one_line() {
        let path = "/mnt/a";
        let buf = encoded(&event(
            Level::Info,
            format_args!("served"),
            &[Field::new("PATH", &path)],
        ));
        assert_eq!(
            buf,
            b"PRIORITY=6\nSYSLOG_IDENTIFIER=d\nMESSAGE=served\nPATH=/mnt/a\n"
        );
    }

    #[test]
    fn the_source_goes_as_code_file_and_line() {
        let buf = encoded(&Event {
            level: Level::Error,
            source: Some(Source {
                file: "src/x.rs",
                line: 7,
            }),
            message: format_args!("m"),
            fields: &[],
        });
        assert_eq!(
            buf,
            b"PRIORITY=3\nSYSLOG_IDENTIFIER=d\nMESSAGE=m\nCODE_FILE=src/x.rs\nCODE_LINE=7\n"
        );
    }

    /// A value with a newline takes the form with a length, and the fields
    /// around it keep the plain one.
    #[test]
    fn a_value_with_a_newline_carries_its_length() {
        let name = "a\nb";
        let buf = encoded(&event(
            Level::Info,
            format_args!("served"),
            &[Field::new("NAME", &name), Field::new("AFTER", &1)],
        ));
        let mut want =
            b"PRIORITY=6\nSYSLOG_IDENTIFIER=d\nMESSAGE=served\nNAME\n".to_vec();
        want.extend_from_slice(&3u64.to_le_bytes());
        want.extend_from_slice(b"a\nb\nAFTER=1\n");
        assert_eq!(buf, want);
    }

    #[test]
    fn a_message_with_a_newline_carries_its_length_too() {
        let buf = encoded(&event(Level::Info, format_args!("x\ny"), &[]));
        let mut want = b"PRIORITY=6\nSYSLOG_IDENTIFIER=d\nMESSAGE\n".to_vec();
        want.extend_from_slice(&3u64.to_le_bytes());
        want.extend_from_slice(b"x\ny\n");
        assert_eq!(buf, want);
    }

    /// A cut lands on a character boundary, so a value of two byte
    /// characters is cut after the last whole one that fits.
    #[test]
    fn a_long_value_is_cut_whole() {
        let long = "é".repeat(MAX_VALUE);
        let buf = encoded(&event(
            Level::Info,
            format_args!("m"),
            &[Field::new("V", &long)],
        ));
        let text = std::str::from_utf8(&buf).expect("still UTF-8");
        let value = text
            .lines()
            .find_map(|l| l.strip_prefix("V="))
            .expect("the field");
        assert!(value.ends_with(CUT));
        let kept = value.strip_suffix(CUT).unwrap();
        assert_eq!(kept.len(), MAX_VALUE);
        assert_eq!(kept.chars().count(), MAX_VALUE / 2);
        assert!(kept.chars().all(|c| c == 'é'));
    }

    /// One ASCII byte ahead of two byte characters puts the limit inside a
    /// character, which is then left out whole.
    #[test]
    fn a_cut_inside_a_character_keeps_it_whole() {
        let long = format!("a{}", "é".repeat(MAX_VALUE));
        let buf = encoded(&event(
            Level::Info,
            format_args!("m"),
            &[Field::new("V", &long)],
        ));
        let text = std::str::from_utf8(&buf).expect("still UTF-8");
        let value = text
            .lines()
            .find_map(|l| l.strip_prefix("V="))
            .expect("the field");
        let kept = value.strip_suffix(CUT).expect("cut");
        assert_eq!(kept.len(), MAX_VALUE - 1);
        assert!(kept.starts_with('a'));
    }

    /// A value that arrives in pieces, from a `Display` that writes several
    /// times, is cut across the pieces and not in each.
    #[test]
    fn a_cut_holds_across_pieces() {
        struct Pieces;
        impl fmt::Display for Pieces {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                for _ in 0..MAX_VALUE {
                    f.write_str("ab")?;
                }
                Ok(())
            }
        }
        let buf = encoded(&event(
            Level::Info,
            format_args!("m"),
            &[Field::new("V", &Pieces)],
        ));
        let text = std::str::from_utf8(&buf).unwrap();
        let value = text.lines().find_map(|l| l.strip_prefix("V=")).unwrap();
        assert_eq!(value.len(), MAX_VALUE + CUT.len());
    }

    #[test]
    fn an_exact_fit_is_not_cut() {
        let exact = "a".repeat(MAX_VALUE);
        let buf = encoded(&event(
            Level::Info,
            format_args!("m"),
            &[Field::new("V", &exact)],
        ));
        let text = std::str::from_utf8(&buf).unwrap();
        let value = text.lines().find_map(|l| l.strip_prefix("V=")).unwrap();
        assert_eq!(value, exact);
    }

    #[test]
    fn a_stderr_line_names_the_level_only_when_it_is_not_ordinary() {
        let mut line = String::new();
        let name = "two words";
        render_line(
            &mut line,
            "d",
            &event(
                Level::Info,
                format_args!("served /a"),
                &[Field::new("SHARE", &"a"), Field::new("NAME", &name)],
            ),
        );
        assert_eq!(line, "d: served /a SHARE=a NAME=\"two words\"\n");
        line.clear();
        render_line(
            &mut line,
            "d",
            &event(Level::Notice, format_args!("listening"), &[]),
        );
        assert_eq!(line, "d: listening\n");
        line.clear();
        render_line(
            &mut line,
            "d",
            &event(Level::Warning, format_args!("degraded"), &[]),
        );
        assert_eq!(line, "d: warning: degraded\n");
        line.clear();
        render_line(
            &mut line,
            "d",
            &event(Level::Error, format_args!("e"), &[Field::new("E", &"")]),
        );
        assert_eq!(line, "d: error: e E=\"\"\n");
    }

    #[test]
    fn the_threshold_gates_and_moves() {
        let journal = Journal::stderr("t", Level::Notice);
        assert!(!journal.is_native());
        assert!(journal.enabled(Level::Error));
        assert!(journal.enabled(Level::Notice));
        assert!(!journal.enabled(Level::Info));
        journal.set_level(Level::Debug);
        assert_eq!(journal.level(), Level::Debug);
        assert!(journal.enabled(Level::Debug));
        journal.set_level(Level::Error);
        assert!(!journal.enabled(Level::Warning));
    }

    #[test]
    fn without_the_stream_variable_stderr_is_chosen() {
        assert_eq!(choose(None), None);
        assert_eq!(
            choose(Some(OsStr::new("8:12345"))),
            Some(Path::new(SOCKET))
        );
    }

    /// A listener in a directory of its own, standing in for journald.
    struct Listener {
        socket: UnixDatagram,
        path: PathBuf,
        _dir: TempDir,
    }

    impl Listener {
        fn bind() -> Listener {
            let dir = tempdir().unwrap();
            let path = dir.path().join("j");
            let socket = UnixDatagram::bind(&path).unwrap();
            socket.set_nonblocking(true).unwrap();
            Listener {
                socket,
                path,
                _dir: dir,
            }
        }

        fn recv(&self) -> Option<Vec<u8>> {
            let mut buf = vec![0; 64 * 1024];
            match self.socket.recv(&mut buf) {
                Ok(n) => {
                    buf.truncate(n);
                    Some(buf)
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => None,
                Err(e) => panic!("{e}"),
            }
        }
    }

    #[test]
    fn a_record_reaches_the_socket_whole() {
        let listener = Listener::bind();
        let journal =
            Journal::native("d", Level::Info, &listener.path).unwrap();
        assert!(journal.is_native());
        journal.emit(&event(
            Level::Notice,
            format_args!("listening"),
            &[Field::new("PORT", &2049)],
        ));
        assert_eq!(
            listener.recv().unwrap(),
            b"PRIORITY=5\nSYSLOG_IDENTIFIER=d\nMESSAGE=listening\nPORT=2049\n"
        );
        assert_eq!(listener.recv(), None);
        assert_eq!(journal.lost(), 0);
    }

    /// The listener's queue fills, a send then fails at once rather than
    /// waiting, and once the queue drains the gap is said before the next
    /// record.
    #[test]
    fn a_full_queue_loses_records_and_the_gap_is_said_first() {
        let listener = Listener::bind();
        let journal = std::sync::Arc::new(
            Journal::native("d", Level::Info, &listener.path).unwrap(),
        );
        let logger = Logger::new(journal.clone());
        let mut sent = 0u64;
        while journal.lost() == 0 {
            crate::log!(logger, Level::Info, "record {sent}");
            sent += 1;
            assert!(sent < 100_000, "the queue never filled");
        }
        let landed = sent - 1;
        for _ in 0..3 {
            crate::log!(logger, Level::Info, "more");
        }
        assert_eq!(journal.lost(), 4);
        let mut drained = 0;
        while listener.recv().is_some() {
            drained += 1;
        }
        assert_eq!(drained, landed);
        crate::log!(logger, Level::Info, "after");
        assert_eq!(journal.lost(), 0);
        let notice = String::from_utf8(listener.recv().unwrap()).unwrap();
        assert!(notice.contains("PRIORITY=4\n"), "{notice}");
        assert!(notice.contains("MESSAGE=4 log records lost\n"), "{notice}");
        assert!(notice.contains("LOST=4\n"), "{notice}");
        let after = String::from_utf8(listener.recv().unwrap()).unwrap();
        assert!(after.contains("MESSAGE=after\n"), "{after}");
        assert_eq!(listener.recv(), None);
    }

    /// With no listener at the path nothing waits and nothing panics, and
    /// the loss is counted for a listener that comes later.
    #[test]
    fn a_missing_listener_is_a_counted_loss() {
        let listener = Listener::bind();
        let path = listener.path.clone();
        drop(listener);
        let journal = Journal::native("d", Level::Info, &path).unwrap();
        journal.emit(&event(Level::Error, format_args!("gone"), &[]));
        assert_eq!(journal.lost(), 1);
    }

    #[test]
    fn a_level_below_the_threshold_costs_no_send() {
        let listener = Listener::bind();
        let journal =
            Journal::native("d", Level::Warning, &listener.path).unwrap();
        let logger = Logger::new(std::sync::Arc::new(journal));
        crate::log!(logger, Level::Info, "quiet");
        assert_eq!(listener.recv(), None);
    }
}
