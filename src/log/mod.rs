//! What a daemon says about itself. A record has a level and named fields,
//! a sink keeps it, and a [`Logger`] is the handle code reports through.
//!
//! A record is structured rather than a line, because the journal it lands
//! in indexes fields and an operator asks it by field
//! (`journalctl PEER=192.0.2.7`). The message is for a reader and the fields
//! are for a query, and a value is in both only when a reader needs it.
//!
//! The handle is passed in and never global, the way a clock is. Code under
//! test is handed a [`capture::Capture`], and the test asserts on what was
//! said. Nothing is formatted until the sink has said the level is on, so a
//! record below the threshold costs one load and one compare.
//!
//! [`journal::Journal`] is the sink of a daemon, which never blocks the
//! thread that logs. What must never be said, such as a secret, is a rule of
//! the code that holds the value, not of this module.
#![deny(unsafe_code)]

pub mod capture;
pub mod journal;

use std::fmt;
use std::str::FromStr;
use std::sync::Arc;

/// How serious a record is, numbered as the journal numbers its
/// priorities, so the two never need a table between them. They are
/// ordered from most to least serious, so a threshold keeps everything up
/// to itself.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[repr(u8)]
pub enum Level {
    /// Something failed that an operator must act on.
    Error = 3,
    /// Something degraded that the daemon is living with.
    Warning = 4,
    /// A lifecycle event, such as a start, a reload or a stop. It is the
    /// threshold a daemon gets without asking.
    #[default]
    Notice = 5,
    /// A request served, when an access log is wanted.
    Info = 6,
    /// Detail for a developer, off unless asked for.
    Debug = 7,
}

impl Level {
    /// Every level, most serious first.
    pub const ALL: [Level; 5] = [
        Level::Error,
        Level::Warning,
        Level::Notice,
        Level::Info,
        Level::Debug,
    ];

    /// The name a configuration file uses.
    pub const fn as_str(self) -> &'static str {
        match self {
            Level::Error => "error",
            Level::Warning => "warning",
            Level::Notice => "notice",
            Level::Info => "info",
            Level::Debug => "debug",
        }
    }

    /// The journal's `PRIORITY=` number.
    pub const fn priority(self) -> u8 {
        self as u8
    }

    pub(crate) const fn from_priority(n: u8) -> Level {
        match n {
            0..=3 => Level::Error,
            4 => Level::Warning,
            5 => Level::Notice,
            6 => Level::Info,
            _ => Level::Debug,
        }
    }
}

impl fmt::Display for Level {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A level name that is none of the five.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnknownLevel(pub String);

impl fmt::Display for UnknownLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "unknown log level {:?}, which is not error, warning, notice, \
             info or debug",
            self.0
        )
    }
}

impl std::error::Error for UnknownLevel {}

impl FromStr for Level {
    type Err = UnknownLevel;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Level::ALL
            .into_iter()
            .find(|level| level.as_str() == s)
            .ok_or_else(|| UnknownLevel(s.to_string()))
    }
}

/// Where in the source a record was made, for the journal's `CODE_FILE=`
/// and `CODE_LINE=`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Source {
    /// `file!()` at the call.
    pub file: &'static str,
    /// `line!()` at the call.
    pub line: u32,
}

/// One named value of a record.
#[derive(Clone, Copy)]
pub struct Field<'a> {
    name: &'static str,
    value: &'a dyn fmt::Display,
}

impl<'a> Field<'a> {
    /// A field. The name must be one the journal takes, which is uppercase
    /// letters, digits and underscores, at most 64 of them, starting with a
    /// letter, since a name starting with an underscore is the journal's
    /// own. The journal enforces this when a record arrives, so it is
    /// checked here, where a mistake fails a test rather than leaving a
    /// silent gap.
    pub fn new(name: &'static str, value: &'a dyn fmt::Display) -> Self {
        debug_assert!(is_field_name(name), "bad field name {name:?}");
        Self { name, value }
    }

    /// The field's name.
    pub fn name(&self) -> &'static str {
        self.name
    }

    /// The field's value.
    pub fn value(&self) -> &'a dyn fmt::Display {
        self.value
    }
}

impl fmt::Debug for Field<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}={}", self.name, self.value)
    }
}

/// Whether the journal would take `name` as the name of a field.
pub fn is_field_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    match bytes.first() {
        Some(first) if first.is_ascii_uppercase() => {
            bytes.len() <= 64
                && bytes.iter().all(|c| {
                    c.is_ascii_uppercase() || c.is_ascii_digit() || *c == b'_'
                })
        }
        _ => false,
    }
}

/// One record, as a sink receives it.
#[derive(Clone, Copy, Debug)]
pub struct Event<'a> {
    /// How serious it is.
    pub level: Level,
    /// Where it was made, when the call said.
    pub source: Option<Source>,
    /// What a reader sees.
    pub message: fmt::Arguments<'a>,
    /// What a query sees.
    pub fields: &'a [Field<'a>],
}

/// Where records go.
///
/// A sink is called from any thread, the ones that serve requests among
/// them, so it must not block. It sends, or it counts what it could not
/// send. `enabled` is asked before a record is formatted.
pub trait Sink: Send + Sync + fmt::Debug {
    /// Whether a record at `level` would be kept.
    fn enabled(&self, level: Level) -> bool;

    /// Keep a record. It is only called at a level `enabled` said yes to.
    fn emit(&self, event: &Event<'_>);
}

/// The handle code reports through. It is cheap to clone and to pass,
/// which is how it reaches the code that has something to say.
#[derive(Clone, Debug)]
pub struct Logger {
    sink: Arc<dyn Sink>,
}

impl Logger {
    /// A handle over a sink.
    pub fn new(sink: Arc<dyn Sink>) -> Self {
        Self { sink }
    }

    /// A handle that keeps nothing, for code that is given no sink.
    pub fn silent() -> Self {
        Self::new(Arc::new(Silent))
    }

    /// Whether a record at `level` would be kept. Ask before building one
    /// that costs anything to build.
    pub fn enabled(&self, level: Level) -> bool {
        self.sink.enabled(level)
    }

    /// Keep a record, if its level is on. [`log!`](crate::log!) is the
    /// usual way to make one.
    pub fn emit(
        &self,
        level: Level,
        source: Option<Source>,
        message: fmt::Arguments<'_>,
        fields: &[Field<'_>],
    ) {
        if self.sink.enabled(level) {
            self.sink.emit(&Event {
                level,
                source,
                message,
                fields,
            });
        }
    }
}

/// The sink behind [`Logger::silent`].
#[derive(Debug)]
struct Silent;

impl Sink for Silent {
    fn enabled(&self, _: Level) -> bool {
        false
    }

    fn emit(&self, _: &Event<'_>) {}
}

/// Make a record with a logger, a level, a bracketed list of `NAME = value`
/// fields if there are any, and then a format string and its arguments.
///
/// ```
/// use truenas_ros::log::{Level, Logger};
///
/// let logger = Logger::silent();
/// let path = "/mnt/tank/a";
/// truenas_ros::log!(logger, Level::Warning, [PATH = path], "{path} left out");
/// truenas_ros::log!(logger, Level::Notice, "stopped");
/// ```
///
/// A field value is anything `Display`, and `&format_args!("{x:?}")` gives
/// a `Debug` one. Nothing is formatted when the level is off. The file and
/// the line of the call go with the record as its source.
#[macro_export]
macro_rules! log {
    (
        $log:expr, $level:expr,
        [$($name:ident = $value:expr),* $(,)?],
        $($arg:tt)+
    ) => {{
        let level: $crate::log::Level = $level;
        let log: &$crate::log::Logger = &$log;
        if log.enabled(level) {
            log.emit(
                level,
                ::core::option::Option::Some($crate::log::Source {
                    file: ::core::file!(),
                    line: ::core::line!(),
                }),
                ::core::format_args!($($arg)+),
                &[$($crate::log::Field::new(
                    ::core::stringify!($name),
                    &$value,
                )),*],
            );
        }
    }};
    ($log:expr, $level:expr, $($arg:tt)+) => {
        $crate::log!($log, $level, [], $($arg)+)
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::log::capture::Capture;

    #[test]
    fn levels_round_trip_through_their_names() {
        for level in Level::ALL {
            assert_eq!(level.as_str().parse::<Level>(), Ok(level));
            assert_eq!(level.to_string(), level.as_str());
        }
        assert_eq!("warn".parse::<Level>(), Err(UnknownLevel("warn".into())));
        assert!("Info".parse::<Level>().is_err());
        assert_eq!(Level::default(), Level::Notice);
    }

    /// The numbering is the journal's, and the order is the threshold's.
    #[test]
    fn levels_are_journal_priorities_in_severity_order() {
        assert_eq!(Level::Error.priority(), 3);
        assert_eq!(Level::Debug.priority(), 7);
        assert!(Level::Error < Level::Warning);
        assert!(Level::Info < Level::Debug);
        for level in Level::ALL {
            assert_eq!(Level::from_priority(level.priority()), level);
        }
        assert_eq!(Level::from_priority(0), Level::Error);
    }

    #[test]
    fn field_names_are_what_the_journal_takes() {
        for ok in ["PEER", "HTTP_STATUS", "A1", "X"] {
            assert!(is_field_name(ok), "{ok}");
        }
        for bad in ["", "_PID", "peer", "Peer", "1ST", "A-B", "A B", "É"] {
            assert!(!is_field_name(bad), "{bad:?}");
        }
        assert!(is_field_name(&"A".repeat(64)));
        assert!(!is_field_name(&"A".repeat(65)));
    }

    /// The guard is a `debug_assert!`, which a release build leaves out, so
    /// this test is for debug builds alone. A field name is never data of a
    /// request, since `log!` makes each one with `stringify!` and a direct
    /// `Field::new` passes a literal, so a bad one is a mistake in the code.
    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "bad field name")]
    fn a_bad_field_name_is_caught_where_it_is_written() {
        let _ = Field::new("lower", &1);
    }

    /// In a release build the bad name gets through, and the journal is
    /// what refuses it.
    #[test]
    #[cfg(not(debug_assertions))]
    fn a_bad_field_name_gets_through_a_release_build() {
        assert_eq!(Field::new("lower", &1).name(), "lower");
    }

    #[test]
    fn the_macro_records_fields_message_and_source() {
        let capture = Capture::new();
        let logger = capture.logger();
        let path = "/mnt/a";
        let status = 70;
        crate::log!(
            logger,
            Level::Info,
            [PATH = path, STATUS = status],
            "{path} answered {status}"
        );
        let records = capture.take();
        assert_eq!(records.len(), 1);
        let record = &records[0];
        assert_eq!(record.level, Level::Info);
        assert_eq!(record.message, "/mnt/a answered 70");
        assert_eq!(record.field("PATH"), Some("/mnt/a"));
        assert_eq!(record.field("STATUS"), Some("70"));
        assert_eq!(record.field("MISSING"), None);
        let source = record.source.expect("the macro names its call");
        assert!(source.file.ends_with("mod.rs"), "{}", source.file);
        assert!(source.line > 0);
    }

    #[test]
    fn the_macro_takes_no_fields_and_a_borrowed_logger() {
        let capture = Capture::new();
        let logger = capture.logger();
        let by_ref = &logger;
        crate::log!(by_ref, Level::Notice, "stopped");
        crate::log!(logger, Level::Warning, [], "bare {}", "brackets");
        let records = capture.take();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].message, "stopped");
        assert!(records[0].fields.is_empty());
        assert_eq!(records[1].message, "bare brackets");
    }

    #[test]
    fn a_debug_value_rides_as_format_args() {
        let capture = Capture::new();
        let logger = capture.logger();
        let signal = Some(15);
        crate::log!(
            logger,
            Level::Notice,
            [SIGNAL = format_args!("{signal:?}")],
            "signal"
        );
        assert_eq!(capture.take()[0].field("SIGNAL"), Some("Some(15)"));
    }

    /// Below the threshold, the arguments are never evaluated.
    #[test]
    fn a_record_below_the_threshold_is_never_built() {
        let logger = Logger::silent();
        let mut built = false;
        let mut build = || {
            built = true;
            "value"
        };
        crate::log!(logger, Level::Error, [V = build()], "{}", build());
        assert!(!built);
        assert!(!logger.enabled(Level::Error));
    }

    #[test]
    fn emit_itself_honors_the_threshold() {
        let capture = Capture::at(Level::Warning);
        let logger = capture.logger();
        logger.emit(Level::Info, None, format_args!("quiet"), &[]);
        logger.emit(Level::Error, None, format_args!("loud"), &[]);
        let records = capture.take();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].message, "loud");
        assert_eq!(records[0].source, None);
    }
}
