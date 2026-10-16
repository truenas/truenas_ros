//! A sink that keeps what was said, for a test to assert on.

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};

use super::{Event, Level, Logger, Sink, Source};

/// One record, owned.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Record {
    /// How serious it was.
    pub level: Level,
    /// Where it was made, when the call said.
    pub source: Option<Source>,
    /// The message, rendered.
    pub message: String,
    /// The fields, in order, rendered.
    pub fields: Vec<(&'static str, String)>,
}

impl Record {
    /// The first field of that name, rendered.
    pub fn field(&self, name: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, v)| v.as_str())
    }
}

/// Keeps every record at or above its threshold.
#[derive(Debug)]
pub struct Capture {
    level: AtomicU8,
    records: Mutex<Vec<Record>>,
}

impl Capture {
    /// A capture that keeps everything.
    pub fn new() -> Arc<Self> {
        Self::at(Level::Debug)
    }

    /// A capture with a threshold, to test what is not said.
    pub fn at(level: Level) -> Arc<Self> {
        Arc::new(Self {
            level: AtomicU8::new(level.priority()),
            records: Mutex::new(Vec::new()),
        })
    }

    /// A handle over this capture.
    pub fn logger(self: &Arc<Self>) -> Logger {
        Logger::new(Arc::clone(self) as Arc<dyn Sink>)
    }

    /// Everything kept so far, oldest first.
    pub fn records(&self) -> Vec<Record> {
        self.lock().clone()
    }

    /// Everything kept so far, oldest first, leaving nothing behind.
    pub fn take(&self) -> Vec<Record> {
        std::mem::take(&mut *self.lock())
    }

    /// The records, locked. A test that panicked while it held the lock
    /// left records that are still worth reading, so the poison is passed
    /// over.
    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<Record>> {
        self.records
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl Sink for Capture {
    fn enabled(&self, level: Level) -> bool {
        level.priority() <= self.level.load(Ordering::Relaxed)
    }

    fn emit(&self, event: &Event<'_>) {
        let record = Record {
            level: event.level,
            source: event.source,
            message: event.message.to_string(),
            fields: event
                .fields
                .iter()
                .map(|f| (f.name(), f.value().to_string()))
                .collect(),
        };
        self.lock().push(record);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_in_order_and_take_empties() {
        let capture = Capture::new();
        let logger = capture.logger();
        crate::log!(logger, Level::Error, "one");
        crate::log!(logger, Level::Debug, "two");
        assert_eq!(capture.records().len(), 2);
        let taken = capture.take();
        assert_eq!(taken[0].message, "one");
        assert_eq!(taken[1].message, "two");
        assert!(capture.records().is_empty());
    }

    #[test]
    fn the_threshold_keeps_the_serious_and_drops_the_rest() {
        let capture = Capture::at(Level::Notice);
        let logger = capture.logger();
        assert!(logger.enabled(Level::Error));
        assert!(logger.enabled(Level::Notice));
        assert!(!logger.enabled(Level::Info));
        crate::log!(logger, Level::Info, "dropped");
        crate::log!(logger, Level::Notice, "kept");
        let records = capture.take();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].level, Level::Notice);
    }
}
