//! JSON-lines-to-stdout sink: one JSON object per line per record, for a
//! container runtime (Docker / CloudWatch) to collect. Pairs with the [`Ring`]
//! inside [`StdoutRingSink`] — stdout is the cloud path, the ring is what SOVD
//! reads locally (stdout can't serve a SOVD client).
//!
//! [`Level`] is serialized as its lowercase name; `unix_nanos` passes through
//! (0 = unknown). A serialization failure is swallowed — logging must never
//! wedge the caller — but is astronomically unlikely for this fixed shape.

use std::io::Write;

use host_log_contract::{LogRecord, LogSink};
use serde::Serialize;

/// Writes each record as a JSON line to stdout.
pub struct StdoutJsonSink {
    _priv: (),
}

impl Default for StdoutJsonSink {
    fn default() -> Self {
        Self::new()
    }
}

impl StdoutJsonSink {
    pub fn new() -> Self {
        StdoutJsonSink { _priv: () }
    }

    /// Emit without taking ownership — used by the fan-out, which still needs the
    /// record afterward for the ring.
    pub fn emit_ref(&self, record: &LogRecord) {
        let line = match serde_json::to_string(&Wire::from(record)) {
            Ok(s) => s,
            Err(_) => return, // never wedge the caller on a serialize error
        };
        // One locked write of line + '\n' so concurrent emits don't interleave.
        let stdout = std::io::stdout();
        let mut lock = stdout.lock();
        let _ = writeln!(lock, "{line}");
    }
}

impl LogSink for StdoutJsonSink {
    fn emit(&self, record: LogRecord) {
        self.emit_ref(&record);
    }
}

/// The on-the-wire JSON shape. Fields render as an object; a level renders as its
/// lowercase name. Borrowed from a `&LogRecord` to avoid a clone on the hot path.
#[derive(Serialize)]
struct Wire<'a> {
    unix_nanos: i64,
    level: &'static str,
    source: &'a str,
    message: &'a str,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    fields: Vec<(&'a str, &'a str)>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pid: Option<u32>,
}

impl<'a> From<&'a LogRecord> for Wire<'a> {
    fn from(r: &'a LogRecord) -> Self {
        Wire {
            unix_nanos: r.unix_nanos,
            level: level_name(r.level),
            source: &r.source,
            message: &r.message,
            fields: r
                .fields
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect(),
            pid: r.pid,
        }
    }
}

fn level_name(l: host_log_contract::Level) -> &'static str {
    use host_log_contract::Level::*;
    match l {
        Emergency => "emergency",
        Alert => "alert",
        Critical => "critical",
        Error => "error",
        Warning => "warning",
        Notice => "notice",
        Info => "info",
        Debug => "debug",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use host_log_contract::Level;

    #[test]
    fn wire_shape_is_stable_json() {
        let mut r = LogRecord::new(Level::Warning, "supernova", "creating NV store");
        r.unix_nanos = 1_753_000_000_000_000_000;
        r.fields.push(("path".into(), "/mnt/x".into()));
        r.pid = Some(42);
        let json = serde_json::to_string(&Wire::from(&r)).unwrap();
        // Round-trip through a Value so the assert isn't field-order sensitive.
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["level"], "warning");
        assert_eq!(v["source"], "supernova");
        assert_eq!(v["message"], "creating NV store");
        assert_eq!(v["unix_nanos"], 1_753_000_000_000_000_000i64);
        assert_eq!(v["fields"][0][0], "path");
        assert_eq!(v["fields"][0][1], "/mnt/x");
        assert_eq!(v["pid"], 42);
    }

    #[test]
    fn empty_fields_and_no_pid_are_omitted() {
        let r = LogRecord::new(Level::Info, "s", "m");
        let json = serde_json::to_string(&Wire::from(&r)).unwrap();
        assert!(!json.contains("fields"));
        assert!(!json.contains("pid"));
        assert!(json.contains("\"unix_nanos\":0"));
    }
}
