//! Host log pipeline — the contract.
//!
//! One structured record type ([`LogRecord`]) and two traits:
//!
//! - [`LogSink`] — the PRODUCER side: something that accepts records (a ring,
//!   stdout-JSON, slog2, a future journald sink). supernova's tracing layer emits
//!   into an `Arc<dyn LogSink>` chosen by build feature — oblivious to which
//!   concrete sink it got, exactly as it is oblivious to which `DeviceTransport`.
//! - [`HostLogReader`] — the READ side: something SOVD §7.21 can snapshot. A ring
//!   reads itself; a slog2 reader reads the kernel buffer.
//!
//! This crate is deliberately THIN — no `tracing`, no async runtime, no
//! `sovd-core`, no `chrono`. That dep-lightness is the point: it keeps the set of
//! possible implementers wide (host binaries today; minimal-dep guest agents and
//! an eventual ASIL-B-auditable unit tomorrow — see
//! `tasks/reusable-component-convention.md`). Concrete sinks/readers, and the
//! conversions to `tracing` events / `sovd_core::LogEntry`, live in `host-log-sink`.

/// Syslog-style severity, most-severe first (numeric value matches the syslog
/// level and `sovd_core::LogPriority`: `Emergency = 0` … `Debug = 7`). Kept as our
/// own enum so the contract does not depend on `sovd-core`; `host-log-sink` maps
/// it across. "This level and above" filtering is `<=` on the numeric value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum Level {
    Emergency = 0,
    Alert = 1,
    Critical = 2,
    Error = 3,
    Warning = 4,
    Notice = 5,
    Info = 6,
    Debug = 7,
}

impl Level {
    /// The numeric syslog value (0 = most severe).
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// One structured log record — the unit every sink accepts and every reader
/// yields. Structured AT THE SOURCE: no downstream parsing of a leading timestamp
/// token, no ANSI, no filename-derived source. That is what retires the three
/// bugs of the old `>> supernova.log` funnel (mtime timestamps, ANSI-in-file,
/// source-collapse) by construction.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct LogRecord {
    /// Wall-clock time, NANOSECONDS since the Unix epoch. `0` means UNKNOWN — the
    /// honest sentinel for a record emitted before the clock was set (early boot),
    /// rather than a misleading substitute like a file mtime. `i64` spans
    /// ~1678–2262, comfortably beyond any device lifetime.
    pub unix_nanos: i64,
    /// Severity.
    pub level: Level,
    /// Where it came from — a service/target name, NOT a filename. For a `tracing`
    /// producer this is the event target.
    pub source: String,
    /// The message text (no embedded timestamp, no ANSI).
    pub message: String,
    /// Structured key/value fields (a `tracing` event's fields). Kept as ordered
    /// pairs to avoid a JSON-value dep in the contract; `host-log-sink` renders
    /// them to `sovd_core::LogEntry.fields` as it sees fit.
    pub fields: Vec<(String, String)>,
    /// Emitting process id, when known.
    pub pid: Option<u32>,
}

impl LogRecord {
    /// A record with just a level, source and message — time UNKNOWN (`0`), no
    /// fields, no pid. Convenience for the common case; set `unix_nanos`/`fields`
    /// afterward when available.
    pub fn new(level: Level, source: impl Into<String>, message: impl Into<String>) -> Self {
        LogRecord {
            unix_nanos: 0,
            level,
            source: source.into(),
            message: message.into(),
            fields: Vec::new(),
            pid: None,
        }
    }

    /// `true` when the timestamp is the UNKNOWN sentinel (`0`).
    pub fn time_unknown(&self) -> bool {
        self.unix_nanos == 0
    }
}

/// The PRODUCER contract: accept a record. Implementations must be cheap and
/// non-blocking on the hot path (a producer calls this from arbitrary threads) —
/// a ring push, a formatted write to stdout, a `slog2c` call. `Send + Sync` so it
/// can live behind an `Arc<dyn LogSink>` shared across the process.
pub trait LogSink: Send + Sync {
    /// Record `record`. Best-effort: a sink that cannot accept it (full, closed)
    /// drops it rather than blocking or erroring — logging must never wedge the
    /// caller. Return is `()` for exactly that reason.
    fn emit(&self, record: LogRecord);
}

/// The READ contract: hand back the most recent records for SOVD §7.21 to serve.
/// A ring copies out its buffer; a slog2 reader parses the kernel buffer. Higher
/// layers (component-mgr's `LogSource`) apply their own since/until/source/
/// priority filtering on top — the reader just supplies the raw, ordered records.
/// `Send + Sync` so it can back an async request handler.
pub trait HostLogReader: Send + Sync {
    /// Up to `max` of the most recent records, OLDEST-first (chronological within
    /// what is retained). Fewer than `max` when the buffer holds fewer. `max == 0`
    /// yields an empty vec.
    fn snapshot(&self, max: usize) -> Vec<LogRecord>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn level_numeric_matches_syslog_and_orders_by_severity() {
        assert_eq!(Level::Emergency.as_u8(), 0);
        assert_eq!(Level::Debug.as_u8(), 7);
        // "this level and above" is `<=` on the numeric value.
        assert!(Level::Error < Level::Info);
        assert!(Level::Error <= Level::Info);
    }

    #[test]
    fn new_record_has_unknown_time() {
        let r = LogRecord::new(Level::Info, "supernova", "hello");
        assert!(r.time_unknown());
        assert_eq!(r.unix_nanos, 0);
        assert_eq!(r.source, "supernova");
        assert_eq!(r.message, "hello");
        assert!(r.fields.is_empty());
        assert_eq!(r.pid, None);
    }

    #[test]
    fn time_known_when_set() {
        let mut r = LogRecord::new(Level::Warning, "svc", "m");
        r.unix_nanos = 1;
        assert!(!r.time_unknown());
    }
}
