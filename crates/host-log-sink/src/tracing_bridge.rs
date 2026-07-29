//! `TracingBridge` — a `tracing_subscriber::Layer` that turns each `tracing`
//! event into a [`LogRecord`] and hands it to a [`LogSink`]. This is how supernova
//! (a `tracing` producer) feeds the pluggable pipeline WITHOUT any formatting,
//! ANSI, or file involved: the record is structured at the source.
//!
//! Install it as a layer on the registry (feature `tracing-bridge`):
//! ```ignore
//! use tracing_subscriber::prelude::*;
//! let (sink, reader) = host_log_sink::StdoutRingSink::build(8192);
//! tracing_subscriber::registry()
//!     .with(env_filter)
//!     .with(host_log_sink::TracingBridge::new(sink))
//!     .init();
//! // hand `reader` to the SOVD host LogSource.
//! ```

use std::sync::Arc;

use host_log_contract::{Level, LogRecord, LogSink};
use tracing_core::field::{Field, Visit};
use tracing_core::{Event, Subscriber};
use tracing_subscriber::layer::Context;
use tracing_subscriber::Layer;

/// A tracing layer that forwards events to a [`LogSink`].
pub struct TracingBridge {
    sink: Arc<dyn LogSink>,
}

impl TracingBridge {
    pub fn new(sink: Arc<dyn LogSink>) -> Self {
        TracingBridge { sink }
    }
}

impl<S: Subscriber> Layer<S> for TracingBridge {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let meta = event.metadata();

        let mut visitor = FieldVisitor::default();
        event.record(&mut visitor);

        // `tracing` has no timestamp on the event itself; the sink/reader that
        // needs one stamps it (the portable ring/stdout path leaves records
        // relative-ordered, the caller can stamp on emit if it wants wall-clock).
        // We keep 0 = UNKNOWN here rather than fabricate one, honoring the
        // contract's sentinel. A future stamping wrapper can set it.
        let record = LogRecord {
            unix_nanos: 0,
            level: map_level(*meta.level()),
            source: meta.target().to_string(),
            message: visitor.message.unwrap_or_default(),
            fields: visitor.fields,
            pid: None,
        };
        self.sink.emit(record);
    }
}

/// Map a `tracing` level onto our syslog-style [`Level`]. tracing has 5 levels;
/// we place them on the syslog scale (Error→Error, Warn→Warning, Info→Info,
/// Debug→Debug, Trace→Debug — no finer syslog level than Debug).
fn map_level(l: tracing_core::Level) -> Level {
    match l {
        tracing_core::Level::ERROR => Level::Error,
        tracing_core::Level::WARN => Level::Warning,
        tracing_core::Level::INFO => Level::Info,
        tracing_core::Level::DEBUG => Level::Debug,
        tracing_core::Level::TRACE => Level::Debug,
    }
}

/// Collects the event's `message` field (special-cased) and all other fields as
/// stringified key/value pairs.
#[derive(Default)]
struct FieldVisitor {
    message: Option<String>,
    fields: Vec<(String, String)>,
}

impl FieldVisitor {
    fn put(&mut self, field: &Field, value: String) {
        if field.name() == "message" {
            self.message = Some(value);
        } else {
            self.fields.push((field.name().to_string(), value));
        }
    }
}

impl Visit for FieldVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.put(field, format!("{value:?}"));
    }
    fn record_str(&mut self, field: &Field, value: &str) {
        self.put(field, value.to_string());
    }
    fn record_i64(&mut self, field: &Field, value: i64) {
        self.put(field, value.to_string());
    }
    fn record_u64(&mut self, field: &Field, value: u64) {
        self.put(field, value.to_string());
    }
    fn record_bool(&mut self, field: &Field, value: bool) {
        self.put(field, value.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Ring;
    use tracing_subscriber::prelude::*;

    #[test]
    fn event_becomes_record_with_target_and_message() {
        let ring = Arc::new(Ring::new(16));
        let sink: Arc<dyn LogSink> = ring.clone();
        let subscriber = tracing_subscriber::registry().with(TracingBridge::new(sink));

        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(target: "supernova", answer = 42, "hello world");
            tracing::warn!(target: "vm_service", "vm down");
        });

        let snap = host_log_contract::HostLogReader::snapshot(&*ring, 10);
        assert_eq!(snap.len(), 2);

        assert_eq!(snap[0].source, "supernova");
        assert_eq!(snap[0].level, Level::Info);
        assert_eq!(snap[0].message, "hello world");
        assert!(snap[0]
            .fields
            .iter()
            .any(|(k, v)| k == "answer" && v == "42"));

        assert_eq!(snap[1].source, "vm_service");
        assert_eq!(snap[1].level, Level::Warning);
        assert_eq!(snap[1].message, "vm down");
    }

    #[test]
    fn level_mapping() {
        assert_eq!(map_level(tracing_core::Level::ERROR), Level::Error);
        assert_eq!(map_level(tracing_core::Level::WARN), Level::Warning);
        assert_eq!(map_level(tracing_core::Level::TRACE), Level::Debug);
    }
}
