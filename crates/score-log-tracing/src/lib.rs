//! `tracing` → S-CORE `score_log` bridge.
//!
//! A [`ScoreLogBridge`] is a [`tracing_subscriber::Layer`] that forwards every
//! `tracing` event into the installed `score_log` global logger. It lets a host
//! binary that already emits with `tracing` (supernova, and eventually
//! vm-service / vhsm-ssd / vm-sovd) adopt `score_log` as the logging facade
//! WITHOUT rewriting its `tracing::info!(…)` call sites — the `score_log`
//! recorder installed via [`score_log::set_global_logger`] (S-CORE's
//! `stdout_logger` in a container, or our `Slog2Sink` on QNX) then decides where
//! records actually land.
//!
//! ```ignore
//! use tracing_subscriber::prelude::*;
//! // install a score_log recorder (e.g. stdout_logger) as the global logger,
//! // set_max_level(...), then:
//! tracing_subscriber::registry()
//!     .with(env_filter)
//!     .with(score_log_tracing::ScoreLogBridge::new())
//!     .init();
//! ```
//!
//! ## Mapping
//! - tracing level → `score_log::Level` (`ERROR→Error`, `WARN→Warn`, `INFO→Info`,
//!   `DEBUG→Debug`, `TRACE→Trace`; `score_log`'s `Fatal` has no tracing analogue).
//! - the event `target` → the record `context` (S-CORE's DLT-style tag) AND the
//!   record `module_path`.
//! - the event's `message` field + any other fields → a single rendered string
//!   carried as one `Fragment::Literal`. `score_log`'s `Arguments` is a borrowed
//!   slice of fragments built for compile-time macro use; a runtime-formatted
//!   `tracing` message is wrapped as one literal fragment, which `score_log::fmt`
//!   emits verbatim.

use core::fmt::Write as _;

use score_log::fmt::{Arguments, Fragment};
use score_log::{global_logger, Level, Metadata, Record};
use tracing_core::field::{Field, Visit};
use tracing_core::{Event, Subscriber};
use tracing_subscriber::layer::Context;
use tracing_subscriber::Layer;

/// A `tracing` layer that forwards events to the `score_log` global logger.
///
/// Filtering is left to the layers composed around it (an `EnvFilter`) and to the
/// installed `score_log` recorder's own `enabled`/`max_level` — this layer just
/// translates and forwards.
#[derive(Debug, Default, Clone, Copy)]
pub struct ScoreLogBridge;

impl ScoreLogBridge {
    /// Create the bridge layer.
    pub fn new() -> Self {
        ScoreLogBridge
    }
}

impl<S: Subscriber> Layer<S> for ScoreLogBridge {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let meta = event.metadata();
        let level = map_level(meta.level());

        // Render the event's message (+ any extra fields) into one owned string.
        let mut visitor = MessageVisitor::default();
        event.record(&mut visitor);

        // Wrap the runtime string as a single literal fragment. `frags`, `msg`,
        // and `record` all live on this stack frame; `Log::log` borrows them.
        let frags = [Fragment::Literal(visitor.message.as_str())];
        let args = Arguments(&frags);
        let target = meta.target();
        let metadata = Metadata::new(level, target);
        let record = Record::new(
            args,
            metadata,
            target,
            meta.file().unwrap_or(""),
            meta.line().unwrap_or(0),
        );
        global_logger().log(&record);
    }
}

/// Map a `tracing` level onto `score_log::Level`. `tracing` has five levels;
/// `score_log` adds `Fatal` above `Error` (a safety level with no tracing
/// analogue), so nothing maps to it here.
fn map_level(l: &tracing_core::Level) -> Level {
    match *l {
        tracing_core::Level::ERROR => Level::Error,
        tracing_core::Level::WARN => Level::Warn,
        tracing_core::Level::INFO => Level::Info,
        tracing_core::Level::DEBUG => Level::Debug,
        tracing_core::Level::TRACE => Level::Trace,
    }
}

/// Renders an event's `message` field, then appends any other fields as
/// ` key=value`. Matches how a fmt subscriber presents an event as one line.
#[derive(Default)]
struct MessageVisitor {
    message: String,
}

impl Visit for MessageVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn core::fmt::Debug) {
        if field.name() == "message" {
            // The primary message: render at the front, no key= prefix.
            let _ = write!(self.message, "{value:?}");
        } else {
            let _ = write!(self.message, " {}={value:?}", field.name());
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message.push_str(value);
        } else {
            let _ = write!(self.message, " {}={value}", field.name());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tracing_subscriber::prelude::*;

    /// A capturing `score_log::Log` recording (level, rendered-message) per event.
    struct Capture(Arc<Mutex<Vec<(Level, String)>>>);

    impl score_log::Log for Capture {
        fn enabled(&self, _m: &Metadata) -> bool {
            true
        }
        fn context(&self) -> &str {
            "TEST"
        }
        fn log(&self, record: &Record) {
            let mut s = String::new();
            let _ = score_log::fmt::write(&mut StrWriter(&mut s), *record.args());
            self.0.lock().unwrap().push((record.level(), s));
        }
        fn flush(&self) {}
    }

    /// Minimal `ScoreWrite` that concatenates into a `String` (the bridge only
    /// ever emits `Literal`s, so `write_str` is the only path exercised; the
    /// numeric methods delegate to it for completeness).
    struct StrWriter<'a>(&'a mut String);
    impl score_log::fmt::ScoreWrite for StrWriter<'_> {
        fn write_str(&mut self, v: &str, _: &score_log::fmt::FormatSpec) -> score_log::fmt::Result {
            self.0.push_str(v);
            Ok(())
        }
        fn write_bool(
            &mut self,
            v: &bool,
            _: &score_log::fmt::FormatSpec,
        ) -> score_log::fmt::Result {
            let _ = write!(self.0, "{v}");
            Ok(())
        }
        fn write_f32(&mut self, v: &f32, _: &score_log::fmt::FormatSpec) -> score_log::fmt::Result {
            let _ = write!(self.0, "{v}");
            Ok(())
        }
        fn write_f64(&mut self, v: &f64, _: &score_log::fmt::FormatSpec) -> score_log::fmt::Result {
            let _ = write!(self.0, "{v}");
            Ok(())
        }
        fn write_i8(&mut self, v: &i8, _: &score_log::fmt::FormatSpec) -> score_log::fmt::Result {
            let _ = write!(self.0, "{v}");
            Ok(())
        }
        fn write_i16(&mut self, v: &i16, _: &score_log::fmt::FormatSpec) -> score_log::fmt::Result {
            let _ = write!(self.0, "{v}");
            Ok(())
        }
        fn write_i32(&mut self, v: &i32, _: &score_log::fmt::FormatSpec) -> score_log::fmt::Result {
            let _ = write!(self.0, "{v}");
            Ok(())
        }
        fn write_i64(&mut self, v: &i64, _: &score_log::fmt::FormatSpec) -> score_log::fmt::Result {
            let _ = write!(self.0, "{v}");
            Ok(())
        }
        fn write_u8(&mut self, v: &u8, _: &score_log::fmt::FormatSpec) -> score_log::fmt::Result {
            let _ = write!(self.0, "{v}");
            Ok(())
        }
        fn write_u16(&mut self, v: &u16, _: &score_log::fmt::FormatSpec) -> score_log::fmt::Result {
            let _ = write!(self.0, "{v}");
            Ok(())
        }
        fn write_u32(&mut self, v: &u32, _: &score_log::fmt::FormatSpec) -> score_log::fmt::Result {
            let _ = write!(self.0, "{v}");
            Ok(())
        }
        fn write_u64(&mut self, v: &u64, _: &score_log::fmt::FormatSpec) -> score_log::fmt::Result {
            let _ = write!(self.0, "{v}");
            Ok(())
        }
    }

    #[test]
    fn forwards_level_target_and_message() {
        let cap = Arc::new(Mutex::new(Vec::new()));
        // set_global_logger may fail if another test already set one in-process;
        // ignore the error — a prior Capture works the same for this assertion is
        // not safe across loggers, so run this as the sole logger-setting test.
        let _ = score_log::set_global_logger(Box::new(Capture(cap.clone())));

        let sub = tracing_subscriber::registry().with(ScoreLogBridge::new());
        tracing::subscriber::with_default(sub, || {
            tracing::info!(target: "supernova", "hello {}", 42);
            tracing::warn!(target: "vm_service", "vm down");
        });

        let got = cap.lock().unwrap().clone();
        assert_eq!(got.len(), 2, "got: {got:?}");
        assert_eq!(got[0].0, Level::Info);
        assert_eq!(got[0].1, "hello 42");
        assert_eq!(got[1].0, Level::Warn);
        assert_eq!(got[1].1, "vm down");
    }

    #[test]
    fn level_mapping_covers_all() {
        assert_eq!(map_level(&tracing_core::Level::ERROR), Level::Error);
        assert_eq!(map_level(&tracing_core::Level::WARN), Level::Warn);
        assert_eq!(map_level(&tracing_core::Level::INFO), Level::Info);
        assert_eq!(map_level(&tracing_core::Level::DEBUG), Level::Debug);
        assert_eq!(map_level(&tracing_core::Level::TRACE), Level::Trace);
    }
}
