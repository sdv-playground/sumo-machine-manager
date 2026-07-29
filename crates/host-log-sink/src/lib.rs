//! Concrete host-log sinks + readers, behind the [`host_log_contract`] traits.
//!
//! The PORTABLE default ([`StdoutRingSink`]) is a fan-out:
//!   - JSON-to-stdout, so a container runtime (Docker / CloudWatch) collects it;
//!   - a bounded in-process [`Ring`], which is also the [`HostLogReader`] SOVD
//!     §7.21 snapshots (stdout alone can't serve a SOVD client — it needs a local
//!     source).
//!
//! A `tracing` producer feeds records in via [`TracingBridge`] (feature
//! `tracing-bridge`). QNX `slog2` and a durable file backing (`log-rotate`) are
//! feature-gated add-ons layered on the same traits (see
//! `tasks/host-log-pipeline-design.md`). supernova holds an `Arc<dyn LogSink>`
//! and an `Arc<dyn HostLogReader>` chosen by build feature, oblivious to which.

mod ring;
mod stdout;

pub use ring::Ring;
pub use stdout::StdoutJsonSink;

#[cfg(feature = "tracing-bridge")]
mod tracing_bridge;
#[cfg(feature = "tracing-bridge")]
pub use tracing_bridge::TracingBridge;

use std::sync::Arc;

use host_log_contract::{HostLogReader, LogRecord, LogSink};

/// The portable default sink: JSON-to-stdout PLUS a bounded ring.
///
/// Construct with [`StdoutRingSink::build`], which hands back the sink and the
/// matching [`HostLogReader`] (the shared ring) so SOVD can read what was emitted.
/// This is the feature-off build used by QEMU / Docker / AWS — no QNX deps.
pub struct StdoutRingSink {
    ring: Arc<Ring>,
    stdout: StdoutJsonSink,
}

impl StdoutRingSink {
    /// Build a sink whose ring retains the last `capacity` records, and return it
    /// alongside the reader over that same ring. Named `build` (not `new`) because
    /// it yields a `(sink, reader)` pair, not `Self`.
    pub fn build(capacity: usize) -> (Arc<dyn LogSink>, Arc<dyn HostLogReader>) {
        let ring = Arc::new(Ring::new(capacity));
        let sink: Arc<dyn LogSink> = Arc::new(StdoutRingSink {
            ring: ring.clone(),
            stdout: StdoutJsonSink::new(),
        });
        let reader: Arc<dyn HostLogReader> = ring;
        (sink, reader)
    }
}

impl LogSink for StdoutRingSink {
    fn emit(&self, record: LogRecord) {
        // Stdout first (cheap, cloud-collectable), then retain in the ring for
        // SOVD. Clone once for the ring; stdout borrows.
        self.stdout.emit_ref(&record);
        self.ring.push(record);
    }
}
